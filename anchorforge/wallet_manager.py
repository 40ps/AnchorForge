# wallet_manager.py
'''
.. now git
Version 25-09-05 
Version 25-08-16
   make filename dependend on address used to avoid overwriting

'''

import json
from typing import Dict, Any
from datetime import datetime, timezone
import logging
import os
import portalocker
from portalocker import LOCK_EX

from bsv import PrivateKey, Network

from config import Config

import blockchain_api


logger = logging.getLogger(__name__)

# --- Helper function for dynamic file naming
def _get_filename_for_address(address: str, network_name: str, simulation: bool = False) -> str:
    """
    Generates a unique filename for the UTXO store based on the address and network.
    Appends a '.sim.json' suffix if running in simulation mode.

    Args:
        address (str): The wallet address.
        network_name (str): The name of the network ('main' or 'test').
        simulation (bool, optional): If True, appends '.sim.json'. Defaults to False.

    Returns:
        str: The generated filename.
    """
    short_address = f"{address[:4]}{address[-4:]}"
    base_name = f"utxo_store_{network_name}_{short_address}"
    
    # Add '.sim.json' suffix for simulation runs, otherwise '.json'
    suffix = ".sim.json" if simulation else ".json"
    
    return f"{base_name}{suffix}"


# --- Section local UTXO and Tx Store

def load_utxo_store(f) -> Dict[str, Any]:
    """Load unused UTXOs from an open file object."""
    try:
        f.seek(0)
        return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"address": "", "utxos": [], "network": ""}

def load_used_utxo_store(f) -> Dict[str, Any]:
    """Load used UTXOs from an open file object."""
    try:
        f.seek(0)
        return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"address": "", "used_utxos": [], "network": ""}

def save_utxo_store(f, store: Dict):
    """Save unused UTXOs to an open file object."""
    f.seek(0)
    json.dump(store, f, indent=4)
    f.truncate()

def save_used_utxo_store(f, store: Dict):
    """Save used UTXOs to an open file object."""
    f.seek(0)
    json.dump(store, f, indent=4)
    f.truncate()


# --- Transaction Store
def load_tx_store(f) -> Dict[str, Any]:
    """Load Tx from an open file object."""
    try:
        f.seek(0)
        return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"address": "", "transactions": [], "network": ""}

def save_tx_store(f, store: Dict):
    """Save TXs to an open file object."""
    f.seek(0)
    json.dump(store, f, indent=4)
    f.truncate()


async def initialize_utxo_store(private_key_wif: str, network_name: str):
    """
    Initialize the UTXO store with UTXOs from the blockchain.

    Args:
        private_key_wif (str): The private key WIF of the address to manage.
        network_name (str): The name of the network ('test' or 'main').
    """
    if network_name.lower() not in Config.NETWORK_API_ENDPOINTS:
        raise ValueError("Invalid network name. Use 'main' or 'test'.")

    # Determine the bsv.Network object
    bsv_network = Network.TESTNET if network_name.lower() == 'test' else Network.MAINNET
    
    priv_key = PrivateKey(private_key_wif, network=bsv_network)
    sender_address = priv_key.address()
    
    # Derive dynamic file paths based on the address and network
    utxo_file_path = _get_filename_for_address(str(sender_address), network_name)
    tx_file_path = f"tx_store_{network_name}_{str(sender_address)[:4]}{str(sender_address)[-4:]}.json"
    used_utxo_file_path = f"used_utxo_store_{network_name}_{str(sender_address)[:4]}{str(sender_address)[-4:]}.json"

    print(f"Initializing stores for address: {sender_address}")
    print(f"  Using UTXO store file: {utxo_file_path}")


    # --- Robust File Handling: Ensure files exist before locking with "r+" ---
    for path in [utxo_file_path, tx_file_path, used_utxo_file_path]:
        if not os.path.exists(path):
            print(f"File not found, creating empty store: {path}")
            # Create empty but valid JSON Structure
            initial_data = {}
            if "used_utxo" in path:
                initial_data = {"address": "", "network": "", "used_utxos": []}
            elif "utxo_store" in path:
                initial_data = {"address": "", "network": "", "utxos": []}
            elif "tx_store" in path:
                initial_data = {"address": "", "network": "", "transactions": []}
            
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(initial_data, f, indent=4)

    # Fetch all UTXOs belonging to the sender's address
    utxos_from_woc = await blockchain_api.fetch_utxos_for_address(str(sender_address))

    if not utxos_from_woc:
        print(f"No UTXOs found for address {sender_address}. Using existing local store.")
        return

    # Ensure every UTXO has all expected keys
    formatted_utxos_for_store = []
    for utxo in utxos_from_woc:
        formatted_utxos_for_store.append({
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "satoshis": utxo["satoshis"],
            "height": utxo.get("height", -1),
            "used": False,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    # --- Lock, Load, Process, and Save with the correct "r+" mode ---
    # 1. Lock tx_store
    # Initialize empty tx_store if it doesn't exist
    with portalocker.Lock(tx_file_path, "r+", flags=LOCK_EX, timeout=5) as f:
        tx_store = load_tx_store(f)
        if not tx_store.get("address") or tx_store["address"] != str(sender_address) or tx_store["network"] != network_name:
            print(f"TX store being initialized/reset for address {sender_address}.")
            tx_store = {"address": str(sender_address),
                        "network": network_name,
                        "transactions": []}
        
        # Collect unique txids from utxos
        existing_txids = {tx["txid"] for tx in tx_store.get("transactions",[])}
        new_txids_to_cache = {utxo["txid"] for utxo in formatted_utxos_for_store if utxo["txid"] not in existing_txids}
        
        # Add placeholder entries for new txids
        for txid_to_cache in new_txids_to_cache:
            raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(txid_to_cache)
            if raw_source_tx_hex:            
                tx_store["transactions"].append({
                    "txid": txid_to_cache,
                    "rawtx": raw_source_tx_hex,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            else:
                # raw_source_tx_hex is None:
                print(f"Skipping txid {txid_to_cache}, could not fetch raw Tx")
        
        save_tx_store(f, tx_store)
    print(f"TX store cache populated with {len(new_txids_to_cache)} new raw transactions.")


    # Populate and save used_utxo_store.json
    # 2. Lock used_utxo_store
    with portalocker.Lock(used_utxo_file_path, "r+", flags=LOCK_EX, timeout=5) as f:
        used_store = load_used_utxo_store(f)
        if not used_store.get("address") or used_store["address"] != str(sender_address) or used_store["network"] != network_name:
            print(f"USED UTXO store being initialized/reset for address {sender_address}.")
            used_store = {"address": str(sender_address), "network": network_name, "used_utxos": []}
            save_used_utxo_store(f, used_store)

    
    # Load and update the UTXO store
    # 3. Lock UTXO Store as last!
    with portalocker.Lock(utxo_file_path, "r+", flags=LOCK_EX, timeout=5) as f:
        utxo_store = load_utxo_store(f) 
        utxo_store["address"] = str(sender_address)
        utxo_store["network"] = network_name
        # This will OVERWRITE the old utxos with the fresh list from the blockchain
        utxo_store["utxos"] = formatted_utxos_for_store
        save_utxo_store(f, utxo_store)
    print(f"UTXO store initialized with {len(formatted_utxos_for_store)} UTXOs.")

    return 