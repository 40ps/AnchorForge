# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    wallet_manager.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

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
import time
import portalocker
from portalocker import LOCK_EX

from bsv import PrivateKey, Network

from anchorforge.config import Config

from anchorforge import blockchain_api


logger = logging.getLogger(__name__)

# --- Helper function for dynamic file naming
def _get_filename_for_address(
        address: str, 
        network_name: str = Config.ACTIVE_NETWORK_NAME, 
        file_type: str = "utxo",
        simulation: bool = False) -> str:
    """
    Generates a unique filename for the UTXO store based on the address and network.
    Automatically places the file in the correct directory (CACHE or DATABASE).
    Appends a '.sim.json' suffix if running in simulation mode.

    Args:
        address (str): The wallet address.
        network_name (str): The name of the network ('main' or 'test').
        simulation (bool, optional): If True, appends '.sim.json'. Defaults to False.

    Returns:
        str: The full absolute path to the file.
    """

    # 1. Determine Prefix and Directory based on type
    ft = file_type.lower()

    # Using getattr ensures it works even if config.py hasn't been reloaded/updated yet (fallback to CACHE_DIR).
    wallet_dir = getattr(Config, 'WALLET_CACHE_DIR', Config.CACHE_DIR)

    if ft in ["utxo", "utxo_store"]:
        prefix = "utxo_store"
        target_dir = wallet_dir
    elif ft in  ["used", "used_utxo", "used_utxo_store"]:
        prefix = "used_utxo_store"
        target_dir = wallet_dir
    elif ft in ["tx", "tx_store"]:
        prefix = "tx_store"
        target_dir = Config.DATABASE_DIR
    else:
        # Fallback for custom types, defaults to CACHE
        prefix = f"{file_type}_store"
        target_dir = wallet_dir
        logger.warning(f"Unknown file_type '{file_type}'. Defaulting to CACHE directory with prefix '{prefix}'.")

    # 2. Build Filename
    # Format: prefix_network_shortAddr.json
    short_address = f"{address[:4]}{address[-4:]}"
    base_name = f"{prefix}_{network_name}_{short_address}"
    
    # Add '.sim.json' suffix for simulation runs, otherwise '.json'
    suffix = ".sim.json" if simulation else ".json"
    
    filename = f"{base_name}{suffix}"
    
    # 3. Return full path
    # Config.CACHE_DIR is a pathlib.Path object, so we can use / operator
    return str(target_dir / filename)


# --- Section local UTXO and Tx Store

# --- Helper: Safe Initialization ---
def _ensure_store_exists(file_path: str, store_type: str):
    """
    Checks if a store file exists. If not, creates it with the correct
    empty JSON structure for that specific type.
    """
    if os.path.exists(file_path):
        return

    logger.info("File not found, creating empty store: {file_path}")
    
    # Define structure based on explicit type, not filename pattern

    st = store_type.lower()
    if st == "used" or st == "used_utxo":
        initial_data = {"address": "", "network": "", "used_utxos": []}
    elif st == "utxo":
        initial_data = {"address": "", "network": "", "utxos": []}
    elif st == "tx":
        initial_data = {"address": "", "network": "", "transactions": []}
    else:
        # Fallback
        initial_data = {}

    # Ensure directory exists (cache/database)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(initial_data, f, indent=4)
        logger.info(f"Initialized {store_type} store at {file_path}")
        #  give OS filesystem a moment to settle (important for cloud sync drives like Google Drives)
        time.sleep(0.5)
    except Exception as e:
        logger.error(f"Failed to create store file {file_path}: {e}")


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
    utxo_file_path      = _get_filename_for_address(str(sender_address), network_name, file_type="utxo")
    tx_file_path        = _get_filename_for_address(str(sender_address), network_name, file_type="tx")
    used_utxo_file_path = _get_filename_for_address(str(sender_address), network_name, file_type="used")

    logger.info("Initializing stores for address: {sender_address}")
    logger.info("  Using UTXO store file: {utxo_file_path}")


    # --- Robust File Handling: Ensure files exist before locking with "r+" ---
    _ensure_store_exists(utxo_file_path, "utxo")
    _ensure_store_exists(tx_file_path, "tx")
    _ensure_store_exists(used_utxo_file_path, "used")



    # Fetch all UTXOs belonging to the sender's address
    utxos_from_woc = await blockchain_api.fetch_normalized_utxos_for_address(str(sender_address))

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
    with portalocker.Lock(tx_file_path, "r+", flags=LOCK_EX, timeout=30) as f:
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