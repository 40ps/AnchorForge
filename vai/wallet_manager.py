# wallet_manager.py
'''
Version 25-08-16
   make filename dependend on address used to avoid overwriting


'''
import asyncio
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import logging

from config import Config
import utils
import blockchain_api

from bsv import PrivateKey, Network

logger = logging.getLogger(__name__)

# --- Helper function for dynamic file naming
def _get_filename_for_address(address: str, network_name: str) -> str:
    """
    Generates a unique filename for the UTXO store based on the address and network.
    The filename will be 'utxo_store_<network>_<first4>...<last4>.json'.
    """
    short_address = f"{address[:4]}{address[-4:]}"
    return f"utxo_store_{network_name}_{short_address}.json"


# --- Section local UTXO and Tx Store

def load_utxo_store(file_path: str) -> Dict[str, Any]:
    """Load unused UTXOs from the JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # If the file doesn't exist or is empty, return an empty structure
        return {"address": "", "utxos": [], "network": ""}

def load_used_utxo_store(file_path: str) -> Dict[str, Any]:
    """Load used UTXOs from the JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"address": "", "used_utxos": [], "network": ""}

def save_utxo_store(store: Dict, file_path: str):
    """Save unused UTXOs to the JSON file."""
    with open(file_path, 'w') as f:
        json.dump(store, f, indent=4)

def save_used_utxo_store(store: Dict, file_path: str):
    """Save used UTXOs to the JSON file."""
    with open(file_path, 'w') as f:
        json.dump(store, f, indent=4)


# --- Transaction Store
def load_tx_store(file_path: str) -> Dict[str, Any]:
    """Load Tx from the JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"address": "", "transactions": [], "network": ""}

def save_tx_store(store: Dict, file_path: str):
    """Save TXs to the JSON file."""
    with open(file_path, 'w') as f:
        json.dump(store, f, indent=4)


def load_block_headers() -> Dict[str, Dict]:
    """
    Loads cached block headers from the BLOCK_HEADERS_FILE.
    Returns a dictionary mapping blockhash to block header data.
    """
    try:
        with open(Config.BLOCK_HEADERS_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # The block headers store is a dictionary, so it starts empty.
        return {}


def save_block_headers(headers_data: Dict[str, Dict]):
    """
    Saves block headers to the BLOCK_HEADERS_FILE.
    """
    with open(Config.BLOCK_HEADERS_FILE, 'w') as f:
        json.dump(headers_data, f, indent=4)



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

    # Fetch all UTXOs belonging to the sender's address
    utxos_from_woc = await blockchain_api.fetch_utxos_for_address(str(sender_address))

    if not utxos_from_woc:
        print(f"No UTXOs found for address {sender_address}. Cannot create transaction.")
        return None

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

    # Load and update the UTXO store
    utxo_store = load_utxo_store(utxo_file_path)
    utxo_store["address"] = str(sender_address)
    utxo_store["network"] = network_name
    utxo_store["utxos"] = formatted_utxos_for_store
    save_utxo_store(utxo_store, utxo_file_path)
    print(f"UTXO store initialized with {len(formatted_utxos_for_store)} UTXOs.")

    # Initialize empty tx_store if it doesn't exist
    tx_store = load_tx_store(tx_file_path)
    if not tx_store.get("address") or tx_store["address"] != str(sender_address) or tx_store["network"] != network_name:
        print(f"TX store being initialized/reset for address {sender_address}.")
        tx_store = {"address": str(sender_address),
                    "network": network_name,
                    "transactions": []}
    
    # Collect unique txids from utxos
    existing_txids = {tx["txid"] for tx in tx_store["transactions"]}
    new_txids_to_cache = {utxo["txid"] for utxo in formatted_utxos_for_store if utxo["txid"] not in existing_txids}
    
    # Add placeholder entries for new txids
    for txid_to_cache in new_txids_to_cache:
        raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(txid_to_cache)
        if raw_source_tx_hex is None:
            print(f"Skipping txid {txid_to_cache}, could not fetch raw Tx")
            continue
        
        tx_store["transactions"].append({
            "txid": txid_to_cache,
            "rawtx": raw_source_tx_hex,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    
    save_tx_store(tx_store, tx_file_path)
    print(f"TX store cache populated with {len(new_txids_to_cache)} new raw transactions.")

    # Populate and save used_utxo_store.json
    used_store = load_used_utxo_store(used_utxo_file_path)
    if not used_store.get("address") or used_store["address"] != str(sender_address) or used_store["network"] != network_name:
        print(f"USED UTXO store being initialized/reset for address {sender_address}.")
        used_store = {"address": str(sender_address), "network": network_name, "used_utxos": []}
        save_used_utxo_store(used_store, used_utxo_file_path)

    return utxo_store # Return the (updated) utxo_store data in memory
