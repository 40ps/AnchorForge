import asyncio
import json
from typing import List, Dict
from datetime import datetime, timezone
import logging

from config import Config
import utils
import blockchain_api

from bsv import PrivateKey, Network
# Note: PublicKey is also used in main audit logic, but PrivateKey is enough for wallet management here.

logger = logging.getLogger(__name__)

# --- Section local UTXO and Tx Store


def load_utxo_store():
    """Load unused UTXOs from the JSON file."""
    try:
        with open(Config.UTXO_STORE_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"address": "", "utxos": []}

def load_used_utxo_store():
    """Load used UTXOs from the JSON file."""
    try:
        with open(Config.USED_UTXO_STORE_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"address": "", "used_utxos": []}

def save_utxo_store(store):
    """Save unused UTXOs to the JSON file."""
    with open(Config.UTXO_STORE_FILE, 'w') as f:
        json.dump(store, f, indent=4)

def save_used_utxo_store(store):
    """Save used UTXOs to the JSON file."""
    with open(Config.USED_UTXO_STORE_FILE, 'w') as f:
        json.dump(store, f, indent=4)


# --- Transaction Store
'''
to add a transaction:
{
    "address": "...",
    "network": "...",
    "transactions": [
        {
            "txid": "...",
            "rawtx": "...",
            "timestamp": "...",
            "status": "pending",        
            "blockhash": null,          
            "blockheight": null,        
            "merkle_proof": null        (stores the dict from blockchain_api.get_merkle_path)
        }
    ]
}
'''
def load_tx_store():
    """Load Tx from the JSON file."""
    try:
        with open(Config.TX_STORE_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"address": "", "transactions": []}

def save_tx_store(store):
    """Save TXs to the JSON file."""
    with open(Config.TX_STORE_FILE, 'w') as f:
        json.dump(store, f, indent=4)


async def initialize_utxo_store(private_key_wif, network="main"):
    """Initialize the UTXO store with UTXOs from the blockchain."""
    if network not in Config.NETWORK_API_ENDPOINTS:
        raise ValueError("Invalid network. Use 'main' or 'test'.")
    
    # api_endpoint = Config.NETWORK_API_ENDPOINTS[network]

    priv_key = PrivateKey(private_key_wif, network=Network.TESTNET)
    sender_address = priv_key.address() 

    # Fetch all UTXOs belonging to the sender's address
    utxos_from_woc = await blockchain_api.fetch_utxos_for_address(sender_address)

    if not utxos_from_woc:
        print(f"No UTXOs found for address {sender_address}. Cannot create transaction.")
        return None

    # Ensure every UTXO has all expected keys, esp. 'height' and 'satoshis'
    formatted_utxos_for_store = []

    for utxo in utxos_from_woc:
        formatted_utxos_for_store.append({
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "satoshis": utxo["satoshis"], # Ensure 'satoshis' is used, as fetched from WOC
            "height": utxo.get("height", -1), # Use .get() for safety, though WOC usually provides it
            "used": False,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    store = {  # note, using my own utxo-json already
        "address": priv_key.address(),
        "network": network,  # Store network for reference
        "utxos": formatted_utxos_for_store
        }

    save_utxo_store(store)
    print(f"UTXO store initialized with {len(formatted_utxos_for_store)} UTXOs.")


    # Initialize empty tx_store if it doesn't exist
    tx_store = load_tx_store()
    
    # If the loaded tx_store is for a different address or empty, re-initialize its structure.
    if not tx_store.get("address") or tx_store["address"] != sender_address:
        print(f"TX store being initialized/reset for address {sender_address}.")
        tx_store = {"address": priv_key.address(), 
                    "network": network, 
                    "transactions": []}
        

    # Collect unique txids from utxos
    existing_txids = {tx["txid"] for tx in tx_store["transactions"]}
    new_txids_to_cache = {utxo["txid"] for utxo in formatted_utxos_for_store if utxo["txid"] not in existing_txids}
    
    # Add placeholder entries for new txids
    for txid_to_cache in new_txids_to_cache:
        raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(txid_to_cache)
        if raw_source_tx_hex is None:
            #print(f"Skipping UTXO {utxo['txid']}:{utxo['vout']} due to failure to fetch source transaction.")
            print(f"Skipping txid {txid_to_cache}, could not fetch raw Tx")
            continue
        
        tx_store["transactions"].append({
            "txid": txid_to_cache,
            "rawtx": raw_source_tx_hex,  # Placeholder for raw transaction data
            "timestamp": datetime.now(timezone.utc).isoformat()  # Timestamp for entry
        })
    
    save_tx_store(tx_store)
    print(f"TX store cache populated with {len(new_txids_to_cache)} new raw transactions.")


    # 4. Populate and save used_utxo_store.json
    used_store = load_used_utxo_store()
    
    # If the loaded used_store is for a different address or empty, re-initialize its structure.
    if not used_store.get("address") or used_store["address"] != sender_address:
        print(f"USED UTXO store being initialized/reset for address {sender_address}.")
        used_store = {"address": priv_key.address(), "network": network, "used_utxos": []}
        save_used_utxo_store(used_store) # Save immediately if just initialized/reset

    return store # Return the (updated) utxo_store data in memory

