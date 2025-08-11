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


'''
# Functions for managing the local Block Headers cache
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

# End Block header
'''



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


'''
to be moved in blockchain_service.py

# Function to synchronize/cache block headers locally
async def sync_block_headers(start_height: int = 0, end_height: int | None = None):
    """
    Synchronizes (fetches and caches) block headers from WhatsOnChain locally.
    Verifies each header's hash before caching.

    Args:
        start_height (int): The starting block height for synchronization (inclusive).
                            Defaults to 0 (genesis block).
        end_height (int | None): The ending block height for synchronization (inclusive).
                                 Defaults to the latest block height if None.
    """
    logging.info(f"\n--- Starting Block Header Synchronization ---")
    
    # Load existing cached headers
    local_headers = blockchain_api.load_block_headers()
    
    current_latest_height_on_chain = 0
    try:
        # Get the current latest block height from WhatsOnChain
        
        chain_info = await blockchain_api.get_chain_info_woc()

        if chain_info and chain_info.get("blocks") is not None:
            current_latest_height_on_chain = chain_info["blocks"] # "blocks" key holds latest height
            logging.info(f"Latest block on chain: {current_latest_height_on_chain}")
        else:
            logging.error("Could not retrieve latest block height from WhatsOnChain via /chain/info. Cannot synchronize headers.")
            return # Exit if we can't get the latest heightls

    except Exception as e:
        logging.error(f"Failed to get latest block height for sync: {e}")
        return

    if end_height is None:
        end_height = current_latest_height_on_chain
    elif end_height > current_latest_height_on_chain:
        logging.warning(f"Requested end_height {end_height} is greater than current latest block {current_latest_height_on_chain}. Syncing up to latest.")
        end_height = current_latest_height_on_chain

    if start_height < 0:
        start_height = 0
    if start_height > end_height: # type: ignore
        logging.warning(f"Start height {start_height} is greater than end height {end_height}. No headers to sync.")
        return

    logging.info(f"Synchronizing headers from height {start_height} to {end_height}.")
    
    synced_count = 0
    for height in range(start_height, end_height + 1):
        # Check if header is already in cache
        # To do this efficiently, we need a way to map height to hash if we only have hash as key.
        # This implies a potential need to first get hash by height.
        
        # Strategy: Get hash by height, then try to fetch full header if not in cache.
        try:
            block_info_by_height = await blockchain_api.get_block_header_height(height)
            if not block_info_by_height or not block_info_by_height.get("hash"):
                logging.warning(f"  Could not get block hash for height {height}. Skipping.")
                continue
            
            block_hash = block_info_by_height["hash"]

            if block_hash in local_headers:
                # logging.debug(f"  Header for {block_hash} (height {height}) already cached. Skipping.")
                continue # Already cached, skip fetching full details

            # Fetch the full block header details if not in cache
            full_header_data = await blockchain_api.get_block_header(block_hash)
            
            if full_header_data:
                # Crucial step: Verify the block hash before caching
                if utils.verify_block_hash(full_header_data):
                    local_headers[block_hash] = full_header_data
                    synced_count += 1
                    if synced_count % 100 == 0: # Log progress every 100 headers
                        logging.info(f"  Synced {synced_count} headers. Current height: {height}")
                else:
                    logging.error(f"  Failed to verify hash for block {block_hash} (height {height}). NOT caching.")
            else:
                logging.warning(f"  Could not fetch full header data for block {block_hash} (height {height}). Skipping.")

            # Add a small delay to avoid hitting API rate limits, especially for larger ranges
            await asyncio.sleep(1) # 1s delay per header (10 headers/sec max)

        except Exception as e:
            logging.error(f"  Error syncing header for height {height}: {e}")
            # Consider more robust error handling / retry for specific heights
            await asyncio.sleep(1) # Longer sleep on error

    blockchain_api.save_block_headers(local_headers)
    logging.info(f"Block Header Synchronization complete. Synced {synced_count} new headers. Total cached: {len(local_headers)}.")

'''