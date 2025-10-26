# blockchain_api.py
'''
Version 25-08-16
All functions related to the blockchain inquiry
V25-10-20
Change from httpx to aiohttp to solve timeout issues
'''

import logging
from typing import Dict, Any, Optional, List
import json
import asyncio

# --- MODIFIED: Import aiohttp instead of httpx ---
import aiohttp

from config import Config

# Configure logging
logger = logging.getLogger(__name__)

# --- NEW: A helper function for consistent error logging with aiohttp ---
async def _log_aiohttp_error(response: aiohttp.ClientResponse, context: str):
    """Logs detailed error information from an aiohttp response."""
    try:
        error_data = await response.json()
        error_message = error_data.get('message', str(error_data))
    except Exception:
        error_message = await response.text()
    logger.error(f"Request failed for {context}: Status {response.status}, Error: {error_message}")

# --- MODIFIED: broadcast_transaction rewritten for aiohttp ---
async def broadcast_transaction(signed_raw_tx_string: str) -> str | None:
    """
    Broadcasts a signed raw Bitcoin SV transaction to the network via WhatsOnChain API.
    """
    url = f"{Config.WOC_API_BASE_URL}/tx/raw"
    headers = {'Content-Type': 'application/json'}
    payload = {'txhex': signed_raw_tx_string}

    if Config.VERBOSE and Config.SHOW_RAW_TX:
        print(f"Payload: {signed_raw_tx_string}")
    
    # aiohttp uses a different timeout object
    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)
    
    logging.info(f"--- Broadcasting Transaction to {url} ---")
    print("--- Point 1 ---")
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload, headers=headers) as response:
                print("--- Point 2 ---")
                if Config.VERBOSE:
                    logging.info(f"HTTP Status Code: {response.status}")
                
                if response.status == 200:
                    txid = await response.text()
                    # The response is sometimes quoted, remove quotes if they exist
                    txid = txid.strip('"')
                    logging.info(f"Success: Transaction broadcasted with txid: {txid}")
                    return txid
                else:
                    await _log_aiohttp_error(response, "broadcast_transaction")
                    return None
                    
    except asyncio.TimeoutError:
        logging.error(f"Request failed: Timeout occurred after {Config.TIMEOUT_CONNECT} seconds during broadcast.")
        return None
    except aiohttp.ClientError as e:
        logging.error(f"Request failed: A network client error occurred during broadcast. Error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during broadcast: {e}")
        return None

# --- MODIFIED: fetch_raw_transaction_hex rewritten for aiohttp ---
async def fetch_raw_transaction_hex(txid: str) -> Optional[str]:
    """Fetches the raw transaction hex for a given txid from WhatsOnChain."""
    network_url = Config.NETWORK_API_ENDPOINTS[Config.ACTIVE_NETWORK_NAME]
    url = f"{network_url}/tx/{txid}/hex"
    
    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    await _log_aiohttp_error(response, f"fetch_raw_transaction_hex for {txid}")
                    return None
    except asyncio.TimeoutError:
        logger.error(f"Timeout fetching raw tx for {txid}")
        return None
    except aiohttp.ClientError as e:
        logger.error(f"ClientError fetching raw tx for {txid}: {e}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred fetching raw tx for {txid}: {e}")
        return None

# --- MODIFIED: get_transaction_status_woc rewritten for aiohttp ---
async def get_transaction_status_woc(txid: str) -> Optional[Dict[str, Any]]:
    """Get the status of a transaction by its ID from WhatsOnChain."""
    network_url = Config.NETWORK_API_ENDPOINTS[Config.ACTIVE_NETWORK_NAME]
    url = f"{network_url}/tx/{txid}"
    
    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    # Specific handling for 404 Not Found, which is a valid state for an unconfirmed tx
                    if response.status == 404:
                        logger.info(f"Transaction {txid} not found on WhatsOnChain (likely not yet confirmed).")
                    else:
                        await _log_aiohttp_error(response, f"get_transaction_status_woc for {txid}")
                    return None
    except asyncio.TimeoutError:
        logger.error(f"Timeout getting status for {txid}")
        return None
    except aiohttp.ClientError as e:
        logger.error(f"ClientError getting status for {txid}: {e}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred getting status for {txid}: {e}")
        return None

# --- MODIFIED: The rest of the functions are also converted to aiohttp ---

async def get_chain_info_woc() -> Optional[Dict[str, Any]]:
    """Get general blockchain information from WhatsOnChain."""
    network_url = Config.NETWORK_API_ENDPOINTS[Config.ACTIVE_NETWORK_NAME]
    url = f"{network_url}/chain/info"
    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    await _log_aiohttp_error(response, "get_chain_info_woc")
                    return None
    except Exception as e:
        logger.error(f"An unexpected error occurred in get_chain_info_woc: {e}")
        return None

async def get_block_header(block_hash: str) -> Optional[Dict[str, Any]]:
    """Get block header information by block hash from WhatsOnChain."""
    network_url = Config.NETWORK_API_ENDPOINTS[Config.ACTIVE_NETWORK_NAME]
    url = f"{network_url}/block/{block_hash}/header"
    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    await _log_aiohttp_error(response, f"get_block_header for {block_hash}")
                    return None
    except Exception as e:
        logger.error(f"An unexpected error occurred in get_block_header: {e}")
        return None

async def get_block_header_height(height: int) -> Optional[Dict[str, Any]]:
    """Get block header information by block height from WhatsOnChain."""
    network_url = Config.NETWORK_API_ENDPOINTS[Config.ACTIVE_NETWORK_NAME]
    url = f"{network_url}/block/height/{height}"
    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    # This endpoint returns a list, we are interested in the first element
                    data = await response.json()
                    if data and isinstance(data, list):
                        return data[0]
                    return None
                else:
                    await _log_aiohttp_error(response, f"get_block_header_height for {height}")
                    return None
    except Exception as e:
        logger.error(f"An unexpected error occurred in get_block_header_height: {e}")
        return None

async def get_merkle_path(txid: str) -> Optional[Dict[str, Any]]:
    """Get the Merkle path for a transaction by its ID from WhatsOnChain."""
    network_url = Config.NETWORK_API_ENDPOINTS[Config.ACTIVE_NETWORK_NAME]
    url = f"{network_url}/tx/{txid}/proof"
    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    await _log_aiohttp_error(response, f"get_merkle_path for {txid}")
                    return None
    except Exception as e:
        logger.error(f"An unexpected error occurred in get_merkle_path: {e}")
        return None

async def fetch_utxos_for_address(address: str) -> List[Dict[str, Any]]:
    """Fetch all unspent transaction outputs (UTXOs) for a given address."""
    network_url = Config.NETWORK_API_ENDPOINTS[Config.ACTIVE_NETWORK_NAME]
    url = f"{network_url}/address/{address}/unspent"
    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    await _log_aiohttp_error(response, f"fetch_utxos_for_address for {address}")
                    return []
    except Exception as e:
        logger.error(f"An unexpected error occurred in fetch_utxos_for_address: {e}")
        return []