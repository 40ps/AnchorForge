# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    blockchain_api.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

# blockchain_api.py
'''
Version 25-08-16
All functions related to the blockchain inquiry
V25-10-20
Change from httpx to aiohttp to solve timeout issues
'''

from typing import Dict, Any, Optional, List
import logging
import time
from collections import deque
import json
import asyncio

# --- Import aiohttp instead of httpx to solve local problems ---
import aiohttp

from anchorforge.config import Config

VERSION = 2511032020

api_call_timestamps = deque()  # Time stamps of last calls
MEASUREMENT_WINDOW_SECONDS = 60 # time for sliding average 

# Configure logging
logger = logging.getLogger(__name__)

# --- Helper to count and compute rate
def _record_api_call_and_get_rate():
    """Records the current timestamp and calculates the average rate over the window."""
    now = time.time()
    api_call_timestamps.append(now)

    # remove time stamps older than a measuring window
    while api_call_timestamps and api_call_timestamps[0] < now - MEASUREMENT_WINDOW_SECONDS:
        api_call_timestamps.popleft()

    # compute the rate
    count_in_window = len(api_call_timestamps)
    rate_per_second = count_in_window / MEASUREMENT_WINDOW_SECONDS if MEASUREMENT_WINDOW_SECONDS > 0 else 0
    rate_per_minute = rate_per_second * 60

    logger.info(f"[API Rate] Calls in last {MEASUREMENT_WINDOW_SECONDS}s: {count_in_window}. Avg Rate: {rate_per_minute:.2f} calls/min.")
    return rate_per_minute


# --- consistent error logging with aiohttp ---
async def _log_aiohttp_error_bu251109(response: aiohttp.ClientResponse, context: str):
    """Logs detailed error information from an aiohttp response."""
    try:
        error_data = await response.json()
        error_message = error_data.get('message', str(error_data))
    except Exception:
        error_message = await response.text()
    logger.error(f"Request failed for {context}: Status {response.status}, Error: {error_message}")

# --- consistent error logging with aiohttp ---
async def _log_aiohttp_error(response: aiohttp.ClientResponse, context: str):
    """Logs detailed error information from an aiohttp response."""
    try:
        error_data = await response.json()
        error_message = error_data.get('message', str(error_data))
    except Exception:
        error_message = await response.text()
    
    logger.error(f"Request failed for {context}: Status {response.status}, Error: {error_message}")

    # Check if this error is the specific UTXO-related error
    if "missing inputs" in error_message.lower() and context == "broadcast_transaction":
        logger.warning("---------------------------------------------------------------------------------")
        logger.warning(f"Hint: A 'Missing inputs' error (Status {response.status}) indicates your local UTXO store is out of sync.")
        logger.warning(f"Hint: Please check UTXO Store consistency with: python utxo_manager.py --address <YourAddress> --network {Config.ACTIVE_NETWORK_NAME} repair")
        logger.warning("---------------------------------------------------------------------------------")


async def api_call(url: str) -> Optional[Dict[str, Any]]:
    """
    Central function for an API call using aiohttp.
    Handles timeouts and basic error logging.
    """
    # Use a specific timeout for the connection
    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    await _log_aiohttp_error(response, f"api_call to {url}")
                    return None
    except aiohttp.ClientConnectorError as e:
        logger.error(f"Connection Error: Failed to connect to {url}: {e}")
        return None
    except asyncio.TimeoutError:
        logger.error(f"Timeout Error: Request to {url} timed out after {Config.TIMEOUT_CONNECT} seconds.")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred in api_call for {url}: {e}")
        return None


# --- broadcast_transaction rewritten for aiohttp ---
async def broadcast_transaction(signed_raw_tx_string: str) -> str | None:
    """
    Broadcasts a signed raw Bitcoin SV transaction to the network via WhatsOnChain API.
    """
    _record_api_call_and_get_rate()
    url = f"{Config.WOC_API_BASE_URL}/tx/raw"
    headers = {'Content-Type': 'application/json'}
    payload = {'txhex': signed_raw_tx_string}

    if Config.VERBOSE and Config.SHOW_RAW_TX:
        print(f"Payload: {signed_raw_tx_string}")
    
    # aiohttp uses a different timeout object
    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)
    
    logging.info(f"--- Broadcasting Transaction to {url} ---")
    
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload, headers=headers) as response:
                
                if Config.VERBOSE:
                    logging.info(f"HTTP Status Code: {response.status}")
                
                if response.status == 200:
                    txid_raw = await response.text()

                    # The response is sometimes quoted, remove quotes if they exist
                    # 1. leading/subsequent Space AND line breaks (\n, \r etc.)
                    txid_stripped = txid_raw.strip() 
                    txid = txid_stripped.strip('"') 
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

async def fetch_raw_transaction_hex(txid: str) -> Optional[str]:
    """Fetches the raw transaction hex for a given txid from WhatsOnChain."""
    _record_api_call_and_get_rate()
    url = f"{Config.WOC_API_BASE_URL}/tx/{txid}/hex"

    logger.info(f"API Request URL (fetch_raw_transaction): {url}")

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

async def get_transaction_status_woc(txid: str) -> Optional[Dict[str, Any]]:
    """Get the status of a transaction by its ID from WhatsOnChain."""
    _record_api_call_and_get_rate()
    
    url = f"{Config.WOC_API_BASE_URL}/tx/{txid}"

    logger.info(f"Monitor: Attempting to get status for txid {txid} from URL: {url}")

    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    logger.info(f"Monitor: Successfully received status 200 for txid {txid}.")
                    return await response.json()
                else:
                    response_text = await response.text() 
                    logger.warning(f"Monitor: Received status {response.status} for txid {txid} from {url}. Response: {response_text}")


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


async def get_chain_info_woc() -> Optional[Dict[str, Any]]:
    """Get general blockchain information from WhatsOnChain."""
    _record_api_call_and_get_rate()
    url = f"{Config.WOC_API_BASE_URL}/chain/info"
    
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
    _record_api_call_and_get_rate()
    url = f"{Config.WOC_API_BASE_URL}/block/hash/{block_hash}"
    logger.info(f"API Request URL (get_block_header): {url}")

    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if isinstance(data, dict) and "hash" in data:
                        return data
                    elif isinstance(data, list) and len(data) > 0 and "hash" in data[0]:
                        return data[0]  # Fallback for compatibility
                    else:
                        logger.warning(f"Unexpected response format for hash {url}: {data}")
                        return None
                else:
                    await _log_aiohttp_error(response, f"get_block_header for {block_hash}")
                    return None
    except Exception as e:
        logger.error(f"An unexpected error occurred in get_block_header: {e}")
        return None

async def get_block_header_height(height: int) -> Optional[Dict[str, Any]]:
    """Get block header information by block height from WhatsOnChain."""
    _record_api_call_and_get_rate()
    url = f"{Config.WOC_API_BASE_URL}/block/height/{height}"

    logger.info(f"API Request URL (get_block_header_height): {url}")

    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                logger.debug(f"API Response Status for {url}: {response.status}")
                
                if response.status == 200:
                    data = await response.json()
                    logger.debug(f"Raw API Response: {data}")

                    if isinstance(data, dict) and "height" in data: 
                        return data
                    elif isinstance(data, list) and len(data) > 0 and "height" in data[0]:
                        return data[0]  # fallback for compatibility
                    else:
                        logger.warning(f"Unexpected response format for {url}: {data}")
                        return None
                else:
                    await _log_aiohttp_error(response, f"get_block_header_height for {height}")
                    return None
    except Exception as e:
        logger.error(f"An unexpected error occurred in get_block_header_height: {e}")
        return None

async def get_tsc_merkle_path(txid: str) -> Optional[Dict[str, Any]]:
    """Get the TSC Merkle path for a transaction by its ID from WhatsOnChain."""
    _record_api_call_and_get_rate()

    url = f"{Config.WOC_API_BASE_URL}/tx/{txid}/proof/tsc"
    
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


async def get_merkle_path(txid: str) -> Optional[Dict[str, Any]]:
    """Get the Merkle path for a transaction by its ID from WhatsOnChain."""

    _record_api_call_and_get_rate()
    url = f"{Config.WOC_API_BASE_URL}/tx/{txid}/proof"
    
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

def _normalize_utxo(u: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Normalises UTXO-Dicts to Keys: txid, vout, satoshis, height(optional)
    """
    txid = u.get("txid") or u.get("tx_hash")
    vout = u.get("vout")
    if vout is None:
        vout = u.get("tx_pos")
    sats = u.get("satoshis")
    if sats is None:
        sats = u.get("value")

    if txid is None or vout is None or sats is None:
        return None

    return {
        "txid": str(txid),
        "vout": int(vout),
        "satoshis": int(sats),
        "height": int(u.get("height", -1)) if u.get("height") is not None else -1,
    }

async def fetch_utxos_for_address(address: str) -> List[Dict[str, Any]]:
    """
    RAW WhatsOnChain response
    DO NOT use directly for tx constuction
    use fetch_normalized_utxos_for_address() instead
    Fetch all unspent transaction outputs (UTXOs) for a given address."""

    _record_api_call_and_get_rate()

    url = f"{Config.WOC_API_BASE_URL}/address/{address}/unspent"
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
    
async def fetch_normalized_utxos_for_address(address: str) -> List[Dict[str, Any]]:
    utxos_raw = await fetch_utxos_for_address(address)
    utxos: List[Dict[str, Any]] = []

    for u in utxos_raw:
        nu = _normalize_utxo(u)
        if not nu:
            logger.warning(f"Skipping unrecognized UTXO format: keys={list(u.keys())}")
            continue
        utxos.append(nu)
    
    return utxos