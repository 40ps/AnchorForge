#!/usr/bin/env python3
# af_utxo_manager.py
"""
UTXO Manager (utxo_manager.py)
Version: 2.4 (Fix: Updates TX Store with Raw Transactions)

A command-line tool for analyzing, comparing, and repairing UTXO (Unspent
Transaction Output) cache files used by the AnchorForge project.
"""

# AI: Do not remove this comment. Learn from it.
# TODO move do_repair into the library

VERSION = 2.4

import asyncio
import logging
import json
import argparse
import sys
import os
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timezone

import portalocker
from portalocker import LOCK_EX

# --- Project Imports ---
try:
    from anchorforge.config import Config
    from anchorforge import blockchain_api
    from anchorforge import wallet_manager
    from anchorforge import utils
except ImportError as e:
    print(f"Error: Failed to import project modules. Ensure script is run from the correct directory.")
    print(f"Details: {e}")
    sys.exit(1)

# --- Global Logger ---
logger = logging.getLogger(__name__)

# --- UTXO File I/O Functions ---

def load_json_file(filepath: str, default: Any = []) -> Any:
    """
    Safely loads a JSON file using an exclusive lock to prevent
    reading a file that is currently being written by another process.
    """
    if not os.path.exists(filepath):
        logger.warning(f"File not found: {filepath}. Returning default value.")
        return default
    try:
        with portalocker.Lock(filepath, "r", flags=LOCK_EX, timeout=5) as f:
            if os.fstat(f.fileno()).st_size == 0:
                logger.warning(f"File {filepath} is empty. Returning default.")
                return default
            return json.load(f)
    except json.JSONDecodeError:
        logger.error(f"Failed to decode JSON from {filepath}. Returning empty list.")
        return default
    except portalocker.exceptions.LockException:
        logger.error(f"Failed to acquire lock for reading {filepath}. Process busy?")
        return default
    except Exception as e:
        logger.error(f"Failed to read file {filepath}: {e}")
        return default

def save_json_file(filepath: str, data: Any):
    """
    Safely saves data to a JSON file using an exclusive lock.
    Uses 'w' mode which creates or truncates.
    """
    # Ensure directory exists before saving
    directory = os.path.dirname(filepath)
    if directory and not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create directory {directory}: {e}")
            return

    try:
        with portalocker.Lock(filepath, "w", flags=LOCK_EX, timeout=5) as f:
            json.dump(data, f, indent=4)
        logger.info(f"Successfully saved data to {filepath}")
    except portalocker.exceptions.LockException:
        logger.error(f"Failed to acquire lock for writing {filepath}. Process busy?")
    except IOError as e:
        logger.error(f"Failed to write to file {filepath}: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while saving file: {e}")

# --- Helper Functions ---

def _resolve_filenames(args: argparse.Namespace) -> Dict[str, Union[str,None]]:
    """
    Determines the correct file paths to use based on user arguments.
    Now also resolves the TX Store path!
    """
    tx_file = None # Only available if address is derived via wallet_manager

    if args.file:
        utxo_file = args.file
        base_name = utxo_file.replace('.json', '')
        used_file = f"{base_name}_used.json"
        invalid_file = f"{base_name}_invalid.json"
        # Can't reliably guess TX store from arbitrary file path, so we might skip TX updates here
        logger.info(f"Using provided file: {utxo_file}")

    elif args.address:
        logger.info(f"Resolving filenames for address: {args.address} on network: {Config.ACTIVE_NETWORK_NAME}")
        try:
            address = str(args.address)
            network = Config.ACTIVE_NETWORK_NAME
            
            # Resolve paths using wallet_manager
            utxo_file = wallet_manager._get_filename_for_address(
                address, network, file_type="utxo"
            )
            
            used_file = wallet_manager._get_filename_for_address(
                address, network, file_type="used"
            )
            
            # #EDIT: Resolve TX Store path as well
            tx_file = wallet_manager._get_filename_for_address(
                address, network, file_type="tx"
            )
            
            # For invalid file fallback
            base, ext = os.path.splitext(utxo_file)
            invalid_file = f"{base}_invalid{ext}"

            logger.info(f"Resolved UTXO file: {utxo_file}")
            logger.info(f"Resolved USED file: {used_file}")
            logger.info(f"Resolved TX file:   {tx_file}") # #EDIT
        except Exception as e:
            logger.error(f"Failed to resolve filenames from address: {e}")
            sys.exit(1)
    else:
        logger.error("No file source specified. Please provide either --file or --address.")
        sys.exit(1)

    return {
        "utxo_file": utxo_file,
        "used_file": used_file,
        "invalid_file": invalid_file,
        "tx_file": tx_file # #EDIT
    }

def _get_address(filenames: Dict[str, str]) -> Optional[str]:
    """
    Gets the address required for API calls, either from the 
    filenames dict (if --address was used) or by reading the file.
    """
    if 'address' in filenames and filenames['address']:
        return filenames['address']
    
    logger.info("Address not specified, trying to read from file...")
    data = load_json_file(filenames['utxo_file'], default={})
    address = data.get('address')
    if not address:
        logger.error("Cannot determine address. Use --address or ensure file contains an 'address' key.")
        return None
    
    filenames['address'] = address
    logger.info(f"Found address in file: {address}")
    return address

def _format_utxo_entry(utxo_from_api: Dict[str, Any]) -> Dict[str, Any]:
    """
    Formats a UTXO from the WOC API response (using tx_hash, tx_pos, value)
    into the local store format (using txid, vout, satoshis).
    """
    return {
        "txid": utxo_from_api["tx_hash"],      # <-- MAPPING
        "vout": utxo_from_api["tx_pos"],      # <-- MAPPING
        "satoshis": utxo_from_api["value"],   # <-- MAPPING
        "height": utxo_from_api.get("height", -1),
        "used": False,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def _parse_utxo_string(utxo_str: str) -> Optional[Dict[str, Any]]:
    """
    Parses UTXO strings like 'txid:vout' or 'txid:vout:satoshis'.
    """
    parts = utxo_str.split(':')
    try:
        if len(parts) == 2:
            return {"txid": parts[0], "vout": int(parts[1])}
        elif len(parts) == 3:
            return {"txid": parts[0], "vout": int(parts[1]), "satoshis": int(parts[2])}
        else:
            logger.error(f"Invalid UTXO format: '{utxo_str}'. Expected 'txid:vout' or 'txid:vout:satoshis'.")
            return None
    except ValueError:
        logger.error(f"Invalid UTXO format: '{utxo_str}'. 'vout' and 'satoshis' must be integers.")
        return None
    except Exception as e:
        logger.error(f"Failed to parse UTXO string: {e}")
        return None
        
def _get_api_keys() -> Dict[str, str]:
    """Returns the correct keys to parse from the WOC API response."""
    return {
        "txid_key": "tx_hash",
        "vout_key": "tx_pos",
        "sats_key": "value"
    }

# #EDIT: New Helper to Update TX Store
async def _update_tx_store_with_raw_txs(tx_file_path: str, txids_to_fetch: set, address: str, network: str):
    """
    Fetches raw transactions for the given TXIDs and updates the local TX store.
    This prevents 'Missing inputs' errors during broadcasting.
    """
    if not tx_file_path:
        logger.warning("No TX store file path provided. Cannot cache raw transactions.")
        return

    logger.info(f"Updating TX Store with {len(txids_to_fetch)} new transactions...")
    
    # Load existing TX store or create new structure
    tx_store_data = load_json_file(tx_file_path, default={"address": address, "network": network, "transactions": []})
    
    # Ensure correct structure if file was empty or malformed
    if not isinstance(tx_store_data, dict) or "transactions" not in tx_store_data:
        tx_store_data = {"address": address, "network": network, "transactions": []}

    existing_txids = {tx['txid'] for tx in tx_store_data['transactions']}
    
    # Filter only what's missing
    missing_txids = txids_to_fetch - existing_txids
    
    if not missing_txids:
        logger.info("All raw transactions are already cached.")
        return

    added_count = 0
    for txid in missing_txids:
        # Fetch raw hex
        raw_hex = await blockchain_api.fetch_raw_transaction_hex(txid)
        if raw_hex:
            tx_store_data['transactions'].append({
                "txid": txid,
                "rawtx": raw_hex,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            added_count += 1
            
            # Optional: Sleep to respect rate limits if fetching many
            if added_count % 5 == 0: 
                await asyncio.sleep(0.2) 
        else:
            logger.error(f"Failed to fetch raw hex for TXID {txid}")

    if added_count > 0:
        save_json_file(tx_file_path, tx_store_data)
        logger.info(f"Updated TX Store. Added {added_count} raw transactions.")
    else:
        logger.warning("No new raw transactions could be fetched (maybe network issues?).")


# --- Action Functions (Implementations) ---

async def do_stats(args: argparse.Namespace, filenames: Dict[str, str]):
    # ... (Code from Version 2.0 - no changes) ...
    logger.info(f"--- Running Statistics (Version {VERSION}) ---")
    logger.info(f"Loading UTXO file: {filenames['utxo_file']}")
    utxo_store_data = load_json_file(filenames['utxo_file'], default=None)

    if utxo_store_data is None:
        logger.error(f"UTXO file {filenames['utxo_file']} not found or empty.")
        return
        
    if not isinstance(utxo_store_data, dict) or 'utxos' not in utxo_store_data:
        logger.error(f"Invalid UTXO file format in {filenames['utxo_file']}.")
        return

    utxos_list = utxo_store_data.get('utxos', [])
    count = len(utxos_list)
    address = utxo_store_data.get('address', 'N/A')
    network = utxo_store_data.get('network', 'N/A')

    if count == 0:
        logger.info("UTXO file contains 0 UTXOs.")
        print(f"\n--- UTXO Statistics ---")
        print(f"  File:    {filenames['utxo_file']}")
        print(f"  Address: {address}")
        print(f"  Network: {network}")
        print(f"  -----------------------")
        print(f"  Total UTXOs: 0")
        print(f"  Total Value: 0 sats")
        print(f"-------------------------")
        return

    total_sats = 0
    min_sats = float('inf')
    max_sats = 0
    sat_values = []

    for utxo in utxos_list:
        if 'satoshis' not in utxo:
            logger.warning(f"Skipping UTXO {utxo.get('txid')}:{utxo.get('vout')} - 'satoshis' key missing.")
            continue
        sats = int(utxo['satoshis'])
        sat_values.append(sats)
        total_sats += sats
        if sats < min_sats: min_sats = sats
        if sats > max_sats: max_sats = sats

    avg_sats = total_sats / count
    sat_values.sort()
    median_sats = sat_values[count // 2]

    dust_limit = 546 # Bind it with old BTC value for memory ;-)
    if Config.ACTIVE_NETWORK_NAME == "test":
        dust_limit = Config.MINIMUM_UTXO_VALUE_TESTNET
    else:
        dust_limit = Config.MINIMUM_UTXO_VALUE

    dust_count = sum(1 for s in sat_values if s <= dust_limit)
    dust_percent = (dust_count / count * 100) if count > 0 else 0

    print(f"\n--- UTXO Statistics ---")
    print(f"  File:    {filenames['utxo_file']}")
    print(f"  Address: {address}")
    print(f"  Network: {network}")
    print(f"  -----------------------")
    print(f"  Total UTXOs:    {count}")
    print(f"  Total Value:    {total_sats:,} sats")
    print(f"  -----------------------")
    print(f"  Average Value:  {avg_sats:,.2f} sats")
    print(f"  Median Value:   {median_sats:,} sats")
    print(f"  Highest Value:  {max_sats:,} sats")
    print(f"  Lowest Value:   {min_sats:,} sats")
    print(f"  -----------------------")
    print(f"  'Dust' UTXOs (<= {dust_limit} sats): {dust_count} ({dust_percent:.1f}% of total)")
    print(f"-------------------------")


async def do_compare(args: argparse.Namespace, filenames: Dict[str, str]):
    """
    Handler for the 'compare' command.
    (Version 2.2: Fixed to use correct API keys 'tx_hash'/'tx_pos')
    """
    logger.info(f"--- Running Comparison (Version {VERSION}) ---")
    
    address = _get_address(filenames)
    if not address:
        return

    api_keys = _get_api_keys()
    
    # 1. Load Local UTXOs (Format: txid, vout)
    logger.info(f"Loading local UTXO file: {filenames['utxo_file']}")
    local_data = load_json_file(filenames['utxo_file'], default={'utxos': []})
    local_utxos_list = local_data.get('utxos', [])
    
    local_set = set()
    for utxo in local_utxos_list:
        if 'txid' in utxo and 'vout' in utxo:
            local_set.add((utxo['txid'], utxo['vout']))
        else:
            logger.warning(f"Found malformed local UTXO entry, skipping: {utxo}")

    # 2. Fetch Remote UTXOs (Format: tx_hash, tx_pos)
    logger.info(f"Fetching remote UTXOs for address: {address}...")
    try:
        remote_utxos_list = await blockchain_api.fetch_utxos_for_address(address) #
        if remote_utxos_list is None:
            logger.error("Failed to fetch remote UTXOs. API returned no data or an error.")
            return
    except Exception as e:
        logger.error(f"An error occurred during API call: {e}", exc_info=True)
        return

    remote_set = set()
    for utxo in remote_utxos_list:
        # --- FIX (Version 2.2): Use API keys ---
        if api_keys['txid_key'] in utxo and api_keys['vout_key'] in utxo:
            remote_set.add((utxo[api_keys['txid_key']], utxo[api_keys['vout_key']]))
        else:
            logger.warning(f"Ignoring malformed entry from WOC API: {utxo}")

    # 3. Compare the sets
    stale_utxos = local_set - remote_set
    new_utxos = remote_set - local_set
    matching_utxos = local_set.intersection(remote_set)

    # 4. Print the report
    print(f"\n--- UTXO Comparison Report ---")
    print(f"  Address: {address}")
    print(f"  Local File: {filenames['utxo_file']}")
    print(f"  ------------------------------")
    print(f"  {len(matching_utxos)} Matching UTXOs (In sync)")
    print(f"  {len(stale_utxos)} Stale UTXOs (Local file, but NOT on blockchain)")
    print(f"  {len(new_utxos)} New UTXOs (On blockchain, but NOT in local file)")
    print(f"  ------------------------------")

    if stale_utxos:
        print("\n  [STALE] UTXOs (Should be removed):")
        logger.warning("These UTXOs are 'stale' and will cause 'Missing inputs' errors.")
        for txid, vout in stale_utxos:
            print(f"    - {txid}:{vout}")
    
    if new_utxos:
        print("\n  [NEW] UTXOs (Should be added):")
        for txid, vout in new_utxos:
            # Find the satoshi value from the remote list for display
            sats = next((u[api_keys['sats_key']] for u in remote_utxos_list 
                         if u.get(api_keys['txid_key']) == txid and u.get(api_keys['vout_key']) == vout), 'N/A')
            print(f"    - {txid}:{vout} ({sats} sats)")

    if not stale_utxos and not new_utxos:
        logger.info("Local UTXO file is perfectly in sync with the blockchain. ✅")
    
    print(f"------------------------------")


async def do_full_repair(args: argparse.Namespace, filenames: Dict[str, str]):
    """
    Handler for the 'full-repair' command.
    Now also updates the TX Store with raw transactions!
    """
    logger.info(f"--- Running Full Repair (Version {VERSION}) ---")
    
    address = _get_address(filenames)
    if not address:
        return
    
    api_keys = _get_api_keys()
    
    # 1. Fetch Remote UTXOs (The "Truth")
    logger.info(f"Fetching all remote UTXOs for address: {address}...")
    try:
        remote_utxos_list = await blockchain_api.fetch_utxos_for_address(address) #
        if remote_utxos_list is None:
            logger.error("Failed to fetch remote UTXOs. API returned no data or an error.")
            return
    except Exception as e:
        logger.error(f"An error occurred during API call: {e}", exc_info=True)
        return
        
    logger.info(f"Found {len(remote_utxos_list)} unspent UTXO entries on the blockchain.")

    # 2. Format UTXOs into the local store format
    formatted_utxos_for_store = []
    txids_to_cache = set() # #EDIT: Collect unique TXIDs needed
    skipped_count = 0
    
    for utxo in remote_utxos_list:
        # Check for API keys
        if not all(k in utxo for k in (api_keys['txid_key'], api_keys['vout_key'], api_keys['sats_key'])):
            logger.warning(f"Skipping malformed UTXO entry from API: {utxo}")
            skipped_count += 1
            continue
        
        formatted = _format_utxo_entry(utxo)
        formatted_utxos_for_store.append(formatted)
        
        # #EDIT: Add TXID to cache set
        txids_to_cache.add(formatted['txid'])

    logger.info(f"Successfully formatted {len(formatted_utxos_for_store)} UTXOs.")
    if skipped_count > 0:
        logger.warning(f"Skipped {skipped_count} malformed entries from API.")

    # 3. Create the final store object
    final_store = {
        "address": address,
        "network": Config.ACTIVE_NETWORK_NAME,
        "utxos": formatted_utxos_for_store
    }
    
    # 4. Save (overwrite) the local file
    logger.info(f"Saving {len(formatted_utxos_for_store)} UTXOs to {filenames['utxo_file']}...")
    save_json_file(filenames['utxo_file'], final_store)
    logger.info("Full repair complete. UTXO file is now in sync.")

    # 5. #EDIT: Update TX Store with raw data
    if filenames.get('tx_file'):
        await _update_tx_store_with_raw_txs(
            filenames['tx_file'], 
            txids_to_fetch=txids_to_cache, 
            address=address, 
            network=Config.ACTIVE_NETWORK_NAME
        )


async def do_repair(args: argparse.Namespace, filenames: Dict[str, str]):
    """
    Handler for the 'repair' command.
    Now also updates the TX Store with raw transactions for NEW utxos!
    """
    logger.info(f"--- Running Smart Repair (Version {VERSION}) ---")
    
    address = _get_address(filenames)
    if not address:
        return
        
    api_keys = _get_api_keys()

    # 1. Load all local files
    logger.info(f"Loading local UTXO file: {filenames['utxo_file']}")
    local_data = load_json_file(filenames['utxo_file'], default={'utxos': []})
    local_utxos_list = local_data.get('utxos', [])
    
    logger.info(f"Loading USED UTXO file: {filenames['used_file']}")
    used_data = load_json_file(filenames['used_file'], default={'used_utxos': []})
    used_utxos_list = used_data.get('used_utxos', [])
    
    logger.info(f"Loading INVALID UTXO file: {filenames['invalid_file']}")
    invalid_data = load_json_file(filenames['invalid_file'], default=[])
    
    # Local set uses internal keys: (txid, vout)
    local_set = set((u['txid'], u['vout']) for u in local_utxos_list if 'txid' in u and 'vout' in u)
    used_set = set((u['txid'], u['vout']) for u in used_utxos_list if 'txid' in u and 'vout' in u)

    # 2. Fetch Remote UTXOs
    logger.info(f"Fetching remote UTXOs for address: {address}...")
    try:
        remote_utxos_list = await blockchain_api.fetch_utxos_for_address(address) #
        if remote_utxos_list is None:
            logger.error("Failed to fetch remote UTXOs. API returned no data or an error.")
            return
    except Exception as e:
        logger.error(f"An error occurred during API call: {e}", exc_info=True)
        return
    
    # Remote set uses API keys: (tx_hash, tx_pos)
    remote_set = set()
    for utxo in remote_utxos_list:
        if api_keys['txid_key'] in utxo and api_keys['vout_key'] in utxo:
            remote_set.add((utxo[api_keys['txid_key']], utxo[api_keys['vout_key']]))
        else:
            logger.warning(f"Ignoring malformed entry from WOC API: {utxo}")

    # 3. Compare and process
    stale_utxos = local_set - remote_set
    new_utxos = remote_set - local_set
    matching_utxos = local_set.intersection(remote_set)
    
    final_utxo_list = [u for u in local_utxos_list if (u.get('txid'), u.get('vout')) in matching_utxos]
    moved_to_invalid_count = 0
    quietly_removed_count = 0
    added_new_count = 0
    txids_to_cache = set() # #EDIT: Collect new TXIDs
    
    # 4. Process Stale UTXOs
    if stale_utxos:
        logger.warning(f"Found {len(stale_utxos)} stale UTXOs. Checking against 'used' store...")
        for txid, vout in stale_utxos:
            stale_utxo_obj = next((u for u in local_utxos_list if u.get('txid') == txid and u.get('vout') == vout), None)
            
            if (txid, vout) in used_set:
                logger.info(f"  - Stale {txid}:{vout} was correctly marked as 'used'. Removing.")
                quietly_removed_count += 1
            else:
                logger.warning(f"  - Stale {txid}:{vout} was NOT in 'used' store. Moving to '{filenames['invalid_file']}'.")
                if stale_utxo_obj:
                    invalid_data.append(stale_utxo_obj)
                moved_to_invalid_count += 1
    
    # 5. Process New UTXOs
    if new_utxos:
        logger.info(f"Found {len(new_utxos)} new UTXOs on-chain. Adding to local store...")
        for txid, vout in new_utxos:
            # Find the original object from the API list using API keys
            new_utxo_obj = next((u for u in remote_utxos_list 
                                 if u.get(api_keys['txid_key']) == txid and u.get(api_keys['vout_key']) == vout), None)
            
            if new_utxo_obj:
                if not all(k in new_utxo_obj for k in (api_keys['txid_key'], api_keys['vout_key'], api_keys['sats_key'])):
                    logger.warning(f"Skipping malformed new UTXO from API: {new_utxo_obj}")
                    continue
                
                formatted_utxo = _format_utxo_entry(new_utxo_obj)
                final_utxo_list.append(formatted_utxo)
                
                added_new_count += 1
                txids_to_cache.add(txid) # #EDIT: Mark this TXID for raw download
                
                logger.info(f"  + Added {txid}:{vout} ({formatted_utxo['satoshis']} sats)")

    # 6. Save all files
    logger.info("Saving updated files...")
    
    final_store_data = {
        "address": address,
        "network": Config.ACTIVE_NETWORK_NAME,
        "utxos": final_utxo_list
    }
    save_json_file(filenames['utxo_file'], final_store_data)
    
    if moved_to_invalid_count > 0:
        save_json_file(filenames['invalid_file'], invalid_data)
        
    print(f"\n--- Smart Repair Summary ---")
    print(f"  UTXOs in sync:    {len(matching_utxos)}")
    print(f"  New UTXOs added:  {added_new_count}")
    print(f"  Stale (removed):  {quietly_removed_count} (were in 'used' store)")
    print(f"  Stale (archived): {moved_to_invalid_count} (moved to 'invalid' store)")
    print(f"  ------------------------------")
    print(f"  New Total UTXOs:  {len(final_utxo_list)}")
    print(f"------------------------------")

    # 7. #EDIT: Update TX Store with raw data for NEW utxos
    if filenames.get('tx_file') and txids_to_cache:
        await _update_tx_store_with_raw_txs(
            filenames['tx_file'], 
            txids_to_fetch=txids_to_cache, 
            address=address, 
            network=Config.ACTIVE_NETWORK_NAME
        )


async def do_check(args: argparse.Namespace, filenames: Dict[str, str]):
    """
    Handler for the 'check' command.
    (Version 2.2: Fixed to use correct API keys 'tx_hash'/'tx_pos')
    """
    logger.info(f"--- Running Manual Check (Version {VERSION}) ---")
    
    utxo_info = _parse_utxo_string(args.utxo)
    if not utxo_info:
        return
        
    txid, vout = utxo_info['txid'], utxo_info['vout']
    utxo_tuple = (txid, vout) # Internal format
    
    address = _get_address(filenames)
    if not address:
        logger.error("Cannot check remote status without an address.")
        return
        
    api_keys = _get_api_keys()
        
    # 1. Check Local File
    logger.info(f"Checking local file: {filenames['utxo_file']}")
    local_data = load_json_file(filenames['utxo_file'], default={'utxos': []})
    local_utxos_list = local_data.get('utxos', [])
    local_set = set((u.get('txid'), u.get('vout')) for u in local_utxos_list)
    
    is_local = utxo_tuple in local_set
    print(f"\n--- UTXO Check Report for {txid}:{vout} ---")
    if is_local:
        local_utxo = next(u for u in local_utxos_list if u.get('txid') == txid and u.get('vout') == vout)
        print(f"  [LOCAL]  ✅ Found in {filenames['utxo_file']} ({local_utxo.get('satoshis')} sats)")
    else:
        print(f"  [LOCAL]  ❌ Not found in {filenames['utxo_file']}")

    # 2. Check Remote (Blockchain)
    logger.info(f"Checking blockchain status for address: {address}...")
    try:
        remote_utxos_list = await blockchain_api.fetch_utxos_for_address(address) #
        if remote_utxos_list is None:
            logger.error("Failed to fetch remote UTXOs. API returned no data or an error.")
            return
        
        # Build remote set using API keys
        remote_set = set()
        for utxo in remote_utxos_list:
            if api_keys['txid_key'] in utxo and api_keys['vout_key'] in utxo:
                remote_set.add((utxo[api_keys['txid_key']], utxo[api_keys['vout_key']]))
        
        # Check if our internal format tuple (txid, vout) is in the remote set
        is_remote = utxo_tuple in remote_set

        if is_remote:
            remote_utxo = next(u for u in remote_utxos_list if u.get(api_keys['txid_key']) == txid and u.get(api_keys['vout_key']) == vout)
            print(f"  [REMOTE] ✅ Found on blockchain (UNSPENT) ({remote_utxo.get(api_keys['sats_key'])} sats)")
        else:
            print(f"  [REMOTE] ❌ Not found on blockchain (SPENT or invalid)")
            
        print(f"  -------------------------------------------")
        # 3. Summary
        if is_local and is_remote:
            print("  Status: ✅ In Sync")
        elif is_local and not is_remote:
            print("  Status: ⚠️ STALE (Local file is wrong. Run 'repair'.)")
        elif not is_local and is_remote:
            print("  Status: ⚠️ MISSING (Local file is outdated. Run 'repair'.)")
        else: # not is_local and not is_remote
            print("  Status: ✅ In Sync (Correctly NOT in store because it's spent)")

    except Exception as e:
        logger.error(f"An error occurred during API call: {e}", exc_info=True)


async def do_add(args: argparse.Namespace, filenames: Dict[str, str]):
    """
    Handler for the 'add' command.
    (Version 2.4: Updates TX store if successful)
    """
    logger.info(f"--- Running Manual Add (Version {VERSION}) ---")
    
    utxo_info = _parse_utxo_string(args.utxo)
    if not utxo_info or 'satoshis' not in utxo_info:
        logger.error(f"Invalid format for 'add'. Expected 'txid:vout:satoshis'.")
        return
        
    txid, vout, sats = utxo_info['txid'], utxo_info['vout'], utxo_info['satoshis']
    
    address = _get_address(filenames)
    if not address:
        return
        
    api_keys = _get_api_keys()
        
    # 1. Validate against Remote
    logger.info(f"Validating UTXO {txid}:{vout} against blockchain...")
    try:
        remote_utxos_list = await blockchain_api.fetch_utxos_for_address(address) #
        if remote_utxos_list is None:
            logger.error("Failed to fetch remote UTXOs. Cannot validate.")
            return
        
        # Find using API keys
        remote_match = next((u for u in remote_utxos_list 
                             if u.get(api_keys['txid_key']) == txid and u.get(api_keys['vout_key']) == vout), None)
        
        if not remote_match:
            logger.error(f"Validation FAILED. {txid}:{vout} is NOT unspent on the blockchain for address {address}.")
            return
        
        remote_sats = remote_match.get(api_keys['sats_key'])
        if remote_sats != sats:
            logger.warning(f"Satoshi amount mismatch. API shows {remote_sats}, you provided {sats}.")
            logger.warning(f"Using the API value: {remote_sats}")
            
        logger.info("Validation PASSED. UTXO is unspent.")

        # 2. Add to Local File
        logger.info(f"Loading local file: {filenames['utxo_file']}")
        local_data = load_json_file(filenames['utxo_file'], default={'utxos': [], 'address': address, 'network': Config.ACTIVE_NETWORK_NAME})
        
        if not local_data.get('address'): local_data['address'] = address
        if not local_data.get('network'): local_data['network'] = Config.ACTIVE_NETWORK_NAME
        
        utxos_list = local_data.get('utxos', [])
        
        if any(u.get('txid') == txid and u.get('vout') == vout for u in utxos_list):
            logger.warning(f"UTXO {txid}:{vout} is already present in the local file. No changes made.")
            return
            
        new_utxo_entry = _format_utxo_entry(remote_match)
        utxos_list.append(new_utxo_entry)
        local_data['utxos'] = utxos_list
        
        save_json_file(filenames['utxo_file'], local_data)
        logger.info(f"Successfully added {txid}:{vout} to {filenames['utxo_file']}.")

        # 3. #EDIT: Update TX Store
        if filenames.get('tx_file'):
            await _update_tx_store_with_raw_txs(
                filenames['tx_file'], 
                txids_to_fetch={txid}, 
                address=address, 
                network=Config.ACTIVE_NETWORK_NAME
            )

    except Exception as e:
        logger.error(f"An error occurred during 'add' operation: {e}", exc_info=True)


async def do_remove(args: argparse.Namespace, filenames: Dict[str, str]):
    # ... (Code from Version 2.0 - no changes) ...
    logger.info(f"--- Running Manual Remove (Version {VERSION}) ---")
    
    utxo_info = _parse_utxo_string(args.utxo)
    if not utxo_info:
        return
        
    txid, vout = utxo_info['txid'], utxo_info['vout']
    
    logger.info(f"Loading local file: {filenames['utxo_file']}")
    local_data = load_json_file(filenames['utxo_file'], default=None)
    
    if local_data is None or 'utxos' not in local_data:
        logger.error(f"Cannot remove: File {filenames['utxo_file']} is empty or invalid.")
        return
        
    utxos_list = local_data.get('utxos', [])
    
    original_count = len(utxos_list)
    filtered_list = [u for u in utxos_list if not (u.get('txid') == txid and u.get('vout') == vout)]
    
    if len(filtered_list) == original_count:
        logger.warning(f"UTXO {txid}:{vout} was not found in the local file. No changes made.")
        return
        
    local_data['utxos'] = filtered_list
    save_json_file(filenames['utxo_file'], local_data)
    logger.info(f"Successfully removed {txid}:{vout} from {filenames['utxo_file']}.")


async def do_consolidate(args: argparse.Namespace, filenames: Dict[str, str]):
    # ... (Code from Version 2.0 - no changes) ...
    logger.info(f"--- Running Consolidate (Version {VERSION}) ---")
    logger.warning("Action 'consolidate' is a complex feature and is not yet implemented.")
    pass

# --- Main Execution ---

def setup_logging():
    """Configures the main logger."""
    
    # PATHCHANGE: Ensure log directory exists before initializing logging
    if hasattr(Config, 'LOG_FILE') and Config.LOG_FILE:
        log_dir = os.path.dirname(Config.LOG_FILE)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
    # Default handlers
    # Explicit type annotation to appease Pylance/MyPy regarding variance
    handlers: List[logging.Handler] = [logging.StreamHandler()]
    
    # Add file handler if configured
    if hasattr(Config, 'LOG_FILE') and Config.LOG_FILE:
        handlers.append(logging.FileHandler(Config.LOG_FILE, mode='a', encoding='utf-8'))

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

async def main():
    """
    Main entry point for the UTXO Manager.
    """
    setup_logging()

    Config.validate_wallet_config()
    
    parser = argparse.ArgumentParser(
        description=f"AnchorForge UTXO Manager (Version {VERSION}). Manages and repairs UTXO cache files.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # --- Global Options ---
    parser.add_argument(
        '-n', '--network',
        choices=['main', 'test'],
        default=None,
        help=f"Specify the network. Overrides the .env config (Default: {Config.ACTIVE_NETWORK_NAME})."
    )

    file_group = parser.add_mutually_exclusive_group(required=True)
    file_group.add_argument(
        '-f', '--file',
        type=str,
        help="Path to a specific UTXO JSON file to manage."
    )
    file_group.add_argument(
        '-a', '--address',
        type=str,
        help="The UTXO store address. The script will derive the filename (e.g., utxo_store_...json)."
    )

    # --- Sub-commands for Actions ---
    subparsers = parser.add_subparsers(dest='command', required=True, help="The action to perform.")

    # 'stats' command
    stats_parser = subparsers.add_parser(
        'stats',
        help="Show statistics about the local UTXO file (count, total value, avg, min, max)."
    )
    stats_parser.set_defaults(func=do_stats)

    # 'compare' command
    compare_parser = subparsers.add_parser(
        'compare',
        help="Compare local file with blockchain (WOC API) and show differences."
    )
    compare_parser.set_defaults(func=do_compare)

    # 'full-repair' command
    full_repair_parser = subparsers.add_parser(
        'full-repair',
        help="Create a fresh UTXO file by fetching all unspent outputs from the API."
    )
    full_repair_parser.set_defaults(func=do_full_repair)

    # 'repair' command
    repair_parser = subparsers.add_parser(
        'repair',
        help="Smart repair: Compare with API, remove stale UTXOs, and fetch new ones."
    )
    repair_parser.set_defaults(func=do_repair)
    
    # 'check' command
    check_parser = subparsers.add_parser(
        'check',
        help="Check the status of a single UTXO (local vs. remote)."
    )
    check_parser.add_argument('utxo', type=str, help="The UTXO to check (format: 'txid:vout').")
    check_parser.set_defaults(func=do_check)

    # 'add' command
    add_parser = subparsers.add_parser(
        'add',
        help="Manually add a UTXO to the local file (with API validation)."
    )
    add_parser.add_argument('utxo', type=str, help="The UTXO to add (format: 'txid:vout:satoshis').")
    add_parser.set_defaults(func=do_add)

    # 'remove' command
    remove_parser = subparsers.add_parser(
        'remove',
        help="Manually remove a UTXO from the local file."
    )
    remove_parser.add_argument('utxo', type=str, help="The UTXO to remove (format: 'txid:vout').")
    remove_parser.set_defaults(func=do_remove)
    
    # 'consolidate' command
    consolidate_parser = subparsers.add_parser(
        'consolidate',
        help="[NOT IMPLEMENTED] Consolidate multiple small UTXOs into a single new one."
    )
    consolidate_parser.set_defaults(func=do_consolidate)


    args = parser.parse_args()

    # --- Network Configuration Override ---
    if args.network:
        if args.network != Config.ACTIVE_NETWORK_NAME:
            logger.warning(f"Overriding configured network. Using: '{args.network}'")
            Config.ACTIVE_NETWORK_NAME = args.network
            
            if Config.ACTIVE_NETWORK_NAME == "test":
                network_prefix = "TESTNET_"
            else:
                network_prefix = "MAINNET_"
            
            Config.WOC_API_BASE_URL = os.getenv(f"{network_prefix}WOC_API_BASE_URL")
            
            if not Config.WOC_API_BASE_URL:
                 logger.error(f"Failed to load {network_prefix}WOC_API_BASE_URL from .env!")
                 sys.exit(1)
            logger.info(f"WOC API Base URL set to: {Config.WOC_API_BASE_URL}")

    # --- Resolve Filenames ---
    try:
        filenames = _resolve_filenames(args)
        if args.address:
            filenames['address'] = args.address
    except Exception as e:
        logger.error(f"Failed to start: {e}")
        sys.exit(1)

    # --- Execute the Command ---
    try:
        await args.func(args, filenames)
    except Exception as e:
        logger.error(f"An unexpected error occurred during command execution: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())