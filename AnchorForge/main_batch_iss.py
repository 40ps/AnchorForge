# main_batch_iss.py
'''
This program serves as a batch logger for creating multiple audit events
based on external data fetched from the WhereTheISS.at API.

Command Examples:
python main_batch_iss.py --count 100
python main_batch_iss.py --count 1000 --reset
python main_batch_iss.py --count 50 --dry-run
python main_batch_iss.py --backup
'''

import asyncio
import logging
import json
from typing import List, Dict
from datetime import datetime, timezone
import uuid
import os
import sys
import argparse
import time # For time measurement
import portalocker
from portalocker import LOCK_EX

# --- Project specific imports ---
from config import Config
import wallet_manager
import audit_core
import key_x509_manager
import utils
import data_services # Contains get_iss_location
from bsv import PrivateKey
from bsv.hash import sha256

# Configure logging for this specific program
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# --- CONSTANTS specific to this script ---
# Default transaction note embedded in the code
DEFAULT_TX_NOTE = """SPV-based Off-Chain Data Verification
This tx is part of a series demonstrating scalable, off-chain verifiable audit trails anchored to the blockchain.
Data Source: api.wheretheiss.at (ISS Location)
Keyword: iss-location-001
PoC: github.com/40ps/AnchorForge
"""
# Default keyword for audit records created by this script
DEFAULT_KEYWORD = "iss-location-001"
# Process name for pause/stop controls
PROCESS_NAME = "iss"
# Status file specific to this batch type
STATUS_FILE = "iss_batch_status.json"

DELAY_NEXT_ISS_REQUEST = 1 # Not more 1 API Call /s for wheretheiss.at and whatsonchain


# --- Helper function (copied from main_audit_log_event) ---
def get_content_from_source(source: str | None) -> str | None:
    # ... (Implementation remains the same as in your other scripts) ...
    if source is None:
        return None
    if os.path.isfile(source):
        try:
            with open(source, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logging.error(f"Error reading file {source}: {e}")
            sys.exit(1) # Exit on error
    return source

async def log_iss_location_event(
        dry_run: bool = False, 
        keyword: str = "default",
        tx_note_content: str | None = None,
        no_broadcast: bool = False):
    """
    Orchestrates fetching ISS location data and creating a single audit record.
    This function represents one iteration in our batch process.
    """
    logging.info(f"--- Starting Single ISS Location Log ---")

    # --- Block 1: Fetch and prepare data source ---
    query_timestamp_utc = datetime.now(timezone.utc).isoformat()
    iss_data_from_api = await data_services.get_iss_location() # Call the correct function

    if not iss_data_from_api:
        logging.error("Could not fetch location data from wheretheiss.at. Aborting this iteration.")
        return False # Return False to indicate failure

    # Format the data for anchoring, including the query timestamp and source
    data_to_anchor = {
        "client_query_timestamp_utc": query_timestamp_utc,
        # The ISS API includes its own 'timestamp' field (Unix epoch)
        "iss_server_timestamp": iss_data_from_api.get("timestamp"),
        "location_data": {
            "latitude": iss_data_from_api.get("latitude"),
            "longitude": iss_data_from_api.get("longitude"),
            "altitude": iss_data_from_api.get("altitude"),
            "velocity": iss_data_from_api.get("velocity"),
            "visibility": iss_data_from_api.get("visibility"),
            "footprint": iss_data_from_api.get("footprint"),
            "units": iss_data_from_api.get("units")
            # Add other fields as needed
        },
        "source": "api.wheretheiss.at/v1/satellites/25544"
    }
    data_content_string = json.dumps(data_to_anchor, indent=4)
    record_note_content = "Live ISS Location Data from api.wheretheiss.at." # Adjusted note

    logging.info(f"  Content to be logged: '{data_content_string[:200]}...'")

    # --- Block 2 & 3: File Locking, TX Creation etc. (Largely the same) ---
    priv_key_funding = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
    sender_address = priv_key_funding.address()

    # Determine file paths based on mode (simulation or real)
    is_simulation = no_broadcast # Use the flag passed to the function
    utxo_file_path = wallet_manager._get_filename_for_address(str(sender_address), 
                                                              Config.ACTIVE_NETWORK_NAME, 
                                                              simulation=is_simulation)
    tx_file_path = utxo_file_path.replace("utxo_store", "tx_store")
    used_utxo_file_path = utxo_file_path.replace("utxo_store", "used_utxo_store")
    audit_log_file = Config.AUDIT_LOG_FILE.replace(".json", ".sim.json") if is_simulation else Config.AUDIT_LOG_FILE

    try:
        with portalocker.Lock(audit_log_file, "r+", flags=LOCK_EX, timeout=5) as f_audit, \
             portalocker.Lock(tx_file_path, "r+", flags=LOCK_EX, timeout=5) as f_tx, \
             portalocker.Lock(used_utxo_file_path, "r+", flags=LOCK_EX, timeout=5) as f_used, \
             portalocker.Lock(utxo_file_path, "r+", flags=LOCK_EX, timeout=5) as f_utxo:

            audit_log = audit_core.load_audit_log(f_audit)
            tx_store = wallet_manager.load_tx_store(f_tx)
            used_store = wallet_manager.load_used_utxo_store(f_used)
            store = wallet_manager.load_utxo_store(f_utxo)

            # --- Prepare Payloads (including App ID) ---
            assert Config.PRIVATE_SIGNING_KEY_WIF is not None
            ec_payload = audit_core.build_audit_payload(data_content_string, Config.PRIVATE_SIGNING_KEY_WIF)
            x509_payload = [] # Simplified
            app_id_payload = [audit_core.AUDIT_MODE_APP_ID, Config.ANCHOR_FORGE_ID.encode('utf-8')]
            op_return_payload_for_tx = app_id_payload + ec_payload + x509_payload

            # --- Prepare Audit Record Entry ---
            audit_record_entry = {
                "log_id": str(uuid.uuid4()),
                "keyword": keyword, # Use the passed keyword
                "original_audit_content": data_content_string,
                "timestamp_logged_local": datetime.now(timezone.utc).isoformat(),
                "format": audit_core.AUDIT_RECORD_FORMAT_V1,
                "blockchain_record": { "status": "pending_creation" # Minimal initial state
                },
                "notes": record_note_content
            }

            # --- Create Transaction ---
            assert Config.UTXO_STORE_KEY_WIF is not None, "UTXO_STORE_KEY_WIF None"
            tx_hex_returned, broadcast_timestamp_str, broadcast_txid, \
            consumed_utxos_details, new_utxos_details, calculated_fee = await audit_core.create_op_return_transaction(
                spending_key_wif=Config.UTXO_STORE_KEY_WIF,
                recipient_address=str(sender_address),
                op_return_data_pushes=op_return_payload_for_tx,
                original_audit_content_string=data_content_string,
                network=Config.ACTIVE_NETWORK_BSV,
                current_utxo_store_data=store,
                tx_store=tx_store,
                f_tx_store=f_tx,
                note=tx_note_content, # Pass the resolved note
                dry_run=dry_run,
                no_broadcast=no_broadcast # Pass the flag
            )

            # --- Process Result ---
            if tx_hex_returned and broadcast_txid:
                tx_size_bytes = len(tx_hex_returned) // 2
                audit_record_entry["blockchain_record"].update({
                    "txid": broadcast_txid, "raw_transaction_hex": tx_hex_returned,
                    "status": "broadcasted", "timestamp_broadcasted_utc": broadcast_timestamp_str,
                    "fee_satoshis": calculated_fee, "tx_size_bytes": tx_size_bytes,
                    "inputs": consumed_utxos_details, "outputs": new_utxos_details,
                    "data_hash_pushed_to_op_return": ec_payload[1].hex() if ec_payload else None,
                    # ... other hash fields ...
                    "tx_note": tx_note_content # Save the note used in the tx
                })
                audit_log.append(audit_record_entry)

                # Update UTXO stores
                for consumed_utxo in consumed_utxos_details:
                    store["utxos"] = [u for u in store["utxos"] if not (u["txid"] == consumed_utxo["txid"] and u["vout"] == consumed_utxo["vout"])]
                    consumed_utxo.update({"used": True, "used_in_txid": broadcast_txid, "used_timestamp": datetime.now(timezone.utc).isoformat()})
                    used_store["used_utxos"].append(consumed_utxo)
                store["utxos"].extend(new_utxos_details)

                # Save all stores
                wallet_manager.save_utxo_store(f_utxo, store)
                wallet_manager.save_used_utxo_store(f_used, used_store)
                audit_core.save_audit_log(f_audit, audit_log)
                wallet_manager.save_tx_store(f_tx, tx_store)

                logging.info(f"ISS location logged successfully. TXID: {broadcast_txid}")
                return True
            else:
                # Log minimal failure record
                audit_record_entry["blockchain_record"]["status"] = "tx_creation_failed"
                 # Add hashes even on failure
                audit_record_entry["blockchain_record"]["data_hash_pushed_to_op_return"] = ec_payload[1].hex() if ec_payload else None
                # ... add other hash fields if needed ...
                audit_log.append(audit_record_entry)
                audit_core.save_audit_log(f_audit, audit_log)
                logging.error(f"Failed to create transaction for ISS audit record '{audit_record_entry['log_id']}'.")
                return False

    except portalocker.exceptions.LockException as e:
        logging.error(f"Could not acquire lock for processing: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred in log_iss_location_event: {e}", exc_info=True)
        return False

# --- main function to control the batch ---
async def main():
    parser = argparse.ArgumentParser(
        description="Fetches ISS location from wheretheiss.at in a batch and creates audit records.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # --- Standard Arguments ---
    parser.add_argument('-c', '--count', type=int, help="The total number of location events to log.")
    parser.add_argument('-k', '--keyword', default=DEFAULT_KEYWORD, help=f"Keyword/tag for audit records (default: {DEFAULT_KEYWORD}).")
    parser.add_argument('-tn', '--transaction-note', help="Note for the OP_RETURN transaction (string or file path). Overrides default.")
    parser.add_argument('--dry-run', action='store_true', help="Build transactions but do not broadcast.")
    parser.add_argument('--no-broadcast', action='store_true', help="Simulate broadcast locally, update *.sim.json files.")
    parser.add_argument('--reset', action='store_true', help="Reset batch status and start from 0.")
    parser.add_argument('--backup', action='store_true', help="Create a backup and exit.")
    parser.add_argument('--mainnet', action='store_true', help="Required safety flag if config is set to 'main'.")

    args = parser.parse_args()

    # --- Mainnet Safety Check ---
    if Config.ACTIVE_NETWORK_NAME == 'main' and not args.mainnet and not args.dry_run and not args.no_broadcast and not args.backup:
        logging.error("--- SAFETY ABORT --- Add --mainnet flag to confirm writing to mainnet.")
        return

    # --- Handle Manual Backup ---
    if args.backup:
        # ... (Implementation remains the same as in main_batch_coingecko) ...
        logging.info("--- Manual Backup Triggered ---")
        priv_key = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
        address = priv_key.address()
        # Use is_simulation=False for backup, we always back up the real files
        utxo_file = wallet_manager._get_filename_for_address(str(address), Config.ACTIVE_NETWORK_NAME, simulation=False)
        tx_file = utxo_file.replace("utxo_store", "tx_store")
        used_utxo_file = utxo_file.replace("utxo_store", "used_utxo_store")
        audit_log_file_real = Config.AUDIT_LOG_FILE # Ensure we back up the correct audit log

        files_to_backup = [audit_log_file_real, utxo_file, tx_file, used_utxo_file]
        utils.create_backup(files_to_backup, Config.BACKUP_DIR)
        logging.info("--- Manual Backup Complete. Exiting. ---")
        return

    # --- Count is mandatory if not doing a backup ---
    if not args.count:
        parser.error("Argument -c/--count is required unless using --backup.")

    # --- Resolve Transaction Note ---
    tx_note_content = utils.get_content_from_source(args.transaction_note) if args.transaction_note else DEFAULT_TX_NOTE

    # --- Status Management using specific status file ---
    status_data = utils.read_batch_status(STATUS_FILE) # Pass the specific status file name

    if args.reset or status_data.get('status') == 'completed' or status_data.get('total_requested') != args.count:
        status_data = {"total_requested": args.count, "completed_count": 0, "status": "pending"}
        logging.info("Batch status reset for ISS.")
    
    start_index = status_data.get('completed_count', 0)
    total_requested = status_data.get('total_requested', args.count) # Ensure total is set

    if start_index >= total_requested:
        logging.info("ISS batch already completed. Use --reset.")
        return

    logging.info(f"--- Starting ISS Batch Run: Logging {total_requested} events ---")
    logging.info(f"Resuming from event {start_index + 1}.")
    start_time = time.time()
    status_data['status'] = 'running'
    utils.write_batch_status(status_data, STATUS_FILE) # Pass status file name

    utils.ensure_json_file_exists(Config.AUDIT_LOG_FILE)
    
    # Optionally: same for other critical files
    utils.ensure_json_file_exists(Config.TX_STORE_FILE)
    # utils.ensure_json_file_exists(Config.X509_KEYPAIR_STORE_FILE, initial_content={}) # (Da dies ein Dict ist)


    successful_logs_this_run = 0
    failed_logs = 0
    is_simulation_run = args.no_broadcast # Determine if this is a simulation run

    for i in range(start_index, total_requested):
        logging.info(f"\n>>> Processing ISS event {i + 1} of {total_requested} <<<")

        # Pass all relevant flags and data
        success = await log_iss_location_event(
            dry_run=args.dry_run,
            no_broadcast=is_simulation_run, # Pass simulation flag
            keyword=args.keyword,
            tx_note_content=tx_note_content
        )

        if success:
            successful_logs_this_run += 1
            status_data['completed_count'] += 1
            utils.write_batch_status(status_data, STATUS_FILE) # Update status file
            logging.info(f"Event {i + 1} logged. Progress: {status_data['completed_count']}/{total_requested}")

            # Backup Trigger (no changes needed)
            if not is_simulation_run and status_data['completed_count'] % Config.BACKUP_INTERVAL == 0:
                 # ... (Backup logic remains the same, backs up non-sim files) ...
                logging.info(f"Reached backup interval at {status_data['completed_count']} logs.")
                priv_key = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
                address = priv_key.address()
                utxo_file = wallet_manager._get_filename_for_address(str(address), Config.ACTIVE_NETWORK_NAME, simulation=False)
                tx_file = utxo_file.replace("utxo_store", "tx_store")
                used_utxo_file = utxo_file.replace("utxo_store", "used_utxo_store")
                files_to_backup = [Config.AUDIT_LOG_FILE, utxo_file, tx_file, used_utxo_file]
                utils.create_backup(files_to_backup, Config.BACKUP_DIR)
        else:
            failed_logs += 1
            status_data['status'] = 'failed'
            utils.write_batch_status(status_data, STATUS_FILE)
            logging.error(f"Failed to log event {i + 1}. Stopping batch.")
            break

        # Pause/Stop Controls using specific process name
        if await utils.check_process_controls(PROCESS_NAME):
            break

        # Pause between requests (1 second for ISS)
        if i < total_requested - 1:
            logging.info("Waiting 1 second before next ISS/Next Batch request...")
            await asyncio.sleep(DELAY_NEXT_ISS_REQUEST) # Adjusted pause time

    # --- Final Summary ---
    end_time = time.time()
    # ... (Summary calculation and output remains the same as in main_batch_coingecko) ...
    duration_seconds = end_time - start_time
    duration_minutes = duration_seconds / 60
    if status_data.get('completed_count') == total_requested and failed_logs == 0:
        status_data['status'] = 'completed'
        utils.write_batch_status(status_data, STATUS_FILE)
        logging.info("ISS Batch successfully completed.")
    
    summary = ( f"\n--- ISS Batch Run Summary ---\n" # Adjusted title
                # ... (rest of summary format is the same)
              )
    print(summary)
    logging.info(f"[ISS_BATCH_SUMMARY] {json.dumps(status_data)}") # Adjusted prefix
    logging.info(summary)


if __name__ == "__main__":
    # Ensure utils.py has the updated read/write_batch_status functions
    # that accept a filename argument.
    try:
        # Check if the required functions exist and accept the filename argument
        if not (hasattr(utils, 'read_batch_status') and 
                hasattr(utils, 'write_batch_status') and
                'filename' in utils.write_batch_status.__code__.co_varnames):
             print("Error: utils.py functions read/write_batch_status need update to accept filename.")
             sys.exit(1)
        
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("\n--- ISS Batch logger stopped by user (Ctrl+C). ---")