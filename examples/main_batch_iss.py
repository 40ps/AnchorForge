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

from bsv import PrivateKey
from bsv.hash import sha256

# --- Project specific imports ---
from anchorforge.config import Config
from anchorforge import wallet_manager

from anchorforge import key_x509_manager
from anchorforge import utils
from anchorforge import data_services # Contains get_iss_location

from anchorforge import manager

# Ensure log directory exists before initializing logging
if hasattr(Config, 'LOG_FILE') and Config.LOG_FILE:
    log_dir = os.path.dirname(Config.LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

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
VERSION=0.1

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

# Move batch status file to runtime directory
# If Config.RUNTIME_DIR is defined, use it. Otherwise fallback to 'runtime'.
RUNTIME_DIR = getattr(Config, 'RUNTIME_DIR', 'runtime')
if not os.path.exists(RUNTIME_DIR):
    try:
        os.makedirs(RUNTIME_DIR, exist_ok=True)
    except OSError:
        pass # If we can't create it, we'll likely fail later or write to current dir

STATUS_FILE = os.path.join(RUNTIME_DIR, "iss_batch_status.json")


DELAY_NEXT_ISS_REQUEST = 1 # Not more 1 API Call /s for wheretheiss.at and whatsonchain

Config.validate_wallet_config()


async def process_single_iss_location_event(
        dry_run: bool = False, 
        keyword: str = "default",
        tx_note: str | None = None,
        no_broadcast: bool = False):
    """
    Orchestrates fetching ISS location data and creating a single audit record.
    This function represents one iteration in our batch process.
    """
    logging.info(f"--- Starting Single ISS Location Log ---")

    # --- Block 1: Fetch and prepare data source ---
    query_timestamp_utc = datetime.now(timezone.utc).isoformat()

    # --- 1. Fetch Data (Specific to this app)
    iss_data_from_api = await data_services.get_iss_location() # Call the correct function

    if not iss_data_from_api:
        logging.error("Could not fetch location data from wheretheiss.at. Aborting this iteration.")
        return False

    # --- 2. Format Data (Specific to this app)
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
    data_string = json.dumps(data_to_anchor, indent=4)
    record_note = "Live ISS Location Data from api.wheretheiss.at." # Adjusted note

    logging.info(f"  Content to be logged: '{data_string[:200]}...'")

    # 3. Log it (Generic Service Call)
    # No more file locking, path calculation, or transaction logic here!
    return await manager.log_audit_event(
        data_source=data_string,
        data_storage_mode="embedded",
        record_note=record_note,
        tx_note=tx_note,
        keyword=keyword,
        dry_run=dry_run,
        no_broadcast=no_broadcast
    )

# --- main function to control the batch ---
async def main():

    Config.validate_wallet_config()

    parser = argparse.ArgumentParser(
        description="ISS Batch Logger"+
            " \nFetches ISS location from wheretheiss.at in a batch and creates audit records.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # --- Standard Arguments ---
    parser.add_argument('-c', '--count', type=int, help="The total number of location events to log.")
    parser.add_argument('-k', '--keyword', default=DEFAULT_KEYWORD, help=f"Keyword/tag for audit records (default: {DEFAULT_KEYWORD}).")
    parser.add_argument('-tn', '--transaction-note', help="Note for the OP_RETURN transaction (string or file path). Overrides default.", 
                        default=DEFAULT_TX_NOTE)
    parser.add_argument('--dry-run', action='store_true', help="Build transactions but do not broadcast.")
    parser.add_argument('--no-broadcast', action='store_true', help="Simulate broadcast locally, update *.sim.json files.")
    parser.add_argument('--reset', action='store_true', help="Reset batch status and start from 0.")
    parser.add_argument('--backup', action='store_true', help="Create a backup and exit.")
    parser.add_argument('--mainnet', action='store_true', help="Required safety flag if config is set to 'main'.")

    args = parser.parse_args()

    # --- Mainnet Safety Check ---
    if Config.ACTIVE_NETWORK_NAME == 'main' \
            and not args.mainnet \
            and not args.dry_run \
            and not args.no_broadcast \
            and not args.backup:
        logging.error("--- SAFETY ABORT --- Add --mainnet flag to confirm writing to mainnet.")
        return

    # --- 1. Immediate Backup Handling ---
    if args.backup:
        logging.info("Manual backup requested.")
        manager.perform_backup()
        return

    # --- Count is mandatory if not doing a backup ---
    if not args.count:
        parser.error("Argument -c/--count is required unless using --backup.")



    # --- Resolve Transaction Note ---
    tx_note_content = utils.get_content_from_source(args.transaction_note) if args.transaction_note else DEFAULT_TX_NOTE



    # region --- Batch Control Logic / Status Management using specific status file ---
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
    # removed: handled by the manager    utils.ensure_json_file_exists(Config.TX_STORE_FILE)
    # utils.ensure_json_file_exists(Config.X509_KEYPAIR_STORE_FILE, initial_content={}) # (Da dies ein Dict ist)


    successful_logs_this_run = 0
    failed_logs = 0
    is_simulation_run = args.no_broadcast # Determine if this is a simulation run

    for i in range(start_index, total_requested):
        logging.info(f"\n>>> Processing ISS event {i + 1}/ {total_requested} <<<")

        # Pass all relevant flags and data
        success = await process_single_iss_location_event(
            dry_run=args.dry_run,
            no_broadcast=is_simulation_run, # Pass simulation flag
            keyword=args.keyword,
            tx_note=tx_note_content
        )

        if success:
            successful_logs_this_run += 1
            status_data['completed_count'] += 1
            utils.write_batch_status(status_data, STATUS_FILE) # Update status file
            logging.info(f"Event {i + 1} logged. Progress: {status_data['completed_count']}/{total_requested}")

            # Backup Trigger (no changes needed)
            if not is_simulation_run \
                and status_data['completed_count'] % Config.BACKUP_INTERVAL == 0:
                logging.info(f"Reached backup interval at {status_data['completed_count']} logs.")
                manager.perform_backup()

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
    
    summary = ( f"\n--- ISS Batch Run Summary ---\n"  )
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