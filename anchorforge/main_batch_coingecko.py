# main_batch_coingecko.py
'''
This program serves as the entry point for logging a single audit event 
based on external data fetched from the CoinGecko API.

Note: use --mainnet to confirm you want the mainnet (matching with config.py/.env)

python main_batch_coingecko.py --keyword coingecko-001 
python main_batch_coingecko.py --count 10 --keyword coingecko-001
python main_batch_coingecko.py --count 1000
python main_batch_coingecko.py --count 1000 --reset   # starts a complete new batch even with some already processed
python main_batch_coingecko.py --backup
python control_process coingecko pause/resume/stop


5 events without broadcast:
python main_batch_coingecko.py --count 5 --dry-run


'''

import asyncio
import logging
import json
import argparse
import time
import sys
import os
from datetime import datetime, timezone

from anchorforge.config import Config
from anchorforge import utils
from anchorforge import data_services
from anchorforge import manager # Using the shared service layer

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

#  --- CONSTANTS ---
DEFAULT_KEYWORD = "coingecko-001"
PROCESS_NAME = "coingecko"

# Move batch status file to runtime directory
# If Config.RUNTIME_DIR is defined, use it. Otherwise fallback to 'runtime'.
RUNTIME_DIR = getattr(Config, 'RUNTIME_DIR', 'runtime')
if not os.path.exists(RUNTIME_DIR):
    try:
        os.makedirs(RUNTIME_DIR, exist_ok=True)
    except OSError:
        pass # If we can't create it, we'll likely fail later or write to current dir

STATUS_FILE = os.path.join(RUNTIME_DIR, "coingecko_batch_status.json")

# Original script had a mismatch (log said 3s, code said 10s). 
# We settle on 10s to be safe with free API limits.
DELAY_NEXT_REQUEST = 10 

DEFAULT_TX_NOTE = """**SPV-based Off-Chain Data Verification**
This tx is part of a series demonstrating scalable, off-chain verifiable audit trails anchored to the blockchain. A verifier only needs an Integrity Record and a local cache of block headers.
Keyword: coingecko-001

**Description**
Is contained as OP_RETURN payload of genesis txs
Spending Tx (provides UTXOs): e98aa51c3d2de8041719c32079d1a8ada3d8160137f5d2655ad67d0ef1f2fe2b
Genesis Tx 1 (Concept): 5cd8197616fab4a6579ccdd3a782e229c84c0238975aefdb3ea1007a8b1ef6c8
Genesis Tx 2 (Example): 9bd554b491aeafc64e9693cd69880225aea17f44e39507000378252d091661da

*PoC*: github.com/40ps/AnchorForge"""

async def process_single_coingecko_event(
        dry_run: bool, 
        keyword: str, 
        tx_note: str) -> bool:
    """
    Fetches one price data point and logs it using the audit service.
    """
    logging.info(f"\n--- Starting CoinGecko Price Log Process ---")
    
    # --- 1. Fetch Data ---
    # Capture timestamp just before API call
    query_timestamp_utc = datetime.now(timezone.utc).isoformat()
    
    price_data = await data_services.get_coingecko_bsv_price()

    if not price_data:
        logging.error("Could not fetch price data from CoinGecko. Aborting iteration.")
        return False
    
    # --- 2. Format Data ---
    # Extract server timestamp if available
    server_unix_timestamp = price_data.get('bitcoin-cash-sv', {}).get('last_updated_at')
    server_iso_timestamp = datetime.fromtimestamp(server_unix_timestamp, tz=timezone.utc).isoformat() if server_unix_timestamp else None

    data_to_anchor = {
        "client_query_timestamp_utc": query_timestamp_utc,
        "server_last_updated_utc": server_iso_timestamp,
        "price_data": {
            "bitcoin-cash-sv": {
                "eur": price_data.get('bitcoin-cash-sv', {}).get('eur')
            }
        },
        "source": "Powered by CoinGecko API"
    }
    
    data_string = json.dumps(data_to_anchor, indent=4)
    record_note = "Live price data for BSV/EUR from CoinGecko."

    # logging.info(f"\n--- New Audit Content ---")
    # logging.info(f"  Content to be logged: '{data_content_string[:200]}...'")
    # logging.info(f"\n--- New Audit Note ---")
    # logging.info(f"  Content to be noted: '{record_note_content}'")


    # --- 3. Log it (Generic Service Call) ---
    return await manager.log_audit_event(
        data_source=data_string,
        data_storage_mode="embedded",
        record_note=record_note,
        tx_note=tx_note,
        keyword=keyword,
        dry_run=dry_run,
        no_broadcast=False # Batch script usually implies broadcasting, unless dry-run is set
    )



async def main():
    """
    Main function to control the batch logging process.
    It now includes status tracking, resume capabilities, and periodic backups, and a final summary.
    """
    parser = argparse.ArgumentParser(
        description="Fetches BSV/EUR price from CoinGecko in a batch and creates audit records."
    )
    
    parser.add_argument('-c', '--count', type=int, help="The number of price events to log.")
    parser.add_argument('--dry-run', action='store_true', help="Perform a dry run: build transactions but do not broadcast.")
    parser.add_argument('--reset', action='store_true', help="Reset the batch status and start from the beginning.")
    parser.add_argument('--backup', action='store_true', help="Immediately create a backup of the current state files and exit.")
    parser.add_argument('-k', '--keyword', type=str, default=DEFAULT_KEYWORD, help="A keyword/tag for audit records.")
    parser.add_argument('-tn', '--transaction-note', help="Note for the OP_RETURN transaction.")
    parser.add_argument('--mainnet', action='store_true', help="Safety flag for mainnet.")
       
    args = parser.parse_args()


    # --- Safety Checks ---
    if Config.ACTIVE_NETWORK_NAME == 'main' and not args.mainnet:
        logging.error("--- SAFETY ABORT ---")
        logging.error("Your configuration is set to 'mainnet', but the --mainnet flag was not provided.")
        logging.error("This is a safety measure to prevent accidental mainnet transactions.")
        logging.error("Please add the --mainnet flag to your command if you are sure you want to proceed.")
        return # Exit gracefully
    
    # --- 1. Immediate Backup Handling ---
    if args.backup:
        logging.info("--- Manual Backup Triggered ---")
        manager.perform_backup()
        return

    # Count is mandatory if not doing a backup
    if not args.count:
        parser.error("Argument -c/--count is required (unless using --backup).")

    # --- Note Resolution ---
    # We use utils to resolve file paths (starting with @) or use raw string
    tx_note_content = DEFAULT_TX_NOTE
    if args.transaction_note:
        tx_note_content = utils.get_content_from_source(args.transaction_note) or DEFAULT_TX_NOTE
        
    # --- Status Management ---
    # Using a specific status file for CoinGecko to avoid conflicts
    status_data = utils.read_batch_status(STATUS_FILE)

    if args.reset or status_data.get('status') == 'completed' or status_data.get('total_requested') != args.count:
        status_data = {
            "total_requested": args.count,
            "completed_count": 0,
            "status": "pending"
        }
        logging.info("Batch status reset.")
        utils.write_batch_status(status_data, STATUS_FILE)

    start_index = status_data.get('completed_count', 0)
    total_requested = status_data.get('total_requested', args.count)

    if start_index >= total_requested:
        logging.info("Batch already completed. Use --reset to start a new one.")
        return

    logging.info(f"--- Starting CoinGecko Batch: {start_index + 1} to {total_requested} ---")
    start_time = time.time()
    status_data['status'] = 'running'
    utils.write_batch_status(status_data, STATUS_FILE)

    # Ensure dependencies
    utils.ensure_json_file_exists(Config.AUDIT_LOG_FILE)
    # Removed: utils.ensure_json_file_exists(Config.TX_STORE_FILE), the store is handled by the manager
    # utils.ensure_json_file_exists(Config.X509_KEYPAIR_STORE_FILE, initial_content={})
 
    successful_logs_this_run = 0
    failed_logs = 0

    for i in range(start_index, total_requested):
        loop_start = time.time()
        logging.info(f"\n>>> Processing event {i + 1} of {total_requested} <<<")
        
        success = await process_single_coingecko_event(
            dry_run=args.dry_run, 
            keyword=args.keyword,
            tx_note=tx_note_content
        )
        
        if success:
            successful_logs_this_run += 1
            status_data['completed_count'] += 1
            utils.write_batch_status(status_data, STATUS_FILE)
            logging.info(f"Event {i + 1} logged successfully.")

            # --- Periodic Backup ---
            if status_data['completed_count'] % Config.BACKUP_INTERVAL == 0:
                logging.info(f"Backup interval ({Config.BACKUP_INTERVAL}) reached. Performing backup...")
                manager.perform_backup()

        else:
            failed_logs += 1
            status_data['status'] = 'failed'
            utils.write_batch_status(status_data, STATUS_FILE)
            logging.error(f"Failed to log event {i + 1}. Stopping batch.")
            break 

        # --- Process Controls ---
        if await utils.check_process_controls(PROCESS_NAME):
            break 

        # Pause between requests
        if i < total_requested - 1:
            logging.info(f"Waiting {DELAY_NEXT_REQUEST}s before next request...")
            await asyncio.sleep(DELAY_NEXT_REQUEST)
        
        logging.info(f"Loop duration: {time.time() - loop_start:.2f}s")

    # --- Summary ---
    end_time = time.time()
    duration = end_time - start_time
    duration_seconds = end_time - start_time
    duration_minutes = duration_seconds / 60
    
    if status_data.get('completed_count') == total_requested:
        status_data['status'] = 'completed'
        utils.write_batch_status(status_data, STATUS_FILE)
        logging.info("Batch successfully completed.")

    status = status_data.get('status')
    if status is None: status ="Undefined"

    summary = (
        f"\n--- Batch Run Summary ---\n"
        f"Status: {status.upper()}\n"
        f"Total Requested: {total_requested}\n"
        f"Completed Total: {status_data.get('completed_count')}\n"
        f"  - This Run Success: {successful_logs_this_run}\n"
        f"  - This Run Failed: {failed_logs}\n"
        f"--------------------------\n"
        f"Start Time: {datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"End Time:   {datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Total Duration: {duration_seconds:.2f} seconds ({duration_minutes:.2f} minutes)\n"
        f"--------------------------"
    )

    print(summary)
    logging.info(f"[BATCH_SUMMARY] {json.dumps(status_data)}")
    logging.info(summary)



if __name__ == "__main__":
    asyncio.run(main())