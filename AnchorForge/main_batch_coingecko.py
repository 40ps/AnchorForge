# main_batch_coingecko.py
'''
This program serves as the entry point for logging a single audit event 
based on external data fetched from the CoinGecko API.

Note: use --mainnet to confirm you want the mainnet (matching with config.py/.env)

python main_batch_coingecko.py   --keyword coingecko-001 
python main_batch_coingecko.py --count 10 --keyword coingecko-001
python main_batch_coingecko.py --count 1000
python main_batch_coingecko.py --count 1000 --reset   # starts a complete new batch even with some already processed
python main_batch_coingecko.py --backup
python control_process coingecko pause/resume/stop


Um 5 Events im Trockenlauf zu testen (ohne zu broadcasten):
python main_batch_coingecko.py --count 5 --dry-run


'''

import asyncio
import logging
import json
from typing import List, Dict
from datetime import datetime, timezone
import uuid
import os
import time
import sys
import argparse
import portalocker
from portalocker import LOCK_EX

import data_services # Import our new data service module

from config import Config
import wallet_manager
import bank_functions
import audit_core
import key_x509_manager
import utils 
from bsv import PrivateKey
from bsv.hash import sha256

#  --- CONSTANTS ---
DEFAULT_TX_NOTE = """**SPV-based Off-Chain Data Verification**
This tx is part of a series demonstrating scalable, off-chain verifiable audit trails anchored to the blockchain. A verifier only needs an Integrity Record and a local cache of block headers.
Keyword: coingecko-001

**Description**
Is contained as OP_RETURN payload of genesis txs
Spending Tx (provides UTXOs): e98aa51c3d2de8041719c32079d1a8ada3d8160137f5d2655ad67d0ef1f2fe2b
Genesis Tx 1 (Concept): 5cd8197616fab4a6579ccdd3a782e229c84c0238975aefdb3ea1007a8b1ef6c8
Genesis Tx 2 (Example): 9bd554b491aeafc64e9693cd69880225aea17f44e39507000378252d091661da

*PoC*: github.com/40ps/AnchorForge"""


# Configure logging for this specific program
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def get_content_from_source(source: str | None) -> str | None:
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

async def log_coingecko_price_event(dry_run: bool = False, keyword: str = "default", 
                                    tx_note_content: str | None = None):
    """
    Orchestrates fetching data from CoinGecko and creating a single audit record.
    """
    logging.info(f"\n--- Starting CoinGecko Price Log Process ---")

    # --- Block 1: Fetch and prepare data source ---

    # Capture the timestamp just before the API call
    query_timestamp_utc = datetime.now(timezone.utc).isoformat()

    price_data_from_api = await data_services.get_coingecko_bsv_price()

    if not price_data_from_api:
        logging.error("Could not fetch price data from CoinGecko. Aborting process.")
        return
    
    # Extract the server's timestamp and convert it from Unix time to ISO format
    # The API returns a nested structure, so we access it directly
    server_unix_timestamp = price_data_from_api.get('bitcoin-cash-sv', {}).get('last_updated_at')
    server_iso_timestamp = datetime.fromtimestamp(server_unix_timestamp, tz=timezone.utc).isoformat() if server_unix_timestamp else None


    # Format the data for anchoring, including the source attribution
    data_to_anchor = {
        "client_query_timestamp_utc": query_timestamp_utc,
        "server_last_updated_utc": server_iso_timestamp,
        "price_data": {
            "bitcoin-cash-sv": {
                "eur": price_data_from_api.get('bitcoin-cash-sv', {}).get('eur')
            }
        },
        "source": "Powered by CoinGecko API"
    }
    
    # Convert dict to a formatted JSON string for the audit log process
    data_content_string = json.dumps(data_to_anchor, indent=4)
    
    # Define metadata for the local audit record
    record_note_content = "Live price data for BSV/EUR from CoinGecko."
    
    logging.info(f"\n--- New Audit Content ---")
    logging.info(f"  Content to be logged: '{data_content_string[:200]}...'")
    logging.info(f"\n--- New Audit Note ---")
    logging.info(f"  Content to be noted: '{record_note_content}'")

    # --- Block 2: prepare file paths ---
    priv_key_funding = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
    sender_address = priv_key_funding.address()
    utxo_file_path = wallet_manager._get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME)
    tx_file_path = wallet_manager._get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME).replace("utxo_store", "tx_store")
    used_utxo_file_path = wallet_manager._get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME).replace("utxo_store", "used_utxo_store")

    # --- Block 3: Atomic operations: lock, load, process, store ---
    try:
        # The file mode "r+" is essential for safe read/write operations
        with portalocker.Lock(Config.AUDIT_LOG_FILE, "r+", flags=LOCK_EX, timeout=5) as f_audit, \
             portalocker.Lock(tx_file_path, "r+", flags=LOCK_EX, timeout=5) as f_tx, \
             portalocker.Lock(used_utxo_file_path, "r+", flags=LOCK_EX, timeout=5) as f_used, \
             portalocker.Lock(utxo_file_path, "r+", flags=LOCK_EX, timeout=5) as f_utxo:

            # 1. load all stores securely
            audit_log = audit_core.load_audit_log(f_audit)
            tx_store = wallet_manager.load_tx_store(f_tx)
            used_store = wallet_manager.load_used_utxo_store(f_used)
            store = wallet_manager.load_utxo_store(f_utxo)
  
            # 2. create Payloads and Audit-Record in memory
            # This part is largely the same as in the original script
            assert Config.PRIVATE_SIGNING_KEY_WIF is not None
            ec_payload = audit_core.build_audit_payload(data_content_string, Config.PRIVATE_SIGNING_KEY_WIF)
            
            x509_payload = []
            x509_key_label = 'anchor_example_certificate'
            cert_info = key_x509_manager.get_x509_key_pair_by_label(x509_key_label)
            
            if cert_info:
                private_x509_key_pem = cert_info.get('private_key_pem')
                x509_cert_pem = cert_info.get('certificate_pem')
                if private_x509_key_pem and x509_cert_pem:
                    x509_payload = audit_core.build_x509_audit_payload(data_content_string, private_x509_key_pem, x509_cert_pem)


            # --- Prepend the Application ID payload ---
            app_id_payload = [
                audit_core.AUDIT_MODE_APP_ID,
                Config.ANCHOR_FORGE_ID.encode('utf-8')
            ]
            op_return_payload_for_tx = app_id_payload + ec_payload + x509_payload
            
            
            # --- OPTIMIZATION: Prepare the audit record entry beforehand ---
            # This ensures we capture all pre-transaction info even on failure.
            audit_record_entry = {
                "log_id": str(uuid.uuid4()),
                "keyword": keyword, 
                "original_audit_content": data_content_string,
                "timestamp_logged_local": datetime.now(timezone.utc).isoformat(),
                "format": audit_core.AUDIT_RECORD_FORMAT_V1,
                "blockchain_record": {
                    "status": "pending_creation",
                    "txid": None, 
                    "raw_transaction_hex": None,
                    "data_hash_pushed_to_op_return": ec_payload[1].hex() if ec_payload else None,
                    "signature_pushed_to_op_return": ec_payload[2].hex() if ec_payload else None,
                    "public_key_pushed_to_op_return": ec_payload[3].hex() if ec_payload else None,
                    "x509_hash_pushed": x509_payload[1].hex() if x509_payload else None,
                    "x509_signature_pushed": x509_payload[2].hex() if x509_payload else None,
                    "x509_certificate_pushed": x509_payload[3].decode('utf-8') if x509_payload else None,
                    "tx_note": tx_note_content
                }, 
                "notes": record_note_content
            }


            # 3. Create Transaction
            assert Config.UTXO_STORE_KEY_WIF is not None, "UTXO_STORE_KEY_WIF is none"
            
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
                note=tx_note_content,
                dry_run=dry_run
            )

            # 4. if tx success, write all changes into stores
            if tx_hex_returned and broadcast_txid:
                logging.info(f"Transaction created & broadcasted: {broadcast_txid}")
                
                tx_size_bytes = len(tx_hex_returned) // 2 if tx_hex_returned else 0


                # --- Enrich the existing entry with transaction results ---
                audit_record_entry["blockchain_record"].update({
                    "txid": broadcast_txid,
                    "raw_transaction_hex": tx_hex_returned,
                    "status": "broadcasted",
                    "timestamp_broadcasted_utc": broadcast_timestamp_str,
                    "fee_satoshis": calculated_fee,
                    "tx_size_bytes": tx_size_bytes,
                    "inputs": consumed_utxos_details,
                    "outputs": new_utxos_details,
                })


                

                audit_log.append(audit_record_entry)

                for consumed_utxo in consumed_utxos_details:
                    store["utxos"] = [u for u in store["utxos"] if not (u["txid"] == consumed_utxo["txid"] and u["vout"] == consumed_utxo["vout"])]
                    consumed_utxo.update({"used": True, "used_in_txid": broadcast_txid, "used_timestamp": datetime.now(timezone.utc).isoformat()})
                    used_store["used_utxos"].append(consumed_utxo)
                
                store["utxos"].extend(new_utxos_details)
                
                # 5. write all changed stores securely
                wallet_manager.save_utxo_store(f_utxo, store)
                wallet_manager.save_used_utxo_store(f_used, used_store)
                audit_core.save_audit_log(f_audit, audit_log)
                wallet_manager.save_tx_store(f_tx, tx_store)
                
                logging.info("All local stores updated successfully.")
                return True

            else:
                # --- On failure, just update the status and save ---
                audit_record_entry["blockchain_record"]["status"] = "tx_creation_failed"
                audit_log.append(audit_record_entry)
                audit_core.save_audit_log(f_audit, audit_log)
                logging.error(f"Failed to create transaction for audit record '{audit_record_entry['log_id']}'.")
                return False

    except portalocker.exceptions.LockException as e:
        logging.error(f"Could not acquire lock for processing, another process might be running: {e}")
        return False

    logging.info("\n--- Finished CoinGecko Price Log Process ---")



async def main():
    """
    Main function to control the batch logging process.
    It now includes status tracking, resume capabilities, and periodic backups, and a final summary.
    """
    parser = argparse.ArgumentParser(
        description="Fetches BSV/EUR price from CoinGecko in a batch and creates audit records."
    )
    
    parser.add_argument(
        '-c', '--count',
        type=int, 
        # enable if backup option is removed required=True,  # Count is now mandatory to start a specific batch
        help="The number of price events to log."
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help="Perform a dry run: build transactions but do not broadcast."
    )
    parser.add_argument(
        '--reset',
        action='store_true',
        help="Reset the batch status and start from the beginning."
    )
    parser.add_argument(
        '--backup',
        action='store_true',
        help="Immediately create a backup of the current state files and exit."
    )

    parser.add_argument(
        '-k', '--keyword',
        type=str,
        default="coingecko-001", # A sensible default for this script
        help="A keyword or tag to associate with the audit records."
    )
    
    parser.add_argument(
        '-tn', '--transaction-note',
        help="A note to be included in the OP_RETURN transaction. Can be a direct string or a file path."
    )

    parser.add_argument(
        '--mainnet',
        action='store_true',
        help="A safety flag to confirm that you intend to write to the mainnet. Required if ACTIVE_NETWORK is 'main'."
    )
    
    args = parser.parse_args()

    if Config.ACTIVE_NETWORK_NAME == 'main' and not args.mainnet:
        logging.error("--- SAFETY ABORT ---")
        logging.error("Your configuration is set to 'mainnet', but the --mainnet flag was not provided.")
        logging.error("This is a safety measure to prevent accidental mainnet transactions.")
        logging.error("Please add the --mainnet flag to your command if you are sure you want to proceed.")
        return # Exit gracefully
    
    if args.backup:
        logging.info("--- Manual Backup Triggered ---")
        
        priv_key = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
        address = priv_key.address()
        
        utxo_file = wallet_manager._get_filename_for_address(str(address), Config.ACTIVE_NETWORK_NAME)
        tx_file = utxo_file.replace("utxo_store", "tx_store")
        used_utxo_file = utxo_file.replace("utxo_store", "used_utxo_store")

        files_to_backup = [
            Config.AUDIT_LOG_FILE,
            utxo_file,
            tx_file,
            used_utxo_file
        ]
        
        utils.create_backup(files_to_backup, Config.BACKUP_DIR)
        logging.info("--- Manual Backup Complete. Exiting. ---")
        return # Exit the program after backup



    # --- Count becomes mandatory only if not doing a backup ---
    if not args.count:
        parser.error("the following arguments are required: -c/--count (unless you are using --backup)")


    if args.transaction_note:
        tx_note_content = get_content_from_source(args.transaction_note)
    else:
        tx_note_content = DEFAULT_TX_NOTE
        
    # --- Status Management ---
    status_data = utils.read_batch_status()

    if args.reset or status_data['status'] == 'completed' or status_data['total_requested'] != args.count:
        status_data = {
            "total_requested": args.count,
            "completed_count": 0,
            "status": "pending"
        }
        utils.write_batch_status(status_data)
        logging.info("Batch status has been reset. Starting a new batch.")
    
    start_index = status_data['completed_count']
    total_requested = status_data['total_requested']


    if start_index >= total_requested:
        logging.info("Batch has already been completed. Use --reset to start a new one.")
        return

    logging.info(f"--- Starting Batch Run: Attempting to log {total_requested} events. ---")
    logging.info(f"Resuming from event {start_index + 1}.")

    # --- Record start time ---
    start_time = time.time()


    status_data['status'] = 'running'
    utils.write_batch_status(status_data)

    utils.ensure_json_file_exists(Config.AUDIT_LOG_FILE)
    utils.ensure_json_file_exists(Config.TX_STORE_FILE)
    # utils.ensure_json_file_exists(Config.X509_KEYPAIR_STORE_FILE, initial_content={})

    successful_logs_this_run = 0
    failed_logs = 0

    for i in range(start_index, total_requested):
        looptime = time.time()
        logging.info(f"\n>>> Processing event {i + 1} of {total_requested} <<<")
        
        success = await log_coingecko_price_event(
            dry_run=args.dry_run, 
            keyword=args.keyword,
            tx_note_content=tx_note_content)
        
        if success:
            successful_logs_this_run += 1
            # Update status file IMMEDIATELY after a successful log
            status_data['completed_count'] += 1
            utils.write_batch_status(status_data)
            logging.info(f"Event {i + 1} logged successfully. Progress: {status_data['completed_count']}/{total_requested}")

            # --- CHECKPOINT: Trigger backup at the specified interval ---
            if status_data['completed_count'] % Config.BACKUP_INTERVAL == 0:
                logging.info(f"Reached backup interval at {status_data['completed_count']} logs.")
                
                # We need to get the current wallet file paths to back them up
                priv_key = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
                address = priv_key.address()
                
                utxo_file = wallet_manager._get_filename_for_address(str(address), Config.ACTIVE_NETWORK_NAME)
                tx_file = utxo_file.replace("utxo_store", "tx_store")
                used_utxo_file = utxo_file.replace("utxo_store", "used_utxo_store")

                files_to_backup = [
                    Config.AUDIT_LOG_FILE,
                    utxo_file,
                    tx_file,
                    used_utxo_file
                ]
                
                utils.create_backup(files_to_backup, Config.BACKUP_DIR)

        else:
            failed_logs += 1
            logging.error(f"Failed to log event {i + 1}. The process will be stopped. Please check the logs and restart.")
            status_data['status'] = 'failed'
            utils.write_batch_status(status_data)
            break # Stop the loop on the first failure to allow for investigation
        

        # --- Check for command files (pause or stop) ---
        if await utils.check_process_controls('coingecko'):
            break # Exit the main for-loop if a stop was requested

        # Pause between requests to respect the API rate limit, but not after the last one
        if i < total_requested - 1:
            logging.info(f"Waiting for 3 seconds before next request...")
            await asyncio.sleep(10)
        loopendtime = time.time()
        logging.info(f"Time for loop {i} is {loopendtime - looptime}")

    # --- Record end time and calculate duration ---
    end_time = time.time()
    duration_seconds = end_time - start_time
    duration_minutes = duration_seconds / 60

    # --- Final status update
    if status_data['completed_count'] == total_requested:
        status_data['status'] = 'completed'
        utils.write_batch_status(status_data)
        logging.info("Batch successfully completed.")

    # --- Generate and print the final summary ---
    summary = (
        f"\n--- Batch Run Summary ---\n"
        f"Status: {status_data['status'].upper()}\n"
        f"Total Events Requested: {total_requested}\n"
        f"Total Events Completed: {status_data['completed_count']}\n"
        f"  - Succeeded in this run: {successful_logs_this_run}\n"
        f"  - Failed in this run: {failed_logs}\n"
        f"--------------------------\n"
        f"Start Time: {datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"End Time:   {datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Total Duration: {duration_seconds:.2f} seconds ({duration_minutes:.2f} minutes)\n"
        f"--------------------------"
    )
    
    print(summary) # Print summary to console
    logging.info(f"[BATCH_SUMMARY] {json.dumps(status_data)}") # Log final status for machine parsing
    logging.info(summary) # Log human-readable summary to file


if __name__ == "__main__":
    asyncio.run(main())