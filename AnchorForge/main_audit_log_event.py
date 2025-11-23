# main_audit_log_event.py
'''
This program serves as the entry point for logging a single audit event.
(Version 0.3: Now supports --data for 'embedded' and --file for 'by_reference')

--dry-run no change to stores
--no-broadcast no broardcast, BUT updates all Stores
'''

import asyncio
import logging
from typing import List, Dict, Optional
from datetime import datetime, timezone
import uuid
import os
import sys
import argparse
import portalocker
from portalocker import LOCK_EX

from config import Config
import wallet_manager
import utils
import bank_functions
import audit_core
import key_x509_manager # Import the new module
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

logger = logging.getLogger(__name__)

VIBECODEVERSION=0.5 # Version updated

#AUDIT_RECORD_FORMAT_STRING = "TX, OP_RETURN format: [mode:byte, [( (hash:bytes, signature:bytes, [pubkey:bytes|certificate:bytes])|(note:bytes) ]+"


def get_content_from_source(source: str | None) -> str | None:
    """
    Resolves the content from a source string.
    If the string starts with '@', it's treated as a file path.
    Otherwise, it's treated as a literal string.
    """
    if source is None:
        return None
    
    if source.startswith('@'):
        file_path = source[1:]
        try:
            if not os.path.exists(file_path):
                logger.warning(f"File path specified but not found: {file_path}")
                return f"Error: File not found at {file_path}"
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return f"Error: Could not read file {file_path}"
    else:
        # It's a literal string
        return source

async def log_intermediate_result_process_extended(
        data_source: str | None = None,
        file_source: str | None = None,         # New: Path to file
        data_storage_mode: str = "embedded",  # New: Passed from main()
        record_note_content: str | None = None,
        tx_note_content: str | None = None,
        keyword: str | None = None,
        dry_run: bool = False,
        no_broadcast: bool = False) -> bool:
    """
    (Version 0.4)
    Orchestrates all steps for logging a single event, supporting both
    - embedded data and 
    - by-reference file content anchoring.

    This function is the "intelligent" worker for main_audit_log_event.py.
    """
    logging.info(f"--- Starting Single Audit Log Process (Mode: {data_storage_mode}) ---")
    
    # signing makes no sense without signing key
    assert Config.PRIVATE_SIGNING_KEY_WIF is not None
    assert Config.UTXO_STORE_KEY_WIF is not None, "UTXO_STORE_KEY_WIF is none"

    # --- 1. Prepare Data and Hash ---    
    intermediate_audit_content_string: str = ""          # This will be the string OR the filepath
    record_note = ""
    tx_note = ""

    data_hash: Optional[bytes] = None  # Must be raw bytes for audit_core functions


    # region set intermediate audit content + create data hash (embedded/by_reference)
    try:
        if data_storage_mode == "embedded":
            if data_source is None:
                timestamp_str = datetime.now(timezone.utc).isoformat()
                intermediate_audit_content_string = f"Audit Log Entry: Process step completed at {timestamp_str}. Result: SUCCESS. [Germany Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"


                logger.error("  Audit Data: Using default data for demonstration.")

            else:
                intermediate_audit_content_string = data_source  # data_source IS the content string

            logging.info(f" 1. Content to be hashed (embedded): '{intermediate_audit_content_string[:200]}...'")

            # Calculate hash (sha256 returns raw bytes)
            data_hash = sha256(intermediate_audit_content_string.encode('utf-8'))

        elif data_storage_mode == "by_reference":
            if file_source is None:
                logger.error("  FAIL: Mode is 'by_reference' but no file was provided.")
                return False

            intermediate_audit_content_string = file_source  # file_source IS the file path
            logging.info(f" 1. File to be hashed (by reference): '{intermediate_audit_content_string}'")
            
            # Call the async file hasher from utils.py
            # (Ensure utils.py contains 'hash_file_async' from our previous discussion)
            data_hash = await utils.hash_file_async(intermediate_audit_content_string)
            
            if data_hash is None:
                # Error is already logged by hash_file_async
                logging.error(f"  FAIL: Failed to hash file at '{intermediate_audit_content_string}'. Aborting.")
                return False # Abort this event
        
        else:
            logging.error(f"  FAIL: Unknown data_storage_mode: '{data_storage_mode}'")
            return False

        # This log is safe because 'data_hash' is guaranteed to be 'bytes' here
        logging.info(f" 1a. Generated Hash (bytes): {data_hash.hex()}")

    except Exception as e:
        logger.error(f"  FAIL: An unexpected error occurred during hashing: {e}", exc_info=True)
        return False
    
    # endregion
   
    # region set record note
    if record_note_content is None:
        # do nothing (what happens with an empty note?)
        logging.info(f"No record note given, using standard")
        record_note = audit_core.AUDIT_RECORD_FORMAT_V1
    else:
        record_note = record_note_content
    # endregion

    # region set tx note
    if tx_note_content is None:
        # do nothing (what happens with an empty note?)
        logging.info(f"No tx note given. Using empty")
        tx_note = None
    else:
        tx_note = tx_note_content

    logging.info(f"\n--- New Tx Note ---")
    if tx_note is None:
        logging.info("Content to be noted: None")
    else:
        logging.info(f"  Content to be noted: '{tx_note[:200]}...'")
    #endregion tx note

    # region --- 2. Determine file paths (simulation or real)
    is_simulation = no_broadcast
    
    # We must use the correct PrivateKey for the address
    assert Config.UTXO_STORE_KEY_WIF is not None

    priv_key_funding = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
    sender_address = priv_key_funding.address()
    
    utxo_file_path = wallet_manager._get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME, simulation=is_simulation)
    tx_file_path = utxo_file_path.replace("utxo_store", "tx_store")
    used_utxo_file_path = utxo_file_path.replace("utxo_store", "used_utxo_store")
    audit_log_file = Config.AUDIT_LOG_FILE.replace(".json", ".sim.json") if is_simulation else Config.AUDIT_LOG_FILE
    # endregion


    # --- 4. Lock files and execute transaction ---
    try:
        

        # ORDER is important. Ensure identical order whenever used
        with portalocker.Lock(audit_log_file, "r+", flags=LOCK_EX, timeout=Config.ACCESS_TIMEOUT) as f_audit, \
             portalocker.Lock(tx_file_path, "r+", flags=LOCK_EX, timeout=Config.ACCESS_TIMEOUT) as f_tx, \
             portalocker.Lock(used_utxo_file_path, "r+", flags=LOCK_EX, timeout=Config.ACCESS_TIMEOUT) as f_used, \
             portalocker.Lock(utxo_file_path, "r+", flags=LOCK_EX, timeout=Config.ACCESS_TIMEOUT) as f_utxo:

            # region  Load all stores using the open file handles
            audit_log = audit_core.load_audit_log(f_audit)
            tx_store = wallet_manager.load_tx_store(f_tx)
            used_store = wallet_manager.load_used_utxo_store(f_used)
            store = wallet_manager.load_utxo_store(f_utxo)
            #endregion

            #region --- 4a. Prepare Payloads (EC, X509, App ID) ---
            # region ec
            if data_storage_mode== "embedded":
                # use original method
                ec_payload = audit_core.build_audit_payload(
                                 intermediate_audit_content_string, 
                                 Config.PRIVATE_SIGNING_KEY_WIF)
            else:
                # use the hash computed from the file directly
                # build_audit_payload expects the raw data_hash (bytes)
                ec_payload = audit_core.build_audit_payload_prehashed(
                                            precomputed_hash=data_hash, # This needs to be 'bytes'
                                            signing_key_wif=Config.PRIVATE_SIGNING_KEY_WIF,
                                            
                )
            # endregion


            # region x509
            x509_payload = []
            x509_key_label = 'anchor_example_certificate' if Config.ACTIVE_NETWORK_NAME == "test" else 'anchor_example_certificate'
            cert_info = key_x509_manager.get_x509_key_pair_by_label(x509_key_label)
            
            if cert_info:
                private_x509_key_pem = cert_info.get('private_key_pem')
                x509_cert_pem = cert_info.get('certificate_pem')
                if private_x509_key_pem and x509_cert_pem:
                    if data_storage_mode == "embedded":
                        x509_payload = audit_core.build_x509_audit_payload(intermediate_audit_content_string, private_x509_key_pem, x509_cert_pem)
                    else:
                        x509_payload = audit_core.build_x509_audit_payload_prehashed(data_hash, private_x509_key_pem, x509_cert_pem)

            #endregion
            

            app_id_payload = [audit_core.AUDIT_MODE_APP_ID, Config.ANCHOR_FORGE_ID.encode('utf-8')]
            
            op_return_payload_for_tx = app_id_payload + ec_payload + x509_payload

            #endregion Payloads

            
            # Temporary Audit-Record in memory
            audit_record_entry = {
                "log_id": str(uuid.uuid4()),
                "keyword": keyword, 
                "data_storage_mode": data_storage_mode,
                "original_audit_content": intermediate_audit_content_string, # (contains string or path)
                "timestamp_logged_local": datetime.now(timezone.utc).isoformat(),
                "format": audit_core.AUDIT_RECORD_FORMAT_V1,
                "blockchain_record": {
                    "txid": None, 
                    "raw_transaction_hex": None, 
                    "status": "pending_creation",
                    "data_hash_pushed_to_op_return": ec_payload[1].hex() if ec_payload else None,
                    "signature_pushed_to_op_return": ec_payload[2].hex() if ec_payload else None,
                    "public_key_pushed_to_op_return": ec_payload[3].hex() if ec_payload else None,
                    "x509_hash_pushed": x509_payload[1].hex() if x509_payload else None,
                    "x509_signature_pushed": x509_payload[2].hex() if x509_payload else None,
                    "x509_certificate_pushed": x509_payload[3].decode('utf-8') if x509_payload else None,
                    "tx_node": tx_note
                }, "notes": record_note
            }
            
            
            # region --- 4b. Create Transaction ---
            tx_hex_returned, broadcast_timestamp_str, broadcast_txid, \
             consumed_utxos_details, new_utxos_details, calculated_fee = await audit_core.create_op_return_transaction(
                spending_key_wif=Config.UTXO_STORE_KEY_WIF,
                recipient_address=str(sender_address),
                op_return_data_pushes=op_return_payload_for_tx,
                original_audit_content_string=intermediate_audit_content_string, # only for logs
                network=Config.ACTIVE_NETWORK_BSV,
                current_utxo_store_data=store,
                tx_store=tx_store,
                f_tx_store=f_tx,
                note=tx_note_content,
                dry_run=dry_run,
                no_broadcast=no_broadcast
            )
            #endregion

            # --- 4c. Process Result ---
            if tx_hex_returned and broadcast_txid:
                # --- SUCCESS CASE ---
                logging.info(f"Transaction created & broadcasted: {broadcast_txid}")

                tx_size_bytes = len(tx_hex_returned) // 2 if tx_hex_returned else 0
                
                # Update the record with all blockchain info
                audit_record_entry["blockchain_record"].update({
                    "txid": broadcast_txid,
                    "raw_transaction_hex": tx_hex_returned,
                    "status": "broadcasted", 
                    "timestamp_broadcasted_utc": broadcast_timestamp_str,
                    "fee_satoshis": calculated_fee, 
                    "tx_size_bytes": tx_size_bytes,
                    "inputs": consumed_utxos_details, 
                    "outputs": new_utxos_details,
                    "tx_note": tx_note_content
                })
                audit_log.append(audit_record_entry)

                # region Update UTXO stores (recycle change)
                for consumed_utxo in consumed_utxos_details:
                    store["utxos"] = [u for u in store["utxos"] if not (u["txid"] == consumed_utxo["txid"] and u["vout"] == consumed_utxo["vout"])]
                    consumed_utxo.update({"used": True, "used_in_txid": broadcast_txid, "used_timestamp": datetime.now(timezone.utc).isoformat()})
                    used_store["used_utxos"].append(consumed_utxo)
                
                store["utxos"].extend(new_utxos_details)
                # endregion

                # region Save all stores
                wallet_manager.save_utxo_store(f_utxo, store)
                wallet_manager.save_used_utxo_store(f_used, used_store)
                audit_core.save_audit_log(f_audit, audit_log)
                wallet_manager.save_tx_store(f_tx, tx_store)

                logging.info("All local stores updated successfully.")
                #endregion

                logging.info(f"Audit event logged successfully. TXID: {broadcast_txid}")
                return True
            else:
                # --- FAILURE CASE ---
                audit_record_entry["blockchain_record"]["status"] = "tx_creation_failed"
                # Add hash even on failure
                audit_record_entry["blockchain_record"]["data_hash_pushed_to_op_return"] = data_hash.hex()
                audit_log.append(audit_record_entry)
                audit_core.save_audit_log(f_audit, audit_log)
                
                logging.error(f"Failed to create transaction for audit record '{audit_record_entry['log_id']}'.")
                return False

    except portalocker.exceptions.LockException as e:
        logging.error(f"Could not acquire lock for processing: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred in log_intermediate_result_process: {e}", exc_info=True)
        return False


async def main():
    """
    (Version 0.3)
    Main entry point. Parses arguments and passes them to the worker function.
    Now supports mutually exclusive --data and --file arguments.
    """
    parser = argparse.ArgumentParser(
        description="AnchorForge v0.2: Log a single audit event.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # --- START: --data and --file as an exclusive group ---
    data_group = parser.add_mutually_exclusive_group(required=True)
    data_group.add_argument(
        '--data',
        type=str,
        help="The raw string data to be embedded and anchored (mode: embedded)."
    )
    data_group.add_argument(
        '--file',
        type=str,
        help="The file path to be hashed and anchored (mode: by_reference)."
    )
    # --- END ---

    parser.add_argument(
        '--record-note',
        type=str,
        default=None,
        help="A note for the audit log record (e.g., '@./path/to/note.txt' or 'Literal note')."
    )
    parser.add_argument(
        '--transaction-note',
        type=str,
        default=None,
        help="A note for the blockchain transaction (e.g., '@./path/to/note.txt' or 'Literal note')."
    )
    parser.add_argument(
        '--keyword',
        type=str,
        default="general-event",
        help="A keyword to categorize this event (e.g., 'system-startup')."
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help="Simulate the transaction without making changes to local stores."
    )
    parser.add_argument(
        '--no-broadcast',
        action='store_true',
        help="Create the transaction and update stores, but do not broadcast to the network."
    )
    parser.add_argument(
        '--mainnet',
        action='store_true',
        help="DANGEROUS: Force use of mainnet. Must be explicitly set."
    )

    args = parser.parse_args()

    # 1. Safety check for mainnet
    if Config.ACTIVE_NETWORK_NAME == "main" and not args.mainnet:
        logging.error("ERROR: Network is set to 'main' in .env, but --mainnet flag was not provided.")
        logging.error("This is a safety feature. Add --mainnet to your command if you are sure.")
        return
    elif Config.ACTIVE_NETWORK_NAME == "test" and args.mainnet:
        logging.warning("Warning: --mainnet flag is set, but .env network is 'test'. Proceeding with TESTNET.")

    # 4. resolve content from note sources
    record_note_content = get_content_from_source(args.record_note)
    tx_note_content = get_content_from_source(args.transaction_note)

    # --- START: New Linter-Proof Logic ---
    # We define the variables *before* the 'await' call
    
    data_to_pass: str | None
    file_to_pass: str | None
    data_storage_mode: str
    
    if args.data:
        data_storage_mode = "embedded"
        
        
        data_to_pass = args.data 
        assert data_to_pass is not None

        file_to_pass = None # Explicitly set the other to None
        
        # Linter is happy: 'data_to_pass' is confirmed to be 'str' inside this block.
        logging.info(f"Received data (mode: {data_storage_mode}): {data_to_pass[:100]}...") 
        
    elif args.file:
        data_storage_mode = "by_reference"
        file_to_pass = args.file

        assert file_to_pass is not None
        data_to_pass = None # Explicitly set the other to None
        
        # Linter is happy: 'file_to_pass' is confirmed to be 'str' inside this block.
        if not os.path.exists(file_to_pass): 
            logger.error(f"Error: File not found at path: {file_to_pass}")
            sys.exit(1)
        logging.info(f"Received file (mode: {data_storage_mode}): {file_to_pass}")
    
    else:
        # This block makes the linter happy about unassigned variables,
        # even if argparse(required=True) makes it unreachable.
        logger.error("Internal Error: No --data or --file provided, but argparse group was required.")
        sys.exit(1)

    logging.info(f"Received audit record note: {record_note_content}")
    logging.info(f"Received audit tx note: {tx_note_content}")
    # --- END: New Linter-Proof Logic ---

    # Ensure log files exist before locking with "r+"
    utils.ensure_json_file_exists(Config.AUDIT_LOG_FILE)
    utils.ensure_json_file_exists(Config.TX_STORE_FILE)
    # utils.ensure_json_file_exists(Config.X509_KEYPAIR_STORE_FILE, initial_content={})

    # 5. call core function
    await log_intermediate_result_process_extended(
            data_source=data_to_pass,       # Is 'str | None'
            file_source=file_to_pass,       # Is 'str | None'
            data_storage_mode=data_storage_mode, # Is 'str'
            record_note_content=record_note_content,
            tx_note_content=tx_note_content,
            keyword=args.keyword,
            dry_run=args.dry_run,
            no_broadcast=args.no_broadcast
        )

if __name__ == "__main__":
    asyncio.run(main())

# The old sys.argv logic at the end of the file is removed as
# it conflicts with the argparse implementation.