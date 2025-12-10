# audit_service.py
'''
This module acts as the high-level service layer for the AnchorForge application.
It abstracts away the complexity of file locking, store management, and transaction orchestration,
providing a simple interface for logging events.
'''

import logging
import uuid
import portalocker
from portalocker import LOCK_EX
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
import asyncio
import json

from bsv import PrivateKey
from bsv.hash import sha256

from anchorforge.config import Config
from anchorforge import wallet_manager
from anchorforge import utils
from anchorforge import core_defs
from anchorforge import publisher
from anchorforge import key_x509_manager
from anchorforge import blockchain_api
from anchorforge.block_manager import BlockHeaderManager


logger = logging.getLogger(__name__)

# --- Internal Helpers ---

async def _prepare_data_and_hash(
    data_source: str | None, 
    file_source: str | None, 
    mode: str
) -> Tuple[str, Optional[bytes]]:
    """
    Determines the content to be logged and computes its hash.
    Returns: (content_string_for_log, hash_bytes)
    """
    content_str = ""
    data_hash = None

    if mode == "embedded":
        content_str = data_source if data_source else "Default Audit Entry"
        data_hash = sha256(content_str.encode('utf-8'))
        # logger.debug(f"Prepared embedded data. Hash: {data_hash.hex()}")

    elif mode == "by_reference":
        if not file_source:
            logger.error("Mode is 'by_reference' but no file provided.")
            return "", None
        content_str = file_source # For the log, the content is the filename
        data_hash = await utils.hash_file_async(file_source)
        if data_hash:
            logger.info(f"Prepared file reference '{file_source}'. Hash: {data_hash.hex()}")
        else:
            logger.error(f"Failed to hash file {file_source}")

    return content_str, data_hash

def _build_payloads(
    content_str: str, 
    data_hash: bytes, 
    mode: str
) -> List[bytes]:
    """Constructs the list of data pushes (AppID, EC, X509). 
    op_return_payload_for_tx = app_id_payload + ec_payload + x509_payload """
    
    # 1. App ID
    payloads = [core_defs.AUDIT_MODE_APP_ID, Config.ANCHOR_FORGE_ID.encode('utf-8')]

    # 2. EC Signature
    assert Config.PRIVATE_SIGNING_KEY_WIF is not None
    if mode == "embedded":
        payloads += publisher.build_audit_payload(content_str, Config.PRIVATE_SIGNING_KEY_WIF)
    else:
        payloads += publisher.build_audit_payload_prehashed(data_hash, Config.PRIVATE_SIGNING_KEY_WIF)

    # 3. X.509 Certificate (Optional)
    # TODO: Make the label configurable if needed
    x509_label = 'anchor_example_certificate'
    cert_info = key_x509_manager.get_x509_key_pair_by_label(x509_label)
    
    if cert_info and cert_info.get('private_key_pem') and cert_info.get('certificate_pem'):
        priv_pem = cert_info['private_key_pem']
        cert_pem = cert_info['certificate_pem']
        if mode == "embedded":
            payloads += publisher.build_x509_audit_payload(content_str, priv_pem, cert_pem)
        else:
            payloads += publisher.build_x509_audit_payload_prehashed(data_hash, priv_pem, cert_pem)
            
    return payloads

def _create_audit_record_entry(
    log_id: str,
    keyword: str | None,
    mode: str,
    content_str: str,
    record_note: str | None,
    tx_note: str | None,
    payloads: List[bytes]
) -> Dict:
    """Creates the initial dictionary for the audit record."""
    
    # Helper to find data based on mode byte in the linear payload list
    def find_payload_data(mode_byte):
        try:
            idx = payloads.index(mode_byte)
            # Ensure we have enough elements following the mode byte
            if idx + 3 < len(payloads):
                return payloads[idx+1], payloads[idx+2], payloads[idx+3]
        except ValueError:
            pass
        return None, None, None

    ec_hash, ec_sig, ec_pub = find_payload_data(core_defs.AUDIT_MODE_EC)
    x509_hash, x509_sig, x509_cert = find_payload_data(core_defs.AUDIT_MODE_X509)

    return {
        "log_id": log_id,
        "keyword": keyword,
        "data_storage_mode": mode,
        "original_audit_content": content_str,
        "timestamp_logged_local": datetime.now(timezone.utc).isoformat(),
        "format": core_defs.AUDIT_RECORD_FORMAT_V1,
        "blockchain_record": {
            "txid": None,
            "status": "pending_creation",
            "data_hash_pushed_to_op_return": ec_hash.hex() if ec_hash else None,
            "signature_pushed_to_op_return": ec_sig.hex() if ec_sig else None,
            "x509_hash_pushed": x509_hash.hex() if x509_hash else None,
            "x509_certificate_pushed": x509_cert.decode('utf-8') if x509_cert else None,
            "tx_note": tx_note
        },
        "notes": record_note or ""
    }


# --- Public Interface ---


def perform_backup(target_dir: str = Config.BACKUP_DIR):
    """
    Creates a backup of all critical state files (Audit Log, UTXO Store, TX Store).
    Can be called by any script using this service.
    """
    logger.info("--- Service: Performing Backup ---")
    try:
        # Determine paths
        assert Config.UTXO_STORE_KEY_WIF is not None
        priv_key = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
        address = str(priv_key.address())
        
        # We always backup the REAL files, not simulation files
        path_utxo = wallet_manager._get_filename_for_address(address, Config.ACTIVE_NETWORK_NAME, simulation=False)
        path_tx = path_utxo.replace("utxo_store", "tx_store")
        path_used = path_utxo.replace("utxo_store", "used_utxo_store")
        
        audit_file = Config.AUDIT_LOG_FILE
        files_to_backup = [
            Config.AUDIT_LOG_FILE,
            path_utxo,
            path_tx,
            path_used
        ]
        
        # Check if X509 store exists and add it
        if hasattr(Config, 'X509_KEYPAIR_STORE_FILE') and Config.X509_KEYPAIR_STORE_FILE:
             files_to_backup.append(Config.X509_KEYPAIR_STORE_FILE)

        utils.create_backup(files_to_backup, target_dir)
        logger.info("Backup completed successfully via Service.")
        
    except Exception as e:
        logger.error(f"Backup failed: {e}")




async def log_audit_event(
        data_source: str | None = None,
        file_source: str | None = None,
        data_storage_mode: str = "embedded",
        record_note: str | None = None,
        tx_note: str | None = None,
        keyword: str | None = "general",
        dry_run: bool = False,
        no_broadcast: bool = False) -> bool:
    """
    Main service function to log an event.
    Handles preparation, locking, transaction creation, and storage updates.
    """
    
    logger.info(f"--- Service: Logging Audit Event (Mode: {data_storage_mode}) ---")
    
    # 1. Prepare Data
    content_str, data_hash = await _prepare_data_and_hash(data_source, file_source, data_storage_mode)
    if data_hash is None: 
        return False

    # 2. Setup File Paths
    # Ideally, wallet_manager should expose a cleaner way to get this without private keys, 
    # but for now we stick to the existing pattern.
    assert Config.UTXO_STORE_KEY_WIF is not None
    priv_key = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
    address = str(priv_key.address())
    
    is_sim = no_broadcast
    
    # Define file paths
    path_utxo = wallet_manager._get_filename_for_address(address, Config.ACTIVE_NETWORK_NAME, simulation=is_sim)
    path_tx = path_utxo.replace("utxo_store", "tx_store")
    path_used = path_utxo.replace("utxo_store", "used_utxo_store")
    path_audit = Config.AUDIT_LOG_FILE.replace(".json", ".sim.json") if is_sim else Config.AUDIT_LOG_FILE

    # 3. Execution (Locking & Transaction)
    try:
        # Atomic lock on all stores
        with portalocker.Lock(path_audit, "r+", flags=LOCK_EX, timeout=5) as f_audit, \
             portalocker.Lock(path_tx, "r+", flags=LOCK_EX, timeout=5) as f_tx, \
             portalocker.Lock(path_used, "r+", flags=LOCK_EX, timeout=5) as f_used, \
             portalocker.Lock(path_utxo, "r+", flags=LOCK_EX, timeout=5) as f_utxo:

            # Load Stores
            audit_log = core_defs.load_audit_log(f_audit)
            store_utxo = wallet_manager.load_utxo_store(f_utxo)
            store_tx = wallet_manager.load_tx_store(f_tx)
            store_used = wallet_manager.load_used_utxo_store(f_used)

            # Build Payloads
            op_return_pushes = _build_payloads(content_str, data_hash, data_storage_mode)
            
            # Create Record Entry
            log_id = str(uuid.uuid4())
            record = _create_audit_record_entry(
                log_id, keyword, data_storage_mode, content_str, record_note, tx_note, op_return_pushes
            )

            # Create Transaction
            result = await publisher.create_op_return_transaction(
                spending_key_wif=Config.UTXO_STORE_KEY_WIF,
                recipient_address=address,
                op_return_data_pushes=op_return_pushes,
                original_audit_content_string=content_str,
                network=Config.ACTIVE_NETWORK_BSV,
                current_utxo_store_data=store_utxo,
                tx_store=store_tx,
                f_tx_store=f_tx,
                note=tx_note,
                dry_run=dry_run,
                no_broadcast=no_broadcast
            )
            
            raw_tx, ts, txid, consumed, new_utxos, fee = result

            if raw_tx and (txid or dry_run):
                if dry_run:
                    logger.info("Dry run complete. No changes saved.")
                    return True

                tx_size_bytes = len(raw_tx) // 2

                # Update Record with success details
                record["blockchain_record"].update({
                    "txid": txid,
                    "raw_transaction_hex": raw_tx,
                    # "tx_size_bytes": tx_size_bytes,
                    # "data_hash_pushed_to_op_return": ec_payload[1].hex() if ec_payload else None,
                    "status": "broadcasted",
                    "timestamp_broadcasted_utc": ts,
                    "fee_satoshis": fee,
                    "inputs": consumed,
                    "outputs": new_utxos,
                    "tx_note": tx_note
                })
                audit_log.append(record)


                # Update Stores
                # Remove consumed UTXOs

                consumed_ids = set((u['txid'], u['vout']) for u in consumed)
                store_utxo["utxos"] = [u for u in store_utxo["utxos"] if (u['txid'], u['vout']) not in consumed_ids]
                
                # Add to used store
                for u in consumed:
                    u.update({
                        "used": True, 
                        "used_in_txid": txid, 
                        "used_timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    store_used["used_utxos"].append(u)
                
                # Add new UTXOs (change)
                store_utxo["utxos"].extend(new_utxos)

                # Save All
                wallet_manager.save_utxo_store(f_utxo, store_utxo)
                wallet_manager.save_used_utxo_store(f_used, store_used)
                wallet_manager.save_tx_store(f_tx, store_tx)
                core_defs.save_audit_log(f_audit, audit_log)
                
                logger.info(f"Success. Logged Event {log_id}. TXID: {txid}")
                return True
            else:
                # Failure Case
                if not dry_run:
                    record["blockchain_record"]["status"] = "tx_creation_failed"
                    audit_log.append(record)
                    core_defs.save_audit_log(f_audit, audit_log)
                
                logger.error("Transaction creation failed.")
                return False

    except portalocker.exceptions.LockException:
        logger.error("Could not acquire file locks. Is another process running?")
        return False
    except Exception as e:
        logger.error(f"Service Error: {e}", exc_info=True)
        return False
    

    
async def monitor_pending_transactions(utxo_file_path: str, used_utxo_file_path: str, polling_interval_seconds: int = 30):
    """
    Monitors locally stored pending transactions for confirmation on the blockchain.
    Once confirmed, fetches and stores their Merkle path and updates UTXO heights.

    Args:
        utxo_file_path (str): The file path for the UTXO store.
        used_utxo_file_path (str): The file path for the used UTXO store.
        polling_interval_seconds (int): How often to check for confirmations.
    """
    logger.info(f"\n--- Starting Transaction Confirmation Monitor (polling every {polling_interval_seconds}s) ---")

    # only start if new blocks exist.
    last_known_block_height = 0

    # start first time to solve waiting queue
    initial_run_completed = False  

    while True: # Loop indefinitely to keep monitoring
         # --- Check for pause/stop commands at the start of each cycle ---
        if await utils.check_process_controls('monitor'):
            break # Exit the loop if stop is requested

        if initial_run_completed:
            try:
                chain_info = await blockchain_api.get_chain_info_woc()
                current_block_height = chain_info.get("blocks", 0) if chain_info else 0

                if current_block_height <= last_known_block_height:
                    logger.info(f"  No new block found (current height: {current_block_height}). Sleeping...")
                    await asyncio.sleep(polling_interval_seconds)
                    continue # start next cycle without checking txs

                logger.info(f"  New block found! Height changed from {last_known_block_height} to {current_block_height}. Checking transactions...")
                last_known_block_height = current_block_height

            except Exception as e:
                logger.error(f"  Could not fetch current block height: {e}. Skipping this cycle.")
                await asyncio.sleep(polling_interval_seconds)
                continue

        try:
            try:
                with portalocker.Lock(Config.AUDIT_LOG_FILE, "r", flags=LOCK_EX, timeout=5) as f:
                    
                    # Load the entire audit log, as this is our central source of truth for records and their status.
                    audit_log = core_defs.load_audit_log(f)
            except FileNotFoundError:
                audit_log = [] # If the file doesn't exist, the log is empty
            
            # Filter records that have blockchain_record and whose status indicates they need monitoring.
            # This includes "broadcasted" (waiting for block), "broadcast_failed" (might retry or inspect),
            # or "pending_creation" (if we want the monitor to also attempt to broadcast, though currently
            # create_op_return_transaction handles initial broadcast).
            records_to_monitor = [
                record for record in audit_log
                if record.get("blockchain_record") and 
                    #X
                    record["blockchain_record"].get("status") in ["broadcasted", "broadcast_failed", "pending_creation"]
                ]
            
        except portalocker.exceptions.LockException:
            logger.warning("Monitor could not acquire lock to get tasks, skipping this cycle.")
            await asyncio.sleep(polling_interval_seconds)
            continue # jump to next cycle


        if not records_to_monitor:
            logger.info("  No pending audit records to monitor. Sleeping...")
        else:
            if not initial_run_completed:
                logger.info(f"  Initial run: Processing {len(records_to_monitor)} backlog records...")
            else:
                logger.info(f"  Monitoring {len(records_to_monitor)} audit records...")

            for record in records_to_monitor:
                # check for stop. When many tx to monitor, it would be blocked otherwise
                if await utils.check_process_controls('monitor'):
                    logger.info("Stop requested during record processing loop.")
                    # signal end of outer loop or break
                    # using a return
                    return # Stops monitor completely

                blockchain_rec = record["blockchain_record"]
                
                log_id = record["log_id"]


                txid_raw = blockchain_rec.get("txid") # TXID might be None for "pending_creation" status
                if not txid_raw: 
                    continue
                
                txid = txid_raw.strip().strip('"')
                if not txid: # is something left after cleaning
                    logger.warning(f"  Record '{log_id}' has an empty or invalid TXID after stripping. Skipping.")
                    continue


                # --- Handle "pending_creation" status (if create_op_return_transaction didn't broadcast yet) ---
                # Currently, create_op_return_transaction tries to broadcast immediately.
                # If txid is None here, it means create_op_return_transaction failed or wasn't fully executed.
                if not txid or blockchain_rec["status"] == "pending_creation":
                    logger.warning(f"  Audit record '{log_id}' is still in 'pending_creation' status or missing TXID. Cannot check confirmation yet.")
                    continue 
                        
                logger.info(f"  Checking confirmation for audit record '{log_id}' (TXID: {txid})...")
                        

                # API Request (reminder Ensure low request rate)
                tx_info = await blockchain_api.get_transaction_status_woc(txid)
                await asyncio.sleep(Config.DELAY_NEXT_MONITOR_REQUEST)


# Confirmed, now process
                if tx_info and tx_info.get("blockhash") and tx_info.get("blockheight"):
                    logger.info(f"    Audit record '{log_id}' (TXID {txid}) confirmed in block {tx_info['blockheight']} ({tx_info['blockhash']}).")


                    legacy_proof_data = None
                    tsc_proof_data = None

                    legacy_error = False
                    tsc_error = False

                    # 1. Fetch Legacy Proof (optional, Fallback, possibly for BTC?)
                    if Config.LEGACY_PROOF: # ignore, prepare for fadeout
                        try:
                            legacy_proof_data = core_defs.normalize_proof_data(await blockchain_api.get_merkle_path(txid))
                            
                            await asyncio.sleep(Config.DELAY_NEXT_MONITOR_REQUEST) # Pause
                        except Exception as e:
                            logger.error(f"    Error fetching legacy Merkle proof for {log_id}: {e}")
                            legacy_proof_data = None
                            legacy_error = True

                    # 2. Fetch TSC Proof (Mainnet only supports new one)
                    # try:
                    #     # --- call TSC-Function ---
                    #     tsc_proof_data = await blockchain_api.get_tsc_merkle_path(txid)
                    #     await asyncio.sleep(Config.DELAY_NEXT_MONITOR_REQUEST) # Pause
                    # except Exception as e:
                    #     logger.error(f"    Error fetching TSC Merkle proof for {log_id}: {e}")
                    #     fetch_error = True 
                    
                    try:
                        # --- call TSC-Function ---
                        tsc_proof_data = core_defs.normalize_proof_data(await blockchain_api.get_tsc_merkle_path(txid))
                        await asyncio.sleep(Config.DELAY_NEXT_MONITOR_REQUEST) # Pause

                    except Exception as e:
                        logger.error(f"    Error fetching TSC Merkle proof for {log_id}: {e}")
                        tsc_proof_data = None
                        tsc_error = True

                    try:
                        with portalocker.Lock(Config.AUDIT_LOG_FILE,  "r+", flags=LOCK_EX, timeout=10) as f_audit, \
                            portalocker.Lock(utxo_file_path, "r+", flags=LOCK_EX, timeout=5) as f_utxo:

                            # load data again to ensure work with most uptodate data
                            current_audit_log = core_defs.load_audit_log(f_audit)
                            utxo_store = wallet_manager.load_utxo_store(f_utxo)

                            # data record to be updated
                            target_record = next((r for r in current_audit_log if r.get("log_id") == log_id), None)


                            if target_record:
                                # Prevents overwriting if another process confirmed it in the meantime
                                if target_record.get("blockchain_record", {}).get("status") != "confirmed":
                                    needs_save = False # Flag ob gespeichert werden muss
                                    current_bc_rec = target_record["blockchain_record"]

                                    current_bc_rec["status"] = "confirmed"
                                    current_bc_rec["block_hash"] = tx_info["blockhash"]
                                    current_bc_rec["block_height"] = tx_info["blockheight"]
                                    current_bc_rec["timestamp_confirmed_utc"] = datetime.now(timezone.utc).isoformat()
                                    needs_save = True
                           
                                    if Config.LEGACY_PROOF: # only if we want to support it
                                        if legacy_proof_data:
                                            current_bc_rec[Config.LEGACY_PROOF_FIELD] = legacy_proof_data
                                            legacy_size = len(json.dumps(legacy_proof_data).encode('utf-8'))
                                            current_bc_rec[Config.LEGACY_SIZE_FIELD] = legacy_size
                                            logger.info(f"    Added legacy proof for {log_id} (Size: {legacy_size} bytes).")
                                        elif not legacy_error: # only log errors if no general error
                                            logger.warning(f"    Could not fetch legacy Merkle proof for {log_id}.")
                                            current_bc_rec[Config.LEGACY_PROOF_FIELD] = {"error": "Legacy proof unavailable"}

                                    # TSC Proof hinzufügen (falls erfolgreich geholt)
                                    if tsc_proof_data:
                                        current_bc_rec[Config.TSC_PROOF_FIELD] = tsc_proof_data
                                        current_bc_rec[Config.TSC_TIMESTAMP_FIELD] = datetime.now(timezone.utc).isoformat()
                                        tsc_size = len(json.dumps(tsc_proof_data).encode('utf-8'))
                                        current_bc_rec[Config.TSC_SIZE_FIELD] = tsc_size
                                        logger.info(f"    Added TSC proof for {log_id} (Size: {tsc_size} bytes).")
                                    elif not tsc_error: # Nur Fehler loggen, wenn kein genereller Fehler auftrat
                                        logger.warning(f"    Could not fetch TSC Merkle proof for {log_id}.")
                                        current_bc_rec[Config.TSC_PROOF_FIELD] = {"error": "TSC proof unavailable"}
                    
                                
                                    # Update UTXO store for newly created UTXOs in this transaction (height)
                                    # This needs to be loaded and saved specifically by the monitor.

                                
                                    updated_utxos_count = 0
                                    for utxo in utxo_store["utxos"]:
                                        # Check if this UTXO was created by the confirmed transaction and its height is unknown
                                        if utxo["txid"] == txid and utxo.get("height", -1) == -1: 
                                            utxo["height"] = tx_info["blockheight"]
                                            updated_utxos_count += 1

                                    if needs_save:
                                        core_defs.save_audit_log(f_audit, current_audit_log)

                                        if updated_utxos_count > 0:
                                            wallet_manager.save_utxo_store(f_utxo, utxo_store)
                                            logger.info(f"    Updated height for {updated_utxos_count} UTXO(s) from TXID {txid} in local UTXO store.")
     
                                        logger.info(f"    Successfully confirmed and updated record '{log_id}'.")
                                else:
                                    logger.info(f"   Record '{log_id}' was already marked for confirmed. Skipping update.")
                            else: logger.warning(f"    Record '{log_id}' not found in audit log during update attempt. Log might have changed.")
                    
                    except portalocker.exceptions.LockException:
                        logger.warning("Monitor could not acquire lock, skipping this cycle.")
                elif blockchain_rec["status"] == "broadcasted":
                    logger.info(f"    Audit record '{log_id}' (TXID {txid}) is on the network but not yet confirmed.")
                elif blockchain_rec["status"] == "broadcast_failed":
                    logger.warning(f"    Audit record '{log_id}' (TXID {txid}) was previously marked 'broadcast_failed'. Still unconfirmed.")
                else:
                    logger.warning(f"    Audit record '{log_id}' (TXID {txid}) status: '{blockchain_rec.get('status')}'. Still unconfirmed or encountered network issue.")
        if not initial_run_completed:
            initial_run_completed = True
            try:
                chain_info = await blockchain_api.get_chain_info_woc()
                last_known_block_height = chain_info.get("blocks", 0) if chain_info else 0
                logger.info(f"  Initial run completed. Now monitoring for new blocks starting from height {last_known_block_height}.")
            except Exception as e:
                logger.error(f"Could not fetch block height after initial run:{e}")

        logger.info(f"  ... sleeping for {polling_interval_seconds} seconds.")
        await asyncio.sleep(polling_interval_seconds)
    logger.info("--- Monitor worker loop has been stopped gracefully. ---")
