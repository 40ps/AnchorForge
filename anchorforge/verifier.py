# audit_verifier.py
'''
Logic for VERIFYING and MONITORING audit records.
Contains: Payload verification, SPV proofs
'''

#import asyncio

from typing import List, Dict, Any, Optional, IO, cast
from datetime import datetime, timezone

import os
import logging
import portalocker
from portalocker import LOCK_EX

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend



from bsv import (
    PrivateKey, PublicKey,
    P2PKH, 
    Transaction, TransactionInput, TransactionOutput, 
    Network, 
    Script, 
    SatoshisPerKilobyte, 
    UnlockingScriptTemplate,
    hash256
)

from bsv.hash import sha256 # Import sha256 function directly from bsv.hash module

from anchorforge.config import Config
from anchorforge import blockchain_api
from anchorforge import utils
from anchorforge import core_defs # Shared constants
from anchorforge.block_manager import BlockHeaderManager

logger = logging.getLogger(__name__)


async def _resolve_and_hash_file(
    original_path: str,
    data_search_path: Optional[str],
    alt_file_reference: Optional[str]
) -> Optional[bytes]:
    """
    Resolves the final file path based on a 3-tier priority system and hashes the file.
    Returns the SHA-256 hash (bytes) if successful, None otherwise.
    """
    logger.debug(f"Starting file resolution for original path: {original_path}")
    final_path = None
    
    # 1. Priority 1: Check Original Path (The fastest check)
    if os.path.exists(original_path):
        final_path = original_path
        logger.debug(f"File resolution: Found at original path: {final_path}")
    
    # 2. Priority 2: Check Alternative File Reference (Applies to both full path and filename in search path)
    if final_path is None and alt_file_reference:
        
        # 2a. Check if alt_file_reference is a direct path that exists
        if os.path.exists(alt_file_reference):
            final_path = alt_file_reference
            logger.warning(f"File resolution: Using full alternative path: {final_path}")
            
        # 2b. Check if alt_file_reference (as filename) exists in the search path
        elif data_search_path:
            alt_filename = os.path.basename(alt_file_reference)
            candidate_path = os.path.join(data_search_path, alt_filename)
            
            if os.path.exists(candidate_path):
                final_path = candidate_path
                logger.warning(f"File resolution: Using search path with alternative filename: {final_path}")

    # 3. Priority 3: Check Search Path + Original Filename (Fallback)
    if final_path is None and data_search_path:
        original_filename = os.path.basename(original_path)
        candidate_path = os.path.join(data_search_path, original_filename)
        
        if os.path.exists(candidate_path):
            final_path = candidate_path
            logger.warning(f"File resolution: Using search path with original filename fallback: {final_path}")

    # 4. Hash the found file
    if final_path is None:
        logger.error(f"File resolution FAILED: Cannot find file for original reference '{original_path}'.")
        return None
        
    logger.info(f"File resolution SUCCESS: Hashing file at: {final_path}")
    
    # Call the asynchronous file hasher (utils.py)
    return await utils.hash_file_async(final_path)


# --- Payload Extraction & Verification 
def extract_op_return_payload(raw_tx_hex: str) -> List[bytes]:
    """
    Extracts all data pushes from the first OP_RETURN output in a raw transaction.
    This corrected version manually parses the script bytes to correctly handle
    all OP_PUSHDATA opcodes, fixing the bug in older bsv-sdk versions.

    Args:
        raw_tx_hex (str): The raw transaction in hexadecimal string format.

    Returns:
        List[bytes]: A list of byte strings representing the data pushes in the
                     OP_RETURN script. Returns an empty list if no OP_RETURN
                     output is found or an error occurs.
    """
    #TODO Make robust against missing OP_FALSE
    logger.info("\n--- SIMULATION: Extracting OP_FALSE OP_RETURN Payload from Transaction ---")
    try:
        tx = Transaction.from_hex(raw_tx_hex)
        if tx is None:
            logger.error("Error: Could not deserialize transaction hex.")
            return []

        for tx_output in tx.outputs:
            locking_script = tx_output.locking_script
            script_bytes = bytes.fromhex(locking_script.hex())

            start_index = -1

            if script_bytes.startswith(bytes.fromhex("006a")): # OP_FALSE (0x00) OP_RETURN (0x6a)
                start_index = 2
                logger.info(f"  Found OP_FALSE OP_RETURN output at index {tx.outputs.index(tx_output)}.")
            # Fall back to old pattern
            elif script_bytes.startswith(bytes.fromhex("6a")):
               start_index = 1
               logger.info(f"  Found legacy OP_RETURN output at index {tx.outputs.index(tx_output)}.")
            
            if start_index == -1:
                continue

            data_pushes = []
            current_index = start_index # Start after [OP_FALSE] OP_RETURN-Opcode (0x6a)

            while current_index < len(script_bytes):
                # read length byte (or Opcode)
                length_or_opcode = script_bytes[current_index]
                current_index += 1

                if 0x01 <= length_or_opcode <= 0x4b:
                    # Direce Data-Push (OP_1 - OP_75)
                    data_length = length_or_opcode
                    data_push_end = current_index + data_length
                    data_pushes.append(script_bytes[current_index:data_push_end])
                    current_index = data_push_end
                elif length_or_opcode == 0x4c: # OP_PUSHDATA1
                    data_length = script_bytes[current_index]
                    current_index += 1
                    data_push_end = current_index + data_length
                    data_pushes.append(script_bytes[current_index:data_push_end])
                    current_index = data_push_end
                elif length_or_opcode == 0x4d: # OP_PUSHDATA2
                    data_length_bytes = script_bytes[current_index:current_index + 2]
                    data_length = int.from_bytes(data_length_bytes, byteorder='little')
                    current_index += 2
                    data_push_end = current_index + data_length
                    data_pushes.append(script_bytes[current_index:data_push_end])
                    current_index = data_push_end
                elif length_or_opcode == 0x4e: # OP_PUSHDATA4
                    data_length_bytes = script_bytes[current_index:current_index + 4]
                    data_length = int.from_bytes(data_length_bytes, byteorder='little')
                    current_index += 4
                    data_push_end = current_index + data_length
                    data_pushes.append(script_bytes[current_index:data_push_end])
                    current_index = data_push_end
                else:
                    logger.warning(f"  Unknown opcode or length prefix found: {hex(length_or_opcode)}. Stopping extraction.")
                    break
            
            logger.info(f"  Successfully extracted {len(data_pushes)} data pushes.")
            return data_pushes
            
        logger.warning("No OP_FALSE OP_RETURN output found in the transaction.")
        return []

    except Exception as e:
        logger.error(f"An unexpected error occurred during payload extraction: {e}")
        return []


async def _verify_spv_proof(
    blockchain_rec: dict, 
    txid: str, 
    header_manager: BlockHeaderManager, 
    log_id: str
) -> bool:
    """
    Internal V2 helper to verify the SPV proof for a record.
    Re-uses logic from the original audit_record_verifier.
    
    Returns False only if *a required* check fails. Not required checks will be ignored
    """
    logger.info(f"  Verifying Step 4: Blockchain Inclusion (SPV Proof)...")
    
    block_hash = blockchain_rec.get("block_hash")
    block_height = blockchain_rec.get("block_height")

    if block_hash is None:
        logger.warning("No blockheader for log id {log_id}")
        return False

    merkle_proof_to_use = None
    proof_type_used = None

    # --- Select which proof to use (prefer TSC) ---
    if Config.TSC_PROOF_FIELD in blockchain_rec:
        merkle_proof_to_use = blockchain_rec[Config.TSC_PROOF_FIELD]
        proof_type_used = "TSC"
    elif Config.LEGACY_PROOF_FIELD in blockchain_rec:
        merkle_proof_to_use = blockchain_rec[Config.LEGACY_PROOF_FIELD]
        proof_type_used = "Legacy"
    
    # --- Correct list[dict] format issue (for both types) ---
    if isinstance(merkle_proof_to_use, list) and len(merkle_proof_to_use) == 1 and isinstance(merkle_proof_to_use[0], dict):
        merkle_proof_to_use = merkle_proof_to_use[0]
        logger.warning(f"  Record {log_id}: Corrected {proof_type_used} proof format from list to dict.")

    if not all([block_hash, merkle_proof_to_use]):
        logger.error(f"  SPV Proof: FAIL. Missing block_hash or Merkle proof data for record '{log_id}'.")
        return False
    if not isinstance(merkle_proof_to_use, dict):
        logger.error(f"  SPV Proof: FAIL. Merkle proof data ({proof_type_used}) is not a dictionary. Type: {type(merkle_proof_to_use)}")
        return False

    # --- Fetch and Verify Block Header (uses passed-in header_manager) ---
    local_block_headers = header_manager.headers
    live_block_header = None
    
    if block_hash in local_block_headers:
        live_block_header = local_block_headers[block_hash]
    else:
        logger.info(f"  Block Header for '{block_hash}' (height {block_height}) NOT in cache. Fetching LIVE.")
        live_block_header = await blockchain_api.get_block_header(block_hash)
        if live_block_header:
            header_manager.headers[block_hash] = live_block_header
            header_manager.save()
            logger.info(f"  Live Block Header for '{block_hash}' fetched and cached.")

    if not live_block_header:
        logger.error(f"  SPV Proof: FAIL. Could not fetch or find block header for block '{block_hash}'.")
        return False

    if not utils.verify_block_hash(live_block_header):
        logger.error(f"  SPV Proof: FAIL. Live block hash verification failed for block '{block_hash}'.")
        return False

    merkle_root_from_header = live_block_header.get("merkleroot")
    if not merkle_root_from_header:
        logger.error(f"  SPV Proof: FAIL. Merkle root not found in block header.")
        return False

    # --- Verify Merkle Path ---
    merkle_proof_verified = core_defs.verify_merkle_path(
        txid,
        merkle_proof_to_use.get("index", -1),
        merkle_proof_to_use.get("nodes", []),
        merkle_root_from_header
    )

    if merkle_proof_to_use.get("index", -1) == -1:
        logger.error(f"  SPV Proof: FAIL. 'index' field missing in {proof_type_used} Merkle proof data.")
        return False
    elif not merkle_proof_verified:
        logger.error(f"  SPV Proof: FAIL. {proof_type_used} Merkle path verification failed for TXID '{txid}'.")
        return False
    
    logger.info(f"  PASS: SPV proof check.")
    return True

def _dispatch_payload_verification(
    all_data_pushes: List[bytes], 
    recomputed_original_hash: bytes, 
    checks_to_perform: dict
) -> tuple[bool, str]:
    """
    Dispatcher: Ermittelt die Protokollversion aus den Rohdaten und 
    wählt die passende Verifikations-Logik (Legacy v0.1 vs. Atomic v0.2).
    """
    protocol_version = "v0.1" # Default fallback for legacy records without AppID
    
    # Check if AppID tag is present and try to read the version string
    if len(all_data_pushes) > 1 and all_data_pushes[0] == core_defs.AUDIT_MODE_APP_ID:
        try:
            # The second element is the version string
            potential_version = all_data_pushes[1].decode('utf-8')
            if "v0." in potential_version: 
                protocol_version = potential_version
        except Exception: 
            pass
    
    logger.info(f"  Protocol Version detected: {protocol_version}")

    # Router
    if "v0.1" in protocol_version:
        return _verify_payload_loop_legacy_v01(
            all_data_pushes, 
            recomputed_original_hash, 
            checks_to_perform
        )
    elif "v0.2" in protocol_version:
        return _verify_payload_loop_atomic_v02(
            all_data_pushes, 
            recomputed_original_hash, 
            checks_to_perform
        )
    else:
        logger.error(f"  FAIL: Unknown Protocol Version: {protocol_version}")
        return False, ""

async def verify_record(
    record: dict, 
    checks_to_perform: dict, 
    header_manager: BlockHeaderManager,
    data_search_path: Optional[str] = None,
    alt_file_reference: Optional[str] = None
) -> Dict[str, Any]:
    """
    Performs a series of verifications on a single, already loaded audit record.

    This function is stateless (performs no file I/O to get the record) and
    is controlled by the 'checks_to_perform' dictionary.
     Returns the full verification summary dictionary instead of a boolean.

    Args:
        record (dict): The complete audit record dictionary to verify.
        checks_to_perform (dict): A dictionary specifying which checks to run.
                                  e.g., {'check_ec_hash': True, 'check_spv_proof': False}
        header_manager (BlockHeaderManager): An initialized BlockHeaderManager
                                             instance for SPV checking.

        data_search_path (str): Path to search the file for if not found from audit record
        alt_file_reference (str): Alt file name to apply audit to in case of mismatch

    Returns:
        bool: True if all requested checks passed, False otherwise.
    """
 
    # region --- 0. Setup and Prerequisite Check ---
    log_id = record.get("log_id", "UNKNOWN")
    result = {
        "log_id": log_id,
        "verification_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "overall_status": "success", # Assume success unless a check fails
        "checks_performed": [],
        "failures": []
    }
    
    
    logger.info(f"\n--- V2 Verification Started for Record: {log_id} ---")

    blockchain_rec = record.get("blockchain_record", {})
    payload_ok = True

    if blockchain_rec.get("status") != "confirmed":
        logger.warning(f"  Record {log_id}: Skipped verification. Status is not 'confirmed' (Status: {blockchain_rec.get('status')}).")
        result["overall_status"] = "SKIPPED"
        return result

    original_content = record.get("original_audit_content")
    txid = blockchain_rec.get("txid") 
    raw_transaction_hex = blockchain_rec.get("raw_transaction_hex")


    if not all([original_content, txid, raw_transaction_hex]):
        # actually txid and raw_transaction_hex could be recomputed
        logger.error(f"  Record {log_id}: FAIL. Missing essential data (content, txid, or raw_tx) for verification.")
        result["overall_status"] = "failed"
        result["failures"].append("Missing essential record data (content, txid, or raw_tx).")
        return result
    #endregion

    # region --- 1. Compute actual hash
    # for efficiency
    storage_mode = record.get("data_storage_mode", "embedded")
   
    assert original_content is not None
    computed_original_hash: Optional[bytes] = None

    if storage_mode == "embedded":
        computed_original_hash = sha256(original_content.encode('utf-8'))
    elif storage_mode == "by_reference":
        computed_original_hash = await _resolve_and_hash_file(
            original_path=original_content,
            data_search_path=data_search_path,
            alt_file_reference=alt_file_reference
        )
    
    if computed_original_hash is None:
        logger.error(f"  Record {log_id}: FAIL. Could not compute original hash for mode '{storage_mode}'.")
        result["overall_status"] = "failed"
        result["failures"].append(f"Hash calculation failed for mode '{storage_mode}'.")
        return result
    
    assert computed_original_hash is not None
    #endregion

    # region --- 2. Check TX Consistency ---
    if checks_to_perform.get("check_tx_consistency"):
        result["checks_performed"].append("check_tx_consistency")
        logger.info(f"  Verifying Step: Local Transaction Consistency...")
        try:
            tx_obj_from_raw = Transaction.from_hex(raw_transaction_hex)

            #region TO CHECK!
            if tx_obj_from_raw is None:
                logger.error("  FAIL: Failed to deserialize raw_transaction_hex.")
                result["failures"].append("Could not create tx obj from raw")
                return result
                
            #endregion

            computed_txid_from_raw = tx_obj_from_raw.txid()

            if computed_txid_from_raw != txid:
                logger.error(f"  FAIL: Computed TXID '{computed_txid_from_raw}' does NOT match stored TXID '{txid}'.")
                payload_ok = False
                result["failures"].append("TXID mismatch (Local integrity error).")
            else:
                logger.info(f"  PASS: TX consistency check.")
        except Exception as e:
            logger.error(f"  FAIL: Error during TX consistency check: {e}", exc_info=True)
            payload_ok = False
            result["failures"].append(f"TX consistency check failed: {e}")
    #endregion 

    # region --- 3. Check Local Hash Consistency (EC) ---
    # Only local consistency check. Check against raw tx is in payload check
    # TODO Later maybe change?
    if checks_to_perform.get("check_ec_hash"):
        result["checks_performed"].append("check_ec_hash")
        logger.info(f"  Verifying Step: Local Hash Consistency (EC)...")
        
        ec_hash_pushed_hex = blockchain_rec.get("data_hash_pushed_to_op_return")
        
        if not ec_hash_pushed_hex:
             logger.info(f"  SKIP: Record does not contain an EC hash ('data_hash_pushed_to_op_return').")
        else:
            if computed_original_hash != bytes.fromhex(ec_hash_pushed_hex):
                logger.error(f"  FAIL: EC Hash Mismatch.")
                payload_ok = False
                result["failures"].append("EC Hash Mismatch (Local file integrity broken).")
            else:
                logger.info(f"  PASS: Local EC hash consistency check.")
    #endregion

    # region --- 4. Check Local Hash Consistency (X.509) ---
    # ONLY Local integrity check
    # TODO later maybe query raw tx?
    if checks_to_perform.get("check_x509_hash"):
        result["checks_performed"].append("check_x509_hash")
        logger.info(f"  Verifying Step: Local Hash Consistency (X.509)...")
        
        x509_hash_pushed_hex = blockchain_rec.get("x509_hash_pushed")
        
        if not x509_hash_pushed_hex:
             logger.info(f"  SKIP: Record does not contain an X.509 hash ('x509_hash_pushed').")
            
        else:
            if computed_original_hash != bytes.fromhex(x509_hash_pushed_hex):
                logger.error(f"  FAIL: X.509 Hash Mismatch (Local file vs. Raw TX).")
                payload_ok = False
                result["failures"].append("X.509 Hash Mismatch (Local file integrity broken).")
            else:
                logger.info(f"  PASS: Local X.509 hash consistency check.")
    #endregion

    # region --- 5. Check Payload Integrity (Signatures) ---
    # We combine these checks as they both require parsing the raw transaction
    run_payload_check = checks_to_perform.get("check_ec_signature") or \
                        checks_to_perform.get("check_x509_signature")
    
    if run_payload_check:
        all_data_pushes = extract_op_return_payload(raw_transaction_hex)
        if not all_data_pushes:
            logger.error("  FAIL: No OP_RETURN data found in the transaction.")
            payload_ok = False
            result["failures"].append("No OP_RETURN data found.")
        else:
         
            payload_ok_check, _ = _dispatch_payload_verification(
                    all_data_pushes, 
                    computed_original_hash, 
                    checks_to_perform
                )


            if not payload_ok_check:
                logger.error(f"  FAIL: Payload integrity check (signatures) failed.")
                payload_ok = False
                result["failures"].append("Signature verification failed.")
        # PASS message is logged inside the helper
    #endregion

    # region --- 6. Check SPV (Blockchain Inclusion) ---
    if checks_to_perform.get("check_spv_proof"):
        # We pass 'header_manager' instead of creating a new one
        result["checks_performed"].append("check_spv_proof")
        spv_ok = await _verify_spv_proof(blockchain_rec, txid, header_manager, log_id)

        if not spv_ok:
            # The _verify_spv_proof_v2 function will log the specific failure
            logger.error(f"  FAIL: SPV proof check failed.")
            payload_ok = False
            result["failures"].append("SPV proof validation failed.")

        # PASS message is logged inside the helper
    #endregion

    if payload_ok:
        logger.info("--- OVERALL: PASSED ---")
        result["overall_status"] = "success"
    else:
        logger.error("--- OVERALL: FAILED ---")
        result["overall_status"] = "failed"
        
    return result





async def audit_records_runner(
    all_audit_data: List[Dict], 
    checks_to_perform: dict, 
    record_id: Optional[str] = None,
    #TODO force_audit: bool = False,
    data_search_path: Optional[str] = None,
    alt_file_reference: Optional[str] = None
) -> bool:
    """
    Manages the V0.1.3 verification process.
    
    This function loads necessary resources (like the block header cache) once,
    filters the records based on user input, and dispatches them to the
    'verify_record' worker function.

    Args:
        all_audit_data (List[Dict]): The complete list of loaded audit records.
        checks_to_perform (dict): A dictionary specifying which checks to run.
        record_id (Optional[str], optional): A specific log_id to verify. 
                                             If None, all records are verified.

    Returns:
        bool: True if all verified records passed, False if any failed.
    """
    logger.info("--- V0.1.3 Audit Runner Started ---")
    
    valid_keys = {
       "check_ec_hash", "check_ec_signature",
        "check_x509_hash", "check_x509_signature",
        "check_tx_consistency",
        "check_spv_proof"
    }
    
    unknown = set(checks_to_perform.keys()) - valid_keys
    if unknown:
        logger.error(f"Unknown check flags ignored: {sorted(unknown)}")
        return False # abort early

    non_bool = [k for k, v in checks_to_perform.items() if not isinstance(v, bool)]
    if non_bool:
        logger.error(f"Non-boolean values for flags: {sorted(non_bool)}")
        return False  # abort early

    
    if not any(checks_to_perform.values()):
        logger.warning("No verification flags enabled; proceeding with no-op payload checks.")

    # --- 1. Load resources once ---
    # Initialize the block header manager (loads cache in __init__)

    # PATHCHANGE: Use Config.BLOCK_HEADER_FILE if available to ensure we look in 'database/'
    # This aligns the verifier with the sync tool's storage location.
    if hasattr(Config, 'BLOCK_HEADERS_FILE') and Config.BLOCK_HEADERS_FILE:
        header_file = Config.BLOCK_HEADERS_FILE
    else:
        # Fallback to local file, but ideally this should align with where af_sync puts it
        header_file = f"block_headers_{Config.ACTIVE_NETWORK_NAME}.json"

    
    header_manager = BlockHeaderManager(header_file)
    logger.info(f"Block header cache initialized from {header_file}.")

    # region --- 2. Filter records to verify ---
    records_to_verify = []
    if record_id:
        logger.info(f"Filtering for single record ID: {record_id}")
        record = next((r for r in all_audit_data if r.get("log_id") == record_id), None)
        if record:
            records_to_verify.append(record)
        else:
            logger.error(f"Record with ID '{record_id}' not found in the provided data.")
            return False
    else:
        logger.info("Preparing to verify all records in the dataset.")
        records_to_verify = all_audit_data

    #endregion
    
    # region --- 3. Filter for 'confirmed' records only ---
    # The worker function (verify_record) also checks this,
    # but filtering here provides a correct count for the summary.
    confirmed_records = [
        r for r in records_to_verify 
        if r.get("blockchain_record", {}).get("status") == "confirmed"
    ]
    skipped_not_confirmed = len(records_to_verify) - len(confirmed_records)

    # --- D: Early exit for single record if not confirmed --- TODO should become an option
    if record_id and not confirmed_records:
        logger.error(f"Record {record_id} is not confirmed; cannot verify this record.")
        return False

    if not confirmed_records:
        if record_id:
             logger.warning(f"Record {record_id} is not in 'confirmed' state. Nothing to verify.")
        else:
             logger.info("No 'confirmed' records found in the dataset. Nothing to verify.")

        logger.info(f"Skipped (not confirmed): {skipped_not_confirmed}")
        # No failures occurred, so return True
        return True  # intentional: no failures occurred. May want to indicate unchecked records
    #endregion
    
    # --- 4. Iterate and verify ---
    total_to_check = len(confirmed_records)
    passed_count = 0
    failed_count = 0
    skipped_previous_success_count = 0

    logger.info(f"Found {total_to_check} 'confirmed' record(s) to verify...")
    
    for i, record in enumerate(confirmed_records):
        log_id = record.get("log_id", f"record_{i}")
        logger.info(f"--- Verifying {i+1}/{total_to_check} (ID: {log_id}) ---")
        
        try:
            # Call the 'worker' function, passing in the shared header manager
            verification_payload = await verify_record(
                    record, 
                    checks_to_perform, header_manager,
                    data_search_path, alt_file_reference)
            
            record["verification_summary"] = verification_payload

            if verification_payload.get('overall_status') == 'success':
                passed_count += 1
            elif verification_payload.get('overall_status') == 'SKIPPED_PREVIOUS_SUCCESS':
                skipped_previous_success_count += 1
            else:
                failed_count += 1

        except Exception as e:
            logger.error(f"--- UNEXPECTED ERROR during verification of {log_id}: {e} ---", exc_info=True)
            failed_count += 1

    # --- 5. Print summary ---
    logger.info(f"\n--- V0.1.3 AUDIT RUNNER SUMMARY ---")
    logger.info(f"Total Records Requested: {len(records_to_verify)}")
    logger.info(f"Skipped (not confirmed): {skipped_not_confirmed}")
    logger.info(f"Total Confirmed Records Checked: {total_to_check}")
    logger.info(f"Passed: {passed_count}")
    logger.info(f"Failed: {failed_count}")

    if skipped_previous_success_count > 0:
        logger.info(f"Skipped (already success): {skipped_previous_success_count}")
        
    overall_status = (failed_count == 0)
    logger.info(f"Overall Result: {'PASS' if overall_status else 'FAIL'}")
     
    return overall_status



async def audit_record_verifier(log_id: str) -> bool:  #deprecated? # made to wrapper, a copy is in audit_core (Nov), Legacy
    """
    Simulates an auditor's tool to verify a specific audit record's integrity and blockchain inclusion.

    This function first verifies the integrity of the raw transaction and then
    iterates through all data payloads within the OP_RETURN script to perform
    a self-contained verification for each one. Finally, it confirms the transaction's
    inclusion in the blockchain via an SPV proof.

    Note: deprecated, will be replaced by verify_record

    Args:
        log_id (str): The unique identifier of the audit record to verify.

    Returns:
        bool: True if all verification steps pass, False otherwise.
    """
    logger.info(f"\n### AUDITOR VERIFICATION FOR LOG ID: {log_id} ###")
    
    try:
        with portalocker.Lock(Config.AUDIT_LOG_FILE, "r", flags=LOCK_EX) as f:
            audit_log = core_defs.load_audit_log(f)
    except FileNotFoundError:
        logger.error(f"Audit log file '{Config.AUDIT_LOG_FILE}' not found. Cannot perform verification.")
        return False
    
    record = next((r for r in audit_log if r.get("log_id") == log_id), None)
    if not record:
        logger.error(f"Audit record with ID '{log_id}' not found in {Config.AUDIT_LOG_FILE}.")
        return False
    
    blockchain_rec = record.get("blockchain_record", {})

    # --- Step 1: Check if the record is confirmed on blockchain ---
    if blockchain_rec.get("status") != "confirmed":
        logger.warning(f"  Record '{log_id}' is not confirmed on blockchain (Status: {blockchain_rec.get('status')}). Cannot perform full on-chain verification.")
        return False
    logger.info(f"  Status Check: PASS (Confirmed)")


    # PATHCHANGE: Ensure legacy verifier uses correct header path from Config
    if hasattr(Config, 'BLOCK_HEADERS_FILE') and Config.BLOCK_HEADERS_FILE:
        header_file = Config.BLOCK_HEADERS_FILE
    else:
        header_file = f"block_headers_{Config.ACTIVE_NETWORK_NAME}.json"

    hm = BlockHeaderManager(f"block_headers_{Config.ACTIVE_NETWORK_NAME}.json")
    checks = {"check_tx_consistency": True, "check_ec_hash": True, "check_ec_signature": True, "check_spv_proof": True}
        
    # Call the new standard function name
    res = await verify_record(record, checks, hm)
    return res["overall_status"] == "success"



#region verify_ec/x509_payload, verify_payload_integrity, _verify_payload_loop_v2, *v2(w) legacy
# replaced by verify*v3, original in audit_core (November)
#endregion verify_ec/x509 legacy

# --- START: V2 Audit Functions (Refactored for efficiency and flexibility) ---
# This section implements the V2 audit logic (Step 1.1) which separates
# data loading from verification and allows for granular checks.


# --- V3 abstracting from original_content, using precomputed hash, has to be ensured at higher level

def verify_ec_payload(
    payload: List[bytes], 
    recomputed_original_hash: bytes, 
    check_hash: bool, 
    check_signature: bool
) -> bool:
    """
    V2 helper: Verifies a single ECDSA payload triplet based on requested checks.
    """
    logger.info("  --- V2 Verifying ECDSA Payload ---")
    if len(payload) != 4 or payload[0] != core_defs.AUDIT_MODE_EC:
        logger.error("  FAIL: Invalid ECDSA payload format or mode byte.")
        return False
    
    extracted_hash_bytes, extracted_signature_bytes, extracted_public_key_bytes = payload[1:]
    verification_passed = True

    # more strict validation ( by ChatGPT )
    if check_signature:
        # minimale Strukturchecks
        if not extracted_signature_bytes or not extracted_public_key_bytes:
            logger.error("  EC Signature verification: FAIL (empty sig or pubkey)")
            verification_passed = False
        if len(extracted_hash_bytes) != 32:
            logger.error(f"  EC Signature verification: FAIL (hash len={len(extracted_hash_bytes)} != 32)")
            verification_passed = False


    # --- Granular Check 1: Hash Consistency ---
    if check_hash:
        assert recomputed_original_hash is not None # Hint for linter
        # computed_original_hash = sha256(original_content.encode('utf-8'))    (from V2)
        if recomputed_original_hash != extracted_hash_bytes:
            logger.error(f"  EC Hash Mismatch: FAIL (Expected: {recomputed_original_hash.hex()}, Got: {extracted_hash_bytes.hex()})")
            verification_passed = False
        else:
            logger.info("  EC Hash comparison: PASS")
    
    # --- Granular Check 2: Signature Integrity ---
    if check_signature:
        try:
            pub_key = PublicKey(extracted_public_key_bytes)
            # We must verify against the hash *extracted* from the transaction
            if pub_key.verify(extracted_signature_bytes, extracted_hash_bytes):
                logger.info("  EC Signature verification: PASS")
            else:
                logger.error("  EC Signature verification: FAIL")
                verification_passed = False
        except Exception as e:
            logger.error(f"  Error during EC signature verification: {e}")
            verification_passed = False

    return verification_passed

def verify_x509_payload(
    payload: List[bytes], 
    recomputed_original_hash: bytes, 
    check_hash: bool, 
    check_signature: bool
) -> bool:
    """
    V2 helper: Verifies a single X.509 payload triplet based on requested checks.

    Args:
        payload (List[bytes]): The list of byte strings representing the payload (mode, hash, signature, certificate).
        original_content (str): The original content string that was hashed and signed.
        check_hash( bool): 
        check_signature ( bool)
    Returns:
        bool: True if the verification passes, False otherwise.
    """
    logger.info("  --- V2 Verifying X.509 Payload ---")
    if len(payload) != 4 or payload[0] != core_defs.AUDIT_MODE_X509:
        logger.error("  FAIL: Invalid X.509 payload format or mode byte.")
        return False

    extracted_hash_bytes, extracted_signature_bytes, extracted_certificate_bytes = payload[1:]
    verification_passed = True

    # --- Granular Check 1: Hash Consistency ---
    if check_hash:
        assert recomputed_original_hash is not None # Hint for linter
        # computed_original_hash = sha256(original_content.encode('utf-8')) from V2
        if recomputed_original_hash != extracted_hash_bytes:
            logger.error(f"  X.509 Hash Mismatch: FAIL (Expected: {recomputed_original_hash.hex()}, Got: {extracted_hash_bytes.hex()})")
            verification_passed = False
        else:
            logger.info("  X.509 Hash comparison: PASS")

    # --- Granular Check 2: Signature Integrity ---
    if check_signature:
        public_key = None
        try:
            cert = x509.load_pem_x509_certificate(extracted_certificate_bytes, default_backend())
            public_key = cert.public_key()
            if not isinstance(public_key, rsa.RSAPublicKey):
                logger.error(f"  FAIL: Invalid public key type for X.509: expected RSA, got {type(public_key).__name__}")
                verification_passed = False
        except Exception as e:
            logger.error(f"  Error loading X.509 certificate: {e}")
            verification_passed = False


        if public_key and verification_passed: # Only proceed if key was loaded successfully
            try:
                # Strict chechs (ChatGPT)
                if check_signature and verification_passed:
                    if len(extracted_hash_bytes) != 32:
                        logger.error(f"  X.509 Signature verification: FAIL (hash len={len(extracted_hash_bytes)} != 32)")
                        verification_passed = False

                rsa_public_key = cast(rsa.RSAPublicKey, public_key)
                rsa_public_key.verify(
                    extracted_signature_bytes,
                    extracted_hash_bytes, # We must verify against the hash *extracted* from the transaction
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                logger.info("  X.509 Signature verification: PASS")
            except Exception as e:
                logger.error(f"  X.509 Signature verification: FAIL - {e}")
                verification_passed = False

    return verification_passed


def _verify_payload_loop_legacy_v01( # without async!
    all_data_pushes: List[bytes], 
    recomputed_original_hash: bytes, 
    checks_to_perform: dict
) -> tuple[bool,str]:
    """
    Internal V01 helper to loop through and verify all OP_RETURN payloads
    based on the granular checks_to_perform flags.
    V01->02: calling with precomputed hash computed from the original instead of original content
    Attention, will be used for older AnchorForge Data
    """
    logger.info(f"  Verifying Step 3: Payload Data Integrity (Signatures)...")
    current_index = 0
    found_app_id = "" 
    
    # We only fail if a requested check fails.
    # If no signature checks are requested, this loop will just skip them.
    while current_index < len(all_data_pushes):
        mode_byte = all_data_pushes[current_index]
        
        if mode_byte == core_defs.AUDIT_MODE_APP_ID:
            if len(all_data_pushes) < current_index + 2: 
                logger.error("   FAIL: APP-ID present but missing value push.")
                return (False, found_app_id) # Malformed payload
            app_id_bytes = all_data_pushes[current_index + 1]
            # TODO optionally validate for b"anchorforge-v1"
            
            current_index += 2
            continue

        elif mode_byte == core_defs.AUDIT_MODE_NOTE:
            if len(all_data_pushes) < current_index + 2: return (False, found_app_id) # Malformed payload
            current_index += 2
            continue
        
        elif mode_byte == core_defs.AUDIT_MODE_EC:
            if len(all_data_pushes) < current_index + 4: return (False, found_app_id) # Malformed payload
            payload_triplet = all_data_pushes[current_index : current_index + 4]
            # Call V2 helper with specific checks
            if not verify_ec_payload(
                payload_triplet, 
                recomputed_original_hash, 
                check_hash=checks_to_perform.get("check_ec_hash", False), 
                check_signature=checks_to_perform.get("check_ec_signature", False)
            ):
                return (False, found_app_id) # A requested check failed
            current_index += 4
        
        elif mode_byte == core_defs.AUDIT_MODE_X509:
            if len(all_data_pushes) < current_index + 4: return (False, found_app_id) # Malformed payload
            payload_triplet = all_data_pushes[current_index : current_index + 4]
            # Call V2 helper with specific checks
            if not verify_x509_payload(
                payload_triplet, 
                recomputed_original_hash, 
                check_hash=checks_to_perform.get("check_x509_hash", False), 
                check_signature=checks_to_perform.get("check_x509_signature", False)
            ):
                return (False, found_app_id) # A requested check failed
            current_index += 4
        
        else:
            logger.error(f"  FAIL: Unknown mode byte found: {mode_byte}.")
            return (False, found_app_id) # Unknown payload type
    
    logger.info(f"  PASS: Payload integrity check.")
    return (True, found_app_id)

def _verify_payload_loop_atomic_v02(
    all_data_pushes: List[bytes], 
    recomputed_original_hash: bytes, 
    checks_to_perform: dict
) -> tuple[bool, str]:
    """
    V2 Atomic Loop: Processes a flexible list of tags (TLV).
    Supports multiple signatures, notes, and certificates in a single payload.
    Includes validation that requested checks were actually possible.
    """
    logger.info("  --- V2 (Atomic) Payload Verification ---")
    
    current_hash = None
    current_pubkey_bytes = None 
    current_x509_cert_obj = None
    
    # Tracking flags to detect missing data for requested checks
    has_hash_tag = False
    has_ec_sig_tag = False
    has_pubkey_tag = False
    has_cert_tag = False

    has_x509_tag = False
    has_x509_sig_tag = False
    
    verification_passed = True
    found_app_id = "" 

    idx = 2 
    
    while idx < len(all_data_pushes):
        # We always expect pairs: [TAG] [VALUE]
        if idx + 1 >= len(all_data_pushes):
            logger.error(f"  FAIL: Tag at index {idx} has no corresponding Value.")
            return False, found_app_id
            
        tag_chunk = all_data_pushes[idx]
        value_chunk = all_data_pushes[idx+1]
        
        # --- TAG: HASH ---
        if tag_chunk == core_defs.AUDIT_TAG_HASH:
            # Format: [Algo-Byte (1) + Hash-Bytes (n)]
            has_hash_tag = True
            if len(value_chunk) < 2:
                logger.error("  FAIL: Hash value too short.")
                verification_passed = False
            else:
                algo_byte = value_chunk[0]
                stored_hash = value_chunk[1:]
                
                # Info-Log for Algorithm (interesting for PoC)
                algo_name = "UNKNOWN"

                current_hash = stored_hash  # Set hash for subsequent signatures
                
                algo_name = "SHA256" if algo_byte == core_defs.HASH_ALGO_SHA256 else "UNKNOWN"
                logger.info(f"  [TAG_HASH] Algo: {algo_name}, Hash: {stored_hash.hex()[:10]}...")

                # Verification (only if flag is set)
                if checks_to_perform.get("check_ec_hash") or checks_to_perform.get("check_x509_hash"):
                    if stored_hash == recomputed_original_hash:
                        logger.info("    -> Hash Match: PASS")
                        
                    else:
                        logger.error(f"    -> Hash Mismatch! Expected: {recomputed_original_hash.hex()[:10]}...")
                        verification_passed = False
        
        # --- TAG: PUBLIC KEY ---
        elif tag_chunk == core_defs.AUDIT_TAG_PUBKEY:
            # Format: [Type-Byte (1) + Key-Bytes (n)]
            has_pubkey_tag = True
            if len(value_chunk) < 2:
                logger.error("  FAIL: PubKey value too short.")
                verification_passed = False
            else:
                # byte 0 is type (compressed/uncompressed), we store the key bytes
                current_pubkey_bytes = value_chunk[1:] 
                logger.info(f"  [TAG_PUBKEY] Key loaded ({len(current_pubkey_bytes)} bytes)")

        # --- TAG: EC SIGNATURE ---
        elif tag_chunk == core_defs.AUDIT_TAG_SIG_EC:
            # Format: [Format-Byte (1) + Sig-Bytes (n)]
            has_ec_sig_tag = True
            if len(value_chunk) < 2:
                logger.error("  FAIL: Sig value too short.")
                verification_passed = False
            else:
                sig_fmt = value_chunk[0]
                sig_bytes = value_chunk[1:]

                fmt_name = "UNKNOWN"
                if sig_fmt == core_defs.SIG_FMT_RAW: fmt_name = "RAW"
                elif sig_fmt == core_defs.SIG_FMT_DER: fmt_name = "DER"
                elif sig_fmt == core_defs.SIG_FMT_BSM: fmt_name = "BSM" # (Bitcoin Signed Message)
                    

                logger.info(f"  [TAG_SIG_EC] Format: {fmt_name}")

                if checks_to_perform.get("check_ec_signature"):
                    if current_hash is None:
                        logger.error("    -> FAIL: Signature found, but no Hash defined previously.")
                        verification_passed = False
                    elif current_pubkey_bytes is None:
                         logger.error("    -> FAIL: Signature found, but no PubKey defined previously.")
                         # TODO: Could implement Compact-Sig Recovery here later 
                         verification_passed = False
                    else:
                        try:
                            # Using bsv.PublicKey for verification
                            # Note: The library expects specific formats (DER/RAW).
                            # We assume the publisher sends compatible bytes for now.
                            pub_key_obj = PublicKey(current_pubkey_bytes)

                            if pub_key_obj.verify(sig_bytes, current_hash):
                                logger.info("    -> Signature Check: PASS")
                            else:
                                logger.error("    -> Signature Check: FAIL")
                                verification_passed = False
                        except Exception as e:
                            logger.error(f"    -> Sig Check Exception: {e}")
                            verification_passed = False

        # --- TAG: NOTE ---
        elif tag_chunk == core_defs.AUDIT_TAG_NOTE:
            try:
                note_str = value_chunk.decode('utf-8')
                logger.info(f"  [TAG_NOTE] '{note_str}'")
            except:
                logger.warning(f"  [TAG_NOTE] Could not decode note (Hex: {value_chunk.hex()})")

        # --- TAG: CERTIFICATE (X.509) ---
        elif tag_chunk == core_defs.AUDIT_TAG_CERT:
            has_cert_tag = True
            if len(value_chunk) < 2:
                logger.warning("  [TAG_CERT] Empty cert value.")
            else:
                cert_pem_bytes = value_chunk[1:]
                logger.info(f"  [TAG_CERT] X.509 Certificate found ({len(value_chunk)-1} bytes).")
                try:
                    # Parse Certificate
                    current_x509_cert_obj = x509.load_pem_x509_certificate(cert_pem_bytes, default_backend())
                    
                    # Optional: Log Issuer/Subject
                    subject = current_x509_cert_obj.subject.rfc4514_string()
                    logger.info(f"    -> Subject: {subject}")
                except Exception as e:
                    logger.error(f"    -> FAIL: Could not parse X.509 certificate: {e}")
        
        # --- TAG: X.509 SIGNATURE ---
        elif tag_chunk == core_defs.AUDIT_TAG_SIG_X509:
            has_x509_sig_tag = True
            if len(value_chunk) < 2:
                logger.error("  FAIL: X.509 Sig value too short.")
                verification_passed = False
            else:
                # byte 0 = algo (0x01 = RSA PKCS1v15)
                # sig_algo_byte = value_chunk[0] # unused for now, assumed RSA
                sig_bytes = value_chunk[1:]
                logger.info(f"  [TAG_SIG_X509] Signature found ({len(sig_bytes)} bytes).")
                
                if checks_to_perform.get("check_x509_signature"):
                    if current_hash is None:
                        logger.error("    -> FAIL: Sig found but no Hash defined previously.")
                        verification_passed = False
                    elif current_x509_cert_obj is None:
                        logger.error("    -> FAIL: Sig found but no Certificate loaded yet.")
                        verification_passed = False
                    else:
                        try:
                            # Get Public Key from Cert
                            pub_key = current_x509_cert_obj.public_key()
                            
                            # Type Guard for Pylance/Runtime
                            if isinstance(pub_key, rsa.RSAPublicKey):
                                pub_key.verify(
                                    sig_bytes,
                                    current_hash,
                                    padding.PKCS1v15(),
                                    hashes.SHA256()
                                )
                                logger.info("    -> X.509 Signature Check: PASS")
                            else:
                                logger.warning(f"    -> SKIPPED: Certificate key type {type(pub_key)} is not RSA.")
                                # Optional: verification_passed = False
                                
                        except Exception as e:
                            logger.error(f"    -> X.509 Signature Check: FAIL ({e})")
                            verification_passed = False


        # --- TAG: DATA (On-Chain Content) ---
        elif tag_chunk == core_defs.AUDIT_TAG_DATA:
            # Format: [Format-Byte (1) + Data-Bytes (n)]
            if len(value_chunk) < 1:
                logger.warning("  [TAG_DATA] Empty data value.")
            else:
                fmt_byte = value_chunk[0]
                data_content = value_chunk[1:]
                
                # Check format (0x00=UTF8, 0x01=RAW)
                is_utf8 = (fmt_byte == core_defs.DATA_FMT_UTF8)
                
                # Try to decode for display if UTF8 or looks like text
                display_str = f"<BINARY DATA: {len(data_content)} bytes>"
                if is_utf8:
                    try:
                        display_str = f"'{data_content.decode('utf-8')}'"
                    except: pass
                
                logger.info(f"  [TAG_DATA] Format: {hex(fmt_byte)}, Content: {display_str}")

        # --- TAG: REFERENCE (File Reference) ---
        elif tag_chunk == core_defs.AUDIT_TAG_REFERENCE:
            # Format: [Type-Byte (1) + Path-String (n)]
            if len(value_chunk) < 1:
                logger.warning("  [TAG_REFERENCE] Empty reference value.")
            else:
                ref_type = value_chunk[0]
                ref_path_bytes = value_chunk[1:]
                
                type_str = "UNKNOWN"
                if ref_type == core_defs.REF_TYPE_PATH: type_str = "FULL PATH"
                elif ref_type == core_defs.REF_TYPE_FILENAME: type_str = "FILENAME"
                
                try:
                    ref_path = ref_path_bytes.decode('utf-8')
                    logger.info(f"  [TAG_REFERENCE] Type: {type_str}, Path: '{ref_path}'")
                except:
                    logger.warning(f"  [TAG_REFERENCE] Type: {type_str}, Path: <Undecodable>")

        # --- UNKNOWN TAG ---
        else:
            logger.warning(f"  [UNKNOWN TAG] {tag_chunk.hex()} (Length: {len(value_chunk)})")
            # We do not abort, but ignore it (Forward Compatibility)

        idx += 2 

    # --- FINAL CONSISTENCY CHECK ---
    # Check whether we ignored checks due to missing data
    
    # 0. BASIC INTEGRITY: Hash has to be there always
    if not has_hash_tag:
        logger.error("  [FAIL] Critical: No Data Hash found in payload.")
        verification_passed = False

    # 1. EC Signature Check requested?
    if checks_to_perform.get("check_ec_signature"):
        if not has_ec_sig_tag:
            logger.warning("  [WARNING] 'check_ec_signature' requested, but NO EC Signature found.")
            # verification_passed = False # Optionally, depending on strategy
        elif not has_pubkey_tag:
            logger.warning("  [WARNING] EC Signature found, but NO Public Key found. Verification impossible.")

    # 2. X.509 Check requested?
    if checks_to_perform.get("check_x509_signature") or checks_to_perform.get("check_x509_hash"):
        # Check Cert presence
        if not has_cert_tag:
            logger.warning("  [WARNING] X.509 check requested, but NO Certificate found.")
        
        # Check Sig presence (releveant only, when we want to check signatures)
        if checks_to_perform.get("check_x509_signature") and not has_x509_sig_tag:
             logger.warning("  [WARNING] 'check_x509_signature' requested, but NO X.509 Signature found.")
    return verification_passed, found_app_id

def OLD_verify_payload_loop_atomic_v02_obsolete_with_260125(
    all_data_pushes: List[bytes], 
    recomputed_original_hash: bytes, 
    checks_to_perform: dict
) -> tuple[bool, str]:
    """
    V2 Atomic Loop: Processes a flexible list of tags (TLV).
    Supports multiple signatures, notes, and certificates in a single payload.
    """
    logger.info("  --- V2 (Atomic) Payload Verification ---")
    
    current_hash = None
    # Store the Public Key if it appears before the signature (or applies globally)
    current_pubkey_bytes = None 
    
    verification_passed = True
    found_app_id = "" # Can be used to return specific IDs if needed

    # Index starts at 2 (0=AppID, 1=VersionString are already checked by the dispatcher)
    idx = 2 
    
    while idx < len(all_data_pushes):
        # We always expect pairs: [TAG] [VALUE]
        if idx + 1 >= len(all_data_pushes):
            logger.error(f"  FAIL: Tag at index {idx} has no corresponding Value.")
            return False, found_app_id
            
        tag_chunk = all_data_pushes[idx]
        value_chunk = all_data_pushes[idx+1]
        
        # --- TAG: HASH ---
        if tag_chunk == core_defs.AUDIT_TAG_HASH:
            # Format: [Algo-Byte (1) + Hash-Bytes (n)]
            if len(value_chunk) < 2:
                logger.error("  FAIL: Hash value too short (missing Algo-Byte).")
                verification_passed = False
            else:
                algo_byte = value_chunk[0]
                stored_hash = value_chunk[1:]
                
                # Info-Log for Algorithm (interesting for PoC)
                algo_name = "UNKNOWN"
                if algo_byte == core_defs.HASH_ALGO_SHA256: algo_name = "SHA256"
                logger.info(f"  [TAG_HASH] Algo: {algo_name}, Hash: {stored_hash.hex()[:10]}...")

                # Verification (only if flag is set)
                if checks_to_perform.get("check_ec_hash") or checks_to_perform.get("check_x509_hash"):
                    if stored_hash == recomputed_original_hash:
                        logger.info("    -> Hash Match: PASS")
                        current_hash = stored_hash # Set hash for subsequent signatures
                    else:
                        logger.error(f"    -> Hash Mismatch! Expected: {recomputed_original_hash.hex()[:10]}...")
                        verification_passed = False
        
        # --- TAG: PUBLIC KEY ---
        elif tag_chunk == core_defs.AUDIT_TAG_PUBKEY:
            # Format: [Type-Byte (1) + Key-Bytes (n)]
            if len(value_chunk) < 2:
                logger.error("  FAIL: PubKey value too short.")
                verification_passed = False
            else:
                # byte 0 is type (compressed/uncompressed), we store the key bytes
                current_pubkey_bytes = value_chunk[1:] 
                logger.info(f"  [TAG_PUBKEY] Key loaded ({len(current_pubkey_bytes)} bytes)")

        # --- TAG: EC SIGNATURE ---
        elif tag_chunk == core_defs.AUDIT_TAG_SIG_EC:
            # Format: [Format-Byte (1) + Sig-Bytes (n)]
            if len(value_chunk) < 2:
                logger.error("  FAIL: Sig value too short.")
                verification_passed = False
            else:
                sig_fmt = value_chunk[0]
                sig_bytes = value_chunk[1:]
                
                fmt_name = "UNKNOWN"
                if sig_fmt == core_defs.SIG_FMT_RAW: fmt_name = "RAW"
                elif sig_fmt == core_defs.SIG_FMT_DER: fmt_name = "DER"
                elif sig_fmt == core_defs.SIG_FMT_BSM: fmt_name = "BSM" # (Bitcoin Signed Message)
                
                logger.info(f"  [TAG_SIG_EC] Format: {fmt_name}")

                if checks_to_perform.get("check_ec_signature"):
                    if current_hash is None:
                        logger.error("    -> FAIL: Signature found, but no Hash defined previously.")
                        verification_passed = False
                    elif current_pubkey_bytes is None:
                         logger.error("    -> FAIL: Signature found, but no PubKey defined previously.")
                         # TODO: Could implement Compact-Sig Recovery here later
                         verification_passed = False
                    else:
                        try:
                            # Using bsv.PublicKey for verification
                            # Note: The library expects specific formats (DER/RAW).
                            # We assume the publisher sends compatible bytes for now.
                            pub_key_obj = PublicKey(current_pubkey_bytes)
                            
                            if pub_key_obj.verify(sig_bytes, current_hash):
                                logger.info("    -> Signature Check: PASS")
                            else:
                                logger.error("    -> Signature Check: FAIL")
                                verification_passed = False
                        except Exception as e:
                            logger.error(f"    -> Sig Check Exception: {e}")
                            verification_passed = False

        # --- TAG: NOTE ---
        elif tag_chunk == core_defs.AUDIT_TAG_NOTE:
            try:
                note_str = value_chunk.decode('utf-8')
                logger.info(f"  [TAG_NOTE] '{note_str}'")
            except:
                logger.warning(f"  [TAG_NOTE] Could not decode note (Hex: {value_chunk.hex()})")


        # --- TAG: DATA (On-Chain Content) ---
        elif tag_chunk == core_defs.AUDIT_TAG_DATA:
            # Format: [Format-Byte (1) + Data-Bytes (n)]
            if len(value_chunk) < 1:
                logger.warning("  [TAG_DATA] Empty data value.")
            else:
                fmt_byte = value_chunk[0]
                data_content = value_chunk[1:]
                
                # Check format (0x00=UTF8, 0x01=RAW)
                is_utf8 = (fmt_byte == core_defs.DATA_FMT_UTF8)
                
                # Try to decode for display if UTF8 or looks like text
                display_str = f"<BINARY DATA: {len(data_content)} bytes>"
                if is_utf8:
                    try:
                        display_str = f"'{data_content.decode('utf-8')}'"
                    except: pass
                
                logger.info(f"  [TAG_DATA] Format: {hex(fmt_byte)}, Content: {display_str}")

        # --- TAG: REFERENCE (File Reference) ---
        elif tag_chunk == core_defs.AUDIT_TAG_REFERENCE:
            # Format: [Type-Byte (1) + Path-String (n)]
            if len(value_chunk) < 1:
                logger.warning("  [TAG_REFERENCE] Empty reference value.")
            else:
                ref_type = value_chunk[0]
                ref_path_bytes = value_chunk[1:]
                
                type_str = "UNKNOWN"
                if ref_type == core_defs.REF_TYPE_PATH: type_str = "FULL PATH"
                elif ref_type == core_defs.REF_TYPE_FILENAME: type_str = "FILENAME"
                
                try:
                    ref_path = ref_path_bytes.decode('utf-8')
                    logger.info(f"  [TAG_REFERENCE] Type: {type_str}, Path: '{ref_path}'")
                except:
                    logger.warning(f"  [TAG_REFERENCE] Type: {type_str}, Path: <Undecodable>")

        # --- UNKNOWN TAG ---
        else:
            logger.warning(f"  [UNKNOWN TAG] {tag_chunk.hex()} (Length: {len(value_chunk)})")
            # We do not abort, but ignore it (Forward Compatibility)

        idx += 2 # Move to next Tag-Value pair

    return verification_passed, found_app_id
