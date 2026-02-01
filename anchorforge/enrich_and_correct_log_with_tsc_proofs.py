# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    enrich_and_correct_log_with_tsc_proofs.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

# enrich_and_correct_log_with_tsc_proofs.py
"""
This script iterates through the audit log and performs three tasks:
1. Corrects any 'txid' fields that contain unwanted trailing characters.
2. Corrects legacy 'merkle_proof_data' AND 'merkle_proof_tsc_data' fields
   that are incorrectly stored as a list[dict].
3. Enriches 'confirmed' records by fetching and adding the TSC Merkle proof if missing.

Usage:
python enrich_and_correct_log_with_tsc_proofs.py --log-file <path_to_log.json> --network <main|test>
"""
import asyncio
import logging
import json
import argparse
import sys
import os
from datetime import datetime, timezone
import portalocker
from portalocker import LOCK_EX

# Assuming your project structure allows these imports
from anchorforge.config import Config
# import audit_core
from anchorforge import blockchain_api # Needs the get_tsc_merkle_path function!
from anchorforge import utils
from anchorforge import core_defs

# Ensure log directory exists before initializing logging
if hasattr(Config, 'LOG_FILE') and Config.LOG_FILE:
    log_dir = os.path.dirname(Config.LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# --- Configuration ---
# Use field names directly or import from Config if defined there
TSC_PROOF_FIELD = Config.TSC_PROOF_FIELD
TSC_TIMESTAMP_FIELD = Config.TSC_TIMESTAMP_FIELD
LEGACY_PROOF_FIELD = Config.LEGACY_PROOF_FIELD
TSC_SIZE_FIELD = Config.TSC_SIZE_FIELD
LEGACY_SIZE_FIELD = Config.LEGACY_SIZE_FIELD # Added for consistency if needed
# API call delay
API_CALL_DELAY_SECONDS = 1

async def enrich_and_correct_log(log_file_path: str, network_name: str):
    """
    Loads the audit log, corrects faulty txids and proof formats,
    finds confirmed records without TSC proofs, fetches TSC proofs,
    and saves the modified log back.
    """
    logging.info(f"--- Starting Audit Log Enrichment and Correction for '{log_file_path}' (Network: {network_name}) ---")

    # --- Pre-check API function ---
    if not hasattr(blockchain_api, 'get_tsc_merkle_path'):
         logging.error("FATAL ERROR: 'get_tsc_merkle_path' missing in blockchain_api.py.")
         return

    # --- Network check ---
    if Config.ACTIVE_NETWORK_NAME != network_name:
        logging.warning(f"Warning: Configured network is {Config.ACTIVE_NETWORK_NAME}, but processing for {network_name}.")

    records_processed = 0
    records_updated_tsc = 0
    records_failed_tsc = 0
    records_corrected_txid = 0
    records_corrected_legacy_proof = 0
    records_corrected_tsc_proof = 0 # --- NEW: Counter for corrected TSC proofs ---
    needs_saving = False
    audit_log = []

    try:
        with portalocker.Lock(log_file_path, "r+", flags=LOCK_EX, timeout=10) as f_audit:
            audit_log = core_defs.load_audit_log(f_audit)
            logging.info(f"Loaded {len(audit_log)} records from the log file.")

            for i, record in enumerate(audit_log):
                records_processed += 1
                log_id = record.get("log_id", f"Record_{i}")
                blockchain_rec = record.get("blockchain_record", {})
                txid_original = blockchain_rec.get("txid")

                # --- 1. TXID Correction Logic ---
                if txid_original and isinstance(txid_original, str):
                    txid_cleaned = txid_original.strip().strip('"')
                    if txid_cleaned != txid_original:
                        logging.warning(f"  Record {log_id}: Correcting faulty TXID from '[{txid_original}]' to '[{txid_cleaned}]'.")
                        blockchain_rec["txid"] = txid_cleaned
                        records_corrected_txid += 1
                        needs_saving = True
                # --- END TXID Correction ---

                # --- 2. Legacy Merkle Proof Format Correction ---
                if LEGACY_PROOF_FIELD in blockchain_rec:
                    legacy_proof = blockchain_rec[LEGACY_PROOF_FIELD]
                    if isinstance(legacy_proof, list) and len(legacy_proof) == 1 and isinstance(legacy_proof[0], dict):
                        logging.warning(f"  Record {log_id}: Correcting legacy proof format ({LEGACY_PROOF_FIELD}) from list[dict] to dict.")
                        blockchain_rec[LEGACY_PROOF_FIELD] = legacy_proof[0]
                        records_corrected_legacy_proof += 1
                        needs_saving = True
                # --- END Legacy Proof Correction ---

                # --- NEW: 3. TSC Merkle Proof Format Correction ---
                if TSC_PROOF_FIELD in blockchain_rec:
                    tsc_proof = blockchain_rec[TSC_PROOF_FIELD]
                    # Also check TSC proof for the incorrect list format
                    if isinstance(tsc_proof, list) and len(tsc_proof) == 1 and isinstance(tsc_proof[0], dict):
                         # Check if it contains an error message, ignore if so
                         if "error" not in tsc_proof[0]:
                             logging.warning(f"  Record {log_id}: Correcting TSC proof format ({TSC_PROOF_FIELD}) from list[dict] to dict.")
                             blockchain_rec[TSC_PROOF_FIELD] = tsc_proof[0]
                             records_corrected_tsc_proof += 1
                             needs_saving = True
                # --- END TSC Proof Correction ---


                # --- 4. TSC Proof Enrichment Logic ---
                # Process only confirmed records that don't already have a VALID TSC proof field
                # (A field with an error marker counts as "present" but not valid for enrichment)
                current_tsc_proof = blockchain_rec.get(TSC_PROOF_FIELD)
                should_enrich_tsc = (
                    blockchain_rec.get("status") == "confirmed" and
                    (current_tsc_proof is None or (isinstance(current_tsc_proof, dict) and "error" in current_tsc_proof))
                )

                if should_enrich_tsc:
                    txid = blockchain_rec.get("txid") # Use potentially corrected txid

                    if not txid:
                        logging.warning(f"  Record {log_id}: Skipping TSC enrichment due to missing/invalid TXID.")
                        records_failed_tsc += 1
                        continue

                    logging.info(f"  Processing record {log_id} (TXID: {txid}): Fetching TSC proof...")

                    try:
                        tsc_proof_data = await blockchain_api.get_tsc_merkle_path(txid)
                        await asyncio.sleep(API_CALL_DELAY_SECONDS)

                        if tsc_proof_data:
                            enrichment_timestamp = datetime.now(timezone.utc).isoformat()
                            blockchain_rec[TSC_PROOF_FIELD] = tsc_proof_data
                            blockchain_rec[TSC_TIMESTAMP_FIELD] = enrichment_timestamp
                            tsc_proof_size = len(json.dumps(tsc_proof_data).encode('utf-8'))
                            blockchain_rec[TSC_SIZE_FIELD] = tsc_proof_size
                            logging.info(f"    -> Successfully added/updated TSC proof for {log_id} (Size: {tsc_proof_size} bytes).")
                            records_updated_tsc += 1
                            needs_saving = True
                        else:
                            logging.warning(f"    -> Failed to fetch TSC proof for {log_id}. API returned no data.")
                            # Add/Update error marker
                            blockchain_rec[TSC_PROOF_FIELD] = {"error": "TSC proof fetch failed", "timestamp": datetime.now(timezone.utc).isoformat()}
                            needs_saving = True
                            records_failed_tsc += 1
                    except Exception as e:
                        logging.error(f"    -> An unexpected error occurred fetching TSC proof for {log_id}: {e}")
                        # Add/Update error marker
                        blockchain_rec[TSC_PROOF_FIELD] = {"error": f"Exception during fetch: {e}", "timestamp": datetime.now(timezone.utc).isoformat()}
                        needs_saving = True
                        records_failed_tsc += 1
                # --- END TSC Proof Enrichment ---

            # --- Save the log file only if changes were made ---
            if needs_saving:
                logging.info("Saving updated audit log...")
                core_defs.save_audit_log(f_audit, audit_log)
                logging.info("Audit log saved successfully.")
            else:
                logging.info("No records needed TXID/Proof correction or TSC enrichment. Log file unchanged.")

    except portalocker.exceptions.LockException:
        logging.error(f"Could not acquire lock for '{log_file_path}'.")
    except FileNotFoundError:
        logging.error(f"Error: Audit log file '{log_file_path}' not found.")
    except json.JSONDecodeError as e:
        logging.error(f"Error: Could not decode JSON from '{log_file_path}'. {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)


    # --- Final Summary ---
    logging.info(f"--- Audit Log Enrichment and Correction Finished ---")
    logging.info(f"Total records processed: {records_processed}")
    logging.info(f"Records with TXID corrected: {records_corrected_txid}")
    logging.info(f"Records with Legacy Proof format corrected: {records_corrected_legacy_proof}")
    logging.info(f"Records with TSC Proof format corrected: {records_corrected_tsc_proof}") # --- NEW ---
    if audit_log:
        # Count confirmed records still needing a VALID TSC proof (None or contains error)
        confirmed_needing_valid_tsc = len([
            r for r in audit_log
            if r.get("blockchain_record", {}).get("status") == "confirmed" and
            (TSC_PROOF_FIELD not in r.get("blockchain_record", {}) or
             (isinstance(r.get("blockchain_record", {}).get(TSC_PROOF_FIELD), dict) and
              "error" in r.get("blockchain_record", {}).get(TSC_PROOF_FIELD)))
        ])
        logging.info(f"Confirmed records still needing valid TSC proof (after run): {confirmed_needing_valid_tsc}")
    logging.info(f"Records successfully updated with TSC proof in this run: {records_updated_tsc}")
    logging.info(f"Records where TSC proof fetch failed in this run: {records_failed_tsc}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enrich confirmed audit log records with TSC Merkle proofs, correct faulty TXIDs, and fix proof formats.", # Updated description
        formatter_class=argparse.RawTextHelpFormatter
    )
    # ... (Arguments --log-file and --network remain required) ...
    parser.add_argument( '--log-file', required=True, help="Path to the audit log file to process." )
    parser.add_argument( '--network', required=True, choices=['main', 'test'], help="Specify the network ('main' or 'test')." )

    args = parser.parse_args()
    log_file = args.log_file

    if not os.path.exists(log_file):
        print(f"Error: Specified log file does not exist: {log_file}")
        sys.exit(1)

    # ... (Network mismatch warnings and Config override logic remain the same) ...
    original_network_config = Config.ACTIVE_NETWORK_NAME
    if args.network != original_network_config:
         logging.warning(f"Temporarily setting ACTIVE_NETWORK_NAME to '{args.network}'...")
         Config.ACTIVE_NETWORK_NAME = args.network

    try:
        asyncio.run(enrich_and_correct_log(log_file, args.network))
    finally:
        if args.network != original_network_config:
            Config.ACTIVE_NETWORK_NAME = original_network_config
            logging.info(f"Restored ACTIVE_NETWORK_NAME to '{original_network_config}'.")