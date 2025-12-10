# Usage: python ....py --log-file <path_to_log.json> --network <main|test>
import json
import logging
import argparse # Import argparse
import sys      # Import sys for exit
import os       # Import os for path checks
from collections import Counter
from anchorforge.config import Config
# import audit_core # Import audit_core to use load_audit_log


# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
    # Keep handlers defined elsewhere if needed, or add StreamHandler here
    # handlers=[logging.StreamHandler()]
)

# Define field names consistently
TSC_PROOF_FIELD = "merkle_proof_tsc_data"
LEGACY_PROOF_FIELD = "merkle_proof_data"

def analyze_audit_log_details(log_file_path: str, network_name: str):
    """
    Reads the audit log file, checks the format/presence of both legacy
    and TSC Merkle proofs for confirmed records, and reports the status
    of ignored records.
    """
    logging.info(f"--- Analyzing Audit Log Details in '{log_file_path}' (Network: {network_name}) ---")

    malformed_legacy_proofs = []
    malformed_tsc_proofs = []
    missing_legacy_proofs = 0
    missing_tsc_proofs = 0
    ignored_record_statuses = Counter()

    audit_log = [] # Initialize before try block
    try:
        # Use portalocker for consistency if other scripts might write concurrently
        # For a read-only analysis, simple open might suffice if run standalone.
        # Using simple open here for clarity as locking might not be strictly needed for analysis.
        with open(log_file_path, 'r', encoding='utf-8') as f:
             audit_log = json.load(f) # Use standard json.load
             # audit_log = audit_core.load_audit_log(f) # Or use your existing function if preferred
    except FileNotFoundError:
        logging.error(f"Error: Audit log file '{log_file_path}' not found.")
        return
    except json.JSONDecodeError as e:
        logging.error(f"Error: Could not decode JSON from '{log_file_path}'. {e}")
        return
    except Exception as e:
        logging.error(f"Error loading audit log '{log_file_path}': {e}")
        return

    record_count = 0
    confirmed_count = 0
    checked_legacy_count = 0
    checked_tsc_count = 0

    for record in audit_log:
        record_count += 1
        log_id = record.get("log_id", "N/A")
        blockchain_rec = record.get("blockchain_record", {})
        status = blockchain_rec.get("status", "unknown_status")

        if status == "confirmed":
            confirmed_count += 1

            # --- Check Legacy Merkle Proof ---
            checked_legacy_count += 1
            legacy_proof = blockchain_rec.get(LEGACY_PROOF_FIELD)
            if legacy_proof is None:
                logging.debug(f"Record {log_id}: Legacy Merkle proof ({LEGACY_PROOF_FIELD}) is missing.")
                missing_legacy_proofs += 1
            elif not isinstance(legacy_proof, dict):
                # Check if it's the known list[dict] issue and report specifically
                if isinstance(legacy_proof, list) and len(legacy_proof) == 1 and isinstance(legacy_proof[0], dict):
                     logging.warning(f"Record {log_id}: Legacy Merkle proof ({LEGACY_PROOF_FIELD}) has incorrect list format.")
                     malformed_legacy_proofs.append({"log_id": log_id, "issue": "Incorrect type: list[dict]"})
                else:
                     logging.warning(f"Record {log_id}: Legacy Merkle proof ({LEGACY_PROOF_FIELD}) is not a dictionary. Type: {type(legacy_proof)}")
                     malformed_legacy_proofs.append({"log_id": log_id, "issue": f"Incorrect type: {type(legacy_proof)}"})


            # --- Check TSC Merkle Proof ---
            checked_tsc_count += 1
            tsc_proof = blockchain_rec.get(TSC_PROOF_FIELD)
            if tsc_proof is None:
                logging.debug(f"Record {log_id}: TSC Merkle proof ({TSC_PROOF_FIELD}) is missing.")
                missing_tsc_proofs += 1
            elif not isinstance(tsc_proof, dict):
                 # TSC proof should likely always be a dict if present
                 logging.warning(f"Record {log_id}: TSC Merkle proof ({TSC_PROOF_FIELD}) is not a dictionary. Type: {type(tsc_proof)}")
                 malformed_tsc_proofs.append({"log_id": log_id, "issue": f"Incorrect type: {type(tsc_proof)}"})
            # Optional: Add checks for specific fields within the tsc_proof if needed

        else:
            ignored_record_statuses[status] += 1

    # --- Print Summary ---
    logging.info(f"--- Analysis Complete ---")
    logging.info(f"Total records processed: {record_count}")
    logging.info(f"Total confirmed records found: {confirmed_count}")

    # Legacy Proof Summary
    logging.info(f"\n--- Legacy Merkle Proof ({LEGACY_PROOF_FIELD}) Analysis ---")
    logging.info(f"Checked: {checked_legacy_count} confirmed records")
    logging.info(f"Missing: {missing_legacy_proofs} records")
    if malformed_legacy_proofs:
        logging.warning(f"Malformed: {len(malformed_legacy_proofs)} records")
        for malformed in malformed_legacy_proofs:
            logging.warning(f"  - ID: {malformed['log_id']}, Issue: {malformed['issue']}")
    else:
        logging.info("Malformed: 0 records")

    # TSC Proof Summary
    logging.info(f"\n--- TSC Merkle Proof ({TSC_PROOF_FIELD}) Analysis ---")
    logging.info(f"Checked: {checked_tsc_count} confirmed records")
    logging.info(f"Missing: {missing_tsc_proofs} records")
    if malformed_tsc_proofs:
        logging.warning(f"Malformed: {len(malformed_tsc_proofs)} records")
        for malformed in malformed_tsc_proofs:
            logging.warning(f"  - ID: {malformed['log_id']}, Issue: {malformed['issue']}")
    else:
        logging.info("Malformed: 0 records")

    # Ignored Records Summary
    total_ignored = sum(ignored_record_statuses.values())
    if total_ignored > 0:
        logging.info(f"\n--- Ignored Records Summary (Not checked for Merkle proof format) ---")
        logging.info(f"Total ignored records: {total_ignored}")
        for status, count in ignored_record_statuses.items():
            logging.info(f"  - Status '{status}': {count} records")
    else:
        logging.info("No records were ignored.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze audit log for Merkle proof format issues and status distribution.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # --- Add mandatory command-line arguments ---
    parser.add_argument(
        '--log-file',
        required=True,
        help="Path to the audit log file to analyze (e.g., audit_log_main.json)."
    )
    parser.add_argument(
        '--network',
        required=True,
        choices=['main', 'test'],
        help="Specify the network ('main' or 'test') corresponding to the log file."
    )

    args = parser.parse_args()

    log_file = args.log_file

    if not os.path.exists(log_file):
        print(f"Error: Specified log file does not exist: {log_file}")
        sys.exit(1)

    # Optional: Add filename vs network mismatch warnings if desired
    if 'main' in log_file.lower() and args.network == 'test':
         logging.warning(f"Potential Mismatch: Log file name suggests 'mainnet' but --network is 'test'.")
    elif 'test' in log_file.lower() and args.network == 'main':
         logging.warning(f"Potential Mismatch: Log file name suggests 'testnet' but --network is 'main'.")

    # Execute the analysis function
    analyze_audit_log_details(log_file, args.network)