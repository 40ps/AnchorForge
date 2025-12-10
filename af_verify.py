# AF_py/main_audit.py
"""
V0.1.3 Audit Runner - The flexible and efficient audit tool.

This script loads the audit log file once and uses the V2/3 "manager" 
and "worker" functions in audit_core.py to perform granular, 
user-specified checks.

This separation of concerns makes it much faster than the v1 auditor
and suitable for use with different data sources (e.g., databases).

With functions in audit it now supports local files

Example usage:
# Run all checks on all confirmed records in the test log
python main_audit.py --log-file audit_log_test.json --network test

# Run only hash consistency checks on all "iss-location-001" records
python main_audit.py --log-file audit_log_test.json --network test --keyword "iss-location-001" --check-ec-hash

# Run only signature checks for a single record
python main_audit.py --log-file audit_log_test.json --network test --id <log-id> --check-ec-signature
"""

import asyncio
import logging
import json
import argparse
import sys
import os
import portalocker
from portalocker import LOCK_EX
from typing import List, Dict

# Import necessary components from your project
from anchorforge.config import Config
from anchorforge import core_defs
from anchorforge import verifier
# from block_manager import BlockHeaderManager

VIBECODEVERSION=0.6

# Configure logging for this script
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def load_audit_data(log_file_path: str) -> List[Dict]:
    """
    Securely loads the audit log file using an exclusive lock (to be safe).
    This is the only file-reading operation.
    """
    logger.info(f"Loading audit log file: {log_file_path}")
    if not os.path.exists(log_file_path):
        logger.error(f"Error: Audit log file '{log_file_path}' not found.")
        sys.exit(1)
        
    try:
        # Use an exclusive lock (LOCK_EX) to prevent collision with monitor/batch processes
        # Using "r" mode for read-only, but still locking exclusively
        with portalocker.Lock(log_file_path, "r", flags=LOCK_EX, timeout=5) as f:
            data = core_defs.load_audit_log(f) # Re-use your existing loader
            if data is None: # load_audit_log returns [] on error, but good to check
                 return []
            logger.info(f"Successfully loaded {len(data)} records.")
            return data
    except (json.JSONDecodeError, portalocker.exceptions.LockException) as e:
        logger.error(f"Error loading or locking log file '{log_file_path}': {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred loading the log file: {e}", exc_info=True)
        sys.exit(1)

def save_audit_results(output_file_path: str, data: List[Dict]):
    """
    Securely saves the audit results using an exclusive lock.
    """
    logger.info(f"Saving audit results to: {output_file_path}")
    try:
        # Use "w" mode to create/overwrite the file
        with portalocker.Lock(output_file_path, "w", flags=LOCK_EX, timeout=5) as f:
            json.dump(data, f, indent=4)
        logger.info(f"Successfully saved {len(data)} records to {output_file_path}.")
    except (portalocker.exceptions.LockException, IOError) as e:
        logger.error(f"Error saving or locking results file '{output_file_path}': {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred saving the results: {e}", exc_info=True)


async def main_audit():
    """
    Main asynchronous function to parse arguments and run the audit.
    """
    parser = argparse.ArgumentParser(
        description="V2 Audit Runner for AnchorForge Logs.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    

    # --- Data Source Arguments (Your Request) ---
    parser.add_argument(
        '--log-file',
        required=True,
        help="Path to the audit log file to verify (e.g., audit_log_test.json)."
    )

    # --- Data Path Arguments ---
    data_path_flags = parser.add_argument_group('Data Resolution Flags')
    data_path_flags.add_argument(
        '--data-dir',
        type=str,
        default=None,
        help="Optional base directory to search for 'by_reference' files if the original path is missing."
    )

    data_path_flags.add_argument(
        '--alt-file',
        type=str,
        default=None,
        help="Specify an alternative filename or full path to use instead of the original file path stored in the log."
    )


    parser.add_argument(
        '-o', '--output-file',
        required=True, # default=None,
        help="Path to write the audit results. "
             "If not set, the --log-file is updated in-place."
    )


    parser.add_argument(
        '--network',
        choices=['main', 'test'],
        default=None, # Will default to Config.ACTIVE_NETWORK_NAME
        help=f"Specify the network ('main' or 'test'). Overrides the config if set. "
             f"Ensures correct block headers are used. (Default: {Config.ACTIVE_NETWORK_NAME})"
    )

    # parser.add_argument(
    #     '-f', '--force',
    #     action='store_true',
    #     help="Force a complete re-audit of all transactions, ignoring previous results."
    # )
    # args = parser.parse_args()
    # force_audit = args.force

    # if force_audit:
    #     logging.warning("--- FORCE RE-AUDIT ENABLED ---")
    #     logging.warning("All transactions will be re-verified, ignoring previous 'success' status.")

    # --- Filtering Arguments ---
    filter_group = parser.add_argument_group('Filtering Flags')
    filter_group.add_argument(
        '--id',
        default=None,
        help="Optional: A specific log_id to verify. Overrides --keyword."
    )
    filter_group.add_argument(
        '-k', '--keyword',
        default=None,
        help="Optional: Filter records to verify only those matching this keyword."
    )

    # --- Granular Check Flags ---
    check_flags = parser.add_argument_group('Granular Check Flags', 
                                            'Specify which verifications to run. If none are specified, all checks are run.')
    
    check_flags.add_argument('--check-tx-consistency', action='store_true', help="Verify: Stored TXID matches computed TXID.")
    check_flags.add_argument('--check-spv-proof', action='store_true', help="Verify: SPV (Merkle Proof) against the block header.")
    check_flags.add_argument('--check-ec-hash', action='store_true', help="Verify: ECDSA hash matches original content.")
    check_flags.add_argument('--check-ec-signature', action='store_true', help="Verify: ECDSA signature is valid.")
    check_flags.add_argument('--check-x509-hash', action='store_true', help="Verify: X.509 hash matches original content.")
    check_flags.add_argument('--check-x509-signature', action='store_true', help="Verify: X.509 signature is valid.")

    args = parser.parse_args()

    # --- 1. Set up Network Configuration ---
    original_network_config = Config.ACTIVE_NETWORK_NAME
    network_to_use = args.network or original_network_config
    
    # Temporarily override the global config if the user specified a network.
    # This is crucial so that the 'header_manager' and 'blockchain_api' calls
    # use the correct network context (e.g., loading 'block_headers_test.json').
    if args.network and args.network != original_network_config:
         logger.warning(f"Temporarily setting ACTIVE_NETWORK_NAME to '{args.network}' for this run, overriding config value '{original_network_config}'.")
         Config.ACTIVE_NETWORK_NAME = args.network
    
    # Safety check for filename/network mismatch
    if 'main' in args.log_file.lower() and network_to_use == 'test':
         logger.warning(f"Potential Mismatch: Log file name suggests 'mainnet' but active network is 'test'.")
    elif 'test' in args.log_file.lower() and network_to_use == 'main':
         logger.warning(f"Potential Mismatch: Log file name suggests 'testnet' but active network is 'main'.")


    # --- 2. Build the checks_to_perform dictionary ---
    checks_to_perform = {
        "check_tx_consistency": args.check_tx_consistency,
        "check_ec_hash": args.check_ec_hash,
        "check_ec_signature": args.check_ec_signature,
        "check_x509_hash": args.check_x509_hash,
        "check_x509_signature": args.check_x509_signature,
        "check_spv_proof": args.check_spv_proof
    }

    # Default behavior: If no specific check is selected, run all checks.
    run_all_checks = not any(checks_to_perform.values())
    if run_all_checks:
        logger.info("No specific checks selected. Running ALL verifications by default.")
        for key in checks_to_perform:
            checks_to_perform[key] = True

    # --- 3. Load Data (Once) ---
    all_audit_data = load_audit_data(args.log_file)
    if not all_audit_data:
        logger.warning("Log file is empty. Nothing to verify.")
        # Restore config if we changed it
        if Config.ACTIVE_NETWORK_NAME != original_network_config:
             Config.ACTIVE_NETWORK_NAME = original_network_config
        return

    # --- 4. Filter Data by Keyword (if --id is not used) ---
    data_to_run = all_audit_data
    if args.id:
        logger.info(f"Filtering by --id {args.id}. --keyword flag will be ignored.")
        # The 'audit_records_runner' will handle the --id filtering
        pass
    elif args.keyword:
        logger.info(f"Filtering records by keyword: '{args.keyword}'")
        data_to_run = [
            r for r in all_audit_data 
            if r.get("keyword") == args.keyword
        ]
        if not data_to_run:
            logger.warning(f"No records found with keyword '{args.keyword}'. Nothing to verify.")
            if Config.ACTIVE_NETWORK_NAME != original_network_config:
                 Config.ACTIVE_NETWORK_NAME = original_network_config
            return
        logger.info(f"Found {len(data_to_run)} records matching keyword.")
    # --- END Filter ---

    # --- 5. Call the V2 Runner Function ---
    try:
        overall_success = await verifier.audit_records_runner(
            all_audit_data=data_to_run, # Pass the (potentially filtered) data
            checks_to_perform=checks_to_perform,
            record_id=args.id,  # Pass the ID, runner will prioritize this
            #TODO force_audit
            data_search_path = args.data_dir,
            alt_file_reference = args.alt_file
        )
        # Entweder in die --output-file, falls angegeben,
        # oder zurück in die --log-file (in-place update).
        output_path = args.output_file if args.output_file else args.log_file

        if args.output_file:
            logger.info(f"Audit run complete. Writing results to NEW file: {output_path}")
            # WICHTIG: Wir speichern 'all_audit_data', nicht nur 'data_to_run',
            # falls wir gefiltert haben, damit die Originaldatei nicht schrumpft.
            save_audit_results(output_path, all_audit_data)
        else: # for now, output is required argument
            logger.info(f"Audit run complete. Updating results IN-PLACE: {output_path}")
            save_audit_results(output_path, all_audit_data)
        # ---  ---
    finally:
        # --- 6. Restore Config ---
        # Ensure the config is always restored, even if the runner fails
        if Config.ACTIVE_NETWORK_NAME != original_network_config:
            Config.ACTIVE_NETWORK_NAME = original_network_config
            logger.info(f"Restored ACTIVE_NETWORK_NAME to '{original_network_config}'.")

    if not overall_success:
        logger.error("--- V0.1.3 AUDIT RUN FAILED ---")
        sys.exit(1) # Exit with an error code if any check failed
    else:
        logger.info("--- V0.1.3 AUDIT RUN PASSED ---")

if __name__ == "__main__":
    try:
        asyncio.run(main_audit())
    except KeyboardInterrupt:
        logger.info("\n--- V0.1.3 Audit interrupted by user. ---")