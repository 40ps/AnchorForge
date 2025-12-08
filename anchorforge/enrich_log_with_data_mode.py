# enrich_log_with_data_mode.py
"""
This script performs a one-time migration on an existing audit log file.
It iterates through all records and adds the field:
"data_storage_mode": "embedded"

This is necessary to prepare older log files for the new v3 audit logic,
which differentiates between 'embedded' and 'by_reference' data.

Usage:
python enrich_log_with_data_mode.py --log-file <input_log.json> --output-file <migrated_log.json>
"""

import logging
import json
import argparse
import sys
import os
import portalocker
from portalocker import LOCK_EX
from typing import List, Dict, Any

from config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_log_file(filepath: str) -> List[Dict[str, Any]]:
    """
    Safely loads the target log file using an exclusive lock.
    """
    if not os.path.exists(filepath):
        logger.error(f"Error: Input file not found: {filepath}")
        sys.exit(1)
    
    logger.info(f"Loading input file: {filepath}")
    try:
        # Lock exclusively to prevent conflicts, even though we read
        with portalocker.Lock(filepath, "r", flags=LOCK_EX, timeout=5) as f:
            data = json.load(f)
            if not isinstance(data, list):
                logger.error(f"Error: Log file {filepath} is not in the expected format (a JSON list of records).")
                sys.exit(1)
            return data
    except json.JSONDecodeError:
        logger.error(f"Error: Failed to decode JSON from {filepath}.")
        sys.exit(1)
    except portalocker.exceptions.LockException:
        logger.error(f"Error: Could not acquire lock on {filepath}. Is it in use by another process?")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading the file: {e}")
        sys.exit(1)

def save_log_file(filepath: str, data: List[Dict[str, Any]]):
    """
    Safely saves the migrated data to the new output file using an exclusive lock.
    """
    logger.info(f"Saving migrated data to output file: {filepath}")
    try:
        # Lock exclusively to write the new file
        with portalocker.Lock(filepath, "w", flags=LOCK_EX, timeout=5) as f:
            json.dump(data, f, indent=4)
    except portalocker.exceptions.LockException:
        logger.error(f"Error: Could not acquire lock on output file {filepath}.")
        sys.exit(1)
    except IOError as e:
        logger.error(f"Error: Failed to write to output file {filepath}: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred while saving the file: {e}")
        sys.exit(1)


def main():
    """
    Main entry point for the migration script.
    """
    parser = argparse.ArgumentParser(
        description="Migration script to add 'data_storage_mode: embedded' to all records in an audit log.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '--log-file',
        required=True,
        help="Path to the *input* audit log file to migrate (e.g., audit_log_main.json)."
    )
    parser.add_argument(
        '--output-file',
        required=True,
        help="Path to the *output* file where the migrated log will be saved (e.g., audit_log_main_v2.json)."
    )
    
    args = parser.parse_args()

    # --- Safety Check ---
    if os.path.abspath(args.log_file) == os.path.abspath(args.output_file):
        logger.error("Error: Input and output file paths must be different.")
        logger.error("This script does not support in-place modification.")
        sys.exit(1)

    # --- Load ---
    log_data = load_log_file(args.log_file)
    
    if not log_data:
        logger.warning(f"Input file {args.log_file} is empty. No records to migrate.")
        # We can still write an empty list to the output file if desired
        # but for now, we'll just exit.
        print("Migration complete: 0 records processed.")
        return

    # --- Process ---
    logger.info(f"Starting migration for {len(log_data)} records...")
    processed_count = 0
    skipped_count = 0
    
    for record in log_data:
        if "data_storage_mode" in record:
            logger.warning(f"Record {record.get('log_id', 'N/A')} already has 'data_storage_mode'. Skipping.")
            skipped_count += 1
        else:
            record["data_storage_mode"] = "embedded"
            processed_count += 1
            
    logger.info(f"Migration processing complete. Added field to {processed_count} records.")
    if skipped_count > 0:
        logger.info(f"Skipped {skipped_count} records that already had the field.")

    # --- Save ---
    save_log_file(args.output_file, log_data)
    
    logger.info(f"--- Migration Successful ---")
    logger.info(f"Total records processed: {processed_count}")
    logger.info(f"Migrated log saved to: {args.output_file}")


if __name__ == "__main__":
    main()