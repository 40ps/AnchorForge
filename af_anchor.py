# af_anchor.py
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


from bsv import PrivateKey
from bsv.hash import sha256


from anchorforge.config import Config
from anchorforge import utils
from anchorforge import manager

import anchorforge

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

print(f"AnchorForge {anchorforge.__version__} (network={Config.ACTIVE_NETWORK_NAME})")

logger = logging.getLogger(__name__)

VIBECODEVERSION=0.5 # Version updated

#AUDIT_RECORD_FORMAT_STRING = "TX, OP_RETURN format: [mode:byte, [( (hash:bytes, signature:bytes, [pubkey:bytes|certificate:bytes])|(note:bytes) ]+"

Config.validate_wallet_config()

async def main():
    """
    (Version 0.3)
    Main entry point. Parses arguments and passes them to the worker function.
    Now supports mutually exclusive --data and --file arguments.
    """
    Config.validate_wallet_config()

    
    parser = argparse.ArgumentParser(
        description="AnchorForge v0.1: Log a single audit event.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
 
    data_group = parser.add_mutually_exclusive_group(required=True)
    data_group.add_argument('--data',  type=str,    help="The raw string data to be embedded and anchored (mode: embedded)."    )
    data_group.add_argument( '--file', type=str,  help="The file path to be hashed and anchored (mode: by_reference)."    )
    

    parser.add_argument(  '--record-note', type=str, default=None, help="A note for the audit log record (e.g., '@./path/to/note.txt' or 'Literal note').")
    parser.add_argument(  '--transaction-note',    type=str,        default=None,        help="A note for the blockchain transaction (e.g., '@./path/to/note.txt' or 'Literal note')."  )
    parser.add_argument(  '--keyword',  type=str, default="general-event", help="A keyword to categorize this event (e.g., 'system-startup')." )
    parser.add_argument(  '--dry-run',  action='store_true',   help="Simulate the transaction without making changes to local stores."    )
    parser.add_argument(  '--no-broadcast', action='store_true', help="Create the transaction and update stores, but do not broadcast to the network." )
    parser.add_argument(  '--mainnet', action='store_true', help="Force use of mainnet. Must be explicitly set."    )

    args = parser.parse_args()

    # 1. Safety check for mainnet
    if Config.ACTIVE_NETWORK_NAME == "main" and not args.mainnet:
        logging.error("ERROR: Network is set to 'main' in .env, but --mainnet flag was not provided.")
        logging.error("This is a safety feature. Add --mainnet to your command if you are sure.")
        return
    elif Config.ACTIVE_NETWORK_NAME == "test" and args.mainnet:
        logging.warning("Warning: --mainnet flag is set, but .env network is 'test'.")
        logging.error("This is a safety feature. Add --mainnet to your command if you are sure.")
        return

    # Dependencies
    utils.ensure_json_file_exists(Config.AUDIT_LOG_FILE)
    # intentionally removed: utils.ensure_json_file_exists(Config.TX_STORE_FILE)

    mode = "embedded" if args.data else "by_reference"
    logging.info(f"Received data (mode: {mode})")
    
    logging.info(f"Received audit record note: {utils.get_content_from_source(args.record_note)}")
    logging.info(f"Received audit tx note: {utils.get_content_from_source(args.transaction_note)}")
    # --- END: New Linter-Proof Logic ---

    # Ensure log files exist before locking with "r+"
    utils.ensure_json_file_exists(Config.AUDIT_LOG_FILE)
    # Removed: utils.ensure_json_file_exists(Config.TX_STORE_FILE)
    # utils.ensure_json_file_exists(Config.X509_KEYPAIR_STORE_FILE, initial_content={})

    await manager.log_audit_event(
            data_source=args.data,
            file_source=args.file,
            data_storage_mode=mode,
            record_note=utils.get_content_from_source(args.record_note),
            tx_note=utils.get_content_from_source(args.transaction_note),
            keyword=args.keyword,
            dry_run=args.dry_run,
            no_broadcast=args.no_broadcast
        )

if __name__ == "__main__":
    asyncio.run(main())
