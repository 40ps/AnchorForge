# main_audit.py
'''
This program serves as the entry point for a blockchain auditor.
Its sole responsibility is to verify the integrity and blockchain inclusion
of all confirmed audit records found in the local audit log.

For a successful audit, the block headers must be synchronized beforehand.
This is typically done by running the main_sync_headers.py script.
'''

import asyncio
import logging

from config import Config
import audit_core
from block_manager import BlockHeaderManager

# Configure logging for this specific program
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

async def main_auditor():
    """
    Main entry point for the audit verification process.
    """
    logging.info("\n--- Starting the Auditor Application ---")

    # Check if block headers are available. A simple check is to see if the file exists and has content.
    header_manager = BlockHeaderManager(Config.BLOCK_HEADERS_FILE)
    if not header_manager.headers:
        logging.warning("Local block header cache is empty or not found. Cannot perform full off-chain audit.")
        logging.warning("Please run main_sync_headers.py first to prepare the auditor's environment.")
        return

    await audit_core.audit_all_records()
    logging.info("\n--- Auditor Application finished ---")

if __name__ == "__main__":
    asyncio.run(main_auditor())
