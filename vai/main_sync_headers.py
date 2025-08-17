# main_sync_headers.py
'''
This program is dedicated to synchronizing blockchain block headers.
It is intended to be run separately from the audit process to ensure
the local cache is up-to-date for later SPV verification tasks.
'''

import asyncio
import logging

from config import Config
import blockchain_api
import blockchain_service
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

async def main_sync_headers():
    """
    Main entry point for the block header synchronization process.
    It synchronizes a configurable number of recent block headers
    to a local cache for later use in SPV proofs.
    """
    logging.info("\n--- Starting Block Header Synchronization ---")

    dynamic_header_file_path = f"block_headers_{Config.ACTIVE_NETWORK_NAME}.json"
    header_manager = BlockHeaderManager(dynamic_header_file_path)
    try:
        chain_info = await blockchain_api.get_chain_info_woc()
        if chain_info and chain_info.get("blocks") is not None:
            current_latest_chain_height = chain_info["blocks"]

            # Sync the last x blocks as a configurable default
            sync_start_height = max(0, current_latest_chain_height - 10)
            await blockchain_service.sync_block_headers(
                header_manager,
                start_height=sync_start_height,
                end_height=current_latest_chain_height
            )
        else:
            logging.warning("Could not get chain info. Skipping block header synchronization.")
    except Exception as e:
        logging.error(f"Failed to synchronize block headers: {e}")

    logging.info("\n--- Block Header Synchronization finished ---")

if __name__ == "__main__":
    asyncio.run(main_sync_headers())

