# main_sync_headers.py
'''
This program is dedicated to synchronizing blockchain block headers.
It is intended to be run separately from the audit process to ensure
the local cache is up-to-date for later SPV verification tasks.


It can be controlled via command-line arguments to sync:
- The last N blocks: --last <N>
- A specific range of blocks: --range <start>-<end>
- A single block: --block <block_height>
- A list of specific blocks: --blocks <block1,block2,...>
'''

import asyncio
import logging
import argparse
import sys

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

async def main_sync_headers_old():
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
            sync_start_height = max(0, current_latest_chain_height - 2)
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

async def main_sync_headers():
    """
    Main entry point for the block header synchronization process.
    Parses command-line arguments to determine which blocks to sync.
    """
    parser = argparse.ArgumentParser(
        description="Synchronize blockchain block headers for off-chain SPV verification.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-l', '--last', type=int, metavar='N', help="Synchronize the last N blocks.")
    group.add_argument('-r', '--range', type=str, metavar='START-END', help="Synchronize a specific range of blocks (e.g., 1683340-1683350).")
    group.add_argument('-b', '--block', type=int, metavar='HEIGHT', help="Synchronize a single, specific block by its height.")
    group.add_argument('-B', '--blocks', type=str, metavar='H1,H2,...', help="Synchronize a comma-separated list of specific block heights.")

    args = parser.parse_args()

    logging.info("\n--- Starting Block Header Synchronization ---")

    dynamic_header_file_path = f"block_headers_{Config.ACTIVE_NETWORK_NAME}.json"
    header_manager = BlockHeaderManager(dynamic_header_file_path)

    try:
        if args.last:
            logging.info(f"Mode: Synchronizing last {args.last} blocks.")
            chain_info = await blockchain_api.get_chain_info_woc()
            if chain_info and chain_info.get("blocks") is not None:
                end_height = chain_info["blocks"]
                start_height = max(0, end_height - args.last + 1)
                await blockchain_service.sync_block_headers(header_manager, start_height, end_height)
            else:
                logging.error("Could not get chain info to determine the last blocks.")
        
        elif args.range:
            logging.info(f"Mode: Synchronizing block range {args.range}.")
            try:
                start_str, end_str = args.range.split('-')
                start_height = int(start_str)
                end_height = int(end_str)
                if start_height > end_height:
                    logging.error("Error in range: Start height cannot be greater than end height.")
                else:
                    await blockchain_service.sync_block_headers(header_manager, start_height, end_height)
            except ValueError:
                logging.error("Invalid range format. Please use START-END (e.g., 100-200).")

        elif args.block:
            logging.info(f"Mode: Synchronizing single block {args.block}.")
            await blockchain_service.sync_block_headers(header_manager, args.block, args.block)

        elif args.blocks:
            logging.info(f"Mode: Synchronizing block list {args.blocks}.")
            try:
                block_heights = [int(h.strip()) for h in args.blocks.split(',')]
                for height in sorted(block_heights):
                    logging.info(f"  Syncing block {height} from list...")
                    await blockchain_service.sync_block_headers(header_manager, height, height)
            except ValueError:
                logging.error("Invalid blocks format. Please use a comma-separated list of numbers (e.g., 100,105,110).")

        else:
            logging.info("No specific mode selected. Synchronizing last 2 blocks by default.")
            # Default behavior if no arguments are provided
            chain_info = await blockchain_api.get_chain_info_woc()
            if chain_info and chain_info.get("blocks") is not None:
                end_height = chain_info["blocks"]
                start_height = max(0, end_height - 1) # Sync last 2 blocks
                await blockchain_service.sync_block_headers(header_manager, start_height, end_height)
            else:
                logging.error("Could not get chain info for default synchronization.")

    except Exception as e:
        logging.error(f"An unexpected error occurred during synchronization: {e}", exc_info=True)

    logging.info("\n--- Block Header Synchronization finished ---")


if __name__ == "__main__":
    asyncio.run(main_sync_headers())

