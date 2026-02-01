# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    af_sync.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

# af_sync.py
'''
This program is dedicated to synchronizing blockchain block headers.
It is intended to be run separately from the audit process to ensure
the local cache is up-to-date for later SPV verification tasks.

Flexible Block Header Synchronization Tool.

Features:
- Sync from network (Last N, Range, List)
- Minimize storage (--minimal-info)
- Custom output file (--output)
- Network override (--network)
- Convert existing files (--convert)

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
import json
import os
import sys
from typing import Dict, Any

from anchorforge.config import Config
from anchorforge import blockchain_api
from anchorforge import blockchain_service
from anchorforge.block_manager import BlockHeaderManager


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

logger = logging.getLogger(__name__)

def get_minimal_header(full_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extremely minimal header data for pure SPV demo purposes."""
    return {
        "hash": full_data.get("hash"),
        "height": full_data.get("height"),
        "merkleroot": full_data.get("merkleroot"),
        "previousblockhash": full_data.get("previousblockhash"),
        "time": full_data.get("time")
    }

async def convert_file(input_file: str, output_file: str, minimal: bool):
    """Converts an existing header file to a cleaner/minimal version."""
    logger.info(f"Converting '{input_file}' -> '{output_file}' (Minimal: {minimal})")
    
    if not os.path.exists(input_file):
        logger.error(f"Input file not found: {input_file}")
        return

    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        # Determine format (Dict or List)
        # BlockHeaderManager usually stores as Dict {hash: header}
        headers_to_process = data if isinstance(data, dict) else {}
        
        processed_headers = {}
        for h_hash, header in headers_to_process.items():
            if minimal:
                processed_headers[h_hash] = get_minimal_header(header)
            else:
                # Use the service's optimized filter (removes TX list)
                processed_headers[h_hash] = blockchain_service._minimize_header_data(header)
        
        with open(output_file, 'w') as f:
            json.dump(processed_headers, f, indent=4)
            
        logger.info(f"Conversion complete. Processed {len(processed_headers)} headers.")
        
    except Exception as e:
        logger.error(f"Conversion failed: {e}")



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

    # Tool Modes
    group.add_argument('--convert', type=str, metavar='INPUT_FILE', help="Convert an existing file (offline mode).")

    # Options
    parser.add_argument('-o', '--output', type=str, help="Custom output filename (default: block_headers_<NET>.json).")
    parser.add_argument('--minimal-info', action='store_true', help="Store only absolute minimum data (hash, root, prev, time).")
    parser.add_argument('--network', type=str, choices=['main', 'test'], help="Override network selection.")

    args = parser.parse_args()

    # 1. Network Override (Simple Hack: Monkey-Patch Config)
    if args.network:
        logger.info(f"Overriding network configuration to: {args.network}")
        Config.ACTIVE_NETWORK_NAME = args.network
        # Re-init API constants if needed (simplified)
        if args.network == 'main':
            Config.WOC_API_BASE_URL = "https://api.whatsonchain.com/v1/bsv/main"
        else:
            Config.WOC_API_BASE_URL = "https://api.whatsonchain.com/v1/bsv/test"


    logging.info("\n--- Starting Block Header Synchronization ---")

    # Use Config.BLOCK_HEADERS_FILE as default if available (pointing to database/),
    # otherwise fallback to local filename generation.
    if args.output:
        output_file = args.output
    elif hasattr(Config, 'BLOCK_HEADERS_FILE') and Config.BLOCK_HEADERS_FILE:
         output_file = Config.BLOCK_HEADERS_FILE
    else:
        output_file = f"block_headers_{Config.ACTIVE_NETWORK_NAME}.json"


    
    # 2. Conversion Mode (Offline)
    if args.convert:
        await convert_file(args.convert, output_file, args.minimal_info)
        return

    # 3. Sync Mode (Online)
    logger.info(f"--- Starting Sync (Target: {output_file}) ---")


    # Ensure directory for output file exists (e.g. database/)
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        logger.info(f"Creating directory for block headers: {output_dir}")
        os.makedirs(output_dir, exist_ok=True)

    # We initialize the manager with the output file. 
    # If it exists, it loads it. If not, it starts empty.
    manager = BlockHeaderManager(output_file)
    



    try:
        original_minimizer = blockchain_service._minimize_header_data
        if args.minimal_info:
            logger.info("Mode: Minimal Info (Extreme SPV)")
            blockchain_service._minimize_header_data = get_minimal_header


        # --- Logic Selection ---
        if args.last:
            if args.last <= 0:
                logger.error("Argument --last must be a positive integer.")
                return

            logging.info(f"Mode: Synchronizing last {args.last} blocks.")
            info = await blockchain_api.get_chain_info_woc()
            if info and info.get("blocks"):
                end = info["blocks"]
                start = max(0, end - args.last + 1)
                await blockchain_service.sync_block_headers(manager, start, end)
            else:
                logging.error("Could not get chain info to determine the last blocks.")
        elif args.range:
            try: 
                start, end = map(int, args.range.split('-'))
                if start < 0 or end < 0:
                        logger.error("Block heights cannot be negative.")
                        return
                if start > end:
                    logging.error("Error in range: Start height cannot be greater than end height.")
                    return
                
                logger.info(f"Mode: Syncing specific range {start} to {end}.")
                await blockchain_service.sync_block_headers(manager, start, end)
            except ValueError:
                logger.error("Invalid format for --range. Please use START-END (e.g., 100-200).")
                return
    
        elif args.block:
            if args.block < 0:
                logger.error("Block height cannot be negative.")
                return
            logger.info(f"Mode: Syncing single block {args.block}.")
            await blockchain_service.sync_block_headers(manager, args.block, args.block)

        elif args.blocks:
            try:
                block_heights = [int(h.strip()) for h in args.blocks.split(',') if h.strip()]
                if not block_heights:
                    logger.error("No valid block numbers provided.")
                    return
                
                unique_heights = sorted(set(block_heights))
                logger.info(f"Mode: Syncing list of {len(unique_heights)} blocks: {unique_heights}")
                
                for height in unique_heights:
                    if height < 0:
                        logger.warning(f"Skipping negative block height: {height}")
                        continue
                    # We reuse the service logic which handles single block caching gracefully
                    await blockchain_service.sync_block_headers(manager, height, height)
            except ValueError:
                logger.error("Invalid format for --blocks. Please use a comma-separated list of numbers (e.g., 100,105,110).")
                return
        else:
            # Default
            logger.info("No specific arguments provided. Defaulting to: Sync last 2 blocks.")
            info = await blockchain_api.get_chain_info_woc()
            if info and info.get("blocks"):
                end = info["blocks"]
                start = max(0, end - 1)
                logger.info(f"Chain tip: {end}. Syncing range: {start}-{end}")
                await blockchain_service.sync_block_headers(manager, start, end)
            else:
                logger.error("Could not get chain info for default synchronization.")
        # Restore minimizer (good practice)
        if args.minimal_info:
            blockchain_service._minimize_header_data = original_minimizer

    except Exception as e:
        logger.error(f"Sync failed: {e}", exc_info=True)

    logger.info("--- Finished ---")
  


if __name__ == "__main__":
    asyncio.run(main_sync_headers())
