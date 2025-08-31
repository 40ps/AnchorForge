# blockchain_service.py
import logging
import asyncio
from typing import Dict, Any, Optional

from block_manager import BlockHeaderManager
from blockchain_api import get_chain_info_woc, get_block_header_height, get_block_header
from utils import verify_block_hash 

async def sync_block_headers(header_manager: BlockHeaderManager, start_height: int = 0, end_height: Optional[int] = None):
    """
    Synchronizes (fetches and caches) block headers from WhatsOnChain locally.
    Verifies each header's hash before caching.
    
    Args:
        header_manager (BlockHeaderManager): The manager instance for header data.
        start_height (int): The starting block height for synchronization (inclusive).
        end_height (int | None): The ending block height for synchronization (inclusive).
    """
    logging.info(f"\n--- Starting Block Header Synchronization ---")
    
    # local_headers wird jetzt über den header_manager verwaltet
    local_headers = header_manager.headers 
    
    current_latest_height_on_chain = 0
    try:
        chain_info = await get_chain_info_woc()
        if chain_info and chain_info.get("blocks") is not None:
            current_latest_height_on_chain = chain_info["blocks"]
            logging.info(f"Latest block on chain: {current_latest_height_on_chain}")
        else:
            logging.error("Could not retrieve latest block height. Cannot synchronize headers.")
            return
    except Exception as e:
        logging.error(f"Failed to get latest block height for sync: {e}")
        return

    if end_height is None or end_height > current_latest_height_on_chain:
        end_height = current_latest_height_on_chain

    if start_height < 0:
        start_height = 0
    if start_height > end_height:  #type: ignore
        logging.warning(f"Start height {start_height} is greater than end height {end_height}. No headers to sync.")
        return

    logging.info(f"Synchronizing headers from height {start_height} to {end_height}.")
    
    synced_count = 0
    for height in range(start_height, end_height + 1): #type: ignore
        try:
            block_info_by_height = await get_block_header_height(height)
            if not block_info_by_height or not block_info_by_height.get("hash"):
                logging.warning(f"  Could not get block hash for height {height}. Skipping.")
                continue
            
            block_hash = block_info_by_height["hash"]

            if block_hash in local_headers:
                continue

            full_header_data = await get_block_header(block_hash)
            
            if full_header_data:
                if verify_block_hash(full_header_data):
                    local_headers[block_hash] = full_header_data
                    synced_count += 1
                    if synced_count % 100 == 0:
                        logging.info(f"  Synced {synced_count} headers. Current height: {height}")
                else:
                    logging.error(f"  Failed to verify hash for block {block_hash}. NOT caching.")
            else:
                logging.warning(f"  Could not fetch full header data for block {block_hash}. Skipping.")

            await asyncio.sleep(1)

        except Exception as e:
            logging.error(f"  Error syncing header for height {height}: {e}")
            await asyncio.sleep(1)

    # Speichern der Änderungen über die save-Methode des Managers
    header_manager.save()
    logging.info(f"Block Header Synchronization complete. Synced {synced_count} new headers. Total cached: {len(local_headers)}.")