# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    blockchain_service.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

# blockchain_service.py
# Optimized to store only essential block header data (excluding TX lists).

import logging
import asyncio
from typing import Dict, Any, Optional

from anchorforge.config import Config
from anchorforge.block_manager import BlockHeaderManager
from anchorforge.blockchain_api import get_chain_info_woc, get_block_header_height, get_block_header
from anchorforge.utils import verify_block_hash 

logger = logging.getLogger(__name__)

def _minimize_header_data(full_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts only the essential fields needed for SPV verification and
    block linking. Discards the potentially huge list of transaction IDs ('tx').
    """
    return {
        "hash": full_data.get("hash"),
        "height": full_data.get("height"),
        "version": full_data.get("version"),
        "merkleroot": full_data.get("merkleroot"),
        "time": full_data.get("time"),
        "nonce": full_data.get("nonce"),
        "bits": full_data.get("bits"),
        "previousblockhash": full_data.get("previousblockhash"),
        # Optional metadata that doesn't take much space but is useful
        "difficulty": full_data.get("difficulty"),
        "confirmations": full_data.get("confirmations"),
        "nextblockhash": full_data.get("nextblockhash")
        # EXPLICITLY REMOVED: "tx" (List of transaction IDs)
    }

async def sync_block_headers(header_manager: BlockHeaderManager, start_height: int = 0, end_height: Optional[int] = None):
    """
    Synchronizes (fetches and caches) block headers from WhatsOnChain locally.
    Verifies each header's hash before caching.
    
    Args:
        header_manager (BlockHeaderManager): The manager instance for header data.
        start_height (int): The starting block height for synchronization (inclusive).
        end_height (int | None): The ending block height for synchronization (inclusive).
    """
    logger.info(f"\n--- Starting Block Header Synchronization ---")
    
    local_headers = header_manager.headers 
    
    current_latest_height_on_chain = 0
    try:
        chain_info = await get_chain_info_woc()
        if chain_info and chain_info.get("blocks") is not None:
            current_latest_height_on_chain = chain_info["blocks"]
            logger.info(f"Latest block on chain: {current_latest_height_on_chain}")
        else:
            logger.error("Could not retrieve latest block height. Cannot synchronize headers.")
            return
    except Exception as e:
        logger.error(f"Failed to get latest block height for sync: {e}")
        return

    if end_height is None or end_height > current_latest_height_on_chain:
        end_height = current_latest_height_on_chain

    if start_height < 0:
        start_height = 0
    if start_height > end_height:  #type: ignore
        logger.warning(f"Start height {start_height} is greater than end height {end_height}. No headers to sync.")
        return

    logger.info(f"Synchronizing headers from height {start_height} to {end_height}.")
    
    synced_count = 0
    for height in range(start_height, end_height + 1): #type: ignore
        try:
            block_info_by_height = await get_block_header_height(height)
            
            if not block_info_by_height or "hash" not in block_info_by_height:
                logger.warning(f"  Could not get block hash for height {height}. Response: {block_info_by_height}. Skipping.")
                continue
            
            block_hash = block_info_by_height["hash"]

            if block_hash in local_headers:
                if height % 1000 == 0: logger.info(f"Height {height} already cached.")
                continue

            full_header_data = await get_block_header(block_hash)
            
            if full_header_data:

                # 4. Filter Data (remove verbosity)
                minimal_header = _minimize_header_data(full_header_data)

                if verify_block_hash(minimal_header):
                    local_headers[block_hash] = minimal_header
                    synced_count += 1
                    if synced_count % 100 == 0:
                        logger.info(f"  Synced {synced_count} headers. Current height: {height}")
                else:
                    logger.error(f"  Failed to verify hash for block {block_hash}. NOT caching.")
            else:
                logger.warning(f"  Could not fetch full header data for block {block_hash}. Skipping.")

            # await asyncio.sleep(1) now in finally

        except Exception as e:
            logger.error(f"  Error syncing header for height {height}: {e}")
            # await asyncio.sleep(1) now in finally

        finally:
            await asyncio.sleep(Config.DELAY_BETWEEN_HEADER_REQUESTS)

    # Speichern der Änderungen über die save-Methode des Managers
    header_manager.save()
    logger.info(f"Block Header Synchronization complete. Synced {synced_count} new headers. Total cached: {len(local_headers)}.")