# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    af_download.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

import asyncio
import argparse
import logging
import sys
import os

from anchorforge.config import Config
from anchorforge import blockchain_api
from anchorforge import verifier
from anchorforge import core_defs

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def download_onchain_data(txid: str, output_path: str):
    """
    Fetches a transaction, extracts the AnchorForge OP_RETURN payload,
    and saves the embedded data (TAG_DATA) to a file.
    """
    logger.info(f"Fetching transaction {txid} from {Config.ACTIVE_NETWORK_NAME} network...")
    
    # 1. Fetch raw transaction from blockchain
    raw_tx = await blockchain_api.fetch_raw_transaction_hex(txid)
    if not raw_tx:
        logger.error("Failed to fetch transaction. Check TXID and network.")
        return

    logger.info("Extracting OP_RETURN payload...")
    
    # 2. Parse OP_RETURN chunks
    data_pushes = verifier.extract_op_return_payload(raw_tx)
    
    if not data_pushes:
        logger.error("No OP_RETURN payload found in this transaction.")
        return

    # 3. Verify AnchorForge AppID (Optional but good practice)
    if len(data_pushes) > 1 and data_pushes[0] == core_defs.AUDIT_MODE_APP_ID:
        try:
            app_id = data_pushes[1].decode('utf-8', errors='ignore')
            logger.info(f"Found Protocol AppID: {app_id}")
        except:
            pass
    else:
        logger.warning("No AnchorForge AppID found at the start. Proceeding anyway...")

    # 4. Search for TAG_DATA ('D') in the TLV structure
    idx = 2
    extracted_bytes = None
    
    while idx < len(data_pushes) - 1:
        tag = data_pushes[idx]
        val = data_pushes[idx+1]
        
        if tag == core_defs.AUDIT_TAG_DATA:
            logger.info("Found On-Chain Data block (TAG_DATA)!")
            if len(val) > 0:
                fmt_byte = val[0]
                extracted_bytes = val[1:]  # Strip the format byte (0x00 or 0x01)
                
                fmt_name = "RAW" if fmt_byte == core_defs.DATA_FMT_RAW else "UTF-8" if fmt_byte == core_defs.DATA_FMT_UTF8 else "UNKNOWN"
                logger.info(f"Format: {fmt_name} (Byte: {hex(fmt_byte)})")
                logger.info(f"Data Size: {len(extracted_bytes)} bytes")
            break
        
        idx += 2  # Move to the next Tag-Value pair
        
    # 5. Write to file
    if extracted_bytes is not None:
        try:
            # Ensure output directory exists
            out_dir = os.path.dirname(output_path)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
                
            with open(output_path, 'wb') as f:
                f.write(extracted_bytes)
            logger.info(f"Success! Exact binary data written to '{output_path}'")
            
        except Exception as e:
            logger.error(f"Failed to write to file {output_path}: {e}")
    else:
        logger.error("No embedded data (TAG_DATA) found in this transaction.")


def main():
    parser = argparse.ArgumentParser(
        description="AnchorForge v0.2: Extract and download embedded on-chain data from a transaction.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--txid', required=True, help="The Transaction ID containing the data.")
    parser.add_argument('--output', required=True, help="Path where the extracted file should be saved.")
    parser.add_argument('--network', choices=['main', 'test'], help="Override the network config (main/test).")
    
    args = parser.parse_args()
    
    # Override network configuration if requested
    if args.network:
        Config.ACTIVE_NETWORK_NAME = args.network
        if args.network == 'main':
            Config.WOC_API_BASE_URL = "https://api.whatsonchain.com/v1/bsv/main"
        else:
            Config.WOC_API_BASE_URL = "https://api.whatsonchain.com/v1/bsv/test"
            
    asyncio.run(download_onchain_data(args.txid, args.output))


if __name__ == "__main__":
    main()