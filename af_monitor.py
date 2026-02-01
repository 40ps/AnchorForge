# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    af_monitor.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

# af_monitor.py
import asyncio
import logging
import os
import argparse  # We'll use argparse for cleaner argument handling

from bsv import PrivateKey

from anchorforge.config import Config
from anchorforge import manager
from anchorforge import utils
from anchorforge import wallet_manager

if hasattr(Config, 'LOG_FILE') and Config.LOG_FILE:
    log_dir = os.path.dirname(Config.LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

# Configure logging (remains the same)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

async def main_monitor(duration_minutes: int | None):
    """
    Starts the transaction monitor.
    - If duration_minutes is provided, it runs for that specific time.
    - If duration_minutes is None, it runs as a continuous service.
    """
    if duration_minutes:
        logging.info(f"\n--- Starting Audit Monitor in DURATION mode for {duration_minutes} minutes ---")
    else:
        logging.info(f"\n--- Starting Audit Monitor in CONTINUOUS mode ---")
    
    # Generate dynamic file paths (remains the same)
    try:
        priv_key = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
        sender_address = priv_key.address()

        utxo_file_path = wallet_manager._get_filename_for_address(
            str(sender_address), 
            Config.ACTIVE_NETWORK_NAME, 
            file_type="utxo"
        )
        
        used_utxo_file_path = wallet_manager._get_filename_for_address(
            str(sender_address), 
            Config.ACTIVE_NETWORK_NAME, 
            file_type="used"
        )
    except Exception as e:
        logging.error(f"Failed to get address for dynamic file paths: {e}")
        return

    # --- Logic to switch between modes ---
    try:
        if duration_minutes:
            # --- DURATION MODE ---
            monitor_task = asyncio.create_task(
                manager.monitor_pending_transactions(
                    utxo_file_path, 
                    used_utxo_file_path
                )
            )
            await asyncio.sleep(duration_minutes * 60)
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                logging.info("Monitor task cancelled gracefully after duration.")
        
        else:
            # --- CONTINUOUS MODE ---
            while True:
                if await utils.check_process_controls('monitor'):
                    break  # Exit loop if stop is requested

                await manager.monitor_pending_transactions(
                    utxo_file_path, 
                    used_utxo_file_path
                )
                await asyncio.sleep(Config.MONITOR_POLLING_INTERVAL)

    except asyncio.CancelledError:
        # This handles Ctrl+C gracefully in both modes
        pass
        
    logging.info("\n--- Audit Monitor has been stopped. ---")

if __name__ == "__main__":
    Config.validate_wallet_config()
    
    parser = argparse.ArgumentParser(description="Run the Audit Monitor.")
    parser.add_argument(
        '-d', '--duration', 
        type=int, 
        help="Optional: Run the monitor for a specific duration in minutes."
    )
    args = parser.parse_args()

    try:
        asyncio.run(main_monitor(args.duration))
    except KeyboardInterrupt:
        logging.info("\n--- Audit Monitor stopped by user (Ctrl+C). ---")