# main_audit_monitor.py
import asyncio
import logging
import sys

from config import Config
import audit_core
from wallet_manager import _get_filename_for_address
from bsv import PrivateKey

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

async def main_monitor(duration_minutes: int):
    """
    Starts the transaction monitor for a specified duration.
    
    Args:
        duration_minutes (int): The duration in minutes for which the monitor should run.
    """
    logging.info(f"\n--- Starting Audit Monitor for {duration_minutes} minutes ---")
    
    # Generate dynamic file paths based on the main UTXO store key
    try:
        priv_key = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
        sender_address = priv_key.address()
        utxo_file_path = _get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME)
        used_utxo_file_path = _get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME).replace("utxo_store", "used_utxo_store")
    except Exception as e:
        logging.error(f"Failed to get address for dynamic file paths: {e}")
        return

    monitor_task = asyncio.create_task(
        audit_core.monitor_pending_transactions(
            utxo_file_path, 
            used_utxo_file_path, 
            polling_interval_seconds=Config.MONITOR_POLLING_INTERVAL
        )
    )
    
    # Run the monitor for the specified duration
    await asyncio.sleep(duration_minutes * 60)
    
    # Stop the monitor gracefully
    monitor_task.cancel()
    try:
        await monitor_task
    except asyncio.CancelledError:
        logging.info("Transaction monitor task cancelled gracefully.")
        
    logging.info("\n--- Audit Monitor finished ---")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
            asyncio.run(main_monitor(duration))
        except ValueError:
            logging.error("Invalid argument. Please provide an integer for the duration in minutes.")
    else:
        logging.info("python  main_audit_monitor x to start it for x minutes")
        asyncio.run(main_monitor(60))