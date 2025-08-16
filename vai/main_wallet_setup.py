# main_wallet_setup.py
'''
Tasks: 
Initialisation of UTXO Store
Consolidation of funds in bank address
Creation of small usable UTXOs from bank fundings
Synchronisation of blockheaders for SPV Proofs

Workflow in use:
- first, the bank address is filled with funds.
- it may get funds from several addresses
- these funds may or may not be consolidated into the same bank address
- from these funds, many small UTXOs are created 
  for the UTXO store that will be used to create registrations transactions

- These can be consolidated back into the back account end of task for clean up - if wanted
- Sync of blockheaders not necessary. 


V25-08-16: all

'''

import asyncio
import logging
from typing import Dict, Any

from config import Config
import wallet_manager
import bank_functions
import blockchain_api
import blockchain_service
import key_manager
from block_manager import BlockHeaderManager
from bsv import PrivateKey, Network

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)


# Consolidate UTXOs into the Bank Address
async def fill_bank_with(source_pk):
    logging.info("\nStep 2: Consolidating UTXOs into the Bank Address.")
    try:
        # If they are the same, this step will be a self-consolidation.
        if Config.PRIVATE_BANK_KEY_WIF is None:
            raise ValueError("PRIVATE_BANK_KEY_WIF is not configured.")
        
        # This function restores all funds from UTXO_STORE_KEY to BANK_ADDRESS
        consolidation_tx_hex = await bank_functions.load_bank(source_pk)
        
        if consolidation_tx_hex:
            # Broadcast the consolidation transaction
            logging.info(f"Consolidation transaction created. Broadcasting now...")
            broadcast_txid = await blockchain_api.broadcast_transaction(consolidation_tx_hex)
            if broadcast_txid:
                logging.info(f"Consolidation transaction broadcasted with TXID: {broadcast_txid}")
            else:
                logging.error("Failed to broadcast consolidation transaction.")
        else:
            logging.info("No consolidation transaction was created (no UTXOs to consolidate or insufficient funds).")
    except Exception as e:
        logging.error(f"An error occurred during consolidation: {e}")

# Create a pool of working UTXOs from the Bank
async def create_utxolets(size : int = 1000, number : int = 5):
    # These smaller UTXOs will be used for future transactions
    logging.info("\nCreating working UTXOs from the bank for future use.")
    try:
        # A simple example: create 5 UTXOs of 1000 satoshis each
        # The recipient is the same as the UTXO store address.
        assert Config.UTXO_STORE_KEY_WIF is not None, "ERROR no UTXO STORE KEY set"
        priv_key_utxo_store = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
        recipient_address = priv_key_utxo_store.address()
        
        # It's better to fetch UTXOs for the bank address here and consolidate first
        # to ensure there's enough balance for the split.
        
        working_utxo_tx_hex = await bank_functions.create_working_utxos(
            recipient_address=str(recipient_address),
            utxo_value=size,
            num_utxos=number
        )
        if working_utxo_tx_hex:
            logging.info("Working UTXOs transaction created. Broadcasting now...")
            broadcast_txid = await blockchain_api.broadcast_transaction(working_utxo_tx_hex)
            if broadcast_txid:
                logging.info(f"Working UTXOs transaction broadcasted with TXID: {broadcast_txid}")

                # Re-initialize UTXO store to reflect new UTXOs
                await asyncio.sleep(10) # Wait for network propagation
                await wallet_manager.initialize_utxo_store(Config.UTXO_STORE_KEY_WIF, Config.ACTIVE_NETWORK_NAME)
            else:
                logging.error("Failed to broadcast working UTXOs transaction.")
        else:
            logging.info("Could not create working UTXOs (insufficient funds or other issue).")

    except Exception as e:
        logging.error(f"An error occurred while creating working UTXOs: {e}")


# Fetches all UTXOs for the main UTXO store key and caches them locally.
async def initialize_utxo_store(): 
    logging.info("Initializing local UTXO and TX stores.")
    try:
        if Config.UTXO_STORE_KEY_WIF is None:
            raise ValueError("UTXO_STORE_KEY_WIF is not configured.")
        await wallet_manager.initialize_utxo_store(Config.UTXO_STORE_KEY_WIF, Config.ACTIVE_NETWORK_NAME)
    except Exception as e:
        logging.error(f"Failed to initialize UTXO store: {e}")
        return

async def sync_blockheaders() :
    # Synchronize block headers for SPV 
    # This step is crucial for the AUDITOR, not for transaction creation.
    # It ensures the auditor has a local chain of trust.
    logging.info("\nSynchronizing recent block headers for SPV proof verification.")
    header_manager = BlockHeaderManager(Config.BLOCK_HEADERS_FILE)
    try:
        chain_info = await blockchain_api.get_chain_info_woc()
        if chain_info and chain_info.get("blocks") is not None:
            current_latest_chain_height = chain_info["blocks"]
            # Sync the last 1000 blocks to ensure recent transactions can be verified.
            sync_start_height = max(0, current_latest_chain_height - 1000)
            await blockchain_service.sync_block_headers(
                header_manager,
                start_height=sync_start_height,
                end_height=current_latest_chain_height
            )
        else:
            logging.warning("Could not get chain info. Skipping block header synchronization.")
    except Exception as e:
        logging.error(f"Failed to synchronize block headers: {e}")

    logging.info("\n--- Wallet environment setup complete. ---")


async def setup_wallet_environment():
    
    pk = key_manager.get_private_key_by_label('M-bank_account')
    # pk = Config.PRIVATE_BANK_KEY_WIF # default: fill with itself to show
    assert pk is not None, "No key from key file"
 
    await fill_bank_with(pk) # now it is just filling itself
    await create_utxolets(1000,5)
    await initialize_utxo_store()
    await sync_blockheaders()




if __name__ == "__main__":
    asyncio.run(setup_wallet_environment())