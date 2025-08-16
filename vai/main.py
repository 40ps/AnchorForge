'''
Version: 25-08-10
    moved load/save blockheader into an own class BlockHeaderManager
    created blockchain_service
    moved helpers into utils
    cleaned up a lot of type issues
Version: 25-08-09
    moved secrets to .env, made config to class query environment
    addapted type info
Version: 25-07-19
    Modularisation Step 1-2

Version: 25-07-11
    
Works:
    Make SPV off-chain, audit_record_verifier uses local blockheaders
    Sync Blockheader works, but not optimal. Order in data base not correct
    TODO: download height only, if not in data base (1fetch to much)
    
Version: 25-07-10
Implements
    Sync Blockheaders (untested)
Works:
    Proof correctnes with live - blockheaders + Audit_log
    

Version: 25-07-09
Works:
    Audit_log selfcontained

    huge changes 
    create_op_return_transaction
    monitor
    Store concept
    replaced log_intermediate_result with new version
    removed create_op_return_payload_data_obsolte

Version 25-07-08
Works:
    Improving Store UTXO and TX structure
    Getting Merkle Tree
    Monitoring Transactions
    
create_audit_record
Version 25-07-06c
Works:
    OP_RETURN Payload separat
    Hole Merkle trees, teste in verification


Version 25-07-06
Works: 
    Store UTXO, used UTXO, created TX (without merkle path)
    create_and_send_local_transaction - OP Return with 3 Arguments
    print OP_RETURN + 3
    verify OP_RETURN + 3

'''

import asyncio
import httpx # For making asynchronous HTTP requests
import json

from typing import List, Dict

import logging

from config import Config
import blockchain_api

from block_manager import BlockHeaderManager
from blockchain_service import sync_block_headers

import wallet_manager
import audit_core
import bank_functions

import utils



# Configure logging
logging.basicConfig(
    level=logging.INFO, # Default logging level (e.g., INFO, DEBUG, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE, mode='a', encoding='utf-8'), # Log to file, append mode
        logging.StreamHandler() # Log to console (sys.stdout/stderr)
    ]
)

from bsv import (
    PrivateKey, 
    Network
)

from bsv.hash import sha256 # Import sha256 function directly from bsv.hash module

    

'''
to be transformed into class into blockchain_service.py

# Functions for managing the local Block Headers cache
def load_block_headers() -> Dict[str, Dict]:
    """
    Loads cached block headers from the BLOCK_HEADERS_FILE.
    Returns a dictionary mapping blockhash to block header data.
    """
    try:
        with open(Config.BLOCK_HEADERS_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # The block headers store is a dictionary, so it starts empty.
        return {}

def save_block_headers(headers_data: Dict[str, Dict]):
    """
    Saves block headers to the BLOCK_HEADERS_FILE.
    """
    with open(Config.BLOCK_HEADERS_FILE, 'w') as f:
        json.dump(headers_data, f, indent=4)

# End Block header
'''




async def main():
    header_manager = BlockHeaderManager(Config.BLOCK_HEADERS_FILE)

    # await sync_block_headers(1683340)

    #result = await audit_record_verifier("2542298b-57aa-4480-b283-6ebaffa009e0")
    
    await audit_core.audit_all_records()
    
    print(f"Audit Test Ende ")

async def mainmain():
    header_manager = BlockHeaderManager(Config.BLOCK_HEADERS_FILE)

    assert Config.UTXO_STORE_KEY_WIF is not None, "UTXO STORE Key not set"
    priv_key = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
    sender_address = priv_key.address()


    # Create dynamic file paths based on the sender's address
    utxo_file_path = wallet_manager._get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME)
    tx_file_path = wallet_manager._get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME).replace("utxo_store", "tx_store")
    used_utxo_file_path = wallet_manager._get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME).replace("utxo_store", "used_utxo_store")

    await wallet_manager.initialize_utxo_store(Config.UTXO_STORE_KEY_WIF, Config.ACTIVE_NETWORK_NAME)

    latest_height_info = await blockchain_api.get_chain_info_woc()
    if latest_height_info:
        current_latest_chain_height = latest_height_info["blocks"]
        sync_start_height = max(0, current_latest_chain_height - 10000)
        logging.info(f"Syncing block headers from {sync_start_height} to {current_latest_chain_height}...")
        await sync_block_headers(header_manager, start_height=sync_start_height, end_height=current_latest_chain_height)

    # Start the monitoring task in the background
    monitor_task = asyncio.create_task(
        audit_core.monitor_pending_transactions(utxo_file_path, used_utxo_file_path, polling_interval_seconds=Config.MONITOR_POLLING_INTERVAL))
    logging.info("Monitor task has been scheduled to run in the background.") 
    
    # Simulate logging an intermediate result
    logging.info("\n--- Initiating Intermediate Result Logging Process ---")
    await bank_functions.log_intermediate_result_process(utxo_file_path, used_utxo_file_path, tx_file_path)

    # Example of logging multiple audit records (optional)
    # for i in range(2): 
    #     logging.info(f"\n--- Logging Additional Intermediate Result {i+1} ---")
    #     await asyncio.sleep(5) 
    #     await audit_core.log_intermediate_result_process() 

    logging.info(f"Main script will continue running for {Config.MAINSCRIPT_RUNNING/60:.0f } minutes to allow transaction monitoring...")
    logging.info(f"Check audit_log.json for status updates and monitor console for 'Checking confirmation' messages.")
    await asyncio.sleep(Config.MAINSCRIPT_RUNNING) # Wait 
    
    monitor_task.cancel() # Stop the monitoring task gracefully
    try:
        await monitor_task # Await its cancellation
    except asyncio.CancelledError:
        print("Transaction monitor task cancelled gracefully.")



    # --- FINAL VERIFICATION STEP: AUDITOR'S PERSPECTIVE ---

    await audit_core.audit_all_records()


    '''
    # This step is performed after the main waiting period, assuming a record is confirmed.
    created_log_id = "2542298b-57aa-4480-b283-6ebaffa009e0"
    if created_log_id: # Only attempt if a log was successfully created
        logging.info(f"\n### Attempting Auditor Verification for the created record (ID: {created_log_id}) ###")
        # Ensure that this record is now confirmed in the audit_log.json for verification.
        # You might need to reload audit_log here to get the latest status
        current_audit_log_state = audit_core.load_audit_log()
        target_record = next((r for r in current_audit_log_state if r.get("log_id") == created_log_id), None)

        if target_record and target_record.get("blockchain_record", {}).get("status") == "confirmed":
            verification_successful = await audit_core.audit_record_verifier(created_log_id)
            if verification_successful:
                logging.info(f"Auditor Verification of '{created_log_id}' (Confirmed Record): OVERALL PASS.")
            else:
                logging.error(f"Auditor Verification of '{created_log_id}' (Confirmed Record): OVERALL FAIL.")
        else:
            logging.warning(f"Auditor Verification skipped for '{created_log_id}': Record not found or not yet confirmed.")
            if target_record:
                logging.warning(f"  Current Status: {target_record.get('blockchain_record', {}).get('status', 'N/A')}")
    else:
        logging.warning("No audit record was created successfully, skipping auditor verification.")
    '''
    # await create_op_return_payload_data_obsolete()
    # await test_merkle_proof()
    # await test_methods()
    # await test_bank()
    

    print("\nScript execution finished.")


if __name__ == "__main__":
    asyncio.run(main())

