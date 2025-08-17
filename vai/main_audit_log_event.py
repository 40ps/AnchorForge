# main_audit_log_event.py
'''
This program serves as the entry point for logging a single audit event.
It orchestrates the creation of an OP_RETURN transaction based on a static
string and updates the local caches accordingly.
'''

import asyncio
import logging
from typing import List, Dict
from datetime import datetime, timezone
import uuid

from config import Config
import wallet_manager
import bank_functions
import audit_core
from bsv import PrivateKey
from bsv.hash import sha256

# Configure logging for this specific program
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

async def log_intermediate_result_process():
    """
    Orchestrates the process of creating and broadcasting an audit record.
    This function uses dynamic file paths for the local stores.
    """
    priv_key_funding = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
    sender_address = priv_key_funding.address()

    # Create dynamic file paths based on the sender's address
    utxo_file_path = wallet_manager._get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME)
    tx_file_path = wallet_manager._get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME).replace("utxo_store", "tx_store")
    used_utxo_file_path = wallet_manager._get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME).replace("utxo_store", "used_utxo_store")

    # 1. Load local stores using the provided dynamic file paths.
    store = wallet_manager.load_utxo_store(utxo_file_path)
    used_store = wallet_manager.load_used_utxo_store(used_utxo_file_path)
    tx_store = wallet_manager.load_tx_store(tx_file_path)

    if store.get("address") != str(sender_address) or store.get("network") != Config.ACTIVE_NETWORK_NAME:
         logging.warning(f"Warning: UTXO store address/network ({store.get('address', 'N/A')}/{store.get('network')}) does not match sender address/network ({sender_address}/{Config.ACTIVE_NETWORK_NAME}). Please run main_wallet_setup.py first to initialize stores for this address.")
         return

    if tx_store.get("address") != str(sender_address) or tx_store.get("network") != Config.ACTIVE_NETWORK_NAME:
        logging.warning(f"Warning: TX store address/network ({tx_store.get('address', 'N/A')}/{tx_store.get('network')}) does not match sender address/network ({sender_address}/{Config.ACTIVE_NETWORK_NAME}). Please run main_wallet_setup.py first to initialize stores for this address.")
        return


    # --- SIMULATE AN INTERMEDIATE PROCESS RESULT ---
    # Generate the original content that needs to be audited.
    timestamp_str = datetime.now(timezone.utc).isoformat()
    intermediate_audit_content_string = f"Audit Log Entry: Process step completed at {timestamp_str}. Result: SUCCESS. [Germany Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"
    
    logging.info(f"\n--- Simulating New Audit Content ---")
    logging.info(f"  Content to be logged: '{intermediate_audit_content_string}'")

    # --- BUILD THE OP_RETURN PAYLOAD (Hash, Sig, PubKey from content) ---
    assert Config.PRIVATE_SIGNING_KEY_WIF is not None
    own_signing_key = Config.PRIVATE_SIGNING_KEY_WIF
    op_return_payload_for_tx = audit_core.build_audit_payload(
        intermediate_audit_content_string, 
        own_signing_key
    )
    
    # Create a new audit record entry locally.
    audit_record_entry = {
        "log_id": str(uuid.uuid4()),
        "original_audit_content": intermediate_audit_content_string,
        "timestamp_logged_local": datetime.now(timezone.utc).isoformat(),
        "blockchain_record": {
            "txid": None,
            "raw_transaction_hex": None,
            "data_hash_pushed_to_op_return": op_return_payload_for_tx[0].hex(),
            "signature_pushed_to_op_return": op_return_payload_for_tx[1].hex(),
            "public_key_pushed_to_op_return": op_return_payload_for_tx[2].hex(),
            "status": "pending_creation",
            "timestamp_broadcasted_utc": None,
            "timestamp_confirmed_utc": None,
            "block_hash": None,
            "block_height": None,
            "merkle_proof_data": None
        },
        "notes": "Intermediate process result audit log entry"
    }
    
    audit_log = audit_core.load_audit_log()
    audit_log.append(audit_record_entry)
    audit_core.save_audit_log(audit_log)
    logging.info(f"Initial audit record '{audit_record_entry['log_id']}' saved to {Config.AUDIT_LOG_FILE}.")

    # 2. Create the blockchain transaction containing the audit payload.
    assert Config.UTXO_STORE_KEY_WIF is not None #linter
    
    tx_hex_returned, broadcast_timestamp_str, broadcast_txid, \
        consumed_utxos_details, new_utxos_details = await audit_core.create_op_return_transaction(
            spending_key_wif=Config.UTXO_STORE_KEY_WIF, 
            recipient_address=str(sender_address),
            op_return_data_pushes=op_return_payload_for_tx,
            original_audit_content_string=intermediate_audit_content_string,
            network=Config.ACTIVE_NETWORK_BSV,
            utxo_file_path=utxo_file_path,
            tx_file_path=tx_file_path
    )

    # 3. Update the audit record with broadcast details and handle UTXO state
    if tx_hex_returned:
        if broadcast_txid is None:
            logging.error(f"\nERROR: Transaction created but not broadcasted")
        else:
            logging.info(f"\nTransaction created & broadcasted: {broadcast_txid[:100]}...")

        audit_record_entry["blockchain_record"]["txid"] = broadcast_txid
        audit_record_entry["blockchain_record"]["raw_transaction_hex"] = tx_hex_returned
        audit_record_entry["blockchain_record"]["status"] = "broadcasted"
        audit_record_entry["blockchain_record"]["timestamp_broadcasted_utc"] = broadcast_timestamp_str
        
        # Update UTXO stores (move consumed to used_store, add new to store)
        logging.info(f"Updating local UTXO stores for TXID {broadcast_txid}...")
        
        store = wallet_manager.load_utxo_store(utxo_file_path)
        used_store = wallet_manager.load_used_utxo_store(used_utxo_file_path)
        
        for consumed_utxo in consumed_utxos_details:
            store["utxos"] = [u for u in store["utxos"] if not (u["txid"] == consumed_utxo["txid"] and u["vout"] == consumed_utxo["vout"])]
            
            consumed_utxo["used"] = True
            consumed_utxo["used_in_txid"] = broadcast_txid
            consumed_utxo["used_timestamp"] = datetime.now(timezone.utc).isoformat()
            used_store["used_utxos"].append(consumed_utxo)
            logging.info(f"  - Consumed UTXO: {consumed_utxo['txid']}:{consumed_utxo['vout']}")

        for new_utxo in new_utxos_details:
            store["utxos"].append(new_utxo)
            logging.info(f"  - New UTXO created: {new_utxo['txid']}:{new_utxo['vout']} ({new_utxo['satoshis']} sats)")
        
        wallet_manager.save_utxo_store(store, utxo_file_path)
        wallet_manager.save_used_utxo_store(used_store, used_utxo_file_path)
        logging.info("Local UTXO stores updated.")

        audit_core.save_audit_log(audit_log) 
        logging.info(f"Audit record '{audit_record_entry['log_id']}' updated with TXID {broadcast_txid} and broadcast status.")

        original_hash_expected = sha256(intermediate_audit_content_string.encode('utf-8'))
        original_public_key_hex_expected = PrivateKey(Config.PRIVATE_SIGNING_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV).public_key().hex()

        verification_passed = await audit_core.verify_op_return_hash_sig_pub(
            tx_hex_returned,
            original_hash_expected,
            original_public_key_hex_expected
        )
        logging.info(f"\nOP_RETURN Hash/Signature/Public Key Verification (pre-confirmation): { 'PASS' if verification_passed else 'FAIL' }")

    else:
        audit_record_entry["blockchain_record"]["status"] = "tx_creation_failed"
        audit_core.save_audit_log(audit_log)
        logging.error(f"\nFailed to create or broadcast transaction for audit record '{audit_record_entry['log_id']}'. Status updated.")
    
    logging.info("\nEnd log_intermediate_result_process.")

if __name__ == "__main__":
    asyncio.run(log_intermediate_result_process())
