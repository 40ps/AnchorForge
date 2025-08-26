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
import key_x509_manager # Import the new module
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
    logging.info(f"\n--- Enter log Intermediate_result_process ---")
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

    # --- BUILD THE ECDSA PAYLOAD (Hash, Sig, PubKey) ---
    assert Config.PRIVATE_SIGNING_KEY_WIF is not None
    ec_payload = audit_core.build_audit_payload(
        intermediate_audit_content_string, 
        Config.PRIVATE_SIGNING_KEY_WIF
    )

    # --- BUILD AND APPEND THE X.509 PAYLOAD ---
    x509_payload = []
    cert_info = key_x509_manager.get_x509_key_pair_by_label('test_certificate')
    

    if cert_info:
        private_x509_key_pem = cert_info.get('private_key_pem')
        x509_cert_pem = cert_info.get('certificate_pem')

        assert private_x509_key_pem is not None, "Private key PEM not found in X.509 key store."
        assert x509_cert_pem is not None, "Certificate PEM not found in X.509 key store."

        x509_payload = audit_core.build_x509_audit_payload(
            intermediate_audit_content_string, 
            private_x509_key_pem, 
            x509_cert_pem
        )
    else:
        logging.warning("X.509 certificate with label 'test_certificate' not found. Skipping X.509 payload.")
    
    # Concatenate all payloads into a single list
    op_return_payload_for_tx = ec_payload
    op_return_payload_for_tx.extend(x509_payload)

    # Create a new audit record entry locally.
    audit_record_entry = {
        "log_id": str(uuid.uuid4()),
        "original_audit_content": intermediate_audit_content_string,
        "timestamp_logged_local": datetime.now(timezone.utc).isoformat(),
        "blockchain_record": {
            "txid": None,
            "raw_transaction_hex": None,
            "data_hash_pushed_to_op_return": None,
            "signature_pushed_to_op_return": None,
            "public_key_pushed_to_op_return": None,
            "x509_hash_pushed": None,
            "x509_signature_pushed": None,
            "x509_certificate_pushed": None,
            "status": "pending_creation",
            "timestamp_broadcasted_utc": None,
            "timestamp_confirmed_utc": None,
            "block_hash": None,
            "block_height": None,
            "merkle_proof_data": None
        },
        "notes": "Intermediate process result audit log entry"
    }

    # Populate the audit record with the ECDSA payload data
    if ec_payload:
        audit_record_entry["blockchain_record"]["data_hash_pushed_to_op_return"] = ec_payload[1].hex()
        audit_record_entry["blockchain_record"]["signature_pushed_to_op_return"] = ec_payload[2].hex()
        audit_record_entry["blockchain_record"]["public_key_pushed_to_op_return"] = ec_payload[3].hex()
        logging.info("ECDSA payload data added to audit record.")
    
    # Populate the audit record with the X.509 payload data if it was created
    if x509_payload:
        audit_record_entry["blockchain_record"]["x509_hash_pushed"] = x509_payload[1].hex()
        audit_record_entry["blockchain_record"]["x509_signature_pushed"] = x509_payload[2].hex()
        audit_record_entry["blockchain_record"]["x509_certificate_pushed"] = x509_payload[3].hex()
        logging.info("X.509 payload data added to audit record.")
    
    
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
            tx_file_path=tx_file_path,
            note="40ps/vai"
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

        # CHANGE
        # Die alte, monolithische Verifizierungsmethode wurde durch eine neue, modulare
        # Methode ersetzt, die die gesamte Payload-Liste verarbeitet.
        logging.info(f"\n--- In-Code Payload Verification (pre-broadcast) ---")
        verification_passed = audit_core.verify_payload_integrity(
            op_return_payload_for_tx,
            intermediate_audit_content_string
        )
        logging.info(f"\nOP_RETURN Hash/Signature/Public Key Verification (pre-confirmation): { 'PASS' if verification_passed else 'FAIL' }")

    else:
        audit_record_entry["blockchain_record"]["status"] = "tx_creation_failed"
        audit_core.save_audit_log(audit_log)
        logging.error(f"\nFailed to create or broadcast transaction for audit record '{audit_record_entry['log_id']}'. Status updated.")
    
    logging.info("\nEnd log_intermediate_result_process.")

if __name__ == "__main__":
    asyncio.run(log_intermediate_result_process())
