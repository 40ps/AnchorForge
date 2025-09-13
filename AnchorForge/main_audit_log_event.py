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
import os
import sys
import portalocker
from portalocker import LOCK_EX

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

async def log_intermediate_result_process(data_source: str|None = None):
    """
    Orchestrates the process of creating and broadcasting an audit record
    in a single, atomic file-locking operation.
    """
    logging.info(f"\n--- Starting Audit Log Process ---")

    # --- Block 1: Datenquelle bestimmen (Ihre Logik, unverändert) ---
    intermediate_audit_content_string = ""
    note_content = ""
    if data_source is None:
        timestamp_str = datetime.now(timezone.utc).isoformat()
        intermediate_audit_content_string = f"Audit Log Entry: Process step completed at {timestamp_str}. Result: SUCCESS. [Germany Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"
        note_content = "Default Test Entry"
    elif os.path.isfile(data_source):
        try:
            with open(data_source, 'r', encoding='utf-8') as f:
                file_content = f.read()
            intermediate_audit_content_string = file_content
            note_content = file_content
        except Exception as e:
            logging.error(f"Could not read file '{data_source}': {e}")
            return
    else:
        intermediate_audit_content_string = data_source
        note_content = "Content from direct string input"
    
    logging.info(f"\n--- New Audit Content ---")
    logging.info(f"  Content to be logged: '{intermediate_audit_content_string[:200]}...'")

    # --- Block 2: Dateipfade vorbereiten (unverändert) ---
    priv_key_funding = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
    sender_address = priv_key_funding.address()
    utxo_file_path = wallet_manager._get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME)
    tx_file_path = wallet_manager._get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME).replace("utxo_store", "tx_store")
    used_utxo_file_path = wallet_manager._get_filename_for_address(str(sender_address), Config.ACTIVE_NETWORK_NAME).replace("utxo_store", "used_utxo_store")

    # --- Block 3: Atomare Operation: Sperren, Laden, Verarbeiten, Speichern ---
    try:
        # order is important
        with portalocker.Lock(Config.AUDIT_LOG_FILE, "r+", flags=LOCK_EX, timeout=5) as f_audit, \
             portalocker.Lock(tx_file_path, "r+", flags=LOCK_EX, timeout=5) as f_tx, \
             portalocker.Lock(used_utxo_file_path, "r+", flags=LOCK_EX, timeout=5) as f_used, \
             portalocker.Lock(utxo_file_path, "r+", flags=LOCK_EX, timeout=5) as f_utxo:

            # 1. load all stores securely
            audit_log = audit_core.load_audit_log(f_audit)
            tx_store = wallet_manager.load_tx_store(f_tx)
            used_store = wallet_manager.load_used_utxo_store(f_used)
            store = wallet_manager.load_utxo_store(f_utxo)
  

            # 2. Payloads und Audit-Record im Speicher erstellen
            assert Config.PRIVATE_SIGNING_KEY_WIF is not None
            ec_payload = audit_core.build_audit_payload(intermediate_audit_content_string, Config.PRIVATE_SIGNING_KEY_WIF)
            
            x509_payload = []
            x509_key_label = 'anchor_test_certificate' if Config.ACTIVE_NETWORK_NAME == "test" else 'anchor_main_certificate'
            cert_info = key_x509_manager.get_x509_key_pair_by_label(x509_key_label)
            
            if cert_info:
                private_x509_key_pem = cert_info.get('private_key_pem')
                x509_cert_pem = cert_info.get('certificate_pem')
                if private_x509_key_pem and x509_cert_pem:
                    x509_payload = audit_core.build_x509_audit_payload(intermediate_audit_content_string, private_x509_key_pem, x509_cert_pem)

            op_return_payload_for_tx = ec_payload + x509_payload
            
            # Temporärer Audit-Record im Speicher
            audit_record_entry = {
                "log_id": str(uuid.uuid4()),
                "original_audit_content": intermediate_audit_content_string,
                "timestamp_logged_local": datetime.now(timezone.utc).isoformat(),
                "blockchain_record": {
                    "txid": None, "raw_transaction_hex": None, "status": "pending_creation",
                    "data_hash_pushed_to_op_return": ec_payload[1].hex() if ec_payload else None,
                    "signature_pushed_to_op_return": ec_payload[2].hex() if ec_payload else None,
                    "public_key_pushed_to_op_return": ec_payload[3].hex() if ec_payload else None,
                    "x509_hash_pushed": x509_payload[1].hex() if x509_payload else None,
                    "x509_signature_pushed": x509_payload[2].hex() if x509_payload else None,
                    "x509_certificate_pushed": x509_payload[3].decode('utf-8') if x509_payload else None,
                }, "notes": "Intermediate process result audit log entry"
            }
            
            # 3. Create Transaction
            assert Config.UTXO_STORE_KEY_WIF is not None, "UTXO_STORE_KEY_WIF is none"
            tx_hex_returned, broadcast_timestamp_str, broadcast_txid, \
            consumed_utxos_details, new_utxos_details = await audit_core.create_op_return_transaction(
                spending_key_wif=Config.UTXO_STORE_KEY_WIF, 
                recipient_address=str(sender_address),
                op_return_data_pushes=op_return_payload_for_tx,
                original_audit_content_string=intermediate_audit_content_string,
                network=Config.ACTIVE_NETWORK_BSV,
                current_utxo_store_data=store,
                tx_store=tx_store,
                f_tx_store=f_tx, # Dateihandle wird jetzt korrekt übergeben
                note=note_content
            )

            # 4. Wenn Transaktion erfolgreich, alle Änderungen in die Stores schreiben
            if tx_hex_returned and broadcast_txid:
                logging.info(f"Transaction created & broadcasted: {broadcast_txid}")
                
                # Audit-Record aktualisieren und zur Log-Liste hinzufügen
                audit_record_entry["blockchain_record"].update({
                    "txid": broadcast_txid,
                    "raw_transaction_hex": tx_hex_returned,
                    "status": "broadcasted",
                    "timestamp_broadcasted_utc": broadcast_timestamp_str
                })
                audit_log.append(audit_record_entry)

                # UTXO-Stores aktualisieren
                for consumed_utxo in consumed_utxos_details:
                    store["utxos"] = [u for u in store["utxos"] if not (u["txid"] == consumed_utxo["txid"] and u["vout"] == consumed_utxo["vout"])]
                    consumed_utxo.update({"used": True, "used_in_txid": broadcast_txid, "used_timestamp": datetime.now(timezone.utc).isoformat()})
                    used_store["used_utxos"].append(consumed_utxo)
                
                store["utxos"].extend(new_utxos_details)
                
                # 5. Alle geänderten Stores sicher zurückschreiben
                wallet_manager.save_utxo_store(f_utxo, store)
                wallet_manager.save_used_utxo_store(f_used, used_store)
                audit_core.save_audit_log(f_audit, audit_log)
                
                logging.info("All local stores updated successfully.")
            
            else:
                # Transaktion fehlgeschlagen, nur den fehlgeschlagenen Audit-Record speichern
                audit_record_entry["blockchain_record"]["status"] = "tx_creation_failed"
                audit_log.append(audit_record_entry)
                audit_core.save_audit_log(f_audit, audit_log)
                logging.error(f"Failed to create transaction for audit record '{audit_record_entry['log_id']}'.")

    except portalocker.exceptions.LockException as e:
        logging.error(f"Could not acquire lock for processing, another process might be running: {e}")

    logging.info("\n--- Finished Audit Log Process ---")

if __name__ == "__main__":
    # Prüfen, ob ein Kommandozeilenargument (der Dateiname) übergeben wurde
    if len(sys.argv) > 1:
        # Das erste Argument (sys.argv[1]) wird als Dateiname verwendet
        file_name = sys.argv[1]
        logging.info(f"Received file '{file_name}' from command line as data source.")
        # Rufen Sie den Prozess mit dem Dateinamen auf
        asyncio.run(log_intermediate_result_process(data_source=file_name))
    else:
        # Wenn kein Argument übergeben wird, das Standardverhalten (Dummy-Text) ausführen
        logging.info("No command line argument provided, running with default (timestamp) data.")
        asyncio.run(log_intermediate_result_process())
