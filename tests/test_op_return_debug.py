# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    test_op_return_debug.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

# test_op_return_debug.py

import asyncio
import json
import logging
from typing import List, Dict, Any, Optional
from typing import cast
from datetime import datetime, timezone
import uuid

# Mocks und Kopien der Originalfunktionen aus audit_core.py
# Wir kopieren diese, um eine unabhängige Testumgebung zu schaffen
from bsv import (
    PrivateKey, PublicKey,
    P2PKH,
    Transaction, TransactionInput, TransactionOutput,
    Network,
    Script,
    SatoshisPerKilobyte,
    UnlockingScriptTemplate,
    hash256
)
from bsv.hash import sha256
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

# --- Mocks für externe Abhängigkeiten ---
# Da wir ohne Netzwerk oder Dateisystem arbeiten, mocken wir diese
class MockConfig:
    ACTIVE_NETWORK_BSV = Network.TESTNET
    FEE_STRATEGY = 300
    LOGGING_UTXO_THRESHOLD = 301

# --- Logger Konfiguration für den Test ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- KOPIEN DER RELEVANTEN FUNKTIONEN AUS audit_core.py ---
# Umbenannt zur Klarheit. Abhängigkeiten wie load/save stores und API-Aufrufe
# wurden entfernt oder gemockt.

def _build_audit_payload(
    intermediate_result_data: str,
    signing_key_wif: str
) -> List[bytes]:
    """Kopie von audit_core.build_audit_payload, ohne externe Abhängigkeiten."""
    data_bytes_for_hash = intermediate_result_data.encode('utf-8')
    audit_hash = sha256(data_bytes_for_hash)
    
    private_signing_key_obj = PrivateKey(signing_key_wif, network=MockConfig.ACTIVE_NETWORK_BSV)
    public_signing_key_obj = private_signing_key_obj.public_key()
    audit_signature = private_signing_key_obj.sign(audit_hash)

    logger.info(f"\n--- Building Audit Payload (ECDSA) ---")
    logger.info(f"  Data to Hash: '{intermediate_result_data}'")
    logger.info(f"  Generated Hash: {audit_hash.hex()}")
    logger.info(f"  Signing Public Key: {public_signing_key_obj.hex()}")
    logger.info(f"  Generated Signature: {audit_signature.hex()}")

    return [
        b'E', # AUDIT_MODE_EC
        audit_hash,
        audit_signature,
        public_signing_key_obj.serialize()
    ]

def _build_x509_audit_payload(
    intermediate_result_data: str,
    private_key_pem: str,
    certificate_pem: str
) -> List[bytes]:
    """Kopie von audit_core.build_x509_audit_payload, ohne externe Abhängigkeiten."""
    logger.info("\n--- Building Audit Payload (X.509) ---")
    try:
        data_bytes_for_hash = intermediate_result_data.encode('utf-8')
        audit_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        audit_hash.update(data_bytes_for_hash)
        final_hash_bytes = audit_hash.finalize()

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'), password=None, backend=default_backend()
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("Invalid private key type: expected RSA.")

        signature = private_key.sign(
            final_hash_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        certificate_bytes = certificate_pem.encode('utf-8')

        logger.info(f"  Data to Hash: '{intermediate_result_data}'")
        logger.info(f"  Generated Hash: {final_hash_bytes.hex()}")
        logger.info(f"  Signature (truncated): {signature.hex()[:20]}...")

        return [b'X', final_hash_bytes, signature, certificate_bytes]
    except Exception as e:
        logger.error(f"Error building X.509 audit payload: {e}")
        return []
    



def _simulate_create_op_return_transaction(
        recipient_address: str,
        op_return_data_pushes: List[bytes],
        original_audit_content_string: str,
        network: Network,
) -> Optional[str]:
    """
    Simuliert die Erstellung einer Transaktion mit OP_RETURN ohne neuere SDK-Funktionen.
    """
    logger.info(f"\n--- SIMULATION: Creating OP_RETURN Transaction ---")

    # Mock-UTXOs für den Test
    mock_utxos = [
        {"txid": "e0e2e50c4c44933a3e6f9b2d3e9c933b4d4a8a68b4183d21b767d9c025d5d674", "vout": 0, "satoshis": 500000},
        {"txid": "a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6b7b8b9b0c1c2c3c4c5c6c7c8c9c0d1d2", "vout": 1, "satoshis": 500000}
    ]

    tx_inputs = []
    total_input_satoshis = 0
    priv_key_funding = PrivateKey()
    
    # Erstellen Sie eine minimale, simulierte Quelltransaktion mit zwei Ausgaben.
    source_tx_mock = Transaction()
    source_tx_mock.add_output(TransactionOutput(
        locking_script=P2PKH().lock(priv_key_funding.address()),
        satoshis=1000000
    ))
    source_tx_mock.add_output(TransactionOutput(
        locking_script=P2PKH().lock(priv_key_funding.address()),
        satoshis=1000000
    ))
    
    for utxo in mock_utxos:
        tx_inputs.append(TransactionInput(
            source_transaction=source_tx_mock,
            source_txid=utxo['txid'],
            source_output_index=utxo['vout'],
            unlocking_script_template=cast(UnlockingScriptTemplate, P2PKH().unlock(priv_key_funding))
        ))
        total_input_satoshis += utxo['satoshis']

    if not tx_inputs:
        logger.error(f"No usable UTXOs for simulation.")
        return None

    # VÖLLIG NEU: Manuelle Erstellung des OP_RETURN-Skripts mit korrekten Längen-Präfixen
    op_return_script_bytes = bytes.fromhex("6a") # 0x6a ist OP_RETURN

    for data_bytes in op_return_data_pushes:
        data_length = len(data_bytes)
        
        if data_length < 76:
            # OP_1 bis OP_75 ist der Längen-Code
            op_return_script_bytes += bytes([data_length])
        elif data_length <= 255:
            # OP_PUSHDATA1 (0x4c) gefolgt von der 1-Byte-Länge
            op_return_script_bytes += bytes.fromhex("4c") + data_length.to_bytes(1, byteorder='little')
        elif data_length <= 65535:
            # OP_PUSHDATA2 (0x4d) gefolgt von der 2-Byte-Länge
            op_return_script_bytes += bytes.fromhex("4d") + data_length.to_bytes(2, byteorder='little')
        elif data_length <= 4294967295:
            # OP_PUSHDATA4 (0x4e) gefolgt von der 4-Byte-Länge
            op_return_script_bytes += bytes.fromhex("4e") + data_length.to_bytes(4, byteorder='little')
        else:
            logger.error("Data push is too large for a valid script.")
            return None
        
        op_return_script_bytes += data_bytes
        
    op_return_script = Script(op_return_script_bytes.hex())

    tx_output_op_return = TransactionOutput(
        locking_script=op_return_script,
        satoshis=0,
        change=False
    )

    tx_output_change = TransactionOutput(
        locking_script=P2PKH().lock(recipient_address),
        satoshis=1,
        change=True
    )

    tx = Transaction(tx_inputs, [tx_output_op_return, tx_output_change])
    tx.fee(SatoshisPerKilobyte(value=MockConfig.FEE_STRATEGY))
    tx.sign()

    logger.info(f"  Simulated TXID: {tx.txid()}")
    logger.info(f"  Simulated Raw Hex: {tx.hex()}")

    return tx.hex()

def _simulate_extract_op_return_payload(raw_tx_hex: str) -> List[bytes]:
    """
    Kopie von audit_core.extract_op_return_payload, aber mit manueller Parsing-Logik.
    """
    logger.info("\n--- SIMULATION: Extracting OP_RETURN Payload from Transaction ---")
    try:
        tx = Transaction.from_hex(raw_tx_hex)
        if tx is None:
            logger.error("Error: Could not deserialize transaction hex.")
            return []

        for tx_output in tx.outputs:
            locking_script = tx_output.locking_script
            script_bytes = bytes.fromhex(locking_script.hex())

            if not script_bytes.startswith(bytes.fromhex("6a")): # OP_RETURN (0x6a)
                continue

            logger.info(f"  Found OP_RETURN output at index {tx.outputs.index(tx_output)}.")
            
            data_pushes = []
            current_index = 1 # Start nach dem OP_RETURN-Opcode (0x6a)

            while current_index < len(script_bytes):
                # Lesen des Längen-Bytes (oder Opcode)
                length_or_opcode = script_bytes[current_index]
                current_index += 1

                if 0x01 <= length_or_opcode <= 0x4b:
                    # Direkte Daten-Push (OP_1 bis OP_75)
                    data_length = length_or_opcode
                    data_push_end = current_index + data_length
                    data_pushes.append(script_bytes[current_index:data_push_end])
                    current_index = data_push_end
                elif length_or_opcode == 0x4c: # OP_PUSHDATA1
                    data_length = script_bytes[current_index]
                    current_index += 1
                    data_push_end = current_index + data_length
                    data_pushes.append(script_bytes[current_index:data_push_end])
                    current_index = data_push_end
                elif length_or_opcode == 0x4d: # OP_PUSHDATA2
                    data_length_bytes = script_bytes[current_index:current_index + 2]
                    data_length = int.from_bytes(data_length_bytes, byteorder='little')
                    current_index += 2
                    data_push_end = current_index + data_length
                    data_pushes.append(script_bytes[current_index:data_push_end])
                    current_index = data_push_end
                elif length_or_opcode == 0x4e: # OP_PUSHDATA4
                    data_length_bytes = script_bytes[current_index:current_index + 4]
                    data_length = int.from_bytes(data_length_bytes, byteorder='little')
                    current_index += 4
                    data_push_end = current_index + data_length
                    data_pushes.append(script_bytes[current_index:data_push_end])
                    current_index = data_push_end
                else:
                    logger.warning(f"  Unknown opcode or length prefix found: {hex(length_or_opcode)}. Stopping extraction.")
                    break
            
            logger.info(f"  Successfully extracted {len(data_pushes)} data pushes.")
            return data_pushes
            
        logger.warning("No OP_RETURN output found in the transaction.")
        return []

    except Exception as e:
        logger.error(f"An unexpected error occurred during payload extraction: {e}")
        return []

def test_data_flow(test_label: str, op_return_data_list: List[bytes]):
    """
    Führt einen Round-Trip-Test für eine gegebene Datenliste durch.
    """
    logger.info(f"\n===== Running Test: {test_label} =====")
    
    # 1. Simuliere die Erstellung der Raw-Transaktion
    # Wir verwenden eine leere Adresse, da wir nicht wirklich Geld senden.
    # dummy_address = "mpB5JjQ42Y3kYqB4CgX6sB1jXwQ2u5z1f"
    dummy_address = str(PrivateKey().address(network=MockConfig.ACTIVE_NETWORK_BSV))
    
    raw_tx_hex = _simulate_create_op_return_transaction(
        recipient_address=dummy_address,
        op_return_data_pushes=op_return_data_list,
        original_audit_content_string="Test data",
        network=MockConfig.ACTIVE_NETWORK_BSV
    )

    if not raw_tx_hex:
        logger.error(f"Test '{test_label}': FAILED. Transaction creation failed.")
        return

    # 2. Simuliere das Auslesen der Daten
    extracted_data_list = _simulate_extract_op_return_payload(raw_tx_hex)

    # 3. Vergleiche die ursprünglichen Daten mit den extrahierten Daten
    if extracted_data_list == op_return_data_list:
        logger.info(f"✅ Test '{test_label}': PASSED. Data matches.")
    else:
        logger.error(f"❌ Test '{test_label}': FAILED. Data mismatch.")
        logger.error(f"  Expected: {[d.hex() for d in op_return_data_list]}")
        logger.error(f"  Got:      {[d.hex() for d in extracted_data_list]}")
    
    logger.info(f"========================================\n")


async def main_test_suite():
    """
    Führt die gesamte Test-Suite durch, um das Problem schrittweise zu isolieren.
    """
    # Testfall 1: Kleines Payload (<75 bytes)
    small_payload = [b'Hello World!', b'Another short string.']
    test_data_flow("Small Payload Test (<75 Bytes)", small_payload)

    # Testfall 2: Payload > 75 bytes, sollte OP_PUSHDATA1 verwenden
    large_string = "a" * 80 # 80 Bytes
    large_payload = [b'Start', large_string.encode('utf-8'), b'End']
    test_data_flow("Medium Payload Test (>75 Bytes)", large_payload)

    # Testfall 3: Payload > 255 bytes, sollte OP_PUSHDATA2 verwenden
    very_large_string = "b" * 300 # 300 Bytes
    very_large_payload = [b'Start', very_large_string.encode('utf-8'), b'End']
    test_data_flow("Large Payload Test (>255 Bytes)", very_large_payload)

    # Testfall 4: Test mit Ihrer ursprünglichen Payload-Struktur (ECDSA + X.509 + Note)
    # Mocken wir eine X.509-Payload. Normalerweise käme dies aus einem Manager.
    # Wir brauchen einen realistischen PEM-String, um die Funktionalität zu testen.
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        # Generiere einen Mock-Schlüssel und ein Zertifikat
        mock_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        mock_private_key_pem = mock_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        mock_cert_pem = (b'-----BEGIN CERTIFICATE-----\n'
                         b'MII... (truncated for brevity) ...\n'
                         b'-----END CERTIFICATE-----').decode('utf-8')

        original_content = "This is a comprehensive test for all payload types."
        
        test_wif = PrivateKey().wif()
        ec_payload_part = _build_audit_payload(original_content, test_wif) 
     
        x509_payload_part = _build_x509_audit_payload(original_content, mock_private_key_pem, mock_cert_pem)
        
        # Manuelle Erstellung der Payload, wie sie in main_audit_log_event.py
        # geschieht.
        full_complex_payload = []
        full_complex_payload.extend(ec_payload_part)
        full_complex_payload.extend(x509_payload_part)

        # Die Notiz "40ps/vai" wird manuell als separater Daten-Push hinzugefügt
        full_complex_payload.extend([b'N', "40ps/vai".encode('utf-8')])
        
        test_data_flow("Complex Payload Test (ECDSA+X.509+Note)", full_complex_payload)
    
    except ImportError:
        logger.error("Skipping complex payload test: 'cryptography' library not installed.")


if __name__ == "__main__":
    asyncio.run(main_test_suite())