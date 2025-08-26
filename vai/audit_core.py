# audit_core.py

import asyncio
import json
from typing import List, Dict, Any, Optional
from typing import cast
from datetime import datetime, timezone
import uuid # for generating unique identifiers
import logging

from config import Config
import blockchain_api
import blockchain_service
from block_manager import BlockHeaderManager
import wallet_manager
import utils

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

from bsv.hash import sha256 # Import sha256 function directly from bsv.hash module

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

# --- AUDIT MODE CONSTANTS FOR SELF-DESCRIBING PAYLOADS ---
# These single-byte identifiers are a key component of the new, flexible
# payload structure, allowing the verifier to know which type of signature
# to expect for each data triplet.
AUDIT_MODE_EC = b'E' # 'E' for Elliptic Curve Digital Signature Algorithm (ECDSA)
AUDIT_MODE_X509 = b'X' # 'X' for X.509 Certificate
# CHANGE
# New constant for a generic note payload.
AUDIT_MODE_NOTE = b'N' # 'N' for a Note or a comment.

def load_audit_log() -> List[Dict]:
    """
    Loads audit records from the audit log JSON file.
    """
    try:
        with open(Config.AUDIT_LOG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # The audit log is a list of records, so it starts empty if the file doesn't exist.
        return []

def save_audit_log(audit_records: List[Dict]):
    """
    Saves audit records to the audit log JSON file.
    """
    with open(Config.AUDIT_LOG_FILE, 'w') as f:
        json.dump(audit_records, f, indent=4)


def print_op_return_scriptpubkey(script: Script):
    """
    Prints a human-readable form of the OP_RETURN scriptPubKey.
    It iterates through the script chunks to identify and display
    OP_RETURN and the data pushes.

    Args:
        script (Script): The Script object of the OP_RETURN output.
    """
    logger.info("\n--- OP_RETURN ScriptPubkey Details ---")
    
    if script is None:
        logger.error("Error: The script object passed to print_op_return_scriptpubkey is None.")
        return
    
    if not hasattr(script, 'chunks') or not script.chunks:
        logger.error("Error: The script object has no chunks or an empty chunks list.")
        return

    first_chunk_op_raw = script.chunks[0].op
    
    if isinstance(first_chunk_op_raw, bytes):
        if len(first_chunk_op_raw) == 1:
            first_chunk_op_int = first_chunk_op_raw[0]
        else:
            logger.warning(f"Warning: Unexpected multi-byte opcode representation: {first_chunk_op_raw.hex()}")
            first_chunk_op_int = -1
    elif isinstance(first_chunk_op_raw, int):
        first_chunk_op_int = first_chunk_op_raw
    else:
        logger.warning(f"Warning: Unexpected type for opcode: {type(first_chunk_op_raw)}. Value: {first_chunk_op_raw}")
        first_chunk_op_int = -1

    logger.debug(f"Debug: First script chunk opcode (int value): {first_chunk_op_int}")
    logger.debug(f"Debug: First script chunk opcode (hex value): {hex(first_chunk_op_int) if first_chunk_op_int != -1 else 'N/A'}")
    
    if first_chunk_op_int != 0x6a: # 0x6a is OP_RETURN, now comparing with an int
        logger.warning("This is not an OP_RETURN script. First opcode is not OP_RETURN.")
        return

    logger.info(f"Full Script (ASM): {script.to_asm()}")
    logger.info(f"Full Script (Hex): {script.hex()}")

    logger.info("OP_RETURN Data Elements:")
    for i, chunk in enumerate(script.chunks[1:]):
        if chunk.data is not None: # It's a data push
            try:
                # Try to decode as UTF-8, if not, print hex
                decoded_data = chunk.data.decode('utf-8')
                logger.info(f"  Element {i+1}: (Text) '{decoded_data}' (Hex: {chunk.data.hex()})")
            except UnicodeDecodeError:
                logger.info(f"  Element {i+1}: (Raw Hex) {chunk.data.hex()} (Length: {len(chunk.data)} bytes)")
        else:
            chunk_op_raw_inner = chunk.op
            if isinstance(chunk_op_raw_inner, bytes) and len(chunk_op_raw_inner) == 1:
                chunk_op_int_inner = chunk_op_raw_inner[0]
            elif isinstance(chunk_op_raw_inner, int):
                chunk_op_int_inner = chunk_op_raw_inner
            else:
                chunk_op_int_inner = -1 # Unknown
            
            if chunk_op_int_inner != -1:
                logger.info(f"  Element {i+1}: (Opcode) {hex(chunk_op_int_inner)} (Not data)")
            else:
                logger.info(f"  Element {i+1}: (Unexpected Opcode format) {chunk_op_raw_inner}")

   
def verify_merkle_path(txid: str, index: int, nodes: List[str], target: str) -> bool:
    """
    Verifies if a TxID is included in a block based on the Merkle path.
    
    Args:
        txid (str): The transaction ID (hex, Big-Endian).
        index (int): The index of the transaction in the Merkle tree.
        nodes (List[str]): List of hashes in the Merkle path (hex, Big-Endian).
        target (str): The expected Merkle root (hex, Big-Endian).
    
    Returns:
        bool: True if the transaction is included in the block, otherwise False.
    """
    try:
        current_hash = bytes.fromhex(txid)[::-1]
        logger.info(f"Starting hash (TxID, Little-Endian): {current_hash.hex()}")

        # Verarbeite den Merkle-Pfad
        current_index = index
        for i, node in enumerate(nodes):
            node_hash = bytes.fromhex(node)[::-1]
            logger.info(f"Node {i+1} (Little-Endian): {node_hash.hex()}")

            # Entscheide, ob der aktuelle Hash links oder rechts im Baum steht
            if current_index % 2 == 0:
                combined = current_hash + node_hash
            else:
                combined = node_hash + current_hash
            logger.debug(f"Combined hash: {combined.hex()}")

            # Berechne den doppelten SHA256-Hash
            current_hash = hash256(combined)
            logger.debug(f"New hash after hash256 (Little-Endian): {current_hash.hex()}")

            current_index //= 2  # Gehe eine Ebene höher im Baum

        # Konvertiere die berechnete Merkle-Root in Big-Endian für den Vergleich
        calculated_root = current_hash[::-1].hex()
        logger.info(f"Calculated Merkle Root (Big-Endian): {calculated_root}")
        logger.info(f"Target Merkle Root (Big-Endian): {target}")
        return calculated_root == target
    except ValueError as e:
        logger.error(f"Error processing hex data: {e}")
        return False


# --- Builders ---

def build_audit_payload(
    intermediate_result_data: str, # Or Dict, or custom Object, depending on your data
    signing_key_wif: str
) -> List[bytes]:
    """
    Builds the OP_RETURN payload (mode, hash, signature, public key) for an audit record.

    Args:
        intermediate_result_data (str): The human-readable intermediate result to be logged.
                                        This will be hashed.
        signing_key_wif (str): The WIF of the private key used to sign the hash.

    Returns:
        List[bytes]: A list containing the mode (bytes), hash (bytes), signature (bytes),
                     and public key (bytes) ready for OP_RETURN.
    """
    # Convert input data to bytes for hashing
    data_bytes_for_hash = intermediate_result_data.encode('utf-8')
    audit_hash = sha256(data_bytes_for_hash)
    
    # Perform signing
    private_signing_key_obj = PrivateKey(signing_key_wif, network=Config.ACTIVE_NETWORK_BSV)
    public_signing_key_obj = private_signing_key_obj.public_key()
    audit_signature = private_signing_key_obj.sign(audit_hash)

    logger.info(f"\n--- Building Audit Payload (ECDSA) ---")
    logger.info(f"  Data to Hash: '{intermediate_result_data}'")
    logger.info(f"  Generated Hash: {audit_hash.hex()}")
    logger.info(f"  Signing Public Key: {public_signing_key_obj.hex()}")
    logger.info(f"  Generated Signature: {audit_signature.hex()}")

    if public_signing_key_obj.verify(audit_signature, audit_hash):
        logger.info("  Initial Signature Verification (Payload Build): PASS")
    else:
        logger.error("  Initial Signature Verification (Payload Build): FAIL")
        # You might want to raise an error here if verification fails

    # Return the payload as a list of bytes, prepending the mode byte
    return [
        AUDIT_MODE_EC,
        audit_hash,
        audit_signature, # Ensure Signature object is converted to bytes
        public_signing_key_obj.serialize() # Ensure PublicKey object is converted to bytes
    ]

def build_x509_audit_payload(
    intermediate_result_data: str,
    private_key_pem: str,
    certificate_pem: str
) -> List[bytes]:
    """
    Builds the OP_RETURN payload (mode, hash, signature, x.509 certificate) for an audit record.

    This function hashes the provided data, signs it with the private key from a
    given X.509 certificate, and returns the hash, the signature, and the full certificate
    as a list of byte strings, ready for an OP_RETURN transaction.

    Args:
        intermediate_result_data (str): The human-readable intermediate result to be logged.
                                        This will be hashed.
        private_key_pem (str): The private key in PEM format.
        certificate_pem (str): The self-signed X.509 certificate in PEM format.

    Returns:
        List[bytes]: A list containing the mode (bytes), hash (bytes), signature (bytes),
                     and certificate (bytes) ready for OP_RETURN.
    """
    logger.info("\n--- Building Audit Payload (X.509) ---")

    try:
        # 1. Convert input data to bytes for hashing
        data_bytes_for_hash = intermediate_result_data.encode('utf-8')
        audit_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        audit_hash.update(data_bytes_for_hash)
        final_hash_bytes = audit_hash.finalize()
        
        # 2. Load the private key for signing
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Check if the key is an RSA key instance
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError(f"Invalid private key type: expected RSA, got {type(private_key).__name__}. The sign method with PSS padding is only available for RSA keys.")

        # 3. Sign the hash using the private key
        signature = private_key.sign(
            final_hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # 4. Convert certificate PEM string to bytes
        certificate_bytes = certificate_pem.encode('utf-8')
        
        logger.info(f"  Data to Hash: '{intermediate_result_data}'")
        logger.info(f"  Generated Hash: {final_hash_bytes.hex()}")
        logger.info(f"  Signature (truncated): {signature.hex()[:20]}...")
        
        # 5. Verify the signature locally before returning
        try:
            public_key = private_key.public_key()
            public_key.verify(
                signature,
                final_hash_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logger.info("  Initial Signature Verification (Payload Build): PASS")
        except Exception as e:
            logger.error(f"  Initial Signature Verification (Payload Build): FAIL - {e}")

        # 6. Return the payload as a list of bytes, prepending the mode byte
        return [
            AUDIT_MODE_X509,
            final_hash_bytes,
            signature,
            certificate_bytes
        ]
        
    except Exception as e:
        logger.error(f"Error building X.509 audit payload: {e}")
        return []

def verify_payload_integrity(payload_pushes: List[bytes], original_content: str) -> bool:
    """
    Verifies the integrity of a series of payloads by iterating through them
    and delegating verification to the appropriate specialized functions.

    This function acts as a central dispatcher for the in-code verification
    before a transaction is broadcasted. It is a robust replacement for the
    legacy, monolithic verification function.

    Args:
        payload_pushes (List[bytes]): The list of byte strings representing all
                                     data pushes in the OP_RETURN script.
        original_content (str): The original content string that was hashed and signed.

    Returns:
        bool: True if all payloads are valid, False otherwise.
    """
    logger.info("\n  --- Verifying Payload Integrity (In-Code Dispatcher) ---")
    current_index = 0
    payloads_ok = True
    
    while current_index < len(payload_pushes):
        mode_byte = payload_pushes[current_index]

        if mode_byte == AUDIT_MODE_EC:
            if len(payload_pushes) < current_index + 4:
                logger.error("  Payload Integrity Check: FAIL. Incomplete ECDSA payload found.")
                payloads_ok = False
                break
            payload_triplet = payload_pushes[current_index : current_index + 4]
            if not verify_ec_payload(payload_triplet, original_content):
                payloads_ok = False
            current_index += 4
        
        elif mode_byte == AUDIT_MODE_X509:
            if len(payload_pushes) < current_index + 4:
                logger.error("  Payload Integrity Check: FAIL. Incomplete X.509 payload found.")
                payloads_ok = False
                break
            payload_triplet = payload_pushes[current_index : current_index + 4]
            if not verify_x509_payload(payload_triplet, original_content):
                payloads_ok = False
            current_index += 4
        
        elif mode_byte == AUDIT_MODE_NOTE:
            if len(payload_pushes) < current_index + 2:
                logger.error("  Payload Integrity Check: FAIL. Incomplete note payload found.")
                payloads_ok = False
                break
            note_payload = payload_pushes[current_index : current_index + 2]
            try:
                # We can't verify the note itself, just that it's a valid string.
                decoded_note = note_payload[1].decode('utf-8')
                logger.info(f"  Note found and verified (format only): '{decoded_note}'")
            except UnicodeDecodeError:
                logger.error("  Payload Integrity Check: FAIL. Could not decode note as UTF-8.")
                payloads_ok = False
            current_index += 2

        else:
            logger.error(f"  Payload Integrity Check: FAIL. Unknown mode byte found: {mode_byte}.")
            payloads_ok = False
            break
            
    if not payloads_ok:
        logger.error("  Payload Integrity Check: OVERALL FAIL.")
        return False
    
    logger.info("  Payload Integrity Check: OVERALL PASS.")
    return True

def extract_op_return_payload_false_25_08_26(raw_tx_hex: str) -> List[bytes]:
    """
    Extracts all data pushes from the first OP_RETURN output in a raw transaction.

    This function deserializes a raw transaction and searches for the first output
    that contains an OP_RETURN opcode. It then extracts all subsequent data pushes
    and returns them as a list of byte strings. It does not perform any
    verification of the data itself.

    Args:
        raw_tx_hex (str): The raw transaction in hexadecimal string format.

    Returns:
        List[bytes]: A list of byte strings representing the data pushes in the
                     OP_RETURN script. Returns an empty list if no OP_RETURN
                     output is found or an error occurs.
    """
    logger.info("\n--- Extracting OP_RETURN Payload from Transaction ---")
    try:
        tx = Transaction.from_hex(raw_tx_hex)
        if tx is None:
            logger.error("Error: Could not deserialize transaction hex.")
            return []

        for tx_output in tx.outputs:
            locking_script = tx_output.locking_script
            
            # CHANGE: Log the script hex to debug parsing issues.
            logger.info(f"  Checking output script (hex): {locking_script.hex()}")

            # Check for the OP_RETURN opcode (0x6a) at the beginning of the script
            if locking_script.chunks and locking_script.chunks[0].op == 0x6a:
                logger.info(f"  Found OP_RETURN output at index {tx.outputs.index(tx_output)}.")
                
                # Extract all data chunks after the OP_RETURN opcode
                # The .data attribute of the chunk contains the actual bytes pushed
                data_pushes = [chunk.data for chunk in locking_script.chunks[1:] if chunk.data is not None]
                
                logger.info(f"  Successfully extracted {len(data_pushes)} data pushes.")
                return data_pushes
                
        logger.warning("No OP_RETURN output found in the transaction.")
        return []

    except Exception as e:
        logger.error(f"An unexpected error occurred during payload extraction: {e}")
        return []



def extract_op_return_payload_correct_25_08_25(raw_tx_hex: str) -> List[bytes]:
    """
    Extracts all data pushes from the first OP_RETURN output in a raw transaction.
    This corrected version manually parses the script bytes to correctly handle
    all OP_PUSHDATA opcodes, fixing the bug in older bsv-sdk versions.

    Args:
        raw_tx_hex (str): The raw transaction in hexadecimal string format.

    Returns:
        List[bytes]: A list of byte strings representing the data pushes in the
                     OP_RETURN script. Returns an empty list if no OP_RETURN
                     output is found or an error occurs.
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

def extract_op_return_payload(raw_tx_hex: str) -> List[bytes]:
    return extract_op_return_payload_correct_25_08_25(raw_tx_hex)

def verify_ec_payload(payload: List[bytes], original_content: str) -> bool:
    """
    Verifies a single ECDSA audit payload triplet.

    Args:
        payload (List[bytes]): The list of byte strings representing the payload (mode, hash, signature, public key).
        original_content (str): The original content string that was hashed and signed.

    Returns:
        bool: True if the verification passes, False otherwise.
    """
    logger.info("  --- Verifying ECDSA Payload ---")
    if len(payload) != 4 or payload[0] != AUDIT_MODE_EC:
        logger.error("  Invalid ECDSA payload format or missing mode byte.")
        return False
    
    # Extract data from the payload (skipping the mode byte)
    extracted_hash_bytes, extracted_signature_bytes, extracted_public_key_bytes = payload[1:]

    # 1. Compare the hash
    computed_original_hash = sha256(original_content.encode('utf-8'))
    if computed_original_hash != extracted_hash_bytes:
        logger.error(f"  Hash comparison: FAIL (Expected: {computed_original_hash.hex()}, Got: {extracted_hash_bytes.hex()})")
        return False
    logger.info("  Hash comparison: PASS")
    
    # 2. Verify the signature
    try:
        pub_key = PublicKey(extracted_public_key_bytes)
        if pub_key.verify(extracted_signature_bytes, extracted_hash_bytes):
            logger.info("  Signature verification: PASS")
            return True
        else:
            logger.error("  Signature verification: FAIL")
            return False
    except Exception as e:
        logger.error(f"  Error during signature verification: {e}")
        return False


def verify_x509_payload(payload: List[bytes], original_content: str) -> bool:
    """
    Verifies a single X.509 audit payload triplet.

    Args:
        payload (List[bytes]): The list of byte strings representing the payload (mode, hash, signature, certificate).
        original_content (str): The original content string that was hashed and signed.

    Returns:
        bool: True if the verification passes, False otherwise.
    """
    logger.info("  --- Verifying X.509 Payload ---")
    if len(payload) != 4 or payload[0] != AUDIT_MODE_X509:
        logger.error("  Invalid X.509 payload format or missing mode byte.")
        return False

    # Extract data from the payload (skipping the mode byte)
    extracted_hash_bytes, extracted_signature_bytes, extracted_certificate_bytes = payload[1:]

    # 1. Compare the hash
    computed_original_hash = sha256(original_content.encode('utf-8'))
    if computed_original_hash != extracted_hash_bytes:
        logger.error(f"  Hash comparison: FAIL (Expected: {computed_original_hash.hex()}, Got: {extracted_hash_bytes.hex()})")
        return False
    logger.info("  Hash comparison: PASS")

    # 2. Load the certificate and extract the public key
    public_key = None # Initialize public_key to None
    try:
        cert = x509.load_pem_x509_certificate(extracted_certificate_bytes, default_backend())
        public_key = cert.public_key()
        
        # Check if the extracted public key is an RSA key
        if not isinstance(public_key, rsa.RSAPublicKey):
            logger.error(f"  Invalid public key type for X.509 verification: expected RSA, got {type(public_key).__name__}")
            return False
        
        logger.info("  Certificate loaded and RSA public key extracted.")
    except Exception as e:
        logger.error(f"  Error loading X.509 certificate: {e}")
        return False # The verification fails if the certificate cannot be loaded

    # 3. Verify the signature
    try:
        public_key.verify(
            extracted_signature_bytes,
            extracted_hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        logger.info("  Signature verification: PASS")
        return True
    except Exception as e:
        logger.error(f"  Signature verification: FAIL - {e}")
        return False


# audit_core.py

async def create_op_return_transaction(
        spending_key_wif: str,
        recipient_address: str, 
        op_return_data_pushes: List[bytes],
        original_audit_content_string: str,
        network: Network,
        utxo_file_path: str,
        tx_file_path: str,
        note: Optional[str] = None
) -> tuple[Optional[str], Optional[str], Optional[str], List[Dict], List[Dict]]:
    """
    Creates a Bitcoin SV transaction with an OP_RETURN output and returns change.

    Args:
        spending_key_wif (str): The WIF of the private key used to fund the transaction.
        recipient_address (str): The address to send change to (or a small payment if included).
        op_return_data_pushes (List[bytes]): List of byte strings to be pushed into OP_RETURN.
        original_audit_content_string (Str): The original string content for internal verification/hashing.
        network (Network): The bsv.Network object for the transaction.
        utxo_file_path (str): The file path for the UTXO store.
        tx_file_path (str): The file path for the transaction store.
        note (Optional[str]): An optional note to be added as a fourth data push to OP_RETURN.
    
    Returns:
         tuple[str | None, str | None, str | None, List[Dict], List[Dict]]:
            Now returns (raw_tx_hex, timestamp_broadcasted, txid, consumed_utxos_details, new_utxos_details).
    """
    logger.info(f"\n--- Creating OP_RETURN Transaction from {recipient_address} ---")
    
    # 1. Load local stores here, as this function manages their state updates.
    current_utxo_store_data = wallet_manager.load_utxo_store(utxo_file_path)
    tx_store = wallet_manager.load_tx_store(tx_file_path)

    available_utxos = [utxo for utxo in current_utxo_store_data["utxos"] if not utxo["used"] and utxo["satoshis"] >= Config.FEE_STRATEGY * 5]
    if not available_utxos:
        logger.error(f"No suitable UTXOs available for {recipient_address} to cover fees. Please fund the address.")
        return None, None, None, [], []

    # 2. prepare transaction inputs from all available UTXO until sufficient funds
    tx_inputs = []
    total_input_satoshis = 0
    consumed_utxos_details = []
    priv_key = PrivateKey(spending_key_wif, network)

    for utxo in available_utxos:
        
        # emergency solution: raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(utxo['txid'])

        # Retrieve rawtx for the selected UTXO's txid from tx_store
        raw_source_tx_hex = None
        for tx_entry in tx_store["transactions"]:
            if tx_entry["txid"] == utxo['txid']:
                raw_source_tx_hex = tx_entry['rawtx']
                break

        if raw_source_tx_hex is None:
            logger.warning(f"Warning: Raw transaction for UTXO {utxo['txid']} not in cache. Fetching from network.")
            raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(utxo['txid'])
            if raw_source_tx_hex:
                tx_store["transactions"].append({
                    "txid": utxo['txid'], 
                    "rawtx": raw_source_tx_hex,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                wallet_manager.save_tx_store(tx_store, tx_file_path)
            else:
                logger.warning(f"Skipping UTXO {utxo['txid']}:{utxo['vout']} due to failure to get source transaction hex.")
                continue 
        
        if raw_source_tx_hex == "0": 
            logger.warning(f"Raw transaction data for txid {utxo['txid']} is placeholder '0', cannot use for signing. Skipping.")
            continue
        
        source_tx_obj = Transaction.from_hex(raw_source_tx_hex)
        
        tx_inputs.append(TransactionInput(
            source_transaction=source_tx_obj,
            source_txid=utxo['txid'],
            source_output_index=utxo['vout'],
            unlocking_script_template=cast(UnlockingScriptTemplate, P2PKH().unlock(priv_key))
        ))
        total_input_satoshis += utxo['satoshis']
        consumed_utxos_details.append(utxo)

        # Only ask for sufficient UTXOs, ignore all others
        if total_input_satoshis >= Config.LOGGING_UTXO_THRESHOLD:
            break

    if not tx_inputs:
        logger.warning(f"No usable UTXOs found for address {recipient_address} after fetching source transactions. Cannot create transaction.")
        return None, None, None, [], []
    
    logger.info(f"  Attempting to create transaction for content: '{original_audit_content_string}'")

    # 3. Create the OP_RETURN output with correct OP_PUSHDATA logic
    op_return_script_bytes = bytes.fromhex("6a") # OP_RETURN (0x6a)

    for data_bytes in op_return_data_pushes:
        data_length = len(data_bytes)
        
        if data_length < 76:
            op_return_script_bytes += bytes([data_length])
        elif data_length <= 255:
            op_return_script_bytes += bytes.fromhex("4c") + data_length.to_bytes(1, byteorder='little')
        elif data_length <= 65535:
            op_return_script_bytes += bytes.fromhex("4d") + data_length.to_bytes(2, byteorder='little')
        elif data_length <= 4294967295:
            op_return_script_bytes += bytes.fromhex("4e") + data_length.to_bytes(4, byteorder='little')
        else:
            logger.error("Data push is too large for a valid script.")
            return None, None, None, [], []
        
        op_return_script_bytes += data_bytes
    
    # Add optional note if it exists
    if note:
        note_bytes = note.encode('utf-8')
        op_return_script_bytes += bytes.fromhex("014e") # Mode byte (N) plus length byte
        op_return_script_bytes += bytes([len(note_bytes)])
        op_return_script_bytes += note_bytes
    
    op_return_script = Script(op_return_script_bytes.hex())
    
    logger.info(f"OP_RETURN script (Hex): {op_return_script.hex()}")
    
    print_op_return_scriptpubkey(op_return_script) 

    tx_output_op_return = TransactionOutput(
        locking_script=op_return_script,
        satoshis=0, # OP_RETURN outputs are unspendable and have 0 value
        change=False 
    )

    # 4. Create the change output back to the sender
    tx_output_change = TransactionOutput(
        locking_script=P2PKH().lock(recipient_address),
        satoshis=1, # Dummy value, bsv-sdk overwrites is with actual change
        change=True # Mark as change output for automatic fee calculation
    )

    # 5. Assemble the transaction
    tx = Transaction(tx_inputs, [tx_output_op_return, tx_output_change])

    logger.info("\n--- DEBUG: Transaction Outputs IMMEDIATELY after assembly ---")
    if not tx.outputs:
        logger.info("    No outputs found in transaction immediately after assembly.")
    else:
        for i, output in enumerate(tx.outputs):
            is_op_return_flag = " (OP_RETURN)" if output.locking_script.chunks and output.locking_script.chunks[0].op == 0x6a else ""
            logger.info(f"    Output {i}: Satoshis={output.satoshis}, Script ASM={output.locking_script.to_asm()}{is_op_return_flag}")
    logger.info("------------------------------------------------------------")

    tx.fee(SatoshisPerKilobyte(value=Config.FEE_STRATEGY)) 

    # After tx.fee() has been called, retrieve the fee by summing inputs and subtracting outputs.
    # This is the most reliable way to get the *actual* fee determined by the SDK.
    total_output_satoshis = sum(output.satoshis for output in tx.outputs)
    calculated_fee = total_input_satoshis - total_output_satoshis
    
    logger.info(f"Total Input Satoshis: {total_input_satoshis}")
    logger.info(f"Total Output Satoshis (including OP_RETURN and change): {total_output_satoshis}")
    logger.info(f"Calculated Fee for new transaction: {calculated_fee} satoshis")
    
    # Check if there are enough funds for the OP_RETURN output (0 satoshis) + fee
    # And critically, if there's enough for a reasonable change output.
    # The SDK handles the change output automatically, so we just need to ensure inputs cover it.
    if total_input_satoshis < calculated_fee:
        logger.error(f"Insufficient funds for transaction. Total inputs: {total_input_satoshis}, required for fee: {calculated_fee}.")
        return None, None, None, [], []
    
    change_output_satoshis = tx_output_change.satoshis
    if change_output_satoshis < 1 and change_output_satoshis != 0: 
        logger.warning(f"Warning: Calculated change output ({change_output_satoshis} satoshis) is too low. It might be discarded by miners or not be a valid UTXO.")

    tx.sign()

    logger.info(f"New Transaction ID: {tx.txid()}")
    logger.info(f"New Transaction Raw Hex: {tx.hex()}")

    logger.info(f"Adding raw transaction {tx.txid()} to tx_store (UTXO cache)...")
    tx_store["transactions"].append({
            "txid": tx.txid(),
            "rawtx": tx.hex(), 
            "timestamp": datetime.now(timezone.utc).isoformat(),  # Timestamp for entry
            #"status": "pending",         # Initialize status as pending
            #"blockhash": None,           # Initialize blockhash as null
            #"blockheight": None,         # Initialize blockheight as null
            #"merkle_proof": None         # Initialize merkle_proof as null
        })
    wallet_manager.save_tx_store(tx_store, tx_file_path)

    broadcast_txid = await blockchain_api.broadcast_transaction(tx.hex())
    broadcast_timestamp = datetime.now(timezone.utc).isoformat() if broadcast_txid else None

    # --- Important: Move UTXO marking logic to the calling function (log_intermediate_result_process) ---
    # The actual marking of UTXOs as used, and storing new UTXOs created by this transaction,
    # should ideally happen at a higher level of abstraction, where the impact on the wallet state
    # is fully managed. This keeps create_op_return_transaction focused on just building/broadcasting one TX.
    # For now, we'll keep the `used_utxos_for_this_tx` list here and let the calling function handle it.

    # Identify and collect details of NEW UTXOs created by this transaction for the caller
    new_utxos_details = []
    for vout_idx, output in enumerate(tx.outputs):
        if output.satoshis > 0:
            new_utxos_details.append({
                "txid": tx.txid(),
                "vout": vout_idx, 
                "satoshis": output.satoshis,
                "scriptPubKey": output.locking_script.hex(), 
                "height": -1, # Height unknown until mined
                "used": False,
                "timestamp": datetime.now(timezone.utc).isoformat() 
            })
    
    logger.info(f"--- End of create_op_return_transaction ---")
    
    if broadcast_txid:
        return tx.hex(), broadcast_timestamp, broadcast_txid, consumed_utxos_details, new_utxos_details
    else:
        return None, None, None, [], [] # Return empty lists for UTXO changes on failure
       
async def monitor_pending_transactions(utxo_file_path: str, used_utxo_file_path: str, polling_interval_seconds: int = 30):
    """
    Monitors locally stored pending transactions for confirmation on the blockchain.
    Once confirmed, fetches and stores their Merkle path and updates UTXO heights.

    Args:
        utxo_file_path (str): The file path for the UTXO store.
        used_utxo_file_path (str): The file path for the used UTXO store.
        polling_interval_seconds (int): How often to check for confirmations.
    """
    logger.info(f"\n--- Starting Transaction Confirmation Monitor (polling every {polling_interval_seconds}s) ---")
    
    while True: # Loop indefinitely to keep monitoring
        # Load the entire audit log, as this is our central source of truth for records and their status.
        audit_log = load_audit_log()

       
        # Filter records that have blockchain_record and whose status indicates they need monitoring.
        # This includes "broadcasted" (waiting for block), "broadcast_failed" (might retry or inspect),
        # or "pending_creation" (if we want the monitor to also attempt to broadcast, though currently
        # create_op_return_transaction handles initial broadcast).
        records_to_monitor = [
            record for record in audit_log
            if record.get("blockchain_record") and 
               record["blockchain_record"].get("status") in ["broadcasted", "broadcast_failed", "pending_creation"]
        ]

        if not records_to_monitor:
            logger.info("  No pending audit records to monitor. Sleeping...")
        else:
            logger.info(f"  Monitoring {len(records_to_monitor)} audit records...")

        for record in records_to_monitor:
            blockchain_rec = record["blockchain_record"]
            log_id = record["log_id"]
            txid = blockchain_rec.get("txid") # TXID might be None for "pending_creation" status

            # --- Handle "pending_creation" status (if create_op_return_transaction didn't broadcast yet) ---
            # Currently, create_op_return_transaction tries to broadcast immediately.
            # If txid is None here, it means create_op_return_transaction failed or wasn't fully executed.
            if not txid or blockchain_rec["status"] == "pending_creation":
                logger.warning(f"  Audit record '{log_id}' is still in 'pending_creation' status or missing TXID. Cannot check confirmation yet.")
                continue 
            
            logger.info(f"  Checking confirmation for audit record '{log_id}' (TXID: {txid})...")
            
            tx_info = await blockchain_api.get_transaction_status_woc(txid)

            if tx_info and tx_info.get("blockhash") and tx_info.get("blockheight"):
                logger.info(f"    Audit record '{log_id}' (TXID {txid}) confirmed in block {tx_info['blockheight']} ({tx_info['blockhash']}).")
                
                merkle_proof_data = await blockchain_api.get_merkle_path(txid)

                # Update the blockchain_record directly within the audit record entry
                blockchain_rec["status"] = "confirmed"
                blockchain_rec["block_hash"] = tx_info["blockhash"]
                blockchain_rec["block_height"] = tx_info["blockheight"]
                blockchain_rec["timestamp_confirmed_utc"] = datetime.now(timezone.utc).isoformat()
                
                if merkle_proof_data:
                    blockchain_rec["merkle_proof_data"] = merkle_proof_data
                    logger.info(f"    Merkle path for '{log_id}' saved to audit_log.")
                else:
                    logger.warning(f"    Could not fetch Merkle path for confirmed record '{log_id}'. Marking as confirmed but incomplete proof.")
                    blockchain_rec["merkle_proof_data"] = {"error": "Merkle proof unavailable"}
                
                # Update UTXO store for newly created UTXOs in this transaction (height)
                # This needs to be loaded and saved specifically by the monitor.

                utxo_store = wallet_manager.load_utxo_store(utxo_file_path)
                updated_utxos_count = 0
                for utxo in utxo_store["utxos"]:
                    # Check if this UTXO was created by the confirmed transaction and its height is unknown
                    if utxo["txid"] == txid and utxo.get("height", -1) == -1: 
                        utxo["height"] = tx_info["blockheight"]
                        updated_utxos_count += 1
                if updated_utxos_count > 0:
                    wallet_manager.save_utxo_store(utxo_store, utxo_file_path)
                    logger.info(f"    Updated height for {updated_utxos_count} UTXO(s) from TXID {txid} in local UTXO store.")

            elif blockchain_rec["status"] == "broadcasted":
                logger.info(f"    Audit record '{log_id}' (TXID {txid}) is on the network but not yet confirmed.")
            elif blockchain_rec["status"] == "broadcast_failed":
                logger.warning(f"    Audit record '{log_id}' (TXID {txid}) was previously marked 'broadcast_failed'. Still unconfirmed.")
            else:
                logger.warning(f"    Audit record '{log_id}' (TXID {txid}) status: '{blockchain_rec.get('status')}'. Still unconfirmed or encountered network issue.")

        save_audit_log(audit_log)
        await asyncio.sleep(polling_interval_seconds)


async def audit_record_verifier(log_id: str) -> bool:
    """
    Simulates an auditor's tool to verify a specific audit record's integrity and blockchain inclusion.

    This function first verifies the integrity of the raw transaction and then
    iterates through all data payloads within the OP_RETURN script to perform
    a self-contained verification for each one. Finally, it confirms the transaction's
    inclusion in the blockchain via an SPV proof.

    Args:
        log_id (str): The unique identifier of the audit record to verify.

    Returns:
        bool: True if all verification steps pass, False otherwise.
    """
    logger.info(f"\n### AUDITOR VERIFICATION FOR LOG ID: {log_id} ###")
    
    audit_log = load_audit_log()
    
    record = next((r for r in audit_log if r.get("log_id") == log_id), None)
    if not record:
        logger.error(f"Audit record with ID '{log_id}' not found in {Config.AUDIT_LOG_FILE}.")
        return False
    
    blockchain_rec = record.get("blockchain_record", {})

    # --- Step 1: Check if the record is confirmed on blockchain ---
    if blockchain_rec.get("status") != "confirmed":
        logger.warning(f"  Record '{log_id}' is not confirmed on blockchain (Status: {blockchain_rec.get('status')}). Cannot perform full on-chain verification.")
        return False
    logger.info(f"  Status Check: PASS (Confirmed)")

    # Extract necessary data for verification from the local record
    original_content = record.get("original_audit_content")
    txid = blockchain_rec.get("txid")
    raw_transaction_hex = blockchain_rec.get("raw_transaction_hex")
    
    # Check for missing data
    if not all([original_content, txid, raw_transaction_hex]):
        logger.error(f"  Missing essential data in audit record '{log_id}' for verification. Cannot proceed.")
        return False

    # Initialize a flag to track the overall success of the verification
    overall_success = True

    # --- Step 2: Verify consistency between stored TXID and stored Raw Transaction ---
    logger.info("\n  --- Verifying Local Transaction Consistency (Stored TXID vs. Computed TXID from RawTX) ---")
    try:
        # Check if the raw transaction is not None before attempting to deserialize
        if not raw_transaction_hex:
            logger.error("  Local TX Consistency Check: FAIL. raw_transaction_hex is empty or None.")
            return False
            
        tx_obj_from_raw = Transaction.from_hex(raw_transaction_hex)
        # Check if deserialization was successful
        if tx_obj_from_raw is None:
            logger.error("  Local TX Consistency Check: FAIL. Failed to deserialize raw_transaction_hex.")
            return False

        computed_txid_from_raw = tx_obj_from_raw.txid()
        if computed_txid_from_raw != txid:
            logger.error(f"  Local TX Consistency Check: FAIL. Computed TXID '{computed_txid_from_raw}' from raw_transaction_hex does NOT match stored TXID '{txid}'.")
            return False
        else:
            logger.info(f"  Local TX Consistency Check: PASS. Raw transaction hex matches stored TXID.")
    except Exception as e:
        logger.error(f"  Local TX Consistency Check: FAIL. Error parsing raw_transaction_hex: {e}", exc_info=True)
        return False

    # --- Step 3: Check for internal consistency of the locally stored hashes ---
    # This is an important step to ensure that the hashes in the audit record
    # were correctly generated from the original content, before we compare
    # them with the data on the blockchain.
    logger.info("\n  --- Verifying Local Hash Consistency (Original Content vs. Stored Hashes) ---")
    local_hashes_verified = True
    
    if not original_content:
        logger.error("  Local Hash Consistency Check: FAIL. Original content is empty or None.")
        return False

    computed_original_hash = sha256(original_content.encode('utf-8'))
    
    # Check EC hash consistency
    ec_hash_pushed_hex = blockchain_rec.get("data_hash_pushed_to_op_return")
    if ec_hash_pushed_hex:
        stored_ec_hash = bytes.fromhex(ec_hash_pushed_hex)
        if computed_original_hash != stored_ec_hash:
            logger.error(f"  EC Hash Mismatch: FAIL. Computed hash '{computed_original_hash.hex()}' does NOT match stored hash '{stored_ec_hash.hex()}'.")
            local_hashes_verified = False
        else:
            logger.info("  EC Hash Mismatch: PASS.")
            
    # Check X.509 hash consistency (if available)
    x509_hash_pushed_hex = blockchain_rec.get("x509_hash_pushed")
    if x509_hash_pushed_hex:
        stored_x509_hash = bytes.fromhex(x509_hash_pushed_hex)
        if computed_original_hash != stored_x509_hash:
            logger.error(f"  X.509 Hash Mismatch: FAIL. Computed hash '{computed_original_hash.hex()}' does NOT match stored hash '{stored_x509_hash.hex()}'.")
            local_hashes_verified = False
        else:
            logger.info("  X.509 Hash Mismatch: PASS.")
    
    if not local_hashes_verified:
        logger.error("  Local Hash Consistency Check: FAIL.")
        overall_success = False
    else:
        logger.info("  Local Hash Consistency Check: PASS.")

    # --- Step 4: Extract and Verify ALL Payload Data from Raw Transaction ---
    logger.info("\n  --- Verifying Payload Data from Raw Transaction ---")
    all_data_pushes = extract_op_return_payload(raw_transaction_hex)

    if not all_data_pushes:
        logger.error("  Payload Verification: FAIL. No OP_RETURN data found in the transaction.")
        overall_success = False
    else:
        # Initialize a flag to track the overall success of the payload verification
        payload_verification_overall_success = True
        current_index = 0
        
        while current_index < len(all_data_pushes):
            mode_byte = all_data_pushes[current_index]
            
            # Check for a "note" payload, which only has one data push
            if mode_byte == AUDIT_MODE_NOTE:
                if len(all_data_pushes) < current_index + 2:
                    logger.error("  Note Payload Verification: FAIL. Incomplete note payload found.")
                    payload_verification_overall_success = False
                    break
                
                note_bytes = all_data_pushes[current_index + 1]
                try:
                    decoded_note = note_bytes.decode('utf-8')
                    logger.info(f"  Note found and verified: '{decoded_note}'")
                except UnicodeDecodeError:
                    logger.error("  Note Payload Verification: FAIL. Could not decode note as UTF-8.")
                    payload_verification_overall_success = False
                
                # Move the index forward by 2 (mode byte + note data)
                current_index += 2
                continue # Continue to the next item in the while loop
            
            # If it's not a note, check for a full payload triplet
            if len(all_data_pushes) < current_index + 4:
                logger.error("  Payload Verification: FAIL. Incomplete payload triplet found.")
                payload_verification_overall_success = False
                break

            payload_triplet = all_data_pushes[current_index : current_index + 4]

            if mode_byte == AUDIT_MODE_EC:
                if not verify_ec_payload(payload_triplet, original_content):
                    payload_verification_overall_success = False
            elif mode_byte == AUDIT_MODE_X509:
                if not verify_x509_payload(payload_triplet, original_content):
                    payload_verification_overall_success = False
            else:
                logger.error(f"  Payload Verification: FAIL. Unknown mode byte found: {mode_byte}.")
                payload_verification_overall_success = False
                break
            
            current_index += 4
        
        if not payload_verification_overall_success:
            logger.error("  Payload Verification: OVERALL FAIL.")
            overall_success = False
        else:
            logger.info("  Payload Verification: OVERALL PASS.")

    # --- Step 5: Verify Blockchain Inclusion (SPV Proof) ---
    logger.info("\n  --- Verifying Blockchain Inclusion (SPV Proof) ---")

    block_hash = blockchain_rec.get("block_hash")
    block_height = blockchain_rec.get("block_height")
    merkle_proof_data = blockchain_rec.get("merkle_proof_data")

    if not all([block_hash, merkle_proof_data]):
        logger.error(f"  SPV Proof: FAIL. Missing essential data for SPV proof in audit record '{log_id}'.")
        overall_success = False
    else:
        header_manager = BlockHeaderManager(f"block_headers_{Config.ACTIVE_NETWORK_NAME}.json")
        local_block_headers = header_manager.headers
        
        live_block_header = None
        if block_hash in local_block_headers:
            live_block_header = local_block_headers[block_hash]
            logger.info(f"  Block Header for '{block_hash}' (height {block_height}) found in local cache. Using cached data.")
        else:
            logger.info(f"  Block Header for '{block_hash}' (height {block_height}) NOT found in local cache. Fetching LIVE from network.")
            live_block_header = await blockchain_api.get_block_header(block_hash)
            if live_block_header:
                header_manager.headers[block_hash] = live_block_header
                header_manager.save()
                logger.info(f"  Live Block Header for '{block_hash}' (height {block_height}) fetched and cached.")
            else:
                logger.error(f"  SPV Proof: FAIL. Could not fetch live block header for block '{block_hash}'.")
                overall_success = False

        if not utils.verify_block_hash(live_block_header):
            logger.error(f"  SPV Proof: FAIL. Live block hash verification failed for block '{block_hash}'. Block header may be invalid.")
            overall_success = False
        else:
            logger.info(f"  Live Block Header Check: PASS. Block hash is valid.")

        merkle_root_from_header = live_block_header.get("merkleroot")
        if not merkle_root_from_header:
            logger.error(f"  SPV Proof: FAIL. Merkle root not found in live block header for block '{block_hash}'.")
            overall_success = False
        else:
            merkle_proof_verified = verify_merkle_path(
                txid, 
                merkle_proof_data.get("index", 0), 
                merkle_proof_data.get("nodes", []), 
                merkle_root_from_header 
            )
            if not merkle_proof_verified:
                logger.error(f"  SPV Proof: FAIL. Merkle path verification failed for TXID '{txid}'.")
                overall_success = False
            else:
                logger.info(f"  SPV Proof: PASS. Transaction is verifiably included in block '{block_hash}'.")
    
    logger.info(f"\n### AUDITOR VERIFICATION FOR LOG ID: {log_id} COMPLETE: { 'PASS' if overall_success else 'FAIL' } ###")
    return overall_success  

async def audit_all_records():
    """
    Performs a full audit verification for all 'confirmed' records in the audit log.
    Prints a summary of the verification results.
    """
    logger.info(f"\n### STARTING BATCH AUDIT OF ALL CONFIRMED RECORDS ###")
    
    audit_log = load_audit_log()
    
    # Filter for records that are marked as 'confirmed' and thus have all necessary info
    # for a full audit (txid, block_hash, merkle_proof).
    confirmed_records = [
        record for record in audit_log
        if record.get("blockchain_record", {}).get("status") == "confirmed"
    ]

    if not confirmed_records:
        logger.info("No confirmed records found in the audit log to perform a batch audit.")
        return

    total_audited = len(confirmed_records)
    passed_audits = 0
    failed_audits = 0

    logger.info(f"Found {total_audited} confirmed record(s) for batch audit.")

    for i, record in enumerate(confirmed_records):
        log_id = record["log_id"]
        logger.info(f"\n--- Auditing Record {i+1}/{total_audited}: ID {log_id} ---")
        
        verification_result = await audit_record_verifier(log_id)
        
        if verification_result:
            passed_audits += 1
            logger.info(f"Audit for ID {log_id}: PASSED.")
        else:
            failed_audits += 1
            logger.error(f"Audit for ID {log_id}: FAILED.")
        
        await asyncio.sleep(0.1)

    logger.info(f"\n### BATCH AUDIT COMPLETE ###")
    logger.info(f"Total Confirmed Records Audited: {total_audited}")
    logger.info(f"Passed Audits: {passed_audits}")
    logger.info(f"Failed Audits: {failed_audits}")
    overall_result = 'PASS' if failed_audits == 0 else 'FAIL'
    logger.info(f"Overall Batch Audit Result: { overall_result }")
