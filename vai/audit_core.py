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
    Network, Script, SatoshisPerKilobyte, 
    UnlockingScriptTemplate,
    hash256
)

from bsv.hash import sha256 # Import sha256 function directly from bsv.hash module

logger = logging.getLogger(__name__)

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

   
def verify_op_return_hash(raw_tx_hex: str, expected_hash_bytes: bytes) -> bool:
    """
    Deserializes a raw Bitcoin SV transaction hex, looks for OP_RETURN outputs,
    and compares their data payload with a given hash value.

    Args:
        raw_tx_hex (str): The raw transaction in hexadecimal string format.
        expected_hash_bytes (bytes): The expected hash value in bytes for comparison.

    Returns:
        bool: True if an OP_RETURN output is found and its data matches the expected hash,
              False otherwise.
    """
    try:
        tx = Transaction.from_hex(raw_tx_hex)
        found_match = False

        logger.info("\n--- Verifying OP_RETURN Hashes ---")
        for i, tx_output in enumerate(tx.outputs): #type:ignore
            locking_script = tx_output.locking_script
            script_asm = locking_script.to_asm()

            if script_asm.startswith("OP_RETURN"):
                logger.info(f"  Found OP_RETURN in Output {i}:")
                logger.info(f"    Full OP_RETURN Script (ASM): {script_asm}")

                parts = script_asm.split(' ', 1) 

                if len(parts) > 1:
                    op_return_data_hex = parts[1]
                    try:
                        op_return_data_bytes = bytes.fromhex(op_return_data_hex)

                        logger.info(f"    Extracted OP_RETURN Data: {op_return_data_hex}")
                        logger.info(f"    Expected Hash Value: {expected_hash_bytes.hex()}")

                        if op_return_data_bytes == expected_hash_bytes:
                            logger.info("    Comparison: MATCH")
                            found_match = True
                            return True 
                        else:
                            logger.info("    Comparison: NO MATCH")
                    except ValueError:
                        logger.error(f"    Could not convert extracted data '{op_return_data_hex}' to bytes (not valid hex).")
                else:
                    logger.warning("    OP_RETURN found but no data payload detected (e.g., just 'OP_RETURN').")
        
        if not found_match:
            logger.info("No matching OP_RETURN hash found in any output.")
        
        return found_match

    except Exception as e:
        logger.error(f"Error during OP_RETURN hash verification: {e}")
        return False


async def verify_op_return_hash_sig_pub(
    raw_tx_hex: str,
    expected_hash: bytes,
    expected_public_key_hex: str
) -> bool:
    """
    Gets the OP_RETURN from raw_tx_hex, identifies the 3 arguments
    (hash, signature, public key), and performs verification.
    """
    logger.info("\n--- Verifying OP_RETURN Hash, Signature, and Public Key ---")
    
    try:
        tx = Transaction.from_hex(raw_tx_hex)
        if tx is None:
            logger.error(f"ERROR: Tx is None")
            return False

        for tx_output in tx.outputs:
            locking_script = tx_output.locking_script
            
            # ---  Robust check for OP_RETURN opcode to handle different data types ---
            first_chunk_op_raw = locking_script.chunks[0].op if locking_script.chunks else None
            is_op_return = False
            if isinstance(first_chunk_op_raw, int):
                if first_chunk_op_raw == 0x6a:
                    is_op_return = True
            elif isinstance(first_chunk_op_raw, bytes) and len(first_chunk_op_raw) == 1:
                if first_chunk_op_raw[0] == 0x6a:
                    is_op_return = True
            
            if not is_op_return:
                continue

            logger.info(f"Found OP_RETURN output: {locking_script.to_asm()}")

            # (1) Check for expected number of data pushes
            if len(locking_script.chunks) < 4:
                logger.warning("OP_RETURN script does not contain enough data elements.")
                return False

            # (2) Extract and validate data pushes
            extracted_hash_bytes = locking_script.chunks[1].data
            extracted_signature_bytes = locking_script.chunks[2].data
            extracted_public_key_bytes = locking_script.chunks[3].data

            # convince linter
            assert extracted_hash_bytes is not None
            assert extracted_signature_bytes is not None
            assert extracted_public_key_bytes is not None


            if any(x is None for x in [extracted_hash_bytes, extracted_signature_bytes, extracted_public_key_bytes]):
                logger.warning("One or more data elements are not valid data pushes.")
                return False

            # (3) Perform robust length checks
            if not (
                len(extracted_hash_bytes) == 32 and
                30 <= len(extracted_signature_bytes) <= 72 and
                (len(extracted_public_key_bytes) == 33 or len(extracted_public_key_bytes) == 65)
            ):
                logger.warning("Data element length mismatch detected.")
                return False

            logger.info(f"  Extracted Hash: {extracted_hash_bytes.hex()}")
            logger.info(f"  Extracted Public Key: {extracted_public_key_bytes.hex()}")
            
            # (4) Compare the hash
            if extracted_hash_bytes != expected_hash:
                logger.warning(f"  Hash comparison: FAIL")
                return False
            logger.info("  Hash comparison: PASS")

            # (5) Compare the public key
            if extracted_public_key_bytes.hex() != expected_public_key_hex.lower():
                logger.warning(f"  Public Key comparison: FAIL")
                return False
            logger.info("  Public Key comparison: PASS")

            # (6) Verify the signature
            try:
                pub_key = PublicKey(extracted_public_key_bytes)
                if pub_key.verify(extracted_signature_bytes, extracted_hash_bytes):
                    logger.info("  Signature verification: PASS")
                    return True # Success path, we can exit here
                else:
                    logger.warning("  Signature verification: FAIL")
                    return False
            except Exception as sig_err:
                logger.error(f"  Error during signature verification: {sig_err}")
                return False

    except Exception as e:
        logger.error(f"Error during OP_RETURN verification: {e}")
        return False
        
    # Final return for the case where no OP_RETURN output was found after checking all outputs
    logger.info("No OP_RETURN output found in the transaction.")
    return False

async def verify_op_return_hash_sig_pub_old_26_08_16(#not robust enough
    raw_tx_hex: str,
    expected_hash: bytes,
    expected_public_key_hex: str
) -> bool:
    """
    Gets the OP_RETURN from raw_tx_hex, identifies the 3 arguments
    (hash, signature, public key), and performs verification.
    """
    logger.info("\n--- Verifying OP_RETURN Hash, Signature, and Public Key ---")
    
    try:
        tx = Transaction.from_hex(raw_tx_hex)
        if tx is None:
            logger.error(f"ERROR: Tx is None")
            return False

        for tx_output in tx.outputs:
            locking_script = tx_output.locking_script
            
            # Simplified check for OP_RETURN
            if not locking_script.chunks or locking_script.chunks[0].op != 0x6a:
                continue

            logger.info(f"Found OP_RETURN output: {locking_script.to_asm()}")

            # (1) Check for expected number of data pushes
            if len(locking_script.chunks) < 4:
                logger.warning("OP_RETURN script does not contain enough data elements.")
                return False

            # (2) Extract and validate data pushes
            extracted_hash_bytes = locking_script.chunks[1].data
            extracted_signature_bytes = locking_script.chunks[2].data
            extracted_public_key_bytes = locking_script.chunks[3].data

            # convince linter
            assert extracted_hash_bytes is not None
            assert extracted_signature_bytes is not None
            assert extracted_public_key_bytes is not None


            if any(x is None for x in [extracted_hash_bytes, extracted_signature_bytes, extracted_public_key_bytes]):
                logger.warning("One or more data elements are not valid data pushes.")
                return False

            # (3) Perform robust length checks
            if not (
                len(extracted_hash_bytes) == 32 and
                30 <= len(extracted_signature_bytes) <= 72 and
                (len(extracted_public_key_bytes) == 33 or len(extracted_public_key_bytes) == 65)
            ):
                logger.warning("Data element length mismatch detected.")
                return False

            logger.info(f"  Extracted Hash: {extracted_hash_bytes.hex()}")
            logger.info(f"  Extracted Public Key: {extracted_public_key_bytes.hex()}")
            
            # (4) Compare the hash
            if extracted_hash_bytes != expected_hash:
                logger.warning(f"  Hash comparison: FAIL")
                return False
            logger.info("  Hash comparison: PASS")

            # (5) Compare the public key
            if extracted_public_key_bytes.hex() != expected_public_key_hex.lower():
                logger.warning(f"  Public Key comparison: FAIL")
                return False
            logger.info("  Public Key comparison: PASS")

            # (6) Verify the signature
            try:
                pub_key = PublicKey(extracted_public_key_bytes)
                if pub_key.verify(extracted_signature_bytes, extracted_hash_bytes):
                    logger.info("  Signature verification: PASS")
                    return True # Success path, we can exit here
                else:
                    logger.warning("  Signature verification: FAIL")
                    return False
            except Exception as sig_err:
                logger.error(f"  Error during signature verification: {sig_err}")
                return False

    except Exception as e:
        logger.error(f"Error during OP_RETURN verification: {e}")
        return False
        
    # Final return for the case where no OP_RETURN output was found after checking all outputs
    logger.info("No OP_RETURN output found in the transaction.")
    return False




# --- Verify OP_RETURN hash, signature, and public key ---
async def verify_op_return_hash_sig_pub_old( #TODO check the new method!
    raw_tx_hex: str,
    expected_hash: bytes,
    expected_public_key_hex: str
) -> bool: #type:ignore -> solved in the new method, but check that for semantics! 
    """
    Gets the OP_RETURN from raw_tx_hex, identifies the 3 arguments
    (hash, signature, public key), and performs verification:
    a) Compares the extracted hash with the expected_hash.
    b) Compares the extracted public key with the expected_public_key_hex.
    c) Verifies the signature using the extracted public key and hash.

    Args:
        raw_tx_hex (str): The raw transaction in hexadecimal string format.
        expected_hash (bytes): The expected hash value in bytes.
        expected_public_key_hex (str): The expected public key in hexadecimal string format.

    Returns:
        bool: True if all comparisons and signature verification pass, False otherwise.
    """
    logger.info("\n--- Verifying OP_RETURN Hash, Signature, and Public Key ---")
    
    try:
        tx = Transaction.from_hex(raw_tx_hex)
        if tx is None:
            logger.error(f"ERROR: Tx is None")
            return False
        op_return_output_found = False

        
        for tx_output in tx.outputs: 
            locking_script = tx_output.locking_script
            

            # Use the robust check for OP_RETURN here too
            first_chunk_op_raw = locking_script.chunks[0].op if locking_script.chunks else None
            first_chunk_op_int = -1
            if isinstance(first_chunk_op_raw, bytes) and len(first_chunk_op_raw) == 1:
                first_chunk_op_int = first_chunk_op_raw[0]
            elif isinstance(first_chunk_op_raw, int):
                first_chunk_op_int = first_chunk_op_raw


            if locking_script.chunks and first_chunk_op_int == 0x6a: # Check for OP_RETURN
                op_return_output_found = True
                logger.info(f"Found OP_RETURN output: {locking_script.to_asm()}")

                # Expecting 3 data pushes after OP_RETURN: hash, signature, public key
                if len(locking_script.chunks) < 4: # OP_RETURN + 3 data pushes
                    logger.warning("OP_RETURN script does not contain enough data elements (expected hash, signature, public key).")
                    return False

                # Extract the three data elements
                # Ensure they are indeed data pushes
                extracted_hash_bytes = locking_script.chunks[1].data
                extracted_signature_bytes = locking_script.chunks[2].data
                extracted_public_key_bytes = locking_script.chunks[3].data

                if any(x is None for x in [extracted_hash_bytes, extracted_signature_bytes, extracted_public_key_bytes]):
                    logger.warning("One or more expected data elements after OP_RETURN are not valid data pushes.")
                    return False
                
                # convince linter
                assert extracted_hash_bytes is not None
                assert extracted_signature_bytes is not None
                assert extracted_public_key_bytes is not None

                # Add length checks for robustness (optional but good practice)
                if not (
                    len(extracted_hash_bytes) == 32 and
                    30 <= len(extracted_signature_bytes) <= 72 and
                    (len(extracted_public_key_bytes) == 33 or len(extracted_public_key_bytes) == 65)
                ):
                    logger.warning(f"Data element length mismatch detected. Hash: {len(extracted_hash_bytes)}B, Sig: {len(extracted_signature_bytes)}B, PubKey: {len(extracted_public_key_bytes)}B.")
                    logger.warning("This may indicate incorrect data types were pushed to OP_RETURN or incorrect extraction logic.")
                    return False
                
                logger.info(f"  Extracted Hash: {extracted_hash_bytes.hex()}")
                logger.info(f"  Extracted Signature: {extracted_signature_bytes.hex()}")
                logger.info(f"  Extracted Public Key: {extracted_public_key_bytes.hex()}")

                if extracted_hash_bytes != expected_hash:
                    logger.warning(f"  Hash comparison: FAIL (Expected: {expected_hash.hex()}, Got: {extracted_hash_bytes.hex()})")
                    return False
                logger.info("  Hash comparison: PASS")

                # b) Compare the public key
                if extracted_public_key_bytes.hex() != expected_public_key_hex.lower(): # Ensure lower case for comparison
                    print(f"  Public Key comparison: FAIL (Expected: {expected_public_key_hex}, Got: {extracted_public_key_bytes.hex()})")
                    return False
                logger.info("  Public Key comparison: PASS")

                # c) Verify the signature
                try:
                    # Convert bytes back to bsv-sdk objects for verification
                    sig = extracted_signature_bytes
                    pub_key = PublicKey(extracted_public_key_bytes)
                    
                    if pub_key.verify(sig, extracted_hash_bytes):
                        logger.info("  Signature verification: PASS")
                        return True
                    else:
                        logger.warning("  Signature verification: FAIL")
                        return False
                except Exception as sig_err:
                    logger.error(f"  Error during signature or public key conversion/verification: {sig_err}")
                    return False
        
        if not op_return_output_found:
            logger.info("No OP_RETURN output found in the transaction.")
            return False

    except Exception as e:
        logger.error(f"Error during OP_RETURN hash/signature/pubkey verification: {e}")
        return False




def build_audit_payload(
    intermediate_result_data: str, # Or Dict, or custom Object, depending on your data
    signing_key_wif: str
) -> List[bytes]:
    """
    Builds the OP_RETURN payload (hash, signature, public key) for an audit record.

    Args:
        intermediate_result_data (str): The human-readable intermediate result to be logged.
                                        This will be hashed.
        signing_key_wif (str): The WIF of the private key used to sign the hash.

    Returns:
        List[bytes]: A list containing the hash (bytes), signature (bytes),
                     and public key (bytes) ready for OP_RETURN.
    """
    # Convert input data to bytes for hashing
    data_bytes_for_hash = intermediate_result_data.encode('utf-8')
    audit_hash = sha256(data_bytes_for_hash)
    
    # Perform signing
    private_signing_key_obj = PrivateKey(signing_key_wif, network=Config.ACTIVE_NETWORK_BSV)
    public_signing_key_obj = private_signing_key_obj.public_key()
    audit_signature = private_signing_key_obj.sign(audit_hash)

    print(f"\n--- Building Audit Payload ---")
    print(f"  Data to Hash: '{intermediate_result_data}'")
    print(f"  Generated Hash: {audit_hash.hex()}")
    print(f"  Signing Public Key: {public_signing_key_obj.hex()}")
    print(f"  Generated Signature: {audit_signature.hex()}")

    if public_signing_key_obj.verify(audit_signature, audit_hash):
        print("  Initial Signature Verification (Payload Build): PASS")
    else:
        print("  Initial Signature Verification (Payload Build): FAIL")
        # You might want to raise an error here if verification fails

    # Return the payload as a list of bytes
    return [
        audit_hash,
        audit_signature, # Ensure Signature object is converted to bytes
        public_signing_key_obj.serialize() # Ensure PublicKey object is converted to bytes
    ]



async def create_op_return_transaction(
        spending_key_wif: str,
        recipient_address: str, 
        op_return_data_pushes: List[bytes],
        original_audit_content_string: str,
        network: Network,
        utxo_file_path: str,
        tx_file_path: str
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

    # 3. Create the OP_RETURN output
    op_return_script_parts = ["OP_RETURN"]
    if op_return_data_pushes:
        for data_bytes in op_return_data_pushes:
            op_return_script_parts.append(data_bytes.hex())

    op_return_script_asm = " ".join(op_return_script_parts) 
    op_return_script = Script.from_asm(op_return_script_asm)
    
    logger.info(f"OP_RETURN script (ASM representation from to_asm()): {op_return_script.to_asm()}")
    
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

    Args:
        log_id (str): The unique identifier of the audit record to verify.

    Returns:
        bool: True if all verification steps pass, False otherwise.
    """
    logger.info(f"\n### AUDITOR VERIFICATION FOR LOG ID: {log_id} ###")
    overall_success = True

    audit_log = load_audit_log()

    dynamic_header_file_path = f"block_headers_{Config.ACTIVE_NETWORK_NAME}.json"
    header_manager = BlockHeaderManager(dynamic_header_file_path)
    local_block_headers = header_manager.headers

    record = next((r for r in audit_log if r.get("log_id") == log_id), None)

    if not record:
        logger.error(f"Audit record with ID '{log_id}' not found in {Config.AUDIT_LOG_FILE}.")
        return False

    blockchain_rec = record.get("blockchain_record", {})

    # --- Step 1: Check if the record is confirmed on blockchain ---
    if blockchain_rec.get("status") != "confirmed":
        logger.warning(f"  Record '{log_id}' is not confirmed on blockchain (Status: {blockchain_rec.get('status')}). Cannot perform full on-chain verification.")
        logger.warning(f"  Status Check: FAIL (Not confirmed)")
        return False
    logger.info(f"  Status Check: PASS (Confirmed)")

    # Extract necessary data for verification
    original_content = record.get("original_audit_content")
    txid = blockchain_rec.get("txid")
    raw_transaction_hex = blockchain_rec.get("raw_transaction_hex")
    data_hash_pushed = bytes.fromhex(blockchain_rec.get("data_hash_pushed_to_op_return", ""))
    signature_pushed = bytes.fromhex(blockchain_rec.get("signature_pushed_to_op_return", ""))
    public_key_pushed_hex = blockchain_rec.get("public_key_pushed_to_op_return", "")
    block_hash = blockchain_rec.get("block_hash")
    block_height = blockchain_rec.get("block_height")
    merkle_proof_data = blockchain_rec.get("merkle_proof_data")

    if not all([original_content, txid, raw_transaction_hex, data_hash_pushed, signature_pushed, public_key_pushed_hex, block_hash, merkle_proof_data]):
        logger.error(f"  Missing essential data in audit record '{log_id}' for verification. Cannot proceed.")
        logger.error(f"  Data Integrity Check (Local Record): FAIL (Missing data)")
        return False
    logger.info(f"  Local Record Data Check: PASS (All essential data present)")


    # --- Step 2a: Verify consistency between stored TXID and stored Raw Transaction ---
    logger.info("\n  --- Verifying Local Transaction Consistency (TXID vs. RawTX Hash) ---")
    try:
        tx_obj_from_raw = Transaction.from_hex(raw_transaction_hex)
        computed_txid_from_raw = tx_obj_from_raw.txid() #type:ignore
        if computed_txid_from_raw != txid:
            logger.error(f"  Local TX Consistency Check: FAIL. Computed TXID '{computed_txid_from_raw}' from raw_transaction_hex does NOT match stored TXID '{txid}'. Raw transaction may be tampered or invalid.")
            logger.error(f"  Local TX Consistency Check: FAIL (RawTX Mismatch)")
            overall_success = False
            return overall_success
        else:
            logger.info(f"  Local TX Consistency Check: PASS. Raw transaction hex matches stored TXID.")
    except Exception as e:
        logger.error(f"  Local TX Consistency Check: FAIL. Error parsing raw_transaction_hex: {e}", exc_info=True)
        logger.error(f"  Local TX Consistency Check: FAIL (RawTX Parsing Error)")
        overall_success = False
        return overall_success


    # --- Step 3: Verify Data Integrity (Off-Chain) ---
    logger.info("\n  --- Verifying Data Integrity (Original Content vs. Hashed) ---")
    computed_original_hash = sha256(original_content.encode('utf-8')) #type:ignore
    if computed_original_hash != data_hash_pushed:
        logger.error(f"  Data Integrity Check: FAIL. Computed hash '{computed_original_hash.hex()}' does NOT match pushed hash '{data_hash_pushed.hex()}'. Original content may be tampered.")
        logger.error(f"  Data Integrity Check: FAIL (Content Tampered)")
        overall_success = False
    else:
        logger.info(f"  Data Integrity Check: PASS. Original content hash matches pushed hash.")


    # --- Step 4: Verify Data Authenticity (Signature Check) ---
    logger.info("\n  --- Verifying Data Authenticity (Signature Check) ---")
    verification_passed = await verify_op_return_hash_sig_pub(
        raw_transaction_hex, # Use the stored raw transaction hex
        data_hash_pushed,    # Use the hash pushed to OP_RETURN
        public_key_pushed_hex # Use the public key pushed to OP_RETURN
    )
    if not verification_passed:
        logger.error(f"  Data Authenticity Check: FAIL. Signature verification failed for record '{log_id}'.")
        logger.error(f"  Data Authenticity Check: FAIL (Signature Invalid)")
        overall_success = False
    else:
        logger.info(f"  Data Authenticity Check: PASS. Signature is valid.")


    # --- Step 5: Verify Blockchain Inclusion (SPV Proof) ---
    logger.info("\n  --- Verifying Blockchain Inclusion (SPV Proof) ---")
    
    # 5.1 Fetch Block Header (FIRST from cache, THEN live)
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
            logger.error(f"  SPV Proof: FAIL (Block Header Unavailable)")
            overall_success = False
            return overall_success 

    # 5.2 Verify the live Block Hash itself (self-consistency check)
    if not utils.verify_block_hash(live_block_header):
        logger.error(f"  SPV Proof: FAIL. Live block hash verification failed for block '{block_hash}'. Block header may be invalid.")
        logger.error(f"  SPV Proof: FAIL (Block Header Invalid)")
        overall_success = False
    else:
        logger.info(f"  Live Block Header Check: PASS. Block hash is valid.")

    # 5.3 Verify Merkle Path against live Block Header's Merkle Root
    merkle_root_from_header = live_block_header.get("merkleroot")
    if not merkle_root_from_header:
        logger.error(f"  SPV Proof: FAIL. Merkle root not found in live block header for block '{block_hash}'.")
        logger.error(f"  SPV Proof: FAIL (Merkle Root Missing)")
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
            logger.error(f"  SPV Proof: FAIL (Merkle Path Invalid)")
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
    logger.info(f"Overall Batch Audit Result: { 'PASS' if failed_audits == 0 else 'FAIL' }")
