
import logging
from typing import List, Dict, Optional, IO, cast
from datetime import datetime, timezone

from bsv import (
    PrivateKey, Transaction, TransactionInput, TransactionOutput, 
    Network, Script, SatoshisPerKilobyte, UnlockingScriptTemplate, P2PKH
)
from bsv.hash import sha256 
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

from anchorforge.config import Config
from anchorforge import blockchain_api
from anchorforge import core_defs # Shared constants

logger = logging.getLogger(__name__)



# region --- Payload Builders ---

def build_audit_payload(intermediate_result_data: str, signing_key_wif: str ) -> List[bytes]:
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

    logger.info(f"  Generated Hash from local data: {audit_hash.hex()}")

    # Return the payload as a list of bytes, prepending the mode byte
    return build_audit_payload_prehashed(audit_hash, signing_key_wif)

def build_audit_payload_prehashed(
    precomputed_hash: bytes,    
    signing_key_wif: str
) -> List[bytes]:
    """
    Builds the OP_RETURN payload (mode, hash, signature, public key) for an audit record.

    Args:
        signing_key_wif (str): The WIF of the private key used to sign the hash.
        precomuted_hash (bytes) : comes from other source, uppper level has to ensure integrity

    Returns:
        List[bytes]: A list containing the mode (bytes), hash (bytes), signature (bytes),
                     and public key (bytes) ready for OP_RETURN.

    """

    audit_hash = precomputed_hash

    # Perform signing
    private_signing_key_obj = PrivateKey(signing_key_wif, network=Config.ACTIVE_NETWORK_BSV)
    public_signing_key_obj = private_signing_key_obj.public_key()
    audit_signature = private_signing_key_obj.sign(audit_hash)

    logger.info(f"\n--- Building Audit Payload (ECDSA) ---")
    logger.info(f"  Data to Hash: prehashed, from an external source'")
    logger.info(f"  Used Hash: {audit_hash.hex()}")
    logger.info(f"  Signing Public Key: {public_signing_key_obj.hex()}")
    logger.info(f"  Generated Signature: {audit_signature.hex()}")

    if public_signing_key_obj.verify(audit_signature, audit_hash):
        logger.info("  Initial Signature Verification (Payload Build): PASS")
    else:
        logger.error("  Initial Signature Verification (Payload Build): FAIL")

    # Return the payload as a list of bytes, prepending the mode byte
    return [
        core_defs.AUDIT_MODE_EC,
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

    # 1. Convert input data to bytes for hashing
    data_bytes_for_hash = intermediate_result_data.encode('utf-8')

    audit_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    audit_hash.update(data_bytes_for_hash)

    final_hash_bytes = audit_hash.finalize()
    
    logger.info(f"  Data to Hash: '{intermediate_result_data}'")
    logger.info(f"  Generated Hash: {final_hash_bytes.hex()}")

    return build_x509_audit_payload_prehashed(final_hash_bytes, private_key_pem, certificate_pem)
        
    


def build_x509_audit_payload_prehashed(
    precomputed_hash: bytes, 
    private_key_pem: str,
    certificate_pem: str
) -> List[bytes]:
    """
    Builds the OP_RETURN payload (mode, hash, signature, x.509 certificate) for an audit record.

    This function expects a hash, signs it with the private key from a
    given X.509 certificate, and returns the hash, the signature, and the full certificate
    as a list of byte strings, ready for an OP_RETURN transaction.

    Args:
        precomputed hash(bytes): Hash from external source
        private_key_pem (str): The private key in PEM format.
        certificate_pem (str): The self-signed X.509 certificate in PEM format.

    Returns:
        List[bytes]: A list containing the mode (bytes), hash (bytes), signature (bytes),
                     and certificate (bytes) ready for OP_RETURN.
    """
    logger.info("\n--- Building Audit Payload (X.509) ---")

    try:
        final_hash_bytes = precomputed_hash  # here replaced hash derivation from input
        # Note:
        # Ensure it replaces:  (from build_x509audit_payload() )
        # data_bytes_for_hash = intermediate_result_data.encode('utf-8')
        # audit_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        # audit_hash.update(data_bytes_for_hash)
        # final_hash_bytes = audit_hash.finalize()

        
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
        
        logger.info(f"  Hash from external data")
        
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
            core_defs.AUDIT_MODE_X509,
            final_hash_bytes,
            signature,
            certificate_bytes
        ]
        
    except Exception as e:
        logger.error(f"Error building X.509 audit payload: {e}")
        return []
#endregion



# region --- Transaction Creation Logic

async def _fetch_inputs_for_amount(
    target_amount_satoshis: int,
    current_utxo_store_data: Dict, 
    tx_store: Dict,
    spending_key_wif: str,
    network: Network
) -> tuple[List[TransactionInput], int, List[Dict]]:
    """
    Selects UTXOs and prepares TransactionInputs to cover the target amount.
    Returns: (inputs, total_input_satoshis, consumed_utxo_details)
    """

    min_utxo_value = 546 # legacy

    if Config.ACTIVE_NETWORK_NAME == "test":
        min_utxo_value = Config.MINIMUM_UTXO_VALUE_TESTNET
    else:
        min_utxo_value = Config.MINIMUM_UTXO_VALUE
    
    available_utxos = [utxo for utxo in current_utxo_store_data["utxos"] if not utxo["used"] and utxo["satoshis"] >= min_utxo_value]
        
    if not available_utxos:
        # TODO <recipient address>
        logger.error(f"No suitable UTXOs available for <recipient_address> to cover fees. Please fund the address.")
        return [], 0, []

    # 2. prepare transaction inputs from all available UTXO until sufficient funds
    tx_inputs = []
    total_input_satoshis = 0
    consumed_utxos_details = []
    priv_key = PrivateKey(spending_key_wif, network)


    for utxo in available_utxos:
        
        # Retrieve rawtx for the selected UTXO's txid from tx_store
        raw_source_tx_hex = None
        for tx_entry in tx_store["transactions"]:
            if tx_entry["txid"] == utxo['txid']:
                raw_source_tx_hex = tx_entry['rawtx']
                break
        # Question: Is the following identical?
        # raw_source_tx_hex = next((t['rawtx'] for t in tx_store["transactions"] if t["txid"] == utxo['txid']), None)

        if raw_source_tx_hex is None:
            logger.warning(f"Warning: Raw transaction for UTXO {utxo['txid']} not in cache. Fetching from network.")
            raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(utxo['txid'])

            if not raw_source_tx_hex or raw_source_tx_hex == "0":
                logger.warning(f"Skipping UTXO {utxo['txid']}:{utxo['vout']} due to failure to get source transaction hex.")
                continue 

            # only add when not yet in store
            if not any(tx['txid'] == utxo['txid'] for tx in tx_store["transactions"]):
                tx_store["transactions"].append({
                    "txid": utxo['txid'], 
                    "rawtx": raw_source_tx_hex,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                # TODO Entfernen: wallet_manager.save_tx_store(f_tx_store, tx_store)
        
        source_tx_obj = Transaction.from_hex(raw_source_tx_hex)
        if source_tx_obj is None:
            logger.warning(f"Failed to parse source transaction hex for UTXO {utxo['txid']}. Skipping.")
            continue
        
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

    return tx_inputs, total_input_satoshis, consumed_utxos_details

def _build_op_return_script(data_pushes: List[bytes], note: Optional[str] = None) -> Optional[Script]:
    """Constructs the OP_FALSE OP_RETURN script with appropriate push opcodes."""
    script_bytes = bytes.fromhex("006a") # OP_FALSE OP_RETURN

    all_pushes = list(data_pushes)
    if note:
        all_pushes.extend([core_defs.AUDIT_MODE_NOTE, note.encode('utf-8')])

    for data in all_pushes:
        length = len(data)
        if length < 76:
            script_bytes += bytes([length])
        elif length <= 255:
            script_bytes += bytes.fromhex("4c") + length.to_bytes(1, 'little')
        elif length <= 65535:
            script_bytes += bytes.fromhex("4d") + length.to_bytes(2, 'little')
        elif length <= 4294967295:
            script_bytes += bytes.fromhex("4e") + length.to_bytes(4, 'little')
        else:
            logger.error("Data push too large.")
            return None
        script_bytes += data
    
    return Script(script_bytes.hex())

#endregion




async def create_op_return_transaction(
        spending_key_wif: str,
        recipient_address: str, 
        op_return_data_pushes: List[bytes],
        original_audit_content_string: Optional[str],  # should deprecate
        network: Network,
        current_utxo_store_data: Dict,
        tx_store: Dict,
        f_tx_store: IO, 
        note: Optional[str] = None,
        dry_run: bool = False,
        no_broadcast: bool = False
) -> tuple[Optional[str], Optional[str], Optional[str], List[Dict], List[Dict], Optional[int]]:
    """
    Creates a Bitcoin SV transaction with an OP_RETURN output and returns change.

    Args:
        spending_key_wif (str): The WIF of the private key used to fund the transaction.
        recipient_address (str): The address to send change to (or a small payment if included).
        op_return_data_pushes (List[bytes]): List of byte strings to be pushed into OP_RETURN.
        original_audit_content_string Optional[Str]: The original string content for internal verification/hashing. (deprecate?)
        network (Network): The bsv.Network object for the transaction.
        utxo_file_path (str): The file path for the UTXO store.
        tx_store (Dict): The memory reference to store. Only store outside!
        tx_file_path (str): The file path for the transaction store.
        note (Optional[str]): An optional note to be added as a fourth data push to OP_RETURN.
        dry_run (Bool): do not broadcast if true
    
    Returns:
        tuple[Optional[str], Optional[str], Optional[str], List[Dict], List[Dict], Optional[int]]:
            Now returns (raw_tx_hex, timestamp_broadcasted, txid, consumed_utxos_details, new_utxos_details, calculated_fee).
    """
    logger.info(f"\n--- Creating OP_RETURN Transaction from {recipient_address} ---")
    
    op_return_script = _build_op_return_script(op_return_data_pushes, note)
    if not op_return_script:
        return None, None, None, [], [], None

    logger.info(f"OP_RETURN script (Hex): {op_return_script.hex()}")
    
    core_defs.print_op_return_scriptpubkey(op_return_script)


    # 2. Prepare Inputs
    # We ask for a bit more than strictly necessary to be safe with fees initially
    TARGET_INPUT_AMOUNT = Config.LOGGING_UTXO_THRESHOLD 
    tx_inputs, total_input_sats, consumed_details = await _fetch_inputs_for_amount(
        TARGET_INPUT_AMOUNT, current_utxo_store_data, tx_store, spending_key_wif, network
    )


    if not tx_inputs:
        logger.warning(f"No usable UTXOs found for address {recipient_address} after fetching source transactions. Cannot create transaction.")
        return None, None, None, [], [], None
    
    if original_audit_content_string is not None:
        logger.info(f"  Attempting to create transaction for content: '{original_audit_content_string}'")

    # OP_RETURN outputs are unspendable and have 0 value
    # Dummy value, bsv-sdk overwrites is with actual change
    # Mark as change output for automatic fee calculation
    tx_outputs = [
        TransactionOutput(locking_script=op_return_script, satoshis=0, change=False),
        TransactionOutput(locking_script=P2PKH().lock(recipient_address), satoshis=1, change=True)
    ]

    # 5. Assemble the transaction
    tx = Transaction(tx_inputs, tx_outputs)

    #region Debug Outputs + Satoshis
    logger.info("\n--- DEBUG: Transaction Outputs IMMEDIATELY after assembly ---")
    if not tx.outputs:
        logger.info("    No outputs found in transaction immediately after assembly.")
    else:
        for i, output in enumerate(tx.outputs):
            is_op_return_flag = " (OP_RETURN)" if output.locking_script.chunks and output.locking_script.chunks[0].op == 0x6a else ""
            logger.info(f"    Output {i}: Satoshis={output.satoshis}, Script ASM={output.locking_script.to_asm()}{is_op_return_flag}")
    logger.info("------------------------------------------------------------")
    #endregion

    
    tx.fee(SatoshisPerKilobyte(value=Config.FEE_STRATEGY)) 



    # After tx.fee() has been called, retrieve the fee by summing inputs and subtracting outputs.
    # This is the most reliable way to get the *actual* fee determined by the SDK.
    total_output_sats = sum(output.satoshis for output in tx.outputs)
    calculated_fee = total_input_sats - total_output_sats
    
    logger.info(f"Total Input Satoshis: {total_input_sats}")
    logger.info(f"Total Output Satoshis (including OP_RETURN and change): {total_output_sats}")
    logger.info(f"Calculated Fee for new transaction: {calculated_fee} satoshis")
    
    # Check if there are enough funds for the OP_RETURN output (0 satoshis) + fee
    # And critically, if there's enough for a reasonable change output.
    # The SDK handles the change output automatically, so we just need to ensure inputs cover it.
    if total_input_sats < calculated_fee:
        logger.error(f"Insufficient funds for transaction. Total inputs: {total_input_sats}, required for fee: {calculated_fee}.")
        return None, None, None, [], [], calculated_fee
    
    change_output_sats = tx_outputs[1].satoshis

    if change_output_sats < 1 and change_output_sats != 0: 
        logger.warning(f"Warning: Calculated change output ({change_output_sats} satoshis) is too low. It might be discarded by miners or not be a valid UTXO.")


    min_utxo_val = 546 # (is the default dust limit in BTC)
    if Config.ACTIVE_NETWORK_NAME == "test":
        min_utxo_val = Config.MINIMUM_UTXO_VALUE_TESTNET
    else:
        min_utxo_val = Config.MINIMUM_UTXO_VALUE

    if 0 < change_output_sats < min_utxo_val: 
        logger.error(f"DUST ERROR: The calculated change ({change_output_sats} satoshis) is below the dust limit. Aborting transaction.")
        return None, None, None, [], [], None

    if total_input_sats < calculated_fee:
        logger.error(f"Insufficient funds for transaction. Total inputs: {total_input_sats}, required for fee: {calculated_fee}.")
        return None, None, None, [], [], None
    
    tx.sign()

    ## 5. Handle Result
    
    raw_tx_hex = tx.hex()
    txid = tx.txid()

    logger.info(f"New Transaction ID: {txid}")
    logger.info(f"New Transaction Raw Hex: {raw_tx_hex}")

    # region DRY RUN happy path (return)
    if dry_run:
        # Find Change-Output: look for Script matching receiver address
        expected_change_script_hex = P2PKH().lock(recipient_address).hex()
        change_output = next((o for o in tx.outputs if o.locking_script.hex() == expected_change_script_hex), None)
        change_sats = change_output.satoshis if change_output else 0
        
        logger.info("\n--- DRY RUN ---")
        logger.info(f"Final Calculated Fee: {calculated_fee} satoshis")
        logger.info(f"Input Satoshis: {total_input_sats}")
        logger.info(f"Change Output: {change_sats} satoshis")
        
        # check Dust-Limit
        if change_sats > 0 and change_sats < min_utxo_val:
             logger.warning(f"DUST LIMIT WARNING: Change output is below the typical dust threshold of {min_utxo_val} satoshis.")
        else:
             logger.info("Change output appears to be safely above the dust limit.")
             
        logger.info("Transaction will NOT be broadcast. Exiting now.")
        
        # Stop befire broadcast ,  broadcast_txid ist None to avoid writing logs.
        return tx.hex(), None, None, consumed_details, [], calculated_fee
    #endregion

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
    
    broadcast_txid = None
    broadcast_ts = None

    if no_broadcast:
        # --- Simulate a successful broadcast locally
        logger.info("\n--- NO-BROADCAST MODE ---")
        logger.info("Simulating successful broadcast. Local stores will be updated.")
        broadcast_txid = tx.txid()
        broadcast_timestamp = datetime.now(timezone.utc).isoformat()
    else:
        # Normal broadcast logic
        broadcast_txid = await blockchain_api.broadcast_transaction(tx.hex())
        broadcast_timestamp = datetime.now(timezone.utc).isoformat() if broadcast_txid else None



    # --- Important: Move UTXO marking logic to the calling function (log_intermediate_result_process) ---
    # The actual marking of UTXOs as used, and storing new UTXOs created by this transaction,
    # should ideally happen at a higher level of abstraction, where the impact on the wallet state
    # is fully managed. This keeps create_op_return_transaction focused on just building/broadcasting one TX.
    # For now, we'll keep the `used_utxos_for_this_tx` list here and let the calling function handle it.

    # Identify and collect details of NEW UTXOs created by this transaction for the caller
    new_utxos_details = []
    if broadcast_txid:
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
        return tx.hex(), broadcast_timestamp, broadcast_txid, consumed_details, new_utxos_details, calculated_fee
    else:
        return None, None, None, [], [], None # Return empty lists for UTXO changes on failure




