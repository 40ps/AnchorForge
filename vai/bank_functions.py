# bank_functions.py

import asyncio
import httpx # For making asynchronous HTTP requests
import json
import hashlib # Standard Python hashlib module for SHA256 (used for checksum in address derivation)
import base58 # Library for Base58 encoding/decoding
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid # for generating unique identifiers
import logging

from config import Config
import blockchain_api
import wallet_manager
import audit_core

from bsv import (
    PrivateKey, PublicKey,
    P2PKH, 
    Transaction, TransactionInput, TransactionOutput, 
    Network, Script, SatoshisPerKilobyte, 
    hash256
)

from bsv.hash import sha256 # Import sha256 function directly from bsv.hash module

from bsv import UnlockingScriptTemplate 
from typing import cast

logger = logging.getLogger(__name__)

async def load_bank(private_key_wif: str) -> Optional[str]:
    """
    Transfers all UTXOs from the address corresponding to `private_key_wif` to the bank address.
    This serves to "fund" the bank from another address.

    Args:
        private_key_wif (str): The WIF of the private key of the source address whose UTXOs are to be sent to the bank.

    Returns:
        str | None: The raw hexadecimal representation of the signed transaction, or None if it failed.
    """
    logger.info("\n--- Transferring UTXOs to the Bank from another Address ---")

    priv_key_sender = PrivateKey(private_key_wif, network=Config.ACTIVE_NETWORK_BSV)
    sender_address = priv_key_sender.address()
    
    logger.info(f"  Source Address: {sender_address}")
    logger.info(f"  Destination Address (Bank): {Config.BANK_ADDRESS}")

    utxos = await blockchain_api.fetch_utxos_for_address(str(sender_address))

    if not utxos:
        logger.info(f"  No UTXOs found for address {sender_address}. Nothing to send to the bank.")
        return None

    tx_inputs = []
    total_input_satoshis = 0
    for utxo in utxos:
        raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(utxo['txid'])
        if raw_source_tx_hex is None:
            logger.warning(f"  Skipping UTXO {utxo['txid']}:{utxo['vout']} from {sender_address} due to a failure to retrieve the source transaction.")
            continue
        
        source_tx_obj = Transaction.from_hex(raw_source_tx_hex)
        
        tx_inputs.append(TransactionInput(
            source_transaction=source_tx_obj,
            source_txid=utxo['txid'],
            source_output_index=utxo['vout'],
            unlocking_script_template=cast(UnlockingScriptTemplate, P2PKH().unlock(priv_key_sender)),
        ))
        total_input_satoshis += utxo['satoshis']

    if not tx_inputs:
        logger.warning(f"  No usable UTXOs found for address {sender_address} after retrieving source transactions. Cannot transfer to bank.")
        return None

    # Creates a single output to the BANK_ADDRESS
    assert Config.BANK_ADDRESS is not None
    tx_output_to_bank = TransactionOutput(
        locking_script=P2PKH().lock(Config.BANK_ADDRESS),
        change=True # The remainder (reduced by fee) goes to the bank
    )

    # Builds the transaction
    tx = Transaction(tx_inputs, [tx_output_to_bank])

    # Calculates the fee. Calls tx.fee() to let the SDK estimate the fee and adjust the outputs.
    tx.fee(SatoshisPerKilobyte(value=Config.FEE_STRATEGY)) 
    calculated_fee = total_input_satoshis - sum(output.satoshis for output in tx.outputs)

    logger.info(f"  Total inputs from {sender_address}: {total_input_satoshis} satoshis")
    logger.info(f"  Calculated fee for transfer to bank: {calculated_fee} satoshis")

    if total_input_satoshis <= calculated_fee:
        logger.error(f"  Insufficient funds for transfer to the bank. Total inputs: {total_input_satoshis}, required fee: {calculated_fee}.")
        return None

    tx.sign() 

    logger.info(f"  Bank Transfer Transaction ID: {tx.txid()}")
    logger.info(f"  Bank Transfer Raw Hex: {tx.hex()}")

    return tx.hex()

async def consolidate_utxos(private_key_wif: str) -> Optional[str]:
    """
    Consolidates all UTXOs belonging to a private key's address into a single output
    back to the same address, effectively sweeping multiple small UTXOs into one.

    Args:
        private_key_wif (str): The WIF of the private key whose UTXOs are to be consolidated.

    Returns:
        str | None: The raw hexadecimal representation of the signed consolidation transaction,
                    or None if no UTXOs found or transaction creation fails.
    """
    logger.info("\n--- Consolidating UTXOs ---")

    priv_key = PrivateKey(private_key_wif, network=Config.ACTIVE_NETWORK_BSV)
    sender_address = priv_key.address()

    utxos = await blockchain_api.fetch_utxos_for_address(str(sender_address))

    if not utxos:
        logger.info(f"No UTXOs found for address {sender_address}. Nothing to consolidate.")
        return None

    tx_inputs = []
    total_input_satoshis = 0
    for utxo in utxos:
        raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(utxo['txid'])
        if raw_source_tx_hex is None:
            logger.warning(f"Skipping UTXO {utxo['txid']}:{utxo['vout']} due to failure to fetch source transaction.")
            continue
        
        source_tx_obj = Transaction.from_hex(raw_source_tx_hex)
        
        tx_inputs.append(TransactionInput(
            source_transaction=source_tx_obj,
            source_txid=utxo['txid'],
            source_output_index=utxo['vout'],
            unlocking_script_template=cast(UnlockingScriptTemplate, P2PKH().unlock(priv_key)),
        ))
        total_input_satoshis += utxo['satoshis']

    if not tx_inputs:
        logger.warning(f"No usable UTXOs found for address {sender_address} after fetching source transactions. Cannot consolidate.")
        return None

    tx_output_consolidated = TransactionOutput(
        locking_script=P2PKH().lock(str(sender_address)),
        change=True 
    )

    tx = Transaction(tx_inputs, [tx_output_consolidated])

    tx.fee(SatoshisPerKilobyte(value=Config.FEE_STRATEGY)) 
    calculated_fee = total_input_satoshis - sum(output.satoshis for output in tx.outputs)
    
    logger.info(f"Total UTXOs to consolidate: {len(utxos)}")
    logger.info(f"Total input value: {total_input_satoshis} satoshis")
    logger.info(f"Calculated consolidation fee: {calculated_fee} satoshis")

    if total_input_satoshis <= calculated_fee:
        logger.error(f"Insufficient funds for consolidation. Total inputs: {total_input_satoshis}, required for fee: {calculated_fee}.")
        return None

    tx.sign()

    logger.info(f"Consolidation Transaction ID: {tx.txid()}")
    logger.info(f"Consolidation Transaction Raw Hex: {tx.hex()}")

    return tx.hex()


async def consolidate_bank_utxos(private_key_wif: str) -> Optional[str]:
    """ 
    Collects all UTXOs of BANK_ADDRESS (using the provided private_key_wif) and sends it to BANK_ADDRESS.
    This is essentially a specialized consolidation function for the bank address.
    """
    logger.info(f"\n--- Consolidating Bank UTXOs for {Config.BANK_ADDRESS} ---")
    return await consolidate_utxos(private_key_wif)


async def consolidate_addresses_into_bank(private_key_wifs: list[str]) -> Optional[str]:
    """
    Moves all UTXOs of all addresses derived from `private_key_wifs` into one UTXO,
    sending the total consolidated amount to BANK_ADDRESS.

    Args:
        private_key_wifs (list[str]): A list of WIFs for private keys whose UTXOs are to be consolidated.

    Returns:
        str | None: The raw hexadecimal representation of the signed consolidation transaction,
                    or None if no UTXOs found or transaction creation fails.
    """
    logger.info("\n--- Consolidating Multiple Addresses into Bank ---")

    all_tx_inputs = []
    total_input_satoshis = 0
    priv_key_bank = PrivateKey(Config.PRIVATE_BANK_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
    
    for wif in private_key_wifs:
        current_priv_key = PrivateKey(wif, network=Config.ACTIVE_NETWORK_BSV)
        current_address = current_priv_key.address()
        logger.info(f"  Fetching UTXOs for address: {current_address}")
        
        utxos = await blockchain_api.fetch_utxos_for_address(str(current_address))
        
        if not utxos:
            logger.warning(f"  No UTXOs found for {current_address}. Skipping.")
            continue

        for utxo in utxos:
            raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(utxo['txid'])
            if raw_source_tx_hex is None:
                logger.warning(f"  Skipping UTXO {utxo['txid']}:{utxo['vout']} from {current_address} due to failure to fetch source transaction.")
                continue
            
            source_tx_obj = Transaction.from_hex(raw_source_tx_hex)
            
            all_tx_inputs.append(TransactionInput(
                source_transaction=source_tx_obj,
                source_txid=utxo['txid'],
                source_output_index=utxo['vout'],
                unlocking_script_template=cast(UnlockingScriptTemplate, P2PKH().unlock(current_priv_key)),
            ))
            total_input_satoshis += utxo['satoshis']

    if not all_tx_inputs:
        logger.warning("No usable UTXOs found across all provided addresses. Cannot consolidate into bank.")
        return None

    tx_output_to_bank = TransactionOutput(
        locking_script=P2PKH().lock(str(Config.BANK_ADDRESS)),
        change=True # This will act as the "change" to the bank address, covering all inputs minus fee
    )

    tx = Transaction(all_tx_inputs, [tx_output_to_bank])

    tx.fee(SatoshisPerKilobyte(value=Config.FEE_STRATEGY)) 
    calculated_fee = total_input_satoshis - sum(output.satoshis for output in tx.outputs)

    logger.info(f"Total Inputs from all addresses: {total_input_satoshis} satoshis")
    logger.info(f"Calculated consolidation to bank fee: {calculated_fee} satoshis")

    if total_input_satoshis <= calculated_fee:
        logger.error(f"Insufficient funds for consolidation into bank. Total inputs: {total_input_satoshis}, required for fee: {calculated_fee}.")
        return None

    tx.sign()

    logger.info(f"Consolidation to Bank Transaction ID: {tx.txid()}")
    logger.info(f"Consolidation to Bank Transaction Raw Hex: {tx.hex()}")

    return tx.hex()


async def create_working_utxos(recipient_address: str, utxo_value: int, num_utxos: int) -> Optional[str]:
    """
    Creates a transaction from PRIVATE_BANK_KEY that generates `num_utxos` (amount)
    new UTXOs, each with a value of `utxo_value` (size) satoshis, and sends them to `recipient_address`.
    Includes a change output back to the bank.

    Args:
        recipient_address (str): The address to send the new UTXOs to.
        utxo_value (int): The value in satoshis for each new UTXO.
        num_utxos (int): The number of new UTXOs to create.

    Returns:
        str | None: The raw hexadecimal representation of the signed transaction, or None if failed.
    """
    logger.info(f"\n--- Creating {num_utxos} Working UTXOs of {utxo_value} satoshis each ---")

    priv_key_bank = PrivateKey(Config.PRIVATE_BANK_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
    bank_address = priv_key_bank.address()

    utxos_from_bank = await blockchain_api.fetch_utxos_for_address(str(bank_address))

    if not utxos_from_bank:
        logger.info(f"No UTXOs found for bank address {bank_address}. Cannot create working UTXOs.")
        return None

    tx_inputs = []
    total_input_satoshis = 0
    for utxo in utxos_from_bank:
        raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(utxo['txid'])
        if raw_source_tx_hex is None:
            logger.warning(f"Skipping bank UTXO {utxo['txid']}:{utxo['vout']} due to failure to fetch source transaction.")
            continue
        
        source_tx_obj = Transaction.from_hex(raw_source_tx_hex)
        
        tx_inputs.append(TransactionInput(
            source_transaction=source_tx_obj,
            source_txid=utxo['txid'],
            source_output_index=utxo['vout'],
            unlocking_script_template=cast(UnlockingScriptTemplate, P2PKH().unlock(priv_key_bank)),
        ))
        total_input_satoshis += utxo['satoshis']

    if not tx_inputs:
        logger.warning(f"No usable bank UTXOs found after fetching source transactions. Cannot create working UTXOs.")
        return None

    tx_outputs = []
    for _ in range(num_utxos):
        tx_outputs.append(TransactionOutput(
            locking_script=P2PKH().lock(recipient_address),
            satoshis=utxo_value,
            change=False
        ))
    
    total_output_value = utxo_value * num_utxos

    tx_output_change_to_bank = TransactionOutput(
        locking_script=P2PKH().lock(str(bank_address)),
        change=True
    )
    tx_outputs.append(tx_output_change_to_bank)

    tx = Transaction(tx_inputs, tx_outputs)

    tx.fee(SatoshisPerKilobyte(value=Config.FEE_STRATEGY))
    calculated_fee = total_input_satoshis - sum(output.satoshis for output in tx.outputs)

    logger.info(f"Total Bank Input Satoshis: {total_input_satoshis}")
    logger.info(f"Total value of new UTXOs: {total_output_value} satoshis")
    logger.info(f"Calculated fee for creating UTXOs: {calculated_fee} satoshis")
    
    required_funds = total_output_value + calculated_fee
    if total_input_satoshis < required_funds:
        logger.error(f"Insufficient funds in bank for creating UTXOs. Total inputs: {total_input_satoshis}, required: {required_funds}.")
        return None

    tx.sign()

    logger.info(f"Created Working UTXOs Transaction ID: {tx.txid()}")
    logger.info(f"Created Working UTXOs Transaction Raw Hex: {tx.hex()}")

    return tx.hex()

async def log_intermediate_result_process(utxo_file_path: str, used_utxo_file_path: str, tx_file_path: str):
    """
    Orchestrates the process of creating and broadcasting an audit record.
    This function now accepts dynamic file paths for the local stores.

    Args:
        utxo_file_path (str): The file path for the UTXO store.
        used_utxo_file_path (str): The file path for the used UTXO store.
        tx_file_path (str): The file path for the transaction store.
    """
    priv_key_funding = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
    sender_address = priv_key_funding.address()

    # 1. Load local stores using the provided dynamic file paths.
    store = wallet_manager.load_utxo_store(utxo_file_path)
    used_store = wallet_manager.load_used_utxo_store(used_utxo_file_path)
    tx_store = wallet_manager.load_tx_store(tx_file_path)

    if store.get("address") != str(sender_address) or store.get("network") != Config.ACTIVE_NETWORK_NAME:
         logger.warning(f"Warning: UTXO store address/network ({store.get('address', 'N/A')}/{store.get('network')}) does not match sender address/network ({sender_address}/{Config.ACTIVE_NETWORK_NAME}). Please run main_wallet_setup.py first to initialize stores for this address.")
         return

    if tx_store.get("address") != str(sender_address) or tx_store.get("network") != Config.ACTIVE_NETWORK_NAME:
        logger.warning(f"Warning: TX store address/network ({tx_store.get('address', 'N/A')}/{tx_store.get('network')}) does not match sender address/network ({sender_address}/{Config.ACTIVE_NETWORK_NAME}). Please run main_wallet_setup.py first to initialize stores for this address.")
        return


    # --- SIMULATE AN INTERMEDIATE PROCESS RESULT ---
    # Generate the original content that needs to be audited.
    timestamp_str = datetime.now(timezone.utc).isoformat()
    intermediate_audit_content_string = f"Audit Log Entry: Process step completed at {timestamp_str}. Result: SUCCESS. [Germany Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"
    
    logger.info(f"\n--- Simulating New Audit Content ---")
    logger.info(f"  Content to be logged: '{intermediate_audit_content_string}'")

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
    logger.info(f"Initial audit record '{audit_record_entry['log_id']}' saved to {Config.AUDIT_LOG_FILE}.")

    assert Config.UTXO_STORE_KEY_WIF is not None, "UTXO_STORE_KEY has to be set"
    # 2. Create the blockchain transaction containing the audit payload.
    tx_hex_returned, broadcast_timestamp_str, broadcast_txid, \
        consumed_utxos_details, new_utxos_details = await audit_core.create_op_return_transaction(
            spending_key_wif=Config.UTXO_STORE_KEY_WIF, 
            recipient_address=str(sender_address),
            op_return_data_pushes=op_return_payload_for_tx,
            original_audit_content_string=intermediate_audit_content_string,
            network=Config.ACTIVE_NETWORK_BSV,
            utxo_file_path=utxo_file_path,  # Now passing the correct argument
            tx_file_path=tx_file_path # Pass the dynamic TX store path
    )

    # 3. Update the audit record with broadcast details and handle UTXO state
    if tx_hex_returned:
        if broadcast_txid is None:
            logger.error(f"\nERROR: Transaction created but not broadcasted")
        else:
            logger.info(f"\nTransaction created & broadcasted: {broadcast_txid[:100]}...")

        audit_record_entry["blockchain_record"]["txid"] = broadcast_txid
        audit_record_entry["blockchain_record"]["raw_transaction_hex"] = tx_hex_returned
        audit_record_entry["blockchain_record"]["status"] = "broadcasted"
        audit_record_entry["blockchain_record"]["timestamp_broadcasted_utc"] = broadcast_timestamp_str
        
        # Update UTXO stores (move consumed to used_store, add new to store)
        logger.info(f"Updating local UTXO stores for TXID {broadcast_txid}...")
        
        # We need to re-load the stores to ensure they are consistent after the transaction creation/broadcast
        store = wallet_manager.load_utxo_store(utxo_file_path)
        used_store = wallet_manager.load_used_utxo_store(used_utxo_file_path)
        
        for consumed_utxo in consumed_utxos_details:
            store["utxos"] = [u for u in store["utxos"] if not (u["txid"] == consumed_utxo["txid"] and u["vout"] == consumed_utxo["vout"])]
            
            consumed_utxo["used"] = True
            consumed_utxo["used_in_txid"] = broadcast_txid
            consumed_utxo["used_timestamp"] = datetime.now(timezone.utc).isoformat()
            used_store["used_utxos"].append(consumed_utxo)
            logger.info(f"  - Consumed UTXO: {consumed_utxo['txid']}:{consumed_utxo['vout']}")

        for new_utxo in new_utxos_details:
            store["utxos"].append(new_utxo)
            logger.info(f"  - New UTXO created: {new_utxo['txid']}:{new_utxo['vout']} ({new_utxo['satoshis']} sats)")
        
        wallet_manager.save_utxo_store(store, utxo_file_path)
        wallet_manager.save_used_utxo_store(used_store, used_utxo_file_path)
        logger.info("Local UTXO stores updated.")

        audit_core.save_audit_log(audit_log) 
        logger.info(f"Audit record '{audit_record_entry['log_id']}' updated with TXID {broadcast_txid} and broadcast status.")

        original_hash_expected = sha256(intermediate_audit_content_string.encode('utf-8'))
        original_public_key_hex_expected = PrivateKey(Config.PRIVATE_SIGNING_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV).public_key().hex()

        verification_passed = await audit_core.verify_op_return_hash_sig_pub(
            tx_hex_returned,
            original_hash_expected,
            original_public_key_hex_expected
        )
        logger.info(f"\nOP_RETURN Hash/Signature/Public Key Verification (pre-confirmation): { 'PASS' if verification_passed else 'FAIL' }")

    else:
        audit_record_entry["blockchain_record"]["status"] = "tx_creation_failed"
        audit_core.save_audit_log(audit_log)
        logger.error(f"\nFailed to create or broadcast transaction for audit record '{audit_record_entry['log_id']}'. Status updated.")
    
    logger.info("\nEnd log_intermediate_result_process.")
