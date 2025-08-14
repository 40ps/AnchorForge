'''
import asyncio
import httpx # For making asynchronous HTTP requests
import json
import hashlib # Standard Python hashlib module for SHA256 (used for checksum in address derivation)
import base58 # Library for Base58 encoding/decoding
'''
from typing import List, Dict
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

async def load_bank(private_key_wif: str) -> str | None:
    """
    Überweist alle UTXOs der Adresse, die dem `private_key_wif` entspricht, an die Bankadresse.
    Dies dient zum "Aufladen" der Bank von einer anderen Adresse.

    Argumente:
        private_key_wif (str): Der WIF des Privatschlüssels der Quelladresse, deren UTXOs an die Bank gesendet werden sollen.

    Gibt zurück:
        str | None: Die rohe hexadezimale Darstellung der signierten Transaktion, oder None, wenn fehlgeschlagen.
    """
    print(f"\n--- Überweisung von UTXOs an die Bank von einer anderen Adresse ---")

    priv_key_sender = PrivateKey(private_key_wif, network=Config.ACTIVE_NETWORK_BSV)
    sender_address = priv_key_sender.address()
    
    print(f"  Quelladresse: {sender_address}")
    print(f"  Zieladresse (Bank): {Config.BANK_ADDRESS}")

    utxos = await blockchain_api.fetch_utxos_for_address(sender_address)

    if not utxos:
        print(f"  Keine UTXOs für Adresse {sender_address} gefunden. Nichts an die Bank zu senden.")
        return None

    tx_inputs = []
    total_input_satoshis = 0
    for utxo in utxos:
        raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(utxo['txid'])
        if raw_source_tx_hex is None:
            print(f"  Überspringe UTXO {utxo['txid']}:{utxo['vout']} von {sender_address} aufgrund eines Fehlers beim Abrufen der Quelltransaktion.")
            continue
        
        source_tx_obj = Transaction.from_hex(raw_source_tx_hex)
        
        #unlocking_script_template = P2PKH(private_key=priv_key_sender)
        tx_inputs.append(TransactionInput(
            source_transaction=source_tx_obj,
            source_txid=utxo['txid'],
            source_output_index=utxo['vout'],
            #unlocking_script_template=P2PKH().unlock(priv_key_sender), # Verwende den Absender-Privatschlüssel für diese Eingabe
            unlocking_script_template=cast(UnlockingScriptTemplate, P2PKH().unlock(priv_key_sender)),
        ))
        total_input_satoshis += utxo['satoshis']

    if not tx_inputs:
        print(f"  Keine verwendbaren UTXOs für Adresse {sender_address} nach dem Abrufen der Quelltransaktionen gefunden. Überweisung an Bank nicht möglich.")
        return None

    # Erstellt eine einzelne Ausgabe an die BANK_ADDRESS
    assert Config.BANK_ADDRESS is not None

    tx_output_to_bank = TransactionOutput(
        locking_script=P2PKH().lock(Config.BANK_ADDRESS),
        change=True # Restbetrag (reduced by fee) go to bank
                    # `change=True` an einer Ausgabe in einer Transaktion mit nur einer Ausgabe
                    # bewirkt, dass diese Ausgabe den gesamten Restbetrag erhält.
    )

    # Baut die Transaktion zusammen
    tx = Transaction(tx_inputs, [tx_output_to_bank])

    # Berechnet die Gebühr. Ruft tx.fee() auf, um das SDK die Gebühr schätzen und die Ausgaben anpassen zu lassen.
    tx.fee(SatoshisPerKilobyte(value=Config.FEE_STRATEGY)) 
    calculated_fee = total_input_satoshis - sum(output.satoshis for output in tx.outputs)

    print(f"  Gesamte Eingaben von {sender_address}: {total_input_satoshis} Satoshis")
    print(f"  Berechnete Gebühr für Überweisung an Bank: {calculated_fee} Satoshis")

    if total_input_satoshis <= calculated_fee:
        print(f"  Unzureichende Mittel für die Überweisung an die Bank. Gesamte Eingaben: {total_input_satoshis}, Gebühr erforderlich: {calculated_fee}.")
        return None

    tx.sign() # Die Transaktion wird mit dem Absender-Privatschlüssel signiert.

    print(f"  Überweisung an Bank Transaktions-ID: {tx.txid()}")
    print(f"  Überweisung an Bank Transaktion Roh-Hex: {tx.hex()}")

    return tx.hex()

async def consolidate_utxos(private_key_wif: str) -> str | None:
    """
    Consolidates all UTXOs belonging to a private key's address into a single output
    back to the same address, effectively sweeping multiple small UTXOs into one.

    Args:
        private_key_wif (str): The WIF of the private key whose UTXOs are to be consolidated.

    Returns:
        str | None: The raw hexadecimal representation of the signed consolidation transaction,
                    or None if no UTXOs found or transaction creation fails.
    """
    print("\n--- Consolidating UTXOs ---")

    priv_key = PrivateKey(private_key_wif, network=Config.ACTIVE_NETWORK_BSV)
    sender_address = priv_key.address()

    # Fetch all UTXOs for the address
    utxos = await blockchain_api.fetch_utxos_for_address(sender_address)

    if not utxos:
        print(f"No UTXOs found for address {sender_address}. Nothing to consolidate.")
        return None

    tx_inputs = []
    total_input_satoshis = 0
    # Fetch full source transactions for each UTXO as required by bsv-sdk
    for utxo in utxos:
        raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(utxo['txid'])
        if raw_source_tx_hex is None:
            print(f"Skipping UTXO {utxo['txid']}:{utxo['vout']} due to failure to fetch source transaction.")
            continue
        
        source_tx_obj = Transaction.from_hex(raw_source_tx_hex)
        
        tx_inputs.append(TransactionInput(
            source_transaction=source_tx_obj,
            source_txid=utxo['txid'],
            source_output_index=utxo['vout'],
            # unlocking_script_template=P2PKH().unlock(priv_key),
            unlocking_script_template=cast(UnlockingScriptTemplate, P2PKH().unlock(priv_key)),
        ))
        total_input_satoshis += utxo['satoshis']

    if not tx_inputs:
        print(f"No usable UTXOs found for address {sender_address} after fetching source transactions. Cannot consolidate.")
        return None

    # Create a single output sending all funds back to the sender's address
    # Mark it as change=True so the SDK calculates the exact amount after fees
    tx_output_consolidated = TransactionOutput(
        locking_script=P2PKH().lock(sender_address),
        change=True # This output will receive the sum of inputs minus fees
    )

    # Assemble the transaction
    tx = Transaction(tx_inputs, [tx_output_consolidated])

    # Calculate fee. Call tx.fee() to let the SDK adjust the change output.
    tx.fee(SatoshisPerKilobyte(value=Config.FEE_STRATEGY)) 
    # After tx.fee() has been called, retrieve the fee by summing inputs and subtracting outputs.
    calculated_fee = total_input_satoshis - sum(output.satoshis for output in tx.outputs)
    
    print(f"Total UTXOs to consolidate: {len(utxos)}")
    print(f"Total input value: {total_input_satoshis} satoshis")
    print(f"Calculated consolidation fee: {calculated_fee} satoshis")

    if total_input_satoshis <= calculated_fee:
        print(f"Insufficient funds for consolidation. Total inputs: {total_input_satoshis}, required for fee: {calculated_fee}.")
        return None

    tx.sign()

    print(f"Consolidation Transaction ID: {tx.txid()}")
    print(f"Consolidation Transaction Raw Hex: {tx.hex()}")

    return tx.hex()


async def consolidate_bank_utxos(private_key_wif: str) -> str | None:
    """ 
    Collects all UTXOs of BANK_ADDRESS (using the provided private_key_wif) and sends it to BANK_ADDRESS.
    This is essentially a specialized consolidation function for the bank address.
    """
    print(f"\n--- Consolidating Bank UTXOs for {Config.BANK_ADDRESS} ---")
    return await consolidate_utxos(private_key_wif)


async def consolidate_addresses_into_bank(private_key_wifs: list[str]) -> str | None:
    """
    Moves all UTXOs of all addresses derived from `private_key_wifs` into one UTXO,
    sending the total consolidated amount to BANK_ADDRESS.

    Args:
        private_key_wifs (list[str]): A list of WIFs for private keys whose UTXOs are to be consolidated.

    Returns:
        str | None: The raw hexadecimal representation of the signed consolidation transaction,
                    or None if no UTXOs found or transaction creation fails.
    """
    print("\n--- Consolidating Multiple Addresses into Bank ---")

    all_tx_inputs = []
    total_input_satoshis = 0
    priv_key_bank = PrivateKey(Config.PRIVATE_BANK_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV) # Bank key for signing the consolidation
    
    for wif in private_key_wifs:
        current_priv_key = PrivateKey(wif, network=Config.ACTIVE_NETWORK_BSV)
        current_address = current_priv_key.address()
        print(f"  Fetching UTXOs for address: {current_address}")
        
        utxos = await blockchain_api.fetch_utxos_for_address(current_address)
        
        if not utxos:
            print(f"  No UTXOs found for {current_address}. Skipping.")
            continue

        for utxo in utxos:
            raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(utxo['txid'])
            if raw_source_tx_hex is None:
                print(f"  Skipping UTXO {utxo['txid']}:{utxo['vout']} from {current_address} due to failure to fetch source transaction.")
                continue
            
            source_tx_obj = Transaction.from_hex(raw_source_tx_hex)
            
            all_tx_inputs.append(TransactionInput(
                source_transaction=source_tx_obj,
                source_txid=utxo['txid'],
                source_output_index=utxo['vout'],
                #unlocking_script_template=P2PKH().unlock(current_priv_key), # Use the specific private key for this input
                unlocking_script_template=cast(UnlockingScriptTemplate, P2PKH().unlock(current_priv_key)),
            ))
            total_input_satoshis += utxo['satoshis']

    if not all_tx_inputs:
        print("No usable UTXOs found across all provided addresses. Cannot consolidate into bank.")
        return None

    # Create a single output to the BANK_ADDRESS
    tx_output_to_bank = TransactionOutput(
        locking_script=P2PKH().lock(str(Config.BANK_ADDRESS)),
        change=True # This will act as the "change" to the bank address, covering all inputs minus fee
    )

    # Assemble the transaction
    tx = Transaction(all_tx_inputs, [tx_output_to_bank])

    # Calculate fee and sign. We use the bank's private key to sign this consolidation transaction.
    tx.fee(SatoshisPerKilobyte(value=Config.FEE_STRATEGY)) 
    calculated_fee = total_input_satoshis - sum(output.satoshis for output in tx.outputs)

    print(f"Total Inputs from all addresses: {total_input_satoshis} satoshis")
    print(f"Calculated consolidation fee to bank: {calculated_fee} satoshis")

    if total_input_satoshis <= calculated_fee:
        print(f"Insufficient funds for consolidation into bank. Total inputs: {total_input_satoshis}, required for fee: {calculated_fee}.")
        return None

    tx.sign() # Signing with the bank key will cover all inputs if their private keys are implicitly handled by the input templates.
              # Note: For multi-input transactions where inputs come from different private keys,
              # `tx.sign()` must be able to associate the correct private key with each `TransactionInput`.
              # The `bsv-sdk`'s `tx.sign()` method takes `key` or `keys` parameter, which handles this.
              # Since each input's `unlocking_script_template` was created with `P2PKH().unlock(current_priv_key)`,
              # the `tx.sign()` should correctly pick up the necessary keys from these templates.

    print(f"Consolidation to Bank Transaction ID: {tx.txid()}")
    print(f"Consolidation to Bank Transaction Raw Hex: {tx.hex()}")

    return tx.hex()


async def create_working_utxos(recipient_address: str, utxo_value: int, num_utxos: int) -> str | None:
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
    print(f"\n--- Creating {num_utxos} Working UTXOs of {utxo_value} satoshis each ---")

    priv_key_bank = PrivateKey(Config.PRIVATE_BANK_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)


    assert Config.BANK_ADDRESS is not None
    bank_address = Config.BANK_ADDRESS

    # Fetch all UTXOs belonging to the bank's address to fund this transaction
    utxos_from_bank = await blockchain_api.fetch_utxos_for_address(bank_address)

    if not utxos_from_bank:
        print(f"No UTXOs found for bank address {bank_address}. Cannot create working UTXOs.")
        return None

    tx_inputs = []
    total_input_satoshis = 0
    # Fetch full source transactions for each bank UTXO
    for utxo in utxos_from_bank:
        raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(utxo['txid'])
        if raw_source_tx_hex is None:
            print(f"Skipping bank UTXO {utxo['txid']}:{utxo['vout']} due to failure to fetch source transaction.")
            continue
        
        source_tx_obj = Transaction.from_hex(raw_source_tx_hex)
        
        tx_inputs.append(TransactionInput(
            source_transaction=source_tx_obj,
            source_txid=utxo['txid'],
            source_output_index=utxo['vout'],
            # unlocking_script_template=P2PKH().unlock(priv_key_bank),
            unlocking_script_template=cast(UnlockingScriptTemplate, P2PKH().unlock(priv_key_bank)),
        ))
        total_input_satoshis += utxo['satoshis']

    if not tx_inputs:
        print(f"No usable bank UTXOs found after fetching source transactions. Cannot create working UTXOs.")
        return None

    # Create multiple outputs for the new working UTXOs
    tx_outputs = []
    for _ in range(num_utxos):
        tx_outputs.append(TransactionOutput(
            locking_script=P2PKH().lock(recipient_address),
            satoshis=utxo_value,
            change=False
        ))
    
    # Calculate the total amount for the new UTXOs
    total_output_value = utxo_value * num_utxos

    # Create the change output back to the bank
    tx_output_change_to_bank = TransactionOutput(
        locking_script=P2PKH().lock(bank_address),
        change=True # Mark as change output
    )
    tx_outputs.append(tx_output_change_to_bank) # Add change output to the list of outputs

    # Assemble the transaction
    tx = Transaction(tx_inputs, tx_outputs)

    # Calculate fee
    tx.fee(SatoshisPerKilobyte(value=Config.FEE_STRATEGY))
    calculated_fee = total_input_satoshis - sum(output.satoshis for output in tx.outputs)

    print(f"Total Bank Input Satoshis: {total_input_satoshis}")
    print(f"Total value of new UTXOs: {total_output_value} satoshis")
    print(f"Calculated fee for creating UTXOs: {calculated_fee} satoshis")
    
    # Check if there are enough funds
    required_funds = total_output_value + calculated_fee
    if total_input_satoshis < required_funds:
        print(f"Insufficient funds in bank for creating UTXOs. Total inputs: {total_input_satoshis}, required: {required_funds}.")
        return None

    tx.sign()

    print(f"Created Working UTXOs Transaction ID: {tx.txid()}")
    print(f"Created Working UTXOs Transaction Raw Hex: {tx.hex()}")

    return tx.hex()

async def log_intermediate_result_process():
    priv_key_funding = PrivateKey(Config.UTXO_STORE_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV)
    sender_address = priv_key_funding.address()


    # 1. Load local stores here, as this function manages their state updates.
    store = wallet_manager.load_utxo_store()
    used_store = wallet_manager.load_used_utxo_store()
    tx_store = wallet_manager.load_tx_store() # This is also needed for UTXO resolution by create_op_return_transaction

    # Initial check if store addresses match sender_address. If not, initialize.
    # This ensures our local store is aligned with the key being used.
    if store.get("address") != sender_address:
         print(f"Warning: UTXO store address ({store.get('address', 'N/A')}) does not match sender address ({sender_address}). Re-initializing UTXO store for sender.")
         await wallet_manager.initialize_utxo_store(Config.UTXO_STORE_KEY_WIF) # Pass WIF string
         store = wallet_manager.load_utxo_store() # Reload after init

    if tx_store.get("address") != sender_address:
        print(f"Warning: TX store address ({tx_store.get('address', 'N/A')}) does not match sender address ({sender_address}). Re-initializing TX store for sender.")
        await wallet_manager.initialize_utxo_store(Config.UTXO_STORE_KEY_WIF) # Pass WIF string
        tx_store = wallet_manager.load_tx_store() # Reload after init
    


    # --- SIMULATE AN INTERMEDIATE PROCESS RESULT ---
    # Generate the original content that needs to be audited.
    timestamp_str = datetime.now(timezone.utc).isoformat()
    intermediate_audit_content_string = f"Audit Log Entry: Process step completed at {timestamp_str}. Result: SUCCESS. [Germany Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"
    
    print(f"\n--- Simulating New Audit Content ---")
    print(f"  Content to be logged: '{intermediate_audit_content_string}'")

    # --- BUILD THE OP_RETURN PAYLOAD (Hash, Sig, PubKey from content) ---
    assert Config.PRIVATE_BANK_KEY_WIF is not None
    own_signing_key = Config.PRIVATE_BANK_KEY_WIF
    op_return_payload_for_tx = audit_core.build_audit_payload(
        intermediate_audit_content_string, 
        own_signing_key
    )
    
    # Create a new audit record entry locally.
    # This record holds all details for the auditor, and its status will be updated over time.
    audit_record_entry = {
        "log_id": str(uuid.uuid4()), # Generate a unique ID for this specific log event
        "original_audit_content": intermediate_audit_content_string,
        "timestamp_logged_local": datetime.now(timezone.utc).isoformat(), # When this record was created locally
        "blockchain_record": { # This nested dictionary holds all blockchain-related proof info
            "txid": None, # Will be filled after transaction creation/broadcast
            "raw_transaction_hex": None, # Will be filled with the full transaction hex
            "data_hash_pushed_to_op_return": op_return_payload_for_tx[0].hex(),
            "signature_pushed_to_op_return": op_return_payload_for_tx[1].hex(),
            "public_key_pushed_to_op_return": op_return_payload_for_tx[2].hex(),
            "status": "pending_creation", # Initial status: Audit record exists, but TX is not created/broadcasted yet
            "timestamp_broadcasted_utc": None,
            "timestamp_confirmed_utc": None,
            "block_hash": None,
            "block_height": None,
            "merkle_proof_data": None
        },
        "notes": "Intermediate process result audit log entry"
    }
    
    # Save the initial audit record to the audit log file.
    audit_log = audit_core.load_audit_log()
    audit_log.append(audit_record_entry)
    audit_core.save_audit_log(audit_log)
    print(f"Initial audit record '{audit_record_entry['log_id']}' saved to {Config.AUDIT_LOG_FILE}.")


    # --- Prepare a snapshot of UTXOs before passing control to transaction creation ---
    # This allows `create_op_return_transaction` to select and use them,
    # and we can then apply the state changes back to the main `store`.
    # We must ensure that `create_op_return_transaction` is given *enough* context
    # to select UTXOs, but doesn't modify the overall `store` files itself.
    

    # This is a bit tricky with the current `create_op_return_transaction` design
    # because it loads stores internally.
    # We will adjust `create_op_return_transaction` to return `used_utxos_for_this_tx`
    # and `new_output_utxos_for_store` so this function can manage the updates.


    # 2. Create the blockchain transaction containing the audit payload.
    # This function now returns the full transaction hex, broadcast timestamp, and TXID.
    # It also handles broadcasting and initial updates to the rawtx cache (tx_store.json).
    assert Config.UTXO_STORE_KEY_WIF is not None, "UTXO_STORE_KEY_WIF must be set"
    
    tx_hex_returned, broadcast_timestamp_str, broadcast_txid, \
        consumed_utxos_details, new_utxos_details = await audit_core.create_op_return_transaction(
            spending_key_wif=Config.UTXO_STORE_KEY_WIF, 
            recipient_address=sender_address, # Change goes back here
            op_return_data_pushes=op_return_payload_for_tx,
            original_audit_content_string=intermediate_audit_content_string, # Pass original content for internal hashing/verification
            network=Config.ACTIVE_NETWORK_BSV
    )


    # 3. Update the audit record with broadcast details and handle UTXO state
    if tx_hex_returned: # Check if transaction creation/broadcast was successful
        if broadcast_txid is None:
            print(f"\nERROR: Transaction created but not broadcasted")
        else:
            print(f"\nTransaction created & broadcasted: {broadcast_txid[:100]}...")

        # 1 Update the audit record entry's blockchain_record details
        audit_record_entry["blockchain_record"]["txid"] = broadcast_txid
        audit_record_entry["blockchain_record"]["raw_transaction_hex"] = tx_hex_returned # Store the full raw transaction hex
        audit_record_entry["blockchain_record"]["status"] = "broadcasted"
        audit_record_entry["blockchain_record"]["timestamp_broadcasted_utc"] = broadcast_timestamp_str
        
         # 2. Update UTXO stores (move consumed to used_store, add new to store)
        print(f"Updating local UTXO stores for TXID {broadcast_txid}...")
        
        # Mark consumed UTXOs as used and move to used_store
        for consumed_utxo in consumed_utxos_details:
            # Remove from main store
            store["utxos"] = [u for u in store["utxos"] if not (u["txid"] == consumed_utxo["txid"] and u["vout"] == consumed_utxo["vout"])]
            
            # Add to used_store
            consumed_utxo["used"] = True
            consumed_utxo["used_in_txid"] = broadcast_txid
            consumed_utxo["used_timestamp"] = datetime.now(timezone.utc).isoformat()
            used_store["used_utxos"].append(consumed_utxo)
            print(f"  - Consumed UTXO: {consumed_utxo['txid']}:{consumed_utxo['vout']}")

        # Add new UTXOs (change outputs) to main store
        for new_utxo in new_utxos_details:
            store["utxos"].append(new_utxo)
            print(f"  - New UTXO created: {new_utxo['txid']}:{new_utxo['vout']} ({new_utxo['satoshis']} sats)")
        
        wallet_manager.save_utxo_store(store)
        wallet_manager.save_used_utxo_store(used_store)
        print("Local UTXO stores updated.")


        # Save the updated audit log after populating blockchain_record details.
        audit_core.save_audit_log(audit_log) 
        print(f"Audit record '{audit_record_entry['log_id']}' updated with TXID {broadcast_txid} and broadcast status.")

        # --- VERIFY THE TRANSACTION'S OP_RETURN CONTENT IMMEDIATELY (OPTIONAL BUT GOOD) ---
        # This verification uses the raw transaction hex that was just created.
        original_hash_expected = sha256(intermediate_audit_content_string.encode('utf-8'))
        original_public_key_hex_expected = PrivateKey(Config.PRIVATE_SIGNING_KEY_WIF, network=Config.ACTIVE_NETWORK_BSV).public_key().hex()

        verification_passed = await audit_core.verify_op_return_hash_sig_pub(
            tx_hex_returned, # Use the returned raw transaction hex for immediate verification
            original_hash_expected,
            original_public_key_hex_expected
        )
        print(f"\nOP_RETURN Hash/Signature/Public Key Verification (pre-confirmation): { 'PASS' if verification_passed else 'FAIL' }")

    else:
        # If transaction creation or broadcast failed, update the audit record status to reflect this.
        audit_record_entry["blockchain_record"]["status"] = "tx_creation_failed"
        audit_core.save_audit_log(audit_log)
        print(f"\nFailed to create or broadcast transaction for audit record '{audit_record_entry['log_id']}'. Status updated.")
    
    print("\nEnd log_intermediate_result_process.")
