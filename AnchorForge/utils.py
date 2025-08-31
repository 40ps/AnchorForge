

import logging
from typing import Dict
import httpx
import json

from bsv.hash import hash256 # Assuming hash256 is used by verify_block_hash
from bsv import Transaction # Assuming Transaction is used by deserialize_and_print_transaction
import base58 # Add to imports
import hashlib # Add to imports
from bsv import Script # Add to imports if Script is used directly here

from bsv import (
    PrivateKey,
    Transaction,
    Network, Script, 
    hash256
)

from bsv.hash import sha256 # Import sha256 function directly from bsv.hash module

from config import Config


logger = logging.getLogger(__name__)

def extract_testnet_address(locking_script_hex: str) -> str | None:
    """
    Attempts to extract a testnet P2PKH address from a locking script's hexadecimal representation.
    This function manually reconstructs the Base58Check encoding.

    Args:
        locking_script_hex (str): The hexadecimal string of the locking script.

    Returns:
        str | None: The derived testnet address string, or None if derivation fails or
                    it's not a standard P2PKH script.
    """
    try:
        # Convert hex locking script to Script object for chunk analysis
        script = Script(locking_script_hex)

        # A standard P2PKH locking script has 5 chunks:
        # OP_DUP OP_HASH160 <20-byte-pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
        chunks = script.chunks

        if not (
            len(chunks) == 5 and
            chunks[0].op == 0x76 and      # OP_DUP
            chunks[1].op == 0xa9 and      # OP_HASH160
            chunks[2].data and len(chunks[2].data) == 20 and # 20-byte public key hash
            chunks[3].op == 0x88 and      # OP_EQUALVERIFY
            chunks[4].op == 0xac         # OP_CHECKSIG
        ):
            # print("  Could not identify correct P2PKH script pattern based on opcodes and data length.")
            return None

        # Extract public key hash (which is the data from the 3rd chunk)
        pubkey_hash = chunks[2].data.hex()
        
        # Manually derive testnet address using Base58Check encoding rules for BSV testnet
        version_byte = bytes.fromhex('6f')  # BSV testnet P2PKH version byte (starts with 'm' or 'n')
        pubkey_hash_bytes = bytes.fromhex(pubkey_hash)
        
        # Concatenate version byte and pubkey hash
        payload = version_byte + pubkey_hash_bytes
        
        # Compute checksum: first 4 bytes of SHA256(SHA256(payload))
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        
        # Append checksum to payload
        full_payload = payload + checksum
        
        # Encode to Base58
        address = base58.b58encode(full_payload).decode('utf-8')
        
        return address

    except Exception as e:
        # print(f'  Error deriving address: {e}') # Suppress this for cleaner output when iterating
        return None



def is_transaction_signed(raw_tx_hex: str) -> bool:
    """
    Checks if a given raw transaction hex is fully signed.
    A transaction is considered signed if all its inputs have a non-empty unlocking script.

    Args:
        raw_tx_hex (str): The raw transaction in hexadecimal string format.

    Returns:
        bool: True if the transaction is signed (all inputs have non-empty unlocking scripts),
              False otherwise or if deserialization fails.
    """
    try:
        tx = Transaction.from_hex(raw_tx_hex)
        if tx is None:
            print(f"ERROR: No Transaction (NONE)")
            return False
        if not tx.inputs:
            return False # A transaction with no inputs can't be "signed" in the traditional sense

        for i, tx_input in enumerate(tx.inputs):
            # The unlocking script (script_sig) is what contains the signature(s) and public key(s)
            # If it's empty, it's typically an unsigned input.
            if not tx_input.unlocking_script or len(tx_input.unlocking_script.hex()) == 0:
                print(f"Input {i} has an empty unlocking script. Transaction is not fully signed.")
                return False
        
        print("All inputs have non-empty unlocking scripts. Transaction appears to be signed.")
        return True
    except Exception as e:
        print(f"Error checking if transaction is signed: {e}")
        return False



def deserialize_and_print_transaction(raw_tx_hex: str):
    """
    Deserializes a raw Bitcoin SV transaction hex string and prints its details in a readable format.
    Includes readable unlocking and locking scripts.

    Args:
        raw_tx_hex (str): The raw transaction in hexadecimal string format.
    """
    try:
        tx = Transaction.from_hex(raw_tx_hex)

        print("\n--- Transaction Details ---")

        if tx is None:
            print(f"ERROR: Tx is NONE")
            return
        print(f"Transaction ID (TXID): {tx.txid()}")
        print(f"Version: {tx.version}")
        print(f"Size: {len(raw_tx_hex) // 2} bytes") 

        print("\n--- Inputs ---")
        if not tx.inputs:
            print("No inputs found.")
        for i, tx_input in enumerate(tx.inputs):
            print(f"  Input {i}:")
            print(f"    Source TXID: {tx_input.source_txid}")
            print(f"    Source Output Index: {tx_input.source_output_index}")

            unlocking_script = tx_input.unlocking_script
            print(f"    Unlocking Script (Hex): {unlocking_script.hex()}")
            print(f"    Unlocking Script (ASM): {unlocking_script.to_asm()}")
            
            print(f"    Sequence: {tx_input.sequence}")

        print("\n--- Outputs ---")
        if not tx.outputs:
            print("No outputs found.")
        for i, tx_output in enumerate(tx.outputs):
            print(f"  Output {i}:")

            value_bsv = tx_output.satoshis / 100_000_000
            print(f"    Value: {value_bsv:.8f} BSV ({tx_output.satoshis} satoshis)")
            
            locking_script = tx_output.locking_script 
            print(f"    Locking Script (Hex): {locking_script.hex()}")
            print(f"    Locking Script (ASM): {locking_script.to_asm()}")

            # Call the new address extraction method here
            derived_address = extract_testnet_address(locking_script.hex())
            if derived_address:
                print(f"    Derived Address (Manual): {derived_address}")
            else:
                print(f"    (Could not derive a standard P2PKH address for this output: {locking_script.to_asm()})")

    except Exception as e:
        print(f"Error deserializing transaction: {e}")


def verify_block_hash(block_header: Dict) -> bool:
    """
    Verifiziert den Block-Hash durch Berechnung und Vergleich.
    
    Args:
        block_header (Dict): Block-Header-Daten (version, prevBlock, merkleRoot, time, bits, nonce).
    
    Returns:
        bool: True, wenn der berechnete Block-Hash mit dem erwarteten übereinstimmt.
    """
    try:
        # Extrahiere Block-Header-Felder (alle in Big-Endian als Hex-Strings)
        version = int(block_header["version"]).to_bytes(4, byteorder="little")
        prev_block = bytes.fromhex(block_header["previousblockhash"])[::-1]  # Little-Endian
        merkle_root = bytes.fromhex(block_header["merkleroot"])[::-1]  # Little-Endian
        time = int(block_header["time"]).to_bytes(4, byteorder="little")
        bits = int(block_header["bits"], 16).to_bytes(4, byteorder="little")
        nonce = int(block_header["nonce"]).to_bytes(4, byteorder="little")

        # Verkette die Felder in Little-Endian
        header = version + prev_block + merkle_root + time + bits + nonce
        print(f"Block-Header (Little-Endian): {header.hex()}")

        # Berechne den doppelten SHA256-Hash
        calculated_hash = hash256(header)[::-1]  # Konvertiere in Big-Endian für Vergleich
        expected_hash = block_header["hash"]
        print(f"Berechneter Block-Hash: {calculated_hash.hex()}")
        print(f"Erwarteter Block-Hash: {expected_hash}")
        return calculated_hash.hex() == expected_hash
    except (KeyError, ValueError) as e:
        print(f"Fehler bei der Verarbeitung des Block-Headers: {e}")
        return False


def verify_proof_of_work(block_hash: bytes, bits: str) -> bool:
    target = bits_to_target(int(bits, 16))  # Konvertiere bits in Zielwert
    return int.from_bytes(block_hash, "big") < target

def bits_to_target(bits: int) -> int:
    """Konvertiert das bits-Feld in einen Zielwert."""
    exponent = bits >> 24
    mantissa = bits & 0xFFFFFF
    target = mantissa << (8 * (exponent - 3))
    return target




        
async def get_merkle_proof(transaction_id: str) -> dict | None:
    """
    Fetches the Merkle proof for a given transaction ID from WhatsOnChain.

    Args:
        transaction_id (str): The TXID of the transaction to get the Merkle proof for.

    Returns:
        dict | None: A dictionary containing the Merkle proof details if successful, None otherwise.
                     The dictionary typically includes 'blockhash', 'merkleProof', 'txid', 'pos'.
    """
    #url = f"{Config.WOC_TESTNET_API_BASE_URL}/tx/{transaction_id}/merkle-proof"
   
    print(f"\n--- Fetching Merkle Proof for TXID: {transaction_id} ---")
    url = f"{Config.WOC_API_BASE_URL}/tx/{transaction_id}/proof/tsc"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=110.0)
            response.raise_for_status()
            merkle_proof_data = response.json()
            print("Merkle Proof Data:")
            print(json.dumps(merkle_proof_data, indent=2))
            return merkle_proof_data
        except httpx.HTTPStatusError as e:
            print(f"HTTP Status Error fetching Merkle proof (Code: {e.response.status_code}): {e.response.text}")
            return None
        except httpx.RequestError as e:
            print(f"Network Request Error fetching Merkle proof (Type: {type(e).__name__}): {e}")
            return None
        except Exception as e:
            print(f"An unexpected error occurred while fetching Merkle proof: {e}")
            return None