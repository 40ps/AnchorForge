# utils.py
# little helpers to simplify task for testing or extending the PoC
# - output and queries on Transaction data
# - API call history to avoid too many calls

import logging
from typing import Dict, List, Any, Optional
import httpx
import json
from datetime import datetime
import shutil
import os
import sys
import asyncio

from bsv.hash import hash256 # Assuming hash256 is used by verify_block_hash
from bsv import Transaction # Assuming Transaction is used by deserialize_and_print_transaction
import base58 
import hashlib 
from bsv import Script

from bsv import (
    PrivateKey,
    Transaction,
    Network, Script, 
    hash256
)

from bsv.hash import sha256 

from anchorforge.config import Config

VIBECODEVERSION=0.1
VERSION=0.1

API_COUNTER_FILE = "api_usage_counter.json"  # To avoid overusing API
STATUS_FILE = "coingecko_batch_status.json"  # for recovery mechanism
DEFAULT_STATUS_FILE = "coingecko_batch_status.json" # Default for backward compatibility

logger = logging.getLogger(__name__)

# --- NEW: Function to resolve content from string or file path ---
def get_content_from_source(source: str | None) -> str | None:
    """
    Reads content either directly from a string or from a file path.

    Args:
        source (str | None): The input string or a path to a file.

    Returns:
        str | None: The content as a string, or None if input was None. 
                    Exits on file read error.
    """
    if source is None:
        return None
    
    # 1. Explicit File Reference
    if source.startswith('@'):
        file_path = source[1:]
    elif os.path.isfile(source):
        file_path = source
    else:
        file_path = None

    if file_path:
        try:
            with open(source, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            # Using logger if available, otherwise print
            logger.error(f"Error reading file {source}: {e}") if 'logger' in globals() else print(f"Error reading file {source}: {e}")
            sys.exit(1) 
    # If it's not a file path, assume it's the direct content string
    return source

async def hash_file_async(filepath: str, block_size: int = 65536) -> Optional[bytes]:
    """
    Hashes a file asynchronously using SHA-256 without blocking the event loop.
    Reads the file in chunks. Returns raw bytes.
    """
    try:
        def read_and_hash():
            # This blocking I/O runs in a separate thread
            hash_obj = hashlib.sha256()
            with open(filepath, 'rb') as f:
                while chunk := f.read(block_size):
                    hash_obj.update(chunk)
            return hash_obj.digest() # raw bytes

        # Run the blocking file I/O in asyncio's default thread pool
        return await asyncio.to_thread(read_and_hash)
    
    except FileNotFoundError:
        logger.error(f"[hash_file_async] File not found at: {filepath}")
        return None
    except Exception as e:
        logger.error(f"[hash_file_async] Error hashing file {filepath}: {e}", exc_info=True)
        return None


def read_api_usage() -> dict:
    """
    Reads the API usage counter file and handles monthly reset.
    Returns the full counter data dictionary.
    """
    try:
        with open(API_COUNTER_FILE, 'r') as f:
            counter_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # If file does not exist or is corrupt, create a new default structure
        logger.warning(f"'{API_COUNTER_FILE}' not found or corrupt. Creating a new one.")
        counter_data = {
            "coingecko_monthly_count": 0,
            "iss_monthly_count": 0,
            "last_reset_date": datetime.now().strftime('%Y-%m-01')
        }
        _write_api_usage(counter_data)

    # Check for month change to reset all counters
    try:
        last_reset = datetime.strptime(counter_data.get('last_reset_date', '1970-01-01'), '%Y-%m-%d')
        now = datetime.now()
        if last_reset.month != now.month or last_reset.year != now.year:
            logger.info("New month detected. Resetting API usage counters.")
            # Reset all known service counters
            for key in counter_data.keys():
                if key.endswith('_monthly_count'):
                    counter_data[key] = 0
            counter_data['last_reset_date'] = now.strftime('%Y-%m-01')
            _write_api_usage(counter_data)
    except ValueError:
         logger.error(f"Invalid date format in '{API_COUNTER_FILE}'. Resetting date.")
         counter_data['last_reset_date'] = datetime.now().strftime('%Y-%m-01')
         _write_api_usage(counter_data)
        
    return counter_data


def ensure_json_file_exists(file_path: str, initial_content: Any = []):
    """
    Ensures a file with at least [] exists.
    Prevents 'FileNotFoundError' e.g. for 'r+' Locks.
    """
    if not os.path.exists(file_path):
        logger.warning(f"File not found: {file_path}. Create new with content: {initial_content}")
        try:
            # 'w'-Mode also creates file
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(initial_content, f)
            logger.info(f"File created successfully: {file_path}")
        except Exception as e:
            logger.error(f"Couldn't create {file_path} : {e}", exc_info=True)

def _write_api_usage(data: dict):
    """
    Internal function to write data to the counter file.
    """
    try:
        with open(API_COUNTER_FILE, 'w') as f:
            json.dump(data, f, indent=4)
    except IOError as e:
        logger.error(f"Could not write to API counter file '{API_COUNTER_FILE}': {e}")

def increment_api_usage(service_name: str):
    """
    Increments the usage counter for a given service.
    """
    counter_data = read_api_usage()
    counter_key = f"{service_name}_monthly_count"
    
    # Ensure the key exists before incrementing
    if counter_key not in counter_data:
         logger.warning(f"Counter key '{counter_key}' not found in '{API_COUNTER_FILE}'. Initializing to 1.")
         counter_data[counter_key] = 1
    else:
        counter_data[counter_key] = counter_data.get(counter_key, 0) + 1
        
    _write_api_usage(counter_data)
    logger.debug(f"Incremented API counter for '{service_name}'. New count: {counter_data[counter_key]}")

def check_api_limit_exceeded(service_name: str, limit: int | None) -> bool:
    """
    Checks if the API usage limit for a service has been exceeded.
    Returns True if limit is reached or exceeded, False otherwise.
    If limit is None, it always returns False (no limit).
    """
    if limit is None:
        return False # No limit defined for this service

    counter_data = read_api_usage()
    counter_key = f"{service_name}_monthly_count"
    count = counter_data.get(counter_key, 0)
    
    if count >= limit:
        logger.warning(f"API limit for '{service_name}' reached ({count}/{limit}).")
        return True
    else:
        return False

# --- Backup support ---
def read_batch_status(filename: str = DEFAULT_STATUS_FILE) -> dict:
    """
    Reads the specified batch status file.
    Uses DEFAULT_STATUS_FILE if no filename is provided.
    """
    try:
        with open(filename, 'r') as f:
            status_data = json.load(f)
            # Ensure essential keys exist
            status_data.setdefault('total_requested', 0)
            status_data.setdefault('completed_count', 0)
            status_data.setdefault('status', 'idle')
            return status_data
    except (FileNotFoundError, json.JSONDecodeError):
        # If file does not exist or is corrupt, return a default state
        logger.warning(f"Status file '{filename}' not found or corrupt. Returning default state.")
        return {"total_requested": 0, "completed_count": 0, "status": "idle"}
    

def write_batch_status(status_data: dict, filename: str = DEFAULT_STATUS_FILE):
    """
    Writes data to the specified batch status file.
    Uses DEFAULT_STATUS_FILE if no filename is provided.
    """
    try:
        with open(filename, 'w') as f:
            json.dump(status_data, f, indent=4)
    except IOError as e:
        logger.error(f"Could not write to status file '{filename}': {e}")

def create_backup(files_to_backup: list, backup_dir: str):
    """
    Creates a timestamped backup of a list of files.

    Args:
        files_to_backup (list): A list of file paths to be backed up.
        backup_dir (str): The directory where backups will be stored.
    """
    try:
        # Ensure the backup directory exists
        os.makedirs(backup_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        logging.info(f"--- Creating backup at {timestamp} ---")

        for file_path in files_to_backup:
            if not os.path.exists(file_path):
                logging.warning(f"Backup skipped for non-existent file: {file_path}")
                continue

            # Construct the destination path with a timestamp
            file_name = os.path.basename(file_path)
            backup_file_path = os.path.join(backup_dir, f"{file_name}.{timestamp}.bak")
            
            # Copy the file
            shutil.copy2(file_path, backup_file_path)
            logging.info(f"  Successfully backed up '{file_name}' to '{backup_file_path}'")

    except Exception as e:
        logging.error(f"An error occurred during the backup process: {e}")



# 

async def check_process_controls(process_name: str):
    """
    Checks for pause and stop flag files for a given process.
    Returns True if the process should stop, False otherwise.
    """
    pause_flag = f"{process_name}.pause.flag"
    stop_flag = f"{process_name}.stop.flag"

    # Check for pause flag
    if os.path.exists(pause_flag):
        logging.info(f"'{pause_flag}' detected. Pausing process. To resume, run 'control_process.py {process_name} resume'.")
        while os.path.exists(pause_flag):
            await asyncio.sleep(5) # Check every 5 seconds
        logging.info(f"'{pause_flag}' removed. Resuming process.")

    # Check for stop flag
    if os.path.exists(stop_flag):
        logging.info(f"'{stop_flag}' detected. Stopping process gracefully.")
        try:
            os.remove(stop_flag) # Clean up the flag file
        except OSError as e:
            logging.error(f"Error removing {stop_flag}: {e}")
        return True # Signal to stop

    return False # Signal to continue
# -------------------------------------------------------------

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
    Verifies Block-Hash by computation and comparison.
    
    Args:
        block_header (Dict): Block-Header-Daten (version, prevBlock, merkleRoot, time, bits, nonce).
    
    Returns:
        bool: True, if computed block hash matches expected hash.
    """
    try:
        # Extract Block-Header-Fields (all in Big-Endian as Hex-Strings)
        version = int(block_header["version"]).to_bytes(4, byteorder="little")
        prev_block = bytes.fromhex(block_header["previousblockhash"])[::-1]  # Little-Endian
        merkle_root = bytes.fromhex(block_header["merkleroot"])[::-1]  # Little-Endian
        time = int(block_header["time"]).to_bytes(4, byteorder="little")
        bits = int(block_header["bits"], 16).to_bytes(4, byteorder="little")
        nonce = int(block_header["nonce"]).to_bytes(4, byteorder="little")

        # concat fields in Little-Endian
        header = version + prev_block + merkle_root + time + bits + nonce
        print(f"Block-Header (Little-Endian): {header.hex()}")

        # Double SHA256-Hash
        calculated_hash = hash256(header)[::-1]  # convert into Big-Endian for compaison
        expected_hash = block_header["hash"]
        print(f"Computed Block-Hash: {calculated_hash.hex()}")
        print(f"Expected Block-Hash: {expected_hash}")
        return calculated_hash.hex() == expected_hash
    except (KeyError, ValueError) as e:
        print(f"Error processing Block-Header: {e}")
        return False


def verify_proof_of_work(block_hash: bytes, bits: str) -> bool:
    target = bits_to_target(int(bits, 16))  # converts bits into target value
    return int.from_bytes(block_hash, "big") < target

def bits_to_target(bits: int) -> int:
    """converts bits-Field into target value."""
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
        
async def _log_aiohttp_error(response, context: str):
    """
    Hilfsfunktion: Liest den Fehlertext aus einer aiohttp-Response und gibt ihn aus.
    Wird von data_services.py genutzt.
    """
    try:
        # Versuchen, den Body der Antwort zu lesen
        error_text = await response.text()
    except Exception:
        error_text = "<Konnte Antwort-Text nicht lesen>"
    
    print(f"❌ ERROR in {context}: HTTP {response.status}")
    print(f"   Response Body: {error_text}")