# core_defs.py  
#    was audit_common.py
'''
Common definitions, constants, and utility functions shared between 
the Publisher (creation) and Verifier (checking) modules.
'''

import json
import logging
from typing import List, Dict, IO
from bsv import Script, hash256

logger = logging.getLogger(__name__)

VIBECODEVERSION=0.1

# --- AUDIT MODE CONSTANTS ---
AUDIT_MODE_APP_ID = b'\xF0' # Protocol Identifier
AUDIT_MODE_EC = b'E' # 'E' for Elliptic Curve Digital Signature Algorithm (ECDSA)
AUDIT_MODE_X509 = b'X' # 'X' for X.509 Certificate
AUDIT_MODE_NOTE = b'N' # 'N' for a Note or a comment.

# logic structure ofs OP_RETURN Payloads for Version.
AUDIT_RECORD_FORMAT_V1 = "anchor-forge-v1:(xF0,T)|(E,H,S,P)|(X,H,S,C)|(N,T)+"



def load_audit_log(f) -> List[Dict]:
    """
    Loads audit records from an open file object.
    """
    try:
        f.seek(0)           # read from beginning!
        return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_audit_log(f, audit_records: List[Dict]):
    """
    Saves audit records to an open file object.
    """
    f.seek(0)
    json.dump(audit_records, f, indent=4)
    f.truncate()


# --- Shared Utilities ---

def normalize_proof_data(proof_data):
    if isinstance(proof_data, list):
        if len(proof_data) == 1:
            return proof_data[0]
        elif len(proof_data) == 0:
            return None
        else:
            logger.warning(f"Proof data has {len(proof_data)} items, using first.")
            return proof_data[0]
    return proof_data


# region --- Verification Logic --- 
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

        current_index = index
        for i, node in enumerate(nodes):
            node_hash = bytes.fromhex(node)[::-1]
            logger.info(f"Node {i+1} (Little-Endian): {node_hash.hex()}")

            # Is actual hash left or right in tree
            if current_index % 2 == 0:
                combined = current_hash + node_hash
            else:
                combined = node_hash + current_hash

            logger.debug(f"Combined hash: {combined.hex()}")

            # compute double SHA256-Hash
            current_hash = hash256(combined)

            logger.debug(f"New hash after hash256 (Little-Endian): {current_hash.hex()}")

            current_index //= 2  # move on level up in the tree

        # convert Merkle root computed into Bit Endian for comparison
        calculated_root = current_hash[::-1].hex()

        logger.info(f"Calculated Merkle Root (Big-Endian): {calculated_root}")
        logger.info(f"Target Merkle Root (Big-Endian): {target}")
        
        return calculated_root == target
    except ValueError as e:
        logger.error(f"Error processing hex data: {e}")
        return False
# endregion

#region new [OP_FALSE] OP_RETURN
def print_op_return_scriptpubkey(script: Script):
    """
    Prints a human-readable form of the OP_RETURN scriptPubKey.
    Uses manual byte-parsing (similar to verifier.py) to be robust against
    library inconsistencies regarding chunks.
    """
    logger.info("\n--- OP_RETURN ScriptPubkey Details ---")
    
    if script is None:
        logger.error("Error: Invalid script object.")
        return

    try:
        # 1. Get raw bytes
        # Script.hex() returns string hex, convert to bytes
        script_bytes = bytes.fromhex(script.hex())
        logger.info(f"Full Script (Hex): {script.hex()}")
        try:
             logger.info(f"Full Script (ASM): {script.to_asm()}")
        except Exception:
             logger.warning("Could not generate ASM for this script.")

        # 2. Check Pattern (Byte Level)
        start_index = -1
        
        # Check for Safe OP_RETURN (0x00 0x6a)
        if script_bytes.startswith(b'\x00\x6a'):
            logger.info("Detected 'Safe' OP_RETURN (OP_FALSE OP_RETURN).")
            start_index = 2
        # Check for Legacy OP_RETURN (0x6a)
        elif script_bytes.startswith(b'\x6a'):
            logger.info("Detected Legacy OP_RETURN.")
            start_index = 1
        else:
            # For logging/debug purposes, print the first byte
            first_byte = script_bytes[0] if len(script_bytes) > 0 else "Empty"
            logger.warning(f"Script does not start with OP_RETURN (0x6a) or OP_FALSE (0x00). First byte: {hex(first_byte) if isinstance(first_byte, int) else first_byte}")
            return

        # 3. Manual Chunk Parsing
        # We parse the rest of the bytes manually to extract data pushes
        logger.info("OP_RETURN Data Elements:")
        
        current_index = start_index
        element_count = 0
        
        while current_index < len(script_bytes):
            element_count += 1
            length_or_opcode = script_bytes[current_index]
            current_index += 1
            
            data_length = 0
            
            # Determine data length based on opcode
            if 0x01 <= length_or_opcode <= 0x4b:
                # Direct Data Push (1-75 bytes)
                data_length = length_or_opcode
                
            elif length_or_opcode == 0x4c: # OP_PUSHDATA1
                if current_index + 1 > len(script_bytes): break
                data_length = script_bytes[current_index]
                current_index += 1
                
            elif length_or_opcode == 0x4d: # OP_PUSHDATA2
                if current_index + 2 > len(script_bytes): break
                data_length = int.from_bytes(script_bytes[current_index:current_index + 2], byteorder='little')
                current_index += 2
                
            elif length_or_opcode == 0x4e: # OP_PUSHDATA4
                if current_index + 4 > len(script_bytes): break
                data_length = int.from_bytes(script_bytes[current_index:current_index + 4], byteorder='little')
                current_index += 4
            else:
                 # It's an opcode, not a data push (e.g. OP_0 inside the data stream? Unlikely for standard OP_RETURN protocols)
                 logger.info(f"  Element {element_count}: (Opcode) {hex(length_or_opcode)}")
                 continue

            # Extract Data
            data_end = current_index + data_length
            if data_end > len(script_bytes):
                logger.error("  Error: Data push length exceeds script size.")
                break
                
            chunk_data = script_bytes[current_index:data_end]
            current_index = data_end
            
            # Print Data
            try:
                decoded_data = chunk_data.decode('utf-8')
                logger.info(f"  Element {element_count}: (Text) '{decoded_data}' (Hex: {chunk_data.hex()})")
            except UnicodeDecodeError:
                logger.info(f"  Element {element_count}: (Raw Hex) {chunk_data.hex()} (Length: {len(chunk_data)} bytes)")

    except Exception as e:
        logger.error(f"Exception in print_op_return_scriptpubkey: {e}", exc_info=True)
#end region



#region new [OP_FALSE] OP_RETURN test
def print_op_return_scriptpubkey_260111 (script: Script):
    """
    Prints a human-readable form of the OP_RETURN scriptPubKey.
    Handles legacy (OP_RETURN) and new (OP_FALSE OP_RETURN) formats.
    """
    logger.info("\n--- OP_RETURN ScriptPubkey Details ---")
    
    logger.info(f"Full Script (ASM) 1: {script.to_asm()}")
    logger.info(f"Full Script (Hex) 1: {script.hex()}")

    
    if script is None or not hasattr(script, 'chunks') or not script.chunks:
        logger.error("Error: Invalid script object.")
        return

    first_chunk_op = script.chunks[0].op
    start_index = 0

    # #FIX: Added detection for Safe OP_RETURN (0x00 0x6a) to avoid false warnings
    if first_chunk_op == 0x00:
        if len(script.chunks) > 1 and script.chunks[1].op == 0x6a:
            logger.info("Detected 'Safe' OP_RETURN (OP_FALSE OP_RETURN).")
            start_index = 2
        else:
            logger.warning("Starts with OP_FALSE but not followed by OP_RETURN.")
            return
    elif first_chunk_op == 0x6a:
        logger.info("Detected Legacy OP_RETURN.")
        start_index = 1
    else:
        logger.warning(f"Script does not start with OP_RETURN (0x6a) or OP_FALSE (0x00). Opcode: {first_chunk_op}")
        return

    logger.info(f"Full Script (ASM): {script.to_asm()}")
    logger.info(f"Full Script (Hex): {script.hex()}")

    logger.info("OP_RETURN Data Elements:")
    for i, chunk in enumerate(script.chunks[start_index:]):
        if chunk.data is not None: 
            try:
                decoded_data = chunk.data.decode('utf-8')
                logger.info(f"  Element {i+1}: (Text) '{decoded_data}' (Hex: {chunk.data.hex()})")
            except UnicodeDecodeError:
                logger.info(f"  Element {i+1}: (Raw Hex) {chunk.data.hex()} (Length: {len(chunk.data)} bytes)")
        else:
             # Just print opcode if it's not data
             logger.info(f"  Element {i+1}: (Opcode) {chunk.op}")
# endregion new [OP_FALSE] OP_RETURN test


#region debug 2
def print_op_return_scriptpubkey_260111_bug (script: Script):
    """
    Prints a human-readable form of the OP_RETURN scriptPubKey.
    Handles legacy (OP_RETURN) and new (OP_FALSE OP_RETURN) formats.
    """
    logger.info("\n--- OP_RETURN ScriptPubkey Details ---")
    
    if script is None or not hasattr(script, 'chunks') or not script.chunks:
        logger.error("Error: Invalid script object.")
        return

    # #FIX: Added detailed debugging to inspect what we actually get
    # logger.info(f"Full Script (ASM): {script.to_asm()}")
    # logger.info(f"Full Script (Hex): {script.hex()}")

    try:
        first_chunk_op = script.chunks[0].op
        # logger.debug(f"DEBUG: First Chunk Opcode: {first_chunk_op} (Type: {type(first_chunk_op)})")
        
        start_index = 0

        # #FIX: Added detection for Safe OP_RETURN (0x00 0x6a)
        # Note: In some bsv libs, OP_0 might be represented as int 0.
        if first_chunk_op == 0 or first_chunk_op == 0x00:
            if len(script.chunks) > 1 and script.chunks[1].op == 0x6a:
                logger.info("Detected 'Safe' OP_RETURN (OP_FALSE OP_RETURN).")
                start_index = 2
            else:
                logger.warning("Starts with OP_FALSE (0x00) but not followed by OP_RETURN (0x6a).")
                # Continue anyway to see what's inside
                start_index = 1
                
        elif first_chunk_op == 0x6a:
            logger.info("Detected Legacy OP_RETURN.")
            start_index = 1
        else:
            logger.warning(f"Script does not start with OP_RETURN (0x6a) or OP_FALSE (0x00). Opcode: {first_chunk_op}")
            # We assume it might be a weird format and try to parse from index 0 anyway if debug is needed
            return

        logger.info("OP_RETURN Data Elements:")
        for i, chunk in enumerate(script.chunks[start_index:]):
            if chunk.data is not None: 
                try:
                    # Attempt UTF-8 decode
                    decoded_data = chunk.data.decode('utf-8')
                    # Log printable characters, hex for others
                    logger.info(f"  Element {i+1}: (Text) '{decoded_data}' (Hex: {chunk.data.hex()})")
                except UnicodeDecodeError:
                    logger.info(f"  Element {i+1}: (Raw Hex) {chunk.data.hex()} (Length: {len(chunk.data)} bytes)")
            else:
                # Just print opcode if it's not data
                logger.info(f"  Element {i+1}: (Opcode) {chunk.op}")

    except Exception as e:
        logger.error(f"Exception in print_op_return_scriptpubkey: {e}", exc_info=True)

#endregion


#region debug print_op_return_scriptkey
def print_op_return_scriptpubkey_1 (script: Script):
    """
    Prints a human-readable form of the OP_RETURN scriptPubKey.
    Handles legacy (OP_RETURN) and new (OP_FALSE OP_RETURN) formats.
    """
    logger.info("\n--- OP_RETURN ScriptPubkey Details ---")
    
    if script is None or not hasattr(script, 'chunks') or not script.chunks:
        logger.error("Error: Invalid script object.")
        return

    # #FIX: Added detailed debugging to inspect what we actually get
    # logger.info(f"Full Script (ASM): {script.to_asm()}")
    # logger.info(f"Full Script (Hex): {script.hex()}")

    try:
        first_chunk_op = script.chunks[0].op
        # logger.debug(f"DEBUG: First Chunk Opcode: {first_chunk_op} (Type: {type(first_chunk_op)})")
        
        start_index = 0

        # #FIX: Added detection for Safe OP_RETURN (0x00 0x6a)
        # Note: In some bsv libs, OP_0 might be represented as int 0.
        if first_chunk_op == 0 or first_chunk_op == 0x00:
            if len(script.chunks) > 1 and script.chunks[1].op == 0x6a:
                logger.info("Detected 'Safe' OP_RETURN (OP_FALSE OP_RETURN).")
                start_index = 2
            else:
                logger.warning("Starts with OP_FALSE (0x00) but not followed by OP_RETURN (0x6a).")
                # Continue anyway to see what's inside
                start_index = 1
                
        elif first_chunk_op == 0x6a:
            logger.info("Detected Legacy OP_RETURN.")
            start_index = 1
        else:
            logger.warning(f"Script does not start with OP_RETURN (0x6a) or OP_FALSE (0x00). Opcode: {first_chunk_op}")
            # We assume it might be a weird format and try to parse from index 0 anyway if debug is needed
            return

        logger.info("OP_RETURN Data Elements:")
        for i, chunk in enumerate(script.chunks[start_index:]):
            if chunk.data is not None: 
                try:
                    # Attempt UTF-8 decode
                    decoded_data = chunk.data.decode('utf-8')
                    # Log printable characters, hex for others
                    logger.info(f"  Element {i+1}: (Text) '{decoded_data}' (Hex: {chunk.data.hex()})")
                except UnicodeDecodeError:
                    logger.info(f"  Element {i+1}: (Raw Hex) {chunk.data.hex()} (Length: {len(chunk.data)} bytes)")
            else:
                # Just print opcode if it's not data
                logger.info(f"  Element {i+1}: (Opcode) {chunk.op}")

    except Exception as e:
        logger.error(f"Exception in print_op_return_scriptpubkey: {e}", exc_info=True)
# endregion debug print_op_return

# region Utility / Debugging - still buggy
def print_op_return_scriptpubkey_buggy (script: Script):   #_bu251015  # TODO contains an error
    """
    Prints a human-readable form of the OP_RETURN scriptPubKey.
    It iterates through the script chunks to identify and display
    OP_RETURN and the data pushes.
    This version handles both, legacy (OP_RETURN) and new 
    (OP_FALSE OP_RETURN) script formats

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
    
    #region buggy OP_RETURN
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

    # endregion -----------------


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


#endregion Utility / Debug
