#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    af_header_tool.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

# Purpose: Utility to analyze, repair, and manipulate local block header caches.
"""
python af_header_tool.py --input-file block_headers_test.json --check
Test structure

python af_header_tool.py --input-file block_headers_test.json --output headers_min.json --minimalize
create a reduced file

--check, action="store_true", help="Checks input for structure and plausibility."
--minimalize, action="store_true", help="Format to minimal SPV representation."
--micromize, action="store_true", help="Format to block-id and 80-byte raw header only."
--repair, action="store_true", help="Attempt to repair broken headers (Not yet implemented)."
--maximalize, action="store_true", help="Fetch full data from API, but omit transaction hashes."
--maximalize-with-tx, action="store_true", help="Fetch full data from API, including all transaction hashes."
"""
# -----------------------------------------------------------------------------

import argparse
import json
import sys
import os
import struct
import urllib.request
import urllib.error

def load_json(filepath):
    if not os.path.exists(filepath):
        print(f"Error: Input file '{filepath}' not found.")
        sys.exit(1)
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON in '{filepath}': {e}")
        sys.exit(1)

def save_json(filepath, data):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        print(f"Successfully saved output to '{filepath}'.")
    except Exception as e:
        print(f"Error saving to '{filepath}': {e}")

def fetch_block_from_woc(block_hash, network):
    """Fetches full block details from WhatsOnChain API."""
    url = f"https://api.whatsonchain.com/v1/bsv/{network}/block/hash/{block_hash}"
    print(f"Fetching {block_hash} from {network}...")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'AnchorForge-HeaderTool/0.2'})
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except urllib.error.URLError as e:
        print(f"Failed to fetch block {block_hash}: {e}")
        return None

def build_raw_header_hex(block):
    """
    Constructs the 80-byte Bitcoin block header (as a hex string) 
    from the parsed JSON fields using Little-Endian byte order.
    """
    try:
        # Version (4 bytes, Little Endian)
        version = struct.pack('<I', block['version']).hex()
        # Previous Block Hash (32 bytes, Reversed)
        prevhash = bytes.fromhex(block['previousblockhash'])[::-1].hex()
        # Merkle Root (32 bytes, Reversed)
        merkleroot = bytes.fromhex(block['merkleroot'])[::-1].hex()
        # Timestamp (4 bytes, Little Endian)
        time = struct.pack('<I', block['time']).hex()
        # Bits / Difficulty Target (4 bytes, Reversed from hex string)
        bits = bytes.fromhex(block['bits'])[::-1].hex()
        # Nonce (4 bytes, Little Endian)
        nonce = struct.pack('<I', block['nonce']).hex()
        
        return version + prevhash + merkleroot + time + bits + nonce
    except KeyError as e:
        print(f"Missing key for header generation: {e}")
        return None

# --- Core Operation Functions ---

def do_check(data):
    """Checks the input for structure and plausibility."""
    print("--- Running Structure & Plausibility Check ---")
    issues_found = 0
    required_keys = ['hash', 'height', 'version', 'merkleroot', 'time', 'bits', 'nonce', 'previousblockhash']
    
    for block_id, block_data in data.items():
        if block_id != block_data.get('hash'):
            print(f"[WARN] Dictionary key '{block_id}' does not match internal block hash '{block_data.get('hash')}'.")
            issues_found += 1
            
        for key in required_keys:
            if key not in block_data:
                print(f"[ERROR] Block {block_id} is missing required SPV field: '{key}'")
                issues_found += 1
                
    if issues_found == 0:
        print("Check passed! The file structure looks completely plausible and healthy.")
    else:
        print(f"Check finished with {issues_found} potential issue(s).")
    return data # Unmodified

def do_minimalize(data):
    """Writes the input file in a format containing the minimal SPV representation."""
    print("--- Minimalizing Block Headers ---")
    minimal_data = {}
    keep_keys = ['hash', 'confirmations', 'height', 'version', 'merkleroot', 
                 'time', 'bits', 'nonce', 'previousblockhash', 'nextblockhash']
    
    for block_id, block_data in data.items():
        minimal_block = {}
        for k in keep_keys:
            if k in block_data:
                minimal_block[k] = block_data[k]
        minimal_data[block_id] = minimal_block
        
    print(f"Reduced {len(minimal_data)} blocks to minimal SPV metadata.")
    return minimal_data

def do_micromize(data):
    """Generates a JSON file with only the block-id and the 80-byte header."""
    print("--- Micromizing Block Headers (80-byte raw hex) ---")
    micromized_data = {}
    
    for block_id, block_data in data.items():
        raw_hex = build_raw_header_hex(block_data)
        if raw_hex:
            micromized_data[block_id] = {"header": raw_hex}
        else:
            print(f"Skipping {block_id} due to missing data.")
            
    print(f"Converted {len(micromized_data)} blocks to raw 80-byte hex headers.")
    return micromized_data

def do_repair(data):
    """Placeholder for future repair logic."""
    print("Error: repair mode is not yet implemented.")
    sys.exit(0)

def do_maximalize(data, network, include_tx=False):
    """Takes input and fills it up using WhatsOnChain, optionally with or without TX hashes."""
    mode_name = "maximalize-with-tx" if include_tx else "maximalize"
    print(f"--- Running {mode_name} via {network.upper()} network ---")
    
    maximalized_data = {}
    for block_id in data.keys():
        api_block = fetch_block_from_woc(block_id, network)
        if api_block:
            if not include_tx and 'tx' in api_block:
                del api_block['tx'] # Remove the massive transaction array
            maximalized_data[block_id] = api_block
        else:
            print(f"Keeping local data for {block_id} due to API failure.")
            maximalized_data[block_id] = data[block_id]
            
    return maximalized_data

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="AnchorForge Block Header Manipulation Tool")
    parser.add_argument("--input-file", required=True, help="Input JSON file to process.")
    parser.add_argument("--output", required=False, help="Output JSON file for the results.")
    parser.add_argument("--network", choices=['main', 'test'], default='test', help="Network to use for API lookups (default: test).")
    
    # Mutually exclusive operation group
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="Checks input for structure and plausibility.")
    group.add_argument("--minimalize", action="store_true", help="Format to minimal SPV representation.")
    group.add_argument("--micromize", action="store_true", help="Format to block-id and 80-byte raw header only.")
    group.add_argument("--repair", action="store_true", help="Attempt to repair broken headers (Not yet implemented).")
    group.add_argument("--maximalize", action="store_true", help="Fetch full data from API, but omit transaction hashes.")
    group.add_argument("--maximalize-with-tx", action="store_true", help="Fetch full data from API, including all transaction hashes.")

    args = parser.parse_args()

    # Require --output for modifying actions
    if not args.check and not args.repair and not args.output:
        print("Error: --output is required for operations that modify data (--minimalize, --micromize, --maximalize*).")
        sys.exit(1)

    # 1. Load Data
    data = load_json(args.input_file)

    # 2. Process Data
    result_data = data
    if args.check:
        do_check(data)
        sys.exit(0) # Check doesn't save anything
    elif args.repair:
        do_repair(data)
    elif args.minimalize:
        result_data = do_minimalize(data)
    elif args.micromize:
        result_data = do_micromize(data)
    elif args.maximalize:
        result_data = do_maximalize(data, args.network, include_tx=False)
    elif args.maximalize_with_tx:
        result_data = do_maximalize(data, args.network, include_tx=True)

    # 3. Save Data
    if args.output:
        save_json(args.output, result_data)

if __name__ == "__main__":
    main()