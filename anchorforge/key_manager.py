# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    key_manager.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

# key_manager.py
'''
V25-08-16: added access to private key via label


TODO add Net type for query
'''
import os 
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from bsv import PrivateKey, Network

from anchorforge.config import Config


# REQ: Config.KEYPAIR_STORE_FILE = "../config/local_config/key_pairs.json" # see Config.


def load_key_store(file_path: str) -> Dict:
    """Loads key pairs from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"key_pairs": []}

def save_key_store(key_pairs: Dict, file_path: str):
    """Saves key pairs to a JSON file."""

    # Ensure the target directory exists before saving keys.
    # This prevents FileNotFoundError if 'database/' directory is missing.
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)


    with open(file_path, 'w') as f:
        json.dump(key_pairs, f, indent=4)

def generate_key_pair(
    network_type: str,
    label: str,
    comment: str,
    file_path: Optional[str] = None
) -> Dict:
    """
    Generates a new Bitcoin SV key pair (Private Key WIF and Public Address)
    and saves it to a JSON file.

    Args:
        network_type (str): 'test' for Testnet or 'main' for Mainnet.
        label (str): A label for easy identification of the key.
        comment (str): A comment explaining the purpose and generation context.
        file_path (Optional[str]): Path to the key store file. If None,
                                   it uses a default path (to be defined in config).
    
    Returns:
        Dict: The newly generated key pair data.
    """
    if network_type.lower() == 'test':
        network = Network.TESTNET
    elif network_type.lower() == 'main':
        network = Network.MAINNET
    else:
        raise ValueError("Invalid network_type. Use 'test' or 'main'.")

    # Generate a new private key and derive the public address
    new_private_key = PrivateKey(network=network)
    new_private_key_wif = new_private_key.wif()
    new_public_address = new_private_key.address(network=network)
    
    # Get the current UTC date in YYYY-MM-DD format
    generation_date =datetime.now(timezone.utc).strftime('%Y-%m-%d')

    # Create the key pair data dictionary
    key_pair_data = {
        "label": label,
        "private_key_wif": new_private_key_wif,
        "public_address": new_public_address,
        "network": network_type.lower(),
        "generation_date_utc": generation_date,
        "comment": comment
    }

    # Load existing keys, add the new one, and save
    store_file_path = file_path if file_path else Config.KEYPAIR_STORE_FILE
    assert store_file_path is not None

    key_store = load_key_store(store_file_path)
    key_store["key_pairs"].append(key_pair_data)
    save_key_store(key_store, store_file_path)

    print(f"New key pair generated and saved to {store_file_path}:")
    print(f"  Label: {label}")
    print(f"  Address: {new_public_address}")
    
    return key_pair_data


def get_private_key_by_label(label: str, file_path: Optional[str] = None) -> Optional[str]:
    """
    Retrieves a private key (WIF) from the key store file by its label.

    Args:
        label (str): The label of the key to retrieve.
        file_path (Optional[str]): Path to the key store file. If None,
                                   it uses a default path (to be defined in config).

    Returns:
        Optional[str]: The private key in WIF format, or None if the key is not found.
    """
    # Use the default path if not provided
    store_file_path = file_path if file_path else Config.KEYPAIR_STORE_FILE

    assert store_file_path is not None
    
    # Load the entire key store
    key_store = load_key_store(store_file_path)
    
    # Search for the key by its label
    for key_pair in key_store.get("key_pairs", []):
        if key_pair.get("label") == label:
            return key_pair.get("private_key_wif")
            
    # Return None if no matching label was found
    return None

def get_key_pair_by_label(label: str, file_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieves the full key pair data (private key, public address, network)
    from the key store file by its label.

    Args:
        label (str): The label of the key pair to retrieve.
        file_path (Optional[str]): Path to the key store file. If None,
                                   it uses a default path (to be defined in config).

    Returns:
        Optional[Dict[str, Any]]: The full key pair data dictionary, or None if not found.
    """
    store_file_path = file_path if file_path else Config.KEYPAIR_STORE_FILE
    assert store_file_path is not None
    
    key_store = load_key_store(store_file_path)
    
    for key_pair in key_store.get("key_pairs", []):
        if key_pair.get("label") == label:
            return key_pair
            
    return None

def gen_specific_keys():
    
    '''
    generate_key_pair(
        network_type='test',
        label='bank_key_testnet',
        comment='Generated for funding testnet transactions.'
    )
    generate_key_pair(
        network_type='test',
        label='utxo_store',
        comment='For the store of UTXOs to be used for mass transactions'
    )


    '''
    
    generate_key_pair(
        network_type='test',
        label='T-bank_account-J',
        comment='Bankaccount to maintain funds for spending in audits (Linux J)'
    )

    generate_key_pair(
        network_type='test',
        label='T-utxo_account-J',
        comment='audit trail receipts (Linux-J)'
    )
  
    generate_key_pair(
        network_type='test',
        label='T-signing_key-J',
        comment='Signing key to demo for signing the hash (Linux-J)'
    )
    
    generate_key_pair(
        network_type='test',
        label='T-Funding_key-J1',
        comment='Funding (Linux-J)'
    )

    generate_key_pair(
        network_type='test',
        label='T-Funding_key-J2',
        comment='Funding (Linux-J)'
    )

    generate_key_pair(
        network_type='test',
        label='T-Funding_key-J3',
        comment='Funding (Linux-J)'
    )


# Example of how to use this function
if __name__ == "__main__":
    '''
    new_key = generate_key_pair(
        network_type='test',
        label='temp_key',
        comment='Temporary key for a single transaction demo.'
    )
    '''
   

    gen_specific_keys()


    # Retrieve the private key of the generated key pair using its label
    label = 'T-bank_account-J'
    private_key_wif = get_private_key_by_label(label)
    if private_key_wif:
        print(f"\nRetrieved private key (WIF) for '{label}': {private_key_wif}")
    else:
        print(f"\nCould not find a private key with the label '{label}'.")


    key_info = get_key_pair_by_label(label)
    if key_info:
        print("\n--- Retrieved Full Key Pair Info ---")
        print(f"Label: {key_info.get('label')}")
        print(f"Private Key WIF: {key_info.get('private_key_wif')}")
        print(f"Public Address: {key_info.get('public_address')}")
        print(f"Network: {key_info.get('network')}")
    else:
        print("\nCould not find full key pair info with the label '{label}'.")