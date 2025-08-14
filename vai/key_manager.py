# key_manager.py
import os
import json
from datetime import datetime, timezone
from typing import Optional, Dict

from bsv import PrivateKey, Network


# REQ: KEYPAIR_STORE_FILE = "key_pairs.json" # TODO MOVE to secure!

from config import Config

def load_key_store(file_path: str) -> Dict:
    """Loads key pairs from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"key_pairs": []}

def save_key_store(key_pairs: Dict, file_path: str):
    """Saves key pairs to a JSON file."""
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
    new_private_key = PrivateKey()
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

# Example of how to use this function
if __name__ == "__main__":
    # Example for Testnet
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
        network_type='main',
        label='bank_account',
        comment='Bankaccount to maintain funds for spending in audits'
    )

    generate_key_pair(
        network_type='main',
        label='utxo_account',
        comment='audit trail receipts'
    )
  
    generate_key_pair(
        network_type='main',
        label='signing_key',
        comment='Signing key to demo for signing the hash'
    )