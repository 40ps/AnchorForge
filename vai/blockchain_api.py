import httpx
import json
import logging
from typing import Dict, List

# Import configuration constants
from config import Config 

# --- Logging configuration (for this module) ---
logger = logging.getLogger(__name__) 

# --- API Functions ---

async def get_merkle_path(txid: str) -> Dict:
    """
    Asks merkle path from WhatsOnChain.
    
    Args:
        txid (str): Transaction-ID (hex).
    
    Returns:
        Dict: Merkle-Path-Data (index, nodes, target).
    """
    try:
        url = f"{Config.WOC_API_BASE_URL}/tx/{txid}/proof/tsc"
        print(f"  Fetching Merkle path from: {url}")
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10.0) # Use await here
            response.raise_for_status()
            data = response.json()
            if isinstance(data, list) and len(data) > 0:
                return data[0]
            else:
                raise ValueError("Invalid Data format of WhatsOnChain")
    except httpx.RequestError as e: # Catch httpx specific exceptions
        print(f"Error fetching data from WhatsOnChain: {e}")
        return {}
    except Exception as e:
        print(f"An unexpected error occurred while fetching Merkle path: {e}")
        return {}

async def get_block_header_height(block_height: int) -> dict:
    """
    Fetches block header by height from WhatsOnChain using httpx.
    """
    url = f"{Config.WOC_API_BASE_URL}/block/height/{block_height}"
    print(f"  Fetching block header by height from: {url}")
    async with httpx.AsyncClient() as client:
        response = await client.get(url, timeout=10.0)
        response.raise_for_status()
        return response.json()
    
async def get_block_header(block_hash: str) -> Dict:
    """
    Retrieves the block header from WhatsOnChain (Testnet) using httpx.
    
    Args:
        block_hash (str): The block hash (hex, Big-Endian).
    
    Returns:
        Dict: Block header data.
    """
    try:
        url = f"{Config.WOC_API_BASE_URL}/block/{block_hash}/header"
        print(f"  Fetching block header by hash from: {url}")
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10.0)
            response.raise_for_status()
            return response.json()
    except httpx.RequestError as e:
        print(f"Error fetching block data: {e}")
        return {}
    except Exception as e:
        print(f"An unexpected error occurred while fetching block header: {e}")
        return {}
    
        
async def get_merkle_proof(transaction_id: str) -> dict | None:
    """
    Fetches the Merkle proof for a given transaction ID from WhatsOnChain.

    Args:
        transaction_id (str): The TXID of the transaction to get the Merkle proof for.

    Returns:
        dict | None: A dictionary containing the Merkle proof details if successful, None otherwise.
                     The dictionary typically includes 'blockhash', 'merkleProof', 'txid', 'pos'.
    """
    #url = f"{Config.WOC_API_BASE_URL}/tx/{transaction_id}/merkle-proof"
   
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

   
async def get_chain_info_woc() -> Dict | None:
    """
    Fetches general blockchain information (including the latest block height) from WhatsOnChain.
    """
    url = f"{Config.WOC_API_BASE_URL}/chain/info"
    logging.info(f"  Fetching chain info from: {url}")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=10.0)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logging.error(f"Error fetching chain info from WhatsOnChain: {e}")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred while fetching chain info: {e}")
            return None
        
async def get_transaction_status_woc(txid: str) -> Dict | None:
    """
    Fetches detailed transaction info from WhatsOnChain to check confirmation status.

    Args:
        txid (str): The transaction ID.

    Returns:
        Dict | None: A dictionary with transaction details, including 'blockhash' and 'blockheight'
                     if confirmed. Returns None on error or if not found.
    """
    url = f"{Config.WOC_API_BASE_URL}/tx/hash/{txid}"
    print(f"  Checking status of TXID {txid} from: {url}")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=10.0)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                print(f"  TXID {txid} not yet found on network (might still be propagating).")
                return None # Not necessarily an error, just not confirmed yet
            print(f"  HTTP Status Error checking tx status {txid} (Code: {e.response.status_code}): {e.response.text}")
            return None
        except httpx.RequestError as e:
            print(f"  Network Request Error checking tx status {txid} (Type: {type(e).__name__}): {e}")
            return None
        except Exception as e:
            print(f"  An unexpected error occurred checking tx status {txid}: {e}")
            return None



async def fetch_utxos_for_address(address: str) -> list[dict]:
    """
    Fetches unspent transaction outputs (UTXOs) for a given Bitcoin SV address from WhatsOnChain.

    Args:
        address (str): The Bitcoin SV address (e.g., testnet address).

    Returns:
        list[dict]: A list of UTXO dictionaries. Each dictionary contains:
                    'tx_hash', 'tx_pos' (output index), 'value' (in satoshis).
                    Note: 'scriptPubKey' is NOT returned by WhatsOnChain /unspent endpoint directly.
    """
    url = f"{Config.WOC_API_BASE_URL}/address/{address}/unspent"
    print(f"Attempting to fetch UTXOs from: {url}") # Debugging: Print URL
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=10.0)
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
            utxos_data = response.json()
            print(f"WhatsOnChain API Response (Status: {response.status_code}): {response.text[:200]}...") # Debugging: Print partial response

            formatted_utxos = []
            for utxo in utxos_data:
                formatted_utxos.append({
                    "txid": utxo["tx_hash"],
                    "vout": utxo["tx_pos"],
                    "satoshis": utxo["value"],
                    "height" : utxo["height"]
                    # Removed: "scriptPubKey": utxo["scriptPubKey"] because it's not in WhatsOnChain /unspent endpoint response
                })
            return formatted_utxos
        except httpx.HTTPStatusError as e:
            print(f"HTTP Status Error fetching UTXOs (Code: {e.response.status_code}): {e.response.text}")
            return []
        except httpx.RequestError as e:
            print(f"Network Request Error fetching UTXOs (Type: {type(e).__name__}): {e}")
            return []
        except Exception as e:
            print(f"An unexpected error occurred while fetching UTXOs: {e}")
            return []


# Helper for fetch_raw_transaction_hex (defined here because it's only used internally by main transaction methods)
async def fetch_raw_transaction_hex(txid: str) -> str | None:
    url = f"{Config.WOC_API_BASE_URL}/tx/{txid}/hex"
    print(f"  Attempting to fetch raw transaction hex from: {url}") # Debugging: Print URL
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=10.0)
            response.raise_for_status()
            # print(f"  Raw TX Fetch Response (Status: {response.status_code}): {response.text[:200]}...") # Debugging: Print partial response
            return response.text
        except httpx.HTTPStatusError as e:
            print(f"  HTTP Status Error fetching raw transaction {txid} (Code: {e.response.status_code}): {e.response.text}")
            return None
        except httpx.RequestError as e:
            print(f"  Network Request Error fetching raw transaction {txid} (Type: {type(e).__name__}): {e}")
            return None
        except Exception as e:
            print(f"  An unexpected error occurred while fetching raw transaction {txid}: {e}")
            return None

     
async def broadcast_transaction(signed_raw_tx_string: str) -> str | None:
    """
    Broadcasts a signed raw Bitcoin SV transaction to the network via WhatsOnChain API.

    Args:
        signed_raw_tx_string (str): The hexadecimal representation of the signed transaction.

    Returns:
        str | None: The transaction ID (TXID) if broadcast is successful, None otherwise.
    """
    url = f"{Config.WOC_API_BASE_URL}/tx/raw"
    headers = {'Content-Type': 'application/json'}
    payload = {'txhex': signed_raw_tx_string}

    print(f"Payload: {signed_raw_tx_string}")


    print(f"\n--- Broadcasting Transaction to {url} ---")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, json=payload, headers=headers, timeout=30.0)
            
            print(f"HTTP Status Code: {response.status_code}")
            print(f"Response Headers: {response.headers}")

            try:
                response_json = response.json()
                print("Response Body (JSON):")
                print(json.dumps(response_json, indent=2))
                
                if response.status_code == 200:
                    # WhatsOnChain successful broadcast returns the txid directly as a string.
                    # Or, if it's an error, it might be a JSON object with 'error'.
                    # CORRECTED: Explicitly check if the response_json is a non-empty string for TXID
                    if isinstance(response_json, str) and response_json: # Check for non-empty string
                        print(f"Success: Transaction broadcasted with txid: {response_json}")
                        return response_json
                    elif isinstance(response_json, dict) and 'txid' in response_json:
                         print(f"Success: Transaction broadcasted with txid: {response_json['txid']}")
                         return response_json['txid']
                    else:
                        print(f"Error: Transaction rejected by Config.WOC API. Unexpected JSON response format or empty response.")
                        return None
                else:
                    # Non-200 status code, but JSON response might have an error detail
                    error_message = response_json.get('message', response_json.get('error', 'No specific error message provided'))
                    print(f"Request failed: Status {response.status_code}, Error: {error_message}")
                    return None
            except json.JSONDecodeError as e:
                print(f"JSON parsing error: {e}")
                print(f"Raw Response Body (Non-JSON): {response.text}")
                return None
            
        except httpx.HTTPStatusError as e:
            print(f"HTTP Status Error broadcasting transaction (Code: {e.response.status_code}): {e.response.text}")
            return None
        except httpx.RequestError as e:
            print(f"Network Request Error broadcasting transaction (Type: {type(e).__name__}): {e}")
            return None
        except Exception as e:
            print(f"An unexpected error occurred during broadcast: {e}")
            return None
