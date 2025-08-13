# config.py
import os
from typing import Optional
from dotenv import load_dotenv, find_dotenv

# Load environment variables from .env file
#load_dotenv(find_dotenv())
load_dotenv("../local_config/.env")

class Config:
    """
    A class to centralize and manage application configuration.
    It reads settings from environment variables, providing a single source of truth.
    """

    # --- File Paths ---
    # These are not secrets and can remain in the code, but you could also move them to .env.
    UTXO_STORE_FILE = "utxo_store.json"
    USED_UTXO_STORE_FILE = "used_utxo_store.json"
    TX_STORE_FILE = "tx_store.json"
    AUDIT_LOG_FILE = "audit_log.json"
    BLOCK_HEADERS_FILE = "block_headers.json"
    LOG_FILE = "application.log"
    
    KEYPAIR_STORE_FILE: Optional[str] = os.getenv("KEYPAIR_STORE_FILE")
    assert KEYPAIR_STORE_FILE is not None, "KEYPAIR_STORE_FILE must be set in environment variable"
    
    WOC_TESTNET_API_BASE_URL: Optional[str] = os.getenv("WOC_TESTNET_API_BASE_URL")
    assert WOC_TESTNET_API_BASE_URL is not None, "WOC_TESTNET_API_BASE_URL must be set in environment variable"

    # --- Network-specific API Endpoints ---
    NETWORK_API_ENDPOINTS = {
        "main": "https://api.whatsonchain.com/v1/bsv/main",
        "test": WOC_TESTNET_API_BASE_URL
    }

    # --- Secrets (loaded from .env) ---
    # The getenv() method returns None if the key does not exist.
    # It's good practice to handle mandatory keys explicitly.
    PRIVATE_KEY_WIF: Optional[str]  = os.getenv("PRIVATE_KEY_WIF")
    UTXO_STORE_KEY_WIF: Optional[str]  = os.getenv("UTXO_STORE_KEY_WIF")
    PRIVATE_BANK_KEY_WIF: Optional[str] = os.getenv("PRIVATE_BANK_KEY_WIF")
    PRIVATE_SIGNING_KEY_WIF: Optional[str]  = os.getenv("PRIVATE_SIGNING_KEY_WIF")

    # The bank address is not a secret, but it's good to keep it with the bank key.
    BANK_ADDRESS: Optional[str]  = os.getenv("BANK_ADDRESS")
    
    assert PRIVATE_KEY_WIF is not None, "PRIVATE_KEY_WIF must be set in environment variable"
    assert UTXO_STORE_KEY_WIF is not None, "UTXO_STORE_KEY_WIF must be set in environment variable"
    assert PRIVATE_BANK_KEY_WIF is not None, "PRIVATE_BANK_KEY_WIF must be set in environment variable"
    assert PRIVATE_SIGNING_KEY_WIF is not None, "PRIVATE_SIGNING_KEY_WIF must be set in environment variable"

    # The bank address is not a secret, but it's good to keep it with the bank key.
    assert BANK_ADDRESS is not None, "BANK_ADDRESS must be set in environment variable"
    

    # --- Control Behavior (loaded from .env and cast to correct types) ---
    FEE_STRATEGY = int(os.getenv("FEE_STRATEGY", 300))
    LOGGING_UTXO_THRESHOLD = int(os.getenv("LOGGING_UTXO_THRESHOLD", 301))
    MONITOR_POLLING_INTERVAL = int(os.getenv("MONITOR_POLLING_INTERVAL", 30))
    MAINSCRIPT_RUNNING = int(os.getenv("MAINSCRIPT_RUNNING", 1000))
    IGNORE_REST = os.getenv("IGNORE_REST", "True").lower() in ('true', '1', 't')
    
    # Check if critical secrets are missing
    if not all([PRIVATE_KEY_WIF, UTXO_STORE_KEY_WIF, PRIVATE_BANK_KEY_WIF, PRIVATE_SIGNING_KEY_WIF]):
        raise ValueError("One or more critical private keys are missing. Check your .env file.")

# Example of how to use the Config class
# from config import Config
#
# print(f"Fee Strategy: {Config.FEE_STRATEGY}")
# print(f"Is Ignoring Rest: {Config.IGNORE_REST}")
# print(f"Bank Private Key: {Config.PRIVATE_BANK_KEY_WIF}")


