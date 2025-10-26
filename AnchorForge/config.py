# config.py
import os
from typing import Optional
from dotenv import load_dotenv, find_dotenv
from bsv import Network

# Load environment variables from .env file
#load_dotenv(find_dotenv())
load_dotenv("../local_config/.env")

class Config:
    """
    A class to centralize and manage application configuration.
    It reads settings from environment variables, providing a single source of truth.
    """

    # --- Protocol Identifier ---
    # This string is pushed into the OP_RETURN data to identify the application.
    ANCHOR_FORGE_ID = "AnchorForge v0.1"

    ACTIVE_NETWORK_NAME = os.getenv("NETWORK", "test").lower()

    if ACTIVE_NETWORK_NAME == "test":
        NETWORK_PREFIX = "TESTNET_"
        ACTIVE_NETWORK_BSV = Network.TESTNET
    elif ACTIVE_NETWORK_NAME == "main":
        NETWORK_PREFIX = "MAINNET_"
        ACTIVE_NETWORK_BSV = Network.MAINNET
    else:
        raise ValueError(f"Invalid NETWORK '{ACTIVE_NETWORK_NAME}' specified in .env file. Use 'test' or 'main'.")



    WOC_API_BASE_URL: Optional[str] = os.getenv(f"{NETWORK_PREFIX}WOC_API_BASE_URL")
    assert WOC_API_BASE_URL is not None, "WOC_API_BASE_URL must be set in environment variable"

    
    # --- Network-specific API Endpoints ---
    NETWORK_API_ENDPOINTS = {
        "main": "https://api.whatsonchain.com/v1/bsv/main",
        "test": "https://api.whatsonchain.com/v1/bsv/test"
    }
    

    # --- Secrets (loaded from .env) ---
    # It's good practice to handle mandatory keys explicitly.
    PRIVATE_KEY_WIF: Optional[str]  = os.getenv(f"{NETWORK_PREFIX}PRIVATE_KEY_WIF")

    UTXO_STORE_KEY_WIF: Optional[str]  = os.getenv(f"{NETWORK_PREFIX}UTXO_STORE_KEY_WIF")
    PRIVATE_SIGNING_KEY_WIF: Optional[str]  = os.getenv(f"{NETWORK_PREFIX}PRIVATE_SIGNING_KEY_WIF")
    PRIVATE_BANK_KEY_WIF: Optional[str] = os.getenv(f"{NETWORK_PREFIX}PRIVATE_BANK_KEY_WIF")

    # The bank address is not a secret, but it's good to keep it with the bank key.
    BANK_ADDRESS: Optional[str]  = os.getenv(f"{NETWORK_PREFIX}BANK_ADDRESS")
    

    KEYPAIR_STORE_FILE: Optional[str] = os.getenv("KEYPAIR_STORE_FILE")
    
    X509_KEYPAIR_STORE_FILE : Optional[str] = os.getenv("X509_KEYPAIR_STORE_FILE", "../local_config/local_x509_keys.json")

    assert PRIVATE_KEY_WIF is not None, "PRIVATE_KEY_WIF must be set in environment variable"
    assert UTXO_STORE_KEY_WIF is not None, "UTXO_STORE_KEY_WIF must be set in environment variable"
    assert PRIVATE_BANK_KEY_WIF is not None, "PRIVATE_BANK_KEY_WIF must be set in environment variable"
    assert PRIVATE_SIGNING_KEY_WIF is not None, "PRIVATE_SIGNING_KEY_WIF must be set in environment variable"

    assert KEYPAIR_STORE_FILE is not None, "KEYPAIR_STORE_FILE must be set in environment variable"

    # The bank address is not a secret, but it's good to keep it with the bank key.
    assert BANK_ADDRESS is not None, "BANK_ADDRESS must be set in environment variable"
    

    
    # --- File Paths ---
    # --- File Paths ---
    # File paths are now dynamically named based on the active network
    UTXO_STORE_FILE = f"utxo_store_{ACTIVE_NETWORK_NAME}.json"
    USED_UTXO_STORE_FILE = f"used_utxo_store_{ACTIVE_NETWORK_NAME}.json"
    TX_STORE_FILE = f"tx_store_{ACTIVE_NETWORK_NAME}.json"

    # 
    LOG_FILE = f"application_{ACTIVE_NETWORK_NAME}.log"

    # 
    AUDIT_LOG_FILE = f"audit_log_{ACTIVE_NETWORK_NAME}.json"

    
    BLOCK_HEADERS_FILE = f"block_headers_{ACTIVE_NETWORK_NAME}.json"




    # --- Control Behavior (loaded from .env and cast to correct types) ---
    FEE_STRATEGY = int(os.getenv("FEE_STRATEGY", 30))
    LOGGING_UTXO_THRESHOLD = int(os.getenv("LOGGING_UTXO_THRESHOLD", 31))
    MONITOR_POLLING_INTERVAL = int(os.getenv("MONITOR_POLLING_INTERVAL", 30))
    DELAY_NEXT_MONITOR_REQUEST=1
    
    MAINSCRIPT_RUNNING = int(os.getenv("MAINSCRIPT_RUNNING", 1000))
    IGNORE_REST = os.getenv("IGNORE_REST", "True").lower() in ('true', '1', 't')
    
    ACCESS_TIMEOUT = 5  # ATTENTION! CURRENTLY NOT USED EVERYWHERE
    TIMEOUT_1 = 5.0
    TIMEOUT_CONNECT = 10.0


    # Check if critical secrets are missing
    if not all([PRIVATE_KEY_WIF, UTXO_STORE_KEY_WIF, PRIVATE_BANK_KEY_WIF, PRIVATE_SIGNING_KEY_WIF]):
        raise ValueError("One or more critical private keys are missing. Check your .env file.")

    # --- Backup Configuration ---
    BACKUP_DIR = "backup"
    BACKUP_INTERVAL = 100

    # API Limits
    COINGECKO_API_MONTHLY_LIMIT = 10000


    # Other global Vars
    VERBOSE = True # False
    SHOW_RAW_TX = False




