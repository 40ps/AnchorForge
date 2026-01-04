# anchorforge/config.py
import os
import sys
from pathlib import Path  # <--- Modern path handling
from typing import Optional
from dotenv import load_dotenv
from bsv import Network

class Config:
    """
    Central Configuration.
    Uses pathlib to find paths relative to THIS file, not the current working directory.
    """
    
    # --- PATH SETUP ---
    # Determine the path of this file (anchorforge/config.py)
    # and go up two levels to find the project root.
    BASE_DIR = Path(__file__).resolve().parent.parent

    LOCAL_CONFIG_DIR = BASE_DIR / "local_config"

    # Path to .env (flexible location)
    ENV_PATH = LOCAL_CONFIG_DIR / ".env"
    
    # 1. Path for outputs (Logs, JSONs)
    OUTPUT_DIR = BASE_DIR / "output"

    # 2. DATABASE_DIR: Permanent History (TXs, Headers) - CRITICAL FOR PROOFS!
    # These files are part of the evidence chain and should be backed up.
    DATABASE_DIR = BASE_DIR / "database"

    # 3. CACHE_DIR: Wallet State (UTXOs) - Operational Data
    # These represent current money/state. Can be rebuilt/rescanned if lost.
    CACHE_DIR = BASE_DIR / "cache"


    # 4. RUNTIME_DIR: Process Control (Flags, PIDs) - Volatile
    # Can be cleared on restart without data loss.
    RUNTIME_DIR = BASE_DIR / "runtime"

    # IMPORTANT: Create directory immediately if missing.
    # Since we are in the class body, this runs once at startup.
    # Create directories immediately
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(DATABASE_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(RUNTIME_DIR, exist_ok=True)

    
    if not LOCAL_CONFIG_DIR.exists():
        print(f"{LOCAL_CONFIG_DIR} is missing.")
        sys.exit(1)

    # Load .env
    # Safety check if file exists
    if ENV_PATH.exists():
        load_dotenv(ENV_PATH)
    else:
        print(f"WARNING: .env not found at {ENV_PATH}")

    # --- Protocol Identifier ---
    ANCHOR_FORGE_ID = "AnchorForge v0.1"

    ACTIVE_NETWORK_NAME = os.getenv("NETWORK", "test").lower()

    if ACTIVE_NETWORK_NAME == "test":
        NETWORK_PREFIX = "TESTNET_"
        ACTIVE_NETWORK_BSV = Network.TESTNET
    elif ACTIVE_NETWORK_NAME == "main":
        NETWORK_PREFIX = "MAINNET_"
        ACTIVE_NETWORK_BSV = Network.MAINNET
    else:
        raise ValueError(f"Invalid NETWORK '{ACTIVE_NETWORK_NAME}' specified. Use 'test' or 'main'.")

    WOC_API_BASE_URL: Optional[str] = os.getenv(f"{NETWORK_PREFIX}WOC_API_BASE_URL")
    assert WOC_API_BASE_URL is not None, "WOC_API_BASE_URL missing"

    NETWORK_API_ENDPOINTS = {
        "main": "https://api.whatsonchain.com/v1/bsv/main",
        "test": "https://api.whatsonchain.com/v1/bsv/test"
    }

    # --- Secrets ---
    PRIVATE_KEY_WIF: Optional[str]  = os.getenv(f"{NETWORK_PREFIX}PRIVATE_KEY_WIF")
    UTXO_STORE_KEY_WIF: Optional[str]  = os.getenv(f"{NETWORK_PREFIX}UTXO_STORE_KEY_WIF")
    PRIVATE_SIGNING_KEY_WIF: Optional[str]  = os.getenv(f"{NETWORK_PREFIX}PRIVATE_SIGNING_KEY_WIF")
    PRIVATE_BANK_KEY_WIF: Optional[str] = os.getenv(f"{NETWORK_PREFIX}PRIVATE_BANK_KEY_WIF")
    BANK_ADDRESS: Optional[str]  = os.getenv(f"{NETWORK_PREFIX}BANK_ADDRESS")
    
    KEYPAIR_STORE_FILE: Optional[str] = os.getenv("KEYPAIR_STORE_FILE")
    
    # Path correction for Keypair Store (if relative)
    X509_KEYPAIR_STORE_FILE : Optional[str] = os.getenv("X509_KEYPAIR_STORE_FILE")
    if X509_KEYPAIR_STORE_FILE and not os.path.isabs(X509_KEYPAIR_STORE_FILE):
         # If it is e.g. "../local_config/keys.json", handle resolution here if needed.
         # Be careful how it is set in .env.
         pass 

    ANCHOR_CERT_LABEL = "anchor_example_certificate"

    # Assertions (shortened for clarity)
    assert PRIVATE_KEY_WIF is not None
    
    # --- File Paths (CLEANLY IN OUTPUT/DB/CACHE DIR) ---
    # Using direct pathlib operators (OUTPUT_DIR / "file").
    # str(...) converts the Path object to a string at the end, 
    # so the rest of the code (expecting strings) doesn't crash.
    
    # A. CACHE (Operational Wallet State)
    UTXO_STORE_FILE = str(CACHE_DIR / f"utxo_store_{ACTIVE_NETWORK_NAME}.json")
    USED_UTXO_STORE_FILE = str(CACHE_DIR / f"used_utxo_store_{ACTIVE_NETWORK_NAME}.json")

    # B. DATABASE (Permanent History / Proof Data)
    TX_STORE_FILE = str(DATABASE_DIR / f"tx_store_{ACTIVE_NETWORK_NAME}.json")
    BLOCK_HEADERS_FILE = str(DATABASE_DIR / f"block_headers_{ACTIVE_NETWORK_NAME}.json")

    # C. OUTPUT (Logs & Reports)
    LOG_FILE = str(OUTPUT_DIR / f"application_{ACTIVE_NETWORK_NAME}.log")
    
    # Audit Log is a report/export, so it fits in Output. 
    # (Unless you treat it as a database, then move to DATABASE_DIR)
    AUDIT_LOG_FILE = str(OUTPUT_DIR / f"audit_log_{ACTIVE_NETWORK_NAME}.json")




 
    # --- Constants ---
    TSC_PROOF_FIELD = "merkle_proof_tsc_data"
    TSC_TIMESTAMP_FIELD = "tsc_proof_added_utc"
    LEGACY_PROOF_FIELD = "merkle_proof_data"
    LEGACY_SIZE_FIELD = "merkle_proof_size_bytes"
    TSC_SIZE_FIELD = "merkle_proof_tsc_size_bytes"
    LEGACY_PROOF = False

    # --- Control Behavior ---
    MINIMUM_UTXO_VALUE = 10
    MINIMUM_UTXO_VALUE_TESTNET = 10
    FEE_STRATEGY = int(os.getenv("FEE_STRATEGY", 30))
    LOGGING_UTXO_THRESHOLD = int(os.getenv("LOGGING_UTXO_THRESHOLD", 31))
    MONITOR_POLLING_INTERVAL = int(os.getenv("MONITOR_POLLING_INTERVAL", 30))
    DELAY_NEXT_MONITOR_REQUEST=1
    DELAY_BETWEEN_HEADER_REQUESTS=1
    MAINSCRIPT_RUNNING = int(os.getenv("MAINSCRIPT_RUNNING", 1000))
    IGNORE_REST = os.getenv("IGNORE_REST", "True").lower() in ('true', '1', 't')
    ACCESS_TIMEOUT = 5
    TIMEOUT_1 = 5.0
    TIMEOUT_CONNECT = 10.0
    AUDIT_INCLUDING_FILES = True
    
    # Check secrets
    if not all([PRIVATE_KEY_WIF, UTXO_STORE_KEY_WIF, PRIVATE_BANK_KEY_WIF, PRIVATE_SIGNING_KEY_WIF]):
        raise ValueError("Critical keys missing in .env")

    BACKUP_DIR = "backup" # TODO Consider moving this to OUTPUT_DIR/backup too
    BACKUP_INTERVAL = 500
    COINGECKO_API_MONTHLY_LIMIT = 10000
    VERBOSE = True 
    SHOW_RAW_TX = False