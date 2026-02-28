# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    config.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

# anchorforge/config.py
import os
import sys
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from bsv import Network

import logging
from importlib.metadata import version, PackageNotFoundError


class Config:
    """
    Central Configuration.
    Manages paths, network settings, and secrets.
    """

    # --- central Identity ---
    PROJECT_NAME = "AnchorForge"


    try:
        __version__ = version("anchorforge")
    except PackageNotFoundError:
        # Fallback, falls das Paket nicht installiert ist (z.B. während der Entwicklung)
        __version__ = "0.2.0-beta-local"

    @classmethod
    def get_app_header(cls):
        """returns standardized header for log outputs"""
        # using cls to ensure to use class variables
        return f"{cls.PROJECT_NAME} v{cls.__version__}"
    
    # --- PATH SETUP ---
    BASE_DIR = Path(__file__).resolve().parent.parent
    LOCAL_CONFIG_DIR = BASE_DIR / "local_config"
    ENV_PATH = LOCAL_CONFIG_DIR / ".env"
    
    # --- NEW DIRECTORY STRUCTURE ---
    
    # 1. OUTPUT: Logs & Reports
    OUTPUT_DIR = BASE_DIR / "output"

    # 2. DATABASE: Permanent History (TXs) - Private & Critical
    DATABASE_DIR = BASE_DIR / "database"

    # 3. WALLET CACHE: UTXOs - Private & Reconstructible
    # "My State": Should not be shared publicly.
    WALLET_CACHE_DIR = BASE_DIR / "cache" / "wallet"

    # 4. PUBLIC CACHE: Block Headers - Public & Shared
    # "Global State": Can be distributed with the Verifier.
    PUBLIC_CACHE_DIR = BASE_DIR / "cache" / "public"

    # 5. RUNTIME: Process Control (Flags, PIDs)
    RUNTIME_DIR = BASE_DIR / "runtime"

    # Create all directories immediately
    # TODO better: call explicitely or they are created even in unit tests
    for d in [OUTPUT_DIR, DATABASE_DIR, WALLET_CACHE_DIR, PUBLIC_CACHE_DIR, RUNTIME_DIR]:
        os.makedirs(d, exist_ok=True)
    
    if not LOCAL_CONFIG_DIR.exists():
        # Fallback/Warning if config dir is missing (e.g. fresh clone)
        print(f"Hinweis: {LOCAL_CONFIG_DIR} existiert nicht. Nutze Standardwerte/Env-Vars.")

    # Load .env
    if ENV_PATH.exists():
        load_dotenv(ENV_PATH)
    else:
        # Not critical for Verifier mode, so just print warning
        pass 

    # --- Protocol Identifier ---
    # ANCHOR_FORGE_ID = "AnchorForge v0.1" # until 2026-01-17
    ANCHOR_FORGE_ID = "AnchorForge v0.2"
    

    ACTIVE_NETWORK_NAME = os.getenv("NETWORK", "test").lower()

    if ACTIVE_NETWORK_NAME == "test":
        NETWORK_PREFIX = "TESTNET_"
        ACTIVE_NETWORK_BSV = Network.TESTNET
    elif ACTIVE_NETWORK_NAME == "main":
        NETWORK_PREFIX = "MAINNET_"
        ACTIVE_NETWORK_BSV = Network.MAINNET
    else:
        raise ValueError(f"Invalid NETWORK '{ACTIVE_NETWORK_NAME}' specified. Use 'test' or 'main'.")

    # API is needed for both Verifier and Anchor
    WOC_API_BASE_URL: Optional[str] = os.getenv(f"{NETWORK_PREFIX}WOC_API_BASE_URL")
    if not WOC_API_BASE_URL:
        # Fallback defaults if .env is missing (useful for quick start verifiers)
        if ACTIVE_NETWORK_NAME == "main":
             WOC_API_BASE_URL = "https://api.whatsonchain.com/v1/bsv/main"
        else:
             WOC_API_BASE_URL = "https://api.whatsonchain.com/v1/bsv/test"

    
    NETWORK_API_ENDPOINTS = {
        "main": "https://api.whatsonchain.com/v1/bsv/main",
        "test": "https://api.whatsonchain.com/v1/bsv/test"
    }

    
    # --- Secrets (Lazy Loading) ---
    # We explicitly allow these to be None so the Verifier doesn't crash.
    PRIVATE_KEY_WIF: Optional[str]  = os.getenv(f"{NETWORK_PREFIX}PRIVATE_KEY_WIF")
    UTXO_STORE_KEY_WIF: Optional[str]  = os.getenv(f"{NETWORK_PREFIX}UTXO_STORE_KEY_WIF")
    PRIVATE_SIGNING_KEY_WIF: Optional[str]  = os.getenv(f"{NETWORK_PREFIX}PRIVATE_SIGNING_KEY_WIF")
    PRIVATE_BANK_KEY_WIF: Optional[str] = os.getenv(f"{NETWORK_PREFIX}PRIVATE_BANK_KEY_WIF")
    BANK_ADDRESS: Optional[str]  = os.getenv(f"{NETWORK_PREFIX}BANK_ADDRESS")

    TEMPORARY_SOURCE_FUNDS_KEY_WIF: Optional[str] = os.getenv(f"{NETWORK_PREFIX}TEMPORARY_SOURCE_FUNDS_KEY_WIF")

    
    KEYPAIR_STORE_FILE: Optional[str] = os.getenv("KEYPAIR_STORE_FILE")
    X509_KEYPAIR_STORE_FILE : Optional[str] = os.getenv("X509_KEYPAIR_STORE_FILE")

    ANCHOR_CERT_LABEL = "anchor_example_certificate"

    # --- File Paths ---

    # A. WALLET CACHE (Private)
    # Used by wallet_manager. Points to the private cache subdir.
    # Note: wallet_manager usually builds filenames dynamically, but uses this dir as base.
    CACHE_DIR = WALLET_CACHE_DIR # Alias for compatibility with existing wallet_manager
    
    UTXO_STORE_FILE = str(WALLET_CACHE_DIR / f"utxo_store_{ACTIVE_NETWORK_NAME}.json")
    USED_UTXO_STORE_FILE = str(WALLET_CACHE_DIR / f"used_utxo_store_{ACTIVE_NETWORK_NAME}.json")

    # B. PUBLIC CACHE (Public)
    # Block Headers reside here now.
    BLOCK_HEADERS_FILE = str(PUBLIC_CACHE_DIR / f"block_headers_{ACTIVE_NETWORK_NAME}.json")

    # C. DATABASE (Private History)
    TX_STORE_FILE = str(DATABASE_DIR / f"tx_store_{ACTIVE_NETWORK_NAME}.json")

    # D. OUTPUT (Logs & Reports)
    LOG_FILE = str(OUTPUT_DIR / f"application_{ACTIVE_NETWORK_NAME}.log")
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

    ONCHAIN_DATA_SIZE_LIMIT = 100000
    
    FEE_STRATEGY = int(os.getenv("FEE_STRATEGY", 100))
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
    
    BACKUP_DIR = "backup"
    BACKUP_INTERVAL = 500
    COINGECKO_API_MONTHLY_LIMIT = 10000
    VERBOSE = True 
    SHOW_RAW_TX = False

    @classmethod
    def validate_wallet_config(cls):
        """
        Explicitly check if wallet keys are present.
        Call this method from scripts that REQUIRE a wallet (Anchor, Monitor).
        Do NOT call this from scripts that are read-only (Verifier, Sync).
        """
        missing = []
        if not cls.PRIVATE_KEY_WIF: missing.append("PRIVATE_KEY_WIF")
        if not cls.UTXO_STORE_KEY_WIF: missing.append("UTXO_STORE_KEY_WIF")
        
        if missing:
            raise ValueError(f"CRITICAL: Missing wallet keys in .env: {', '.join(missing)}. "
                             f"This script requires a configured wallet.")
        
# Shortcut for easy access to Version 
APP_VERSION = Config.__version__