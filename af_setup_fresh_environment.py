# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    af_setup_fresh_environment.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

import os
import sys
import shutil
import argparse
import platform
from datetime import datetime

# NOTE: We do NOT import Config globally yet,
# to avoid the "chicken-and-egg problem" (Config needs .env).

def get_paths():
    """Determines the absolute paths for the setup."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return {
        "base": base_dir,
        "local_config": os.path.join(base_dir, "local_config"),
        "env_example": os.path.join(base_dir, ".env.example"),
        "target_env": os.path.join(base_dir, "local_config", ".env")
    }

# --- STEP 1: BOOTSTRAP ---

def step1_bootstrap(force=False):
    """
    Creates directories and copies .env.example.
    """
    paths = get_paths()
    print("--- STEP 1: Environment Bootstrap ---")

    # 1. Check Source
    if not os.path.exists(paths["env_example"]):
        print(f"❌ ERROR: '{paths['env_example']}' missing.")
        sys.exit(1)

    # 2. Create Directory
    if not os.path.exists(paths["local_config"]):
        print(f"📁 Creating directory: {paths['local_config']}")
        os.makedirs(paths["local_config"])

    # 3. Handle .env
    if os.path.exists(paths["target_env"]):
        print(f"ℹ️  .env already exists.")
        if force:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f".env.backup.{timestamp}"
            backup_path = os.path.join(paths["local_config"], backup_name)
            shutil.copy2(paths["target_env"], backup_path)
            print(f"✅ Backup created: {backup_name}")
            
            shutil.copy2(paths["env_example"], paths["target_env"])
            print(f"✅ .env has been overwritten (Reset).")
        else:
            print("   Keeping existing file (Use --force to overwrite).")
    else:
        shutil.copy2(paths["env_example"], paths["target_env"])
        print(f"✅ .env file created.")

    print("\n👉 NEXT STEPS:")
    print(f"1. Open: {paths['target_env']}")
    print("2. Enter your keys (if available) or adjust 'NETWORK'.")
    print("3. Run: python af_setup_fresh_environment.py --step 2")

# --- STEP 2: CONFIGURE & SYNC ---

def step2_configure():
    """
    Loads Config, generates keys (if necessary), and starts sync.
    """
    paths = get_paths()
    
    # 1. Pre-Check
    if not os.path.exists(paths["target_env"]):
        print("❌ ERROR: .env not found.")
        print("   Please run first: python af_setup_fresh_environment.py --step 1")
        sys.exit(1)

    print("--- STEP 2: Configuration & Sync ---")
    print("🔄 Loading AnchorForge Configuration...")

    # Import safely now
    try:
        # Ensure path for modules
        sys.path.append(paths["base"])
        from anchorforge.config import Config
        from anchorforge import key_manager
        from bsv import PrivateKey
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        sys.exit(1)

    # 2. Directory Check (Config creates these automatically on import)
    print(f"✅ Directories checked (DB: {getattr(Config, 'DATABASE_DIR', 'ok')})")

    # 3. Key Validation logic
    wif_in_env = Config.PRIVATE_KEY_WIF
    # Roughly check if default text is still present
    is_default_key = wif_in_env is None or "put_your_key_here" in wif_in_env or len(wif_in_env) < 10

    address = None

    if not is_default_key:
        try:
            pk = PrivateKey(wif_in_env)
            address = pk.address(network=Config.ACTIVE_NETWORK_BSV)
            print(f"✅ Valid key found.")
            print(f"   Address: {address}")
            print(f"   Network: {Config.ACTIVE_NETWORK_NAME}")
        except Exception as e:
            print(f"❌ Error reading key from .env: {e}")
            sys.exit(1)
    else:
        print("\n⚠️  No valid key configured.")
        print("   Generating new key for this setup...")
        
        try:
            hostname = platform.node() or "dev"
        except: hostname = "dev"

        new_key = key_manager.generate_key_pair(
            network_type=Config.ACTIVE_NETWORK_NAME,
            label=f"autogen_{hostname}",
            comment="Step2 Auto-Gen"
        )
        address = new_key['public_address']
        wif = new_key['private_key_wif']

        print("\n" + "="*60)
        print("🔑 NEW KEY GENERATED")
        print("="*60)
        print(f"WIF:     {wif}")
        print(f"Address: {address}")
        print("="*60)
        print("🔴 ACTION REQUIRED:")
        print(f"   Please copy the WIF above NOW into your .env file: {paths['target_env']}")
        print("   Save the file and press [ENTER] to start sync.")
        input() # Waits for user confirmation that key is inserted for sync
        
        # Note: For the following sync we use the variable 'address',
        # even if the user hasn't saved the key yet,
        # the sync (public data) will work, but subsequent Txs would fail.

    # 4. Trigger Sync Scripts
    utxo_script = os.path.join(paths["base"], "af_utxo_manager.py")
    sync_script = os.path.join(paths["base"], "af_sync.py")

    print(f"\n🚀 Starting Initial Sync for {address} ({Config.ACTIVE_NETWORK_NAME})...")

    if os.path.exists(utxo_script) and os.path.exists(sync_script):
        # UTXO Repair
        cmd_utxo = f"{sys.executable} {utxo_script} full-repair --address {address} --network {Config.ACTIVE_NETWORK_NAME}"
        print(f"   > {cmd_utxo}")
        ret1 = os.system(cmd_utxo)
        
        # Header Sync
        cmd_sync = f"{sys.executable} {sync_script} --last 2000 --network {Config.ACTIVE_NETWORK_NAME}"
        print(f"   > {cmd_sync}")
        ret2 = os.system(cmd_sync)

        if ret1 == 0 and ret2 == 0:
            print("\n✅ Setup successfully completed.")
        else:
            print("\n⚠️  Warning: One or more sync scripts had errors.")
    else:
        print("❌ CLI tools not found. Setup incomplete.")

def main():
    parser = argparse.ArgumentParser(description="AnchorForge Environment Setup Tool")
    
    parser.add_argument("--step", type=int, choices=[1, 2], required=True,
                        help="Step 1: Bootstrap .env files / Step 2: Validate Keys & Sync")
    
    parser.add_argument("--force", action="store_true",
                        help="Step 1: Overwrite existing .env (creates backup)")

    args = parser.parse_args()

    if args.step == 1:
        step1_bootstrap(force=args.force)
    elif args.step == 2:
        # Here we use asyncio.run if async is used internally (optional)
        import asyncio
        asyncio.run(async_wrapper_step2())

async def async_wrapper_step2():
    step2_configure()

if __name__ == "__main__":
    main()