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
import re
from datetime import datetime

# NOTE: We do NOT import Config globally yet,
# to avoid the "chicken-and-egg problem" (Config needs .env).

# --- DEFAULT CONFIGURATION BLOCK ---
DEFAULT_ENV_APPEND = """
# --- AnchorForge Defaults (Auto-generated) ---
NETWORK=test

MAINNET_WOC_API_BASE_URL=https://api.whatsonchain.com/v1/bsv/main
TESTNET_WOC_API_BASE_URL=https://api.whatsonchain.com/v1/bsv/test

# Keystore Paths
KEYPAIR_STORE_FILE=local_config/Keystore/key_pairs.json
X509_KEYPAIR_STORE_FILE=local_config/Keystore/x509_key_pairs.json

# Transaction Fee Strategy
FEE_STRATEGY=1

# UTXO Threshold
LOGGING_UTXO_THRESHOLD=31

# Monitoring Interval
MONITOR_POLLING_INTERVAL=30

# Mainscript Running Count
MAINSCRIPT_RUNNING=1000

# Other Flags
IGNORE_REST=True
"""

def get_paths():
    """Determines the absolute paths for the setup."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return {
        "base": base_dir,
        "local_config": os.path.join(base_dir, "local_config"),
        "keystore": os.path.join(base_dir, "local_config", "Keystore"),
        "env_example": os.path.join(base_dir, ".env.example"),
        "target_env": os.path.join(base_dir, "local_config", ".env")
    }

def extract_keys_from_defaults(defaults_str):
    """
    Extracts variable names (keys) from the default configuration string.
    Returns a set of keys (e.g., {'NETWORK', 'FEE_STRATEGY'}).
    """
    keys = set()
    pattern = re.compile(r"^\s*([A-Z0-9_]+)=")
    for line in defaults_str.splitlines():
        match = pattern.match(line)
        if match:
            keys.add(match.group(1))
    return keys

def update_env_secrets_batch(env_path, updates):
    """
    Replaces multiple secrets in the .env file based on a dictionary.
    updates: Dict { "VAR_NAME": "NEW_VALUE" }
    """
    print(f"📝 Updating {len(updates)} variables in .env...")
    
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = []
        for line in lines:
            # Check if line defines one of our keys
            updated_line = False
            for key, value in updates.items():
                # Strict matching: Start of line, Key, optional space, =, rest
                if re.match(r"^\s*" + re.escape(key) + r"\s*=.*", line):
                    new_lines.append(f"{key}={value}\n")
                    updated_line = True
                    break # Stop checking other keys for this line
            
            if not updated_line:
                new_lines.append(line)
        
        with open(env_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
            
        print("✅ .env file successfully updated.")
        
    except Exception as e:
        print(f"❌ Error updating .env: {e}")
        print("   -> You might need to fill them manually.")

# --- STEP 1: BOOTSTRAP ---

def step1_bootstrap(force=False, use_defaults=False):
    """
    Creates directories, intelligently merges .env.example with defaults.
    """
    paths = get_paths()
    print("--- STEP 1: Environment Bootstrap ---")

    # 1. Check Source
    if not os.path.exists(paths["env_example"]):
        print(f"❌ ERROR: '{paths['env_example']}' missing.")
        sys.exit(1)

    # 2. Create Directories
    if not os.path.exists(paths["local_config"]):
        print(f"📁 Creating directory: {paths['local_config']}")
        os.makedirs(paths["local_config"])
    
    if use_defaults and not os.path.exists(paths["keystore"]):
        print(f"📁 Creating directory: {paths['keystore']}")
        os.makedirs(paths["keystore"])

    # 3. Handle .env Creation/Merge
    
    # Check if target exists
    if os.path.exists(paths["target_env"]) and not force:
        print(f"ℹ️  .env already exists.")
        print("   Keeping existing file (Use --force to overwrite).")
        if use_defaults:
            print("⚠️  Warning: --defaults ignored because file exists and --force was not used.")
        return

    # Logic for overwriting or creating new
    if os.path.exists(paths["target_env"]) and force:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f".env.backup.{timestamp}"
        backup_path = os.path.join(paths["local_config"], backup_name)
        shutil.copy2(paths["target_env"], backup_path)
        print(f"✅ Backup created: {backup_name}")

    print(f"⚙️  Generating .env file...")

    try:
        if use_defaults:
            # Smart Merge: Comment out keys in example that are present in defaults
            default_keys = extract_keys_from_defaults(DEFAULT_ENV_APPEND)
            
            with open(paths["env_example"], "r", encoding="utf-8") as src, \
                 open(paths["target_env"], "w", encoding="utf-8") as dst:
                
                dst.write("# --- CONTENT FROM .env.example ---\n")
                for line in src:
                    key_match = re.match(r"^\s*([A-Z0-9_]+)=", line)
                    if key_match and key_match.group(1) in default_keys:
                        dst.write(f"# [Overridden by Defaults] # {line}")
                    else:
                        dst.write(line)
                
                dst.write("\n" + DEFAULT_ENV_APPEND)
            print(f"✅ .env created with Defaults applied (conflicts resolved).")
            
        else:
            shutil.copy2(paths["env_example"], paths["target_env"])
            print(f"✅ .env created (Copy of example).")

    except Exception as e:
        print(f"❌ Error writing .env: {e}")
        sys.exit(1)

    print("\n👉 NEXT STEPS:")
    print(f"1. Open: {paths['target_env']}")
    print("2. Enter your keys (The script generated defaults, but YOU need to add secrets).")
    print("3. Run: python af_setup_fresh_environment.py --step 2")

# --- STEP 2: CONFIGURE & SYNC ---

def is_placeholder_key(val):
    """Checks if a key value looks like a placeholder or is empty."""
    if not val: return True
    if "YOUR_" in val and "_HERE" in val: return True
    if len(val) < 10: return True
    return False

def generate_keys_for_network(network_name, hostname, key_manager):
    """Generates a key pair for a specific network."""
    print(f"   Generating new {network_name.upper()} Key...")
    new_key = key_manager.generate_key_pair(
        network_type=network_name,
        label=f"autogen_{network_name}_{hostname}",
        comment=f"Step2 Auto-Gen ({network_name})"
    )
    return new_key['private_key_wif'], new_key['public_address']

def step2_configure():
    """
    Loads Config, checks BOTH Testnet and Mainnet keys, generates them if missing,
    writes to .env, and starts sync for the active network.
    """
    paths = get_paths()
    
    # 1. Pre-Check
    if not os.path.exists(paths["target_env"]):
        print("❌ ERROR: .env not found.")
        print("   Please run first: python af_setup_fresh_environment.py --step 1")
        sys.exit(1)

    print("--- STEP 2: Configuration & Sync ---")
    print("🔄 Loading AnchorForge Configuration...")

    try:
        sys.path.append(paths["base"])
        from anchorforge.config import Config
        from anchorforge import key_manager
        # Import PrivateKey and Network for address derivation later
        from bsv import PrivateKey, Network
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        sys.exit(1)

    # 2. Directory Check
    print(f"✅ Directories checked (DB: {getattr(Config, 'DATABASE_DIR', 'ok')})")

    # 3. Check & Generate Keys for BOTH Networks
    try:
        hostname = platform.node() or "dev"
    except: hostname = "dev"

    updates = {}
    
    # --- CHECK TESTNET ---
    # We read from os.environ because Config only exposes the *active* network keys conveniently
    testnet_wif = os.getenv("TESTNET_PRIVATE_KEY_WIF")
    
    if is_placeholder_key(testnet_wif):
        print("⚠️  No valid TESTNET key found.")
        wif, addr = generate_keys_for_network("test", hostname, key_manager)
        updates["TESTNET_PRIVATE_KEY_WIF"] = wif
        updates["TESTNET_UTXO_STORE_KEY_WIF"] = wif
        updates["TESTNET_PRIVATE_BANK_KEY_WIF"] = wif
        updates["TESTNET_PRIVATE_SIGNING_KEY_WIF"] = wif
        updates["TESTNET_BANK_ADDRESS"] = addr
        print(f"   -> Created Testnet Address: {addr}")
    else:
        print("✅ TESTNET keys present.")

    # --- CHECK MAINNET ---
    mainnet_wif = os.getenv("MAINNET_PRIVATE_KEY_WIF")
    
    if is_placeholder_key(mainnet_wif):
        print("⚠️  No valid MAINNET key found.")
        wif, addr = generate_keys_for_network("main", hostname, key_manager)
        updates["MAINNET_PRIVATE_KEY_WIF"] = wif
        updates["MAINNET_UTXO_STORE_KEY_WIF"] = wif
        updates["MAINNET_PRIVATE_BANK_KEY_WIF"] = wif
        updates["MAINNET_PRIVATE_SIGNING_KEY_WIF"] = wif
        updates["MAINNET_BANK_ADDRESS"] = addr
        print(f"   -> Created Mainnet Address: {addr}")
    else:
        print("✅ MAINNET keys present.")

    # Apply Updates
    if updates:
        print(f"\n⚙️  Writing {len(updates)} new keys to .env file...")
        update_env_secrets_batch(paths["target_env"], updates)
        print("✅ Keys saved.")
    else:
        print("✅ All keys are configured. No changes to .env.")

    # 4. Trigger Sync Scripts (Only for ACTIVE network)
    active_net = Config.ACTIVE_NETWORK_NAME
    print(f"\n🚀 Preparing Initial Sync for ACTIVE network: {active_net}")
    
    # Helper to find address for a given network (from updates or env)
    def get_address_for_net(net_name):
        prefix = "TESTNET" if net_name == "test" else "MAINNET"
        # 1. Try updates first (most fresh)
        addr = updates.get(f"{prefix}_BANK_ADDRESS")
        if addr: return addr
        
        # 2. Try Env/WIF
        wif = os.getenv(f"{prefix}_PRIVATE_KEY_WIF")
        if wif and not is_placeholder_key(wif):
            try:
                bsv_net = Network.TESTNET if net_name == "test" else Network.MAINNET
                return str(PrivateKey(wif).address(network=bsv_net))
            except: pass
        return None

    sync_address = get_address_for_net(active_net)

    if not sync_address:
        print("⚠️  Could not determine address for sync. Skipping sync.")
        return

    utxo_script = os.path.join(paths["base"], "af_utxo_manager.py")
    sync_script = os.path.join(paths["base"], "af_sync.py")

    ret1, ret2 = 1, 1

    if os.path.exists(utxo_script) and os.path.exists(sync_script):
        # UTXO Repair
        print(f"1. UTXO Full-Repair ({active_net})...")
        cmd_utxo = f"{sys.executable} {utxo_script} full-repair --address {sync_address} --network {active_net}"
        ret1 = os.system(cmd_utxo)
        
        # Header Sync
        print(f"2. Block Header Sync ({active_net})...")
        cmd_sync = f"{sys.executable} {sync_script} --last 2000 --network {active_net}"
        ret2 = os.system(cmd_sync)

        if ret1 == 0 and ret2 == 0:
            print("\n✅ Setup successfully completed.")
        else:
            print("\n⚠️  Warning: One or more sync scripts had errors.")
    else:
        print("❌ CLI tools not found. Setup incomplete.")

    # 5. Hint for the OTHER network
    other_net = "main" if active_net == "test" else "test"
    other_addr = get_address_for_net(other_net) or "<YOUR_ADDRESS>"
    
    print("\n" + "="*60)
    print(f"💡 IMPORTANT HINT")
    print("="*60)
    print(f"We have synchronized the currently active network: '{active_net}'.")
    print(f"If you switch to '{other_net}' in your .env later,")
    print(f"the local cache will be empty. You MUST run these commands manually:")
    print("-" * 60)
    print(f"python af_utxo_manager.py full-repair --address {other_addr} --network {other_net}")
    print(f"python af_sync.py --last 2000 --network {other_net}")
    print("="*60)

def main():
    parser = argparse.ArgumentParser(description="AnchorForge Environment Setup Tool")
    
    parser.add_argument("--step", type=int, choices=[1, 2], required=True,
                        help="Step 1: Bootstrap .env files / Step 2: Validate Keys & Sync")
    
    parser.add_argument("--force", action="store_true",
                        help="Step 1: Overwrite existing .env (creates backup)")

    parser.add_argument("--defaults", action="store_true",
                        help="Step 1: Apply standard default configuration and resolve conflicts in .env")

    args = parser.parse_args()

    if args.step == 1:
        step1_bootstrap(force=args.force, use_defaults=args.defaults)
    elif args.step == 2:
        # Here we use asyncio.run if async is used internally (optional)
        import asyncio
        asyncio.run(async_wrapper_step2())

async def async_wrapper_step2():
    step2_configure()

if __name__ == "__main__":
    main()