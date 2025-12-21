import os
import sys
import asyncio
from anchorforge.config import Config
from anchorforge import blockchain_api
from bsv import PrivateKey

# Workaround to enable relative Imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

async def main():
    print("--- Initialise environment for computer 2 ---")
    
    # 1. Config triggers creation of folders
    print(f"1. folders checked: {Config.DATABASE_DIR}, {Config.CACHE_DIR}")

    # 2. determine addresses
    if not Config.UTXO_STORE_KEY_WIF:
        print("Error: UTXO_STORE_KEY_WIF is missing in .env")
        return

    pk = PrivateKey(Config.UTXO_STORE_KEY_WIF)
    address = pk.address(network=Config.ACTIVE_NETWORK_BSV)
    print(f"2. Wallet address: {address}")

    # 3. load UTXOs from blockchain (Full Repair)
    # call Manager as subprocess or use the logic directly
    # For simplicity, as sub process to simulate CLI args:
    print("3. Load UTXOs from blockchain (Full Repair)...")
    cmd = f"python utxo_manager.py --address {address} --network {Config.ACTIVE_NETWORK_NAME} full-repair"
    os.system(cmd)

    # 4. Header Sync
    print("4. Synch Block-Header...")
    cmd_sync = f"python af_sync.py --last 50 --network {Config.ACTIVE_NETWORK_NAME}"
    os.system(cmd_sync)

    print("\n--- Setup finished. Env ready for development. ---")

if __name__ == "__main__":
    asyncio.run(main())