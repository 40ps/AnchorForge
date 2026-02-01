# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    af_drain_bank.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

# af_drain_bank.py
import asyncio
import argparse
from anchorforge.config import Config
from anchorforge.transfer import sweep_funds

async def main():
    Config.validate_wallet_config()

    assert Config.PRIVATE_BANK_KEY_WIF is not None, "Bank WIF not set (should be validated)"


    parser = argparse.ArgumentParser(description="Drain all funds from the Bank Address to a target address.")
    parser.add_argument("target_address", type=str, help="The BSV address to receive the funds.")
    args = parser.parse_args()

    print(f"--- DRAINING BANK ---")
    print(f"Source (Bank): {Config.BANK_ADDRESS}")
    print(f"Target:        {args.target_address}")
    
    confirm = input("Are you sure? (y/n): ")
    if confirm.lower() != 'y':
        print("Aborted.")
        return

    # Wir nutzen den BANK KEY als Quelle
    res = await sweep_funds(
        private_key_wif=Config.PRIVATE_BANK_KEY_WIF,
        destination_address=args.target_address,
        broadcast=True
    )

    if res:
        print(f"Bank drained successfully! TXID: {res.get('txid')}")
    else:
        print("Failed to drain bank (maybe empty?).")

if __name__ == "__main__":
    asyncio.run(main())