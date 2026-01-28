import asyncio
import logging

from anchorforge.config import Config
from anchorforge.transfer import sweep_funds

async def main():
    Config.validate_wallet_config()
    source_wif = Config.TEMPORARY_SOURCE_FUNDS_KEY_WIF

    if not source_wif:
        print("ERROR: TEMPORARY_SOURCE_FUNDS_KEY_WIF is not set in .env or Config.")
        return

    min_sats = 546

    if Config.ACTIVE_NETWORK_NAME == "test":
        min_sats = Config.MINIMUM_UTXO_VALUE_TESTNET
    else:
        min_sats = Config.MINIMUM_UTXO_VALUE


    assert Config.BANK_ADDRESS is not None, "Bankaddress is not set"

    res = await sweep_funds(
        private_key_wif=source_wif, 
        destination_address=Config.BANK_ADDRESS,
        broadcast=True, 
        min_output_sats=min_sats)
    print(res)

if __name__ == "__main__":
    asyncio.run(main())
