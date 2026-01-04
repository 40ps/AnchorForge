import asyncio
from anchorforge.config import Config
from anchorforge.sweep_bank import sweep_to_bank

async def main():
    wif = "cXXXX"

    min_sats = 546

    if Config.ACTIVE_NETWORK_NAME == "test":
        dust_limit = Config.MINIMUM_UTXO_VALUE_TESTNET
    else:
        dust_limit = Config.MINIMUM_UTXO_VALUE

    res = await sweep_to_bank(wif, broadcast=True, min_output_sats=min_sats)
    print(res)

if __name__ == "__main__":
    asyncio.run(main())
