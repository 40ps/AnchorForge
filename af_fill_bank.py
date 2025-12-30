import asyncio
from anchorforge.sweep_bank import sweep_to_bank

async def main():
    wif = "cXXXX"
    res = await sweep_to_bank(wif, broadcast=True)
    print(res)

if __name__ == "__main__":
    asyncio.run(main())
