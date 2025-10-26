# AF_py/data_services.py
import asyncio
import logging
import json
import aiohttp  # Use aiohttp instead of httpx

import utils
from config import Config

logger = logging.getLogger(__name__)

async def get_coingecko_bsv_price():
    """
    Fetches the current price for Bitcoin SV in EUR from the CoinGecko API using aiohttp.
    It checks the API usage limit before making a call and increments the counter on success.

    Returns:
        dict: The price data from the API, e.g., {'bitcoin-cash-sv': {'eur': 45.33}}, or None on failure.
    """
    # 1. Check if we are within the API limits before making the call
    if utils.check_api_limit_exceeded('coingecko', limit=Config.COINGECKO_API_MONTHLY_LIMIT):
        logger.error("CoinGecko API monthly limit reached or exceeded. Halting request.")
        return None

    # 2. Make the API call
    url = "https://api.coingecko.com/api/v3/simple/price"
    params = {
        'ids': 'bitcoin-cash-sv',
        'vs_currencies': 'eur',
        'include_last_updated_at': 'true'
    }
    headers = {
        'Accept': 'application/json'
    }

    # aiohttp uses a different timeout object
    timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT_CONNECT)

    price_data = None
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    price_data = await response.json()
                    logger.info(f"Successfully fetched data from CoinGecko: {price_data}")
                else:
                    error_text = await response.text()
                    logger.error(f"HTTP error occurred while fetching CoinGecko data: {response.status} - {error_text}")
                    return None

    except asyncio.TimeoutError:
        logger.error(f"Request to CoinGecko failed: Timeout occurred after {Config.TIMEOUT_CONNECT} seconds.")
        return None
    except aiohttp.ClientError as e:
        logger.error(f"Request to CoinGecko failed: A network client error occurred. Error: {e}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred during CoinGecko API call: {e}")
        return None

    # 3. If the call was successful, increment the counter
    if price_data:
        utils.increment_api_usage('coingecko')
        
    return price_data