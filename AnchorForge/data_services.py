# data_services.py
# Provide foundation to count API requests to control limits 
# AF_py/data_services.py
import asyncio
import logging
import json
import httpx  # A modern, async-capable HTTP client library

import utils
from config import Config

logger = logging.getLogger(__name__)

async def get_coingecko_bsv_price():
    """
    Fetches the current price for Bitcoin SV in EUR from the CoinGecko API.
    It now also requests the last_updated_at timestamp from the server.
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
        'include_last_updated_at': 'true'  # Request the server timestamp
    }
    headers = {
        'Accept': 'application/json'
    }

    price_data = None
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()  # Will raise an exception for 4xx/5xx status codes
            price_data = response.json()
            logger.info(f"Successfully fetched data from CoinGecko: {price_data}")

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error occurred while fetching CoinGecko data: {e.response.status_code} - {e.response.text}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred during CoinGecko API call: {e}")
        return None

    # 3. If the call was successful, increment the counter
    if price_data:
        utils.increment_api_usage('coingecko')
        
    return price_data