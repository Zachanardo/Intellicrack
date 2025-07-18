"""
API Client Utilities

Provides async/await based API client functionality with proper error handling
and environment-based configuration.

Copyright (C) 2025 Zachary Flint
"""

import asyncio
import logging
from typing import Any, Dict, Optional

from .secrets_manager import get_secret

logger = logging.getLogger(__name__)

try:
    import aiohttp
    from aiohttp import ClientTimeout
    HAS_AIOHTTP = True
except ImportError as e:
    logger.error("Import error in api_client: %s", e)
    aiohttp = None
    ClientTimeout = None
    HAS_AIOHTTP = False


class APIClient:
    """Production-ready API client with retry logic and error handling."""

    def __init__(self, base_url: Optional[str] = None):
        """Initialize the API client with configuration from environment or defaults."""
        if not HAS_AIOHTTP:
            logger.warning("aiohttp not available - API client will use fallback implementation")
        self.base_url = base_url or get_secret('API_BASE_URL', 'https://api.intellicrack.com')
        self.timeout = int(get_secret('API_TIMEOUT', '60'))
        self.retry_attempts = int(get_secret('API_RETRY_ATTEMPTS', '3'))
        self.retry_delay = int(get_secret('API_RETRY_DELAY', '1000')) / 1000  # Convert ms to seconds
        self.session = None

    async def __aenter__(self):
        """Async context manager entry."""
        if not HAS_AIOHTTP:
            return self
        timeout = ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session and HAS_AIOHTTP:
            await self.session.close()

    async def fetch(self, endpoint: str, method: str = 'GET',
                   data: Optional[Dict[str, Any]] = None,
                   headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Fetch data from API endpoint with retry logic and error handling.

        Args:
            endpoint: API endpoint path
            method: HTTP method (GET, POST, PUT, DELETE)
            data: Request data for POST/PUT
            headers: Additional headers

        Returns:
            Response data as dictionary

        Raises:
            aiohttp.ClientError: On network errors
            ValueError: On invalid responses
        """
        if not HAS_AIOHTTP:
            # Fallback implementation using requests or urllib
            logger.warning(f"API call to {endpoint} skipped - aiohttp not available")
            return {
                'error': 'aiohttp not available',
                'fallback': True,
                'endpoint': endpoint,
                'method': method
            }

        url = f"{self.base_url}{endpoint}"

        # Default headers
        default_headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        # Add API key if available
        api_key = get_secret('API_KEY')
        if api_key:
            default_headers['Authorization'] = f'Bearer {api_key}'

        if headers:
            default_headers.update(headers)

        # Retry logic
        for attempt in range(self.retry_attempts):
            try:
                async with self.session.request(
                    method=method,
                    url=url,
                    json=data,
                    headers=default_headers
                ) as response:
                    # Check response status
                    if not response.ok:
                        error_msg = f"API request failed: {response.status} {response.reason}"

                        # Try to get error details from response
                        try:
                            error_data = await response.json()
                            error_msg = f"{error_msg} - {error_data.get('error', error_data)}"
                        except Exception as e:
                            logger.debug(f"Failed to parse error response: {e}")

                        # Don't retry client errors (4xx)
                        if 400 <= response.status < 500:
                            raise ValueError(error_msg)

                        # Retry server errors (5xx)
                        raise aiohttp.ClientError(error_msg)

                    # Parse response
                    return await response.json()

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(f"API request attempt {attempt + 1} failed: {e}")

                # Don't retry on last attempt
                if attempt >= self.retry_attempts - 1:
                    raise

                # Wait before retry
                await asyncio.sleep(self.retry_delay)

        raise RuntimeError("Max retry attempts exceeded")


async def make_api_call(endpoint: str, method: str = 'GET',
                       data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience function for making API calls.

    Args:
        endpoint: API endpoint
        method: HTTP method
        data: Request data

    Returns:
        Response data
    """
    async with APIClient() as client:
        return await client.fetch(endpoint, method, data)


# Synchronous wrapper for compatibility
def sync_api_call(endpoint: str, method: str = 'GET',
                  data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Synchronous wrapper for API calls.

    Args:
        endpoint: API endpoint
        method: HTTP method
        data: Request data

    Returns:
        Response data
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(make_api_call(endpoint, method, data))
    finally:
        loop.close()
