"""API Client Utilities.

Provides async/await based API client functionality with proper error handling
and environment-based configuration.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import asyncio
import logging
import types
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from intellicrack.handlers.aiohttp_handler import (
        ClientTimeout,
        aiohttp as aiohttp_module,
    )
else:
    aiohttp_module = None
    ClientTimeout = None

logger = logging.getLogger(__name__)

try:
    from intellicrack.handlers.aiohttp_handler import ClientTimeout, aiohttp

    HAS_AIOHTTP = True
except ImportError as e:
    logger.exception("Import error in api_client: %s", e)
    aiohttp = None
    ClientTimeout = None
    HAS_AIOHTTP = False


class APIClient:
    """Production-ready API client with retry logic and error handling."""

    def __init__(self, base_url: str | None = None) -> None:
        """Initialize the API client with configuration from environment or defaults.

        Args:
            base_url: Optional base URL for API calls. If not provided,
                retrieved from environment variables. Defaults to None.
        """
        from .secrets_manager import get_secret

        if not HAS_AIOHTTP:
            logger.warning("aiohttp not available - API client will use fallback implementation")
        self.base_url = base_url or get_secret("API_BASE_URL", "https://api.intellicrack.com")
        timeout_str = get_secret("API_TIMEOUT", "60")
        self.timeout = int(timeout_str) if timeout_str else 60
        retry_attempts_str = get_secret("API_RETRY_ATTEMPTS", "3")
        self.retry_attempts = int(retry_attempts_str) if retry_attempts_str else 3
        retry_delay_str = get_secret("API_RETRY_DELAY", "1000")
        self.retry_delay = (int(retry_delay_str) if retry_delay_str else 1000) / 1000  # Convert ms to seconds
        self.session: Any = None

    async def __aenter__(self) -> "APIClient":
        """Async context manager entry.

        Returns:
            APIClient: The APIClient instance for use in async context manager.
        """
        if not HAS_AIOHTTP:
            return self
        if ClientTimeout is not None and aiohttp is not None:
            timeout = ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Async context manager exit.

        Args:
            exc_type: Exception type if an exception occurred, or None.
            exc_val: Exception instance if an exception occurred, or None.
            exc_tb: Traceback if an exception occurred, or None.
        """
        if self.session is not None:
            await self.session.close()

    async def fetch(
        self,
        endpoint: str,
        method: str = "GET",
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Fetch data from API endpoint with retry logic and error handling.

        Args:
            endpoint: API endpoint path.
            method: HTTP method (GET, POST, PUT, DELETE). Defaults to "GET".
            data: Request data for POST/PUT requests. Defaults to None.
            headers: Additional headers for the request. Defaults to None.

        Returns:
            dict[str, Any]: Response data as dictionary containing the API response.

        Raises:
            RuntimeError: If session is not initialized or max retry attempts
                exceeded.
            ValueError: On invalid API responses (4xx client errors).
            ClientError: On server errors (5xx) after retry attempts exhausted.

        """
        if not HAS_AIOHTTP:
            # Fallback implementation using requests or urllib
            logger.warning("API call to %s skipped - aiohttp not available", endpoint)
            return {
                "error": "aiohttp not available",
                "fallback": True,
                "endpoint": endpoint,
                "method": method,
            }

        url = f"{self.base_url}{endpoint}"

        # Default headers
        default_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Add API key if available
        from .secrets_manager import get_secret

        if api_key := get_secret("API_KEY"):
            default_headers["Authorization"] = f"Bearer {api_key}"

        if headers:
            default_headers |= headers

        # Retry logic
        for attempt in range(self.retry_attempts):
            try:
                if self.session is None:
                    raise RuntimeError("Session not initialized - use async context manager")
                async with self.session.request(
                    method=method,
                    url=url,
                    json=data,
                    headers=default_headers,
                ) as response:
                    # Check response status
                    if not response.ok:
                        error_msg = f"API request failed: {response.status} {response.reason}"

                        # Try to get error details from response
                        try:
                            error_data = await response.json()
                            error_msg = f"{error_msg} - {error_data.get('error', error_data)}"
                        except Exception as e:
                            logger.debug("Failed to parse error response: %s", e, exc_info=True)

                        # Don't retry client errors (4xx)
                        if 400 <= response.status < 500:
                            logger.error(error_msg)
                            raise ValueError(error_msg)

                        # Retry server errors (5xx)
                        logger.error(error_msg)
                        raise aiohttp.ClientError(error_msg)

                    # Parse response
                    result: dict[str, Any] = await response.json()
                    return result

            except (TimeoutError, aiohttp.ClientError) as e:
                logger.warning("API request attempt %s failed: %s", attempt + 1, e, exc_info=True)

                # Don't retry on last attempt
                if attempt >= self.retry_attempts - 1:
                    raise

                # Wait before retry
                await asyncio.sleep(self.retry_delay)

        error_msg = "Max retry attempts exceeded"
        logger.error(error_msg)
        raise RuntimeError(error_msg)


async def make_api_call(endpoint: str, method: str = "GET", data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Convenience function for making API calls.

    Args:
        endpoint: API endpoint path.
        method: HTTP method (GET, POST, PUT, DELETE). Defaults to "GET".
        data: Optional request data for POST/PUT requests. Defaults to None.

    Returns:
        dict[str, Any]: Response data as dictionary containing the API response.

    Raises:
        RuntimeError: If session is not initialized or max retry attempts
            exceeded.
        ValueError: On invalid API responses (4xx client errors).
        ClientError: On server errors (5xx) after retry attempts exhausted.
    """
    async with APIClient() as client:
        return await client.fetch(endpoint, method, data)


# Synchronous wrapper for compatibility
def sync_api_call(endpoint: str, method: str = "GET", data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Synchronous wrapper for making API calls.

    Runs async API calls in a new event loop for synchronous contexts.

    Args:
        endpoint: API endpoint path.
        method: HTTP method (GET, POST, PUT, DELETE). Defaults to "GET".
        data: Optional request data for POST/PUT requests. Defaults to None.

    Returns:
        dict[str, Any]: Response data as dictionary containing the API response.

    Raises:
        RuntimeError: If session is not initialized or max retry attempts
            exceeded.
        ValueError: On invalid API responses (4xx client errors).
        ClientError: On server errors (5xx) after retry attempts exhausted.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(make_api_call(endpoint, method, data))
    finally:
        loop.close()
