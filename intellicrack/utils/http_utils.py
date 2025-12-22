"""HTTP Request Utilities with Configurable SSL Verification.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import os
import warnings
from collections.abc import Callable
from pathlib import Path
from typing import Any

import requests
from requests import PreparedRequest, Response
from requests.adapters import HTTPAdapter
from requests.auth import AuthBase
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

from intellicrack.utils.logger import logger


class SecureHTTPClient:
    """HTTP client with configurable SSL verification for security research."""

    def __init__(self) -> None:
        """Initialize HTTP client with configuration from IntellicrackConfig."""
        from intellicrack.core.config_manager import IntellicrackConfig

        self.config_manager = IntellicrackConfig()
        self.session: requests.Session = requests.Session()
        self._setup_session()

    def _setup_session(self) -> None:
        """Configure session with retry logic and SSL settings."""
        config: dict[str, Any] = dict(self.config_manager._config)
        network_config_raw: object = config.get("network", {})
        network_config: dict[str, Any] = network_config_raw if isinstance(network_config_raw, dict) else {}

        # Set up retry strategy
        max_retries_raw: Any = network_config.get("max_retries", 3)
        max_retries: int = max_retries_raw if isinstance(max_retries_raw, int) else 3

        backoff_factor_raw: Any = network_config.get("retry_delay", 1)
        backoff_factor: int = backoff_factor_raw if isinstance(backoff_factor_raw, int) else 1

        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set default headers
        user_agent_raw: Any = network_config.get("user_agent", "Intellicrack/3.0")
        user_agent: str = user_agent_raw if isinstance(user_agent_raw, str) else "Intellicrack/3.0"
        self.session.headers.update({"User-Agent": user_agent})

        # Configure proxy if enabled
        proxy_enabled_raw: Any = network_config.get("proxy_enabled", False)
        proxy_enabled: bool = proxy_enabled_raw if isinstance(proxy_enabled_raw, bool) else False

        if proxy_enabled:
            proxy_host_raw: Any = network_config.get("proxy_host", "")
            proxy_host: str = proxy_host_raw if isinstance(proxy_host_raw, str) else ""

            proxy_port_raw: Any = network_config.get("proxy_port", 8080)
            proxy_port: int = proxy_port_raw if isinstance(proxy_port_raw, int) else 8080

            proxy_username_raw: Any = network_config.get("proxy_username", "")
            proxy_username: str = proxy_username_raw if isinstance(proxy_username_raw, str) else ""

            proxy_password_raw: Any = network_config.get("proxy_password", "")
            proxy_password: str = proxy_password_raw if isinstance(proxy_password_raw, str) else ""

            if proxy_host:
                proxy_url: str = f"http://{proxy_host}:{proxy_port}"
                if proxy_username and proxy_password:
                    proxy_url = f"http://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}"

                self.session.proxies = {"http": proxy_url, "https": proxy_url}

    def _get_ssl_verify(self, override_verify: bool | str | None = None) -> bool | str:
        """Get SSL verification setting with override capability.

        Args:
            override_verify: Optional override for SSL verification.
                - True: Enable verification (default)
                - False: Disable verification (for self-signed certs)
                - str: Path to CA bundle file

        Returns:
            SSL verification setting for requests

        """
        if override_verify is not None:
            if override_verify is False:
                # Warn when disabling SSL verification
                logger.warning(
                    "SSL certificate verification disabled for this request. "
                    "This should only be used for testing with self-signed certificates.",
                )
                # Suppress only the specific InsecureRequestWarning
                warnings.filterwarnings("ignore", category=InsecureRequestWarning)
            return override_verify

        # Get from configuration
        config: dict[str, Any] = dict(self.config_manager._config)
        network_config_raw: object = config.get("network", {})
        network_config: dict[str, Any] = network_config_raw if isinstance(network_config_raw, dict) else {}

        ssl_verify_raw: Any = network_config.get("ssl_verify", True)
        ssl_verify: bool = ssl_verify_raw if isinstance(ssl_verify_raw, bool) else True

        # Check for custom CA bundle path
        ca_bundle_path_raw: Any = network_config.get("ca_bundle_path", "")
        ca_bundle_path: str = ca_bundle_path_raw if isinstance(ca_bundle_path_raw, str) else ""
        if ca_bundle_path and Path(ca_bundle_path).exists():
            return ca_bundle_path

        # Check environment variable for CA bundle
        env_ca_bundle: str = os.environ.get("REQUESTS_CA_BUNDLE", "")
        if env_ca_bundle and Path(env_ca_bundle).exists():
            return env_ca_bundle

        if not ssl_verify:
            logger.warning("SSL certificate verification is disabled in configuration. Consider enabling it for production use.")
            warnings.filterwarnings("ignore", category=InsecureRequestWarning)

        return ssl_verify

    def request(self, method: str, url: str, verify: bool | str | None = None, **kwargs: Any) -> Response:
        """Make an HTTP request with configurable SSL verification.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            verify: SSL verification override (True, False, or CA bundle path)
            **kwargs: Additional arguments passed to requests

        Returns:
            Response object

        """
        # Get timeout from config if not specified
        if "timeout" not in kwargs:
            config: dict[str, Any] = dict(self.config_manager._config)
            network_config_raw: object = config.get("network", {})
            network_config: dict[str, Any] = network_config_raw if isinstance(network_config_raw, dict) else {}
            timeout_raw: object = network_config.get("timeout", 30)
            timeout: int = timeout_raw if isinstance(timeout_raw, int) else 30
            kwargs["timeout"] = timeout

        # Set SSL verification
        kwargs["verify"] = self._get_ssl_verify(verify)

        # Log the request (without sensitive data)
        logger.debug("Making %s request to %s", method, url)

        try:
            response: Response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.SSLError as e:
            logger.error("SSL error for %s: %s", url, e, exc_info=True)
            logger.info(
                "If this is a self-signed certificate, you can disable SSL verification "
                "by setting verify=False or providing a CA bundle path",
            )
            raise
        except requests.exceptions.RequestException as e:
            logger.error("Request failed for %s: %s", url, e, exc_info=True)
            raise

    def get(self, url: str, **kwargs: Any) -> Response:
        """Make a GET request."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        """Make a POST request."""
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Response:
        """Make a PUT request."""
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Response:
        """Make a DELETE request."""
        return self.request("DELETE", url, **kwargs)

    def close(self) -> None:
        """Close the session."""
        self.session.close()


# Global instance for convenient access
_http_client: SecureHTTPClient | None = None


def get_http_client() -> SecureHTTPClient:
    """Get or create the global HTTP client instance.

    Returns:
        SecureHTTPClient instance

    """
    global _http_client
    if _http_client is None:
        _http_client = SecureHTTPClient()
    return _http_client


def secure_request(method: str, url: str, verify: bool | str | None = None, **kwargs: Any) -> Response:
    """Make secure HTTP requests.

    This function uses the global HTTP client with proper SSL configuration.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Target URL
        verify: SSL verification override (True, False, or CA bundle path)
        **kwargs: Additional arguments passed to requests

    Returns:
        Response object

    """
    client: SecureHTTPClient = get_http_client()
    return client.request(method, url, verify=verify, **kwargs)


def secure_get(url: str, **kwargs: Any) -> Response:
    """Make secure GET requests."""
    return secure_request("GET", url, **kwargs)


def secure_post(url: str, **kwargs: Any) -> Response:
    """Make secure POST requests."""
    return secure_request("POST", url, **kwargs)
