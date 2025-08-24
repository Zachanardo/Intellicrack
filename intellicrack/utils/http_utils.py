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
from pathlib import Path
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

from intellicrack.core.config_manager import ConfigManager
from intellicrack.logger import logger


class SecureHTTPClient:
    """HTTP client with configurable SSL verification for security research."""

    def __init__(self):
        """Initialize HTTP client with configuration from ConfigManager."""
        self.config_manager = ConfigManager()
        self.session = requests.Session()
        self._setup_session()

    def _setup_session(self):
        """Configure session with retry logic and SSL settings."""
        config = self.config_manager.get_config()
        network_config = config.get("network", {})

        # Set up retry strategy
        retry_strategy = Retry(
            total=network_config.get("max_retries", 3),
            backoff_factor=network_config.get("retry_delay", 1),
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set default headers
        self.session.headers.update({
            "User-Agent": network_config.get("user_agent", "Intellicrack/3.0")
        })

        # Configure proxy if enabled
        if network_config.get("proxy_enabled", False):
            proxy_host = network_config.get("proxy_host", "")
            proxy_port = network_config.get("proxy_port", 8080)
            proxy_username = network_config.get("proxy_username", "")
            proxy_password = network_config.get("proxy_password", "")

            if proxy_host:
                proxy_url = f"http://{proxy_host}:{proxy_port}"
                if proxy_username and proxy_password:
                    proxy_url = f"http://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}"

                self.session.proxies = {
                    "http": proxy_url,
                    "https": proxy_url
                }

    def _get_ssl_verify(self, override_verify: Optional[bool] = None) -> bool | str:
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
                    "This should only be used for testing with self-signed certificates."
                )
                # Suppress only the specific InsecureRequestWarning
                warnings.filterwarnings("ignore", category=InsecureRequestWarning)
            return override_verify

        # Get from configuration
        config = self.config_manager.get_config()
        network_config = config.get("network", {})
        ssl_verify = network_config.get("ssl_verify", True)

        # Check for custom CA bundle path
        ca_bundle_path = network_config.get("ca_bundle_path", "")
        if ca_bundle_path and Path(ca_bundle_path).exists():
            return ca_bundle_path

        # Check environment variable for CA bundle
        env_ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE", "")
        if env_ca_bundle and Path(env_ca_bundle).exists():
            return env_ca_bundle

        if not ssl_verify:
            logger.warning(
                "SSL certificate verification is disabled in configuration. "
                "Consider enabling it for production use."
            )
            warnings.filterwarnings("ignore", category=InsecureRequestWarning)

        return ssl_verify

    def request(
        self,
        method: str,
        url: str,
        verify: Optional[bool | str] = None,
        **kwargs
    ) -> requests.Response:
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
            config = self.config_manager.get_config()
            kwargs["timeout"] = config.get("network", {}).get("timeout", 30)

        # Set SSL verification
        kwargs["verify"] = self._get_ssl_verify(verify)

        # Log the request (without sensitive data)
        logger.debug(f"Making {method} request to {url}")

        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL error for {url}: {e}")
            logger.info(
                "If this is a self-signed certificate, you can disable SSL verification "
                "by setting verify=False or providing a CA bundle path"
            )
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            raise

    def get(self, url: str, **kwargs) -> requests.Response:
        """Make a GET request."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """Make a POST request."""
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> requests.Response:
        """Make a PUT request."""
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> requests.Response:
        """Make a DELETE request."""
        return self.request("DELETE", url, **kwargs)

    def close(self):
        """Close the session."""
        self.session.close()


# Global instance for convenient access
_http_client: Optional[SecureHTTPClient] = None


def get_http_client() -> SecureHTTPClient:
    """Get or create the global HTTP client instance.

    Returns:
        SecureHTTPClient instance

    """
    global _http_client
    if _http_client is None:
        _http_client = SecureHTTPClient()
    return _http_client


def secure_request(
    method: str,
    url: str,
    verify: Optional[bool | str] = None,
    **kwargs
) -> requests.Response:
    """Convenience function for making secure HTTP requests.

    This function uses the global HTTP client with proper SSL configuration.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Target URL
        verify: SSL verification override (True, False, or CA bundle path)
        **kwargs: Additional arguments passed to requests

    Returns:
        Response object

    """
    client = get_http_client()
    return client.request(method, url, verify=verify, **kwargs)


def secure_get(url: str, **kwargs) -> requests.Response:
    """Convenience function for GET requests."""
    return secure_request("GET", url, **kwargs)


def secure_post(url: str, **kwargs) -> requests.Response:
    """Convenience function for POST requests."""
    return secure_request("POST", url, **kwargs)
