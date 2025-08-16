"""Service Health Checker for monitoring service availability and endpoints.

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

import asyncio
import logging
import socket
import time
from typing import Any
from urllib.parse import urlparse

import aiohttp

from intellicrack.core.config_manager import get_config
from intellicrack.core.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class ServiceHealthChecker:
    """Check health status of various services and endpoints."""

    def __init__(self):
        """Initialize the service health checker."""
        self.config = get_config()
        self.health_cache = {}
        self.cache_duration = 300  # 5 minutes
        self.last_check_times = {}

    def get_service_url(self, service_name: str) -> str | None:
        """Get the URL for a service from configuration.

        Args:
            service_name: Name of the service

        Returns:
            Service URL or None if not found
        """
        return self.config.get(f"service_urls.{service_name}")

    def check_port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a port is open on a host.

        Args:
            host: Hostname or IP address
            port: Port number
            timeout: Connection timeout in seconds

        Returns:
            True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            logger.debug(f"Port check failed for {host}:{port}: {e}")
            return False

    async def check_http_endpoint(self, url: str, timeout: float = 5.0) -> dict[str, Any]:
        """Check if an HTTP endpoint is accessible.

        Args:
            url: URL to check
            timeout: Request timeout in seconds

        Returns:
            Dictionary with health check results
        """
        result = {
            "url": url,
            "healthy": False,
            "status_code": None,
            "response_time": None,
            "error": None,
            "timestamp": time.time(),
        }

        try:
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=timeout)
                ) as response:
                    result["status_code"] = response.status
                    result["response_time"] = time.time() - start_time
                    result["healthy"] = 200 <= response.status < 400

        except aiohttp.ClientError as e:
            result["error"] = str(e)
            logger.debug(f"HTTP check failed for {url}: {e}")
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Unexpected error checking {url}: {e}")

        return result

    async def check_websocket_endpoint(self, url: str, timeout: float = 5.0) -> dict[str, Any]:
        """Check if a WebSocket endpoint is accessible.

        Args:
            url: WebSocket URL to check
            timeout: Connection timeout in seconds

        Returns:
            Dictionary with health check results
        """
        result = {
            "url": url,
            "healthy": False,
            "connected": False,
            "response_time": None,
            "error": None,
            "timestamp": time.time(),
        }

        try:
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(url, timeout=timeout) as ws:
                    result["connected"] = True
                    result["response_time"] = time.time() - start_time
                    result["healthy"] = True
                    await ws.close()

        except Exception as e:
            result["error"] = str(e)
            logger.debug(f"WebSocket check failed for {url}: {e}")

        return result

    async def check_service(self, service_name: str) -> dict[str, Any]:
        """Check the health of a specific service.

        Args:
            service_name: Name of the service to check

        Returns:
            Dictionary with service health information
        """
        # Check cache first
        cache_key = service_name
        if cache_key in self.health_cache:
            cached_result = self.health_cache[cache_key]
            if time.time() - cached_result["timestamp"] < self.cache_duration:
                logger.debug(f"Using cached health check for {service_name}")
                return cached_result

        # Get service URL from config
        service_url = self.get_service_url(service_name)
        if not service_url:
            return {
                "service": service_name,
                "healthy": False,
                "error": "Service URL not configured",
                "timestamp": time.time(),
            }

        # Parse URL to determine check type
        parsed = urlparse(service_url)

        result = {
            "service": service_name,
            "url": service_url,
            "healthy": False,
            "timestamp": time.time(),
        }

        # Perform appropriate health check based on URL scheme
        if parsed.scheme in ["http", "https"]:
            check_result = await self.check_http_endpoint(service_url)
            result.update(check_result)
        elif parsed.scheme in ["ws", "wss"]:
            check_result = await self.check_websocket_endpoint(service_url)
            result.update(check_result)
        else:
            # For non-HTTP services, just check if port is open
            if parsed.hostname and parsed.port:
                is_open = self.check_port_open(parsed.hostname, parsed.port)
                result["healthy"] = is_open
                result["port_open"] = is_open
            else:
                result["error"] = f"Cannot parse service URL: {service_url}"

        # Cache the result
        self.health_cache[cache_key] = result

        return result

    async def check_all_services(self) -> dict[str, dict[str, Any]]:
        """Check health of all configured services.

        Returns:
            Dictionary mapping service names to health check results
        """
        service_urls = self.config.get("service_urls", {})
        results = {}

        # Create tasks for parallel checking
        tasks = []
        service_names = []

        for service_name in service_urls:
            tasks.append(self.check_service(service_name))
            service_names.append(service_name)

        # Execute all checks in parallel
        if tasks:
            check_results = await asyncio.gather(*tasks, return_exceptions=True)

            for service_name, result in zip(service_names, check_results, strict=False):
                if isinstance(result, Exception):
                    results[service_name] = {
                        "service": service_name,
                        "healthy": False,
                        "error": str(result),
                        "timestamp": time.time(),
                    }
                else:
                    results[service_name] = result

        # Save results to config
        self.config.set("service_health.last_check", results)
        self.config.set("service_health.last_check_time", time.time())

        return results

    async def check_critical_services(self) -> dict[str, dict[str, Any]]:
        """Check health of critical services only.

        Returns:
            Dictionary mapping service names to health check results
        """
        critical_services = ["ollama_api", "local_llm_server", "c2_server", "proxy_server"]

        results = {}
        for service_name in critical_services:
            if self.get_service_url(service_name):
                results[service_name] = await self.check_service(service_name)

        return results

    def get_healthy_services(self) -> list[str]:
        """Get list of services that passed health checks.

        Returns:
            List of healthy service names
        """
        health_data = self.config.get("service_health.last_check", {})
        return [
            service_name
            for service_name, status in health_data.items()
            if status.get("healthy", False)
        ]

    def get_unhealthy_services(self) -> list[str]:
        """Get list of services that failed health checks.

        Returns:
            List of unhealthy service names
        """
        health_data = self.config.get("service_health.last_check", {})
        return [
            service_name
            for service_name, status in health_data.items()
            if not status.get("healthy", False)
        ]

    async def wait_for_service(
        self, service_name: str, timeout: float = 30.0, check_interval: float = 2.0
    ) -> bool:
        """Wait for a service to become available.

        Args:
            service_name: Name of the service to wait for
            timeout: Maximum time to wait in seconds
            check_interval: Time between checks in seconds

        Returns:
            True if service became available, False if timeout
        """
        start_time = time.time()

        while time.time() - start_time < timeout:
            result = await self.check_service(service_name)
            if result.get("healthy", False):
                logger.info(f"Service {service_name} is now available")
                return True

            await asyncio.sleep(check_interval)

        logger.warning(f"Service {service_name} did not become available within {timeout} seconds")
        return False

    def get_service_endpoint(self, service_name: str) -> str:
        """Get service endpoint from configuration.

        Args:
            service_name: Name of the service

        Returns:
            Service URL from configuration

        Raises:
            ConfigurationError: If service URL is not configured
        """
        url = self.get_service_url(service_name)
        if not url:
            raise ConfigurationError(
                f"Service '{service_name}' URL not configured. "
                f"Please set 'service_urls.{service_name}' in configuration.",
                service_name=service_name,
                config_key=f"service_urls.{service_name}",
            )

        # Validate URL format
        if not url.startswith(("http://", "https://", "ws://", "wss://", "tcp://", "udp://")):
            raise ConfigurationError(
                f"Invalid URL format for service '{service_name}': {url}. "
                f"URL must start with a valid protocol (http://, https://, ws://, wss://, tcp://, udp://)",
                service_name=service_name,
                config_key=f"service_urls.{service_name}",
            )

        return url


# Singleton instance
_health_checker = None


def get_health_checker() -> ServiceHealthChecker:
    """Get the singleton ServiceHealthChecker instance.

    Returns:
        ServiceHealthChecker instance
    """
    global _health_checker
    if _health_checker is None:
        _health_checker = ServiceHealthChecker()
    return _health_checker


async def check_service_health(service_name: str) -> dict[str, Any]:
    """Check health of a specific service.

    Args:
        service_name: Name of the service

    Returns:
        Health check results
    """
    checker = get_health_checker()
    return await checker.check_service(service_name)


async def check_all_services_health() -> dict[str, dict[str, Any]]:
    """Check health of all configured services.

    Returns:
        Dictionary of health check results
    """
    checker = get_health_checker()
    return await checker.check_all_services()


def get_service_url(service_name: str) -> str:
    """Get URL for a service from configuration.

    Args:
        service_name: Name of the service

    Returns:
        Service URL from configuration

    Raises:
        ConfigurationError: If service URL is not configured
    """
    checker = get_health_checker()
    return checker.get_service_endpoint(service_name)
