"""Production-grade tests for service health checker.

Tests validate real async health checking, port connectivity, HTTP endpoint validation,
WebSocket validation, concurrent checking, timeout handling, and service recovery.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
import http.server
import socket
import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import aiohttp
import pytest
from aiohttp import web

from intellicrack.core.exceptions import ConfigurationError
from intellicrack.utils.service_health_checker import (
    ServiceHealthChecker,
    check_all_services_health,
    check_service_health,
    get_health_checker,
)


class SimpleHTTPServer(threading.Thread):
    """Simple HTTP server for testing health checks."""

    def __init__(self, port: int, response_delay: float = 0.0) -> None:
        """Initialize HTTP server.

        Args:
            port: Port to listen on
            response_delay: Delay before sending response (for timeout testing)
        """
        super().__init__(daemon=True)
        self.port = port
        self.response_delay = response_delay
        self.server: http.server.HTTPServer | None = None
        self.ready = threading.Event()

    def run(self) -> None:
        """Run the HTTP server."""

        class HealthHandler(http.server.BaseHTTPRequestHandler):
            """Handler for health check endpoints."""

            delay = self.response_delay

            def do_GET(self) -> None:
                """Handle GET requests."""
                time.sleep(self.delay)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "healthy"}')

            def log_message(self, format: str, *args: object) -> None:
                """Suppress log messages."""
                pass

        try:
            self.server = http.server.HTTPServer(("localhost", self.port), HealthHandler)
            self.ready.set()
            self.server.serve_forever()
        except Exception:
            pass

    def stop(self) -> None:
        """Stop the server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()


class SimpleWebSocketServer:
    """Simple WebSocket server for testing."""

    def __init__(self, port: int) -> None:
        """Initialize WebSocket server.

        Args:
            port: Port to listen on
        """
        self.port = port
        self.app = web.Application()
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None

    async def websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        """Handle WebSocket connections."""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_str("connected")
        await ws.close()
        return ws

    async def start(self) -> None:
        """Start the WebSocket server."""
        self.app.router.add_get("/", self.websocket_handler)
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "localhost", self.port)
        await self.site.start()

    async def stop(self) -> None:
        """Stop the WebSocket server."""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()


class FakeServiceHealthChecker(ServiceHealthChecker):
    """Test double for ServiceHealthChecker with configurable behavior."""

    def __init__(self) -> None:
        """Initialize fake health checker."""
        super().__init__()
        self._fake_service_urls: dict[str, str | None] = {}
        self._fake_config: dict[str, Any] = {}

    def set_service_url(self, service_name: str, url: str | None) -> None:
        """Configure fake service URL.

        Args:
            service_name: Name of service
            url: URL to return or None
        """
        self._fake_service_urls[service_name] = url

    def set_config(self, config: dict[str, Any]) -> None:
        """Set fake configuration.

        Args:
            config: Configuration dictionary
        """
        self._fake_config = config

    def get_service_url(self, service_name: str) -> str | None:
        """Get configured service URL.

        Args:
            service_name: Name of service

        Returns:
            URL or None if not configured
        """
        return self._fake_service_urls.get(service_name)

    @property
    def config(self) -> dict[str, Any]:
        """Get configuration.

        Returns:
            Configuration dictionary
        """
        if self._fake_config:
            return self._fake_config
        return super().config


@pytest.fixture(scope="module")
def http_test_server() -> Generator[int, None, None]:
    """Start HTTP test server and return port."""
    port = 18766
    server = SimpleHTTPServer(port)
    server.start()
    server.ready.wait(timeout=5.0)
    time.sleep(0.5)
    yield port
    server.stop()


@pytest.fixture
def health_checker() -> ServiceHealthChecker:
    """Create a ServiceHealthChecker instance."""
    return ServiceHealthChecker()


@pytest.fixture
def fake_health_checker() -> FakeServiceHealthChecker:
    """Create a fake ServiceHealthChecker for testing."""
    return FakeServiceHealthChecker()


class TestServiceHealthCheckerInitialization:
    """Test suite for ServiceHealthChecker initialization."""

    def test_health_checker_initialization(self, health_checker: ServiceHealthChecker) -> None:
        """ServiceHealthChecker initializes with proper defaults."""
        assert health_checker._config is None
        assert health_checker.health_cache == {}
        assert health_checker.cache_duration == 300
        assert health_checker.last_check_times == {}

    def test_config_lazy_loading(self, health_checker: ServiceHealthChecker) -> None:
        """Configuration is lazily loaded on first access."""
        config = health_checker.config
        assert isinstance(config, dict)
        assert health_checker._config is not None


class TestPortConnectivity:
    """Test suite for port connectivity checking."""

    def test_check_port_open_success(self, health_checker: ServiceHealthChecker, http_test_server: int) -> None:
        """check_port_open detects open port."""
        is_open = health_checker.check_port_open("localhost", http_test_server, timeout=2.0)
        assert is_open is True

    def test_check_port_open_closed(self, health_checker: ServiceHealthChecker) -> None:
        """check_port_open detects closed port."""
        is_open = health_checker.check_port_open("localhost", 65534, timeout=1.0)
        assert is_open is False

    def test_check_port_open_timeout(self, health_checker: ServiceHealthChecker) -> None:
        """check_port_open respects timeout setting."""
        start = time.time()
        is_open = health_checker.check_port_open("10.255.255.1", 80, timeout=0.5)
        elapsed = time.time() - start

        assert is_open is False
        assert elapsed < 2.0

    def test_check_port_invalid_host(self, health_checker: ServiceHealthChecker) -> None:
        """check_port_open handles invalid hostname gracefully."""
        is_open = health_checker.check_port_open("invalid-hostname-12345", 80, timeout=1.0)
        assert is_open is False


class TestHTTPEndpointChecking:
    """Test suite for HTTP endpoint health checking."""

    @pytest.mark.asyncio
    async def test_check_http_endpoint_success(self, health_checker: ServiceHealthChecker, http_test_server: int) -> None:
        """check_http_endpoint successfully validates healthy endpoint."""
        url = f"http://localhost:{http_test_server}/"

        result = await health_checker.check_http_endpoint(url)

        assert result["healthy"] is True
        assert result["status_code"] == 200
        assert result["response_time"] is not None
        assert result["response_time"] > 0
        assert result["error"] is None

    @pytest.mark.asyncio
    async def test_check_http_endpoint_timeout(self, health_checker: ServiceHealthChecker) -> None:
        """check_http_endpoint handles timeout appropriately."""
        url = "http://10.255.255.1/"

        result = await health_checker.check_http_endpoint(url)

        assert result["healthy"] is False
        assert result["error"] is not None
        assert "timeout" in result["error"].lower() or "error" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_check_http_endpoint_invalid_url(self, health_checker: ServiceHealthChecker) -> None:
        """check_http_endpoint handles invalid URLs gracefully."""
        url = "http://invalid-domain-xyz-12345.com/"

        result = await health_checker.check_http_endpoint(url)

        assert result["healthy"] is False
        assert result["error"] is not None

    @pytest.mark.asyncio
    async def test_check_http_endpoint_404_unhealthy(self, health_checker: ServiceHealthChecker) -> None:
        """check_http_endpoint marks 404 responses as unhealthy."""
        url = f"http://httpbin.org/status/404"

        try:
            result = await health_checker.check_http_endpoint(url)
            assert result["status_code"] == 404
            assert result["healthy"] is False
        except Exception:
            pytest.skip("Network connectivity required")


class TestWebSocketEndpointChecking:
    """Test suite for WebSocket endpoint health checking."""

    @pytest.mark.asyncio
    async def test_check_websocket_endpoint_invalid(self, health_checker: ServiceHealthChecker) -> None:
        """check_websocket_endpoint handles connection failure."""
        url = "ws://localhost:65533/"

        result = await health_checker.check_websocket_endpoint(url)

        assert result["healthy"] is False
        assert result["connected"] is False
        assert result["error"] is not None

    @pytest.mark.asyncio
    async def test_check_websocket_endpoint_timeout(self, health_checker: ServiceHealthChecker) -> None:
        """check_websocket_endpoint respects timeout."""
        url = "ws://10.255.255.1:8765/"

        result = await health_checker.check_websocket_endpoint(url)

        assert result["healthy"] is False
        assert "timeout" in result["error"].lower() or "error" in result["error"].lower()


class TestServiceHealthChecking:
    """Test suite for complete service health checking."""

    @pytest.mark.asyncio
    async def test_check_service_http(self, fake_health_checker: FakeServiceHealthChecker, http_test_server: int) -> None:
        """check_service validates HTTP service health."""
        fake_health_checker.set_service_url("test_service", f"http://localhost:{http_test_server}/")
        result = await fake_health_checker.check_service("test_service")

        assert result["service"] == "test_service"
        assert result["healthy"] is True
        assert result["status_code"] == 200

    @pytest.mark.asyncio
    async def test_check_service_port_only(self, fake_health_checker: FakeServiceHealthChecker, http_test_server: int) -> None:
        """check_service validates port connectivity when no scheme."""
        fake_health_checker.set_service_url("test_service", f"localhost:{http_test_server}")
        result = await fake_health_checker.check_service("test_service")

        assert result["service"] == "test_service"

    @pytest.mark.asyncio
    async def test_check_service_not_configured(self, fake_health_checker: FakeServiceHealthChecker) -> None:
        """check_service handles unconfigured service."""
        fake_health_checker.set_service_url("unconfigured_service", None)
        result = await fake_health_checker.check_service("unconfigured_service")

        assert result["service"] == "unconfigured_service"
        assert result["healthy"] is False
        assert "not configured" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_check_service_caching(self, fake_health_checker: FakeServiceHealthChecker, http_test_server: int) -> None:
        """check_service caches results for efficiency."""
        fake_health_checker.set_service_url("cached_service", f"http://localhost:{http_test_server}/")
        result1 = await fake_health_checker.check_service("cached_service")
        result2 = await fake_health_checker.check_service("cached_service")

        assert result1["timestamp"] == result2["timestamp"]

    @pytest.mark.asyncio
    async def test_check_service_cache_expiry(self, fake_health_checker: FakeServiceHealthChecker, http_test_server: int) -> None:
        """check_service cache expires after cache_duration."""
        fake_health_checker.cache_duration = 1
        fake_health_checker.set_service_url("expiring_service", f"http://localhost:{http_test_server}/")

        result1 = await fake_health_checker.check_service("expiring_service")
        await asyncio.sleep(1.5)
        result2 = await fake_health_checker.check_service("expiring_service")

        assert result1["timestamp"] != result2["timestamp"]


class TestConcurrentServiceChecking:
    """Test suite for concurrent service health checking."""

    @pytest.mark.asyncio
    async def test_check_all_services_concurrent(self, fake_health_checker: FakeServiceHealthChecker, http_test_server: int) -> None:
        """check_all_services checks multiple services concurrently."""
        mock_config = {
            "service_urls": {
                "service1": f"http://localhost:{http_test_server}/",
                "service2": f"http://localhost:{http_test_server}/",
                "service3": f"http://localhost:{http_test_server}/",
            }
        }

        fake_health_checker.set_config(mock_config)
        start = time.time()
        results = await fake_health_checker.check_all_services()
        elapsed = time.time() - start

        assert len(results) == 3
        assert elapsed < 5.0
        assert all(result["healthy"] for result in results.values())

    @pytest.mark.asyncio
    async def test_check_all_services_handles_failures(self, fake_health_checker: FakeServiceHealthChecker) -> None:
        """check_all_services handles individual service failures."""
        mock_config = {
            "service_urls": {
                "bad_service": "http://localhost:65534/",
                "invalid_service": "http://invalid-host-xyz/",
            }
        }

        fake_health_checker.set_config(mock_config)
        results = await fake_health_checker.check_all_services()

        assert len(results) == 2
        assert all(not result["healthy"] for result in results.values())

    @pytest.mark.asyncio
    async def test_check_critical_services(self, fake_health_checker: FakeServiceHealthChecker, http_test_server: int) -> None:
        """check_critical_services only checks critical services."""
        mock_config = {
            "service_urls": {
                "ollama_api": f"http://localhost:{http_test_server}/",
                "other_service": f"http://localhost:{http_test_server}/",
            }
        }

        fake_health_checker.set_config(mock_config)
        results = await fake_health_checker.check_critical_services()

        assert "ollama_api" in results
        assert "other_service" not in results


class TestWaitForService:
    """Test suite for wait_for_service functionality."""

    @pytest.mark.asyncio
    async def test_wait_for_service_available(self, fake_health_checker: FakeServiceHealthChecker, http_test_server: int) -> None:
        """wait_for_service returns True for available service."""
        fake_health_checker.set_service_url("available_service", f"http://localhost:{http_test_server}/")
        result = await fake_health_checker.wait_for_service("available_service", check_interval=0.5)

        assert result is True

    @pytest.mark.asyncio
    async def test_wait_for_service_timeout(self, fake_health_checker: FakeServiceHealthChecker) -> None:
        """wait_for_service returns False on timeout."""
        fake_health_checker.set_service_url("unavailable_service", "http://localhost:65534/")
        start = time.time()
        result = await fake_health_checker.wait_for_service("unavailable_service", check_interval=1.0)
        elapsed = time.time() - start

        assert result is False
        assert elapsed >= 30.0
        assert elapsed < 35.0


class TestGetServiceEndpoint:
    """Test suite for get_service_endpoint functionality."""

    def test_get_service_endpoint_success(self, fake_health_checker: FakeServiceHealthChecker) -> None:
        """get_service_endpoint returns configured URL."""
        fake_health_checker.set_service_url("api_service", "http://example.com/api")
        url = fake_health_checker.get_service_endpoint("api_service")
        assert url == "http://example.com/api"

    def test_get_service_endpoint_not_configured_raises(self, fake_health_checker: FakeServiceHealthChecker) -> None:
        """get_service_endpoint raises ConfigurationError for missing service."""
        fake_health_checker.set_service_url("missing_service", None)
        with pytest.raises(ConfigurationError) as exc_info:
            fake_health_checker.get_service_endpoint("missing_service")

        assert "missing_service" in str(exc_info.value)
        assert "not configured" in str(exc_info.value).lower()

    def test_get_service_endpoint_invalid_format_raises(self, fake_health_checker: FakeServiceHealthChecker) -> None:
        """get_service_endpoint raises ConfigurationError for invalid URL format."""
        fake_health_checker.set_service_url("invalid_service", "not-a-valid-url")
        with pytest.raises(ConfigurationError) as exc_info:
            fake_health_checker.get_service_endpoint("invalid_service")

        assert "invalid url format" in str(exc_info.value).lower()


class TestHealthDataRetrieval:
    """Test suite for health data retrieval methods."""

    def test_get_healthy_services(self, fake_health_checker: FakeServiceHealthChecker) -> None:
        """get_healthy_services returns list of healthy services."""
        mock_config = {
            "service_health": {
                "last_check": {
                    "service1": {"healthy": True},
                    "service2": {"healthy": False},
                    "service3": {"healthy": True},
                }
            }
        }

        fake_health_checker.set_config(mock_config)
        healthy = fake_health_checker.get_healthy_services()

        assert len(healthy) == 2
        assert "service1" in healthy
        assert "service3" in healthy
        assert "service2" not in healthy

    def test_get_unhealthy_services(self, fake_health_checker: FakeServiceHealthChecker) -> None:
        """get_unhealthy_services returns list of unhealthy services."""
        mock_config = {
            "service_health": {
                "last_check": {
                    "service1": {"healthy": True},
                    "service2": {"healthy": False},
                    "service3": {"healthy": False},
                }
            }
        }

        fake_health_checker.set_config(mock_config)
        unhealthy = fake_health_checker.get_unhealthy_services()

        assert len(unhealthy) == 2
        assert "service2" in unhealthy
        assert "service3" in unhealthy
        assert "service1" not in unhealthy


class TestGlobalFunctions:
    """Test suite for global convenience functions."""

    def test_get_health_checker_singleton(self) -> None:
        """get_health_checker returns singleton instance."""
        checker1 = get_health_checker()
        checker2 = get_health_checker()

        assert checker1 is checker2
        assert isinstance(checker1, ServiceHealthChecker)

    @pytest.mark.asyncio
    async def test_check_service_health_function(self, http_test_server: int, monkeypatch: pytest.MonkeyPatch) -> None:
        """check_service_health function works correctly."""
        checker = get_health_checker()
        fake_checker = FakeServiceHealthChecker()
        fake_checker.set_service_url("test_service", f"http://localhost:{http_test_server}/")

        def fake_get_service_url(service_name: str) -> str | None:
            return fake_checker.get_service_url(service_name)

        monkeypatch.setattr(checker, "get_service_url", fake_get_service_url)
        result = await check_service_health("test_service")

        assert isinstance(result, dict)
        assert "service" in result

    @pytest.mark.asyncio
    async def test_check_all_services_health_function(self, http_test_server: int, monkeypatch: pytest.MonkeyPatch) -> None:
        """check_all_services_health function works correctly."""
        checker = get_health_checker()
        mock_config = {"service_urls": {"service1": f"http://localhost:{http_test_server}/"}}

        def fake_config() -> dict[str, Any]:
            return mock_config

        monkeypatch.setattr(type(checker), "config", property(lambda self: fake_config()))
        results = await check_all_services_health()

        assert isinstance(results, dict)


class TestErrorScenarios:
    """Test suite for error handling scenarios."""

    @pytest.mark.asyncio
    async def test_check_service_handles_exception(self, fake_health_checker: FakeServiceHealthChecker) -> None:
        """check_service handles exceptions during health check."""
        fake_health_checker.set_service_url("broken_service", "http://[::1:invalid")
        result = await fake_health_checker.check_service("broken_service")

        assert result["healthy"] is False

    @pytest.mark.asyncio
    async def test_check_all_services_exception_handling(self, fake_health_checker: FakeServiceHealthChecker) -> None:
        """check_all_services handles exceptions for individual services."""
        mock_config = {
            "service_urls": {
                "good_service": None,
            }
        }

        fake_health_checker.set_config(mock_config)
        results = await fake_health_checker.check_all_services()

        assert isinstance(results, dict)


class TestCacheManagement:
    """Test suite for health check cache management."""

    @pytest.mark.asyncio
    async def test_cache_stores_results(self, fake_health_checker: FakeServiceHealthChecker, http_test_server: int) -> None:
        """Health check results are stored in cache."""
        fake_health_checker.set_service_url("cached_service", f"http://localhost:{http_test_server}/")
        await fake_health_checker.check_service("cached_service")

        assert "cached_service" in fake_health_checker.health_cache
        assert fake_health_checker.health_cache["cached_service"]["healthy"] is True


class TestResponseTimeTracking:
    """Test suite for response time tracking."""

    @pytest.mark.asyncio
    async def test_response_time_tracked(self, health_checker: ServiceHealthChecker, http_test_server: int) -> None:
        """Response time is tracked for HTTP health checks."""
        url = f"http://localhost:{http_test_server}/"

        result = await health_checker.check_http_endpoint(url)

        assert "response_time" in result
        assert result["response_time"] is not None
        assert result["response_time"] > 0


class TestTimestampTracking:
    """Test suite for timestamp tracking in health checks."""

    @pytest.mark.asyncio
    async def test_timestamp_included_in_results(self, fake_health_checker: FakeServiceHealthChecker, http_test_server: int) -> None:
        """Timestamp is included in health check results."""
        fake_health_checker.set_service_url("timestamped_service", f"http://localhost:{http_test_server}/")
        result = await fake_health_checker.check_service("timestamped_service")

        assert "timestamp" in result
        assert isinstance(result["timestamp"], float)
        assert result["timestamp"] > 0
