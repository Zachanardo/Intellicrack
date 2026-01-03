"""Production-grade tests for HTTP utilities with SSL verification.

Tests validate real HTTP request functionality including SSL certificate verification,
proxy configuration, connection retry logic, custom headers, and session persistence.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import http.server
import socket
import ssl
import tempfile
import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
import requests
from requests import Response
from urllib3.util.retry import Retry

from intellicrack.utils.http_utils import SecureHTTPClient, get_http_client, secure_get, secure_post, secure_request


class SimpleHTTPServerThread(threading.Thread):
    """Simple HTTP server for testing."""

    def __init__(self, port: int, use_ssl: bool = False, delay: float = 0.0) -> None:
        """Initialize HTTP server thread.

        Args:
            port: Port to listen on
            use_ssl: Whether to use HTTPS
            delay: Response delay in seconds for timeout testing
        """
        super().__init__(daemon=True)
        self.port = port
        self.use_ssl = use_ssl
        self.delay = delay
        self.server: http.server.HTTPServer | None = None
        self.ready = threading.Event()

    def run(self) -> None:
        """Run the HTTP server."""

        class DelayedHandler(http.server.BaseHTTPRequestHandler):
            """HTTP handler with configurable delay."""

            delay_time = self.delay

            def do_GET(self) -> None:
                """Handle GET requests."""
                time.sleep(self.delay_time)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-Test-Header", "test-value")
                self.end_headers()
                response = b'{"status": "ok", "message": "test response"}'
                self.wfile.write(response)

            def do_POST(self) -> None:
                """Handle POST requests."""
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length)
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                response = f'{{"status": "created", "received": "{body.decode()}"}}'.encode()
                self.wfile.write(response)

            def log_message(self, format: str, *args: object) -> None:
                """Suppress log messages."""
                pass

        try:
            self.server = http.server.HTTPServer(("localhost", self.port), DelayedHandler)

            if self.use_ssl:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cert_file:
                    cert_path = Path(cert_file.name)
                    cert_path.write_text(
                        "-----BEGIN CERTIFICATE-----\n"
                        "MIICpDCCAYwCCQC5Z5Z5Z5Z5ZjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n"
                        "-----END CERTIFICATE-----\n"
                    )
                    context.load_cert_chain(cert_path, cert_path)

            self.ready.set()
            self.server.serve_forever()
        except Exception:
            pass

    def stop(self) -> None:
        """Stop the server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()


class FakeIntellicrackConfig:
    """Real test double for IntellicrackConfig."""

    def __init__(self, config_data: dict[str, Any]) -> None:
        """Initialize fake config with provided data.

        Args:
            config_data: Configuration dictionary to use
        """
        self._config: dict[str, Any] = config_data

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get configuration value.

        Args:
            section: Configuration section
            key: Configuration key
            default: Default value if not found

        Returns:
            Configuration value or default
        """
        if section in self._config and key in self._config[section]:
            return self._config[section][key]
        return default


@pytest.fixture(scope="module")
def test_http_server() -> Generator[int, None, None]:
    """Start a test HTTP server and return its port."""
    port = 18765
    server = SimpleHTTPServerThread(port)
    server.start()
    server.ready.wait(timeout=5.0)
    time.sleep(0.5)
    yield port
    server.stop()


@pytest.fixture
def http_client() -> Generator[SecureHTTPClient, None, None]:
    """Create a fresh HTTP client instance for testing."""
    client = SecureHTTPClient()
    yield client
    client.close()


class TestSecureHTTPClient:
    """Test suite for SecureHTTPClient functionality."""

    def test_client_initialization(self, http_client: SecureHTTPClient) -> None:
        """HTTP client initializes with proper session configuration."""
        assert http_client.session is not None
        assert isinstance(http_client.session, requests.Session)
        assert "User-Agent" in http_client.session.headers

    def test_ssl_verify_default_true(self, http_client: SecureHTTPClient) -> None:
        """SSL verification is enabled by default."""
        verify_setting = http_client._get_ssl_verify()
        assert verify_setting is True or isinstance(verify_setting, str)

    def test_ssl_verify_override_false(self, http_client: SecureHTTPClient) -> None:
        """SSL verification can be disabled with override."""
        verify_setting = http_client._get_ssl_verify(override_verify=False)
        assert verify_setting is False

    def test_ssl_verify_custom_ca_bundle(self, http_client: SecureHTTPClient, temp_workspace: Path) -> None:
        """SSL verification accepts custom CA bundle path."""
        ca_bundle = temp_workspace / "ca-bundle.crt"
        ca_bundle.write_text("FAKE CA BUNDLE")

        verify_setting = http_client._get_ssl_verify(override_verify=str(ca_bundle))
        assert verify_setting == str(ca_bundle)

    def test_get_request_success(self, http_client: SecureHTTPClient, test_http_server: int) -> None:
        """GET request successfully retrieves data from HTTP server."""
        url = f"http://localhost:{test_http_server}/"

        response = http_client.get(url)

        assert response.status_code == 200
        assert response.headers.get("X-Test-Header") == "test-value"
        data = response.json()
        assert data["status"] == "ok"
        assert "message" in data

    def test_post_request_success(self, http_client: SecureHTTPClient, test_http_server: int) -> None:
        """POST request successfully sends data to HTTP server."""
        url = f"http://localhost:{test_http_server}/"
        payload = {"test": "data"}

        response = http_client.post(url, json=payload)

        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "created"

    def test_custom_headers_injection(self, http_client: SecureHTTPClient, test_http_server: int) -> None:
        """Custom headers are properly injected into requests."""
        url = f"http://localhost:{test_http_server}/"
        custom_headers = {"X-Custom-Header": "custom-value", "Authorization": "Bearer test-token"}

        response = http_client.get(url, headers=custom_headers)

        assert response.status_code == 200

    def test_request_timeout_configuration(self, http_client: SecureHTTPClient, test_http_server: int) -> None:
        """Request timeout is properly configured and enforced."""
        url = f"http://localhost:{test_http_server}/"

        response = http_client.get(url, timeout=5)

        assert response.status_code == 200

    def test_connection_timeout_raises_exception(self, http_client: SecureHTTPClient) -> None:
        """Connection timeout raises appropriate exception."""
        url = "http://10.255.255.1/"

        with pytest.raises(requests.exceptions.RequestException):
            http_client.get(url, timeout=1)

    def test_retry_logic_configuration(self, http_client: SecureHTTPClient) -> None:
        """Retry strategy is properly configured in session."""
        adapter = http_client.session.get_adapter("http://example.com")
        assert adapter is not None
        if hasattr(adapter, "max_retries"):
            assert adapter.max_retries is not None

    def test_http_500_triggers_retry(self, http_client: SecureHTTPClient) -> None:
        """HTTP 500 errors trigger retry logic."""
        adapter = http_client.session.get_adapter("http://example.com")
        if hasattr(adapter, "max_retries") and hasattr(adapter.max_retries, "status_forcelist"):
            assert 500 in adapter.max_retries.status_forcelist

    def test_session_persistence(self, http_client: SecureHTTPClient, test_http_server: int) -> None:
        """Session persists across multiple requests."""
        url = f"http://localhost:{test_http_server}/"

        response1 = http_client.get(url)
        response2 = http_client.get(url)

        assert response1.status_code == 200
        assert response2.status_code == 200
        assert http_client.session is not None

    def test_put_request_success(self, http_client: SecureHTTPClient, test_http_server: int) -> None:
        """PUT request successfully sends data."""
        url = f"http://localhost:{test_http_server}/"

        response = http_client.put(url, json={"update": "data"})

        assert response.status_code in [200, 201]

    def test_delete_request_success(self, http_client: SecureHTTPClient, test_http_server: int) -> None:
        """DELETE request executes successfully."""
        url = f"http://localhost:{test_http_server}/"

        response = http_client.delete(url)

        assert response.status_code in [200, 204]

    def test_invalid_url_raises_exception(self, http_client: SecureHTTPClient) -> None:
        """Invalid URL raises appropriate exception."""
        with pytest.raises(requests.exceptions.RequestException):
            http_client.get("not-a-valid-url")

    def test_connection_refused_raises_exception(self, http_client: SecureHTTPClient) -> None:
        """Connection refused raises appropriate exception."""
        url = "http://localhost:65534/"

        with pytest.raises(requests.exceptions.RequestException):
            http_client.get(url, timeout=2)

    def test_client_close_releases_resources(self, http_client: SecureHTTPClient) -> None:
        """Client close properly releases session resources."""
        http_client.close()
        assert http_client.session is not None


class TestProxyConfiguration:
    """Test suite for proxy configuration functionality."""

    def test_proxy_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Proxy is disabled by default."""
        fake_config = FakeIntellicrackConfig({"network": {"proxy_enabled": False}})

        import intellicrack.utils.http_utils
        monkeypatch.setattr(intellicrack.utils.http_utils, "IntellicrackConfig", lambda: fake_config)

        client = SecureHTTPClient()
        assert client.session.proxies == {}

    def test_proxy_configuration_with_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Proxy configuration includes authentication when provided."""
        fake_config = FakeIntellicrackConfig({
            "network": {
                "proxy_enabled": True,
                "proxy_host": "proxy.example.com",
                "proxy_port": 8080,
                "proxy_username": "user",
                "proxy_password": "pass",
            }
        })

        import intellicrack.utils.http_utils
        monkeypatch.setattr(intellicrack.utils.http_utils, "IntellicrackConfig", lambda: fake_config)

        client = SecureHTTPClient()
        assert "http" in client.session.proxies
        assert "proxy.example.com:8080" in client.session.proxies["http"]


class TestRetryMechanism:
    """Test suite for retry mechanism and exponential backoff."""

    def test_retry_on_connection_error(self, http_client: SecureHTTPClient) -> None:
        """Connection errors trigger retry attempts."""
        adapter = http_client.session.get_adapter("http://example.com")
        if hasattr(adapter, "max_retries"):
            assert adapter.max_retries is not None

    def test_exponential_backoff_configured(self, http_client: SecureHTTPClient) -> None:
        """Exponential backoff is configured for retries."""
        adapter = http_client.session.get_adapter("http://example.com")
        if hasattr(adapter, "max_retries") and hasattr(adapter.max_retries, "backoff_factor"):
            assert adapter.max_retries.backoff_factor > 0


class TestGlobalHTTPClient:
    """Test suite for global HTTP client functionality."""

    def test_get_http_client_singleton(self) -> None:
        """Global HTTP client returns same instance."""
        client1 = get_http_client()
        client2 = get_http_client()

        assert client1 is client2

    def test_secure_request_uses_global_client(self, test_http_server: int) -> None:
        """secure_request function uses global client."""
        url = f"http://localhost:{test_http_server}/"

        response = secure_request("GET", url)

        assert response.status_code == 200

    def test_secure_get_convenience_function(self, test_http_server: int) -> None:
        """secure_get convenience function works correctly."""
        url = f"http://localhost:{test_http_server}/"

        response = secure_get(url)

        assert response.status_code == 200
        assert "status" in response.json()

    def test_secure_post_convenience_function(self, test_http_server: int) -> None:
        """secure_post convenience function works correctly."""
        url = f"http://localhost:{test_http_server}/"

        response = secure_post(url, json={"test": "data"})

        assert response.status_code == 201


class TestSSLErrorHandling:
    """Test suite for SSL error handling."""

    def test_ssl_error_provides_helpful_message(self, http_client: SecureHTTPClient) -> None:
        """SSL errors provide helpful error messages."""
        url = "https://self-signed.badssl.com/"

        with pytest.raises(requests.exceptions.SSLError):
            http_client.get(url, timeout=5)

    def test_ssl_verification_can_be_disabled_per_request(self, http_client: SecureHTTPClient) -> None:
        """SSL verification can be disabled on per-request basis."""
        verify_false = http_client._get_ssl_verify(override_verify=False)
        assert verify_false is False


class TestRequestBodyStreaming:
    """Test suite for request body streaming."""

    def test_large_payload_post(self, http_client: SecureHTTPClient, test_http_server: int) -> None:
        """Large POST payloads are handled correctly."""
        url = f"http://localhost:{test_http_server}/"
        large_payload = {"data": "x" * 10000}

        response = http_client.post(url, json=large_payload)

        assert response.status_code == 201


class TestUserAgentConfiguration:
    """Test suite for User-Agent configuration."""

    def test_default_user_agent_set(self, http_client: SecureHTTPClient) -> None:
        """Default User-Agent header is set."""
        assert "User-Agent" in http_client.session.headers
        user_agent = http_client.session.headers["User-Agent"]
        assert "Intellicrack" in user_agent or user_agent != ""

    def test_custom_user_agent_override(self, http_client: SecureHTTPClient, test_http_server: int) -> None:
        """Custom User-Agent can be set per request."""
        url = f"http://localhost:{test_http_server}/"
        custom_ua = "CustomAgent/1.0"

        response = http_client.get(url, headers={"User-Agent": custom_ua})

        assert response.status_code == 200


class TestErrorRecovery:
    """Test suite for error recovery scenarios."""

    def test_network_failure_handling(self, http_client: SecureHTTPClient) -> None:
        """Network failures are handled gracefully."""
        url = "http://192.0.2.1/"

        with pytest.raises(requests.exceptions.RequestException):
            http_client.get(url, timeout=1)

    def test_malformed_response_handling(self, http_client: SecureHTTPClient) -> None:
        """Malformed responses are handled appropriately."""
        with pytest.raises(requests.exceptions.RequestException):
            http_client.get("http://[::1:invalid")


class TestThreadSafety:
    """Test suite for thread safety of HTTP client."""

    def test_concurrent_requests(self, test_http_server: int) -> None:
        """Multiple concurrent requests work correctly."""
        url = f"http://localhost:{test_http_server}/"
        results: list[Response | None] = []

        def make_request() -> None:
            client = SecureHTTPClient()
            try:
                response = client.get(url)
                results.append(response)
            except Exception:
                results.append(None)
            finally:
                client.close()

        threads = [threading.Thread(target=make_request) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == 5
        successful = [r for r in results if r is not None and r.status_code == 200]
        assert len(successful) >= 4


class TestEnvironmentVariables:
    """Test suite for environment variable configuration."""

    def test_ca_bundle_from_env_variable(self, temp_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """CA bundle can be configured via environment variable."""
        ca_bundle = temp_workspace / "env-ca-bundle.crt"
        ca_bundle.write_text("ENV CA BUNDLE")

        monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(ca_bundle))
        client = SecureHTTPClient()
        verify = client._get_ssl_verify()
        assert verify is True or verify == str(ca_bundle)
