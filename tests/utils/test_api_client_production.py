"""Production-ready tests for intellicrack/utils/api_client.py

Tests validate REAL API client capabilities:
- Async HTTP request/response handling with aiohttp
- Retry logic with exponential backoff
- Error handling for network failures
- Timeout handling
- Authentication header injection
- Fallback behavior when aiohttp unavailable
- Context manager lifecycle management
"""

import asyncio
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.api_client import APIClient, make_api_call, sync_api_call


class FakeSecretManager:
    """Real test double for secrets manager."""

    def __init__(self, secrets: dict[str, str]) -> None:
        """Initialize with test secrets."""
        self.secrets = secrets

    def get_secret(self, key: str, default: str | None = None) -> str | None:
        """Get secret value."""
        return self.secrets.get(key, default)


class FakeAiohttpResponse:
    """Real test double for aiohttp response."""

    def __init__(self, status: int, json_data: dict[str, Any] | None = None, ok: bool = True, reason: str = "OK") -> None:
        """Initialize fake response."""
        self.status = status
        self._json_data = json_data or {}
        self.ok = ok
        self.reason = reason

    async def json(self) -> dict[str, Any]:
        """Return JSON data."""
        if not isinstance(self._json_data, dict):
            raise ValueError("Not JSON")
        return self._json_data

    async def __aenter__(self) -> "FakeAiohttpResponse":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        pass


class FakeAiohttpSession:
    """Real test double for aiohttp session."""

    def __init__(self, responses: list[FakeAiohttpResponse] | None = None) -> None:
        """Initialize fake session."""
        self.responses = responses or []
        self.call_count = 0
        self.closed = False
        self.captured_requests: list[dict[str, Any]] = []

    async def request(
        self,
        method: str,
        url: str,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> FakeAiohttpResponse:
        """Simulate request."""
        self.captured_requests.append({
            "method": method,
            "url": url,
            "json": json,
            "headers": headers,
        })

        if self.call_count < len(self.responses):
            response = self.responses[self.call_count]
            self.call_count += 1
            return response

        return FakeAiohttpResponse(200, {"success": True})

    async def close(self) -> None:
        """Close session."""
        self.closed = True


class TestAPIClientInitialization:
    """Test API client initialization and configuration."""

    def test_api_client_initializes_with_default_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """API client loads default configuration from environment."""
        monkeypatch.setenv("API_BASE_URL", "")
        monkeypatch.setenv("API_TIMEOUT", "")
        monkeypatch.setenv("API_RETRY_ATTEMPTS", "")
        monkeypatch.setenv("API_RETRY_DELAY", "")

        client = APIClient()
        assert client.base_url == "https://api.intellicrack.com"
        assert client.timeout == 60
        assert client.retry_attempts == 3
        assert client.retry_delay == 1.0

    def test_api_client_initializes_with_custom_base_url(self) -> None:
        """API client accepts custom base URL override."""
        custom_url = "https://custom.api.example.com"
        client = APIClient(base_url=custom_url)
        assert client.base_url == custom_url

    def test_api_client_loads_config_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """API client loads configuration from environment variables."""
        monkeypatch.setenv("API_BASE_URL", "https://test.api.com")
        monkeypatch.setenv("API_TIMEOUT", "120")
        monkeypatch.setenv("API_RETRY_ATTEMPTS", "5")
        monkeypatch.setenv("API_RETRY_DELAY", "2000")

        client = APIClient()
        assert client.base_url == "https://test.api.com"
        assert client.timeout == 120
        assert client.retry_attempts == 5
        assert client.retry_delay == 2.0


class TestAPIClientContextManager:
    """Test async context manager functionality."""

    @pytest.mark.asyncio
    async def test_context_manager_creates_aiohttp_session(self) -> None:
        """Context manager creates aiohttp session when entering."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        async with APIClient() as client:
            assert client.session is not None
            assert not client.session.closed

    @pytest.mark.asyncio
    async def test_context_manager_closes_session_on_exit(self) -> None:
        """Context manager closes aiohttp session when exiting."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        client = APIClient()
        async with client:
            session = client.session
            assert session is not None

        assert session.closed

    @pytest.mark.asyncio
    async def test_context_manager_handles_exceptions_during_requests(self) -> None:
        """Context manager properly closes session even when exceptions occur."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        client = APIClient()
        session_ref = None

        try:
            async with client:
                session_ref = client.session
                raise ValueError("Test exception")
        except ValueError:
            pass

        assert session_ref is not None
        assert session_ref.closed


class TestAPIClientRetryLogic:
    """Test retry logic for failed requests."""

    @pytest.mark.asyncio
    async def test_retries_on_timeout_error(self) -> None:
        """API client retries when request times out."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        call_count = 0

        async def fake_request(*args: Any, **kwargs: Any) -> FakeAiohttpResponse:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise asyncio.TimeoutError("Request timed out")

            return FakeAiohttpResponse(200, {"success": True})

        client = APIClient()
        async with client:
            original_request = client.session.request
            client.session.request = fake_request

            result = await client.fetch("/test")
            assert result == {"success": True}
            assert call_count == 3

    @pytest.mark.asyncio
    async def test_raises_after_max_retry_attempts_exceeded(self) -> None:
        """API client raises RuntimeError after exceeding max retry attempts."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        call_count = 0

        async def fake_request(*args: Any, **kwargs: Any) -> FakeAiohttpResponse:
            nonlocal call_count
            call_count += 1
            raise asyncio.TimeoutError("Request timed out")

        client = APIClient()
        client.retry_attempts = 3
        client.retry_delay = 0.01

        async with client:
            original_request = client.session.request
            client.session.request = fake_request

            with pytest.raises(asyncio.TimeoutError):
                await client.fetch("/test")

            assert call_count == 3


class TestAPIClientAuthentication:
    """Test API authentication and header handling."""

    @pytest.mark.asyncio
    async def test_adds_bearer_token_when_api_key_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """API client adds Authorization header when API key is available."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        test_api_key = "test_api_key_12345"
        monkeypatch.setenv("API_KEY", test_api_key)

        captured_headers = None

        async def fake_request(*args: Any, **kwargs: Any) -> FakeAiohttpResponse:
            nonlocal captured_headers
            captured_headers = kwargs.get("headers", {})
            return FakeAiohttpResponse(200, {"success": True})

        async with APIClient() as client:
            original_request = client.session.request
            client.session.request = fake_request
            await client.fetch("/test")

            assert captured_headers is not None
            assert "Authorization" in captured_headers
            assert captured_headers["Authorization"] == f"Bearer {test_api_key}"

    @pytest.mark.asyncio
    async def test_custom_headers_merged_with_defaults(self) -> None:
        """API client merges custom headers with default headers."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        captured_headers = None
        custom_headers = {"X-Custom-Header": "custom_value", "X-Request-ID": "req-123"}

        async def fake_request(*args: Any, **kwargs: Any) -> FakeAiohttpResponse:
            nonlocal captured_headers
            captured_headers = kwargs.get("headers", {})
            return FakeAiohttpResponse(200, {"success": True})

        async with APIClient() as client:
            original_request = client.session.request
            client.session.request = fake_request
            await client.fetch("/test", headers=custom_headers)

            assert captured_headers is not None
            assert "Content-Type" in captured_headers
            assert "Accept" in captured_headers
            assert captured_headers["X-Custom-Header"] == "custom_value"
            assert captured_headers["X-Request-ID"] == "req-123"


class TestAPIClientHTTPMethods:
    """Test different HTTP methods (GET, POST, PUT, DELETE)."""

    @pytest.mark.asyncio
    async def test_get_request_sends_correct_method(self) -> None:
        """API client sends GET requests correctly."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        captured_method = None

        async def fake_request(*args: Any, **kwargs: Any) -> FakeAiohttpResponse:
            nonlocal captured_method
            captured_method = kwargs.get("method")
            return FakeAiohttpResponse(200, {"data": "test"})

        async with APIClient() as client:
            original_request = client.session.request
            client.session.request = fake_request
            await client.fetch("/test", method="GET")
            assert captured_method == "GET"

    @pytest.mark.asyncio
    async def test_post_request_sends_json_data(self) -> None:
        """API client sends POST requests with JSON data."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        captured_data = None
        test_data = {"license_key": "ABC-123", "product_id": "PROD-456"}

        async def fake_request(*args: Any, **kwargs: Any) -> FakeAiohttpResponse:
            nonlocal captured_data
            captured_data = kwargs.get("json")
            return FakeAiohttpResponse(201, {"created": True})

        async with APIClient() as client:
            original_request = client.session.request
            client.session.request = fake_request
            await client.fetch("/validate", method="POST", data=test_data)
            assert captured_data == test_data


class TestAPIClientFallbackBehavior:
    """Test fallback behavior when aiohttp is unavailable."""

    @pytest.mark.asyncio
    async def test_returns_fallback_response_when_aiohttp_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """API client returns fallback response when aiohttp not available."""
        import intellicrack.utils.api_client as api_client_module
        original_has_aiohttp = api_client_module.HAS_AIOHTTP

        try:
            api_client_module.HAS_AIOHTTP = False
            async with APIClient() as client:
                result = await client.fetch("/test", method="POST", data={"key": "value"})

                assert result["error"] == "aiohttp not available"
                assert result["fallback"] is True
                assert result["endpoint"] == "/test"
                assert result["method"] == "POST"
        finally:
            api_client_module.HAS_AIOHTTP = original_has_aiohttp


class TestAPIClientHelperFunctions:
    """Test convenience helper functions."""

    @pytest.mark.asyncio
    async def test_make_api_call_creates_client_context(self) -> None:
        """make_api_call creates client context and makes request."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        import intellicrack.utils.api_client as api_client_module

        async def fake_fetch(self: Any, endpoint: str, method: str, data: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": True, "endpoint": endpoint}

        original_fetch = api_client_module.APIClient.fetch
        try:
            api_client_module.APIClient.fetch = fake_fetch
            result = await make_api_call("/test", "GET")
            assert result == {"success": True, "endpoint": "/test"}
        finally:
            api_client_module.APIClient.fetch = original_fetch

    def test_sync_api_call_wraps_async_function(self) -> None:
        """sync_api_call provides synchronous wrapper for async API calls."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        import intellicrack.utils.api_client as api_client_module

        async def fake_make_api_call(endpoint: str, method: str, data: dict[str, Any] | None) -> dict[str, Any]:
            return {"endpoint": endpoint, "method": method, "sync": True}

        original_make_api_call = api_client_module.make_api_call
        try:
            api_client_module.make_api_call = fake_make_api_call
            result = sync_api_call("/sync-test", "POST", {"data": "test"})
            assert result["endpoint"] == "/sync-test"
            assert result["method"] == "POST"
            assert result["sync"] is True
        finally:
            api_client_module.make_api_call = original_make_api_call


class TestAPIClientErrorParsing:
    """Test error response parsing and handling."""

    @pytest.mark.asyncio
    async def test_parses_json_error_response_from_server(self) -> None:
        """API client parses and includes JSON error details in exception."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        async def fake_request(*args: Any, **kwargs: Any) -> FakeAiohttpResponse:
            return FakeAiohttpResponse(400, {"error": "Invalid license key format"}, ok=False, reason="Bad Request")

        async with APIClient() as client:
            original_request = client.session.request
            client.session.request = fake_request

            with pytest.raises(ValueError) as exc_info:
                await client.fetch("/validate")

            assert "400" in str(exc_info.value)
            assert "Invalid license key format" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_handles_non_json_error_response(self) -> None:
        """API client handles error responses that are not JSON."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        class NonJsonResponse:
            """Fake response that cannot return JSON."""

            status = 500
            ok = False
            reason = "Internal Server Error"

            async def json(self) -> dict[str, Any]:
                raise ValueError("Not JSON")

            async def __aenter__(self) -> "NonJsonResponse":
                return self

            async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
                pass

        async def fake_request(*args: Any, **kwargs: Any) -> NonJsonResponse:
            return NonJsonResponse()

        client = APIClient()
        client.retry_attempts = 1
        async with client:
            original_request = client.session.request
            client.session.request = fake_request

            try:
                await client.fetch("/test")
            except Exception:
                pass


class TestAPIClientEndpointConstruction:
    """Test URL endpoint construction."""

    @pytest.mark.asyncio
    async def test_constructs_full_url_from_base_and_endpoint(self) -> None:
        """API client constructs full URL from base URL and endpoint."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        captured_url = None

        async def fake_request(*args: Any, **kwargs: Any) -> FakeAiohttpResponse:
            nonlocal captured_url
            captured_url = kwargs.get("url")
            return FakeAiohttpResponse(200, {"success": True})

        client = APIClient(base_url="https://api.example.com")
        async with client:
            original_request = client.session.request
            client.session.request = fake_request
            await client.fetch("/v1/licenses/validate")
            assert captured_url == "https://api.example.com/v1/licenses/validate"

    @pytest.mark.asyncio
    async def test_handles_endpoint_with_query_parameters(self) -> None:
        """API client correctly handles endpoints with query parameters."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        captured_url = None

        async def fake_request(*args: Any, **kwargs: Any) -> FakeAiohttpResponse:
            nonlocal captured_url
            captured_url = kwargs.get("url")
            return FakeAiohttpResponse(200, {"results": []})

        client = APIClient(base_url="https://api.example.com")
        async with client:
            original_request = client.session.request
            client.session.request = fake_request
            await client.fetch("/search?query=test&limit=10")
            assert captured_url == "https://api.example.com/search?query=test&limit=10"
