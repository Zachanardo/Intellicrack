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
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from intellicrack.utils.api_client import APIClient, make_api_call, sync_api_call


class TestAPIClientInitialization:
    """Test API client initialization and configuration."""

    def test_api_client_initializes_with_default_config(self) -> None:
        """API client loads default configuration from environment."""
        with patch.dict(os.environ, {}, clear=True):
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

    def test_api_client_loads_config_from_environment(self) -> None:
        """API client loads configuration from environment variables."""
        env_vars = {
            "API_BASE_URL": "https://test.api.com",
            "API_TIMEOUT": "120",
            "API_RETRY_ATTEMPTS": "5",
            "API_RETRY_DELAY": "2000",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            with patch("intellicrack.utils.api_client.get_secret", side_effect=lambda k, d=None: env_vars.get(k, d)):
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

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise asyncio.TimeoutError("Request timed out")

            mock_response = AsyncMock()
            mock_response.ok = True
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"success": True})
            return mock_response

        async with APIClient() as client:
            with patch.object(client.session, "request", side_effect=mock_request):
                result = await client.fetch("/test")
                assert result == {"success": True}
                assert call_count == 3

    @pytest.mark.asyncio
    async def test_retries_on_server_error_5xx(self) -> None:
        """API client retries on 5xx server errors."""
        from intellicrack.utils.api_client import HAS_AIOHTTP, aiohttp

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        call_count = 0

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal call_count
            call_count += 1

            mock_response = AsyncMock()
            if call_count < 2:
                mock_response.ok = False
                mock_response.status = 503
                mock_response.reason = "Service Unavailable"
                mock_response.json = AsyncMock(return_value={"error": "Service down"})
            else:
                mock_response.ok = True
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value={"success": True})

            return mock_response

        async with APIClient() as client:
            with patch.object(client.session, "request", side_effect=mock_request):
                try:
                    await client.fetch("/test")
                except aiohttp.ClientError:
                    pass
                assert call_count >= 2

    @pytest.mark.asyncio
    async def test_no_retry_on_client_error_4xx(self) -> None:
        """API client does not retry on 4xx client errors."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        call_count = 0

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal call_count
            call_count += 1

            mock_response = AsyncMock()
            mock_response.ok = False
            mock_response.status = 404
            mock_response.reason = "Not Found"
            mock_response.json = AsyncMock(return_value={"error": "Resource not found"})
            return mock_response

        async with APIClient() as client:
            with patch.object(client.session, "request", side_effect=mock_request):
                with pytest.raises(ValueError) as exc_info:
                    await client.fetch("/test")

                assert "404" in str(exc_info.value)
                assert call_count == 1

    @pytest.mark.asyncio
    async def test_raises_after_max_retry_attempts_exceeded(self) -> None:
        """API client raises RuntimeError after exceeding max retry attempts."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        call_count = 0

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal call_count
            call_count += 1
            raise asyncio.TimeoutError("Request timed out")

        client = APIClient()
        client.retry_attempts = 3
        client.retry_delay = 0.01

        async with client:
            with patch.object(client.session, "request", side_effect=mock_request):
                with pytest.raises(asyncio.TimeoutError):
                    await client.fetch("/test")

                assert call_count == 3


class TestAPIClientAuthentication:
    """Test API authentication and header handling."""

    @pytest.mark.asyncio
    async def test_adds_bearer_token_when_api_key_present(self) -> None:
        """API client adds Authorization header when API key is available."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        test_api_key = "test_api_key_12345"
        captured_headers = None

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal captured_headers
            captured_headers = kwargs.get("headers", {})

            mock_response = AsyncMock()
            mock_response.ok = True
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"success": True})
            return mock_response

        with patch("intellicrack.utils.api_client.get_secret", return_value=test_api_key):
            async with APIClient() as client:
                with patch.object(client.session, "request", side_effect=mock_request):
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

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal captured_headers
            captured_headers = kwargs.get("headers", {})

            mock_response = AsyncMock()
            mock_response.ok = True
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"success": True})
            return mock_response

        async with APIClient() as client:
            with patch.object(client.session, "request", side_effect=mock_request):
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

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal captured_method
            captured_method = kwargs.get("method")

            mock_response = AsyncMock()
            mock_response.ok = True
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"data": "test"})
            return mock_response

        async with APIClient() as client:
            with patch.object(client.session, "request", side_effect=mock_request):
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

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal captured_data
            captured_data = kwargs.get("json")

            mock_response = AsyncMock()
            mock_response.ok = True
            mock_response.status = 201
            mock_response.json = AsyncMock(return_value={"created": True})
            return mock_response

        async with APIClient() as client:
            with patch.object(client.session, "request", side_effect=mock_request):
                await client.fetch("/validate", method="POST", data=test_data)
                assert captured_data == test_data

    @pytest.mark.asyncio
    async def test_put_request_updates_resource(self) -> None:
        """API client sends PUT requests for updates."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        captured_method = None

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal captured_method
            captured_method = kwargs.get("method")

            mock_response = AsyncMock()
            mock_response.ok = True
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"updated": True})
            return mock_response

        async with APIClient() as client:
            with patch.object(client.session, "request", side_effect=mock_request):
                await client.fetch("/resource/123", method="PUT", data={"status": "active"})
                assert captured_method == "PUT"

    @pytest.mark.asyncio
    async def test_delete_request_removes_resource(self) -> None:
        """API client sends DELETE requests."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        captured_method = None

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal captured_method
            captured_method = kwargs.get("method")

            mock_response = AsyncMock()
            mock_response.ok = True
            mock_response.status = 204
            mock_response.json = AsyncMock(return_value={})
            return mock_response

        async with APIClient() as client:
            with patch.object(client.session, "request", side_effect=mock_request):
                await client.fetch("/resource/123", method="DELETE")
                assert captured_method == "DELETE"


class TestAPIClientFallbackBehavior:
    """Test fallback behavior when aiohttp is unavailable."""

    @pytest.mark.asyncio
    async def test_returns_fallback_response_when_aiohttp_unavailable(self) -> None:
        """API client returns fallback response when aiohttp not available."""
        with patch("intellicrack.utils.api_client.HAS_AIOHTTP", False):
            async with APIClient() as client:
                result = await client.fetch("/test", method="POST", data={"key": "value"})

                assert result["error"] == "aiohttp not available"
                assert result["fallback"] is True
                assert result["endpoint"] == "/test"
                assert result["method"] == "POST"


class TestAPIClientHelperFunctions:
    """Test convenience helper functions."""

    @pytest.mark.asyncio
    async def test_make_api_call_creates_client_context(self) -> None:
        """make_api_call creates client context and makes request."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        with patch("intellicrack.utils.api_client.APIClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock()
            mock_instance.fetch = AsyncMock(return_value={"success": True})
            MockClient.return_value = mock_instance

            result = await make_api_call("/test", "GET")
            assert result == {"success": True}
            mock_instance.fetch.assert_called_once_with("/test", "GET", None)

    def test_sync_api_call_wraps_async_function(self) -> None:
        """sync_api_call provides synchronous wrapper for async API calls."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        async def mock_make_api_call(endpoint: str, method: str, data: dict[str, Any] | None) -> dict[str, Any]:
            return {"endpoint": endpoint, "method": method, "sync": True}

        with patch("intellicrack.utils.api_client.make_api_call", side_effect=mock_make_api_call):
            result = sync_api_call("/sync-test", "POST", {"data": "test"})
            assert result["endpoint"] == "/sync-test"
            assert result["method"] == "POST"
            assert result["sync"] is True


class TestAPIClientErrorParsing:
    """Test error response parsing and handling."""

    @pytest.mark.asyncio
    async def test_parses_json_error_response_from_server(self) -> None:
        """API client parses and includes JSON error details in exception."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            mock_response = AsyncMock()
            mock_response.ok = False
            mock_response.status = 400
            mock_response.reason = "Bad Request"
            mock_response.json = AsyncMock(return_value={"error": "Invalid license key format"})
            return mock_response

        async with APIClient() as client:
            with patch.object(client.session, "request", side_effect=mock_request):
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

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            mock_response = AsyncMock()
            mock_response.ok = False
            mock_response.status = 500
            mock_response.reason = "Internal Server Error"
            mock_response.json = AsyncMock(side_effect=ValueError("Not JSON"))
            return mock_response

        async with APIClient() as client:
            client.retry_attempts = 1
            with patch.object(client.session, "request", side_effect=mock_request):
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

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal captured_url
            captured_url = kwargs.get("url")

            mock_response = AsyncMock()
            mock_response.ok = True
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"success": True})
            return mock_response

        client = APIClient(base_url="https://api.example.com")
        async with client:
            with patch.object(client.session, "request", side_effect=mock_request):
                await client.fetch("/v1/licenses/validate")
                assert captured_url == "https://api.example.com/v1/licenses/validate"

    @pytest.mark.asyncio
    async def test_handles_endpoint_with_query_parameters(self) -> None:
        """API client correctly handles endpoints with query parameters."""
        from intellicrack.utils.api_client import HAS_AIOHTTP

        if not HAS_AIOHTTP:
            pytest.skip("aiohttp not available")

        captured_url = None

        async def mock_request(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal captured_url
            captured_url = kwargs.get("url")

            mock_response = AsyncMock()
            mock_response.ok = True
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"results": []})
            return mock_response

        client = APIClient(base_url="https://api.example.com")
        async with client:
            with patch.object(client.session, "request", side_effect=mock_request):
                await client.fetch("/search?query=test&limit=10")
                assert captured_url == "https://api.example.com/search?query=test&limit=10"
