"""Production tests for aiohttp_handler.

Tests validate async HTTP client operations, server responses, fallback implementation,
timeout handling, and error recovery for both real aiohttp and fallback.
"""

import asyncio
import json
from typing import Any

import pytest

from intellicrack.handlers import aiohttp_handler


@pytest.mark.asyncio
async def test_client_session_get_request() -> None:
    """ClientSession performs GET request and returns valid response."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.get("https://httpbin.org/get")

        assert response.status < 400
        assert response.ok is True

        data = await response.json()
        assert isinstance(data, dict)


@pytest.mark.asyncio
async def test_client_session_post_request_with_json() -> None:
    """ClientSession performs POST request with JSON payload."""
    test_data = {"key": "value", "number": 42}

    async with aiohttp_handler.ClientSession() as session:
        response = await session.post("https://httpbin.org/post", json=test_data)

        assert response.status < 400

        data = await response.json()
        assert isinstance(data, dict)
        assert "json" in data
        assert data["json"]["key"] == "value"
        assert data["json"]["number"] == 42


@pytest.mark.asyncio
async def test_client_session_post_request_with_form_data() -> None:
    """ClientSession performs POST request with form data."""
    form_data = {"field1": "value1", "field2": "value2"}

    async with aiohttp_handler.ClientSession() as session:
        response = await session.post("https://httpbin.org/post", data=form_data)

        assert response.status < 400

        data = await response.json()
        assert "form" in data
        assert data["form"]["field1"] == "value1"


@pytest.mark.asyncio
async def test_client_session_put_request() -> None:
    """ClientSession performs PUT request successfully."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.put("https://httpbin.org/put", data={"test": "data"})

        assert response.status < 400


@pytest.mark.asyncio
async def test_client_session_delete_request() -> None:
    """ClientSession performs DELETE request successfully."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.delete("https://httpbin.org/delete")

        assert response.status < 400


@pytest.mark.asyncio
async def test_client_session_patch_request() -> None:
    """ClientSession performs PATCH request successfully."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.patch("https://httpbin.org/patch", data={"update": "value"})

        assert response.status < 400


@pytest.mark.asyncio
async def test_client_session_head_request() -> None:
    """ClientSession performs HEAD request and returns headers only."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.head("https://httpbin.org/get")

        assert response.status < 400
        assert response.headers is not None


@pytest.mark.asyncio
async def test_client_session_options_request() -> None:
    """ClientSession performs OPTIONS request successfully."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.options("https://httpbin.org/get")

        assert response.status < 400


@pytest.mark.asyncio
async def test_client_session_with_custom_headers() -> None:
    """ClientSession sends custom headers with request."""
    custom_headers = {"X-Custom-Header": "TestValue", "User-Agent": "IntellicrackTest/1.0"}

    async with aiohttp_handler.ClientSession(headers=custom_headers) as session:
        response = await session.get("https://httpbin.org/headers")

        assert response.status < 400

        data = await response.json()
        assert "headers" in data
        assert "X-Custom-Header" in data["headers"]
        assert data["headers"]["X-Custom-Header"] == "TestValue"


@pytest.mark.asyncio
async def test_client_session_with_query_parameters() -> None:
    """ClientSession includes query parameters in URL."""
    params = {"param1": "value1", "param2": "value2"}

    async with aiohttp_handler.ClientSession() as session:
        response = await session.get("https://httpbin.org/get", params=params)

        assert response.status < 400

        data = await response.json()
        assert "args" in data
        assert data["args"]["param1"] == "value1"
        assert data["args"]["param2"] == "value2"


@pytest.mark.asyncio
async def test_client_session_timeout_configuration() -> None:
    """ClientSession respects timeout configuration."""
    timeout = aiohttp_handler.ClientTimeout(total=30)

    async with aiohttp_handler.ClientSession(timeout=timeout) as session:
        response = await session.get("https://httpbin.org/delay/1")

        assert response.status < 400


@pytest.mark.asyncio
async def test_client_session_timeout_expires() -> None:
    """ClientSession raises timeout error when request exceeds timeout."""
    timeout = aiohttp_handler.ClientTimeout(total=1)

    async with aiohttp_handler.ClientSession(timeout=timeout) as session:
        with pytest.raises((aiohttp_handler.ServerTimeoutError, asyncio.TimeoutError)):
            await session.get("https://httpbin.org/delay/5")


@pytest.mark.asyncio
async def test_client_response_text_method() -> None:
    """ClientResponse.text() returns response body as string."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.get("https://httpbin.org/html")

        text = await response.text()

        assert isinstance(text, str)
        assert len(text) > 0
        assert "html" in text.lower()


@pytest.mark.asyncio
async def test_client_response_read_method() -> None:
    """ClientResponse.read() returns response body as bytes."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.get("https://httpbin.org/bytes/100")

        data = await response.read()

        assert isinstance(data, bytes)
        assert len(data) == 100


@pytest.mark.asyncio
async def test_client_response_json_parsing() -> None:
    """ClientResponse.json() parses JSON response correctly."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.get("https://httpbin.org/json")

        data = await response.json()

        assert isinstance(data, dict)


@pytest.mark.asyncio
async def test_client_response_raise_for_status() -> None:
    """ClientResponse.raise_for_status() raises exception for error codes."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.get("https://httpbin.org/status/404")

        assert response.status == 404
        assert response.ok is False

        with pytest.raises(aiohttp_handler.ClientError):
            response.raise_for_status()


@pytest.mark.asyncio
async def test_client_session_connection_error_handling() -> None:
    """ClientSession raises ClientConnectorError for invalid host."""
    async with aiohttp_handler.ClientSession() as session:
        with pytest.raises(aiohttp_handler.ClientConnectorError):
            await session.get("http://invalid-host-that-does-not-exist-12345.com")


@pytest.mark.asyncio
async def test_client_session_context_manager_cleanup() -> None:
    """ClientSession properly cleans up resources in async context manager."""
    session = aiohttp_handler.ClientSession()

    async with session:
        response = await session.get("https://httpbin.org/get")
        assert response.status < 400

    assert session._closed is True


@pytest.mark.asyncio
async def test_tcp_connector_configuration() -> None:
    """TCPConnector accepts configuration parameters."""
    connector = aiohttp_handler.TCPConnector(limit=50, limit_per_host=10)

    async with aiohttp_handler.ClientSession(connector=connector) as session:
        response = await session.get("https://httpbin.org/get")

        assert response.status < 400


@pytest.mark.asyncio
async def test_client_session_multiple_concurrent_requests() -> None:
    """ClientSession handles multiple concurrent requests efficiently."""
    async with aiohttp_handler.ClientSession() as session:
        tasks = [session.get(f"https://httpbin.org/delay/{i}") for i in range(3)]

        responses = await asyncio.gather(*tasks)

        assert len(responses) == 3
        for response in responses:
            assert response.status < 400


@pytest.mark.asyncio
async def test_availability_flag_indicates_library_status() -> None:
    """HAS_AIOHTTP flag correctly indicates aiohttp availability."""
    assert isinstance(aiohttp_handler.HAS_AIOHTTP, bool)

    if aiohttp_handler.HAS_AIOHTTP:
        assert aiohttp_handler.AIOHTTP_VERSION is not None
    else:
        assert aiohttp_handler.AIOHTTP_VERSION is None


@pytest.mark.asyncio
async def test_fallback_client_session_basic_operations() -> None:
    """Fallback ClientSession performs basic HTTP operations."""
    if aiohttp_handler.HAS_AIOHTTP:
        pytest.skip("Real aiohttp available, testing fallback requires import error")

    async with aiohttp_handler.ClientSession() as session:
        response = await session.get("https://httpbin.org/get")

        assert isinstance(response.status, int)


@pytest.mark.asyncio
async def test_client_session_handles_binary_response() -> None:
    """ClientSession correctly handles binary response data."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.get("https://httpbin.org/bytes/256")

        data = await response.read()

        assert isinstance(data, bytes)
        assert len(data) == 256


@pytest.mark.asyncio
async def test_client_session_post_with_bytes_data() -> None:
    """ClientSession posts binary data correctly."""
    binary_data = b"\x00\x01\x02\x03\x04\x05"

    async with aiohttp_handler.ClientSession() as session:
        response = await session.post("https://httpbin.org/post", data=binary_data)

        assert response.status < 400


@pytest.mark.asyncio
async def test_client_session_custom_json_serializer() -> None:
    """ClientSession uses custom JSON serializer if provided."""
    test_data = {"key": "value"}

    def custom_serializer(obj: Any) -> str:
        return json.dumps(obj, separators=(",", ":"))

    async with aiohttp_handler.ClientSession(json_serialize=custom_serializer) as session:
        response = await session.post("https://httpbin.org/post", json=test_data)

        assert response.status < 400

        data = await response.json()
        assert data["json"]["key"] == "value"


@pytest.mark.asyncio
async def test_response_url_property() -> None:
    """ClientResponse.url contains the final URL after redirects."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.get("https://httpbin.org/redirect/1")

        assert response.url is not None
        assert isinstance(response.url, str)


@pytest.mark.asyncio
async def test_client_session_error_responses_return_valid_objects() -> None:
    """ClientSession returns valid response object even for HTTP errors."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.get("https://httpbin.org/status/500")

        assert response.status == 500
        assert hasattr(response, "text")
        assert hasattr(response, "read")


@pytest.mark.asyncio
async def test_client_session_handles_redirect() -> None:
    """ClientSession follows HTTP redirects by default."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.get("https://httpbin.org/redirect/3")

        assert response.status < 400

        data = await response.json()
        assert isinstance(data, dict)


@pytest.mark.asyncio
async def test_client_response_headers_accessible() -> None:
    """ClientResponse headers are accessible as dictionary."""
    async with aiohttp_handler.ClientSession() as session:
        response = await session.get("https://httpbin.org/response-headers?Header1=Value1")

        assert response.headers is not None
        assert isinstance(response.headers, dict)


@pytest.mark.asyncio
async def test_module_exports_all_required_classes() -> None:
    """aiohttp_handler exports all required classes and functions."""
    assert hasattr(aiohttp_handler, "ClientSession")
    assert hasattr(aiohttp_handler, "ClientResponse")
    assert hasattr(aiohttp_handler, "ClientTimeout")
    assert hasattr(aiohttp_handler, "TCPConnector")
    assert hasattr(aiohttp_handler, "ClientError")
    assert hasattr(aiohttp_handler, "ClientConnectorError")
    assert hasattr(aiohttp_handler, "ServerTimeoutError")
    assert hasattr(aiohttp_handler, "HAS_AIOHTTP")


def test_synchronous_availability_check() -> None:
    """HAS_AIOHTTP flag can be checked synchronously."""
    has_aiohttp = aiohttp_handler.HAS_AIOHTTP

    assert isinstance(has_aiohttp, bool)


def test_version_string_format() -> None:
    """AIOHTTP_VERSION is None or valid version string."""
    version = aiohttp_handler.AIOHTTP_VERSION

    if version is not None:
        assert isinstance(version, str)
        assert len(version) > 0
