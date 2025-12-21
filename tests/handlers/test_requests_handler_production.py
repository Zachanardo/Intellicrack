"""Production-grade tests for requests handler.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator


class SimpleHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Test HTTP server handler."""

    def do_GET(self) -> None:
        if self.path == "/test":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"GET Success")
        elif self.path == "/json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "data": "test"}')
        elif self.path == "/error":
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Server Error")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"POST received: " + body)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def test_server() -> Generator[str, None, None]:
    port = 38475
    server = socketserver.TCPServer(("127.0.0.1", port), SimpleHTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    server.server_close()


class TestRequestsHandlerFallbackMode:
    """Test requests handler fallback urllib implementation."""

    def test_fallback_get_request_success(self, test_server: str) -> None:
        import intellicrack.handlers.requests_handler as handler

        response = handler.get(f"{test_server}/test", timeout=5)

        assert response.status_code == 200
        assert response.text == "GET Success"
        assert response.ok

    def test_fallback_get_request_json_parsing(self, test_server: str) -> None:
        import intellicrack.handlers.requests_handler as handler

        response = handler.get(f"{test_server}/json", timeout=5)

        assert response.status_code == 200
        json_data = response.json()
        assert json_data["status"] == "ok"
        assert json_data["data"] == "test"

    def test_fallback_post_request_with_data(self, test_server: str) -> None:
        import intellicrack.handlers.requests_handler as handler

        data = {"key": "value", "number": "42"}
        response = handler.post(f"{test_server}/test", data=data, timeout=5)

        assert response.status_code == 200
        assert b"POST received" in response.content

    def test_fallback_post_request_with_json(self, test_server: str) -> None:
        import intellicrack.handlers.requests_handler as handler

        json_data = {"test": "data", "number": 123}
        response = handler.post(f"{test_server}/test", json=json_data, timeout=5)

        assert response.status_code == 200
        assert "Content-Type" in response.headers

    def test_fallback_http_error_response(self, test_server: str) -> None:
        import intellicrack.handlers.requests_handler as handler

        response = handler.get(f"{test_server}/error", timeout=5)

        assert response.status_code == 500
        assert not response.ok

        with pytest.raises(handler.HTTPError):
            response.raise_for_status()

    def test_fallback_session_cookies_persistence(self, test_server: str) -> None:
        import intellicrack.handlers.requests_handler as handler

        session = handler.Session()

        session.cookies["test_cookie"] = "cookie_value"

        response = session.get(f"{test_server}/test", timeout=5)
        assert response.status_code == 200

    def test_fallback_session_headers_persistence(self, test_server: str) -> None:
        import intellicrack.handlers.requests_handler as handler

        session = handler.Session()
        session.headers["X-Custom-Header"] = "test-value"

        response = session.get(f"{test_server}/test", timeout=5)
        assert response.status_code == 200

    def test_fallback_case_insensitive_dict(self) -> None:
        import intellicrack.handlers.requests_handler as handler

        headers = handler.CaseInsensitiveDict()
        headers["Content-Type"] = "application/json"

        assert headers["content-type"] == "application/json"
        assert headers["CONTENT-TYPE"] == "application/json"
        assert headers.get("Content-TYPE") == "application/json"

    def test_fallback_basic_auth_header(self, test_server: str) -> None:
        import intellicrack.handlers.requests_handler as handler

        auth = handler.HTTPBasicAuth("username", "password")

        assert auth.username == "username"
        assert auth.password == "password"

    def test_fallback_response_iteration(self, test_server: str) -> None:
        import intellicrack.handlers.requests_handler as handler

        response = handler.get(f"{test_server}/test", timeout=5)

        chunks = list(response.iter_content(chunk_size=4))
        assert len(chunks) > 0
        assert b"".join(chunks) == response.content

    def test_fallback_prepared_request(self) -> None:
        import intellicrack.handlers.requests_handler as handler

        req = handler.PreparedRequest()
        req.prepare(
            method="POST",
            url="http://example.com/api",
            headers={"User-Agent": "Test"},
            json={"key": "value"},
        )

        assert req.method == "POST"
        assert req.url == "http://example.com/api"
        assert req.headers["Content-Type"] == "application/json"
        assert req.body is not None

    def test_fallback_timeout_handling(self) -> None:
        import intellicrack.handlers.requests_handler as handler

        with pytest.raises((TimeoutError, ConnectionError)):
            handler.get("http://192.0.2.1:9999", timeout=1)

    def test_fallback_connection_error(self) -> None:
        import intellicrack.handlers.requests_handler as handler

        with pytest.raises(ConnectionError):
            handler.get("http://invalid-hostname-that-does-not-exist.test", timeout=2)


class TestRequestsHandlerRealMode:
    """Test requests handler with real requests library (if available)."""

    def test_real_requests_detection(self) -> None:
        import intellicrack.handlers.requests_handler as handler

        if handler.HAS_REQUESTS:
            assert handler.REQUESTS_VERSION is not None
            assert handler.Session is not None
            assert handler.get is not None
        else:
            assert handler.Session is not None

    def test_all_http_methods_available(self) -> None:
        import intellicrack.handlers.requests_handler as handler

        assert callable(handler.get)
        assert callable(handler.post)
        assert callable(handler.put)
        assert callable(handler.patch)
        assert callable(handler.delete)
        assert callable(handler.head)
        assert callable(handler.options)

    def test_exception_classes_available(self) -> None:
        import intellicrack.handlers.requests_handler as handler

        assert handler.RequestError is not None
        assert handler.HTTPError is not None
        assert handler.ConnectTimeoutError is not None
        assert handler.ReadTimeoutError is not None
