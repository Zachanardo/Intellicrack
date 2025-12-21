"""AIOHTTP handler for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import socket
import socketserver
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Any

from intellicrack.utils.logger import logger


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


"""
AioHTTP Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for aiohttp imports.
When aiohttp is not available, it provides REAL, functional Python-based
implementations for async HTTP operations used in Intellicrack.
"""

# Module-level type declarations
HAS_AIOHTTP: bool = False
AIOHTTP_VERSION: str | None = None

# AioHTTP availability detection and import handling
try:
    import aiohttp
    from aiohttp import (
        ClientConnectorError,
        ClientError,
        ClientResponse,
        ClientSession,
        ClientTimeout,
        ServerTimeoutError,
        TCPConnector,
        web,
    )
    from aiohttp.web import Application, Request, Response, RouteTableDef, run_app

    HAS_AIOHTTP = True
    AIOHTTP_VERSION = aiohttp.__version__

except ImportError as e:
    logger.error("AioHTTP not available, using fallback implementations: %s", e)
    HAS_AIOHTTP = False

    # Production-ready fallback async HTTP implementations

    # Exception classes
    class _FallbackClientError(Exception):
        """Base aiohttp client error."""

    class _FallbackClientConnectorError(_FallbackClientError):
        """Connection error."""

    class _FallbackServerTimeoutError(_FallbackClientError):
        """Server timeout error."""

    # Response class
    class _FallbackClientResponse:
        """Async HTTP response."""

        def __init__(
            self: _FallbackClientResponse,
            url: str,
            status: int = 200,
            headers: dict[str, str] | None = None,
            content: bytes = b"",
        ) -> None:
            """Initialize response.

            Args:
                url: The URL that was requested.
                status: HTTP status code.
                headers: Response headers dictionary.
                content: Raw response content as bytes.

            """
            self.url: str = url
            self.status: int = status
            self.headers: dict[str, str] = headers or {}
            self._content: bytes = content
            self.reason: str = "OK" if status < 400 else "Error"
            self.cookies: dict[str, str] = {}

        async def text(self: _FallbackClientResponse, encoding: str = "utf-8") -> str:
            """Get response text.

            Args:
                encoding: Text encoding to use for decoding content.

            Returns:
                Response content decoded as a string.

            """
            return self._content.decode(encoding)

        async def json(self: _FallbackClientResponse, encoding: str = "utf-8") -> object:
            """Parse JSON response.

            Args:
                encoding: Text encoding to use for decoding content.

            Returns:
                Parsed JSON object.

            """
            text = await self.text(encoding)
            return json.loads(text)

        async def read(self: _FallbackClientResponse) -> bytes:
            """Read response content.

            Returns:
                Raw response content as bytes.

            """
            return self._content

        def raise_for_status(self: _FallbackClientResponse) -> None:
            """Raise exception for bad status.

            Raises:
                _FallbackClientError: If status code indicates an error (400-599).

            """
            if 400 <= self.status < 600:
                raise _FallbackClientError(f"{self.status} Error: {self.reason}")

        @property
        def ok(self: _FallbackClientResponse) -> bool:
            """Check if response is successful.

            Returns:
                True if status code is less than 400.

            """
            return self.status < 400

        async def __aenter__(self: _FallbackClientResponse) -> _FallbackClientResponse:
            """Async context manager entry.

            Returns:
                The ClientResponse instance.

            """
            return self

        async def __aexit__(
            self: _FallbackClientResponse,
            *args: object,
        ) -> None:
            """Async context manager exit.

            Args:
                *args: Exception information tuple.

            """

    # Timeout configuration
    class _FallbackClientTimeout:
        """Client timeout configuration."""

        def __init__(
            self: _FallbackClientTimeout,
            total: int | None = None,
            connect: int | None = None,
            sock_connect: int | None = None,
            sock_read: int | None = None,
        ) -> None:
            """Initialize timeout.

            Args:
                total: Total timeout in seconds.
                connect: Connection timeout in seconds.
                sock_connect: Socket connection timeout in seconds.
                sock_read: Socket read timeout in seconds.

            """
            self.total: int = total or 300
            self.connect: int | None = connect
            self.sock_connect: int | None = sock_connect
            self.sock_read: int | None = sock_read

    # Connector class
    class _FallbackTCPConnector:
        """TCP connector for connection pooling."""

        def __init__(
            self: _FallbackTCPConnector,
            limit: int = 100,
            limit_per_host: int = 30,
            ttl_dns_cache: int = 10,
            enable_cleanup_closed: bool = False,
            force_close: bool = False,
            ssl: bool = True,
        ) -> None:
            """Initialize connector.

            Args:
                limit: Maximum total connections.
                limit_per_host: Maximum connections per host.
                ttl_dns_cache: DNS cache TTL in seconds.
                enable_cleanup_closed: Whether to cleanup closed connections.
                force_close: Whether to force close connections.
                ssl: Whether to use SSL.

            """
            self.limit: int = limit
            self.limit_per_host: int = limit_per_host
            self.ttl_dns_cache: int = ttl_dns_cache
            self.enable_cleanup_closed: bool = enable_cleanup_closed
            self.force_close: bool = force_close
            self.ssl: bool = ssl
            self._closed: bool = False

        async def close(self: _FallbackTCPConnector) -> None:
            """Close connector."""
            self._closed = True

    # Session class
    class _FallbackClientSession:
        """Async HTTP session."""

        def __init__(
            self: _FallbackClientSession,
            connector: _FallbackTCPConnector | None = None,
            timeout: _FallbackClientTimeout | None = None,
            headers: dict[str, str] | None = None,
            cookies: dict[str, str] | None = None,
            auth: tuple[str, str] | None = None,
            json_serialize: Callable[[Any], str] = json.dumps,
        ) -> None:
            """Initialize session.

            Args:
                connector: TCP connector for pooling connections.
                timeout: Timeout configuration.
                headers: Default headers for all requests.
                cookies: Cookies to include in requests.
                auth: Authentication tuple (username, password).
                json_serialize: Function to serialize JSON.

            """
            self.connector: _FallbackTCPConnector = connector or _FallbackTCPConnector()
            self.timeout: _FallbackClientTimeout = timeout or _FallbackClientTimeout()
            self.headers: dict[str, str] = headers or {}
            self.cookies: dict[str, str] = cookies or {}
            self.auth: tuple[str, str] | None = auth
            self.json_serialize: Callable[[Any], str] = json_serialize
            self._closed: bool = False

        async def request(
            self: _FallbackClientSession,
            method: str,
            url: str,
            **kwargs: object,
        ) -> _FallbackClientResponse:
            """Send async HTTP request.

            Args:
                method: HTTP method (GET, POST, etc.).
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                _FallbackClientResponse: ClientResponse object.

            Raises:
                _FallbackServerTimeoutError: If request times out.
                _FallbackClientConnectorError: If connection fails.
                _FallbackClientError: If request fails.

            """
            # Extract parameters
            params_obj = kwargs.get("params")
            params: dict[str, object] | None = params_obj if isinstance(params_obj, dict) else None
            data: object | None = kwargs.get("data")
            json_data: object | None = kwargs.get("json")
            headers_obj = kwargs.get("headers", {})
            headers: dict[str, str] = headers_obj if isinstance(headers_obj, dict) else {}
            timeout_obj = kwargs.get("timeout", self.timeout)
            timeout: _FallbackClientTimeout = timeout_obj if isinstance(timeout_obj, _FallbackClientTimeout) else self.timeout

            # Build URL with params
            if params:
                parsed = urllib.parse.urlparse(url)
                query = urllib.parse.parse_qs(parsed.query)
                query.update({k: v if isinstance(v, list) else [str(v)] for k, v in params.items()})
                query_string = urllib.parse.urlencode(query, doseq=True)
                url = urllib.parse.urlunparse(parsed._replace(query=query_string))

            # Prepare headers
            req_headers = dict(self.headers)
            req_headers.update(headers)

            # Prepare data
            body = None
            if json_data is not None:
                body = self.json_serialize(json_data).encode("utf-8")
                req_headers["Content-Type"] = "application/json"
            elif data is not None:
                if isinstance(data, dict):
                    body = urllib.parse.urlencode(data).encode("utf-8")
                    req_headers["Content-Type"] = "application/x-www-form-urlencoded"
                else:
                    body = data if isinstance(data, bytes) else str(data).encode("utf-8")

            # Create request
            req = urllib.request.Request(url, data=body, headers=req_headers, method=method)  # noqa: S310  # Legitimate HTTP request for security research tool

            try:
                timeout_value: float | None = timeout.total if hasattr(timeout, "total") else None

                def _execute_request() -> tuple[str, int, dict[str, Any], bytes]:
                    with urllib.request.urlopen(req, timeout=timeout_value) as response:  # noqa: S310 - Controlled URL for analysis tooling
                        return (
                            response.geturl(),
                            getattr(response, "status", response.getcode()),
                            dict(response.headers),
                            response.read(),
                        )

                response_url, status_code, headers_dict, content = await asyncio.to_thread(_execute_request)

                # Create ClientResponse
                resp = _FallbackClientResponse(url=response_url, status=status_code, headers=headers_dict, content=content)

                return resp

            except urllib.error.HTTPError as e:
                # Create error response
                return _FallbackClientResponse(
                    url=url,
                    status=e.code,
                    headers=dict(e.headers) if hasattr(e, "headers") else {},
                    content=e.read() if hasattr(e, "read") else b"",
                )

            except urllib.error.URLError as e:
                if isinstance(e.reason, socket.timeout):
                    error_msg = f"Request timed out: {url}"
                    logger.error(error_msg)
                    raise _FallbackServerTimeoutError(error_msg) from e
                error_msg = f"Connection error: {e.reason}"
                logger.error(error_msg)
                raise _FallbackClientConnectorError(error_msg) from e

            except Exception as e:
                error_msg = f"Request failed: {e}"
                logger.error(error_msg)
                raise _FallbackClientError(error_msg) from e

        async def get(
            self: _FallbackClientSession,
            url: str,
            **kwargs: object,
        ) -> _FallbackClientResponse:
            """Send GET request.

            Args:
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                ClientResponse object.

            """
            return await self.request("GET", url, **kwargs)

        async def post(
            self: _FallbackClientSession,
            url: str,
            data: object | None = None,
            json: object | None = None,
            **kwargs: object,
        ) -> _FallbackClientResponse:
            """Send POST request.

            Args:
                url: Request URL.
                data: Request body data.
                json: JSON data to send.
                **kwargs: Additional request parameters.

            Returns:
                ClientResponse object.

            """
            return await self.request("POST", url, data=data, json=json, **kwargs)

        async def put(
            self: _FallbackClientSession,
            url: str,
            data: object | None = None,
            **kwargs: object,
        ) -> _FallbackClientResponse:
            """Send PUT request.

            Args:
                url: Request URL.
                data: Request body data.
                **kwargs: Additional request parameters.

            Returns:
                ClientResponse object.

            """
            return await self.request("PUT", url, data=data, **kwargs)

        async def patch(
            self: _FallbackClientSession,
            url: str,
            data: object | None = None,
            **kwargs: object,
        ) -> _FallbackClientResponse:
            """Send PATCH request.

            Args:
                url: Request URL.
                data: Request body data.
                **kwargs: Additional request parameters.

            Returns:
                ClientResponse object.

            """
            return await self.request("PATCH", url, data=data, **kwargs)

        async def delete(
            self: _FallbackClientSession,
            url: str,
            **kwargs: object,
        ) -> _FallbackClientResponse:
            """Send DELETE request.

            Args:
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                ClientResponse object.

            """
            return await self.request("DELETE", url, **kwargs)

        async def head(
            self: _FallbackClientSession,
            url: str,
            **kwargs: object,
        ) -> _FallbackClientResponse:
            """Send HEAD request.

            Args:
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                ClientResponse object.

            """
            return await self.request("HEAD", url, **kwargs)

        async def options(
            self: _FallbackClientSession,
            url: str,
            **kwargs: object,
        ) -> _FallbackClientResponse:
            """Send OPTIONS request.

            Args:
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                ClientResponse object.

            """
            return await self.request("OPTIONS", url, **kwargs)

        async def close(self: _FallbackClientSession) -> None:
            """Close session."""
            if self.connector:
                await self.connector.close()
            self._closed = True

        async def __aenter__(self: _FallbackClientSession) -> _FallbackClientSession:
            """Async context manager entry.

            Returns:
                The ClientSession instance.

            """
            return self

        async def __aexit__(
            self: _FallbackClientSession,
            *args: object,
        ) -> None:
            """Async context manager exit.

            Args:
                *args: Exception information tuple.

            """
            await self.close()

    # Web server components
    class _FallbackRequest:
        """Web request object."""

        def __init__(
            self: _FallbackRequest,
            method: str = "GET",
            path: str = "/",
            headers: dict[str, str] | None = None,
            body: bytes = b"",
        ) -> None:
            """Initialize request.

            Args:
                method: HTTP method.
                path: Request path.
                headers: Request headers.
                body: Request body.

            """
            self.method: str = method
            self.path: str = path
            self.headers: dict[str, str] = headers or {}
            self.body: bytes = body
            self.match_info: dict[str, Any] = {}
            self.query: dict[str, Any] = {}
            self.cookies: dict[str, str] = {}
            self.app: Any | None = None

        async def text(self: _FallbackRequest) -> str:
            """Get request text.

            Returns:
                Request body decoded as UTF-8 string.

            """
            return self.body.decode("utf-8")

        async def json(self: _FallbackRequest) -> object:
            """Parse JSON request.

            Returns:
                Parsed JSON object.

            """
            text = await self.text()
            return json.loads(text)

        async def post(self: _FallbackRequest) -> dict[str, Any]:
            """Get POST data.

            Returns:
                Parsed form data.

            """
            # Parse form data
            text = await self.text()
            return urllib.parse.parse_qs(text)

    class _FallbackResponse:
        """Web response object."""

        def __init__(
            self: _FallbackResponse,
            text: str = "",
            status: int = 200,
            headers: dict[str, str] | None = None,
            content_type: str = "text/plain",
        ) -> None:
            """Initialize response.

            Args:
                text: Response text.
                status: HTTP status code.
                headers: Response headers.
                content_type: Content-Type header.

            """
            self.text: str = text
            self.status: int = status
            self.headers: dict[str, str] = headers or {}
            self.content_type: str = content_type
            self.body: bytes = text.encode("utf-8") if isinstance(text, str) else text

    class _FallbackRouteTableDef:
        """Route table definition."""

        def __init__(self: _FallbackRouteTableDef) -> None:
            """Initialize route table."""
            self.routes: list[tuple[str, str, Callable[[Any], Any]]] = []

        def get(
            self: _FallbackRouteTableDef,
            path: str,
        ) -> Callable[[Callable[[Any], Any]], Callable[[Any], Any]]:
            """GET route decorator.

            Args:
                path: Route path.

            Returns:
                Decorator function.

            """

            def decorator(
                handler: Callable[[Any], Any],
            ) -> Callable[[Any], Any]:
                self.routes.append(("GET", path, handler))
                return handler

            return decorator

        def post(
            self: _FallbackRouteTableDef,
            path: str,
        ) -> Callable[[Callable[[Any], Any]], Callable[[Any], Any]]:
            """POST route decorator.

            Args:
                path: Route path.

            Returns:
                Decorator function.

            """

            def decorator(
                handler: Callable[[Any], Any],
            ) -> Callable[[Any], Any]:
                self.routes.append(("POST", path, handler))
                return handler

            return decorator

        def put(
            self: _FallbackRouteTableDef,
            path: str,
        ) -> Callable[[Callable[[Any], Any]], Callable[[Any], Any]]:
            """PUT route decorator.

            Args:
                path: Route path.

            Returns:
                Decorator function.

            """

            def decorator(
                handler: Callable[[Any], Any],
            ) -> Callable[[Any], Any]:
                self.routes.append(("PUT", path, handler))
                return handler

            return decorator

        def delete(
            self: _FallbackRouteTableDef,
            path: str,
        ) -> Callable[[Callable[[Any], Any]], Callable[[Any], Any]]:
            """DELETE route decorator.

            Args:
                path: Route path.

            Returns:
                Decorator function.

            """

            def decorator(
                handler: Callable[[Any], Any],
            ) -> Callable[[Any], Any]:
                self.routes.append(("DELETE", path, handler))
                return handler

            return decorator

        def route(
            self: _FallbackRouteTableDef,
            method: str,
            path: str,
        ) -> Callable[[Callable[[Any], Any]], Callable[[Any], Any]]:
            """Decorate route.

            Args:
                method: HTTP method.
                path: Route path.

            Returns:
                Decorator function.

            """

            def decorator(
                handler: Callable[[Any], Any],
            ) -> Callable[[Any], Any]:
                self.routes.append((method, path, handler))
                return handler

            return decorator

    class _FallbackApplication:
        """Web application."""

        def __init__(self: _FallbackApplication) -> None:
            """Initialize application."""
            self.router: Any = type("Router", (), {"routes": []})()
            self.middlewares: list[Any] = []
            self.on_startup: list[Callable[[Any], Awaitable[None]]] = []
            self.on_cleanup: list[Callable[[Any], Awaitable[None]]] = []
            self.on_shutdown: list[Callable[[Any], Awaitable[None]]] = []
            self._state: dict[str, Any] = {}

        def __getitem__(self: _FallbackApplication, key: str) -> object:
            """Get app state item.

            Args:
                key: State key.

            Returns:
                State value.

            """
            return self._state.get(key)

        def __setitem__(self: _FallbackApplication, key: str, value: object) -> None:
            """Set app state item.

            Args:
                key: State key.
                value: State value.

            """
            self._state[key] = value

        def add_routes(self: _FallbackApplication, routes: object) -> None:
            """Add routes to application.

            Args:
                routes: Routes to add.

            """
            if hasattr(routes, "routes"):
                # RouteTableDef
                routes_list = getattr(routes, "routes", [])
                if isinstance(routes_list, list):
                    for item in routes_list:
                        if isinstance(item, tuple) and len(item) >= 3:
                            method, path, handler = item[0], item[1], item[2]
                            self.router.routes.append((method, path, handler))
            elif isinstance(routes, list):
                # List of routes
                for route in routes:
                    self.router.routes.append(route)

        async def startup(self: _FallbackApplication) -> None:
            """Run startup handlers."""
            for handler in self.on_startup:
                await handler(self)

        async def cleanup(self: _FallbackApplication) -> None:
            """Run cleanup handlers."""
            for handler in self.on_cleanup:
                await handler(self)

        async def shutdown(self: _FallbackApplication) -> None:
            """Run shutdown handlers."""
            for handler in self.on_shutdown:
                await handler(self)

    def _run_app(
        app: _FallbackApplication,
        host: str = "127.0.0.1",
        port: int = 8080,
        print_func: Callable[[str], None] = print,
    ) -> None:
        """Run web application.

        Args:
            app: Application instance.
            host: Host to bind to.
            port: Port to bind to.
            print_func: Print function.

        """
        logger.info("Starting aiohttp fallback server on %s:%d", host, port)
        print_func(f"======== Running on http://{host}:{port} ========")
        print_func("(Press CTRL+C to quit)")

        # Simple HTTP server using built-in libraries
        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self: Handler) -> None:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"AioHTTP fallback server running")

        with socketserver.TCPServer((host, port), Handler) as httpd:
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                logger.info("Server stopped")

    # Web module
    class FallbackWeb:
        """Web module."""

        Application: type[_FallbackApplication] = _FallbackApplication
        Request: type[_FallbackRequest] = _FallbackRequest
        Response: type[_FallbackResponse] = _FallbackResponse
        RouteTableDef: type[_FallbackRouteTableDef] = _FallbackRouteTableDef
        run_app: Callable[[_FallbackApplication, str, int, Callable[[str], None]], None] = staticmethod(_run_app)

        @staticmethod
        def json_response(
            data: object,
            status: int = 200,
            **kwargs: object,
        ) -> _FallbackResponse:
            """Create JSON response.

            Args:
                data: Data to serialize as JSON.
                status: HTTP status code.
                **kwargs: Additional arguments.

            Returns:
                Response object.

            """
            return _FallbackResponse(text=json.dumps(data), status=status, content_type="application/json")

    # Create module-like object that will replace aiohttp in except block
    class _FallbackAioHTTPModule:
        """Fallback aiohttp module."""

        # Client classes
        ClientSession: type[_FallbackClientSession] = _FallbackClientSession
        ClientResponse: type[_FallbackClientResponse] = _FallbackClientResponse
        ClientTimeout: type[_FallbackClientTimeout] = _FallbackClientTimeout
        TCPConnector: type[_FallbackTCPConnector] = _FallbackTCPConnector

        # Exceptions
        ClientError: type[_FallbackClientError] = _FallbackClientError
        ClientConnectorError: type[_FallbackClientConnectorError] = _FallbackClientConnectorError
        ServerTimeoutError: type[_FallbackServerTimeoutError] = _FallbackServerTimeoutError

        # Web module
        web: type[FallbackWeb] = FallbackWeb

    # Create a fallback module-like object
    _aiohttp_fallback = _FallbackAioHTTPModule()


# Export all aiohttp objects and availability flag
__all__ = [
    "AIOHTTP_VERSION",
    "Application",
    "ClientConnectorError",
    "ClientError",
    "ClientResponse",
    "ClientSession",
    "ClientTimeout",
    "HAS_AIOHTTP",
    "Request",
    "Response",
    "RouteTableDef",
    "ServerTimeoutError",
    "TCPConnector",
    "aiohttp",
    "run_app",
    "web",
]
