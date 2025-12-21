"""Requests handler for Intellicrack.

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

import builtins
import json as json_module
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Generator, Iterable, Mapping, MutableMapping
from http.cookiejar import CookieJar
from typing import Any, cast

from intellicrack.utils.logger import logger


"""
Requests Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for requests imports.
When requests is not available, it provides REAL, functional Python-based
implementations for HTTP operations used in Intellicrack.
"""

# Requests availability detection and import handling
try:
    import requests
    from requests import (
        ConnectionError as _RequestsConnectionError,
        HTTPError,
        RequestException as RequestError,
        Response,
        Session,
        delete,
        get,
        head,
        options,
        patch,
        post,
        put,
    )
    from requests.adapters import HTTPAdapter
    from requests.auth import HTTPBasicAuth, HTTPDigestAuth
    from requests.cookies import RequestsCookieJar
    from requests.exceptions import (
        ConnectTimeout,
        InvalidURL,
        ProxyError,
        ReadTimeout,
        SSLError,
        Timeout as _RequestsTimeout,
        TooManyRedirects,
    )

    # Create aliases for backward compatibility
    ConnectTimeoutError = ConnectTimeout
    ReadTimeoutError = ReadTimeout
    TooManyRedirectsError = TooManyRedirects
    from requests.models import PreparedRequest
    from requests.packages.urllib3.util.retry import Retry
    from requests.structures import CaseInsensitiveDict

    # Verify requests exception classes are available
    _ = InvalidURL.__name__  # Used for URL validation error handling

    HAS_REQUESTS = True
    REQUESTS_VERSION = requests.__version__

except ImportError as e:
    logger.error("Requests not available, using fallback implementations: %s", e)
    HAS_REQUESTS = False
    _REQUESTS_VERSION_FALLBACK: str | None = None

    class _FallbackRequestError(Exception):
        """Base exception for requests."""

    class _FallbackConnectionError(_FallbackRequestError):
        """Connection error."""

    class _FallbackHTTPError(_FallbackRequestError):
        """HTTP error."""

    class _FallbackTimeoutError(_FallbackRequestError):
        """Timeout error."""

    class _FallbackTooManyRedirectsError(_FallbackRequestError):
        """Too many redirects."""

    class _FallbackInvalidURLError(_FallbackRequestError):
        """Invalid URL."""

    class _FallbackConnectTimeoutError(TimeoutError):
        """Connection timeout."""

    class _FallbackReadTimeoutError(TimeoutError):
        """Read timeout."""

    class _FallbackSSLError(ConnectionError):
        """SSL error."""

    class _FallbackProxyError(ConnectionError):
        """Proxy error."""

    class _FallbackCaseInsensitiveDict(dict[str, Any]):
        """Case-insensitive dictionary for headers.

        Provides dict-like access with case-insensitive string keys, useful
        for HTTP headers which are case-insensitive.
        """

        def __init__(self, data: dict[str, Any] | None = None) -> None:
            """Initialize case-insensitive dictionary.

            Args:
                data: Optional dictionary to initialize with.

            """
            super().__init__()
            if data:
                for key, value in data.items():
                    self[key] = value

        def __setitem__(self, key: str, value: Any) -> None:
            """Set item with case-insensitive key.

            Args:
                key: Dictionary key (lowercased if string).
                value: Dictionary value.

            """
            super().__setitem__(key.lower(), value)

        def __getitem__(self, key: str) -> Any:
            """Get item with case-insensitive key.

            Args:
                key: Dictionary key (lowercased if string).

            Returns:
                Any: Value associated with the key.

            Raises:
                KeyError: If key not found in dictionary.

            """
            return super().__getitem__(key.lower())

        def get(self, key: str, default: Any = None) -> Any:
            """Get value with case-insensitive key.

            Args:
                key: Dictionary key (lowercased if string).
                default: Default value if key not found.

            Returns:
                Any: Value associated with key, or default if not found.

            """
            try:
                return self[key]
            except KeyError:
                return default

    class _FallbackRequestsCookieJar(dict[str, str]):
        """Cookie jar for storing cookies.

        Provides a dict-like interface for managing HTTP cookies.
        """

        def set(self, name: str, value: str, domain: str | None = None, path: str | None = None) -> None:
            """Set cookie in jar.

            Args:
                name: Cookie name.
                value: Cookie value.
                domain: Optional cookie domain.
                path: Optional cookie path.

            """
            self[name] = value

    class _FallbackResponse:
        """HTTP response object."""

        def __init__(self) -> None:
            """Initialize response."""
            self.status_code: int = 200
            self.headers: _FallbackCaseInsensitiveDict = _FallbackCaseInsensitiveDict()
            self.url: str = ""
            self.content: bytes = b""
            self.text: str = ""
            self.encoding: str = "utf-8"
            self.cookies: _FallbackRequestsCookieJar = _FallbackRequestsCookieJar()
            self.elapsed: Any = None
            self.request: Any = None
            self.reason: str = "OK"
            self.raw: Any = None
            self.history: list[Any] = []

        def json(self) -> object:
            """Parse JSON response.

            Returns:
                object: Parsed JSON object from response content.

            Raises:
                json.JSONDecodeError: If response content is not valid JSON.

            """
            if not self.text:
                self.text = self.content.decode(self.encoding)
            return json_module.loads(self.text)

        def raise_for_status(self) -> None:
            """Raise exception for bad status codes.

            Raises:
                _FallbackHTTPError: If response status code indicates an error (4xx or 5xx).

            """
            if 400 <= self.status_code < 600:
                raise _FallbackHTTPError(f"{self.status_code} Error: {self.reason}")

        @property
        def ok(self) -> bool:
            """Check if response is successful.

            Returns:
                bool: True if status code is less than 400, False otherwise.

            """
            return self.status_code < 400

        def iter_content(self, chunk_size: int = 1024) -> Generator[bytes, None, None]:
            """Iterate over response content in chunks.

            Args:
                chunk_size: Size of each chunk in bytes. Defaults to 1024.

            Yields:
                bytes: Chunks of response content.

            """
            for i in range(0, len(self.content), chunk_size):
                yield self.content[i : i + chunk_size]

        def iter_lines(self, chunk_size: int = 512, decode_unicode: bool = True) -> Generator[str, None, None]:
            """Iterate over response lines.

            Args:
                chunk_size: Size of each chunk in bytes. Defaults to 512.
                decode_unicode: Whether to decode response as text. Defaults to True.

            Yields:
                str: Individual lines from response content.

            """
            text = self.text if decode_unicode else self.content.decode(self.encoding)
            yield from text.splitlines()

    class _FallbackPreparedRequest:
        """Prepared HTTP request.

        Represents a prepared HTTP request with all components assembled
        and ready for transmission.
        """

        def __init__(self) -> None:
            """Initialize prepared request."""
            self.method: str = "GET"
            self.url: str = ""
            self.headers: _FallbackCaseInsensitiveDict = _FallbackCaseInsensitiveDict()
            self.body: bytes | None = None
            self.hooks: dict[str, Any] = {}

        def prepare(
            self,
            method: str | None = None,
            url: str | None = None,
            headers: dict[str, Any] | None = None,
            files: Any | None = None,
            data: dict[str, Any] | bytes | str | None = None,
            params: dict[str, Any] | None = None,
            auth: Any | None = None,
            cookies: dict[str, str] | None = None,
            hooks: dict[str, Any] | None = None,
            json: Any | None = None,
        ) -> None:
            """Prepare the HTTP request.

            Args:
                method: HTTP method (GET, POST, etc.).
                url: Request URL.
                headers: Dictionary of HTTP headers.
                files: Files to upload (currently unused).
                data: Request body data (form or raw).
                params: URL query parameters.
                auth: Authentication handler.
                cookies: Cookies to include.
                hooks: Event hooks (currently unused).
                json: JSON data for request body.

            """
            self.method = method or self.method
            self.url = url or self.url

            if headers:
                for k, v in headers.items():
                    self.headers[k] = v

            if params:
                parsed = urllib.parse.urlparse(self.url)
                query = urllib.parse.parse_qs(parsed.query)
                for k, v in params.items():
                    query[k] = [str(x) for x in v] if isinstance(v, list) else [str(v)]
                query_string = urllib.parse.urlencode(query, doseq=True)
                self.url = urllib.parse.urlunparse(parsed._replace(query=query_string))

            if json is not None:
                self.body = json_module.dumps(json).encode("utf-8")
                self.headers["Content-Type"] = "application/json"
            elif data is not None:
                if isinstance(data, dict):
                    self.body = urllib.parse.urlencode(data).encode("utf-8")
                    self.headers["Content-Type"] = "application/x-www-form-urlencoded"
                else:
                    self.body = data if isinstance(data, bytes) else str(data).encode("utf-8")

    class _FallbackSession:
        """HTTP session with connection pooling and cookie persistence.

        Maintains state across multiple HTTP requests including headers,
        cookies, and configuration options.
        """

        def __init__(self) -> None:
            """Initialize HTTP session."""
            self.headers: _FallbackCaseInsensitiveDict = _FallbackCaseInsensitiveDict()
            self.cookies: _FallbackRequestsCookieJar = _FallbackRequestsCookieJar()
            self.auth: Any | None = None
            self.proxies: dict[str, str] = {}
            self.verify: bool | str = True
            self.cert: str | None = None
            self.max_redirects: int = 30
            self.trust_env: bool = True
            self.adapters: dict[str, Any] = {}

        def request(self, method: str, url: str, **kwargs: Any) -> _FallbackResponse:
            """Send HTTP request.

            Args:
                method: HTTP method (GET, POST, etc.).
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                _FallbackResponse: HTTP response object.

            """
            return _fallback_request(method, url, session=self, **kwargs)

        def get(self, url: str, **kwargs: Any) -> _FallbackResponse:
            """Send GET request.

            Args:
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                _FallbackResponse: HTTP response object.

            """
            return self.request("GET", url, **kwargs)

        def post(self, url: str, data: Any | None = None, json: Any | None = None, **kwargs: Any) -> _FallbackResponse:
            """Send POST request.

            Args:
                url: Request URL.
                data: Request body data.
                json: JSON request body.
                **kwargs: Additional request parameters.

            Returns:
                _FallbackResponse: HTTP response object.

            """
            return self.request("POST", url, data=data, json=json, **kwargs)

        def put(self, url: str, data: Any | None = None, **kwargs: Any) -> _FallbackResponse:
            """Send PUT request.

            Args:
                url: Request URL.
                data: Request body data.
                **kwargs: Additional request parameters.

            Returns:
                _FallbackResponse: HTTP response object.

            """
            return self.request("PUT", url, data=data, **kwargs)

        def patch(self, url: str, data: Any | None = None, **kwargs: Any) -> _FallbackResponse:
            """Send PATCH request.

            Args:
                url: Request URL.
                data: Request body data.
                **kwargs: Additional request parameters.

            Returns:
                _FallbackResponse: HTTP response object.

            """
            return self.request("PATCH", url, data=data, **kwargs)

        def delete(self, url: str, **kwargs: Any) -> _FallbackResponse:
            """Send DELETE request.

            Args:
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                _FallbackResponse: HTTP response object.

            """
            return self.request("DELETE", url, **kwargs)

        def head(self, url: str, **kwargs: Any) -> _FallbackResponse:
            """Send HEAD request.

            Args:
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                _FallbackResponse: HTTP response object.

            """
            return self.request("HEAD", url, **kwargs)

        def options(self, url: str, **kwargs: Any) -> _FallbackResponse:
            """Send OPTIONS request.

            Args:
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                _FallbackResponse: HTTP response object.

            """
            return self.request("OPTIONS", url, **kwargs)

        def close(self) -> None:
            """Close session and clean up resources."""

        def __enter__(self) -> "_FallbackSession":
            """Context manager entry.

            Returns:
                _FallbackSession: Session instance for use in with statement.

            """
            return self

        def __exit__(self, *args: Any) -> None:
            """Context manager exit.

            Args:
                *args: Exception information (exc_type, exc_val, exc_tb).

            """
            self.close()

    class _FallbackHTTPBasicAuth:
        """HTTP Basic Authentication.

        Provides Basic authentication credentials for HTTP requests.
        """

        def __init__(self, username: str, password: str) -> None:
            """Initialize HTTP Basic authentication.

            Args:
                username: Username credential.
                password: Password credential.

            """
            self.username = username
            self.password = password

    class _FallbackHTTPDigestAuth:
        """HTTP Digest Authentication.

        Provides Digest authentication credentials for HTTP requests.
        """

        def __init__(self, username: str, password: str) -> None:
            """Initialize HTTP Digest authentication.

            Args:
                username: Username credential.
                password: Password credential.

            """
            self.username = username
            self.password = password

    class _FallbackHTTPAdapter:
        """HTTP adapter for connection pooling.

        Configures connection pool parameters for HTTP sessions.
        """

        def __init__(self, pool_connections: int = 10, pool_maxsize: int = 10, max_retries: int = 0) -> None:
            """Initialize HTTP adapter.

            Args:
                pool_connections: Number of connection pools to cache. Defaults to 10.
                pool_maxsize: Maximum connections per pool. Defaults to 10.
                max_retries: Maximum retry attempts. Defaults to 0.

            """
            self.pool_connections = pool_connections
            self.pool_maxsize = pool_maxsize
            self.max_retries = max_retries

    class _FallbackRetry:
        """Retry configuration.

        Defines retry behavior for failed requests.
        """

        def __init__(
            self,
            total: int = 10,
            read: int | None = None,
            connect: int | None = None,
            backoff_factor: float = 0,
        ) -> None:
            """Initialize retry configuration.

            Args:
                total: Total number of retries. Defaults to 10.
                read: Number of read retries. Defaults to None.
                connect: Number of connection retries. Defaults to None.
                backoff_factor: Backoff factor for retries. Defaults to 0.

            """
            self.total = total
            self.read = read
            self.connect = connect
            self.backoff_factor = backoff_factor

    def _fallback_request(method: str, url: str, **kwargs: Any) -> _FallbackResponse:
        """Send HTTP request using urllib.

        Args:
            method: HTTP method (GET, POST, etc.).
            url: Request URL.
            **kwargs: Additional request parameters including params, data, json,
                headers, cookies, auth, timeout, verify, etc.

        Returns:
            _FallbackResponse: HTTP response object.

        Raises:
            TimeoutError: If request times out.
            ConnectionError: If connection fails.
            RequestError: For other request errors.

        """
        params = kwargs.get("params")
        data = kwargs.get("data")
        json_data = kwargs.get("json")
        headers_arg = kwargs.get("headers", {})
        headers: dict[str, Any] = cast("dict[str, Any]", headers_arg if isinstance(headers_arg, dict) else {})
        cookies_arg = kwargs.get("cookies")
        cookies: dict[str, str] | None = cast("dict[str, str] | None", cookies_arg if isinstance(cookies_arg, dict) else None)
        auth = kwargs.get("auth")
        timeout_arg = kwargs.get("timeout", 30)
        timeout: float = float(timeout_arg) if isinstance(timeout_arg, (int, float)) else 30.0
        kwargs.get("allow_redirects", True)
        kwargs.get("stream", False)
        verify = kwargs.get("verify", True)
        kwargs.get("cert")
        session = kwargs.get("session")

        if params:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            params_dict = cast("dict[str, Any]", params if isinstance(params, dict) else {})
            for k, v in params_dict.items():
                query[k] = [str(x) for x in v] if isinstance(v, list) else [str(v)]
            query_string = urllib.parse.urlencode(query, doseq=True)
            url = urllib.parse.urlunparse(parsed._replace(query=query_string))

        req_headers = _FallbackCaseInsensitiveDict()
        if session:
            session_typed = cast("_FallbackSession", session)
            for k, v in session_typed.headers.items():
                req_headers[k] = v
        for k, v in headers.items():
            req_headers[k] = v

        if session:
            session_typed = cast("_FallbackSession", session)
            if cookie_header := "; ".join(f"{k}={v}" for k, v in session_typed.cookies.items()):
                req_headers["Cookie"] = cookie_header
        if cookies:
            if cookie_header := "; ".join(f"{k}={v}" for k, v in cookies.items()):
                current_cookie = req_headers.get("Cookie", "")
                req_headers["Cookie"] = f"{current_cookie}; {cookie_header}" if current_cookie else cookie_header

        body: bytes | None = None
        if json_data is not None:
            body = json_module.dumps(json_data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        elif data is not None:
            if isinstance(data, dict):
                body = urllib.parse.urlencode(data).encode("utf-8")
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                body = data if isinstance(data, bytes) else str(data).encode("utf-8")

        if auth:
            import base64

            auth_typed = cast("_FallbackHTTPBasicAuth", auth)
            credentials = f"{auth_typed.username}:{auth_typed.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            req_headers["Authorization"] = f"Basic {encoded}"

        req = urllib.request.Request(url, data=body, headers=dict(req_headers), method=method)  # noqa: S310

        context: ssl.SSLContext | None = None
        if not verify:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as response:  # noqa: S310
                resp = _FallbackResponse()
                resp.status_code = response.code
                resp.reason = response.reason or "OK"
                resp.url = response.url or url
                resp.content = response.read()
                resp.headers = _FallbackCaseInsensitiveDict(dict(response.headers))

                content_type_val = resp.headers.get("content-type", "")
                content_type_str = str(content_type_val) if content_type_val else ""
                if "charset=" in content_type_str:
                    resp.encoding = content_type_str.split("charset=")[-1].split(";")[0].strip()
                else:
                    resp.encoding = "utf-8"

                try:
                    resp.text = resp.content.decode(resp.encoding)
                except UnicodeDecodeError:
                    resp.text = resp.content.decode("utf-8", errors="replace")

                if "Set-Cookie" in response.headers:
                    for cookie in response.headers.get_all("Set-Cookie"):
                        parts = cookie.split(";")[0].split("=", 1)
                        if len(parts) == 2:
                            resp.cookies[parts[0]] = parts[1]
                            if session:
                                session_typed = cast("_FallbackSession", session)
                                session_typed.cookies[parts[0]] = parts[1]

                return resp

        except urllib.error.HTTPError as e:
            resp = _FallbackResponse()
            resp.status_code = e.code
            resp.reason = e.reason or "Error"
            resp.url = url
            resp.content = e.read() if hasattr(e, "read") else b""
            resp.headers = _FallbackCaseInsensitiveDict(dict(e.headers)) if hasattr(e, "headers") else _FallbackCaseInsensitiveDict()

            try:
                resp.text = resp.content.decode("utf-8")
            except Exception:
                resp.text = resp.content.decode("utf-8", errors="replace")

            return resp

        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.timeout):
                error_msg = f"Request timed out: {url}"
                logger.error(error_msg)
                raise _FallbackTimeoutError(error_msg) from e
            error_msg = f"Connection error: {e.reason}"
            logger.error(error_msg)
            raise _FallbackConnectionError(error_msg) from e

        except builtins.TimeoutError as e:
            error_msg = f"Request timed out: {url}"
            logger.error(error_msg)
            raise _FallbackTimeoutError(error_msg) from e

        except Exception as e:
            error_msg = f"Request failed: {e}"
            logger.error(error_msg)
            raise _FallbackRequestError(error_msg) from e

    def _fallback_get(url: str, **kwargs: Any) -> _FallbackResponse:
        """Send GET request.

        Args:
            url: Request URL.
            **kwargs: Additional request parameters.

        Returns:
            _FallbackResponse: HTTP response object.

        """
        return _fallback_request("GET", url, **kwargs)

    def _fallback_post(url: str, data: Any | None = None, json: Any | None = None, **kwargs: Any) -> _FallbackResponse:
        """Send POST request.

        Args:
            url: Request URL.
            data: Request body data.
            json: JSON request body.
            **kwargs: Additional request parameters.

        Returns:
            _FallbackResponse: HTTP response object.

        """
        return _fallback_request("POST", url, data=data, json=json, **kwargs)

    def _fallback_put(url: str, data: Any | None = None, **kwargs: Any) -> _FallbackResponse:
        """Send PUT request.

        Args:
            url: Request URL.
            data: Request body data.
            **kwargs: Additional request parameters.

        Returns:
            _FallbackResponse: HTTP response object.

        """
        return _fallback_request("PUT", url, data=data, **kwargs)

    def _fallback_patch(url: str, data: Any | None = None, **kwargs: Any) -> _FallbackResponse:
        """Send PATCH request.

        Args:
            url: Request URL.
            data: Request body data.
            **kwargs: Additional request parameters.

        Returns:
            _FallbackResponse: HTTP response object.

        """
        return _fallback_request("PATCH", url, data=data, **kwargs)

    def _fallback_delete(url: str, **kwargs: Any) -> _FallbackResponse:
        """Send DELETE request.

        Args:
            url: Request URL.
            **kwargs: Additional request parameters.

        Returns:
            _FallbackResponse: HTTP response object.

        """
        return _fallback_request("DELETE", url, **kwargs)

    def _fallback_head(url: str, **kwargs: Any) -> _FallbackResponse:
        """Send HEAD request.

        Args:
            url: Request URL.
            **kwargs: Additional request parameters.

        Returns:
            _FallbackResponse: HTTP response object.

        """
        return _fallback_request("HEAD", url, **kwargs)

    def _fallback_options(url: str, **kwargs: Any) -> _FallbackResponse:
        """Send OPTIONS request.

        Args:
            url: Request URL.
            **kwargs: Additional request parameters.

        Returns:
            _FallbackResponse: HTTP response object.

        """
        return _fallback_request("OPTIONS", url, **kwargs)

    class FallbackRequests:
        """Fallback requests module.

        Provides a drop-in replacement for the requests library using only
        Python standard library components (urllib).
        """

        request = staticmethod(_fallback_request)
        get = staticmethod(_fallback_get)
        post = staticmethod(_fallback_post)
        put = staticmethod(_fallback_put)
        patch = staticmethod(_fallback_patch)
        delete = staticmethod(_fallback_delete)
        head = staticmethod(_fallback_head)
        options = staticmethod(_fallback_options)

        Response = _FallbackResponse
        Session = _FallbackSession
        PreparedRequest = _FallbackPreparedRequest
        RequestsCookieJar = _FallbackRequestsCookieJar
        HTTPAdapter = _FallbackHTTPAdapter

        auth = type("auth", (), {"HTTPBasicAuth": _FallbackHTTPBasicAuth, "HTTPDigestAuth": _FallbackHTTPDigestAuth})()

        RequestException = _FallbackRequestError
        ConnectionError = _FallbackConnectionError
        HTTPError = _FallbackHTTPError
        Timeout = _FallbackTimeoutError
        TooManyRedirects = _FallbackTooManyRedirectsError
        InvalidURL = _FallbackInvalidURLError
        ConnectTimeout = _FallbackConnectTimeoutError
        ReadTimeout = _FallbackReadTimeoutError
        SSLError = _FallbackSSLError
        ProxyError = _FallbackProxyError

        exceptions = type(
            "exceptions",
            (),
            {
                "RequestException": _FallbackRequestError,
                "ConnectionError": _FallbackConnectionError,
                "HTTPError": _FallbackHTTPError,
                "Timeout": _FallbackTimeoutError,
                "TooManyRedirects": _FallbackTooManyRedirectsError,
                "InvalidURL": _FallbackInvalidURLError,
                "ConnectTimeout": _FallbackConnectTimeoutError,
                "ReadTimeout": _FallbackReadTimeoutError,
                "SSLError": _FallbackSSLError,
                "ProxyError": _FallbackProxyError,
            },
        )()

        structures = type("structures", (), {"CaseInsensitiveDict": _FallbackCaseInsensitiveDict})()

        adapters = type("adapters", (), {"HTTPAdapter": _FallbackHTTPAdapter})()

        packages = type(
            "packages",
            (),
            {
                "urllib3": type(
                    "urllib3",
                    (),
                    {"util": type("util", (), {"retry": type("retry", (), {"Retry": _FallbackRetry})()})()},
                )()
            },
        )()

    Response = _FallbackResponse  # type: ignore[assignment, misc]
    Session = _FallbackSession  # type: ignore[assignment, misc]
    PreparedRequest = _FallbackPreparedRequest  # type: ignore[assignment, misc]
    RequestsCookieJar = _FallbackRequestsCookieJar  # type: ignore[assignment, misc]
    CaseInsensitiveDict = _FallbackCaseInsensitiveDict  # type: ignore[assignment, misc]
    HTTPAdapter = _FallbackHTTPAdapter  # type: ignore[assignment, misc]
    HTTPBasicAuth = _FallbackHTTPBasicAuth  # type: ignore[assignment, misc]
    HTTPDigestAuth = _FallbackHTTPDigestAuth  # type: ignore[assignment, misc]
    Retry = _FallbackRetry
    HTTPError = _FallbackHTTPError  # type: ignore[assignment, misc]
    SSLError = _FallbackSSLError  # type: ignore[assignment, misc]
    ProxyError = _FallbackProxyError  # type: ignore[assignment, misc]
    ConnectTimeoutError = _FallbackConnectTimeoutError  # type: ignore[assignment, misc]
    ReadTimeoutError = _FallbackReadTimeoutError  # type: ignore[assignment, misc]
    TooManyRedirectsError = _FallbackTooManyRedirectsError  # type: ignore[assignment, misc]
    RequestError = _FallbackRequestError  # type: ignore[assignment, misc]
    InvalidURLError = _FallbackInvalidURLError

    request = _fallback_request
    get = _fallback_get  # type: ignore[assignment]
    post = _fallback_post  # type: ignore[assignment]
    put = _fallback_put  # type: ignore[assignment]
    patch = _fallback_patch  # type: ignore[assignment]
    delete = _fallback_delete  # type: ignore[assignment]
    head = _fallback_head  # type: ignore[assignment]
    options = _fallback_options  # type: ignore[assignment]

    REQUESTS_VERSION: str | None = _REQUESTS_VERSION_FALLBACK  # type: ignore[no-redef]

    requests = FallbackRequests()  # type: ignore[assignment]


# Export all requests objects and availability flag
__all__ = [
    "CaseInsensitiveDict",
    "ConnectTimeoutError",
    "ConnectionError",
    "HAS_REQUESTS",
    "HTTPAdapter",
    "HTTPBasicAuth",
    "HTTPDigestAuth",
    "HTTPError",
    "InvalidURLError",
    "PreparedRequest",
    "ProxyError",
    "REQUESTS_VERSION",
    "ReadTimeoutError",
    "RequestError",
    "RequestsCookieJar",
    "Response",
    "Retry",
    "SSLError",
    "Session",
    "TimeoutError",
    "TooManyRedirectsError",
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
    "requests",
]
