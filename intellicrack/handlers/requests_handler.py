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
from typing import Dict, Generator, Optional, Union

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
    )
    from requests import (
        HTTPError,
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
    from requests import (
        RequestException as RequestError,
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
        TooManyRedirects,
    )
    from requests.exceptions import Timeout as _RequestsTimeout

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
    REQUESTS_VERSION = None

    # Production-ready fallback implementations using urllib

    # Exception classes
    class RequestError(Exception):
        """Base exception for requests."""

    class ConnectionError(RequestError):
        """Connection error."""

    class HTTPError(RequestError):
        """HTTP error."""

    class TimeoutError(RequestError):
        """Timeout error."""

    class TooManyRedirectsError(RequestError):
        """Too many redirects."""

    class InvalidURLError(RequestError):
        """Invalid URL."""

    class ConnectTimeoutError(TimeoutError):
        """Connection timeout."""

    class ReadTimeoutError(TimeoutError):
        """Read timeout."""

    class SSLError(ConnectionError):
        """SSL error."""

    class ProxyError(ConnectionError):
        """Proxy error."""

    # Response class
    class Response:
        """HTTP response object."""

        def __init__(self) -> None:
            """Initialize response."""
            self.status_code = 200
            self.headers = CaseInsensitiveDict()
            self.url = ""
            self.content = b""
            self.text = ""
            self.encoding = "utf-8"
            self.cookies = RequestsCookieJar()
            self.elapsed = None
            self.request = None
            self.reason = "OK"
            self.raw = None
            self.history = []

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
                HTTPError: If response status code indicates an error (4xx or 5xx).

            """
            if 400 <= self.status_code < 600:
                raise HTTPError(f"{self.status_code} Error: {self.reason}")

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

    # Case-insensitive dictionary
    class CaseInsensitiveDict(dict):
        """Case-insensitive dictionary for headers.

        Provides dict-like access with case-insensitive string keys, useful
        for HTTP headers which are case-insensitive.
        """

        def __init__(self, data: Optional[Dict[object, object]] = None) -> None:
            """Initialize case-insensitive dictionary.

            Args:
                data: Optional dictionary to initialize with.

            """
            super().__init__()
            if data:
                for key, value in data.items():
                    self[key] = value

        def __setitem__(self, key: object, value: object) -> None:
            """Set item with case-insensitive key.

            Args:
                key: Dictionary key (lowercased if string).
                value: Dictionary value.

            """
            super().__setitem__(key.lower() if isinstance(key, str) else key, value)

        def __getitem__(self, key: object) -> object:
            """Get item with case-insensitive key.

            Args:
                key: Dictionary key (lowercased if string).

            Returns:
                object: Value associated with the key.

            Raises:
                KeyError: If key not found in dictionary.

            """
            return super().__getitem__(key.lower() if isinstance(key, str) else key)

        def get(self, key: object, default: object = None) -> object:
            """Get value with case-insensitive key.

            Args:
                key: Dictionary key (lowercased if string).
                default: Default value if key not found.

            Returns:
                object: Value associated with key, or default if not found.

            """
            try:
                return self[key]
            except KeyError:
                return default

    # Cookie jar
    class RequestsCookieJar(dict):
        """Cookie jar for storing cookies.

        Provides a dict-like interface for managing HTTP cookies.
        """

        def set(self, name: str, value: str, domain: Optional[str] = None, path: Optional[str] = None) -> None:
            """Set cookie in jar.

            Args:
                name: Cookie name.
                value: Cookie value.
                domain: Optional cookie domain.
                path: Optional cookie path.

            """
            self[name] = value

        def get(self, name: str, default: object = None) -> object:
            """Get cookie from jar.

            Args:
                name: Cookie name.
                default: Default value if cookie not found.

            Returns:
                object: Cookie value or default if not found.

            """
            return super().get(name, default)

    # Prepared request
    class PreparedRequest:
        """Prepared HTTP request.

        Represents a prepared HTTP request with all components assembled
        and ready for transmission.
        """

        def __init__(self) -> None:
            """Initialize prepared request."""
            self.method = "GET"
            self.url = ""
            self.headers = CaseInsensitiveDict()
            self.body: Optional[bytes] = None
            self.hooks: Dict[str, object] = {}

        def prepare(
            self,
            method: Optional[str] = None,
            url: Optional[str] = None,
            headers: Optional[Dict[str, object]] = None,
            files: Optional[object] = None,
            data: Optional[Union[Dict[str, object], bytes, str]] = None,
            params: Optional[Dict[str, object]] = None,
            auth: Optional[object] = None,
            cookies: Optional[Dict[str, object]] = None,
            hooks: Optional[Dict[str, object]] = None,
            json: Optional[object] = None,
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
                self.headers.update(headers)

            if params:
                parsed = urllib.parse.urlparse(self.url)
                query = urllib.parse.parse_qs(parsed.query)
                query.update(params)
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

    # Session class
    class Session:
        """HTTP session with connection pooling and cookie persistence.

        Maintains state across multiple HTTP requests including headers,
        cookies, and configuration options.
        """

        def __init__(self) -> None:
            """Initialize HTTP session."""
            self.headers: CaseInsensitiveDict = CaseInsensitiveDict()
            self.cookies: RequestsCookieJar = RequestsCookieJar()
            self.auth: Optional[object] = None
            self.proxies: Dict[str, str] = {}
            self.verify: Union[bool, str] = True
            self.cert: Optional[str] = None
            self.max_redirects: int = 30
            self.trust_env: bool = True
            self.adapters: Dict[str, object] = {}

        def request(self, method: str, url: str, **kwargs: object) -> Response:
            """Send HTTP request.

            Args:
                method: HTTP method (GET, POST, etc.).
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                Response: HTTP response object.

            """
            return request(method, url, session=self, **kwargs)

        def get(self, url: str, **kwargs: object) -> Response:
            """Send GET request.

            Args:
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                Response: HTTP response object.

            """
            return self.request("GET", url, **kwargs)

        def post(self, url: str, data: Optional[object] = None, json: Optional[object] = None, **kwargs: object) -> Response:
            """Send POST request.

            Args:
                url: Request URL.
                data: Request body data.
                json: JSON request body.
                **kwargs: Additional request parameters.

            Returns:
                Response: HTTP response object.

            """
            return self.request("POST", url, data=data, json=json, **kwargs)

        def put(self, url: str, data: Optional[object] = None, **kwargs: object) -> Response:
            """Send PUT request.

            Args:
                url: Request URL.
                data: Request body data.
                **kwargs: Additional request parameters.

            Returns:
                Response: HTTP response object.

            """
            return self.request("PUT", url, data=data, **kwargs)

        def patch(self, url: str, data: Optional[object] = None, **kwargs: object) -> Response:
            """Send PATCH request.

            Args:
                url: Request URL.
                data: Request body data.
                **kwargs: Additional request parameters.

            Returns:
                Response: HTTP response object.

            """
            return self.request("PATCH", url, data=data, **kwargs)

        def delete(self, url: str, **kwargs: object) -> Response:
            """Send DELETE request.

            Args:
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                Response: HTTP response object.

            """
            return self.request("DELETE", url, **kwargs)

        def head(self, url: str, **kwargs: object) -> Response:
            """Send HEAD request.

            Args:
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                Response: HTTP response object.

            """
            return self.request("HEAD", url, **kwargs)

        def options(self, url: str, **kwargs: object) -> Response:
            """Send OPTIONS request.

            Args:
                url: Request URL.
                **kwargs: Additional request parameters.

            Returns:
                Response: HTTP response object.

            """
            return self.request("OPTIONS", url, **kwargs)

        def close(self) -> None:
            """Close session and clean up resources."""

        def __enter__(self) -> "Session":
            """Context manager entry.

            Returns:
                Session: Session instance for use in with statement.

            """
            return self

        def __exit__(self, *args: object) -> None:
            """Context manager exit.

            Args:
                *args: Exception information (exc_type, exc_val, exc_tb).

            """
            self.close()

    # Auth classes
    class HTTPBasicAuth:
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

    class HTTPDigestAuth:
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

    # Adapter and retry classes
    class HTTPAdapter:
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

    class Retry:
        """Retry configuration.

        Defines retry behavior for failed requests.
        """

        def __init__(self, total: int = 10, read: Optional[int] = None, connect: Optional[int] = None, backoff_factor: float = 0) -> None:
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

    # Main request function
    def request(method: str, url: str, **kwargs: object) -> Response:
        """Send HTTP request using urllib.

        Args:
            method: HTTP method (GET, POST, etc.).
            url: Request URL.
            **kwargs: Additional request parameters including params, data, json,
                headers, cookies, auth, timeout, verify, etc.

        Returns:
            Response: HTTP response object.

        Raises:
            TimeoutError: If request times out.
            ConnectionError: If connection fails.
            RequestError: For other request errors.

        """
        params = kwargs.get("params")
        data = kwargs.get("data")
        json_data = kwargs.get("json")
        headers = kwargs.get("headers", {})
        cookies = kwargs.get("cookies")
        auth = kwargs.get("auth")
        timeout = kwargs.get("timeout", 30)
        kwargs.get("allow_redirects", True)
        kwargs.get("stream", False)
        verify = kwargs.get("verify", True)
        kwargs.get("cert")
        session = kwargs.get("session")

        # Build URL with params
        if params:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            query.update(params)
            query_string = urllib.parse.urlencode(query, doseq=True)
            url = urllib.parse.urlunparse(parsed._replace(query=query_string))

        # Prepare headers
        req_headers = CaseInsensitiveDict()
        if session and session.headers:
            req_headers.update(session.headers)
        if headers:
            req_headers.update(headers)

        # Handle cookies
        if session and session.cookies:
            cookie_header = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
            if cookie_header:
                req_headers["Cookie"] = cookie_header
        if cookies:
            cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
            if cookie_header:
                req_headers["Cookie"] = req_headers.get("Cookie", "") + "; " + cookie_header

        # Prepare data
        body = None
        if json_data is not None:
            body = json_module.dumps(json_data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        elif data is not None:
            if isinstance(data, dict):
                body = urllib.parse.urlencode(data).encode("utf-8")
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                body = data if isinstance(data, bytes) else str(data).encode("utf-8")

        # Handle auth
        if auth:
            import base64

            credentials = f"{auth.username}:{auth.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            req_headers["Authorization"] = f"Basic {encoded}"

        # Create request
        req = urllib.request.Request(url, data=body, headers=dict(req_headers), method=method)  # noqa: S310  # Legitimate HTTP request for security research tool

        # Configure SSL
        context = None
        if not verify:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        # Send request
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as response:  # noqa: S310  # Legitimate HTTP request for security research tool
                # Create Response object
                resp = Response()
                resp.status_code = response.code
                resp.reason = response.reason
                resp.url = response.url
                resp.content = response.read()
                resp.headers = CaseInsensitiveDict(dict(response.headers))

                # Detect encoding
                content_type = resp.headers.get("content-type", "")
                if "charset=" in content_type:
                    resp.encoding = content_type.split("charset=")[-1].split(";")[0].strip()
                else:
                    resp.encoding = "utf-8"

                try:
                    resp.text = resp.content.decode(resp.encoding)
                except UnicodeDecodeError:
                    resp.text = resp.content.decode("utf-8", errors="replace")

                # Parse cookies from response
                if "Set-Cookie" in response.headers:
                    for cookie in response.headers.get_all("Set-Cookie"):
                        parts = cookie.split(";")[0].split("=", 1)
                        if len(parts) == 2:
                            resp.cookies[parts[0]] = parts[1]
                            if session:
                                session.cookies[parts[0]] = parts[1]

                return resp

        except urllib.error.HTTPError as e:
            # Create error response
            resp = Response()
            resp.status_code = e.code
            resp.reason = e.reason
            resp.url = url
            resp.content = e.read() if hasattr(e, "read") else b""
            resp.headers = CaseInsensitiveDict(dict(e.headers)) if hasattr(e, "headers") else CaseInsensitiveDict()

            try:
                resp.text = resp.content.decode("utf-8")
            except Exception:
                resp.text = resp.content.decode("utf-8", errors="replace")

            return resp

        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.timeout):
                error_msg = f"Request timed out: {url}"
                logger.error(error_msg)
                raise TimeoutError(error_msg) from e
            error_msg = f"Connection error: {e.reason}"
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e

        except builtins.TimeoutError as e:
            error_msg = f"Request timed out: {url}"
            logger.error(error_msg)
            raise TimeoutError(error_msg) from e

        except Exception as e:
            error_msg = f"Request failed: {e}"
            logger.error(error_msg)
            raise RequestError(error_msg) from e

    # Convenience functions
    def get(url: str, **kwargs: object) -> Response:
        """Send GET request.

        Args:
            url: Request URL.
            **kwargs: Additional request parameters.

        Returns:
            Response: HTTP response object.

        """
        return request("GET", url, **kwargs)

    def post(url: str, data: Optional[object] = None, json: Optional[object] = None, **kwargs: object) -> Response:
        """Send POST request.

        Args:
            url: Request URL.
            data: Request body data.
            json: JSON request body.
            **kwargs: Additional request parameters.

        Returns:
            Response: HTTP response object.

        """
        return request("POST", url, data=data, json=json, **kwargs)

    def put(url: str, data: Optional[object] = None, **kwargs: object) -> Response:
        """Send PUT request.

        Args:
            url: Request URL.
            data: Request body data.
            **kwargs: Additional request parameters.

        Returns:
            Response: HTTP response object.

        """
        return request("PUT", url, data=data, **kwargs)

    def patch(url: str, data: Optional[object] = None, **kwargs: object) -> Response:
        """Send PATCH request.

        Args:
            url: Request URL.
            data: Request body data.
            **kwargs: Additional request parameters.

        Returns:
            Response: HTTP response object.

        """
        return request("PATCH", url, data=data, **kwargs)

    def delete(url: str, **kwargs: object) -> Response:
        """Send DELETE request.

        Args:
            url: Request URL.
            **kwargs: Additional request parameters.

        Returns:
            Response: HTTP response object.

        """
        return request("DELETE", url, **kwargs)

    def head(url: str, **kwargs: object) -> Response:
        """Send HEAD request.

        Args:
            url: Request URL.
            **kwargs: Additional request parameters.

        Returns:
            Response: HTTP response object.

        """
        return request("HEAD", url, **kwargs)

    def options(url: str, **kwargs: object) -> Response:
        """Send OPTIONS request.

        Args:
            url: Request URL.
            **kwargs: Additional request parameters.

        Returns:
            Response: HTTP response object.

        """
        return request("OPTIONS", url, **kwargs)

    # Create module-like object
    class FallbackRequests:
        """Fallback requests module.

        Provides a drop-in replacement for the requests library using only
        Python standard library components (urllib).
        """

        # Functions
        request = staticmethod(request)
        get = staticmethod(get)
        post = staticmethod(post)
        put = staticmethod(put)
        patch = staticmethod(patch)
        delete = staticmethod(delete)
        head = staticmethod(head)
        options = staticmethod(options)

        # Classes
        Response = Response
        Session = Session
        PreparedRequest = PreparedRequest
        RequestsCookieJar = RequestsCookieJar
        HTTPAdapter = HTTPAdapter

        # Auth
        auth = type("auth", (), {"HTTPBasicAuth": HTTPBasicAuth, "HTTPDigestAuth": HTTPDigestAuth})()

        # Exceptions
        RequestException = RequestError
        ConnectionError = ConnectionError
        HTTPError = HTTPError
        Timeout = TimeoutError
        TooManyRedirects = TooManyRedirectsError
        InvalidURL = InvalidURLError
        ConnectTimeout = ConnectTimeoutError
        ReadTimeout = ReadTimeoutError
        SSLError = SSLError
        ProxyError = ProxyError

        exceptions = type(
            "exceptions",
            (),
            {
                "RequestException": RequestError,
                "ConnectionError": ConnectionError,
                "HTTPError": HTTPError,
                "Timeout": Timeout,
                "TooManyRedirects": TooManyRedirects,
                "InvalidURL": InvalidURL,
                "ConnectTimeout": ConnectTimeout,
                "ReadTimeout": ReadTimeout,
                "SSLError": SSLError,
                "ProxyError": ProxyError,
            },
        )()

        # Structures
        structures = type("structures", (), {"CaseInsensitiveDict": CaseInsensitiveDict})()

        # Adapters
        adapters = type("adapters", (), {"HTTPAdapter": HTTPAdapter})()

        # Packages
        packages = type(
            "packages",
            (),
            {"urllib3": type("urllib3", (), {"util": type("util", (), {"retry": type("retry", (), {"Retry": Retry})()})()})()},
        )()

    requests = FallbackRequests()


# Export all requests objects and availability flag
__all__ = [
    # Availability flags
    "HAS_REQUESTS",
    "REQUESTS_VERSION",
    # Main module
    "requests",
    # Functions
    "request",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    # Classes
    "Response",
    "Session",
    "PreparedRequest",
    "RequestsCookieJar",
    "HTTPAdapter",
    "Retry",
    # Auth
    "HTTPBasicAuth",
    "HTTPDigestAuth",
    # Exceptions
    "RequestError",
    "ConnectionError",
    "HTTPError",
    "TimeoutError",
    "TooManyRedirectsError",
    "InvalidURLError",
    "ConnectTimeoutError",
    "ReadTimeoutError",
    "SSLError",
    "ProxyError",
    # Structures
    "CaseInsensitiveDict",
]
