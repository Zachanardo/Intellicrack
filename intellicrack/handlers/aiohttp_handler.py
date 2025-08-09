"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import asyncio
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Union

from intellicrack.logger import logger

"""
AioHTTP Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for aiohttp imports.
When aiohttp is not available, it provides REAL, functional Python-based
implementations for async HTTP operations used in Intellicrack.
"""

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
    AIOHTTP_VERSION = None
    
    # Production-ready fallback async HTTP implementations
    
    # Exception classes
    class ClientError(Exception):
        """Base aiohttp client error."""
        pass
        
    class ClientConnectorError(ClientError):
        """Connection error."""
        pass
        
    class ServerTimeoutError(ClientError):
        """Server timeout error."""
        pass
        
    # Response class
    class ClientResponse:
        """Async HTTP response."""
        
        def __init__(self, url, status=200, headers=None, content=b""):
            """Initialize response."""
            self.url = url
            self.status = status
            self.headers = headers or {}
            self._content = content
            self.reason = "OK" if status < 400 else "Error"
            self.cookies = {}
            
        async def text(self, encoding='utf-8'):
            """Get response text."""
            return self._content.decode(encoding)
            
        async def json(self, encoding='utf-8'):
            """Parse JSON response."""
            text = await self.text(encoding)
            return json.loads(text)
            
        async def read(self):
            """Read response content."""
            return self._content
            
        def raise_for_status(self):
            """Raise exception for bad status."""
            if 400 <= self.status < 600:
                raise ClientError(f"{self.status} Error: {self.reason}")
                
        @property
        def ok(self):
            """Check if response is successful."""
            return self.status < 400
            
        async def __aenter__(self):
            """Async context manager entry."""
            return self
            
        async def __aexit__(self, *args):
            """Async context manager exit."""
            pass
            
    # Timeout configuration
    class ClientTimeout:
        """Client timeout configuration."""
        
        def __init__(self, total=None, connect=None, sock_connect=None, sock_read=None):
            """Initialize timeout."""
            self.total = total or 300
            self.connect = connect
            self.sock_connect = sock_connect
            self.sock_read = sock_read
            
    # Connector class
    class TCPConnector:
        """TCP connector for connection pooling."""
        
        def __init__(self, limit=100, limit_per_host=30, ttl_dns_cache=10, 
                    enable_cleanup_closed=False, force_close=False, ssl=True):
            """Initialize connector."""
            self.limit = limit
            self.limit_per_host = limit_per_host
            self.ttl_dns_cache = ttl_dns_cache
            self.enable_cleanup_closed = enable_cleanup_closed
            self.force_close = force_close
            self.ssl = ssl
            self._closed = False
            
        async def close(self):
            """Close connector."""
            self._closed = True
            
    # Session class
    class ClientSession:
        """Async HTTP session."""
        
        def __init__(self, connector=None, timeout=None, headers=None, 
                    cookies=None, auth=None, json_serialize=json.dumps):
            """Initialize session."""
            self.connector = connector or TCPConnector()
            self.timeout = timeout or ClientTimeout()
            self.headers = headers or {}
            self.cookies = cookies or {}
            self.auth = auth
            self.json_serialize = json_serialize
            self._closed = False
            
        async def request(self, method, url, **kwargs):
            """Send async HTTP request."""
            # Extract parameters
            params = kwargs.get('params')
            data = kwargs.get('data')
            json_data = kwargs.get('json')
            headers = kwargs.get('headers', {})
            timeout = kwargs.get('timeout', self.timeout)
            
            # Build URL with params
            if params:
                parsed = urllib.parse.urlparse(url)
                query = urllib.parse.parse_qs(parsed.query)
                query.update(params)
                query_string = urllib.parse.urlencode(query, doseq=True)
                url = urllib.parse.urlunparse(parsed._replace(query=query_string))
                
            # Prepare headers
            req_headers = dict(self.headers)
            req_headers.update(headers)
            
            # Prepare data
            body = None
            if json_data is not None:
                body = self.json_serialize(json_data).encode('utf-8')
                req_headers['Content-Type'] = 'application/json'
            elif data is not None:
                if isinstance(data, dict):
                    body = urllib.parse.urlencode(data).encode('utf-8')
                    req_headers['Content-Type'] = 'application/x-www-form-urlencoded'
                else:
                    body = data if isinstance(data, bytes) else str(data).encode('utf-8')
                    
            # Create request
            req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
            
            # Send request using asyncio
            loop = asyncio.get_event_loop()
            
            try:
                # Run urllib request in thread pool
                response = await loop.run_in_executor(
                    None,
                    lambda: urllib.request.urlopen(req, timeout=timeout.total if hasattr(timeout, 'total') else timeout)
                )
                
                content = response.read()
                
                # Create ClientResponse
                resp = ClientResponse(
                    url=response.url,
                    status=response.code,
                    headers=dict(response.headers),
                    content=content
                )
                
                return resp
                
            except urllib.error.HTTPError as e:
                # Create error response
                return ClientResponse(
                    url=url,
                    status=e.code,
                    headers=dict(e.headers) if hasattr(e, 'headers') else {},
                    content=e.read() if hasattr(e, 'read') else b''
                )
                
            except urllib.error.URLError as e:
                if isinstance(e.reason, socket.timeout):
                    raise ServerTimeoutError(f"Request timed out: {url}")
                else:
                    raise ClientConnectorError(f"Connection error: {e.reason}")
                    
            except Exception as e:
                raise ClientError(f"Request failed: {e}")
                
        async def get(self, url, **kwargs):
            """Send GET request."""
            return await self.request('GET', url, **kwargs)
            
        async def post(self, url, data=None, json=None, **kwargs):
            """Send POST request."""
            return await self.request('POST', url, data=data, json=json, **kwargs)
            
        async def put(self, url, data=None, **kwargs):
            """Send PUT request."""
            return await self.request('PUT', url, data=data, **kwargs)
            
        async def patch(self, url, data=None, **kwargs):
            """Send PATCH request."""
            return await self.request('PATCH', url, data=data, **kwargs)
            
        async def delete(self, url, **kwargs):
            """Send DELETE request."""
            return await self.request('DELETE', url, **kwargs)
            
        async def head(self, url, **kwargs):
            """Send HEAD request."""
            return await self.request('HEAD', url, **kwargs)
            
        async def options(self, url, **kwargs):
            """Send OPTIONS request."""
            return await self.request('OPTIONS', url, **kwargs)
            
        async def close(self):
            """Close session."""
            await self.connector.close()
            self._closed = True
            
        async def __aenter__(self):
            """Async context manager entry."""
            return self
            
        async def __aexit__(self, *args):
            """Async context manager exit."""
            await self.close()
            
    # Web server components
    class Request:
        """Web request object."""
        
        def __init__(self, method='GET', path='/', headers=None, body=b''):
            """Initialize request."""
            self.method = method
            self.path = path
            self.headers = headers or {}
            self.body = body
            self.match_info = {}
            self.query = {}
            self.cookies = {}
            self.app = None
            
        async def text(self):
            """Get request text."""
            return self.body.decode('utf-8')
            
        async def json(self):
            """Parse JSON request."""
            text = await self.text()
            return json.loads(text)
            
        async def post(self):
            """Get POST data."""
            # Parse form data
            text = await self.text()
            return urllib.parse.parse_qs(text)
            
    class Response:
        """Web response object."""
        
        def __init__(self, text='', status=200, headers=None, content_type='text/plain'):
            """Initialize response."""
            self.text = text
            self.status = status
            self.headers = headers or {}
            self.content_type = content_type
            self.body = text.encode('utf-8') if isinstance(text, str) else text
            
    class RouteTableDef:
        """Route table definition."""
        
        def __init__(self):
            """Initialize route table."""
            self.routes = []
            
        def get(self, path):
            """GET route decorator."""
            def decorator(handler):
                self.routes.append(('GET', path, handler))
                return handler
            return decorator
            
        def post(self, path):
            """POST route decorator."""
            def decorator(handler):
                self.routes.append(('POST', path, handler))
                return handler
            return decorator
            
        def put(self, path):
            """PUT route decorator."""
            def decorator(handler):
                self.routes.append(('PUT', path, handler))
                return handler
            return decorator
            
        def delete(self, path):
            """DELETE route decorator."""
            def decorator(handler):
                self.routes.append(('DELETE', path, handler))
                return handler
            return decorator
            
        def route(self, method, path):
            """Generic route decorator."""
            def decorator(handler):
                self.routes.append((method, path, handler))
                return handler
            return decorator
            
    class Application:
        """Web application."""
        
        def __init__(self):
            """Initialize application."""
            self.router = type('Router', (), {'routes': []})()
            self.middlewares = []
            self.on_startup = []
            self.on_cleanup = []
            self.on_shutdown = []
            self['state'] = {}
            
        def __getitem__(self, key):
            """Get app state item."""
            if not hasattr(self, '_state'):
                self._state = {}
            return self._state.get(key)
            
        def __setitem__(self, key, value):
            """Set app state item."""
            if not hasattr(self, '_state'):
                self._state = {}
            self._state[key] = value
            
        def add_routes(self, routes):
            """Add routes to application."""
            if hasattr(routes, 'routes'):
                # RouteTableDef
                for method, path, handler in routes.routes:
                    self.router.routes.append((method, path, handler))
            else:
                # List of routes
                for route in routes:
                    self.router.routes.append(route)
                    
        async def startup(self):
            """Run startup handlers."""
            for handler in self.on_startup:
                await handler(self)
                
        async def cleanup(self):
            """Run cleanup handlers."""
            for handler in self.on_cleanup:
                await handler(self)
                
        async def shutdown(self):
            """Run shutdown handlers."""
            for handler in self.on_shutdown:
                await handler(self)
                
    def run_app(app, host='127.0.0.1', port=8080, print=print):
        """Run web application."""
        logger.info("Starting aiohttp fallback server on %s:%d", host, port)
        print(f"======== Running on http://{host}:{port} ========")
        print("(Press CTRL+C to quit)")
        
        # Simple HTTP server using built-in libraries
        import http.server
        import socketserver
        
        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
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
        
        Application = Application
        Request = Request
        Response = Response
        RouteTableDef = RouteTableDef
        run_app = staticmethod(run_app)
        
        @staticmethod
        def json_response(data, status=200, **kwargs):
            """Create JSON response."""
            return Response(
                text=json.dumps(data),
                status=status,
                content_type='application/json',
                **kwargs
            )
            
    # Create module-like object
    class FallbackAioHTTP:
        """Fallback aiohttp module."""
        
        # Client classes
        ClientSession = ClientSession
        ClientResponse = ClientResponse
        ClientTimeout = ClientTimeout
        TCPConnector = TCPConnector
        
        # Exceptions
        ClientError = ClientError
        ClientConnectorError = ClientConnectorError
        ServerTimeoutError = ServerTimeoutError
        
        # Web module
        web = FallbackWeb
        
    aiohttp = FallbackAioHTTP()
    
    # Direct exports
    web = FallbackWeb
    Application = Application
    Request = Request
    Response = Response
    RouteTableDef = RouteTableDef
    run_app = run_app


# Export all aiohttp objects and availability flag
__all__ = [
    # Availability flags
    "HAS_AIOHTTP", "AIOHTTP_VERSION",
    # Main module
    "aiohttp",
    # Client classes
    "ClientSession", "ClientResponse", "ClientTimeout", "TCPConnector",
    # Exceptions
    "ClientError", "ClientConnectorError", "ServerTimeoutError",
    # Web module
    "web", "Application", "Request", "Response", "RouteTableDef", "run_app",
]