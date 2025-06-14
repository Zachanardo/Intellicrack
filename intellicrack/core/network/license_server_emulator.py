"""
Network License Server Emulator 

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import ipaddress
import json
import logging
import os
import socket
import socketserver
import ssl
import threading
import time
import traceback
from typing import Any, Dict, List, Optional, Tuple

# Import new components
try:
    from .traffic_interception_engine import TrafficInterceptionEngine, InterceptedPacket, AnalyzedTraffic
    from .dynamic_response_generator import DynamicResponseGenerator, ResponseContext, GeneratedResponse
    HAS_NEW_COMPONENTS = True
except ImportError:
    HAS_NEW_COMPONENTS = False

try:
    from PyQt5.QtWidgets import QInputDialog, QLineEdit
    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False


class NetworkLicenseServerEmulator:
    """
    Full network license server emulator for intercepting and responding to license verification requests.

    This enhanced implementation provides a modular design with protocol-specific handlers,
    allowing for more sophisticated emulation of various license server protocols.
    It can emulate various license server protocols, intercept license verification
    requests, and generate valid-looking responses to bypass network license checks.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the network license server emulator.

        Args:
            config: Configuration dictionary (optional)
        """
        self.logger = logging.getLogger("IntellicrackLogger.NetworkEmulator")

        # Default configuration
        self.config = {
            'listen_ip': '127.0.0.1',  # Bind only to localhost for security
            'listen_ports': [1111, 1234, 1337, 8080, 8888, 27000, 27001],
            'dns_redirect': True,
            'ssl_intercept': True,
            'record_traffic': True,
            'auto_respond': True,
            'response_delay': 0.1  # seconds
        }

        # Update with provided configuration
        if config:
            self.config.update(config)

        # Add handlers from the first implementation
        self.protocol_handlers: Dict[str, Any] = {}
        self.running: bool = False
        self.server_thread: Optional[threading.Thread] = None

        # Initialize components
        self.servers: List[socketserver.TCPServer] = []
        self.dns_server: Optional[Any] = None
        self.ssl_interceptor: Optional[Any] = None
        self.traffic_recorder: Optional[Any] = None
        self.response_templates: Dict[str, Dict[str, bytes]] = {}
        self.protocol_fingerprints: Dict[str, Dict[str, Any]] = {}
        
        # New enhanced components
        self.traffic_engine: Optional[TrafficInterceptionEngine] = None
        self.response_generator: Optional[DynamicResponseGenerator] = None
        
        # Initialize enhanced components if available
        if HAS_NEW_COMPONENTS:
            self._initialize_enhanced_components()

        # Load protocol fingerprints
        self._load_protocol_fingerprints()

        # Load response templates
        self._load_response_templates()
        
    def _initialize_enhanced_components(self):
        """Initialize enhanced traffic interception and response generation"""
        try:
            # Initialize traffic interception engine
            self.traffic_engine = TrafficInterceptionEngine(self.config['listen_ip'])
            
            # Initialize dynamic response generator
            self.response_generator = DynamicResponseGenerator()
            
            # Set up analysis callback
            self.traffic_engine.add_analysis_callback(self._handle_analyzed_traffic)
            
            self.logger.info("Enhanced license server components initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize enhanced components: {e}")
            self.traffic_engine = None
            self.response_generator = None

    def _load_protocol_fingerprints(self) -> None:
        """
        Load protocol fingerprints for identifying license check protocols.
        """
        # Common license server protocols
        self.protocol_fingerprints = {
            'flexlm': {
                'patterns': [
                    b'VENDOR_STRING',
                    b'FEATURE',
                    b'INCREMENT',
                    b'SERVER_HOSTID',
                    b'SIGN='
                ],
                'ports': [27000, 27001, 1101]
            },
            'hasp': {
                'patterns': [
                    b'hasp',
                    b'HASP',
                    b'sentinel',
                    b'SENTINEL'
                ],
                'ports': [1947]
            },
            'adobe': {
                'patterns': [
                    b'adobe',
                    b'ADOBE',
                    b'lcsap',
                    b'LCSAP'
                ],
                'ports': [443, 8080]
            },
            'autodesk': {
                'patterns': [
                    b'adsk',
                    b'ADSK',
                    b'autodesk',
                    b'AUTODESK'
                ],
                'ports': [2080, 443]
            },
            'microsoft': {
                'patterns': [
                    b'msft',
                    b'MSFT',
                    b'microsoft',
                    b'MICROSOFT',
                    b'kms',
                    b'KMS'
                ],
                'ports': [1688, 443]
            }
        }

    def _load_response_templates(self) -> None:
        """
        Load response templates for various license server protocols.
        """
        # FlexLM response template
        self.response_templates['flexlm'] = {
            'license_ok': (
                b"SERVER this_host ANY 27000\n"
                b"VENDOR vendor\n"
                b"FEATURE product vendor 1.0 permanent uncounted HOSTID=ANY SIGN=VALID\n"
            )
        }

        # HASP response template
        self.response_templates['hasp'] = {
            'license_ok': (
                b'{"status":"OK","key":"VALID","expiration":"permanent","features":["all"]}'
            )
        }

        # Adobe response template
        self.response_templates['adobe'] = {
            'license_ok': (
                b'{"status":"SUCCESS","message":"License is valid","expiry":"never","serial":"1234-5678-9012-3456-7890"}'
            )
        }

        # Autodesk response template
        self.response_templates['autodesk'] = {
            'license_ok': (
                b'{"status":"success","license":{"status":"ACTIVATED","type":"PERMANENT"}}'
            )
        }

        # Microsoft KMS response template
        self.response_templates['microsoft'] = {
            'license_ok': (
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            )
        }

    def start(self) -> bool:
        """
        Start the network license server emulator.

        Returns:
            bool: True if started successfully, False otherwise
        """
        try:
            self.running = True

            # Start DNS server if enabled
            if self.config['dns_redirect']:
                self._start_dns_server()

            # Start SSL interceptor if enabled
            if self.config['ssl_intercept']:
                self._start_ssl_interceptor()

            # Start traffic recorder if enabled
            if self.config['record_traffic']:
                self._start_traffic_recorder()

            # Start enhanced traffic interception if available
            if self.traffic_engine and HAS_NEW_COMPONENTS:
                self.traffic_engine.start_interception(self.config['listen_ports'])
                self.logger.info("Enhanced traffic interception started")
            
            # Start TCP servers on configured ports
            for _port in self.config['listen_ports']:
                self._start_tcp_server(_port)

            self.logger.info("Network License Server Emulator started on ports: %s", self.config['listen_ports'])
            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error starting Network License Server Emulator: %s", e)
            self.logger.error(traceback.format_exc())
            self.stop()
            return False

    def stop(self) -> bool:
        """
        Stop the network license server emulator.

        Returns:
            bool: True if stopped successfully, False otherwise
        """
        try:
            self.running = False

            # Stop all TCP servers
            for _server in self.servers:
                _server.shutdown()
                _server.server_close()

            # Stop DNS server if running
            if self.dns_server:
                self.dns_server.shutdown()

            # Stop SSL interceptor if running
            if self.ssl_interceptor:
                self.ssl_interceptor.stop()

            # Stop traffic recorder if running
            if self.traffic_recorder:
                self.traffic_recorder.stop()
                
            # Stop enhanced components
            if self.traffic_engine:
                self.traffic_engine.stop_interception()

            self.logger.info("Network License Server Emulator stopped")
            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error stopping Network License Server Emulator: %s", e)
            return False

    def _start_tcp_server(self, port: int) -> socketserver.TCPServer:
        """
        Start a TCP server on the specified port.

        Args:
            port: Port number to listen on

        Returns:
            socketserver.TCPServer: Server instance
        """

        class LicenseRequestHandler(socketserver.BaseRequestHandler):
            """
            Request handler for license server emulator.
            """
            def handle(self) -> None:
                """
                Handle incoming license verification requests from client applications.

                This method is called by the socketserver framework whenever a client connects
                to the license server emulator. It processes incoming license requests by:
                1. Receiving data from the client
                2. Logging the request details
                3. Identifying the license protocol from the request data
                4. Generating an appropriate response based on the protocol
                5. Adding configured delays to simulate network conditions
                6. Sending the response back to the client

                The method interfaces with the parent emulator instance to access configuration
                settings and utilize helper methods for protocol identification and response generation.
                """
                # Get reference to parent emulator
                emulator = self.server.emulator

                try:
                    # Receive data
                    data = self.request.recv(4096)

                    if data:
                        # Log received data
                        emulator.logger.info(f"Received data on port {self.server.server_address[1]} from {self.client_address[0]}")

                        # Identify protocol
                        protocol = emulator._identify_protocol(data, self.server.server_address[1])

                        # Generate response using enhanced generator if available
                        if emulator.config['auto_respond']:
                            if emulator.response_generator and HAS_NEW_COMPONENTS:
                                # Use enhanced response generation
                                context = ResponseContext(
                                    source_ip=self.client_address[0],
                                    source_port=self.client_address[1],
                                    target_host=self.server.server_address[0],
                                    target_port=self.server.server_address[1],
                                    protocol_type=protocol,
                                    request_data=data,
                                    parsed_request=None,
                                    client_fingerprint=f"{self.client_address[0]}:{self.client_address[1]}",
                                    timestamp=time.time()
                                )
                                
                                generated_response = emulator.response_generator.generate_response(context)
                                response = generated_response.response_data
                                
                                emulator.logger.info(f"Generated {generated_response.response_type} response using {generated_response.generation_method}")
                            else:
                                # Use legacy response generation
                                response = emulator._generate_response(protocol, data)

                            # Add delay if configured
                            if emulator.config['response_delay'] > 0:
                                time.sleep(emulator.config['response_delay'])

                            # Send response
                            self.request.sendall(response)

                            # Log response
                            emulator.logger.info(f"Sent {len(response)} bytes response for {protocol} protocol")

                        # Record traffic if enabled
                        if emulator.traffic_recorder:
                            emulator.traffic_recorder.record(
                                source=self.client_address[0],
                                destination=f"{self.server.server_address[0]}:{self.server.server_address[1]}",
                                data=data,
                                protocol=protocol
                            )

                except (OSError, ValueError, RuntimeError) as e:
                    emulator.logger.error("Error handling request: %s", e)

        # Create server
        server = socketserver.ThreadingTCPServer((self.config['listen_ip'], port), LicenseRequestHandler)
        server.allow_reuse_address = True

        # Store reference to emulator
        server.emulator = self

        # Start server in a separate thread
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        # Store server instance
        self.servers.append(server)

        self.logger.info("TCP server started on port %s", port)
        return server

    def _identify_protocol(self, data: bytes, port: int) -> str:
        """
        Identify the license server protocol from the request data.

        Args:
            data: Request data
            port: Port number the request was received on

        Returns:
            str: Protocol name, or 'unknown' if not identified
        """
        # Check each protocol fingerprint
        for protocol, fingerprint in self.protocol_fingerprints.items():
            # Check if port matches
            if port in fingerprint['ports']:
                # Higher probability of this protocol
                probability = 0.5
            else:
                probability = 0.0

            # Check for pattern matches
            for _pattern in fingerprint['patterns']:
                if _pattern in data:
                    probability += 0.1

            if probability >= 0.5:
                return protocol

        # Check for common patterns
        if b'license' in data.lower() or b'activation' in data.lower():
            return 'generic'

        # Default to unknown protocol
        return 'unknown'

    def _generate_response(self, protocol: str, request_data: bytes) -> bytes:  # pylint: disable=unused-argument
        """
        Generate a response for the identified protocol.

        Args:
            protocol: Protocol name
            request_data: Request data

        Returns:
            bytes: Response data
        """
        # Check if we have a template for this protocol
        if protocol in self.response_templates:
            # Use license_ok template by default
            if 'license_ok' in self.response_templates[protocol]:
                return self.response_templates[protocol]['license_ok']

        # Default response for unknown protocols
        return b'{"status":"OK","license":"valid"}'

    def _start_dns_server(self) -> None:
        """
        Start a DNS server for redirecting license server hostnames.
        
        This DNS server intercepts license server DNS queries and redirects them
        to the local license server emulator, enabling license bypass.
        """
        import socket
        import struct
        import threading
        
        self.logger.info("Starting DNS server for license server redirection")
        
        # Common license server hostnames to intercept
        self.license_hostnames = {
            b'activate.adobe.com': '127.0.0.1',
            b'practivate.adobe.com': '127.0.0.1', 
            b'lm.licenses.adobe.com': '127.0.0.1',
            b'na1r.services.adobe.com': '127.0.0.1',
            b'hlrcv.stage.adobe.com': '127.0.0.1',
            b'lcs-mobile-cops.adobe.com': '127.0.0.1',
            b'autodesk.com': '127.0.0.1',
            b'registeronce.adobe.com': '127.0.0.1',
            b'3dns.adobe.com': '127.0.0.1',
            b'3dns-1.adobe.com': '127.0.0.1',
            b'3dns-2.adobe.com': '127.0.0.1',
            b'3dns-3.adobe.com': '127.0.0.1',
            b'3dns-4.adobe.com': '127.0.0.1',
            b'adobe-dns.adobe.com': '127.0.0.1',
            b'adobe-dns-1.adobe.com': '127.0.0.1',
            b'adobe-dns-2.adobe.com': '127.0.0.1',
            b'adobe-dns-3.adobe.com': '127.0.0.1',
            b'adobe-dns-4.adobe.com': '127.0.0.1',
            b'hl2rcv.adobe.com': '127.0.0.1',
        }
        
        try:
            # Create UDP socket for DNS
            self.dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.dns_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind to localhost only for security - prevents external access
            self.dns_socket.bind(('127.0.0.1', 53))
            self.dns_socket.settimeout(1.0)
            
            self.logger.info("DNS server started on port 53")
            
            while self.running:
                try:
                    data, addr = self.dns_socket.recvfrom(512)
                    # Handle DNS query in separate thread
                    dns_thread = threading.Thread(
                        target=self._handle_dns_query,
                        args=(data, addr),
                        daemon=True
                    )
                    dns_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error("DNS server error: %s", e)
                        
        except PermissionError:
            self.logger.warning("Cannot bind to port 53 (requires root/admin privileges)")
            self.logger.info("DNS server functionality disabled")
        except Exception as e:
            self.logger.error("Failed to start DNS server: %s", e)
        finally:
            if hasattr(self, 'dns_socket'):
                self.dns_socket.close()
                
    def _handle_dns_query(self, data: bytes, addr: tuple) -> None:
        """
        Handle individual DNS query.
        
        Args:
            data: DNS query data
            addr: Client address (ip, port)
        """
        try:
            if len(data) < 12:  # Minimum DNS header size
                return
                
            # Parse DNS header
            transaction_id = struct.unpack('>H', data[0:2])[0]
            flags = struct.unpack('>H', data[2:4])[0]
            questions = struct.unpack('>H', data[4:6])[0]
            
            if questions != 1:  # Only handle single question queries
                return
                
            # Parse question section (skip header)
            query_offset = 12
            query_name = b''
            
            # Parse domain name from DNS query
            while query_offset < len(data):
                length = data[query_offset]
                if length == 0:
                    query_offset += 1
                    break
                if length > 63:  # Invalid label length
                    return
                query_name += data[query_offset + 1:query_offset + 1 + length]
                if query_offset + 1 + length < len(data) and data[query_offset + 1 + length] != 0:
                    query_name += b'.'
                query_offset += 1 + length
                
            # Check if we should redirect this hostname
            redirect_ip = None
            for hostname, ip in self.license_hostnames.items():
                if hostname in query_name.lower():
                    redirect_ip = ip
                    break
                    
            if redirect_ip:
                # Create DNS response redirecting to local server
                response = self._create_dns_response(
                    transaction_id, query_name, redirect_ip, data[12:query_offset+4]
                )
                self.dns_socket.sendto(response, addr)
                self.logger.debug("Redirected %s to %s for %s", 
                                query_name.decode('utf-8', errors='ignore'), 
                                redirect_ip, addr[0])
            else:
                # Forward to real DNS server (8.8.8.8)
                try:
                    forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    forward_socket.settimeout(5.0)
                    forward_socket.sendto(data, ('8.8.8.8', 53))
                    response, _ = forward_socket.recvfrom(512)
                    self.dns_socket.sendto(response, addr)
                    forward_socket.close()
                except Exception:
                    # If forwarding fails, send NXDOMAIN response
                    response = self._create_dns_error_response(transaction_id, data[12:query_offset+4])
                    self.dns_socket.sendto(response, addr)
                    
        except Exception as e:
            self.logger.debug("Error handling DNS query: %s", e)
            
    def _create_dns_response(self, transaction_id: int, query_name: bytes, 
                           ip_address: str, question_section: bytes) -> bytes:
        """
        Create a DNS A record response.
        
        Args:
            transaction_id: DNS transaction ID
            query_name: Original query name
            ip_address: IP address to return
            question_section: Original question section
            
        Returns:
            DNS response packet
        """
        # DNS header (response)
        header = struct.pack('>HHHHHH',
            transaction_id,  # Transaction ID
            0x8180,         # Flags: response, authoritative
            1,              # Questions
            1,              # Answers
            0,              # Authority RRs
            0               # Additional RRs
        )
        
        # Answer section (A record)
        ip_parts = [int(part) for part in ip_address.split('.')]
        answer = (
            question_section[:-4] +  # Name (compressed pointer to question)
            struct.pack('>HH', 0x0001, 0x0001) +  # Type A, Class IN
            struct.pack('>I', 300) +  # TTL (5 minutes)
            struct.pack('>H', 4) +    # Data length
            struct.pack('BBBB', *ip_parts)  # IP address
        )
        
        return header + question_section + answer
        
    def _create_dns_error_response(self, transaction_id: int, question_section: bytes) -> bytes:
        """
        Create a DNS NXDOMAIN error response.
        
        Args:
            transaction_id: DNS transaction ID
            question_section: Original question section
            
        Returns:
            DNS error response packet
        """
        # DNS header (NXDOMAIN response)
        header = struct.pack('>HHHHHH',
            transaction_id,  # Transaction ID
            0x8183,         # Flags: response, NXDOMAIN
            1,              # Questions
            0,              # Answers
            0,              # Authority RRs
            0               # Additional RRs
        )
        
        return header + question_section

    def _start_ssl_interceptor(self) -> Optional[Any]:
        """
        Start an SSL interceptor for HTTPS license verification.

        This interceptor uses a man-in-the-middle approach to decrypt and analyze HTTPS traffic,
        allowing the emulator to respond to license verification requests over SSL/TLS.
        """
        try:
            class SSLInterceptor:
                """SSL/TLS interceptor for HTTPS license verification"""

                def __init__(self, parent: 'NetworkLicenseServerEmulator') -> None:
                    self.parent = parent
                    self.context = self._create_ssl_context()
                    self.running = False

                def _create_ssl_context(self) -> ssl.SSLContext:
                    """Create SSL context with custom certificate"""
                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

                    # Check for certificate files or create them
                    cert_dir = os.path.join(os.path.dirname(__file__), 'certs')
                    cert_file = os.path.join(cert_dir, 'server.crt')
                    key_file = os.path.join(cert_dir, 'server.key')

                    if not os.path.exists(cert_dir):
                        os.makedirs(cert_dir)

                    if not os.path.exists(cert_file) or not os.path.exists(key_file):
                        # Generate self-signed certificate
                        self._generate_self_signed_cert(cert_file, key_file)

                    try:
                        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    except (OSError, ValueError, RuntimeError) as e:
                        self.parent.logger.error("Failed to load SSL certificates: %s", e)

                    return context

                def _generate_self_signed_cert(self, cert_file: str, key_file: str) -> None:
                    """Generate a self-signed certificate for SSL interception using common utility"""
                    try:
                        from ....utils.certificate_utils import generate_self_signed_cert
                        
                        # Use common certificate generation utility
                        cert_data = generate_self_signed_cert(
                            common_name="localhost",
                            organization="License Server",
                            country="US",
                            state="State",
                            locality="City",
                            valid_days=365
                        )
                        
                        if cert_data:
                            cert_pem, key_pem = cert_data
                            
                            # Write certificate and key
                            with open(cert_file, 'wb') as f:
                                f.write(cert_pem)
                            
                            with open(key_file, 'wb') as f:
                                f.write(key_pem)
                                
                            self.parent.logger.info("Generated self-signed certificate for SSL interception")
                        else:
                            self.parent.logger.error("Failed to generate certificate using common utility")

                    except ImportError:
                        self.parent.logger.error("cryptography module not available, using basic SSL")
                        # Fallback to basic SSL without custom cert
                        pass
                    except (OSError, ValueError, RuntimeError) as e:
                        self.parent.logger.error("Error generating certificate: %s", e)

                def intercept_connection(self, client_socket: socket.socket, server_address: Tuple[str, int]) -> None:
                    """Intercept and handle SSL connection"""
                    try:
                        # Wrap socket with SSL
                        ssl_socket = self.context.wrap_socket(client_socket, server_side=True)

                        # Read request
                        request_data = ssl_socket.recv(8192)

                        # Analyze request
                        protocol = self.parent._identify_protocol(request_data, server_address[1])

                        # Generate response
                        if protocol in self.parent.response_templates:
                            response = self.parent.response_templates[protocol]['license_ok']
                        else:
                            response = b'OK'

                        # Send response
                        ssl_socket.send(response)
                        ssl_socket.close()

                    except (OSError, ValueError, RuntimeError) as e:
                        self.parent.logger.error("SSL interception error: %s", e)

                def stop(self) -> None:
                    """Stop the SSL interceptor"""
                    self.running = False

            self.ssl_interceptor = SSLInterceptor(self)
            self.logger.info("SSL interceptor initialized")

            # Start interceptor for HTTPS ports
            https_ports = [443, 8443]
            for _port in self.config['listen_ports']:
                if _port in https_ports:
                    # Start SSL server on this port
                    thread = threading.Thread(
                        target=self._run_ssl_server,
                        args=(_port,),
                        daemon=True
                    )
                    thread.start()
                    self.logger.info("SSL interceptor started on port %s", _port)

            return self.ssl_interceptor

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to start SSL interceptor: %s", e)
            return None

    def _run_ssl_server(self, port: int) -> None:
        """
        Run SSL server on specified port.

        Args:
            port: Port number to listen on
        """
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.config['listen_ip'], port))
            server_socket.listen(5)

            self.logger.info("SSL server listening on %s:%s", self.config['listen_ip'], port)

            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    self.logger.info("SSL connection from %s", address)

                    # Handle connection in a thread
                    thread = threading.Thread(
                        target=self.ssl_interceptor.intercept_connection,
                        args=(client_socket, address),
                        daemon=True
                    )
                    thread.start()

                except (OSError, ValueError, RuntimeError) as e:
                    if self.running:
                        self.logger.error("SSL server error: %s", e)

            server_socket.close()

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to start SSL server on port %s: %s", port, e)

    def _start_traffic_recorder(self) -> Optional[Any]:
        """
        Start a traffic recorder for license communications.

        Records all intercepted traffic for analysis and pattern learning.
        """
        try:
            class TrafficRecorder:
                """Records network traffic for analysis"""

                def __init__(self, parent: 'NetworkLicenseServerEmulator') -> None:
                    self.parent = parent
                    self.traffic_log: List[Dict[str, Any]] = []
                    self.recording = True
                    self.max_entries = 10000
                    self.save_interval = 60  # seconds
                    self.last_save = time.time()

                def record(self, source: str, destination: str, data: bytes, protocol: str = 'unknown') -> None:
                    """Record a traffic entry"""
                    entry = {
                        'timestamp': time.time(),
                        'source': source,
                        'destination': destination,
                        'data': data,
                        'protocol': protocol,
                        'size': len(data) if data else 0
                    }

                    self.traffic_log.append(entry)

                    # Maintain size limit
                    if len(self.traffic_log) > self.max_entries:
                        self.traffic_log.pop(0)

                    # Auto-save periodically
                    if time.time() - self.last_save > self.save_interval:
                        self.save_log()

                def save_log(self) -> None:
                    """Save traffic log to file"""
                    try:
                        log_dir = os.path.join(os.path.dirname(__file__), 'logs', 'traffic')
                        os.makedirs(log_dir, exist_ok=True)

                        log_file = os.path.join(log_dir, f"traffic_{time.strftime('%Y%m%d_%H%M%S')}.json")

                        # Convert bytes to string for JSON serialization
                        serializable_log = []
                        for _entry in self.traffic_log:
                            serializable_entry = _entry.copy()
                            if isinstance(serializable_entry['data'], bytes):
                                serializable_entry['data'] = serializable_entry['data'].hex()
                            serializable_log.append(serializable_entry)

                        with open(log_file, 'w', encoding='utf-8') as f:
                            json.dump(serializable_log, f, indent=2, default=str)

                        self.parent.logger.info("Saved traffic log to %s", log_file)
                        self.last_save = time.time()

                    except (OSError, ValueError, RuntimeError) as e:
                        self.parent.logger.error("Failed to save traffic log: %s", e)

                def analyze_patterns(self) -> Dict[str, List[str]]:
                    """Analyze recorded traffic for patterns"""
                    patterns: Dict[str, List[str]] = {}

                    for _entry in self.traffic_log:
                        protocol = _entry['protocol']
                        if protocol not in patterns:
                            patterns[protocol] = []

                        # Extract patterns from data
                        if _entry['data']:
                            data_str = _entry['data'][:100] if isinstance(_entry['data'], bytes) else str(_entry['data'])[:100]
                            patterns[protocol].append(data_str)

                    return patterns

                def stop(self) -> None:
                    """Stop traffic recording"""
                    self.recording = False
                    self.save_log()

            self.traffic_recorder = TrafficRecorder(self)
            self.logger.info("Traffic recorder initialized")

            # Start auto-save thread
            def auto_save_thread() -> None:
                """
                Background thread to automatically save traffic logs at regular intervals.
                
                Runs continuously while the server is active, checking every save_interval
                seconds whether traffic recording is enabled and saving logs if so.
                """
                while self.running:
                    time.sleep(self.traffic_recorder.save_interval)
                    if self.traffic_recorder.recording:
                        self.traffic_recorder.save_log()

            thread = threading.Thread(target=auto_save_thread, daemon=True)
            thread.start()

            return self.traffic_recorder

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to start traffic recorder: %s", e)
            return None

    def get_status(self) -> Dict[str, Any]:
        """
        Get the current status of the license server emulator.

        Returns:
            Dict containing emulator status information
        """
        return {
            'running': self.running,
            'ports': self.config['listen_ports'],
            'active_servers': len(self.servers),
            'protocols_supported': list(self.protocol_fingerprints.keys()),
            'ssl_enabled': self.ssl_interceptor is not None,
            'traffic_recording': self.traffic_recorder is not None,
            'dns_redirect': self.dns_server is not None
        }


def run_network_license_emulator(app: Any) -> None:
    """
    Run the network license server emulator.

    Args:
        app: Application instance
    """
    try:
        from ...utils.ui_utils import log_message
    except ImportError:
        def log_message(msg):
            """
            Fallback log message function when ui_utils is not available.
            
            Args:
                msg: Message to log
                
            Returns:
                str: The input message unchanged
            """
            return msg

    if not QT_AVAILABLE:
        print("PyQt5 not available, cannot run interactive emulator")
        return

    app.update_output.emit(log_message("[Network] Starting network license server emulator..."))

    # Create emulator
    emulator = NetworkLicenseServerEmulator()

    # Ask for ports
    ports_str, ok = QInputDialog.getText(
        app,
        "License Server Ports",
        "Enter comma-separated list of ports to listen on:",
        QLineEdit.Normal,
        "1111,1234,1337,8080,8888,27000,27001"
    )

    if ok:
        # Parse ports
        try:
            ports = [int(_port.strip()) for _port in ports_str.split(',')]
            emulator.config['listen_ports'] = ports
        except ValueError:
            app.update_output.emit(log_message("[Network] Invalid port numbers, using defaults"))
    else:
        app.update_output.emit(log_message("[Network] Cancelled"))
        return

    # Start emulator
    if emulator.start():
        app.update_output.emit(log_message("[Network] Network license server emulator started"))
        app.update_output.emit(log_message(f"[Network] Listening on ports: {emulator.config['listen_ports']}"))

        # Store emulator instance in app
        app.license_emulator = emulator

        # Add to analyze results
        if not hasattr(app, "analyze_results"):
            app.analyze_results = []

        app.analyze_results.append("\n=== NETWORK LICENSE SERVER EMULATOR ===")
        app.analyze_results.append(f"Listening on ports: {emulator.config['listen_ports']}")
        app.analyze_results.append("\nSupported protocols:")
        for _protocol in emulator.protocol_fingerprints.keys():
            app.analyze_results.append(f"- {_protocol.upper()}")

        app.analyze_results.append("\nTo use the emulator:")
        app.analyze_results.append("1. Configure the application to use localhost as the license server")
        app.analyze_results.append("2. Or redirect license server hostnames to localhost using hosts file")
        app.analyze_results.append("3. The emulator will automatically respond to license checks with valid responses")
    else:
        app.update_output.emit(log_message("[Network] Failed to start network license server emulator"))


__all__ = ['NetworkLicenseServerEmulator', 'run_network_license_emulator']
