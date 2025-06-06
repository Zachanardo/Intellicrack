"""
Network License Server Emulator

This module provides comprehensive network-based license server emulation capabilities.
It can intercept and respond to license verification requests from various software vendors
including FlexLM, HASP/Sentinel, Adobe, Autodesk, and Microsoft KMS protocols.

The emulator supports:
- Multi-protocol license server emulation
- SSL/TLS interception and response generation
- Traffic recording and analysis
- DNS redirection capabilities
- Automatic protocol detection and response generation

Author: Intellicrack Development Team
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
            'listen_ip': '0.0.0.0',
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

        # Load protocol fingerprints
        self._load_protocol_fingerprints()

        # Load response templates
        self._load_response_templates()

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

            # Start TCP servers on configured ports
            for port in self.config['listen_ports']:
                self._start_tcp_server(port)

            self.logger.info(f"Network License Server Emulator started on ports: {self.config['listen_ports']}")
            return True

        except Exception as e:
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
            for server in self.servers:
                server.shutdown()
                server.server_close()

            # Stop DNS server if running
            if self.dns_server:
                self.dns_server.shutdown()

            # Stop SSL interceptor if running
            if self.ssl_interceptor:
                self.ssl_interceptor.stop()

            # Stop traffic recorder if running
            if self.traffic_recorder:
                self.traffic_recorder.stop()

            self.logger.info("Network License Server Emulator stopped")
            return True

        except Exception as e:
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

                        # Generate response
                        if emulator.config['auto_respond']:
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

                except Exception as e:
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
            for pattern in fingerprint['patterns']:
                if pattern in data:
                    probability += 0.1

            if probability >= 0.5:
                return protocol

        # Check for common patterns
        if b'license' in data.lower() or b'activation' in data.lower():
            return 'generic'

        # Default to unknown protocol
        return 'unknown'

    def _generate_response(self, protocol: str, request_data: bytes) -> bytes:
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
        """
        self.logger.info("DNS server functionality would be implemented here")
        # This would require additional DNS libraries like dnslib
        # For now, it's a placeholder for future implementation

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
                    except Exception as e:
                        self.parent.logger.error("Failed to load SSL certificates: %s", e)

                    return context

                def _generate_self_signed_cert(self, cert_file: str, key_file: str) -> None:
                    """Generate a self-signed certificate for SSL interception"""
                    try:
                        import datetime

                        from cryptography import x509
                        from cryptography.hazmat.primitives import hashes, serialization
                        from cryptography.hazmat.primitives.asymmetric import rsa
                        from cryptography.x509.oid import NameOID

                        # Generate private key
                        key = rsa.generate_private_key(
                            public_exponent=65537,
                            key_size=2048,
                        )

                        # Generate certificate
                        subject = issuer = x509.Name([
                            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "License Server"),
                            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                        ])

                        cert = x509.CertificateBuilder().subject_name(
                            subject
                        ).issuer_name(
                            issuer
                        ).public_key(
                            key.public_key()
                        ).serial_number(
                            x509.random_serial_number()
                        ).not_valid_before(
                            datetime.datetime.utcnow()
                        ).not_valid_after(
                            datetime.datetime.utcnow() + datetime.timedelta(days=365)
                        ).add_extension(
                            x509.SubjectAlternativeName([
                                x509.DNSName("localhost"),
                                x509.DNSName("*.localhost"),
                                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                            ]),
                            critical=False,
                        ).sign(key, hashes.SHA256())

                        # Write private key
                        with open(key_file, 'wb') as f:
                            f.write(key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.NoEncryption()
                            ))

                        # Write certificate
                        with open(cert_file, 'wb') as f:
                            f.write(cert.public_bytes(serialization.Encoding.PEM))

                        self.parent.logger.info("Generated self-signed certificate for SSL interception")

                    except ImportError:
                        self.parent.logger.error("cryptography module not available, using basic SSL")
                        # Fallback to basic SSL without custom cert
                        pass
                    except Exception as e:
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

                    except Exception as e:
                        self.parent.logger.error("SSL interception error: %s", e)

                def stop(self) -> None:
                    """Stop the SSL interceptor"""
                    self.running = False

            self.ssl_interceptor = SSLInterceptor(self)
            self.logger.info("SSL interceptor initialized")

            # Start interceptor for HTTPS ports
            https_ports = [443, 8443]
            for port in self.config['listen_ports']:
                if port in https_ports:
                    # Start SSL server on this port
                    thread = threading.Thread(
                        target=self._run_ssl_server,
                        args=(port,),
                        daemon=True
                    )
                    thread.start()
                    self.logger.info("SSL interceptor started on port %s", port)

            return self.ssl_interceptor

        except Exception as e:
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

            self.logger.info(f"SSL server listening on {self.config['listen_ip']}:{port}")

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

                except Exception as e:
                    if self.running:
                        self.logger.error("SSL server error: %s", e)

            server_socket.close()

        except Exception as e:
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
                        for entry in self.traffic_log:
                            serializable_entry = entry.copy()
                            if isinstance(serializable_entry['data'], bytes):
                                serializable_entry['data'] = serializable_entry['data'].hex()
                            serializable_log.append(serializable_entry)

                        with open(log_file, 'w') as f:
                            json.dump(serializable_log, f, indent=2, default=str)

                        self.parent.logger.info("Saved traffic log to %s", log_file)
                        self.last_save = time.time()

                    except Exception as e:
                        self.parent.logger.error("Failed to save traffic log: %s", e)

                def analyze_patterns(self) -> Dict[str, List[str]]:
                    """Analyze recorded traffic for patterns"""
                    patterns: Dict[str, List[str]] = {}

                    for entry in self.traffic_log:
                        protocol = entry['protocol']
                        if protocol not in patterns:
                            patterns[protocol] = []

                        # Extract patterns from data
                        if entry['data']:
                            data_str = entry['data'][:100] if isinstance(entry['data'], bytes) else str(entry['data'])[:100]
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
                while self.running:
                    time.sleep(self.traffic_recorder.save_interval)
                    if self.traffic_recorder.recording:
                        self.traffic_recorder.save_log()

            thread = threading.Thread(target=auto_save_thread, daemon=True)
            thread.start()

            return self.traffic_recorder

        except Exception as e:
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
            ports = [int(port.strip()) for port in ports_str.split(',')]
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
        for protocol in emulator.protocol_fingerprints.keys():
            app.analyze_results.append(f"- {protocol.upper()}")

        app.analyze_results.append("\nTo use the emulator:")
        app.analyze_results.append("1. Configure the application to use localhost as the license server")
        app.analyze_results.append("2. Or redirect license server hostnames to localhost using hosts file")
        app.analyze_results.append("3. The emulator will automatically respond to license checks with valid responses")
    else:
        app.update_output.emit(log_message("[Network] Failed to start network license server emulator"))


__all__ = ['NetworkLicenseServerEmulator', 'run_network_license_emulator']
