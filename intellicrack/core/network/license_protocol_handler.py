#!/usr/bin/env python3
"""License protocol handler for processing license validation requests.

License Protocol Handler Base Class.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import os
import secrets
import socket
import threading
from typing import Any

from intellicrack.utils.logger import logger


"""
License Protocol Handler Base Class.

This module provides a base class for implementing protocol-specific handlers
for various license verification protocols including FlexLM, HASP, Adobe, and others.
"""


class LicenseProtocolHandler:
    """Base class for license protocol handlers.

    This abstract base class defines the interface for implementing protocol-specific
    handlers for various license verification systems. Subclasses must implement
    the abstract methods to provide protocol-specific functionality.

    Features:
        - Proxy server management for intercepting license requests
        - Thread-safe operation with daemon threads
        - Configurable protocol-specific settings
        - Comprehensive logging and error handling

    Security Note:
        By default, the proxy binds to localhost (127.0.0.1) only for security.
        To bind to all interfaces (0.0.0.0), explicitly set bind_host in config.
        Binding to all interfaces poses security risks and should be avoided in production.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize the base LicenseProtocolHandler.

        Sets up the running state, proxy thread, and logger for protocol handling.

        Args:
            config: Optional configuration dictionary for the protocol handler

        """
        logger.debug("Entering LicenseProtocolHandler.__init__ with config=%s", config is not None)
        self.config = config or {}
        self.running = False
        self.proxy_thread: threading.Thread | None = None
        self.logger = logging.getLogger(__name__)

        self.port = self.config.get("port", int(os.environ.get("LICENSE_PROTOCOL_PORT", "8080")))
        self.host = self.config.get("host", os.environ.get("LICENSE_PROTOCOL_HOST", "localhost"))
        self.bind_host = self.config.get("bind_host", self.host)
        self.timeout = self.config.get("timeout", int(os.environ.get("LICENSE_PROTOCOL_TIMEOUT", "30")))

        self.logger.info("Initialized %s protocol handler", self.__class__.__name__)
        logger.debug("Exiting LicenseProtocolHandler.__init__: port=%d, host=%s", self.port, self.host)

    def clear_data(self) -> None:
        """Clear any captured data.

        This method clears captured requests, responses, and any cached information.
        Subclasses should override this to clear protocol-specific data structures.
        """
        self.logger.debug("Clearing protocol handler data")

        # Clear any base-level captured data
        if hasattr(self, "captured_requests"):
            self.captured_requests.clear()
            self.logger.debug("Cleared %d captured requests", len(self.captured_requests))

        if hasattr(self, "captured_responses"):
            self.captured_responses.clear()
            self.logger.debug("Cleared captured responses")

        if hasattr(self, "session_data"):
            self.session_data.clear()
            self.logger.debug("Cleared session data")

        if hasattr(self, "client_connections"):
            self.client_connections.clear()
            self.logger.debug("Cleared client connections tracking")

    def start_proxy(self, port: int = 8080) -> bool:
        """Start the proxy server for intercepting license requests.

        Args:
            port: Port number to bind the proxy server to

        Returns:
            True if proxy started successfully, False if already running

        """
        logger.debug("Entering start_proxy: port=%d", port)
        if self.running:
            self.logger.warning("Proxy server is already running")
            logger.debug("Exiting start_proxy: already running")
            return False

        self.clear_data()

        self.running = True
        self.port = port

        self.proxy_thread = threading.Thread(
            target=self._run_proxy,
            args=(port,),
            daemon=True,
            name=f"{self.__class__.__name__}Proxy",
        )
        self.proxy_thread.start()

        self.logger.info("Started %s proxy on port %s", self.__class__.__name__, port)
        logger.debug("Exiting start_proxy: success")
        return True

    def stop_proxy(self) -> bool:
        """Stop the proxy server.

        Returns:
            True if proxy stopped successfully, False if not running

        """
        logger.debug("Entering stop_proxy")
        if not self.running:
            self.logger.warning("Proxy server is not running")
            logger.debug("Exiting stop_proxy: not running")
            return False

        self.running = False

        if self.proxy_thread and self.proxy_thread.is_alive():
            self.proxy_thread.join(timeout=5.0)
            if self.proxy_thread.is_alive():
                self.logger.warning("Proxy thread did not terminate gracefully")

        self.logger.info("Stopped %s proxy", self.__class__.__name__)
        logger.debug("Exiting stop_proxy: success")
        return True

    def shutdown(self) -> None:
        """Shutdown the protocol handler completely.

        This method stops the proxy server and cleans up all resources.
        """
        logger.debug("Entering shutdown")
        self.logger.info("Shutting down %s protocol handler", self.__class__.__name__)

        if self.running:
            self.stop_proxy()

        self.clear_data()

        self.running = False
        self.proxy_thread = None

        self.logger.info("Protocol handler shutdown complete")
        logger.debug("Exiting shutdown")

    def is_running(self) -> bool:
        """Check if the proxy server is currently running.

        Returns:
            True if proxy is running, False otherwise

        """
        return self.running

    def get_status(self) -> dict[str, Any]:
        """Get current status of the protocol handler.

        Returns:
            Dictionary containing handler status information

        """
        return {
            "protocol": self.__class__.__name__,
            "running": self.running,
            "port": self.port,
            "host": self.host,
            "thread_active": self.proxy_thread.is_alive() if self.proxy_thread else False,
        }

    def _run_proxy(self, port: int) -> None:
        """Run the proxy server.

        Default implementation provides a basic TCP server that accepts connections
        and delegates to handle_connection. Subclasses can override for protocol-specific
        server logic (UDP, custom protocols, etc.).

        Args:
            port: Port number to bind the proxy server to

        """
        logger.debug("Entering _run_proxy: port=%d", port)
        import socket

        self.logger.info("Starting proxy server on port %s", port)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.bind_host, port))
            server_socket.listen(5)
            server_socket.settimeout(1.0)

            self.logger.info("Proxy listening on %s:%s", self.bind_host, port)

            while self.running:
                try:
                    client_socket, client_addr = server_socket.accept()
                    self.logger.info("Connection from %s:%s", client_addr[0], client_addr[1])

                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_addr),
                        daemon=True,
                    )
                    client_thread.start()

                except TimeoutError:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error("Proxy server error: %s", e, exc_info=True)

        finally:
            server_socket.close()
            self.logger.info("Proxy server stopped")
            logger.debug("Exiting _run_proxy")

    def _handle_client(self, client_socket: socket.socket, client_addr: tuple[str, int]) -> None:
        """Handle individual client connection.

        Args:
            client_socket: Client socket connection
            client_addr: Client address tuple (ip, port)

        """
        try:
            if initial_data := client_socket.recv(4096):
                self.handle_connection(client_socket, initial_data)
        except Exception as e:
            self.logger.error("Error handling client %s: %s", client_addr, e, exc_info=True)
        finally:
            client_socket.close()

    def handle_connection(self, socket: socket.socket, initial_data: bytes) -> None:
        """Handle a client connection with the specific protocol.

        Default implementation logs the request and sends back a generic response.
        Subclasses should override for protocol-specific handling.

        Args:
            socket: Client socket connection
            initial_data: Initial data received from the client

        """
        self.log_request(initial_data, "client")

        response = self.generate_response(initial_data)

        try:
            socket.send(response)
            self.log_response(response, "client")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to send response: %s", e, exc_info=True)

    def generate_response(self, request_data: bytes) -> bytes:
        """Generate a protocol-specific response.

        Default implementation returns a generic success response.
        Subclasses should override for protocol-specific response generation.

        Args:
            request_data: Raw request data from the client

        Returns:
            Protocol-specific response data

        """
        self.logger.debug("Generating generic response for %d bytes of data", len(request_data))
        return b"OK\n"

    def log_request(self, request_data: bytes, source: str = "unknown") -> None:
        """Log incoming request data for analysis.

        Args:
            request_data: Raw request data to log
            source: Source identifier for the request

        """
        self.logger.debug("Request from %s: %d bytes", source, len(request_data))

        # Log hex dump for debugging (limit to first 256 bytes)
        if self.logger.isEnabledFor(logging.DEBUG):
            hex_data = request_data[:256].hex()
            self.logger.debug("Request hex: %s", hex_data)

    def log_response(self, response_data: bytes, destination: str = "unknown") -> None:
        """Log outgoing response data for analysis.

        Args:
            response_data: Raw response data to log
            destination: Destination identifier for the response

        """
        self.logger.debug("Response to %s: %d bytes", destination, len(response_data))

        # Log hex dump for debugging (limit to first 256 bytes)
        if self.logger.isEnabledFor(logging.DEBUG):
            hex_data = response_data[:256].hex()
            self.logger.debug("Response hex: %s", hex_data)


class FlexLMProtocolHandler(LicenseProtocolHandler):
    """FlexLM license protocol handler implementation.

    Handles FlexNet (FlexLM) license server protocol communication
    for intercepting and emulating FlexLM license verification.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize FlexLM protocol handler."""
        super().__init__(config)
        self.flexlm_port = self.config.get("flexlm_port", 27000)
        self.captured_requests = []
        self.captured_responses = []
        self.session_data = {}
        self.client_connections = {}
        self.vendor_daemon_port = self.config.get("vendor_daemon_port", 27001)

        # Configure FlexLM response parameters
        self.flexlm_version = self.config.get("flexlm_version", "11.16.2")
        self.license_count = self.config.get("license_count", 9999)
        self.license_type = self.config.get("license_type", "permanent")
        self.feature_version = self.config.get("feature_version", "2.0")
        self.server_status = self.config.get("server_status", "UP")

    def clear_data(self) -> None:
        """Clear FlexLM-specific captured data."""
        super().clear_data()
        # Additional FlexLM-specific cleanup if needed
        self.logger.debug("Cleared FlexLM protocol data")

    def _run_proxy(self, port: int) -> None:
        """Run FlexLM proxy server.

        Args:
            port: Port to bind the proxy server to

        """
        import socket

        self.logger.info("FlexLM proxy started on port %s", port)

        # Create TCP socket for FlexLM protocol
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            # Use configured host (defaults to localhost for security)
            bind_host = self.config.get("bind_host", self.host)
            server_socket.bind((bind_host, port))
            server_socket.listen(5)
            server_socket.settimeout(1.0)  # 1 second timeout for checking self.running

            self.logger.info("FlexLM proxy listening on port %s", port)

            while self.running:
                try:
                    client_socket, client_addr = server_socket.accept()
                    self.logger.info("FlexLM connection from %s:%s", client_addr[0], client_addr[1])

                    # Handle client connection in a separate thread
                    client_thread = threading.Thread(
                        target=self._handle_flexlm_client,
                        args=(client_socket, client_addr),
                        daemon=True,
                    )
                    client_thread.start()

                except TimeoutError:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error("FlexLM proxy error: %s", e, exc_info=True)

        finally:
            server_socket.close()
            self.logger.info("FlexLM proxy stopped")

    def handle_connection(self, socket: socket.socket, initial_data: bytes) -> None:
        """Handle FlexLM client connection.

        Args:
            socket: Client socket
            initial_data: Initial request data

        """
        self.log_request(initial_data, "FlexLM client")

        # Generate FlexLM response
        response = self.generate_response(initial_data)

        try:
            socket.send(response)
            self.log_response(response, "FlexLM client")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to send FlexLM response: %s", e, exc_info=True)

    def _handle_flexlm_client(self, client_socket: socket.socket, client_addr: tuple[str, int]) -> None:
        """Handle individual FlexLM client connection.

        Args:
            client_socket: Client socket connection
            client_addr: Client address tuple (ip, port)

        """
        try:
            if initial_data := client_socket.recv(4096):
                self.handle_connection(client_socket, initial_data)
        except Exception as e:
            self.logger.error("Error handling FlexLM client %s: %s", client_addr, e, exc_info=True)
        finally:
            client_socket.close()

    def generate_response(self, request_data: bytes) -> bytes:
        """Generate FlexLM protocol response.

        Args:
            request_data: FlexLM request data

        Returns:
            FlexLM response data

        """
        import time

        # Store request for analysis
        self.captured_requests.append(
            {
                "timestamp": time.time(),
                "data": request_data,
                "hex": request_data.hex(),
            },
        )

        # Parse FlexLM request to determine type
        if len(request_data) < 4:
            return b"ERROR: Invalid request\n"

        # FlexLM uses a simple text-based protocol for many operations
        request_str = request_data.decode("utf-8", errors="ignore")

        # Check for common FlexLM commands
        if request_str.startswith("HELLO"):
            # Initial handshake - use configured vendor daemon port
            major, minor = self.flexlm_version.split(".")[:2]
            return f"HELLO {major} {minor} {self.vendor_daemon_port}\n".encode()

        if request_str.startswith("GETLIC"):
            # License checkout request
            # Format: GETLIC feature version user host display
            parts = request_str.split()
            if len(parts) >= 2:
                feature = parts[1]
                # Generate a success response with configurable license details
                import time

                expiry = "0" if self.license_type == "permanent" else str(int(time.time()) + 86400 * 365)
                response = f"GRANT {feature} {self.feature_version} {self.license_type} {expiry} 0 0 0 HOSTID=ANY\n"
                return response.encode("utf-8")
            return b"ERROR: Invalid GETLIC request\n"

        elif request_str.startswith("CHECKIN"):
            # License checkin
            return b"CHECKIN_OK\n"

        elif request_str.startswith("HEARTBEAT"):
            # Keepalive
            return b"HEARTBEAT_OK\n"

        elif "STATUS" in request_str:
            # Status query - use configured values
            response = "STATUS OK\n"
            response += f"SERVER {self.server_status}\n"
            response += f"LICENSES AVAILABLE: {self.license_count}\n"
            return response.encode("utf-8")

        else:
            # For unknown requests, send a generic success
            self.logger.debug("Unknown FlexLM request: %s", request_str[:100])
            return b"OK\n"


class HASPProtocolHandler(LicenseProtocolHandler):
    """HASP/Sentinel license protocol handler implementation.

    Handles HASP (Hardware Against Software Piracy) / Sentinel
    license verification protocol communication.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize HASP protocol handler."""
        super().__init__(config)
        self.hasp_port = self.config.get("hasp_port", 1947)
        self.captured_requests = []
        self.captured_responses = []
        self.session_data = {}
        self.client_connections = {}
        self._hasp_aes_key = None
        self._hasp_nonce = None

        # Configure HASP response parameters
        self.hasp_memory_size = self.config.get("hasp_memory_size", 0x20000)  # 128KB default
        self.hasp_version = self.config.get("hasp_version", "7.50")
        self.hasp_vendor_id = self.config.get("hasp_vendor_id", 0x1234)
        self.license_features = self.config.get(
            "license_features",
            [
                "PROFESSIONAL",
                "ENTERPRISE",
                "DEVELOPER",
                "RUNTIME",
            ],
        )
        self.hasp_emulator_version = self.config.get("hasp_emulator_version", "HASP_EMU_v2.1")

    def clear_data(self) -> None:
        """Clear HASP-specific captured data."""
        super().clear_data()
        # Additional HASP-specific cleanup if needed
        self.logger.debug("Cleared HASP protocol data")

    def _run_proxy(self, port: int) -> None:
        """Run HASP proxy server.

        Args:
            port: Port to bind the proxy server to

        """
        import socket

        self.logger.info("HASP proxy started on port %s", port)

        # HASP uses both TCP and UDP, but primarily TCP for license server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            # Use configured host (defaults to localhost for security)
            bind_host = self.config.get("bind_host", self.host)
            server_socket.bind((bind_host, port))
            server_socket.listen(5)
            server_socket.settimeout(1.0)

            self.logger.info("HASP proxy listening on port %s", port)

            while self.running:
                try:
                    client_socket, client_addr = server_socket.accept()
                    self.logger.info("HASP connection from %s:%s", client_addr[0], client_addr[1])

                    # Handle client connection in a separate thread
                    client_thread = threading.Thread(
                        target=self._handle_hasp_client,  # pylint: disable=no-member
                        args=(client_socket, client_addr),
                        daemon=True,
                    )
                    client_thread.start()

                except TimeoutError:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error("HASP proxy error: %s", e, exc_info=True)

        finally:
            server_socket.close()
            self.logger.info("HASP proxy stopped")

    def handle_connection(self, socket: socket.socket, initial_data: bytes) -> None:
        """Handle HASP client connection.

        Args:
            socket: Client socket
            initial_data: Initial request data

        """
        self.log_request(initial_data, "HASP client")

        response = self.generate_response(initial_data)

        try:
            socket.send(response)
            self.log_response(response, "HASP client")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to send HASP response: %s", e, exc_info=True)

    def _handle_hasp_client(self, client_socket: socket.socket, client_addr: tuple[str, int]) -> None:
        """Handle individual HASP client connection.

        Args:
            client_socket: Client socket connection
            client_addr: Client address tuple (ip, port)

        """
        try:
            if initial_data := client_socket.recv(4096):
                self.handle_connection(client_socket, initial_data)
        except Exception as e:
            self.logger.error("Error handling HASP client %s: %s", client_addr, e, exc_info=True)
        finally:
            client_socket.close()

    def generate_response(self, request_data: bytes) -> bytes:
        """Generate HASP protocol response.

        Args:
            request_data: HASP request data

        Returns:
            HASP response data

        """
        import struct
        import time

        # Store request for analysis
        self.captured_requests.append(
            {
                "timestamp": time.time(),
                "data": request_data,
                "hex": request_data.hex(),
            },
        )

        # HASP protocol uses binary format
        if len(request_data) < 8:
            return b"\x00\x00\x00\x00"  # Error response

        # Parse HASP packet header
        # Common HASP packet structure: [command_id(4), data_len(4), data(...)]
        try:
            command_id = struct.unpack("<I", request_data[:4])[0]

            # Handle common HASP commands
            if command_id == 0x01:  # HASP_LOGIN
                # Login response: success status + dynamic handle
                handle = secrets.randbelow(0x7FFFFFFF - 0x10000000 + 1) + 0x10000000  # Generate dynamic handle
                response = struct.pack("<II", 0x00000000, handle)  # Success + handle
                # Store handle for this session
                self.session_data["handle"] = handle
                return response

            if command_id == 0x02:  # HASP_LOGOUT
                # Logout response: success
                return struct.pack("<I", 0x00000000)

            if command_id == 0x03:  # HASP_ENCRYPT
                # Encryption response: return encrypted data using AES-CTR
                if len(request_data) > 8:
                    data_to_encrypt = request_data[8:]
                    try:
                        # Use proper encryption (AES-CTR mode for HASP emulation)
                        import os

                        from intellicrack.handlers.cryptography_handler import Cipher, algorithms, default_backend, modes

                        # Generate or use stored key/nonce for this session
                        if self._hasp_aes_key is None:
                            self._hasp_aes_key = os.urandom(32)  # AES-256
                            self._hasp_nonce = os.urandom(16)

                        # Encrypt data
                        cipher = Cipher(
                            algorithms.AES(self._hasp_aes_key),
                            modes.CTR(self._hasp_nonce),
                            backend=default_backend(),
                        )
                        encryptor = cipher.encryptor()
                        encrypted = encryptor.update(data_to_encrypt) + encryptor.finalize()

                        return struct.pack("<I", 0x00000000) + encrypted
                    except ImportError:
                        # Fallback to XOR if cryptography not available, but warn
                        self.logger.warning("cryptography library not available - using weak XOR encryption")
                        encrypted = bytes(b ^ 0xAA for b in data_to_encrypt)
                        return struct.pack("<I", 0x00000000) + encrypted
                return struct.pack("<I", 0x00000000)

            if command_id == 0x04:  # HASP_DECRYPT
                # Decryption response: return decrypted data using AES-CTR
                if len(request_data) > 8:
                    data_to_decrypt = request_data[8:]
                    try:
                        # Use proper decryption (AES-CTR mode for HASP emulation)
                        from intellicrack.handlers.cryptography_handler import Cipher, algorithms, default_backend, modes

                        # Use stored key/nonce from encryption
                        if self._hasp_aes_key is not None:
                            cipher = Cipher(
                                algorithms.AES(self._hasp_aes_key),
                                modes.CTR(self._hasp_nonce),
                                backend=default_backend(),
                            )
                            decryptor = cipher.decryptor()
                            decrypted = decryptor.update(data_to_decrypt) + decryptor.finalize()
                        else:
                            # No key established yet
                            self.logger.error("No encryption key established for decryption")
                            decrypted = data_to_decrypt

                        return struct.pack("<I", 0x00000000) + decrypted
                    except ImportError:
                        # Fallback to XOR if cryptography not available
                        self.logger.warning("cryptography library not available - using weak XOR decryption")
                        decrypted = bytes(b ^ 0xAA for b in data_to_decrypt)
                        return struct.pack("<I", 0x00000000) + decrypted
                return struct.pack("<I", 0x00000000)

            if command_id == 0x05:  # HASP_GET_SIZE
                # Return size of available memory from configuration
                return struct.pack("<II", 0x00000000, self.hasp_memory_size)  # Success + configured size

            if command_id == 0x06:  # HASP_READ
                # Read memory response
                # Parse read request to get offset and size
                try:
                    if len(request_data) >= 16:
                        offset = struct.unpack("<I", request_data[8:12])[0]
                        size = struct.unpack("<I", request_data[12:16])[0]
                        # Limit size to prevent memory issues
                        size = min(size, 4096)
                    else:
                        offset = 0
                        size = 64

                    # Generate realistic license data based on offset
                    if offset < 16:
                        # License header area - return dynamic license signature
                        version_bytes = self.hasp_version.replace(".", "_").encode("utf-8")
                        license_sig = b"HASP_LIC_" + version_bytes + b"\x00"
                        license_data = license_sig.ljust(size, b"\x00")
                    elif offset < 256:
                        # License info area - return configured feature data
                        feature_bytes = b""
                        for feature in self.license_features:
                            feature_bytes += feature.encode("utf-8") + b"\x00"
                        # Pad to requested size
                        feature_data = feature_bytes + b"\x00" * max(0, size - len(feature_bytes))
                        license_data = feature_data[:size]
                    else:
                        # Data area - return mixed content
                        license_data = bytes((i + offset) % 256 for i in range(size))

                    return struct.pack("<I", 0x00000000) + license_data
                except struct.error as e:
                    self.logger.error("struct.error in license_protocol_handler: %s", e, exc_info=True)
                    return struct.pack("<I", 0x00000001)

            elif command_id == 0x07:  # HASP_WRITE
                # Write memory response: success
                return struct.pack("<I", 0x00000000)

            elif command_id == 0x08:  # HASP_GET_RTC
                # Get real-time clock
                current_time = int(time.time())
                return struct.pack("<II", 0x00000000, current_time)

            elif command_id == 0x09:  # HASP_GET_INFO
                # Get HASP info - use configured emulator version
                info = self.hasp_emulator_version.encode("utf-8") + b"\x00"
                return struct.pack("<I", 0x00000000) + info

            else:
                # Unknown command - return generic success
                self.logger.debug("Unknown HASP command: 0x%08X", command_id)
                return struct.pack("<I", 0x00000000)

        except struct.error as e:
            self.logger.error("struct.error in license_protocol_handler: %s", e, exc_info=True)
            return b"\xff\xff\xff\xff"


# Export main classes
__all__ = ["FlexLMProtocolHandler", "HASPProtocolHandler", "LicenseProtocolHandler"]
