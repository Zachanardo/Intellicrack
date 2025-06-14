"""
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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

#!/usr/bin/env python3
"""
License Protocol Handler Base Class.

This module provides a base class for implementing protocol-specific handlers
for various license verification protocols including FlexLM, HASP, Adobe, and others.
"""

import logging
import threading
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class LicenseProtocolHandler(ABC):
    """
    Base class for license protocol handlers.

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

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the base LicenseProtocolHandler.

        Sets up the running state, proxy thread, and logger for protocol handling.

        Args:
            config: Optional configuration dictionary for the protocol handler
        """
        self.config = config or {}
        self.running = False
        self.proxy_thread: Optional[threading.Thread] = None
        self.logger = logging.getLogger(__name__)

        # Initialize protocol-specific configuration
        self.port = self.config.get('port', 8080)
        self.host = self.config.get('host', 'localhost')  # Default to localhost for security
        self.bind_host = self.config.get('bind_host', self.host)  # Allow separate bind host
        self.timeout = self.config.get('timeout', 30)

        self.logger.info("Initialized %s protocol handler", self.__class__.__name__)

    def clear_data(self) -> None:
        """
        Clear any captured data.

        This method clears captured requests, responses, and any cached information.
        Subclasses should override this to clear protocol-specific data structures.
        """
        self.logger.debug("Clearing protocol handler data")

        # Clear any base-level captured data
        if hasattr(self, 'captured_requests'):
            self.captured_requests.clear()
            self.logger.debug("Cleared %d captured requests", len(self.captured_requests))

        if hasattr(self, 'captured_responses'):
            self.captured_responses.clear()
            self.logger.debug("Cleared captured responses")

        if hasattr(self, 'session_data'):
            self.session_data.clear()
            self.logger.debug("Cleared session data")

        if hasattr(self, 'client_connections'):
            self.client_connections.clear()
            self.logger.debug("Cleared client connections tracking")

    def start_proxy(self, port: int = 8080) -> bool:
        """
        Start the proxy server for intercepting license requests.

        Args:
            port: Port number to bind the proxy server to

        Returns:
            True if proxy started successfully, False if already running
        """
        if self.running:
            self.logger.warning("Proxy server is already running")
            return False

        # Clear previous captured requests on start
        self.clear_data()

        self.running = True
        self.port = port

        # Start proxy in a separate daemon thread
        self.proxy_thread = threading.Thread(
            target=self._run_proxy,
            args=(port,),
            daemon=True,
            name=f"{self.__class__.__name__}Proxy"
        )
        self.proxy_thread.start()

        self.logger.info("Started %s proxy on port %s", self.__class__.__name__, port)
        return True

    def stop_proxy(self) -> bool:
        """
        Stop the proxy server.

        Returns:
            True if proxy stopped successfully, False if not running
        """
        if not self.running:
            self.logger.warning("Proxy server is not running")
            return False

        self.running = False

        if self.proxy_thread and self.proxy_thread.is_alive():
            # Wait for thread to complete
            self.proxy_thread.join(timeout=5.0)
            if self.proxy_thread.is_alive():
                self.logger.warning("Proxy thread did not terminate gracefully")

        self.logger.info("Stopped %s proxy", self.__class__.__name__)
        return True

    def shutdown(self) -> None:
        """
        Shutdown the protocol handler completely.
        
        This method stops the proxy server and cleans up all resources.
        """
        self.logger.info("Shutting down %s protocol handler", self.__class__.__name__)

        # Stop the proxy server
        if self.running:
            self.stop_proxy()

        # Clear all data
        self.clear_data()

        # Reset state
        self.running = False
        self.proxy_thread = None

        self.logger.info("Protocol handler shutdown complete")

    def is_running(self) -> bool:
        """
        Check if the proxy server is currently running.

        Returns:
            True if proxy is running, False otherwise
        """
        return self.running

    def get_status(self) -> Dict[str, Any]:
        """
        Get current status of the protocol handler.

        Returns:
            Dictionary containing handler status information
        """
        return {
            "protocol": self.__class__.__name__,
            "running": self.running,
            "port": self.port,
            "host": self.host,
            "thread_active": self.proxy_thread.is_alive() if self.proxy_thread else False
        }

    @abstractmethod
    def _run_proxy(self, port: int) -> None:
        """
        Run the proxy server - must be implemented by subclasses.

        This method contains the main proxy server loop and should handle
        incoming connections according to the specific protocol requirements.

        Args:
            port: Port number to bind the proxy server to
        """
        raise NotImplementedError("Subclasses must implement _run_proxy")

    @abstractmethod
    def handle_connection(self, socket: Any, initial_data: bytes) -> None:
        """
        Handle a client connection with the specific protocol.

        This method should process incoming connections and implement
        protocol-specific communication handling.

        Args:
            socket: Client socket connection
            initial_data: Initial data received from the client
        """
        raise NotImplementedError("Subclasses must implement handle_connection")

    @abstractmethod
    def generate_response(self, request_data: bytes) -> bytes:
        """
        Generate a protocol-specific response.

        This method should analyze the request data and generate an appropriate
        response according to the specific license protocol requirements.

        Args:
            request_data: Raw request data from the client

        Returns:
            Protocol-specific response data
        """
        raise NotImplementedError("Subclasses must implement generate_response")

    def log_request(self, request_data: bytes, source: str = "unknown") -> None:
        """
        Log incoming request data for analysis.

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
        """
        Log outgoing response data for analysis.

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
    """
    FlexLM license protocol handler implementation.

    Handles FlexNet (FlexLM) license server protocol communication
    for intercepting and emulating FlexLM license verification.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize FlexLM protocol handler."""
        super().__init__(config)
        self.flexlm_port = self.config.get('flexlm_port', 27000)
        self.captured_requests = []
        self.captured_responses = []
        self.session_data = {}
        self.client_connections = {}
        self.vendor_daemon_port = self.config.get('vendor_daemon_port', 27001)

    def clear_data(self) -> None:
        """Clear FlexLM-specific captured data."""
        super().clear_data()
        # Additional FlexLM-specific cleanup if needed
        self.logger.debug("Cleared FlexLM protocol data")

    def _run_proxy(self, port: int) -> None:
        """
        Run FlexLM proxy server.

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
            bind_host = self.config.get('bind_host', self.host)
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
                        daemon=True
                    )
                    client_thread.start()

                except socket.timeout:
                    continue  # Check self.running and continue
                except Exception as e:
                    if self.running:
                        self.logger.error("FlexLM proxy error: %s", e)

        finally:
            server_socket.close()
            self.logger.info("FlexLM proxy stopped")

    def handle_connection(self, socket: Any, initial_data: bytes) -> None:
        """
        Handle FlexLM client connection.

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
            self.logger.error("Failed to send FlexLM response: %s", e)

    def _handle_flexlm_client(self, client_socket, client_addr):
        """
        Handle individual FlexLM client connection.
        
        Args:
            client_socket: Client socket connection
            client_addr: Client address tuple (ip, port)
        """
        try:
            # Receive initial data
            initial_data = client_socket.recv(4096)
            if initial_data:
                self.handle_connection(client_socket, initial_data)
        except Exception as e:
            self.logger.error("Error handling FlexLM client %s: %s", client_addr, e)
        finally:
            client_socket.close()

    def generate_response(self, request_data: bytes) -> bytes:
        """
        Generate FlexLM protocol response.

        Args:
            request_data: FlexLM request data

        Returns:
            FlexLM response data
        """
        import time

        # Store request for analysis
        self.captured_requests.append({
            'timestamp': time.time(),
            'data': request_data,
            'hex': request_data.hex()
        })

        # Parse FlexLM request to determine type
        if len(request_data) < 4:
            return b"ERROR: Invalid request\n"

        # FlexLM uses a simple text-based protocol for many operations
        request_str = request_data.decode('utf-8', errors='ignore')

        # Check for common FlexLM commands
        if request_str.startswith('HELLO'):
            # Initial handshake
            return b"HELLO 1 1 27001\n"  # version 1.1, vendor daemon on port 27001

        elif request_str.startswith('GETLIC'):
            # License checkout request
            # Format: GETLIC feature version user host display
            parts = request_str.split()
            if len(parts) >= 2:
                feature = parts[1]
                # Generate a success response with license details
                response = f"GRANT {feature} 1.0 permanent 0 0 0 0 HOSTID=ANY\n"
                return response.encode('utf-8')

        elif request_str.startswith('CHECKIN'):
            # License checkin
            return b"CHECKIN_OK\n"

        elif request_str.startswith('HEARTBEAT'):
            # Keepalive
            return b"HEARTBEAT_OK\n"

        elif 'STATUS' in request_str:
            # Status query
            response = "STATUS OK\n"
            response += "SERVER UP\n"
            response += "LICENSES AVAILABLE: 999\n"
            return response.encode('utf-8')

        else:
            # For unknown requests, send a generic success
            self.logger.debug("Unknown FlexLM request: %s", request_str[:100])
            return b"OK\n"


class HASPProtocolHandler(LicenseProtocolHandler):
    """
    HASP/Sentinel license protocol handler implementation.

    Handles HASP (Hardware Against Software Piracy) / Sentinel
    license verification protocol communication.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize HASP protocol handler."""
        super().__init__(config)
        self.hasp_port = self.config.get('hasp_port', 1947)
        self.captured_requests = []
        self.captured_responses = []
        self.session_data = {}
        self.client_connections = {}

    def clear_data(self) -> None:
        """Clear HASP-specific captured data."""
        super().clear_data()
        # Additional HASP-specific cleanup if needed
        self.logger.debug("Cleared HASP protocol data")

    def _run_proxy(self, port: int) -> None:
        """
        Run HASP proxy server.

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
            bind_host = self.config.get('bind_host', self.host)
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
                        daemon=True
                    )
                    client_thread.start()

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error("HASP proxy error: %s", e)

        finally:
            server_socket.close()
            self.logger.info("HASP proxy stopped")

    def handle_connection(self, socket: Any, initial_data: bytes) -> None:
        """
        Handle HASP client connection.

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
            self.logger.error("Failed to send HASP response: %s", e)

    def _handle_hasp_client(self, client_socket, client_addr):
        """
        Handle individual HASP client connection.
        
        Args:
            client_socket: Client socket connection
            client_addr: Client address tuple (ip, port)
        """
        try:
            # Receive initial data
            initial_data = client_socket.recv(4096)
            if initial_data:
                self.handle_connection(client_socket, initial_data)
        except Exception as e:
            self.logger.error("Error handling HASP client %s: %s", client_addr, e)
        finally:
            client_socket.close()

    def generate_response(self, request_data: bytes) -> bytes:
        """
        Generate HASP protocol response.

        Args:
            request_data: HASP request data

        Returns:
            HASP response data
        """
        import struct
        import time

        # Store request for analysis
        self.captured_requests.append({
            'timestamp': time.time(),
            'data': request_data,
            'hex': request_data.hex()
        })

        # HASP protocol uses binary format
        if len(request_data) < 8:
            return b"\x00\x00\x00\x00"  # Error response

        # Parse HASP packet header
        # Common HASP packet structure: [command_id(4), data_len(4), data(...)]
        try:
            command_id = struct.unpack('<I', request_data[:4])[0]

            # Handle common HASP commands
            if command_id == 0x01:  # HASP_LOGIN
                # Login response: success status + handle
                response = struct.pack('<II', 0x00000000, 0x12345678)  # Success + handle
                return response

            elif command_id == 0x02:  # HASP_LOGOUT
                # Logout response: success
                return struct.pack('<I', 0x00000000)

            elif command_id == 0x03:  # HASP_ENCRYPT
                # Encryption response: return encrypted data using AES-CTR
                if len(request_data) > 8:
                    data_to_encrypt = request_data[8:]
                    try:
                        # Use proper encryption (AES-CTR mode for HASP emulation)
                        import os

                        from cryptography.hazmat.backends import default_backend
                        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

                        # Generate or use stored key/nonce for this session
                        if not hasattr(self, '_hasp_aes_key'):
                            self._hasp_aes_key = os.urandom(32)  # AES-256
                            self._hasp_nonce = os.urandom(16)

                        # Encrypt data
                        cipher = Cipher(
                            algorithms.AES(self._hasp_aes_key),
                            modes.CTR(self._hasp_nonce),
                            backend=default_backend()
                        )
                        encryptor = cipher.encryptor()
                        encrypted = encryptor.update(data_to_encrypt) + encryptor.finalize()

                        return struct.pack('<I', 0x00000000) + encrypted
                    except ImportError:
                        # Fallback to XOR if cryptography not available, but warn
                        logger.warning("cryptography library not available - using weak XOR encryption")
                        encrypted = bytes(b ^ 0xAA for b in data_to_encrypt)
                        return struct.pack('<I', 0x00000000) + encrypted
                return struct.pack('<I', 0x00000000)

            elif command_id == 0x04:  # HASP_DECRYPT
                # Decryption response: return decrypted data using AES-CTR
                if len(request_data) > 8:
                    data_to_decrypt = request_data[8:]
                    try:
                        # Use proper decryption (AES-CTR mode for HASP emulation)
                        from cryptography.hazmat.backends import default_backend
                        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

                        # Use stored key/nonce from encryption
                        if hasattr(self, '_hasp_aes_key'):
                            cipher = Cipher(
                                algorithms.AES(self._hasp_aes_key),
                                modes.CTR(self._hasp_nonce),
                                backend=default_backend()
                            )
                            decryptor = cipher.decryptor()
                            decrypted = decryptor.update(data_to_decrypt) + decryptor.finalize()
                        else:
                            # No key established yet
                            logger.error("No encryption key established for decryption")
                            decrypted = data_to_decrypt

                        return struct.pack('<I', 0x00000000) + decrypted
                    except ImportError:
                        # Fallback to XOR if cryptography not available
                        logger.warning("cryptography library not available - using weak XOR decryption")
                        decrypted = bytes(b ^ 0xAA for b in data_to_decrypt)
                        return struct.pack('<I', 0x00000000) + decrypted
                return struct.pack('<I', 0x00000000)

            elif command_id == 0x05:  # HASP_GET_SIZE
                # Return size of available memory
                return struct.pack('<II', 0x00000000, 0x10000)  # Success + 64KB

            elif command_id == 0x06:  # HASP_READ
                # Read memory response
                # Parse read request to get offset and size
                try:
                    if len(request_data) >= 16:
                        offset = struct.unpack('<I', request_data[8:12])[0]
                        size = struct.unpack('<I', request_data[12:16])[0]
                        # Limit size to prevent memory issues
                        size = min(size, 4096)
                    else:
                        offset = 0
                        size = 64

                    # Generate realistic license data based on offset
                    if offset < 16:
                        # License header area - return license signature
                        license_data = b"HASP_LICENSE_V2\x00" + b"\x00" * (size - 16)
                    elif offset < 256:
                        # License info area - return feature data
                        feature_data = b"FEATURE_1\x00FEATURE_2\x00FEATURE_3\x00" + b"\x00" * (size - 30)
                        license_data = feature_data[:size]
                    else:
                        # Data area - return mixed content
                        license_data = bytes((i + offset) % 256 for i in range(size))

                    return struct.pack('<I', 0x00000000) + license_data
                except struct.error:
                    # Fallback for malformed requests
                    return struct.pack('<I', 0x00000001)  # Error status

            elif command_id == 0x07:  # HASP_WRITE
                # Write memory response: success
                return struct.pack('<I', 0x00000000)

            elif command_id == 0x08:  # HASP_GET_RTC
                # Get real-time clock
                current_time = int(time.time())
                return struct.pack('<II', 0x00000000, current_time)

            elif command_id == 0x09:  # HASP_GET_INFO
                # Get HASP info
                info = b"HASP_EMU_v1.0\x00"
                return struct.pack('<I', 0x00000000) + info

            else:
                # Unknown command - return generic success
                self.logger.debug("Unknown HASP command: 0x%08X", command_id)
                return struct.pack('<I', 0x00000000)

        except struct.error:
            # Malformed packet
            return b"\xFF\xFF\xFF\xFF"  # Error response


# Export main classes
__all__ = ['LicenseProtocolHandler', 'FlexLMProtocolHandler', 'HASPProtocolHandler']
