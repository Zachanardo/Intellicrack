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
        self.host = self.config.get('host', 'localhost')
        self.timeout = self.config.get('timeout', 30)

        self.logger.info(f"Initialized {self.__class__.__name__} protocol handler")

    def clear_data(self) -> None:
        """
        Clear any captured data.

        This method should be overridden by subclasses to clear protocol-specific
        captured data such as requests, responses, or cached information.
        """
        self.logger.debug("Clearing protocol handler data")
        pass

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

        self.logger.info(f"Started {self.__class__.__name__} proxy on port {port}")
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

        self.logger.info(f"Stopped {self.__class__.__name__} proxy")
        return True

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
        self.logger.debug(f"Request from {source}: {len(request_data)} bytes")

        # Log hex dump for debugging (limit to first 256 bytes)
        if self.logger.isEnabledFor(logging.DEBUG):
            hex_data = request_data[:256].hex()
            self.logger.debug(f"Request hex: {hex_data}")

    def log_response(self, response_data: bytes, destination: str = "unknown") -> None:
        """
        Log outgoing response data for analysis.

        Args:
            response_data: Raw response data to log
            destination: Destination identifier for the response
        """
        self.logger.debug(f"Response to {destination}: {len(response_data)} bytes")

        # Log hex dump for debugging (limit to first 256 bytes)
        if self.logger.isEnabledFor(logging.DEBUG):
            hex_data = response_data[:256].hex()
            self.logger.debug(f"Response hex: {hex_data}")


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

    def _run_proxy(self, port: int) -> None:
        """
        Run FlexLM proxy server.

        Args:
            port: Port to bind the proxy server to
        """
        # FlexLM-specific proxy implementation would go here
        self.logger.info(f"FlexLM proxy started on port {port}")

        # Placeholder implementation
        while self.running:
            threading.Event().wait(1.0)  # Simple wait loop

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
        except Exception as e:
            self.logger.error(f"Failed to send FlexLM response: {e}")

    def generate_response(self, request_data: bytes) -> bytes:
        """
        Generate FlexLM protocol response.

        Args:
            request_data: FlexLM request data

        Returns:
            FlexLM response data
        """
        # Placeholder FlexLM response generation
        # In a real implementation, this would parse the FlexLM request
        # and generate an appropriate license grant response
        return b"FLEXLM_SUCCESS\n"


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

    def _run_proxy(self, port: int) -> None:
        """
        Run HASP proxy server.

        Args:
            port: Port to bind the proxy server to
        """
        self.logger.info(f"HASP proxy started on port {port}")

        # Placeholder implementation
        while self.running:
            threading.Event().wait(1.0)  # Simple wait loop

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
        except Exception as e:
            self.logger.error(f"Failed to send HASP response: {e}")

    def generate_response(self, request_data: bytes) -> bytes:
        """
        Generate HASP protocol response.

        Args:
            request_data: HASP request data

        Returns:
            HASP response data
        """
        # Placeholder HASP response generation
        return b"HASP_SUCCESS\x00"


# Export main classes
__all__ = ['LicenseProtocolHandler', 'FlexLMProtocolHandler', 'HASPProtocolHandler']
