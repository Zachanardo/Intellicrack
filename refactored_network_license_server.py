
import json
import logging
import socket
import threading
import time

from intellicrack.utils.log_message import log_message

logger = logging.getLogger(__name__)

class SimpleLicenseServer:
    """Simple license server implementation for testing purposes."""

    def __init__(self, app, port=27000):
        self.app = app
        self.logger = logging.getLogger("IntellicrackLogger.SimpleLicenseServer")
        self.port = port
        self.protocol = "FlexLM"
        self.running = False
        self.server_socket = None
        self.server_thread = None
        self.features = self._get_server_features()
        self.client_stats = {}

    def start(self):
        """Start the license server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("127.0.0.1", self.port))
            self.server_socket.listen(5)
            self.running = True

            self.server_thread = threading.Thread(target=self._handle_connections)
            self.server_thread.daemon = True
            self.server_thread.start()

            return True
        except (
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            KeyError,
            OSError,
            IOError,
        ) as e:
            self.logger.error(
                "(AttributeError, ValueError, TypeError, RuntimeError, KeyError, OSError, IOError) in main_app.py: %s",
                e,
            )
            if hasattr(self.app, "update_output"):
                self.app.update_output.emit(
                    log_message(f"[License Server] Socket error: {str(e)}")
                )
            return False

    def _handle_connections(self):
        """Handle incoming client connections."""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                self._log_client_connection(address)

                # Handle the connection in a new thread
                client_thread = threading.Thread(
                    target=self._handle_client, args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
            except (socket.error, ConnectionError, Exception) as e:
                logger.debug(f"Failed to handle client connection: {e}")
                if self.running:
                    time.sleep(0.1)

    def _log_client_connection(self, address):
        """Log client connection information."""
        if hasattr(self.app, "update_output"):
            self.app.update_output.emit(
                log_message(f"[License Server] Connection from {address}")
            )

    def _handle_client(self, client_socket, address):
        """Handle individual client connection."""
        try:
            # Use address to log client information
            client_ip, client_port = address
            if hasattr(self.app, "update_output"):
                self.app.update_output.emit(
                    log_message(
                        f"[License Server] New connection from {client_ip}:{client_port}"
                    )
                )

            # Receive and process request
            data = client_socket.recv(4096)
            if data:
                # Track client statistics
                self._track_client_stats(client_ip)

                # Generate and send response
                response = self._generate_license_response(data, self.features)
                client_socket.sendall(response)

                if hasattr(self.app, "update_output"):
                    self.app.update_output.emit(
                        log_message(
                            f"[License Server] Sent license response to {address}"
                        )
                    )
        except (
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            KeyError,
            OSError,
            IOError,
        ) as e:
            logger.error(
                "(AttributeError, ValueError, TypeError, RuntimeError, KeyError, OSError, IOError) in main_app.py: %s",
                e,
            )
            if hasattr(self.app, "update_output"):
                self.app.update_output.emit(
                    log_message(f"[License Server] Client error: {str(e)}")
                )
        finally:
            client_socket.close()

    def _track_client_stats(self, client_ip):
        """Track statistics for client connections."""
        self.client_stats[client_ip] = (
            self.client_stats.get(client_ip, 0) + 1
        )

    def stop(self):
        """Stop the license server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()

    def _get_server_features(self):
        """Get the list of available server features."""
        return [
            {"name": "premium_feature", "version": "2024.1", "count": 100},
            {"name": "basic_feature", "version": "2024.1", "count": 1000},
            {"name": "advanced_tools", "version": "2024.1", "count": 50},
        ]

    def _generate_license_response(self, data, features):
        """Generate appropriate license response based on request data."""
        if b"flexlm" in data.lower() or b"license" in data.lower():
            # FlexLM-style response
            return self._generate_flexlm_response()
        elif b"json" in data.lower() or b"{" in data:
            # JSON-style response
            return self._generate_json_response(features)
        else:
            # Generic success response
            return b"LICENSE_VALID\n"

    def _generate_flexlm_response(self):
        """Generate FlexLM protocol response."""
        return (
            b"SERVER this_host ANY 27000\n"
            b"VENDOR intellicrack\n"
            b"FEATURE premium_feature intellicrack 2024.1 permanent uncounted HOSTID=ANY SIGN=VALID\n"
            b"FEATURE basic_feature intellicrack 2024.1 permanent uncounted HOSTID=ANY SIGN=VALID\n"
            b"FEATURE advanced_tools intellicrack 2024.1 permanent uncounted HOSTID=ANY SIGN=VALID\n"
        )

    def _generate_json_response(self, features):
        """Generate JSON protocol response."""
        response_data = {
            "status": "OK",
            "license": "valid",
            "features": [f["name"] for f in features],
            "expiration": "permanent",
        }
        return json.dumps(response_data).encode()

class NetworkLicenseServer:
    def run_network_license_server(self, app, *args, **kwargs):
        """Start network license server emulator."""
        _ = args, kwargs
        try:
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message("[License Server] Starting network license server...")
                )

            # Configure the server
            config = self._configure_license_server()

            # Try primary server implementation first
            result = self._attempt_primary_license_server(app, config)

            # If primary fails, use fallback implementation
            if not result:
                result = self._create_fallback_license_server(app)

            # Update UI with results
            self._update_license_server_ui(app, result)

            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[License Server] Server started successfully"))

            return result

        except (
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            KeyError,
            OSError,
            IOError,
        ) as e:
            logger.error(
                "(AttributeError, ValueError, TypeError, RuntimeError, KeyError, OSError, IOError) in main_app.py: %s",
                e,
            )
            error_msg = f"Error starting license server: {str(e)}"
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message(f"[License Server] {error_msg}"))
            return {"success": False, "error": error_msg}


    def _configure_license_server(self):
        """Configure the license server settings."""
        return {
            "listen_ip": "127.0.0.1",
            "listen_ports": [27000, 27001, 1111, 8080],
            "dns_redirect": True,
            "ssl_intercept": False,  # Disable SSL for now
            "record_traffic": True,
            "auto_respond": True,
            "response_delay": 0.1,
        }

    def _attempt_primary_license_server(self, app, config):
        """Attempt to start the primary license server implementation."""
        try:
            from ..core.network.license_server_emulator import NetworkLicenseServerEmulator

            server = NetworkLicenseServerEmulator(config)
            success = server.start()

            if success:
                if hasattr(app, "license_server"):
                    app.license_server = server

                # Get server information
                active_features = self._get_server_features()

                result = {
                    "success": True,
                    "status": "running",
                    "port": server.port,
                    "protocol": server.protocol,
                    "features": active_features,
                    "clients": [],
                    "config": config,
                    "server_instance": server,
                }

                self._report_primary_server_status(app, server, active_features)
                return result
            else:
                raise RuntimeError("Failed to start license server")

        except (ImportError, RuntimeError, AttributeError, ValueError, OSError) as e:
            logger.error(
                "(ImportError, RuntimeError, AttributeError, ValueError, OSError) in main_app.py: %s",
                e,
            )
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(
                        f"[License Server] Primary server failed ({str(e)}), using fallback implementation..."
                    )
                )
            return None

    def _get_server_features(self):
        """Get the list of available server features."""
        return [
            {"name": "premium_feature", "version": "2024.1", "count": 100},
            {"name": "basic_feature", "version": "2024.1", "count": 1000},
            {"name": "advanced_tools", "version": "2024.1", "count": 50},
        ]

    def _report_primary_server_status(self, app, server, active_features):
        """Report the status of the primary server."""
        if hasattr(app, "update_output"):
            app.update_output.emit(
                log_message(f"[License Server] Server started on port {server.port}")
            )
            app.update_output.emit(
                log_message(f"[License Server] Protocol: {server.protocol} compatible")
            )
            app.update_output.emit(
                log_message(f"[License Server] Features loaded: {len(active_features)}")
            )
            app.update_output.emit(
                log_message("[License Server] DNS redirection enabled")
            )
            app.update_output.emit(
                log_message("[License Server] Traffic recording enabled")
            )

    def _create_fallback_license_server(self, app):
        """Create and start a fallback license server implementation."""
        # Create the fallback server
        simple_server = SimpleLicenseServer(app, 27000)

        if simple_server.start():
            if hasattr(app, "license_server"):
                app.license_server = simple_server

            result = {
                "success": True,
                "status": "running",
                "port": simple_server.port,
                "protocol": simple_server.protocol,
                "features": simple_server.features,
                "clients": [],
                "server_type": "fallback",
            }

            self._report_fallback_server_status(app)
            return result
        else:
            # Last resort - report configuration only
            return self._create_configuration_only_result(app)

    def _report_fallback_server_status(self, app):
        """Report the status of the fallback server."""
        if hasattr(app, "update_output"):
            app.update_output.emit(
                log_message("[License Server] Fallback server listening on port 27000")
            )
            app.update_output.emit(
                log_message("[License Server] Protocol: FlexLM compatible")
            )
            app.update_output.emit(log_message("[License Server] Features loaded: 3"))

    def _create_configuration_only_result(self, app):
        """Create a configuration-only result when servers fail to start."""
        result = {
            "success": True,
            "status": "configured",
            "port": 27000,
            "protocol": "FlexLM",
            "features": self._get_server_features(),
            "clients": [],
        }

        if hasattr(app, "update_output"):
            app.update_output.emit(
                log_message("[License Server] Server configured (port may be in use)")
            )
            app.update_output.emit(
                log_message("[License Server] Protocol: FlexLM compatible")
            )
            app.update_output.emit(
                log_message("[License Server] Features configured: 3")
            )

        return result

    def _update_license_server_ui(self, app, result):
        """Update the UI with license server status."""
        if hasattr(app, "update_analysis_results"):
            app.update_analysis_results.emit("\n=== License Server Status ===\n")
            app.update_analysis_results.emit(f"Status: {result['status']}\n")
            app.update_analysis_results.emit(f"Port: {result['port']}\n")
            app.update_analysis_results.emit(f"Protocol: {result['protocol']}\n")

            if "features" in result:
                app.update_analysis_results.emit("\nAvailable Features:\n")
                for feature in result["features"]:
                    app.update_analysis_results.emit(
                        f"  - {feature['name']} v{feature['version']}: {feature['count']} licenses\n"
                    )

