"""SSL traffic interceptor for analyzing and modifying encrypted communications."""

import logging
import os
import subprocess
import tempfile
import traceback
from typing import Any

from intellicrack.utils.logger import logger

from ...utils.resource_helper import get_resource_path

"""
SSL/TLS Interception System for Encrypted License Verification

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


# Optional cryptography dependencies - graceful fallback if not available
try:
    import importlib.util

    CRYPTOGRAPHY_AVAILABLE = importlib.util.find_spec("cryptography") is not None
except ImportError as e:
    logger.error("Import error in ssl_interceptor: %s", e)
    CRYPTOGRAPHY_AVAILABLE = False


class SSLTLSInterceptor:
    """SSL/TLS interception system for encrypted license verification.

    This system allows Intellicrack to intercept, analyze, and modify encrypted
    communications between applications and license servers, enabling bypass of
    secure license verification mechanisms.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize the SSL/TLS interceptor.

        Args:
            config: Configuration dictionary (optional)

        """
        self.logger = logging.getLogger(__name__)

        # Default configuration
        from ...utils.system.windows_structures import COMMON_LICENSE_DOMAINS

        self.config = {
            "listen_ip": "127.0.0.1",
            "listen_port": 8443,
            "target_hosts": COMMON_LICENSE_DOMAINS,
            "ca_cert_path": get_resource_path("ssl_certificates/ca.crt"),
            "ca_key_path": get_resource_path("ssl_certificates/ca.key"),
            "record_traffic": True,
            "auto_respond": True,
        }

        # Update with provided configuration
        if config:
            self.config.update(config)

        # Initialize components
        self.proxy_server = None
        self.ca_cert = None
        self.ca_key = None
        self.traffic_log = []
        self.proxy_process = None

    def generate_ca_certificate(self) -> tuple[bytes | None, bytes | None]:
        """Generate a CA certificate for SSL/TLS interception.

        Returns:
            tuple: (certificate, key) as PEM bytes, or (None, None) if failed

        """
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.error("cryptography library not available - cannot generate CA certificate")
            return None, None

        try:
            from ...utils.protection.certificate_utils import generate_self_signed_cert

            cert_result = generate_self_signed_cert(
                common_name="Intellicrack Root CA",
                organization="Intellicrack CA",
                state="California",
                locality="San Francisco",
                valid_days=3650,
            )

            if cert_result:
                return cert_result
            self.logger.error("Failed to generate CA certificate")
            return None, None

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error generating CA certificate: %s", e)
            self.logger.error(traceback.format_exc())
            return None, None

    def start(self) -> bool:
        """Start the SSL/TLS interceptor.

        Returns:
            bool: True if started successfully, False otherwise

        """
        try:
            # Generate CA certificate if needed
            if not os.path.exists(self.config["ca_cert_path"]) or not os.path.exists(self.config["ca_key_path"]):
                self.logger.info("Generating CA certificate...")
                cert_pem, key_pem = self.generate_ca_certificate()
                if cert_pem and key_pem:
                    # Create directory if it doesn't exist
                    os.makedirs(os.path.dirname(os.path.abspath(self.config["ca_cert_path"])), exist_ok=True)

                    # Save certificate and key
                    with open(self.config["ca_cert_path"], "wb") as f:
                        f.write(cert_pem)
                    with open(self.config["ca_key_path"], "wb") as f:
                        f.write(key_pem)

                    self.logger.info(f"CA certificate saved to {self.config['ca_cert_path']}")
                else:
                    self.logger.error("Failed to generate CA certificate")
                    return False

            # Check if mitmproxy is available
            mitmdump_path = self._find_executable("mitmdump")
            if mitmdump_path:
                # Create script for intercepting license verification
                script_fd, script_path = tempfile.mkstemp(suffix=".py", prefix="intellicrack_mitm_")
                with os.fdopen(script_fd, "w", encoding="utf-8") as f:
                    f.write(f"""
import json
from mitmproxy import http

# License verification endpoints
LICENSE_ENDPOINTS = {self.config["target_hosts"]}

def request(flow: http.HTTPFlow) -> None:
    # Check if this is a license verification request
    if any(endpoint in flow.request.pretty_host for _endpoint in LICENSE_ENDPOINTS):
        print(f"Intercepted license verification request to {{flow.request.pretty_host}}")

        # Log request details
        with open('license_requests.log', 'a', encoding='utf-8') as f:
            f.write(f"\\n=== REQUEST to {{flow.request.pretty_host}} ===\\n")
            f.write(f"Method: {{flow.request.method}}\\n")
            f.write(f"Path: {{flow.request.path}}\\n")
            f.write(f"Headers: {{flow.request.headers}}\\n")
            f.write(f"Content: {{flow.request.content}}\\n")

def response(flow: http.HTTPFlow) -> None:
    # Check if this is a license verification response
    if any(endpoint in flow.request.pretty_host for _endpoint in LICENSE_ENDPOINTS):
        print(f"Intercepted license verification response from {{flow.request.pretty_host}}")

        # Log response details
        with open('license_responses.log', 'a', encoding='utf-8') as f:
            f.write(f"\\n=== RESPONSE from {{flow.request.pretty_host}} ===\\n")
            f.write(f"Status: {{flow.response.status_code}}\\n")
            f.write(f"Headers: {{flow.response.headers}}\\n")
            f.write(f"Content: {{flow.response.content}}\\n")

        # Modify response to indicate valid license
        content_type = flow.response.headers.get('Content-Type', '')

        if 'json' in content_type:
            try:
                # Parse JSON response
                data = json.loads(flow.response.content)

                # Modify response to indicate valid license
                if 'status' in data:
                    data['status'] = 'SUCCESS'
                if 'license' in data:
                    if isinstance(data['license'], dict):
                        data['license']['status'] = 'ACTIVATED'
                        data['license']['type'] = 'PERMANENT'
                    else:
                        data['license'] = 'ACTIVATED'
                if 'isValid' in data:
                    data['isValid'] = True
                if 'valid' in data:
                    data['valid'] = True
                if 'expired' in data:
                    data['expired'] = False
                if 'expiry' in data:
                    data['expiry'] = '2099-12-31'

                # Update response content
                flow.response.content = json.dumps(data).encode('utf-8')

                print(f"Modified license response: {{data}}")
            except Exception as e:
                logger.error("Exception in ssl_interceptor: %s", e)
                # Not valid JSON, leave as is
                pass
        elif 'xml' in content_type:
            # Simple string replacements for XML
            content = flow.response.content.decode('utf-8', errors='ignore')
            content = content.replace('<status>ERROR</status>', '<status>SUCCESS</status>')
            content = content.replace('<valid>false</valid>', '<valid>true</valid>')
            content = content.replace('<expired>true</expired>', '<expired>false</expired>')
            flow.response.content = content.encode('utf-8')
""")

                # Start mitmproxy
                cmd = [
                    mitmdump_path,
                    "-s",
                    script_path,
                    "--listen-host",
                    self.config["listen_ip"],
                    "--listen-port",
                    str(self.config["listen_port"]),
                    "--set",
                    "block_global=false",
                    "--set",
                    "ssl_insecure=true",
                ]

                self.proxy_process = subprocess.Popen(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                )

                self.logger.info("mitmproxy started with PID %s", self.proxy_process.pid)
            else:
                self.logger.warning("mitmproxy not found. SSL/TLS interception will be limited.")
                # Implement a basic proxy server here if needed

            self.logger.info(
                "SSL/TLS interceptor started on %s:%s",
                self.config["listen_ip"],
                self.config["listen_port"],
            )

            # Print instructions
            self.logger.info("To use the SSL/TLS interceptor:")
            self.logger.info(
                "1. Configure the application to use %s:%s as proxy",
                self.config["listen_ip"],
                self.config["listen_port"],
            )
            self.logger.info(
                "2. Install the CA certificate (%s) in the system trust store",
                self.config["ca_cert_path"],
            )

            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error starting SSL/TLS interceptor: %s", e)
            self.logger.error(traceback.format_exc())
            return False

    def stop(self) -> bool:
        """Stop the SSL/TLS interceptor.

        Returns:
            bool: True if stopped successfully, False otherwise

        """
        try:
            # Stop proxy process
            if self.proxy_process is not None:
                self.proxy_process.terminate()
                self.proxy_process = None

            self.logger.info("SSL/TLS interceptor stopped")
            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error stopping SSL/TLS interceptor: %s", e)
            return False

    def _find_executable(self, executable: str) -> str | None:
        """Find the path to an executable using the path discovery system.

        Args:
            executable: Name of the executable

        Returns:
            str: Path to the executable, or None if not found

        """
        from ...utils.core.path_discovery import find_tool

        # Try to find using path_discovery first
        path = find_tool(executable)
        if path:
            return path

        # Fallback to simple PATH search for tools not in path_discovery specs
        import shutil

        return shutil.which(executable)

    def get_traffic_log(self) -> list[dict[str, Any]]:
        """Get the captured traffic log.

        Returns:
            list: List of captured traffic entries

        """
        return self.traffic_log.copy()

    def add_target_host(self, host: str) -> None:
        """Add a target host for interception.

        Args:
            host: Hostname to intercept

        """
        if host not in self.config["target_hosts"]:
            self.config["target_hosts"].append(host)
            self.logger.info("Added target host: %s", host)

    def remove_target_host(self, host: str) -> None:
        """Remove a target host from interception.

        Args:
            host: Hostname to remove

        """
        if host in self.config["target_hosts"]:
            self.config["target_hosts"].remove(host)
            self.logger.info("Removed target host: %s", host)

    def get_target_hosts(self) -> list[str]:
        """Get the list of target hosts.

        Returns:
            list: List of target hostnames

        """
        return self.config["target_hosts"].copy()

    def configure(self, config: dict[str, Any]) -> bool:
        """Configure SSL/TLS interception settings.

        This method allows dynamic configuration of the SSL/TLS interceptor,
        including proxy settings, target hosts, certificate paths, and behavior options.

        Args:
            config: Configuration dictionary with settings to update

        Returns:
            bool: True if configuration was successful, False otherwise

        """
        try:
            self.logger.info("Configuring SSL/TLS interceptor with new settings")

            # Validate configuration
            valid_keys = {
                "listen_ip",
                "listen_port",
                "target_hosts",
                "ca_cert_path",
                "ca_key_path",
                "record_traffic",
                "auto_respond",
                "proxy_timeout",
                "max_connections",
                "log_level",
                "response_delay",
                "inject_headers",
            }

            invalid_keys = set(config.keys()) - valid_keys
            if invalid_keys:
                self.logger.warning(f"Ignoring invalid configuration keys: {invalid_keys}")

            # Validate specific settings
            if "listen_port" in config:
                port = config["listen_port"]
                if not isinstance(port, int) or port < 1 or port > 65535:
                    self.logger.error(f"Invalid port number: {port}")
                    return False

            if "listen_ip" in config:
                ip = config["listen_ip"]
                # Basic IP validation
                import socket

                try:
                    socket.inet_aton(ip)
                except OSError:
                    self.logger.error(f"Invalid IP address: {ip}")
                    return False

            if "target_hosts" in config:
                if not isinstance(config["target_hosts"], list):
                    self.logger.error("target_hosts must be a list")
                    return False

            # Check if interceptor is running
            was_running = self.proxy_process is not None
            if was_running:
                self.logger.info("Stopping interceptor for reconfiguration")
                self.stop()

            # Update configuration
            old_config = self.config.copy()
            self.config.update(config)

            # Validate certificate paths if changed
            if "ca_cert_path" in config or "ca_key_path" in config:
                if not os.path.exists(self.config["ca_cert_path"]):
                    self.logger.warning(f"CA certificate not found at {self.config['ca_cert_path']}")
                    # Generate new certificate if needed
                    self.logger.info("Generating new CA certificate")
                    cert, key = self.generate_ca_certificate()
                    if not cert or not key:
                        self.logger.error("Failed to generate CA certificate")
                        self.config = old_config  # Restore old config
                        return False

                if not os.path.exists(self.config["ca_key_path"]):
                    self.logger.error(f"CA key not found at {self.config['ca_key_path']}")
                    self.config = old_config  # Restore old config
                    return False

            # Apply runtime configuration changes
            if "log_level" in config:
                log_levels = {
                    "DEBUG": logging.DEBUG,
                    "INFO": logging.INFO,
                    "WARNING": logging.WARNING,
                    "ERROR": logging.ERROR,
                }
                level = log_levels.get(config["log_level"].upper(), logging.INFO)
                self.logger.setLevel(level)

            # Restart if was running
            if was_running:
                self.logger.info("Restarting interceptor with new configuration")
                if not self.start():
                    self.logger.error("Failed to restart interceptor")
                    self.config = old_config  # Restore old config
                    return False

            self.logger.info("Configuration updated successfully")

            # Log configuration summary
            self.logger.debug(f"Current configuration: {self._get_safe_config()}")

            return True

        except Exception as e:
            self.logger.error(f"Error configuring SSL/TLS interceptor: {e}")
            self.logger.error(traceback.format_exc())
            return False

    def get_config(self) -> dict[str, Any]:
        """Get current configuration.

        Returns the current configuration of the SSL/TLS interceptor with
        sensitive information like private keys redacted for security.

        Returns:
            Dictionary containing current configuration settings

        """
        return self._get_safe_config()

    def _get_safe_config(self) -> dict[str, Any]:
        """Get configuration with sensitive data redacted."""
        safe_config = self.config.copy()

        # Redact sensitive information
        if "ca_key_path" in safe_config:
            safe_config["ca_key_path"] = "<redacted>" if os.path.exists(self.config["ca_key_path"]) else "not found"

        # Add runtime status
        safe_config["status"] = {
            "running": self.proxy_process is not None,
            "traffic_captured": len(self.traffic_log),
            "ca_cert_exists": os.path.exists(self.config["ca_cert_path"]),
            "ca_key_exists": os.path.exists(self.config["ca_key_path"]),
        }

        return safe_config


__all__ = ["SSLTLSInterceptor"]
