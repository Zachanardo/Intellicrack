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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import datetime
import logging
import os
import subprocess
import tempfile
import traceback
from typing import Any, Dict, List, Optional, Tuple

# Optional cryptography dependencies - graceful fallback if not available
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    from cryptography.x509.oid import NameOID
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


class SSLTLSInterceptor:
    """
    SSL/TLS interception system for encrypted license verification.

    This system allows Intellicrack to intercept, analyze, and modify encrypted
    communications between applications and license servers, enabling bypass of
    secure license verification mechanisms.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the SSL/TLS interceptor.

        Args:
            config: Configuration dictionary (optional)
        """
        self.logger = logging.getLogger(__name__)

        # Default configuration
        self.config = {
            'listen_ip': '127.0.0.1',
            'listen_port': 8443,
            'target_hosts': [
                'licensing.adobe.com',
                'lm.autodesk.com',
                'activation.cloud.techsmith.com',
                'license.jetbrains.com',
                'license.sublimehq.com',
                'licensing.tableausoftware.com',
                'flexnetls.flexnetoperations.com',
                'licensing.steinberg.net',
                'license.ableton.com',
                'api.licenses.adobe.com',
                'lmlicensing.autodesk.com',
                'lm-autocad.autodesk.com',
                'kms.microsoft.com',
                'kms.core.windows.net',
                'licensing.mp.microsoft.com'
            ],
            'ca_cert_path': os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), 'ssl_certificates', 'ca.crt'),
            'ca_key_path': os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), 'ssl_certificates', 'ca.key'),
            'record_traffic': True,
            'auto_respond': True
        }

        # Update with provided configuration
        if config:
            self.config.update(config)

        # Initialize components
        self.proxy_server = None
        self.ca_cert = None
        self.ca_key = None
        self.traffic_log = []
        self.response_templates = {}

        # Load response templates
        self._load_response_templates()

    def _load_response_templates(self):
        """
        Load response templates for various license verification endpoints.
        """
        from ...utils.license_response_templates import get_all_response_templates
        self.response_templates = get_all_response_templates()

    def generate_ca_certificate(self) -> Tuple[Optional[bytes], Optional[bytes]]:
        """
        Generate a CA certificate for SSL/TLS interception.

        Returns:
            tuple: (certificate, key) as PEM bytes, or (None, None) if failed
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.error("cryptography library not available - cannot generate CA certificate")
            return None, None

        try:
            from ...utils.certificate_utils import generate_self_signed_cert
            
            cert_result = generate_self_signed_cert(
                common_name="Intellicrack Root CA",
                organization="Intellicrack CA",
                state="California",
                locality="San Francisco",
                valid_days=3650,
                is_ca=True
            )
            
            if cert_result:
                return cert_result
            else:
                self.logger.error("Failed to generate CA certificate")
                return None, None

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error generating CA certificate: %s", e)
            self.logger.error(traceback.format_exc())
            return None, None

    def start(self) -> bool:
        """
        Start the SSL/TLS interceptor.

        Returns:
            bool: True if started successfully, False otherwise
        """
        try:
            # Generate CA certificate if needed
            if not os.path.exists(self.config['ca_cert_path']) or not os.path.exists(self.config['ca_key_path']):
                self.logger.info("Generating CA certificate...")
                cert_pem, key_pem = self.generate_ca_certificate()
                if cert_pem and key_pem:
                    # Create directory if it doesn't exist
                    os.makedirs(os.path.dirname(os.path.abspath(self.config['ca_cert_path'])), exist_ok=True)

                    # Save certificate and key
                    with open(self.config['ca_cert_path'], 'wb') as f:
                        f.write(cert_pem)
                    with open(self.config['ca_key_path'], 'wb') as f:
                        f.write(key_pem)

                    self.logger.info(f"CA certificate saved to {self.config['ca_cert_path']}")
                else:
                    self.logger.error("Failed to generate CA certificate")
                    return False

            # Check if mitmproxy is available
            mitmdump_path = self._find_executable('mitmdump')
            if mitmdump_path:
                # Create script for intercepting license verification
                script_fd, script_path = tempfile.mkstemp(suffix='.py', prefix='intellicrack_mitm_')
                with os.fdopen(script_fd, 'w', encoding='utf-8') as f:
                    f.write(f"""
import json
from mitmproxy import http

# License verification endpoints
LICENSE_ENDPOINTS = {self.config['target_hosts']}

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
            except Exception:
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
                    '-s', script_path,
                    '--listen-host', self.config['listen_ip'],
                    '--listen-port', str(self.config['listen_port']),
                    '--set', 'block_global=false',
                    '--set', 'ssl_insecure=true'
                ]

                self.proxy_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )

                self.logger.info("mitmproxy started with PID %s", self.proxy_process.pid)
            else:
                self.logger.warning("mitmproxy not found. SSL/TLS interception will be limited.")
                # Implement a basic proxy server here if needed

            self.logger.info("SSL/TLS interceptor started on %s:%s", self.config['listen_ip'], self.config['listen_port'])

            # Print instructions
            self.logger.info("To use the SSL/TLS interceptor:")
            self.logger.info("1. Configure the application to use %s:%s as proxy", self.config['listen_ip'], self.config['listen_port'])
            self.logger.info("2. Install the CA certificate (%s) in the system trust store", self.config['ca_cert_path'])

            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error starting SSL/TLS interceptor: %s", e)
            self.logger.error(traceback.format_exc())
            return False

    def stop(self) -> bool:
        """
        Stop the SSL/TLS interceptor.

        Returns:
            bool: True if stopped successfully, False otherwise
        """
        try:
            # Stop proxy process
            if hasattr(self, 'proxy_process') and self.proxy_process:
                self.proxy_process.terminate()
                self.proxy_process = None

            self.logger.info("SSL/TLS interceptor stopped")
            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error stopping SSL/TLS interceptor: %s", e)
            return False

    def _find_executable(self, executable: str) -> Optional[str]:
        """
        Find the path to an executable using the path discovery system.

        Args:
            executable: Name of the executable

        Returns:
            str: Path to the executable, or None if not found
        """
        from ...utils.path_discovery import find_tool
        
        # Try to find using path_discovery first
        path = find_tool(executable)
        if path:
            return path
            
        # Fallback to simple PATH search for tools not in path_discovery specs
        import shutil
        return shutil.which(executable)

    def get_traffic_log(self) -> List[Dict[str, Any]]:
        """
        Get the captured traffic log.

        Returns:
            list: List of captured traffic entries
        """
        return self.traffic_log.copy()

    def add_target_host(self, host: str):
        """
        Add a target host for interception.

        Args:
            host: Hostname to intercept
        """
        if host not in self.config['target_hosts']:
            self.config['target_hosts'].append(host)
            self.logger.info("Added target host: %s", host)

    def remove_target_host(self, host: str):
        """
        Remove a target host from interception.

        Args:
            host: Hostname to remove
        """
        if host in self.config['target_hosts']:
            self.config['target_hosts'].remove(host)
            self.logger.info("Removed target host: %s", host)

    def get_target_hosts(self) -> List[str]:
        """
        Get the list of target hosts.

        Returns:
            list: List of target hostnames
        """
        return self.config['target_hosts'].copy()


__all__ = ['SSLTLSInterceptor']
