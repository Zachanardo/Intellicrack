"""
SSL/TLS Interception System for Encrypted License Verification

This module provides comprehensive SSL/TLS traffic interception capabilities using mitmproxy
to analyze and modify encrypted communications between applications and license servers,
enabling bypass of secure license verification mechanisms.
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
            'ca_cert_path': 'ca.crt',
            'ca_key_path': 'ca.key',
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
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            # Create self-signed certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intellicrack CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Intellicrack Root CA"),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            ).sign(private_key, hashes.SHA256())

            # Serialize to PEM format
            cert_pem = cert.public_bytes(Encoding.PEM)
            key_pem = private_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                NoEncryption()
            )

            return cert_pem, key_pem

        except Exception as e:
            self.logger.error(f"Error generating CA certificate: {e}")
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
                with os.fdopen(script_fd, 'w') as f:
                    f.write(f"""
import json
from mitmproxy import http

# License verification endpoints
LICENSE_ENDPOINTS = {self.config['target_hosts']}

def request(flow: http.HTTPFlow) -> None:
    # Check if this is a license verification request
    if any(endpoint in flow.request.pretty_host for endpoint in LICENSE_ENDPOINTS):
        print(f"Intercepted license verification request to {{flow.request.pretty_host}}")

        # Log request details
        with open('license_requests.log', 'a') as f:
            f.write(f"\\n=== REQUEST to {{flow.request.pretty_host}} ===\\n")
            f.write(f"Method: {{flow.request.method}}\\n")
            f.write(f"Path: {{flow.request.path}}\\n")
            f.write(f"Headers: {{flow.request.headers}}\\n")
            f.write(f"Content: {{flow.request.content}}\\n")

def response(flow: http.HTTPFlow) -> None:
    # Check if this is a license verification response
    if any(endpoint in flow.request.pretty_host for endpoint in LICENSE_ENDPOINTS):
        print(f"Intercepted license verification response from {{flow.request.pretty_host}}")

        # Log response details
        with open('license_responses.log', 'a') as f:
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
            except:
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

                self.logger.info(f"mitmproxy started with PID {self.proxy_process.pid}")
            else:
                self.logger.warning("mitmproxy not found. SSL/TLS interception will be limited.")
                # Implement a basic proxy server here if needed

            self.logger.info(f"SSL/TLS interceptor started on {self.config['listen_ip']}:{self.config['listen_port']}")

            # Print instructions
            self.logger.info("To use the SSL/TLS interceptor:")
            self.logger.info(f"1. Configure the application to use {self.config['listen_ip']}:{self.config['listen_port']} as proxy")
            self.logger.info(f"2. Install the CA certificate ({self.config['ca_cert_path']}) in the system trust store")

            return True

        except Exception as e:
            self.logger.error(f"Error starting SSL/TLS interceptor: {e}")
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

        except Exception as e:
            self.logger.error(f"Error stopping SSL/TLS interceptor: {e}")
            return False

    def _find_executable(self, executable: str) -> Optional[str]:
        """
        Find the path to an executable in the system PATH.

        Args:
            executable: Name of the executable

        Returns:
            str: Path to the executable, or None if not found
        """
        for path in os.environ['PATH'].split(os.pathsep):
            exe_path = os.path.join(path, executable)
            if os.path.isfile(exe_path) and os.access(exe_path, os.X_OK):
                return exe_path

            # Check for Windows executable
            exe_path_win = os.path.join(path, executable + '.exe')
            if os.path.isfile(exe_path_win) and os.access(exe_path_win, os.X_OK):
                return exe_path_win

        return None

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
            self.logger.info(f"Added target host: {host}")

    def remove_target_host(self, host: str):
        """
        Remove a target host from interception.

        Args:
            host: Hostname to remove
        """
        if host in self.config['target_hosts']:
            self.config['target_hosts'].remove(host)
            self.logger.info(f"Removed target host: {host}")

    def get_target_hosts(self) -> List[str]:
        """
        Get the list of target hosts.

        Returns:
            list: List of target hostnames
        """
        return self.config['target_hosts'].copy()


__all__ = ['SSLTLSInterceptor']
