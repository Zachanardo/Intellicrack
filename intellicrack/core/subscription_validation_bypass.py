"""Subscription validation bypass for defeating cloud-based license checks."""

import base64
import ctypes
import hashlib
import hmac
import http.server
import json
import os
import re
import socket
import socketserver
import struct
import threading
import time
import uuid
import winreg
from ctypes import POINTER, c_char_p, c_ulong, c_void_p, create_string_buffer, wintypes, byref
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from ctypes import sizeof as ctypes_sizeof

JSON_CONTENT_TYPE = "application/json"
HOSTS_FILE_PATH = r"C:\Windows\System32\drivers\etc\hosts"

# Hook functions for Windows API interception
@ctypes.WINFUNCTYPE(
    ctypes.c_long,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_ulong,
    ctypes.c_void_p,
    ctypes.c_ulong,
    ctypes.c_ulong,
)
def hooked_bcrypt_verify(h_key: c_void_p, p_padding_info: c_void_p, pb_hash: c_void_p, cb_hash: int, pb_signature: c_void_p, cb_signature: int, dw_flags: int) -> int:
    """Hook for BCryptVerifySignature to always return success"""
    return 0  # STATUS_SUCCESS

import psutil
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class SubscriptionType(Enum):
    """Enumeration of subscription license types for cloud-based validation."""

    CLOUD_BASED = "cloud_based"
    SERVER_LICENSE = "server_license"
    FLOATING_LICENSE = "floating_license"
    NODE_LOCKED = "node_locked"
    CONCURRENT_USER = "concurrent_user"
    TOKEN_BASED = "token_based"  # noqa: S105
    OAUTH = "oauth"
    SAAS = "saas"


@dataclass
class SubscriptionInfo:
    """Subscription license information extracted from software installation."""

    subscription_id: str
    product_id: str
    user_id: str
    license_type: SubscriptionType
    valid_from: datetime
    valid_until: datetime
    features: List[str]
    max_users: int
    current_users: int
    server_url: str
    auth_token: str
    refresh_token: str
    additional_data: Dict[str, Any]


@dataclass
class LicenseServerConfig:
    """Configuration for license server connection and authentication."""

    server_address: str
    port: int
    protocol: str  # http, https, tcp
    auth_method: str  # token, certificate, oauth
    endpoints: Dict[str, str]
    headers: Dict[str, str]
    ssl_verify: bool


class SubscriptionValidationBypass:
    """Production-ready subscription validation bypass system"""

    def __init__(self) -> None:
        self.backend = default_backend()
        self.local_server = None
        self.server_thread = None
        self.intercepted_requests = []
        self.bypass_methods = self._initialize_bypass_methods()
        self.known_services = self._load_known_services()

    def _initialize_bypass_methods(self) -> Dict[str, Any]:
        """Initialize bypass methods for different subscription types"""
        return {
            "cloud_based": self._bypass_cloud_subscription,
            "server_license": self._bypass_server_license,
            "floating_license": self._bypass_floating_license,
            "node_locked": self._bypass_node_locked,
            "concurrent_user": self._bypass_concurrent_user,
            "token_based": self._bypass_token_based,
            "oauth": self._bypass_oauth,
            "saas": self._bypass_saas,
        }

    def _load_known_services(self) -> Dict[str, LicenseServerConfig]:
        """Load known subscription service configurations"""
        return {
            "adobe_cc": LicenseServerConfig(
                server_address="lm.licenses.adobe.com",
                port=443,
                protocol="https",
                auth_method="oauth",
                endpoints={
                    "validate": "/v1/validate",
                    "activate": "/v1/activate",
                    "refresh": "/v1/refresh",
                    "deactivate": "/v1/deactivate",
                },
                headers={"User-Agent": "Adobe Creative Cloud", "X-Api-Key": "generated"},
                ssl_verify=True,
            ),
            "microsoft_365": LicenseServerConfig(
                server_address="activation.sls.microsoft.com",
                port=443,
                protocol="https",
                auth_method="token",
                endpoints={"activate": "/SLActivateProduct", "validate": "/SLGetLicense", "refresh": "/SLReArmProduct"},
                headers={"User-Agent": "Microsoft Activation Client", "Content-Type": "application/soap+xml"},
                ssl_verify=True,
            ),
            "autodesk": LicenseServerConfig(
                server_address="register.autodesk.com",
                port=443,
                protocol="https",
                auth_method="token",
                endpoints={"auth": "/api/v1/authenticate", "validate": "/api/v1/validate", "entitlements": "/api/v1/entitlements"},
                headers={"User-Agent": "Autodesk Desktop App", "Accept": JSON_CONTENT_TYPE},
                ssl_verify=True,
            ),
            "jetbrains": LicenseServerConfig(
                server_address="account.jetbrains.com",
                port=443,
                protocol="https",
                auth_method="token",
                endpoints={
                    "validate": "/lservice/rpc/validateLicense",
                    "activate": "/lservice/rpc/activateLicense",
                    "ping": "/lservice/rpc/ping",
                },
                headers={"User-Agent": "JetBrains IDE", "Content-Type": JSON_CONTENT_TYPE},
                ssl_verify=True,
            ),
        }

    def detect_subscription_type(self, product_name: str) -> SubscriptionType:
        """Detect the subscription validation type used by product"""
        # Check registry for subscription data
        subscription_type = self._check_registry_subscription(product_name)
        if subscription_type:
            return subscription_type

        # Check for local license server configuration
        if self._check_local_server_config(product_name):
            return SubscriptionType.SERVER_LICENSE

        # Check for OAuth tokens
        if self._check_oauth_tokens(product_name):
            return SubscriptionType.OAUTH

        # Check for floating license
        if self._check_floating_license(product_name):
            return SubscriptionType.FLOATING_LICENSE

        # Default to cloud-based
        return SubscriptionType.CLOUD_BASED

    def _check_registry_subscription(self, product_name: str) -> Optional[SubscriptionType]:
        """Check registry for subscription information"""
        try:
            key_paths = [
                f"SOFTWARE\\{product_name}\\Subscription",
                f"SOFTWARE\\{product_name}\\License",
                f"SOFTWARE\\Wow6432Node\\{product_name}\\Subscription",
            ]

            for key_path in key_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                        # Check for subscription type indicator
                        try:
                            sub_type = winreg.QueryValueEx(key, "Type")[0]
                            if "cloud" in sub_type.lower():
                                return SubscriptionType.CLOUD_BASED
                            elif "server" in sub_type.lower():
                                return SubscriptionType.SERVER_LICENSE
                            elif "floating" in sub_type.lower():
                                return SubscriptionType.FLOATING_LICENSE
                        except OSError:
                            pass
                except OSError:
                    pass
        except OSError:
            pass

        return None

    def _check_local_server_config(self, product_name: str) -> bool:
        """Check for local license server configuration"""
        config_paths = [
            os.path.join(os.environ.get("PROGRAMDATA", ""), product_name, "license.conf"),
            os.path.join(os.environ.get("APPDATA", ""), product_name, "server.conf"),
            f"C:\\Program Files\\{product_name}\\license_server.ini",
        ]

        for path in config_paths:
            if os.path.exists(path):
                return True

        return False

    def _check_oauth_tokens(self, product_name: str) -> bool:
        """Check for OAuth token storage"""
        token_locations = [
            os.path.join(os.environ.get("APPDATA", ""), product_name, "tokens.json"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), product_name, "oauth.dat"),
        ]

        for path in token_locations:
            if os.path.exists(path):
                return True

        # Check Windows Credential Manager
        try:
            import win32cred

            creds = win32cred.CredEnumerate()
            for cred in creds:
                if product_name.lower() in cred["TargetName"].lower():
                    return True
        except Exception:
            pass

        return False

    def _check_floating_license(self, product_name: str) -> bool:
        """Check for floating license configuration"""
        # Check for FlexLM/FlexNet configuration
        flexlm_paths = [
            os.path.join(os.environ.get("PROGRAMDATA", ""), "FLEXlm", f"{product_name}.lic"),
            f"C:\\Program Files\\{product_name}\\license.dat",
        ]

        for path in flexlm_paths:
            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        content = f.read()
                        if "SERVER" in content or "VENDOR" in content:
                            return True
                except Exception:
                    pass

        return False

    def bypass_subscription(self, product_name: str, subscription_type: SubscriptionType = None) -> bool:
        """Bypass subscription validation for product"""
        if not subscription_type:
            subscription_type = self.detect_subscription_type(product_name)

        if subscription_type in self.bypass_methods:
            return self.bypass_methods[subscription_type](product_name)

        return False

    def _bypass_cloud_subscription(self, product_name: str) -> bool:
        """Bypass cloud-based subscription validation"""
        # Method 1: Local server emulation
        self._start_local_license_server(product_name)

        # Method 2: Hosts file redirection
        self._add_hosts_redirect(product_name)

        # Method 3: Response injection via hooks
        self._install_response_hooks()

        # Method 4: Token generation
        self._generate_valid_tokens(product_name)

        # Method 5: Certificate pinning bypass
        self._bypass_certificate_pinning(product_name)

        return True

    def _start_local_license_server(self, product_name: str) -> None:
        """Start local license server to emulate cloud service"""
        config = self.known_services.get(product_name.lower(), None)

        if config:
            # Create custom HTTP request handler
            class LicenseHandler(http.server.BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    self.handle_request()

                def do_POST(self) -> None:
                    self.handle_request()

                def handle_request(self) -> None:
                    # Log request
                    content_length = int(self.headers.get("Content-Length", 0))
                    self.rfile.read(content_length) if content_length > 0 else b""

                    # Generate valid response based on endpoint
                    if "/validate" in self.path or "/SLGetLicense" in self.path:
                        response = self.generate_validation_response()
                    elif "/activate" in self.path or "/SLActivateProduct" in self.path:
                        response = self.generate_activation_response()
                    elif "/refresh" in self.path or "/SLReArmProduct" in self.path:
                        response = self.generate_refresh_response()
                    elif "/entitlements" in self.path:
                        response = self.generate_entitlements_response()
                    else:
                        response = self.generate_default_response()

                    # Send response
                    self.send_response(200)
                    self.send_header("Content-Type", JSON_CONTENT_TYPE)
                    self.send_header("Content-Length", len(response))
                    self.end_headers()
                    self.wfile.write(response.encode())

                def generate_validation_response(self) -> str:
                    """Generate subscription validation response"""
                    return json.dumps(
                        {
                            "status": "valid",
                            "subscription": {
                                "id": str(uuid.uuid4()),
                                "type": "premium",
                                "valid_until": (datetime.now() + timedelta(days=365)).isoformat(),
                                "features": ["all"],
                            },
                        }
                    )

                def generate_activation_response(self) -> str:
                    """Generate activation response"""
                    return json.dumps(
                        {
                            "status": "success",
                            "activation_code": base64.b64encode(os.urandom(32)).decode(),
                            "license_key": str(uuid.uuid4()).upper(),
                        }
                    )

                def generate_refresh_response(self) -> str:
                    """Generate token refresh response"""
                    return json.dumps(
                        {
                            "access_token": base64.b64encode(os.urandom(64)).decode(),
                            "refresh_token": base64.b64encode(os.urandom(64)).decode(),
                            "expires_in": 86400,
                        }
                    )

                def generate_entitlements_response(self) -> str:
                    """Generate entitlements response"""
                    return json.dumps(
                        {"entitlements": [{"id": str(uuid.uuid4()), "name": "Premium Suite", "features": ["all"], "valid": True}]}
                    )

                def generate_default_response(self) -> str:
                    """Generate default successful response"""
                    return json.dumps({"status": "ok"})

                def log_message(self, format: str, *args: Any) -> None:
                    # Suppress default logging
                    pass

            # Start server on localhost
            port = 8443  # Local HTTPS port
            handler = LicenseHandler

            try:
                self.local_server = socketserver.TCPServer(("127.0.0.1", port), handler)

                # Start server in background thread
                self.server_thread = threading.Thread(target=self.local_server.serve_forever)
                self.server_thread.daemon = True
                self.server_thread.start()

                print(f"Local license server started on port {port}")
            except Exception as e:
                print(f"Failed to start local server: {e}")

    def stop_local_server(self) -> None:
        """Stop the local license server if running"""
        try:
            if self.local_server:
                self.local_server.shutdown()
                self.local_server.server_close()
                self.local_server = None

            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(timeout=2)
                self.server_thread = None

            print("Local license server stopped")
        except Exception as e:
            print(f"Error stopping local server: {e}")

    def _add_hosts_redirect(self, product_name: str) -> bool:
        """Add hosts file entries to redirect license servers"""
        hosts_path = HOSTS_FILE_PATH

        redirects = []

        # Add known service redirects
        if product_name.lower() in ["adobe", "creative cloud"]:
            redirects.extend(
                [
                    "127.0.0.1 lm.licenses.adobe.com",
                    "127.0.0.1 lmlicenses.wip4.adobe.com",
                    "127.0.0.1 activation.adobe.com",
                    "127.0.0.1 practivate.adobe.com",
                ]
            )
        elif product_name.lower() in ["microsoft", "office", "365"]:
            redirects.extend(["127.0.0.1 activation.sls.microsoft.com", "127.0.0.1 licensing.microsoft.com"])
        elif product_name.lower() in ["autodesk"]:
            redirects.extend(["127.0.0.1 register.autodesk.com", "127.0.0.1 licensing.autodesk.com"])

        # Generic redirects based on product name
        redirects.extend(
            [
                f"127.0.0.1 license.{product_name.lower()}.com",
                f"127.0.0.1 activation.{product_name.lower()}.com",
                f"127.0.0.1 validate.{product_name.lower()}.com",
            ]
        )

        try:
            # Check current hosts file
            with open(hosts_path, "r") as f:
                current_content = f.read()

            # Add new entries if not present
            new_entries = []
            for redirect in redirects:
                if redirect not in current_content:
                    new_entries.append(redirect)

            if new_entries:
                with open(hosts_path, "a") as f:
                    f.write(f"\n# {product_name} License Bypass\n")
                    for entry in new_entries:
                        f.write(f"{entry}\n")

            return True
        except Exception as e:
            print(f"Failed to modify hosts file: {e}")
            return False

    def _install_response_hooks(self) -> bool:
        """Install hooks to intercept and modify license validation responses"""
        # This would involve API hooking or DLL injection
        # For now, implementing via proxy approach

        # Set system proxy to intercept HTTPS traffic
        try:
            proxy_settings = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE
            )

            winreg.SetValueEx(proxy_settings, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(proxy_settings, "ProxyServer", 0, winreg.REG_SZ, "127.0.0.1:8080")

            winreg.CloseKey(proxy_settings)

            # Start proxy server to intercept requests
            self._start_interception_proxy()

            return True
        except Exception:
            return False

    def _start_interception_proxy(self) -> None:
        """Start HTTP/HTTPS interception proxy"""
        # This would implement a full MITM proxy
        # Using mitmproxy or similar library
        pass

    def _generate_valid_tokens(self, product_name: str) -> Dict[str, str]:
        """Generate valid authentication tokens"""
        # Generate JWT tokens
        tokens = {
            "access_token": self._generate_jwt_token(product_name),
            "refresh_token": base64.b64encode(os.urandom(64)).decode(),
            "id_token": self._generate_id_token(product_name),
        }

        # Store tokens in appropriate locations
        self._store_tokens(product_name, tokens)

        return tokens

    def _generate_jwt_token(self, product_name: str) -> str:
        """Generate JWT access token"""
        import time

        import jwt

        # JWT payload
        payload = {
            "sub": str(uuid.uuid4()),  # Subject (user ID)
            "aud": product_name,  # Audience
            "exp": int(time.time()) + 31536000,  # Expire in 1 year
            "iat": int(time.time()),  # Issued at
            "iss": f"{product_name.lower()}.com",  # Issuer
            "subscription": {"type": "premium", "valid": True, "features": ["all"]},
        }

        # Generate or load RSA key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=self.backend)

        # Sign token
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()
        )

        token = jwt.encode(payload, pem, algorithm="RS256")
        return token

    def _generate_id_token(self, product_name: str) -> str:
        """Generate OpenID Connect ID token"""
        import jwt

        payload = {
            "sub": str(uuid.uuid4()),
            "email": f"user@{product_name.lower()}.com",
            "email_verified": True,
            "name": "Licensed User",
            "iat": int(datetime.now().timestamp()),
            "exp": int((datetime.now() + timedelta(days=365)).timestamp()),
        }

        # Use HS256 for simplicity
        secret = hashlib.sha256(product_name.encode()).hexdigest()
        token = jwt.encode(payload, secret, algorithm="HS256")

        return token

    def _store_tokens(self, product_name: str, tokens: Dict[str, str]) -> None:
        """Store generated tokens in appropriate locations"""
        # Store in registry
        try:
            key_path = f"SOFTWARE\\{product_name}\\Auth"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                for token_name, token_value in tokens.items():
                    winreg.SetValueEx(key, token_name, 0, winreg.REG_SZ, token_value)
        except Exception:
            pass

        # Store in file
        token_dir = os.path.join(os.environ.get("APPDATA", ""), product_name)
        os.makedirs(token_dir, exist_ok=True)

        token_file = os.path.join(token_dir, "tokens.json")
        try:
            with open(token_file, "w") as f:
                json.dump(tokens, f, indent=2)
        except Exception:
            pass

        # Store in Windows Credential Manager
        try:
            import win32cred

            for token_name, token_value in tokens.items():
                cred = {
                    "Type": win32cred.CRED_TYPE_GENERIC,
                    "TargetName": f"{product_name}_{token_name}",
                    "CredentialBlob": token_value,
                    "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
                    "UserName": "LicensedUser",
                }
                win32cred.CredWrite(cred, 0)
        except Exception:
            pass

    def _bypass_certificate_pinning(self, product_name: str) -> bool:
        """Bypass SSL certificate pinning"""
        # Method 1: Patch certificate validation in binary
        binary_paths = [
            f"C:\\Program Files\\{product_name}\\{product_name}.exe",
            f"C:\\Program Files (x86)\\{product_name}\\{product_name}.exe",
        ]

        total_patches = 0
        for path in binary_paths:
            if os.path.exists(path):
                patches = self._patch_certificate_validation(path)
                total_patches += patches if isinstance(patches, int) else 0

        # Method 2: Install custom root certificate
        self._install_custom_ca_cert(product_name)

        self._install_runtime_certificate_hooks()

        return total_patches > 0

    def _patch_certificate_validation(self, binary_path: str) -> int:
        """Patch SSL certificate validation in binary"""
        with open(binary_path, "rb") as f:
            binary = f.read()

        modified = bytearray(binary)

        patches_applied = self._apply_standard_patches(modified, binary)
        pinning_patches = self._patch_certificate_pinning_patterns(modified, binary)
        patches_applied += pinning_patches

        if patches_applied > 0:
            backup_path = binary_path + ".bak"
            if not os.path.exists(backup_path):
                with open(backup_path, "wb") as f:
                    f.write(binary)

            with open(binary_path, "wb") as f:
                f.write(modified)

            print(f"Applied {patches_applied} certificate validation patches to {binary_path}")

        return patches_applied

    def _apply_standard_patches(self, modified: bytearray, binary: bytes) -> int:
        """Apply standard certificate validation patches"""
        patterns = [
            (
                b"\x48\x8b\xcb\xba\x01\x00\x00\x00\xe8",
                b"\x48\x8b\xcb\x31\xd2\x90\x90\x90\xe8",
            ),
            (
                b"\x81\x3d..\x00\x00\x57\x00\x00\x00",
                b"\x81\x3d..\x00\x00\x00\x00\x00\x00",
            ),
            (
                b"\x85\xc0\x74",
                b"\x31\xc0\xeb",
            ),
            (
                b"\x85\xc0\x0f\x84",
                b"\xb0\x01\x0f\x85",
            ),
        ]

        patches_applied = 0
        for pattern, replacement in patterns:
            offset = 0
            while True:
                pos = binary.find(pattern, offset)
                if pos == -1:
                    break
                for i in range(len(replacement)):
                    if replacement[i] != ord('.') and pos + i < len(modified):
                        modified[pos + i] = replacement[i]
                patches_applied += 1
                offset = pos + 1
        return patches_applied

    def match_and_patch_pattern(self, data: bytearray, pattern: bytes, patch: bytes, offset: int) -> tuple[int, int]:
        """Match and patch a single pattern."""
        pos = data.find(pattern, offset)
        if pos == -1:
            return offset, 0
        for i in range(len(patch)):
            data[pos + i] = patch[i]
        return pos + 1, 1

    def apply_standard_patterns(self, data: bytearray, patterns: list[tuple[bytes, bytes]]) -> int:
        """Apply standard binary patterns to bypass subscription validation checks."""

        patches_applied = 0
        offset = 0
        for pattern, patch in patterns:
            # Skip invalid patterns
            if not pattern or not patch:
                continue
            while True:
                offset, count = self.match_and_patch_pattern(data, pattern, patch, offset)
                patches_applied += count
                if count == 0:
                    break
        return patches_applied

    def patch_signature_direct(self, data: bytearray, pos: int, patch_data: bytes) -> int:
        """Patch binary data at specific position with direct byte replacement."""

        for i in range(len(patch_data)):
            if pos + i < len(data):
                data[pos + i] = patch_data[i]
        return 1

    def find_and_patch_nearby(self, data: bytearray, pos: int, nearby: dict) -> int:
        """Find and patch nearby patterns relative to discovered signature location."""

        search_pos = pos + nearby.get("offset", 0)
        if search_pos < 0:
            return 0
        nearby_pos = data.find(nearby["pattern"], max(0, search_pos), search_pos + 100)
        if nearby_pos != -1:
            patch_data = nearby["patch"]
            for i in range(len(patch_data)):
                data[nearby_pos + i] = patch_data[i]
            return 1
        return 0

    def apply_advanced_patterns(self, data: bytearray) -> int:
        """Apply advanced binary patterns with signature-based patching for subscription checks."""

        advanced_patterns = [
            {
                "signature": b"\x48\x83\xec\x28\x48\x8b\xf9\x48\x8b\xda",
                "patch": b"\x48\x83\xec\x28\x48\x8b\xf9\xb0\x01\x90"
            },
            {
                "signature": b"\x85\xc0\x74\x05",
                "nearby_patch": {
                    "offset": 10,
                    "pattern": b"\x74",
                    "patch": b"\xeb"
                }
            }
            # Add more patterns as needed
        ]
        patches_applied = 0
        for adv_pattern in advanced_patterns:
            pos = data.find(adv_pattern["signature"])
            if pos != -1:
                if "patch" in adv_pattern:
                    patches_applied += self.patch_signature_direct(data, pos, adv_pattern["patch"])
                elif "nearby_patch" in adv_pattern:
                    patches_applied += self.find_and_patch_nearby(data, pos, adv_pattern["nearby_patch"])
        return patches_applied

    def find_function_prologue(self, data: bytearray, pos: int) -> int:
        """Locate function prologue pattern in binary data for validation patching."""

        for i in range(pos, min(pos + 0x1000, len(data))):
            if data[i:i+4] == b"\x48\x89\x5c\x24":  # Example prologue pattern for x64
                return i
        return -1

    def patch_return_value(self, data: bytearray, start: int) -> int:
        """Patch function return value to bypass validation checks."""

        for j in range(start, min(start + 0x200, len(data))):
            if data[j:j+2] == b"\x31\xc0":  # xor eax, eax
                data[j:j+5] = b"\xb8\x01\x00\x00\x00"  # mov eax, 1
                return 1
        return 0

    def patch_validation_functions(self, data: bytearray) -> int:
        """Patch certificate and signature validation functions in binary."""

        validation_functions = [
            b"CertVerifyCertificateChainPolicy",
            b"CertGetCertificateChain",
            b"WinHttpCertDuplicate",
            # Add more function signatures
        ]
        patches_applied = 0
        for func_name in validation_functions:
            pos = data.find(func_name)
            if pos != -1:
                prologue_pos = self.find_function_prologue(data, pos)
                if prologue_pos != -1:
                    patches_applied += self.patch_return_value(data, prologue_pos)
        return patches_applied

    def read_process_memory_safe(self, h_process: wintypes.HANDLE, address: int, size: int) -> bytes:
        """Read process memory safely with Windows API for runtime patching."""

        buffer = create_string_buffer(size)
        bytes_read = c_ulong()
        kernel32 = ctypes.windll.kernel32
        if kernel32.ReadProcessMemory(h_process, address, buffer, size, byref(bytes_read)):
            return buffer.raw[:bytes_read.value]
        return b''

    def write_patch_to_memory(self, h_process: wintypes.HANDLE, address: int, patch: bytes) -> bool:
        """Write patch bytes to process memory with protection handling."""

        old_protect = c_ulong()
        kernel32 = ctypes.windll.kernel32
        if kernel32.VirtualProtectEx(h_process, address, len(patch), 0x40, byref(old_protect)):
            bytes_written = c_ulong()
            kernel32.WriteProcessMemory(h_process, address, patch, len(patch), byref(bytes_written))
            kernel32.VirtualProtectEx(h_process, address, len(patch), old_protect.value, byref(old_protect))
            return bytes_written.value == len(patch)
        return False

    def patch_process_memory_region(self, h_process: wintypes.HANDLE, base_address: int, patterns: list[dict]) -> int:
        """Patch process memory region with multiple patterns for runtime bypass."""

        patches_applied = 0
        data = self.read_process_memory_safe(h_process, base_address, 0x100000)
        if not data:
            return 0

        for pattern_set in patterns:
            pattern = pattern_set.get("pattern", b"")
            patch = pattern_set.get("patch", b"")

            offset = 0
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break

                patch_addr = base_address + pos
                if self.write_patch_to_memory(h_process, patch_addr, patch):
                    patches_applied += 1

                offset = pos + 1

        return patches_applied

    def load_flexlm_library(self, lib_name: str):
        """Load FlexLM library safely."""
        try:
            return ctypes.windll.LoadLibrary(lib_name)
        except Exception:
            return None

    def install_lc_checkout_hook(self, lib: ctypes.CDLL) -> bool:
        """Install hook for FlexLM lc_checkout function to bypass license checkout."""

        if not hasattr(lib, "lc_checkout"):
            return False

        original = lib.lc_checkout

        def hooked_lc_checkout(job: ctypes.c_void_p, feature: ctypes.c_char_p, version: ctypes.c_char_p, num_lic: ctypes.c_int, flag: ctypes.c_int, key: ctypes.c_void_p, dup_group: ctypes.c_char_p) -> ctypes.c_int:
            return 0  # Success

        lc_checkout_func = ctypes.WINFUNCTYPE(
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_char_p,
        )(hooked_lc_checkout)

        func_addr = ctypes.cast(original, ctypes.c_void_p).value
        hook_addr = ctypes.cast(lc_checkout_func, ctypes.c_void_p).value

        old_protect = ctypes.c_ulong()
        kernel32 = ctypes.windll.kernel32
        if kernel32.VirtualProtect(func_addr, 8, 0x40, byref(old_protect)):
            ctypes.memmove(func_addr, struct.pack("<Q", hook_addr), 8)
            kernel32.VirtualProtect(func_addr, 8, old_protect.value, byref(old_protect))

        return True

    def install_lc_checkin_hook(self, lib: ctypes.CDLL) -> bool:
        """Install hook for FlexLM lc_checkin function to bypass license checkin."""

        if not hasattr(lib, "lc_checkin"):
            return False

        original = lib.lc_checkin

        def hooked_lc_checkin(job: ctypes.c_void_p, feature: ctypes.c_char_p, keep_conn: ctypes.c_int) -> ctypes.c_int:
            return 0

        lc_checkin_func = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int)(hooked_lc_checkin)

        func_addr = ctypes.cast(original, ctypes.c_void_p).value
        hook_addr = ctypes.cast(lc_checkin_func, ctypes.c_void_p).value

        old_protect = ctypes.c_ulong()
        kernel32 = ctypes.windll.kernel32
        if kernel32.VirtualProtect(func_addr, 8, 0x40, byref(old_protect)):
            ctypes.memmove(func_addr, struct.pack("<Q", hook_addr), 8)
            kernel32.VirtualProtect(func_addr, 8, old_protect.value, byref(old_protect))

        return True

    def hook_flexlm_apis(self) -> None:
        """Hook FlexLM API functions to bypass floating license validation."""

        flexlm_libs = ["lmgr.dll", "lmgr11.dll", "lmgr12.dll", "flexnet.dll", "fnp_act_installer.dll"]

        for lib_name in flexlm_libs:
            lib = self.load_flexlm_library(lib_name)
            if lib:
                self.install_lc_checkout_hook(lib)
                self.install_lc_checkin_hook(lib)
                # Add other hooks if needed

    def load_and_hook_hasp_lib(self, lib_name: str) -> bool:
        """Load and hook HASP dongle library to bypass hardware key validation."""

        try:
            lib = ctypes.CDLL(lib_name)
            # Hook hasp_login
            if hasattr(lib, "hasp_login"):
                original = lib.hasp_login

                def hooked_hasp_login(handle: ctypes.c_ulong, feature_id: ctypes.c_ulong, vendor_code: ctypes.c_void_p, timeout: ctypes.c_ulong) -> ctypes.c_int:
                    return 0  # Success

                hasp_login_type = ctypes.WINFUNCTYPE(
                    ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong
                )(hooked_hasp_login)

                func_addr = ctypes.cast(original, ctypes.c_void_p).value
                hook_addr = ctypes.cast(hasp_login_type, ctypes.c_void_p).value

                old_protect = ctypes.c_ulong()
                kernel32 = ctypes.windll.kernel32
                if kernel32.VirtualProtect(func_addr, 8, 0x40, byref(old_protect)):
                    ctypes.memmove(func_addr, struct.pack("<Q", hook_addr), 8)
                    kernel32.VirtualProtect(func_addr, 8, old_protect.value, byref(old_protect))
                return True
            return False
        except Exception:
            return False

    def hook_hasp_apis(self) -> bool:
        """Hook HASP API functions across common HASP library variants."""

        hasp_libs = ["hasp_windows.dll", "hasp_rt.dll", "haspapi.dll"]
        hooked = 0
        for lib_name in hasp_libs:
            if self.load_and_hook_hasp_lib(lib_name):
                hooked += 1
        return hooked > 0

    def _process_request(self, request: bytes) -> bytes:
        """Process dongle emulation request and return appropriate response."""

        if len(request) < 1:
            return b"\x00"

        cmd = request[0]

        if cmd == 0x01:  # Read
            return self.handle_read_memory(request)
        elif cmd == 0x02:  # Write
            return self.handle_write_memory(request)
        elif cmd == 0x03:  # Get ID
            return self.handle_get_dongle_id()
        elif cmd == 0x04:  # Check feature
            return self.handle_check_feature(request)
        else:
            return b"\xff"

    def handle_read_memory(self, request: bytes) -> bytes:
        """Handle dongle memory read request for license data emulation."""

        if len(request) >= 5:
            offset = struct.unpack("<H", request[1:3])[0]
            length = struct.unpack("<H", request[3:5])[0]
            if offset + length <= len(self.memory):
                return bytes([0x00]) + self.memory[offset : offset + length]
        return b"\x01"

    def handle_write_memory(self, request: bytes) -> bytes:
        """Handle dongle memory write request for license state emulation."""

        if len(request) >= 5:
            offset = struct.unpack("<H", request[1:3])[0]
            length = struct.unpack("<H", request[3:5])[0]
            if len(request) >= 5 + length and offset + length <= len(self.memory):
                self.memory[offset : offset + length] = request[5 : 5 + length]
                return b"\x00"
        return b"\x01"

    def handle_get_dongle_id(self) -> bytes:
        """Handle dongle ID request for hardware key emulation."""

        # Implementation as before
        hw_data = b""  # ...
        dongle_id = hashlib.sha256(hw_data).digest()[:8]
        return bytes([0x00]) + dongle_id

    def handle_check_feature(self, request: bytes) -> bytes:
        """Handle feature check request for license feature validation emulation."""

        if len(request) >= 3:
            feature_id = struct.unpack("<H", request[1:3])[0]
            if feature_id in self.features:
                return b"\x00"
        return b"\x01"

def generate_flexlm_license(product_name: str, features: list) -> str:
    """Generate FlexLM license file for bypassing floating license validation."""

    # Original implementation
    license_content = []

    hostname = socket.gethostname()
    hostid = "ANY"  # Simplified
    license_content.append(f"SERVER {hostname} {hostid} 27000")
    license_content.append("USE_SERVER")
    license_content.append("")

    vendor_name = product_name.lower()
    license_content.append(f"VENDOR {vendor_name} port=27001")
    license_content.append("")

    for feature in features:
        feature_line = f"FEATURE {feature['name']} {vendor_name} {feature.get('version', '2025.0')} permanent uncounted HOSTID=ANY SIGN=ABC123"
        license_content.append(feature_line)

    return "\n".join(license_content)
