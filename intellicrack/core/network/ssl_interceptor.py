"""SSL traffic interceptor for analyzing and modifying encrypted communications."""

import base64
import datetime
import gzip
import hashlib
import hmac
import json
import logging
import os
import platform
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from subprocess import Popen
from typing import Any

from intellicrack.data import CA_CERT_PATH, CA_KEY_PATH
from intellicrack.utils.logger import logger
from intellicrack.utils.type_safety import get_typed_item, validate_type


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


try:
    import importlib.util

    CRYPTOGRAPHY_AVAILABLE = importlib.util.find_spec("cryptography") is not None
except ImportError as e:
    logger.exception("Import error in ssl_interceptor: %s", e)
    CRYPTOGRAPHY_AVAILABLE = False

try:
    import importlib.util

    JWT_AVAILABLE = importlib.util.find_spec("jwt") is not None
except ImportError:
    JWT_AVAILABLE = False


try:
    import importlib.util

    MITMPROXY_AVAILABLE = importlib.util.find_spec("mitmproxy") is not None
except ImportError:
    MITMPROXY_AVAILABLE = False


try:
    import importlib.util

    PYOPENSSL_AVAILABLE = importlib.util.find_spec("OpenSSL") is not None
except ImportError:
    PYOPENSSL_AVAILABLE = False


class JWTTokenModifier:
    """Handles JWT token parsing, modification, and re-signing for license bypass."""

    def __init__(self, binary_path: str | None = None, wordlist_path: str | None = None) -> None:
        """Initialize JWT token modifier.

        Args:
            binary_path: Optional path to binary for extracting potential secrets
            wordlist_path: Optional path to custom wordlist for brute force

        """
        self.logger = logging.getLogger(__name__)
        self.captured_keys: dict[str, bytes] = {}
        self.captured_jwks: dict[str, bytes] = {}
        self.binary_path = binary_path
        self.wordlist_path = wordlist_path
        self.common_secrets = self._load_common_secrets()

    def _load_common_secrets(self) -> list[bytes]:
        """Load common JWT secrets for brute force attempts.

        Returns:
            List of common secret bytes for JWT signing

        """
        secrets = [
            b"secret",
            b"password",
            b"12345678",
            b"changeme",
            b"default",
            b"admin",
            b"test",
            b"jwt",
            b"key",
            b"api-key",
            b"app-secret",
            b"client-secret",
            b"jwt-secret",
            b"token-secret",
            b"auth-secret",
            b"signing-key",
            b"private-key",
            b"secret-key",
            b"application-key",
            b"server-secret",
            b"master-key",
            b"encryption-key",
            b"secure-key",
            b"session-secret",
            b"auth-key",
            b"token-key",
            b"api-secret",
            b"oauth-secret",
            b"bearer-secret",
            b"access-secret",
            b"refresh-secret",
            b"license-key",
            b"license-secret",
            b"verification-key",
            b"validation-secret",
            b"prod-secret",
            b"dev-secret",
            b"test-secret",
            b"staging-secret",
            b"production-key",
            b"development-key",
            b"testing-key",
            b"qwerty",
            b"123456",
            b"password123",
            b"admin123",
            b"root",
            b"toor",
            b"passw0rd",
            b"P@ssw0rd",
            b"letmein",
            b"welcome",
        ]

        if self.wordlist_path and os.path.exists(self.wordlist_path):
            try:
                with open(self.wordlist_path, "rb") as f:
                    for line in f:
                        secret = line.strip()
                        if secret and secret not in secrets:
                            secrets.append(secret)
            except OSError as e:
                self.logger.warning("Failed to load wordlist from %s: %s", self.wordlist_path, e)

        if self.binary_path:
            secrets.extend(self._extract_secrets_from_binary())

        return secrets

    def _extract_secrets_from_binary(self) -> list[bytes]:
        """Extract potential JWT secrets from binary using string analysis.

        Returns:
            List of potential secret strings found in binary

        """
        secrets: list[bytes] = []

        if not self.binary_path or not os.path.exists(self.binary_path):
            return secrets

        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()

            import re

            patterns = [
                rb'[A-Za-z0-9_-]{16,64}',
                rb'jwt[_-]?secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]+)',
                rb'api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]+)',
                rb'secret[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]+)',
                rb'signing[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]+)',
            ]

            for pattern in patterns:
                for match in re.finditer(pattern, data):
                    if match.groups():
                        candidate = match.group(1)
                    else:
                        candidate = match.group(0)

                    if len(candidate) >= 8 and candidate not in secrets:
                        secrets.append(candidate)

        except OSError as e:
            self.logger.debug("Failed to extract secrets from binary: %s", e)

        return secrets[:100]

    def verify_jwt_signature(self, token: str, secret: bytes) -> bool:
        """Verify JWT signature matches the expected HMAC-SHA256 signature.

        Args:
            token: JWT token string
            secret: Secret key to verify against

        Returns:
            True if signature is valid, False otherwise

        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False

            message = f"{parts[0]}.{parts[1]}"
            expected_signature = hmac.new(secret, message.encode(), hashlib.sha256).digest()
            expected_b64 = base64.urlsafe_b64encode(expected_signature).decode().rstrip("=")

            actual_b64 = parts[2]
            padding = 4 - len(actual_b64) % 4
            if padding != 4:
                actual_b64 += "=" * padding

            actual_signature = base64.urlsafe_b64decode(actual_b64)

            return hmac.compare_digest(expected_signature, actual_signature)

        except (ValueError, KeyError) as e:
            self.logger.debug("Signature verification failed: %s", e)
            return False

    def intercept_jwks_endpoint(self, url: str) -> bytes | None:
        """Intercept JWKS endpoint to extract public key for algorithm confusion attack.

        Args:
            url: JWKS endpoint URL (.well-known/jwks.json)

        Returns:
            Public key bytes if successful, None otherwise

        """
        try:
            import urllib.request

            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310 - Legitimate security research
                data = json.loads(response.read().decode("utf-8"))

                if "keys" in data and len(data["keys"]) > 0:
                    key_data = data["keys"][0]

                    if CRYPTOGRAPHY_AVAILABLE and key_data.get("kty") == "RSA":
                        from cryptography.hazmat.primitives import serialization
                        from cryptography.hazmat.primitives.asymmetric import rsa
                        from cryptography.hazmat.backends import default_backend

                        n = int.from_bytes(base64.urlsafe_b64decode(key_data["n"] + "=="), "big")
                        e = int.from_bytes(base64.urlsafe_b64decode(key_data["e"] + "=="), "big")

                        public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
                        public_key_pem = public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )

                        self.captured_jwks[url] = public_key_pem
                        return public_key_pem

        except Exception as e:
            self.logger.debug("Failed to intercept JWKS endpoint: %s", e)

        return None

    def decode_jwt_without_verification(self, token: str) -> dict[str, Any] | None:
        """Decode JWT token without signature verification.

        Args:
            token: JWT token string

        Returns:
            Decoded token payload as dictionary, or None if failed

        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            payload_part = parts[1]
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += "=" * padding

            payload_bytes = base64.urlsafe_b64decode(payload_part)
            payload = json.loads(payload_bytes.decode("utf-8"))
            return payload
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            self.logger.debug("Failed to decode JWT: %s", e)
            return None

    def modify_jwt_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Modify JWT payload to bypass license restrictions.

        Args:
            payload: Original JWT payload

        Returns:
            Modified JWT payload with license bypass modifications

        """
        modified = payload.copy()

        future_date = (datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=3650)).isoformat()
        future_timestamp = int((datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=3650)).timestamp())

        license_bypass_mappings = {
            "exp": future_timestamp,
            "expiry": future_date,
            "expiration": future_date,
            "valid_until": future_date,
            "expires_at": future_timestamp,
            "license_status": "active",
            "status": "active",
            "is_valid": True,
            "valid": True,
            "is_active": True,
            "active": True,
            "is_expired": False,
            "expired": False,
            "license_type": "perpetual",
            "type": "perpetual",
            "tier": "enterprise",
            "plan": "enterprise",
            "features": ["all"],
            "entitlements": ["full_access"],
            "max_users": 999999,
            "max_seats": 999999,
            "seats": 999999,
            "trial": False,
            "is_trial": False,
        }

        for key, value in license_bypass_mappings.items():
            if key in modified:
                modified[key] = value
            elif any(k in str(modified) for k in ["license", "subscription", "entitlement"]):
                if isinstance(modified.get("license"), dict):
                    modified["license"][key] = value
                elif isinstance(modified.get("subscription"), dict):
                    modified["subscription"][key] = value

        return modified

    def resign_jwt_hs256(self, header: dict[str, Any], payload: dict[str, Any], secret: bytes) -> str:
        """Re-sign JWT token using HS256 (HMAC-SHA256).

        Args:
            header: JWT header
            payload: JWT payload
            secret: Signing secret key

        Returns:
            Newly signed JWT token string

        """
        import hmac
        import hashlib

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        message = f"{header_b64}.{payload_b64}"

        signature = hmac.new(secret, message.encode(), hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        return f"{message}.{signature_b64}"

    def resign_jwt_rs256(self, header: dict[str, Any], payload: dict[str, Any], private_key: Any) -> str:
        """Re-sign JWT token using RS256 (RSA-SHA256).

        Args:
            header: JWT header
            payload: JWT payload
            private_key: RSA private key object

        Returns:
            Newly signed JWT token string

        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography library required for RS256 signing")

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        message = f"{header_b64}.{payload_b64}"

        signature = private_key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        return f"{message}.{signature_b64}"

    def attempt_jwt_modification(self, token: str, jwks_url: str | None = None) -> str | None:
        """Attempt to modify and re-sign JWT token.

        Args:
            token: Original JWT token
            jwks_url: Optional JWKS endpoint URL for algorithm confusion attack

        Returns:
            Modified JWT token if successful, None otherwise

        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            header_b64 = parts[0]
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += "=" * padding
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            payload = self.decode_jwt_without_verification(token)
            if not payload:
                return None

            modified_payload = self.modify_jwt_payload(payload)

            alg = header.get("alg", "").upper()

            if alg == "NONE":
                header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
                payload_b64 = base64.urlsafe_b64encode(json.dumps(modified_payload).encode()).decode().rstrip("=")
                return f"{header_b64}.{payload_b64}."

            if alg == "HS256":
                for secret in self.common_secrets:
                    try:
                        new_token = self.resign_jwt_hs256(header, modified_payload, secret)
                        if self.verify_jwt_signature(token, secret):
                            self.logger.info("Successfully found HS256 secret: %s", secret[:10])
                            return new_token
                    except Exception:
                        continue

            if alg == "RS256":
                if jwks_url:
                    public_key_pem = self.intercept_jwks_endpoint(jwks_url)
                    if public_key_pem:
                        try:
                            header["alg"] = "HS256"
                            new_token = self.resign_jwt_hs256(header, modified_payload, public_key_pem)
                            self.logger.info("Algorithm confusion attack successful using JWKS public key")
                            return new_token
                        except Exception as e:
                            self.logger.debug("JWKS algorithm confusion failed: %s", e)

                for url in list(self.captured_jwks.keys()):
                    try:
                        public_key_pem = self.captured_jwks[url]
                        header["alg"] = "HS256"
                        new_token = self.resign_jwt_hs256(header, modified_payload, public_key_pem)
                        self.logger.info("Algorithm confusion attack successful using cached JWKS")
                        return new_token
                    except Exception:
                        continue

                if CRYPTOGRAPHY_AVAILABLE:
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.hazmat.primitives import serialization

                    try:
                        if "kid" in header:
                            for captured_url, public_key_pem in self.captured_jwks.items():
                                from cryptography.hazmat.primitives.serialization import load_pem_public_key

                                public_key = load_pem_public_key(public_key_pem, default_backend())
                                public_key_bytes = public_key.public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                                )

                                header["alg"] = "HS256"
                                new_token = self.resign_jwt_hs256(header, modified_payload, public_key_bytes)
                                self.logger.info("Algorithm confusion with key ID matched")
                                return new_token
                    except Exception as e:
                        self.logger.debug("Advanced RS256 bypass failed: %s", e)

            return None

        except (ValueError, KeyError, json.JSONDecodeError) as e:
            self.logger.debug("JWT modification failed: %s", e)
            return None


class PyOpenSSLInterceptor:
    """Fallback SSL interceptor using pyOpenSSL for socket-level interception."""

    def __init__(
        self,
        listen_ip: str,
        listen_port: int,
        ca_cert_path: str,
        ca_key_path: str,
        target_hosts: list[str],
    ) -> None:
        """Initialize PyOpenSSL interceptor.

        Args:
            listen_ip: IP address to listen on
            listen_port: Port to listen on
            ca_cert_path: Path to CA certificate
            ca_key_path: Path to CA private key
            target_hosts: List of target hostnames to intercept

        """
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.target_hosts = target_hosts
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.server_socket: socket.socket | None = None
        self.server_thread: threading.Thread | None = None
        self.cert_cache: dict[str, tuple[str, str]] = {}
        self.cert_cache_lock = threading.Lock()
        self.jwt_modifier = JWTTokenModifier()

    def generate_cert_for_domain(self, domain: str) -> tuple[str, str] | None:
        """Generate a certificate for a specific domain.

        Args:
            domain: Domain name to generate certificate for

        Returns:
            Tuple of (cert_path, key_path) or None if failed

        """
        with self.cert_cache_lock:
            if domain in self.cert_cache:
                return self.cert_cache[domain]

        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.error("cryptography library not available")
            return None

        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

            with open(self.ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            with open(self.ca_key_path, "rb") as f:
                ca_key_data = f.read()
                ca_key = serialization.load_pem_private_key(ca_key_data, password=None, backend=default_backend())

            subject = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, domain),
                    x509.NameAttribute(NameOID.COMMON_NAME, domain),
                ]
            )

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(tz=datetime.timezone.utc))
                .not_valid_after(datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=365))
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(domain)]),
                    critical=False,
                )
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .sign(ca_key, hashes.SHA256(), default_backend())
            )

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )

            cert_fd, cert_path = tempfile.mkstemp(suffix=".crt", prefix=f"ic_{domain}_")
            key_fd, key_path = tempfile.mkstemp(suffix=".key", prefix=f"ic_{domain}_")

            with os.fdopen(cert_fd, "wb") as f:
                f.write(cert_pem)
            with os.fdopen(key_fd, "wb") as f:
                f.write(key_pem)

            with self.cert_cache_lock:
                self.cert_cache[domain] = (cert_path, key_path)

            return cert_path, key_path

        except (OSError, ValueError) as e:
            self.logger.error("Failed to generate certificate for %s: %s", domain, e)
            return None

    def modify_response(self, response_data: bytes) -> bytes:
        """Modify HTTP response to bypass license checks.

        Args:
            response_data: Original HTTP response bytes

        Returns:
            Modified HTTP response bytes

        """
        try:
            response_str = response_data.decode("utf-8", errors="ignore")

            headers_end = response_str.find("\r\n\r\n")
            if headers_end == -1:
                return response_data

            headers = response_str[:headers_end]
            body_bytes = response_data[headers_end + 4 :]

            content_type = ""
            content_encoding = ""
            is_chunked = False

            for line in headers.split("\r\n"):
                line_lower = line.lower()
                if line_lower.startswith("content-type:"):
                    content_type = line.split(":", 1)[1].strip().lower()
                elif line_lower.startswith("content-encoding:"):
                    content_encoding = line.split(":", 1)[1].strip().lower()
                elif line_lower.startswith("transfer-encoding:"):
                    if "chunked" in line.lower():
                        is_chunked = True

            if is_chunked:
                try:
                    body_bytes = self._decode_chunked(body_bytes)
                except Exception as e:
                    self.logger.debug("Failed to decode chunked encoding: %s", e)

            if content_encoding in ("gzip", "deflate"):
                try:
                    if content_encoding == "gzip":
                        body_bytes = gzip.decompress(body_bytes)
                    elif content_encoding == "deflate":
                        import zlib

                        body_bytes = zlib.decompress(body_bytes)
                except Exception as e:
                    self.logger.debug("Failed to decompress %s: %s", content_encoding, e)

            body = body_bytes.decode("utf-8", errors="ignore")
            modified_body = body

            if "json" in content_type:
                try:
                    data = json.loads(body)

                    if isinstance(data, str) and data.count(".") == 2:
                        if modified_token := self.jwt_modifier.attempt_jwt_modification(data):
                            modified_body = modified_token
                    elif isinstance(data, dict):
                        if "token" in data and isinstance(data["token"], str):
                            if modified_token := self.jwt_modifier.attempt_jwt_modification(data["token"]):
                                data["token"] = modified_token

                        if "status" in data:
                            data["status"] = "SUCCESS"
                        if "license" in data:
                            if isinstance(data["license"], dict):
                                data["license"]["status"] = "ACTIVATED"
                                data["license"]["type"] = "PERMANENT"
                            else:
                                data["license"] = "ACTIVATED"
                        if "isValid" in data:
                            data["isValid"] = True
                        if "valid" in data:
                            data["valid"] = True
                        if "expired" in data:
                            data["expired"] = False
                        if "expiry" in data:
                            data["expiry"] = "2099-12-31"

                        modified_body = json.dumps(data)

                except (ValueError, json.JSONDecodeError):
                    pass

            elif "xml" in content_type:
                modified_body = body.replace("<status>ERROR</status>", "<status>SUCCESS</status>")
                modified_body = modified_body.replace("<valid>false</valid>", "<valid>true</valid>")
                modified_body = modified_body.replace("<expired>true</expired>", "<expired>false</expired>")

            if modified_body != body:
                modified_body_bytes = modified_body.encode("utf-8")

                if content_encoding == "gzip":
                    modified_body_bytes = gzip.compress(modified_body_bytes)
                elif content_encoding == "deflate":
                    import zlib

                    modified_body_bytes = zlib.compress(modified_body_bytes)

                new_headers = []
                for line in headers.split("\r\n"):
                    line_lower = line.lower()
                    if line_lower.startswith("content-length:"):
                        new_headers.append(f"Content-Length: {len(modified_body_bytes)}")
                    elif line_lower.startswith("transfer-encoding:") and is_chunked:
                        continue
                    else:
                        new_headers.append(line)

                return b"\r\n".join(h.encode("utf-8") for h in new_headers) + b"\r\n\r\n" + modified_body_bytes

            return response_data

        except (ValueError, UnicodeDecodeError) as e:
            self.logger.debug("Response modification failed: %s", e)
            return response_data

    def _decode_chunked(self, data: bytes) -> bytes:
        """Decode HTTP chunked transfer encoding.

        Args:
            data: Chunked encoded data

        Returns:
            Decoded data bytes

        """
        result = bytearray()
        pos = 0

        while pos < len(data):
            chunk_size_end = data.find(b"\r\n", pos)
            if chunk_size_end == -1:
                break

            try:
                chunk_size_str = data[pos:chunk_size_end].decode("ascii")
                chunk_size = int(chunk_size_str.split(";")[0], 16)

                if chunk_size == 0:
                    break

                chunk_data_start = chunk_size_end + 2
                chunk_data_end = chunk_data_start + chunk_size

                if chunk_data_end + 2 > len(data):
                    break

                result.extend(data[chunk_data_start:chunk_data_end])

                pos = chunk_data_end + 2

            except (ValueError, UnicodeDecodeError):
                break

        return bytes(result)

    def handle_client(self, client_socket: socket.socket, client_address: tuple[str, int]) -> None:
        """Handle incoming client connection.

        Args:
            client_socket: Client socket connection
            client_address: Client address tuple (ip, port)

        """
        ssl_socket: ssl.SSLSocket | None = None

        try:
            first_bytes = client_socket.recv(1024, socket.MSG_PEEK)
            if not first_bytes:
                return

            is_connect = first_bytes.startswith(b"CONNECT ")

            if is_connect:
                connect_line = first_bytes.split(b"\r\n")[0].decode("utf-8")
                target = connect_line.split(" ")[1]
                host, port_str = target.split(":")
                port = int(port_str)

                client_socket.recv(len(first_bytes))
                client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                if any(target_host in host for target_host in self.target_hosts):
                    cert_key = self.generate_cert_for_domain(host)
                    if cert_key:
                        cert_path, key_path = cert_key
                        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        ssl_context.load_cert_chain(cert_path, key_path)
                        ssl_socket = ssl_context.wrap_socket(client_socket, server_side=True)

                        self.handle_https_connection(ssl_socket, host, port)
                        return

        except (OSError, ValueError) as e:
            self.logger.debug("Client handling error: %s", e)
        finally:
            try:
                if ssl_socket:
                    ssl_socket.close()
                else:
                    client_socket.close()
            except Exception:
                pass

    def handle_https_connection(self, client_ssl_socket: ssl.SSLSocket, target_host: str, target_port: int) -> None:
        """Handle HTTPS connection with target server.

        Args:
            client_ssl_socket: SSL socket for client connection
            target_host: Target server hostname
            target_port: Target server port

        """
        server_socket = None
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)

            server_context = ssl.create_default_context()
            server_context.check_hostname = False
            server_context.verify_mode = ssl.CERT_NONE

            server_ssl_socket = server_context.wrap_socket(server_socket, server_hostname=target_host)
            server_ssl_socket.connect((target_host, target_port))

            client_ssl_socket.setblocking(False)
            server_ssl_socket.setblocking(False)

            if sys.platform == "win32":
                import select

                while True:
                    readable, _, exceptional = select.select(
                        [client_ssl_socket, server_ssl_socket], [], [client_ssl_socket, server_ssl_socket], 1.0
                    )

                    if exceptional:
                        break

                    if client_ssl_socket in readable:
                        try:
                            data = client_ssl_socket.recv(8192)
                            if not data:
                                break
                            server_ssl_socket.sendall(data)
                        except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                            continue

                    if server_ssl_socket in readable:
                        try:
                            data = server_ssl_socket.recv(8192)
                            if not data:
                                break
                            modified_data = self.modify_response(data)
                            client_ssl_socket.sendall(modified_data)
                        except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                            continue
            else:
                import select

                while True:
                    readable, _, exceptional = select.select(
                        [client_ssl_socket, server_ssl_socket], [], [client_ssl_socket, server_ssl_socket], 1.0
                    )

                    if exceptional:
                        break

                    if client_ssl_socket in readable:
                        data = client_ssl_socket.recv(8192)
                        if not data:
                            break
                        server_ssl_socket.sendall(data)

                    if server_ssl_socket in readable:
                        data = server_ssl_socket.recv(8192)
                        if not data:
                            break
                        modified_data = self.modify_response(data)
                        client_ssl_socket.sendall(modified_data)

        except (OSError, ssl.SSLError) as e:
            self.logger.debug("HTTPS connection error: %s", e)
        finally:
            try:
                client_ssl_socket.close()
            except Exception:
                pass
            if server_socket:
                try:
                    server_socket.close()
                except Exception:
                    pass

    def run_server(self) -> None:
        """Run the interceptor server loop."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.listen_ip, self.listen_port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)

            self.logger.info("PyOpenSSL interceptor listening on %s:%s", self.listen_ip, self.listen_port)

            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client, args=(client_socket, client_address), daemon=True
                    )
                    client_thread.start()
                except socket.timeout:
                    continue
                except OSError as e:
                    if self.running:
                        self.logger.error("Accept error: %s", e)
                    break

        except OSError as e:
            self.logger.error("Server error: %s", e)
        finally:
            if self.server_socket:
                try:
                    self.server_socket.close()
                except Exception:
                    pass

    def start(self) -> bool:
        """Start the PyOpenSSL interceptor.

        Returns:
            True if started successfully, False otherwise

        """
        if self.running:
            return False

        self.running = True
        self.server_thread = threading.Thread(target=self.run_server, daemon=True)
        self.server_thread.start()
        return True

    def stop(self) -> None:
        """Stop the PyOpenSSL interceptor."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

        with self.cert_cache_lock:
            for cert_path, key_path in self.cert_cache.values():
                try:
                    os.unlink(cert_path)
                    os.unlink(key_path)
                except OSError:
                    pass
            self.cert_cache.clear()


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

        from ...utils.system.windows_structures import COMMON_LICENSE_DOMAINS

        self.config: dict[str, Any] = {
            "listen_ip": "127.0.0.1",
            "listen_port": 8443,
            "target_hosts": COMMON_LICENSE_DOMAINS,
            "ca_cert_path": str(CA_CERT_PATH),
            "ca_key_path": str(CA_KEY_PATH),
            "record_traffic": True,
            "auto_respond": True,
        }

        if config:
            self.config |= config

        self.proxy_server: Any = None
        self.ca_cert: bytes | None = None
        self.ca_key: bytes | None = None
        self.traffic_log: list[dict[str, Any]] = []
        self.proxy_process: Popen[str] | None = None
        self.fallback_interceptor: PyOpenSSLInterceptor | None = None
        self.jwt_modifier = JWTTokenModifier()
        self.mitm_script_path: str | None = None

    def check_mitmproxy_available(self) -> bool:
        """Check if mitmproxy is available for SSL interception.

        Returns:
            True if mitmproxy is available, False otherwise

        """
        return MITMPROXY_AVAILABLE

    def check_fallback_available(self) -> bool | None:
        """Check if pyOpenSSL fallback is available for SSL interception.

        Returns:
            True if pyOpenSSL is available, None if neither is available

        """
        if PYOPENSSL_AVAILABLE:
            return True
        return None

    def generate_ca_certificate(self) -> tuple[bytes | None, bytes | None]:
        """Generate a CA certificate for SSL/TLS interception.

        Returns:
            Tuple of (certificate, key) as PEM bytes, or (None, None) if failed

        """
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.exception("cryptography library not available - cannot generate CA certificate")
            return None, None

        try:
            from ...utils.protection.certificate_utils import generate_self_signed_cert

            if cert_result := generate_self_signed_cert(
                common_name="Intellicrack Root CA",
                organization="Intellicrack CA",
                state="California",
                locality="San Francisco",
                valid_days=3650,
            ):
                return cert_result
            self.logger.exception("Failed to generate CA certificate")
            return None, None

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error generating CA certificate: %s", e)
            return None, None

    def start(self) -> bool:
        """Start the SSL/TLS interceptor.

        Returns:
            True if started successfully, False otherwise

        """
        try:
            # Generate CA certificate if needed
            ca_cert_path = get_typed_item(self.config, "ca_cert_path", str)
            ca_key_path = get_typed_item(self.config, "ca_key_path", str)
            if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
                self.logger.info("Generating CA certificate...")
                cert_pem, key_pem = self.generate_ca_certificate()
                if cert_pem and key_pem:
                    # Create directory if it doesn't exist
                    os.makedirs(os.path.dirname(os.path.abspath(ca_cert_path)), exist_ok=True)

                    # Save certificate and key
                    with open(ca_cert_path, "wb") as f:
                        f.write(cert_pem)
                    with open(ca_key_path, "wb") as f:
                        f.write(key_pem)

                    self.logger.info("CA certificate saved to %s", self.config["ca_cert_path"])
                else:
                    self.logger.exception("Failed to generate CA certificate")
                    return False

            if mitmdump_path := self._find_executable("mitmdump"):
                try:
                    script_fd, script_path = tempfile.mkstemp(suffix=".py", prefix="intellicrack_mitm_")
                    self.mitm_script_path = script_path
                except OSError as e:
                    self.logger.error("Failed to create temporary script file: %s", e)
                    return False

                try:
                    with os.fdopen(script_fd, "w", encoding="utf-8") as f:
                        f.write(f"""
import json
import base64
import hmac
import hashlib
import datetime
from mitmproxy import http

LICENSE_ENDPOINTS = {self.config["target_hosts"]}

def decode_jwt_without_verification(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_part = parts[1]
        padding = 4 - len(payload_part) % 4
        if padding != 4:
            payload_part += "=" * padding
        payload_bytes = base64.urlsafe_b64decode(payload_part)
        return json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return None

def modify_jwt_payload(payload):
    modified = payload.copy()
    future_date = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)).isoformat()
    future_timestamp = int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)).timestamp())

    mappings = {{
        "exp": future_timestamp, "expiry": future_date, "expiration": future_date,
        "valid_until": future_date, "expires_at": future_timestamp,
        "license_status": "active", "status": "active", "is_valid": True,
        "valid": True, "is_active": True, "active": True, "is_expired": False,
        "expired": False, "license_type": "perpetual", "type": "perpetual",
        "tier": "enterprise", "plan": "enterprise", "features": ["all"],
        "entitlements": ["full_access"], "max_users": 999999, "max_seats": 999999,
        "seats": 999999, "trial": False, "is_trial": False,
    }}

    for key, value in mappings.items():
        if key in modified:
            modified[key] = value
    return modified

def resign_jwt_hs256(header, payload, secret):
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    message = f"{{header_b64}}.{{payload_b64}}"
    signature = hmac.new(secret, message.encode(), hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{{message}}.{{signature_b64}}"

def attempt_jwt_modification(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64 = parts[0]
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        payload = decode_jwt_without_verification(token)
        if not payload:
            return None
        modified_payload = modify_jwt_payload(payload)
        alg = header.get("alg", "").upper()

        if alg == "NONE":
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
            payload_b64 = base64.urlsafe_b64encode(json.dumps(modified_payload).encode()).decode().rstrip("=")
            return f"{{header_b64}}.{{payload_b64}}."

        if alg == "HS256":
            for secret in [b"secret", b"password", b"12345678", b"changeme", b"default", b"admin", b"test"]:
                try:
                    return resign_jwt_hs256(header, modified_payload, secret)
                except Exception:
                    continue

        if alg == "RS256":
            try:
                header["alg"] = "HS256"
                return resign_jwt_hs256(header, modified_payload, b"secret")
            except Exception:
                pass
        return None
    except Exception:
        return None

def request(flow: http.HTTPFlow) -> None:
    if any(endpoint in flow.request.pretty_host for endpoint in LICENSE_ENDPOINTS):
        print(f"Intercepted license verification request to {{flow.request.pretty_host}}")
        with open('license_requests.log', 'a', encoding='utf-8') as f:
            f.write(f"\\n=== REQUEST to {{flow.request.pretty_host}} ===\\n")
            f.write(f"Method: {{flow.request.method}}\\n")
            f.write(f"Path: {{flow.request.path}}\\n")
            f.write(f"Headers: {{flow.request.headers}}\\n")
            f.write(f"Content: {{flow.request.content}}\\n")

def response(flow: http.HTTPFlow) -> None:
    if any(endpoint in flow.request.pretty_host for endpoint in LICENSE_ENDPOINTS):
        print(f"Intercepted license verification response from {{flow.request.pretty_host}}")
        with open('license_responses.log', 'a', encoding='utf-8') as f:
            f.write(f"\\n=== RESPONSE from {{flow.request.pretty_host}} ===\\n")
            f.write(f"Status: {{flow.response.status_code}}\\n")
            f.write(f"Headers: {{flow.response.headers}}\\n")
            f.write(f"Content: {{flow.response.content}}\\n")

        content_type = flow.response.headers.get('Content-Type', '')

        if 'json' in content_type:
            try:
                data = json.loads(flow.response.content)

                if isinstance(data, str) and data.count(".") == 2:
                    if modified_token := attempt_jwt_modification(data):
                        flow.response.content = json.dumps(modified_token).encode('utf-8')
                        print(f"Modified JWT token in response")
                        return
                elif isinstance(data, dict):
                    if "token" in data and isinstance(data["token"], str):
                        if modified_token := attempt_jwt_modification(data["token"]):
                            data["token"] = modified_token
                            print(f"Modified JWT token in response data")

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

                    flow.response.content = json.dumps(data).encode('utf-8')
                    print(f"Modified license response: {{data}}")
            except Exception as e:
                print(f"Error parsing JSON response: {{e}}")
        elif 'xml' in content_type:
            content = flow.response.content.decode('utf-8', errors='ignore')
            content = content.replace('<status>ERROR</status>', '<status>SUCCESS</status>')
            content = content.replace('<valid>false</valid>', '<valid>true</valid>')
            content = content.replace('<expired>true</expired>', '<expired>false</expired>')
            flow.response.content = content.encode('utf-8')
""")
                except OSError as e:
                    self.logger.error("Failed to write mitmproxy script: %s", e)
                    if self.mitm_script_path and os.path.exists(self.mitm_script_path):
                        try:
                            os.unlink(self.mitm_script_path)
                        except OSError:
                            pass
                        self.mitm_script_path = None
                    return False

                # Start mitmproxy
                listen_ip = get_typed_item(self.config, "listen_ip", str)
                listen_port = get_typed_item(self.config, "listen_port", int)
                cmd: list[str] = [
                    mitmdump_path,
                    "-s",
                    script_path,
                    "--listen-host",
                    listen_ip,
                    "--listen-port",
                    str(listen_port),
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

                if self.proxy_process is not None:
                    self.logger.info("mitmproxy started with PID %s", self.proxy_process.pid)
                    self.logger.info(
                        "SSL/TLS interceptor started on %s:%s",
                        self.config["listen_ip"],
                        self.config["listen_port"],
                    )
            else:
                self.logger.warning("mitmproxy not found. Falling back to PyOpenSSL interceptor.")

                if not CRYPTOGRAPHY_AVAILABLE:
                    self.logger.error("cryptography library required for fallback SSL interception")
                    return False

                listen_ip = get_typed_item(self.config, "listen_ip", str)
                listen_port = get_typed_item(self.config, "listen_port", int)
                target_hosts = validate_type(self.config["target_hosts"], list)

                self.fallback_interceptor = PyOpenSSLInterceptor(
                    listen_ip=listen_ip,
                    listen_port=listen_port,
                    ca_cert_path=ca_cert_path,
                    ca_key_path=ca_key_path,
                    target_hosts=target_hosts,
                )

                if not self.fallback_interceptor.start():
                    self.logger.error("Failed to start PyOpenSSL fallback interceptor")
                    return False

                self.logger.info(
                    "PyOpenSSL fallback interceptor started on %s:%s",
                    listen_ip,
                    listen_port,
                )

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
            self.logger.exception("Error starting SSL/TLS interceptor: %s", e)
            return False

    def stop(self) -> bool:
        """Stop the SSL/TLS interceptor.

        Returns:
            True if stopped successfully, False otherwise

        """
        try:
            if self.proxy_process is not None:
                self.proxy_process.terminate()
                self.proxy_process = None

            if self.fallback_interceptor is not None:
                self.fallback_interceptor.stop()
                self.fallback_interceptor = None

            if self.mitm_script_path and os.path.exists(self.mitm_script_path):
                try:
                    os.unlink(self.mitm_script_path)
                    self.mitm_script_path = None
                except OSError as e:
                    self.logger.warning("Failed to clean up mitmproxy script: %s", e)

            self.logger.info("SSL/TLS interceptor stopped")
            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error stopping SSL/TLS interceptor: %s", e)
            return False

    def _find_executable(self, executable: str) -> str | None:
        """Find the path to an executable using the path discovery system.

        Args:
            executable: Name of the executable

        Returns:
            Path to the executable, or None if not found

        """
        from ...utils.core.path_discovery import find_tool

        if path := find_tool(executable):
            return path

        # Fallback to simple PATH search for tools not in path_discovery specs
        import shutil

        return shutil.which(executable)

    def get_traffic_log(self) -> list[dict[str, Any]]:
        """Get the captured traffic log.

        Returns:
            List of captured traffic entries

        """
        return self.traffic_log.copy()

    def add_target_host(self, host: str) -> None:
        """Add a target host for interception.

        Args:
            host: Hostname to intercept

        """
        target_hosts = validate_type(self.config["target_hosts"], list)
        if host not in target_hosts:
            target_hosts.append(host)
            self.logger.info("Added target host: %s", host)

    def remove_target_host(self, host: str) -> None:
        """Remove a target host from interception.

        Args:
            host: Hostname to remove

        """
        target_hosts = validate_type(self.config["target_hosts"], list)
        if host in target_hosts:
            target_hosts.remove(host)
            self.logger.info("Removed target host: %s", host)

    def get_target_hosts(self) -> list[str]:
        """Get the list of target hosts.

        Returns:
            List of target hostnames

        """
        target_hosts = validate_type(self.config["target_hosts"], list)
        return target_hosts.copy()

    def configure(self, config: dict[str, Any]) -> bool:
        """Configure SSL/TLS interception settings.

        This method allows dynamic configuration of the SSL/TLS interceptor,
        including proxy settings, target hosts, certificate paths, and behavior options.

        Args:
            config: Configuration dictionary with settings to update

        Returns:
            True if configuration was successful, False otherwise

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

            if invalid_keys := set(config.keys()) - valid_keys:
                self.logger.warning("Ignoring invalid configuration keys: %s", invalid_keys)

            # Validate specific settings
            if "listen_port" in config:
                port = config["listen_port"]
                if not isinstance(port, int) or port < 1 or port > 65535:
                    self.logger.exception("Invalid port number: %s", port)
                    return False

            if "listen_ip" in config:
                ip = config["listen_ip"]
                # Basic IP validation
                import socket

                try:
                    socket.inet_aton(ip)
                except OSError:
                    self.logger.exception("Invalid IP address: %s", ip)
                    return False

            if "target_hosts" in config and not isinstance(config["target_hosts"], list):
                self.logger.exception("target_hosts must be a list")
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
                ca_cert_path = get_typed_item(self.config, "ca_cert_path", str)
                ca_key_path = get_typed_item(self.config, "ca_key_path", str)
                if not os.path.exists(ca_cert_path):
                    self.logger.warning("CA certificate not found at %s", ca_cert_path)
                    # Generate new certificate if needed
                    self.logger.info("Generating new CA certificate")
                    cert, key = self.generate_ca_certificate()
                    if not cert or not key:
                        self.logger.exception("Failed to generate CA certificate")
                        self.config = old_config  # Restore old config
                        return False

                if not os.path.exists(ca_key_path):
                    self.logger.exception("CA key not found at %s", ca_key_path)
                    self.config = old_config
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
                    self.logger.exception("Failed to restart interceptor")
                    self.config = old_config  # Restore old config
                    return False

            self.logger.info("Configuration updated successfully")

            self.logger.debug("Current configuration: %s", self._get_safe_config())

            return True

        except Exception as e:
            self.logger.exception("Error configuring SSL/TLS interceptor: %s", e)
            return False

    def get_config(self) -> dict[str, Any]:
        """Get current configuration with sensitive data redacted.

        Returns the current configuration of the SSL/TLS interceptor with
        sensitive information like private keys redacted for security.

        Returns:
            Dictionary containing current configuration settings

        """
        return self._get_safe_config()

    def _get_safe_config(self) -> dict[str, Any]:
        """Get configuration with sensitive data redacted.

        Returns:
            Dictionary containing current configuration with sensitive information redacted

        """
        safe_config = self.config.copy()

        # Redact sensitive information
        if "ca_key_path" in safe_config:
            ca_key_path_val = get_typed_item(self.config, "ca_key_path", str)
            safe_config["ca_key_path"] = "<redacted>" if os.path.exists(ca_key_path_val) else "not found"

        # Add runtime status
        ca_cert_path = get_typed_item(self.config, "ca_cert_path", str)
        ca_key_path = get_typed_item(self.config, "ca_key_path", str)
        safe_config["status"] = {
            "running": self.proxy_process is not None,
            "traffic_captured": len(self.traffic_log),
            "ca_cert_exists": os.path.exists(ca_cert_path),
            "ca_key_exists": os.path.exists(ca_key_path),
        }

        return safe_config


__all__ = ["SSLTLSInterceptor", "JWTTokenModifier", "PyOpenSSLInterceptor"]
