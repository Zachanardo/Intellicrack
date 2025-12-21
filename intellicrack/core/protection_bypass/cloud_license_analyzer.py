"""Cloud-based license server analyzer for intercepting and bypassing online activation."""

import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import os
import pickle  # noqa: S403
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import frida
import jwt
import mitmproxy.http
import requests
import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster


# Token type constants (not passwords)
TOKEN_TYPE_COOKIE = "cookie"  # noqa: S105
TOKEN_TYPE_JWT = "jwt"  # noqa: S105
TOKEN_TYPE_BEARER = "bearer"  # noqa: S105
TOKEN_TYPE_API_KEY = "api_key"  # noqa: S105
TOKEN_TYPE_LICENSE_KEY = "license_key"  # noqa: S105

try:
    import xmltodict
except ImportError:
    xmltodict = None  # type: ignore[assignment]

from typing import TYPE_CHECKING, Any as FridaSession, Any as FridaScript

if TYPE_CHECKING:
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.options import Options

logger = logging.getLogger(__name__)


@dataclass
class CloudEndpoint:
    """Discovered cloud license server endpoint with captured metadata."""

    url: str
    method: str
    headers: dict[str, str]
    parameters: dict[str, Any]
    response_schema: dict[str, Any]
    authentication_type: str
    rate_limit: int | None = None
    last_seen: datetime = field(default_factory=datetime.now)


@dataclass
class LicenseToken:
    """Extracted or generated license token for cloud license systems."""

    token_type: str
    value: str
    expires_at: datetime | None
    refresh_token: str | None
    scope: list[str] | None
    metadata: dict[str, Any] = field(default_factory=dict)


class CloudLicenseAnalyzer:
    """MITM proxy-based analyzer for intercepting and manipulating cloud license traffic."""

    def __init__(self) -> None:
        """Initialize the MITMProxyAnalyzer with interception data structures and proxy settings."""
        self.intercepted_requests: list[dict[str, Any]] = []
        self.discovered_endpoints: dict[str, CloudEndpoint] = {}
        self.license_tokens: dict[str, LicenseToken] = {}
        self.api_schemas: dict[str, Any] = {}
        self.proxy_port: int = 8080
        self.ca_cert: bytes | None = None
        self.ca_key: bytes | None = None
        self.proxy_thread: threading.Thread | None = None
        self.frida_session: FridaSession | None = None
        self.target_process: int | None = None
        self.proxy_options: Options
        self.proxy_master: DumpMaster
        self._init_certificates()
        self._init_proxy()

    def _init_certificates(self) -> None:
        ca_path = Path(__file__).parent / "certs"
        ca_path.mkdir(exist_ok=True)

        cert_file = ca_path / "ca.crt"
        key_file = ca_path / "ca.key"

        if cert_file.exists() and key_file.exists():
            self.ca_cert = cert_file.read_bytes()
            self.ca_key = key_file.read_bytes()
        else:
            self._generate_ca_certificate(cert_file, key_file)

    def _generate_ca_certificate(self, cert_file: Path, key_file: Path) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intellicrack CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Intellicrack Root CA"),
            ],
        )

        cert = (
            x509
            .CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )

        self.ca_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        self.ca_cert = cert.public_bytes(serialization.Encoding.PEM)

        key_file.write_bytes(self.ca_key)
        cert_file.write_bytes(self.ca_cert)

    def _init_proxy(self) -> None:
        self.proxy_options = options.Options(
            listen_port=self.proxy_port,
            ssl_insecure=True,
            confdir=str(Path(__file__).parent / "mitmproxy_config"),
        )

        self.proxy_master = DumpMaster(self.proxy_options, with_termlog=False, with_dumper=False)

        self.proxy_master.addons.add(CloudInterceptor(self))

    def generate_host_certificate(self, hostname: str) -> tuple[bytes, bytes]:
        """Generate SSL certificate for intercepting HTTPS traffic to specific host."""
        if self.ca_key is None or self.ca_cert is None:
            raise ValueError("CA certificate and key must be initialized before generating host certificates")

        ca_key_obj = serialization.load_pem_private_key(self.ca_key, password=None, backend=default_backend())

        ca_cert_obj = x509.load_pem_x509_certificate(self.ca_cert, backend=default_backend())

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, hostname),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ],
        )

        cert = (
            x509
            .CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert_obj.issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(hostname),
                        x509.DNSName(f"*.{hostname}"),
                    ],
                ),
                critical=False,
            )
            .sign(ca_key_obj, hashes.SHA256(), default_backend())  # type: ignore[arg-type]
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cert_pem, key_pem

    def start_interception(self, target_process: int | None = None) -> None:
        """Start MITM proxy to intercept cloud license traffic from target process."""
        self.target_process = target_process

        if target_process:
            self._inject_proxy_settings(target_process)

        proxy_thread = threading.Thread(target=self._run_proxy, daemon=True)
        proxy_thread.start()
        self.proxy_thread = proxy_thread

        logger.info("TLS interception proxy started on port %d", self.proxy_port)

    def _run_proxy(self) -> None:
        asyncio.set_event_loop(asyncio.new_event_loop())
        self.proxy_master.run()

    def _inject_proxy_settings(self, pid: int) -> None:
        try:
            session: FridaSession = frida.attach(pid)
            script_code = self._generate_proxy_injection_script()
            script: FridaScript = session.create_script(script_code)
            script.on("message", self._on_frida_message)
            script.load()
            self.frida_session = session
        except Exception as e:
            logger.exception("Failed to inject proxy settings: %s", e)

    def _generate_proxy_injection_script(self) -> str:
        return (
            """
        'use strict';

        // Hook WinHTTP
        if (Process.platform === 'windows') {
            const winhttp = Module.load('winhttp.dll');

            const WinHttpOpen = winhttp.getExportByName('WinHttpOpen');
            const WinHttpSetOption = winhttp.getExportByName('WinHttpSetOption');

            Interceptor.attach(WinHttpOpen, {
                onEnter: function(args) {
                    // Force proxy usage
                    this.accessType = args[1];
                    args[1] = ptr(3); // WINHTTP_ACCESS_TYPE_NAMED_PROXY
                    args[2] = Memory.allocUtf16String('http://127.0.0.1:"""
            + str(self.proxy_port)
            + """');
                },
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        send({type: 'winhttp_session', handle: retval.toString()});
                    }
                }
            });

            // Disable certificate validation
            const WINHTTP_OPTION_SECURITY_FLAGS = 31;
            const SECURITY_FLAG_IGNORE_ALL = 0x3300;

            Interceptor.attach(WinHttpSetOption, {
                onEnter: function(args) {
                    const option = args[1].toInt32();
                    if (option === WINHTTP_OPTION_SECURITY_FLAGS) {
                        const buffer = Memory.alloc(4);
                        buffer.writeU32(SECURITY_FLAG_IGNORE_ALL);
                        args[2] = buffer;
                    }
                }
            });
        }

        // Hook OpenSSL
        const ssl_libs = ['libssl.so', 'ssleay32.dll', 'libssl-1_1.dll', 'libssl-3.dll'];
        let ssl_module = null;

        for (const lib of ssl_libs) {
            try {
                ssl_module = Module.load(lib);
                break;
            } catch (e) {}
        }

        if (ssl_module) {
            // Hook SSL_CTX_set_verify to disable certificate verification
            const SSL_CTX_set_verify = ssl_module.findExportByName('SSL_CTX_set_verify');
            if (SSL_CTX_set_verify) {
                Interceptor.attach(SSL_CTX_set_verify, {
                    onEnter: function(args) {
                        args[1] = ptr(0); // SSL_VERIFY_NONE
                    }
                });
            }

            // Hook SSL_get_verify_result to always return success
            const SSL_get_verify_result = ssl_module.findExportByName('SSL_get_verify_result');
            if (SSL_get_verify_result) {
                Interceptor.replace(SSL_get_verify_result, new NativeCallback(function() {
                    return 0; // X509_V_OK
                }, 'long', ['pointer']));
            }
        }

        // Hook .NET HttpClient
        if (Process.platform === 'windows') {
            try {
                const clr = Module.load('clr.dll');

                // Hook certificate validation callbacks
                const patterns = [
                    '55 8B EC 83 EC ?? 53 56 57 8B F1 8B DA', // Certificate validation pattern
                    '48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F9' // x64 pattern
                ];

                for (const pattern of patterns) {
                    Memory.scan(clr.base, clr.size, pattern, {
                        onMatch: function(address, size) {
                            Interceptor.attach(address, {
                                onLeave: function(retval) {
                                    retval.replace(1); // Always return valid
                                }
                            });
                        }
                    });
                }
            } catch (e) {}
        }

        // Hook curl
        const curl_libs = ['libcurl.so', 'libcurl.dll', 'curl.dll'];
        let curl_module = null;

        for (const lib of curl_libs) {
            try {
                curl_module = Module.load(lib);
                break;
            } catch (e) {}
        }

        if (curl_module) {
            const curl_easy_setopt = curl_module.findExportByName('curl_easy_setopt');
            if (curl_easy_setopt) {
                const CURLOPT_PROXY = 10004;
                const CURLOPT_SSL_VERIFYPEER = 64;
                const CURLOPT_SSL_VERIFYHOST = 81;

                Interceptor.attach(curl_easy_setopt, {
                    onEnter: function(args) {
                        const option = args[1].toInt32();

                        if (option === CURLOPT_SSL_VERIFYPEER || option === CURLOPT_SSL_VERIFYHOST) {
                            args[2] = ptr(0); // Disable verification
                        }

                        if (option === CURLOPT_PROXY) {
                            // Override with our proxy
                            args[2] = Memory.allocUtf8String('http://127.0.0.1:"""
            + str(self.proxy_port)
            + """');
                        }
                    }
                });
            }
        }

        send({type: 'hooks_installed'});
        """
        )

    def _on_frida_message(self, message: dict[str, object], data: object) -> None:
        """Handle Frida script messages from injected proxy hooks.

        Args:
            message: Message dictionary from Frida script containing type and payload.
            data: Binary data associated with message, if any.

        """
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("type") == "hooks_installed":
                logger.info("Proxy hooks successfully installed in target process")

    def analyze_endpoint(self, request: mitmproxy.http.Request, response: mitmproxy.http.Response) -> CloudEndpoint:
        """Analyze intercepted HTTP request/response to extract endpoint metadata."""
        url = request.pretty_url
        method = request.method
        headers = dict(request.headers)

        parameters = {}
        if request.query:
            parameters["query"] = dict(request.query)

        if request.content:
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type:
                try:
                    parameters["body"] = json.loads(request.content)
                except (json.JSONDecodeError, ValueError):
                    parameters["body"] = request.content.decode("utf-8", errors="ignore")
            elif "application/x-www-form-urlencoded" in content_type:
                parameters["body"] = dict(parse_qs(request.content.decode("utf-8")))
            elif "text/xml" in content_type or "application/xml" in content_type:
                try:
                    parameters["body"] = xmltodict.parse(request.content)
                except (xmltodict.expat.ExpatError, ValueError):
                    parameters["body"] = request.content.decode("utf-8", errors="ignore")
            else:
                parameters["body"] = request.content.decode("utf-8", errors="ignore")

        response_schema = self._analyze_response_schema(response)
        auth_type = self._detect_authentication_type(request)

        endpoint = CloudEndpoint(
            url=url,
            method=method,
            headers=headers,
            parameters=parameters,
            response_schema=response_schema,
            authentication_type=auth_type,
        )

        endpoint_key = f"{method}:{urlparse(url).path}"
        self.discovered_endpoints[endpoint_key] = endpoint

        return endpoint

    def _analyze_response_schema(self, response: mitmproxy.http.Response) -> dict[str, Any]:
        schema = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_type": response.headers.get("content-type", ""),
        }

        if response.content:
            content_type = response.headers.get("content-type", "")

            if "application/json" in content_type:
                with contextlib.suppress(ValueError, TypeError):
                    data = json.loads(response.content)
                    schema["body_schema"] = self._extract_json_schema(data)
                    schema["body_sample"] = data
            elif "text/xml" in content_type or "application/xml" in content_type:
                with contextlib.suppress(ValueError, TypeError):
                    data = xmltodict.parse(response.content)
                    schema["body_schema"] = self._extract_json_schema(data)
                    schema["body_sample"] = data
        return schema

    def _extract_json_schema(self, data: object, depth: int = 0) -> dict[str, object]:
        if depth > 5:
            return {"type": "any"}

        if isinstance(data, dict):
            properties = {key: self._extract_json_schema(value, depth + 1) for key, value in data.items()}
            return {"type": "object", "properties": properties}
        if isinstance(data, list):
            if data:
                return {"type": "array", "items": self._extract_json_schema(data[0], depth + 1)}
            return {"type": "array", "items": {"type": "any"}}
        if isinstance(data, str):
            return {"type": "string", "example": data[:100] if len(data) > 100 else data}
        if isinstance(data, (int, float)):
            return {"type": "number", "example": data}
        if isinstance(data, bool):
            return {"type": "boolean", "example": data}
        return {"type": "any"}

    def _detect_authentication_type(self, request: mitmproxy.http.Request) -> str:
        auth_header = request.headers.get("authorization", "").lower()

        if auth_header.startswith("bearer "):
            token = auth_header[7:]
            return "jwt" if self._is_jwt_token(token) else "bearer_token"
        if auth_header.startswith("basic "):
            return "basic"
        if auth_header.startswith("digest "):
            return "digest"
        if "api-key" in request.headers or "x-api-key" in request.headers:
            return "api_key"
        if "oauth" in auth_header:
            return "oauth"
        if request.cookies:
            for cookie_name in request.cookies:
                if "session" in cookie_name.lower() or "token" in cookie_name.lower():
                    return "cookie_based"

        return "unknown"

    def _is_jwt_token(self, token: str) -> bool:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False

            for part in parts[:2]:
                base64.urlsafe_b64decode(part + "=" * (4 - len(part) % 4))

            return True
        except OSError:
            return False

    def extract_license_tokens(self, request: mitmproxy.http.Request, response: mitmproxy.http.Response) -> list[LicenseToken]:
        """Extract license tokens from intercepted HTTP traffic."""
        tokens = []

        if auth_header := request.headers.get("authorization", ""):
            if auth_header.startswith("Bearer "):
                token_value = auth_header[7:]
                if token := self._analyze_bearer_token(token_value):
                    tokens.append(token)

        if response.content:
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                with contextlib.suppress(json.JSONDecodeError, ValueError):
                    data = json.loads(response.content)
                    tokens.extend(self._extract_tokens_from_json(data))
        for cookie in response.cookies:
            if "token" in cookie.lower() or "session" in cookie.lower():
                token = LicenseToken(
                    token_type=TOKEN_TYPE_COOKIE,
                    value=response.cookies[cookie],
                    expires_at=None,
                    refresh_token=None,
                    scope=None,
                    metadata={"cookie_name": cookie},
                )
                tokens.append(token)

        return tokens

    def _analyze_bearer_token(self, token_value: str) -> LicenseToken | None:
        if self._is_jwt_token(token_value):
            with contextlib.suppress(ValueError, TypeError):
                header = jwt.get_unverified_header(token_value)
                payload = jwt.decode(token_value, options={"verify_signature": False})

                expires_at = None
                if "exp" in payload:
                    expires_at = datetime.fromtimestamp(payload["exp"])

                scope = payload.get("scope", "").split() if "scope" in payload else None

                return LicenseToken(
                    token_type=TOKEN_TYPE_JWT,
                    value=token_value,
                    expires_at=expires_at,
                    refresh_token=None,
                    scope=scope,
                    metadata={"header": header, "payload": payload},
                )
        return LicenseToken(
            token_type=TOKEN_TYPE_BEARER,
            value=token_value,
            expires_at=None,
            refresh_token=None,
            scope=None,
        )

    def _extract_tokens_from_json(self, data: object, tokens: list[LicenseToken] | None = None) -> list[LicenseToken]:
        if tokens is None:
            tokens = []

        if isinstance(data, dict):
            token_fields = ["access_token", "token", "license_key", "api_key", "session_token"]
            refresh_fields = ["refresh_token", "renewal_token"]

            token_value = None
            refresh_value = None

            for field in token_fields:
                if field in data:
                    token_value = data[field]
                    break

            for field in refresh_fields:
                if field in data:
                    refresh_value = data[field]
                    break

            if token_value:
                expires_at = None
                if "expires_in" in data:
                    expires_at = datetime.now() + timedelta(seconds=data["expires_in"])
                elif "expires_at" in data:
                    with contextlib.suppress(ValueError, TypeError):
                        expires_at = datetime.fromisoformat(data["expires_at"])

                scope = None
                if "scope" in data:
                    scope = data["scope"].split() if isinstance(data["scope"], str) else data["scope"]

                token = LicenseToken(
                    token_type=data.get("token_type", "unknown"),
                    value=token_value,
                    expires_at=expires_at,
                    refresh_token=refresh_value,
                    scope=scope,
                    metadata={k: v for k, v in data.items() if k not in ["access_token", "token", "refresh_token"]},
                )
                tokens.append(token)

            for value in data.values():
                if isinstance(value, (dict, list)):
                    self._extract_tokens_from_json(value, tokens)

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self._extract_tokens_from_json(item, tokens)

        return tokens

    def generate_token(self, token_type: str, **kwargs: Any) -> str:
        """Generate valid license token of specified type for bypassing cloud checks."""
        if token_type == TOKEN_TYPE_JWT:
            return self._generate_jwt_token(**kwargs)
        if token_type == TOKEN_TYPE_API_KEY:
            return self._generate_api_key(**kwargs)
        if token_type == TOKEN_TYPE_LICENSE_KEY:
            return self._generate_license_key(**kwargs)
        return self._generate_generic_token(**kwargs)

    def _generate_jwt_token(
        self,
        issuer: str = "intellicrack",
        subject: str = "user",
        audience: str | None = None,
        expires_in: int = 3600,
        claims: dict[str, object] | None = None,
        **kwargs: Any,
    ) -> str:
        now = datetime.utcnow()

        payload: dict[str, Any] = {
            "iss": issuer,
            "sub": subject,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
            "jti": hashlib.sha256(os.urandom(32)).hexdigest(),
        }

        if audience:
            payload["aud"] = audience

        if claims:
            payload |= claims

        secret_raw = kwargs.get("secret", "intellicrack-secret-key")
        algorithm_raw = kwargs.get("algorithm", "HS256")

        secret: str | bytes = secret_raw if isinstance(secret_raw, (str, bytes)) else "intellicrack-secret-key"
        algorithm: str = algorithm_raw if isinstance(algorithm_raw, str) else "HS256"

        if algorithm.startswith("RS"):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            private_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            secret = private_pem

        return jwt.encode(payload, secret, algorithm=algorithm)

    def _generate_api_key(self, prefix: str = "ik", length: int = 32, **kwargs: Any) -> str:
        random_bytes = os.urandom(length)
        key = base64.urlsafe_b64encode(random_bytes).decode("utf-8")[:length]
        return f"{prefix}_{key}"

    def _generate_license_key(self, format: str = "4-4-4-4", **kwargs: Any) -> str:
        import string

        chars = string.ascii_uppercase + string.digits

        # Parse format string: '4-4-4-4' means 4 chars, dash, 4 chars, etc.
        parts = format.split("-")
        key_parts = []

        for part in parts:
            try:
                length = int(part)
                segment = "".join(secrets.choice(chars) for _ in range(length))
                key_parts.append(segment)
            except ValueError:
                # If not a number, use the literal value
                key_parts.append(part)

        return "-".join(key_parts)

    def _generate_generic_token(self, length: int = 64, **kwargs: Any) -> str:
        return hashlib.sha256(os.urandom(32)).hexdigest()[:length]

    def refresh_token(self, token: LicenseToken) -> LicenseToken | None:
        """Attempt to refresh expired license token using refresh_token grant."""
        if not token.refresh_token:
            return None

        for endpoint_key, endpoint in self.discovered_endpoints.items():
            if "refresh" in endpoint_key.lower() or "token" in endpoint_key.lower():
                try:
                    response = self._make_refresh_request(endpoint, token.refresh_token)

                    if response.status_code == 200:
                        data = response.json()
                        if new_tokens := self._extract_tokens_from_json(data):
                            return new_tokens[0]
                except (ValueError, TypeError):
                    continue

        return None

    def _make_refresh_request(self, endpoint: CloudEndpoint, refresh_token: str) -> requests.Response:
        url = endpoint.url
        headers = endpoint.headers.copy()

        if endpoint.method == "POST":
            data = {"grant_type": "refresh_token", "refresh_token": refresh_token}

            if "application/json" in headers.get("content-type", ""):
                return requests.post(url, json=data, headers=headers, timeout=30)
            return requests.post(url, data=data, headers=headers, timeout=30)
        params = {"refresh_token": refresh_token}
        return requests.get(url, params=params, headers=headers, timeout=30)

    def emulate_license_server(self, port: int = 9090) -> None:
        """Start local emulated license server to respond to intercepted requests."""
        from flask import Flask, Response, jsonify, request

        app = Flask(__name__)

        @app.route("/api/license/verify", methods=["POST"])
        def verify_license() -> Response:
            data = request.json
            data.get("license_key")

            response = {
                "valid": True,
                "expires_at": (datetime.now() + timedelta(days=365)).isoformat(),
                "features": ["all"],
                "max_activations": 999,
                "current_activations": 1,
            }

            return jsonify(response)

        @app.route("/api/license/activate", methods=["POST"])
        def activate_license() -> Response:
            data = request.json

            response = {
                "success": True,
                "activation_id": hashlib.sha256(os.urandom(32)).hexdigest(),
                "machine_id": data.get("machine_id"),
                "activated_at": datetime.now().isoformat(),
            }

            return jsonify(response)

        @app.route("/api/token/refresh", methods=["POST"])
        def refresh_token() -> Response:
            new_token = self.generate_token("jwt", expires_in=3600)

            response = {
                "access_token": new_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": self.generate_token("generic"),
            }

            return jsonify(response)

        app.run(host="127.0.0.1", port=port, ssl_context="adhoc")

    def export_analysis(self, filepath: Path) -> bool:
        """Export intercepted cloud license analysis data to file."""
        try:
            analysis_data = {
                "timestamp": datetime.now().isoformat(),
                "endpoints": {k: self._serialize_endpoint(v) for k, v in self.discovered_endpoints.items()},
                "tokens": {k: self._serialize_token(v) for k, v in self.license_tokens.items()},
                "api_schemas": self.api_schemas,
                "intercepted_requests": len(self.intercepted_requests),
            }

            filepath = Path(filepath)

            if filepath.suffix == ".json" or filepath.suffix not in [
                ".yaml",
                ".pkl",
            ]:
                filepath.write_text(json.dumps(analysis_data, indent=2))
            elif filepath.suffix == ".yaml":
                filepath.write_text(yaml.dump(analysis_data))
            else:
                with filepath.open("wb") as f:
                    pickle.dump(analysis_data, f)
            return True

        except Exception as e:
            logger.exception("Failed to export analysis: %s", e)
            return False

    def _serialize_endpoint(self, endpoint: CloudEndpoint) -> dict[str, Any]:
        return {
            "url": endpoint.url,
            "method": endpoint.method,
            "headers": endpoint.headers,
            "parameters": endpoint.parameters,
            "response_schema": endpoint.response_schema,
            "authentication_type": endpoint.authentication_type,
            "rate_limit": endpoint.rate_limit,
            "last_seen": endpoint.last_seen.isoformat(),
        }

    def _serialize_token(self, token: LicenseToken) -> dict[str, Any]:
        return {
            "token_type": token.token_type,
            "value": (f"{token.value[:20]}..." if len(token.value) > 20 else token.value),
            "expires_at": (token.expires_at.isoformat() if token.expires_at else None),
            "has_refresh": bool(token.refresh_token),
            "scope": token.scope,
            "metadata": token.metadata,
        }

    def cleanup(self) -> None:
        """Clean up proxy and Frida resources."""
        if self.proxy_master:
            self.proxy_master.shutdown()

        if self.frida_session:
            self.frida_session.detach()


class CloudInterceptor:
    """Mitmproxy addon for intercepting and analyzing cloud license traffic."""

    def __init__(self, analyzer: CloudLicenseAnalyzer) -> None:
        """Initialize interceptor with reference to parent analyzer."""
        self.analyzer = analyzer

    def request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        """Handle intercepted HTTP request."""
        request = flow.request

        self.analyzer.intercepted_requests.append(
            {
                "timestamp": datetime.now(),
                "method": request.method,
                "url": request.pretty_url,
                "headers": dict(request.headers),
                "content": request.content,
            },
        )

    def response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        """Handle intercepted HTTP response."""
        request = flow.request
        response = flow.response

        self.analyzer.analyze_endpoint(request, response)

        tokens = self.analyzer.extract_license_tokens(request, response)
        for token in tokens:
            token_key = f"{token.token_type}:{hashlib.sha256(token.value.encode()).hexdigest()[:8]}"
            self.analyzer.license_tokens[token_key] = token

        if self._should_modify_response(request, response):
            self._modify_response(flow)

    def _should_modify_response(self, request: mitmproxy.http.Request, response: mitmproxy.http.Response) -> bool:
        url_path = urlparse(request.pretty_url).path.lower()

        license_paths = ["/license", "/verify", "/validate", "/check", "/activate"]

        return any(path in url_path for path in license_paths)

    def _modify_response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        response = flow.response

        if response.content:
            content_type = response.headers.get("content-type", "")

            if "application/json" in content_type:
                with contextlib.suppress(json.JSONDecodeError, TypeError):
                    data = json.loads(response.content)

                    if "valid" in data or "licensed" in data or "activated" in data:
                        data["valid"] = True
                        data["licensed"] = True
                        data["activated"] = True

                    if "expires" in data or "expiry" in data:
                        future_date = (datetime.now() + timedelta(days=365)).isoformat()
                    if "expires" in data:
                        data["expires"] = future_date
                    if "expiry" in data:
                        data["expiry"] = future_date

                    if "features" in data:
                        data["features"] = ["all", "unlimited", "enterprise"]

                    response.content = json.dumps(data).encode("utf-8")


class CloudLicenseBypasser:
    """Cloud license bypass system for defeating cloud-based activation."""

    def __init__(self, analyzer: CloudLicenseAnalyzer) -> None:
        """Initialize the CloudLicenseBypassSystem with an analyzer instance.

        Args:
            analyzer: CloudLicenseAnalyzer instance to use for analysis data.

        """
        self.analyzer = analyzer

    def bypass_license_check(self, target_url: str) -> bool:
        """Bypass cloud license check by replaying valid tokens to target URL."""
        parsed = urlparse(target_url)

        for endpoint in self.analyzer.discovered_endpoints.values():
            if parsed.path in endpoint.url:
                if token := self._get_valid_token(endpoint):
                    return self._send_bypass_request(endpoint, token)

        return False

    def _get_valid_token(self, endpoint: CloudEndpoint) -> LicenseToken | None:
        for token in self.analyzer.license_tokens.values():
            if token.expires_at and token.expires_at > datetime.now():
                return token
            if token.refresh_token:
                if new_token := self.analyzer.refresh_token(token):
                    return new_token

        token_value = self.analyzer.generate_token("jwt")
        return LicenseToken(
            token_type=TOKEN_TYPE_JWT,
            value=token_value,
            expires_at=None,
            refresh_token=None,
            scope=None,
        )

    def _send_bypass_request(self, endpoint: CloudEndpoint, token: LicenseToken) -> bool:
        headers = endpoint.headers.copy()

        if token.token_type in (TOKEN_TYPE_JWT, TOKEN_TYPE_BEARER):
            headers["Authorization"] = f"Bearer {token.value}"
        elif token.token_type == TOKEN_TYPE_API_KEY:
            headers["X-API-Key"] = token.value

        try:
            if endpoint.method == "GET":
                response = requests.get(endpoint.url, headers=headers, timeout=30)
            elif endpoint.method == "POST":
                response = requests.post(
                    endpoint.url,
                    headers=headers,
                    json=endpoint.parameters.get("body", {}),
                    timeout=30,
                )
            else:
                response = requests.request(endpoint.method, endpoint.url, headers=headers, timeout=30)

            return response.status_code in [200, 201, 204]

        except Exception as e:
            logger.exception("Bypass request failed: %s", e)
            return False
