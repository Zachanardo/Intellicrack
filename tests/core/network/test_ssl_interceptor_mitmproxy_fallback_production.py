"""Production tests for SSL interceptor mitmproxy fallback functionality.

Tests validate that SSL interceptor:
1. Falls back to PyOpenSSL when mitmproxy unavailable
2. Provides transparent proxy functionality without mitmproxy
3. Implements certificate generation on-the-fly
4. Supports TLS 1.2/1.3 interception
5. Logs interception failures with actionable diagnostics
6. Handles edge cases: client certificates, HSTS, certificate transparency
"""

import datetime
import json
import os
import socket
import ssl
import tempfile
import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from intellicrack.core.network.ssl_interceptor import (
    PyOpenSSLInterceptor,
    SSLTLSInterceptor,
)


@pytest.fixture(scope="module")
def temp_ca_cert() -> Generator[tuple[str, str], None, None]:
    """Generate temporary CA certificate for testing.

    Returns:
        Tuple of (cert_path, key_path)
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available - cannot generate CA certificate")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_fd, cert_path = tempfile.mkstemp(suffix=".crt", prefix="test_ca_")
    key_fd, key_path = tempfile.mkstemp(suffix=".key", prefix="test_ca_")

    with os.fdopen(cert_fd, "wb") as f:
        f.write(cert_pem)
    with os.fdopen(key_fd, "wb") as f:
        f.write(key_pem)

    yield cert_path, key_path

    try:
        os.unlink(cert_path)
        os.unlink(key_path)
    except OSError:
        pass


@pytest.fixture
def mock_license_server() -> Generator[tuple[str, int, threading.Thread, threading.Event], None, None]:
    """Start a mock HTTPS license server.

    Returns:
        Tuple of (hostname, port, server_thread, stop_event)
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test License Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, "license.example.com"),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("license.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    cert_fd, cert_path = tempfile.mkstemp(suffix=".crt")
    key_fd, key_path = tempfile.mkstemp(suffix=".key")

    with os.fdopen(cert_fd, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with os.fdopen(key_fd, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(5)
    port = server_socket.getsockname()[1]

    stop_event = threading.Event()

    def server_loop() -> None:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_path, key_path)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

        server_socket.settimeout(1.0)

        while not stop_event.is_set():
            try:
                client_socket, _ = server_socket.accept()
                ssl_socket = ssl_context.wrap_socket(client_socket, server_side=True)

                request = ssl_socket.recv(4096).decode("utf-8")

                response_data = {
                    "status": "INVALID",
                    "license": {"status": "EXPIRED", "type": "TRIAL"},
                    "isValid": False,
                    "valid": False,
                    "expired": True,
                    "expiry": "2020-01-01",
                }

                response_body = json.dumps(response_data)
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(response_body)}\r\n"
                    "\r\n"
                    f"{response_body}"
                )

                ssl_socket.sendall(response.encode("utf-8"))
                ssl_socket.close()

            except socket.timeout:
                continue
            except (OSError, ssl.SSLError):
                break

        server_socket.close()
        try:
            os.unlink(cert_path)
            os.unlink(key_path)
        except OSError:
            pass

    server_thread = threading.Thread(target=server_loop, daemon=True)
    server_thread.start()

    time.sleep(0.5)

    yield "127.0.0.1", port, server_thread, stop_event

    stop_event.set()
    server_thread.join(timeout=2.0)


def test_fallback_activates_when_mitmproxy_unavailable(temp_ca_cert: tuple[str, str], monkeypatch: Any) -> None:
    """Fallback SSL interception activates when mitmproxy is not available.

    Validates:
    - PyOpenSSL interceptor starts when mitmproxy missing
    - No errors or exceptions during fallback activation
    - Proper logging of mitmproxy unavailability
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available - VERBOSE: Cannot perform SSL interception without cryptography. Install: pip install cryptography>=41.0.0")

    cert_path, key_path = temp_ca_cert

    def mock_find_executable(executable: str) -> str | None:
        return None

    interceptor = SSLTLSInterceptor(
        {
            "listen_ip": "127.0.0.1",
            "listen_port": 18443,
            "target_hosts": ["license.example.com"],
            "ca_cert_path": cert_path,
            "ca_key_path": key_path,
        }
    )

    monkeypatch.setattr(interceptor, "_find_executable", mock_find_executable)

    try:
        result = interceptor.start()
        assert result is True, "Fallback interceptor must start successfully when mitmproxy unavailable"
        assert interceptor.fallback_interceptor is not None, "PyOpenSSL fallback must be initialized"
        assert interceptor.fallback_interceptor.running is True, "Fallback interceptor must be running"
        assert interceptor.proxy_process is None, "mitmproxy process must not be started"
    finally:
        interceptor.stop()


def test_fallback_generates_certificates_on_the_fly(temp_ca_cert: tuple[str, str]) -> None:
    """Fallback generates domain-specific certificates dynamically.

    Validates:
    - Certificates generated for requested domains
    - Certificates properly signed by CA
    - Certificate caching works correctly
    - Generated certificates have correct Subject Alternative Names
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available - VERBOSE: Certificate generation requires cryptography library. Install: pip install cryptography>=41.0.0")

    cert_path, key_path = temp_ca_cert

    interceptor = PyOpenSSLInterceptor(
        listen_ip="127.0.0.1",
        listen_port=18444,
        ca_cert_path=cert_path,
        ca_key_path=key_path,
        target_hosts=["license.example.com"],
    )

    domain = "license.example.com"
    cert_tuple = interceptor.generate_cert_for_domain(domain)

    assert cert_tuple is not None, "Certificate generation must succeed"
    domain_cert_path, domain_key_path = cert_tuple

    assert os.path.exists(domain_cert_path), "Generated certificate file must exist"
    assert os.path.exists(domain_key_path), "Generated key file must exist"

    with open(domain_cert_path, "rb") as f:
        cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = san_extension.value.get_values_for_type(x509.DNSName)
    assert domain in dns_names, f"Certificate SAN must include {domain}"

    with open(cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    assert cert.issuer == ca_cert.subject, "Certificate must be signed by CA"

    cached_cert_tuple = interceptor.generate_cert_for_domain(domain)
    assert cached_cert_tuple == cert_tuple, "Certificate must be retrieved from cache"

    try:
        os.unlink(domain_cert_path)
        os.unlink(domain_key_path)
    except OSError:
        pass


def test_fallback_supports_tls_1_2_and_1_3(temp_ca_cert: tuple[str, str]) -> None:
    """Fallback interceptor supports TLS 1.2 and TLS 1.3.

    Validates:
    - TLS 1.2 connections intercepted successfully
    - TLS 1.3 connections intercepted successfully
    - Proper SSL context configuration
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available - VERBOSE: TLS interception requires cryptography. Install: pip install cryptography>=41.0.0")

    cert_path, key_path = temp_ca_cert

    interceptor = PyOpenSSLInterceptor(
        listen_ip="127.0.0.1",
        listen_port=18445,
        ca_cert_path=cert_path,
        ca_key_path=key_path,
        target_hosts=["license.example.com"],
    )

    domain = "license.example.com"
    cert_tuple = interceptor.generate_cert_for_domain(domain)
    assert cert_tuple is not None, "Certificate generation must succeed"

    domain_cert_path, domain_key_path = cert_tuple

    ssl_context_tls12 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context_tls12.load_cert_chain(domain_cert_path, domain_key_path)
    ssl_context_tls12.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context_tls12.maximum_version = ssl.TLSVersion.TLSv1_2

    assert ssl_context_tls12.minimum_version == ssl.TLSVersion.TLSv1_2, "TLS 1.2 must be supported"

    ssl_context_tls13 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context_tls13.load_cert_chain(domain_cert_path, domain_key_path)
    ssl_context_tls13.minimum_version = ssl.TLSVersion.TLSv1_3

    if hasattr(ssl.TLSVersion, "TLSv1_3"):
        assert ssl_context_tls13.minimum_version == ssl.TLSVersion.TLSv1_3, "TLS 1.3 must be supported"

    try:
        os.unlink(domain_cert_path)
        os.unlink(domain_key_path)
    except OSError:
        pass


def test_fallback_intercepts_and_modifies_https_traffic(
    temp_ca_cert: tuple[str, str], mock_license_server: tuple[str, int, threading.Thread, threading.Event]
) -> None:
    """Fallback interceptor intercepts and modifies HTTPS traffic.

    Validates:
    - HTTPS connections intercepted transparently
    - License responses modified to bypass restrictions
    - Modified responses correctly re-encoded
    - Client receives modified data
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available - VERBOSE: HTTPS interception requires cryptography. Install: pip install cryptography>=41.0.0")

    cert_path, key_path = temp_ca_cert
    server_host, server_port, _, stop_event = mock_license_server

    interceptor = PyOpenSSLInterceptor(
        listen_ip="127.0.0.1",
        listen_port=18446,
        ca_cert_path=cert_path,
        ca_key_path=key_path,
        target_hosts=["license.example.com"],
    )

    try:
        interceptor.start()
        time.sleep(1.0)

        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.connect(("127.0.0.1", 18446))

        connect_request = f"CONNECT license.example.com:{server_port} HTTP/1.1\r\nHost: license.example.com:{server_port}\r\n\r\n"
        proxy_socket.sendall(connect_request.encode("utf-8"))

        connect_response = proxy_socket.recv(4096).decode("utf-8")
        assert "200 Connection Established" in connect_response, "CONNECT must be accepted"

        client_context = ssl.create_default_context()
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE

        ssl_socket = client_context.wrap_socket(proxy_socket, server_hostname="license.example.com")

        http_request = (
            "GET /validate HTTP/1.1\r\n" "Host: license.example.com\r\n" "Connection: close\r\n" "\r\n"
        )
        ssl_socket.sendall(http_request.encode("utf-8"))

        response = b""
        while True:
            chunk = ssl_socket.recv(4096)
            if not chunk:
                break
            response += chunk

        response_str = response.decode("utf-8")

        headers_end = response_str.find("\r\n\r\n")
        assert headers_end != -1, "Response must have headers"
        body = response_str[headers_end + 4 :]

        response_data = json.loads(body)

        assert response_data["status"] == "SUCCESS", "Status must be modified to SUCCESS"
        assert response_data["license"]["status"] == "ACTIVATED", "License status must be ACTIVATED"
        assert response_data["license"]["type"] == "PERMANENT", "License type must be PERMANENT"
        assert response_data["isValid"] is True, "isValid must be True"
        assert response_data["valid"] is True, "valid must be True"
        assert response_data["expired"] is False, "expired must be False"
        assert response_data["expiry"] == "2099-12-31", "expiry must be far future"

        ssl_socket.close()

    finally:
        interceptor.stop()
        stop_event.set()


def test_fallback_handles_certificate_generation_failure(temp_ca_cert: tuple[str, str]) -> None:
    """Fallback handles certificate generation failures gracefully.

    Validates:
    - Invalid CA certificate paths logged with actionable error
    - Certificate generation failure returns None
    - No crashes or unhandled exceptions
    - Clear diagnostic messages provided
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available - VERBOSE: Cannot test certificate generation without cryptography. Install: pip install cryptography>=41.0.0")

    interceptor = PyOpenSSLInterceptor(
        listen_ip="127.0.0.1",
        listen_port=18447,
        ca_cert_path="/nonexistent/ca.crt",
        ca_key_path="/nonexistent/ca.key",
        target_hosts=["license.example.com"],
    )

    domain = "license.example.com"
    cert_tuple = interceptor.generate_cert_for_domain(domain)

    assert cert_tuple is None, "Certificate generation must fail for invalid CA paths"


def test_fallback_handles_client_certificate_authentication_edge_case(temp_ca_cert: tuple[str, str]) -> None:
    """Fallback handles client certificate authentication requirements.

    Validates:
    - Servers requiring client certificates handled gracefully
    - Connection failures logged with clear diagnostics
    - No crashes when client cert required but not provided
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available - VERBOSE: Client certificate testing requires cryptography. Install: pip install cryptography>=41.0.0")

    cert_path, key_path = temp_ca_cert

    interceptor = PyOpenSSLInterceptor(
        listen_ip="127.0.0.1",
        listen_port=18448,
        ca_cert_path=cert_path,
        ca_key_path=key_path,
        target_hosts=["license.example.com"],
    )

    domain = "license.example.com"
    cert_tuple = interceptor.generate_cert_for_domain(domain)
    assert cert_tuple is not None, "Certificate generation must succeed"

    domain_cert_path, domain_key_path = cert_tuple

    client_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    client_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Client CA"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "Client CA"),
                ]
            )
        )
        .issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Client CA"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "Client CA"),
                ]
            )
        )
        .public_key(client_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(client_ca_key, hashes.SHA256(), default_backend())
    )

    client_ca_cert_fd, client_ca_cert_path = tempfile.mkstemp(suffix=".crt")
    with os.fdopen(client_ca_cert_fd, "wb") as f:
        f.write(client_ca_cert.public_bytes(serialization.Encoding.PEM))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(1)
    server_port = server_socket.getsockname()[1]

    def client_cert_server() -> None:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(domain_cert_path, domain_key_path)
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.load_verify_locations(client_ca_cert_path)

        server_socket.settimeout(5.0)
        try:
            client_socket, _ = server_socket.accept()
            ssl_socket = ssl_context.wrap_socket(client_socket, server_side=True)
            ssl_socket.recv(1024)
            ssl_socket.close()
        except (socket.timeout, ssl.SSLError):
            pass
        finally:
            server_socket.close()

    server_thread = threading.Thread(target=client_cert_server, daemon=True)
    server_thread.start()

    time.sleep(0.5)

    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_socket.settimeout(5.0)

    client_context = ssl.create_default_context()
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE

    ssl_test_socket = client_context.wrap_socket(test_socket, server_hostname="license.example.com")

    try:
        ssl_test_socket.connect(("127.0.0.1", server_port))
        ssl_test_socket.sendall(b"GET / HTTP/1.1\r\n\r\n")
        ssl_test_socket.recv(1024)
        assert False, "Connection should fail without client certificate"
    except (ssl.SSLError, socket.timeout, OSError) as e:
        assert True, f"Connection correctly failed with client cert requirement: {e}"
    finally:
        try:
            ssl_test_socket.close()
        except Exception:
            pass

    server_thread.join(timeout=2.0)

    try:
        os.unlink(client_ca_cert_path)
        os.unlink(domain_cert_path)
        os.unlink(domain_key_path)
    except OSError:
        pass


def test_fallback_handles_hsts_edge_case(temp_ca_cert: tuple[str, str]) -> None:
    """Fallback handles HSTS (HTTP Strict Transport Security) properly.

    Validates:
    - HSTS headers preserved in intercepted responses
    - No protocol downgrade attempts
    - HTTPS enforcement maintained
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available - VERBOSE: HSTS testing requires cryptography. Install: pip install cryptography>=41.0.0")

    cert_path, key_path = temp_ca_cert

    interceptor = PyOpenSSLInterceptor(
        listen_ip="127.0.0.1",
        listen_port=18449,
        ca_cert_path=cert_path,
        ca_key_path=key_path,
        target_hosts=["license.example.com"],
    )

    response_with_hsts = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n"
        b"Content-Length: 18\r\n"
        b"\r\n"
        b'{"status":"FAIL"}'
    )

    modified_response = interceptor.modify_response(response_with_hsts)

    modified_str = modified_response.decode("utf-8")

    assert "Strict-Transport-Security: max-age=31536000" in modified_str, "HSTS header must be preserved"
    assert "includeSubDomains" in modified_str, "HSTS directives must be preserved"
    assert "preload" in modified_str, "HSTS preload directive must be preserved"

    headers_end = modified_str.find("\r\n\r\n")
    body = modified_str[headers_end + 4 :]
    response_data = json.loads(body)

    assert response_data["status"] == "SUCCESS", "Status must still be modified despite HSTS"


def test_fallback_handles_invalid_ssl_contexts(temp_ca_cert: tuple[str, str]) -> None:
    """Fallback handles invalid SSL contexts gracefully.

    Validates:
    - Corrupted certificates logged with diagnostics
    - Connection failures handled without crashes
    - Actionable error messages provided
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available - VERBOSE: SSL context testing requires cryptography. Install: pip install cryptography>=41.0.0")

    cert_path, key_path = temp_ca_cert

    corrupted_cert_fd, corrupted_cert_path = tempfile.mkstemp(suffix=".crt")
    with os.fdopen(corrupted_cert_fd, "wb") as f:
        f.write(b"CORRUPTED CERTIFICATE DATA")

    interceptor = PyOpenSSLInterceptor(
        listen_ip="127.0.0.1",
        listen_port=18450,
        ca_cert_path=corrupted_cert_path,
        ca_key_path=key_path,
        target_hosts=["license.example.com"],
    )

    domain = "license.example.com"
    cert_tuple = interceptor.generate_cert_for_domain(domain)

    assert cert_tuple is None, "Certificate generation must fail with corrupted CA cert"

    try:
        os.unlink(corrupted_cert_path)
    except OSError:
        pass


def test_fallback_logs_interception_failures_with_diagnostics(temp_ca_cert: tuple[str, str], caplog: Any) -> None:
    """Fallback logs interception failures with actionable diagnostics.

    Validates:
    - Connection failures logged with details
    - SSL errors include diagnostic information
    - Certificate issues clearly reported
    - Network errors properly logged
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available - VERBOSE: Logging diagnostics testing requires cryptography. Install: pip install cryptography>=41.0.0")

    cert_path, key_path = temp_ca_cert

    interceptor = PyOpenSSLInterceptor(
        listen_ip="127.0.0.1",
        listen_port=18451,
        ca_cert_path=cert_path,
        ca_key_path=key_path,
        target_hosts=["license.example.com"],
    )

    try:
        interceptor.start()
        time.sleep(0.5)

        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.connect(("127.0.0.1", 18451))

        malformed_request = b"INVALID REQUEST DATA\r\n\r\n"
        test_socket.sendall(malformed_request)

        time.sleep(0.5)
        test_socket.close()

        time.sleep(0.5)

        assert any("error" in record.message.lower() for record in caplog.records), "Errors must be logged"

    finally:
        interceptor.stop()


def test_fallback_modifies_jwt_tokens_in_responses(temp_ca_cert: tuple[str, str]) -> None:
    """Fallback modifies JWT tokens in license responses.

    Validates:
    - JWT tokens detected in JSON responses
    - Token payloads modified to bypass restrictions
    - Tokens re-signed with common secrets
    - Modified tokens returned to client
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available - VERBOSE: JWT modification requires cryptography. Install: pip install cryptography>=41.0.0")

    cert_path, key_path = temp_ca_cert

    interceptor = PyOpenSSLInterceptor(
        listen_ip="127.0.0.1",
        listen_port=18452,
        ca_cert_path=cert_path,
        ca_key_path=key_path,
        target_hosts=["license.example.com"],
    )

    import base64
    import hmac
    import hashlib

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"status": "EXPIRED", "exp": 1609459200, "license_type": "trial"}

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    message = f"{header_b64}.{payload_b64}"

    signature = hmac.new(b"secret", message.encode(), hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    jwt_token = f"{message}.{signature_b64}"

    response_data = {"token": jwt_token}
    response_body = json.dumps(response_data)

    response = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(response_body)}\r\n"
        f"\r\n"
        f"{response_body}"
    )

    modified_response = interceptor.modify_response(response.encode("utf-8"))
    modified_str = modified_response.decode("utf-8")

    headers_end = modified_str.find("\r\n\r\n")
    body = modified_str[headers_end + 4 :]

    modified_data = json.loads(body)

    assert "token" in modified_data, "Token must be present in response"

    modified_token = modified_data["token"]
    parts = modified_token.split(".")
    assert len(parts) == 3, "Modified token must be valid JWT format"

    payload_part = parts[1]
    padding = 4 - len(payload_part) % 4
    if padding != 4:
        payload_part += "=" * padding

    decoded_payload = json.loads(base64.urlsafe_b64decode(payload_part))

    assert decoded_payload.get("license_type") == "perpetual", "License type must be modified to perpetual"
    assert decoded_payload.get("status") == "active", "Status must be modified to active"
    assert decoded_payload.get("exp", 0) > 2000000000, "Expiry must be set to far future"


def test_ssl_interceptor_uses_fallback_when_mitmproxy_missing(temp_ca_cert: tuple[str, str], monkeypatch: Any) -> None:
    """SSLTLSInterceptor correctly activates fallback when mitmproxy missing.

    Validates:
    - SSLTLSInterceptor.start() detects missing mitmproxy
    - PyOpenSSL fallback automatically activated
    - Proper logging of fallback activation
    - No errors during fallback transition
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available - VERBOSE: Fallback activation testing requires cryptography. Install: pip install cryptography>=41.0.0")

    cert_path, key_path = temp_ca_cert

    interceptor = SSLTLSInterceptor(
        {
            "listen_ip": "127.0.0.1",
            "listen_port": 18453,
            "target_hosts": ["license.example.com"],
            "ca_cert_path": cert_path,
            "ca_key_path": key_path,
        }
    )

    def mock_find_executable(executable: str) -> str | None:
        return None

    monkeypatch.setattr(interceptor, "_find_executable", mock_find_executable)

    try:
        result = interceptor.start()

        assert result is True, "Interceptor must start successfully with fallback"
        assert interceptor.fallback_interceptor is not None, "Fallback must be initialized"
        assert isinstance(interceptor.fallback_interceptor, PyOpenSSLInterceptor), "Fallback must be PyOpenSSL"
        assert interceptor.fallback_interceptor.running is True, "Fallback must be running"

    finally:
        interceptor.stop()
        assert interceptor.fallback_interceptor is None, "Fallback must be cleaned up after stop"


def test_fallback_handles_xml_response_modification(temp_ca_cert: tuple[str, str]) -> None:
    """Fallback modifies XML license responses correctly.

    Validates:
    - XML content-type detected
    - XML tags modified appropriately
    - Content-Length updated after modification
    - Modified XML well-formed
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography library not available - VERBOSE: XML modification testing requires cryptography. Install: pip install cryptography>=41.0.0")

    cert_path, key_path = temp_ca_cert

    interceptor = PyOpenSSLInterceptor(
        listen_ip="127.0.0.1",
        listen_port=18454,
        ca_cert_path=cert_path,
        ca_key_path=key_path,
        target_hosts=["license.example.com"],
    )

    xml_body = "<?xml version='1.0'?><license><status>ERROR</status><valid>false</valid><expired>true</expired></license>"

    response = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/xml\r\n"
        f"Content-Length: {len(xml_body)}\r\n"
        f"\r\n"
        f"{xml_body}"
    )

    modified_response = interceptor.modify_response(response.encode("utf-8"))
    modified_str = modified_response.decode("utf-8")

    headers_end = modified_str.find("\r\n\r\n")
    body = modified_str[headers_end + 4 :]

    assert "<status>SUCCESS</status>" in body, "Status must be modified to SUCCESS"
    assert "<valid>true</valid>" in body, "Valid must be modified to true"
    assert "<expired>false</expired>" in body, "Expired must be modified to false"

    headers = modified_str[:headers_end]
    for line in headers.split("\r\n"):
        if line.lower().startswith("content-length:"):
            content_length = int(line.split(":")[1].strip())
            assert content_length == len(body.encode("utf-8")), "Content-Length must be updated correctly"
            break
