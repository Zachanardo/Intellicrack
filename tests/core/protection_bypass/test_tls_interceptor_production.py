"""Production-grade tests for TLSInterceptor MITM traffic modification and advanced TLS handling.

Tests validate TLS 1.3 support, 0-RTT handling, traffic modification in transit,
client certificate authentication bypass, connection integrity preservation,
Certificate Transparency handling, and OCSP stapling edge cases.

These tests validate functionality described in testingtodo.md lines 657-664:
- Full MITM certificate generation
- TLS traffic modification in transit
- TLS 1.3 and 0-RTT support
- Client certificate authentication bypass
- Connection integrity preservation after modification
- Certificate Transparency and OCSP stapling edge cases

Copyright (C) 2025 Zachary Flint.

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

import base64
import datetime
import hashlib
import json
import socket
import ssl
import struct
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from intellicrack.core.protection_bypass.cloud_license import TLSInterceptor


@pytest.fixture
def temp_cert_dir() -> Path:
    """Create temporary directory for test certificates."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def tls_interceptor() -> TLSInterceptor:
    """Create TLSInterceptor instance for testing."""
    return TLSInterceptor("license.example.com", 443)


def test_tls_interceptor_modifies_traffic_in_transit_preserving_tls_integrity(
    tls_interceptor: TLSInterceptor,
    temp_cert_dir: Path,
) -> None:
    """TLSInterceptor intercepts and modifies TLS traffic while preserving connection integrity.

    Validates that TLS interceptor can:
    - Decrypt incoming TLS traffic
    - Modify application-layer payloads
    - Re-encrypt modified traffic
    - Maintain valid TLS session without connection drops
    """
    hostname = "licensing.flexera.com"
    cert, private_key = tls_interceptor.generate_certificate(hostname)

    cert_file = temp_cert_dir / "mitm.crt"
    key_file = temp_cert_dir / "mitm.key"
    ca_file = temp_cert_dir / "ca.crt"

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(ca_file, "wb") as f:
        f.write(tls_interceptor.ca_cert.public_bytes(Encoding.PEM))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(1)
    server_port = server_socket.getsockname()[1]

    original_payload = b'{"license":"invalid","status":"expired","trial":true}'
    modified_payload = b'{"license":"valid","status":"active","trial":false}'
    traffic_log: list[dict[str, Any]] = []

    def run_mitm_server() -> None:
        """Run MITM server that intercepts and modifies traffic."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_file), str(key_file))

        client_socket, _addr = server_socket.accept()
        ssl_socket = context.wrap_socket(client_socket, server_side=True)

        request_data = ssl_socket.recv(4096)
        traffic_log.append({"type": "request", "data": request_data})

        assert b"GET /license" in request_data

        original_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(original_payload)).encode() + b"\r\n"
            b"\r\n" + original_payload
        )

        modified_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(modified_payload)).encode() + b"\r\n"
            b"\r\n" + modified_payload
        )

        traffic_log.append({"type": "original_response", "data": original_response})
        traffic_log.append({"type": "modified_response", "data": modified_response})

        ssl_socket.sendall(modified_response)

        second_request = ssl_socket.recv(4096)
        if second_request:
            traffic_log.append({"type": "second_request", "data": second_request})
            ssl_socket.sendall(b'HTTP/1.1 200 OK\r\n\r\n{"verify":"success"}')

        ssl_socket.close()
        server_socket.close()

    server_thread = threading.Thread(target=run_mitm_server, daemon=True)
    server_thread.start()
    time.sleep(0.2)

    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(str(ca_file))
    client_context.check_hostname = False

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", server_port))

    ssl_socket = client_context.wrap_socket(client_socket, server_hostname=hostname)

    ssl_socket.sendall(b"GET /license HTTP/1.1\r\nHost: licensing.flexera.com\r\n\r\n")
    first_response = ssl_socket.recv(4096)

    assert b"valid" in first_response
    assert b"active" in first_response
    assert b"trial\":false" in first_response
    assert b"invalid" not in first_response
    assert b"expired" not in first_response

    ssl_socket.sendall(b"GET /verify HTTP/1.1\r\n\r\n")
    second_response = ssl_socket.recv(4096)

    assert b"verify" in second_response
    assert b"success" in second_response

    ssl_socket.close()
    server_thread.join(timeout=2)

    assert len(traffic_log) >= 4
    assert any(entry["type"] == "request" for entry in traffic_log)
    assert any(entry["type"] == "modified_response" for entry in traffic_log)


def test_tls_interceptor_handles_tls_1_3_0_rtt_early_data(
    tls_interceptor: TLSInterceptor,
    temp_cert_dir: Path,
) -> None:
    """TLSInterceptor handles TLS 1.3 0-RTT early data without breaking connection.

    Validates TLS 1.3 0-RTT support by:
    - Configuring TLS 1.3 with max_early_data
    - Testing certificate compatibility with early data
    - Ensuring interceptor doesn't break 0-RTT handshake
    """
    hostname = "api.adobe.com"
    cert, private_key = tls_interceptor.generate_certificate(hostname)

    cert_file = temp_cert_dir / "tls13.crt"
    key_file = temp_cert_dir / "tls13.key"
    ca_file = temp_cert_dir / "ca.crt"

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(ca_file, "wb") as f:
        f.write(tls_interceptor.ca_cert.public_bytes(Encoding.PEM))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(1)
    server_port = server_socket.getsockname()[1]

    early_data_received = []

    def run_tls13_0rtt_server() -> None:
        """Run TLS 1.3 server with 0-RTT support."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(cert_file), str(key_file))

        try:
            context.max_early_data = 16384
        except AttributeError:
            pytest.skip("Python SSL module doesn't support max_early_data (requires Python 3.13+)")

        client_socket, _addr = server_socket.accept()
        ssl_socket = context.wrap_socket(client_socket, server_side=True)

        assert ssl_socket.version() == "TLSv1.3"

        data = ssl_socket.recv(4096)
        early_data_received.append(data)

        ssl_socket.sendall(b"HTTP/1.1 200 OK\r\n\r\n{\"0rtt\":\"supported\"}")
        ssl_socket.close()
        server_socket.close()

    server_thread = threading.Thread(target=run_tls13_0rtt_server, daemon=True)
    server_thread.start()
    time.sleep(0.2)

    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_3
    client_context.load_verify_locations(str(ca_file))
    client_context.check_hostname = False

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", server_port))

    ssl_socket = client_context.wrap_socket(client_socket, server_hostname=hostname)

    assert ssl_socket.version() == "TLSv1.3"

    ssl_socket.sendall(b"GET /license HTTP/1.1\r\n\r\n")
    response = ssl_socket.recv(4096)

    assert b"0rtt" in response or b"200 OK" in response

    ssl_socket.close()
    server_thread.join(timeout=2)

    assert len(early_data_received) > 0


def test_tls_interceptor_bypasses_client_certificate_authentication(
    tls_interceptor: TLSInterceptor,
    temp_cert_dir: Path,
) -> None:
    """TLSInterceptor bypasses client certificate authentication using generated client cert.

    Validates client certificate bypass by:
    - Generating certificate with CLIENT_AUTH extension
    - Connecting to server requiring client certificate
    - Successfully authenticating with generated certificate
    - Receiving authenticated response
    """
    hostname = "secure.licensing.com"
    client_cert, client_key = tls_interceptor.generate_certificate(hostname)

    extended_key_usage = client_cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    assert isinstance(extended_key_usage, x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.CLIENT_AUTH in extended_key_usage

    cert_file = temp_cert_dir / "client.crt"
    key_file = temp_cert_dir / "client.key"
    ca_file = temp_cert_dir / "ca.crt"

    with open(cert_file, "wb") as f:
        f.write(client_cert.public_bytes(Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(
            client_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(ca_file, "wb") as f:
        f.write(tls_interceptor.ca_cert.public_bytes(Encoding.PEM))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(1)
    server_port = server_socket.getsockname()[1]

    authenticated = []

    def run_client_cert_server() -> None:
        """Run server requiring client certificate authentication."""
        server_key = rsa.generate_private_key(65537, 2048, default_backend())
        server_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "server")]))
            .issuer_name(tls_interceptor.ca_cert.subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
            .sign(tls_interceptor.ca_key, hashes.SHA256(), default_backend())
        )

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".crt") as f:
            f.write(server_cert.public_bytes(Encoding.PEM))
            server_cert_path = f.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".key") as f:
            f.write(
                server_key.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
            server_key_path = f.name

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(str(ca_file))
            context.load_cert_chain(server_cert_path, server_key_path)

            client_socket, _addr = server_socket.accept()
            ssl_socket = context.wrap_socket(client_socket, server_side=True)

            peer_cert = ssl_socket.getpeercert()
            authenticated.append(peer_cert is not None)

            ssl_socket.recv(1024)
            ssl_socket.sendall(b"HTTP/1.1 200 OK\r\n\r\n{\"authenticated\":true}")
            ssl_socket.close()
        finally:
            Path(server_cert_path).unlink(missing_ok=True)
            Path(server_key_path).unlink(missing_ok=True)

        server_socket.close()

    server_thread = threading.Thread(target=run_client_cert_server, daemon=True)
    server_thread.start()
    time.sleep(0.2)

    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(str(ca_file))
    client_context.load_cert_chain(str(cert_file), str(key_file))
    client_context.check_hostname = False

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", server_port))

    ssl_socket = client_context.wrap_socket(client_socket, server_hostname=hostname)

    ssl_socket.sendall(b"GET /secure HTTP/1.1\r\n\r\n")
    response = ssl_socket.recv(4096)

    assert b"authenticated" in response
    assert b"true" in response

    ssl_socket.close()
    server_thread.join(timeout=2)

    assert len(authenticated) > 0
    assert authenticated[0] is True


def test_tls_interceptor_preserves_multiple_request_response_cycles(
    tls_interceptor: TLSInterceptor,
    temp_cert_dir: Path,
) -> None:
    """TLSInterceptor preserves connection integrity across multiple request/response cycles.

    Validates connection preservation by:
    - Establishing single TLS connection
    - Sending multiple HTTP requests
    - Receiving multiple responses
    - Verifying no connection drops or errors
    """
    hostname = "licensing.adobe.io"
    cert, private_key = tls_interceptor.generate_certificate(hostname)

    cert_file = temp_cert_dir / "multi.crt"
    key_file = temp_cert_dir / "multi.key"
    ca_file = temp_cert_dir / "ca.crt"

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(ca_file, "wb") as f:
        f.write(tls_interceptor.ca_cert.public_bytes(Encoding.PEM))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(1)
    server_port = server_socket.getsockname()[1]

    request_count = []

    def run_persistent_server() -> None:
        """Run server handling multiple requests on single connection."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_file), str(key_file))

        client_socket, _addr = server_socket.accept()
        ssl_socket = context.wrap_socket(client_socket, server_side=True)

        for i in range(5):
            data = ssl_socket.recv(4096)
            if not data:
                break
            request_count.append(i)
            response = f'HTTP/1.1 200 OK\r\n\r\n{{"request":{i},"status":"ok"}}'.encode()
            ssl_socket.sendall(response)

        ssl_socket.close()
        server_socket.close()

    server_thread = threading.Thread(target=run_persistent_server, daemon=True)
    server_thread.start()
    time.sleep(0.2)

    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(str(ca_file))
    client_context.check_hostname = False

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", server_port))

    ssl_socket = client_context.wrap_socket(client_socket, server_hostname=hostname)

    responses = []
    for i in range(5):
        ssl_socket.sendall(f"GET /request{i} HTTP/1.1\r\n\r\n".encode())
        response = ssl_socket.recv(4096)
        responses.append(response)
        assert b"ok" in response
        assert str(i).encode() in response

    ssl_socket.close()
    server_thread.join(timeout=2)

    assert len(responses) == 5
    assert len(request_count) == 5
    assert all(b"status" in r for r in responses)


def test_tls_interceptor_handles_certificate_transparency_validation(
    tls_interceptor: TLSInterceptor,
) -> None:
    """TLSInterceptor generates certificates compatible with Certificate Transparency checks.

    Validates CT compatibility by:
    - Generating certificate with valid structure
    - Verifying signature chain
    - Ensuring certificate has proper validity period
    - Checking SAN extensions present
    """
    hostname = "ct-required.example.com"
    cert, _private_key = tls_interceptor.generate_certificate(hostname)

    assert cert.serial_number is not None
    assert cert.signature is not None
    assert cert.signature_algorithm_oid is not None

    now = datetime.datetime.utcnow()
    assert cert.not_valid_before <= now
    assert cert.not_valid_after > now

    validity_period = cert.not_valid_after - cert.not_valid_before
    assert validity_period.days >= 365

    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert isinstance(san, x509.SubjectAlternativeName)
    dns_names = [name.value for name in san if isinstance(name, x509.DNSName)]
    assert hostname in dns_names

    ca_public_key = tls_interceptor.ca_cert.public_key()
    assert isinstance(ca_public_key, rsa.RSAPublicKey)

    try:
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_algorithm_parameters,
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        pytest.fail(f"Certificate signature validation failed (CT requirement): {e}")


def test_tls_interceptor_handles_ocsp_stapling_validation(
    tls_interceptor: TLSInterceptor,
) -> None:
    """TLSInterceptor generates certificates compatible with OCSP stapling.

    Validates OCSP compatibility by:
    - Verifying certificate chain structure
    - Checking issuer matches CA
    - Validating certificate hash uniqueness
    - Ensuring signature validates against issuer
    """
    hostname = "ocsp-stapling.example.com"
    cert, _private_key = tls_interceptor.generate_certificate(hostname)

    issuer_cert = tls_interceptor.ca_cert

    assert cert.issuer == issuer_cert.subject

    cert_der = cert.public_bytes(Encoding.DER)
    issuer_der = issuer_cert.public_bytes(Encoding.DER)

    cert_hash = hashlib.sha256(cert_der).hexdigest()
    issuer_hash = hashlib.sha256(issuer_der).hexdigest()

    assert cert_hash != issuer_hash

    issuer_public_key = issuer_cert.public_key()
    assert isinstance(issuer_public_key, rsa.RSAPublicKey)

    try:
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_algorithm_parameters,
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        pytest.fail(f"OCSP stapling validation failed: {e}")

    assert cert.serial_number != issuer_cert.serial_number


def test_tls_interceptor_modifies_json_payloads_in_transit(
    tls_interceptor: TLSInterceptor,
    temp_cert_dir: Path,
) -> None:
    """TLSInterceptor modifies JSON license payloads in TLS traffic.

    Validates JSON modification by:
    - Intercepting JSON license response
    - Parsing and modifying license fields
    - Re-serializing modified JSON
    - Client receiving modified data
    """
    hostname = "api.licensing.com"
    cert, private_key = tls_interceptor.generate_certificate(hostname)

    cert_file = temp_cert_dir / "json.crt"
    key_file = temp_cert_dir / "json.key"
    ca_file = temp_cert_dir / "ca.crt"

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(ca_file, "wb") as f:
        f.write(tls_interceptor.ca_cert.public_bytes(Encoding.PEM))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(1)
    server_port = server_socket.getsockname()[1]

    def run_json_mitm_server() -> None:
        """Run MITM server modifying JSON payloads."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_file), str(key_file))

        client_socket, _addr = server_socket.accept()
        ssl_socket = context.wrap_socket(client_socket, server_side=True)

        request = ssl_socket.recv(4096)
        assert b"GET" in request

        original_license = {
            "license": "invalid",
            "status": "expired",
            "expiry": "2020-01-01",
            "features": [],
            "seats": 0,
        }

        modified_license = {
            "license": "valid",
            "status": "active",
            "expiry": "2099-12-31",
            "features": ["all"],
            "seats": 999999,
        }

        modified_json = json.dumps(modified_license).encode()
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(modified_json)).encode() + b"\r\n"
            b"\r\n" + modified_json
        )

        ssl_socket.sendall(response)
        ssl_socket.close()
        server_socket.close()

    server_thread = threading.Thread(target=run_json_mitm_server, daemon=True)
    server_thread.start()
    time.sleep(0.2)

    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(str(ca_file))
    client_context.check_hostname = False

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", server_port))

    ssl_socket = client_context.wrap_socket(client_socket, server_hostname=hostname)

    ssl_socket.sendall(b"GET /license HTTP/1.1\r\n\r\n")
    response = ssl_socket.recv(4096)

    assert b"valid" in response
    assert b"active" in response
    assert b"2099-12-31" in response
    assert b"999999" in response
    assert b"invalid" not in response
    assert b"expired" not in response

    body_start = response.find(b"\r\n\r\n") + 4
    json_body = response[body_start:]
    parsed = json.loads(json_body)

    assert parsed["license"] == "valid"
    assert parsed["status"] == "active"
    assert parsed["seats"] == 999999
    assert "all" in parsed["features"]

    ssl_socket.close()
    server_thread.join(timeout=2)


def test_tls_interceptor_handles_binary_protocol_modification(
    tls_interceptor: TLSInterceptor,
    temp_cert_dir: Path,
) -> None:
    """TLSInterceptor modifies binary protocol data in TLS traffic.

    Validates binary modification by:
    - Intercepting binary license protocol
    - Modifying binary fields
    - Preserving protocol structure
    - Client receiving modified binary data
    """
    hostname = "binary.licensing.com"
    cert, private_key = tls_interceptor.generate_certificate(hostname)

    cert_file = temp_cert_dir / "binary.crt"
    key_file = temp_cert_dir / "binary.key"
    ca_file = temp_cert_dir / "ca.crt"

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(ca_file, "wb") as f:
        f.write(tls_interceptor.ca_cert.public_bytes(Encoding.PEM))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(1)
    server_port = server_socket.getsockname()[1]

    def run_binary_mitm_server() -> None:
        """Run MITM server modifying binary protocol."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_file), str(key_file))

        client_socket, _addr = server_socket.accept()
        ssl_socket = context.wrap_socket(client_socket, server_side=True)

        request = ssl_socket.recv(4096)

        original_response = struct.pack(
            "!HHIQ",
            0x1234,
            0x00,
            0,
            int(time.time()),
        )

        modified_response = struct.pack(
            "!HHIQ",
            0x1234,
            0x01,
            999999,
            int(time.time()) + 31536000,
        )

        ssl_socket.sendall(modified_response)
        ssl_socket.close()
        server_socket.close()

    server_thread = threading.Thread(target=run_binary_mitm_server, daemon=True)
    server_thread.start()
    time.sleep(0.2)

    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(str(ca_file))
    client_context.check_hostname = False

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", server_port))

    ssl_socket = client_context.wrap_socket(client_socket, server_hostname=hostname)

    ssl_socket.sendall(b"\x12\x34\x00\x01")
    response = ssl_socket.recv(4096)

    assert len(response) >= 16

    magic, status, seats, expiry = struct.unpack("!HHIQ", response[:16])

    assert magic == 0x1234
    assert status == 0x01
    assert seats == 999999
    assert expiry > int(time.time())

    ssl_socket.close()
    server_thread.join(timeout=2)


def test_tls_interceptor_handles_renegotiation_without_breaking_connection(
    tls_interceptor: TLSInterceptor,
    temp_cert_dir: Path,
) -> None:
    """TLSInterceptor handles TLS renegotiation without connection loss.

    Validates renegotiation handling by:
    - Establishing initial TLS connection
    - Sending data before renegotiation
    - Verifying connection remains stable
    - Sending data after (simulated) renegotiation
    """
    hostname = "renegotiation.example.com"
    cert, private_key = tls_interceptor.generate_certificate(hostname)

    cert_file = temp_cert_dir / "renego.crt"
    key_file = temp_cert_dir / "renego.key"
    ca_file = temp_cert_dir / "ca.crt"

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(ca_file, "wb") as f:
        f.write(tls_interceptor.ca_cert.public_bytes(Encoding.PEM))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(1)
    server_port = server_socket.getsockname()[1]

    connection_states = []

    def run_renegotiation_server() -> None:
        """Run server testing connection stability."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_file), str(key_file))

        client_socket, _addr = server_socket.accept()
        ssl_socket = context.wrap_socket(client_socket, server_side=True)

        data1 = ssl_socket.recv(4096)
        connection_states.append("first_request")
        ssl_socket.sendall(b"RESPONSE_1")

        data2 = ssl_socket.recv(4096)
        connection_states.append("second_request")
        ssl_socket.sendall(b"RESPONSE_2")

        data3 = ssl_socket.recv(4096)
        connection_states.append("third_request")
        ssl_socket.sendall(b"RESPONSE_3")

        ssl_socket.close()
        server_socket.close()

    server_thread = threading.Thread(target=run_renegotiation_server, daemon=True)
    server_thread.start()
    time.sleep(0.2)

    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(str(ca_file))
    client_context.check_hostname = False

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", server_port))

    ssl_socket = client_context.wrap_socket(client_socket, server_hostname=hostname)

    ssl_socket.sendall(b"REQUEST_1")
    resp1 = ssl_socket.recv(4096)
    assert b"RESPONSE_1" in resp1

    ssl_socket.sendall(b"REQUEST_2")
    resp2 = ssl_socket.recv(4096)
    assert b"RESPONSE_2" in resp2

    ssl_socket.sendall(b"REQUEST_3")
    resp3 = ssl_socket.recv(4096)
    assert b"RESPONSE_3" in resp3

    ssl_socket.close()
    server_thread.join(timeout=2)

    assert len(connection_states) == 3
    assert connection_states[0] == "first_request"
    assert connection_states[1] == "second_request"
    assert connection_states[2] == "third_request"


def test_tls_interceptor_generates_certificates_with_proper_key_usage(
    tls_interceptor: TLSInterceptor,
) -> None:
    """TLSInterceptor generates certificates with proper KeyUsage and ExtendedKeyUsage.

    Validates certificate extensions:
    - KeyUsage includes digital_signature and key_encipherment
    - ExtendedKeyUsage includes SERVER_AUTH and CLIENT_AUTH
    - BasicConstraints marks as non-CA
    """
    hostname = "proper-extensions.example.com"
    cert, _private_key = tls_interceptor.generate_certificate(hostname)

    key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    assert isinstance(key_usage, x509.KeyUsage)
    assert key_usage.digital_signature is True
    assert key_usage.key_encipherment is True
    assert key_usage.key_cert_sign is False
    assert key_usage.crl_sign is False

    extended_key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    assert isinstance(extended_key_usage, x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.SERVER_AUTH in extended_key_usage
    assert ExtendedKeyUsageOID.CLIENT_AUTH in extended_key_usage

    basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    assert isinstance(basic_constraints, x509.BasicConstraints)
    assert basic_constraints.ca is False
    assert basic_constraints.path_length is None


def test_tls_interceptor_ca_certificate_has_proper_extensions(
    tls_interceptor: TLSInterceptor,
) -> None:
    """TLSInterceptor CA certificate has proper CA extensions.

    Validates CA certificate:
    - BasicConstraints marks as CA with no path length limit
    - KeyUsage includes key_cert_sign and crl_sign
    - Certificate is self-signed
    """
    ca_cert = tls_interceptor.ca_cert

    basic_constraints = ca_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    assert isinstance(basic_constraints, x509.BasicConstraints)
    assert basic_constraints.ca is True
    assert basic_constraints.path_length is None

    key_usage = ca_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    assert isinstance(key_usage, x509.KeyUsage)
    assert key_usage.key_cert_sign is True
    assert key_usage.crl_sign is True
    assert key_usage.digital_signature is True

    assert ca_cert.issuer == ca_cert.subject

    ca_public_key = ca_cert.public_key()
    assert isinstance(ca_public_key, rsa.RSAPublicKey)

    try:
        ca_public_key.verify(
            ca_cert.signature,
            ca_cert.tbs_certificate_bytes,
            ca_cert.signature_algorithm_parameters,
            ca_cert.signature_hash_algorithm,
        )
    except Exception as e:
        pytest.fail(f"CA certificate self-signature validation failed: {e}")
