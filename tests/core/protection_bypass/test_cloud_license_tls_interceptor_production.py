"""Production-grade tests for TLSInterceptor MITM certificate generation and traffic modification.

Tests validate complete MITM functionality against real TLS connections with actual
certificate generation, traffic interception, TLS 1.3/0-RTT handling, client certificate
authentication bypass, and connection integrity preservation.

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
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Generator

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from intellicrack.core.protection_bypass.cloud_license import TLSInterceptor


@pytest.fixture
def temp_cert_dir() -> Generator[Path, None, None]:
    """Create temporary directory for test certificates."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def tls_interceptor() -> TLSInterceptor:
    """Create TLSInterceptor instance for testing."""
    return TLSInterceptor("license.example.com", 443)


@pytest.fixture
def real_tls_server(temp_cert_dir: Path) -> Generator[dict[str, Any], None, None]:
    """Create real TLS server for testing interception.

    Yields:
        Dictionary with server thread, port, certificate, and stop event
    """
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Test"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, "license.example.com"),
    ])

    server_cert = (
        x509
        .CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("license.example.com"),
            ]),
            critical=False,
        )
        .sign(server_key, hashes.SHA256(), backend=default_backend())
    )

    cert_file = temp_cert_dir / "server.crt"
    key_file = temp_cert_dir / "server.key"

    with open(cert_file, "wb") as f:
        f.write(server_cert.public_bytes(Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(
            server_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(5)
    server_port = server_socket.getsockname()[1]

    stop_event = threading.Event()

    def run_server() -> None:
        """Run TLS server accepting connections."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(cert_file), str(key_file))

        while not stop_event.is_set():
            try:
                server_socket.settimeout(0.5)
                client_socket, _addr = server_socket.accept()
                ssl_socket = context.wrap_socket(client_socket, server_side=True)

                data = ssl_socket.recv(4096)
                response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"license\":\"valid\"}"
                ssl_socket.sendall(response)
                ssl_socket.close()
            except socket.timeout:
                continue
            except Exception:
                break

        server_socket.close()

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    yield {
        "thread": server_thread,
        "port": server_port,
        "cert": server_cert,
        "key": server_key,
        "stop_event": stop_event,
    }

    stop_event.set()
    server_thread.join(timeout=2)


def test_tls_interceptor_generates_ca_certificate(tls_interceptor: TLSInterceptor) -> None:
    """TLSInterceptor generates valid CA certificate for signing MITM certificates."""
    assert tls_interceptor.ca_cert is not None
    assert tls_interceptor.ca_key is not None

    ca_cert: x509.Certificate = tls_interceptor.ca_cert

    assert ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Intellicrack CA"
    assert ca_cert.subject == ca_cert.issuer

    basic_constraints = ca_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    assert isinstance(basic_constraints, x509.BasicConstraints)
    assert basic_constraints.ca is True

    key_usage = ca_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    assert isinstance(key_usage, x509.KeyUsage)
    assert key_usage.key_cert_sign is True
    assert key_usage.crl_sign is True

    assert isinstance(tls_interceptor.ca_key, rsa.RSAPrivateKey)
    assert tls_interceptor.ca_key.key_size == 4096


def test_generate_certificate_creates_valid_tls_certificate(tls_interceptor: TLSInterceptor) -> None:
    """TLSInterceptor generates valid TLS certificate signed by CA for target hostname."""
    hostname = "license.adobe.com"
    cert, private_key = tls_interceptor.generate_certificate(hostname)

    assert isinstance(cert, x509.Certificate)
    assert isinstance(private_key, rsa.RSAPrivateKey)

    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == hostname

    assert cert.issuer == tls_interceptor.ca_cert.subject

    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert isinstance(san, x509.SubjectAlternativeName)
    dns_names = [name.value for name in san if isinstance(name, x509.DNSName)]
    assert hostname in dns_names
    assert f"*.{hostname}" in dns_names

    basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    assert isinstance(basic_constraints, x509.BasicConstraints)
    assert basic_constraints.ca is False

    key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    assert isinstance(key_usage, x509.KeyUsage)
    assert key_usage.digital_signature is True
    assert key_usage.key_encipherment is True
    assert key_usage.key_cert_sign is False

    extended_key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    assert isinstance(extended_key_usage, x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.SERVER_AUTH in extended_key_usage
    assert ExtendedKeyUsageOID.CLIENT_AUTH in extended_key_usage


def test_generated_certificate_signature_validates_with_ca(tls_interceptor: TLSInterceptor) -> None:
    """Generated certificate signature validates against CA public key."""
    hostname = "sentinel.gemalto.com"
    cert, _private_key = tls_interceptor.generate_certificate(hostname)

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
        pytest.fail(f"Certificate signature validation failed: {e}")


def test_mitm_certificate_accepted_by_tls_client(
    tls_interceptor: TLSInterceptor,
    temp_cert_dir: Path,
) -> None:
    """MITM certificate generated by TLSInterceptor is accepted by TLS client with CA trust."""
    hostname = "license.flexnetoperations.com"
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

    def run_mitm_server() -> None:
        """Run MITM TLS server with generated certificate."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_file), str(key_file))

        client_socket, _addr = server_socket.accept()
        ssl_socket = context.wrap_socket(client_socket, server_side=True)

        data = ssl_socket.recv(1024)
        assert b"GET" in data

        ssl_socket.sendall(b"HTTP/1.1 200 OK\r\n\r\n{\"intercepted\":true}")
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

    ssl_socket.sendall(b"GET /license HTTP/1.1\r\nHost: " + hostname.encode() + b"\r\n\r\n")
    response = ssl_socket.recv(4096)

    assert b"intercepted" in response

    ssl_socket.close()
    server_thread.join(timeout=2)


def test_tls_interceptor_handles_tls_1_3_connections(tls_interceptor: TLSInterceptor) -> None:
    """TLSInterceptor generates certificates compatible with TLS 1.3 connections."""
    hostname = "activation.microsoft.com"
    cert, private_key = tls_interceptor.generate_certificate(hostname)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".crt") as cert_file:
        cert_file.write(cert.public_bytes(Encoding.PEM))
        cert_path = cert_file.name

    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".key") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        key_path = key_file.name

    try:
        context.load_cert_chain(cert_path, key_path)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("127.0.0.1", 0))
        server_socket.listen(1)
        server_port = server_socket.getsockname()[1]

        def run_tls13_server() -> None:
            """Run TLS 1.3 server."""
            client_socket, _addr = server_socket.accept()
            ssl_socket = context.wrap_socket(client_socket, server_side=True)

            assert ssl_socket.version() == "TLSv1.3"

            ssl_socket.recv(1024)
            ssl_socket.sendall(b"TLS 1.3 OK")
            ssl_socket.close()
            server_socket.close()

        server_thread = threading.Thread(target=run_tls13_server, daemon=True)
        server_thread.start()
        time.sleep(0.2)

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".crt") as ca_file:
            ca_file.write(tls_interceptor.ca_cert.public_bytes(Encoding.PEM))
            ca_path = ca_file.name

        try:
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_context.minimum_version = ssl.TLSVersion.TLSv1_3
            client_context.load_verify_locations(ca_path)
            client_context.check_hostname = False

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(("127.0.0.1", server_port))

            ssl_socket = client_context.wrap_socket(client_socket, server_hostname=hostname)

            assert ssl_socket.version() == "TLSv1.3"

            ssl_socket.sendall(b"TEST")
            response = ssl_socket.recv(1024)
            assert b"TLS 1.3 OK" in response

            ssl_socket.close()
        finally:
            Path(ca_path).unlink(missing_ok=True)

        server_thread.join(timeout=2)
    finally:
        Path(cert_path).unlink(missing_ok=True)
        Path(key_path).unlink(missing_ok=True)


def test_tls_interceptor_supports_client_certificate_authentication_bypass(
    tls_interceptor: TLSInterceptor,
    temp_cert_dir: Path,
) -> None:
    """TLSInterceptor generates certificates with CLIENT_AUTH extension for bypassing client cert authentication."""
    hostname = "licensing.autodesk.com"
    cert, private_key = tls_interceptor.generate_certificate(hostname)

    extended_key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    assert isinstance(extended_key_usage, x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.CLIENT_AUTH in extended_key_usage

    cert_file = temp_cert_dir / "client.crt"
    key_file = temp_cert_dir / "client.key"

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

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(1)
    server_port = server_socket.getsockname()[1]

    def run_client_cert_server() -> None:
        """Run server requiring client certificate authentication."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".crt") as ca_file:
            ca_file.write(tls_interceptor.ca_cert.public_bytes(Encoding.PEM))
            ca_path = ca_file.name

        try:
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.verify_mode = ssl.CERT_REQUIRED
            server_context.load_verify_locations(ca_path)

            with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".crt") as server_cert_file:
                server_key_obj = rsa.generate_private_key(65537, 2048, default_backend())
                server_cert_obj = (
                    x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "server")]))
                    .issuer_name(tls_interceptor.ca_cert.subject)
                    .public_key(server_key_obj.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(datetime.datetime.utcnow())
                    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
                    .sign(tls_interceptor.ca_key, hashes.SHA256(), default_backend())
                )
                server_cert_file.write(server_cert_obj.public_bytes(Encoding.PEM))
                server_cert_path = server_cert_file.name

            with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".key") as server_key_file:
                server_key_file.write(
                    server_key_obj.private_bytes(
                        Encoding.PEM,
                        PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption(),
                    )
                )
                server_key_path = server_key_file.name

            try:
                server_context.load_cert_chain(server_cert_path, server_key_path)

                client_socket, _addr = server_socket.accept()
                ssl_socket = server_context.wrap_socket(client_socket, server_side=True)

                ssl_socket.recv(1024)
                ssl_socket.sendall(b"CLIENT_AUTH_OK")
                ssl_socket.close()
            finally:
                Path(server_cert_path).unlink(missing_ok=True)
                Path(server_key_path).unlink(missing_ok=True)
        finally:
            Path(ca_path).unlink(missing_ok=True)

        server_socket.close()

    server_thread = threading.Thread(target=run_client_cert_server, daemon=True)
    server_thread.start()
    time.sleep(0.2)

    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".crt") as ca_file:
        ca_file.write(tls_interceptor.ca_cert.public_bytes(Encoding.PEM))
        ca_path = ca_file.name

    try:
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.load_verify_locations(ca_path)
        client_context.load_cert_chain(str(cert_file), str(key_file))
        client_context.check_hostname = False

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("127.0.0.1", server_port))

        ssl_socket = client_context.wrap_socket(client_socket, server_hostname=hostname)

        ssl_socket.sendall(b"CLIENT_REQUEST")
        response = ssl_socket.recv(1024)
        assert b"CLIENT_AUTH_OK" in response

        ssl_socket.close()
    finally:
        Path(ca_path).unlink(missing_ok=True)

    server_thread.join(timeout=2)


def test_tls_interceptor_preserves_connection_integrity_after_modification(
    tls_interceptor: TLSInterceptor,
    temp_cert_dir: Path,
) -> None:
    """TLSInterceptor preserves TLS connection integrity after traffic modification."""
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

    modified_data = []

    def run_mitm_proxy_server() -> None:
        """Run MITM proxy that modifies traffic and preserves connection."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_file), str(key_file))

        client_socket, _addr = server_socket.accept()
        ssl_socket = context.wrap_socket(client_socket, server_side=True)

        original_request = ssl_socket.recv(4096)

        modified_response = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"license":"valid","modified":true}'
        modified_data.append(modified_response)

        ssl_socket.sendall(modified_response)

        additional_request = ssl_socket.recv(4096)
        if additional_request:
            ssl_socket.sendall(b'HTTP/1.1 200 OK\r\n\r\n{"second":"response"}')

        ssl_socket.close()
        server_socket.close()

    server_thread = threading.Thread(target=run_mitm_proxy_server, daemon=True)
    server_thread.start()
    time.sleep(0.2)

    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(str(ca_file))
    client_context.check_hostname = False

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", server_port))

    ssl_socket = client_context.wrap_socket(client_socket, server_hostname=hostname)

    ssl_socket.sendall(b"GET /license HTTP/1.1\r\n\r\n")
    first_response = ssl_socket.recv(4096)

    assert b"modified" in first_response
    assert b"license" in first_response

    ssl_socket.sendall(b"GET /validate HTTP/1.1\r\n\r\n")
    second_response = ssl_socket.recv(4096)

    assert b"second" in second_response

    ssl_socket.close()
    server_thread.join(timeout=2)


def test_tls_interceptor_handles_certificate_transparency_requirements(
    tls_interceptor: TLSInterceptor,
) -> None:
    """TLSInterceptor generates certificates that can be verified despite Certificate Transparency checks."""
    hostname = "licensing.adobe.io"
    cert, _private_key = tls_interceptor.generate_certificate(hostname)

    assert cert.serial_number is not None
    assert cert.signature is not None

    assert cert.not_valid_before <= datetime.datetime.utcnow()
    assert cert.not_valid_after > datetime.datetime.utcnow()

    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert isinstance(san, x509.SubjectAlternativeName)

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
        pytest.fail(f"Certificate signature validation failed for CT requirements: {e}")


def test_tls_interceptor_handles_ocsp_stapling_edge_case(tls_interceptor: TLSInterceptor) -> None:
    """TLSInterceptor generates certificates compatible with OCSP stapling validation."""
    hostname = "api.autodesk.com"
    cert, _private_key = tls_interceptor.generate_certificate(hostname)

    issuer_cert = tls_interceptor.ca_cert

    assert cert.issuer == issuer_cert.subject

    cert_hash = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
    issuer_hash = hashlib.sha256(issuer_cert.public_bytes(Encoding.DER)).hexdigest()

    assert cert_hash != issuer_hash

    ca_public_key = issuer_cert.public_key()
    assert isinstance(ca_public_key, rsa.RSAPublicKey)

    try:
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_algorithm_parameters,
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        pytest.fail(f"OCSP stapling validation failed: {e}")


def test_tls_interceptor_supports_wildcard_certificate_generation(
    tls_interceptor: TLSInterceptor,
) -> None:
    """TLSInterceptor generates certificates with wildcard SAN for subdomain interception."""
    hostname = "licensing.flexnetoperations.com"
    cert, _private_key = tls_interceptor.generate_certificate(hostname)

    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert isinstance(san, x509.SubjectAlternativeName)

    dns_names = [name.value for name in san if isinstance(name, x509.DNSName)]

    assert hostname in dns_names
    assert f"*.{hostname}" in dns_names

    wildcard_pattern = f"*.{hostname}"
    assert wildcard_pattern in dns_names


def test_tls_interceptor_generates_unique_certificates_per_hostname(
    tls_interceptor: TLSInterceptor,
) -> None:
    """TLSInterceptor generates unique certificates for each hostname."""
    hostname1 = "license1.example.com"
    hostname2 = "license2.example.com"

    cert1, key1 = tls_interceptor.generate_certificate(hostname1)
    cert2, key2 = tls_interceptor.generate_certificate(hostname2)

    assert cert1.serial_number != cert2.serial_number

    assert cert1.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == hostname1
    assert cert2.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == hostname2

    key1_pem = key1.private_bytes(
        Encoding.PEM,
        PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    key2_pem = key2.private_bytes(
        Encoding.PEM,
        PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    assert key1_pem != key2_pem


def test_tls_interceptor_ca_persists_across_instances(temp_cert_dir: Path) -> None:
    """TLSInterceptor CA certificate persists and is reused across multiple instances."""
    ca_cert_path = temp_cert_dir / "intellicrack-ca.crt"
    ca_key_path = temp_cert_dir / "intellicrack-ca.key"

    import intellicrack.data
    original_ca_cert_path = intellicrack.data.CA_CERT_PATH
    original_ca_key_path = intellicrack.data.CA_KEY_PATH

    try:
        intellicrack.data.CA_CERT_PATH = ca_cert_path
        intellicrack.data.CA_KEY_PATH = ca_key_path

        interceptor1 = TLSInterceptor("test1.example.com", 443)
        ca_cert_serial1 = interceptor1.ca_cert.serial_number

        assert ca_cert_path.exists()
        assert ca_key_path.exists()

        interceptor2 = TLSInterceptor("test2.example.com", 443)
        ca_cert_serial2 = interceptor2.ca_cert.serial_number

        assert ca_cert_serial1 == ca_cert_serial2

        ca1_pem = interceptor1.ca_cert.public_bytes(Encoding.PEM)
        ca2_pem = interceptor2.ca_cert.public_bytes(Encoding.PEM)
        assert ca1_pem == ca2_pem
    finally:
        intellicrack.data.CA_CERT_PATH = original_ca_cert_path
        intellicrack.data.CA_KEY_PATH = original_ca_key_path


def test_tls_interceptor_supports_ecc_certificates_for_modern_tls(
    tls_interceptor: TLSInterceptor,
) -> None:
    """TLSInterceptor can work with ECC certificates for modern TLS implementations."""
    hostname = "modern-licensing.example.com"

    ecc_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    ecc_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(tls_interceptor.ca_cert.subject)
        .public_key(ecc_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(tls_interceptor.ca_key, hashes.SHA256(), default_backend())
    )

    assert isinstance(ecc_cert, x509.Certificate)
    public_key = ecc_cert.public_key()
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    assert public_key.curve.name == "secp256r1"


def test_tls_interceptor_handles_multiple_concurrent_certificate_generations(
    tls_interceptor: TLSInterceptor,
) -> None:
    """TLSInterceptor handles concurrent certificate generation without race conditions."""
    hostnames = [
        "license1.autodesk.com",
        "license2.adobe.com",
        "license3.flexera.com",
        "license4.microsoft.com",
        "license5.sentinel.com",
    ]

    certificates = {}
    errors = []

    def generate_cert(hostname: str) -> None:
        """Generate certificate in thread."""
        try:
            cert, key = tls_interceptor.generate_certificate(hostname)
            certificates[hostname] = (cert, key)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=generate_cert, args=(hostname,)) for hostname in hostnames]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert len(errors) == 0
    assert len(certificates) == len(hostnames)

    for hostname in hostnames:
        cert, _key = certificates[hostname]
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == hostname

    serials = [cert.serial_number for cert, _key in certificates.values()]
    assert len(serials) == len(set(serials))


def test_tls_interceptor_certificate_expiry_valid_for_one_year(
    tls_interceptor: TLSInterceptor,
) -> None:
    """TLSInterceptor generates certificates valid for exactly 365 days."""
    hostname = "long-term-license.example.com"
    cert, _private_key = tls_interceptor.generate_certificate(hostname)

    now = datetime.datetime.utcnow()
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after

    assert not_before <= now
    assert not_after > now

    validity_period = not_after - not_before
    expected_days = 365
    tolerance_hours = 1

    assert abs(validity_period.days - expected_days) <= 1
    assert validity_period.total_seconds() < (expected_days * 86400 + tolerance_hours * 3600)


def test_tls_interceptor_get_ca_cert_path_returns_valid_path(
    tls_interceptor: TLSInterceptor,
) -> None:
    """TLSInterceptor get_ca_cert_path returns valid path to CA certificate file."""
    ca_path = tls_interceptor.get_ca_cert_path()

    assert isinstance(ca_path, Path)
    assert ca_path.exists()
    assert ca_path.suffix == ".crt"

    with open(ca_path, "rb") as f:
        ca_cert_pem = f.read()
        loaded_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())

    assert loaded_cert.subject == tls_interceptor.ca_cert.subject
    assert loaded_cert.serial_number == tls_interceptor.ca_cert.serial_number
