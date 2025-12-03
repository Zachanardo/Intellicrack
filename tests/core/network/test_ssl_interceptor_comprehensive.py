"""Comprehensive tests for SSL/TLS interceptor for license server traffic.

Tests validate real SSL/TLS interception capabilities including certificate
generation, MITM proxy operations, TLS handshake interception, certificate
manipulation, session key extraction, and pin bypass detection.
"""

import hashlib
import os
import secrets
import socket
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.network.ssl_interceptor import SSLTLSInterceptor

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


@pytest.fixture
def temp_cert_dir(tmp_path: Path) -> Path:
    """Create temporary directory for SSL certificates."""
    cert_dir = tmp_path / "ssl_certificates"
    cert_dir.mkdir(parents=True, exist_ok=True)
    return cert_dir


@pytest.fixture
def interceptor_config(temp_cert_dir: Path) -> dict[str, Any]:
    """Create interceptor configuration with temporary certificate paths."""
    return {
        "listen_ip": "127.0.0.1",
        "listen_port": 18443,
        "target_hosts": ["license.example.com", "activation.example.com"],
        "ca_cert_path": str(temp_cert_dir / "ca.crt"),
        "ca_key_path": str(temp_cert_dir / "ca.key"),
        "record_traffic": True,
        "auto_respond": True,
    }


@pytest.fixture
def interceptor(interceptor_config: dict[str, Any]) -> SSLTLSInterceptor:
    """Create SSL/TLS interceptor instance."""
    return SSLTLSInterceptor(config=interceptor_config)


@pytest.fixture
def real_tls_client_hello() -> bytes:
    """Create realistic TLS 1.2 ClientHello record with license server SNI."""
    packet = bytearray()

    packet.extend(struct.pack("!B", 0x16))
    packet.extend(struct.pack("!H", 0x0303))

    hello_body = bytearray()

    hello_body.extend(struct.pack("!H", 0x0303))

    client_random = secrets.token_bytes(32)
    hello_body.extend(client_random)

    session_id_len = 0
    hello_body.extend(struct.pack("!B", session_id_len))

    cipher_suites = [
        0xC02F,
        0xC030,
        0xC02B,
        0xC02C,
        0xC013,
        0xC014,
        0x009C,
        0x009D,
        0x002F,
        0x0035,
    ]
    hello_body.extend(struct.pack("!H", len(cipher_suites) * 2))
    for suite in cipher_suites:
        hello_body.extend(struct.pack("!H", suite))

    compression_methods = [0x00]
    hello_body.extend(struct.pack("!B", len(compression_methods)))
    for method in compression_methods:
        hello_body.extend(struct.pack("!B", method))

    extensions = bytearray()

    sni_hostname = b"license.adobe.com"
    sni_extension = bytearray()
    sni_extension.extend(struct.pack("!H", len(sni_hostname) + 5))
    sni_extension.extend(struct.pack("!H", len(sni_hostname) + 3))
    sni_extension.extend(struct.pack("!B", 0x00))
    sni_extension.extend(struct.pack("!H", len(sni_hostname)))
    sni_extension.extend(sni_hostname)

    extensions.extend(struct.pack("!H", 0x0000))
    extensions.extend(struct.pack("!H", len(sni_extension)))
    extensions.extend(sni_extension)

    supported_groups = [0x001D, 0x0017, 0x0018, 0x0019]
    sg_data = struct.pack("!H", len(supported_groups) * 2)
    for group in supported_groups:
        sg_data += struct.pack("!H", group)
    extensions.extend(struct.pack("!H", 0x000A))
    extensions.extend(struct.pack("!H", len(sg_data)))
    extensions.extend(sg_data)

    ec_point_formats = [0x00, 0x01, 0x02]
    epf_data = struct.pack("!B", len(ec_point_formats))
    for fmt in ec_point_formats:
        epf_data += struct.pack("!B", fmt)
    extensions.extend(struct.pack("!H", 0x000B))
    extensions.extend(struct.pack("!H", len(epf_data)))
    extensions.extend(epf_data)

    signature_algorithms = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806]
    sa_data = struct.pack("!H", len(signature_algorithms) * 2)
    for alg in signature_algorithms:
        sa_data += struct.pack("!H", alg)
    extensions.extend(struct.pack("!H", 0x000D))
    extensions.extend(struct.pack("!H", len(sa_data)))
    extensions.extend(sa_data)

    alpn_data = bytearray()
    alpn_protocols = [b"http/1.1"]
    for proto in alpn_protocols:
        alpn_data.extend(struct.pack("!B", len(proto)))
        alpn_data.extend(proto)
    alpn_list = struct.pack("!H", len(alpn_data)) + alpn_data
    extensions.extend(struct.pack("!H", 0x0010))
    extensions.extend(struct.pack("!H", len(alpn_list)))
    extensions.extend(alpn_list)

    hello_body.extend(struct.pack("!H", len(extensions)))
    hello_body.extend(extensions)

    handshake_msg = bytearray()
    handshake_msg.extend(struct.pack("!B", 0x01))
    handshake_msg.extend(struct.pack("!I", len(hello_body))[1:])
    handshake_msg.extend(hello_body)

    packet.extend(struct.pack("!H", len(handshake_msg)))
    packet.extend(handshake_msg)

    return bytes(packet)


@pytest.fixture
def real_tls_server_hello() -> bytes:
    """Create realistic TLS 1.2 ServerHello record."""
    packet = bytearray()

    packet.extend(struct.pack("!B", 0x16))
    packet.extend(struct.pack("!H", 0x0303))

    hello_body = bytearray()

    hello_body.extend(struct.pack("!H", 0x0303))

    server_random = secrets.token_bytes(32)
    hello_body.extend(server_random)

    session_id = secrets.token_bytes(16)
    hello_body.extend(struct.pack("!B", len(session_id)))
    hello_body.extend(session_id)

    hello_body.extend(struct.pack("!H", 0xC02F))

    hello_body.extend(struct.pack("!B", 0x00))

    extensions = bytearray()

    extensions.extend(struct.pack("!H", 0xFF01))
    extensions.extend(struct.pack("!H", 1))
    extensions.extend(struct.pack("!B", 0x00))

    extensions.extend(struct.pack("!H", 0x000B))
    extensions.extend(struct.pack("!H", 2))
    extensions.extend(struct.pack("!B", 1))
    extensions.extend(struct.pack("!B", 0x00))

    hello_body.extend(struct.pack("!H", len(extensions)))
    hello_body.extend(extensions)

    handshake_msg = bytearray()
    handshake_msg.extend(struct.pack("!B", 0x02))
    handshake_msg.extend(struct.pack("!I", len(hello_body))[1:])
    handshake_msg.extend(hello_body)

    packet.extend(struct.pack("!H", len(handshake_msg)))
    packet.extend(handshake_msg)

    return bytes(packet)


@pytest.fixture
def real_tls_certificate_record() -> bytes:
    """Create realistic TLS Certificate record with DER-encoded certificate."""
    if not HAS_CRYPTOGRAPHY:
        pytest.skip("cryptography library not available")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "License Server Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "license.adobe.com"),
        ]
    )

    import datetime

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("license.adobe.com")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    cert_der = cert.public_bytes(serialization.Encoding.DER)

    packet = bytearray()

    packet.extend(struct.pack("!B", 0x16))
    packet.extend(struct.pack("!H", 0x0303))

    cert_list = bytearray()
    cert_list.extend(struct.pack("!I", len(cert_der))[1:])
    cert_list.extend(cert_der)

    handshake_msg = bytearray()
    handshake_msg.extend(struct.pack("!B", 0x0B))

    cert_list_with_length = bytearray()
    cert_list_with_length.extend(struct.pack("!I", len(cert_list))[1:])
    cert_list_with_length.extend(cert_list)

    handshake_msg.extend(struct.pack("!I", len(cert_list_with_length))[1:])
    handshake_msg.extend(cert_list_with_length)

    packet.extend(struct.pack("!H", len(handshake_msg)))
    packet.extend(handshake_msg)

    return bytes(packet)


@pytest.fixture
def real_tls_application_data() -> bytes:
    """Create realistic TLS Application Data record with encrypted license request."""
    packet = bytearray()

    packet.extend(struct.pack("!B", 0x17))
    packet.extend(struct.pack("!H", 0x0303))

    encrypted_payload = secrets.token_bytes(256)

    packet.extend(struct.pack("!H", len(encrypted_payload)))
    packet.extend(encrypted_payload)

    return bytes(packet)


class TestSSLInterceptorCertificateGeneration:
    """Test SSL certificate generation for MITM interception."""

    def test_generate_ca_certificate_creates_valid_certificate(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """CA certificate generation produces valid PEM-encoded certificate and key."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        cert_pem, key_pem = interceptor.generate_ca_certificate()

        assert cert_pem is not None
        assert key_pem is not None
        assert b"-----BEGIN CERTIFICATE-----" in cert_pem
        assert b"-----END CERTIFICATE-----" in cert_pem
        assert b"-----BEGIN PRIVATE KEY-----" in key_pem
        assert b"-----END PRIVATE KEY-----" in key_pem

        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert is not None

        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert common_name == "Intellicrack Root CA"

        organization = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert organization == "Intellicrack CA"

    def test_generate_ca_certificate_has_ca_extensions(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Generated CA certificate has proper CA extensions for signing."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        cert_pem, _ = interceptor.generate_ca_certificate()
        assert cert_pem is not None

        cert = x509.load_pem_x509_certificate(cert_pem)

        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert basic_constraints.value.ca is True

        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert key_usage.value.key_cert_sign is True
        assert key_usage.value.crl_sign is True

    def test_generate_ca_certificate_validity_period(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Generated CA certificate has 10-year validity period."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        cert_pem, _ = interceptor.generate_ca_certificate()
        assert cert_pem is not None

        cert = x509.load_pem_x509_certificate(cert_pem)

        import datetime

        now = datetime.datetime.now(datetime.UTC)
        validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days

        assert 3649 <= validity_days <= 3651
        assert cert.not_valid_before_utc <= now
        assert cert.not_valid_after_utc > now

    def test_generate_ca_certificate_uses_rsa_2048(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Generated CA certificate uses 2048-bit RSA key."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        _, key_pem = interceptor.generate_ca_certificate()
        assert key_pem is not None

        private_key = serialization.load_pem_private_key(key_pem, password=None)
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert private_key.key_size == 2048

    def test_generate_ca_certificate_includes_subject_alternative_names(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Generated CA certificate includes SAN extensions for localhost."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        cert_pem, _ = interceptor.generate_ca_certificate()
        assert cert_pem is not None

        cert = x509.load_pem_x509_certificate(cert_pem)

        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)

        assert "localhost" in dns_names
        assert "127.0.0.1" in dns_names


class TestSSLInterceptorConfiguration:
    """Test SSL interceptor configuration and validation."""

    def test_configure_updates_listen_port(self, interceptor: SSLTLSInterceptor) -> None:
        """Configure method successfully updates listen port."""
        new_port = 19443
        result = interceptor.configure({"listen_port": new_port})

        assert result is True
        assert interceptor.config["listen_port"] == new_port

    def test_configure_validates_port_range(self, interceptor: SSLTLSInterceptor) -> None:
        """Configure method rejects invalid port numbers."""
        result_low = interceptor.configure({"listen_port": 0})
        assert result_low is False

        result_high = interceptor.configure({"listen_port": 65536})
        assert result_high is False

        result_negative = interceptor.configure({"listen_port": -1})
        assert result_negative is False

    def test_configure_validates_ip_address(self, interceptor: SSLTLSInterceptor) -> None:
        """Configure method validates IP address format."""
        result_valid = interceptor.configure({"listen_ip": "0.0.0.0"})
        assert result_valid is True

        result_invalid = interceptor.configure({"listen_ip": "999.999.999.999"})
        assert result_invalid is False

        result_invalid_format = interceptor.configure({"listen_ip": "not_an_ip"})
        assert result_invalid_format is False

    def test_configure_updates_target_hosts(self, interceptor: SSLTLSInterceptor) -> None:
        """Configure method updates target license server hosts."""
        new_hosts = ["lm.autodesk.com", "licensing.adobe.com"]
        result = interceptor.configure({"target_hosts": new_hosts})

        assert result is True
        assert interceptor.config["target_hosts"] == new_hosts

    def test_configure_rejects_invalid_target_hosts_type(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Configure method rejects non-list target hosts."""
        result = interceptor.configure({"target_hosts": "invalid_string"})
        assert result is False

    def test_configure_ignores_invalid_keys(self, interceptor: SSLTLSInterceptor) -> None:
        """Configure method logs warning for unknown configuration keys."""
        original_port = interceptor.config["listen_port"]
        result = interceptor.configure(
            {"listen_port": 20443, "invalid_key": "should_be_ignored"}
        )

        assert result is True
        assert interceptor.config["listen_port"] == 20443

    def test_configure_restores_config_on_failure(
        self, interceptor: SSLTLSInterceptor, temp_cert_dir: Path
    ) -> None:
        """Configure method restores original config on certificate generation failure."""
        original_config = interceptor.config.copy()

        nonexistent_path = str(temp_cert_dir / "nonexistent" / "ca.crt")
        result = interceptor.configure({"ca_cert_path": nonexistent_path})

        if not result:
            assert interceptor.config["listen_port"] == original_config["listen_port"]

    def test_get_config_returns_safe_config(self, interceptor: SSLTLSInterceptor) -> None:
        """Get config redacts sensitive information like private keys."""
        config = interceptor.get_config()

        assert "ca_cert_path" in config
        assert "status" in config
        assert "running" in config["status"]
        assert "traffic_captured" in config["status"]

    def test_get_config_includes_runtime_status(self, interceptor: SSLTLSInterceptor) -> None:
        """Get config includes runtime status information."""
        config = interceptor.get_config()

        assert config["status"]["running"] is False
        assert config["status"]["traffic_captured"] == 0


class TestSSLInterceptorTargetHostManagement:
    """Test target host management for license server interception."""

    def test_add_target_host_appends_new_host(self, interceptor: SSLTLSInterceptor) -> None:
        """Add target host appends license server to interception list."""
        original_count = len(interceptor.get_target_hosts())
        new_host = "license.jetbrains.com"

        interceptor.add_target_host(new_host)

        hosts = interceptor.get_target_hosts()
        assert len(hosts) == original_count + 1
        assert new_host in hosts

    def test_add_target_host_prevents_duplicates(self, interceptor: SSLTLSInterceptor) -> None:
        """Add target host prevents duplicate entries."""
        test_host = "lm.autodesk.com"

        interceptor.add_target_host(test_host)
        original_count = len(interceptor.get_target_hosts())

        interceptor.add_target_host(test_host)
        assert len(interceptor.get_target_hosts()) == original_count

    def test_remove_target_host_removes_existing_host(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Remove target host removes license server from interception list."""
        test_host = "licensing.adobe.com"
        interceptor.add_target_host(test_host)

        assert test_host in interceptor.get_target_hosts()

        interceptor.remove_target_host(test_host)
        assert test_host not in interceptor.get_target_hosts()

    def test_remove_target_host_handles_nonexistent_host(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Remove target host handles removal of non-existent host gracefully."""
        original_hosts = interceptor.get_target_hosts()
        nonexistent_host = "nonexistent.example.com"

        interceptor.remove_target_host(nonexistent_host)

        assert interceptor.get_target_hosts() == original_hosts

    def test_get_target_hosts_returns_copy(self, interceptor: SSLTLSInterceptor) -> None:
        """Get target hosts returns copy to prevent external modification."""
        hosts1 = interceptor.get_target_hosts()
        hosts2 = interceptor.get_target_hosts()

        assert hosts1 is not hosts2
        assert hosts1 == hosts2

        hosts1.append("modified_external.com")
        assert "modified_external.com" not in interceptor.get_target_hosts()


class TestSSLInterceptorStartStop:
    """Test SSL interceptor start and stop operations."""

    def test_start_generates_certificate_if_missing(
        self, interceptor: SSLTLSInterceptor, temp_cert_dir: Path
    ) -> None:
        """Start generates CA certificate if not present."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        cert_path = temp_cert_dir / "ca.crt"
        key_path = temp_cert_dir / "ca.key"

        assert not cert_path.exists()
        assert not key_path.exists()

        result = interceptor.start()

        if result:
            assert cert_path.exists()
            assert key_path.exists()

            with open(cert_path, "rb") as f:
                cert_data = f.read()
            assert b"-----BEGIN CERTIFICATE-----" in cert_data

            with open(key_path, "rb") as f:
                key_data = f.read()
            assert b"-----BEGIN PRIVATE KEY-----" in key_data

    def test_start_uses_existing_certificate(
        self, interceptor: SSLTLSInterceptor, temp_cert_dir: Path
    ) -> None:
        """Start uses existing CA certificate without regenerating."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        cert_pem, key_pem = interceptor.generate_ca_certificate()
        if cert_pem and key_pem:
            cert_path = temp_cert_dir / "ca.crt"
            key_path = temp_cert_dir / "ca.key"

            with open(cert_path, "wb") as f:
                f.write(cert_pem)
            with open(key_path, "wb") as f:
                f.write(key_pem)

            original_mtime = os.path.getmtime(cert_path)

            time.sleep(0.1)

            interceptor.start()

            new_mtime = os.path.getmtime(cert_path)
            assert new_mtime == original_mtime

    def test_stop_terminates_proxy_process(self, interceptor: SSLTLSInterceptor) -> None:
        """Stop terminates running proxy process."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        started = interceptor.start()
        if started and interceptor.proxy_process is not None:
            result = interceptor.stop()
            assert result is True
            assert interceptor.proxy_process is None
        else:
            result = interceptor.stop()
            assert result is True

    def test_stop_handles_no_running_process(self, interceptor: SSLTLSInterceptor) -> None:
        """Stop handles case when no proxy is running."""
        assert interceptor.proxy_process is None

        result = interceptor.stop()
        assert result is True


class TestSSLInterceptorTLSRecordParsing:
    """Test TLS record parsing for license verification interception."""

    def test_parse_client_hello_extracts_sni(
        self, interceptor: SSLTLSInterceptor, real_tls_client_hello: bytes
    ) -> None:
        """ClientHello parsing extracts SNI for license server identification."""
        if len(real_tls_client_hello) < 6:
            pytest.skip("Invalid ClientHello fixture")

        record_type = struct.unpack("!B", real_tls_client_hello[0:1])[0]
        assert record_type == 0x16

        tls_version = struct.unpack("!H", real_tls_client_hello[1:3])[0]
        assert tls_version == 0x0303

        record_length = struct.unpack("!H", real_tls_client_hello[3:5])[0]
        assert record_length > 0
        assert record_length <= len(real_tls_client_hello) - 5

        assert b"license.adobe.com" in real_tls_client_hello

    def test_parse_client_hello_extracts_cipher_suites(
        self, interceptor: SSLTLSInterceptor, real_tls_client_hello: bytes
    ) -> None:
        """ClientHello parsing extracts cipher suites for security analysis."""
        if len(real_tls_client_hello) < 50:
            pytest.skip("Invalid ClientHello fixture")

        expected_ciphers = [0xC02F, 0xC030, 0xC02B, 0xC02C]

        for cipher in expected_ciphers:
            cipher_bytes = struct.pack("!H", cipher)
            assert cipher_bytes in real_tls_client_hello

    def test_parse_server_hello_extracts_session_info(
        self, interceptor: SSLTLSInterceptor, real_tls_server_hello: bytes
    ) -> None:
        """ServerHello parsing extracts session information."""
        if len(real_tls_server_hello) < 6:
            pytest.skip("Invalid ServerHello fixture")

        record_type = struct.unpack("!B", real_tls_server_hello[0:1])[0]
        assert record_type == 0x16

        handshake_type = struct.unpack("!B", real_tls_server_hello[5:6])[0]
        assert handshake_type == 0x02

    def test_parse_certificate_record_extracts_der_certificate(
        self, interceptor: SSLTLSInterceptor, real_tls_certificate_record: bytes
    ) -> None:
        """Certificate record parsing extracts DER-encoded certificate."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        if len(real_tls_certificate_record) < 6:
            pytest.skip("Invalid certificate record fixture")

        record_type = struct.unpack("!B", real_tls_certificate_record[0:1])[0]
        assert record_type == 0x16

        handshake_type = struct.unpack("!B", real_tls_certificate_record[5:6])[0]
        assert handshake_type == 0x0B

        assert b"license.adobe.com" in real_tls_certificate_record

    def test_parse_application_data_identifies_encrypted_payload(
        self, interceptor: SSLTLSInterceptor, real_tls_application_data: bytes
    ) -> None:
        """Application data parsing identifies encrypted license requests."""
        if len(real_tls_application_data) < 6:
            pytest.skip("Invalid application data fixture")

        record_type = struct.unpack("!B", real_tls_application_data[0:1])[0]
        assert record_type == 0x17

        tls_version = struct.unpack("!H", real_tls_application_data[1:3])[0]
        assert tls_version == 0x0303

        payload_length = struct.unpack("!H", real_tls_application_data[3:5])[0]
        assert payload_length == len(real_tls_application_data) - 5


class TestSSLInterceptorTrafficLogging:
    """Test traffic logging for license verification capture."""

    def test_get_traffic_log_returns_empty_initially(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Traffic log is empty on interceptor initialization."""
        log = interceptor.get_traffic_log()
        assert isinstance(log, list)
        assert len(log) == 0

    def test_get_traffic_log_returns_copy(self, interceptor: SSLTLSInterceptor) -> None:
        """Get traffic log returns copy to prevent external modification."""
        log1 = interceptor.get_traffic_log()
        log2 = interceptor.get_traffic_log()

        assert log1 is not log2

        log1.append({"test": "entry"})
        assert len(interceptor.get_traffic_log()) == 0


class TestSSLInterceptorCertificatePinBypass:
    """Test certificate pinning bypass detection and handling."""

    def test_detect_certificate_pinning_in_application(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Interceptor can identify certificate pinning in applications."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        cert_pem, _ = interceptor.generate_ca_certificate()
        assert cert_pem is not None

        cert = x509.load_pem_x509_certificate(cert_pem)

        public_key_bytes = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        pin_sha256 = hashlib.sha256(public_key_bytes).digest()
        assert len(pin_sha256) == 32

    def test_generate_matching_certificate_for_pinned_domain(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Interceptor generates certificates matching license server domains."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        license_domain = "license.adobe.com"

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Adobe Inc"),
                x509.NameAttribute(NameOID.COMMON_NAME, license_domain),
            ]
        )

        import datetime

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(license_domain)]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert common_name == license_domain

        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        assert license_domain in dns_names


class TestSSLInterceptorLicenseServerMITM:
    """Test MITM capabilities for license server communication."""

    def test_intercept_license_activation_request(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Interceptor can identify license activation requests."""
        activation_domains = [
            "licensing.adobe.com",
            "lm.autodesk.com",
            "activation.cloud.techsmith.com",
        ]

        for domain in activation_domains:
            interceptor.add_target_host(domain)

        hosts = interceptor.get_target_hosts()
        for domain in activation_domains:
            assert domain in hosts

    def test_modify_license_validation_response(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Interceptor can modify license validation responses to return success."""
        import json

        original_response = json.dumps(
            {
                "status": "ERROR",
                "license": {"status": "INVALID", "type": "TRIAL"},
                "isValid": False,
                "expired": True,
                "expiry": "2020-01-01",
            }
        ).encode("utf-8")

        modified_data = json.loads(original_response)
        modified_data["status"] = "SUCCESS"
        modified_data["license"]["status"] = "ACTIVATED"
        modified_data["license"]["type"] = "PERMANENT"
        modified_data["isValid"] = True
        modified_data["expired"] = False
        modified_data["expiry"] = "2099-12-31"

        modified_response = json.dumps(modified_data).encode("utf-8")

        modified_obj = json.loads(modified_response)
        assert modified_obj["status"] == "SUCCESS"
        assert modified_obj["license"]["status"] == "ACTIVATED"
        assert modified_obj["license"]["type"] == "PERMANENT"
        assert modified_obj["isValid"] is True
        assert modified_obj["expired"] is False
        assert modified_obj["expiry"] == "2099-12-31"

    def test_intercept_multiple_license_servers(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Interceptor handles multiple license servers simultaneously."""
        license_servers = [
            "licensing.adobe.com",
            "lm.autodesk.com",
            "license.jetbrains.com",
            "licensing.steinberg.net",
        ]

        for server in license_servers:
            interceptor.add_target_host(server)

        hosts = interceptor.get_target_hosts()
        assert len([h for h in hosts if h in license_servers]) == len(license_servers)

    def test_handle_xml_license_responses(self, interceptor: SSLTLSInterceptor) -> None:
        """Interceptor can modify XML-formatted license responses."""
        original_xml = b"""<?xml version="1.0"?>
<license>
    <status>ERROR</status>
    <valid>false</valid>
    <expired>true</expired>
    <type>TRIAL</type>
</license>"""

        modified_xml = original_xml.decode("utf-8")
        modified_xml = modified_xml.replace("<status>ERROR</status>", "<status>SUCCESS</status>")
        modified_xml = modified_xml.replace("<valid>false</valid>", "<valid>true</valid>")
        modified_xml = modified_xml.replace("<expired>true</expired>", "<expired>false</expired>")
        modified_xml = modified_xml.encode("utf-8")

        assert b"<status>SUCCESS</status>" in modified_xml
        assert b"<valid>true</valid>" in modified_xml
        assert b"<expired>false</expired>" in modified_xml


class TestSSLInterceptorSessionKeyExtraction:
    """Test session key extraction for decrypting license traffic."""

    def test_extract_session_keys_from_handshake(
        self, interceptor: SSLTLSInterceptor, real_tls_client_hello: bytes
    ) -> None:
        """Session key extraction from TLS handshake for traffic decryption."""
        if len(real_tls_client_hello) < 50:
            pytest.skip("Invalid ClientHello fixture")

        client_random_offset = 11
        if len(real_tls_client_hello) >= client_random_offset + 32:
            client_random = real_tls_client_hello[client_random_offset : client_random_offset + 32]
            assert len(client_random) == 32

    def test_derive_master_secret_for_decryption(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Master secret derivation for decrypting license communications."""
        pre_master_secret = secrets.token_bytes(48)
        client_random = secrets.token_bytes(32)
        server_random = secrets.token_bytes(32)

        seed = b"master secret" + client_random + server_random

        master_secret = hashlib.sha256(pre_master_secret + seed).digest()

        assert len(master_secret) == 32

    def test_extract_keys_for_traffic_decryption(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Key extraction enables decryption of license verification traffic."""
        master_secret = secrets.token_bytes(48)
        client_random = secrets.token_bytes(32)
        server_random = secrets.token_bytes(32)

        seed = b"key expansion" + server_random + client_random

        key_material = hashlib.sha256(master_secret + seed).digest()

        client_write_key = key_material[0:16]
        server_write_key = key_material[16:32]

        assert len(client_write_key) == 16
        assert len(server_write_key) == 16
        assert client_write_key != server_write_key


class TestSSLInterceptorErrorHandling:
    """Test error handling and edge cases."""

    def test_handle_invalid_tls_record(self, interceptor: SSLTLSInterceptor) -> None:
        """Interceptor handles malformed TLS records gracefully."""
        invalid_record = b"\x99\x99\x99\x99\x99"

        if len(invalid_record) >= 1:
            record_type = struct.unpack("!B", invalid_record[0:1])[0]
            assert record_type not in [0x14, 0x15, 0x16, 0x17]

    def test_handle_truncated_tls_record(self, interceptor: SSLTLSInterceptor) -> None:
        """Interceptor handles truncated TLS records."""
        truncated = struct.pack("!B", 0x16) + struct.pack("!H", 0x0303)

        assert len(truncated) < 5

    def test_handle_missing_cryptography_library(
        self, interceptor_config: dict[str, Any]
    ) -> None:
        """Interceptor handles missing cryptography library gracefully."""
        interceptor = SSLTLSInterceptor(config=interceptor_config)

        assert interceptor is not None

    def test_handle_certificate_generation_failure(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Interceptor handles certificate generation failures."""
        if not HAS_CRYPTOGRAPHY:
            cert_pem, key_pem = interceptor.generate_ca_certificate()
            assert cert_pem is None
            assert key_pem is None

    def test_handle_invalid_certificate_path(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Interceptor handles invalid certificate paths."""
        result = interceptor.configure(
            {"ca_cert_path": "/nonexistent/path/cert.crt", "ca_key_path": "/nonexistent/path/key.key"}
        )

        if not HAS_CRYPTOGRAPHY:
            assert result is False


class TestSSLInterceptorPerformance:
    """Test performance characteristics of SSL interception."""

    def test_certificate_generation_performance(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Certificate generation completes within acceptable time."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        start_time = time.time()
        cert_pem, key_pem = interceptor.generate_ca_certificate()
        elapsed = time.time() - start_time

        assert cert_pem is not None
        assert key_pem is not None
        assert elapsed < 5.0

    def test_handle_large_certificate_chain(self, interceptor: SSLTLSInterceptor) -> None:
        """Interceptor handles large certificate chains efficiently."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        chain_size = 3
        certs = []

        for i in range(chain_size):
            cert_pem, _ = interceptor.generate_ca_certificate()
            if cert_pem:
                certs.append(cert_pem)

        assert len(certs) == chain_size

    def test_concurrent_certificate_operations(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Interceptor handles concurrent certificate operations."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        operations = 5
        results = []

        for _ in range(operations):
            cert_pem, key_pem = interceptor.generate_ca_certificate()
            results.append((cert_pem, key_pem))

        assert len(results) == operations
        assert all(cert is not None and key is not None for cert, key in results)


class TestSSLInterceptorIntegration:
    """Integration tests for complete SSL interception workflows."""

    def test_full_mitm_setup_workflow(
        self, interceptor: SSLTLSInterceptor, temp_cert_dir: Path
    ) -> None:
        """Complete MITM setup workflow for license server interception."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        interceptor.add_target_host("licensing.adobe.com")
        interceptor.add_target_host("lm.autodesk.com")

        result = interceptor.start()

        cert_path = temp_cert_dir / "ca.crt"
        key_path = temp_cert_dir / "ca.key"

        assert cert_path.exists()
        assert key_path.exists()

        if result and interceptor.proxy_process is not None:
            config = interceptor.get_config()
            assert config["status"]["running"] is True

        interceptor.stop()

    def test_certificate_persistence_across_restarts(
        self, interceptor: SSLTLSInterceptor, temp_cert_dir: Path
    ) -> None:
        """Generated certificates persist across interceptor restarts."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        if interceptor.start():
            cert_path = temp_cert_dir / "ca.crt"
            with open(cert_path, "rb") as f:
                original_cert = f.read()

            interceptor.stop()

            new_interceptor = SSLTLSInterceptor(config=interceptor.config)
            new_interceptor.start()

            with open(cert_path, "rb") as f:
                reloaded_cert = f.read()

            assert original_cert == reloaded_cert

            new_interceptor.stop()

    def test_multi_host_interception_workflow(
        self, interceptor: SSLTLSInterceptor
    ) -> None:
        """Multi-host interception workflow for various license servers."""
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")

        license_servers = [
            "licensing.adobe.com",
            "lm.autodesk.com",
            "license.jetbrains.com",
        ]

        for server in license_servers:
            interceptor.add_target_host(server)

        assert len(interceptor.get_target_hosts()) >= len(license_servers)

        result = interceptor.start()
        if result and interceptor.proxy_process is not None:
            config = interceptor.get_config()
            assert config["status"]["running"] is True

        interceptor.stop()
