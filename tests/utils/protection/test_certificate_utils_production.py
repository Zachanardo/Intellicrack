"""Production tests for certificate_utils module.

Tests real X.509 certificate generation, validation, and management capabilities
used for SSL/TLS operations in license server emulation and network interception.
"""

from __future__ import annotations

import datetime
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from cryptography import x509

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

from intellicrack.utils.protection.certificate_utils import (
    generate_self_signed_cert,
    get_certificate_info,
    load_certificate_from_file,
    verify_certificate_validity,
)


pytestmark = pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="cryptography library required")


class TestCertificateGeneration:
    """Test real certificate generation capabilities."""

    def test_generate_self_signed_cert_creates_valid_certificate(self) -> None:
        """Certificate generation produces valid X.509 certificate with correct structure."""
        result = generate_self_signed_cert(
            common_name="test.example.com",
            organization="TestOrg",
            country="US",
            state="California",
            locality="San Francisco",
            valid_days=365,
        )

        assert result is not None
        cert_pem, key_pem = result

        assert isinstance(cert_pem, bytes)
        assert isinstance(key_pem, bytes)
        assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")

        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert is not None

        subject = cert.subject
        subject_dict = {attr.oid._name: attr.value for attr in subject}
        assert subject_dict["commonName"] == "test.example.com"
        assert subject_dict["organizationName"] == "TestOrg"
        assert subject_dict["countryName"] == "US"

    def test_certificate_has_correct_validity_period(self) -> None:
        """Certificate has correct not_valid_before and not_valid_after dates."""
        valid_days = 730
        result = generate_self_signed_cert(common_name="validity-test.local", valid_days=valid_days)

        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)

        now = datetime.datetime.now(datetime.UTC)
        assert cert.not_valid_before <= now
        assert cert.not_valid_after > now

        validity_period = cert.not_valid_after - cert.not_valid_before
        expected_delta = datetime.timedelta(days=valid_days)
        delta_diff = abs((validity_period - expected_delta).total_seconds())
        assert delta_diff < 60

    def test_certificate_contains_subject_alternative_names(self) -> None:
        """Certificate includes SAN extension with common name and localhost entries."""
        result = generate_self_signed_cert(common_name="san-test.example.com")

        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)

        san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        assert san_ext is not None
        san_value = san_ext.value

        dns_names = san_value.get_values_for_type(x509.DNSName)  # type: ignore[attr-defined]
        assert "san-test.example.com" in dns_names
        assert "localhost" in dns_names
        assert "127.0.0.1" in dns_names

    def test_certificate_has_ca_basic_constraints(self) -> None:
        """Certificate has BasicConstraints extension marking it as CA."""
        result = generate_self_signed_cert(common_name="ca-test.local")

        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)

        basic_constraints_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
        assert basic_constraints_ext is not None
        assert basic_constraints_ext.critical is True

        bc_value = basic_constraints_ext.value
        assert bc_value.ca is True  # type: ignore[attr-defined]
        assert bc_value.path_length == 0  # type: ignore[attr-defined]

    def test_certificate_key_usage_includes_digital_signature(self) -> None:
        """Certificate KeyUsage extension includes digital_signature and key_encipherment."""
        result = generate_self_signed_cert(common_name="keyusage-test.local")

        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)

        key_usage_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        assert key_usage_ext is not None
        assert key_usage_ext.critical is True

        ku_value = key_usage_ext.value
        assert ku_value.digital_signature is True  # type: ignore[attr-defined]
        assert ku_value.key_encipherment is True  # type: ignore[attr-defined]
        assert ku_value.key_cert_sign is True  # type: ignore[attr-defined]
        assert ku_value.crl_sign is True  # type: ignore[attr-defined]

    def test_private_key_matches_certificate_public_key(self) -> None:
        """Private key corresponds to public key in certificate."""
        result = generate_self_signed_cert(common_name="keypair-test.local")

        assert result is not None
        cert_pem, key_pem = result

        cert = x509.load_pem_x509_certificate(cert_pem)
        private_key = serialization.load_pem_private_key(key_pem, password=None)

        cert_public_key = cert.public_key()
        private_public_key = private_key.public_key()

        cert_public_numbers = cert_public_key.public_numbers()  # type: ignore[union-attr]
        private_public_numbers = private_public_key.public_numbers()  # type: ignore[union-attr]

        assert cert_public_numbers.n == private_public_numbers.n  # type: ignore[union-attr]
        assert cert_public_numbers.e == private_public_numbers.e  # type: ignore[union-attr]

    def test_certificate_uses_rsa_2048_key(self) -> None:
        """Certificate uses RSA 2048-bit key for security."""
        result = generate_self_signed_cert(common_name="rsa-test.local")

        assert result is not None
        _, key_pem = result

        private_key = serialization.load_pem_private_key(key_pem, password=None)
        assert isinstance(private_key, rsa.RSAPrivateKey)

        key_size = private_key.key_size
        assert key_size == 2048

    def test_certificate_signed_with_sha256(self) -> None:
        """Certificate is signed using SHA256 hash algorithm."""
        result = generate_self_signed_cert(common_name="hash-test.local")

        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)

        signature_hash_algorithm = cert.signature_hash_algorithm
        assert isinstance(signature_hash_algorithm, hashes.SHA256)


class TestCertificateLoading:
    """Test certificate loading from files."""

    def test_load_certificate_from_pem_file(self, tmp_path: Path) -> None:
        """Certificate loads successfully from PEM file."""
        result = generate_self_signed_cert(common_name="load-test.local")
        assert result is not None
        cert_pem, _ = result

        cert_file = tmp_path / "test_cert.pem"
        cert_file.write_bytes(cert_pem)

        loaded_cert = load_certificate_from_file(str(cert_file))
        assert loaded_cert is not None

        original_cert = x509.load_pem_x509_certificate(cert_pem)
        assert loaded_cert.serial_number == original_cert.serial_number
        assert loaded_cert.subject == original_cert.subject

    def test_load_certificate_handles_missing_file(self, tmp_path: Path) -> None:
        """Loading non-existent certificate file returns None."""
        nonexistent_file = tmp_path / "nonexistent.pem"

        result = load_certificate_from_file(str(nonexistent_file))
        assert result is None

    def test_load_certificate_handles_invalid_pem_data(self, tmp_path: Path) -> None:
        """Loading invalid PEM data returns None."""
        invalid_file = tmp_path / "invalid.pem"
        invalid_file.write_bytes(b"This is not a valid PEM certificate")

        result = load_certificate_from_file(str(invalid_file))
        assert result is None

    def test_load_certificate_handles_corrupted_pem(self, tmp_path: Path) -> None:
        """Loading corrupted PEM file returns None."""
        result = generate_self_signed_cert(common_name="corrupt-test.local")
        assert result is not None
        cert_pem, _ = result

        corrupted_pem = cert_pem[:100] + b"CORRUPTED" + cert_pem[100:]

        corrupt_file = tmp_path / "corrupted.pem"
        corrupt_file.write_bytes(corrupted_pem)

        loaded = load_certificate_from_file(str(corrupt_file))
        assert loaded is None


class TestCertificateValidation:
    """Test certificate validity verification."""

    def test_verify_certificate_validity_for_current_cert(self) -> None:
        """Currently valid certificate passes validation."""
        result = generate_self_signed_cert(common_name="valid-test.local", valid_days=365)
        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)

        is_valid = verify_certificate_validity(cert)
        assert is_valid is True

    def test_verify_certificate_validity_for_expired_cert(self) -> None:
        """Expired certificate fails validation."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.COMMON_NAME, "expired-test.local"),
            ]
        )

        not_valid_before = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=365)
        not_valid_after = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
            .sign(private_key, hashes.SHA256())
        )

        is_valid = verify_certificate_validity(cert)
        assert is_valid is False

    def test_verify_certificate_validity_for_future_cert(self) -> None:
        """Certificate not yet valid fails validation."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.COMMON_NAME, "future-test.local"),
            ]
        )

        not_valid_before = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        not_valid_after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
            .sign(private_key, hashes.SHA256())
        )

        is_valid = verify_certificate_validity(cert)
        assert is_valid is False


class TestCertificateInfo:
    """Test certificate information extraction."""

    def test_get_certificate_info_extracts_subject_fields(self) -> None:
        """Certificate info extraction returns complete subject information."""
        result = generate_self_signed_cert(
            common_name="info-test.example.com",
            organization="InfoTestOrg",
            country="DE",
            state="Bavaria",
            locality="Munich",
        )
        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)
        info = get_certificate_info(cert)

        assert "subject" in info
        assert info["subject"]["commonName"] == "info-test.example.com"
        assert info["subject"]["organizationName"] == "InfoTestOrg"
        assert info["subject"]["countryName"] == "DE"
        assert info["subject"]["stateOrProvinceName"] == "Bavaria"
        assert info["subject"]["localityName"] == "Munich"

    def test_get_certificate_info_includes_validity_dates(self) -> None:
        """Certificate info includes not_valid_before and not_valid_after dates."""
        result = generate_self_signed_cert(common_name="dates-test.local", valid_days=180)
        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)
        info = get_certificate_info(cert)

        assert "not_valid_before" in info
        assert "not_valid_after" in info
        assert isinstance(info["not_valid_before"], str)
        assert isinstance(info["not_valid_after"], str)

        not_before = datetime.datetime.fromisoformat(info["not_valid_before"])
        not_after = datetime.datetime.fromisoformat(info["not_valid_after"])

        assert not_after > not_before

    def test_get_certificate_info_includes_serial_number(self) -> None:
        """Certificate info includes serial number."""
        result = generate_self_signed_cert(common_name="serial-test.local")
        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)
        info = get_certificate_info(cert)

        assert "serial_number" in info
        assert isinstance(info["serial_number"], str)
        assert len(info["serial_number"]) > 0
        assert info["serial_number"].isdigit()

    def test_get_certificate_info_includes_signature_algorithm(self) -> None:
        """Certificate info includes signature algorithm name."""
        result = generate_self_signed_cert(common_name="sigalg-test.local")
        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)
        info = get_certificate_info(cert)

        assert "signature_algorithm" in info
        assert "sha256" in info["signature_algorithm"].lower()

    def test_get_certificate_info_includes_extensions(self) -> None:
        """Certificate info includes extensions list with details."""
        result = generate_self_signed_cert(common_name="ext-test.local")
        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)
        info = get_certificate_info(cert)

        assert "extensions" in info
        assert isinstance(info["extensions"], list)
        assert len(info["extensions"]) > 0

        ext_oids = [ext["oid"] for ext in info["extensions"]]
        assert "subjectAltName" in ext_oids
        assert "basicConstraints" in ext_oids
        assert "keyUsage" in ext_oids

    def test_get_certificate_info_reports_validity_status(self) -> None:
        """Certificate info includes is_valid field indicating current validity."""
        result = generate_self_signed_cert(common_name="validity-status-test.local")
        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)
        info = get_certificate_info(cert)

        assert "is_valid" in info
        assert info["is_valid"] is True


class TestCertificateEdgeCases:
    """Test edge cases and error handling."""

    def test_generate_certificate_with_minimal_parameters(self) -> None:
        """Certificate generation works with default parameters."""
        result = generate_self_signed_cert()

        assert result is not None
        cert_pem, key_pem = result

        cert = x509.load_pem_x509_certificate(cert_pem)
        subject_dict = {attr.oid._name: attr.value for attr in cert.subject}

        assert subject_dict["commonName"] == "localhost"
        assert subject_dict["organizationName"] == "IntelliCrack"

    def test_generate_certificate_with_long_valid_days(self) -> None:
        """Certificate generation handles very long validity periods."""
        result = generate_self_signed_cert(common_name="long-validity.local", valid_days=3650)

        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)

        validity_delta = cert.not_valid_after - cert.not_valid_before
        assert validity_delta.days >= 3649
        assert validity_delta.days <= 3651

    def test_generate_certificate_with_special_characters_in_cn(self) -> None:
        """Certificate generation handles special characters in common name."""
        result = generate_self_signed_cert(common_name="test-*.example.com")

        assert result is not None
        cert_pem, _ = result

        cert = x509.load_pem_x509_certificate(cert_pem)
        subject_dict = {attr.oid._name: attr.value for attr in cert.subject}

        assert subject_dict["commonName"] == "test-*.example.com"

    def test_load_certificate_with_empty_file(self, tmp_path: Path) -> None:
        """Loading empty certificate file returns None."""
        empty_file = tmp_path / "empty.pem"
        empty_file.write_bytes(b"")

        result = load_certificate_from_file(str(empty_file))
        assert result is None


class TestSSLContextUsage:
    """Test certificates can be used in SSL contexts."""

    def test_certificate_can_be_loaded_into_ssl_context(self, tmp_path: Path) -> None:
        """Generated certificate and key can be loaded into Python SSL context."""
        import ssl

        result = generate_self_signed_cert(common_name="ssl-test.local")
        assert result is not None
        cert_pem, key_pem = result

        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"

        cert_file.write_bytes(cert_pem)
        key_file.write_bytes(key_pem)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_file), str(key_file))

        assert context is not None

    def test_certificate_chain_file_format(self, tmp_path: Path) -> None:
        """Certificate and key can be combined into single PEM file for SSL."""
        result = generate_self_signed_cert(common_name="chain-test.local")
        assert result is not None
        cert_pem, key_pem = result

        chain_file = tmp_path / "chain.pem"
        chain_file.write_bytes(cert_pem + key_pem)

        loaded_cert = x509.load_pem_x509_certificate(cert_pem)
        loaded_key = serialization.load_pem_private_key(key_pem, password=None)

        assert loaded_cert is not None
        assert loaded_key is not None
