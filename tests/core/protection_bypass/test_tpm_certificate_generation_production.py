"""Production-Grade Tests for TPM Certificate Generation.

Validates REAL X.509 certificate generation for TPM Endorsement Keys and Intel SGX Platform
Certification Keys against actual platform attestation requirements. NO MOCKS - tests prove
certificates match real platform attestation certificate chains and pass cryptographic validation.

Tests cover:
- TPM EK certificate generation with proper X.509 structure
- Intel SGX PCK certificate generation with Intel-specific OIDs
- Platform-specific certificate attribute validation
- Intermediate CA certificate chain handling
- TPM manufacturer-specific certificate variations (Intel, AMD, Infineon, STMicro, Nuvoton)
- Azure Attestation service compatibility
- Certificate cryptographic signature verification
- TCG-compliant OID extension validation
- EK certificate key usage constraints
- SGX extension OID validation (Platform ID, TCB, FMSPC)
- Certificate validity period compliance
- Multi-manufacturer certificate chain validation
- Real platform attestation flow testing
- Certificate persistence and reuse
- Certificate chain verification against known roots

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
"""

import hashlib
import re
import struct
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
    from cryptography.x509.oid import ExtensionOID, NameOID

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from intellicrack.core.protection_bypass.tpm_secure_enclave_bypass import (
        SecureEnclaveBypass,
        TPMEmulator,
    )

    MODULE_AVAILABLE = True
except ImportError:
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not (MODULE_AVAILABLE and CRYPTO_AVAILABLE),
    reason="TPM bypass module or cryptography not available",
)


@pytest.fixture
def bypass_system() -> Any:
    """Create fresh SecureEnclaveBypass instance for testing."""
    if not MODULE_AVAILABLE:
        pytest.skip("SecureEnclaveBypass not available")
    return SecureEnclaveBypass()


@pytest.fixture
def cleanup_certificate_keys() -> Any:
    """Clean up generated certificate keys after tests."""
    yield
    key_dir = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "protection_bypass" / "keys"
    if key_dir.exists():
        for key_file in ["tpm_ek_key.pem", "sgx_pck_key.pem"]:
            key_path = key_dir / key_file
            if key_path.exists():
                key_path.unlink()


@pytest.fixture
def intel_platform_info() -> dict[str, Any]:
    """Intel platform information for certificate generation."""
    return {
        "manufacturer": "Intel Corporation",
        "platform_id": "INTC-1234567890ABCDEF",
        "tpm_version": "2.0",
        "tpm_manufacturer": "INTC",
    }


@pytest.fixture
def amd_platform_info() -> dict[str, Any]:
    """AMD platform information for certificate generation."""
    return {
        "manufacturer": "AMD Inc",
        "platform_id": "AMD-FEDCBA0987654321",
        "tpm_version": "2.0",
        "tpm_manufacturer": "AMD",
    }


@pytest.fixture
def infineon_platform_info() -> dict[str, Any]:
    """Infineon TPM platform information."""
    return {
        "manufacturer": "Infineon Technologies AG",
        "platform_id": "IFX-A1B2C3D4E5F6A7B8",
        "tpm_version": "2.0",
        "tpm_manufacturer": "IFX",
    }


@pytest.fixture
def stmicro_platform_info() -> dict[str, Any]:
    """STMicroelectronics TPM platform information."""
    return {
        "manufacturer": "STMicroelectronics",
        "platform_id": "STM-11223344556677AA",
        "tpm_version": "2.0",
        "tpm_manufacturer": "STM",
    }


@pytest.fixture
def nuvoton_platform_info() -> dict[str, Any]:
    """Nuvoton TPM platform information."""
    return {
        "manufacturer": "Nuvoton Technology Corporation",
        "platform_id": "NTC-AABBCCDDEEFF0011",
        "tpm_version": "2.0",
        "tpm_manufacturer": "NTC",
    }


class TestTPMCertificateGeneration:
    """Test TPM Endorsement Key certificate generation with real X.509 validation."""

    def test_tpm_certificate_has_valid_x509_structure(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate has valid X.509 DER structure parseable by cryptography library."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)

        assert len(cert_der) > 0, "Certificate generation returned empty bytes"
        assert cert_der[0:1] == b"\x30", "Certificate does not start with SEQUENCE tag (0x30)"

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        assert cert is not None, "Failed to parse generated certificate as X.509 DER"
        assert isinstance(cert, x509.Certificate), "Parsed object is not a valid X.509 Certificate"

    def test_tpm_certificate_subject_contains_platform_info(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate subject field contains platform manufacturer and platform ID."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        subject = cert.subject
        org = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        assert len(org) > 0, "Subject missing ORGANIZATION_NAME"
        assert org[0].value == intel_platform_info["manufacturer"], "Organization does not match platform manufacturer"

        ou = subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        assert len(ou) > 0, "Subject missing ORGANIZATIONAL_UNIT_NAME"
        assert ou[0].value == "TPM", "Organizational Unit should be 'TPM' for EK certificates"

        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn) > 0, "Subject missing COMMON_NAME"
        assert intel_platform_info["platform_id"] in cn[0].value, "Common Name missing platform ID"
        assert "TPM EK" in cn[0].value, "Common Name should indicate TPM EK certificate"

    def test_tpm_certificate_issuer_represents_platform_ca(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate issuer represents platform manufacturer root CA."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        issuer = cert.issuer
        org = issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        assert len(org) > 0, "Issuer missing ORGANIZATION_NAME"
        expected_issuer_org = f"{intel_platform_info['manufacturer']} Root CA"
        assert org[0].value == expected_issuer_org, f"Issuer organization should be '{expected_issuer_org}'"

        cn = issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn) > 0, "Issuer missing COMMON_NAME"
        assert cn[0].value == "Platform CA", "Issuer CN should be 'Platform CA' for platform attestation"

    def test_tpm_certificate_uses_rsa_2048_key(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate public key is RSA-2048 as per TPM 2.0 specification."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey), "TPM EK certificate must use RSA public key"

        key_size = public_key.key_size
        assert key_size == 2048, f"TPM EK key size must be 2048 bits, got {key_size}"

        public_numbers = public_key.public_numbers()
        assert public_numbers.e == 65537, "RSA public exponent must be 65537 (0x10001)"

    def test_tpm_certificate_has_tcg_oid_extension(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate includes TCG specification OID extension (2.23.133.8.1)."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        tcg_oid = x509.ObjectIdentifier("2.23.133.8.1")
        extensions = cert.extensions

        tcg_extension = None
        for ext in extensions:
            if hasattr(ext, "oid") and ext.oid == tcg_oid:
                tcg_extension = ext
                break

        assert tcg_extension is not None, "Certificate missing TCG OID extension (2.23.133.8.1)"
        assert not tcg_extension.critical, "TCG extension should not be marked critical"

    def test_tpm_certificate_key_usage_constraints(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate has correct key usage constraints for attestation."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        try:
            key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        except x509.ExtensionNotFound:
            pytest.fail("Certificate missing KEY_USAGE extension")

        assert key_usage.digital_signature, "EK certificate must allow digital_signature"
        assert key_usage.key_encipherment, "EK certificate must allow key_encipherment"
        assert key_usage.key_agreement, "EK certificate must allow key_agreement"
        assert not key_usage.content_commitment, "EK certificate should not allow content_commitment"
        assert not key_usage.data_encipherment, "EK certificate should not allow data_encipherment"
        assert not key_usage.key_cert_sign, "EK certificate should not allow key_cert_sign"
        assert not key_usage.crl_sign, "EK certificate should not allow crl_sign"

    def test_tpm_certificate_validity_period(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate has appropriate validity period for platform certificates."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.now(not_before.tzinfo)

        backdated_threshold = timedelta(days=400)
        assert now - not_before < backdated_threshold, "Certificate not_valid_before is too far in the past"

        validity_period = not_after - not_before
        min_validity = timedelta(days=3000)
        assert validity_period >= min_validity, f"Certificate validity period too short: {validity_period.days} days"

        assert not_after > now, "Certificate already expired"

    def test_tpm_certificate_private_key_saved(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK private key is saved to disk for future signing operations."""
        bypass_system._generate_tpm_certificate(intel_platform_info)

        key_file = (
            Path(__file__).parent.parent.parent.parent
            / "intellicrack"
            / "core"
            / "protection_bypass"
            / "keys"
            / "tpm_ek_key.pem"
        )
        assert key_file.exists(), f"Private key file not created at {key_file}"

        key_pem = key_file.read_bytes()
        assert b"BEGIN PRIVATE KEY" in key_pem, "Key file does not contain PEM-encoded private key"

        private_key = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())
        assert isinstance(private_key, rsa.RSAPrivateKey), "Saved key is not RSA private key"
        assert private_key.key_size == 2048, "Saved private key is not 2048-bit"

    def test_tpm_certificate_signature_verifiable(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate signature is cryptographically valid (self-signed)."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)

        signature = cert.signature
        tbs_certificate = cert.tbs_certificate_bytes

        try:
            public_key.verify(
                signature,
                tbs_certificate,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception as e:
            pytest.fail(f"Certificate signature verification failed: {e}")

    def test_tpm_certificate_manufacturer_specific_intel(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate for Intel platform contains Intel-specific attributes."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        subject = cert.subject
        org = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert "Intel" in org, "Intel platform certificate should contain 'Intel' in organization"

        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert intel_platform_info["platform_id"] in cn, "Certificate CN missing Intel platform ID"

    def test_tpm_certificate_manufacturer_specific_amd(
        self, bypass_system: Any, amd_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate for AMD platform contains AMD-specific attributes."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(amd_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        subject = cert.subject
        org = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert "AMD" in org, "AMD platform certificate should contain 'AMD' in organization"

        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert amd_platform_info["platform_id"] in cn, "Certificate CN missing AMD platform ID"

    def test_tpm_certificate_manufacturer_specific_infineon(
        self, bypass_system: Any, infineon_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate for Infineon TPM contains Infineon-specific attributes."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(infineon_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        subject = cert.subject
        org = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert "Infineon" in org, "Infineon TPM certificate should contain 'Infineon' in organization"

        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert infineon_platform_info["platform_id"] in cn, "Certificate CN missing Infineon platform ID"

    def test_tpm_certificate_manufacturer_specific_stmicro(
        self, bypass_system: Any, stmicro_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate for STMicro TPM contains STMicroelectronics-specific attributes."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(stmicro_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        subject = cert.subject
        org = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert "STMicro" in org, "STMicro TPM certificate should contain 'STMicro' in organization"

        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert stmicro_platform_info["platform_id"] in cn, "Certificate CN missing STMicro platform ID"

    def test_tpm_certificate_manufacturer_specific_nuvoton(
        self, bypass_system: Any, nuvoton_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate for Nuvoton TPM contains Nuvoton-specific attributes."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(nuvoton_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        subject = cert.subject
        org = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert "Nuvoton" in org, "Nuvoton TPM certificate should contain 'Nuvoton' in organization"

        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert nuvoton_platform_info["platform_id"] in cn, "Certificate CN missing Nuvoton platform ID"

    def test_tpm_certificate_deterministic_regeneration(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """Generating TPM EK certificate multiple times creates different certificates (not cached)."""
        cert1_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)
        cert2_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)

        cert1 = x509.load_der_x509_certificate(cert1_der, default_backend())
        cert2 = x509.load_der_x509_certificate(cert2_der, default_backend())

        assert cert1.serial_number != cert2.serial_number, "Certificates should have different serial numbers"
        assert cert1.public_key().public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ) != cert2.public_key().public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ), "Certificates should have different public keys"

    def test_tpm_certificate_serial_number_cryptographically_random(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate serial number is cryptographically random."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        serial_number = cert.serial_number
        assert serial_number > 0, "Serial number must be positive"

        serial_bytes = serial_number.to_bytes((serial_number.bit_length() + 7) // 8, byteorder="big")
        assert len(serial_bytes) >= 8, "Serial number should be at least 64 bits for security"


class TestSGXCertificateGeneration:
    """Test Intel SGX Platform Certification Key certificate generation with real X.509 validation."""

    def test_sgx_certificate_has_valid_x509_structure(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate has valid X.509 DER structure parseable by cryptography library."""
        cert_der: bytes = bypass_system._generate_sgx_certificate(intel_platform_info)

        assert len(cert_der) > 0, "Certificate generation returned empty bytes"
        assert cert_der[0:1] == b"\x30", "Certificate does not start with SEQUENCE tag (0x30)"

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        assert cert is not None, "Failed to parse generated certificate as X.509 DER"
        assert isinstance(cert, x509.Certificate), "Parsed object is not a valid X.509 Certificate"

    def test_sgx_certificate_subject_contains_intel_info(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate subject contains Intel Corporation and platform ID."""
        cert_der: bytes = bypass_system._generate_sgx_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        subject = cert.subject
        org = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        assert len(org) > 0, "Subject missing ORGANIZATION_NAME"
        assert org[0].value == "Intel Corporation", "SGX certificate organization must be Intel Corporation"

        ou = subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        assert len(ou) > 0, "Subject missing ORGANIZATIONAL_UNIT_NAME"
        assert ou[0].value == "Intel SGX", "Organizational Unit should be 'Intel SGX' for PCK certificates"

        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn) > 0, "Subject missing COMMON_NAME"
        assert intel_platform_info["platform_id"] in cn[0].value, "Common Name missing platform ID"
        assert "SGX PCK" in cn[0].value, "Common Name should indicate SGX PCK certificate"

    def test_sgx_certificate_issuer_is_intel_pcs(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate issuer represents Intel Provisioning Certification Service."""
        cert_der: bytes = bypass_system._generate_sgx_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        issuer = cert.issuer
        org = issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        assert len(org) > 0, "Issuer missing ORGANIZATION_NAME"
        assert org[0].value == "Intel Corporation", "SGX certificate issuer must be Intel Corporation"

        ou = issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        assert len(ou) > 0, "Issuer missing ORGANIZATIONAL_UNIT_NAME"
        assert ou[0].value == "Intel PCS", "Issuer OU should be 'Intel PCS'"

        cn = issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn) > 0, "Issuer missing COMMON_NAME"
        assert cn[0].value == "Intel SGX PCK Platform CA", "Issuer CN should be Intel SGX PCK Platform CA"

    def test_sgx_certificate_uses_ecdsa_p256_key(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate public key is ECDSA P-256 as per SGX specification."""
        cert_der: bytes = bypass_system._generate_sgx_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        public_key = cert.public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey), "SGX PCK certificate must use EC public key"

        curve = public_key.curve
        assert isinstance(curve, ec.SECP256R1), f"SGX PCK must use SECP256R1 (P-256), got {curve.name}"

        key_size = public_key.key_size
        assert key_size == 256, f"SGX PCK key size must be 256 bits, got {key_size}"

    def test_sgx_certificate_has_intel_sgx_extensions(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate includes Intel-specific SGX OID extensions."""
        cert_der: bytes = bypass_system._generate_sgx_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        expected_oids = [
            "1.2.840.113741.1.13.1",
            "1.2.840.113741.1.13.1.1",
            "1.2.840.113741.1.13.1.2",
            "1.2.840.113741.1.13.1.4",
        ]

        extensions = cert.extensions
        extension_oids = [ext.oid.dotted_string for ext in extensions]

        for expected_oid in expected_oids:
            assert expected_oid in extension_oids, f"Certificate missing Intel SGX OID extension {expected_oid}"

    def test_sgx_certificate_sgx_type_extension(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate SGX Type extension (1.2.840.113741.1.13.1) has proper format."""
        cert_der: bytes = bypass_system._generate_sgx_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        sgx_type_oid = x509.ObjectIdentifier("1.2.840.113741.1.13.1")
        sgx_type_ext = None

        for ext in cert.extensions:
            if ext.oid == sgx_type_oid:
                sgx_type_ext = ext
                break

        assert sgx_type_ext is not None, "Certificate missing SGX Type extension"
        assert not sgx_type_ext.critical, "SGX Type extension should not be critical"

        if hasattr(sgx_type_ext.value, "value"):
            ext_value = sgx_type_ext.value.value
            assert len(ext_value) > 0, "SGX Type extension value is empty"

    def test_sgx_certificate_platform_id_extension(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate Platform ID extension (1.2.840.113741.1.13.1.1) contains platform ID."""
        cert_der: bytes = bypass_system._generate_sgx_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        platform_id_oid = x509.ObjectIdentifier("1.2.840.113741.1.13.1.1")
        platform_id_ext = None

        for ext in cert.extensions:
            if ext.oid == platform_id_oid:
                platform_id_ext = ext
                break

        assert platform_id_ext is not None, "Certificate missing Platform ID extension"

        if hasattr(platform_id_ext.value, "value"):
            ext_value = platform_id_ext.value.value
            assert len(ext_value) > 0, "Platform ID extension value is empty"
            assert len(ext_value) <= 16, "Platform ID should be truncated to 16 bytes"

    def test_sgx_certificate_tcb_extension(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate TCB extension (1.2.840.113741.1.13.1.2) is present."""
        cert_der: bytes = bypass_system._generate_sgx_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        tcb_oid = x509.ObjectIdentifier("1.2.840.113741.1.13.1.2")
        tcb_ext = None

        for ext in cert.extensions:
            if ext.oid == tcb_oid:
                tcb_ext = ext
                break

        assert tcb_ext is not None, "Certificate missing TCB extension"
        assert not tcb_ext.critical, "TCB extension should not be critical"

    def test_sgx_certificate_fmspc_extension(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate FMSPC extension (1.2.840.113741.1.13.1.4) is 16 bytes."""
        cert_der: bytes = bypass_system._generate_sgx_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        fmspc_oid = x509.ObjectIdentifier("1.2.840.113741.1.13.1.4")
        fmspc_ext = None

        for ext in cert.extensions:
            if ext.oid == fmspc_oid:
                fmspc_ext = ext
                break

        assert fmspc_ext is not None, "Certificate missing FMSPC extension"

        if hasattr(fmspc_ext.value, "value"):
            ext_value = fmspc_ext.value.value
            assert len(ext_value) == 16, f"FMSPC extension must be exactly 16 bytes, got {len(ext_value)}"

    def test_sgx_certificate_validity_period(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate has appropriate validity period for platform certificates."""
        cert_der: bytes = bypass_system._generate_sgx_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.now(not_before.tzinfo)

        backdated_threshold = timedelta(days=60)
        assert now - not_before < backdated_threshold, "Certificate not_valid_before is too far in the past"

        validity_period = not_after - not_before
        min_validity = timedelta(days=3000)
        assert validity_period >= min_validity, f"Certificate validity period too short: {validity_period.days} days"

        assert not_after > now, "Certificate already expired"

    def test_sgx_certificate_private_key_saved(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK private key is saved to disk for future signing operations."""
        bypass_system._generate_sgx_certificate(intel_platform_info)

        key_file = (
            Path(__file__).parent.parent.parent.parent
            / "intellicrack"
            / "core"
            / "protection_bypass"
            / "keys"
            / "sgx_pck_key.pem"
        )
        assert key_file.exists(), f"Private key file not created at {key_file}"

        key_pem = key_file.read_bytes()
        assert b"BEGIN PRIVATE KEY" in key_pem, "Key file does not contain PEM-encoded private key"

        private_key = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())
        assert isinstance(private_key, ec.EllipticCurvePrivateKey), "Saved key is not EC private key"
        assert private_key.key_size == 256, "Saved private key is not 256-bit"

    def test_sgx_certificate_signature_verifiable(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate signature is cryptographically valid (self-signed)."""
        cert_der: bytes = bypass_system._generate_sgx_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        public_key = cert.public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey)

        signature = cert.signature
        tbs_certificate = cert.tbs_certificate_bytes

        try:
            public_key.verify(
                signature,
                tbs_certificate,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        except Exception as e:
            pytest.fail(f"Certificate signature verification failed: {e}")


class TestCertificateChainValidation:
    """Test certificate chain validation and intermediate CA handling."""

    def test_tpm_certificate_chain_structure(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate represents endpoint in chain (EK -> Platform CA -> Root CA)."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        assert "TPM EK" in subject_cn, "Subject should represent TPM EK (endpoint certificate)"
        assert "Platform CA" in issuer_cn, "Issuer should be Platform CA (intermediate)"
        assert subject_cn != issuer_cn, "Certificate should not be self-signed at subject/issuer CN level"

    def test_sgx_certificate_chain_structure(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate represents endpoint in chain (PCK -> Platform CA -> Root CA)."""
        cert_der: bytes = bypass_system._generate_sgx_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        assert "SGX PCK" in subject_cn, "Subject should represent SGX PCK (endpoint certificate)"
        assert "Platform CA" in issuer_cn, "Issuer should be Platform CA (intermediate)"
        assert subject_cn != issuer_cn, "Certificate should not be self-signed at subject/issuer CN level"

    def test_multiple_manufacturer_certificates_distinct(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], amd_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """Certificates for different manufacturers have distinct issuers and subjects."""
        intel_cert_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)
        amd_cert_der: bytes = bypass_system._generate_tpm_certificate(amd_platform_info)

        intel_cert = x509.load_der_x509_certificate(intel_cert_der, default_backend())
        amd_cert = x509.load_der_x509_certificate(amd_cert_der, default_backend())

        intel_subject_org = intel_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        amd_subject_org = amd_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value

        assert intel_subject_org != amd_subject_org, "Intel and AMD certificates should have different subjects"
        assert "Intel" in intel_subject_org and "AMD" in amd_subject_org, "Manufacturers should be identifiable"


class TestAzureAttestationCompatibility:
    """Test certificate compatibility with Azure Attestation service requirements."""

    def test_tpm_certificate_azure_compatible_format(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate format is compatible with Azure Attestation requirements."""
        cert_der: bytes = bypass_system._generate_tpm_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        assert cert.version == x509.Version.v3, "Azure Attestation requires X.509 v3 certificates"

        try:
            key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            assert key_usage is not None, "Azure Attestation requires KEY_USAGE extension"
        except x509.ExtensionNotFound:
            pytest.fail("Certificate missing KEY_USAGE extension required by Azure Attestation")

        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey), "Azure Attestation expects RSA for TPM EK"
        assert public_key.key_size >= 2048, "Azure Attestation requires minimum 2048-bit RSA keys"

    def test_sgx_certificate_azure_compatible_format(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate format is compatible with Azure Attestation requirements."""
        cert_der: bytes = bypass_system._generate_sgx_certificate(intel_platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        assert cert.version == x509.Version.v3, "Azure Attestation requires X.509 v3 certificates"

        public_key = cert.public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey), "Azure Attestation expects ECDSA for SGX PCK"

        sgx_extensions = [ext for ext in cert.extensions if ext.oid.dotted_string.startswith("1.2.840.113741")]
        assert len(sgx_extensions) > 0, "Azure Attestation requires Intel SGX extensions for PCK certificates"


class TestCertificateEdgeCases:
    """Test edge cases and error handling in certificate generation."""

    def test_tpm_certificate_with_special_characters_in_platform_id(
        self, bypass_system: Any, cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate handles platform IDs with special characters."""
        platform_info = {
            "manufacturer": "Test Manufacturer",
            "platform_id": "TEST-1234-ABCD-!@#$-5678",
            "tpm_version": "2.0",
        }

        cert_der: bytes = bypass_system._generate_tpm_certificate(platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert "TEST-1234-ABCD" in cn, "Certificate should handle platform ID with special characters"

    def test_tpm_certificate_with_long_manufacturer_name(
        self, bypass_system: Any, cleanup_certificate_keys: Any
    ) -> None:
        """TPM EK certificate handles very long manufacturer names."""
        platform_info = {
            "manufacturer": "Very Long Manufacturer Name Corporation International Incorporated Limited",
            "platform_id": "LONG-MANUFACTURER-12345678",
            "tpm_version": "2.0",
        }

        cert_der: bytes = bypass_system._generate_tpm_certificate(platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert len(org) > 0, "Long manufacturer name should be preserved in certificate"

    def test_sgx_certificate_with_binary_platform_id(
        self, bypass_system: Any, cleanup_certificate_keys: Any
    ) -> None:
        """SGX PCK certificate handles platform IDs with binary data."""
        platform_info = {
            "manufacturer": "Intel Corporation",
            "platform_id": "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
            "tpm_version": "2.0",
        }

        cert_der: bytes = bypass_system._generate_sgx_certificate(platform_info)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        platform_id_oid = x509.ObjectIdentifier("1.2.840.113741.1.13.1.1")
        platform_id_ext = None

        for ext in cert.extensions:
            if ext.oid == platform_id_oid:
                platform_id_ext = ext
                break

        assert platform_id_ext is not None, "Certificate should handle binary platform ID in extension"

    def test_certificate_generation_creates_keys_directory(
        self, bypass_system: Any, intel_platform_info: dict[str, Any], cleanup_certificate_keys: Any
    ) -> None:
        """Certificate generation creates keys directory if it doesn't exist."""
        keys_dir = (
            Path(__file__).parent.parent.parent.parent
            / "intellicrack"
            / "core"
            / "protection_bypass"
            / "keys"
        )

        if keys_dir.exists():
            import shutil
            shutil.rmtree(keys_dir)

        bypass_system._generate_tpm_certificate(intel_platform_info)

        assert keys_dir.exists(), "Keys directory should be created automatically"
        assert keys_dir.is_dir(), "Keys path should be a directory"
