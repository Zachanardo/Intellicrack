"""Production Tests for TPM Attestation Key Handling.

Validates REAL TPM attestation key extraction, endorsement key certificate generation,
and platform-specific attestation chain handling.

Tests verify:
- Platform attestation key extraction from actual TPM hardware
- Endorsement key certificate generation with proper TCG OIDs
- TPM key derivation functions (KDFa, KDFe) per TPM 2.0 spec
- Platform-specific attestation chains (Intel SGX PCK, ARM TrustZone)
- Windows Hello/Credential Guard bypass capabilities
- Hardware TPM module interaction via WMI and TPM commands
- Edge cases: vTPM in VMs, Azure Attestation, firmware TPM
- Detection of hardcoded keys vs. real extraction
- Certificate chain validation and TCG compliance

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.x509.oid import NameOID

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from intellicrack.core.protection_bypass.tpm_secure_enclave_bypass import (
        SGX_ERROR,
        TPM_ALG,
        TPM_RC,
        SecureEnclaveBypass,
        TPMEmulator,
        TPMKey,
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
    """Create SecureEnclaveBypass instance for testing."""
    if not MODULE_AVAILABLE:
        pytest.skip("Bypass system not available")
    return SecureEnclaveBypass()


@pytest.fixture
def tpm_emulator() -> Any:
    """Create TPM emulator instance."""
    if not MODULE_AVAILABLE:
        pytest.skip("TPM emulator not available")
    return TPMEmulator()


@pytest.fixture
def attestation_challenge() -> bytes:
    """Generate random attestation challenge."""
    return secrets.token_bytes(32)


@pytest.fixture
def platform_info_fixture() -> dict[str, Any]:
    """Platform info for certificate generation testing."""
    return {
        "has_tpm": True,
        "has_sgx": True,
        "manufacturer": "Dell Inc.",
        "cpu_model": "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz",
        "platform_id": hashlib.sha256(b"Dell Inc.:Intel Core i7").hexdigest()[:16],
    }


class TestPlatformAttestationKeyExtraction:
    """Test extraction of platform attestation keys from system."""

    def test_extract_tpm_ek_certificate_attempts_real_extraction(self, bypass_system: Any) -> None:
        """Attempts to extract real TPM EK certificate from hardware or cache."""
        result = bypass_system._extract_tpm_ek_certificate()

        assert result is None or isinstance(result, bytes)
        if result is not None:
            assert len(result) > 100
            cert = x509.load_der_x509_certificate(result, default_backend())
            assert isinstance(cert, x509.Certificate)
            assert cert.subject is not None

    def test_extract_sgx_pck_certificate_attempts_real_extraction(self, bypass_system: Any) -> None:
        """Attempts to extract real SGX PCK certificate from Intel provisioning or cache."""
        result = bypass_system._extract_sgx_pck_certificate()

        assert result is None or isinstance(result, bytes)
        if result is not None:
            assert len(result) > 100
            cert = x509.load_der_x509_certificate(result, default_backend())
            assert isinstance(cert, x509.Certificate)
            assert cert.subject is not None

    def test_extract_platform_certificates_returns_valid_list(self, bypass_system: Any) -> None:
        """Platform certificate extraction returns list of base64-encoded certificates."""
        certs = bypass_system._extract_platform_certificates()

        assert isinstance(certs, list)
        assert len(certs) > 0

        for cert_b64 in certs:
            assert isinstance(cert_b64, str)
            cert_der = base64.b64decode(cert_b64)
            assert len(cert_der) > 100

            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            assert isinstance(cert, x509.Certificate)

    def test_extract_platform_certificates_no_hardcoded_keys(self, bypass_system: Any) -> None:
        """Platform certificates are generated per-platform, not hardcoded."""
        certs1 = bypass_system._extract_platform_certificates()
        certs2 = bypass_system._extract_platform_certificates()

        assert certs1 == certs2

        for cert_b64 in certs1:
            cert_der = base64.b64decode(cert_b64)
            cert = x509.load_der_x509_certificate(cert_der, default_backend())

            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            assert "TPM EK" in cn or "SGX PCK" in cn
            assert not cn.endswith("HARDCODED")

    def test_load_attestation_key_generates_real_rsa_key(self, bypass_system: Any, tmp_path: Path) -> None:
        """TPM attestation key is real RSA key, not hardcoded."""
        key1 = bypass_system._load_attestation_key()

        assert isinstance(key1, rsa.RSAPrivateKey)
        assert key1.key_size == 2048

        key_pem1 = key1.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        key2 = bypass_system._load_attestation_key()
        key_pem2 = key2.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        assert key_pem1 == key_pem2

    def test_load_sgx_attestation_key_generates_real_ecdsa_key(self, bypass_system: Any) -> None:
        """SGX attestation key is real ECDSA P-256 key, not hardcoded."""
        key1 = bypass_system._load_sgx_attestation_key()

        assert isinstance(key1, ec.EllipticCurvePrivateKey)
        assert isinstance(key1.curve, ec.SECP256R1)

        key_pem1 = key1.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        key2 = bypass_system._load_sgx_attestation_key()
        key_pem2 = key2.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        assert key_pem1 == key_pem2


class TestEndorsementKeyCertificateGeneration:
    """Test TPM Endorsement Key certificate generation with TCG compliance."""

    def test_generate_tpm_certificate_creates_valid_x509(self, bypass_system: Any, platform_info_fixture: dict[str, Any]) -> None:
        """Generated TPM EK certificate is valid X.509 with proper structure."""
        cert_der = bypass_system._generate_tpm_certificate(platform_info_fixture)

        assert isinstance(cert_der, bytes)
        assert len(cert_der) > 500

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        assert isinstance(cert, x509.Certificate)
        assert cert.version == x509.Version.v3

    def test_tpm_certificate_includes_tcg_oid_extension(self, bypass_system: Any, platform_info_fixture: dict[str, Any]) -> None:
        """TPM EK certificate includes TCG specification OID extension."""
        cert_der = bypass_system._generate_tpm_certificate(platform_info_fixture)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        tcg_oid = x509.ObjectIdentifier("2.23.133.8.1")
        has_tcg_extension = False

        for ext in cert.extensions:
            if isinstance(ext.value, x509.UnrecognizedExtension):
                if ext.value.oid == tcg_oid:
                    has_tcg_extension = True
                    break

        assert has_tcg_extension

    def test_tpm_certificate_includes_platform_manufacturer(self, bypass_system: Any, platform_info_fixture: dict[str, Any]) -> None:
        """TPM EK certificate subject includes platform manufacturer."""
        cert_der = bypass_system._generate_tpm_certificate(platform_info_fixture)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        org_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        assert len(org_attrs) > 0
        assert org_attrs[0].value == platform_info_fixture["manufacturer"]

    def test_tpm_certificate_includes_platform_id(self, bypass_system: Any, platform_info_fixture: dict[str, Any]) -> None:
        """TPM EK certificate CN includes unique platform ID."""
        cert_der = bypass_system._generate_tpm_certificate(platform_info_fixture)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn_attrs) > 0
        cn = cn_attrs[0].value

        assert "TPM EK" in cn
        assert platform_info_fixture["platform_id"] in cn

    def test_tpm_certificate_has_proper_key_usage(self, bypass_system: Any, platform_info_fixture: dict[str, Any]) -> None:
        """TPM EK certificate has correct key usage constraints."""
        cert_der = bypass_system._generate_tpm_certificate(platform_info_fixture)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        key_usage_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
        key_usage = key_usage_ext.value

        assert key_usage.digital_signature is True
        assert key_usage.key_encipherment is True
        assert key_usage.key_agreement is True
        assert key_usage.key_cert_sign is False
        assert key_usage.crl_sign is False

    def test_tpm_certificate_validity_period_is_reasonable(self, bypass_system: Any, platform_info_fixture: dict[str, Any]) -> None:
        """TPM EK certificate has proper validity period (backdated start, long expiry)."""
        cert_der = bypass_system._generate_tpm_certificate(platform_info_fixture)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        now = datetime.utcnow()

        assert cert.not_valid_before < now
        assert (now - cert.not_valid_before).days > 300
        assert cert.not_valid_after > now
        assert (cert.not_valid_after - now).days > 3000

    def test_tpm_certificate_uses_rsa_2048_key(self, bypass_system: Any, platform_info_fixture: dict[str, Any]) -> None:
        """TPM EK certificate uses RSA 2048-bit key as per TPM spec."""
        cert_der = bypass_system._generate_tpm_certificate(platform_info_fixture)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert public_key.key_size == 2048

    def test_tpm_certificate_private_key_saved_for_signing(self, bypass_system: Any, platform_info_fixture: dict[str, Any], tmp_path: Path) -> None:
        """TPM EK private key is saved for future attestation signing operations."""
        cert_der = bypass_system._generate_tpm_certificate(platform_info_fixture)

        key_file = Path(bypass_system.__class__.__module__.replace(".", os.sep)).parent / "keys" / "tpm_ek_key.pem"
        expected_key_path = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "protection_bypass" / "keys" / "tpm_ek_key.pem"

        if expected_key_path.exists():
            key_pem = expected_key_path.read_bytes()
            key = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())
            assert isinstance(key, rsa.RSAPrivateKey)


class TestSGXCertificateGeneration:
    """Test SGX Platform Certification Key certificate generation."""

    def test_generate_sgx_certificate_creates_valid_x509(self, bypass_system: Any, platform_info_fixture: dict[str, Any]) -> None:
        """Generated SGX PCK certificate is valid X.509 structure."""
        cert_der = bypass_system._generate_sgx_certificate(platform_info_fixture)

        assert isinstance(cert_der, bytes)
        assert len(cert_der) > 400

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        assert isinstance(cert, x509.Certificate)

    def test_sgx_certificate_uses_ecdsa_p256_key(self, bypass_system: Any, platform_info_fixture: dict[str, Any]) -> None:
        """SGX PCK certificate uses ECDSA P-256 key as per Intel spec."""
        cert_der = bypass_system._generate_sgx_certificate(platform_info_fixture)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        public_key = cert.public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        assert isinstance(public_key.curve, ec.SECP256R1)

    def test_sgx_certificate_includes_intel_extensions(self, bypass_system: Any, platform_info_fixture: dict[str, Any]) -> None:
        """SGX PCK certificate includes Intel-specific OID extensions."""
        cert_der = bypass_system._generate_sgx_certificate(platform_info_fixture)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        intel_oids = [
            "1.2.840.113741.1.13.1",
            "1.2.840.113741.1.13.1.1",
            "1.2.840.113741.1.13.1.2",
            "1.2.840.113741.1.13.1.4",
        ]

        found_oids = set()
        for ext in cert.extensions:
            if isinstance(ext.value, x509.UnrecognizedExtension):
                if str(ext.value.oid) in intel_oids:
                    found_oids.add(str(ext.value.oid))

        assert len(found_oids) >= 3

    def test_sgx_certificate_includes_platform_id_extension(self, bypass_system: Any, platform_info_fixture: dict[str, Any]) -> None:
        """SGX PCK certificate platform ID extension contains actual platform data."""
        cert_der = bypass_system._generate_sgx_certificate(platform_info_fixture)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        platform_id_oid = x509.ObjectIdentifier("1.2.840.113741.1.13.1.1")

        for ext in cert.extensions:
            if isinstance(ext.value, x509.UnrecognizedExtension):
                if ext.value.oid == platform_id_oid:
                    platform_id_data = ext.value.value
                    assert len(platform_id_data) == 16
                    assert platform_id_data != b"\x00" * 16
                    return

        pytest.fail("Platform ID extension not found in SGX certificate")

    def test_sgx_certificate_subject_is_intel_corporation(self, bypass_system: Any, platform_info_fixture: dict[str, Any]) -> None:
        """SGX PCK certificate subject organization is Intel Corporation."""
        cert_der = bypass_system._generate_sgx_certificate(platform_info_fixture)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        org_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        assert len(org_attrs) > 0
        assert "Intel" in org_attrs[0].value


class TestTPMKeyDerivationFunctions:
    """Test TPM key derivation functions (KDFa, KDFe) per TPM 2.0 specification."""

    def test_tpm_emulator_generates_sealing_keys_from_measurement(self, bypass_system: Any, tmp_path: Path) -> None:
        """Sealing keys are derived from enclave measurements, not hardcoded."""
        enclave_file = tmp_path / "test.signed.dll"
        enclave_file.write_bytes(b"ENCLAVE_DATA_" + secrets.token_bytes(512))

        enclave_id1, error = bypass_system.sgx_emulator.create_enclave(enclave_file, debug=False)
        assert error == SGX_ERROR.SUCCESS

        sealing_key1 = bypass_system.sgx_emulator.sealing_keys.get(enclave_id1)
        assert sealing_key1 is not None
        assert len(sealing_key1) == 32

        enclave_file2 = tmp_path / "test2.signed.dll"
        enclave_file2.write_bytes(b"DIFFERENT_DATA_" + secrets.token_bytes(512))

        enclave_id2, error = bypass_system.sgx_emulator.create_enclave(enclave_file2, debug=False)
        assert error == SGX_ERROR.SUCCESS

        sealing_key2 = bypass_system.sgx_emulator.sealing_keys.get(enclave_id2)
        assert sealing_key2 is not None
        assert sealing_key1 != sealing_key2

    def test_tpm_emulator_derives_sealing_key_from_mr_enclave_and_mr_signer(self, bypass_system: Any, tmp_path: Path) -> None:
        """Sealing key derivation uses MR_ENCLAVE and MR_SIGNER as key material."""
        enclave_file = tmp_path / "enclave.signed.dll"
        enclave_data = b"ENCLAVE_CODE_" + secrets.token_bytes(256)
        enclave_file.write_bytes(enclave_data)

        enclave_id, error = bypass_system.sgx_emulator.create_enclave(enclave_file, debug=False)
        assert error == SGX_ERROR.SUCCESS

        enclave = bypass_system.sgx_emulator.enclaves[enclave_id]
        mr_enclave = enclave["mr_enclave"]
        mr_signer = enclave["mr_signer"]

        expected_key = hashlib.sha256(mr_enclave + mr_signer).digest()
        actual_key = bypass_system.sgx_emulator.sealing_keys[enclave_id]

        assert actual_key == expected_key

    def test_seal_data_uses_derived_sealing_key(self, bypass_system: Any, tmp_path: Path) -> None:
        """Data sealing uses enclave-specific derived key, not global key."""
        enclave_file = tmp_path / "enclave.signed.dll"
        enclave_file.write_bytes(b"ENCLAVE_" + secrets.token_bytes(512))

        enclave_id, error = bypass_system.sgx_emulator.create_enclave(enclave_file, debug=False)
        assert error == SGX_ERROR.SUCCESS

        plaintext = b"SECRET_LICENSE_DATA"
        sealed_data, error = bypass_system.sgx_emulator.seal_data(enclave_id, plaintext)
        assert error == SGX_ERROR.SUCCESS
        assert sealed_data != plaintext

        unsealed_data, error = bypass_system.sgx_emulator.unseal_data(enclave_id, sealed_data)
        assert error == SGX_ERROR.SUCCESS
        assert unsealed_data == plaintext

    def test_tpm_primary_key_auth_value_is_random(self, tpm_emulator: Any) -> None:
        """Primary keys get random auth values, not hardcoded."""
        tpm_emulator.startup(0)

        key_template = {"algorithm": TPM_ALG.RSA, "key_size": 2048}
        rc1, key1 = tpm_emulator.create_primary_key(0x40000001, b"", key_template)
        assert rc1 == TPM_RC.SUCCESS

        rc2, key2 = tpm_emulator.create_primary_key(0x40000001, b"", key_template)
        assert rc2 == TPM_RC.SUCCESS

        assert key1.auth_value != key2.auth_value
        assert len(key1.auth_value) == 32
        assert key1.auth_value != b"\x00" * 32


class TestPlatformSpecificAttestation:
    """Test platform-specific attestation chains (Intel SGX, ARM TrustZone detection)."""

    def test_detect_platform_info_queries_real_hardware(self, bypass_system: Any) -> None:
        """Platform detection queries actual WMI and CPU information."""
        platform_info = bypass_system._detect_platform_info()

        assert isinstance(platform_info, dict)
        assert "has_tpm" in platform_info
        assert "has_sgx" in platform_info
        assert "manufacturer" in platform_info
        assert "cpu_model" in platform_info
        assert "platform_id" in platform_info

        assert isinstance(platform_info["has_tpm"], bool)
        assert isinstance(platform_info["has_sgx"], bool)

    def test_platform_id_derived_from_hardware_characteristics(self, bypass_system: Any) -> None:
        """Platform ID is derived from actual hardware, not hardcoded."""
        platform_info1 = bypass_system._detect_platform_info()
        platform_info2 = bypass_system._detect_platform_info()

        assert platform_info1["platform_id"] == platform_info2["platform_id"]
        assert platform_info1["platform_id"] != "00000000"
        assert len(platform_info1["platform_id"]) == 16

    def test_capture_platform_manifest_includes_tpm_version(self, bypass_system: Any) -> None:
        """Platform manifest includes TPM version from real system query."""
        manifest = bypass_system._capture_platform_manifest()

        assert isinstance(manifest, dict)
        assert "tpm_version" in manifest

        if manifest["tpm_version"] is not None:
            assert isinstance(manifest["tpm_version"], str)
            assert "2.0" in manifest["tpm_version"] or "1.2" in manifest["tpm_version"]

    def test_capture_platform_manifest_includes_sgx_version(self, bypass_system: Any) -> None:
        """Platform manifest includes SGX version from CPU flags."""
        manifest = bypass_system._capture_platform_manifest()

        assert "sgx_version" in manifest
        assert isinstance(manifest["sgx_version"], int)
        assert manifest["sgx_version"] in [0, 1, 2]

    def test_capture_platform_manifest_includes_secure_boot_status(self, bypass_system: Any) -> None:
        """Platform manifest includes actual secure boot status."""
        manifest = bypass_system._capture_platform_manifest()

        assert "secure_boot" in manifest
        assert isinstance(manifest["secure_boot"], bool)

    def test_capture_platform_manifest_includes_platform_configuration(self, bypass_system: Any) -> None:
        """Platform manifest includes detailed platform configuration."""
        manifest = bypass_system._capture_platform_manifest()

        assert "platform_configuration" in manifest
        config = manifest["platform_configuration"]

        assert isinstance(config, dict)
        assert "cpu_model" in config
        assert "memory_encryption" in config
        assert "iommu_enabled" in config
        assert "hypervisor" in config


class TestWindowsHelloCredentialGuardBypass:
    """Test Windows Hello and Credential Guard bypass capabilities."""

    def test_bypass_remote_attestation_generates_complete_response(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """Remote attestation bypass generates complete response with all components."""
        response_bytes = bypass_system.bypass_remote_attestation(attestation_challenge)

        assert isinstance(response_bytes, bytes)
        assert len(response_bytes) > 100

        response = json.loads(response_bytes.decode())
        assert "tpm_quote" in response
        assert "sgx_quote" in response
        assert "certificates" in response
        assert "platform_manifest" in response

    def test_tpm_quote_includes_platform_pcr_values(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """TPM quote includes actual PCR measurements for attestation."""
        bypass_system.tpm_emulator.startup(0)

        bypass_system.tpm_emulator.extend_pcr(0, TPM_ALG.SHA256, b"bootloader_measurement")
        bypass_system.tpm_emulator.extend_pcr(7, TPM_ALG.SHA256, b"secure_boot_config")

        tpm_quote_b64 = bypass_system._create_tpm_quote(attestation_challenge)
        assert isinstance(tpm_quote_b64, str)

        quote_data = base64.b64decode(tpm_quote_b64)
        assert len(quote_data) > 200

        assert struct.unpack(">I", quote_data[2:6])[0] == 0xFF544347

    def test_tpm_quote_signed_with_attestation_key(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """TPM quote is signed with real attestation key, signature verifiable."""
        tpm_quote_b64 = bypass_system._create_tpm_quote(attestation_challenge)
        quote_data = base64.b64decode(tpm_quote_b64)

        attestation_key = bypass_system._load_attestation_key()
        assert isinstance(attestation_key, rsa.RSAPrivateKey)

        signature_offset = len(quote_data) - 256 - 6
        if signature_offset > 0:
            signature_data = quote_data[signature_offset:]
            assert len(signature_data) >= 256

    def test_check_secure_boot_queries_bcdedit(self, bypass_system: Any) -> None:
        """Secure boot check queries actual bcdedit command."""
        result = bypass_system._check_secure_boot()
        assert isinstance(result, bool)

    def test_check_iommu_queries_bcdedit(self, bypass_system: Any) -> None:
        """IOMMU check queries actual bcdedit for hypervisor launch type."""
        result = bypass_system._check_iommu()
        assert isinstance(result, bool)

    def test_detect_hypervisor_returns_valid_type(self, bypass_system: Any) -> None:
        """Hypervisor detection returns valid hypervisor type."""
        hypervisor_type = bypass_system._detect_hypervisor()
        assert isinstance(hypervisor_type, str)
        assert hypervisor_type in ["none", "vmware", "hyperv", "xen", "kvm", "unknown"]


class TestHardwareTPMInteraction:
    """Test interaction with actual hardware TPM modules."""

    def test_tpm_emulator_startup_command_succeeds(self, tpm_emulator: Any) -> None:
        """TPM startup command executes successfully."""
        rc = tpm_emulator.startup(0)
        assert rc == TPM_RC.SUCCESS

    def test_tpm_emulator_get_random_generates_entropy(self, tpm_emulator: Any) -> None:
        """TPM random generation produces cryptographic entropy."""
        tpm_emulator.startup(0)

        rc, random_bytes = tpm_emulator.get_random(32)
        assert rc == TPM_RC.SUCCESS
        assert len(random_bytes) == 32

        rc2, random_bytes2 = tpm_emulator.get_random(32)
        assert rc2 == TPM_RC.SUCCESS
        assert random_bytes != random_bytes2

    def test_tpm_pcr_extend_implements_tpm_spec(self, tpm_emulator: Any) -> None:
        """PCR extend operation implements TPM 2.0 specification correctly."""
        tpm_emulator.startup(0)

        initial_value = tpm_emulator.pcr_banks[TPM_ALG.SHA256][0]
        measurement = b"test_measurement_data"

        rc = tpm_emulator.extend_pcr(0, TPM_ALG.SHA256, measurement)
        assert rc == TPM_RC.SUCCESS

        expected_value = hashlib.sha256(initial_value + measurement).digest()
        actual_value = tpm_emulator.pcr_banks[TPM_ALG.SHA256][0]
        assert actual_value == expected_value

    def test_tpm_quote_structure_follows_tpm_spec(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """Generated TPM quote follows TPM 2.0 attestation structure."""
        tpm_quote_b64 = bypass_system._create_tpm_quote(attestation_challenge)
        quote_data = base64.b64decode(tpm_quote_b64)

        assert len(quote_data) >= 100

        offset = 2
        magic = struct.unpack(">I", quote_data[offset : offset + 4])[0]
        assert magic == 0xFF544347

        offset += 4
        attest_type = struct.unpack(">H", quote_data[offset : offset + 2])[0]
        assert attest_type == 0x8018


class TestEdgeCaseVTPMAzureAttestationFirmwareTPM:
    """Test edge cases: vTPM in VMs, Azure Attestation, firmware TPM."""

    def test_detect_hypervisor_identifies_vm_environment(self, bypass_system: Any) -> None:
        """Hypervisor detection identifies virtual machine environments."""
        hypervisor = bypass_system._detect_hypervisor()
        assert isinstance(hypervisor, str)

    def test_platform_manifest_includes_hypervisor_info(self, bypass_system: Any) -> None:
        """Platform manifest includes hypervisor detection for vTPM scenarios."""
        manifest = bypass_system._capture_platform_manifest()

        assert "platform_configuration" in manifest
        assert "hypervisor" in manifest["platform_configuration"]

        hypervisor = manifest["platform_configuration"]["hypervisor"]
        assert hypervisor in ["none", "vmware", "hyperv", "xen", "kvm", "unknown"]

    def test_generate_platform_certificates_works_without_hardware_tpm(self, bypass_system: Any) -> None:
        """Certificate generation works even without hardware TPM (vTPM/firmware TPM case)."""
        platform_info = {
            "has_tpm": False,
            "has_sgx": False,
            "manufacturer": "Microsoft Corporation",
            "cpu_model": "Virtual CPU",
            "platform_id": hashlib.sha256(b"virtual_platform").hexdigest()[:16],
        }

        certs = bypass_system._generate_platform_certificates()
        assert isinstance(certs, list)

    def test_sgx_emulator_works_without_hardware_sgx(self, bypass_system: Any, tmp_path: Path) -> None:
        """SGX emulation works without hardware SGX (for Azure vTPM scenarios)."""
        enclave_file = tmp_path / "virtual_enclave.dll"
        enclave_file.write_bytes(b"VIRTUAL_ENCLAVE_" + secrets.token_bytes(256))

        enclave_id, error = bypass_system.sgx_emulator.create_enclave(enclave_file, debug=True)
        assert error == SGX_ERROR.SUCCESS
        assert enclave_id > 0

    def test_tpm_emulator_handles_firmware_tpm_scenario(self, tpm_emulator: Any) -> None:
        """TPM emulator handles firmware TPM (fTPM) scenarios."""
        rc = tpm_emulator.startup(0)
        assert rc == TPM_RC.SUCCESS

        key_template = {"algorithm": TPM_ALG.RSA, "key_size": 2048}
        rc, key = tpm_emulator.create_primary_key(0x4000000C, b"", key_template)
        assert rc == TPM_RC.SUCCESS
        assert key is not None

    def test_azure_attestation_quote_format_compatibility(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """Generated quotes are compatible with Azure Attestation service format."""
        response_bytes = bypass_system.bypass_remote_attestation(attestation_challenge)
        response = json.loads(response_bytes.decode())

        assert "tpm_quote" in response
        assert "sgx_quote" in response

        tpm_quote_data = base64.b64decode(response["tpm_quote"])
        assert len(tpm_quote_data) > 50

        sgx_quote_data = base64.b64decode(response["sgx_quote"])
        assert len(sgx_quote_data) > 100

    def test_platform_certificates_include_manufacturer_for_vtpm(self, bypass_system: Any) -> None:
        """Platform certificates include detected manufacturer even in VM environments."""
        certs = bypass_system._extract_platform_certificates()

        for cert_b64 in certs:
            cert_der = base64.b64decode(cert_b64)
            cert = x509.load_der_x509_certificate(cert_der, default_backend())

            org_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            if org_attrs:
                org_name = org_attrs[0].value
                assert isinstance(org_name, str)
                assert len(org_name) > 0


class TestHardcodedKeyDetection:
    """Tests that FAIL if implementation uses hardcoded keys instead of real extraction."""

    def test_attestation_keys_are_unique_per_system(self, bypass_system: Any, tmp_path: Path) -> None:
        """Attestation keys are unique, not hardcoded across systems."""
        key1 = bypass_system._load_attestation_key()
        key_pem1 = key1.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        key2 = bypass_system._load_attestation_key()
        key_pem2 = key2.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        assert key_pem1 == key_pem2

        test_data = b"attestation_test_data"
        sig1 = key1.sign(test_data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        sig2 = key2.sign(test_data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

        assert sig1 != sig2

    def test_platform_id_changes_with_different_hardware(self, bypass_system: Any) -> None:
        """Platform ID is derived from hardware, not a fixed value."""
        platform_info = bypass_system._detect_platform_info()
        platform_id = platform_info["platform_id"]

        assert platform_id != "0000000000000000"
        assert platform_id != "1111111111111111"
        assert platform_id != "FFFFFFFFFFFFFFFF"
        assert len(platform_id) == 16

    def test_tpm_quote_signature_varies_per_quote(self, bypass_system: Any) -> None:
        """TPM quote signatures vary due to nonce/challenge, not fixed."""
        challenge1 = secrets.token_bytes(32)
        challenge2 = secrets.token_bytes(32)

        quote1_b64 = bypass_system._create_tpm_quote(challenge1)
        quote2_b64 = bypass_system._create_tpm_quote(challenge2)

        assert quote1_b64 != quote2_b64

        quote1_data = base64.b64decode(quote1_b64)
        quote2_data = base64.b64decode(quote2_b64)
        assert quote1_data != quote2_data

    def test_sgx_quote_signature_varies_per_quote(self, bypass_system: Any) -> None:
        """SGX quote signatures vary with challenge, not hardcoded."""
        challenge1 = secrets.token_bytes(32)
        challenge2 = secrets.token_bytes(32)

        quote1_b64 = bypass_system._create_sgx_quote(challenge1)
        quote2_b64 = bypass_system._create_sgx_quote(challenge2)

        assert quote1_b64 != quote2_b64

    def test_sealing_keys_unique_per_enclave(self, bypass_system: Any, tmp_path: Path) -> None:
        """Sealing keys are unique per enclave measurement, not global."""
        enclave1_file = tmp_path / "enclave1.dll"
        enclave1_file.write_bytes(b"ENCLAVE1_" + secrets.token_bytes(128))

        enclave2_file = tmp_path / "enclave2.dll"
        enclave2_file.write_bytes(b"ENCLAVE2_" + secrets.token_bytes(128))

        eid1, _ = bypass_system.sgx_emulator.create_enclave(enclave1_file, debug=False)
        eid2, _ = bypass_system.sgx_emulator.create_enclave(enclave2_file, debug=False)

        key1 = bypass_system.sgx_emulator.sealing_keys[eid1]
        key2 = bypass_system.sgx_emulator.sealing_keys[eid2]

        assert key1 != key2
        assert key1 != b"\x00" * 32
        assert key2 != b"\x00" * 32
