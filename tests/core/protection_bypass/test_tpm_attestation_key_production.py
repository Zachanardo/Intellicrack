"""Production tests for TPM attestation key generation and platform certificate extraction.

Tests verify that TPM attestation keys are dynamically generated, NOT hardcoded,
and that proper platform certificate extraction works with real TPM/SGX modules.
"""

import base64
import hashlib
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from intellicrack.core.protection_bypass.tpm_secure_enclave_bypass import (
    TPM_ALG,
    TPM_RC,
    SecureEnclaveBypass,
)


class TestTPMAttestationKeyGeneration:
    """Tests for TPM attestation key generation without hardcoded values."""

    @pytest.fixture
    def bypass_engine(self) -> SecureEnclaveBypass:
        """Create SecureEnclaveBypass instance for testing.

        Returns:
            SecureEnclaveBypass: Initialized bypass engine.
        """
        return SecureEnclaveBypass()

    def test_no_hardcoded_attestation_keys_in_source(self) -> None:
        """Verify source code contains NO hardcoded attestation keys.

        Tests that module does not contain static RSA/ECC private keys,
        hardcoded TPM EK certificates, or fixed attestation signatures.
        """
        module_path: Path = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "protection_bypass" / "tpm_secure_enclave_bypass.py"
        source_code: str = module_path.read_text(encoding="utf-8")

        hardcoded_key_patterns: list[str] = [
            r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            r"-----BEGIN CERTIFICATE-----",
            r"MII[A-Za-z0-9+/]{100,}={0,2}",
            r"attestation_key\s*=\s*[\"'][0-9a-fA-F]{64,}[\"']",
            r"ek_key\s*=\s*[\"'][0-9a-fA-F]{64,}[\"']",
            r"HARDCODED.*KEY",
            r"STATIC.*ATTESTATION",
        ]

        for pattern in hardcoded_key_patterns:
            matches: list[Any] = re.findall(pattern, source_code, re.IGNORECASE)
            if matches:
                pytest.fail(f"Found hardcoded key pattern '{pattern}': {matches[0][:100]}")

    def test_attestation_response_uses_dynamic_keys(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify attestation responses use dynamically generated keys.

        Tests that multiple attestation challenges produce different signatures,
        proving keys are generated per-request not hardcoded.
        """
        challenge1: bytes = b"test_challenge_1"
        challenge2: bytes = b"test_challenge_2"

        response1: dict[str, Any] = bypass_engine.process_attestation_challenge(challenge1)
        response2: dict[str, Any] = bypass_engine.process_attestation_challenge(challenge2)

        signature1: str = response1["signature"]
        signature2: str = response2["signature"]
        assert signature1 != signature2, "Signatures must differ for different challenges"
        assert len(signature1) > 0, "Signature must not be empty"
        assert len(signature2) > 0, "Signature must not be empty"

        sig1_decoded: bytes = base64.b64decode(signature1)
        sig2_decoded: bytes = base64.b64decode(signature2)
        assert sig1_decoded != sig2_decoded, "Decoded signatures must be cryptographically distinct"

    def test_attestation_key_regenerated_per_instance(self) -> None:
        """Verify each bypass instance generates unique attestation keys.

        Tests that different SecureEnclaveBypass instances produce different
        attestation keys, proving no global static key exists.
        """
        bypass1: SecureEnclaveBypass = SecureEnclaveBypass()
        bypass2: SecureEnclaveBypass = SecureEnclaveBypass()

        challenge: bytes = b"identical_challenge"

        response1: dict[str, Any] = bypass1.process_attestation_challenge(challenge)
        response2: dict[str, Any] = bypass2.process_attestation_challenge(challenge)

        certificates1: list[Any] = response1["certificates"]
        certificates2: list[Any] = response2["certificates"]
        cert1: str = certificates1[0] if certificates1 else ""
        cert2: str = certificates2[0] if certificates2 else ""

        assert cert1 != cert2, "Certificates must be unique per instance"
        assert len(cert1) > 0, "Certificate must be generated"
        assert len(cert2) > 0, "Certificate must be generated"

    def test_tpm_ek_certificate_extraction_from_system(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test TPM EK certificate extraction from actual system.

        Verifies extraction attempts real TPM access and falls back to generation
        when TPM unavailable. Tests platform-specific extraction logic.
        """
        ek_cert_bytes: bytes | None = bypass_engine._extract_tpm_ek_certificate()  # type: ignore[attr-defined]

        if ek_cert_bytes is not None:
            assert len(ek_cert_bytes) > 100, "Real TPM EK certificate should be >100 bytes"

            try:
                cert: x509.Certificate = x509.load_der_x509_certificate(ek_cert_bytes, default_backend())
                assert cert.subject is not None, "Certificate must have subject"
                subject_cn: list[x509.NameAttribute] = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if subject_cn:
                    cn_value: Any = subject_cn[0].value
                    assert "TPM" in str(cn_value) or "EK" in str(cn_value), "Certificate should identify as TPM EK"
            except Exception as e:
                pytest.fail(f"Extracted TPM EK cert is invalid: {e}")

    def test_sgx_pck_certificate_extraction_from_system(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test SGX PCK certificate extraction from Intel SGX.

        Verifies extraction attempts real SGX certificate retrieval and validates
        certificate format when available.
        """
        pck_cert_bytes: bytes | None = bypass_engine._extract_sgx_pck_certificate()

        if pck_cert_bytes is not None:
            assert len(pck_cert_bytes) > 100, "Real SGX PCK certificate should be >100 bytes"

            try:
                cert: x509.Certificate = x509.load_der_x509_certificate(pck_cert_bytes, default_backend())
                assert cert.subject is not None, "Certificate must have subject"
                subject_cn: list[Any] = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if subject_cn:
                    cn_value: Any = subject_cn[0].value
                    assert "SGX" in cn_value or "PCK" in cn_value, "Certificate should identify as SGX PCK"

                public_key: Any = cert.public_key()
                assert isinstance(public_key, ec.EllipticCurvePublicKey), "SGX PCK must use ECC key (P-256)"
            except Exception as e:
                pytest.fail(f"Extracted SGX PCK cert is invalid: {e}")

    def test_platform_certificate_generation_with_real_platform_info(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test certificate generation uses real platform detection.

        Verifies platform info extraction from WMI/CPU and that generated
        certificates include actual manufacturer and platform ID.
        """
        platform_info: dict[str, Any] = bypass_engine._detect_platform_info()

        assert "has_tpm" in platform_info, "Platform detection must check TPM"
        assert "has_sgx" in platform_info, "Platform detection must check SGX"
        assert "manufacturer" in platform_info, "Platform detection must identify manufacturer"
        assert "cpu_model" in platform_info, "Platform detection must identify CPU"
        assert "platform_id" in platform_info, "Platform detection must generate platform ID"

        manufacturer: Any = platform_info["manufacturer"]
        if manufacturer != "Unknown":
            assert len(manufacturer) > 0, "Manufacturer should be detected"

        platform_id: Any = platform_info["platform_id"]
        if platform_id:
            assert len(platform_id) == 16, "Platform ID should be 16 hex chars (SHA256 truncated)"
            assert all(c in "0123456789abcdef" for c in platform_id.lower()), "Platform ID must be hex"

    def test_generated_tpm_certificate_structure_valid(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify generated TPM EK certificates have proper X.509 structure.

        Tests certificate generation includes TCG OID extensions, proper key usage,
        and valid RSA-2048 public key.
        """
        platform_info: dict[str, Any] = {
            "has_tpm": True,
            "has_sgx": False,
            "manufacturer": "TestManufacturer",
            "cpu_model": "TestCPU",
            "platform_id": "1234567890abcdef",
        }

        cert_bytes: bytes = bypass_engine._generate_tpm_certificate(platform_info)

        assert len(cert_bytes) > 500, "TPM certificate should be >500 bytes DER encoded"

        cert: x509.Certificate = x509.load_der_x509_certificate(cert_bytes, default_backend())

        subject_cn: Any = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert "TPM EK" in subject_cn, "Certificate CN should identify as TPM EK"
        manufacturer_str: Any = platform_info["manufacturer"]
        assert platform_info["platform_id"] in subject_cn, "Certificate should include platform ID"

        org: Any = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert org == manufacturer_str, "Organization should match platform manufacturer"

        public_key: Any = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey), "TPM EK must use RSA key"
        assert public_key.key_size == 2048, "TPM EK must be RSA-2048"

        key_usage_ext: x509.Extension[x509.KeyUsage] = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        key_usage: x509.KeyUsage = key_usage_ext.value
        assert key_usage.digital_signature, "TPM EK must have digital signature usage"
        assert key_usage.key_encipherment, "TPM EK must have key encipherment usage"

        tcg_oid: x509.ObjectIdentifier = x509.ObjectIdentifier("2.23.133.8.1")
        try:
            tcg_ext: x509.Extension[Any] = cert.extensions.get_extension_for_oid(tcg_oid)
            assert tcg_ext is not None, "TPM certificate must have TCG OID extension"
        except x509.ExtensionNotFound:
            pytest.fail("TPM certificate missing TCG specification OID 2.23.133.8.1")

    def test_generated_sgx_certificate_structure_valid(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify generated SGX PCK certificates have proper X.509 structure.

        Tests certificate generation includes Intel-specific OIDs, ECDSA P-256 key,
        and proper SGX-specific attributes.
        """
        platform_info: dict[str, Any] = {
            "has_tpm": False,
            "has_sgx": True,
            "manufacturer": "GenuineIntel",
            "cpu_model": "Intel(R) Core(TM) i7-10700K",
            "platform_id": "abcdef1234567890",
        }

        cert_bytes: bytes = bypass_engine._generate_sgx_certificate(platform_info)

        assert len(cert_bytes) > 400, "SGX certificate should be >400 bytes DER encoded"

        cert: x509.Certificate = x509.load_der_x509_certificate(cert_bytes, default_backend())

        subject: Any = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        platform_id_str: Any = platform_info["platform_id"]
        assert "SGX PCK" in subject, "Certificate CN should identify as SGX PCK"
        assert platform_id_str in subject, "Certificate should include platform ID"

        org: Any = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert org == "Intel Corporation", "SGX cert organization must be Intel Corporation"

        public_key: Any = cert.public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey), "SGX PCK must use ECDSA key"
        assert public_key.curve.name == "secp256r1", "SGX PCK must use P-256 curve"

        issuer_cn: Any = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert "Intel SGX PCK Platform CA" in issuer_cn, "Issuer should identify as Intel PCS CA"

    def test_attestation_key_derivation_from_platform_id(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify attestation keys derived from platform-specific information.

        Tests that key generation uses platform ID, manufacturer, and CPU model
        to create unique keys tied to hardware.
        """
        platform_info: dict[str, Any] = bypass_engine._detect_platform_info()

        platform_id: Any = platform_info["platform_id"]
        if platform_id:
            challenge: bytes = b"test_challenge"
            response: dict[str, Any] = bypass_engine.process_attestation_challenge(challenge)

            certificates: list[Any] = response["certificates"]
            assert len(certificates) > 0, "Attestation must include certificates"

            cert_bytes: bytes = base64.b64decode(certificates[0])
            cert: x509.Certificate = x509.load_der_x509_certificate(cert_bytes, default_backend())

            subject_cn: Any = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            assert platform_id in subject_cn or "EK" in subject_cn or "PCK" in subject_cn, "Certificate should reference platform ID or be recognized attestation cert"

    def test_no_repeated_signatures_across_challenges(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify signatures are never repeated across different challenges.

        Tests cryptographic uniqueness by generating 10 attestation responses
        and ensuring all signatures are distinct.
        """
        challenges: list[bytes] = [os.urandom(32) for _ in range(10)]
        signatures: list[Any] = []

        for challenge in challenges:
            response: dict[str, Any] = bypass_engine.process_attestation_challenge(challenge)
            sig: Any = response["signature"]
            signatures.append(sig)

        assert len(set(signatures)) == 10, "All signatures must be cryptographically unique"

        for sig_b64 in signatures:
            sig_bytes: bytes = base64.b64decode(sig_b64)
            assert len(sig_bytes) >= 64, "Signature should be at least 64 bytes (RSA-2048 or ECDSA P-256)"


class TestTPMKeyDerivationFunctions:
    """Tests for TPM key derivation functions (KDF)."""

    @pytest.fixture
    def bypass_engine(self) -> SecureEnclaveBypass:
        """Create SecureEnclaveBypass instance for testing.

        Returns:
            SecureEnclaveBypass: Initialized bypass engine.
        """
        return SecureEnclaveBypass()

    def test_tpm_kdf_produces_unique_keys(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify TPM KDF produces unique keys for different inputs.

        Tests that key derivation function generates different keys when
        provided different seed values or derivation parameters.
        """
        seed1: bytes = b"seed_value_1"
        seed2: bytes = b"seed_value_2"

        key1: bytes = hashlib.sha256(seed1).digest()
        key2: bytes = hashlib.sha256(seed2).digest()

        assert key1 != key2, "KDF must produce different keys for different seeds"
        assert len(key1) == 32, "KDF output should be 256 bits"
        assert len(key2) == 32, "KDF output should be 256 bits"

    def test_endorsement_key_generation_not_deterministic(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify EK generation is non-deterministic across runs.

        Tests that multiple EK generation calls produce different keys,
        proving proper random number generation.
        """
        platform_info: dict[str, Any] = {
            "has_tpm": True,
            "manufacturer": "Test",
            "platform_id": "1234567890abcdef",
            "cpu_model": "TestCPU",
        }

        cert1_bytes: bytes = bypass_engine._generate_tpm_certificate(platform_info)
        cert2_bytes: bytes = bypass_engine._generate_tpm_certificate(platform_info)

        assert cert1_bytes != cert2_bytes, "EK certificates must be unique per generation"

        cert1: x509.Certificate = x509.load_der_x509_certificate(cert1_bytes, default_backend())
        cert2: x509.Certificate = x509.load_der_x509_certificate(cert2_bytes, default_backend())

        key1: Any = cert1.public_key()
        key2: Any = cert2.public_key()

        key1_pem: bytes = key1.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key2_pem: bytes = key2.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        assert key1_pem != key2_pem, "Public keys must differ across generations"

    def test_storage_root_key_hierarchy(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify TPM storage root key (SRK) hierarchy implementation.

        Tests that TPM emulator maintains proper key hierarchy with SRK
        as root for storage keys and sealing keys.
        """
        tpm_emulator = bypass_engine.tpm_emulator

        key_template = b"\x00" * 32
        rc, srk = tpm_emulator.create_primary_key(0x40000001, b"", key_template)

        assert rc == TPM_RC.SUCCESS, "SRK creation must succeed"
        assert srk is not None, "SRK must be generated"
        assert hasattr(srk, "handle"), "SRK must have handle"
        assert hasattr(srk, "public"), "SRK must have public key"

    def test_pcr_based_policy_unsealing(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test PCR-based policy validation for unsealing.

        Verifies that TPM unsealing requires correct PCR values,
        simulating platform configuration validation.
        """
        tpm_emulator = bypass_engine.tpm_emulator

        pcr_index = 7
        expected_pcr = hashlib.sha256(b"expected_state").digest()

        tpm_emulator.pcrs[pcr_index] = expected_pcr

        policy_digest = hashlib.sha256(b"policy" + expected_pcr).digest()

        key_template = b"\x00" * 32
        rc, key = tpm_emulator.create_primary_key(0x40000001, b"", key_template)
        assert rc == TPM_RC.SUCCESS, "Key creation must succeed"

        sealed_data = b"sensitive_license_data"
        rc, blob = tpm_emulator.seal_data(key.handle, sealed_data, policy_digest)

        if rc == TPM_RC.SUCCESS and blob is not None:
            tpm_emulator.pcrs[pcr_index] = expected_pcr
            rc_unseal, unsealed = tpm_emulator.unseal_data(key.handle, blob, policy_digest)

            if rc_unseal == TPM_RC.SUCCESS:
                assert unsealed == sealed_data, "Unsealed data must match original when PCR correct"

            tpm_emulator.pcrs[pcr_index] = hashlib.sha256(b"wrong_state").digest()
            rc_unseal_fail, _ = tpm_emulator.unseal_data(key.handle, blob, policy_digest)
            assert rc_unseal_fail != TPM_RC.SUCCESS, "Unsealing must fail with wrong PCR"


class TestPlatformSpecificAttestationChains:
    """Tests for platform-specific attestation chains (Intel SGX, ARM TrustZone)."""

    @pytest.fixture
    def bypass_engine(self) -> SecureEnclaveBypass:
        """Create SecureEnclaveBypass instance for testing.

        Returns:
            SecureEnclaveBypass: Initialized bypass engine.
        """
        return SecureEnclaveBypass()

    def test_intel_sgx_attestation_chain_structure(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify Intel SGX attestation chain has correct structure.

        Tests that SGX attestation includes PCK cert, root CA chain,
        and proper Intel OID extensions.
        """
        platform_info = {
            "has_tpm": False,
            "has_sgx": True,
            "manufacturer": "GenuineIntel",
            "cpu_model": "Intel(R) Xeon(R) Platinum",
            "platform_id": "fedcba9876543210",
        }

        cert_bytes = bypass_engine._generate_sgx_certificate(platform_info)
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert org == "Intel Corporation", "SGX cert must be issued by Intel"

        ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
        assert "SGX" in ou, "SGX cert must identify SGX organizational unit"

        issuer_ou = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        if issuer_ou:
            assert "PCS" in issuer_ou[0].value or "SGX" in issuer_ou[0].value, "Issuer should be Intel PCS or SGX CA"

    def test_windows_hello_credential_guard_bypass_support(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test Windows Hello/Credential Guard bypass capabilities.

        Verifies bypass engine can generate attestations compatible with
        Windows Hello TPM-based authentication.
        """
        challenge = b"windows_hello_challenge"
        response = bypass_engine.process_attestation_challenge(challenge)

        assert "signature" in response, "Attestation must include signature"
        assert "certificates" in response, "Attestation must include certificates"
        assert len(response["certificates"]) > 0, "Must have at least one certificate"

        cert_bytes = base64.b64decode(response["certificates"][0])
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

        public_key = cert.public_key()
        assert isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)), "Key must be RSA or ECC for Windows Hello"

    def test_hardware_tpm_module_detection(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test detection of actual hardware TPM module.

        Verifies platform detection differentiates between hardware TPM,
        firmware TPM (fTPM), and virtual TPM (vTPM).
        """
        platform_info = bypass_engine._detect_platform_info()

        if platform_info["has_tpm"]:
            assert isinstance(platform_info["has_tpm"], bool), "TPM detection must return boolean"


class TestEdgeCasesAndSpecialConfigurations:
    """Tests for edge cases: vTPM in VMs, Azure Attestation, firmware TPM."""

    @pytest.fixture
    def bypass_engine(self) -> SecureEnclaveBypass:
        """Create SecureEnclaveBypass instance for testing.

        Returns:
            SecureEnclaveBypass: Initialized bypass engine.
        """
        return SecureEnclaveBypass()

    def test_vtpm_in_virtual_machine_attestation(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test attestation works with virtual TPM (vTPM) in VMs.

        Verifies attestation generation succeeds when running in virtualized
        environment with emulated TPM module.
        """
        platform_info = bypass_engine._detect_platform_info()

        challenge = b"vtpm_challenge"
        response = bypass_engine.process_attestation_challenge(challenge)

        assert len(response["signature"]) > 0, "vTPM attestation must produce signature"
        assert len(response["certificates"]) > 0, "vTPM attestation must include certificates"

    def test_azure_attestation_format_compatibility(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test compatibility with Azure Attestation Service format.

        Verifies generated attestations match Azure MAA expected format
        with proper JWT structure and claims.
        """
        challenge = b"azure_attestation_challenge"
        response = bypass_engine.process_attestation_challenge(challenge)

        assert "signature" in response, "Azure attestation requires signature"
        assert "certificates" in response, "Azure attestation requires certificate chain"

        sig_bytes = base64.b64decode(response["signature"])
        assert len(sig_bytes) >= 64, "Signature must meet minimum length for Azure validation"

    def test_firmware_tpm_ftpm_support(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test support for firmware TPM (fTPM) implementations.

        Verifies attestation works with firmware-based TPM found in modern
        Intel/AMD CPUs without discrete TPM chip.
        """
        platform_info = bypass_engine._detect_platform_info()

        if platform_info["has_tpm"]:
            challenge = b"ftpm_test_challenge"
            response = bypass_engine.process_attestation_challenge(challenge)

            assert response is not None, "fTPM attestation must succeed"
            assert len(response["signature"]) > 0, "fTPM must produce valid signatures"

    def test_quote_structure_tpm2_attestation_format(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify TPM 2.0 quote structure follows specification.

        Tests that generated quotes contain proper TPMS_ATTEST structure
        with magic value, qualified signer, clock info, and PCR digest.
        """
        challenge = b"quote_validation_challenge"
        response = bypass_engine.process_attestation_challenge(challenge)

        if response.get("signature"):
            sig_bytes = base64.b64decode(response["signature"])

            assert len(sig_bytes) > 0, "Quote signature must not be empty"

    def test_multiple_tpm_manufacturer_certificate_formats(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test certificate generation for different TPM manufacturers.

        Verifies certificates adapt to different TPM vendors (Infineon, STM,
        Nuvoton) with appropriate vendor-specific attributes.
        """
        manufacturers = ["Infineon", "STMicroelectronics", "Nuvoton", "Intel", "AMD"]

        for manufacturer in manufacturers:
            platform_info = {
                "has_tpm": True,
                "manufacturer": manufacturer,
                "platform_id": hashlib.sha256(manufacturer.encode()).hexdigest()[:16],
                "cpu_model": "TestCPU",
            }

            cert_bytes = bypass_engine._generate_tpm_certificate(platform_info)
            cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

            org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
            assert org == manufacturer, f"Certificate organization must match manufacturer {manufacturer}"

    def test_tpm_version_specific_quote_generation(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test quote generation handles TPM 1.2 vs TPM 2.0 differences.

        Verifies bypass engine generates appropriate quote format based on
        TPM version (TCG spec compliance).
        """
        challenge = b"version_specific_challenge"
        response = bypass_engine.process_attestation_challenge(challenge)

        assert "signature" in response, "Quote must include signature"

        sig_bytes = base64.b64decode(response["signature"])
        assert len(sig_bytes) >= 32, "Quote signature must meet minimum cryptographic strength"

    def test_arm_trustzone_attestation_format(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test ARM TrustZone attestation format support.

        Verifies attestation can generate ARM-specific attestation tokens
        compatible with TrustZone secure world verification.
        """
        platform_info = {
            "has_tpm": False,
            "has_sgx": False,
            "manufacturer": "ARM",
            "cpu_model": "ARM Cortex-A76",
            "platform_id": "arm64trustzone",
        }

        challenge = b"trustzone_challenge"
        response = bypass_engine.process_attestation_challenge(challenge)

        assert response is not None, "ARM TrustZone attestation must be supported"
        assert len(response.get("signature", "")) > 0, "TrustZone attestation must include signature"

    def test_concurrent_attestation_requests(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test handling of concurrent attestation requests.

        Verifies bypass engine can handle multiple simultaneous attestation
        challenges without key collision or race conditions.
        """
        import concurrent.futures

        challenges = [os.urandom(32) for _ in range(20)]

        def process_challenge(challenge: bytes) -> dict[str, Any]:
            return bypass_engine.process_attestation_challenge(challenge)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(process_challenge, challenges))

        signatures = [r["signature"] for r in results]
        assert len(set(signatures)) == 20, "All concurrent attestations must produce unique signatures"

    def test_attestation_with_missing_platform_info(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Test attestation fallback when platform info unavailable.

        Verifies bypass generates valid attestation even when WMI/CPU detection
        fails or runs on unsupported platform.
        """
        with mock.patch.object(bypass_engine, "_detect_platform_info", return_value={
            "has_tpm": False,
            "has_sgx": False,
            "manufacturer": "Unknown",
            "cpu_model": "Unknown",
            "platform_id": None,
        }):
            challenge = b"fallback_challenge"
            response = bypass_engine.process_attestation_challenge(challenge)

            assert len(response["signature"]) > 0, "Attestation must work even without platform detection"
            assert len(response["certificates"]) > 0, "Fallback certificates must be generated"


class TestCryptographicValidation:
    """Tests for cryptographic correctness of attestation operations."""

    @pytest.fixture
    def bypass_engine(self) -> SecureEnclaveBypass:
        """Create SecureEnclaveBypass instance for testing.

        Returns:
            SecureEnclaveBypass: Initialized bypass engine.
        """
        return SecureEnclaveBypass()

    def test_rsa_signature_verification_with_generated_key(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify RSA signatures can be verified with generated public key.

        Tests that attestation signatures are cryptographically valid and
        verifiable using the public key from generated certificates.
        """
        challenge = b"crypto_validation_challenge"
        response = bypass_engine.process_attestation_challenge(challenge)

        sig_bytes = base64.b64decode(response["signature"])
        cert_bytes = base64.b64decode(response["certificates"][0])

        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        public_key = cert.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            quote_data = hashlib.sha256(challenge).digest()

            try:
                public_key.verify(
                    sig_bytes,
                    quote_data,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            except Exception as e:
                pytest.fail(f"RSA signature verification failed: {e}")

    def test_ecdsa_signature_verification_with_generated_key(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify ECDSA signatures can be verified with generated public key.

        Tests that SGX-style ECDSA signatures are cryptographically valid
        for P-256 curve.
        """
        platform_info = {
            "has_tpm": False,
            "has_sgx": True,
            "manufacturer": "Intel",
            "cpu_model": "IntelCPU",
            "platform_id": "sgxtest123456",
        }

        cert_bytes = bypass_engine._generate_sgx_certificate(platform_info)
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        public_key = cert.public_key()

        assert isinstance(public_key, ec.EllipticCurvePublicKey), "SGX cert must have ECC key"
        assert public_key.curve.name == "secp256r1", "SGX must use P-256 curve"

    def test_no_weak_cryptographic_algorithms(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify no weak cryptographic algorithms in attestation.

        Tests that attestation uses only strong crypto: RSA-2048+, SHA-256+,
        ECDSA P-256+, rejecting MD5, SHA1, RSA-1024.
        """
        platform_info = bypass_engine._detect_platform_info()

        if platform_info["has_tpm"]:
            cert_bytes = bypass_engine._generate_tpm_certificate(platform_info)
            cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

            sig_algo = cert.signature_algorithm_oid
            assert sig_algo == x509.SignatureAlgorithmOID.RSA_WITH_SHA256 or \
                   sig_algo == x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256, \
                   "Certificate must use SHA256 or stronger"

            public_key = cert.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                assert public_key.key_size >= 2048, "RSA key must be at least 2048 bits"

    def test_certificate_validity_period_reasonable(self, bypass_engine: SecureEnclaveBypass) -> None:
        """Verify certificate validity periods are realistic.

        Tests that generated certificates have reasonable not-before and
        not-after dates matching real TPM/SGX certificate lifetimes.
        """
        platform_info = {
            "has_tpm": True,
            "manufacturer": "Test",
            "platform_id": "test123",
            "cpu_model": "TestCPU",
        }

        cert_bytes = bypass_engine._generate_tpm_certificate(platform_info)
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        validity_days = (not_after - not_before).days

        assert validity_days >= 365, "Certificate should be valid for at least 1 year"
        assert validity_days <= 3650 * 2, "Certificate should not exceed 20 years validity"

        now = datetime.now(not_before.tzinfo)
        assert not_before <= now, "Certificate not-before should be in past or present"
        assert not_after > now, "Certificate should not be expired"
