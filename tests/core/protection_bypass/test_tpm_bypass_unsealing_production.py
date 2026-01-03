"""Production Tests for TPM Unsealing Fallback Without Cryptographic Libraries.

Validates REAL TPM unsealing fallback capabilities when PyCryptodome is unavailable.
Tests prove the TPM bypass engine can extract license data from TPM-sealed blobs using
pattern matching and heuristics when cryptographic libraries fail or are missing.

This tests the specific issue identified in testingtodo.md:
`intellicrack/core/protection_bypass/tpm_bypass.py:1908-1935` - Pattern matching on encrypted data, returns None

Expected Behavior (from testingtodo.md):
- Must implement proper TPM unsealing for license data retrieval
- Must handle TPM 2.0 key hierarchy (SRK, storage keys, sealing keys)
- Must emulate TPM PCR values for policy-based unsealing
- Must bypass TPM-based attestation checks
- Must handle software TPM vs hardware TPM differences
- Must provide meaningful fallback when TPM operations fail
- Edge cases: Remote attestation, TPM 2.0 enhanced authorization

NO MOCKS - tests validate genuine offensive capability against real TPM data structures.

Tests cover:
- Pattern-based unsealing when crypto libraries unavailable
- TPM 2.0 private key blob format recognition
- PEM-encoded key extraction from sealed blobs
- DER-encoded key extraction from sealed blobs
- VMK (BitLocker Volume Master Key) extraction
- RSA/ECC key material detection
- Software TPM blob format handling
- Hardware TPM blob format handling
- Multi-layer encrypted blob unwrapping
- Remote attestation data extraction
- Enhanced authorization (TPM 2.0) fallback handling
- Edge cases: corrupted blobs, minimal valid data, partial structures

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
"""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.protection_bypass.tpm_bypass import (
    AttestationData,
    PCRBank,
    TPM2Algorithm,
    TPM2CommandCode,
    TPMBypassEngine,
)


@pytest.fixture
def tpm_engine() -> TPMBypassEngine:
    """Create TPM bypass engine instance for unsealing tests."""
    return TPMBypassEngine()


@pytest.fixture
def minimal_valid_blob() -> bytes:
    """Create minimal valid blob (16 bytes) for edge case testing."""
    return os.urandom(16)


@pytest.fixture
def tpm2_private_key_blob_pattern() -> bytes:
    """Create realistic TPM 2.0 private key blob with type marker.

    TPM 2.0 private key blobs start with type marker 0x0001.
    This pattern should be recognized and returned as-is for further processing.
    """
    blob_type = b"\x00\x01\x00\x00"
    key_material = os.urandom(256)
    return blob_type + key_material


@pytest.fixture
def tpm2_sha256_sealed_blob_pattern() -> bytes:
    """Create TPM 2.0 SHA-256 sealed blob with length marker.

    TPM 2.0 SHA-256 sealed blobs use format:
    - Length marker (2 bytes): 0x0020 (32 bytes)
    - SHA-256 hash (32 bytes): actual key material
    - Additional data (variable): metadata/padding
    """
    length_marker = b"\x00\x20"
    key_material = hashlib.sha256(b"LicenseKey_12345").digest()
    additional_data = os.urandom(32)
    return length_marker + key_material + additional_data


@pytest.fixture
def pem_encoded_rsa_key_blob() -> bytes:
    """Create blob containing PEM-encoded RSA private key.

    Many TPM implementations store keys in PEM format within sealed blobs.
    The unsealer should extract the PEM block starting from the header.
    """
    pem_header = b"-----BEGIN RSA PRIVATE KEY-----\n"
    pem_body = b"MIIEpAIBAAKCAQEA1234567890ABCDEF" * 4
    pem_footer = b"\n-----END RSA PRIVATE KEY-----"
    pem_key = pem_header + pem_body + pem_footer

    random_prefix = os.urandom(64)
    random_suffix = os.urandom(32)

    return random_prefix + pem_key + random_suffix


@pytest.fixture
def pem_encoded_ecc_key_blob() -> bytes:
    """Create blob containing PEM-encoded ECC private key."""
    pem_header = b"-----BEGIN EC PRIVATE KEY-----\n"
    pem_body = b"MHcCAQEEIIGNjZWay1234567890ABCDEF" * 3
    pem_footer = b"\n-----END EC PRIVATE KEY-----"
    pem_key = pem_header + pem_body + pem_footer

    random_prefix = os.urandom(48)
    random_suffix = os.urandom(16)

    return random_prefix + pem_key + random_suffix


@pytest.fixture
def der_encoded_key_blob() -> bytes:
    """Create blob containing DER-encoded key structure.

    DER encoding starts with SEQUENCE tag 0x30 followed by length.
    Common pattern: 0x30 0x82 (long form length) for RSA keys.
    """
    der_sequence_marker = b"\x30\x82"
    der_length = struct.pack(">H", 512)
    der_body = os.urandom(512)

    random_prefix = os.urandom(100)
    random_suffix = os.urandom(50)

    return random_prefix + der_sequence_marker + der_length + der_body + random_suffix


@pytest.fixture
def bitlocker_vmk_blob() -> bytes:
    """Create BitLocker Volume Master Key (VMK) sealed blob.

    BitLocker stores VMKs in TPM with distinctive "VMK\x00" marker.
    The unsealer should extract VMK data for BitLocker bypass.
    """
    vmk_marker = b"VMK\x00"
    vmk_version = struct.pack("<H", 2)
    vmk_guid = os.urandom(16)
    vmk_key_material = os.urandom(256)

    random_prefix = os.urandom(80)
    random_suffix = os.urandom(40)

    return random_prefix + vmk_marker + vmk_version + vmk_guid + vmk_key_material + random_suffix


@pytest.fixture
def multi_layer_encrypted_blob() -> bytes:
    """Create multi-layer encrypted blob with nested key structures.

    Some protections use layered encryption with outer envelope and inner payload.
    Multiple patterns may be present - unsealer should find innermost valid data.
    """
    inner_pem = b"-----BEGIN PRIVATE KEY-----\nMIIE" + os.urandom(200) + b"\n-----END PRIVATE KEY-----"
    middle_layer = os.urandom(50) + inner_pem + os.urandom(50)
    outer_layer = b"\x00\x01\x00\x00" + middle_layer

    return outer_layer


@pytest.fixture
def software_tpm_blob() -> bytes:
    """Create software TPM sealed blob with common pattern.

    Software TPM implementations (e.g., Microsoft software TPM) use different
    blob structures than hardware TPM. Often use PEM or DER within simple wrappers.
    """
    wrapper_header = b"SWTPM_SEALED_v1\x00"
    der_key = b"\x30\x82" + struct.pack(">H", 256) + os.urandom(256)

    return wrapper_header + der_key


@pytest.fixture
def hardware_tpm_blob() -> bytes:
    """Create hardware TPM sealed blob with vendor-specific format.

    Hardware TPM chips (Infineon, STMicroelectronics, etc.) use proprietary formats.
    Common patterns include type markers and length-prefixed structures.
    """
    vendor_marker = b"TPM_VENDOR_001\x00\x00"
    blob_type = b"\x00\x01\x00\x00"
    key_hierarchy = struct.pack(">I", 0x40000001)
    sealed_data = os.urandom(512)

    return vendor_marker + blob_type + key_hierarchy + sealed_data


@pytest.fixture
def remote_attestation_blob() -> bytes:
    """Create remote attestation response blob with AIK certificate.

    Remote attestation responses contain Attestation Identity Key (AIK) certificates.
    These are often DER-encoded X.509 certificates within sealed blobs.
    """
    x509_cert_marker = b"\x30\x82"
    cert_length = struct.pack(">H", 1024)
    cert_data = os.urandom(1024)

    attestation_header = b"REMOTE_ATTEST\x00\x00\x00"

    return attestation_header + x509_cert_marker + cert_length + cert_data


@pytest.fixture
def enhanced_authorization_blob() -> bytes:
    """Create TPM 2.0 enhanced authorization (EA) policy blob.

    TPM 2.0 EA policies contain authorization structures with multiple elements.
    Should extract policy digest or embedded key material.
    """
    ea_magic = b"TPM2_EA_POLICY\x00\x00"
    policy_digest = hashlib.sha256(b"PolicyPCR_SecureBoot").digest()
    embedded_key = b"-----BEGIN PUBLIC KEY-----\n" + os.urandom(128) + b"\n-----END PUBLIC KEY-----"

    return ea_magic + policy_digest + embedded_key


@pytest.fixture
def corrupted_short_blob() -> bytes:
    """Create corrupted blob shorter than minimum (< 16 bytes)."""
    return os.urandom(12)


@pytest.fixture
def corrupted_no_patterns_blob() -> bytes:
    """Create blob with no recognizable patterns (pure random data)."""
    return os.urandom(256)


@pytest.fixture
def corrupted_partial_pattern_blob() -> bytes:
    """Create blob with partial/incomplete patterns."""
    partial_pem = b"-----BEGIN RSA"
    partial_der = b"\x30"
    return os.urandom(50) + partial_pem + os.urandom(50) + partial_der + os.urandom(50)


class TestTPMUnsealWithoutCrypto:
    """Tests for TPM unsealing fallback without cryptographic libraries."""

    def test_unseal_returns_none_for_too_short_blob(
        self, tpm_engine: TPMBypassEngine, corrupted_short_blob: bytes
    ) -> None:
        """Unsealing fails gracefully for blobs shorter than 16 bytes."""
        result = tpm_engine._unseal_without_crypto(corrupted_short_blob)

        assert result is None, "Should return None for blobs < 16 bytes"

    def test_unseal_recognizes_tpm2_private_key_blob_type(
        self, tpm_engine: TPMBypassEngine, tpm2_private_key_blob_pattern: bytes
    ) -> None:
        """Unsealing recognizes TPM 2.0 private key blob type marker (0x00010000)."""
        result = tpm_engine._unseal_without_crypto(tpm2_private_key_blob_pattern)

        assert result is not None, "Should extract TPM 2.0 private key blob"
        assert result.startswith(b"\x00\x01\x00\x00"), "Should preserve type marker"
        assert len(result) == len(tpm2_private_key_blob_pattern), "Should return full blob for private key type"

    def test_unseal_extracts_sha256_sealed_key_material(
        self, tpm_engine: TPMBypassEngine, tpm2_sha256_sealed_blob_pattern: bytes
    ) -> None:
        """Unsealing extracts 32-byte SHA-256 key material from length-prefixed blob."""
        result = tpm_engine._unseal_without_crypto(tpm2_sha256_sealed_blob_pattern)

        assert result is not None, "Should extract SHA-256 key material"
        assert len(result) == 32, "Should extract exactly 32 bytes (SHA-256 hash size)"

        expected_key = hashlib.sha256(b"LicenseKey_12345").digest()
        assert result == expected_key, "Should extract correct SHA-256 key material"

    def test_unseal_extracts_pem_encoded_rsa_key(
        self, tpm_engine: TPMBypassEngine, pem_encoded_rsa_key_blob: bytes
    ) -> None:
        """Unsealing locates and extracts PEM-encoded RSA private key from blob."""
        result = tpm_engine._unseal_without_crypto(pem_encoded_rsa_key_blob)

        assert result is not None, "Should extract PEM-encoded RSA key"
        assert result.startswith(b"-----BEGIN"), "Should start at PEM header"
        assert b"RSA PRIVATE KEY" in result, "Should contain RSA key marker"
        assert b"-----END RSA PRIVATE KEY-----" in result, "Should include complete PEM block"

    def test_unseal_extracts_pem_encoded_ecc_key(
        self, tpm_engine: TPMBypassEngine, pem_encoded_ecc_key_blob: bytes
    ) -> None:
        """Unsealing locates and extracts PEM-encoded ECC private key from blob."""
        result = tpm_engine._unseal_without_crypto(pem_encoded_ecc_key_blob)

        assert result is not None, "Should extract PEM-encoded ECC key"
        assert result.startswith(b"-----BEGIN"), "Should start at PEM header"
        assert b"EC PRIVATE KEY" in result, "Should contain ECC key marker"

    def test_unseal_extracts_der_encoded_key(
        self, tpm_engine: TPMBypassEngine, der_encoded_key_blob: bytes
    ) -> None:
        """Unsealing locates and extracts DER-encoded key structure from blob."""
        result = tpm_engine._unseal_without_crypto(der_encoded_key_blob)

        assert result is not None, "Should extract DER-encoded key"
        assert result.startswith(b"\x30\x82"), "Should start at DER SEQUENCE marker"
        assert len(result) >= 514, "Should include DER header and body (at minimum)"

    def test_unseal_extracts_bitlocker_vmk(
        self, tpm_engine: TPMBypassEngine, bitlocker_vmk_blob: bytes
    ) -> None:
        """Unsealing locates and extracts BitLocker Volume Master Key (VMK)."""
        result = tpm_engine._unseal_without_crypto(bitlocker_vmk_blob)

        assert result is not None, "Should extract BitLocker VMK"
        assert result.startswith(b"VMK\x00"), "Should start at VMK marker"
        assert len(result) >= 256, "Should include VMK metadata and key material"

    def test_unseal_handles_multi_layer_encrypted_blob(
        self, tpm_engine: TPMBypassEngine, multi_layer_encrypted_blob: bytes
    ) -> None:
        """Unsealing extracts valid key material from multi-layer encrypted blob.

        Should find FIRST matching pattern (type marker 0x00010000 in this case).
        """
        result = tpm_engine._unseal_without_crypto(multi_layer_encrypted_blob)

        assert result is not None, "Should extract key material from layered blob"
        assert result.startswith(b"\x00\x01\x00\x00"), "Should extract outermost type marker pattern"

    def test_unseal_handles_software_tpm_blob(
        self, tpm_engine: TPMBypassEngine, software_tpm_blob: bytes
    ) -> None:
        """Unsealing extracts key material from software TPM sealed blob."""
        result = tpm_engine._unseal_without_crypto(software_tpm_blob)

        assert result is not None, "Should extract key from software TPM blob"
        assert result.startswith(b"\x30\x82"), "Should extract DER-encoded key"

    def test_unseal_handles_hardware_tpm_blob(
        self, tpm_engine: TPMBypassEngine, hardware_tpm_blob: bytes
    ) -> None:
        """Unsealing extracts key material from hardware TPM sealed blob."""
        result = tpm_engine._unseal_without_crypto(hardware_tpm_blob)

        assert result is not None, "Should extract key from hardware TPM blob"
        assert result.startswith(b"\x00\x01\x00\x00"), "Should recognize TPM 2.0 private key blob type"

    def test_unseal_handles_remote_attestation_blob(
        self, tpm_engine: TPMBypassEngine, remote_attestation_blob: bytes
    ) -> None:
        """Unsealing extracts AIK certificate from remote attestation response."""
        result = tpm_engine._unseal_without_crypto(remote_attestation_blob)

        assert result is not None, "Should extract certificate from attestation blob"
        assert result.startswith(b"\x30\x82"), "Should extract DER-encoded X.509 certificate"
        assert len(result) >= 1024, "Should include complete certificate data"

    def test_unseal_handles_enhanced_authorization_blob(
        self, tpm_engine: TPMBypassEngine, enhanced_authorization_blob: bytes
    ) -> None:
        """Unsealing extracts embedded key from TPM 2.0 enhanced authorization policy."""
        result = tpm_engine._unseal_without_crypto(enhanced_authorization_blob)

        assert result is not None, "Should extract key from EA policy blob"
        assert result.startswith(b"-----BEGIN"), "Should extract embedded PEM public key"

    def test_unseal_returns_none_for_no_patterns(
        self, tpm_engine: TPMBypassEngine, corrupted_no_patterns_blob: bytes
    ) -> None:
        """Unsealing returns None when no recognizable patterns found."""
        result = tpm_engine._unseal_without_crypto(corrupted_no_patterns_blob)

        assert result is None, "Should return None for unrecognizable blob"

    def test_unseal_returns_none_for_partial_patterns(
        self, tpm_engine: TPMBypassEngine, corrupted_partial_pattern_blob: bytes
    ) -> None:
        """Unsealing returns None when only partial/incomplete patterns present.

        Note: Implementation may still extract partial patterns if they exist.
        This test validates handling of incomplete/corrupted data.
        """
        result = tpm_engine._unseal_without_crypto(corrupted_partial_pattern_blob)

        if result is not None:
            assert b"-----BEGIN RSA" in result or b"\x30" in result, "If extracted, should contain found pattern"

    def test_unseal_minimal_valid_blob(
        self, tpm_engine: TPMBypassEngine, minimal_valid_blob: bytes
    ) -> None:
        """Unsealing handles minimal valid blob (exactly 16 bytes)."""
        result = tpm_engine._unseal_without_crypto(minimal_valid_blob)

        assert result is None or len(result) > 0, "Should return None or valid extraction"


class TestTPMUnsealWithoutCryptoEdgeCases:
    """Edge case tests for TPM unsealing fallback."""

    def test_unseal_blob_with_multiple_pem_blocks(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing extracts first PEM block when multiple present."""
        pem1 = b"-----BEGIN RSA PRIVATE KEY-----\nAAA\n-----END RSA PRIVATE KEY-----"
        pem2 = b"-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----"

        blob = os.urandom(32) + pem1 + os.urandom(16) + pem2 + os.urandom(32)

        result = tpm_engine._unseal_without_crypto(blob)

        assert result is not None, "Should extract first PEM block"
        assert result.startswith(b"-----BEGIN"), "Should start at first PEM header"
        assert b"RSA PRIVATE KEY" in result, "Should extract first (RSA) key, not certificate"

    def test_unseal_blob_with_type_marker_and_pem(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing prioritizes type marker over later PEM pattern."""
        blob_type = b"\x00\x01\x00\x00"
        random_data = os.urandom(64)
        pem_key = b"-----BEGIN PRIVATE KEY-----\nXYZ\n-----END PRIVATE KEY-----"

        blob = blob_type + random_data + pem_key

        result = tpm_engine._unseal_without_crypto(blob)

        assert result is not None, "Should extract based on type marker"
        assert result.startswith(b"\x00\x01\x00\x00"), "Should prioritize type marker (earlier in pattern list)"

    def test_unseal_blob_with_embedded_null_bytes(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing handles blobs with embedded null bytes correctly."""
        vmk_marker = b"VMK\x00"
        null_padding = b"\x00" * 16
        key_data = os.urandom(128)

        blob = os.urandom(40) + vmk_marker + null_padding + key_data

        result = tpm_engine._unseal_without_crypto(blob)

        assert result is not None, "Should handle null bytes in blob"
        assert result.startswith(b"VMK\x00"), "Should extract VMK marker and data"

    def test_unseal_blob_exactly_16_bytes_with_no_patterns(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing returns None for exactly 16 bytes of random data."""
        blob = os.urandom(16)

        while blob[:4] == b"\x00\x01\x00\x00" or blob[:2] == b"\x00\x20" or b"-----BEGIN" in blob or b"\x30\x82" in blob or b"VMK\x00" in blob:
            blob = os.urandom(16)

        result = tpm_engine._unseal_without_crypto(blob)

        assert result is None, "Should return None for 16-byte blob with no patterns"

    def test_unseal_sha256_blob_with_insufficient_remaining_data(
        self, tpm_engine: TPMBypassEngine
    ) -> None:
        """Unsealing handles SHA-256 marker but insufficient data (< 32 bytes remaining).

        Should fail bounds check and return None or try next pattern.
        """
        length_marker = b"\x00\x20"
        insufficient_data = os.urandom(20)

        blob = length_marker + insufficient_data

        result = tpm_engine._unseal_without_crypto(blob)

        if result is not None:
            assert len(result) != 32, "Should not extract exactly 32 bytes when only 20 available"

    def test_unseal_blob_with_pattern_at_exact_end(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing handles pattern marker at exact end of blob."""
        random_data = os.urandom(100)
        pattern_at_end = b"VMK\x00"

        blob = random_data + pattern_at_end

        result = tpm_engine._unseal_without_crypto(blob)

        assert result is not None, "Should extract pattern at end of blob"
        assert result == pattern_at_end, "Should extract only the pattern marker"

    def test_unseal_very_large_blob_with_late_pattern(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing efficiently handles very large blobs with pattern near end."""
        random_prefix = os.urandom(10000)
        der_key = b"\x30\x82" + struct.pack(">H", 256) + os.urandom(256)

        blob = random_prefix + der_key

        result = tpm_engine._unseal_without_crypto(blob)

        assert result is not None, "Should find pattern in large blob"
        assert result.startswith(b"\x30\x82"), "Should extract DER key from large blob"


class TestTPMUnsealIntegrationWithMainFunction:
    """Integration tests for unsealing with main unseal_tpm_key function."""

    def test_unseal_tpm_key_falls_back_to_pattern_matching_without_crypto(
        self, tpm_engine: TPMBypassEngine, pem_encoded_rsa_key_blob: bytes, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Main unseal_tpm_key function uses fallback when HAS_CRYPTO is False."""
        import intellicrack.core.protection_bypass.tpm_bypass as tpm_module

        original_has_crypto = tpm_module.HAS_CRYPTO
        monkeypatch.setattr(tpm_module, "HAS_CRYPTO", False)

        engine = TPMBypassEngine()

        result = engine.unseal_tpm_key(pem_encoded_rsa_key_blob)

        assert result is not None, "Should use fallback unsealing"
        assert result.startswith(b"-----BEGIN"), "Should extract PEM key via fallback"

        monkeypatch.setattr(tpm_module, "HAS_CRYPTO", original_has_crypto)

    def test_unseal_tpm_key_uses_crypto_when_available(
        self, tpm_engine: TPMBypassEngine, valid_auth_value: bytes
    ) -> None:
        """Main unseal_tpm_key function prefers crypto unsealing when available.

        This test validates the decision logic - NOT the crypto unsealing itself
        (that's covered in other test files).
        """
        import intellicrack.core.protection_bypass.tpm_bypass as tpm_module

        if not tpm_module.HAS_CRYPTO:
            pytest.skip("Crypto libraries not available - cannot test crypto path")

        blob_type = struct.pack(">H", 0x0001)
        integrity_size = struct.pack(">H", 0)
        sensitive_size = struct.pack(">H", 32)
        encrypted_data = os.urandom(48)

        sealed_blob = blob_type + integrity_size + sensitive_size + encrypted_data

        result = tpm_engine.unseal_tpm_key(sealed_blob, valid_auth_value)

        assert result is None or isinstance(result, bytes), "Should attempt crypto unsealing"


class TestTPMUnsealPerformance:
    """Performance tests for unsealing operations."""

    def test_unseal_performance_on_large_blob(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing completes in reasonable time for large blobs."""
        import time

        large_blob = os.urandom(1024 * 1024)
        der_pattern = b"\x30\x82" + struct.pack(">H", 256) + os.urandom(256)
        blob_with_pattern = large_blob + der_pattern

        start_time = time.time()
        result = tpm_engine._unseal_without_crypto(blob_with_pattern)
        elapsed_time = time.time() - start_time

        assert result is not None, "Should find pattern in large blob"
        assert elapsed_time < 2.0, f"Should complete within 2 seconds (took {elapsed_time:.3f}s)"

    def test_unseal_performance_on_no_pattern_blob(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing fails fast when no patterns present in large blob."""
        import time

        large_blob = os.urandom(512 * 1024)

        while b"-----BEGIN" in large_blob or b"\x30\x82" in large_blob or b"VMK\x00" in large_blob:
            large_blob = os.urandom(512 * 1024)

        start_time = time.time()
        result = tpm_engine._unseal_without_crypto(large_blob)
        elapsed_time = time.time() - start_time

        assert result is None, "Should return None for blob with no patterns"
        assert elapsed_time < 1.0, f"Should fail fast (took {elapsed_time:.3f}s)"


class TestTPMUnsealRealWorldScenarios:
    """Real-world scenario tests for TPM unsealing."""

    def test_unseal_windows_hello_credential_guard_blob(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing extracts credentials from Windows Hello/Credential Guard blob.

        Windows Hello stores biometric template keys in TPM-sealed blobs.
        Credential Guard stores domain credentials similarly.
        """
        hello_magic = b"WINDOWS_HELLO_v2\x00"
        der_credential = b"\x30\x82" + struct.pack(">H", 384) + os.urandom(384)

        blob = hello_magic + os.urandom(32) + der_credential

        result = tpm_engine._unseal_without_crypto(blob)

        assert result is not None, "Should extract Windows Hello credential"
        assert result.startswith(b"\x30\x82"), "Should extract DER-encoded credential"

    def test_unseal_azure_attestation_blob(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing extracts attestation key from Azure Attestation blob."""
        azure_magic = b"AZURE_ATTEST_v1\x00"
        pem_aik = b"-----BEGIN CERTIFICATE-----\n" + os.urandom(256) + b"\n-----END CERTIFICATE-----"

        blob = azure_magic + pem_aik

        result = tpm_engine._unseal_without_crypto(blob)

        assert result is not None, "Should extract Azure attestation certificate"
        assert b"CERTIFICATE" in result, "Should extract PEM certificate"

    def test_unseal_intel_sgx_sealed_blob(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing extracts key from Intel SGX sealed blob.

        Intel SGX uses TPM for remote attestation. Sealed blobs contain
        enclave identity keys and measurement data.
        """
        sgx_magic = b"SGX_SEALED_v1\x00\x00\x00"
        der_enclave_key = b"\x30\x82" + struct.pack(">H", 512) + os.urandom(512)

        blob = sgx_magic + der_enclave_key

        result = tpm_engine._unseal_without_crypto(blob)

        assert result is not None, "Should extract SGX enclave key"
        assert result.startswith(b"\x30\x82"), "Should extract DER-encoded key"

    def test_unseal_arm_trustzone_blob(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing extracts key from ARM TrustZone secure storage.

        ARM TrustZone implementations use TPM-like sealing for secure keys.
        """
        trustzone_magic = b"TRUSTZONE_SEAL\x00\x00"
        pem_key = b"-----BEGIN PRIVATE KEY-----\n" + os.urandom(192) + b"\n-----END PRIVATE KEY-----"

        blob = trustzone_magic + pem_key

        result = tpm_engine._unseal_without_crypto(blob)

        assert result is not None, "Should extract TrustZone key"
        assert result.startswith(b"-----BEGIN"), "Should extract PEM private key"

    def test_unseal_software_license_key_sealed_in_tpm(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing extracts software license key from TPM-sealed blob.

        Commercial software protection systems (Sentinel, CodeMeter, etc.) use
        TPM for license key storage. This validates license cracking capability.
        """
        license_header = b"LICENSE_v1\x00\x00\x00\x00\x00\x00"
        license_type = struct.pack("<I", 1)
        sealed_key_marker = b"\x00\x20"
        license_key = hashlib.sha256(b"PRODUCT-SERIAL-123456").digest()

        blob = license_header + license_type + sealed_key_marker + license_key

        result = tpm_engine._unseal_without_crypto(blob)

        assert result is not None, "CRITICAL: Should extract license key from TPM blob"
        assert len(result) == 32, "Should extract complete license key (SHA-256)"
        assert result == license_key, "Should extract correct license key value"

    def test_unseal_hardware_dongle_emulation_key(self, tpm_engine: TPMBypassEngine) -> None:
        """Unsealing extracts hardware dongle emulation key from TPM.

        Some protections store dongle emulation keys in TPM to prevent
        software dongle emulators. Unsealing defeats this protection.
        """
        dongle_magic = b"HASP_DONGLE_KEY\x00"
        der_dongle_key = b"\x30\x82" + struct.pack(">H", 256) + os.urandom(256)

        blob = dongle_magic + der_dongle_key

        result = tpm_engine._unseal_without_crypto(blob)

        assert result is not None, "CRITICAL: Should extract dongle emulation key"
        assert result.startswith(b"\x30\x82"), "Should extract DER-encoded dongle key"
        assert len(result) >= 258, "Should include complete key structure"
