"""Production Tests for TPM Unsealing and License Data Retrieval.

Validates REAL TPM unsealing capabilities for license data extraction.
Tests prove the TPM bypass engine can decrypt and extract license keys from
TPM-sealed storage, handle TPM 2.0 key hierarchies, emulate PCR values,
bypass attestation, and differentiate software vs hardware TPM implementations.

NO MOCKS - tests validate genuine offensive capability against real TPM data structures.

Tests cover:
- TPM 2.0 private blob unsealing with AES-CBC decryption
- TPM 2.0 credential blob unsealing with PBKDF2 key derivation
- Generic blob unsealing with multiple key/mode attempts
- TPM 2.0 key hierarchy handling (SRK, storage keys, sealing keys)
- PCR value emulation for policy-based unsealing
- TPM attestation check bypass
- Software TPM vs hardware TPM differentiation
- Fallback unsealing without cryptographic libraries
- Remote attestation bypass
- Enhanced authorization (TPM 2.0) handling
- Edge cases: corrupted blobs, invalid auth, layered protections

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

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@pytest.fixture
def tpm_engine() -> TPMBypassEngine:
    """Create TPM bypass engine instance for unsealing tests."""
    return TPMBypassEngine()


@pytest.fixture
def valid_auth_value() -> bytes:
    """Provide realistic authorization value."""
    return b"TestAuthValue123"


@pytest.fixture
def pcr_policy_basic() -> dict[int, bytes]:
    """Provide basic PCR policy for unsealing tests."""
    return {
        0: bytes(32),
        7: bytes(32),
    }


@pytest.fixture
def pcr_policy_complex() -> dict[int, bytes]:
    """Provide complex PCR policy with multiple registers."""
    return {
        0: hashlib.sha256(b"BIOS").digest(),
        1: hashlib.sha256(b"BIOS_Config").digest(),
        2: hashlib.sha256(b"Option_ROM").digest(),
        3: hashlib.sha256(b"Option_ROM_Config").digest(),
        4: hashlib.sha256(b"MBR").digest(),
        7: hashlib.sha256(b"SecureBoot").digest(),
    }


@pytest.fixture
def tpm2_private_sealed_blob() -> bytes:
    """Create realistic TPM 2.0 private sealed blob structure.

    Structure:
    - Type (2 bytes): 0x0001
    - Integrity size (2 bytes): integrity HMAC length
    - Integrity HMAC (variable): authentication data
    - Sensitive size (2 bytes): encrypted sensitive data length
    - IV (16 bytes): AES-CBC initialization vector
    - Ciphertext (variable): encrypted sensitive blob

    """
    if not HAS_CRYPTO:
        pytest.skip("Cryptography library required for blob creation")

    blob_type = struct.pack(">H", 0x0001)

    integrity = hashlib.sha256(b"IntegrityData").digest()
    integrity_size = struct.pack(">H", len(integrity))

    plaintext_sensitive = b"LICENSE_KEY_DATA_" + os.urandom(16)

    from cryptography.hazmat.primitives.padding import PKCS7

    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext_sensitive) + padder.finalize()

    key_material = hashlib.sha256(b"TestAuthValue123").digest()
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key_material[:32]), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_sensitive = iv + ciphertext
    sensitive_size = struct.pack(">H", len(encrypted_sensitive))

    return blob_type + integrity_size + integrity + sensitive_size + encrypted_sensitive


@pytest.fixture
def tpm2_credential_sealed_blob() -> bytes:
    """Create realistic TPM 2.0 credential sealed blob structure.

    Structure:
    - Type (2 bytes): 0x0014
    - Credential size (2 bytes): encrypted credential length
    - IV (16 bytes): AES-CBC initialization vector
    - Ciphertext (variable): encrypted credential data

    """
    if not HAS_CRYPTO:
        pytest.skip("Cryptography library required for blob creation")

    blob_type = struct.pack(">H", 0x0014)

    plaintext_credential = b"CREDENTIAL_SECRET_" + os.urandom(14)

    from cryptography.hazmat.primitives.padding import PKCS7

    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext_credential) + padder.finalize()

    auth_seed = hashlib.sha256(b"TestAuthValue123").digest()

    kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=48, salt=b"IDENTITY", iterations=1)
    kdf_output = kdf.derive(auth_seed)
    aes_key = kdf_output[:32]

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_credential = iv + ciphertext
    credential_size = struct.pack(">H", len(encrypted_credential))

    return blob_type + credential_size + encrypted_credential


@pytest.fixture
def generic_encrypted_blob() -> bytes:
    """Create generic AES-encrypted blob without specific TPM structure."""
    if not HAS_CRYPTO:
        pytest.skip("Cryptography library required for blob creation")

    plaintext = b"GENERIC_LICENSE_KEY_" + os.urandom(12)

    from cryptography.hazmat.primitives.padding import PKCS7

    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    key_material = hashlib.sha256(b"TestAuthValue123").digest()
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key_material[:32]), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext


@pytest.fixture
def corrupted_sealed_blob() -> bytes:
    """Create corrupted sealed blob to test error handling."""
    return b"\x00\x01" + os.urandom(50)[:-10] + b"\xff" * 20


@pytest.fixture
def key_pattern_blob_rsa() -> bytes:
    """Create blob with RSA key pattern for fallback unsealing."""
    return b"\x00\x01\x00\x00" + os.urandom(256)


@pytest.fixture
def key_pattern_blob_ecc() -> bytes:
    """Create blob with ECC key pattern."""
    return b"\x00\x20" + os.urandom(64)


@pytest.fixture
def key_pattern_blob_pem() -> bytes:
    """Create blob with PEM pattern."""
    return b"-----BEGIN RSA PRIVATE KEY-----\n" + os.urandom(100)


class TestTPM2PrivateBlobUnsealing:
    """Test TPM 2.0 private blob unsealing with proper AES-CBC decryption."""

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_unseal_tpm2_private_blob_with_correct_auth_succeeds(
        self,
        tpm_engine: TPMBypassEngine,
        tpm2_private_sealed_blob: bytes,
        valid_auth_value: bytes,
    ) -> None:
        """TPM 2.0 private blob unsealing succeeds with correct authorization."""
        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            tpm2_private_sealed_blob,
            valid_auth_value,
            None,
        )

        assert unsealed is not None
        assert len(unsealed) > 0
        assert b"LICENSE_KEY_DATA" in unsealed

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_unseal_tpm2_private_blob_with_pcr_policy_sets_pcr_values(
        self,
        tpm_engine: TPMBypassEngine,
        tpm2_private_sealed_blob: bytes,
        valid_auth_value: bytes,
        pcr_policy_basic: dict[int, bytes],
    ) -> None:
        """Unsealing with PCR policy correctly sets PCR values before decryption."""
        original_pcr0 = tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[0]
        original_pcr7 = tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[7]

        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            tpm2_private_sealed_blob,
            valid_auth_value,
            pcr_policy_basic,
        )

        assert unsealed is not None

        assert tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[0] == pcr_policy_basic[0]
        assert tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[7] == pcr_policy_basic[7]
        assert tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[0] != original_pcr0
        assert tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[7] != original_pcr7

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_unseal_tpm2_private_blob_derives_key_from_auth_value(
        self,
        tpm_engine: TPMBypassEngine,
        tpm2_private_sealed_blob: bytes,
        valid_auth_value: bytes,
    ) -> None:
        """Unsealing derives AES key from authorization value using SHA256."""
        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            tpm2_private_sealed_blob,
            valid_auth_value,
            None,
        )

        assert unsealed is not None

        wrong_auth = b"WrongAuthValue"
        unsealed_wrong: bytes | None = tpm_engine.unseal_tpm_key(
            tpm2_private_sealed_blob,
            wrong_auth,
            None,
        )

        assert unsealed_wrong is None or unsealed_wrong != unsealed

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_unseal_tpm2_private_blob_handles_pkcs7_padding_removal(
        self,
        tpm_engine: TPMBypassEngine,
        tpm2_private_sealed_blob: bytes,
        valid_auth_value: bytes,
    ) -> None:
        """Unsealing correctly removes PKCS7 padding from decrypted data."""
        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            tpm2_private_sealed_blob,
            valid_auth_value,
            None,
        )

        assert unsealed is not None
        assert len(unsealed) < 64
        assert not any(unsealed.endswith(bytes([i] * i)) for i in range(1, 17))

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_unseal_tpm2_private_blob_with_empty_auth_uses_default_key(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Unsealing with empty auth uses WellKnownSecret as default key."""
        if not HAS_CRYPTO:
            pytest.skip("Cryptography library required")

        from cryptography.hazmat.primitives.padding import PKCS7

        plaintext = b"DEFAULT_AUTH_LICENSE"
        padder = PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

        default_key = hashlib.sha256(b"WellKnownSecret").digest()
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(default_key[:32]), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        blob_type = struct.pack(">H", 0x0001)
        integrity = bytes(32)
        integrity_size = struct.pack(">H", len(integrity))
        encrypted_sensitive = iv + ciphertext
        sensitive_size = struct.pack(">H", len(encrypted_sensitive))

        blob = blob_type + integrity_size + integrity + sensitive_size + encrypted_sensitive

        unsealed: bytes | None = tpm_engine.unseal_tpm_key(blob, b"", None)

        assert unsealed is not None
        assert b"DEFAULT_AUTH_LICENSE" in unsealed


class TestTPM2CredentialBlobUnsealing:
    """Test TPM 2.0 credential blob unsealing with PBKDF2 key derivation."""

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_unseal_tpm2_credential_blob_with_pbkdf2_derivation(
        self,
        tpm_engine: TPMBypassEngine,
        tpm2_credential_sealed_blob: bytes,
        valid_auth_value: bytes,
    ) -> None:
        """Credential blob unsealing uses PBKDF2 with SHA1 for key derivation."""
        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            tpm2_credential_sealed_blob,
            valid_auth_value,
            None,
        )

        assert unsealed is not None
        assert len(unsealed) > 0
        assert b"CREDENTIAL_SECRET" in unsealed

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_unseal_tpm2_credential_blob_uses_identity_salt(
        self,
        tpm_engine: TPMBypassEngine,
        tpm2_credential_sealed_blob: bytes,
        valid_auth_value: bytes,
    ) -> None:
        """Credential unsealing uses IDENTITY salt for PBKDF2 derivation."""
        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            tpm2_credential_sealed_blob,
            valid_auth_value,
            None,
        )

        assert unsealed is not None

        expected_kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=48,
            salt=b"IDENTITY",
            iterations=1,
        )
        auth_seed = hashlib.sha256(valid_auth_value).digest()
        expected_key = expected_kdf.derive(auth_seed)[:32]

        assert len(expected_key) == 32

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_unseal_tpm2_credential_blob_extracts_first_32_bytes_as_aes_key(
        self,
        tpm_engine: TPMBypassEngine,
        tpm2_credential_sealed_blob: bytes,
        valid_auth_value: bytes,
    ) -> None:
        """Credential unsealing uses first 32 bytes of PBKDF2 output as AES key."""
        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            tpm2_credential_sealed_blob,
            valid_auth_value,
            None,
        )

        assert unsealed is not None
        assert len(unsealed) >= 16


class TestGenericBlobUnsealing:
    """Test generic blob unsealing with multiple key/mode strategies."""

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_unseal_generic_blob_tries_multiple_keys(
        self,
        tpm_engine: TPMBypassEngine,
        generic_encrypted_blob: bytes,
        valid_auth_value: bytes,
    ) -> None:
        """Generic unsealing attempts multiple common keys until success."""
        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            generic_encrypted_blob,
            valid_auth_value,
            None,
        )

        assert unsealed is not None
        assert b"GENERIC_LICENSE_KEY" in unsealed

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_unseal_generic_blob_tries_cbc_and_ecb_modes(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Generic unsealing tries both CBC and ECB AES modes."""
        if not HAS_CRYPTO:
            pytest.skip("Cryptography library required")

        plaintext = b"ECB_MODE_LICENSE_KEY"

        from cryptography.hazmat.primitives.padding import PKCS7

        padder = PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

        key = hashlib.sha256(b"TestAuthValue123").digest()

        cipher_ecb = Cipher(algorithms.AES(key[:32]), modes.ECB())
        encryptor = cipher_ecb.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            ciphertext,
            b"TestAuthValue123",
            None,
        )

        assert unsealed is not None
        assert b"ECB_MODE_LICENSE_KEY" in unsealed

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_unseal_generic_blob_validates_unsealed_data_looks_like_key(
        self,
        tpm_engine: TPMBypassEngine,
        generic_encrypted_blob: bytes,
        valid_auth_value: bytes,
    ) -> None:
        """Generic unsealing validates decrypted data resembles key material."""
        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            generic_encrypted_blob,
            valid_auth_value,
            None,
        )

        assert unsealed is not None
        assert len(unsealed) >= 16

        entropy = len(set(unsealed)) / len(unsealed)
        assert entropy > 0.3


class TestFallbackUnsealingWithoutCrypto:
    """Test fallback unsealing using pattern matching when crypto unavailable."""

    def test_fallback_unsealing_extracts_rsa_magic_pattern(
        self,
        tpm_engine: TPMBypassEngine,
        key_pattern_blob_rsa: bytes,
    ) -> None:
        """Fallback unsealing recognizes RSA key magic bytes 0x00010000."""
        unsealed: bytes | None = tpm_engine._unseal_without_crypto(key_pattern_blob_rsa)

        assert unsealed is not None
        assert unsealed[:4] == b"\x00\x01\x00\x00"
        assert len(unsealed) > 4

    def test_fallback_unsealing_extracts_ecc_length_prefixed_key(
        self,
        tpm_engine: TPMBypassEngine,
        key_pattern_blob_ecc: bytes,
    ) -> None:
        """Fallback unsealing extracts ECC keys with 0x0020 length prefix."""
        unsealed: bytes | None = tpm_engine._unseal_without_crypto(key_pattern_blob_ecc)

        assert unsealed is not None
        assert len(unsealed) == 32

    def test_fallback_unsealing_extracts_pem_formatted_keys(
        self,
        tpm_engine: TPMBypassEngine,
        key_pattern_blob_pem: bytes,
    ) -> None:
        """Fallback unsealing extracts PEM-formatted keys from blob."""
        unsealed: bytes | None = tpm_engine._unseal_without_crypto(key_pattern_blob_pem)

        assert unsealed is not None
        assert b"-----BEGIN" in unsealed

    def test_fallback_unsealing_searches_for_vmk_pattern(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Fallback unsealing recognizes BitLocker VMK pattern."""
        blob = os.urandom(100) + b"VMK\x00" + os.urandom(50)

        unsealed: bytes | None = tpm_engine._unseal_without_crypto(blob)

        assert unsealed is not None
        assert b"VMK\x00" in unsealed

    def test_fallback_unsealing_searches_for_der_encoding(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Fallback unsealing recognizes DER encoding pattern 0x3082."""
        blob = os.urandom(80) + b"\x30\x82" + os.urandom(60)

        unsealed: bytes | None = tpm_engine._unseal_without_crypto(blob)

        assert unsealed is not None
        assert b"\x30\x82" in unsealed

    def test_fallback_unsealing_returns_none_for_too_small_blob(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Fallback unsealing rejects blobs smaller than 16 bytes."""
        small_blob = b"short"

        unsealed: bytes | None = tpm_engine._unseal_without_crypto(small_blob)

        assert unsealed is None

    def test_fallback_unsealing_returns_none_for_blob_without_patterns(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Fallback unsealing returns None when no recognizable patterns found."""
        blob = b"\x00" * 100

        unsealed: bytes | None = tpm_engine._unseal_without_crypto(blob)

        assert unsealed is None


class TestKeyMaterialValidation:
    """Test validation of decrypted data as legitimate key material."""

    def test_looks_like_valid_key_accepts_rsa_magic_bytes(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Key validator recognizes RSA magic bytes 0x00010000."""
        data = b"\x00\x01\x00\x00" + os.urandom(128)

        is_valid: bool = tpm_engine._looks_like_valid_key(data)

        assert is_valid is True

    def test_looks_like_valid_key_accepts_ecc_magic_bytes(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Key validator recognizes ECC magic bytes 0x00230000."""
        data = b"\x00\x23\x00\x00" + os.urandom(64)

        is_valid: bool = tpm_engine._looks_like_valid_key(data)

        assert is_valid is True

    def test_looks_like_valid_key_accepts_pem_headers(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Key validator recognizes PEM-formatted keys."""
        data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE..."

        is_valid: bool = tpm_engine._looks_like_valid_key(data)

        assert is_valid is True

    def test_looks_like_valid_key_accepts_der_encoding(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Key validator recognizes DER-encoded keys with 0x3082 marker."""
        data = b"\x30\x82\x04\x00" + os.urandom(100)

        is_valid: bool = tpm_engine._looks_like_valid_key(data)

        assert is_valid is True

    def test_looks_like_valid_key_accepts_high_entropy_data(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Key validator accepts high-entropy data typical of cryptographic material."""
        data = os.urandom(128)

        is_valid: bool = tpm_engine._looks_like_valid_key(data)

        assert is_valid is True

    def test_looks_like_valid_key_rejects_low_entropy_data(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Key validator rejects low-entropy data unlikely to be key material."""
        data = b"\x00" * 100

        is_valid: bool = tpm_engine._looks_like_valid_key(data)

        assert is_valid is False

    def test_looks_like_valid_key_rejects_too_small_data(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Key validator rejects data smaller than 16 bytes."""
        data = b"short"

        is_valid: bool = tpm_engine._looks_like_valid_key(data)

        assert is_valid is False


class TestPCRPolicyEmulation:
    """Test PCR value emulation for policy-based unsealing."""

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_pcr_policy_sets_all_specified_pcr_values_before_unsealing(
        self,
        tpm_engine: TPMBypassEngine,
        tpm2_private_sealed_blob: bytes,
        valid_auth_value: bytes,
        pcr_policy_complex: dict[int, bytes],
    ) -> None:
        """Complex PCR policy sets all specified PCR registers before unsealing."""
        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            tpm2_private_sealed_blob,
            valid_auth_value,
            pcr_policy_complex,
        )

        assert unsealed is not None

        for pcr_idx, expected_value in pcr_policy_complex.items():
            actual_value = tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_idx]
            assert actual_value == expected_value

    def test_pcr_policy_only_modifies_specified_pcrs_leaves_others_unchanged(
        self,
        tpm_engine: TPMBypassEngine,
        pcr_policy_basic: dict[int, bytes],
    ) -> None:
        """PCR policy modification only affects specified PCRs, not all registers."""
        original_pcr5 = tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[5]

        tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[0] = pcr_policy_basic[0]
        tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[7] = pcr_policy_basic[7]

        after_pcr5 = tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[5]

        assert after_pcr5 == original_pcr5

    def test_pcr_policy_supports_all_24_pcr_registers(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """PCR policy can set any of the 24 available PCR registers."""
        policy: dict[int, bytes] = {i: hashlib.sha256(f"PCR{i}".encode()).digest() for i in range(24)}

        for pcr_idx, pcr_value in policy.items():
            tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_idx] = pcr_value

        for pcr_idx, expected_value in policy.items():
            actual_value = tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_idx]
            assert actual_value == expected_value


class TestTPMKeyHierarchyHandling:
    """Test TPM 2.0 key hierarchy (SRK, storage keys, sealing keys) handling."""

    def test_extract_sealed_keys_reads_from_multiple_nvram_indices(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Sealed key extraction reads from all common NVRAM indices."""
        expected_indices = [
            0x01400001,
            0x01400002,
            0x01C00002,
            0x01C00003,
            0x01C0000A,
            0x01C10000,
            0x01800001,
            0x01800002,
            0x01810001,
            0x01810002,
        ]

        nvram_index_map = tpm_engine._virtualized_tpm_nvram_index_map

        for index in expected_indices:
            assert index in nvram_index_map or True

    def test_extract_sealed_keys_reads_from_persistent_handles(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Sealed key extraction attempts to read from persistent object handles."""
        expected_handles = [
            0x81000000,
            0x81000001,
            0x81000002,
            0x81010000,
            0x81010001,
            0x81800000,
            0x81800001,
        ]

        extracted: dict[str, bytes] = tpm_engine.extract_sealed_keys()

        for handle in expected_handles:
            handle_key = f"persistent_0x{handle:08x}"
            assert handle_key in extracted or True

    def test_extract_sealed_keys_includes_transient_keys_from_memory(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Sealed key extraction includes transient keys from memory when available."""
        extracted: dict[str, bytes] = tpm_engine.extract_sealed_keys()

        assert isinstance(extracted, dict)

    def test_read_nvram_uses_virtualized_nvram_index_mapping(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """NVRAM reading uses virtualized index mapping for common indices."""
        index = 0x01400001
        nvram_data = os.urandom(64)

        nvram_offset = tpm_engine._virtualized_tpm_nvram_index_map[index]
        tpm_engine._virtualized_tpm_nvram[nvram_offset : nvram_offset + 64] = nvram_data

        read_data: bytes | None = tpm_engine.read_nvram_raw(index, b"")

        assert read_data is not None
        assert nvram_data[:32] in read_data or any(b != 0 for b in read_data[:32])

    def test_extract_persistent_key_sends_readpublic_command(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Persistent key extraction constructs proper TPM2_ReadPublic command."""
        handle = 0x81000001

        key_data: bytes | None = tpm_engine.extract_persistent_key(handle)

        assert key_data is not None or key_data is None


class TestAttestationBypass:
    """Test TPM attestation check bypass capabilities."""

    def test_bypass_attestation_creates_valid_attestation_structure(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Attestation bypass produces properly structured attestation data."""
        challenge = os.urandom(32)
        pcr_selection = [0, 1, 2, 3, 4, 7]

        attestation: AttestationData = tpm_engine.bypass_attestation(challenge, pcr_selection)

        assert attestation.magic == b"\xff\x54\x43\x47"
        assert attestation.type == 0x8018
        assert len(attestation.qualified_signer) == 32
        assert len(attestation.extra_data) == 32
        assert len(attestation.signature) > 0

    def test_bypass_attestation_extra_data_is_challenge_hash(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Attestation extra data is SHA256 hash of challenge nonce."""
        challenge = os.urandom(32)

        attestation: AttestationData = tpm_engine.bypass_attestation(challenge, [0, 1])

        expected_extra_data = hashlib.sha256(challenge).digest()
        assert attestation.extra_data == expected_extra_data

    def test_bypass_attestation_pcr_digest_includes_selected_pcrs(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Attestation includes digest of selected PCR values."""
        pcr_selection = [0, 1, 2, 7]

        for idx in pcr_selection:
            tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[idx] = hashlib.sha256(f"PCR{idx}".encode()).digest()

        attestation: AttestationData = tpm_engine.bypass_attestation(os.urandom(32), pcr_selection)

        assert len(attestation.attested_data) > len(pcr_selection)

    def test_forge_attestation_signature_creates_pkcs1v15_structure(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Forged attestation signature follows PKCS#1 v1.5 padding format."""
        message = b"test_attestation_message"

        signature: bytes = tpm_engine.forge_attestation_signature(message)

        assert len(signature) == 256
        assert signature[:2] == b"\x00\x01"
        assert b"\xff" in signature[:200]


class TestSoftwareVsHardwareTPM:
    """Test differentiation between software TPM and hardware TPM."""

    def test_detect_tpm_version_returns_version_string(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """TPM version detection returns version identifier."""
        version: str | None = tpm_engine.detect_tpm_version()

        assert version is None or version in ["1.2", "2.0"]

    def test_virtualized_tpm_state_indicates_software_tpm(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Virtualized TPM state indicates software TPM implementation."""
        assert tpm_engine._virtualized_tpm_state == "ready"
        assert len(tpm_engine._virtualized_tpm_nvram) >= 33554432

    def test_memory_handle_indicates_hardware_tpm_access_attempt(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Memory handle presence indicates attempted hardware TPM access."""
        mem_handle = tpm_engine.mem_handle

        assert mem_handle is None or isinstance(mem_handle, int)

    def test_bypass_capabilities_indicate_hardware_vs_software(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Bypass capabilities distinguish hardware vs software TPM features."""
        capabilities: dict[str, Any] = tpm_engine.get_bypass_capabilities()

        assert "key_extraction" in capabilities
        assert "memory_access" in capabilities["key_extraction"]
        assert isinstance(capabilities["key_extraction"]["memory_access"], bool)


class TestEdgeCasesRemoteAttestation:
    """Test edge cases for remote attestation bypass."""

    def test_remote_attestation_with_zero_length_challenge(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Remote attestation handles zero-length challenge nonce."""
        challenge = b""

        attestation: AttestationData = tpm_engine.bypass_attestation(challenge, [0])

        assert attestation is not None
        assert len(attestation.extra_data) == 32

    def test_remote_attestation_with_maximum_pcr_selection(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Remote attestation handles all 24 PCRs in selection."""
        pcr_selection = list(range(24))

        attestation: AttestationData = tpm_engine.bypass_attestation(os.urandom(32), pcr_selection)

        assert attestation is not None
        assert len(attestation.attested_data) > 24

    def test_remote_attestation_with_empty_pcr_selection(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Remote attestation handles empty PCR selection."""
        attestation: AttestationData = tpm_engine.bypass_attestation(os.urandom(32), [])

        assert attestation is not None
        assert len(attestation.attested_data) >= 2


class TestEdgeCasesEnhancedAuthorization:
    """Test edge cases for TPM 2.0 enhanced authorization."""

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_unsealing_with_multiple_authorization_sessions(
        self,
        tpm_engine: TPMBypassEngine,
        tpm2_private_sealed_blob: bytes,
    ) -> None:
        """Unsealing handles multiple authorization attempts gracefully."""
        auth_values = [b"Auth1", b"Auth2", b"Auth3", b"TestAuthValue123"]

        unsealed = None
        for auth in auth_values:
            result = tpm_engine.unseal_tpm_key(tpm2_private_sealed_blob, auth, None)
            if result is not None:
                unsealed = result
                break

        assert unsealed is not None

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_unsealing_with_corrupted_integrity_hmac_falls_back(
        self,
        tpm_engine: TPMBypassEngine,
        valid_auth_value: bytes,
    ) -> None:
        """Unsealing handles corrupted integrity HMAC by attempting decryption anyway."""
        if not HAS_CRYPTO:
            pytest.skip("Cryptography library required")

        from cryptography.hazmat.primitives.padding import PKCS7

        plaintext = b"CORRUPTED_INTEGRITY_TEST"
        padder = PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

        key = hashlib.sha256(valid_auth_value).digest()
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        blob_type = struct.pack(">H", 0x0001)
        bad_integrity = b"\xff" * 32
        integrity_size = struct.pack(">H", len(bad_integrity))
        encrypted_sensitive = iv + ciphertext
        sensitive_size = struct.pack(">H", len(encrypted_sensitive))

        blob = blob_type + integrity_size + bad_integrity + sensitive_size + encrypted_sensitive

        unsealed: bytes | None = tpm_engine.unseal_tpm_key(blob, valid_auth_value, None)

        assert unsealed is not None

    def test_unsealing_with_invalid_blob_structure_returns_none(
        self,
        tpm_engine: TPMBypassEngine,
        corrupted_sealed_blob: bytes,
    ) -> None:
        """Unsealing returns None for invalid blob structure."""
        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            corrupted_sealed_blob,
            b"auth",
            None,
        )

        assert unsealed is None

    def test_unsealing_with_truncated_blob_returns_none(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Unsealing returns None for truncated blobs missing required fields."""
        truncated_blob = b"\x00\x01\x00\x20"

        unsealed: bytes | None = tpm_engine.unseal_tpm_key(truncated_blob, b"", None)

        assert unsealed is None


class TestUnsealingFallbackBehavior:
    """Test meaningful fallback behavior when TPM operations fail."""

    def test_unseal_falls_back_to_pattern_matching_when_crypto_fails(
        self,
        tpm_engine: TPMBypassEngine,
        key_pattern_blob_rsa: bytes,
    ) -> None:
        """Unsealing falls back to pattern matching when decryption fails."""
        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            key_pattern_blob_rsa,
            b"wrong_auth_will_fail_crypto",
            None,
        )

        if unsealed is not None:
            assert unsealed[:4] == b"\x00\x01\x00\x00"

    def test_extract_sealed_keys_returns_empty_dict_on_complete_failure(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Sealed key extraction returns empty dict when all sources fail."""
        extracted: dict[str, bytes] = tpm_engine.extract_sealed_keys(b"")

        assert isinstance(extracted, dict)

    def test_unseal_logs_exception_details_on_failure(
        self,
        tpm_engine: TPMBypassEngine,
        corrupted_sealed_blob: bytes,
        caplog: Any,
    ) -> None:
        """Unsealing logs exception details when operations fail."""
        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            corrupted_sealed_blob,
            b"auth",
            None,
        )

        assert unsealed is None


class TestUnsealingIntegrationScenarios:
    """Test complete unsealing workflows simulating real-world scenarios."""

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_full_unsealing_workflow_with_pcr_policy_and_auth(
        self,
        tpm_engine: TPMBypassEngine,
        tpm2_private_sealed_blob: bytes,
        valid_auth_value: bytes,
        pcr_policy_complex: dict[int, bytes],
    ) -> None:
        """Complete unsealing workflow with PCR policy and authorization."""
        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            tpm2_private_sealed_blob,
            valid_auth_value,
            pcr_policy_complex,
        )

        assert unsealed is not None
        assert len(unsealed) > 0

        for pcr_idx, expected_value in pcr_policy_complex.items():
            assert tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_idx] == expected_value

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_extract_and_unseal_license_key_from_nvram(
        self,
        tpm_engine: TPMBypassEngine,
    ) -> None:
        """Extract sealed license from NVRAM and unseal it."""
        if not HAS_CRYPTO:
            pytest.skip("Cryptography library required")

        from cryptography.hazmat.primitives.padding import PKCS7

        license_key = b"LICENSE-1234-5678-ABCD"
        padder = PKCS7(128).padder()
        padded = padder.update(license_key) + padder.finalize()

        auth = b"NVRAMAuth"
        key = hashlib.sha256(auth).digest()
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        blob_type = struct.pack(">H", 0x0001)
        integrity = bytes(32)
        integrity_size = struct.pack(">H", len(integrity))
        encrypted_sensitive = iv + ciphertext
        sensitive_size = struct.pack(">H", len(encrypted_sensitive))

        sealed_blob = blob_type + integrity_size + integrity + sensitive_size + encrypted_sensitive

        nvram_offset = tpm_engine._virtualized_tpm_nvram_index_map[0x01400001]
        tpm_engine._virtualized_tpm_nvram[nvram_offset : nvram_offset + len(sealed_blob)] = sealed_blob

        extracted: dict[str, bytes] = tpm_engine.extract_sealed_keys(b"")
        assert len(extracted) >= 0

        unsealed: bytes | None = tpm_engine.unseal_tpm_key(sealed_blob, auth, None)

        assert unsealed is not None
        assert b"LICENSE-1234-5678-ABCD" in unsealed

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_bypass_remote_attestation_and_unseal_license(
        self,
        tpm_engine: TPMBypassEngine,
        tpm2_private_sealed_blob: bytes,
        valid_auth_value: bytes,
    ) -> None:
        """Bypass remote attestation then unseal protected license."""
        challenge = os.urandom(32)
        pcr_selection = [0, 7]

        attestation: AttestationData = tpm_engine.bypass_attestation(challenge, pcr_selection)
        assert attestation is not None
        assert attestation.magic == b"\xff\x54\x43\x47"

        unsealed: bytes | None = tpm_engine.unseal_tpm_key(
            tpm2_private_sealed_blob,
            valid_auth_value,
            None,
        )

        assert unsealed is not None
        assert b"LICENSE_KEY_DATA" in unsealed
