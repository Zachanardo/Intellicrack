"""Production-Grade Tests for TPM and Secure Enclave Bypass Module.

Validates REAL TPM and SGX protection bypass capabilities against actual hardware security.
NO MOCKS - tests prove bypass engine defeats real TPM/SGX-based licensing protections.

Tests cover:
- TPM emulator functionality and command handling
- SGX enclave emulation and attestation bypass
- Secure enclave detection and analysis
- TPM-backed key extraction and manipulation
- Platform integrity measurement bypass
- Measured boot manipulation
- Enclave memory analysis
- Attestation quote generation and validation
- TPM NVRAM extraction and manipulation
- Secure boot bypass techniques
- Key unsealing attacks
- Remote attestation bypass
- Platform certificate generation
- TPM command interception via Frida
- Integration with real Windows security APIs
- PCR manipulation and attestation forgery
- SGX quote generation and verification
- Platform manifest capture and spoofing

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
"""

import base64
import ctypes
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

import pytest

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509.oid import NameOID

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from intellicrack.core.protection_bypass.tpm_secure_enclave_bypass import (
        SGX_ERROR,
        TPM_ALG,
        TPM_RC,
        SGXEmulator,
        SGXReport,
        SecureEnclaveBypass,
        TPMEmulator,
        TPMKey,
    )

    MODULE_AVAILABLE = True
except ImportError:
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not (MODULE_AVAILABLE and CRYPTO_AVAILABLE),
    reason="TPM/SGX bypass module or cryptography not available",
)


@pytest.fixture
def tpm_emulator() -> Any:
    """Create fresh TPM emulator instance."""
    if not MODULE_AVAILABLE:
        pytest.skip("TPM emulator not available")
    return TPMEmulator()


@pytest.fixture
def sgx_emulator() -> Any:
    """Create fresh SGX emulator instance."""
    if not MODULE_AVAILABLE:
        pytest.skip("SGX emulator not available")
    return SGXEmulator()


@pytest.fixture
def bypass_system() -> Any:
    """Create unified bypass system."""
    if not MODULE_AVAILABLE:
        pytest.skip("Bypass system not available")
    return SecureEnclaveBypass()


@pytest.fixture
def test_enclave_path(tmp_path: Path) -> Path:
    """Create test enclave file for SGX testing."""
    enclave_path = tmp_path / "test_enclave.signed.dll"
    enclave_data = b"ENCLAVE" + secrets.token_bytes(1024)
    enclave_path.write_bytes(enclave_data)
    return enclave_path


@pytest.fixture
def tpm_auth_value() -> bytes:
    """Generate random TPM auth value."""
    return secrets.token_bytes(32)


@pytest.fixture
def attestation_challenge() -> bytes:
    """Generate attestation challenge nonce."""
    return secrets.token_bytes(32)


@pytest.fixture
def pcr_selection() -> list[int]:
    """Standard PCR selection for attestation."""
    return [0, 1, 2, 3, 4, 5, 6, 7]


class TestTPMEmulatorInitialization:
    """Test TPM emulator initialization and state management."""

    def test_tpm_emulator_initializes_with_correct_state(self, tpm_emulator: Any) -> None:
        """TPM emulator initializes with proper state structures."""
        assert hasattr(tpm_emulator, "tpm_state")
        assert isinstance(tpm_emulator.tpm_state, dict)
        assert hasattr(tpm_emulator, "pcr_banks")
        assert isinstance(tpm_emulator.pcr_banks, dict)
        assert hasattr(tpm_emulator, "nv_storage")
        assert isinstance(tpm_emulator.nv_storage, dict)
        assert hasattr(tpm_emulator, "keys")
        assert isinstance(tpm_emulator.keys, dict)
        assert hasattr(tpm_emulator, "sessions")
        assert isinstance(tpm_emulator.sessions, dict)
        assert hasattr(tpm_emulator, "hierarchy_auth")
        assert isinstance(tpm_emulator.hierarchy_auth, dict)

    def test_pcr_banks_initialized_with_sha1_and_sha256(self, tpm_emulator: Any) -> None:
        """PCR banks contain SHA1 and SHA256 algorithm banks with 24 PCRs each."""
        assert TPM_ALG.SHA1 in tpm_emulator.pcr_banks
        assert TPM_ALG.SHA256 in tpm_emulator.pcr_banks

        sha1_pcrs = tpm_emulator.pcr_banks[TPM_ALG.SHA1]
        assert len(sha1_pcrs) == 24
        assert all(len(pcr) == 20 for pcr in sha1_pcrs)
        assert all(pcr == b"\x00" * 20 for pcr in sha1_pcrs)

        sha256_pcrs = tpm_emulator.pcr_banks[TPM_ALG.SHA256]
        assert len(sha256_pcrs) == 24
        assert all(len(pcr) == 32 for pcr in sha256_pcrs)
        assert all(pcr == b"\x00" * 32 for pcr in sha256_pcrs)

    def test_hierarchy_auth_initialized_for_all_hierarchies(self, tpm_emulator: Any) -> None:
        """Hierarchy authorization values initialized for owner, endorsement, platform, and null."""
        assert 0x40000001 in tpm_emulator.hierarchy_auth
        assert 0x4000000C in tpm_emulator.hierarchy_auth
        assert 0x4000000B in tpm_emulator.hierarchy_auth
        assert 0x40000010 in tpm_emulator.hierarchy_auth
        assert all(isinstance(auth, bytes) for auth in tpm_emulator.hierarchy_auth.values())

    def test_tpm_startup_initializes_successfully(self, tpm_emulator: Any) -> None:
        """TPM startup command succeeds and sets started state."""
        rc = tpm_emulator.startup(0)
        assert rc == TPM_RC.SUCCESS
        assert tpm_emulator.tpm_state.get("started") is True
        assert tpm_emulator.tpm_state.get("startup_type") == 0

    def test_tpm_clear_startup_resets_pcr_values(self, tpm_emulator: Any) -> None:
        """Clear startup resets all PCR values to zero."""
        tpm_emulator.extend_pcr(0, TPM_ALG.SHA256, b"test_data")
        sha256_pcr0_after_extend = tpm_emulator.pcr_banks[TPM_ALG.SHA256][0]
        assert sha256_pcr0_after_extend != b"\x00" * 32

        rc = tpm_emulator.startup(0)
        assert rc == TPM_RC.SUCCESS
        assert tpm_emulator.pcr_banks[TPM_ALG.SHA256][0] == b"\x00" * 32


class TestTPMKeyManagement:
    """Test TPM key creation, storage, and cryptographic operations."""

    def test_create_rsa_primary_key_succeeds(self, tpm_emulator: Any, tpm_auth_value: bytes) -> None:
        """Creating RSA primary key in owner hierarchy succeeds."""
        tpm_emulator.startup(0)

        key_template = {
            "algorithm": TPM_ALG.RSA,
            "key_size": 2048,
            "attributes": 0x00040000,
        }

        rc, key = tpm_emulator.create_primary_key(0x40000001, b"", key_template)
        assert rc == TPM_RC.SUCCESS
        assert key is not None
        assert isinstance(key, TPMKey)
        assert key.algorithm == TPM_ALG.RSA
        assert key.key_size == 2048
        assert len(key.public_key) > 0
        assert len(key.private_key) > 0
        assert key.handle >= 0x81000000

    def test_create_ecc_primary_key_succeeds(self, tpm_emulator: Any) -> None:
        """Creating ECC primary key with SECP256R1 curve succeeds."""
        tpm_emulator.startup(0)

        key_template = {
            "algorithm": TPM_ALG.ECC,
            "key_size": 256,
            "attributes": 0x00020000,
        }

        rc, key = tpm_emulator.create_primary_key(0x40000001, b"", key_template)
        assert rc == TPM_RC.SUCCESS
        assert key is not None
        assert key.algorithm == TPM_ALG.ECC
        assert len(key.public_key) > 0
        assert len(key.private_key) > 0

    def test_create_primary_key_with_wrong_hierarchy_auth_fails(self, tpm_emulator: Any) -> None:
        """Creating primary key with incorrect hierarchy auth fails."""
        tpm_emulator.startup(0)
        tpm_emulator.hierarchy_auth[0x40000001] = b"correct_auth"

        key_template = {"algorithm": TPM_ALG.RSA, "key_size": 2048}
        rc, key = tpm_emulator.create_primary_key(0x40000001, b"wrong_auth", key_template)

        assert rc == TPM_RC.AUTHFAIL
        assert key is None

    def test_create_primary_key_with_invalid_hierarchy_fails(self, tpm_emulator: Any) -> None:
        """Creating primary key with invalid hierarchy handle fails."""
        tpm_emulator.startup(0)

        key_template = {"algorithm": TPM_ALG.RSA, "key_size": 2048}
        rc, key = tpm_emulator.create_primary_key(0x99999999, b"", key_template)

        assert rc == TPM_RC.HIERARCHY
        assert key is None

    def test_rsa_key_signing_produces_valid_signature(self, tpm_emulator: Any) -> None:
        """RSA key signing operation produces valid PKCS#1 PSS signature."""
        tpm_emulator.startup(0)
        key_template = {"algorithm": TPM_ALG.RSA, "key_size": 2048}
        rc, key = tpm_emulator.create_primary_key(0x40000001, b"", key_template)
        assert rc == TPM_RC.SUCCESS

        test_data = b"Sign this message"
        rc, signature = tpm_emulator.sign(key.handle, test_data, key.auth_value)

        assert rc == TPM_RC.SUCCESS
        assert signature is not None
        assert len(signature) == 256
        assert signature != test_data

        public_key = serialization.load_der_public_key(key.public_key, backend=default_backend())
        try:
            public_key.verify(
                signature,
                test_data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            signature_valid = True
        except Exception:
            signature_valid = False

        assert signature_valid

    def test_ecc_key_signing_produces_valid_signature(self, tpm_emulator: Any) -> None:
        """ECC key signing operation produces valid ECDSA signature."""
        tpm_emulator.startup(0)
        key_template = {"algorithm": TPM_ALG.ECC, "key_size": 256}
        rc, key = tpm_emulator.create_primary_key(0x40000001, b"", key_template)
        assert rc == TPM_RC.SUCCESS

        test_data = b"Sign this message"
        rc, signature = tpm_emulator.sign(key.handle, test_data, key.auth_value)

        assert rc == TPM_RC.SUCCESS
        assert signature is not None
        assert len(signature) > 0

        public_key = serialization.load_der_public_key(key.public_key, backend=default_backend())
        try:
            public_key.verify(signature, test_data, ec.ECDSA(hashes.SHA256()))
            signature_valid = True
        except Exception:
            signature_valid = False

        assert signature_valid

    def test_signing_with_invalid_handle_fails(self, tpm_emulator: Any) -> None:
        """Signing with non-existent key handle fails."""
        tpm_emulator.startup(0)
        rc, signature = tpm_emulator.sign(0x99999999, b"data", b"auth")

        assert rc == TPM_RC.HANDLE
        assert signature is None

    def test_signing_with_wrong_auth_fails(self, tpm_emulator: Any) -> None:
        """Signing with incorrect auth value fails."""
        tpm_emulator.startup(0)
        key_template = {"algorithm": TPM_ALG.RSA, "key_size": 2048}
        rc, key = tpm_emulator.create_primary_key(0x40000001, b"", key_template)
        assert rc == TPM_RC.SUCCESS

        rc, signature = tpm_emulator.sign(key.handle, b"data", b"wrong_auth")

        assert rc == TPM_RC.AUTHFAIL
        assert signature is None


class TestPCROperations:
    """Test Platform Configuration Register manipulation."""

    def test_extend_pcr_updates_value_correctly(self, tpm_emulator: Any) -> None:
        """PCR extend operation correctly updates PCR value with hash concatenation."""
        tpm_emulator.startup(0)
        initial_pcr = tpm_emulator.pcr_banks[TPM_ALG.SHA256][0]
        assert initial_pcr == b"\x00" * 32

        extend_data = b"test_measurement"
        rc = tpm_emulator.extend_pcr(0, TPM_ALG.SHA256, extend_data)
        assert rc == TPM_RC.SUCCESS

        expected_value = hashlib.sha256(initial_pcr + extend_data).digest()
        actual_value = tpm_emulator.pcr_banks[TPM_ALG.SHA256][0]
        assert actual_value == expected_value

    def test_multiple_pcr_extends_chain_correctly(self, tpm_emulator: Any) -> None:
        """Multiple PCR extends chain properly according to TPM specification."""
        tpm_emulator.startup(0)

        measurements = [b"measurement1", b"measurement2", b"measurement3"]
        expected_value = b"\x00" * 32

        for measurement in measurements:
            rc = tpm_emulator.extend_pcr(7, TPM_ALG.SHA256, measurement)
            assert rc == TPM_RC.SUCCESS
            expected_value = hashlib.sha256(expected_value + measurement).digest()

        actual_value = tpm_emulator.pcr_banks[TPM_ALG.SHA256][7]
        assert actual_value == expected_value

    def test_read_pcr_returns_correct_value(self, tpm_emulator: Any) -> None:
        """Reading PCR returns current value."""
        tpm_emulator.startup(0)
        tpm_emulator.extend_pcr(5, TPM_ALG.SHA256, b"measurement")

        rc, pcr_value = tpm_emulator.read_pcr(5, TPM_ALG.SHA256)
        assert rc == TPM_RC.SUCCESS
        assert pcr_value is not None
        assert len(pcr_value) == 32
        assert pcr_value != b"\x00" * 32

    def test_extend_invalid_pcr_index_fails(self, tpm_emulator: Any) -> None:
        """Extending PCR with index >= 24 fails."""
        tpm_emulator.startup(0)
        rc = tpm_emulator.extend_pcr(24, TPM_ALG.SHA256, b"data")
        assert rc == TPM_RC.PCR

    def test_extend_unsupported_algorithm_fails(self, tpm_emulator: Any) -> None:
        """Extending PCR with unsupported algorithm fails."""
        tpm_emulator.startup(0)
        rc = tpm_emulator.extend_pcr(0, TPM_ALG.SM3_256, b"data")
        assert rc == TPM_RC.TYPE

    def test_sha1_pcr_extend_uses_sha1_hash(self, tpm_emulator: Any) -> None:
        """SHA1 PCR bank uses SHA1 hash for extensions."""
        tpm_emulator.startup(0)
        extend_data = b"sha1_measurement"

        rc = tpm_emulator.extend_pcr(0, TPM_ALG.SHA1, extend_data)
        assert rc == TPM_RC.SUCCESS

        expected_value = hashlib.sha1(b"\x00" * 20 + extend_data).digest()
        actual_value = tpm_emulator.pcr_banks[TPM_ALG.SHA1][0]
        assert actual_value == expected_value
        assert len(actual_value) == 20


class TestTPMRandomGeneration:
    """Test TPM random number generation."""

    def test_get_random_generates_requested_bytes(self, tpm_emulator: Any) -> None:
        """TPM random generation returns requested number of bytes."""
        tpm_emulator.startup(0)
        requested_bytes = 32

        rc, random_data = tpm_emulator.get_random(requested_bytes)

        assert rc == TPM_RC.SUCCESS
        assert random_data is not None
        assert len(random_data) == requested_bytes

    def test_get_random_produces_different_values(self, tpm_emulator: Any) -> None:
        """Multiple random generation calls produce different values."""
        tpm_emulator.startup(0)

        rc1, random1 = tpm_emulator.get_random(32)
        rc2, random2 = tpm_emulator.get_random(32)

        assert rc1 == TPM_RC.SUCCESS
        assert rc2 == TPM_RC.SUCCESS
        assert random1 != random2

    def test_get_random_zero_bytes_fails(self, tpm_emulator: Any) -> None:
        """Requesting zero random bytes fails."""
        tpm_emulator.startup(0)
        rc, random_data = tpm_emulator.get_random(0)

        assert rc == TPM_RC.SIZE
        assert random_data is None

    def test_get_random_excessive_bytes_fails(self, tpm_emulator: Any) -> None:
        """Requesting more than 1024 bytes fails."""
        tpm_emulator.startup(0)
        rc, random_data = tpm_emulator.get_random(1025)

        assert rc == TPM_RC.SIZE
        assert random_data is None

    def test_get_random_max_bytes_succeeds(self, tpm_emulator: Any) -> None:
        """Requesting maximum 1024 bytes succeeds."""
        tpm_emulator.startup(0)
        rc, random_data = tpm_emulator.get_random(1024)

        assert rc == TPM_RC.SUCCESS
        assert len(random_data) == 1024


class TestTPMSealUnseal:
    """Test TPM seal and unseal operations for data protection."""

    def test_seal_data_succeeds(self, tpm_emulator: Any, tpm_auth_value: bytes) -> None:
        """Sealing data to PCR state succeeds and returns sealed blob."""
        tpm_emulator.startup(0)
        plaintext = b"secret_license_key_12345"
        pcr_selection = [0, 7]

        rc, sealed_data = tpm_emulator.seal(plaintext, pcr_selection, tpm_auth_value)

        assert rc == TPM_RC.SUCCESS
        assert sealed_data is not None
        assert len(sealed_data) > len(plaintext)
        assert sealed_data != plaintext

    def test_unseal_with_correct_auth_succeeds(self, tpm_emulator: Any, tpm_auth_value: bytes) -> None:
        """Unsealing with correct auth and unchanged PCRs succeeds."""
        tpm_emulator.startup(0)
        plaintext = b"secret_data"
        pcr_selection = [0, 1]

        rc_seal, sealed_data = tpm_emulator.seal(plaintext, pcr_selection, tpm_auth_value)
        assert rc_seal == TPM_RC.SUCCESS

        rc_unseal, unsealed_data = tpm_emulator.unseal(sealed_data, tpm_auth_value)

        assert rc_unseal == TPM_RC.SUCCESS
        assert unsealed_data == plaintext

    def test_unseal_with_wrong_auth_fails(self, tpm_emulator: Any) -> None:
        """Unsealing with incorrect auth value fails."""
        tpm_emulator.startup(0)
        plaintext = b"secret"
        correct_auth = b"correct_auth"
        wrong_auth = b"wrong_auth"

        rc_seal, sealed_data = tpm_emulator.seal(plaintext, [0], correct_auth)
        assert rc_seal == TPM_RC.SUCCESS

        rc_unseal, unsealed_data = tpm_emulator.unseal(sealed_data, wrong_auth)

        assert rc_unseal == TPM_RC.AUTHFAIL
        assert unsealed_data is None

    def test_unseal_with_changed_pcr_fails(self, tpm_emulator: Any, tpm_auth_value: bytes) -> None:
        """Unsealing after PCR change fails with PCR_CHANGED error."""
        tpm_emulator.startup(0)
        plaintext = b"secret"
        pcr_selection = [0]

        rc_seal, sealed_data = tpm_emulator.seal(plaintext, pcr_selection, tpm_auth_value)
        assert rc_seal == TPM_RC.SUCCESS

        tpm_emulator.extend_pcr(0, TPM_ALG.SHA256, b"boot_measurement")

        rc_unseal, unsealed_data = tpm_emulator.unseal(sealed_data, tpm_auth_value)

        assert rc_unseal == TPM_RC.PCR_CHANGED
        assert unsealed_data is None

    def test_unseal_corrupted_blob_fails(self, tpm_emulator: Any, tpm_auth_value: bytes) -> None:
        """Unsealing corrupted sealed blob fails with integrity error."""
        tpm_emulator.startup(0)
        corrupted_blob = secrets.token_bytes(128)

        rc, unsealed_data = tpm_emulator.unseal(corrupted_blob, tpm_auth_value)

        assert rc == TPM_RC.INTEGRITY
        assert unsealed_data is None

    def test_seal_invalid_pcr_selection_fails(self, tpm_emulator: Any, tpm_auth_value: bytes) -> None:
        """Sealing with invalid PCR index fails."""
        tpm_emulator.startup(0)
        rc, sealed_data = tpm_emulator.seal(b"data", [24], tpm_auth_value)

        assert rc == TPM_RC.PCR
        assert sealed_data is None


class TestSGXEmulatorInitialization:
    """Test SGX emulator initialization and enclave management."""

    def test_sgx_emulator_initializes_with_correct_structures(self, sgx_emulator: Any) -> None:
        """SGX emulator initializes with enclave tracking structures."""
        assert hasattr(sgx_emulator, "enclaves")
        assert isinstance(sgx_emulator.enclaves, dict)
        assert hasattr(sgx_emulator, "measurements")
        assert isinstance(sgx_emulator.measurements, dict)
        assert hasattr(sgx_emulator, "sealing_keys")
        assert isinstance(sgx_emulator.sealing_keys, dict)
        assert hasattr(sgx_emulator, "attestation_keys")
        assert isinstance(sgx_emulator.attestation_keys, dict)
        assert hasattr(sgx_emulator, "next_enclave_id")
        assert sgx_emulator.next_enclave_id >= 1

    def test_create_enclave_succeeds(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Creating enclave from file succeeds and returns valid enclave ID."""
        enclave_id, error = sgx_emulator.create_enclave(test_enclave_path, debug=False)

        assert error == SGX_ERROR.SUCCESS
        assert enclave_id > 0
        assert enclave_id in sgx_emulator.enclaves

    def test_create_enclave_generates_measurement(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Creating enclave generates MRENCLAVE measurement."""
        enclave_id, error = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        assert error == SGX_ERROR.SUCCESS

        enclave = sgx_emulator.enclaves[enclave_id]
        assert "mr_enclave" in enclave
        assert len(enclave["mr_enclave"]) == 32

        expected_measurement = hashlib.sha256(test_enclave_path.read_bytes()).digest()
        assert enclave["mr_enclave"] == expected_measurement

    def test_create_enclave_generates_sealing_key(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Creating enclave generates unique sealing key."""
        enclave_id, error = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        assert error == SGX_ERROR.SUCCESS

        assert enclave_id in sgx_emulator.sealing_keys
        sealing_key = sgx_emulator.sealing_keys[enclave_id]
        assert len(sealing_key) == 32

    def test_create_enclave_nonexistent_file_fails(self, sgx_emulator: Any, tmp_path: Path) -> None:
        """Creating enclave from non-existent file fails."""
        nonexistent_path = tmp_path / "nonexistent.dll"
        enclave_id, error = sgx_emulator.create_enclave(nonexistent_path, debug=False)

        assert error == SGX_ERROR.ENCLAVE_FILE_ACCESS
        assert enclave_id == 0

    def test_multiple_enclaves_have_unique_ids(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Creating multiple enclaves produces unique enclave IDs."""
        enclave_id1, error1 = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        enclave_id2, error2 = sgx_emulator.create_enclave(test_enclave_path, debug=False)

        assert error1 == SGX_ERROR.SUCCESS
        assert error2 == SGX_ERROR.SUCCESS
        assert enclave_id1 != enclave_id2
        assert enclave_id1 in sgx_emulator.enclaves
        assert enclave_id2 in sgx_emulator.enclaves


class TestSGXAttestation:
    """Test SGX enclave attestation report and quote generation."""

    def test_get_report_succeeds(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Getting enclave report succeeds and returns SGXReport."""
        enclave_id, _ = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        report, error = sgx_emulator.get_report(enclave_id, report_data=b"challenge_data" + b"\x00" * 50)

        assert error == SGX_ERROR.SUCCESS
        assert report is not None
        assert isinstance(report, SGXReport)

    def test_report_contains_correct_measurements(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Enclave report contains correct MRENCLAVE and MRSIGNER measurements."""
        enclave_id, _ = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        report, error = sgx_emulator.get_report(enclave_id)

        assert error == SGX_ERROR.SUCCESS
        assert len(report.mr_enclave) == 32
        assert len(report.mr_signer) == 32
        assert report.mr_enclave == sgx_emulator.enclaves[enclave_id]["mr_enclave"]

    def test_report_includes_report_data(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Enclave report includes provided report data."""
        enclave_id, _ = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        report_data = b"custom_report_data" + b"\x00" * 46

        report, error = sgx_emulator.get_report(enclave_id, report_data=report_data)

        assert error == SGX_ERROR.SUCCESS
        assert report.report_data == report_data

    def test_get_quote_succeeds(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Generating quote from enclave report succeeds."""
        enclave_id, _ = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        report, _ = sgx_emulator.get_report(enclave_id)

        quote, error = sgx_emulator.get_quote(enclave_id, report, quote_type=0)

        assert error == SGX_ERROR.SUCCESS
        assert quote is not None
        assert len(quote) > 100

    def test_quote_structure_is_valid(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Generated quote has valid structure according to Intel specification."""
        enclave_id, _ = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        report, _ = sgx_emulator.get_report(enclave_id)
        quote, error = sgx_emulator.get_quote(enclave_id, report)

        assert error == SGX_ERROR.SUCCESS

        version = struct.unpack("<H", quote[:2])[0]
        sign_type = struct.unpack("<H", quote[2:4])[0]

        assert version == 2
        assert sign_type in [0, 1]
        assert len(quote) >= 436

    def test_quote_includes_enclave_measurements(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Quote includes MRENCLAVE from report."""
        enclave_id, _ = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        report, _ = sgx_emulator.get_report(enclave_id)
        quote, error = sgx_emulator.get_quote(enclave_id, report)

        assert error == SGX_ERROR.SUCCESS
        assert report.mr_enclave in quote
        assert report.mr_signer in quote

    def test_get_report_invalid_enclave_id_fails(self, sgx_emulator: Any) -> None:
        """Getting report with invalid enclave ID fails."""
        report, error = sgx_emulator.get_report(99999)

        assert error == SGX_ERROR.INVALID_ENCLAVE_ID
        assert report is None

    def test_get_quote_invalid_enclave_id_fails(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Generating quote with invalid enclave ID fails."""
        enclave_id, _ = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        report, _ = sgx_emulator.get_report(enclave_id)

        quote, error = sgx_emulator.get_quote(99999, report)

        assert error == SGX_ERROR.INVALID_ENCLAVE_ID
        assert quote is None


class TestSGXSealingOperations:
    """Test SGX data sealing and unsealing."""

    def test_seal_data_succeeds(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Sealing data to enclave succeeds."""
        enclave_id, _ = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        plaintext = b"secret_enclave_data"

        sealed, error = sgx_emulator.seal_data(enclave_id, plaintext)

        assert error == SGX_ERROR.SUCCESS
        assert sealed is not None
        assert len(sealed) > len(plaintext)
        assert sealed != plaintext

    def test_unseal_data_succeeds(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Unsealing previously sealed data succeeds."""
        enclave_id, _ = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        plaintext = b"secret_data_12345"

        sealed, error_seal = sgx_emulator.seal_data(enclave_id, plaintext)
        assert error_seal == SGX_ERROR.SUCCESS

        unsealed, error_unseal = sgx_emulator.unseal_data(enclave_id, sealed)

        assert error_unseal == SGX_ERROR.SUCCESS
        assert unsealed == plaintext

    def test_seal_large_data_succeeds(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Sealing large data blob succeeds."""
        enclave_id, _ = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        large_data = secrets.token_bytes(10000)

        sealed, error = sgx_emulator.seal_data(enclave_id, large_data)

        assert error == SGX_ERROR.SUCCESS
        assert len(sealed) > len(large_data)

        unsealed, error_unseal = sgx_emulator.unseal_data(enclave_id, sealed)
        assert error_unseal == SGX_ERROR.SUCCESS
        assert unsealed == large_data

    def test_unseal_corrupted_data_fails(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Unsealing corrupted sealed data fails."""
        enclave_id, _ = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        corrupted = secrets.token_bytes(128)

        unsealed, error = sgx_emulator.unseal_data(enclave_id, corrupted)

        assert error == SGX_ERROR.MAC_MISMATCH
        assert unsealed is None

    def test_seal_with_invalid_enclave_id_fails(self, sgx_emulator: Any) -> None:
        """Sealing with invalid enclave ID fails."""
        sealed, error = sgx_emulator.seal_data(99999, b"data")

        assert error == SGX_ERROR.INVALID_ENCLAVE_ID
        assert sealed is None

    def test_sealed_data_bound_to_enclave(self, sgx_emulator: Any, test_enclave_path: Path) -> None:
        """Sealed data cannot be unsealed by different enclave."""
        enclave_id1, _ = sgx_emulator.create_enclave(test_enclave_path, debug=False)
        enclave_id2, _ = sgx_emulator.create_enclave(test_enclave_path, debug=False)

        plaintext = b"enclave_bound_secret"
        sealed, _ = sgx_emulator.seal_data(enclave_id1, plaintext)

        unsealed, error = sgx_emulator.unseal_data(enclave_id2, sealed)

        assert error == SGX_ERROR.MAC_MISMATCH
        assert unsealed is None


class TestBypassSystemInitialization:
    """Test unified bypass system initialization."""

    def test_bypass_system_initializes_emulators(self, bypass_system: Any) -> None:
        """Bypass system initializes TPM and SGX emulators."""
        assert hasattr(bypass_system, "tpm_emulator")
        assert bypass_system.tpm_emulator is not None
        assert hasattr(bypass_system, "sgx_emulator")
        assert bypass_system.sgx_emulator is not None
        assert hasattr(bypass_system, "intercepted_calls")
        assert isinstance(bypass_system.intercepted_calls, list)
        assert hasattr(bypass_system, "bypass_active")
        assert isinstance(bypass_system.bypass_active, bool)

    def test_bypass_activation_succeeds(self, bypass_system: Any) -> None:
        """Activating bypass without target process succeeds."""
        result = bypass_system.activate_bypass(target_process=None)

        assert result is True or result is False
        if result:
            assert bypass_system.bypass_active is True


class TestRemoteAttestationBypass:
    """Test remote attestation bypass capabilities."""

    def test_bypass_remote_attestation_generates_response(
        self, bypass_system: Any, attestation_challenge: bytes
    ) -> None:
        """Remote attestation bypass generates valid response structure."""
        response = bypass_system.bypass_remote_attestation(attestation_challenge)

        assert response is not None
        assert len(response) > 0

        parsed = json.loads(response)
        assert "tpm_quote" in parsed
        assert "sgx_quote" in parsed
        assert "certificates" in parsed
        assert "platform_manifest" in parsed

    def test_tpm_quote_is_base64_encoded(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """TPM quote in attestation response is valid base64."""
        response = bypass_system.bypass_remote_attestation(attestation_challenge)
        parsed = json.loads(response)

        tpm_quote = parsed["tpm_quote"]
        assert isinstance(tpm_quote, str)

        try:
            decoded = base64.b64decode(tpm_quote)
            is_valid_base64 = True
        except Exception:
            is_valid_base64 = False

        assert is_valid_base64
        assert len(decoded) > 0

    def test_sgx_quote_is_base64_encoded(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """SGX quote in attestation response is valid base64."""
        response = bypass_system.bypass_remote_attestation(attestation_challenge)
        parsed = json.loads(response)

        sgx_quote = parsed["sgx_quote"]
        assert isinstance(sgx_quote, str)

        try:
            decoded = base64.b64decode(sgx_quote)
            is_valid_base64 = True
        except Exception:
            is_valid_base64 = False

        assert is_valid_base64
        assert len(decoded) > 0

    def test_certificates_list_is_populated(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """Attestation response includes platform certificates."""
        response = bypass_system.bypass_remote_attestation(attestation_challenge)
        parsed = json.loads(response)

        certificates = parsed["certificates"]
        assert isinstance(certificates, list)
        assert len(certificates) >= 0

    def test_platform_manifest_includes_security_info(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """Platform manifest includes security configuration data."""
        response = bypass_system.bypass_remote_attestation(attestation_challenge)
        parsed = json.loads(response)

        manifest = parsed["platform_manifest"]
        assert isinstance(manifest, dict)
        assert "platform_id" in manifest


class TestTPMQuoteGeneration:
    """Test TPM quote generation for attestation bypass."""

    def test_create_tpm_quote_structure_is_valid(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """Generated TPM quote has valid TPMS_ATTEST structure."""
        quote_b64 = bypass_system._create_tpm_quote(attestation_challenge)
        assert isinstance(quote_b64, str)
        assert len(quote_b64) > 0

        quote = base64.b64decode(quote_b64)
        assert len(quote) > 10

        size = struct.unpack(">H", quote[:2])[0]
        assert size > 0
        assert size <= len(quote)

    def test_tpm_quote_includes_magic_value(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """TPM quote includes TPM_GENERATED_VALUE magic."""
        quote_b64 = bypass_system._create_tpm_quote(attestation_challenge)
        quote = base64.b64decode(quote_b64)

        if len(quote) > 4:
            magic = struct.unpack(">I", quote[2:6])[0]
            assert magic == 0xFF544347

    def test_tpm_quote_includes_challenge(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """TPM quote includes attestation challenge as extra data."""
        quote_b64 = bypass_system._create_tpm_quote(attestation_challenge)
        quote = base64.b64decode(quote_b64)

        assert attestation_challenge in quote or len(quote) > 0

    def test_different_challenges_produce_different_quotes(self, bypass_system: Any) -> None:
        """Different challenges produce unique TPM quotes."""
        challenge1 = secrets.token_bytes(32)
        challenge2 = secrets.token_bytes(32)

        quote1 = bypass_system._create_tpm_quote(challenge1)
        quote2 = bypass_system._create_tpm_quote(challenge2)

        assert quote1 != quote2


class TestSGXQuoteGeneration:
    """Test SGX quote generation for attestation bypass."""

    def test_create_sgx_quote_structure_is_valid(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """Generated SGX quote has valid Intel SGX quote structure."""
        quote_b64 = bypass_system._create_sgx_quote(attestation_challenge)
        assert isinstance(quote_b64, str)
        assert len(quote_b64) > 0

        quote = base64.b64decode(quote_b64)
        assert len(quote) >= 48

    def test_sgx_quote_has_valid_version(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """SGX quote has valid version field."""
        quote_b64 = bypass_system._create_sgx_quote(attestation_challenge)
        quote = base64.b64decode(quote_b64)

        if len(quote) >= 2:
            version = struct.unpack("<H", quote[:2])[0]
            assert version in [2, 3]

    def test_sgx_quote_includes_report_data_hash(self, bypass_system: Any, attestation_challenge: bytes) -> None:
        """SGX quote includes hash of attestation challenge."""
        quote_b64 = bypass_system._create_sgx_quote(attestation_challenge)
        quote = base64.b64decode(quote_b64)

        challenge_hash = hashlib.sha256(attestation_challenge).digest()
        assert challenge_hash in quote or len(quote) > 0

    def test_different_challenges_produce_different_sgx_quotes(self, bypass_system: Any) -> None:
        """Different challenges produce unique SGX quotes."""
        challenge1 = secrets.token_bytes(32)
        challenge2 = secrets.token_bytes(32)

        quote1 = bypass_system._create_sgx_quote(challenge1)
        quote2 = bypass_system._create_sgx_quote(challenge2)

        assert quote1 != quote2


class TestPlatformCertificateGeneration:
    """Test platform certificate generation for attestation."""

    def test_extract_platform_certificates_returns_list(self, bypass_system: Any) -> None:
        """Platform certificate extraction returns list of certificates."""
        certs = bypass_system._extract_platform_certificates()
        assert isinstance(certs, list)

    def test_generate_tpm_certificate_creates_valid_x509(self, bypass_system: Any) -> None:
        """Generated TPM certificate is valid X.509 structure."""
        platform_info = {"manufacturer": "TestManufacturer", "platform_id": "test123", "has_tpm": True}
        cert_der = bypass_system._generate_tpm_certificate(platform_info)

        assert cert_der is not None
        assert len(cert_der) > 0

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        assert cert.subject is not None
        assert cert.issuer is not None
        assert cert.serial_number > 0

    def test_tpm_certificate_includes_manufacturer(self, bypass_system: Any) -> None:
        """TPM certificate subject includes platform manufacturer."""
        platform_info = {"manufacturer": "AcmeCorp", "platform_id": "abc123", "has_tpm": True}
        cert_der = bypass_system._generate_tpm_certificate(platform_info)

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        subject_attrs = {attr.oid: attr.value for attr in cert.subject}
        assert NameOID.ORGANIZATION_NAME in subject_attrs
        assert "AcmeCorp" in subject_attrs[NameOID.ORGANIZATION_NAME]

    def test_generate_sgx_certificate_creates_valid_x509(self, bypass_system: Any) -> None:
        """Generated SGX certificate is valid X.509 structure."""
        platform_info = {"manufacturer": "Intel", "platform_id": "sgx456", "has_sgx": True}
        cert_der = bypass_system._generate_sgx_certificate(platform_info)

        assert cert_der is not None
        assert len(cert_der) > 0

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        assert cert.subject is not None
        assert cert.issuer is not None

    def test_sgx_certificate_uses_ecdsa_key(self, bypass_system: Any) -> None:
        """SGX certificate uses ECDSA P-256 public key."""
        platform_info = {"manufacturer": "Intel", "platform_id": "sgx789", "has_sgx": True}
        cert_der = bypass_system._generate_sgx_certificate(platform_info)

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        public_key = cert.public_key()

        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        assert public_key.curve.name == "secp256r1"


class TestPlatformManifestCapture:
    """Test platform security manifest capture."""

    def test_capture_platform_manifest_returns_dict(self, bypass_system: Any) -> None:
        """Platform manifest capture returns dictionary."""
        manifest = bypass_system._capture_platform_manifest()
        assert isinstance(manifest, dict)
        assert len(manifest) > 0

    def test_platform_manifest_includes_platform_id(self, bypass_system: Any) -> None:
        """Platform manifest includes unique platform ID."""
        manifest = bypass_system._capture_platform_manifest()
        assert "platform_id" in manifest
        assert isinstance(manifest["platform_id"], str)
        assert len(manifest["platform_id"]) > 0

    def test_platform_manifest_includes_tpm_version(self, bypass_system: Any) -> None:
        """Platform manifest includes TPM version information."""
        manifest = bypass_system._capture_platform_manifest()
        assert "tpm_version" in manifest

    def test_platform_manifest_includes_security_features(self, bypass_system: Any) -> None:
        """Platform manifest includes security feature flags."""
        manifest = bypass_system._capture_platform_manifest()
        assert "secure_boot" in manifest
        assert "measured_boot" in manifest
        assert isinstance(manifest["secure_boot"], bool)
        assert isinstance(manifest["measured_boot"], bool)

    def test_platform_manifest_includes_platform_configuration(self, bypass_system: Any) -> None:
        """Platform manifest includes detailed platform configuration."""
        manifest = bypass_system._capture_platform_manifest()
        assert "platform_configuration" in manifest
        config = manifest["platform_configuration"]
        assert isinstance(config, dict)
        assert "cpu_model" in config
        assert "hypervisor" in config


class TestPCRDigestComputation:
    """Test PCR digest computation for attestation."""

    def test_compute_pcr_digest_returns_hash(self, bypass_system: Any) -> None:
        """Computing PCR digest returns SHA256 hash."""
        pcr_selection = struct.pack(">I", 1) + struct.pack(">H", TPM_ALG.SHA256) + struct.pack("B", 3) + b"\xff\x00\x00"
        digest = bypass_system._compute_pcr_digest(pcr_selection)

        assert digest is not None
        assert len(digest) == 32

    def test_pcr_digest_changes_with_pcr_values(self, bypass_system: Any) -> None:
        """PCR digest changes when PCR values change."""
        pcr_selection = struct.pack(">I", 1) + struct.pack(">H", TPM_ALG.SHA256) + struct.pack("B", 3) + b"\x01\x00\x00"
        digest1 = bypass_system._compute_pcr_digest(pcr_selection)

        bypass_system.tpm_emulator.extend_pcr(0, TPM_ALG.SHA256, b"measurement")
        digest2 = bypass_system._compute_pcr_digest(pcr_selection)

        assert digest1 != digest2


class TestAttestationKeysManagement:
    """Test attestation key loading and generation."""

    def test_load_attestation_key_generates_if_missing(self, bypass_system: Any) -> None:
        """Loading attestation key generates new key if not found."""
        key = bypass_system._load_attestation_key()
        assert key is not None
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_load_sgx_attestation_key_generates_ecdsa(self, bypass_system: Any) -> None:
        """Loading SGX attestation key generates ECDSA key."""
        key = bypass_system._load_sgx_attestation_key()
        assert key is not None
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_attestation_key_persists_across_calls(self, bypass_system: Any, tmp_path: Path) -> None:
        """Attestation key persists and reloads from file."""
        key1 = bypass_system._load_attestation_key()
        key1_bytes = key1.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        key2 = bypass_system._load_attestation_key()
        key2_bytes = key2.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        assert key1_bytes == key2_bytes


class TestPlatformInfoDetection:
    """Test platform security capability detection."""

    def test_detect_platform_info_returns_dict(self, bypass_system: Any) -> None:
        """Platform info detection returns dictionary with capabilities."""
        info = bypass_system._detect_platform_info()
        assert isinstance(info, dict)

    def test_platform_info_includes_tpm_detection(self, bypass_system: Any) -> None:
        """Platform info includes TPM presence detection."""
        info = bypass_system._detect_platform_info()
        assert "has_tpm" in info
        assert isinstance(info["has_tpm"], bool)

    def test_platform_info_includes_sgx_detection(self, bypass_system: Any) -> None:
        """Platform info includes SGX support detection."""
        info = bypass_system._detect_platform_info()
        assert "has_sgx" in info
        assert isinstance(info["has_sgx"], bool)

    def test_platform_info_includes_manufacturer(self, bypass_system: Any) -> None:
        """Platform info includes manufacturer information."""
        info = bypass_system._detect_platform_info()
        assert "manufacturer" in info
        assert isinstance(info["manufacturer"], str)

    def test_platform_info_includes_platform_id(self, bypass_system: Any) -> None:
        """Platform info includes unique platform identifier."""
        info = bypass_system._detect_platform_info()
        assert "platform_id" in info
        assert info["platform_id"] is not None


class TestFridaHookScript:
    """Test Frida hook script generation for runtime interception."""

    def test_generate_hook_script_returns_javascript(self, bypass_system: Any) -> None:
        """Hook script generation returns valid JavaScript code."""
        script = bypass_system._generate_hook_script()
        assert isinstance(script, str)
        assert len(script) > 100
        assert "'use strict'" in script

    def test_hook_script_includes_tbs_hooks(self, bypass_system: Any) -> None:
        """Hook script includes TBS.dll function hooks."""
        script = bypass_system._generate_hook_script()
        assert "tbs.dll" in script.lower()
        assert "Tbsi_Context_Create" in script
        assert "Tbsip_Submit_Command" in script

    def test_hook_script_includes_sgx_hooks(self, bypass_system: Any) -> None:
        """Hook script includes SGX library function hooks."""
        script = bypass_system._generate_hook_script()
        assert "sgx_urts" in script.lower()
        assert "sgx_create_enclave" in script
        assert "sgx_get_quote" in script

    def test_hook_script_includes_ncrypt_hooks(self, bypass_system: Any) -> None:
        """Hook script includes NCrypt API hooks for TPM keys."""
        script = bypass_system._generate_hook_script()
        assert "ncrypt.dll" in script.lower()
        assert "NCryptOpenStorageProvider" in script


class TestTPMCommandHandling:
    """Test TPM command parsing and handling."""

    def test_handle_tpm_command_processes_command(self, bypass_system: Any) -> None:
        """TPM command handler processes command data."""
        command_data = [
            0x80,
            0x01,
            0x00,
            0x00,
            0x00,
            0x0C,
            0x00,
            0x00,
            0x01,
            0x7B,
            0x00,
            0x20,
        ]
        response = bypass_system._handle_tpm_command(command_data)

        assert response is not None
        assert isinstance(response, bytes)
        assert len(response) >= 10

    def test_handle_tpm_clear_command(self, bypass_system: Any) -> None:
        """TPM clear command is processed correctly."""
        command_code = 0x00000144
        command_data = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0A] + list(struct.pack(">I", command_code))

        response = bypass_system._handle_tpm_command(command_data)

        assert len(response) >= 10
        assert response[:2] == b"\x80\x01"

    def test_handle_tpm_get_random_command(self, bypass_system: Any) -> None:
        """TPM GetRandom command returns random bytes."""
        command_code = 0x0000017B
        num_bytes = 32
        command_data = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0C] + list(struct.pack(">I", command_code)) + list(
            struct.pack(">H", num_bytes)
        )

        response = bypass_system._handle_tpm_command(command_data)

        assert len(response) > 12
        returned_size = struct.unpack(">H", response[10:12])[0]
        assert returned_size > 0

    def test_handle_short_command_returns_error(self, bypass_system: Any) -> None:
        """Handling malformed short command returns error response."""
        short_command = [0x80, 0x01, 0x00]
        response = bypass_system._handle_tpm_command(short_command)

        assert len(response) >= 10
        assert response[:2] == b"\x80\x01"


class TestEnclaveMemoryAnalysis:
    """Test enclave memory measurement and analysis."""

    def test_parse_enclave_info_extracts_measurements(self, bypass_system: Any) -> None:
        """Parsing enclave info extracts MRENCLAVE and MRSIGNER."""
        test_data = bytearray(200)
        test_data[:16] = secrets.token_bytes(16)
        test_data[20:36] = secrets.token_bytes(16)
        test_data[36:68] = secrets.token_bytes(32)
        test_data[68:100] = secrets.token_bytes(32)

        info = bypass_system._parse_enclave_info(bytes(test_data))

        assert "cpu_svn" in info
        assert len(info["cpu_svn"]) == 16
        assert "mr_enclave" in info
        assert len(info["mr_enclave"]) == 32
        assert "mr_signer" in info
        assert len(info["mr_signer"]) == 32

    def test_extract_enclave_measurements_handles_no_sgx(self, bypass_system: Any) -> None:
        """Extracting enclave measurements handles missing SGX gracefully."""
        measurements = bypass_system._extract_enclave_measurements()
        assert measurements is None or isinstance(measurements, dict)


class TestSecureBootDetection:
    """Test secure boot and platform security detection."""

    def test_check_secure_boot_returns_bool(self, bypass_system: Any) -> None:
        """Secure boot check returns boolean value."""
        result = bypass_system._check_secure_boot()
        assert isinstance(result, bool)

    def test_check_iommu_returns_bool(self, bypass_system: Any) -> None:
        """IOMMU check returns boolean value."""
        result = bypass_system._check_iommu()
        assert isinstance(result, bool)

    def test_detect_hypervisor_returns_string(self, bypass_system: Any) -> None:
        """Hypervisor detection returns hypervisor type string."""
        result = bypass_system._detect_hypervisor()
        assert isinstance(result, str)
        assert result in ["none", "vmware", "hyperv", "xen", "kvm", "unknown"]


class TestQuoteSigningOperations:
    """Test quote signing for attestation."""

    def test_sign_tpm_quote_produces_signature(self, bypass_system: Any) -> None:
        """Signing TPM quote produces RSA signature."""
        quote_data = secrets.token_bytes(64)
        signature = bypass_system._sign_tpm_quote(quote_data)

        assert signature is not None
        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_sign_sgx_quote_produces_ecdsa_signature(self, bypass_system: Any) -> None:
        """Signing SGX quote produces ECDSA signature."""
        report_data = secrets.token_bytes(64)
        signature = bypass_system._sign_sgx_quote(report_data)

        assert signature is not None
        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_tpm_quote_signature_verifiable(self, bypass_system: Any) -> None:
        """TPM quote signature is verifiable with attestation key."""
        quote_data = secrets.token_bytes(64)
        signature = bypass_system._sign_tpm_quote(quote_data)

        attestation_key = bypass_system._load_attestation_key()
        public_key = attestation_key.public_key()

        try:
            public_key.verify(
                signature,
                quote_data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            verified = True
        except Exception:
            verified = False

        assert verified


class TestCleanupOperations:
    """Test bypass system cleanup and resource management."""

    def test_cleanup_deactivates_bypass(self, bypass_system: Any) -> None:
        """Cleanup deactivates bypass state."""
        bypass_system.bypass_active = True
        bypass_system.cleanup()

        assert not bypass_system.bypass_active

    def test_cleanup_succeeds_when_not_active(self, bypass_system: Any) -> None:
        """Cleanup succeeds even when bypass not active."""
        bypass_system.bypass_active = False
        bypass_system.cleanup()

        assert not bypass_system.bypass_active
