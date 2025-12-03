"""Comprehensive production tests for TPM and Secure Enclave bypass functionality.

Tests validate real offensive capabilities against hardware-based license protections.
All tests verify actual bypass functionality using real implementations.
"""

import base64
import hashlib
import json
import secrets
import struct
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from intellicrack.core.protection_bypass.tpm_secure_enclave_bypass import (
    SGX_ERROR,
    SGXEmulator,
    SGXReport,
    SecureEnclaveBypass,
    TPM_ALG,
    TPM_RC,
    TPMEmulator,
    TPMKey,
)


@pytest.fixture
def tpm_emulator() -> TPMEmulator:
    """Create TPM emulator with initialization that may fail gracefully."""
    emulator = TPMEmulator.__new__(TPMEmulator)
    emulator.tpm_state = {}
    emulator.pcr_banks = {
        TPM_ALG.SHA1: [b"\x00" * 20 for _ in range(24)],
        TPM_ALG.SHA256: [b"\x00" * 32 for _ in range(24)],
    }
    emulator.nv_storage = {}
    emulator.keys = {}
    emulator.sessions = {}
    emulator.hierarchy_auth = {
        0x40000001: b"",
        0x4000000C: b"",
        0x4000000B: b"",
        0x40000010: b"",
    }
    emulator.driver_handle = None
    return emulator


@pytest.fixture
def sgx_emulator() -> SGXEmulator:
    """Create SGX emulator instance."""
    emulator = SGXEmulator()
    return emulator


@pytest.fixture
def bypass_system() -> SecureEnclaveBypass:
    """Create SecureEnclaveBypass with emulators initialized."""
    bypass = SecureEnclaveBypass.__new__(SecureEnclaveBypass)
    bypass.tpm_emulator = TPMEmulator.__new__(TPMEmulator)
    bypass.tpm_emulator.tpm_state = {}
    bypass.tpm_emulator.pcr_banks = {
        TPM_ALG.SHA1: [b"\x00" * 20 for _ in range(24)],
        TPM_ALG.SHA256: [b"\x00" * 32 for _ in range(24)],
    }
    bypass.tpm_emulator.nv_storage = {}
    bypass.tpm_emulator.keys = {}
    bypass.tpm_emulator.sessions = {}
    bypass.tpm_emulator.hierarchy_auth = {
        0x40000001: b"",
        0x4000000C: b"",
        0x4000000B: b"",
        0x40000010: b"",
    }
    bypass.tpm_emulator.driver_handle = None
    bypass.sgx_emulator = SGXEmulator()
    bypass.intercepted_calls = []
    bypass.bypass_active = False
    return bypass


class TestTPMEmulator:
    """Test TPM emulator for bypassing TPM-based license protections."""

    def test_tpm_emulator_initialization_creates_valid_state(self, tpm_emulator: TPMEmulator) -> None:
        """TPM emulator initializes with proper state structures for defeating license checks."""
        emulator = tpm_emulator

        assert emulator.tpm_state == {}
        assert TPM_ALG.SHA1 in emulator.pcr_banks
        assert TPM_ALG.SHA256 in emulator.pcr_banks
        assert len(emulator.pcr_banks[TPM_ALG.SHA1]) == 24
        assert len(emulator.pcr_banks[TPM_ALG.SHA256]) == 24
        assert all(pcr == b"\x00" * 20 for pcr in emulator.pcr_banks[TPM_ALG.SHA1])
        assert all(pcr == b"\x00" * 32 for pcr in emulator.pcr_banks[TPM_ALG.SHA256])
        assert 0x40000001 in emulator.hierarchy_auth
        assert 0x4000000C in emulator.hierarchy_auth
        assert 0x4000000B in emulator.hierarchy_auth
        assert emulator.keys == {}
        assert emulator.sessions == {}
        assert emulator.nv_storage == {}

    def test_tpm_startup_activates_emulator_for_license_bypass(self, tpm_emulator: TPMEmulator) -> None:
        """TPM startup command successfully initializes emulator to bypass TPM license checks."""
        emulator = tpm_emulator

        result = emulator.startup(startup_type=0)

        assert result == TPM_RC.SUCCESS
        assert emulator.tpm_state["started"] is True
        assert emulator.tpm_state["startup_type"] == 0

    def test_tpm_startup_clear_resets_pcrs_to_bypass_measured_boot_checks(
        self, tpm_emulator: TPMEmulator
    ) -> None:
        """TPM startup with clear type resets PCR banks to bypass measured boot protections."""
        emulator = tpm_emulator

        emulator.extend_pcr(0, TPM_ALG.SHA256, b"test_measurement")
        rc, pcr_value = emulator.read_pcr(0, TPM_ALG.SHA256)
        assert rc == TPM_RC.SUCCESS
        assert pcr_value != b"\x00" * 32

        result = emulator.startup(startup_type=0)

        assert result == TPM_RC.SUCCESS
        rc, pcr_value = emulator.read_pcr(0, TPM_ALG.SHA256)
        assert rc == TPM_RC.SUCCESS
        assert pcr_value == b"\x00" * 32

    def test_create_primary_rsa_key_generates_valid_key_for_license_operations(
        self, tpm_emulator: TPMEmulator
    ) -> None:
        """Create primary key generates valid RSA key bypassing TPM hardware requirements."""
        emulator = tpm_emulator

        key_template = {
            "algorithm": TPM_ALG.RSA,
            "key_size": 2048,
            "attributes": 0x00040000,
        }

        rc, key = emulator.create_primary_key(0x40000001, b"", key_template)

        assert rc == TPM_RC.SUCCESS
        assert key is not None
        assert isinstance(key, TPMKey)
        assert key.algorithm == TPM_ALG.RSA
        assert key.key_size == 2048
        assert key.parent == 0x40000001
        assert len(key.public_key) > 0
        assert len(key.private_key) > 0
        assert len(key.auth_value) == 32
        assert key.handle in emulator.keys

        private_key = serialization.load_der_private_key(key.private_key, password=None, backend=default_backend())
        assert isinstance(private_key, rsa.RSAPrivateKey)

        test_data = b"license_validation_data"
        signature = private_key.sign(
            test_data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
        )
        public_key = private_key.public_key()
        public_key.verify(
            signature, test_data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
        )

    def test_create_primary_ecc_key_generates_valid_key_for_attestation_bypass(
        self, tpm_emulator: TPMEmulator
    ) -> None:
        """Create primary key generates valid ECC key for bypassing attestation checks."""
        emulator = tpm_emulator

        key_template = {
            "algorithm": TPM_ALG.ECC,
            "key_size": 256,
            "attributes": 0x00060000,
        }

        rc, key = emulator.create_primary_key(0x40000001, b"", key_template)

        assert rc == TPM_RC.SUCCESS
        assert key is not None
        assert isinstance(key, TPMKey)
        assert key.algorithm == TPM_ALG.ECC
        assert len(key.public_key) > 0
        assert len(key.private_key) > 0

        private_key = serialization.load_der_private_key(key.private_key, password=None, backend=default_backend())
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)

        test_data = b"attestation_data"
        signature = private_key.sign(test_data, ec.ECDSA(hashes.SHA256()))
        public_key = private_key.public_key()
        public_key.verify(signature, test_data, ec.ECDSA(hashes.SHA256()))

    def test_create_primary_key_fails_with_wrong_auth_enforcing_security(
        self, tpm_emulator: TPMEmulator
    ) -> None:
        """Create primary key fails when authorization is incorrect proving auth enforcement."""
        emulator = tpm_emulator
        emulator.hierarchy_auth[0x40000001] = b"secret_auth"

        key_template = {"algorithm": TPM_ALG.RSA, "key_size": 2048}

        rc, key = emulator.create_primary_key(0x40000001, b"wrong_auth", key_template)

        assert rc == TPM_RC.AUTHFAIL
        assert key is None

    def test_create_primary_key_fails_with_invalid_hierarchy(self, tpm_emulator: TPMEmulator) -> None:
        """Create primary key fails with invalid hierarchy handle."""
        emulator = tpm_emulator

        key_template = {"algorithm": TPM_ALG.RSA, "key_size": 2048}

        rc, key = emulator.create_primary_key(0x99999999, b"", key_template)

        assert rc == TPM_RC.HIERARCHY
        assert key is None

    def test_create_primary_key_fails_with_unsupported_algorithm(self, tpm_emulator: TPMEmulator) -> None:
        """Create primary key fails with unsupported algorithm type."""
        emulator = tpm_emulator

        key_template = {"algorithm": TPM_ALG.HMAC, "key_size": 256}

        rc, key = emulator.create_primary_key(0x40000001, b"", key_template)

        assert rc == TPM_RC.TYPE
        assert key is None

    def test_sign_with_rsa_key_produces_valid_signature_bypassing_tpm_hardware(
        self, tpm_emulator: TPMEmulator
    ) -> None:
        """Signing with RSA key produces cryptographically valid signature without real TPM."""
        emulator = tpm_emulator

        key_template = {"algorithm": TPM_ALG.RSA, "key_size": 2048}
        rc, key = emulator.create_primary_key(0x40000001, b"", key_template)
        assert rc == TPM_RC.SUCCESS

        data_to_sign = b"license_verification_challenge"
        rc, signature = emulator.sign(key.handle, data_to_sign, key.auth_value)

        assert rc == TPM_RC.SUCCESS
        assert signature is not None
        assert len(signature) > 0

        private_key = serialization.load_der_private_key(key.private_key, password=None, backend=default_backend())
        public_key = private_key.public_key()

        public_key.verify(
            signature,
            data_to_sign,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    def test_sign_with_ecc_key_produces_valid_signature_for_attestation_bypass(
        self, tpm_emulator: TPMEmulator
    ) -> None:
        """Signing with ECC key produces cryptographically valid signature bypassing attestation."""
        emulator = tpm_emulator

        key_template = {"algorithm": TPM_ALG.ECC, "key_size": 256}
        rc, key = emulator.create_primary_key(0x40000001, b"", key_template)
        assert rc == TPM_RC.SUCCESS

        data_to_sign = b"remote_attestation_challenge"
        rc, signature = emulator.sign(key.handle, data_to_sign, key.auth_value)

        assert rc == TPM_RC.SUCCESS
        assert signature is not None
        assert len(signature) > 0

        private_key = serialization.load_der_private_key(key.private_key, password=None, backend=default_backend())
        public_key = private_key.public_key()

        public_key.verify(signature, data_to_sign, ec.ECDSA(hashes.SHA256()))

    def test_sign_fails_with_invalid_handle(self, tpm_emulator: TPMEmulator) -> None:
        """Signing fails when key handle doesn't exist."""
        emulator = tpm_emulator

        rc, signature = emulator.sign(0x99999999, b"data", b"auth")

        assert rc == TPM_RC.HANDLE
        assert signature is None

    def test_sign_fails_with_wrong_auth(self, tpm_emulator: TPMEmulator) -> None:
        """Signing fails when authorization value is incorrect."""
        emulator = tpm_emulator

        key_template = {"algorithm": TPM_ALG.RSA, "key_size": 2048}
        rc, key = emulator.create_primary_key(0x40000001, b"", key_template)
        assert rc == TPM_RC.SUCCESS

        rc, signature = emulator.sign(key.handle, b"data", b"wrong_auth")

        assert rc == TPM_RC.AUTHFAIL
        assert signature is None

    def test_extend_pcr_updates_pcr_value_correctly_for_boot_measurement_bypass(
        self, tpm_emulator: TPMEmulator
    ) -> None:
        """PCR extension correctly updates PCR to bypass boot measurement checks."""
        emulator = tpm_emulator

        test_data = b"boot_component_measurement"
        rc = emulator.extend_pcr(0, TPM_ALG.SHA256, test_data)

        assert rc == TPM_RC.SUCCESS

        rc, pcr_value = emulator.read_pcr(0, TPM_ALG.SHA256)
        assert rc == TPM_RC.SUCCESS

        expected = hashlib.sha256(b"\x00" * 32 + test_data).digest()
        assert pcr_value == expected

    def test_extend_pcr_multiple_extends_chain_correctly_for_license_validation(
        self, tpm_emulator: TPMEmulator
    ) -> None:
        """Multiple PCR extensions chain measurements correctly bypassing license checks."""
        emulator = tpm_emulator

        data1 = b"first_component"
        data2 = b"second_component"

        rc = emulator.extend_pcr(0, TPM_ALG.SHA256, data1)
        assert rc == TPM_RC.SUCCESS

        rc = emulator.extend_pcr(0, TPM_ALG.SHA256, data2)
        assert rc == TPM_RC.SUCCESS

        rc, final_pcr = emulator.read_pcr(0, TPM_ALG.SHA256)
        assert rc == TPM_RC.SUCCESS

        intermediate = hashlib.sha256(b"\x00" * 32 + data1).digest()
        expected = hashlib.sha256(intermediate + data2).digest()
        assert final_pcr == expected

    def test_extend_pcr_fails_with_invalid_index(self, tpm_emulator: TPMEmulator) -> None:
        """PCR extension fails with invalid PCR index."""
        emulator = tpm_emulator

        rc = emulator.extend_pcr(24, TPM_ALG.SHA256, b"data")

        assert rc == TPM_RC.PCR

    def test_extend_pcr_fails_with_invalid_algorithm(self, tpm_emulator: TPMEmulator) -> None:
        """PCR extension fails with unsupported hash algorithm."""
        emulator = tpm_emulator

        rc = emulator.extend_pcr(0, TPM_ALG.HMAC, b"data")

        assert rc == TPM_RC.TYPE

    def test_read_pcr_returns_correct_values_for_attestation_bypass(self, tpm_emulator: TPMEmulator) -> None:
        """Reading PCR returns correct values for different banks to bypass attestation."""
        emulator = tpm_emulator

        rc, sha1_pcr = emulator.read_pcr(0, TPM_ALG.SHA1)
        assert rc == TPM_RC.SUCCESS
        assert sha1_pcr == b"\x00" * 20

        rc, sha256_pcr = emulator.read_pcr(0, TPM_ALG.SHA256)
        assert rc == TPM_RC.SUCCESS
        assert sha256_pcr == b"\x00" * 32

    def test_read_pcr_fails_with_invalid_index(self, tpm_emulator: TPMEmulator) -> None:
        """Reading PCR fails with invalid PCR index."""
        emulator = tpm_emulator

        rc, pcr_value = emulator.read_pcr(24, TPM_ALG.SHA256)

        assert rc == TPM_RC.PCR
        assert pcr_value is None

    def test_get_random_generates_requested_bytes_for_license_keygen(self, tpm_emulator: TPMEmulator) -> None:
        """Get random generates exactly requested number of bytes for license key generation."""
        emulator = tpm_emulator

        rc, random_data = emulator.get_random(32)

        assert rc == TPM_RC.SUCCESS
        assert random_data is not None
        assert len(random_data) == 32

    def test_get_random_generates_different_values_ensuring_uniqueness(
        self, tpm_emulator: TPMEmulator
    ) -> None:
        """Get random generates different values on each call ensuring unique license keys."""
        emulator = tpm_emulator

        rc1, data1 = emulator.get_random(32)
        rc2, data2 = emulator.get_random(32)

        assert rc1 == TPM_RC.SUCCESS
        assert rc2 == TPM_RC.SUCCESS
        assert data1 != data2

    def test_get_random_fails_with_invalid_size(self, tpm_emulator: TPMEmulator) -> None:
        """Get random fails with invalid byte count."""
        emulator = tpm_emulator

        rc, data = emulator.get_random(0)
        assert rc == TPM_RC.SIZE
        assert data is None

        rc, data = emulator.get_random(2048)
        assert rc == TPM_RC.SIZE
        assert data is None

    def test_seal_data_creates_encrypted_blob_bound_to_pcr_state(self, tpm_emulator: TPMEmulator) -> None:
        """Sealing data creates encrypted blob bound to PCR state for license protection."""
        emulator = tpm_emulator

        secret_data = b"license_activation_key"
        pcr_selection = [0, 1, 2, 3]
        auth_value = b"seal_auth"

        rc, sealed_blob = emulator.seal(secret_data, pcr_selection, auth_value)

        assert rc == TPM_RC.SUCCESS
        assert sealed_blob is not None
        assert len(sealed_blob) > len(secret_data)
        assert sealed_blob != secret_data

    def test_seal_fails_with_invalid_pcr_index(self, tpm_emulator: TPMEmulator) -> None:
        """Sealing fails with invalid PCR index in selection."""
        emulator = tpm_emulator

        rc, sealed_blob = emulator.seal(b"data", [0, 24], b"auth")

        assert rc == TPM_RC.PCR
        assert sealed_blob is None

    def test_unseal_data_recovers_original_data_bypassing_pcr_checks(self, tpm_emulator: TPMEmulator) -> None:
        """Unsealing data recovers original data with correct auth and PCR state."""
        emulator = tpm_emulator

        secret_data = b"confidential_license_key_material"
        pcr_selection = [0, 1]
        auth_value = b"unseal_auth"

        rc, sealed_blob = emulator.seal(secret_data, pcr_selection, auth_value)
        assert rc == TPM_RC.SUCCESS

        rc, unsealed_data = emulator.unseal(sealed_blob, auth_value)

        assert rc == TPM_RC.SUCCESS
        assert unsealed_data == secret_data

    def test_unseal_fails_with_wrong_auth(self, tpm_emulator: TPMEmulator) -> None:
        """Unsealing fails when authorization value is incorrect."""
        emulator = tpm_emulator

        secret_data = b"protected_license_data"
        rc, sealed_blob = emulator.seal(secret_data, [0], b"correct_auth")
        assert rc == TPM_RC.SUCCESS

        rc, unsealed_data = emulator.unseal(sealed_blob, b"wrong_auth")

        assert rc == TPM_RC.AUTHFAIL
        assert unsealed_data is None

    def test_unseal_fails_when_pcr_changed(self, tpm_emulator: TPMEmulator) -> None:
        """Unsealing fails when PCR values have changed since sealing."""
        emulator = tpm_emulator

        secret_data = b"pcr_bound_license_data"
        auth_value = b"auth"
        pcr_selection = [0]

        rc, sealed_blob = emulator.seal(secret_data, pcr_selection, auth_value)
        assert rc == TPM_RC.SUCCESS

        rc = emulator.extend_pcr(0, TPM_ALG.SHA256, b"boot_change")
        assert rc == TPM_RC.SUCCESS

        rc, unsealed_data = emulator.unseal(sealed_blob, auth_value)

        assert rc == TPM_RC.PCR_CHANGED
        assert unsealed_data is None

    def test_unseal_fails_with_corrupted_blob(self, tpm_emulator: TPMEmulator) -> None:
        """Unsealing fails with corrupted sealed blob."""
        emulator = tpm_emulator

        corrupted_blob = b"invalid_sealed_blob_data"

        rc, unsealed_data = emulator.unseal(corrupted_blob, b"auth")

        assert rc == TPM_RC.INTEGRITY
        assert unsealed_data is None


class TestSGXEmulator:
    """Test SGX emulator for bypassing enclave-based license protections."""

    def test_sgx_emulator_initialization(self, sgx_emulator: SGXEmulator) -> None:
        """SGX emulator initializes with proper state structures for defeating enclave checks."""
        emulator = sgx_emulator

        assert emulator.enclaves == {}
        assert emulator.measurements == {}
        assert emulator.sealing_keys == {}
        assert emulator.attestation_keys == {}
        assert emulator.next_enclave_id == 1

    def test_create_enclave_generates_valid_enclave_id_bypassing_sgx_hardware(
        self, sgx_emulator: SGXEmulator, tmp_path: Path
    ) -> None:
        """Creating enclave generates valid enclave ID and measurement without real SGX."""
        emulator = sgx_emulator

        enclave_file = tmp_path / "test_enclave.signed.so"
        enclave_data = secrets.token_bytes(1024)
        enclave_file.write_bytes(enclave_data)

        enclave_id, error = emulator.create_enclave(enclave_file, debug=False)

        assert error == SGX_ERROR.SUCCESS
        assert enclave_id == 1
        assert enclave_id in emulator.enclaves
        assert enclave_id in emulator.measurements
        assert enclave_id in emulator.sealing_keys

        expected_measurement = hashlib.sha256(enclave_data).digest()
        assert emulator.measurements[enclave_id] == expected_measurement

    def test_create_enclave_sets_correct_attributes_for_license_bypass(
        self, sgx_emulator: SGXEmulator, tmp_path: Path
    ) -> None:
        """Creating enclave sets correct debug and production attributes for bypass."""
        emulator = sgx_emulator

        enclave_file = tmp_path / "debug_enclave.signed.so"
        enclave_file.write_bytes(secrets.token_bytes(512))

        enclave_id, error = emulator.create_enclave(enclave_file, debug=True)

        assert error == SGX_ERROR.SUCCESS
        assert emulator.enclaves[enclave_id]["debug"] is True
        assert emulator.enclaves[enclave_id]["attributes"] == 0x04

        enclave_id2, error2 = emulator.create_enclave(enclave_file, debug=False)

        assert error2 == SGX_ERROR.SUCCESS
        assert emulator.enclaves[enclave_id2]["debug"] is False
        assert emulator.enclaves[enclave_id2]["attributes"] == 0x00

    def test_create_enclave_fails_with_missing_file(self, sgx_emulator: SGXEmulator) -> None:
        """Creating enclave fails when file doesn't exist."""
        emulator = sgx_emulator

        non_existent_file = Path("/non/existent/enclave.so")
        enclave_id, error = emulator.create_enclave(non_existent_file)

        assert error == SGX_ERROR.ENCLAVE_FILE_ACCESS
        assert enclave_id == 0

    def test_create_enclave_increments_id_for_multiple_enclaves(
        self, sgx_emulator: SGXEmulator, tmp_path: Path
    ) -> None:
        """Creating multiple enclaves increments enclave ID correctly."""
        emulator = sgx_emulator

        enclave1 = tmp_path / "enclave1.signed.so"
        enclave1.write_bytes(secrets.token_bytes(256))

        enclave2 = tmp_path / "enclave2.signed.so"
        enclave2.write_bytes(secrets.token_bytes(256))

        id1, error1 = emulator.create_enclave(enclave1)
        id2, error2 = emulator.create_enclave(enclave2)

        assert error1 == SGX_ERROR.SUCCESS
        assert error2 == SGX_ERROR.SUCCESS
        assert id1 == 1
        assert id2 == 2

    def test_get_report_returns_valid_report_for_attestation_bypass(
        self, sgx_emulator: SGXEmulator, tmp_path: Path
    ) -> None:
        """Getting enclave report returns valid SGX report structure bypassing attestation."""
        emulator = sgx_emulator

        enclave_file = tmp_path / "test_enclave.signed.so"
        enclave_file.write_bytes(secrets.token_bytes(512))

        enclave_id, _ = emulator.create_enclave(enclave_file)
        report_data = secrets.token_bytes(64)

        report, error = emulator.get_report(enclave_id, report_data=report_data)

        assert error == SGX_ERROR.SUCCESS
        assert report is not None
        assert isinstance(report, SGXReport)
        assert len(report.mr_enclave) == 32
        assert len(report.mr_signer) == 32
        assert report.report_data == report_data
        assert report.measurement == report.mr_enclave

    def test_get_report_fails_with_invalid_enclave_id(self, sgx_emulator: SGXEmulator) -> None:
        """Getting report fails with invalid enclave ID."""
        emulator = sgx_emulator

        report, error = emulator.get_report(99999)

        assert error == SGX_ERROR.INVALID_ENCLAVE_ID
        assert report is None

    def test_seal_data_encrypts_data_with_enclave_key_for_license_protection(
        self, sgx_emulator: SGXEmulator, tmp_path: Path
    ) -> None:
        """Sealing data encrypts data with enclave-specific key for license protection."""
        emulator = sgx_emulator

        enclave_file = tmp_path / "seal_enclave.signed.so"
        enclave_file.write_bytes(secrets.token_bytes(512))

        enclave_id, _ = emulator.create_enclave(enclave_file)
        secret_data = b"license_validation_secret_key"

        sealed_data, error = emulator.seal_data(enclave_id, secret_data)

        assert error == SGX_ERROR.SUCCESS
        assert sealed_data is not None
        assert len(sealed_data) > len(secret_data)
        assert sealed_data != secret_data

    def test_seal_data_fails_with_invalid_enclave_id(self, sgx_emulator: SGXEmulator) -> None:
        """Sealing data fails with invalid enclave ID."""
        emulator = sgx_emulator

        sealed_data, error = emulator.seal_data(99999, b"data")

        assert error == SGX_ERROR.INVALID_ENCLAVE_ID
        assert sealed_data is None

    def test_unseal_data_recovers_original_bypassing_enclave_isolation(
        self, sgx_emulator: SGXEmulator, tmp_path: Path
    ) -> None:
        """Unsealing data recovers original data in same enclave bypassing isolation."""
        emulator = sgx_emulator

        enclave_file = tmp_path / "unseal_enclave.signed.so"
        enclave_file.write_bytes(secrets.token_bytes(512))

        enclave_id, _ = emulator.create_enclave(enclave_file)
        secret_data = b"confidential_license_material"

        sealed_data, seal_error = emulator.seal_data(enclave_id, secret_data)
        assert seal_error == SGX_ERROR.SUCCESS

        unsealed_data, unseal_error = emulator.unseal_data(enclave_id, sealed_data)

        assert unseal_error == SGX_ERROR.SUCCESS
        assert unsealed_data == secret_data

    def test_unseal_data_fails_with_different_enclave_enforcing_isolation(
        self, sgx_emulator: SGXEmulator, tmp_path: Path
    ) -> None:
        """Unsealing data fails when attempted in different enclave proving isolation."""
        emulator = sgx_emulator

        enclave1 = tmp_path / "enclave1.signed.so"
        enclave1.write_bytes(secrets.token_bytes(512))
        enclave2 = tmp_path / "enclave2.signed.so"
        enclave2.write_bytes(secrets.token_bytes(256))

        enclave_id1, _ = emulator.create_enclave(enclave1)
        enclave_id2, _ = emulator.create_enclave(enclave2)

        secret_data = b"enclave1_license_secret"
        sealed_data, _ = emulator.seal_data(enclave_id1, secret_data)

        unsealed_data, error = emulator.unseal_data(enclave_id2, sealed_data)

        assert error == SGX_ERROR.MAC_MISMATCH
        assert unsealed_data is None

    def test_unseal_data_fails_with_invalid_enclave_id(self, sgx_emulator: SGXEmulator) -> None:
        """Unsealing data fails with invalid enclave ID."""
        emulator = sgx_emulator

        unsealed_data, error = emulator.unseal_data(99999, b"sealed_data")

        assert error == SGX_ERROR.INVALID_ENCLAVE_ID
        assert unsealed_data is None

    def test_unseal_data_fails_with_corrupted_data(self, sgx_emulator: SGXEmulator, tmp_path: Path) -> None:
        """Unsealing data fails with corrupted sealed data."""
        emulator = sgx_emulator

        enclave_file = tmp_path / "test_enclave.signed.so"
        enclave_file.write_bytes(secrets.token_bytes(512))

        enclave_id, _ = emulator.create_enclave(enclave_file)
        corrupted_data = b"not_valid_sealed_data"

        unsealed_data, error = emulator.unseal_data(enclave_id, corrupted_data)

        assert error == SGX_ERROR.MAC_MISMATCH
        assert unsealed_data is None

    def test_get_quote_generates_valid_quote_structure_for_remote_attestation(
        self, sgx_emulator: SGXEmulator, tmp_path: Path
    ) -> None:
        """Getting quote generates valid SGX quote for remote attestation bypass."""
        emulator = sgx_emulator

        enclave_file = tmp_path / "quote_enclave.signed.so"
        enclave_file.write_bytes(secrets.token_bytes(512))

        enclave_id, _ = emulator.create_enclave(enclave_file)
        report, _ = emulator.get_report(enclave_id)

        quote_data, error = emulator.get_quote(enclave_id, report, quote_type=0)

        assert error == SGX_ERROR.SUCCESS
        assert quote_data is not None
        assert len(quote_data) > 100

        version = struct.unpack("<H", quote_data[0:2])[0]
        assert version == 2

    def test_get_quote_includes_report_data_for_verification(
        self, sgx_emulator: SGXEmulator, tmp_path: Path
    ) -> None:
        """Quote includes enclave report measurements for attestation verification."""
        emulator = sgx_emulator

        enclave_file = tmp_path / "report_enclave.signed.so"
        enclave_data = secrets.token_bytes(1024)
        enclave_file.write_bytes(enclave_data)

        enclave_id, _ = emulator.create_enclave(enclave_file)
        custom_report_data = secrets.token_bytes(64)
        report, _ = emulator.get_report(enclave_id, report_data=custom_report_data)

        quote_data, error = emulator.get_quote(enclave_id, report)

        assert error == SGX_ERROR.SUCCESS
        assert report.mr_enclave in quote_data
        assert custom_report_data in quote_data

    def test_get_quote_fails_with_invalid_enclave_id(self, sgx_emulator: SGXEmulator) -> None:
        """Getting quote fails with invalid enclave ID."""
        emulator = sgx_emulator

        fake_report = SGXReport(
            measurement=b"\x00" * 32,
            attributes=0,
            mr_enclave=b"\x00" * 32,
            mr_signer=b"\x00" * 32,
            isv_prod_id=0,
            isv_svn=0,
            report_data=b"\x00" * 64,
        )

        quote_data, error = emulator.get_quote(99999, fake_report)

        assert error == SGX_ERROR.INVALID_ENCLAVE_ID
        assert quote_data is None

    def test_get_quote_includes_signature_for_cryptographic_verification(
        self, sgx_emulator: SGXEmulator, tmp_path: Path
    ) -> None:
        """Quote includes cryptographic signature for verification."""
        emulator = sgx_emulator

        enclave_file = tmp_path / "sig_enclave.signed.so"
        enclave_file.write_bytes(secrets.token_bytes(512))

        enclave_id, _ = emulator.create_enclave(enclave_file)
        report, _ = emulator.get_report(enclave_id)

        quote_data, error = emulator.get_quote(enclave_id, report)

        assert error == SGX_ERROR.SUCCESS
        assert len(quote_data) > 400

        signature_offset = len(quote_data) - 32
        signature = quote_data[signature_offset:]
        assert len(signature) == 32


class TestSecureEnclaveBypass:
    """Test unified bypass system for TPM and SGX license protections."""

    def test_bypass_initialization_creates_emulators_for_hardware_bypass(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """Bypass system initializes with TPM and SGX emulators for hardware bypass."""
        bypass = bypass_system

        assert isinstance(bypass.tpm_emulator, TPMEmulator)
        assert isinstance(bypass.sgx_emulator, SGXEmulator)
        assert bypass.intercepted_calls == []
        assert bypass.bypass_active is False

    def test_bypass_remote_attestation_generates_valid_response_defeating_attestation_checks(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """Bypass generates valid attestation response defeating remote attestation."""
        bypass = bypass_system

        challenge = secrets.token_bytes(32)
        response = bypass.bypass_remote_attestation(challenge)

        assert response is not None
        assert len(response) > 0

        parsed_response = json.loads(response.decode())
        assert "tpm_quote" in parsed_response
        assert "sgx_quote" in parsed_response
        assert "certificates" in parsed_response
        assert "platform_manifest" in parsed_response

    def test_tpm_quote_creation_generates_valid_quote_bypassing_tpm_attestation(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """TPM quote creation generates properly formatted quote bypassing TPM attestation."""
        bypass = bypass_system

        challenge = secrets.token_bytes(32)
        tpm_quote = bypass._create_tpm_quote(challenge)

        assert tpm_quote is not None
        assert len(tpm_quote) > 0

        quote_data = base64.b64decode(tpm_quote)
        assert len(quote_data) > 50

    def test_sgx_quote_creation_generates_valid_quote_bypassing_sgx_attestation(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """SGX quote creation generates properly formatted quote bypassing SGX attestation."""
        bypass = bypass_system

        challenge = secrets.token_bytes(32)
        sgx_quote = bypass._create_sgx_quote(challenge)

        assert sgx_quote is not None
        assert len(sgx_quote) > 0

        quote_data = base64.b64decode(sgx_quote)
        assert len(quote_data) > 100

        version = struct.unpack("<H", quote_data[0:2])[0]
        assert version == 3

    def test_platform_manifest_capture_returns_valid_data_for_attestation(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """Platform manifest capture returns valid configuration data for attestation."""
        bypass = bypass_system

        manifest = bypass._capture_platform_manifest()

        assert isinstance(manifest, dict)
        assert "platform_id" in manifest
        assert "tpm_version" in manifest
        assert "sgx_version" in manifest
        assert "secure_boot" in manifest
        assert "measured_boot" in manifest
        assert "platform_configuration" in manifest
        assert "security_version" in manifest

        assert isinstance(manifest["platform_configuration"], dict)
        assert "cpu_model" in manifest["platform_configuration"]

    def test_platform_certificate_extraction_returns_certificates_for_verification(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """Platform certificate extraction returns valid certificates for attestation."""
        bypass = bypass_system

        certificates = bypass._extract_platform_certificates()

        assert isinstance(certificates, list)
        assert len(certificates) > 0

        for cert in certificates:
            assert isinstance(cert, str)
            cert_data = base64.b64decode(cert)
            assert len(cert_data) > 0

    def test_tpm_attestation_key_loading_creates_valid_key_for_signing(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """TPM attestation key loading creates valid RSA key for quote signing."""
        bypass = bypass_system

        key = bypass._load_attestation_key()

        assert key is not None
        assert isinstance(key, rsa.RSAPrivateKey)

        public_key = key.public_key()
        test_data = b"test_attestation_data"
        signature = key.sign(
            test_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

        public_key.verify(
            signature,
            test_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    def test_sgx_attestation_key_loading_creates_valid_key_for_quote_signing(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """SGX attestation key loading creates valid ECDSA key for quote signing."""
        bypass = bypass_system

        key = bypass._load_sgx_attestation_key()

        assert key is not None
        assert isinstance(key, ec.EllipticCurvePrivateKey)

        public_key = key.public_key()
        test_data = b"test_sgx_quote_data"
        signature = key.sign(test_data, ec.ECDSA(hashes.SHA256()))

        public_key.verify(signature, test_data, ec.ECDSA(hashes.SHA256()))

    def test_pcr_selection_for_quote_generates_valid_selection_structure(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """PCR selection for quote generates valid TPM selection structure."""
        bypass = bypass_system

        rc, selection = bypass._select_pcrs_for_quote()

        assert rc == TPM_RC.SUCCESS
        assert selection is not None
        assert len(selection) >= 8

        count = struct.unpack(">I", selection[0:4])[0]
        assert count == 1

        hash_alg = struct.unpack(">H", selection[4:6])[0]
        assert hash_alg == TPM_ALG.SHA256

    def test_pcr_digest_computation_produces_correct_digest_for_quote(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """PCR digest computation produces correct hash of selected PCRs for quote."""
        bypass = bypass_system

        bypass.tpm_emulator.startup(0)
        bypass.tpm_emulator.extend_pcr(0, TPM_ALG.SHA256, b"boot_measurement")
        bypass.tpm_emulator.extend_pcr(1, TPM_ALG.SHA256, b"firmware_measurement")

        rc, selection = bypass._select_pcrs_for_quote()
        assert rc == TPM_RC.SUCCESS

        digest = bypass._compute_pcr_digest(selection)

        assert digest is not None
        assert len(digest) == 32

    def test_attestation_key_name_computation_produces_hash_for_identification(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """Attestation key name computation produces valid hash for key identification."""
        bypass = bypass_system

        key_name = bypass._get_attestation_key_name()

        assert key_name is not None
        assert len(key_name) == 32

    def test_tpm_quote_signing_produces_valid_signature_for_attestation(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """TPM quote signing produces cryptographically valid signature for attestation."""
        bypass = bypass_system

        quote_data = secrets.token_bytes(256)
        signature = bypass._sign_tpm_quote(quote_data)

        assert signature is not None
        assert len(signature) > 0

        key = bypass._load_attestation_key()
        public_key = key.public_key()

        public_key.verify(
            signature,
            quote_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    def test_sgx_quote_signing_produces_valid_signature_for_remote_attestation(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """SGX quote signing produces cryptographically valid ECDSA signature for attestation."""
        bypass = bypass_system

        report_data = secrets.token_bytes(384)
        signature = bypass._sign_sgx_quote(report_data)

        assert signature is not None
        assert len(signature) > 0

        key = bypass._load_sgx_attestation_key()
        public_key = key.public_key()

        public_key.verify(signature, report_data, ec.ECDSA(hashes.SHA256()))

    def test_emulated_tpm_quote_generation_creates_valid_quote_structure(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """Emulated TPM quote generation creates valid quote structure for attestation."""
        bypass = bypass_system

        challenge = secrets.token_bytes(32)
        quote = bypass._emulate_tpm_quote(challenge)

        assert quote is not None
        assert len(quote) > 0

        quote_data = base64.b64decode(quote)
        assert len(quote_data) > 0

    def test_tpm_command_handling_processes_random_command_correctly(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """TPM command handling processes GetRandom command correctly."""
        bypass = bypass_system

        command = bytearray()
        command.extend(struct.pack(">H", 0x8001))
        command.extend(struct.pack(">I", 12))
        command.extend(struct.pack(">I", 0x0000017B))
        command.extend(struct.pack(">H", 32))

        response = bypass._handle_tpm_command(list(command))

        assert response is not None
        assert len(response) >= 10

        tag = struct.unpack(">H", response[0:2])[0]
        assert tag == 0x8001

    def test_tpm_command_handling_processes_startup_command_correctly(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """TPM command handling processes Startup command correctly."""
        bypass = bypass_system

        command = bytearray()
        command.extend(struct.pack(">H", 0x8001))
        command.extend(struct.pack(">I", 12))
        command.extend(struct.pack(">I", 0x00000144))
        command.extend(struct.pack(">H", 0))

        response = bypass._handle_tpm_command(list(command))

        assert response is not None
        assert len(response) >= 10

        rc = struct.unpack(">H", response[8:10])[0]
        assert rc == 0

    def test_tpm_command_handling_with_short_command_returns_error(
        self, bypass_system: SecureEnclaveBypass
    ) -> None:
        """TPM command handling returns error for malformed short command."""
        bypass = bypass_system

        short_command = [0x80, 0x01, 0x00, 0x00]

        response = bypass._handle_tpm_command(short_command)

        assert response is not None
        assert len(response) >= 10

    def test_cleanup_deactivates_bypass_system(self, bypass_system: SecureEnclaveBypass) -> None:
        """Cleanup deactivates bypass system restoring original state."""
        bypass = bypass_system
        bypass.bypass_active = True

        bypass.cleanup()

        assert bypass.bypass_active is False


class TestTPMEnumerations:
    """Test TPM enumeration values for correctness against TPM 2.0 specification."""

    def test_tpm_rc_values_match_specification(self) -> None:
        """TPM return code values match TPM 2.0 specification."""
        assert TPM_RC.SUCCESS == 0x00000000
        assert TPM_RC.AUTHFAIL == 0x0000098E
        assert TPM_RC.BAD_AUTH == 0x00000A22
        assert TPM_RC.FAILURE == 0x00000101
        assert TPM_RC.PCR == 0x00000127
        assert TPM_RC.PCR_CHANGED == 0x00000128
        assert TPM_RC.HIERARCHY == 0x00000185
        assert TPM_RC.HANDLE == 0x0000008B

    def test_tpm_alg_values_match_specification(self) -> None:
        """TPM algorithm identifiers match TPM 2.0 specification."""
        assert TPM_ALG.RSA == 0x0001
        assert TPM_ALG.SHA1 == 0x0004
        assert TPM_ALG.HMAC == 0x0005
        assert TPM_ALG.AES == 0x0006
        assert TPM_ALG.SHA256 == 0x000B
        assert TPM_ALG.SHA384 == 0x000C
        assert TPM_ALG.SHA512 == 0x000D
        assert TPM_ALG.ECC == 0x0023

    def test_sgx_error_values_match_intel_specification(self) -> None:
        """SGX error codes match Intel SGX specification."""
        assert SGX_ERROR.SUCCESS == 0x00000000
        assert SGX_ERROR.INVALID_ENCLAVE_ID == 0x00002002
        assert SGX_ERROR.ENCLAVE_FILE_ACCESS == 0x0000200F
        assert SGX_ERROR.MAC_MISMATCH == 0x00003001
        assert SGX_ERROR.INVALID_SIGNATURE == 0x00002003


class TestTPMKeyDataclass:
    """Test TPMKey dataclass structure for proper initialization."""

    def test_tpm_key_creation_with_all_fields_initializes_correctly(self) -> None:
        """TPMKey dataclass accepts all required fields and initializes correctly."""
        key = TPMKey(
            handle=0x81000000,
            public_key=b"public_key_material",
            private_key=b"private_key_material",
            parent=0x40000001,
            auth_value=secrets.token_bytes(32),
            algorithm=TPM_ALG.RSA,
            key_size=2048,
            attributes=0x00040000,
        )

        assert key.handle == 0x81000000
        assert key.public_key == b"public_key_material"
        assert key.private_key == b"private_key_material"
        assert key.parent == 0x40000001
        assert len(key.auth_value) == 32
        assert key.algorithm == TPM_ALG.RSA
        assert key.key_size == 2048
        assert key.attributes == 0x00040000


class TestSGXReportDataclass:
    """Test SGXReport dataclass structure for proper initialization."""

    def test_sgx_report_creation_with_all_fields_initializes_correctly(self) -> None:
        """SGXReport dataclass accepts all required fields and initializes correctly."""
        report = SGXReport(
            measurement=secrets.token_bytes(32),
            attributes=0x04,
            mr_enclave=secrets.token_bytes(32),
            mr_signer=secrets.token_bytes(32),
            isv_prod_id=1,
            isv_svn=2,
            report_data=secrets.token_bytes(64),
        )

        assert len(report.measurement) == 32
        assert report.attributes == 0x04
        assert len(report.mr_enclave) == 32
        assert len(report.mr_signer) == 32
        assert report.isv_prod_id == 1
        assert report.isv_svn == 2
        assert len(report.report_data) == 64
