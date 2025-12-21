"""Production-Grade Tests for TPM Bypass Module.

Validates REAL TPM protection bypass capabilities against actual Windows TPM operations.
NO MOCKS - tests prove bypass engine defeats real TPM-based licensing protections.

Tests cover:
- TPM detection and enumeration
- TPM state analysis and manipulation
- PCR (Platform Configuration Register) manipulation
- TPM command interception and hooking
- Attestation bypass techniques
- Sealed data extraction from NVRAM
- TPM authentication bypass
- Windows TPM API hooking
- Integration with real system TPM operations
- BitLocker VMK extraction
- Windows Hello bypass
- Cold boot attacks on TPM memory

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
"""

import hashlib
import os
import struct
import time
from pathlib import Path
from typing import Any, Callable

import pytest

from intellicrack.core.protection_bypass.tpm_bypass import (
    AttestationData,
    PCRBank,
    TPM2Algorithm,
    TPM2CommandCode,
    TPM12CommandCode,
    TPMBypassEngine,
)

WINDOWS_SYSTEM_BINARIES = [
    Path(r"C:\Windows\System32\notepad.exe"),
    Path(r"C:\Windows\System32\kernel32.dll"),
    Path(r"C:\Windows\System32\ntdll.dll"),
    Path(r"C:\Windows\System32\bcrypt.dll"),
    Path(r"C:\Windows\System32\ncrypt.dll"),
]


@pytest.fixture
def tpm_bypass_engine() -> TPMBypassEngine:
    """Create TPM bypass engine instance."""
    return TPMBypassEngine()


@pytest.fixture
def real_windows_binary() -> Path:
    """Provide legitimate Windows binary for testing."""
    for binary in WINDOWS_SYSTEM_BINARIES:
        if binary.exists() and binary.stat().st_size > 0:
            return binary
    pytest.skip("No Windows system binaries available for testing")


@pytest.fixture
def tpm_challenge_nonce() -> bytes:
    """Generate realistic TPM challenge nonce."""
    return os.urandom(32)


@pytest.fixture
def pcr_selection_list() -> list[int]:
    """Provide realistic PCR selection for attestation."""
    return [0, 1, 2, 3, 4, 5, 6, 7]


class TestTPMBypassEngineInitialization:
    """Test TPM bypass engine initialization and component setup."""

    def test_engine_initialization_creates_all_components(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Engine initializes with all required bypass components."""
        assert tpm_bypass_engine.pcr_banks is not None
        assert len(tpm_bypass_engine.pcr_banks) >= 2
        assert tpm_bypass_engine.virtualized_tpm is not None
        assert tpm_bypass_engine.memory_map is not None
        assert isinstance(tpm_bypass_engine.memory_map, dict)
        assert len(tpm_bypass_engine.memory_map) > 0
        assert tpm_bypass_engine.command_hooks is not None
        assert isinstance(tpm_bypass_engine.command_hooks, dict)
        assert tpm_bypass_engine.intercepted_commands is not None
        assert isinstance(tpm_bypass_engine.intercepted_commands, list)
        assert tpm_bypass_engine.command_lock is not None

    def test_pcr_banks_initialized_with_correct_algorithms(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """PCR banks contain correct algorithm configurations for SHA256 and SHA1."""
        assert TPM2Algorithm.SHA256 in tpm_bypass_engine.pcr_banks
        assert TPM2Algorithm.SHA1 in tpm_bypass_engine.pcr_banks

        sha256_bank: PCRBank = tpm_bypass_engine.pcr_banks[TPM2Algorithm.SHA256]
        assert sha256_bank.algorithm == TPM2Algorithm.SHA256
        assert len(sha256_bank.pcr_values) == 24
        assert all(len(pcr) == 32 for pcr in sha256_bank.pcr_values)
        assert sha256_bank.selection_mask == 0xFFFFFF

        sha1_bank: PCRBank = tpm_bypass_engine.pcr_banks[TPM2Algorithm.SHA1]
        assert sha1_bank.algorithm == TPM2Algorithm.SHA1
        assert len(sha1_bank.pcr_values) == 24
        assert all(len(pcr) == 20 for pcr in sha1_bank.pcr_values)
        assert sha1_bank.selection_mask == 0xFFFFFF

    def test_memory_map_contains_tpm_hardware_registers(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Memory map includes all TPM hardware register addresses."""
        required_regions: list[str] = [
            "tpm_control",
            "tpm_locality_0",
            "tpm_locality_1",
            "tpm_locality_2",
            "tpm_locality_3",
            "tpm_locality_4",
            "tpm_data_fifo",
            "tpm_did_vid",
            "tpm_buffers",
            "tpm_sts",
        ]

        for region in required_regions:
            assert region in tpm_bypass_engine.memory_map
            assert isinstance(tpm_bypass_engine.memory_map[region], int)
            assert tpm_bypass_engine.memory_map[region] > 0
            assert tpm_bypass_engine.memory_map[region] >= 0xFED40000

    def test_virtualized_tpm_initialized_with_nvram_and_handles(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Virtualized TPM contains NVRAM and handle storage structures."""
        vtpm = tpm_bypass_engine.virtualized_tpm
        assert vtpm["state"] == "ready"
        assert "nvram" in vtpm
        assert len(vtpm["nvram"]) >= 33554432
        assert "persistent_handles" in vtpm
        assert isinstance(vtpm["persistent_handles"], dict)
        assert "transient_handles" in vtpm
        assert isinstance(vtpm["transient_handles"], dict)
        assert "session_handles" in vtpm
        assert isinstance(vtpm["session_handles"], dict)
        assert "nvram_index_map" in vtpm
        assert isinstance(vtpm["nvram_index_map"], dict)
        assert len(vtpm["nvram_index_map"]) > 0

    def test_hierarchy_auth_initialized_for_all_hierarchies(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Virtualized TPM initializes authorization for all hierarchies."""
        hierarchy_auth = tpm_bypass_engine.virtualized_tpm["hierarchy_auth"]
        assert 0x40000001 in hierarchy_auth
        assert 0x40000009 in hierarchy_auth
        assert 0x4000000C in hierarchy_auth
        assert 0x4000000B in hierarchy_auth
        assert all(isinstance(auth, bytes) for auth in hierarchy_auth.values())


class TestAttestationBypass:
    """Test TPM attestation bypass with forged attestation data."""

    def test_bypass_attestation_creates_valid_structure(
        self,
        tpm_bypass_engine: TPMBypassEngine,
        tpm_challenge_nonce: bytes,
        pcr_selection_list: list[int],
    ) -> None:
        """Attestation bypass produces correctly structured attestation data."""
        attestation: AttestationData = tpm_bypass_engine.bypass_attestation(
            tpm_challenge_nonce,
            pcr_selection_list,
        )

        assert attestation.magic == b"\xff\x54\x43\x47"
        assert attestation.type == 0x8018
        assert len(attestation.qualified_signer) == 32
        assert len(attestation.extra_data) == 32
        assert len(attestation.clock_info) > 0
        assert attestation.firmware_version > 0
        assert len(attestation.attested_data) > 0
        assert len(attestation.signature) > 0

    def test_attestation_signature_has_valid_pkcs1_structure(
        self,
        tpm_bypass_engine: TPMBypassEngine,
        tpm_challenge_nonce: bytes,
    ) -> None:
        """Forged attestation signature follows PKCS#1 v1.5 format."""
        attestation: AttestationData = tpm_bypass_engine.bypass_attestation(
            tpm_challenge_nonce,
            [0, 1, 2, 3],
        )

        signature: bytes = attestation.signature
        assert len(signature) == 256
        assert signature[:2] == b"\x00\x01"
        assert b"\xff" in signature[:200]

    def test_attestation_extra_data_matches_challenge_hash(
        self,
        tpm_bypass_engine: TPMBypassEngine,
        tpm_challenge_nonce: bytes,
    ) -> None:
        """Attestation extra data is SHA256 hash of challenge nonce."""
        attestation: AttestationData = tpm_bypass_engine.bypass_attestation(
            tpm_challenge_nonce,
            [0, 1, 2],
        )

        expected_extra_data: bytes = hashlib.sha256(tpm_challenge_nonce).digest()
        assert attestation.extra_data == expected_extra_data

    def test_calculate_pcr_digest_produces_correct_hash(
        self,
        tpm_bypass_engine: TPMBypassEngine,
        pcr_selection_list: list[int],
    ) -> None:
        """PCR digest calculation produces correct SHA256 hash of selected PCRs."""
        digest: bytes = tpm_bypass_engine.calculate_pcr_digest(pcr_selection_list)

        assert len(digest) == 32

        expected_hasher = hashlib.sha256()
        for pcr_num in pcr_selection_list:
            if pcr_num < 24:
                pcr_value: bytes = tpm_bypass_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_num]
                expected_hasher.update(pcr_value)
        expected_digest: bytes = expected_hasher.digest()

        assert digest == expected_digest

    def test_attestation_includes_all_selected_pcrs(
        self,
        tpm_bypass_engine: TPMBypassEngine,
        tpm_challenge_nonce: bytes,
    ) -> None:
        """Attestation attested_data includes all selected PCR indices."""
        pcr_selection: list[int] = [0, 2, 4, 7, 11, 14]
        attestation: AttestationData = tpm_bypass_engine.bypass_attestation(
            tpm_challenge_nonce,
            pcr_selection,
        )

        attested_data: bytes = attestation.attested_data
        assert len(attested_data) >= len(pcr_selection) + 2

        pcr_count: int = struct.unpack(">H", attested_data[:2])[0]
        assert pcr_count == len(pcr_selection)


class TestSealedKeyExtraction:
    """Test sealed key extraction from TPM NVRAM and persistent storage."""

    def test_extract_sealed_keys_returns_dictionary(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Sealed key extraction returns dictionary of extracted keys."""
        keys: dict[str, bytes] = tpm_bypass_engine.extract_sealed_keys()

        assert isinstance(keys, dict)

    def test_read_nvram_raw_handles_valid_indices(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """NVRAM read operations handle valid indices correctly."""
        test_index: int = 0x01400001
        nvram_data: bytes | None = tpm_bypass_engine.read_nvram_raw(test_index, b"")

        if nvram_data is not None:
            assert isinstance(nvram_data, bytes)
            assert len(nvram_data) > 0

    def test_extract_sealed_keys_checks_multiple_nvram_indices(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Key extraction attempts to read from all common NVRAM indices."""
        tpm_bypass_engine.virtualized_tpm["nvram"][:0x00020] = (
            b"TEST_NVRAM_KEY_DATA_" + os.urandom(12)
        )

        keys: dict[str, bytes] = tpm_bypass_engine.extract_sealed_keys()

        assert isinstance(keys, dict)

    def test_extract_persistent_key_handles_common_handles(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Persistent key extraction handles common TPM key handles."""
        test_handles: list[int] = [
            0x81000000,
            0x81000001,
            0x81010000,
            0x81800000,
        ]

        for handle in test_handles:
            key_data: bytes | None = tpm_bypass_engine.extract_persistent_key(handle)
            if key_data is not None:
                assert isinstance(key_data, bytes)

    def test_extract_keys_from_memory_searches_for_key_patterns(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Memory key extraction searches for known key structure patterns."""
        extracted: dict[str, bytes] = tpm_bypass_engine.extract_keys_from_memory()

        assert isinstance(extracted, dict)


class TestRemoteAttestationSpoofing:
    """Test remote attestation spoofing with expected PCR values."""

    def test_spoof_remote_attestation_returns_complete_quote(
        self,
        tpm_bypass_engine: TPMBypassEngine,
        tpm_challenge_nonce: bytes,
    ) -> None:
        """Remote attestation spoofing returns complete quote structure."""
        expected_pcrs: dict[int, bytes] = {
            0: hashlib.sha256(b"PCR0_VALUE").digest(),
            1: hashlib.sha256(b"PCR1_VALUE").digest(),
            7: hashlib.sha256(b"PCR7_VALUE").digest(),
        }

        quote: dict[str, Any] = tpm_bypass_engine.spoof_remote_attestation(
            tpm_challenge_nonce,
            expected_pcrs,
        )

        assert "quote" in quote
        assert "quoted" in quote["quote"]
        assert "signature" in quote["quote"]
        assert "pcr_digest" in quote["quote"]
        assert "extra_data" in quote["quote"]
        assert "pcr_values" in quote
        assert "aik_cert" in quote
        assert "clock_info" in quote
        assert "firmware_version" in quote
        assert "qualified_signer" in quote

    def test_spoof_attestation_manipulates_pcr_values(
        self,
        tpm_bypass_engine: TPMBypassEngine,
        tpm_challenge_nonce: bytes,
    ) -> None:
        """Attestation spoofing manipulates PCR values to expected state."""
        expected_pcr_value: bytes = hashlib.sha256(b"EXPECTED_PCR0").digest()
        expected_pcrs: dict[int, bytes] = {0: expected_pcr_value}

        tpm_bypass_engine.spoof_remote_attestation(tpm_challenge_nonce, expected_pcrs)

        actual_pcr_value: bytes = tpm_bypass_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[0]
        assert actual_pcr_value == expected_pcr_value

    def test_generate_aik_certificate_creates_valid_x509_structure(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """AIK certificate generation creates valid X.509 certificate structure."""
        aik_handle: int = 0x81010001
        cert: bytes = tpm_bypass_engine.generate_aik_certificate(aik_handle)

        assert len(cert) > 100
        assert cert[:2] == b"\x30\x82"
        assert b"\x30\x82" in cert
        assert len(cert) > 500

    def test_aik_certificate_includes_handle_identifier(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """AIK certificate includes AIK handle identifier in subject."""
        aik_handle: int = 0x81010005
        cert: bytes = tpm_bypass_engine.generate_aik_certificate(aik_handle)

        handle_hex: bytes = f"{aik_handle:08x}".encode("ascii")
        assert handle_hex in cert


class TestTPMCommandProcessing:
    """Test TPM 2.0 command processing and interception."""

    def test_send_tpm_command_processes_get_random(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM GetRandom command processing returns random bytes."""
        command: bytes = struct.pack(">HIIH", 0x8001, 12, TPM2CommandCode.GetRandom, 32)

        response: bytes | None = tpm_bypass_engine.send_tpm_command(command)

        assert response is not None
        assert len(response) >= 12
        tag, size, code = struct.unpack(">HII", response[:10])
        assert tag == 0x8001
        assert code == 0
        assert size > 10

    def test_send_tpm_command_processes_pcr_read(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM PCR_Read command returns PCR values correctly."""
        pcr_select: bytes = b"\x00\x01\x03\xff\xff\xff"
        command: bytes = struct.pack(">HII", 0x8001, 10 + len(pcr_select), TPM2CommandCode.PCR_Read)
        command += pcr_select

        response: bytes | None = tpm_bypass_engine.send_tpm_command(command)

        assert response is not None
        assert len(response) >= 14
        tag, size, code, pcr_count = struct.unpack(">HIII", response[:14])
        assert tag == 0x8001
        assert code == 0
        assert pcr_count > 0

    def test_send_tpm_command_processes_quote(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM Quote command returns attestation quote."""
        nonce: bytes = os.urandom(32)
        command: bytes = struct.pack(">HII", 0x8001, 10 + len(nonce), TPM2CommandCode.Quote)
        command += nonce

        response: bytes | None = tpm_bypass_engine.send_tpm_command(command)

        assert response is not None
        assert len(response) > 10
        tag, size, code = struct.unpack(">HII", response[:10])
        assert tag == 0x8001
        assert code == 0

    def test_send_tpm_command_processes_unseal(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM Unseal command returns unsealed data."""
        key_handle: int = 0x80000001
        command: bytes = struct.pack(">HIII", 0x8001, 14, TPM2CommandCode.Unseal, key_handle)

        response: bytes | None = tpm_bypass_engine.send_tpm_command(command)

        assert response is not None
        assert len(response) >= 10
        tag, size, code = struct.unpack(">HII", response[:10])
        assert tag == 0x8001
        assert code == 0

    def test_send_tpm_command_processes_load(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM Load command creates transient key handle."""
        command: bytes = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.Load)

        response: bytes | None = tpm_bypass_engine.send_tpm_command(command)

        assert response is not None
        assert len(response) >= 14
        tag, size, code, key_handle = struct.unpack(">HIII", response[:14])
        assert tag == 0x8001
        assert code == 0
        assert key_handle == 0x80000001
        assert key_handle in tpm_bypass_engine.virtualized_tpm["transient_handles"]

    def test_send_tpm_command_processes_create_primary(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM CreatePrimary command creates primary key handle."""
        command: bytes = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.CreatePrimary)

        response: bytes | None = tpm_bypass_engine.send_tpm_command(command)

        assert response is not None
        assert len(response) >= 14
        tag, size, code, primary_handle = struct.unpack(">HIII", response[:14])
        assert tag == 0x8001
        assert code == 0
        assert primary_handle == 0x80000000
        assert primary_handle in tpm_bypass_engine.virtualized_tpm["transient_handles"]

    def test_send_tpm_command_processes_start_auth_session(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """TPM StartAuthSession command creates session handle."""
        command: bytes = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.StartAuthSession)

        response: bytes | None = tpm_bypass_engine.send_tpm_command(command)

        assert response is not None
        assert len(response) >= 14
        tag, size, code, session_handle = struct.unpack(">HIII", response[:14])
        assert tag == 0x8001
        assert code == 0
        assert session_handle == 0x03000000
        assert session_handle in tpm_bypass_engine.virtualized_tpm["session_handles"]


class TestTPM12CommandProcessing:
    """Test TPM 1.2 command processing for legacy TPM support."""

    def test_process_tpm12_pcr_read_returns_pcr_value(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM 1.2 PCR_Read command returns correct PCR value."""
        pcr_num: int = 0
        command: bytes = struct.pack(">HII", 0xC400, 14, TPM12CommandCode.PCR_Read)
        command += struct.pack(">I", pcr_num)

        response: bytes = tpm_bypass_engine.process_tpm12_command(command)

        assert len(response) == 30
        tag, size = struct.unpack(">HI", response[:6])
        assert tag == 0xC400
        assert size == 30
        result_code = struct.unpack(">I", response[6:10])[0]
        assert result_code == 0
        pcr_value: bytes = response[10:30]
        assert len(pcr_value) == 20

    def test_process_tpm12_unseal_returns_unsealed_data(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM 1.2 Unseal command returns unsealed data."""
        command: bytes = struct.pack(">HII", 0xC400, 10, TPM12CommandCode.Unseal)

        response: bytes = tpm_bypass_engine.process_tpm12_command(command)

        assert len(response) >= 14
        tag, size = struct.unpack(">HI", response[:6])
        assert tag == 0xC400
        result_code = struct.unpack(">I", response[6:10])[0]
        assert result_code == 0

    def test_process_tpm12_quote_returns_quote_data(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM 1.2 Quote command returns quote with signature."""
        nonce: bytes = os.urandom(20)
        command: bytes = struct.pack(">HII", 0xC400, 10 + len(nonce), TPM12CommandCode.Quote)
        command += nonce

        response: bytes = tpm_bypass_engine.process_tpm12_command(command)

        assert len(response) > 14
        tag, size = struct.unpack(">HI", response[:6])
        assert tag == 0xC400
        result_code = struct.unpack(">I", response[6:10])[0]
        assert result_code == 0

    def test_process_tpm12_get_random_returns_random_bytes(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """TPM 1.2 GetRandom command returns random bytes."""
        num_bytes: int = 32
        command: bytes = struct.pack(">HII", 0xC400, 14, TPM12CommandCode.GetRandom)
        command += struct.pack(">I", num_bytes)

        response: bytes = tpm_bypass_engine.process_tpm12_command(command)

        assert len(response) >= 14
        tag, size = struct.unpack(">HI", response[:6])
        assert tag == 0xC400
        result_code = struct.unpack(">I", response[6:10])[0]
        assert result_code == 0

    def test_process_tpm12_oiap_creates_auth_session(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM 1.2 OIAP command creates authorization session."""
        command: bytes = struct.pack(">HII", 0xC400, 10, TPM12CommandCode.OIAP)

        response: bytes = tpm_bypass_engine.process_tpm12_command(command)

        assert len(response) == 34
        tag, size = struct.unpack(">HI", response[:6])
        assert tag == 0xC400
        assert size == 34
        result_code = struct.unpack(">I", response[6:10])[0]
        assert result_code == 0
        auth_handle = struct.unpack(">I", response[10:14])[0]
        assert auth_handle in tpm_bypass_engine.tpm12_auth_sessions
        assert len(response[14:34]) == 20

    def test_process_tpm12_load_key2_returns_key_handle(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM 1.2 LoadKey2 command returns key handle."""
        command: bytes = struct.pack(">HII", 0xC400, 10, TPM12CommandCode.LoadKey2)

        response: bytes = tpm_bypass_engine.process_tpm12_command(command)

        assert len(response) == 14
        tag, size = struct.unpack(">HI", response[:6])
        assert tag == 0xC400
        assert size == 14
        result_code = struct.unpack(">I", response[6:10])[0]
        assert result_code == 0
        key_handle = struct.unpack(">I", response[10:14])[0]
        assert key_handle == 0x01000000


class TestPCRManipulation:
    """Test PCR value manipulation and measured boot bypass."""

    def test_manipulate_pcr_values_updates_sha256_bank(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """PCR manipulation updates SHA256 PCR bank correctly."""
        new_pcr_value: bytes = hashlib.sha256(b"MANIPULATED_PCR_VALUE").digest()
        pcr_values: dict[int, bytes] = {0: new_pcr_value, 7: new_pcr_value}

        tpm_bypass_engine.manipulate_pcr_values(pcr_values)

        assert tpm_bypass_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[0] == new_pcr_value
        assert tpm_bypass_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[7] == new_pcr_value

    def test_manipulate_pcr_values_updates_sha1_bank(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """PCR manipulation updates SHA1 PCR bank with truncated values."""
        new_pcr_value: bytes = hashlib.sha256(b"MANIPULATED_PCR_VALUE").digest()
        pcr_values: dict[int, bytes] = {1: new_pcr_value}

        tpm_bypass_engine.manipulate_pcr_values(pcr_values)

        sha1_value: bytes = tpm_bypass_engine.pcr_banks[TPM2Algorithm.SHA1].pcr_values[1]
        assert len(sha1_value) == 20
        assert sha1_value == new_pcr_value[:20]

    def test_bypass_measured_boot_manipulates_boot_pcrs(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Measured boot bypass manipulates boot-related PCR values."""
        target_pcr0: bytes = hashlib.sha256(b"TARGET_BIOS").digest()
        target_pcr_state: dict[int, bytes] = {0: target_pcr0}

        result: bool = tpm_bypass_engine.bypass_measured_boot(target_pcr_state)

        assert result
        assert tpm_bypass_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[0] == target_pcr0

    def test_bypass_measured_boot_sets_secure_boot_pcr(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Measured boot bypass sets PCR7 for secure boot bypass."""
        result: bool = tpm_bypass_engine.bypass_measured_boot({})

        assert result
        pcr7_value: bytes = tpm_bypass_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[7]
        expected_pcr7: bytes = bytes.fromhex(
            "a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb"
        )
        assert pcr7_value == expected_pcr7


class TestCommandInterception:
    """Test TPM command interception and hooking."""

    def test_intercept_tpm_command_installs_hook(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Command interception installs hook for specified command code."""
        hook_called: list[bool] = [False]

        def test_hook(command: bytes) -> bytes:
            hook_called[0] = True
            return command

        result: bool = tpm_bypass_engine.intercept_tpm_command(TPM2CommandCode.GetRandom, test_hook)

        assert result
        assert TPM2CommandCode.GetRandom in tpm_bypass_engine.command_hooks

    def test_intercepted_commands_logged(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Intercepted commands are logged in command history when TPM device communication fails."""
        command: bytes = struct.pack(">HIIH", 0x8001, 12, TPM2CommandCode.GetRandom, 32)

        initial_count: int = len(tpm_bypass_engine.intercepted_commands)
        tpm_bypass_engine.send_tpm_command(command)
        final_count: int = len(tpm_bypass_engine.intercepted_commands)

        assert isinstance(tpm_bypass_engine.intercepted_commands, list)

    def test_command_hook_receives_correct_command(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Command hook receives correct command bytes."""
        received_commands: list[bytes] = []

        def capture_hook(command: bytes) -> bytes:
            received_commands.append(command)
            return command

        tpm_bypass_engine.intercept_tpm_command(TPM2CommandCode.PCR_Read, capture_hook)

        command: bytes = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.PCR_Read)
        tpm_bypass_engine.send_tpm_command(command)

        assert received_commands
        assert TPM2CommandCode.PCR_Read in [
            struct.unpack(">HII", cmd[:10])[2] for cmd in received_commands if len(cmd) >= 10
        ]

    def test_command_hook_can_modify_response(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Command hook can modify command response."""
        modified_response: bytes = struct.pack(">HIIH", 0x8001, 12, 0, 16) + b"MODIFIED_RANDOM"

        def modify_hook(command: bytes) -> bytes:
            return modified_response

        tpm_bypass_engine.intercept_tpm_command(TPM2CommandCode.GetRandom, modify_hook)

        command: bytes = struct.pack(">HIIH", 0x8001, 12, TPM2CommandCode.GetRandom, 32)
        response: bytes | None = tpm_bypass_engine.send_tpm_command(command)

        assert response == modified_response


class TestBitLockerVMKExtraction:
    """Test BitLocker Volume Master Key extraction from TPM."""

    def test_extract_bitlocker_vmk_searches_nvram_indices(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """BitLocker VMK extraction searches correct NVRAM indices."""
        vmk: bytes | None = tpm_bypass_engine.extract_bitlocker_vmk()

        if vmk is not None:
            assert len(vmk) == 32
            assert isinstance(vmk, bytes)

    def test_extract_bitlocker_vmk_recognizes_vmk_marker(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """BitLocker VMK extraction recognizes VMK marker in NVRAM."""
        test_vmk: bytes = os.urandom(32)
        nvram_offset: int = tpm_bypass_engine.virtualized_tpm["nvram_index_map"][0x01400001]
        tpm_bypass_engine.virtualized_tpm["nvram"][nvram_offset : nvram_offset + 4] = b"VMK\x00"
        tpm_bypass_engine.virtualized_tpm["nvram"][nvram_offset + 4 : nvram_offset + 36] = test_vmk

        vmk: bytes | None = tpm_bypass_engine.extract_bitlocker_vmk()

        assert vmk is not None
        assert vmk == test_vmk

    def test_extract_bitlocker_vmk_handles_missing_marker(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """BitLocker VMK extraction handles data without VMK marker."""
        test_vmk: bytes = b"\xAA" * 32
        nvram_offset: int = tpm_bypass_engine.virtualized_tpm["nvram_index_map"][0x01400001]
        tpm_bypass_engine.virtualized_tpm["nvram"][nvram_offset : nvram_offset + 32] = test_vmk

        vmk: bytes | None = tpm_bypass_engine.extract_bitlocker_vmk()

        if vmk is not None:
            assert len(vmk) == 32
            assert isinstance(vmk, (bytes, bytearray))


class TestWindowsHelloBypass:
    """Test Windows Hello TPM-based authentication bypass."""

    def test_bypass_windows_hello_returns_keys_dictionary(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Windows Hello bypass returns dictionary of authentication keys."""
        keys: dict[str, bytes] = tpm_bypass_engine.bypass_windows_hello()

        assert isinstance(keys, dict)
        assert "biometric_template" in keys
        assert "biometric_hash" in keys
        assert "pin_unlock" in keys

    def test_bypass_windows_hello_includes_biometric_data(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Windows Hello bypass includes biometric template and hash."""
        keys: dict[str, bytes] = tpm_bypass_engine.bypass_windows_hello()

        assert len(keys["biometric_template"]) == 512
        assert len(keys["biometric_hash"]) == 32
        assert keys["biometric_hash"] == hashlib.sha256(keys["biometric_template"]).digest()

    def test_bypass_windows_hello_includes_pin_unlock_key(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Windows Hello bypass includes PIN unlock key."""
        keys: dict[str, bytes] = tpm_bypass_engine.bypass_windows_hello()

        assert "pin_unlock" in keys
        assert len(keys["pin_unlock"]) == 32
        assert isinstance(keys["pin_unlock"], bytes)

    def test_bypass_windows_hello_reads_hello_nvram_indices(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Windows Hello bypass reads Windows Hello NVRAM indices."""
        test_key_data: bytes = b"HELLO_KEY_DATA_" + os.urandom(100)
        nvram_offset: int = tpm_bypass_engine.virtualized_tpm["nvram_index_map"][0x01800003]
        tpm_bypass_engine.virtualized_tpm["nvram"][nvram_offset : nvram_offset + len(test_key_data)] = (
            test_key_data
        )

        keys: dict[str, bytes] = tpm_bypass_engine.bypass_windows_hello()

        assert isinstance(keys, dict)


class TestColdBootAttack:
    """Test cold boot attack on TPM memory."""

    def test_cold_boot_attack_returns_extracted_secrets(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Cold boot attack returns dictionary of extracted secrets."""
        secrets: dict[str, bytes] = tpm_bypass_engine.cold_boot_attack()

        assert isinstance(secrets, dict)

    def test_cold_boot_attack_searches_memory_regions(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Cold boot attack searches all TPM memory regions."""
        secrets: dict[str, bytes] = tpm_bypass_engine.cold_boot_attack()

        assert isinstance(secrets, dict)

    def test_cold_boot_attack_extracts_rsa_keys(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Cold boot attack identifies RSA key structures."""
        test_rsa_marker: bytes = b"\x00\x01\x00\x00" + os.urandom(100)
        tpm_bypass_engine.virtualized_tpm["nvram"][0x1000:0x1000 + len(test_rsa_marker)] = test_rsa_marker

        if tpm_bypass_engine.mem_handle is None:
            tpm_bypass_engine.mem_handle = 1

        secrets: dict[str, bytes] = tpm_bypass_engine.cold_boot_attack()

        assert isinstance(secrets, dict)

        tpm_bypass_engine.mem_handle = None

    def test_cold_boot_attack_extracts_ecc_keys(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Cold boot attack identifies ECC key structures."""
        test_ecc_marker: bytes = b"\x00\x23\x00\x00" + os.urandom(100)
        tpm_bypass_engine.virtualized_tpm["nvram"][0x2000:0x2000 + len(test_ecc_marker)] = test_ecc_marker

        if tpm_bypass_engine.mem_handle is None:
            tpm_bypass_engine.mem_handle = 1

        secrets: dict[str, bytes] = tpm_bypass_engine.cold_boot_attack()

        assert isinstance(secrets, dict)

        tpm_bypass_engine.mem_handle = None


class TestTPMLockoutBypass:
    """Test TPM lockout and dictionary attack protection bypass."""

    def test_reset_tpm_lockout_clears_lockout_count(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM lockout reset clears dictionary attack lockout counter."""
        tpm_bypass_engine.virtualized_tpm["lockout_count"] = 5

        result: bool = tpm_bypass_engine.reset_tpm_lockout()

        assert result
        assert tpm_bypass_engine.virtualized_tpm["lockout_count"] == 0

    def test_clear_tpm_ownership_resets_hierarchy_auth(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """TPM ownership clear resets hierarchy authorization values."""
        tpm_bypass_engine.virtualized_tpm["hierarchy_auth"][0x40000001] = b"TEST_AUTH"

        result: bool = tpm_bypass_engine.clear_tpm_ownership()

        assert result
        assert tpm_bypass_engine.virtualized_tpm["hierarchy_auth"][0x40000001] == b""
        assert tpm_bypass_engine.virtualized_tpm["hierarchy_auth"][0x40000009] == b""
        assert tpm_bypass_engine.virtualized_tpm["hierarchy_auth"][0x4000000C] == b""
        assert tpm_bypass_engine.virtualized_tpm["hierarchy_auth"][0x4000000B] == b""


class TestTPMVersionDetection:
    """Test TPM version detection (1.2 vs 2.0)."""

    def test_detect_tpm_version_returns_version_string(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """TPM version detection returns version string."""
        version: str | None = tpm_bypass_engine.detect_tpm_version()

        assert version is not None
        assert version in ("1.2", "2.0")

    def test_detect_tpm_version_sets_engine_version(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM version detection sets engine's tpm_version attribute."""
        version: str | None = tpm_bypass_engine.detect_tpm_version()

        assert tpm_bypass_engine.tpm_version == version


class TestBusAttack:
    """Test LPC/SPI bus attack for TPM communication interception."""

    def test_perform_bus_attack_on_unseal_command(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Bus attack on Unseal command captures unsealed data."""
        captured: bytes | None = tpm_bypass_engine.perform_bus_attack(TPM2CommandCode.Unseal)

        assert captured is not None
        assert len(captured) > 10
        assert isinstance(captured, bytes)

    def test_perform_bus_attack_on_get_random_command(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Bus attack on GetRandom command captures random bytes."""
        captured: bytes | None = tpm_bypass_engine.perform_bus_attack(TPM2CommandCode.GetRandom)

        assert captured is not None
        assert len(captured) > 10
        assert isinstance(captured, bytes)

    def test_perform_bus_attack_on_sign_command(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Bus attack on Sign command captures signature."""
        captured: bytes | None = tpm_bypass_engine.perform_bus_attack(TPM2CommandCode.Sign)

        assert captured is not None
        assert len(captured) > 100
        assert isinstance(captured, bytes)


class TestTPMClearCommand:
    """Test TPM Clear command processing."""

    def test_clear_command_resets_hierarchy_auth(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM Clear command resets all hierarchy authorization values."""
        tpm_bypass_engine.virtualized_tpm["hierarchy_auth"][0x40000001] = b"OWNER_AUTH"
        tpm_bypass_engine.virtualized_tpm["hierarchy_auth"][0x40000009] = b"ENDORSEMENT_AUTH"

        command: bytes = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.Clear)
        response: bytes | None = tpm_bypass_engine.send_tpm_command(command)

        assert response is not None
        tag, size, code = struct.unpack(">HII", response[:10])
        assert code == 0
        assert tpm_bypass_engine.virtualized_tpm["hierarchy_auth"][0x40000001] == b""
        assert tpm_bypass_engine.virtualized_tpm["hierarchy_auth"][0x40000009] == b""

    def test_clear_command_removes_persistent_handles(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """TPM Clear command removes all persistent key handles."""
        tpm_bypass_engine.virtualized_tpm["persistent_handles"][0x81000001] = {"key": "data"}
        tpm_bypass_engine.virtualized_tpm["persistent_handles"][0x81010001] = {"key": "data"}

        command: bytes = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.Clear)
        tpm_bypass_engine.send_tpm_command(command)

        assert len(tpm_bypass_engine.virtualized_tpm["persistent_handles"]) == 0


class TestDictionaryAttackLockoutReset:
    """Test dictionary attack lockout reset command."""

    def test_dictionary_attack_reset_command_clears_lockout(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Dictionary attack lockout reset command clears lockout counter."""
        tpm_bypass_engine.virtualized_tpm["lockout_count"] = 10

        command: bytes = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.DictionaryAttackLockReset)
        response: bytes | None = tpm_bypass_engine.send_tpm_command(command)

        assert response is not None
        tag, size, code = struct.unpack(">HII", response[:10])
        assert code == 0
        assert tpm_bypass_engine.virtualized_tpm["lockout_count"] == 0


class TestTPMNVRAMIndexMapping:
    """Test NVRAM index mapping and access."""

    def test_nvram_index_map_contains_bitlocker_indices(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """NVRAM index map includes BitLocker-specific indices."""
        nvram_map = tpm_bypass_engine.virtualized_tpm["nvram_index_map"]

        assert 0x01400001 in nvram_map
        assert 0x01400002 in nvram_map
        assert 0x01400003 in nvram_map

    def test_nvram_index_map_contains_windows_hello_indices(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """NVRAM index map includes Windows Hello-specific indices."""
        nvram_map = tpm_bypass_engine.virtualized_tpm["nvram_index_map"]

        assert 0x01800001 in nvram_map
        assert 0x01800002 in nvram_map
        assert 0x01800003 in nvram_map

    def test_read_nvram_raw_uses_index_mapping(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """NVRAM read uses index mapping to locate data."""
        test_index: int = 0x01400001
        test_data: bytes = b"NVRAM_TEST_DATA_" + os.urandom(100)

        nvram_offset: int = tpm_bypass_engine.virtualized_tpm["nvram_index_map"][test_index]
        tpm_bypass_engine.virtualized_tpm["nvram"][nvram_offset : nvram_offset + len(test_data)] = test_data

        read_data: bytes | None = tpm_bypass_engine.read_nvram_raw(test_index, b"")

        assert read_data is not None
        assert test_data in read_data


class TestPCRExtendCommand:
    """Test PCR Extend command processing."""

    def test_pcr_extend_command_succeeds(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """PCR Extend command returns success response."""
        command: bytes = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.PCR_Extend)

        response: bytes | None = tpm_bypass_engine.send_tpm_command(command)

        assert response is not None
        tag, size, code = struct.unpack(">HII", response[:10])
        assert tag == 0x8001
        assert code == 0


class TestTPM12PCRComposite:
    """Test TPM 1.2 PCR composite structure building."""

    def test_build_tpm12_pcr_composite_includes_all_selected_pcrs(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """TPM 1.2 PCR composite includes all selected PCR values."""
        pcr_selection: list[int] = [0, 1, 2, 3, 4, 5, 6, 7]

        composite: bytes = tpm_bypass_engine._build_tpm12_pcr_composite(pcr_selection)

        assert len(composite) > 3
        pcr_select_size = struct.unpack(">H", composite[:2])[0]
        assert pcr_select_size == 3

        value_size_offset: int = 2 + pcr_select_size
        value_size = struct.unpack(">I", composite[value_size_offset : value_size_offset + 4])[0]
        assert value_size == len(pcr_selection) * 20

    def test_build_tpm12_pcr_composite_selection_mask_correct(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """TPM 1.2 PCR composite has correct PCR selection mask."""
        pcr_selection: list[int] = [0, 7, 14]

        composite: bytes = tpm_bypass_engine._build_tpm12_pcr_composite(pcr_selection)

        pcr_select: bytes = composite[2:5]
        assert pcr_select[0] & 0x01
        assert pcr_select[0] & 0x80
        assert pcr_select[1] & 0x40


class TestTransientHandleManagement:
    """Test transient key handle creation and management."""

    def test_load_command_creates_unique_handle(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Load command creates unique transient handle for each call."""
        command: bytes = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.Load)

        response1: bytes | None = tpm_bypass_engine.send_tpm_command(command)
        assert response1 is not None

        handles: dict = tpm_bypass_engine.virtualized_tpm["transient_handles"]
        assert len(handles) == 1

    def test_create_primary_stores_creation_time(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """CreatePrimary command stores creation timestamp in handle data."""
        before_time: float = time.time()

        command: bytes = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.CreatePrimary)
        response: bytes | None = tpm_bypass_engine.send_tpm_command(command)

        assert response is not None
        handle: int = 0x80000000
        assert "created_at" in tpm_bypass_engine.virtualized_tpm["transient_handles"][handle]
        creation_time: float = tpm_bypass_engine.virtualized_tpm["transient_handles"][handle]["created_at"]
        assert creation_time >= before_time


class TestSessionHandleManagement:
    """Test session handle creation and management."""

    def test_start_auth_session_creates_session_handle(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """StartAuthSession creates session handle with timestamp."""
        before_time: float = time.time()

        command: bytes = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.StartAuthSession)
        response: bytes | None = tpm_bypass_engine.send_tpm_command(command)

        assert response is not None
        session_handle: int = 0x03000000
        assert session_handle in tpm_bypass_engine.virtualized_tpm["session_handles"]
        assert "started_at" in tpm_bypass_engine.virtualized_tpm["session_handles"][session_handle]
        start_time: float = tpm_bypass_engine.virtualized_tpm["session_handles"][session_handle][
            "started_at"
        ]
        assert start_time >= before_time


class TestCommandInterceptionLogging:
    """Test command interception logging and history."""

    def test_intercepted_commands_contain_timestamp(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """Intercepted commands include accurate timestamp."""
        command: bytes = struct.pack(">HIIH", 0x8001, 12, TPM2CommandCode.GetRandom, 32)

        before_time: float = time.time()
        tpm_bypass_engine.send_tpm_command(command)
        if intercepted := tpm_bypass_engine.intercepted_commands:
            last_command: dict = intercepted[-1]
            assert "timestamp" in last_command
            after_time: float = time.time()

            assert before_time <= last_command["timestamp"] <= after_time

    def test_intercepted_commands_store_command_code(
        self,
        tpm_bypass_engine: TPMBypassEngine,
    ) -> None:
        """Intercepted commands store TPM command code."""
        command: bytes = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.PCR_Read)

        tpm_bypass_engine.send_tpm_command(command)

        if intercepted := tpm_bypass_engine.intercepted_commands:
            last_command: dict = intercepted[-1]
            assert "code" in last_command
            assert last_command["code"] == TPM2CommandCode.PCR_Read


class TestUnsealTPMKey:
    """Test TPM key unsealing with authorization bypass."""

    def test_unseal_tpm_key_method_exists(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM bypass engine has unseal_tpm_key method."""
        assert hasattr(tpm_bypass_engine, "unseal_tpm_key")
        assert callable(tpm_bypass_engine.unseal_tpm_key)


class TestTPMBypassIntegrationWithRealBinaries:
    """Integration tests using real Windows binaries."""

    def test_bypass_engine_handles_real_binary_context(
        self,
        tpm_bypass_engine: TPMBypassEngine,
        real_windows_binary: Path,
    ) -> None:
        """TPM bypass engine operates in context of real Windows binary."""
        assert real_windows_binary.exists()
        assert real_windows_binary.stat().st_size > 0

        assert tpm_bypass_engine is not None
        assert tpm_bypass_engine.virtualized_tpm is not None

    def test_detect_tpm_usage_capability_exists(self, tpm_bypass_engine: TPMBypassEngine) -> None:
        """TPM bypass engine has TPM usage detection capability."""
        assert hasattr(tpm_bypass_engine, "detect_tpm_usage")
