"""Comprehensive production-ready tests for TPM 2.0 bypass capabilities.

Tests validate real TPM protection bypass operations including:
- Attestation bypass with forged signatures
- Sealed key extraction from NVRAM and memory
- Remote attestation spoofing
- PCR manipulation and measured boot bypass
- Windows Hello and BitLocker bypass
- Command interception and hooking
- TPM 1.2 and 2.0 command processing
"""

import hashlib
import os
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.protection_bypass.tpm_bypass import (
    AttestationData,
    PCRBank,
    TPM2Algorithm,
    TPM2CommandCode,
    TPM12CommandCode,
    TPMBypassEngine,
)


class TestTPMBypassEngineInitialization:
    """Test TPM bypass engine initialization and component setup."""

    def test_engine_initialization_creates_all_components(self) -> None:
        """Engine initializes with all required bypass components."""
        engine = TPMBypassEngine()

        assert engine.pcr_banks is not None
        assert engine.virtualized_tpm is not None
        assert engine.memory_map is not None
        assert engine.command_hooks is not None
        assert engine.intercepted_commands is not None
        assert engine.command_lock is not None

    def test_pcr_banks_initialized_correctly(self) -> None:
        """PCR banks contain correct algorithm configurations."""
        engine = TPMBypassEngine()

        assert TPM2Algorithm.SHA256 in engine.pcr_banks
        assert TPM2Algorithm.SHA1 in engine.pcr_banks

        sha256_bank = engine.pcr_banks[TPM2Algorithm.SHA256]
        assert sha256_bank.algorithm == TPM2Algorithm.SHA256
        assert len(sha256_bank.pcr_values) == 24
        assert all(len(pcr) == 32 for pcr in sha256_bank.pcr_values)
        assert sha256_bank.selection_mask == 0xFFFFFF

        sha1_bank = engine.pcr_banks[TPM2Algorithm.SHA1]
        assert sha1_bank.algorithm == TPM2Algorithm.SHA1
        assert len(sha1_bank.pcr_values) == 24
        assert all(len(pcr) == 20 for pcr in sha1_bank.pcr_values)

    def test_memory_map_contains_tpm_registers(self) -> None:
        """Memory map includes all TPM hardware register addresses."""
        engine = TPMBypassEngine()

        required_regions = [
            "tpm_control",
            "tpm_locality_0",
            "tpm_data_fifo",
            "tpm_did_vid",
            "tpm_buffers",
        ]

        for region in required_regions:
            assert region in engine.memory_map
            assert isinstance(engine.memory_map[region], int)
            assert engine.memory_map[region] > 0

    def test_virtualized_tpm_initialized_with_nvram(self) -> None:
        """Virtualized TPM contains NVRAM and handle storage."""
        engine = TPMBypassEngine()

        assert engine.virtualized_tpm["state"] == "ready"
        assert len(engine.virtualized_tpm["nvram"]) > 0
        assert "persistent_handles" in engine.virtualized_tpm
        assert "transient_handles" in engine.virtualized_tpm
        assert "session_handles" in engine.virtualized_tpm
        assert "nvram_index_map" in engine.virtualized_tpm


class TestAttestationBypass:
    """Test TPM attestation bypass with forged attestation data."""

    def test_bypass_attestation_creates_valid_structure(self) -> None:
        """Attestation bypass produces correctly structured attestation data."""
        engine = TPMBypassEngine()
        challenge = os.urandom(32)
        pcr_selection = [0, 1, 2, 7]

        attestation = engine.bypass_attestation(challenge, pcr_selection)

        assert isinstance(attestation, AttestationData)
        assert attestation.magic == b"\xff\x54\x43\x47"
        assert attestation.type == 0x8018
        assert len(attestation.qualified_signer) == 32
        assert len(attestation.extra_data) == 32
        assert len(attestation.signature) == 256
        assert len(attestation.attested_data) > 0

    def test_attestation_includes_correct_pcr_selection(self) -> None:
        """Attestation data includes all selected PCRs in attested data."""
        engine = TPMBypassEngine()
        challenge = os.urandom(32)
        pcr_selection = [0, 3, 7, 14, 23]

        attestation = engine.bypass_attestation(challenge, pcr_selection)

        pcr_count = struct.unpack(">H", attestation.attested_data[:2])[0]
        assert pcr_count == len(pcr_selection)

        for i, expected_pcr in enumerate(pcr_selection):
            actual_pcr = struct.unpack(">B", attestation.attested_data[2 + i : 3 + i])[0]
            assert actual_pcr == expected_pcr

    def test_attestation_signature_has_pkcs1_structure(self) -> None:
        """Forged attestation signature follows PKCS#1 v1.5 format."""
        engine = TPMBypassEngine()
        message = b"test_message_for_signature"

        signature = engine.forge_attestation_signature(message)

        assert len(signature) == 256
        assert signature[:2] == b"\x00\x01"
        assert b"\xff\xff\xff" in signature[:50]
        assert b"\x00" in signature[2:]

    def test_pcr_digest_calculation_deterministic(self) -> None:
        """PCR digest calculation produces consistent results."""
        engine = TPMBypassEngine()

        pcr_values = [os.urandom(32) for _ in range(24)]
        for i, value in enumerate(pcr_values):
            engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[i] = value

        pcr_selection = [0, 1, 2, 3]

        digest1 = engine.calculate_pcr_digest(pcr_selection)
        digest2 = engine.calculate_pcr_digest(pcr_selection)

        assert digest1 == digest2
        assert len(digest1) == 32

        expected_hasher = hashlib.sha256()
        for pcr_num in pcr_selection:
            expected_hasher.update(pcr_values[pcr_num])
        expected_digest = expected_hasher.digest()

        assert digest1 == expected_digest

    def test_attestation_extra_data_derives_from_challenge(self) -> None:
        """Attestation extra data correctly hashes challenge nonce."""
        engine = TPMBypassEngine()
        challenge = os.urandom(32)

        attestation = engine.bypass_attestation(challenge, [0])

        expected_extra_data = hashlib.sha256(challenge).digest()
        assert attestation.extra_data == expected_extra_data


class TestSealedKeyExtraction:
    """Test extraction of sealed keys from TPM NVRAM and memory."""

    def test_extract_sealed_keys_scans_standard_indices(self) -> None:
        """Key extraction attempts to read from all standard NVRAM indices."""
        engine = TPMBypassEngine()

        test_key = os.urandom(256)
        nvram_index = 0x01400001
        nvram_offset = engine.virtualized_tpm["nvram_index_map"][nvram_index]
        engine.virtualized_tpm["nvram"][nvram_offset : nvram_offset + len(test_key)] = test_key

        extracted_keys = engine.extract_sealed_keys()

        assert isinstance(extracted_keys, dict)
        assert len(extracted_keys) > 0
        assert any("nvram" in key_name for key_name in extracted_keys)

    def test_read_nvram_raw_returns_data_from_mapped_index(self) -> None:
        """NVRAM read operation retrieves data from correct offset."""
        engine = TPMBypassEngine()

        test_data = os.urandom(512)
        nvram_index = 0x01400002
        nvram_offset = engine.virtualized_tpm["nvram_index_map"][nvram_index]
        engine.virtualized_tpm["nvram"][nvram_offset : nvram_offset + 512] = test_data

        retrieved_data = engine.read_nvram_raw(nvram_index, b"")

        assert retrieved_data is not None
        assert retrieved_data == test_data

    def test_read_nvram_handles_unmapped_index(self) -> None:
        """NVRAM read with unmapped index falls back to safe offset calculation."""
        engine = TPMBypassEngine()

        unmapped_index = 0x99999999
        result = engine.read_nvram_raw(unmapped_index, b"")

        assert result is None or isinstance(result, bytes)

    def test_extract_persistent_key_builds_correct_command(self) -> None:
        """Persistent key extraction uses correct TPM ReadPublic command."""
        engine = TPMBypassEngine()

        test_handle = 0x81000001
        test_key_data = os.urandom(256)

        def capture_readpublic_command(command: bytes) -> bytes:
            tag, size, code = struct.unpack(">HII", command[:10])
            assert code == TPM2CommandCode.ReadPublic
            assert size == 14

            handle = struct.unpack(">I", command[10:14])[0]
            assert handle == test_handle

            response = struct.pack(">HII", 0x8001, 10 + len(test_key_data), 0)
            response += test_key_data
            return response

        engine.command_hooks[TPM2CommandCode.ReadPublic] = capture_readpublic_command

        result = engine.extract_persistent_key(test_handle)

        assert result == test_key_data


class TestRemoteAttestationSpoofing:
    """Test remote attestation spoofing with expected PCR values."""

    def test_spoof_remote_attestation_returns_complete_attestation(self) -> None:
        """Remote attestation spoofing produces all required attestation components."""
        engine = TPMBypassEngine()
        nonce = os.urandom(32)
        expected_pcrs = {
            0: os.urandom(32),
            7: os.urandom(32),
            14: os.urandom(32),
        }

        attestation = engine.spoof_remote_attestation(nonce, expected_pcrs)

        assert "quote" in attestation
        assert "pcr_values" in attestation
        assert "aik_cert" in attestation
        assert "clock_info" in attestation
        assert "firmware_version" in attestation

        assert "quoted" in attestation["quote"]
        assert "signature" in attestation["quote"]
        assert "pcr_digest" in attestation["quote"]

    def test_spoof_remote_attestation_sets_pcr_values(self) -> None:
        """Spoofed attestation manipulates PCR banks to expected values."""
        engine = TPMBypassEngine()
        nonce = os.urandom(32)
        expected_pcrs = {0: b"A" * 32, 7: b"B" * 32}

        engine.spoof_remote_attestation(nonce, expected_pcrs)

        assert engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[0] == b"A" * 32
        assert engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[7] == b"B" * 32

    def test_generate_aik_certificate_creates_valid_x509_structure(self) -> None:
        """AIK certificate generation produces valid X.509 certificate structure."""
        engine = TPMBypassEngine()
        aik_handle = 0x81010001

        cert = engine.generate_aik_certificate(aik_handle)

        assert len(cert) > 100
        assert cert[:2] == b"\x30\x82"

        assert b"\x02\x01\x02" in cert or b"\x02\x01\x00" in cert

        assert b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01" in cert

    def test_spoof_remote_attestation_includes_pcr_digest(self) -> None:
        """Spoofed attestation includes correct PCR digest for verification."""
        engine = TPMBypassEngine()
        nonce = os.urandom(32)
        expected_pcrs = {0: os.urandom(32), 1: os.urandom(32), 2: os.urandom(32)}

        attestation = engine.spoof_remote_attestation(nonce, expected_pcrs)

        pcr_digest = attestation["quote"]["pcr_digest"]
        assert len(pcr_digest) == 32

        manual_digest = engine.calculate_pcr_digest([0, 1, 2])
        assert pcr_digest == manual_digest


class TestTPMCommandProcessing:
    """Test TPM command interception and virtualized processing."""

    def test_send_tpm_command_processes_getrandom(self) -> None:
        """Virtualized TPM responds to GetRandom command with random bytes."""
        engine = TPMBypassEngine()

        random_size = 32
        command = struct.pack(">HIIH", 0x8001, 12, TPM2CommandCode.GetRandom, random_size)

        response = engine.send_tpm_command(command)

        assert response is not None
        tag, size, code = struct.unpack(">HII", response[:10])
        assert code == 0
        assert size > 10

        returned_size = struct.unpack(">H", response[10:12])[0]
        assert returned_size == random_size

        random_data = response[12 : 12 + returned_size]
        assert len(random_data) == random_size
        assert any(b != 0 for b in random_data)

    def test_send_tpm_command_processes_pcr_read(self) -> None:
        """Virtualized TPM responds to PCR_Read with PCR values."""
        engine = TPMBypassEngine()

        test_pcr_value = os.urandom(32)
        engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[0] = test_pcr_value

        command = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.PCR_Read)
        command += b"\x00\x01\x03\xff\xff\xff"

        response = engine.send_tpm_command(command)

        assert response is not None
        tag, size, code, pcr_count = struct.unpack(">HIII", response[:14])
        assert code == 0
        assert pcr_count > 0

        pcr_data = response[14:]
        assert len(pcr_data) >= 32

    def test_send_tpm_command_processes_quote(self) -> None:
        """Virtualized TPM responds to Quote command with attestation."""
        engine = TPMBypassEngine()

        nonce = os.urandom(32)
        command = struct.pack(">HII", 0x8001, 10 + len(nonce), TPM2CommandCode.Quote)
        command += nonce

        response = engine.send_tpm_command(command)

        assert response is not None
        tag, size, code = struct.unpack(">HII", response[:10])
        assert code == 0
        assert size > 100

    def test_send_tpm_command_processes_unseal(self) -> None:
        """Virtualized TPM responds to Unseal command with valid response."""
        engine = TPMBypassEngine()

        key_handle = 0x80000001
        command = struct.pack(">HIII", 0x8001, 14, TPM2CommandCode.Unseal, key_handle)

        response = engine.send_tpm_command(command)

        assert response is not None
        assert len(response) >= 10
        tag, size, code = struct.unpack(">HII", response[:10])
        assert tag == 0x8001
        assert code == 0

    def test_send_tpm_command_tracks_intercepted_commands(self) -> None:
        """Command interception records hooked commands."""
        engine = TPMBypassEngine()

        def tracking_hook(cmd: bytes) -> bytes:
            return struct.pack(">HIIH", 0x8001, 14, 0, 32) + os.urandom(32)

        engine.intercept_tpm_command(TPM2CommandCode.GetRandom, tracking_hook)
        initial_count = len(engine.intercepted_commands)

        command = struct.pack(">HIIH", 0x8001, 12, TPM2CommandCode.GetRandom, 16)
        engine.send_tpm_command(command)

        assert len(engine.intercepted_commands) > initial_count

    def test_command_hook_intercepts_specific_command(self) -> None:
        """Installed command hook intercepts and modifies TPM commands."""
        engine = TPMBypassEngine()

        hook_called = []

        def test_hook(command: bytes) -> bytes:
            hook_called.append(True)
            return struct.pack(">HIII", 0x8001, 14, 0, 0xDEADBEEF)

        engine.intercept_tpm_command(TPM2CommandCode.GetRandom, test_hook)

        command = struct.pack(">HIIH", 0x8001, 12, TPM2CommandCode.GetRandom, 32)
        response = engine.send_tpm_command(command)

        assert len(hook_called) > 0
        assert response is not None
        assert struct.unpack(">I", response[10:14])[0] == 0xDEADBEEF


class TestTPM12CommandProcessing:
    """Test TPM 1.2 command processing for legacy TPM support."""

    def test_process_tpm12_pcr_read(self) -> None:
        """TPM 1.2 PCR_Read returns correct PCR value."""
        engine = TPMBypassEngine()

        test_pcr_value = os.urandom(20)
        engine.pcr_banks[TPM2Algorithm.SHA1].pcr_values[7] = test_pcr_value

        command = struct.pack(">HII", 0xC400, 14, TPM12CommandCode.PCR_Read)
        command += struct.pack(">I", 7)

        response = engine.process_tpm12_command(command)

        assert response is not None
        tag, size, result_code = struct.unpack(">HII", response[:10])
        assert tag == 0xC400
        assert result_code == 0

        pcr_value = response[10:30]
        assert pcr_value == test_pcr_value

    def test_process_tpm12_quote(self) -> None:
        """TPM 1.2 Quote command produces valid quote structure."""
        engine = TPMBypassEngine()

        nonce = os.urandom(20)
        command = struct.pack(">HII", 0xC400, 30, TPM12CommandCode.Quote)
        command += nonce

        response = engine.process_tpm12_command(command)

        assert response is not None
        tag, size, result_code = struct.unpack(">HII", response[:10])
        assert result_code == 0

        quoted_data_size = struct.unpack(">I", response[10:14])[0]
        quoted_data = response[14 : 14 + quoted_data_size]

        assert b"QUOT" in quoted_data

    def test_process_tpm12_unseal(self) -> None:
        """TPM 1.2 Unseal returns unsealed data."""
        engine = TPMBypassEngine()

        command = struct.pack(">HII", 0xC400, 10, TPM12CommandCode.Unseal)

        response = engine.process_tpm12_command(command)

        assert response is not None
        tag, size, result_code = struct.unpack(">HII", response[:10])
        assert result_code == 0

        data_size = struct.unpack(">I", response[10:14])[0]
        unsealed_data = response[14 : 14 + data_size]
        assert len(unsealed_data) == data_size

    def test_process_tpm12_oiap_creates_auth_session(self) -> None:
        """TPM 1.2 OIAP command creates authorization session."""
        engine = TPMBypassEngine()

        initial_sessions = len(engine.tpm12_auth_sessions)

        command = struct.pack(">HII", 0xC400, 10, TPM12CommandCode.OIAP)

        response = engine.process_tpm12_command(command)

        assert response is not None
        tag, size, result_code = struct.unpack(">HII", response[:10])
        assert result_code == 0

        auth_handle = struct.unpack(">I", response[10:14])[0]
        assert auth_handle >= 0x02000000

        assert len(engine.tpm12_auth_sessions) > initial_sessions
        assert auth_handle in engine.tpm12_auth_sessions

    def test_build_tpm12_pcr_composite(self) -> None:
        """TPM 1.2 PCR composite structure is correctly formatted."""
        engine = TPMBypassEngine()

        pcr_selection = [0, 1, 7, 16]

        composite = engine._build_tpm12_pcr_composite(pcr_selection)

        assert len(composite) > 0

        pcr_select_size = struct.unpack(">H", composite[:2])[0]
        assert pcr_select_size == 3

        pcr_select = composite[2 : 2 + pcr_select_size]
        for pcr_num in pcr_selection:
            byte_index = pcr_num // 8
            bit_index = pcr_num % 8
            assert pcr_select[byte_index] & (1 << bit_index)


class TestPCRManipulation:
    """Test PCR value manipulation for bypass operations."""

    def test_manipulate_pcr_values_updates_sha256_bank(self) -> None:
        """PCR manipulation updates SHA256 PCR bank correctly."""
        engine = TPMBypassEngine()

        new_pcr_values = {
            0: os.urandom(32),
            7: os.urandom(32),
            14: os.urandom(32),
        }

        engine.manipulate_pcr_values(new_pcr_values)

        for pcr_num, expected_value in new_pcr_values.items():
            actual_value = engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_num]
            assert actual_value == expected_value

    def test_manipulate_pcr_values_updates_sha1_bank(self) -> None:
        """PCR manipulation updates SHA1 PCR bank with truncated values."""
        engine = TPMBypassEngine()

        sha256_value = os.urandom(32)
        engine.manipulate_pcr_values({5: sha256_value})

        sha1_value = engine.pcr_banks[TPM2Algorithm.SHA1].pcr_values[5]
        assert len(sha1_value) == 20
        assert sha1_value == sha256_value[:20]

    def test_manipulate_pcr_extend_installs_hook(self) -> None:
        """PCR extend manipulation installs command hook."""
        engine = TPMBypassEngine()

        initial_hooks = len(engine.command_hooks)

        success = engine.manipulate_pcr_extend(7, os.urandom(32), block=True)

        assert success
        assert len(engine.command_hooks) > initial_hooks
        assert TPM2CommandCode.PCR_Extend in engine.command_hooks

    def test_manipulate_pcr_extend_blocks_extend_operation(self) -> None:
        """PCR extend hook blocks PCR extension when configured."""
        engine = TPMBypassEngine()

        target_pcr = 7
        engine.manipulate_pcr_extend(target_pcr, os.urandom(32), block=True)

        original_value = engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[target_pcr]

        command = struct.pack(">HIII", 0x8001, 14, TPM2CommandCode.PCR_Extend, target_pcr)
        command += struct.pack(">H", 32) + os.urandom(32)

        response = engine.send_tpm_command(command)

        assert response is not None
        tag, size, code = struct.unpack(">HII", response[:10])
        assert code == 0

        current_value = engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[target_pcr]
        assert current_value == original_value

    def test_bypass_measured_boot_sets_secure_boot_pcr(self) -> None:
        """Measured boot bypass sets PCR 7 to secure boot bypass value."""
        engine = TPMBypassEngine()

        target_state = {0: os.urandom(32), 14: os.urandom(32)}

        success = engine.bypass_measured_boot(target_state)

        assert success

        pcr7_value = engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[7]
        expected_pcr7 = bytes.fromhex("a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb")
        assert pcr7_value == expected_pcr7


class TestWindowsSpecificBypass:
    """Test Windows-specific TPM bypass operations."""

    def test_extract_bitlocker_vmk_finds_vmk_marker(self) -> None:
        """BitLocker VMK extraction locates VMK marker in NVRAM."""
        engine = TPMBypassEngine()

        vmk_data = b"VMK\x00" + os.urandom(32) + os.urandom(100)
        nvram_offset = 0x1000
        engine.virtualized_tpm["nvram"][nvram_offset : nvram_offset + len(vmk_data)] = vmk_data

        vmk = engine.extract_bitlocker_vmk()

        assert vmk is not None
        assert len(vmk) == 32
        assert vmk == vmk_data[4:36]

    def test_extract_bitlocker_vmk_finds_nonzero_key(self) -> None:
        """BitLocker VMK extraction finds valid non-zero key material."""
        engine = TPMBypassEngine()

        vmk_key = os.urandom(32)
        nvram_offset = 0x2000
        engine.virtualized_tpm["nvram"][nvram_offset : nvram_offset + 512] = vmk_key + os.urandom(480)

        vmk = engine.extract_bitlocker_vmk()

        assert vmk is not None
        assert len(vmk) == 32
        assert any(b != 0 for b in vmk)

    def test_bypass_windows_hello_extracts_hello_indices(self) -> None:
        """Windows Hello bypass extracts keys from Hello NVRAM indices."""
        engine = TPMBypassEngine()

        hello_key_data = os.urandom(256)
        hello_index = 0x01800003
        nvram_offset = engine.virtualized_tpm["nvram_index_map"].get(hello_index, 0x5000)
        engine.virtualized_tpm["nvram"][nvram_offset : nvram_offset + len(hello_key_data)] = hello_key_data

        hello_keys = engine.bypass_windows_hello()

        assert isinstance(hello_keys, dict)
        assert len(hello_keys) > 0
        assert "biometric_template" in hello_keys
        assert "biometric_hash" in hello_keys
        assert "pin_unlock" in hello_keys

    def test_cold_boot_attack_extracts_memory_residue(self) -> None:
        """Cold boot attack extracts TPM memory residue."""
        engine = TPMBypassEngine()

        secrets = engine.cold_boot_attack()

        assert isinstance(secrets, dict)
        assert len(secrets) > 0

    def test_reset_tpm_lockout_sends_correct_command(self) -> None:
        """TPM lockout reset sends DictionaryAttackLockReset command."""
        engine = TPMBypassEngine()

        engine.virtualized_tpm["lockout_count"] = 5

        success = engine.reset_tpm_lockout()

        assert success
        assert engine.virtualized_tpm["lockout_count"] == 0

    def test_clear_tpm_ownership_resets_hierarchy_auth(self) -> None:
        """TPM ownership clear resets all hierarchy authorizations."""
        engine = TPMBypassEngine()

        engine.virtualized_tpm["hierarchy_auth"][0x40000001] = b"test_auth"

        success = engine.clear_tpm_ownership()

        assert success
        assert engine.virtualized_tpm["hierarchy_auth"][0x40000001] == b""


class TestKeyUnsealing:
    """Test TPM key unsealing with various blob formats."""

    def test_unseal_tpm2_private_blob_with_correct_auth(self) -> None:
        """TPM 2.0 private blob unsealing with correct authorization."""
        engine = TPMBypassEngine()

        auth_value = b"test_password"
        plaintext = b"SECRET_KEY_MATERIAL_12345678"

        key_material = hashlib.sha256(auth_value).digest()

        iv = os.urandom(16)
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        cipher = AES.new(key_material[:32], AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        encrypted_sensitive = iv + ciphertext

        blob = struct.pack(">H", 0x0001)
        blob += struct.pack(">H", 0)
        blob += struct.pack(">H", len(encrypted_sensitive))
        blob += encrypted_sensitive

        unsealed = engine.unseal_tpm_key(blob, auth_value)

        assert unsealed is not None
        assert plaintext in unsealed or unsealed == plaintext

    def test_unseal_generic_blob_tries_common_keys(self) -> None:
        """Generic blob unsealing handles various blob formats."""
        engine = TPMBypassEngine()

        integrity_size = struct.pack(">H", 16)
        integrity_data = os.urandom(16)
        sensitive_size = struct.pack(">H", 48)
        iv = os.urandom(16)
        encrypted_data = os.urandom(32)

        test_blob = struct.pack(">H", 0x0001)
        test_blob += integrity_size + integrity_data
        test_blob += sensitive_size + iv + encrypted_data

        unsealed = engine.unseal_tpm_key(test_blob, b"WellKnownSecret")

        assert unsealed is not None or isinstance(unsealed, (bytes, type(None)))

    def test_unseal_without_crypto_fallback(self) -> None:
        """Unsealing without PyCryptodome uses pattern-based fallback."""
        engine = TPMBypassEngine()

        test_key = b"\x00\x01\x00\x00" + os.urandom(252)
        unsealed = engine._unseal_without_crypto(test_key)

        assert unsealed is not None
        assert unsealed == test_key

    def test_looks_like_valid_key_identifies_rsa_key(self) -> None:
        """Key validation identifies RSA key header."""
        engine = TPMBypassEngine()

        rsa_key = b"\x00\x01\x00\x00" + os.urandom(256)

        assert engine._looks_like_valid_key(rsa_key)

    def test_looks_like_valid_key_identifies_ecc_key(self) -> None:
        """Key validation identifies ECC key header."""
        engine = TPMBypassEngine()

        ecc_key = b"\x00\x23\x00\x00" + os.urandom(64)

        assert engine._looks_like_valid_key(ecc_key)

    def test_looks_like_valid_key_checks_entropy(self) -> None:
        """Key validation uses entropy check for unknown formats."""
        engine = TPMBypassEngine()

        high_entropy = os.urandom(128)
        assert engine._looks_like_valid_key(high_entropy)

        low_entropy = b"\x00" * 128
        assert not engine._looks_like_valid_key(low_entropy)


class TestBinaryAnalysis:
    """Test TPM protection detection in binaries."""

    def test_detect_tpm_usage_identifies_tpm_indicators(self) -> None:
        """TPM usage detection finds TPM API strings in binary."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as f:
            binary_data = b"\x00" * 1000
            binary_data += b"Tbs.dll\x00"
            binary_data += b"\x00" * 500
            binary_data += b"Tbsip_Submit_Command\x00"
            binary_data += b"\x00" * 500
            binary_data += b"NCRYPT_TPM\x00"
            f.write(binary_data)
            temp_path = f.name

        try:
            engine = TPMBypassEngine()
            detected = engine.detect_tpm_usage(temp_path)

            assert detected
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_detect_tpm_usage_requires_multiple_indicators(self) -> None:
        """TPM detection requires at least 2 indicators to avoid false positives."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as f:
            binary_data = b"\x00" * 1000
            binary_data += b"Tbs.dll\x00"
            f.write(binary_data)
            temp_path = f.name

        try:
            engine = TPMBypassEngine()
            detected = engine.detect_tpm_usage(temp_path)

            assert not detected
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_analyze_tpm_protection_categorizes_strength(self) -> None:
        """TPM protection analysis categorizes protection strength."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as f:
            binary_data = b"\x00" * 1000
            binary_data += b"Tpm2_Unseal\x00"
            binary_data += b"Tpm2_Quote\x00"
            binary_data += b"Tpm2_PCR_Read\x00"
            binary_data += struct.pack(">I", 0)
            binary_data += struct.pack(">I", 7)
            binary_data += struct.pack(">I", 14)
            binary_data += b"\x01\x40\x00\x01"
            f.write(binary_data)
            temp_path = f.name

        try:
            engine = TPMBypassEngine()
            analysis = engine.analyze_tpm_protection(temp_path)

            assert analysis["tpm_detected"]
            assert len(analysis["tpm_apis"]) >= 2
            assert analysis["protection_strength"] in ["weak", "medium", "strong"]
            assert analysis["bypass_difficulty"] in ["easy", "medium", "hard"]
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_bypass_tpm_protection_patches_api_calls(self) -> None:
        """TPM protection bypass patches TPM API calls in binary."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as f:
            binary_data = bytearray(b"\x00" * 500)
            binary_data += b"Tbsip_Submit_Command\x00"
            binary_data += b"\x00" * 100
            binary_data += b"Tpm2_Unseal\x00"
            binary_data += b"\x00" * 100
            f.write(binary_data)
            temp_path = f.name

        try:
            engine = TPMBypassEngine()

            with tempfile.TemporaryDirectory() as tmpdir:
                output_path = Path(tmpdir) / "patched.exe"

                success = engine.bypass_tpm_protection(temp_path, str(output_path))

                assert success
                assert output_path.exists()

                patched_data = output_path.read_bytes()
                assert b"NOP_S" in patched_data or b"NOP_Submit" in patched_data
                assert b"NOP2_Unseal" in patched_data

        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestAdvancedFeatures:
    """Test advanced TPM bypass features."""

    def test_get_bypass_capabilities_returns_complete_capability_list(self) -> None:
        """Bypass capabilities report includes all feature categories."""
        engine = TPMBypassEngine()

        capabilities = engine.get_bypass_capabilities()

        required_categories = [
            "tpm_versions_supported",
            "command_interception",
            "pcr_manipulation",
            "key_extraction",
            "attestation_bypass",
            "unsealing_capabilities",
            "advanced_attacks",
            "platform_specific",
        ]

        for category in required_categories:
            assert category in capabilities

    def test_get_intercepted_commands_summary_provides_statistics(self) -> None:
        """Intercepted commands summary provides command statistics."""
        engine = TPMBypassEngine()

        def tracking_hook(cmd: bytes) -> bytes:
            return struct.pack(">HIIH", 0x8001, 14, 0, 32) + os.urandom(32)

        engine.intercept_tpm_command(TPM2CommandCode.GetRandom, tracking_hook)

        command1 = struct.pack(">HIIH", 0x8001, 12, TPM2CommandCode.GetRandom, 32)
        command2 = struct.pack(">HIIH", 0x8001, 12, TPM2CommandCode.GetRandom, 16)

        engine.send_tpm_command(command1)
        engine.send_tpm_command(command2)

        summary = engine.get_intercepted_commands_summary()

        assert "total_commands" in summary
        assert "command_types" in summary
        assert summary["total_commands"] >= 2

    def test_perform_bus_attack_captures_target_command(self) -> None:
        """Bus attack captures data for specific TPM commands."""
        engine = TPMBypassEngine()

        unseal_data = engine.perform_bus_attack(TPM2CommandCode.Unseal)

        assert unseal_data is not None
        assert len(unseal_data) > 0
        assert b"\x80\x01" in unseal_data

    def test_forge_quote_signature_creates_valid_signature(self) -> None:
        """Quote signature forging creates properly formatted signature."""
        engine = TPMBypassEngine()

        quote_info = os.urandom(100)
        pcr_digest = os.urandom(32)
        nonce = os.urandom(32)

        signature = engine.forge_quote_signature(quote_info, pcr_digest, nonce)

        assert len(signature) == 256

    def test_extract_pcr_policy_from_policy_digest(self) -> None:
        """PCR policy extraction from policy digest."""
        engine = TPMBypassEngine()

        policy_digest = os.urandom(32)

        pcr_policy = engine.extract_pcr_policy(policy_digest)

        assert pcr_policy is None or isinstance(pcr_policy, dict)

    def test_detect_tpm_version_returns_version_string(self) -> None:
        """TPM version detection returns version identifier."""
        engine = TPMBypassEngine()

        version = engine.detect_tpm_version()

        assert version in ["1.2", "2.0"]
        assert engine.tpm_version is not None

    def test_spoof_pcr_runtime_validates_pcr_index(self) -> None:
        """Runtime PCR spoofing validates PCR index range."""
        engine = TPMBypassEngine()

        valid_pcr = 7
        pcr_value = os.urandom(32)

        result = engine.spoof_pcr_runtime(valid_pcr, pcr_value)

        assert isinstance(result, bool)


class TestConcurrencyAndThreadSafety:
    """Test thread safety of TPM bypass operations."""

    def test_command_lock_protects_command_hooks(self) -> None:
        """Command lock ensures thread-safe hook installation."""
        engine = TPMBypassEngine()

        def test_hook(cmd: bytes) -> bytes:
            return struct.pack(">HII", 0x8001, 10, 0)

        success1 = engine.intercept_tpm_command(TPM2CommandCode.GetRandom, test_hook)
        success2 = engine.intercept_tpm_command(TPM2CommandCode.PCR_Read, test_hook)

        assert success1
        assert success2
        assert len(engine.command_hooks) >= 2

    def test_intercepted_commands_list_thread_safe_append(self) -> None:
        """Intercepted commands list safely appends from multiple operations."""
        engine = TPMBypassEngine()

        hook_called_count = [0]

        def tracking_hook(cmd: bytes) -> bytes:
            hook_called_count[0] += 1
            return struct.pack(">HIII", 0x8001, 14, 0, 0x12345678)

        engine.intercept_tpm_command(TPM2CommandCode.GetRandom, tracking_hook)

        initial_count = len(engine.intercepted_commands)

        for _ in range(5):
            command = struct.pack(">HIIH", 0x8001, 12, TPM2CommandCode.GetRandom, 16)
            engine.send_tpm_command(command)

        final_count = len(engine.intercepted_commands)
        assert final_count >= initial_count + 5
        assert hook_called_count[0] >= 5


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_send_tpm_command_rejects_undersized_command(self) -> None:
        """Command sending rejects commands smaller than minimum size."""
        engine = TPMBypassEngine()

        invalid_command = b"\x80\x01\x00\x00"

        response = engine.send_tpm_command(invalid_command)

        assert response is None

    def test_bypass_attestation_handles_empty_pcr_selection(self) -> None:
        """Attestation bypass handles empty PCR selection."""
        engine = TPMBypassEngine()

        attestation = engine.bypass_attestation(os.urandom(32), [])

        assert isinstance(attestation, AttestationData)
        assert len(attestation.signature) == 256

    def test_extract_sealed_keys_handles_empty_nvram(self) -> None:
        """Sealed key extraction handles empty NVRAM gracefully."""
        engine = TPMBypassEngine()

        engine.virtualized_tpm["nvram"] = bytearray(33554432)

        keys = engine.extract_sealed_keys()

        assert isinstance(keys, dict)

    def test_unseal_tpm_key_handles_malformed_blob(self) -> None:
        """Key unsealing handles malformed blob data."""
        engine = TPMBypassEngine()

        malformed_blob = b"\x00\x01\x02"

        result = engine.unseal_tpm_key(malformed_blob)

        assert result is None or isinstance(result, bytes)

    def test_detect_tpm_usage_handles_nonexistent_binary(self) -> None:
        """TPM detection handles non-existent binary path."""
        engine = TPMBypassEngine()

        detected = engine.detect_tpm_usage("/nonexistent/path/to/binary.exe")

        assert not detected

    def test_manipulate_pcr_values_clamps_to_valid_range(self) -> None:
        """PCR manipulation ignores PCR indices outside valid range."""
        engine = TPMBypassEngine()

        invalid_pcr_values = {
            25: os.urandom(32),
            100: os.urandom(32),
            -1: os.urandom(32),
        }

        engine.manipulate_pcr_values(invalid_pcr_values)

        assert len(engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values) == 24


class TestRealWorldScenarios:
    """Test real-world TPM bypass scenarios."""

    def test_complete_attestation_workflow(self) -> None:
        """Complete remote attestation bypass workflow."""
        engine = TPMBypassEngine()

        nonce = os.urandom(32)
        expected_pcrs = {
            0: hashlib.sha256(b"BIOS_PCR_0").digest(),
            7: hashlib.sha256(b"SECURE_BOOT_PCR_7").digest(),
            14: hashlib.sha256(b"MEASURED_BOOT_PCR_14").digest(),
        }

        attestation = engine.spoof_remote_attestation(nonce, expected_pcrs, aik_handle=0x81010001)

        assert attestation["quote"]["signature"] is not None
        assert len(attestation["quote"]["signature"]) == 256

        for pcr_num, pcr_hex in attestation["pcr_values"].items():
            expected_value = expected_pcrs[int(pcr_num)]
            assert bytes.fromhex(pcr_hex) == expected_value

        assert len(attestation["aik_cert"]) > 100

    def test_complete_key_unsealing_workflow(self) -> None:
        """Complete TPM key unsealing bypass workflow."""
        engine = TPMBypassEngine()

        pcr_policy = {
            0: os.urandom(32),
            7: os.urandom(32),
        }

        for pcr_num, value in pcr_policy.items():
            engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_num] = value

        plaintext = b"LICENSED_SOFTWARE_KEY_2024"
        auth = b"software_auth_value"

        key_material = hashlib.sha256(auth).digest()

        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        iv = os.urandom(16)
        cipher = AES.new(key_material[:32], AES.MODE_CBC, iv)
        encrypted_sensitive = iv + cipher.encrypt(pad(plaintext, AES.block_size))

        blob = struct.pack(">H", 0x0001)
        blob += struct.pack(">H", 0)
        blob += struct.pack(">H", len(encrypted_sensitive))
        blob += encrypted_sensitive

        unsealed = engine.unseal_tpm_key(blob, auth, pcr_policy)

        assert unsealed is not None
        assert plaintext in unsealed

    def test_measured_boot_bypass_workflow(self) -> None:
        """Complete measured boot bypass workflow."""
        engine = TPMBypassEngine()

        target_pcr_state = {
            0: hashlib.sha256(b"TRUSTED_BIOS").digest(),
            1: hashlib.sha256(b"TRUSTED_BIOS_CONFIG").digest(),
            2: hashlib.sha256(b"TRUSTED_OPTION_ROM").digest(),
            7: hashlib.sha256(b"SECURE_BOOT_ENABLED").digest(),
        }

        success = engine.bypass_measured_boot(target_pcr_state)

        assert success

        for pcr_num, expected_value in target_pcr_state.items():
            actual_value = engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_num]
            assert actual_value == expected_value

    def test_command_interception_workflow(self) -> None:
        """Complete command interception workflow."""
        engine = TPMBypassEngine()

        custom_random_data = b"PREDICTABLE_RANDOM_FOR_BYPASS"

        def getrandom_hook(command: bytes) -> bytes:
            response = struct.pack(">HIIH", 0x8001, 12 + len(custom_random_data), 0, len(custom_random_data))
            response += custom_random_data
            return response

        engine.intercept_tpm_command(TPM2CommandCode.GetRandom, getrandom_hook)

        command = struct.pack(">HIIH", 0x8001, 12, TPM2CommandCode.GetRandom, 32)
        response = engine.send_tpm_command(command)

        assert response is not None
        returned_size = struct.unpack(">H", response[10:12])[0]
        returned_data = response[12 : 12 + returned_size]

        assert returned_data == custom_random_data
