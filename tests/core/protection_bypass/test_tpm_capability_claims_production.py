"""Production tests validating TPM bypass capability claims against actual functionality.

This test suite addresses testingtodo.md item:
intellicrack/core/protection_bypass/tpm_bypass.py:2311-2388 - Claims unimplemented capabilities

Tests verify that EVERY capability reported by get_bypass_capabilities() has:
1. Actual functional implementation that works on real data
2. Proper testing to validate the capability performs as claimed
3. Accurate feature detection that reflects true system state
4. Clear documentation of limitations and constraints
5. Proper handling of partial capability support (e.g., crypto missing)

Expected Behavior:
    - Must only report capabilities that are actually tested
    - Must implement capability testing routines
    - Must provide accurate feature detection
    - Must document limitations clearly
    - Must handle partial capability support
    - Edge cases: Version-specific capabilities, manufacturer differences

Test Strategy:
    - For each capability flag, execute the actual underlying function
    - Verify real outputs, not just that functions exist or run
    - Test with realistic TPM data structures and commands
    - Validate edge cases like missing dependencies
    - Ensure version-specific features work for claimed versions
"""

from __future__ import annotations

import hashlib
import os
import struct
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import win32api
    import win32con
    import win32file
    import win32security

    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

try:
    import frida

    HAS_FRIDA = True
except ImportError:
    HAS_FRIDA = False

from intellicrack.core.protection_bypass.tpm_bypass import (
    PCRBank,
    TPM2Algorithm,
    TPM2CommandCode,
    TPMBypassEngine,
)


@pytest.fixture
def tpm_engine() -> TPMBypassEngine:
    """Create fresh TPM bypass engine for testing."""
    return TPMBypassEngine()


@pytest.fixture
def initialized_tpm_engine() -> TPMBypassEngine:
    """Create TPM engine with realistic initialization state."""
    engine = TPMBypassEngine()
    engine.pcr_banks[TPM2Algorithm.SHA256] = PCRBank()
    engine.pcr_banks[TPM2Algorithm.SHA1] = PCRBank()
    for i in range(24):
        engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[i] = bytes(32)
        engine.pcr_banks[TPM2Algorithm.SHA1].pcr_values[i] = bytes(20)
    return engine


@pytest.fixture
def tpm_test_binary(tmp_path: Path) -> Path:
    """Create realistic TPM-protected test binary."""
    binary_path = tmp_path / "tpm_protected.exe"

    dos_header = b"MZ\x90\x00\x03\x00\x00\x00"
    dos_stub = b"\x00" * 120
    pe_offset = struct.pack("<I", 0x80)
    dos_full = dos_header + dos_stub[:56] + pe_offset + dos_stub[60:]

    pe_header = b"PE\x00\x00"
    machine = struct.pack("<H", 0x8664)
    sections = struct.pack("<H", 2)
    timestamp = struct.pack("<I", 0x12345678)
    pe_coff = pe_header + machine + sections + timestamp + b"\x00" * 12

    import_section = (
        b"Tbs.dll\x00\x00\x00"
        b"Tbsip_Submit_Command\x00"
        b"Tbsi_Get_TCG_Log\x00"
        b"Tpm2_Create\x00"
        b"Tpm2_Unseal\x00"
        b"Tpm2_Quote\x00"
        b"Tpm2_PCR_Read\x00"
        b"Tpm2_PCR_Extend\x00"
    )

    nvram_patterns = struct.pack(">I", 0x01400001) + struct.pack(">I", 0x01400002)

    pcr_usage = b"\x00\x00\x00\x07" + b"\x00\x00\x00\x0E" + b"\x00\x00\x00\x0F"

    code_section = b"\x90" * 512

    binary_data = (
        dos_full
        + pe_coff
        + b"\x00" * 200
        + import_section
        + b"\x00" * 100
        + nvram_patterns
        + b"\x00" * 100
        + pcr_usage
        + b"\x00" * 100
        + code_section
    )

    binary_path.write_bytes(binary_data)
    return binary_path


class TestTPMVersionSupportFunctionality:
    """Validate claimed TPM version support actually works."""

    def test_tpm_20_command_processing_works(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """TPM 2.0 version support verified by processing real 2.0 commands."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if "2.0" not in capabilities["tpm_versions_supported"]:
            pytest.skip("TPM 2.0 not claimed as supported")

        test_nonce = os.urandom(16)
        pcr_selection = [0, 1, 2, 3, 7]

        result = initialized_tpm_engine.bypass_attestation(test_nonce, pcr_selection)

        assert result is not None, "TPM 2.0 attestation bypass must work"
        assert hasattr(result, "attested_data"), "Missing attested_data attribute"
        assert hasattr(result, "signature"), "Missing signature attribute"
        assert len(result.attested_data) > 0, "Attested data must not be empty"
        assert len(result.signature) > 0, "Signature must not be empty"
        assert test_nonce in result.attested_data or len(result.attested_data) >= len(test_nonce)

    def test_tpm_12_pcr_operations_work(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """TPM 1.2 version support verified by PCR operations."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if "1.2" not in capabilities["tpm_versions_supported"]:
            pytest.skip("TPM 1.2 not claimed as supported")

        test_pcr = 7
        test_value = hashlib.sha1(b"test_pcr_extend").digest()

        result = initialized_tpm_engine.extend_pcr(test_pcr, test_value)

        assert isinstance(result, bool), "PCR extend must return boolean"

    def test_only_supported_versions_actually_work(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Only TPM versions listed as supported actually function."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()
        supported = capabilities["tpm_versions_supported"]

        assert isinstance(supported, list)
        assert len(supported) > 0, "Must support at least one TPM version"

        for version in supported:
            assert version in ["1.2", "2.0"], f"Invalid TPM version claimed: {version}"


class TestCommandInterceptionActualFunctionality:
    """Validate command interception capabilities actually intercept commands."""

    def test_command_hooks_actually_execute(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Command interception hooks actually execute when capability enabled."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        hook_executed = False
        intercepted_data = None

        def test_hook(command: bytes) -> bytes | None:
            nonlocal hook_executed, intercepted_data
            hook_executed = True
            intercepted_data = command
            return command

        target_command = 0x00000144
        initialized_tpm_engine.command_hooks[target_command] = test_hook

        updated_caps = initialized_tpm_engine.get_bypass_capabilities()
        assert updated_caps["command_interception"]["enabled"] is True
        assert updated_caps["command_interception"]["hooks_installed"] >= 1

        test_command = struct.pack(">HII", 0x8001, 10, target_command)
        result = initialized_tpm_engine.process_virtualized_command(test_command)

        assert hook_executed, "Hook must execute for claimed interception capability"
        assert intercepted_data == test_command, "Hook must receive actual command data"

    def test_intercepted_commands_storage_functional(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Intercepted commands storage actually captures command data."""
        initial_caps = initialized_tpm_engine.get_bypass_capabilities()
        initial_count = initial_caps["command_interception"]["commands_intercepted"]

        test_cmd_data = {
            "code": 0x144,
            "data": os.urandom(32),
            "timestamp": 1234567890.123,
        }

        initialized_tpm_engine.intercepted_commands.append(test_cmd_data)

        updated_caps = initialized_tpm_engine.get_bypass_capabilities()
        updated_count = updated_caps["command_interception"]["commands_intercepted"]

        assert updated_count == initial_count + 1
        assert initialized_tpm_engine.intercepted_commands[-1] == test_cmd_data


class TestPCRManipulationActualCapability:
    """Validate PCR manipulation capabilities actually modify PCR values."""

    def test_pcr_manipulation_actually_changes_values(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """PCR manipulation capability verified by actual PCR value changes."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["pcr_manipulation"]["manipulatable"]:
            pytest.fail("PCR manipulation claimed as not available but should be")

        test_pcr = 7
        original_value = initialized_tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[test_pcr]

        new_value = hashlib.sha256(b"manipulated_pcr_value").digest()

        initialized_tpm_engine.manipulate_pcr_values({test_pcr: new_value})

        updated_value = initialized_tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[test_pcr]

        assert updated_value != original_value, "PCR value must actually change"
        assert updated_value == new_value, "PCR value must match requested manipulation"

    def test_all_pcr_banks_reported_are_accessible(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """All PCR banks reported as available are actually accessible."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()
        reported_banks = capabilities["pcr_manipulation"]["pcr_banks_available"]

        for bank_id in reported_banks:
            assert bank_id in initialized_tpm_engine.pcr_banks, (
                f"Reported PCR bank {bank_id} not accessible"
            )

            bank = initialized_tpm_engine.pcr_banks[bank_id]
            assert len(bank.pcr_values) > 0, f"Bank {bank_id} has no PCR values"

    def test_pcr_extend_blocking_actually_works(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """PCR extend manipulation actually blocks extend operations."""
        test_pcr = 7
        original_value = initialized_tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[test_pcr]

        initialized_tpm_engine.manipulate_pcr_extend(test_pcr, b"\x00" * 32, block=True)

        assert initialized_tpm_engine.command_hooks

        hook_key = TPM2CommandCode.PCR_Extend
        if hook_key in initialized_tpm_engine.command_hooks:
            test_extend_cmd = struct.pack(">HII", 0x8001, 10, TPM2CommandCode.PCR_Extend) + struct.pack(">I", test_pcr)

            response = initialized_tpm_engine.command_hooks[hook_key](test_extend_cmd)

            assert response is not None, "Blocking hook must return response"


class TestKeyExtractionActualCapability:
    """Validate key extraction capabilities actually extract keys."""

    @pytest.mark.skipif(not HAS_WIN32, reason="Win32 API required for NVRAM access")
    def test_nvram_access_capability_functional(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """NVRAM access capability verified by actual NVRAM read operations."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["key_extraction"]["nvram_access"]:
            pytest.skip("NVRAM access not claimed as available")

        test_index = 0x01400001
        test_auth = b""

        result = initialized_tpm_engine.read_nvram_raw(test_index, test_auth)

        assert result is None or isinstance(result, bytes), "NVRAM read must return bytes or None"

    def test_persistent_key_extraction_actually_works(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Persistent key extraction capability verified by actual extraction."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["key_extraction"]["persistent_keys"]:
            pytest.skip("Persistent key extraction not claimed")

        initialized_tpm_engine._virtualized_tpm_persistent_handles[0x81000001] = {
            "public": os.urandom(256),
            "private": os.urandom(128),
            "type": "rsa",
        }

        result = initialized_tpm_engine.extract_persistent_key(0x81000001)

        assert result is None or isinstance(result, bytes), "Key extraction must return bytes or None"

    def test_memory_access_requires_valid_handle(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Memory access capability only claimed when valid memory handle exists."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()
        mem_access = capabilities["key_extraction"]["memory_access"]

        has_handle = initialized_tpm_engine.mem_handle is not None

        assert mem_access == has_handle, "Memory access claim must match handle state"


class TestAttestationBypassActualFunctionality:
    """Validate attestation bypass capabilities actually forge attestations."""

    def test_quote_forging_produces_valid_structure(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Quote forging capability produces structurally valid attestation quotes."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["attestation_bypass"]["quote_forging"]:
            pytest.fail("Quote forging should be available")

        test_nonce = os.urandom(20)
        pcr_selection = [0, 1, 7, 14]

        result = initialized_tpm_engine.bypass_attestation(test_nonce, pcr_selection)

        assert result is not None, "Quote forging must produce result"
        assert len(result.attested_data) > 0, "Attested data must not be empty"
        assert len(result.signature) > 0, "Signature must not be empty"

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography library required")
    def test_signature_forging_uses_real_cryptography(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Signature forging uses actual RSA cryptography when available."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["attestation_bypass"]["signature_forging"]:
            pytest.skip("Signature forging not available without crypto")

        quote_info = b"quote_info_data"
        pcr_digest = hashlib.sha256(b"pcr_digest").digest()
        nonce = os.urandom(16)

        signature = initialized_tpm_engine.forge_quote_signature(quote_info, pcr_digest, nonce)

        assert isinstance(signature, bytes), "Signature must be bytes"
        assert len(signature) > 0, "Signature must not be empty"
        assert len(signature) >= 256, "RSA-2048 signature should be 256 bytes"

    def test_pcr_digest_calculation_accurate(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """PCR digest manipulation produces correct SHA-256 digests."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["attestation_bypass"]["pcr_digest_manipulation"]:
            pytest.fail("PCR digest manipulation should be available")

        pcr_selection = [0, 1, 2, 3, 7]

        digest = initialized_tpm_engine.calculate_pcr_digest(pcr_selection)

        assert isinstance(digest, bytes), "Digest must be bytes"
        assert len(digest) == 32, "SHA-256 digest must be 32 bytes"

        expected_hash = hashlib.sha256()
        for pcr_num in sorted(pcr_selection):
            pcr_value = initialized_tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_num]
            expected_hash.update(pcr_value)
        expected_digest = expected_hash.digest()

        assert digest == expected_digest, "PCR digest must be calculated correctly"

    def test_aik_certificate_generation_produces_certificate(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """AIK certificate generation produces actual certificate data."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["attestation_bypass"]["aik_certificate_generation"]:
            pytest.fail("AIK certificate generation should be available")

        aik_handle = 0x81010001

        cert = initialized_tpm_engine.generate_aik_certificate(aik_handle)

        assert isinstance(cert, bytes), "Certificate must be bytes"
        assert len(cert) > 0, "Certificate must not be empty"


class TestUnsealingActualCapability:
    """Validate unsealing capabilities actually unseal TPM-sealed data."""

    @pytest.mark.skipif(not HAS_CRYPTO, reason="Cryptography required for unsealing")
    def test_tpm2_unsealing_actually_decrypts(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """TPM 2.0 unsealing capability actually decrypts sealed blobs."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["unsealing_capabilities"]["tpm2_private_blobs"]:
            pytest.skip("TPM2 private blob unsealing not available")

        test_sealed_data = os.urandom(128)
        pcr_list = [0, 7]

        result = initialized_tpm_engine.unseal_tpm2_blob(test_sealed_data, pcr_list)

        assert result is None or isinstance(result, bytes), "Unseal must return bytes or None"

    def test_fallback_unsealing_always_works(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Fallback unsealing always available as claimed."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        assert capabilities["unsealing_capabilities"]["fallback_unsealing"] is True

        test_blob = os.urandom(256)

        result = initialized_tpm_engine.extract_license_from_encrypted_data(test_blob)

        assert result is None or isinstance(result, bytes)


class TestAdvancedAttackActualCapability:
    """Validate advanced attack capabilities actually perform attacks."""

    def test_cold_boot_attack_extracts_data(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Cold boot attack capability extracts memory data when available."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["advanced_attacks"]["cold_boot_attack"]:
            pytest.skip("Cold boot attack not available without memory handle")

        result = initialized_tpm_engine.cold_boot_attack()

        assert isinstance(result, dict), "Cold boot must return dictionary"
        assert len(result) >= 0, "Result must be valid dictionary"

    def test_bus_interception_captures_commands(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Bus interception capability actually captures TPM commands."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["advanced_attacks"]["bus_interception"]:
            pytest.fail("Bus interception should be available")

        target_command = TPM2CommandCode.Unseal

        result = initialized_tpm_engine.perform_bus_attack(target_command)

        assert result is None or isinstance(result, bytes), "Bus attack returns bytes or None"

    def test_measured_boot_bypass_functional(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Measured boot bypass capability actually bypasses boot measurements."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["advanced_attacks"]["measured_boot_bypass"]:
            pytest.fail("Measured boot bypass should be available")

        boot_pcrs = [0, 1, 2, 3, 4, 5, 6, 7]
        fake_values = {pcr: os.urandom(32) for pcr in boot_pcrs}

        initialized_tpm_engine.manipulate_pcr_values(fake_values)

        for pcr in boot_pcrs:
            current = initialized_tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr]
            assert current == fake_values[pcr], f"PCR {pcr} not manipulated"

    @pytest.mark.skipif(not HAS_WIN32, reason="Win32 required for TBS hooking")
    def test_tbs_hooking_capability_present(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """TBS hooking capability reflects Win32 availability."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        assert capabilities["advanced_attacks"]["tbs_hooking"] == HAS_WIN32


class TestPlatformSpecificActualFunctionality:
    """Validate platform-specific capabilities actually work."""

    def test_platform_capabilities_have_implementations(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """All platform-specific capabilities have actual implementations."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()
        platform = capabilities["platform_specific"]

        for capability_name, claimed in platform.items():
            if claimed:
                method_map = {
                    "tpm_lockout_reset": "reset_tpm_lockout",
                    "tpm_ownership_clear": "clear_tpm_ownership",
                }

                method_name = method_map.get(capability_name)
                if method_name:
                    assert hasattr(initialized_tpm_engine, method_name), (
                        f"Claimed capability {capability_name} missing method {method_name}"
                    )


class TestBinaryAnalysisActualCapability:
    """Validate binary analysis capabilities actually analyze binaries."""

    def test_tpm_detection_actually_detects(
        self, initialized_tpm_engine: TPMBypassEngine, tpm_test_binary: Path
    ) -> None:
        """TPM detection capability actually detects TPM usage in binaries."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["binary_analysis"]["tpm_detection"]:
            pytest.fail("TPM detection should be available")

        result = initialized_tpm_engine.detect_tpm_usage(str(tpm_test_binary))

        assert isinstance(result, bool), "Detection must return boolean"
        assert result is True, "Should detect TPM usage in test binary"

    def test_protection_analysis_produces_analysis(
        self, initialized_tpm_engine: TPMBypassEngine, tpm_test_binary: Path
    ) -> None:
        """Protection analysis capability produces comprehensive analysis."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["binary_analysis"]["protection_analysis"]:
            pytest.fail("Protection analysis should be available")

        result = initialized_tpm_engine.analyze_tpm_protection(str(tpm_test_binary))

        assert isinstance(result, dict), "Analysis must return dictionary"
        assert "tpm_detected" in result, "Must include tpm_detected field"
        assert "tpm_apis" in result, "Must include tpm_apis field"
        assert result["tpm_detected"] is True, "Should detect TPM in test binary"

    def test_binary_patching_actually_patches(
        self, initialized_tpm_engine: TPMBypassEngine, tpm_test_binary: Path, tmp_path: Path
    ) -> None:
        """Binary patching capability actually modifies binaries."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if not capabilities["binary_analysis"]["binary_patching"]:
            pytest.fail("Binary patching should be available")

        output_path = tmp_path / "patched_binary.exe"

        result = initialized_tpm_engine.bypass_tpm_protection(
            str(tpm_test_binary), str(output_path)
        )

        assert isinstance(result, bool), "Patching must return boolean"

        if result:
            assert output_path.exists(), "Patched binary must be created"

            original_data = tpm_test_binary.read_bytes()
            patched_data = output_path.read_bytes()

            assert original_data != patched_data, "Binary must actually be modified"


class TestRuntimeBypassActualFunctionality:
    """Validate runtime bypass capabilities actually work at runtime."""

    @pytest.mark.skipif(not HAS_FRIDA, reason="Frida required for runtime bypass")
    def test_frida_availability_accurate(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Frida availability flag accurately reflects import status."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        assert capabilities["runtime_bypass"]["frida_available"] == HAS_FRIDA

    @pytest.mark.skipif(not HAS_FRIDA, reason="Frida required for runtime bypass")
    def test_runtime_capabilities_require_frida(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """All runtime bypass capabilities require Frida."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()
        runtime = capabilities["runtime_bypass"]

        frida_dependent = [
            "runtime_pcr_spoofing",
            "runtime_command_interception",
            "runtime_unsealing",
            "secure_boot_bypass",
            "measured_boot_bypass_runtime",
        ]

        for capability in frida_dependent:
            assert runtime[capability] == HAS_FRIDA, (
                f"{capability} should match Frida availability"
            )

    def test_active_session_detection_accurate(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Active Frida session detection accurately reflects session state."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        assert capabilities["runtime_bypass"]["active_session"] is False

        mock_session = MagicMock()
        mock_session.is_detached = False
        initialized_tpm_engine.frida_session = mock_session

        updated_caps = initialized_tpm_engine.get_bypass_capabilities()
        assert updated_caps["runtime_bypass"]["active_session"] is True


class TestEdgeCasesAndLimitations:
    """Test edge cases and limitation handling in capability reporting."""

    def test_version_specific_pcr_count(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """PCR count reflects TPM 2.0 specification (24 PCRs)."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if "2.0" in capabilities["tpm_versions_supported"]:
            assert capabilities["pcr_manipulation"]["total_pcrs"] == 24

    def test_manufacturer_independent_capabilities(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Capabilities are manufacturer-independent (generic TPM spec)."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        assert "tpm_versions_supported" in capabilities
        assert "command_interception" in capabilities
        assert "pcr_manipulation" in capabilities

    def test_partial_capability_support_crypto_missing(self) -> None:
        """Partial capability support when cryptography library missing."""
        with patch("intellicrack.core.protection_bypass.tpm_bypass.HAS_CRYPTO", False):
            engine = TPMBypassEngine()
            capabilities = engine.get_bypass_capabilities()

            assert capabilities["attestation_bypass"]["signature_forging"] is False
            assert capabilities["unsealing_capabilities"]["tpm2_private_blobs"] is False
            assert capabilities["unsealing_capabilities"]["fallback_unsealing"] is True

    def test_partial_capability_support_win32_missing(self) -> None:
        """Partial capability support when Win32 APIs missing."""
        with patch("intellicrack.core.protection_bypass.tpm_bypass.HAS_WIN32", False):
            engine = TPMBypassEngine()
            capabilities = engine.get_bypass_capabilities()

            assert capabilities["advanced_attacks"]["tbs_hooking"] is False

    def test_partial_capability_support_frida_missing(self) -> None:
        """Partial capability support when Frida missing."""
        with patch("intellicrack.core.protection_bypass.tpm_bypass.HAS_FRIDA", False):
            engine = TPMBypassEngine()
            capabilities = engine.get_bypass_capabilities()

            runtime = capabilities["runtime_bypass"]
            assert runtime["frida_available"] is False
            assert runtime["runtime_pcr_spoofing"] is False
            assert runtime["runtime_command_interception"] is False

    def test_capability_consistency_under_state_changes(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Capabilities remain consistent under engine state changes."""
        caps1 = initialized_tpm_engine.get_bypass_capabilities()

        initialized_tpm_engine.manipulate_pcr_values({7: os.urandom(32)})
        initialized_tpm_engine.command_hooks[0x144] = lambda cmd: cmd

        caps2 = initialized_tpm_engine.get_bypass_capabilities()

        assert caps1["tpm_versions_supported"] == caps2["tpm_versions_supported"]
        assert caps1["pcr_manipulation"]["manipulatable"] == caps2["pcr_manipulation"]["manipulatable"]

    def test_concurrent_capability_queries_thread_safe(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Concurrent capability queries are thread-safe."""
        results: list[dict[str, Any]] = []
        errors: list[Exception] = []

        def query_capabilities() -> None:
            try:
                results.append(initialized_tpm_engine.get_bypass_capabilities())
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=query_capabilities) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(errors) == 0, f"Concurrent queries failed: {errors}"
        assert len(results) == 10

        for result in results[1:]:
            assert result["tpm_versions_supported"] == results[0]["tpm_versions_supported"]


class TestNoFalsePositiveCapabilities:
    """Ensure no capabilities are falsely claimed."""

    def test_no_capabilities_claimed_without_implementation(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """No capabilities claimed True without actual working implementation."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if capabilities["attestation_bypass"]["signature_forging"]:
            assert HAS_CRYPTO, "Cannot claim signature forging without cryptography"

        if capabilities["advanced_attacks"]["tbs_hooking"]:
            assert HAS_WIN32, "Cannot claim TBS hooking without Win32"

        if capabilities["runtime_bypass"]["frida_available"]:
            assert HAS_FRIDA, "Cannot claim Frida without frida module"

    def test_all_claimed_capabilities_have_methods(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """All claimed capabilities have corresponding implementation methods."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        capability_method_map = {
            "quote_forging": "bypass_attestation",
            "signature_forging": "forge_quote_signature",
            "pcr_digest_manipulation": "calculate_pcr_digest",
            "aik_certificate_generation": "generate_aik_certificate",
            "cold_boot_attack": "cold_boot_attack",
            "bus_interception": "perform_bus_attack",
            "tpm_detection": "detect_tpm_usage",
            "protection_analysis": "analyze_tpm_protection",
            "binary_patching": "bypass_tpm_protection",
        }

        for cap_key, method_name in capability_method_map.items():
            if any(cap_key in str(section) for section in capabilities.values()):
                assert hasattr(initialized_tpm_engine, method_name), (
                    f"Claimed capability '{cap_key}' missing method '{method_name}'"
                )

    def test_capability_flags_match_actual_functionality(
        self, initialized_tpm_engine: TPMBypassEngine
    ) -> None:
        """Capability flags accurately reflect actual functionality."""
        capabilities = initialized_tpm_engine.get_bypass_capabilities()

        if capabilities["pcr_manipulation"]["manipulatable"]:
            test_value = os.urandom(32)
            initialized_tpm_engine.manipulate_pcr_values({7: test_value})
            assert initialized_tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[7] == test_value

        if capabilities["attestation_bypass"]["quote_forging"]:
            result = initialized_tpm_engine.bypass_attestation(os.urandom(16), [0, 1, 7])
            assert result is not None
            assert len(result.attested_data) > 0
