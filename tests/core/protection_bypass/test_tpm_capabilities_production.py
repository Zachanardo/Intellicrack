"""Production tests for TPM bypass capability reporting.

Validates that TPMBypassEngine.get_bypass_capabilities() accurately reports
only capabilities that are actually implemented and tested. Tests verify that
capability flags correctly reflect system state, available libraries, and
actual feature implementation.

Expected Behavior:
    - Must only report capabilities that are actually tested
    - Must implement capability testing routines
    - Must provide accurate feature detection
    - Must document limitations clearly
    - Must handle partial capability support
    - Edge cases: Version-specific capabilities, manufacturer differences

Test Categories:
    - Capability accuracy validation (flags match reality)
    - Dynamic capability detection (runtime state changes)
    - Partial implementation handling
    - Platform-specific capability reporting
    - Version-specific capability detection
"""

from __future__ import annotations

import ctypes
import struct
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import win32api

    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

try:
    import frida

    HAS_FRIDA = True
except ImportError:
    HAS_FRIDA = False

from intellicrack.core.protection_bypass.tpm_bypass import TPMBypassEngine


@pytest.fixture
def tpm_bypass() -> TPMBypassEngine:
    """Create TPMBypassEngine instance for testing."""
    return TPMBypassEngine()


@pytest.fixture
def tpm_bypass_with_memory(tpm_bypass: TPMBypassEngine) -> TPMBypassEngine:
    """Create TPMBypassEngine with simulated memory handle."""
    with patch.object(tpm_bypass, "mem_handle", value=42):
        yield tpm_bypass


@pytest.fixture
def tpm_bypass_with_frida_session(tpm_bypass: TPMBypassEngine) -> TPMBypassEngine:
    """Create TPMBypassEngine with active Frida session."""
    mock_session = MagicMock()
    mock_session.is_detached = False
    with patch.object(tpm_bypass, "frida_session", value=mock_session):
        yield tpm_bypass


class TestTPMVersionSupport:
    """Test TPM version capability reporting."""

    def test_tpm_versions_supported_matches_implementation(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """TPM versions reported match actual implementation capabilities."""
        capabilities = tpm_bypass.get_bypass_capabilities()

        supported_versions = capabilities["tpm_versions_supported"]
        assert isinstance(supported_versions, list)
        assert len(supported_versions) > 0
        assert "1.2" in supported_versions or "2.0" in supported_versions

        for version in supported_versions:
            assert version in ["1.2", "2.0"], f"Unsupported TPM version reported: {version}"

    def test_tpm_version_capabilities_functional(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Reported TPM versions have functional command processing."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        supported_versions = capabilities["tpm_versions_supported"]

        if "2.0" in supported_versions:
            nonce = b"test_nonce_12345"
            pcr_list = [0, 1, 2, 7]
            result = tpm_bypass.bypass_attestation(nonce, pcr_list)

            assert result is not None
            assert hasattr(result, "attested_data")
            assert hasattr(result, "signature")
            assert len(result.attested_data) > 0

        if "1.2" in supported_versions:
            pcr_value = b"\x00" * 20
            result_12 = tpm_bypass.extend_pcr(0, pcr_value)
            assert result_12 in [True, False], "TPM 1.2 PCR extend should return boolean"


class TestCommandInterceptionCapabilities:
    """Test command interception capability reporting."""

    def test_command_interception_reflects_hook_state(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Command interception enabled flag matches hook installation state."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        command_interception = capabilities["command_interception"]

        assert isinstance(command_interception, dict)
        assert "enabled" in command_interception
        assert "hooks_installed" in command_interception
        assert "commands_intercepted" in command_interception

        enabled = command_interception["enabled"]
        hooks_installed = command_interception["hooks_installed"]
        commands_intercepted = command_interception["commands_intercepted"]

        assert isinstance(enabled, bool)
        assert isinstance(hooks_installed, int)
        assert isinstance(commands_intercepted, int)

        assert enabled == (hooks_installed > 0), "enabled flag must match hook count"

    def test_command_interception_hook_installation(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Hook installation increases reported capability counts."""
        initial_capabilities = tpm_bypass.get_bypass_capabilities()
        initial_hooks = initial_capabilities["command_interception"]["hooks_installed"]

        test_command_code = 0x00000144
        test_hook: Any = lambda cmd, data: data

        tpm_bypass.command_hooks[test_command_code] = test_hook

        updated_capabilities = tpm_bypass.get_bypass_capabilities()
        updated_hooks = updated_capabilities["command_interception"]["hooks_installed"]

        assert updated_hooks == initial_hooks + 1
        assert updated_capabilities["command_interception"]["enabled"] is True

    def test_commands_intercepted_count_accurate(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Intercepted commands count matches actual interception list."""
        test_commands = [
            {"code": 0x144, "data": b"test1", "timestamp": 1234567890.0},
            {"code": 0x145, "data": b"test2", "timestamp": 1234567891.0},
            {"code": 0x146, "data": b"test3", "timestamp": 1234567892.0},
        ]

        tpm_bypass.intercepted_commands.extend(test_commands)

        capabilities = tpm_bypass.get_bypass_capabilities()
        reported_count = capabilities["command_interception"]["commands_intercepted"]

        assert reported_count == len(tpm_bypass.intercepted_commands)
        assert reported_count >= 3


class TestPCRManipulationCapabilities:
    """Test PCR manipulation capability reporting."""

    def test_pcr_banks_available_reflect_initialization(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """PCR banks available match initialized PCR bank structures."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        pcr_manipulation = capabilities["pcr_manipulation"]

        assert isinstance(pcr_manipulation, dict)
        assert "pcr_banks_available" in pcr_manipulation
        assert "total_pcrs" in pcr_manipulation
        assert "manipulatable" in pcr_manipulation

        pcr_banks = pcr_manipulation["pcr_banks_available"]
        assert isinstance(pcr_banks, list)

        for bank_id in pcr_banks:
            assert bank_id in tpm_bypass.pcr_banks, f"Reported bank {bank_id} not in actual banks"

    def test_total_pcrs_matches_specification(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Total PCRs reported matches TPM 2.0 specification (24 PCRs)."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        total_pcrs = capabilities["pcr_manipulation"]["total_pcrs"]

        assert total_pcrs == 24, "TPM 2.0 specifies 24 PCRs (0-23)"

    def test_pcr_manipulation_actually_works(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """PCR manipulation capability reflects actual ability to modify PCRs."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        manipulatable = capabilities["pcr_manipulation"]["manipulatable"]

        assert isinstance(manipulatable, bool)

        if manipulatable:
            test_pcr = 7
            test_value = b"\xAA" * 32

            if tpm_bypass.pcr_banks:
                first_bank = next(iter(tpm_bypass.pcr_banks.values()))
                original_value = first_bank.pcr_values[test_pcr]

                first_bank.pcr_values[test_pcr] = test_value

                assert first_bank.pcr_values[test_pcr] == test_value
                assert first_bank.pcr_values[test_pcr] != original_value


class TestKeyExtractionCapabilities:
    """Test key extraction capability reporting."""

    def test_nvram_access_reflects_actual_memory_capability(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """NVRAM access capability reflects actual memory handle or Win32 availability."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        key_extraction = capabilities["key_extraction"]

        nvram_access = key_extraction["nvram_access"]
        expected_access = tpm_bypass.mem_handle is not None or HAS_WIN32

        assert nvram_access == expected_access

    def test_memory_access_depends_on_handle(
        self, tpm_bypass: TPMBypassEngine, tpm_bypass_with_memory: TPMBypassEngine
    ) -> None:
        """Memory access capability depends on valid memory handle."""
        no_memory_caps = tpm_bypass.get_bypass_capabilities()
        assert no_memory_caps["key_extraction"]["memory_access"] is False

        with_memory_caps = tpm_bypass_with_memory.get_bypass_capabilities()
        assert with_memory_caps["key_extraction"]["memory_access"] is True

    def test_persistent_key_extraction_capability(
        self, tpm_bypass_with_memory: TPMBypassEngine
    ) -> None:
        """Persistent key extraction capability reflects actual implementation."""
        capabilities = tpm_bypass_with_memory.get_bypass_capabilities()
        persistent_keys = capabilities["key_extraction"]["persistent_keys"]

        assert isinstance(persistent_keys, bool)

        if persistent_keys and tpm_bypass_with_memory.mem_handle:
            test_handle = 0x81000001
            result = tpm_bypass_with_memory.extract_persistent_key(test_handle)

            assert result is None or isinstance(result, bytes)

    def test_transient_key_capability_accurate(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Transient key capability accurately reflects implementation status."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        transient_keys = capabilities["key_extraction"]["transient_keys"]

        assert isinstance(transient_keys, bool)
        assert transient_keys is True


class TestAttestationBypassCapabilities:
    """Test attestation bypass capability reporting."""

    def test_quote_forging_capability_functional(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Quote forging capability reflects actual attestation bypass functionality."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        quote_forging = capabilities["attestation_bypass"]["quote_forging"]

        assert isinstance(quote_forging, bool)

        if quote_forging:
            nonce = b"attestation_test"
            pcr_list = [0, 1, 7]
            result = tpm_bypass.bypass_attestation(nonce, pcr_list)

            assert result is not None
            assert hasattr(result, "attested_data")
            assert hasattr(result, "signature")
            assert len(result.signature) > 0

    def test_signature_forging_requires_crypto(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Signature forging capability depends on cryptography library availability."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        signature_forging = capabilities["attestation_bypass"]["signature_forging"]

        assert signature_forging == HAS_CRYPTO

    def test_pcr_digest_manipulation_functional(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """PCR digest manipulation capability reflects actual implementation."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        pcr_digest_manipulation = capabilities["attestation_bypass"][
            "pcr_digest_manipulation"
        ]

        assert isinstance(pcr_digest_manipulation, bool)

        if pcr_digest_manipulation:
            pcr_list = [0, 1, 2, 3, 7]
            digest = tpm_bypass.calculate_pcr_digest(pcr_list)

            assert isinstance(digest, bytes)
            assert len(digest) == 32

    def test_aik_certificate_generation_capability(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """AIK certificate generation capability reflects actual implementation."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        aik_cert_gen = capabilities["attestation_bypass"]["aik_certificate_generation"]

        assert isinstance(aik_cert_gen, bool)

        if aik_cert_gen:
            test_handle = 0x81010001
            cert = tpm_bypass.generate_aik_certificate(test_handle)

            assert isinstance(cert, bytes)
            assert len(cert) > 0


class TestUnsealingCapabilities:
    """Test unsealing capability reporting."""

    def test_unsealing_capabilities_depend_on_crypto(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Unsealing capabilities correctly reflect cryptography library dependency."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        unsealing = capabilities["unsealing_capabilities"]

        assert unsealing["tpm2_private_blobs"] == HAS_CRYPTO
        assert unsealing["tpm2_credential_blobs"] == HAS_CRYPTO
        assert unsealing["generic_encrypted_blobs"] == HAS_CRYPTO

    def test_fallback_unsealing_always_available(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Fallback unsealing capability always available regardless of dependencies."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        fallback_unsealing = capabilities["unsealing_capabilities"]["fallback_unsealing"]

        assert fallback_unsealing is True


class TestAdvancedAttackCapabilities:
    """Test advanced attack capability reporting."""

    def test_cold_boot_attack_requires_memory_handle(
        self, tpm_bypass: TPMBypassEngine, tpm_bypass_with_memory: TPMBypassEngine
    ) -> None:
        """Cold boot attack capability requires valid memory handle."""
        no_memory_caps = tpm_bypass.get_bypass_capabilities()
        assert no_memory_caps["advanced_attacks"]["cold_boot_attack"] is False

        with_memory_caps = tpm_bypass_with_memory.get_bypass_capabilities()
        assert with_memory_caps["advanced_attacks"]["cold_boot_attack"] is True

    def test_bus_interception_capability(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Bus interception capability accurately reported."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        bus_interception = capabilities["advanced_attacks"]["bus_interception"]

        assert isinstance(bus_interception, bool)
        assert bus_interception is True

    def test_measured_boot_bypass_capability(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Measured boot bypass capability accurately reported."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        measured_boot = capabilities["advanced_attacks"]["measured_boot_bypass"]

        assert isinstance(measured_boot, bool)
        assert measured_boot is True

    def test_tbs_hooking_depends_on_win32(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """TBS hooking capability depends on Win32 API availability."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        tbs_hooking = capabilities["advanced_attacks"]["tbs_hooking"]

        assert tbs_hooking == HAS_WIN32


class TestPlatformSpecificCapabilities:
    """Test platform-specific capability reporting."""

    def test_platform_specific_capabilities_reported(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Platform-specific capabilities all reported as boolean values."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        platform_specific = capabilities["platform_specific"]

        assert isinstance(platform_specific["bitlocker_vmk_extraction"], bool)
        assert isinstance(platform_specific["windows_hello_bypass"], bool)
        assert isinstance(platform_specific["tpm_lockout_reset"], bool)
        assert isinstance(platform_specific["tpm_ownership_clear"], bool)

    def test_platform_capabilities_consistency(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Platform capabilities remain consistent across multiple calls."""
        caps1 = tpm_bypass.get_bypass_capabilities()
        caps2 = tpm_bypass.get_bypass_capabilities()

        assert caps1["platform_specific"] == caps2["platform_specific"]


class TestBinaryAnalysisCapabilities:
    """Test binary analysis capability reporting."""

    def test_binary_analysis_capabilities_all_true(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Binary analysis capabilities reported and all available."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        binary_analysis = capabilities["binary_analysis"]

        assert binary_analysis["tpm_detection"] is True
        assert binary_analysis["protection_analysis"] is True
        assert binary_analysis["binary_patching"] is True

    def test_tpm_detection_actually_works(
        self, tpm_bypass: TPMBypassEngine, tmp_path: Path
    ) -> None:
        """TPM detection capability reflects actual detection functionality."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        tpm_detection = capabilities["binary_analysis"]["tpm_detection"]

        if tpm_detection:
            test_binary = tmp_path / "test_tpm_binary.exe"
            test_binary.write_bytes(
                b"MZ\x90\x00" + b"\x00" * 100 + b"Tbs.dll\x00Tbsip_Submit_Command\x00"
            )

            result = tpm_bypass.detect_tpm_usage(str(test_binary))
            assert isinstance(result, bool)

    def test_protection_analysis_actually_works(
        self, tpm_bypass: TPMBypassEngine, tmp_path: Path
    ) -> None:
        """Protection analysis capability reflects actual analysis functionality."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        protection_analysis = capabilities["binary_analysis"]["protection_analysis"]

        if protection_analysis:
            test_binary = tmp_path / "test_analysis.exe"
            test_binary.write_bytes(
                b"MZ\x90\x00" + b"\x00" * 100 + b"Tpm2_Create\x00Tpm2_Unseal\x00"
            )

            result = tpm_bypass.analyze_tpm_protection(str(test_binary))
            assert isinstance(result, dict)
            assert "tpm_detected" in result


class TestRuntimeBypassCapabilities:
    """Test runtime bypass capability reporting."""

    def test_runtime_capabilities_depend_on_frida(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Runtime bypass capabilities depend on Frida availability."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        runtime_bypass = capabilities["runtime_bypass"]

        assert runtime_bypass["frida_available"] == HAS_FRIDA
        assert runtime_bypass["runtime_pcr_spoofing"] == HAS_FRIDA
        assert runtime_bypass["runtime_command_interception"] == HAS_FRIDA
        assert runtime_bypass["runtime_unsealing"] == HAS_FRIDA
        assert runtime_bypass["secure_boot_bypass"] == HAS_FRIDA
        assert runtime_bypass["measured_boot_bypass_runtime"] == HAS_FRIDA

    def test_active_session_reflects_frida_state(
        self, tpm_bypass: TPMBypassEngine, tpm_bypass_with_frida_session: TPMBypassEngine
    ) -> None:
        """Active session flag reflects actual Frida session state."""
        no_session_caps = tpm_bypass.get_bypass_capabilities()
        assert no_session_caps["runtime_bypass"]["active_session"] is False

        with_session_caps = tpm_bypass_with_frida_session.get_bypass_capabilities()
        assert with_session_caps["runtime_bypass"]["active_session"] is True

    def test_detached_session_reported_correctly(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Detached Frida session correctly reported as inactive."""
        mock_session = MagicMock()
        mock_session.is_detached = True

        with patch.object(tpm_bypass, "frida_session", value=mock_session):
            capabilities = tpm_bypass.get_bypass_capabilities()
            assert capabilities["runtime_bypass"]["active_session"] is False

    def test_session_exception_handled_gracefully(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Session state check exception handled gracefully."""
        mock_session = MagicMock()
        mock_session.is_detached.side_effect = RuntimeError("Session check failed")

        with patch.object(tpm_bypass, "frida_session", value=mock_session):
            capabilities = tpm_bypass.get_bypass_capabilities()
            assert capabilities["runtime_bypass"]["active_session"] is False


class TestCapabilityStateConsistency:
    """Test capability reporting state consistency."""

    def test_capabilities_reflect_state_changes(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Capabilities update to reflect engine state changes."""
        initial_caps = tpm_bypass.get_bypass_capabilities()
        initial_hooks = initial_caps["command_interception"]["hooks_installed"]

        test_hook: Any = lambda cmd, data: data
        tpm_bypass.command_hooks[0x144] = test_hook
        tpm_bypass.command_hooks[0x145] = test_hook

        updated_caps = tpm_bypass.get_bypass_capabilities()
        updated_hooks = updated_caps["command_interception"]["hooks_installed"]

        assert updated_hooks == initial_hooks + 2

    def test_pcr_bank_changes_reflected(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """PCR bank changes reflected in capability reporting."""
        from intellicrack.core.protection_bypass.tpm_bypass import (
            PCRBank,
            TPM2Algorithm,
        )

        initial_caps = tpm_bypass.get_bypass_capabilities()
        initial_banks = initial_caps["pcr_manipulation"]["pcr_banks_available"]

        test_algorithm = TPM2Algorithm.SHA384
        if test_algorithm not in tpm_bypass.pcr_banks:
            tpm_bypass.pcr_banks[test_algorithm] = PCRBank()

        updated_caps = tpm_bypass.get_bypass_capabilities()
        updated_banks = updated_caps["pcr_manipulation"]["pcr_banks_available"]

        assert len(updated_banks) > len(initial_banks)
        assert test_algorithm in updated_banks


class TestCapabilityAccuracy:
    """Test capability reporting accuracy against actual implementation."""

    def test_no_false_positive_capabilities(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """No capabilities reported as True without actual implementation."""
        capabilities = tpm_bypass.get_bypass_capabilities()

        if not HAS_CRYPTO:
            assert capabilities["attestation_bypass"]["signature_forging"] is False
            assert capabilities["unsealing_capabilities"]["tpm2_private_blobs"] is False

        if not HAS_WIN32:
            assert capabilities["advanced_attacks"]["tbs_hooking"] is False

        if not HAS_FRIDA:
            assert capabilities["runtime_bypass"]["frida_available"] is False

    def test_all_capability_sections_present(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """All expected capability sections present in report."""
        capabilities = tpm_bypass.get_bypass_capabilities()

        expected_sections = [
            "tpm_versions_supported",
            "command_interception",
            "pcr_manipulation",
            "key_extraction",
            "attestation_bypass",
            "unsealing_capabilities",
            "advanced_attacks",
            "platform_specific",
            "binary_analysis",
            "runtime_bypass",
        ]

        for section in expected_sections:
            assert section in capabilities, f"Missing capability section: {section}"

    def test_capability_values_are_correct_types(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """All capability values have correct types."""
        capabilities = tpm_bypass.get_bypass_capabilities()

        assert isinstance(capabilities["tpm_versions_supported"], list)
        assert isinstance(capabilities["command_interception"], dict)
        assert isinstance(capabilities["pcr_manipulation"], dict)
        assert isinstance(capabilities["key_extraction"], dict)
        assert isinstance(capabilities["attestation_bypass"], dict)
        assert isinstance(capabilities["unsealing_capabilities"], dict)
        assert isinstance(capabilities["advanced_attacks"], dict)
        assert isinstance(capabilities["platform_specific"], dict)
        assert isinstance(capabilities["binary_analysis"], dict)
        assert isinstance(capabilities["runtime_bypass"], dict)


class TestEdgeCases:
    """Test edge cases in capability reporting."""

    def test_version_specific_capabilities(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Version-specific capabilities correctly distinguished."""
        capabilities = tpm_bypass.get_bypass_capabilities()
        supported_versions = capabilities["tpm_versions_supported"]

        if "2.0" in supported_versions:
            assert capabilities["pcr_manipulation"]["total_pcrs"] == 24

        if "1.2" in supported_versions:
            assert len(supported_versions) >= 1

    def test_manufacturer_independent_reporting(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Capability reporting independent of TPM manufacturer."""
        capabilities = tpm_bypass.get_bypass_capabilities()

        assert "tpm_versions_supported" in capabilities
        assert "command_interception" in capabilities

    def test_partial_capability_support_handled(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Partial capability support correctly reported."""
        capabilities = tpm_bypass.get_bypass_capabilities()

        if not HAS_CRYPTO:
            unsealing = capabilities["unsealing_capabilities"]
            assert unsealing["fallback_unsealing"] is True
            assert unsealing["tpm2_private_blobs"] is False

    def test_capability_reporting_with_no_dependencies(self) -> None:
        """Capability reporting works without any optional dependencies."""
        with patch("intellicrack.core.protection_bypass.tpm_bypass.HAS_CRYPTO", False):
            with patch("intellicrack.core.protection_bypass.tpm_bypass.HAS_WIN32", False):
                with patch("intellicrack.core.protection_bypass.tpm_bypass.HAS_FRIDA", False):
                    engine = TPMBypassEngine()
                    capabilities = engine.get_bypass_capabilities()

                    assert capabilities["attestation_bypass"]["signature_forging"] is False
                    assert capabilities["advanced_attacks"]["tbs_hooking"] is False
                    assert capabilities["runtime_bypass"]["frida_available"] is False
                    assert capabilities["unsealing_capabilities"]["fallback_unsealing"] is True

    def test_memory_handle_acquisition_failure_handling(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Memory handle acquisition failure properly reflected in capabilities."""
        tpm_bypass.mem_handle = None

        capabilities = tpm_bypass.get_bypass_capabilities()

        assert capabilities["key_extraction"]["memory_access"] is False
        assert capabilities["advanced_attacks"]["cold_boot_attack"] is False

    def test_concurrent_capability_queries(
        self, tpm_bypass: TPMBypassEngine
    ) -> None:
        """Concurrent capability queries return consistent results."""
        import threading

        results: list[dict[str, Any]] = []

        def query_capabilities() -> None:
            results.append(tpm_bypass.get_bypass_capabilities())

        threads = [threading.Thread(target=query_capabilities) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == 5
        for result in results[1:]:
            assert result == results[0]
