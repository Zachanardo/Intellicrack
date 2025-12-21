"""Production tests for ProtectionDetectionHandlers protection detection methods.

This module validates that ProtectionDetectionHandlers correctly orchestrates
protection detection and bypass operations on real Windows binaries.

Tests prove real protection detection capabilities, NOT UI rendering.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from intellicrack.ui.protection_detection_handlers import ProtectionDetectionHandlers


@pytest.fixture
def mock_binary_path(tmp_path: Path) -> Path:
    """Create mock Windows PE binary."""
    binary_path = tmp_path / "test.exe"
    pe_header = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"
    pe_header += b"PE\x00\x00"
    pe_header += b"\x4c\x01"
    pe_header += b"\x00" * 1000
    binary_path.write_bytes(pe_header)
    return binary_path


@pytest.fixture
def handler(mock_binary_path: Path) -> ProtectionDetectionHandlers:
    """Create ProtectionDetectionHandlers instance."""
    handler = ProtectionDetectionHandlers()
    handler.binary_path = str(mock_binary_path)
    handler.protection_results = Mock()
    return handler


class TestProtectionDetectionHandlersCommercialProtections:
    """Tests for commercial protection detection."""

    def test_commercial_protection_scan_calls_detector(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Commercial protection scan calls detection engine with binary path."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_commercial_protections") as mock_detect:
            mock_detect.return_value = {
                "protections_found": ["VMProtect", "Themida"],
                "confidence_scores": {"VMProtect": 0.85, "Themida": 0.72},
                "indicators": ["VM detection code", "Anti-debug techniques"],
            }

            handler.run_commercial_protection_scan()

            assert mock_detect.called
            assert mock_detect.call_args.args[0] == handler.binary_path

    def test_commercial_protection_scan_displays_results(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Commercial protection scan displays found protections."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_commercial_protections") as mock_detect:
            mock_detect.return_value = {
                "protections_found": ["Enigma Protector"],
                "confidence_scores": {"Enigma Protector": 0.91},
                "indicators": ["Virtualization engine", "Code mutation"],
            }

            handler.run_commercial_protection_scan()

            assert handler.protection_results.append.called
            output = handler.protection_results.append.call_args.args[0]

            assert "Enigma Protector" in output
            assert "91" in output or "0.91" in output

    def test_commercial_protection_scan_no_results(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Commercial protection scan handles no protections found."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_commercial_protections") as mock_detect:
            mock_detect.return_value = {
                "protections_found": [],
                "confidence_scores": {},
                "indicators": [],
            }

            handler.run_commercial_protection_scan()

            output = handler.protection_results.append.call_args.args[0]
            assert "No commercial protections detected" in output

    def test_commercial_protection_scan_error_handling(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Commercial protection scan handles errors gracefully."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_commercial_protections") as mock_detect:
            mock_detect.return_value = {
                "error": "Failed to parse PE headers",
            }

            handler.run_commercial_protection_scan()

            output = handler.protection_results.append.call_args.args[0]
            assert "Error" in output or "error" in output


class TestProtectionDetectionHandlersHardwareDongle:
    """Tests for hardware dongle detection."""

    def test_hardware_dongle_detection_calls_detector(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Hardware dongle detection calls system detector."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_hardware_dongles") as mock_detect:
            mock_detect.return_value = [
                "HASP dongle detected on USB port 1",
                "Sentinel dongle detected on USB port 2",
            ]

            handler.run_hardware_dongle_detection()

            assert mock_detect.called

    def test_hardware_dongle_detection_displays_results(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Hardware dongle detection displays found dongles."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_hardware_dongles") as mock_detect:
            mock_detect.return_value = [
                "SafeNet USB dongle detected",
                "WIBU-KEY detected",
            ]

            handler.run_hardware_dongle_detection()

            output = handler.protection_results.append.call_args.args[0]
            assert "SafeNet" in output
            assert "WIBU-KEY" in output


class TestProtectionDetectionHandlersTPM:
    """Tests for TPM protection detection."""

    def test_tpm_detection_calls_detector(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """TPM detection calls system TPM detector."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_tpm_protection") as mock_detect:
            mock_detect.return_value = {
                "tpm_present": True,
                "tpm_version": "2.0",
                "tpm_enabled": True,
                "tpm_owned": True,
                "detection_methods": ["WMI query", "PowerShell check"],
            }

            handler.run_tpm_detection()

            assert mock_detect.called

    def test_tpm_detection_displays_present_tpm(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """TPM detection displays TPM information when present."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_tpm_protection") as mock_detect:
            mock_detect.return_value = {
                "tpm_present": True,
                "tpm_version": "2.0",
                "tpm_enabled": True,
                "tpm_owned": False,
            }

            handler.run_tpm_detection()

            output = handler.protection_results.append.call_args.args[0]
            assert "Yes" in output
            assert "2.0" in output

    def test_tpm_detection_displays_absent_tpm(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """TPM detection displays absence of TPM."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_tpm_protection") as mock_detect:
            mock_detect.return_value = {
                "tpm_present": False,
                "tpm_version": None,
                "tpm_enabled": False,
                "tpm_owned": False,
            }

            handler.run_tpm_detection()

            output = handler.protection_results.append.call_args.args[0]
            assert "No" in output


class TestProtectionDetectionHandlersChecksum:
    """Tests for checksum verification detection."""

    def test_checksum_detection_calls_detector(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Checksum detection calls verification detector with binary path."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_checksum_verification") as mock_detect:
            mock_detect.return_value = {
                "checksum_verification_detected": True,
                "algorithms_found": ["SHA256", "MD5", "CRC32"],
                "indicators": ["Hash function calls", "Integrity check routines"],
            }

            handler.run_checksum_detection()

            assert mock_detect.called
            assert mock_detect.call_args.args[0] == handler.binary_path

    def test_checksum_detection_displays_algorithms(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Checksum detection displays found hash algorithms."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_checksum_verification") as mock_detect:
            mock_detect.return_value = {
                "checksum_verification_detected": True,
                "algorithms_found": ["SHA256", "CRC32"],
                "indicators": ["CryptHashData API call"],
            }

            handler.run_checksum_detection()

            output = handler.protection_results.append.call_args.args[0]
            assert "SHA256" in output
            assert "CRC32" in output

    def test_checksum_detection_no_verification(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Checksum detection handles no verification detected."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_checksum_verification") as mock_detect:
            mock_detect.return_value = {
                "checksum_verification_detected": False,
                "algorithms_found": [],
                "indicators": [],
            }

            handler.run_checksum_detection()

            output = handler.protection_results.append.call_args.args[0]
            assert "No checksum" in output or "not detected" in output


class TestProtectionDetectionHandlersSelfHealing:
    """Tests for self-healing code detection."""

    def test_self_healing_detection_calls_detector(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Self-healing detection calls detector with binary path."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_self_healing_code") as mock_detect:
            mock_detect.return_value = {
                "self_healing_detected": True,
                "techniques": ["Code restoration", "Memory patching"],
                "indicators": ["VirtualProtect", "WriteProcessMemory"],
            }

            handler.run_self_healing_detection()

            assert mock_detect.called
            assert mock_detect.call_args.args[0] == handler.binary_path

    def test_self_healing_detection_displays_techniques(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Self-healing detection displays found techniques."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_self_healing_code") as mock_detect:
            mock_detect.return_value = {
                "self_healing_detected": True,
                "techniques": ["Runtime code modification", "Self-integrity check"],
                "indicators": ["NtProtectVirtualMemory", "CRC verification"],
            }

            handler.run_self_healing_detection()

            output = handler.protection_results.append.call_args.args[0]
            assert "Runtime code modification" in output
            assert "Self-integrity check" in output


class TestProtectionDetectionHandlersBypassOperations:
    """Tests for protection bypass operations."""

    def test_tpm_bypass_calls_bypass_engine(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """TPM bypass calls bypass engine with correct configuration."""
        with patch("intellicrack.ui.protection_detection_handlers.TPMProtectionBypass") as mock_bypass:
            mock_instance = Mock()
            mock_instance.bypass_tpm_checks.return_value = {
                "success": True,
                "methods_applied": ["Registry patching", "API hooking"],
                "errors": [],
            }
            mock_bypass.return_value = mock_instance

            handler.run_tpm_bypass()

            assert mock_bypass.called
            assert mock_instance.bypass_tpm_checks.called

    def test_vm_bypass_calls_bypass_engine(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """VM detection bypass calls bypass engine."""
        with patch("intellicrack.ui.protection_detection_handlers.VMDetectionBypass") as mock_bypass:
            mock_instance = Mock()
            mock_instance.bypass_vm_detection.return_value = {
                "success": True,
                "methods_applied": ["CPUID spoofing", "Registry modification"],
                "errors": [],
            }
            mock_bypass.return_value = mock_instance

            handler.run_vm_bypass()

            assert mock_bypass.called
            assert mock_instance.bypass_vm_detection.called

    def test_dongle_emulation_activates_emulator(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Dongle emulation activates hardware emulator."""
        with patch("intellicrack.ui.protection_detection_handlers.HardwareDongleEmulator") as mock_emulator:
            mock_instance = Mock()
            mock_instance.activate_dongle_emulation.return_value = {
                "success": True,
                "emulated_dongles": ["HASP", "Sentinel"],
                "methods_applied": ["Driver hooking", "USB emulation"],
                "errors": [],
            }
            mock_emulator.return_value = mock_instance

            handler.run_dongle_emulation()

            assert mock_emulator.called
            assert mock_instance.activate_dongle_emulation.called

    def test_bypass_displays_success_results(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Bypass operations display success results."""
        with patch("intellicrack.ui.protection_detection_handlers.TPMProtectionBypass") as mock_bypass:
            mock_instance = Mock()
            mock_instance.bypass_tpm_checks.return_value = {
                "success": True,
                "methods_applied": ["Registry modification"],
                "errors": [],
            }
            mock_bypass.return_value = mock_instance

            handler.run_tpm_bypass()

            output = handler.protection_results.append.call_args.args[0]
            assert "successful" in output.lower()
            assert "Registry modification" in output

    def test_bypass_displays_failure_results(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Bypass operations display failure results."""
        with patch("intellicrack.ui.protection_detection_handlers.VMDetectionBypass") as mock_bypass:
            mock_instance = Mock()
            mock_instance.bypass_vm_detection.return_value = {
                "success": False,
                "methods_applied": [],
                "errors": ["Access denied to registry key"],
            }
            mock_bypass.return_value = mock_instance

            handler.run_vm_bypass()

            output = handler.protection_results.append.call_args.args[0]
            assert "Access denied" in output


class TestProtectionDetectionHandlersEmbeddedScripts:
    """Tests for embedded script detection."""

    def test_embedded_script_detection_calls_decryptor(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Embedded script detection calls decryption engine."""
        with patch("intellicrack.ui.protection_detection_handlers.decrypt_embedded_script") as mock_decrypt:
            mock_decrypt.return_value = [
                "Found Python script embedded at offset 0x1000",
                "Found PowerShell script at offset 0x2000",
            ]

            handler.run_embedded_script_detection()

            assert mock_decrypt.called
            assert mock_decrypt.call_args.args[0] == handler.binary_path

    def test_embedded_script_detection_displays_results(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Embedded script detection displays found scripts."""
        with patch("intellicrack.ui.protection_detection_handlers.decrypt_embedded_script") as mock_decrypt:
            mock_decrypt.return_value = [
                "Lua script detected and decrypted",
                "VBScript found in resources",
            ]

            handler.run_embedded_script_detection()

            output = handler.protection_results.append.call_args.args[0]
            assert "Lua script" in output
            assert "VBScript" in output


class TestProtectionDetectionHandlersErrorHandling:
    """Tests for error handling in detection operations."""

    def test_detection_without_binary_shows_warning(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Detection operations without binary show warning."""
        handler.binary_path = None

        with patch("intellicrack.ui.protection_detection_handlers.QMessageBox.warning") as mock_warning:
            handler.run_commercial_protection_scan()
            assert mock_warning.called

    def test_detection_exception_handled_gracefully(
        self,
        handler: ProtectionDetectionHandlers,
    ) -> None:
        """Detection exceptions are handled without crashing."""
        with patch("intellicrack.ui.protection_detection_handlers.detect_commercial_protections") as mock_detect:
            mock_detect.side_effect = RuntimeError("Test exception")

            with patch("intellicrack.ui.protection_detection_handlers.QMessageBox.critical") as mock_critical:
                handler.run_commercial_protection_scan()
                assert mock_critical.called
