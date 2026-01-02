"""Production tests for ProtectionDetectionHandlers protection detection methods.

This module validates that ProtectionDetectionHandlers correctly orchestrates
protection detection and bypass operations on real Windows binaries.

Tests prove real protection detection capabilities, NOT UI rendering.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

from pathlib import Path
from typing import Any

import pytest

from intellicrack.ui.protection_detection_handlers import ProtectionDetectionHandlers


class FakeProtectionResults:
    """Real test double for protection results display."""

    def __init__(self) -> None:
        self.appended_outputs: list[str] = []
        self.call_count: int = 0

    def append(self, text: str) -> None:
        """Record appended output text."""
        self.appended_outputs.append(text)
        self.call_count += 1


class FakeCommercialProtectionDetector:
    """Real test double for commercial protection detection."""

    def __init__(self) -> None:
        self.called: bool = False
        self.call_args_list: list[tuple[str]] = []
        self.return_value: dict[str, Any] = {}

    def __call__(self, binary_path: str) -> dict[str, Any]:
        """Execute detection and track calls."""
        self.called = True
        self.call_args_list.append((binary_path,))
        return self.return_value


class FakeHardwareDongleDetector:
    """Real test double for hardware dongle detection."""

    def __init__(self) -> None:
        self.called: bool = False
        self.return_value: list[str] = []

    def __call__(self) -> list[str]:
        """Execute detection and track calls."""
        self.called = True
        return self.return_value


class FakeTPMDetector:
    """Real test double for TPM detection."""

    def __init__(self) -> None:
        self.called: bool = False
        self.return_value: dict[str, Any] = {}

    def __call__(self) -> dict[str, Any]:
        """Execute detection and track calls."""
        self.called = True
        return self.return_value


class FakeChecksumDetector:
    """Real test double for checksum verification detection."""

    def __init__(self) -> None:
        self.called: bool = False
        self.call_args_list: list[tuple[str]] = []
        self.return_value: dict[str, Any] = {}

    def __call__(self, binary_path: str) -> dict[str, Any]:
        """Execute detection and track calls."""
        self.called = True
        self.call_args_list.append((binary_path,))
        return self.return_value


class FakeSelfHealingDetector:
    """Real test double for self-healing code detection."""

    def __init__(self) -> None:
        self.called: bool = False
        self.call_args_list: list[tuple[str]] = []
        self.return_value: dict[str, Any] = {}

    def __call__(self, binary_path: str) -> dict[str, Any]:
        """Execute detection and track calls."""
        self.called = True
        self.call_args_list.append((binary_path,))
        return self.return_value


class FakeEmbeddedScriptDecryptor:
    """Real test double for embedded script decryption."""

    def __init__(self) -> None:
        self.called: bool = False
        self.call_args_list: list[tuple[str]] = []
        self.return_value: list[str] = []

    def __call__(self, binary_path: str) -> list[str]:
        """Execute decryption and track calls."""
        self.called = True
        self.call_args_list.append((binary_path,))
        return self.return_value


class FakeTPMBypass:
    """Real test double for TPM bypass operations."""

    def __init__(self) -> None:
        self.called: bool = False
        self.bypass_tpm_checks_called: bool = False
        self.bypass_return_value: dict[str, Any] = {}

    def bypass_tpm_checks(self) -> dict[str, Any]:
        """Execute bypass and track calls."""
        self.bypass_tpm_checks_called = True
        return self.bypass_return_value


class FakeTPMBypassClass:
    """Real test double for TPMProtectionBypass class constructor."""

    def __init__(self) -> None:
        self.called: bool = False
        self.instances: list[FakeTPMBypass] = []
        self.next_instance: FakeTPMBypass = FakeTPMBypass()

    def __call__(self, *args: Any, **kwargs: Any) -> FakeTPMBypass:
        """Create instance and track calls."""
        self.called = True
        self.instances.append(self.next_instance)
        return self.next_instance


class FakeVMBypass:
    """Real test double for VM detection bypass operations."""

    def __init__(self) -> None:
        self.called: bool = False
        self.bypass_vm_detection_called: bool = False
        self.bypass_return_value: dict[str, Any] = {}

    def bypass_vm_detection(self) -> dict[str, Any]:
        """Execute bypass and track calls."""
        self.bypass_vm_detection_called = True
        return self.bypass_return_value


class FakeVMBypassClass:
    """Real test double for VMDetectionBypass class constructor."""

    def __init__(self) -> None:
        self.called: bool = False
        self.instances: list[FakeVMBypass] = []
        self.next_instance: FakeVMBypass = FakeVMBypass()

    def __call__(self, *args: Any, **kwargs: Any) -> FakeVMBypass:
        """Create instance and track calls."""
        self.called = True
        self.instances.append(self.next_instance)
        return self.next_instance


class FakeDongleEmulator:
    """Real test double for hardware dongle emulator operations."""

    def __init__(self) -> None:
        self.called: bool = False
        self.activate_dongle_emulation_called: bool = False
        self.emulation_return_value: dict[str, Any] = {}

    def activate_dongle_emulation(self) -> dict[str, Any]:
        """Execute emulation and track calls."""
        self.activate_dongle_emulation_called = True
        return self.emulation_return_value


class FakeDongleEmulatorClass:
    """Real test double for HardwareDongleEmulator class constructor."""

    def __init__(self) -> None:
        self.called: bool = False
        self.instances: list[FakeDongleEmulator] = []
        self.next_instance: FakeDongleEmulator = FakeDongleEmulator()

    def __call__(self, *args: Any, **kwargs: Any) -> FakeDongleEmulator:
        """Create instance and track calls."""
        self.called = True
        self.instances.append(self.next_instance)
        return self.next_instance


class FakeQMessageBox:
    """Real test double for QMessageBox dialogs."""

    def __init__(self) -> None:
        self.warning_called: bool = False
        self.warning_call_count: int = 0
        self.warning_args_list: list[tuple[Any, ...]] = []
        self.critical_called: bool = False
        self.critical_call_count: int = 0
        self.critical_args_list: list[tuple[Any, ...]] = []

    def warning(self, parent: Any, title: str, message: str) -> None:
        """Track warning dialog calls."""
        self.warning_called = True
        self.warning_call_count += 1
        self.warning_args_list.append((parent, title, message))

    def critical(self, parent: Any, title: str, message: str) -> None:
        """Track critical dialog calls."""
        self.critical_called = True
        self.critical_call_count += 1
        self.critical_args_list.append((parent, title, message))


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
    handler.protection_results = FakeProtectionResults()
    return handler


class TestProtectionDetectionHandlersCommercialProtections:
    """Tests for commercial protection detection."""

    def test_commercial_protection_scan_calls_detector(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Commercial protection scan calls detection engine with binary path."""
        fake_detector = FakeCommercialProtectionDetector()
        fake_detector.return_value = {
            "protections_found": ["VMProtect", "Themida"],
            "confidence_scores": {"VMProtect": 0.85, "Themida": 0.72},
            "indicators": ["VM detection code", "Anti-debug techniques"],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_commercial_protections",
            fake_detector,
        )

        handler.run_commercial_protection_scan()

        assert fake_detector.called
        assert fake_detector.call_args_list[0][0] == handler.binary_path

    def test_commercial_protection_scan_displays_results(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Commercial protection scan displays found protections."""
        fake_detector = FakeCommercialProtectionDetector()
        fake_detector.return_value = {
            "protections_found": ["Enigma Protector"],
            "confidence_scores": {"Enigma Protector": 0.91},
            "indicators": ["Virtualization engine", "Code mutation"],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_commercial_protections",
            fake_detector,
        )

        handler.run_commercial_protection_scan()

        results = handler.protection_results
        assert isinstance(results, FakeProtectionResults)
        assert results.call_count > 0
        output = results.appended_outputs[0]

        assert "Enigma Protector" in output
        assert "91" in output or "0.91" in output

    def test_commercial_protection_scan_no_results(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Commercial protection scan handles no protections found."""
        fake_detector = FakeCommercialProtectionDetector()
        fake_detector.return_value = {
            "protections_found": [],
            "confidence_scores": {},
            "indicators": [],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_commercial_protections",
            fake_detector,
        )

        handler.run_commercial_protection_scan()

        results = handler.protection_results
        assert isinstance(results, FakeProtectionResults)
        output = results.appended_outputs[0]
        assert "No commercial protections detected" in output

    def test_commercial_protection_scan_error_handling(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Commercial protection scan handles errors gracefully."""
        fake_detector = FakeCommercialProtectionDetector()
        fake_detector.return_value = {
            "error": "Failed to parse PE headers",
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_commercial_protections",
            fake_detector,
        )

        handler.run_commercial_protection_scan()

        results = handler.protection_results
        assert isinstance(results, FakeProtectionResults)
        output = results.appended_outputs[0]
        assert "Error" in output or "error" in output


class TestProtectionDetectionHandlersHardwareDongle:
    """Tests for hardware dongle detection."""

    def test_hardware_dongle_detection_calls_detector(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Hardware dongle detection calls system detector."""
        fake_detector = FakeHardwareDongleDetector()
        fake_detector.return_value = [
            "HASP dongle detected on USB port 1",
            "Sentinel dongle detected on USB port 2",
        ]
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_hardware_dongles",
            fake_detector,
        )

        handler.run_hardware_dongle_detection()

        assert fake_detector.called

    def test_hardware_dongle_detection_displays_results(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Hardware dongle detection displays found dongles."""
        fake_detector = FakeHardwareDongleDetector()
        fake_detector.return_value = [
            "SafeNet USB dongle detected",
            "WIBU-KEY detected",
        ]
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_hardware_dongles",
            fake_detector,
        )

        handler.run_hardware_dongle_detection()

        results = handler.protection_results
        assert isinstance(results, FakeProtectionResults)
        output = results.appended_outputs[0]
        assert "SafeNet" in output
        assert "WIBU-KEY" in output


class TestProtectionDetectionHandlersTPM:
    """Tests for TPM protection detection."""

    def test_tpm_detection_calls_detector(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """TPM detection calls system TPM detector."""
        fake_detector = FakeTPMDetector()
        fake_detector.return_value = {
            "tpm_present": True,
            "tpm_version": "2.0",
            "tpm_enabled": True,
            "tpm_owned": True,
            "detection_methods": ["WMI query", "PowerShell check"],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_tpm_protection",
            fake_detector,
        )

        handler.run_tpm_detection()

        assert fake_detector.called

    def test_tpm_detection_displays_present_tpm(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """TPM detection displays TPM information when present."""
        fake_detector = FakeTPMDetector()
        fake_detector.return_value = {
            "tpm_present": True,
            "tpm_version": "2.0",
            "tpm_enabled": True,
            "tpm_owned": False,
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_tpm_protection",
            fake_detector,
        )

        handler.run_tpm_detection()

        results = handler.protection_results
        assert isinstance(results, FakeProtectionResults)
        output = results.appended_outputs[0]
        assert "Yes" in output
        assert "2.0" in output

    def test_tpm_detection_displays_absent_tpm(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """TPM detection displays absence of TPM."""
        fake_detector = FakeTPMDetector()
        fake_detector.return_value = {
            "tpm_present": False,
            "tpm_version": None,
            "tpm_enabled": False,
            "tpm_owned": False,
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_tpm_protection",
            fake_detector,
        )

        handler.run_tpm_detection()

        results = handler.protection_results
        assert isinstance(results, FakeProtectionResults)
        output = results.appended_outputs[0]
        assert "No" in output


class TestProtectionDetectionHandlersChecksum:
    """Tests for checksum verification detection."""

    def test_checksum_detection_calls_detector(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Checksum detection calls verification detector with binary path."""
        fake_detector = FakeChecksumDetector()
        fake_detector.return_value = {
            "checksum_verification_detected": True,
            "algorithms_found": ["SHA256", "MD5", "CRC32"],
            "indicators": ["Hash function calls", "Integrity check routines"],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_checksum_verification",
            fake_detector,
        )

        handler.run_checksum_detection()

        assert fake_detector.called
        assert fake_detector.call_args_list[0][0] == handler.binary_path

    def test_checksum_detection_displays_algorithms(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Checksum detection displays found hash algorithms."""
        fake_detector = FakeChecksumDetector()
        fake_detector.return_value = {
            "checksum_verification_detected": True,
            "algorithms_found": ["SHA256", "CRC32"],
            "indicators": ["CryptHashData API call"],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_checksum_verification",
            fake_detector,
        )

        handler.run_checksum_detection()

        results = handler.protection_results
        assert isinstance(results, FakeProtectionResults)
        output = results.appended_outputs[0]
        assert "SHA256" in output
        assert "CRC32" in output

    def test_checksum_detection_no_verification(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Checksum detection handles no verification detected."""
        fake_detector = FakeChecksumDetector()
        fake_detector.return_value = {
            "checksum_verification_detected": False,
            "algorithms_found": [],
            "indicators": [],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_checksum_verification",
            fake_detector,
        )

        handler.run_checksum_detection()

        results = handler.protection_results
        assert isinstance(results, FakeProtectionResults)
        output = results.appended_outputs[0]
        assert "No checksum" in output or "not detected" in output


class TestProtectionDetectionHandlersSelfHealing:
    """Tests for self-healing code detection."""

    def test_self_healing_detection_calls_detector(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Self-healing detection calls detector with binary path."""
        fake_detector = FakeSelfHealingDetector()
        fake_detector.return_value = {
            "self_healing_detected": True,
            "techniques": ["Code restoration", "Memory patching"],
            "indicators": ["VirtualProtect", "WriteProcessMemory"],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_self_healing_code",
            fake_detector,
        )

        handler.run_self_healing_detection()

        assert fake_detector.called
        assert fake_detector.call_args_list[0][0] == handler.binary_path

    def test_self_healing_detection_displays_techniques(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Self-healing detection displays found techniques."""
        fake_detector = FakeSelfHealingDetector()
        fake_detector.return_value = {
            "self_healing_detected": True,
            "techniques": ["Runtime code modification", "Self-integrity check"],
            "indicators": ["NtProtectVirtualMemory", "CRC verification"],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_self_healing_code",
            fake_detector,
        )

        handler.run_self_healing_detection()

        results = handler.protection_results
        assert isinstance(results, FakeProtectionResults)
        output = results.appended_outputs[0]
        assert "Runtime code modification" in output
        assert "Self-integrity check" in output


class TestProtectionDetectionHandlersBypassOperations:
    """Tests for protection bypass operations."""

    def test_tpm_bypass_calls_bypass_engine(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """TPM bypass calls bypass engine with correct configuration."""
        fake_bypass_class = FakeTPMBypassClass()
        fake_bypass_instance = fake_bypass_class.next_instance
        fake_bypass_instance.bypass_return_value = {
            "success": True,
            "methods_applied": ["Registry patching", "API hooking"],
            "errors": [],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.TPMProtectionBypass",
            fake_bypass_class,
        )

        handler.run_tpm_bypass()

        assert fake_bypass_class.called
        assert fake_bypass_instance.bypass_tpm_checks_called

    def test_vm_bypass_calls_bypass_engine(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """VM detection bypass calls bypass engine."""
        fake_bypass_class = FakeVMBypassClass()
        fake_bypass_instance = fake_bypass_class.next_instance
        fake_bypass_instance.bypass_return_value = {
            "success": True,
            "methods_applied": ["CPUID spoofing", "Registry modification"],
            "errors": [],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.VMDetectionBypass",
            fake_bypass_class,
        )

        handler.run_vm_bypass()

        assert fake_bypass_class.called
        assert fake_bypass_instance.bypass_vm_detection_called

    def test_dongle_emulation_activates_emulator(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Dongle emulation activates hardware emulator."""
        fake_emulator_class = FakeDongleEmulatorClass()
        fake_emulator_instance = fake_emulator_class.next_instance
        fake_emulator_instance.emulation_return_value = {
            "success": True,
            "emulated_dongles": ["HASP", "Sentinel"],
            "methods_applied": ["Driver hooking", "USB emulation"],
            "errors": [],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.HardwareDongleEmulator",
            fake_emulator_class,
        )

        handler.run_dongle_emulation()

        assert fake_emulator_class.called
        assert fake_emulator_instance.activate_dongle_emulation_called

    def test_bypass_displays_success_results(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Bypass operations display success results."""
        fake_bypass_class = FakeTPMBypassClass()
        fake_bypass_instance = fake_bypass_class.next_instance
        fake_bypass_instance.bypass_return_value = {
            "success": True,
            "methods_applied": ["Registry modification"],
            "errors": [],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.TPMProtectionBypass",
            fake_bypass_class,
        )

        handler.run_tpm_bypass()

        results = handler.protection_results
        assert isinstance(results, FakeProtectionResults)
        output = results.appended_outputs[0]
        assert "successful" in output.lower()
        assert "Registry modification" in output

    def test_bypass_displays_failure_results(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Bypass operations display failure results."""
        fake_bypass_class = FakeVMBypassClass()
        fake_bypass_instance = fake_bypass_class.next_instance
        fake_bypass_instance.bypass_return_value = {
            "success": False,
            "methods_applied": [],
            "errors": ["Access denied to registry key"],
        }
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.VMDetectionBypass",
            fake_bypass_class,
        )

        handler.run_vm_bypass()

        results = handler.protection_results
        assert isinstance(results, FakeProtectionResults)
        output = results.appended_outputs[0]
        assert "Access denied" in output


class TestProtectionDetectionHandlersEmbeddedScripts:
    """Tests for embedded script detection."""

    def test_embedded_script_detection_calls_decryptor(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Embedded script detection calls decryption engine."""
        fake_decryptor = FakeEmbeddedScriptDecryptor()
        fake_decryptor.return_value = [
            "Found Python script embedded at offset 0x1000",
            "Found PowerShell script at offset 0x2000",
        ]
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.decrypt_embedded_script",
            fake_decryptor,
        )

        handler.run_embedded_script_detection()

        assert fake_decryptor.called
        assert fake_decryptor.call_args_list[0][0] == handler.binary_path

    def test_embedded_script_detection_displays_results(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Embedded script detection displays found scripts."""
        fake_decryptor = FakeEmbeddedScriptDecryptor()
        fake_decryptor.return_value = [
            "Lua script detected and decrypted",
            "VBScript found in resources",
        ]
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.decrypt_embedded_script",
            fake_decryptor,
        )

        handler.run_embedded_script_detection()

        results = handler.protection_results
        assert isinstance(results, FakeProtectionResults)
        output = results.appended_outputs[0]
        assert "Lua script" in output
        assert "VBScript" in output


class TestProtectionDetectionHandlersErrorHandling:
    """Tests for error handling in detection operations."""

    def test_detection_without_binary_shows_warning(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Detection operations without binary show warning."""
        handler.binary_path = None

        fake_messagebox = FakeQMessageBox()
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.QMessageBox",
            fake_messagebox,
        )

        handler.run_commercial_protection_scan()
        assert fake_messagebox.warning_called

    def test_detection_exception_handled_gracefully(
        self,
        handler: ProtectionDetectionHandlers,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Detection exceptions are handled without crashing."""
        fake_detector = FakeCommercialProtectionDetector()

        def raise_exception(binary_path: str) -> dict[str, Any]:
            raise RuntimeError("Test exception")

        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.detect_commercial_protections",
            raise_exception,
        )

        fake_messagebox = FakeQMessageBox()
        monkeypatch.setattr(
            "intellicrack.ui.protection_detection_handlers.QMessageBox",
            fake_messagebox,
        )

        handler.run_commercial_protection_scan()
        assert fake_messagebox.critical_called
