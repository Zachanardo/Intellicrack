"""Comprehensive Tests for VM Detection Bypass.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import os
import platform
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.protection_bypass.vm_bypass import (
    FRIDA_AVAILABLE,
    WINREG_AVAILABLE,
    VMDetector,
    VirtualizationAnalyzer,
    VirtualizationDetectionBypass,
    analyze_vm_protection,
    bypass_vm_detection,
    detect_virtualization,
)


@pytest.fixture
def sample_binary_with_vm_detection(tmp_path: Path) -> Path:
    """Create test binary with VM detection instructions."""
    binary_path = tmp_path / "vm_protected.exe"

    vm_detection_code = bytearray(4096)

    vm_detection_code[:2] = b"\x4D\x5A"

    vm_detection_code[100:102] = b"\x0f\xa2"
    vm_detection_code[150:152] = b"\x0f\x31"
    vm_detection_code[200:203] = b"\x0f\x00\xc8"
    vm_detection_code[250:252] = b"\xe5\x10"

    vm_detection_code[300:308] = b"\x0f\xa2\xf7\xc1\x00\x00\x00\x80"

    vm_strings = [
        b"VirtualBox\x00",
        b"VMware\x00",
        b"QEMU\x00",
        b"Hyper-V\x00",
        b"VBOX\x00",
        b"vboxguest\x00",
        b"vmhgfs\x00",
    ]

    offset = 500
    for vm_string in vm_strings:
        vm_detection_code[offset:offset + len(vm_string)] = vm_string
        offset += len(vm_string) + 10

    binary_path.write_bytes(bytes(vm_detection_code))
    return binary_path


@pytest.fixture
def sample_binary_no_vm_detection(tmp_path: Path) -> Path:
    """Create test binary without VM detection."""
    binary_path = tmp_path / "clean.exe"

    clean_code = bytearray(2048)
    clean_code[:2] = b"\x4D\x5A"
    clean_code[100:150] = b"\x90" * 50

    binary_path.write_bytes(bytes(clean_code))
    return binary_path


@pytest.fixture
def mock_app_with_binary(sample_binary_with_vm_detection: Path) -> object:
    """Create mock application object with binary path."""
    class MockApp:
        def __init__(self, binary_path: Path) -> None:
            self.binary_path = str(binary_path)

    return MockApp(sample_binary_with_vm_detection)


@pytest.fixture
def mock_app_no_binary() -> object:
    """Create mock application object without binary path."""
    class MockApp:
        def __init__(self) -> None:
            self.binary_path = None

    return MockApp()


class TestVirtualizationDetectionBypass:
    """Test suite for VirtualizationDetectionBypass class."""

    def test_initialization_with_app(self, mock_app_with_binary: object) -> None:
        """Bypass initializes correctly with application instance."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        assert bypass.app == mock_app_with_binary
        assert hasattr(bypass, "logger")
        assert isinstance(bypass.hooks, list)
        assert isinstance(bypass.patches, list)
        assert len(bypass.hooks) == 0
        assert len(bypass.patches) == 0

    def test_initialization_without_app(self) -> None:
        """Bypass initializes correctly without application instance."""
        bypass = VirtualizationDetectionBypass(None)

        assert bypass.app is None
        assert hasattr(bypass, "logger")
        assert isinstance(bypass.hooks, list)
        assert isinstance(bypass.patches, list)

    def test_bypass_vm_detection_returns_valid_structure(self, mock_app_with_binary: object) -> None:
        """bypass_vm_detection returns properly structured result dictionary."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)
        result = bypass.bypass_vm_detection()

        assert isinstance(result, dict)
        assert "success" in result
        assert "methods_applied" in result
        assert "errors" in result
        assert isinstance(result["success"], bool)
        assert isinstance(result["methods_applied"], list)
        assert isinstance(result["errors"], list)

    def test_bypass_vm_detection_applies_multiple_methods(self, mock_app_with_binary: object) -> None:
        """bypass_vm_detection attempts multiple bypass strategies."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)
        result = bypass.bypass_vm_detection()

        expected_methods = [
            "API Hooking",
            "Binary Patching",
            "Registry Manipulation",
            "Timing Attack Mitigation",
            "VM Artifact Hiding",
            "System Info Modification",
        ]

        applied_methods = result["methods_applied"]

        if FRIDA_AVAILABLE:
            assert "API Hooking" in applied_methods or "API hooking failed" in str(result["errors"])

        assert "Binary Patching" in applied_methods or "Binary patching failed" in str(result["errors"])

        if result["success"]:
            assert len(applied_methods) > 0

    def test_hook_vm_detection_apis_creates_frida_hooks(self, mock_app_with_binary: object) -> None:
        """_hook_vm_detection_apis creates Frida hook scripts."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)
        initial_hook_count = len(bypass.hooks)

        bypass._hook_vm_detection_apis()

        if FRIDA_AVAILABLE:
            assert len(bypass.hooks) > initial_hook_count
            assert any(hook["type"] == "frida" for hook in bypass.hooks)
            assert any("VM Detection APIs" in hook["target"] for hook in bypass.hooks)

            vm_hook = next(hook for hook in bypass.hooks if "VM Detection APIs" in hook["target"])
            script_content = vm_hook["script"]

            assert "regQueryValueExA" in script_content or "RegQueryValueExA" in script_content
            assert "VirtualBox" in script_content
            assert "VMware" in script_content
            assert "CPUID" in script_content or "cpuid" in script_content.lower()

    def test_hook_vm_detection_apis_without_frida(self, mock_app_with_binary: object, monkeypatch: pytest.MonkeyPatch) -> None:
        """_hook_vm_detection_apis handles missing Frida gracefully."""
        monkeypatch.setattr("intellicrack.core.protection_bypass.vm_bypass.FRIDA_AVAILABLE", False)

        bypass = VirtualizationDetectionBypass(mock_app_with_binary)
        initial_hooks = len(bypass.hooks)

        bypass._hook_vm_detection_apis()

        assert len(bypass.hooks) == initial_hooks

    def test_patch_vm_detection_identifies_patterns(self, mock_app_with_binary: object) -> None:
        """_patch_vm_detection identifies VM detection patterns in binary."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        bypass._patch_vm_detection()

        assert len(bypass.patches) > 0

        patch_patterns = [patch["original"] for patch in bypass.patches]

        assert any(b"\x0f\xa2" in pattern for pattern in patch_patterns)

    def test_patch_vm_detection_records_correct_offsets(self, mock_app_with_binary: object) -> None:
        """_patch_vm_detection records correct byte offsets for patches."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        bypass._patch_vm_detection()

        if len(bypass.patches) > 0:
            for patch in bypass.patches:
                assert "offset" in patch
                assert "original" in patch
                assert "patch" in patch
                assert isinstance(patch["offset"], int)
                assert patch["offset"] >= 0
                assert len(patch["original"]) == len(patch["patch"])

    def test_patch_vm_detection_without_binary(self, mock_app_no_binary: object) -> None:
        """_patch_vm_detection handles missing binary path gracefully."""
        bypass = VirtualizationDetectionBypass(mock_app_no_binary)

        bypass._patch_vm_detection()

        assert len(bypass.patches) == 0

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows registry only")
    @pytest.mark.skipif(not WINREG_AVAILABLE, reason="winreg module required")
    def test_hide_vm_registry_artifacts_on_windows(self, mock_app_with_binary: object) -> None:
        """_hide_vm_registry_artifacts attempts registry manipulation on Windows."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        try:
            bypass._hide_vm_registry_artifacts()
        except Exception as e:
            pytest.fail(f"Registry manipulation raised unexpected exception: {e}")

    @pytest.mark.skipif(platform.system() == "Windows", reason="Non-Windows only")
    def test_hide_vm_registry_artifacts_on_non_windows(self, mock_app_with_binary: object) -> None:
        """_hide_vm_registry_artifacts skips on non-Windows platforms."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        bypass._hide_vm_registry_artifacts()

    def test_hide_vm_artifacts_returns_tuple(self, mock_app_with_binary: object) -> None:
        """_hide_vm_artifacts returns (success, renamed_count) tuple."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        result = bypass._hide_vm_artifacts()

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], int)
        assert result[1] >= 0

    def test_hide_vm_artifacts_creates_frida_hooks(self, mock_app_with_binary: object) -> None:
        """_hide_vm_artifacts creates process hiding hooks."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)
        initial_hook_count = len(bypass.hooks)

        bypass._hide_vm_artifacts()

        if FRIDA_AVAILABLE:
            assert len(bypass.hooks) > initial_hook_count
            assert any("Process Hiding" in hook.get("target", "") for hook in bypass.hooks)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows registry only")
    @pytest.mark.skipif(not WINREG_AVAILABLE, reason="winreg module required")
    def test_modify_system_info_on_windows(self, mock_app_with_binary: object) -> None:
        """_modify_system_info attempts system info modification on Windows."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        result = bypass._modify_system_info()

        assert isinstance(result, bool)

    @pytest.mark.skipif(platform.system() == "Windows", reason="Non-Windows only")
    def test_modify_system_info_on_non_windows(self, mock_app_with_binary: object) -> None:
        """_modify_system_info uses DMI modification on non-Windows."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        result = bypass._modify_system_info()

        assert isinstance(result, bool)

    def test_modify_dmi_info_returns_bool(self, mock_app_with_binary: object) -> None:
        """_modify_dmi_info returns boolean result."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        result = bypass._modify_dmi_info()

        assert isinstance(result, bool)

    def test_hook_timing_functions_creates_hooks(self, mock_app_with_binary: object) -> None:
        """_hook_timing_functions creates timing attack mitigation hooks."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)
        initial_hook_count = len(bypass.hooks)

        bypass._hook_timing_functions()

        if FRIDA_AVAILABLE:
            assert len(bypass.hooks) > initial_hook_count
            assert any("Timing Functions" in hook.get("target", "") for hook in bypass.hooks)

            if timing_hook := next(
                (
                    hook
                    for hook in bypass.hooks
                    if "Timing Functions" in hook.get("target", "")
                ),
                None,
            ):
                script_content = timing_hook["script"]
                assert "GetTickCount" in script_content or "QueryPerformanceCounter" in script_content
                assert "RDTSC" in script_content or "rdtsc" in script_content.lower()

    def test_generate_bypass_script_returns_valid_script(self, mock_app_with_binary: object) -> None:
        """generate_bypass_script produces valid Frida script."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        bypass._hook_vm_detection_apis()
        bypass._hook_timing_functions()

        script = bypass.generate_bypass_script()

        assert isinstance(script, str)
        assert len(script) > 0
        assert "VM Detection Bypass Script" in script or "Intellicrack" in script

    def test_generate_bypass_script_includes_all_hooks(self, mock_app_with_binary: object) -> None:
        """generate_bypass_script includes all installed hooks."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        if FRIDA_AVAILABLE:
            bypass._hook_vm_detection_apis()
            bypass._hook_timing_functions()
            bypass._hide_vm_artifacts()

            script = bypass.generate_bypass_script()

            hook_count = len(bypass.hooks)
            if hook_count > 0:
                for hook in bypass.hooks:
                    assert hook["script"] in script

    def test_get_hook_status_returns_complete_status(self, mock_app_with_binary: object) -> None:
        """get_hook_status returns complete status information."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        bypass._hook_vm_detection_apis()
        bypass._patch_vm_detection()

        status = bypass.get_hook_status()

        assert isinstance(status, dict)
        assert "hooks_installed" in status
        assert "patches_identified" in status
        assert "frida_available" in status
        assert "winreg_available" in status
        assert isinstance(status["hooks_installed"], int)
        assert isinstance(status["patches_identified"], int)
        assert isinstance(status["frida_available"], bool)
        assert isinstance(status["winreg_available"], bool)

    def test_clear_hooks_removes_all_hooks_and_patches(self, mock_app_with_binary: object) -> None:
        """clear_hooks removes all hooks and patches."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        bypass._hook_vm_detection_apis()
        bypass._patch_vm_detection()

        assert len(bypass.hooks) > 0 or len(bypass.patches) > 0

        bypass.clear_hooks()

        assert len(bypass.hooks) == 0
        assert len(bypass.patches) == 0

    def test_get_driver_path_finds_existing_driver(self, mock_app_with_binary: object) -> None:
        """_get_driver_path returns valid path for driver."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        driver_path = bypass._get_driver_path("ntfs.sys")

        assert isinstance(driver_path, str)
        assert "drivers" in driver_path.lower()
        assert "ntfs.sys" in driver_path


class TestVMDetector:
    """Test suite for VMDetector class."""

    def test_initialization(self) -> None:
        """VMDetector initializes correctly."""
        detector = VMDetector()

        assert hasattr(detector, "logger")
        assert hasattr(detector, "vm_indicators")
        assert isinstance(detector.vm_indicators, list)

    def test_detect_returns_valid_structure(self) -> None:
        """detect returns properly structured result dictionary."""
        detector = VMDetector()
        result = detector.detect()

        assert isinstance(result, dict)
        assert "vm_type" in result
        assert "indicators" in result
        assert "is_vm" in result
        assert "confidence" in result
        assert isinstance(result["is_vm"], bool)
        assert isinstance(result["confidence"], float)
        assert 0.0 <= result["confidence"] <= 1.0
        assert isinstance(result["indicators"], list)

    def test_detect_identifies_vm_type_from_indicators(self) -> None:
        """detect correctly identifies VM type from indicators."""
        detector = VMDetector()
        result = detector.detect()

        if result["is_vm"]:
            assert result["vm_type"] is not None
            assert result["vm_type"] in ["VirtualBox", "VMware", "Hyper-V", "QEMU", "Unknown"]
            assert result["confidence"] > 0.0

    def test_detect_confidence_scales_with_indicators(self) -> None:
        """detect confidence score increases with more indicators."""
        detector = VMDetector()
        result = detector.detect()

        indicator_count = len(result["indicators"])
        expected_confidence = min(indicator_count * 0.25, 1.0)

        assert result["confidence"] == expected_confidence

    def test_detect_stores_indicators_in_instance(self) -> None:
        """detect stores found indicators in instance variable."""
        detector = VMDetector()
        result = detector.detect()

        assert detector.vm_indicators == result["indicators"]

    def test_generate_bypass_returns_valid_structure(self) -> None:
        """generate_bypass returns properly structured bypass strategy."""
        detector = VMDetector()
        result = detector.generate_bypass("VMware")

        assert isinstance(result, dict)
        assert "vm_type" in result
        assert "bypass_method" in result
        assert "success_probability" in result
        assert "requirements" in result
        assert "techniques" in result
        assert "registry_modifications" in result
        assert "file_operations" in result
        assert "implementation_script" in result
        assert "stealth_level" in result

        assert isinstance(result["success_probability"], float)
        assert 0.0 <= result["success_probability"] <= 1.0
        assert isinstance(result["techniques"], list)
        assert isinstance(result["registry_modifications"], list)
        assert isinstance(result["file_operations"], list)

    def test_generate_bypass_vmware_specific_techniques(self) -> None:
        """generate_bypass includes VMware-specific techniques."""
        detector = VMDetector()
        result = detector.generate_bypass("VMware")

        techniques_str = " ".join(result["techniques"]).lower()

        assert "vmware" in techniques_str
        assert len(result["techniques"]) > 0
        assert any("vmware" in str(mod).lower() for mod in result["registry_modifications"] + result["file_operations"])

    def test_generate_bypass_virtualbox_specific_techniques(self) -> None:
        """generate_bypass includes VirtualBox-specific techniques."""
        detector = VMDetector()
        result = detector.generate_bypass("VirtualBox")

        techniques_str = " ".join(result["techniques"]).lower()

        assert "virtualbox" in techniques_str or "vbox" in techniques_str
        assert len(result["techniques"]) > 0

    def test_generate_bypass_qemu_specific_techniques(self) -> None:
        """generate_bypass includes QEMU-specific techniques."""
        detector = VMDetector()
        result = detector.generate_bypass("QEMU")

        techniques_str = " ".join(result["techniques"]).lower()

        assert "qemu" in techniques_str
        assert len(result["techniques"]) > 0

    def test_generate_bypass_generic_vm_techniques(self) -> None:
        """generate_bypass includes generic techniques for unknown VM."""
        detector = VMDetector()
        result = detector.generate_bypass("UnknownVM")

        assert len(result["techniques"]) > 0
        assert result["bypass_method"] == "multi-technique"

    def test_generate_bypass_script_content_valid(self) -> None:
        """generate_bypass produces valid Python script."""
        detector = VMDetector()
        result = detector.generate_bypass("VMware")

        script = result["implementation_script"]

        assert isinstance(script, str)
        assert "import" in script
        assert "def apply_vm_bypass" in script
        assert "VMware" in script

    def test_generate_bypass_success_probability_calculation(self) -> None:
        """generate_bypass calculates success probability correctly."""
        detector = VMDetector()

        vmware_result = detector.generate_bypass("VMware")
        generic_result = detector.generate_bypass("UnknownVM")

        assert vmware_result["success_probability"] >= generic_result["success_probability"]

    def test_generate_bypass_handles_error_conditions(self) -> None:
        """generate_bypass handles errors gracefully."""
        detector = VMDetector()

        result = detector.generate_bypass("")

        assert isinstance(result, dict)
        assert "bypass_method" in result

    def test_calculate_success_probability_known_vm(self) -> None:
        """_calculate_success_probability returns higher values for known VMs."""
        detector = VMDetector()

        prob_vmware = detector._calculate_success_probability("VMware", ["technique1", "technique2"])
        prob_unknown = detector._calculate_success_probability("UnknownVM", ["technique1", "technique2"])

        assert prob_vmware > prob_unknown
        assert prob_vmware <= 0.85

    def test_calculate_success_probability_scales_with_techniques(self) -> None:
        """_calculate_success_probability increases with more techniques."""
        detector = VMDetector()

        prob_few = detector._calculate_success_probability("VMware", ["tech1"])
        prob_many = detector._calculate_success_probability("VMware", ["tech1", "tech2", "tech3", "tech4"])

        assert prob_many > prob_few

    def test_get_vm_driver_path_returns_valid_path(self) -> None:
        """_get_vm_driver_path returns valid driver path."""
        detector = VMDetector()

        driver_path = detector._get_vm_driver_path("ntfs.sys")

        assert isinstance(driver_path, str)
        assert "drivers" in driver_path.lower()
        assert "ntfs.sys" in driver_path


class TestVirtualizationAnalyzer:
    """Test suite for VirtualizationAnalyzer class."""

    def test_initialization_with_binary_path(self, sample_binary_with_vm_detection: Path) -> None:
        """VirtualizationAnalyzer initializes with binary path."""
        analyzer = VirtualizationAnalyzer(str(sample_binary_with_vm_detection))

        assert analyzer.binary_path == str(sample_binary_with_vm_detection)
        assert hasattr(analyzer, "logger")

    def test_initialization_without_binary_path(self) -> None:
        """VirtualizationAnalyzer initializes without binary path."""
        analyzer = VirtualizationAnalyzer(None)

        assert analyzer.binary_path is None
        assert hasattr(analyzer, "logger")

    def test_analyze_returns_valid_structure(self, sample_binary_with_vm_detection: Path) -> None:
        """analyze returns properly structured result dictionary."""
        analyzer = VirtualizationAnalyzer(str(sample_binary_with_vm_detection))
        result = analyzer.analyze()

        assert isinstance(result, dict)
        assert "has_vm_detection" in result
        assert "detection_methods" in result
        assert "vm_artifacts" in result
        assert "confidence" in result
        assert isinstance(result["has_vm_detection"], bool)
        assert isinstance(result["detection_methods"], list)
        assert isinstance(result["vm_artifacts"], list)
        assert isinstance(result["confidence"], float)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_analyze_detects_vm_instructions(self, sample_binary_with_vm_detection: Path) -> None:
        """analyze detects VM detection instructions in binary."""
        analyzer = VirtualizationAnalyzer(str(sample_binary_with_vm_detection))
        result = analyzer.analyze()

        assert result["has_vm_detection"] is True
        assert len(result["detection_methods"]) > 0

        methods_str = " ".join(result["detection_methods"]).lower()
        assert any(keyword in methods_str for keyword in ["cpuid", "rdtsc", "str", "port"])

    def test_analyze_detects_vm_strings(self, sample_binary_with_vm_detection: Path) -> None:
        """analyze detects VM-related strings in binary."""
        analyzer = VirtualizationAnalyzer(str(sample_binary_with_vm_detection))
        result = analyzer.analyze()

        artifacts_str = " ".join(result["vm_artifacts"]).lower()
        expected_strings = ["virtualbox", "vmware", "qemu", "vbox"]

        assert any(expected in artifacts_str for expected in expected_strings)

    def test_analyze_clean_binary_no_detection(self, sample_binary_no_vm_detection: Path) -> None:
        """analyze returns negative result for clean binary."""
        analyzer = VirtualizationAnalyzer(str(sample_binary_no_vm_detection))
        result = analyzer.analyze()

        assert result["has_vm_detection"] is False or result["confidence"] < 0.3

    def test_analyze_without_binary_path_returns_empty(self) -> None:
        """analyze returns empty results without binary path."""
        analyzer = VirtualizationAnalyzer(None)
        result = analyzer.analyze()

        assert result["has_vm_detection"] is False
        assert len(result["detection_methods"]) == 0
        assert len(result["vm_artifacts"]) == 0
        assert result["confidence"] == 0.0

    def test_analyze_confidence_calculation(self, sample_binary_with_vm_detection: Path) -> None:
        """analyze calculates confidence correctly based on findings."""
        analyzer = VirtualizationAnalyzer(str(sample_binary_with_vm_detection))
        result = analyzer.analyze()

        total_findings = len(result["vm_artifacts"]) + len(result["detection_methods"])
        expected_confidence = min(total_findings * 0.15, 1.0)

        assert result["confidence"] == expected_confidence

    def test_analyze_handles_missing_file(self, tmp_path: Path) -> None:
        """analyze handles missing binary file gracefully."""
        non_existent = tmp_path / "nonexistent.exe"
        analyzer = VirtualizationAnalyzer(str(non_existent))

        result = analyzer.analyze()

        assert isinstance(result, dict)
        assert result["has_vm_detection"] is False

    def test_analyze_identifies_cpuid_instruction(self, sample_binary_with_vm_detection: Path) -> None:
        """analyze specifically identifies CPUID instruction."""
        analyzer = VirtualizationAnalyzer(str(sample_binary_with_vm_detection))
        result = analyzer.analyze()

        methods = [m.lower() for m in result["detection_methods"]]
        assert any("cpuid" in method for method in methods)

    def test_analyze_identifies_rdtsc_instruction(self, sample_binary_with_vm_detection: Path) -> None:
        """analyze specifically identifies RDTSC instruction."""
        analyzer = VirtualizationAnalyzer(str(sample_binary_with_vm_detection))
        result = analyzer.analyze()

        methods = [m.lower() for m in result["detection_methods"]]
        assert any("rdtsc" in method for method in methods)


class TestModuleFunctions:
    """Test suite for module-level functions."""

    def test_bypass_vm_detection_function(self, mock_app_with_binary: object) -> None:
        """bypass_vm_detection function works correctly."""
        result = bypass_vm_detection(mock_app_with_binary)

        assert isinstance(result, dict)
        assert "success" in result
        assert "methods_applied" in result
        assert "errors" in result

    def test_detect_virtualization_function(self) -> None:
        """detect_virtualization function works correctly."""
        result = detect_virtualization()

        assert isinstance(result, bool)

    def test_analyze_vm_protection_function(self, sample_binary_with_vm_detection: Path) -> None:
        """analyze_vm_protection function works correctly."""
        result = analyze_vm_protection(str(sample_binary_with_vm_detection))

        assert isinstance(result, dict)
        assert "has_vm_detection" in result
        assert "detection_methods" in result
        assert "vm_artifacts" in result
        assert "confidence" in result


class TestVMDetectionPatterns:
    """Test suite for VM detection pattern identification."""

    @pytest.fixture
    def binary_with_cpuid_hypervisor_check(self, tmp_path: Path) -> Path:
        """Create binary with CPUID hypervisor bit check pattern."""
        binary_path = tmp_path / "cpuid_check.exe"

        code = bytearray(1024)
        code[:2] = b"\x4D\x5A"
        code[100:108] = b"\x0f\xa2\xf7\xc1\x00\x00\x00\x80"

        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_rdtsc_timing(self, tmp_path: Path) -> Path:
        """Create binary with RDTSC timing check."""
        binary_path = tmp_path / "rdtsc_check.exe"

        code = bytearray(1024)
        code[:2] = b"\x4D\x5A"
        code[100:102] = b"\x0f\x31"
        code[150:152] = b"\x0f\x31"

        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_port_io(self, tmp_path: Path) -> Path:
        """Create binary with port I/O detection."""
        binary_path = tmp_path / "port_io_check.exe"

        code = bytearray(1024)
        code[:2] = b"\x4D\x5A"
        code[100:102] = b"\xe5\x10"

        binary_path.write_bytes(bytes(code))
        return binary_path

    def test_detect_cpuid_hypervisor_check(self, binary_with_cpuid_hypervisor_check: Path) -> None:
        """Analyzer detects CPUID hypervisor bit check pattern."""
        analyzer = VirtualizationAnalyzer(str(binary_with_cpuid_hypervisor_check))
        result = analyzer.analyze()

        assert result["has_vm_detection"] is True
        methods = [m.lower() for m in result["detection_methods"]]
        assert any("cpuid" in method for method in methods)

    def test_detect_rdtsc_timing_check(self, binary_with_rdtsc_timing: Path) -> None:
        """Analyzer detects RDTSC timing attack pattern."""
        analyzer = VirtualizationAnalyzer(str(binary_with_rdtsc_timing))
        result = analyzer.analyze()

        assert result["has_vm_detection"] is True
        methods = [m.lower() for m in result["detection_methods"]]
        assert any("rdtsc" in method or "timing" in method for method in methods)

    def test_detect_port_io_check(self, binary_with_port_io: Path) -> None:
        """Analyzer detects port I/O VM detection."""
        analyzer = VirtualizationAnalyzer(str(binary_with_port_io))
        result = analyzer.analyze()

        assert result["has_vm_detection"] is True
        methods = [m.lower() for m in result["detection_methods"]]
        assert any("port" in method for method in methods)


class TestBypassEffectiveness:
    """Test suite for bypass effectiveness validation."""

    def test_bypass_identifies_all_detection_methods(self, sample_binary_with_vm_detection: Path, mock_app_with_binary: object) -> None:
        """Bypass identifies same detection methods as analyzer."""
        analyzer = VirtualizationAnalyzer(str(sample_binary_with_vm_detection))
        analysis_result = analyzer.analyze()

        bypass = VirtualizationDetectionBypass(mock_app_with_binary)
        bypass._patch_vm_detection()

        detection_method_count = len(analysis_result["detection_methods"])

        if detection_method_count > 0:
            assert len(bypass.patches) > 0

    def test_bypass_patches_match_detection_patterns(self, sample_binary_with_vm_detection: Path, mock_app_with_binary: object) -> None:
        """Bypass patches correspond to detected VM check patterns."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)
        bypass._patch_vm_detection()

        if len(bypass.patches) > 0:
            patch_bytes = {patch["original"] for patch in bypass.patches}
            expected_patterns = [
                b"\x0f\xa2",
                b"\x0f\x31",
            ]

            found_expected = any(any(pattern in pb for pattern in expected_patterns) for pb in patch_bytes)
            assert found_expected

    def test_multiple_bypass_strategies_increase_coverage(self, mock_app_with_binary: object) -> None:
        """Multiple bypass strategies provide comprehensive coverage."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        result = bypass.bypass_vm_detection()

        if result["success"]:
            strategy_categories = {
                "api_hooks": "API Hooking" in result["methods_applied"],
                "binary_patches": "Binary Patching" in result["methods_applied"],
                "registry": "Registry Manipulation" in result["methods_applied"],
                "timing": "Timing Attack Mitigation" in result["methods_applied"],
                "artifacts": "VM Artifact Hiding" in result["methods_applied"],
                "system_info": "System Info Modification" in result["methods_applied"],
            }

            applied_categories = sum(strategy_categories.values())

            assert applied_categories > 0


class TestEdgeCases:
    """Test suite for edge cases and error conditions."""

    def test_bypass_empty_binary(self, tmp_path: Path) -> None:
        """Bypass handles empty binary file."""
        empty_binary = tmp_path / "empty.exe"
        empty_binary.write_bytes(b"")

        class MockApp:
            def __init__(self, path: Path) -> None:
                self.binary_path = str(path)

        app = MockApp(empty_binary)
        bypass = VirtualizationDetectionBypass(app)

        bypass._patch_vm_detection()

        assert len(bypass.patches) == 0

    def test_bypass_very_large_binary(self, tmp_path: Path) -> None:
        """Bypass handles large binary files efficiently."""
        large_binary = tmp_path / "large.exe"

        large_data = bytearray(10 * 1024 * 1024)
        large_data[:2] = b"\x4D\x5A"
        large_data[5000000:5000002] = b"\x0f\xa2"

        large_binary.write_bytes(bytes(large_data))

        class MockApp:
            def __init__(self, path: Path) -> None:
                self.binary_path = str(path)

        app = MockApp(large_binary)
        bypass = VirtualizationDetectionBypass(app)

        bypass._patch_vm_detection()

        assert isinstance(bypass.patches, list)

    def test_analyzer_corrupted_binary(self, tmp_path: Path) -> None:
        """Analyzer handles corrupted binary gracefully."""
        corrupted = tmp_path / "corrupted.exe"
        corrupted.write_bytes(b"\xFF" * 1000)

        analyzer = VirtualizationAnalyzer(str(corrupted))
        result = analyzer.analyze()

        assert isinstance(result, dict)
        assert "has_vm_detection" in result

    def test_detector_no_vm_indicators(self) -> None:
        """Detector returns negative result when no VM detected."""
        detector = VMDetector()
        result = detector.detect()

        if not result["is_vm"]:
            assert result["vm_type"] is None
            assert result["confidence"] == 0.0
            assert len(result["indicators"]) == 0

    def test_bypass_concurrent_operations(self, mock_app_with_binary: object) -> None:
        """Bypass handles concurrent bypass operations."""
        bypass1 = VirtualizationDetectionBypass(mock_app_with_binary)
        bypass2 = VirtualizationDetectionBypass(mock_app_with_binary)

        result1 = bypass1.bypass_vm_detection()
        result2 = bypass2.bypass_vm_detection()

        assert isinstance(result1, dict)
        assert isinstance(result2, dict)

    def test_clear_hooks_on_empty_bypass(self, mock_app_with_binary: object) -> None:
        """clear_hooks works on bypass with no hooks."""
        bypass = VirtualizationDetectionBypass(mock_app_with_binary)

        bypass.clear_hooks()

        assert len(bypass.hooks) == 0
        assert len(bypass.patches) == 0


class TestRealWorldScenarios:
    """Test suite for real-world VM detection bypass scenarios."""

    @pytest.fixture
    def vmware_protected_binary(self, tmp_path: Path) -> Path:
        """Create binary with VMware-specific detection."""
        binary_path = tmp_path / "vmware_protected.exe"

        code = bytearray(8192)
        code[:2] = b"\x4D\x5A"

        code[100:102] = b"\x0f\xa2"
        code[200:203] = b"\x0f\x00\xc8"

        vm_strings = [b"VMware\x00", b"vmhgfs\x00", b"vmmemctl\x00"]
        offset = 500
        for s in vm_strings:
            code[offset:offset + len(s)] = s
            offset += len(s) + 20

        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def virtualbox_protected_binary(self, tmp_path: Path) -> Path:
        """Create binary with VirtualBox-specific detection."""
        binary_path = tmp_path / "vbox_protected.exe"

        code = bytearray(8192)
        code[:2] = b"\x4D\x5A"

        code[100:102] = b"\x0f\xa2"
        code[200:202] = b"\x0f\x31"

        vm_strings = [b"VirtualBox\x00", b"VBOX\x00", b"vboxguest\x00", b"vboxvideo\x00"]
        offset = 500
        for s in vm_strings:
            code[offset:offset + len(s)] = s
            offset += len(s) + 20

        binary_path.write_bytes(bytes(code))
        return binary_path

    def test_vmware_detection_bypass_workflow(self, vmware_protected_binary: Path) -> None:
        """Complete workflow for bypassing VMware detection."""
        analyzer = VirtualizationAnalyzer(str(vmware_protected_binary))
        analysis = analyzer.analyze()

        assert analysis["has_vm_detection"] is True

        artifacts_str = " ".join(analysis["vm_artifacts"]).lower()
        assert "vmware" in artifacts_str

        class MockApp:
            def __init__(self, path: Path) -> None:
                self.binary_path = str(path)

        app = MockApp(vmware_protected_binary)
        result = bypass_vm_detection(app)

        assert isinstance(result, dict)
        assert "methods_applied" in result

    def test_virtualbox_detection_bypass_workflow(self, virtualbox_protected_binary: Path) -> None:
        """Complete workflow for bypassing VirtualBox detection."""
        analyzer = VirtualizationAnalyzer(str(virtualbox_protected_binary))
        analysis = analyzer.analyze()

        assert analysis["has_vm_detection"] is True

        artifacts_str = " ".join(analysis["vm_artifacts"]).lower()
        assert "virtualbox" in artifacts_str or "vbox" in artifacts_str

        class MockApp:
            def __init__(self, path: Path) -> None:
                self.binary_path = str(path)

        app = MockApp(virtualbox_protected_binary)
        result = bypass_vm_detection(app)

        assert isinstance(result, dict)
        assert "methods_applied" in result

    def test_multi_layer_vm_detection_bypass(self, tmp_path: Path) -> None:
        """Bypass handles multiple layers of VM detection."""
        binary_path = tmp_path / "multilayer.exe"

        code = bytearray(16384)
        code[:2] = b"\x4D\x5A"

        code[100:102] = b"\x0f\xa2"
        code[200:202] = b"\x0f\x31"
        code[300:303] = b"\x0f\x00\xc8"
        code[400:402] = b"\xe5\x10"

        code[500:508] = b"\x0f\xa2\xf7\xc1\x00\x00\x00\x80"

        vm_strings = [
            b"VirtualBox\x00", b"VMware\x00", b"QEMU\x00",
            b"vboxguest\x00", b"vmhgfs\x00"
        ]
        offset = 1000
        for s in vm_strings:
            code[offset:offset + len(s)] = s
            offset += len(s) + 20

        binary_path.write_bytes(bytes(code))

        analyzer = VirtualizationAnalyzer(str(binary_path))
        analysis = analyzer.analyze()

        assert analysis["has_vm_detection"] is True
        assert len(analysis["detection_methods"]) >= 3

        class MockApp:
            def __init__(self, path: Path) -> None:
                self.binary_path = str(path)

        app = MockApp(binary_path)
        bypass = VirtualizationDetectionBypass(app)
        result = bypass.bypass_vm_detection()

        assert len(result["methods_applied"]) >= 2
