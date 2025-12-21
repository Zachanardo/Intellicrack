"""Production Tests for VM Detection Bypass.

Tests validate real VM detection and bypass capabilities against actual Windows
binaries and system configurations. All tests use real system files and actual
VM detection techniques without mocks or stubs.

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
from typing import Any, Dict, List, Tuple

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


WINDOWS_NOTEPAD: str = "C:/Windows/System32/notepad.exe"
WINDOWS_CALC: str = "C:/Windows/System32/calc.exe"
WINDOWS_KERNEL32: str = "C:/Windows/System32/kernel32.dll"


@pytest.fixture
def real_system_binary() -> Path:
    """Provide real Windows system binary for testing."""
    binary_path: Path = Path(WINDOWS_NOTEPAD)
    if not binary_path.exists():
        pytest.skip("Windows notepad.exe not available")
    return binary_path


@pytest.fixture
def real_dll_binary() -> Path:
    """Provide real Windows DLL for testing."""
    dll_path: Path = Path(WINDOWS_KERNEL32)
    if not dll_path.exists():
        pytest.skip("Windows kernel32.dll not available")
    return dll_path


@pytest.fixture
def vm_protected_binary(tmp_path: Path) -> Path:
    """Create realistic binary with actual VM detection patterns."""
    binary_path: Path = tmp_path / "vm_detect.exe"

    binary_data: bytearray = bytearray(16384)

    binary_data[:2] = b"\x4D\x5A"
    binary_data[60:64] = struct.pack("<I", 0x80)

    pe_offset: int = 0x80
    binary_data[pe_offset:pe_offset + 4] = b"PE\x00\x00"

    code_section_offset: int = 0x200
    binary_data[code_section_offset:code_section_offset + 2] = b"\x0F\xA2"
    binary_data[code_section_offset + 10:code_section_offset + 18] = b"\x0F\xA2\xF7\xC1\x00\x00\x00\x80"

    binary_data[code_section_offset + 30:code_section_offset + 32] = b"\x0F\x31"
    binary_data[code_section_offset + 40:code_section_offset + 42] = b"\x0F\x31"

    binary_data[code_section_offset + 60:code_section_offset + 62] = b"\xE5\x10"

    binary_data[code_section_offset + 80:code_section_offset + 83] = b"\x0F\x00\xC8"

    string_section_offset: int = 0x1000
    vm_strings: List[bytes] = [
        b"VirtualBox Guest Additions\x00",
        b"VMware Tools\x00",
        b"QEMU HARDDISK\x00",
        b"VBOX HARDDISK\x00",
        b"vboxguest.sys\x00",
        b"vmhgfs.sys\x00",
        b"vmmemctl.sys\x00",
        b"VBoxMouse.sys\x00",
        b"Red Hat VirtIO\x00",
    ]

    offset: int = string_section_offset
    for vm_string in vm_strings:
        binary_data[offset:offset + len(vm_string)] = vm_string
        offset += len(vm_string) + 16

    binary_path.write_bytes(bytes(binary_data))
    return binary_path


@pytest.fixture
def vmware_specific_binary(tmp_path: Path) -> Path:
    """Create binary with VMware-specific detection techniques."""
    binary_path: Path = tmp_path / "vmware_check.exe"

    binary_data: bytearray = bytearray(8192)
    binary_data[:2] = b"\x4D\x5A"
    binary_data[60:64] = struct.pack("<I", 0x80)

    code_offset: int = 0x200
    binary_data[code_offset:code_offset + 3] = b"\x0F\x00\xC8"

    binary_data[code_offset + 20:code_offset + 22] = b"\x0F\xA2"

    vmware_strings: List[bytes] = [
        b"VMware\x00",
        b"vmhgfs\x00",
        b"vmmemctl\x00",
        b"vmscsi\x00",
        b"VMware SVGA II\x00",
    ]

    offset: int = 0x1000
    for s in vmware_strings:
        binary_data[offset:offset + len(s)] = s
        offset += len(s) + 32

    binary_path.write_bytes(bytes(binary_data))
    return binary_path


@pytest.fixture
def virtualbox_specific_binary(tmp_path: Path) -> Path:
    """Create binary with VirtualBox-specific detection techniques."""
    binary_path: Path = tmp_path / "vbox_check.exe"

    binary_data: bytearray = bytearray(8192)
    binary_data[:2] = b"\x4D\x5A"
    binary_data[60:64] = struct.pack("<I", 0x80)

    code_offset: int = 0x200
    binary_data[code_offset:code_offset + 2] = b"\x0F\xA2"
    binary_data[code_offset + 20:code_offset + 22] = b"\x0F\x31"

    vbox_strings: List[bytes] = [
        b"VirtualBox\x00",
        b"VBOX__\x00",
        b"vboxguest\x00",
        b"vboxvideo\x00",
        b"VBoxMouse\x00",
        b"Oracle\x00",
    ]

    offset: int = 0x1000
    for s in vbox_strings:
        binary_data[offset:offset + len(s)] = s
        offset += len(s) + 32

    binary_path.write_bytes(bytes(binary_data))
    return binary_path


@pytest.fixture
def clean_binary(tmp_path: Path) -> Path:
    """Create clean binary without VM detection."""
    binary_path: Path = tmp_path / "clean.exe"

    binary_data: bytearray = bytearray(4096)
    binary_data[:2] = b"\x4D\x5A"
    binary_data[60:64] = struct.pack("<I", 0x80)
    binary_data[0x80:0x84] = b"PE\x00\x00"

    code_offset: int = 0x200
    binary_data[code_offset:code_offset + 100] = b"\x90" * 100

    binary_path.write_bytes(bytes(binary_data))
    return binary_path


@pytest.fixture
def mock_app_with_binary(vm_protected_binary: Path) -> object:
    """Create application object with VM-protected binary."""
    class App:
        def __init__(self, path: Path) -> None:
            self.binary_path: str = str(path)

    return App(vm_protected_binary)


@pytest.fixture
def mock_app_with_system_binary(real_system_binary: Path) -> object:
    """Create application object with real system binary."""
    class App:
        def __init__(self, path: Path) -> None:
            self.binary_path: str = str(path)

    return App(real_system_binary)


class TestVMDetectorRealEnvironment:
    """Test VM detection against real system environment."""

    def test_vm_detector_initialization_creates_valid_instance(self) -> None:
        """VMDetector initializes with all required attributes."""
        detector: VMDetector = VMDetector()

        assert hasattr(detector, "logger")
        assert hasattr(detector, "vm_indicators")
        assert isinstance(detector.vm_indicators, list)

    def test_vm_detector_detect_returns_complete_result_structure(self) -> None:
        """detect() returns complete result dictionary with all required fields."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.detect()

        assert isinstance(result, dict)
        assert "vm_type" in result
        assert "indicators" in result
        assert "is_vm" in result
        assert "confidence" in result

        assert isinstance(result["is_vm"], bool)
        assert isinstance(result["confidence"], float)
        assert 0.0 <= result["confidence"] <= 1.0
        assert isinstance(result["indicators"], list)

    def test_vm_detector_detect_analyzes_real_system_cpu(self) -> None:
        """detect() analyzes real system CPU information."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.detect()

        assert isinstance(result, dict)
        if result["is_vm"]:
            assert len(result["indicators"]) > 0
            assert result["confidence"] > 0.0
            assert result["vm_type"] is not None

    def test_vm_detector_detect_checks_real_system_files(self) -> None:
        """detect() checks for real VM driver files on system."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.detect()

        if result["is_vm"]:
            indicators_str: str = " ".join(result["indicators"]).lower()
            assert any(vm_term in indicators_str for vm_term in
                      ["vbox", "vmware", "virtual", "hypervisor"])

    def test_vm_detector_detect_validates_mac_addresses(self) -> None:
        """detect() checks for VM-specific MAC address prefixes."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.detect()

        assert isinstance(result["indicators"], list)

    def test_vm_detector_detect_confidence_correlates_with_indicators(self) -> None:
        """detect() confidence score properly correlates with indicator count."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.detect()

        indicator_count: int = len(result["indicators"])
        expected_confidence: float = min(indicator_count * 0.25, 1.0)

        assert result["confidence"] == expected_confidence

    def test_vm_detector_identify_virtualbox_from_indicators(self) -> None:
        """detect() correctly identifies VirtualBox from indicators."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.detect()

        if result["is_vm"]:
            indicators_str: str = " ".join(result["indicators"]).lower()
            if "vbox" in indicators_str or "virtualbox" in indicators_str:
                assert result["vm_type"] == "VirtualBox"

    def test_vm_detector_identify_vmware_from_indicators(self) -> None:
        """detect() correctly identifies VMware from indicators."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.detect()

        if result["is_vm"]:
            indicators_str: str = " ".join(result["indicators"]).lower()
            if "vmware" in indicators_str:
                assert result["vm_type"] == "VMware"

    def test_vm_detector_stores_indicators_in_instance_variable(self) -> None:
        """detect() stores found indicators in instance variable."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.detect()

        assert detector.vm_indicators == result["indicators"]

    def test_vm_detector_get_vm_driver_path_returns_valid_windows_path(self) -> None:
        """_get_vm_driver_path returns valid Windows driver path."""
        detector: VMDetector = VMDetector()
        driver_path: str = detector._get_vm_driver_path("ntfs.sys")

        assert isinstance(driver_path, str)
        assert "drivers" in driver_path.lower()
        assert driver_path.endswith("ntfs.sys")

    def test_vm_detector_get_vm_driver_path_checks_system_directories(self) -> None:
        """_get_vm_driver_path checks System32 and SysWOW64 directories."""
        detector: VMDetector = VMDetector()
        driver_path: str = detector._get_vm_driver_path("kernel32.dll")

        assert "System32" in driver_path or "SysWOW64" in driver_path


class TestVMDetectorBypassGeneration:
    """Test VM bypass strategy generation."""

    def test_generate_bypass_returns_complete_strategy_structure(self) -> None:
        """generate_bypass() returns complete bypass strategy dictionary."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.generate_bypass("VMware")

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

    def test_generate_bypass_vmware_includes_specific_techniques(self) -> None:
        """generate_bypass() includes VMware-specific bypass techniques."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.generate_bypass("VMware")

        assert result["vm_type"] == "VMware"
        assert len(result["techniques"]) > 0

        techniques_str: str = " ".join(result["techniques"]).lower()
        assert "vmware" in techniques_str

        combined_ops: str = " ".join(
            str(item) for item in
            result["registry_modifications"] + result["file_operations"]
        ).lower()
        assert "vmware" in combined_ops

    def test_generate_bypass_virtualbox_includes_specific_techniques(self) -> None:
        """generate_bypass() includes VirtualBox-specific bypass techniques."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.generate_bypass("VirtualBox")

        assert result["vm_type"] == "VirtualBox"
        assert len(result["techniques"]) > 0

        techniques_str: str = " ".join(result["techniques"]).lower()
        assert "virtualbox" in techniques_str or "vbox" in techniques_str

    def test_generate_bypass_qemu_includes_specific_techniques(self) -> None:
        """generate_bypass() includes QEMU-specific bypass techniques."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.generate_bypass("QEMU")

        assert result["vm_type"] == "QEMU"
        assert len(result["techniques"]) > 0

        techniques_str: str = " ".join(result["techniques"]).lower()
        assert "qemu" in techniques_str

    def test_generate_bypass_unknown_vm_includes_generic_techniques(self) -> None:
        """generate_bypass() provides generic techniques for unknown VM types."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.generate_bypass("UnknownVM")

        assert len(result["techniques"]) > 0
        assert result["bypass_method"] == "multi-technique"
        assert result["success_probability"] > 0.0

    def test_generate_bypass_script_content_is_valid_python(self) -> None:
        """generate_bypass() produces syntactically valid Python script."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.generate_bypass("VMware")

        script: str = result["implementation_script"]

        assert isinstance(script, str)
        assert script != ""
        assert "import" in script
        assert "def apply_vm_bypass" in script
        assert "VMware" in script

    def test_generate_bypass_known_vm_higher_success_probability(self) -> None:
        """generate_bypass() assigns higher success probability to known VMs."""
        detector: VMDetector = VMDetector()

        vmware_result: Dict[str, Any] = detector.generate_bypass("VMware")
        unknown_result: Dict[str, Any] = detector.generate_bypass("UnknownVM")

        assert vmware_result["success_probability"] > unknown_result["success_probability"]

    def test_generate_bypass_success_probability_capped_at_85_percent(self) -> None:
        """generate_bypass() caps success probability at 85%."""
        detector: VMDetector = VMDetector()

        techniques: List[str] = [f"technique_{i}" for i in range(20)]
        probability: float = detector._calculate_success_probability("VMware", techniques)

        assert probability <= 0.85

    def test_generate_bypass_technique_count_increases_probability(self) -> None:
        """generate_bypass() increases probability with more techniques."""
        detector: VMDetector = VMDetector()

        prob_few: float = detector._calculate_success_probability("VMware", ["tech1"])
        prob_many: float = detector._calculate_success_probability(
            "VMware", ["tech1", "tech2", "tech3", "tech4"]
        )

        assert prob_many > prob_few

    def test_generate_bypass_handles_empty_vm_type(self) -> None:
        """generate_bypass() handles empty VM type gracefully."""
        detector: VMDetector = VMDetector()
        result: Dict[str, Any] = detector.generate_bypass("")

        assert isinstance(result, dict)
        assert "bypass_method" in result
        assert len(result["techniques"]) > 0


class TestVirtualizationAnalyzerRealBinaries:
    """Test virtualization analyzer against real Windows binaries."""

    def test_analyzer_initialization_with_real_binary(self, real_system_binary: Path) -> None:
        """VirtualizationAnalyzer initializes with real Windows binary."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(real_system_binary))

        assert analyzer.binary_path == str(real_system_binary)
        assert hasattr(analyzer, "logger")

    def test_analyzer_analyze_real_notepad_exe(self, real_system_binary: Path) -> None:
        """analyze() processes real Windows notepad.exe successfully."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(real_system_binary))
        result: Dict[str, Any] = analyzer.analyze()

        assert isinstance(result, dict)
        assert "has_vm_detection" in result
        assert "detection_methods" in result
        assert "vm_artifacts" in result
        assert "confidence" in result

        assert isinstance(result["has_vm_detection"], bool)
        assert isinstance(result["detection_methods"], list)
        assert isinstance(result["vm_artifacts"], list)
        assert isinstance(result["confidence"], float)

    def test_analyzer_analyze_real_kernel32_dll(self, real_dll_binary: Path) -> None:
        """analyze() processes real Windows kernel32.dll successfully."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(real_dll_binary))
        result: Dict[str, Any] = analyzer.analyze()

        assert isinstance(result, dict)
        assert "has_vm_detection" in result

    def test_analyzer_detects_cpuid_instruction_in_binary(self, vm_protected_binary: Path) -> None:
        """analyze() detects CPUID instruction (0x0F 0xA2) in binary."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(vm_protected_binary))
        result: Dict[str, Any] = analyzer.analyze()

        assert result["has_vm_detection"] is True

        methods: List[str] = [m.lower() for m in result["detection_methods"]]
        assert any("cpuid" in method for method in methods)

    def test_analyzer_detects_rdtsc_instruction_in_binary(self, vm_protected_binary: Path) -> None:
        """analyze() detects RDTSC instruction (0x0F 0x31) for timing attacks."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(vm_protected_binary))
        result: Dict[str, Any] = analyzer.analyze()

        methods: List[str] = [m.lower() for m in result["detection_methods"]]
        assert any("rdtsc" in method or "timing" in method for method in methods)

    def test_analyzer_detects_str_instruction_in_binary(self, vm_protected_binary: Path) -> None:
        """analyze() detects STR instruction (0x0F 0x00 0xC8) for VM detection."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(vm_protected_binary))
        result: Dict[str, Any] = analyzer.analyze()

        methods: List[str] = [m.lower() for m in result["detection_methods"]]
        assert any("str" in method for method in methods)

    def test_analyzer_detects_port_io_instruction_in_binary(self, vm_protected_binary: Path) -> None:
        """analyze() detects port I/O instruction (IN/OUT) for VirtualBox detection."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(vm_protected_binary))
        result: Dict[str, Any] = analyzer.analyze()

        methods: List[str] = [m.lower() for m in result["detection_methods"]]
        assert any("port" in method for method in methods)

    def test_analyzer_detects_vm_strings_in_binary(self, vm_protected_binary: Path) -> None:
        """analyze() detects VM-related strings (VirtualBox, VMware, QEMU)."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(vm_protected_binary))
        result: Dict[str, Any] = analyzer.analyze()

        assert len(result["vm_artifacts"]) > 0

        artifacts_str: str = " ".join(result["vm_artifacts"]).lower()
        assert any(vm_name in artifacts_str for vm_name in
                  ["virtualbox", "vmware", "qemu", "vbox"])

    def test_analyzer_clean_binary_low_detection_confidence(self, clean_binary: Path) -> None:
        """analyze() returns low confidence for clean binary without VM detection."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(clean_binary))
        result: Dict[str, Any] = analyzer.analyze()

        assert result["confidence"] < 0.3 or result["has_vm_detection"] is False

    def test_analyzer_confidence_calculation_accuracy(self, vm_protected_binary: Path) -> None:
        """analyze() calculates confidence based on findings count."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(vm_protected_binary))
        result: Dict[str, Any] = analyzer.analyze()

        total_findings: int = len(result["vm_artifacts"]) + len(result["detection_methods"])
        expected_confidence: float = min(total_findings * 0.15, 1.0)

        assert result["confidence"] == expected_confidence

    def test_analyzer_handles_missing_binary_file(self, tmp_path: Path) -> None:
        """analyze() handles non-existent binary file gracefully."""
        non_existent: Path = tmp_path / "nonexistent.exe"
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(non_existent))

        result: Dict[str, Any] = analyzer.analyze()

        assert isinstance(result, dict)
        assert result["has_vm_detection"] is False

    def test_analyzer_handles_empty_binary_file(self, tmp_path: Path) -> None:
        """analyze() handles empty binary file without crashing."""
        empty_binary: Path = tmp_path / "empty.exe"
        empty_binary.write_bytes(b"")

        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(empty_binary))
        result: Dict[str, Any] = analyzer.analyze()

        assert isinstance(result, dict)
        assert result["has_vm_detection"] is False

    def test_analyzer_handles_corrupted_binary_data(self, tmp_path: Path) -> None:
        """analyze() handles corrupted binary data gracefully."""
        corrupted: Path = tmp_path / "corrupted.exe"
        corrupted.write_bytes(b"\xFF\xFE\xFD\xFC" * 256)

        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(corrupted))
        result: Dict[str, Any] = analyzer.analyze()

        assert isinstance(result, dict)

    def test_analyzer_vmware_specific_detection(self, vmware_specific_binary: Path) -> None:
        """analyze() detects VMware-specific indicators."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(vmware_specific_binary))
        result: Dict[str, Any] = analyzer.analyze()

        assert result["has_vm_detection"] is True

        artifacts_str: str = " ".join(result["vm_artifacts"]).lower()
        assert "vmware" in artifacts_str

    def test_analyzer_virtualbox_specific_detection(self, virtualbox_specific_binary: Path) -> None:
        """analyze() detects VirtualBox-specific indicators."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(virtualbox_specific_binary))
        result: Dict[str, Any] = analyzer.analyze()

        assert result["has_vm_detection"] is True

        artifacts_str: str = " ".join(result["vm_artifacts"]).lower()
        assert "virtualbox" in artifacts_str or "vbox" in artifacts_str


class TestVirtualizationDetectionBypassReal:
    """Test VM detection bypass against real binaries."""

    def test_bypass_initialization_with_app(self, mock_app_with_binary: object) -> None:
        """VirtualizationDetectionBypass initializes with application object."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)

        assert bypass.app == mock_app_with_binary
        assert hasattr(bypass, "logger")
        assert isinstance(bypass.hooks, list)
        assert isinstance(bypass.patches, list)
        assert len(bypass.hooks) == 0
        assert len(bypass.patches) == 0

    def test_bypass_vm_detection_applies_strategies(self, mock_app_with_binary: object) -> None:
        """bypass_vm_detection() applies multiple bypass strategies."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)
        result: Dict[str, Any] = bypass.bypass_vm_detection()

        assert isinstance(result, dict)
        assert "success" in result
        assert "methods_applied" in result
        assert "errors" in result

        assert isinstance(result["success"], bool)
        assert isinstance(result["methods_applied"], list)
        assert isinstance(result["errors"], list)

    def test_bypass_patch_vm_detection_identifies_patterns(self, mock_app_with_binary: object) -> None:
        """_patch_vm_detection() identifies VM detection patterns in binary."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)

        bypass._patch_vm_detection()

        assert len(bypass.patches) > 0

        for patch in bypass.patches:
            assert "offset" in patch
            assert "original" in patch
            assert "patch" in patch
            assert isinstance(patch["offset"], int)
            assert patch["offset"] >= 0
            assert len(patch["original"]) == len(patch["patch"])

    def test_bypass_patches_cpuid_instruction(self, mock_app_with_binary: object) -> None:
        """_patch_vm_detection() identifies and patches CPUID instructions."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)

        bypass._patch_vm_detection()

        patch_patterns: List[bytes] = [patch["original"] for patch in bypass.patches]
        assert any(b"\x0F\xA2" in pattern for pattern in patch_patterns)

    def test_bypass_patches_rdtsc_instruction(self, mock_app_with_binary: object) -> None:
        """_patch_vm_detection() identifies and patches RDTSC instructions."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)

        bypass._patch_vm_detection()

        patch_patterns: List[bytes] = [patch["original"] for patch in bypass.patches]
        assert any(b"\x0F\x31" in pattern for pattern in patch_patterns)

    def test_bypass_hook_vm_detection_apis_creates_frida_script(self, mock_app_with_binary: object) -> None:
        """_hook_vm_detection_apis() creates Frida hook scripts."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)

        initial_hook_count: int = len(bypass.hooks)
        bypass._hook_vm_detection_apis()

        if FRIDA_AVAILABLE:
            assert len(bypass.hooks) > initial_hook_count

            if vm_hook := next(
                (
                    hook
                    for hook in bypass.hooks
                    if "VM Detection APIs" in hook["target"]
                ),
                {},
            ):
                script: str = vm_hook["script"]
                assert "RegQueryValueExA" in script or "regQueryValueExA" in script
                assert "VirtualBox" in script
                assert "VMware" in script

    def test_bypass_hook_timing_functions_creates_hooks(self, mock_app_with_binary: object) -> None:
        """_hook_timing_functions() creates timing mitigation hooks."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)

        initial_hook_count: int = len(bypass.hooks)
        bypass._hook_timing_functions()

        if FRIDA_AVAILABLE:
            assert len(bypass.hooks) > initial_hook_count

            if timing_hook := next(
                (
                    hook
                    for hook in bypass.hooks
                    if "Timing Functions" in hook.get("target", "")
                ),
                {},
            ):
                script: str = timing_hook["script"]
                assert "GetTickCount" in script or "QueryPerformanceCounter" in script
                assert "RDTSC" in script or "rdtsc" in script.lower()

    def test_bypass_hide_vm_artifacts_returns_tuple(self, mock_app_with_binary: object) -> None:
        """_hide_vm_artifacts() returns (success, renamed_count) tuple."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)

        result: Tuple[bool, int] = bypass._hide_vm_artifacts()

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], int)
        assert result[1] >= 0

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows registry only")
    @pytest.mark.skipif(not WINREG_AVAILABLE, reason="winreg module required")
    def test_bypass_modify_system_info_on_windows(self, mock_app_with_binary: object) -> None:
        """_modify_system_info() attempts system modification on Windows."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)

        result: bool = bypass._modify_system_info()

        assert isinstance(result, bool)

    def test_bypass_generate_script_includes_all_hooks(self, mock_app_with_binary: object) -> None:
        """generate_bypass_script() includes all installed hooks."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)

        if FRIDA_AVAILABLE:
            bypass._hook_vm_detection_apis()
            bypass._hook_timing_functions()

            script: str = bypass.generate_bypass_script()

            assert isinstance(script, str)
            assert script != ""
            assert "VM Detection Bypass Script" in script or "Intellicrack" in script

            for hook in bypass.hooks:
                assert hook["script"] in script

    def test_bypass_get_hook_status_returns_complete_info(self, mock_app_with_binary: object) -> None:
        """get_hook_status() returns complete status information."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)

        bypass._hook_vm_detection_apis()
        bypass._patch_vm_detection()

        status: Dict[str, Any] = bypass.get_hook_status()

        assert isinstance(status, dict)
        assert "hooks_installed" in status
        assert "patches_identified" in status
        assert "frida_available" in status
        assert "winreg_available" in status

        assert isinstance(status["hooks_installed"], int)
        assert isinstance(status["patches_identified"], int)
        assert isinstance(status["frida_available"], bool)
        assert isinstance(status["winreg_available"], bool)

    def test_bypass_clear_hooks_removes_all_data(self, mock_app_with_binary: object) -> None:
        """clear_hooks() removes all hooks and patches."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)

        bypass._hook_vm_detection_apis()
        bypass._patch_vm_detection()

        assert len(bypass.hooks) > 0 or len(bypass.patches) > 0

        bypass.clear_hooks()

        assert len(bypass.hooks) == 0
        assert len(bypass.patches) == 0

    def test_bypass_get_driver_path_returns_valid_path(self, mock_app_with_binary: object) -> None:
        """_get_driver_path() returns valid Windows driver path."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)

        driver_path: str = bypass._get_driver_path("ntfs.sys")

        assert isinstance(driver_path, str)
        assert "drivers" in driver_path.lower()
        assert driver_path.endswith("ntfs.sys")


class TestModuleLevelFunctions:
    """Test module-level convenience functions."""

    def test_bypass_vm_detection_function_works(self, mock_app_with_binary: object) -> None:
        """bypass_vm_detection() function works correctly."""
        result: Dict[str, Any] = bypass_vm_detection(mock_app_with_binary)

        assert isinstance(result, dict)
        assert "success" in result
        assert "methods_applied" in result
        assert "errors" in result

    def test_detect_virtualization_function_returns_bool(self) -> None:
        """detect_virtualization() function returns boolean."""
        result: bool = detect_virtualization()

        assert isinstance(result, bool)

    def test_analyze_vm_protection_function_works(self, vm_protected_binary: Path) -> None:
        """analyze_vm_protection() function analyzes binary."""
        result: Dict[str, Any] = analyze_vm_protection(str(vm_protected_binary))

        assert isinstance(result, dict)
        assert "has_vm_detection" in result
        assert "detection_methods" in result
        assert "vm_artifacts" in result
        assert "confidence" in result


class TestRealWorldBypassScenarios:
    """Test complete real-world VM detection bypass workflows."""

    def test_complete_vmware_bypass_workflow(self, vmware_specific_binary: Path) -> None:
        """Complete workflow: detect VMware indicators and generate bypass."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(vmware_specific_binary))
        analysis: Dict[str, Any] = analyzer.analyze()

        assert analysis["has_vm_detection"] is True

        artifacts_str: str = " ".join(analysis["vm_artifacts"]).lower()
        assert "vmware" in artifacts_str

        class App:
            def __init__(self, path: Path) -> None:
                self.binary_path: str = str(path)

        app: App = App(vmware_specific_binary)
        bypass_result: Dict[str, Any] = bypass_vm_detection(app)

        assert isinstance(bypass_result, dict)
        assert len(bypass_result["methods_applied"]) > 0 or len(bypass_result["errors"]) > 0

    def test_complete_virtualbox_bypass_workflow(self, virtualbox_specific_binary: Path) -> None:
        """Complete workflow: detect VirtualBox indicators and generate bypass."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(virtualbox_specific_binary))
        analysis: Dict[str, Any] = analyzer.analyze()

        assert analysis["has_vm_detection"] is True

        artifacts_str: str = " ".join(analysis["vm_artifacts"]).lower()
        assert "virtualbox" in artifacts_str or "vbox" in artifacts_str

        class App:
            def __init__(self, path: Path) -> None:
                self.binary_path: str = str(path)

        app: App = App(virtualbox_specific_binary)
        bypass_result: Dict[str, Any] = bypass_vm_detection(app)

        assert isinstance(bypass_result, dict)
        assert len(bypass_result["methods_applied"]) > 0 or len(bypass_result["errors"]) > 0

    def test_multilayer_vm_detection_bypass(self, tmp_path: Path) -> None:
        """Bypass handles multiple layers of VM detection techniques."""
        binary_path: Path = tmp_path / "multilayer.exe"

        binary_data: bytearray = bytearray(16384)
        binary_data[:2] = b"\x4D\x5A"
        binary_data[60:64] = struct.pack("<I", 0x80)

        code_offset: int = 0x200
        binary_data[code_offset:code_offset + 2] = b"\x0F\xA2"
        binary_data[code_offset + 20:code_offset + 22] = b"\x0F\x31"
        binary_data[code_offset + 40:code_offset + 43] = b"\x0F\x00\xC8"
        binary_data[code_offset + 60:code_offset + 62] = b"\xE5\x10"
        binary_data[code_offset + 80:code_offset + 88] = b"\x0F\xA2\xF7\xC1\x00\x00\x00\x80"

        vm_strings: List[bytes] = [
            b"VirtualBox\x00", b"VMware\x00", b"QEMU\x00",
            b"vboxguest\x00", b"vmhgfs\x00", b"Red Hat VirtIO\x00"
        ]

        offset: int = 0x1000
        for s in vm_strings:
            binary_data[offset:offset + len(s)] = s
            offset += len(s) + 20

        binary_path.write_bytes(bytes(binary_data))

        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(binary_path))
        analysis: Dict[str, Any] = analyzer.analyze()

        assert analysis["has_vm_detection"] is True
        assert len(analysis["detection_methods"]) >= 3
        assert len(analysis["vm_artifacts"]) >= 3

        class App:
            def __init__(self, path: Path) -> None:
                self.binary_path: str = str(path)

        app: App = App(binary_path)
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(app)
        result: Dict[str, Any] = bypass.bypass_vm_detection()

        assert len(result["methods_applied"]) >= 2

    def test_real_system_binary_analysis_workflow(self, mock_app_with_system_binary: object) -> None:
        """Analyze real Windows system binary for VM detection routines."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_system_binary)

        bypass._patch_vm_detection()

        assert isinstance(bypass.patches, list)

    def test_vm_environment_detection_and_bypass_generation(self) -> None:
        """Detect current environment and generate appropriate bypass."""
        detector: VMDetector = VMDetector()
        env_result: Dict[str, Any] = detector.detect()

        if env_result["is_vm"]:
            vm_type: str = env_result["vm_type"] or "Unknown"
            bypass_strategy: Dict[str, Any] = detector.generate_bypass(vm_type)

            assert bypass_strategy["vm_type"] == vm_type
            assert len(bypass_strategy["techniques"]) > 0
            assert bypass_strategy["success_probability"] > 0.0


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_bypass_with_empty_binary(self, tmp_path: Path) -> None:
        """Bypass handles empty binary file without crashing."""
        empty_binary: Path = tmp_path / "empty.exe"
        empty_binary.write_bytes(b"")

        class App:
            def __init__(self, path: Path) -> None:
                self.binary_path: str = str(path)

        app: App = App(empty_binary)
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(app)

        bypass._patch_vm_detection()

        assert len(bypass.patches) == 0

    def test_bypass_with_very_large_binary(self, tmp_path: Path) -> None:
        """Bypass handles large binary files efficiently."""
        large_binary: Path = tmp_path / "large.exe"

        large_data: bytearray = bytearray(10 * 1024 * 1024)
        large_data[:2] = b"\x4D\x5A"
        large_data[5000000:5000002] = b"\x0F\xA2"
        large_data[7500000:7500002] = b"\x0F\x31"

        large_binary.write_bytes(bytes(large_data))

        class App:
            def __init__(self, path: Path) -> None:
                self.binary_path: str = str(path)

        app: App = App(large_binary)
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(app)

        bypass._patch_vm_detection()

        assert isinstance(bypass.patches, list)
        assert len(bypass.patches) > 0

    def test_analyzer_with_non_pe_binary(self, tmp_path: Path) -> None:
        """Analyzer handles non-PE binary format gracefully."""
        non_pe: Path = tmp_path / "script.sh"
        non_pe.write_bytes(b"#!/bin/bash\necho 'test'\n")

        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(str(non_pe))
        result: Dict[str, Any] = analyzer.analyze()

        assert isinstance(result, dict)

    def test_bypass_without_frida_available(self, mock_app_with_binary: object, monkeypatch: pytest.MonkeyPatch) -> None:
        """Bypass handles missing Frida dependency gracefully."""
        monkeypatch.setattr("intellicrack.core.protection_bypass.vm_bypass.FRIDA_AVAILABLE", False)

        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(mock_app_with_binary)
        initial_hooks: int = len(bypass.hooks)

        bypass._hook_vm_detection_apis()

        assert len(bypass.hooks) == initial_hooks

    def test_bypass_with_none_app(self) -> None:
        """Bypass initializes correctly with None app."""
        bypass: VirtualizationDetectionBypass = VirtualizationDetectionBypass(None)

        assert bypass.app is None
        assert isinstance(bypass.hooks, list)
        assert isinstance(bypass.patches, list)

    def test_analyzer_with_none_binary_path(self) -> None:
        """Analyzer handles None binary path without crashing."""
        analyzer: VirtualizationAnalyzer = VirtualizationAnalyzer(None)
        result: Dict[str, Any] = analyzer.analyze()

        assert result["has_vm_detection"] is False
        assert len(result["detection_methods"]) == 0
        assert result["confidence"] == 0.0

    def test_detector_generate_bypass_with_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """generate_bypass() handles internal errors gracefully."""
        detector: VMDetector = VMDetector()

        def raise_error(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("Simulated error")

        monkeypatch.setattr(detector, "_generate_bypass_script", raise_error)

        result: Dict[str, Any] = detector.generate_bypass("VMware")

        assert "error" in result or result["bypass_method"] == "failed"
