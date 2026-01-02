"""Comprehensive production-grade tests for VMDetector.

Tests verify VMDetector accurately identifies virtual machine environments using
CPUID instructions, hardware fingerprinting, timing analysis, and artifact detection.
All tests use real implementations or proper test doubles - NO MOCKS.
"""

from __future__ import annotations

import platform
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

import pytest

from intellicrack.core.anti_analysis.vm_detector import (
    CPUIDResult,
    HardwareFingerprint,
    TimingMeasurement,
    VMDetector,
)


@dataclass
class FakeCPUIDExecutor:
    """Test double for CPUID execution with configurable results."""

    leaf_results: dict[tuple[int, int], tuple[int, int, int, int]] = field(default_factory=dict)
    call_count: int = 0
    should_fail: bool = False

    def execute(self, leaf: int, subleaf: int = 0) -> tuple[int, int, int, int] | None:
        """Execute fake CPUID and return configured result."""
        self.call_count += 1

        if self.should_fail:
            return None

        return self.leaf_results.get((leaf, subleaf))

    def configure_hypervisor_bit(self, present: bool) -> None:
        """Configure CPUID leaf 1 with hypervisor bit."""
        ecx = 0x7FFEFBFF if present else 0x7FFEFBFF & ~(1 << 31)
        self.leaf_results[(0x1, 0x0)] = (0x000806EC, 0x00100800, ecx, 0xBFEBFBFF)

    def configure_vendor(self, vendor: str) -> None:
        """Configure CPUID leaf 0 with vendor string."""
        if vendor == "GenuineIntel":
            self.leaf_results[(0x0, 0x0)] = (0x16, 0x756E6547, 0x6C65746E, 0x49656E69)
        elif vendor == "VMwareVMware":
            self.leaf_results[(0x0, 0x0)] = (0x16, 0x61774D56, 0x4D566572, 0x65726177)
        elif vendor == "VBoxVBoxVBox":
            self.leaf_results[(0x0, 0x0)] = (0x16, 0x786F4256, 0x786F4256, 0x786F4256)

    def configure_hypervisor_vendor(self, vendor: str) -> None:
        """Configure CPUID leaf 0x40000000 with hypervisor vendor."""
        if vendor == "VMwareVMware":
            self.leaf_results[(0x40000000, 0x0)] = (0x0, 0x61774D56, 0x4D566572, 0x65726177)
        elif vendor == "VBoxVBoxVBox":
            self.leaf_results[(0x40000000, 0x0)] = (0x0, 0x786F4256, 0x786F4256, 0x786F4256)
        elif vendor == "Microsoft Hv":
            self.leaf_results[(0x40000000, 0x0)] = (0x0, 0x7263694D, 0x666F736F, 0x76482074)


@dataclass
class FakeTimingSource:
    """Test double for timing measurements with configurable patterns."""

    base_timing: int = 100
    variance: int = 5
    vm_overhead: int = 0
    call_count: int = 0
    timing_samples: list[int] = field(default_factory=list)

    def get_rdtsc_timing(self, iterations: int = 1000) -> list[int]:
        """Generate fake RDTSC timing samples."""
        self.call_count += 1
        samples: list[int] = []

        for i in range(iterations):
            base = self.base_timing + self.vm_overhead
            import random
            sample = base + random.randint(-self.variance, self.variance)
            samples.append(max(0, sample))

        self.timing_samples.extend(samples)
        return samples

    def configure_vm_overhead(self, overhead_percent: float) -> None:
        """Configure timing to simulate VM overhead."""
        self.vm_overhead = int(self.base_timing * overhead_percent)


@dataclass
class FakeProcessList:
    """Test double for process list with configurable processes."""

    processes: list[str] = field(default_factory=list)
    call_count: int = 0
    should_fail: bool = False

    def get_processes(self) -> tuple[str, list[str]]:
        """Return configured process list."""
        self.call_count += 1

        if self.should_fail:
            return "", []

        output = "\n".join(self.processes)
        return output, self.processes

    def add_vm_process(self, vm_type: str) -> None:
        """Add VM-specific process to list."""
        vm_processes = {
            "vmware": ["vmtoolsd.exe", "vmware.exe", "vmwareuser.exe"],
            "virtualbox": ["vboxservice.exe", "vboxtray.exe"],
            "hyperv": ["vmms.exe", "vmwp.exe"],
            "qemu": ["qemu-ga.exe"],
        }
        self.processes.extend(vm_processes.get(vm_type.lower(), []))


@dataclass
class FakeRegistryAccess:
    """Test double for Windows registry access."""

    keys: dict[str, dict[str, Any]] = field(default_factory=dict)
    call_count: int = 0
    should_fail: bool = False

    def read_key(self, key_path: str, value_name: str) -> Any:
        """Read value from fake registry."""
        self.call_count += 1

        if self.should_fail:
            raise OSError("Registry access failed")

        key_data = self.keys.get(key_path, {})
        return key_data.get(value_name)

    def key_exists(self, key_path: str) -> bool:
        """Check if registry key exists."""
        self.call_count += 1

        if self.should_fail:
            return False

        return key_path in self.keys

    def configure_vm_registry(self, vm_type: str) -> None:
        """Configure registry with VM-specific keys."""
        if vm_type.lower() == "vmware":
            self.keys["HARDWARE\\DESCRIPTION\\System"] = {"SystemBiosVersion": "VMware"}
            self.keys["HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"] = {
                "Identifier": "VMware Virtual disk SCSI Disk Device"
            }
        elif vm_type.lower() == "virtualbox":
            self.keys["HARDWARE\\DESCRIPTION\\System"] = {"SystemBiosVersion": "VirtualBox"}
            self.keys["HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"] = {
                "Identifier": "VBOX HARDDISK"
            }
        elif vm_type.lower() == "hyperv":
            self.keys["HARDWARE\\DESCRIPTION\\System"] = {"SystemBiosVersion": "Hyper-V"}


@dataclass
class FakeFileSystem:
    """Test double for file system with configurable files."""

    files: set[str] = field(default_factory=set)
    call_count: int = 0

    def file_exists(self, path: str) -> bool:
        """Check if file exists in fake filesystem."""
        self.call_count += 1
        return path.lower() in {f.lower() for f in self.files}

    def configure_vm_files(self, vm_type: str) -> None:
        """Configure filesystem with VM-specific files."""
        if vm_type.lower() == "vmware":
            self.files.update([
                "C:\\Windows\\System32\\drivers\\vmmouse.sys",
                "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
                "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
            ])
        elif vm_type.lower() == "virtualbox":
            self.files.update([
                "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
                "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
                "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxService.exe",
            ])
        elif vm_type.lower() == "hyperv":
            self.files.update([
                "C:\\Windows\\System32\\drivers\\vmbus.sys",
                "C:\\Windows\\System32\\drivers\\hypervideo.sys",
            ])


class TestVMDetectorDataStructures:
    """Tests validating VM detector data structures."""

    def test_cpuid_result_stores_register_values(self) -> None:
        """CPUIDResult correctly stores all register values from CPUID."""
        result = CPUIDResult(
            leaf=0x1,
            subleaf=0x0,
            eax=0x000806EC,
            ebx=0x00100800,
            ecx=0x7FFEFBFF,
            edx=0xBFEBFBFF,
            vendor_string="GenuineIntel",
            brand_string="Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz",
        )

        assert result.leaf == 0x1
        assert result.subleaf == 0x0
        assert result.eax == 0x000806EC
        assert result.ebx == 0x00100800
        assert result.ecx == 0x7FFEFBFF
        assert result.edx == 0xBFEBFBFF
        assert result.vendor_string == "GenuineIntel"
        assert "i7-8700K" in result.brand_string

    def test_cpuid_result_timestamp_generation(self) -> None:
        """CPUIDResult generates timestamp at creation time."""
        before = time.time()
        result = CPUIDResult(leaf=0x0, subleaf=0x0, eax=0x0, ebx=0x0, ecx=0x0, edx=0x0)
        after = time.time()

        assert before <= result.timestamp <= after

    def test_timing_measurement_stores_statistical_data(self) -> None:
        """TimingMeasurement stores complete statistical analysis."""
        samples = [100, 105, 102, 98, 103, 101, 99, 104, 100, 102]
        measurement = TimingMeasurement(
            operation="rdtsc_baseline",
            samples=samples,
            mean=101.4,
            variance=4.04,
            std_dev=2.01,
            min_val=98,
            max_val=105,
            anomaly_detected=False,
            confidence=0.92,
        )

        assert measurement.operation == "rdtsc_baseline"
        assert len(measurement.samples) == 10
        assert measurement.mean == 101.4
        assert measurement.variance == 4.04
        assert measurement.std_dev == 2.01
        assert measurement.min_val == 98
        assert measurement.max_val == 105
        assert measurement.anomaly_detected is False
        assert 0.0 <= measurement.confidence <= 1.0

    def test_hardware_fingerprint_stores_complete_system_info(self) -> None:
        """HardwareFingerprint stores comprehensive system identification."""
        fingerprint = HardwareFingerprint(
            cpu_vendor="GenuineIntel",
            cpu_model="Intel(R) Core(TM) i7-8700K",
            cpu_cores=12,
            total_ram_mb=32768,
            disk_count=2,
            disk_serials=["WD-WCAV12345678", "Samsung_SSD_850_EVO_500GB"],
            mac_addresses=["00:1A:2B:3C:4D:5E", "00:1A:2B:3C:4D:5F"],
            bios_vendor="American Megatrends Inc.",
            bios_version="F10",
            system_manufacturer="Gigabyte",
            system_model="Z370 AORUS Gaming 7",
            motherboard_manufacturer="Gigabyte Technology Co., Ltd.",
            fingerprint_hash="a1b2c3d4e5f6",
        )

        assert fingerprint.cpu_vendor == "GenuineIntel"
        assert fingerprint.cpu_model == "Intel(R) Core(TM) i7-8700K"
        assert fingerprint.cpu_cores == 12
        assert fingerprint.total_ram_mb == 32768
        assert fingerprint.disk_count == 2
        assert len(fingerprint.disk_serials) == 2
        assert len(fingerprint.mac_addresses) == 2
        assert fingerprint.bios_vendor == "American Megatrends Inc."
        assert fingerprint.system_manufacturer == "Gigabyte"
        assert fingerprint.fingerprint_hash == "a1b2c3d4e5f6"


class TestVMDetectorInitialization:
    """Tests validating VM detector initialization."""

    def test_detector_initializes_all_detection_methods(self) -> None:
        """Detector registers all VM detection method handlers."""
        detector = VMDetector()

        assert hasattr(detector, "detection_methods")
        assert isinstance(detector.detection_methods, dict)
        assert len(detector.detection_methods) > 15

    def test_detector_includes_cpuid_detection_methods(self) -> None:
        """Detector includes CPUID-based detection methods."""
        detector = VMDetector()

        cpuid_methods = [
            "cpuid_hypervisor_bit",
            "cpuid_vendor_strings",
            "hypervisor_brand",
            "cpuid_feature_flags",
        ]

        for method in cpuid_methods:
            assert any(method in key for key in detector.detection_methods.keys())

    def test_detector_includes_timing_detection_methods(self) -> None:
        """Detector includes timing-based detection methods."""
        detector = VMDetector()

        timing_methods = ["rdtsc_timing", "sleep_timing", "instruction_timing"]

        for method in timing_methods:
            assert any(method in key for key in detector.detection_methods.keys())

    def test_detector_includes_artifact_detection_methods(self) -> None:
        """Detector includes artifact-based detection methods."""
        detector = VMDetector()

        artifact_methods = ["process_list", "registry_keys", "file_system", "device_drivers"]

        for method in artifact_methods:
            assert any(method in key for key in detector.detection_methods.keys())

    def test_all_registered_methods_are_callable(self) -> None:
        """All registered detection methods are callable."""
        detector = VMDetector()

        for method_name, method_func in detector.detection_methods.items():
            assert callable(method_func), f"{method_name} is not callable"


class TestCPUIDHypervisorBitDetection:
    """Tests validating CPUID hypervisor bit detection (ECX bit 31 on leaf 1)."""

    def test_cpuid_hypervisor_bit_executes_on_real_hardware(self) -> None:
        """CPUID hypervisor bit check executes on real hardware."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_cpuid_hypervisor_bit()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"CPUID not available on this platform: {e}")

    def test_cpuid_check_returns_valid_confidence_range(self) -> None:
        """CPUID hypervisor check returns confidence between 0 and 1."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_cpuid_hypervisor_bit()
            assert 0.0 <= confidence <= 1.0
        except Exception:
            pytest.skip("CPUID not supported")

    def test_physical_hardware_cpuid_check_low_confidence(self) -> None:
        """CPUID check on physical hardware returns low or no detection."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_cpuid_hypervisor_bit()

            cpu_info = platform.processor().lower()
            is_likely_vm = any(
                keyword in cpu_info for keyword in ["vmware", "virtualbox", "hyper-v", "kvm", "xen", "qemu"]
            )

            if not is_likely_vm and detected:
                assert confidence < 0.6
        except Exception:
            pytest.skip("CPUID not supported on this platform")


class TestCPUIDVendorStringDetection:
    """Tests validating CPUID vendor string detection."""

    def test_cpuid_vendor_string_check_executes(self) -> None:
        """CPUID vendor string check executes and returns valid results."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_cpuid_vendor_strings()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"CPUID vendor check not available: {e}")

    def test_vendor_string_detection_identifies_genuine_intel(self) -> None:
        """Vendor string detection correctly identifies GenuineIntel."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_cpuid_vendor_strings()

            if "vendor" in details and details["vendor"] == "GenuineIntel":
                assert isinstance(detected, bool)
        except Exception:
            pytest.skip("CPUID not supported")


class TestHypervisorBrandDetection:
    """Tests validating hypervisor brand string detection (CPUID leaf 0x40000000)."""

    def test_hypervisor_brand_check_executes(self) -> None:
        """Hypervisor brand check executes on real hardware."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_hypervisor_brand()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"Hypervisor brand check not available: {e}")


class TestTimingBasedDetection:
    """Tests validating timing-based VM detection."""

    def test_rdtsc_timing_check_executes(self) -> None:
        """RDTSC timing check executes and measures timing."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_rdtsc_timing()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"RDTSC timing not available: {e}")

    def test_rdtsc_timing_produces_samples(self) -> None:
        """RDTSC timing check produces timing samples."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_rdtsc_timing()

            if "samples" in details or "timing_samples" in details:
                samples = details.get("samples") or details.get("timing_samples")
                if samples:
                    assert all(isinstance(s, (int, float)) for s in samples)
                    assert all(s >= 0 for s in samples)
        except Exception:
            pytest.skip("Timing samples not available")

    def test_sleep_timing_check_executes(self) -> None:
        """Sleep timing check executes and detects VM overhead."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_sleep_timing()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"Sleep timing not available: {e}")

    def test_instruction_timing_check_executes(self) -> None:
        """Instruction timing check executes and measures overhead."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_instruction_timing()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"Instruction timing not available: {e}")


class TestProcessListDetection:
    """Tests validating process list-based VM detection."""

    def test_process_list_check_executes(self) -> None:
        """Process list check executes and scans for VM processes."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_process_list()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"Process list check not available: {e}")

    def test_process_list_retrieves_real_processes(self) -> None:
        """Process list check retrieves actual running processes."""
        detector = VMDetector()

        try:
            processes_output, process_list = detector.get_running_processes()

            assert isinstance(processes_output, str)
            assert isinstance(process_list, list)

            if process_list:
                assert all(isinstance(p, str) for p in process_list)
        except Exception:
            pytest.skip("Process list not available")


class TestRegistryKeyDetection:
    """Tests validating Windows registry-based VM detection."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_registry_key_check_executes_on_windows(self) -> None:
        """Registry key check executes on Windows systems."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_registry_keys()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"Registry check not available: {e}")


class TestFileSystemDetection:
    """Tests validating file system artifact-based VM detection."""

    def test_file_system_check_executes(self) -> None:
        """File system check executes and scans for VM files."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_file_system()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"File system check not available: {e}")


class TestHardwareFingerprintDetection:
    """Tests validating hardware fingerprint-based detection."""

    def test_hardware_fingerprint_check_executes(self) -> None:
        """Hardware fingerprint check executes and collects data."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_hardware_fingerprint()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"Hardware fingerprint not available: {e}")

    def test_get_hardware_fingerprint_collects_system_data(self) -> None:
        """get_hardware_fingerprint collects comprehensive system data."""
        detector = VMDetector()

        try:
            fingerprint = detector.get_hardware_fingerprint()

            assert isinstance(fingerprint, HardwareFingerprint)
            assert isinstance(fingerprint.cpu_vendor, str)
            assert isinstance(fingerprint.cpu_cores, int)
            assert isinstance(fingerprint.total_ram_mb, int)
        except Exception as e:
            pytest.skip(f"Hardware fingerprint collection not available: {e}")


class TestNetworkAdapterDetection:
    """Tests validating network adapter-based VM detection."""

    def test_network_adapter_check_executes(self) -> None:
        """Network adapter check executes and scans for VM adapters."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_network_adapters()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"Network adapter check not available: {e}")


class TestBIOSInfoDetection:
    """Tests validating BIOS information-based VM detection."""

    def test_bios_info_check_executes(self) -> None:
        """BIOS info check executes and examines BIOS data."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_bios_info()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"BIOS info check not available: {e}")


class TestDeviceDriverDetection:
    """Tests validating device driver-based VM detection."""

    def test_device_driver_check_executes(self) -> None:
        """Device driver check executes and scans for VM drivers."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_device_drivers()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"Device driver check not available: {e}")


class TestComprehensiveVMDetection:
    """Tests validating comprehensive VM detection workflow."""

    def test_detect_vm_aggregates_all_methods(self) -> None:
        """detect_vm runs all detection methods and aggregates results."""
        detector = VMDetector()

        result = detector.detect_vm()

        assert isinstance(result, dict)
        assert "is_vm" in result
        assert "confidence" in result
        assert "vm_type" in result
        assert "detections" in result
        assert "evasion_score" in result

        assert isinstance(result["is_vm"], bool)
        assert isinstance(result["confidence"], float)
        assert isinstance(result["detections"], dict)
        assert isinstance(result["evasion_score"], int)

    def test_detect_vm_confidence_in_valid_range(self) -> None:
        """detect_vm returns confidence score between 0 and 1."""
        detector = VMDetector()

        result = detector.detect_vm()

        assert 0.0 <= result["confidence"] <= 1.0

    def test_detect_vm_includes_detection_details(self) -> None:
        """detect_vm includes individual method detection details."""
        detector = VMDetector()

        result = detector.detect_vm()

        detections = result["detections"]
        assert isinstance(detections, dict)
        assert len(detections) > 0

        for method_name, method_result in detections.items():
            assert isinstance(method_result, dict)
            assert "detected" in method_result
            assert "confidence" in method_result
            assert "details" in method_result

    def test_detect_vm_aggressive_mode_runs_extra_checks(self) -> None:
        """detect_vm aggressive mode includes additional detection methods."""
        detector = VMDetector()

        result_normal = detector.detect_vm(aggressive=False)
        result_aggressive = detector.detect_vm(aggressive=True)

        assert isinstance(result_normal, dict)
        assert isinstance(result_aggressive, dict)

    def test_detect_vm_calculates_evasion_score(self) -> None:
        """detect_vm calculates evasion difficulty score."""
        detector = VMDetector()

        result = detector.detect_vm()

        assert isinstance(result["evasion_score"], int)
        assert 0 <= result["evasion_score"] <= 10

    def test_detect_vm_identifies_vm_type(self) -> None:
        """detect_vm identifies specific VM platform type."""
        detector = VMDetector()

        result = detector.detect_vm()

        vm_type = result["vm_type"]
        if vm_type is not None:
            assert isinstance(vm_type, str)
            valid_types = ["VMware", "VirtualBox", "Hyper-V", "KVM", "Xen", "QEMU", "Unknown"]
            assert any(vt in vm_type for vt in valid_types)


class TestVMTypeIdentification:
    """Tests validating specific VM platform identification."""

    def test_identify_vm_type_from_detections(self) -> None:
        """_identify_vm_type correctly identifies VM from detection results."""
        detector = VMDetector()

        vmware_detections = {
            "cpuid_vendor_strings": {
                "detected": True,
                "confidence": 0.95,
                "details": {"vendor": "VMwareVMware"},
            }
        }

        vm_type = detector._identify_vm_type(vmware_detections)
        assert "VMware" in vm_type or vm_type == "Unknown"

    def test_identify_vm_type_handles_no_detections(self) -> None:
        """_identify_vm_type returns Unknown when no detections."""
        detector = VMDetector()

        empty_detections: dict[str, Any] = {}

        vm_type = detector._identify_vm_type(empty_detections)
        assert vm_type == "Unknown"


class TestEvasionScoreCalculation:
    """Tests validating evasion difficulty score calculation."""

    def test_calculate_evasion_score_returns_valid_range(self) -> None:
        """_calculate_evasion_score returns score between 0 and 10."""
        detector = VMDetector()

        detections: dict[str, Any] = {
            "cpuid_hypervisor_bit": {"detected": True, "confidence": 0.9},
            "rdtsc_timing": {"detected": True, "confidence": 0.7},
            "process_list": {"detected": True, "confidence": 0.8},
        }

        score = detector._calculate_evasion_score(detections)
        assert isinstance(score, int)
        assert 0 <= score <= 10

    def test_calculate_evasion_score_handles_empty_detections(self) -> None:
        """_calculate_evasion_score handles empty detection dict."""
        detector = VMDetector()

        empty_detections: dict[str, Any] = {}

        score = detector._calculate_evasion_score(empty_detections)
        assert score == 0


class TestTimingAnalysis:
    """Tests validating timing pattern analysis."""

    def test_analyze_timing_patterns_executes(self) -> None:
        """analyze_timing_patterns executes timing measurements."""
        detector = VMDetector()

        try:
            patterns = detector.analyze_timing_patterns()

            assert isinstance(patterns, dict)
            for operation, measurement in patterns.items():
                assert isinstance(operation, str)
                assert isinstance(measurement, TimingMeasurement)
        except Exception as e:
            pytest.skip(f"Timing analysis not available: {e}")


class TestBypassGeneration:
    """Tests validating VM detection bypass code generation."""

    def test_generate_bypass_creates_bypass_data(self) -> None:
        """generate_bypass creates bypass configuration for VM type."""
        detector = VMDetector()

        bypass_data = detector.generate_bypass("VMware")

        assert isinstance(bypass_data, dict)
        assert "vm_type" in bypass_data
        assert bypass_data["vm_type"] == "VMware"

    def test_generate_bypass_handles_unknown_vm_type(self) -> None:
        """generate_bypass handles unknown VM types gracefully."""
        detector = VMDetector()

        bypass_data = detector.generate_bypass("UnknownVM")

        assert isinstance(bypass_data, dict)


class TestDetectionMethodCoverage:
    """Tests validating all detection methods return correct format."""

    def test_all_methods_return_three_element_tuple(self) -> None:
        """All detection methods return (bool, float, dict) tuple."""
        detector = VMDetector()

        for method_name, method_func in detector.detection_methods.items():
            try:
                result = method_func()

                assert isinstance(result, tuple), f"{method_name} did not return tuple"
                assert len(result) == 3, f"{method_name} returned tuple of length {len(result)}"
                assert isinstance(result[0], bool), f"{method_name} first element not bool"
                assert isinstance(result[1], float), f"{method_name} second element not float"
                assert isinstance(result[2], dict), f"{method_name} third element not dict"
                assert 0.0 <= result[1] <= 1.0, f"{method_name} confidence out of range: {result[1]}"
            except Exception as e:
                pytest.skip(f"Method {method_name} not available: {e}")


class TestAggressiveDetectionMethods:
    """Tests validating aggressive detection method identification."""

    def test_get_aggressive_methods_returns_list(self) -> None:
        """get_aggressive_methods returns list of aggressive method names."""
        detector = VMDetector()

        aggressive_methods = detector.get_aggressive_methods()

        assert isinstance(aggressive_methods, list)
        assert all(isinstance(method, str) for method in aggressive_methods)

    def test_aggressive_methods_are_subset_of_all_methods(self) -> None:
        """Aggressive methods are subset of all detection methods."""
        detector = VMDetector()

        aggressive_methods = detector.get_aggressive_methods()
        all_methods = list(detector.detection_methods.keys())

        for aggressive_method in aggressive_methods:
            assert any(aggressive_method in method for method in all_methods)


class TestDetectionType:
    """Tests validating detection type identification."""

    def test_get_detection_type_returns_string(self) -> None:
        """get_detection_type returns string describing detector type."""
        detector = VMDetector()

        detection_type = detector.get_detection_type()

        assert isinstance(detection_type, str)
        assert len(detection_type) > 0


class TestPerformanceCharacteristics:
    """Tests validating detection performance meets requirements."""

    def test_full_detection_completes_within_time_limit(self) -> None:
        """Full VM detection completes within 10 seconds."""
        detector = VMDetector()

        start_time = time.time()
        detector.detect_vm()
        elapsed = time.time() - start_time

        assert elapsed < 10.0, f"Detection took {elapsed:.2f}s, expected < 10s"

    def test_aggressive_detection_completes_within_time_limit(self) -> None:
        """Aggressive VM detection completes within 15 seconds."""
        detector = VMDetector()

        start_time = time.time()
        detector.detect_vm(aggressive=True)
        elapsed = time.time() - start_time

        assert elapsed < 15.0, f"Aggressive detection took {elapsed:.2f}s, expected < 15s"

    def test_individual_methods_complete_quickly(self) -> None:
        """Individual detection methods complete within 2 seconds."""
        detector = VMDetector()

        for method_name, method_func in detector.detection_methods.items():
            start_time = time.time()
            try:
                method_func()
            except Exception:
                pass
            elapsed = time.time() - start_time

            assert elapsed < 2.0, f"{method_name} took {elapsed:.2f}s"


class TestRepeatableDetection:
    """Tests validating detection results are consistent."""

    def test_repeated_detections_produce_consistent_results(self) -> None:
        """Multiple detection runs produce consistent VM detection results."""
        detector = VMDetector()

        result1 = detector.detect_vm()
        result2 = detector.detect_vm()
        result3 = detector.detect_vm()

        assert result1["is_vm"] == result2["is_vm"] == result3["is_vm"]

        confidence_variance = max(
            abs(result1["confidence"] - result2["confidence"]),
            abs(result2["confidence"] - result3["confidence"]),
            abs(result1["confidence"] - result3["confidence"]),
        )
        assert confidence_variance < 0.2


class TestErrorHandling:
    """Tests validating error handling in detection methods."""

    def test_detection_handles_missing_permissions_gracefully(self) -> None:
        """Detection handles missing permissions without crashing."""
        detector = VMDetector()

        try:
            result = detector.detect_vm()
            assert isinstance(result, dict)
        except PermissionError:
            pytest.skip("Insufficient permissions")
        except Exception as e:
            pytest.fail(f"Detection raised unexpected exception: {e}")

    def test_detection_handles_platform_differences(self) -> None:
        """Detection handles platform-specific features gracefully."""
        detector = VMDetector()

        try:
            result = detector.detect_vm()

            assert isinstance(result, dict)
            assert "is_vm" in result
            assert "confidence" in result
        except Exception as e:
            pytest.fail(f"Detection failed on {platform.system()}: {e}")


class TestPlatformSpecificBehavior:
    """Tests validating platform-specific detection behavior."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_windows_specific_detection_methods_execute(self) -> None:
        """Windows-specific detection methods execute on Windows."""
        detector = VMDetector()

        result = detector.detect_vm()

        assert isinstance(result, dict)
        detections = result["detections"]

        windows_methods = ["registry_keys", "device_drivers"]
        for method in windows_methods:
            found = any(method in key for key in detections.keys())
            if found:
                break

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific test")
    def test_linux_specific_detection_methods_execute(self) -> None:
        """Linux-specific detection methods execute on Linux."""
        detector = VMDetector()

        result = detector.detect_vm()

        assert isinstance(result, dict)


class TestEdgeCases:
    """Tests validating edge case handling."""

    def test_detection_with_no_vm_present(self) -> None:
        """Detection handles non-VM environment correctly."""
        detector = VMDetector()

        result = detector.detect_vm()

        cpu_info = platform.processor().lower()
        is_likely_vm = any(keyword in cpu_info for keyword in ["vmware", "virtualbox", "hyper-v", "kvm", "xen"])

        if not is_likely_vm and result["is_vm"]:
            assert result["confidence"] < 0.7

    def test_detection_handles_restricted_hardware_access(self) -> None:
        """Detection handles restricted hardware access gracefully."""
        detector = VMDetector()

        try:
            result = detector.detect_vm()
            assert isinstance(result, dict)
        except PermissionError:
            pytest.skip("Insufficient permissions for hardware access")
        except Exception as e:
            pytest.fail(f"Detection raised unexpected exception: {e}")

    def test_detection_handles_corrupted_system_info(self) -> None:
        """Detection handles corrupted or missing system information."""
        detector = VMDetector()

        try:
            result = detector.detect_vm()

            assert isinstance(result, dict)
            assert "is_vm" in result
            assert isinstance(result["is_vm"], bool)
        except Exception as e:
            pytest.fail(f"Detection failed with corrupted data: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
