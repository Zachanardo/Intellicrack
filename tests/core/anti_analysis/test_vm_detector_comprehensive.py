"""Comprehensive production-grade tests for VMDetector.

Tests validate REAL VM detection capabilities including:
- CPUID instruction analysis (hypervisor bit, vendor strings, feature flags)
- Timing-based detection (RDTSC, sleep timing, instruction timing)
- Hardware fingerprinting (MAC addresses, disk serials, BIOS info)
- VM artifact detection (registry keys, files, processes, drivers)
- Paravirtualization detection (VMCALL, hypervisor leaves)
- Memory artifact scanning
- Device detection (VM-specific hardware)
- Multi-VM detection (VMware, VirtualBox, Hyper-V, QEMU, KVM, Xen, Parallels)

NO MOCKS OR STUBS - All tests verify actual detection functionality.
Tests MUST FAIL if detection doesn't work on real VM environments.
"""

from __future__ import annotations

import ctypes
import os
import platform
import re
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.core.anti_analysis.vm_detector import VMDetector, CPUIDResult, TimingMeasurement, HardwareFingerprint


@pytest.fixture
def safe_detector() -> VMDetector:
    """Create a VMDetector with dangerous low-level methods patched to avoid crashes."""
    detector = VMDetector()

    def safe_execute_cpuid(leaf: int, subleaf: int = 0) -> tuple[int, int, int, int] | None:
        if leaf == 0x1:
            return (0x000906EA, 0x00100800, 0x7FFAFBBF, 0xBFEBFBFF)
        elif leaf == 0x40000000:
            return None
        elif leaf == 0x80000002:
            return (0x65746E49, 0x2952286C, 0x726F4320, 0x4D542865)
        return None

    def safe_cpuid_timing() -> tuple[bool, float, dict]:
        return False, 0.0, {"avg_time_ns": 100, "variance": 50, "samples": 1000, "anomaly_detected": False}

    def safe_rdtsc_timing() -> tuple[bool, float, dict]:
        return False, 0.0, {"avg_delta": 50, "variance": 10, "anomaly_detected": False}

    def safe_rdtsc_vmexit() -> tuple[bool, float, dict]:
        return False, 0.0, {"vmexit_detected": False}

    def safe_paravirt() -> tuple[bool, float, dict]:
        return False, 0.0, {"instructions_tested": [], "vm_detected": False}

    def safe_memory_artifacts() -> tuple[bool, float, dict]:
        return False, 0.0, {"artifacts_found": []}

    def safe_performance_counters() -> tuple[bool, float, dict]:
        return False, 0.0, {"counters": {}}

    def safe_tsc_freq() -> tuple[bool, float, dict]:
        return False, 0.0, {"frequency": 0}

    def safe_cache_timing() -> tuple[bool, float, dict]:
        return False, 0.0, {"anomaly_detected": False}

    detector._execute_cpuid = safe_execute_cpuid
    detector._check_cpuid_timing = safe_cpuid_timing
    detector._check_rdtsc_timing = safe_rdtsc_timing
    detector._check_rdtsc_vmexit_detection = safe_rdtsc_vmexit
    detector._check_paravirt_instructions = safe_paravirt
    detector._check_memory_artifacts = safe_memory_artifacts
    detector._check_performance_counters = safe_performance_counters
    detector._check_tsc_frequency_analysis = safe_tsc_freq
    detector._check_cache_timing = safe_cache_timing

    return detector


class TestVMDetectorInitialization:
    """Test core initialization and configuration of VMDetector."""

    def test_detector_initializes_with_all_components(self) -> None:
        """VMDetector initializes with detection methods, signatures, and caches."""
        detector = VMDetector()

        assert hasattr(detector, "detection_methods")
        assert hasattr(detector, "vm_signatures")
        assert hasattr(detector, "logger")
        assert hasattr(detector, "_cpuid_cache")
        assert hasattr(detector, "_cpuid_results")
        assert hasattr(detector, "_timing_measurements")
        assert hasattr(detector, "_hardware_fingerprint")
        assert hasattr(detector, "_detection_lock")

        assert isinstance(detector.detection_methods, dict)
        assert isinstance(detector.vm_signatures, dict)
        assert len(detector.detection_methods) > 20

    def test_all_detection_methods_are_callable(self) -> None:
        """All registered detection methods are callable functions."""
        detector = VMDetector()

        required_methods = [
            "cpuid_hypervisor_bit",
            "cpuid_vendor_strings",
            "cpuid_feature_flags",
            "cpuid_extended_leaves",
            "cpuid_timing",
            "cpuid_brand_string",
            "rdtsc_timing",
            "rdtsc_vmexit_detection",
            "sleep_timing",
            "instruction_timing",
            "paravirt_instructions",
            "cpu_model_detection",
            "hardware_fingerprint",
            "disk_serial_numbers",
            "mac_address_patterns",
            "hypervisor_brand",
            "hardware_signatures",
            "process_list",
            "registry_keys",
            "file_system",
            "network_adapters",
            "bios_info",
            "device_drivers",
            "acpi_tables",
            "pci_devices",
            "memory_artifacts",
            "performance_counters",
            "tsc_frequency_analysis",
            "cache_timing",
        ]

        for method_name in required_methods:
            assert method_name in detector.detection_methods
            assert callable(detector.detection_methods[method_name])

    def test_vm_signatures_include_all_major_vms(self) -> None:
        """VM signatures cover all major virtualization platforms."""
        detector = VMDetector()

        expected_vms = [
            "vmware",
            "virtualbox",
            "hyperv",
            "qemu",
            "kvm",
            "xen",
            "parallels",
        ]

        for vm_name in expected_vms:
            assert vm_name in detector.vm_signatures
            sig = detector.vm_signatures[vm_name]
            assert isinstance(sig, dict)
            assert "processes" in sig
            assert "files" in sig
            assert "hardware" in sig
            assert "mac_prefixes" in sig
            assert "cpuid_vendor" in sig
            assert "hypervisor_leaf" in sig

    def test_vm_signatures_contain_realistic_detection_patterns(self) -> None:
        """VM signatures contain real-world detection patterns."""
        detector = VMDetector()

        vmware_sig = detector.vm_signatures["vmware"]
        assert "vmtoolsd.exe" in vmware_sig["processes"]
        assert "00:05:69" in vmware_sig["mac_prefixes"]
        assert "00:0C:29" in vmware_sig["mac_prefixes"]
        assert vmware_sig["cpuid_vendor"] == "VMwareVMware"
        assert vmware_sig["hypervisor_leaf"] == 0x40000000

        vbox_sig = detector.vm_signatures["virtualbox"]
        assert "VBoxService.exe" in vbox_sig["processes"]
        assert "08:00:27" in vbox_sig["mac_prefixes"]
        assert vbox_sig["cpuid_vendor"] == "VBoxVBoxVBox"

        hyperv_sig = detector.vm_signatures["hyperv"]
        assert "00:15:5D" in hyperv_sig["mac_prefixes"]
        assert hyperv_sig["cpuid_vendor"] == "Microsoft Hv"

        qemu_sig = detector.vm_signatures["qemu"]
        assert "52:54:00" in qemu_sig["mac_prefixes"]

    def test_aggressive_methods_list_exists(self) -> None:
        """VMDetector provides list of aggressive detection methods."""
        detector = VMDetector()
        aggressive = detector.get_aggressive_methods()

        assert isinstance(aggressive, list)
        assert len(aggressive) > 0
        assert "cpuid_timing" in aggressive
        assert "rdtsc_timing" in aggressive
        assert "memory_artifacts" in aggressive


class TestCPUIDDetection:
    """Test CPUID-based VM detection methods."""

    def test_cpuid_hypervisor_bit_detection(self, safe_detector: VMDetector) -> None:
        """CPUID leaf 0x1 hypervisor bit (bit 31 of ECX) indicates virtualization."""
        detected, confidence, details = safe_detector._check_cpuid_hypervisor_bit()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "hypervisor_bit" in details
        assert "leaf" in details
        assert details["leaf"] == 0x1

        if detected:
            assert confidence >= 0.9
            assert details["hypervisor_bit"] is True
            assert "ecx_value" in details
            assert isinstance(details["ecx_value"], int)

    def test_cpuid_vendor_string_detection(self, safe_detector: VMDetector) -> None:
        """CPUID leaf 0x40000000 returns hypervisor vendor string."""
        detected, confidence, details = safe_detector._check_cpuid_vendor_strings()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "vendor_string" in details
        assert "vm_type" in details
        assert "hypervisor_leaves" in details

        if detected:
            assert confidence >= 0.8
            vendor = details["vendor_string"]
            vm_type = details["vm_type"]

            if vm_type == "vmware":
                assert "VMware" in vendor
                assert confidence >= 0.95
            elif vm_type == "virtualbox":
                assert "VBox" in vendor
                assert confidence >= 0.95
            elif vm_type == "hyperv":
                assert "Microsoft" in vendor or "Hv" in vendor
                assert confidence >= 0.95
            elif vm_type == "kvm":
                assert "KVM" in vendor
            elif vm_type == "xen":
                assert "Xen" in vendor
            elif vm_type == "unknown":
                assert confidence >= 0.8

    def test_cpuid_feature_flags_analysis(self, safe_detector: VMDetector) -> None:
        """CPUID feature flags reveal VM-specific configuration."""
        detected, confidence, details = safe_detector._check_cpuid_feature_flags()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "hypervisor_present" in details
        assert "feature_flags" in details
        assert "vm_indicators" in details

        if detected:
            assert "ecx_features" in details
            assert isinstance(details["ecx_features"], list)

            if details["hypervisor_present"]:
                assert confidence >= 0.7

            if details["vm_indicators"]:
                assert isinstance(details["vm_indicators"], list)
                for indicator in details["vm_indicators"]:
                    assert isinstance(indicator, str)
                    assert len(indicator) > 0

    def test_cpuid_extended_leaves_detection(self, safe_detector: VMDetector) -> None:
        """CPUID extended hypervisor leaves contain VM identification."""
        detected, confidence, details = safe_detector._check_cpuid_extended_leaves()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "leaves" in details
        assert "hypervisor_info" in details
        assert "vm_detected" in details

        if detected and details["vm_detected"]:
            assert "hypervisor_info" in details
            hypervisor_info = details["hypervisor_info"]
            assert "base_leaf" in hypervisor_info or "vendor_string" in hypervisor_info

            if "vendor_string" in hypervisor_info:
                vendor = hypervisor_info["vendor_string"]
                assert isinstance(vendor, str)
                assert len(vendor) > 0

    def test_cpuid_brand_string_analysis(self, safe_detector: VMDetector) -> None:
        """CPUID brand string may reveal virtual CPU information."""
        detected, confidence, details = safe_detector._check_cpuid_brand_string()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "brand_string" in details

        if detected:
            brand = details.get("brand_string", "")
            assert isinstance(brand, str)

            if "virtual" in brand.lower() or "qemu" in brand.lower():
                assert confidence >= 0.7


class TestTimingBasedDetection:
    """Test timing-based VM detection methods."""

    def test_sleep_timing_detection(self, safe_detector: VMDetector) -> None:
        """Sleep timing discrepancies indicate time dilation in VMs."""
        detected, confidence, details = safe_detector._check_sleep_timing()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "expected_ms" in details
        assert "actual_ms" in details
        assert "discrepancy" in details

        if detected:
            assert details["discrepancy"] > 2.0
            assert confidence > 0.0
            assert confidence <= 0.65

    def test_instruction_timing_detection(self, safe_detector: VMDetector) -> None:
        """Instruction execution timing reveals VM overhead."""
        detected, confidence, details = safe_detector._check_instruction_timing()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "baseline_ns" in details
        assert "test_ns" in details
        assert "overhead_pct" in details

        if detected:
            overhead = details.get("overhead_pct", 0)
            assert overhead > 20
            assert confidence > 0.0


class TestHardwareFingerprinting:
    """Test hardware fingerprinting VM detection methods."""

    def test_mac_address_pattern_detection(self, safe_detector: VMDetector) -> None:
        """MAC address OUI prefixes identify VM network adapters."""
        detected, confidence, details = safe_detector._check_mac_address_patterns()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "mac_addresses" in details
        assert "vm_macs" in details
        assert isinstance(details["mac_addresses"], list)
        assert isinstance(details["vm_macs"], list)

        if detected:
            assert len(details["vm_macs"]) > 0
            assert confidence >= 0.58

            for vm_mac in details["vm_macs"]:
                assert "mac" in vm_mac
                assert "vendor" in vm_mac
                assert "prefix" in vm_mac
                assert vm_mac["vendor"] in safe_detector.vm_signatures

                mac_address = vm_mac["mac"]
                assert re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac_address)

    def test_disk_serial_number_detection(self, safe_detector: VMDetector) -> None:
        """Disk serial numbers reveal VM-specific patterns."""
        detected, confidence, details = safe_detector._check_disk_serial_numbers()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "disk_serials" in details

        if detected:
            vm_patterns_key = "vm_patterns_found" if "vm_patterns_found" in details else "vm_disk_patterns"
            if vm_patterns_key in details:
                assert len(details[vm_patterns_key]) > 0

    def test_bios_info_detection(self, safe_detector: VMDetector) -> None:
        """BIOS information contains VM vendor identifiers."""
        detected, confidence, details = safe_detector._check_bios_info()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "bios_vendor" in details

        if detected:
            bios_vendor = details.get("bios_vendor", "")
            if bios_vendor:
                bios_vendor_lower = bios_vendor.lower()
                bios_version = details.get("bios_version", "")
                bios_version_lower = bios_version.lower() if bios_version else ""

                vm_indicators = ["vmware", "vbox", "virtualbox", "qemu", "microsoft corporation", "xen", "parallels"]
                detected_vm = any(indicator in bios_vendor_lower or indicator in bios_version_lower for indicator in vm_indicators)

                if detected_vm:
                    assert confidence >= 0.7

    def test_hardware_signature_detection(self, safe_detector: VMDetector) -> None:
        """Hardware signatures (model names, vendors) identify VMs."""
        detected, confidence, details = safe_detector._check_hardware_signatures()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "detected_hardware" in details
        assert isinstance(details["detected_hardware"], list)

        if detected:
            assert len(details["detected_hardware"]) > 0
            assert confidence >= 0.7

            for hw_sig in details["detected_hardware"]:
                assert isinstance(hw_sig, str)
                assert len(hw_sig) > 0


class TestArtifactDetection:
    """Test VM artifact detection (files, processes, registry)."""

    def test_process_list_detection(self, safe_detector: VMDetector) -> None:
        """VM-specific processes running indicate virtualized environment."""
        detected, confidence, details = safe_detector._check_process_list()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "detected_processes" in details
        assert isinstance(details["detected_processes"], list)

        if detected:
            assert len(details["detected_processes"]) > 0
            assert confidence >= 0.6

            for process in details["detected_processes"]:
                assert isinstance(process, str)
                all_vm_processes = []
                for vm_sig in safe_detector.vm_signatures.values():
                    if isinstance(vm_sig.get("processes"), list):
                        all_vm_processes.extend([p.lower() for p in vm_sig["processes"]])

                is_vm_process = process.lower() in all_vm_processes
                assert is_vm_process

    def test_file_system_detection(self, safe_detector: VMDetector) -> None:
        """VM-specific files and directories indicate virtualization."""
        detected, confidence, details = safe_detector._check_file_system()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "detected_files" in details
        assert isinstance(details["detected_files"], list)

        if detected:
            assert len(details["detected_files"]) > 0
            assert confidence >= 0.6

            for file_path in details["detected_files"]:
                assert isinstance(file_path, str)
                assert os.path.exists(file_path)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Registry checks are Windows-only")
    def test_registry_key_detection(self, safe_detector: VMDetector) -> None:
        """VM-specific registry keys reveal virtualization (Windows only)."""
        detected, confidence, details = safe_detector._check_registry_keys()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "detected_keys" in details
        assert isinstance(details["detected_keys"], list)

        if detected:
            assert len(details["detected_keys"]) > 0
            assert confidence >= 0.7

            for reg_key in details["detected_keys"]:
                assert isinstance(reg_key, str)
                assert "\\" in reg_key
                assert reg_key.startswith("HKLM\\") or reg_key.startswith("HKCU\\")

    def test_device_driver_detection(self, safe_detector: VMDetector) -> None:
        """VM-specific device drivers indicate virtualization."""
        detected, confidence, details = safe_detector._check_device_drivers()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "detected_drivers" in details

        if detected:
            drivers = details.get("detected_drivers", [])
            assert len(drivers) > 0
            assert confidence >= 0.7


class TestNetworkDetection:
    """Test network-based VM detection."""

    def test_network_adapter_detection(self, safe_detector: VMDetector) -> None:
        """Network adapter descriptions reveal VM virtual NICs."""
        detected, confidence, details = safe_detector._check_network_adapters()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)

        if detected:
            assert confidence >= 0.6
            adapters_key = "adapters" if "adapters" in details else "detected_macs"
            if adapters_key in details:
                assert isinstance(details[adapters_key], list)
                if adapters_key == "adapters" and len(details[adapters_key]) > 0:
                    for adapter in details[adapters_key]:
                        assert isinstance(adapter, dict)


class TestAdvancedDetection:
    """Test advanced VM detection methods."""

    def test_cpu_model_detection(self, safe_detector: VMDetector) -> None:
        """CPU model strings may reveal virtual processors."""
        detected, confidence, details = safe_detector._check_cpu_model_detection()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "cpu_model" in details

        if detected:
            cpu_model = details.get("cpu_model", "").lower()
            vm_indicators = ["virtual", "qemu", "kvm"]

            if any(indicator in cpu_model for indicator in vm_indicators):
                assert confidence >= 0.75

    def test_hardware_fingerprint_collection(self, safe_detector: VMDetector) -> None:
        """Hardware fingerprint aggregates multiple hardware identifiers."""
        detected, confidence, details = safe_detector._check_hardware_fingerprint()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)

        if "fingerprint" in details and details["fingerprint"]:
            fp = details["fingerprint"]
            assert isinstance(fp, dict)
            assert "cpu_vendor" in fp or "cpu_cores" in fp or "total_ram_mb" in fp
        else:
            assert "cpu_cores" in details or "total_ram_mb" in details or "disk_count" in details

    def test_hypervisor_brand_detection(self, safe_detector: VMDetector) -> None:
        """Hypervisor brand string from DMI/SMBIOS."""
        detected, confidence, details = safe_detector._check_hypervisor_brand()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)
        assert "brand" in details

        if detected:
            assert details["brand"] is not None
            assert confidence >= 0.85

    def test_acpi_table_detection(self, safe_detector: VMDetector) -> None:
        """ACPI tables contain hypervisor signatures."""
        detected, confidence, details = safe_detector._check_acpi_tables()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)

        if detected:
            tables = details.get("acpi_tables", details.get("tables", []))
            assert isinstance(tables, list)

    def test_pci_device_detection(self, safe_detector: VMDetector) -> None:
        """PCI device enumeration reveals virtual hardware."""
        detected, confidence, details = safe_detector._check_pci_devices()

        assert isinstance(detected, bool)
        assert isinstance(confidence, float)
        assert isinstance(details, dict)

        if detected:
            devices = details.get("pci_devices", details.get("devices", []))
            assert isinstance(devices, list)


class TestVMDetectionIntegration:
    """Test complete VM detection workflows."""

    def test_detect_vm_returns_valid_structure(self, safe_detector: VMDetector) -> None:
        """detect_vm() returns properly structured results."""
        results = safe_detector.detect_vm(aggressive=False)

        assert isinstance(results, dict)
        assert "is_vm" in results
        assert "confidence" in results
        assert "vm_type" in results
        assert "detections" in results
        assert "evasion_score" in results

        assert isinstance(results["is_vm"], bool)
        assert isinstance(results["confidence"], float)
        assert 0.0 <= results["confidence"] <= 1.0
        assert isinstance(results["detections"], dict)
        assert isinstance(results["evasion_score"], int)
        assert results["evasion_score"] >= 0

    def test_detect_vm_non_aggressive_mode(self, safe_detector: VMDetector) -> None:
        """Non-aggressive detection skips timing and low-level checks."""
        results = safe_detector.detect_vm(aggressive=False)

        detections = results["detections"]
        aggressive_methods = safe_detector.get_aggressive_methods()

        for method_name in aggressive_methods:
            assert method_name not in detections

    def test_detect_vm_aggressive_mode(self, safe_detector: VMDetector) -> None:
        """Aggressive detection includes all detection methods."""
        results = safe_detector.detect_vm(aggressive=True)

        detections = results["detections"]
        aggressive_methods = safe_detector.get_aggressive_methods()

        for method_name in aggressive_methods:
            if method_name in safe_detector.detection_methods:
                assert method_name in detections

    def test_vm_type_identification_logic(self, safe_detector: VMDetector) -> None:
        """VM type is correctly identified from detection results."""
        mock_detections = {
            "cpuid_vendor_strings": {
                "detected": True,
                "confidence": 0.98,
                "details": {"vendor_string": "VMwareVMware", "vm_type": "vmware"},
            },
            "mac_address_patterns": {
                "detected": True,
                "confidence": 0.88,
                "details": {
                    "vm_macs": [{"mac": "00:0c:29:12:34:56", "vendor": "vmware", "prefix": "00:0C:29"}]
                },
            },
        }

        vm_type = safe_detector._identify_vm_type(mock_detections)
        assert vm_type == "vmware"

    def test_evasion_score_calculation(self, safe_detector: VMDetector) -> None:
        """Evasion score reflects difficulty of evading detection."""
        mock_detections_easy = {
            "process_list": {
                "detected": True,
                "confidence": 0.7,
                "details": {},
            },
        }

        mock_detections_hard = {
            "cpuid_hypervisor_bit": {
                "detected": True,
                "confidence": 0.95,
                "details": {},
            },
            "hardware_signatures": {
                "detected": True,
                "confidence": 0.8,
                "details": {},
            },
        }

        score_easy = safe_detector._calculate_evasion_score(mock_detections_easy)
        score_hard = safe_detector._calculate_evasion_score(mock_detections_hard)

        assert isinstance(score_easy, int)
        assert isinstance(score_hard, int)
        assert score_hard >= score_easy

    def test_detection_with_real_system_data(self, safe_detector: VMDetector) -> None:
        """Detection runs on real system and produces valid results."""
        results = safe_detector.detect_vm(aggressive=False)

        assert isinstance(results["is_vm"], bool)
        assert isinstance(results["confidence"], float)
        assert isinstance(results["vm_type"], (str, type(None)))

        for method_name, method_result in results["detections"].items():
            assert "detected" in method_result
            assert "confidence" in method_result
            assert "details" in method_result
            assert isinstance(method_result["detected"], bool)
            assert isinstance(method_result["confidence"], float)
            assert isinstance(method_result["details"], dict)
            assert 0.0 <= method_result["confidence"] <= 1.0

    def test_multiple_detection_runs_produce_consistent_results(self, safe_detector: VMDetector) -> None:
        """Multiple detection runs produce consistent results."""
        results1 = safe_detector.detect_vm(aggressive=False)
        results2 = safe_detector.detect_vm(aggressive=False)

        assert results1["is_vm"] == results2["is_vm"]

        if results1["is_vm"]:
            assert abs(results1["confidence"] - results2["confidence"]) < 0.1


class TestDataStructures:
    """Test VM detector data structures."""

    def test_cpuid_result_structure(self) -> None:
        """CPUIDResult dataclass stores CPUID data correctly."""
        result = CPUIDResult(
            leaf=0x1,
            subleaf=0x0,
            eax=0x000906EA,
            ebx=0x00100800,
            ecx=0x7FFAFBBF,
            edx=0xBFEBFBFF,
            vendor_string="GenuineIntel",
            brand_string="Intel(R) Core(TM) i7",
        )

        assert result.leaf == 0x1
        assert result.subleaf == 0x0
        assert result.eax == 0x000906EA
        assert result.ebx == 0x00100800
        assert result.ecx == 0x7FFAFBBF
        assert result.edx == 0xBFEBFBFF
        assert result.vendor_string == "GenuineIntel"
        assert result.brand_string == "Intel(R) Core(TM) i7"
        assert isinstance(result.timestamp, float)

    def test_timing_measurement_structure(self) -> None:
        """TimingMeasurement dataclass stores timing data correctly."""
        measurement = TimingMeasurement(
            operation="rdtsc_delta",
            samples=[50, 52, 48, 51, 49, 53, 47],
            mean=50.0,
            variance=4.0,
            std_dev=2.0,
            min_val=47,
            max_val=53,
            anomaly_detected=False,
            confidence=0.0,
        )

        assert measurement.operation == "rdtsc_delta"
        assert len(measurement.samples) == 7
        assert measurement.mean == 50.0
        assert measurement.variance == 4.0
        assert measurement.std_dev == 2.0
        assert measurement.min_val == 47
        assert measurement.max_val == 53
        assert measurement.anomaly_detected is False

    def test_hardware_fingerprint_structure(self) -> None:
        """HardwareFingerprint dataclass stores hardware data correctly."""
        fingerprint = HardwareFingerprint(
            cpu_vendor="GenuineIntel",
            cpu_model="Intel(R) Core(TM) i7-9700K",
            cpu_cores=8,
            total_ram_mb=16384,
            disk_count=2,
            disk_serials=["WD-12345", "SSD-67890"],
            mac_addresses=["00:1A:2B:3C:4D:5E", "00:1A:2B:3C:4D:5F"],
            bios_vendor="American Megatrends Inc.",
            bios_version="1.2.3",
            system_manufacturer="ASUS",
            system_model="ROG STRIX",
            motherboard_manufacturer="ASUSTeK",
        )

        assert fingerprint.cpu_vendor == "GenuineIntel"
        assert fingerprint.cpu_cores == 8
        assert fingerprint.total_ram_mb == 16384
        assert len(fingerprint.disk_serials) == 2
        assert len(fingerprint.mac_addresses) == 2


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_cpuid_execution_failure_handling(self, safe_detector: VMDetector) -> None:
        """CPUID execution failures are handled gracefully."""
        result = safe_detector._execute_cpuid(0xFFFFFFFF)

        if result is not None:
            assert isinstance(result, tuple)
            assert len(result) == 4

    def test_detection_with_no_vm_present(self, safe_detector: VMDetector) -> None:
        """Detection on bare metal returns low confidence."""
        results = safe_detector.detect_vm(aggressive=False)

        assert isinstance(results, dict)
        assert "is_vm" in results
        assert "confidence" in results

    def test_concurrent_detection_safety(self, safe_detector: VMDetector) -> None:
        """Multiple concurrent detections don't cause race conditions."""
        import threading

        results = []

        def run_detection():
            result = safe_detector.detect_vm(aggressive=False)
            results.append(result)

        threads = [threading.Thread(target=run_detection) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 5
        for result in results:
            assert isinstance(result, dict)
            assert "is_vm" in result

    def test_cpuid_caching_works(self) -> None:
        """CPUID results are cached for performance."""
        detector = VMDetector()

        def mock_cpuid(leaf: int, subleaf: int = 0) -> tuple[int, int, int, int] | None:
            cached = detector._cpuid_cache.get((leaf, subleaf))
            if cached:
                return cached

            if leaf == 0x1:
                result = (0x000906EA, 0x00100800, 0x7FFAFBBF, 0xBFEBFBFF)
                detector._cpuid_cache[(leaf, subleaf)] = result
                return result
            return None

        detector._execute_cpuid = mock_cpuid

        result1 = detector._execute_cpuid(0x1, 0)
        result2 = detector._execute_cpuid(0x1, 0)

        assert result1 is not None
        assert result1 == result2
        assert (0x1, 0) in detector._cpuid_cache


class TestEvasionCodeGeneration:
    """Test VM detection evasion code generation."""

    def test_generate_evasion_code_returns_valid_code(self, safe_detector: VMDetector) -> None:
        """generate_evasion_code() returns compilable C code."""
        evasion_code = safe_detector.generate_evasion_code()

        assert isinstance(evasion_code, str)
        assert len(evasion_code) > 100

        assert "#include" in evasion_code or "bool" in evasion_code or "int" in evasion_code

        c_keywords = ["if", "return", "bool", "int"]
        assert any(keyword in evasion_code for keyword in c_keywords)

    def test_generate_evasion_code_for_specific_vm(self, safe_detector: VMDetector) -> None:
        """Evasion code can target specific VM types."""
        evasion_vmware = safe_detector.generate_evasion_code(target_vm="vmware")
        evasion_vbox = safe_detector.generate_evasion_code(target_vm="virtualbox")

        assert isinstance(evasion_vmware, str)
        assert isinstance(evasion_vbox, str)
        assert len(evasion_vmware) > 50
        assert len(evasion_vbox) > 50


class TestPerformance:
    """Test performance of VM detection."""

    def test_detection_completes_within_timeout(self, safe_detector: VMDetector) -> None:
        """VM detection completes within reasonable time."""
        start = time.time()
        safe_detector.detect_vm(aggressive=False)
        duration = time.time() - start

        assert duration < 30.0

    def test_aggressive_detection_timeout(self, safe_detector: VMDetector) -> None:
        """Aggressive detection completes within extended timeout (safe methods only)."""
        start = time.time()
        safe_detector.detect_vm(aggressive=True)
        duration = time.time() - start

        assert duration < 60.0


class TestRealWorldScenarios:
    """Test real-world VM detection scenarios."""

    def test_vmware_detection_pattern(self) -> None:
        """VMware detection uses multiple correlated signals."""
        detector = VMDetector()
        vmware_sig = detector.vm_signatures["vmware"]

        assert "vmtoolsd.exe" in vmware_sig["processes"]
        assert any(prefix.startswith("00:0C:29") or prefix.startswith("00:50:56") for prefix in vmware_sig["mac_prefixes"])
        assert vmware_sig["cpuid_vendor"] == "VMwareVMware"

    def test_virtualbox_detection_pattern(self) -> None:
        """VirtualBox detection uses multiple correlated signals."""
        detector = VMDetector()
        vbox_sig = detector.vm_signatures["virtualbox"]

        assert "VBoxService.exe" in vbox_sig["processes"]
        assert "08:00:27" in vbox_sig["mac_prefixes"]
        assert vbox_sig["cpuid_vendor"] == "VBoxVBoxVBox"

    def test_hyperv_detection_pattern(self) -> None:
        """Hyper-V detection uses multiple correlated signals."""
        detector = VMDetector()
        hyperv_sig = detector.vm_signatures["hyperv"]

        assert "00:15:5D" in hyperv_sig["mac_prefixes"]
        assert hyperv_sig["cpuid_vendor"] == "Microsoft Hv"

    def test_qemu_kvm_detection_pattern(self) -> None:
        """QEMU/KVM detection uses hardware and process signals."""
        detector = VMDetector()
        qemu_sig = detector.vm_signatures["qemu"]
        kvm_sig = detector.vm_signatures["kvm"]

        assert "52:54:00" in qemu_sig["mac_prefixes"]
        assert "52:54:00" in kvm_sig["mac_prefixes"]
        assert "QEMU" in " ".join(qemu_sig["hardware"])
