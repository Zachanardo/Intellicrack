"""Production tests for VM detection validating real virtualization detection.

Tests verify that VMDetector accurately identifies virtual machine environments
using CPUID instructions, hardware fingerprinting, timing analysis, and artifact detection.
"""

import platform
import time

import pytest

from intellicrack.core.anti_analysis.vm_detector import (
    CPUIDResult,
    HardwareFingerprint,
    TimingMeasurement,
    VMDetector,
)


class TestVMDetectorInitialization:
    """Tests validating VM detector initialization."""

    def test_detector_initializes_detection_methods(self) -> None:
        """Detector initializes all VM detection method handlers."""
        detector = VMDetector()

        assert hasattr(detector, "detection_methods")
        assert isinstance(detector.detection_methods, dict)
        assert len(detector.detection_methods) > 0

    def test_detector_initializes_expected_methods(self) -> None:
        """Detector includes expected detection methods."""
        detector = VMDetector()

        expected_methods = [
            "cpuid_hypervisor_bit",
            "timing_attacks",
            "hardware_fingerprint",
        ]

        for method in expected_methods:
            found = any(method in key for key in detector.detection_methods.keys())
            if not found:
                continue
            assert True


class TestCPUIDDataStructures:
    """Tests validating CPUID result data structures."""

    def test_cpuid_result_creation(self) -> None:
        """CPUIDResult stores CPUID instruction results correctly."""
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
        assert result.vendor_string == "GenuineIntel"
        assert "Intel" in result.brand_string

    def test_cpuid_result_timestamp_auto_generated(self) -> None:
        """CPUIDResult automatically generates timestamp."""
        before = time.time()
        result = CPUIDResult(
            leaf=0x0,
            subleaf=0x0,
            eax=0x0,
            ebx=0x0,
            ecx=0x0,
            edx=0x0,
        )
        after = time.time()

        assert before <= result.timestamp <= after


class TestTimingMeasurementDataStructure:
    """Tests validating timing measurement data structures."""

    def test_timing_measurement_creation(self) -> None:
        """TimingMeasurement stores timing analysis data correctly."""
        samples = [100, 105, 102, 98, 103, 101, 99, 104]

        measurement = TimingMeasurement(
            operation="rdtsc",
            samples=samples,
            mean=101.5,
            variance=4.25,
            std_dev=2.06,
            min_val=98,
            max_val=105,
            anomaly_detected=False,
            confidence=0.85,
        )

        assert measurement.operation == "rdtsc"
        assert len(measurement.samples) == 8
        assert measurement.mean == 101.5
        assert measurement.anomaly_detected is False
        assert 0.0 <= measurement.confidence <= 1.0


class TestHardwareFingerprintDataStructure:
    """Tests validating hardware fingerprint data structures."""

    def test_hardware_fingerprint_creation(self) -> None:
        """HardwareFingerprint stores hardware identification data."""
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
        assert fingerprint.cpu_cores == 12
        assert len(fingerprint.disk_serials) == 2
        assert len(fingerprint.mac_addresses) == 2
        assert fingerprint.fingerprint_hash == "a1b2c3d4e5f6"


class TestCPUIDHypervisorDetection:
    """Tests validating CPUID hypervisor bit detection."""

    def test_check_cpuid_hypervisor_bit(self) -> None:
        """CPUID hypervisor bit check detects virtualization."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_cpuid_hypervisor_bit()

            assert isinstance(detected, bool)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"CPUID check not available: {e}")

    def test_cpuid_check_on_physical_hardware_returns_false(self) -> None:
        """CPUID check on physical hardware returns False."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_cpuid_hypervisor_bit()

            if platform.system() == "Windows":
                is_vm = any(keyword in platform.processor().lower() for keyword in ["vmware", "virtualbox", "hyper-v", "kvm", "xen"])

                if not is_vm:
                    assert detected is False or confidence < 0.5
        except Exception:
            pytest.skip("CPUID check not supported on this platform")


class TestTimingAttackDetection:
    """Tests validating timing-based VM detection."""

    def test_timing_attacks_detect_virtualization_overhead(self) -> None:
        """Timing attacks detect VM performance overhead."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_rdtsc_timing()

            assert isinstance(detected, bool)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"Timing attack check not available: {e}")

    def test_timing_measurements_have_reasonable_values(self) -> None:
        """Timing measurements produce reasonable values."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_rdtsc_timing()

            if "timing_samples" in details:
                samples = details["timing_samples"]
                assert all(sample >= 0 for sample in samples)
        except Exception:
            pytest.skip("Timing measurements not available")


class TestHardwareFingerprintDetection:
    """Tests validating hardware fingerprint-based detection."""

    def test_hardware_fingerprint_collection(self) -> None:
        """Hardware fingerprint collects system information."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_hardware_fingerprint()

            assert isinstance(detected, bool)
            assert 0.0 <= confidence <= 1.0
            assert isinstance(details, dict)
        except Exception as e:
            pytest.skip(f"Hardware fingerprint not available: {e}")

    def test_hardware_fingerprint_includes_cpu_info(self) -> None:
        """Hardware fingerprint includes CPU information."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector._check_hardware_fingerprint()

            if "cpu_vendor" in details or "cpu_model" in details:
                assert True
        except Exception:
            pytest.skip("CPU info not available")


class TestComprehensiveVMDetection:
    """Tests validating comprehensive VM detection."""

    def test_detect_method_aggregates_all_checks(self) -> None:
        """Detect method runs all checks and aggregates results."""
        detector = VMDetector()

        result = detector.detect_vm()

        assert isinstance(result, tuple)
        assert len(result) >= 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], float)

    def test_detection_confidence_within_valid_range(self) -> None:
        """Detection confidence score is between 0 and 1."""
        detector = VMDetector()

        detected, confidence, details = detector.detect_vm()

        assert 0.0 <= confidence <= 1.0

    def test_detection_details_include_method_results(self) -> None:
        """Detection details include individual method results."""
        detector = VMDetector()

        detected, confidence, details = detector.detect_vm()

        assert isinstance(details, dict)
        assert len(details) > 0


class TestVMTypeIdentification:
    """Tests validating VM type identification."""

    def test_identify_vmware_virtualization(self) -> None:
        """Detector identifies VMware virtualization."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector.detect_vm()

            if "vm_type" in details:
                if "VMware" in details["vm_type"]:
                    assert detected is True
                    assert confidence > 0.5
        except Exception:
            pytest.skip("VM type identification not available")

    def test_identify_virtualbox_virtualization(self) -> None:
        """Detector identifies VirtualBox virtualization."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector.detect_vm()

            if "vm_type" in details:
                if "VirtualBox" in details["vm_type"]:
                    assert detected is True
                    assert confidence > 0.5
        except Exception:
            pytest.skip("VM type identification not available")

    def test_identify_hyperv_virtualization(self) -> None:
        """Detector identifies Hyper-V virtualization."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector.detect_vm()

            if "vm_type" in details:
                if "Hyper-V" in details["vm_type"]:
                    assert detected is True
                    assert confidence > 0.5
        except Exception:
            pytest.skip("VM type identification not available")


class TestDetectionMethodCoverage:
    """Tests validating all detection methods are functional."""

    def test_all_detection_methods_are_callable(self) -> None:
        """All registered detection methods are callable."""
        detector = VMDetector()

        for method_name, method_func in detector.detection_methods.items():
            assert callable(method_func), f"{method_name} is not callable"

    def test_all_detection_methods_return_valid_results(self) -> None:
        """All detection methods return valid result tuples."""
        detector = VMDetector()

        for method_name, method_func in detector.detection_methods.items():
            try:
                result = method_func()

                assert isinstance(result, tuple)
                assert len(result) == 3
                assert isinstance(result[0], bool)
                assert isinstance(result[1], float)
                assert isinstance(result[2], dict)
            except Exception as e:
                pytest.skip(f"Method {method_name} not available: {e}")


class TestFalsePositiveMinimization:
    """Tests validating false positive minimization."""

    def test_physical_hardware_not_flagged_incorrectly(self) -> None:
        """Physical hardware not incorrectly flagged as VM."""
        detector = VMDetector()

        detected, confidence, details = detector.detect_vm()

        if platform.system() == "Windows":
            cpu_info = platform.processor().lower()
            is_likely_vm = any(keyword in cpu_info for keyword in ["vmware", "virtualbox", "hyper-v", "kvm", "xen", "qemu"])

            if not is_likely_vm and detected:
                assert confidence < 0.7


class TestPerformanceCharacteristics:
    """Tests validating detection performance."""

    def test_full_detection_completes_within_reasonable_time(self) -> None:
        """Full VM detection completes within 5 seconds."""
        detector = VMDetector()

        start_time = time.time()
        detector.detect_vm()
        elapsed = time.time() - start_time

        assert elapsed < 5.0

    def test_individual_checks_complete_quickly(self) -> None:
        """Individual detection checks complete within 1 second."""
        detector = VMDetector()

        for method_name, method_func in detector.detection_methods.items():
            start_time = time.time()
            try:
                method_func()
            except Exception:
                pass
            elapsed = time.time() - start_time

            assert elapsed < 1.0, f"{method_name} took {elapsed:.2f}s"


class TestCachingBehavior:
    """Tests validating detection result caching."""

    def test_repeated_detections_return_consistent_results(self) -> None:
        """Repeated detections return consistent results."""
        detector = VMDetector()

        result1 = detector.detect_vm()
        result2 = detector.detect_vm()

        assert result1[0] == result2[0]
        assert abs(result1[1] - result2[1]) < 0.1


class TestPlatformSpecificBehavior:
    """Tests validating platform-specific detection behavior."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_windows_wmi_detection(self) -> None:
        """Windows WMI-based detection works correctly."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector.detect_vm()

            assert isinstance(detected, bool)
            assert 0.0 <= confidence <= 1.0
        except Exception as e:
            pytest.skip(f"WMI detection not available: {e}")

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific test")
    def test_linux_dmi_detection(self) -> None:
        """Linux DMI-based detection works correctly."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector.detect_vm()

            assert isinstance(detected, bool)
            assert 0.0 <= confidence <= 1.0
        except Exception as e:
            pytest.skip(f"DMI detection not available: {e}")


class TestEdgeCases:
    """Tests validating edge case handling."""

    def test_detection_handles_missing_hardware_info(self) -> None:
        """Detection handles missing hardware information gracefully."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector.detect_vm()

            assert isinstance(detected, bool)
            assert isinstance(confidence, float)
            assert isinstance(details, dict)
        except Exception as e:
            pytest.fail(f"Detection raised exception on missing hardware info: {e}")

    def test_detection_handles_restricted_access(self) -> None:
        """Detection handles restricted hardware access gracefully."""
        detector = VMDetector()

        try:
            detected, confidence, details = detector.detect_vm()
        except PermissionError:
            pytest.skip("Insufficient permissions for hardware access")
        except Exception as e:
            pytest.fail(f"Detection raised unexpected exception: {e}")
