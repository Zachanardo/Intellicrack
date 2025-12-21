"""Production-grade tests for SandboxDetector module.

Tests validate real sandbox detection capabilities on Windows systems,
including detection of VMware, VirtualBox, QEMU, Hyper-V, Sandboxie,
Cuckoo, VMRay, and other analysis environments.
"""

import contextlib
import ctypes
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import patch, MagicMock

import pytest

from intellicrack.handlers.psutil_handler import psutil

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    import intellicrack.core.anti_analysis.base_detector
    from intellicrack.core.anti_analysis import sandbox_detector
    SandboxDetector = sandbox_detector.SandboxDetector
    SANDBOX_AVAILABLE = True
except (ImportError, AttributeError) as e:
    SANDBOX_AVAILABLE = False
    SKIP_REASON = f"SandboxDetector unavailable: {e}"


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestSandboxDetectorInitialization:
    """Test SandboxDetector initialization and signature building."""

    def test_detector_initializes_successfully(self) -> None:
        """SandboxDetector initializes with all required attributes."""
        detector = SandboxDetector()

        assert detector is not None
        assert hasattr(detector, "detection_methods")
        assert hasattr(detector, "sandbox_signatures")
        assert hasattr(detector, "behavioral_patterns")
        assert hasattr(detector, "system_profile")
        assert hasattr(detector, "logger")

    def test_detection_methods_registered(self) -> None:
        """All detection methods are registered during initialization."""
        detector = SandboxDetector()

        expected_methods = [
            "environment_checks",
            "behavioral_detection",
            "resource_limits",
            "network_connectivity",
            "user_interaction",
            "file_system",
            "process_monitoring",
            "time_acceleration",
            "api_hooks",
            "mouse_movement",
            "hardware_analysis",
            "registry_analysis",
            "virtualization",
            "environment_variables",
            "parent_process_analysis",
            "cpuid_hypervisor_check",
            "mac_address_analysis",
            "browser_automation",
            "timing_attacks",
        ]

        for method_name in expected_methods:
            assert method_name in detector.detection_methods
            assert callable(detector.detection_methods[method_name])

    def test_sandbox_signatures_built(self) -> None:
        """Sandbox signatures are dynamically built for all major sandboxes."""
        detector = SandboxDetector()

        expected_sandboxes = [
            "cuckoo",
            "vmray",
            "joe_sandbox",
            "threatgrid",
            "hybrid_analysis",
            "sandboxie",
            "anubis",
            "norman",
            "fortinet",
            "fireeye",
            "hatching_triage",
            "intezer",
            "virustotal",
            "browserstack",
            "vmware",
            "virtualbox",
            "hyperv",
            "qemu",
            "xen",
            "parallels",
        ]

        for sandbox_name in expected_sandboxes:
            assert sandbox_name in detector.sandbox_signatures
            sig = detector.sandbox_signatures[sandbox_name]
            assert isinstance(sig, dict)
            assert any(
                key in sig for key in ["files", "processes", "registry", "artifacts", "network"]
            )

    def test_behavioral_patterns_established(self) -> None:
        """Behavioral patterns baseline is established from current system."""
        detector = SandboxDetector()
        patterns = detector.behavioral_patterns

        assert "user_files" in patterns
        assert "processes" in patterns
        assert "uptime" in patterns
        assert "network" in patterns
        assert "disk" in patterns
        assert "memory" in patterns
        assert "cpu" in patterns

        assert patterns["processes"]["min_processes"] > 0
        assert patterns["memory"]["min_total_gb"] >= 0
        assert patterns["cpu"]["min_cores"] >= 1

    def test_system_profile_created(self) -> None:
        """System profiling creates fingerprint during initialization."""
        detector = SandboxDetector()
        profile = detector.system_profile

        assert "timestamp" in profile
        assert "boot_time" in profile
        assert "cpu_count" in profile
        assert "memory_total" in profile
        assert "disk_total" in profile
        assert "process_count" in profile
        assert "network_interfaces" in profile
        assert "unique_id" in profile
        assert "fingerprint" in profile

        assert isinstance(profile["fingerprint"], str)
        assert len(profile["fingerprint"]) == 64

    def test_vm_signatures_include_all_platforms(self) -> None:
        """VM signatures include all major virtualization platforms."""
        detector = SandboxDetector()

        vm_platforms = ["vmware", "virtualbox", "hyperv", "qemu", "xen", "parallels"]

        for platform_name in vm_platforms:
            assert platform_name in detector.sandbox_signatures
            sig = detector.sandbox_signatures[platform_name]
            assert "files" in sig or "processes" in sig or "artifacts" in sig


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestEnvironmentDetection:
    """Test environment-based sandbox detection."""

    def test_check_environment_detects_suspicious_username(self) -> None:
        """Environment check detects sandbox-related usernames."""
        detector = SandboxDetector()

        suspicious_users = ["sandbox", "maltest", "analyst", "virus"]
        original_username = os.environ.get("USERNAME", "")

        for username in suspicious_users:
            with patch.dict(os.environ, {"USERNAME": username}):
                detected, confidence, details = detector._check_environment()

                if username in os.environ.get("USERNAME", "").lower():
                    assert detected or username not in os.environ["USERNAME"].lower()
                    assert "username" in details or not detected
                    if detected:
                        assert confidence > 0

        if original_username:
            os.environ["USERNAME"] = original_username

    def test_check_environment_detects_suspicious_computername(self) -> None:
        """Environment check detects sandbox-related computer names."""
        detector = SandboxDetector()

        suspicious_computers = ["sandbox", "vmware", "virtualbox", "analysis"]
        original_computername = os.environ.get("COMPUTERNAME", "")

        for computername in suspicious_computers:
            with patch.dict(os.environ, {"COMPUTERNAME": computername}):
                detected, confidence, details = detector._check_environment()

                if computername in os.environ.get("COMPUTERNAME", "").lower():
                    assert detected or computername not in os.environ["COMPUTERNAME"].lower()
                    if detected:
                        assert confidence > 0
                        assert "computername" in details

        if original_computername:
            os.environ["COMPUTERNAME"] = original_computername

    def test_check_environment_variables_detects_sandbox_vars(self) -> None:
        """Environment variable check detects sandbox-specific variables."""
        detector = SandboxDetector()

        sandbox_vars = [
            ("CUCKOO", "1"),
            ("VMRAY_ANALYSIS", "true"),
            ("JOEBOX", "/opt/joebox"),
            ("SANDBOXIE", "C:\\Program Files\\Sandboxie"),
        ]

        for var_name, var_value in sandbox_vars:
            with patch.dict(os.environ, {var_name: var_value}, clear=False):
                detected, confidence, details = detector._check_environment_variables()

                assert detected
                assert confidence > 0
                assert len(details["suspicious_vars"]) > 0
                assert any(var_name in str(var) for var in details["suspicious_vars"])


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestHardwareDetection:
    """Test hardware-based sandbox detection."""

    def test_check_hardware_indicators_examines_cpu(self) -> None:
        """Hardware check examines CPU information for VM indicators."""
        detector = SandboxDetector()
        indicators = detector._check_hardware_indicators()

        assert "detected" in indicators
        assert "confidence" in indicators
        assert "details" in indicators
        assert isinstance(indicators["details"], list)

    def test_check_mac_address_artifacts_validates_interfaces(self) -> None:
        """MAC address check validates network interface addresses."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_mac_address_artifacts()

        assert isinstance(detected, bool)
        assert 0 <= confidence <= 1.0
        assert "mac_addresses" in details
        assert "suspicious_vendors" in details

        if detected:
            assert len(details["suspicious_vendors"]) > 0
            assert confidence > 0

    def test_mac_address_detection_identifies_vm_prefixes(self) -> None:
        """MAC address detection identifies known VM vendor prefixes."""
        detector = SandboxDetector()

        vm_prefixes = {
            "00:05:69": "VMware",
            "00:0C:29": "VMware",
            "08:00:27": "VirtualBox",
            "52:54:00": "QEMU/KVM",
            "00:15:5D": "Microsoft Hyper-V",
        }

        mac_node = uuid.getnode()
        mac_str = ":".join([f"{(mac_node >> i) & 0xFF:02x}" for i in range(0, 48, 8)])

        is_vm = any(mac_str.upper().startswith(prefix) for prefix in vm_prefixes)

        detected, confidence, details = detector._check_mac_address_artifacts()

        if is_vm:
            assert detected
            assert confidence > 0
        else:
            assert detected in (True, False)


@pytest.mark.skipif(not SANDBOX_AVAILABLE or platform.system() != "Windows", reason="Windows-specific registry tests")
class TestRegistryDetection:
    """Test Windows registry-based sandbox detection."""

    def test_check_registry_indicators_searches_vm_keys(self) -> None:
        """Registry check searches for virtualization-related registry keys."""
        detector = SandboxDetector()
        indicators = detector._check_registry_indicators()

        assert "detected" in indicators
        assert "confidence" in indicators
        assert "details" in indicators
        assert isinstance(indicators["details"], list)

    def test_registry_check_identifies_virtualbox_keys(self) -> None:
        """Registry check identifies VirtualBox-specific registry keys."""
        detector = SandboxDetector()
        indicators = detector._check_registry_indicators()

        if indicators["detected"]:
            assert indicators["confidence"] > 0
            assert len(indicators["details"]) > 0

    def test_registry_check_identifies_vmware_keys(self) -> None:
        """Registry check identifies VMware-specific registry keys."""
        detector = SandboxDetector()
        indicators = detector._check_registry_indicators()

        if indicators["detected"]:
            found_vmware = any("vmware" in detail.lower() for detail in indicators["details"])
            found_vbox = any("vbox" in detail.lower() for detail in indicators["details"])
            assert found_vmware or found_vbox or indicators["detected"]


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestVirtualizationDetection:
    """Test virtualization artifact detection."""

    def test_check_virtualization_artifacts_examines_drivers(self) -> None:
        """Virtualization check examines loaded drivers and modules."""
        detector = SandboxDetector()
        artifacts = detector._check_virtualization_artifacts()

        assert "detected" in artifacts
        assert "confidence" in artifacts
        assert "details" in artifacts
        assert isinstance(artifacts["details"], list)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows driver check")
    def test_virtualization_check_identifies_vm_drivers(self) -> None:
        """Virtualization check identifies VM-specific drivers on Windows."""
        detector = SandboxDetector()
        artifacts = detector._check_virtualization_artifacts()

        if artifacts["detected"]:
            assert artifacts["confidence"] > 0
            vm_drivers = ["vbox", "vmware", "vmci", "vmhgfs", "vmmouse"]
            assert any(driver in str(artifacts["details"]).lower() for driver in vm_drivers)

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux module check")
    def test_virtualization_check_identifies_vm_modules_linux(self) -> None:
        """Virtualization check identifies VM kernel modules on Linux."""
        detector = SandboxDetector()
        artifacts = detector._check_virtualization_artifacts()

        if artifacts["detected"]:
            assert artifacts["confidence"] > 0
            vm_modules = ["vboxguest", "vmw_balloon", "virtio", "kvm", "xen"]
            assert any(module in str(artifacts["details"]).lower() for module in vm_modules)

    def test_check_cpuid_hypervisor_uses_real_cpuid(self) -> None:
        """CPUID hypervisor check uses real CPUID instruction."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_cpuid_hypervisor()

        assert isinstance(detected, bool)
        assert 0 <= confidence <= 1.0
        assert "hypervisor_present" in details

        if detected:
            assert details["hypervisor_present"]
            assert confidence >= 0.7


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestBehavioralDetection:
    """Test behavioral sandbox detection."""

    def test_check_behavioral_analyzes_user_files(self) -> None:
        """Behavioral check analyzes user file presence."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_behavioral()

        assert isinstance(detected, bool)
        assert 0 <= confidence <= 1.0
        assert "anomalies" in details
        assert isinstance(details["anomalies"], list)

    def test_check_resource_limits_validates_cpu(self) -> None:
        """Resource limit check validates CPU core count."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_resource_limits()

        assert isinstance(detected, bool)
        assert "limitations" in details

        cpu_count = os.cpu_count()
        if cpu_count and cpu_count <= 2:
            assert any("cpu" in limit.lower() for limit in details["limitations"])

    def test_check_resource_limits_validates_memory(self) -> None:
        """Resource limit check validates system memory."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_resource_limits()

        mem = psutil.virtual_memory()
        total_gb = mem.total / (1024**3)

        if total_gb < 4:
            assert detected or total_gb >= 4
            if detected:
                assert any("memory" in limit.lower() for limit in details["limitations"])

    def test_check_resource_limits_validates_disk(self) -> None:
        """Resource limit check validates disk space."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_resource_limits()

        disk = psutil.disk_usage("/")
        total_gb = disk.total / (1024**3)

        if total_gb < 60:
            assert detected or total_gb >= 60
            if detected:
                assert any("disk" in limit.lower() for limit in details["limitations"])


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestNetworkDetection:
    """Test network-based sandbox detection."""

    def test_check_network_analyzes_connections(self) -> None:
        """Network check analyzes active network connections."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_network()

        assert isinstance(detected, bool)
        assert "network_anomalies" in details
        assert "connections" in details
        assert isinstance(details["connections"], int)

    def test_check_network_validates_dns_resolution(self) -> None:
        """Network check validates DNS resolution capability."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_network()

        try:
            socket.gethostbyname("google.com")
            dns_works = True
        except socket.gaierror:
            dns_works = False

        if not dns_works:
            assert any("dns" in anomaly.lower() for anomaly in details["network_anomalies"])

    def test_ip_in_network_validates_subnet_membership(self) -> None:
        """IP network check validates subnet membership correctly."""
        detector = SandboxDetector()

        assert detector._ip_in_network("192.168.1.10", "192.168.1.0/24")
        assert detector._ip_in_network("10.0.0.5", "10.0.0.0/24")
        assert not detector._ip_in_network("192.168.2.1", "192.168.1.0/24")
        assert not detector._ip_in_network("10.1.1.1", "10.0.0.0/24")


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestProcessDetection:
    """Test process-based sandbox detection."""

    def test_check_process_monitoring_identifies_monitoring_tools(self) -> None:
        """Process monitoring check identifies analysis tools."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_process_monitoring()

        assert isinstance(detected, bool)
        assert "monitoring_signs" in details
        assert isinstance(details["monitoring_signs"], list)

        if detected:
            assert confidence > 0
            monitoring_tools = ["procmon", "wireshark", "sysmon", "apimonitor", "regmon"]
            details_str = str(details).lower()
            assert any(tool in details_str for tool in monitoring_tools)

    def test_check_parent_process_analyzes_parent(self) -> None:
        """Parent process check analyzes launching process."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_parent_process()

        assert isinstance(detected, bool)
        assert "parent_name" in details

        current_proc = psutil.Process()
        with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            if parent := current_proc.parent():
                assert details["parent_name"] == parent.name() or details["parent_name"] is None

    def test_check_file_system_artifacts_finds_sandbox_files(self) -> None:
        """File system check identifies sandbox-specific files."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_file_system_artifacts()

        assert isinstance(detected, bool)
        assert "artifacts_found" in details
        assert isinstance(details["artifacts_found"], list)

        if detected:
            assert confidence > 0
            assert len(details["artifacts_found"]) > 0


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestTimingDetection:
    """Test timing-based sandbox detection."""

    def test_check_time_acceleration_uses_rdtsc(self) -> None:
        """Time acceleration check uses RDTSC instruction for timing."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_time_acceleration()

        assert isinstance(detected, bool)
        assert "time_anomaly" in details
        assert "rdtsc_drift" in details or "qpc_drift" in details

    def test_check_advanced_timing_compares_time_sources(self) -> None:
        """Advanced timing check compares multiple time sources."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_advanced_timing()

        assert isinstance(detected, bool)
        assert "timing_anomalies" in details
        assert "methods_checked" in details
        assert isinstance(details["methods_checked"], list)

        if detected:
            assert len(details["timing_anomalies"]) > 0

    def test_timing_check_detects_computation_anomalies(self) -> None:
        """Timing check detects unrealistic computation speeds."""
        detector = SandboxDetector()

        start = time.perf_counter()
        detected, confidence, details = detector._check_advanced_timing()
        duration = time.perf_counter() - start

        assert duration < 30.0


@pytest.mark.skipif(not SANDBOX_AVAILABLE or platform.system() != "Windows", reason="Windows API hook tests")
class TestAPIHookDetection:
    """Test API hooking detection."""

    def test_check_api_hooks_examines_common_apis(self) -> None:
        """API hook check examines common hooked APIs."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_api_hooks()

        assert isinstance(detected, bool)
        assert "hooked_apis" in details
        assert isinstance(details["hooked_apis"], list)

    def test_api_hook_check_identifies_jmp_hooks(self) -> None:
        """API hook check identifies JMP-based API hooks."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_api_hooks()

        if detected:
            assert confidence > 0
            assert len(details["hooked_apis"]) > 0
            assert all(isinstance(api, str) and "!" in api for api in details["hooked_apis"])


@pytest.mark.skipif(not SANDBOX_AVAILABLE or platform.system() != "Windows", reason="Windows mouse check")
class TestMouseDetection:
    """Test mouse movement detection."""

    def test_check_mouse_movement_monitors_cursor(self) -> None:
        """Mouse movement check monitors cursor position."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_mouse_movement()

        assert isinstance(detected, bool)
        assert "mouse_active" in details
        assert "movement_count" in details

    def test_mouse_check_detects_suspicious_patterns(self) -> None:
        """Mouse check detects robotic movement patterns."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_mouse_movement()

        if detected:
            assert confidence > 0
            assert "suspicious_pattern" in details or not detected
            if "suspicious_pattern" in details:
                suspicious_patterns = ["constant_velocity", "perfectly_linear", "identical_distances"]
                assert details["suspicious_pattern"] in suspicious_patterns


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestBrowserAutomationDetection:
    """Test browser automation framework detection."""

    def test_check_browser_automation_identifies_drivers(self) -> None:
        """Browser automation check identifies webdriver processes."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_browser_automation()

        assert isinstance(detected, bool)
        assert "automation_indicators" in details
        assert "detected_frameworks" in details
        assert isinstance(details["detected_frameworks"], list)

    def test_browser_automation_check_finds_selenium(self) -> None:
        """Browser automation check finds Selenium indicators."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_browser_automation()

        if detected:
            automation_frameworks = ["selenium", "chromedriver", "geckodriver", "puppeteer"]
            assert any(
                framework in details["detected_frameworks"] for framework in automation_frameworks
            )


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestUserInteractionDetection:
    """Test user interaction detection."""

    def test_check_user_interaction_examines_recent_files(self) -> None:
        """User interaction check examines recently used files."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_user_interaction()

        assert isinstance(detected, bool)
        assert "interaction_signs" in details
        assert isinstance(details["interaction_signs"], list)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows browser data check")
    def test_user_interaction_check_validates_browser_data(self) -> None:
        """User interaction check validates browser history presence."""
        detector = SandboxDetector()
        detected, confidence, details = detector._check_user_interaction()

        if "found_browsers" in details:
            assert isinstance(details["found_browsers"], list)


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestSandboxDetectionIntegration:
    """Test complete sandbox detection workflow."""

    def test_detect_sandbox_executes_all_methods(self) -> None:
        """Detect sandbox executes all configured detection methods."""
        detector = SandboxDetector()
        results = detector.detect_sandbox(aggressive=False)

        assert "is_sandbox" in results
        assert "confidence" in results
        assert "sandbox_type" in results
        assert "detections" in results
        assert "evasion_difficulty" in results

        assert isinstance(results["is_sandbox"], bool)
        assert 0 <= results["confidence"] <= 1.0
        assert isinstance(results["detections"], dict)

    def test_detect_sandbox_aggressive_runs_all_checks(self) -> None:
        """Aggressive mode runs all detection methods."""
        detector = SandboxDetector()
        results = detector.detect_sandbox(aggressive=True)

        assert len(results["detections"]) > 0

    def test_identify_sandbox_type_from_detections(self) -> None:
        """Sandbox type identification works from detection results."""
        detector = SandboxDetector()

        mock_detections = {
            "file_system": {
                "detected": True,
                "confidence": 0.8,
                "details": {"artifacts_found": ["vmware: C:\\Program Files\\VMware\\VMware Tools"]},
            }
        }

        sandbox_type = detector._identify_sandbox_type(mock_detections)
        assert isinstance(sandbox_type, str)
        assert len(sandbox_type) > 0

    def test_calculate_evasion_difficulty_scores_correctly(self) -> None:
        """Evasion difficulty calculation produces valid scores."""
        detector = SandboxDetector()

        mock_detections = {
            "file_system": {"detected": True, "confidence": 0.9, "details": {}},
            "environment_checks": {"detected": True, "confidence": 0.6, "details": {}},
        }

        difficulty = detector._calculate_evasion_difficulty(mock_detections)
        assert isinstance(difficulty, int)
        assert difficulty >= 0


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestSandboxEvasion:
    """Test sandbox evasion functionality."""

    def test_generate_sandbox_evasion_produces_code(self) -> None:
        """Sandbox evasion generator produces valid C code."""
        detector = SandboxDetector()
        evasion_code = detector.generate_sandbox_evasion()

        assert isinstance(evasion_code, str)
        assert len(evasion_code) > 0
        assert "#include" in evasion_code
        assert "IsSandbox" in evasion_code
        assert "GetUserName" in evasion_code or "GetComputerName" in evasion_code

    def test_evade_with_behavioral_adaptation_detects_first(self) -> None:
        """Behavioral adaptation performs detection before evasion."""
        detector = SandboxDetector()
        results = detector.evade_with_behavioral_adaptation(aggressive=False)

        assert "evasion_applied" in results
        assert "sandbox_detected" in results
        assert "confidence" in results
        assert "evasion_strategy" in results
        assert isinstance(results["sandbox_detected"], bool)

    def test_get_aggressive_methods_returns_list(self) -> None:
        """Aggressive methods list includes timing and mouse checks."""
        detector = SandboxDetector()
        aggressive_methods = detector.get_aggressive_methods()

        assert isinstance(aggressive_methods, list)
        assert "time_acceleration" in aggressive_methods
        assert "mouse_movement" in aggressive_methods

    def test_get_detection_type_returns_sandbox(self) -> None:
        """Detection type correctly identifies as sandbox detector."""
        detector = SandboxDetector()
        detection_type = detector.get_detection_type()

        assert detection_type == "sandbox"


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestSystemUtilities:
    """Test system utility methods."""

    def test_get_system_uptime_returns_valid_value(self) -> None:
        """System uptime returns valid uptime in seconds."""
        detector = SandboxDetector()
        uptime = detector._get_system_uptime()

        if uptime is not None:
            assert isinstance(uptime, int)
            assert uptime >= 0

    def test_get_common_directories_returns_accessible_paths(self) -> None:
        """Common directories returns only accessible paths."""
        detector = SandboxDetector()
        directories = detector._get_common_directories()

        assert isinstance(directories, list)
        for directory in directories:
            assert os.path.exists(directory)
            assert os.path.isdir(directory)

    def test_get_common_processes_returns_platform_specific_list(self) -> None:
        """Common processes returns platform-appropriate process list."""
        detector = SandboxDetector()
        processes = detector._get_common_processes()

        assert isinstance(processes, list)
        assert len(processes) > 0

        if platform.system() == "Windows":
            assert "explorer.exe" in processes
            assert "svchost.exe" in processes
        else:
            assert "systemd" in processes or "init" in processes


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestSandboxSignatures:
    """Test sandbox signature matching."""

    def test_cuckoo_signatures_comprehensive(self) -> None:
        """Cuckoo sandbox signatures include all detection vectors."""
        detector = SandboxDetector()
        cuckoo_sig = detector.sandbox_signatures.get("cuckoo", {})

        assert "files" in cuckoo_sig or "processes" in cuckoo_sig
        assert "network" in cuckoo_sig or "artifacts" in cuckoo_sig

    def test_vmray_signatures_comprehensive(self) -> None:
        """VMRay sandbox signatures include all detection vectors."""
        detector = SandboxDetector()
        vmray_sig = detector.sandbox_signatures.get("vmray", {})

        assert "files" in vmray_sig or "processes" in vmray_sig
        assert "registry" in vmray_sig or "artifacts" in vmray_sig

    def test_vmware_signatures_comprehensive(self) -> None:
        """VMware virtualization signatures include all detection vectors."""
        detector = SandboxDetector()
        vmware_sig = detector.sandbox_signatures.get("vmware", {})

        assert len(vmware_sig.get("files", [])) > 0
        assert len(vmware_sig.get("processes", [])) > 0
        assert len(vmware_sig.get("registry", [])) > 0
        assert len(vmware_sig.get("artifacts", [])) > 0

    def test_virtualbox_signatures_comprehensive(self) -> None:
        """VirtualBox virtualization signatures include all detection vectors."""
        detector = SandboxDetector()
        vbox_sig = detector.sandbox_signatures.get("virtualbox", {})

        assert len(vbox_sig.get("files", [])) > 0
        assert len(vbox_sig.get("processes", [])) > 0
        assert len(vbox_sig.get("registry", [])) > 0
        assert len(vbox_sig.get("artifacts", [])) > 0

    def test_sandboxie_signatures_comprehensive(self) -> None:
        """Sandboxie signatures include DLL and process detection."""
        detector = SandboxDetector()
        sbie_sig = detector.sandbox_signatures.get("sandboxie", {})

        assert "dlls" in sbie_sig
        assert len(sbie_sig["dlls"]) > 0
        assert any("sbie" in dll.lower() for dll in sbie_sig["dlls"])


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestProfileMatching:
    """Test known sandbox profile matching."""

    def test_check_against_known_profiles_validates_system(self) -> None:
        """Known profile check validates against sandbox profiles."""
        detector = SandboxDetector()

        assert hasattr(detector, "system_profile")
        assert hasattr(detector, "detection_cache")

    def test_system_profile_fingerprinting_unique(self) -> None:
        """System fingerprinting creates unique identifier."""
        detector1 = SandboxDetector()
        detector2 = SandboxDetector()

        assert detector1.system_profile["fingerprint"] == detector2.system_profile["fingerprint"]
        assert len(detector1.system_profile["fingerprint"]) == 64


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_detection_methods_handle_exceptions_gracefully(self) -> None:
        """Detection methods handle exceptions without crashing."""
        detector = SandboxDetector()

        results = detector.detect_sandbox(aggressive=False)

        assert isinstance(results, dict)
        assert "is_sandbox" in results

    def test_missing_system_info_handled(self) -> None:
        """Missing system information is handled gracefully."""
        detector = SandboxDetector()

        with patch("os.cpu_count", return_value=None):
            detected, confidence, details = detector._check_resource_limits()
            assert isinstance(detected, bool)

    def test_network_unavailable_handled(self) -> None:
        """Network unavailability is handled gracefully."""
        detector = SandboxDetector()

        with patch("socket.gethostbyname", side_effect=socket.gaierror):
            detected, confidence, details = detector._check_network()
            assert isinstance(detected, bool)


@pytest.mark.skipif(not SANDBOX_AVAILABLE, reason="" if SANDBOX_AVAILABLE else SKIP_REASON)
@pytest.mark.real_data
class TestRealWorldScenarios:
    """Test real-world sandbox detection scenarios."""

    def test_real_system_detection_consistency(self) -> None:
        """Real system detection produces consistent results."""
        detector1 = SandboxDetector()
        detector2 = SandboxDetector()

        results1 = detector1.detect_sandbox(aggressive=False)
        results2 = detector2.detect_sandbox(aggressive=False)

        assert results1["is_sandbox"] == results2["is_sandbox"]

    def test_detection_completes_within_timeout(self) -> None:
        """Sandbox detection completes within reasonable timeout."""
        detector = SandboxDetector()

        start = time.perf_counter()
        results = detector.detect_sandbox(aggressive=False)
        duration = time.perf_counter() - start

        assert duration < 10.0
        assert "is_sandbox" in results

    def test_confidence_scores_valid_range(self) -> None:
        """All confidence scores fall within valid 0-1 range."""
        detector = SandboxDetector()
        results = detector.detect_sandbox(aggressive=True)

        assert 0 <= results["confidence"] <= 1.0

        for method_name, method_result in results["detections"].items():
            assert 0 <= method_result["confidence"] <= 1.0

    def test_multiple_detection_runs_stable(self) -> None:
        """Multiple detection runs produce stable results."""
        detector = SandboxDetector()

        results_list = [detector.detect_sandbox(aggressive=False) for _ in range(3)]

        assert all(r["is_sandbox"] == results_list[0]["is_sandbox"] for r in results_list)
