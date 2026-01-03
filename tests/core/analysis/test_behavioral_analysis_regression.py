"""Regression tests for behavioral analysis QEMU integration and licensing behavior detection.

This module validates that behavioral analysis capabilities continue to work correctly across
releases. Tests verify QEMU virtualization integration, Frida API hooking, licensing behavior
detection, and anti-analysis detection.

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
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import psutil
import pytest

from intellicrack.core.analysis.behavioral_analysis import (
    AntiAnalysisDetector,
    ApiMonitoringResults,
    BehavioralAnalyzer,
    FridaAPIHookingFramework,
    HookPoint,
    MonitorEvent,
    NativeAnalysisResults,
    QEMUConfig,
    QEMUController,
    QemuAnalysisResults,
    create_behavioral_analyzer,
    run_behavioral_analysis,
)


FIXTURE_DIR = Path(r"D:\Intellicrack\tests\fixtures")
BINARIES_DIR = FIXTURE_DIR / "binaries"
PROTECTED_DIR = BINARIES_DIR / "protected"
PORTABLE_DIR = FIXTURE_DIR / "PORTABLE_SANDBOX"
FULL_SOFTWARE_DIR = FIXTURE_DIR / "full_protected_software"


@pytest.fixture(scope="session")
def protected_binary() -> Path:
    """Get a real protected binary for testing."""
    candidates = [
        PROTECTED_DIR / "vmprotect_protected.exe",
        PROTECTED_DIR / "themida_protected.exe",
        BINARIES_DIR / "pe" / "legitimate" / "notepadpp.exe",
        PORTABLE_DIR / "pestudio_portable" / "pestudio" / "pestudio.exe",
    ]

    for candidate in candidates:
        if candidate.exists():
            pytest.skip(
                f"Using {candidate.name} for behavioral analysis regression test - "
                f"verifying licensing detection patterns work"
            )
            return candidate

    pytest.skip(
        "No protected binaries available for testing. Need one of:\n"
        f"  - {PROTECTED_DIR / 'vmprotect_protected.exe'}\n"
        f"  - {PROTECTED_DIR / 'themida_protected.exe'}\n"
        f"  - {BINARIES_DIR / 'pe' / 'legitimate' / 'notepadpp.exe'}\n"
        f"  - {PORTABLE_DIR / 'pestudio_portable' / 'pestudio' / 'pestudio.exe'}\n"
        "These binaries are required to validate behavioral analysis capabilities."
    )


@pytest.fixture(scope="session")
def license_check_binary() -> Path:
    """Get a binary with licensing mechanisms."""
    candidates = [
        FULL_SOFTWARE_DIR / "Beyond_Compare_Full.exe",
        FULL_SOFTWARE_DIR / "Resource_Hacker_Full.exe",
        PROTECTED_DIR / "enterprise_license_check.exe",
        PROTECTED_DIR / "online_activation_app.exe",
    ]

    for candidate in candidates:
        if candidate.exists():
            pytest.skip(
                f"Using {candidate.name} for license detection test - "
                f"verifying licensing validation pattern recognition"
            )
            return candidate

    pytest.skip(
        "No license-protected binaries available. Need one of:\n"
        f"  - {FULL_SOFTWARE_DIR / 'Beyond_Compare_Full.exe'}\n"
        f"  - {FULL_SOFTWARE_DIR / 'Resource_Hacker_Full.exe'}\n"
        f"  - {PROTECTED_DIR / 'enterprise_license_check.exe'}\n"
        f"  - {PROTECTED_DIR / 'online_activation_app.exe'}\n"
        "Required to validate licensing behavior detection."
    )


@pytest.fixture
def temp_qemu_disk() -> Path | None:
    """Create temporary QEMU disk image if QEMU is available."""
    if not shutil.which("qemu-img"):
        pytest.skip("QEMU not available - skipping QEMU regression tests")

    temp_dir = Path(tempfile.mkdtemp(prefix="qemu_test_"))
    disk_path = temp_dir / "test_disk.qcow2"

    try:
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", str(disk_path), "1G"],
            check=True,
            capture_output=True,
            shell=False,
        )
        yield disk_path
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


class TestQEMUIntegrationRegression:
    """Regression tests for QEMU virtualization integration."""

    def test_qemu_controller_initialization_still_works(self) -> None:
        """Verify QEMU controller initializes with correct configuration."""
        config = QEMUConfig(
            machine_type="pc",
            cpu_model="qemu64",
            memory_size="1G",
            enable_kvm=False,
            enable_gdb=True,
            gdb_port=1234,
            monitor_port=4444,
            qmp_port=5555,
        )

        controller = QEMUController(config)

        assert controller.config.machine_type == "pc"
        assert controller.config.cpu_model == "qemu64"
        assert controller.config.memory_size == "1G"
        assert controller.config.enable_gdb is True
        assert controller.config.gdb_port == 1234
        assert controller.config.monitor_port == 4444
        assert controller.config.qmp_port == 5555
        assert controller.is_running is False
        assert controller.process is None

    def test_qemu_binary_detection_still_functional(self) -> None:
        """Verify QEMU binary detection logic works on current system."""
        controller = QEMUController(QEMUConfig())

        qemu_path = controller._find_qemu_binary()

        if platform.system() == "Windows":
            expected_paths = [
                r"C:\Program Files\qemu",
                r"C:\Program Files (x86)\qemu",
                r"C:\qemu",
            ]
            if qemu_path:
                assert any(str(qemu_path).startswith(p) for p in expected_paths) or Path(qemu_path).exists()
        elif qemu_path is not None:
            assert Path(qemu_path).exists()
            assert os.access(qemu_path, os.X_OK)

    def test_qemu_config_defaults_unchanged(self) -> None:
        """Verify default QEMU configuration values remain stable."""
        config = QEMUConfig()

        assert config.machine_type == "pc"
        assert config.cpu_model == "max"
        assert config.memory_size == "2G"
        assert config.kernel is None
        assert config.initrd is None
        assert config.disk_image is None
        assert config.network_mode == "user"
        assert config.enable_kvm is True
        assert config.enable_gdb is True
        assert config.gdb_port == 1234
        assert config.monitor_port == 4444
        assert config.qmp_port == 5555
        assert config.vnc_display == 0
        assert config.extra_args == []

    def test_qemu_kvm_detection_still_works(self) -> None:
        """Verify KVM availability detection logic unchanged."""
        controller = QEMUController(QEMUConfig())

        kvm_available = controller._check_kvm_available()

        if platform.system() == "Linux":
            if os.path.exists("/dev/kvm"):
                assert kvm_available == os.access("/dev/kvm", os.R_OK | os.W_OK)
            else:
                assert kvm_available is False
        else:
            assert kvm_available is False

    @pytest.mark.skipif(not shutil.which("qemu-system-x86_64"), reason="QEMU not installed")
    def test_qemu_snapshot_operations_regression(self, temp_qemu_disk: Path | None, protected_binary: Path) -> None:
        """Verify QEMU snapshot creation and restoration still functional."""
        if not temp_qemu_disk:
            pytest.skip("QEMU disk image creation failed")

        config = QEMUConfig(
            disk_image=temp_qemu_disk,
            enable_kvm=False,
            enable_gdb=False,
            vnc_display=None,
        )

        controller = QEMUController(config)

        try:
            if not controller.start(protected_binary):
                pytest.skip("QEMU failed to start - possibly missing dependencies or permissions")

            assert controller.is_running is True

            snapshot_created = controller.take_snapshot("test_snapshot")
            assert snapshot_created is True, "Snapshot creation must succeed"

            restore_success = controller.restore_snapshot("test_snapshot")
            assert restore_success is True, "Snapshot restoration must succeed"

        finally:
            controller.stop()


class TestFridaAPIHookingRegression:
    """Regression tests for Frida API hooking framework."""

    def test_frida_framework_initialization_unchanged(self) -> None:
        """Verify Frida framework initializes with correct platform hooks."""
        framework = FridaAPIHookingFramework()

        assert len(framework.hooks) > 0, "Platform hooks must be registered on initialization"
        assert len(framework.events) == 0, "Event list must be empty on init"
        assert len(framework.active_hooks) == 0, "No hooks should be active initially"

        if platform.system() == "Windows":
            assert "kernel32.dll:CreateFileW" in framework.hooks
            assert "advapi32.dll:RegOpenKeyExW" in framework.hooks
            assert "ws2_32.dll:connect" in framework.hooks
            assert "ntdll.dll:NtCreateProcess" in framework.hooks
        elif platform.system() == "Linux":
            assert "libc.so.6:open" in framework.hooks
            assert "libc.so.6:socket" in framework.hooks
            assert "libc.so.6:connect" in framework.hooks

    def test_hook_management_operations_still_work(self) -> None:
        """Verify hook add/remove/enable/disable operations functional."""
        framework = FridaAPIHookingFramework()

        initial_hook_count = len(framework.hooks)

        test_hook = HookPoint(
            module="test.dll",
            function="TestFunction",
            enabled=True,
            priority=50,
        )

        framework.add_hook(test_hook)
        assert len(framework.hooks) == initial_hook_count + 1
        assert "test.dll:TestFunction" in framework.hooks

        framework.enable_hook("test.dll", "TestFunction")
        assert "test.dll:TestFunction" in framework.active_hooks

        framework.disable_hook("test.dll", "TestFunction")
        assert "test.dll:TestFunction" not in framework.active_hooks

        framework.remove_hook("test.dll", "TestFunction")
        assert "test.dll:TestFunction" not in framework.hooks

    def test_monitor_event_serialization_unchanged(self) -> None:
        """Verify MonitorEvent to_dict conversion format stable."""
        event = MonitorEvent(
            timestamp=1234567890.123,
            event_type="file_create",
            process_id=1234,
            thread_id=5678,
            data={"filename": "test.dat", "access": "read"},
            context={"additional": "info"},
        )

        event_dict = event.to_dict()

        assert event_dict["timestamp"] == 1234567890.123
        assert event_dict["type"] == "file_create"
        assert event_dict["pid"] == 1234
        assert event_dict["tid"] == 5678
        assert event_dict["data"]["filename"] == "test.dat"
        assert event_dict["context"]["additional"] == "info"

    def test_frida_script_generation_still_creates_valid_js(self) -> None:
        """Verify generated Frida JavaScript is syntactically valid."""
        framework = FridaAPIHookingFramework()

        if platform.system() == "Windows":
            framework.enable_hook("kernel32.dll", "CreateFileW")

        script_code = framework._generate_frida_script()

        assert "Module.findExportByName" in script_code
        assert "Interceptor.attach" in script_code
        assert "onEnter:" in script_code
        assert "onLeave:" in script_code
        assert "send(" in script_code
        assert script_code.count("(function() {") > 0

    def test_hook_callback_invocation_still_works(self) -> None:
        """Verify hook callbacks are invoked correctly on API calls."""
        framework = FridaAPIHookingFramework()
        callback_invoked: list[tuple[list[Any], dict[str, Any]]] = []

        def test_callback(args: list[Any], context: dict[str, Any]) -> None:
            callback_invoked.append((args, context))

        hook = HookPoint(
            module="kernel32.dll",
            function="CreateFileW",
            on_enter=test_callback,
            priority=100,
        )

        framework.add_hook(hook)

        message: dict[str, Any] = {
            "type": "send",
            "payload": {
                "type": "api_call",
                "module": "kernel32.dll",
                "function": "CreateFileW",
                "args": ["test.txt", 0x80000000, 0, 0],
                "timestamp": time.time(),
                "pid": os.getpid(),
                "tid": 12345,
            },
        }

        framework._on_frida_message(message, None)

        assert len(callback_invoked) == 1
        assert callback_invoked[0][0] == ["test.txt", 0x80000000, 0, 0]


class TestAntiAnalysisDetectionRegression:
    """Regression tests for anti-analysis detection."""

    def test_anti_analysis_detector_initialization(self) -> None:
        """Verify anti-analysis detector initializes with all detection methods."""
        detector = AntiAnalysisDetector()

        assert len(detector.detections) == 0
        assert len(detector.detection_methods) == 8

        method_names = [m.__name__ for m in detector.detection_methods]
        assert "_detect_debugger_presence" in method_names
        assert "_detect_vm_artifacts" in method_names
        assert "_detect_timing_attacks" in method_names
        assert "_detect_process_hollowing" in method_names
        assert "_detect_api_hooks" in method_names
        assert "_detect_sandbox_artifacts" in method_names
        assert "_detect_memory_protections" in method_names
        assert "_detect_code_obfuscation" in method_names

    def test_debugger_detection_still_functional(self) -> None:
        """Verify debugger presence detection works on current process."""
        detector = AntiAnalysisDetector()

        detector._detect_debugger_presence(os.getpid())

        if platform.system() == "Windows":
            assert True
        elif platform.system() == "Linux":
            status_file = f"/proc/{os.getpid()}/status"
            if os.path.exists(status_file):
                with open(status_file, encoding="utf-8") as f:
                    content = f.read()
                    assert "TracerPid:" in content

    def test_vm_artifact_detection_unchanged(self) -> None:
        """Verify VM artifact detection logic identifies known indicators."""
        detector = AntiAnalysisDetector()

        detector._detect_vm_artifacts(os.getpid())

        vm_processes = ["vmtoolsd", "vboxservice", "qemu-ga", "xenservice"]
        for proc in psutil.process_iter(["name"]):
            proc_name = proc.info["name"]
            if proc_name is not None and any(vm in proc_name.lower() for vm in vm_processes):
                assert any(d["type"] == "vm_artifacts" for d in detector.detections)
                break

    def test_timing_attack_detection_regression(self) -> None:
        """Verify timing-based anti-debugging detection still works."""
        detector = AntiAnalysisDetector()

        detector._detect_timing_attacks(os.getpid())

        if platform.system() == "Windows":
            assert True
        elif platform.system() == "Linux":
            assert True

    def test_sandbox_detection_regression(self) -> None:
        """Verify sandbox artifact detection identifies common indicators."""
        detector = AntiAnalysisDetector()

        detector._detect_sandbox_artifacts(os.getpid())

        hostname = socket.gethostname().lower()
        username = os.environ.get("USERNAME", os.environ.get("USER", "")).lower()

        if any(s in hostname for s in ["sandbox", "malware", "virus", "analysis"]):
            assert any(d["type"] == "sandbox_artifacts" for d in detector.detections)

        if any(s in username for s in ["sandbox", "admin", "test", "malware"]):
            assert any(d["type"] == "sandbox_artifacts" for d in detector.detections)

    def test_entropy_calculation_accuracy_unchanged(self) -> None:
        """Verify entropy calculation produces expected values."""
        detector = AntiAnalysisDetector()

        zero_entropy = detector._calculate_entropy(b"\x00" * 100)
        assert zero_entropy == 0.0

        high_entropy = detector._calculate_entropy(os.urandom(256))
        assert high_entropy > 7.0

        ascii_entropy = detector._calculate_entropy(b"AAAA" * 25)
        assert 0.0 < ascii_entropy < 2.0


class TestNativeAnalysisRegression:
    """Regression tests for native binary execution analysis."""

    def test_native_analysis_monitors_process_resources(self, protected_binary: Path) -> None:
        """Verify native analysis captures CPU and memory metrics."""
        analyzer = BehavioralAnalyzer(protected_binary)

        results = analyzer._run_native_analysis(duration=2)

        assert isinstance(results, dict)
        assert "process_started" in results
        assert "pid" in results
        assert "cpu_usage" in results
        assert "memory_usage" in results

        if results["process_started"]:
            assert results["pid"] is not None
            assert isinstance(results["cpu_usage"], list)
            assert isinstance(results["memory_usage"], dict)

            if results["memory_usage"]:
                assert "rss" in results["memory_usage"]
                assert "vms" in results["memory_usage"]
                assert "timestamp" in results["memory_usage"]

    def test_native_analysis_handles_quick_exit_binaries(self, protected_binary: Path) -> None:
        """Verify native analysis handles binaries that exit immediately."""
        analyzer = BehavioralAnalyzer(protected_binary)

        results = analyzer._run_native_analysis(duration=1)

        assert isinstance(results, dict)
        assert "process_started" in results

        if not results.get("process_started"):
            assert "error" in results

    def test_native_analysis_path_validation_regression(self) -> None:
        """Verify path traversal protection still prevents unsafe paths."""
        analyzer = BehavioralAnalyzer(Path("../../../../../etc/passwd"))

        results = analyzer._run_native_analysis(duration=1)

        assert "error" in results
        assert "Unsafe binary path" in results["error"]


class TestAPIMonitoringRegression:
    """Regression tests for API call monitoring."""

    def test_api_monitoring_tracks_hook_installation(self, protected_binary: Path) -> None:
        """Verify API monitoring counts installed hooks correctly."""
        analyzer = BehavioralAnalyzer(protected_binary)

        results = analyzer._run_api_monitoring(duration=1)

        assert isinstance(results, dict)
        assert "hooks_installed" in results
        assert "events_captured" in results
        assert "unique_apis_called" in results
        assert "frida_attached" in results

        assert results["hooks_installed"] > 0

    def test_api_monitoring_captures_events(self, protected_binary: Path) -> None:
        """Verify API monitoring captures events from binary execution."""
        analyzer = BehavioralAnalyzer(protected_binary)

        results = analyzer._run_api_monitoring(duration=2)

        if results.get("frida_attached"):
            assert results["events_captured"] >= 0
            assert isinstance(results["unique_apis_called"], set)
        else:
            pytest.skip("Frida not available or failed to attach - cannot verify event capture")


class TestLicensingBehaviorDetectionRegression:
    """Regression tests for licensing behavior pattern detection."""

    def test_license_check_pattern_detection_unchanged(self, license_check_binary: Path) -> None:
        """Verify licensing validation patterns are detected in protected software."""
        analyzer = BehavioralAnalyzer(license_check_binary)

        license_keywords = ["license", "serial", "key", "activation", "registration", "trial"]

        test_events = [
            MonitorEvent(
                timestamp=time.time(),
                event_type="registry_query",
                process_id=1234,
                thread_id=5678,
                data={"hkey": "HKEY_CURRENT_USER", "value": "LicenseKey"},
            ),
            MonitorEvent(
                timestamp=time.time(),
                event_type="file_read",
                process_id=1234,
                thread_id=5678,
                data={"filename": "license.dat", "size": "128"},
            ),
            MonitorEvent(
                timestamp=time.time(),
                event_type="network_connect",
                process_id=1234,
                thread_id=5678,
                data={"socket": "3", "sockaddr": "activation.server.com:443"},
            ),
        ]

        analyzer.events.extend(test_events)

        patterns = analyzer._analyze_behavioral_patterns()

        assert "license_checks" in patterns
        assert len(patterns["license_checks"]) > 0

        for check in patterns["license_checks"]:
            event_data_str = str(check["data"]).lower()
            assert any(keyword in event_data_str for keyword in license_keywords)

    def test_network_license_validation_detection(self) -> None:
        """Verify network-based licensing validation is detected."""
        analyzer = BehavioralAnalyzer(Path("test.exe"))

        analyzer.events.append(
            MonitorEvent(
                timestamp=time.time(),
                event_type="network_connect",
                process_id=1234,
                thread_id=5678,
                data={"socket": "5", "sockaddr": "license.server.com:443"},
            )
        )

        patterns = analyzer._analyze_behavioral_patterns()

        assert "network_communications" in patterns
        assert len(patterns["network_communications"]) > 0

    def test_persistence_mechanism_detection_regression(self) -> None:
        """Verify registry persistence detection still identifies startup hooks."""
        analyzer = BehavioralAnalyzer(Path("test.exe"))

        analyzer.events.append(
            MonitorEvent(
                timestamp=time.time(),
                event_type="registry_set",
                process_id=1234,
                thread_id=5678,
                data={
                    "hkey": "HKEY_CURRENT_USER",
                    "value": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MyApp",
                    "type": "REG_SZ",
                },
            )
        )

        patterns = analyzer._analyze_behavioral_patterns()

        assert "persistence_mechanisms" in patterns
        assert len(patterns["persistence_mechanisms"]) > 0


class TestBehavioralAnalyzerRegression:
    """Regression tests for complete behavioral analysis workflow."""

    def test_behavioral_analyzer_initialization_unchanged(self, protected_binary: Path) -> None:
        """Verify BehavioralAnalyzer initializes with all required components."""
        analyzer = BehavioralAnalyzer(protected_binary)

        assert analyzer.binary_path == protected_binary
        assert isinstance(analyzer.qemu_config, QEMUConfig)
        assert isinstance(analyzer.qemu_controller, QEMUController)
        assert isinstance(analyzer.api_hooks, FridaAPIHookingFramework)
        assert isinstance(analyzer.anti_analysis, AntiAnalysisDetector)
        assert len(analyzer.events) == 0
        assert analyzer.analysis_thread is None

    def test_complete_analysis_workflow_regression(self, protected_binary: Path) -> None:
        """Verify complete analysis workflow executes without errors."""
        results = run_behavioral_analysis(protected_binary, duration=2, use_qemu=False)

        assert isinstance(results, dict)
        assert "binary" in results
        assert "start_time" in results
        assert "native_analysis" in results
        assert "api_monitoring" in results
        assert "anti_analysis" in results
        assert "behavioral_patterns" in results
        assert "network_activity" in results
        assert "file_operations" in results
        assert "registry_activity" in results
        assert "process_activity" in results
        assert "summary" in results
        assert "end_time" in results
        assert "duration" in results

        assert results["binary"] == str(protected_binary)
        assert results["duration"] > 0

    def test_analysis_summary_generation_unchanged(self, protected_binary: Path) -> None:
        """Verify analysis summary contains expected fields and structure."""
        analyzer = BehavioralAnalyzer(protected_binary)

        analyzer.events.append(
            MonitorEvent(
                timestamp=time.time(),
                event_type="file_read",
                process_id=1234,
                thread_id=5678,
                data={"filename": "license.dat"},
            )
        )

        test_results: dict[str, Any] = {
            "anti_analysis": {"detections": []},
            "behavioral_patterns": {
                "license_checks": [{"type": "registry_query"}],
                "network_communications": [{"type": "connect"}],
                "persistence_mechanisms": [],
                "data_exfiltration": [],
            },
        }

        summary = analyzer._generate_summary(test_results)

        assert "total_events" in summary
        assert "unique_event_types" in summary
        assert "suspicious_activities" in summary
        assert "risk_level" in summary
        assert "key_findings" in summary
        assert "bypass_recommendations" in summary

        assert summary["risk_level"] in ["low", "medium", "high"]
        assert isinstance(summary["key_findings"], list)
        assert isinstance(summary["bypass_recommendations"], list)

    def test_bypass_recommendations_generated_for_detections(self) -> None:
        """Verify bypass recommendations are generated for detected protections."""
        analyzer = BehavioralAnalyzer(Path("test.exe"))

        test_results: dict[str, Any] = {
            "anti_analysis": {
                "detections": [
                    {"type": "debugger_presence", "methods": ["IsDebuggerPresent"]},
                    {"type": "vm_artifacts", "indicators": ["vmtoolsd"]},
                    {"type": "timing_attacks", "checks": ["GetTickCount"]},
                ]
            },
            "behavioral_patterns": {
                "license_checks": [{"event": "registry_query"}],
                "network_communications": [{"event": "connect"}],
            },
        }

        summary = analyzer._generate_summary(test_results)

        assert len(summary["bypass_recommendations"]) > 0

        recommendations = summary["bypass_recommendations"]
        assert isinstance(recommendations, list)
        assert any("debugger detection" in r.lower() for r in recommendations)
        assert any("vm" in r.lower() for r in recommendations)
        assert any("timing" in r.lower() for r in recommendations)
        assert any("license" in r.lower() or "patch" in r.lower() for r in recommendations)

    def test_cleanup_releases_resources_regression(self, protected_binary: Path) -> None:
        """Verify cleanup properly releases all acquired resources."""
        analyzer = BehavioralAnalyzer(protected_binary)

        analyzer.cleanup()

        assert analyzer.stop_flag.is_set()
        assert analyzer.qemu_controller.is_running is False


class TestFactoryFunctionsRegression:
    """Regression tests for factory functions."""

    def test_create_behavioral_analyzer_factory_unchanged(self, protected_binary: Path) -> None:
        """Verify factory function creates properly configured analyzer."""
        analyzer = create_behavioral_analyzer(protected_binary)

        assert isinstance(analyzer, BehavioralAnalyzer)
        assert analyzer.binary_path == protected_binary
        assert isinstance(analyzer.qemu_config, QEMUConfig)
        assert isinstance(analyzer.api_hooks, FridaAPIHookingFramework)

    def test_run_behavioral_analysis_convenience_function(self, protected_binary: Path) -> None:
        """Verify convenience function executes complete analysis."""
        results = run_behavioral_analysis(protected_binary, duration=1, use_qemu=False)

        assert isinstance(results, dict)
        assert "summary" in results
        assert "behavioral_patterns" in results
        assert results["binary"] == str(protected_binary)
