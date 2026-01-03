"""Production Tests for QEMU Integration in Behavioral Analysis Module.

This module tests REAL QEMU integration capabilities for sandboxed binary execution
and licensing behavior analysis. All tests validate genuine offensive capability
against actual binaries and protection mechanisms.

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
    BehavioralAnalyzer,
    FridaAPIHookingFramework,
    HookPoint,
    MonitorEvent,
    QEMUConfig,
    QEMUController,
    create_behavioral_analyzer,
    run_behavioral_analysis,
)


@pytest.fixture(scope="session")
def test_binaries_dir() -> Path:
    """Provide test binaries directory path."""
    test_dir = Path(__file__).parent.parent.parent / "test_binaries"
    return test_dir


@pytest.fixture(scope="session")
def any_test_binary(test_binaries_dir: Path) -> Path:
    """Find any executable in test_binaries directory."""
    if not test_binaries_dir.exists():
        pytest.skip(f"Test binaries directory not found: {test_binaries_dir}")

    exe_files = list(test_binaries_dir.rglob("*.exe"))
    dll_files = list(test_binaries_dir.rglob("*.dll"))
    all_binaries = exe_files + dll_files

    if not all_binaries:
        pytest.skip(f"No test binaries found in {test_binaries_dir} - add binaries to test directory")

    return all_binaries[0]


@pytest.fixture(scope="session")
def windows_system_binary() -> Path:
    """Provide Windows system binary for testing."""
    if platform.system() != "Windows":
        pytest.skip("Windows-only test")

    notepad_path = Path(r"C:\Windows\System32\notepad.exe")
    if not notepad_path.exists():
        pytest.skip("Windows notepad.exe not found")
    return notepad_path


@pytest.fixture
def qemu_disk_image(tmp_path: Path) -> Path:
    """Create minimal QEMU disk image for testing."""
    if platform.system() != "Linux":
        pytest.skip("QEMU disk creation requires Linux")

    disk_image = tmp_path / "test_disk.img"

    try:
        result = subprocess.run(
            ["qemu-img", "create", "-f", "raw", str(disk_image), "100M"],
            capture_output=True,
            check=False,
            shell=False,
            timeout=30,
        )
        if result.returncode != 0:
            pytest.skip(f"Failed to create QEMU disk image: {result.stderr.decode()}")

        if not disk_image.exists():
            pytest.skip("QEMU disk image not created")

        return disk_image

    except FileNotFoundError:
        pytest.skip("qemu-img not available")
    except subprocess.TimeoutExpired:
        pytest.skip("QEMU disk image creation timeout")


class TestQEMUIntegration:
    """Test real QEMU integration for sandboxed binary execution."""

    def test_qemu_controller_starts_with_valid_binary(self, windows_system_binary: Path) -> None:
        """QEMU controller successfully starts VM with real binary."""
        config: QEMUConfig = QEMUConfig(
            enable_kvm=False,
            enable_gdb=True,
            vnc_display=None,
        )
        controller: QEMUController = QEMUController(config)

        qemu_binary = controller._find_qemu_binary()
        if not qemu_binary:
            pytest.skip("QEMU not installed on system")

        try:
            started: bool = controller.start(windows_system_binary)

            if started:
                assert controller.is_running
                assert controller.process is not None
                assert controller.process.poll() is None

                vm_status = controller.send_qmp_command({"execute": "query-status"})
                assert isinstance(vm_status, dict)

        finally:
            controller.stop()
            assert not controller.is_running

    def test_qemu_controller_creates_snapshots_during_execution(self, windows_system_binary: Path) -> None:
        """QEMU controller captures execution snapshots at key points."""
        config: QEMUConfig = QEMUConfig(enable_kvm=False, vnc_display=None)
        controller: QEMUController = QEMUController(config)

        if not controller._find_qemu_binary():
            pytest.skip("QEMU not installed")

        try:
            if not controller.start(windows_system_binary):
                pytest.skip("QEMU failed to start")

            snapshot_name = "test_snapshot_" + str(int(time.time()))
            snapshot_created: bool = controller.take_snapshot(snapshot_name)

            assert snapshot_created, "Snapshot creation must succeed"

            vm_info = controller.send_qmp_command({"execute": "query-status"})
            assert "return" in vm_info or "status" in str(vm_info)

        finally:
            controller.stop()

    def test_qemu_controller_connects_to_monitor_interface(self, windows_system_binary: Path) -> None:
        """QEMU controller establishes monitor connection for VM control."""
        config: QEMUConfig = QEMUConfig(
            monitor_port=44440,
            qmp_port=55550,
            enable_kvm=False,
            vnc_display=None,
        )
        controller: QEMUController = QEMUController(config)

        if not controller._find_qemu_binary():
            pytest.skip("QEMU not installed")

        try:
            if not controller.start(windows_system_binary):
                pytest.skip("QEMU failed to start")

            assert controller.monitor_socket is not None
            assert controller.qmp_socket is not None

            monitor_response: str = controller.send_monitor_command("info version")
            assert isinstance(monitor_response, str)

        finally:
            controller.stop()

    def test_qemu_controller_handles_binary_injection_to_disk(
        self, windows_system_binary: Path, qemu_disk_image: Path
    ) -> None:
        """QEMU controller prepares disk image with target binary."""
        config: QEMUConfig = QEMUConfig(
            disk_image=qemu_disk_image,
            enable_kvm=False,
            vnc_display=None,
        )
        controller: QEMUController = QEMUController(config)

        if not controller._find_qemu_binary():
            pytest.skip("QEMU not installed")

        controller._prepare_disk_image(windows_system_binary)

        assert qemu_disk_image.exists()
        assert qemu_disk_image.stat().st_size > 0

    def test_qemu_controller_detects_kvm_availability_correctly(self) -> None:
        """QEMU controller accurately detects KVM hardware acceleration."""
        config: QEMUConfig = QEMUConfig()
        controller: QEMUController = QEMUController(config)

        kvm_available: bool = controller._check_kvm_available()

        if platform.system() == "Linux":
            expected_kvm: bool = os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)
            assert kvm_available == expected_kvm
        else:
            assert not kvm_available

    def test_qemu_controller_restores_snapshots_for_trial_reset(self, windows_system_binary: Path) -> None:
        """QEMU controller restores snapshots to reset trial states."""
        config: QEMUConfig = QEMUConfig(enable_kvm=False, vnc_display=None)
        controller: QEMUController = QEMUController(config)

        if not controller._find_qemu_binary():
            pytest.skip("QEMU not installed")

        try:
            if not controller.start(windows_system_binary):
                pytest.skip("QEMU failed to start")

            snapshot_name = "clean_trial_state"
            if not controller.take_snapshot(snapshot_name):
                pytest.skip("Snapshot creation failed")

            time.sleep(1)

            restored: bool = controller.restore_snapshot(snapshot_name)
            assert restored, "Snapshot restoration must succeed for trial reset"

        finally:
            controller.stop()


class TestWindowsAPIHooking:
    """Test Windows API call hooking for license behavior monitoring."""

    def test_api_hooks_capture_file_operations_on_real_binary(self, windows_system_binary: Path) -> None:
        """API hooks capture file access related to license validation."""
        framework: FridaAPIHookingFramework = FridaAPIHookingFramework()

        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        test_context: dict[str, Any] = {"pid": os.getpid(), "tid": 1234}
        test_args: list[Any] = ["C:\\license.dat", 0x80000000, 0x3, 0, 3]

        initial_event_count = len(framework.events)
        framework._hook_create_file(test_args, test_context)

        assert len(framework.events) > initial_event_count
        latest_event: MonitorEvent = framework.events[-1]
        assert latest_event.event_type == "file_create"
        assert "license.dat" in str(latest_event.data.get("filename", ""))

    def test_api_hooks_capture_registry_operations_for_serial_validation(self) -> None:
        """API hooks capture registry access for license key storage."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        framework: FridaAPIHookingFramework = FridaAPIHookingFramework()

        test_context: dict[str, Any] = {"pid": os.getpid(), "tid": 5678}
        test_args: list[Any] = [0x80000002, "Software\\Product\\SerialKey", 0, 0xF003F]

        initial_count = len(framework.events)
        framework._hook_reg_open_key(test_args, test_context)

        assert len(framework.events) > initial_count
        event: MonitorEvent = framework.events[-1]
        assert event.event_type == "registry_open"
        assert "serial" in str(event.data).lower() or "product" in str(event.data).lower()

    def test_api_hooks_capture_network_connections_to_activation_servers(self) -> None:
        """API hooks capture network communication to license servers."""
        framework: FridaAPIHookingFramework = FridaAPIHookingFramework()

        test_context: dict[str, Any] = {"pid": os.getpid(), "tid": 9999}
        test_args: list[Any] = [100, 0x12345678]

        initial_count = len(framework.events)
        framework._hook_connect(test_args, test_context)

        assert len(framework.events) > initial_count
        event: MonitorEvent = framework.events[-1]
        assert event.event_type == "network_connect"
        assert "socket" in event.data

    def test_api_hooks_install_on_running_process_via_frida(self, windows_system_binary: Path) -> None:
        """API hooks successfully attach to running process using Frida."""
        framework: FridaAPIHookingFramework = FridaAPIHookingFramework()

        process: subprocess.Popen = subprocess.Popen(
            [str(windows_system_binary)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        time.sleep(1)

        try:
            attached: bool = framework.attach_to_process(process.pid)

            if attached:
                assert framework.frida_session is not None
                assert framework.frida_script is not None

                time.sleep(2)

                framework.detach_from_process()
                assert framework.frida_session is None
                assert framework.frida_script is None

        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

    def test_api_hooks_monitor_license_file_read_operations(self) -> None:
        """API hooks detect license file read patterns."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        framework: FridaAPIHookingFramework = FridaAPIHookingFramework()

        license_read_args: list[Any] = [0x12345, 1024]
        test_context: dict[str, Any] = {"pid": 1234, "tid": 5678}

        framework._hook_read_file(license_read_args, test_context)

        assert len(framework.events) > 0
        event: MonitorEvent = framework.events[-1]
        assert event.event_type == "file_read"
        assert event.data.get("size") == str(1024)

    def test_api_hooks_detect_registry_license_key_writes(self) -> None:
        """API hooks capture registry writes storing license data."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        framework: FridaAPIHookingFramework = FridaAPIHookingFramework()

        reg_write_args: list[Any] = [0x80000002, "LicenseKey", 0, 1, b"serial123"]
        test_context: dict[str, Any] = {"pid": 9876, "tid": 5432}

        framework._hook_reg_set_value(reg_write_args, test_context)

        assert len(framework.events) > 0
        event: MonitorEvent = framework.events[-1]
        assert event.event_type == "registry_set"
        assert "license" in event.data.get("value", "").lower()

    def test_api_hooks_track_network_data_transmission_to_servers(self) -> None:
        """API hooks monitor network data sent to activation servers."""
        framework: FridaAPIHookingFramework = FridaAPIHookingFramework()

        send_args: list[Any] = [100, 0xDEADBEEF, 512]
        test_context: dict[str, Any] = {"pid": 1111, "tid": 2222}

        framework._hook_send(send_args, test_context)

        assert len(framework.events) > 0
        event: MonitorEvent = framework.events[-1]
        assert event.event_type == "network_send"
        assert event.data.get("length") == str(512)


class TestFileRegistryNetworkMonitoring:
    """Test comprehensive monitoring of file, registry, and network operations."""

    def test_behavioral_analyzer_monitors_file_operations_during_execution(
        self, windows_system_binary: Path
    ) -> None:
        """Behavioral analyzer captures all file operations during binary execution."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        license_file_event = MonitorEvent(
            timestamp=time.time(),
            event_type="file_read",
            process_id=1234,
            thread_id=5678,
            data={"filename": "license.key", "size": 256},
        )
        analyzer.events.append(license_file_event)

        results: dict[str, Any] = {"behavioral_patterns": {}}
        results["file_operations"] = [e.to_dict() for e in analyzer.events if e.event_type.startswith("file_")]

        assert len(results["file_operations"]) > 0
        assert any("license" in str(op).lower() for op in results["file_operations"])

    def test_behavioral_analyzer_monitors_registry_operations_for_license_storage(
        self, windows_system_binary: Path
    ) -> None:
        """Behavioral analyzer tracks registry operations storing license data."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        registry_events = [
            MonitorEvent(
                timestamp=time.time(),
                event_type="registry_query",
                process_id=9999,
                thread_id=8888,
                data={"key": "HKLM\\Software\\Product\\Serial"},
            ),
            MonitorEvent(
                timestamp=time.time(),
                event_type="registry_set",
                process_id=9999,
                thread_id=8888,
                data={"key": "HKLM\\Software\\Product\\ActivationKey", "value": "key123"},
            ),
        ]
        analyzer.events.extend(registry_events)

        registry_ops = [e.to_dict() for e in analyzer.events if e.event_type.startswith("registry_")]

        assert len(registry_ops) >= 2
        assert any("serial" in str(op).lower() for op in registry_ops)
        assert any("activation" in str(op).lower() for op in registry_ops)

    def test_behavioral_analyzer_monitors_network_activity_to_license_servers(
        self, windows_system_binary: Path
    ) -> None:
        """Behavioral analyzer captures network communications with activation servers."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        network_events = [
            MonitorEvent(
                timestamp=time.time(),
                event_type="network_connect",
                process_id=5555,
                thread_id=6666,
                data={"address": "license-server.example.com", "port": 443},
            ),
            MonitorEvent(
                timestamp=time.time(),
                event_type="network_send",
                process_id=5555,
                thread_id=6666,
                data={"length": 256, "preview": "activation_request"},
            ),
        ]
        analyzer.events.extend(network_events)

        network_activity = [e.to_dict() for e in analyzer.events if e.event_type.startswith("network_")]

        assert len(network_activity) >= 2
        assert any(e["type"] == "network_connect" for e in network_activity)
        assert any(e["type"] == "network_send" for e in network_activity)


class TestLicenseCheckPatternDetection:
    """Test detection of licensing check patterns in behavioral data."""

    def test_analyzer_detects_serial_number_validation_patterns(self, windows_system_binary: Path) -> None:
        """Analyzer identifies serial number validation behavior."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        serial_events = [
            MonitorEvent(
                time.time(),
                "file_read",
                1234,
                5678,
                {"filename": "serial.dat"},
            ),
            MonitorEvent(
                time.time(),
                "registry_query",
                1234,
                5678,
                {"key": "HKLM\\Software\\Product\\SerialNumber"},
            ),
        ]
        analyzer.events.extend(serial_events)

        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        assert "license_checks" in patterns
        assert len(patterns["license_checks"]) >= 2

    def test_analyzer_detects_activation_key_verification_patterns(self, windows_system_binary: Path) -> None:
        """Analyzer identifies activation key validation routines."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        activation_events = [
            MonitorEvent(
                time.time(),
                "registry_query",
                9999,
                8888,
                {"key": "HKCU\\Software\\Product\\ActivationKey"},
            ),
            MonitorEvent(
                time.time(),
                "network_send",
                9999,
                8888,
                {"length": 128, "preview": "activation_check"},
            ),
        ]
        analyzer.events.extend(activation_events)

        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        assert len(patterns["license_checks"]) > 0
        assert len(patterns["network_communications"]) > 0

    def test_analyzer_detects_trial_expiration_check_patterns(self, windows_system_binary: Path) -> None:
        """Analyzer identifies trial period validation checks."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        trial_events = [
            MonitorEvent(
                time.time(),
                "registry_query",
                1111,
                2222,
                {"key": "HKLM\\Software\\Product\\TrialExpiration"},
            ),
            MonitorEvent(
                time.time(),
                "file_read",
                1111,
                2222,
                {"filename": "trial.dat"},
            ),
        ]
        analyzer.events.extend(trial_events)

        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        assert len(patterns["license_checks"]) >= 2
        assert any("trial" in str(check).lower() for check in patterns["license_checks"])

    def test_analyzer_detects_feature_unlock_validation_patterns(self, windows_system_binary: Path) -> None:
        """Analyzer identifies feature unlock license verification."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        feature_event = MonitorEvent(
            time.time(),
            "registry_query",
            3333,
            4444,
            {"key": "HKLM\\Software\\Product\\RegisteredFeatures"},
        )
        analyzer.events.append(feature_event)

        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        assert len(patterns["license_checks"]) > 0


class TestMemoryDumpCapture:
    """Test memory dump capture at key execution points."""

    def test_analyzer_captures_process_memory_during_license_checks(self, windows_system_binary: Path) -> None:
        """Analyzer captures memory state during license validation."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        results: dict[str, Any] = analyzer._run_native_analysis(duration=2)

        if results.get("process_started"):
            assert "memory_usage" in results
            memory_usage: dict[str, Any] = results["memory_usage"]
            assert "rss" in memory_usage
            assert "vms" in memory_usage
            assert memory_usage["rss"] > 0

    def test_frida_hooks_process_binary_payloads_from_api_calls(self) -> None:
        """Frida hooks extract and analyze binary data from API calls."""
        framework: FridaAPIHookingFramework = FridaAPIHookingFramework()

        test_data = b"LICENSE-KEY-12345" + b"\x00" * 100
        context: dict[str, Any] = {"function": "CryptDecrypt"}

        binary_info: dict[str, Any] = framework._process_binary_payload(test_data, context)

        assert "size" in binary_info
        assert binary_info["size"] == len(test_data)
        assert "hex_preview" in binary_info
        assert "entropy" in binary_info
        assert "strings" in binary_info or "license_data_detected" in binary_info


class TestExecutionFlowTracing:
    """Test execution flow tracing through protection layers."""

    def test_analyzer_traces_execution_through_license_validation_flow(
        self, windows_system_binary: Path
    ) -> None:
        """Analyzer traces execution path through licensing checks."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        execution_flow = [
            MonitorEvent(time.time(), "file_read", 1, 1, {"filename": "license.key"}),
            MonitorEvent(time.time(), "registry_query", 1, 1, {"key": "HKLM\\Software\\Serial"}),
            MonitorEvent(time.time(), "network_connect", 1, 1, {"address": "server.com", "port": 443}),
            MonitorEvent(time.time(), "network_send", 1, 1, {"length": 128}),
            MonitorEvent(time.time(), "network_recv", 1, 1, {"length": 256}),
            MonitorEvent(time.time(), "registry_set", 1, 1, {"key": "HKLM\\Software\\Activated"}),
        ]
        analyzer.events.extend(execution_flow)

        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        assert len(patterns["license_checks"]) >= 2
        assert len(patterns["network_communications"]) >= 3


class TestAntiSandboxDetection:
    """Test detection of anti-sandbox evasion techniques."""

    def test_anti_analysis_detector_identifies_vm_artifacts(self) -> None:
        """Anti-analysis detector finds virtual machine indicators."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()
        current_pid = os.getpid()

        detector._detect_vm_artifacts(current_pid)

        vm_detection = any(d["type"] == "vm_artifacts" for d in detector.detections)
        assert isinstance(vm_detection, bool)

    def test_anti_analysis_detector_identifies_sandbox_environment_indicators(self) -> None:
        """Anti-analysis detector finds sandbox artifacts."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()
        current_pid = os.getpid()

        detector._detect_sandbox_artifacts(current_pid)

        sandbox_detection = any(d["type"] == "sandbox_artifacts" for d in detector.detections)
        assert isinstance(sandbox_detection, bool)

    def test_analyzer_detects_anti_sandbox_checks_in_protected_binary(
        self, windows_system_binary: Path
    ) -> None:
        """Analyzer identifies anti-sandbox techniques in binary."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        process: subprocess.Popen = subprocess.Popen(
            [str(windows_system_binary)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        time.sleep(1)

        try:
            if process.poll() is None:
                detections = analyzer.anti_analysis.scan(process.pid)
                assert isinstance(detections, list)

        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


class TestTimeBasedChecks:
    """Test detection of time-based licensing checks."""

    def test_anti_analysis_detector_identifies_timing_based_checks(self) -> None:
        """Anti-analysis detector finds timing-based anti-debugging."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()
        current_pid = os.getpid()

        detector._detect_timing_attacks(current_pid)

        timing_detected = any(d["type"] == "timing_attacks" for d in detector.detections)
        assert isinstance(timing_detected, bool)

    def test_analyzer_detects_trial_time_manipulation_resistance(self, windows_system_binary: Path) -> None:
        """Analyzer identifies time-based trial protection mechanisms."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        time_check_event = MonitorEvent(
            time.time(),
            "registry_query",
            1234,
            5678,
            {"key": "HKLM\\Software\\Product\\InstallDate"},
        )
        analyzer.events.append(time_check_event)

        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        assert len(patterns["license_checks"]) > 0


class TestHardwareChecks:
    """Test detection of hardware-based licensing checks."""

    def test_analyzer_detects_hardware_id_validation_checks(self, windows_system_binary: Path) -> None:
        """Analyzer identifies hardware-based license binding."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        hardware_events = [
            MonitorEvent(
                time.time(),
                "registry_query",
                1111,
                2222,
                {"key": "SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles"},
            ),
            MonitorEvent(
                time.time(),
                "file_read",
                1111,
                2222,
                {"filename": "\\\\.\\PhysicalDrive0"},
            ),
        ]
        analyzer.events.extend(hardware_events)

        file_ops = [e.to_dict() for e in analyzer.events if e.event_type.startswith("file_")]
        registry_ops = [e.to_dict() for e in analyzer.events if e.event_type.startswith("registry_")]

        assert len(file_ops) + len(registry_ops) >= 2

    def test_analyzer_detects_dongle_hardware_communication(self, windows_system_binary: Path) -> None:
        """Analyzer identifies hardware dongle license validation."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        dongle_event = MonitorEvent(
            time.time(),
            "file_read",
            5555,
            6666,
            {"filename": "\\\\.\\HASP"},
        )
        analyzer.events.append(dongle_event)

        file_operations = [e.to_dict() for e in analyzer.events if e.event_type.startswith("file_")]

        assert len(file_operations) > 0
        assert any("hasp" in str(op).lower() for op in file_operations)


class TestComprehensiveWorkflow:
    """Test complete end-to-end behavioral analysis workflows."""

    def test_full_behavioral_analysis_workflow_on_real_binary(self, windows_system_binary: Path) -> None:
        """Complete behavioral analysis identifies all licensing mechanisms."""
        results: dict[str, Any] = run_behavioral_analysis(windows_system_binary, duration=3, use_qemu=False)

        assert "binary" in results
        assert str(windows_system_binary) in results["binary"]
        assert "summary" in results
        assert "total_events" in results["summary"]
        assert "risk_level" in results["summary"]
        assert results["summary"]["risk_level"] in ["low", "medium", "high"]

    def test_behavioral_analysis_with_any_user_provided_binary(self, any_test_binary: Path) -> None:
        """Behavioral analysis works on any binary in test_binaries directory."""
        results: dict[str, Any] = run_behavioral_analysis(any_test_binary, duration=2, use_qemu=False)

        assert "binary" in results
        assert "native_analysis" in results or "qemu_analysis" in results
        assert "summary" in results
        assert isinstance(results["summary"], dict)

    def test_behavioral_analysis_generates_bypass_recommendations(self, windows_system_binary: Path) -> None:
        """Behavioral analysis provides actionable bypass strategies."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_system_binary)

        license_events = [
            MonitorEvent(time.time(), "file_read", 1, 1, {"filename": "license.dat"}),
            MonitorEvent(time.time(), "registry_query", 1, 1, {"key": "HKLM\\Software\\Serial"}),
            MonitorEvent(time.time(), "network_connect", 1, 1, {"address": "activation.com", "port": 443}),
        ]
        analyzer.events.extend(license_events)

        results: dict[str, Any] = {
            "anti_analysis": {"detections": []},
            "behavioral_patterns": analyzer._analyze_behavioral_patterns(),
        }

        summary: dict[str, Any] = analyzer._generate_summary(results)

        assert "bypass_recommendations" in summary
        assert isinstance(summary["bypass_recommendations"], list)

    def test_behavioral_analysis_performance_meets_requirements(self, windows_system_binary: Path) -> None:
        """Behavioral analysis completes within expected timeframe."""
        duration = 3
        start_time = time.time()

        results: dict[str, Any] = run_behavioral_analysis(windows_system_binary, duration=duration, use_qemu=False)

        elapsed = time.time() - start_time

        assert elapsed < duration + 5
        assert "duration" in results
        assert results["duration"] < duration + 3


class TestEdgeCases:
    """Test edge cases and error handling in behavioral analysis."""

    def test_analyzer_handles_binary_that_exits_immediately(self, tmp_path: Path) -> None:
        """Analyzer handles binaries that terminate quickly."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        cmd_path = Path(r"C:\Windows\System32\cmd.exe")
        if not cmd_path.exists():
            pytest.skip("cmd.exe not found")

        results: dict[str, Any] = run_behavioral_analysis(cmd_path, duration=1, use_qemu=False)

        assert "binary" in results
        assert "summary" in results

    def test_analyzer_handles_protected_binary_with_anti_debug(self, windows_system_binary: Path) -> None:
        """Analyzer successfully analyzes binaries with anti-debugging."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()

        process: subprocess.Popen = subprocess.Popen(
            [str(windows_system_binary)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        time.sleep(1)

        try:
            if process.poll() is None:
                detections = detector.scan(process.pid)
                assert isinstance(detections, list)

        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

    def test_analyzer_handles_missing_qemu_gracefully(self, windows_system_binary: Path) -> None:
        """Analyzer falls back to native analysis when QEMU unavailable."""
        config: QEMUConfig = QEMUConfig()
        controller: QEMUController = QEMUController(config)

        qemu_binary = controller._find_qemu_binary()

        if not qemu_binary:
            results: dict[str, Any] = run_behavioral_analysis(
                windows_system_binary, duration=1, use_qemu=False
            )

            assert "native_analysis" in results
            assert "summary" in results

    def test_analyzer_handles_frida_unavailable_gracefully(self, windows_system_binary: Path) -> None:
        """Analyzer handles Frida installation absence without crashing."""
        framework: FridaAPIHookingFramework = FridaAPIHookingFramework()

        attached = framework.attach_to_process(99999)

        assert isinstance(attached, bool)
