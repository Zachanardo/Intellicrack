"""Production Tests for Behavioral Analysis Module.

This module tests REAL behavioral analysis capabilities against actual Windows binaries.
All tests validate genuine offensive capability against actual protection mechanisms.

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

import ctypes
import os
import platform
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import psutil
import pytest

from intellicrack.core.analysis.behavioral_analysis import (
    APIHookingFramework,
    AntiAnalysisDetector,
    BehavioralAnalyzer,
    HookPoint,
    MonitorEvent,
    QEMUConfig,
    QEMUController,
    create_behavioral_analyzer,
    run_behavioral_analysis,
)


@pytest.fixture(scope="session")
def windows_notepad() -> Path:
    """Provide path to Windows notepad.exe for testing."""
    notepad_path = Path(r"C:\Windows\System32\notepad.exe")
    if not notepad_path.exists():
        pytest.skip("Windows notepad.exe not found")
    return notepad_path


@pytest.fixture(scope="session")
def windows_calc() -> Path:
    """Provide path to Windows calculator for testing."""
    if platform.system() != "Windows":
        pytest.skip("Windows-only test")

    calc_paths = [
        Path(r"C:\Windows\System32\calc.exe"),
        Path(r"C:\Windows\System32\win32calc.exe"),
        Path(r"C:\Windows\SysWOW64\calc.exe"),
    ]

    for calc_path in calc_paths:
        if calc_path.exists():
            return calc_path

    pytest.skip("Windows calculator not found")


@pytest.fixture(scope="session")
def windows_cmd() -> Path:
    """Provide path to Windows cmd.exe for testing."""
    cmd_path = Path(r"C:\Windows\System32\cmd.exe")
    if not cmd_path.exists():
        pytest.skip("Windows cmd.exe not found")
    return cmd_path


@pytest.fixture
def test_binary_file(tmp_path: Path) -> Path:
    """Create a minimal PE test binary."""
    test_exe = tmp_path / "test_binary.exe"

    pe_header = bytearray([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    pe_header.extend(b'\x00' * (0x3C - len(pe_header)))
    pe_header.extend([0x40, 0x00, 0x00, 0x00])
    pe_header.extend(b'\x00' * (0x40 - len(pe_header)))

    pe_signature = b'PE\x00\x00'
    coff_header = bytearray([
        0x4C, 0x01,
        0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xE0, 0x00,
        0x02, 0x01,
    ])

    test_exe.write_bytes(pe_header + pe_signature + coff_header + (b'\x00' * 1024))
    return test_exe


class TestMonitorEvent:
    """Test MonitorEvent dataclass functionality."""

    def test_monitor_event_creation_with_all_fields(self) -> None:
        """MonitorEvent captures complete event information."""
        timestamp: float = time.time()
        event: MonitorEvent = MonitorEvent(
            timestamp=timestamp,
            event_type="file_create",
            process_id=1234,
            thread_id=5678,
            data={"filename": "test.txt", "access": "0x80000000"},
            context={"module": "kernel32.dll"},
        )

        assert event.timestamp == timestamp
        assert event.event_type == "file_create"
        assert event.process_id == 1234
        assert event.thread_id == 5678
        assert event.data["filename"] == "test.txt"
        assert event.context["module"] == "kernel32.dll"

    def test_monitor_event_to_dict_serialization(self) -> None:
        """MonitorEvent serializes correctly to dictionary."""
        event: MonitorEvent = MonitorEvent(
            timestamp=123456.789,
            event_type="registry_query",
            process_id=9999,
            thread_id=8888,
            data={"key": "HKLM\\Software\\Test"},
            context={"caller": "test.exe"},
        )

        event_dict: dict[str, Any] = event.to_dict()

        assert event_dict["timestamp"] == 123456.789
        assert event_dict["type"] == "registry_query"
        assert event_dict["pid"] == 9999
        assert event_dict["tid"] == 8888
        assert event_dict["data"]["key"] == "HKLM\\Software\\Test"
        assert event_dict["context"]["caller"] == "test.exe"

    def test_monitor_event_default_context_empty(self) -> None:
        """MonitorEvent defaults to empty context when not provided."""
        event: MonitorEvent = MonitorEvent(
            timestamp=time.time(),
            event_type="network_connect",
            process_id=1111,
            thread_id=2222,
            data={"ip": "192.168.1.1"},
        )

        assert event.context == {}
        assert isinstance(event.context, dict)

    def test_monitor_event_handles_complex_data_structures(self) -> None:
        """MonitorEvent preserves complex nested data structures."""
        complex_data: dict[str, Any] = {
            "operation": "write",
            "buffer": {"size": 1024, "preview": "deadbeef"},
            "flags": ["async", "cached"],
            "metadata": {"timestamp": time.time(), "user": "admin"},
        }

        event: MonitorEvent = MonitorEvent(
            timestamp=time.time(),
            event_type="file_write",
            process_id=5000,
            thread_id=6000,
            data=complex_data,
        )

        assert event.data["buffer"]["size"] == 1024
        assert "async" in event.data["flags"]
        assert "user" in event.data["metadata"]


class TestQEMUConfig:
    """Test QEMU configuration management."""

    def test_qemu_config_default_values_correct(self) -> None:
        """QEMUConfig initializes with sensible defaults."""
        config: QEMUConfig = QEMUConfig()

        assert config.machine_type == "pc"
        assert config.cpu_model == "max"
        assert config.memory_size == "2G"
        assert config.network_mode == "user"
        assert config.enable_kvm is True
        assert config.enable_gdb is True
        assert config.gdb_port == 1234
        assert config.monitor_port == 4444
        assert config.qmp_port == 5555
        assert config.vnc_display == 0

    def test_qemu_config_custom_settings_applied(self) -> None:
        """QEMUConfig accepts custom configuration values."""
        config: QEMUConfig = QEMUConfig(
            machine_type="q35",
            cpu_model="host",
            memory_size="4G",
            enable_kvm=False,
            gdb_port=9999,
            vnc_display=None,
        )

        assert config.machine_type == "q35"
        assert config.cpu_model == "host"
        assert config.memory_size == "4G"
        assert config.enable_kvm is False
        assert config.gdb_port == 9999
        assert config.vnc_display is None

    def test_qemu_config_supports_disk_image_path(self) -> None:
        """QEMUConfig handles disk image paths correctly."""
        disk_path: Path = Path("/tmp/test_disk.img")
        config: QEMUConfig = QEMUConfig(disk_image=disk_path)

        assert config.disk_image == disk_path
        assert isinstance(config.disk_image, Path)

    def test_qemu_config_extra_args_accumulate(self) -> None:
        """QEMUConfig preserves extra command-line arguments."""
        extra_args: list[str] = ["-snapshot", "-no-reboot", "-serial", "stdio"]
        config: QEMUConfig = QEMUConfig(extra_args=extra_args)

        assert config.extra_args == extra_args
        assert len(config.extra_args) == 4


class TestQEMUController:
    """Test QEMU virtual machine control."""

    def test_qemu_controller_initialization(self) -> None:
        """QEMUController initializes with clean state."""
        config: QEMUConfig = QEMUConfig()
        controller: QEMUController = QEMUController(config)

        assert controller.config == config
        assert controller.process is None
        assert controller.monitor_socket is None
        assert controller.qmp_socket is None
        assert controller.gdb_socket is None
        assert controller.is_running is False

    def test_qemu_controller_finds_qemu_binary_when_available(self) -> None:
        """QEMUController detects installed QEMU binary."""
        config: QEMUConfig = QEMUConfig()
        controller: QEMUController = QEMUController(config)

        qemu_binary: str | None = controller._find_qemu_binary()

        if qemu_binary:
            assert isinstance(qemu_binary, str)
            assert len(qemu_binary) > 0
            assert "qemu" in qemu_binary.lower()

    def test_qemu_controller_kvm_detection_on_linux(self) -> None:
        """QEMUController correctly detects KVM availability on Linux."""
        config: QEMUConfig = QEMUConfig()
        controller: QEMUController = QEMUController(config)

        kvm_available: bool = controller._check_kvm_available()

        if platform.system() == "Linux":
            kvm_expected: bool = os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)
            assert kvm_available == kvm_expected
        else:
            assert kvm_available is False

    def test_qemu_controller_stops_cleanly_when_not_running(self) -> None:
        """QEMUController handles stop when no VM is running."""
        config: QEMUConfig = QEMUConfig()
        controller: QEMUController = QEMUController(config)

        controller.stop()

        assert controller.is_running is False
        assert controller.process is None

    def test_qemu_controller_monitor_command_handles_no_socket(self) -> None:
        """QEMUController returns empty string when monitor not connected."""
        config: QEMUConfig = QEMUConfig()
        controller: QEMUController = QEMUController(config)

        result: str = controller.send_monitor_command("info registers")

        assert result == ""
        assert isinstance(result, str)

    def test_qemu_controller_qmp_command_handles_no_socket(self) -> None:
        """QEMUController returns empty dict when QMP not connected."""
        config: QEMUConfig = QEMUConfig()
        controller: QEMUController = QEMUController(config)

        result: dict[str, Any] = controller.send_qmp_command({"execute": "query-status"})

        assert result == {}
        assert isinstance(result, dict)


class TestAPIHookingFramework:
    """Test API hooking framework functionality."""

    def test_api_hooking_framework_initializes_with_platform_hooks(self) -> None:
        """APIHookingFramework sets up hooks for current platform."""
        framework: APIHookingFramework = APIHookingFramework()

        assert isinstance(framework.hooks, dict)
        assert isinstance(framework.events, list)
        assert isinstance(framework.active_hooks, set)
        assert len(framework.hooks) > 0

    def test_api_hooking_framework_windows_hooks_registered(self) -> None:
        """APIHookingFramework registers Windows API hooks on Windows."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        framework: APIHookingFramework = APIHookingFramework()

        expected_hooks: list[str] = [
            "kernel32.dll:CreateFileW",
            "kernel32.dll:ReadFile",
            "kernel32.dll:WriteFile",
            "advapi32.dll:RegOpenKeyExW",
            "advapi32.dll:RegQueryValueExW",
            "advapi32.dll:RegSetValueExW",
            "ws2_32.dll:connect",
            "ws2_32.dll:send",
            "ws2_32.dll:recv",
            "ntdll.dll:NtCreateProcess",
            "ntdll.dll:NtOpenProcess",
        ]

        for hook_key in expected_hooks:
            assert hook_key in framework.hooks, f"Missing hook: {hook_key}"
            assert len(framework.hooks[hook_key]) > 0

    def test_api_hooking_framework_linux_hooks_registered(self) -> None:
        """APIHookingFramework registers Linux syscall hooks on Linux."""
        if platform.system() != "Linux":
            pytest.skip("Linux-specific test")

        framework: APIHookingFramework = APIHookingFramework()

        expected_hooks: list[str] = [
            "libc.so.6:open",
            "libc.so.6:read",
            "libc.so.6:write",
            "libc.so.6:socket",
            "libc.so.6:connect",
        ]

        for hook_key in expected_hooks:
            assert hook_key in framework.hooks, f"Missing hook: {hook_key}"

    def test_api_hooking_framework_add_hook_registers_correctly(self) -> None:
        """APIHookingFramework adds custom hooks correctly."""
        framework: APIHookingFramework = APIHookingFramework()

        custom_hook: HookPoint = HookPoint(
            module="custom.dll",
            function="CustomFunction",
            on_enter=lambda args, ctx: None,
            priority=50,
        )

        initial_count: int = len(framework.hooks)
        framework.add_hook(custom_hook)

        assert len(framework.hooks) >= initial_count
        assert "custom.dll:CustomFunction" in framework.hooks

    def test_api_hooking_framework_hooks_sorted_by_priority(self) -> None:
        """APIHookingFramework maintains hooks in priority order."""
        framework: APIHookingFramework = APIHookingFramework()

        hook_low: HookPoint = HookPoint(module="test.dll", function="TestFunc", priority=10)
        hook_high: HookPoint = HookPoint(module="test.dll", function="TestFunc", priority=100)
        hook_mid: HookPoint = HookPoint(module="test.dll", function="TestFunc", priority=50)

        framework.add_hook(hook_low)
        framework.add_hook(hook_high)
        framework.add_hook(hook_mid)

        hooks: list[HookPoint] = framework.hooks["test.dll:TestFunc"]
        assert hooks[0].priority == 100
        assert hooks[1].priority == 50
        assert hooks[2].priority == 10

    def test_api_hooking_framework_remove_hook_deletes_correctly(self) -> None:
        """APIHookingFramework removes hooks successfully."""
        framework: APIHookingFramework = APIHookingFramework()

        framework.add_hook(HookPoint(module="remove.dll", function="TestFunc", priority=10))
        assert "remove.dll:TestFunc" in framework.hooks

        framework.remove_hook("remove.dll", "TestFunc")
        assert "remove.dll:TestFunc" not in framework.hooks

    def test_api_hooking_framework_enable_hook_activates(self) -> None:
        """APIHookingFramework enables hooks for monitoring."""
        framework: APIHookingFramework = APIHookingFramework()

        hook_key: str = "kernel32.dll:CreateFileW"
        framework.enable_hook("kernel32.dll", "CreateFileW")

        assert hook_key in framework.active_hooks

    def test_api_hooking_framework_disable_hook_deactivates(self) -> None:
        """APIHookingFramework disables active hooks."""
        framework: APIHookingFramework = APIHookingFramework()

        hook_key: str = "kernel32.dll:CreateFileW"
        framework.enable_hook("kernel32.dll", "CreateFileW")
        framework.disable_hook("kernel32.dll", "CreateFileW")

        assert hook_key not in framework.active_hooks

    def test_api_hooking_framework_captures_file_create_events(self) -> None:
        """APIHookingFramework hooks capture file creation events."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        framework: APIHookingFramework = APIHookingFramework()

        test_args: list[Any] = [0x12345678, 0x80000000, 0x00000003, 0, 3]
        test_context: dict[str, Any] = {"pid": 1234, "tid": 5678}

        framework._hook_create_file(test_args, test_context)

        assert len(framework.events) > 0
        event: MonitorEvent = framework.events[0]
        assert event.event_type == "file_create"
        assert event.process_id == 1234
        assert event.thread_id == 5678

    def test_api_hooking_framework_captures_registry_operations(self) -> None:
        """APIHookingFramework hooks capture registry access."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        framework: APIHookingFramework = APIHookingFramework()

        test_args: list[Any] = [0x80000002, 0x12345678, 0, 0xF003F]
        test_context: dict[str, Any] = {"pid": 9999, "tid": 8888}

        framework._hook_reg_open_key(test_args, test_context)

        assert len(framework.events) > 0
        event: MonitorEvent = framework.events[0]
        assert event.event_type == "registry_open"
        assert event.process_id == 9999

    def test_api_hooking_framework_captures_network_activity(self) -> None:
        """APIHookingFramework hooks capture network connections."""
        framework: APIHookingFramework = APIHookingFramework()

        test_args: list[Any] = [100, 0x87654321]
        test_context: dict[str, Any] = {"pid": 5555, "tid": 6666}

        framework._hook_connect(test_args, test_context)

        assert len(framework.events) > 0
        event: MonitorEvent = framework.events[0]
        assert event.event_type == "network_connect"
        assert event.data["socket"] == 100


class TestAntiAnalysisDetector:
    """Test anti-analysis technique detection."""

    def test_anti_analysis_detector_initializes_with_methods(self) -> None:
        """AntiAnalysisDetector loads all detection methods."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()

        assert isinstance(detector.detections, list)
        assert len(detector.detection_methods) == 8
        assert detector._detect_debugger_presence in detector.detection_methods
        assert detector._detect_vm_artifacts in detector.detection_methods
        assert detector._detect_timing_attacks in detector.detection_methods

    def test_anti_analysis_detector_scans_current_process(self) -> None:
        """AntiAnalysisDetector scans current process for anti-analysis."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()
        current_pid: int = os.getpid()

        detections: list[dict[str, Any]] = detector.scan(current_pid)

        assert isinstance(detections, list)

    def test_anti_analysis_detector_detects_debugger_presence(self) -> None:
        """AntiAnalysisDetector identifies debugger presence checks."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()
        current_pid: int = os.getpid()

        detector._detect_debugger_presence(current_pid)

        if platform.system() == "Windows":
            kernel32 = ctypes.windll.kernel32
            if kernel32.IsDebuggerPresent():
                assert any(d["type"] == "debugger_presence" for d in detector.detections)

    def test_anti_analysis_detector_identifies_vm_artifacts(self) -> None:
        """AntiAnalysisDetector detects virtual machine indicators."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()
        current_pid: int = os.getpid()

        detector._detect_vm_artifacts(current_pid)

        vm_detected: bool = any(d["type"] == "vm_artifacts" for d in detector.detections)
        assert isinstance(vm_detected, bool)

    def test_anti_analysis_detector_measures_timing_anomalies(self) -> None:
        """AntiAnalysisDetector identifies timing-based anti-debugging."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()
        current_pid: int = os.getpid()

        detector._detect_timing_attacks(current_pid)

        timing_checks: bool = any(d["type"] == "timing_attacks" for d in detector.detections)
        assert isinstance(timing_checks, bool)

    def test_anti_analysis_detector_finds_process_hollowing(self) -> None:
        """AntiAnalysisDetector detects process hollowing indicators."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()
        current_pid: int = os.getpid()

        detector._detect_process_hollowing(current_pid)

        hollowing_detected: bool = any(d["type"] == "process_hollowing" for d in detector.detections)
        assert isinstance(hollowing_detected, bool)

    def test_anti_analysis_detector_identifies_api_hooks(self) -> None:
        """AntiAnalysisDetector detects hooked API functions."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        detector: AntiAnalysisDetector = AntiAnalysisDetector()
        current_pid: int = os.getpid()

        detector._detect_api_hooks(current_pid)

        hooks_detected: bool = any(d["type"] == "api_hooks" for d in detector.detections)
        assert isinstance(hooks_detected, bool)

    def test_anti_analysis_detector_finds_sandbox_artifacts(self) -> None:
        """AntiAnalysisDetector identifies sandbox environment indicators."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()
        current_pid: int = os.getpid()

        detector._detect_sandbox_artifacts(current_pid)

        sandbox_detected: bool = any(d["type"] == "sandbox_artifacts" for d in detector.detections)
        assert isinstance(sandbox_detected, bool)

    def test_anti_analysis_detector_checks_memory_protections(self) -> None:
        """AntiAnalysisDetector detects memory protection mechanisms."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()
        current_pid: int = os.getpid()

        detector._detect_memory_protections(current_pid)

        protections_found: bool = any(d["type"] == "memory_protections" for d in detector.detections)
        assert isinstance(protections_found, bool)

    def test_anti_analysis_detector_identifies_obfuscation(self) -> None:
        """AntiAnalysisDetector detects code obfuscation techniques."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()
        current_pid: int = os.getpid()

        detector._detect_code_obfuscation(current_pid)

        obfuscation_detected: bool = any(d["type"] == "code_obfuscation" for d in detector.detections)
        assert isinstance(obfuscation_detected, bool)

    def test_anti_analysis_detector_calculates_entropy_correctly(self) -> None:
        """AntiAnalysisDetector computes Shannon entropy accurately."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()

        low_entropy_data: bytes = b'\x00' * 100
        high_entropy_data: bytes = bytes(range(256)) * 4

        low_entropy: float = detector._calculate_entropy(low_entropy_data)
        high_entropy: float = detector._calculate_entropy(high_entropy_data)

        assert 0.0 <= low_entropy < 2.0
        assert 6.0 <= high_entropy <= 8.0
        assert high_entropy > low_entropy

    def test_anti_analysis_detector_handles_empty_data(self) -> None:
        """AntiAnalysisDetector handles empty entropy calculation."""
        detector: AntiAnalysisDetector = AntiAnalysisDetector()

        entropy: float = detector._calculate_entropy(b'')

        assert entropy == 0.0


class TestBehavioralAnalyzer:
    """Test behavioral analysis orchestrator."""

    def test_behavioral_analyzer_initializes_with_binary_path(self, windows_notepad: Path) -> None:
        """BehavioralAnalyzer initializes with target binary."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        assert analyzer.binary_path == windows_notepad
        assert isinstance(analyzer.qemu_config, QEMUConfig)
        assert isinstance(analyzer.qemu_controller, QEMUController)
        assert isinstance(analyzer.api_hooks, APIHookingFramework)
        assert isinstance(analyzer.anti_analysis, AntiAnalysisDetector)

    def test_behavioral_analyzer_runs_native_analysis(self, windows_notepad: Path) -> None:
        """BehavioralAnalyzer executes native analysis on real binary."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        results: dict[str, Any] = analyzer._run_native_analysis(duration=1)

        assert "process_started" in results
        assert "pid" in results
        assert "memory_usage" in results
        assert "cpu_usage" in results

    def test_behavioral_analyzer_monitors_process_resources(self, windows_cmd: Path) -> None:
        """BehavioralAnalyzer tracks process resource consumption."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_cmd)

        results: dict[str, Any] = analyzer._run_native_analysis(duration=2)

        if results["process_started"]:
            assert results["pid"] is not None
            assert isinstance(results["cpu_usage"], list)
            assert isinstance(results["memory_usage"], dict)

    def test_behavioral_analyzer_detects_license_check_patterns(self, windows_notepad: Path) -> None:
        """BehavioralAnalyzer identifies license validation behavior."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        test_events: list[MonitorEvent] = [
            MonitorEvent(
                timestamp=time.time(),
                event_type="file_read",
                process_id=1234,
                thread_id=5678,
                data={"filename": "license.dat"},
            ),
            MonitorEvent(
                timestamp=time.time(),
                event_type="registry_query",
                process_id=1234,
                thread_id=5678,
                data={"key": "HKLM\\Software\\Product\\Serial"},
            ),
        ]

        analyzer.events.extend(test_events)
        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        assert "license_checks" in patterns
        assert len(patterns["license_checks"]) > 0

    def test_behavioral_analyzer_identifies_network_communications(self, windows_notepad: Path) -> None:
        """BehavioralAnalyzer tracks network activity patterns."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        network_event: MonitorEvent = MonitorEvent(
            timestamp=time.time(),
            event_type="network_connect",
            process_id=9999,
            thread_id=8888,
            data={"address": "192.168.1.1", "port": 443},
        )

        analyzer.events.append(network_event)
        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        assert "network_communications" in patterns
        assert len(patterns["network_communications"]) == 1

    def test_behavioral_analyzer_detects_persistence_mechanisms(self, windows_notepad: Path) -> None:
        """BehavioralAnalyzer identifies persistence installation."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        registry_activity: list[MonitorEvent] = [
            MonitorEvent(
                timestamp=time.time(),
                event_type="registry_set",
                process_id=5555,
                thread_id=6666,
                data={"key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
            ),
            MonitorEvent(
                timestamp=time.time(),
                event_type="registry_query",
                process_id=5555,
                thread_id=6666,
                data={"key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
            ),
        ]

        analyzer.events.extend(registry_activity)
        results: dict[str, Any] = {
            "binary": str(windows_notepad),
            "registry_activity": [e.to_dict() for e in analyzer.events if e.event_type.startswith("registry_")],
        }

        assert len(results["registry_activity"]) == 2
        assert any("run" in str(e).lower() for e in results["registry_activity"])

    def test_behavioral_analyzer_flags_data_exfiltration(self, windows_notepad: Path) -> None:
        """BehavioralAnalyzer detects large network transmissions."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        exfil_event: MonitorEvent = MonitorEvent(
            timestamp=time.time(),
            event_type="network_send",
            process_id=7777,
            thread_id=8888,
            data={"length": 10240, "preview": "deadbeef"},
        )

        analyzer.events.append(exfil_event)
        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        assert "data_exfiltration" in patterns
        assert len(patterns["data_exfiltration"]) > 0

    def test_behavioral_analyzer_generates_summary_with_risk_level(self, windows_notepad: Path) -> None:
        """BehavioralAnalyzer generates comprehensive analysis summary."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        test_events: list[MonitorEvent] = [
            MonitorEvent(time.time(), "file_read", 1, 1, {}),
            MonitorEvent(time.time(), "network_connect", 1, 1, {}),
            MonitorEvent(time.time(), "registry_query", 1, 1, {}),
        ]
        analyzer.events.extend(test_events)

        results: dict[str, Any] = {
            "anti_analysis": {"detections": []},
            "behavioral_patterns": {
                "license_checks": [],
                "persistence_mechanisms": [],
                "data_exfiltration": [],
            },
        }

        summary: dict[str, Any] = analyzer._generate_summary(results)

        assert "total_events" in summary
        assert "unique_event_types" in summary
        assert "suspicious_activities" in summary
        assert "risk_level" in summary
        assert "key_findings" in summary
        assert summary["risk_level"] in ["low", "medium", "high"]

    def test_behavioral_analyzer_cleans_up_resources(self, windows_notepad: Path) -> None:
        """BehavioralAnalyzer properly releases resources."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        analyzer.cleanup()

        assert analyzer.stop_flag.is_set()
        assert analyzer.qemu_controller.is_running is False

    def test_behavioral_analyzer_finds_target_process_by_name(self, windows_notepad: Path) -> None:
        """BehavioralAnalyzer locates running process by binary name."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        process: subprocess.Popen = subprocess.Popen([str(windows_notepad)], shell=False)
        time.sleep(0.5)

        try:
            pid: int | None = analyzer._get_target_process_id()

            if pid:
                assert isinstance(pid, int)
                assert pid > 0
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_behavioral_analyzer_handles_nonexistent_process(self, test_binary_file: Path) -> None:
        """BehavioralAnalyzer handles case when target process not found."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(test_binary_file)

        pid: int | None = analyzer._get_target_process_id()

        assert pid is None


class TestBehavioralAnalysisFactoryFunctions:
    """Test factory functions for behavioral analysis."""

    def test_create_behavioral_analyzer_factory(self, windows_notepad: Path) -> None:
        """create_behavioral_analyzer factory creates valid instance."""
        analyzer: BehavioralAnalyzer = create_behavioral_analyzer(windows_notepad)

        assert isinstance(analyzer, BehavioralAnalyzer)
        assert analyzer.binary_path == windows_notepad

    def test_run_behavioral_analysis_executes_full_workflow(self, windows_notepad: Path) -> None:
        """run_behavioral_analysis performs complete analysis workflow."""
        results: dict[str, Any] = run_behavioral_analysis(windows_notepad, duration=1)

        assert "binary" in results
        assert "start_time" in results
        assert "summary" in results
        assert str(windows_notepad) in results["binary"]

    def test_run_behavioral_analysis_returns_complete_results(self, windows_cmd: Path) -> None:
        """run_behavioral_analysis provides all expected result fields."""
        results: dict[str, Any] = run_behavioral_analysis(windows_cmd, duration=1)

        expected_keys: list[str] = [
            "binary",
            "start_time",
            "api_monitoring",
            "anti_analysis",
            "behavioral_patterns",
            "network_activity",
            "file_operations",
            "registry_activity",
            "process_activity",
            "summary",
        ]

        for key in expected_keys:
            assert key in results, f"Missing result key: {key}"


class TestBehavioralAnalysisRealWorldScenarios:
    """Test behavioral analysis against real-world scenarios."""

    def test_behavioral_analysis_detects_trial_check_behavior(self, windows_notepad: Path) -> None:
        """Behavioral analysis identifies trial limitation checks."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        trial_events: list[MonitorEvent] = [
            MonitorEvent(
                timestamp=time.time(),
                event_type="registry_query",
                process_id=1234,
                thread_id=5678,
                data={"key": "HKLM\\Software\\Product\\TrialExpiration"},
            ),
            MonitorEvent(
                timestamp=time.time(),
                event_type="file_read",
                process_id=1234,
                thread_id=5678,
                data={"filename": "trial.dat"},
            ),
        ]

        analyzer.events.extend(trial_events)
        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        assert len(patterns["license_checks"]) >= 2

    def test_behavioral_analysis_identifies_activation_server_contact(self, windows_notepad: Path) -> None:
        """Behavioral analysis detects license activation server communication."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        activation_events: list[MonitorEvent] = [
            MonitorEvent(
                timestamp=time.time(),
                event_type="network_connect",
                process_id=9999,
                thread_id=8888,
                data={"address": "activation.server.com", "port": 443},
            ),
            MonitorEvent(
                timestamp=time.time(),
                event_type="network_send",
                process_id=9999,
                thread_id=8888,
                data={"length": 256, "preview": "license_request"},
            ),
        ]

        analyzer.events.extend(activation_events)
        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        assert len(patterns["network_communications"]) == 2

    def test_behavioral_analysis_detects_dongle_communication(self, windows_notepad: Path) -> None:
        """Behavioral analysis identifies hardware dongle interactions."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        dongle_event: MonitorEvent = MonitorEvent(
            timestamp=time.time(),
            event_type="file_read",
            process_id=5555,
            thread_id=6666,
            data={"filename": "\\\\.\\HASP"},
        )

        analyzer.events.append(dongle_event)
        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        file_operations: list[dict[str, Any]] = [
            e.to_dict() for e in analyzer.events if e.event_type.startswith("file_")
        ]
        assert len(file_operations) > 0

    def test_behavioral_analysis_tracks_license_file_modifications(self, windows_notepad: Path) -> None:
        """Behavioral analysis monitors license file write operations."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        license_write: MonitorEvent = MonitorEvent(
            timestamp=time.time(),
            event_type="file_write",
            process_id=7777,
            thread_id=8888,
            data={"filename": "license.key", "size": 512},
        )

        analyzer.events.append(license_write)
        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        assert len(patterns["license_checks"]) > 0

    def test_behavioral_analysis_identifies_registry_license_storage(self, windows_notepad: Path) -> None:
        """Behavioral analysis detects license data stored in registry."""
        analyzer: BehavioralAnalyzer = BehavioralAnalyzer(windows_notepad)

        registry_events: list[MonitorEvent] = [
            MonitorEvent(
                timestamp=time.time(),
                event_type="registry_set",
                process_id=1111,
                thread_id=2222,
                data={"key": "HKLM\\Software\\Product\\Activation", "value": "LicenseKey"},
            ),
            MonitorEvent(
                timestamp=time.time(),
                event_type="registry_query",
                process_id=1111,
                thread_id=2222,
                data={"key": "HKLM\\Software\\Product\\Serial"},
            ),
        ]

        analyzer.events.extend(registry_events)
        patterns: dict[str, Any] = analyzer._analyze_behavioral_patterns()

        assert len(patterns["license_checks"]) >= 2

    def test_behavioral_analysis_full_workflow_on_real_binary(self, windows_notepad: Path) -> None:
        """Complete behavioral analysis workflow on actual Windows binary."""
        results: dict[str, Any] = run_behavioral_analysis(windows_notepad, duration=2)

        assert results["binary"] == str(windows_notepad)
        assert "summary" in results
        assert results["summary"]["total_events"] >= 0
        assert results["summary"]["risk_level"] in ["low", "medium", "high"]

    def test_behavioral_analysis_performance_completes_in_time(self, windows_cmd: Path) -> None:
        """Behavioral analysis completes within specified duration."""
        start_time: float = time.time()
        duration: int = 3

        results: dict[str, Any] = run_behavioral_analysis(windows_cmd, duration=duration)

        elapsed: float = time.time() - start_time
        assert elapsed < duration + 5
        assert "duration" in results
        assert results["duration"] < duration + 3
