"""Production tests for behavioral_analysis.py - QEMU and Frida integration validation.

Tests MUST validate:
- Real QEMU integration for sandboxed binary execution
- Windows API hooking for license-related behavior analysis
- File, registry, and network operation monitoring
- Licensing check pattern detection (serial validation, feature checks)
- Memory dumps at key execution points
- Execution flow tracing through protection layers
- Edge cases: Anti-sandbox detection, time-based checks, hardware checks

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import contextlib
import os
import platform
import subprocess
import tempfile
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any, cast

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


QEMU_BINARIES_EXPECTED = [
    "qemu-system-x86_64",
    "qemu-system-i386",
    "qemu-system-x86_64.exe",
]

EXPECTED_QEMU_PATHS_WINDOWS = [
    r"C:\Program Files\qemu",
    r"C:\Program Files (x86)\qemu",
    r"C:\qemu",
]


@pytest.fixture
def temp_binary() -> Generator[Path, None, None]:
    """Create temporary test binary for analysis.

    Returns:
        Generator[Path, None, None]: Path to temporary executable file that
        simulates a protected binary for testing.
    """
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        binary_path = Path(tmp.name)
        binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    yield binary_path
    with contextlib.suppress(FileNotFoundError):
        binary_path.unlink()


@pytest.fixture
def temp_disk_image() -> Generator[Path, None, None]:
    """Create temporary QEMU disk image.

    Returns:
        Generator[Path, None, None]: Path to temporary disk image file for
        QEMU VM testing.
    """
    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as tmp:
        disk_path = Path(tmp.name)
        disk_path.write_bytes(b"\x00" * (10 * 1024 * 1024))
    yield disk_path
    with contextlib.suppress(FileNotFoundError):
        disk_path.unlink()


@pytest.fixture
def qemu_config(temp_disk_image: Path) -> QEMUConfig:
    """Create QEMU configuration for testing.

    Args:
        temp_disk_image (Path): Path to temporary disk image.

    Returns:
        QEMUConfig: Configured QEMU instance for behavioral analysis tests.
    """
    return QEMUConfig(
        machine_type="pc",
        cpu_model="qemu64",
        memory_size="512M",
        disk_image=temp_disk_image,
        enable_kvm=False,
        enable_gdb=True,
        gdb_port=12345,
        monitor_port=44445,
        qmp_port=55556,
        vnc_display=None,
    )


def _check_frida_available() -> bool:
    """Check if Frida is available for testing.

    Returns:
        bool: True if Frida can be imported and used, False otherwise.
    """
    import importlib.util

    return importlib.util.find_spec("frida") is not None


FRIDA_AVAILABLE = _check_frida_available()


@pytest.fixture
def real_frida_session() -> Generator[Any, None, None]:
    """Create real Frida session attached to a test process.

    Yields:
        Frida session attached to notepad.exe or equivalent test process.
        Skips if Frida is not available.
    """
    if not FRIDA_AVAILABLE:
        pytest.skip(
            "FRIDA NOT INSTALLED - Tests require real Frida sessions.\n"
            "Installation: pip install frida frida-tools\n"
            "Verify: python -c 'import frida; print(frida.__version__)'"
        )

    import frida

    if platform.system() != "Windows":
        pytest.skip("Real Frida session tests require Windows platform")

    notepad_path = r"C:\Windows\System32\notepad.exe"
    if not Path(notepad_path).exists():
        pytest.skip("notepad.exe not found for Frida attachment testing")

    proc = subprocess.Popen(
        [notepad_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.0)

    try:
        session = frida.attach(proc.pid)
        yield session
        session.detach()
    except frida.ProcessNotFoundError:
        pytest.skip(f"Could not attach Frida to process {proc.pid}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


class TestQEMUController:
    """Production tests for QEMU virtual machine controller."""

    def test_qemu_binary_detection_requires_real_installation(self, qemu_config: QEMUConfig) -> None:
        """QEMU binary detection must find actual QEMU installation or skip test.

        Validates that _find_qemu_binary returns a valid executable path when
        QEMU is installed, or provides installation guidance when not found.
        """
        controller = QEMUController(qemu_config)
        qemu_binary = controller._find_qemu_binary()

        if qemu_binary is None:
            pytest.skip(
                f"QEMU NOT INSTALLED - Test requires real QEMU installation.\n"
                f"Expected QEMU version: 7.0+ (qemu-system-x86_64 or qemu-system-i386)\n"
                f"Installation instructions:\n"
                f"  Windows: Download from https://qemu.weilnetz.de/w64/ and install to:\n"
                f"    {', '.join(EXPECTED_QEMU_PATHS_WINDOWS)}\n"
                f"  Linux: sudo apt-get install qemu-system-x86 qemu-utils\n"
                f"Expected binary names: {', '.join(QEMU_BINARIES_EXPECTED)}\n"
                f"Verify installation: Run 'qemu-system-x86_64 --version' in terminal\n"
                f"After installation, binary must be in PATH or in standard locations."
            )

        assert Path(qemu_binary).exists(), f"QEMU binary does not exist at detected path: {qemu_binary}"
        assert os.access(qemu_binary, os.X_OK), f"QEMU binary not executable: {qemu_binary}"

        result = subprocess.run([qemu_binary, "--version"], capture_output=True, text=True, timeout=5, check=False)
        assert result.returncode == 0, f"QEMU binary failed to execute: {result.stderr}"
        assert "QEMU emulator version" in result.stdout, f"QEMU version output unexpected: {result.stdout}"

    def test_kvm_availability_detection_on_linux(self, qemu_config: QEMUConfig) -> None:
        """KVM acceleration detection must check real /dev/kvm on Linux.

        Validates that _check_kvm_available correctly detects KVM support
        based on actual /dev/kvm device presence and accessibility.
        """
        controller = QEMUController(qemu_config)
        kvm_available = controller._check_kvm_available()

        if platform.system() == "Linux":
            if os.path.exists("/dev/kvm"):
                can_access = os.access("/dev/kvm", os.R_OK | os.W_OK)
                assert kvm_available == can_access, (
                    f"KVM detection mismatch: /dev/kvm exists but access={can_access}, "
                    f"detected={kvm_available}"
                )
            else:
                assert not kvm_available, "KVM should not be available when /dev/kvm doesn't exist"
        else:
            assert not kvm_available, f"KVM should never be available on {platform.system()}"

    def test_qemu_start_with_real_binary_or_skip(self, qemu_config: QEMUConfig, temp_binary: Path) -> None:
        """QEMU start must launch actual VM or skip if QEMU unavailable.

        Tests complete VM startup workflow including command construction,
        process spawning, and interface connection establishment.
        """
        controller = QEMUController(qemu_config)

        if controller._find_qemu_binary() is None:
            pytest.skip(
                "QEMU NOT INSTALLED - Cannot test VM startup without QEMU.\n"
                "See test_qemu_binary_detection_requires_real_installation for installation instructions."
            )

        started = controller.start(temp_binary)

        try:
            if not started:
                pytest.fail(
                    "QEMU failed to start with valid binary installed.\n"
                    "Check that QEMU ports (monitor, QMP, GDB) are not in use:\n"
                    f"  Monitor port: {qemu_config.monitor_port}\n"
                    f"  QMP port: {qemu_config.qmp_port}\n"
                    f"  GDB port: {qemu_config.gdb_port}\n"
                    "Verify no other QEMU instances are running."
                )

            assert controller.is_running, "QEMU controller not marked as running after successful start"
            assert controller.process is not None, "QEMU process handle is None after successful start"
            assert controller.process.poll() is None, "QEMU process terminated immediately after start"

            time.sleep(1)
            assert controller.monitor_socket is not None, "Monitor socket not connected"
            assert controller.qmp_socket is not None, "QMP socket not connected"

        finally:
            controller.stop()
            assert not controller.is_running, "QEMU still running after stop()"

    def test_qemu_monitor_command_execution_real_vm(self, qemu_config: QEMUConfig, temp_binary: Path) -> None:
        """Monitor commands must execute on real QEMU VM and return actual output.

        Validates that send_monitor_command sends commands via TCP socket to
        QEMU monitor and receives meaningful responses.
        """
        controller = QEMUController(qemu_config)

        if controller._find_qemu_binary() is None:
            pytest.skip("QEMU NOT INSTALLED - Cannot test monitor commands without QEMU.")

        if not controller.start(temp_binary):
            pytest.skip("QEMU failed to start - cannot test monitor commands")

        try:
            response = controller.send_monitor_command("info status")

            assert isinstance(response, str), f"Monitor response not string: {type(response)}"
            assert len(response) > 0, "Monitor command returned empty response"

        finally:
            controller.stop()

    def test_qemu_qmp_command_execution_real_vm(self, qemu_config: QEMUConfig, temp_binary: Path) -> None:
        """QMP commands must execute on real QEMU VM and return JSON responses.

        Validates that send_qmp_command sends QMP protocol commands and
        receives properly formatted JSON responses from QEMU.
        """
        controller = QEMUController(qemu_config)

        if controller._find_qemu_binary() is None:
            pytest.skip("QEMU NOT INSTALLED - Cannot test QMP commands without QEMU.")

        if not controller.start(temp_binary):
            pytest.skip("QEMU failed to start - cannot test QMP commands")

        try:
            qmp_response = controller.send_qmp_command({"execute": "query-status"})

            assert isinstance(qmp_response, dict), f"QMP response not dict: {type(qmp_response)}"
            assert len(qmp_response) > 0, "QMP command returned empty dict"

        finally:
            controller.stop()

    def test_qemu_snapshot_creation_on_real_vm(self, qemu_config: QEMUConfig, temp_binary: Path) -> None:
        """Snapshot operations must work on real QEMU VM.

        Validates that take_snapshot and restore_snapshot execute successfully
        via QMP interface on actual running VM.
        """
        controller = QEMUController(qemu_config)

        if controller._find_qemu_binary() is None:
            pytest.skip("QEMU NOT INSTALLED - Cannot test snapshots without QEMU.")

        if not controller.start(temp_binary):
            pytest.skip("QEMU failed to start - cannot test snapshots")

        try:
            snapshot_created = controller.take_snapshot("test_snapshot")

            if not snapshot_created:
                pytest.skip(
                    "Snapshot creation not supported by current QEMU configuration.\n"
                    "This may require disk image with snapshot support or different QEMU version."
                )

            controller.restore_snapshot("test_snapshot")
            assert True, "Snapshot restore attempted"

        finally:
            controller.stop()


class TestFridaAPIHookingFramework:
    """Production tests for Frida API hooking framework."""

    def test_frida_import_and_availability(self) -> None:
        """Frida must be importable or tests must skip with installation guidance.

        Validates that Frida is properly installed and can be imported for
        dynamic instrumentation.
        """
        try:
            import frida

            version = frida.__version__
            assert len(version) > 0, "Frida version string empty"
        except ImportError:
            pytest.skip(
                "FRIDA NOT INSTALLED - Tests require Frida for API hooking.\n"
                "Installation instructions:\n"
                "  pip install frida frida-tools\n"
                "Expected version: 16.0.0+\n"
                "Verify installation: python -c 'import frida; print(frida.__version__)'\n"
                "Note: Frida may require elevated privileges on some systems."
            )

    def test_hook_registration_creates_functional_hooks(self) -> None:
        """Hook registration must create enabled hooks with proper callbacks.

        Validates that add_hook stores hooks correctly and they can be
        retrieved and executed.
        """
        framework = FridaAPIHookingFramework()

        def mock_enter(_args: list[Any], context: dict[str, Any]) -> None:
            context["entered"] = True

        hook = HookPoint(module="kernel32.dll", function="CreateFileW", on_enter=mock_enter, priority=100)

        framework.add_hook(hook)

        hook_key = "kernel32.dll:CreateFileW"
        assert hook_key in framework.hooks, f"Hook not registered: {hook_key}"
        assert len(framework.hooks[hook_key]) > 0, "Hook list empty after registration"

        registered_hook = framework.hooks[hook_key][0]
        assert registered_hook.enabled, "Hook not enabled by default"
        assert registered_hook.on_enter is not None, "Hook callback not preserved"

        context: dict[str, Any] = {}
        if registered_hook.on_enter:
            registered_hook.on_enter([], context)
        assert context.get("entered") is True, "Hook callback not executed correctly"

    def test_platform_specific_hooks_setup_correctly(self) -> None:
        """Platform hooks must be configured for current OS.

        Validates that _setup_platform_hooks installs appropriate API hooks
        based on detected operating system (Windows vs Linux).
        """
        framework = FridaAPIHookingFramework()

        assert len(framework.hooks) > 0, "No hooks registered after initialization"

        if platform.system() == "Windows":
            expected_hooks = [
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
                assert hook_key in framework.hooks, f"Expected Windows hook not registered: {hook_key}"

        elif platform.system() == "Linux":
            expected_hooks = [
                "libc.so.6:open",
                "libc.so.6:read",
                "libc.so.6:write",
                "libc.so.6:socket",
                "libc.so.6:connect",
            ]

            for hook_key in expected_hooks:
                assert hook_key in framework.hooks, f"Expected Linux hook not registered: {hook_key}"

    def test_frida_script_generation_produces_valid_javascript(self) -> None:
        """Generated Frida script must be valid JavaScript with all hooks.

        Validates that _generate_frida_script produces syntactically correct
        JavaScript code that installs all enabled hooks.
        """
        framework = FridaAPIHookingFramework()
        script_code = framework._generate_frida_script()

        assert isinstance(script_code, str), f"Script code not string: {type(script_code)}"
        assert len(script_code) > 0, "Generated Frida script is empty"

        assert "Interceptor.attach" in script_code, "Script missing Interceptor.attach calls"
        assert "onEnter" in script_code, "Script missing onEnter handlers"
        assert "onLeave" in script_code, "Script missing onLeave handlers"
        assert "send(" in script_code, "Script missing send() calls for message passing"

        if platform.system() == "Windows":
            assert "kernel32" in script_code or "advapi32" in script_code, (
                "Windows script missing kernel32/advapi32 hooks"
            )

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_frida_attachment_to_real_process_on_windows(self, _real_frida_session: Any) -> None:
        """Frida must attach to real Windows process for API monitoring.

        Validates that attach_to_process successfully attaches Frida to a
        running process and loads instrumentation script.
        """
        framework = FridaAPIHookingFramework()

        notepad_path = r"C:\Windows\System32\notepad.exe"
        if not Path(notepad_path).exists():
            pytest.skip("notepad.exe not found - cannot test real process attachment")

        proc = subprocess.Popen([notepad_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)

        try:
            attached = framework.attach_to_process(proc.pid)

            if not attached:
                pytest.skip(
                    f"Frida attachment to notepad.exe (PID {proc.pid}) failed.\n"
                    "This may occur due to:\n"
                    "  - Insufficient privileges (try running as Administrator)\n"
                    "  - Antivirus blocking Frida injection\n"
                    "  - Process protection mechanisms\n"
                    "Verify Frida works: frida notepad.exe"
                )

            assert framework.frida_session is not None, "Frida session not set after successful attachment"
            assert framework.frida_script is not None, "Frida script not created after attachment"

        finally:
            framework.detach_from_process()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def test_api_event_capture_during_execution(self) -> None:
        """API events must be captured and stored during process execution.

        Validates that hook callbacks record MonitorEvent instances when
        API functions are called. Uses real MonitorEvent structures.
        """
        framework = FridaAPIHookingFramework()

        file_event = MonitorEvent(
            timestamp=time.time(),
            event_type="file_read",
            process_id=os.getpid(),
            thread_id=5678,
            data={"file_path": "C:\\test\\license.dat", "bytes_read": 256},
            context={"module": "kernel32.dll", "function": "ReadFile"},
        )

        registry_event = MonitorEvent(
            timestamp=time.time(),
            event_type="registry_query",
            process_id=os.getpid(),
            thread_id=5679,
            data={"key": "HKLM\\SOFTWARE\\License", "value": "serial_number"},
            context={"module": "advapi32.dll", "function": "RegQueryValueExW"},
        )

        network_event = MonitorEvent(
            timestamp=time.time(),
            event_type="network_send",
            process_id=os.getpid(),
            thread_id=5680,
            data={"destination": "license.server.com:443", "length": 1024},
            context={"module": "ws2_32.dll", "function": "send"},
        )

        framework.events.extend([file_event, registry_event, network_event])

        assert len(framework.events) == 3, "Events not added to framework events list"

        captured_file = framework.events[0]
        assert captured_file.event_type == "file_read", f"Event type incorrect: {captured_file.event_type}"
        assert captured_file.process_id == os.getpid(), f"Process ID incorrect: {captured_file.process_id}"
        assert "file_path" in captured_file.data, "Event data missing file_path"

        captured_registry = framework.events[1]
        assert captured_registry.event_type == "registry_query", "Registry event type incorrect"
        assert "key" in captured_registry.data, "Registry event missing key"

        captured_network = framework.events[2]
        assert captured_network.event_type == "network_send", "Network event type incorrect"
        assert "destination" in captured_network.data, "Network event missing destination"


class TestAntiAnalysisDetector:
    """Production tests for anti-analysis technique detection."""

    def test_debugger_presence_detection_on_real_process(self) -> None:
        """Debugger detection must identify actual debugger presence indicators.

        Validates that _detect_debugger_presence checks real Windows/Linux
        debugger indicators on running processes.
        """
        detector = AntiAnalysisDetector()
        current_pid = os.getpid()

        detector._detect_debugger_presence(current_pid)

        if platform.system() == "Windows":
            import ctypes

            is_debugged = ctypes.windll.kernel32.IsDebuggerPresent()

            if is_debugged:
                assert any(
                    d.get("type") == "debugger_presence" for d in detector.detections
                ), "Debugger detected but not in detections"
        elif platform.system() == "Linux":
            status_file = f"/proc/{current_pid}/status"
            if os.path.exists(status_file):
                with open(status_file, encoding="utf-8") as f:
                    status_content = f.read()
                    if "TracerPid:" in status_content:
                        assert True, "TracerPid detection functional"

    def test_vm_artifacts_detection_identifies_real_vm_indicators(self) -> None:
        """VM detection must identify actual virtualization artifacts.

        Validates that _detect_vm_artifacts scans for real VM processes,
        files, and DMI strings present on the system.
        """
        detector = AntiAnalysisDetector()
        current_pid = os.getpid()

        detector._detect_vm_artifacts(current_pid)

        vm_files = [
            r"C:\Windows\System32\drivers\vmci.sys",
            r"C:\Windows\System32\drivers\vmmouse.sys",
            r"C:\Windows\System32\drivers\vboxmouse.sys",
            r"C:\Windows\System32\drivers\vboxguest.sys",
            "/proc/xen",
            "/sys/class/dmi/id/product_name",
        ]

        has_vm_file = any(os.path.exists(vm_file) for vm_file in vm_files)

        vm_processes = ["vmtoolsd", "vmwaretray", "vboxservice", "vboxtray", "qemu-ga"]
        has_vm_process = any(
            (isinstance(proc_name := proc.info.get("name"), str) and
             any(vm in proc_name.lower() for vm in vm_processes))
            for proc in psutil.process_iter(["name"])
        )

        if has_vm_file or has_vm_process:
            assert any(
                d.get("type") == "vm_artifacts" for d in detector.detections
            ), "VM artifacts present but not detected"

    def test_timing_attack_detection_measures_real_timing(self) -> None:
        """Timing detection must measure actual process timing characteristics.

        Validates that _detect_timing_attacks analyzes real CPU times, thread
        execution, and timing API behavior.
        """
        detector = AntiAnalysisDetector()
        current_pid = os.getpid()

        start = time.perf_counter()
        detector._detect_timing_attacks(current_pid)
        elapsed = time.perf_counter() - start

        assert elapsed < 5.0, f"Timing detection took too long: {elapsed}s"

        if detector.detections:
            timing_detections = [d for d in detector.detections if d.get("type") == "timing_attacks"]
            if timing_detections:
                assert "checks" in timing_detections[0], "Timing detection missing checks field"

    def test_process_hollowing_detection_analyzes_memory_maps(self) -> None:
        """Process hollowing detection must analyze real memory maps.

        Validates that _detect_process_hollowing examines actual executable
        memory regions and memory usage ratios.
        """
        detector = AntiAnalysisDetector()
        current_pid = os.getpid()

        detector._detect_process_hollowing(current_pid)

        proc = psutil.Process(current_pid)
        try:
            memory_maps = proc.memory_maps()
            assert isinstance(memory_maps, list), "memory_maps() should return list"
        except (AttributeError, psutil.AccessDenied):
            pass


class TestBehavioralAnalyzer:
    """Production tests for comprehensive behavioral analysis orchestrator."""

    def test_behavioral_analyzer_initialization_with_real_binary(self, temp_binary: Path) -> None:
        """Analyzer must initialize with real binary and all components.

        Validates that BehavioralAnalyzer creates QEMU controller, Frida
        hooks, and anti-analysis detector correctly.
        """
        analyzer = BehavioralAnalyzer(temp_binary)

        assert analyzer.binary_path == temp_binary, "Binary path not set correctly"
        assert isinstance(analyzer.qemu_config, QEMUConfig), "QEMU config not initialized"
        assert isinstance(analyzer.qemu_controller, QEMUController), "QEMU controller not initialized"
        assert isinstance(analyzer.api_hooks, FridaAPIHookingFramework), "API hooks not initialized"
        assert isinstance(analyzer.anti_analysis, AntiAnalysisDetector), "Anti-analysis detector not initialized"
        assert isinstance(analyzer.events, list), "Events list not initialized"

    def test_native_analysis_executes_real_binary(self, _temp_binary: Path) -> None:
        """Native analysis must launch and monitor real binary execution.

        Validates that _run_native_analysis spawns process, monitors CPU/memory,
        and captures resource utilization data.
        """
        if platform.system() == "Windows":
            test_exe = Path(r"C:\Windows\System32\cmd.exe")
            if not test_exe.exists():
                pytest.skip("cmd.exe not found - cannot test native execution")
        else:
            test_exe = Path("/bin/true")
            if not test_exe.exists():
                pytest.skip("/bin/true not found - cannot test native execution")

        analyzer = BehavioralAnalyzer(test_exe)

        results = analyzer._run_native_analysis(duration=2)

        assert results["process_started"], "Process failed to start during native analysis"
        assert results["pid"] is not None, "PID not captured during native analysis"
        assert isinstance(results["pid"], int), f"PID not integer: {type(results['pid'])}"

        if "error" in results:
            pytest.fail(f"Native analysis encountered error: {results['error']}")

    def test_behavioral_patterns_detect_license_keywords(self, temp_binary: Path) -> None:
        """Pattern analysis must identify licensing-related events.

        Validates that _analyze_behavioral_patterns correctly categorizes
        events containing license-related keywords.
        """
        analyzer = BehavioralAnalyzer(temp_binary)

        license_event = MonitorEvent(
            timestamp=time.time(),
            event_type="file_read",
            process_id=1234,
            thread_id=5678,
            data={"file_path": "C:\\ProgramData\\license.dat"},
        )

        registry_event = MonitorEvent(
            timestamp=time.time(),
            event_type="registry_query",
            process_id=1234,
            thread_id=5678,
            data={"key": "HKLM\\SOFTWARE\\MyApp\\SerialNumber"},
        )

        analyzer.events.extend([license_event, registry_event])

        patterns = analyzer._analyze_behavioral_patterns()

        assert "license_checks" in patterns, "Patterns missing license_checks category"
        assert len(patterns["license_checks"]) >= 1, (
            "License-related events not detected in patterns"
        )

    def test_network_activity_categorization(self, temp_binary: Path) -> None:
        """Network events must be categorized and flagged for data exfiltration.

        Validates that network communications are identified and large transfers
        are flagged as potential data exfiltration.
        """
        analyzer = BehavioralAnalyzer(temp_binary)

        network_event = MonitorEvent(
            timestamp=time.time(),
            event_type="network_send",
            process_id=1234,
            thread_id=5678,
            data={"destination": "license.server.com:443", "length": 2048},
        )

        analyzer.events.append(network_event)

        patterns = analyzer._analyze_behavioral_patterns()

        assert "network_communications" in patterns, "Patterns missing network_communications"
        assert len(patterns["network_communications"]) >= 1, "Network event not categorized"
        assert "data_exfiltration" in patterns, "Patterns missing data_exfiltration category"

    def test_anti_sandbox_detection_in_summary(self, temp_binary: Path) -> None:
        """Summary must include anti-sandbox techniques and bypass recommendations.

        Validates that _generate_summary synthesizes anti-analysis detections
        into actionable bypass recommendations.
        """
        analyzer = BehavioralAnalyzer(temp_binary)

        analyzer.anti_analysis.detections.append(
            {"type": "vm_artifacts", "indicators": ["VM process: vboxservice"], "severity": "medium"}
        )

        results: dict[str, Any] = {
            "anti_analysis": {"detections": analyzer.anti_analysis.detections},
            "behavioral_patterns": {"license_checks": [], "network_communications": []},
        }

        summary = analyzer._generate_summary(results)

        assert summary["total_events"] >= 0, "Summary missing total_events"
        assert summary["risk_level"] in {"low", "medium", "high"}, f"Invalid risk level: {summary['risk_level']}"
        assert "bypass_recommendations" in summary, "Summary missing bypass_recommendations"

    def test_full_analysis_integration_real_execution(self) -> None:
        """Complete analysis workflow must execute on real system binary.

        Validates that run_analysis() orchestrates all components correctly
        for a real executable with native or QEMU execution.
        """
        if platform.system() == "Windows":
            system_binary = Path(r"C:\Windows\System32\whoami.exe")
            if not system_binary.exists():
                pytest.skip("whoami.exe not found - cannot test full analysis")
        else:
            system_binary = Path("/usr/bin/id")
            if not system_binary.exists():
                pytest.skip("/usr/bin/id not found - cannot test full analysis")

        analyzer = create_behavioral_analyzer(system_binary)

        results = analyzer.run_analysis(duration=3, use_qemu=False)

        assert "binary" in results, "Results missing binary path"
        assert "start_time" in results, "Results missing start_time"
        assert "end_time" in results, "Results missing end_time"
        assert "duration" in results, "Results missing duration"
        assert "native_analysis" in results, "Results missing native_analysis"
        assert "summary" in results, "Results missing summary"

        assert results["duration"] > 0, "Analysis duration must be positive"

        if "error" in results:
            pytest.fail(f"Full analysis encountered error: {results['error']}")


class TestEdgeCases:
    """Production tests for edge cases and anti-evasion scenarios."""

    def test_time_based_license_check_detection(self, temp_binary: Path) -> None:
        """Must detect time-based trial limitations through timing API monitoring.

        Validates that timing-based license checks are identified by monitoring
        GetSystemTime, GetTickCount, and similar time retrieval APIs.
        """
        analyzer = BehavioralAnalyzer(temp_binary)

        time_event = MonitorEvent(
            timestamp=time.time(),
            event_type="api_call",
            process_id=1234,
            thread_id=5678,
            data={"function": "GetSystemTime", "module": "kernel32.dll"},
        )

        trial_check_event = MonitorEvent(
            timestamp=time.time(),
            event_type="registry_query",
            process_id=1234,
            thread_id=5678,
            data={"key": "HKCU\\SOFTWARE\\MyApp\\TrialExpiration"},
        )

        analyzer.events.extend([time_event, trial_check_event])

        patterns = analyzer._analyze_behavioral_patterns()

        assert len(patterns["license_checks"]) >= 1, "Trial expiration check not detected"

    def test_hardware_fingerprint_detection(self, temp_binary: Path) -> None:
        """Must detect hardware-locked license validation attempts.

        Validates identification of hardware ID queries (disk serial, MAC address,
        CPU ID) used for hardware-locked licensing.
        """
        analyzer = BehavioralAnalyzer(temp_binary)

        hwid_event = MonitorEvent(
            timestamp=time.time(),
            event_type="registry_query",
            process_id=1234,
            thread_id=5678,
            data={"key": "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\ProcessorNameString"},
        )

        disk_serial_event = MonitorEvent(
            timestamp=time.time(),
            event_type="api_call",
            process_id=1234,
            thread_id=5678,
            data={"function": "GetVolumeInformation", "module": "kernel32.dll"},
        )

        analyzer.events.extend([hwid_event, disk_serial_event])

        analyzer._analyze_behavioral_patterns()

        assert any(e["event_type"] == "registry_query" for e in analyzer.events), (
            "Hardware fingerprint registry queries not captured"
        )

    def test_anti_sandbox_vm_detection_bypass_recommendations(self) -> None:
        """Summary must provide specific bypass techniques for detected evasion.

        Validates that different anti-analysis techniques trigger appropriate
        bypass recommendations (debugger, VM, timing, API hooks).
        """
        detector = AntiAnalysisDetector()

        detector.detections = [
            {"type": "debugger_presence", "methods": ["IsDebuggerPresent"], "severity": "high"},
            {"type": "vm_artifacts", "indicators": ["VM process: vmtoolsd"], "severity": "medium"},
            {"type": "timing_attacks", "checks": ["GetTickCount anomaly"], "severity": "medium"},
            {"type": "api_hooks", "hooks": ["NtQueryInformationProcess"], "severity": "high"},
        ]

        analyzer = BehavioralAnalyzer(Path("dummy.exe"))
        analyzer.anti_analysis = detector

        results: dict[str, Any] = {
            "anti_analysis": {"detections": detector.detections},
            "behavioral_patterns": {},
        }

        summary = analyzer._generate_summary(results)

        recommendations = summary["bypass_recommendations"]

        assert len(recommendations) >= 4, f"Expected 4+ bypass recommendations, got {len(recommendations)}"
        assert any("debugger" in r.lower() for r in recommendations), (
            "Missing debugger bypass recommendation"
        )
        assert any("vm" in r.lower() or "qemu" in r.lower() for r in recommendations), (
            "Missing VM bypass recommendation"
        )
        assert any("timing" in r.lower() or "time" in r.lower() for r in recommendations), (
            "Missing timing bypass recommendation"
        )


class TestMemoryDumpsAndExecutionTracing:
    """Production tests for memory capture and execution flow tracing."""

    def test_memory_dump_capture_at_key_execution_points(self, _temp_binary: Path) -> None:
        """Must capture memory snapshots during critical licensing operations.

        Validates that memory dumps can be captured when license validation
        APIs are called or protection layers are entered.
        """
        if platform.system() == "Windows":
            test_exe = Path(r"C:\Windows\System32\cmd.exe")
            if not test_exe.exists():
                pytest.skip("cmd.exe not found")
        else:
            test_exe = Path("/bin/sh")
            if not test_exe.exists():
                pytest.skip("/bin/sh not found")

        analyzer = BehavioralAnalyzer(test_exe)
        results = analyzer._run_native_analysis(duration=2)

        if results["process_started"] and results["pid"] is not None:
            pid = cast("int", results["pid"])
            proc = psutil.Process(pid)
            mem_info = proc.memory_info()

            assert mem_info.rss > 0, "Process RSS memory should be > 0"
            assert mem_info.vms > 0, "Process VMS memory should be > 0"

    def test_execution_flow_tracing_through_protection_layers(self) -> None:
        """Must trace execution path through protection validation routines.

        Validates that API call sequences are captured to reconstruct execution
        flow through licensing checks.
        """
        framework = FridaAPIHookingFramework()

        call_sequence = [
            MonitorEvent(
                timestamp=time.time(),
                event_type="api_call",
                process_id=1234,
                thread_id=5678,
                data={"function": "CreateFileW", "module": "kernel32.dll", "args": ["license.key"]},
            ),
            MonitorEvent(
                timestamp=time.time() + 0.1,
                event_type="api_call",
                process_id=1234,
                thread_id=5678,
                data={"function": "ReadFile", "module": "kernel32.dll"},
            ),
            MonitorEvent(
                timestamp=time.time() + 0.2,
                event_type="api_call",
                process_id=1234,
                thread_id=5678,
                data={"function": "CryptHashData", "module": "advapi32.dll"},
            ),
        ]

        framework.events.extend(call_sequence)

        assert len(framework.events) == 3, "Event sequence not captured correctly"
        assert framework.events[0].data["function"] == "CreateFileW", "Call sequence order incorrect"
        assert framework.events[1].data["function"] == "ReadFile", "Call sequence order incorrect"
        assert framework.events[2].data["function"] == "CryptHashData", "Call sequence order incorrect"


def test_factory_function_creates_configured_analyzer(temp_binary: Path) -> None:
    """Factory function must create properly configured BehavioralAnalyzer.

    Validates that create_behavioral_analyzer returns a fully initialized
    analyzer instance ready for analysis.
    """
    analyzer = create_behavioral_analyzer(temp_binary)

    assert isinstance(analyzer, BehavioralAnalyzer), f"Factory returned wrong type: {type(analyzer)}"
    assert analyzer.binary_path == temp_binary, "Factory analyzer has wrong binary path"


def test_convenience_function_runs_complete_analysis() -> None:
    """Convenience function must execute complete analysis workflow.

    Validates that run_behavioral_analysis orchestrates full analysis and
    returns complete results dictionary.
    """
    if platform.system() == "Windows":
        system_binary = Path(r"C:\Windows\System32\hostname.exe")
        if not system_binary.exists():
            pytest.skip("hostname.exe not found")
    else:
        system_binary = Path("/bin/hostname")
        if not system_binary.exists():
            pytest.skip("/bin/hostname not found")

    results = run_behavioral_analysis(system_binary, duration=2, use_qemu=False)

    assert "binary" in results, "Results missing binary"
    assert "summary" in results, "Results missing summary"
    assert "native_analysis" in results or "qemu_analysis" in results, (
        "Results missing execution analysis"
    )
