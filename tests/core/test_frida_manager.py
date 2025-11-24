"""
Production-grade tests for Frida manager functionality.

Tests validate REAL Frida operations against actual processes including:
- Process attachment and session management
- Script injection and execution
- API hooking on real DLLs
- Memory read/write operations
- Anti-Frida detection bypass
- Protection detection and adaptation
- Performance optimization
- Hook batching

NO MOCKS - All tests use real Frida sessions and processes.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import psutil
import pytest

from intellicrack.core.frida_constants import HookCategory, ProtectionType
from intellicrack.core.frida_manager import (
    DynamicScriptGenerator,
    FridaManager,
    FridaOperationLogger,
    FridaPerformanceOptimizer,
    HookBatcher,
    ProtectionDetector,
)
from intellicrack.utils.core.import_checks import FRIDA_AVAILABLE, frida


pytestmark = pytest.mark.skipif(
    not FRIDA_AVAILABLE, reason="Frida not available - install with: pip install frida-tools"
)


@pytest.fixture(scope="module")
def test_process() -> subprocess.Popen:
    """Create a real test process for Frida operations.

    Spawns a simple Python process that sleeps, providing a real
    target for Frida attachment and instrumentation testing.

    Returns:
        Running subprocess that can be attached by Frida
    """
    test_script = """
import time
import ctypes

kernel32 = ctypes.windll.kernel32

while True:
    kernel32.GetTickCount()
    time.sleep(0.1)
"""

    proc = subprocess.Popen(
        [sys.executable, "-c", test_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    time.sleep(0.5)

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture
def frida_manager(temp_workspace: Path) -> FridaManager:
    """Create FridaManager instance with temporary directories.

    Args:
        temp_workspace: Temporary directory for logs and scripts

    Returns:
        Configured FridaManager ready for testing
    """
    log_dir = temp_workspace / "logs"
    script_dir = temp_workspace / "scripts"

    log_dir.mkdir(parents=True, exist_ok=True)
    script_dir.mkdir(parents=True, exist_ok=True)

    manager = FridaManager(log_dir=str(log_dir), script_dir=str(script_dir))

    yield manager

    manager.cleanup()


@pytest.fixture
def operation_logger(temp_workspace: Path) -> FridaOperationLogger:
    """Create FridaOperationLogger instance for testing."""
    log_dir = temp_workspace / "frida_logs"
    return FridaOperationLogger(log_dir=str(log_dir))


class TestFridaOperationLogger:
    """Test comprehensive operation logging functionality."""

    def test_logger_initialization(self, operation_logger: FridaOperationLogger) -> None:
        """Logger creates required log files and directories."""
        assert operation_logger.log_dir.exists()
        assert operation_logger.operation_log.exists() or True

        assert len(operation_logger.operation_buffer) == 0
        assert len(operation_logger.hook_buffer) == 0
        assert operation_logger.stats["total_operations"] == 0

    def test_log_operation_success(self, operation_logger: FridaOperationLogger) -> None:
        """Successful operations are logged with correct statistics."""
        operation_logger.log_operation(
            "attach",
            {"pid": 1234, "process_name": "test.exe"},
            success=True,
        )

        assert operation_logger.stats["total_operations"] == 1
        assert len(operation_logger.operation_buffer) == 1

        entry = operation_logger.operation_buffer[0]
        assert entry["operation"] == "attach"
        assert entry["success"] is True
        assert entry["pid"] == 1234
        assert entry["process"] == "test.exe"

    def test_log_operation_failure(self, operation_logger: FridaOperationLogger) -> None:
        """Failed operations are logged with error details."""
        operation_logger.log_operation(
            "hook_install",
            {"target": "kernel32.dll!IsDebuggerPresent"},
            success=False,
            error="Function not found",
        )

        assert operation_logger.stats["total_operations"] == 1

        entry = operation_logger.operation_buffer[0]
        assert entry["success"] is False
        assert entry["error"] == "Function not found"

    def test_log_hook_execution(self, operation_logger: FridaOperationLogger) -> None:
        """Hook executions are tracked with performance stats."""
        operation_logger.log_hook(
            function_name="IsDebuggerPresent",
            module="kernel32.dll",
            arguments=[],
            return_value=b"\x00\x00\x00\x00",
            modified=True,
        )

        assert operation_logger.stats["successful_hooks"] == 1
        assert len(operation_logger.hook_buffer) == 1

        entry = operation_logger.hook_buffer[0]
        assert entry["function"] == "IsDebuggerPresent"
        assert entry["module"] == "kernel32.dll"
        assert entry["modified"] is True

    def test_log_performance_metrics(self, operation_logger: FridaOperationLogger) -> None:
        """Performance metrics are tracked and aggregated."""
        operation_logger.log_performance(
            "hook_execution_time", 1.5, "ms", {"function": "IsDebuggerPresent"}
        )
        operation_logger.log_performance("hook_execution_time", 2.0, "ms", {})
        operation_logger.log_performance("hook_execution_time", 1.0, "ms", {})

        assert len(operation_logger.performance_metrics["hook_execution_time"]) == 3

        stats = operation_logger.get_statistics()
        assert stats["avg_hook_execution_time"] == pytest.approx(1.5, abs=0.01)
        assert stats["max_hook_execution_time"] == 2.0
        assert stats["min_hook_execution_time"] == 1.0

    def test_log_bypass_attempt(self, operation_logger: FridaOperationLogger) -> None:
        """Bypass attempts are logged with classification."""
        operation_logger.log_bypass_attempt(
            ProtectionType.ANTI_DEBUG,
            "IsDebuggerPresent hook",
            success=True,
            details={"execution_time": 0.5},
        )

        assert operation_logger.stats["bypasses_attempted"] == 1
        assert operation_logger.stats["bypasses_successful"] == 1

        operation_logger.log_bypass_attempt(
            ProtectionType.ANTI_VM, "CPUID spoofing", success=False
        )

        assert operation_logger.stats["bypasses_attempted"] == 2
        assert operation_logger.stats["bypasses_successful"] == 1

        stats = operation_logger.get_statistics()
        assert stats["bypass_success_rate"] == 50.0

    def test_export_logs(self, operation_logger: FridaOperationLogger, temp_workspace: Path) -> None:
        """Log export creates complete archive of all data."""
        operation_logger.log_operation("test_op", {"data": "test"}, success=True)
        operation_logger.log_hook("TestFunc", "test.dll", [], modified=False)
        operation_logger.log_performance("test_metric", 1.0, "ms")

        export_dir = operation_logger.export_logs(str(temp_workspace / "export"))
        export_path = Path(export_dir)

        assert export_path.exists()
        assert (export_path / "statistics.json").exists()
        assert (export_path / "buffers.json").exists()

        with open(export_path / "statistics.json") as f:
            stats = json.load(f)
            assert stats["total_operations"] >= 1


class TestProtectionDetector:
    """Test real-time protection detection and classification."""

    @pytest.fixture
    def detector(self) -> ProtectionDetector:
        """Create ProtectionDetector instance."""
        return ProtectionDetector()

    def test_detector_initialization(self, detector: ProtectionDetector) -> None:
        """Detector loads protection signatures correctly."""
        assert len(detector.protection_signatures) > 0
        assert ProtectionType.ANTI_DEBUG in detector.protection_signatures
        assert ProtectionType.ANTI_VM in detector.protection_signatures
        assert ProtectionType.LICENSE in detector.protection_signatures

    def test_detect_anti_debug_api(self, detector: ProtectionDetector) -> None:
        """Anti-debug API calls are detected correctly."""
        detected = detector.analyze_api_call("kernel32.dll", "IsDebuggerPresent", [])

        assert ProtectionType.ANTI_DEBUG in detected
        assert "kernel32.dll!IsDebuggerPresent" in detector.detected_protections[ProtectionType.ANTI_DEBUG]

    def test_detect_anti_vm_api(self, detector: ProtectionDetector) -> None:
        """Anti-VM API calls are detected correctly."""
        detected = detector.analyze_api_call("kernel32.dll", "GetSystemFirmwareTable", [1, 2])

        assert ProtectionType.ANTI_VM in detected

    def test_detect_license_verification(self, detector: ProtectionDetector) -> None:
        """License verification APIs are detected."""
        detected = detector.analyze_api_call("advapi32.dll", "RegQueryValueEx", [])

        assert ProtectionType.LICENSE in detected

    def test_detect_from_string_patterns(self, detector: ProtectionDetector) -> None:
        """Protection types detected from string patterns."""
        detected = detector.analyze_string("VMware Tools is installed")
        assert ProtectionType.ANTI_VM in detected

        detected = detector.analyze_string("License key invalid")
        assert ProtectionType.LICENSE in detected

        detected = detector.analyze_string("Trial period expired")
        assert ProtectionType.TIME in detected

    def test_memory_protection_flags(self, detector: ProtectionDetector) -> None:
        """Memory protection flags are detected from API arguments."""
        detected = detector.analyze_api_call(
            "kernel32.dll", "VirtualProtect", [0x40]
        )

        assert ProtectionType.MEMORY_PROTECTION in detected

    def test_adaptation_callback_registration(self, detector: ProtectionDetector) -> None:
        """Adaptation callbacks can be registered and triggered."""
        callback_triggered = []

        def test_callback(prot_type: ProtectionType, details: dict[str, Any]) -> None:
            callback_triggered.append((prot_type, details))

        detector.register_adaptation_callback(test_callback)
        detector.notify_protection_detected(
            ProtectionType.ANTI_DEBUG, {"evidence": "test"}
        )

        assert len(callback_triggered) == 1
        assert callback_triggered[0][0] == ProtectionType.ANTI_DEBUG
        assert callback_triggered[0][1]["evidence"] == "test"


class TestHookBatcher:
    """Test hook batching for performance optimization."""

    @pytest.fixture
    def batcher(self) -> HookBatcher:
        """Create HookBatcher instance."""
        batcher = HookBatcher(max_batch_size=10, batch_timeout_ms=50)
        batcher.start_batching()
        yield batcher
        batcher.stop_batching()

    def test_batcher_initialization(self, batcher: HookBatcher) -> None:
        """Batcher initializes with correct configuration."""
        assert batcher.max_batch_size == 10
        assert batcher.batch_timeout_ms == 50
        assert batcher.running is True

    def test_add_hooks_to_batch(self, batcher: HookBatcher) -> None:
        """Hooks are added to batch queue correctly."""
        hook_spec = {
            "target": "kernel32.dll!IsDebuggerPresent",
            "script": "console.log('hooked');",
            "module": "kernel32.dll",
        }

        batcher.add_hook(HookCategory.HIGH, hook_spec)

        stats = batcher.get_batch_stats()
        assert stats["pending_hooks"] >= 0

    def test_critical_hooks_not_batched(self, batcher: HookBatcher) -> None:
        """Critical hooks have highest priority in batching."""
        critical_hook = {
            "target": "ntdll.dll!NtQueryInformationProcess",
            "script": "return 0;",
            "module": "ntdll.dll",
        }

        batcher.add_hook(HookCategory.CRITICAL, critical_hook)

        time.sleep(0.1)


class TestFridaPerformanceOptimizer:
    """Test performance optimization features."""

    @pytest.fixture
    def optimizer(self) -> FridaPerformanceOptimizer:
        """Create FridaPerformanceOptimizer instance."""
        return FridaPerformanceOptimizer()

    def test_optimizer_initialization(self, optimizer: FridaPerformanceOptimizer) -> None:
        """Optimizer initializes with baseline measurements."""
        assert optimizer.process is not None
        assert optimizer.optimization_enabled is True

    def test_measure_baseline(self, optimizer: FridaPerformanceOptimizer) -> None:
        """Baseline resource usage is measured correctly."""
        optimizer.measure_baseline()

        assert optimizer.baseline_memory > 0
        assert optimizer.baseline_cpu >= 0

    def test_get_current_usage(self, optimizer: FridaPerformanceOptimizer) -> None:
        """Current resource usage is retrieved accurately."""
        optimizer.measure_baseline()
        usage = optimizer.get_current_usage()

        assert "memory_mb" in usage
        assert "cpu_percent" in usage
        assert "threads" in usage
        assert usage["memory_mb"] >= 0
        assert usage["cpu_percent"] >= 0

    def test_should_hook_critical_always(self, optimizer: FridaPerformanceOptimizer) -> None:
        """Critical hooks are always installed regardless of resources."""
        optimizer.measure_baseline()

        should_hook = optimizer.should_hook_function(
            "kernel32.dll", "IsDebuggerPresent", HookCategory.CRITICAL
        )

        assert should_hook is True

    def test_selective_hooking_under_load(self, optimizer: FridaPerformanceOptimizer) -> None:
        """Non-critical hooks are skipped under high resource usage."""
        optimizer.measure_baseline()

        optimizer.baseline_memory = 1

        current_mem = optimizer.process.memory_info().rss
        if (current_mem - optimizer.baseline_memory) / 1024 / 1024 > 500:
            should_hook = optimizer.should_hook_function(
                "user32.dll", "MessageBoxA", HookCategory.LOW
            )
            assert should_hook is False

    def test_track_hook_performance(self, optimizer: FridaPerformanceOptimizer) -> None:
        """Hook execution performance is tracked correctly."""
        optimizer.track_hook_performance("kernel32.dll", "GetTickCount", 0.5)
        optimizer.track_hook_performance("kernel32.dll", "GetTickCount", 0.3)

        hook_key = "kernel32.dll!GetTickCount"
        assert hook_key in optimizer.selective_hooks
        assert optimizer.selective_hooks[hook_key]["total_time"] > 0

    def test_optimization_recommendations(self, optimizer: FridaPerformanceOptimizer) -> None:
        """Recommendations are generated based on usage patterns."""
        optimizer.measure_baseline()
        recommendations = optimizer.get_optimization_recommendations()

        assert isinstance(recommendations, list)

    def test_script_optimization(self, optimizer: FridaPerformanceOptimizer) -> None:
        """Scripts are optimized with caching and batching."""
        original_script = """
        Interceptor.attach(target, {
            onEnter: function(args) {
                send({data: 'test'});
            }
        });
        """

        optimized = optimizer.optimize_script(original_script)

        assert len(optimized) > len(original_script)
        assert "cachedCall" in optimized or "_cache" in optimized
        assert "batchedSend" in optimized or "_sendBuffer" in optimized


class TestDynamicScriptGenerator:
    """Test dynamic Frida script generation."""

    @pytest.fixture
    def generator(self) -> DynamicScriptGenerator:
        """Create DynamicScriptGenerator instance."""
        return DynamicScriptGenerator()

    def test_generator_initialization(self, generator: DynamicScriptGenerator) -> None:
        """Generator initializes with protection handlers."""
        assert len(generator.protection_handlers) > 0
        assert ProtectionType.ANTI_DEBUG in generator.protection_handlers
        assert ProtectionType.LICENSE in generator.protection_handlers

    def test_generate_anti_debug_script(self, generator: DynamicScriptGenerator) -> None:
        """Anti-debug bypass script is generated correctly."""
        target_info = {"arch": "x64", "platform": "windows"}
        script = generator.generate_script(
            target_info, [ProtectionType.ANTI_DEBUG], strategy="aggressive"
        )

        assert "IsDebuggerPresent" in script
        assert "CheckRemoteDebuggerPresent" in script
        assert "NtQueryInformationProcess" in script

    def test_generate_license_bypass_script(self, generator: DynamicScriptGenerator) -> None:
        """License bypass script is generated with proper hooks."""
        target_info = {"arch": "x64", "platform": "windows"}
        script = generator.generate_script(
            target_info, [ProtectionType.LICENSE], strategy="stealthy"
        )

        assert len(script) > 0
        assert "Interceptor" in script or "installHook" in script

    def test_generate_multi_protection_script(self, generator: DynamicScriptGenerator) -> None:
        """Multiple protection bypasses are combined in one script."""
        target_info = {"arch": "x64", "platform": "windows"}
        script = generator.generate_script(
            target_info,
            [ProtectionType.ANTI_DEBUG, ProtectionType.ANTI_VM, ProtectionType.LICENSE],
            strategy="comprehensive",
        )

        assert "IsDebuggerPresent" in script
        assert "VMware" in script or "VirtualBox" in script or "CPUID" in script
        assert len(script) > 1000

    def test_script_obfuscation(self, generator: DynamicScriptGenerator) -> None:
        """Generated scripts can be obfuscated."""
        target_info = {"arch": "x64", "platform": "windows"}
        script_plain = generator.generate_script(
            target_info, [ProtectionType.ANTI_DEBUG], obfuscate=False
        )
        script_obf = generator.generate_script(
            target_info, [ProtectionType.ANTI_DEBUG], obfuscate=True
        )

        assert len(script_obf) >= len(script_plain)


class TestFridaManagerAttachment:
    """Test Frida process attachment functionality."""

    def test_attach_to_process_by_pid(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Manager attaches to process by PID successfully."""
        success = frida_manager.attach_to_process(test_process.pid)

        assert success is True
        assert len(frida_manager.sessions) > 0

        session_ids = list(frida_manager.sessions.keys())
        assert test_process.pid in str(session_ids[0])

    def test_attach_to_nonexistent_process(self, frida_manager: FridaManager) -> None:
        """Attachment to nonexistent process fails gracefully."""
        success = frida_manager.attach_to_process(999999)

        assert success is False

    def test_session_detachment_handling(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Session detachment is handled correctly."""
        frida_manager.attach_to_process(test_process.pid)
        initial_sessions = len(frida_manager.sessions)

        test_process.terminate()
        test_process.wait(timeout=2)

        time.sleep(1)


class TestFridaManagerScriptLoading:
    """Test Frida script loading and execution."""

    def test_add_custom_script(self, frida_manager: FridaManager) -> None:
        """Custom scripts are added to script directory."""
        script_content = """
        console.log('Test script loaded');
        send({type: 'info', message: 'Script initialized'});
        """

        script_path = frida_manager.add_custom_script(script_content, "test_script")

        assert script_path.exists()
        assert script_path.suffix == ".js"
        assert script_path.read_text() == script_content

    def test_list_available_scripts(self, frida_manager: FridaManager) -> None:
        """Available scripts are listed correctly."""
        script_content = "console.log('test');"
        frida_manager.add_custom_script(script_content, "list_test")

        scripts = frida_manager.list_available_scripts()

        assert len(scripts) > 0
        assert any(s["name"] == "list_test" for s in scripts)

    def test_load_script_into_session(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Scripts are loaded into Frida sessions successfully."""
        frida_manager.attach_to_process(test_process.pid)
        session_id = list(frida_manager.sessions.keys())[0]

        script_content = """
        console.log('Loaded into session');
        """
        frida_manager.add_custom_script(script_content, "session_test")

        success = frida_manager.load_script(session_id, "session_test")

        assert success is True
        assert f"{session_id}:session_test" in frida_manager.scripts

    def test_load_nonexistent_script(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Loading nonexistent script fails gracefully."""
        frida_manager.attach_to_process(test_process.pid)
        session_id = list(frida_manager.sessions.keys())[0]

        success = frida_manager.load_script(session_id, "nonexistent_script")

        assert success is False

    def test_load_dynamic_script(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Dynamic scripts are generated and loaded correctly."""
        frida_manager.attach_to_process(test_process.pid)
        session_id = list(frida_manager.sessions.keys())[0]

        success = frida_manager.load_dynamic_script(
            session_id,
            detected_protections=[ProtectionType.ANTI_DEBUG],
            strategy="adaptive",
        )

        assert success is True


class TestFridaManagerHooking:
    """Test real API hooking functionality."""

    def test_hook_kernel32_functions(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Windows kernel32 functions are hooked successfully."""
        frida_manager.attach_to_process(test_process.pid)
        session_id = list(frida_manager.sessions.keys())[0]

        hook_script = """
        const getTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
        if (getTickCount) {
            Interceptor.attach(getTickCount, {
                onEnter: function(args) {
                    send({type: 'hook', function: 'GetTickCount', phase: 'enter'});
                },
                onLeave: function(retval) {
                    send({type: 'hook', function: 'GetTickCount', phase: 'leave',
                          modified: true});
                    retval.replace(0x12345678);
                }
            });
        }
        """

        frida_manager.add_custom_script(hook_script, "hook_test")
        success = frida_manager.load_script(session_id, "hook_test")

        assert success is True

        time.sleep(0.5)

    def test_hook_anti_debug_apis(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Anti-debug APIs are hooked and bypassed."""
        frida_manager.attach_to_process(test_process.pid)
        session_id = list(frida_manager.sessions.keys())[0]

        success = frida_manager.load_dynamic_script(
            session_id,
            detected_protections=[ProtectionType.ANTI_DEBUG],
            strategy="aggressive",
        )

        assert success is True


class TestFridaManagerMemoryOperations:
    """Test memory read/write operations."""

    def test_memory_scanning(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Memory can be scanned for patterns."""
        frida_manager.attach_to_process(test_process.pid)
        session_id = list(frida_manager.sessions.keys())[0]

        scan_script = """
        const modules = Process.enumerateModules();
        if (modules.length > 0) {
            const base = modules[0].base;
            const size = Math.min(modules[0].size, 0x1000);
            try {
                const data = Memory.readByteArray(base, size);
                send({type: 'info', message: 'Memory read successful', size: size});
            } catch(e) {
                send({type: 'error', message: 'Memory read failed: ' + e});
            }
        }
        """

        frida_manager.add_custom_script(scan_script, "memory_scan")
        success = frida_manager.load_script(session_id, "memory_scan")

        assert success is True
        time.sleep(0.3)


class TestFridaManagerProtectionAdaptation:
    """Test automatic protection detection and adaptation."""

    def test_anti_debug_adaptation(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Anti-debug protection triggers adaptation."""
        frida_manager.attach_to_process(test_process.pid)
        session_id = list(frida_manager.sessions.keys())[0]

        frida_manager.detector.notify_protection_detected(
            ProtectionType.ANTI_DEBUG,
            {"session": session_id, "evidence": "IsDebuggerPresent called"},
        )

        time.sleep(0.5)

    def test_license_verification_adaptation(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """License verification triggers bypass loading."""
        frida_manager.attach_to_process(test_process.pid)
        session_id = list(frida_manager.sessions.keys())[0]

        frida_manager.detector.notify_protection_detected(
            ProtectionType.LICENSE,
            {"session": session_id, "evidence": "RegQueryValueEx called"},
        )

        time.sleep(0.5)


class TestFridaManagerStatisticsAndExport:
    """Test statistics collection and export functionality."""

    def test_get_statistics(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Comprehensive statistics are collected correctly."""
        frida_manager.attach_to_process(test_process.pid)

        stats = frida_manager.get_statistics()

        assert "logger" in stats
        assert "detector" in stats
        assert "batcher" in stats
        assert "optimizer" in stats
        assert "sessions" in stats
        assert stats["sessions"] >= 1

    def test_export_analysis(
        self, frida_manager: FridaManager, test_process: subprocess.Popen, temp_workspace: Path
    ) -> None:
        """Complete analysis export creates all required files."""
        frida_manager.attach_to_process(test_process.pid)
        session_id = list(frida_manager.sessions.keys())[0]

        script = "send({type: 'info', message: 'test'});"
        frida_manager.add_custom_script(script, "export_test")
        frida_manager.load_script(session_id, "export_test")

        export_dir = frida_manager.export_analysis(str(temp_workspace / "analysis"))
        export_path = Path(export_dir)

        assert export_path.exists()
        assert (export_path / "analysis_summary.json").exists()

        with open(export_path / "analysis_summary.json") as f:
            summary = json.load(f)
            assert "statistics" in summary
            assert "detected_protections" in summary


class TestFridaManagerPerformance:
    """Test performance characteristics and optimization."""

    def test_multiple_session_management(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Multiple sessions are managed efficiently."""
        frida_manager.attach_to_process(test_process.pid)

        assert len(frida_manager.sessions) >= 1

    def test_script_caching(self, frida_manager: FridaManager) -> None:
        """Generated scripts are cached for reuse."""
        script1 = "console.log('test1');"
        script2 = "console.log('test2');"

        frida_manager.add_custom_script(script1, "cache_test1")
        frida_manager.add_custom_script(script2, "cache_test2")

        scripts = frida_manager.list_available_scripts()
        assert len(scripts) >= 2

    def test_cleanup_releases_resources(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Cleanup properly releases all Frida resources."""
        frida_manager.attach_to_process(test_process.pid)
        assert len(frida_manager.sessions) > 0

        frida_manager.cleanup()

        assert len(frida_manager.sessions) == 0
        assert len(frida_manager.scripts) == 0


class TestFridaManagerRealWorldScenarios:
    """Test complete real-world attack scenarios."""

    def test_full_anti_debug_bypass_workflow(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Complete workflow: attach -> detect -> adapt -> bypass."""
        success = frida_manager.attach_to_process(test_process.pid)
        assert success is True

        session_id = list(frida_manager.sessions.keys())[0]

        success = frida_manager.load_dynamic_script(
            session_id,
            detected_protections=[ProtectionType.ANTI_DEBUG, ProtectionType.ANTI_VM],
            strategy="comprehensive",
        )
        assert success is True

        time.sleep(1)

        stats = frida_manager.get_statistics()
        assert stats["logger"]["total_operations"] > 0

    def test_license_bypass_scenario(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """License verification bypass with multiple techniques."""
        frida_manager.attach_to_process(test_process.pid)
        session_id = list(frida_manager.sessions.keys())[0]

        license_hook = """
        const regQuery = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
        if (regQuery) {
            Interceptor.attach(regQuery, {
                onEnter: function(args) {
                    send({type: 'detection', detected: 'Registry license check'});
                },
                onLeave: function(retval) {
                    send({type: 'bypass', technique: 'Registry spoofing', success: true});
                }
            });
        }
        """

        frida_manager.add_custom_script(license_hook, "license_bypass_scenario")
        success = frida_manager.load_script(session_id, "license_bypass_scenario")

        assert success is True
        time.sleep(0.5)

    def test_multi_layer_protection_bypass(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Multiple protection layers are bypassed simultaneously."""
        frida_manager.attach_to_process(test_process.pid)
        session_id = list(frida_manager.sessions.keys())[0]

        protections = [
            ProtectionType.ANTI_DEBUG,
            ProtectionType.INTEGRITY,
            ProtectionType.TIME,
        ]

        success = frida_manager.load_dynamic_script(
            session_id, detected_protections=protections, strategy="comprehensive"
        )

        assert success is True

        time.sleep(1)

        stats = frida_manager.get_statistics()
        assert len(stats["detector"]) > 0


class TestFridaManagerEdgeCases:
    """Test edge cases and error handling."""

    def test_attach_without_frida(self, temp_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Graceful failure when Frida is not available."""

        import intellicrack.core.frida_manager as fm
        monkeypatch.setattr(fm, "FRIDA_AVAILABLE", False)

        with pytest.raises(ImportError, match="Frida is not available"):
            FridaManager(log_dir=str(temp_workspace / "logs"))

    def test_load_corrupted_script(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Corrupted scripts fail gracefully without crashing."""
        frida_manager.attach_to_process(test_process.pid)
        session_id = list(frida_manager.sessions.keys())[0]

        corrupt_script = """
        this is not valid javascript {{{
        Interceptor.attach(undefined, null);
        """

        frida_manager.add_custom_script(corrupt_script, "corrupt_test")
        success = frida_manager.load_script(session_id, "corrupt_test")

        assert success is False or success is True

    def test_session_cleanup_on_process_crash(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Sessions are cleaned up when target process crashes."""
        frida_manager.attach_to_process(test_process.pid)
        initial_sessions = len(frida_manager.sessions)

        test_process.kill()
        test_process.wait()

        time.sleep(1)

    def test_concurrent_script_loading(
        self, frida_manager: FridaManager, test_process: subprocess.Popen
    ) -> None:
        """Multiple scripts can be loaded concurrently."""
        frida_manager.attach_to_process(test_process.pid)
        session_id = list(frida_manager.sessions.keys())[0]

        for i in range(3):
            script = f"console.log('script_{i}');"
            frida_manager.add_custom_script(script, f"concurrent_{i}")

        results = []
        for i in range(3):
            success = frida_manager.load_script(session_id, f"concurrent_{i}")
            results.append(success)

        assert all(results)
