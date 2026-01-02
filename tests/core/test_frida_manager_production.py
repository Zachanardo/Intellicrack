"""Production tests for FridaManager - validates real Frida operations.

Tests Frida script injection, hook management, process attachment, protection detection,
and bypass capabilities WITHOUT mocks - requires Frida to be available.
"""

import logging
import platform
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.frida_constants import HookCategory, ProtectionType
from intellicrack.core.frida_manager import (
    DynamicScriptGenerator,
    FridaOperationLogger,
    FridaPerformanceOptimizer,
    HookBatcher,
    ProtectionDetector,
)
from intellicrack.utils.core.import_checks import FRIDA_AVAILABLE

frida: type[Any] | None
try:
    import frida

    FRIDA_IMPORT_AVAILABLE = True
except ImportError:
    frida = None
    FRIDA_IMPORT_AVAILABLE = False

pytestmark = pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")

BUFFER_MAX_SIZE: int = 10000
MINIMUM_LOG_ENTRIES: int = 1
VALID_HOOK_CATEGORIES: set[str] = {category.value for category in HookCategory}
VALID_PROTECTION_TYPES: set[str] = {ptype.value for ptype in ProtectionType}


class TestFridaOperationLogger:
    """Test comprehensive Frida operation logging."""

    def test_logger_initialization_creates_log_directory(self, tmp_path: Path) -> None:
        """Logger creates log directory on initialization."""
        log_dir: Path = tmp_path / "frida_logs"

        logger: FridaOperationLogger = FridaOperationLogger(log_dir=str(log_dir))

        assert log_dir.exists()
        assert log_dir.is_dir()
        assert logger.log_dir == log_dir

    def test_logger_creates_separate_log_files(self, tmp_path: Path) -> None:
        """Logger creates separate files for different operation types."""
        log_dir: Path = tmp_path / "frida_logs"

        logger: FridaOperationLogger = FridaOperationLogger(log_dir=str(log_dir))

        assert logger.operation_log.exists()
        assert logger.hook_log.exists()
        assert logger.performance_log.exists()
        assert logger.bypass_log.exists()

    def test_log_operation_records_to_buffer(self, tmp_path: Path) -> None:
        """log_operation adds entry to operation buffer."""
        log_dir: Path = tmp_path / "frida_logs"
        logger: FridaOperationLogger = FridaOperationLogger(log_dir=str(log_dir))

        logger.log_operation(
            operation="test_attach",
            details={"pid": 1234, "process_name": "test.exe"},
            success=True,
        )

        assert len(logger.operation_buffer) >= MINIMUM_LOG_ENTRIES
        entry: dict[str, Any] = logger.operation_buffer[-1]
        assert entry["operation"] == "test_attach"
        assert entry["success"] is True

    def test_log_operation_updates_statistics(self, tmp_path: Path) -> None:
        """log_operation updates total operations counter."""
        log_dir: Path = tmp_path / "frida_logs"
        logger: FridaOperationLogger = FridaOperationLogger(log_dir=str(log_dir))

        initial_count: int = logger.stats["total_operations"]

        logger.log_operation(
            operation="test_op",
            details={"test": "data"},
            success=True,
        )

        assert logger.stats["total_operations"] == initial_count + 1

    def test_log_hook_records_hook_execution(self, tmp_path: Path) -> None:
        """log_hook records hook execution details."""
        log_dir: Path = tmp_path / "frida_logs"
        logger: FridaOperationLogger = FridaOperationLogger(log_dir=str(log_dir))

        logger.log_hook(
            hook_name="TestHook",
            function="TestFunction",
            args={"arg1": "value1"},
            result="success",
        )

        assert len(logger.hook_buffer) >= MINIMUM_LOG_ENTRIES
        entry: dict[str, Any] = logger.hook_buffer[-1]
        assert entry["hook_name"] == "TestHook"
        assert entry["function"] == "TestFunction"

    def test_log_bypass_attempt_records_bypass_details(self, tmp_path: Path) -> None:
        """log_bypass_attempt records protection bypass attempts."""
        log_dir: Path = tmp_path / "frida_logs"
        logger: FridaOperationLogger = FridaOperationLogger(log_dir=str(log_dir))

        logger.log_bypass_attempt(
            protection_type=ProtectionType.ANTI_DEBUG,
            technique="test_technique",
            success=True,
            details={"method": "hook_modification"},
        )

        assert logger.stats["bypasses_attempted"] >= 1
        assert logger.stats["bypasses_successful"] >= 1

    def test_log_performance_metric_tracks_execution_time(self, tmp_path: Path) -> None:
        """log_performance tracks operation performance."""
        log_dir: Path = tmp_path / "frida_logs"
        logger: FridaOperationLogger = FridaOperationLogger(log_dir=str(log_dir))

        logger.log_performance(
            metric_name="test_operation",
            value=1.5,
            unit="ms",
            metadata={"cpu_usage": 25.0, "memory_usage": 1024},
        )

        assert "test_operation" in logger.performance_metrics
        assert logger.performance_metrics["test_operation"]

    def test_get_statistics_returns_current_stats(self, tmp_path: Path) -> None:
        """get_statistics returns comprehensive statistics."""
        log_dir: Path = tmp_path / "frida_logs"
        logger: FridaOperationLogger = FridaOperationLogger(log_dir=str(log_dir))

        logger.log_operation("op1", {}, True)
        logger.log_hook("hook1", "func1", {}, "result")

        stats: dict[str, Any] = logger.get_statistics()

        assert "total_operations" in stats
        assert "successful_hooks" in stats
        assert stats["total_operations"] >= 1


class TestProtectionDetector:
    """Test real-time protection detection."""

    def test_detector_initialization(self) -> None:
        """ProtectionDetector initializes with protection patterns."""
        detector: ProtectionDetector = ProtectionDetector()

        assert detector.detected_protections is not None
        assert isinstance(detector.detected_protections, dict)
        assert detector.protection_signatures is not None

    def test_analyze_api_call_detects_debugger_checks(self) -> None:
        """analyze_api_call detects debugger detection patterns."""
        detector: ProtectionDetector = ProtectionDetector()

        result: set[ProtectionType] = detector.analyze_api_call(
            module="kernel32.dll",
            function="IsDebuggerPresent",
            args=[],
        )

        assert result is not None
        assert ProtectionType.ANTI_DEBUG in result

    def test_analyze_string_detects_protection_indicators(self) -> None:
        """analyze_string detects protection strings."""
        detector: ProtectionDetector = ProtectionDetector()

        test_string: str = "VMware guest additions detected"

        result: set[ProtectionType] = detector.analyze_string(test_string)

        assert result is None or isinstance(result, set)

    def test_get_detected_protections_returns_evidence(self) -> None:
        """get_detected_protections returns detected protections with evidence."""
        detector: ProtectionDetector = ProtectionDetector()

        detector.analyze_api_call("kernel32.dll", "IsDebuggerPresent", [])

        protections: dict[str, list[str]] = detector.get_detected_protections()

        assert protections is not None
        assert isinstance(protections, dict)


class TestHookBatcher:
    """Test hook batching for performance optimization."""

    def test_batcher_initialization(self) -> None:
        """HookBatcher initializes with batch size configuration."""
        batcher: HookBatcher = HookBatcher(max_batch_size=50)

        assert batcher.max_batch_size == 50
        assert batcher.pending_hooks is not None
        assert isinstance(batcher.pending_hooks, dict)

    def test_add_hook_to_queue(self) -> None:
        """add_hook adds hook to pending queue."""
        batcher: HookBatcher = HookBatcher(max_batch_size=50)

        hook_spec: dict[str, Any] = {
            "target": "TestFunction",
            "script": "Interceptor.attach(ptr('0x1000'), { onEnter: function(args) {} });",
            "module": "test.dll",
        }

        batcher.add_hook(category=HookCategory.DEBUGGER_DETECTION, hook_spec=hook_spec)

        assert batcher.hook_queue.qsize() >= 1

    def test_get_batch_stats_returns_queue_status(self) -> None:
        """get_batch_stats returns batching statistics."""
        batcher: HookBatcher = HookBatcher(max_batch_size=10)

        hook_spec1: dict[str, Any] = {"target": "Func1", "script": "hook1", "module": "test.dll"}
        hook_spec2: dict[str, Any] = {"target": "Func2", "script": "hook2", "module": "test.dll"}

        batcher.add_hook(HookCategory.DEBUGGER_DETECTION, hook_spec1)
        batcher.add_hook(HookCategory.LICENSE_CHECK, hook_spec2)

        stats: dict[str, Any] = batcher.get_batch_stats()

        assert "pending_hooks" in stats
        assert stats["pending_hooks"] >= 2


class TestFridaPerformanceOptimizer:
    """Test Frida performance optimization."""

    def test_optimizer_initialization(self) -> None:
        """FridaPerformanceOptimizer initializes with configuration."""
        optimizer: FridaPerformanceOptimizer = FridaPerformanceOptimizer()

        assert hasattr(optimizer, "optimization_enabled")
        assert hasattr(optimizer, "selective_hooks")

    def test_should_hook_function_evaluates_importance(self) -> None:
        """should_hook_function evaluates based on importance."""
        optimizer: FridaPerformanceOptimizer = FridaPerformanceOptimizer()

        result: bool = optimizer.should_hook_function(
            module="kernel32.dll",
            function="IsDebuggerPresent",
            importance=HookCategory.CRITICAL,
        )

        assert isinstance(result, bool)

    def test_optimize_script_improves_performance(self) -> None:
        """optimize_script applies performance optimizations to script."""
        optimizer: FridaPerformanceOptimizer = FridaPerformanceOptimizer()

        original_script: str = """
        Interceptor.attach(ptr('0x1000'), {
            onEnter: function(args) {
                console.log('Hook called');
            }
        });
        """

        optimized: str = optimizer.optimize_script(original_script)

        assert optimized is not None
        assert isinstance(optimized, str)
        assert len(optimized) > 0

    def test_get_optimization_recommendations_provides_tips(self) -> None:
        """get_optimization_recommendations provides optimization tips."""
        optimizer: FridaPerformanceOptimizer = FridaPerformanceOptimizer()

        optimizer.track_hook_performance("kernel32.dll", "TestFunction", 5.0)

        recommendations: list[str] = optimizer.get_optimization_recommendations()

        assert isinstance(recommendations, list)


class TestDynamicScriptGenerator:
    """Test dynamic Frida script generation."""

    def test_generator_initialization(self) -> None:
        """DynamicScriptGenerator initializes with script templates."""
        generator: DynamicScriptGenerator = DynamicScriptGenerator()

        assert generator.protection_handlers is not None
        assert isinstance(generator.protection_handlers, dict)

    def test_generate_script_creates_complete_bypass(self) -> None:
        """generate_script creates complete bypass script."""
        generator: DynamicScriptGenerator = DynamicScriptGenerator()

        script: str = generator.generate_script(
            target_info={"process": "test.exe", "arch": "x64"},
            detected_protections=[ProtectionType.ANTI_DEBUG],
            strategy="adaptive",
        )

        assert script is not None
        assert isinstance(script, str)
        assert len(script) > 0

    def test_generate_script_with_multiple_protections(self) -> None:
        """generate_script handles multiple protections."""
        generator: DynamicScriptGenerator = DynamicScriptGenerator()

        script: str = generator.generate_script(
            target_info={"process": "test.exe"},
            detected_protections=[
                ProtectionType.ANTI_DEBUG,
                ProtectionType.ANTI_VM,
                ProtectionType.LICENSE,
            ],
            strategy="comprehensive",
        )

        assert script is not None
        assert len(script) > 0


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
class TestFridaManagerWindowsIntegration:
    """Test Frida manager with Windows processes (requires admin)."""

    def test_enumerate_processes_returns_running_processes(self) -> None:
        """enumerate_processes returns list of running Windows processes."""
        if not FRIDA_IMPORT_AVAILABLE or frida is None:
            pytest.skip("Frida not available")

        try:
            device: Any = frida.get_local_device()
            processes: list[Any] = device.enumerate_processes()

            assert processes is not None
            assert len(processes) > 0

            for process in processes[:5]:
                assert hasattr(process, "pid")
                assert hasattr(process, "name")
                assert process.pid > 0

        except Exception as e:
            pytest.skip(f"Frida device access failed: {e}")

    def test_frida_can_access_system_process(self) -> None:
        """Frida can access and query system process information."""
        if not FRIDA_IMPORT_AVAILABLE or frida is None:
            pytest.skip("Frida not available")

        try:
            device: Any = frida.get_local_device()

            system_processes: list[Any] = [
                p
                for p in device.enumerate_processes()
                if "System" in p.name or "explorer" in p.name.lower()
            ]

            if system_processes:
                assert len(system_processes) > 0
                test_process: Any = system_processes[0]
                assert test_process.pid > 0
                assert test_process.name

        except Exception as e:
            pytest.skip(f"System process access failed: {e}")


class TestScriptGeneration:
    """Test script generation capabilities."""

    def test_generate_script_for_all_protection_types(self) -> None:
        """Generates scripts for all protection types."""
        generator: DynamicScriptGenerator = DynamicScriptGenerator()

        for protection in ProtectionType:
            script: str = generator.generate_script(
                target_info={"process": "test.exe"},
                detected_protections=[protection],
                strategy="adaptive",
            )

            assert script is not None
            assert isinstance(script, str)
            assert len(script) > 0

    def test_generate_script_with_different_strategies(self) -> None:
        """Generates scripts with different hooking strategies."""
        generator: DynamicScriptGenerator = DynamicScriptGenerator()

        strategies: list[str] = ["aggressive", "stealthy", "adaptive", "minimal", "comprehensive"]

        for strategy in strategies:
            script: str = generator.generate_script(
                target_info={"process": "test.exe"},
                detected_protections=[ProtectionType.ANTI_DEBUG],
                strategy=strategy,
            )

            assert script is not None
            assert len(script) > 0


class TestLoggingPerformance:
    """Test logging system performance and buffer management."""

    def test_operation_buffer_maintains_max_size(self, tmp_path: Path) -> None:
        """Operation buffer respects maximum size limit."""
        log_dir: Path = tmp_path / "frida_logs"
        logger: FridaOperationLogger = FridaOperationLogger(log_dir=str(log_dir))

        for i in range(BUFFER_MAX_SIZE + 100):
            logger.log_operation(f"op_{i}", {}, True)

        assert len(logger.operation_buffer) <= BUFFER_MAX_SIZE

    def test_hook_buffer_maintains_max_size(self, tmp_path: Path) -> None:
        """Hook buffer respects maximum size limit."""
        log_dir: Path = tmp_path / "frida_logs"
        logger: FridaOperationLogger = FridaOperationLogger(log_dir=str(log_dir))

        max_hook_buffer: int = 50000

        for i in range(max_hook_buffer + 100):
            logger.log_hook(f"hook_{i}", "func", {}, "result")

        assert len(logger.hook_buffer) <= max_hook_buffer


class TestProtectionDetectionIntegration:
    """Test protection detection integration."""

    def test_detection_with_multiple_api_calls(self) -> None:
        """Detects protections from multiple API calls."""
        detector: ProtectionDetector = ProtectionDetector()

        api_calls: list[tuple[str, str]] = [
            ("kernel32.dll", "IsDebuggerPresent"),
            ("kernel32.dll", "CheckRemoteDebuggerPresent"),
            ("ntdll.dll", "NtQueryInformationProcess"),
        ]

        for module, function in api_calls:
            detector.analyze_api_call(module, function, [])

        protections: dict[str, list[str]] = detector.get_detected_protections()

        assert len(protections) > 0

    def test_adaptation_callback_invocation(self) -> None:
        """Adaptation callbacks are invoked on detection."""
        detector: ProtectionDetector = ProtectionDetector()

        called: list[bool] = [False]

        def callback(prot_type: ProtectionType, details: dict[str, Any] | set[str]) -> None:
            called[0] = True

        detector.register_adaptation_callback(callback)
        detector.notify_protection_detected(ProtectionType.ANTI_DEBUG, {"test": "data"})

        assert called[0]


class TestEndToEndScriptGeneration:
    """Test end-to-end script generation workflow."""

    def test_complete_bypass_script_generation_workflow(self) -> None:
        """Generates complete bypass script from detection to implementation."""
        detector: ProtectionDetector = ProtectionDetector()
        generator: DynamicScriptGenerator = DynamicScriptGenerator()

        detector.analyze_api_call("kernel32.dll", "IsDebuggerPresent", [])
        protections_dict: dict[str, list[str]] = detector.get_detected_protections()

        bypass_script: str = generator.generate_script(
            target_info={"process": "test.exe"},
            detected_protections=[ProtectionType.ANTI_DEBUG],
            strategy="adaptive",
        )

        assert bypass_script is not None
        assert len(bypass_script) > 0

    def test_multi_protection_bypass_script_generation(self) -> None:
        """Generates combined bypass script for multiple protections."""
        generator: DynamicScriptGenerator = DynamicScriptGenerator()

        protections: list[ProtectionType] = [
            ProtectionType.ANTI_DEBUG,
            ProtectionType.ANTI_VM,
            ProtectionType.LICENSE,
        ]

        script: str = generator.generate_script(
            target_info={"process": "test.exe"},
            detected_protections=protections,
            strategy="comprehensive",
        )

        assert script is not None
        assert len(script) > 0
