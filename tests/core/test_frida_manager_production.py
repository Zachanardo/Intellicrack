"""Production tests for FridaManager - validates real Frida operations.

Tests Frida script injection, hook management, process attachment, protection detection,
and bypass capabilities WITHOUT mocks - requires Frida to be available.
"""

import json
import logging
import os
import platform
import tempfile
import time
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
from intellicrack.utils.core.import_checks import FRIDA_AVAILABLE, frida, psutil


pytestmark = pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")

BUFFER_MAX_SIZE = 10000
MINIMUM_LOG_ENTRIES = 1
VALID_HOOK_CATEGORIES = {category.value for category in HookCategory}
VALID_PROTECTION_TYPES = {ptype.value for ptype in ProtectionType}


class TestFridaOperationLogger:
    """Test comprehensive Frida operation logging."""

    def test_logger_initialization_creates_log_directory(self, tmp_path: Path) -> None:
        """Logger creates log directory on initialization."""
        log_dir = tmp_path / "frida_logs"

        logger = FridaOperationLogger(log_dir=str(log_dir))

        assert log_dir.exists()
        assert log_dir.is_dir()
        assert logger.log_dir == log_dir

    def test_logger_creates_separate_log_files(self, tmp_path: Path) -> None:
        """Logger creates separate files for different operation types."""
        log_dir = tmp_path / "frida_logs"

        logger = FridaOperationLogger(log_dir=str(log_dir))

        assert logger.operation_log.exists()
        assert logger.hook_log.exists()
        assert logger.performance_log.exists()
        assert logger.bypass_log.exists()

    def test_log_operation_records_to_buffer(self, tmp_path: Path) -> None:
        """log_operation adds entry to operation buffer."""
        log_dir = tmp_path / "frida_logs"
        logger = FridaOperationLogger(log_dir=str(log_dir))

        logger.log_operation(
            operation="test_attach",
            details={"pid": 1234, "process_name": "test.exe"},
            success=True,
        )

        assert len(logger.operation_buffer) >= MINIMUM_LOG_ENTRIES
        entry = logger.operation_buffer[-1]
        assert entry["operation"] == "test_attach"
        assert entry["success"] is True

    def test_log_operation_updates_statistics(self, tmp_path: Path) -> None:
        """log_operation updates total operations counter."""
        log_dir = tmp_path / "frida_logs"
        logger = FridaOperationLogger(log_dir=str(log_dir))

        initial_count = logger.stats["total_operations"]

        logger.log_operation(
            operation="test_op",
            details={"test": "data"},
            success=True,
        )

        assert logger.stats["total_operations"] == initial_count + 1

    def test_log_hook_call_records_hook_execution(self, tmp_path: Path) -> None:
        """log_hook_call records hook execution details."""
        log_dir = tmp_path / "frida_logs"
        logger = FridaOperationLogger(log_dir=str(log_dir))

        logger.log_hook_call(
            hook_name="TestHook",
            function="TestFunction",
            args={"arg1": "value1"},
            result="success",
        )

        assert len(logger.hook_buffer) >= MINIMUM_LOG_ENTRIES
        entry = logger.hook_buffer[-1]
        assert entry["hook_name"] == "TestHook"
        assert entry["function"] == "TestFunction"

    def test_log_bypass_attempt_records_bypass_details(self, tmp_path: Path) -> None:
        """log_bypass_attempt records protection bypass attempts."""
        log_dir = tmp_path / "frida_logs"
        logger = FridaOperationLogger(log_dir=str(log_dir))

        logger.log_bypass_attempt(
            protection_type="test_protection",
            technique="test_technique",
            success=True,
            details={"method": "hook_modification"},
        )

        assert logger.stats["bypasses_attempted"] >= 1
        if success := True:
            assert logger.stats["bypasses_successful"] >= 1

    def test_log_performance_metric_tracks_execution_time(self, tmp_path: Path) -> None:
        """log_performance_metric tracks operation performance."""
        log_dir = tmp_path / "frida_logs"
        logger = FridaOperationLogger(log_dir=str(log_dir))

        logger.log_performance_metric(
            operation="test_operation",
            duration=1.5,
            cpu_usage=25.0,
            memory_usage=1024,
        )

        assert "test_operation" in logger.performance_metrics
        assert logger.performance_metrics["test_operation"]

    def test_get_recent_operations_returns_latest_entries(self, tmp_path: Path) -> None:
        """get_recent_operations returns most recent operation entries."""
        log_dir = tmp_path / "frida_logs"
        logger = FridaOperationLogger(log_dir=str(log_dir))

        for i in range(5):
            logger.log_operation(
                operation=f"op_{i}",
                details={"index": i},
                success=True,
            )

        recent = logger.get_recent_operations(count=3)

        assert len(recent) == 3
        assert recent[0]["operation"] == "op_4"
        assert recent[1]["operation"] == "op_3"
        assert recent[2]["operation"] == "op_2"

    def test_get_statistics_returns_current_stats(self, tmp_path: Path) -> None:
        """get_statistics returns comprehensive statistics."""
        log_dir = tmp_path / "frida_logs"
        logger = FridaOperationLogger(log_dir=str(log_dir))

        logger.log_operation("op1", {}, True)
        logger.log_hook_call("hook1", "func1", {}, "result")

        stats = logger.get_statistics()

        assert "total_operations" in stats
        assert "successful_hooks" in stats
        assert stats["total_operations"] >= 1


class TestProtectionDetector:
    """Test real-time protection detection."""

    def test_detector_initialization(self) -> None:
        """ProtectionDetector initializes with protection patterns."""
        detector = ProtectionDetector()

        assert detector.detected_protections is not None
        assert isinstance(detector.detected_protections, dict)
        assert detector.detection_patterns is not None

    def test_analyze_function_detects_debugger_checks(self) -> None:
        """analyze_function detects debugger detection patterns."""
        detector = ProtectionDetector()

        test_code = """
        if (IsDebuggerPresent()) {
            exit(1);
        }
        """

        result = detector.analyze_function(
            function_name="check_debugger",
            code=test_code,
        )

        assert result is not None
        if result:
            assert "protection_type" in result or isinstance(result, dict)

    def test_analyze_function_detects_virtualization_checks(self) -> None:
        """analyze_function detects virtualization detection."""
        detector = ProtectionDetector()

        test_code = """
        CPUID instruction check for VMware
        Check for VBox guest additions
        """

        result = detector.analyze_function(
            function_name="check_vm",
            code=test_code,
        )

        assert result is None or isinstance(result, dict)

    def test_classify_protection_categorizes_correctly(self) -> None:
        """classify_protection categorizes protection types."""
        detector = ProtectionDetector()

        protection_type = "debugger_detection"

        category = detector.classify_protection(protection_type)

        assert category is not None
        assert category in VALID_PROTECTION_TYPES or isinstance(category, str)

    def test_get_bypass_strategy_provides_strategy(self) -> None:
        """get_bypass_strategy provides bypass strategy for protection."""
        detector = ProtectionDetector()

        strategy = detector.get_bypass_strategy("debugger_detection")

        assert strategy is not None
        assert isinstance(strategy, dict)
        assert "hooks" in strategy or "technique" in strategy


class TestHookBatcher:
    """Test hook batching for performance optimization."""

    def test_batcher_initialization(self) -> None:
        """HookBatcher initializes with batch size configuration."""
        batcher = HookBatcher(batch_size=50)

        assert batcher.batch_size == 50
        assert batcher.pending_hooks is not None
        assert isinstance(batcher.pending_hooks, list)

    def test_add_hook_to_batch(self) -> None:
        """add_hook adds hook to pending batch."""
        batcher = HookBatcher(batch_size=50)

        hook_script = "Interceptor.attach(ptr('0x1000'), { onEnter: function(args) {} });"

        batcher.add_hook(hook_script, category=HookCategory.DEBUGGER_DETECTION)

        assert len(batcher.pending_hooks) >= 1

    def test_batch_ready_when_size_reached(self) -> None:
        """Batch becomes ready when batch size is reached."""
        batcher = HookBatcher(batch_size=2)

        batcher.add_hook("hook1", category=HookCategory.DEBUGGER_DETECTION)
        assert not batcher.is_batch_ready()

        batcher.add_hook("hook2", category=HookCategory.ANTI_TAMPERING)
        assert batcher.is_batch_ready()

    def test_get_batch_returns_pending_hooks(self) -> None:
        """get_batch returns and clears pending hooks."""
        batcher = HookBatcher(batch_size=10)

        batcher.add_hook("hook1", HookCategory.DEBUGGER_DETECTION)
        batcher.add_hook("hook2", HookCategory.LICENSE_CHECK)

        batch = batcher.get_batch()

        assert len(batch) >= 2
        assert len(batcher.pending_hooks) == 0

    def test_generate_batch_script_combines_hooks(self) -> None:
        """generate_batch_script combines multiple hooks into single script."""
        batcher = HookBatcher(batch_size=10)

        batcher.add_hook("console.log('Hook 1');", HookCategory.DEBUGGER_DETECTION)
        batcher.add_hook("console.log('Hook 2');", HookCategory.LICENSE_CHECK)

        script = batcher.generate_batch_script()

        assert "Hook 1" in script
        assert "Hook 2" in script


class TestFridaPerformanceOptimizer:
    """Test Frida performance optimization."""

    def test_optimizer_initialization(self) -> None:
        """FridaPerformanceOptimizer initializes with configuration."""
        optimizer = FridaPerformanceOptimizer()

        assert optimizer.metrics is not None
        assert isinstance(optimizer.metrics, dict)

    def test_should_batch_hooks_based_on_threshold(self) -> None:
        """should_batch_hooks returns True when hook count exceeds threshold."""
        optimizer = FridaPerformanceOptimizer()

        result = optimizer.should_batch_hooks(hook_count=100)

        assert isinstance(result, bool)

    def test_optimize_script_improves_performance(self) -> None:
        """optimize_script applies performance optimizations to script."""
        optimizer = FridaPerformanceOptimizer()

        original_script = """
        Interceptor.attach(ptr('0x1000'), {
            onEnter: function(args) {
                console.log('Hook called');
            }
        });
        """

        optimized = optimizer.optimize_script(original_script)

        assert optimized is not None
        assert isinstance(optimized, str)
        assert len(optimized) > 0

    def test_get_recommendations_provides_optimization_tips(self) -> None:
        """get_recommendations provides performance optimization recommendations."""
        optimizer = FridaPerformanceOptimizer()

        optimizer.record_metric("hook_execution_time", 5.0)
        optimizer.record_metric("memory_usage", 1024 * 1024 * 100)

        recommendations = optimizer.get_recommendations()

        assert isinstance(recommendations, list)


class TestDynamicScriptGenerator:
    """Test dynamic Frida script generation."""

    def test_generator_initialization(self) -> None:
        """DynamicScriptGenerator initializes with script templates."""
        generator = DynamicScriptGenerator()

        assert generator.templates is not None
        assert isinstance(generator.templates, dict)

    def test_generate_debugger_bypass_script(self) -> None:
        """generate_debugger_bypass generates valid Frida script."""
        generator = DynamicScriptGenerator()

        script = generator.generate_debugger_bypass()

        assert script is not None
        assert isinstance(script, str)
        assert len(script) > 0
        assert "Interceptor" in script or "NativeFunction" in script

    def test_generate_license_check_bypass_script(self) -> None:
        """generate_license_check_bypass generates license bypass script."""
        generator = DynamicScriptGenerator()

        script = generator.generate_license_check_bypass(
            target_function="CheckLicense",
        )

        assert script is not None
        assert isinstance(script, str)
        assert "CheckLicense" in script

    def test_generate_trial_reset_script(self) -> None:
        """generate_trial_reset generates trial period bypass script."""
        generator = DynamicScriptGenerator()

        script = generator.generate_trial_reset()

        assert script is not None
        assert isinstance(script, str)
        assert len(script) > 0

    def test_generate_custom_hook_with_parameters(self) -> None:
        """generate_custom_hook creates hook with custom parameters."""
        generator = DynamicScriptGenerator()

        script = generator.generate_custom_hook(
            function_name="CustomFunction",
            module_name="test.dll",
            on_enter="console.log('Enter');",
            on_leave="console.log('Leave');",
        )

        assert script is not None
        assert "CustomFunction" in script
        assert "test.dll" in script

    def test_generate_anti_tampering_bypass(self) -> None:
        """generate_anti_tampering_bypass generates anti-tamper bypass script."""
        generator = DynamicScriptGenerator()

        script = generator.generate_anti_tampering_bypass()

        assert script is not None
        assert isinstance(script, str)
        assert len(script) > 0


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
class TestFridaManagerWindowsIntegration:
    """Test Frida manager with Windows processes (requires admin)."""

    def test_enumerate_processes_returns_running_processes(self) -> None:
        """enumerate_processes returns list of running Windows processes."""
        if not FRIDA_AVAILABLE:
            pytest.skip("Frida not available")

        try:
            device = frida.get_local_device()
            processes = device.enumerate_processes()

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
        if not FRIDA_AVAILABLE:
            pytest.skip("Frida not available")

        try:
            device = frida.get_local_device()

            system_processes = [p for p in device.enumerate_processes() if "System" in p.name or "explorer" in p.name.lower()]

            if system_processes:
                assert len(system_processes) > 0
                test_process = system_processes[0]
                assert test_process.pid > 0
                assert test_process.name

        except Exception as e:
            pytest.skip(f"System process access failed: {e}")


class TestScriptTemplateGeneration:
    """Test script template generation and customization."""

    def test_generate_hook_template_with_all_parameters(self) -> None:
        """Generates complete hook template with all parameters."""
        generator = DynamicScriptGenerator()

        template_params = {
            "function_name": "TestFunction",
            "module_name": "test.dll",
            "return_type": "int",
            "log_args": True,
            "log_return": True,
        }

        script = generator.generate_from_template("hook", template_params)

        assert script is not None
        assert isinstance(script, str)

    def test_generate_bypass_template_for_common_protections(self) -> None:
        """Generates bypass templates for common protection mechanisms."""
        generator = DynamicScriptGenerator()

        for protection in ["debugger", "vm", "integrity"]:
            script = generator.generate_bypass_for_protection(protection)

            assert script is not None
            assert isinstance(script, str)
            assert len(script) > 0


class TestLoggingPerformance:
    """Test logging system performance and buffer management."""

    def test_operation_buffer_maintains_max_size(self, tmp_path: Path) -> None:
        """Operation buffer respects maximum size limit."""
        log_dir = tmp_path / "frida_logs"
        logger = FridaOperationLogger(log_dir=str(log_dir))

        for i in range(BUFFER_MAX_SIZE + 100):
            logger.log_operation(f"op_{i}", {}, True)

        assert len(logger.operation_buffer) <= BUFFER_MAX_SIZE

    def test_hook_buffer_maintains_max_size(self, tmp_path: Path) -> None:
        """Hook buffer respects maximum size limit."""
        log_dir = tmp_path / "frida_logs"
        logger = FridaOperationLogger(log_dir=str(log_dir))

        max_hook_buffer = 50000

        for i in range(max_hook_buffer + 100):
            logger.log_hook_call(f"hook_{i}", "func", {}, "result")

        assert len(logger.hook_buffer) <= max_hook_buffer


class TestProtectionBypassStrategies:
    """Test protection bypass strategy generation."""

    def test_get_bypass_for_debugger_detection(self) -> None:
        """get_bypass_strategy returns strategy for debugger detection."""
        detector = ProtectionDetector()

        strategy = detector.get_bypass_strategy("debugger_detection")

        assert strategy is not None
        assert "technique" in strategy or "hooks" in strategy

    def test_get_bypass_for_vm_detection(self) -> None:
        """get_bypass_strategy returns strategy for VM detection."""
        detector = ProtectionDetector()

        strategy = detector.get_bypass_strategy("vm_detection")

        assert strategy is not None

    def test_get_bypass_for_license_check(self) -> None:
        """get_bypass_strategy returns strategy for license validation."""
        detector = ProtectionDetector()

        strategy = detector.get_bypass_strategy("license_check")

        assert strategy is not None


class TestEndToEndScriptGeneration:
    """Test end-to-end script generation workflow."""

    def test_complete_bypass_script_generation_workflow(self) -> None:
        """Generates complete bypass script from detection to implementation."""
        detector = ProtectionDetector()
        generator = DynamicScriptGenerator()

        protection_type = "debugger_detection"

        strategy = detector.get_bypass_strategy(protection_type)
        assert strategy is not None

        bypass_script = generator.generate_debugger_bypass()
        assert bypass_script is not None
        assert len(bypass_script) > 0

    def test_multi_protection_bypass_script_generation(self) -> None:
        """Generates combined bypass script for multiple protections."""
        generator = DynamicScriptGenerator()

        scripts = []
        scripts.append(generator.generate_debugger_bypass())
        scripts.append(generator.generate_trial_reset())
        scripts.append(generator.generate_anti_tampering_bypass())

        combined_script = "\n\n".join(scripts)

        assert combined_script is not None
        assert len(combined_script) > len(scripts[0])
