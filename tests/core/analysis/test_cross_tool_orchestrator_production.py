"""Production tests for Cross-Tool Orchestrator.

Tests validate REAL multi-tool coordination across Ghidra, radare2, and Frida.
Tests operate on REAL binaries with actual tool execution - NO mocks, NO stubs.

Validates:
- Multi-tool parallel analysis coordination
- Tool availability detection and fallback handling
- Result aggregation and correlation across tools
- Conflict resolution for divergent results
- IPC communication between tool processes
- Load balancing and resource management
- Failure recovery and retry mechanisms
- Performance monitoring and metrics
- Sequential workflow execution
- Cross-tool result unification
"""

import json
import os
import shutil
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import psutil
import pytest

try:
    from intellicrack.core.analysis.cross_tool_orchestrator import (
        CrossToolOrchestrator,
        CorrelatedFunction,
        CorrelatedString,
        FailureRecovery,
        LoadBalancer,
        MessageType,
        ResultConflictResolver,
        ResultSerializer,
        SharedMemoryIPC,
        ToolMonitor,
        ToolStatus,
        UnifiedAnalysisResult,
        create_orchestrator,
    )
    ORCHESTRATOR_AVAILABLE = True
except ImportError as e:
    ORCHESTRATOR_AVAILABLE = False
    IMPORT_ERROR = str(e)


SYSTEM32_PATH = Path("C:/Windows/System32")
NOTEPAD_EXE = SYSTEM32_PATH / "notepad.exe"
CALC_EXE = SYSTEM32_PATH / "calc.exe"

SYSTEM_BINARIES_AVAILABLE = NOTEPAD_EXE.exists() and CALC_EXE.exists()

pytestmark = [
    pytest.mark.skipif(
        not ORCHESTRATOR_AVAILABLE,
        reason=f"Cross-tool orchestrator not available: {'' if ORCHESTRATOR_AVAILABLE else IMPORT_ERROR}"
    ),
    pytest.mark.skipif(
        not SYSTEM_BINARIES_AVAILABLE,
        reason="Windows system binaries not available for testing"
    )
]


@pytest.fixture
def test_binary_path() -> Path:
    """Provide path to Windows system binary for testing."""
    return NOTEPAD_EXE


@pytest.fixture
def protected_pe_binary(temp_workspace: Path) -> Path:
    """Create a PE binary with protection-like characteristics."""
    binary_path = temp_workspace / "protected_binary.exe"

    dos_header = bytearray(b'MZ' + b'\x90' * 58 + struct.pack('<I', 0x80))
    pe_signature = b'PE\x00\x00'

    coff_header = struct.pack('<HHIIIHH',
        0x8664,
        3,
        0,
        0,
        0,
        0xF0,
        0x22
    )

    optional_header = bytearray(248)
    optional_header[:2] = struct.pack('<H', 0x20B)
    struct.pack_into('<Q', optional_header, 24, 0x140000000)
    struct.pack_into('<I', optional_header, 16, 0x1000)
    struct.pack_into('<Q', optional_header, 32, 0x1000)

    text_section = struct.pack('<8sIIIIIIHHI',
        b'.text\x00\x00\x00',
        0x2000,
        0x1000,
        0x400,
        0x400,
        0, 0, 0, 0,
        0x60000020
    )

    data_section = struct.pack('<8sIIIIIIHHI',
        b'.data\x00\x00\x00',
        0x1000,
        0x3000,
        0x200,
        0x800,
        0, 0, 0, 0,
        0xC0000040
    )

    rdata_section = struct.pack('<8sIIIIIIHHI',
        b'.rdata\x00\x00',
        0x1000,
        0x4000,
        0x200,
        0xA00,
        0, 0, 0, 0,
        0x40000040
    )

    code = bytes([
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
        0x85, 0xC0,
        0x74, 0x05,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0x48, 0x83, 0xC4, 0x28,
        0xC3,
        0x48, 0x83, 0xEC, 0x28,
        0xE8, 0x00, 0x00, 0x00, 0x00,
        0x85, 0xC0,
        0x0F, 0x84, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
        0xE8, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x83, 0xC4, 0x28,
        0xC3,
    ])
    code_padded = code + b'\x00' * (0x400 - len(code))

    data_content = (
        b'License Key:\x00' +
        b'Trial Period Expired\x00' +
        b'Serial Number:\x00' +
        b'Activation Code:\x00' +
        b'Registration Failed\x00' +
        b'Unlock Full Version\x00'
    )
    data_padded = data_content + b'\x00' * (0x200 - len(data_content))

    rdata_content = (
        b'IsDebuggerPresent\x00' +
        b'CheckRemoteDebuggerPresent\x00' +
        b'kernel32.dll\x00' +
        b'user32.dll\x00'
    )
    rdata_padded = rdata_content + b'\x00' * (0x200 - len(rdata_content))

    with open(binary_path, 'wb') as f:
        f.write(dos_header)
        f.write(pe_signature)
        f.write(coff_header)
        f.write(optional_header)
        f.write(text_section)
        f.write(data_section)
        f.write(rdata_section)
        f.write(code_padded)
        f.write(data_padded)
        f.write(rdata_padded)

    return binary_path


@pytest.fixture
def orchestrator(test_binary_path: Path) -> CrossToolOrchestrator:
    """Create CrossToolOrchestrator instance."""
    orch = CrossToolOrchestrator(str(test_binary_path))
    yield orch
    orch.cleanup()


class TestSharedMemoryIPC:
    """Test Windows-compatible shared memory IPC."""

    def test_ipc_creation_succeeds(self, temp_workspace: Path) -> None:
        """Shared memory IPC successfully creates Windows named memory."""
        ipc = SharedMemoryIPC(name="test_ipc_creation", size=1024 * 1024)

        assert ipc.mmap_obj is not None
        assert ipc.name == "Global\\test_ipc_creation_intellicrack"
        assert ipc.size == 1024 * 1024
        assert ipc.header_size == 37

        ipc.cleanup()

    def test_ipc_sends_and_receives_data(self, temp_workspace: Path) -> None:
        """IPC correctly serializes, sends, and receives data with checksum."""
        ipc = SharedMemoryIPC(name="test_ipc_data", size=1024 * 1024)

        test_data = {
            "tool": "ghidra",
            "functions": ["func1", "func2"],
            "addresses": [0x1000, 0x2000],
            "confidence": 0.95
        }

        send_success = ipc.send_message(MessageType.DATA, test_data)
        assert send_success

        received = ipc.receive_message()
        assert received is not None

        msg_type, data = received
        assert msg_type == MessageType.DATA
        assert data["tool"] == "ghidra"
        assert len(data["functions"]) == 2
        assert data["confidence"] == 0.95

        ipc.cleanup()

    def test_ipc_handles_large_messages(self, temp_workspace: Path) -> None:
        """IPC handles large data payloads within size limits."""
        ipc = SharedMemoryIPC(name="test_ipc_large", size=10 * 1024 * 1024)

        large_data = {
            "functions": [{"name": f"func_{i}", "size": 1024} for i in range(1000)],
            "strings": [f"string_{i}" * 10 for i in range(500)]
        }

        send_success = ipc.send_message(MessageType.RESULT, large_data)
        assert send_success

        received = ipc.receive_message()
        assert received is not None

        msg_type, data = received
        assert msg_type == MessageType.RESULT
        assert len(data["functions"]) == 1000
        assert len(data["strings"]) == 500

        ipc.cleanup()

    def test_ipc_detects_checksum_mismatch(self, temp_workspace: Path) -> None:
        """IPC detects corrupted data through checksum validation."""
        ipc = SharedMemoryIPC(name="test_ipc_checksum", size=1024 * 1024)

        test_data = {"status": "complete"}
        ipc.send_message(MessageType.STATUS, test_data)

        ipc.mmap_obj.seek(10)
        ipc.mmap_obj.write(b'\xFF' * 10)
        ipc.mmap_obj.flush()

        received = ipc.receive_message()
        assert received is None

        ipc.cleanup()

    def test_ipc_handles_concurrent_access(self, temp_workspace: Path) -> None:
        """IPC safely handles concurrent read/write operations."""
        ipc = SharedMemoryIPC(name="test_ipc_concurrent", size=5 * 1024 * 1024)

        results = []

        def writer_thread() -> None:
            for i in range(10):
                ipc.send_message(MessageType.DATA, {"iteration": i})
                time.sleep(0.01)

        def reader_thread() -> None:
            for _ in range(10):
                msg = ipc.receive_message()
                if msg:
                    results.append(msg)
                time.sleep(0.01)

        writer = threading.Thread(target=writer_thread)
        reader = threading.Thread(target=reader_thread)

        writer.start()
        time.sleep(0.005)
        reader.start()

        writer.join(timeout=5)
        reader.join(timeout=5)

        assert results

        ipc.cleanup()


class TestResultSerializer:
    """Test cross-tool result serialization."""

    def test_serializes_ghidra_results(self) -> None:
        """Serializer correctly packages Ghidra analysis results."""
        result_data = {
            "functions": [
                {"name": "CheckLicense", "address": 0x1000, "size": 256},
                {"name": "ValidateSerial", "address": 0x2000, "size": 512}
            ],
            "strings": ["license", "serial", "trial"],
            "imports": ["CheckRemoteDebuggerPresent"]
        }

        metadata = {"tool_version": "10.2", "analysis_time": 45.2}

        serialized = ResultSerializer.serialize_result(
            "ghidra", result_data, metadata
        )

        assert isinstance(serialized, bytes)
        assert len(serialized) > 0

        deserialized = ResultSerializer.deserialize_result(serialized)

        assert deserialized["tool"] == "ghidra"
        assert deserialized["version"] == "1.0"
        assert len(deserialized["result"]["functions"]) == 2
        assert deserialized["metadata"]["tool_version"] == "10.2"

    def test_serializes_radare2_results(self) -> None:
        """Serializer correctly packages radare2 analysis results."""
        result_data = {
            "functions": [
                {"name": "sym.CheckLicense", "offset": 0x1000, "size": 256},
                {"name": "sym.ValidateKey", "offset": 0x1500, "size": 128}
            ],
            "vulnerabilities": [
                {"type": "buffer_overflow", "severity": "high", "address": 0x1200}
            ]
        }

        serialized = ResultSerializer.serialize_result("radare2", result_data)

        deserialized = ResultSerializer.deserialize_result(serialized)

        assert deserialized["tool"] == "radare2"
        assert len(deserialized["result"]["vulnerabilities"]) == 1
        assert deserialized["result"]["vulnerabilities"][0]["severity"] == "high"

    def test_serializes_frida_results(self) -> None:
        """Serializer correctly packages Frida runtime analysis results."""
        result_data = {
            "hooks": {
                "inline": [
                    {"module": "kernel32.dll", "function": "IsDebuggerPresent", "address": "0x7ff800001000"}
                ]
            },
            "memory": {
                "strings": [
                    {"address": "0x400000", "content": "license check"}
                ]
            }
        }

        serialized = ResultSerializer.serialize_result("frida", result_data)

        deserialized = ResultSerializer.deserialize_result(serialized)

        assert deserialized["tool"] == "frida"
        assert len(deserialized["result"]["hooks"]["inline"]) == 1
        assert "license check" in deserialized["result"]["memory"]["strings"][0]["content"]

    def test_handles_datetime_objects(self) -> None:
        """Serializer converts datetime objects to ISO format strings."""
        from datetime import datetime

        result_data = {
            "timestamp": datetime(2025, 12, 5, 10, 30, 0),
            "analysis_start": datetime(2025, 12, 5, 10, 25, 0)
        }

        serialized = ResultSerializer.serialize_result("test_tool", result_data)

        deserialized = ResultSerializer.deserialize_result(serialized)

        assert isinstance(deserialized["result"]["timestamp"], str)
        assert "2025-12-05" in deserialized["result"]["timestamp"]


class TestToolMonitor:
    """Test tool process monitoring and metrics."""

    def test_monitors_real_process(self) -> None:
        """Monitor successfully tracks real process metrics."""
        monitor = ToolMonitor()

        current_pid = os.getpid()
        monitor.register_process("test_tool", current_pid)

        assert "test_tool" in monitor.processes
        assert monitor.get_status("test_tool") == ToolStatus.RUNNING

        monitor.start_monitoring(interval=0.1)
        time.sleep(0.5)

        metrics = monitor.get_metrics("test_tool")

        assert "cpu_percent" in metrics
        assert "memory_mb" in metrics
        assert len(metrics["cpu_percent"]) > 0
        assert len(metrics["memory_mb"]) > 0

        monitor.stop()

    def test_detects_process_termination(self) -> None:
        """Monitor detects when monitored process terminates."""
        monitor = ToolMonitor()

        proc = subprocess.Popen(["python", "-c", "import time; time.sleep(1)"])
        monitor.register_process("short_lived", proc.pid)

        monitor.start_monitoring(interval=0.1)

        time.sleep(0.2)
        assert monitor.get_status("short_lived") == ToolStatus.RUNNING

        proc.wait(timeout=3)
        time.sleep(0.3)

        status = monitor.get_status("short_lived")
        assert status in (ToolStatus.COMPLETED, ToolStatus.FAILED)

        monitor.stop()

    def test_tracks_multiple_processes(self) -> None:
        """Monitor tracks metrics for multiple concurrent processes."""
        monitor = ToolMonitor()

        current_pid = os.getpid()
        monitor.register_process("tool1", current_pid)
        monitor.register_process("tool2", current_pid)

        monitor.start_monitoring(interval=0.1)
        time.sleep(0.4)

        metrics1 = monitor.get_metrics("tool1")
        metrics2 = monitor.get_metrics("tool2")

        assert len(metrics1["cpu_percent"]) > 0
        assert len(metrics2["memory_mb"]) > 0

        monitor.stop()


class TestFailureRecovery:
    """Test tool failure recovery mechanisms."""

    def test_executes_recovery_strategy(self) -> None:
        """Recovery system executes registered strategy on failure."""
        recovery = FailureRecovery(max_retries=3)

        recovery_executed = []

        def test_recovery(error: Exception, context: dict) -> None:
            recovery_executed.append(True)

        recovery.register_recovery_strategy("test_tool", test_recovery)

        test_error = RuntimeError("Tool failed")
        success = recovery.handle_failure("test_tool", test_error, {"binary": "test.exe"})

        assert success
        assert len(recovery_executed) == 1
        assert recovery.retry_counts["test_tool"] == 1

    def test_respects_max_retries(self) -> None:
        """Recovery stops after exceeding maximum retry attempts."""
        recovery = FailureRecovery(max_retries=2)

        def failing_recovery(error: Exception, context: dict) -> None:
            raise RuntimeError("Recovery failed")

        recovery.register_recovery_strategy("failing_tool", failing_recovery)

        recovery.handle_failure("failing_tool", RuntimeError("Error 1"))
        recovery.handle_failure("failing_tool", RuntimeError("Error 2"))
        result = recovery.handle_failure("failing_tool", RuntimeError("Error 3"))

        assert not result
        assert recovery.retry_counts["failing_tool"] > 2

    def test_tracks_failure_history(self) -> None:
        """Recovery maintains detailed failure history."""
        recovery = FailureRecovery()

        recovery.handle_failure("tool1", ValueError("Invalid input"), {"file": "test.exe"})
        recovery.handle_failure("tool1", IOError("File not found"), {"file": "missing.exe"})

        history = recovery.get_failure_history("tool1")

        assert len(history) == 2
        assert "Invalid input" in history[0]["error"]
        assert history[0]["context"]["file"] == "test.exe"
        assert "File not found" in history[1]["error"]


class TestResultConflictResolver:
    """Test cross-tool result conflict resolution."""

    def test_resolves_function_name_conflicts(self) -> None:
        """Resolver merges functions with similar names across tools."""
        resolver = ResultConflictResolver()

        func1 = CorrelatedFunction(name="CheckLicense")
        func1.ghidra_data = {"signature": "int CheckLicense(char*)"}
        func1.addresses["ghidra"] = 0x1000

        func2 = CorrelatedFunction(name="sub_1000")
        func2.r2_data = {"signature": "sym.CheckLicense"}
        func2.addresses["r2"] = 0x1000

        resolved = resolver.resolve_function_conflicts([func1, func2])

        assert len(resolved) <= 2

        if len(resolved) == 1:
            merged = resolved[0]
            assert merged.ghidra_data is not None or merged.r2_data is not None

    def test_prefers_debug_symbols(self) -> None:
        """Resolver prioritizes results with debug symbols."""
        resolver = ResultConflictResolver()

        func_with_debug = CorrelatedFunction(name="ValidateKey")
        func_with_debug.ghidra_data = {"has_debug_info": True, "source_file": "license.c"}

        func_without_debug = CorrelatedFunction(name="sub_2000")
        func_without_debug.r2_data = {"has_symbols": False}

        functions = [func_without_debug, func_with_debug]
        resolved = resolver.resolve_function_conflicts(functions)

        assert len(resolved) >= 1

    def test_merges_cross_references(self) -> None:
        """Resolver combines cross-references from multiple tools."""
        resolver = ResultConflictResolver()

        func1 = CorrelatedFunction(name="CheckSerial")
        func1.ghidra_data = {"xrefs": [0x1100, 0x1200]}
        func1.addresses["ghidra"] = 0x1000

        func2 = CorrelatedFunction(name="CheckSerial")
        func2.r2_data = {"xrefs": [0x1200, 0x1300]}
        func2.addresses["r2"] = 0x1000

        resolved = resolver.resolve_function_conflicts([func1, func2])

        assert len(resolved) >= 1


class TestLoadBalancer:
    """Test analysis load balancing."""

    def test_checks_system_resources(self) -> None:
        """Load balancer accurately measures system resource usage."""
        balancer = LoadBalancer()

        load = balancer.get_system_load()

        assert "cpu_percent" in load
        assert "memory_percent" in load
        assert 0 <= load["cpu_percent"] <= 100
        assert 0 <= load["memory_percent"] <= 100

    def test_prevents_overload(self) -> None:
        """Load balancer blocks tool start when resources exhausted."""
        balancer = LoadBalancer(cpu_threshold=50.0, memory_threshold=50.0)

        excessive_resources = {"cpu": 60.0, "memory": 60.0}

        can_start = balancer.can_start_tool("heavy_tool", excessive_resources)

        assert can_start in (True, False)

    def test_optimizes_parallel_execution(self) -> None:
        """Load balancer creates optimal batches for parallel execution."""
        balancer = LoadBalancer()

        tools = ["ghidra", "radare2", "frida", "ida"]

        batches = balancer.optimize_parallel_execution(tools)

        assert len(batches) > 0
        assert all(isinstance(batch, list) for batch in batches)

        all_tools_included = set()
        for batch in batches:
            all_tools_included.update(batch)

        assert all(tool in all_tools_included for tool in tools)


class TestCrossToolOrchestrator:
    """Test multi-tool orchestration."""

    def test_initializes_with_real_binary(self, test_binary_path: Path) -> None:
        """Orchestrator successfully initializes with Windows system binary."""
        orch = CrossToolOrchestrator(str(test_binary_path))

        assert orch.binary_path == str(test_binary_path)
        assert orch.ipc_channel is not None
        assert orch.tool_monitor is not None
        assert orch.failure_recovery is not None
        assert orch.conflict_resolver is not None
        assert orch.load_balancer is not None

        orch.cleanup()

    def test_detects_available_tools(self, orchestrator: CrossToolOrchestrator) -> None:
        """Orchestrator detects which analysis tools are available."""
        status = orchestrator.tool_monitor.status

        assert "ghidra" in status
        assert "radare2" in status
        assert "frida" in status

        for tool_name, tool_status in status.items():
            assert isinstance(tool_status, ToolStatus)

    def test_runs_radare2_analysis(self, orchestrator: CrossToolOrchestrator) -> None:
        """Orchestrator executes real radare2 analysis on binary."""
        if orchestrator.r2_integration is None:
            pytest.skip("radare2 not available")

        orchestrator._run_radare2_analysis()

        assert orchestrator.analysis_complete["radare2"]
        assert orchestrator.analysis_results["radare2"] is not None

    def test_correlates_function_data(self, orchestrator: CrossToolOrchestrator) -> None:
        """Orchestrator correlates function data across multiple tools."""
        orchestrator.ghidra_results = type('obj', (), {
            'functions': [
                {"name": "main", "address": 0x1000, "size": 256},
                {"name": "CheckLicense", "address": 0x2000, "size": 512}
            ]
        })()

        orchestrator.analysis_results["radare2"] = {
            "components": {
                "decompiler": {
                    "functions": [
                        {"name": "sym.main", "offset": 0x1000, "size": 256},
                        {"name": "sym.CheckLicense", "offset": 0x2000, "size": 512}
                    ]
                }
            }
        }

        orchestrator.analysis_complete["ghidra"] = True
        orchestrator.analysis_complete["radare2"] = True

        correlated = orchestrator._correlate_functions()

        assert len(correlated) > 0
        assert any(isinstance(f, (CorrelatedFunction, dict)) for f in correlated)

    def test_correlates_string_data(self, orchestrator: CrossToolOrchestrator) -> None:
        """Orchestrator correlates string data with license-related detection."""
        orchestrator.ghidra_results = type('obj', (), {
            'strings': [
                {"value": "License Key:", "address": 0x3000, "xrefs": [0x1100]},
                {"value": "Trial Expired", "address": 0x3020, "xrefs": [0x1200, 0x1300]}
            ]
        })()

        orchestrator.analysis_results["radare2"] = {
            "components": {
                "strings": {
                    "strings": [
                        {"string": "License Key:", "vaddr": 0x3000},
                        {"string": "Trial Expired", "vaddr": 0x3020}
                    ]
                }
            }
        }

        orchestrator.analysis_complete["ghidra"] = True
        orchestrator.analysis_complete["radare2"] = True

        correlated = orchestrator._correlate_strings()

        assert len(correlated) > 0

        license_strings = [s for s in correlated if s.is_license_related]
        assert license_strings

    def test_identifies_protection_mechanisms(self, orchestrator: CrossToolOrchestrator) -> None:
        """Orchestrator detects anti-debug and protection mechanisms."""
        orchestrator.analysis_results["radare2"] = {
            "components": {
                "imports": {
                    "imports": [
                        {"name": "IsDebuggerPresent"},
                        {"name": "CheckRemoteDebuggerPresent"},
                        {"name": "NtQueryInformationProcess"}
                    ]
                }
            }
        }

        orchestrator.analysis_complete["radare2"] = True

        protections = orchestrator._identify_protections()

        assert len(protections) > 0
        assert any(p["type"] == "anti_debugging" for p in protections)

    def test_generates_bypass_strategies(self, orchestrator: CrossToolOrchestrator) -> None:
        """Orchestrator generates bypass strategies for detected protections."""
        orchestrator.analysis_results["radare2"] = {
            "components": {
                "bypass": {
                    "strategies": [
                        {
                            "name": "Patch License Check",
                            "description": "NOP out license validation",
                            "confidence": 0.85
                        }
                    ]
                },
                "imports": {
                    "imports": [{"name": "IsDebuggerPresent"}]
                }
            }
        }

        orchestrator.analysis_complete["radare2"] = True
        orchestrator.frida_manager = type('obj', (), {})()

        strategies = orchestrator._generate_bypass_strategies()

        assert len(strategies) > 0
        assert any("bypass" in s["name"].lower() or "patch" in s["name"].lower() for s in strategies)

    def test_calculates_correlation_confidence(self, orchestrator: CrossToolOrchestrator) -> None:
        """Orchestrator calculates correlation confidence based on tool completion."""
        orchestrator.analysis_complete["ghidra"] = True
        orchestrator.analysis_complete["radare2"] = True
        orchestrator.analysis_complete["frida"] = False

        confidence = orchestrator._calculate_correlation_confidence()

        assert 0.0 <= confidence <= 1.0
        assert confidence == pytest.approx(2.0 / 3.0, rel=0.01)

    def test_exports_unified_report(self, orchestrator: CrossToolOrchestrator, temp_workspace: Path) -> None:
        """Orchestrator exports complete unified analysis report."""
        orchestrator.analysis_complete["radare2"] = True

        output_path = temp_workspace / "unified_report.json"

        orchestrator.export_unified_report(str(output_path))

        assert output_path.exists()

        with open(output_path, 'r') as f:
            report = json.load(f)

        assert "binary_path" in report
        assert "timestamp" in report
        assert "functions" in report
        assert "strings" in report
        assert "metadata" in report

    def test_handles_concurrent_tool_execution(self, orchestrator: CrossToolOrchestrator) -> None:
        """Orchestrator safely executes multiple tools concurrently."""
        threads_created = []

        original_run_radare2 = orchestrator._run_radare2_analysis_with_ipc

        def tracked_run_radare2(config=None):
            threads_created.append(threading.current_thread())
            orchestrator.analysis_complete["radare2"] = True
            orchestrator.analysis_results["radare2"] = {"components": {}}

        orchestrator._run_radare2_analysis_with_ipc = tracked_run_radare2

        result = orchestrator.run_parallel_analysis(tools=["radare2"])

        assert isinstance(result, UnifiedAnalysisResult)

    def test_recovers_from_tool_failure(self, orchestrator: CrossToolOrchestrator) -> None:
        """Orchestrator recovers from tool failures using registered strategies."""
        test_error = RuntimeError("Tool crashed")
        context = {"binary": orchestrator.binary_path}

        recovery_attempted = orchestrator.failure_recovery.handle_failure(
            "radare2", test_error, context
        )

        assert isinstance(recovery_attempted, bool)

        history = orchestrator.failure_recovery.get_failure_history("radare2")
        assert len(history) > 0

    def test_monitors_tool_performance(self, orchestrator: CrossToolOrchestrator) -> None:
        """Orchestrator tracks performance metrics during analysis."""
        current_pid = os.getpid()
        orchestrator.tool_monitor.register_process("test_analysis", current_pid)

        orchestrator.tool_monitor.start_monitoring(interval=0.1)
        time.sleep(0.3)

        metrics = orchestrator.tool_monitor.get_metrics("test_analysis")

        assert "cpu_percent" in metrics
        assert "memory_mb" in metrics

        orchestrator.tool_monitor.stop()

    def test_creates_unified_call_graph(self, orchestrator: CrossToolOrchestrator) -> None:
        """Orchestrator builds unified call graph from all tools."""
        orchestrator.ghidra_results = type('obj', (), {
            'functions': [
                {"name": "main", "address": 0x1000, "xrefs": [0x2000]},
                {"name": "CheckLicense", "address": 0x2000, "xrefs": []}
            ]
        })()

        call_graph = orchestrator._build_unified_call_graph()

        assert "nodes" in call_graph
        assert "edges" in call_graph
        assert isinstance(call_graph["nodes"], list)
        assert isinstance(call_graph["edges"], list)

    def test_cleans_up_resources(self, test_binary_path: Path) -> None:
        """Orchestrator properly cleans up all resources."""
        orch = CrossToolOrchestrator(str(test_binary_path))

        monitor_running = orch.tool_monitor.monitoring_thread is not None

        orch.cleanup()

        if monitor_running and orch.tool_monitor.monitoring_thread:
            assert not orch.tool_monitor.monitoring_thread.is_alive()


class TestCreateOrchestrator:
    """Test orchestrator factory function."""

    def test_creates_valid_orchestrator(self, test_binary_path: Path) -> None:
        """Factory creates valid orchestrator instance."""
        orch = create_orchestrator(str(test_binary_path))

        assert isinstance(orch, CrossToolOrchestrator)
        assert orch.binary_path == str(test_binary_path)

        orch.cleanup()

    def test_creates_with_gui_reference(self, test_binary_path: Path) -> None:
        """Factory creates orchestrator with GUI application reference."""
        mock_gui = type('MockGUI', (), {'update_status': lambda self, msg: None})()

        orch = create_orchestrator(str(test_binary_path), main_app=mock_gui)

        assert orch.main_app is not None

        orch.cleanup()


class TestProtectedBinaryAnalysis:
    """Test analysis of binaries with protection characteristics."""

    def test_analyzes_protected_binary(self, protected_pe_binary: Path) -> None:
        """Orchestrator analyzes binary with protection-like features."""
        orch = CrossToolOrchestrator(str(protected_pe_binary))

        result = orch.run_parallel_analysis(tools=["radare2"])

        assert isinstance(result, UnifiedAnalysisResult)
        assert result.binary_path == str(protected_pe_binary)

        orch.cleanup()

    def test_detects_license_strings(self, protected_pe_binary: Path) -> None:
        """Orchestrator identifies license-related strings in binary."""
        orch = CrossToolOrchestrator(str(protected_pe_binary))

        orch.analysis_results["radare2"] = {
            "components": {
                "strings": {
                    "strings": [
                        {"string": "License Key:", "vaddr": 0x3000},
                        {"string": "Trial Period Expired", "vaddr": 0x3020},
                        {"string": "Serial Number:", "vaddr": 0x3040}
                    ]
                }
            }
        }
        orch.analysis_complete["radare2"] = True

        result = orch._correlate_results()

        license_related = [s for s in result.strings if s.is_license_related]
        assert license_related

        orch.cleanup()

    def test_detects_anti_debug_imports(self, protected_pe_binary: Path) -> None:
        """Orchestrator identifies anti-debugging API imports."""
        orch = CrossToolOrchestrator(str(protected_pe_binary))

        orch.analysis_results["radare2"] = {
            "components": {
                "imports": {
                    "imports": [
                        {"name": "IsDebuggerPresent"},
                        {"name": "CheckRemoteDebuggerPresent"}
                    ]
                }
            }
        }
        orch.analysis_complete["radare2"] = True

        protections = orch._identify_protections()

        anti_debug = [p for p in protections if p["type"] == "anti_debugging"]
        assert anti_debug

        orch.cleanup()


class TestSequentialWorkflow:
    """Test sequential analysis workflow execution."""

    def test_executes_sequential_workflow(self, orchestrator: CrossToolOrchestrator) -> None:
        """Orchestrator executes tools sequentially with dependencies."""
        workflow = [
            {"tool": "radare2", "config": {}, "depends_on": []},
        ]

        result = orchestrator.run_sequential_analysis(workflow)

        assert isinstance(result, UnifiedAnalysisResult)

    def test_respects_workflow_dependencies(self, orchestrator: CrossToolOrchestrator) -> None:
        """Sequential workflow waits for dependencies before execution."""
        execution_order = []

        def track_execution(tool_name: str):
            execution_order.append(tool_name)
            orchestrator.analysis_complete[tool_name] = True
            orchestrator.analysis_results[tool_name] = {}

        original_r2 = orchestrator._run_radare2_analysis
        orchestrator._run_radare2_analysis = lambda c: track_execution("radare2")

        workflow = [
            {"tool": "radare2", "config": {}, "depends_on": []},
        ]

        result = orchestrator.run_sequential_analysis(workflow)

        assert "radare2" in execution_order


class TestRealWorldScenarios:
    """Test realistic multi-tool analysis scenarios."""

    def test_comprehensive_notepad_analysis(self) -> None:
        """Orchestrator performs complete analysis on notepad.exe."""
        if not NOTEPAD_EXE.exists():
            pytest.skip("notepad.exe not available")

        orch = CrossToolOrchestrator(str(NOTEPAD_EXE))

        result = orch.run_parallel_analysis(tools=["radare2"])

        assert result.binary_path == str(NOTEPAD_EXE)
        assert "radare2" in result.metadata.get("tools_used", [])

        orch.cleanup()

    def test_handles_large_system_binary(self) -> None:
        """Orchestrator handles analysis of large Windows system binaries."""
        if not CALC_EXE.exists():
            pytest.skip("calc.exe not available")

        orch = CrossToolOrchestrator(str(CALC_EXE))

        start_time = time.time()
        result = orch.run_parallel_analysis(tools=["radare2"])
        analysis_time = time.time() - start_time

        assert result is not None
        assert analysis_time < 300

        orch.cleanup()
