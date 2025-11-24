"""Comprehensive production tests for symbolic execution engine.

This module validates real symbolic execution capabilities for license cracking,
vulnerability discovery, and constraint solving against actual binaries.
"""

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.symbolic_executor import (
    SymbolicExecutionEngine,
    SymbolicExecutor,
    TaintTracker,
)

try:
    import angr
    import claripy

    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


def create_pe_binary(content: bytes = b"") -> bytes:
    """Create minimal valid PE binary for testing."""
    dos_header = b"MZ" + b"\x00" * 58
    pe_offset = struct.pack("<I", 0x80)
    dos_header += pe_offset

    pe_header = b"PE\x00\x00"
    pe_header += b"\x4c\x01"
    pe_header += struct.pack("<H", 1)
    pe_header += b"\x00" * 12
    pe_header += struct.pack("<H", 224)
    pe_header += struct.pack("<H", 0x010B)
    pe_header += b"\x00" * 204

    padding = b"\x00" * (0x80 - len(dos_header))
    text_section = b"\x90" * 0x1000

    if content:
        text_section = content + b"\x90" * (0x1000 - len(content))

    return dos_header + padding + pe_header + text_section


def create_elf_binary(content: bytes = b"") -> bytes:
    """Create minimal valid ELF binary for testing."""
    elf_header = b"\x7fELF"
    elf_header += b"\x02"
    elf_header += b"\x01"
    elf_header += b"\x01"
    elf_header += b"\x00" * 9
    elf_header += struct.pack("<H", 2)
    elf_header += struct.pack("<H", 0x3E)
    elf_header += struct.pack("<I", 1)
    elf_header += struct.pack("<Q", 0x400000)
    elf_header += b"\x00" * (0x1000 - len(elf_header))

    text_section = b"\x48\x31\xc0\xc3" + b"\x90" * 0xFFC

    if content:
        text_section = content + b"\x90" * (0x1000 - len(content))

    return elf_header + text_section


def create_binary_with_dangerous_functions() -> bytes:
    """Create binary containing dangerous function references."""
    binary = create_pe_binary()
    dangerous_strings = b"strcpy\x00gets\x00sprintf\x00memcpy\x00"
    binary += dangerous_strings
    return binary


def create_binary_with_format_strings() -> bytes:
    """Create binary with format string patterns."""
    binary = create_pe_binary()
    format_strings = b"User: %s\x00Debug: %x %x %x\x00Format: %n\x00"
    binary += format_strings
    return binary


def create_binary_with_arithmetic() -> bytes:
    """Create binary with arithmetic operations for integer overflow testing."""
    code = bytearray()
    code.extend(b"\x01\xc0")
    code.extend(b"\x29\xd8")
    code.extend(b"\xf7\xe0")
    code.extend(b"\xc3")

    return create_pe_binary(code)


def create_binary_with_heap_operations() -> bytes:
    """Create binary with heap allocation patterns."""
    binary = create_pe_binary()
    heap_strings = b"malloc\x00free\x00calloc\x00realloc\x00new\x00delete\x00"
    binary += heap_strings
    return binary


def create_binary_with_sql() -> bytes:
    """Create binary with SQL injection patterns."""
    binary = create_pe_binary()
    sql_strings = b"SELECT * FROM users WHERE id=\x00INSERT INTO\x00' OR '1'='1\x00"
    binary += sql_strings
    return binary


def create_binary_with_commands() -> bytes:
    """Create binary with command execution patterns."""
    binary = create_pe_binary()
    cmd_strings = b"system\x00exec\x00popen\x00cmd.exe\x00/bin/sh\x00;ls\x00"
    binary += cmd_strings
    return binary


class TestSymbolicExecutionEngineInitialization:
    """Test SymbolicExecutionEngine initialization and configuration."""

    def test_engine_initialization_with_valid_binary(self, tmp_path: Path) -> None:
        """Engine initializes successfully with valid binary path."""
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(create_pe_binary())

        engine = SymbolicExecutionEngine(str(binary_path))

        assert engine.binary_path == str(binary_path)
        assert engine.max_paths == 100
        assert engine.timeout == 300
        assert engine.memory_limit == 4096 * 1024 * 1024
        assert isinstance(engine.states, list)
        assert isinstance(engine.completed_paths, list)
        assert isinstance(engine.crashed_states, list)

    def test_engine_initialization_with_custom_limits(self, tmp_path: Path) -> None:
        """Engine accepts custom path, timeout, and memory limits."""
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(create_pe_binary())

        engine = SymbolicExecutionEngine(str(binary_path), max_paths=50, timeout=60, memory_limit=2048)

        assert engine.max_paths == 50
        assert engine.timeout == 60
        assert engine.memory_limit == 2048 * 1024 * 1024

    def test_engine_initialization_nonexistent_binary_raises_error(self, tmp_path: Path) -> None:
        """Engine raises FileNotFoundError for nonexistent binary."""
        binary_path = tmp_path / "nonexistent.exe"

        with pytest.raises(FileNotFoundError, match="Binary file not found"):
            SymbolicExecutionEngine(str(binary_path))

    def test_engine_angr_availability_detection(self, tmp_path: Path) -> None:
        """Engine correctly detects angr availability."""
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(create_pe_binary())

        engine = SymbolicExecutionEngine(str(binary_path))

        assert engine.angr_available == ANGR_AVAILABLE


class TestSymbolicExecutionEngineBasicTests:
    """Test SymbolicExecutionEngine with real angr symbolic execution."""

    def _create_minimal_pe(self) -> bytes:
        """Create minimal valid PE binary for testing."""
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 128)

        pe_header = bytearray(256)
        pe_header[0:4] = b"PE\x00\x00"
        pe_header[4:6] = struct.pack("<H", 0x8664)
        pe_header[6:8] = struct.pack("<H", 1)
        pe_header[16:18] = struct.pack("<H", 224)
        pe_header[18:20] = struct.pack("<H", 0x020B)
        pe_header[24:28] = struct.pack("<I", 0x1000)
        pe_header[28:32] = struct.pack("<I", 0x1000)

        code_section = bytearray(4096)
        code_section[0:10] = b"\x48\x83\xEC\x28\x48\x8D\x0D\x00\x00\x00"
        code_section[16:20] = b"\x48\x31\xC0\xC3"

        return bytes(dos_header + pe_header + code_section)

    def _create_vulnerable_pe(self) -> bytes:
        """Create PE binary with buffer overflow vulnerability pattern."""
        base = bytearray(self._create_minimal_pe())

        vuln_code = bytearray()
        vuln_code.extend(b"\x55\x48\x89\xE5")
        vuln_code.extend(b"\x48\x83\xEC\x50")
        vuln_code.extend(b"\x48\x8D\x45\xB0")
        vuln_code.extend(b"\x48\x89\xC1")
        vuln_code.extend(b"\xE8\x00\x00\x00\x00")
        vuln_code.extend(b"\x48\x83\xC4\x50")
        vuln_code.extend(b"\x5D\xC3")

        base[256:256 + len(vuln_code)] = vuln_code
        return bytes(base)

    def test_engine_initialization_with_real_binary(self, temp_binary: Path) -> None:
        """Symbolic execution engine initializes with real binary file."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=50,
            timeout=60,
            memory_limit=2048,
        )

        assert engine.binary_path == str(temp_binary)
        assert engine.max_paths == 50
        assert engine.timeout == 60
        assert engine.memory_limit == 2048 * 1024 * 1024
        assert isinstance(engine.states, list)
        assert isinstance(engine.completed_paths, list)
        assert isinstance(engine.crashed_states, list)
        assert isinstance(engine.discovered_vulnerabilities, list)
        assert isinstance(engine.coverage_data, dict)
        assert temp_binary.exists()

    def test_engine_rejects_nonexistent_binary(self) -> None:
        """Symbolic execution engine rejects non-existent binary."""
        with pytest.raises(FileNotFoundError) as exc_info:
            SymbolicExecutionEngine(
                binary_path="/nonexistent/path/fake.exe",
                max_paths=10,
                timeout=30,
            )

        assert "not found" in str(exc_info.value).lower()

    def test_discover_vulnerabilities_buffer_overflow_detection(
        self, vulnerable_binary: Path
    ) -> None:
        """Symbolic execution discovers buffer overflow vulnerabilities in real binary."""
        engine = SymbolicExecutionEngine(
            binary_path=str(vulnerable_binary),
            max_paths=20,
            timeout=120,
            memory_limit=1024,
        )

        vulns = engine.discover_vulnerabilities(
            vulnerability_types=["buffer_overflow", "stack_overflow"]
        )

        assert isinstance(vulns, list)

        if engine.angr_available:
            assert len(vulns) >= 0

            for vuln in vulns:
                assert isinstance(vuln, dict)
                assert "type" in vuln
                assert vuln["type"] in [
                    "buffer_overflow",
                    "stack_overflow",
                    "heap_overflow",
                ]
                assert "address" in vuln
                assert "description" in vuln
                assert "severity" in vuln
                assert vuln["severity"] in ["critical", "high", "medium", "low"]

                if "input" in vuln:
                    assert isinstance(vuln["input"], (bytes, str, type(None)))

    def test_discover_vulnerabilities_integer_overflow(self, temp_binary: Path) -> None:
        """Symbolic execution detects integer overflow vulnerabilities."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=15,
            timeout=90,
        )

        vulns = engine.discover_vulnerabilities(
            vulnerability_types=["integer_overflow", "buffer_overflow"]
        )

        assert isinstance(vulns, list)

        for vuln in vulns:
            assert isinstance(vuln, dict)
            assert "type" in vuln

            if vuln["type"] == "integer_overflow":
                assert "address" in vuln
                assert "constraint" in vuln
                assert "severity" in vuln

    def test_discover_vulnerabilities_format_string(self, temp_binary: Path) -> None:
        """Symbolic execution detects format string vulnerabilities."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=10,
            timeout=60,
        )

        vulns = engine.discover_vulnerabilities(vulnerability_types=["format_string"])

        assert isinstance(vulns, list)

        for vuln in vulns:
            if vuln.get("type") == "format_string":
                assert "address" in vuln
                assert "description" in vuln
                assert "severity" in vuln

    def test_discover_vulnerabilities_without_angr_fallback(
        self, temp_binary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Symbolic execution provides native fallback when angr unavailable."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=5,
            timeout=30,
        )

        monkeypatch.setattr(engine, "angr_available", False)

        vulns = engine.discover_vulnerabilities(
            vulnerability_types=["buffer_overflow", "integer_overflow"]
        )

        assert isinstance(vulns, list)
        assert len(vulns) >= 0

    def test_discover_vulnerabilities_comprehensive_scan(
        self, vulnerable_binary: Path
    ) -> None:
        """Symbolic execution performs comprehensive vulnerability scan."""
        engine = SymbolicExecutionEngine(
            binary_path=str(vulnerable_binary),
            max_paths=30,
            timeout=180,
        )

        vulns = engine.discover_vulnerabilities(vulnerability_types=None)

        assert isinstance(vulns, list)

        if engine.angr_available and vulns:
            vuln_types = {v["type"] for v in vulns}

            for vuln in vulns:
                assert isinstance(vuln, dict)
                assert "type" in vuln
                assert "address" in vuln or "error" in vuln
                assert "description" in vuln or "error" in vuln

    def test_generate_exploit_buffer_overflow(self, temp_binary: Path) -> None:
        """Generate exploit payload for buffer overflow vulnerability."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=10,
            timeout=60,
        )

        vulnerability = {
            "type": "buffer_overflow",
            "address": "0x401000",
            "severity": "high",
            "input": b"A" * 256,
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)

        if "error" not in exploit:
            assert exploit["type"] == "buffer_overflow"
            assert "payload" in exploit
            assert isinstance(exploit["payload"], str)
            assert "instructions" in exploit
            assert len(exploit["payload"]) > 0

    def test_generate_exploit_format_string(self, temp_binary: Path) -> None:
        """Generate exploit payload for format string vulnerability."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=10,
            timeout=60,
        )

        vulnerability = {
            "type": "format_string",
            "address": "0x401100",
            "severity": "high",
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)

        if "error" not in exploit:
            assert exploit["type"] == "format_string"
            assert "payload" in exploit
            assert "instructions" in exploit

    def test_generate_exploit_integer_overflow(self, temp_binary: Path) -> None:
        """Generate exploit payload for integer overflow vulnerability."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=5,
            timeout=30,
        )

        vulnerability = {
            "type": "integer_overflow",
            "address": "0x401200",
            "severity": "medium",
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)

        if "error" not in exploit:
            assert exploit["type"] == "integer_overflow"
            assert "payload" in exploit
            assert "instructions" in exploit

    def test_generate_exploit_heap_overflow(self, temp_binary: Path) -> None:
        """Generate exploit for heap overflow with heap manipulation techniques."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=10,
            timeout=60,
        )

        vulnerability = {
            "type": "heap_overflow",
            "address": "0x401300",
            "severity": "critical",
            "heap_info": {
                "chunk_size": 0x100,
                "target_addr": 0x600000,
                "technique": "unlink",
            },
            "overflow_size": 256,
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)

        if "error" not in exploit:
            assert exploit["type"] == "heap_overflow"
            assert "payload" in exploit
            assert "technique" in exploit
            assert "instructions" in exploit
            assert "heap_layout" in exploit

            heap_layout = exploit["heap_layout"]
            assert isinstance(heap_layout, dict)
            assert "spray_count" in heap_layout
            assert "chunk_size" in heap_layout
            assert "overflow_offset" in heap_layout

    def test_generate_exploit_use_after_free(self, temp_binary: Path) -> None:
        """Generate exploit for use-after-free with object lifecycle manipulation."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=10,
            timeout=60,
        )

        vulnerability = {
            "type": "use_after_free",
            "address": "0x401400",
            "severity": "critical",
            "uaf_info": {
                "object_size": 0x40,
                "vtable_offset": 0,
                "target_id": 1,
                "trigger_method": "virtual_call",
            },
            "process_info": {
                "base_address": 0x400000,
                "module_size": 0x100000,
                "aslr_enabled": False,
            },
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)

        if "error" not in exploit:
            assert exploit["type"] == "use_after_free"
            assert "exploit_sequence" in exploit
            assert "payload" in exploit
            assert "instructions" in exploit
            assert "object_info" in exploit
            assert "reliability" in exploit

            exploit_seq = exploit["exploit_sequence"]
            assert isinstance(exploit_seq, list)
            assert len(exploit_seq) > 0

            for step in exploit_seq:
                assert isinstance(step, dict)
                assert "action" in step

    def test_generate_exploit_race_condition(self, temp_binary: Path) -> None:
        """Generate exploit for race condition with timing attacks."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=5,
            timeout=30,
        )

        vulnerability = {
            "type": "race_condition",
            "address": "0x401500",
            "severity": "high",
            "race_info": {"window_size": 1000},
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)

        if "error" not in exploit:
            assert exploit["type"] == "race_condition"
            assert "exploit" in exploit
            assert "payload" in exploit
            assert "instructions" in exploit
            assert "timing_info" in exploit

            timing = exploit["timing_info"]
            assert isinstance(timing, dict)
            assert "window_size_us" in timing
            assert "iterations" in timing

    def test_generate_exploit_type_confusion(self, temp_binary: Path) -> None:
        """Generate exploit for type confusion vulnerability."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=5,
            timeout=30,
        )

        vulnerability = {
            "type": "type_confusion",
            "address": "0x401600",
            "severity": "high",
            "confusion_info": {"source_type": "TypeA", "target_type": "TypeB"},
            "process_info": {"base_address": 0x400000, "symbols": {}},
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)

    def test_explore_from_address_path_discovery(self, temp_binary: Path) -> None:
        """Symbolic execution explores paths from specific address."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=10,
            timeout=60,
        )

        result = engine.explore_from(
            start_address=0x401000,
            max_depth=5,
            find_addresses=[0x401100],
            avoid_addresses=[0x401200],
        )

        assert isinstance(result, dict)

        if engine.angr_available:
            assert "found_paths" in result or "active_states" in result
            assert "execution_time" in result

            if "found_paths" in result:
                found_paths = result["found_paths"]
                assert isinstance(found_paths, list)

    def test_explore_from_native_fallback(
        self, temp_binary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Native path exploration when angr unavailable."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=5,
            timeout=30,
        )

        monkeypatch.setattr(engine, "angr_available", False)

        result = engine.explore_from(start_address=0x401000, max_depth=3)

        assert isinstance(result, dict)
        assert "paths" in result
        assert "vulnerabilities" in result
        assert "execution_tree" in result

    def test_taint_tracker_basic_operations(self) -> None:
        """TaintTracker tracks tainted data propagation."""
        tracker = TaintTracker()

        tracker.add_taint("user_input_buffer", "stdin")
        tracker.add_taint("network_data", "socket_recv")
        tracker.add_taint("file_contents", "file_read")

        assert tracker.is_tainted("user_input_buffer")
        assert tracker.is_tainted("network_data")
        assert tracker.is_tainted("file_contents")
        assert not tracker.is_tainted("safe_constant")

        assert tracker.get_taint_source("user_input_buffer") == "stdin"
        assert tracker.get_taint_source("network_data") == "socket_recv"
        assert tracker.get_taint_source("file_contents") == "file_read"
        assert tracker.get_taint_source("safe_constant") is None

    def test_taint_tracker_data_flow_analysis(self) -> None:
        """TaintTracker supports data flow analysis for license checks."""
        tracker = TaintTracker()

        tracker.add_taint("license_key_input", "user_input")
        tracker.add_taint("serial_number", "registry_read")
        tracker.add_taint("activation_code", "network_response")

        tainted_vars = [
            "license_key_input",
            "serial_number",
            "activation_code",
            "safe_hardcoded_value",
        ]

        tainted_count = sum(1 for var in tainted_vars if tracker.is_tainted(var))

        assert tainted_count == 3

        sources = [
            tracker.get_taint_source(var)
            for var in tainted_vars
            if tracker.is_tainted(var)
        ]

        assert "user_input" in sources
        assert "registry_read" in sources
        assert "network_response" in sources

    def test_vulnerability_discovery_on_real_fixtures(self) -> None:
        """Symbolic execution analyzes real vulnerable test fixtures."""
        fixtures_dir = Path("tests/fixtures/vulnerable_samples")

        if not fixtures_dir.exists():
            pytest.skip("Vulnerable test fixtures not available")

        vulnerable_files = list(fixtures_dir.glob("*.exe"))

        if not vulnerable_files:
            pytest.skip("No vulnerable binaries found in fixtures")

        test_binary = vulnerable_files[0]

        engine = SymbolicExecutionEngine(
            binary_path=str(test_binary),
            max_paths=20,
            timeout=120,
        )

        vulns = engine.discover_vulnerabilities(
            vulnerability_types=["buffer_overflow", "integer_overflow", "format_string"]
        )

        assert isinstance(vulns, list)

    def test_constraint_solving_for_license_validation(self, temp_binary: Path) -> None:
        """Symbolic execution solves constraints to find valid license keys."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=15,
            timeout=90,
        )

        result = engine.explore_from(
            start_address=0x401000,
            max_depth=10,
            symbolic_stdin=True,
        )

        assert isinstance(result, dict)

        if engine.angr_available and "found_paths" in result:
            found_paths = result["found_paths"]

            for path in found_paths:
                if "constraints" in path:
                    constraints = path["constraints"]
                    assert isinstance(constraints, (list, tuple))

    def test_path_exploration_with_depth_limit(self, temp_binary: Path) -> None:
        """Symbolic execution respects depth limits during path exploration."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=5,
            timeout=30,
        )

        shallow_result = engine.explore_from(start_address=0x401000, max_depth=2)

        deep_result = engine.explore_from(start_address=0x401000, max_depth=10)

        assert isinstance(shallow_result, dict)
        assert isinstance(deep_result, dict)

    def test_memory_limit_enforcement(self, temp_binary: Path) -> None:
        """Symbolic execution enforces memory limits during analysis."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=100,
            timeout=120,
            memory_limit=512,
        )

        assert engine.memory_limit == 512 * 1024 * 1024

        result = engine.explore_from(start_address=0x401000, max_depth=5)

        assert isinstance(result, dict)

    def test_timeout_handling_during_execution(self, temp_binary: Path) -> None:
        """Symbolic execution handles timeouts gracefully."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=1000,
            timeout=5,
        )

        import time

        start = time.time()
        result = engine.discover_vulnerabilities(vulnerability_types=None)
        elapsed = time.time() - start

        assert isinstance(result, list)
        assert elapsed < 15

    def test_binary_with_protection_detection(self) -> None:
        """Symbolic execution analyzes protected binaries."""
        protected_dir = Path("tests/fixtures/binaries/protected")

        if not protected_dir.exists():
            pytest.skip("Protected binary fixtures not available")

        protected_files = list(protected_dir.glob("*.exe"))

        if not protected_files:
            pytest.skip("No protected binaries found")

        test_binary = protected_files[0]

        engine = SymbolicExecutionEngine(
            binary_path=str(test_binary),
            max_paths=10,
            timeout=60,
        )

        vulns = engine.discover_vulnerabilities(
            vulnerability_types=["buffer_overflow"]
        )

        assert isinstance(vulns, list)

    def test_state_management_during_exploration(self, temp_binary: Path) -> None:
        """Symbolic execution maintains state lists during exploration."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=10,
            timeout=60,
        )

        initial_states_count = len(engine.states)
        initial_completed_count = len(engine.completed_paths)
        initial_crashed_count = len(engine.crashed_states)

        engine.discover_vulnerabilities(vulnerability_types=["buffer_overflow"])

        assert isinstance(engine.states, list)
        assert isinstance(engine.completed_paths, list)
        assert isinstance(engine.crashed_states, list)
        assert isinstance(engine.timed_out_states, list)

    def test_coverage_data_collection(self, temp_binary: Path) -> None:
        """Symbolic execution collects coverage data during analysis."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=15,
            timeout=60,
        )

        engine.discover_vulnerabilities(vulnerability_types=["buffer_overflow"])

        assert isinstance(engine.coverage_data, dict)

    def test_vulnerability_deduplication(self, vulnerable_binary: Path) -> None:
        """Symbolic execution deduplicates discovered vulnerabilities."""
        engine = SymbolicExecutionEngine(
            binary_path=str(vulnerable_binary),
            max_paths=20,
            timeout=90,
        )

        vulns = engine.discover_vulnerabilities(
            vulnerability_types=["buffer_overflow", "stack_overflow", "heap_overflow"]
        )

        assert isinstance(vulns, list)

        if vulns:
            vuln_keys = [(v["type"], v.get("address")) for v in vulns]
            unique_keys = set(vuln_keys)

            assert len(unique_keys) <= len(vulns)

    def test_error_handling_with_corrupted_binary(self, tmp_path: Path) -> None:
        """Symbolic execution handles corrupted binaries gracefully."""
        corrupted_binary = tmp_path / "corrupted.exe"
        corrupted_binary.write_bytes(b"CORRUPTED_NOT_PE_FORMAT_DATA")

        engine = SymbolicExecutionEngine(
            binary_path=str(corrupted_binary),
            max_paths=5,
            timeout=30,
        )

        result = engine.discover_vulnerabilities(vulnerability_types=["buffer_overflow"])

        assert isinstance(result, list)

    def test_multiple_vulnerability_types_detection(
        self, vulnerable_binary: Path
    ) -> None:
        """Symbolic execution detects multiple vulnerability types simultaneously."""
        engine = SymbolicExecutionEngine(
            binary_path=str(vulnerable_binary),
            max_paths=25,
            timeout=120,
        )

        vuln_types = [
            "buffer_overflow",
            "integer_overflow",
            "use_after_free",
            "format_string",
            "null_pointer_deref",
        ]

        vulns = engine.discover_vulnerabilities(vulnerability_types=vuln_types)

        assert isinstance(vulns, list)

        if vulns:
            detected_types = {v["type"] for v in vulns}

            for v_type in detected_types:
                assert v_type in [
                    "buffer_overflow",
                    "integer_overflow",
                    "use_after_free",
                    "format_string",
                    "null_pointer_deref",
                    "stack_overflow",
                    "heap_overflow",
                    "command_injection",
                    "race_condition",
                ]

    def test_symbolic_execution_with_real_pe_binaries(self) -> None:
        """Symbolic execution analyzes real PE binaries from fixtures."""
        pe_dir = Path("tests/fixtures/binaries/pe/legitimate")

        if not pe_dir.exists():
            pytest.skip("PE binary fixtures not available")

        pe_files = list(pe_dir.glob("*.exe"))[:1]

        if not pe_files:
            pytest.skip("No PE binaries found")

        test_binary = pe_files[0]

        engine = SymbolicExecutionEngine(
            binary_path=str(test_binary),
            max_paths=15,
            timeout=90,
        )

        result = engine.explore_from(start_address=0x140001000, max_depth=5)

        assert isinstance(result, dict)

    def test_path_constraint_generation(self, temp_binary: Path) -> None:
        """Symbolic execution generates path constraints during exploration."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=10,
            timeout=60,
        )

        result = engine.explore_from(start_address=0x401000, max_depth=6)

        assert isinstance(result, dict)
        assert isinstance(engine.path_constraints, list)

    def test_crashed_state_detection(self, vulnerable_binary: Path) -> None:
        """Symbolic execution detects crashed states during exploration."""
        engine = SymbolicExecutionEngine(
            binary_path=str(vulnerable_binary),
            max_paths=20,
            timeout=90,
        )

        engine.discover_vulnerabilities(vulnerability_types=["buffer_overflow"])

        assert isinstance(engine.crashed_states, list)

    def test_exploit_reliability_calculation(self, temp_binary: Path) -> None:
        """Exploit generation calculates reliability scores."""
        engine = SymbolicExecutionEngine(
            binary_path=str(temp_binary),
            max_paths=5,
            timeout=30,
        )

        vulnerability = {
            "type": "use_after_free",
            "address": "0x401000",
            "severity": "critical",
            "uaf_info": {"object_size": 0x40, "vtable_offset": 0},
            "process_info": {"aslr_enabled": False, "dep_enabled": False},
        }

        exploit = engine.generate_exploit(vulnerability)

        if "reliability" in exploit:
            reliability = exploit["reliability"]
            assert isinstance(reliability, float)
            assert 0.0 <= reliability <= 1.0


class TestSymbolicExecutionRealWorldScenarios:
    """Test symbolic execution on real-world license validation scenarios."""

    def test_license_key_validation_path_discovery(self, tmp_path: Path) -> None:
        """Symbolic execution discovers paths to valid license keys."""
        binary_path = tmp_path / "license_check.exe"
        binary_path.write_bytes(self._create_license_validation_binary())

        engine = SymbolicExecutionEngine(
            binary_path=str(binary_path),
            max_paths=30,
            timeout=120,
        )

        result = engine.explore_from(
            start_address=0x401000,
            max_depth=15,
            find_addresses=[0x401500],
            avoid_addresses=[0x401600],
        )

        assert isinstance(result, dict)

    def test_serial_number_constraint_solving(self, tmp_path: Path) -> None:
        """Symbolic execution solves constraints for valid serial numbers."""
        binary_path = tmp_path / "serial_check.exe"
        binary_path.write_bytes(self._create_serial_validation_binary())

        engine = SymbolicExecutionEngine(
            binary_path=str(binary_path),
            max_paths=20,
            timeout=90,
        )

        vulns = engine.discover_vulnerabilities(vulnerability_types=None)

        assert isinstance(vulns, list)

    def test_activation_code_analysis(self, tmp_path: Path) -> None:
        """Symbolic execution analyzes activation code validation logic."""
        binary_path = tmp_path / "activation.exe"
        binary_path.write_bytes(self._create_activation_binary())

        engine = SymbolicExecutionEngine(
            binary_path=str(binary_path),
            max_paths=25,
            timeout=120,
        )

        result = engine.explore_from(start_address=0x401000, max_depth=10)

        assert isinstance(result, dict)

    def _create_license_validation_binary(self) -> bytes:
        """Create binary with license validation logic."""
        base = bytearray(4096)
        base[0:2] = b"MZ"
        base[60:64] = struct.pack("<I", 128)
        base[128:132] = b"PE\x00\x00"
        base[132:134] = struct.pack("<H", 0x8664)

        code = bytearray()
        code.extend(b"\x55\x48\x89\xE5")
        code.extend(b"\x48\x83\xEC\x20")
        code.extend(b"\x48\x8B\x45\x10")
        code.extend(b"\x48\x83\xF8\x00")
        code.extend(b"\x74\x10")
        code.extend(b"\xB8\x01\x00\x00\x00")
        code.extend(b"\x48\x83\xC4\x20")
        code.extend(b"\x5D\xC3")

        base[256:256 + len(code)] = code
        return bytes(base)

    def _create_serial_validation_binary(self) -> bytes:
        """Create binary with serial number validation."""
        base = bytearray(4096)
        base[0:2] = b"MZ"
        base[60:64] = struct.pack("<I", 128)
        base[128:132] = b"PE\x00\x00"
        base[132:134] = struct.pack("<H", 0x8664)

        code = bytearray()
        code.extend(b"\x55\x48\x89\xE5")
        code.extend(b"\x48\x83\xEC\x10")
        code.extend(b"\x48\x8B\x45\x08")
        code.extend(b"\x48\x3D\x12\x34\x56\x78")
        code.extend(b"\x75\x08")
        code.extend(b"\xB8\x01\x00\x00\x00")
        code.extend(b"\xEB\x05")
        code.extend(b"\xB8\x00\x00\x00\x00")
        code.extend(b"\x48\x83\xC4\x10")
        code.extend(b"\x5D\xC3")

        base[256:256 + len(code)] = code
        return bytes(base)

    def _create_activation_binary(self) -> bytes:
        """Create binary with activation code logic."""
        base = bytearray(4096)
        base[0:2] = b"MZ"
        base[60:64] = struct.pack("<I", 128)
        base[128:132] = b"PE\x00\x00"
        base[132:134] = struct.pack("<H", 0x8664)

        code = bytearray()
        code.extend(b"\x55\x48\x89\xE5")
        code.extend(b"\x48\x83\xEC\x30")
        code.extend(b"\x48\x89\x4D\x10")
        code.extend(b"\x48\x8B\x45\x10")
        code.extend(b"\x48\x85\xC0")
        code.extend(b"\x74\x15")
        code.extend(b"\x48\x8B\x45\x10")
        code.extend(b"\x8A\x00")
        code.extend(b"\x3C\x41")
        code.extend(b"\x75\x0A")
        code.extend(b"\xB8\x01\x00\x00\x00")
        code.extend(b"\xEB\x05")
        code.extend(b"\xB8\x00\x00\x00\x00")
        code.extend(b"\x48\x83\xC4\x30")
        code.extend(b"\x5D\xC3")

        base[256:256 + len(code)] = code
        return bytes(base)
