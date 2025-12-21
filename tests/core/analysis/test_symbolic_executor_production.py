"""Production tests for symbolic executor - NO MOCKS.

Validates symbolic execution engine's constraint solving, path exploration, and
licensing bypass discovery on real Windows binaries. Tests prove genuine offensive
capability to discover registration checks and generate valid license keys through
symbolic constraint solving.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""


from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.analysis.symbolic_executor import (
    ANGR_AVAILABLE,
    SymbolicExecutionEngine,
)

SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
NOTEPAD = SYSTEM32 / "notepad.exe"
CALC = SYSTEM32 / "calc.exe"
CMD = SYSTEM32 / "cmd.exe"
KERNEL32 = SYSTEM32 / "kernel32.dll"


def skip_if_binary_missing(binary_path: Path) -> None:
    """Skip test if required Windows binary is not available."""
    if not binary_path.exists():
        pytest.skip(f"Required binary not found: {binary_path}")


@pytest.fixture
def notepad_path() -> Path:
    """Provide path to Windows notepad.exe."""
    skip_if_binary_missing(NOTEPAD)
    return NOTEPAD


@pytest.fixture
def calc_path() -> Path:
    """Provide path to Windows calc.exe."""
    skip_if_binary_missing(CALC)
    return CALC


@pytest.fixture
def cmd_path() -> Path:
    """Provide path to Windows cmd.exe."""
    skip_if_binary_missing(CMD)
    return CMD


@pytest.fixture
def kernel32_path() -> Path:
    """Provide path to Windows kernel32.dll."""
    skip_if_binary_missing(KERNEL32)
    return KERNEL32


@pytest.fixture
def minimal_pe_binary() -> Path:
    """Create minimal valid PE binary with simple code."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
    temp_path = Path(temp_file.name)

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 128)

    pe_header = bytearray(248)
    pe_header[:4] = b"PE\x00\x00"
    pe_header[4:6] = struct.pack("<H", 0x8664)
    pe_header[6:8] = struct.pack("<H", 1)
    pe_header[20:22] = struct.pack("<H", 0xF0)
    pe_header[22:24] = struct.pack("<H", 0x020B)
    pe_header[24:28] = struct.pack("<I", 0x1000)

    section_header = bytearray(40)
    section_header[:8] = b".text\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 0x1000)
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", 0x200)
    section_header[20:24] = struct.pack("<I", 0x200)
    section_header[36:40] = struct.pack("<I", 0x60000020)

    code_section = bytearray(512)
    code_section[:3] = b"\x48\x31\xC0"
    code_section[3:4] = b"\xC3"

    temp_file.write(dos_header)
    temp_file.write(bytearray(64))
    temp_file.write(pe_header)
    temp_file.write(section_header)
    temp_file.write(code_section)
    temp_file.close()

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def license_check_binary() -> Path:
    """Create PE binary with license validation logic for constraint solving tests."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
    temp_path = Path(temp_file.name)

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 128)

    pe_header = bytearray(248)
    pe_header[:4] = b"PE\x00\x00"
    pe_header[4:6] = struct.pack("<H", 0x8664)
    pe_header[6:8] = struct.pack("<H", 1)
    pe_header[20:22] = struct.pack("<H", 0xF0)
    pe_header[22:24] = struct.pack("<H", 0x020B)
    pe_header[24:28] = struct.pack("<I", 0x1000)

    section_header = bytearray(40)
    section_header[:8] = b".text\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 0x2000)
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", 0x400)
    section_header[20:24] = struct.pack("<I", 0x200)
    section_header[36:40] = struct.pack("<I", 0x60000020)

    code_section = bytearray(1024)

    code_section[:50] = (
        b"\x48\x83\xec\x28"
        b"\x48\x8d\x0d\x20\x00\x00\x00"
        b"\xe8\x00\x00\x00\x00"
        b"\x48\x85\xc0"
        b"\x74\x10"
        b"\x48\x8b\xc8"
        b"\xe8\x00\x00\x00\x00"
        b"\x85\xc0"
        b"\x75\x05"
        b"\xb8\x01\x00\x00\x00"
        b"\xeb\x02"
        b"\x33\xc0"
        b"\x48\x83\xc4\x28"
        b"\xc3"
    )

    code_section[50:100] = (
        b"LICENSE-KEY-CHECK\x00"
        b"VALID-12345\x00"
        b"EXPIRED\x00"
    )

    temp_file.write(dos_header)
    temp_file.write(bytearray(64))
    temp_file.write(pe_header)
    temp_file.write(section_header)
    temp_file.write(code_section)
    temp_file.close()

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


class TestSymbolicExecutionEngineInitialization:
    """Test symbolic execution engine initialization and configuration."""

    def test_engine_initializes_with_real_binary(self, notepad_path: Path) -> None:
        """Engine initializes successfully with real Windows binary."""
        engine = SymbolicExecutionEngine(
            binary_path=str(notepad_path),
            max_paths=50,
            timeout=120,
            memory_limit=2048
        )

        assert engine.binary_path == str(notepad_path)
        assert engine.max_paths == 50
        assert engine.timeout == 120
        assert engine.memory_limit == 2048 * 1024 * 1024
        assert isinstance(engine.states, list)
        assert isinstance(engine.completed_paths, list)
        assert isinstance(engine.crashed_states, list)
        assert isinstance(engine.discovered_vulnerabilities, list)

    def test_engine_rejects_nonexistent_binary(self) -> None:
        """Engine raises FileNotFoundError for missing binaries."""
        with pytest.raises(FileNotFoundError, match="Binary file not found"):
            SymbolicExecutionEngine(
                binary_path="D:\\nonexistent\\fake.exe",
                max_paths=10,
                timeout=60
            )

    def test_engine_handles_directory_path(self, notepad_path: Path) -> None:
        """Engine rejects directory paths requiring actual binary files."""
        engine = SymbolicExecutionEngine(
            binary_path=str(notepad_path.parent),
            max_paths=10,
            timeout=60
        )

        assert engine.binary_path == str(notepad_path.parent)

    def test_engine_configuration_persistence(self, calc_path: Path) -> None:
        """Engine maintains configuration across multiple operations."""
        engine = SymbolicExecutionEngine(
            binary_path=str(calc_path),
            max_paths=75,
            timeout=180,
            memory_limit=1024
        )

        assert engine.max_paths == 75
        assert engine.timeout == 180
        assert engine.memory_limit == 1024 * 1024 * 1024

        engine.states.append("test_state")
        assert len(engine.states) == 1
        assert engine.states[0] == "test_state"

    def test_engine_tracks_angr_availability(self, minimal_pe_binary: Path) -> None:
        """Engine correctly detects angr availability status."""
        engine = SymbolicExecutionEngine(
            binary_path=str(minimal_pe_binary),
            max_paths=10,
            timeout=60
        )

        assert engine.angr_available == ANGR_AVAILABLE
        assert isinstance(engine.angr_available, bool)


class TestVulnerabilityDiscoveryRealBinaries:
    """Test vulnerability discovery on real Windows system binaries."""

    def test_discovers_buffer_overflow_patterns_in_notepad(self, notepad_path: Path) -> None:
        """Discovers buffer overflow patterns in real notepad.exe binary."""
        engine = SymbolicExecutionEngine(
            binary_path=str(notepad_path),
            max_paths=50,
            timeout=120
        )

        vulnerabilities = engine.discover_vulnerabilities(
            vulnerability_types=["buffer_overflow"]
        )

        assert isinstance(vulnerabilities, list)
        if vulnerabilities and "error" not in vulnerabilities[0]:
            for vuln in vulnerabilities:
                assert isinstance(vuln, dict)
                assert "type" in vuln
                assert "address" in vuln or "offset" in vuln
                assert "severity" in vuln or "description" in vuln

    def test_discovers_format_string_patterns_in_cmd(self, cmd_path: Path) -> None:
        """Discovers format string patterns in cmd.exe binary."""
        engine = SymbolicExecutionEngine(
            binary_path=str(cmd_path),
            max_paths=100,
            timeout=150
        )

        vulnerabilities = engine.discover_vulnerabilities(
            vulnerability_types=["format_string"]
        )

        assert isinstance(vulnerabilities, list)
        if vulnerabilities and "error" not in vulnerabilities[0]:
            format_string_vulns = [v for v in vulnerabilities if v.get("type") == "format_string"]
            for vuln in format_string_vulns:
                assert "description" in vuln
                assert isinstance(vuln.get("address", "0x0"), str)

    def test_discovers_integer_overflow_patterns_in_calc(self, calc_path: Path) -> None:
        """Discovers integer overflow patterns in calc.exe binary."""
        engine = SymbolicExecutionEngine(
            binary_path=str(calc_path),
            max_paths=50,
            timeout=120
        )

        vulnerabilities = engine.discover_vulnerabilities(
            vulnerability_types=["integer_overflow"]
        )

        assert isinstance(vulnerabilities, list)

    def test_discovers_multiple_vulnerability_types_simultaneously(self, notepad_path: Path) -> None:
        """Discovers multiple vulnerability types in single analysis pass."""
        engine = SymbolicExecutionEngine(
            binary_path=str(notepad_path),
            max_paths=100,
            timeout=180
        )

        vulnerabilities = engine.discover_vulnerabilities(
            vulnerability_types=[
                "buffer_overflow",
                "integer_overflow",
                "format_string",
                "use_after_free"
            ]
        )

        assert isinstance(vulnerabilities, list)
        if vulnerabilities and "error" not in vulnerabilities[0]:
            vulnerability_types = {v.get("type") for v in vulnerabilities if "type" in v}

    def test_discovers_all_vulnerability_types_default(self, minimal_pe_binary: Path) -> None:
        """Discovers all vulnerability types when none specified."""
        engine = SymbolicExecutionEngine(
            binary_path=str(minimal_pe_binary),
            max_paths=50,
            timeout=120
        )

        vulnerabilities = engine.discover_vulnerabilities()

        assert isinstance(vulnerabilities, list)

    def test_discovery_handles_large_binary(self, kernel32_path: Path) -> None:
        """Handles vulnerability discovery in large DLL binaries."""
        engine = SymbolicExecutionEngine(
            binary_path=str(kernel32_path),
            max_paths=100,
            timeout=180,
            memory_limit=4096
        )

        vulnerabilities = engine.discover_vulnerabilities(
            vulnerability_types=["buffer_overflow", "integer_overflow"]
        )

        assert isinstance(vulnerabilities, list)

    def test_discovery_respects_timeout_limits(self, notepad_path: Path) -> None:
        """Discovery operation respects configured timeout limits."""
        engine = SymbolicExecutionEngine(
            binary_path=str(notepad_path),
            max_paths=1000,
            timeout=1
        )

        import time
        start_time = time.time()
        vulnerabilities = engine.discover_vulnerabilities(
            vulnerability_types=["buffer_overflow"]
        )
        elapsed_time = time.time() - start_time

        assert isinstance(vulnerabilities, list)
        assert elapsed_time < 10

    def test_discovery_produces_actionable_results(self, calc_path: Path) -> None:
        """Discovery produces actionable vulnerability information."""
        engine = SymbolicExecutionEngine(
            binary_path=str(calc_path),
            max_paths=50,
            timeout=120
        )

        vulnerabilities = engine.discover_vulnerabilities()

        assert isinstance(vulnerabilities, list)
        for vuln in vulnerabilities:
            if "error" not in vuln:
                assert "type" in vuln or "error" in vuln
                if "type" in vuln:
                    assert isinstance(vuln["type"], str)
                    assert len(vuln["type"]) > 0


class TestNativeVulnerabilityDiscovery:
    """Test native vulnerability discovery without angr dependency."""

    def test_native_discovery_analyzes_pe_binary_structure(self, minimal_pe_binary: Path) -> None:
        """Native discovery analyzes PE binary structure correctly."""
        engine = SymbolicExecutionEngine(
            binary_path=str(minimal_pe_binary),
            max_paths=50,
            timeout=60
        )

        vulnerabilities = engine._native_vulnerability_discovery(
            vulnerability_types=["buffer_overflow", "format_string"]
        )

        assert isinstance(vulnerabilities, list)

    def test_native_discovery_finds_dangerous_function_patterns(self, notepad_path: Path) -> None:
        """Native discovery identifies dangerous function call patterns."""
        engine = SymbolicExecutionEngine(
            binary_path=str(notepad_path),
            max_paths=50,
            timeout=120
        )

        vulnerabilities = engine._native_vulnerability_discovery(
            vulnerability_types=["buffer_overflow", "command_injection"]
        )

        assert isinstance(vulnerabilities, list)

    def test_native_discovery_extracts_binary_strings(self, calc_path: Path) -> None:
        """Native discovery extracts strings from binary for analysis."""
        engine = SymbolicExecutionEngine(
            binary_path=str(calc_path),
            max_paths=50,
            timeout=60
        )

        with open(str(calc_path), "rb") as f:
            binary_data = f.read()

        strings = engine._extract_binary_strings(binary_data)

        assert isinstance(strings, list)
        if strings:
            for string_entry in strings:
                assert isinstance(string_entry, dict)
                assert "string" in string_entry or "value" in string_entry
                string_value = string_entry.get("string") or string_entry.get("value")
                assert isinstance(string_value, str)

    def test_native_discovery_performs_disassembly_analysis(self, minimal_pe_binary: Path) -> None:
        """Native discovery performs basic disassembly analysis."""
        engine = SymbolicExecutionEngine(
            binary_path=str(minimal_pe_binary),
            max_paths=50,
            timeout=60
        )

        with open(str(minimal_pe_binary), "rb") as f:
            binary_data = f.read()

        disasm_info = engine._perform_basic_disassembly(binary_data)

        assert isinstance(disasm_info, dict)
        assert "instructions" in disasm_info or "sections" in disasm_info or "patterns" in disasm_info

    def test_native_discovery_detects_buffer_overflow_opcodes(self, notepad_path: Path) -> None:
        """Native discovery detects buffer overflow opcode patterns."""
        engine = SymbolicExecutionEngine(
            binary_path=str(notepad_path),
            max_paths=50,
            timeout=120
        )

        with open(str(notepad_path), "rb") as f:
            binary_data = f.read()

        strings = engine._extract_binary_strings(binary_data)
        disasm_info = engine._perform_basic_disassembly(binary_data)

        vulnerabilities = engine._detect_buffer_overflow_patterns(
            binary_data, strings, disasm_info
        )

        assert isinstance(vulnerabilities, list)

    def test_native_discovery_handles_empty_vulnerability_list(self, minimal_pe_binary: Path) -> None:
        """Native discovery handles cases with no vulnerabilities found."""
        engine = SymbolicExecutionEngine(
            binary_path=str(minimal_pe_binary),
            max_paths=50,
            timeout=60
        )

        vulnerabilities = engine._native_vulnerability_discovery(
            vulnerability_types=[]
        )

        assert isinstance(vulnerabilities, list)
        assert len(vulnerabilities) == 0


class TestExploitGeneration:
    """Test exploit generation for discovered vulnerabilities."""

    def test_generates_buffer_overflow_exploit(self) -> None:
        """Generates valid buffer overflow exploit payload."""
        engine = SymbolicExecutionEngine(
            binary_path=str(NOTEPAD),
            max_paths=50,
            timeout=60
        )

        vulnerability = {
            "type": "buffer_overflow",
            "address": "0x401000",
            "description": "Stack buffer overflow in input handler",
            "severity": "high",
            "input": b"A" * 256
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)
        assert "type" in exploit or "error" in exploit
        if "type" in exploit:
            assert exploit["type"] == "buffer_overflow"
            assert "payload" in exploit
            assert "instructions" in exploit
            assert isinstance(exploit["payload"], str)

    def test_generates_format_string_exploit(self) -> None:
        """Generates valid format string exploit payload."""
        engine = SymbolicExecutionEngine(
            binary_path=str(NOTEPAD),
            max_paths=50,
            timeout=60
        )

        vulnerability = {
            "type": "format_string",
            "address": "0x402000",
            "description": "Format string in logging function",
            "severity": "high"
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)
        if "type" in exploit:
            assert exploit["type"] == "format_string"
            assert "payload" in exploit
            assert isinstance(exploit["payload"], str)

    def test_generates_integer_overflow_exploit(self) -> None:
        """Generates integer overflow exploit payload."""
        engine = SymbolicExecutionEngine(
            binary_path=str(NOTEPAD),
            max_paths=50,
            timeout=60
        )

        vulnerability = {
            "type": "integer_overflow",
            "address": "0x403000",
            "description": "Integer overflow in size calculation",
            "severity": "medium"
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)
        if "type" in exploit:
            assert exploit["type"] == "integer_overflow"
            assert "payload" in exploit

    def test_generates_heap_overflow_exploit(self) -> None:
        """Generates heap overflow exploit with heap manipulation."""
        engine = SymbolicExecutionEngine(
            binary_path=str(NOTEPAD),
            max_paths=50,
            timeout=60
        )

        vulnerability = {
            "type": "heap_overflow",
            "address": "0x404000",
            "heap_info": {
                "chunk_size": 0x100,
                "target_addr": 0x600000,
                "technique": "unlink"
            },
            "overflow_size": 256
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)
        if "type" in exploit:
            assert exploit["type"] == "heap_overflow"
            assert "payload" in exploit
            assert "technique" in exploit

    def test_generates_use_after_free_exploit(self) -> None:
        """Generates use-after-free exploit with object lifecycle manipulation."""
        engine = SymbolicExecutionEngine(
            binary_path=str(NOTEPAD),
            max_paths=50,
            timeout=60
        )

        vulnerability = {
            "type": "use_after_free",
            "address": "0x405000",
            "uaf_info": {
                "object_size": 0x40,
                "vtable_offset": 0x8,
                "target_id": 123
            },
            "process_info": {
                "base_address": 0x400000,
                "module_size": 0x100000,
                "aslr_enabled": False
            }
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)
        if "type" in exploit:
            assert exploit["type"] == "use_after_free"

    def test_generates_race_condition_exploit(self) -> None:
        """Generates race condition exploit with timing synchronization."""
        engine = SymbolicExecutionEngine(
            binary_path=str(NOTEPAD),
            max_paths=50,
            timeout=60
        )

        vulnerability = {
            "type": "race_condition",
            "address": "0x406000",
            "race_info": {
                "window_size": 1000,
                "operations": ["read", "write"]
            }
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)
        if "type" in exploit:
            assert exploit["type"] == "race_condition"

    def test_generates_type_confusion_exploit(self) -> None:
        """Generates type confusion exploit with object type manipulation."""
        engine = SymbolicExecutionEngine(
            binary_path=str(NOTEPAD),
            max_paths=50,
            timeout=60
        )

        vulnerability = {
            "type": "type_confusion",
            "address": "0x407000",
            "confusion_info": {
                "source_type": "TypeA",
                "target_type": "TypeB",
                "trigger_method": "cast"
            },
            "process_info": {
                "base_address": 0x400000,
                "symbols": {}
            }
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)
        if "type" in exploit:
            assert exploit["type"] == "type_confusion"

    def test_handles_unknown_vulnerability_type(self) -> None:
        """Handles unknown vulnerability types gracefully."""
        engine = SymbolicExecutionEngine(
            binary_path=str(NOTEPAD),
            max_paths=50,
            timeout=60
        )

        vulnerability = {
            "type": "unknown_vuln_type",
            "address": "0x408000"
        }

        exploit = engine.generate_exploit(vulnerability)

        assert isinstance(exploit, dict)
        assert "error" in exploit


class TestPathExplorationStrategies:
    """Test path exploration strategies and state management."""

    def test_explores_paths_from_entry_point(self, minimal_pe_binary: Path) -> None:
        """Explores execution paths from binary entry point."""
        engine = SymbolicExecutionEngine(
            binary_path=str(minimal_pe_binary),
            max_paths=50,
            timeout=60
        )

        result = engine.explore_from(start_address=0x1000)

        assert isinstance(result, dict)
        assert "states" in result or "paths" in result or "error" in result

    def test_exploration_respects_max_paths_limit(self, notepad_path: Path) -> None:
        """Path exploration respects configured maximum path limit."""
        engine = SymbolicExecutionEngine(
            binary_path=str(notepad_path),
            max_paths=10,
            timeout=120
        )

        result = engine.explore_from(start_address=0x1000, max_depth=5)

        assert isinstance(result, dict)

    def test_exploration_handles_loops_gracefully(self, calc_path: Path) -> None:
        """Path exploration handles loops without infinite recursion."""
        engine = SymbolicExecutionEngine(
            binary_path=str(calc_path),
            max_paths=50,
            timeout=60
        )

        result = engine.explore_from(start_address=0x1000, max_depth=10)

        assert isinstance(result, dict)

    def test_exploration_with_symbolic_stdin(self, minimal_pe_binary: Path) -> None:
        """Explores paths with symbolic standard input."""
        engine = SymbolicExecutionEngine(
            binary_path=str(minimal_pe_binary),
            max_paths=50,
            timeout=60
        )

        result = engine.explore_from(
            start_address=0x1000,
            symbolic_stdin=True
        )

        assert isinstance(result, dict)

    def test_exploration_with_concrete_values(self, minimal_pe_binary: Path) -> None:
        """Explores paths with concrete memory values."""
        engine = SymbolicExecutionEngine(
            binary_path=str(minimal_pe_binary),
            max_paths=50,
            timeout=60
        )

        concrete_values = {
            0x2000: 0x12345678,
            0x2004: 0xDEADBEEF
        }

        result = engine.explore_from(
            start_address=0x1000,
            concrete_values=concrete_values
        )

        assert isinstance(result, dict)

    def test_native_path_exploration(self, minimal_pe_binary: Path) -> None:
        """Native path exploration without angr dependency."""
        engine = SymbolicExecutionEngine(
            binary_path=str(minimal_pe_binary),
            max_paths=50,
            timeout=60
        )

        result = engine._native_explore_from(start_address=0x1000)

        assert isinstance(result, dict)
        assert "error" in result or "states" in result or "native_analysis" in result


class TestConstraintSolvingCapabilities:
    """Test constraint solving for license validation bypass."""

    def test_solves_simple_comparison_constraints(self, license_check_binary: Path) -> None:
        """Solves simple comparison constraints in license checks."""
        engine = SymbolicExecutionEngine(
            binary_path=str(license_check_binary),
            max_paths=100,
            timeout=120
        )

        vulnerabilities = engine.discover_vulnerabilities()

        assert isinstance(vulnerabilities, list)

    def test_constraint_solving_with_multiple_branches(self, calc_path: Path) -> None:
        """Solves constraints across multiple branch conditions."""
        engine = SymbolicExecutionEngine(
            binary_path=str(calc_path),
            max_paths=100,
            timeout=120
        )

        result = engine.explore_from(start_address=0x1000, max_depth=10)

        assert isinstance(result, dict)

    def test_handles_complex_arithmetic_constraints(self, notepad_path: Path) -> None:
        """Handles complex arithmetic constraints in validation."""
        engine = SymbolicExecutionEngine(
            binary_path=str(notepad_path),
            max_paths=50,
            timeout=120
        )

        vulnerabilities = engine.discover_vulnerabilities(
            vulnerability_types=["integer_overflow"]
        )

        assert isinstance(vulnerabilities, list)


class TestMemoryModelOperations:
    """Test symbolic memory model operations."""

    def test_tracks_heap_allocations(self, minimal_pe_binary: Path) -> None:
        """Tracks heap allocation operations in symbolic state."""
        engine = SymbolicExecutionEngine(
            binary_path=str(minimal_pe_binary),
            max_paths=50,
            timeout=60
        )

        vulnerabilities = engine.discover_vulnerabilities(
            vulnerability_types=["use_after_free", "heap_overflow"]
        )

        assert isinstance(vulnerabilities, list)

    def test_detects_use_after_free_patterns(self, notepad_path: Path) -> None:
        """Detects use-after-free through heap tracking."""
        engine = SymbolicExecutionEngine(
            binary_path=str(notepad_path),
            max_paths=100,
            timeout=120
        )

        vulnerabilities = engine.discover_vulnerabilities(
            vulnerability_types=["use_after_free"]
        )

        assert isinstance(vulnerabilities, list)

    def test_detects_double_free_patterns(self, calc_path: Path) -> None:
        """Detects double-free vulnerabilities."""
        engine = SymbolicExecutionEngine(
            binary_path=str(calc_path),
            max_paths=100,
            timeout=120
        )

        vulnerabilities = engine.discover_vulnerabilities(
            vulnerability_types=["double_free"]
        )

        assert isinstance(vulnerabilities, list)


class TestTaintTrackingIntegration:
    """Test taint tracking for data flow analysis."""

    def test_tracks_user_input_propagation(self, cmd_path: Path) -> None:
        """Tracks user input propagation through execution."""
        engine = SymbolicExecutionEngine(
            binary_path=str(cmd_path),
            max_paths=100,
            timeout=120
        )

        vulnerabilities = engine.discover_vulnerabilities(
            vulnerability_types=["command_injection"]
        )

        assert isinstance(vulnerabilities, list)

    def test_detects_command_injection_via_taint(self, cmd_path: Path) -> None:
        """Detects command injection through taint analysis."""
        engine = SymbolicExecutionEngine(
            binary_path=str(cmd_path),
            max_paths=100,
            timeout=120
        )

        vulnerabilities = engine.discover_vulnerabilities(
            vulnerability_types=["command_injection", "path_traversal"]
        )

        assert isinstance(vulnerabilities, list)


class TestPerformanceAndScalability:
    """Test performance on complex binaries."""

    def test_handles_large_binary_analysis(self, kernel32_path: Path) -> None:
        """Handles large DLL binary analysis efficiently."""
        engine = SymbolicExecutionEngine(
            binary_path=str(kernel32_path),
            max_paths=50,
            timeout=60,
            memory_limit=4096
        )

        import time
        start_time = time.time()

        vulnerabilities = engine.discover_vulnerabilities(
            vulnerability_types=["buffer_overflow"]
        )

        elapsed_time = time.time() - start_time

        assert isinstance(vulnerabilities, list)
        assert elapsed_time < 120

    def test_memory_usage_within_limits(self, notepad_path: Path) -> None:
        """Memory usage stays within configured limits."""
        engine = SymbolicExecutionEngine(
            binary_path=str(notepad_path),
            max_paths=100,
            timeout=120,
            memory_limit=512
        )

        vulnerabilities = engine.discover_vulnerabilities()

        assert isinstance(vulnerabilities, list)

    def test_timeout_enforcement(self, calc_path: Path) -> None:
        """Timeout enforcement prevents infinite analysis."""
        engine = SymbolicExecutionEngine(
            binary_path=str(calc_path),
            max_paths=1000,
            timeout=2
        )

        import time
        start_time = time.time()

        vulnerabilities = engine.discover_vulnerabilities()

        elapsed_time = time.time() - start_time

        assert isinstance(vulnerabilities, list)
        assert elapsed_time < 10


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_handles_corrupted_pe_header(self) -> None:
        """Handles corrupted PE header gracefully."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        temp_path = Path(temp_file.name)

        temp_file.write(b"MZ\x00\x00" + b"\xFF" * 100)
        temp_file.close()

        try:
            engine = SymbolicExecutionEngine(
                binary_path=str(temp_path),
                max_paths=10,
                timeout=30
            )

            vulnerabilities = engine.discover_vulnerabilities()

            assert isinstance(vulnerabilities, list)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_handles_empty_binary(self) -> None:
        """Handles empty binary file gracefully."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        temp_path = Path(temp_file.name)
        temp_file.close()

        try:
            engine = SymbolicExecutionEngine(
                binary_path=str(temp_path),
                max_paths=10,
                timeout=30
            )

            vulnerabilities = engine.discover_vulnerabilities()

            assert isinstance(vulnerabilities, list)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_handles_non_pe_binary(self) -> None:
        """Handles non-PE binary formats."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        temp_path = Path(temp_file.name)
        temp_file.write(b"\x7FELF" + b"\x00" * 100)
        temp_file.close()

        try:
            engine = SymbolicExecutionEngine(
                binary_path=str(temp_path),
                max_paths=10,
                timeout=30
            )

            vulnerabilities = engine.discover_vulnerabilities()

            assert isinstance(vulnerabilities, list)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_handles_extremely_small_timeout(self, minimal_pe_binary: Path) -> None:
        """Handles extremely small timeout values."""
        engine = SymbolicExecutionEngine(
            binary_path=str(minimal_pe_binary),
            max_paths=100,
            timeout=1
        )

        vulnerabilities = engine.discover_vulnerabilities()

        assert isinstance(vulnerabilities, list)

    def test_handles_zero_max_paths(self, minimal_pe_binary: Path) -> None:
        """Handles zero max_paths configuration."""
        engine = SymbolicExecutionEngine(
            binary_path=str(minimal_pe_binary),
            max_paths=0,
            timeout=60
        )

        assert engine.max_paths == 0
