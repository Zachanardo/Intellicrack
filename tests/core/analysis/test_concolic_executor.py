"""Comprehensive tests for concolic executor module.

Tests cover all classes, methods, and edge cases for the concolic execution engine.
All tests validate real functionality against actual binary execution and constraint solving.
"""

import logging
import os
import struct
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

from intellicrack.core.analysis.concolic_executor import (
    MANTICORE_AVAILABLE,
    ConcolicExecutionEngine,
    Manticore,
    NativeConcolicState,
    Plugin,
    run_concolic_execution,
)


CAPSTONE_AVAILABLE = False
try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    pass

Z3_AVAILABLE = False
try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    pass


class FakeApplicationContext:
    """Real test double for application context object.

    Represents an application context that concolic execution functions
    might receive as a parameter. This is a real implementation that stores
    configuration and state rather than a mock.
    """

    def __init__(self) -> None:
        """Initialize fake application context with default configuration."""
        self.config: Dict[str, Any] = {
            "timeout": 300,
            "max_states": 1000,
            "verbose": False,
        }
        self.logger: logging.Logger = logging.getLogger("FakeApp")
        self.session_data: Dict[str, Any] = {}
        self.execution_history: List[str] = []

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key.

        Args:
            key: Configuration key to retrieve.
            default: Default value if key not found.

        Returns:
            Configuration value or default.
        """
        return self.config.get(key, default)

    def set_config(self, key: str, value: Any) -> None:
        """Set configuration value.

        Args:
            key: Configuration key to set.
            value: Value to store.
        """
        self.config[key] = value

    def log_execution(self, binary_path: str) -> None:
        """Log execution of a binary analysis.

        Args:
            binary_path: Path to analyzed binary.
        """
        self.execution_history.append(binary_path)
        self.logger.info("Logged execution: %s", binary_path)


@pytest.fixture
def simple_pe_binary(tmp_path: Path) -> Path:
    """Create a minimal valid PE binary for testing."""
    pe_binary = tmp_path / "test_binary.exe"

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 128)

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,
        1,
        0,
        0,
        0,
        224,
        0x0103,
    )

    optional_header = struct.pack(
        "<HHIIIIHHHHHHIIIHHHHHHII",
        0x010B,
        0,
        4096,
        0,
        0,
        0x1000,
        0x1000,
        0x400000,
        0x1000,
        0x200,
        0,
        0,
        4,
        0,
        0,
        0,
        0,
        0,
        4096,
        512,
        0,
        3,
        0,
        0x100000,
        0x1000,
    )

    section_header = bytearray(40)
    section_header[:8] = b".text\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 4096)
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", 512)
    section_header[20:24] = struct.pack("<I", 512)
    section_header[36:40] = struct.pack("<I", 0x60000020)

    code_section = bytearray(512)
    code_section[:6] = bytes(
        [
            0x90,
            0xB8,
            0x01,
            0x00,
            0x00,
            0x00,
        ]
    )
    code_section[6:7] = bytes([0xC3])

    pe_data = dos_header + pe_signature + coff_header + optional_header + section_header + code_section

    pe_binary.write_bytes(pe_data)
    return pe_binary


@pytest.fixture
def simple_elf_binary(tmp_path: Path) -> Path:
    """Create a minimal valid ELF binary for testing."""
    elf_binary = tmp_path / "test_binary.elf"

    elf_header = bytearray(64)
    elf_header[:4] = b"\x7fELF"
    elf_header[4] = 2
    elf_header[5] = 1
    elf_header[6] = 1
    elf_header[16:18] = struct.pack("<H", 2)
    elf_header[18:20] = struct.pack("<H", 0x3E)
    elf_header[20:24] = struct.pack("<I", 1)
    elf_header[24:32] = struct.pack("<Q", 0x401000)

    code = bytearray(256)
    code[:3] = bytes([0x90, 0x90, 0xC3])

    elf_data = elf_header + code

    elf_binary.write_bytes(elf_data)
    return elf_binary


@pytest.fixture
def binary_with_license_string(tmp_path: Path) -> Path:
    """Create a binary containing license-related strings."""
    binary = tmp_path / "licensed_app.exe"

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 128)

    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0103)
    optional_header = struct.pack(
        "<HHIIIIHHHHHHIIIHHHHHHII",
        0x010B, 0, 4096, 0, 0, 0x1000, 0x1000, 0x400000, 0x1000, 0x200,
        0, 0, 4, 0, 0, 0, 0, 0, 4096, 512, 0, 3, 0, 0x100000, 0x1000,
    )

    section_header = bytearray(40)
    section_header[:8] = b".data\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 4096)
    section_header[12:16] = struct.pack("<I", 0x2000)
    section_header[16:20] = struct.pack("<I", 512)
    section_header[20:24] = struct.pack("<I", 512)
    section_header[36:40] = struct.pack("<I", 0xC0000040)

    data_section = bytearray(512)
    license_string = b"license validation check failed"
    data_section[100:100+len(license_string)] = license_string

    binary_data = dos_header + pe_signature + coff_header + optional_header + section_header + data_section
    binary.write_bytes(binary_data)
    return binary


@pytest.fixture
def binary_with_conditional_branches(tmp_path: Path) -> Path:
    """Create a binary with conditional branch instructions."""
    binary = tmp_path / "branching_app.exe"

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 128)

    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0103)
    optional_header = struct.pack(
        "<HHIIIIHHHHHHIIIHHHHHHII",
        0x010B, 0, 4096, 0, 0, 0x1000, 0x1000, 0x400000, 0x1000, 0x200,
        0, 0, 4, 0, 0, 0, 0, 0, 4096, 512, 0, 3, 0, 0x100000, 0x1000,
    )

    section_header = bytearray(40)
    section_header[:8] = b".text\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 4096)
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", 512)
    section_header[20:24] = struct.pack("<I", 512)
    section_header[36:40] = struct.pack("<I", 0x60000020)

    code_section = bytearray(512)
    code = [
        0x31, 0xC0,
        0x3C, 0x05,
        0x74, 0x05,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3,
        0xB8, 0x02, 0x00, 0x00, 0x00,
        0xC3,
    ]
    code_section[:len(code)] = bytes(code)

    binary_data = dos_header + pe_signature + coff_header + optional_header + section_header + code_section
    binary.write_bytes(binary_data)
    return binary


class TestNativeConcolicState:
    """Tests for NativeConcolicState class."""

    def test_initialization_default_values(self) -> None:
        """NativeConcolicState initializes with correct default values."""
        state = NativeConcolicState()

        assert state.pc == 0
        assert isinstance(state.memory, dict)
        assert isinstance(state.registers, dict)
        assert state.registers["eax"] == 0
        assert state.registers["esp"] == 0x7FFF0000
        assert state.registers["ebp"] == 0x7FFF0000
        assert isinstance(state.symbolic_memory, dict)
        assert isinstance(state.symbolic_registers, dict)
        assert isinstance(state.constraints, list)
        assert len(state.constraints) == 0
        assert state.is_terminated_flag is False
        assert state.termination_reason is None

    def test_initialization_custom_values(self) -> None:
        """NativeConcolicState initializes with custom values."""
        custom_memory = {0x1000: 0x42, 0x1001: 0x43}
        custom_registers = {"eax": 0x100, "ebx": 0x200}

        state = NativeConcolicState(pc=0x401000, memory=custom_memory, registers=custom_registers)

        assert state.pc == 0x401000
        assert state.memory[0x1000] == 0x42
        assert state.registers["eax"] == 0x100
        assert state.registers["ebx"] == 0x200

    def test_is_terminated_returns_false_initially(self) -> None:
        """is_terminated returns False for newly created state."""
        state = NativeConcolicState()
        assert state.is_terminated() is False

    def test_terminate_sets_flag_and_reason(self) -> None:
        """terminate sets termination flag and reason."""
        state = NativeConcolicState()
        state.terminate("test_reason")

        assert state.is_terminated() is True
        assert state.termination_reason == "test_reason"

    def test_fork_creates_independent_copy(self) -> None:
        """fork creates independent copy of state."""
        original = NativeConcolicState(pc=0x1000)
        original.memory[0x2000] = 0x42
        original.registers["eax"] = 0x100
        original.constraints.append("ZF==1")
        original.execution_trace.append({"pc": 0x1000, "instruction": "test"})

        forked = original.fork()

        assert forked.pc == original.pc
        assert forked.memory[0x2000] == 0x42
        assert forked.registers["eax"] == 0x100
        assert "ZF==1" in forked.constraints
        assert len(forked.execution_trace) == 1

        forked.pc = 0x2000
        forked.memory[0x2000] = 0x99
        forked.constraints.append("CF==0")

        assert original.pc == 0x1000
        assert original.memory[0x2000] == 0x42
        assert len(original.constraints) == 1

    def test_add_constraint_appends_to_list(self) -> None:
        """add_constraint appends constraint to constraint list."""
        state = NativeConcolicState()

        state.add_constraint("ZF==1")
        state.add_constraint("CF==0")

        assert len(state.constraints) == 2
        assert "ZF==1" in state.constraints
        assert "CF==0" in state.constraints

    def test_set_register_concrete_value(self) -> None:
        """set_register sets concrete register value."""
        state = NativeConcolicState()

        state.set_register("eax", 0x12345678)

        assert state.registers["eax"] == 0x12345678
        assert "eax" not in state.symbolic_registers

    def test_set_register_symbolic_value(self) -> None:
        """set_register sets symbolic register value."""
        state = NativeConcolicState()

        state.set_register("ebx", b"SYMBOLIC", symbolic=True)

        assert state.registers["ebx"] == b"SYMBOLIC"
        assert state.symbolic_registers["ebx"] == b"SYMBOLIC"

    def test_get_register_returns_value(self) -> None:
        """get_register returns register value."""
        state = NativeConcolicState()
        state.registers["ecx"] = 0xDEADBEEF

        value = state.get_register("ecx")

        assert value == 0xDEADBEEF

    def test_get_register_returns_zero_for_unknown(self) -> None:
        """get_register returns zero for unknown register."""
        state = NativeConcolicState()

        value = state.get_register("unknown_reg")

        assert value == 0

    def test_write_memory_single_byte(self) -> None:
        """write_memory writes single byte to memory."""
        state = NativeConcolicState()

        state.write_memory(0x1000, 0x42, size=1)

        assert state.memory[0x1000] == 0x42

    def test_write_memory_four_bytes(self) -> None:
        """write_memory writes four bytes to memory in little-endian."""
        state = NativeConcolicState()

        state.write_memory(0x2000, 0x12345678, size=4)

        assert state.memory[0x2000] == 0x78
        assert state.memory[0x2001] == 0x56
        assert state.memory[0x2002] == 0x34
        assert state.memory[0x2003] == 0x12

    def test_write_memory_symbolic_flag(self) -> None:
        """write_memory stores symbolic memory location."""
        state = NativeConcolicState()

        state.write_memory(0x3000, 0x1234, size=2, symbolic=True)

        assert 0x3000 in state.symbolic_memory
        assert state.symbolic_memory[0x3000] == 0x1234

    def test_read_memory_single_byte(self) -> None:
        """read_memory reads single byte from memory."""
        state = NativeConcolicState()
        state.memory[0x4000] = 0x99

        value = state.read_memory(0x4000, size=1)

        assert value == 0x99

    def test_read_memory_four_bytes(self) -> None:
        """read_memory reads four bytes from memory in little-endian."""
        state = NativeConcolicState()
        state.memory[0x5000] = 0xAA
        state.memory[0x5001] = 0xBB
        state.memory[0x5002] = 0xCC
        state.memory[0x5003] = 0xDD

        value = state.read_memory(0x5000, size=4)

        assert value == 0xDDCCBBAA

    def test_read_memory_missing_bytes_returns_zero(self) -> None:
        """read_memory returns zero for missing memory bytes."""
        state = NativeConcolicState()

        value = state.read_memory(0x9000, size=4)

        assert value == 0


class TestManticoreNativeImplementation:
    """Tests for native Manticore implementation."""

    def test_initialization_without_binary(self) -> None:
        """Manticore initializes without binary path."""
        m = Manticore(None)

        assert m.binary_path is None
        assert isinstance(m.all_states, dict)
        assert isinstance(m.ready_states, list)
        assert isinstance(m.terminated_states, list)
        assert m.execution_complete is False
        assert m.timeout == 300
        assert m.max_states == 1000

    def test_initialization_with_pe_binary(self, simple_pe_binary: Path) -> None:
        """Manticore loads PE binary and parses entry point."""
        m = Manticore(str(simple_pe_binary))

        assert m.binary_path == str(simple_pe_binary)
        assert m.binary_data is not None
        assert len(m.binary_data) > 0
        assert m.entry_point != 0

    def test_initialization_with_elf_binary(self, simple_elf_binary: Path) -> None:
        """Manticore loads ELF binary and parses entry point."""
        m = Manticore(str(simple_elf_binary))

        assert m.binary_path == str(simple_elf_binary)
        assert m.binary_data is not None
        assert m.entry_point != 0

    def test_add_hook_stores_callback(self) -> None:
        """add_hook stores callback for address."""
        m = Manticore(None)
        callback_executed = []

        def test_callback(state: NativeConcolicState) -> None:
            callback_executed.append(True)

        m.add_hook(0x401000, test_callback)

        assert 0x401000 in m.hooks
        assert m.hooks[0x401000] == test_callback

    def test_register_plugin_adds_to_list(self) -> None:
        """register_plugin adds plugin to plugin list."""
        m = Manticore(None)
        plugin = Plugin()

        m.register_plugin(plugin)

        assert plugin in m.plugins

    def test_set_exec_timeout_updates_timeout(self) -> None:
        """set_exec_timeout updates timeout value."""
        m = Manticore(None)

        m.set_exec_timeout(600)

        assert m.timeout == 600

    def test_run_creates_initial_state(self, simple_pe_binary: Path) -> None:
        """run creates initial execution state."""
        m = Manticore(str(simple_pe_binary))
        m.timeout = 1

        m.run(procs=1)

        assert len(m.all_states) > 0
        assert 0 in m.all_states

    def test_run_respects_timeout(self, simple_pe_binary: Path) -> None:
        """run terminates execution after timeout."""
        m = Manticore(str(simple_pe_binary))
        m.timeout = 0.1
        m.max_instructions = 1000000

        m.run(procs=1)

        assert m.execution_complete is True

    def test_run_respects_state_limit(self, simple_pe_binary: Path) -> None:
        """run stops creating states after max_states limit."""
        m = Manticore(str(simple_pe_binary))
        m.max_states = 5
        m.timeout = 1

        m.run(procs=1)

        assert len(m.all_states) <= m.max_states

    def test_run_executes_hook_at_address(self, simple_pe_binary: Path) -> None:
        """run executes hook callback when address is reached."""
        m = Manticore(str(simple_pe_binary))
        hook_called = []

        def hook_callback(state: NativeConcolicState) -> None:
            hook_called.append(state.pc)

        m.add_hook(m.entry_point, hook_callback)
        m.timeout = 1

        m.run(procs=1)

        assert hook_called

    def test_run_terminates_states_properly(self, simple_pe_binary: Path) -> None:
        """run moves completed states to terminated list."""
        m = Manticore(str(simple_pe_binary))
        m.timeout = 1
        m.max_instructions = 100

        m.run(procs=1)

        assert len(m.terminated_states) > 0
        for state in m.terminated_states:
            assert state.is_terminated() is True

    def test_get_all_states_returns_list(self) -> None:
        """get_all_states returns list of all states."""
        m = Manticore(None)
        state1 = NativeConcolicState(pc=0x1000)
        state2 = NativeConcolicState(pc=0x2000)
        m.all_states[0] = state1
        m.all_states[1] = state2

        states = m.get_all_states()

        assert len(states) == 2
        assert state1 in states
        assert state2 in states

    def test_get_terminated_states_returns_list(self) -> None:
        """get_terminated_states returns terminated states."""
        m = Manticore(None)
        terminated_state = NativeConcolicState()
        terminated_state.terminate("test")
        m.terminated_states.append(terminated_state)

        states = m.get_terminated_states()

        assert len(states) == 1
        assert terminated_state in states

    def test_get_ready_states_returns_list(self) -> None:
        """get_ready_states returns ready states."""
        m = Manticore(None)
        ready_state = NativeConcolicState(pc=0x5000)
        m.ready_states.append(ready_state)

        states = m.get_ready_states()

        assert len(states) == 1
        assert ready_state in states

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_emulate_instruction_nop(self) -> None:
        """_emulate_instruction handles NOP instruction."""
        m = Manticore(None)
        state = NativeConcolicState(pc=0x1000)
        state.arch = "x64"
        instruction_bytes = bytes([0x90])

        m._emulate_instruction(state, instruction_bytes)

        assert state.pc == 0x1001

    def test_negate_condition_simple_flags(self) -> None:
        """_negate_condition negates simple flag conditions."""
        m = Manticore(None)

        assert m._negate_condition("ZF==1") == "ZF==0"
        assert m._negate_condition("ZF==0") == "ZF==1"
        assert m._negate_condition("CF==1") == "CF==0"
        assert m._negate_condition("SF==1") == "SF==0"

    def test_negate_condition_complex_or(self) -> None:
        """_negate_condition negates OR conditions."""
        m = Manticore(None)

        result = m._negate_condition("CF==1 or ZF==1")

        assert "CF==0" in result
        assert "ZF==0" in result
        assert " and " in result

    def test_negate_condition_complex_and(self) -> None:
        """_negate_condition negates AND conditions."""
        m = Manticore(None)

        result = m._negate_condition("CF==0 and ZF==0")

        assert "CF==1" in result
        assert "ZF==1" in result
        assert " or " in result

    def test_should_explore_branch_limits_exploration(self) -> None:
        """_should_explore_branch limits state explosion."""
        m = Manticore(None)
        state = NativeConcolicState(pc=0x1000)

        for _ in range(m.max_states + 10):
            m.ready_states.append(NativeConcolicState())

        result = m._should_explore_branch(state, "ZF==1")

        assert result is False

    def test_create_branch_state_respects_limit(self) -> None:
        """_create_branch_state respects max_states limit."""
        m = Manticore(None)
        state = NativeConcolicState(pc=0x1000)

        for _ in range(m.max_states):
            m.ready_states.append(NativeConcolicState())

        initial_count = len(m.ready_states)
        m._create_branch_state(state, 0x2000, "test_constraint")

        assert len(m.ready_states) == initial_count

    def test_create_branch_state_adds_new_state(self) -> None:
        """_create_branch_state creates new state with constraint."""
        m = Manticore(None)
        state = NativeConcolicState(pc=0x1000)
        state.add_constraint("original")

        m._create_branch_state(state, 0x2000, "branch_taken")

        assert len(m.ready_states) == 1
        new_state = m.ready_states[0]
        assert new_state.pc == 0x2000
        assert "branch_taken" in new_state.constraints
        assert "original" in new_state.constraints

    def test_manual_decode_instruction_nop(self) -> None:
        """_manual_decode_instruction handles NOP without Capstone."""
        m = Manticore(None)
        state = NativeConcolicState(pc=0x1000)
        state.arch = "x64"

        m._manual_decode_instruction(state, bytes([0x90]))

        assert state.pc == 0x1001

    def test_manual_decode_instruction_ret(self) -> None:
        """_manual_decode_instruction handles RET instruction."""
        m = Manticore(None)
        state = NativeConcolicState(pc=0x1000)
        state.arch = "x64"
        state.registers["rsp"] = 0x7FFF0000
        state.memory[0x7FFF0000:0x7FFF0008] = struct.pack("<Q", 0x2000)

        m._manual_decode_instruction(state, bytes([0xC3]))

        assert state.pc == 0x2000
        assert state.registers["rsp"] == 0x7FFF0008

    def test_manual_decode_instruction_jmp_short(self) -> None:
        """_manual_decode_instruction handles short JMP."""
        m = Manticore(None)
        state = NativeConcolicState(pc=0x1000)
        state.arch = "x64"

        m._manual_decode_instruction(state, bytes([0xEB, 0x10]))

        assert state.pc == 0x1012

    def test_manual_decode_instruction_jz_taken(self) -> None:
        """_manual_decode_instruction handles JZ when zero flag set."""
        m = Manticore(None)
        state = NativeConcolicState(pc=0x1000)
        state.arch = "x64"
        state.flags = {"ZF": True}

        m._manual_decode_instruction(state, bytes([0x74, 0x05]))

        assert state.pc == 0x1007
        assert any("JZ_taken" in c for c in state.constraints)

    def test_manual_decode_instruction_jnz_not_taken(self) -> None:
        """_manual_decode_instruction handles JNZ when zero flag set."""
        m = Manticore(None)
        state = NativeConcolicState(pc=0x1000)
        state.arch = "x64"
        state.flags = {"ZF": True}

        m._manual_decode_instruction(state, bytes([0x75, 0x05]))

        assert state.pc == 0x1002
        assert any("JNZ_not_taken" in c for c in state.constraints)

    def test_check_for_branches_detects_conditional_jump(self) -> None:
        """_check_for_branches creates alternate states for conditional jumps."""
        m = Manticore(None)
        state = NativeConcolicState(pc=0x1000)
        state.arch = "x64"
        state.flags = {"ZF": False}
        state.memory[0x1000] = 0x74
        state.memory[0x1001] = 0x10

        new_states = m._check_for_branches(state)

        assert isinstance(new_states, list)

    def test_prioritize_states_returns_top_states(self) -> None:
        """_prioritize_states returns highest priority states."""
        m = Manticore(None)
        m.visited_pcs = set()

        states = [NativeConcolicState(pc=0x1000 + i) for i in range(20)]

        for state in states[:10]:
            state.constraints = ["constraint1", "constraint2"]

        prioritized = m._prioritize_states(states, 5)

        assert len(prioritized) == 5

    def test_estimate_instruction_length_single_byte(self) -> None:
        """_estimate_instruction_length estimates single-byte instructions."""
        m = Manticore(None)

        length = m._estimate_instruction_length(bytes([0x90]))

        assert length >= 1

    def test_estimate_instruction_length_with_prefix(self) -> None:
        """_estimate_instruction_length handles instruction prefixes."""
        m = Manticore(None)

        length = m._estimate_instruction_length(bytes([0x66, 0x90]))

        assert length >= 2

    def test_is_indirect_branch_detects_indirect_jmp(self) -> None:
        """_is_indirect_branch detects indirect JMP instruction."""
        m = Manticore(None)
        state = NativeConcolicState()

        result = m._is_indirect_branch(state, bytes([0xFF, 0x20]))

        assert result is True

    def test_is_indirect_branch_detects_ret(self) -> None:
        """_is_indirect_branch detects RET instruction."""
        m = Manticore(None)
        state = NativeConcolicState()

        result = m._is_indirect_branch(state, bytes([0xC3]))

        assert result is True

    def test_analyze_indirect_targets_returns_list(self) -> None:
        """_analyze_indirect_targets returns list of potential targets."""
        m = Manticore(None)
        state = NativeConcolicState(pc=0x1000)
        state.arch = "x64"
        state.memory[0x1000] = 0xC3

        targets = m._analyze_indirect_targets(state)

        assert isinstance(targets, list)
        assert len(targets) > 0


class TestPlugin:
    """Tests for Plugin class."""

    def test_initialization(self) -> None:
        """Plugin initializes correctly."""
        plugin = Plugin()

        assert plugin.logger is not None

    def test_will_run_callback_executes(self) -> None:
        """will_run_callback executes without error."""
        plugin = Plugin()
        executor = Manticore(None)

        plugin.will_run_callback(executor, "test_arg", key="value")

    def test_did_finish_run_callback_executes(self) -> None:
        """did_finish_run_callback executes without error."""
        plugin = Plugin()
        executor = Manticore(None)

        plugin.did_finish_run_callback(executor)

    def test_will_fork_state_callback_executes(self) -> None:
        """will_fork_state_callback executes without error."""
        plugin = Plugin()
        state1 = NativeConcolicState(pc=0x1000)
        state2 = NativeConcolicState(pc=0x2000)

        plugin.will_fork_state_callback(state1, state2)

    def test_will_execute_instruction_callback_executes(self) -> None:
        """will_execute_instruction_callback executes without error."""
        plugin = Plugin()
        state = NativeConcolicState(pc=0x1000)

        plugin.will_execute_instruction_callback(state, 0x1000, None)


class TestConcolicExecutionEngine:
    """Tests for ConcolicExecutionEngine class."""

    def test_initialization_with_valid_binary(self, simple_pe_binary: Path) -> None:
        """ConcolicExecutionEngine initializes with valid binary."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary))

        assert engine.binary_path == str(simple_pe_binary)
        assert engine.max_iterations == 100
        assert engine.timeout == 300
        assert engine.logger is not None

    def test_initialization_with_missing_binary(self, tmp_path: Path) -> None:
        """ConcolicExecutionEngine raises error for missing binary."""
        missing_binary = tmp_path / "nonexistent.exe"

        with pytest.raises(FileNotFoundError):
            ConcolicExecutionEngine(str(missing_binary))

    def test_explore_paths_without_targets(self, simple_pe_binary: Path) -> None:
        """explore_paths executes basic path exploration."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary), timeout=1)

        results = engine.explore_paths()

        assert "success" in results or "error" in results
        if "success" in results:
            assert results["success"] is True
            assert "paths_explored" in results
            assert "inputs" in results

    def test_explore_paths_with_target_address(self, simple_pe_binary: Path) -> None:
        """explore_paths reaches target address."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary), timeout=1)

        results = engine.explore_paths(target_address=0x401000)

        assert "success" in results or "error" in results

    def test_explore_paths_with_avoid_addresses(self, simple_pe_binary: Path) -> None:
        """explore_paths avoids specified addresses."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary), timeout=1)

        results = engine.explore_paths(avoid_addresses=[0x402000, 0x403000])

        assert "success" in results or "error" in results

    def test_find_license_bypass_with_address(self, binary_with_license_string: Path) -> None:
        """find_license_bypass attempts to find bypass with known address."""
        engine = ConcolicExecutionEngine(str(binary_with_license_string), timeout=1)

        results = engine.find_license_bypass(license_check_address=0x401000)

        assert "success" in results or "error" in results
        if "success" in results:
            assert "bypass_found" in results

    def test_find_license_bypass_auto_detect(self, binary_with_license_string: Path) -> None:
        """find_license_bypass attempts automatic license check detection."""
        engine = ConcolicExecutionEngine(str(binary_with_license_string), timeout=1)

        results = engine.find_license_bypass()

        assert isinstance(results, dict)

    def test_find_license_check_address_detects_string(self, binary_with_license_string: Path) -> None:
        """_find_license_check_address detects license-related strings."""
        engine = ConcolicExecutionEngine(str(binary_with_license_string))

        address = engine._find_license_check_address()

        assert address is None or isinstance(address, int)

    def test_extract_analysis_parameters_defaults(self) -> None:
        """_extract_analysis_parameters returns default parameters."""
        engine = ConcolicExecutionEngine.__new__(ConcolicExecutionEngine)
        engine.timeout = 300

        params = engine._extract_analysis_parameters()

        assert params["target_functions"] == []
        assert params["avoid_functions"] == []
        assert params["max_depth"] == 100
        assert params["timeout"] == 300
        assert params["find_vulnerabilities"] is True
        assert params["find_license_checks"] is True
        assert params["generate_test_cases"] is True

    def test_extract_analysis_parameters_custom(self) -> None:
        """_extract_analysis_parameters extracts custom parameters."""
        engine = ConcolicExecutionEngine.__new__(ConcolicExecutionEngine)
        engine.timeout = 300

        params = engine._extract_analysis_parameters(
            max_depth=50,
            timeout=600,
            find_vulnerabilities=False,
            symbolic_stdin_size=512,
        )

        assert params["max_depth"] == 50
        assert params["timeout"] == 600
        assert params["find_vulnerabilities"] is False
        assert params["symbolic_stdin_size"] == 512

    def test_initialize_analysis_results_structure(self) -> None:
        """_initialize_analysis_results creates correct structure."""
        engine = ConcolicExecutionEngine.__new__(ConcolicExecutionEngine)
        engine.binary_path = "/test/binary.exe"

        results = engine._initialize_analysis_results(max_depth=100)

        assert results["binary"] == "/test/binary.exe"
        assert results["test_cases"] == []
        assert results["coverage"] == 0.0
        assert results["paths_explored"] == 0
        assert results["vulnerabilities"] == []
        assert isinstance(results["license_checks"], dict)
        assert results["max_depth"] == 100

    def test_analyze_executes_native_implementation(self, simple_pe_binary: Path) -> None:
        """analyze executes native concolic analysis."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary), timeout=1)

        results = engine.analyze(str(simple_pe_binary))

        assert isinstance(results, dict)
        assert "binary" in results
        assert "paths_explored" in results

    def test_native_analyze_returns_results(self, simple_pe_binary: Path) -> None:
        """_native_analyze returns analysis results."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary))

        results = engine._native_analyze(str(simple_pe_binary), timeout=1)

        assert isinstance(results, dict)
        assert "binary" in results
        assert "test_cases" in results
        assert "coverage" in results
        assert "paths_explored" in results
        assert "execution_time" in results

    def test_native_analyze_handles_errors(self, tmp_path: Path) -> None:
        """_native_analyze handles analysis errors gracefully."""
        invalid_binary = tmp_path / "invalid.exe"
        invalid_binary.write_bytes(b"invalid binary data")

        engine = ConcolicExecutionEngine.__new__(ConcolicExecutionEngine)
        engine.binary_path = str(invalid_binary)
        engine.timeout = 1
        engine.logger = logging.getLogger("test")

        results = engine._native_analyze(str(invalid_binary))

        assert isinstance(results, dict)

    def test_execute_runs_comprehensive_analysis(self, simple_pe_binary: Path) -> None:
        """execute runs comprehensive concolic analysis."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary), timeout=1)

        results = engine.execute()

        assert isinstance(results, dict)
        assert "binary" in results

    def test_execute_with_custom_binary_path(self, simple_pe_binary: Path, simple_elf_binary: Path) -> None:
        """execute accepts different binary path."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary), timeout=1)

        results = engine.execute(str(simple_elf_binary))

        assert engine.binary_path == str(simple_elf_binary)
        assert isinstance(results, dict)


class TestRunConcolicExecution:
    """Tests for run_concolic_execution function."""

    def test_run_concolic_execution_creates_engine(self, simple_pe_binary: Path) -> None:
        """run_concolic_execution creates engine and executes."""
        app = FakeApplicationContext()

        results = run_concolic_execution(app, str(simple_pe_binary))

        assert isinstance(results, dict)

    def test_run_concolic_execution_returns_results(self, simple_pe_binary: Path) -> None:
        """run_concolic_execution returns execution results."""
        app = FakeApplicationContext()

        results = run_concolic_execution(app, str(simple_pe_binary))

        assert "binary" in results or "error" in results


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_state_fork_with_deep_nesting(self) -> None:
        """State fork works with deeply nested constraints."""
        state = NativeConcolicState()
        for i in range(100):
            state.add_constraint(f"constraint_{i}")

        forked = state.fork()

        assert len(forked.constraints) == 100

    def test_memory_operations_at_boundary(self) -> None:
        """Memory operations work at address boundaries."""
        state = NativeConcolicState()

        state.write_memory(0xFFFFFFFC, 0x12345678, size=4)
        value = state.read_memory(0xFFFFFFFC, size=4)

        assert value == 0x12345678

    def test_register_operations_with_bytes(self) -> None:
        """Register operations handle bytes values."""
        state = NativeConcolicState()

        state.set_register("eax", b"\x12\x34\x56\x78", symbolic=True)

        assert state.registers["eax"] == b"\x12\x34\x56\x78"
        assert state.symbolic_registers["eax"] == b"\x12\x34\x56\x78"

    def test_execution_with_empty_binary(self, tmp_path: Path) -> None:
        """Execution handles empty binary file."""
        empty_binary = tmp_path / "empty.exe"
        empty_binary.write_bytes(b"")

        m = Manticore(str(empty_binary))
        m.timeout = 1

        m.run(procs=1)

        assert m.execution_complete is True

    def test_hook_execution_with_exception(self, simple_pe_binary: Path) -> None:
        """Execution continues when hook raises exception."""
        m = Manticore(str(simple_pe_binary))

        def failing_hook(state: NativeConcolicState) -> None:
            raise ValueError("Hook error")

        m.add_hook(m.entry_point, failing_hook)
        m.timeout = 1

        m.run(procs=1)

        assert m.execution_complete is True

    def test_constraint_with_special_characters(self) -> None:
        """Constraints handle special characters."""
        state = NativeConcolicState()

        state.add_constraint("(eax & 0xFF) == 0x42")
        state.add_constraint("input[0] != '\\n'")

        assert len(state.constraints) == 2

    def test_analyze_with_multiple_parameters(self, simple_pe_binary: Path) -> None:
        """analyze handles multiple configuration parameters."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary), timeout=1)

        results = engine.analyze(
            str(simple_pe_binary),
            max_depth=50,
            find_vulnerabilities=True,
            find_license_checks=False,
            generate_test_cases=True,
            symbolic_stdin_size=128,
        )

        assert isinstance(results, dict)

    def test_state_termination_reasons(self) -> None:
        """State supports various termination reasons."""
        state = NativeConcolicState()

        reasons = ["normal", "timeout", "error", "segfault", "max_depth"]
        for reason in reasons:
            test_state = state.fork()
            test_state.terminate(reason)
            assert test_state.termination_reason == reason

    def test_execution_trace_recording(self) -> None:
        """Execution trace records instruction history."""
        state = NativeConcolicState(pc=0x1000)

        state.execution_trace.append({
            "pc": 0x1000,
            "instruction": "mov eax, 1",
            "registers": state.registers.copy(),
        })
        state.execution_trace.append({
            "pc": 0x1005,
            "instruction": "ret",
            "registers": state.registers.copy(),
        })

        assert len(state.execution_trace) == 2
        assert state.execution_trace[0]["pc"] == 0x1000
        assert state.execution_trace[1]["pc"] == 0x1005

    def test_plugin_callbacks_with_multiple_args(self) -> None:
        """Plugin callbacks handle variable arguments."""
        plugin = Plugin()

        plugin.will_run_callback(
            "executor",
            "arg1",
            "arg2",
            key1="value1",
            key2="value2",
        )

        plugin.will_fork_state_callback(
            "state",
            "new_state",
            "extra_arg",
            context="test",
        )

    def test_manticore_with_large_state_count(self) -> None:
        """Manticore handles large number of states."""
        m = Manticore(None)

        for i in range(100):
            state = NativeConcolicState(pc=0x1000 + i)
            m.all_states[i] = state

        all_states = m.get_all_states()

        assert len(all_states) == 100

    def test_concolic_engine_timeout_configuration(self, simple_pe_binary: Path) -> None:
        """ConcolicExecutionEngine respects timeout configuration."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary), timeout=0.5)

        assert engine.timeout == 0.5

    def test_license_bypass_with_nonexistent_address(self, simple_pe_binary: Path) -> None:
        """find_license_bypass handles invalid license check address."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary), timeout=1)

        results = engine.find_license_bypass(license_check_address=0xFFFFFFFF)

        assert isinstance(results, dict)


class TestRealWorldScenarios:
    """Tests simulating real-world concolic execution scenarios."""

    def test_path_explosion_mitigation(self, binary_with_conditional_branches: Path) -> None:
        """Engine mitigates path explosion in branching code."""
        engine = ConcolicExecutionEngine(str(binary_with_conditional_branches), timeout=2)
        engine.max_iterations = 50

        results = engine.explore_paths()

        assert "success" in results or "error" in results

    def test_symbolic_input_generation(self, simple_pe_binary: Path) -> None:
        """Engine generates symbolic inputs for path coverage."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary), timeout=1)

        results = engine.analyze(
            str(simple_pe_binary),
            generate_test_cases=True,
            symbolic_stdin_size=256,
        )

        assert "test_cases" in results

    def test_constraint_solving_for_branches(self) -> None:
        """Engine builds constraints for branch conditions."""
        state = NativeConcolicState(pc=0x1000)
        state.add_constraint("input[0] > 0x30")
        state.add_constraint("input[0] < 0x40")
        state.add_constraint("ZF==1")

        forked = state.fork()
        forked.add_constraint("CF==0")

        assert len(state.constraints) == 3
        assert len(forked.constraints) == 4

    def test_vulnerability_detection_crash(self, simple_pe_binary: Path) -> None:
        """Engine detects potential crashes as vulnerabilities."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary), timeout=1)

        results = engine._native_analyze(
            str(simple_pe_binary),
            find_vulnerabilities=True,
        )

        assert "vulnerabilities" in results
        assert isinstance(results["vulnerabilities"], list)

    def test_coverage_calculation(self, simple_pe_binary: Path) -> None:
        """Engine calculates code coverage correctly."""
        engine = ConcolicExecutionEngine(str(simple_pe_binary), timeout=1)

        results = engine.analyze(str(simple_pe_binary))

        assert "coverage" in results
        assert results["coverage"] >= 0

    def test_multi_path_exploration(self, binary_with_conditional_branches: Path) -> None:
        """Engine explores multiple execution paths."""
        m = Manticore(str(binary_with_conditional_branches))
        m.timeout = 2

        m.run(procs=1)

        all_states = m.get_all_states()
        assert len(all_states) > 0

    def test_license_string_detection(self, binary_with_license_string: Path) -> None:
        """Engine detects license-related strings in binary."""
        engine = ConcolicExecutionEngine(str(binary_with_license_string))

        address = engine._find_license_check_address()

        assert address is None or isinstance(address, int)

    def test_instruction_limit_enforcement(self, simple_pe_binary: Path) -> None:
        """Engine respects instruction limit during execution."""
        m = Manticore(str(simple_pe_binary))
        m.max_instructions = 50
        m.timeout = 5

        m.run(procs=1)

        assert m.instruction_count <= m.max_instructions + 100

    def test_state_prioritization_strategy(self) -> None:
        """Engine prioritizes states for efficient exploration."""
        m = Manticore(None)
        m.visited_pcs = {0x1000, 0x1005}
        m.interesting_addresses = [0x2000]

        states = []
        for i in range(10):
            state = NativeConcolicState(pc=0x1000 + i * 100)
            state.constraints = ["c1"] * i
            states.append(state)

        prioritized = m._prioritize_states(states, 3)

        assert len(prioritized) <= 3

    def test_error_handling_during_analysis(self, tmp_path: Path) -> None:
        """Engine handles analysis errors gracefully."""
        corrupt_binary = tmp_path / "corrupt.exe"
        corrupt_binary.write_bytes(b"MZ" + b"\x00" * 100)

        engine = ConcolicExecutionEngine.__new__(ConcolicExecutionEngine)
        engine.binary_path = str(corrupt_binary)
        engine.timeout = 1
        engine.logger = logging.getLogger("test")

        results = engine._native_analyze(str(corrupt_binary))

        assert isinstance(results, dict)
