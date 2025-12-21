"""Concolic Execution Engine for Precise Path Exploration.

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

from __future__ import annotations

import logging
import os
import re
import struct
import time
import traceback
from typing import TYPE_CHECKING, Any, TypedDict

from intellicrack.utils.logger import logger


if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType


MANTICORE_AVAILABLE = False
MANTICORE_TYPE: str | None = None


class TraceEntry(TypedDict):
    pc: int
    instruction: str
    registers: dict[str, int]


class InputSymbols(TypedDict):
    stdin: bytes
    argv: list[bytes]


class FlagsDict(TypedDict, total=False):
    ZF: bool
    SF: bool
    CF: bool
    OF: bool
    PF: bool


class CodeSection(TypedDict):
    start: int
    end: int


class NativeConcolicState:
    """Native concolic execution state implementation.

    Represents a single execution state in the concolic execution engine,
    maintaining both concrete and symbolic values for program variables.
    """

    def __init__(
        self,
        pc: int = 0,
        memory: dict[int, int] | None = None,
        registers: dict[str, int] | None = None,
    ) -> None:
        """Initialize a new execution state."""
        self.pc: int = pc
        self.memory: dict[int, int] = memory if memory is not None else {}
        self.registers: dict[str, int] = (
            registers
            if registers is not None
            else {
                "eax": 0,
                "ebx": 0,
                "ecx": 0,
                "edx": 0,
                "esp": 0x7FFF0000,
                "ebp": 0x7FFF0000,
                "esi": 0,
                "edi": 0,
                "eflags": 0,
                "rax": 0,
                "rbx": 0,
                "rcx": 0,
                "rdx": 0,
                "rsp": 0x7FFF0000,
                "rbp": 0x7FFF0000,
                "rsi": 0,
                "rdi": 0,
                "r8": 0,
                "r9": 0,
                "r10": 0,
                "r11": 0,
                "r12": 0,
                "r13": 0,
                "r14": 0,
                "r15": 0,
            }
        )
        self.symbolic_memory: dict[int | str, int | bytes] = {}
        self.symbolic_registers: dict[str, int | bytes] = {}
        self.constraints: list[str] = []
        self.input_symbols: InputSymbols = {"stdin": b"", "argv": []}
        self.is_terminated_flag: bool = False
        self.termination_reason: str | None = None
        self.stack: list[int] = []
        self.execution_trace: list[TraceEntry] = []
        self.arch: str = "x86"
        self.flags: FlagsDict = {"ZF": False, "SF": False, "CF": False, "OF": False, "PF": False}
        self.output: list[str] = []
        self.path_predicate: list[str] = []

    def is_terminated(self) -> bool:
        """Check if state is terminated."""
        return self.is_terminated_flag

    def terminate(self, reason: str = "normal") -> None:
        """Terminate the state."""
        self.is_terminated_flag = True
        self.termination_reason = reason

    def fork(self) -> NativeConcolicState:
        """Create a copy of this state for branching."""
        new_state = NativeConcolicState(self.pc, self.memory.copy(), self.registers.copy())
        new_state.symbolic_memory = self.symbolic_memory.copy()
        new_state.symbolic_registers = self.symbolic_registers.copy()
        new_state.constraints = self.constraints.copy()
        new_state.input_symbols = {
            "stdin": self.input_symbols["stdin"],
            "argv": self.input_symbols["argv"].copy(),
        }
        new_state.stack = self.stack.copy()
        new_state.execution_trace = self.execution_trace.copy()
        new_state.arch = self.arch
        new_state.flags = self.flags.copy()
        new_state.output = self.output.copy()
        new_state.path_predicate = self.path_predicate.copy()
        return new_state

    def add_constraint(self, constraint: str) -> None:
        """Add a path constraint."""
        self.constraints.append(constraint)

    def set_register(self, reg: str, value: int | bytes, symbolic: bool = False) -> None:
        """Set register value."""
        if isinstance(value, bytes):
            int_value = int.from_bytes(value, "little")
        else:
            int_value = value
        self.registers[reg] = int_value
        if symbolic:
            self.symbolic_registers[reg] = value

    def get_register(self, reg: str) -> int:
        """Get register value."""
        return self.registers.get(reg, 0)

    def write_memory(self, addr: int, value: int | bytes, size: int = 4, symbolic: bool = False) -> None:
        """Write to memory."""
        if isinstance(value, bytes):
            for i, byte in enumerate(value[:size]):
                self.memory[addr + i] = byte
        else:
            for i in range(size):
                self.memory[addr + i] = (value >> (i * 8)) & 0xFF
        if symbolic:
            self.symbolic_memory[addr] = value

    def read_memory(self, addr: int, size: int = 4) -> int:
        """Read from memory."""
        value = 0
        for i in range(size):
            byte = self.memory.get(addr + i, 0)
            value |= byte << (i * 8)
        return value

    def set_symbolic_value(self, symbol: str, value: int | bytes | list[bytes]) -> None:
        """Set a symbolic value for a program variable."""
        if symbol in self.registers:
            if isinstance(value, list):
                return
            self.registers[symbol] = value if isinstance(value, int) else int.from_bytes(value, "little")
            self.symbolic_registers[symbol] = value
            return

        if symbol.startswith("mem_"):
            if isinstance(value, list):
                return
            try:
                addr_str = symbol[4:]
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                if isinstance(value, bytes):
                    for i, byte in enumerate(value):
                        self.memory[addr + i] = byte
                else:
                    size = 4
                    for i in range(size):
                        self.memory[addr + i] = (value >> (i * 8)) & 0xFF
                self.symbolic_memory[addr] = value
                return
            except (ValueError, TypeError):
                pass

        if symbol in {"stdin", "argv"}:
            if symbol == "argv":
                if isinstance(value, list):
                    self.input_symbols["argv"] = value
                elif isinstance(value, bytes):
                    self.input_symbols["argv"] = [value]
                else:
                    self.input_symbols["argv"] = [str(value).encode()]
            elif symbol == "stdin":
                if isinstance(value, bytes):
                    self.input_symbols["stdin"] = value
                elif isinstance(value, int):
                    byte_length = max((value.bit_length() + 7) // 8, 1)
                    self.input_symbols["stdin"] = value.to_bytes(byte_length, "little")
            return

        if not isinstance(value, list):
            self.symbolic_memory[symbol] = value


class NativePlugin:
    """Native plugin implementation for concolic execution."""

    def __init__(self) -> None:
        """Initialize native plugin."""
        self._logger = logging.getLogger(__name__)
        self._logger.debug("Native plugin implementation initialized")

    def will_run_callback(self, executor: object, *args: object, **kwargs: object) -> None:
        """Call before execution starts."""
        self._logger.debug("Execution starting on executor %s", type(executor).__name__)

    def did_finish_run_callback(self, executor: object, *args: object, **kwargs: object) -> None:
        """Call after execution completes."""
        self._logger.debug("Execution finished on executor %s", type(executor).__name__)

    def will_fork_state_callback(self, state: NativeConcolicState, new_state: NativeConcolicState, *args: object, **kwargs: object) -> None:
        """Call before state fork."""
        self._logger.debug("State fork: PC 0x%x -> 0x%x", state.pc, new_state.pc)

    def will_execute_instruction_callback(self, state: NativeConcolicState, pc: int, insn: object) -> None:
        """Call before instruction execution."""
        self._logger.debug("Executing instruction at 0x%x", pc)


class NativeManticore:
    """Native concolic execution engine implementation."""

    def __init__(self, binary_path: str | None = None, *args: object, **kwargs: object) -> None:
        """Initialize native concolic execution engine."""
        self.binary_path: str | None = binary_path
        self.init_args: tuple[object, ...] = args
        self.init_kwargs: dict[str, object] = dict(kwargs)
        self.all_states: dict[int, NativeConcolicState] = {}
        self.ready_states: list[NativeConcolicState] = []
        self.terminated_states: list[NativeConcolicState] = []
        self.execution_complete: bool = False
        self._logger = logging.getLogger(__name__)
        self.hooks: dict[int, Callable[[NativeConcolicState], None]] = {}
        self.plugins: list[NativePlugin] = []
        self.timeout: int = 300
        self.max_states: int = 1000
        self.instruction_count: int = 0
        self.max_instructions: int = 100000

        self.binary_data: bytes | None = None
        self.entry_point: int = 0
        self.code_sections: list[CodeSection] = []
        self.explored_branches: set[str] = set()

        self._logger.info("Native concolic execution engine initialized")

        if binary_path:
            self._load_binary()

    def _load_binary(self) -> None:
        """Load and analyze the target binary."""
        if self.binary_path is None:
            return
        try:
            with open(self.binary_path, "rb") as f:
                self.binary_data = f.read()

            if self.binary_data.startswith(b"MZ"):
                self.entry_point = self._parse_pe_entry_point()
            elif self.binary_data.startswith(b"\x7fELF"):
                self.entry_point = self._parse_elf_entry_point()
            else:
                self.entry_point = 0x1000

            self._logger.info("Binary loaded, entry point: 0x%x", self.entry_point)

        except OSError as e:
            self._logger.exception("Failed to load binary: %s", e)

    def _parse_pe_entry_point(self) -> int:
        """Parse PE file to find entry point."""
        if self.binary_data is None:
            return 0x401000
        try:
            dos_header = self.binary_data[:64]
            if len(dos_header) >= 60:
                pe_offset = int.from_bytes(dos_header[60:64], "little")
                if pe_offset < len(self.binary_data) - 24:
                    opt_header_offset = pe_offset + 24
                    if opt_header_offset + 20 < len(self.binary_data):
                        entry_point = int.from_bytes(
                            self.binary_data[opt_header_offset + 16 : opt_header_offset + 20],
                            "little",
                        )
                        return entry_point + 0x400000
        except (ValueError, IndexError) as e:
            self._logger.debug("Failed to parse PE entry point: %s", e)
        return 0x401000

    def _parse_elf_entry_point(self) -> int:
        """Parse ELF file to find entry point."""
        if self.binary_data is None:
            return 0x8048000
        try:
            if len(self.binary_data) >= 32:
                if self.binary_data[4] == 2:
                    return int.from_bytes(self.binary_data[24:32], "little")
                return int.from_bytes(self.binary_data[24:28], "little")
        except (ValueError, IndexError) as e:
            self._logger.debug("Failed to parse ELF entry point: %s", e)
        return 0x8048000

    def add_hook(self, address: int, callback: Callable[[NativeConcolicState], None]) -> None:
        """Add execution hook at specific address."""
        self.hooks[address] = callback
        self._logger.debug("Hook added for address 0x%x", address)

    def register_plugin(self, plugin: NativePlugin) -> None:
        """Register a plugin for execution callbacks."""
        self.plugins.append(plugin)
        self._logger.debug("Plugin registered: %s", type(plugin).__name__)

    def set_exec_timeout(self, timeout: int) -> None:
        """Set execution timeout in seconds."""
        self.timeout = timeout
        self._logger.debug("Execution timeout set to %d seconds", timeout)

    def run(self, procs: int = 1) -> None:
        """Run concolic execution."""
        self._logger.info("Starting concolic execution with %d processes", procs)
        start_time = time.time()

        self._logger.info("Starting concolic execution (timeout: %ds)", self.timeout)

        initial_state = NativeConcolicState(pc=self.entry_point)
        self.ready_states.append(initial_state)
        self.all_states[0] = initial_state

        state_id = 0

        try:
            while self.ready_states and not self.execution_complete:
                if time.time() - start_time > self.timeout:
                    self._logger.warning("Execution timeout reached")
                    break

                if len(self.all_states) >= self.max_states:
                    self._logger.warning("Maximum state limit reached")
                    break

                current_state = self.ready_states.pop(0)

                for _ in range(100):
                    if current_state.is_terminated():
                        break

                    if self.instruction_count >= self.max_instructions:
                        current_state.terminate("instruction_limit")
                        break

                    self._execute_instruction(current_state)
                    self.instruction_count += 1

                    if current_state.pc in self.hooks:
                        try:
                            self.hooks[current_state.pc](current_state)
                        except (ValueError, RuntimeError) as e:
                            self._logger.exception("Hook execution failed: %s", e)

                    if new_states := self._check_for_branches(current_state):
                        for new_state in new_states:
                            state_id += 1
                            self.all_states[state_id] = new_state
                            self.ready_states.append(new_state)

                if current_state.is_terminated():
                    self.terminated_states.append(current_state)
                else:
                    self.ready_states.append(current_state)

        except KeyboardInterrupt:
            self._logger.info("Execution interrupted by user")
        except (ValueError, RuntimeError) as e:
            self._logger.exception("Execution error: %s", e)

        self.execution_complete = True
        self._logger.info(
            "Concolic execution completed. States: %d terminated, %d active",
            len(self.terminated_states),
            len(self.ready_states),
        )

    def _execute_instruction(self, state: NativeConcolicState) -> None:
        """Execute a single instruction in the given state."""
        try:
            if not self.binary_data:
                state.terminate("no_binary_data")
                return

            pc_offset = state.pc - self.entry_point
            if pc_offset < 0 or pc_offset >= len(self.binary_data):
                state.terminate("invalid_pc")
                return

            instruction_bytes = self.binary_data[pc_offset : pc_offset + 8]
            if not instruction_bytes:
                state.terminate("end_of_code")
                return

            state.execution_trace.append(
                {
                    "pc": state.pc,
                    "instruction": instruction_bytes[:4].hex(),
                    "registers": state.registers.copy(),
                },
            )

            self._emulate_instruction(state, instruction_bytes)

        except (ValueError, RuntimeError) as e:
            self._logger.debug("Instruction execution error at 0x%x: %s", state.pc, e)
            state.terminate("execution_error")

    def _emulate_instruction(self, state: NativeConcolicState, instruction_bytes: bytes) -> None:
        """Emulate instruction execution using real x86/x64 emulation."""
        if not instruction_bytes:
            state.terminate("empty_instruction")
            return

        try:
            from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

            mode = CS_MODE_64 if state.arch == "x64" else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)

            for insn in md.disasm(instruction_bytes, state.pc):
                if insn.mnemonic == "nop":
                    state.pc += insn.size

                elif insn.mnemonic == "ret":
                    if state.stack:
                        state.pc = state.stack.pop()
                    else:
                        rsp_reg = "rsp" if state.arch == "x64" else "esp"
                        rsp = state.registers.get(rsp_reg, 0)
                        word_size = 8 if state.arch == "x64" else 4
                        if ret_addr := state.read_memory(rsp, word_size):
                            state.pc = ret_addr
                            state.registers[rsp_reg] = rsp + word_size
                        else:
                            state.terminate("invalid_stack_pointer")

                elif insn.mnemonic == "call":
                    op_str = insn.op_str
                    if op_str.startswith("0x"):
                        target = int(op_str, 16)
                    elif len(instruction_bytes) >= 5:
                        displacement = struct.unpack("<i", instruction_bytes[1:5])[0]
                        target = state.pc + insn.size + displacement
                    else:
                        target = state.pc + insn.size

                    ret_addr = state.pc + insn.size
                    rsp_reg = "rsp" if state.arch == "x64" else "esp"
                    rsp = state.registers.get(rsp_reg, 0)
                    word_size = 8 if state.arch == "x64" else 4
                    rsp -= word_size
                    state.write_memory(rsp, ret_addr, word_size)
                    state.registers[rsp_reg] = rsp
                    state.pc = target

                elif insn.mnemonic.startswith("j"):
                    self._handle_jump(state, insn, instruction_bytes)

                elif insn.mnemonic in ["mov", "movzx", "movsx"]:
                    self._handle_mov(state, insn)
                    state.pc += insn.size

                elif insn.mnemonic in ["add", "sub", "xor", "and", "or"]:
                    self._handle_arithmetic(state, insn)
                    state.pc += insn.size

                elif insn.mnemonic in ["push", "pop"]:
                    self._handle_stack_op(state, insn)
                    state.pc += insn.size

                elif insn.mnemonic in ["cmp", "test"]:
                    self._handle_comparison(state, insn)
                    state.pc += insn.size

                elif insn.mnemonic == "lea":
                    self._handle_lea(state, insn)
                    state.pc += insn.size

                elif insn.mnemonic in ["int", "syscall", "sysenter"]:
                    self._handle_syscall(state, insn)
                    state.pc += insn.size

                else:
                    state.pc += insn.size

                self.instruction_count += 1

                if self.instruction_count >= self.max_instructions:
                    state.terminate("max_instructions_reached")

                break

        except ImportError:
            self._manual_decode_instruction(state, instruction_bytes)

    def _handle_jump(self, state: NativeConcolicState, insn: object, instruction_bytes: bytes) -> None:
        """Handle jump instructions with proper branching."""
        mnemonic = getattr(insn, "mnemonic", "")
        op_str = getattr(insn, "op_str", "")
        size = getattr(insn, "size", 2)

        if op_str.startswith("0x"):
            target = int(op_str, 16)
        else:
            if size == 2:
                displacement = struct.unpack("b", instruction_bytes[1:2])[0]
            else:
                if len(instruction_bytes) >= size:
                    displacement = struct.unpack("<i", instruction_bytes[size - 4 : size])[0]
                else:
                    displacement = 0
            target = state.pc + size + displacement

        if mnemonic == "jmp":
            state.pc = target

        elif mnemonic in {"jz", "je"}:
            if state.flags.get("ZF", False):
                state.pc = target
                state.add_constraint(f"ZF==1_at_{state.pc:x}")
            else:
                state.pc += size
                state.add_constraint(f"ZF==0_at_{state.pc:x}")
                self._create_branch_state(state, target, "ZF==1")

        elif mnemonic in {"jnz", "jne"}:
            if not state.flags.get("ZF", False):
                state.pc = target
                state.add_constraint(f"ZF==0_at_{state.pc:x}")
            else:
                state.pc += size
                state.add_constraint(f"ZF==1_at_{state.pc:x}")
                self._create_branch_state(state, target, "ZF==0")

        elif mnemonic in {"jg", "jnle"}:
            zf = state.flags.get("ZF", False)
            sf = state.flags.get("SF", False)
            of = state.flags.get("OF", False)
            if not zf and (sf == of):
                state.pc = target
                state.add_constraint(f"JG_taken_at_{state.pc:x}")
            else:
                state.pc += size
                state.add_constraint(f"JG_not_taken_at_{state.pc:x}")
                self._create_branch_state(state, target, "JG_taken")

        elif mnemonic in {"jl", "jnge"}:
            sf = state.flags.get("SF", False)
            of = state.flags.get("OF", False)
            if sf != of:
                state.pc = target
                state.add_constraint(f"JL_taken_at_{state.pc:x}")
            else:
                state.pc += size
                state.add_constraint(f"JL_not_taken_at_{state.pc:x}")
                self._create_branch_state(state, target, "JL_taken")

        else:
            state.pc += size
            state.add_constraint(f"{mnemonic}_not_taken_at_{state.pc:x}")
            self._create_branch_state(state, target, f"{mnemonic}_taken")

    def _create_branch_state(self, state: NativeConcolicState, target: int, constraint: str) -> None:
        """Create alternate state for branch exploration."""
        if len(self.ready_states) < self.max_states:
            alternate = state.fork()
            alternate.pc = target
            alternate.add_constraint(constraint)
            self.ready_states.append(alternate)

    def _handle_mov(self, state: NativeConcolicState, insn: object) -> None:
        """Handle MOV instructions."""
        op_str = getattr(insn, "op_str", "")
        ops = op_str.split(",")
        if len(ops) == 2:
            dst = ops[0].strip()
            src = ops[1].strip()
            src_val = self._get_operand_value(state, src)
            self._set_operand_value(state, dst, src_val)

    def _handle_arithmetic(self, state: NativeConcolicState, insn: object) -> None:
        """Handle arithmetic and logic operations."""
        mnemonic = getattr(insn, "mnemonic", "")
        op_str = getattr(insn, "op_str", "")
        ops = op_str.split(",")

        if len(ops) >= 2:
            dst = ops[0].strip()
            src = ops[1].strip()

            dst_val = self._get_operand_value(state, dst)
            src_val = self._get_operand_value(state, src)

            max_val = 0xFFFFFFFFFFFFFFFF if state.arch == "x64" else 0xFFFFFFFF
            sign_bit = 0x8000000000000000 if state.arch == "x64" else 0x80000000
            result = 0

            if mnemonic == "add":
                result = dst_val + src_val
                state.flags["CF"] = result > max_val
                state.flags["ZF"] = (result & max_val) == 0
                state.flags["SF"] = (result & sign_bit) != 0

            elif mnemonic == "sub":
                result = dst_val - src_val
                state.flags["CF"] = dst_val < src_val
                state.flags["ZF"] = result == 0
                state.flags["SF"] = result < 0

            elif mnemonic == "xor":
                result = dst_val ^ src_val
                state.flags["ZF"] = result == 0
                state.flags["SF"] = (result & sign_bit) != 0
                state.flags["CF"] = False
                state.flags["OF"] = False

            elif mnemonic == "and":
                result = dst_val & src_val
                state.flags["ZF"] = result == 0
                state.flags["SF"] = (result & sign_bit) != 0
                state.flags["CF"] = False
                state.flags["OF"] = False

            elif mnemonic == "or":
                result = dst_val | src_val
                state.flags["ZF"] = result == 0
                state.flags["SF"] = (result & sign_bit) != 0
                state.flags["CF"] = False
                state.flags["OF"] = False

            self._set_operand_value(state, dst, result)

    def _handle_comparison(self, state: NativeConcolicState, insn: object) -> None:
        """Handle comparison instructions."""
        mnemonic = getattr(insn, "mnemonic", "")
        op_str = getattr(insn, "op_str", "")
        ops = op_str.split(",")

        if len(ops) == 2:
            op1 = ops[0].strip()
            op2 = ops[1].strip()

            val1 = self._get_operand_value(state, op1)
            val2 = self._get_operand_value(state, op2)

            sign_bit = 0x8000000000000000 if state.arch == "x64" else 0x80000000

            if mnemonic == "cmp":
                result = val1 - val2
                state.flags["ZF"] = result == 0
                state.flags["SF"] = result < 0
                state.flags["CF"] = val1 < val2
                state.flags["OF"] = ((val1 ^ val2) & (val1 ^ result) & sign_bit) != 0

            elif mnemonic == "test":
                result = val1 & val2
                state.flags["ZF"] = result == 0
                state.flags["SF"] = (result & sign_bit) != 0
                state.flags["CF"] = False
                state.flags["OF"] = False

    def _handle_stack_op(self, state: NativeConcolicState, insn: object) -> None:
        """Handle stack operations."""
        mnemonic = getattr(insn, "mnemonic", "")
        op_str = getattr(insn, "op_str", "")

        sp_reg = "rsp" if state.arch == "x64" else "esp"
        sp = state.registers.get(sp_reg, 0)
        word_size = 8 if state.arch == "x64" else 4

        if mnemonic == "push":
            op = op_str.strip()
            val = self._get_operand_value(state, op)

            sp -= word_size
            state.registers[sp_reg] = sp
            state.write_memory(sp, val, word_size)

        elif mnemonic == "pop":
            val = state.read_memory(sp, word_size)
            op = op_str.strip()
            self._set_operand_value(state, op, val)
            state.registers[sp_reg] = sp + word_size

    def _handle_lea(self, state: NativeConcolicState, insn: object) -> None:
        """Handle load effective address."""
        op_str = getattr(insn, "op_str", "")
        ops = op_str.split(",")
        if len(ops) == 2:
            dst = ops[0].strip()
            src = ops[1].strip()
            addr = self._calculate_effective_address(state, src)
            self._set_operand_value(state, dst, addr)

    def _handle_syscall(self, state: NativeConcolicState, insn: object) -> None:
        """Handle system calls."""
        mnemonic = getattr(insn, "mnemonic", "")
        op_str = getattr(insn, "op_str", "")

        if mnemonic == "int" and "0x80" in op_str:
            syscall_num = state.registers.get("eax", 0)
            self._process_syscall(state, syscall_num, "x86")

        elif mnemonic == "syscall":
            syscall_num = state.registers.get("rax", 0)
            self._process_syscall(state, syscall_num, "x64")

        elif mnemonic == "sysenter":
            syscall_num = state.registers.get("eax", 0)
            self._process_syscall(state, syscall_num, "fast")

    def _process_syscall(self, state: NativeConcolicState, syscall_num: int, arch: str) -> None:
        """Process system call."""
        if syscall_num == 1:
            if arch == "x86":
                state.terminate(f"exit({state.registers.get('ebx', 0)})")
            else:
                fd = state.registers.get("rdi", 0)
                buf = state.registers.get("rsi", 0)
                count = state.registers.get("rdx", 0)
                state.output.append(f"write({fd}, 0x{buf:x}, {count})")

        elif syscall_num == 60 and arch == "x64":
            state.terminate(f"exit({state.registers.get('rdi', 0)})")

        elif syscall_num == 3:
            state.add_constraint(f"read_syscall_at_{state.pc:x}")

        if arch == "x64":
            state.registers["rax"] = 0
        else:
            state.registers["eax"] = 0

    def _get_operand_value(self, state: NativeConcolicState, operand: str) -> int:
        """Get value from operand (register, memory, or immediate)."""
        operand = operand.strip()

        if operand.startswith("0x"):
            return int(operand, 16)
        if operand.lstrip("-").isdigit():
            return int(operand)

        if operand in state.registers:
            return state.registers[operand]

        if operand.startswith("[") and operand.endswith("]"):
            addr_expr = operand[1:-1]
            addr = self._calculate_effective_address(state, addr_expr)
            word_size = 8 if state.arch == "x64" else 4
            return state.read_memory(addr, word_size)

        return 0

    def _set_operand_value(self, state: NativeConcolicState, operand: str, value: int) -> None:
        """Set value to operand (register or memory)."""
        operand = operand.strip()
        valid_regs = {
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
        }

        if operand in valid_regs:
            state.registers[operand] = value

        elif operand.startswith("[") and operand.endswith("]"):
            addr_expr = operand[1:-1]
            addr = self._calculate_effective_address(state, addr_expr)
            word_size = 8 if state.arch == "x64" else 4
            state.write_memory(addr, value, word_size)

    def _calculate_effective_address(self, state: NativeConcolicState, expr: str) -> int:
        """Calculate effective address from expression like 'rbp-0x10'."""
        expr = expr.strip()

        if expr in state.registers:
            return state.registers[expr]

        if match := re.match(r"(\w+)\s*([+-])\s*(0x[0-9a-f]+|\d+)", expr, re.IGNORECASE):
            base_reg = match[1]
            op = match[2]
            disp = match[3]

            base = state.registers.get(base_reg, 0)
            offset = int(disp, 16) if disp.startswith("0x") else int(disp)

            return base + offset if op == "+" else base - offset

        if match := re.match(
            r"(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)\s*([+-])\s*(0x[0-9a-f]+|\d+)",
            expr,
            re.IGNORECASE,
        ):
            base_reg = match[1]
            index_reg = match[2]
            scale = int(match[3])
            op = match[4]
            disp = match[5]

            base = state.registers.get(base_reg, 0)
            index = state.registers.get(index_reg, 0)
            offset = int(disp, 16) if disp.startswith("0x") else int(disp)

            addr = base + (index * scale)
            if op == "+":
                addr += offset
            else:
                addr -= offset
            return addr

        return 0

    def _manual_decode_instruction(self, state: NativeConcolicState, instruction_bytes: bytes) -> None:
        """Manual instruction decoding fallback."""
        if not instruction_bytes:
            state.pc += 1
            return

        opcode = instruction_bytes[0]

        if opcode == 0x90:
            state.pc += 1
        elif opcode == 0xC3:
            sp_reg = "rsp" if state.arch == "x64" else "esp"
            sp = state.registers.get(sp_reg, 0)
            word_size = 8 if state.arch == "x64" else 4
            if ret_addr := state.read_memory(sp, word_size):
                state.pc = ret_addr
                state.registers[sp_reg] = sp + word_size
            else:
                state.terminate("invalid_stack")
        elif opcode == 0xE8:
            if len(instruction_bytes) >= 5:
                displacement = struct.unpack("<i", instruction_bytes[1:5])[0]
                ret_addr = state.pc + 5
                target = state.pc + 5 + displacement

                sp_reg = "rsp" if state.arch == "x64" else "esp"
                sp = state.registers.get(sp_reg, 0)
                word_size = 8 if state.arch == "x64" else 4
                sp -= word_size
                state.registers[sp_reg] = sp
                state.write_memory(sp, ret_addr, word_size)

                state.pc = target
            else:
                state.pc += len(instruction_bytes)
        elif opcode == 0xEB:
            if len(instruction_bytes) >= 2:
                displacement = struct.unpack("b", instruction_bytes[1:2])[0]
                state.pc = state.pc + 2 + displacement
            else:
                state.pc += 2
        elif opcode in [0x74, 0x75]:
            if len(instruction_bytes) >= 2:
                displacement = struct.unpack("b", instruction_bytes[1:2])[0]

                if take_branch := (opcode == 0x74 and state.flags.get("ZF", False)) or (
                    opcode == 0x75 and not state.flags.get("ZF", False)
                ):
                    state.add_constraint(f"{'JZ' if opcode == 0x74 else 'JNZ'}_taken_at_{state.pc:x}")
                    state.pc = state.pc + 2 + displacement
                else:
                    state.add_constraint(f"{'JZ' if opcode == 0x74 else 'JNZ'}_not_taken_at_{state.pc:x}")
                    state.pc += 2

                    if len(self.ready_states) < self.max_states:
                        alternate = state.fork()
                        alternate.pc = state.pc + displacement - 2
                        alternate.add_constraint(f"{'JZ' if opcode == 0x74 else 'JNZ'}_taken_at_{state.pc:x}")
                        self.ready_states.append(alternate)
            else:
                state.pc += 2
        elif opcode == 0x0F:
            if len(instruction_bytes) >= 2:
                opcode2 = instruction_bytes[1]
                if opcode2 in [0x84, 0x85] and len(instruction_bytes) >= 6:
                    displacement = struct.unpack("<i", instruction_bytes[2:6])[0]

                    if take_branch := (opcode2 == 0x84 and state.flags.get("ZF", False)) or (
                        opcode2 == 0x85 and not state.flags.get("ZF", False)
                    ):
                        logger.debug("Taking branch at PC %#x: take_branch=%s", state.pc, take_branch)
                        state.pc = state.pc + 6 + displacement
                    else:
                        logger.debug("Not taking branch at PC %#x: take_branch=%s", state.pc, take_branch)
                        state.pc += 6
                        if len(self.ready_states) < self.max_states:
                            alternate = state.fork()
                            alternate.pc = state.pc + displacement - 6
                            self.ready_states.append(alternate)
                else:
                    state.pc += 2
            else:
                state.pc += 1
        else:
            insn_len = self._estimate_instruction_length(instruction_bytes)
            state.pc += insn_len

    def _estimate_instruction_length(self, instruction_bytes: bytes) -> int:
        """Estimate instruction length for unknown opcodes."""
        if not instruction_bytes:
            return 1

        opcode = instruction_bytes[0]

        if opcode in [0x66, 0x67, 0xF2, 0xF3]:
            return 1 + self._estimate_instruction_length(instruction_bytes[1:])

        if 0x40 <= opcode <= 0x4F:
            return 1 + self._estimate_instruction_length(instruction_bytes[1:])

        if opcode in [0x89, 0x8B, 0x8D, 0x01, 0x03, 0x29, 0x2B, 0x31, 0x33, 0x39, 0x3B]:
            return self._get_modrm_instruction_length(instruction_bytes)

        if opcode in [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57]:
            return 1
        if opcode in [0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F]:
            return 1
        if opcode in [0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF]:
            return 5

        return min(len(instruction_bytes), 4)

    def _get_modrm_instruction_length(self, instruction_bytes: bytes) -> int:
        """Calculate instruction length for opcodes with ModR/M byte."""
        if len(instruction_bytes) < 2:
            return len(instruction_bytes)

        modrm = instruction_bytes[1]
        mod = (modrm >> 6) & 0x3
        rm = modrm & 0x7

        base_length = 2

        if mod == 0b11:
            return base_length

        has_sib = rm == 0b100 and mod != 0b11

        if has_sib:
            base_length += 1
            if len(instruction_bytes) > 2:
                sib = instruction_bytes[2]
                sib_base = sib & 0x7
                if mod == 0b00 and sib_base == 0b101:
                    base_length += 4

        if mod == 0b00:
            if rm == 0b101:
                base_length += 4
        elif mod == 0b01:
            base_length += 1
        elif mod == 0b10:
            base_length += 4

        return base_length

    def _check_for_branches(self, state: NativeConcolicState) -> list[NativeConcolicState]:
        """Check if the current state should branch into multiple states."""
        new_states: list[NativeConcolicState] = []

        if hasattr(state, "symbolic_branches"):
            symbolic_branches: list[dict[str, Any]] = getattr(state, "symbolic_branches", [])
            for branch_info in symbolic_branches:
                if branch_info.get("pc") == state.pc:
                    possible_values = branch_info.get("possible_values", [])
                    current_value = branch_info.get("current_value")
                    symbol = branch_info.get("symbol", "")
                    for possible_value in possible_values:
                        if possible_value != current_value:
                            alt_state = state.fork()
                            alt_state.set_symbolic_value(symbol, possible_value)
                            alt_state.add_constraint(f"{symbol}=={possible_value}")
                            new_states.append(alt_state)

        if len(self.ready_states) + len(new_states) > self.max_states:
            new_states = self._prioritize_states(new_states, self.max_states - len(self.ready_states))

        return new_states

    def _should_explore_branch(self, state: NativeConcolicState, condition: str) -> bool:
        """Determine if we should explore a branch based on path constraints."""
        branch_key = f"{state.pc:x}_{condition}"
        if branch_key in self.explored_branches:
            return False

        self.explored_branches.add(branch_key)
        return len(self.ready_states) < self.max_states

    def _negate_condition(self, condition: str) -> str:
        """Negate a branch condition."""
        negations = {
            "OF==1": "OF==0",
            "OF==0": "OF==1",
            "CF==1": "CF==0",
            "CF==0": "CF==1",
            "ZF==1": "ZF==0",
            "ZF==0": "ZF==1",
            "SF==1": "SF==0",
            "SF==0": "SF==1",
            "PF==1": "PF==0",
            "PF==0": "PF==1",
            "SF!=OF": "SF==OF",
            "SF==OF": "SF!=OF",
        }

        if " or " in condition:
            parts = condition.split(" or ")
            negated_parts = [self._negate_condition(p.strip()) for p in parts]
            return " and ".join(negated_parts)
        if " and " in condition:
            parts = condition.split(" and ")
            negated_parts = [self._negate_condition(p.strip()) for p in parts]
            return " or ".join(negated_parts)

        return negations.get(condition, f"not({condition})")

    def _is_indirect_branch(self, state: NativeConcolicState, instruction_bytes: bytes | None) -> bool:
        """Check if instruction is an indirect branch."""
        if not instruction_bytes:
            return False

        opcode = instruction_bytes[0]

        if opcode == 0xFF and len(instruction_bytes) >= 2:
            modrm = instruction_bytes[1]
            reg_field = (modrm >> 3) & 0x7
            if reg_field in {4, 2}:
                return True

        return opcode in [195, 203, 194, 202]

    def _analyze_indirect_targets(self, state: NativeConcolicState) -> list[int]:
        """Analyze possible targets for indirect branches."""
        targets: list[int] = []

        sp_reg = "rsp" if state.arch == "x64" else "esp"
        sp = state.registers.get(sp_reg, 0)
        word_size = 8 if state.arch == "x64" else 4

        for i in range(min(10, len(state.stack))):
            ret_addr = state.read_memory(sp + i * word_size, word_size)
            if ret_addr and self._is_valid_code_address(ret_addr):
                targets.append(ret_addr)

        if not targets:
            targets.append(state.pc + 2)

        return targets[:5]

    def _is_valid_code_address(self, addr: int) -> bool:
        """Check if address points to valid code section."""
        return any(section["start"] <= addr < section["end"] for section in self.code_sections)

    def _prioritize_states(self, states: list[NativeConcolicState], max_count: int) -> list[NativeConcolicState]:
        """Prioritize states for exploration based on heuristics."""
        if len(states) <= max_count:
            return states

        scored_states: list[tuple[float, NativeConcolicState]] = []
        visited_pcs: set[int] = getattr(self, "visited_pcs", set())
        interesting_addresses: list[int] = getattr(self, "interesting_addresses", [])

        for state in states:
            score: float = 0.0

            score -= len(state.constraints) * 0.1

            if state.pc not in visited_pcs:
                score += 10.0

            for interesting_addr in interesting_addresses:
                distance = abs(state.pc - interesting_addr)
                if distance < 0x1000:
                    score += (0x1000 - distance) / 100.0

            if hasattr(state, "symbolic_inputs") and state.symbolic_inputs:
                score += 5.0

            scored_states.append((score, state))

        scored_states.sort(key=lambda x: x[0], reverse=True)
        return [state for _, state in scored_states[:max_count]]

    def get_all_states(self) -> list[NativeConcolicState]:
        """Get all execution states."""
        return list(self.all_states.values())

    def get_terminated_states(self) -> list[NativeConcolicState]:
        """Get all terminated states."""
        return self.terminated_states

    def get_ready_states(self) -> list[NativeConcolicState]:
        """Get all ready states."""
        return self.ready_states


lief_module: ModuleType | None = None
LIEF_AVAILABLE: bool = False
HAS_LIEF: bool = False

try:
    from intellicrack.handlers.lief_handler import HAS_LIEF as _HAS_LIEF

    HAS_LIEF = _HAS_LIEF
    LIEF_AVAILABLE = _HAS_LIEF
    if _HAS_LIEF:
        import lief as _lief

        lief_module = _lief
except ImportError as e:
    logger.exception("Import error in concolic_executor: %s", e)


class ConcolicExecutionEngine:
    """Advanced concolic execution engine for precise path exploration."""

    def __init__(self, binary_path: str, max_iterations: int = 100, timeout: int = 300) -> None:
        """Initialize the concolic execution engine with binary analysis configuration."""
        self.binary_path: str = binary_path
        self.max_iterations: int = max_iterations
        self.timeout: int = timeout
        self._logger = logging.getLogger("IntellicrackLogger.ConcolicExecution")

        self.exploration_depth: int = 10
        self.memory_limit: int = 1024 * 1024 * 1024

        self.execution_paths: list[dict[str, Any]] = []
        self.discovered_bugs: list[dict[str, Any]] = []
        self.code_coverage: dict[int, int] = {}
        self.symbolic_variables: list[str] = []

        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        self.engine: NativeManticore | None = None
        self._initialize_execution_engine()

        self._logger.info("Concolic execution engine initialized for %s", binary_path)

    def _initialize_execution_engine(self) -> None:
        """Initialize the execution engine based on available frameworks."""
        self._logger.info("Using native concolic execution implementation")
        self.max_states = 1000
        self.instruction_limit = 100000

    def explore_paths(self, target_address: int | None = None, avoid_addresses: list[int] | None = None) -> dict[str, Any]:
        """Perform concolic execution to explore program paths."""
        try:
            self._logger.info("Starting concolic execution on %s", self.binary_path)

            m = NativeManticore(self.binary_path)

            if target_address is not None:
                m.add_hook(target_address, self._target_hook)

            if avoid_addresses is not None:
                for addr in avoid_addresses:
                    m.add_hook(addr, self._avoid_hook)

            path_plugin = NativePlugin()
            m.register_plugin(path_plugin)

            m.set_exec_timeout(self.timeout)

            self._logger.info("Running concolic execution...")
            m.run(procs=4)

            results: dict[str, Any] = {
                "success": True,
                "paths_explored": len(m.all_states),
                "inputs": [],
            }

            for state_id, state in m.all_states.items():
                if state.is_terminated():
                    stdin_data = state.input_symbols.get("stdin", b"")
                    argv_data = state.input_symbols.get("argv", [])

                    results["inputs"].append(
                        {
                            "id": state_id,
                            "stdin": stdin_data.hex() if isinstance(stdin_data, bytes) else str(stdin_data),
                            "argv": [arg.hex() if isinstance(arg, bytes) else str(arg) for arg in argv_data],
                            "termination_reason": state.termination_reason,
                        },
                    )

            self._logger.info("Concolic execution completed. Explored %d paths.", results["paths_explored"])
            return results

        except (OSError, ValueError, RuntimeError) as e:
            self._logger.exception("Error during concolic execution: %s", e)
            self._logger.exception(traceback.format_exc())
            return {"error": f"Concolic execution failed: {e!s}"}

    def _target_hook(self, state: NativeConcolicState) -> None:
        """Execute hook when target address is reached."""
        state.terminate("target_reached")
        self._logger.info("Reached target address at PC: 0x%x", state.pc)

    def _avoid_hook(self, state: NativeConcolicState) -> None:
        """Execute hook to avoid specified addresses."""
        state.terminate("avoided")
        self._logger.info("Avoided address at PC: 0x%x", state.pc)

    def find_license_bypass(self, license_check_address: int | None = None) -> dict[str, Any]:
        """Find inputs that bypass license checks."""
        try:
            self._logger.info("Finding license bypass for %s", self.binary_path)

            if license_check_address is None:
                license_check_address = self._find_license_check_address()
            if license_check_address is None:
                return {"error": "Could not automatically find license check address"}

            self._logger.info("License check identified at address: 0x%x", license_check_address)

            m = NativeManticore(self.binary_path)

            success_found: list[bool] = [False]
            bypass_input: list[InputSymbols | None] = [None]

            def license_check_callback(state: NativeConcolicState) -> None:
                success_found[0] = True
                bypass_input[0] = {"stdin": state.input_symbols["stdin"], "argv": state.input_symbols["argv"].copy()}
                self._logger.info("Found potential license bypass at 0x%x", state.pc)

            m.add_hook(license_check_address, license_check_callback)
            m.set_exec_timeout(self.timeout)

            self._logger.info("Running concolic execution for license bypass...")
            m.run(procs=4)

            if success_found[0] and bypass_input[0]:
                stdin_data = bypass_input[0].get("stdin", b"")
                argv_data = bypass_input[0].get("argv", [])

                return {
                    "success": True,
                    "bypass_found": True,
                    "license_check_address": hex(license_check_address),
                    "stdin": stdin_data.hex() if isinstance(stdin_data, bytes) else str(stdin_data),
                    "argv": [arg.hex() if isinstance(arg, bytes) else str(arg) for arg in argv_data],
                    "description": "Found input that bypasses license check",
                }
            return {
                "success": True,
                "bypass_found": False,
                "description": "Could not find input that bypasses license check",
            }

        except (OSError, ValueError, RuntimeError) as e:
            self._logger.exception("Error finding license bypass: %s", e)
            self._logger.exception(traceback.format_exc())
            return {"error": f"License bypass search failed: {e!s}"}

    def _find_license_check_address(self) -> int | None:
        """Attempt to automatically find license check address."""
        try:
            if not LIEF_AVAILABLE or lief_module is None:
                self._logger.warning("LIEF not available - cannot analyze binary functions")
                return None

            binary = lief_module.parse(self.binary_path)
            if binary is None:
                self._logger.exception("Failed to parse binary with LIEF")
                return None

            if hasattr(binary, "exported_functions"):
                for func in binary.exported_functions:
                    func_name = func.name.lower()
                    if any(pattern_ in func_name for pattern_ in ["licen", "valid", "check", "auth"]):
                        return int(func.address)

            try:
                with open(self.binary_path, "rb") as f:
                    binary_data = f.read()

                license_patterns = [b"license", b"valid", b"key", b"auth", b"check"]
                for pattern in license_patterns:
                    if matches := list(re.finditer(pattern, binary_data, re.IGNORECASE)):
                        string_offset = matches[0].start()
                        potential_func_start = max(0, string_offset - 0x1000)
                        potential_func_start = (potential_func_start // 0x10) * 0x10

                        self._logger.info(
                            "Found potential license string at offset 0x%x, estimated function at 0x%x",
                            string_offset,
                            potential_func_start,
                        )
                        return potential_func_start

                self._logger.info("No license-related patterns found in binary")
                return None
            except OSError as e:
                self._logger.exception("Error reading binary file for pattern analysis: %s", e)
                return None

        except (OSError, ValueError, RuntimeError) as e:
            self._logger.exception("Error finding license check address: %s", e)
            return None

    def _extract_analysis_parameters(self, **kwargs: object) -> dict[str, object]:
        """Extract and validate analysis parameters from kwargs."""
        return {
            "target_functions": kwargs.get("target_functions", []),
            "avoid_functions": kwargs.get("avoid_functions", []),
            "max_depth": kwargs.get("max_depth", 100),
            "timeout": kwargs.get("timeout", self.timeout),
            "find_vulnerabilities": kwargs.get("find_vulnerabilities", True),
            "find_license_checks": kwargs.get("find_license_checks", True),
            "generate_test_cases": kwargs.get("generate_test_cases", True),
            "symbolic_stdin_size": kwargs.get("symbolic_stdin_size", 256),
            "concrete_seed": kwargs.get("concrete_seed"),
        }

    def _initialize_analysis_results(self, max_depth: int) -> dict[str, Any]:
        """Initialize the analysis results dictionary."""
        return {
            "binary": self.binary_path,
            "test_cases": [],
            "coverage": 0.0,
            "paths_explored": 0,
            "vulnerabilities": [],
            "license_checks": {},
            "execution_time": 0.0,
            "constraints": [],
            "interesting_addresses": [],
            "max_depth": max_depth,
            "error": None,
        }

    def analyze(self, binary_path: str | None, **kwargs: object) -> dict[str, Any]:
        """Perform comprehensive concolic execution analysis on a binary."""
        time.time()

        if binary_path:
            self.binary_path = binary_path

        self._logger.info("Starting concolic execution analysis on %s", self.binary_path)

        params = self._extract_analysis_parameters(**kwargs)
        max_depth_val = params.get("max_depth", 100)
        if not isinstance(max_depth_val, int):
            max_depth_val = 100
        self._initialize_analysis_results(max_depth_val)

        return self._native_analyze(self.binary_path, **kwargs)

    def _native_analyze(self, binary_path: str, **kwargs: object) -> dict[str, Any]:
        """Native implementation of analyze without Manticore."""
        start_time = time.time()

        self._logger.info("Starting native concolic analysis on %s", binary_path)

        results: dict[str, Any] = {
            "binary": binary_path,
            "test_cases": [],
            "coverage": 0.0,
            "paths_explored": 0,
            "vulnerabilities": [],
            "license_checks": {},
            "execution_time": 0.0,
            "constraints": [],
            "interesting_addresses": [],
            "error": None,
        }

        try:
            m = NativeManticore(binary_path)
            timeout_val = kwargs.get("timeout", self.timeout)
            if isinstance(timeout_val, int):
                m.set_exec_timeout(timeout_val)
            else:
                m.set_exec_timeout(self.timeout)

            m.run()

            all_states = m.get_all_states()
            terminated_states = m.get_terminated_states()

            results["paths_explored"] = len(all_states)

            for i, state in enumerate(terminated_states[:10]):
                exploit_vector: dict[str, Any] = {
                    "id": i,
                    "input": state.input_symbols.get("stdin", b"").hex(),
                    "triggers": [],
                    "path_length": len(state.execution_trace),
                    "termination_reason": state.termination_reason or "unknown",
                }
                results["test_cases"].append(exploit_vector)

            for state in all_states[:20]:
                if state.constraints:
                    results["constraints"].append(
                        {
                            "state_id": id(state),
                            "pc": hex(state.pc),
                            "constraints": state.constraints[:5],
                        },
                    )

            for state in terminated_states:
                if state.termination_reason == "segfault":
                    results["vulnerabilities"].append(
                        {
                            "type": "crash",
                            "address": hex(state.pc),
                            "description": "Program crashed (potential vulnerability)",
                        },
                    )

            unique_pcs: set[int] = set()
            for state in all_states:
                for trace_entry in state.execution_trace:
                    unique_pcs.add(trace_entry.get("pc", 0))

            results["coverage"] = float(len(unique_pcs))

            results["execution_time"] = time.time() - start_time

            return results

        except (OSError, ValueError, RuntimeError) as e:
            self._logger.exception("Native analysis failed: %s", e)
            results["error"] = str(e)
            results["execution_time"] = time.time() - start_time
            return results

    def _target_reached(self, state: NativeConcolicState, analysis_data: dict[str, Any]) -> None:
        """Handle when target address is reached."""
        successful_states: list[NativeConcolicState] = analysis_data.get("successful_states", [])
        successful_states.append(state)
        analysis_data["successful_states"] = successful_states

        interesting_addrs: set[int] = analysis_data.get("interesting_addresses", set())
        interesting_addrs.add(state.pc)
        analysis_data["interesting_addresses"] = interesting_addrs

        self._logger.info("Target reached at PC: 0x%x", state.pc)

    def execute(self, binary_path: str | None = None) -> dict[str, Any]:
        """Execute concolic analysis on the binary."""
        if binary_path:
            self.binary_path = binary_path

        return self.analyze(
            self.binary_path,
            find_vulnerabilities=True,
            find_license_checks=True,
            generate_test_cases=True,
        )


def run_concolic_execution(app: object, target_binary: str) -> dict[str, Any]:
    """Run concolic execution on a binary."""
    engine = ConcolicExecutionEngine(target_binary)
    return engine.execute(target_binary)


__all__ = [
    "ConcolicExecutionEngine",
    "MANTICORE_AVAILABLE",
    "NativeConcolicState",
    "NativeManticore",
    "NativePlugin",
    "run_concolic_execution",
]
