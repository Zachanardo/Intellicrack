"""Radare2 ESIL Emulation Engine.

This module provides advanced ESIL (Evaluable Strings Intermediate Language)
emulation capabilities for dynamic analysis and symbolic execution of binaries.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import ast
import json
import logging
import struct
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import TracebackType
from typing import Any, Callable

try:
    import r2pipe

    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False

from intellicrack.core.analysis.radare2_session_manager import (
    R2SessionPool,
    R2SessionWrapper,
)

logger = logging.getLogger(__name__)


class ESILState(Enum):
    """ESIL emulation states."""

    READY = "ready"
    RUNNING = "running"
    BREAKPOINT = "breakpoint"
    TRAPPED = "trapped"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class ESILRegister:
    """Register state during ESIL emulation."""

    name: str
    value: int
    size: int
    symbolic: bool = False
    tainted: bool = False
    constraints: list[str] = field(default_factory=list)


@dataclass
class ESILMemoryAccess:
    """Memory access tracking during emulation."""

    address: int
    size: int
    value: bytes
    operation: str
    instruction_address: int
    register_state: dict[str, int]


@dataclass
class ESILBreakpoint:
    """ESIL breakpoint configuration."""

    address: int
    condition: str | None = None
    hit_count: int = 0
    enabled: bool = True
    callback: Callable | None = None


class RadareESILEmulator:
    """Advanced ESIL emulation engine for dynamic binary analysis.

    This emulator provides ESIL (Evaluable Strings Intermediate Language) VM
    capabilities for analyzing binary behavior without execution. It integrates
    with the R2SessionPool for efficient resource management.

    Attributes:
        binary_path: Path to the binary being analyzed
        base_address: Base address for binary mapping
        session: R2SessionWrapper for radare2 communication
        state: Current emulation state
        registers: Register state tracking
        memory_map: Memory region tracking
        breakpoints: Active breakpoints
        memory_accesses: Logged memory operations
        call_stack: Function call tracking

    """

    def __init__(
        self,
        binary_path: str,
        base_address: int = 0x400000,
        session_pool: R2SessionPool | None = None,
        auto_analyze: bool = True,
        analysis_level: str = "aaa",
    ) -> None:
        """Initialize ESIL emulator with binary.

        Args:
            binary_path: Path to binary file to emulate
            base_address: Base address for binary mapping
            session_pool: Optional R2SessionPool for session management
            auto_analyze: Whether to auto-analyze binary on load
            analysis_level: radare2 analysis level (a, aa, aaa, aaaa)

        Raises:
            RuntimeError: If r2pipe is not available
            FileNotFoundError: If binary file not found

        """
        if not R2PIPE_AVAILABLE:
            raise RuntimeError("r2pipe not available - please install radare2-r2pipe")

        self.binary_path = Path(binary_path)
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self.base_address = base_address
        self.session_pool = session_pool
        self.auto_analyze = auto_analyze
        self.analysis_level = analysis_level

        self.session: R2SessionWrapper | None = None
        self.state = ESILState.READY
        self.registers: dict[str, ESILRegister] = {}
        self.memory_map: dict[int, bytes] = {}
        self.stack: list[int] = []
        self.breakpoints: dict[int, ESILBreakpoint] = {}
        self.memory_accesses: list[ESILMemoryAccess] = []
        self.call_stack: list[dict[str, Any]] = []
        self.taint_sources: list[int] = []
        self.symbolic_memory: dict[int, str] = {}
        self.path_constraints: list[str] = []
        self.instruction_count = 0
        self.cycle_count = 0
        self.arch = ""
        self.bits = 64
        self.entry_point = 0

        self._lock = threading.RLock()
        self._esil_hooks: dict[str, list[Callable]] = {}

        self._initialize_session()
        self._setup_esil_vm()

    def _initialize_session(self) -> None:
        """Initialize r2pipe session from pool or create new one.

        Raises:
            RuntimeError: If session initialization fails

        """
        try:
            flags = ["-2", "-w"]
            if not self.auto_analyze:
                flags.append("-n")

            if self.session_pool:
                self.session = self.session_pool.get_session(
                    str(self.binary_path),
                    flags=flags,
                )
            else:
                self.session = R2SessionWrapper(
                    binary_path=str(self.binary_path),
                    session_id=f"esil_{id(self)}",
                    flags=flags,
                    auto_analyze=self.auto_analyze,
                    analysis_level=self.analysis_level,
                )
                if not self.session.connect():
                    raise RuntimeError("Failed to connect session")

            self.session.execute("e io.va=true")
            self.session.execute("e asm.esil=true")
            self.session.execute("e esil.stack.addr=0x100000")
            self.session.execute("e esil.stack.size=0x10000")
            self.session.execute("e esil.fillstack=true")
            self.session.execute("e esil.nonull=false")

            info = self.session.execute("ij", expect_json=True)
            self.arch = info.get("bin", {}).get("arch", "x86")
            self.bits = info.get("bin", {}).get("bits", 64)

            logger.info(f"Initialized ESIL emulator for {self.arch}-{self.bits} binary: {self.binary_path}")

        except Exception as e:
            logger.error(f"Failed to initialize ESIL session: {e}")
            raise RuntimeError(f"ESIL session initialization failed: {e}") from e

    def _setup_esil_vm(self) -> None:
        """Set up ESIL virtual machine with initial state.

        Raises:
            RuntimeError: If ESIL VM setup fails

        """
        try:
            self.session.execute("aei")
            self.session.execute("aeim")
            self.session.execute("aeip")

            self._initialize_registers()
            self._setup_memory_regions()

            entry = self.session.execute("iej", expect_json=True)
            if entry and isinstance(entry, list) and len(entry) > 0 and "vaddr" in entry[0]:
                self.entry_point = entry[0]["vaddr"]
                self.session.execute(f"s {self.entry_point}")
                logger.debug(f"Set entry point to 0x{self.entry_point:x}")
            else:
                logger.warning("Could not determine entry point, using current address")
                pc_info = self.session.execute("drj", expect_json=True)
                if pc_info:
                    for reg in pc_info:
                        if reg.get("role") == "PC" or reg.get("name") in ["rip", "eip", "pc"]:
                            self.entry_point = reg.get("value", 0)
                            break

        except Exception as e:
            logger.error(f"Failed to setup ESIL VM: {e}")
            raise RuntimeError(f"ESIL VM setup failed: {e}") from e

    def _initialize_registers(self) -> None:
        """Initialize register tracking based on architecture.

        Raises:
            RuntimeError: If register initialization fails

        """
        try:
            reg_info = self.session.execute("drrj", expect_json=True)
            if not reg_info:
                logger.warning("No register information available")
                return

            for reg in reg_info:
                name = reg.get("name", "")
                if not name:
                    continue

                size = reg.get("size", 8)
                value = reg.get("value", 0)

                self.registers[name] = ESILRegister(
                    name=name,
                    value=value,
                    size=size,
                )

            logger.debug(f"Initialized {len(self.registers)} registers")

        except Exception as e:
            logger.error(f"Failed to initialize registers: {e}")
            raise RuntimeError(f"Register initialization failed: {e}") from e

    def _setup_memory_regions(self) -> None:
        """Set up memory regions for emulation.

        Raises:
            RuntimeError: If memory setup fails

        """
        try:
            sections = self.session.execute("iSj", expect_json=True)
            if not sections:
                logger.warning("No section information available")
                return

            for section in sections:
                perm = section.get("perm", "")
                if "r" in perm:
                    addr = section.get("vaddr", 0)
                    size = section.get("vsize", 0)
                    name = section.get("name", "section")

                    if addr and size:
                        self.session.execute(f"aeim {addr} {size} {name}")
                        logger.debug(f"Mapped memory region: {name} at 0x{addr:x} (size: 0x{size:x})")

            self.session.execute("aeim 0x200000 0x100000 heap")
            logger.debug("Mapped heap region at 0x200000")

        except Exception as e:
            logger.error(f"Failed to setup memory regions: {e}")
            raise RuntimeError(f"Memory region setup failed: {e}") from e

    def get_register(self, register: str) -> int:
        """Get current register value.

        Args:
            register: Register name

        Returns:
            Current register value

        Raises:
            RuntimeError: If register read fails

        """
        with self._lock:
            try:
                result = self.session.execute(f"?v ${register}")
                return int(result.strip(), 0)
            except Exception as e:
                logger.error(f"Failed to read register {register}: {e}")
                raise RuntimeError(f"Register read failed: {e}") from e

    def set_register(self, register: str, value: int | str, symbolic: bool = False) -> None:
        """Set register value with optional symbolic marking.

        Args:
            register: Register name to set
            value: Value to set (integer or symbolic expression)
            symbolic: Whether to mark this as a symbolic value

        Raises:
            RuntimeError: If register set operation fails

        """
        with self._lock:
            try:
                if symbolic:
                    sym_name = f"sym_{register}_{self.instruction_count}"
                    self.registers[register] = ESILRegister(
                        name=register,
                        value=value if isinstance(value, int) else 0,
                        size=self.registers.get(register, ESILRegister(register, 0, 8)).size,
                        symbolic=True,
                        constraints=[f"{sym_name} = {value}"],
                    )
                    self.session.execute(f"dr {register}={sym_name}")
                else:
                    self.session.execute(f"dr {register}={value}")
                    if register in self.registers:
                        self.registers[register].value = value if isinstance(value, int) else int(value)
                        self.registers[register].symbolic = False

                logger.debug(f"Set register {register} = {value} (symbolic={symbolic})")

            except Exception as e:
                logger.error(f"Failed to set register {register}: {e}")
                raise RuntimeError(f"Register set failed: {e}") from e

    def get_memory(self, address: int, size: int) -> bytes:
        """Read memory at address.

        Args:
            address: Memory address to read
            size: Number of bytes to read

        Returns:
            Memory contents as bytes

        Raises:
            RuntimeError: If memory read fails

        """
        with self._lock:
            try:
                result = self.session.execute(f"p8 {size} @ {address}")
                return bytes.fromhex(result.strip())
            except Exception as e:
                logger.error(f"Failed to read memory at 0x{address:x}: {e}")
                raise RuntimeError(f"Memory read failed: {e}") from e

    def set_memory(self, address: int, data: bytes, symbolic: bool = False) -> None:
        """Write memory with optional symbolic marking.

        Args:
            address: Memory address to write
            data: Data to write
            symbolic: Whether to mark as symbolic

        Raises:
            RuntimeError: If memory write fails

        """
        with self._lock:
            try:
                if symbolic:
                    for i, byte in enumerate(data):
                        sym_name = f"mem_{address + i:x}_{self.instruction_count}"
                        self.symbolic_memory[address + i] = sym_name
                        self.path_constraints.append(f"{sym_name} = {byte}")

                hex_data = data.hex()
                self.session.execute(f"wx {hex_data} @ {address}")
                self.memory_map[address] = data

                logger.debug(f"Wrote {len(data)} bytes to 0x{address:x} (symbolic={symbolic})")

            except Exception as e:
                logger.error(f"Failed to write memory at 0x{address:x}: {e}")
                raise RuntimeError(f"Memory write failed: {e}") from e

    def add_breakpoint(
        self,
        address: int,
        condition: str | None = None,
        callback: Callable | None = None,
    ) -> ESILBreakpoint:
        """Add conditional breakpoint with optional callback.

        Args:
            address: Address for breakpoint
            condition: Optional condition expression
            callback: Optional callback function(emulator, instruction_info)

        Returns:
            ESILBreakpoint object

        Raises:
            RuntimeError: If breakpoint creation fails

        """
        with self._lock:
            try:
                bp = ESILBreakpoint(address=address, condition=condition, callback=callback)
                self.breakpoints[address] = bp
                self.session.execute(f"db {address}")
                logger.debug(f"Added breakpoint at 0x{address:x}")
                return bp
            except Exception as e:
                logger.error(f"Failed to add breakpoint at 0x{address:x}: {e}")
                raise RuntimeError(f"Breakpoint creation failed: {e}") from e

    def remove_breakpoint(self, address: int) -> None:
        """Remove breakpoint at address.

        Args:
            address: Address of breakpoint to remove

        """
        with self._lock:
            if address in self.breakpoints:
                del self.breakpoints[address]
                try:
                    self.session.execute(f"db- {address}")
                    logger.debug(f"Removed breakpoint at 0x{address:x}")
                except Exception as e:
                    logger.warning(f"Failed to remove breakpoint: {e}")

    def add_hook(self, hook_type: str, callback: Callable) -> None:
        """Add ESIL operation hook.

        Args:
            hook_type: Type of operation to hook (e.g., 'mem_read', 'mem_write', 'reg_write')
            callback: Callback function

        """
        with self._lock:
            if hook_type not in self._esil_hooks:
                self._esil_hooks[hook_type] = []
            self._esil_hooks[hook_type].append(callback)
            logger.debug(f"Added hook for {hook_type}")

    def add_taint_source(self, address: int, size: int = 8) -> None:
        """Mark memory region as taint source for taint analysis.

        Args:
            address: Starting address of taint source
            size: Size of taint region in bytes

        """
        with self._lock:
            self.taint_sources.append(address)
            try:
                for i in range(size):
                    self.session.execute(f"dte {address + i}")
                logger.debug(f"Added taint source at 0x{address:x} (size: {size})")
            except Exception as e:
                logger.warning(f"Failed to set taint source: {e}")

    def step_instruction(self) -> dict[str, Any]:
        """Execute single instruction and track state changes.

        Returns:
            Dictionary containing execution step information

        Raises:
            RuntimeError: If step execution fails

        """
        with self._lock:
            try:
                prev_registers = self._get_register_state()
                prev_pc_info = self.session.execute("drj", expect_json=True)
                prev_pc = next(
                    (r["value"] for r in prev_pc_info if r.get("role") == "PC" or r.get("name") in ["rip", "eip", "pc"]),
                    0,
                )

                inst_info = self.session.execute("pdj 1", expect_json=True)
                if not inst_info or len(inst_info) == 0:
                    raise RuntimeError("No instruction at current address")

                inst = inst_info[0]
                inst_addr = inst.get("offset", 0)
                inst_esil = inst.get("esil", "")
                inst_opcode = inst.get("opcode", "")

                self.session.execute("aes")
                self.instruction_count += 1

                new_registers = self._get_register_state()
                new_pc_info = self.session.execute("drj", expect_json=True)
                new_pc = next(
                    (r["value"] for r in new_pc_info if r.get("role") == "PC" or r.get("name") in ["rip", "eip", "pc"]),
                    prev_pc,
                )

                changed_regs = {}
                for reg, new_val in new_registers.items():
                    if reg in prev_registers and prev_registers[reg] != new_val:
                        changed_regs[reg] = {"old": prev_registers[reg], "new": new_val}
                        if self._is_register_tainted(reg):
                            if reg in self.registers:
                                self.registers[reg].tainted = True

                mem_accesses = self._get_memory_accesses(inst_esil, inst_addr, new_registers)
                self.memory_accesses.extend(mem_accesses)

                control_flow_change = None
                if new_pc != prev_pc + inst.get("size", 4):
                    control_flow_change = {
                        "from": prev_pc,
                        "to": new_pc,
                        "type": self._determine_control_flow_type(inst_opcode),
                    }

                if new_pc in self.breakpoints:
                    bp = self.breakpoints[new_pc]
                    bp.hit_count += 1
                    if bp.enabled:
                        if not bp.condition or self._evaluate_condition(bp.condition):
                            self.state = ESILState.BREAKPOINT
                            if bp.callback:
                                bp.callback(self, inst)

                if "call" in inst_opcode.lower():
                    self.call_stack.append({
                        "from": inst_addr,
                        "to": new_pc,
                        "instruction": inst_opcode,
                        "stack_ptr": new_registers.get("rsp", new_registers.get("esp", 0)),
                    })
                elif "ret" in inst_opcode.lower() and self.call_stack:
                    self.call_stack.pop()

                return {
                    "address": inst_addr,
                    "instruction": inst_opcode,
                    "esil": inst_esil,
                    "changed_registers": changed_regs,
                    "memory_accesses": mem_accesses,
                    "new_pc": new_pc,
                    "call_depth": len(self.call_stack),
                    "control_flow": control_flow_change,
                }

            except Exception as e:
                logger.error(f"Step instruction failed: {e}")
                self.state = ESILState.ERROR
                raise RuntimeError(f"Instruction step failed: {e}") from e

    def _determine_control_flow_type(self, opcode: str) -> str:
        """Determine control flow type from opcode.

        Args:
            opcode: Instruction opcode

        Returns:
            Control flow type string

        """
        opcode_lower = opcode.lower()
        if "call" in opcode_lower:
            return "call"
        if "ret" in opcode_lower:
            return "ret"
        if any(j in opcode_lower for j in ["jmp", "je", "jne", "jz", "jnz", "jg", "jl", "ja", "jb"]):
            return "jump"
        return "other"

    def _get_register_state(self) -> dict[str, int]:
        """Get current register values.

        Returns:
            Dictionary mapping register names to values

        """
        try:
            reg_info = self.session.execute("drj", expect_json=True)
            regs = {}
            for reg in reg_info:
                name = reg.get("name", "")
                if name:
                    regs[name] = reg.get("value", 0)
            return regs
        except Exception as e:
            logger.warning(f"Failed to get register state: {e}")
            return {}

    def _is_register_tainted(self, register: str) -> bool:
        """Check if register is tainted through data flow.

        Args:
            register: Register name to check

        Returns:
            True if register is tainted

        """
        try:
            taint_info = self.session.execute(f"dtg {register}")
            return "tainted" in taint_info.lower()
        except Exception:
            return False

    def _get_memory_accesses(
        self,
        esil: str,
        inst_addr: int,
        registers: dict[str, int],
    ) -> list[ESILMemoryAccess]:
        """Extract memory accesses from ESIL expression.

        Args:
            esil: ESIL expression
            inst_addr: Instruction address
            registers: Current register state

        Returns:
            List of memory accesses

        """
        accesses = []

        if "[" in esil and "]" in esil:
            parts = esil.split(",")
            for part in parts:
                if "]" in part:
                    addr_expr = part.replace("[", "").replace("]", "")
                    try:
                        addr = self._evaluate_esil_expr(addr_expr, registers)
                        if addr is not None and addr > 0x1000:
                            try:
                                mem_val = self.get_memory(addr, 8)
                                accesses.append(ESILMemoryAccess(
                                    address=addr,
                                    size=8,
                                    value=mem_val,
                                    operation="read",
                                    instruction_address=inst_addr,
                                    register_state=registers.copy(),
                                ))
                            except Exception as e:
                                logger.debug(f"Failed to read memory during access tracking: {e}")
                    except Exception as e:
                        logger.debug(f"Failed to track memory read operation: {e}")

        if "=[" in esil:
            parts = esil.split(",")
            for i, part in enumerate(parts):
                if "=[" in part and i > 0:
                    value_expr = parts[i - 1]
                    addr_expr = part.replace("=[", "").replace("]", "")
                    try:
                        addr = self._evaluate_esil_expr(addr_expr, registers)
                        value = self._evaluate_esil_expr(value_expr, registers)
                        if addr is not None and value is not None and addr > 0x1000:
                            accesses.append(ESILMemoryAccess(
                                address=addr,
                                size=8,
                                value=struct.pack("<Q", value)[:8],
                                operation="write",
                                instruction_address=inst_addr,
                                register_state=registers.copy(),
                            ))
                    except Exception as e:
                        logger.debug(f"Failed to track memory write operation: {e}")

        return accesses

    def _evaluate_esil_expr(self, expr: str, registers: dict[str, int]) -> int | None:
        """Evaluate ESIL expression to concrete value.

        Args:
            expr: ESIL expression
            registers: Current register values

        Returns:
            Evaluated integer value or None

        """
        if expr in registers:
            return registers[expr]

        if expr.startswith("0x"):
            try:
                return int(expr, 16)
            except ValueError:
                pass

        try:
            return int(expr)
        except ValueError:
            pass

        try:
            result = self.session.execute(f"?v {expr}")
            return int(result.strip(), 0)
        except Exception:
            return None

    def _evaluate_condition(self, condition: str) -> bool:
        """Evaluate breakpoint condition.

        Args:
            condition: Condition expression

        Returns:
            True if condition is met

        """
        registers = self._get_register_state()
        for reg, val in registers.items():
            condition = condition.replace(reg, str(val))

        try:
            import ast

            node = ast.parse(condition, mode="eval")
            if not self._validate_ast_node(node):
                return False

            return self._eval_node(node.body)
        except Exception:
            return False

    def _validate_ast_node(self, node: ast.AST) -> bool:
        """Validate that the AST node contains only safe operations.

        Args:
            node: AST node to validate

        Returns:
            True if node is safe

        """
        for subnode in ast.walk(node):
            if not isinstance(subnode, (
                ast.Expression, ast.Compare, ast.BinOp, ast.UnaryOp,
                ast.Name, ast.Constant, ast.Load, ast.Eq, ast.NotEq,
                ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Add, ast.Sub,
                ast.Mult, ast.Div, ast.Mod, ast.Pow, ast.BitAnd,
                ast.BitOr, ast.BitXor, ast.LShift, ast.RShift,
                ast.UAdd, ast.USub, ast.Invert,
            )):
                return False
        return True

    def _eval_node(self, node: ast.AST) -> int | float | str | bool:
        """Evaluate the parsed AST manually instead of using eval.

        Args:
            node: AST node to evaluate

        Returns:
            Evaluation result

        """
        if isinstance(node, ast.Expression):
            return self._eval_node(node.body)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Num):
            return node.n
        if isinstance(node, ast.Str):
            return node.s
        if isinstance(node, ast.NameConstant):
            return node.value
        if isinstance(node, ast.Name):
            raise TypeError(f"Unexpected variable name: {node.id}")
        if isinstance(node, ast.BinOp):
            return self._eval_binop(node)
        if isinstance(node, ast.UnaryOp):
            return self._eval_unaryop(node)
        if isinstance(node, ast.Compare):
            return self._eval_compare(node)
        raise ValueError(f"Unsupported AST node type: {type(node)}")

    def _eval_binop(self, node: ast.BinOp) -> int | float:
        """Evaluate binary operations.

        Args:
            node: Binary operation AST node

        Returns:
            Operation result

        """
        left = self._eval_node(node.left)
        right = self._eval_node(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            return left / right if right != 0 else 0
        if isinstance(node.op, ast.Mod):
            return left % right if right != 0 else 0
        if isinstance(node.op, ast.Pow):
            return left ** right
        if isinstance(node.op, ast.BitAnd):
            return left & right
        if isinstance(node.op, ast.BitOr):
            return left | right
        if isinstance(node.op, ast.BitXor):
            return left ^ right
        if isinstance(node.op, ast.LShift):
            return left << right
        if isinstance(node.op, ast.RShift):
            return left >> right
        return 0

    def _eval_unaryop(self, node: ast.UnaryOp) -> int:
        """Evaluate unary operations.

        Args:
            node: Unary operation AST node

        Returns:
            Operation result

        """
        operand = self._eval_node(node.operand)
        if isinstance(node.op, ast.UAdd):
            return +operand
        if isinstance(node.op, ast.USub):
            return -operand
        if isinstance(node.op, ast.Invert):
            return ~operand
        return 0

    def _eval_compare(self, node: ast.Compare) -> bool:
        """Evaluate comparison operations.

        Args:
            node: Comparison AST node

        Returns:
            Comparison result

        """
        left = self._eval_node(node.left)
        result = True
        for op, comparator in zip(node.ops, node.comparators, strict=False):
            right = self._eval_node(comparator)
            if isinstance(op, ast.Eq):
                result = result and (left == right)
            elif isinstance(op, ast.NotEq):
                result = result and (left != right)
            elif isinstance(op, ast.Lt):
                result = result and (left < right)
            elif isinstance(op, ast.LtE):
                result = result and (left <= right)
            elif isinstance(op, ast.Gt):
                result = result and (left > right)
            elif isinstance(op, ast.GtE):
                result = result and (left >= right)
            left = right
        return result

    def run_until(
        self,
        target: int | str,
        max_steps: int = 10000,
    ) -> list[dict[str, Any]]:
        """Run emulation until target address or condition.

        Args:
            target: Target address or symbol name
            max_steps: Maximum number of instructions to execute

        Returns:
            List of execution step information

        Raises:
            RuntimeError: If emulation fails

        """
        trace = []
        self.state = ESILState.RUNNING

        try:
            if isinstance(target, str):
                result = self.session.execute(f"?v {target}")
                target_addr = int(result.strip(), 0)
            else:
                target_addr = target

            for _ in range(max_steps):
                if self.state != ESILState.RUNNING:
                    break

                step = self.step_instruction()
                trace.append(step)

                if step["new_pc"] == target_addr:
                    self.state = ESILState.COMPLETE
                    break

                if self._check_trap_conditions(step):
                    self.state = ESILState.TRAPPED
                    break

            return trace

        except Exception as e:
            logger.error(f"Emulation failed: {e}")
            self.state = ESILState.ERROR
            raise RuntimeError(f"Emulation failed: {e}") from e

    def _check_trap_conditions(self, step: dict[str, Any]) -> bool:
        """Check for trap conditions like invalid memory access.

        Args:
            step: Execution step information

        Returns:
            True if trap condition detected

        """
        for access in step.get("memory_accesses", []):
            if access.address < 0x1000:
                logger.warning(f"Null pointer access at {step['address']:x}")
                return True

            try:
                sections = self.session.execute("iSj", expect_json=True)
                mapped = False
                for section in sections:
                    start = section.get("vaddr", 0)
                    end = start + section.get("vsize", 0)
                    if start <= access.address < end:
                        mapped = True
                        break

                if not mapped:
                    logger.warning(f"Unmapped memory access at {access.address:x}")
                    return True
            except Exception as e:
                logger.debug(f"Error checking trap condition: {e}")

        return False

    def extract_api_calls(self) -> list[dict[str, Any]]:
        """Extract API calls made during emulation.

        Returns:
            List of API call information

        """
        api_calls = []

        try:
            imports = self.session.execute("iij", expect_json=True)
            import_addrs = {imp.get("plt", 0): imp.get("name", "") for imp in imports}

            for entry in self.call_stack:
                if entry["to"] in import_addrs:
                    api_calls.append({
                        "address": entry["from"],
                        "api": import_addrs[entry["to"]],
                        "stack_ptr": entry["stack_ptr"],
                        "arguments": self._extract_call_arguments(entry["from"]),
                    })

        except Exception as e:
            logger.warning(f"Failed to extract API calls: {e}")

        return api_calls

    def _extract_call_arguments(self, call_addr: int) -> list[int]:
        """Extract function call arguments based on calling convention.

        Args:
            call_addr: Address of call instruction

        Returns:
            List of argument values

        """
        args = []
        registers = self._get_register_state()

        if self.arch == "x86":
            if self.bits == 64:
                arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
                for reg in arg_regs:
                    if reg in registers:
                        args.append(registers[reg])
            else:
                esp = registers.get("esp", 0)
                for i in range(6):
                    try:
                        arg_data = self.get_memory(esp + 4 + i * 4, 4)
                        args.append(struct.unpack("<I", arg_data)[0])
                    except Exception:
                        break

        elif self.arch == "arm":
            if self.bits == 64:
                for i in range(8):
                    reg = f"x{i}"
                    if reg in registers:
                        args.append(registers[reg])
            else:
                for i in range(4):
                    reg = f"r{i}"
                    if reg in registers:
                        args.append(registers[reg])

        return args

    def find_license_checks(self) -> list[dict[str, Any]]:
        """Find potential license validation code through symbolic execution.

        Returns:
            List of potential license check locations

        """
        license_patterns = []
        patterns = [
            "cmp.*0x.*",
            "test.*",
            "je.*",
            "jne.*",
        ]

        try:
            for pattern in patterns:
                matches = self.session.execute(f"/j {pattern}", expect_json=True)
                if not matches:
                    continue

                for match in matches:
                    addr = match.get("offset", 0)
                    if not addr:
                        continue

                    try:
                        cfg = self.session.execute(f"agj @ {addr}", expect_json=True)
                        if cfg and len(cfg) > 0:
                            blocks = cfg[0].get("blocks", [])
                            for block in blocks:
                                if block.get("offset", 0) == addr:
                                    jumps = block.get("jump", [])
                                    if len(jumps) > 1:
                                        license_patterns.append({
                                            "address": addr,
                                            "type": "conditional_branch",
                                            "pattern": pattern,
                                            "true_path": jumps[0],
                                            "false_path": jumps[1] if len(jumps) > 1 else None,
                                        })
                    except Exception as e:
                        logger.debug(f"Failed to analyze license check pattern: {e}")

        except Exception as e:
            logger.warning(f"Failed to find license checks: {e}")

        return license_patterns

    def generate_path_constraints(self, target: int) -> list[str]:
        """Generate path constraints to reach target address.

        Args:
            target: Target address

        Returns:
            List of path constraints

        """
        constraints = []

        try:
            self.path_constraints = []
            trace = self.run_until(target)

            for step in trace:
                inst = step.get("instruction", "")

                if any(cond in inst.lower() for cond in ["je", "jne", "jz", "jnz", "jg", "jl", "ja", "jb"]):
                    esil = step.get("esil", "")
                    if "?{" in esil:
                        condition = esil.split("?{")[0]

                        if step["new_pc"] == step["address"] + len(inst):
                            constraints.append(f"NOT({condition})")
                        else:
                            constraints.append(condition)

            constraints.extend(self.path_constraints)

        except Exception as e:
            logger.warning(f"Failed to generate path constraints: {e}")

        return constraints

    def dump_execution_trace(self, output_path: str) -> None:
        """Dump complete execution trace to JSON file.

        Args:
            output_path: Path to output file

        Raises:
            RuntimeError: If trace dump fails

        """
        try:
            trace_data = {
                "binary": str(self.binary_path),
                "architecture": f"{self.arch}-{self.bits}",
                "entry_point": self.entry_point,
                "instruction_count": self.instruction_count,
                "breakpoints_hit": [
                    {
                        "address": addr,
                        "hits": bp.hit_count,
                        "condition": bp.condition,
                    }
                    for addr, bp in self.breakpoints.items()
                    if bp.hit_count > 0
                ],
                "api_calls": self.extract_api_calls(),
                "memory_accesses": [
                    {
                        "address": acc.address,
                        "size": acc.size,
                        "operation": acc.operation,
                        "instruction": acc.instruction_address,
                    }
                    for acc in self.memory_accesses
                ],
                "tainted_registers": [
                    reg for reg, state in self.registers.items()
                    if state.tainted
                ],
                "path_constraints": self.path_constraints,
                "call_stack_max_depth": max(len(self.call_stack), 1),
            }

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(trace_data, f, indent=2)

            logger.info(f"Execution trace dumped to {output_path}")

        except Exception as e:
            logger.error(f"Failed to dump execution trace: {e}")
            raise RuntimeError(f"Trace dump failed: {e}") from e

    def reset(self) -> None:
        """Reset emulator state to initial conditions.

        Raises:
            RuntimeError: If reset fails

        """
        with self._lock:
            try:
                self.state = ESILState.READY
                self.memory_accesses.clear()
                self.call_stack.clear()
                self.path_constraints.clear()
                self.instruction_count = 0
                self.cycle_count = 0

                self.session.execute("aei")
                self.session.execute("aeim")
                self.session.execute("aeip")

                if self.entry_point:
                    self.session.execute(f"s {self.entry_point}")

                self._initialize_registers()

                logger.info("Emulator state reset")

            except Exception as e:
                logger.error(f"Failed to reset emulator: {e}")
                raise RuntimeError(f"Reset failed: {e}") from e

    def cleanup(self) -> None:
        """Clean up resources.

        This method should be called when done with the emulator to properly
        release resources and return sessions to the pool.
        """
        with self._lock:
            if self.session:
                if self.session_pool:
                    self.session_pool.return_session(self.session)
                else:
                    self.session.disconnect()
                self.session = None

            logger.info("ESIL emulator cleaned up")

    def __enter__(self) -> "RadareESILEmulator":
        """Context manager entry.

        Returns:
            Self for context manager

        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager exit.

        Args:
            exc_type: Exception type
            exc_val: Exception value
            exc_tb: Exception traceback

        """
        self.cleanup()


__all__ = [
    "ESILState",
    "ESILRegister",
    "ESILMemoryAccess",
    "ESILBreakpoint",
    "RadareESILEmulator",
]
