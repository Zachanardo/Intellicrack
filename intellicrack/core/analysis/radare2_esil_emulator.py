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

import r2pipe
import struct
import json
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
import logging

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
    constraints: List[str] = None

    def __post_init__(self):
        if self.constraints is None:
            self.constraints = []


@dataclass
class ESILMemoryAccess:
    """Memory access tracking during emulation."""
    address: int
    size: int
    value: bytes
    operation: str  # "read" or "write"
    instruction_address: int
    register_state: Dict[str, int]


@dataclass
class ESILBreakpoint:
    """ESIL breakpoint configuration."""
    address: int
    condition: Optional[str] = None
    hit_count: int = 0
    enabled: bool = True
    callback: Optional[callable] = None


class RadareESILEmulator:
    """Advanced ESIL emulation engine for dynamic binary analysis."""

    def __init__(self, binary_path: str, base_address: int = 0x400000):
        """Initialize ESIL emulator with binary."""
        self.binary_path = binary_path
        self.base_address = base_address
        self.r2 = None
        self.state = ESILState.READY
        self.registers: Dict[str, ESILRegister] = {}
        self.memory_map: Dict[int, bytes] = {}
        self.stack: List[int] = []
        self.breakpoints: Dict[int, ESILBreakpoint] = {}
        self.memory_accesses: List[ESILMemoryAccess] = []
        self.call_stack: List[Dict[str, Any]] = []
        self.taint_sources: List[int] = []
        self.symbolic_memory: Dict[int, str] = {}
        self.path_constraints: List[str] = []
        self.instruction_count = 0
        self.cycle_count = 0

        self._initialize_r2()
        self._setup_esil_vm()

    def _initialize_r2(self):
        """Initialize r2pipe connection and analyze binary."""
        try:
            self.r2 = r2pipe.open(self.binary_path, ["-2", "-w"])
            self.r2.cmd("aaa")  # Analyze all
            self.r2.cmd(f"e io.va=true")  # Enable virtual addressing
            self.r2.cmd(f"e asm.esil=true")  # Enable ESIL output
            self.r2.cmd(f"e esil.stack.addr=0x100000")  # Set stack address
            self.r2.cmd(f"e esil.stack.size=0x10000")  # Set stack size

            # Get architecture info
            info = json.loads(self.r2.cmd("ij"))
            self.arch = info.get("bin", {}).get("arch", "x86")
            self.bits = info.get("bin", {}).get("bits", 64)

            logger.info(f"Initialized ESIL for {self.arch}-{self.bits} binary")

        except Exception as e:
            logger.error(f"Failed to initialize r2pipe: {e}")
            raise

    def _setup_esil_vm(self):
        """Setup ESIL virtual machine with initial state."""
        # Initialize ESIL VM
        self.r2.cmd("aei")  # Initialize ESIL VM
        self.r2.cmd("aeim")  # Initialize ESIL VM memory

        # Setup register tracking
        self._initialize_registers()

        # Setup memory regions
        self._setup_memory_regions()

        # Set entry point
        entry = json.loads(self.r2.cmd("iej"))
        if entry and "vaddr" in entry[0]:
            self.entry_point = entry[0]["vaddr"]
            self.r2.cmd(f"s {self.entry_point}")

    def _initialize_registers(self):
        """Initialize register tracking based on architecture."""
        reg_info = json.loads(self.r2.cmd("drrj"))

        for reg in reg_info:
            name = reg.get("name", "")
            size = reg.get("size", 8)
            value = reg.get("value", 0)

            self.registers[name] = ESILRegister(
                name=name,
                value=value,
                size=size
            )

    def _setup_memory_regions(self):
        """Setup memory regions for emulation."""
        # Map binary sections
        sections = json.loads(self.r2.cmd("iSj"))
        for section in sections:
            if section.get("perm", "").find("r") >= 0:
                addr = section.get("vaddr", 0)
                size = section.get("vsize", 0)
                if addr and size:
                    self.r2.cmd(f"aeim {addr} {size} {section.get('name', 'section')}")

        # Setup heap
        self.r2.cmd("aeim 0x200000 0x100000 heap")

    def set_register(self, register: str, value: Union[int, str], symbolic: bool = False):
        """Set register value with optional symbolic marking."""
        if symbolic:
            # Create symbolic variable
            sym_name = f"sym_{register}_{self.instruction_count}"
            self.registers[register] = ESILRegister(
                name=register,
                value=value if isinstance(value, int) else 0,
                size=self.registers[register].size if register in self.registers else 8,
                symbolic=True,
                constraints=[f"{sym_name} = {value}"]
            )
            self.r2.cmd(f"dr {register}={sym_name}")
        else:
            # Set concrete value
            self.r2.cmd(f"dr {register}={value}")
            if register in self.registers:
                self.registers[register].value = value
                self.registers[register].symbolic = False

    def set_memory(self, address: int, data: bytes, symbolic: bool = False):
        """Write memory with optional symbolic marking."""
        if symbolic:
            # Store symbolic expression
            for i, byte in enumerate(data):
                sym_name = f"mem_{address + i:x}_{self.instruction_count}"
                self.symbolic_memory[address + i] = sym_name
                self.path_constraints.append(f"{sym_name} = {byte}")

        # Write concrete data for emulation
        hex_data = data.hex()
        self.r2.cmd(f"wx {hex_data} @ {address}")
        self.memory_map[address] = data

    def add_breakpoint(self, address: int, condition: Optional[str] = None,
                       callback: Optional[callable] = None) -> ESILBreakpoint:
        """Add conditional breakpoint with optional callback."""
        bp = ESILBreakpoint(
            address=address,
            condition=condition,
            callback=callback
        )
        self.breakpoints[address] = bp
        self.r2.cmd(f"db {address}")
        return bp

    def add_taint_source(self, address: int, size: int = 8):
        """Mark memory region as taint source for taint analysis."""
        self.taint_sources.append(address)
        # Mark registers that load from this address as tainted
        for i in range(size):
            self.r2.cmd(f"dte {address + i}")

    def step_instruction(self) -> Dict[str, Any]:
        """Execute single instruction and track state changes."""
        # Save current state
        prev_registers = self._get_register_state()
        prev_pc = json.loads(self.r2.cmd("drj pc"))[0]["value"]

        # Get current instruction
        inst_info = json.loads(self.r2.cmd("pdj 1"))[0]
        inst_addr = inst_info.get("offset", 0)
        inst_esil = inst_info.get("esil", "")
        inst_opcode = inst_info.get("opcode", "")

        # Execute ESIL step
        self.r2.cmd("aes")
        self.instruction_count += 1

        # Get new state
        new_registers = self._get_register_state()
        new_pc = json.loads(self.r2.cmd("drj pc"))[0]["value"]

        # Track register changes
        changed_regs = {}
        for reg, new_val in new_registers.items():
            if reg in prev_registers and prev_registers[reg] != new_val:
                changed_regs[reg] = {
                    "old": prev_registers[reg],
                    "new": new_val
                }
                # Propagate taint
                if self._is_register_tainted(reg):
                    self.registers[reg].tainted = True

        # Track memory accesses
        mem_accesses = self._get_memory_accesses(inst_esil, inst_addr, new_registers)
        self.memory_accesses.extend(mem_accesses)

        # Check breakpoints
        if new_pc in self.breakpoints:
            bp = self.breakpoints[new_pc]
            bp.hit_count += 1
            if bp.enabled:
                if bp.condition:
                    # Evaluate condition
                    if self._evaluate_condition(bp.condition):
                        self.state = ESILState.BREAKPOINT
                        if bp.callback:
                            bp.callback(self, inst_info)
                else:
                    self.state = ESILState.BREAKPOINT
                    if bp.callback:
                        bp.callback(self, inst_info)

        # Track calls
        if "call" in inst_opcode.lower():
            self.call_stack.append({
                "from": inst_addr,
                "to": new_pc,
                "instruction": inst_opcode,
                "stack_ptr": new_registers.get("rsp", new_registers.get("esp", 0))
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
            "call_depth": len(self.call_stack)
        }

    def _get_register_state(self) -> Dict[str, int]:
        """Get current register values."""
        regs = {}
        reg_info = json.loads(self.r2.cmd("drj"))
        for reg in reg_info:
            regs[reg["name"]] = reg["value"]
        return regs

    def _is_register_tainted(self, register: str) -> bool:
        """Check if register is tainted through data flow."""
        # Check taint propagation through ESIL
        taint_info = self.r2.cmd(f"dtg {register}")
        return "tainted" in taint_info.lower()

    def _get_memory_accesses(self, esil: str, inst_addr: int,
                            registers: Dict[str, int]) -> List[ESILMemoryAccess]:
        """Extract memory accesses from ESIL expression."""
        accesses = []

        # Parse ESIL for memory operations
        if "[" in esil and "]" in esil:
            # Memory read operation
            parts = esil.split(",")
            for i, part in enumerate(parts):
                if "]" in part:
                    # Found memory dereference
                    addr_expr = part.replace("[", "").replace("]", "")
                    try:
                        # Evaluate address
                        addr = self._evaluate_esil_expr(addr_expr, registers)
                        if addr:
                            # Read memory value
                            mem_val = self.r2.cmd(f"pv @ {addr}")
                            accesses.append(ESILMemoryAccess(
                                address=addr,
                                size=8,  # Default size
                                value=bytes.fromhex(mem_val.strip()),
                                operation="read",
                                instruction_address=inst_addr,
                                register_state=registers.copy()
                            ))
                    except:
                        pass

        if "=[" in esil:
            # Memory write operation
            parts = esil.split(",")
            for i, part in enumerate(parts):
                if "=[" in part:
                    if i > 0:
                        # Previous part is the value
                        value_expr = parts[i-1]
                        addr_expr = part.replace("=[", "").replace("]", "")
                        try:
                            addr = self._evaluate_esil_expr(addr_expr, registers)
                            value = self._evaluate_esil_expr(value_expr, registers)
                            if addr and value is not None:
                                accesses.append(ESILMemoryAccess(
                                    address=addr,
                                    size=8,
                                    value=struct.pack("<Q", value)[:8],
                                    operation="write",
                                    instruction_address=inst_addr,
                                    register_state=registers.copy()
                                ))
                        except:
                            pass

        return accesses

    def _evaluate_esil_expr(self, expr: str, registers: Dict[str, int]) -> Optional[int]:
        """Evaluate ESIL expression to concrete value."""
        # Handle register references
        if expr in registers:
            return registers[expr]

        # Handle hex values
        if expr.startswith("0x"):
            return int(expr, 16)

        # Handle decimal values
        try:
            return int(expr)
        except:
            pass

        # Complex expression - use r2 to evaluate
        try:
            result = self.r2.cmd(f"?v {expr}")
            return int(result.strip())
        except:
            return None

    def _evaluate_condition(self, condition: str) -> bool:
        """Evaluate breakpoint condition."""
        # Replace register names with values
        registers = self._get_register_state()
        for reg, val in registers.items():
            condition = condition.replace(reg, str(val))

        try:
            # Safe evaluation
            import ast
            node = ast.parse(condition, mode='eval')
            for subnode in ast.walk(node):
                if not isinstance(subnode, (ast.Expression, ast.Compare, ast.BinOp,
                                           ast.UnaryOp, ast.Name, ast.Constant,
                                           ast.Load, ast.Eq, ast.NotEq, ast.Lt,
                                           ast.LtE, ast.Gt, ast.GtE)):
                    return False

            compiled = compile(node, '<string>', 'eval')
            return eval(compiled, {"__builtins__": {}}, {})
        except:
            return False

    def run_until(self, target: Union[int, str], max_steps: int = 10000) -> List[Dict[str, Any]]:
        """Run emulation until target address or condition."""
        trace = []
        self.state = ESILState.RUNNING

        if isinstance(target, str):
            # Symbol name - resolve to address
            target_addr = json.loads(self.r2.cmd(f"?j {target}"))[0]["value"]
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

            # Check for traps
            if self._check_trap_conditions(step):
                self.state = ESILState.TRAPPED
                break

        return trace

    def _check_trap_conditions(self, step: Dict[str, Any]) -> bool:
        """Check for trap conditions like invalid memory access."""
        # Check for null pointer dereference
        for access in step.get("memory_accesses", []):
            if access.address < 0x1000:
                logger.warning(f"Null pointer access at {step['address']:x}")
                return True

            # Check for unmapped memory
            sections = json.loads(self.r2.cmd("iSj"))
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

        return False

    def extract_api_calls(self) -> List[Dict[str, Any]]:
        """Extract API calls made during emulation."""
        api_calls = []

        imports = json.loads(self.r2.cmd("iij"))
        import_addrs = {imp.get("plt", 0): imp.get("name", "") for imp in imports}

        for entry in self.call_stack:
            if entry["to"] in import_addrs:
                api_calls.append({
                    "address": entry["from"],
                    "api": import_addrs[entry["to"]],
                    "stack_ptr": entry["stack_ptr"],
                    "arguments": self._extract_call_arguments(entry["from"])
                })

        return api_calls

    def _extract_call_arguments(self, call_addr: int) -> List[int]:
        """Extract function call arguments based on calling convention."""
        args = []
        registers = self._get_register_state()

        if self.arch == "x86":
            if self.bits == 64:
                # x64 calling convention (System V AMD64 ABI)
                arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
                for reg in arg_regs:
                    if reg in registers:
                        args.append(registers[reg])
            else:
                # x86 stdcall/cdecl - args on stack
                esp = registers.get("esp", 0)
                for i in range(6):
                    try:
                        arg_data = self.r2.cmd(f"pv @ {esp + 4 + i*4}")
                        args.append(int(arg_data.strip()))
                    except:
                        break

        elif self.arch == "arm":
            if self.bits == 64:
                # ARM64 calling convention
                for i in range(8):
                    reg = f"x{i}"
                    if reg in registers:
                        args.append(registers[reg])
            else:
                # ARM32 calling convention
                for i in range(4):
                    reg = f"r{i}"
                    if reg in registers:
                        args.append(registers[reg])

        return args

    def find_license_checks(self) -> List[Dict[str, Any]]:
        """Find potential license validation code through symbolic execution."""
        license_patterns = []

        # Common license check patterns
        patterns = [
            "cmp.*0x.*",  # Comparisons with constants
            "test.*",      # Test instructions
            "je.*fail",    # Jump to failure
            "jne.*success" # Jump to success
        ]

        # Search for patterns
        for pattern in patterns:
            matches = json.loads(self.r2.cmd(f"/j {pattern}"))
            for match in matches:
                addr = match.get("offset", 0)

                # Analyze control flow around match
                cfg = json.loads(self.r2.cmd(f"agj @ {addr}"))
                if cfg:
                    # Look for divergent paths (success/failure)
                    blocks = cfg[0].get("blocks", [])
                    for block in blocks:
                        if block.get("offset", 0) == addr:
                            if len(block.get("jump", [])) > 1:
                                license_patterns.append({
                                    "address": addr,
                                    "type": "conditional_branch",
                                    "pattern": pattern,
                                    "true_path": block["jump"][0],
                                    "false_path": block["jump"][1] if len(block["jump"]) > 1 else None
                                })

        return license_patterns

    def generate_path_constraints(self, target: int) -> List[str]:
        """Generate path constraints to reach target address."""
        constraints = []

        # Run symbolic execution
        self.path_constraints = []
        trace = self.run_until(target)

        # Collect branch conditions
        for step in trace:
            inst = step.get("instruction", "")

            # Check for conditional branches
            if any(cond in inst.lower() for cond in ["je", "jne", "jz", "jnz", "jg", "jl", "ja", "jb"]):
                # Extract condition from ESIL
                esil = step.get("esil", "")
                if "?{" in esil:
                    # Conditional execution in ESIL
                    condition = esil.split("?{")[0]

                    # Add to constraints based on branch taken
                    if step["new_pc"] == step["address"] + len(inst):
                        # Branch not taken
                        constraints.append(f"NOT({condition})")
                    else:
                        # Branch taken
                        constraints.append(condition)

        return constraints + self.path_constraints

    def dump_execution_trace(self, output_path: str):
        """Dump complete execution trace to JSON file."""
        trace_data = {
            "binary": self.binary_path,
            "architecture": f"{self.arch}-{self.bits}",
            "entry_point": self.entry_point,
            "instruction_count": self.instruction_count,
            "breakpoints_hit": [
                {
                    "address": addr,
                    "hits": bp.hit_count,
                    "condition": bp.condition
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
                    "instruction": acc.instruction_address
                }
                for acc in self.memory_accesses
            ],
            "tainted_registers": [
                reg for reg, state in self.registers.items()
                if state.tainted
            ],
            "path_constraints": self.path_constraints,
            "call_stack_max_depth": max(len(self.call_stack), 1)
        }

        with open(output_path, 'w') as f:
            json.dump(trace_data, f, indent=2)

    def cleanup(self):
        """Clean up resources."""
        if self.r2:
            self.r2.quit()
            self.r2 = None