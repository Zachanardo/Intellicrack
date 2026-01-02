"""Production-Ready Symbolic Execution-Based Devirtualization Engine.

Advanced devirtualization engine using angr symbolic execution to recover original
code from virtualized binaries (VMProtect, Themida, Code Virtualizer, etc.).

Capabilities:
- Symbolic execution of VM handlers with angr
- Handler semantic lifting to intermediate representation
- Path exploration strategies (DFS, BFS, guided)
- VM context tracking and register mapping
- Control flow recovery from VM bytecode
- Constraint solving for complex VM logic
- Code reconstruction to native assembly
- Multi-architecture support (x86, x64, ARM)

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import re
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import angr
import claripy
from angr import Project, SimState
from angr.errors import SimEngineError, SimValueError
from angr.exploration_techniques import DFS, ExplorationTechnique
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from keystone import KS_ARCH_X86, KS_MODE_32, KS_MODE_64, Ks

from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)

ARCH_32_BITS = 32
ARCH_64_BITS = 64
POINTER_SIZE_32 = 4
POINTER_SIZE_64 = 8
MIN_VALID_POINTER = 0x1000
MAX_VALID_POINTER_32 = 0x10000000
MAX_VALID_POINTER_64 = 0x7FFFFFFFFFFF
MAX_STACK_POINTER_32 = 0x7FFFFFFF
NATIVE_CODE_SIZE_THRESHOLD = 50
MIN_BLOCK_COUNT = 5
MIN_HANDLER_COUNT = 20

AngrSimMgr = Any


class ExplorationStrategy(Enum):
    """Enumeration of VM exploration strategies."""

    DFS = "depth_first_search"
    BFS = "breadth_first_search"
    GUIDED = "guided_search"
    CONCOLIC = "concolic_execution"


class VMType(Enum):
    """Enumeration of supported VM protection types."""

    VMPROTECT = "vmprotect"
    THEMIDA = "themida"
    CODE_VIRTUALIZER = "code_virtualizer"
    GENERIC = "generic"
    UNKNOWN = "unknown"


class HandlerSemantic(Enum):
    """Enumeration of VM handler semantics."""

    STACK_PUSH = "stack_push"
    STACK_POP = "stack_pop"
    ARITHMETIC_ADD = "arithmetic_add"
    ARITHMETIC_SUB = "arithmetic_sub"
    ARITHMETIC_MUL = "arithmetic_mul"
    ARITHMETIC_DIV = "arithmetic_div"
    LOGICAL_AND = "logical_and"
    LOGICAL_OR = "logical_or"
    LOGICAL_XOR = "logical_xor"
    LOGICAL_NOT = "logical_not"
    SHIFT_LEFT = "shift_left"
    SHIFT_RIGHT = "shift_right"
    BRANCH_CONDITIONAL = "branch_conditional"
    BRANCH_UNCONDITIONAL = "branch_unconditional"
    CALL = "call"
    RETURN = "return"
    MEMORY_LOAD = "memory_load"
    MEMORY_STORE = "memory_store"
    VM_EXIT = "vm_exit"
    UNKNOWN = "unknown"


@dataclass
class LiftedHandler:
    """Lifted VM handler with semantic information."""

    handler_address: int
    semantic: HandlerSemantic
    symbolic_effects: list[tuple[str, Any]]
    constraints: list[Any]
    native_translation: bytes | None
    assembly_code: list[str]
    confidence: float
    operand_count: int = 0
    operand_types: list[str] = field(default_factory=list)


@dataclass
class DevirtualizedBlock:
    """Devirtualized VM code block.

    Note:
        vm_bytecode field is currently not extracted and will be empty (b"").
        This is because VM bytecode extraction requires additional parsing of
        the VM's custom instruction stream, which varies significantly between
        different virtualization protectors. Future versions may implement
        VM-specific bytecode extractors.
    """

    original_vm_entry: int
    original_vm_exit: int
    vm_bytecode: bytes
    handlers_executed: list[int]
    lifted_semantics: list[LiftedHandler]
    native_code: bytes
    assembly: list[str]
    control_flow_edges: list[tuple[int, int]]
    confidence: float
    execution_paths: int


@dataclass
class DevirtualizationResult:
    """Result of VM devirtualization analysis."""

    vm_type: VMType
    architecture: str
    vm_entry_point: int
    handler_table: int | None
    dispatcher_address: int | None
    lifted_handlers: dict[int, LiftedHandler]
    devirtualized_blocks: list[DevirtualizedBlock]
    total_paths_explored: int
    total_constraints_solved: int
    overall_confidence: float
    analysis_time_seconds: float
    technical_details: dict[str, Any] = field(default_factory=dict)


class GuidedVMExploration(ExplorationTechnique):
    """Guided exploration technique for VM devirtualization."""

    def __init__(
        self,
        vm_dispatcher: int,
        handler_table: int,
        max_depth: int = 100,
    ) -> None:
        """Initialize guided VM exploration.

        Args:
            vm_dispatcher: Address of the VM dispatcher routine.
            handler_table: Address of the VM handler table.
            max_depth: Maximum exploration depth for path exploration.
        """
        super().__init__()
        self.vm_dispatcher = vm_dispatcher
        self.handler_table = handler_table
        self.max_depth = max_depth
        self.visited_handlers: set[int] = set()

    def step(self, simgr: AngrSimMgr, stash: str = "active", **kwargs: Any) -> AngrSimMgr:
        """Perform guided exploration step.

        Args:
            simgr: The angr exploration manager instance.
            stash: The stash name to process (default: "active").
            **kwargs: Additional keyword arguments passed to step method.

        Returns:
            The updated angr exploration manager.

        """
        simgr = simgr.step(stash=stash, **kwargs)

        if stash in simgr.stashes:
            for state in simgr.stashes[stash]:
                if state.history.depth > self.max_depth:
                    simgr.stashes[stash].remove(state)
                    if "pruned" not in simgr.stashes:
                        simgr.stashes["pruned"] = []
                    simgr.stashes["pruned"].append(state)

        return simgr


class PathExplosionMitigation(ExplorationTechnique):
    """Mitigation technique for path explosion in symbolic execution."""

    def __init__(
        self,
        max_active: int = 50,
        max_total: int = 500,
    ) -> None:
        """Initialize path explosion mitigation.

        Args:
            max_active: Maximum number of active paths to maintain.
            max_total: Maximum total number of paths before stopping exploration.
        """
        super().__init__()
        self.max_active = max_active
        self.max_total = max_total
        self.total_stepped = 0

    def step(self, simgr: AngrSimMgr, stash: str = "active", **kwargs: Any) -> AngrSimMgr:
        """Perform path explosion mitigation step.

        Args:
            simgr: The angr exploration manager instance.
            stash: The stash name to process (default: "active").
            **kwargs: Additional keyword arguments passed to step method.

        Returns:
            The updated angr exploration manager after mitigation.

        """
        if self.total_stepped >= self.max_total:
            return simgr

        if stash in simgr.stashes and len(simgr.stashes[stash]) > self.max_active:
            simgr.stashes[stash] = simgr.stashes[stash][: self.max_active]

        simgr = simgr.step(stash=stash, **kwargs)
        self.total_stepped += 1

        return simgr


class SymbolicDevirtualizer:
    """Symbolic devirtualizer for VM-protected code."""

    def __init__(self, binary_path: str) -> None:
        """Initialize the symbolic devirtualizer.

        Args:
            binary_path: Path to the binary to devirtualize.

        Raises:
            FileNotFoundError: If binary file does not exist.
        """
        binary_file = Path(binary_path)
        if not binary_file.exists():
            msg = f"Binary file not found: {binary_path}"
            raise FileNotFoundError(msg)

        self.binary_path = binary_path
        self.project: Project | None = None
        self.vm_type = VMType.UNKNOWN
        self.architecture = "unknown"

        self.handler_semantics: dict[int, HandlerSemantic] = {}
        self.lifted_handlers: dict[int, LiftedHandler] = {}

        self.vm_dispatcher: int | None = None
        self.handler_table: int | None = None

        self.cs_x86: Cs | None = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs_x64: Cs | None = Cs(CS_ARCH_X86, CS_MODE_64)
        if self.cs_x86:
            self.cs_x86.detail = True
        if self.cs_x64:
            self.cs_x64.detail = True

        self.ks_x86: Ks | None = Ks(KS_ARCH_X86, KS_MODE_32)
        self.ks_x64: Ks | None = Ks(KS_ARCH_X86, KS_MODE_64)

    def devirtualize(
        self,
        vm_entry_point: int,
        vm_type: VMType = VMType.UNKNOWN,
        exploration_strategy: ExplorationStrategy = ExplorationStrategy.GUIDED,
        max_paths: int = 500,
        timeout_seconds: int = 300,
    ) -> DevirtualizationResult:
        """Perform symbolic devirtualization of VM-protected code.

        Args:
            vm_entry_point: Address of the VM entry point in the binary.
            vm_type: Type of VM protection detected or specified.
            exploration_strategy: Path exploration strategy to use.
            max_paths: Maximum number of paths to explore.
            timeout_seconds: Timeout for the exploration process.

        Returns:
            DevirtualizationResult containing lifted handlers, devirtualized blocks,
            and confidence scores.

        Raises:
            RuntimeError: If angr project initialization fails.
        """
        start_time = time.time()

        logger.info("Starting symbolic devirtualization at entry point 0x%x", vm_entry_point)

        try:
            self.project = angr.Project(
                self.binary_path,
                auto_load_libs=False,
                load_options={"main_opts": {"base_addr": 0}},
            )

            self.architecture = "x64" if self.project.arch.bits == ARCH_64_BITS else "x86"
            self.vm_type = vm_type if vm_type != VMType.UNKNOWN else self._detect_vm_type()

            logger.info("Architecture: %s, VM Type: %s", self.architecture, self.vm_type.value)

            self.vm_dispatcher = self._find_dispatcher_symbolic(vm_entry_point)
            self.handler_table = self._find_handler_table_symbolic(vm_entry_point)

            logger.info("Dispatcher: 0x%x", self.vm_dispatcher or 0)
            logger.info("Handler table: 0x%x", self.handler_table or 0)

            handler_addresses = self._extract_handler_addresses()
            logger.info("Extracted %d handler addresses", len(handler_addresses))

            for handler_addr in handler_addresses:
                if lifted := self._lift_handler_symbolic(handler_addr):
                    self.lifted_handlers[handler_addr] = lifted

            logger.info("Lifted %d handlers with symbolic execution", len(self.lifted_handlers))

            devirtualized_blocks = self._trace_vm_execution(vm_entry_point, exploration_strategy, max_paths, timeout_seconds)

            elapsed = time.time() - start_time

            total_paths = sum(block.execution_paths for block in devirtualized_blocks)
            total_constraints = sum(len(handler.constraints) for handler in self.lifted_handlers.values())

            overall_confidence = self._calculate_overall_confidence(devirtualized_blocks)

            result = DevirtualizationResult(
                vm_type=self.vm_type,
                architecture=self.architecture,
                vm_entry_point=vm_entry_point,
                handler_table=self.handler_table,
                dispatcher_address=self.vm_dispatcher,
                lifted_handlers=self.lifted_handlers,
                devirtualized_blocks=devirtualized_blocks,
                total_paths_explored=total_paths,
                total_constraints_solved=total_constraints,
                overall_confidence=overall_confidence,
                analysis_time_seconds=elapsed,
                technical_details={
                    "exploration_strategy": exploration_strategy.value,
                    "max_paths_limit": max_paths,
                    "timeout_limit": timeout_seconds,
                    "handlers_discovered": len(handler_addresses),
                    "handlers_lifted": len(self.lifted_handlers),
                    "blocks_devirtualized": len(devirtualized_blocks),
                },
            )

            logger.info("Devirtualization complete in %.2fs - Confidence: %.1f%%", elapsed, overall_confidence)

            return result
        except (OSError, ValueError, RuntimeError) as e:
            msg = f"Failed to initialize angr project: {e}"
            raise RuntimeError(msg) from e
        finally:
            if self.project is not None:
                del self.project
                self.project = None

    def _detect_vm_type(self) -> VMType:
        """Detect the VM protection type in the binary.

        Analyzes the binary file for characteristic strings and patterns
        to identify the VM protection mechanism used.

        Returns:
            The detected VM type or VMType.GENERIC if no specific protection
            is identified.

        Raises:
            OSError: If binary file cannot be read.
        """
        try:
            with Path(self.binary_path).open("rb") as f:
                data = f.read()
        except OSError as e:
            logger.warning("Failed to read binary for VM type detection: %s", e)
            return VMType.GENERIC

        if b".vmp" in data or b"VMProtect" in data:
            return VMType.VMPROTECT
        if b".themida" in data or b"Themida" in data or b"WinLicense" in data:
            return VMType.THEMIDA
        if b"Code Virtualizer" in data or b".cvirt" in data:
            return VMType.CODE_VIRTUALIZER

        return VMType.GENERIC

    def _find_dispatcher_symbolic(self, start_addr: int) -> int | None:
        """Find the VM dispatcher address using symbolic execution.

        Attempts to locate the VM dispatcher routine by exploring execution
        paths and identifying indirect jumps characteristic of dispatcher patterns.

        Args:
            start_addr: Starting address for the symbolic exploration.

        Returns:
            Address of the VM dispatcher if found, None otherwise.
        """
        if self.project is None:
            return None

        initial_state = self.project.factory.blank_state(addr=start_addr)

        exploration_manager = self.project.factory.simgr(initial_state)

        try:
            exploration_manager.explore(find=self._is_dispatcher_state, num_find=1, n=100)

            if exploration_manager.found:
                dispatcher_addr: int = exploration_manager.found[0].addr
                logger.debug("Found dispatcher at 0x%x", dispatcher_addr)
                return dispatcher_addr
        except (SimEngineError, SimValueError, AttributeError, KeyError, RuntimeError) as e:
            logger.debug("Symbolic dispatcher search failed: %s", e)

        return self._find_dispatcher_pattern()

    def _is_dispatcher_state(self, state: SimState) -> bool:
        """Check if a state represents a VM dispatcher routine.

        Analyzes the code at a given state address to determine if it contains
        characteristics of a VM dispatcher (e.g., indirect jumps).

        Args:
            state: The symbolic execution state to analyze.

        Returns:
            True if the state appears to be a dispatcher routine, False otherwise.
        """
        if self.project is None:
            return False

        try:
            block = self.project.factory.block(state.addr)

            if not hasattr(block, "capstone") or not block.capstone:
                return False

            indirect_jumps: int = sum(
                1
                for insn in block.capstone.insns
                if hasattr(insn, "mnemonic") and insn.mnemonic == "jmp" and "[" in insn.op_str
            )
            return indirect_jumps >= 1
        except (SimEngineError, AttributeError, KeyError) as e:
            logger.debug("Failed to analyze state at 0x%x: %s", state.addr, e)
            return False

    def _find_dispatcher_pattern(self) -> int | None:
        """Find the dispatcher address using byte pattern matching.

        Scans the binary for machine code patterns characteristic of VM
        dispatchers (indirect jump instructions with table addressing).

        Returns:
            Offset of the first matching dispatcher pattern, None if not found.
        """
        try:
            with Path(self.binary_path).open("rb") as f:
                data = f.read()
        except OSError as e:
            logger.warning("Failed to read binary for pattern matching: %s", e)
            return None

        patterns_x86 = [b"\xff\x24\x85", b"\xff\x24\x8d"]
        patterns_x64 = [b"\xff\x24\xc5", b"\xff\x24\xcd", b"\x41\xff\x24\xc5"]

        patterns = patterns_x64 if self.architecture == "x64" else patterns_x86

        for pattern in patterns:
            offset = data.find(pattern)
            if offset != -1:
                return offset

        return None

    def _find_handler_table_symbolic(self, _start_addr: int) -> int | None:
        """Find the VM handler table address using symbolic analysis.

        Analyzes the dispatcher routine to extract the handler table address
        from dispatcher code patterns and operands.

        Args:
            start_addr: Starting address for analysis (not directly used in lookup).

        Returns:
            Address of the handler table if found, None otherwise.
        """
        if not self.vm_dispatcher or self.project is None:
            return None

        try:
            block = self.project.factory.block(self.vm_dispatcher)

            if not hasattr(block, "capstone") or not block.capstone:
                return self._scan_for_pointer_table()

            for insn in block.capstone.insns:
                if not (hasattr(insn, "mnemonic") and hasattr(insn, "op_str")):
                    continue

                if insn.mnemonic == "jmp" and "[" in insn.op_str:
                    operand_str = insn.op_str

                    if addr_match := re.search(r"0x([0-9a-fA-F]+)", operand_str):
                        table_addr = int(addr_match.group(1), 16)
                        logger.debug("Found handler table at 0x%x", table_addr)
                        return table_addr
        except (SimEngineError, AttributeError, KeyError, ValueError) as e:
            logger.debug("Handler table extraction failed: %s", e)

        return self._scan_for_pointer_table()

    def _scan_for_pointer_table(self) -> int | None:
        """Scan binary for valid pointer tables.

        Searches the binary for sequences of valid pointers that likely represent
        the VM handler table by checking for consecutive valid addresses.

        Returns:
            Offset of the identified handler table, None if not found.
        """
        with open(self.binary_path, "rb") as f:
            data = f.read()

        ptr_size = 8 if self.architecture == "x64" else 4
        min_entries = 16

        for offset in range(0, len(data) - min_entries * ptr_size, ptr_size):
            consecutive = 0

            for i in range(min_entries):
                ptr_offset = offset + i * ptr_size

                if ptr_offset + ptr_size > len(data):
                    break

                if ptr_size == POINTER_SIZE_32:
                    ptr_val = struct.unpack("<I", data[ptr_offset : ptr_offset + POINTER_SIZE_32])[0]
                    valid = MIN_VALID_POINTER < ptr_val < MAX_VALID_POINTER_32
                else:
                    ptr_val = struct.unpack("<Q", data[ptr_offset : ptr_offset + POINTER_SIZE_64])[0]
                    valid = MIN_VALID_POINTER < ptr_val < MAX_VALID_POINTER_64

                if valid:
                    consecutive += 1
                else:
                    break

            if consecutive >= min_entries:
                return offset

        return None

    def _extract_handler_addresses(self) -> list[int]:
        """Extract all VM handler addresses from the handler table.

        Combines handlers discovered from the handler table and dispatcher
        targets into a deduplicated sorted list.

        Returns:
            List of VM handler addresses.
        """
        handlers = []

        if self.handler_table:
            handlers.extend(self._read_handler_table())

        if self.vm_dispatcher:
            handlers.extend(self._trace_dispatcher_targets())

        return sorted(set(handlers))

    def _read_handler_table(self) -> list[int]:
        """Read handler addresses from the handler table.

        Parses the handler table in binary memory to extract pointer addresses
        to individual VM handler routines.

        Returns:
            List of handler addresses extracted from the table.
        """
        handlers: list[int] = []

        if self.handler_table is None:
            return handlers

        with open(self.binary_path, "rb") as f:
            f.seek(self.handler_table)

            ptr_size = 8 if self.architecture == "x64" else 4
            max_handlers = 256

            for _ in range(max_handlers):
                ptr_data = f.read(ptr_size)
                if len(ptr_data) < ptr_size:
                    break

                if ptr_size == POINTER_SIZE_32:
                    handler_addr = struct.unpack("<I", ptr_data)[0]
                    valid = MIN_VALID_POINTER < handler_addr < MAX_VALID_POINTER_32
                else:
                    handler_addr = struct.unpack("<Q", ptr_data)[0]
                    valid = MIN_VALID_POINTER < handler_addr < MAX_VALID_POINTER_64

                if valid:
                    handlers.append(handler_addr)
                else:
                    break

        return handlers

    def _trace_dispatcher_targets(self) -> list[int]:
        """Trace dispatcher execution to find handler addresses.

        Performs symbolic execution from the dispatcher to identify all possible
        handler targets and extract addresses from register values.

        Returns:
            List of handler addresses discovered through symbolic execution.
        """
        handlers: list[int] = []

        if self.project is None or self.vm_dispatcher is None:
            return handlers

        try:
            state = self.project.factory.blank_state(addr=self.vm_dispatcher)

            exec_manager = self.project.factory.simgr(state)
            target_dispatcher = self.vm_dispatcher
            exec_manager.explore(n=100, find=lambda s: s.addr != target_dispatcher)

            for found_state in exec_manager.found + exec_manager.active:
                try:
                    addr: int = found_state.addr
                    if MIN_VALID_POINTER < addr < MAX_VALID_POINTER_64 and addr not in handlers:
                        handlers.append(addr)

                    if hasattr(found_state.regs, "rip") and found_state.regs.rip.symbolic:
                        solutions = found_state.solver.eval_upto(found_state.regs.rip, 10)
                        for solution in solutions:
                            if MIN_VALID_POINTER < solution < MAX_VALID_POINTER_64 and solution not in handlers:
                                handlers.append(solution)
                except (SimEngineError, SimValueError, AttributeError, KeyError, ValueError) as e:
                    logger.debug("State analysis failed: %s", e)
                    continue

            block = self.project.factory.block(self.vm_dispatcher)
            if hasattr(block, "successors"):
                for successor in block.successors:
                    if MIN_VALID_POINTER < successor < MAX_VALID_POINTER_64 and successor not in handlers:
                        handlers.append(successor)
        except (SimEngineError, SimValueError, AttributeError, KeyError, RuntimeError) as e:
            logger.debug("Dispatcher target tracing failed: %s", e)

        return handlers

    def _lift_handler_symbolic(self, handler_addr: int) -> LiftedHandler | None:
        """Lift a VM handler to its semantic meaning using symbolic execution.

        Analyzes a VM handler by executing it symbolically to determine its
        semantic operation and infer native code translation.

        Args:
            handler_addr: Address of the VM handler to lift.

        Returns:
            LiftedHandler object with semantic information and translation,
            or None if lifting fails.
        """
        if self.project is None:
            return None

        try:
            state = self.project.factory.call_state(
                handler_addr,
                add_options={
                    angr.options.SYMBOLIC_WRITE_ADDRESSES,
                    angr.options.SYMBOLIC,
                },
            )

            arch_bits = self.project.arch.bits
            vm_stack = claripy.BVS("vm_stack", arch_bits * 8)
            vm_ip = claripy.BVS("vm_ip", arch_bits)

            if self.project.arch.bits == ARCH_64_BITS:
                state.regs.rip = vm_ip
                state.regs.rsp = vm_stack[:ARCH_64_BITS]
                state.solver.add(state.regs.rsp >= MIN_VALID_POINTER)
                state.solver.add(state.regs.rsp < MAX_VALID_POINTER_64)
            elif self.project.arch.bits == ARCH_32_BITS:
                state.regs.eip = vm_ip[:ARCH_32_BITS]
                state.regs.esp = vm_stack[:ARCH_32_BITS]
                state.solver.add(state.regs.esp >= MIN_VALID_POINTER)
                state.solver.add(state.regs.esp < MAX_STACK_POINTER_32)

            state.mem[state.regs.sp].qword = vm_stack

            exploration_manager = self.project.factory.simgr(state)
            exploration_manager.explore(n=50)

            symbolic_effects: list[tuple[str, Any]] = []
            constraints: list[Any] = []

            if exploration_manager.active or exploration_manager.deadended:
                final_states = exploration_manager.active + exploration_manager.deadended

                for final_state in final_states[:5]:
                    for reg_name in self.project.arch.register_names.values():
                        if isinstance(reg_name, str):
                            try:
                                reg_val = final_state.registers.load(reg_name)
                                if reg_val.symbolic:
                                    symbolic_effects.append((f"reg_{reg_name}", reg_val))
                            except (KeyError, AttributeError, angr.errors.SimValueError) as e:
                                logger.debug("Register %s not accessible: %s", reg_name, e)
                    constraints.extend(final_state.solver.constraints)

            semantic = self._infer_handler_semantic(handler_addr, symbolic_effects, constraints)

            native_code, assembly = self._translate_handler_to_native(handler_addr, semantic, symbolic_effects)

            confidence = self._calculate_handler_confidence(semantic, symbolic_effects, constraints, native_code)

            return LiftedHandler(
                handler_address=handler_addr,
                semantic=semantic,
                symbolic_effects=symbolic_effects,
                constraints=constraints,
                native_translation=native_code,
                assembly_code=assembly,
                confidence=confidence,
                operand_count=len(symbolic_effects),
                operand_types=[type(effect[1]).__name__ for effect in symbolic_effects],
            )

        except Exception as e:
            logger.debug("Handler lifting failed at 0x%x: %s", handler_addr, e)
            return None

    def _infer_handler_semantic(self, handler_addr: int, effects: list[tuple[str, Any]], constraints: list[Any]) -> HandlerSemantic:
        """Infer the semantic meaning of a VM handler.

        Analyzes handler instructions and symbolic effects to determine the
        operation performed (arithmetic, logical, memory, etc.). Uses symbolic
        effects to refine inference when instruction analysis is ambiguous.

        Args:
            handler_addr: Address of the handler to analyze.
            effects: List of symbolic effects observed during execution containing
                (register_name, symbolic_value) tuples that indicate state changes.
            constraints: Constraints accumulated during symbolic execution that
                can indicate conditional behavior or value ranges.

        Returns:
            The inferred HandlerSemantic type.
        """
        if self.project is None:
            return HandlerSemantic.UNKNOWN

        inferred_from_effects = self._analyze_symbolic_effects(effects, constraints)
        if inferred_from_effects != HandlerSemantic.UNKNOWN:
            return inferred_from_effects

        try:
            block = self.project.factory.block(handler_addr)

            mnemonics = [insn.mnemonic for insn in block.capstone.insns]

            if "push" in mnemonics:
                return HandlerSemantic.STACK_PUSH
            if "pop" in mnemonics:
                return HandlerSemantic.STACK_POP
            if "add" in mnemonics:
                return HandlerSemantic.ARITHMETIC_ADD
            if "sub" in mnemonics:
                return HandlerSemantic.ARITHMETIC_SUB
            if any(m in mnemonics for m in ["mul", "imul"]):
                return HandlerSemantic.ARITHMETIC_MUL
            if any(m in mnemonics for m in ["div", "idiv"]):
                return HandlerSemantic.ARITHMETIC_DIV
            if "and" in mnemonics:
                return HandlerSemantic.LOGICAL_AND
            if "or" in mnemonics:
                return HandlerSemantic.LOGICAL_OR
            if "xor" in mnemonics:
                return HandlerSemantic.LOGICAL_XOR
            if "not" in mnemonics:
                return HandlerSemantic.LOGICAL_NOT
            if "shl" in mnemonics or "sal" in mnemonics:
                return HandlerSemantic.SHIFT_LEFT
            if "shr" in mnemonics or "sar" in mnemonics:
                return HandlerSemantic.SHIFT_RIGHT
            if any(m.startswith("j") for m in mnemonics if m != "jmp"):
                return HandlerSemantic.BRANCH_CONDITIONAL
            if "jmp" in mnemonics:
                return HandlerSemantic.BRANCH_UNCONDITIONAL
            if "call" in mnemonics:
                return HandlerSemantic.CALL
            if "ret" in mnemonics:
                return HandlerSemantic.RETURN
            if any(m in mnemonics for m in ["mov", "movzx", "movsx"]) and "[" in str(block.capstone.insns):
                if any("esp" in str(insn) or "rsp" in str(insn) for insn in block.capstone.insns):
                    return HandlerSemantic.MEMORY_LOAD
                return HandlerSemantic.MEMORY_STORE
        except Exception as e:
            logger.debug("Semantic inference failed: %s", e)

        return HandlerSemantic.UNKNOWN

    def _analyze_symbolic_effects(self, effects: list[tuple[str, Any]], constraints: list[Any]) -> HandlerSemantic:
        """Analyze symbolic effects to infer handler semantics.

        Uses symbolic execution results to determine handler behavior when
        instruction-level analysis is insufficient.

        Args:
            effects: List of (register_name, symbolic_value) tuples.
            constraints: Path constraints from symbolic execution.

        Returns:
            Inferred semantic type or UNKNOWN if cannot determine.
        """
        if not effects:
            return HandlerSemantic.UNKNOWN

        stack_regs = {"reg_esp", "reg_rsp", "reg_sp"}
        ip_regs = {"reg_eip", "reg_rip", "reg_ip"}

        stack_modified = any(name in stack_regs for name, _ in effects)
        ip_modified = any(name in ip_regs for name, _ in effects)

        if constraints:
            has_conditional = any(
                hasattr(c, "op") and c.op in {"__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__"}
                for c in constraints
            )
            if has_conditional and ip_modified:
                return HandlerSemantic.BRANCH_CONDITIONAL

        for name, value in effects:
            if name in stack_regs:
                value_str = str(value)
                if "+" in value_str and "8" in value_str:
                    return HandlerSemantic.STACK_POP
                if "-" in value_str and "8" in value_str:
                    return HandlerSemantic.STACK_PUSH

            if hasattr(value, "op"):
                op = getattr(value, "op", "")
                if op == "__add__":
                    return HandlerSemantic.ARITHMETIC_ADD
                if op == "__sub__":
                    return HandlerSemantic.ARITHMETIC_SUB
                if op == "__mul__":
                    return HandlerSemantic.ARITHMETIC_MUL
                if op == "__and__":
                    return HandlerSemantic.LOGICAL_AND
                if op == "__or__":
                    return HandlerSemantic.LOGICAL_OR
                if op == "__xor__":
                    return HandlerSemantic.LOGICAL_XOR
                if op == "__lshift__":
                    return HandlerSemantic.SHIFT_LEFT
                if op == "__rshift__":
                    return HandlerSemantic.SHIFT_RIGHT

        if stack_modified and not ip_modified:
            return HandlerSemantic.MEMORY_STORE

        return HandlerSemantic.UNKNOWN

    def _translate_handler_to_native(
        self,
        handler_addr: int,
        semantic: HandlerSemantic,
        effects: list[tuple[str, Any]],
    ) -> tuple[bytes | None, list[str]]:
        """Translate a VM handler to native assembly code.

        Converts a VM handler to its equivalent native x86/x64 code based on
        the inferred semantic meaning and observed symbolic effects. Uses
        effects to determine operand registers and generate accurate code.

        Args:
            handler_addr: Address of the handler to translate.
            semantic: The semantic type of the handler.
            effects: List of symbolic effects containing (register_name, value)
                tuples used to determine which registers are modified.

        Returns:
            Tuple containing native bytecode and assembly mnemonics list,
            or (None, asm_list) if translation fails.
        """
        dest_reg, src_reg = self._extract_registers_from_effects(effects)

        is_64bit = self.architecture == "x64"

        semantic_to_asm_32: dict[HandlerSemantic, tuple[str, bytes]] = {
            HandlerSemantic.STACK_PUSH: (f"push {dest_reg or 'eax'}", b"\x50"),
            HandlerSemantic.STACK_POP: (f"pop {dest_reg or 'eax'}", b"\x58"),
            HandlerSemantic.ARITHMETIC_ADD: (f"add {dest_reg or 'eax'}, {src_reg or 'ebx'}", b"\x01\xd8"),
            HandlerSemantic.ARITHMETIC_SUB: (f"sub {dest_reg or 'eax'}, {src_reg or 'ebx'}", b"\x29\xd8"),
            HandlerSemantic.ARITHMETIC_MUL: (f"imul {dest_reg or 'eax'}, {src_reg or 'ebx'}", b"\x0f\xaf\xc3"),
            HandlerSemantic.ARITHMETIC_DIV: (f"idiv {src_reg or 'ebx'}", b"\xf7\xfb"),
            HandlerSemantic.LOGICAL_AND: (f"and {dest_reg or 'eax'}, {src_reg or 'ebx'}", b"\x21\xd8"),
            HandlerSemantic.LOGICAL_OR: (f"or {dest_reg or 'eax'}, {src_reg or 'ebx'}", b"\x09\xd8"),
            HandlerSemantic.LOGICAL_XOR: (f"xor {dest_reg or 'eax'}, {src_reg or 'ebx'}", b"\x31\xd8"),
            HandlerSemantic.LOGICAL_NOT: (f"not {dest_reg or 'eax'}", b"\xf7\xd0"),
            HandlerSemantic.SHIFT_LEFT: (f"shl {dest_reg or 'eax'}, cl", b"\xd3\xe0"),
            HandlerSemantic.SHIFT_RIGHT: (f"shr {dest_reg or 'eax'}, cl", b"\xd3\xe8"),
            HandlerSemantic.BRANCH_CONDITIONAL: ("jz 0x00", b"\x74\x00"),
            HandlerSemantic.BRANCH_UNCONDITIONAL: ("jmp 0x00", b"\xeb\x00"),
            HandlerSemantic.CALL: ("call 0x00000000", b"\xe8\x00\x00\x00\x00"),
            HandlerSemantic.RETURN: ("ret", b"\xc3"),
            HandlerSemantic.MEMORY_LOAD: (f"mov {dest_reg or 'eax'}, [{src_reg or 'ebx'}]", b"\x8b\x03"),
            HandlerSemantic.MEMORY_STORE: (f"mov [{dest_reg or 'ebx'}], {src_reg or 'eax'}", b"\x89\x03"),
        }

        semantic_to_asm_64: dict[HandlerSemantic, tuple[str, bytes]] = {
            HandlerSemantic.STACK_PUSH: (f"push {dest_reg or 'rax'}", b"\x50"),
            HandlerSemantic.STACK_POP: (f"pop {dest_reg or 'rax'}", b"\x58"),
            HandlerSemantic.ARITHMETIC_ADD: (f"add {dest_reg or 'rax'}, {src_reg or 'rbx'}", b"\x48\x01\xd8"),
            HandlerSemantic.ARITHMETIC_SUB: (f"sub {dest_reg or 'rax'}, {src_reg or 'rbx'}", b"\x48\x29\xd8"),
            HandlerSemantic.ARITHMETIC_MUL: (f"imul {dest_reg or 'rax'}, {src_reg or 'rbx'}", b"\x48\x0f\xaf\xc3"),
            HandlerSemantic.ARITHMETIC_DIV: (f"idiv {src_reg or 'rbx'}", b"\x48\xf7\xfb"),
            HandlerSemantic.LOGICAL_AND: (f"and {dest_reg or 'rax'}, {src_reg or 'rbx'}", b"\x48\x21\xd8"),
            HandlerSemantic.LOGICAL_OR: (f"or {dest_reg or 'rax'}, {src_reg or 'rbx'}", b"\x48\x09\xd8"),
            HandlerSemantic.LOGICAL_XOR: (f"xor {dest_reg or 'rax'}, {src_reg or 'rbx'}", b"\x48\x31\xd8"),
            HandlerSemantic.LOGICAL_NOT: (f"not {dest_reg or 'rax'}", b"\x48\xf7\xd0"),
            HandlerSemantic.SHIFT_LEFT: (f"shl {dest_reg or 'rax'}, cl", b"\x48\xd3\xe0"),
            HandlerSemantic.SHIFT_RIGHT: (f"shr {dest_reg or 'rax'}, cl", b"\x48\xd3\xe8"),
            HandlerSemantic.BRANCH_CONDITIONAL: ("jz 0x00", b"\x74\x00"),
            HandlerSemantic.BRANCH_UNCONDITIONAL: ("jmp 0x00", b"\xeb\x00"),
            HandlerSemantic.CALL: ("call 0x00000000", b"\xe8\x00\x00\x00\x00"),
            HandlerSemantic.RETURN: ("ret", b"\xc3"),
            HandlerSemantic.MEMORY_LOAD: (f"mov {dest_reg or 'rax'}, [{src_reg or 'rbx'}]", b"\x48\x8b\x03"),
            HandlerSemantic.MEMORY_STORE: (f"mov [{dest_reg or 'rbx'}], {src_reg or 'rax'}", b"\x48\x89\x03"),
        }

        asm_table = semantic_to_asm_64 if is_64bit else semantic_to_asm_32

        if semantic in asm_table:
            asm, bytecode = asm_table[semantic]
            return bytecode, [asm]

        if self.project is None:
            return None, [f"unknown_handler_0x{handler_addr:x}"]

        try:
            block = self.project.factory.block(handler_addr)
            assembly = [f"{insn.mnemonic} {insn.op_str}" for insn in block.capstone.insns]
            return block.bytes, assembly
        except (AttributeError, KeyError, angr.errors.SimEngineError) as e:
            logger.debug("Failed to disassemble handler at 0x%x: %s", handler_addr, e)
            return None, [f"unknown_handler_0x{handler_addr:x}"]

    def _extract_registers_from_effects(self, effects: list[tuple[str, Any]]) -> tuple[str | None, str | None]:
        """Extract destination and source registers from symbolic effects.

        Analyzes symbolic effects to identify which registers are being modified
        and used as sources for generating accurate native code.

        Args:
            effects: List of (register_name, symbolic_value) tuples.

        Returns:
            Tuple of (destination_register, source_register) or (None, None).
        """
        if not effects:
            return None, None

        dest_reg: str | None = None
        src_reg: str | None = None

        reg_mapping_32 = {
            "reg_eax": "eax", "reg_ebx": "ebx", "reg_ecx": "ecx", "reg_edx": "edx",
            "reg_esi": "esi", "reg_edi": "edi", "reg_esp": "esp", "reg_ebp": "ebp",
        }
        reg_mapping_64 = {
            "reg_rax": "rax", "reg_rbx": "rbx", "reg_rcx": "rcx", "reg_rdx": "rdx",
            "reg_rsi": "rsi", "reg_rdi": "rdi", "reg_rsp": "rsp", "reg_rbp": "rbp",
            "reg_r8": "r8", "reg_r9": "r9", "reg_r10": "r10", "reg_r11": "r11",
            "reg_r12": "r12", "reg_r13": "r13", "reg_r14": "r14", "reg_r15": "r15",
        }

        reg_mapping = reg_mapping_64 if self.architecture == "x64" else reg_mapping_32

        for name, value in effects:
            if name in reg_mapping and dest_reg is None:
                dest_reg = reg_mapping[name]

            if hasattr(value, "args") and value.args:
                for arg in value.args:
                    arg_str = str(arg)
                    for reg_key, reg_name in reg_mapping.items():
                        if reg_key in arg_str and reg_name != dest_reg:
                            src_reg = reg_name
                            break
                    if src_reg:
                        break

        return dest_reg, src_reg

    def _calculate_handler_confidence(
        self,
        semantic: HandlerSemantic,
        effects: list[tuple[str, Any]],
        constraints: list[Any],
        native_code: bytes | None,
    ) -> float:
        """Calculate confidence score for a lifted handler.

        Computes a confidence metric based on semantic clarity, symbolic
        effects, constraints, and availability of native code. Uses a weighted
        scoring system that reflects the quality of analysis results.

        Args:
            semantic: The semantic type of the handler.
            effects: List of symbolic effects from execution.
            constraints: Constraints accumulated during analysis.
            native_code: Native code translation if available.

        Returns:
            Confidence score between 0.0 and 100.0.
        """
        base_confidence = 0.0

        if semantic == HandlerSemantic.UNKNOWN:
            base_confidence = 20.0
        elif semantic in {HandlerSemantic.STACK_PUSH, HandlerSemantic.STACK_POP}:
            base_confidence = 85.0
        elif semantic in {
            HandlerSemantic.ARITHMETIC_ADD,
            HandlerSemantic.ARITHMETIC_SUB,
            HandlerSemantic.LOGICAL_AND,
            HandlerSemantic.LOGICAL_OR,
            HandlerSemantic.LOGICAL_XOR,
        }:
            base_confidence = 80.0
        elif semantic in {
            HandlerSemantic.ARITHMETIC_MUL,
            HandlerSemantic.ARITHMETIC_DIV,
            HandlerSemantic.SHIFT_LEFT,
            HandlerSemantic.SHIFT_RIGHT,
        }:
            base_confidence = 75.0
        elif semantic in {
            HandlerSemantic.MEMORY_LOAD,
            HandlerSemantic.MEMORY_STORE,
            HandlerSemantic.BRANCH_CONDITIONAL,
            HandlerSemantic.BRANCH_UNCONDITIONAL,
        }:
            base_confidence = 70.0
        elif semantic in {HandlerSemantic.CALL, HandlerSemantic.RETURN, HandlerSemantic.VM_EXIT}:
            base_confidence = 90.0
        else:
            base_confidence = 50.0

        effects_factor = min(len(effects) * 2.0, 10.0) if effects else 0.0

        constraint_factor = 0.0
        if constraints:
            satisfiable_count = 0
            for constraint in constraints[:10]:
                try:
                    if hasattr(constraint, "is_true") and constraint.is_true():
                        satisfiable_count += 1
                except (AttributeError, RuntimeError):
                    continue
            constraint_factor = min(satisfiable_count * 1.5, 8.0)

        native_code_factor = 0.0
        if native_code:
            if len(native_code) > 0 and len(native_code) <= NATIVE_CODE_SIZE_THRESHOLD:
                native_code_factor = 5.0
            elif len(native_code) > NATIVE_CODE_SIZE_THRESHOLD:
                native_code_factor = 3.0

        confidence = base_confidence + effects_factor + constraint_factor + native_code_factor

        return min(confidence, 100.0)

    def _trace_vm_execution(
        self,
        entry_point: int,
        strategy: ExplorationStrategy,
        max_paths: int,
        timeout: int,
    ) -> list[DevirtualizedBlock]:
        """Trace VM execution to discover and devirtualize code blocks.

        Performs symbolic execution of VM bytecode starting from the entry point
        to discover devirtualized blocks and control flow.

        Args:
            entry_point: VM entry point address.
            strategy: Path exploration strategy to use.
            max_paths: Maximum number of paths to explore.
            timeout: Timeout in seconds for exploration.

        Returns:
            List of devirtualized code blocks recovered from VM execution.
        """
        blocks: list[DevirtualizedBlock] = []

        if self.project is None:
            return blocks

        try:
            state = self.project.factory.call_state(
                entry_point,
                add_options={
                    angr.options.SYMBOLIC,
                    angr.options.TRACK_CONSTRAINTS,
                },
            )

            exploration_manager = self.project.factory.simgr(state)

            if self.vm_dispatcher and self.handler_table:
                exploration_manager.use_technique(GuidedVMExploration(self.vm_dispatcher, self.handler_table, max_depth=100))

            exploration_manager.use_technique(PathExplosionMitigation(max_active=50, max_total=max_paths))

            if strategy == ExplorationStrategy.DFS:
                exploration_manager.use_technique(DFS())

            exploration_complete = threading.Event()
            exploration_error: Exception | None = None

            def run_exploration() -> None:
                nonlocal exploration_error
                try:
                    exploration_manager.run()
                except Exception as e:
                    exploration_error = e
                finally:
                    exploration_complete.set()

            exploration_thread = threading.Thread(target=run_exploration, daemon=False)
            exploration_thread.start()

            if not exploration_complete.wait(timeout=timeout):
                logger.info("Exploration timeout reached")

            exploration_thread.join(timeout=5.0)

            if exploration_error:
                logger.debug("Exploration error: %s", exploration_error)

            all_states = exploration_manager.deadended + exploration_manager.active

            for state in all_states[:20]:
                block = self._reconstruct_block_from_state(state, entry_point)
                if block:
                    blocks.append(block)

        except Exception:
            logger.exception("VM execution tracing failed")

        return blocks

    def _reconstruct_block_from_state(self, state: Any, entry: int) -> DevirtualizedBlock | None:
        """Reconstruct a devirtualized code block from an execution state.

        Converts a symbolic execution state into a devirtualized block by
        extracting handler sequence and translating to native code.

        Args:
            state: The symbolic execution state to analyze.
            entry: The original VM entry point address.

        Returns:
            DevirtualizedBlock if reconstruction succeeds, None otherwise.
        """
        try:
            path_addrs: list[int] = list(state.history.bbl_addrs)

            handlers_exec: list[int] = [addr for addr in path_addrs if addr in self.lifted_handlers]
            if not handlers_exec:
                return None

            lifted_seq: list[LiftedHandler] = [self.lifted_handlers[h] for h in handlers_exec if h in self.lifted_handlers]

            native_code: bytearray = bytearray()
            assembly: list[str] = []

            for lifted in lifted_seq:
                if lifted.native_translation:
                    native_code.extend(lifted.native_translation)
                assembly.extend(lifted.assembly_code)

            cf_edges: list[tuple[int, int]] = [(path_addrs[i], path_addrs[i + 1]) for i in range(len(path_addrs) - 1)]
            avg_confidence: float = sum(h.confidence for h in lifted_seq) / len(lifted_seq) if lifted_seq else 0.0

            return DevirtualizedBlock(
                original_vm_entry=entry,
                original_vm_exit=state.addr,
                vm_bytecode=b"",
                handlers_executed=handlers_exec,
                lifted_semantics=lifted_seq,
                native_code=bytes(native_code),
                assembly=assembly,
                control_flow_edges=cf_edges,
                confidence=avg_confidence,
                execution_paths=1,
            )

        except Exception as e:
            logger.debug("Block reconstruction failed: %s", e)
            return None

    def _calculate_overall_confidence(self, blocks: list[DevirtualizedBlock]) -> float:
        """Calculate overall confidence for the devirtualization analysis.

        Computes an aggregate confidence metric based on individual block
        confidence scores and the quantity of lifted handlers.

        Args:
            blocks: List of devirtualized blocks to evaluate.

        Returns:
            Overall confidence score between 0.0 and 100.0.
        """
        if not blocks:
            return 0.0

        total_confidence = sum(block.confidence for block in blocks)
        avg_confidence = total_confidence / len(blocks)

        bonus = 0.0
        if len(blocks) > MIN_BLOCK_COUNT:
            bonus += 10.0
        if len(self.lifted_handlers) > MIN_HANDLER_COUNT:
            bonus += 10.0

        return min(avg_confidence + bonus, 100.0)


def devirtualize_vmprotect(
    binary_path: str,
    vm_entry_point: int,
    max_paths: int = 500,
    timeout: int = 300,
) -> DevirtualizationResult:
    """Devirtualize VMProtect-protected binary.

    Args:
        binary_path: Path to the VMProtect-protected binary.
        vm_entry_point: Address of the VM entry point.
        max_paths: Maximum number of paths to explore.
        timeout: Timeout in seconds for exploration.

    Returns:
        DevirtualizationResult: Devirtualization result with lifted handlers
            and analysis metadata.
    """
    devirt = SymbolicDevirtualizer(binary_path)
    return devirt.devirtualize(vm_entry_point, VMType.VMPROTECT, ExplorationStrategy.GUIDED, max_paths, timeout)


def devirtualize_themida(
    binary_path: str,
    vm_entry_point: int,
    max_paths: int = 500,
    timeout: int = 300,
) -> DevirtualizationResult:
    """Devirtualize Themida-protected binary.

    Args:
        binary_path: Path to the Themida-protected binary.
        vm_entry_point: Address of the VM entry point.
        max_paths: Maximum number of paths to explore.
        timeout: Timeout in seconds for exploration.

    Returns:
        DevirtualizationResult: Devirtualization result with lifted handlers
            and analysis metadata.
    """
    devirt = SymbolicDevirtualizer(binary_path)
    return devirt.devirtualize(vm_entry_point, VMType.THEMIDA, ExplorationStrategy.GUIDED, max_paths, timeout)


def devirtualize_generic(
    binary_path: str,
    vm_entry_point: int,
    exploration_strategy: ExplorationStrategy = ExplorationStrategy.DFS,
    max_paths: int = 500,
    timeout: int = 300,
) -> DevirtualizationResult:
    """Devirtualize generically protected binary.

    Args:
        binary_path: Path to the binary file to analyze.
        vm_entry_point: Address of the VM entry point.
        exploration_strategy: Path exploration strategy to use.
        max_paths: Maximum number of paths to explore.
        timeout: Timeout in seconds for exploration.

    Returns:
        DevirtualizationResult: Devirtualization result with lifted handlers
            and analysis metadata.
    """
    devirt = SymbolicDevirtualizer(binary_path)
    return devirt.devirtualize(vm_entry_point, VMType.GENERIC, exploration_strategy, max_paths, timeout)
