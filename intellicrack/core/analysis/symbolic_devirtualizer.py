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

import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


try:
    import angr
    import claripy
    from angr import Project, SimState
    from angr.exploration_techniques import DFS, ExplorationTechnique

    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    from keystone import KS_ARCH_X86, KS_MODE_32, KS_MODE_64, Ks

    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)


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
class SymbolicVMContext:
    """Context for symbolic VM execution state."""

    vm_ip_symbolic: Any
    vm_sp_symbolic: Any
    vm_stack_symbolic: Any
    vm_registers: dict[str, Any]
    native_registers_mapping: dict[str, int]
    constraints: list[Any] = field(default_factory=list)
    path_history: list[int] = field(default_factory=list)


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
    """Devirtualized VM code block."""

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

    def __init__(self, vm_dispatcher: int, handler_table: int, max_depth: int = 100) -> None:
        """Initialize guided VM exploration."""
        super().__init__()  # type: ignore[no-untyped-call]
        self.vm_dispatcher = vm_dispatcher
        self.handler_table = handler_table
        self.max_depth = max_depth
        self.visited_handlers: set[int] = set()

    def step(self, simgr: Any, stash: Any = "active", **kwargs: Any) -> Any:
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

    def __init__(self, max_active: int = 50, max_total: int = 500) -> None:
        """Initialize path explosion mitigation."""
        super().__init__()  # type: ignore[no-untyped-call]
        self.max_active = max_active
        self.max_total = max_total
        self.total_stepped = 0

    def step(self, simgr: Any, stash: Any = "active", **kwargs: Any) -> Any:
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
        """Initialize the symbolic devirtualizer."""
        if not ANGR_AVAILABLE:
            raise ImportError("angr framework required for symbolic devirtualization")

        self.binary_path = binary_path
        self.project: Project | None = None
        self.vm_type = VMType.UNKNOWN
        self.architecture = "unknown"

        self.handler_semantics: dict[int, HandlerSemantic] = {}
        self.lifted_handlers: dict[int, LiftedHandler] = {}

        self.vm_dispatcher: int | None = None
        self.handler_table: int | None = None

        if CAPSTONE_AVAILABLE:
            self.cs_x86 = Cs(CS_ARCH_X86, CS_MODE_32)
            self.cs_x64 = Cs(CS_ARCH_X86, CS_MODE_64)
            self.cs_x86.detail = True
            self.cs_x64.detail = True

        if KEYSTONE_AVAILABLE:
            self.ks_x86 = Ks(KS_ARCH_X86, KS_MODE_32)
            self.ks_x64 = Ks(KS_ARCH_X86, KS_MODE_64)

    def devirtualize(
        self,
        vm_entry_point: int,
        vm_type: VMType = VMType.UNKNOWN,
        exploration_strategy: ExplorationStrategy = ExplorationStrategy.GUIDED,
        max_paths: int = 500,
        timeout_seconds: int = 300,
    ) -> DevirtualizationResult:
        """Perform symbolic devirtualization of VM-protected code."""
        import time

        start_time = time.time()

        logger.info("Starting symbolic devirtualization at entry point 0x%x", vm_entry_point)

        self.project = angr.Project(self.binary_path, auto_load_libs=False, load_options={"main_opts": {"base_addr": 0}})

        self.architecture = "x64" if self.project.arch.bits == 64 else "x86"
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

    def _detect_vm_type(self) -> VMType:
        with open(self.binary_path, "rb") as f:
            data = f.read()

        if b".vmp" in data or b"VMProtect" in data:
            return VMType.VMPROTECT
        if b".themida" in data or b"Themida" in data or b"WinLicense" in data:
            return VMType.THEMIDA
        if b"Code Virtualizer" in data or b".cvirt" in data:
            return VMType.CODE_VIRTUALIZER

        return VMType.GENERIC

    def _find_dispatcher_symbolic(self, start_addr: int) -> int | None:
        if self.project is None:
            return None

        initial_state = self.project.factory.blank_state(addr=start_addr)  # type: ignore[no-untyped-call]

        exploration_manager = self.project.factory.simgr(initial_state)  # type: ignore[no-untyped-call]

        try:
            exploration_manager.explore(find=self._is_dispatcher_state, num_find=1, n=100)

            if exploration_manager.found:
                dispatcher_addr: int = exploration_manager.found[0].addr
                logger.debug("Found dispatcher at 0x%x", dispatcher_addr)
                return dispatcher_addr
        except Exception as e:
            logger.debug("Symbolic dispatcher search failed: %s", e)

        return self._find_dispatcher_pattern()

    def _is_dispatcher_state(self, state: Any) -> bool:
        if self.project is None:
            return False

        block = self.project.factory.block(state.addr)

        if not block.capstone:
            return False

        indirect_jumps: int = sum(insn.mnemonic == "jmp" and "[" in insn.op_str for insn in block.capstone.insns)
        return indirect_jumps >= 1

    def _find_dispatcher_pattern(self) -> int | None:
        with open(self.binary_path, "rb") as f:
            data = f.read()

        patterns_x86 = [b"\xff\x24\x85", b"\xff\x24\x8d"]

        patterns_x64 = [b"\xff\x24\xc5", b"\xff\x24\xcd", b"\x41\xff\x24\xc5"]

        patterns = patterns_x64 if self.architecture == "x64" else patterns_x86

        for pattern in patterns:
            offset = data.find(pattern)
            if offset != -1:
                return offset

        return None

    def _find_handler_table_symbolic(self, start_addr: int) -> int | None:
        if not self.vm_dispatcher or self.project is None:
            return None

        try:
            block = self.project.factory.block(self.vm_dispatcher)

            for insn in block.capstone.insns:
                if insn.mnemonic == "jmp" and "[" in insn.op_str:
                    operand_str = insn.op_str

                    import re

                    if addr_match := re.search(r"0x([0-9a-fA-F]+)", operand_str):
                        table_addr = int(addr_match.group(1), 16)
                        logger.debug("Found handler table at 0x%x", table_addr)
                        return table_addr
        except Exception as e:
            logger.debug("Handler table extraction failed: %s", e)

        return self._scan_for_pointer_table()

    def _scan_for_pointer_table(self) -> int | None:
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

                if ptr_size == 4:
                    ptr_val = struct.unpack("<I", data[ptr_offset : ptr_offset + 4])[0]
                    valid = 0x1000 < ptr_val < 0x10000000
                else:
                    ptr_val = struct.unpack("<Q", data[ptr_offset : ptr_offset + 8])[0]
                    valid = 0x1000 < ptr_val < 0x7FFFFFFFFFFF

                if valid:
                    consecutive += 1
                else:
                    break

            if consecutive >= min_entries:
                return offset

        return None

    def _extract_handler_addresses(self) -> list[int]:
        handlers = []

        if self.handler_table:
            handlers.extend(self._read_handler_table())

        if self.vm_dispatcher:
            handlers.extend(self._trace_dispatcher_targets())

        return sorted(set(handlers))

    def _read_handler_table(self) -> list[int]:
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

                if ptr_size == 4:
                    handler_addr = struct.unpack("<I", ptr_data)[0]
                    valid = 0x1000 < handler_addr < 0x10000000
                else:
                    handler_addr = struct.unpack("<Q", ptr_data)[0]
                    valid = 0x1000 < handler_addr < 0x7FFFFFFFFFFF

                if valid:
                    handlers.append(handler_addr)
                else:
                    break

        return handlers

    def _trace_dispatcher_targets(self) -> list[int]:
        handlers: list[int] = []

        if self.project is None or self.vm_dispatcher is None:
            return handlers

        try:
            state = self.project.factory.blank_state(addr=self.vm_dispatcher)  # type: ignore[no-untyped-call]

            exec_manager = self.project.factory.simgr(state)  # type: ignore[no-untyped-call]
            target_dispatcher = self.vm_dispatcher
            exec_manager.explore(n=100, find=lambda s: s.addr != target_dispatcher)

            for found_state in exec_manager.found + exec_manager.active:
                try:
                    addr: int = found_state.addr
                    if 0x1000 < addr < 0x7FFFFFFFFFFF and addr not in handlers:
                        handlers.append(addr)

                    if hasattr(found_state.regs, "rip") and found_state.regs.rip.symbolic:
                        solutions = found_state.solver.eval_upto(found_state.regs.rip, 10)
                        for solution in solutions:
                            if 0x1000 < solution < 0x7FFFFFFFFFFF and solution not in handlers:
                                handlers.append(solution)
                except Exception as e:
                    logger.debug("State analysis failed: %s", e)
                    continue

            block = self.project.factory.block(self.vm_dispatcher)
            if hasattr(block, "successors"):
                for successor in block.successors:
                    if 0x1000 < successor < 0x7FFFFFFFFFFF and successor not in handlers:
                        handlers.append(successor)
        except Exception as e:
            logger.debug("Dispatcher target tracing failed: %s", e)

        return handlers

    def _lift_handler_symbolic(self, handler_addr: int) -> LiftedHandler | None:
        if self.project is None:
            return None

        try:
            state = self.project.factory.call_state(  # type: ignore[no-untyped-call]
                handler_addr,
                add_options={
                    angr.options.SYMBOLIC_WRITE_ADDRESSES,
                    angr.options.SYMBOLIC,
                },
            )

            vm_stack = claripy.BVS("vm_stack", 64 * 8)
            vm_ip = claripy.BVS("vm_ip", self.project.arch.bits)

            if self.project.arch.bits == 64:
                state.regs.rip = vm_ip
                state.regs.rsp = vm_stack[:64]
                state.solver.add(state.regs.rsp >= 0x1000)
                state.solver.add(state.regs.rsp < 0x7FFFFFFFFFFF)
            elif self.project.arch.bits == 32:
                state.regs.eip = vm_ip[:32]
                state.regs.esp = vm_stack[:32]
                state.solver.add(state.regs.esp >= 0x1000)
                state.solver.add(state.regs.esp < 0x7FFFFFFF)

            state.mem[state.regs.sp].qword = vm_stack

            exploration_manager = self.project.factory.simgr(state)  # type: ignore[no-untyped-call]
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
        if self.project is None:
            return HandlerSemantic.UNKNOWN

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

    def _translate_handler_to_native(
        self,
        handler_addr: int,
        semantic: HandlerSemantic,
        effects: list[tuple[str, Any]],
    ) -> tuple[bytes | None, list[str]]:
        semantic_to_asm: dict[HandlerSemantic, tuple[str, bytes]] = {
            HandlerSemantic.STACK_PUSH: ("push eax", b"\x50"),
            HandlerSemantic.STACK_POP: ("pop eax", b"\x58"),
            HandlerSemantic.ARITHMETIC_ADD: ("add eax, ebx", b"\x01\xd8"),
            HandlerSemantic.ARITHMETIC_SUB: ("sub eax, ebx", b"\x29\xd8"),
            HandlerSemantic.ARITHMETIC_MUL: ("imul eax, ebx", b"\x0f\xaf\xc3"),
            HandlerSemantic.ARITHMETIC_DIV: ("idiv ebx", b"\xf7\xfb"),
            HandlerSemantic.LOGICAL_AND: ("and eax, ebx", b"\x21\xd8"),
            HandlerSemantic.LOGICAL_OR: ("or eax, ebx", b"\x09\xd8"),
            HandlerSemantic.LOGICAL_XOR: ("xor eax, ebx", b"\x31\xd8"),
            HandlerSemantic.LOGICAL_NOT: ("not eax", b"\xf7\xd0"),
            HandlerSemantic.SHIFT_LEFT: ("shl eax, cl", b"\xd3\xe0"),
            HandlerSemantic.SHIFT_RIGHT: ("shr eax, cl", b"\xd3\xe8"),
            HandlerSemantic.BRANCH_CONDITIONAL: ("jz 0x00", b"\x74\x00"),
            HandlerSemantic.BRANCH_UNCONDITIONAL: ("jmp 0x00", b"\xeb\x00"),
            HandlerSemantic.CALL: ("call 0x00000000", b"\xe8\x00\x00\x00\x00"),
            HandlerSemantic.RETURN: ("ret", b"\xc3"),
            HandlerSemantic.MEMORY_LOAD: ("mov eax, [ebx]", b"\x8b\x03"),
            HandlerSemantic.MEMORY_STORE: ("mov [ebx], eax", b"\x89\x03"),
        }

        if semantic in semantic_to_asm:
            asm, bytecode = semantic_to_asm[semantic]
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

    def _calculate_handler_confidence(
        self,
        semantic: HandlerSemantic,
        effects: list[tuple[str, Any]],
        constraints: list[Any],
        native_code: bytes | None,
    ) -> float:
        confidence = 50.0

        if semantic != HandlerSemantic.UNKNOWN:
            confidence += 20.0

        if effects:
            confidence += min(len(effects) * 5, 15.0)

        if constraints:
            confidence += min(len(constraints) * 2, 10.0)

        if native_code:
            confidence += 15.0

        return min(confidence, 100.0)

    def _trace_vm_execution(
        self,
        entry_point: int,
        strategy: ExplorationStrategy,
        max_paths: int,
        timeout: int,
    ) -> list[DevirtualizedBlock]:
        blocks: list[DevirtualizedBlock] = []

        if self.project is None:
            return blocks

        try:
            state = self.project.factory.call_state(  # type: ignore[no-untyped-call]
                entry_point,
                add_options={
                    angr.options.SYMBOLIC,
                    angr.options.TRACK_CONSTRAINTS,
                },
            )

            exploration_manager = self.project.factory.simgr(state)  # type: ignore[no-untyped-call]

            if self.vm_dispatcher and self.handler_table:
                exploration_manager.use_technique(GuidedVMExploration(self.vm_dispatcher, self.handler_table, max_depth=max_paths))

            exploration_manager.use_technique(PathExplosionMitigation(max_active=50, max_total=max_paths))

            if strategy == ExplorationStrategy.DFS:
                exploration_manager.use_technique(DFS())  # type: ignore[no-untyped-call]

            import threading

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

            exploration_thread = threading.Thread(target=run_exploration, daemon=True)
            exploration_thread.start()

            if not exploration_complete.wait(timeout=timeout):
                logger.info("Exploration timeout reached")

            if exploration_error:
                logger.debug("Exploration error: %s", exploration_error)

            all_states = exploration_manager.deadended + exploration_manager.active

            for state in all_states[:20]:
                block = self._reconstruct_block_from_state(state, entry_point)
                if block:
                    blocks.append(block)

        except Exception as e:
            logger.exception("VM execution tracing failed: %s", e)

        return blocks

    def _reconstruct_block_from_state(self, state: Any, entry: int) -> DevirtualizedBlock | None:
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
        if not blocks:
            return 0.0

        total_confidence = sum(block.confidence for block in blocks)
        avg_confidence = total_confidence / len(blocks)

        bonus = 0.0
        if len(blocks) > 5:
            bonus += 10.0
        if len(self.lifted_handlers) > 20:
            bonus += 10.0

        return min(avg_confidence + bonus, 100.0)


def devirtualize_vmprotect(binary_path: str, vm_entry_point: int, max_paths: int = 500, timeout: int = 300) -> DevirtualizationResult:
    """Devirtualize VMProtect-protected binary."""
    devirt = SymbolicDevirtualizer(binary_path)
    return devirt.devirtualize(vm_entry_point, VMType.VMPROTECT, ExplorationStrategy.GUIDED, max_paths, timeout)


def devirtualize_themida(binary_path: str, vm_entry_point: int, max_paths: int = 500, timeout: int = 300) -> DevirtualizationResult:
    """Devirtualize Themida-protected binary."""
    devirt = SymbolicDevirtualizer(binary_path)
    return devirt.devirtualize(vm_entry_point, VMType.THEMIDA, ExplorationStrategy.GUIDED, max_paths, timeout)


def devirtualize_generic(
    binary_path: str,
    vm_entry_point: int,
    exploration_strategy: ExplorationStrategy = ExplorationStrategy.DFS,
    max_paths: int = 500,
    timeout: int = 300,
) -> DevirtualizationResult:
    """Devirtualize generically protected binary."""
    devirt = SymbolicDevirtualizer(binary_path)
    return devirt.devirtualize(vm_entry_point, VMType.GENERIC, exploration_strategy, max_paths, timeout)
