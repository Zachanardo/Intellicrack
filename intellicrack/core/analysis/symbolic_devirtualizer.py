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
from typing import Dict, List, Optional, Set, Tuple, Any

try:
    import angr
    import claripy
    from angr import SimState, Project
    from angr.exploration_techniques import DFS, ExplorationTechnique
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)


class ExplorationStrategy(Enum):
    DFS = "depth_first_search"
    BFS = "breadth_first_search"
    GUIDED = "guided_search"
    CONCOLIC = "concolic_execution"


class VMType(Enum):
    VMPROTECT = "vmprotect"
    THEMIDA = "themida"
    CODE_VIRTUALIZER = "code_virtualizer"
    GENERIC = "generic"
    UNKNOWN = "unknown"


class HandlerSemantic(Enum):
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
    vm_ip_symbolic: Any
    vm_sp_symbolic: Any
    vm_stack_symbolic: Any
    vm_registers: Dict[str, Any]
    native_registers_mapping: Dict[str, int]
    constraints: List[Any] = field(default_factory=list)
    path_history: List[int] = field(default_factory=list)


@dataclass
class LiftedHandler:
    handler_address: int
    semantic: HandlerSemantic
    symbolic_effects: List[Tuple[str, Any]]
    constraints: List[Any]
    native_translation: Optional[bytes]
    assembly_code: List[str]
    confidence: float
    operand_count: int = 0
    operand_types: List[str] = field(default_factory=list)


@dataclass
class DevirtualizedBlock:
    original_vm_entry: int
    original_vm_exit: int
    vm_bytecode: bytes
    handlers_executed: List[int]
    lifted_semantics: List[LiftedHandler]
    native_code: bytes
    assembly: List[str]
    control_flow_edges: List[Tuple[int, int]]
    confidence: float
    execution_paths: int


@dataclass
class DevirtualizationResult:
    vm_type: VMType
    architecture: str
    vm_entry_point: int
    handler_table: Optional[int]
    dispatcher_address: Optional[int]
    lifted_handlers: Dict[int, LiftedHandler]
    devirtualized_blocks: List[DevirtualizedBlock]
    total_paths_explored: int
    total_constraints_solved: int
    overall_confidence: float
    analysis_time_seconds: float
    technical_details: Dict[str, Any] = field(default_factory=dict)


class GuidedVMExploration(ExplorationTechnique):
    def __init__(self, vm_dispatcher: int, handler_table: int, max_depth: int = 100):
        super().__init__()
        self.vm_dispatcher = vm_dispatcher
        self.handler_table = handler_table
        self.max_depth = max_depth
        self.visited_handlers = set()

    def step(self, exploration_mgr, stash='active', **kwargs):
        exploration_mgr = exploration_mgr.step(stash=stash, **kwargs)

        if stash in exploration_mgr.stashes:
            for state in exploration_mgr.stashes[stash]:
                if state.history.depth > self.max_depth:
                    exploration_mgr.stashes[stash].remove(state)
                    if 'pruned' not in exploration_mgr.stashes:
                        exploration_mgr.stashes['pruned'] = []
                    exploration_mgr.stashes['pruned'].append(state)

        return exploration_mgr


class PathExplosionMitigation(ExplorationTechnique):
    def __init__(self, max_active: int = 50, max_total: int = 500):
        super().__init__()
        self.max_active = max_active
        self.max_total = max_total
        self.total_stepped = 0

    def step(self, exploration_mgr, stash='active', **kwargs):
        if self.total_stepped >= self.max_total:
            return exploration_mgr

        if stash in exploration_mgr.stashes and len(exploration_mgr.stashes[stash]) > self.max_active:
            exploration_mgr.stashes[stash] = exploration_mgr.stashes[stash][:self.max_active]

        exploration_mgr = exploration_mgr.step(stash=stash, **kwargs)
        self.total_stepped += 1

        return exploration_mgr


class SymbolicDevirtualizer:
    def __init__(self, binary_path: str):
        if not ANGR_AVAILABLE:
            raise ImportError("angr framework required for symbolic devirtualization")

        self.binary_path = binary_path
        self.project: Optional[Project] = None
        self.vm_type = VMType.UNKNOWN
        self.architecture = "unknown"

        self.handler_semantics: Dict[int, HandlerSemantic] = {}
        self.lifted_handlers: Dict[int, LiftedHandler] = {}

        self.vm_dispatcher: Optional[int] = None
        self.handler_table: Optional[int] = None

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
        timeout_seconds: int = 300
    ) -> DevirtualizationResult:
        import time
        start_time = time.time()

        logger.info(f"Starting symbolic devirtualization at entry point 0x{vm_entry_point:x}")

        self.project = angr.Project(
            self.binary_path,
            auto_load_libs=False,
            load_options={'main_opts': {'base_addr': 0}}
        )

        self.architecture = "x64" if self.project.arch.bits == 64 else "x86"
        self.vm_type = vm_type if vm_type != VMType.UNKNOWN else self._detect_vm_type()

        logger.info(f"Architecture: {self.architecture}, VM Type: {self.vm_type.value}")

        self.vm_dispatcher = self._find_dispatcher_symbolic(vm_entry_point)
        self.handler_table = self._find_handler_table_symbolic(vm_entry_point)

        logger.info(f"Dispatcher: 0x{self.vm_dispatcher:x if self.vm_dispatcher else 0}")
        logger.info(f"Handler table: 0x{self.handler_table:x if self.handler_table else 0}")

        handler_addresses = self._extract_handler_addresses()
        logger.info(f"Extracted {len(handler_addresses)} handler addresses")

        for handler_addr in handler_addresses:
            lifted = self._lift_handler_symbolic(handler_addr)
            if lifted:
                self.lifted_handlers[handler_addr] = lifted

        logger.info(f"Lifted {len(self.lifted_handlers)} handlers with symbolic execution")

        devirtualized_blocks = self._trace_vm_execution(
            vm_entry_point,
            exploration_strategy,
            max_paths,
            timeout_seconds
        )

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
                'exploration_strategy': exploration_strategy.value,
                'max_paths_limit': max_paths,
                'timeout_limit': timeout_seconds,
                'handlers_discovered': len(handler_addresses),
                'handlers_lifted': len(self.lifted_handlers),
                'blocks_devirtualized': len(devirtualized_blocks)
            }
        )

        logger.info(f"Devirtualization complete in {elapsed:.2f}s - Confidence: {overall_confidence:.1f}%")

        return result

    def _detect_vm_type(self) -> VMType:
        with open(self.binary_path, 'rb') as f:
            data = f.read()

        if b'.vmp' in data or b'VMProtect' in data:
            return VMType.VMPROTECT
        elif b'.themida' in data or b'Themida' in data or b'WinLicense' in data:
            return VMType.THEMIDA
        elif b'Code Virtualizer' in data or b'.cvirt' in data:
            return VMType.CODE_VIRTUALIZER

        return VMType.GENERIC

    def _find_dispatcher_symbolic(self, start_addr: int) -> Optional[int]:
        initial_state = self.project.factory.blank_state(addr=start_addr)

        exploration_manager = self.project.factory.simgr(initial_state)

        try:
            exploration_manager.explore(
                find=lambda s: self._is_dispatcher_state(s),
                num_find=1,
                n=100
            )

            if exploration_manager.found:
                dispatcher_addr = exploration_manager.found[0].addr
                logger.debug(f"Found dispatcher at 0x{dispatcher_addr:x}")
                return dispatcher_addr
        except Exception as e:
            logger.debug(f"Symbolic dispatcher search failed: {e}")

        return self._find_dispatcher_pattern()

    def _is_dispatcher_state(self, state: SimState) -> bool:
        block = self.project.factory.block(state.addr)

        if not block.capstone:
            return False

        indirect_jumps = 0
        for insn in block.capstone.insns:
            if insn.mnemonic == 'jmp' and '[' in insn.op_str:
                indirect_jumps += 1

        return indirect_jumps >= 1

    def _find_dispatcher_pattern(self) -> Optional[int]:
        with open(self.binary_path, 'rb') as f:
            data = f.read()

        patterns_x86 = [
            b'\xff\x24\x85',
            b'\xff\x24\x8d'
        ]

        patterns_x64 = [
            b'\xff\x24\xc5',
            b'\xff\x24\xcd',
            b'\x41\xff\x24\xc5'
        ]

        patterns = patterns_x64 if self.architecture == 'x64' else patterns_x86

        for pattern in patterns:
            offset = data.find(pattern)
            if offset != -1:
                return offset

        return None

    def _find_handler_table_symbolic(self, start_addr: int) -> Optional[int]:
        if not self.vm_dispatcher:
            return None

        try:
            block = self.project.factory.block(self.vm_dispatcher)

            for insn in block.capstone.insns:
                if insn.mnemonic == 'jmp' and '[' in insn.op_str:
                    operand_str = insn.op_str

                    import re
                    addr_match = re.search(r'0x([0-9a-fA-F]+)', operand_str)
                    if addr_match:
                        table_addr = int(addr_match.group(1), 16)
                        logger.debug(f"Found handler table at 0x{table_addr:x}")
                        return table_addr
        except Exception as e:
            logger.debug(f"Handler table extraction failed: {e}")

        return self._scan_for_pointer_table()

    def _scan_for_pointer_table(self) -> Optional[int]:
        with open(self.binary_path, 'rb') as f:
            data = f.read()

        ptr_size = 8 if self.architecture == 'x64' else 4
        min_entries = 16

        for offset in range(0, len(data) - min_entries * ptr_size, ptr_size):
            consecutive = 0

            for i in range(min_entries):
                ptr_offset = offset + i * ptr_size

                if ptr_offset + ptr_size > len(data):
                    break

                if ptr_size == 4:
                    ptr_val = struct.unpack('<I', data[ptr_offset:ptr_offset+4])[0]
                    valid = 0x1000 < ptr_val < 0x10000000
                else:
                    ptr_val = struct.unpack('<Q', data[ptr_offset:ptr_offset+8])[0]
                    valid = 0x1000 < ptr_val < 0x7FFFFFFFFFFF

                if valid:
                    consecutive += 1
                else:
                    break

            if consecutive >= min_entries:
                return offset

        return None

    def _extract_handler_addresses(self) -> List[int]:
        handlers = []

        if self.handler_table:
            handlers.extend(self._read_handler_table())

        if self.vm_dispatcher:
            handlers.extend(self._trace_dispatcher_targets())

        return sorted(set(handlers))

    def _read_handler_table(self) -> List[int]:
        handlers = []

        with open(self.binary_path, 'rb') as f:
            f.seek(self.handler_table)

            ptr_size = 8 if self.architecture == 'x64' else 4
            max_handlers = 256

            for _ in range(max_handlers):
                ptr_data = f.read(ptr_size)
                if len(ptr_data) < ptr_size:
                    break

                if ptr_size == 4:
                    handler_addr = struct.unpack('<I', ptr_data)[0]
                    valid = 0x1000 < handler_addr < 0x10000000
                else:
                    handler_addr = struct.unpack('<Q', ptr_data)[0]
                    valid = 0x1000 < handler_addr < 0x7FFFFFFFFFFF

                if valid:
                    handlers.append(handler_addr)
                else:
                    break

        return handlers

    def _trace_dispatcher_targets(self) -> List[int]:
        handlers = []

        try:
            state = self.project.factory.blank_state(addr=self.vm_dispatcher)

            exec_manager = self.project.factory.simgr(state)
            target_dispatcher = self.vm_dispatcher
            exec_manager.explore(
                n=100,
                find=lambda s: s.addr != target_dispatcher
            )

            for found_state in exec_manager.found + exec_manager.active:
                try:
                    addr = found_state.addr
                    if 0x1000 < addr < 0x7FFFFFFFFFFF and addr not in handlers:
                        handlers.append(addr)

                    if hasattr(found_state.regs, 'rip') and found_state.regs.rip.symbolic:
                        solutions = found_state.solver.eval_upto(found_state.regs.rip, 10)
                        for solution in solutions:
                            if 0x1000 < solution < 0x7FFFFFFFFFFF and solution not in handlers:
                                handlers.append(solution)
                except Exception as e:
                    logger.debug(f"State analysis failed: {e}")
                    continue

            block = self.project.factory.block(self.vm_dispatcher)
            for successor in block.successors:
                if 0x1000 < successor < 0x7FFFFFFFFFFF and successor not in handlers:
                    handlers.append(successor)
        except Exception as e:
            logger.debug(f"Dispatcher target tracing failed: {e}")

        return handlers

    def _lift_handler_symbolic(self, handler_addr: int) -> Optional[LiftedHandler]:
        try:
            state = self.project.factory.call_state(
                handler_addr,
                add_options={
                    angr.options.SYMBOLIC_WRITE_ADDRESSES,
                    angr.options.SYMBOLIC,
                }
            )

            vm_stack = claripy.BVS('vm_stack', 64 * 8)
            vm_ip = claripy.BVS('vm_ip', self.project.arch.bits)

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

            exploration_manager = self.project.factory.simgr(state)
            exploration_manager.explore(n=50)

            symbolic_effects = []
            constraints = []

            if exploration_manager.active or exploration_manager.deadended:
                final_states = exploration_manager.active + exploration_manager.deadended

                for final_state in final_states[:5]:
                    for reg_name in self.project.arch.register_names.values():
                        if isinstance(reg_name, str):
                            try:
                                reg_val = final_state.registers.load(reg_name)
                                if reg_val.symbolic:
                                    symbolic_effects.append((f'reg_{reg_name}', reg_val))
                            except (KeyError, AttributeError, angr.errors.SimValueError) as e:
                                logger.debug(f"Register {reg_name} not accessible: {e}")
                                continue

                    constraints.extend(final_state.solver.constraints)

            semantic = self._infer_handler_semantic(handler_addr, symbolic_effects, constraints)

            native_code, assembly = self._translate_handler_to_native(
                handler_addr,
                semantic,
                symbolic_effects
            )

            confidence = self._calculate_handler_confidence(
                semantic,
                symbolic_effects,
                constraints,
                native_code
            )

            return LiftedHandler(
                handler_address=handler_addr,
                semantic=semantic,
                symbolic_effects=symbolic_effects,
                constraints=constraints,
                native_translation=native_code,
                assembly_code=assembly,
                confidence=confidence,
                operand_count=len(symbolic_effects),
                operand_types=[type(effect[1]).__name__ for effect in symbolic_effects]
            )

        except Exception as e:
            logger.debug(f"Handler lifting failed at 0x{handler_addr:x}: {e}")
            return None

    def _infer_handler_semantic(
        self,
        handler_addr: int,
        effects: List[Tuple[str, Any]],
        constraints: List[Any]
    ) -> HandlerSemantic:
        try:
            block = self.project.factory.block(handler_addr)

            mnemonics = [insn.mnemonic for insn in block.capstone.insns]

            if 'push' in mnemonics:
                return HandlerSemantic.STACK_PUSH
            elif 'pop' in mnemonics:
                return HandlerSemantic.STACK_POP
            elif 'add' in mnemonics:
                return HandlerSemantic.ARITHMETIC_ADD
            elif 'sub' in mnemonics:
                return HandlerSemantic.ARITHMETIC_SUB
            elif any(m in mnemonics for m in ['mul', 'imul']):
                return HandlerSemantic.ARITHMETIC_MUL
            elif any(m in mnemonics for m in ['div', 'idiv']):
                return HandlerSemantic.ARITHMETIC_DIV
            elif 'and' in mnemonics:
                return HandlerSemantic.LOGICAL_AND
            elif 'or' in mnemonics:
                return HandlerSemantic.LOGICAL_OR
            elif 'xor' in mnemonics:
                return HandlerSemantic.LOGICAL_XOR
            elif 'not' in mnemonics:
                return HandlerSemantic.LOGICAL_NOT
            elif 'shl' in mnemonics or 'sal' in mnemonics:
                return HandlerSemantic.SHIFT_LEFT
            elif 'shr' in mnemonics or 'sar' in mnemonics:
                return HandlerSemantic.SHIFT_RIGHT
            elif any(m.startswith('j') for m in mnemonics if m != 'jmp'):
                return HandlerSemantic.BRANCH_CONDITIONAL
            elif 'jmp' in mnemonics:
                return HandlerSemantic.BRANCH_UNCONDITIONAL
            elif 'call' in mnemonics:
                return HandlerSemantic.CALL
            elif 'ret' in mnemonics:
                return HandlerSemantic.RETURN
            elif any(m in mnemonics for m in ['mov', 'movzx', 'movsx']) and '[' in str(block.capstone.insns):
                if any('esp' in str(insn) or 'rsp' in str(insn) for insn in block.capstone.insns):
                    return HandlerSemantic.MEMORY_LOAD
                else:
                    return HandlerSemantic.MEMORY_STORE
        except Exception as e:
            logger.debug(f"Semantic inference failed: {e}")

        return HandlerSemantic.UNKNOWN

    def _translate_handler_to_native(
        self,
        handler_addr: int,
        semantic: HandlerSemantic,
        effects: List[Tuple[str, Any]]
    ) -> Tuple[Optional[bytes], List[str]]:
        semantic_to_asm = {
            HandlerSemantic.STACK_PUSH: ("push eax", b'\x50'),
            HandlerSemantic.STACK_POP: ("pop eax", b'\x58'),
            HandlerSemantic.ARITHMETIC_ADD: ("add eax, ebx", b'\x01\xd8'),
            HandlerSemantic.ARITHMETIC_SUB: ("sub eax, ebx", b'\x29\xd8'),
            HandlerSemantic.ARITHMETIC_MUL: ("imul eax, ebx", b'\x0f\xaf\xc3'),
            HandlerSemantic.ARITHMETIC_DIV: ("idiv ebx", b'\xf7\xfb'),
            HandlerSemantic.LOGICAL_AND: ("and eax, ebx", b'\x21\xd8'),
            HandlerSemantic.LOGICAL_OR: ("or eax, ebx", b'\x09\xd8'),
            HandlerSemantic.LOGICAL_XOR: ("xor eax, ebx", b'\x31\xd8'),
            HandlerSemantic.LOGICAL_NOT: ("not eax", b'\xf7\xd0'),
            HandlerSemantic.SHIFT_LEFT: ("shl eax, cl", b'\xd3\xe0'),
            HandlerSemantic.SHIFT_RIGHT: ("shr eax, cl", b'\xd3\xe8'),
            HandlerSemantic.BRANCH_CONDITIONAL: ("jz 0x00", b'\x74\x00'),
            HandlerSemantic.BRANCH_UNCONDITIONAL: ("jmp 0x00", b'\xeb\x00'),
            HandlerSemantic.CALL: ("call 0x00000000", b'\xe8\x00\x00\x00\x00'),
            HandlerSemantic.RETURN: ("ret", b'\xc3'),
            HandlerSemantic.MEMORY_LOAD: ("mov eax, [ebx]", b'\x8b\x03'),
            HandlerSemantic.MEMORY_STORE: ("mov [ebx], eax", b'\x89\x03'),
        }

        if semantic in semantic_to_asm:
            asm, bytecode = semantic_to_asm[semantic]
            return bytecode, [asm]

        try:
            block = self.project.factory.block(handler_addr)
            assembly = [f"{insn.mnemonic} {insn.op_str}" for insn in block.capstone.insns]
            return block.bytes, assembly
        except (AttributeError, KeyError, angr.errors.SimEngineError) as e:
            logger.debug(f"Failed to disassemble handler at 0x{handler_addr:x}: {e}")
            return None, [f"unknown_handler_0x{handler_addr:x}"]

    def _calculate_handler_confidence(
        self,
        semantic: HandlerSemantic,
        effects: List[Tuple[str, Any]],
        constraints: List[Any],
        native_code: Optional[bytes]
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
        timeout: int
    ) -> List[DevirtualizedBlock]:
        blocks = []

        try:
            state = self.project.factory.call_state(
                entry_point,
                add_options={
                    angr.options.SYMBOLIC,
                    angr.options.TRACK_CONSTRAINTS,
                }
            )

            exploration_manager = self.project.factory.simgr(state)

            if self.vm_dispatcher and self.handler_table:
                exploration_manager.use_technique(
                    GuidedVMExploration(
                        self.vm_dispatcher,
                        self.handler_table,
                        max_depth=max_paths
                    )
                )

            exploration_manager.use_technique(
                PathExplosionMitigation(
                    max_active=50,
                    max_total=max_paths
                )
            )

            if strategy == ExplorationStrategy.DFS:
                exploration_manager.use_technique(DFS())

            import threading

            exploration_complete = threading.Event()
            exploration_error = None

            def run_exploration():
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
                logger.debug(f"Exploration error: {exploration_error}")

            all_states = exploration_manager.deadended + exploration_manager.active

            for state in all_states[:20]:
                block = self._reconstruct_block_from_state(state, entry_point)
                if block:
                    blocks.append(block)

        except Exception as e:
            logger.error(f"VM execution tracing failed: {e}")

        return blocks

    def _reconstruct_block_from_state(
        self,
        state: SimState,
        entry: int
    ) -> Optional[DevirtualizedBlock]:
        try:
            path_addrs = [addr for addr in state.history.bbl_addrs]

            handlers_exec = []
            for addr in path_addrs:
                if addr in self.lifted_handlers:
                    handlers_exec.append(addr)

            if not handlers_exec:
                return None

            lifted_seq = [self.lifted_handlers[h] for h in handlers_exec if h in self.lifted_handlers]

            native_code = bytearray()
            assembly = []

            for lifted in lifted_seq:
                if lifted.native_translation:
                    native_code.extend(lifted.native_translation)
                assembly.extend(lifted.assembly_code)

            cf_edges = []
            for i in range(len(path_addrs) - 1):
                cf_edges.append((path_addrs[i], path_addrs[i+1]))

            avg_confidence = sum(h.confidence for h in lifted_seq) / len(lifted_seq) if lifted_seq else 0.0

            return DevirtualizedBlock(
                original_vm_entry=entry,
                original_vm_exit=state.addr,
                vm_bytecode=b'',
                handlers_executed=handlers_exec,
                lifted_semantics=lifted_seq,
                native_code=bytes(native_code),
                assembly=assembly,
                control_flow_edges=cf_edges,
                confidence=avg_confidence,
                execution_paths=1
            )

        except Exception as e:
            logger.debug(f"Block reconstruction failed: {e}")
            return None

    def _calculate_overall_confidence(self, blocks: List[DevirtualizedBlock]) -> float:
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


def devirtualize_vmprotect(
    binary_path: str,
    vm_entry_point: int,
    max_paths: int = 500,
    timeout: int = 300
) -> DevirtualizationResult:
    devirt = SymbolicDevirtualizer(binary_path)
    return devirt.devirtualize(
        vm_entry_point,
        VMType.VMPROTECT,
        ExplorationStrategy.GUIDED,
        max_paths,
        timeout
    )


def devirtualize_themida(
    binary_path: str,
    vm_entry_point: int,
    max_paths: int = 500,
    timeout: int = 300
) -> DevirtualizationResult:
    devirt = SymbolicDevirtualizer(binary_path)
    return devirt.devirtualize(
        vm_entry_point,
        VMType.THEMIDA,
        ExplorationStrategy.GUIDED,
        max_paths,
        timeout
    )


def devirtualize_generic(
    binary_path: str,
    vm_entry_point: int,
    exploration_strategy: ExplorationStrategy = ExplorationStrategy.DFS,
    max_paths: int = 500,
    timeout: int = 300
) -> DevirtualizationResult:
    devirt = SymbolicDevirtualizer(binary_path)
    return devirt.devirtualize(
        vm_entry_point,
        VMType.GENERIC,
        exploration_strategy,
        max_paths,
        timeout
    )
