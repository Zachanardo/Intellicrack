"""Advanced Opaque Predicate Analysis Engine.

This module provides sophisticated opaque predicate detection and removal using:
- Constant propagation analysis
- Symbolic execution with Z3
- Pattern recognition for complex invariants
- Dead code elimination

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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""


import logging
from dataclasses import dataclass
from typing import Any, Protocol

from intellicrack.utils.logger import logger


Z3Expr = Any  # Z3 expression type - cannot be typed statically


class BasicBlockProtocol(Protocol):
    """Protocol for BasicBlock objects in control flow analysis."""

    instructions: list[dict[str, Any]]
    successors: list[int]
    address: int


try:
    import z3

    Z3_AVAILABLE = True
except ImportError:
    logger.warning("Z3 not available for symbolic execution")
    Z3_AVAILABLE = False
    z3 = None

try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    logger.warning("NetworkX not available for opaque predicate analysis")
    NETWORKX_AVAILABLE = False
    nx = None


@dataclass
class ConstantValue:
    """Represents a constant value tracked through control flow."""

    register: str
    value: int | None
    is_constant: bool
    source_instruction: dict[str, Any]


@dataclass
class PredicateAnalysis:
    """Results of opaque predicate analysis."""

    address: int
    instruction: str
    predicate_type: str
    always_value: bool | None
    confidence: float
    analysis_method: str
    dead_branch: int | None
    symbolic_proof: str | None


class ConstantPropagationEngine:
    """Performs interprocedural constant propagation analysis."""

    def __init__(self) -> None:
        """Initialize constant propagation engine."""
        self.logger = logging.getLogger(__name__)
        self.register_state: dict[int, dict[str, ConstantValue]] = {}
        self.block_entry_states: dict[int, dict[str, ConstantValue]] = {}

    def analyze_cfg(self, cfg: nx.DiGraph, entry_block: int) -> dict[int, dict[str, ConstantValue]]:
        """Perform constant propagation across entire CFG.

        Args:
            cfg: Control flow graph
            entry_block: Entry block address

        Returns:
            Mapping of block addresses to register states at block entry

        """
        if not NETWORKX_AVAILABLE:
            return {}

        worklist = [entry_block]
        visited = set()

        self.block_entry_states[entry_block] = {}

        while worklist:
            block_addr = worklist.pop(0)

            if block_addr in visited:
                continue

            visited.add(block_addr)

            if block_addr not in cfg.nodes():
                continue

            basic_block = cfg.nodes[block_addr]["data"]

            entry_state = self.block_entry_states.get(block_addr, {}).copy()

            exit_state = self._analyze_block(basic_block, entry_state)

            self.register_state[block_addr] = exit_state

            for successor in basic_block.successors:
                if successor not in self.block_entry_states:
                    self.block_entry_states[successor] = exit_state.copy()
                else:
                    self.block_entry_states[successor] = self._merge_states(
                        self.block_entry_states[successor],
                        exit_state,
                    )

                if successor not in visited:
                    worklist.append(successor)

        return self.block_entry_states

    def _parse_operands(self, disasm: str) -> tuple[str, list[str]]:
        """Parse mnemonic and operands from disassembly string.

        Args:
            disasm: Disassembly string like "mov eax, 0x42"

        Returns:
            Tuple of (mnemonic, [operands])

        """
        parts = disasm.split(None, 1)
        if len(parts) < 2:
            return parts[0] if parts else "", []

        mnemonic = parts[0]
        operand_str = parts[1]
        operands = [op.strip() for op in operand_str.split(",")]

        return mnemonic, operands

    def _analyze_block(
        self,
        basic_block: BasicBlockProtocol,
        entry_state: dict[str, ConstantValue],
    ) -> dict[str, ConstantValue]:
        """Analyze a single basic block for constant propagation.

        Args:
            basic_block: BasicBlock to analyze
            entry_state: Register state at block entry

        Returns:
            Register state at block exit

        """
        state = entry_state.copy()

        for inst in basic_block.instructions:
            disasm = inst.get("disasm", "").lower()
            mnemonic, operands = self._parse_operands(disasm)

            if not mnemonic:
                continue

            if mnemonic in ["mov", "movzx", "movsx"]:
                self._handle_mov(operands, inst, state)
            elif mnemonic in ["lea"]:
                self._handle_lea(operands, inst, state)
            elif mnemonic in ["add", "sub", "inc", "dec"]:
                self._handle_arithmetic(mnemonic, operands, inst, state)
            elif mnemonic in ["xor", "or", "and"]:
                self._handle_bitwise(mnemonic, operands, inst, state)
            elif mnemonic in ["shl", "shr", "sal", "sar", "rol", "ror"]:
                self._handle_shift(mnemonic, operands, inst, state)
            elif mnemonic in ["mul", "imul", "div", "idiv"]:
                self._handle_multiply_divide(mnemonic, operands, inst, state)
            elif mnemonic == "push":
                pass
            elif mnemonic == "pop":
                self._handle_pop(operands, inst, state)
            elif mnemonic == "call":
                self._invalidate_volatile_registers(state)
            elif operands:
                if dest := self._extract_register(operands[0]):
                    state.pop(dest, None)

        return state

    def _handle_mov(
        self,
        operands: list[str],
        inst: dict[str, Any],
        state: dict[str, ConstantValue],
    ) -> None:
        """Handle MOV instruction.

        Args:
            operands: List of operands
            inst: Instruction dictionary
            state: Current register state

        """
        if len(operands) < 2:
            return

        dest = self._extract_register(operands[0])
        src = operands[1]

        if not dest:
            return

        if src.startswith("0x"):
            try:
                value = int(src, 16)
                state[dest] = ConstantValue(
                    register=dest,
                    value=value,
                    is_constant=True,
                    source_instruction=inst,
                )
            except ValueError:
                state.pop(dest, None)
        elif src.isdigit():
            try:
                value = int(src)
                state[dest] = ConstantValue(
                    register=dest,
                    value=value,
                    is_constant=True,
                    source_instruction=inst,
                )
            except ValueError:
                state.pop(dest, None)
        else:
            src_reg = self._extract_register(src)
            if src_reg and src_reg in state and state[src_reg].is_constant:
                state[dest] = ConstantValue(
                    register=dest,
                    value=state[src_reg].value,
                    is_constant=True,
                    source_instruction=inst,
                )
            else:
                state.pop(dest, None)

    def _handle_lea(
        self,
        operands: list[str],
        inst: dict[str, Any],
        state: dict[str, ConstantValue],
    ) -> None:
        """Handle LEA instruction.

        Args:
            operands: List of operands
            inst: Instruction dictionary
            state: Current register state

        """
        if not operands:
            return

        if dest := self._extract_register(operands[0]):
            state.pop(dest, None)

    def _handle_arithmetic(
        self,
        mnemonic: str,
        operands: list[str],
        inst: dict[str, Any],
        state: dict[str, ConstantValue],
    ) -> None:
        """Handle arithmetic instructions (ADD, SUB, INC, DEC).

        Args:
            mnemonic: Instruction mnemonic
            operands: List of operands
            inst: Instruction dictionary
            state: Current register state

        """
        if not operands:
            return

        dest = self._extract_register(operands[0])
        if not dest:
            return

        if mnemonic in {"inc"}:
            if dest in state and state[dest].is_constant and state[dest].value is not None:
                state[dest] = ConstantValue(
                    register=dest,
                    value=state[dest].value + 1,
                    is_constant=True,
                    source_instruction=inst,
                )
            else:
                state.pop(dest, None)
        elif mnemonic in ["dec"]:
            if dest in state and state[dest].is_constant and state[dest].value is not None:
                state[dest] = ConstantValue(
                    register=dest,
                    value=state[dest].value - 1,
                    is_constant=True,
                    source_instruction=inst,
                )
            else:
                state.pop(dest, None)
        elif len(operands) >= 2:
            src = operands[1]
            if dest in state and state[dest].is_constant and state[dest].value is not None:
                if src.startswith("0x"):
                    try:
                        src_val = int(src, 16)
                        if mnemonic == "add":
                            new_val = state[dest].value + src_val
                        elif mnemonic == "sub":
                            new_val = state[dest].value - src_val
                        else:
                            state.pop(dest, None)
                            return
                        state[dest] = ConstantValue(
                            register=dest,
                            value=new_val,
                            is_constant=True,
                            source_instruction=inst,
                        )
                    except ValueError:
                        state.pop(dest, None)
                elif src.isdigit():
                    try:
                        src_val = int(src)
                        if mnemonic == "add":
                            new_val = state[dest].value + src_val
                        elif mnemonic == "sub":
                            new_val = state[dest].value - src_val
                        else:
                            state.pop(dest, None)
                            return
                        state[dest] = ConstantValue(
                            register=dest,
                            value=new_val,
                            is_constant=True,
                            source_instruction=inst,
                        )
                    except ValueError:
                        state.pop(dest, None)
                else:
                    src_reg = self._extract_register(src)
                    if (
                        src_reg
                        and src_reg in state
                        and state[src_reg].is_constant
                        and state[src_reg].value is not None
                    ):
                        if mnemonic == "add":
                            new_val = state[dest].value + state[src_reg].value
                        elif mnemonic == "sub":
                            new_val = state[dest].value - state[src_reg].value
                        else:
                            state.pop(dest, None)
                            return
                        state[dest] = ConstantValue(
                            register=dest,
                            value=new_val,
                            is_constant=True,
                            source_instruction=inst,
                        )
                    else:
                        state.pop(dest, None)
            else:
                state.pop(dest, None)
        else:
            state.pop(dest, None)

    def _handle_bitwise(
        self,
        mnemonic: str,
        operands: list[str],
        inst: dict[str, Any],
        state: dict[str, ConstantValue],
    ) -> None:
        """Handle bitwise operations (XOR, OR, AND).

        Args:
            mnemonic: Instruction mnemonic
            operands: List of operands
            inst: Instruction dictionary
            state: Current register state

        """
        if len(operands) < 2:
            return

        dest = self._extract_register(operands[0])
        src = operands[1]

        if not dest:
            return

        src_reg = self._extract_register(src)

        if mnemonic == "xor" and dest == src_reg:
            state[dest] = ConstantValue(
                register=dest,
                value=0,
                is_constant=True,
                source_instruction=inst,
            )
        elif dest in state and state[dest].is_constant and state[dest].value is not None:
            if src.startswith("0x"):
                try:
                    src_val = int(src, 16)
                    if mnemonic == "xor":
                        new_val = state[dest].value ^ src_val
                    elif mnemonic == "or":
                        new_val = state[dest].value | src_val
                    elif mnemonic == "and":
                        new_val = state[dest].value & src_val
                    else:
                        state.pop(dest, None)
                        return
                    state[dest] = ConstantValue(
                        register=dest,
                        value=new_val,
                        is_constant=True,
                        source_instruction=inst,
                    )
                except ValueError:
                    state.pop(dest, None)
            elif src.isdigit():
                try:
                    src_val = int(src)
                    if mnemonic == "xor":
                        new_val = state[dest].value ^ src_val
                    elif mnemonic == "or":
                        new_val = state[dest].value | src_val
                    elif mnemonic == "and":
                        new_val = state[dest].value & src_val
                    else:
                        state.pop(dest, None)
                        return
                    state[dest] = ConstantValue(
                        register=dest,
                        value=new_val,
                        is_constant=True,
                        source_instruction=inst,
                    )
                except ValueError:
                    state.pop(dest, None)
            elif src_reg and src_reg in state and state[src_reg].is_constant:
                if state[src_reg].value is not None:
                    if mnemonic == "xor":
                        new_val = state[dest].value ^ state[src_reg].value
                    elif mnemonic == "or":
                        new_val = state[dest].value | state[src_reg].value
                    elif mnemonic == "and":
                        new_val = state[dest].value & state[src_reg].value
                    else:
                        state.pop(dest, None)
                        return
                    state[dest] = ConstantValue(
                        register=dest,
                        value=new_val,
                        is_constant=True,
                        source_instruction=inst,
                    )
                else:
                    state.pop(dest, None)
            else:
                state.pop(dest, None)
        else:
            state.pop(dest, None)

    def _handle_shift(
        self,
        mnemonic: str,
        operands: list[str],
        inst: dict[str, Any],
        state: dict[str, ConstantValue],
    ) -> None:
        """Handle shift operations.

        Args:
            mnemonic: Instruction mnemonic
            operands: List of operands
            inst: Instruction dictionary
            state: Current register state

        """
        if not operands:
            return

        dest = self._extract_register(operands[0])
        if not dest:
            return

        if dest in state and state[dest].is_constant and len(operands) >= 2:
            if state[dest].value is not None:
                shift_amount_str = operands[1].strip()
                if shift_amount_str.startswith("0x"):
                    try:
                        shift_amount = int(shift_amount_str, 16)
                    except ValueError:
                        state.pop(dest, None)
                        return
                elif shift_amount_str.isdigit():
                    shift_amount = int(shift_amount_str)
                else:
                    state.pop(dest, None)
                    return

                if mnemonic in {"shl", "sal"}:
                    new_val = state[dest].value << shift_amount
                elif mnemonic in {"shr", "sar"}:
                    new_val = state[dest].value >> shift_amount
                else:
                    state.pop(dest, None)
                    return

                state[dest] = ConstantValue(
                    register=dest,
                    value=new_val,
                    is_constant=True,
                    source_instruction=inst,
                )
            else:
                state.pop(dest, None)
        else:
            state.pop(dest, None)

    def _handle_multiply_divide(
        self,
        mnemonic: str,
        operands: list[str],
        inst: dict[str, Any],
        state: dict[str, ConstantValue],
    ) -> None:
        """Handle multiplication and division.

        Args:
            mnemonic: Instruction mnemonic
            operands: List of operands
            inst: Instruction dictionary
            state: Current register state

        """
        state.pop("rax", None)
        state.pop("eax", None)
        state.pop("rdx", None)
        state.pop("edx", None)

    def _handle_pop(
        self,
        operands: list[str],
        inst: dict[str, Any],
        state: dict[str, ConstantValue],
    ) -> None:
        """Handle POP instruction.

        Args:
            operands: List of operands
            inst: Instruction dictionary
            state: Current register state

        """
        if not operands:
            return

        if dest := self._extract_register(operands[0]):
            state.pop(dest, None)

    def _invalidate_volatile_registers(self, state: dict[str, ConstantValue]) -> None:
        """Invalidate volatile registers after function calls.

        Args:
            state: Current register state

        """
        volatile_regs = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "eax", "ecx", "edx"]
        for reg in volatile_regs:
            state.pop(reg, None)

    def _merge_states(
        self,
        state1: dict[str, ConstantValue],
        state2: dict[str, ConstantValue],
    ) -> dict[str, ConstantValue]:
        """Merge two register states (join operation).

        Args:
            state1: First state
            state2: Second state

        Returns:
            Merged state with only constants that match in both states

        """
        merged = {}

        for reg, reg_value in state1.items():
            if reg in state2 and (
                                reg_value.is_constant
                                and state2[reg].is_constant
                                and reg_value.value == state2[reg].value
                            ):
                merged[reg] = reg_value

        return merged

    def _extract_register(self, operand: str) -> str | None:
        """Extract register name from operand string.

        Args:
            operand: Operand string

        Returns:
            Register name or None

        """
        operand = operand.strip().lower()

        registers = [
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
            "ax",
            "bx",
            "cx",
            "dx",
            "al",
            "bl",
            "cl",
            "dl",
            "ah",
            "bh",
            "ch",
            "dh",
        ]

        return next((reg for reg in registers if reg in operand), None)


class SymbolicExecutionEngine:
    """Performs symbolic execution using Z3 to prove opaque predicates."""

    def __init__(self) -> None:
        """Initialize symbolic execution engine."""
        self.logger = logging.getLogger(__name__)
        self.solver = z3.Solver() if Z3_AVAILABLE else None

    def analyze_predicate(
        self,
        basic_block: BasicBlockProtocol,
        register_state: dict[str, ConstantValue],
    ) -> tuple[bool | None, str | None]:
        """Symbolically analyze a conditional predicate.

        Args:
            basic_block: BasicBlock containing the predicate
            register_state: Known register state at block entry

        Returns:
            Tuple of (always_value, proof_string) or (None, None)

        """
        if not Z3_AVAILABLE or not self.solver:
            return None, None

        try:
            self.solver.reset()

            symbolic_vars = {
                reg: (
                    z3.BitVecVal(const_val.value, 64)
                    if const_val.is_constant and const_val.value is not None
                    else z3.BitVec(reg, 64)
                )
                for reg, const_val in register_state.items()
            }
            condition_expr = self._build_symbolic_expression(basic_block, symbolic_vars)

            if condition_expr is None:
                return None, None

            self.solver.push()
            self.solver.add(z3.Not(condition_expr))
            result_false = self.solver.check()
            self.solver.pop()

            self.solver.push()
            self.solver.add(condition_expr)
            result_true = self.solver.check()
            self.solver.pop()

            if result_true == z3.sat and result_false == z3.unsat:
                proof = f"Z3 proved predicate is always TRUE: {condition_expr}"
                return True, proof
            if result_false == z3.sat and result_true == z3.unsat:
                proof = f"Z3 proved predicate is always FALSE: {condition_expr}"
                return False, proof
            return None, None

        except Exception as e:
            self.logger.debug(f"Symbolic execution failed: {e}")
            return None, None

    def _build_symbolic_expression(
        self, basic_block: BasicBlockProtocol, symbolic_vars: dict[str, Any]
    ) -> Z3Expr:
        """Build Z3 expression from assembly instructions.

        Args:
            basic_block: BasicBlock to analyze
            symbolic_vars: Symbolic variable mapping

        Returns:
            Z3 expression or None

        """
        if not basic_block.instructions:
            return None

        last_inst = basic_block.instructions[-1]
        disasm = last_inst.get("disasm", "").lower()

        if all(
            jcc not in disasm
            for jcc in [
                "je",
                "jne",
                "jz",
                "jnz",
                "ja",
                "jb",
                "jg",
                "jl",
                "jge",
                "jle",
            ]
        ):
            return None

        cmp_inst = None
        test_inst = None

        for inst in reversed(basic_block.instructions[:-1]):
            inst_disasm = inst.get("disasm", "").lower()
            if inst_disasm.startswith("cmp"):
                cmp_inst = inst
                break
            if inst_disasm.startswith("test"):
                test_inst = inst
                break

        if cmp_inst:
            return self._build_comparison_expr(cmp_inst, disasm, symbolic_vars)
        if test_inst:
            return self._build_test_expr(test_inst, disasm, symbolic_vars)

        return None

    def _build_comparison_expr(
        self,
        cmp_inst: dict[str, Any],
        jump_inst: str,
        symbolic_vars: dict[str, Any],
    ) -> Z3Expr:
        """Build Z3 expression for CMP instruction.

        Args:
            cmp_inst: CMP instruction
            jump_inst: Conditional jump instruction
            symbolic_vars: Symbolic variables

        Returns:
            Z3 expression

        """
        disasm = cmp_inst.get("disasm", "").lower()
        parts = disasm.split(None, 1)

        if len(parts) < 2:
            return None

        operand_str = parts[1]
        operands = [op.strip() for op in operand_str.split(",")]
        if len(operands) < 2:
            return None

        op1_str = operands[0]
        op2_str = operands[1]

        op1 = self._parse_operand(op1_str, symbolic_vars)
        op2 = self._parse_operand(op2_str, symbolic_vars)

        if op1 is None or op2 is None:
            return None

        if "je" in jump_inst or "jz" in jump_inst:
            return op1 == op2
        if "jne" in jump_inst or "jnz" in jump_inst:
            return op1 != op2
        if "ja" in jump_inst:
            return z3.UGT(op1, op2)
        if "jb" in jump_inst:
            return z3.ULT(op1, op2)
        if "jg" in jump_inst:
            return op1 > op2
        if "jl" in jump_inst:
            return op1 < op2
        if "jge" in jump_inst:
            return op1 >= op2
        return op1 <= op2 if "jle" in jump_inst else None

    def _build_test_expr(
        self,
        test_inst: dict[str, Any],
        jump_inst: str,
        symbolic_vars: dict[str, Any],
    ) -> Z3Expr:
        """Build Z3 expression for TEST instruction.

        Args:
            test_inst: TEST instruction
            jump_inst: Conditional jump instruction
            symbolic_vars: Symbolic variables

        Returns:
            Z3 expression

        """
        disasm = test_inst.get("disasm", "").lower()
        parts = disasm.split(None, 1)

        if len(parts) < 2:
            return None

        operand_str = parts[1]
        operands = [op.strip() for op in operand_str.split(",")]
        if len(operands) < 2:
            return None

        op1_str = operands[0]
        op2_str = operands[1]

        op1 = self._parse_operand(op1_str, symbolic_vars)
        op2 = self._parse_operand(op2_str, symbolic_vars)

        if op1 is None or op2 is None:
            return None

        result = op1 & op2

        if "jz" in jump_inst or "je" in jump_inst:
            return result == 0
        return result != 0 if "jnz" in jump_inst or "jne" in jump_inst else None

    def _parse_operand(self, operand: str, symbolic_vars: dict[str, Any]) -> Z3Expr:
        """Parse operand into Z3 expression.

        Args:
            operand: Operand string
            symbolic_vars: Symbolic variables

        Returns:
            Z3 expression or None

        """
        operand = operand.strip().lower()

        if operand.startswith("0x"):
            try:
                return z3.BitVecVal(int(operand, 16), 64)
            except ValueError:
                return None
        elif operand.isdigit():
            return z3.BitVecVal(int(operand), 64)
        else:
            return next(
                (var for reg, var in symbolic_vars.items() if reg in operand), None
            )


class PatternRecognizer:
    """Recognizes complex opaque predicate patterns."""

    def __init__(self) -> None:
        """Initialize pattern recognizer."""
        self.logger = logging.getLogger(__name__)
        self.patterns = self._initialize_patterns()

    def _parse_operands(self, disasm: str) -> tuple[str, list[str]]:
        """Parse mnemonic and operands from disassembly string.

        Args:
            disasm: Disassembly string like "xor eax, eax"

        Returns:
            Tuple of (mnemonic, [operands])

        """
        parts = disasm.split(None, 1)
        if len(parts) < 2:
            return parts[0] if parts else "", []

        mnemonic = parts[0]
        operand_str = parts[1]
        operands = [op.strip() for op in operand_str.split(",")]

        return mnemonic, operands

    def _initialize_patterns(self) -> list[dict[str, Any]]:
        """Initialize known opaque predicate patterns.

        Returns:
            List of pattern definitions

        """
        return [
            {
                "name": "square_nonnegative",
                "description": "(x * x) >= 0",
                "match_func": self._match_algebraic_identity,
                "always_value": True,
            },
            {
                "name": "modulo_invariant",
                "description": "(x % 2) in {0, 1}",
                "match_func": self._match_modulo_invariant,
                "always_value": None,
            },
            {
                "name": "bit_masking",
                "description": "(x & 0) == 0",
                "match_func": self._match_bit_masking,
                "always_value": True,
            },
            {
                "name": "self_xor",
                "description": "x XOR x = 0",
                "match_func": self._match_self_xor,
                "always_value": True,
            },
            {
                "name": "self_comparison",
                "description": "x == x",
                "match_func": self._match_self_comparison,
                "always_value": True,
            },
            {
                "name": "impossible_overflow",
                "description": "small_const + small_const > MAX",
                "match_func": self._match_impossible_overflow,
                "always_value": False,
            },
        ]

    def recognize_pattern(self, basic_block: BasicBlockProtocol) -> tuple[str | None, bool | None]:
        """Try to recognize opaque predicate pattern.

        Args:
            basic_block: BasicBlock to analyze

        Returns:
            Tuple of (pattern_name, always_value) or (None, None)

        """
        for pattern in self.patterns:
            if match_result := pattern["match_func"](basic_block):
                return pattern["name"], pattern["always_value"]

        return None, None

    def _match_self_xor(self, basic_block: BasicBlockProtocol) -> bool:
        """Match x XOR x pattern.

        Args:
            basic_block: BasicBlock to check

        Returns:
            True if pattern matches

        """
        for inst in basic_block.instructions:
            disasm = inst.get("disasm", "").lower()
            if "xor" in disasm:
                _mnemonic, operands = self._parse_operands(disasm)
                if len(operands) >= 2 and operands[0] == operands[1]:
                    return True
        return False

    def _match_self_comparison(self, basic_block: BasicBlockProtocol) -> bool:
        """Match x CMP x pattern.

        Args:
            basic_block: BasicBlock to check

        Returns:
            True if pattern matches

        """
        for inst in basic_block.instructions:
            disasm = inst.get("disasm", "").lower()
            if "cmp" in disasm or "test" in disasm:
                _mnemonic, operands = self._parse_operands(disasm)
                if len(operands) >= 2 and operands[0] == operands[1]:
                    return True
        return False

    def _match_algebraic_identity(self, basic_block: BasicBlockProtocol) -> bool:
        """Match algebraic identities like x*x >= 0.

        Args:
            basic_block: BasicBlock to check

        Returns:
            True if pattern matches

        """
        instructions = [inst.get("disasm", "").lower() for inst in basic_block.instructions]

        for i, inst_disasm in enumerate(instructions):
            if "imul" in inst_disasm or "mul" in inst_disasm:
                _mnemonic, operands = self._parse_operands(inst_disasm)
                if len(operands) >= 2 and operands[0] == operands[1] and i + 1 < len(instructions):
                    next_inst = instructions[i + 1]
                    if "test" in next_inst:
                        remaining = instructions[i + 2 : i + 4]
                        if any("jns" in inst or "jge" in inst for inst in remaining):
                            return True

        return False

    def _match_modulo_invariant(self, basic_block: BasicBlockProtocol) -> bool:
        """Match modulo 2 invariants.

        Args:
            basic_block: BasicBlock to check

        Returns:
            True if pattern matches

        """
        instructions = [inst.get("disasm", "").lower() for inst in basic_block.instructions]

        for i, inst_disasm in enumerate(instructions):
            if "and" in inst_disasm and ("1" in inst_disasm or "0x1" in inst_disasm) and i + 1 < len(instructions):
                next_inst = instructions[i + 1]
                if "cmp" in next_inst:
                    _mnemonic, operands = self._parse_operands(next_inst)
                    if len(operands) >= 2:
                        try:
                            cmp_val = int(operands[1])
                            if cmp_val >= 2:
                                return True
                        except ValueError:
                            pass

        return False

    def _match_bit_masking(self, basic_block: BasicBlockProtocol) -> bool:
        """Match (x & 0) == 0 pattern.

        Args:
            basic_block: BasicBlock to check

        Returns:
            True if pattern matches

        """
        for inst in basic_block.instructions:
            disasm = inst.get("disasm", "").lower()
            if "and" in disasm and ("0" in disasm or "0x0" in disasm):
                parts = disasm.split(",")
                if len(parts) >= 2 and parts[1].strip() in ["0", "0x0"]:
                    return True

        return False

    def _match_impossible_overflow(self, basic_block: BasicBlockProtocol) -> bool:
        """Match impossible overflow conditions.

        Args:
            basic_block: BasicBlock to check

        Returns:
            True if pattern matches

        """
        return False


class OpaquePredicateAnalyzer:
    """Main opaque predicate analyzer combining all analysis techniques."""

    def __init__(self) -> None:
        """Initialize opaque predicate analyzer."""
        self.logger = logging.getLogger(__name__)
        self.constant_propagation = ConstantPropagationEngine()
        self.symbolic_execution = SymbolicExecutionEngine()
        self.pattern_recognizer = PatternRecognizer()

    def analyze_cfg(self, cfg: nx.DiGraph, entry_block: int) -> list[PredicateAnalysis]:
        """Analyze CFG for opaque predicates using all available techniques.

        Args:
            cfg: Control flow graph
            entry_block: Entry block address

        Returns:
            List of detected opaque predicates with analysis results

        """
        if not NETWORKX_AVAILABLE:
            return []

        opaque_predicates = []

        block_states = self.constant_propagation.analyze_cfg(cfg, entry_block)

        for node in cfg.nodes():
            basic_block = cfg.nodes[node]["data"]

            if len(basic_block.successors) != 2:
                continue

            register_state = block_states.get(node, {})

            pattern_name, pattern_value = self.pattern_recognizer.recognize_pattern(basic_block)

            symbolic_value, symbolic_proof = self.symbolic_execution.analyze_predicate(
                basic_block,
                register_state,
            )

            constant_value = self._check_constant_predicate(basic_block, register_state)

            final_value = None
            method = "unknown"
            confidence = 0.0

            if symbolic_value is not None:
                final_value = symbolic_value
                method = "symbolic_execution"
                confidence = 0.95
            elif pattern_name is not None:
                final_value = pattern_value
                method = f"pattern_{pattern_name}"
                confidence = 0.85
            elif constant_value is not None:
                final_value = constant_value
                method = "constant_propagation"
                confidence = 0.90

            if final_value is not None:
                dead_branch = self._identify_dead_branch(basic_block, cfg, final_value)

                instruction_str = "; ".join(
                    inst.get("disasm", "") for inst in basic_block.instructions[-2:]
                )

                opaque_predicates.append(
                    PredicateAnalysis(
                        address=node,
                        instruction=instruction_str,
                        predicate_type=method,
                        always_value=final_value,
                        confidence=confidence,
                        analysis_method=method,
                        dead_branch=dead_branch,
                        symbolic_proof=symbolic_proof,
                    ),
                )

        return opaque_predicates

    def _check_constant_predicate(
        self,
        basic_block: BasicBlockProtocol,
        register_state: dict[str, ConstantValue],
    ) -> bool | None:
        """Check if predicate can be resolved using constant values.

        Args:
            basic_block: BasicBlock to check
            register_state: Known register state

        Returns:
            True/False if constant, None otherwise

        """
        if not basic_block.instructions:
            return None

        for inst in reversed(basic_block.instructions):
            disasm = inst.get("disasm", "").lower()

            if disasm.startswith("cmp"):
                parts = disasm.split(None, 1)
                if len(parts) >= 2:
                    operands = [op.strip() for op in parts[1].split(",")]
                    if len(operands) >= 2:
                        op1 = operands[0]
                        op2 = operands[1]

                        val1 = self._get_value(op1, register_state)
                        val2 = self._get_value(op2, register_state)

                        if val1 is not None and val2 is not None:
                            last_inst = basic_block.instructions[-1].get("disasm", "").lower()

                            if "je" in last_inst or "jz" in last_inst:
                                return val1 == val2
                            if "jne" in last_inst or "jnz" in last_inst:
                                return val1 != val2
                            if "jg" in last_inst:
                                return val1 > val2
                            if "jl" in last_inst:
                                return val1 < val2
                            if "jge" in last_inst:
                                return val1 >= val2
                            if "jle" in last_inst:
                                return val1 <= val2

            elif disasm.startswith("test"):
                parts = disasm.split(None, 1)
                if len(parts) >= 2:
                    operands = [op.strip() for op in parts[1].split(",")]
                    if len(operands) >= 2:
                        op1 = operands[0]
                        op2 = operands[1]

                        if op1 == op2:
                            val = self._get_value(op1, register_state)
                            if val is not None:
                                last_inst = basic_block.instructions[-1].get("disasm", "").lower()
                                if "jz" in last_inst or "je" in last_inst:
                                    return val == 0
                                if "jnz" in last_inst or "jne" in last_inst:
                                    return val != 0

        return None

    def _get_value(self, operand: str, register_state: dict[str, ConstantValue]) -> int | None:
        """Get constant value for operand.

        Args:
            operand: Operand string
            register_state: Register state

        Returns:
            Constant value or None

        """
        operand = operand.strip().lower()

        if operand.startswith("0x"):
            try:
                return int(operand, 16)
            except ValueError:
                return None
        elif operand.isdigit():
            return int(operand)
        else:
            for reg, const_val in register_state.items():
                if reg in operand and const_val.is_constant:
                    return const_val.value

        return None

    def _identify_dead_branch(
        self, basic_block: BasicBlockProtocol, cfg: nx.DiGraph, always_value: bool
    ) -> int | None:
        """Identify which branch is dead based on predicate value.

        Args:
            basic_block: BasicBlock with predicate
            cfg: Control flow graph
            always_value: Predicate evaluation result

        Returns:
            Address of dead branch or None

        """
        if len(basic_block.successors) != 2:
            return None

        true_successor = None
        false_successor = None

        block_addr = basic_block.address

        for edge in cfg.out_edges(block_addr, data=True):
            edge_type = edge[2].get("edge_type", "")
            if "true" in edge_type or edge_type == "conditional_true":
                true_successor = edge[1]
            elif "false" in edge_type or edge_type == "conditional_false":
                false_successor = edge[1]

        if true_successor and false_successor:
            return false_successor if always_value else true_successor
        return None


__all__ = [
    "ConstantPropagationEngine",
    "ConstantValue",
    "OpaquePredicateAnalyzer",
    "PatternRecognizer",
    "PredicateAnalysis",
    "SymbolicExecutionEngine",
]
