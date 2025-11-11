"""Polymorphic and Metamorphic Code Analysis Engine.

Advanced analyzer for detecting, normalizing, and extracting behavioral patterns
from polymorphic and metamorphic code used in software licensing protections.
Handles real-world mutation engines like MetaPHOR, NGVCK, Zmist and commercial
polymorphic packers/protectors.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logger.warning("Capstone not available - polymorphic analysis limited")
    X86_OP_IMM = X86_OP_MEM = X86_OP_REG = None

R2PIPE_AVAILABLE = False


class MutationType(Enum):
    """Types of code mutations detected."""

    INSTRUCTION_SUBSTITUTION = "instruction_substitution"
    REGISTER_RENAMING = "register_renaming"
    CODE_REORDERING = "code_reordering"
    JUNK_INSERTION = "junk_insertion"
    DEAD_CODE = "dead_code"
    OPAQUE_PREDICATES = "opaque_predicates"
    SEMANTIC_NOP = "semantic_nop"
    INSTRUCTION_EXPANSION = "instruction_expansion"
    CONTROL_FLOW_FLATTENING = "control_flow_flattening"
    VIRTUALIZATION = "virtualization"


class PolymorphicEngine(Enum):
    """Known polymorphic engine types."""

    METAPHOR = "metaphor"
    NGVCK = "ngvck"
    ZMIST = "zmist"
    PRIZM = "prizm"
    RDA = "rda"
    CREATEPOLY = "createpoly"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


@dataclass
class InstructionNode:
    """Normalized instruction representation for semantic analysis."""

    semantic_class: str
    operand_types: Tuple[str, ...]
    data_dependencies: Set[str] = field(default_factory=set)
    control_dependencies: Set[str] = field(default_factory=set)
    side_effects: Set[str] = field(default_factory=set)
    semantic_hash: str = ""

    def __post_init__(self):
        """Compute semantic hash after initialization."""
        hash_components = [
            self.semantic_class,
            "".join(sorted(self.operand_types)),
            "".join(sorted(self.data_dependencies)),
            "".join(sorted(self.control_dependencies)),
            "".join(sorted(self.side_effects)),
        ]
        self.semantic_hash = hashlib.sha256("".join(hash_components).encode()).hexdigest()[:16]


@dataclass
class CodeBlock:
    """Code block with instructions and metadata."""

    start_address: int
    end_address: int
    instructions: List[Any]
    normalized_instructions: List[InstructionNode] = field(default_factory=list)
    semantic_signature: str = ""
    mutations_detected: List[MutationType] = field(default_factory=list)
    invariants: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviorPattern:
    """Extracted behavior pattern invariant across mutations."""

    pattern_id: str
    semantic_signature: str
    data_flow_graph: Dict[str, Set[str]]
    control_flow_graph: Dict[int, Set[int]]
    register_usage: Dict[str, str]
    memory_accesses: List[Tuple[str, int, int]]
    api_calls: List[str]
    constants: Set[int]
    behavioral_hash: str
    confidence: float = 1.0


@dataclass
class PolymorphicAnalysis:
    """Complete analysis result for polymorphic code."""

    engine_type: PolymorphicEngine
    mutation_types: List[MutationType]
    behavior_patterns: List[BehaviorPattern]
    invariant_features: Dict[str, Any]
    decryption_routine: Optional[CodeBlock] = None
    mutation_complexity: float = 0.0
    evasion_techniques: List[str] = field(default_factory=list)


class PolymorphicAnalyzer:
    """Advanced polymorphic and metamorphic code analyzer.

    Analyzes mutating code using semantic analysis, behavior extraction,
    and invariant detection to identify core functionality regardless of
    syntactic variations.
    """

    INSTRUCTION_SEMANTICS = {
        "mov": "data_transfer",
        "movzx": "data_transfer",
        "movsx": "data_transfer",
        "lea": "address_computation",
        "push": "stack_operation",
        "pop": "stack_operation",
        "add": "arithmetic",
        "sub": "arithmetic",
        "inc": "arithmetic",
        "dec": "arithmetic",
        "imul": "arithmetic",
        "idiv": "arithmetic",
        "mul": "arithmetic",
        "div": "arithmetic",
        "xor": "bitwise",
        "or": "bitwise",
        "and": "bitwise",
        "not": "bitwise",
        "shl": "bitwise",
        "shr": "bitwise",
        "rol": "bitwise",
        "ror": "bitwise",
        "cmp": "comparison",
        "test": "comparison",
        "jmp": "control_flow",
        "je": "control_flow",
        "jne": "control_flow",
        "jl": "control_flow",
        "jg": "control_flow",
        "jle": "control_flow",
        "jge": "control_flow",
        "call": "function_call",
        "ret": "function_return",
        "loop": "control_flow",
        "nop": "no_operation",
    }

    EQUIVALENT_INSTRUCTIONS = {
        frozenset(["xor reg, reg"]): "zero_register",
        frozenset(["sub reg, reg"]): "zero_register",
        frozenset(["mov reg, 0"]): "zero_register",
        frozenset(["add reg, 1", "inc reg"]): "increment",
        frozenset(["sub reg, 1", "dec reg"]): "decrement",
        frozenset(["push reg", "pop reg"]): "register_preserve",
        frozenset(["mov reg1, reg2", "xchg reg1, reg2", "xchg reg1, reg2"]): "swap_registers",
    }

    def __init__(self, binary_path: Optional[str] = None, arch: str = "x86", bits: int = 64) -> None:
        """Initialize the polymorphic analyzer.

        Args:
            binary_path: Path to binary being analyzed
            arch: Target architecture (x86, x64, arm)
            bits: Architecture bit width (32 or 64)

        """
        self.binary_path = binary_path
        self.arch = arch
        self.bits = bits

        if CAPSTONE_AVAILABLE:
            mode = CS_MODE_64 if bits == 64 else CS_MODE_32
            self.disassembler = Cs(CS_ARCH_X86, mode)
            self.disassembler.detail = True
        else:
            self.disassembler = None
            logger.warning("Capstone unavailable - disassembly disabled")

        self.semantic_cache: Dict[str, InstructionNode] = {}
        self.behavior_database: Dict[str, BehaviorPattern] = {}

    def analyze_polymorphic_code(
        self, data: bytes, base_address: int = 0, max_instructions: int = 1000,
    ) -> PolymorphicAnalysis:
        """Analyze polymorphic code and extract behavioral patterns.

        Args:
            data: Raw code bytes to analyze
            base_address: Base address for disassembly
            max_instructions: Maximum instructions to analyze

        Returns:
            Complete polymorphic analysis result

        """
        if not CAPSTONE_AVAILABLE or not self.disassembler:
            logger.error("Cannot analyze polymorphic code without Capstone")
            return PolymorphicAnalysis(
                engine_type=PolymorphicEngine.UNKNOWN,
                mutation_types=[],
                behavior_patterns=[],
                invariant_features={},
            )

        code_block = self._disassemble_block(data, base_address, max_instructions)

        engine_type = self._identify_polymorphic_engine(code_block)

        mutation_types = self._detect_mutations(code_block)

        self._normalize_instructions(code_block)

        behavior_patterns = self._extract_behavior_patterns(code_block)

        invariants = self._extract_invariants(code_block)

        decryption_routine = self._identify_decryption_routine(code_block)

        complexity = self._calculate_mutation_complexity(code_block, mutation_types)

        evasion_techniques = self._detect_evasion_techniques(code_block)

        return PolymorphicAnalysis(
            engine_type=engine_type,
            mutation_types=mutation_types,
            behavior_patterns=behavior_patterns,
            invariant_features=invariants,
            decryption_routine=decryption_routine,
            mutation_complexity=complexity,
            evasion_techniques=evasion_techniques,
        )

    def normalize_code_variant(self, data: bytes, base_address: int = 0) -> str:
        """Normalize a code variant to canonical form for pattern matching.

        Args:
            data: Raw code bytes
            base_address: Base address for disassembly

        Returns:
            Canonical normalized representation as hex string

        """
        if not CAPSTONE_AVAILABLE or not self.disassembler:
            return hashlib.sha256(data).hexdigest()

        code_block = self._disassemble_block(data, base_address, len(data))
        self._normalize_instructions(code_block)

        canonical_form = []
        for node in code_block.normalized_instructions:
            canonical_form.append(node.semantic_hash)

        return hashlib.sha256("".join(canonical_form).encode()).hexdigest()

    def extract_semantic_signature(self, data: bytes, base_address: int = 0) -> str:
        """Extract semantic signature that remains constant across mutations.

        Args:
            data: Raw code bytes
            base_address: Base address for disassembly

        Returns:
            Semantic signature string

        """
        if not CAPSTONE_AVAILABLE or not self.disassembler:
            return ""

        code_block = self._disassemble_block(data, base_address, len(data))
        self._normalize_instructions(code_block)

        signature_components = []

        for node in code_block.normalized_instructions:
            if node.semantic_class not in ["no_operation", "dead_code"]:
                signature_components.append(
                    f"{node.semantic_class}:{','.join(node.operand_types)}",
                )

        data_flow = self._analyze_data_flow(code_block)
        signature_components.append(f"DF:{len(data_flow)}")

        control_flow = self._analyze_control_flow(code_block)
        signature_components.append(f"CF:{len(control_flow)}")

        return hashlib.sha256("|".join(signature_components).encode()).hexdigest()

    def _disassemble_block(
        self, data: bytes, base_address: int, max_instructions: int,
    ) -> CodeBlock:
        """Disassemble code block into instructions."""
        instructions = []
        try:
            for insn in self.disassembler.disasm(data, base_address):
                instructions.append(insn)
                if len(instructions) >= max_instructions:
                    break
        except Exception as e:
            logger.error(f"Disassembly error: {e}")

        if not instructions:
            return CodeBlock(
                start_address=base_address,
                end_address=base_address,
                instructions=[],
            )

        return CodeBlock(
            start_address=instructions[0].address,
            end_address=instructions[-1].address + instructions[-1].size,
            instructions=instructions,
        )

    def _identify_polymorphic_engine(self, code_block: CodeBlock) -> PolymorphicEngine:
        """Identify the polymorphic engine type from code patterns."""
        if not code_block.instructions:
            return PolymorphicEngine.UNKNOWN

        mnemonics = [insn.mnemonic for insn in code_block.instructions[:100]]
        mnemonic_sequence = " ".join(mnemonics[:20])

        if "call" in mnemonics and "xor" in mnemonics and "loop" in mnemonics:
            xor_count = mnemonics.count("xor")
            loop_count = mnemonics.count("loop")

            if xor_count > 5 and loop_count > 2:
                return PolymorphicEngine.METAPHOR

        if "rdtsc" in mnemonics or "cpuid" in mnemonics:
            if "jmp" in mnemonics and mnemonics.count("jmp") > 10:
                return PolymorphicEngine.NGVCK

        if "push" in mnemonics and "pop" in mnemonics:
            push_count = mnemonics.count("push")
            pop_count = mnemonics.count("pop")
            if abs(push_count - pop_count) < 3 and push_count > 15:
                return PolymorphicEngine.ZMIST

        if "mov" in mnemonic_sequence and "add" in mnemonic_sequence:
            pattern_density = len(set(mnemonics)) / len(mnemonics) if mnemonics else 0
            if pattern_density > 0.6:
                return PolymorphicEngine.CUSTOM

        return PolymorphicEngine.UNKNOWN

    def _detect_mutations(self, code_block: CodeBlock) -> List[MutationType]:
        """Detect types of mutations present in code block."""
        mutations = []

        if self._detect_instruction_substitution(code_block):
            mutations.append(MutationType.INSTRUCTION_SUBSTITUTION)

        if self._detect_register_renaming(code_block):
            mutations.append(MutationType.REGISTER_RENAMING)

        if self._detect_junk_insertion(code_block):
            mutations.append(MutationType.JUNK_INSERTION)

        if self._detect_dead_code(code_block):
            mutations.append(MutationType.DEAD_CODE)

        if self._detect_opaque_predicates(code_block):
            mutations.append(MutationType.OPAQUE_PREDICATES)

        if self._detect_semantic_nops(code_block):
            mutations.append(MutationType.SEMANTIC_NOP)

        if self._detect_code_reordering(code_block):
            mutations.append(MutationType.CODE_REORDERING)

        return mutations

    def _detect_instruction_substitution(self, code_block: CodeBlock) -> bool:
        """Detect instruction substitution patterns."""
        if len(code_block.instructions) < 3:
            return False

        equivalent_sequences = 0
        i = 0

        while i < len(code_block.instructions) - 1:
            insn = code_block.instructions[i]
            next_insn = code_block.instructions[i + 1]

            if insn.mnemonic == "xor" and len(insn.operands) == 2:
                if self._operands_equal(insn.operands[0], insn.operands[1]):
                    equivalent_sequences += 1

            if insn.mnemonic == "add" and next_insn.mnemonic == "sub":
                if self._is_register_operand(insn.operands[0]):
                    equivalent_sequences += 1

            i += 1

        return equivalent_sequences >= 2

    def _detect_register_renaming(self, code_block: CodeBlock) -> bool:
        """Detect register renaming patterns."""
        register_uses: Dict[str, int] = defaultdict(int)

        for insn in code_block.instructions:
            for operand in insn.operands:
                if operand.type == X86_OP_REG:
                    reg_name = insn.reg_name(operand.reg)
                    register_uses[reg_name] += 1

        if not register_uses:
            return False

        max_uses = max(register_uses.values())
        min_uses = min(register_uses.values())

        if max_uses > 0 and min_uses > 0:
            ratio = max_uses / min_uses
            return ratio < 3.0

        return False

    def _detect_junk_insertion(self, code_block: CodeBlock) -> bool:
        """Detect junk code insertion."""
        junk_patterns = 0

        for i, insn in enumerate(code_block.instructions):
            if insn.mnemonic == "nop":
                junk_patterns += 1
                continue

            if insn.mnemonic in ["push", "pop"] and i < len(code_block.instructions) - 1:
                next_insn = code_block.instructions[i + 1]
                if next_insn.mnemonic == "pop" and insn.mnemonic == "push":
                    if len(insn.operands) > 0 and len(next_insn.operands) > 0:
                        if self._operands_equal(insn.operands[0], next_insn.operands[0]):
                            junk_patterns += 1

            if insn.mnemonic in ["mov", "lea"] and len(insn.operands) == 2:
                if self._operands_equal(insn.operands[0], insn.operands[1]):
                    junk_patterns += 1

        return junk_patterns >= 3

    def _detect_dead_code(self, code_block: CodeBlock) -> bool:
        """Detect dead code that doesn't affect program state."""
        dead_code_count = 0

        for i, insn in enumerate(code_block.instructions):
            if insn.mnemonic in ["xor", "sub"] and len(insn.operands) == 2:
                if self._operands_equal(insn.operands[0], insn.operands[1]):
                    if i < len(code_block.instructions) - 1:
                        next_insn = code_block.instructions[i + 1]
                        if next_insn.mnemonic == "mov":
                            dead_code_count += 1

        return dead_code_count >= 2

    def _detect_opaque_predicates(self, code_block: CodeBlock) -> bool:
        """Detect opaque predicates (conditions with constant outcomes)."""
        opaque_count = 0

        for i, insn in enumerate(code_block.instructions):
            if insn.mnemonic in ["cmp", "test"]:
                if i < len(code_block.instructions) - 1:
                    next_insn = code_block.instructions[i + 1]
                    if next_insn.mnemonic in ["je", "jne", "jz", "jnz"]:
                        if insn.mnemonic == "test" and len(insn.operands) == 2:
                            if self._operands_equal(insn.operands[0], insn.operands[1]):
                                opaque_count += 1

        return opaque_count >= 1

    def _detect_semantic_nops(self, code_block: CodeBlock) -> bool:
        """Detect semantic NOPs (operations with no net effect)."""
        semantic_nop_count = 0

        i = 0
        while i < len(code_block.instructions) - 1:
            insn = code_block.instructions[i]
            next_insn = code_block.instructions[i + 1]

            if insn.mnemonic in ["add", "sub", "xor", "or"] and next_insn.mnemonic in [
                "add",
                "sub",
                "xor",
                "or",
            ]:
                if len(insn.operands) >= 2 and len(next_insn.operands) >= 2:
                    if (
                        insn.mnemonic == "add"
                        and next_insn.mnemonic == "sub"
                        and self._operands_equal(insn.operands[0], next_insn.operands[0])
                    ):
                        if self._operands_equal(insn.operands[1], next_insn.operands[1]):
                            semantic_nop_count += 1

            i += 1

        return semantic_nop_count >= 1

    def _detect_code_reordering(self, code_block: CodeBlock) -> bool:
        """Detect code reordering patterns."""
        dependencies = self._analyze_data_dependencies(code_block)

        independent_sequences = 0
        for i in range(len(code_block.instructions) - 2):
            addr1 = code_block.instructions[i].address
            addr2 = code_block.instructions[i + 1].address
            addr3 = code_block.instructions[i + 2].address

            dep12 = addr2 in dependencies.get(addr1, set())
            dep23 = addr3 in dependencies.get(addr2, set())
            dep13 = addr3 in dependencies.get(addr1, set())

            if not dep12 and not dep23 and not dep13:
                independent_sequences += 1

        return independent_sequences >= 3

    def _normalize_instructions(self, code_block: CodeBlock) -> None:
        """Normalize instructions to semantic representation."""
        code_block.normalized_instructions = []

        for insn in code_block.instructions:
            node = self._create_instruction_node(insn)
            code_block.normalized_instructions.append(node)

        semantic_hashes = [node.semantic_hash for node in code_block.normalized_instructions]
        code_block.semantic_signature = hashlib.sha256(
            "".join(semantic_hashes).encode(),
        ).hexdigest()

    def _create_instruction_node(self, insn) -> InstructionNode:
        """Create normalized instruction node from disassembled instruction."""
        semantic_class = self.INSTRUCTION_SEMANTICS.get(insn.mnemonic, "other")

        operand_types = []
        for operand in insn.operands:
            if operand.type == X86_OP_REG:
                operand_types.append("reg")
            elif operand.type == X86_OP_IMM:
                operand_types.append("imm")
            elif operand.type == X86_OP_MEM:
                operand_types.append("mem")

        data_deps = set()
        control_deps = set()
        side_effects = set()

        if semantic_class == "data_transfer":
            if len(insn.operands) >= 2:
                src_type = "reg" if insn.operands[1].type == X86_OP_REG else "mem"
                data_deps.add(src_type)

        if semantic_class == "arithmetic":
            if len(insn.operands) >= 2:
                data_deps.add("reg")
            side_effects.add("flags")

        if semantic_class == "control_flow":
            control_deps.add("flags")

        if semantic_class == "function_call":
            side_effects.add("stack")
            side_effects.add("memory")

        if insn.mnemonic in ["push", "pop", "call", "ret"]:
            side_effects.add("stack")

        return InstructionNode(
            semantic_class=semantic_class,
            operand_types=tuple(operand_types),
            data_dependencies=data_deps,
            control_dependencies=control_deps,
            side_effects=side_effects,
        )

    def _extract_behavior_patterns(self, code_block: CodeBlock) -> List[BehaviorPattern]:
        """Extract invariant behavior patterns from code block."""
        patterns = []

        data_flow = self._analyze_data_flow(code_block)
        control_flow = self._analyze_control_flow(code_block)
        register_usage = self._analyze_register_usage(code_block)
        memory_accesses = self._analyze_memory_accesses(code_block)
        api_calls = self._extract_api_calls(code_block)
        constants = self._extract_constants(code_block)

        behavioral_components = [
            f"DF:{len(data_flow)}",
            f"CF:{len(control_flow)}",
            f"REG:{len(register_usage)}",
            f"MEM:{len(memory_accesses)}",
            f"API:{len(api_calls)}",
            f"CONST:{len(constants)}",
        ]

        behavioral_hash = hashlib.sha256("|".join(behavioral_components).encode()).hexdigest()

        pattern = BehaviorPattern(
            pattern_id=f"BP_{behavioral_hash[:16]}",
            semantic_signature=code_block.semantic_signature,
            data_flow_graph=data_flow,
            control_flow_graph=control_flow,
            register_usage=register_usage,
            memory_accesses=memory_accesses,
            api_calls=api_calls,
            constants=constants,
            behavioral_hash=behavioral_hash,
        )

        patterns.append(pattern)
        return patterns

    def _analyze_data_flow(self, code_block: CodeBlock) -> Dict[str, Set[str]]:
        """Analyze data flow between instructions."""
        data_flow: Dict[str, Set[str]] = defaultdict(set)

        for node in code_block.normalized_instructions:
            if node.semantic_class == "data_transfer":
                for dep in node.data_dependencies:
                    data_flow[node.semantic_hash].add(dep)

        return dict(data_flow)

    def _analyze_control_flow(self, code_block: CodeBlock) -> Dict[int, Set[int]]:
        """Analyze control flow graph."""
        cfg: Dict[int, Set[int]] = defaultdict(set)

        for i, insn in enumerate(code_block.instructions):
            if insn.mnemonic in ["jmp", "je", "jne", "jl", "jg", "call"]:
                if len(insn.operands) > 0 and insn.operands[0].type == X86_OP_IMM:
                    target = insn.operands[0].imm
                    cfg[insn.address].add(target)

            if i < len(code_block.instructions) - 1:
                if insn.mnemonic not in ["jmp", "ret"]:
                    next_insn = code_block.instructions[i + 1]
                    cfg[insn.address].add(next_insn.address)

        return dict(cfg)

    def _analyze_register_usage(self, code_block: CodeBlock) -> Dict[str, str]:
        """Analyze register usage patterns."""
        register_usage: Dict[str, str] = {}

        for insn in code_block.instructions:
            for operand in insn.operands:
                if operand.type == X86_OP_REG:
                    reg_name = insn.reg_name(operand.reg)
                    semantic = self.INSTRUCTION_SEMANTICS.get(insn.mnemonic, "other")
                    register_usage[reg_name] = semantic

        return register_usage

    def _analyze_memory_accesses(self, code_block: CodeBlock) -> List[Tuple[str, int, int]]:
        """Analyze memory access patterns."""
        accesses = []

        for insn in code_block.instructions:
            for operand in insn.operands:
                if operand.type == X86_OP_MEM:
                    access_type = "read" if insn.mnemonic in ["mov", "lea"] else "write"
                    size = operand.size if hasattr(operand, "size") else 0
                    accesses.append((access_type, insn.address, size))

        return accesses

    def _extract_api_calls(self, code_block: CodeBlock) -> List[str]:
        """Extract API call patterns."""
        api_calls = []

        for insn in code_block.instructions:
            if insn.mnemonic == "call":
                if len(insn.operands) > 0:
                    if insn.operands[0].type == X86_OP_IMM:
                        api_calls.append(f"call_{hex(insn.operands[0].imm)}")
                    elif insn.operands[0].type == X86_OP_REG:
                        reg_name = insn.reg_name(insn.operands[0].reg)
                        api_calls.append(f"call_{reg_name}")

        return api_calls

    def _extract_constants(self, code_block: CodeBlock) -> Set[int]:
        """Extract constant values used in code."""
        constants = set()

        for insn in code_block.instructions:
            for operand in insn.operands:
                if operand.type == X86_OP_IMM:
                    value = operand.imm
                    if 0 < value < 0x1000000:
                        constants.add(value)

        return constants

    def _extract_invariants(self, code_block: CodeBlock) -> Dict[str, Any]:
        """Extract code features that remain constant across mutations."""
        invariants = {}

        semantic_classes = [
            node.semantic_class
            for node in code_block.normalized_instructions
            if node.semantic_class not in ["no_operation", "dead_code"]
        ]
        invariants["semantic_sequence"] = tuple(semantic_classes)

        data_flow = self._analyze_data_flow(code_block)
        invariants["data_flow_depth"] = max([len(v) for v in data_flow.values()], default=0)

        control_flow = self._analyze_control_flow(code_block)
        invariants["control_flow_branches"] = len(
            [k for k, v in control_flow.items() if len(v) > 1],
        )

        constants = self._extract_constants(code_block)
        invariants["unique_constants"] = len(constants)

        api_calls = self._extract_api_calls(code_block)
        invariants["api_call_count"] = len(api_calls)

        return invariants

    def _identify_decryption_routine(self, code_block: CodeBlock) -> Optional[CodeBlock]:
        """Identify decryption/decoding routines in polymorphic code."""
        xor_instructions = []
        loop_instructions = []

        for i, insn in enumerate(code_block.instructions):
            if insn.mnemonic in ["xor", "xorps", "xorpd"]:
                xor_instructions.append(i)
            if insn.mnemonic in ["loop", "loope", "loopne"]:
                loop_instructions.append(i)

        if xor_instructions and loop_instructions:
            start_idx = max(0, min(xor_instructions) - 5)
            end_idx = min(len(code_block.instructions), max(loop_instructions) + 5)

            decryption_insns = code_block.instructions[start_idx:end_idx]

            if decryption_insns:
                return CodeBlock(
                    start_address=decryption_insns[0].address,
                    end_address=decryption_insns[-1].address + decryption_insns[-1].size,
                    instructions=decryption_insns,
                )

        return None

    def _calculate_mutation_complexity(
        self, code_block: CodeBlock, mutations: List[MutationType],
    ) -> float:
        """Calculate mutation complexity score."""
        if not code_block.instructions or not mutations:
            return 0.0

        base_score = len(mutations) / len(MutationType)

        instruction_diversity = len({insn.mnemonic for insn in code_block.instructions}) / len(
            code_block.instructions,
        )

        cfg = self._analyze_control_flow(code_block)
        control_complexity = len(cfg) / len(code_block.instructions) if cfg else 0

        complexity = (base_score * 0.5) + (instruction_diversity * 0.3) + (control_complexity * 0.2)

        return min(1.0, complexity)

    def _detect_evasion_techniques(self, code_block: CodeBlock) -> List[str]:
        """Detect anti-analysis evasion techniques."""
        techniques = []

        mnemonics = [insn.mnemonic for insn in code_block.instructions]

        if "rdtsc" in mnemonics:
            techniques.append("timing_check")

        if "cpuid" in mnemonics:
            techniques.append("vm_detection")

        if "int" in mnemonics:
            if any(
                insn.mnemonic == "int" and insn.operands[0].imm in [0x2D, 0x03]
                for insn in code_block.instructions
                if insn.mnemonic == "int" and len(insn.operands) > 0
            ):
                techniques.append("anti_debug")

        push_pop_count = mnemonics.count("push") + mnemonics.count("pop")
        if push_pop_count > len(code_block.instructions) * 0.3:
            techniques.append("stack_obfuscation")

        return techniques

    def _analyze_data_dependencies(self, code_block: CodeBlock) -> Dict[int, Set[int]]:
        """Analyze data dependencies between instructions."""
        dependencies: Dict[int, Set[int]] = defaultdict(set)

        register_definitions: Dict[str, int] = {}

        for insn in code_block.instructions:
            for operand in insn.operands:
                if operand.type == X86_OP_REG:
                    reg_name = insn.reg_name(operand.reg)

                    if reg_name in register_definitions:
                        dependencies[insn.address].add(register_definitions[reg_name])

            if len(insn.operands) > 0 and insn.operands[0].type == X86_OP_REG:
                reg_name = insn.reg_name(insn.operands[0].reg)
                register_definitions[reg_name] = insn.address

        return dict(dependencies)

    def _operands_equal(self, op1, op2) -> bool:
        """Check if two operands are equal."""
        if op1.type != op2.type:
            return False

        if op1.type == X86_OP_REG:
            return op1.reg == op2.reg
        elif op1.type == X86_OP_IMM:
            return op1.imm == op2.imm
        elif op1.type == X86_OP_MEM:
            return (
                op1.mem.base == op2.mem.base
                and op1.mem.index == op2.mem.index
                and op1.mem.disp == op2.mem.disp
            )

        return False

    def _is_register_operand(self, operand) -> bool:
        """Check if operand is a register."""
        return operand.type == X86_OP_REG

    def compare_code_variants(
        self, variant1: bytes, variant2: bytes, base_address: int = 0,
    ) -> Tuple[float, Dict[str, Any]]:
        """Compare two code variants and determine semantic similarity.

        Args:
            variant1: First code variant
            variant2: Second code variant
            base_address: Base address for disassembly

        Returns:
            Tuple of (similarity_score, similarity_details)

        """
        sig1 = self.extract_semantic_signature(variant1, base_address)
        sig2 = self.extract_semantic_signature(variant2, base_address)

        if sig1 == sig2:
            return 1.0, {"identical_semantics": True}

        analysis1 = self.analyze_polymorphic_code(variant1, base_address)
        analysis2 = self.analyze_polymorphic_code(variant2, base_address)

        similarity_score = 0.0
        details = {}

        if analysis1.invariant_features and analysis2.invariant_features:
            inv1 = analysis1.invariant_features
            inv2 = analysis2.invariant_features

            seq1 = inv1.get("semantic_sequence", ())
            seq2 = inv2.get("semantic_sequence", ())

            if seq1 == seq2:
                similarity_score += 0.5
                details["identical_semantic_sequence"] = True

            df1 = inv1.get("data_flow_depth", 0)
            df2 = inv2.get("data_flow_depth", 0)
            if df1 > 0 and df2 > 0:
                df_similarity = 1.0 - abs(df1 - df2) / max(df1, df2)
                similarity_score += df_similarity * 0.2
                details["data_flow_similarity"] = df_similarity

            cf1 = inv1.get("control_flow_branches", 0)
            cf2 = inv2.get("control_flow_branches", 0)
            if cf1 > 0 and cf2 > 0:
                cf_similarity = 1.0 - abs(cf1 - cf2) / max(cf1, cf2)
                similarity_score += cf_similarity * 0.2
                details["control_flow_similarity"] = cf_similarity

            const1 = inv1.get("unique_constants", 0)
            const2 = inv2.get("unique_constants", 0)
            if const1 > 0 and const2 > 0:
                const_similarity = 1.0 - abs(const1 - const2) / max(const1, const2)
                similarity_score += const_similarity * 0.1
                details["constant_similarity"] = const_similarity

        return similarity_score, details
