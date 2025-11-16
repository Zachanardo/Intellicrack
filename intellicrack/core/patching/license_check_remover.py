"""Advanced License Check Remover for Intellicrack.

Automatically identifies and patches license validation checks in binaries,
including serial validation, registration checks, and activation routines.
Features intelligent patch point selection with control flow, data flow, and
side-effect analysis for safe, targeted patching.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import logging
import shutil
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

try:
    import capstone

    CAPSTONE_AVAILABLE = True
except ImportError:
    capstone = None
    CAPSTONE_AVAILABLE = False

try:
    import keystone

    KEYSTONE_AVAILABLE = True
except ImportError:
    keystone = None
    KEYSTONE_AVAILABLE = False

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    pefile = None
    PEFILE_AVAILABLE = False

try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    nx = None
    NETWORKX_AVAILABLE = False

logger = logging.getLogger(__name__)


class CheckType(Enum):
    """Types of license checks."""

    SERIAL_VALIDATION = "serial_validation"
    REGISTRATION_CHECK = "registration_check"
    ACTIVATION_CHECK = "activation_check"
    TRIAL_CHECK = "trial_check"
    FEATURE_CHECK = "feature_check"
    ONLINE_VALIDATION = "online_validation"
    HARDWARE_CHECK = "hardware_check"
    DATE_CHECK = "date_check"
    SIGNATURE_CHECK = "signature_check"
    INTEGRITY_CHECK = "integrity_check"


@dataclass
class BasicBlock:
    """Represents a basic block in control flow analysis."""

    start_addr: int
    end_addr: int
    instructions: list[tuple[int, str, str]]
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    dominators: set[int] = field(default_factory=set)
    post_dominators: set[int] = field(default_factory=set)
    block_type: str = "normal"
    data_dependencies: dict[str, set[int]] = field(default_factory=lambda: defaultdict(set))
    def_use_chain: dict[str, list[int]] = field(default_factory=lambda: defaultdict(list))
    live_in: set[str] = field(default_factory=set)
    live_out: set[str] = field(default_factory=set)


@dataclass
class DataFlowInfo:
    """Data flow analysis information."""

    definitions: dict[str, set[int]]
    uses: dict[str, set[int]]
    reaching_definitions: dict[int, set[tuple[str, int]]]
    live_variables: dict[int, set[str]]
    tainted_registers: dict[int, set[str]]
    constant_propagation: dict[str, Any]
    alias_analysis: dict[str, set[str]]


@dataclass
class PatchPoint:
    """Represents an optimal patch point with safety analysis."""

    address: int
    block: BasicBlock
    patch_type: str
    safety_score: float
    side_effects: list[str]
    registers_modified: set[str]
    flags_modified: bool
    can_use_nop: bool
    can_use_jump: bool
    can_modify_return: bool
    alternative_points: list[int] = field(default_factory=list)
    data_dependencies: set[str] = field(default_factory=set)
    control_dependencies: list[int] = field(default_factory=list)
    risk_assessment: str = "low"
    rollback_strategy: str = "restore_original"


@dataclass
class LicenseCheck:
    """Represents a detected license check in the binary."""

    check_type: CheckType
    address: int
    size: int
    instructions: list[tuple[int, str, str]]
    confidence: float
    patch_strategy: str
    original_bytes: bytes
    patched_bytes: bytes
    patch_points: list[PatchPoint] = field(default_factory=list)
    control_flow_context: dict | None = None
    data_flow_context: DataFlowInfo | None = None
    critical_path: bool = False
    validated_safe: bool = False


class PatternMatcher:
    """Advanced pattern matching engine for modern license checks."""

    def __init__(self) -> None:
        """Initialize the ModernLicenseCheckRemover with pattern databases."""
        self.patterns = self._initialize_patterns()
        self.obfuscation_patterns = self._initialize_obfuscation_patterns()
        self.vm_patterns = self._initialize_vm_patterns()

    def _initialize_patterns(self) -> dict[str, dict]:
        """Initialize comprehensive license check patterns for modern software."""
        return {
            "serial_cmp": {
                "pattern": [("call", "strcmp|lstrcmp|memcmp|wcscmp|_stricmp"), ("test", "eax|rax"), ("j", "nz|ne")],
                "type": CheckType.SERIAL_VALIDATION,
                "confidence": 0.9,
            },
            "dotnet_license": {
                "pattern": [("call", "String.Equals|String.Compare"), ("brfalse|brtrue", "")],
                "type": CheckType.SERIAL_VALIDATION,
                "confidence": 0.85,
            },
            "cloud_validation": {
                "pattern": [
                    ("call", "HttpClient.SendAsync|WebRequest.Create"),
                    ("*", ""),
                    ("call", "Task.Result|GetAwaiter"),
                    ("test|cmp", ""),
                    ("j", ""),
                ],
                "type": CheckType.ONLINE_VALIDATION,
                "confidence": 0.9,
            },
            "modern_crypto": {
                "pattern": [("call", "ECDSA_verify|Ed25519_verify|EVP_DigestVerify"), ("test", "eax|rax"), ("j", "z|nz")],
                "type": CheckType.SIGNATURE_CHECK,
                "confidence": 0.95,
            },
            "tpm_check": {
                "pattern": [("call", "Tbsi_GetDeviceInfo|NCryptOpenStorageProvider"), ("*", ""), ("test", "eax|rax"), ("j", "")],
                "type": CheckType.HARDWARE_CHECK,
                "confidence": 0.85,
            },
            "ml_validation": {
                "pattern": [("call", "TensorFlow|ONNX|ML.NET"), ("*", ""), ("cmp", "threshold"), ("j", "")],
                "type": CheckType.ACTIVATION_CHECK,
                "confidence": 0.8,
            },
            "blockchain_check": {
                "pattern": [("call", "Web3|ethers|BlockCypher"), ("*", ""), ("test", ""), ("j", "")],
                "type": CheckType.ONLINE_VALIDATION,
                "confidence": 0.85,
            },
            "integrity_check": {
                "pattern": [("call", "CRC32|SHA256|HMAC"), ("cmp", "expected_hash"), ("j", "ne|nz")],
                "type": CheckType.INTEGRITY_CHECK,
                "confidence": 0.9,
            },
            "ntp_time_check": {
                "pattern": [("call", "NtpClient|GetNetworkTime"), ("*", ""), ("cmp", "expiry_time"), ("j", "g|ge")],
                "type": CheckType.DATE_CHECK,
                "confidence": 0.85,
            },
            "container_check": {
                "pattern": [("call", "File.Exists.*dockerenv|File.Exists.*containerenv"), ("test", ""), ("j", "")],
                "type": CheckType.INTEGRITY_CHECK,
                "confidence": 0.75,
            },
            "usb_dongle": {
                "pattern": [("call", "SetupDiGetClassDevs|HidD_GetAttributes"), ("*", ""), ("cmp", "vendor_id|product_id"), ("j", "")],
                "type": CheckType.HARDWARE_CHECK,
                "confidence": 0.85,
            },
        }

    def _initialize_obfuscation_patterns(self) -> dict[str, dict]:
        """Initialize patterns for obfuscated license checks."""
        return {
            "cff_license": {
                "pattern": [
                    ("mov", "state_var"),
                    ("*", ""),
                    ("switch|cmp", "state_var"),
                    ("*", ""),
                    ("mov", "eax|rax, 0|1"),
                ],
                "type": CheckType.SERIAL_VALIDATION,
                "confidence": 0.7,
            },
            "opaque_predicate": {
                "pattern": [("xor", "reg, reg"), ("add", "reg, constant"), ("imul", ""), ("cmp", ""), ("j", "always_taken")],
                "type": CheckType.INTEGRITY_CHECK,
                "confidence": 0.65,
            },
            "mba_check": {
                "pattern": [("and|or|xor", ""), ("not|neg", ""), ("add|sub", ""), ("and|or|xor", ""), ("cmp", "magic_value")],
                "type": CheckType.SERIAL_VALIDATION,
                "confidence": 0.7,
            },
        }

    def _initialize_vm_patterns(self) -> dict[str, dict]:
        """Initialize patterns for virtualized license checks."""
        return {
            "vmprotect_check": {
                "pattern": [
                    ("push", "encrypted_data"),
                    ("call", "vm_enter"),
                    ("*", ""),
                    ("pop", "result"),
                    ("test", "result"),
                ],
                "type": CheckType.ACTIVATION_CHECK,
                "confidence": 0.75,
            },
            "themida_check": {
                "pattern": [
                    ("db", "0xCC"),
                    ("push", "marker"),
                    ("call", "vm_dispatcher"),
                    ("*", ""),
                    ("cmp", "vm_result"),
                ],
                "type": CheckType.REGISTRATION_CHECK,
                "confidence": 0.7,
            },
        }

    def find_patterns(self, instructions: list[tuple[int, str, str]]) -> list[dict]:
        """Find all types of license check patterns including obfuscated ones."""
        matches = []

        for pattern_name, pattern_data in self.patterns.items():
            pattern = pattern_data["pattern"]

            for i in range(len(instructions) - len(pattern) + 1):
                if self._match_pattern(instructions[i:], pattern):
                    matches.append(
                        {
                            "name": pattern_name,
                            "type": pattern_data["type"],
                            "confidence": pattern_data["confidence"],
                            "start": i,
                            "length": len(pattern),
                        },
                    )

        for pattern_name, pattern_data in self.obfuscation_patterns.items():
            pattern = pattern_data["pattern"]

            for i in range(len(instructions) - len(pattern) + 1):
                if self._match_pattern(instructions[i:], pattern):
                    matches.append(
                        {
                            "name": pattern_name + "_obfuscated",
                            "type": pattern_data["type"],
                            "confidence": pattern_data["confidence"] * 0.9,
                            "start": i,
                            "length": len(pattern),
                        },
                    )

        for pattern_name, pattern_data in self.vm_patterns.items():
            pattern = pattern_data["pattern"]

            for i in range(len(instructions) - len(pattern) + 1):
                if self._match_pattern(instructions[i:], pattern):
                    matches.append(
                        {
                            "name": pattern_name + "_virtualized",
                            "type": pattern_data["type"],
                            "confidence": pattern_data["confidence"] * 0.85,
                            "start": i,
                            "length": len(pattern),
                        },
                    )

        return matches

    def _match_pattern(self, instructions: list[tuple[int, str, str]], pattern: list[tuple[str, str]]) -> bool:
        """Check if instructions match pattern."""
        for i, (p_mnem, p_ops) in enumerate(pattern):
            if i >= len(instructions):
                return False

            _, mnem, ops = instructions[i]

            if p_mnem == "*":
                continue

            if "|" in p_mnem:
                if mnem.lower() not in p_mnem.lower().split("|"):
                    return False
            elif mnem.lower() != p_mnem.lower():
                if not mnem.lower().startswith(p_mnem.lower()):
                    return False

            if p_ops and "|" in p_ops:
                found = False
                for possible_op in p_ops.split("|"):
                    if possible_op.lower() in ops.lower():
                        found = True
                        break
                if not found:
                    return False
            elif p_ops and p_ops.lower() not in ops.lower():
                return False

        return True


class DataFlowAnalyzer:
    """Advanced data flow analysis for tracking license-related data."""

    def __init__(self, cfg_analyzer: object) -> None:
        """Initialize data flow analyzer.

        Args:
            cfg_analyzer: Control flow graph analyzer instance.

        """
        self.cfg_analyzer = cfg_analyzer
        self.reaching_defs = {}
        self.live_vars = {}
        self.taint_sources = set()
        self.tainted_data = defaultdict(set)

    def analyze_data_flow(self, instructions: list[tuple[int, str, str]]) -> DataFlowInfo:
        """Perform comprehensive data flow analysis."""
        if not self.cfg_analyzer.basic_blocks:
            return self._create_empty_dataflow_info()

        definitions = defaultdict(set)
        uses = defaultdict(set)

        for _addr, block in self.cfg_analyzer.basic_blocks.items():
            for insn_addr, mnem, ops in block.instructions:
                defined_regs = self._get_defined_registers(mnem, ops)
                used_regs = self._get_used_registers(mnem, ops)

                for reg in defined_regs:
                    definitions[reg].add(insn_addr)

                for reg in used_regs:
                    uses[reg].add(insn_addr)

        reaching_defs = self._compute_reaching_definitions(definitions)
        live_vars = self._compute_live_variables(uses, definitions)
        tainted = self._perform_taint_analysis(instructions)
        constants = self._propagate_constants(instructions)
        aliases = self._analyze_aliases(instructions)

        return DataFlowInfo(
            definitions=definitions,
            uses=uses,
            reaching_definitions=reaching_defs,
            live_variables=live_vars,
            tainted_registers=tainted,
            constant_propagation=constants,
            alias_analysis=aliases,
        )

    def _create_empty_dataflow_info(self) -> DataFlowInfo:
        """Create empty data flow info structure."""
        return DataFlowInfo(
            definitions=defaultdict(set),
            uses=defaultdict(set),
            reaching_definitions=defaultdict(set),
            live_variables=defaultdict(set),
            tainted_registers=defaultdict(set),
            constant_propagation={},
            alias_analysis=defaultdict(set),
        )

    def _get_defined_registers(self, mnemonic: str, operands: str) -> set[str]:
        """Extract registers that are defined (written) by instruction."""
        defined = set()

        write_mnemonics = ["mov", "lea", "add", "sub", "xor", "or", "and", "inc", "dec", "shl", "shr", "imul", "idiv", "neg", "not"]

        if mnemonic in write_mnemonics:
            parts = operands.split(",")
            if parts:
                dest = parts[0].strip().lower()
                for reg in self._get_all_registers():
                    if reg in dest and not any(ptr in dest for ptr in ["ptr", "[", "]"]):
                        defined.add(reg)

        if mnemonic == "pop":
            for reg in self._get_all_registers():
                if reg in operands.lower():
                    defined.add(reg)

        if mnemonic in ["call", "syscall"]:
            defined.update(["eax", "rax", "ecx", "rcx", "edx", "rdx"])

        return defined

    def _get_used_registers(self, mnemonic: str, operands: str) -> set[str]:
        """Extract registers that are used (read) by instruction."""
        used = set()
        operands_lower = operands.lower()

        for reg in self._get_all_registers():
            if reg in operands_lower:
                used.add(reg)

        if mnemonic in ["mov", "lea", "add", "sub", "xor", "or", "and"]:
            parts = operands.split(",")
            if len(parts) > 1:
                src = parts[1].strip().lower()
                for reg in self._get_all_registers():
                    if reg in src:
                        used.add(reg)

        return used

    def _get_all_registers(self) -> list[str]:
        """Get list of all x86/x64 registers to track."""
        return [
            "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
        ]

    def _compute_reaching_definitions(self, definitions: dict[str, set[int]]) -> dict[int, set[tuple[str, int]]]:
        """Compute reaching definitions for each instruction."""
        reaching = defaultdict(set)

        for addr, block in self.cfg_analyzer.basic_blocks.items():
            gen_set = set()
            kill_set = set()

            for insn_addr, mnem, ops in block.instructions:
                defined_regs = self._get_defined_registers(mnem, ops)

                for reg in defined_regs:
                    for def_addr in definitions[reg]:
                        if def_addr != insn_addr:
                            kill_set.add((reg, def_addr))
                    gen_set.add((reg, insn_addr))

            reaching[addr] = gen_set

        changed = True
        iterations = 0
        max_iterations = len(self.cfg_analyzer.basic_blocks) * 10

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for addr, block in self.cfg_analyzer.basic_blocks.items():
                in_set = set()
                for pred in block.predecessors:
                    if pred in reaching:
                        in_set.update(reaching[pred])

                old_out = reaching[addr].copy()
                gen_set = set()
                kill_set = set()

                for insn_addr, mnem, ops in block.instructions:
                    defined_regs = self._get_defined_registers(mnem, ops)
                    for reg in defined_regs:
                        kill_set.update((r, a) for r, a in in_set if r == reg)
                        gen_set.add((reg, insn_addr))

                reaching[addr] = (in_set - kill_set) | gen_set

                if reaching[addr] != old_out:
                    changed = True

        return reaching

    def _compute_live_variables(self, uses: dict[str, set[int]], definitions: dict[str, set[int]]) -> dict[int, set[str]]:
        """Compute live variables at each program point."""
        live = defaultdict(set)

        for addr, block in self.cfg_analyzer.basic_blocks.items():
            out_set = set()

            for succ in block.successors:
                if succ in self.cfg_analyzer.basic_blocks:
                    for _insn_addr, mnem, ops in self.cfg_analyzer.basic_blocks[succ].instructions:
                        used_regs = self._get_used_registers(mnem, ops)
                        out_set.update(used_regs)

            live[addr] = out_set

        changed = True
        iterations = 0
        max_iterations = len(self.cfg_analyzer.basic_blocks) * 10

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for addr, block in self.cfg_analyzer.basic_blocks.items():
                old_live = live[addr].copy()

                out_set = set()
                for succ in block.successors:
                    if succ in live:
                        out_set.update(live[succ])

                in_set = out_set.copy()
                for _insn_addr, mnem, ops in reversed(block.instructions):
                    defined_regs = self._get_defined_registers(mnem, ops)
                    used_regs = self._get_used_registers(mnem, ops)

                    in_set.difference_update(defined_regs)
                    in_set.update(used_regs)

                live[addr] = in_set

                if live[addr] != old_live:
                    changed = True

        return live

    def _perform_taint_analysis(self, instructions: list[tuple[int, str, str]]) -> dict[int, set[str]]:
        """Track tainted data from license-related sources."""
        tainted = defaultdict(set)

        taint_sources = ["serial", "license", "key", "activation", "registration", "hwid", "machine"]

        for addr, mnem, ops in instructions:
            ops_lower = ops.lower()

            for source in taint_sources:
                if source in ops_lower:
                    defined_regs = self._get_defined_registers(mnem, ops)
                    tainted[addr].update(defined_regs)

        changed = True
        iterations = 0
        max_iterations = len(instructions) * 5

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for addr, mnem, ops in instructions:
                used_regs = self._get_used_registers(mnem, ops)
                defined_regs = self._get_defined_registers(mnem, ops)

                old_taint = tainted[addr].copy()

                for reg in used_regs:
                    if any(reg in tainted[prev_addr] for prev_addr, _, _ in instructions if prev_addr < addr):
                        tainted[addr].update(defined_regs)

                if tainted[addr] != old_taint:
                    changed = True

        return tainted

    def _propagate_constants(self, instructions: list[tuple[int, str, str]]) -> dict[str, Any]:
        """Propagate constant values through the program."""
        constants = {}

        for _addr, mnem, ops in instructions:
            if mnem == "mov":
                parts = ops.split(",")
                if len(parts) == 2:
                    dest = parts[0].strip()
                    src = parts[1].strip()

                    try:
                        if src.startswith("0x"):
                            value = int(src, 16)
                            constants[dest] = value
                        elif src.isdigit():
                            value = int(src)
                            constants[dest] = value
                    except ValueError:
                        pass

            elif mnem in ["xor", "sub"] and "," in ops:
                parts = ops.split(",")
                if len(parts) == 2 and parts[0].strip() == parts[1].strip():
                    constants[parts[0].strip()] = 0

        return constants

    def _analyze_aliases(self, instructions: list[tuple[int, str, str]]) -> dict[str, set[str]]:
        """Analyze register aliasing."""
        aliases = defaultdict(set)

        for _addr, mnem, ops in instructions:
            if mnem == "mov":
                parts = ops.split(",")
                if len(parts) == 2:
                    dest = parts[0].strip()
                    src = parts[1].strip()

                    if not any(x in src for x in ["[", "]", "ptr", "0x"]):
                        aliases[dest].add(src)
                        aliases[src].add(dest)

        return aliases


class ControlFlowAnalyzer:
    """Sophisticated control flow analysis for identifying optimal patch points."""

    def __init__(self, disassembler: object) -> None:
        """Initialize control flow analyzer.

        Args:
            disassembler: Capstone disassembler instance.

        """
        self.disassembler = disassembler
        self.basic_blocks = {}
        self.cfg_graph = nx.DiGraph() if NETWORKX_AVAILABLE else None
        self.dominator_tree = {}
        self.post_dominator_tree = {}

    def build_cfg(self, instructions: list[tuple[int, str, str]]) -> dict[int, BasicBlock]:
        """Build comprehensive control flow graph from instructions."""
        if not instructions:
            return {}

        leaders = self._identify_leaders(instructions)
        self.basic_blocks = self._construct_basic_blocks(instructions, leaders)
        self._link_basic_blocks()
        self._compute_dominators()
        self._compute_post_dominators()
        self._classify_blocks()

        if self.cfg_graph is not None:
            self._build_networkx_graph()

        return self.basic_blocks

    def _identify_leaders(self, instructions: list[tuple[int, str, str]]) -> set[int]:
        """Identify instruction addresses that start basic blocks."""
        leaders = {instructions[0][0]}

        for i, (addr, mnem, ops) in enumerate(instructions):
            if mnem in ["ret", "retn", "jmp"] or mnem.startswith("j"):
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1][0])

                if mnem not in {"ret", "retn"}:
                    target = self._parse_jump_target(ops, addr)
                    if target:
                        leaders.add(target)

            elif mnem == "call":
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1][0])

        return leaders

    def _parse_jump_target(self, operands: str, current_addr: int) -> int | None:
        """Parse jump target from operands."""
        try:
            if "0x" in operands:
                target_str = operands.split("0x")[1].split()[0].rstrip(",")
                return int(target_str, 16)
        except (ValueError, IndexError):
            pass
        return None

    def _construct_basic_blocks(self, instructions: list[tuple[int, str, str]], leaders: set[int]) -> dict[int, BasicBlock]:
        """Construct basic blocks from instructions and leaders."""
        blocks = {}
        current_block_insns = []
        current_start = None

        for addr, mnem, ops in instructions:
            if addr in leaders and current_block_insns:
                block = BasicBlock(
                    start_addr=current_start,
                    end_addr=current_block_insns[-1][0],
                    instructions=current_block_insns,
                )
                blocks[current_start] = block
                current_block_insns = []
                current_start = None

            if current_start is None:
                current_start = addr

            current_block_insns.append((addr, mnem, ops))

            if mnem in ["ret", "retn", "jmp"] or (mnem.startswith("j") and mnem != "jmp"):
                if current_block_insns:
                    block = BasicBlock(
                        start_addr=current_start,
                        end_addr=addr,
                        instructions=current_block_insns,
                    )
                    blocks[current_start] = block
                    current_block_insns = []
                    current_start = None

        if current_block_insns:
            block = BasicBlock(
                start_addr=current_start,
                end_addr=current_block_insns[-1][0],
                instructions=current_block_insns,
            )
            blocks[current_start] = block

        return blocks

    def _link_basic_blocks(self) -> None:
        """Link basic blocks by computing successors and predecessors."""
        for start_addr, block in self.basic_blocks.items():
            last_insn = block.instructions[-1]
            addr, mnem, ops = last_insn

            if mnem in ["ret", "retn"]:
                continue
            if mnem == "jmp":
                target = self._parse_jump_target(ops, addr)
                if target and target in self.basic_blocks:
                    block.successors.append(target)
                    self.basic_blocks[target].predecessors.append(start_addr)
            elif mnem.startswith("j"):
                target = self._parse_jump_target(ops, addr)
                if target and target in self.basic_blocks:
                    block.successors.append(target)
                    self.basic_blocks[target].predecessors.append(start_addr)

                next_addr = self._find_next_block(start_addr)
                if next_addr:
                    block.successors.append(next_addr)
                    self.basic_blocks[next_addr].predecessors.append(start_addr)
            else:
                next_addr = self._find_next_block(start_addr)
                if next_addr:
                    block.successors.append(next_addr)
                    self.basic_blocks[next_addr].predecessors.append(start_addr)

    def _find_next_block(self, current_addr: int) -> int | None:
        """Find the next basic block after the current one."""
        sorted_addrs = sorted(self.basic_blocks.keys())
        try:
            idx = sorted_addrs.index(current_addr)
            if idx + 1 < len(sorted_addrs):
                return sorted_addrs[idx + 1]
        except ValueError:
            pass
        return None

    def _compute_dominators(self) -> None:
        """Compute dominator sets for all basic blocks."""
        if not self.basic_blocks:
            return

        all_blocks = set(self.basic_blocks.keys())
        entry_block = min(self.basic_blocks.keys())

        for addr in self.basic_blocks:
            if addr == entry_block:
                self.basic_blocks[addr].dominators = {addr}
            else:
                self.basic_blocks[addr].dominators = all_blocks.copy()

        changed = True
        iterations = 0
        max_iterations = len(self.basic_blocks) * 10

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for addr, block in self.basic_blocks.items():
                if addr == entry_block:
                    continue

                if not block.predecessors:
                    continue

                new_dom = all_blocks.copy()
                for pred in block.predecessors:
                    if pred in self.basic_blocks:
                        new_dom &= self.basic_blocks[pred].dominators

                new_dom.add(addr)

                if new_dom != block.dominators:
                    block.dominators = new_dom
                    changed = True

    def _compute_post_dominators(self) -> None:
        """Compute post-dominator sets for all basic blocks."""
        if not self.basic_blocks:
            return

        all_blocks = set(self.basic_blocks.keys())
        exit_blocks = [addr for addr, block in self.basic_blocks.items() if not block.successors]

        if not exit_blocks:
            return

        for addr in self.basic_blocks:
            if addr in exit_blocks:
                self.basic_blocks[addr].post_dominators = {addr}
            else:
                self.basic_blocks[addr].post_dominators = all_blocks.copy()

        changed = True
        iterations = 0
        max_iterations = len(self.basic_blocks) * 10

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for addr, block in self.basic_blocks.items():
                if addr in exit_blocks:
                    continue

                if not block.successors:
                    continue

                new_post_dom = all_blocks.copy()
                for succ in block.successors:
                    if succ in self.basic_blocks:
                        new_post_dom &= self.basic_blocks[succ].post_dominators

                new_post_dom.add(addr)

                if new_post_dom != block.post_dominators:
                    block.post_dominators = new_post_dom
                    changed = True

    def _classify_blocks(self) -> None:
        """Classify basic blocks by type."""
        for _addr, block in self.basic_blocks.items():
            last_insn = block.instructions[-1] if block.instructions else None
            if not last_insn:
                continue

            _, mnem, _ = last_insn

            if mnem in ["ret", "retn"]:
                block.block_type = "return"
            elif mnem == "jmp":
                block.block_type = "unconditional_jump"
            elif mnem.startswith("j"):
                block.block_type = "conditional_branch"
            elif mnem == "call":
                block.block_type = "call"
            else:
                block.block_type = "normal"

    def _build_networkx_graph(self) -> None:
        """Build NetworkX graph for advanced analysis."""
        if not NETWORKX_AVAILABLE:
            return

        for addr, block in self.basic_blocks.items():
            self.cfg_graph.add_node(addr, block=block)

        for addr, block in self.basic_blocks.items():
            for succ in block.successors:
                self.cfg_graph.add_edge(addr, succ)

    def find_common_post_dominator(self, block_addrs: list[int]) -> int | None:
        """Find common post-dominator for multiple blocks."""
        if not block_addrs or not self.basic_blocks:
            return None

        common_post_doms = self.basic_blocks[block_addrs[0]].post_dominators.copy()

        for addr in block_addrs[1:]:
            if addr in self.basic_blocks:
                common_post_doms &= self.basic_blocks[addr].post_dominators

        if common_post_doms:
            return min(common_post_doms)
        return None

    def find_error_handlers(self) -> list[int]:
        """Identify error handler blocks in the control flow."""
        error_blocks = []

        for addr, block in self.basic_blocks.items():
            if block.block_type == "return" and len(block.predecessors) > 2:
                error_blocks.append(addr)

            for _insn_addr, _mnem, ops in block.instructions:
                if any(keyword in ops.lower() for keyword in ["error", "invalid", "fail"]):
                    error_blocks.append(addr)
                    break

        return error_blocks

    def find_validation_branches(self) -> list[tuple[int, int, int]]:
        """Find validation branch patterns (test/cmp followed by conditional jump)."""
        validation_branches = []

        for addr, block in self.basic_blocks.items():
            instructions = block.instructions

            for i in range(len(instructions) - 1):
                current_insn = instructions[i]
                next_insn = instructions[i + 1]

                _, curr_mnem, _ = current_insn
                _, next_mnem, _ = next_insn

                if curr_mnem in ["test", "cmp"] and next_mnem.startswith("j") and next_mnem not in ["jmp"]:
                    if len(block.successors) == 2:
                        validation_branches.append((addr, block.successors[0], block.successors[1]))

        return validation_branches


class SideEffectAnalyzer:
    """Analyzes side effects of instructions and patch points."""

    def __init__(self, cfg_analyzer: object, data_flow_analyzer: object) -> None:
        """Initialize side effect analyzer.

        Args:
            cfg_analyzer: Control flow graph analyzer instance.
            data_flow_analyzer: Data flow analyzer instance.

        """
        self.cfg_analyzer = cfg_analyzer
        self.data_flow_analyzer = data_flow_analyzer

    def analyze_side_effects(self, patch_point: PatchPoint, context_instructions: list[tuple[int, str, str]]) -> dict:
        """Analyze comprehensive side effects of patching at this point."""
        side_effects = {
            "breaks_functionality": False,
            "affects_critical_path": False,
            "corrupts_data": False,
            "breaks_stack": False,
            "invalidates_assumptions": False,
            "risk_level": "low",
            "mitigation_strategies": [],
        }

        block = patch_point.block

        if self._is_on_critical_path(block):
            side_effects["affects_critical_path"] = True
            side_effects["risk_level"] = "high"

        if self._breaks_stack_integrity(patch_point):
            side_effects["breaks_stack"] = True
            side_effects["risk_level"] = "critical"
            side_effects["mitigation_strategies"].append("preserve_stack_pointer")

        if self._corrupts_data_dependencies(patch_point):
            side_effects["corrupts_data"] = True
            side_effects["risk_level"] = "high"
            side_effects["mitigation_strategies"].append("preserve_data_flow")

        if self._breaks_control_flow_assumptions(patch_point):
            side_effects["invalidates_assumptions"] = True
            side_effects["mitigation_strategies"].append("redirect_control_flow")

        return side_effects

    def _is_on_critical_path(self, block: BasicBlock) -> bool:
        """Check if block is on a critical execution path."""
        if block.block_type == "return" and len(block.predecessors) > 5:
            return True

        return bool(any("main" in str(insn) for insn in block.instructions))

    def _breaks_stack_integrity(self, patch_point: PatchPoint) -> bool:
        """Check if patching would break stack integrity."""
        stack_ops = ["push", "pop", "call", "ret"]

        for insn_addr, mnem, _ops in patch_point.block.instructions:
            if insn_addr == patch_point.address:
                if mnem in stack_ops:
                    return True

        return bool("esp" in patch_point.registers_modified or "rsp" in patch_point.registers_modified)

    def _corrupts_data_dependencies(self, patch_point: PatchPoint) -> bool:
        """Check if patching would corrupt data dependencies."""
        if not hasattr(patch_point.block, 'data_dependencies'):
            return False

        critical_deps = patch_point.data_dependencies

        for reg in patch_point.registers_modified:
            if reg in critical_deps:
                return True

        return False

    def _breaks_control_flow_assumptions(self, patch_point: PatchPoint) -> bool:
        """Check if patching breaks control flow assumptions."""
        if patch_point.patch_type == "jump_redirect":
            if len(patch_point.alternative_points) == 0:
                return True

        return bool(patch_point.block.block_type == "conditional_branch" and len(patch_point.block.successors) != 2)


class RiskAssessmentEngine:
    """Advanced risk assessment for patch points."""

    def __init__(self, cfg_analyzer: object, data_flow_analyzer: object, side_effect_analyzer: object) -> None:
        """Initialize risk assessment engine.

        Args:
            cfg_analyzer: Control flow graph analyzer instance.
            data_flow_analyzer: Data flow analyzer instance.
            side_effect_analyzer: Side effect analyzer instance.

        """
        self.cfg_analyzer = cfg_analyzer
        self.data_flow_analyzer = data_flow_analyzer
        self.side_effect_analyzer = side_effect_analyzer

    def assess_patch_risk(self, patch_point: PatchPoint, license_check: LicenseCheck) -> str:
        """Comprehensive risk assessment for patch point."""
        risk_score = 0.0

        risk_score += self._assess_control_flow_risk(patch_point) * 0.3
        risk_score += self._assess_data_flow_risk(patch_point) * 0.3
        risk_score += self._assess_side_effect_risk(patch_point) * 0.2
        risk_score += self._assess_structural_risk(patch_point) * 0.2

        if risk_score < 0.3:
            return "low"
        if risk_score < 0.6:
            return "medium"
        if risk_score < 0.8:
            return "high"
        return "critical"

    def _assess_control_flow_risk(self, patch_point: PatchPoint) -> float:
        """Assess control flow related risks."""
        risk = 0.0

        if patch_point.patch_type == "jump_redirect":
            if len(patch_point.alternative_points) == 0:
                risk += 0.8
            elif len(patch_point.alternative_points) == 1:
                risk += 0.3

        if patch_point.block.block_type == "return":
            risk += 0.5

        if len(patch_point.control_dependencies) > 3:
            risk += 0.4

        return min(risk, 1.0)

    def _assess_data_flow_risk(self, patch_point: PatchPoint) -> float:
        """Assess data flow related risks."""
        risk = 0.0

        if len(patch_point.data_dependencies) > 5:
            risk += 0.5

        if len(patch_point.registers_modified) > 3:
            risk += 0.3

        if "esp" in patch_point.registers_modified or "rsp" in patch_point.registers_modified:
            risk += 0.7

        return min(risk, 1.0)

    def _assess_side_effect_risk(self, patch_point: PatchPoint) -> float:
        """Assess side effect risks."""
        risk = 0.0

        dangerous_effects = ["function_call", "stack_pointer_modification", "memory_access"]

        for effect in patch_point.side_effects:
            if effect in dangerous_effects:
                risk += 0.4

        if len(patch_point.side_effects) > 4:
            risk += 0.3

        return min(risk, 1.0)

    def _assess_structural_risk(self, patch_point: PatchPoint) -> float:
        """Assess structural risks."""
        risk = 0.0

        if patch_point.safety_score < 0.5:
            risk += 0.6

        if not patch_point.can_use_nop and not patch_point.can_use_jump and not patch_point.can_modify_return:
            risk += 0.8

        return min(risk, 1.0)


class PatchPointSelector:
    """Select optimal patch points with safety analysis."""

    def __init__(self, cfg_analyzer: object, disassembler: object) -> None:
        """Initialize patch point selector.

        Args:
            cfg_analyzer: Control flow graph analyzer instance.
            disassembler: Capstone disassembler instance.

        """
        self.cfg_analyzer = cfg_analyzer
        self.disassembler = disassembler
        self.data_flow_analyzer = DataFlowAnalyzer(cfg_analyzer)
        self.side_effect_analyzer = None
        self.risk_assessor = None

    def select_optimal_patch_points(self, license_check: LicenseCheck, instructions: list[tuple[int, str, str]]) -> list[PatchPoint]:
        """Select optimal patch points for a license check with safety analysis."""
        patch_points = []

        check_addr = license_check.address
        check_block = self._find_containing_block(check_addr)

        if not check_block:
            return []

        data_flow = self.data_flow_analyzer.analyze_data_flow(instructions)
        license_check.data_flow_context = data_flow

        self.side_effect_analyzer = SideEffectAnalyzer(self.cfg_analyzer, self.data_flow_analyzer)
        self.risk_assessor = RiskAssessmentEngine(self.cfg_analyzer, self.data_flow_analyzer, self.side_effect_analyzer)

        nop_points = self._analyze_nop_points(check_block, check_addr, data_flow)
        patch_points.extend(nop_points)

        jump_points = self._analyze_jump_redirection_points(check_block, check_addr, data_flow)
        patch_points.extend(jump_points)

        return_points = self._analyze_return_modification_points(check_block, check_addr, data_flow)
        patch_points.extend(return_points)

        post_dom = self.cfg_analyzer.find_common_post_dominator([check_block.start_addr])
        if post_dom:
            convergence_points = self._analyze_convergence_points(post_dom, data_flow)
            patch_points.extend(convergence_points)

        for point in patch_points:
            side_effects = self.side_effect_analyzer.analyze_side_effects(point, instructions)
            point.risk_assessment = self.risk_assessor.assess_patch_risk(point, license_check)

            if side_effects["risk_level"] == "critical":
                point.safety_score *= 0.5
            elif side_effects["risk_level"] == "high":
                point.safety_score *= 0.7

        patch_points.sort(key=lambda p: p.safety_score, reverse=True)

        return patch_points

    def _find_containing_block(self, address: int) -> BasicBlock | None:
        """Find the basic block containing the given address."""
        for block in self.cfg_analyzer.basic_blocks.values():
            if block.start_addr <= address <= block.end_addr:
                return block
        return None

    def _analyze_nop_points(self, block: BasicBlock, check_addr: int, data_flow: DataFlowInfo) -> list[PatchPoint]:
        """Analyze NOP-safe patch points."""
        nop_points = []

        for insn_addr, mnem, ops in block.instructions:
            if insn_addr < check_addr:
                continue

            side_effects = self._analyze_side_effects(mnem, ops)
            regs_modified = self._get_modified_registers(mnem, ops)
            flags_modified = self._modifies_flags(mnem)

            live_at_point = data_flow.live_variables.get(insn_addr, set())
            data_deps = set()
            for reg in regs_modified:
                if reg in live_at_point:
                    data_deps.add(reg)

            if not side_effects and len(regs_modified) <= 1:
                safety_score = 0.9
                if not flags_modified:
                    safety_score = 0.95
                if len(data_deps) == 0:
                    safety_score = 0.98

                patch_point = PatchPoint(
                    address=insn_addr,
                    block=block,
                    patch_type="nop",
                    safety_score=safety_score,
                    side_effects=side_effects,
                    registers_modified=regs_modified,
                    flags_modified=flags_modified,
                    can_use_nop=True,
                    can_use_jump=False,
                    can_modify_return=False,
                    data_dependencies=data_deps,
                    control_dependencies=[],
                )
                nop_points.append(patch_point)

        return nop_points

    def _analyze_jump_redirection_points(self, block: BasicBlock, check_addr: int, data_flow: DataFlowInfo) -> list[PatchPoint]:
        """Analyze jump redirection patch points."""
        jump_points = []

        if block.block_type == "conditional_branch":
            last_insn = block.instructions[-1]
            insn_addr, mnem, _ops = last_insn

            if mnem.startswith("j") and mnem != "jmp":
                side_effects = ["control_flow_redirect"]
                regs_modified = set()
                flags_modified = False

                safety_score = 0.85
                if len(block.successors) == 2:
                    safety_score = 0.9

                control_deps = block.predecessors.copy()

                patch_point = PatchPoint(
                    address=insn_addr,
                    block=block,
                    patch_type="jump_redirect",
                    safety_score=safety_score,
                    side_effects=side_effects,
                    registers_modified=regs_modified,
                    flags_modified=flags_modified,
                    can_use_nop=False,
                    can_use_jump=True,
                    can_modify_return=False,
                    alternative_points=list(block.successors),
                    control_dependencies=control_deps,
                )
                jump_points.append(patch_point)

        return jump_points

    def _analyze_return_modification_points(self, block: BasicBlock, check_addr: int, data_flow: DataFlowInfo) -> list[PatchPoint]:
        """Analyze return value modification patch points."""
        return_points = []

        for i, (insn_addr, mnem, ops) in enumerate(block.instructions):
            if insn_addr < check_addr:
                continue

            if mnem in ["mov", "xor", "or"] and ("eax" in ops or "rax" in ops):
                side_effects = ["register_modification"]
                regs_modified = {"eax", "rax"}
                flags_modified = mnem in {"xor", "or"}

                safety_score = 0.8
                if i < len(block.instructions) - 1:
                    next_mnem = block.instructions[i + 1][1]
                    if next_mnem in ["ret", "retn"]:
                        safety_score = 0.85

                data_deps = set()
                live_at_point = data_flow.live_variables.get(insn_addr, set())
                for reg in regs_modified:
                    if reg in live_at_point:
                        data_deps.add(reg)

                patch_point = PatchPoint(
                    address=insn_addr,
                    block=block,
                    patch_type="return_modify",
                    safety_score=safety_score,
                    side_effects=side_effects,
                    registers_modified=regs_modified,
                    flags_modified=flags_modified,
                    can_use_nop=False,
                    can_use_jump=False,
                    can_modify_return=True,
                    data_dependencies=data_deps,
                )
                return_points.append(patch_point)

        return return_points

    def _analyze_convergence_points(self, post_dom_addr: int, data_flow: DataFlowInfo) -> list[PatchPoint]:
        """Analyze convergence points (post-dominators)."""
        convergence_points = []

        if post_dom_addr not in self.cfg_analyzer.basic_blocks:
            return []

        block = self.cfg_analyzer.basic_blocks[post_dom_addr]

        first_insn = block.instructions[0] if block.instructions else None
        if first_insn:
            insn_addr, mnem, ops = first_insn

            side_effects = ["convergence_point"]
            regs_modified = self._get_modified_registers(mnem, ops)
            flags_modified = self._modifies_flags(mnem)

            patch_point = PatchPoint(
                address=insn_addr,
                block=block,
                patch_type="convergence",
                safety_score=0.75,
                side_effects=side_effects,
                registers_modified=regs_modified,
                flags_modified=flags_modified,
                can_use_nop=True,
                can_use_jump=True,
                can_modify_return=False,
                control_dependencies=block.predecessors.copy(),
            )
            convergence_points.append(patch_point)

        return convergence_points

    def _analyze_side_effects(self, mnemonic: str, operands: str) -> list[str]:
        """Analyze potential side effects of an instruction."""
        side_effects = []

        if mnemonic in ["call"]:
            side_effects.append("function_call")
        if mnemonic.startswith("j"):
            side_effects.append("control_flow")
        if mnemonic in ["push", "pop"]:
            side_effects.append("stack_modification")
        if "dword ptr" in operands or "qword ptr" in operands or "byte ptr" in operands:
            side_effects.append("memory_access")
        if any(reg in operands.lower() for reg in ["esp", "rsp", "ebp", "rbp"]):
            side_effects.append("stack_pointer_modification")

        return side_effects

    def _get_modified_registers(self, mnemonic: str, operands: str) -> set[str]:
        """Get set of registers modified by instruction."""
        modified = set()

        if mnemonic in ["mov", "lea", "add", "sub", "xor", "or", "and", "inc", "dec"]:
            parts = operands.split(",")
            if parts:
                dest = parts[0].strip().lower()
                for reg in ["eax", "ebx", "ecx", "edx", "esi", "edi", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]:
                    if reg in dest:
                        modified.add(reg)

        return modified

    def _modifies_flags(self, mnemonic: str) -> bool:
        """Check if instruction modifies CPU flags."""
        flag_modifying = ["add", "sub", "cmp", "test", "and", "or", "xor", "inc", "dec", "neg", "shl", "shr", "sal", "sar", "rol", "ror"]
        return mnemonic in flag_modifying


class LicenseCheckRemover:
    """Advanced license check removal engine for modern software."""

    def __init__(self, binary_path: str) -> None:
        """Initialize the license check remover."""
        self.binary_path = binary_path
        self.pe = None
        self.disassembler = None
        self.assembler = None
        self.pattern_matcher = PatternMatcher()
        self.detected_checks = []
        self.backup_created = False
        self.is_dotnet = False
        self.is_packed = False
        self.has_antidebug = False
        self.virtualization_detected = False

        self.control_flow_graph = {}
        self.data_flow_tracking = {}
        self.symbolic_execution_paths = []
        self.taint_analysis_results = {}
        self.cfg_analyzer = None
        self.patch_selector = None

        self._initialize_engines()
        self._detect_binary_characteristics()

    def _initialize_engines(self) -> None:
        """Initialize Capstone disassembler and Keystone assembler."""
        try:
            self.pe = pefile.PE(self.binary_path)

            if self.pe.FILE_HEADER.Machine == 0x14C:
                self.disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                self.assembler = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
            elif self.pe.FILE_HEADER.Machine == 0x8664:
                self.disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                self.assembler = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            else:
                raise ValueError(f"Unsupported architecture: {hex(self.pe.FILE_HEADER.Machine)}")

            self.disassembler.detail = True

            self.cfg_analyzer = ControlFlowAnalyzer(self.disassembler)
            self.patch_selector = PatchPointSelector(self.cfg_analyzer, self.disassembler)

        except Exception as e:
            logger.error(f"Failed to initialize engines: {e}")
            raise

    def _detect_binary_characteristics(self) -> None:
        """Detect characteristics of the binary for specialized handling."""
        if not self.pe:
            return

        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll and b"mscoree.dll" in entry.dll.lower():
                    self.is_dotnet = True
                    logger.info("Detected .NET binary")
                    break

        packer_sections = [".UPX", ".aspack", ".themida", ".vmp", ".enigma"]
        for section in self.pe.sections:
            section_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            if any(packer in section_name.lower() for packer in packer_sections):
                self.is_packed = True
                logger.info(f"Detected packed binary: {section_name}")
                break

        for section in self.pe.sections:
            if section.get_entropy() > 7.0:
                self.is_packed = True
                logger.info(f"High entropy detected in section: {section.Name}")

        anti_debug_imports = [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugString",
            "NtSetInformationThread",
            "RtlQueryProcessDebugInformation",
        ]

        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and any(api in str(imp.name) for api in anti_debug_imports):
                        self.has_antidebug = True
                        logger.info(f"Anti-debug detected: {imp.name}")

        vm_signatures = [
            b"\x0f\x3f",
            b"\x60\xe8\x00\x00\x00\x00",
            b"\x50\x51\x52\x53\x54\x55",
        ]

        for section in self.pe.sections:
            section_data = section.get_data()[:1000]
            for sig in vm_signatures:
                if sig in section_data:
                    self.virtualization_detected = True
                    logger.info("Code virtualization detected")
                    break

    def _build_control_flow_graph(self, instructions: list[tuple[int, str, str]]) -> None:
        """Build control flow graph for advanced analysis."""
        cfg = {}
        current_block = []
        block_start = 0

        for i, (addr, mnem, ops) in enumerate(instructions):
            current_block.append((addr, mnem, ops))

            if mnem.startswith("j") or mnem in ["call", "ret", "retn"]:
                cfg[block_start] = {"instructions": current_block.copy(), "successors": [], "type": mnem}

                if mnem.startswith("j") and i + 1 < len(instructions):
                    cfg[block_start]["successors"].append(instructions[i + 1][0])

                    try:
                        if "0x" in ops:
                            target = int(ops.split("0x")[1].split()[0], 16)
                            cfg[block_start]["successors"].append(target)
                    except (ValueError, IndexError, KeyError):
                        pass

                if i + 1 < len(instructions):
                    block_start = instructions[i + 1][0]
                    current_block = []

        self.control_flow_graph = cfg

    def _perform_taint_analysis(self, start_addr: int, taint_source: str) -> None:
        """Perform taint analysis to track license data flow."""
        tainted = {taint_source}
        worklist = [(start_addr, tainted.copy())]
        visited = set()

        while worklist:
            addr, current_taint = worklist.pop(0)

            if addr in visited:
                continue
            visited.add(addr)

            if addr in self.control_flow_graph:
                block = self.control_flow_graph[addr]

                for insn_addr, mnem, ops in block["instructions"]:
                    if mnem == "mov":
                        parts = ops.split(",")
                        if len(parts) == 2:
                            dst, src = parts[0].strip(), parts[1].strip()
                            if any(t in src for t in current_taint):
                                current_taint.add(dst)

                    if mnem in ["cmp", "test"] and any(t in ops for t in current_taint):
                        if insn_addr not in self.taint_analysis_results:
                            self.taint_analysis_results[insn_addr] = []
                        self.taint_analysis_results[insn_addr].append(taint_source)

                for successor in block.get("successors", []):
                    worklist.append((successor, current_taint.copy()))

    def analyze(self) -> list[LicenseCheck]:
        """Analyze binary for license checks."""
        logger.info(f"Analyzing {self.binary_path} for license checks...")

        self.detected_checks = []

        for section in self.pe.sections:
            if section.IMAGE_SCN_MEM_EXECUTE:
                self._analyze_section(section)

        self._analyze_imports()
        self._analyze_strings()

        self.detected_checks.sort(key=lambda x: x.confidence, reverse=True)

        logger.info(f"Found {len(self.detected_checks)} potential license checks")
        return self.detected_checks

    def _analyze_section(self, section: object) -> None:
        """Analyze a code section for license checks.

        Args:
            section: PE section object from pefile library.

        """
        section_data = section.get_data()
        section_va = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

        instructions = []
        for insn in self.disassembler.disasm(section_data, section_va):
            instructions.append((insn.address, insn.mnemonic, insn.op_str))

        if not instructions:
            return

        try:
            cfg_blocks = self.cfg_analyzer.build_cfg(instructions)
            logger.info(f"Built CFG with {len(cfg_blocks)} basic blocks for section {section.Name}")
        except Exception as e:
            logger.warning(f"CFG analysis failed: {e}")
            cfg_blocks = {}

        matches = self.pattern_matcher.find_patterns(instructions)

        for match in matches:
            start_idx = match["start"]
            length = match["length"]

            matched_instructions = instructions[start_idx : start_idx + length]

            if matched_instructions:
                start_addr = matched_instructions[0][0]
                end_addr = matched_instructions[-1][0] + 10

                offset = start_addr - section_va
                size = end_addr - start_addr
                original_bytes = section_data[offset : offset + size]

                patched_bytes = self._generate_patch(match["type"], matched_instructions, size)

                check = LicenseCheck(
                    check_type=match["type"],
                    address=start_addr,
                    size=size,
                    instructions=matched_instructions,
                    confidence=match["confidence"],
                    patch_strategy=self._get_patch_strategy(match["type"]),
                    original_bytes=original_bytes,
                    patched_bytes=patched_bytes,
                )

                if cfg_blocks and self.patch_selector:
                    try:
                        patch_points = self.patch_selector.select_optimal_patch_points(check, instructions)
                        check.patch_points = patch_points
                        logger.info(f"Found {len(patch_points)} optimal patch points for check at 0x{start_addr:08X}")

                        if patch_points:
                            best_point = patch_points[0]
                            check.control_flow_context = {
                                "best_patch_point": best_point.address,
                                "patch_type": best_point.patch_type,
                                "safety_score": best_point.safety_score,
                                "side_effects": best_point.side_effects,
                                "alternative_points": [p.address for p in patch_points[1:4]],
                                "risk_assessment": best_point.risk_assessment,
                            }
                            check.validated_safe = best_point.risk_assessment in ["low", "medium"]
                    except Exception as e:
                        logger.warning(f"Patch point selection failed for check at 0x{start_addr:08X}: {e}")

                self.detected_checks.append(check)

    def _analyze_imports(self) -> None:
        """Analyze import table for license-related functions."""
        license_apis = {
            "IsDebuggerPresent": CheckType.INTEGRITY_CHECK,
            "CheckRemoteDebuggerPresent": CheckType.INTEGRITY_CHECK,
            "GetSystemTime": CheckType.DATE_CHECK,
            "GetLocalTime": CheckType.DATE_CHECK,
            "GetTickCount": CheckType.TRIAL_CHECK,
            "RegOpenKeyEx": CheckType.REGISTRATION_CHECK,
            "RegQueryValueEx": CheckType.REGISTRATION_CHECK,
            "InternetOpenUrl": CheckType.ONLINE_VALIDATION,
            "HttpSendRequest": CheckType.ONLINE_VALIDATION,
            "GetVolumeInformation": CheckType.HARDWARE_CHECK,
            "GetComputerName": CheckType.HARDWARE_CHECK,
            "CryptVerifySignature": CheckType.SIGNATURE_CHECK,
            "CryptHashData": CheckType.SIGNATURE_CHECK,
        }

        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode("utf-8") if isinstance(imp.name, bytes) else imp.name

                        for api_name, check_type in license_apis.items():
                            if api_name.lower() in func_name.lower():
                                self._find_import_references(imp.address, check_type)

    def _find_import_references(self, import_address: int, check_type: CheckType) -> None:
        """Find references to an imported function."""
        for section in self.pe.sections:
            if section.IMAGE_SCN_MEM_EXECUTE:
                section_data = section.get_data()
                section_va = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

                patterns = [
                    b"\xff\x15",
                    b"\xff\x25",
                ]

                for pattern in patterns:
                    offset = 0
                    while True:
                        pos = section_data.find(pattern, offset)
                        if pos == -1:
                            break

                        if pos + 6 <= len(section_data):
                            target = struct.unpack("<I", section_data[pos + 2 : pos + 6])[0]

                            if target == import_address:
                                ref_address = section_va + pos

                                check = LicenseCheck(
                                    check_type=check_type,
                                    address=ref_address,
                                    size=6,
                                    instructions=[(ref_address, "call/jmp", hex(import_address))],
                                    confidence=0.7,
                                    patch_strategy="nop_call",
                                    original_bytes=section_data[pos : pos + 6],
                                    patched_bytes=b"\x90" * 6,
                                )

                                self.detected_checks.append(check)

                        offset = pos + 1

    def _analyze_strings(self) -> None:
        """Analyze string references for license-related checks."""
        license_strings = [
            "Invalid license",
            "License expired",
            "Trial period",
            "Registration required",
            "Unregistered",
            "Evaluation copy",
            "Serial number",
            "Activation",
            "Invalid key",
            "License not found",
        ]

        for section in self.pe.sections:
            section_data = section.get_data()

            for target_string in license_strings:
                for encoding in [target_string.encode("utf-8"), target_string.encode("utf-16le")]:
                    pos = section_data.find(encoding)
                    if pos != -1:
                        string_va = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + pos
                        self._find_string_references(string_va, target_string)

    def _find_string_references(self, string_address: int, string_content: str) -> None:
        """Find references to a string address."""
        addr_bytes = struct.pack("<I", string_address)

        for section in self.pe.sections:
            if section.IMAGE_SCN_MEM_EXECUTE:
                section_data = section.get_data()
                section_va = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

                pos = 0
                while True:
                    offset = section_data.find(addr_bytes, pos)
                    if offset == -1:
                        break

                    ref_address = section_va + offset

                    context_start = max(0, offset - 20)
                    context_end = min(len(section_data), offset + 20)
                    section_data[context_start:context_end]

                    if "trial" in string_content.lower():
                        check_type = CheckType.TRIAL_CHECK
                    elif "regist" in string_content.lower():
                        check_type = CheckType.REGISTRATION_CHECK
                    elif "serial" in string_content.lower() or "key" in string_content.lower():
                        check_type = CheckType.SERIAL_VALIDATION
                    else:
                        check_type = CheckType.ACTIVATION_CHECK

                    check = LicenseCheck(
                        check_type=check_type,
                        address=ref_address,
                        size=4,
                        instructions=[(ref_address, "ref", string_content)],
                        confidence=0.6,
                        patch_strategy="redirect_string",
                        original_bytes=addr_bytes,
                        patched_bytes=self._get_success_string_address(check_type),
                    )

                    self.detected_checks.append(check)
                    pos = offset + 1

    def _generate_patch(self, check_type: CheckType, instructions: list[tuple[int, str, str]], size: int) -> bytes:
        """Generate sophisticated patch bytes for modern license checks."""
        is_x64 = self.pe.FILE_HEADER.Machine == 0x8664

        if check_type == CheckType.SERIAL_VALIDATION:
            return self._generate_serial_validation_patch(is_x64, instructions, size)
        if check_type == CheckType.TRIAL_CHECK:
            return self._generate_trial_patch(is_x64, size)
        if check_type == CheckType.REGISTRATION_CHECK:
            return self._generate_registration_patch(is_x64, size)
        if check_type == CheckType.HARDWARE_CHECK:
            return self._generate_hardware_check_patch(is_x64, size)
        if check_type == CheckType.ONLINE_VALIDATION:
            return self._generate_online_validation_patch(is_x64, instructions, size)
        if check_type == CheckType.SIGNATURE_CHECK:
            return self._generate_signature_check_patch(is_x64, instructions, size)
        if check_type == CheckType.INTEGRITY_CHECK:
            return self._generate_integrity_check_patch(is_x64, size)
        return self._generate_default_patch(is_x64, size)

    def _generate_serial_validation_patch(self, is_x64: bool, instructions: list[tuple[int, str, str]], size: int) -> bytes:
        """Generate patch for serial validation checks."""
        if self.is_dotnet:
            return b"\x17\x2a" + b"\x00" * (size - 2)
        if any("cmov" in insn[1] for insn in instructions):
            if is_x64:
                return b"\x48\x89\xf0" + b"\x90" * (size - 3)
            return b"\x89\xf0" + b"\x90" * (size - 2)
        if any("jz" in insn[1] or "je" in insn[1] for insn in instructions):
            if size <= 127:
                return b"\xeb" + bytes([size - 2]) + b"\x90" * (size - 2)
            return b"\xe9" + struct.pack("<I", size - 5) + b"\x90" * (size - 5)
        if any("jnz" in insn[1] or "jne" in insn[1] for insn in instructions):
            return b"\x90" * size
        if is_x64:
            return b"\x9f\x48\xc7\xc0\x01\x00\x00\x00\x9e" + b"\x90" * (size - 9)
        return b"\x9c\xb8\x01\x00\x00\x00\x9d" + b"\x90" * (size - 7)

    def _generate_trial_patch(self, is_x64: bool, size: int) -> bytes:
        """Generate patch for trial checks."""
        if self.is_dotnet:
            return b"\x20\xff\xff\xff\x7f" + b"\x00" * (size - 5)
        if is_x64:
            return b"\x48\x8d\x05\xff\xff\xff\x7f" + b"\x90" * (size - 7)
        return b"\xb8\xff\xff\xff\x7f" + b"\x90" * (size - 5)

    def _generate_registration_patch(self, is_x64: bool, size: int) -> bytes:
        """Generate patch for registration checks."""
        if self.virtualization_detected:
            return self._generate_virt_registration_patch(is_x64, size)
        if is_x64:
            return b"\x48\x31\xc0\x48\xff\xc0" + b"\x90" * (size - 6)
        return b"\x31\xc0\x40" + b"\x90" * (size - 3)

    def _generate_virt_registration_patch(self, is_x64: bool, size: int) -> bytes:
        """Generate patch for virtualized registration checks."""
        if is_x64:
            deobfuscation_code = b"\x50\x53\x51\x52"
            deobfuscation_code += b"\x48\x31\xdb"
            deobfuscation_code += b"\x48\xc7\xc0\x01\x00\x00\x00"
            deobfuscation_code += b"\x5a\x59\x5b\x58"
            if len(deobfuscation_code) <= size:
                return deobfuscation_code + b"\x90" * (size - len(deobfuscation_code))
            return b"\x48\xc7\xc0\x01\x00\x00\x00" + b"\x90" * (size - 7)
        deobfuscation_code = b"\x50\x53\x51\x52"
        deobfuscation_code += b"\x31\xdb"
        deobfuscation_code += b"\xb8\x01\x00\x00\x00"
        deobfuscation_code += b"\x5a\x59\x5b\x58"
        if len(deobfuscation_code) <= size:
            return deobfuscation_code + b"\x90" * (size - len(deobfuscation_code))
        return b"\xb8\x01\x00\x00\x00" + b"\x90" * (size - 5)

    def _generate_hardware_check_patch(self, is_x64: bool, size: int) -> bytes:
        """Generate patch for hardware checks."""
        if self.has_antidebug:
            if is_x64:
                return b"\x48\x8d\x05\x00\x10\x00\x00" + b"\x90" * (size - 7)
            return b"\x8d\x05\x00\x10\x00\x00" + b"\x90" * (size - 6)
        return b"\x90" * size

    def _generate_online_validation_patch(self, is_x64: bool, instructions: list[tuple[int, str, str]], size: int) -> bytes:
        """Generate patch for online validation checks."""
        if any("async" in str(insn[2]).lower() for insn in instructions):
            return self._generate_async_online_patch(is_x64, size)
        if is_x64:
            return b"\x48\x31\xc0\x48\xff\xc0\xc3" + b"\x90" * (size - 6)
        return b"\xb8\x01\x00\x00\x00\xc3" + b"\x90" * (size - 6)

    def _generate_async_online_patch(self, is_x64: bool, size: int) -> bytes:
        """Generate patch for async online validation."""
        if is_x64:
            response_code = b"\x50\x51\x52"
            response_code += b"\x48\xc7\xc0\xc8\x00\x00\x00"
            response_code += b"\x48\xc7\xc1\x01\x00\x00\x00"
            response_code += b"\x48\x89\x0d\x00\x00\x00\x00"
            response_code += b"\x5a\x59\x58"
            if len(response_code) <= size:
                return response_code + b"\x90" * (size - len(response_code))
            return b"\x48\xc7\xc0\xc8\x00\x00\x00" + b"\x90" * (size - 7)
        response_code = b"\x50\x51\x52"
        response_code += b"\xb8\xc8\x00\x00\x00"
        response_code += b"\xb9\x01\x00\x00\x00"
        response_code += b"\x89\x0d\x00\x00\x00\x00"
        response_code += b"\x5a\x59\x58"
        if len(response_code) <= size:
            return response_code + b"\x90" * (size - len(response_code))
        return b"\xb8\xc8\x00\x00\x00" + b"\x90" * (size - 5)

    def _generate_signature_check_patch(self, is_x64: bool, instructions: list[tuple[int, str, str]], size: int) -> bytes:
        """Generate patch for signature checks."""
        if any("ecdsa" in str(insn[2]).lower() for insn in instructions):
            if is_x64:
                return b"\x48\x31\xc0\x48\xff\xc0\x48\x31\xdb" + b"\x90" * (size - 8)
            return b"\x31\xc0\x40\x31\xdb" + b"\x90" * (size - 5)
        if is_x64:
            return b"\x48\xc7\xc0\x01\x00\x00\x00" + b"\x90" * (size - 7)
        return b"\xb8\x01\x00\x00\x00" + b"\x90" * (size - 5)

    def _generate_integrity_check_patch(self, is_x64: bool, size: int) -> bytes:
        """Generate patch for integrity checks."""
        if self.is_packed:
            if size >= 2:
                return b"\x74\x00" + b"\x90" * (size - 2)
            return b"\x90" * size
        return b"\x90" * size

    def _generate_default_patch(self, is_x64: bool, size: int) -> bytes:
        """Generate default patch based on context."""
        if self.virtualization_detected:
            if is_x64:
                return b"\x48\x31\xc0\x48\xff\xc0" + b"\x90" * (size - 6)
            return b"\x31\xc0\x40" + b"\x90" * (size - 3)
        return b"\x90" * size

    def _get_patch_strategy(self, check_type: CheckType) -> str:
        """Get patching strategy for check type."""
        strategies = {
            CheckType.SERIAL_VALIDATION: "force_valid_comparison",
            CheckType.REGISTRATION_CHECK: "set_registered_flag",
            CheckType.TRIAL_CHECK: "infinite_trial",
            CheckType.ACTIVATION_CHECK: "skip_activation",
            CheckType.FEATURE_CHECK: "enable_all_features",
            CheckType.ONLINE_VALIDATION: "skip_online_check",
            CheckType.HARDWARE_CHECK: "skip_hardware_validation",
            CheckType.DATE_CHECK: "freeze_date",
            CheckType.SIGNATURE_CHECK: "force_signature_valid",
            CheckType.INTEGRITY_CHECK: "disable_integrity_check",
        }
        return strategies.get(check_type, "nop_check")

    def _get_success_string_address(self, check_type: CheckType) -> bytes:
        """Get address of success string for redirection."""
        return b"\x00\x00\x00\x00"

    def patch(self, checks: list[LicenseCheck] | None = None, create_backup: bool = True) -> bool:
        """Apply patches to remove license checks."""
        if not checks:
            checks = self.detected_checks

        if not checks:
            logger.warning("No license checks to patch")
            return False

        if create_backup and not self.backup_created:
            backup_path = self.binary_path + ".bak"
            shutil.copy2(self.binary_path, backup_path)
            self.backup_created = True
            logger.info(f"Created backup: {backup_path}")

        patched_count = 0

        try:
            with open(self.binary_path, "rb") as f:
                data = bytearray(f.read())

            for check in checks:
                rva = check.address - self.pe.OPTIONAL_HEADER.ImageBase
                offset = self._rva_to_offset(rva)

                if offset:
                    patch_size = len(check.patched_bytes)
                    data[offset : offset + patch_size] = check.patched_bytes
                    patched_count += 1

                    logger.info(f"Patched {check.check_type.value} at 0x{check.address:08X}")

            with open(self.binary_path, "wb") as f:
                f.write(data)

            self._update_checksum()

            logger.info(f"Successfully patched {patched_count} license checks")
            return True

        except Exception as e:
            logger.error(f"Patching failed: {e}")

            if self.backup_created:
                backup_path = self.binary_path + ".bak"
                shutil.copy2(backup_path, self.binary_path)
                logger.info("Restored from backup due to patching error")

            return False

    def _rva_to_offset(self, rva: int) -> int | None:
        """Convert RVA to file offset."""
        for section in self.pe.sections:
            if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
                return section.PointerToRawData + (rva - section.VirtualAddress)
        return None

    def _update_checksum(self) -> None:
        """Update PE checksum after patching."""
        try:
            pe = pefile.PE(self.binary_path)

            pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()

            pe.write(self.binary_path)
            pe.close()

            logger.info("Updated PE checksum")
        except Exception as e:
            logger.warning(f"Failed to update checksum: {e}")

    def verify_patches(self) -> bool:
        """Verify that patches were applied successfully."""
        try:
            pe_verify = pefile.PE(self.binary_path)

            for check in self.detected_checks:
                rva = check.address - self.pe.OPTIONAL_HEADER.ImageBase
                offset = self._rva_to_offset(rva)

                if offset:
                    with open(self.binary_path, "rb") as f:
                        f.seek(offset)
                        actual_bytes = f.read(len(check.patched_bytes))

                    if actual_bytes != check.patched_bytes:
                        logger.error(f"Patch verification failed at 0x{check.address:08X}")
                        return False

            pe_verify.close()
            logger.info("All patches verified successfully")
            return True

        except Exception as e:
            logger.error(f"Patch verification failed: {e}")
            return False

    def apply_intelligent_patches(self, checks: list[LicenseCheck] | None = None, use_best_point: bool = True) -> bool:
        """Apply intelligent patches using optimal patch points."""
        if not checks:
            checks = self.detected_checks

        if not checks:
            logger.warning("No license checks to patch")
            return False

        if not self.backup_created:
            backup_path = self.binary_path + ".bak"
            shutil.copy2(self.binary_path, backup_path)
            self.backup_created = True
            logger.info(f"Created backup: {backup_path}")

        patched_count = 0

        try:
            with open(self.binary_path, "rb") as f:
                data = bytearray(f.read())

            for check in checks:
                if not check.patch_points:
                    logger.warning(f"No patch points available for check at 0x{check.address:08X}, using default patching")
                    rva = check.address - self.pe.OPTIONAL_HEADER.ImageBase
                    offset = self._rva_to_offset(rva)

                    if offset:
                        patch_size = len(check.patched_bytes)
                        data[offset : offset + patch_size] = check.patched_bytes
                        patched_count += 1
                        logger.info(f"Patched {check.check_type.value} at 0x{check.address:08X} (default method)")
                    continue

                best_point = check.patch_points[0] if use_best_point else check.patch_points[-1]

                patch_bytes = self._generate_intelligent_patch(best_point, check)

                rva = best_point.address - self.pe.OPTIONAL_HEADER.ImageBase
                offset = self._rva_to_offset(rva)

                if offset:
                    data[offset : offset + len(patch_bytes)] = patch_bytes
                    patched_count += 1
                    logger.info(
                        f"Patched {check.check_type.value} at 0x{best_point.address:08X} "
                        f"using {best_point.patch_type} (safety: {best_point.safety_score:.2f}, risk: {best_point.risk_assessment})",
                    )

            with open(self.binary_path, "wb") as f:
                f.write(data)

            self._update_checksum()

            logger.info(f"Successfully applied {patched_count} intelligent patches")
            return True

        except Exception as e:
            logger.error(f"Intelligent patching failed: {e}")

            if self.backup_created:
                backup_path = self.binary_path + ".bak"
                shutil.copy2(backup_path, self.binary_path)
                logger.info("Restored from backup due to patching error")

            return False

    def _generate_intelligent_patch(self, patch_point: PatchPoint, check: LicenseCheck) -> bytes:
        """Generate patch bytes based on patch point type and safety analysis."""
        is_x64 = self.pe.FILE_HEADER.Machine == 0x8664

        if patch_point.patch_type == "nop":
            insn_size = 6 if is_x64 else 5
            return b"\x90" * insn_size

        if patch_point.patch_type == "jump_redirect":
            if patch_point.alternative_points:
                success_target = patch_point.alternative_points[0]
                current_addr = patch_point.address

                offset = success_target - (current_addr + 5)

                if -128 <= offset <= 127:
                    return b"\xeb" + struct.pack("<b", offset)
                return b"\xe9" + struct.pack("<i", offset)
            return b"\x90\x90"

        if patch_point.patch_type == "return_modify":
            if is_x64:
                return b"\x48\x31\xc0\x48\xff\xc0"
            return b"\x31\xc0\x40"

        if patch_point.patch_type == "convergence":
            if is_x64:
                return b"\x48\xc7\xc0\x01\x00\x00\x00"
            return b"\xb8\x01\x00\x00\x00"

        return check.patched_bytes

    def generate_report(self) -> str:
        """Generate detailed report of detected checks and patches."""
        report = []
        report.append("=" * 80)
        report.append("LICENSE CHECK REMOVAL REPORT")
        report.append("=" * 80)
        report.append(f"Binary: {self.binary_path}")
        report.append(f"Architecture: {'x64' if self.pe.FILE_HEADER.Machine == 0x8664 else 'x86'}")
        report.append(f"Total Checks Found: {len(self.detected_checks)}")

        cfg_available = self.cfg_analyzer and self.cfg_analyzer.basic_blocks
        if cfg_available:
            report.append(f"Control Flow Blocks: {len(self.cfg_analyzer.basic_blocks)}")

        report.append("")

        by_type = {}
        for check in self.detected_checks:
            if check.check_type not in by_type:
                by_type[check.check_type] = []
            by_type[check.check_type].append(check)

        for check_type, checks in by_type.items():
            report.append(f"\n{check_type.value.upper()} ({len(checks)} found)")
            report.append("-" * 40)

            for check in checks[:5]:
                report.append(f"  Address: 0x{check.address:08X}")
                report.append(f"  Confidence: {check.confidence:.1%}")
                report.append(f"  Strategy: {check.patch_strategy}")
                report.append(f"  Validated Safe: {check.validated_safe}")

                if check.instructions:
                    report.append("  Instructions:")
                    for addr, mnem, ops in check.instructions[:3]:
                        report.append(f"    0x{addr:08X}: {mnem} {ops}")

                if check.patch_points:
                    report.append(f"  Patch Points: {len(check.patch_points)}")
                    best_point = check.patch_points[0]
                    report.append(f"    Best: 0x{best_point.address:08X} ({best_point.patch_type}, safety={best_point.safety_score:.2f}, risk={best_point.risk_assessment})")

                    if best_point.side_effects:
                        report.append(f"    Side Effects: {', '.join(best_point.side_effects)}")

                    if best_point.data_dependencies:
                        report.append(f"    Data Dependencies: {', '.join(best_point.data_dependencies)}")

                    if len(check.patch_points) > 1:
                        report.append(f"    Alternatives: {len(check.patch_points) - 1}")

                report.append("")

        return "\n".join(report)


def main() -> None:
    """Command-line interface for license check remover."""
    import argparse

    parser = argparse.ArgumentParser(description="Remove license checks from binaries with intelligent patch point selection")
    parser.add_argument("binary", help="Path to binary file")
    parser.add_argument("-a", "--analyze", action="store_true", help="Only analyze, don't patch")
    parser.add_argument("-p", "--patch", action="store_true", help="Apply patches to remove checks")
    parser.add_argument("-i", "--intelligent", action="store_true", help="Use intelligent patch point selection (default)")
    parser.add_argument("--legacy", action="store_true", help="Use legacy patching method")
    parser.add_argument("-r", "--report", action="store_true", help="Generate detailed report")
    parser.add_argument("-c", "--confidence", type=float, default=0.7, help="Minimum confidence threshold (0.0-1.0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    remover = LicenseCheckRemover(args.binary)

    checks = remover.analyze()

    checks = [c for c in checks if c.confidence >= args.confidence]

    print(f"\nFound {len(checks)} license checks with confidence >= {args.confidence:.1%}")

    if args.report:
        print(remover.generate_report())

    if args.patch and not args.analyze:
        use_intelligent = not args.legacy

        if use_intelligent:
            print("\nApplying intelligent patches with CFG analysis...")
            if remover.apply_intelligent_patches(checks):
                print("OK Intelligent patches applied successfully")
            else:
                print("FAIL Intelligent patching failed")
        else:
            print("\nApplying legacy patches...")
            if remover.patch(checks):
                print("OK Patches applied successfully")

                if remover.verify_patches():
                    print("OK Patches verified")
                else:
                    print("FAIL Patch verification failed")
            else:
                print("FAIL Patching failed")


if __name__ == "__main__":
    main()
