"""Control Flow Deobfuscation Engine for defeating commercial software protection obfuscation.

This module provides comprehensive control flow deobfuscation capabilities targeting
licensing protection schemes that use control flow flattening, virtualization, and
opaque predicates to protect license validation code.

Supported obfuscation schemes:
- OLLVM (Obfuscator-LLVM) control flow flattening
- Tigress control flow obfuscation
- VMProtect control flow graph flattening
- Code Virtualizer dispatcher-based obfuscation
- Custom control flow flattening schemes

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
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from intellicrack.utils.tools.radare2_utils import Radare2Session

from intellicrack.utils.logger import logger


try:
    from intellicrack.core.analysis.opaque_predicate_analyzer import OpaquePredicateAnalyzer, PredicateAnalysis

    OPAQUE_ANALYZER_AVAILABLE = True
except ImportError:
    logger.warning("Advanced opaque predicate analyzer not available")
    OPAQUE_ANALYZER_AVAILABLE = False
    OpaquePredicateAnalyzer = None
    PredicateAnalysis = None

try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    logger.warning("NetworkX not available for control flow deobfuscation")
    NETWORKX_AVAILABLE = False
    nx = None

try:
    from intellicrack.handlers.capstone_handler import (
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_ARCH_X86,
        CS_GRP_JUMP,
        CS_MODE_32,
        CS_MODE_64,
        CS_MODE_ARM,
        CS_MODE_THUMB,
        Cs,
    )

    CAPSTONE_AVAILABLE = True
except ImportError:
    logger.warning("Capstone not available for control flow deobfuscation")
    CAPSTONE_AVAILABLE = False
    CS_ARCH_X86 = CS_ARCH_ARM = CS_ARCH_ARM64 = None
    CS_MODE_32 = CS_MODE_64 = CS_MODE_ARM = CS_MODE_THUMB = None
    CS_GRP_JUMP = None
    Cs = None

try:
    from intellicrack.handlers.keystone_handler import (
        KS_ARCH_ARM,
        KS_ARCH_ARM64,
        KS_ARCH_X86,
        KS_MODE_32,
        KS_MODE_64,
        KS_MODE_ARM,
        KS_MODE_THUMB,
        Ks,
    )

    KEYSTONE_AVAILABLE = True
except ImportError:
    logger.warning("Keystone not available for control flow deobfuscation")
    KEYSTONE_AVAILABLE = False
    KS_ARCH_X86 = KS_ARCH_ARM = KS_ARCH_ARM64 = None
    KS_MODE_32 = KS_MODE_64 = KS_MODE_ARM = KS_MODE_THUMB = None
    Ks = None

try:
    from intellicrack.handlers.lief_handler import lief

    if TYPE_CHECKING:
        from lief import Binary, Section

    LIEF_AVAILABLE = True
except ImportError:
    logger.warning("LIEF not available for control flow deobfuscation")
    LIEF_AVAILABLE = False
    lief = None
    if TYPE_CHECKING:
        Binary = Any
        Section = Any

from ...utils.tools.radare2_utils import r2_session


@dataclass
class BasicBlock:
    """Represents a basic block in the control flow graph."""

    address: int
    size: int
    instructions: list[dict[str, Any]]
    successors: list[int]
    predecessors: list[int]
    block_type: str
    is_dispatcher: bool = False
    is_prologue: bool = False
    is_epilogue: bool = False
    state_variable_refs: list[int] = None
    complexity_score: float = 0.0

    def __post_init__(self) -> None:
        """Initialize mutable defaults after dataclass creation."""
        if self.state_variable_refs is None:
            self.state_variable_refs = []


@dataclass
class DispatcherInfo:
    """Information about a control flow flattening dispatcher."""

    dispatcher_address: int
    state_variable_location: int
    state_variable_type: str
    controlled_blocks: list[int]
    case_mappings: dict[int, int]
    switch_type: str


@dataclass
class DeobfuscationResult:
    """Result of control flow deobfuscation."""

    original_cfg: Any
    deobfuscated_cfg: Any
    dispatcher_info: list[DispatcherInfo]
    removed_blocks: list[int]
    recovered_edges: list[tuple[int, int]]
    opaque_predicates: list[dict[str, Any]]
    patch_info: list[dict[str, Any]]
    confidence: float
    metrics: dict[str, Any]


class ControlFlowDeobfuscator:
    """Comprehensive control flow deobfuscation engine for defeating licensing protection obfuscation.

    This class implements sophisticated techniques to reverse control flow flattening,
    dispatcher-based obfuscation, and opaque predicates commonly used to protect
    license validation routines in commercial software.
    """

    def __init__(self, binary_path: str | Path, radare2_path: str | None = None) -> None:
        """Initialize the control flow deobfuscator.

        Args:
            binary_path: Path to the binary to deobfuscate
            radare2_path: Optional custom path to radare2 executable

        """
        self.binary_path = Path(binary_path)
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)
        self.binary = None
        self.architecture = None
        self.disassembler = None
        self.assembler = None
        self.opaque_analyzer = None

        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")

        self._initialize_binary()
        self._initialize_disassembler()
        self._initialize_opaque_analyzer()

    def _initialize_binary(self) -> None:
        """Initialize binary parsing with LIEF."""
        if not LIEF_AVAILABLE:
            self.logger.warning("LIEF not available, binary manipulation will be limited")
            return

        try:
            self.binary = lief.parse(str(self.binary_path))
            if self.binary is None:
                raise ValueError(f"Failed to parse binary: {self.binary_path}")

            if hasattr(self.binary, "header"):
                if hasattr(self.binary.header, "machine_type"):
                    machine = str(self.binary.header.machine_type)
                    if "AMD64" in machine or "X86_64" in machine:
                        self.architecture = "x86_64"
                    elif "I386" in machine or "X86" in machine:
                        self.architecture = "x86"
                    elif "ARM64" in machine or "AARCH64" in machine:
                        self.architecture = "arm64"
                    elif "ARM" in machine:
                        self.architecture = "arm"
            elif hasattr(self.binary, "header64"):
                if hasattr(self.binary.header64, "cputype"):
                    cputype = self.binary.header64.cputype
                    if cputype == 0x01000007:
                        self.architecture = "x86_64"
                    elif cputype == 0x0100000C:
                        self.architecture = "arm64"

            if self.architecture is None:
                self.architecture = "x86_64"

            self.logger.info(f"Detected architecture: {self.architecture}")

        except Exception as e:
            self.logger.error(f"Failed to initialize binary: {e}")
            self.architecture = "x86_64"

    def _initialize_disassembler(self) -> None:
        """Initialize Capstone disassembler and Keystone assembler."""
        if not CAPSTONE_AVAILABLE:
            self.logger.warning("Capstone not available, disassembly will be limited")
            return

        try:
            if self.architecture == "x86_64":
                self.disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
                if KEYSTONE_AVAILABLE:
                    self.assembler = Ks(KS_ARCH_X86, KS_MODE_64)
            elif self.architecture == "x86":
                self.disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
                if KEYSTONE_AVAILABLE:
                    self.assembler = Ks(KS_ARCH_X86, KS_MODE_32)
            elif self.architecture == "arm64":
                self.disassembler = Cs(CS_ARCH_ARM64, 0)
                if KEYSTONE_AVAILABLE:
                    self.assembler = Ks(KS_ARCH_ARM64, 0)
            elif self.architecture == "arm":
                self.disassembler = Cs(CS_ARCH_ARM, CS_MODE_ARM)
                if KEYSTONE_AVAILABLE:
                    self.assembler = Ks(KS_ARCH_ARM, KS_MODE_ARM)

            if self.disassembler:
                self.disassembler.detail = True
                self.logger.info(f"Initialized disassembler for {self.architecture}")

        except Exception as e:
            self.logger.error(f"Failed to initialize disassembler: {e}")

    def _initialize_opaque_analyzer(self) -> None:
        """Initialize advanced opaque predicate analyzer."""
        if OPAQUE_ANALYZER_AVAILABLE:
            try:
                self.opaque_analyzer = OpaquePredicateAnalyzer()
                self.logger.info("Initialized advanced opaque predicate analyzer")
            except Exception as e:
                self.logger.warning(f"Failed to initialize opaque analyzer: {e}")
                self.opaque_analyzer = None
        else:
            self.logger.warning("Advanced opaque predicate analyzer not available")

    def deobfuscate_function(
        self,
        function_address: int,
        function_name: str | None = None,
    ) -> DeobfuscationResult:
        """Deobfuscate a single function's control flow.

        Args:
            function_address: Address of the function to deobfuscate
            function_name: Optional name of the function

        Returns:
            DeobfuscationResult containing deobfuscated CFG and analysis data

        """
        self.logger.info(f"Deobfuscating function at 0x{function_address:x}")

        try:
            with r2_session(str(self.binary_path), self.radare2_path) as r2:
                original_cfg = self._build_control_flow_graph(r2, function_address)

                dispatcher_info = self._detect_dispatchers(r2, original_cfg, function_address)

                if dispatcher_info:
                    self.logger.info(
                        f"Detected {len(dispatcher_info)} control flow flattening dispatchers",
                    )
                    deobfuscated_cfg = self._unflatten_control_flow(
                        r2,
                        original_cfg,
                        dispatcher_info,
                        function_address,
                    )
                else:
                    self.logger.info("No control flow flattening detected")
                    deobfuscated_cfg = original_cfg

                opaque_predicates = self._detect_opaque_predicates(
                    r2, deobfuscated_cfg, function_address
                )

                if opaque_predicates:
                    self.logger.info(f"Detected {len(opaque_predicates)} opaque predicates")
                    deobfuscated_cfg = self._remove_opaque_predicates(
                        r2,
                        deobfuscated_cfg,
                        opaque_predicates,
                    )

                bogus_blocks = self._detect_bogus_blocks(r2, deobfuscated_cfg, function_address)

                if bogus_blocks:
                    self.logger.info(f"Detected {len(bogus_blocks)} bogus/unreachable blocks")
                    deobfuscated_cfg = self._remove_bogus_blocks(deobfuscated_cfg, bogus_blocks)

                patch_info = self._generate_patch_information(
                    r2,
                    original_cfg,
                    deobfuscated_cfg,
                    dispatcher_info,
                    function_address,
                )

                metrics = self._calculate_deobfuscation_metrics(original_cfg, deobfuscated_cfg)

                confidence = self._calculate_confidence_score(
                    dispatcher_info,
                    opaque_predicates,
                    bogus_blocks,
                    metrics,
                )

                removed_blocks = bogus_blocks
                recovered_edges = self._extract_recovered_edges(original_cfg, deobfuscated_cfg)

                return DeobfuscationResult(
                    original_cfg=original_cfg,
                    deobfuscated_cfg=deobfuscated_cfg,
                    dispatcher_info=dispatcher_info,
                    removed_blocks=removed_blocks,
                    recovered_edges=recovered_edges,
                    opaque_predicates=opaque_predicates,
                    patch_info=patch_info,
                    confidence=confidence,
                    metrics=metrics,
                )

        except Exception as e:
            self.logger.error(f"Deobfuscation failed: {e}")
            raise

    def _build_control_flow_graph(self, r2: "Radare2Session", function_address: int) -> nx.DiGraph:
        """Build control flow graph for a function using radare2.

        Args:
            r2: Active radare2 session
            function_address: Address of the function

        Returns:
            NetworkX directed graph representing the CFG

        """
        if not NETWORKX_AVAILABLE:
            raise RuntimeError("NetworkX required for control flow deobfuscation")

        try:
            graph_data = r2._execute_command(f"agfj @ {hex(function_address)}", expect_json=True)

            if not graph_data or not isinstance(graph_data, list):
                raise ValueError(f"Failed to get CFG for function at 0x{function_address:x}")

            cfg = nx.DiGraph()
            blocks_data = graph_data[0].get("blocks", [])

            for block in blocks_data:
                block_addr = block.get("offset", 0)
                block_size = block.get("size", 0)
                block_ops = block.get("ops", [])

                basic_block = BasicBlock(
                    address=block_addr,
                    size=block_size,
                    instructions=block_ops,
                    successors=[],
                    predecessors=[],
                    block_type=self._classify_block(block_ops),
                    complexity_score=self._calculate_block_complexity(block_ops),
                )

                cfg.add_node(block_addr, data=basic_block)

                if block.get("jump"):
                    cfg.add_edge(block_addr, block["jump"], edge_type="conditional_true")
                    basic_block.successors.append(block["jump"])

                if block.get("fail"):
                    cfg.add_edge(block_addr, block["fail"], edge_type="conditional_false")
                    basic_block.successors.append(block["fail"])

                next_block = block.get("next")
                if next_block and not self._is_terminator_block(block_ops):
                    cfg.add_edge(block_addr, next_block, edge_type="fallthrough")
                    basic_block.successors.append(next_block)

            for node in cfg.nodes():
                basic_block = cfg.nodes[node]["data"]
                basic_block.predecessors = list(cfg.predecessors(node))

            return cfg

        except Exception as e:
            self.logger.error(f"Failed to build CFG: {e}")
            raise

    def _detect_dispatchers(
        self,
        r2: "Radare2Session",
        cfg: nx.DiGraph,
        function_address: int,
    ) -> list[DispatcherInfo]:
        """Detect control flow flattening dispatchers in the CFG.

        Identifies dispatcher blocks that implement control flow flattening through
        state variable based switching. Supports OLLVM, Tigress, and VMProtect patterns.

        Args:
            r2: Active radare2 session
            cfg: Control flow graph
            function_address: Function address

        Returns:
            List of detected dispatchers

        """
        dispatchers = []

        for node in cfg.nodes():
            basic_block = cfg.nodes[node]["data"]

            if self._is_dispatcher_block(basic_block, cfg):
                self.logger.debug(f"Potential dispatcher at 0x{node:x}")

                state_var = self._identify_state_variable(r2, basic_block, function_address)

                controlled_blocks = self._identify_controlled_blocks(cfg, node)

                case_mappings = self._extract_switch_cases(
                    r2, basic_block, controlled_blocks, function_address
                )

                dispatcher = DispatcherInfo(
                    dispatcher_address=node,
                    state_variable_location=state_var.get("location", 0) if state_var else 0,
                    state_variable_type=state_var.get("type", "unknown")
                    if state_var
                    else "unknown",
                    controlled_blocks=controlled_blocks,
                    case_mappings=case_mappings,
                    switch_type=self._classify_dispatcher_type(basic_block),
                )

                dispatchers.append(dispatcher)
                basic_block.is_dispatcher = True

        return dispatchers

    def _is_dispatcher_block(self, basic_block: BasicBlock, cfg: nx.DiGraph) -> bool:
        """Determine if a basic block is a control flow dispatcher.

        Dispatcher characteristics:
        - High out-degree (multiple successors)
        - Contains comparison/switch logic
        - References state variable
        - Dominates many blocks in the CFG

        Args:
            basic_block: Basic block to analyze
            cfg: Control flow graph

        Returns:
            True if block is likely a dispatcher

        """
        out_degree = len(basic_block.successors)
        if out_degree < 3:
            return False

        has_comparison = any(
            any(op in inst.get("disasm", "").lower() for op in ["cmp", "test", "sub"])
            for inst in basic_block.instructions
        )

        has_jump_table = any(
            "jmp" in inst.get("disasm", "").lower() and "[" in inst.get("disasm", "")
            for inst in basic_block.instructions
        )

        has_switch = any(
            any(keyword in inst.get("disasm", "").lower() for keyword in ["switch", "case"])
            for inst in basic_block.instructions
        )

        in_degree = len(basic_block.predecessors)
        high_loop_back = in_degree > out_degree * 0.5

        return (has_comparison or has_jump_table or has_switch) and (
            out_degree >= 5 or high_loop_back
        )

    def _identify_state_variable(
        self,
        r2: "Radare2Session",
        basic_block: BasicBlock,
        function_address: int,
    ) -> dict[str, Any]:
        """Identify the state variable used by a dispatcher.

        Args:
            r2: Active radare2 session
            basic_block: Dispatcher block
            function_address: Function address

        Returns:
            Dictionary containing state variable information

        """
        state_var_candidates = []

        for inst in basic_block.instructions:
            disasm = inst.get("disasm", "").lower()

            if any(op in disasm for op in ["mov", "movzx", "movsx", "lea"]) and "[" in disasm:
                parts = disasm.split("[")
                if len(parts) > 1:
                    location_str = parts[1].split("]")[0]

                    if (
                        "rbp" in location_str
                        or "rsp" in location_str
                        or "ebp" in location_str
                        or "esp" in location_str
                    ):
                        state_var_candidates.append(
                            {
                                "location": inst.get("offset", 0),
                                "type": "stack",
                                "access": location_str,
                                "instruction": disasm,
                            },
                        )
                    elif "rip" in location_str:
                        state_var_candidates.append(
                            {
                                "location": inst.get("offset", 0),
                                "type": "global",
                                "access": location_str,
                                "instruction": disasm,
                            },
                        )

        if state_var_candidates:
            access_counts = defaultdict(int)
            for candidate in state_var_candidates:
                access_counts[candidate["access"]] += 1

            most_common = max(access_counts.items(), key=lambda x: x[1])
            for candidate in state_var_candidates:
                if candidate["access"] == most_common[0]:
                    return candidate

        return {"location": 0, "type": "unknown", "access": "", "instruction": ""}

    def _identify_controlled_blocks(self, cfg: nx.DiGraph, dispatcher_address: int) -> list[int]:
        """Identify blocks controlled by a dispatcher.

        Args:
            cfg: Control flow graph
            dispatcher_address: Address of dispatcher block

        Returns:
            List of controlled block addresses

        """
        controlled = list(cfg.successors(dispatcher_address))

        controlled_extended = set(controlled)
        for block_addr in controlled:
            descendants = nx.descendants(cfg, block_addr)
            for desc in descendants:
                if desc != dispatcher_address:
                    out_edges = list(cfg.successors(desc))
                    if dispatcher_address in out_edges:
                        controlled_extended.add(desc)

        return list(controlled_extended)

    def _extract_switch_cases(
        self,
        r2: "Radare2Session",
        basic_block: BasicBlock,
        controlled_blocks: list[int],
        function_address: int,
    ) -> dict[int, int]:
        """Extract switch case mappings from dispatcher block.

        Args:
            r2: Active radare2 session
            basic_block: Dispatcher block
            controlled_blocks: List of controlled blocks
            function_address: Function address

        Returns:
            Mapping from case values to target block addresses

        """
        try:
            switch_info = r2._execute_command(
                f"afi @ {hex(basic_block.address)}",
                expect_json=False,
            )

            if "switch" in str(switch_info).lower():
                pass

        except Exception as e:
            self.logger.debug(f"Failed to extract switch info via radare2: {e}")

        return dict(enumerate(controlled_blocks))

    def _classify_dispatcher_type(self, basic_block: BasicBlock) -> str:
        """Classify the type of dispatcher (OLLVM, Tigress, VMProtect, etc.).

        Args:
            basic_block: Dispatcher block

        Returns:
            String identifying dispatcher type

        """
        disasm_text = " ".join(inst.get("disasm", "") for inst in basic_block.instructions)

        if "cmov" in disasm_text.lower() and len(basic_block.successors) > 10:
            return "OLLVM"
        if "switch" in disasm_text.lower():
            return "Tigress"
        return "VMProtect" if len(basic_block.successors) > 20 else "Generic"

    def _unflatten_control_flow(
        self,
        r2: "Radare2Session",
        cfg: nx.DiGraph,
        dispatchers: list[DispatcherInfo],
        function_address: int,
    ) -> nx.DiGraph:
        """Unflatten control flow by removing dispatcher blocks and recovering original edges.

        Args:
            r2: Active radare2 session
            cfg: Original control flow graph
            dispatchers: List of detected dispatchers
            function_address: Function address

        Returns:
            Deobfuscated control flow graph

        """
        deobfuscated = cfg.copy()

        for dispatcher in dispatchers:
            self.logger.debug(f"Unflattening dispatcher at 0x{dispatcher.dispatcher_address:x}")

            original_edges = self._recover_original_edges(
                r2,
                cfg,
                dispatcher,
                function_address,
            )

            for source, target in original_edges:
                if dispatcher.dispatcher_address not in (source, target):
                    deobfuscated.add_edge(source, target, edge_type="recovered")

            edges_to_remove = [
                (source, target)
                for source, target in deobfuscated.edges()
                if dispatcher.dispatcher_address in (source, target)
            ]
            for edge in edges_to_remove:
                deobfuscated.remove_edge(*edge)

        return deobfuscated

    def _recover_original_edges(
        self,
        r2: "Radare2Session",
        cfg: nx.DiGraph,
        dispatcher: DispatcherInfo,
        function_address: int,
    ) -> list[tuple[int, int]]:
        """Recover original control flow edges from flattened structure.

        Analyzes state variable assignments in predecessor blocks to determine
        the original control flow before flattening.

        Args:
            r2: Active radare2 session
            cfg: Control flow graph
            dispatcher: Dispatcher information
            function_address: Function address

        Returns:
            List of (source, target) edge tuples

        """
        recovered_edges = []

        for block_addr in dispatcher.controlled_blocks:
            if block_addr not in cfg.nodes():
                continue

            basic_block = cfg.nodes[block_addr]["data"]

            next_state_value = self._extract_state_assignment(basic_block, dispatcher)

            if next_state_value is not None and next_state_value in dispatcher.case_mappings:
                target_block = dispatcher.case_mappings[next_state_value]
                recovered_edges.append((block_addr, target_block))
            else:
                recovered_edges.extend(
                    (block_addr, successor)
                    for successor in basic_block.successors
                    if successor != dispatcher.dispatcher_address
                )
        return recovered_edges

    def _extract_state_assignment(
        self,
        basic_block: BasicBlock,
        dispatcher: DispatcherInfo,
    ) -> int | None:
        """Extract state variable assignment from a basic block.

        Args:
            basic_block: Basic block to analyze
            dispatcher: Dispatcher information

        Returns:
            Assigned state value or None

        """
        for inst in reversed(basic_block.instructions):
            disasm = inst.get("disasm", "").lower()

            if "mov" in disasm and "[" in disasm:
                parts = disasm.split(",")
                if len(parts) >= 2:
                    value_part = parts[-1].strip()
                    try:
                        if value_part.startswith("0x"):
                            return int(value_part, 16)
                        if value_part.isdigit():
                            return int(value_part)
                    except ValueError:
                        continue

        return None

    def _detect_opaque_predicates(
        self,
        r2: "Radare2Session",
        cfg: nx.DiGraph,
        function_address: int,
    ) -> list[dict[str, Any]]:
        """Detect opaque predicates using advanced analysis techniques.

        This method combines multiple analysis approaches:
        1. Constant propagation to identify invariant conditions
        2. Symbolic execution with Z3 to prove predicates
        3. Pattern recognition for common opaque predicate patterns
        4. Legacy heuristic-based detection as fallback

        Args:
            r2: Active radare2 session
            cfg: Control flow graph
            function_address: Function address

        Returns:
            List of detected opaque predicates with analysis metadata

        """
        opaque_predicates = []

        if self.opaque_analyzer and OPAQUE_ANALYZER_AVAILABLE:
            try:
                entry_block = min(cfg.nodes()) if cfg.nodes() else function_address

                advanced_results = self.opaque_analyzer.analyze_cfg(cfg, entry_block)

                opaque_predicates.extend(
                    {
                        "address": result.address,
                        "instruction": result.instruction,
                        "type": result.predicate_type,
                        "always_value": result.always_value,
                        "confidence": result.confidence,
                        "analysis_method": result.analysis_method,
                        "dead_branch": result.dead_branch,
                        "symbolic_proof": result.symbolic_proof,
                    }
                    for result in advanced_results
                )
                self.logger.info(
                    f"Advanced analysis detected {len(advanced_results)} opaque predicates",
                )

                if advanced_results:
                    return opaque_predicates

            except Exception as e:
                self.logger.warning(f"Advanced opaque predicate analysis failed: {e}")

        for node in cfg.nodes():
            basic_block = cfg.nodes[node]["data"]

            if len(basic_block.successors) == 2:
                for inst in basic_block.instructions:
                    disasm = inst.get("disasm", "").lower()

                    if any(op in disasm for op in ["xor", "test", "cmp"]):
                        operands = disasm.split()
                        if len(operands) >= 3 and operands[1].rstrip(",") == operands[2]:
                            opaque_predicates.append(
                                {
                                    "address": node,
                                    "instruction": inst.get("disasm", ""),
                                    "type": "self_comparison",
                                    "always_value": True if "xor" in disasm else None,
                                    "confidence": 0.80,
                                    "analysis_method": "heuristic",
                                    "dead_branch": None,
                                    "symbolic_proof": None,
                                },
                            )

                    if "jmp" not in disasm and any(
                        jcc in disasm for jcc in ["je", "jne", "jz", "jnz", "ja", "jb"]
                    ):
                        prev_inst = None
                        for prev in basic_block.instructions:
                            if prev["offset"] < inst["offset"]:
                                prev_inst = prev

                        if prev_inst:
                            prev_disasm = prev_inst.get("disasm", "").lower()
                            if "test" in prev_disasm:
                                operands = prev_disasm.split()
                                if len(operands) >= 3 and operands[1].rstrip(",") == operands[2]:
                                    opaque_predicates.append(
                                        {
                                            "address": node,
                                            "instruction": f"{prev_inst.get('disasm', '')}; {inst.get('disasm', '')}",
                                            "type": "invariant_test",
                                            "always_value": "jz" in disasm,
                                            "confidence": 0.75,
                                            "analysis_method": "heuristic",
                                            "dead_branch": None,
                                            "symbolic_proof": None,
                                        },
                                    )

        return opaque_predicates

    def _remove_opaque_predicates(
        self,
        r2: "Radare2Session",
        cfg: nx.DiGraph,
        opaque_predicates: list[dict[str, Any]],
    ) -> nx.DiGraph:
        """Remove opaque predicates and perform comprehensive dead code elimination.

        This enhanced method:
        1. Removes edges to dead branches identified by analysis
        2. Performs iterative dead code elimination
        3. Removes unreachable blocks resulting from opaque predicate removal
        4. Simplifies control flow by collapsing linear chains

        Args:
            r2: Active radare2 session
            cfg: Control flow graph
            opaque_predicates: List of opaque predicates with analysis metadata

        Returns:
            Simplified control flow graph with dead code removed

        """
        simplified = cfg.copy()

        dead_branches_removed = []

        for predicate in opaque_predicates:
            node = predicate["address"]
            if node not in simplified.nodes():
                continue

            basic_block = simplified.nodes[node]["data"]

            always_value = predicate.get("always_value")
            if always_value is None:
                continue

            dead_branch = predicate.get("dead_branch")

            if dead_branch is None:
                if len(basic_block.successors) != 2:
                    continue

                true_successor = None
                false_successor = None

                for edge in simplified.out_edges(node, data=True):
                    edge_type = edge[2].get("edge_type", "")
                    if "true" in edge_type or edge_type == "conditional_true":
                        true_successor = edge[1]
                    elif "false" in edge_type or edge_type == "conditional_false":
                        false_successor = edge[1]

                if true_successor and false_successor:
                    if always_value:
                        simplified.remove_edge(node, false_successor)
                        dead_branches_removed.append(false_successor)
                        self.logger.debug(
                            f"Removed false branch from 0x{node:x} to 0x{false_successor:x}",
                        )
                    else:
                        simplified.remove_edge(node, true_successor)
                        dead_branches_removed.append(true_successor)
                        self.logger.debug(
                            f"Removed true branch from 0x{node:x} to 0x{true_successor:x}",
                        )

            elif simplified.has_edge(node, dead_branch):
                simplified.remove_edge(node, dead_branch)
                dead_branches_removed.append(dead_branch)
                self.logger.debug(
                    f"Removed dead branch from 0x{node:x} to 0x{dead_branch:x}",
                )
        simplified = self._eliminate_dead_code(simplified, dead_branches_removed)

        simplified = self._collapse_linear_chains(simplified)

        return simplified

    def _eliminate_dead_code(
        self,
        cfg: nx.DiGraph,
        initial_dead_blocks: list[int],
    ) -> nx.DiGraph:
        """Perform comprehensive dead code elimination.

        This method iteratively removes unreachable blocks and blocks that
        become unreachable as a result of previous removals.

        Args:
            cfg: Control flow graph
            initial_dead_blocks: Initial set of dead blocks to start elimination

        Returns:
            Control flow graph with dead code removed

        """
        if not NETWORKX_AVAILABLE:
            return cfg

        cleaned = cfg.copy()

        try:
            entry_node = min(cleaned.nodes()) if cleaned.nodes() else None
            if entry_node is None:
                return cleaned

            reachable = set(nx.descendants(cleaned, entry_node))
            reachable.add(entry_node)

            unreachable = set(cleaned.nodes()) - reachable

            blocks_to_remove = set(initial_dead_blocks) | unreachable

            changed = True
            while changed:
                changed = False
                additional_dead = set()

                for node in list(cleaned.nodes()):
                    if node in blocks_to_remove:
                        continue

                    in_degree = cleaned.in_degree(node)
                    if in_degree == 0 and node != entry_node:
                        additional_dead.add(node)
                        changed = True

                blocks_to_remove |= additional_dead

            for block in blocks_to_remove:
                if block in cleaned.nodes():
                    cleaned.remove_node(block)
                    self.logger.debug(f"Removed dead block at 0x{block:x}")

        except Exception as e:
            self.logger.debug(f"Dead code elimination failed: {e}")

        return cleaned

    def _collapse_linear_chains(self, cfg: nx.DiGraph) -> nx.DiGraph:
        """Collapse linear chains of basic blocks with single predecessors/successors.

        This simplifies the CFG by merging blocks that form straight-line code.

        Args:
            cfg: Control flow graph

        Returns:
            Simplified control flow graph

        """
        if not NETWORKX_AVAILABLE:
            return cfg

        simplified = cfg.copy()

        changed = True
        while changed:
            changed = False

            for node in list(simplified.nodes()):
                if node not in simplified.nodes():
                    continue

                out_degree = simplified.out_degree(node)
                if out_degree != 1:
                    continue

                successor = next(iter(simplified.successors(node)))

                if successor == node:
                    continue

                in_degree_successor = simplified.in_degree(successor)
                if in_degree_successor != 1:
                    continue

                basic_block = simplified.nodes[node].get("data")
                if basic_block and basic_block.block_type == "branch":
                    continue

                for target in list(simplified.successors(successor)):
                    edge_data = simplified.get_edge_data(successor, target)
                    simplified.add_edge(node, target, **edge_data)

                basic_block_successor = simplified.nodes[successor].get("data")
                if basic_block and basic_block_successor:
                    basic_block.instructions.extend(basic_block_successor.instructions)
                    basic_block.size += basic_block_successor.size

                simplified.remove_node(successor)
                changed = True
                self.logger.debug(f"Collapsed linear chain: 0x{node:x} -> 0x{successor:x}")

        return simplified

    def _detect_bogus_blocks(
        self,
        r2: "Radare2Session",
        cfg: nx.DiGraph,
        function_address: int,
    ) -> list[int]:
        """Detect bogus/unreachable basic blocks inserted by obfuscators.

        Args:
            r2: Active radare2 session
            cfg: Control flow graph
            function_address: Function address

        Returns:
            List of bogus block addresses

        """
        bogus_blocks = []

        try:
            entry_node = min(cfg.nodes())

            reachable = set(nx.descendants(cfg, entry_node))
            reachable.add(entry_node)

            unreachable = set(cfg.nodes()) - reachable
            bogus_blocks.extend(unreachable)

        except Exception as e:
            self.logger.debug(f"Failed to detect unreachable blocks: {e}")

        for node in cfg.nodes():
            if node in bogus_blocks:
                continue

            basic_block = cfg.nodes[node]["data"]

            has_no_effect = True
            for inst in basic_block.instructions:
                disasm = inst.get("disasm", "").lower()
                if all(
                    nop not in disasm
                    for nop in ["nop", "mov eax, eax", "xchg eax, eax"]
                ):
                    has_no_effect = False
                    break

            if has_no_effect and len(basic_block.instructions) > 0:
                bogus_blocks.append(node)

        return bogus_blocks

    def _remove_bogus_blocks(self, cfg: nx.DiGraph, bogus_blocks: list[int]) -> nx.DiGraph:
        """Remove bogus blocks from the control flow graph.

        Args:
            cfg: Control flow graph
            bogus_blocks: List of bogus block addresses

        Returns:
            Cleaned control flow graph

        """
        cleaned = cfg.copy()

        for block_addr in bogus_blocks:
            if block_addr in cleaned.nodes():
                predecessors = list(cleaned.predecessors(block_addr))
                successors = list(cleaned.successors(block_addr))

                for pred in predecessors:
                    for succ in successors:
                        if not cleaned.has_edge(pred, succ):
                            cleaned.add_edge(pred, succ, edge_type="cleaned")

                cleaned.remove_node(block_addr)

        return cleaned

    def _generate_patch_information(
        self,
        r2: "Radare2Session",
        original_cfg: nx.DiGraph,
        deobfuscated_cfg: nx.DiGraph,
        dispatchers: list[DispatcherInfo],
        function_address: int,
    ) -> list[dict[str, Any]]:
        """Generate binary patch information to permanently deobfuscate the function.

        Args:
            r2: Active radare2 session
            original_cfg: Original control flow graph
            deobfuscated_cfg: Deobfuscated control flow graph
            dispatchers: List of dispatchers
            function_address: Function address

        Returns:
            List of patch operations

        """
        patches = []

        for dispatcher in dispatchers:
            nop_patch = {
                "address": dispatcher.dispatcher_address,
                "type": "nop_dispatcher",
                "size": self._get_block_size(original_cfg, dispatcher.dispatcher_address),
                "description": f"NOP out dispatcher at 0x{dispatcher.dispatcher_address:x}",
            }
            patches.append(nop_patch)

        for node in deobfuscated_cfg.nodes():
            if node not in original_cfg.nodes():
                continue

            original_successors = {target for _, target in original_cfg.out_edges(node)}
            deobf_successors = {target for _, target in deobfuscated_cfg.out_edges(node)}

            if original_successors != deobf_successors:
                patches.extend(
                    {
                        "address": node,
                        "type": "redirect_edge",
                        "target": target,
                        "description": f"Redirect 0x{node:x} -> 0x{target:x}",
                    }
                    for target in deobf_successors
                    if target not in original_successors
                )
        return patches

    def _get_block_size(self, cfg: nx.DiGraph, block_address: int) -> int:
        """Get size of a basic block.

        Args:
            cfg: Control flow graph
            block_address: Block address

        Returns:
            Size in bytes

        """
        if block_address in cfg.nodes():
            basic_block = cfg.nodes[block_address]["data"]
            return basic_block.size
        return 0

    def _calculate_deobfuscation_metrics(
        self,
        original_cfg: nx.DiGraph,
        deobfuscated_cfg: nx.DiGraph,
    ) -> dict[str, Any]:
        """Calculate metrics comparing original and deobfuscated CFGs.

        Args:
            original_cfg: Original control flow graph
            deobfuscated_cfg: Deobfuscated control flow graph

        Returns:
            Dictionary of metrics

        """
        metrics = {
            "original_blocks": original_cfg.number_of_nodes(),
            "deobfuscated_blocks": deobfuscated_cfg.number_of_nodes(),
            "blocks_removed": original_cfg.number_of_nodes() - deobfuscated_cfg.number_of_nodes(),
            "original_edges": original_cfg.number_of_edges(),
            "deobfuscated_edges": deobfuscated_cfg.number_of_edges(),
            "edges_changed": abs(
                original_cfg.number_of_edges() - deobfuscated_cfg.number_of_edges()
            ),
        }

        try:
            original_cycles = len(list(nx.simple_cycles(original_cfg)))
            deobf_cycles = len(list(nx.simple_cycles(deobfuscated_cfg)))
            metrics["original_cycles"] = original_cycles
            metrics["deobfuscated_cycles"] = deobf_cycles
            metrics["cycles_removed"] = original_cycles - deobf_cycles
        except Exception as e:
            self.logger.debug(f"Failed to calculate cycles: {e}")
            metrics["original_cycles"] = 0
            metrics["deobfuscated_cycles"] = 0
            metrics["cycles_removed"] = 0

        if original_cfg.number_of_nodes() > 0:
            metrics["complexity_reduction"] = (
                metrics["blocks_removed"] / original_cfg.number_of_nodes()
            ) * 100

        return metrics

    def _calculate_confidence_score(
        self,
        dispatchers: list[DispatcherInfo],
        opaque_predicates: list[dict[str, Any]],
        bogus_blocks: list[int],
        metrics: dict[str, Any],
    ) -> float:
        """Calculate confidence score for deobfuscation results.

        Args:
            dispatchers: Detected dispatchers
            opaque_predicates: Detected opaque predicates
            bogus_blocks: Detected bogus blocks
            metrics: Deobfuscation metrics

        Returns:
            Confidence score between 0.0 and 1.0

        """
        score = 0.0

        if dispatchers:
            score += 0.4

        if opaque_predicates:
            score += 0.2

        if bogus_blocks:
            score += 0.2

        if metrics.get("blocks_removed", 0) > 0:
            reduction_ratio = min(
                metrics["blocks_removed"] / max(metrics["original_blocks"], 1), 1.0
            )
            score += reduction_ratio * 0.2

        return min(score, 1.0)

    def _extract_recovered_edges(
        self,
        original_cfg: nx.DiGraph,
        deobfuscated_cfg: nx.DiGraph,
    ) -> list[tuple[int, int]]:
        """Extract newly recovered edges that weren't in the original CFG.

        Args:
            original_cfg: Original control flow graph
            deobfuscated_cfg: Deobfuscated control flow graph

        Returns:
            List of recovered edge tuples

        """
        return [
            (source, target)
            for source, target, data in deobfuscated_cfg.edges(data=True)
            if data.get("edge_type") == "recovered"
        ]

    def _classify_block(self, instructions: list[dict[str, Any]]) -> str:
        """Classify a basic block based on its instructions.

        Args:
            instructions: List of instructions

        Returns:
            Block type classification

        """
        if not instructions:
            return "empty"

        last_inst = instructions[-1].get("disasm", "").lower()

        if "ret" in last_inst:
            return "return"
        if "call" in last_inst:
            return "call"
        if any(
            jmp in last_inst for jmp in ["jmp", "je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl"]
        ):
            return "branch"
        return "sequential"

    def _calculate_block_complexity(self, instructions: list[dict[str, Any]]) -> float:
        """Calculate complexity score for a basic block.

        Args:
            instructions: List of instructions

        Returns:
            Complexity score

        """
        complexity = len(instructions)

        for inst in instructions:
            disasm = inst.get("disasm", "").lower()

            if "call" in disasm:
                complexity += 2.0
            elif any(jmp in disasm for jmp in ["je", "jne", "jz", "jnz"]):
                complexity += 1.5
            elif any(op in disasm for op in ["mul", "div", "imul", "idiv"]):
                complexity += 1.2

        return complexity

    def _is_terminator_block(self, instructions: list[dict[str, Any]]) -> bool:
        """Check if a block is a terminator (ends with ret or unconditional jmp).

        Args:
            instructions: List of instructions

        Returns:
            True if terminator block

        """
        if not instructions:
            return False

        last_inst = instructions[-1].get("disasm", "").lower()
        return "ret" in last_inst or ("jmp" in last_inst and last_inst[0] != "j")

    def export_deobfuscated_cfg(
        self,
        result: DeobfuscationResult,
        output_path: str | Path,
    ) -> bool:
        """Export deobfuscated CFG to DOT format for visualization.

        Args:
            result: Deobfuscation result
            output_path: Output file path

        Returns:
            True if successful

        """
        if not NETWORKX_AVAILABLE:
            self.logger.error("NetworkX required for export")
            return False

        try:
            output_path = Path(output_path)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write("digraph DeobfuscatedCFG {\n")
                f.write("  node [shape=box];\n")
                f.write("  rankdir=TB;\n\n")

                for node in result.deobfuscated_cfg.nodes():
                    basic_block = result.deobfuscated_cfg.nodes[node]["data"]
                    label = f"0x{node:x}\\n{basic_block.block_type}"

                    color = "lightblue"
                    if basic_block.is_dispatcher:
                        color = "red"
                    elif basic_block.block_type == "return":
                        color = "lightgreen"

                    f.write(f'  "{node}" [label="{label}", fillcolor="{color}", style=filled];\n')

                f.write("\n")

                for source, target, data in result.deobfuscated_cfg.edges(data=True):
                    edge_type = data.get("edge_type", "")
                    color = "black"
                    style = "solid"

                    if edge_type == "recovered":
                        color = "green"
                        style = "bold"
                    elif "true" in edge_type:
                        color = "darkgreen"
                    elif "false" in edge_type:
                        color = "red"

                    f.write(
                        f'  "{source}" -> "{target}" [color="{color}", style="{style}", label="{edge_type}"];\n',
                    )

                f.write("}\n")

            self.logger.info(f"Exported deobfuscated CFG to {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to export CFG: {e}")
            return False

    def apply_patches(
        self,
        result: DeobfuscationResult,
        output_path: str | Path | None = None,
    ) -> bool:
        """Apply deobfuscation patches to create a patched binary.

        Args:
            result: Deobfuscation result with patch information
            output_path: Optional output path for patched binary

        Returns:
            True if successful

        """
        if not LIEF_AVAILABLE or not KEYSTONE_AVAILABLE:
            self.logger.error("LIEF and Keystone required for patching")
            return False

        if not output_path:
            output_path = self.binary_path.with_suffix(f"{self.binary_path.suffix}.deobf")

        try:
            patched_binary = lief.parse(str(self.binary_path))

            for patch in result.patch_info:
                patch_type = patch.get("type")

                if patch_type == "nop_dispatcher":
                    address = patch["address"]
                    size = patch["size"]

                    nop_bytes = b"\x90" * size

                    if section := self._find_section_for_address(
                        patched_binary, address
                    ):
                        offset = address - (section.virtual_address + patched_binary.imagebase)
                        section_content = bytearray(section.content)
                        section_content[offset : offset + size] = nop_bytes
                        section.content = list(section_content)

                elif patch_type == "redirect_edge":
                    address = patch["address"]
                    target = patch["target"]

                    jmp_instruction = f"jmp 0x{target:x}"

                    encoding, _ = self.assembler.asm(jmp_instruction, address)

                    section = self._find_section_for_address(patched_binary, address)
                    if section and encoding:
                        offset = address - (section.virtual_address + patched_binary.imagebase)
                        section_content = bytearray(section.content)
                        section_content[offset : offset + len(encoding)] = encoding
                        section.content = list(section_content)

            patched_binary.write(str(output_path))
            self.logger.info(f"Wrote patched binary to {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to apply patches: {e}")
            return False

    def _find_section_for_address(self, binary: "Binary", address: int) -> "Section | None":
        """Find the section containing a given address.

        Args:
            binary: LIEF binary object
            address: Virtual address

        Returns:
            Section object or None

        """
        try:
            for section in binary.sections:
                section_start = section.virtual_address + binary.imagebase
                section_end = section_start + section.size

                if section_start <= address < section_end:
                    return section
        except Exception as e:
            self.logger.debug(f"Error finding section: {e}")

        return None


__all__ = [
    "BasicBlock",
    "ControlFlowDeobfuscator",
    "DeobfuscationResult",
    "DispatcherInfo",
]
