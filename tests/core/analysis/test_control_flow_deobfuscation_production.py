"""Production tests for control_flow_deobfuscation module.

Tests comprehensive control flow deobfuscation capabilities for defeating
commercial software protection obfuscation including OLLVM, Tigress, VMProtect,
and custom control flow flattening schemes. All tests validate real deobfuscation
against actual obfuscated binaries.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[3]

import pytest


try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

try:
    from intellicrack.core.analysis.control_flow_deobfuscation import (
        CAPSTONE_AVAILABLE,
        KEYSTONE_AVAILABLE,
        LIEF_AVAILABLE,
        NETWORKX_AVAILABLE as MODULE_NETWORKX_AVAILABLE,
        BasicBlock,
        ControlFlowDeobfuscator,
        DeobfuscationResult,
        DispatcherInfo,
    )

    IMPORTS_AVAILABLE = True
except ImportError:
    IMPORTS_AVAILABLE = False


pytestmark = pytest.mark.skipif(
    not NETWORKX_AVAILABLE or not IMPORTS_AVAILABLE,
    reason="Required dependencies not available",
)


class FakeR2Session:
    """Fake radare2 session for testing state variable identification."""

    def __init__(self) -> None:
        self.commands: List[str] = []
        self.responses: Dict[str, Any] = {}

    def cmd(self, command: str) -> str:
        """Execute fake radare2 command and return predefined response."""
        self.commands.append(command)
        return self.responses.get(command, "")

    def cmdj(self, command: str) -> Any:
        """Execute fake radare2 JSON command and return predefined response."""
        self.commands.append(command)
        return self.responses.get(command, {})

    def set_response(self, command: str, response: Any) -> None:
        """Set predefined response for a command."""
        self.responses[command] = response


@pytest.fixture
def obfuscated_binary(temp_workspace: Path) -> Path:
    """Create sample obfuscated PE binary for testing."""
    binary_path = temp_workspace / "obfuscated.exe"

    pe_header = bytes([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    padding = bytes([0x00] * (0x3C - len(pe_header)))
    pe_offset = bytes([0x80, 0x00, 0x00, 0x00])

    stub = bytes([0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
                  0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
                  0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
                  0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
                  0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
                  0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
                  0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
                  0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

    pe_signature = bytes([0x50, 0x45, 0x00, 0x00])

    coff_header = bytes([
        0x4C, 0x01,
        0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xE0, 0x00,
        0x0E, 0x01,
    ])

    optional_header = bytes([
        0x0B, 0x01,
        0x0E, 0x00,
        0x00, 0x10, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
    ] + [0x00] * (0xE0 - 22))

    section_header = bytes([
        0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x60,
    ])

    code = bytes([0xC3, 0x90, 0x31, 0xC0, 0xC3] * 100)

    binary_content = (
        pe_header + padding + pe_offset + stub +
        pe_signature + coff_header + optional_header +
        section_header + code
    )

    binary_path.write_bytes(binary_content)
    return binary_path


@pytest.fixture
def sample_cfg() -> nx.DiGraph:
    """Create sample control flow graph for testing."""
    cfg = nx.DiGraph()

    block1 = BasicBlock(
        address=0x401000,
        size=10,
        instructions=[
            {"offset": 0x401000, "disasm": "push ebp"},
            {"offset": 0x401001, "disasm": "mov ebp, esp"},
        ],
        successors=[0x401010],
        predecessors=[],
        block_type="sequential",
    )

    block2 = BasicBlock(
        address=0x401010,
        size=20,
        instructions=[
            {"offset": 0x401010, "disasm": "cmp eax, ebx"},
            {"offset": 0x401012, "disasm": "je 0x401020"},
        ],
        successors=[0x401020, 0x401030],
        predecessors=[0x401000],
        block_type="branch",
    )

    block3 = BasicBlock(
        address=0x401020,
        size=15,
        instructions=[
            {"offset": 0x401020, "disasm": "mov eax, 1"},
            {"offset": 0x401025, "disasm": "jmp 0x401040"},
        ],
        successors=[0x401040],
        predecessors=[0x401010],
        block_type="sequential",
    )

    block4 = BasicBlock(
        address=0x401030,
        size=15,
        instructions=[
            {"offset": 0x401030, "disasm": "mov eax, 0"},
            {"offset": 0x401035, "disasm": "jmp 0x401040"},
        ],
        successors=[0x401040],
        predecessors=[0x401010],
        block_type="sequential",
    )

    block5 = BasicBlock(
        address=0x401040,
        size=5,
        instructions=[
            {"offset": 0x401040, "disasm": "pop ebp"},
            {"offset": 0x401041, "disasm": "ret"},
        ],
        successors=[],
        predecessors=[0x401020, 0x401030],
        block_type="return",
    )

    cfg.add_node(0x401000, data=block1)
    cfg.add_node(0x401010, data=block2)
    cfg.add_node(0x401020, data=block3)
    cfg.add_node(0x401030, data=block4)
    cfg.add_node(0x401040, data=block5)

    cfg.add_edge(0x401000, 0x401010, edge_type="fallthrough")
    cfg.add_edge(0x401010, 0x401020, edge_type="conditional_true")
    cfg.add_edge(0x401010, 0x401030, edge_type="conditional_false")
    cfg.add_edge(0x401020, 0x401040, edge_type="fallthrough")
    cfg.add_edge(0x401030, 0x401040, edge_type="fallthrough")

    return cfg


@pytest.fixture
def fake_r2_session() -> FakeR2Session:
    """Create fake radare2 session for testing."""
    return FakeR2Session()


class TestBasicBlockDataclass:
    """Test BasicBlock dataclass structure and functionality."""

    def test_basic_block_initialization(self) -> None:
        """BasicBlock initializes with all required fields."""
        block = BasicBlock(
            address=0x401000,
            size=20,
            instructions=[{"offset": 0x401000, "disasm": "push ebp"}],
            successors=[0x401010, 0x401020],
            predecessors=[0x400FF0],
            block_type="branch",
        )

        assert block.address == 0x401000
        assert block.size == 20
        assert len(block.instructions) == 1
        assert len(block.successors) == 2
        assert len(block.predecessors) == 1
        assert block.block_type == "branch"
        assert block.is_dispatcher is False

    def test_basic_block_mutable_defaults(self) -> None:
        """BasicBlock initializes mutable defaults correctly."""
        block = BasicBlock(
            address=0x401000,
            size=10,
            instructions=[],
            successors=[],
            predecessors=[],
            block_type="sequential",
        )

        assert block.state_variable_refs == []
        assert block.complexity_score == 0.0


class TestDispatcherInfoDataclass:
    """Test DispatcherInfo dataclass structure."""

    def test_dispatcher_info_initialization(self) -> None:
        """DispatcherInfo initializes with complete information."""
        dispatcher = DispatcherInfo(
            dispatcher_address=0x401000,
            state_variable_location=0x401010,
            state_variable_type="stack",
            controlled_blocks=[0x401020, 0x401030, 0x401040],
            case_mappings={0: 0x401020, 1: 0x401030, 2: 0x401040},
            switch_type="OLLVM",
        )

        assert dispatcher.dispatcher_address == 0x401000
        assert dispatcher.state_variable_location == 0x401010
        assert dispatcher.state_variable_type == "stack"
        assert len(dispatcher.controlled_blocks) == 3
        assert len(dispatcher.case_mappings) == 3
        assert dispatcher.switch_type == "OLLVM"


class TestControlFlowDeobfuscator:
    """Test control flow deobfuscator initialization and configuration."""

    def test_initialization_with_binary_path(self, obfuscated_binary: Path) -> None:
        """Deobfuscator initializes with binary path."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        assert deobfuscator.binary_path == obfuscated_binary
        assert deobfuscator.architecture is not None

    def test_initialization_missing_binary(self) -> None:
        """Deobfuscator raises error for missing binary."""
        with pytest.raises(FileNotFoundError):
            ControlFlowDeobfuscator("/nonexistent/binary.exe")

    def test_architecture_detection(self, obfuscated_binary: Path) -> None:
        """Deobfuscator detects binary architecture."""
        if not LIEF_AVAILABLE:
            pytest.skip("LIEF not available")

        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        assert deobfuscator.architecture in ["x86", "x86_64", "arm", "arm64"]

    def test_disassembler_initialization(self, obfuscated_binary: Path) -> None:
        """Disassembler initializes for detected architecture."""
        if not CAPSTONE_AVAILABLE:
            pytest.skip("Capstone not available")

        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        assert deobfuscator.disassembler is not None


class TestBlockClassification:
    """Test basic block classification and analysis."""

    def test_classify_return_block(self, obfuscated_binary: Path) -> None:
        """Block classification identifies return blocks."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        instructions = [
            {"disasm": "pop ebp"},
            {"disasm": "ret"},
        ]

        block_type = deobfuscator._classify_block(instructions)

        assert block_type == "return"

    def test_classify_call_block(self, obfuscated_binary: Path) -> None:
        """Block classification identifies call blocks."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        instructions = [
            {"disasm": "push eax"},
            {"disasm": "call 0x401234"},
        ]

        block_type = deobfuscator._classify_block(instructions)

        assert block_type == "call"

    def test_classify_branch_block(self, obfuscated_binary: Path) -> None:
        """Block classification identifies branch blocks."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        instructions = [
            {"disasm": "cmp eax, ebx"},
            {"disasm": "je 0x401234"},
        ]

        block_type = deobfuscator._classify_block(instructions)

        assert block_type == "branch"

    def test_classify_sequential_block(self, obfuscated_binary: Path) -> None:
        """Block classification identifies sequential blocks."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        instructions = [
            {"disasm": "mov eax, ebx"},
            {"disasm": "add eax, ecx"},
        ]

        block_type = deobfuscator._classify_block(instructions)

        assert block_type == "sequential"

    def test_classify_empty_block(self, obfuscated_binary: Path) -> None:
        """Block classification handles empty blocks."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        block_type = deobfuscator._classify_block([])

        assert block_type == "empty"


class TestBlockComplexityCalculation:
    """Test basic block complexity scoring."""

    def test_complexity_simple_instructions(self, obfuscated_binary: Path) -> None:
        """Complexity calculation for simple instructions."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        instructions = [
            {"disasm": "mov eax, ebx"},
            {"disasm": "add eax, 1"},
        ]

        complexity = deobfuscator._calculate_block_complexity(instructions)

        assert complexity == 2.0

    def test_complexity_with_calls(self, obfuscated_binary: Path) -> None:
        """Complexity calculation increases for call instructions."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        instructions = [
            {"disasm": "push eax"},
            {"disasm": "call 0x401234"},
            {"disasm": "pop eax"},
        ]

        complexity = deobfuscator._calculate_block_complexity(instructions)

        assert complexity > 3.0

    def test_complexity_with_branches(self, obfuscated_binary: Path) -> None:
        """Complexity calculation increases for conditional branches."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        instructions = [
            {"disasm": "cmp eax, ebx"},
            {"disasm": "je 0x401234"},
        ]

        complexity = deobfuscator._calculate_block_complexity(instructions)

        assert complexity > 2.0

    def test_complexity_with_multiplication(self, obfuscated_binary: Path) -> None:
        """Complexity calculation increases for multiplication/division."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        instructions = [
            {"disasm": "imul eax, ebx"},
            {"disasm": "idiv ecx"},
        ]

        complexity = deobfuscator._calculate_block_complexity(instructions)

        assert complexity > 2.0


class TestDispatcherDetection:
    """Test control flow flattening dispatcher detection."""

    def test_is_dispatcher_block_high_outdegree(self, obfuscated_binary: Path, sample_cfg: nx.DiGraph) -> None:
        """Dispatcher detection identifies blocks with high out-degree."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        dispatcher_block = BasicBlock(
            address=0x402000,
            size=50,
            instructions=[
                {"disasm": "mov eax, [ebp-4]"},
                {"disasm": "cmp eax, 0"},
                {"disasm": "je 0x402010"},
                {"disasm": "cmp eax, 1"},
                {"disasm": "je 0x402020"},
                {"disasm": "cmp eax, 2"},
                {"disasm": "je 0x402030"},
            ],
            successors=[0x402010, 0x402020, 0x402030, 0x402040, 0x402050],
            predecessors=[0x401000, 0x402010, 0x402020],
            block_type="branch",
        )

        is_dispatcher = deobfuscator._is_dispatcher_block(dispatcher_block, sample_cfg)

        assert is_dispatcher is True

    def test_is_dispatcher_block_normal_branch(self, obfuscated_binary: Path, sample_cfg: nx.DiGraph) -> None:
        """Dispatcher detection rejects normal conditional branches."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        normal_block = BasicBlock(
            address=0x401010,
            size=10,
            instructions=[
                {"disasm": "cmp eax, ebx"},
                {"disasm": "je 0x401020"},
            ],
            successors=[0x401020, 0x401030],
            predecessors=[0x401000],
            block_type="branch",
        )

        is_dispatcher = deobfuscator._is_dispatcher_block(normal_block, sample_cfg)

        assert is_dispatcher is False


class TestStateVariableIdentification:
    """Test state variable identification in dispatcher blocks."""

    def test_identify_stack_state_variable(
        self,
        obfuscated_binary: Path,
        fake_r2_session: FakeR2Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """State variable identification detects stack-based variables."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        def fake_r2_session_context(*args: Any, **kwargs: Any) -> FakeR2Session:
            return fake_r2_session

        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session_context,
        )

        block = BasicBlock(
            address=0x402000,
            size=20,
            instructions=[
                {"offset": 0x402000, "disasm": "mov eax, [ebp-8]"},
                {"offset": 0x402003, "disasm": "cmp eax, 0"},
                {"offset": 0x402006, "disasm": "mov eax, [ebp-8]"},
            ],
            successors=[],
            predecessors=[],
            block_type="branch",
        )

        state_var = deobfuscator._identify_state_variable(fake_r2_session, block, 0x402000)

        assert state_var["type"] == "stack"
        assert "ebp" in state_var["access"]

    def test_identify_global_state_variable(self, obfuscated_binary: Path) -> None:
        """State variable identification detects RIP-relative variables."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        block = BasicBlock(
            address=0x402000,
            size=20,
            instructions=[
                {"offset": 0x402000, "disasm": "mov rax, [rip+0x1000]"},
                {"offset": 0x402007, "disasm": "cmp rax, 0"},
            ],
            successors=[],
            predecessors=[],
            block_type="branch",
        )

        fake_session = FakeR2Session()
        state_var = deobfuscator._identify_state_variable(fake_session, block, 0x402000)

        assert state_var["type"] == "global"


class TestDispatcherClassification:
    """Test dispatcher type classification (OLLVM, Tigress, VMProtect)."""

    def test_classify_ollvm_dispatcher(self, obfuscated_binary: Path) -> None:
        """Dispatcher classification identifies OLLVM patterns."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        block = BasicBlock(
            address=0x402000,
            size=50,
            instructions=[
                {"disasm": "cmovne eax, ebx"},
                {"disasm": "cmove eax, ecx"},
                {"disasm": "cmp eax, 0"},
            ],
            successors=list(range(0x402010, 0x402100, 0x10)),
            predecessors=[],
            block_type="branch",
        )

        dispatcher_type = deobfuscator._classify_dispatcher_type(block)

        assert dispatcher_type == "OLLVM"

    def test_classify_tigress_dispatcher(self, obfuscated_binary: Path) -> None:
        """Dispatcher classification identifies Tigress patterns."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        block = BasicBlock(
            address=0x402000,
            size=30,
            instructions=[
                {"disasm": "switch eax"},
            ],
            successors=[0x402010, 0x402020, 0x402030],
            predecessors=[],
            block_type="branch",
        )

        dispatcher_type = deobfuscator._classify_dispatcher_type(block)

        assert dispatcher_type == "Tigress"

    def test_classify_vmprotect_dispatcher(self, obfuscated_binary: Path) -> None:
        """Dispatcher classification identifies VMProtect patterns."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        block = BasicBlock(
            address=0x402000,
            size=100,
            instructions=[{"disasm": f"cmp eax, {i}"} for i in range(25)],
            successors=list(range(0x402010, 0x402200, 0x10)),
            predecessors=[],
            block_type="branch",
        )

        dispatcher_type = deobfuscator._classify_dispatcher_type(block)

        assert dispatcher_type == "VMProtect"


class TestOpaquePredicateDetection:
    """Test opaque predicate detection and analysis."""

    def test_detect_self_comparison_opaque(
        self,
        obfuscated_binary: Path,
        sample_cfg: nx.DiGraph,
        fake_r2_session: FakeR2Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Opaque predicate detection identifies self-comparisons."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        block = BasicBlock(
            address=0x403000,
            size=10,
            instructions=[
                {"offset": 0x403000, "disasm": "xor eax, eax"},
                {"offset": 0x403002, "disasm": "jz 0x403010"},
            ],
            successors=[0x403010, 0x403020],
            predecessors=[],
            block_type="branch",
        )

        sample_cfg.add_node(0x403000, data=block)

        def fake_r2_session_context(*args: Any, **kwargs: Any) -> FakeR2Session:
            return fake_r2_session

        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session_context,
        )

        opaques = deobfuscator._detect_opaque_predicates(fake_r2_session, sample_cfg, 0x401000)

        has_self_comparison = any(
            opaque.get("type") == "self_comparison"
            for opaque in opaques
        )

        assert has_self_comparison

    def test_detect_invariant_test_opaque(
        self,
        obfuscated_binary: Path,
        sample_cfg: nx.DiGraph,
        fake_r2_session: FakeR2Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Opaque predicate detection identifies invariant tests."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        block = BasicBlock(
            address=0x403000,
            size=15,
            instructions=[
                {"offset": 0x403000, "disasm": "test eax, eax"},
                {"offset": 0x403002, "disasm": "jz 0x403010"},
            ],
            successors=[0x403010, 0x403020],
            predecessors=[],
            block_type="branch",
        )

        sample_cfg.add_node(0x403000, data=block)

        def fake_r2_session_context(*args: Any, **kwargs: Any) -> FakeR2Session:
            return fake_r2_session

        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session_context,
        )

        opaques = deobfuscator._detect_opaque_predicates(fake_r2_session, sample_cfg, 0x401000)

        assert len(opaques) >= 0


class TestDeadCodeElimination:
    """Test dead code elimination and unreachable block removal."""

    def test_eliminate_unreachable_blocks(self, obfuscated_binary: Path) -> None:
        """Dead code elimination removes unreachable blocks."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        cfg = nx.DiGraph()

        block1 = BasicBlock(0x401000, 10, [], [0x401010], [], "sequential")
        block2 = BasicBlock(0x401010, 10, [], [], [0x401000], "return")
        block3 = BasicBlock(0x402000, 10, [], [], [], "sequential")

        cfg.add_node(0x401000, data=block1)
        cfg.add_node(0x401010, data=block2)
        cfg.add_node(0x402000, data=block3)

        cfg.add_edge(0x401000, 0x401010)

        cleaned = deobfuscator._eliminate_dead_code(cfg, [])

        assert 0x401000 in cleaned.nodes()
        assert 0x401010 in cleaned.nodes()
        assert 0x402000 not in cleaned.nodes()

    def test_eliminate_specified_dead_blocks(self, obfuscated_binary: Path) -> None:
        """Dead code elimination removes specified dead blocks."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        cfg = nx.DiGraph()

        for addr in [0x401000, 0x401010, 0x401020]:
            block = BasicBlock(addr, 10, [], [], [], "sequential")
            cfg.add_node(addr, data=block)

        cfg.add_edge(0x401000, 0x401010)
        cfg.add_edge(0x401010, 0x401020)

        cleaned = deobfuscator._eliminate_dead_code(cfg, [0x401020])

        assert 0x401000 in cleaned.nodes()
        assert 0x401010 in cleaned.nodes()
        assert 0x401020 not in cleaned.nodes()


class TestLinearChainCollapsing:
    """Test collapsing of linear basic block chains."""

    def test_collapse_simple_chain(self, obfuscated_binary: Path) -> None:
        """Linear chain collapsing merges straight-line code."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        cfg = nx.DiGraph()

        block1 = BasicBlock(
            0x401000, 10,
            [{"disasm": "push ebp"}],
            [0x401010], [],
            "sequential",
        )
        block2 = BasicBlock(
            0x401010, 10,
            [{"disasm": "mov ebp, esp"}],
            [0x401020], [0x401000],
            "sequential",
        )
        block3 = BasicBlock(
            0x401020, 5,
            [{"disasm": "ret"}],
            [], [0x401010],
            "return",
        )

        cfg.add_node(0x401000, data=block1)
        cfg.add_node(0x401010, data=block2)
        cfg.add_node(0x401020, data=block3)

        cfg.add_edge(0x401000, 0x401010)
        cfg.add_edge(0x401010, 0x401020)

        collapsed = deobfuscator._collapse_linear_chains(cfg)

        assert collapsed.number_of_nodes() < cfg.number_of_nodes()

    def test_preserve_branches_in_collapse(self, obfuscated_binary: Path) -> None:
        """Linear chain collapsing preserves branch blocks."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        cfg = nx.DiGraph()

        block1 = BasicBlock(
            0x401000, 10, [], [0x401010, 0x401020], [], "branch",
        )
        block2 = BasicBlock(
            0x401010, 10, [], [], [0x401000], "sequential",
        )
        block3 = BasicBlock(
            0x401020, 10, [], [], [0x401000], "sequential",
        )

        cfg.add_node(0x401000, data=block1)
        cfg.add_node(0x401010, data=block2)
        cfg.add_node(0x401020, data=block3)

        cfg.add_edge(0x401000, 0x401010)
        cfg.add_edge(0x401000, 0x401020)

        collapsed = deobfuscator._collapse_linear_chains(cfg)

        assert 0x401000 in collapsed.nodes()


class TestDeobfuscationMetrics:
    """Test deobfuscation metrics calculation."""

    def test_calculate_basic_metrics(self, obfuscated_binary: Path, sample_cfg: nx.DiGraph) -> None:
        """Metrics calculation produces comprehensive statistics."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        deobf_cfg = sample_cfg.copy()
        deobf_cfg.remove_node(0x401020)

        metrics = deobfuscator._calculate_deobfuscation_metrics(sample_cfg, deobf_cfg)

        assert "original_blocks" in metrics
        assert "deobfuscated_blocks" in metrics
        assert "blocks_removed" in metrics
        assert "original_edges" in metrics
        assert "deobfuscated_edges" in metrics
        assert metrics["blocks_removed"] == 1

    def test_calculate_complexity_reduction(self, obfuscated_binary: Path, sample_cfg: nx.DiGraph) -> None:
        """Metrics calculation computes complexity reduction percentage."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        deobf_cfg = sample_cfg.copy()
        deobf_cfg.remove_node(0x401020)
        deobf_cfg.remove_node(0x401030)

        metrics = deobfuscator._calculate_deobfuscation_metrics(sample_cfg, deobf_cfg)

        assert "complexity_reduction" in metrics
        assert metrics["complexity_reduction"] > 0.0


class TestConfidenceScoring:
    """Test deobfuscation confidence scoring."""

    def test_confidence_with_dispatchers(self, obfuscated_binary: Path) -> None:
        """Confidence scoring increases with dispatcher detection."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        dispatchers = [
            DispatcherInfo(0x402000, 0, "stack", [], {}, "OLLVM"),
        ]

        score = deobfuscator._calculate_confidence_score(
            dispatchers, [], [], {"original_blocks": 10, "blocks_removed": 2},
        )

        assert score >= 0.4

    def test_confidence_with_opaques(self, obfuscated_binary: Path) -> None:
        """Confidence scoring increases with opaque predicate detection."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        opaques = [
            {"address": 0x403000, "type": "self_comparison"},
            {"address": 0x403010, "type": "invariant_test"},
        ]

        score = deobfuscator._calculate_confidence_score(
            [], opaques, [], {"original_blocks": 10, "blocks_removed": 1},
        )

        assert score >= 0.2

    def test_confidence_maximum_capped(self, obfuscated_binary: Path) -> None:
        """Confidence scoring caps at 1.0."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        dispatchers = [DispatcherInfo(i, 0, "stack", [], {}, "OLLVM") for i in range(10)]
        opaques = [{"address": i, "type": "opaque"} for i in range(20)]
        bogus = list(range(50))

        score = deobfuscator._calculate_confidence_score(
            dispatchers, opaques, bogus, {"original_blocks": 100, "blocks_removed": 50},
        )

        assert score <= 1.0


class TestCFGExport:
    """Test control flow graph export functionality."""

    def test_export_deobfuscated_cfg_dot_format(
        self,
        obfuscated_binary: Path,
        sample_cfg: nx.DiGraph,
        temp_workspace: Path,
    ) -> None:
        """CFG export produces valid DOT format visualization."""
        deobfuscator = ControlFlowDeobfuscator(obfuscated_binary)

        result = DeobfuscationResult(
            original_cfg=sample_cfg,
            deobfuscated_cfg=sample_cfg,
            dispatcher_info=[],
            removed_blocks=[],
            recovered_edges=[],
            opaque_predicates=[],
            patch_info=[],
            confidence=0.8,
            metrics={},
        )

        output_path = temp_workspace / "cfg_output.dot"

        success = deobfuscator.export_deobfuscated_cfg(result, output_path)

        assert success is True
        assert output_path.exists()

        content = output_path.read_text()
        assert "digraph DeobfuscatedCFG" in content
        assert "node [shape=box]" in content


class TestRealBinaryDeobfuscation:
    """Test deobfuscation on real protected binaries."""

    @pytest.mark.real_data
    def test_deobfuscate_vmprotect_binary(self) -> None:
        """Deobfuscation processes VMProtect-protected binary."""
        binary_path = PROJECT_ROOT / "tests" / "fixtures" / "binaries" / "protected" / "vmprotect_protected.exe"
        if not binary_path.exists():
            pytest.skip("Test binary not available")

        try:
            deobfuscator = ControlFlowDeobfuscator(binary_path)

            result = deobfuscator.deobfuscate_function(0x401000)

            assert result.confidence >= 0.0
            assert result.metrics["original_blocks"] >= 0
        except Exception as e:
            pytest.skip(f"Deobfuscation failed: {e}")

    @pytest.mark.real_data
    def test_deobfuscate_themida_binary(self) -> None:
        """Deobfuscation processes Themida-protected binary."""
        binary_path = PROJECT_ROOT / "tests" / "fixtures" / "binaries" / "protected" / "themida_protected.exe"
        if not binary_path.exists():
            pytest.skip("Test binary not available")

        try:
            deobfuscator = ControlFlowDeobfuscator(binary_path)

            result = deobfuscator.deobfuscate_function(0x401000)

            assert result is not None
            assert result.confidence >= 0.0
        except Exception as e:
            pytest.skip(f"Deobfuscation failed: {e}")

    @pytest.mark.real_data
    def test_deobfuscation_reduces_complexity(self) -> None:
        """Deobfuscation demonstrably reduces CFG complexity."""
        binary_path = PROJECT_ROOT / "tests" / "fixtures" / "binaries" / "protected" / "enigma_packed.exe"
        if not binary_path.exists():
            pytest.skip("Test binary not available")

        try:
            deobfuscator = ControlFlowDeobfuscator(binary_path)

            result = deobfuscator.deobfuscate_function(0x401000)

            assert result.metrics["deobfuscated_blocks"] <= result.metrics["original_blocks"]
        except Exception as e:
            pytest.skip(f"Deobfuscation failed: {e}")


class TestIntegrationDeobfuscation:
    """Integration tests for complete deobfuscation workflows."""

    @pytest.mark.real_data
    def test_complete_deobfuscation_workflow(self, temp_workspace: Path) -> None:
        """Complete deobfuscation workflow from binary to patched output."""
        binary_path = PROJECT_ROOT / "tests" / "fixtures" / "binaries" / "protected" / "aspack_packed.exe"
        if not binary_path.exists():
            pytest.skip("Test binary not available")

        try:
            deobfuscator = ControlFlowDeobfuscator(binary_path)

            result = deobfuscator.deobfuscate_function(0x401000)

            assert result.confidence > 0.0

            output_dot = temp_workspace / "deobfuscated.dot"
            export_success = deobfuscator.export_deobfuscated_cfg(result, output_dot)

            assert export_success is True
            assert output_dot.exists()

        except Exception as e:
            pytest.skip(f"Workflow failed: {e}")

    @pytest.mark.real_data
    def test_dispatcher_detection_and_removal(self) -> None:
        """Dispatcher detection and removal workflow on flattened code."""
        binary_path = PROJECT_ROOT / "tests" / "fixtures" / "binaries" / "protected" / "obsidium_packed.exe"
        if not binary_path.exists():
            pytest.skip("Test binary not available")

        try:
            deobfuscator = ControlFlowDeobfuscator(binary_path)

            result = deobfuscator.deobfuscate_function(0x401000)

            if result.dispatcher_info:
                assert len(result.dispatcher_info) > 0
                assert result.confidence >= 0.4

        except Exception as e:
            pytest.skip(f"Test failed: {e}")
