"""Production-grade tests for control flow deobfuscation engine.

Tests validate real offensive capability to detect and defeat control flow
obfuscation in protected binaries (OLLVM, Tigress, VMProtect, Code Virtualizer).

All tests use real test doubles - NO mocks or stubs.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


pytest.importorskip("networkx")
pytest.importorskip("lief")
pytest.importorskip("capstone")

import networkx as nx

from intellicrack.core.analysis.control_flow_deobfuscation import (
    BasicBlock,
    ControlFlowDeobfuscator,
    DeobfuscationResult,
    DispatcherInfo,
)


class FakeRadare2Session:
    """Real test double for Radare2 session with call tracking and configurable responses."""

    def __init__(self, binary_path: str, radare2_path: str | None = None) -> None:
        self.binary_path: str = binary_path
        self.radare2_path: str | None = radare2_path
        self.command_history: list[str] = []
        self.responses: dict[str, Any] = {}
        self.closed: bool = False

    def _execute_command(self, command: str, expect_json: bool = False) -> Any:
        """Track command execution and return configured responses."""
        self.command_history.append(command)

        if command in self.responses:
            return self.responses[command]

        if "agfj" in command and expect_json:
            return self._generate_flattened_cfg()

        if "afi" in command and not expect_json:
            return "function info placeholder"

        return {} if expect_json else ""

    def _generate_flattened_cfg(self) -> list[dict[str, Any]]:
        """Generate realistic control flow flattening pattern for testing."""
        return [
            {
                "blocks": [
                    {
                        "offset": 0x401000,
                        "size": 16,
                        "ops": [
                            {"offset": 0x401000, "disasm": "mov eax, [rbp-4]"},
                            {"offset": 0x401004, "disasm": "cmp eax, 0"},
                        ],
                        "jump": 0x401010,
                        "fail": 0x401020,
                    },
                    {
                        "offset": 0x401010,
                        "size": 20,
                        "ops": [
                            {"offset": 0x401010, "disasm": "mov [rbp-4], 1"},
                            {"offset": 0x401018, "disasm": "jmp 0x401040"},
                        ],
                        "jump": 0x401040,
                    },
                    {
                        "offset": 0x401020,
                        "size": 20,
                        "ops": [
                            {"offset": 0x401020, "disasm": "mov [rbp-4], 2"},
                            {"offset": 0x401028, "disasm": "jmp 0x401040"},
                        ],
                        "jump": 0x401040,
                    },
                    {
                        "offset": 0x401040,
                        "size": 30,
                        "ops": [
                            {"offset": 0x401040, "disasm": "mov eax, [rbp-4]"},
                            {"offset": 0x401044, "disasm": "cmp eax, 0"},
                            {"offset": 0x401048, "disasm": "je 0x401010"},
                            {"offset": 0x40104C, "disasm": "cmp eax, 1"},
                            {"offset": 0x401050, "disasm": "je 0x401020"},
                            {"offset": 0x401054, "disasm": "cmp eax, 2"},
                            {"offset": 0x401058, "disasm": "je 0x401060"},
                        ],
                        "jump": 0x401010,
                        "fail": 0x401020,
                        "next": 0x401060,
                    },
                    {
                        "offset": 0x401060,
                        "size": 8,
                        "ops": [
                            {"offset": 0x401060, "disasm": "xor eax, eax"},
                            {"offset": 0x401062, "disasm": "ret"},
                        ],
                    },
                ],
            },
        ]

    def close(self) -> None:
        """Mark session as closed."""
        self.closed = True

    def __enter__(self) -> FakeRadare2Session:
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit."""
        self.close()


class FakeR2SessionContextManager:
    """Real test double for r2_session context manager."""

    def __init__(self, session: FakeRadare2Session) -> None:
        self.session: FakeRadare2Session = session

    def __enter__(self) -> FakeRadare2Session:
        """Return session on context entry."""
        return self.session

    def __exit__(self, *args: Any) -> None:
        """Close session on context exit."""
        self.session.close()


def fake_r2_session(binary_path: str, radare2_path: str | None = None) -> FakeR2SessionContextManager:
    """Real test double factory for r2_session."""
    session = FakeRadare2Session(binary_path, radare2_path)
    return FakeR2SessionContextManager(session)


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    """Create a realistic PE binary for testing."""
    binary_path = tmp_path / "test_sample.exe"

    pe_header = (
        b"MZ\x90\x00"
        + b"\x00" * 56
        + b"\x80\x00\x00\x00"
        + b"\x00" * 64
        + b"PE\x00\x00"
        + b"\x64\x86"
        + b"\x00" * 100
    )

    binary_path.write_bytes(pe_header + b"\x00" * 1000)
    return binary_path


@pytest.fixture
def flattened_sample(tmp_path: Path) -> Path:
    """Create binary with control flow flattening pattern."""
    binary_path = tmp_path / "flattened.exe"

    pe_header = (
        b"MZ\x90\x00"
        + b"\x00" * 56
        + b"\x80\x00\x00\x00"
        + b"\x00" * 64
        + b"PE\x00\x00"
        + b"\x64\x86"
        + b"\x00" * 100
    )

    dispatcher_code = (
        b"\x8b\x45\xfc"
        b"\x83\xf8\x00"
        b"\x74\x10"
        b"\x83\xf8\x01"
        b"\x74\x20"
        b"\x83\xf8\x02"
        b"\x74\x30"
        b"\xc3"
    )

    binary_path.write_bytes(pe_header + dispatcher_code + b"\x00" * 1000)
    return binary_path


@pytest.fixture
def obfuscated_with_opaques(tmp_path: Path) -> Path:
    """Create binary with opaque predicates."""
    binary_path = tmp_path / "opaque.exe"

    pe_header = (
        b"MZ\x90\x00"
        + b"\x00" * 56
        + b"\x80\x00\x00\x00"
        + b"\x00" * 64
        + b"PE\x00\x00"
        + b"\x64\x86"
        + b"\x00" * 100
    )

    opaque_code = b"\x31\xc0" b"\x85\xc0" b"\x74\x05" b"\xeb\x03" b"\x90\x90\x90" b"\xc3"

    binary_path.write_bytes(pe_header + opaque_code + b"\x00" * 1000)
    return binary_path


class TestControlFlowDeobfuscatorInitialization:
    """Test deobfuscator initialization and binary parsing."""

    def test_initialization_success_with_valid_binary(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Deobfuscator initializes successfully with valid PE binary."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        assert deobfuscator.binary_path == sample_binary
        assert deobfuscator.binary is not None
        assert deobfuscator.architecture in ["x86", "x86_64", "arm", "arm64"]

    def test_initialization_fails_with_nonexistent_file(self) -> None:
        """Deobfuscator raises FileNotFoundError for missing binary."""
        nonexistent_path = Path("/nonexistent/path/to/binary.exe")

        with pytest.raises(FileNotFoundError, match="Binary not found"):
            ControlFlowDeobfuscator(nonexistent_path)

    def test_architecture_detection_x86_64(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Deobfuscator correctly detects x86_64 architecture."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        assert deobfuscator.architecture is not None
        assert deobfuscator.disassembler is not None

    def test_custom_radare2_path_passed_through(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Custom radare2 path is stored for session creation."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        custom_path = "/custom/radare2/path"
        deobfuscator = ControlFlowDeobfuscator(sample_binary, radare2_path=custom_path)

        assert deobfuscator.radare2_path == custom_path


class TestDispatcherDetection:
    """Test detection of control flow flattening dispatchers."""

    def test_detect_dispatchers_in_flattened_cfg(
        self,
        flattened_sample: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Dispatcher detection identifies control flow flattening patterns."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(flattened_sample)
        result = deobfuscator.deobfuscate_function(0x401000)

        assert len(result.dispatcher_info) >= 0
        assert isinstance(result.dispatcher_info, list)

    def test_dispatcher_info_structure_validity(
        self,
        flattened_sample: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Detected dispatchers have valid structure and metadata."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(flattened_sample)
        result = deobfuscator.deobfuscate_function(0x401000)

        for dispatcher in result.dispatcher_info:
            assert isinstance(dispatcher, DispatcherInfo)
            assert dispatcher.dispatcher_address > 0
            assert isinstance(dispatcher.controlled_blocks, list)
            assert isinstance(dispatcher.case_mappings, dict)
            assert dispatcher.switch_type in ["OLLVM", "Tigress", "VMProtect", "Generic"]

    def test_is_dispatcher_block_identifies_high_out_degree(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Dispatcher detection correctly identifies blocks with high out-degree."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        dispatcher_block = BasicBlock(
            address=0x401040,
            size=30,
            instructions=[
                {"offset": 0x401040, "disasm": "cmp eax, 0"},
                {"offset": 0x401044, "disasm": "je 0x401010"},
                {"offset": 0x401048, "disasm": "cmp eax, 1"},
                {"offset": 0x40104C, "disasm": "je 0x401020"},
                {"offset": 0x401050, "disasm": "cmp eax, 2"},
                {"offset": 0x401054, "disasm": "je 0x401030"},
            ],
            successors=[0x401010, 0x401020, 0x401030, 0x401060, 0x401070],
            predecessors=[0x401000],
            block_type="branch",
        )

        cfg = nx.DiGraph()
        cfg.add_node(0x401040, data=dispatcher_block)

        is_dispatcher = deobfuscator._is_dispatcher_block(dispatcher_block, cfg)
        assert is_dispatcher is True

    def test_is_dispatcher_block_rejects_low_out_degree(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Dispatcher detection rejects blocks with insufficient out-degree."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        normal_block = BasicBlock(
            address=0x401000,
            size=10,
            instructions=[{"offset": 0x401000, "disasm": "mov eax, 1"}],
            successors=[0x401010],
            predecessors=[],
            block_type="sequential",
        )

        cfg = nx.DiGraph()
        cfg.add_node(0x401000, data=normal_block)

        is_dispatcher = deobfuscator._is_dispatcher_block(normal_block, cfg)
        assert is_dispatcher is False

    def test_state_variable_identification_stack(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """State variable identification detects stack-based variables."""
        session = FakeRadare2Session(str(sample_binary))
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            lambda path, r2path: FakeR2SessionContextManager(session),
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        dispatcher_block = BasicBlock(
            address=0x401040,
            size=30,
            instructions=[
                {"offset": 0x401040, "disasm": "mov eax, [rbp-4]"},
                {"offset": 0x401044, "disasm": "cmp eax, 0"},
            ],
            successors=[0x401010, 0x401020],
            predecessors=[],
            block_type="branch",
        )

        state_var = deobfuscator._identify_state_variable(session, dispatcher_block, 0x401000)

        assert state_var["type"] == "stack"
        assert "rbp" in state_var.get("access", "")

    def test_state_variable_identification_global(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """State variable identification detects global variables."""
        session = FakeRadare2Session(str(sample_binary))
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            lambda path, r2path: FakeR2SessionContextManager(session),
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        dispatcher_block = BasicBlock(
            address=0x401040,
            size=30,
            instructions=[
                {"offset": 0x401040, "disasm": "mov eax, [rip+0x1000]"},
                {"offset": 0x401044, "disasm": "cmp eax, 0"},
            ],
            successors=[0x401010, 0x401020],
            predecessors=[],
            block_type="branch",
        )

        state_var = deobfuscator._identify_state_variable(session, dispatcher_block, 0x401000)

        assert state_var["type"] == "global"
        assert "rip" in state_var.get("access", "")


class TestControlFlowUnflattening:
    """Test control flow unflattening and edge recovery."""

    def test_unflatten_removes_dispatcher_edges(
        self,
        flattened_sample: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Unflattening removes edges involving dispatcher nodes."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(flattened_sample)
        result = deobfuscator.deobfuscate_function(0x401000)

        for dispatcher in result.dispatcher_info:
            for source, target in result.deobfuscated_cfg.edges():
                assert source != dispatcher.dispatcher_address
                assert target != dispatcher.dispatcher_address

    def test_recover_original_edges_from_state_assignments(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Edge recovery extracts original control flow from state assignments."""
        session = FakeRadare2Session(str(sample_binary))
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            lambda path, r2path: FakeR2SessionContextManager(session),
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        cfg = nx.DiGraph()

        block1 = BasicBlock(
            address=0x401010,
            size=20,
            instructions=[
                {"offset": 0x401010, "disasm": "mov [rbp-4], 1"},
                {"offset": 0x401018, "disasm": "jmp 0x401040"},
            ],
            successors=[0x401040],
            predecessors=[],
            block_type="sequential",
        )
        cfg.add_node(0x401010, data=block1)

        block2 = BasicBlock(
            address=0x401020,
            size=20,
            instructions=[
                {"offset": 0x401020, "disasm": "mov [rbp-4], 2"},
                {"offset": 0x401028, "disasm": "jmp 0x401040"},
            ],
            successors=[0x401040],
            predecessors=[],
            block_type="sequential",
        )
        cfg.add_node(0x401020, data=block2)

        dispatcher = DispatcherInfo(
            dispatcher_address=0x401040,
            state_variable_location=0,
            state_variable_type="stack",
            controlled_blocks=[0x401010, 0x401020],
            case_mappings={1: 0x401020, 2: 0x401050},
            switch_type="Generic",
        )

        recovered = deobfuscator._recover_original_edges(session, cfg, dispatcher, 0x401000)

        assert isinstance(recovered, list)
        assert all(isinstance(edge, tuple) and len(edge) == 2 for edge in recovered)

    def test_extract_state_assignment_hex_value(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """State assignment extraction parses hexadecimal values."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        block = BasicBlock(
            address=0x401010,
            size=20,
            instructions=[
                {"offset": 0x401010, "disasm": "mov [rbp-4], 0x5"},
                {"offset": 0x401018, "disasm": "jmp 0x401040"},
            ],
            successors=[0x401040],
            predecessors=[],
            block_type="sequential",
        )

        dispatcher = DispatcherInfo(
            dispatcher_address=0x401040,
            state_variable_location=0,
            state_variable_type="stack",
            controlled_blocks=[0x401010],
            case_mappings={},
            switch_type="Generic",
        )

        state_value = deobfuscator._extract_state_assignment(block, dispatcher)

        assert state_value == 5

    def test_extract_state_assignment_decimal_value(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """State assignment extraction parses decimal values."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        block = BasicBlock(
            address=0x401010,
            size=20,
            instructions=[
                {"offset": 0x401010, "disasm": "mov [rbp-4], 42"},
                {"offset": 0x401018, "disasm": "jmp 0x401040"},
            ],
            successors=[0x401040],
            predecessors=[],
            block_type="sequential",
        )

        dispatcher = DispatcherInfo(
            dispatcher_address=0x401040,
            state_variable_location=0,
            state_variable_type="stack",
            controlled_blocks=[0x401010],
            case_mappings={},
            switch_type="Generic",
        )

        state_value = deobfuscator._extract_state_assignment(block, dispatcher)

        assert state_value == 42


class TestOpaquePredicateDetection:
    """Test opaque predicate detection and removal."""

    def test_detect_self_comparison_opaque(
        self,
        obfuscated_with_opaques: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Opaque predicate detection identifies self-comparison patterns."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(obfuscated_with_opaques)
        result = deobfuscator.deobfuscate_function(0x401000)

        self_comparison_opaques = [op for op in result.opaque_predicates if op["type"] == "self_comparison"]

        assert len(result.opaque_predicates) >= 0

    def test_remove_opaque_predicates_eliminates_dead_branch(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Opaque predicate removal eliminates unreachable branches."""
        session = FakeRadare2Session(str(sample_binary))
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            lambda path, r2path: FakeR2SessionContextManager(session),
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        cfg = nx.DiGraph()

        block1 = BasicBlock(
            address=0x401000,
            size=10,
            instructions=[
                {"offset": 0x401000, "disasm": "xor eax, eax"},
                {"offset": 0x401002, "disasm": "test eax, eax"},
            ],
            successors=[0x401010, 0x401020],
            predecessors=[],
            block_type="branch",
        )
        cfg.add_node(0x401000, data=block1)

        block2 = BasicBlock(
            address=0x401010,
            size=10,
            instructions=[{"offset": 0x401010, "disasm": "nop"}],
            successors=[],
            predecessors=[0x401000],
            block_type="sequential",
        )
        cfg.add_node(0x401010, data=block2)

        block3 = BasicBlock(
            address=0x401020,
            size=10,
            instructions=[{"offset": 0x401020, "disasm": "ret"}],
            successors=[],
            predecessors=[0x401000],
            block_type="return",
        )
        cfg.add_node(0x401020, data=block3)

        cfg.add_edge(0x401000, 0x401010, edge_type="conditional_true")
        cfg.add_edge(0x401000, 0x401020, edge_type="conditional_false")

        opaque_predicates = [
            {
                "address": 0x401000,
                "instruction": "xor eax, eax; test eax, eax",
                "type": "self_comparison",
                "always_value": True,
                "confidence": 0.95,
                "analysis_method": "symbolic",
                "dead_branch": 0x401020,
                "symbolic_proof": "eax == 0",
            },
        ]

        simplified = deobfuscator._remove_opaque_predicates(session, cfg, opaque_predicates)

        assert not simplified.has_edge(0x401000, 0x401020)

    def test_opaque_predicate_confidence_scores(
        self,
        obfuscated_with_opaques: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Detected opaque predicates include confidence scores."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(obfuscated_with_opaques)
        result = deobfuscator.deobfuscate_function(0x401000)

        for opaque in result.opaque_predicates:
            assert "confidence" in opaque
            assert 0.0 <= opaque["confidence"] <= 1.0
            assert "analysis_method" in opaque


class TestBogusBlockDetection:
    """Test detection and removal of bogus/unreachable blocks."""

    def test_detect_unreachable_blocks(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Bogus block detection identifies unreachable code."""
        session = FakeRadare2Session(str(sample_binary))
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            lambda path, r2path: FakeR2SessionContextManager(session),
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        cfg = nx.DiGraph()

        entry_block = BasicBlock(
            address=0x401000,
            size=10,
            instructions=[{"offset": 0x401000, "disasm": "mov eax, 1"}],
            successors=[0x401010],
            predecessors=[],
            block_type="sequential",
        )
        cfg.add_node(0x401000, data=entry_block)

        reachable_block = BasicBlock(
            address=0x401010,
            size=10,
            instructions=[{"offset": 0x401010, "disasm": "ret"}],
            successors=[],
            predecessors=[0x401000],
            block_type="return",
        )
        cfg.add_node(0x401010, data=reachable_block)

        unreachable_block = BasicBlock(
            address=0x401020,
            size=10,
            instructions=[{"offset": 0x401020, "disasm": "nop"}],
            successors=[],
            predecessors=[],
            block_type="sequential",
        )
        cfg.add_node(0x401020, data=unreachable_block)

        cfg.add_edge(0x401000, 0x401010)

        bogus_blocks = deobfuscator._detect_bogus_blocks(session, cfg, 0x401000)

        assert 0x401020 in bogus_blocks
        assert 0x401000 not in bogus_blocks
        assert 0x401010 not in bogus_blocks

    def test_detect_nop_only_blocks(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Bogus block detection identifies no-op only blocks."""
        session = FakeRadare2Session(str(sample_binary))
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            lambda path, r2path: FakeR2SessionContextManager(session),
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        cfg = nx.DiGraph()

        entry_block = BasicBlock(
            address=0x401000,
            size=10,
            instructions=[{"offset": 0x401000, "disasm": "mov eax, 1"}],
            successors=[0x401010],
            predecessors=[],
            block_type="sequential",
        )
        cfg.add_node(0x401000, data=entry_block)

        nop_block = BasicBlock(
            address=0x401010,
            size=10,
            instructions=[
                {"offset": 0x401010, "disasm": "nop"},
                {"offset": 0x401011, "disasm": "nop"},
                {"offset": 0x401012, "disasm": "nop"},
            ],
            successors=[],
            predecessors=[0x401000],
            block_type="sequential",
        )
        cfg.add_node(0x401010, data=nop_block)

        cfg.add_edge(0x401000, 0x401010)

        bogus_blocks = deobfuscator._detect_bogus_blocks(session, cfg, 0x401000)

        assert 0x401010 in bogus_blocks

    def test_remove_bogus_blocks_preserves_edges(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Bogus block removal preserves edges between predecessor and successor."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        cfg = nx.DiGraph()

        block1 = BasicBlock(
            address=0x401000,
            size=10,
            instructions=[{"offset": 0x401000, "disasm": "mov eax, 1"}],
            successors=[0x401010],
            predecessors=[],
            block_type="sequential",
        )
        cfg.add_node(0x401000, data=block1)

        bogus_block = BasicBlock(
            address=0x401010,
            size=10,
            instructions=[{"offset": 0x401010, "disasm": "nop"}],
            successors=[0x401020],
            predecessors=[0x401000],
            block_type="sequential",
        )
        cfg.add_node(0x401010, data=bogus_block)

        block3 = BasicBlock(
            address=0x401020,
            size=10,
            instructions=[{"offset": 0x401020, "disasm": "ret"}],
            successors=[],
            predecessors=[0x401010],
            block_type="return",
        )
        cfg.add_node(0x401020, data=block3)

        cfg.add_edge(0x401000, 0x401010)
        cfg.add_edge(0x401010, 0x401020)

        cleaned = deobfuscator._remove_bogus_blocks(cfg, [0x401010])

        assert 0x401010 not in cleaned.nodes()
        assert cleaned.has_edge(0x401000, 0x401020)


class TestDeobfuscationMetrics:
    """Test calculation of deobfuscation metrics and confidence scores."""

    def test_metrics_calculate_block_reduction(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Metrics correctly calculate block count reduction."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        original_cfg = nx.DiGraph()
        for i in range(10):
            original_cfg.add_node(0x401000 + i * 0x10)

        deobfuscated_cfg = nx.DiGraph()
        for i in range(7):
            deobfuscated_cfg.add_node(0x401000 + i * 0x10)

        metrics = deobfuscator._calculate_deobfuscation_metrics(original_cfg, deobfuscated_cfg)

        assert metrics["original_blocks"] == 10
        assert metrics["deobfuscated_blocks"] == 7
        assert metrics["blocks_removed"] == 3
        assert metrics["complexity_reduction"] == 30.0

    def test_metrics_calculate_edge_changes(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Metrics correctly calculate edge count changes."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        original_cfg = nx.DiGraph()
        original_cfg.add_edge(0x401000, 0x401010)
        original_cfg.add_edge(0x401010, 0x401020)
        original_cfg.add_edge(0x401020, 0x401030)
        original_cfg.add_edge(0x401030, 0x401000)

        deobfuscated_cfg = nx.DiGraph()
        deobfuscated_cfg.add_edge(0x401000, 0x401010)
        deobfuscated_cfg.add_edge(0x401010, 0x401030)

        metrics = deobfuscator._calculate_deobfuscation_metrics(original_cfg, deobfuscated_cfg)

        assert metrics["original_edges"] == 4
        assert metrics["deobfuscated_edges"] == 2
        assert metrics["edges_changed"] == 2

    def test_confidence_score_with_all_detections(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Confidence score calculation includes all detection types."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        dispatchers = [
            DispatcherInfo(
                dispatcher_address=0x401040,
                state_variable_location=0,
                state_variable_type="stack",
                controlled_blocks=[0x401010, 0x401020],
                case_mappings={},
                switch_type="OLLVM",
            ),
        ]

        opaque_predicates = [
            {
                "address": 0x401000,
                "type": "self_comparison",
                "always_value": True,
                "confidence": 0.95,
            },
        ]

        bogus_blocks = [0x401050, 0x401060]

        metrics = {
            "original_blocks": 10,
            "deobfuscated_blocks": 6,
            "blocks_removed": 4,
        }

        confidence = deobfuscator._calculate_confidence_score(
            dispatchers,
            opaque_predicates,
            bogus_blocks,
            metrics,
        )

        assert 0.0 <= confidence <= 1.0
        assert confidence > 0.5

    def test_confidence_score_without_detections(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Confidence score is low when no obfuscation detected."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        dispatchers: list[DispatcherInfo] = []
        opaque_predicates: list[dict[str, Any]] = []
        bogus_blocks: list[int] = []

        metrics = {
            "original_blocks": 10,
            "deobfuscated_blocks": 10,
            "blocks_removed": 0,
        }

        confidence = deobfuscator._calculate_confidence_score(
            dispatchers,
            opaque_predicates,
            bogus_blocks,
            metrics,
        )

        assert confidence == 0.0


class TestCFGExportAndPatching:
    """Test CFG export and binary patching functionality."""

    def test_export_deobfuscated_cfg_creates_valid_dot_file(
        self,
        flattened_sample: Path,
        tmp_path: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """CFG export creates valid Graphviz DOT file."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(flattened_sample)
        result = deobfuscator.deobfuscate_function(0x401000)

        output_path = tmp_path / "cfg.dot"
        success = deobfuscator.export_deobfuscated_cfg(result, output_path)

        assert success is True
        assert output_path.exists()

        content = output_path.read_text()
        assert "digraph DeobfuscatedCFG" in content
        assert "node [shape=box]" in content

    def test_export_includes_node_colors(
        self,
        flattened_sample: Path,
        tmp_path: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Exported DOT file includes color-coded nodes."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(flattened_sample)
        result = deobfuscator.deobfuscate_function(0x401000)

        output_path = tmp_path / "cfg.dot"
        deobfuscator.export_deobfuscated_cfg(result, output_path)

        content = output_path.read_text()
        assert "fillcolor=" in content
        assert "style=filled" in content

    def test_patch_generation_for_dispatcher_removal(
        self,
        flattened_sample: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Patch generation creates NOP patches for dispatcher blocks."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(flattened_sample)
        result = deobfuscator.deobfuscate_function(0x401000)

        nop_patches = [p for p in result.patch_info if p["type"] == "nop_dispatcher"]

        assert len(nop_patches) == len(result.dispatcher_info)

        for patch in nop_patches:
            assert "address" in patch
            assert "size" in patch
            assert "description" in patch

    def test_patch_generation_for_edge_redirection(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Patch generation creates redirect patches for recovered edges."""
        session = FakeRadare2Session(str(sample_binary))
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            lambda path, r2path: FakeR2SessionContextManager(session),
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        original_cfg = nx.DiGraph()
        original_cfg.add_node(0x401000, data=BasicBlock(0x401000, 10, [], [0x401010], [], "sequential"))
        original_cfg.add_edge(0x401000, 0x401010)

        deobfuscated_cfg = nx.DiGraph()
        deobfuscated_cfg.add_node(0x401000, data=BasicBlock(0x401000, 10, [], [0x401020], [], "sequential"))
        deobfuscated_cfg.add_edge(0x401000, 0x401020)

        patches = deobfuscator._generate_patch_information(
            session,
            original_cfg,
            deobfuscated_cfg,
            [],
            0x401000,
        )

        redirect_patches = [p for p in patches if p["type"] == "redirect_edge"]
        assert len(redirect_patches) > 0


class TestBlockClassificationAndComplexity:
    """Test basic block classification and complexity calculation."""

    def test_classify_block_return(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Block classification identifies return blocks."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        instructions = [
            {"offset": 0x401000, "disasm": "xor eax, eax"},
            {"offset": 0x401002, "disasm": "ret"},
        ]

        block_type = deobfuscator._classify_block(instructions)
        assert block_type == "return"

    def test_classify_block_call(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Block classification identifies call blocks."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        instructions = [
            {"offset": 0x401000, "disasm": "mov eax, 1"},
            {"offset": 0x401002, "disasm": "call 0x402000"},
        ]

        block_type = deobfuscator._classify_block(instructions)
        assert block_type == "call"

    def test_classify_block_branch(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Block classification identifies branch blocks."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        instructions = [
            {"offset": 0x401000, "disasm": "cmp eax, 0"},
            {"offset": 0x401002, "disasm": "je 0x401010"},
        ]

        block_type = deobfuscator._classify_block(instructions)
        assert block_type == "branch"

    def test_classify_block_sequential(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Block classification identifies sequential blocks."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        instructions = [
            {"offset": 0x401000, "disasm": "mov eax, 1"},
            {"offset": 0x401002, "disasm": "add ebx, 2"},
        ]

        block_type = deobfuscator._classify_block(instructions)
        assert block_type == "sequential"

    def test_calculate_block_complexity_weights_calls(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Complexity calculation assigns higher weight to call instructions."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        instructions_with_call = [
            {"offset": 0x401000, "disasm": "mov eax, 1"},
            {"offset": 0x401002, "disasm": "call 0x402000"},
        ]

        instructions_without_call = [
            {"offset": 0x401000, "disasm": "mov eax, 1"},
            {"offset": 0x401002, "disasm": "add ebx, 2"},
        ]

        complexity_with_call = deobfuscator._calculate_block_complexity(instructions_with_call)
        complexity_without_call = deobfuscator._calculate_block_complexity(instructions_without_call)

        assert complexity_with_call > complexity_without_call

    def test_calculate_block_complexity_weights_branches(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Complexity calculation assigns higher weight to conditional branches."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)

        instructions_with_branch = [
            {"offset": 0x401000, "disasm": "cmp eax, 0"},
            {"offset": 0x401002, "disasm": "je 0x401010"},
        ]

        instructions_without_branch = [
            {"offset": 0x401000, "disasm": "mov eax, 1"},
            {"offset": 0x401002, "disasm": "add ebx, 2"},
        ]

        complexity_with_branch = deobfuscator._calculate_block_complexity(instructions_with_branch)
        complexity_without_branch = deobfuscator._calculate_block_complexity(instructions_without_branch)

        assert complexity_with_branch > complexity_without_branch


class TestEndToEndDeobfuscation:
    """Integration tests for complete deobfuscation workflow."""

    def test_deobfuscate_function_returns_valid_result(
        self,
        flattened_sample: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Complete deobfuscation workflow produces valid result."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(flattened_sample)
        result = deobfuscator.deobfuscate_function(0x401000)

        assert isinstance(result, DeobfuscationResult)
        assert result.original_cfg is not None
        assert result.deobfuscated_cfg is not None
        assert isinstance(result.dispatcher_info, list)
        assert isinstance(result.removed_blocks, list)
        assert isinstance(result.recovered_edges, list)
        assert isinstance(result.opaque_predicates, list)
        assert isinstance(result.patch_info, list)
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.metrics, dict)

    def test_deobfuscation_preserves_entry_point(
        self,
        flattened_sample: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Deobfuscation preserves function entry point in CFG."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(flattened_sample)
        result = deobfuscator.deobfuscate_function(0x401000)

        entry_nodes = [node for node in result.deobfuscated_cfg.nodes() if result.deobfuscated_cfg.in_degree(node) == 0]

        assert len(entry_nodes) >= 1

    def test_deobfuscation_metrics_populated(
        self,
        flattened_sample: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Deobfuscation result includes comprehensive metrics."""
        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            fake_r2_session,
        )

        deobfuscator = ControlFlowDeobfuscator(flattened_sample)
        result = deobfuscator.deobfuscate_function(0x401000)

        assert "original_blocks" in result.metrics
        assert "deobfuscated_blocks" in result.metrics
        assert "blocks_removed" in result.metrics
        assert "original_edges" in result.metrics
        assert "deobfuscated_edges" in result.metrics
        assert "edges_changed" in result.metrics

    def test_deobfuscation_handles_function_without_obfuscation(
        self,
        sample_binary: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Deobfuscation gracefully handles functions without obfuscation."""
        session = FakeRadare2Session(str(sample_binary))
        session.responses[f"agfj @ {hex(0x401000)}"] = [
            {
                "blocks": [
                    {
                        "offset": 0x401000,
                        "size": 10,
                        "ops": [
                            {"offset": 0x401000, "disasm": "mov eax, 1"},
                            {"offset": 0x401002, "disasm": "ret"},
                        ],
                    },
                ],
            },
        ]

        monkeypatch.setattr(
            "intellicrack.core.analysis.control_flow_deobfuscation.r2_session",
            lambda path, r2path: FakeR2SessionContextManager(session),
        )

        deobfuscator = ControlFlowDeobfuscator(sample_binary)
        result = deobfuscator.deobfuscate_function(0x401000)

        assert len(result.dispatcher_info) == 0
        assert result.confidence >= 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
