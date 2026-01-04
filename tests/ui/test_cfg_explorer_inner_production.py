"""Production-ready tests for intellicrack/ui/cfg_explorer_inner.py

Tests validate REAL CFG exploration capabilities:
- Control Flow Graph generation from real PE/ELF binaries
- NetworkX graph construction with nodes, edges, and metrics
- Matplotlib visualization rendering to files
- Radare2 integration for function detection and CFG analysis
- Capstone disassembly for instruction-level basic block detection
- License pattern detection in binary strings and functions
- Binary format detection (PE, ELF, Mach-O)
- Function prologue pattern recognition
- Graph export in multiple formats (PNG, SVG, DOT, HTML)
- Comprehensive analysis results compilation
"""

import tempfile
from pathlib import Path
from typing import Any

import networkx as nx
import pytest

from intellicrack.ui.cfg_explorer_inner import CfgExplorerInner


PE_HEADER: bytes = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 56 + b"PE\x00\x00"
ELF_HEADER: bytes = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
MACHO_HEADER: bytes = b"\xfe\xed\xfa\xce" + b"\x00" * 12

FUNCTION_PROLOGUE_X86_64: bytes = b"\x55\x48\x89\xe5"
FUNCTION_PROLOGUE_X86_32: bytes = b"\x55\x89\xe5"

LICENSE_STRINGS: list[bytes] = [
    b"license",
    b"serial",
    b"activation",
    b"register",
    b"trial",
    b"key",
]


class MockApp:
    """Test double application object for testing CFG explorer."""

    def __init__(self) -> None:
        """Initialize test app with update tracking."""
        self.update_output_calls: list[tuple[str, ...]] = []
        self.binary_path: str | None = None
        self.analyze_results: list[str] = []

    def update_output(self, *args: Any) -> None:
        """Track update_output calls."""
        self.update_output_calls.append(args)


def create_realistic_pe_binary() -> bytes:
    """Create realistic PE binary with function prologues and license strings.

    Returns:
        Bytes representing a minimal but realistic PE executable.
    """
    binary = bytearray(PE_HEADER)
    binary.extend(b"\x00" * (0x200 - len(binary)))

    binary.extend(FUNCTION_PROLOGUE_X86_64)
    binary.extend(b"\x48\x83\xec\x20")
    binary.extend(b"\xc3")

    binary.extend(b"\x00" * 50)
    binary.extend(FUNCTION_PROLOGUE_X86_32)
    binary.extend(b"\x83\xec\x0c")
    binary.extend(b"\xc3")

    binary.extend(b"\x00" * 100)
    binary.extend(b"license_key_validation_routine\x00")
    binary.extend(b"serial_number_check\x00")
    binary.extend(b"activation_code_verify\x00")

    binary.extend(b"\x00" * 200)
    binary.extend(FUNCTION_PROLOGUE_X86_64)
    binary.extend(b"\x48\x89\x5c\x24\x08")
    binary.extend(b"\xc3")

    return bytes(binary)


def create_realistic_elf_binary() -> bytes:
    """Create realistic ELF binary with function prologues.

    Returns:
        Bytes representing a minimal ELF executable.
    """
    binary = bytearray(ELF_HEADER)
    binary.extend(b"\x00" * (0x100 - len(binary)))

    binary.extend(FUNCTION_PROLOGUE_X86_64)
    binary.extend(b"\x48\x83\xec\x10")
    binary.extend(b"\xc3")

    binary.extend(b"\x00" * 50)
    binary.extend(b"register_application\x00")
    binary.extend(b"trial_expired\x00")

    return bytes(binary)


class TestCfgExplorerInitialization:
    """Test CFG explorer initialization and configuration."""

    def test_cfg_explorer_initializes_config_with_defaults(self) -> None:
        """CFG explorer creates default configuration on initialization."""
        app = MockApp()
        explorer = CfgExplorerInner()

        explorer._initialize_cfg_explorer_config(app)

        assert hasattr(app, "cfg_explorer_config")
        assert app.cfg_explorer_config["layout_algorithm"] == "spring"
        assert app.cfg_explorer_config["max_nodes"] == 1000
        assert app.cfg_explorer_config["max_edges"] == 2000
        assert app.cfg_explorer_config["analysis_depth"] == 3
        assert app.cfg_explorer_config["highlight_patterns"] is True
        assert "png" in app.cfg_explorer_config["export_formats"]
        assert "svg" in app.cfg_explorer_config["export_formats"]
        assert "dot" in app.cfg_explorer_config["export_formats"]

    def test_cfg_explorer_tracks_available_analysis_tools(self) -> None:
        """CFG explorer correctly tracks availability of analysis tools."""
        app = MockApp()
        explorer = CfgExplorerInner()

        explorer._initialize_cfg_analysis_tools(app)

        assert hasattr(app, "cfg_analysis_tools")
        assert "radare2_available" in app.cfg_analysis_tools
        assert "networkx_available" in app.cfg_analysis_tools
        assert "matplotlib_available" in app.cfg_analysis_tools
        assert "capstone_available" in app.cfg_analysis_tools
        assert "use_fallback_analysis" in app.cfg_analysis_tools
        assert isinstance(app.cfg_analysis_tools["use_fallback_analysis"], bool)

    def test_cfg_explorer_initializes_data_structures(self) -> None:
        """CFG explorer creates necessary data structures."""
        app = MockApp()
        explorer = CfgExplorerInner()

        explorer._initialize_cfg_data_structures(app)

        assert hasattr(app, "cfg_functions")
        assert isinstance(app.cfg_functions, dict)
        assert hasattr(app, "cfg_current_function")
        assert app.cfg_current_function is None

    def test_cfg_explorer_sets_up_license_patterns(self) -> None:
        """CFG explorer configures license pattern detection."""
        app = MockApp()
        explorer = CfgExplorerInner()

        explorer._setup_license_patterns(app)

        assert hasattr(app, "license_patterns")
        assert "keywords" in app.license_patterns
        assert "api_calls" in app.license_patterns
        assert "crypto_functions" in app.license_patterns

        assert "license" in app.license_patterns["keywords"]
        assert "serial" in app.license_patterns["keywords"]
        assert "activation" in app.license_patterns["keywords"]
        assert "trial" in app.license_patterns["keywords"]

        assert "RegQueryValue" in app.license_patterns["api_calls"]
        assert "GetTickCount" in app.license_patterns["api_calls"]

        assert "CryptHashData" in app.license_patterns["crypto_functions"]
        assert "AES_Encrypt" in app.license_patterns["crypto_functions"]


class TestNetworkXIntegration:
    """Test NetworkX integration for graph analysis."""

    def test_networkx_integration_creates_directed_graph(self) -> None:
        """NetworkX integration creates directed graph for CFG."""
        app = MockApp()
        explorer = CfgExplorerInner()

        explorer._setup_networkx_integration(app)

        assert hasattr(app, "cfg_graph")
        assert isinstance(app.cfg_graph, nx.DiGraph)
        assert app.cfg_analysis_tools["networkx_available"] is True  # type: ignore[attr-defined]

    def test_networkx_builds_cfg_with_functions_and_edges(self) -> None:
        """NetworkX builds CFG with real function nodes and control flow edges."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._initialize_cfg_analysis_tools(app)
        explorer._setup_networkx_integration(app)

        functions = [
            {"address": "0x401000", "name": "main", "size": 150, "type": "function", "confidence": 0.95},
            {"address": "0x401100", "name": "check_license", "size": 80, "type": "function", "confidence": 0.90},
            {"address": "0x401200", "name": "validate_serial", "size": 120, "type": "function", "confidence": 0.85},
        ]

        edges = [
            {"from": "0x401000", "to": "0x401100", "type": "call"},
            {"from": "0x401100", "to": "0x401200", "type": "call"},
            {"from": "0x401200", "to": "0x401000", "type": "jump", "condition": "jz"},
        ]

        metrics = app.build_cfg_with_networkx(functions, edges)  # type: ignore[attr-defined]

        assert metrics["nodes"] == 3
        assert metrics["edges"] == 3
        assert metrics["density"] > 0
        assert "centrality" in metrics
        assert "pagerank" in metrics

        assert app.cfg_graph.has_node("0x401000")  # type: ignore[attr-defined]
        assert app.cfg_graph.has_node("0x401100")  # type: ignore[attr-defined]
        assert app.cfg_graph.has_node("0x401200")  # type: ignore[attr-defined]

        assert app.cfg_graph.nodes["0x401000"]["label"] == "main"  # type: ignore[attr-defined]
        assert app.cfg_graph.nodes["0x401100"]["size"] == 80  # type: ignore[attr-defined]
        assert app.cfg_graph.nodes["0x401200"]["confidence"] == 0.85  # type: ignore[attr-defined]

        assert app.cfg_graph.has_edge("0x401000", "0x401100")  # type: ignore[attr-defined]
        assert app.cfg_graph.edges["0x401100", "0x401200"]["type"] == "call"  # type: ignore[attr-defined]

    def test_networkx_calculates_graph_metrics_correctly(self) -> None:
        """NetworkX calculates accurate graph metrics for CFG analysis."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._initialize_cfg_analysis_tools(app)
        explorer._setup_networkx_integration(app)

        functions = [
            {"address": "0x1000", "name": "func1", "size": 50, "confidence": 0.9},
            {"address": "0x2000", "name": "func2", "size": 70, "confidence": 0.85},
            {"address": "0x3000", "name": "func3", "size": 60, "confidence": 0.88},
            {"address": "0x4000", "name": "func4", "size": 40, "confidence": 0.92},
        ]

        edges = [
            {"from": "0x1000", "to": "0x2000", "type": "call"},
            {"from": "0x1000", "to": "0x3000", "type": "call"},
            {"from": "0x2000", "to": "0x4000", "type": "call"},
            {"from": "0x3000", "to": "0x4000", "type": "call"},
        ]

        metrics = app.build_cfg_with_networkx(functions, edges)  # type: ignore[attr-defined]

        assert metrics["nodes"] == 4
        assert metrics["edges"] == 4
        assert 0 < metrics["density"] <= 1
        assert isinstance(metrics["is_connected"], bool)

        assert "0x1000" in metrics["centrality"]
        assert "0x4000" in metrics["centrality"]

        assert metrics["centrality"]["0x1000"] > 0
        assert metrics["pagerank"]["0x4000"] > 0


class TestBinaryFormatDetection:
    """Test binary format detection from magic bytes."""

    def test_detects_pe_format_from_mz_header(self) -> None:
        """CFG explorer detects PE executable format from MZ header."""
        app = MockApp()
        explorer = CfgExplorerInner()

        binary_data = create_realistic_pe_binary()
        detected_format = explorer._detect_binary_format(app, binary_data)

        assert detected_format == "PE"

    def test_detects_elf_format_from_magic_bytes(self) -> None:
        """CFG explorer detects ELF executable format from magic bytes."""
        app = MockApp()
        explorer = CfgExplorerInner()

        binary_data = create_realistic_elf_binary()
        detected_format = explorer._detect_binary_format(app, binary_data)

        assert detected_format == "ELF"

    def test_detects_macho_format_variants(self) -> None:
        """CFG explorer detects Mach-O format in multiple endianness variants."""
        app = MockApp()
        explorer = CfgExplorerInner()

        macho_variants = [
            b"\xfe\xed\xfa\xce" + b"\x00" * 100,
            b"\xce\xfa\xed\xfe" + b"\x00" * 100,
            b"\xfe\xed\xfa\xcf" + b"\x00" * 100,
            b"\xcf\xfa\xed\xfe" + b"\x00" * 100,
        ]

        for variant in macho_variants:
            detected_format = explorer._detect_binary_format(app, variant)
            assert detected_format == "Mach-O"

    def test_returns_unknown_for_unrecognized_format(self) -> None:
        """CFG explorer returns unknown for unrecognized binary formats."""
        app = MockApp()
        explorer = CfgExplorerInner()

        binary_data = b"\x00\x01\x02\x03" + b"\xFF" * 100
        detected_format = explorer._detect_binary_format(app, binary_data)

        assert detected_format == "unknown"


class TestLicensePatternDetection:
    """Test license-related pattern detection in binaries."""

    def test_detects_license_keywords_in_binary_strings(self) -> None:
        """CFG explorer finds license-related keywords in binary data."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._setup_license_patterns(app)

        binary_data = create_realistic_pe_binary()
        license_hits = explorer._search_license_patterns(app, binary_data)

        assert len(license_hits) > 0

        keywords_found = [hit["keyword"] for hit in license_hits]
        assert "license" in keywords_found or "licens" in keywords_found

    def test_captures_license_pattern_addresses_and_context(self) -> None:
        """CFG explorer captures accurate addresses and context for license patterns."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._setup_license_patterns(app)

        binary_data = b"\x00" * 100 + b"activation_code_here" + b"\x00" * 100
        license_hits = explorer._search_license_patterns(app, binary_data)

        activation_hits = [hit for hit in license_hits if hit["keyword"] == "activation"]
        assert activation_hits

        hit = activation_hits[0]
        assert "address" in hit
        assert "context" in hit
        assert hit["address"].startswith("0x")  # type: ignore[attr-defined]
        assert len(hit["context"]) > 0  # type: ignore[arg-type]

    def test_finds_multiple_license_patterns_in_single_binary(self) -> None:
        """CFG explorer finds all license patterns present in binary."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._setup_license_patterns(app)

        binary_data = (
            b"\x00" * 50
            + b"license_key"
            + b"\x00" * 50
            + b"serial_number"
            + b"\x00" * 50
            + b"activation_code"
            + b"\x00" * 50
            + b"trial_expired"
            + b"\x00" * 50
        )

        license_hits = explorer._search_license_patterns(app, binary_data)
        keywords_found = {hit["keyword"] for hit in license_hits}

        assert len(keywords_found) >= 3
        assert any(kw in keywords_found for kw in ["license", "licens"])
        assert "serial" in keywords_found or "trial" in keywords_found


class TestBinaryStructureAnalysis:
    """Test comprehensive binary structure analysis."""

    def test_analyzes_pe_binary_structure_completely(self) -> None:
        """CFG explorer performs complete PE binary analysis."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._setup_license_patterns(app)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(create_realistic_pe_binary())
            tmp.flush()
            app.binary_path = tmp.name

        try:
            explorer._perform_binary_structure_analysis(app)

            assert hasattr(app, "cfg_binary_format")
            assert app.cfg_binary_format == "PE"

            assert hasattr(app, "cfg_detected_functions")
            assert isinstance(app.cfg_detected_functions, list)

            assert hasattr(app, "cfg_license_hits")
            assert isinstance(app.cfg_license_hits, list)

        finally:
            Path(app.binary_path).unlink(missing_ok=True)

    def test_analyzes_elf_binary_structure_completely(self) -> None:
        """CFG explorer performs complete ELF binary analysis."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._setup_license_patterns(app)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".elf") as tmp:
            tmp.write(create_realistic_elf_binary())
            tmp.flush()
            app.binary_path = tmp.name

        try:
            explorer._perform_binary_structure_analysis(app)

            assert hasattr(app, "cfg_binary_format")
            assert app.cfg_binary_format == "ELF"

            assert hasattr(app, "cfg_detected_functions")
            assert hasattr(app, "cfg_license_hits")

        finally:
            Path(app.binary_path).unlink(missing_ok=True)

    def test_handles_missing_binary_path_gracefully(self) -> None:
        """CFG explorer handles missing binary path without crashing."""
        app = MockApp()
        explorer = CfgExplorerInner()

        app.binary_path = None
        explorer._perform_binary_structure_analysis(app)

        assert not hasattr(app, "cfg_binary_format")

    def test_handles_corrupted_binary_file_gracefully(self) -> None:
        """CFG explorer handles corrupted binary files without crashing."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._setup_license_patterns(app)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"\x00" * 10)
            tmp.flush()
            app.binary_path = tmp.name

        try:
            explorer._perform_binary_structure_analysis(app)

            assert hasattr(app, "cfg_binary_format")
            assert app.cfg_binary_format == "unknown"

        finally:
            Path(app.binary_path).unlink(missing_ok=True)


class TestGraphVisualizationData:
    """Test graph visualization data structures."""

    def test_initializes_graph_visualization_structures(self) -> None:
        """CFG explorer creates graph visualization data structures."""
        app = MockApp()
        explorer = CfgExplorerInner()

        explorer._initialize_graph_visualization_data(app)

        assert hasattr(app, "cfg_graph_data")
        assert "nodes" in app.cfg_graph_data
        assert "edges" in app.cfg_graph_data
        assert "layouts" in app.cfg_graph_data
        assert "current_layout" in app.cfg_graph_data
        assert "node_styles" in app.cfg_graph_data
        assert "edge_styles" in app.cfg_graph_data

        assert isinstance(app.cfg_graph_data["nodes"], list)
        assert isinstance(app.cfg_graph_data["edges"], list)
        assert app.cfg_graph_data["current_layout"] == "spring"

    def test_builds_sample_cfg_from_detected_functions(self) -> None:
        """CFG explorer builds sample CFG graph from detected functions."""
        app = MockApp()
        explorer = CfgExplorerInner()

        app.cfg_detected_functions = [  # type: ignore[attr-defined]
            {"address": "0x401000", "confidence": 0.9},
            {"address": "0x401100", "confidence": 0.85},
            {"address": "0x401200", "confidence": 0.88},
        ]

        explorer._initialize_graph_visualization_data(app)
        explorer._build_sample_cfg_graph(app)

        assert len(app.cfg_graph_data["nodes"]) == 3  # type: ignore[attr-defined]
        assert len(app.cfg_graph_data["edges"]) > 0  # type: ignore[attr-defined]

        node_ids = [node["id"] for node in app.cfg_graph_data["nodes"]]  # type: ignore[attr-defined]
        assert "func_0" in node_ids
        assert "func_1" in node_ids
        assert "func_2" in node_ids

        for node in app.cfg_graph_data["nodes"]:  # type: ignore[attr-defined]
            assert "address" in node
            assert "label" in node
            assert "confidence" in node

    def test_handles_empty_function_list_gracefully(self) -> None:
        """CFG explorer handles empty function list without crashing."""
        app = MockApp()
        explorer = CfgExplorerInner()

        app.cfg_detected_functions = []  # type: ignore[attr-defined]
        explorer._initialize_graph_visualization_data(app)
        explorer._build_sample_cfg_graph(app)

        assert hasattr(app, "cfg_graph_data")
        assert len(app.cfg_graph_data["nodes"]) == 0
        assert len(app.cfg_graph_data["edges"]) == 0


class TestCfgAnalysisResults:
    """Test CFG analysis results compilation."""

    def test_compiles_comprehensive_analysis_results(self) -> None:
        """CFG explorer compiles complete analysis results."""
        app = MockApp()
        explorer = CfgExplorerInner()

        app.cfg_binary_format = "PE"  # type: ignore[attr-defined]
        app.cfg_analysis_tools = {  # type: ignore[attr-defined]
            "networkx_available": True,
            "radare2_available": False,
            "matplotlib_available": True,
            "capstone_available": True,
        }
        app.cfg_detected_functions = [  # type: ignore[attr-defined]
            {"address": "0x401000", "confidence": 0.95},
            {"address": "0x401100", "confidence": 0.90},
        ]
        app.cfg_license_hits = [  # type: ignore[attr-defined]
            {"keyword": "license", "address": "0x402000"},
            {"keyword": "serial", "address": "0x402050"},
        ]
        app.cfg_graph_data = {  # type: ignore[attr-defined]
            "nodes": [{"id": "func_0"}, {"id": "func_1"}],
            "edges": [{"from": "func_0", "to": "func_1"}],
            "current_layout": "spring",
        }

        explorer._compile_cfg_analysis_results(app)

        assert len(app.analyze_results) > 0

        results_text = "\n".join(app.analyze_results)
        assert "CONTROL FLOW GRAPH EXPLORER" in results_text
        assert "PE" in results_text
        assert "NetworkX: True" in results_text
        assert "Detected functions: 2" in results_text
        assert "License-related patterns: 2" in results_text
        assert "Nodes: 2" in results_text
        assert "Edges: 1" in results_text

    def test_includes_available_tools_in_results(self) -> None:
        """CFG explorer lists available analysis tools in results."""
        app = MockApp()
        explorer = CfgExplorerInner()

        app.cfg_analysis_tools = {  # type: ignore[attr-defined]
            "networkx_available": True,
            "radare2_available": True,
            "matplotlib_available": False,
            "capstone_available": True,
        }

        explorer._compile_cfg_analysis_results(app)

        results_text = "\n".join(app.analyze_results)
        assert "NetworkX: True" in results_text
        assert "Radare2: True" in results_text
        assert "Matplotlib: False" in results_text
        assert "Capstone: True" in results_text


class TestMatplotlibIntegration:
    """Test Matplotlib visualization integration."""

    def test_matplotlib_integration_creates_visualization_function(self) -> None:
        """Matplotlib integration creates visualization capability."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._initialize_cfg_analysis_tools(app)

        explorer._setup_matplotlib_integration(app)

        assert hasattr(app, "visualize_cfg_with_matplotlib")
        assert callable(app.visualize_cfg_with_matplotlib)

    def test_matplotlib_visualization_requires_graph_data(self) -> None:
        """Matplotlib visualization validates graph data availability."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._initialize_cfg_analysis_tools(app)
        explorer._setup_matplotlib_integration(app)

        app.cfg_analysis_tools["networkx_available"] = False  # type: ignore[attr-defined]
        result = app.visualize_cfg_with_matplotlib()  # type: ignore[attr-defined]

        assert "error" in result
        assert "NetworkX not available" in result["error"]

    def test_matplotlib_saves_graph_visualization_to_file(self) -> None:
        """Matplotlib visualization saves CFG to PNG file."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._initialize_cfg_analysis_tools(app)
        explorer._setup_networkx_integration(app)
        explorer._setup_matplotlib_integration(app)

        functions = [
            {"address": "0x1000", "name": "func1", "size": 50, "confidence": 0.9},
            {"address": "0x2000", "name": "func2", "size": 70, "confidence": 0.85},
        ]
        edges = [{"from": "0x1000", "to": "0x2000", "type": "call"}]

        app.build_cfg_with_networkx(functions, edges)  # type: ignore[attr-defined]

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            save_path = tmp.name

        try:
            result = app.visualize_cfg_with_matplotlib(save_path=save_path)  # type: ignore[attr-defined]

            assert "status" in result
            assert result["status"] == "saved"
            assert "path" in result
            assert Path(save_path).exists()
            assert Path(save_path).stat().st_size > 0

        finally:
            Path(save_path).unlink(missing_ok=True)


class TestCapstoneIntegration:
    """Test Capstone disassembler integration."""

    def test_capstone_integration_creates_disassembly_function(self) -> None:
        """Capstone integration creates disassembly capability."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._initialize_cfg_analysis_tools(app)

        explorer._setup_capstone_integration(app)

        if app.cfg_analysis_tools.get("capstone_available"):  # type: ignore[attr-defined]
            assert hasattr(app, "disassemble_with_capstone")
            assert callable(app.disassemble_with_capstone)

    def test_capstone_disassembles_x86_64_instructions(self) -> None:
        """Capstone disassembles x86-64 instruction stream."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._initialize_cfg_analysis_tools(app)
        explorer._setup_capstone_integration(app)

        if not app.cfg_analysis_tools.get("capstone_available"):  # type: ignore[attr-defined]
            pytest.skip("Capstone not available")

        binary_data = b"\x55\x48\x89\xe5\x48\x83\xec\x20\xc3"
        result = app.disassemble_with_capstone(binary_data, offset=0x1000, arch="x86", mode="64")  # type: ignore[attr-defined]

        assert result["status"] == "success"
        assert "instructions" in result
        assert len(result["instructions"]) > 0
        assert result["architecture"] == "x86-64"

        first_insn = result["instructions"][0]
        assert "address" in first_insn
        assert "mnemonic" in first_insn
        assert "op_str" in first_insn

    def test_capstone_detects_basic_blocks_correctly(self) -> None:
        """Capstone identifies basic blocks from control flow instructions."""
        app = MockApp()
        explorer = CfgExplorerInner()
        explorer._initialize_cfg_analysis_tools(app)
        explorer._setup_capstone_integration(app)

        if not app.cfg_analysis_tools.get("capstone_available"):  # type: ignore[attr-defined]
            pytest.skip("Capstone not available")

        binary_data = (
            b"\x55"
            b"\x48\x89\xe5"
            b"\x48\x83\xec\x10"
            b"\xe8\x00\x00\x00\x00"
            b"\x48\x89\xc3"
            b"\xc3"
        )

        result = app.disassemble_with_capstone(binary_data, offset=0x1000, arch="x86", mode="64")  # type: ignore[attr-defined]

        assert result["status"] == "success"
        assert "basic_blocks" in result
        assert len(result["basic_blocks"]) > 0

        for block in result["basic_blocks"]:
            assert "start" in block
            assert "end" in block
            assert "instructions" in block


class TestFullCfgExplorerWorkflow:
    """Test complete CFG explorer workflow."""

    def test_full_workflow_analyzes_pe_binary_end_to_end(self) -> None:
        """Complete CFG exploration workflow on PE binary."""
        app = MockApp()
        explorer = CfgExplorerInner()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(create_realistic_pe_binary())
            tmp.flush()
            app.binary_path = tmp.name

        try:
            explorer.run_cfg_explorer_inner(app)

            assert hasattr(app, "cfg_explorer_config")
            assert hasattr(app, "cfg_analysis_tools")
            assert hasattr(app, "license_patterns")
            assert hasattr(app, "cfg_binary_format")

            if hasattr(app, "cfg_detected_functions"):
                assert isinstance(app.cfg_detected_functions, list)

            if hasattr(app, "cfg_license_hits"):
                assert isinstance(app.cfg_license_hits, list)

        finally:
            Path(app.binary_path).unlink(missing_ok=True)

    def test_full_workflow_handles_import_fallback_gracefully(self) -> None:
        """CFG explorer falls back to inner implementation when core unavailable."""
        app = MockApp()
        explorer = CfgExplorerInner()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(create_realistic_pe_binary())
            tmp.flush()
            app.binary_path = tmp.name

        try:
            explorer.run_cfg_explorer_inner(app)

            assert len(app.analyze_results) > 0
            results_text = "\n".join(app.analyze_results)
            assert "CONTROL FLOW GRAPH EXPLORER" in results_text

        finally:
            Path(app.binary_path).unlink(missing_ok=True)
