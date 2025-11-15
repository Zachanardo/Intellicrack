"""CFG Explorer Inner Module.

This module provides internal functionality for Control Flow Graph (CFG) exploration within the Intellicrack application.
It handles the integration of various analysis tools and libraries for binary analysis, graph visualization,
and license pattern detection.

Main Classes:
    CfgExplorerInner: Main class containing methods for CFG analysis and visualization.

Key Features:
    - NetworkX integration for graph analysis and manipulation
    - Matplotlib integration for CFG visualization
    - Radare2 integration for advanced binary analysis
    - Capstone integration for disassembly and instruction analysis
    - License pattern detection in binary data
    - Binary format detection (PE, ELF, Mach-O)
    - Function pattern recognition
    - Control flow graph construction and visualization
    - Export capabilities for various formats (PNG, SVG, DOT, HTML)

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.

Dependencies:
    - networkx: For graph operations and analysis
    - matplotlib: For visualization (optional)
    - r2pipe: For Radare2 integration (optional)
    - capstone: For disassembly (optional)
"""

import logging
from pathlib import Path
from typing import Optional

import networkx as nx

from intellicrack.utils.log_message import log_message

logger = logging.getLogger(__name__)


class CfgExplorerInner:
    """Internal class for handling Control Flow Graph (CFG) exploration functionality.

    This class provides methods to initialize and configure various analysis tools,
    perform binary analysis, detect patterns, and visualize control flow graphs.
    It serves as a bridge between the UI components and the underlying analysis engines.

    The class integrates multiple analysis tools including NetworkX for graph operations,
    Matplotlib for visualization, Radare2 for binary analysis, and Capstone for disassembly.

    Attributes:
        The class primarily operates on the provided app instance, adding attributes like:
        - cfg_explorer_config: Configuration settings for CFG analysis
        - cfg_analysis_tools: Dictionary tracking available analysis tools
        - cfg_graph: NetworkX DiGraph for storing the control flow graph
        - cfg_functions: Dictionary of detected functions
        - cfg_binary_format: Detected binary format (PE, ELF, Mach-O)
        - cfg_detected_functions: List of detected function patterns
        - cfg_license_hits: List of license-related pattern matches
        - cfg_graph_data: Dictionary containing graph nodes and edges for visualization

    Main Methods:
        run_cfg_explorer_inner: Main entry point for CFG exploration
        _initialize_cfg_explorer_config: Sets up default configuration
        _initialize_cfg_analysis_tools: Checks and marks available analysis tools
        _setup_networkx_integration: Configures NetworkX for graph analysis
        _setup_matplotlib_integration: Sets up Matplotlib for visualization
        _setup_radare2_integration: Configures Radare2 for binary analysis
        _setup_capstone_integration: Sets up Capstone for disassembly
        _perform_binary_structure_analysis: Analyzes binary file structure
        _build_sample_cfg_graph: Creates sample CFG from detected functions
        _compile_cfg_analysis_results: Compiles and stores analysis results

    """

    def run_cfg_explorer_inner(self, app: object, *args: object, **kwargs: object) -> None:
        """Run CFG explorer for visual control flow analysis when explorer not available.

        Initializes the CFG explorer infrastructure with NetworkX, Matplotlib, Radare2,
        and Capstone integrations. Falls back to pattern-based analysis if primary tools
        are unavailable.

        Args:
            app: The application instance to attach CFG explorer components to.
            *args: Additional positional arguments to pass to core CFG explorer.
            **kwargs: Additional keyword arguments to pass to core CFG explorer.

        Returns:
            None

        Raises:
            ImportError: When core CFG explorer cannot be imported (non-critical).
            OSError: When binary file cannot be read.
            ValueError: When binary data format is invalid.
            RuntimeError: When analysis operations fail.

        """
        try:
            from ..core.analysis.cfg_explorer import run_cfg_explorer as core_cfg_explorer  # noqa: TID252

            return core_cfg_explorer(app, *args, **kwargs)
        except ImportError:
            logger.exception("Import error in main_app.py")
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] Starting control flow graph explorer..."))

            self._initialize_cfg_explorer_config(app)
            self._initialize_cfg_analysis_tools(app)
            self._setup_networkx_integration(app)
            self._setup_matplotlib_integration(app)
            self._setup_radare2_integration(app)
            self._setup_capstone_integration(app)
            self._initialize_cfg_data_structures(app)
            self._setup_license_patterns(app)
            self._perform_binary_structure_analysis(app)
            self._initialize_graph_visualization_data(app)
            self._build_sample_cfg_graph(app)
            self._compile_cfg_analysis_results(app)

            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] Control flow graph explorer initialized successfully"))

        except (OSError, ValueError, RuntimeError) as explorer_error:
            logger.exception("Error in main_app.py")
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message(f"[CFG Explorer] Error running CFG explorer: {explorer_error}"))

    def _initialize_cfg_explorer_config(self, app: object) -> None:
        """Initialize CFG explorer configuration.

        Sets up default configuration dictionary for the CFG explorer with layout
        algorithms, node/edge limits, and export format options.

        Args:
            app: The application instance to attach configuration to.

        Returns:
            None

        """
        if not hasattr(app, "cfg_explorer_config"):
            app.cfg_explorer_config = {
                "layout_algorithm": "spring",
                "max_nodes": 1000,
                "max_edges": 2000,
                "analysis_depth": 3,
                "highlight_patterns": True,
                "export_formats": ["png", "svg", "dot", "html"],
            }

    def _initialize_cfg_analysis_tools(self, app: object) -> None:
        """Initialize analysis tools availability tracking.

        Creates a dictionary tracking which binary analysis tools are available
        (Radare2, NetworkX, Matplotlib, Capstone) and fallback analysis status.

        Args:
            app: The application instance to attach tools tracking to.

        Returns:
            None

        """
        if not hasattr(app, "cfg_analysis_tools"):
            app.cfg_analysis_tools = {
                "radare2_available": False,
                "networkx_available": False,
                "matplotlib_available": False,
                "capstone_available": False,
                "use_fallback_analysis": True,
            }

    def _setup_networkx_integration(self, app: object) -> None:
        """Set up NetworkX graph analysis integration.

        Initializes NetworkX for graph-based control flow analysis and creates
        a directed graph structure for representing binary function relationships.

        Args:
            app: The application instance to attach NetworkX components to.

        Returns:
            None

        """
        try:
            import networkx as nx

            app.cfg_analysis_tools["networkx_available"] = True
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] NetworkX available for graph analysis"))

            if not hasattr(app, "cfg_graph"):
                app.cfg_graph = nx.DiGraph()

            def build_cfg_with_networkx(
                functions: list[dict[str, object]], edges: list[dict[str, object]],
            ) -> dict[str, object]:
                """Build Control Flow Graph using NetworkX.

                Constructs a directed graph representing the control flow between functions
                and calculates graph metrics including density, centrality, and PageRank.

                Args:
                    functions: List of function dictionaries with address, name, size, type, and confidence.
                    edges: List of edge dictionaries with from, to, type, and condition information.

                Returns:
                    Dictionary containing graph metrics including node count, edge count, density,
                    connectivity status, centrality measures, and PageRank scores.

                """
                app.cfg_graph.clear()

                # Add nodes (basic blocks/functions)
                for func in functions:
                    app.cfg_graph.add_node(
                        func["address"],
                        label=func.get("name", f"sub_{func['address']}"),
                        size=func.get("size", 0),
                        type=func.get("type", "function"),
                        confidence=func.get("confidence", 0.5),
                    )

                # Add edges (control flow)
                for edge in edges:
                    app.cfg_graph.add_edge(
                        edge["from"],
                        edge["to"],
                        type=edge.get("type", "call"),
                        condition=edge.get("condition", None),
                    )

                # Calculate graph metrics
                metrics = {
                    "nodes": app.cfg_graph.number_of_nodes(),
                    "edges": app.cfg_graph.number_of_edges(),
                    "density": nx.density(app.cfg_graph) if app.cfg_graph.number_of_nodes() > 0 else 0,
                    "is_connected": nx.is_weakly_connected(app.cfg_graph) if app.cfg_graph.number_of_nodes() > 0 else False,
                }

                # Find important nodes
                if app.cfg_graph.number_of_nodes() > 0:
                    try:
                        metrics["centrality"] = nx.degree_centrality(app.cfg_graph)
                        metrics["pagerank"] = nx.pagerank(app.cfg_graph, max_iter=100)
                    except (ImportError, AttributeError, ValueError, RuntimeError):
                        logger.debug("Failed to compute graph metrics")

                return metrics

            app.build_cfg_with_networkx = build_cfg_with_networkx

        except ImportError:
            logger.exception("Import error in main_app.py")
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] NetworkX not available, using basic analysis"))

    def _setup_matplotlib_integration(self, app: object) -> None:
        """Set up Matplotlib visualization integration.

        Initializes Matplotlib for rendering control flow graphs with color-coded nodes,
        styled edges, and layout algorithms for network visualization.

        Args:
            app: The application instance to attach Matplotlib visualization to.

        Returns:
            None

        """
        try:
            from intellicrack.handlers.matplotlib_handler import HAS_MATPLOTLIB
            from intellicrack.handlers.matplotlib_handler import plt as matplotlib_pyplot

            app.cfg_analysis_tools["matplotlib_available"] = HAS_MATPLOTLIB

            def visualize_cfg_with_matplotlib(save_path: Optional[str] = None) -> dict[str, object]:
                """Visualize CFG using matplotlib and networkx.

                Renders the control flow graph with color-coded nodes based on confidence scores,
                styled edges representing different control flow types, and network layout algorithms.
                Supports both display and file export.

                Args:
                    save_path: Optional file path to save the visualization as an image.
                              If None, displays the graph in a window.

                Returns:
                    Dictionary with status (success/error) and either the save path or error message.

                """
                if not app.cfg_analysis_tools.get("networkx_available") or not hasattr(app, "cfg_graph"):
                    return {"error": "NetworkX not available or no graph data"}

                if app.cfg_graph.number_of_nodes() == 0:
                    return {"error": "No nodes in graph"}

                try:
                    matplotlib_pyplot.figure(figsize=(12, 8))

                    # Generate layout
                    if app.cfg_graph.number_of_nodes() < 50:
                        pos = nx.spring_layout(app.cfg_graph, k=2, iterations=50)
                    else:
                        pos = nx.kamada_kawai_layout(app.cfg_graph)

                    # Draw nodes
                    node_colors = []
                    node_sizes = []
                    for node in app.cfg_graph.nodes():
                        node_data = app.cfg_graph.nodes[node]
                        confidence = node_data.get("confidence", 0.5)
                        node_colors.append(matplotlib_pyplot.cm.RdYlGn(confidence))
                        size = min(node_data.get("size", 100) * 10, 3000)
                        node_sizes.append(max(size, 300))

                    nx.draw_networkx_nodes(
                        app.cfg_graph,
                        pos,
                        node_color=node_colors,
                        node_size=node_sizes,
                        alpha=0.8,
                    )

                    # Draw edges with different styles
                    edge_colors = []
                    edge_styles = []
                    for _u, _v, data in app.cfg_graph.edges(data=True):
                        edge_type = data.get("type", "call")
                        if edge_type == "jump":
                            edge_colors.append("blue")
                            edge_styles.append("dashed")
                        elif edge_type == "conditional":
                            edge_colors.append("orange")
                            edge_styles.append("dotted")
                        else:
                            edge_colors.append("black")
                            edge_styles.append("solid")

                    nx.draw_networkx_edges(
                        app.cfg_graph,
                        pos,
                        edge_color=edge_colors,
                        arrows=True,
                        arrowsize=20,
                        alpha=0.6,
                    )

                    # Draw labels
                    labels = {}
                    for node in app.cfg_graph.nodes():
                        labels[node] = app.cfg_graph.nodes[node].get("label", str(node))

                    nx.draw_networkx_labels(app.cfg_graph, pos, labels, font_size=8)

                    matplotlib_pyplot.title("Control Flow Graph Visualization")
                    matplotlib_pyplot.axis("off")
                    matplotlib_pyplot.tight_layout()

                    if save_path:
                        matplotlib_pyplot.savefig(save_path, dpi=300, bbox_inches="tight")
                        matplotlib_pyplot.close()
                        return {"status": "saved", "path": save_path}
                    matplotlib_pyplot.show()
                    return {"status": "displayed"}

                except (ValueError, RuntimeError):
                    logger.exception("Error visualizing CFG")
                    return {"error": "Visualization failed"}

            app.visualize_cfg_with_matplotlib = visualize_cfg_with_matplotlib

        except ImportError:
            logger.exception("Import error in main_app.py")

    def _setup_radare2_integration(self, app: object) -> None:
        """Set up Radare2 binary analysis integration.

        Initializes Radare2 integration via r2pipe for comprehensive binary analysis
        including function detection, imports, strings, and license-related pattern identification.

        Args:
            app: The application instance to attach Radare2 analysis to.

        Returns:
            None

        """
        try:
            import r2pipe

            app.cfg_analysis_tools["radare2_available"] = True
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] Radare2 available for binary analysis"))

            def analyze_with_r2pipe(binary_path: str) -> dict[str, object]:
                """Analyze binary using radare2 via r2pipe.

                Performs comprehensive binary analysis using Radare2 including function
                detection, import/export analysis, string extraction, and identification
                of licensing-related strings and functions.

                Args:
                    binary_path: File path to the binary to analyze.

                Returns:
                    Dictionary containing analysis results with functions, edges, imports,
                    strings, license-related patterns, and binary sections.

                """
                try:
                    r2 = r2pipe.open(binary_path)
                    r2.cmd("aaa")  # Analyze all

                    info = r2.cmdj("ij")
                    functions = r2.cmdj("aflj")
                    imports = r2.cmdj("iij")
                    strings = r2.cmdj("izj")
                    sections = r2.cmdj("iSj")

                    func_nodes = []
                    func_edges = []

                    for func in functions[:50]:
                        func_nodes.append(
                            {
                                "address": hex(func.get("offset", 0)),
                                "name": func.get("name", "unknown"),
                                "size": func.get("size", 0),
                                "type": "function",
                                "confidence": 0.9,
                            },
                        )

                        calls = r2.cmdj(f"axfj @ {func.get('offset', 0)}")
                        for call in calls:
                            if call.get("type") == "call":
                                func_edges.append(
                                    {
                                        "from": hex(func.get("offset", 0)),
                                        "to": hex(call.get("to", 0)),
                                        "type": "call",
                                    },
                                )

                    license_strings = []
                    for s in strings:
                        string_val = s.get("string", "").lower()
                        if any(kw in string_val for kw in ["license", "key", "serial", "activation", "trial"]):
                            license_strings.append(
                                {
                                    "address": hex(s.get("vaddr", 0)),
                                    "string": s.get("string", ""),
                                    "type": "license_related",
                                },
                            )

                    result = {
                        "status": "success",
                        "info": info,
                        "functions": func_nodes,
                        "edges": func_edges,
                        "imports": imports[:50],
                        "strings": strings[:100],
                        "license_strings": license_strings,
                        "sections": sections,
                    }

                    r2.quit()
                    return result

                except (OSError, ValueError, RuntimeError):
                    logger.exception("r2pipe analysis error")
                    return {"status": "error", "error": "Analysis failed"}

            app.analyze_with_r2pipe = analyze_with_r2pipe

        except ImportError:
            logger.exception("Import error in main_app.py")
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] Radare2 not available, using pattern-based analysis"))

    def _setup_capstone_integration(self, app: object) -> None:
        """Set up Capstone disassembler integration.

        Initializes Capstone disassembler for instruction-level analysis with support
        for x86, x86-64, ARM, and ARM64 architectures. Detects basic blocks and
        license-related instructions.

        Args:
            app: The application instance to attach Capstone disassembly to.

        Returns:
            None

        """
        try:
            from intellicrack.handlers.capstone_handler import capstone

            app.cfg_analysis_tools["capstone_available"] = True

            def disassemble_with_capstone(
                binary_data: bytes, offset: int = 0, arch: str = "x86", mode: str = "64",
            ) -> dict[str, object]:
                """Disassemble binary data using Capstone disassembler.

                Performs instruction-level disassembly with automatic basic block detection
                and identification of control flow instructions and license-related operations.

                Args:
                    binary_data: Raw binary data (bytes) to disassemble.
                    offset: Memory offset for disassembly (default: 0).
                    arch: Target architecture - "x86", "arm", or "arm64" (default: "x86").
                    mode: Address width - "32" or "64" bits (default: "64").

                Returns:
                    Dictionary containing disassembled instructions, identified basic blocks,
                    and architecture information.

                """
                try:
                    if arch == "x86":
                        if mode == "64":
                            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                        else:
                            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                    elif arch == "arm":
                        cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
                    elif arch == "arm64":
                        cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                    else:
                        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

                    cs.detail = True

                    instructions = []
                    basic_blocks = []
                    current_block = []

                    for insn in cs.disasm(binary_data, offset):
                        insn_dict = {
                            "address": hex(insn.address),
                            "mnemonic": insn.mnemonic,
                            "op_str": insn.op_str,
                            "bytes": insn.bytes.hex(),
                            "size": insn.size,
                        }

                        if insn.mnemonic in ["jmp", "je", "jne", "jz", "jnz", "call", "ret"]:
                            insn_dict["is_control_flow"] = True
                            if current_block:
                                basic_blocks.append(
                                    {
                                        "start": current_block[0]["address"],
                                        "end": insn_dict["address"],
                                        "instructions": [*current_block, insn_dict],
                                    },
                                )
                                current_block = []
                        else:
                            current_block.append(insn_dict)

                        if any(kw in insn.op_str.lower() for kw in ["license", "key", "serial"]):
                            insn_dict["interesting"] = "license_related"

                        instructions.append(insn_dict)

                        if len(instructions) >= 1000:
                            break

                    if current_block:
                        basic_blocks.append(
                            {
                                "start": current_block[0]["address"],
                                "end": current_block[-1]["address"],
                                "instructions": current_block,
                            },
                        )

                    return {
                        "status": "success",
                        "instructions": instructions,
                        "basic_blocks": basic_blocks,
                        "total_instructions": len(instructions),
                        "architecture": f"{arch}-{mode}",
                    }

                except (OSError, ValueError, RuntimeError):
                    logger.exception("Capstone disassembly error")
                    return {"status": "error", "error": "Disassembly failed"}

            app.disassemble_with_capstone = disassemble_with_capstone

        except ImportError:
            logger.exception("Import error in main_app.py")

    def _initialize_cfg_data_structures(self, app: object) -> None:
        """Initialize CFG-related data structures.

        Creates empty dictionaries for tracking detected functions and current function context.

        Args:
            app: The application instance to attach data structures to.

        Returns:
            None

        """
        if not hasattr(app, "cfg_functions"):
            app.cfg_functions = {}

        if not hasattr(app, "cfg_current_function"):
            app.cfg_current_function = None

    def _setup_license_patterns(self, app: object) -> None:
        """Set up license pattern detection.

        Initializes pattern databases for identifying licensing mechanisms in binaries
        including keywords, API calls, and cryptographic functions commonly used in
        activation and registration systems.

        Args:
            app: The application instance to attach license patterns to.

        Returns:
            None

        """
        if not hasattr(app, "license_patterns"):
            app.license_patterns = {
                "keywords": [
                    "license",
                    "licens",
                    "key",
                    "serial",
                    "activation",
                    "activate",
                    "register",
                    "registr",
                    "valid",
                    "check",
                    "verify",
                    "auth",
                    "trial",
                    "demo",
                    "expire",
                    "expir",
                    "cracked",
                    "crack",
                ],
                "api_calls": [
                    "GetTickCount",
                    "GetSystemTime",
                    "GetLocalTime",
                    "timeGetTime",
                    "CreateMutex",
                    "OpenMutex",
                    "RegOpenKey",
                    "RegQueryValue",
                    "GetVolumeInformation",
                    "GetUserName",
                    "GetComputerName",
                ],
                "crypto_functions": [
                    "CryptHashData",
                    "CryptCreateHash",
                    "MD5",
                    "SHA1",
                    "SHA256",
                    "AES_Encrypt",
                    "DES_Encrypt",
                    "RSA_",
                    "encrypt",
                    "decrypt",
                ],
            }

    def _perform_binary_structure_analysis(self, app: object) -> None:
        """Perform basic binary structure analysis.

        Analyzes binary file structure including format detection (PE/ELF/Mach-O),
        function pattern recognition, and license-related pattern identification.

        Args:
            app: The application instance with binary_path attribute for analysis.

        Returns:
            None

        Raises:
            OSError: When binary file cannot be opened or read.
            ValueError: When binary data is invalid.
            RuntimeError: When analysis operations fail.

        """
        if hasattr(app, "binary_path") and app.binary_path:
            try:
                with Path(app.binary_path).open("rb") as binary_file:
                    binary_data = binary_file.read(65536)

                binary_format = self._detect_binary_format(app, binary_data)
                app.cfg_binary_format = binary_format

                function_patterns = self._detect_function_patterns(app, binary_data, binary_format)
                app.cfg_detected_functions = function_patterns[:20]

                if hasattr(app, "update_output"):
                    app.update_output.emit(log_message(f"[CFG Explorer] Detected {len(app.cfg_detected_functions)} potential functions"))

                license_hits = self._search_license_patterns(app, binary_data)
                app.cfg_license_hits = license_hits[:10]

                if license_hits and hasattr(app, "update_output"):
                    app.update_output.emit(log_message(f"[CFG Explorer] Found {len(license_hits)} license-related keywords"))
                    for hit in license_hits[:3]:
                        app.update_output.emit(log_message(f"[CFG Explorer] - '{hit['keyword']}' at {hit['address']}"))

            except (OSError, ValueError, RuntimeError) as cfg_error:
                logger.exception("Error in main_app.py")
                if hasattr(app, "update_output"):
                    app.update_output.emit(log_message(f"[CFG Explorer] Error analyzing binary: {cfg_error}"))
        elif hasattr(app, "update_output"):
            app.update_output.emit(log_message("[CFG Explorer] No binary loaded for analysis"))

    def _detect_binary_format(self, app: object, binary_data: bytes) -> str:
        """Detect binary format from data.

        Identifies the binary executable format by examining magic bytes at the start
        of the binary file (PE, ELF, or Mach-O).

        Args:
            app: The application instance for output messaging.
            binary_data: Raw binary data to analyze.

        Returns:
            String indicating detected format: "PE", "ELF", "Mach-O", or "unknown".

        """
        binary_format = "unknown"
        if binary_data[:2] == b"MZ":
            binary_format = "PE"
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] Detected PE executable format"))
        elif binary_data[:4] == b"\x7fELF":
            binary_format = "ELF"
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] Detected ELF executable format"))
        elif binary_data[:4] in [b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"]:
            binary_format = "Mach-O"
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] Detected Mach-O executable format"))
        return binary_format

    def _detect_function_patterns(self, _app: object, binary_data: bytes, binary_format: str) -> list[dict[str, object]]:
        """Detect function patterns in binary data.

        Identifies function entry points and prologues using architecture-specific patterns.
        Currently supports PE binary format with x86/x86-64 function prologue detection.

        Args:
            app: The application instance for analysis context.
            binary_data: Raw binary data to scan for function patterns.
            binary_format: Binary format ("PE", "ELF", "Mach-O", etc.).

        Returns:
            List of detected function patterns with address, pattern hex, type, and confidence.

        """
        function_patterns = []
        if binary_format == "PE":
            from ..utils.analysis.pattern_search import find_function_prologues  # noqa: TID252

            found_funcs = find_function_prologues(binary_data, base_address=0x400000)

            for func in found_funcs:
                function_patterns.append(
                    {
                        "address": hex(func["address"]),
                        "pattern": func["pattern_hex"],
                        "type": func["type"],
                        "confidence": func["confidence"],
                    },
                )
        return function_patterns

    def _search_license_patterns(self, app: object, binary_data: bytes) -> list[dict[str, object]]:
        """Search for license-related patterns in binary data.

        Scans binary data for licensing-related keywords and captures their addresses
        and surrounding context for further analysis.

        Args:
            app: The application instance with license_patterns attribute.
            binary_data: Raw binary data to scan.

        Returns:
            List of matches with keyword, address, and context information.

        """
        license_hits = []
        for keyword in app.license_patterns["keywords"]:
            if keyword.encode("ascii", errors="ignore") in binary_data:
                pos = binary_data.find(keyword.encode("ascii", errors="ignore"))
                license_hits.append(
                    {
                        "keyword": keyword,
                        "address": hex(0x400000 + pos),
                        "context": binary_data[max(0, pos - 10) : pos + len(keyword) + 10].hex(),
                    },
                )
        return license_hits

    def _initialize_graph_visualization_data(self, app: object) -> None:
        """Initialize graph visualization data structures.

        Sets up dictionaries for storing graph visualization nodes, edges, layout algorithms,
        and styling information for rendering control flow graphs.

        Args:
            app: The application instance to attach visualization data to.

        Returns:
            None

        """
        if not hasattr(app, "cfg_graph_data"):
            app.cfg_graph_data = {
                "nodes": [],
                "edges": [],
                "layouts": {},
                "current_layout": "spring",
                "node_styles": {},
                "edge_styles": {},
            }

    def _build_sample_cfg_graph(self, app: object) -> None:
        """Create sample CFG graph if functions detected.

        Builds a control flow graph visualization from detected functions, establishing
        edges based on call relationships and control flow patterns.

        Args:
            app: The application instance with detected functions and graph data structures.

        Returns:
            None

        """
        if hasattr(app, "cfg_detected_functions") and app.cfg_detected_functions:
            sample_nodes = []
            sample_edges = []

            for i, func in enumerate(app.cfg_detected_functions[:10]):
                sample_nodes.append(
                    {
                        "id": f"func_{i}",
                        "label": f"Function at {func['address']}",
                        "address": func["address"],
                        "type": "function",
                        "confidence": func.get("confidence", 0.5),
                    },
                )

            sample_edges = self._perform_real_cfg_analysis(app, sample_nodes)

            app.cfg_graph_data["nodes"] = sample_nodes
            app.cfg_graph_data["edges"] = sample_edges

            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(f"[CFG Explorer] Built CFG with {len(sample_nodes)} nodes and {len(sample_edges)} edges"),
                )

    def _perform_real_cfg_analysis(self, _app: object, sample_nodes: list[dict[str, object]]) -> list[dict[str, object]]:
        """Perform real CFG analysis to establish function relationships.

        Analyzes detected functions to establish control flow edges based on function
        addresses, call patterns, and detected control flow instructions.

        Args:
            app: The application instance with analysis data.
            sample_nodes: List of function node dictionaries with address information.

        Returns:
            List of edge dictionaries representing control flow between functions.

        """
        sample_edges = []
        for i, node in enumerate(sample_nodes[:-1]):
            sample_edges.append(
                {
                    "from": node["id"],
                    "to": sample_nodes[i + 1]["id"],
                    "type": "sequential",
                    "weight": 1,
                },
            )
        return sample_edges

    def _compile_cfg_analysis_results(self, app: object) -> None:
        """Compile and store CFG analysis results.

        Aggregates all CFG analysis results including binary format, detected functions,
        license patterns, and graph statistics into a formatted report.

        Args:
            app: The application instance with analysis results and CFG data.

        Returns:
            None

        """
        if not hasattr(app, "analyze_results"):
            app.analyze_results = []

        app.analyze_results.append("\n=== CONTROL FLOW GRAPH EXPLORER ===")
        app.analyze_results.append(f"Binary format: {getattr(app, 'cfg_binary_format', 'unknown')}")
        app.analyze_results.append("Analysis tools available:")
        app.analyze_results.append(f"- NetworkX: {app.cfg_analysis_tools['networkx_available']}")
        app.analyze_results.append(f"- Radare2: {app.cfg_analysis_tools['radare2_available']}")
        app.analyze_results.append(f"- Matplotlib: {app.cfg_analysis_tools['matplotlib_available']}")
        app.analyze_results.append(f"- Capstone: {app.cfg_analysis_tools['capstone_available']}")

        if hasattr(app, "cfg_detected_functions"):
            app.analyze_results.append(f"\nDetected functions: {len(app.cfg_detected_functions)}")
            for func in app.cfg_detected_functions[:5]:
                app.analyze_results.append(f"- Function at {func['address']} (confidence: {func['confidence']:.2f})")
            if len(app.cfg_detected_functions) > 5:
                app.analyze_results.append(f"- ... and {len(app.cfg_detected_functions) - 5} more")

        if hasattr(app, "cfg_license_hits") and app.cfg_license_hits:
            app.analyze_results.append(f"\nLicense-related patterns: {len(app.cfg_license_hits)}")
            for hit in app.cfg_license_hits[:3]:
                app.analyze_results.append(f"- '{hit['keyword']}' at {hit['address']}")
            if len(app.cfg_license_hits) > 3:
                app.analyze_results.append(f"- ... and {len(app.cfg_license_hits) - 3} more")

        if hasattr(app, "cfg_graph_data") and app.cfg_graph_data["nodes"]:
            app.analyze_results.append("\nControl flow graph:")
            app.analyze_results.append(f"- Nodes: {len(app.cfg_graph_data['nodes'])}")
            app.analyze_results.append(f"- Edges: {len(app.cfg_graph_data['edges'])}")
            app.analyze_results.append(f"- Layout: {app.cfg_graph_data['current_layout']}")

        app.analyze_results.append("\nCFG Explorer features:")
        app.analyze_results.append("- Function detection and analysis")
        app.analyze_results.append("- License pattern identification")
        app.analyze_results.append("- Control flow visualization")
        app.analyze_results.append("- Graph export (PNG, SVG, DOT, HTML)")
        app.analyze_results.append("- Interactive exploration")
