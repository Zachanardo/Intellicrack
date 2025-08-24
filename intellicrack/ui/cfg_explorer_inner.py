import logging

import networkx

from intellicrack.utils.log_message import log_message

logger = logging.getLogger(__name__)

class CfgExplorerInner:
    def run_cfg_explorer_inner(self, app, *args, **kwargs):
        """Run CFG explorer for visual control flow analysis when explorer not available"""
        try:
            from ..core.analysis.cfg_explorer import run_cfg_explorer as core_cfg_explorer
            return core_cfg_explorer(app, *args, **kwargs)
        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
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
            logger.error("(OSError, ValueError, RuntimeError) in main_app.py: %s", explorer_error)
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message(f"[CFG Explorer] Error running CFG explorer: {explorer_error}"))


    def _initialize_cfg_explorer_config(self, app):
        """Initialize CFG explorer configuration"""
        if not hasattr(app, "cfg_explorer_config"):
            app.cfg_explorer_config = {
                "layout_algorithm": "spring",
                "max_nodes": 1000,
                "max_edges": 2000,
                "analysis_depth": 3,
                "highlight_patterns": True,
                "export_formats": ["png", "svg", "dot", "html"],
            }

    def _initialize_cfg_analysis_tools(self, app):
        """Initialize analysis tools availability tracking"""
        if not hasattr(app, "cfg_analysis_tools"):
            app.cfg_analysis_tools = {
                "radare2_available": False,
                "networkx_available": False,
                "matplotlib_available": False,
                "capstone_available": False,
                "use_fallback_analysis": True,
            }

    def _setup_networkx_integration(self, app):
        """Set up NetworkX graph analysis integration"""
        try:
            import networkx
            app.cfg_analysis_tools["networkx_available"] = True
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] NetworkX available for graph analysis"))

            if not hasattr(app, "cfg_graph"):
                app.cfg_graph = networkx.DiGraph()

            def build_cfg_with_networkx(functions, edges):
                """Build Control Flow Graph using NetworkX"""
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
                    "density": networkx.density(app.cfg_graph) if app.cfg_graph.number_of_nodes() > 0 else 0,
                    "is_connected": networkx.is_weakly_connected(app.cfg_graph) if app.cfg_graph.number_of_nodes() > 0 else False,
                }

                # Find important nodes
                if app.cfg_graph.number_of_nodes() > 0:
                    try:
                        metrics["centrality"] = networkx.degree_centrality(app.cfg_graph)
                        metrics["pagerank"] = networkx.pagerank(app.cfg_graph, max_iter=100)
                    except (ImportError, AttributeError, Exception) as e:
                        logger.debug(f"Failed to compute graph metrics: {e}")

                return metrics

            app.build_cfg_with_networkx = build_cfg_with_networkx

        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] NetworkX not available, using basic analysis"))

    def _setup_matplotlib_integration(self, app):
        """Set up Matplotlib visualization integration"""
        try:
            from intellicrack.handlers.matplotlib_handler import HAS_MATPLOTLIB
            from intellicrack.handlers.matplotlib_handler import plt as matplotlib_pyplot

            app.cfg_analysis_tools["matplotlib_available"] = HAS_MATPLOTLIB

            def visualize_cfg_with_matplotlib(save_path=None):
                """Visualize CFG using matplotlib and networkx"""
                if not app.cfg_analysis_tools.get("networkx_available") or not hasattr(app, "cfg_graph"):
                    return {"error": "NetworkX not available or no graph data"}

                if app.cfg_graph.number_of_nodes() == 0:
                    return {"error": "No nodes in graph"}

                try:
                    matplotlib_pyplot.figure(figsize=(12, 8))

                    # Generate layout
                    if app.cfg_graph.number_of_nodes() < 50:
                        pos = networkx.spring_layout(app.cfg_graph, k=2, iterations=50)
                    else:
                        pos = networkx.kamada_kawai_layout(app.cfg_graph)

                    # Draw nodes
                    node_colors = []
                    node_sizes = []
                    for node in app.cfg_graph.nodes():
                        node_data = app.cfg_graph.nodes[node]
                        confidence = node_data.get("confidence", 0.5)
                        node_colors.append(matplotlib_pyplot.cm.RdYlGn(confidence))
                        size = min(node_data.get("size", 100) * 10, 3000)
                        node_sizes.append(max(size, 300))

                    networkx.draw_networkx_nodes(
                        app.cfg_graph, pos, node_color=node_colors, node_size=node_sizes, alpha=0.8,
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

                    networkx.draw_networkx_edges(
                        app.cfg_graph, pos, edge_color=edge_colors, arrows=True, arrowsize=20, alpha=0.6,
                    )

                    # Draw labels
                    labels = {}
                    for node in app.cfg_graph.nodes():
                        labels[node] = app.cfg_graph.nodes[node].get("label", str(node))

                    networkx.draw_networkx_labels(app.cfg_graph, pos, labels, font_size=8)

                    matplotlib_pyplot.title("Control Flow Graph Visualization")
                    matplotlib_pyplot.axis("off")
                    matplotlib_pyplot.tight_layout()

                    if save_path:
                        matplotlib_pyplot.savefig(save_path, dpi=300, bbox_inches="tight")
                        matplotlib_pyplot.close()
                        return {"status": "saved", "path": save_path}
                    else:
                        matplotlib_pyplot.show()
                        return {"status": "displayed"}

                except Exception as e:
                    logger.error(f"Error visualizing CFG: {e}")
                    return {"error": str(e)}

            app.visualize_cfg_with_matplotlib = visualize_cfg_with_matplotlib

        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            pass

    def _setup_radare2_integration(self, app):
        """Set up Radare2 binary analysis integration"""
        try:
            import r2pipe
            app.cfg_analysis_tools["radare2_available"] = True
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] Radare2 available for binary analysis"))

            def analyze_with_r2pipe(binary_path):
                """Analyze binary using radare2 via r2pipe"""
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
                        func_nodes.append({
                            "address": hex(func.get("offset", 0)),
                            "name": func.get("name", "unknown"),
                            "size": func.get("size", 0),
                            "type": "function",
                            "confidence": 0.9,
                        })

                        calls = r2.cmdj(f'axfj @ {func.get("offset", 0)}')
                        for call in calls:
                            if call.get("type") == "call":
                                func_edges.append({
                                    "from": hex(func.get("offset", 0)),
                                    "to": hex(call.get("to", 0)),
                                    "type": "call",
                                })

                    license_strings = []
                    for s in strings:
                        string_val = s.get("string", "").lower()
                        if any(kw in string_val for kw in ["license", "key", "serial", "activation", "trial"]):
                            license_strings.append({
                                "address": hex(s.get("vaddr", 0)),
                                "string": s.get("string", ""),
                                "type": "license_related",
                            })

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

                except Exception as e:
                    logger.error(f"r2pipe analysis error: {e}")
                    return {"status": "error", "error": str(e)}

            app.analyze_with_r2pipe = analyze_with_r2pipe

        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] Radare2 not available, using pattern-based analysis"))

    def _setup_capstone_integration(self, app):
        """Set up Capstone disassembler integration"""
        try:
            from intellicrack.handlers.capstone_handler import capstone
            app.cfg_analysis_tools["capstone_available"] = True

            def disassemble_with_capstone(binary_data, offset=0, arch="x86", mode="64"):
                """Disassemble binary data using Capstone disassembler"""
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
                                basic_blocks.append({
                                    "start": current_block[0]["address"],
                                    "end": insn_dict["address"],
                                    "instructions": current_block + [insn_dict],
                                })
                                current_block = []
                        else:
                            current_block.append(insn_dict)

                        if any(kw in insn.op_str.lower() for kw in ["license", "key", "serial"]):
                            insn_dict["interesting"] = "license_related"

                        instructions.append(insn_dict)

                        if len(instructions) >= 1000:
                            break

                    if current_block:
                        basic_blocks.append({
                            "start": current_block[0]["address"],
                            "end": current_block[-1]["address"],
                            "instructions": current_block,
                        })

                    return {
                        "status": "success",
                        "instructions": instructions,
                        "basic_blocks": basic_blocks,
                        "total_instructions": len(instructions),
                        "architecture": f"{arch}-{mode}",
                    }

                except Exception as e:
                    logger.error(f"Capstone disassembly error: {e}")
                    return {"status": "error", "error": str(e)}

            app.disassemble_with_capstone = disassemble_with_capstone

        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            pass

    def _initialize_cfg_data_structures(self, app):
        """Initialize CFG-related data structures"""
        if not hasattr(app, "cfg_functions"):
            app.cfg_functions = {}

        if not hasattr(app, "cfg_current_function"):
            app.cfg_current_function = None

    def _setup_license_patterns(self, app):
        """Set up license pattern detection"""
        if not hasattr(app, "license_patterns"):
            app.license_patterns = {
                "keywords": [
                    "license", "licens", "key", "serial", "activation", "activate",
                    "register", "registr", "valid", "check", "verify", "auth",
                    "trial", "demo", "expire", "expir", "cracked", "crack",
                ],
                "api_calls": [
                    "GetTickCount", "GetSystemTime", "GetLocalTime", "timeGetTime",
                    "CreateMutex", "OpenMutex", "RegOpenKey", "RegQueryValue",
                    "GetVolumeInformation", "GetUserName", "GetComputerName",
                ],
                "crypto_functions": [
                    "CryptHashData", "CryptCreateHash", "MD5", "SHA1", "SHA256",
                    "AES_Encrypt", "DES_Encrypt", "RSA_", "encrypt", "decrypt",
                ],
            }

    def _perform_binary_structure_analysis(self, app):
        """Perform basic binary structure analysis"""
        if hasattr(app, "binary_path") and app.binary_path:
            try:
                with open(app.binary_path, "rb") as binary_file:
                    binary_data = binary_file.read(65536)

                binary_format = self._detect_binary_format(app, binary_data)
                app.cfg_binary_format = binary_format

                function_patterns = self._detect_function_patterns(app, binary_data, binary_format)
                app.cfg_detected_functions = function_patterns[:20]

                if hasattr(app, "update_output"):
                    app.update_output.emit(
                        log_message(f"[CFG Explorer] Detected {len(app.cfg_detected_functions)} potential functions")
                    )

                license_hits = self._search_license_patterns(app, binary_data)
                app.cfg_license_hits = license_hits[:10]

                if license_hits and hasattr(app, "update_output"):
                    app.update_output.emit(
                        log_message(f"[CFG Explorer] Found {len(license_hits)} license-related keywords")
                    )
                    for hit in license_hits[:3]:
                        app.update_output.emit(
                            log_message(f"[CFG Explorer] - '{hit['keyword']}' at {hit['address']}")
                        )

            except (OSError, ValueError, RuntimeError) as cfg_error:
                logger.error("(OSError, ValueError, RuntimeError) in main_app.py: %s", cfg_error)
                if hasattr(app, "update_output"):
                    app.update_output.emit(log_message(f"[CFG Explorer] Error analyzing binary: {cfg_error}"))
        else:
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[CFG Explorer] No binary loaded for analysis"))

    def _detect_binary_format(self, app, binary_data):
        """Detect binary format from data"""
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

    def _detect_function_patterns(self, app, binary_data, binary_format):
        """Detect function patterns in binary data"""
        function_patterns = []
        if binary_format == "PE":
            from ..utils.analysis.pattern_search import find_function_prologues
            found_funcs = find_function_prologues(binary_data, base_address=0x400000)

            for func in found_funcs:
                function_patterns.append({
                    "address": hex(func["address"]),
                    "pattern": func["pattern_hex"],
                    "type": func["type"],
                    "confidence": func["confidence"],
                })
        return function_patterns

    def _search_license_patterns(self, app, binary_data):
        """Search for license-related patterns in binary data"""
        license_hits = []
        for keyword in app.license_patterns["keywords"]:
            if keyword.encode("ascii", errors="ignore") in binary_data:
                pos = binary_data.find(keyword.encode("ascii", errors="ignore"))
                license_hits.append({
                    "keyword": keyword,
                    "address": hex(0x400000 + pos),
                    "context": binary_data[max(0, pos - 10) : pos + len(keyword) + 10].hex(),
                })
        return license_hits

    def _initialize_graph_visualization_data(self, app):
        """Initialize graph visualization data structures"""
        if not hasattr(app, "cfg_graph_data"):
            app.cfg_graph_data = {
                "nodes": [],
                "edges": [],
                "layouts": {},
                "current_layout": "spring",
                "node_styles": {},
                "edge_styles": {},
            }

    def _build_sample_cfg_graph(self, app):
        """Create sample CFG graph if functions detected"""
        if hasattr(app, "cfg_detected_functions") and app.cfg_detected_functions:
            sample_nodes = []
            sample_edges = []

            for i, func in enumerate(app.cfg_detected_functions[:10]):
                sample_nodes.append({
                    "id": f"func_{i}",
                    "label": f"Function at {func['address']}",
                    "address": func["address"],
                    "type": "function",
                    "confidence": func.get("confidence", 0.5),
                })

            sample_edges = self._perform_real_cfg_analysis(app, sample_nodes)

            app.cfg_graph_data["nodes"] = sample_nodes
            app.cfg_graph_data["edges"] = sample_edges

            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(f"[CFG Explorer] Built CFG with {len(sample_nodes)} nodes and {len(sample_edges)} edges")
                )

    def _compile_cfg_analysis_results(self, app):
        """Compile and store CFG analysis results"""
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
                app.analyze_results.append(
                    f"- Function at {func['address']} (confidence: {func['confidence']:.2f})"
                )
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
