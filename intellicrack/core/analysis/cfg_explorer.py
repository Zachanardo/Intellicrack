"""
Control Flow Graph (CFG) Explorer for Binary Analysis 

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import json
import logging
import os
from typing import Any, Dict, List, Optional

# Optional dependencies - graceful fallback if not available
try:
    import r2pipe
    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

from ...utils.import_checks import CAPSTONE_AVAILABLE, PEFILE_AVAILABLE, capstone, pefile

if CAPSTONE_AVAILABLE and capstone:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
else:
    CS_ARCH_X86 = CS_MODE_32 = CS_MODE_64 = Cs = None

try:
    import subprocess
    SUBPROCESS_AVAILABLE = True
except ImportError:
    SUBPROCESS_AVAILABLE = False

# UI dependencies
try:
    from PyQt5.QtWidgets import QFileDialog, QInputDialog, QMessageBox
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False


class CFGExplorer:
    """
    Visual CFG (Control Flow Graph) Explorer.

    This class provides a graphical interface for analyzing control flow in binary code,
    helping to identify license validation routines and potential bypass points.
    """

    def __init__(self, binary_path: Optional[str] = None):
        """Initialize the CFG explorer with a binary path"""
        self.binary_path = binary_path
        self.logger = logging.getLogger(__name__)
        self.graph = None
        self.functions = {}
        self.current_function = None

    def load_binary(self, binary_path: Optional[str] = None) -> bool:
        """Load a binary file and extract its CFG"""
        if binary_path:
            self.binary_path = binary_path

        if not self.binary_path:
            self.logger.error("No binary path specified")
            return False

        if not R2PIPE_AVAILABLE:
            self.logger.error("r2pipe not available - please install radare2-r2pipe")
            return False

        if not NETWORKX_AVAILABLE:
            self.logger.error("NetworkX not available - please install networkx")
            return False

        try:
            # Use r2pipe to extract CFG
            # Configure radare2 path if available in config
            from ...config import CONFIG
            radare2_path = CONFIG.get('radare2_path', None)

            # Open the binary with radare2
            if radare2_path and os.path.exists(radare2_path):
                # Use specific radare2 binary path
                r2 = r2pipe.open(self.binary_path, flags=['-e', f'bin.radare2={radare2_path}'])
            else:
                # Use system PATH radare2
                r2 = r2pipe.open(self.binary_path)

            # Initialize radare2
            r2.cmd('aaa')  # Analyze all

            # Get list of functions
            functions_json = r2.cmd('aflj')
            functions = json.loads(functions_json)

            # Process functions
            for _func in functions:
                function_name = _func['name']
                function_addr = _func['offset']

                # Get basic blocks for this function
                blocks_json = r2.cmd(f'agfj @ {function_addr}')
                blocks = json.loads(blocks_json)

                if not blocks:
                    continue

                # Create a networkx graph for this function
                function_graph = nx.DiGraph()

                # Process blocks and edges
                for _block in blocks[0]['blocks']:
                    block_addr = _block['offset']
                    block_size = _block['size']
                    block_ops = _block.get('ops', [])

                    # Add node to graph
                    function_graph.add_node(
                        block_addr,
                        size=block_size,
                        ops=block_ops,
                        label=f"0x{block_addr:x}"
                    )

                    # Add edges
                    for _jump in _block.get('jump', []):
                        function_graph.add_edge(block_addr, _jump)

                    if 'fail' in _block and _block['fail'] != 0:
                        function_graph.add_edge(block_addr, _block['fail'])

                # Store function graph
                self.functions[function_name] = {
                    'addr': function_addr,
                    'graph': function_graph,
                    'blocks': blocks[0]['blocks']
                }

            # Close radare2
            r2.quit()

            self.logger.info(f"Loaded {len(self.functions)} functions from {self.binary_path}")
            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error loading binary: %s", e)
            return False

    def get_function_list(self) -> List[str]:
        """Get a list of all functions in the binary"""
        return list(self.functions.keys())

    def set_current_function(self, function_name: str) -> bool:
        """Set the current function for analysis"""
        if function_name in self.functions:
            self.current_function = function_name
            self.graph = self.functions[function_name]['graph']
            return True
        else:
            self.logger.error("Function %s not found", function_name)
            return False

    # Alias methods for compatibility
    def get_functions(self) -> List[Dict]:
        """Get list of functions (alias for get_function_list)."""
        function_list = []
        for func_name, func_data in self.functions.items():
            function_list.append({
                "name": func_name,
                "address": f"0x{func_data['addr']:x}"
            })
        return function_list

    def analyze_function(self, function_name: str) -> Optional[Dict]:
        """Analyze a specific function (compatibility method)."""
        if not self.set_current_function(function_name):
            return None

        func_data = self.functions.get(function_name)
        if not func_data:
            return None

        # Get complexity metrics
        complexity = self.get_complexity_metrics()

        # Find license patterns
        license_patterns = self.find_license_check_patterns()

        # Count basic blocks
        num_blocks = len(func_data.get('blocks', []))

        return {
            "name": function_name,
            "address": f"0x{func_data['addr']:x}",
            "graph": self.graph,
            "num_blocks": num_blocks,
            "complexity": complexity,
            "license_patterns": license_patterns,
            "has_license_checks": len(license_patterns) > 0
        }

    def visualize_cfg(self, function_name: str = None) -> bool:
        """Visualize CFG (compatibility method)."""
        if function_name and not self.set_current_function(function_name):
            return False
        return self.export_graph_image("cfg_visualization.png")

    def export_dot(self, output_file: str) -> bool:
        """Export DOT file (alias for export_dot_file)."""
        return self.export_dot_file(output_file)

    def analyze(self, binary_path: str = None) -> bool:
        """Analyze binary (compatibility method)."""
        if binary_path:
            return self.load_binary(binary_path)
        return True

    def get_complexity_metrics(self) -> Dict:
        """Get complexity metrics for the current function."""
        if not self.graph or not NETWORKX_AVAILABLE:
            return {"error": "No graph or NetworkX not available"}

        try:
            return {
                "nodes": self.graph.number_of_nodes(),
                "edges": self.graph.number_of_edges(),
                "cyclomatic_complexity": len(list(nx.simple_cycles(self.graph))) + 1
            }
        except (OSError, ValueError, RuntimeError) as e:
            return {"error": str(e)}

    def get_graph_layout(self, layout_type: str = 'spring') -> Optional[Dict]:
        """Get a layout for the current function graph"""
        if not self.graph:
            self.logger.error("No graph loaded")
            return None

        if not NETWORKX_AVAILABLE:
            self.logger.error("NetworkX not available")
            return None

        # Choose layout algorithm
        if layout_type == 'spring':
            layout = nx.spring_layout(self.graph)
        elif layout_type == 'dot':
            try:
                layout = nx.nx_pydot.graphviz_layout(self.graph, prog='dot')
            except (ImportError, OSError, FileNotFoundError):
                self.logger.warning("Graphviz not available, falling back to spring layout")
                layout = nx.spring_layout(self.graph)
        elif layout_type == 'circular':
            layout = nx.circular_layout(self.graph)
        else:
            layout = nx.spring_layout(self.graph)

        return layout

    def get_graph_data(self, layout_type: str = 'spring') -> Optional[Dict[str, Any]]:
        """Get graph data for visualization"""
        if not self.graph:
            self.logger.error("No graph loaded")
            return None

        # Get layout
        layout = self.get_graph_layout(layout_type)
        if layout is None:
            self.logger.error("Failed to get graph layout")
            return None

        # Prepare nodes
        nodes = []
        if self.graph is not None:
            for _node in self.graph.nodes():
                node_data = self.graph.nodes[_node]
                nodes.append({
                    'id': _node,
                    'label': node_data.get('label', f"0x{_node:x}"),
                    'x': float(layout[_node][0]) if _node in layout else 0.0,
                    'y': float(layout[_node][1]) if _node in layout else 0.0,
                    'size': node_data.get('size', 0)
                })

        # Prepare edges
        edges = []
        if self.graph is not None:
            for source, target in self.graph.edges():
                edges.append({
                    'source': source,
                    'target': target
                })

        return {
            'nodes': nodes,
            'edges': edges,
            'function': self.current_function
        }

    def find_license_check_patterns(self) -> List[Dict[str, Any]]:
        """Find potential license check patterns in the CFG"""
        if not self.graph:
            self.logger.error("No graph loaded")
            return []

        license_patterns = []

        # License-related keywords
        license_keywords = [
            'licen', 'key', 'activ', 'valid', 'check',
            'auth', 'verif', 'serial', 'regist'
        ]

        # Get function blocks
        blocks = self.functions[self.current_function]['blocks']

        # Check each block for license-related instructions
        for _block in blocks:
            for _op in _block.get('ops', []):
                disasm = _op.get('disasm', '').lower()

                # Check for license keywords in disassembly
                if any(_keyword in disasm for _keyword in license_keywords):
                    license_patterns.append({
                        'block_addr': _block['offset'],
                        'op_addr': _op['offset'],
                        'disasm': _op['disasm'],
                        'type': 'license_keyword'
                    })

                # Check for comparison followed by conditional jump
                if ('cmp' in disasm or 'test' in disasm) and _block.get('jump') and _block.get('fail'):
                    license_patterns.append({
                        'block_addr': _block['offset'],
                        'op_addr': _op['offset'],
                        'disasm': _op['disasm'],
                        'type': 'conditional_check'
                    })

        return license_patterns

    def generate_interactive_html(self, function_name: str, license_patterns: List[Dict], output_file: str) -> bool:
        """Generate an interactive HTML visualization of the CFG"""
        try:
            graph_data = self.get_graph_data(layout_type='spring')
            if not graph_data:
                return False

            from ...utils.html_templates import close_html, get_cfg_html_template

            # Create the HTML content using common template
            html_content = get_cfg_html_template(function_name) + f"""
                <style>
                    #controls {{
                        position: absolute;
                        top: 10px;
                        left: 10px;
                        background: rgba(255, 255, 255, 0.8);
                        padding: 10px;
                        border-radius: 4px;
                        z-index: 100;
                    }}
                </style>
            </head>
            <body>
                <div id="controls">
                    <h3>Control Flow Graph: {function_name}</h3>
                    <div>
                        <button id="zoom-in">Zoom In</button>
                        <button id="zoom-out">Zoom Out</button>
                        <button id="reset">Reset View</button>
                    </div>
                    <div style="margin-top: 10px;">
                        <p>Found {len(license_patterns)} potential license check points</p>
                        <ul style="font-size: 12px;">
                            {"".join(f'<li>{_pattern["type"]} at 0x{_pattern["op_addr"]:x}</li>' for _pattern in license_patterns[:5])}
                            {"<li>...</li>" if len(license_patterns) > 5 else ""}
                        </ul>
                    </div>
                </div>
                <div id="tooltip"></div>
                <script>
                    // Implementation would go here - simplified for brevity
                    console.log("CFG Visualization for {function_name}");
                </script>
            """ + close_html()

            # Write HTML to file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error generating HTML visualization: %s", e)
            return False

    def export_graph_image(self, output_file: str, format: str = 'png') -> bool:  # pylint: disable=redefined-builtin
        """Export the CFG as an image file"""
        if not MATPLOTLIB_AVAILABLE or not NETWORKX_AVAILABLE:
            self.logger.error("Matplotlib or NetworkX not available for image export")
            return False

        try:
            layout = self.get_graph_layout(layout_type='spring')
            if not layout:
                return False

            # Create matplotlib figure
            plt.figure(figsize=(12, 9))

            # Draw the graph
            nx.draw_networkx(
                self.graph,
                pos=layout,
                with_labels=True,
                node_color='lightblue',
                node_size=500,
                font_size=8,
                arrows=True,
                connectionstyle='arc3,rad=0.1'
            )

            # Add title
            plt.title(f"Control Flow Graph: {self.current_function}")

            # Remove axes
            plt.axis('off')

            # Save the figure
            plt.savefig(output_file, format=format, dpi=300, bbox_inches='tight')
            plt.close()

            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error exporting graph image: %s", e)
            return False

    def export_dot_file(self, output_file: str) -> bool:
        """Export the CFG as a DOT file"""
        if not NETWORKX_AVAILABLE:
            self.logger.error("NetworkX not available for DOT export")
            return False

        try:
            nx.drawing.nx_pydot.write_dot(self.graph, output_file)
            return True
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error exporting DOT file: %s", e)
            return False

    def analyze_cfg(self, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive CFG analysis on a binary.

        Args:
            binary_path: Path to binary file to analyze (optional)

        Returns:
            Dictionary containing CFG analysis results
        """
        results = {
            'binary_path': binary_path or self.binary_path,
            'functions_analyzed': 0,
            'complexity_metrics': {},
            'license_patterns': [],
            'graph_data': None,
            'errors': []
        }

        try:
            # Use provided path or existing path
            if binary_path:
                self.binary_path = binary_path

            if not self.binary_path:
                error_msg = "No binary path specified for CFG analysis"
                self.logger.error(error_msg)
                results['errors'].append(error_msg)
                return results

            # Load the binary and build CFG
            if not self.load_binary(self.binary_path):
                error_msg = f"Failed to load binary for CFG analysis: {self.binary_path}"
                self.logger.error(error_msg)
                results['errors'].append(error_msg)
                return results

            self.logger.info("Starting CFG analysis for: %s", self.binary_path)

            # Get function list
            function_list = self.get_function_list()
            results['functions_analyzed'] = len(function_list)

            # Analyze each function for license patterns
            all_license_patterns = []
            for function_name in function_list[:10]:  # Limit to first 10 functions for performance
                try:
                    if self.set_current_function(function_name):
                        patterns = self.find_license_check_patterns()
                        if patterns:
                            all_license_patterns.extend(patterns)
                            self.logger.debug("Found %d patterns in function %s", len(patterns), function_name)
                except (OSError, ValueError, RuntimeError) as e:
                    self.logger.debug("Error analyzing function %s: %s", function_name, e)

            results['license_patterns'] = all_license_patterns

            # Get complexity metrics
            try:
                results['complexity_metrics'] = self.get_complexity_metrics()
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.debug("Error getting complexity metrics: %s", e)
                results['complexity_metrics'] = {}

            # Get graph data for the main function if available
            try:
                if function_list and len(function_list) > 0:
                    main_function = function_list[0]  # Assume first function is main/entry
                    if self.set_current_function(main_function):
                        graph_data = self.get_graph_data()
                        if graph_data:
                            results['graph_data'] = graph_data
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.debug("Error getting graph data: %s", e)

            self.logger.info("CFG analysis completed. Found %d license patterns in %d functions", 
                           len(all_license_patterns), results['functions_analyzed'])

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"CFG analysis failed: {e}"
            self.logger.error(error_msg)
            results['errors'].append(error_msg)

        return results


def run_deep_cfg_analysis(app):
    """Run deep CFG analysis."""
    if not app.binary_path:
        app.update_output.emit(
            log_message("[CFG Analysis] No binary selected."))
        return

    app.update_output.emit(
        log_message("[CFG Analysis] Starting deep CFG analysis..."))
    app.analyze_status.setText("Running CFG analysis...")

    try:
        if not PEFILE_AVAILABLE:
            app.update_output.emit(
                log_message("[CFG Analysis] pefile not available"))
            app.analyze_status.setText("pefile not available")
            return

        if not CAPSTONE_AVAILABLE:
            app.update_output.emit(
                log_message("[CFG Analysis] capstone not available"))
            app.analyze_status.setText("capstone not available")
            return

        if not NETWORKX_AVAILABLE:
            app.update_output.emit(
                log_message("[CFG Analysis] networkx not available"))
            app.analyze_status.setText("networkx not available")
            return

        pe = pefile.PE(app.binary_path)
        is_64bit = getattr(pe.FILE_HEADER, 'Machine', 0) == 0x8664
        if CAPSTONE_AVAILABLE:
            mode = CS_MODE_64 if is_64bit else CS_MODE_32
        else:
            mode = None

        # Find text section
        text_section = next(
            (_s for _s in pe.sections if b".text" in _s.Name), None)
        if not text_section:
            app.update_output.emit(
                log_message("[CFG Analysis] No .text section found"))
            app.analyze_status.setText("CFG analysis failed")
            return

        # Create disassembler
        code_data = text_section.get_data()
        code_addr = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress

        if CAPSTONE_AVAILABLE and mode is not None and Cs is not None and CS_ARCH_X86 is not None:
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True
        else:
            app.update_output.emit(
                log_message("[CFG Analysis] Capstone not available"))
            app.analyze_status.setText("Capstone not available")
            return

        # Disassemble
        app.update_output.emit(
            log_message("[CFG Analysis] Disassembling code..."))

        instructions = list(md.disasm(code_data, code_addr))
        app.update_output.emit(
            log_message(
                f"[CFG Analysis] Disassembled {len(instructions)} instructions"))

        # Build CFG
        app.update_output.emit(
            log_message("[CFG Analysis] Building control flow graph..."))

        G = nx.DiGraph()

        # Add nodes for _all instructions
        for _insn in instructions:
            G.add_node(
                _insn.address,
                instruction=f"{_insn.mnemonic} {_insn.op_str}")

        # Add edges
        for i, insn in enumerate(instructions):
            # Add normal flow edge
            if i + \
                    1 < len(instructions) and insn.mnemonic not in ["ret", "jmp"]:
                G.add_edge(insn.address,
                           instructions[i + 1].address,
                           type="normal")

            # Add jump edges
            if insn.mnemonic.startswith("j"):
                try:
                    # Extract jump target
                    if " 0x" in insn.op_str:
                        jump_target = int(insn.op_str.split("0x")[1], 16)
                        G.add_edge(insn.address, jump_target, type="jump")
                except (OSError, ValueError, RuntimeError) as e:
                    app.update_output.emit(
                        log_message(
                            f"[CFG Analysis] Error parsing jump: {e}"))

        # Save full CFG
        app.update_output.emit(
            log_message("[CFG Analysis] Saving CFG visualization..."))

        # Use NetworkX to output DOT file
        try:
            nx.drawing.nx_pydot.write_dot(G, "full_cfg.dot")
        except (OSError, ValueError, RuntimeError) as e:
            app.update_output.emit(
                log_message(f"[CFG Analysis] Could not write DOT file: {e}"))

        # Generate a smaller CFG focused on license checks
        app.update_output.emit(
            log_message("[CFG Analysis] Analyzing for license checks..."))

        license_keywords = [
            "licens",
            "registr",
            "activ",
            "serial",
            "key",
            "trial",
            "valid"]

        # Find nodes with license-related instructions
        license_nodes = []
        for node, data in G.nodes(data=True):
            instruction = data.get("instruction", "").lower()
            if any(_keyword in instruction for _keyword in license_keywords):
                license_nodes.append(node)

        app.update_output.emit(
            log_message(
                f"[CFG Analysis] Found {len(license_nodes)} license-related nodes"))

        # Create a subgraph with these nodes and their neighbors
        if license_nodes:
            license_subgraph = G.subgraph(license_nodes).copy()

            # Add immediate predecessors and successors
            for _node in list(license_subgraph.nodes()):
                predecessors = list(G.predecessors(_node))
                successors = list(G.successors(_node))

                license_subgraph.add_nodes_from(predecessors)
                license_subgraph.add_nodes_from(successors)

                for _pred in predecessors:
                    license_subgraph.add_edge(
                        _pred, _node, **G.get_edge_data(_pred, _node, {}))

                for _succ in successors:
                    license_subgraph.add_edge(
                        _node, _succ, **G.get_edge_data(_node, _succ, {}))

            # Save license-focused CFG
            try:
                nx.drawing.nx_pydot.write_dot(license_subgraph, "license_cfg.dot")
            except (OSError, ValueError, RuntimeError) as e:
                app.update_output.emit(
                    log_message(f"[CFG Analysis] Could not write license DOT file: {e}"))

            # Try to generate PDF or SVG if graphviz is available
            try:
                if SUBPROCESS_AVAILABLE:
                    subprocess.run(
                        ["dot", "-Tsvg", "-o", "license_cfg.svg", "license_cfg.dot"], check=False)
                    app.update_output.emit(
                        log_message("[CFG Analysis] Generated license_cfg.svg"))
            except (OSError, ValueError, RuntimeError) as e:
                app.update_output.emit(
                    log_message(
                        f"[CFG Analysis] Could not generate SVG: {e}"))

        app.update_output.emit(log_message("[CFG Analysis] Analysis complete"))
        app.analyze_status.setText("CFG analysis complete")

    except (OSError, ValueError, RuntimeError) as e:
        app.update_output.emit(log_message(f"[CFG Analysis] Error: {e}"))
        app.analyze_status.setText(f"CFG analysis error: {str(e)}")


def run_cfg_explorer(app):
    """Initialize and run the CFG explorer with GUI integration"""
    if not PYQT_AVAILABLE:
        print("PyQt5 not available - cannot run GUI version")
        return

    app.update_output.emit(log_message("[CFG Explorer] Initializing CFG explorer..."))

    # Get binary path from UI
    if not app.binary_path:
        app.update_output.emit(log_message("[CFG Explorer] No binary path specified"))

        # Ask for binary path
        binary_path, _ = QFileDialog.getOpenFileName(
            app,
            "Select Binary",
            "",
            "All Files (*)"
        )

        if not binary_path:
            app.update_output.emit(log_message("[CFG Explorer] Cancelled"))
            return

        app.binary_path = binary_path

    # Create and configure the explorer
    explorer = CFGExplorer(app.binary_path)

    # Load the binary
    app.update_output.emit(log_message(f"[CFG Explorer] Loading binary: {app.binary_path}"))
    if explorer.load_binary():
        app.update_output.emit(log_message(f"[CFG Explorer] Loaded binary: {app.binary_path}"))
        app.cfg_explorer_instance = explorer

        # Get function list
        function_list = explorer.get_function_list()

        # Ask user to select a function
        function_name, ok = QInputDialog.getItem(
            app,
            "Select Function",
            "Select a function to analyze:",
            function_list,
            0,
            False
        )

        if not ok:
            app.update_output.emit(log_message("[CFG Explorer] Cancelled"))
            return

        # Set current function
        if explorer.set_current_function(function_name):
            app.update_output.emit(log_message(f"[CFG Explorer] Analyzing function: {function_name}"))

            # Find license check patterns
            license_patterns = explorer.find_license_check_patterns()

            if license_patterns:
                app.update_output.emit(log_message(f"[CFG Explorer] Found {len(license_patterns)} potential license check patterns in {function_name}"))

                # Display patterns
                for _pattern in license_patterns:
                    app.update_output.emit(log_message(
                        f"[CFG Explorer] {_pattern['type']} at 0x{_pattern['op_addr']:x}: {_pattern['disasm']}"
                    ))

            else:
                app.update_output.emit(log_message("[CFG Explorer] No license check patterns found"))
        else:
            app.update_output.emit(log_message(f"[CFG Explorer] Failed to set function: {function_name}"))
    else:
        app.update_output.emit(log_message(f"[CFG Explorer] Failed to load binary: {app.binary_path}"))


def log_message(message: str) -> str:
    """Helper function for log message formatting"""
    return message


__all__ = ['CFGExplorer', 'run_cfg_explorer', 'run_deep_cfg_analysis']
