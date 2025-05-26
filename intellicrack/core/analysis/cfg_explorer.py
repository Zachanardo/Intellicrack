"""
Control Flow Graph (CFG) Explorer for Binary Analysis

This module provides visual CFG analysis capabilities using radare2 and NetworkX
to help identify license validation routines and potential bypass points in binary code.
"""

import json
import logging
import os
import webbrowser
from typing import List, Dict, Any, Optional

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

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import capstone
    from capstone import *
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    
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
            # Open the binary with radare2
            r2 = r2pipe.open(self.binary_path)

            # Initialize radare2
            r2.cmd('aaa')  # Analyze all

            # Get list of functions
            functions_json = r2.cmd('aflj')
            functions = json.loads(functions_json)

            # Process functions
            for func in functions:
                function_name = func['name']
                function_addr = func['offset']

                # Get basic blocks for this function
                blocks_json = r2.cmd(f'agfj @ {function_addr}')
                blocks = json.loads(blocks_json)

                if not blocks:
                    continue

                # Create a networkx graph for this function
                function_graph = nx.DiGraph()

                # Process blocks and edges
                for block in blocks[0]['blocks']:
                    block_addr = block['offset']
                    block_size = block['size']
                    block_ops = block.get('ops', [])

                    # Add node to graph
                    function_graph.add_node(
                        block_addr,
                        size=block_size,
                        ops=block_ops,
                        label=f"0x{block_addr:x}"
                    )

                    # Add edges
                    for jump in block.get('jump', []):
                        function_graph.add_edge(block_addr, jump)

                    if 'fail' in block and block['fail'] != 0:
                        function_graph.add_edge(block_addr, block['fail'])

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

        except Exception as e:
            self.logger.error(f"Error loading binary: {e}")
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
            self.logger.error(f"Function {function_name} not found")
            return False

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
            except:
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
            for node in self.graph.nodes():
                node_data = self.graph.nodes[node]
                nodes.append({
                    'id': node,
                    'label': node_data.get('label', f"0x{node:x}"),
                    'x': float(layout[node][0]) if node in layout else 0.0,
                    'y': float(layout[node][1]) if node in layout else 0.0,
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
        for block in blocks:
            for op in block.get('ops', []):
                disasm = op.get('disasm', '').lower()

                # Check for license keywords in disassembly
                if any(keyword in disasm for keyword in license_keywords):
                    license_patterns.append({
                        'block_addr': block['offset'],
                        'op_addr': op['offset'],
                        'disasm': op['disasm'],
                        'type': 'license_keyword'
                    })

                # Check for comparison followed by conditional jump
                if ('cmp' in disasm or 'test' in disasm) and block.get('jump') and block.get('fail'):
                    license_patterns.append({
                        'block_addr': block['offset'],
                        'op_addr': op['offset'],
                        'disasm': op['disasm'],
                        'type': 'conditional_check'
                    })

        return license_patterns

    def generate_interactive_html(self, function_name: str, license_patterns: List[Dict], output_file: str) -> bool:
        """Generate an interactive HTML visualization of the CFG"""
        try:
            graph_data = self.get_graph_data(layout_type='spring')
            if not graph_data:
                return False

            # Create the HTML content
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>CFG: {function_name}</title>
                <script src="https://d3js.org/d3.v7.min.js"></script>
                <style>
                    body {{ margin: 0; font-family: Arial, sans-serif; overflow: hidden; }}
                    .node {{ stroke: #fff; stroke-width: 1.5px; }}
                    .node.license {{ fill: #ff7777; }}
                    .node.normal {{ fill: #77aaff; }}
                    .link {{ stroke: #999; stroke-opacity: 0.6; stroke-width: 1px; }}
                    .label {{ font-size: 10px; pointer-events: none; }}
                    #tooltip {{
                        position: absolute;
                        background: rgba(0, 0, 0, 0.7);
                        color: white;
                        padding: 5px;
                        border-radius: 4px;
                        font-size: 12px;
                        pointer-events: none;
                        opacity: 0;
                    }}
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
                            {"".join(f'<li>{pattern["type"]} at 0x{pattern["op_addr"]:x}</li>' for pattern in license_patterns[:5])}
                            {"<li>...</li>" if len(license_patterns) > 5 else ""}
                        </ul>
                    </div>
                </div>
                <div id="tooltip"></div>
                <script>
                    // Implementation would go here - simplified for brevity
                    console.log("CFG Visualization for {function_name}");
                </script>
            </body>
            </html>
            """

            # Write HTML to file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            return True

        except Exception as e:
            self.logger.error(f"Error generating HTML visualization: {e}")
            return False

    def export_graph_image(self, output_file: str, format: str = 'png') -> bool:
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

        except Exception as e:
            self.logger.error(f"Error exporting graph image: {e}")
            return False

    def export_dot_file(self, output_file: str) -> bool:
        """Export the CFG as a DOT file"""
        if not NETWORKX_AVAILABLE:
            self.logger.error("NetworkX not available for DOT export")
            return False

        try:
            nx.drawing.nx_pydot.write_dot(self.graph, output_file)
            return True
        except Exception as e:
            self.logger.error(f"Error exporting DOT file: {e}")
            return False


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
        is_64bit = pe.FILE_HEADER.Machine == 0x8664
        mode = CS_MODE_64 if is_64bit else CS_MODE_32

        # Find text section
        text_section = next(
            (s for s in pe.sections if b".text" in s.Name), None)
        if not text_section:
            app.update_output.emit(
                log_message("[CFG Analysis] No .text section found"))
            app.analyze_status.setText("CFG analysis failed")
            return

        # Create disassembler
        code_data = text_section.get_data()
        code_addr = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress

        md = Cs(CS_ARCH_X86, mode)
        md.detail = True

        # Disassemble
        app.update_output.emit(
            log_message("[CFG Analysis] Disassembling code..."))

        instructions = list(md.disasm(code_data, code_addr))
        app.update_output.emit(
            log_message(
                f"[CFG Analysis] Disassembled {
                    len(instructions)} instructions"))

        # Build CFG
        app.update_output.emit(
            log_message("[CFG Analysis] Building control flow graph..."))

        G = nx.DiGraph()

        # Add nodes for all instructions
        for insn in instructions:
            G.add_node(
                insn.address,
                instruction=f"{
                    insn.mnemonic} {
                    insn.op_str}")

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
                except Exception as e:
                    app.update_output.emit(
                        log_message(
                            f"[CFG Analysis] Error parsing jump: {e}"))

        # Save full CFG
        app.update_output.emit(
            log_message("[CFG Analysis] Saving CFG visualization..."))

        # Use NetworkX to output DOT file
        try:
            nx.drawing.nx_pydot.write_dot(G, "full_cfg.dot")
        except Exception as e:
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
            if any(keyword in instruction for keyword in license_keywords):
                license_nodes.append(node)

        app.update_output.emit(
            log_message(
                f"[CFG Analysis] Found {
                    len(license_nodes)} license-related nodes"))

        # Create a subgraph with these nodes and their neighbors
        if license_nodes:
            license_subgraph = G.subgraph(license_nodes).copy()

            # Add immediate predecessors and successors
            for node in list(license_subgraph.nodes()):
                predecessors = list(G.predecessors(node))
                successors = list(G.successors(node))

                license_subgraph.add_nodes_from(predecessors)
                license_subgraph.add_nodes_from(successors)

                for pred in predecessors:
                    license_subgraph.add_edge(
                        pred, node, **G.get_edge_data(pred, node, {}))

                for succ in successors:
                    license_subgraph.add_edge(
                        node, succ, **G.get_edge_data(node, succ, {}))

            # Save license-focused CFG
            try:
                nx.drawing.nx_pydot.write_dot(license_subgraph, "license_cfg.dot")
            except Exception as e:
                app.update_output.emit(
                    log_message(f"[CFG Analysis] Could not write license DOT file: {e}"))

            # Try to generate PDF or SVG if graphviz is available
            try:
                if SUBPROCESS_AVAILABLE:
                    subprocess.run(
                        ["dot", "-Tsvg", "-o", "license_cfg.svg", "license_cfg.dot"])
                    app.update_output.emit(
                        log_message("[CFG Analysis] Generated license_cfg.svg"))
            except Exception as e:
                app.update_output.emit(
                    log_message(
                        f"[CFG Analysis] Could not generate SVG: {e}"))

        app.update_output.emit(log_message("[CFG Analysis] Analysis complete"))
        app.analyze_status.setText("CFG analysis complete")

    except Exception as e:
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
                for pattern in license_patterns:
                    app.update_output.emit(log_message(
                        f"[CFG Explorer] {pattern['type']} at 0x{pattern['op_addr']:x}: {pattern['disasm']}"
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


__all__ = ['CFGExplorer', 'run_cfg_explorer']
