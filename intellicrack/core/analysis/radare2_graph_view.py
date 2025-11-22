"""Radare2 Graph View Module.

This module provides graph visualization capabilities for radare2 analysis,
including control flow graphs, call graphs, and dependency graphs.

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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any


try:
    import r2pipe
except ImportError:
    r2pipe = None

try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    nx = None
    NETWORKX_AVAILABLE = False

try:
    import matplotlib.patches as mpatches
    import matplotlib.pyplot as plt

    MATPLOTLIB_AVAILABLE = True
except ImportError:
    plt = None
    mpatches = None
    MATPLOTLIB_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    """Represents a node in a graph."""

    id: str
    label: str
    type: str  # 'function', 'basic_block', 'import', 'string'
    address: int | None = None
    size: int | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    x: float | None = None
    y: float | None = None
    color: str = "#4A90E2"


@dataclass
class GraphEdge:
    """Represents an edge in a graph."""

    source: str
    target: str
    type: str  # 'call', 'jump', 'conditional', 'reference'
    label: str | None = None
    weight: float = 1.0
    color: str = "#666666"
    style: str = "solid"  # 'solid', 'dashed', 'dotted'


@dataclass
class GraphData:
    """Container for graph data."""

    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class R2GraphGenerator:
    """Generate various graph representations from radare2 analysis."""

    def __init__(self, binary_path: str) -> None:
        """Initialize graph generator.

        Args:
            binary_path: Path to the binary file

        """
        self.binary_path = binary_path
        self.logger = logger
        self.r2 = None

        if r2pipe is None:
            self.logger.warning("r2pipe not available, graph generation limited")
            self.r2pipe_available = False
        else:
            self.r2pipe_available = True
            self._initialize_r2()

    def _initialize_r2(self) -> None:
        """Initialize r2pipe session."""
        if not self.r2pipe_available:
            return

        try:
            self.r2 = r2pipe.open(self.binary_path)
            self.r2.cmd("aaa")  # Analyze all
            self.logger.info(f"Initialized r2 session for graph generation: {self.binary_path}")
        except Exception as e:
            self.logger.error(f"Failed to initialize r2 session: {e}")
            self.r2 = None

    def generate_control_flow_graph(self, function_name: str) -> GraphData:
        """Generate control flow graph for a function.

        Args:
            function_name: Name of the function

        Returns:
            GraphData containing CFG

        """
        if not self.r2:
            self.logger.error("R2 session not initialized")
            return GraphData()

        graph_data = GraphData(
            metadata={"type": "control_flow", "function": function_name, "binary": self.binary_path}
        )

        try:
            # Seek to function
            self.r2.cmd(f"s {function_name}")

            # Get basic blocks
            blocks = json.loads(self.r2.cmd("afbj") or "[]")

            # Create nodes for each basic block
            for block in blocks:
                addr = block.get("addr", 0)
                size = block.get("size", 0)
                ninstr = block.get("ninstr", 0)

                node = GraphNode(
                    id=f"bb_{hex(addr)}",
                    label=f"BB @ {hex(addr)}\n{ninstr} instructions\n{size} bytes",
                    type="basic_block",
                    address=addr,
                    size=size,
                    attributes={
                        "ninstr": ninstr,
                        "traced": block.get("traced", False),
                        "colorize": block.get("colorize", 0),
                    },
                )

                # Set color based on block type
                if block.get("fail", 0) > 0:
                    node.color = "#E74C3C"  # Red for conditional
                elif block.get("switch", []):
                    node.color = "#F39C12"  # Orange for switch
                else:
                    node.color = "#2ECC71"  # Green for sequential

                graph_data.nodes.append(node)

            # Create edges for control flow
            for block in blocks:
                addr = block.get("addr", 0)
                source_id = f"bb_{hex(addr)}"

                # Jump edge
                if block.get("jump", 0) > 0:
                    target_id = f"bb_{hex(block['jump'])}"
                    edge = GraphEdge(
                        source=source_id,
                        target=target_id,
                        type="jump",
                        label="jmp",
                        color="#2ECC71",
                        style="solid",
                    )
                    graph_data.edges.append(edge)

                # Fail edge (conditional)
                if block.get("fail", 0) > 0:
                    target_id = f"bb_{hex(block['fail'])}"
                    edge = GraphEdge(
                        source=source_id,
                        target=target_id,
                        type="conditional",
                        label="fail",
                        color="#E74C3C",
                        style="dashed",
                    )
                    graph_data.edges.append(edge)

                # Switch cases
                for case in block.get("switch", []):
                    target_id = f"bb_{hex(case.get('addr', 0))}"
                    edge = GraphEdge(
                        source=source_id,
                        target=target_id,
                        type="switch",
                        label=f"case {case.get('val', '')}",
                        color="#F39C12",
                        style="dotted",
                    )
                    graph_data.edges.append(edge)

            self.logger.info(
                f"Generated CFG with {len(graph_data.nodes)} blocks and {len(graph_data.edges)} edges for {function_name}"
            )

        except Exception as e:
            self.logger.error(f"Failed to generate CFG: {e}")

        return graph_data

    def generate_call_graph(self, max_depth: int = 3) -> GraphData:
        """Generate function call graph.

        Args:
            max_depth: Maximum depth for call graph traversal

        Returns:
            GraphData containing call graph

        """
        if not self.r2:
            self.logger.error("R2 session not initialized")
            return GraphData()

        graph_data = GraphData(
            metadata={"type": "call_graph", "max_depth": max_depth, "binary": self.binary_path}
        )

        try:
            # Get all functions
            functions = json.loads(self.r2.cmd("aflj") or "[]")

            # Create nodes for functions
            for func in functions:
                name = func.get("name", "")
                addr = func.get("offset", 0)
                size = func.get("size", 0)

                node = GraphNode(
                    id=name,
                    label=f"{name}\n@ {hex(addr)}\n{size} bytes",
                    type="function",
                    address=addr,
                    size=size,
                    attributes={
                        "nargs": func.get("nargs", 0),
                        "nlocals": func.get("nlocals", 0),
                        "cc": func.get("cc", ""),
                        "cost": func.get("cost", 0),
                    },
                )

                # Color based on function type
                if "main" in name:
                    node.color = "#E74C3C"  # Red for main
                elif name.startswith("sym.imp."):
                    node.color = "#3498DB"  # Blue for imports
                elif name.startswith("sub."):
                    node.color = "#95A5A6"  # Gray for subs
                else:
                    node.color = "#2ECC71"  # Green for regular

                graph_data.nodes.append(node)

            # Create edges for function calls
            for func in functions:
                name = func.get("name", "")

                # Get cross-references (calls from this function)
                self.r2.cmd(f"s {func.get('offset', 0)}")
                calls = json.loads(self.r2.cmd("afxj") or "[]")

                for call in calls:
                    if call.get("type", "") == "call":
                        if target := call.get("ref", ""):
                            edge = GraphEdge(
                                source=name,
                                target=target,
                                type="call",
                                color="#34495E",
                                style="solid",
                            )
                            graph_data.edges.append(edge)

            self.logger.info(
                f"Generated call graph with {len(graph_data.nodes)} functions and {len(graph_data.edges)} calls"
            )

        except Exception as e:
            self.logger.error(f"Failed to generate call graph: {e}")

        return graph_data

    def generate_xref_graph(self, address: int) -> GraphData:
        """Generate cross-reference graph for a specific address.

        Args:
            address: Address to analyze

        Returns:
            GraphData containing xref graph

        """
        if not self.r2:
            self.logger.error("R2 session not initialized")
            return GraphData()

        graph_data = GraphData(
            metadata={"type": "xref_graph", "address": address, "binary": self.binary_path}
        )

        try:
            # Create central node
            central_node = GraphNode(
                id=f"addr_{hex(address)}",
                label=f"Address\n{hex(address)}",
                type="address",
                address=address,
                color="#E74C3C",
            )
            graph_data.nodes.append(central_node)

            # Get cross-references to this address
            self.r2.cmd(f"s {address}")
            xrefs_to = json.loads(self.r2.cmd("axtj") or "[]")

            for xref in xrefs_to:
                from_addr = xref.get("from", 0)
                xref_type = xref.get("type", "")
                func_name = xref.get("fcn_name", f"sub_{hex(from_addr)}")

                node_id = f"from_{hex(from_addr)}"
                if all(n.id != node_id for n in graph_data.nodes):
                    node = GraphNode(
                        id=node_id,
                        label=f"{func_name}\n@ {hex(from_addr)}",
                        type="reference_from",
                        address=from_addr,
                        color="#3498DB",
                    )
                    graph_data.nodes.append(node)

                edge = GraphEdge(
                    source=node_id,
                    target=central_node.id,
                    type=xref_type,
                    label=xref_type,
                    color="#3498DB",
                    style="dashed",
                )
                graph_data.edges.append(edge)

            # Get cross-references from this address
            xrefs_from = json.loads(self.r2.cmd("axfj") or "[]")

            for xref in xrefs_from:
                to_addr = xref.get("to", 0)
                xref_type = xref.get("type", "")

                node_id = f"to_{hex(to_addr)}"
                if all(n.id != node_id for n in graph_data.nodes):
                    node = GraphNode(
                        id=node_id,
                        label=f"Target\n@ {hex(to_addr)}",
                        type="reference_to",
                        address=to_addr,
                        color="#2ECC71",
                    )
                    graph_data.nodes.append(node)

                edge = GraphEdge(
                    source=central_node.id,
                    target=node_id,
                    type=xref_type,
                    label=xref_type,
                    color="#2ECC71",
                    style="solid",
                )
                graph_data.edges.append(edge)

            self.logger.info(
                f"Generated xref graph with {len(graph_data.nodes)} nodes and {len(graph_data.edges)} references"
            )

        except Exception as e:
            self.logger.error(f"Failed to generate xref graph: {e}")

        return graph_data

    def generate_import_dependency_graph(self) -> GraphData:
        """Generate import dependency graph.

        Returns:
            GraphData containing import dependencies

        """
        if not self.r2:
            self.logger.error("R2 session not initialized")
            return GraphData()

        graph_data = GraphData(metadata={"type": "import_dependency", "binary": self.binary_path})

        try:
            # Create main binary node
            main_node = GraphNode(
                id="main_binary",
                label=os.path.basename(self.binary_path),
                type="binary",
                color="#E74C3C",
            )
            graph_data.nodes.append(main_node)

            # Get imports
            imports = json.loads(self.r2.cmd("iij") or "[]")

            # Group imports by library
            libs: dict[str, list[dict]] = {}
            for imp in imports:
                lib = imp.get("libname", "unknown")
                if lib not in libs:
                    libs[lib] = []
                libs[lib].append(imp)

            # Create nodes for libraries
            for lib, lib_imports in libs.items():
                lib_node = GraphNode(
                    id=f"lib_{lib}",
                    label=f"{lib}\n({len(lib_imports)} imports)",
                    type="library",
                    color="#3498DB",
                    attributes={"import_count": len(lib_imports)},
                )
                graph_data.nodes.append(lib_node)

                # Create edge from main to library
                edge = GraphEdge(
                    source=main_node.id,
                    target=lib_node.id,
                    type="imports",
                    label=f"{len(lib_imports)} functions",
                    weight=len(lib_imports),
                    color="#34495E",
                )
                graph_data.edges.append(edge)

                # Create nodes for important imports
                for imp in lib_imports[:10]:  # Limit to first 10 to avoid clutter
                    if func_name := imp.get("name", ""):
                        func_node = GraphNode(
                            id=f"import_{lib}_{func_name}",
                            label=func_name,
                            type="import",
                            color="#2ECC71",
                            attributes={"ordinal": imp.get("ordinal", 0)},
                        )
                        graph_data.nodes.append(func_node)

                        edge = GraphEdge(
                            source=lib_node.id,
                            target=func_node.id,
                            type="provides",
                            color="#2ECC71",
                            style="dotted",
                        )
                        graph_data.edges.append(edge)

            self.logger.info(
                f"Generated import dependency graph with {len(graph_data.nodes)} nodes"
            )

        except Exception as e:
            self.logger.error(f"Failed to generate import dependency graph: {e}")

        return graph_data

    def export_to_dot(self, graph_data: GraphData, output_path: str) -> None:
        """Export graph to DOT format.

        Args:
            graph_data: Graph data to export
            output_path: Path for output DOT file

        """
        try:
            with open(output_path, "w") as f:
                f.write("digraph G {\n")
                f.write("    rankdir=TB;\n")
                f.write("    node [shape=box];\n\n")

                # Write nodes
                for node in graph_data.nodes:
                    label = node.label.replace("\n", "\\n")
                    f.write(
                        f'    "{node.id}" [label="{label}", fillcolor="{node.color}", style=filled];\n'
                    )

                f.write("\n")

                # Write edges
                for edge in graph_data.edges:
                    style_attr = f', style="{edge.style}"' if edge.style != "solid" else ""
                    label_attr = f', label="{edge.label}"' if edge.label else ""
                    f.write(
                        f'    "{edge.source}" -> "{edge.target}" [color="{edge.color}"{style_attr}{label_attr}];\n'
                    )

                f.write("}\n")

            self.logger.info(f"Exported graph to DOT format: {output_path}")

        except Exception as e:
            self.logger.error(f"Failed to export to DOT: {e}")

    def visualize_graph(
        self, graph_data: GraphData, output_path: str | None = None, layout: str = "spring"
    ) -> bool:
        """Visualize graph using matplotlib/networkx.

        Args:
            graph_data: Graph data to visualize
            output_path: Optional path to save image
            layout: Layout algorithm ('spring', 'circular', 'shell', 'kamada_kawai')

        Returns:
            True if successful

        """
        if not NETWORKX_AVAILABLE or not MATPLOTLIB_AVAILABLE:
            self.logger.error("NetworkX or Matplotlib not available for visualization")
            return False

        try:
            # Create NetworkX graph
            G = nx.DiGraph()

            # Add nodes
            for node in graph_data.nodes:
                G.add_node(node.id, label=node.label, color=node.color, **node.attributes)

            # Add edges
            for edge in graph_data.edges:
                G.add_edge(
                    edge.source, edge.target, type=edge.type, label=edge.label, weight=edge.weight
                )

            # Calculate layout
            if layout == "spring":
                pos = nx.spring_layout(G, k=2, iterations=50)
            elif layout == "circular":
                pos = nx.circular_layout(G)
            elif layout == "shell":
                pos = nx.shell_layout(G)
            elif layout == "kamada_kawai":
                pos = nx.kamada_kawai_layout(G)
            else:
                pos = nx.spring_layout(G)

            # Create figure
            plt.figure(figsize=(12, 8))
            plt.title(
                f"{graph_data.metadata.get('type', 'Graph')} - {graph_data.metadata.get('binary', '')}"
            )

            # Draw nodes
            node_colors = [graph_data.nodes[i].color for i in range(len(graph_data.nodes))]
            nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=500, alpha=0.9)

            # Draw edges
            edge_colors = [e.color for e in graph_data.edges]
            nx.draw_networkx_edges(
                G, pos, edge_color=edge_colors, arrows=True, arrowsize=20, alpha=0.6
            )

            # Draw labels
            labels = {node.id: node.label.split("\n")[0] for node in graph_data.nodes}
            nx.draw_networkx_labels(G, pos, labels, font_size=8)

            # Add legend
            legend_elements = []
            node_types = {n.type for n in graph_data.nodes}
            for ntype in node_types:
                color = next((n.color for n in graph_data.nodes if n.type == ntype), "#000000")
                legend_elements.append(mpatches.Patch(color=color, label=ntype))

            plt.legend(handles=legend_elements, loc="upper right")

            plt.axis("off")
            plt.tight_layout()

            if output_path:
                plt.savefig(output_path, dpi=150, bbox_inches="tight")
                self.logger.info(f"Saved graph visualization to {output_path}")

            plt.show()
            return True

        except Exception as e:
            self.logger.error(f"Failed to visualize graph: {e}")
            return False

    def cleanup(self) -> None:
        """Clean up resources."""
        if self.r2:
            try:
                self.r2.quit()
            except Exception as e:
                self.logger.warning(f"Error closing r2 session: {e}")


def create_graph_generator(binary_path: str) -> R2GraphGenerator:
    """Create graph generator.

    Args:
        binary_path: Path to binary

    Returns:
        New R2GraphGenerator instance

    """
    return R2GraphGenerator(binary_path)
