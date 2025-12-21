"""Control Flow Graph (CFG) exploration and analysis module for binary analysis.

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

from __future__ import annotations

import json
import logging
import os
import sys
import time
import traceback
from collections.abc import Collection, Sequence
from typing import TYPE_CHECKING, Any

from intellicrack.utils.logger import logger


if TYPE_CHECKING:
    from types import ModuleType

from ...utils.tools.radare2_utils import R2Exception, r2_session
from .radare2_ai_integration import R2AIEngine
from .radare2_decompiler import R2DecompilationEngine
from .radare2_imports import R2ImportExportAnalyzer
from .radare2_scripting import R2ScriptingEngine
from .radare2_strings import R2StringAnalyzer
from .radare2_vulnerability_engine import R2VulnerabilityEngine


logger.debug("Importing radare2_decompiler...")

logger.debug("radare2_decompiler imported OK")

logger.debug("Importing radare2_imports...")

logger.debug("radare2_imports imported OK")

logger.debug("Importing radare2_scripting...")

logger.debug("radare2_scripting imported OK")

logger.debug("Importing radare2_strings...")

logger.debug("radare2_strings imported OK")

logger.debug("Importing radare2_vulnerability_engine...")

logger.debug("radare2_vulnerability_engine imported OK")

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""


np: Any
try:
    from intellicrack.handlers.numpy_handler import (
        HAS_NUMPY as NUMPY_AVAILABLE,
        numpy as np,
    )
except ImportError as e:
    logger.exception("Import error in cfg_explorer: %s", e)
    np = None
    NUMPY_AVAILABLE = False

# Optional dependencies - graceful fallback if not available
# r2pipe is handled through r2_session in radare2_utils

try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError as e:
    logger.warning("NetworkX not available, using built-in graph implementation: %s", e)
    NETWORKX_AVAILABLE = False

    # Real NetworkX-compatible implementation for graph analysis
    class _IntellicrackNetworkX:
        """Production NetworkX-compatible graph implementation for Intellicrack."""

        class DiGraph:
            """Directed graph implementation with NetworkX-compatible interface."""

            def __init__(self, data: dict[str, object] | None = None) -> None:
                """Initialize directed graph.

                Args:
                    data: Optional dictionary containing graph data for initialization

                """
                self._nodes: dict[object, bool] = {}
                self._edges: dict[object, set[object]] = {}
                self._node_attrs: dict[object, dict[str, object]] = {}
                self._edge_attrs: dict[tuple[object, object], dict[str, object]] = {}
                if data:
                    self.update(data)

            def update(self, data: dict[str, object] | _IntellicrackNetworkX.DiGraph) -> None:
                """Update graph with nodes and edges from data.

                Merges nodes, edges, and attributes from the provided data into
                this graph. Supports both dictionary-based graph data and other
                DiGraph instances.

                Args:
                    data: Dictionary containing graph data with optional keys:
                        - 'nodes': Iterable of (node, attrs) tuples or node identifiers
                        - 'edges': Iterable of (u, v) or (u, v, attrs) tuples
                        - 'adjacency': Dict mapping nodes to lists of neighbor dicts
                        Or another DiGraph instance to merge.

                """
                if isinstance(data, _IntellicrackNetworkX.DiGraph):
                    for node in data._nodes:
                        self._nodes[node] = True
                        if node in data._node_attrs:
                            self._node_attrs[node] = data._node_attrs[node].copy()
                    for src, neighbors in data._edges.items():
                        if src not in self._edges:
                            self._edges[src] = set()
                        self._edges[src].update(neighbors)
                    for edge_key, attrs in data._edge_attrs.items():
                        self._edge_attrs[edge_key] = attrs.copy()
                    return

                if isinstance(data, dict):
                    if "nodes" in data:
                        nodes_data = data["nodes"]
                        if isinstance(nodes_data, (list, tuple)):
                            for item in nodes_data:
                                if isinstance(item, tuple) and len(item) >= 2:
                                    node, attrs = item[0], item[1] if len(item) > 1 else {}
                                    self._nodes[node] = True
                                    if isinstance(attrs, dict):
                                        self._node_attrs[node] = attrs
                                else:
                                    self._nodes[item] = True

                    if "edges" in data:
                        edges_data = data["edges"]
                        if isinstance(edges_data, (list, tuple)):
                            for edge in edges_data:
                                if isinstance(edge, (list, tuple)) and len(edge) >= 2:
                                    u, v = edge[0], edge[1]
                                    attrs = edge[2] if len(edge) > 2 and isinstance(edge[2], dict) else {}
                                    if u not in self._nodes:
                                        self._nodes[u] = True
                                    if v not in self._nodes:
                                        self._nodes[v] = True
                                    if u not in self._edges:
                                        self._edges[u] = set()
                                    self._edges[u].add(v)
                                    if attrs:
                                        self._edge_attrs[u, v] = attrs

                    if "adjacency" in data:
                        adjacency = data["adjacency"]
                        if isinstance(adjacency, dict):
                            for node, neighbors in adjacency.items():
                                self._nodes[node] = True
                                if node not in self._edges:
                                    self._edges[node] = set()
                                if isinstance(neighbors, (list, tuple)):
                                    for neighbor_info in neighbors:
                                        if isinstance(neighbor_info, dict):
                                            neighbor = neighbor_info.get("id", neighbor_info.get("node"))
                                            if neighbor is not None:
                                                self._nodes[neighbor] = True
                                                self._edges[node].add(neighbor)
                                                if edge_attrs := {
                                                    k: v
                                                    for k, v in neighbor_info.items()
                                                    if k not in ("id", "node")
                                                }:
                                                    self._edge_attrs[node, neighbor] = edge_attrs
                                        else:
                                            self._nodes[neighbor_info] = True
                                            self._edges[node].add(neighbor_info)

            def add_node(self, node: object, **attrs: object) -> None:
                """Add node to graph with optional attributes.

                Args:
                    node: Node identifier to add
                    **attrs: Optional attributes to attach to the node

                """
                self._nodes[node] = True
                if attrs:
                    self._node_attrs[node] = attrs

            def add_edge(self, u: object, v: object, **attrs: object) -> None:
                """Add edge to graph with optional attributes.

                Args:
                    u: Source node identifier
                    v: Target node identifier
                    **attrs: Optional attributes to attach to the edge

                """
                if u not in self._nodes:
                    self.add_node(u)
                if v not in self._nodes:
                    self.add_node(v)

                if u not in self._edges:
                    self._edges[u] = set()
                self._edges[u].add(v)

                if attrs:
                    self._edge_attrs[u, v] = attrs

            def nodes(self, data: bool = False) -> list[object] | list[tuple[object, dict[str, object]]]:
                """Return nodes with optional data.

                Args:
                    data: If True, return nodes with their attributes

                Returns:
                    List of nodes, or list of (node, attributes) tuples if data=True

                """
                if data:
                    return [(n, self._node_attrs.get(n, {})) for n in self._nodes]
                return list(self._nodes.keys())

            def edges(self, data: bool = False) -> list[tuple[object, object]] | list[tuple[object, object, dict[str, object]]]:
                """Return edges with optional data.

                Args:
                    data: If True, return edges with their attributes

                Returns:
                    List of (source, target) tuples, or (source, target, attributes) if data=True

                """
                if data:
                    edges_with_data: list[tuple[object, object, dict[str, object]]] = []
                    for u, neighbors in self._edges.items():
                        edges_with_data.extend(
                            (u, v, self._edge_attrs.get((u, v), {})) for v in neighbors
                        )
                    return edges_with_data
                else:
                    edges_no_data: list[tuple[object, object]] = []
                    for u, neighbors in self._edges.items():
                        edges_no_data.extend((u, v) for v in neighbors)
                    return edges_no_data

            def number_of_nodes(self) -> int:
                """Return number of nodes.

                Returns:
                    Total count of nodes in the graph

                """
                return len(self._nodes)

            def number_of_edges(self) -> int:
                """Return number of edges.

                Returns:
                    Total count of edges in the graph

                """
                return sum(len(neighbors) for neighbors in self._edges.values())

            def in_degree(self, node: object) -> int:
                """Return in-degree of node.

                Args:
                    node: Node identifier

                Returns:
                    Number of edges pointing to this node

                """
                return sum(node in neighbors for neighbors in self._edges.values())

            def successors(self, node: object) -> list[object]:
                """Return successors of node.

                Args:
                    node: Node identifier

                Returns:
                    List of nodes that this node points to

                """
                return list(self._edges.get(node, set()))

            def predecessors(self, node: object) -> list[object]:
                """Return predecessors of node.

                Args:
                    node: Node identifier

                Returns:
                    List of nodes that point to this node

                """
                return [u for u, neighbors in self._edges.items() if node in neighbors]

            def has_edge(self, u: object, v: object) -> bool:
                """Check if edge exists.

                Args:
                    u: Source node identifier
                    v: Target node identifier

                Returns:
                    True if edge exists, False otherwise

                """
                return u in self._edges and v in self._edges[u]

            def copy(self) -> _IntellicrackNetworkX.DiGraph:
                """Return copy of graph.

                Returns:
                    Deep copy of this graph with all nodes and edges

                """
                new_graph = self.__class__()
                new_graph._nodes = self._nodes.copy()
                new_graph._edges = {u: neighbors.copy() for u, neighbors in self._edges.items()}
                new_graph._node_attrs = self._node_attrs.copy()
                new_graph._edge_attrs = self._edge_attrs.copy()
                return new_graph

        class NetworkXError(Exception):
            """NetworkX-compatible exception."""

        @staticmethod
        def simple_cycles(graph: _IntellicrackNetworkX.DiGraph) -> list[list[object]]:
            """Find simple cycles using DFS.

            Args:
                graph: The directed graph to analyze for cycles

            Returns:
                List of cycles, where each cycle is a list of node identifiers

            """

            def _dfs_cycles(node: object, path: list[object], visited: set[object], stack: list[object]) -> list[list[object]]:
                """Perform depth-first search to find cycles.

                Args:
                    node: Current node being visited
                    path: Current path being traversed
                    visited: Set of already visited nodes
                    stack: Current stack of nodes in the path

                Returns:
                    List of cycles found from this node

                """
                if node in stack:
                    cycle_start = stack.index(node)
                    return [stack[cycle_start:]]

                if node in visited:
                    return []

                visited.add(node)
                stack.append(node)
                cycles = []

                for neighbor in graph.successors(node):
                    cycles.extend(_dfs_cycles(neighbor, path, visited, stack))

                stack.pop()
                return cycles

            all_cycles: list[list[object]] = []
            visited: set[object] = set()

            for node in graph.nodes():
                if node not in visited:
                    cycles = _dfs_cycles(node, [], visited, [])
                    all_cycles.extend(cycles)

            return all_cycles

        @staticmethod
        def strongly_connected_components(
            graph: _IntellicrackNetworkX.DiGraph,
        ) -> list[list[object]]:
            """Find strongly connected components using Tarjan's algorithm.

            Args:
                graph: The directed graph to analyze

            Returns:
                List of strongly connected components, each as a list of node identifiers

            """
            index_counter = [0]
            stack: list[object] = []
            lowlinks: dict[object, int] = {}
            index: dict[object, int] = {}
            on_stack: dict[object, bool] = {}
            components: list[list[object]] = []

            def _strongconnect(node: object) -> None:
                """Recursively find strongly connected components.

                Args:
                    node: The current node to process

                """
                index[node] = index_counter[0]
                lowlinks[node] = index_counter[0]
                index_counter[0] += 1
                stack.append(node)
                on_stack[node] = True

                for neighbor in graph.successors(node):
                    if neighbor not in index:
                        _strongconnect(neighbor)
                        lowlinks[node] = min(lowlinks[node], lowlinks[neighbor])
                    elif on_stack[neighbor]:
                        lowlinks[node] = min(lowlinks[node], index[neighbor])

                if lowlinks[node] == index[node]:
                    component: list[object] = []
                    while True:
                        w = stack.pop()
                        on_stack[w] = False
                        component.append(w)
                        if w == node:
                            break
                    components.append(component)

            for node in graph.nodes():
                if node not in index:
                    _strongconnect(node)

            return components

        @staticmethod
        def pagerank(
            graph: _IntellicrackNetworkX.DiGraph,
            alpha: float = 0.85,
            max_iter: int = 100,
            tol: float = 1e-6,
        ) -> dict[object, float]:
            """Calculate PageRank using power iteration.

            Args:
                graph: The directed graph to analyze
                alpha: Damping factor (0 to 1), default 0.85
                max_iter: Maximum number of iterations, default 100
                tol: Convergence tolerance, default 1e-6

            Returns:
                Dictionary mapping nodes to their PageRank scores

            """
            nodes = list(graph.nodes())
            if not nodes:
                return {}

            n = len(nodes)
            {node: i for i, node in enumerate(nodes)}

            pr = dict.fromkeys(nodes, 1.0 / n)

            for _ in range(max_iter):
                new_pr: dict[object, float] = {}
                max_diff = 0.0

                for node in nodes:
                    rank_sum = 0.0
                    predecessors = graph.predecessors(node)
                    for pred in predecessors:
                        out_degree = len(graph.successors(pred))
                        if out_degree > 0:
                            rank_sum += pr[pred] / out_degree

                    new_rank = (1 - alpha) / n + alpha * rank_sum
                    new_pr[node] = new_rank
                    max_diff = max(max_diff, abs(new_rank - pr[node]))

                pr = new_pr
                if max_diff < tol:
                    break

            return pr

        @staticmethod
        def betweenness_centrality(graph: _IntellicrackNetworkX.DiGraph) -> dict[object, float]:
            """Calculate betweenness centrality.

            Args:
                graph: The directed graph to analyze

            Returns:
                Dictionary mapping nodes to their betweenness centrality scores

            """
            nodes = list(graph.nodes())
            centrality: dict[object, float] = dict.fromkeys(nodes, 0.0)

            for source in nodes:
                stack: list[object] = []
                paths: dict[object, list[object]] = {node: [] for node in nodes}
                paths[source] = [source]
                sigma: dict[object, int] = dict.fromkeys(nodes, 0)
                sigma[source] = 1
                distances: dict[object, int] = dict.fromkeys(nodes, -1)
                distances[source] = 0

                queue: list[object] = [source]
                while queue:
                    node = queue.pop(0)
                    stack.append(node)

                    for neighbor in graph.successors(node):
                        if distances[neighbor] < 0:
                            queue.append(neighbor)
                            distances[neighbor] = distances[node] + 1

                        if distances[neighbor] == distances[node] + 1:
                            sigma[neighbor] += sigma[node]
                            paths[neighbor].extend(paths[node])

                delta: dict[object, float] = dict.fromkeys(nodes, 0)
                while stack:
                    node = stack.pop()
                    for pred in graph.predecessors(node):
                        if distances[pred] == distances[node] - 1:
                            delta[pred] += (sigma[pred] / sigma[node]) * (1 + delta[node])

                    if node != source:
                        centrality[node] += delta[node]

            n = len(nodes)
            if n > 2:
                for node in nodes:
                    centrality[node] /= (n - 1) * (n - 2)

            return centrality

        @staticmethod
        def closeness_centrality(graph: _IntellicrackNetworkX.DiGraph) -> dict[object, float]:
            """Calculate closeness centrality.

            Args:
                graph: The directed graph to analyze

            Returns:
                Dictionary mapping nodes to their closeness centrality scores

            """
            nodes = list(graph.nodes())
            centrality: dict[object, float] = {}

            for node in nodes:
                distances: dict[object, float | int] = {n: float("inf") for n in nodes}
                distances[node] = 0
                queue: list[object] = [node]

                while queue:
                    current = queue.pop(0)
                    for neighbor in graph.successors(current):
                        if distances[neighbor] == float("inf"):
                            distances[neighbor] = distances[current] + 1
                            queue.append(neighbor)

                if reachable := [d for d in distances.values() if d != float("inf") and d > 0]:
                    centrality[node] = len(reachable) / sum(reachable)
                else:
                    centrality[node] = 0.0

            return centrality

        @staticmethod
        def spring_layout(
            graph: _IntellicrackNetworkX.DiGraph,
            k: float | None = None,
            pos: dict[object, tuple[float, float]] | None = None,
            iterations: int = 50,
        ) -> dict[object, tuple[float, float]]:
            """Spring layout algorithm for graph visualization.

            Args:
                graph: The directed graph to layout
                k: Optimal distance between nodes, default calculated from graph size
                pos: Initial positions dictionary, default creates circular layout
                iterations: Number of force-directed iterations, default 50

            Returns:
                Dictionary mapping nodes to (x, y) coordinate tuples

            """
            import math

            nodes = list(graph.nodes())
            if not nodes:
                return {}

            n = len(nodes)
            if k is None:
                k = 1 / math.sqrt(n)

            if pos is None:
                pos = {}
                angle_step = 2 * math.pi / n
                radius = 0.5
                for i, node in enumerate(nodes):
                    angle = i * angle_step
                    x = 0.5 + radius * math.cos(angle)
                    y = 0.5 + radius * math.sin(angle)
                    pos[node] = (x, y)
            else:
                pos = pos.copy()

            for _ in range(iterations):
                forces: dict[object, list[float]] = {node: [0, 0] for node in nodes}

                for i, node1 in enumerate(nodes):
                    for j, node2 in enumerate(nodes):
                        if i != j:
                            x1, y1 = pos[node1]
                            x2, y2 = pos[node2]
                            dx, dy = x1 - x2, y1 - y2
                            dist = math.sqrt(dx * dx + dy * dy) or 0.01
                            force = k * k / dist
                            forces[node1][0] += force * dx / dist
                            forces[node1][1] += force * dy / dist

                for edge in graph.edges():
                    u, v = edge[0], edge[1]
                    x1, y1 = pos[u]
                    x2, y2 = pos[v]
                    dx, dy = x2 - x1, y2 - y1
                    dist = math.sqrt(dx * dx + dy * dy) or 0.01
                    force = dist * dist / k
                    forces[u][0] += force * dx / dist
                    forces[u][1] += force * dy / dist
                    forces[v][0] -= force * dx / dist
                    forces[v][1] -= force * dy / dist

                for node in nodes:
                    fx, fy = forces[node]
                    x, y = pos[node]
                    pos[node] = (x + fx * 0.1, y + fy * 0.1)

            return pos

        @staticmethod
        def circular_layout(
            graph: _IntellicrackNetworkX.DiGraph,
        ) -> dict[object, tuple[float, float]]:
            """Circular layout for graph visualization.

            Args:
                graph: The directed graph to layout

            Returns:
                Dictionary mapping nodes to (x, y) coordinate tuples arranged in a circle

            """
            import math

            nodes = list(graph.nodes())
            if not nodes:
                return {}

            n = len(nodes)
            positions: dict[object, tuple[float, float]] = {}

            for i, node in enumerate(nodes):
                angle = 2 * math.pi * i / n
                x = math.cos(angle)
                y = math.sin(angle)
                positions[node] = (x, y)

            return positions

        @staticmethod
        def draw_networkx(
            graph: _IntellicrackNetworkX.DiGraph,
            pos: dict[object, tuple[float, float]] | None = None,
            ax: object = None,
            **kwargs: object,
        ) -> None:
            """Draw graph with basic functionality.

            Args:
                graph: The directed graph to draw
                pos: Optional positions dictionary for nodes
                ax: Optional matplotlib axes object
                **kwargs: Additional keyword arguments for drawing

            """
            try:
                import matplotlib.pyplot as plt
                import networkx as nx

                if pos is None:
                    pos = nx.spring_layout(graph)
                if ax is None:
                    _fig, ax = plt.subplots()
                nx.draw(graph, pos=pos, ax=ax, **kwargs)
                plt.show()
                logger.info("Drew graph with matplotlib: %s nodes, %s edges", graph.number_of_nodes(), graph.number_of_edges())
            except ImportError:
                logger.info(
                    "Drawing graph with %s nodes and %s edges (matplotlib not available)", graph.number_of_nodes(), graph.number_of_edges()
                )

        class Drawing:
            """Drawing submodule."""

            class NxPydot:
                """PyDot interface for NetworkX compatibility."""

                @staticmethod
                def write_dot(graph: _IntellicrackNetworkX.DiGraph, path: str) -> None:
                    """Write graph in DOT format.

                    Args:
                        graph: The directed graph to export
                        path: File path where to write the DOT file

                    """
                    with open(path, "w", encoding="utf-8") as f:
                        f.write("digraph G {\n")
                        f.write("    node [shape=box];\n")

                        f.writelines(f'    "{node}";\n' for node in graph.nodes())

                        for edge in graph.edges():
                            f.write(f'    "{edge[0]}" -> "{edge[1]}";\n')

                        f.write("}\n")

                @staticmethod
                def graphviz_layout(graph: _IntellicrackNetworkX.DiGraph, prog: str = "dot") -> dict[object, tuple[float, float]]:
                    """Graphviz layout (fallback to spring layout).

                    Args:
                        graph: The directed graph to layout
                        prog: Graphviz program to use (default 'dot')

                    Returns:
                        Dictionary mapping nodes to (x, y) coordinate tuples

                    """
                    try:
                        import pygraphviz as pgv

                        G = pgv.AGraph()
                        G.add_nodes_from(graph.nodes())
                        G.add_edges_from(graph.edges())
                        G.layout(prog=prog)
                        pos = {
                            node: (
                                float(node.attr["pos"].split(",")[0]),
                                float(node.attr["pos"].split(",")[1]),
                            )
                            for node in G.nodes()
                        }
                        logger.info("Used graphviz layout with prog '%s'", prog)
                        return pos
                    except ImportError:
                        logger.warning("Graphviz not available, using spring layout")
                        return _IntellicrackNetworkX.spring_layout(graph)

            # Alias for compatibility
            nx_pydot = NxPydot

        # Alias for compatibility
        drawing = Drawing

    nx = _IntellicrackNetworkX()

plt: Any
try:
    from intellicrack.handlers.matplotlib_handler import HAS_MATPLOTLIB, plt

    MATPLOTLIB_AVAILABLE = HAS_MATPLOTLIB
except ImportError as e:
    logger.exception("Import error in cfg_explorer: %s", e)
    MATPLOTLIB_AVAILABLE = False
    HAS_MATPLOTLIB = False
    plt = None

try:
    from intellicrack.handlers.capstone_handler import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs, capstone

    CAPSTONE_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in cfg_explorer: %s", e)
    capstone = None
    CS_ARCH_X86 = CS_MODE_32 = CS_MODE_64 = Cs = None
    CAPSTONE_AVAILABLE = False

try:
    from intellicrack.handlers.pefile_handler import pefile

    PEFILE_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in cfg_explorer: %s", e)
    pefile = None
    PEFILE_AVAILABLE = False


try:
    import shutil
    import subprocess

    SUBPROCESS_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in cfg_explorer: %s", e)
    SUBPROCESS_AVAILABLE = False

# UI dependencies
try:
    from PyQt6.QtWidgets import QFileDialog, QInputDialog, QMessageBox

    PYQT_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in cfg_explorer: %s", e)
    PYQT_AVAILABLE = False


class CFGExplorer:
    """Advanced Visual CFG (Control Flow Graph) Explorer with radare2 integration.

    This class provides comprehensive control flow analysis including:
    - Advanced graph analysis using radare2
    - License validation detection
    - Vulnerability pattern recognition
    - AI-enhanced analysis
    - Cross-reference analysis
    - Function clustering and similarity
    - Multi-layer graph visualization
    """

    def __init__(self, binary_path: str | None = None, radare2_path: str | None = None) -> None:
        """Initialize the enhanced CFG explorer."""
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)

        self.graph: Any = None
        self.functions: dict[str, dict[str, Any]] = {}
        self.current_function: str | None = None

        self.decompiler: R2DecompilationEngine | None = None
        self.vulnerability_engine: R2VulnerabilityEngine | None = None
        self.ai_engine: R2AIEngine | None = None
        self.string_analyzer: R2StringAnalyzer | None = None
        self.import_analyzer: R2ImportExportAnalyzer | None = None
        self.scripting_engine: R2ScriptingEngine | None = None

        self.function_graphs: dict[str, Any] = {}
        self.call_graph: Any = None
        self.cross_references: dict[str, Any] = {}
        self.function_similarities: dict[str, float] = {}
        self.analysis_cache: dict[str, Any] = {}

        if self.binary_path:
            self._initialize_analysis_engines()

    def _initialize_analysis_engines(self) -> None:
        """Initialize all analysis engines with current binary path."""
        if not self.binary_path:
            return

        try:
            self.decompiler = R2DecompilationEngine(self.binary_path, self.radare2_path)
            self.vulnerability_engine = R2VulnerabilityEngine(self.binary_path, self.radare2_path)
            self.ai_engine = R2AIEngine(self.binary_path, self.radare2_path)
            self.string_analyzer = R2StringAnalyzer(self.binary_path, self.radare2_path)
            self.import_analyzer = R2ImportExportAnalyzer(self.binary_path, self.radare2_path)
            self.scripting_engine = R2ScriptingEngine(self.binary_path, self.radare2_path)
            self.logger.info("Initialized advanced analysis engines")
        except Exception as e:
            self.logger.warning("Failed to initialize some analysis engines: %s", e)

    def load_binary(self, binary_path: str | None = None) -> bool:
        """Load a binary file and extract its enhanced CFG with advanced analysis."""
        if binary_path:
            self.binary_path = binary_path
            self._initialize_analysis_engines()

        if not self.binary_path:
            self.logger.exception("No binary path specified")
            self._show_error_dialog("No binary path specified", "Please specify a valid binary file path.")
            return False

        if not NETWORKX_AVAILABLE:
            self.logger.exception("NetworkX not available - please install networkx")
            self._show_error_dialog("Missing Dependency", "NetworkX not available - please install networkx package.")
            return False

        try:
            # Use our advanced radare2 session manager
            with r2_session(self.binary_path, self.radare2_path) as r2:
                self.logger.info("Loading binary with advanced CFG analysis: %s", self.binary_path)

                # Get comprehensive function information
                functions = r2.get_functions()

                # Initialize call graph
                self.call_graph = nx.DiGraph()

                # Process each function with enhanced analysis
                for func in functions:
                    function_name = func.get("name", f"sub_{func.get('offset', 0):x}")
                    function_addr = func.get("offset", 0)

                    # Skip invalid functions
                    if not function_addr:
                        continue

                    try:
                        # Get advanced function graph with r2
                        graph_data = r2._execute_command(f"agfj @ {hex(function_addr)}", expect_json=True)

                        if not graph_data or not isinstance(graph_data, list):
                            continue

                        # Create enhanced networkx graph
                        function_graph = self._create_enhanced_function_graph(graph_data[0], r2, function_addr)

                        # Store enhanced function data
                        self.functions[function_name] = {
                            "addr": function_addr,
                            "graph": function_graph,
                            "blocks": graph_data[0].get("blocks", []),
                            "size": func.get("size", 0),
                            "complexity": func.get("cc", 1),
                            "calls": func.get("calls", 0),
                            "type": func.get("type", "fcn"),
                            "enhanced_data": {},
                        }

                        # Store in advanced graph storage
                        self.function_graphs[function_name] = function_graph

                        # Add to call graph
                        self.call_graph.add_node(
                            function_name,
                            addr=function_addr,
                            size=func.get("size", 0),
                            complexity=func.get("cc", 1),
                        )

                    except (R2Exception, json.JSONDecodeError) as e:
                        self.logger.debug("Failed to process function %s: %s", function_name, e)
                        continue

                # Build call graph edges
                self._build_call_graph(r2)

                # Perform advanced analysis
                self._perform_advanced_analysis()

                self.logger.info("Loaded %s functions with enhanced analysis", len(self.functions))
                return True

        except (R2Exception, OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error loading binary with advanced analysis: %s", e)
            return False

    def _create_enhanced_function_graph(self, graph_data: dict[str, Any], r2: Any, function_addr: int) -> Any:
        """Create enhanced function graph with comprehensive node data."""
        function_graph = nx.DiGraph()

        if r2 and function_addr:
            try:
                if func_info := r2.cmdj(f"afij @ {function_addr}"):
                    function_graph.graph["function_name"] = func_info[0].get("name", f"func_{function_addr:x}")
                    function_graph.graph["function_size"] = func_info[0].get("realsz", 0)
                    function_graph.graph["function_addr"] = function_addr
            except Exception as e:
                self.logger.exception("Exception in cfg_explorer: %s", e)
                function_graph.graph["function_addr"] = function_addr
                function_graph.graph["function_name"] = f"func_{function_addr:x}"

        blocks_data = graph_data.get("blocks", [])
        blocks: list[dict[str, Any]] = blocks_data if isinstance(blocks_data, list) else []

        for block in blocks:
            block_addr: int = block.get("offset", 0)
            block_size: int = block.get("size", 0)
            block_ops: list[dict[str, Any]] = block.get("ops", [])

            instruction_count = len(block_ops)
            has_call = any("call" in op.get("disasm", "") for op in block_ops)
            has_jump = any(op.get("type", "") in ["jmp", "cjmp"] for op in block_ops)
            has_return = any("ret" in op.get("disasm", "") for op in block_ops)

            # Analyze for security-relevant instructions
            crypto_ops = sum(
                any(
                    (
                        kw in op.get("disasm", "").lower()
                        for kw in ["aes", "crypt", "hash", "rsa"]
                    )
                )
                for op in block_ops
            )

            license_ops = sum(
                any(
                    (
                        kw in op.get("disasm", "").lower()
                        for kw in ["license", "valid", "check", "trial", "serial"]
                    )
                )
                for op in block_ops
            )

            # Add enhanced node with comprehensive metadata
            function_graph.add_node(
                block_addr,
                size=block_size,
                ops=block_ops,
                instruction_count=instruction_count,
                label=f"0x{block_addr:x}",
                has_call=has_call,
                has_jump=has_jump,
                has_return=has_return,
                crypto_operations=crypto_ops,
                license_operations=license_ops,
                block_type=self._classify_block_type(block),
                complexity_score=self._calculate_block_complexity(block),
            )

            # Add control flow edges with enhanced metadata
            if block.get("jump"):
                jump_target = block["jump"]
                function_graph.add_edge(block_addr, jump_target, type="conditional_jump", condition="true")

            if block.get("fail"):
                fail_target = block["fail"]
                function_graph.add_edge(block_addr, fail_target, type="conditional_jump", condition="false")

            # Add sequential flow edges
            next_block = block.get("next")
            if next_block and not has_return and (not block.get("jump") or block.get("fail")):
                function_graph.add_edge(block_addr, next_block, type="sequential", condition="fallthrough")

        return function_graph

    def _classify_block_type(self, block: dict[str, Any]) -> str:
        """Classify block type based on its characteristics."""
        ops_data = block.get("ops", [])
        ops: list[dict[str, Any]] = ops_data if isinstance(ops_data, list) else []

        if not ops:
            return "empty"

        if any("ret" in op.get("disasm", "") for op in ops):
            return "return"

        if any("call" in op.get("disasm", "") for op in ops):
            return "call"

        if block.get("jump"):
            return "conditional" if block.get("fail") else "jump"
        return "basic"

    def _calculate_block_complexity(self, block: dict[str, Any]) -> float:
        """Calculate complexity score for a basic block."""
        ops_data = block.get("ops", [])
        ops: list[dict[str, Any]] = ops_data if isinstance(ops_data, list) else []

        if not ops:
            return 0.0

        complexity: float = float(len(ops))

        for op in ops:
            disasm: str = op.get("disasm", "").lower()

            if "call" in disasm:
                complexity += 2.0
            elif any(jmp in disasm for jmp in ["jmp", "je", "jne", "jz", "jnz"]):
                complexity += 1.5
            elif any(math_op in disasm for math_op in ["mul", "div", "imul", "idiv"]):
                complexity += 1.2
            elif any(crypto in disasm for crypto in ["aes", "sha", "md5"]):
                complexity += 3.0

        return complexity

    def _build_call_graph(self, r2: Any) -> None:
        """Build inter-function call graph."""
        try:
            xrefs = r2._execute_command("axtj", expect_json=True)

            if not isinstance(xrefs, list):
                return

            for xref in xrefs:
                from_addr = xref.get("from", 0)
                to_addr = xref.get("to", 0)
                xref_type = xref.get("type", "")

                if xref_type == "CALL":
                    # Find functions containing these addresses
                    from_func = self._find_function_by_address(from_addr)
                    to_func = self._find_function_by_address(to_addr)

                    if from_func and to_func and from_func != to_func:
                        self.call_graph.add_edge(
                            from_func,
                            to_func,
                            type="function_call",
                            from_addr=hex(from_addr),
                            to_addr=hex(to_addr),
                        )

        except (R2Exception, json.JSONDecodeError) as e:
            self.logger.debug("Failed to build call graph: %s", e)

    def _find_function_by_address(self, address: int) -> str | None:
        """Find function name containing the given address."""
        for func_name, func_data in self.functions.items():
            func_addr = func_data.get("addr", 0)
            func_size = func_data.get("size", 0)

            if func_addr <= address < func_addr + func_size:
                return func_name

        return None

    def _perform_advanced_analysis(self) -> None:
        """Perform advanced analysis using integrated engines."""
        if not self.binary_path:
            return

        try:
            # Perform comprehensive string analysis
            if self.string_analyzer:
                string_analysis = self.string_analyzer.analyze_all_strings()
                self.analysis_cache["string_analysis"] = string_analysis

            # Perform import/export analysis
            if self.import_analyzer:
                import_analysis = self.import_analyzer.analyze_imports_exports()
                self.analysis_cache["import_analysis"] = import_analysis

            # Perform AI-enhanced analysis
            if self.ai_engine:
                ai_analysis = self.ai_engine.analyze_with_ai()
                self.analysis_cache["ai_analysis"] = ai_analysis

            # Calculate function similarities
            self._calculate_function_similarities()

            # Perform license analysis using scripting engine
            if self.scripting_engine:
                license_analysis = self.scripting_engine.execute_license_analysis_workflow()
                self.analysis_cache["license_analysis"] = license_analysis

            self.logger.info("Completed advanced analysis")

        except Exception as e:
            self.logger.warning("Advanced analysis partially failed: %s", e)

    def _calculate_function_similarities(self) -> None:
        """Calculate similarities between functions using graph metrics."""
        if not NETWORKX_AVAILABLE:
            return

        function_names = list(self.function_graphs.keys())

        for i, func1 in enumerate(function_names):
            for _j, func2 in enumerate(function_names[i + 1 :], i + 1):
                try:
                    graph1 = self.function_graphs[func1]
                    graph2 = self.function_graphs[func2]

                    # Calculate structural similarity
                    similarity = self._calculate_graph_similarity(graph1, graph2)

                    if similarity > 0.5:  # Only store significant similarities
                        self.function_similarities[f"{func1}:{func2}"] = similarity

                except Exception as e:
                    self.logger.debug("Failed to calculate similarity between %s and %s: %s", func1, func2, e)

    def _calculate_graph_similarity(self, graph1: Any, graph2: Any) -> float:
        """Calculate similarity between two function graphs."""
        if graph1.number_of_nodes() == 0 or graph2.number_of_nodes() == 0:
            return 0.0

        node_ratio = min(graph1.number_of_nodes(), graph2.number_of_nodes()) / max(graph1.number_of_nodes(), graph2.number_of_nodes())

        max_edges = max(graph1.number_of_edges(), graph2.number_of_edges())
        if max_edges > 0:
            edge_ratio = min(graph1.number_of_edges(), graph2.number_of_edges()) / max_edges
        else:
            edge_ratio = 1.0

        try:
            complexity1 = len(list(nx.simple_cycles(graph1))) + 1
            complexity2 = len(list(nx.simple_cycles(graph2))) + 1
            complexity_ratio = min(complexity1, complexity2) / max(complexity1, complexity2)
        except Exception:
            complexity_ratio = 1.0

        return float((node_ratio + edge_ratio + complexity_ratio) / 3.0)

    def get_function_list(self) -> list[str]:
        """Get a list of all functions in the binary."""
        return list(self.functions.keys())

    def set_current_function(self, function_name: str) -> bool:
        """Set the current function for analysis."""
        if function_name in self.functions:
            self.current_function = function_name
            self.graph = self.functions[function_name]["graph"]
            return True
        self.logger.exception("Function %s not found", function_name)
        return False

    def get_functions(self) -> list[dict[str, Any]]:
        """Get list of functions (alias for get_function_list)."""
        return [
            {
                "name": func_name,
                "address": f"0x{func_data['addr']:x}",
            }
            for func_name, func_data in self.functions.items()
        ]

    def analyze_function(self, function_name: str) -> dict[str, Any] | None:
        """Analyze a specific function (compatibility method)."""
        if not self.set_current_function(function_name):
            return None

        func_data = self.functions.get(function_name)
        if not func_data:
            return None

        complexity = self.get_complexity_metrics()
        license_patterns = self.find_license_check_patterns()
        num_blocks = len(func_data.get("blocks", []))

        return {
            "name": function_name,
            "address": f"0x{func_data['addr']:x}",
            "graph": self.graph,
            "num_blocks": num_blocks,
            "complexity": complexity,
            "license_patterns": license_patterns,
            "has_license_checks": len(license_patterns) > 0,
        }

    def visualize_cfg(self, function_name: str | None = None) -> bool:
        """Visualize CFG (compatibility method)."""
        if function_name and not self.set_current_function(function_name):
            return False
        return self.export_graph_image("cfg_visualization.png")

    def export_dot(self, output_file: str) -> bool:
        """Export DOT file (alias for export_dot_file)."""
        return self.export_dot_file(output_file)

    def analyze(self, binary_path: str | None = None) -> bool:
        """Analyze binary (compatibility method)."""
        return self.load_binary(binary_path) if binary_path else True

    def get_complexity_metrics(self) -> dict[str, Any]:
        """Get complexity metrics for the current function."""
        if not self.graph or not NETWORKX_AVAILABLE:
            return {"error": "No graph or NetworkX not available"}

        try:
            return {
                "nodes": self.graph.number_of_nodes(),
                "edges": self.graph.number_of_edges(),
                "cyclomatic_complexity": len(list(nx.simple_cycles(self.graph))) + 1,
            }
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error in cfg_explorer: %s", e)
            return {"error": str(e)}

    def get_graph_layout(self, layout_type: str = "spring") -> dict[Any, Any] | None:
        """Get a layout for the current function graph."""
        if not self.graph:
            self.logger.exception("No graph loaded")
            return None

        if not NETWORKX_AVAILABLE:
            self.logger.exception("NetworkX not available")
            return None

        if layout_type == "circular":
            layout: dict[Any, Any] = nx.circular_layout(self.graph)
        elif layout_type == "dot":
            try:
                layout = nx.nx_pydot.graphviz_layout(self.graph, prog="dot")
            except (ImportError, OSError):
                self.logger.warning("Graphviz not available, falling back to spring layout")
                layout = nx.spring_layout(self.graph)
        else:
            layout = nx.spring_layout(self.graph)

        return layout

    def get_graph_data(self, layout_type: str = "spring") -> dict[str, Any] | None:
        """Get graph data for visualization."""
        if not self.graph:
            self.logger.exception("No graph loaded")
            return None

        layout = self.get_graph_layout(layout_type)
        if layout is None:
            self.logger.exception("Failed to get graph layout")
            return None

        nodes: list[dict[str, Any]] = []
        if self.graph is not None:
            for node in self.graph.nodes():
                node_data = self.graph.nodes[node]
                nodes.append(
                    {
                        "id": node,
                        "label": node_data.get("label", f"0x{node:x}"),
                        "x": float(layout[node][0]) if node in layout else 0.0,
                        "y": float(layout[node][1]) if node in layout else 0.0,
                        "size": node_data.get("size", 0),
                    },
                )

        edges: list[dict[str, Any]] = []
        if self.graph is not None:
            edges.extend(
                {
                    "source": source,
                    "target": target,
                }
                for source, target in self.graph.edges()
            )
        return {
            "nodes": nodes,
            "edges": edges,
            "function": self.current_function,
        }

    def get_advanced_analysis_results(self) -> dict[str, Any]:
        """Get comprehensive advanced analysis results."""
        return {
            "analysis_cache": self.analysis_cache,
            "function_similarities": self.function_similarities,
            "call_graph_metrics": self.get_call_graph_metrics(),
            "vulnerability_patterns": self.get_vulnerability_patterns(),
            "license_validation_analysis": self.get_license_validation_analysis(),
            "code_complexity_analysis": self.get_code_complexity_analysis(),
            "cross_reference_analysis": self.get_cross_reference_analysis(),
        }

    def get_call_graph_metrics(self) -> dict[str, Any]:
        """Get call graph analysis metrics."""
        if not self.call_graph or not NETWORKX_AVAILABLE:
            return {}

        try:
            metrics: dict[str, Any] = {
                "total_functions": self.call_graph.number_of_nodes(),
                "total_calls": self.call_graph.number_of_edges(),
                "avg_calls_per_function": self.call_graph.number_of_edges() / max(1, self.call_graph.number_of_nodes()),
                "strongly_connected_components": len(list(nx.strongly_connected_components(self.call_graph))),
                "function_ranks": dict(nx.pagerank(self.call_graph)),
                "entry_points": [node for node in self.call_graph.nodes() if self.call_graph.in_degree(node) == 0],
                "leaf_functions": [node for node in self.call_graph.nodes() if self.call_graph.out_degree(node) == 0],
                "recursive_functions": self._find_recursive_functions(),
            }

            if self.call_graph.number_of_nodes() > 0:
                metrics["betweenness_centrality"] = dict(nx.betweenness_centrality(self.call_graph))
                metrics["closeness_centrality"] = dict(nx.closeness_centrality(self.call_graph))

            return metrics
        except Exception as e:
            self.logger.debug("Failed to calculate call graph metrics: %s", e)
            return {}

    def _find_recursive_functions(self) -> list[Any]:
        """Find functions that call themselves directly or indirectly."""
        recursive_funcs: list[Any] = []

        if not self.call_graph:
            return recursive_funcs

        recursive_funcs.extend(node for node in self.call_graph.nodes() if self.call_graph.has_edge(node, node))
        try:
            cycles = list(nx.simple_cycles(self.call_graph))
            for cycle in cycles:
                recursive_funcs.extend(cycle)
        except Exception as e:
            self.logger.debug("Failed to detect indirect recursion cycles: %s", e)

        return list(set(recursive_funcs))

    def get_vulnerability_patterns(self) -> dict[str, Any]:
        """Get vulnerability patterns from advanced analysis."""
        patterns: dict[str, list[dict[str, Any]]] = {
            "buffer_overflow_candidates": [],
            "format_string_candidates": [],
            "integer_overflow_candidates": [],
            "use_after_free_candidates": [],
            "license_bypass_opportunities": [],
        }

        for func_name, func_data in self.functions.items():
            graph = func_data.get("graph")
            if not graph:
                continue

            for node, node_data in graph.nodes(data=True):
                ops = node_data.get("ops", [])

                for op in ops:
                    disasm = op.get("disasm", "").lower()

                    if any(unsafe_func in disasm for unsafe_func in ["strcpy", "strcat", "sprintf", "gets"]):
                        patterns["buffer_overflow_candidates"].append(
                            {
                                "function": func_name,
                                "address": hex(node),
                                "instruction": op.get("disasm", ""),
                                "type": "unsafe_string_function",
                            },
                        )

                    if "printf" in disasm and "%" not in disasm:
                        patterns["format_string_candidates"].append(
                            {
                                "function": func_name,
                                "address": hex(node),
                                "instruction": op.get("disasm", ""),
                                "type": "printf_without_format",
                            },
                        )

                    if node_data.get("license_operations", 0) > 0:
                        patterns["license_bypass_opportunities"].append(
                            {
                                "function": func_name,
                                "address": hex(node),
                                "license_operations": node_data.get("license_operations", 0),
                                "block_type": node_data.get("block_type", "unknown"),
                            },
                        )

        return patterns

    def get_license_validation_analysis(self) -> dict[str, Any]:
        """Get comprehensive license validation analysis."""
        analysis: dict[str, Any] = {
            "license_functions": [],
            "validation_mechanisms": [],
            "bypass_opportunities": [],
            "complexity_assessment": "unknown",
        }

        license_cache = self.analysis_cache.get("license_analysis")
        if isinstance(license_cache, dict):
            analysis |= {
                "license_functions": license_cache.get("license_functions", []),
                "validation_mechanisms": license_cache.get("validation_mechanisms", []),
                "bypass_opportunities": license_cache.get("bypass_opportunities", []),
                "analysis_confidence": license_cache.get("analysis_confidence", 0.0),
            }

        license_related_functions: list[dict[str, Any]] = []
        for func_name, func_data in self.functions.items():
            graph = func_data.get("graph")
            if not graph:
                continue

            license_score = sum(node_data.get("license_operations", 0) for _node, node_data in graph.nodes(data=True))
            if license_score > 0:
                license_related_functions.append(
                    {
                        "function": func_name,
                        "license_score": license_score,
                        "complexity": func_data.get("complexity", 1),
                        "size": func_data.get("size", 0),
                    },
                )

        analysis["cfg_license_functions"] = license_related_functions

        return analysis

    def get_code_complexity_analysis(self) -> dict[str, Any]:
        """Get comprehensive code complexity analysis."""
        complexity_data: dict[str, Any] = {
            "function_complexities": {},
            "overall_metrics": {},
            "complexity_distribution": {},
            "high_complexity_functions": [],
        }

        complexities: list[float] = []

        for func_name, func_data in self.functions.items():
            graph = func_data.get("graph")
            if not graph:
                continue

            cyclomatic_complexity = self._calculate_cyclomatic_complexity(graph)
            instruction_complexity = sum(node_data.get("instruction_count", 0) for _, node_data in graph.nodes(data=True))
            block_complexity = sum(node_data.get("complexity_score", 0) for _, node_data in graph.nodes(data=True))

            func_complexity: dict[str, Any] = {
                "cyclomatic": cyclomatic_complexity,
                "instruction_count": instruction_complexity,
                "block_complexity": block_complexity,
                "combined_score": (cyclomatic_complexity * 2 + instruction_complexity * 0.1 + block_complexity),
            }

            complexity_data["function_complexities"][func_name] = func_complexity
            complexities.append(func_complexity["combined_score"])

            # Identify high complexity functions
            if func_complexity["combined_score"] > 50:  # Threshold for high complexity
                complexity_data["high_complexity_functions"].append(
                    {
                        "function": func_name,
                        "score": func_complexity["combined_score"],
                        "metrics": func_complexity,
                    },
                )

        # Calculate overall metrics
        if complexities:
            if NUMPY_AVAILABLE:
                complexity_data["overall_metrics"] = {
                    "average_complexity": np.mean(complexities),
                    "max_complexity": np.max(complexities),
                    "min_complexity": np.min(complexities),
                    "std_deviation": np.std(complexities),
                    "total_functions": len(complexities),
                }
            else:
                # Use Python built-ins when numpy is not available
                import statistics

                complexity_data["overall_metrics"] = {
                    "average_complexity": statistics.mean(complexities),
                    "max_complexity": max(complexities),
                    "min_complexity": min(complexities),
                    "std_deviation": statistics.stdev(complexities) if len(complexities) > 1 else 0.0,
                    "total_functions": len(complexities),
                }

        return complexity_data

    def _calculate_cyclomatic_complexity(self, graph: Any) -> int:
        """Calculate cyclomatic complexity of a function graph."""
        if not graph or graph.number_of_nodes() == 0:
            return 1

        try:
            edges: int = graph.number_of_edges()
            nodes: int = graph.number_of_nodes()
            complexity = edges - nodes + 2
            return max(1, complexity)
        except (AttributeError, TypeError):
            return 1

    def get_cross_reference_analysis(self) -> dict[str, Any]:
        """Get cross-reference analysis between functions."""
        xref_analysis: dict[str, Any] = {
            "function_dependencies": {},
            "dependency_depth": {},
            "circular_dependencies": [],
            "isolated_functions": [],
        }

        if not self.call_graph:
            return xref_analysis

        for func_name in self.call_graph.nodes():
            direct_deps = list(self.call_graph.successors(func_name))
            reverse_deps = list(self.call_graph.predecessors(func_name))

            xref_analysis["function_dependencies"][func_name] = {
                "calls": direct_deps,
                "called_by": reverse_deps,
                "dependency_count": len(direct_deps),
                "reverse_dependency_count": len(reverse_deps),
            }

        for func_name in self.call_graph.nodes():
            if self.call_graph.in_degree(func_name) == 0 and self.call_graph.out_degree(func_name) == 0:
                xref_analysis["isolated_functions"].append(func_name)

        try:
            cycles = list(nx.simple_cycles(self.call_graph))
            xref_analysis["circular_dependencies"] = cycles
        except Exception as e:
            self.logger.debug("Failed to detect circular dependencies: %s", e)

        return xref_analysis

    def find_license_check_patterns(self) -> list[dict[str, Any]]:
        """Find potential license check patterns in the CFG."""
        if not self.graph:
            self.logger.exception("No graph loaded")
            return []

        license_patterns = []

        # License-related keywords
        license_keywords = [
            "licen",
            "key",
            "activ",
            "valid",
            "check",
            "auth",
            "verif",
            "serial",
            "regist",
        ]

        if self.current_function is None:
            return []

        blocks: list[dict[str, Any]] = self.functions[self.current_function].get("blocks", [])
        for block in blocks:
            for op in block.get("ops", []):
                disasm = op.get("disasm", "").lower()

                # Check for license keywords in disassembly
                if any(keyword in disasm for keyword in license_keywords):
                    license_patterns.append(
                        {
                            "block_addr": block["offset"],
                            "op_addr": op["offset"],
                            "disasm": op["disasm"],
                            "type": "license_keyword",
                        },
                    )

                # Check for comparison followed by conditional jump
                if ("cmp" in disasm or "test" in disasm) and block.get("jump") and block.get("fail"):
                    license_patterns.append(
                        {
                            "block_addr": block["offset"],
                            "op_addr": op["offset"],
                            "disasm": op["disasm"],
                            "type": "conditional_check",
                        },
                    )

        return license_patterns

    def generate_interactive_html(self, function_name: str, license_patterns: list[dict[str, Any]], output_file: str) -> bool:
        """Generate an interactive HTML visualization of the CFG."""
        try:
            graph_data = self.get_graph_data(layout_type="spring")
            if not graph_data:
                return False

            from ...utils.reporting.html_templates import close_html, get_cfg_html_template

            # Create the HTML content using common template
            html_content = (
                get_cfg_html_template(function_name)
                + f"""
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
                            {"".join(f"<li>{pattern['type']} at 0x{pattern['op_addr']:x}</li>" for pattern in license_patterns[:5])}
                            {"<li>...</li>" if len(license_patterns) > 5 else ""}
                        </ul>
                    </div>
                </div>
                <div id="tooltip"></div>
                <canvas id="cfg-canvas" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;"></canvas>
                <script>
                    const canvas = document.getElementById('cfg-canvas');
                    const ctx = canvas.getContext('2d');
                    const tooltip = document.getElementById('tooltip');

                    canvas.width = window.innerWidth;
                    canvas.height = window.innerHeight;

                    let scale = 1;
                    let offsetX = canvas.width / 2;
                    let offsetY = 100;
                    const graphData = {json.dumps(graph_data)};
                    const licensePatterns = {json.dumps(license_patterns)};

                    function drawNode(node, x, y) {{
                        ctx.save();
                        ctx.translate(offsetX, offsetY);
                        ctx.scale(scale, scale);

                        const isLicenseCheck = licensePatterns.some(p => p.op_addr === node.addr);
                        ctx.fillStyle = isLicenseCheck ? '#ffcccc' : (node.is_entry ? '#ccffcc' : '#ccccff');
                        ctx.strokeStyle = '#333';
                        ctx.lineWidth = 2;

                        ctx.fillRect(x - 60, y - 20, 120, 40);
                        ctx.strokeRect(x - 60, y - 20, 120, 40);

                        ctx.fillStyle = '#000';
                        ctx.font = '12px monospace';
                        ctx.textAlign = 'center';
                        ctx.fillText(`0x${{node.addr.toString(16)}}`, x, y);

                        ctx.restore();
                    }}

                    function drawEdge(from, to) {{
                        ctx.save();
                        ctx.translate(offsetX, offsetY);
                        ctx.scale(scale, scale);

                        ctx.strokeStyle = '#666';
                        ctx.lineWidth = 1.5;
                        ctx.beginPath();
                        ctx.moveTo(from.x, from.y + 20);
                        ctx.lineTo(to.x, to.y - 20);
                        ctx.stroke();

                        const angle = Math.atan2(to.y - from.y, to.x - from.x);
                        ctx.save();
                        ctx.translate(to.x, to.y - 20);
                        ctx.rotate(angle - Math.PI / 2);
                        ctx.beginPath();
                        ctx.moveTo(0, 0);
                        ctx.lineTo(-5, -10);
                        ctx.lineTo(5, -10);
                        ctx.closePath();
                        ctx.fill();
                        ctx.restore();

                        ctx.restore();
                    }}

                    function render() {{
                        ctx.clearRect(0, 0, canvas.width, canvas.height);

                        if (!graphData.nodes || graphData.nodes.length === 0) return;

                        graphData.edges?.forEach(edge => {{
                            const fromNode = graphData.nodes.find(n => n.addr === edge.from);
                            const toNode = graphData.nodes.find(n => n.addr === edge.to);
                            if (fromNode && toNode) {{
                                drawEdge(fromNode, toNode);
                            }}
                        }});

                        graphData.nodes.forEach(node => {{
                            drawNode(node, node.x || 0, node.y || 0);
                        }});
                    }}

                    document.getElementById('zoom-in').addEventListener('click', () => {{
                        scale *= 1.2;
                        render();
                    }});

                    document.getElementById('zoom-out').addEventListener('click', () => {{
                        scale /= 1.2;
                        render();
                    }});

                    document.getElementById('reset').addEventListener('click', () => {{
                        scale = 1;
                        offsetX = canvas.width / 2;
                        offsetY = 100;
                        render();
                    }});

                    let isDragging = false;
                    let lastX, lastY;

                    canvas.addEventListener('mousedown', (e) => {{
                        isDragging = true;
                        lastX = e.clientX;
                        lastY = e.clientY;
                    }});

                    canvas.addEventListener('mousemove', (e) => {{
                        if (isDragging) {{
                            offsetX += e.clientX - lastX;
                            offsetY += e.clientY - lastY;
                            lastX = e.clientX;
                            lastY = e.clientY;
                            render();
                        }}

                        const rect = canvas.getBoundingClientRect();
                        const x = (e.clientX - rect.left - offsetX) / scale;
                        const y = (e.clientY - rect.top - offsetY) / scale;

                        const hoveredNode = graphData.nodes?.find(n => {{
                            const nx = n.x || 0;
                            const ny = n.y || 0;
                            return x >= nx - 60 && x <= nx + 60 && y >= ny - 20 && y <= ny + 20;
                        }});

                        if (hoveredNode) {{
                            const pattern = licensePatterns.find(p => p.op_addr === hoveredNode.addr);
                            tooltip.innerHTML = `<div style="position:absolute;left:${{e.clientX+10}}px;top:${{e.clientY+10}}px;background:#fff;border:1px solid #ccc;padding:8px;border-radius:4px;box-shadow:0 2px 8px rgba(0,0,0,0.15);z-index:1000;">
                                <strong>Address:</strong> 0x${{hoveredNode.addr.toString(16)}}<br/>
                                ${{pattern ? `<strong>Type:</strong> ${{pattern.type}}<br/><strong>Disasm:</strong> ${{pattern.disasm}}` : ''}}
                            </div>`;
                        }} else {{
                            tooltip.innerHTML = '';
                        }}
                    }});

                    canvas.addEventListener('mouseup', () => {{
                        isDragging = false;
                    }});

                    canvas.addEventListener('wheel', (e) => {{
                        e.preventDefault();
                        scale *= e.deltaY < 0 ? 1.1 : 0.9;
                        scale = Math.max(0.1, Math.min(scale, 10));
                        render();
                    }});

                    window.addEventListener('resize', () => {{
                        canvas.width = window.innerWidth;
                        canvas.height = window.innerHeight;
                        render();
                    }});

                    render();
                </script>
            """
                + close_html()
            )

            # Write HTML to file
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error generating HTML visualization: %s", e)
            return False

    def export_graph_image(self, output_file: str, format: str = "png") -> bool:  # pylint: disable=redefined-builtin
        """Export the CFG as an image file."""
        if not MATPLOTLIB_AVAILABLE or not NETWORKX_AVAILABLE:
            self.logger.exception("Matplotlib or NetworkX not available for image export")
            return False

        try:
            layout = self.get_graph_layout(layout_type="spring")
            if not layout:
                return False

            # Create matplotlib figure
            plt.figure(figsize=(12, 9))

            # Draw the graph
            nx.draw_networkx(
                self.graph,
                pos=layout,
                with_labels=True,
                node_color="lightblue",
                node_size=500,
                font_size=8,
                arrows=True,
                connectionstyle="arc3,rad=0.1",
            )

            # Add title
            plt.title(f"Control Flow Graph: {self.current_function}")

            # Remove axes
            plt.axis("off")

            # Save the figure
            plt.savefig(output_file, format=format, dpi=300, bbox_inches="tight")
            plt.close()

            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error exporting graph image: %s", e)
            return False

    def export_dot_file(self, output_file: str) -> bool:
        """Export the CFG as a DOT file."""
        if not NETWORKX_AVAILABLE:
            self.logger.exception("NetworkX not available for DOT export")
            return False

        try:
            nx.drawing.nx_pydot.write_dot(self.graph, output_file)
            return True
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error exporting DOT file: %s", e)
            return False

    def analyze_cfg(self, binary_path: str | None = None) -> dict[str, Any]:
        """Perform comprehensive advanced CFG analysis on a binary.

        Args:
            binary_path: Path to binary file to analyze (optional)

        Returns:
            Dictionary containing comprehensive CFG analysis results

        """
        results: dict[str, Any] = {
            "binary_path": binary_path or self.binary_path,
            "functions_analyzed": 0,
            "complexity_metrics": {},
            "license_patterns": [],
            "graph_data": None,
            "advanced_analysis": {},
            "call_graph_analysis": {},
            "vulnerability_analysis": {},
            "similarity_analysis": {},
            "ai_analysis": {},
            "comprehensive_metrics": {},
            "errors": [],
        }

        try:
            if binary_path:
                self.binary_path = binary_path

            if not self.binary_path:
                error_msg = "No binary path specified for advanced CFG analysis"
                self.logger.exception(error_msg)
                errors_list = results.get("errors")
                if isinstance(errors_list, list):
                    errors_list.append(error_msg)
                return results

            if not self.load_binary(self.binary_path):
                error_msg = f"Failed to load binary for advanced CFG analysis: {self.binary_path}"
                self.logger.exception(error_msg)
                errors_list = results.get("errors")
                if isinstance(errors_list, list):
                    errors_list.append(error_msg)
                return results

            self.logger.info("Starting comprehensive CFG analysis for: %s", self.binary_path)

            function_list = self.get_function_list()
            results["functions_analyzed"] = len(function_list)

            all_license_patterns: list[dict[str, Any]] = []
            for function_name in function_list[:20]:
                try:
                    if self.set_current_function(function_name):
                        if patterns := self.find_license_check_patterns():
                            all_license_patterns.extend(patterns)
                            self.logger.debug("Found %d patterns in function %s", len(patterns), function_name)
                except Exception as e:
                    self.logger.debug("Error analyzing function %s: %s", function_name, e)

            results["license_patterns"] = all_license_patterns

            try:
                results["complexity_metrics"] = self.get_complexity_metrics()
                results["comprehensive_metrics"] = self.get_code_complexity_analysis()
            except Exception as e:
                self.logger.debug("Error getting complexity metrics: %s", e)
                results["complexity_metrics"] = {}

            try:
                results["advanced_analysis"] = self.get_advanced_analysis_results()
            except Exception as e:
                self.logger.debug("Error getting advanced analysis: %s", e)
                errors_list = results.get("errors")
                if isinstance(errors_list, list):
                    errors_list.append(f"Advanced analysis error: {e}")

            try:
                results["call_graph_analysis"] = self.get_call_graph_metrics()
            except Exception as e:
                self.logger.debug("Error getting call graph analysis: %s", e)

            try:
                results["vulnerability_analysis"] = self.get_vulnerability_patterns()
            except Exception as e:
                self.logger.debug("Error getting vulnerability analysis: %s", e)

            try:
                results["similarity_analysis"] = {
                    "function_similarities": self.function_similarities,
                    "similarity_clusters": self._generate_similarity_clusters(),
                }
            except Exception as e:
                self.logger.debug("Error getting similarity analysis: %s", e)

            try:
                if ai_cache := self.analysis_cache.get("ai_analysis", {}):
                    results["ai_analysis"] = ai_cache
            except Exception as e:
                self.logger.debug("Error getting AI analysis: %s", e)

            try:
                if function_list and len(function_list) > 0:
                    comprehensive = results.get("comprehensive_metrics")
                    complex_functions: list[Any] = []
                    if isinstance(comprehensive, dict):
                        hcf = comprehensive.get("high_complexity_functions")
                        if isinstance(hcf, list):
                            complex_functions = hcf
                    if complex_functions:
                        target_function = complex_functions[0]["function"]
                    else:
                        target_function = function_list[0]

                    if self.set_current_function(target_function):
                        if graph_data := self.get_graph_data():
                            if isinstance(graph_data, dict):
                                graph_data["selected_function"] = target_function
                            results["graph_data"] = graph_data
            except Exception as e:
                self.logger.debug("Error getting graph data: %s", e)

            try:
                results["summary"] = self._generate_analysis_summary(results)
            except Exception as e:
                self.logger.debug("Error generating summary: %s", e)

            self.logger.info(
                "Advanced CFG analysis completed. Analyzed %d functions with comprehensive metrics",
                results["functions_analyzed"],
            )

        except Exception as e:
            error_msg = f"Advanced CFG analysis failed: {e}"
            self.logger.exception("Advanced CFG analysis failed: %s", e)
            errors_list = results.get("errors")
            if isinstance(errors_list, list):
                errors_list.append(error_msg)

        return results

    def _generate_similarity_clusters(self) -> list[list[str]]:
        """Generate clusters of similar functions."""
        clusters: list[list[str]] = []
        processed: set[str] = set()

        for similarity_key, similarity_score in self.function_similarities.items():
            if similarity_score > 0.7:
                func1, func2 = similarity_key.split(":")

                cluster_found = False
                for cluster in clusters:
                    if func1 in cluster or func2 in cluster:
                        if func1 not in cluster:
                            cluster.append(func1)
                        if func2 not in cluster:
                            cluster.append(func2)
                        cluster_found = True
                        break

                if not cluster_found:
                    clusters.append([func1, func2])

                processed.add(func1)
                processed.add(func2)

        return clusters

    def _generate_analysis_summary(self, results: dict[str, Any]) -> dict[str, Any]:
        """Generate comprehensive analysis summary."""
        summary: dict[str, Any] = {
            "total_functions": results.get("functions_analyzed", 0),
            "license_related_functions": 0,
            "vulnerable_functions": 0,
            "high_complexity_functions": 0,
            "similar_function_clusters": 0,
            "call_graph_complexity": "unknown",
            "overall_risk_assessment": "unknown",
            "key_findings": [],
        }

        advanced = results.get("advanced_analysis")
        license_analysis: dict[str, Any] = {}
        if isinstance(advanced, dict):
            lva = advanced.get("license_validation_analysis")
            if isinstance(lva, dict):
                license_analysis = lva
        cfg_funcs = license_analysis.get("cfg_license_functions", [])
        summary["license_related_functions"] = len(cfg_funcs) if isinstance(cfg_funcs, list) else 0

        vuln_patterns = results.get("vulnerability_analysis")
        vulnerable_count = 0
        if isinstance(vuln_patterns, dict):
            for patterns in vuln_patterns.values():
                if isinstance(patterns, (list, tuple)):
                    vulnerable_count += len(patterns)
        summary["vulnerable_functions"] = vulnerable_count

        complexity_analysis = results.get("comprehensive_metrics")
        hcf_count = 0
        if isinstance(complexity_analysis, dict):
            hcf = complexity_analysis.get("high_complexity_functions")
            if isinstance(hcf, list):
                hcf_count = len(hcf)
        summary["high_complexity_functions"] = hcf_count

        similarity_analysis = results.get("similarity_analysis")
        sc_count = 0
        if isinstance(similarity_analysis, dict):
            sc = similarity_analysis.get("similarity_clusters")
            if isinstance(sc, list):
                sc_count = len(sc)
        summary["similar_function_clusters"] = sc_count

        findings: list[str] = []

        license_funcs = summary["license_related_functions"]
        if isinstance(license_funcs, int) and license_funcs > 0:
            findings.append(f"Identified {license_funcs} license validation functions")

        vuln_funcs = summary["vulnerable_functions"]
        if isinstance(vuln_funcs, int) and vuln_funcs > 0:
            findings.append(f"Found {vuln_funcs} potential vulnerability patterns")

        high_complexity = summary["high_complexity_functions"]
        if isinstance(high_complexity, int) and high_complexity > 0:
            findings.append(f"Detected {high_complexity} high-complexity functions")

        similar_clusters = summary["similar_function_clusters"]
        if isinstance(similar_clusters, int) and similar_clusters > 0:
            findings.append(f"Found {similar_clusters} clusters of similar functions")

        call_graph_metrics = results.get("call_graph_analysis")
        if isinstance(call_graph_metrics, dict):
            avg_calls_val = call_graph_metrics.get("avg_calls_per_function", 0)
            avg_calls: float = float(avg_calls_val) if isinstance(avg_calls_val, (int, float)) else 0.0
            if avg_calls > 5:
                summary["call_graph_complexity"] = "high"
                findings.append("High inter-function connectivity detected")
            elif avg_calls > 2:
                summary["call_graph_complexity"] = "medium"
            else:
                summary["call_graph_complexity"] = "low"

        risk_factors = 0
        vuln_check = summary["vulnerable_functions"]
        if isinstance(vuln_check, int):
            if vuln_check > 5:
                risk_factors += 2
            elif vuln_check > 0:
                risk_factors += 1

        license_check = summary["license_related_functions"]
        if isinstance(license_check, int) and license_check > 3:
            risk_factors += 1

        if summary["call_graph_complexity"] == "high":
            risk_factors += 1

        if risk_factors >= 3:
            summary["overall_risk_assessment"] = "high"
        elif risk_factors >= 1:
            summary["overall_risk_assessment"] = "medium"
        else:
            summary["overall_risk_assessment"] = "low"

        summary["key_findings"] = findings

        return summary

    def _show_error_dialog(self, title: str, message: str) -> None:
        """Show error dialog to user when in GUI mode."""
        if PYQT_AVAILABLE:
            try:
                QMessageBox.critical(None, title, message)
            except Exception as e:
                self.logger.exception("Failed to show error dialog: %s", e)
        self.logger.exception("%s: %s", title, message)

    def export_json(self, output_path: str) -> bool:
        """Export comprehensive CFG analysis to JSON format.

        This exports all analysis data including:
        - Function graphs with full node/edge data
        - Call graph relationships
        - Complexity metrics
        - Vulnerability patterns
        - License validation analysis
        - AI analysis results
        - Cross-reference data

        Args:
            output_path: Path to save the JSON file

        Returns:
            bool: True if export successful, False otherwise

        """
        try:
            self.logger.info("Exporting CFG analysis to JSON: %s", output_path)

            # Prepare comprehensive export data
            export_data = {
                "metadata": {
                    "binary_path": self.binary_path,
                    "export_timestamp": str(time.time()),
                    "export_version": "2.0",
                    "analysis_engines": {
                        "decompiler": self.decompiler is not None,
                        "vulnerability_engine": self.vulnerability_engine is not None,
                        "ai_engine": self.ai_engine is not None,
                        "string_analyzer": self.string_analyzer is not None,
                        "import_analyzer": self.import_analyzer is not None,
                        "scripting_engine": self.scripting_engine is not None,
                    },
                },
                "functions": {},
                "call_graph": {},
                "cross_references": self.cross_references,
                "function_similarities": self.function_similarities,
                "analysis_results": self.analysis_cache,
                "comprehensive_metrics": {},
            }

            # Export function data with full graph information
            for func_name, func_data in self.functions.items():
                function_export = {
                    "address": func_data.get("addr", 0),
                    "size": func_data.get("size", 0),
                    "complexity": func_data.get("complexity", 1),
                    "calls": func_data.get("calls", 0),
                    "type": func_data.get("type", "fcn"),
                    "blocks": [],
                    "edges": [],
                    "enhanced_data": func_data.get("enhanced_data", {}),
                }

                # Export graph data if available
                graph = func_data.get("graph")
                if graph and NETWORKX_AVAILABLE:
                    # Export nodes with all attributes
                    for node, node_data in graph.nodes(data=True):
                        block_export = {
                            "address": node,
                            "size": node_data.get("size", 0),
                            "instruction_count": node_data.get("instruction_count", 0),
                            "has_call": node_data.get("has_call", False),
                            "has_jump": node_data.get("has_jump", False),
                            "has_return": node_data.get("has_return", False),
                            "crypto_operations": node_data.get("crypto_operations", 0),
                            "license_operations": node_data.get("license_operations", 0),
                            "block_type": node_data.get("block_type", "unknown"),
                            "complexity_score": node_data.get("complexity_score", 0.0),
                            "instructions": [],
                        }

                        # Export individual instructions
                        ops = node_data.get("ops", [])
                        for op in ops:
                            instruction_export = {
                                "offset": op.get("offset", 0),
                                "size": op.get("size", 0),
                                "disasm": op.get("disasm", ""),
                                "type": op.get("type", ""),
                                "bytes": op.get("bytes", "").hex() if "bytes" in op and hasattr(op["bytes"], "hex") else "",
                            }
                            block_export["instructions"].append(instruction_export)

                        function_export["blocks"].append(block_export)

                    # Export edges with attributes
                    for source, target, edge_data in graph.edges(data=True):
                        edge_export = {
                            "source": source,
                            "target": target,
                            "type": edge_data.get("type", "unknown"),
                            "condition": edge_data.get("condition", ""),
                        }
                        function_export["edges"].append(edge_export)

                export_data["functions"][func_name] = function_export

            if self.call_graph and NETWORKX_AVAILABLE:
                call_graph_export: dict[str, list[dict[str, Any]]] = {
                    "nodes": [],
                    "edges": [],
                }

                # Export call graph nodes
                for node, node_data in self.call_graph.nodes(data=True):
                    call_graph_export["nodes"].append(
                        {
                            "function": node,
                            "address": node_data.get("addr", 0),
                            "size": node_data.get("size", 0),
                            "complexity": node_data.get("complexity", 1),
                        },
                    )

                # Export call graph edges
                for source, target, edge_data in self.call_graph.edges(data=True):
                    call_graph_export["edges"].append(
                        {
                            "source": source,
                            "target": target,
                            "type": edge_data.get("type", "function_call"),
                            "from_addr": edge_data.get("from_addr", ""),
                            "to_addr": edge_data.get("to_addr", ""),
                        },
                    )

                export_data["call_graph"] = call_graph_export

            # Get comprehensive metrics
            try:
                export_data["comprehensive_metrics"] = {
                    "complexity_metrics": self.get_code_complexity_analysis(),
                    "call_graph_metrics": self.get_call_graph_metrics(),
                    "vulnerability_patterns": self.get_vulnerability_patterns(),
                    "license_validation": self.get_license_validation_analysis(),
                    "cross_reference_analysis": self.get_cross_reference_analysis(),
                }
            except Exception as e:
                self.logger.warning("Failed to export some metrics: %s", e)

            def json_serializable(obj: object) -> object:
                """Convert non-serializable objects to JSON-friendly format.

                Args:
                    obj: Object to convert to JSON-serializable format

                Returns:
                    JSON-serializable representation of the object

                """
                if isinstance(obj, (nx.Graph, nx.DiGraph)):
                    return {
                        "nodes": list(obj.nodes()),
                        "edges": list(obj.edges()),
                        "graph_type": "networkx_graph",
                    }
                if hasattr(obj, "__dict__"):
                    return obj.__dict__
                if isinstance(obj, bytes):
                    return obj.hex()
                return obj.tolist() if hasattr(obj, "tolist") else str(obj)

            # Write JSON file with proper formatting
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, sort_keys=True, default=json_serializable)

            # Verify the file was written successfully
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                self.logger.info("Successfully exported CFG analysis to %s", output_path)

                # Log export statistics
                num_functions = len(export_data["functions"])
                num_blocks = sum(len(func.get("blocks", [])) for func in export_data["functions"].values())
                file_size_kb = os.path.getsize(output_path) / 1024

                self.logger.info("Export statistics: %s functions, %s blocks, %.2f KB", num_functions, num_blocks, file_size_kb)
                return True
            self.logger.exception("Export file verification failed")
            return False

        except Exception as e:
            self.logger.exception("Failed to export CFG to JSON: %s", e)
            self.logger.debug("Export error traceback: %s", traceback.format_exc())
            return False


def run_deep_cfg_analysis(app: Any) -> None:
    """Run deep CFG analysis.

    Args:
        app: Application instance with binary path and output methods

    """
    if not hasattr(app, "binary_path") or not app.binary_path:
        if hasattr(app, "update_output"):
            app.update_output.emit(log_message("[CFG Analysis] No binary selected."))
        return

    if hasattr(app, "update_output"):
        app.update_output.emit(log_message("[CFG Analysis] Starting deep CFG analysis..."))
    if hasattr(app, "analyze_status"):
        app.analyze_status.setText("Running CFG analysis...")

    def _emit_output(msg: str) -> None:
        if hasattr(app, "update_output"):
            app.update_output.emit(log_message(msg))

    def _set_status(msg: str) -> None:
        if hasattr(app, "analyze_status"):
            app.analyze_status.setText(msg)

    try:
        if not PEFILE_AVAILABLE:
            _emit_output("[CFG Analysis] pefile not available")
            _set_status("pefile not available")
            return

        if not CAPSTONE_AVAILABLE:
            _emit_output("[CFG Analysis] capstone not available")
            _set_status("capstone not available")
            return

        if not NETWORKX_AVAILABLE:
            _emit_output("[CFG Analysis] networkx not available")
            _set_status("networkx not available")
            return

        pe = pefile.PE(app.binary_path)
        if CAPSTONE_AVAILABLE and CS_MODE_64 is not None and CS_MODE_32 is not None:
            is_64bit = getattr(pe.FILE_HEADER, "Machine", 0) == 0x8664
            mode = CS_MODE_64 if is_64bit else CS_MODE_32
        else:
            mode = None

        text_section = next((s for s in pe.sections if b".text" in s.Name), None)
        if not text_section:
            _emit_output("[CFG Analysis] No .text section found")
            _set_status("CFG analysis failed")
            return

        code_data = text_section.get_data()
        code_addr = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress

        if CAPSTONE_AVAILABLE and mode is not None and Cs is not None and CS_ARCH_X86 is not None:
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True
        else:
            _emit_output("[CFG Analysis] Capstone not available")
            _set_status("Capstone not available")
            return

        _emit_output("[CFG Analysis] Disassembling code...")

        instructions = list(md.disasm(code_data, code_addr))
        _emit_output(f"[CFG Analysis] Disassembled {len(instructions)} instructions")

        _emit_output("[CFG Analysis] Building control flow graph...")

        G = nx.DiGraph()

        for insn_ in instructions:
            G.add_node(insn_.address, instruction=f"{insn_.mnemonic} {insn_.op_str}")

        for i, insn in enumerate(instructions):
            if i + 1 < len(instructions) and insn.mnemonic not in ["ret", "jmp"]:
                G.add_edge(insn.address, instructions[i + 1].address, type="normal")

            if insn.mnemonic.startswith("j"):
                try:
                    if " 0x" in insn.op_str:
                        jump_target = int(insn.op_str.split("0x")[1], 16)
                        G.add_edge(insn.address, jump_target, type="jump")
                except (OSError, ValueError, RuntimeError) as e:
                    logger.exception("Error in cfg_explorer: %s", e)
                    _emit_output(f"[CFG Analysis] Error parsing jump: {e}")

        _emit_output("[CFG Analysis] Saving CFG visualization...")

        try:
            nx.drawing.nx_pydot.write_dot(G, "full_cfg.dot")
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error in cfg_explorer: %s", e)
            _emit_output(f"[CFG Analysis] Could not write DOT file: {e}")

        _emit_output("[CFG Analysis] Analyzing for license checks...")

        license_keywords = ["licens", "registr", "activ", "serial", "key", "trial", "valid"]

        license_nodes: list[Any] = []
        for node, data in G.nodes(data=True):
            instruction = data.get("instruction", "").lower()
            if any(keyword in instruction for keyword in license_keywords):
                license_nodes.append(node)

        _emit_output(f"[CFG Analysis] Found {len(license_nodes)} license-related nodes")

        if license_nodes:
            license_subgraph = G.subgraph(license_nodes).copy()

            for node_ in list(license_subgraph.nodes()):
                predecessors = list(G.predecessors(node_))
                successors = list(G.successors(node_))

                license_subgraph.add_nodes_from(predecessors)
                license_subgraph.add_nodes_from(successors)

                for pred in predecessors:
                    license_subgraph.add_edge(pred, node_, **G.get_edge_data(pred, node_, {}))

                for succ in successors:
                    license_subgraph.add_edge(node_, succ, **G.get_edge_data(node_, succ, {}))

            try:
                nx.drawing.nx_pydot.write_dot(license_subgraph, "license_cfg.dot")
            except (OSError, ValueError, RuntimeError) as e:
                logger.exception("Error in cfg_explorer: %s", e)
                _emit_output(f"[CFG Analysis] Could not write license DOT file: {e}")

            try:
                if SUBPROCESS_AVAILABLE:
                    if dot_path := shutil.which("dot"):
                        subprocess.run(
                            [dot_path, "-Tsvg", "-o", "license_cfg.svg", "license_cfg.dot"],
                            check=False,
                            shell=False,
                        )
                        _emit_output("[CFG Analysis] Generated license_cfg.svg")
                    else:
                        _emit_output("[CFG Analysis] GraphViz 'dot' command not found in PATH")
            except (OSError, ValueError, RuntimeError) as e:
                logger.exception("Error in cfg_explorer: %s", e)
                _emit_output(f"[CFG Analysis] Could not generate SVG: {e}")

        _emit_output("[CFG Analysis] Analysis complete")
        _set_status("CFG analysis complete")

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in cfg_explorer: %s", e)
        _emit_output(f"[CFG Analysis] Error: {e}")
        _set_status(f"CFG analysis error: {e}")


def run_cfg_explorer(app: Any) -> None:
    """Initialize and run the CFG explorer with GUI integration.

    Args:
        app: Application instance with binary path and output methods

    """
    if not PYQT_AVAILABLE:
        logger.warning("PyQt6 not available - cannot run GUI version")
        return

    def _emit_output(msg: str) -> None:
        if hasattr(app, "update_output"):
            app.update_output.emit(log_message(msg))

    _emit_output("[CFG Explorer] Initializing CFG explorer...")

    if not hasattr(app, "binary_path") or not app.binary_path:
        _emit_output("[CFG Explorer] No binary path specified")

        parent_widget = app if hasattr(app, "parent") else None
        binary_path, _ = QFileDialog.getOpenFileName(
            parent_widget,
            "Select Binary",
            "",
            "All Files (*)",
        )

        if not binary_path:
            _emit_output("[CFG Explorer] Cancelled")
            return

        app.binary_path = binary_path

    explorer = CFGExplorer(app.binary_path)

    _emit_output(f"[CFG Explorer] Loading binary: {app.binary_path}")
    if explorer.load_binary():
        _emit_output(f"[CFG Explorer] Loaded binary: {app.binary_path}")
        if hasattr(app, "cfg_explorer_instance"):
            app.cfg_explorer_instance = explorer

        function_list = explorer.get_function_list()

        parent_widget = app if hasattr(app, "parent") else None
        function_name, ok = QInputDialog.getItem(
            parent_widget,
            "Select Function",
            "Select a function to analyze:",
            function_list,
            0,
            False,
        )

        if not ok:
            _emit_output("[CFG Explorer] Cancelled")
            return

        if explorer.set_current_function(function_name):
            _emit_output(f"[CFG Explorer] Analyzing function: {function_name}")

            if license_patterns := explorer.find_license_check_patterns():
                _emit_output(
                    f"[CFG Explorer] Found {len(license_patterns)} potential license check patterns in {function_name}",
                )

                for pattern in license_patterns:
                    _emit_output(
                        f"[CFG Explorer] {pattern['type']} at 0x{pattern['op_addr']:x}: {pattern['disasm']}",
                    )

            else:
                _emit_output("[CFG Explorer] No license check patterns found")
        else:
            _emit_output(f"[CFG Explorer] Failed to set function: {function_name}")
    else:
        _emit_output(f"[CFG Explorer] Failed to load binary: {app.binary_path}")


def log_message(message: str) -> str:
    """Format log message."""
    return message


__all__ = ["CFGExplorer", "run_cfg_explorer", "run_deep_cfg_analysis"]
