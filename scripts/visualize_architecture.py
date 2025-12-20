"""A script to visualize the architecture of the Intellicrack project.

Optimized version with:
- Multiple layout algorithms (sfdp, hierarchical, radial)
- LOD clustering for large graphs
- Search trie with autocomplete
- Edge bundling for visual clarity
- Path finding between nodes
- WebGL rendering via Sigma.js
- Virtual lazy rendering (progressive display)
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import math
import os
import re
import subprocess  # noqa: S404
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, ClassVar


try:
    import networkx as nx
except ImportError as e:
    print(f"Error: Missing required libraries. {e}")
    print("Please run: pip install networkx")
    sys.exit(1)


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ClusterManager:
    """Manages hierarchical clustering of nodes for LOD rendering."""

    def __init__(self, graph: nx.DiGraph) -> None:
        """Initialize the cluster manager with a graph."""
        self.graph = graph
        self.clusters: dict[str, set[str]] = defaultdict(set)
        self.cluster_meta: dict[str, dict[str, Any]] = {}
        self.node_to_cluster: dict[str, str] = {}

    def build_clusters(self, depth: int = 2) -> None:
        """Group nodes by their parent module at specified depth."""
        for node_id in self.graph.nodes:
            parts = node_id.replace('::', '.').split('.')
            if len(parts) >= depth:
                cluster_id = '.'.join(parts[:depth])
            else:
                cluster_id = parts[0] if parts else 'root'

            self.clusters[cluster_id].add(node_id)
            self.node_to_cluster[node_id] = cluster_id

        for cluster_id, members in self.clusters.items():
            types_count: dict[str, int] = defaultdict(int)
            for node_id in members:
                if node_id in self.graph.nodes:
                    node_type = self.graph.nodes[node_id].get('type', 'unknown')
                    types_count[node_type] += 1

            self.cluster_meta[cluster_id] = {
                'size': len(members),
                'modules': types_count.get('module', 0),
                'classes': types_count.get('class', 0),
                'functions': types_count.get('function', 0),
                'structs': types_count.get('struct', 0),
                'children': sorted(members),
            }


class EdgeBundler:
    """Bundles edges by direction and proximity to reduce visual clutter."""

    MIN_BUNDLE_SIZE = 4

    def __init__(self, positions: dict[str, dict[str, float]]) -> None:
        """Initialize the edge bundler with node positions."""
        self.positions = positions

    def bundle_edges(
        self, edges: list[dict[str, Any]], angle_buckets: int = 24, region_size: float = 300.0
    ) -> list[dict[str, Any]]:
        """Apply edge bundling based on direction and spatial proximity."""
        edge_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for edge in edges:
            from_pos = self.positions.get(edge['from'], {'x': 0, 'y': 0})
            to_pos = self.positions.get(edge['to'], {'x': 0, 'y': 0})

            dx = to_pos['x'] - from_pos['x']
            dy = to_pos['y'] - from_pos['y']

            if dx == 0 and dy == 0:
                edge_groups['zero'].append(edge)
                continue

            angle = math.atan2(dy, dx)
            angle_bucket = int((angle + math.pi) / (2 * math.pi) * angle_buckets)

            mid_x = int((from_pos['x'] + to_pos['x']) / 2 / region_size)
            mid_y = int((from_pos['y'] + to_pos['y']) / 2 / region_size)

            key = f"{angle_bucket}_{mid_x}_{mid_y}"
            edge_groups[key].append(edge)

        bundled_edges: list[dict[str, Any]] = []

        for group_edges in edge_groups.values():
            if len(group_edges) < self.MIN_BUNDLE_SIZE:
                bundled_edges.extend(group_edges)
                continue

            for i, edge in enumerate(group_edges):
                offset_factor = (i - len(group_edges) / 2) / len(group_edges)
                roundness = 0.15 + abs(offset_factor) * 0.2

                edge_copy = edge.copy()
                edge_copy['smooth'] = {
                    'enabled': True,
                    'type': 'curvedCW' if i % 2 == 0 else 'curvedCCW',
                    'roundness': roundness,
                }
                bundled_edges.append(edge_copy)

        return bundled_edges


class KnowledgeGraphGenerator:
    """Generates a comprehensive knowledge graph for Python and Rust projects."""

    MAX_LABEL_LENGTH = 30

    TYPE_COLORS: ClassVar[dict[str, str]] = {
        'module': '#4A90D9',
        'class': '#F5A623',
        'function': '#D0021B',
        'struct': '#7ED321',
        'variable': '#BD10E0',
        'external': '#9B9B9B',
        'cluster': '#50E3C2',
        'entry': '#FF4444',
    }

    def __init__(self, root_dir: Path, rust_root: Path | None = None) -> None:
        """Initialize the knowledge graph generator."""
        self.root_dir = root_dir.resolve()
        if self.root_dir.name != 'intellicrack':
            possible_sub = self.root_dir / 'intellicrack'
            if possible_sub.exists():
                self.root_dir = possible_sub

        self.repo_root = self.root_dir.parent
        self.rust_root = rust_root.resolve() if rust_root else None

        self.graph: nx.DiGraph = nx.DiGraph()
        self.module_map: dict[Path, str] = {}
        self.python_entry_points: set[str] = set()
        self.rust_calls_to_python: list[tuple[str, str]] = []
        self.cluster_manager: ClusterManager | None = None

    def build_graph(self) -> None:
        """Builds the complete knowledge graph."""
        logger.info("Starting Python analysis...")
        self._scan_python()

        if self.rust_root and self.rust_root.exists():
            logger.info("Starting Rust analysis...")
            self._scan_rust()
            self._link_languages()
        else:
            logger.warning("Rust root not found or not provided. Skipping Rust analysis.")

        logger.info(
            "Graph built with %d nodes and %d edges.",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
        )

        self.cluster_manager = ClusterManager(self.graph)
        self.cluster_manager.build_clusters(depth=2)
        logger.info("Built %d clusters.", len(self.cluster_manager.clusters))

    def _scan_python(self) -> None:
        """Scans Python files and parses deep structure."""
        try:
            for root, _, files in os.walk(self.root_dir):
                for file in files:
                    if file.endswith(".py"):
                        path = Path(root) / file
                        if 'tests' in path.parts or '__pycache__' in path.parts:
                            continue

                        module_name = self._get_module_name(path)
                        self.module_map[path] = module_name
                        self.graph.add_node(
                            module_name, type='module', lang='python', path=str(path), label=module_name
                        )
                        self._parse_python_file(path, module_name)
        except (PermissionError, OSError):
            logger.exception("Error identifying files in directory %s", self.root_dir)

    def _parse_python_file(self, path: Path, module_name: str) -> None:
        """Deep parses a Python file for classes, functions, and variables."""
        try:
            with open(path, encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(path))
        except Exception as e:
            logger.warning("Error parsing %s: %s", path, e)
            return

        imports_map: dict[str, str] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = alias.name
                    imports_map[alias.asname or alias.name] = target
                    self.graph.add_edge(module_name, target, type='imports')
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    module_base = node.module
                    if node.level > 0:
                        module_base = self._resolve_relative_import(module_name, node.module, node.level)
                    self.graph.add_edge(module_name, module_base, type='imports')
                    for alias in node.names:
                        full_target = f"{module_base}.{alias.name}"
                        imports_map[alias.asname or alias.name] = full_target

            elif isinstance(node, ast.ClassDef):
                class_id = f"{module_name}.{node.name}"
                self.graph.add_node(class_id, type='class', lang='python', label=node.name)
                self.graph.add_edge(module_name, class_id, type='defines')
                for base in node.bases:
                    if isinstance(base, ast.Name):
                        base_name = imports_map.get(base.id, base.id)
                        self.graph.add_edge(class_id, base_name, type='inherits')

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_id = f"{module_name}.{node.name}"
                args = [a.arg for a in node.args.args]
                self.graph.add_node(func_id, type='function', lang='python', label=node.name, args=str(args))
                self.graph.add_edge(module_name, func_id, type='defines')

                if node.name == 'main' and (
                    module_name.endswith('__main__') or 'intellicrack.main' in module_name
                ):
                    self.python_entry_points.add(func_id)

    def _scan_rust(self) -> None:
        """Scans Rust files using Regex for structure."""
        if not self.rust_root:
            return
        try:
            for root, _, files in os.walk(self.rust_root):
                for file in files:
                    if file.endswith(".rs"):
                        path = Path(root) / file
                        self._parse_rust_file(path)
        except (PermissionError, OSError):
            logger.exception("Error scanning Rust directory %s", self.rust_root)

    def _parse_rust_file(self, path: Path) -> None:
        """Parses a Rust file for basic entities."""
        try:
            with open(path, encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            logger.warning("Error reading Rust file %s: %s", path, e)
            return

        try:
            if self.rust_root:
                rel_path = path.relative_to(self.rust_root.parent)
                module_id = str(rel_path).replace(os.sep, '::').replace('.rs', '')
            else:
                module_id = path.stem
        except ValueError:
            module_id = path.stem

        self.graph.add_node(module_id, type='module', lang='rust', path=str(path), label=module_id)

        fn_pattern = re.compile(r'fn\s+([a-zA-Z0-9_]+)\s*\(')
        struct_pattern = re.compile(r'struct\s+([a-zA-Z0-9_]+)')

        for line in content.splitlines():
            if match := fn_pattern.search(line):
                fn_name = match.group(1)
                fn_id = f"{module_id}::{fn_name}"
                self.graph.add_node(fn_id, type='function', lang='rust', label=fn_name)
                self.graph.add_edge(module_id, fn_id, type='defines')

            if match := struct_pattern.search(line):
                struct_name = match.group(1)
                struct_id = f"{module_id}::{struct_name}"
                self.graph.add_node(struct_id, type='struct', lang='rust', label=struct_name)
                self.graph.add_edge(module_id, struct_id, type='defines')

            if 'intellicrack' in line and '.main' in line:
                self.rust_calls_to_python.append((module_id, "intellicrack.main"))

    def _link_languages(self) -> None:
        for rust_node, py_target in self.rust_calls_to_python:
            for node in self.graph.nodes:
                if py_target in node:
                    self.graph.add_edge(rust_node, node, type='calls_extern', lang='mixed')
                    logger.info("Linked Rust node %s to Python node %s", rust_node, node)

    def _get_module_name(self, path: Path) -> str:
        try:
            rel_path = path.relative_to(self.repo_root)
            return str(rel_path.with_suffix('')).replace(os.sep, '.')
        except ValueError:
            return path.stem

    @staticmethod
    def _resolve_relative_import(current_module: str, partial_module: str | None, level: int) -> str:
        parts = current_module.split('.')
        if level >= len(parts):
            return partial_module if partial_module else ""
        base = ".".join(parts[:-level])
        if partial_module:
            return f"{base}.{partial_module}"
        return base

    def export_graphml(self, output_path: Path) -> None:
        """Export the graph to GraphML format."""
        try:
            nx.write_graphml(self.graph, str(output_path))
            logger.info("GraphML saved to: %s", output_path)
        except Exception:
            logger.exception("Failed to save GraphML file:")

    def _calculate_hierarchical_layout(  # noqa: PLR6301
        self, filtered_graph: nx.DiGraph
    ) -> dict[str, dict[str, float]]:
        """Calculate hierarchical layout based on module depth."""
        logger.info("Calculating hierarchical layout...")
        layout_map: dict[str, dict[str, float]] = {}

        levels: dict[int, list[str]] = defaultdict(list)
        type_offset = {'module': 0, 'class': 1, 'function': 2, 'struct': 1, 'external': 3}

        for node_id in filtered_graph.nodes:
            depth = node_id.count('.') + node_id.count('::')
            node_type = filtered_graph.nodes[node_id].get('type', 'unknown')
            level = depth * 3 + type_offset.get(node_type, 0)
            levels[level].append(node_id)

        y_spacing = 120
        x_spacing = 60

        for level, node_ids in sorted(levels.items()):
            y = level * y_spacing
            sorted_nodes = sorted(node_ids)
            total_width = len(sorted_nodes) * x_spacing
            start_x = -total_width / 2

            for i, node_id in enumerate(sorted_nodes):
                layout_map[node_id] = {'x': start_x + (i * x_spacing), 'y': y}

        logger.info("Hierarchical layout calculated for %d nodes.", len(layout_map))
        return layout_map

    def _calculate_radial_layout(self, filtered_graph: nx.DiGraph) -> dict[str, dict[str, float]]:  # noqa: PLR6301
        """Calculate radial layout with entry point at center."""
        logger.info("Calculating radial layout...")
        layout_map: dict[str, dict[str, float]] = {}

        center_node = None
        for node_id in filtered_graph.nodes:
            if 'intellicrack.main' in node_id and filtered_graph.nodes[node_id].get('type') == 'module':
                center_node = node_id
                break

        if not center_node:
            center_node = next(iter(filtered_graph.nodes), None) if filtered_graph.nodes else None

        if not center_node:
            return layout_map

        layout_map[center_node] = {'x': 0, 'y': 0}

        try:
            lengths = nx.single_source_shortest_path_length(filtered_graph.to_undirected(), center_node)
        except nx.NetworkXError:
            lengths = {center_node: 0}
            for node in filtered_graph.nodes:
                if node != center_node:
                    lengths[node] = 1

        rings: dict[int, list[str]] = defaultdict(list)
        for node, dist in lengths.items():
            if node != center_node:
                rings[dist].append(node)

        ring_spacing = 200

        for ring_num, nodes_in_ring in sorted(rings.items()):
            radius = ring_num * ring_spacing
            sorted_nodes = sorted(nodes_in_ring)
            angle_step = 2 * math.pi / max(len(sorted_nodes), 1)

            for i, node_id in enumerate(sorted_nodes):
                angle = i * angle_step
                layout_map[node_id] = {'x': radius * math.cos(angle), 'y': radius * math.sin(angle)}

        logger.info("Radial layout calculated for %d nodes.", len(layout_map))
        return layout_map

    def _calculate_sfdp_layout(self, dot_file: Path) -> dict[str, dict[str, float]]:  # noqa: PLR6301
        """Calculates layout using sfdp and returns node positions."""
        logger.info("Calculating pre-loaded layout using sfdp (this may take a while)...")
        layout_map: dict[str, dict[str, float]] = {}

        try:
            json_output = subprocess.check_output(
                ['sfdp', '-K', 'sfdp', '-Goverlap=prism', '-Gmaxiter=500', '-Tjson', str(dot_file)],
                text=True,
                stderr=subprocess.PIPE,
            )

            data = json.loads(json_output)

            if 'objects' in data:
                for node in data['objects']:
                    name = node.get('name')
                    pos = node.get('pos')
                    if name and pos:
                        try:
                            x, y = map(float, pos.split(','))
                            layout_map[name] = {'x': x * 5, 'y': y * -5}
                        except ValueError:
                            pass

            logger.info("SFDP layout calculated for %d nodes.", len(layout_map))

        except subprocess.CalledProcessError as e:
            logger.exception("Graphviz layout calculation failed: %s", e.stderr)
        except FileNotFoundError:
            logger.warning("sfdp not found. Falling back to hierarchical layout.")
        except Exception:
            logger.exception("Error parsing layout JSON")

        return layout_map

    def _generate_dot_file(self, filtered_graph: nx.DiGraph, dot_path: Path) -> bool:  # noqa: PLR6301
        """Generate DOT file for external layout tools."""
        try:
            try:
                nx.drawing.nx_pydot.write_dot(filtered_graph, str(dot_path))
            except (ImportError, AttributeError):
                with open(dot_path, 'w', encoding='utf-8') as f:
                    f.write('digraph "Intellicrack" {\n')
                    for n in filtered_graph.nodes:
                        safe_n = n.replace('"', '\\"')
                        f.write(f'  "{safe_n}";\n')
                    for u, v in filtered_graph.edges:
                        safe_u = u.replace('"', '\\"')
                        safe_v = v.replace('"', '\\"')
                        f.write(f'  "{safe_u}" -> "{safe_v}";\n')
                    f.write('}\n')
            return True
        except Exception:
            logger.exception("Failed to generate DOT file.")
            return False

    def generate_interactive_html(  # noqa: PLR0914
        self,
        output_path: Path,
        layout_method: str = 'sfdp',
        *,
        enable_clustering: bool = True,
    ) -> None:
        """Generates a standalone HTML file with all optimizations."""
        logger.info("Filtering graph for visualization...")

        internal_nodes = {
            n for n in self.graph.nodes if n.startswith('intellicrack.') or n.startswith('intellicrack-launcher')
        }

        boundary_nodes: set[str] = set()
        for u in internal_nodes:
            for v in self.graph.successors(u):
                if v not in internal_nodes:
                    boundary_nodes.add(v)

        candidates = internal_nodes.union(boundary_nodes)
        nodes_to_keep = {n for n in candidates if self.graph.nodes[n].get('type') != 'variable'}

        filtered_graph = self.graph.subgraph(nodes_to_keep).copy()

        logger.info(
            "Visualization graph: %d nodes (Original: %d)", len(filtered_graph), self.graph.number_of_nodes()
        )

        dot_path = output_path.with_suffix('.dot')
        positions: dict[str, dict[str, float]] = {}

        if layout_method == 'hierarchical':
            positions = self._calculate_hierarchical_layout(filtered_graph)
        elif layout_method == 'radial':
            positions = self._calculate_radial_layout(filtered_graph)
        else:
            if self._generate_dot_file(filtered_graph, dot_path):
                positions = self._calculate_sfdp_layout(dot_path)
                try:
                    if dot_path.exists():
                        dot_path.unlink()
                except OSError:
                    logger.debug("Could not delete temporary dot file: %s", dot_path)

            if not positions:
                logger.info("Falling back to hierarchical layout...")
                positions = self._calculate_hierarchical_layout(filtered_graph)

        nodes_data: list[dict[str, Any]] = []
        edges_data: list[dict[str, Any]] = []
        clusters_data: dict[str, dict[str, Any]] = {}

        if enable_clustering and self.cluster_manager:
            for cluster_id, meta in self.cluster_manager.cluster_meta.items():
                if any(child.startswith('intellicrack.') for child in meta['children']):
                    clusters_data[cluster_id] = {
                        'id': cluster_id,
                        'label': cluster_id.split('.')[-1],
                        'size': meta['size'],
                        'children': meta['children'],
                        'modules': meta['modules'],
                        'classes': meta['classes'],
                        'functions': meta['functions'],
                    }

        entry_point_id: str | None = None

        for node_id, attrs in filtered_graph.nodes(data=True):
            node_type = attrs.get('type', 'unknown')

            if node_id in boundary_nodes:
                node_type = 'external'

            label = attrs.get('label', node_id.split('.')[-1].split('::')[-1])
            if len(label) > self.MAX_LABEL_LENGTH:
                label = label[: self.MAX_LABEL_LENGTH - 3] + "..."

            color = self.TYPE_COLORS.get(node_type, '#D2E5FF')

            size_map = {'module': 8, 'class': 6, 'struct': 6, 'function': 4, 'external': 4}
            size = size_map.get(node_type, 3)

            if not entry_point_id:
                if 'intellicrack.main' in node_id and node_type == 'module':
                    entry_point_id = node_id
                elif node_id == 'intellicrack-launcher::src::lib' and node_type == 'module':
                    entry_point_id = node_id

            if node_id == entry_point_id:
                color = '#FF4444'
                size = 12

            cluster_id = self.cluster_manager.node_to_cluster.get(node_id, '') if self.cluster_manager else ''

            node_data: dict[str, Any] = {
                'id': node_id,
                'label': label,
                'color': color,
                'type': node_type,
                'size': size,
                'cluster': cluster_id,
            }

            if node_id in positions:
                node_data['x'] = positions[node_id]['x']
                node_data['y'] = positions[node_id]['y']

            nodes_data.append(node_data)

        for u, v, _attrs in filtered_graph.edges(data=True):
            edge_data: dict[str, Any] = {
                'source': u,
                'target': v,
            }
            edges_data.append(edge_data)

        if positions:
            bundler = EdgeBundler(positions)
            vis_edges = [{'from': e['source'], 'to': e['target']} for e in edges_data]
            bundled = bundler.bundle_edges(vis_edges)
            edges_data = [{'source': e['from'], 'target': e['to'], **{k: v for k, v in e.items() if k not in {'from', 'to'}}} for e in bundled]

        json_nodes = json.dumps(nodes_data)
        json_edges = json.dumps(edges_data)
        json_clusters = json.dumps(clusters_data)
        json_entry = json.dumps(entry_point_id) if entry_point_id else "null"
        json_colors = json.dumps(self.TYPE_COLORS)

        html_content = self._generate_html_template(json_nodes, json_edges, json_clusters, json_entry, json_colors)

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info("Interactive HTML saved to: %s", output_path)
        except Exception:
            logger.exception("Failed to save HTML file:")

    def _generate_html_template(  # noqa: PLR6301
        self,
        json_nodes: str,
        json_edges: str,
        json_clusters: str,
        json_entry: str,
        json_colors: str,
    ) -> str:
        """Generate the complete HTML template with all JavaScript features."""
        return f'''<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Intellicrack Architecture Graph</title>
  <script src="https://unpkg.com/graphology@0.25.4/dist/graphology.umd.min.js"></script>
  <script src="https://unpkg.com/sigma@2.4.0/build/sigma.min.js"></script>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #1a1a2e; color: #eee; overflow: hidden; }}
    #container {{ width: 100vw; height: 100vh; }}
    #loading {{ position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: rgba(0,0,0,0.9); padding: 30px 50px; border-radius: 12px; z-index: 9999; text-align: center; }}
    #loading h2 {{ margin-bottom: 15px; color: #667eea; }}
    .progress-bar {{ width: 200px; height: 6px; background: #333; border-radius: 3px; overflow: hidden; }}
    .progress-fill {{ height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); width: 0%; transition: width 0.3s; }}
    #controls {{ position: fixed; top: 15px; right: 15px; width: 320px; background: rgba(26,26,46,0.95); border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); z-index: 1000; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); }}
    .controls-header {{ padding: 15px 20px; border-bottom: 1px solid rgba(255,255,255,0.1); }}
    .controls-header h3 {{ font-size: 16px; font-weight: 600; }}
    .controls-body {{ padding: 15px 20px; }}
    .search-container {{ position: relative; margin-bottom: 15px; }}
    #search {{ width: 100%; padding: 10px 15px; border: 1px solid rgba(255,255,255,0.2); border-radius: 8px; background: rgba(255,255,255,0.05); color: #fff; font-size: 14px; }}
    #search:focus {{ outline: none; border-color: #667eea; }}
    #search-results {{ position: absolute; top: 100%; left: 0; right: 0; background: rgba(26,26,46,0.98); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; max-height: 300px; overflow-y: auto; display: none; z-index: 1001; margin-top: 5px; }}
    .search-result {{ padding: 10px 15px; cursor: pointer; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid rgba(255,255,255,0.05); }}
    .search-result:hover {{ background: rgba(102,126,234,0.2); }}
    .result-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
    .result-label {{ flex: 1; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .result-type {{ font-size: 11px; color: #888; background: rgba(255,255,255,0.1); padding: 2px 8px; border-radius: 10px; }}
    .legend {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 15px; }}
    .legend-item {{ display: flex; align-items: center; gap: 8px; font-size: 12px; }}
    .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; }}
    .view-controls {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    .view-btn {{ padding: 6px 12px; font-size: 11px; border: 1px solid rgba(255,255,255,0.2); background: transparent; color: #ccc; border-radius: 6px; cursor: pointer; transition: all 0.2s; }}
    .view-btn:hover {{ border-color: #667eea; color: #667eea; }}
    .view-btn.active {{ background: #667eea; border-color: #667eea; color: white; }}
    #panel {{ position: fixed; top: 15px; left: 15px; width: 380px; max-height: calc(100vh - 30px); background: rgba(26,26,46,0.95); border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); z-index: 1000; display: none; overflow: hidden; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); }}
    #panel.visible {{ display: block; }}
    .panel-header {{ padding: 15px 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; justify-content: space-between; align-items: center; }}
    .panel-title {{ font-weight: 600; font-size: 14px; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .panel-close {{ background: rgba(255,255,255,0.2); border: none; color: white; width: 28px; height: 28px; border-radius: 50%; cursor: pointer; font-size: 18px; }}
    .panel-close:hover {{ background: rgba(255,255,255,0.3); }}
    .node-info {{ padding: 15px 20px; background: rgba(0,0,0,0.2); border-bottom: 1px solid rgba(255,255,255,0.1); }}
    .info-row {{ display: flex; margin-bottom: 8px; font-size: 13px; }}
    .info-label {{ font-weight: 600; color: #888; width: 80px; flex-shrink: 0; }}
    .info-value {{ color: #eee; word-break: break-all; }}
    .action-bar {{ padding: 12px 20px; background: rgba(255,193,7,0.1); border-bottom: 1px solid rgba(255,193,7,0.2); display: flex; gap: 8px; flex-wrap: wrap; }}
    .action-btn {{ padding: 6px 12px; font-size: 11px; border: none; border-radius: 6px; cursor: pointer; font-weight: 500; }}
    .action-btn.incoming {{ background: #28a745; color: white; }}
    .action-btn.outgoing {{ background: #dc3545; color: white; }}
    .action-btn.both {{ background: #667eea; color: white; }}
    .action-btn.clear {{ background: #6c757d; color: white; }}
    .action-btn.path {{ background: #17a2b8; color: white; }}
    .panel-content {{ max-height: calc(100vh - 280px); overflow-y: auto; }}
    .section {{ border-bottom: 1px solid rgba(255,255,255,0.1); }}
    .section-header {{ padding: 12px 20px; background: rgba(255,255,255,0.03); font-weight: 600; font-size: 13px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }}
    .section-header:hover {{ background: rgba(255,255,255,0.06); }}
    .section-badge {{ padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
    .section-badge.out {{ background: #dc3545; }}
    .section-badge.in {{ background: #28a745; }}
    .connection-list {{ list-style: none; max-height: 200px; overflow-y: auto; }}
    .connection-list.collapsed {{ display: none; }}
    .connection-item {{ padding: 10px 20px 10px 30px; border-bottom: 1px solid rgba(255,255,255,0.05); cursor: pointer; display: flex; align-items: center; gap: 10px; }}
    .connection-item:hover {{ background: rgba(102,126,234,0.15); }}
    .conn-dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }}
    .conn-name {{ font-size: 12px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .conn-type {{ font-size: 10px; color: #888; background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; }}
    .no-conn {{ padding: 20px; text-align: center; color: #666; font-size: 12px; font-style: italic; }}
    #pathfinder {{ display: none; padding: 15px 20px; background: rgba(23,162,184,0.1); border-bottom: 1px solid rgba(23,162,184,0.2); }}
    #pathfinder.visible {{ display: block; }}
    .pf-row {{ display: flex; gap: 10px; align-items: center; margin-bottom: 10px; }}
    .pf-input {{ flex: 1; padding: 8px 12px; border: 1px solid rgba(255,255,255,0.2); border-radius: 6px; background: rgba(0,0,0,0.3); color: #fff; font-size: 12px; }}
    .pf-btn {{ padding: 8px 16px; background: #17a2b8; border: none; color: white; border-radius: 6px; cursor: pointer; font-size: 12px; }}
    #path-result {{ font-size: 12px; }}
    .path-step {{ display: inline-flex; align-items: center; gap: 5px; background: rgba(102,126,234,0.2); padding: 4px 10px; border-radius: 4px; margin: 2px; cursor: pointer; }}
    .path-step:hover {{ background: rgba(102,126,234,0.4); }}
    .path-arrow {{ color: #667eea; margin: 0 5px; }}
    #stats {{ position: fixed; bottom: 15px; left: 15px; background: rgba(26,26,46,0.95); padding: 12px 20px; border-radius: 8px; font-size: 12px; z-index: 1000; display: flex; gap: 20px; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); }}
    .stat {{ display: flex; gap: 5px; }}
    .stat-value {{ font-weight: 600; color: #667eea; }}
  </style>
</head>
<body>
  <div id="loading"><h2>Building Graph</h2><div class="progress-bar"><div class="progress-fill" id="progress"></div></div><p id="load-status">Initializing...</p></div>
  <div id="container"></div>
  <div id="controls"><div class="controls-header"><h3>Intellicrack Architecture</h3></div><div class="controls-body"><div class="search-container"><input type="text" id="search" autocomplete="off"><div id="search-results"></div></div><div class="legend"><div class="legend-item"><div class="legend-dot" style="background:#FF4444"></div>Entry</div><div class="legend-item"><div class="legend-dot" style="background:#4A90D9"></div>Module</div><div class="legend-item"><div class="legend-dot" style="background:#F5A623"></div>Class</div><div class="legend-item"><div class="legend-dot" style="background:#D0021B"></div>Function</div><div class="legend-item"><div class="legend-dot" style="background:#7ED321"></div>Struct</div><div class="legend-item"><div class="legend-dot" style="background:#9B9B9B"></div>External</div></div><div class="view-controls"><button class="view-btn active" onclick="setFilter('all',this)">All</button><button class="view-btn" onclick="setFilter('module',this)">Modules</button><button class="view-btn" onclick="setFilter('class',this)">Classes</button><button class="view-btn" onclick="setFilter('function',this)">Functions</button></div></div></div>
  <div id="panel"><div class="panel-header"><span class="panel-title" id="panel-title">Node</span><button class="panel-close" onclick="closePanel()">&times;</button></div><div class="node-info" id="node-info"></div><div class="action-bar"><button class="action-btn incoming" onclick="highlight('in')">Incoming</button><button class="action-btn outgoing" onclick="highlight('out')">Outgoing</button><button class="action-btn both" onclick="highlight('both')">Both</button><button class="action-btn clear" onclick="clearHL()">Clear</button><button class="action-btn path" onclick="togglePathfinder()">Find Path</button></div><div id="pathfinder"><div class="pf-row"><input type="text" class="pf-input" id="pf-to"><button class="pf-btn" onclick="findPath()">Go</button></div><div id="path-result"></div></div><div class="panel-content"><div class="section"><div class="section-header" onclick="toggleSec('out')"><span>Outgoing</span><span class="section-badge out" id="out-count">0</span></div><ul class="connection-list" id="out-list"></ul></div><div class="section"><div class="section-header" onclick="toggleSec('in')"><span>Incoming</span><span class="section-badge in" id="in-count">0</span></div><ul class="connection-list" id="in-list"></ul></div></div></div>
  <div id="stats"><div class="stat">Nodes: <span class="stat-value" id="stat-nodes">0</span></div><div class="stat">Edges: <span class="stat-value" id="stat-edges">0</span></div><div class="stat">Visible: <span class="stat-value" id="stat-visible">0</span></div></div>
  <script>
const rawNodes={json_nodes};const rawEdges={json_edges};const clusters={json_clusters};const entryPoint={json_entry};const typeColors={json_colors};
let graph,renderer,selectedNode=null,currentFilter='all';const connIndex={{in:{{}},out:{{}}}};const searchTrie={{}};const nodeMap=new Map();
function setProgress(p,m){{document.getElementById('progress').style.width=p+'%';document.getElementById('load-status').textContent=m;}}
function chunk(arr,size){{const r=[];for(let i=0;i<arr.length;i+=size)r.push(arr.slice(i,i+size));return r;}}
async function processChunks(chunks,fn,base,range,label){{for(let i=0;i<chunks.length;i++){{chunks[i].forEach(fn);const pct=base+Math.floor((i+1)/chunks.length*range);setProgress(pct,label+' ('+(i+1)+'/'+chunks.length+')');await new Promise(r=>requestAnimationFrame(r));}}}}
function searchNodes(q,l=15){{if(!q||q.length<2)return[];const ql=q.toLowerCase();let c=searchTrie;for(const ch of ql)if(!c[ch])return[];else c=c[ch];return Array.from(c.nodes||[]).slice(0,l).map(id=>nodeMap.get(id)).filter(Boolean).sort((a,b)=>{{const aE=a.label.toLowerCase()===ql,bE=b.label.toLowerCase()===ql;if(aE&&!bE)return-1;if(bE&&!aE)return 1;return a.label.length-b.label.length;}});}}
function findShortestPath(f,t,m=15){{if(f===t)return[f];const q=[[f]],v=new Set([f]);while(q.length){{const p=q.shift();if(p.length>m)continue;const c=p[p.length-1],nb=[...(connIndex.out[c]||[]),...(connIndex.in[c]||[])];for(const n of nb){{if(n===t)return[...p,n];if(!v.has(n)){{v.add(n);q.push([...p,n]);}}}}}}return null;}}
async function init(){{setProgress(5,'Initializing...');await new Promise(r=>requestAnimationFrame(r));graph=new graphology.Graph({{allowSelfLoops:false,multi:false}});const CHUNK=2000;const nodeChunks=chunk(rawNodes,CHUNK);const edgeChunks=chunk(rawEdges,CHUNK);await processChunks(nodeChunks,n=>{{nodeMap.set(n.id,n);graph.addNode(n.id,{{x:n.x||Math.random()*1000,y:n.y||Math.random()*1000,size:n.size,color:n.color,label:n.label,type:n.type,cluster:n.cluster,originalColor:n.color,originalSize:n.size,hidden:false}});}},5,35,'Adding nodes');await processChunks(edgeChunks,e=>{{if(graph.hasNode(e.source)&&graph.hasNode(e.target)&&!graph.hasEdge(e.source,e.target))graph.addEdge(e.source,e.target,{{color:'rgba(150,150,150,0.15)',size:0.3,originalColor:'rgba(150,150,150,0.15)'}});}},40,25,'Adding edges');setProgress(70,'Building search index...');await new Promise(r=>requestAnimationFrame(r));const trieChunks=chunk(rawNodes,CHUNK);for(let i=0;i<trieChunks.length;i++){{trieChunks[i].forEach(n=>{{[n.id.toLowerCase(),n.label.toLowerCase()].forEach(t=>{{let c=searchTrie;for(const ch of t){{if(!c[ch])c[ch]={{nodes:new Set()}};c=c[ch];c.nodes.add(n.id);}}}});}});await new Promise(r=>requestAnimationFrame(r));}}rawEdges.forEach(e=>{{if(!connIndex.out[e.source])connIndex.out[e.source]=[];connIndex.out[e.source].push(e.target);if(!connIndex.in[e.target])connIndex.in[e.target]=[];connIndex.in[e.target].push(e.source);}});setProgress(85,'Starting renderer...');await new Promise(r=>requestAnimationFrame(r));const container=document.getElementById('container');renderer=new Sigma(graph,container,{{renderLabels:true,labelThreshold:12,labelRenderedSizeThreshold:8,labelFont:'Segoe UI',labelSize:11,labelWeight:'normal',labelColor:{{color:'#ffffff'}},defaultNodeColor:'#4A90D9',defaultEdgeColor:'rgba(150,150,150,0.1)',minCameraRatio:0.01,maxCameraRatio:15,enableEdgeEvents:false,zIndex:true,renderEdgeLabels:false,enableEdgeClickEvents:false,enableEdgeWheelEvents:false,enableEdgeHoverEvents:false,stagePadding:50}});renderer.on('clickNode',({{node}})=>showPanel(node));renderer.on('clickStage',()=>closePanel());setProgress(100,'Done!');await new Promise(r=>setTimeout(r,200));document.getElementById('loading').style.display='none';updateStats();if(entryPoint&&graph.hasNode(entryPoint)){{const pos=graph.getNodeAttributes(entryPoint);renderer.getCamera().animate({{x:pos.x,y:pos.y,ratio:0.3}},{{duration:600}});}}}}
function updateStats(){{document.getElementById('stat-nodes').textContent=graph.order;document.getElementById('stat-edges').textContent=graph.size;let v=0;graph.forEachNode((n,a)=>{{if(!a.hidden)v++;}});document.getElementById('stat-visible').textContent=v;}}
function setFilter(f,btn){{currentFilter=f;document.querySelectorAll('.view-btn').forEach(b=>b.classList.remove('active'));if(btn)btn.classList.add('active');graph.forEachNode((n,a)=>{{const show=f==='all'||a.type===f;graph.setNodeAttribute(n,'hidden',!show);graph.setNodeAttribute(n,'color',show?a.originalColor:'rgba(100,100,100,0.1)');}});renderer.refresh();updateStats();}}
function showPanel(nodeId){{selectedNode=nodeId;const a=graph.getNodeAttributes(nodeId);document.getElementById('panel-title').textContent=a.label;document.getElementById('panel-title').title=nodeId;document.getElementById('node-info').innerHTML='<div class="info-row"><span class="info-label">Type:</span><span class="info-value">'+a.type+'</span></div><div class="info-row"><span class="info-label">Full Path:</span><span class="info-value">'+nodeId+'</span></div><div class="info-row"><span class="info-label">Cluster:</span><span class="info-value">'+(a.cluster||'N/A')+'</span></div>';const outN=connIndex.out[nodeId]||[],inN=connIndex.in[nodeId]||[];document.getElementById('out-count').textContent=outN.length;document.getElementById('in-count').textContent=inN.length;populateList('out-list',outN);populateList('in-list',inN);document.getElementById('pf-to').value='';document.getElementById('path-result').innerHTML='';document.getElementById('pathfinder').classList.remove('visible');document.getElementById('panel').classList.add('visible');}}
function populateList(id,nodes){{const l=document.getElementById(id);if(!nodes.length){{l.innerHTML='<li class="no-conn">None</li>';return;}}const sorted=nodes.map(id=>({{id,attrs:graph.hasNode(id)?graph.getNodeAttributes(id):null}})).filter(x=>x.attrs).sort((a,b)=>{{const order={{module:0,class:1,function:2,struct:3,external:4}};const ao=order[a.attrs.type]??5,bo=order[b.attrs.type]??5;return ao!==bo?ao-bo:a.attrs.label.localeCompare(b.attrs.label);}});l.innerHTML=sorted.map(({{id,attrs}})=>'<li class="connection-item" onclick="goToNode(\\''+id.replace(/'/g,"\\\\'")+'\\')"><span class="conn-dot" style="background:'+attrs.color+'"></span><span class="conn-name" title="'+id+'">'+attrs.label+'</span><span class="conn-type">'+attrs.type+'</span></li>').join('');}}
function goToNode(nodeId){{if(!graph.hasNode(nodeId))return;const pos=graph.getNodeAttributes(nodeId);renderer.getCamera().animate({{x:pos.x,y:pos.y,ratio:0.8}},{{duration:400}});setTimeout(()=>showPanel(nodeId),450);}}
function closePanel(){{document.getElementById('panel').classList.remove('visible');clearHL();selectedNode=null;}}
function toggleSec(sec){{document.getElementById(sec+'-list').classList.toggle('collapsed');}}
function highlight(dir){{if(!selectedNode)return;const outN=connIndex.out[selectedNode]||[],inN=connIndex.in[selectedNode]||[];let hl=[selectedNode];if(dir==='out'||dir==='both')hl=hl.concat(outN);if(dir==='in'||dir==='both')hl=hl.concat(inN);const hlSet=new Set(hl);graph.forEachNode((n,a)=>{{const isHL=hlSet.has(n);graph.setNodeAttribute(n,'color',isHL?a.originalColor:'rgba(100,100,100,0.15)');graph.setNodeAttribute(n,'size',isHL?a.originalSize*1.5:a.originalSize*0.5);}});graph.forEachEdge((e,a,src,tgt)=>{{const isRel=(dir==='out'&&src===selectedNode)||(dir==='in'&&tgt===selectedNode)||(dir==='both'&&(src===selectedNode||tgt===selectedNode));graph.setEdgeAttribute(e,'color',isRel?'rgba(102,126,234,0.8)':'rgba(100,100,100,0.05)');graph.setEdgeAttribute(e,'size',isRel?1.5:0.2);}});renderer.refresh();}}
function clearHL(){{graph.forEachNode((n,a)=>{{graph.setNodeAttribute(n,'color',a.originalColor);graph.setNodeAttribute(n,'size',a.originalSize);}});graph.forEachEdge((e,a)=>{{graph.setEdgeAttribute(e,'color',a.originalColor||'rgba(150,150,150,0.15)');graph.setEdgeAttribute(e,'size',0.3);}});renderer.refresh();}}
function togglePathfinder(){{document.getElementById('pathfinder').classList.toggle('visible');}}
function findPath(){{if(!selectedNode)return;const to=document.getElementById('pf-to').value.trim();if(!to)return;let targetId=null;graph.forEachNode((n,a)=>{{if(n.toLowerCase().includes(to.toLowerCase())||a.label.toLowerCase().includes(to.toLowerCase()))if(!targetId)targetId=n;}});if(!targetId){{document.getElementById('path-result').innerHTML='<span style="color:#dc3545">Node not found</span>';return;}}const path=findShortestPath(selectedNode,targetId);if(!path){{document.getElementById('path-result').innerHTML='<span style="color:#dc3545">No path found</span>';return;}}const pathSet=new Set(path);graph.forEachNode((n,a)=>{{graph.setNodeAttribute(n,'color',pathSet.has(n)?a.originalColor:'rgba(100,100,100,0.1)');graph.setNodeAttribute(n,'size',pathSet.has(n)?a.originalSize*2:a.originalSize*0.3);}});graph.forEachEdge((e,a,src,tgt)=>{{const srcIdx=path.indexOf(src),tgtIdx=path.indexOf(tgt);const isPath=srcIdx!==-1&&tgtIdx!==-1&&Math.abs(srcIdx-tgtIdx)===1;graph.setEdgeAttribute(e,'color',isPath?'rgba(255,107,107,0.9)':'rgba(100,100,100,0.03)');graph.setEdgeAttribute(e,'size',isPath?3:0.1);}});renderer.refresh();document.getElementById('path-result').innerHTML='<div style="margin-bottom:5px;color:#28a745">Path ('+(path.length-1)+' hops):</div>'+path.map((n,i)=>{{const a=graph.getNodeAttributes(n);return'<span class="path-step" onclick="goToNode(\\''+n.replace(/'/g,"\\\\'")+'\\')">'+a.label+'</span>'+(i<path.length-1?'<span class="path-arrow">&#8594;</span>':'');}}).join('');}}
document.getElementById('search').addEventListener('input',function(e){{const q=e.target.value;const results=searchNodes(q);const container=document.getElementById('search-results');if(!results.length){{container.style.display='none';return;}}container.innerHTML=results.map(n=>'<div class="search-result" onclick="goToNode(\\''+n.id.replace(/'/g,"\\\\'")+'\\');document.getElementById(\\'search-results\\').style.display=\\'none\\';"><span class="result-dot" style="background:'+n.color+'"></span><span class="result-label">'+n.label+'</span><span class="result-type">'+n.type+'</span></div>').join('');container.style.display='block';}});
document.addEventListener('click',function(e){{if(!e.target.closest('.search-container'))document.getElementById('search-results').style.display='none';}});
document.addEventListener('keydown',function(e){{if(e.key==='Escape'){{closePanel();document.getElementById('search-results').style.display='none';}}}});
init();
  </script>
</body>
</html>'''


def main() -> None:
    """Main function to parse arguments, scan, and visualize the architecture."""
    parser = argparse.ArgumentParser(description="Generate Intellicrack Knowledge Graph")
    parser.add_argument("--root", "-r", default="intellicrack", help="Root Python package directory")
    parser.add_argument("--rust", default="intellicrack-launcher", help="Root Rust project directory")
    parser.add_argument(
        "--layout",
        "-l",
        choices=['sfdp', 'hierarchical', 'radial'],
        default='sfdp',
        help="Layout algorithm (default: sfdp)",
    )
    parser.add_argument(
        "--no-clusters",
        action="store_true",
        help="Disable cluster data generation",
    )

    args = parser.parse_args()

    base_dir = Path.cwd()
    py_root = base_dir / args.root
    rust_root = base_dir / args.rust

    if not py_root.exists():
        logger.error("Python root directory not found: %s", py_root)
        sys.exit(1)

    try:
        generator = KnowledgeGraphGenerator(py_root, rust_root)
        generator.build_graph()

        generator.export_graphml(base_dir / "IntellicrackKnowledgeGraph.graphml")
        generator.generate_interactive_html(
            base_dir / "IntellicrackKnowledgeGraph.html",
            layout_method=args.layout,
            enable_clustering=not args.no_clusters,
        )

    except Exception:
        logger.exception("An unexpected error occurred during graph generation.")
        sys.exit(1)


if __name__ == "__main__":
    main()
