"""A script to visualize the architecture of the Intellicrack project."""

import argparse
import ast
import html
import json
import logging
import os
import re
import sys
import subprocess
from pathlib import Path
from typing import Any, Optional, Dict

try:
    import networkx as nx
    from graphviz import Digraph, ExecutableNotFound
except ImportError as e:
    print(f"Error: Missing required libraries. {e}")
    print("Please run: pip install networkx graphviz")
    sys.exit(1)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class KnowledgeGraphGenerator:
    """Generates a comprehensive knowledge graph for Python and Rust projects."""

    def __init__(self, root_dir: Path, rust_root: Optional[Path] = None):
        """Initializes the KnowledgeGraphGenerator.

        Args:
            root_dir (Path): The root directory of the Python project to analyze.
            rust_root (Optional[Path]): The root directory of the Rust project to analyze.
        """
        self.root_dir = root_dir.resolve()
        if self.root_dir.name != 'intellicrack':
            possible_sub = self.root_dir / 'intellicrack'
            if possible_sub.exists():
                self.root_dir = possible_sub

        self.repo_root = self.root_dir.parent
        self.rust_root = rust_root.resolve() if rust_root else None
        
        self.graph = nx.DiGraph()
        self.module_map = {}
        self.python_entry_points = set()
        self.rust_calls_to_python = []

    def build_graph(self):
        """Builds the complete knowledge graph."""
        logger.info("Starting Python analysis...")
        self._scan_python()
        
        if self.rust_root and self.rust_root.exists():
            logger.info("Starting Rust analysis...")
            self._scan_rust()
            self._link_languages()
        else:
            logger.warning("Rust root not found or not provided. Skipping Rust analysis.")

        logger.info("Graph built with %d nodes and %d edges.", 
                    self.graph.number_of_nodes(), self.graph.number_of_edges())

    def _scan_python(self):
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
                        self.graph.add_node(module_name, type='module', lang='python', path=str(path), label=module_name)
                        self._parse_python_file(path, module_name)
        except (PermissionError, OSError):
            logger.exception("Error identifying files in directory %s", self.root_dir)

    def _parse_python_file(self, path: Path, module_name: str):
        """Deep parses a Python file for classes, functions, and variables."""
        try:
            with open(path, encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(path))
        except Exception as e:
            logger.warning("Error parsing %s: %s", path, e)
            return

        imports_map = {}

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
                
                if node.name == 'main' and (module_name.endswith('__main__') or 'intellicrack.main' in module_name):
                    self.python_entry_points.add(func_id)

    def _scan_rust(self):
        """Scans Rust files using Regex for structure."""
        try:
            for root, _, files in os.walk(self.rust_root):
                for file in files:
                    if file.endswith(".rs"):
                        path = Path(root) / file
                        self._parse_rust_file(path)
        except (PermissionError, OSError):
            logger.exception("Error scanning Rust directory %s", self.rust_root)

    def _parse_rust_file(self, path: Path):
        """Parses a Rust file for basic entities."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            logger.warning("Error reading Rust file %s: %s", path, e)
            return

        try:
            rel_path = path.relative_to(self.rust_root.parent)
            module_id = str(rel_path).replace(os.sep, '::').replace('.rs', '')
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

    def _link_languages(self):
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
    def _resolve_relative_import(current_module: str, partial_module: str, level: int) -> str:
        parts = current_module.split('.')
        if level >= len(parts):
            return partial_module if partial_module else ""
        base = ".".join(parts[:-level])
        if partial_module:
            return f"{base}.{partial_module}"
        return base

    def export_graphml(self, output_path: Path):
        try:
            nx.write_graphml(self.graph, str(output_path))
            logger.info("GraphML saved to: %s", output_path)
        except Exception:
            logger.exception("Failed to save GraphML file:")

    def _calculate_layout(self, dot_file: Path) -> Dict[str, Dict[str, float]]:
        """Calculates layout using sfdp and returns node positions."""
        logger.info("Calculating pre-loaded layout using sfdp (this may take a minute)...")
        layout_map = {}
        
        try:
            # Output layout to JSON format
            # -K sfdp: Use Scalable Force-Directed Placement (best for large graphs)
            # -Goverlap=prism: Handle node overlap efficiently
            # -Gmaxiter=1000: Limit iterations to prevent hanging on huge graphs
            json_output = subprocess.check_output(
                ['sfdp', '-K', 'sfdp', '-Goverlap=prism', '-Gmaxiter=1000', '-Tjson', str(dot_file)], 
                text=True,
                stderr=subprocess.PIPE
            )
            
            data = json.loads(json_output)
            
            if 'objects' in data:
                for node in data['objects']:
                    name = node.get('name')
                    pos = node.get('pos')
                    if name and pos:
                        try:
                            x, y = map(float, pos.split(','))
                            # Scale significantly for vis.js
                            layout_map[name] = {'x': x * 5, 'y': y * -5} 
                        except ValueError:
                            pass
                        
            logger.info("Layout calculated for %d nodes.", len(layout_map))
            
        except subprocess.CalledProcessError as e:
            logger.error("Graphviz layout calculation failed: %s", e.stderr)
        except Exception as e:
            logger.exception("Error parsing layout JSON: %s", e)
            
        return layout_map

    def generate_interactive_html(self, output_path: Path):
        """Generates a standalone HTML file with PRE-CALCULATED static layout."""
        
        # 1. Filter Graph: Internal Nodes + Direct External Dependencies
        logger.info("Filtering graph for visualization...")
        
        internal_nodes = {
            n for n in self.graph.nodes 
            if n.startswith('intellicrack.') or n.startswith('intellicrack-launcher')
        }
        
        # Find external nodes that are directly used by internal nodes
        boundary_nodes = set()
        for u in internal_nodes:
            for v in self.graph.successors(u):
                if v not in internal_nodes:
                    boundary_nodes.add(v)
        
        candidates = internal_nodes.union(boundary_nodes)
        nodes_to_keep = set()
        
        # Heuristic: If graph is huge, drop functions/structs/variables to show Architecture (Classes/Modules)
        # 20k nodes is too many for static layout + browser rendering without lag.
        total_candidates = len(candidates)
        show_functions = total_candidates < 5000
        
        if not show_functions:
            logger.warning(f"Graph is large ({total_candidates} nodes). Hiding functions/structs to ensure performance.")
        
        for n in candidates:
            node_type = self.graph.nodes[n].get('type')
            if node_type == 'variable':
                continue
            
            if not show_functions and node_type in ('function', 'struct'):
                continue
                
            nodes_to_keep.add(n)

        filtered_graph = self.graph.subgraph(nodes_to_keep).copy()
        
        logger.info("Visualization graph: %d nodes (Original: %d)", 
                    len(filtered_graph), self.graph.number_of_nodes())

        # 2. Generate DOT file for Layout Calculation
        dot_path = output_path.with_suffix('.dot')
        try:
            # Use networkx pydot to export, or manual fallback
            try:
                nx.drawing.nx_pydot.write_dot(filtered_graph, str(dot_path))
            except ImportError:
                # Fallback manual DOT generation
                with open(dot_path, 'w', encoding='utf-8') as f:
                    f.write('digraph "Intellicrack" {\n')
                    for n in filtered_graph.nodes:
                        f.write(f'  "{n}";\n')
                    for u, v in filtered_graph.edges:
                        f.write(f'  "{u}" -> "{v}";\n')
                    f.write('}\n')
        except Exception:
            logger.exception("Failed to generate DOT file.")
            return
        
        # 3. Calculate Layout (Heavy lifting done here)
        positions = self._calculate_layout(dot_path)
        
        # Cleanup DOT file
        try:
            if dot_path.exists():
                dot_path.unlink()
        except Exception:
            logger.warning("Could not delete temporary dot file: %s", dot_path)
        
        nodes_data = []
        edges_data = []

        # Color mapping
        type_colors = {
            'module': '#97C2FC',   # Blue
            'class': '#FFFF00',    # Yellow
            'function': '#FB7E81', # Red
            'struct': '#7BE141',   # Green
            'variable': '#EB7DF4',  # Magenta
            'external': '#E0E0E0'  # Grey for external libs
        }

        entry_point_id = None

        for node_id, attrs in filtered_graph.nodes(data=True):
            node_type = attrs.get('type', 'unknown')
            
            # Mark boundary nodes as 'external' type for coloring
            if node_id in boundary_nodes:
                node_type = 'external'

            # Short label
            label = attrs.get('label', node_id.split('.')[-1].split('::')[-1])
            
            if len(label) > 30:
                label = label[:27] + "..."

            color = type_colors.get(node_type, '#D2E5FF')
            
            # Size hierarchy
            size = 10
            if node_type == 'module': size = 25
            elif node_type == 'class': size = 20
            elif node_type == 'struct': size = 20
            elif node_type == 'function': size = 15
            elif node_type == 'external': size = 15

            shape = 'dot'
            if node_type == 'external': shape = 'square'

            # Identify entry point
            if not entry_point_id:
                if 'intellicrack.main' in node_id and node_type == 'module':
                    entry_point_id = node_id
                elif 'intellicrack-launcher::src::lib' == node_id and node_type == 'module':
                    entry_point_id = node_id
            
            if node_id == entry_point_id:
                color = '#FF4444' # Bright Red
                size = 50
                label = f"★ {label}"
                shape = 'star'

            # Tooltip
            title = f"<strong>{html.escape(label)}</strong><br>Type: {node_type}<br>Full Path: {html.escape(node_id)}"

            node_data = {
                'id': node_id,
                'label': label,
                'title': title,
                'color': color,
                'group': node_type,
                'size': size,
                'shape': shape,
                'font': {
                    'size': 14 if size < 20 else 20,
                    'background': 'rgba(255, 255, 255, 0.7)',
                    'face': 'Segoe UI'
                }
            }
            
            # Apply Fixed Position if available
            if node_id in positions:
                node_data['x'] = positions[node_id]['x']
                node_data['y'] = positions[node_id]['y']
                node_data['fixed'] = True # Important: tell vis.js not to move it
            
            nodes_data.append(node_data)

        for u, v, attrs in filtered_graph.edges(data=True):
            # Edges to external nodes should be dashed
            dashes = False
            if v in boundary_nodes:
                dashes = True

            edges_data.append({
                'from': u,
                'to': v,
                'arrows': 'to',
                'color': {'color': '#CCCCCC', 'opacity': 0.4},
                'width': 0.5,
                'dashes': dashes
            })

        # Serialize data for JS
        json_all_nodes = json.dumps(nodes_data)
        json_all_edges = json.dumps(edges_data)
        initial_focus = json.dumps(entry_point_id) if entry_point_id else "null"

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
  <title>Intellicrack Architecture (Static Map)</title>
  <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style type="text/css">
    body {{ margin: 0; padding: 0; font-family: 'Segoe UI', sans-serif; overflow: hidden; }}
    #mynetwork {{
      width: 100vw;
      height: 100vh;
      border: none;
      background-color: #ffffff;
    }}
    .controls {{
        position: absolute; top: 10px; right: 10px;
        background: rgba(255, 255, 255, 0.95); padding: 15px;
        border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        z-index: 1000; max-width: 300px;
    }}
    .search-box {{
        width: 100%; padding: 8px; margin-bottom: 10px;
        border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box;
    }}
    .legend-item {{ display: flex; align-items: center; margin-bottom: 5px; font-size: 13px; }}
    .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}
    .legend-square {{ width: 12px; height: 12px; margin-right: 8px; }}
    #loading {{
        position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
        background: rgba(255,255,255,0.95); padding: 20px; border-radius: 8px;
        box-shadow: 0 0 15px rgba(0,0,0,0.2); z-index: 2000;
        display: block; font-weight: bold; font-size: 16px; color: #333;
    }}
  </style>
</head>
<body>
  <div id="loading">Rendering Static Map...</div>
  
  <div class="controls">
    <h3>Project Map</h3>
    <input type="text" id="search" class="search-box" placeholder="Search node..." onchange="searchNode()">
    
    <div class="legend-item"><div class="legend-dot" style="background:#FF4444"></div> Entry Point</div>
    <div class="legend-item"><div class="legend-dot" style="background:#97C2FC"></div> Module</div>
    <div class="legend-item"><div class="legend-dot" style="background:#FFFF00"></div> Class</div>
    <div class="legend-item"><div class="legend-dot" style="background:#FB7E81"></div> Function</div>
    <div class="legend-item"><div class="legend-dot" style="background:#7BE141"></div> Struct</div>
    <div class="legend-item"><div class="legend-square" style="background:#E0E0E0"></div> External Dep</div>
    
    <div style="font-size:11px; color:#666; margin-top:10px;">
        * Pre-calculated layout. Pan/Zoom enabled.
    </div>
  </div>

  <div id="mynetwork"></div>

  <script type="text/javascript">
    const nodes = new vis.DataSet({json_all_nodes});
    const edges = new vis.DataSet({json_all_edges});
    const entryPoint = {initial_focus};

    const container = document.getElementById('mynetwork');
    const data = {{ nodes: nodes, edges: edges }};
    const options = {{
      nodes: {{
        borderWidth: 1,
        shadow: false
      }},
      edges: {{
        smooth: false, // Straight lines are faster
        selectionWidth: 2
      }},
      physics: {{
        enabled: false // CRITICAL: No physics, purely static positions
      }},
      interaction: {{
        hover: true,
        tooltipDelay: 200,
        hideEdgesOnDrag: true,
        navigationButtons: true,
        keyboard: true,
        zoomView: true,
        dragView: true
      }},
      layout: {{
        improvedLayout: false
      }}
    }};

    const network = new vis.Network(container, data, options);

    network.once("afterDrawing", function() {{
        document.getElementById('loading').style.display = 'none';
        if (entryPoint) {{
            network.selectNodes([entryPoint]);
            network.focus(entryPoint, {{ scale: 0.5, animation: {{ duration: 1000 }} }});
        }} else {{
            network.fit();
        }}
    }});

    window.searchNode = function() {{
        const query = document.getElementById('search').value.toLowerCase();
        if (!query) return;

        const allNodes = nodes.get();
        const found = allNodes.find(n => n.id.toLowerCase().includes(query) || n.label.toLowerCase().includes(query));

        if (found) {{
            network.selectNodes([found.id]);
            network.focus(found.id, {{
                scale: 1.5,
                animation: {{ duration: 1000, easingFunction: 'easeInOutQuad' }}
            }});
        }} else {{
            alert("Node not found.");
        }}
    }};
  </script>
</body>
</html>
"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info("Interactive HTML saved to: %s", output_path)
        except Exception:
            logger.exception("Failed to save HTML file:")


def main():
    """Main function to parse arguments, scan, and visualize the architecture."""
    parser = argparse.ArgumentParser(description="Generate Intellicrack Knowledge Graph")
    parser.add_argument("--root", "-r", default="intellicrack", help="Root Python package directory")
    parser.add_argument("--rust", default="intellicrack-launcher", help="Root Rust project directory")

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
        
        # Export artifacts
        generator.export_graphml(base_dir / "IntellicrackKnowledgeGraph.graphml")
        generator.generate_interactive_html(base_dir / "IntellicrackKnowledgeGraph.html")
        
    except Exception:
        logger.exception("An unexpected error occurred during graph generation.")
        sys.exit(1)


if __name__ == "__main__":
    main()
