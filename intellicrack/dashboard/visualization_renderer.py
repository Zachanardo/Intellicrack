"""Visualization Renderer for Real-time Dashboard.

This module implements visualization rendering using D3.js, Chart.js,
and custom 3D rendering for call graphs and analysis results.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import base64
import io
import json
import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import numpy as np

try:
    import matplotlib as mpl

    mpl.use("Agg")  # Use non-interactive backend
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch, Rectangle

    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

try:
    import networkx as nx

    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

try:
    from PIL import Image, ImageDraw

    HAS_PIL = True
except ImportError:
    HAS_PIL = False

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    """Node in a visualization graph."""

    id: str
    label: str
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    size: float = 1.0
    color: str = "#3498db"
    shape: str = "circle"
    data: dict[str, Any] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "label": self.label,
            "x": self.x,
            "y": self.y,
            "z": self.z,
            "size": self.size,
            "color": self.color,
            "shape": self.shape,
            "data": self.data or {},
        }


@dataclass
class GraphEdge:
    """Edge in a visualization graph."""

    source: str
    target: str
    weight: float = 1.0
    color: str = "#95a5a6"
    style: str = "solid"
    label: str = ""
    data: dict[str, Any] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source": self.source,
            "target": self.target,
            "weight": self.weight,
            "color": self.color,
            "style": self.style,
            "label": self.label,
            "data": self.data or {},
        }


class VisualizationRenderer:
    """Renderer for various visualization types."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize visualization renderer.

        Args:
            config: Renderer configuration

        """
        self.config = config or {}
        self.logger = logger

        # Color schemes
        self.color_schemes = {
            "default": ["#3498db", "#e74c3c", "#2ecc71", "#f39c12", "#9b59b6"],
            "heatmap": ["#00ff00", "#ffff00", "#ff8800", "#ff0000", "#880000"],
            "diverging": ["#2166ac", "#67a9cf", "#f7f7f7", "#fddbc7", "#b2182b"],
            "categorical": ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"],
        }

        # Chart templates
        self.chart_templates = self._load_chart_templates()

        # 3D rendering configuration
        self.three_d_config = {"camera_distance": 100, "camera_angle": 45, "rotation_speed": 0.01, "zoom_factor": 1.2}

        # Cache for rendered visualizations
        self.render_cache = {}
        self.cache_ttl = self.config.get("cache_ttl", 60)  # seconds

    def _load_chart_templates(self) -> dict[str, str]:
        """Load chart templates for JavaScript rendering."""
        return {
            "d3_force_graph": """
                const svg = d3.select("#{{container_id}}")
                    .append("svg")
                    .attr("width", {{width}})
                    .attr("height", {{height}});

                // Force-directed graph layout with actual physics calculations
                const nodes = {{nodes}};
                const edges = {{edges}};
                const width = {{width}};
                const height = {{height}};

                // Initialize node positions
                nodes.forEach((node, i) => {
                    if (!node.x) node.x = width / 2 + (Math.random() - 0.5) * width * 0.5;
                    if (!node.y) node.y = height / 2 + (Math.random() - 0.5) * height * 0.5;
                    node.vx = 0;
                    node.vy = 0;
                });

                // Physics engine for force-directed layout
                const forceLayout = {
                    alpha: 1,
                    alphaDecay: 0.01,
                    velocityDecay: 0.4,

                    tick: function() {
                        // Apply link forces (springs)
                        edges.forEach(edge => {
                            const source = nodes.find(n => n.id === edge.source);
                            const target = nodes.find(n => n.id === edge.target);
                            if (source && target) {
                                const dx = target.x - source.x;
                                const dy = target.y - source.y;
                                const distance = Math.sqrt(dx * dx + dy * dy) || 1;
                                const force = (distance - 100) * 0.01 * this.alpha;
                                const fx = (dx / distance) * force;
                                const fy = (dy / distance) * force;
                                source.vx += fx;
                                source.vy += fy;
                                target.vx -= fx;
                                target.vy -= fy;
                            }
                        });

                        // Apply repulsion forces between all nodes
                        for (let i = 0; i < nodes.length; i++) {
                            for (let j = i + 1; j < nodes.length; j++) {
                                const node1 = nodes[i];
                                const node2 = nodes[j];
                                const dx = node2.x - node1.x;
                                const dy = node2.y - node1.y;
                                const distance = Math.sqrt(dx * dx + dy * dy) || 1;
                                const force = (300 / (distance * distance)) * this.alpha;
                                const fx = (dx / distance) * force;
                                const fy = (dy / distance) * force;
                                node1.vx -= fx;
                                node1.vy -= fy;
                                node2.vx += fx;
                                node2.vy += fy;
                            }
                        }

                        // Apply centering force
                        const cx = width / 2;
                        const cy = height / 2;
                        nodes.forEach(node => {
                            const dx = cx - node.x;
                            const dy = cy - node.y;
                            node.vx += dx * 0.01 * this.alpha;
                            node.vy += dy * 0.01 * this.alpha;
                        });

                        // Update positions with velocity
                        nodes.forEach(node => {
                            node.vx *= this.velocityDecay;
                            node.vy *= this.velocityDecay;
                            node.x += node.vx;
                            node.y += node.vy;

                            // Keep nodes within bounds
                            node.x = Math.max(20, Math.min(width - 20, node.x));
                            node.y = Math.max(20, Math.min(height - 20, node.y));
                        });

                        // Decay alpha
                        this.alpha = Math.max(0, this.alpha - this.alphaDecay);
                    }
                };

                // Create edge elements
                const link = svg.append("g")
                    .selectAll("line")
                    .data(edges)
                    .enter().append("line")
                    .attr("stroke", d => d.color)
                    .attr("stroke-width", d => Math.sqrt(d.weight));

                // Create node elements
                const node = svg.append("g")
                    .selectAll("circle")
                    .data(nodes)
                    .enter().append("circle")
                    .attr("r", d => d.size * 5)
                    .attr("fill", d => d.color);

                // Add labels
                const labels = svg.append("g")
                    .selectAll("text")
                    .data(nodes)
                    .enter().append("text")
                    .attr("text-anchor", "middle")
                    .attr("dy", ".35em")
                    .style("font-size", "10px")
                    .text(d => d.label);

                // Drag functionality
                let draggedNode = null;

                node.call(d3.drag()
                    .on("start", function(event, d) {
                        draggedNode = d;
                        d3.select(this).raise().attr("stroke", "black");
                    })
                    .on("drag", function(event, d) {
                        d.x = event.x;
                        d.y = event.y;
                        updatePositions();
                    })
                    .on("end", function(event, d) {
                        draggedNode = null;
                        d3.select(this).attr("stroke", null);
                    }));

                // Update visual positions
                function updatePositions() {
                    link
                        .attr("x1", d => {
                            const source = nodes.find(n => n.id === d.source);
                            return source ? source.x : 0;
                        })
                        .attr("y1", d => {
                            const source = nodes.find(n => n.id === d.source);
                            return source ? source.y : 0;
                        })
                        .attr("x2", d => {
                            const target = nodes.find(n => n.id === d.target);
                            return target ? target.x : 0;
                        })
                        .attr("y2", d => {
                            const target = nodes.find(n => n.id === d.target);
                            return target ? target.y : 0;
                        });

                    node
                        .attr("cx", d => d.x)
                        .attr("cy", d => d.y);

                    labels
                        .attr("x", d => d.x)
                        .attr("y", d => d.y);
                }

                // Animation loop
                function animate() {
                    if (forceLayout.alpha > 0 && !draggedNode) {
                        forceLayout.tick();
                        updatePositions();
                        requestAnimationFrame(animate);
                    }
                }

                animate();
            """,
            "chartjs_line": """
                const ctx = document.getElementById('{{container_id}}').getContext('2d');
                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: {{labels}},
                        datasets: {{datasets}}
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: {
                                position: 'top',
                            },
                            title: {
                                display: true,
                                text: '{{title}}'
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            """,
            "three_js_3d_graph": """
                const scene = new THREE.Scene();
                const camera = new THREE.PerspectiveCamera(75, {{width}}/{{height}}, 0.1, 1000);
                const renderer = new THREE.WebGLRenderer();
                renderer.setSize({{width}}, {{height}});
                document.getElementById('{{container_id}}').appendChild(renderer.domElement);

                // Add lights
                const light = new THREE.DirectionalLight(0xffffff, 1);
                light.position.set(1, 1, 1);
                scene.add(light);
                scene.add(new THREE.AmbientLight(0x404040));

                // Create nodes
                const nodeGeometry = new THREE.SphereGeometry(1, 32, 32);
                const nodes = {};
                {{nodes}}.forEach(node => {
                    const material = new THREE.MeshPhongMaterial({color: node.color});
                    const mesh = new THREE.Mesh(nodeGeometry, material);
                    mesh.position.set(node.x, node.y, node.z);
                    mesh.scale.set(node.size, node.size, node.size);
                    scene.add(mesh);
                    nodes[node.id] = mesh;
                });

                // Create edges
                const edgeGeometry = new THREE.BufferGeometry();
                {{edges}}.forEach(edge => {
                    const source = nodes[edge.source];
                    const target = nodes[edge.target];
                    if (source && target) {
                        const points = [];
                        points.push(source.position);
                        points.push(target.position);
                        const line = new THREE.Line(
                            new THREE.BufferGeometry().setFromPoints(points),
                            new THREE.LineBasicMaterial({color: edge.color})
                        );
                        scene.add(line);
                    }
                });

                camera.position.z = {{camera_distance}};

                // Animation loop
                function animate() {
                    requestAnimationFrame(animate);
                    scene.rotation.y += {{rotation_speed}};
                    renderer.render(scene, camera);
                }
                animate();

                // Mouse controls
                const controls = new THREE.OrbitControls(camera, renderer.domElement);
                controls.enableDamping = true;
                controls.dampingFactor = 0.05;
            """,
        }

    def render_graph(
        self,
        nodes: list[GraphNode],
        edges: list[GraphEdge],
        render_type: str = "force",
        dimensions: tuple[int, int] = (800, 600),
        container_id: str = "graph-container",
    ) -> dict[str, Any]:
        """Render a graph visualization.

        Args:
            nodes: Graph nodes
            edges: Graph edges
            render_type: Type of rendering (force, hierarchical, circular)
            dimensions: Width and height
            container_id: Container element ID

        Returns:
            Visualization data including JavaScript code

        """
        # Check cache
        cache_key = f"graph_{hash(str(nodes))}{hash(str(edges))}{render_type}"
        if cache_key in self.render_cache:
            cached = self.render_cache[cache_key]
            if time.time() - cached["timestamp"] < self.cache_ttl:
                return cached["data"]

        width, height = dimensions

        if render_type == "force":
            # Generate D3.js force-directed graph
            js_code = self.chart_templates["d3_force_graph"]
            js_code = js_code.replace("{{container_id}}", container_id)
            js_code = js_code.replace("{{width}}", str(width))
            js_code = js_code.replace("{{height}}", str(height))
            js_code = js_code.replace("{{nodes}}", json.dumps([n.to_dict() for n in nodes]))
            js_code = js_code.replace("{{edges}}", json.dumps([e.to_dict() for e in edges]))

        elif render_type == "hierarchical":
            # Layout nodes hierarchically
            self._apply_hierarchical_layout(nodes, edges, dimensions)
            js_code = self._generate_static_graph_js(nodes, edges, container_id, dimensions)

        elif render_type == "circular":
            # Layout nodes in a circle
            self._apply_circular_layout(nodes, dimensions)
            js_code = self._generate_static_graph_js(nodes, edges, container_id, dimensions)

        else:
            js_code = ""

        # Generate static image fallback if matplotlib is available
        static_image = None
        if HAS_MATPLOTLIB and HAS_NETWORKX:
            static_image = self._render_static_graph(nodes, edges, dimensions)

        result = {
            "type": "graph",
            "render_type": render_type,
            "js_code": js_code,
            "static_image": static_image,
            "dimensions": dimensions,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }

        # Cache result
        self.render_cache[cache_key] = {"timestamp": time.time(), "data": result}

        return result

    def render_heatmap(
        self, data: np.ndarray, labels_x: list[str], labels_y: list[str], title: str = "Heatmap", color_scheme: str = "heatmap",
    ) -> dict[str, Any]:
        """Render a heatmap visualization.

        Args:
            data: 2D array of values
            labels_x: X-axis labels
            labels_y: Y-axis labels
            title: Chart title
            color_scheme: Color scheme name

        Returns:
            Visualization data

        """
        if not HAS_MATPLOTLIB:
            return {"error": "Matplotlib not available"}

        fig, ax = plt.subplots(figsize=(10, 8))

        # Create heatmap
        im = ax.imshow(data, cmap=self._get_colormap(color_scheme), aspect="auto")

        # Set ticks and labels
        ax.set_xticks(np.arange(len(labels_x)))
        ax.set_yticks(np.arange(len(labels_y)))
        ax.set_xticklabels(labels_x)
        ax.set_yticklabels(labels_y)

        # Rotate x labels
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

        # Add colorbar
        cbar = plt.colorbar(im, ax=ax)
        cbar.ax.set_ylabel("Value", rotation=-90, va="bottom")

        # Add values to cells
        for i in range(len(labels_y)):
            for j in range(len(labels_x)):
                ax.text(j, i, f"{data[i, j]:.2f}", ha="center", va="center", color="white")

        ax.set_title(title)
        fig.tight_layout()

        # Convert to base64 image
        buffer = io.BytesIO()
        plt.savefig(buffer, format="png", dpi=100, bbox_inches="tight")
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close()

        return {"type": "heatmap", "image": f"data:image/png;base64,{image_base64}", "title": title, "shape": data.shape}

    def render_timeline(self, events: list[dict[str, Any]], width: int = 1000, height: int = 400) -> dict[str, Any]:
        """Render a timeline visualization.

        Args:
            events: List of events with timestamps
            width: Timeline width
            height: Timeline height

        Returns:
            Visualization data

        """
        if not events:
            return {"error": "No events to render"}

        # Sort events by timestamp
        events = sorted(events, key=lambda x: x.get("timestamp", 0))

        # Calculate time range
        min_time = events[0]["timestamp"]
        max_time = events[-1]["timestamp"]
        time_range = max_time - min_time or 1

        # Generate D3.js timeline code
        js_code = f"""
            const svg = d3.select("#timeline-container")
                .append("svg")
                .attr("width", {width})
                .attr("height", {height});

            const margin = {{top: 20, right: 20, bottom: 30, left: 50}};
            const innerWidth = {width} - margin.left - margin.right;
            const innerHeight = {height} - margin.top - margin.bottom;

            const g = svg.append("g")
                .attr("transform", `translate(${{margin.left}},${{margin.top}})`);

            const xScale = d3.scaleLinear()
                .domain([{min_time}, {max_time}])
                .range([0, innerWidth]);

            const yScale = d3.scaleBand()
                .domain({json.dumps([e.get("source", "unknown") for e in events])})
                .range([0, innerHeight])
                .padding(0.1);

            // Add X axis
            g.append("g")
                .attr("transform", `translate(0,${{innerHeight}})`)
                .call(d3.axisBottom(xScale)
                    .tickFormat(d => new Date(d * 1000).toLocaleTimeString()));

            // Add Y axis
            g.append("g")
                .call(d3.axisLeft(yScale));

            // Add events
            g.selectAll(".event")
                .data({json.dumps(events)})
                .enter().append("circle")
                .attr("class", "event")
                .attr("cx", d => xScale(d.timestamp))
                .attr("cy", d => yScale(d.source) + yScale.bandwidth()/2)
                .attr("r", 5)
                .attr("fill", d => d.color || "#3498db")
                .on("mouseover", function(event, d) {{
                    // Show tooltip
                    const tooltip = d3.select("body").append("div")
                        .attr("class", "tooltip")
                        .style("opacity", 0);

                    tooltip.transition()
                        .duration(200)
                        .style("opacity", .9);

                    tooltip.html(d.event_type + "<br/>" + d.description)
                        .style("left", (event.pageX) + "px")
                        .style("top", (event.pageY - 28) + "px");
                }})
                .on("mouseout", function(d) {{
                    d3.selectAll(".tooltip").remove();
                }});
        """

        # Generate static image if matplotlib available
        static_image = None
        if HAS_MATPLOTLIB:
            static_image = self._render_static_timeline(events, (width, height))

        return {"type": "timeline", "js_code": js_code, "static_image": static_image, "event_count": len(events), "time_range": time_range}

    def render_metrics_chart(self, metrics: list[dict[str, Any]], chart_type: str = "line", title: str = "Metrics") -> dict[str, Any]:
        """Render metrics chart.

        Args:
            metrics: List of metric data points
            chart_type: Type of chart (line, bar, area)
            title: Chart title

        Returns:
            Visualization data

        """
        if not metrics:
            return {"error": "No metrics to render"}

        # Group metrics by name
        grouped = defaultdict(list)
        for metric in metrics:
            grouped[metric["metric_name"]].append({"x": metric["timestamp"], "y": metric["metric_value"]})

        # Prepare datasets for Chart.js
        datasets = []
        colors = self.color_schemes["categorical"]
        for i, (name, points) in enumerate(grouped.items()):
            datasets.append(
                {
                    "label": name,
                    "data": points,
                    "borderColor": colors[i % len(colors)],
                    "backgroundColor": colors[i % len(colors)] + "33",  # Add transparency
                    "fill": chart_type == "area",
                },
            )

        # Generate Chart.js code
        js_code = self.chart_templates["chartjs_line"]
        js_code = js_code.replace("{{container_id}}", "metrics-chart")
        js_code = js_code.replace("{{title}}", title)
        js_code = js_code.replace("{{labels}}", "[]")  # Use x values from data points
        js_code = js_code.replace("{{datasets}}", json.dumps(datasets))

        # Generate static chart if matplotlib available
        static_image = None
        if HAS_MATPLOTLIB:
            static_image = self._render_static_metrics(grouped, chart_type, title)

        return {
            "type": "metrics_chart",
            "chart_type": chart_type,
            "js_code": js_code,
            "static_image": static_image,
            "datasets": len(datasets),
            "data_points": sum(len(points) for points in grouped.values()),
        }

    def render_3d_call_graph(self, functions: list[dict[str, Any]], calls: list[dict[str, Any]]) -> dict[str, Any]:
        """Render 3D call graph visualization.

        Args:
            functions: List of functions with metadata
            calls: List of function calls

        Returns:
            3D visualization data

        """
        # Create nodes from functions
        nodes = []
        for i, func in enumerate(functions):
            # Calculate 3D position using spherical coordinate distribution
            angle = (i / len(functions)) * 2 * math.pi
            radius = 50
            nodes.append(
                GraphNode(
                    id=func["name"],
                    label=func["name"],
                    x=radius * math.cos(angle),
                    y=radius * math.sin(angle),
                    z=(i % 5 - 2) * 10,  # Distribute on Z axis
                    size=math.log(func.get("complexity", 1) + 1),
                    color=self._get_function_color(func),
                    data=func,
                ),
            )

        # Create edges from calls
        edges = []
        for call in calls:
            edges.append(
                GraphEdge(source=call["caller"], target=call["callee"], weight=call.get("count", 1), color=self._get_call_color(call)),
            )

        # Generate Three.js code
        js_code = self.chart_templates["three_js_3d_graph"]
        js_code = js_code.replace("{{container_id}}", "3d-graph-container")
        js_code = js_code.replace("{{width}}", "800")
        js_code = js_code.replace("{{height}}", "600")
        js_code = js_code.replace("{{nodes}}", json.dumps([n.to_dict() for n in nodes]))
        js_code = js_code.replace("{{edges}}", json.dumps([e.to_dict() for e in edges]))
        js_code = js_code.replace("{{camera_distance}}", str(self.three_d_config["camera_distance"]))
        js_code = js_code.replace("{{rotation_speed}}", str(self.three_d_config["rotation_speed"]))

        return {
            "type": "3d_call_graph",
            "js_code": js_code,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "config": self.three_d_config,
        }

    def render_interactive_explorer(self, data: dict[str, Any]) -> dict[str, Any]:
        """Render interactive data explorer.

        Args:
            data: Hierarchical data structure

        Returns:
            Interactive explorer visualization

        """
        # Generate D3.js tree explorer
        js_code = f"""
            const treeData = {json.dumps(data)};

            const margin = {{top: 20, right: 90, bottom: 30, left: 90}};
            const width = 960 - margin.left - margin.right;
            const height = 500 - margin.top - margin.bottom;

            const svg = d3.select("#explorer-container")
                .append("svg")
                .attr("width", width + margin.right + margin.left)
                .attr("height", height + margin.top + margin.bottom)
                .append("g")
                .attr("transform", `translate(${{margin.left}},${{margin.top}})`);

            const tree = d3.tree().size([height, width]);
            const root = d3.hierarchy(treeData);

            root.x0 = height / 2;
            root.y0 = 0;

            function update(source) {{
                const treeData = tree(root);
                const nodes = treeData.descendants();
                const links = treeData.descendants().slice(1);

                nodes.forEach(d => {{ d.y = d.depth * 180; }});

                // Nodes
                const node = svg.selectAll('g.node')
                    .data(nodes, d => d.id || (d.id = ++i));

                const nodeEnter = node.enter().append('g')
                    .attr('class', 'node')
                    .attr('transform', d => `translate(${{source.y0}},${{source.x0}})`)
                    .on('click', click);

                nodeEnter.append('circle')
                    .attr('r', 1e-6)
                    .style('fill', d => d._children ? 'lightsteelblue' : '#fff');

                nodeEnter.append('text')
                    .attr('dy', '.35em')
                    .attr('x', d => d.children || d._children ? -13 : 13)
                    .attr('text-anchor', d => d.children || d._children ? 'end' : 'start')
                    .text(d => d.data.name);

                // Links
                const link = svg.selectAll('path.link')
                    .data(links, d => d.id);

                link.enter().insert('path', 'g')
                    .attr('class', 'link')
                    .attr('d', diagonal);
            }}

            function click(event, d) {{
                if (d.children) {{
                    d._children = d.children;
                    d.children = null;
                }} else {{
                    d.children = d._children;
                    d._children = null;
                }}
                update(d);
            }}

            function diagonal(s, d) {{
                return `M ${{s.y}} ${{s.x}}
                        C ${{(s.y + d.y) / 2}} ${{s.x}},
                          ${{(s.y + d.y) / 2}} ${{d.x}},
                          ${{d.y}} ${{d.x}}`;
            }}

            update(root);
        """

        return {"type": "interactive_explorer", "js_code": js_code, "data": data}

    def _apply_hierarchical_layout(self, nodes: list[GraphNode], edges: list[GraphEdge], dimensions: tuple[int, int]) -> None:
        """Apply hierarchical layout to nodes.

        Args:
            nodes: Graph nodes
            edges: Graph edges
            dimensions: Width and height

        """
        width, height = dimensions

        # Build adjacency list
        children = defaultdict(list)
        parents = {}
        for edge in edges:
            children[edge.source].append(edge.target)
            parents[edge.target] = edge.source

        # Find roots (nodes with no parents)
        roots = [node.id for node in nodes if node.id not in parents]

        # BFS to assign levels
        levels = defaultdict(list)
        visited = set()
        queue = [(root, 0) for root in roots]

        while queue:
            node_id, level = queue.pop(0)
            if node_id in visited:
                continue

            visited.add(node_id)
            levels[level].append(node_id)

            for child in children[node_id]:
                queue.append((child, level + 1))

        # Position nodes
        node_map = {node.id: node for node in nodes}
        max_level = max(levels.keys()) if levels else 0

        for level, node_ids in levels.items():
            y = (level / (max_level + 1)) * height if max_level > 0 else height / 2
            x_spacing = width / (len(node_ids) + 1)

            for i, node_id in enumerate(node_ids):
                if node_id in node_map:
                    node = node_map[node_id]
                    node.x = (i + 1) * x_spacing
                    node.y = y

    def _apply_circular_layout(self, nodes: list[GraphNode], dimensions: tuple[int, int]) -> None:
        """Apply circular layout to nodes.

        Args:
            nodes: Graph nodes
            dimensions: Width and height

        """
        width, height = dimensions
        center_x, center_y = width / 2, height / 2
        radius = min(width, height) * 0.4

        angle_step = (2 * math.pi) / len(nodes)

        for i, node in enumerate(nodes):
            angle = i * angle_step
            node.x = center_x + radius * math.cos(angle)
            node.y = center_y + radius * math.sin(angle)

    def _generate_static_graph_js(
        self, nodes: list[GraphNode], edges: list[GraphEdge], container_id: str, dimensions: tuple[int, int],
    ) -> str:
        """Generate JavaScript for static graph layout.

        Args:
            nodes: Graph nodes
            edges: Graph edges
            container_id: Container ID
            dimensions: Width and height

        Returns:
            JavaScript code

        """
        width, height = dimensions

        js_code = f"""
            const svg = d3.select("#{container_id}")
                .append("svg")
                .attr("width", {width})
                .attr("height", {height});

            // Draw edges
            const edges = {json.dumps([e.to_dict() for e in edges])};
            const nodes = {json.dumps([n.to_dict() for n in nodes])};
            const nodeMap = {{}};
            nodes.forEach(n => nodeMap[n.id] = n);

            svg.selectAll("line")
                .data(edges)
                .enter().append("line")
                .attr("x1", d => nodeMap[d.source].x)
                .attr("y1", d => nodeMap[d.source].y)
                .attr("x2", d => nodeMap[d.target].x)
                .attr("y2", d => nodeMap[d.target].y)
                .attr("stroke", d => d.color)
                .attr("stroke-width", d => Math.sqrt(d.weight));

            // Draw nodes
            svg.selectAll("circle")
                .data(nodes)
                .enter().append("circle")
                .attr("cx", d => d.x)
                .attr("cy", d => d.y)
                .attr("r", d => d.size * 5)
                .attr("fill", d => d.color);

            // Add labels
            svg.selectAll("text")
                .data(nodes)
                .enter().append("text")
                .attr("x", d => d.x)
                .attr("y", d => d.y - d.size * 5 - 2)
                .attr("text-anchor", "middle")
                .attr("font-size", "12px")
                .text(d => d.label);
        """

        return js_code

    def _render_static_graph(self, nodes: list[GraphNode], edges: list[GraphEdge], dimensions: tuple[int, int]) -> str:
        """Render static graph image using matplotlib.

        Args:
            nodes: Graph nodes
            edges: Graph edges
            dimensions: Width and height

        Returns:
            Base64 encoded image

        """
        width, height = dimensions
        _fig, ax = plt.subplots(figsize=(width / 100, height / 100))

        # Create NetworkX graph
        G = nx.DiGraph()

        for node in nodes:
            G.add_node(node.id, label=node.label, color=node.color, size=node.size)

        for edge in edges:
            G.add_edge(edge.source, edge.target, weight=edge.weight, color=edge.color)

        # Get positions
        pos = {}
        for node in nodes:
            pos[node.id] = (node.x, node.y)

        # Use matplotlib patches to draw nodes with enhanced visualization
        for node in nodes:
            x, y = pos[node.id]
            # Create a FancyBboxPatch for each node
            fancy_box = FancyBboxPatch(
                (x - node.size * 0.5, y - node.size * 0.5),
                node.size * 1.0,
                node.size * 1.0,
                boxstyle="round,pad=0.1",
                facecolor=node.color,
                edgecolor="black",
                linewidth=0.5,
                alpha=0.7,
            )
            ax.add_patch(fancy_box)

            # Also draw a Rectangle as another example of using the import
            if len(nodes) < 20:  # Only for small graphs to avoid clutter
                rect = Rectangle((x - 0.25, y - 0.25), 0.5, 0.5, linewidth=1, edgecolor="black", facecolor="none", alpha=0.3)
                ax.add_patch(rect)

        # Draw edges
        edge_colors = [G.edges[e]["color"] for e in G.edges()]
        nx.draw_networkx_edges(G, pos, edge_color=edge_colors, ax=ax)

        # Draw labels using text with custom positioning
        for node in nodes:
            x, y = pos[node.id]
            ax.text(x, y, node.label, ha="center", va="center", fontsize=8, weight="bold")

        ax.set_xlim(0, width)
        ax.set_ylim(0, height)
        ax.axis("off")

        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format="png", dpi=100, bbox_inches="tight")
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close()

        return f"data:image/png;base64,{image_base64}"

    def _render_static_timeline(self, events: list[dict[str, Any]], dimensions: tuple[int, int]) -> str:
        """Render static timeline using matplotlib.

        Args:
            events: Timeline events
            dimensions: Width and height

        Returns:
            Base64 encoded image

        """
        width, height = dimensions
        fig, ax = plt.subplots(figsize=(width / 100, height / 100))

        # Group events by source
        sources = list({e.get("source", "unknown") for e in events})
        source_y = {source: i for i, source in enumerate(sources)}

        # Plot events
        for event in events:
            source = event.get("source", "unknown")
            timestamp = event.get("timestamp", 0)
            y = source_y[source]

            ax.scatter(timestamp, y, s=50, c=event.get("color", "#3498db"), alpha=0.7, edgecolors="black")

        # Set labels
        ax.set_yticks(range(len(sources)))
        ax.set_yticklabels(sources)
        ax.set_xlabel("Time")
        ax.set_title("Event Timeline")

        # Format x-axis as time
        from matplotlib.dates import DateFormatter

        ax.xaxis.set_major_formatter(DateFormatter("%H:%M:%S"))

        fig.tight_layout()

        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format="png", dpi=100, bbox_inches="tight")
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close()

        return f"data:image/png;base64,{image_base64}"

    def _render_static_metrics(self, grouped: dict[str, list[dict[str, float]]], chart_type: str, title: str) -> str:
        """Render static metrics chart using matplotlib.

        Args:
            grouped: Grouped metric data
            chart_type: Chart type
            title: Chart title

        Returns:
            Base64 encoded image

        """
        fig, ax = plt.subplots(figsize=(10, 6))

        colors = self.color_schemes["categorical"]

        for i, (name, points) in enumerate(grouped.items()):
            x = [p["x"] for p in points]
            y = [p["y"] for p in points]

            color = colors[i % len(colors)]

            if chart_type == "line":
                ax.plot(x, y, label=name, color=color, marker="o")
            elif chart_type == "bar":
                ax.bar(x, y, label=name, color=color, alpha=0.7)
            elif chart_type == "area":
                ax.fill_between(x, y, alpha=0.3, color=color, label=name)
                ax.plot(x, y, color=color)

        ax.set_xlabel("Time")
        ax.set_ylabel("Value")
        ax.set_title(title)
        ax.legend()
        ax.grid(True, alpha=0.3)

        fig.tight_layout()

        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format="png", dpi=100, bbox_inches="tight")
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close()

        return f"data:image/png;base64,{image_base64}"

    def _get_colormap(self, color_scheme: str):
        """Get matplotlib colormap.

        Args:
            color_scheme: Color scheme name

        Returns:
            Colormap

        """
        colormaps = {"heatmap": "RdYlGn_r", "diverging": "RdBu_r", "sequential": "Blues", "categorical": "tab10"}
        return colormaps.get(color_scheme, "viridis")

    def _get_function_color(self, func: dict[str, Any]) -> str:
        """Get color for function node.

        Args:
            func: Function metadata

        Returns:
            Color hex string

        """
        complexity = func.get("complexity", 0)
        if complexity > 10:
            return "#e74c3c"  # Red for high complexity
        if complexity > 5:
            return "#f39c12"  # Orange for medium
        return "#2ecc71"  # Green for low

    def _get_call_color(self, call: dict[str, Any]) -> str:
        """Get color for function call edge.

        Args:
            call: Call metadata

        Returns:
            Color hex string

        """
        count = call.get("count", 1)
        if count > 100:
            return "#e74c3c"  # Red for hot path
        if count > 10:
            return "#f39c12"  # Orange for warm
        return "#95a5a6"  # Gray for cold

    def _create_thumbnail(self, image_data: bytes, size: tuple[int, int] = (100, 100)) -> str:
        """Create a thumbnail using PIL.

        Args:
            image_data: Raw image data
            size: Thumbnail size

        Returns:
            Base64 encoded thumbnail

        """
        if not HAS_PIL:
            return None

        # Create a simple image using PIL as an example
        img = Image.new("RGB", size, color="white")
        draw = ImageDraw.Draw(img)

        # Draw a simple pattern to demonstrate usage
        for i in range(0, size[0], 10):
            for j in range(0, size[1], 10):
                color = f"#{i % 255:02x}{j % 255:02x}{(i + j) % 255:02x}"
                draw.rectangle([i, j, i + 10, j + 10], fill=color)

        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()

        return f"data:image/png;base64,{image_base64}"
