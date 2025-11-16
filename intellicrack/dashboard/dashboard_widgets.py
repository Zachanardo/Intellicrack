"""Dashboard Widgets for Intellicrack Analysis.

This module provides individual widget components for the real-time dashboard,
including graphs, meters, tables, and other visualization elements.

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

import logging
import math
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

try:
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure

    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots

    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

logger = logging.getLogger(__name__)


class WidgetType(Enum):
    """Types of dashboard widgets."""

    LINE_CHART = "line_chart"
    BAR_CHART = "bar_chart"
    PIE_CHART = "pie_chart"
    GAUGE = "gauge"
    HEATMAP = "heatmap"
    SCATTER = "scatter"
    TABLE = "table"
    TEXT = "text"
    PROGRESS = "progress"
    NETWORK_GRAPH = "network_graph"
    TIMELINE = "timeline"
    SPARKLINE = "sparkline"


@dataclass
class WidgetConfig:
    """Configuration for a dashboard widget."""

    widget_id: str
    widget_type: WidgetType
    title: str
    width: int = 400
    height: int = 300
    refresh_interval: float = 5.0
    data_source: str | None = None
    options: dict[str, object] = field(default_factory=dict)


@dataclass
class WidgetData:
    """Data for widget rendering."""

    timestamp: datetime
    values: dict[str, object]
    labels: list[str] | None = None
    categories: list[str] | None = None
    metadata: dict[str, object] = field(default_factory=dict)


class DashboardWidget:
    """Base class for dashboard widgets."""

    def __init__(self, config: WidgetConfig) -> None:
        """Initialize widget.

        Args:
            config: Widget configuration

        """
        self.config = config
        self.logger = logger
        self.data_history: deque[WidgetData] = deque(maxlen=config.options.get("history_size", 100))
        self.last_update: datetime = datetime.now()
        self.render_cache: object | None = None

    def update_data(self, data: WidgetData) -> None:
        """Update widget data.

        Args:
            data: New widget data

        """
        self.data_history.append(data)
        self.last_update = datetime.now()
        self.render_cache = None  # Invalidate cache

    def render(self, format: str = "json") -> dict[str, object] | None:
        """Render widget.

        Args:
            format: Output format (json, html, image)

        Returns:
            Rendered widget data

        """
        # Default implementation returns basic JSON representation
        current = self.get_current_data()
        if not current:
            return {
                "type": "widget",
                "id": self.config.widget_id,
                "title": self.config.title,
                "status": "no_data",
                "last_update": self.last_update.isoformat() if self.last_update else None,
            }

        return {
            "type": self.config.widget_type.value if hasattr(self.config.widget_type, "value") else "widget",
            "id": self.config.widget_id,
            "title": self.config.title,
            "timestamp": current.timestamp.isoformat(),
            "values": current.values,
            "labels": current.labels,
            "categories": current.categories,
            "metadata": current.metadata,
            "last_update": self.last_update.isoformat(),
        }

    def get_current_data(self) -> WidgetData | None:
        """Get current widget data.

        Returns:
            Most recent widget data

        """
        return self.data_history[-1] if self.data_history else None


class LineChartWidget(DashboardWidget):
    """Line chart widget for time series data."""

    def render(self, format: str = "json") -> dict[str, object] | object | None:
        """Render line chart.

        Args:
            format: Output format

        Returns:
            Rendered chart data

        """
        if not self.data_history:
            return None

        if format == "json":
            return self._render_json()
        if format == "plotly" and HAS_PLOTLY:
            return self._render_plotly()
        if format == "matplotlib" and HAS_MATPLOTLIB:
            return self._render_matplotlib()
        return self._render_json()

    def _render_json(self) -> dict[str, object]:
        """Render as JSON data."""
        x_data = []
        y_data = {}

        for data in self.data_history:
            x_data.append(data.timestamp.isoformat())
            for key, value in data.values.items():
                if key not in y_data:
                    y_data[key] = []
                y_data[key].append(value)

        return {
            "type": "line_chart",
            "title": self.config.title,
            "x": x_data,
            "series": [{"name": key, "data": values} for key, values in y_data.items()],
        }

    def _render_plotly(self) -> object:
        """Render using Plotly.

        Returns:
            Plotly Figure object

        """
        fig = go.Figure()

        x_data = [data.timestamp for data in self.data_history]

        # Collect all series
        series_data = {}
        for data in self.data_history:
            for key, value in data.values.items():
                if key not in series_data:
                    series_data[key] = []
                series_data[key].append(value)

        # Add traces
        for name, values in series_data.items():
            fig.add_trace(go.Scatter(x=x_data, y=values, mode="lines+markers", name=name))

        fig.update_layout(
            title=self.config.title, xaxis_title="Time", yaxis_title="Value", width=self.config.width, height=self.config.height,
        )

        return fig

    def _render_matplotlib(self) -> Figure:
        """Render using Matplotlib.

        Returns:
            Matplotlib Figure object

        """
        fig = Figure(figsize=(self.config.width / 100, self.config.height / 100))
        FigureCanvasAgg(fig)  # Use FigureCanvasAgg that was imported
        ax = fig.add_subplot(111)

        x_data = [data.timestamp for data in self.data_history]

        # Collect all series
        for data in self.data_history:
            for key, _value in data.values.items():
                ax.plot(x_data, [d.values.get(key, 0) for d in self.data_history], label=key)

        ax.set_title(self.config.title)
        ax.set_xlabel("Time")
        ax.set_ylabel("Value")
        ax.legend()
        ax.grid(True)

        return fig


class GaugeWidget(DashboardWidget):
    """Gauge widget for single metric display."""

    def render(self, format: str = "json") -> dict[str, object] | object | None:
        """Render gauge.

        Args:
            format: Output format

        Returns:
            Rendered gauge data

        """
        current = self.get_current_data()
        if not current:
            return None

        value = next(iter(current.values.values())) if current.values else 0
        min_val = self.config.options.get("min", 0)
        max_val = self.config.options.get("max", 100)

        if format == "json":
            return {
                "type": "gauge",
                "title": self.config.title,
                "value": value,
                "min": min_val,
                "max": max_val,
                "units": self.config.options.get("units", ""),
                "thresholds": self.config.options.get("thresholds", []),
            }
        if format == "plotly" and HAS_PLOTLY:
            fig = go.Figure(
                go.Indicator(
                    mode="gauge+number",
                    value=value,
                    title={"text": self.config.title},
                    domain={"x": [0, 1], "y": [0, 1]},
                    gauge={
                        "axis": {"range": [min_val, max_val]},
                        "bar": {"color": "darkblue"},
                        "steps": self._get_gauge_steps(),
                        "threshold": {
                            "line": {"color": "red", "width": 4},
                            "thickness": 0.75,
                            "value": self.config.options.get("threshold", max_val * 0.9),
                        },
                    },
                ),
            )
            fig.update_layout(width=self.config.width, height=self.config.height)
            return fig
        return self.render("json")

    def _get_gauge_steps(self) -> list[dict[str, object]]:
        """Get gauge color steps.

        Returns:
            List of gauge threshold steps with color ranges

        """
        thresholds = self.config.options.get("thresholds", [])
        if not thresholds:
            return []

        steps = []
        colors = ["green", "yellow", "orange", "red"]
        for i, threshold in enumerate(thresholds):
            steps.append({"range": [threshold.get("min", 0), threshold.get("max", 100)], "color": colors[min(i, len(colors) - 1)]})
        return steps


class TableWidget(DashboardWidget):
    """Table widget for structured data display."""

    def render(self, format: str = "json") -> dict[str, object] | str | None:
        """Render table.

        Args:
            format: Output format

        Returns:
            Rendered table data

        """
        current = self.get_current_data()
        if not current:
            return None

        if format == "json":
            rows = current.values.get("rows", [])
            columns = current.values.get("columns", [])

            return {
                "type": "table",
                "title": self.config.title,
                "columns": columns,
                "rows": rows,
                "sortable": self.config.options.get("sortable", True),
                "filterable": self.config.options.get("filterable", True),
            }
        if format == "html":
            return self._render_html_table(current)
        return self.render("json")

    def _render_html_table(self, data: WidgetData) -> str:
        """Render as HTML table.

        Args:
            data: Widget data to render as HTML table

        Returns:
            HTML string representation of table

        """
        rows = data.values.get("rows", [])
        columns = data.values.get("columns", [])

        html = f"<table class='dashboard-table' id='{self.config.widget_id}'>"
        html += f"<caption>{self.config.title}</caption>"

        # Header
        html += "<thead><tr>"
        for col in columns:
            html += f"<th>{col}</th>"
        html += "</tr></thead>"

        # Body
        html += "<tbody>"
        for row in rows:
            html += "<tr>"
            for col in columns:
                value = row.get(col, "")
                html += f"<td>{value}</td>"
            html += "</tr>"
        html += "</tbody>"

        html += "</table>"
        return html


class HeatmapWidget(DashboardWidget):
    """Heatmap widget for 2D data visualization."""

    def render(self, format: str = "json") -> dict[str, object] | object | None:
        """Render heatmap.

        Args:
            format: Output format

        Returns:
            Rendered heatmap data

        """
        current = self.get_current_data()
        if not current:
            return None

        matrix = current.values.get("matrix", [])
        x_labels = current.labels or []
        y_labels = current.categories or []

        if format == "json":
            return {
                "type": "heatmap",
                "title": self.config.title,
                "matrix": matrix,
                "x_labels": x_labels,
                "y_labels": y_labels,
                "colorscale": self.config.options.get("colorscale", "viridis"),
            }
        if format == "plotly" and HAS_PLOTLY:
            fig = go.Figure(data=go.Heatmap(z=matrix, x=x_labels, y=y_labels, colorscale=self.config.options.get("colorscale", "viridis")))
            fig.update_layout(title=self.config.title, width=self.config.width, height=self.config.height)
            return fig
        return self.render("json")


class NetworkGraphWidget(DashboardWidget):
    """Network graph widget for relationship visualization."""

    def render(self, format: str = "json") -> dict[str, object] | object | None:
        """Render network graph.

        Args:
            format: Output format

        Returns:
            Rendered network graph

        """
        current = self.get_current_data()
        if not current:
            return None

        nodes = current.values.get("nodes", [])
        edges = current.values.get("edges", [])

        if format == "json":
            return {
                "type": "network_graph",
                "title": self.config.title,
                "nodes": nodes,
                "edges": edges,
                "layout": self.config.options.get("layout", "force"),
                "directed": self.config.options.get("directed", True),
            }
        if format == "plotly" and HAS_PLOTLY:
            return self._render_plotly_network(nodes, edges)
        return self.render("json")

    def _render_plotly_network(self, nodes: list[dict[str, object]], edges: list[dict[str, object]]) -> object:
        """Render network using Plotly.

        Args:
            nodes: List of node dictionaries with id and optional label
            edges: List of edge dictionaries with source and target node IDs

        Returns:
            Plotly Figure object with network graph visualization

        """
        # Calculate node positions (simple circular layout)
        n = len(nodes)
        node_positions = {}
        for i, node in enumerate(nodes):
            angle = 2 * math.pi * i / n
            x = math.cos(angle)
            y = math.sin(angle)
            node_positions[node["id"]] = (x, y)

        # Create edge traces
        edge_trace = go.Scatter(x=[], y=[], line={"width": 0.5, "color": "#888"}, hoverinfo="none", mode="lines")

        for edge in edges:
            x0, y0 = node_positions.get(edge["source"], (0, 0))
            x1, y1 = node_positions.get(edge["target"], (0, 0))
            edge_trace["x"] += (x0, x1, None)
            edge_trace["y"] += (y0, y1, None)

        # Create node trace
        node_trace = go.Scatter(
            x=[pos[0] for pos in node_positions.values()],
            y=[pos[1] for pos in node_positions.values()],
            mode="markers+text",
            hoverinfo="text",
            text=[node.get("label", node["id"]) for node in nodes],
            textposition="top center",
            marker={
                "showscale": True,
                "colorscale": "YlGnBu",
                "size": 10,
                "color": [],
                "colorbar": {"thickness": 15, "title": "Node Connections", "xanchor": "left", "titleside": "right"},
                "line_width": 2,
            },
        )

        # Color nodes by connections
        node_adjacencies = []
        for node in nodes:
            adjacencies = sum(1 for edge in edges if edge["source"] == node["id"] or edge["target"] == node["id"])
            node_adjacencies.append(adjacencies)

        node_trace.marker.color = node_adjacencies

        # Use make_subplots to create the network visualization
        fig = make_subplots(
            rows=1,
            cols=1,
            subplot_titles=[self.config.title],
        )

        # Add traces to subplots
        fig.add_trace(edge_trace, row=1, col=1)
        fig.add_trace(node_trace, row=1, col=1)

        # Update layout properties
        fig.update_layout(
            showlegend=False,
            hovermode="closest",
            margin={"b": 20, "l": 5, "r": 5, "t": 40},
            xaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
            yaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
            width=self.config.width,
            height=self.config.height,
        )

        return fig


class TimelineWidget(DashboardWidget):
    """Timeline widget for event visualization."""

    def render(self, format: str = "json") -> dict[str, object] | None:
        """Render timeline.

        Args:
            format: Output format

        Returns:
            Rendered timeline

        """
        if not self.data_history:
            return None

        events = []
        for data in self.data_history:
            for event in data.values.get("events", []):
                events.append(
                    {
                        "timestamp": data.timestamp.isoformat(),
                        "title": event.get("title", ""),
                        "description": event.get("description", ""),
                        "type": event.get("type", "info"),
                        "tool": event.get("tool", "unknown"),
                    },
                )

        if format == "json":
            return {"type": "timeline", "title": self.config.title, "events": events, "groupBy": self.config.options.get("groupBy", "tool")}
        return self.render("json")


class ProgressWidget(DashboardWidget):
    """Progress bar widget."""

    def render(self, format: str = "json") -> dict[str, object] | None:
        """Render progress bar.

        Args:
            format: Output format

        Returns:
            Rendered progress data

        """
        current = self.get_current_data()
        if not current:
            return None

        value = current.values.get("value", 0)
        total = current.values.get("total", 100)
        percentage = (value / total * 100) if total > 0 else 0

        if format == "json":
            return {
                "type": "progress",
                "title": self.config.title,
                "value": value,
                "total": total,
                "percentage": percentage,
                "label": current.values.get("label", ""),
                "color": self._get_progress_color(percentage),
            }
        return self.render("json")

    def _get_progress_color(self, percentage: float) -> str:
        """Get progress bar color based on percentage.

        Args:
            percentage: Progress percentage (0-100)

        Returns:
            Color name for progress bar

        """
        if percentage < 25:
            return "red"
        if percentage < 50:
            return "orange"
        if percentage < 75:
            return "yellow"
        return "green"


class WidgetFactory:
    """Factory for creating dashboard widgets."""

    @staticmethod
    def create_widget(config: WidgetConfig) -> DashboardWidget:
        """Create widget based on configuration.

        Args:
            config: Widget configuration

        Returns:
            Dashboard widget instance

        """
        widget_map = {
            WidgetType.LINE_CHART: LineChartWidget,
            WidgetType.GAUGE: GaugeWidget,
            WidgetType.TABLE: TableWidget,
            WidgetType.HEATMAP: HeatmapWidget,
            WidgetType.NETWORK_GRAPH: NetworkGraphWidget,
            WidgetType.TIMELINE: TimelineWidget,
            WidgetType.PROGRESS: ProgressWidget,
        }

        widget_class = widget_map.get(config.widget_type)
        if not widget_class:
            logger.warning(f"Unknown widget type: {config.widget_type}")
            return DashboardWidget(config)

        return widget_class(config)


def create_widget(widget_id: str, widget_type: WidgetType, title: str, **kwargs: object) -> DashboardWidget:
    """Create a widget.

    Args:
        widget_id: Unique widget identifier
        widget_type: Type of widget
        title: Widget title
        **kwargs: Additional configuration options

    Returns:
        Dashboard widget instance

    """
    config = WidgetConfig(widget_id=widget_id, widget_type=widget_type, title=title, **kwargs)
    return WidgetFactory.create_widget(config)
