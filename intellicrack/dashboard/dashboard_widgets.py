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
from typing import Any, cast


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
        history_size = config.options.get("history_size", 100)
        if not isinstance(history_size, int):
            history_size = 100
        self.data_history: deque[WidgetData] = deque(maxlen=history_size)
        self.last_update: datetime = datetime.now()
        self.render_cache: object | None = None

    def update_data(self, data: WidgetData) -> None:
        """Update widget data.

        Args:
            data: New widget data

        Returns:
            None

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
        if current := self.get_current_data():
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
        else:
            return {
                "type": "widget",
                "id": self.config.widget_id,
                "title": self.config.title,
                "status": "no_data",
                "last_update": self.last_update.isoformat() if self.last_update else None,
            }

    def get_current_data(self) -> WidgetData | None:
        """Get current widget data.

        Returns:
            Most recent widget data

        """
        return self.data_history[-1] if self.data_history else None


class LineChartWidget(DashboardWidget):
    """Line chart widget for time series data."""

    def render(self, format: str = "json") -> dict[str, object] | None:
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
        """Render as JSON data.

        Returns:
            JSON representation of line chart data with series information

        """
        x_data: list[str] = []
        y_data: dict[str, list[object]] = {}

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

    def _render_plotly(self) -> dict[str, object]:
        """Render using Plotly.

        Returns:
            Plotly Figure object as dict

        """
        fig = go.Figure()

        x_data = [data.timestamp for data in self.data_history]

        series_data: dict[str, list[object]] = {}
        for data in self.data_history:
            for key, value in data.values.items():
                if key not in series_data:
                    series_data[key] = []
                series_data[key].append(value)

        # Add traces
        for name, values in series_data.items():
            fig.add_trace(go.Scatter(x=x_data, y=values, mode="lines+markers", name=name))

        fig.update_layout(
            title=self.config.title,
            xaxis_title="Time",
            yaxis_title="Value",
            width=self.config.width,
            height=self.config.height,
        )

        return cast("dict[str, object]", fig.to_dict())

    def _render_matplotlib(self) -> dict[str, object]:
        """Render using Matplotlib.

        Returns:
            Matplotlib Figure data as dict

        """
        fig = Figure(figsize=(self.config.width / 100, self.config.height / 100))
        FigureCanvasAgg(fig)
        ax = fig.add_subplot(111)

        x_data = list(range(len(self.data_history)))

        all_keys: set[str] = set()
        for data in self.data_history:
            all_keys.update(data.values.keys())

        for key in all_keys:
            y_values: list[float] = []
            for d in self.data_history:
                val = d.values.get(key, 0)
                if isinstance(val, (int, float)):
                    y_values.append(float(val))
                else:
                    y_values.append(0.0)
            ax.plot(x_data, y_values, label=str(key))

        ax.set_title(self.config.title)
        ax.set_xlabel("Time")
        ax.set_ylabel("Value")
        ax.legend()
        ax.grid(True)

        return {"type": "matplotlib", "figure": fig}


class GaugeWidget(DashboardWidget):
    """Gauge widget for single metric display."""

    def render(self, format: str = "json") -> dict[str, object] | None:
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
        min_val_obj = self.config.options.get("min", 0)
        max_val_obj = self.config.options.get("max", 100)
        min_val = float(min_val_obj) if isinstance(min_val_obj, (int, float)) else 0.0
        max_val = float(max_val_obj) if isinstance(max_val_obj, (int, float)) else 100.0

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
            threshold_val = self.config.options.get("threshold", max_val * 0.9)
            threshold = float(threshold_val) if isinstance(threshold_val, (int, float)) else max_val * 0.9
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
                            "value": threshold,
                        },
                    },
                ),
            )
            fig.update_layout(width=self.config.width, height=self.config.height)
            return cast("dict[str, object]", fig.to_dict())
        json_result = self.render("json")
        return json_result if json_result is not None else None

    def _get_gauge_steps(self) -> list[dict[str, object]]:
        """Get gauge color steps.

        Returns:
            List of gauge threshold steps with color ranges

        """
        thresholds_obj = self.config.options.get("thresholds", [])
        if not isinstance(thresholds_obj, list):
            return []
        thresholds: list[Any] = thresholds_obj
        if not thresholds:
            return []

        colors = ["green", "yellow", "orange", "red"]
        result: list[dict[str, object]] = []
        for i, threshold_item in enumerate(thresholds):
            if isinstance(threshold_item, dict):
                threshold: dict[str, Any] = threshold_item
                result.append({
                    "range": [threshold.get("min", 0), threshold.get("max", 100)],
                    "color": colors[min(i, len(colors) - 1)],
                })
        return result


class TableWidget(DashboardWidget):
    """Table widget for structured data display."""

    def render(self, format: str = "json") -> dict[str, object] | None:
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
            html_table = self._render_html_table(current)
            return {"type": "html", "content": html_table}
        json_result = self.render("json")
        return json_result if json_result is not None else None

    def _render_html_table(self, data: WidgetData) -> str:
        """Render as HTML table.

        Args:
            data: Widget data to render as HTML table

        Returns:
            HTML string representation of table

        """
        rows_obj = data.values.get("rows", [])
        columns_obj = data.values.get("columns", [])

        if not isinstance(rows_obj, list):
            rows_obj = []
        if not isinstance(columns_obj, list):
            columns_obj = []

        rows: list[Any] = rows_obj
        columns: list[Any] = columns_obj

        html = f"<table class='dashboard-table' id='{self.config.widget_id}'>"
        html += f"<caption>{self.config.title}</caption>"

        html += "<thead><tr>"
        for col in columns:
            html += f"<th>{col}</th>"
        html += "</tr></thead>"

        html += "<tbody>"
        for row in rows:
            if isinstance(row, dict):
                html += "<tr>"
                for col in columns:
                    value = row.get(str(col), "")
                    html += f"<td>{value}</td>"
                html += "</tr>"
        html += "</tbody>"

        html += "</table>"
        return html


class HeatmapWidget(DashboardWidget):
    """Heatmap widget for 2D data visualization."""

    def render(self, format: str = "json") -> dict[str, object] | None:
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
            fig = go.Figure(
                data=go.Heatmap(
                    z=matrix,
                    x=x_labels,
                    y=y_labels,
                    colorscale=self.config.options.get("colorscale", "viridis"),
                )
            )
            fig.update_layout(title=self.config.title, width=self.config.width, height=self.config.height)
            return cast("dict[str, object]", fig.to_dict())
        json_result = self.render("json")
        return json_result if json_result is not None else None


class NetworkGraphWidget(DashboardWidget):
    """Network graph widget for relationship visualization."""

    def render(self, format: str = "json") -> dict[str, object] | None:
        """Render network graph.

        Args:
            format: Output format

        Returns:
            Rendered network graph

        """
        current = self.get_current_data()
        if not current:
            return None

        nodes_obj = current.values.get("nodes", [])
        edges_obj = current.values.get("edges", [])

        if not isinstance(nodes_obj, list):
            nodes_obj = []
        if not isinstance(edges_obj, list):
            edges_obj = []

        nodes: list[dict[str, object]] = [n for n in nodes_obj if isinstance(n, dict)]
        edges: list[dict[str, object]] = [e for e in edges_obj if isinstance(e, dict)]

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
        json_result = self.render("json")
        return json_result if json_result is not None else None

    def _render_plotly_network(self, nodes: list[dict[str, object]], edges: list[dict[str, object]]) -> dict[str, object]:
        """Render network using Plotly.

        Args:
            nodes: List of node dictionaries with id and optional label
            edges: List of edge dictionaries with source and target node IDs

        Returns:
            Plotly Figure as dict with network graph visualization

        """
        n = len(nodes)
        node_positions: dict[object, tuple[float, float]] = {}
        for i, node in enumerate(nodes):
            angle = 2 * math.pi * i / n if n > 0 else 0
            x = math.cos(angle)
            y = math.sin(angle)
            node_id = node.get("id", i)
            node_positions[node_id] = (x, y)

        edge_x: list[float | None] = []
        edge_y: list[float | None] = []

        for edge in edges:
            source_id = edge.get("source")
            target_id = edge.get("target")
            x0, y0 = node_positions.get(source_id, (0.0, 0.0))
            x1, y1 = node_positions.get(target_id, (0.0, 0.0))
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(x=edge_x, y=edge_y, line={"width": 0.5, "color": "#888"}, hoverinfo="none", mode="lines")

        node_x = [pos[0] for pos in node_positions.values()]
        node_y = [pos[1] for pos in node_positions.values()]
        node_text = [str(node.get("label", node.get("id", ""))) for node in nodes]

        node_adjacencies: list[int] = []
        for node in nodes:
            node_id = node.get("id")
            adjacencies = sum(bool(edge.get("source") == node_id or edge.get("target") == node_id) for edge in edges)
            node_adjacencies.append(adjacencies)

        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            mode="markers+text",
            hoverinfo="text",
            text=node_text,
            textposition="top center",
            marker={
                "showscale": True,
                "colorscale": "YlGnBu",
                "size": 10,
                "color": node_adjacencies,
                "colorbar": {
                    "thickness": 15,
                    "title": "Node Connections",
                    "xanchor": "left",
                    "titleside": "right",
                },
                "line_width": 2,
            },
        )

        fig = make_subplots(
            rows=1,
            cols=1,
            subplot_titles=[self.config.title],
        )

        fig.add_trace(edge_trace, row=1, col=1)
        fig.add_trace(node_trace, row=1, col=1)

        fig.update_layout(
            showlegend=False,
            hovermode="closest",
            margin={"b": 20, "l": 5, "r": 5, "t": 40},
            xaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
            yaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
            width=self.config.width,
            height=self.config.height,
        )

        return cast("dict[str, object]", fig.to_dict())


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

        events: list[dict[str, object]] = []
        for data in self.data_history:
            events_obj = data.values.get("events", [])
            if isinstance(events_obj, list):
                for event_item in events_obj:
                    if isinstance(event_item, dict):
                        event: dict[str, Any] = event_item
                        events.append({
                            "timestamp": data.timestamp.isoformat(),
                            "title": event.get("title", ""),
                            "description": event.get("description", ""),
                            "type": event.get("type", "info"),
                            "tool": event.get("tool", "unknown"),
                        })
        if format == "json":
            return {
                "type": "timeline",
                "title": self.config.title,
                "events": events,
                "groupBy": self.config.options.get("groupBy", "tool"),
            }
        json_result = self.render("json")
        return json_result if json_result is not None else None


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

        value_obj = current.values.get("value", 0)
        total_obj = current.values.get("total", 100)

        value = float(value_obj) if isinstance(value_obj, (int, float)) else 0.0
        total = float(total_obj) if isinstance(total_obj, (int, float)) else 100.0
        if format == "json":
            percentage = (value / total * 100) if total > 0 else 0.0

            return {
                "type": "progress",
                "title": self.config.title,
                "value": value,
                "total": total,
                "percentage": percentage,
                "label": current.values.get("label", ""),
                "color": self._get_progress_color(percentage),
            }
        json_result = self.render("json")
        return json_result if json_result is not None else None

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
        return "yellow" if percentage < 75 else "green"


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
            logger.warning("Unknown widget type: %s", config.widget_type)
            return DashboardWidget(config)

        return widget_class(config)


def create_widget(widget_id: str, widget_type: WidgetType, title: str, **kwargs: Any) -> DashboardWidget:
    """Create a widget.

    Args:
        widget_id: Unique widget identifier
        widget_type: Type of widget
        title: Widget title
        **kwargs: Additional configuration options

    Returns:
        Dashboard widget instance

    """
    width = kwargs.get("width", 400)
    height = kwargs.get("height", 300)
    refresh_interval = kwargs.get("refresh_interval", 5.0)
    data_source = kwargs.get("data_source")
    options = kwargs.get("options", {})

    if not isinstance(width, int):
        width = 400
    if not isinstance(height, int):
        height = 300
    if not isinstance(refresh_interval, (int, float)):
        refresh_interval = 5.0
    if not isinstance(data_source, str) and data_source is not None:
        data_source = None
    validated_options: dict[str, object] = options if isinstance(options, dict) else {}

    config = WidgetConfig(
        widget_id=widget_id,
        widget_type=widget_type,
        title=title,
        width=width,
        height=height,
        refresh_interval=float(refresh_interval),
        data_source=data_source,
        options=validated_options,
    )
    return WidgetFactory.create_widget(config)
