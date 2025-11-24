"""Dashboard Manager for Intellicrack Analysis.

This module manages the overall dashboard system, coordinating between
widgets, data sources, and the real-time dashboard display.

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
import threading
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from .dashboard_widgets import DashboardWidget, WidgetData, WidgetType, create_widget
from .real_time_dashboard import DashboardEvent, DashboardEventType, create_dashboard


logger = logging.getLogger(__name__)


class DataSourceType(Enum):
    """Types of data sources."""

    GHIDRA = "ghidra"
    FRIDA = "frida"
    RADARE2 = "radare2"
    CROSS_TOOL = "cross_tool"
    PERFORMANCE = "performance"
    SYSTEM = "system"
    CUSTOM = "custom"


@dataclass
class DataSource:
    """Data source configuration.

    Attributes:
        source_id: Unique identifier for this data source
        source_type: Type of data source (GHIDRA, FRIDA, etc.)
        name: Human-readable name for the data source
        poll_interval: Time in seconds between polling attempts (default: 5.0)
        enabled: Whether this data source is active (default: True)
        config: Configuration dictionary for data source parameters (default: empty dict)
        last_poll: Timestamp of last successful poll (default: None)
        data_callback: Callable to invoke for data collection (default: None)

    """

    source_id: str
    source_type: DataSourceType
    name: str
    poll_interval: float = 5.0
    enabled: bool = True
    config: dict[str, Any] = field(default_factory=dict)
    last_poll: datetime | None = None
    data_callback: Callable[[], dict[str, Any]] | None = None


@dataclass
class DashboardLayout:
    """Dashboard layout configuration.

    Attributes:
        layout_id: Unique identifier for this layout
        name: Human-readable name for the layout
        rows: Number of grid rows (default: 3)
        columns: Number of grid columns (default: 4)
        widgets: List of widget placement configurations (default: empty list)
        theme: Visual theme name (default: "dark")
        refresh_rate: UI refresh rate in seconds (default: 1.0)

    """

    layout_id: str
    name: str
    rows: int = 3
    columns: int = 4
    widgets: list[dict[str, Any]] = field(default_factory=list)
    theme: str = "dark"
    refresh_rate: float = 1.0


class DashboardManager:
    """Manages the overall dashboard system."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize dashboard manager.

        Args:
            config: Dashboard configuration

        """
        self.logger = logger
        self.config = config or {}

        # Core components
        self.dashboard = create_dashboard(self.config.get("dashboard_config", {}))
        self.widgets: dict[str, DashboardWidget] = {}
        self.data_sources: dict[str, DataSource] = {}
        self.layouts: dict[str, DashboardLayout] = {}

        # Current state
        self.current_layout: DashboardLayout | None = None
        self.active_analyses: set[str] = set()

        # Data routing
        self.widget_subscriptions: dict[str, list[str]] = defaultdict(list)
        self.source_subscriptions: dict[str, list[str]] = defaultdict(list)

        # Threading
        self.polling_thread: threading.Thread | None = None
        self.stop_polling = threading.Event()
        self.update_lock = threading.Lock()

        # Tool integrations
        self.tool_handlers: dict[str, object] = {}

        # Initialize default components
        self._initialize_default_layout()
        self._initialize_default_widgets()
        self._initialize_default_sources()

    def _initialize_default_layout(self) -> None:
        """Initialize default dashboard layout."""
        default_layout = DashboardLayout(
            layout_id="default",
            name="Default Layout",
            rows=3,
            columns=4,
            widgets=[
                {"row": 0, "col": 0, "width": 2, "height": 1, "widget_id": "performance_gauge"},
                {"row": 0, "col": 2, "width": 2, "height": 1, "widget_id": "memory_gauge"},
                {"row": 1, "col": 0, "width": 4, "height": 1, "widget_id": "timeline"},
                {"row": 2, "col": 0, "width": 2, "height": 1, "widget_id": "vulnerabilities_table"},
                {"row": 2, "col": 2, "width": 2, "height": 1, "widget_id": "protections_table"},
            ],
        )
        self.add_layout(default_layout)
        self.set_layout("default")

    def _initialize_default_widgets(self) -> None:
        """Initialize default widgets."""
        # Performance gauge
        self.add_widget(
            create_widget(
                "performance_gauge",
                WidgetType.GAUGE,
                "CPU Usage",
                min=0,
                max=100,
                units="%",
                thresholds=[
                    {"min": 0, "max": 50},
                    {"min": 50, "max": 75},
                    {"min": 75, "max": 90},
                    {"min": 90, "max": 100},
                ],
            ),
        )

        # Memory gauge
        self.add_widget(
            create_widget(
                "memory_gauge",
                WidgetType.GAUGE,
                "Memory Usage",
                min=0,
                max=2000,
                units="MB",
                thresholds=[
                    {"min": 0, "max": 500},
                    {"min": 500, "max": 1000},
                    {"min": 1000, "max": 1500},
                    {"min": 1500, "max": 2000},
                ],
            ),
        )

        # Timeline
        self.add_widget(create_widget("timeline", WidgetType.TIMELINE, "Analysis Timeline"))

        # Vulnerabilities table
        self.add_widget(
            create_widget(
                "vulnerabilities_table",
                WidgetType.TABLE,
                "Vulnerabilities Found",
                sortable=True,
                filterable=True,
            )
        )

        # Protections table
        self.add_widget(
            create_widget(
                "protections_table",
                WidgetType.TABLE,
                "Protections Detected",
                sortable=True,
                filterable=True,
            )
        )

        # Analysis progress
        self.add_widget(create_widget("analysis_progress", WidgetType.PROGRESS, "Analysis Progress"))

        # Function analysis chart
        self.add_widget(create_widget("functions_chart", WidgetType.LINE_CHART, "Functions Analyzed", history_size=50))

        # Network graph for call graph
        self.add_widget(create_widget("call_graph", WidgetType.NETWORK_GRAPH, "Call Graph", directed=True, layout="force"))

        # Heatmap for code complexity
        self.add_widget(create_widget("complexity_heatmap", WidgetType.HEATMAP, "Code Complexity", colorscale="viridis"))

    def _initialize_default_sources(self) -> None:
        """Initialize default data sources."""
        # Performance data source
        self.add_data_source(
            DataSource(
                source_id="performance",
                source_type=DataSourceType.PERFORMANCE,
                name="Performance Metrics",
                poll_interval=2.0,
                data_callback=self._collect_performance_data,
            ),
        )

        # System data source
        self.add_data_source(
            DataSource(
                source_id="system",
                source_type=DataSourceType.SYSTEM,
                name="System Metrics",
                poll_interval=5.0,
                data_callback=self._collect_system_data,
            ),
        )

        # Subscribe widgets to sources
        self.subscribe_widget("performance_gauge", "performance")
        self.subscribe_widget("memory_gauge", "performance")
        self.subscribe_widget("functions_chart", "performance")

    def add_widget(self, widget: DashboardWidget) -> None:
        """Add widget to dashboard.

        Args:
            widget: Widget to add

        """
        self.widgets[widget.config.widget_id] = widget
        self.logger.info(f"Added widget: {widget.config.widget_id}")

    def add_data_source(self, source: DataSource) -> None:
        """Add data source.

        Args:
            source: Data source to add

        """
        self.data_sources[source.source_id] = source
        self.logger.info(f"Added data source: {source.source_id}")

    def add_layout(self, layout: DashboardLayout) -> None:
        """Add dashboard layout.

        Args:
            layout: Layout to add

        """
        self.layouts[layout.layout_id] = layout
        self.logger.info(f"Added layout: {layout.layout_id}")

    def set_layout(self, layout_id: str) -> None:
        """Set current dashboard layout.

        Args:
            layout_id: Layout identifier

        """
        if layout_id in self.layouts:
            self.current_layout = self.layouts[layout_id]
            self.logger.info(f"Set layout: {layout_id}")
        else:
            self.logger.warning(f"Layout not found: {layout_id}")

    def subscribe_widget(self, widget_id: str, source_id: str) -> None:
        """Subscribe widget to data source.

        Args:
            widget_id: Widget identifier
            source_id: Data source identifier

        """
        self.widget_subscriptions[source_id].append(widget_id)
        self.source_subscriptions[widget_id].append(source_id)
        self.logger.debug(f"Subscribed widget {widget_id} to source {source_id}")

    def integrate_tool(self, tool_name: str, handler: object) -> None:
        """Integrate analysis tool with dashboard.

        Args:
            tool_name: Tool name
            handler: Tool handler object

        """
        self.tool_handlers[tool_name] = handler

        # Create data source for tool
        source = DataSource(
            source_id=f"{tool_name}_source",
            source_type=DataSourceType.CUSTOM,
            name=f"{tool_name} Data",
            poll_interval=3.0,
            data_callback=lambda: self._collect_tool_data(tool_name),
        )
        self.add_data_source(source)

        self.logger.info(f"Integrated tool: {tool_name}")

    def start(self) -> None:
        """Start dashboard manager."""
        self.logger.info("Starting dashboard manager")

        # Start polling thread
        self.stop_polling.clear()
        self.polling_thread = threading.Thread(target=self._polling_loop, daemon=True)
        self.polling_thread.start()

        # Register dashboard callbacks
        self.dashboard.register_callback(self._handle_dashboard_event)

    def stop(self) -> None:
        """Stop dashboard manager."""
        self.logger.info("Stopping dashboard manager")

        # Stop polling
        self.stop_polling.set()
        if self.polling_thread:
            self.polling_thread.join(timeout=5)

        # Shutdown dashboard
        self.dashboard.shutdown()

    def process_analysis_event(self, event_type: str, tool: str, data: dict[str, Any]) -> None:
        """Process analysis event from tools.

        Args:
            event_type: Type of event
            tool: Tool name
            data: Event data

        """
        # Map to dashboard event type
        event_map = {
            "vulnerability": DashboardEventType.VULNERABILITY_FOUND,
            "protection": DashboardEventType.PROTECTION_DETECTED,
            "function": DashboardEventType.FUNCTION_ANALYZED,
            "error": DashboardEventType.ERROR_OCCURRED,
            "warning": DashboardEventType.WARNING_RAISED,
            "info": DashboardEventType.INFO_MESSAGE,
        }

        dashboard_event_type = event_map.get(event_type, DashboardEventType.INFO_MESSAGE)

        # Create dashboard event
        event = DashboardEvent(
            event_type=dashboard_event_type,
            timestamp=datetime.now(),
            tool=tool,
            title=data.get("title", f"{event_type} from {tool}"),
            description=data.get("description", ""),
            data=data,
            severity=data.get("severity", "info"),
            tags=data.get("tags", []),
        )

        # Add to dashboard
        self.dashboard.add_event(event)

        # Update relevant widgets
        self._update_widgets_for_event(event)

    def get_dashboard_url(self) -> str:
        """Get dashboard URL.

        Returns:
            Dashboard URL

        """
        http_port = self.config.get("dashboard_config", {}).get("http_port", 5000)
        return f"http://localhost:{http_port}"

    def get_websocket_url(self) -> str:
        """Get WebSocket URL.

        Returns:
            WebSocket URL

        """
        ws_port = self.config.get("dashboard_config", {}).get("websocket_port", 8765)
        return f"ws://localhost:{ws_port}"

    def export_dashboard_state(self, filepath: str) -> None:
        """Export dashboard state to file.

        Args:
            filepath: Export file path

        """
        state = {
            "timestamp": datetime.now().isoformat(),
            "dashboard_state": self.dashboard.get_dashboard_state(),
            "widgets": {widget_id: widget.render("json") for widget_id, widget in self.widgets.items()},
            "layouts": {
                layout_id: {
                    "name": layout.name,
                    "rows": layout.rows,
                    "columns": layout.columns,
                    "widgets": layout.widgets,
                }
                for layout_id, layout in self.layouts.items()
            },
            "current_layout": self.current_layout.layout_id if self.current_layout else None,
        }

        with open(filepath, "w") as f:
            json.dump(state, f, indent=2, default=str)

        self.logger.info(f"Exported dashboard state to {filepath}")

    def _polling_loop(self) -> None:
        """Poll data source."""
        while not self.stop_polling.is_set():
            try:
                current_time = datetime.now()

                for source_id, source in self.data_sources.items():
                    if not source.enabled:
                        continue

                    # Check if it's time to poll
                    if source.last_poll:
                        elapsed = (current_time - source.last_poll).total_seconds()
                        if elapsed < source.poll_interval:
                            continue

                    # Poll data source
                    if source.data_callback:
                        try:
                            if data := source.data_callback():
                                self._distribute_data(source_id, data)
                            source.last_poll = current_time
                        except Exception as e:
                            self.logger.error(f"Error polling source {source_id}: {e}")

            except Exception as e:
                self.logger.error(f"Error in polling loop: {e}")

            self.stop_polling.wait(timeout=0.5)

    def _distribute_data(self, source_id: str, data: dict[str, Any]) -> None:
        """Distribute data to subscribed widgets.

        Args:
            source_id: Data source identifier
            data: Data to distribute

        """
        widget_ids = self.widget_subscriptions.get(source_id, [])

        for widget_id in widget_ids:
            if widget_id in self.widgets:
                widget = self.widgets[widget_id]
                widget_data = WidgetData(timestamp=datetime.now(), values=data, metadata={"source": source_id})
                widget.update_data(widget_data)

    def _collect_performance_data(self) -> dict[str, Any]:
        """Collect performance data.

        Returns:
            Performance metrics

        """
        metrics = self.dashboard.get_dashboard_state().get("metrics", {})

        return {
            "cpu_percent": metrics.get("cpu_usage_percent", 0),
            "memory_mb": metrics.get("memory_usage_mb", 0),
            "functions_analyzed": metrics.get("total_functions_analyzed", 0),
            "cache_hit_rate": metrics.get("cache_hit_rate", 0),
        }

    def _collect_system_data(self) -> dict[str, Any]:
        """Collect system data.

        Returns:
            System metrics

        """
        try:
            import psutil

            process = psutil.Process()

            return {
                "cpu_percent": process.cpu_percent(),
                "memory_mb": process.memory_info().rss / (1024 * 1024),
                "num_threads": process.num_threads(),
                "open_files": len(process.open_files()) if hasattr(process, "open_files") else 0,
            }
        except Exception as e:
            self.logger.warning(f"Failed to collect system data: {e}")
            return {}

    def _collect_tool_data(self, tool_name: str) -> dict[str, Any]:
        """Collect data from integrated tool.

        Args:
            tool_name: Tool name

        Returns:
            Tool data

        """
        handler = self.tool_handlers.get(tool_name)
        if not handler:
            return {}

        try:
            # Try to get metrics from tool
            if hasattr(handler, "get_metrics"):
                return handler.get_metrics()
            return handler.get_status() if hasattr(handler, "get_status") else {}
        except Exception as e:
            self.logger.error(f"Error collecting data from {tool_name}: {e}")
            return {}

    def _update_widgets_for_event(self, event: DashboardEvent) -> None:
        """Update widgets based on dashboard event.

        Args:
            event: Dashboard event

        """
        # Update timeline widget
        if "timeline" in self.widgets:
            widget_data = WidgetData(
                timestamp=event.timestamp,
                values={
                    "events": [
                        {
                            "title": event.title,
                            "description": event.description,
                            "type": event.severity,
                            "tool": event.tool,
                        }
                    ]
                },
            )
            self.widgets["timeline"].update_data(widget_data)

        # Update vulnerability table
        if event.event_type == DashboardEventType.VULNERABILITY_FOUND and "vulnerabilities_table" in self.widgets:
            self._update_vulnerability_table(event)

        # Update protection table
        if event.event_type == DashboardEventType.PROTECTION_DETECTED and "protections_table" in self.widgets:
            self._update_protection_table(event)

    def _update_vulnerability_table(self, event: DashboardEvent) -> None:
        """Update vulnerability table widget.

        Args:
            event: Vulnerability event

        """
        widget = self.widgets["vulnerabilities_table"]
        current = widget.get_current_data()

        rows = current.values.get("rows", []) if current else []
        columns = ["Type", "Severity", "Tool", "Location", "Description"]

        rows.append(
            {
                "Type": event.data.get("type", "Unknown"),
                "Severity": event.severity,
                "Tool": event.tool,
                "Location": event.data.get("location", ""),
                "Description": event.description,
            },
        )

        widget_data = WidgetData(timestamp=event.timestamp, values={"rows": rows, "columns": columns})
        widget.update_data(widget_data)

    def _update_protection_table(self, event: DashboardEvent) -> None:
        """Update protection table widget.

        Args:
            event: Protection event

        """
        widget = self.widgets["protections_table"]
        current = widget.get_current_data()

        rows = current.values.get("rows", []) if current else []
        columns = ["Type", "Tool", "Strength", "Location", "Description"]

        rows.append(
            {
                "Type": event.data.get("type", "Unknown"),
                "Tool": event.tool,
                "Strength": event.data.get("strength", "Unknown"),
                "Location": event.data.get("location", ""),
                "Description": event.description,
            },
        )

        widget_data = WidgetData(timestamp=event.timestamp, values={"rows": rows, "columns": columns})
        widget.update_data(widget_data)

    def _handle_dashboard_event(self, event: DashboardEvent) -> None:
        """Handle event from dashboard.

        Args:
            event: Dashboard event

        """
        # Log significant events
        if event.severity in ["error", "critical"]:
            self.logger.error(f"Dashboard event: {event.title} - {event.description}")
        elif event.severity == "warning":
            self.logger.warning(f"Dashboard event: {event.title} - {event.description}")


def create_dashboard_manager(config: dict[str, Any] | None = None) -> DashboardManager:
    """Create dashboard manager.

    Args:
        config: Dashboard configuration

    Returns:
        New DashboardManager instance

    """
    return DashboardManager(config)
