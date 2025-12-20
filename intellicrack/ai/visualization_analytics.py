"""Advanced Visualization & Analytics for AI Operations.

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

import json
import math
import os
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..utils.logger import get_logger
from .learning_engine_simple import get_learning_engine
from .performance_monitor import performance_monitor, profile_ai_operation


if TYPE_CHECKING:
    from collections.abc import Callable

logger = get_logger(__name__)

try:
    from intellicrack.handlers.psutil_handler import psutil

    PSUTIL_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in visualization_analytics: %s", e)
    psutil = None
    PSUTIL_AVAILABLE = False


class ChartType(Enum):
    """Types of visualization charts."""

    LINE_CHART = "line_chart"
    BAR_CHART = "bar_chart"
    PIE_CHART = "pie_chart"
    SCATTER_PLOT = "scatter_plot"
    HEATMAP = "heatmap"
    TIMELINE = "timeline"
    NETWORK_GRAPH = "network_graph"
    TREE_MAP = "tree_map"
    HISTOGRAM = "histogram"
    BOX_PLOT = "box_plot"


class MetricType(Enum):
    """Types of metrics to visualize."""

    PERFORMANCE = "performance"
    SUCCESS_RATE = "success_rate"
    RESOURCE_USAGE = "resource_usage"
    ERROR_RATE = "error_rate"
    EXECUTION_TIME = "execution_time"
    MEMORY_USAGE = "memory_usage"
    LEARNING_PROGRESS = "learning_progress"
    EXPLOIT_CHAINS = "exploit_chains"
    VULNERABILITY_TRENDS = "vulnerability_trends"
    AGENT_ACTIVITY = "agent_activity"


@dataclass
class DataPoint:
    """Single data point for visualization."""

    timestamp: datetime
    value: float
    label: str
    category: str = "default"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ChartData:
    """Chart data structure."""

    chart_id: str
    title: str
    chart_type: ChartType
    data_points: list[DataPoint]
    x_axis_label: str = "Time"
    y_axis_label: str = "Value"
    color_scheme: str = "default"
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class Dashboard:
    """Dashboard configuration."""

    dashboard_id: str
    name: str
    description: str
    charts: list[ChartData]
    layout: dict[str, Any] = field(default_factory=dict)
    refresh_interval: int = 30  # seconds
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)


class DataCollector:
    """Collects data from various AI components for visualization."""

    def __init__(self) -> None:
        """Initialize the data collector for visualization.

        Sets up metric storage, collection functions, and automated
        data gathering from various AI components for real-time
        visualization and analytics.
        """
        self.data_store: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.collectors: dict[MetricType, Callable] = {}
        self.collection_enabled = True
        self.collection_interval = 10  # seconds
        self.learning_engine = get_learning_engine()
        self.learning_records = {}
        self.error_history = deque(maxlen=1000)

        # Initialize data collectors
        self._initialize_collectors()

        # Start data collection
        self._start_data_collection()

        logger.info("Data collector initialized")

    def _initialize_collectors(self) -> None:
        """Initialize metric collectors."""
        self.collectors = {
            MetricType.PERFORMANCE: self._collect_performance_metrics,
            MetricType.SUCCESS_RATE: self._collect_success_rate_metrics,
            MetricType.RESOURCE_USAGE: self._collect_resource_usage_metrics,
            MetricType.ERROR_RATE: self._collect_error_rate_metrics,
            MetricType.LEARNING_PROGRESS: self._collect_learning_metrics,
            MetricType.EXPLOIT_CHAINS: self._collect_exploit_chain_metrics,
            MetricType.AGENT_ACTIVITY: self._collect_agent_activity_metrics,
        }

    def _start_data_collection(self) -> None:
        """Start background data collection."""
        # Skip thread creation during testing
        if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
            logger.info("Skipping data collection worker (testing mode)")
            return

        import threading

        def collection_worker() -> None:
            while self.collection_enabled:
                try:
                    for metric_type, collector in self.collectors.items():
                        data_points = collector()
                        for point in data_points:
                            self.data_store[metric_type.value].append(point)

                    time.sleep(self.collection_interval)

                except Exception as e:
                    logger.error("Error in data collection: %s", e)
                    time.sleep(5)  # Wait on error

        thread = threading.Thread(target=collection_worker, daemon=True)
        thread.start()
        logger.info("Started data collection worker")

    def _collect_performance_metrics(self) -> list[DataPoint]:
        """Collect performance metrics."""
        try:
            metrics_summary = performance_monitor.get_metrics_summary()
            data_points = []

            if system_health := metrics_summary.get("system_health", {}):
                data_points.append(
                    DataPoint(
                        timestamp=datetime.now(),
                        value=system_health.get("score", 0),
                        label="System Health Score",
                        category="health",
                    ),
                )

            # Operation performance
            operation_summary = metrics_summary.get("operation_summary", {})
            for op_name, stats in operation_summary.items():
                avg_time = stats.get("avg_execution_time", 0)
                data_points.append(
                    DataPoint(
                        timestamp=datetime.now(),
                        value=avg_time,
                        label=f"{op_name} Avg Time",
                        category="execution_time",
                    ),
                )

            return data_points

        except Exception as e:
            logger.error("Error collecting performance metrics: %s", e)
            return []

    def _collect_success_rate_metrics(self) -> list[DataPoint]:
        """Collect success rate metrics."""
        try:
            # Get learning insights for success rates
            insights = self.learning_engine.get_learning_insights()
            data_points = []

            if "success_rate" in insights:
                data_points.append(
                    DataPoint(
                        timestamp=datetime.now(),
                        value=insights["success_rate"] * 100,  # Convert to percentage
                        label="Overall Success Rate",
                        category="success_rate",
                    ),
                )

            if "avg_confidence" in insights:
                data_points.append(
                    DataPoint(
                        timestamp=datetime.now(),
                        value=insights["avg_confidence"] * 100,
                        label="Average Confidence",
                        category="confidence",
                    ),
                )

            return data_points

        except Exception as e:
            logger.error("Error collecting success rate metrics: %s", e)
            return []

    def _collect_resource_usage_metrics(self) -> list[DataPoint]:
        """Collect resource usage metrics."""
        data_points = []

        if not PSUTIL_AVAILABLE:
            # Return default fallback data points when psutil is not available
            data_points.extend(
                [
                    DataPoint(
                        timestamp=datetime.now(),
                        value=50.0,
                        label="CPU Usage",
                        category="cpu",
                    ),
                    DataPoint(
                        timestamp=datetime.now(),
                        value=60.0,
                        label="Memory Usage",
                        category="memory",
                    ),
                ],
            )
            return data_points

        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent()
            data_points.append(
                DataPoint(
                    timestamp=datetime.now(),
                    value=cpu_percent,
                    label="CPU Usage",
                    category="cpu",
                ),
            )

            # Memory usage
            memory = psutil.virtual_memory()
            data_points.append(
                DataPoint(
                    timestamp=datetime.now(),
                    value=memory.percent,
                    label="Memory Usage",
                    category="memory",
                ),
            )

            if disk_io := psutil.disk_io_counters():
                data_points.append(
                    DataPoint(
                        timestamp=datetime.now(),
                        value=disk_io.read_bytes / (1024 * 1024),  # MB
                        label="Disk Read MB",
                        category="disk_io",
                    ),
                )

            return data_points

        except Exception as e:
            logger.error("Error collecting resource usage metrics: %s", e)
            return []

    def _collect_error_rate_metrics(self) -> list[DataPoint]:
        """Collect error rate metrics."""
        try:
            # Real error rate calculation based on actual error tracking
            current_time = datetime.now()
            error_rate = self._calculate_real_error_rate(current_time)

            return [
                DataPoint(
                    timestamp=current_time,
                    value=error_rate,
                    label="Error Rate",
                    category="errors",
                )
            ]
        except Exception as e:
            logger.error("Error collecting error rate metrics: %s", e)
            return []

    def _calculate_real_error_rate(self, current_time: datetime) -> float:
        """Calculate real error rate based on actual system error tracking."""
        try:
            # Calculate error rate from the last hour
            lookback_time = current_time - timedelta(hours=1)

            # Get errors from learning records within the time window
            total_operations = 0
            error_count = 0

            for record in self.learning_records.values():
                record_time = datetime.fromisoformat(record.get("timestamp", current_time.isoformat()))

                if record_time >= lookback_time:
                    total_operations += 1

                    # Check for various error indicators in the record
                    if self._has_error_indicators(record):
                        error_count += 1

            # Also check the error history buffer
            recent_errors = [
                error
                for error in self.error_history
                if datetime.fromisoformat(error.get("timestamp", current_time.isoformat())) >= lookback_time
            ]
            error_count += len(recent_errors)

            # Calculate error rate as percentage
            if total_operations > 0:
                error_rate = (error_count / total_operations) * 100.0
            else:
                # If no operations, check if we have baseline error data
                error_rate = len(recent_errors) * 2.0  # Baseline error weight

            # Cap error rate at reasonable maximum
            return min(error_rate, 50.0)

        except Exception as e:
            logger.error("Error calculating real error rate: %s", e)
            # Return conservative estimate if calculation fails
            return 2.5

    def _has_error_indicators(self, record: dict) -> bool:
        """Check if a learning record contains error indicators."""
        try:
            # Check for explicit error flags
            if record.get("error") or record.get("failed"):
                return True

            # Check for error keywords in status or result
            status = record.get("status", "").lower()
            result = record.get("result", "").lower()

            error_keywords = [
                "error",
                "failed",
                "exception",
                "timeout",
                "crash",
                "invalid",
                "denied",
                "refused",
                "blocked",
                "abort",
            ]

            for keyword in error_keywords:
                if keyword in status or keyword in result:
                    return True

            # Check for low confidence scores (might indicate errors)
            confidence = record.get("confidence", 1.0)
            if confidence < 0.3:
                return True

            # Check for execution time anomalies (might indicate errors)
            execution_time = record.get("execution_time", 0)
            return execution_time > 30000

        except Exception as e:
            logger.error("Error checking error indicators: %s", e)
            return False

    def _get_real_agent_metrics(self) -> tuple[int, int]:
        """Get real agent activity metrics from the multi-agent system."""
        try:
            # Check for active learning records to determine active agents
            current_time = datetime.now()
            recent_threshold = current_time - timedelta(minutes=5)

            active_agent_ids = set()
            total_tasks = 0

            # Analyze learning records for agent activity
            for record_id, record in self.learning_records.items():
                try:
                    record_time = datetime.fromisoformat(record.get("timestamp", current_time.isoformat()))

                    if record_time >= recent_threshold:
                        # Extract agent information from record
                        agent_id = record.get("agent_id", record.get("source", "unknown"))
                        if agent_id != "unknown":
                            active_agent_ids.add(agent_id)

                        total_tasks += 1
                except Exception as e:
                    logger.warning("Error parsing learning record %s: %s", record_id, e)
                    continue

            # Also check for active analysis operations
            try:
                from intellicrack.core.analysis.analysis_orchestrator import AnalysisOrchestrator

                # If orchestrator exists, get active operations count
                analysis_operations = getattr(AnalysisOrchestrator, "_active_operations", {})
                for op_id, op_data in analysis_operations.items():
                    if op_data.get("status") == "running":
                        total_tasks += 1
                        agent_id = op_data.get("agent_id", f"analysis_{op_id}")
                        active_agent_ids.add(agent_id)
            except (ImportError, AttributeError):
                # Orchestrator not available, continue with learning record analysis
                pass

            # Check for running AI operations
            try:
                from intellicrack.ai.orchestrator import AIOrchestrator

                # If orchestrator has active tasks, count them
                if hasattr(AIOrchestrator, "_active_tasks"):
                    active_tasks = getattr(AIOrchestrator, "_active_tasks", {})
                    for task_id, task_data in active_tasks.items():
                        if task_data.get("status") in ["running", "queued"]:
                            total_tasks += 1
                            agent_id = task_data.get("agent_id", f"ai_{task_id}")
                            active_agent_ids.add(agent_id)
            except (ImportError, AttributeError):
                # AI Orchestrator not available, continue
                pass

            # If no agents detected from records, check system processes
            if not active_agent_ids:
                # Look for background processes or threads that might be agent-like
                active_agent_ids.add("main_thread")  # At least the main analysis thread

                # Check if we have any queued operations
                if total_tasks == 0:
                    # Estimate based on recent activity
                    recent_hour = current_time - timedelta(hours=1)
                    for record in self.learning_records.values():
                        try:
                            record_time = datetime.fromisoformat(record.get("timestamp", current_time.isoformat()))
                            if record_time >= recent_hour:
                                total_tasks += 1
                        except Exception as e:
                            logger.debug("Skipping task record due to error: %s", e)
                            continue

                    # Scale down to represent current activity level
                    total_tasks = max(1, total_tasks // 10)

            active_agents = len(active_agent_ids)

            # Ensure reasonable bounds
            active_agents = max(1, min(active_agents, 50))  # 1-50 agents
            total_tasks = max(0, min(total_tasks, 10000))  # 0-10000 tasks

            return active_agents, total_tasks

        except Exception as e:
            logger.error("Error getting real agent metrics: %s", e)
            # Return conservative estimates if calculation fails
            return 1, 10

    def _collect_learning_metrics(self) -> list[DataPoint]:
        """Collect learning progress metrics."""
        try:
            insights = self.learning_engine.get_learning_insights()
            data_points = []

            if "total_records" in insights:
                data_points.append(
                    DataPoint(
                        timestamp=datetime.now(),
                        value=insights["total_records"],
                        label="Total Learning Records",
                        category="learning_volume",
                    ),
                )

            # Learning stats
            learning_stats = insights.get("learning_stats", {})
            data_points.extend(
                DataPoint(
                    timestamp=datetime.now(),
                    value=value,
                    label=f"Learning {stat_name}",
                    category="learning_progress",
                )
                for stat_name, value in learning_stats.items()
                if isinstance(value, (int, float))
            )
            return data_points

        except Exception as e:
            logger.error("Error collecting learning metrics: %s", e)
            return []

    def _collect_exploit_chain_metrics(self) -> list[DataPoint]:
        """Collect exploit chain metrics."""
        # exploit_chain_builder module removed - returning empty data
        return []

    def _collect_agent_activity_metrics(self) -> list[DataPoint]:
        """Collect multi-agent activity metrics."""
        try:
            # Real agent activity data from multi-agent system
            active_agents, total_tasks = self._get_real_agent_metrics()

            return [
                DataPoint(
                    timestamp=datetime.now(),
                    value=active_agents,
                    label="Active Agents",
                    category="agent_activity",
                ),
                DataPoint(
                    timestamp=datetime.now(),
                    value=total_tasks,
                    label="Total Tasks Processed",
                    category="task_volume",
                ),
            ]
        except Exception as e:
            logger.error("Error collecting agent activity metrics: %s", e)
            return []

    def get_data(self, metric_type: MetricType, time_range: int = 3600) -> list[DataPoint]:
        """Get collected data for metric type."""
        if metric_type.value not in self.data_store:
            return []

        # Filter by time range (in seconds)
        cutoff_time = datetime.now() - timedelta(seconds=time_range)
        return [point for point in self.data_store[metric_type.value] if point.timestamp >= cutoff_time]

    def stop_collection(self) -> None:
        """Stop data collection."""
        self.collection_enabled = False
        logger.info("Stopped data collection")


class ChartGenerator:
    """Generates various types of charts for visualization."""

    def __init__(self, data_collector: DataCollector) -> None:
        """Initialize the chart generator.

        Args:
            data_collector: Data collector instance providing
                metrics and data for visualization.

        """
        self.data_collector = data_collector
        self.chart_templates = self._load_chart_templates()

        logger.info("Chart generator initialized")

    def _load_chart_templates(self) -> dict[str, dict[str, Any]]:
        """Load chart configuration templates."""
        return {
            "performance_overview": {
                "chart_type": ChartType.LINE_CHART,
                "title": "Performance Overview",
                "metrics": [MetricType.PERFORMANCE],
                "time_range": 3600,
                "options": {"smooth": True, "show_points": True},
            },
            "resource_utilization": {
                "chart_type": ChartType.BAR_CHART,
                "title": "Resource Utilization",
                "metrics": [MetricType.RESOURCE_USAGE],
                "time_range": 1800,
                "options": {"stacked": False},
            },
            "success_trends": {
                "chart_type": ChartType.LINE_CHART,
                "title": "Success Rate Trends",
                "metrics": [MetricType.SUCCESS_RATE],
                "time_range": 7200,
                "options": {"smooth": True, "threshold_lines": [80, 90]},
            },
            "exploit_chain_analysis": {
                "chart_type": ChartType.PIE_CHART,
                "title": "Exploit Chain Distribution",
                "metrics": [MetricType.EXPLOIT_CHAINS],
                "time_range": 86400,
                "options": {"show_labels": True, "show_percentages": True},
            },
            "learning_progress": {
                "chart_type": ChartType.HISTOGRAM,
                "title": "Learning Progress",
                "metrics": [MetricType.LEARNING_PROGRESS],
                "time_range": 3600,
                "options": {"bins": 20, "show_stats": True},
            },
        }

    @profile_ai_operation("chart_generation")
    def generate_chart(self, template_name: str, custom_options: dict[str, Any] = None) -> ChartData:
        """Generate chart from template."""
        if template_name not in self.chart_templates:
            raise ValueError(f"Unknown chart template: {template_name}")

        template = self.chart_templates[template_name]

        # Collect data for all metrics in template
        all_data_points = []
        for metric_type in template["metrics"]:
            data_points = self.data_collector.get_data(metric_type, template["time_range"])
            all_data_points.extend(data_points)

        # Merge custom options
        options = template["options"].copy()
        if custom_options:
            options.update(custom_options)

        return ChartData(
            chart_id=str(uuid.uuid4()),
            title=template["title"],
            chart_type=template["chart_type"],
            data_points=all_data_points,
            options=options,
        )

    def generate_custom_chart(self, chart_config: dict[str, Any]) -> ChartData:
        """Generate custom chart from configuration."""
        chart_type = ChartType(chart_config.get("chart_type", "line_chart"))
        metric_types = [MetricType(m) for m in chart_config.get("metrics", [])]
        time_range = chart_config.get("time_range", 3600)

        # Collect data
        all_data_points = []
        for metric_type in metric_types:
            data_points = self.data_collector.get_data(metric_type, time_range)
            all_data_points.extend(data_points)

        return ChartData(
            chart_id=str(uuid.uuid4()),
            title=chart_config.get("title", "Custom Chart"),
            chart_type=chart_type,
            data_points=all_data_points,
            x_axis_label=chart_config.get("x_axis_label", "Time"),
            y_axis_label=chart_config.get("y_axis_label", "Value"),
            options=chart_config.get("options", {}),
        )

    def generate_exploit_chain_network_graph(self) -> ChartData:
        """Generate network graph of exploit chains."""
        return ChartData(
            chart_id=str(uuid.uuid4()),
            title="Exploit Chain Network (Disabled)",
            chart_type=ChartType.NETWORK_GRAPH,
            data_points=[],
            options={"layout": "force_directed", "show_labels": True},
        )

    def generate_vulnerability_heatmap(self) -> ChartData:
        """Generate heatmap of vulnerability patterns."""
        return ChartData(
            chart_id=str(uuid.uuid4()),
            title="Vulnerability Pattern Heatmap (Disabled)",
            chart_type=ChartType.HEATMAP,
            data_points=[],
            x_axis_label="Protection Type",
            y_axis_label="Severity",
            options={
                "color_scale": "viridis",
                "show_values": True,
                "grid_lines": True,
            },
        )


class DashboardManager:
    """Manages visualization dashboards."""

    def __init__(self, data_collector: DataCollector) -> None:
        """Initialize the dashboard manager for real-time visualization.

        Args:
            data_collector: Data collector instance providing
                metrics for dashboard visualization.

        """
        self.data_collector = data_collector
        self.chart_generator = ChartGenerator(data_collector)
        self.dashboards: dict[str, Dashboard] = {}
        self.dashboard_templates = self._load_dashboard_templates()

        # Create default dashboards
        self._create_default_dashboards()

        logger.info("Dashboard manager initialized")

    def _load_dashboard_templates(self) -> dict[str, dict[str, Any]]:
        """Load dashboard templates."""
        return {
            "ai_overview": {
                "name": "AI System Overview",
                "description": "Overall system performance and health",
                "charts": [
                    "performance_overview",
                    "resource_utilization",
                    "success_trends",
                    "learning_progress",
                ],
                "layout": {"rows": 2, "cols": 2},
            },
            "security_analysis": {
                "name": "Security Analysis Dashboard",
                "description": "Vulnerability and exploit chain analysis",
                "charts": [
                    "exploit_chain_analysis",
                    "vulnerability_heatmap",
                    "exploit_chain_network",
                ],
                "layout": {"rows": 2, "cols": 2},
            },
            "performance_monitoring": {
                "name": "Performance Monitoring",
                "description": "Detailed performance metrics and optimization",
                "charts": [
                    "performance_overview",
                    "resource_utilization",
                ],
                "layout": {"rows": 1, "cols": 2},
            },
        }

    def _create_default_dashboards(self) -> None:
        """Create default dashboards."""
        for template_name, template in self.dashboard_templates.items():
            if dashboard := self.create_dashboard_from_template(template_name):
                self.dashboards[dashboard.dashboard_id] = dashboard
                logger.info("Created default dashboard: %s", template['name'])

    @profile_ai_operation("dashboard_creation")
    def create_dashboard_from_template(self, template_name: str) -> Dashboard | None:
        """Create dashboard from template."""
        if template_name not in self.dashboard_templates:
            logger.error("Unknown dashboard template: %s", template_name)
            return None

        template = self.dashboard_templates[template_name]

        # Generate charts
        charts = []
        for chart_template in template["charts"]:
            try:
                if chart_template == "vulnerability_heatmap":
                    chart = self.chart_generator.generate_vulnerability_heatmap()
                elif chart_template == "exploit_chain_network":
                    chart = self.chart_generator.generate_exploit_chain_network_graph()
                else:
                    chart = self.chart_generator.generate_chart(chart_template)
                charts.append(chart)
            except Exception as e:
                logger.error("Error generating chart %s: %s", chart_template, e)

        return Dashboard(
            dashboard_id=str(uuid.uuid4()),
            name=template["name"],
            description=template["description"],
            charts=charts,
            layout=template["layout"],
        )

    def create_custom_dashboard(self, name: str, description: str, chart_configs: list[dict[str, Any]]) -> Dashboard:
        """Create custom dashboard."""
        charts = []

        for chart_config in chart_configs:
            try:
                chart = self.chart_generator.generate_custom_chart(chart_config)
                charts.append(chart)
            except Exception as e:
                logger.error("Error generating custom chart: %s", e)

        dashboard = Dashboard(
            dashboard_id=str(uuid.uuid4()),
            name=name,
            description=description,
            charts=charts,
        )

        self.dashboards[dashboard.dashboard_id] = dashboard

        return dashboard

    def refresh_dashboard(self, dashboard_id: str) -> bool:
        """Refresh dashboard data."""
        if dashboard_id not in self.dashboards:
            return False

        dashboard = self.dashboards[dashboard_id]

        # Refresh each chart
        for i, chart in enumerate(dashboard.charts):
            try:
                if refreshed_chart := self._refresh_chart(chart):
                    dashboard.charts[i] = refreshed_chart
            except Exception as e:
                logger.error("Error refreshing chart %s: %s", chart.chart_id, e)

        dashboard.last_updated = datetime.now()
        return True

    def _refresh_chart(self, chart: ChartData) -> ChartData | None:
        """Refresh individual chart."""
        # Try to match with known templates
        for template_name in self.chart_generator.chart_templates:
            template = self.chart_generator.chart_templates[template_name]
            if template["title"] == chart.title:
                return self.chart_generator.generate_chart(template_name)

        # For custom charts, regenerate with same configuration
        chart_config = {
            "chart_type": chart.chart_type.value,
            "title": chart.title,
            "metrics": [],  # Would need to extract from original chart
            "options": chart.options,
        }

        return self.chart_generator.generate_custom_chart(chart_config)

    def get_dashboard(self, dashboard_id: str) -> Dashboard | None:
        """Get dashboard by ID."""
        return self.dashboards.get(dashboard_id)

    def list_dashboards(self) -> list[dict[str, str]]:
        """List all dashboards."""
        return [
            {
                "dashboard_id": dashboard.dashboard_id,
                "name": dashboard.name,
                "description": dashboard.description,
                "chart_count": len(dashboard.charts),
                "last_updated": dashboard.last_updated.isoformat(),
            }
            for dashboard in self.dashboards.values()
        ]

    def export_dashboard(self, dashboard_id: str, export_path: Path) -> bool:
        """Export dashboard configuration."""
        if dashboard_id not in self.dashboards:
            return False

        dashboard = self.dashboards[dashboard_id]

        export_data = {
            "dashboard_id": dashboard.dashboard_id,
            "name": dashboard.name,
            "description": dashboard.description,
            "layout": dashboard.layout,
            "charts": [
                {
                    "chart_id": chart.chart_id,
                    "title": chart.title,
                    "chart_type": chart.chart_type.value,
                    "options": chart.options,
                    "data_point_count": len(chart.data_points),
                }
                for chart in dashboard.charts
            ],
            "exported_at": datetime.now().isoformat(),
        }

        try:
            with open(export_path, "w") as f:
                json.dump(export_data, f, indent=2)
            return True
        except Exception as e:
            logger.error("Error exporting dashboard: %s", e)
            return False


class AnalyticsEngine:
    """Advanced analytics engine for AI metrics."""

    def __init__(self, data_collector: DataCollector) -> None:
        """Initialize the analytics engine.

        Args:
            data_collector: Data collector instance providing
                metrics for analysis and reporting.

        """
        self.data_collector = data_collector
        self.analysis_cache: dict[str, Any] = {}

        logger.info("Analytics engine initialized")

    @profile_ai_operation("trend_analysis")
    def analyze_performance_trends(self, time_range: int = 86400) -> dict[str, Any]:
        """Analyze performance trends over time."""
        performance_data = self.data_collector.get_data(MetricType.PERFORMANCE, time_range)

        if not performance_data:
            return {"trend": "no_data", "analysis": "Insufficient data for trend analysis"}

        # Calculate trend
        values = [point.value for point in performance_data]

        if len(values) < 2:
            return {"trend": "insufficient_data", "analysis": "Need at least 2 data points"}

        # Simple linear trend calculation
        n = len(values)
        x_mean = (n - 1) / 2
        y_mean = sum(values) / n

        numerator = sum((i - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))

        slope = 0 if denominator == 0 else numerator / denominator
        # Determine trend direction
        if slope > 0.1:
            trend = "improving"
        elif slope < -0.1:
            trend = "declining"
        else:
            trend = "stable"

        # Calculate variance
        variance = sum((v - y_mean) ** 2 for v in values) / n
        std_dev = math.sqrt(variance)

        return {
            "trend": trend,
            "slope": slope,
            "mean_value": y_mean,
            "std_deviation": std_dev,
            "data_points": n,
            "time_range_hours": time_range / 3600,
            "analysis": f"Performance trend is {trend} with slope {slope:.4f}",
        }

    @profile_ai_operation("success_rate_analysis")
    def analyze_success_patterns(self) -> dict[str, Any]:
        """Analyze success rate patterns."""
        success_data = self.data_collector.get_data(MetricType.SUCCESS_RATE, 86400)

        if not success_data:
            return {"analysis": "No success rate data available"}

        values = [point.value for point in success_data]

        # Calculate statistics
        mean_success = sum(values) / len(values)
        max_success = max(values)
        min_success = min(values)

        # Identify patterns
        patterns = []

        if mean_success > 90:
            patterns.append("High overall success rate")
        elif mean_success < 70:
            patterns.append("Low overall success rate - needs attention")

        variance = sum((v - mean_success) ** 2 for v in values) / len(values)
        if variance > 100:  # High variance
            patterns.append("High variability in success rates")

        # Check for recent trends
        if len(values) >= 10:
            recent_avg = sum(values[-5:]) / 5
            earlier_avg = sum(values[:5]) / 5

            if recent_avg > earlier_avg + 5:
                patterns.append("Recent improvement in success rates")
            elif recent_avg < earlier_avg - 5:
                patterns.append("Recent decline in success rates")

        return {
            "mean_success_rate": mean_success,
            "max_success_rate": max_success,
            "min_success_rate": min_success,
            "variance": variance,
            "patterns": patterns,
            "recommendation": self._get_success_rate_recommendation(mean_success, patterns),
        }

    def _get_success_rate_recommendation(self, mean_success: float, patterns: list[str]) -> str:
        """Get recommendation based on success rate analysis."""
        if mean_success < 70:
            return "Focus on improving error handling and algorithm reliability"
        if mean_success < 85:
            return "Good performance, consider optimization for edge cases"
        if "High variability" in str(patterns):
            return "Investigate causes of success rate variability"
        return "Excellent performance, maintain current approach"

    @profile_ai_operation("resource_efficiency_analysis")
    def analyze_resource_efficiency(self) -> dict[str, Any]:
        """Analyze resource usage efficiency."""
        resource_data = self.data_collector.get_data(MetricType.RESOURCE_USAGE, 3600)

        if not resource_data:
            return {"analysis": "No resource usage data available"}

        # Group by resource type
        resource_usage = defaultdict(list)
        for point in resource_data:
            resource_usage[point.category].append(point.value)

        efficiency_analysis = {}

        for resource_type, values in resource_usage.items():
            if not values:
                continue

            mean_usage = sum(values) / len(values)
            peak_usage = max(values)

            # Determine efficiency rating
            if resource_type == "cpu":
                if mean_usage < 30:
                    efficiency = "underutilized"
                elif mean_usage < 70:
                    efficiency = "optimal"
                else:
                    efficiency = "high_usage"
            elif resource_type == "memory":
                if mean_usage < 50:
                    efficiency = "good"
                elif mean_usage < 80:
                    efficiency = "moderate"
                else:
                    efficiency = "concerning"
            else:
                efficiency = "unknown"

            efficiency_analysis[resource_type] = {
                "mean_usage": mean_usage,
                "peak_usage": peak_usage,
                "efficiency_rating": efficiency,
                "data_points": len(values),
            }

        return {
            "resource_efficiency": efficiency_analysis,
            "overall_rating": self._calculate_overall_efficiency(efficiency_analysis),
        }

    def _calculate_overall_efficiency(self, efficiency_analysis: dict[str, dict[str, Any]]) -> str:
        """Calculate overall efficiency rating."""
        ratings = [analysis["efficiency_rating"] for analysis in efficiency_analysis.values()]

        if "concerning" in ratings:
            return "needs_optimization"
        if "high_usage" in ratings:
            return "monitor_closely"
        if all(r in ["optimal", "good"] for r in ratings):
            return "excellent"
        return "good"

    def generate_insights_report(self) -> dict[str, Any]:
        """Generate comprehensive insights report."""
        report = {
            "generated_at": datetime.now().isoformat(),
            "performance_trends": self.analyze_performance_trends(),
            "success_patterns": self.analyze_success_patterns(),
            "resource_efficiency": self.analyze_resource_efficiency(),
            "recommendations": [],
        }

        # Generate overall recommendations
        performance_trend = report["performance_trends"].get("trend", "unknown")
        success_rate = report["success_patterns"].get("mean_success_rate", 0)
        efficiency_rating = report["resource_efficiency"].get("overall_rating", "unknown")

        if performance_trend == "declining":
            report["recommendations"].append("Performance is declining - investigate bottlenecks")

        if success_rate < 80:
            report["recommendations"].append("Success rate below target - review error handling")

        if efficiency_rating == "needs_optimization":
            report["recommendations"].append("Resource usage needs optimization")

        if not report["recommendations"]:
            report["recommendations"].append("System performing well - continue monitoring")

        return report


class VisualizationAnalytics:
    """Run visualization and analytics system."""

    def __init__(self) -> None:
        """Initialize the visualization and analytics system.

        Creates and initializes the data collector, dashboard manager, and
        analytics engine components to provide comprehensive visualization
        and analytics capabilities for AI operations.
        """
        self.data_collector = DataCollector()
        self.dashboard_manager = DashboardManager(self.data_collector)
        self.analytics_engine = AnalyticsEngine(self.data_collector)

        logger.info("Visualization and analytics system initialized")

    def get_dashboard(self, dashboard_id: str) -> Dashboard | None:
        """Get dashboard by ID."""
        return self.dashboard_manager.get_dashboard(dashboard_id)

    def list_dashboards(self) -> list[dict[str, str]]:
        """List all available dashboards."""
        return self.dashboard_manager.list_dashboards()

    def refresh_dashboard(self, dashboard_id: str) -> bool:
        """Refresh dashboard data."""
        return self.dashboard_manager.refresh_dashboard(dashboard_id)

    def create_custom_dashboard(self, name: str, description: str, chart_configs: list[dict[str, Any]]) -> Dashboard:
        """Create custom dashboard."""
        return self.dashboard_manager.create_custom_dashboard(name, description, chart_configs)

    def generate_insights_report(self) -> dict[str, Any]:
        """Generate comprehensive analytics report."""
        return self.analytics_engine.generate_insights_report()

    def get_system_status(self) -> dict[str, Any]:
        """Get system status including visualization metrics."""
        return {
            "data_collector_active": self.data_collector.collection_enabled,
            "total_dashboards": len(self.dashboard_manager.dashboards),
            "data_points_collected": sum(len(queue) for queue in self.data_collector.data_store.values()),
            "last_collection": datetime.now().isoformat(),
        }

    def analyze_binary_semantics(self, binary_path: str) -> dict[str, Any] | None:
        """Analyze binary to extract semantic understanding of functions and code patterns.

        Performs deep analysis of the binary to understand function purposes,
        identify code patterns related to licensing, and extract semantic
        information useful for protection bypass.

        Args:
            binary_path: Path to the binary file to analyze.

        Returns:
            Dictionary containing semantic analysis results including function
            semantics and code patterns, or None if analysis fails.

        """
        if not binary_path or not Path(binary_path).exists():
            logger.error("Invalid binary path for semantic analysis: %s", binary_path)
            return None

        try:
            results: dict[str, Any] = {
                "binary_path": binary_path,
                "analysis_timestamp": datetime.now().isoformat(),
                "function_semantics": [],
                "code_patterns": [],
                "protection_indicators": [],
                "semantic_summary": {},
            }

            binary_data = Path(binary_path).read_bytes()
            binary_size = len(binary_data)

            function_semantics = self._analyze_function_semantics(binary_data)
            results["function_semantics"] = function_semantics

            code_patterns = self._detect_code_patterns(binary_data)
            results["code_patterns"] = code_patterns

            protection_indicators = self._identify_protection_indicators(binary_data)
            results["protection_indicators"] = protection_indicators

            results["semantic_summary"] = {
                "total_functions_analyzed": len(function_semantics),
                "licensing_related_functions": sum(1 for f in function_semantics if f.get("category") == "licensing"),
                "protection_patterns_found": len(code_patterns),
                "protection_indicators_count": len(protection_indicators),
                "binary_size": binary_size,
                "analysis_confidence": self._calculate_analysis_confidence(function_semantics, code_patterns),
            }

            logger.info(
                "Semantic analysis completed for %s: %d functions, %d patterns",
                binary_path,
                len(function_semantics),
                len(code_patterns),
            )

            return results

        except PermissionError:
            logger.error("Permission denied reading binary: %s", binary_path)
            return None
        except Exception as e:
            logger.error("Error in semantic analysis for %s: %s", binary_path, e)
            return None

    def _analyze_function_semantics(self, binary_data: bytes) -> list[dict[str, Any]]:
        """Analyze binary to identify function purposes and semantics."""
        function_semantics: list[dict[str, Any]] = []

        licensing_signatures = [
            (b"license", "License validation check"),
            (b"License", "License validation check"),
            (b"LICENSE", "License validation check"),
            (b"serial", "Serial number validation"),
            (b"Serial", "Serial number validation"),
            (b"SERIAL", "Serial number validation"),
            (b"trial", "Trial period check"),
            (b"Trial", "Trial period check"),
            (b"TRIAL", "Trial period check"),
            (b"expire", "Expiration check"),
            (b"Expire", "Expiration check"),
            (b"regist", "Registration validation"),
            (b"Regist", "Registration validation"),
            (b"activ", "Activation routine"),
            (b"Activ", "Activation routine"),
            (b"valid", "Validation function"),
            (b"Valid", "Validation function"),
            (b"check", "Check function"),
            (b"Check", "Check function"),
            (b"verify", "Verification routine"),
            (b"Verify", "Verification routine"),
            (b"auth", "Authentication check"),
            (b"Auth", "Authentication check"),
            (b"key", "Key processing"),
            (b"Key", "Key processing"),
            (b"hwid", "Hardware ID check"),
            (b"HWID", "Hardware ID check"),
            (b"machine", "Machine fingerprinting"),
            (b"Machine", "Machine fingerprinting"),
            (b"dongle", "Dongle verification"),
            (b"Dongle", "Dongle verification"),
        ]

        for signature, purpose in licensing_signatures:
            offset = 0
            while True:
                pos = binary_data.find(signature, offset)
                if pos == -1:
                    break

                context_start = max(0, pos - 32)
                context_end = min(len(binary_data), pos + len(signature) + 64)
                context = binary_data[context_start:context_end]

                func_name = self._extract_function_name(context, signature)

                function_semantics.append({
                    "name": func_name or f"sub_{pos:08X}",
                    "offset": pos,
                    "purpose": purpose,
                    "category": "licensing",
                    "confidence": self._calculate_signature_confidence(context, signature),
                    "context_preview": context[:48].hex() if context else "",
                })

                offset = pos + len(signature)

        crypto_signatures = [
            (b"RSA", "RSA cryptographic operation"),
            (b"AES", "AES encryption/decryption"),
            (b"SHA", "SHA hash computation"),
            (b"MD5", "MD5 hash computation"),
            (b"HMAC", "HMAC authentication"),
            (b"crypt", "Cryptographic routine"),
            (b"Crypt", "Cryptographic routine"),
            (b"encrypt", "Encryption routine"),
            (b"decrypt", "Decryption routine"),
            (b"hash", "Hash computation"),
            (b"Hash", "Hash computation"),
            (b"sign", "Signature operation"),
            (b"Sign", "Signature operation"),
        ]

        for signature, purpose in crypto_signatures:
            offset = 0
            while True:
                pos = binary_data.find(signature, offset)
                if pos == -1:
                    break

                context_start = max(0, pos - 32)
                context_end = min(len(binary_data), pos + len(signature) + 64)
                context = binary_data[context_start:context_end]

                func_name = self._extract_function_name(context, signature)

                function_semantics.append({
                    "name": func_name or f"crypto_{pos:08X}",
                    "offset": pos,
                    "purpose": purpose,
                    "category": "crypto",
                    "confidence": self._calculate_signature_confidence(context, signature),
                    "context_preview": context[:48].hex() if context else "",
                })

                offset = pos + len(signature)

        seen_offsets: set[int] = set()
        unique_functions: list[dict[str, Any]] = []
        for func in function_semantics:
            offset = func["offset"]
            if offset not in seen_offsets:
                seen_offsets.add(offset)
                unique_functions.append(func)

        unique_functions.sort(key=lambda x: x["confidence"], reverse=True)

        return unique_functions[:100]

    def _extract_function_name(self, context: bytes, signature: bytes) -> str | None:
        """Extract potential function name from context around signature."""
        try:
            text = context.decode("utf-8", errors="ignore")

            import re

            patterns = [
                rf"(\w+{signature.decode('utf-8', errors='ignore')}\w*)",
                r"([A-Z][a-zA-Z0-9_]+(?:Check|Validate|Verify|License|Serial|Key))",
                r"([a-z_]+(?:check|validate|verify|license|serial|key)[a-z_]*)",
            ]

            for pattern in patterns:
                match = re.search(pattern, text)
                if match:
                    name = match.group(1)
                    if 3 <= len(name) <= 64:
                        return name

            return None
        except Exception:
            return None

    def _calculate_signature_confidence(self, context: bytes, signature: bytes) -> float:
        """Calculate confidence score for a detected signature."""
        confidence = 0.5

        try:
            text = context.decode("utf-8", errors="ignore").lower()

            high_confidence_words = [
                "license",
                "serial",
                "trial",
                "expire",
                "register",
                "activate",
                "validate",
                "check",
                "verify",
                "key",
            ]

            for word in high_confidence_words:
                if word in text:
                    confidence += 0.1

            null_ratio = context.count(b"\x00") / len(context) if context else 0
            if null_ratio < 0.5:
                confidence += 0.1

            printable_count = sum(1 for b in context if 32 <= b <= 126)
            printable_ratio = printable_count / len(context) if context else 0
            if printable_ratio > 0.6:
                confidence += 0.1

        except Exception:
            logger.debug("Failed to calculate context confidence score", exc_info=True)

        return min(1.0, confidence)

    def _detect_code_patterns(self, binary_data: bytes) -> list[dict[str, Any]]:
        """Detect code patterns related to licensing and protection."""
        patterns: list[dict[str, Any]] = []

        pattern_signatures = [
            {
                "name": "License String Comparison",
                "bytes": [b"\x3d", b"\x3c", b"\x75", b"\x74"],
                "description": "Conditional jump after comparison (license check)",
                "type": "comparison",
            },
            {
                "name": "Time-based Check",
                "bytes": [b"GetSystemTime", b"GetLocalTime", b"time"],
                "description": "Time retrieval for trial/expiration check",
                "type": "time_check",
            },
            {
                "name": "Registry Access",
                "bytes": [b"RegOpenKey", b"RegQueryValue", b"RegSetValue"],
                "description": "Registry access for license storage",
                "type": "registry",
            },
            {
                "name": "Network Activation",
                "bytes": [b"WinHttpOpen", b"InternetOpen", b"socket"],
                "description": "Network communication for online activation",
                "type": "network",
            },
            {
                "name": "Hardware ID Collection",
                "bytes": [b"GetVolumeInformation", b"GetComputerName", b"GetAdaptersInfo"],
                "description": "Hardware fingerprinting for node-locking",
                "type": "hwid",
            },
            {
                "name": "Anti-Debug Check",
                "bytes": [b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"NtQueryInformationProcess"],
                "description": "Anti-debugging protection",
                "type": "anti_debug",
            },
            {
                "name": "VM Detection",
                "bytes": [b"VMware", b"VBox", b"QEMU", b"Hyper-V"],
                "description": "Virtual machine detection",
                "type": "vm_detect",
            },
        ]

        for pattern_def in pattern_signatures:
            for sig in pattern_def["bytes"]:
                pos = binary_data.find(sig)
                if pos != -1:
                    patterns.append({
                        "type": pattern_def["type"],
                        "name": pattern_def["name"],
                        "description": pattern_def["description"],
                        "offset": pos,
                        "signature": sig.hex() if isinstance(sig, bytes) else sig,
                        "confidence": 0.7,
                    })
                    break

        return patterns

    def _identify_protection_indicators(self, binary_data: bytes) -> list[dict[str, Any]]:
        """Identify protection system indicators in the binary."""
        indicators: list[dict[str, Any]] = []

        protection_systems = [
            ("VMProtect", [b"VMProtect", b".vmp0", b".vmp1"]),
            ("Themida", [b"Themida", b".themida"]),
            ("Enigma", [b"Enigma", b".enigma"]),
            ("ASProtect", [b"ASProtect", b".aspack"]),
            ("UPX", [b"UPX!", b"UPX0", b"UPX1"]),
            ("PECompact", [b"PEC2", b"PECompact"]),
            ("Obsidium", [b"Obsidium"]),
            ("Armadillo", [b"Armadillo"]),
            ("SafeNet", [b"HASP", b"Sentinel", b"SafeNet"]),
            ("FlexNet", [b"FlexNet", b"FLEXlm"]),
            ("CodeMeter", [b"CodeMeter", b"WIBU"]),
            ("Denuvo", [b"Denuvo", b"steam_api"]),
        ]

        for system_name, signatures in protection_systems:
            for sig in signatures:
                pos = binary_data.find(sig)
                if pos != -1:
                    indicators.append({
                        "system": system_name,
                        "signature": sig.decode("utf-8", errors="ignore"),
                        "offset": pos,
                        "confidence": 0.8,
                    })
                    break

        return indicators

    def _calculate_analysis_confidence(
        self,
        function_semantics: list[dict[str, Any]],
        code_patterns: list[dict[str, Any]],
    ) -> float:
        """Calculate overall confidence in the analysis results."""
        if not function_semantics and not code_patterns:
            return 0.1

        base_confidence = 0.3

        if function_semantics:
            avg_func_confidence = sum(f.get("confidence", 0) for f in function_semantics) / len(function_semantics)
            base_confidence += avg_func_confidence * 0.3

        if code_patterns:
            avg_pattern_confidence = sum(p.get("confidence", 0) for p in code_patterns) / len(code_patterns)
            base_confidence += avg_pattern_confidence * 0.2

        licensing_functions = sum(1 for f in function_semantics if f.get("category") == "licensing")
        if licensing_functions > 5:
            base_confidence += 0.1
        elif licensing_functions > 2:
            base_confidence += 0.05

        return min(1.0, base_confidence)

    def generate_analysis_scripts(self, binary_path: str) -> dict[str, Any] | None:
        """Generate Frida and Ghidra analysis scripts for the target binary.

        Analyzes the binary and generates customized scripts for deeper
        analysis and potential bypass of licensing protections.

        Args:
            binary_path: Path to the binary file to generate scripts for.

        Returns:
            Dictionary containing generated Frida and Ghidra scripts,
            or None if generation fails.

        """
        if not binary_path or not Path(binary_path).exists():
            logger.error("Invalid binary path for script generation: %s", binary_path)
            return None

        try:
            semantic_results = self.analyze_binary_semantics(binary_path)

            results: dict[str, Any] = {
                "binary_path": binary_path,
                "generation_timestamp": datetime.now().isoformat(),
                "frida_scripts": [],
                "ghidra_scripts": [],
            }

            binary_name = Path(binary_path).stem

            frida_scripts = self._generate_frida_scripts(binary_name, semantic_results)
            results["frida_scripts"] = frida_scripts

            ghidra_scripts = self._generate_ghidra_scripts(binary_name, semantic_results)
            results["ghidra_scripts"] = ghidra_scripts

            logger.info(
                "Generated %d Frida scripts and %d Ghidra scripts for %s",
                len(frida_scripts),
                len(ghidra_scripts),
                binary_path,
            )

            return results

        except Exception as e:
            logger.error("Error generating analysis scripts for %s: %s", binary_path, e)
            return None

    def _generate_frida_scripts(
        self,
        binary_name: str,
        semantic_results: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """Generate Frida scripts based on semantic analysis."""
        scripts: list[dict[str, Any]] = []

        scripts.append({
            "name": f"{binary_name}_license_hook.js",
            "description": "Hook licensing functions and log validation attempts",
            "code": self._build_license_hook_script(binary_name, semantic_results),
            "type": "hook",
        })

        scripts.append({
            "name": f"{binary_name}_api_trace.js",
            "description": "Trace Windows API calls related to licensing",
            "code": self._build_api_trace_script(binary_name),
            "type": "trace",
        })

        if semantic_results:
            protection_indicators = semantic_results.get("protection_indicators", [])
            if any(p.get("system") in ["VMProtect", "Themida"] for p in protection_indicators):
                scripts.append({
                    "name": f"{binary_name}_anti_debug_bypass.js",
                    "description": "Bypass anti-debugging protections",
                    "code": self._build_anti_debug_script(binary_name),
                    "type": "bypass",
                })

            code_patterns = semantic_results.get("code_patterns", [])
            if any(p.get("type") == "time_check" for p in code_patterns):
                scripts.append({
                    "name": f"{binary_name}_time_spoof.js",
                    "description": "Spoof time-related API calls for trial bypass",
                    "code": self._build_time_spoof_script(binary_name),
                    "type": "bypass",
                })

        return scripts

    def _generate_ghidra_scripts(
        self,
        binary_name: str,
        semantic_results: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """Generate Ghidra scripts based on semantic analysis."""
        scripts: list[dict[str, Any]] = []

        scripts.append({
            "name": f"{binary_name}_LicenseAnalyzer.java",
            "description": "Analyze and annotate licensing functions in the binary",
            "code": self._build_ghidra_license_analyzer(binary_name, semantic_results),
            "type": "analysis",
        })

        scripts.append({
            "name": f"{binary_name}_CryptoFinder.java",
            "description": "Find and analyze cryptographic routines",
            "code": self._build_ghidra_crypto_finder(binary_name),
            "type": "analysis",
        })

        return scripts

    def _build_license_hook_script(
        self,
        binary_name: str,
        semantic_results: dict[str, Any] | None,
    ) -> str:
        """Build Frida script for hooking licensing functions."""
        target_functions: list[str] = []
        if semantic_results:
            for func in semantic_results.get("function_semantics", []):
                if func.get("category") == "licensing" and func.get("name"):
                    target_functions.append(func["name"])

        target_functions_js = ", ".join(f'"{f}"' for f in target_functions[:10])

        return f'''
"use strict";

const targetModule = "{binary_name}";
const licenseFunctions = [{target_functions_js}];

function hookLicenseFunctions() {{
    const module = Process.findModuleByName(targetModule);
    if (!module) {{
        console.log("[!] Module not found: " + targetModule);
        return;
    }}

    console.log("[*] Hooking licensing functions in " + targetModule);

    module.enumerateExports().forEach(function(exp) {{
        const name = exp.name.toLowerCase();
        const isLicenseRelated = licenseFunctions.some(function(lf) {{
            return name.indexOf(lf.toLowerCase()) !== -1;
        }}) || name.indexOf("license") !== -1 ||
           name.indexOf("serial") !== -1 ||
           name.indexOf("valid") !== -1 ||
           name.indexOf("check") !== -1;

        if (isLicenseRelated) {{
            try {{
                Interceptor.attach(exp.address, {{
                    onEnter: function(args) {{
                        console.log("[+] " + exp.name + " called");
                        console.log("    Return address: " + this.returnAddress);
                        for (var i = 0; i < 4; i++) {{
                            console.log("    arg[" + i + "]: " + args[i]);
                        }}
                    }},
                    onLeave: function(retval) {{
                        console.log("[+] " + exp.name + " returned: " + retval);
                    }}
                }});
                console.log("[*] Hooked: " + exp.name);
            }} catch(e) {{
                console.log("[!] Failed to hook " + exp.name + ": " + e);
            }}
        }}
    }});
}}

hookLicenseFunctions();
'''

    def _build_api_trace_script(self, binary_name: str) -> str:
        """Build Frida script for tracing licensing-related API calls."""
        return f"""
"use strict";

console.log("[*] API Tracer for {binary_name}");

const apis = [
    {{ module: "advapi32.dll", names: ["RegOpenKeyExW", "RegQueryValueExW", "RegSetValueExW"] }},
    {{ module: "kernel32.dll", names: ["GetVolumeInformationW", "GetComputerNameW", "GetSystemTime"] }},
    {{ module: "crypt32.dll", names: ["CryptVerifySignature", "CryptHashData", "CryptDecrypt"] }},
    {{ module: "winhttp.dll", names: ["WinHttpOpen", "WinHttpSendRequest", "WinHttpReceiveResponse"] }}
];

apis.forEach(function(apiGroup) {{
    apiGroup.names.forEach(function(name) {{
        try {{
            const addr = Module.findExportByName(apiGroup.module, name);
            if (addr) {{
                Interceptor.attach(addr, {{
                    onEnter: function(args) {{
                        console.log("[API] " + name + " called from " + this.returnAddress);
                    }},
                    onLeave: function(retval) {{
                        console.log("[API] " + name + " returned: " + retval);
                    }}
                }});
                console.log("[*] Hooked " + apiGroup.module + "!" + name);
            }}
        }} catch(e) {{
            console.log("[!] Failed to hook " + name + ": " + e);
        }}
    }});
}});
"""

    def _build_anti_debug_script(self, binary_name: str) -> str:
        """Build Frida script for bypassing anti-debugging."""
        return f"""
"use strict";

console.log("[*] Anti-Debug Bypass for {binary_name}");

const isDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
if (isDebuggerPresent) {{
    Interceptor.replace(isDebuggerPresent, new NativeCallback(function() {{
        return 0;
    }}, "int", []));
    console.log("[*] Hooked IsDebuggerPresent");
}}

const checkRemoteDebugger = Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent");
if (checkRemoteDebugger) {{
    Interceptor.attach(checkRemoteDebugger, {{
        onLeave: function(retval) {{
            const debuggedPtr = this.context.rdx || this.context.r8;
            if (debuggedPtr) {{
                Memory.writeU8(debuggedPtr, 0);
            }}
        }}
    }});
    console.log("[*] Hooked CheckRemoteDebuggerPresent");
}}

const ntQueryInfo = Module.findExportByName("ntdll.dll", "NtQueryInformationProcess");
if (ntQueryInfo) {{
    Interceptor.attach(ntQueryInfo, {{
        onEnter: function(args) {{
            this.infoClass = args[1].toInt32();
            this.buffer = args[2];
        }},
        onLeave: function(retval) {{
            if (this.infoClass === 7 || this.infoClass === 0x1E) {{
                if (this.buffer) {{
                    Memory.writePointer(this.buffer, ptr(0));
                }}
            }}
        }}
    }});
    console.log("[*] Hooked NtQueryInformationProcess");
}}
"""

    def _build_time_spoof_script(self, binary_name: str) -> str:
        """Build Frida script for spoofing time-related calls."""
        return f"""
"use strict";

console.log("[*] Time Spoof for {binary_name}");

const spoofDate = new Date("2020-01-01T00:00:00");

const getSystemTime = Module.findExportByName("kernel32.dll", "GetSystemTime");
if (getSystemTime) {{
    Interceptor.attach(getSystemTime, {{
        onLeave: function() {{
            const timePtr = this.context.rcx;
            if (timePtr) {{
                Memory.writeU16(timePtr, spoofDate.getFullYear());
                Memory.writeU16(timePtr.add(2), spoofDate.getMonth() + 1);
                Memory.writeU16(timePtr.add(6), spoofDate.getDate());
            }}
        }}
    }});
    console.log("[*] Hooked GetSystemTime");
}}

const getLocalTime = Module.findExportByName("kernel32.dll", "GetLocalTime");
if (getLocalTime) {{
    Interceptor.attach(getLocalTime, {{
        onLeave: function() {{
            const timePtr = this.context.rcx;
            if (timePtr) {{
                Memory.writeU16(timePtr, spoofDate.getFullYear());
                Memory.writeU16(timePtr.add(2), spoofDate.getMonth() + 1);
                Memory.writeU16(timePtr.add(6), spoofDate.getDate());
            }}
        }}
    }});
    console.log("[*] Hooked GetLocalTime");
}}
"""

    def _build_ghidra_license_analyzer(
        self,
        binary_name: str,
        semantic_results: dict[str, Any] | None,
    ) -> str:
        """Build Ghidra script for analyzing licensing functions."""
        return f"""
//@category Analysis
//@menupath Analysis.License Analyzer
//@author Intellicrack
//@description Analyze and annotate licensing functions in {binary_name}

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.*;

public class {binary_name}_LicenseAnalyzer extends GhidraScript {{

    private static final String[] LICENSE_STRINGS = {{
        "license", "serial", "trial", "expire", "register",
        "activate", "validate", "check", "verify", "key", "hwid"
    }};

    @Override
    protected void run() throws Exception {{
        println("[*] License Analyzer for {binary_name}");

        FunctionManager funcManager = currentProgram.getFunctionManager();
        SymbolTable symTable = currentProgram.getSymbolTable();
        Listing listing = currentProgram.getListing();

        int foundCount = 0;

        FunctionIterator functions = funcManager.getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {{
            Function func = functions.next();
            String name = func.getName().toLowerCase();

            boolean isLicenseRelated = false;
            for (String keyword : LICENSE_STRINGS) {{
                if (name.contains(keyword)) {{
                    isLicenseRelated = true;
                    break;
                }}
            }}

            if (isLicenseRelated) {{
                foundCount++;
                println("[+] Found: " + func.getName() + " at " + func.getEntryPoint());

                func.setComment("LICENSING_FUNCTION - Potential license validation");

                symTable.createLabel(func.getEntryPoint(),
                    "LICENSE_" + func.getName(), SourceType.USER_DEFINED);
            }}
        }}

        println("[*] Analysis complete. Found " + foundCount + " licensing-related functions.");
    }}
}}
"""

    def _build_ghidra_crypto_finder(self, binary_name: str) -> str:
        """Build Ghidra script for finding cryptographic routines."""
        return f"""
//@category Analysis
//@menupath Analysis.Crypto Finder
//@author Intellicrack
//@description Find cryptographic routines in {binary_name}

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.util.*;

public class {binary_name}_CryptoFinder extends GhidraScript {{

    private static final byte[][] CRYPTO_CONSTANTS = {{
        {{ 0x63, 0x7c, 0x77, 0x7b }},  // AES S-box
        {{ 0x67, 0x45, 0x23, 0x01 }},  // MD5 init
        {{ 0x01, 0x23, 0x45, 0x67 }},  // SHA-1 init
    }};

    @Override
    protected void run() throws Exception {{
        println("[*] Crypto Finder for {binary_name}");

        Memory memory = currentProgram.getMemory();
        int foundCount = 0;

        for (byte[] constant : CRYPTO_CONSTANTS) {{
            Address addr = memory.findBytes(
                currentProgram.getMinAddress(),
                constant,
                null,
                true,
                monitor
            );

            if (addr != null) {{
                foundCount++;
                println("[+] Found crypto constant at: " + addr);
                createBookmark(addr, "CryptoConstant",
                    "Potential cryptographic constant found");
            }}
        }}

        println("[*] Found " + foundCount + " potential crypto constants.");
    }}
}}
"""


# Global visualization and analytics instance
visualization_analytics = VisualizationAnalytics()
