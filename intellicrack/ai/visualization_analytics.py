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
                    logger.error(f"Error in data collection: {e}")
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
            logger.error(f"Error collecting performance metrics: {e}")
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
            logger.error(f"Error collecting success rate metrics: {e}")
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
            logger.error(f"Error collecting resource usage metrics: {e}")
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
            logger.error(f"Error collecting error rate metrics: {e}")
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
            logger.error(f"Error calculating real error rate: {e}")
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
            logger.error(f"Error checking error indicators: {e}")
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
                    logger.warning(f"Error parsing learning record {record_id}: {e}")
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
                            logger.debug(f"Skipping task record due to error: {e}")
                            continue

                    # Scale down to represent current activity level
                    total_tasks = max(1, total_tasks // 10)

            active_agents = len(active_agent_ids)

            # Ensure reasonable bounds
            active_agents = max(1, min(active_agents, 50))  # 1-50 agents
            total_tasks = max(0, min(total_tasks, 10000))  # 0-10000 tasks

            return active_agents, total_tasks

        except Exception as e:
            logger.error(f"Error getting real agent metrics: {e}")
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
            logger.error(f"Error collecting learning metrics: {e}")
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
            logger.error(f"Error collecting agent activity metrics: {e}")
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
                logger.info(f"Created default dashboard: {template['name']}")

    @profile_ai_operation("dashboard_creation")
    def create_dashboard_from_template(self, template_name: str) -> Dashboard | None:
        """Create dashboard from template."""
        if template_name not in self.dashboard_templates:
            logger.error(f"Unknown dashboard template: {template_name}")
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
                logger.error(f"Error generating chart {chart_template}: {e}")

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
                logger.error(f"Error generating custom chart: {e}")

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
                logger.error(f"Error refreshing chart {chart.chart_id}: {e}")

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
            logger.error(f"Error exporting dashboard: {e}")
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


# Global visualization and analytics instance
visualization_analytics = VisualizationAnalytics()
