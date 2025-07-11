"""
Advanced Visualization & Analytics for AI Operations

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import math
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..utils.logger import get_logger
from .exploit_chain_builder import ChainComplexity, ExploitType
from .learning_engine_simple import get_learning_engine
from .performance_monitor import performance_monitor, profile_ai_operation

logger = get_logger(__name__)

try:
    import psutil
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
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChartData:
    """Chart data structure."""
    chart_id: str
    title: str
    chart_type: ChartType
    data_points: List[DataPoint]
    x_axis_label: str = "Time"
    y_axis_label: str = "Value"
    color_scheme: str = "default"
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Dashboard:
    """Dashboard configuration."""
    dashboard_id: str
    name: str
    description: str
    charts: List[ChartData]
    layout: Dict[str, Any] = field(default_factory=dict)
    refresh_interval: int = 30  # seconds
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)


class DataCollector:
    """Collects data from various AI components for visualization."""

    def __init__(self):
        self.data_store: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000))
        self.collectors: Dict[MetricType, Callable] = {}
        self.collection_enabled = True
        self.collection_interval = 10  # seconds

        # Initialize data collectors
        self._initialize_collectors()

        # Start data collection
        self._start_data_collection()

        logger.info("Data collector initialized")

    def _initialize_collectors(self):
        """Initialize metric collectors."""
        self.collectors = {
            MetricType.PERFORMANCE: self._collect_performance_metrics,
            MetricType.SUCCESS_RATE: self._collect_success_rate_metrics,
            MetricType.RESOURCE_USAGE: self._collect_resource_usage_metrics,
            MetricType.ERROR_RATE: self._collect_error_rate_metrics,
            MetricType.LEARNING_PROGRESS: self._collect_learning_metrics,
            MetricType.EXPLOIT_CHAINS: self._collect_exploit_chain_metrics,
            MetricType.AGENT_ACTIVITY: self._collect_agent_activity_metrics
        }

    def _start_data_collection(self):
        """Start background data collection."""
        import threading

        def collection_worker():
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

    def _collect_performance_metrics(self) -> List[DataPoint]:
        """Collect performance metrics."""
        try:
            metrics_summary = performance_monitor.get_metrics_summary()
            data_points = []

            # Overall system health
            system_health = metrics_summary.get("system_health", {})
            if system_health:
                data_points.append(DataPoint(
                    timestamp=datetime.now(),
                    value=system_health.get("score", 0),
                    label="System Health Score",
                    category="health"
                ))

            # Operation performance
            operation_summary = metrics_summary.get("operation_summary", {})
            for op_name, stats in operation_summary.items():
                avg_time = stats.get("avg_execution_time", 0)
                data_points.append(DataPoint(
                    timestamp=datetime.now(),
                    value=avg_time,
                    label=f"{op_name} Avg Time",
                    category="execution_time"
                ))

            return data_points

        except Exception as e:
            logger.error(f"Error collecting performance metrics: {e}")
            return []

    def _collect_success_rate_metrics(self) -> List[DataPoint]:
        """Collect success rate metrics."""
        try:
            # Get learning insights for success rates
            insights = learning_engine.get_learning_insights()
            data_points = []

            if "success_rate" in insights:
                data_points.append(DataPoint(
                    timestamp=datetime.now(),
                    value=insights["success_rate"] *
                    100,  # Convert to percentage
                    label="Overall Success Rate",
                    category="success_rate"
                ))

            if "avg_confidence" in insights:
                data_points.append(DataPoint(
                    timestamp=datetime.now(),
                    value=insights["avg_confidence"] * 100,
                    label="Average Confidence",
                    category="confidence"
                ))

            return data_points

        except Exception as e:
            logger.error(f"Error collecting success rate metrics: {e}")
            return []

    def _collect_resource_usage_metrics(self) -> List[DataPoint]:
        """Collect resource usage metrics."""
        data_points = []

        if not PSUTIL_AVAILABLE:
            # Return default mock data points when psutil is not available
            data_points.extend([
                DataPoint(
                    timestamp=datetime.now(),
                    value=50.0,
                    label="CPU Usage",
                    category="cpu"
                ),
                DataPoint(
                    timestamp=datetime.now(),
                    value=60.0,
                    label="Memory Usage",
                    category="memory"
                )
            ])
            return data_points

        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent()
            data_points.append(DataPoint(
                timestamp=datetime.now(),
                value=cpu_percent,
                label="CPU Usage",
                category="cpu"
            ))

            # Memory usage
            memory = psutil.virtual_memory()
            data_points.append(DataPoint(
                timestamp=datetime.now(),
                value=memory.percent,
                label="Memory Usage",
                category="memory"
            ))

            # Disk I/O
            disk_io = psutil.disk_io_counters()
            if disk_io:
                data_points.append(DataPoint(
                    timestamp=datetime.now(),
                    value=disk_io.read_bytes / (1024 * 1024),  # MB
                    label="Disk Read MB",
                    category="disk_io"
                ))

            return data_points

        except Exception as e:
            logger.error(f"Error collecting resource usage metrics: {e}")
            return []

    def _collect_error_rate_metrics(self) -> List[DataPoint]:
        """Collect error rate metrics."""
        try:
            # Get recent learning records to calculate error rates
            data_points = []

            # Mock error rate calculation (would be based on actual error tracking)
            current_time = datetime.now()
            error_rate = 5.0  # Placeholder - would calculate from actual errors

            data_points.append(DataPoint(
                timestamp=current_time,
                value=error_rate,
                label="Error Rate",
                category="errors"
            ))

            return data_points

        except Exception as e:
            logger.error(f"Error collecting error rate metrics: {e}")
            return []

    def _collect_learning_metrics(self) -> List[DataPoint]:
        """Collect learning progress metrics."""
        try:
            insights = learning_engine.get_learning_insights()
            data_points = []

            if "total_records" in insights:
                data_points.append(DataPoint(
                    timestamp=datetime.now(),
                    value=insights["total_records"],
                    label="Total Learning Records",
                    category="learning_volume"
                ))

            # Learning stats
            learning_stats = insights.get("learning_stats", {})
            for stat_name, value in learning_stats.items():
                if isinstance(value, (int, float)):
                    data_points.append(DataPoint(
                        timestamp=datetime.now(),
                        value=value,
                        label=f"Learning {stat_name}",
                        category="learning_progress"
                    ))

            return data_points

        except Exception as e:
            logger.error(f"Error collecting learning metrics: {e}")
            return []

    def _collect_exploit_chain_metrics(self) -> List[DataPoint]:
        """Collect exploit chain metrics."""
        try:
            # Would integrate with exploit chain builder
            from .exploit_chain_builder import exploit_chain_builder

            stats = exploit_chain_builder.get_chain_statistics()
            data_points = []

            if "total_chains" in stats:
                data_points.append(DataPoint(
                    timestamp=datetime.now(),
                    value=stats["total_chains"],
                    label="Total Exploit Chains",
                    category="exploit_chains"
                ))

            if "avg_success_probability" in stats:
                data_points.append(DataPoint(
                    timestamp=datetime.now(),
                    value=stats["avg_success_probability"] * 100,
                    label="Avg Chain Success Rate",
                    category="chain_success"
                ))

            return data_points

        except Exception as e:
            logger.error(f"Error collecting exploit chain metrics: {e}")
            return []

    def _collect_agent_activity_metrics(self) -> List[DataPoint]:
        """Collect multi-agent activity metrics."""
        try:
            # Would integrate with multi-agent system
            data_points = []

            # Mock agent activity data
            active_agents = 3
            total_tasks = 150

            data_points.append(DataPoint(
                timestamp=datetime.now(),
                value=active_agents,
                label="Active Agents",
                category="agent_activity"
            ))

            data_points.append(DataPoint(
                timestamp=datetime.now(),
                value=total_tasks,
                label="Total Tasks Processed",
                category="task_volume"
            ))

            return data_points

        except Exception as e:
            logger.error(f"Error collecting agent activity metrics: {e}")
            return []

    def get_data(self, metric_type: MetricType, time_range: int = 3600) -> List[DataPoint]:
        """Get collected data for metric type."""
        if metric_type.value not in self.data_store:
            return []

        # Filter by time range (in seconds)
        cutoff_time = datetime.now() - timedelta(seconds=time_range)
        filtered_data = [
            point for point in self.data_store[metric_type.value]
            if point.timestamp >= cutoff_time
        ]

        return filtered_data

    def stop_collection(self):
        """Stop data collection."""
        self.collection_enabled = False
        logger.info("Stopped data collection")


class ChartGenerator:
    """Generates various types of charts for visualization."""

    def __init__(self, data_collector: DataCollector):
        self.data_collector = data_collector
        self.chart_templates = self._load_chart_templates()

        logger.info("Chart generator initialized")

    def _load_chart_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load chart configuration templates."""
        return {
            "performance_overview": {
                "chart_type": ChartType.LINE_CHART,
                "title": "Performance Overview",
                "metrics": [MetricType.PERFORMANCE],
                "time_range": 3600,
                "options": {"smooth": True, "show_points": True}
            },
            "resource_utilization": {
                "chart_type": ChartType.BAR_CHART,
                "title": "Resource Utilization",
                "metrics": [MetricType.RESOURCE_USAGE],
                "time_range": 1800,
                "options": {"stacked": False}
            },
            "success_trends": {
                "chart_type": ChartType.LINE_CHART,
                "title": "Success Rate Trends",
                "metrics": [MetricType.SUCCESS_RATE],
                "time_range": 7200,
                "options": {"smooth": True, "threshold_lines": [80, 90]}
            },
            "exploit_chain_analysis": {
                "chart_type": ChartType.PIE_CHART,
                "title": "Exploit Chain Distribution",
                "metrics": [MetricType.EXPLOIT_CHAINS],
                "time_range": 86400,
                "options": {"show_labels": True, "show_percentages": True}
            },
            "learning_progress": {
                "chart_type": ChartType.HISTOGRAM,
                "title": "Learning Progress",
                "metrics": [MetricType.LEARNING_PROGRESS],
                "time_range": 3600,
                "options": {"bins": 20, "show_stats": True}
            }
        }

    @profile_ai_operation("chart_generation")
    def generate_chart(self, template_name: str, custom_options: Dict[str, Any] = None) -> ChartData:
        """Generate chart from template."""
        if template_name not in self.chart_templates:
            raise ValueError(f"Unknown chart template: {template_name}")

        template = self.chart_templates[template_name]

        # Collect data for all metrics in template
        all_data_points = []
        for metric_type in template["metrics"]:
            data_points = self.data_collector.get_data(
                metric_type, template["time_range"])
            all_data_points.extend(data_points)

        # Merge custom options
        options = template["options"].copy()
        if custom_options:
            options.update(custom_options)

        chart_data = ChartData(
            chart_id=str(uuid.uuid4()),
            title=template["title"],
            chart_type=template["chart_type"],
            data_points=all_data_points,
            options=options
        )

        return chart_data

    def generate_custom_chart(self, chart_config: Dict[str, Any]) -> ChartData:
        """Generate custom chart from configuration."""
        chart_type = ChartType(chart_config.get("chart_type", "line_chart"))
        metric_types = [MetricType(m) for m in chart_config.get("metrics", [])]
        time_range = chart_config.get("time_range", 3600)

        # Collect data
        all_data_points = []
        for metric_type in metric_types:
            data_points = self.data_collector.get_data(metric_type, time_range)
            all_data_points.extend(data_points)

        chart_data = ChartData(
            chart_id=str(uuid.uuid4()),
            title=chart_config.get("title", "Custom Chart"),
            chart_type=chart_type,
            data_points=all_data_points,
            x_axis_label=chart_config.get("x_axis_label", "Time"),
            y_axis_label=chart_config.get("y_axis_label", "Value"),
            options=chart_config.get("options", {})
        )

        return chart_data

    def generate_exploit_chain_network_graph(self) -> ChartData:
        """Generate network graph of exploit chains."""
        # Create network graph showing relationships between vulnerabilities and exploit chains
        from .exploit_chain_builder import exploit_chain_builder

        # Get exploit chain data
        stats = exploit_chain_builder.get_chain_statistics()

        # Create network data using actual chain statistics
        network_data = []

        # Add nodes for each exploit type with stats-based sizing
        for exploit_type in ExploitType:
            # Use stats to determine node size based on usage frequency
            usage_count = stats.get('exploit_types', {}).get(
                exploit_type.value, 0)
            node_size = min(1.0 + (usage_count * 0.1),
                            3.0)  # Scale based on usage

            network_data.append(DataPoint(
                timestamp=datetime.now(),
                value=node_size,  # Node size based on stats
                label=exploit_type.value,
                category="exploit_type",
                metadata={"node_type": "exploit",
                          "color": "#ff6b6b", "usage_count": usage_count}
            ))

        # Add nodes for complexity levels
        for complexity in ChainComplexity:
            network_data.append(DataPoint(
                timestamp=datetime.now(),
                value=0.8,
                label=complexity.value,
                category="complexity",
                metadata={"node_type": "complexity", "color": "#4ecdc4"}
            ))

        chart_data = ChartData(
            chart_id=str(uuid.uuid4()),
            title="Exploit Chain Network",
            chart_type=ChartType.NETWORK_GRAPH,
            data_points=network_data,
            options={
                "layout": "force_directed",
                "show_labels": True,
                "node_size_field": "value",
                "color_field": "metadata.color"
            }
        )

        return chart_data

    def generate_vulnerability_heatmap(self) -> ChartData:
        """Generate heatmap of vulnerability patterns."""
        # Create heatmap showing vulnerability frequency by type and severity

        heatmap_data = []
        severities = ["low", "medium", "high", "critical"]

        # Limit to first 10
        for i, exploit_type in enumerate(list(ExploitType)[:10]):
            for j, severity in enumerate(severities):
                # Mock frequency data
                frequency = max(0, 100 - abs(i - j) * 20 + (i + j) * 5)

                heatmap_data.append(DataPoint(
                    timestamp=datetime.now(),
                    value=frequency,
                    label=f"{exploit_type.value}-{severity}",
                    category="heatmap_cell",
                    metadata={
                        "x": i, "y": j, "exploit_type": exploit_type.value, "severity": severity}
                ))

        chart_data = ChartData(
            chart_id=str(uuid.uuid4()),
            title="Vulnerability Pattern Heatmap",
            chart_type=ChartType.HEATMAP,
            data_points=heatmap_data,
            x_axis_label="Exploit Type",
            y_axis_label="Severity",
            options={
                "color_scale": "viridis",
                "show_values": True,
                "grid_lines": True
            }
        )

        return chart_data


class DashboardManager:
    """Manages visualization dashboards."""

    def __init__(self, data_collector: DataCollector):
        self.data_collector = data_collector
        self.chart_generator = ChartGenerator(data_collector)
        self.dashboards: Dict[str, Dashboard] = {}
        self.dashboard_templates = self._load_dashboard_templates()

        # Create default dashboards
        self._create_default_dashboards()

        logger.info("Dashboard manager initialized")

    def _load_dashboard_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load dashboard templates."""
        return {
            "ai_overview": {
                "name": "AI System Overview",
                "description": "Overall system performance and health",
                "charts": [
                    "performance_overview",
                    "resource_utilization",
                    "success_trends",
                    "learning_progress"
                ],
                "layout": {"rows": 2, "cols": 2}
            },
            "security_analysis": {
                "name": "Security Analysis Dashboard",
                "description": "Vulnerability and exploit chain analysis",
                "charts": [
                    "exploit_chain_analysis",
                    "vulnerability_heatmap",
                    "exploit_chain_network"
                ],
                "layout": {"rows": 2, "cols": 2}
            },
            "performance_monitoring": {
                "name": "Performance Monitoring",
                "description": "Detailed performance metrics and optimization",
                "charts": [
                    "performance_overview",
                    "resource_utilization"
                ],
                "layout": {"rows": 1, "cols": 2}
            }
        }

    def _create_default_dashboards(self):
        """Create default dashboards."""
        for template_name, template in self.dashboard_templates.items():
            dashboard = self.create_dashboard_from_template(template_name)
            if dashboard:
                self.dashboards[dashboard.dashboard_id] = dashboard
                logger.info(f"Created default dashboard: {template['name']}")

    @profile_ai_operation("dashboard_creation")
    def create_dashboard_from_template(self, template_name: str) -> Optional[Dashboard]:
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

        dashboard = Dashboard(
            dashboard_id=str(uuid.uuid4()),
            name=template["name"],
            description=template["description"],
            charts=charts,
            layout=template["layout"]
        )

        return dashboard

    def create_custom_dashboard(self, name: str, description: str,
                                chart_configs: List[Dict[str, Any]]) -> Dashboard:
        """Create custom dashboard."""
        charts = []

        for chart_config in chart_configs:
            try:
                chart = self.chart_generator.generate_custom_chart(
                    chart_config)
                charts.append(chart)
            except Exception as e:
                logger.error(f"Error generating custom chart: {e}")

        dashboard = Dashboard(
            dashboard_id=str(uuid.uuid4()),
            name=name,
            description=description,
            charts=charts
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
                # Find matching template or regenerate custom chart
                refreshed_chart = self._refresh_chart(chart)
                if refreshed_chart:
                    dashboard.charts[i] = refreshed_chart
            except Exception as e:
                logger.error(f"Error refreshing chart {chart.chart_id}: {e}")

        dashboard.last_updated = datetime.now()
        return True

    def _refresh_chart(self, chart: ChartData) -> Optional[ChartData]:
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
            "options": chart.options
        }

        return self.chart_generator.generate_custom_chart(chart_config)

    def get_dashboard(self, dashboard_id: str) -> Optional[Dashboard]:
        """Get dashboard by ID."""
        return self.dashboards.get(dashboard_id)

    def list_dashboards(self) -> List[Dict[str, str]]:
        """List all dashboards."""
        return [
            {
                "dashboard_id": dashboard.dashboard_id,
                "name": dashboard.name,
                "description": dashboard.description,
                "chart_count": len(dashboard.charts),
                "last_updated": dashboard.last_updated.isoformat()
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
                    "data_point_count": len(chart.data_points)
                }
                for chart in dashboard.charts
            ],
            "exported_at": datetime.now().isoformat()
        }

        try:
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error exporting dashboard: {e}")
            return False


class AnalyticsEngine:
    """Advanced analytics engine for AI metrics."""

    def __init__(self, data_collector: DataCollector):
        self.data_collector = data_collector
        self.analysis_cache: Dict[str, Any] = {}

        logger.info("Analytics engine initialized")

    @profile_ai_operation("trend_analysis")
    def analyze_performance_trends(self, time_range: int = 86400) -> Dict[str, Any]:
        """Analyze performance trends over time."""
        performance_data = self.data_collector.get_data(
            MetricType.PERFORMANCE, time_range)

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

        if denominator == 0:
            slope = 0
        else:
            slope = numerator / denominator

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

        analysis_result = {
            "trend": trend,
            "slope": slope,
            "mean_value": y_mean,
            "std_deviation": std_dev,
            "data_points": n,
            "time_range_hours": time_range / 3600,
            "analysis": f"Performance trend is {trend} with slope {slope:.4f}"
        }

        return analysis_result

    @profile_ai_operation("success_rate_analysis")
    def analyze_success_patterns(self) -> Dict[str, Any]:
        """Analyze success rate patterns."""
        success_data = self.data_collector.get_data(
            MetricType.SUCCESS_RATE, 86400)

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
            "recommendation": self._get_success_rate_recommendation(mean_success, patterns)
        }

    def _get_success_rate_recommendation(self, mean_success: float, patterns: List[str]) -> str:
        """Get recommendation based on success rate analysis."""
        if mean_success < 70:
            return "Focus on improving error handling and algorithm reliability"
        elif mean_success < 85:
            return "Good performance, consider optimization for edge cases"
        elif "High variability" in str(patterns):
            return "Investigate causes of success rate variability"
        else:
            return "Excellent performance, maintain current approach"

    @profile_ai_operation("resource_efficiency_analysis")
    def analyze_resource_efficiency(self) -> Dict[str, Any]:
        """Analyze resource usage efficiency."""
        resource_data = self.data_collector.get_data(
            MetricType.RESOURCE_USAGE, 3600)

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
                "data_points": len(values)
            }

        return {
            "resource_efficiency": efficiency_analysis,
            "overall_rating": self._calculate_overall_efficiency(efficiency_analysis)
        }

    def _calculate_overall_efficiency(self, efficiency_analysis: Dict[str, Dict[str, Any]]) -> str:
        """Calculate overall efficiency rating."""
        ratings = [analysis["efficiency_rating"]
                   for analysis in efficiency_analysis.values()]

        if "concerning" in ratings:
            return "needs_optimization"
        elif "high_usage" in ratings:
            return "monitor_closely"
        elif all(r in ["optimal", "good"] for r in ratings):
            return "excellent"
        else:
            return "good"

    def generate_insights_report(self) -> Dict[str, Any]:
        """Generate comprehensive insights report."""
        report = {
            "generated_at": datetime.now().isoformat(),
            "performance_trends": self.analyze_performance_trends(),
            "success_patterns": self.analyze_success_patterns(),
            "resource_efficiency": self.analyze_resource_efficiency(),
            "recommendations": []
        }

        # Generate overall recommendations
        performance_trend = report["performance_trends"].get(
            "trend", "unknown")
        success_rate = report["success_patterns"].get("mean_success_rate", 0)
        efficiency_rating = report["resource_efficiency"].get(
            "overall_rating", "unknown")

        if performance_trend == "declining":
            report["recommendations"].append(
                "Performance is declining - investigate bottlenecks")

        if success_rate < 80:
            report["recommendations"].append(
                "Success rate below target - review error handling")

        if efficiency_rating == "needs_optimization":
            report["recommendations"].append(
                "Resource usage needs optimization")

        if not report["recommendations"]:
            report["recommendations"].append(
                "System performing well - continue monitoring")

        return report


class VisualizationAnalytics:
    """Main visualization and analytics system."""

    def __init__(self):
        self.data_collector = DataCollector()
        self.dashboard_manager = DashboardManager(self.data_collector)
        self.analytics_engine = AnalyticsEngine(self.data_collector)

        logger.info("Visualization and analytics system initialized")

    def get_dashboard(self, dashboard_id: str) -> Optional[Dashboard]:
        """Get dashboard by ID."""
        return self.dashboard_manager.get_dashboard(dashboard_id)

    def list_dashboards(self) -> List[Dict[str, str]]:
        """List all available dashboards."""
        return self.dashboard_manager.list_dashboards()

    def refresh_dashboard(self, dashboard_id: str) -> bool:
        """Refresh dashboard data."""
        return self.dashboard_manager.refresh_dashboard(dashboard_id)

    def create_custom_dashboard(self, name: str, description: str,
                                chart_configs: List[Dict[str, Any]]) -> Dashboard:
        """Create custom dashboard."""
        return self.dashboard_manager.create_custom_dashboard(name, description, chart_configs)

    def generate_insights_report(self) -> Dict[str, Any]:
        """Generate comprehensive analytics report."""
        return self.analytics_engine.generate_insights_report()

    def get_system_status(self) -> Dict[str, Any]:
        """Get system status including visualization metrics."""
        return {
            "data_collector_active": self.data_collector.collection_enabled,
            "total_dashboards": len(self.dashboard_manager.dashboards),
            "data_points_collected": sum(
                len(queue) for queue in self.data_collector.data_store.values()
            ),
            "last_collection": datetime.now().isoformat()
        }


# Global visualization and analytics instance
visualization_analytics = VisualizationAnalytics()
