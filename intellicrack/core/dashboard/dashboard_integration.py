"""Dashboard Integration Module for Intellicrack.

This module integrates the real-time dashboard with all analysis tools
and provides a unified interface for monitoring analysis operations.

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
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

from .dashboard_manager import DashboardManager, create_dashboard_manager
from .dashboard_widgets import WidgetType, create_widget
from .real_time_dashboard import DashboardEvent, DashboardEventType

logger = logging.getLogger(__name__)


@dataclass
class ToolIntegration:
    """Tool integration configuration."""
    tool_name: str
    analyzer_instance: Any
    event_handler: Optional[Callable] = None
    metrics_provider: Optional[Callable] = None
    status_provider: Optional[Callable] = None
    enabled: bool = True


class DashboardIntegration:
    """Integrates dashboard with all analysis tools."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize dashboard integration.

        Args:
            config: Integration configuration
        """
        self.logger = logger
        self.config = config or {}

        # Dashboard manager
        dashboard_config = {
            "dashboard_config": {
                "enable_websocket": self.config.get("enable_websocket", True),
                "enable_http": self.config.get("enable_http", True),
                "websocket_port": self.config.get("websocket_port", 8765),
                "http_port": self.config.get("http_port", 5000),
                "max_events": self.config.get("max_events", 1000),
                "metrics_history": self.config.get("metrics_history", 100)
            }
        }
        self.dashboard_manager = create_dashboard_manager(dashboard_config)

        # Tool integrations
        self.tool_integrations: Dict[str, ToolIntegration] = {}

        # Analysis tracking
        self.active_analyses: Dict[str, Dict[str, Any]] = {}
        self.analysis_lock = threading.Lock()

        # Event handlers
        self.event_handlers: Dict[str, List[Callable]] = {}

        # Initialize custom widgets
        self._initialize_custom_widgets()

        # Start dashboard
        self.dashboard_manager.start()
        self.logger.info("Dashboard integration initialized")

    def _initialize_custom_widgets(self):
        """Initialize custom analysis widgets."""
        # Binary analysis overview
        self.dashboard_manager.add_widget(create_widget(
            "binary_overview",
            WidgetType.TABLE,
            "Binary Overview",
            sortable=False,
            filterable=False
        ))

        # Tool status grid
        self.dashboard_manager.add_widget(create_widget(
            "tool_status",
            WidgetType.TABLE,
            "Tool Status",
            sortable=True,
            filterable=False
        ))

        # Bypass strategies chart
        self.dashboard_manager.add_widget(create_widget(
            "bypass_strategies",
            WidgetType.BAR_CHART,
            "Bypass Strategies by Type"
        ))

        # Cross-tool correlation matrix
        self.dashboard_manager.add_widget(create_widget(
            "correlation_matrix",
            WidgetType.HEATMAP,
            "Cross-tool Correlation",
            colorscale="RdBu"
        ))

        # Live memory usage
        self.dashboard_manager.add_widget(create_widget(
            "memory_timeline",
            WidgetType.LINE_CHART,
            "Memory Usage Timeline",
            history_size=100
        ))

        # Analysis speed gauge
        self.dashboard_manager.add_widget(create_widget(
            "analysis_speed",
            WidgetType.GAUGE,
            "Analysis Speed",
            min=0,
            max=1000,
            units="ops/sec"
        ))

    def integrate_ghidra(self, ghidra_analyzer: Any):
        """Integrate Ghidra analyzer with dashboard.

        Args:
            ghidra_analyzer: Ghidra analyzer instance
        """
        integration = ToolIntegration(
            tool_name="ghidra",
            analyzer_instance=ghidra_analyzer,
            event_handler=self._handle_ghidra_event,
            metrics_provider=self._get_ghidra_metrics,
            status_provider=self._get_ghidra_status
        )

        self.tool_integrations["ghidra"] = integration
        self.dashboard_manager.integrate_tool("ghidra", ghidra_analyzer)

        # Hook into Ghidra events
        if hasattr(ghidra_analyzer, 'register_callback'):
            ghidra_analyzer.register_callback(self._handle_ghidra_event)

        self.logger.info("Integrated Ghidra with dashboard")

    def integrate_frida(self, frida_analyzer: Any):
        """Integrate Frida analyzer with dashboard.

        Args:
            frida_analyzer: Frida analyzer instance
        """
        integration = ToolIntegration(
            tool_name="frida",
            analyzer_instance=frida_analyzer,
            event_handler=self._handle_frida_event,
            metrics_provider=self._get_frida_metrics,
            status_provider=self._get_frida_status
        )

        self.tool_integrations["frida"] = integration
        self.dashboard_manager.integrate_tool("frida", frida_analyzer)

        # Hook into Frida events
        if hasattr(frida_analyzer, 'set_event_callback'):
            frida_analyzer.set_event_callback(self._handle_frida_event)

        self.logger.info("Integrated Frida with dashboard")

    def integrate_radare2(self, r2_analyzer: Any):
        """Integrate Radare2 analyzer with dashboard.

        Args:
            r2_analyzer: Radare2 analyzer instance
        """
        integration = ToolIntegration(
            tool_name="radare2",
            analyzer_instance=r2_analyzer,
            event_handler=self._handle_r2_event,
            metrics_provider=self._get_r2_metrics,
            status_provider=self._get_r2_status
        )

        self.tool_integrations["radare2"] = integration
        self.dashboard_manager.integrate_tool("radare2", r2_analyzer)

        # Hook into R2 performance monitor if available
        if hasattr(r2_analyzer, 'performance_monitor'):
            monitor = r2_analyzer.performance_monitor
            if hasattr(monitor, 'register_callback'):
                monitor.register_callback(self._handle_r2_performance)

        self.logger.info("Integrated Radare2 with dashboard")

    def integrate_cross_tool_orchestrator(self, orchestrator: Any):
        """Integrate cross-tool orchestrator with dashboard.

        Args:
            orchestrator: Cross-tool orchestrator instance
        """
        integration = ToolIntegration(
            tool_name="cross_tool",
            analyzer_instance=orchestrator,
            event_handler=self._handle_orchestrator_event,
            metrics_provider=self._get_orchestrator_metrics,
            status_provider=self._get_orchestrator_status
        )

        self.tool_integrations["cross_tool"] = integration
        self.dashboard_manager.integrate_tool("cross_tool", orchestrator)

        self.logger.info("Integrated cross-tool orchestrator with dashboard")

    def start_analysis_monitoring(self, analysis_id: str, tool: str,
                                 target: str, options: Optional[Dict[str, Any]] = None):
        """Start monitoring an analysis.

        Args:
            analysis_id: Unique analysis identifier
            tool: Tool name
            target: Target binary path
            options: Analysis options
        """
        with self.analysis_lock:
            self.active_analyses[analysis_id] = {
                'tool': tool,
                'target': target,
                'options': options or {},
                'start_time': datetime.now(),
                'events': [],
                'metrics': {}
            }

        # Notify dashboard
        self.dashboard_manager.dashboard.start_analysis(
            analysis_id, tool, target, options
        )

        # Update binary overview widget
        self._update_binary_overview(target)

        # Update tool status
        self._update_tool_status(tool, "Running")

    def complete_analysis_monitoring(self, analysis_id: str, results: Dict[str, Any]):
        """Complete analysis monitoring.

        Args:
            analysis_id: Analysis identifier
            results: Analysis results
        """
        with self.analysis_lock:
            if analysis_id in self.active_analyses:
                analysis = self.active_analyses[analysis_id]
                analysis['end_time'] = datetime.now()
                analysis['duration'] = (analysis['end_time'] - analysis['start_time']).total_seconds()
                analysis['results'] = results

        # Notify dashboard
        self.dashboard_manager.dashboard.complete_analysis(analysis_id, results)

        # Update tool status
        if analysis_id in self.active_analyses:
            tool = self.active_analyses[analysis_id]['tool']
            self._update_tool_status(tool, "Idle")

        # Process results for visualization
        self._process_analysis_results(results)

    def report_finding(self, finding_type: str, tool: str, data: Dict[str, Any]):
        """Report analysis finding to dashboard.

        Args:
            finding_type: Type of finding (vulnerability, protection, bypass)
            tool: Tool that found it
            data: Finding data
        """
        if finding_type == "vulnerability":
            self.dashboard_manager.dashboard.report_vulnerability(tool, data)
        elif finding_type == "protection":
            self.dashboard_manager.dashboard.report_protection(tool, data)
        elif finding_type == "bypass":
            self.dashboard_manager.dashboard.report_bypass(tool, data)
        else:
            # Generic event
            self.dashboard_manager.process_analysis_event(finding_type, tool, data)

        # Update relevant widgets
        self._update_finding_widgets(finding_type, data)

    def get_dashboard_url(self) -> str:
        """Get dashboard URL.

        Returns:
            Dashboard URL
        """
        return self.dashboard_manager.get_dashboard_url()

    def get_websocket_url(self) -> str:
        """Get WebSocket URL for real-time updates.

        Returns:
            WebSocket URL
        """
        return self.dashboard_manager.get_websocket_url()

    def export_analysis_report(self, filepath: str):
        """Export comprehensive analysis report.

        Args:
            filepath: Export file path
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'analyses': {},
            'findings': {
                'vulnerabilities': [],
                'protections': [],
                'bypasses': []
            },
            'metrics': {},
            'tool_status': {}
        }

        # Collect analysis data
        with self.analysis_lock:
            for analysis_id, analysis in self.active_analyses.items():
                report['analyses'][analysis_id] = {
                    'tool': analysis['tool'],
                    'target': analysis['target'],
                    'duration': analysis.get('duration', 0),
                    'event_count': len(analysis.get('events', [])),
                    'results_summary': self._summarize_results(analysis.get('results', {}))
                }

        # Get dashboard state
        dashboard_state = self.dashboard_manager.dashboard.get_dashboard_state()
        report['metrics'] = dashboard_state.get('metrics', {})

        # Get tool status
        for tool_name, integration in self.tool_integrations.items():
            if integration.status_provider:
                report['tool_status'][tool_name] = integration.status_provider()

        # Export to file
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        self.logger.info(f"Exported analysis report to {filepath}")

    def shutdown(self):
        """Shutdown dashboard integration."""
        self.logger.info("Shutting down dashboard integration")

        # Stop dashboard manager
        self.dashboard_manager.stop()

        # Clear active analyses
        self.active_analyses.clear()

    # Event handlers for different tools

    def _handle_ghidra_event(self, event_type: str, data: Dict[str, Any]):
        """Handle Ghidra event.

        Args:
            event_type: Event type
            data: Event data
        """
        self.dashboard_manager.process_analysis_event(event_type, "ghidra", data)

        # Update specific widgets based on event type
        if event_type == "function_analyzed":
            self._update_function_analysis("ghidra", data)

    def _handle_frida_event(self, event_type: str, data: Dict[str, Any]):
        """Handle Frida event.

        Args:
            event_type: Event type
            data: Event data
        """
        self.dashboard_manager.process_analysis_event(event_type, "frida", data)

        # Update specific widgets based on event type
        if event_type == "hook_installed":
            self._update_hook_status(data)

    def _handle_r2_event(self, event_type: str, data: Dict[str, Any]):
        """Handle Radare2 event.

        Args:
            event_type: Event type
            data: Event data
        """
        self.dashboard_manager.process_analysis_event(event_type, "radare2", data)

        # Update specific widgets based on event type
        if event_type == "graph_generated":
            self._update_graph_widget(data)

    def _handle_r2_performance(self, metrics: Dict[str, Any]):
        """Handle R2 performance metrics.

        Args:
            metrics: Performance metrics
        """
        self.dashboard_manager.dashboard.update_performance("radare2", metrics)

    def _handle_orchestrator_event(self, event_type: str, data: Dict[str, Any]):
        """Handle orchestrator event.

        Args:
            event_type: Event type
            data: Event data
        """
        self.dashboard_manager.process_analysis_event(event_type, "cross_tool", data)

        # Update correlation matrix for cross-tool findings
        if event_type == "correlation_found":
            self._update_correlation_matrix(data)

    # Metrics providers

    def _get_ghidra_metrics(self) -> Dict[str, Any]:
        """Get Ghidra metrics.

        Returns:
            Ghidra metrics
        """
        integration = self.tool_integrations.get("ghidra")
        if not integration or not integration.analyzer_instance:
            return {}

        analyzer = integration.analyzer_instance
        metrics = {}

        if hasattr(analyzer, 'get_analysis_stats'):
            stats = analyzer.get_analysis_stats()
            metrics.update(stats)

        return metrics

    def _get_frida_metrics(self) -> Dict[str, Any]:
        """Get Frida metrics.

        Returns:
            Frida metrics
        """
        integration = self.tool_integrations.get("frida")
        if not integration or not integration.analyzer_instance:
            return {}

        analyzer = integration.analyzer_instance
        metrics = {}

        if hasattr(analyzer, 'get_hook_stats'):
            metrics['hooks_installed'] = analyzer.get_hook_stats().get('total', 0)

        if hasattr(analyzer, 'get_intercept_count'):
            metrics['intercepts'] = analyzer.get_intercept_count()

        return metrics

    def _get_r2_metrics(self) -> Dict[str, Any]:
        """Get Radare2 metrics.

        Returns:
            Radare2 metrics
        """
        integration = self.tool_integrations.get("radare2")
        if not integration or not integration.analyzer_instance:
            return {}

        analyzer = integration.analyzer_instance
        metrics = {}

        if hasattr(analyzer, 'performance_monitor'):
            monitor = analyzer.performance_monitor
            if hasattr(monitor, 'get_current_metrics'):
                metrics.update(monitor.get_current_metrics())

        return metrics

    def _get_orchestrator_metrics(self) -> Dict[str, Any]:
        """Get orchestrator metrics.

        Returns:
            Orchestrator metrics
        """
        integration = self.tool_integrations.get("cross_tool")
        if not integration or not integration.analyzer_instance:
            return {}

        orchestrator = integration.analyzer_instance
        metrics = {}

        if hasattr(orchestrator, 'get_correlation_stats'):
            metrics['correlations'] = orchestrator.get_correlation_stats()

        return metrics

    # Status providers

    def _get_ghidra_status(self) -> Dict[str, Any]:
        """Get Ghidra status.

        Returns:
            Ghidra status
        """
        integration = self.tool_integrations.get("ghidra")
        if not integration:
            return {"status": "Not integrated"}

        return {
            "status": "Active" if integration.enabled else "Disabled",
            "metrics": self._get_ghidra_metrics()
        }

    def _get_frida_status(self) -> Dict[str, Any]:
        """Get Frida status.

        Returns:
            Frida status
        """
        integration = self.tool_integrations.get("frida")
        if not integration:
            return {"status": "Not integrated"}

        analyzer = integration.analyzer_instance
        status = {
            "status": "Active" if integration.enabled else "Disabled",
            "metrics": self._get_frida_metrics()
        }

        if hasattr(analyzer, 'is_attached'):
            status['attached'] = analyzer.is_attached()

        return status

    def _get_r2_status(self) -> Dict[str, Any]:
        """Get Radare2 status.

        Returns:
            Radare2 status
        """
        integration = self.tool_integrations.get("radare2")
        if not integration:
            return {"status": "Not integrated"}

        return {
            "status": "Active" if integration.enabled else "Disabled",
            "metrics": self._get_r2_metrics()
        }

    def _get_orchestrator_status(self) -> Dict[str, Any]:
        """Get orchestrator status.

        Returns:
            Orchestrator status
        """
        integration = self.tool_integrations.get("cross_tool")
        if not integration:
            return {"status": "Not integrated"}

        orchestrator = integration.analyzer_instance
        status = {
            "status": "Active" if integration.enabled else "Disabled",
            "metrics": self._get_orchestrator_metrics()
        }

        if hasattr(orchestrator, 'get_active_tools'):
            status['active_tools'] = orchestrator.get_active_tools()

        return status

    # Widget update methods

    def _update_binary_overview(self, target: str):
        """Update binary overview widget.

        Args:
            target: Target binary path
        """
        from ..dashboard_widgets import WidgetData

        path = Path(target)
        rows = [
            {"Property": "Name", "Value": path.name},
            {"Property": "Path", "Value": str(path)},
            {"Property": "Size", "Value": f"{path.stat().st_size / 1024:.2f} KB" if path.exists() else "N/A"},
            {"Property": "Modified", "Value": datetime.fromtimestamp(path.stat().st_mtime).isoformat() if path.exists() else "N/A"}
        ]

        widget_data = WidgetData(
            timestamp=datetime.now(),
            values={"rows": rows, "columns": ["Property", "Value"]}
        )

        if "binary_overview" in self.dashboard_manager.widgets:
            self.dashboard_manager.widgets["binary_overview"].update_data(widget_data)

    def _update_tool_status(self, tool: str, status: str):
        """Update tool status widget.

        Args:
            tool: Tool name
            status: Tool status
        """
        from ..dashboard_widgets import WidgetData

        # Get current status for all tools
        rows = []
        for tool_name in ["ghidra", "frida", "radare2", "cross_tool"]:
            integration = self.tool_integrations.get(tool_name)
            if integration:
                tool_status = "Running" if tool_name == tool and status == "Running" else "Idle"
                rows.append({
                    "Tool": tool_name.capitalize(),
                    "Status": tool_status,
                    "Enabled": "Yes" if integration.enabled else "No"
                })

        widget_data = WidgetData(
            timestamp=datetime.now(),
            values={"rows": rows, "columns": ["Tool", "Status", "Enabled"]}
        )

        if "tool_status" in self.dashboard_manager.widgets:
            self.dashboard_manager.widgets["tool_status"].update_data(widget_data)

    def _update_function_analysis(self, tool: str, data: Dict[str, Any]):
        """Update function analysis widgets.

        Args:
            tool: Tool name
            data: Function data
        """
        from ..dashboard_widgets import WidgetData

        # Update functions chart
        if "functions_chart" in self.dashboard_manager.widgets:
            widget = self.dashboard_manager.widgets["functions_chart"]
            current = widget.get_current_data()

            values = current.values if current else {}
            values[tool] = values.get(tool, 0) + 1

            widget_data = WidgetData(
                timestamp=datetime.now(),
                values=values
            )
            widget.update_data(widget_data)

    def _update_hook_status(self, data: Dict[str, Any]):
        """Update hook status display.

        Args:
            data: Hook data
        """
        # Create event for timeline
        event = DashboardEvent(
            event_type=DashboardEventType.INFO_MESSAGE,
            timestamp=datetime.now(),
            tool="frida",
            title=f"Hook: {data.get('function', 'Unknown')}",
            description=f"Installed hook at {data.get('address', 'Unknown')}",
            data=data,
            tags=["hook", "frida"]
        )
        self.dashboard_manager.dashboard.add_event(event)

    def _update_graph_widget(self, data: Dict[str, Any]):
        """Update graph visualization widget.

        Args:
            data: Graph data
        """
        from ..dashboard_widgets import WidgetData

        if "call_graph" in self.dashboard_manager.widgets:
            widget_data = WidgetData(
                timestamp=datetime.now(),
                values={
                    "nodes": data.get("nodes", []),
                    "edges": data.get("edges", [])
                }
            )
            self.dashboard_manager.widgets["call_graph"].update_data(widget_data)

    def _update_correlation_matrix(self, data: Dict[str, Any]):
        """Update correlation matrix widget.

        Args:
            data: Correlation data
        """
        from ..dashboard_widgets import WidgetData

        if "correlation_matrix" in self.dashboard_manager.widgets:
            matrix = data.get("correlation_matrix", [])
            tools = data.get("tools", ["ghidra", "frida", "radare2"])

            widget_data = WidgetData(
                timestamp=datetime.now(),
                values={"matrix": matrix},
                labels=tools,
                categories=tools
            )
            self.dashboard_manager.widgets["correlation_matrix"].update_data(widget_data)

    def _update_finding_widgets(self, finding_type: str, data: Dict[str, Any]):
        """Update widgets based on findings.

        Args:
            finding_type: Type of finding
            data: Finding data
        """
        from ..dashboard_widgets import WidgetData

        # Update bypass strategies chart
        if finding_type == "bypass" and "bypass_strategies" in self.dashboard_manager.widgets:
            widget = self.dashboard_manager.widgets["bypass_strategies"]
            current = widget.get_current_data()

            values = current.values if current else {}
            bypass_type = data.get("type", "Unknown")
            values[bypass_type] = values.get(bypass_type, 0) + 1

            widget_data = WidgetData(
                timestamp=datetime.now(),
                values=values
            )
            widget.update_data(widget_data)

    def _process_analysis_results(self, results: Dict[str, Any]):
        """Process analysis results for visualization.

        Args:
            results: Analysis results
        """
        # Update various widgets based on results
        if results.get("functions"):
            self._update_function_analysis("analysis", {"count": len(results["functions"])})

        if results.get("vulnerabilities"):
            for vuln in results["vulnerabilities"]:
                self.report_finding("vulnerability", "analysis", vuln)

        if results.get("protections"):
            for prot in results["protections"]:
                self.report_finding("protection", "analysis", prot)

    def _summarize_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize analysis results.

        Args:
            results: Full results

        Returns:
            Summary dictionary
        """
        return {
            'functions': len(results.get('functions', [])),
            'vulnerabilities': len(results.get('vulnerabilities', [])),
            'protections': len(results.get('protections', [])),
            'imports': len(results.get('imports', [])),
            'strings': len(results.get('strings', []))
        }


def create_dashboard_integration(config: Optional[Dict[str, Any]] = None) -> DashboardIntegration:
    """Factory function to create dashboard integration.

    Args:
        config: Integration configuration

    Returns:
        New DashboardIntegration instance
    """
    return DashboardIntegration(config)