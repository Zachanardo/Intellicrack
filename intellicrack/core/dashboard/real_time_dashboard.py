"""Real-time Dashboard for Intellicrack Analysis.

This module provides a real-time dashboard for monitoring and visualizing
analysis results from all integrated tools (Ghidra, Frida, Radare2).

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

import asyncio
import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
from pathlib import Path

try:
    import websockets
    from websockets.server import WebSocketServerProtocol
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

try:
    from flask import Flask, render_template, jsonify, request
    from flask_cors import CORS
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

logger = logging.getLogger(__name__)


class DashboardEventType(Enum):
    """Types of dashboard events."""
    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETED = "analysis_completed"
    ANALYSIS_FAILED = "analysis_failed"
    TOOL_OUTPUT = "tool_output"
    VULNERABILITY_FOUND = "vulnerability_found"
    PROTECTION_DETECTED = "protection_detected"
    FUNCTION_ANALYZED = "function_analyzed"
    MEMORY_SNAPSHOT = "memory_snapshot"
    PERFORMANCE_UPDATE = "performance_update"
    GRAPH_GENERATED = "graph_generated"
    CORRELATION_FOUND = "correlation_found"
    BYPASS_STRATEGY = "bypass_strategy"
    ERROR_OCCURRED = "error_occurred"
    WARNING_RAISED = "warning_raised"
    INFO_MESSAGE = "info_message"


@dataclass
class DashboardEvent:
    """Event for dashboard display."""
    event_type: DashboardEventType
    timestamp: datetime
    tool: str
    title: str
    description: str
    data: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"  # info, warning, error, critical
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'event_type': self.event_type.value,
            'timestamp': self.timestamp.isoformat(),
            'tool': self.tool,
            'title': self.title,
            'description': self.description,
            'data': self.data,
            'severity': self.severity,
            'tags': self.tags
        }


@dataclass
class AnalysisMetrics:
    """Real-time analysis metrics."""
    total_functions_analyzed: int = 0
    total_vulnerabilities_found: int = 0
    total_protections_detected: int = 0
    total_bypasses_generated: int = 0
    analysis_duration_seconds: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    cache_hit_rate: float = 0.0
    tools_active: Set[str] = field(default_factory=set)
    errors_count: int = 0
    warnings_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'total_functions_analyzed': self.total_functions_analyzed,
            'total_vulnerabilities_found': self.total_vulnerabilities_found,
            'total_protections_detected': self.total_protections_detected,
            'total_bypasses_generated': self.total_bypasses_generated,
            'analysis_duration_seconds': self.analysis_duration_seconds,
            'memory_usage_mb': self.memory_usage_mb,
            'cpu_usage_percent': self.cpu_usage_percent,
            'cache_hit_rate': self.cache_hit_rate,
            'tools_active': list(self.tools_active),
            'errors_count': self.errors_count,
            'warnings_count': self.warnings_count
        }


class RealTimeDashboard:
    """Real-time dashboard for monitoring analysis."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize real-time dashboard.

        Args:
            config: Dashboard configuration
        """
        self.logger = logger
        self.config = config or {}

        # Event management
        self.events: deque = deque(maxlen=self.config.get("max_events", 1000))
        self.event_callbacks: List[Callable] = []
        self.events_lock = threading.Lock()

        # Metrics tracking
        self.metrics = AnalysisMetrics()
        self.metrics_history: deque = deque(maxlen=self.config.get("metrics_history", 100))
        self.metrics_lock = threading.Lock()

        # Analysis state
        self.active_analyses: Dict[str, Dict[str, Any]] = {}
        self.analysis_results: Dict[str, Any] = {}
        self.state_lock = threading.Lock()

        # WebSocket connections
        self.websocket_clients: Set[WebSocketServerProtocol] = set()
        self.websocket_server = None
        self.websocket_thread = None

        # Flask app for HTTP API
        self.flask_app = None
        self.flask_thread = None

        # Update intervals
        self.update_interval = self.config.get("update_interval", 1.0)
        self.metrics_update_interval = self.config.get("metrics_update_interval", 5.0)

        # Start time
        self.start_time = datetime.now()

        # Initialize components
        self._initialize_dashboard()

    def _initialize_dashboard(self):
        """Initialize dashboard components."""
        # Start WebSocket server if available
        if HAS_WEBSOCKETS and self.config.get("enable_websocket", True):
            self._start_websocket_server()

        # Start Flask server if available
        if HAS_FLASK and self.config.get("enable_http", True):
            self._start_flask_server()

        # Start metrics update thread
        self._start_metrics_updater()

        self.logger.info("Real-time dashboard initialized")

    def add_event(self, event: DashboardEvent):
        """Add event to dashboard.

        Args:
            event: Dashboard event to add
        """
        with self.events_lock:
            self.events.append(event)

            # Update metrics based on event
            self._update_metrics_from_event(event)

        # Notify callbacks
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                self.logger.error(f"Error in event callback: {e}")

        # Broadcast to WebSocket clients
        if self.websocket_clients:
            asyncio.run_coroutine_threadsafe(
                self._broadcast_event(event),
                self.websocket_loop
            )

    def register_callback(self, callback: Callable):
        """Register event callback.

        Args:
            callback: Function to call on events
        """
        self.event_callbacks.append(callback)

    def start_analysis(self, analysis_id: str, tool: str, target: str,
                       options: Optional[Dict[str, Any]] = None):
        """Start tracking an analysis.

        Args:
            analysis_id: Unique analysis identifier
            tool: Tool name
            target: Target binary path
            options: Analysis options
        """
        with self.state_lock:
            self.active_analyses[analysis_id] = {
                'tool': tool,
                'target': target,
                'options': options or {},
                'start_time': datetime.now(),
                'status': 'running'
            }

            with self.metrics_lock:
                self.metrics.tools_active.add(tool)

        # Create event
        event = DashboardEvent(
            event_type=DashboardEventType.ANALYSIS_STARTED,
            timestamp=datetime.now(),
            tool=tool,
            title=f"Analysis Started: {Path(target).name}",
            description=f"Started {tool} analysis on {target}",
            data={'analysis_id': analysis_id, 'options': options or {}},
            tags=['analysis', 'started', tool]
        )
        self.add_event(event)

    def complete_analysis(self, analysis_id: str, results: Dict[str, Any]):
        """Mark analysis as complete.

        Args:
            analysis_id: Analysis identifier
            results: Analysis results
        """
        with self.state_lock:
            if analysis_id in self.active_analyses:
                analysis = self.active_analyses[analysis_id]
                analysis['status'] = 'completed'
                analysis['end_time'] = datetime.now()
                analysis['duration'] = (analysis['end_time'] - analysis['start_time']).total_seconds()

                # Store results
                self.analysis_results[analysis_id] = results

                # Update metrics
                with self.metrics_lock:
                    self.metrics.analysis_duration_seconds += analysis['duration']

        # Create event
        event = DashboardEvent(
            event_type=DashboardEventType.ANALYSIS_COMPLETED,
            timestamp=datetime.now(),
            tool=analysis.get('tool', 'unknown'),
            title=f"Analysis Completed",
            description=f"Completed analysis {analysis_id}",
            data={'analysis_id': analysis_id, 'results_summary': self._summarize_results(results)},
            severity='info',
            tags=['analysis', 'completed']
        )
        self.add_event(event)

    def report_vulnerability(self, tool: str, vulnerability: Dict[str, Any]):
        """Report a vulnerability finding.

        Args:
            tool: Tool that found vulnerability
            vulnerability: Vulnerability details
        """
        with self.metrics_lock:
            self.metrics.total_vulnerabilities_found += 1

        event = DashboardEvent(
            event_type=DashboardEventType.VULNERABILITY_FOUND,
            timestamp=datetime.now(),
            tool=tool,
            title=f"Vulnerability: {vulnerability.get('type', 'Unknown')}",
            description=vulnerability.get('description', 'Vulnerability detected'),
            data=vulnerability,
            severity=vulnerability.get('severity', 'warning'),
            tags=['vulnerability', tool, vulnerability.get('type', '')]
        )
        self.add_event(event)

    def report_protection(self, tool: str, protection: Dict[str, Any]):
        """Report a protection detection.

        Args:
            tool: Tool that detected protection
            protection: Protection details
        """
        with self.metrics_lock:
            self.metrics.total_protections_detected += 1

        event = DashboardEvent(
            event_type=DashboardEventType.PROTECTION_DETECTED,
            timestamp=datetime.now(),
            tool=tool,
            title=f"Protection: {protection.get('type', 'Unknown')}",
            description=protection.get('description', 'Protection detected'),
            data=protection,
            severity='info',
            tags=['protection', tool, protection.get('type', '')]
        )
        self.add_event(event)

    def report_bypass(self, tool: str, bypass: Dict[str, Any]):
        """Report a bypass strategy.

        Args:
            tool: Tool that generated bypass
            bypass: Bypass details
        """
        with self.metrics_lock:
            self.metrics.total_bypasses_generated += 1

        event = DashboardEvent(
            event_type=DashboardEventType.BYPASS_STRATEGY,
            timestamp=datetime.now(),
            tool=tool,
            title=f"Bypass Strategy: {bypass.get('target', 'Unknown')}",
            description=bypass.get('description', 'Bypass strategy generated'),
            data=bypass,
            severity='info',
            tags=['bypass', tool, bypass.get('type', '')]
        )
        self.add_event(event)

    def update_performance(self, tool: str, metrics: Dict[str, Any]):
        """Update performance metrics.

        Args:
            tool: Tool name
            metrics: Performance metrics
        """
        with self.metrics_lock:
            if 'memory_mb' in metrics:
                self.metrics.memory_usage_mb = metrics['memory_mb']
            if 'cpu_percent' in metrics:
                self.metrics.cpu_usage_percent = metrics['cpu_percent']
            if 'cache_hit_rate' in metrics:
                self.metrics.cache_hit_rate = metrics['cache_hit_rate']

        event = DashboardEvent(
            event_type=DashboardEventType.PERFORMANCE_UPDATE,
            timestamp=datetime.now(),
            tool=tool,
            title="Performance Update",
            description=f"Performance metrics from {tool}",
            data=metrics,
            severity='info',
            tags=['performance', tool]
        )
        self.add_event(event)

    def get_dashboard_state(self) -> Dict[str, Any]:
        """Get current dashboard state.

        Returns:
            Dictionary containing dashboard state
        """
        with self.events_lock:
            recent_events = [e.to_dict() for e in list(self.events)[-100:]]

        with self.metrics_lock:
            current_metrics = self.metrics.to_dict()

        with self.state_lock:
            active = list(self.active_analyses.values())

        uptime = (datetime.now() - self.start_time).total_seconds()

        return {
            'timestamp': datetime.now().isoformat(),
            'uptime_seconds': uptime,
            'metrics': current_metrics,
            'active_analyses': active,
            'recent_events': recent_events,
            'event_count': len(self.events),
            'result_count': len(self.analysis_results)
        }

    def get_metrics_history(self) -> List[Dict[str, Any]]:
        """Get metrics history.

        Returns:
            List of historical metrics
        """
        with self.metrics_lock:
            return [m for m in self.metrics_history]

    def _update_metrics_from_event(self, event: DashboardEvent):
        """Update metrics based on event.

        Args:
            event: Dashboard event
        """
        with self.metrics_lock:
            if event.event_type == DashboardEventType.FUNCTION_ANALYZED:
                self.metrics.total_functions_analyzed += 1
            elif event.event_type == DashboardEventType.ERROR_OCCURRED:
                self.metrics.errors_count += 1
            elif event.event_type == DashboardEventType.WARNING_RAISED:
                self.metrics.warnings_count += 1

    def _summarize_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize analysis results.

        Args:
            results: Full analysis results

        Returns:
            Summary dictionary
        """
        summary = {
            'functions_count': len(results.get('functions', [])),
            'vulnerabilities_count': len(results.get('vulnerabilities', [])),
            'protections_count': len(results.get('protections', [])),
            'imports_count': len(results.get('imports', [])),
            'strings_count': len(results.get('strings', []))
        }

        # Add vulnerability types
        if results.get('vulnerabilities'):
            vuln_types = set()
            for vuln in results['vulnerabilities']:
                if 'type' in vuln:
                    vuln_types.add(vuln['type'])
            summary['vulnerability_types'] = list(vuln_types)

        # Add protection types
        if results.get('protections'):
            prot_types = set()
            for prot in results['protections']:
                if 'type' in prot:
                    prot_types.add(prot['type'])
            summary['protection_types'] = list(prot_types)

        return summary

    def _start_websocket_server(self):
        """Start WebSocket server for real-time updates."""
        if not HAS_WEBSOCKETS:
            self.logger.warning("WebSockets not available, skipping WebSocket server")
            return

        async def handle_client(websocket, path):
            """Handle WebSocket client connection."""
            self.websocket_clients.add(websocket)
            self.logger.info(f"WebSocket client connected: {websocket.remote_address}")

            try:
                # Send initial state
                state = self.get_dashboard_state()
                await websocket.send(json.dumps({
                    'type': 'state',
                    'data': state
                }))

                # Keep connection alive
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        if data.get('type') == 'ping':
                            await websocket.send(json.dumps({'type': 'pong'}))
                    except json.JSONDecodeError:
                        self.logger.warning(f"Invalid WebSocket message: {message}")

            except websockets.exceptions.ConnectionClosed:
                self.logger.info(f"WebSocket client disconnected: {websocket.remote_address}")
            finally:
                self.websocket_clients.discard(websocket)

        async def start_server():
            """Start the WebSocket server."""
            port = self.config.get("websocket_port", 8765)
            self.websocket_server = await websockets.serve(
                handle_client,
                "localhost",
                port
            )
            self.logger.info(f"WebSocket server started on port {port}")
            await asyncio.Future()  # Run forever

        def run_server():
            """Run WebSocket server in thread."""
            self.websocket_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.websocket_loop)
            self.websocket_loop.run_until_complete(start_server())

        self.websocket_thread = threading.Thread(target=run_server, daemon=True)
        self.websocket_thread.start()

    async def _broadcast_event(self, event: DashboardEvent):
        """Broadcast event to all WebSocket clients.

        Args:
            event: Event to broadcast
        """
        if not self.websocket_clients:
            return

        message = json.dumps({
            'type': 'event',
            'data': event.to_dict()
        })

        # Send to all connected clients
        disconnected = set()
        for client in self.websocket_clients:
            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
            except Exception as e:
                self.logger.error(f"Error broadcasting to client: {e}")
                disconnected.add(client)

        # Remove disconnected clients
        self.websocket_clients -= disconnected

    def _start_flask_server(self):
        """Start Flask HTTP server."""
        if not HAS_FLASK:
            self.logger.warning("Flask not available, skipping HTTP server")
            return

        self.flask_app = Flask(__name__)
        CORS(self.flask_app)  # Enable CORS for web clients

        @self.flask_app.route('/api/state')
        def get_state():
            """Get dashboard state endpoint."""
            return jsonify(self.get_dashboard_state())

        @self.flask_app.route('/api/events')
        def get_events():
            """Get recent events endpoint."""
            limit = request.args.get('limit', 100, type=int)
            with self.events_lock:
                events = [e.to_dict() for e in list(self.events)[-limit:]]
            return jsonify(events)

        @self.flask_app.route('/api/metrics')
        def get_metrics():
            """Get current metrics endpoint."""
            with self.metrics_lock:
                return jsonify(self.metrics.to_dict())

        @self.flask_app.route('/api/metrics/history')
        def get_metrics_history():
            """Get metrics history endpoint."""
            return jsonify(self.get_metrics_history())

        @self.flask_app.route('/api/analyses/active')
        def get_active_analyses():
            """Get active analyses endpoint."""
            with self.state_lock:
                return jsonify(list(self.active_analyses.values()))

        @self.flask_app.route('/api/results/<analysis_id>')
        def get_results(analysis_id):
            """Get analysis results endpoint."""
            with self.state_lock:
                if analysis_id in self.analysis_results:
                    return jsonify(self.analysis_results[analysis_id])
                else:
                    return jsonify({'error': 'Analysis not found'}), 404

        def run_flask():
            """Run Flask server."""
            port = self.config.get("http_port", 5000)
            self.flask_app.run(
                host='localhost',
                port=port,
                debug=False,
                use_reloader=False
            )

        self.flask_thread = threading.Thread(target=run_flask, daemon=True)
        self.flask_thread.start()

        self.logger.info(f"HTTP API server started on port {self.config.get('http_port', 5000)}")

    def _start_metrics_updater(self):
        """Start metrics update thread."""
        def update_loop():
            """Metrics update loop."""
            while True:
                try:
                    # Create metrics snapshot
                    with self.metrics_lock:
                        snapshot = {
                            'timestamp': datetime.now().isoformat(),
                            **self.metrics.to_dict()
                        }
                        self.metrics_history.append(snapshot)

                    # Broadcast metrics update
                    if self.websocket_clients:
                        asyncio.run_coroutine_threadsafe(
                            self._broadcast_metrics(snapshot),
                            self.websocket_loop
                        )

                except Exception as e:
                    self.logger.error(f"Error in metrics updater: {e}")

                time.sleep(self.metrics_update_interval)

        thread = threading.Thread(target=update_loop, daemon=True)
        thread.start()

    async def _broadcast_metrics(self, metrics: Dict[str, Any]):
        """Broadcast metrics update to WebSocket clients.

        Args:
            metrics: Metrics to broadcast
        """
        if not self.websocket_clients:
            return

        message = json.dumps({
            'type': 'metrics',
            'data': metrics
        })

        disconnected = set()
        for client in self.websocket_clients:
            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
            except Exception as e:
                self.logger.error(f"Error broadcasting metrics: {e}")
                disconnected.add(client)

        self.websocket_clients -= disconnected

    def shutdown(self):
        """Shutdown dashboard."""
        self.logger.info("Shutting down dashboard")

        # Close WebSocket connections
        for client in list(self.websocket_clients):
            asyncio.run_coroutine_threadsafe(
                client.close(),
                self.websocket_loop
            )

        # Stop WebSocket server
        if self.websocket_server:
            self.websocket_server.close()

        # Note: Flask server runs as daemon thread and will stop automatically


def create_dashboard(config: Optional[Dict[str, Any]] = None) -> RealTimeDashboard:
    """Factory function to create dashboard.

    Args:
        config: Dashboard configuration

    Returns:
        New RealTimeDashboard instance
    """
    return RealTimeDashboard(config)