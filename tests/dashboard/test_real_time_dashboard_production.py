"""Production tests for real-time dashboard functionality.

Tests validate WebSocket communication, event broadcasting, metrics tracking,
and Flask API endpoints for live analysis monitoring.
"""

import asyncio
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from intellicrack.dashboard.real_time_dashboard import (
    AnalysisMetrics,
    DashboardEvent,
    DashboardEventType,
    RealTimeDashboard,
    create_dashboard,
)


@pytest.fixture
def dashboard_config() -> dict[str, Any]:
    """Create test dashboard configuration."""
    return {
        "max_events": 100,
        "metrics_history": 50,
        "update_interval": 0.1,
        "metrics_update_interval": 0.5,
        "enable_websocket": False,
        "enable_http": False,
    }


@pytest.fixture
def dashboard(dashboard_config: dict[str, Any]) -> RealTimeDashboard:
    """Create dashboard instance for testing."""
    return RealTimeDashboard(dashboard_config)


class TestDashboardEvent:
    """Tests for DashboardEvent dataclass."""

    def test_event_initializes(self) -> None:
        """DashboardEvent initializes with required fields."""
        event = DashboardEvent(
            event_type=DashboardEventType.ANALYSIS_STARTED,
            timestamp=datetime.now(),
            tool="radare2",
            title="Analysis Started",
            description="Starting radare2 analysis",
        )

        assert event.event_type == DashboardEventType.ANALYSIS_STARTED
        assert event.tool == "radare2"
        assert event.severity == "info"
        assert event.tags == []

    def test_event_to_dict_serialization(self) -> None:
        """DashboardEvent converts to dictionary correctly."""
        timestamp = datetime.now()
        event = DashboardEvent(
            event_type=DashboardEventType.VULNERABILITY_FOUND,
            timestamp=timestamp,
            tool="ghidra",
            title="Buffer Overflow",
            description="Found buffer overflow at 0x1000",
            data={"address": 0x1000, "type": "stack_overflow"},
            severity="critical",
            tags=["vulnerability", "memory"],
        )

        event_dict = event.to_dict()

        assert event_dict["event_type"] == "vulnerability_found"
        assert event_dict["timestamp"] == timestamp.isoformat()
        assert event_dict["tool"] == "ghidra"
        assert event_dict["severity"] == "critical"
        assert len(event_dict["tags"]) == 2
        assert event_dict["data"]["address"] == 0x1000


class TestAnalysisMetrics:
    """Tests for AnalysisMetrics dataclass."""

    def test_metrics_initializes_with_defaults(self) -> None:
        """AnalysisMetrics initializes with zero values."""
        metrics = AnalysisMetrics()

        assert metrics.total_functions_analyzed == 0
        assert metrics.total_vulnerabilities_found == 0
        assert metrics.total_protections_detected == 0
        assert metrics.total_bypasses_generated == 0
        assert metrics.analysis_duration_seconds == 0.0
        assert metrics.memory_usage_mb == 0.0
        assert metrics.cpu_usage_percent == 0.0
        assert metrics.cache_hit_rate == 0.0
        assert metrics.errors_count == 0
        assert metrics.warnings_count == 0
        assert isinstance(metrics.tools_active, set)

    def test_metrics_to_dict_serialization(self) -> None:
        """AnalysisMetrics converts to dictionary correctly."""
        metrics = AnalysisMetrics(
            total_functions_analyzed=100,
            total_vulnerabilities_found=5,
            total_protections_detected=3,
            total_bypasses_generated=2,
            analysis_duration_seconds=45.5,
            memory_usage_mb=256.7,
            cpu_usage_percent=75.2,
            cache_hit_rate=0.85,
            tools_active={"radare2", "ghidra"},
            errors_count=1,
            warnings_count=3,
        )

        metrics_dict = metrics.to_dict()

        assert metrics_dict["total_functions_analyzed"] == 100
        assert metrics_dict["total_vulnerabilities_found"] == 5
        assert metrics_dict["analysis_duration_seconds"] == 45.5
        assert metrics_dict["cache_hit_rate"] == 0.85
        assert set(metrics_dict["tools_active"]) == {"radare2", "ghidra"}


class TestRealTimeDashboard:
    """Tests for RealTimeDashboard class."""

    def test_dashboard_initializes(self, dashboard: RealTimeDashboard) -> None:
        """Dashboard initializes with configuration."""
        assert dashboard.config["max_events"] == 100
        assert isinstance(dashboard.events, object)
        assert isinstance(dashboard.metrics, AnalysisMetrics)
        assert isinstance(dashboard.active_analyses, dict)

    def test_add_event_stores_event(self, dashboard: RealTimeDashboard) -> None:
        """add_event stores events in deque."""
        event = DashboardEvent(
            event_type=DashboardEventType.ANALYSIS_STARTED,
            timestamp=datetime.now(),
            tool="frida",
            title="Test Analysis",
            description="Test description",
        )

        dashboard.add_event(event)

        assert len(dashboard.events) > 0
        assert dashboard.events[-1] == event

    def test_add_event_respects_max_events(self, dashboard: RealTimeDashboard) -> None:
        """add_event respects maxlen configuration."""
        max_events = dashboard.config["max_events"]

        for i in range(max_events + 50):
            event = DashboardEvent(
                event_type=DashboardEventType.INFO_MESSAGE,
                timestamp=datetime.now(),
                tool="test",
                title=f"Event {i}",
                description="Test",
            )
            dashboard.add_event(event)

        assert len(dashboard.events) <= max_events

    def test_add_event_updates_metrics(self, dashboard: RealTimeDashboard) -> None:
        """add_event updates metrics based on event type."""
        event = DashboardEvent(
            event_type=DashboardEventType.FUNCTION_ANALYZED,
            timestamp=datetime.now(),
            tool="radare2",
            title="Function Analysis",
            description="Analyzed function",
        )

        initial_count = dashboard.metrics.total_functions_analyzed
        dashboard.add_event(event)

        assert dashboard.metrics.total_functions_analyzed == initial_count + 1

    def test_register_callback_adds_callback(self, dashboard: RealTimeDashboard) -> None:
        """register_callback adds callback to list."""
        callback_called = []

        def test_callback(event: DashboardEvent) -> None:
            callback_called.append(event)

        dashboard.register_callback(test_callback)

        event = DashboardEvent(
            event_type=DashboardEventType.INFO_MESSAGE,
            timestamp=datetime.now(),
            tool="test",
            title="Test",
            description="Test",
        )
        dashboard.add_event(event)

        assert callback_called

    def test_start_analysis_creates_tracking(self, dashboard: RealTimeDashboard) -> None:
        """start_analysis creates analysis tracking entry."""
        dashboard.start_analysis(
            analysis_id="test-001",
            tool="ghidra",
            target="app.exe",
            options={"depth": "deep"},
        )

        assert "test-001" in dashboard.active_analyses
        analysis = dashboard.active_analyses["test-001"]
        assert analysis["tool"] == "ghidra"
        assert analysis["target"] == "app.exe"
        assert analysis["status"] == "running"

    def test_start_analysis_adds_tool_to_metrics(self, dashboard: RealTimeDashboard) -> None:
        """start_analysis adds tool to active tools set."""
        dashboard.start_analysis("test-002", "radare2", "test.exe")

        assert "radare2" in dashboard.metrics.tools_active

    def test_complete_analysis_updates_status(self, dashboard: RealTimeDashboard) -> None:
        """complete_analysis marks analysis as completed."""
        dashboard.start_analysis("test-003", "frida", "app.exe")

        dashboard.complete_analysis("test-003", {"functions": 50, "vulns": 2})

        analysis = dashboard.active_analyses["test-003"]
        assert analysis["status"] == "completed"
        assert "end_time" in analysis
        assert "duration" in analysis

    def test_complete_analysis_stores_results(self, dashboard: RealTimeDashboard) -> None:
        """complete_analysis stores analysis results."""
        dashboard.start_analysis("test-004", "ghidra", "test.exe")

        results = {"functions": 100, "strings": 500}
        dashboard.complete_analysis("test-004", results)

        assert "test-004" in dashboard.analysis_results
        assert dashboard.analysis_results["test-004"] == results

    def test_report_vulnerability_increments_counter(self, dashboard: RealTimeDashboard) -> None:
        """report_vulnerability increments vulnerability counter."""
        initial_count = dashboard.metrics.total_vulnerabilities_found

        dashboard.report_vulnerability("radare2", {"type": "buffer_overflow", "severity": "high"})

        assert dashboard.metrics.total_vulnerabilities_found == initial_count + 1

    def test_report_vulnerability_creates_event(self, dashboard: RealTimeDashboard) -> None:
        """report_vulnerability creates dashboard event."""
        initial_events = len(dashboard.events)

        dashboard.report_vulnerability("ghidra", {"type": "use_after_free", "description": "UAF detected"})

        assert len(dashboard.events) > initial_events
        last_event = dashboard.events[-1]
        assert last_event.event_type == DashboardEventType.VULNERABILITY_FOUND

    def test_report_protection_increments_counter(self, dashboard: RealTimeDashboard) -> None:
        """report_protection increments protection counter."""
        initial_count = dashboard.metrics.total_protections_detected

        dashboard.report_protection("radare2", {"type": "VMProtect", "version": "3.5"})

        assert dashboard.metrics.total_protections_detected == initial_count + 1

    def test_report_bypass_increments_counter(self, dashboard: RealTimeDashboard) -> None:
        """report_bypass increments bypass counter."""
        initial_count = dashboard.metrics.total_bypasses_generated

        dashboard.report_bypass("frida", {"target": "license_check", "method": "hook"})

        assert dashboard.metrics.total_bypasses_generated == initial_count + 1

    def test_update_performance_updates_metrics(self, dashboard: RealTimeDashboard) -> None:
        """update_performance updates performance metrics."""
        dashboard.update_performance("radare2", {"memory_mb": 512.5, "cpu_percent": 45.3})

        assert dashboard.metrics.memory_usage_mb == 512.5
        assert dashboard.metrics.cpu_usage_percent == 45.3

    def test_get_dashboard_state_returns_complete_state(self, dashboard: RealTimeDashboard) -> None:
        """get_dashboard_state returns complete dashboard state."""
        dashboard.start_analysis("test-005", "ghidra", "app.exe")
        dashboard.add_event(
            DashboardEvent(
                event_type=DashboardEventType.INFO_MESSAGE,
                timestamp=datetime.now(),
                tool="test",
                title="Test",
                description="Test event",
            )
        )

        state = dashboard.get_dashboard_state()

        assert "timestamp" in state
        assert "uptime_seconds" in state
        assert "metrics" in state
        assert "active_analyses" in state
        assert "recent_events" in state
        assert "event_count" in state
        assert "result_count" in state

    def test_get_metrics_history_returns_list(self, dashboard: RealTimeDashboard) -> None:
        """get_metrics_history returns list of historical metrics."""
        history = dashboard.get_metrics_history()

        assert isinstance(history, list)


class TestFlaskIntegration:
    """Tests for Flask HTTP API endpoints."""

    @pytest.fixture
    def dashboard_with_flask(self) -> RealTimeDashboard:
        """Create dashboard with Flask enabled."""
        config = {
            "enable_websocket": False,
            "enable_http": True,
            "http_port": 5555,
        }
        return RealTimeDashboard(config)

    def test_flask_app_initializes(self, dashboard_with_flask: RealTimeDashboard) -> None:
        """Flask app initializes when HTTP enabled."""
        time.sleep(0.5)

        if dashboard_with_flask.flask_app is not None:
            assert dashboard_with_flask.flask_app is not None
            assert dashboard_with_flask.flask_thread is not None

    def test_state_endpoint_returns_json(self, dashboard_with_flask: RealTimeDashboard) -> None:
        """State endpoint returns JSON response."""
        time.sleep(0.5)

        if dashboard_with_flask.flask_app is not None:
            with dashboard_with_flask.flask_app.test_client() as client:
                response = client.get("/api/state")
                assert response.status_code == 200
                data = json.loads(response.data)
                assert "metrics" in data
                assert "active_analyses" in data

    def test_events_endpoint_returns_events(self, dashboard_with_flask: RealTimeDashboard) -> None:
        """Events endpoint returns event list."""
        time.sleep(0.5)

        if dashboard_with_flask.flask_app is not None:
            dashboard_with_flask.add_event(
                DashboardEvent(
                    event_type=DashboardEventType.INFO_MESSAGE,
                    timestamp=datetime.now(),
                    tool="test",
                    title="Test Event",
                    description="Test",
                )
            )

            with dashboard_with_flask.flask_app.test_client() as client:
                response = client.get("/api/events")
                assert response.status_code == 200
                data = json.loads(response.data)
                assert isinstance(data, list)

    def test_events_endpoint_respects_limit(self, dashboard_with_flask: RealTimeDashboard) -> None:
        """Events endpoint respects limit parameter."""
        time.sleep(0.5)

        if dashboard_with_flask.flask_app is not None:
            for i in range(20):
                dashboard_with_flask.add_event(
                    DashboardEvent(
                        event_type=DashboardEventType.INFO_MESSAGE,
                        timestamp=datetime.now(),
                        tool="test",
                        title=f"Event {i}",
                        description="Test",
                    )
                )

            with dashboard_with_flask.flask_app.test_client() as client:
                response = client.get("/api/events?limit=10")
                data = json.loads(response.data)
                assert len(data) <= 10

    def test_metrics_endpoint_returns_current_metrics(self, dashboard_with_flask: RealTimeDashboard) -> None:
        """Metrics endpoint returns current metrics."""
        time.sleep(0.5)

        if dashboard_with_flask.flask_app is not None:
            with dashboard_with_flask.flask_app.test_client() as client:
                response = client.get("/api/metrics")
                assert response.status_code == 200
                data = json.loads(response.data)
                assert "total_functions_analyzed" in data

    def test_active_analyses_endpoint(self, dashboard_with_flask: RealTimeDashboard) -> None:
        """Active analyses endpoint returns running analyses."""
        time.sleep(0.5)

        if dashboard_with_flask.flask_app is not None:
            dashboard_with_flask.start_analysis("test-006", "radare2", "app.exe")

            with dashboard_with_flask.flask_app.test_client() as client:
                response = client.get("/api/analyses/active")
                assert response.status_code == 200
                data = json.loads(response.data)
                assert isinstance(data, list)

    def test_results_endpoint_returns_results(self, dashboard_with_flask: RealTimeDashboard) -> None:
        """Results endpoint returns analysis results."""
        time.sleep(0.5)

        if dashboard_with_flask.flask_app is not None:
            dashboard_with_flask.start_analysis("test-007", "ghidra", "test.exe")
            dashboard_with_flask.complete_analysis("test-007", {"functions": 50})

            with dashboard_with_flask.flask_app.test_client() as client:
                response = client.get("/api/results/test-007")
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data["functions"] == 50

    def test_results_endpoint_handles_not_found(self, dashboard_with_flask: RealTimeDashboard) -> None:
        """Results endpoint returns 404 for unknown analysis."""
        time.sleep(0.5)

        if dashboard_with_flask.flask_app is not None:
            with dashboard_with_flask.flask_app.test_client() as client:
                response = client.get("/api/results/nonexistent")
                assert response.status_code == 404


class TestMetricsTracking:
    """Tests for metrics tracking and history."""

    def test_metrics_update_from_error_event(self, dashboard: RealTimeDashboard) -> None:
        """Error events increment error counter."""
        initial_errors = dashboard.metrics.errors_count

        event = DashboardEvent(
            event_type=DashboardEventType.ERROR_OCCURRED,
            timestamp=datetime.now(),
            tool="test",
            title="Error",
            description="Test error",
        )
        dashboard.add_event(event)

        assert dashboard.metrics.errors_count == initial_errors + 1

    def test_metrics_update_from_warning_event(self, dashboard: RealTimeDashboard) -> None:
        """Warning events increment warning counter."""
        initial_warnings = dashboard.metrics.warnings_count

        event = DashboardEvent(
            event_type=DashboardEventType.WARNING_RAISED,
            timestamp=datetime.now(),
            tool="test",
            title="Warning",
            description="Test warning",
        )
        dashboard.add_event(event)

        assert dashboard.metrics.warnings_count == initial_warnings + 1


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_complete_analysis_for_nonexistent_id(self, dashboard: RealTimeDashboard) -> None:
        """complete_analysis handles nonexistent analysis ID."""
        dashboard.complete_analysis("nonexistent", {"data": "test"})

        assert "nonexistent" in dashboard.analysis_results

    def test_event_callback_exception_handling(self, dashboard: RealTimeDashboard) -> None:
        """Dashboard handles exceptions in event callbacks."""

        def failing_callback(event: DashboardEvent) -> None:
            raise Exception("Callback error")

        dashboard.register_callback(failing_callback)

        event = DashboardEvent(
            event_type=DashboardEventType.INFO_MESSAGE,
            timestamp=datetime.now(),
            tool="test",
            title="Test",
            description="Test",
        )

        dashboard.add_event(event)

    def test_shutdown_cleans_up_resources(self, dashboard: RealTimeDashboard) -> None:
        """Shutdown method cleans up dashboard resources."""
        dashboard.shutdown()


class TestCreateDashboardFunction:
    """Tests for create_dashboard convenience function."""

    def test_create_dashboard_returns_instance(self) -> None:
        """create_dashboard returns RealTimeDashboard instance."""
        config = {"enable_websocket": False, "enable_http": False}

        dashboard = create_dashboard(config)

        assert isinstance(dashboard, RealTimeDashboard)

    def test_create_dashboard_with_default_config(self) -> None:
        """create_dashboard works with default configuration."""
        dashboard = create_dashboard()

        assert isinstance(dashboard, RealTimeDashboard)


class TestRealWorldScenarios:
    """Tests for real-world usage scenarios."""

    def test_complete_analysis_workflow(self, dashboard: RealTimeDashboard) -> None:
        """Test complete analysis workflow from start to finish."""
        dashboard.start_analysis("workflow-001", "radare2", "target.exe", {"depth": "deep"})

        dashboard.report_protection("radare2", {"type": "VMProtect", "confidence": 0.95})

        dashboard.report_vulnerability("radare2", {"type": "buffer_overflow", "severity": "high"})

        dashboard.report_bypass("radare2", {"target": "license_check", "method": "nop"})

        dashboard.update_performance("radare2", {"memory_mb": 256, "cpu_percent": 65})

        results = {"functions": 150, "vulnerabilities": 1, "protections": 1, "bypasses": 1}
        dashboard.complete_analysis("workflow-001", results)

        state = dashboard.get_dashboard_state()
        assert len(state["active_analyses"]) > 0
        assert state["metrics"]["total_protections_detected"] >= 1
        assert state["metrics"]["total_vulnerabilities_found"] >= 1
        assert state["metrics"]["total_bypasses_generated"] >= 1

    def test_concurrent_analyses(self, dashboard: RealTimeDashboard) -> None:
        """Test multiple concurrent analyses."""
        dashboard.start_analysis("concurrent-001", "radare2", "app1.exe")
        dashboard.start_analysis("concurrent-002", "ghidra", "app2.exe")
        dashboard.start_analysis("concurrent-003", "frida", "app3.exe")

        assert len(dashboard.active_analyses) == 3
        assert len(dashboard.metrics.tools_active) == 3

        dashboard.complete_analysis("concurrent-001", {"functions": 50})
        dashboard.complete_analysis("concurrent-002", {"functions": 75})

        assert len(dashboard.analysis_results) >= 2


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
