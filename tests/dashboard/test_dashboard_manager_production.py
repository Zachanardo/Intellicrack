"""Production tests for DashboardManager.

This test suite validates the DashboardManager's ability to orchestrate
real-time analysis dashboards, coordinate data sources, manage widgets,
and integrate with analysis tools for Intellicrack.
"""

import json
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from intellicrack.dashboard.dashboard_manager import (
    DashboardLayout,
    DashboardManager,
    DataSource,
    DataSourceType,
    create_dashboard_manager,
)
from intellicrack.dashboard.dashboard_widgets import WidgetType, create_widget
from intellicrack.dashboard.real_time_dashboard import DashboardEvent, DashboardEventType


class MockToolHandler:
    """Mock tool handler for testing integration."""

    def __init__(self) -> None:
        """Initialize mock tool handler."""
        self.metrics: dict[str, Any] = {
            "functions_analyzed": 150,
            "vulnerabilities_found": 5,
            "analysis_time": 45.2,
        }
        self.status: dict[str, Any] = {"active": True, "progress": 75}

    def get_metrics(self) -> dict[str, Any]:
        """Get tool metrics.

        Returns:
            dict[str, Any]: Tool metrics
        """
        return self.metrics

    def get_status(self) -> dict[str, Any]:
        """Get tool status.

        Returns:
            dict[str, Any]: Tool status
        """
        return self.status


@pytest.fixture
def dashboard_config() -> dict[str, Any]:
    """Create dashboard configuration for testing.

    Returns:
        dict[str, Any]: Dashboard configuration
    """
    return {
        "dashboard_config": {
            "http_port": 5001,
            "websocket_port": 8766,
            "update_interval": 0.1,
        }
    }


@pytest.fixture
def dashboard_manager(dashboard_config: dict[str, Any]) -> DashboardManager:
    """Create dashboard manager for testing.

    Args:
        dashboard_config: Dashboard configuration

    Returns:
        DashboardManager: Initialized dashboard manager
    """
    manager = create_dashboard_manager(dashboard_config)
    yield manager
    manager.stop()


class TestDashboardManagerInitialization:
    """Tests for DashboardManager initialization."""

    def test_initialization_creates_core_components(self, dashboard_config: dict[str, Any]) -> None:
        """DashboardManager initializes with all core components."""
        manager = DashboardManager(dashboard_config)

        assert manager.dashboard is not None
        assert isinstance(manager.widgets, dict)
        assert isinstance(manager.data_sources, dict)
        assert isinstance(manager.layouts, dict)
        assert isinstance(manager.active_analyses, set)

        manager.stop()

    def test_initialization_creates_default_layout(self, dashboard_manager: DashboardManager) -> None:
        """DashboardManager creates default layout on initialization."""
        assert "default" in dashboard_manager.layouts
        assert dashboard_manager.current_layout is not None
        assert dashboard_manager.current_layout.layout_id == "default"
        assert dashboard_manager.current_layout.rows == 3
        assert dashboard_manager.current_layout.columns == 4

    def test_initialization_creates_default_widgets(self, dashboard_manager: DashboardManager) -> None:
        """DashboardManager creates default widgets on initialization."""
        expected_widgets = [
            "performance_gauge",
            "memory_gauge",
            "timeline",
            "vulnerabilities_table",
            "protections_table",
            "analysis_progress",
            "functions_chart",
            "call_graph",
            "complexity_heatmap",
        ]

        for widget_id in expected_widgets:
            assert widget_id in dashboard_manager.widgets
            assert dashboard_manager.widgets[widget_id].config.widget_id == widget_id

    def test_initialization_creates_default_data_sources(self, dashboard_manager: DashboardManager) -> None:
        """DashboardManager creates default data sources on initialization."""
        assert "performance" in dashboard_manager.data_sources
        assert "system" in dashboard_manager.data_sources

        performance_source = dashboard_manager.data_sources["performance"]
        assert performance_source.source_type == DataSourceType.PERFORMANCE
        assert performance_source.poll_interval == 2.0

        system_source = dashboard_manager.data_sources["system"]
        assert system_source.source_type == DataSourceType.SYSTEM
        assert system_source.poll_interval == 5.0

    def test_initialization_sets_widget_subscriptions(self, dashboard_manager: DashboardManager) -> None:
        """DashboardManager sets up widget subscriptions on initialization."""
        assert "performance" in dashboard_manager.widget_subscriptions
        subscribed_widgets = dashboard_manager.widget_subscriptions["performance"]

        assert "performance_gauge" in subscribed_widgets
        assert "memory_gauge" in subscribed_widgets
        assert "functions_chart" in subscribed_widgets

    def test_factory_function_creates_manager(self, dashboard_config: dict[str, Any]) -> None:
        """create_dashboard_manager factory function creates DashboardManager."""
        manager = create_dashboard_manager(dashboard_config)

        assert isinstance(manager, DashboardManager)
        assert manager.config == dashboard_config

        manager.stop()


class TestWidgetManagement:
    """Tests for widget management functionality."""

    def test_add_widget_registers_widget(self, dashboard_manager: DashboardManager) -> None:
        """add_widget successfully registers new widget."""
        custom_widget = create_widget(
            "custom_gauge",
            WidgetType.GAUGE,
            "Custom Metric",
            min=0,
            max=100,
        )

        dashboard_manager.add_widget(custom_widget)

        assert "custom_gauge" in dashboard_manager.widgets
        assert dashboard_manager.widgets["custom_gauge"] == custom_widget

    def test_add_multiple_widgets(self, dashboard_manager: DashboardManager) -> None:
        """Adding multiple widgets maintains all registrations."""
        initial_count = len(dashboard_manager.widgets)

        widget1 = create_widget("test_chart1", WidgetType.LINE_CHART, "Chart 1")
        widget2 = create_widget("test_chart2", WidgetType.BAR_CHART, "Chart 2")
        widget3 = create_widget("test_table", WidgetType.TABLE, "Table")

        dashboard_manager.add_widget(widget1)
        dashboard_manager.add_widget(widget2)
        dashboard_manager.add_widget(widget3)

        assert len(dashboard_manager.widgets) == initial_count + 3
        assert "test_chart1" in dashboard_manager.widgets
        assert "test_chart2" in dashboard_manager.widgets
        assert "test_table" in dashboard_manager.widgets


class TestDataSourceManagement:
    """Tests for data source management functionality."""

    def test_add_data_source_registers_source(self, dashboard_manager: DashboardManager) -> None:
        """add_data_source successfully registers new data source."""
        source = DataSource(
            source_id="ghidra_analysis",
            source_type=DataSourceType.GHIDRA,
            name="Ghidra Analysis Data",
            poll_interval=3.0,
        )

        dashboard_manager.add_data_source(source)

        assert "ghidra_analysis" in dashboard_manager.data_sources
        assert dashboard_manager.data_sources["ghidra_analysis"] == source

    def test_data_source_with_callback(self, dashboard_manager: DashboardManager) -> None:
        """Data source with callback is registered correctly."""
        callback_invoked = False

        def test_callback() -> dict[str, Any]:
            nonlocal callback_invoked
            callback_invoked = True
            return {"test": "data"}

        source = DataSource(
            source_id="test_source",
            source_type=DataSourceType.CUSTOM,
            name="Test Source",
            data_callback=test_callback,
        )

        dashboard_manager.add_data_source(source)

        result = source.data_callback()

        assert callback_invoked
        assert result == {"test": "data"}


class TestLayoutManagement:
    """Tests for layout management functionality."""

    def test_add_layout_registers_layout(self, dashboard_manager: DashboardManager) -> None:
        """add_layout successfully registers new layout."""
        custom_layout = DashboardLayout(
            layout_id="custom",
            name="Custom Layout",
            rows=2,
            columns=3,
        )

        dashboard_manager.add_layout(custom_layout)

        assert "custom" in dashboard_manager.layouts
        assert dashboard_manager.layouts["custom"] == custom_layout

    def test_set_layout_changes_current_layout(self, dashboard_manager: DashboardManager) -> None:
        """set_layout successfully changes current layout."""
        custom_layout = DashboardLayout(
            layout_id="custom",
            name="Custom Layout",
            rows=2,
            columns=3,
        )

        dashboard_manager.add_layout(custom_layout)
        dashboard_manager.set_layout("custom")

        assert dashboard_manager.current_layout == custom_layout
        assert dashboard_manager.current_layout.layout_id == "custom"

    def test_set_layout_with_invalid_id(self, dashboard_manager: DashboardManager) -> None:
        """set_layout handles invalid layout ID gracefully."""
        original_layout = dashboard_manager.current_layout

        dashboard_manager.set_layout("nonexistent_layout")

        assert dashboard_manager.current_layout == original_layout


class TestWidgetSubscriptions:
    """Tests for widget subscription functionality."""

    def test_subscribe_widget_creates_subscription(self, dashboard_manager: DashboardManager) -> None:
        """subscribe_widget creates subscription between widget and source."""
        widget = create_widget("test_widget", WidgetType.GAUGE, "Test")
        source = DataSource(
            source_id="test_source",
            source_type=DataSourceType.CUSTOM,
            name="Test",
        )

        dashboard_manager.add_widget(widget)
        dashboard_manager.add_data_source(source)
        dashboard_manager.subscribe_widget("test_widget", "test_source")

        assert "test_widget" in dashboard_manager.widget_subscriptions["test_source"]
        assert "test_source" in dashboard_manager.source_subscriptions["test_widget"]

    def test_multiple_widgets_subscribe_to_source(self, dashboard_manager: DashboardManager) -> None:
        """Multiple widgets can subscribe to same data source."""
        widget1 = create_widget("widget1", WidgetType.GAUGE, "Widget 1")
        widget2 = create_widget("widget2", WidgetType.GAUGE, "Widget 2")
        source = DataSource(
            source_id="shared_source",
            source_type=DataSourceType.CUSTOM,
            name="Shared",
        )

        dashboard_manager.add_widget(widget1)
        dashboard_manager.add_widget(widget2)
        dashboard_manager.add_data_source(source)

        dashboard_manager.subscribe_widget("widget1", "shared_source")
        dashboard_manager.subscribe_widget("widget2", "shared_source")

        subscribed_widgets = dashboard_manager.widget_subscriptions["shared_source"]
        assert "widget1" in subscribed_widgets
        assert "widget2" in subscribed_widgets


class TestToolIntegration:
    """Tests for tool integration functionality."""

    def test_integrate_tool_creates_handler(self, dashboard_manager: DashboardManager) -> None:
        """integrate_tool registers tool handler."""
        handler = MockToolHandler()

        dashboard_manager.integrate_tool("ghidra", handler)

        assert "ghidra" in dashboard_manager.tool_handlers
        assert dashboard_manager.tool_handlers["ghidra"] == handler

    def test_integrate_tool_creates_data_source(self, dashboard_manager: DashboardManager) -> None:
        """integrate_tool creates corresponding data source."""
        handler = MockToolHandler()

        dashboard_manager.integrate_tool("frida", handler)

        assert "frida_source" in dashboard_manager.data_sources
        source = dashboard_manager.data_sources["frida_source"]
        assert source.source_type == DataSourceType.CUSTOM
        assert source.poll_interval == 3.0

    def test_collect_tool_data_calls_handler(self, dashboard_manager: DashboardManager) -> None:
        """Tool data collection invokes handler methods."""
        handler = MockToolHandler()
        dashboard_manager.integrate_tool("test_tool", handler)

        data = dashboard_manager._collect_tool_data("test_tool")

        assert data == handler.metrics
        assert data["functions_analyzed"] == 150
        assert data["vulnerabilities_found"] == 5


class TestAnalysisEventProcessing:
    """Tests for analysis event processing functionality."""

    def test_process_vulnerability_event(self, dashboard_manager: DashboardManager) -> None:
        """process_analysis_event handles vulnerability events correctly."""
        event_data = {
            "title": "License Bypass Found",
            "description": "Trial reset vulnerability detected",
            "type": "license_bypass",
            "severity": "high",
            "location": "0x401234",
        }

        dashboard_manager.process_analysis_event("vulnerability", "ghidra", event_data)

        events = dashboard_manager.dashboard.get_events()
        assert len(events) > 0

        latest_event = events[-1]
        assert latest_event.event_type == DashboardEventType.VULNERABILITY_FOUND
        assert latest_event.tool == "ghidra"
        assert latest_event.severity == "high"

    def test_process_protection_event(self, dashboard_manager: DashboardManager) -> None:
        """process_analysis_event handles protection detection events."""
        event_data = {
            "title": "VMProtect Detected",
            "description": "VMProtect 3.5 protection identified",
            "type": "vmprotect",
            "strength": "high",
            "severity": "info",
        }

        dashboard_manager.process_analysis_event("protection", "radare2", event_data)

        events = dashboard_manager.dashboard.get_events()
        latest_event = events[-1]
        assert latest_event.event_type == DashboardEventType.PROTECTION_DETECTED
        assert latest_event.tool == "radare2"

    def test_process_error_event(self, dashboard_manager: DashboardManager) -> None:
        """process_analysis_event handles error events."""
        event_data = {
            "title": "Analysis Failed",
            "description": "Unable to parse binary format",
            "severity": "error",
        }

        dashboard_manager.process_analysis_event("error", "lief", event_data)

        events = dashboard_manager.dashboard.get_events()
        latest_event = events[-1]
        assert latest_event.event_type == DashboardEventType.ERROR_OCCURRED

    def test_vulnerability_event_updates_table(self, dashboard_manager: DashboardManager) -> None:
        """Vulnerability events update vulnerabilities table widget."""
        event_data = {
            "title": "Keygen Vulnerability",
            "description": "Serial validation can be bypassed",
            "type": "serial_bypass",
            "location": "0x405678",
            "severity": "critical",
        }

        dashboard_manager.process_analysis_event("vulnerability", "frida", event_data)

        vuln_widget = dashboard_manager.widgets["vulnerabilities_table"]
        current_data = vuln_widget.get_current_data()

        if current_data and current_data.values:
            rows = current_data.values.get("rows", [])
            assert len(rows) > 0
            latest_row = rows[-1]
            assert latest_row["Type"] == "serial_bypass"
            assert latest_row["Severity"] == "critical"
            assert latest_row["Tool"] == "frida"


class TestStartStopLifecycle:
    """Tests for dashboard manager start/stop lifecycle."""

    def test_start_initializes_polling_thread(self, dashboard_manager: DashboardManager) -> None:
        """start() initializes polling thread."""
        dashboard_manager.start()
        time.sleep(0.1)

        assert dashboard_manager.polling_thread is not None
        assert dashboard_manager.polling_thread.is_alive()
        assert not dashboard_manager.stop_polling.is_set()

    def test_stop_terminates_polling_thread(self, dashboard_manager: DashboardManager) -> None:
        """stop() terminates polling thread cleanly."""
        dashboard_manager.start()
        time.sleep(0.1)

        dashboard_manager.stop()

        assert dashboard_manager.stop_polling.is_set()

    def test_multiple_start_stop_cycles(self, dashboard_config: dict[str, Any]) -> None:
        """Dashboard manager handles multiple start/stop cycles."""
        manager = DashboardManager(dashboard_config)

        for _ in range(3):
            manager.start()
            time.sleep(0.1)
            assert manager.polling_thread is not None
            assert manager.polling_thread.is_alive()

            manager.stop()
            assert manager.stop_polling.is_set()

            manager.stop_polling.clear()


class TestDataPollingAndDistribution:
    """Tests for data polling and distribution functionality."""

    def test_polling_invokes_data_callbacks(self, dashboard_config: dict[str, Any]) -> None:
        """Polling loop invokes data source callbacks."""
        callback_count = 0

        def test_callback() -> dict[str, Any]:
            nonlocal callback_count
            callback_count += 1
            return {"value": callback_count}

        manager = DashboardManager(dashboard_config)
        source = DataSource(
            source_id="test_poll",
            source_type=DataSourceType.CUSTOM,
            name="Test Poll",
            poll_interval=0.1,
            data_callback=test_callback,
        )

        manager.add_data_source(source)
        manager.start()
        time.sleep(0.35)
        manager.stop()

        assert callback_count >= 2

    def test_data_distribution_to_subscribed_widgets(self, dashboard_config: dict[str, Any]) -> None:
        """Data is distributed to subscribed widgets."""
        manager = DashboardManager(dashboard_config)

        widget = create_widget("test_widget", WidgetType.GAUGE, "Test", min=0, max=100)
        manager.add_widget(widget)

        source = DataSource(
            source_id="test_dist",
            source_type=DataSourceType.CUSTOM,
            name="Test Distribution",
            data_callback=lambda: {"value": 42},
            poll_interval=0.1,
        )
        manager.add_data_source(source)
        manager.subscribe_widget("test_widget", "test_dist")

        manager.start()
        time.sleep(0.25)
        manager.stop()

        current_data = widget.get_current_data()
        assert current_data is not None
        assert "value" in current_data.values
        assert current_data.values["value"] == 42

    def test_disabled_source_not_polled(self, dashboard_config: dict[str, Any]) -> None:
        """Disabled data sources are not polled."""
        callback_count = 0

        def test_callback() -> dict[str, Any]:
            nonlocal callback_count
            callback_count += 1
            return {"value": 1}

        manager = DashboardManager(dashboard_config)
        source = DataSource(
            source_id="disabled_source",
            source_type=DataSourceType.CUSTOM,
            name="Disabled",
            poll_interval=0.1,
            enabled=False,
            data_callback=test_callback,
        )

        manager.add_data_source(source)
        manager.start()
        time.sleep(0.3)
        manager.stop()

        assert callback_count == 0


class TestURLGeneration:
    """Tests for URL generation functionality."""

    def test_get_dashboard_url(self, dashboard_manager: DashboardManager) -> None:
        """get_dashboard_url returns correct HTTP URL."""
        url = dashboard_manager.get_dashboard_url()

        assert url == "http://localhost:5001"

    def test_get_websocket_url(self, dashboard_manager: DashboardManager) -> None:
        """get_websocket_url returns correct WebSocket URL."""
        url = dashboard_manager.get_websocket_url()

        assert url == "ws://localhost:8766"

    def test_default_urls(self) -> None:
        """URLs use default ports when not configured."""
        manager = DashboardManager()

        dashboard_url = manager.get_dashboard_url()
        ws_url = manager.get_websocket_url()

        assert dashboard_url == "http://localhost:5000"
        assert ws_url == "ws://localhost:8765"

        manager.stop()


class TestStateExport:
    """Tests for dashboard state export functionality."""

    def test_export_dashboard_state(self, dashboard_manager: DashboardManager) -> None:
        """export_dashboard_state creates valid JSON file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            export_path = Path(tmpdir) / "dashboard_state.json"

            dashboard_manager.export_dashboard_state(str(export_path))

            assert export_path.exists()

            with open(export_path) as f:
                state = json.load(f)

            assert "timestamp" in state
            assert "dashboard_state" in state
            assert "widgets" in state
            assert "layouts" in state
            assert "current_layout" in state

    def test_export_includes_widget_data(self, dashboard_manager: DashboardManager) -> None:
        """Exported state includes widget configurations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            export_path = Path(tmpdir) / "state.json"

            dashboard_manager.export_dashboard_state(str(export_path))

            with open(export_path) as f:
                state = json.load(f)

            widgets = state["widgets"]
            assert "performance_gauge" in widgets
            assert "timeline" in widgets

    def test_export_includes_layout_data(self, dashboard_manager: DashboardManager) -> None:
        """Exported state includes layout configurations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            export_path = Path(tmpdir) / "state.json"

            dashboard_manager.export_dashboard_state(str(export_path))

            with open(export_path) as f:
                state = json.load(f)

            layouts = state["layouts"]
            assert "default" in layouts
            assert layouts["default"]["rows"] == 3
            assert layouts["default"]["columns"] == 4

    def test_export_includes_current_layout(self, dashboard_manager: DashboardManager) -> None:
        """Exported state includes current layout identifier."""
        with tempfile.TemporaryDirectory() as tmpdir:
            export_path = Path(tmpdir) / "state.json"

            dashboard_manager.export_dashboard_state(str(export_path))

            with open(export_path) as f:
                state = json.load(f)

            assert state["current_layout"] == "default"


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_widget_updates(self, dashboard_config: dict[str, Any]) -> None:
        """Concurrent widget updates are handled safely."""
        manager = DashboardManager(dashboard_config)
        widget = create_widget("concurrent_test", WidgetType.GAUGE, "Test", min=0, max=100)
        manager.add_widget(widget)

        def update_widget() -> None:
            for i in range(10):
                from intellicrack.dashboard.dashboard_widgets import WidgetData

                data = WidgetData(timestamp=datetime.now(), values={"value": i})
                widget.update_data(data)
                time.sleep(0.01)

        threads = [threading.Thread(target=update_widget) for _ in range(3)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        manager.stop()

    def test_concurrent_event_processing(self, dashboard_config: dict[str, Any]) -> None:
        """Concurrent event processing is handled safely."""
        manager = DashboardManager(dashboard_config)
        manager.start()

        def process_events() -> None:
            for i in range(5):
                manager.process_analysis_event(
                    "vulnerability",
                    "test_tool",
                    {
                        "title": f"Vuln {i}",
                        "description": "Test",
                        "severity": "medium",
                    },
                )
                time.sleep(0.01)

        threads = [threading.Thread(target=process_events) for _ in range(3)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        manager.stop()


class TestEdgeCases:
    """Edge case tests for DashboardManager."""

    def test_collect_performance_data_without_metrics(self, dashboard_manager: DashboardManager) -> None:
        """_collect_performance_data handles missing metrics gracefully."""
        data = dashboard_manager._collect_performance_data()

        assert isinstance(data, dict)
        assert "cpu_percent" in data
        assert "memory_mb" in data

    def test_collect_system_data_success(self, dashboard_manager: DashboardManager) -> None:
        """_collect_system_data successfully collects system metrics."""
        data = dashboard_manager._collect_system_data()

        assert isinstance(data, dict)

    def test_collect_tool_data_missing_handler(self, dashboard_manager: DashboardManager) -> None:
        """_collect_tool_data handles missing handler gracefully."""
        data = dashboard_manager._collect_tool_data("nonexistent_tool")

        assert data == {}

    def test_handle_dashboard_event_logs_errors(
        self, dashboard_manager: DashboardManager, caplog: pytest.LogCaptureFixture
    ) -> None:
        """_handle_dashboard_event logs error events."""
        import logging

        event = DashboardEvent(
            event_type=DashboardEventType.ERROR_OCCURRED,
            timestamp=datetime.now(),
            tool="test",
            title="Test Error",
            description="Error description",
            severity="error",
        )

        with caplog.at_level(logging.ERROR):
            dashboard_manager._handle_dashboard_event(event)

        assert len(caplog.records) > 0
        assert any("Test Error" in record.message for record in caplog.records)
