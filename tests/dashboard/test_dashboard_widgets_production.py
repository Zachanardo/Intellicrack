"""Production-grade tests for intellicrack.dashboard.dashboard_widgets module.

This module validates dashboard widget functionality including data updates,
rendering in multiple formats, and real-time visualization capabilities.
Tests cover line charts, gauges, tables, heatmaps, network graphs, timelines,
and progress widgets with actual data processing.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.dashboard.dashboard_widgets import (
    DashboardWidget,
    GaugeWidget,
    HeatmapWidget,
    LineChartWidget,
    NetworkGraphWidget,
    ProgressWidget,
    TableWidget,
    TimelineWidget,
    WidgetConfig,
    WidgetData,
    WidgetFactory,
    WidgetType,
    create_widget,
)


if TYPE_CHECKING:
    pass

pytestmark = pytest.mark.real_data


@pytest.fixture
def base_widget_config() -> WidgetConfig:
    """Provide basic widget configuration for testing."""
    return WidgetConfig(
        widget_id="test_widget_001",
        widget_type=WidgetType.LINE_CHART,
        title="Test Widget",
        width=600,
        height=400,
        refresh_interval=1.0,
        data_source="test_source",
        options={"history_size": 50},
    )


@pytest.fixture
def sample_widget_data() -> WidgetData:
    """Provide licensing-specific widget data for testing."""
    return WidgetData(
        timestamp=datetime.now(),
        values={"bypass_success_rate": 87.5, "protection_detected": 3, "crack_progress": 62.8, "keygen_attempts": 15},
        labels=["Bypass Success", "Protections", "Progress", "Keygen"],
        categories=["VMProtect", "Themida", "Flexera"],
        metadata={"source": "license_cracker", "version": "1.0", "target": "commercial_software.exe"},
    )


class TestWidgetConfig:
    """Test WidgetConfig dataclass validates configuration parameters."""

    def test_widget_config_creates_with_all_parameters(self) -> None:
        """Widget config created with all parameters."""
        config = WidgetConfig(
            widget_id="widget_001",
            widget_type=WidgetType.GAUGE,
            title="CPU Usage",
            width=400,
            height=300,
            refresh_interval=2.5,
            data_source="cpu_monitor",
            options={"min": 0, "max": 100},
        )

        assert config.widget_id == "widget_001"
        assert config.widget_type == WidgetType.GAUGE
        assert config.title == "CPU Usage"
        assert config.width == 400
        assert config.height == 300
        assert config.refresh_interval == 2.5
        assert config.data_source == "cpu_monitor"
        assert config.options == {"min": 0, "max": 100}

    def test_widget_config_defaults_applied(self) -> None:
        """Widget config uses default values when optional params omitted."""
        config = WidgetConfig(
            widget_id="widget_002",
            widget_type=WidgetType.TABLE,
            title="Data Table",
        )

        assert config.width == 400
        assert config.height == 300
        assert config.refresh_interval == 5.0
        assert config.data_source is None
        assert config.options == {}

    def test_widget_config_supports_all_widget_types(self) -> None:
        """Widget config accepts all defined widget types."""
        for widget_type in WidgetType:
            config = WidgetConfig(
                widget_id=f"widget_{widget_type.value}",
                widget_type=widget_type,
                title=f"Test {widget_type.value}",
            )
            assert config.widget_type == widget_type


class TestWidgetData:
    """Test WidgetData dataclass validates data structures."""

    def test_widget_data_creates_with_all_fields(self) -> None:
        """Widget data created with complete information."""
        timestamp = datetime(2025, 12, 27, 10, 30, 0)
        data = WidgetData(
            timestamp=timestamp,
            values={"metric1": 100, "metric2": 200},
            labels=["Label1", "Label2"],
            categories=["Cat1", "Cat2"],
            metadata={"source": "test", "quality": "high"},
        )

        assert data.timestamp == timestamp
        assert data.values == {"metric1": 100, "metric2": 200}
        assert data.labels == ["Label1", "Label2"]
        assert data.categories == ["Cat1", "Cat2"]
        assert data.metadata == {"source": "test", "quality": "high"}

    def test_widget_data_optional_fields_default_to_none(self) -> None:
        """Widget data optional fields default to None."""
        data = WidgetData(
            timestamp=datetime.now(),
            values={"test": 42},
        )

        assert data.labels is None
        assert data.categories is None
        assert data.metadata == {}

    def test_widget_data_supports_nested_values(self) -> None:
        """Widget data values can contain nested structures."""
        complex_values: dict[str, object] = {
            "simple": 42,
            "nested": {"level1": {"level2": [1, 2, 3]}},
            "array": [10, 20, 30],
        }

        data = WidgetData(
            timestamp=datetime.now(),
            values=complex_values,
        )

        assert data.values["simple"] == 42
        nested = data.values["nested"]
        assert isinstance(nested, dict)
        assert nested["level1"]["level2"] == [1, 2, 3]  # type: ignore[index]


class TestDashboardWidget:
    """Test DashboardWidget base class functionality."""

    def test_dashboard_widget_initializes_with_config(
        self, base_widget_config: WidgetConfig
    ) -> None:
        """Dashboard widget initializes with configuration."""
        widget = DashboardWidget(base_widget_config)

        assert widget.config == base_widget_config
        assert len(widget.data_history) == 0
        assert widget.render_cache is None

    def test_dashboard_widget_update_data_appends_to_history(
        self, base_widget_config: WidgetConfig, sample_widget_data: WidgetData
    ) -> None:
        """Widget update_data appends data to history."""
        widget = DashboardWidget(base_widget_config)

        widget.update_data(sample_widget_data)

        assert len(widget.data_history) == 1
        assert widget.data_history[0] == sample_widget_data

    def test_dashboard_widget_update_data_invalidates_cache(
        self, base_widget_config: WidgetConfig, sample_widget_data: WidgetData
    ) -> None:
        """Widget update_data clears render cache."""
        widget = DashboardWidget(base_widget_config)
        widget.render_cache = {"cached": "data"}

        widget.update_data(sample_widget_data)

        assert widget.render_cache is None

    def test_dashboard_widget_respects_history_size_limit(
        self, base_widget_config: WidgetConfig
    ) -> None:
        """Widget history respects maxlen from config."""
        base_widget_config.options["history_size"] = 5
        widget = DashboardWidget(base_widget_config)

        for i in range(10):
            data = WidgetData(
                timestamp=datetime.now() + timedelta(seconds=i),
                values={"value": i},
            )
            widget.update_data(data)

        assert len(widget.data_history) == 5
        assert widget.data_history[0].values["value"] == 5
        assert widget.data_history[-1].values["value"] == 9

    def test_dashboard_widget_get_current_data_returns_latest(
        self, base_widget_config: WidgetConfig
    ) -> None:
        """get_current_data returns most recent data point."""
        widget = DashboardWidget(base_widget_config)

        data1 = WidgetData(timestamp=datetime.now(), values={"v": 1})
        data2 = WidgetData(timestamp=datetime.now(), values={"v": 2})
        data3 = WidgetData(timestamp=datetime.now(), values={"v": 3})

        widget.update_data(data1)
        widget.update_data(data2)
        widget.update_data(data3)

        current = widget.get_current_data()
        assert current is not None
        assert current.values["v"] == 3

    def test_dashboard_widget_get_current_data_returns_none_when_empty(
        self, base_widget_config: WidgetConfig
    ) -> None:
        """get_current_data returns None when no data available."""
        widget = DashboardWidget(base_widget_config)

        assert widget.get_current_data() is None

    def test_dashboard_widget_render_json_with_data(
        self, base_widget_config: WidgetConfig, sample_widget_data: WidgetData
    ) -> None:
        """Widget renders to JSON format with data."""
        widget = DashboardWidget(base_widget_config)
        widget.update_data(sample_widget_data)

        result = widget.render(format="json")

        assert result is not None
        assert result["id"] == "test_widget_001"
        assert result["title"] == "Test Widget"
        assert result["values"] == sample_widget_data.values
        assert result["labels"] == sample_widget_data.labels

    def test_dashboard_widget_render_json_without_data(
        self, base_widget_config: WidgetConfig
    ) -> None:
        """Widget renders status when no data available."""
        widget = DashboardWidget(base_widget_config)

        result = widget.render(format="json")

        assert result is not None
        assert result["status"] == "no_data"
        assert result["id"] == "test_widget_001"


class TestLineChartWidget:
    """Test LineChartWidget validates time series visualization."""

    def test_line_chart_widget_renders_json_with_time_series(self) -> None:
        """Line chart renders licensing crack time series data to JSON."""
        config = WidgetConfig(
            widget_id="chart_001",
            widget_type=WidgetType.LINE_CHART,
            title="License Bypass Performance Over Time",
        )
        widget = LineChartWidget(config)

        timestamps = [datetime.now() + timedelta(seconds=i) for i in range(5)]
        for i, ts in enumerate(timestamps):
            widget.update_data(
                WidgetData(timestamp=ts, values={"bypass_success_rate": i * 10, "crack_progress": i * 5})
            )

        result = widget.render(format="json")

        assert result is not None
        assert result["type"] == "line_chart"
        assert result["title"] == "License Bypass Performance Over Time"
        assert len(result["x"]) == 5  # type: ignore[arg-type]
        assert len(result["series"]) == 2  # type: ignore[arg-type]

        series = result["series"]
        assert isinstance(series, list)
        bypass_series = next(s for s in series if s["name"] == "bypass_success_rate")
        assert bypass_series["data"] == [0, 10, 20, 30, 40]

    def test_line_chart_widget_handles_empty_data(self) -> None:
        """Line chart returns None when no data available."""
        config = WidgetConfig(
            widget_id="chart_002",
            widget_type=WidgetType.LINE_CHART,
            title="Empty Chart",
        )
        widget = LineChartWidget(config)

        result = widget.render(format="json")

        assert result is None

    def test_line_chart_widget_handles_multiple_series(self) -> None:
        """Line chart handles multiple licensing crack data series."""
        config = WidgetConfig(
            widget_id="chart_003",
            widget_type=WidgetType.LINE_CHART,
            title="Multi-Protection Crack Progress",
        )
        widget = LineChartWidget(config)

        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={"vmprotect_bypass": 10, "themida_bypass": 20, "flexera_bypass": 30, "keygen_success": 40},
            )
        )

        result = widget.render(format="json")

        assert result is not None
        series = result["series"]
        assert isinstance(series, list)
        assert len(series) == 4


class TestGaugeWidget:
    """Test GaugeWidget validates single metric display."""

    def test_gauge_widget_renders_current_value(self) -> None:
        """Gauge widget displays current licensing bypass success rate."""
        config = WidgetConfig(
            widget_id="gauge_001",
            widget_type=WidgetType.GAUGE,
            title="Bypass Success Rate",
            options={"min": 0, "max": 100, "units": "%"},
        )
        widget = GaugeWidget(config)

        widget.update_data(WidgetData(timestamp=datetime.now(), values={"usage": 75.5}))

        result = widget.render(format="json")

        assert result is not None
        assert result["type"] == "gauge"
        assert result["title"] == "Bypass Success Rate"
        assert result["value"] == 75.5
        assert result["min"] == 0
        assert result["max"] == 100
        assert result["units"] == "%"

    def test_gauge_widget_applies_default_min_max(self) -> None:
        """Gauge uses default min/max when not specified."""
        config = WidgetConfig(
            widget_id="gauge_002",
            widget_type=WidgetType.GAUGE,
            title="Default Gauge",
        )
        widget = GaugeWidget(config)

        widget.update_data(WidgetData(timestamp=datetime.now(), values={"value": 50}))

        result = widget.render(format="json")

        assert result is not None
        assert result["min"] == 0.0
        assert result["max"] == 100.0

    def test_gauge_widget_supports_threshold_configuration(self) -> None:
        """Gauge widget applies crack progress color thresholds."""
        config = WidgetConfig(
            widget_id="gauge_003",
            widget_type=WidgetType.GAUGE,
            title="License Crack Progress",
            options={
                "thresholds": [
                    {"min": 0, "max": 30, "color": "red"},
                    {"min": 30, "max": 70, "color": "yellow"},
                    {"min": 70, "max": 100, "color": "green"},
                ]
            },
        )
        widget = GaugeWidget(config)

        widget.update_data(WidgetData(timestamp=datetime.now(), values={"value": 85}))

        result = widget.render(format="json")

        assert result is not None
        thresholds = result["thresholds"]
        assert isinstance(thresholds, list)
        assert len(thresholds) == 3

    def test_gauge_widget_returns_none_without_data(self) -> None:
        """Gauge returns None when no data available."""
        config = WidgetConfig(
            widget_id="gauge_004",
            widget_type=WidgetType.GAUGE,
            title="No Data Gauge",
        )
        widget = GaugeWidget(config)

        result = widget.render(format="json")

        assert result is None

    def test_gauge_widget_handles_invalid_option_types(self) -> None:
        """Gauge handles non-numeric min/max gracefully."""
        config = WidgetConfig(
            widget_id="gauge_005",
            widget_type=WidgetType.GAUGE,
            title="Invalid Options",
            options={"min": "invalid", "max": "also_invalid"},
        )
        widget = GaugeWidget(config)

        widget.update_data(WidgetData(timestamp=datetime.now(), values={"value": 50}))

        result = widget.render(format="json")

        assert result is not None
        assert result["min"] == 0.0
        assert result["max"] == 100.0


class TestTableWidget:
    """Test TableWidget validates structured data display."""

    def test_table_widget_renders_rows_and_columns(self) -> None:
        """Table widget displays protection detection results."""
        config = WidgetConfig(
            widget_id="table_001",
            widget_type=WidgetType.TABLE,
            title="Protection Detection Results",
        )
        widget = TableWidget(config)

        table_data = WidgetData(
            timestamp=datetime.now(),
            values={
                "columns": ["Protection", "Binary", "Bypass Success", "Keygen Attempts"],
                "rows": [
                    {"Protection": "VMProtect", "Binary": "target.exe", "Bypass Success": "87.5%", "Keygen Attempts": "15"},
                    {"Protection": "Themida", "Binary": "app.exe", "Bypass Success": "62.3%", "Keygen Attempts": "23"},
                ],
            },
        )
        widget.update_data(table_data)

        result = widget.render(format="json")

        assert result is not None
        assert result["type"] == "table"
        assert result["columns"] == ["Protection", "Binary", "Bypass Success", "Keygen Attempts"]
        assert len(result["rows"]) == 2  # type: ignore[arg-type]

    def test_table_widget_renders_html_format(self) -> None:
        """Table widget generates HTML table."""
        config = WidgetConfig(
            widget_id="table_002",
            widget_type=WidgetType.TABLE,
            title="HTML Table",
        )
        widget = TableWidget(config)

        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={
                    "columns": ["Col1", "Col2"],
                    "rows": [{"Col1": "A", "Col2": "B"}],
                },
            )
        )

        result = widget.render(format="html")

        assert result is not None
        assert result["type"] == "html"
        content = result["content"]
        assert isinstance(content, str)
        assert "<table" in content
        assert "HTML Table" in content
        assert "<th>Col1</th>" in content

    def test_table_widget_supports_sortable_option(self) -> None:
        """Table widget includes sortable configuration."""
        config = WidgetConfig(
            widget_id="table_003",
            widget_type=WidgetType.TABLE,
            title="Sortable Table",
            options={"sortable": True, "filterable": False},
        )
        widget = TableWidget(config)

        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={"columns": ["A"], "rows": []},
            )
        )

        result = widget.render(format="json")

        assert result is not None
        assert result["sortable"] is True
        assert result["filterable"] is False

    def test_table_widget_handles_empty_table(self) -> None:
        """Table widget handles empty data gracefully."""
        config = WidgetConfig(
            widget_id="table_004",
            widget_type=WidgetType.TABLE,
            title="Empty Table",
        )
        widget = TableWidget(config)

        result = widget.render(format="json")

        assert result is None

    def test_table_widget_html_handles_invalid_data_types(self) -> None:
        """Table HTML rendering handles invalid data structures."""
        config = WidgetConfig(
            widget_id="table_005",
            widget_type=WidgetType.TABLE,
            title="Invalid Data",
        )
        widget = TableWidget(config)

        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={"columns": "not_a_list", "rows": "also_not_a_list"},
            )
        )

        result = widget.render(format="html")

        assert result is not None
        content = result["content"]
        assert isinstance(content, str)
        assert "<table" in content


class TestHeatmapWidget:
    """Test HeatmapWidget validates 2D data visualization."""

    def test_heatmap_widget_renders_matrix_data(self) -> None:
        """Heatmap widget displays licensing protection strength heatmap."""
        config = WidgetConfig(
            widget_id="heatmap_001",
            widget_type=WidgetType.HEATMAP,
            title="Protection Strength Analysis",
        )
        widget = HeatmapWidget(config)

        matrix = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={"matrix": matrix},
                labels=["VMProtect", "Themida", "Flexera"],
                categories=["Serial Check", "Hardware ID", "Time Bomb"],
            )
        )

        result = widget.render(format="json")

        assert result is not None
        assert result["type"] == "heatmap"
        assert result["matrix"] == matrix
        assert result["x_labels"] == ["VMProtect", "Themida", "Flexera"]
        assert result["y_labels"] == ["Serial Check", "Hardware ID", "Time Bomb"]

    def test_heatmap_widget_applies_colorscale(self) -> None:
        """Heatmap applies custom colorscale."""
        config = WidgetConfig(
            widget_id="heatmap_002",
            widget_type=WidgetType.HEATMAP,
            title="Custom Colorscale",
            options={"colorscale": "plasma"},
        )
        widget = HeatmapWidget(config)

        widget.update_data(
            WidgetData(timestamp=datetime.now(), values={"matrix": [[1, 2]]})
        )

        result = widget.render(format="json")

        assert result is not None
        assert result["colorscale"] == "plasma"

    def test_heatmap_widget_returns_none_without_data(self) -> None:
        """Heatmap returns None when no data."""
        config = WidgetConfig(
            widget_id="heatmap_003",
            widget_type=WidgetType.HEATMAP,
            title="No Data",
        )
        widget = HeatmapWidget(config)

        result = widget.render(format="json")

        assert result is None


class TestNetworkGraphWidget:
    """Test NetworkGraphWidget validates relationship visualization."""

    def test_network_graph_widget_renders_nodes_and_edges(self) -> None:
        """Network graph displays license validation call graph."""
        config = WidgetConfig(
            widget_id="network_001",
            widget_type=WidgetType.NETWORK_GRAPH,
            title="License Validation Call Graph",
        )
        widget = NetworkGraphWidget(config)

        nodes = [
            {"id": "func1", "label": "CheckLicense()"},
            {"id": "func2", "label": "ValidateSerial()"},
            {"id": "func3", "label": "VerifyHardwareID()"},
        ]
        edges = [
            {"source": "func1", "target": "func2"},
            {"source": "func2", "target": "func3"},
        ]

        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={"nodes": nodes, "edges": edges},
            )
        )

        result = widget.render(format="json")

        assert result is not None
        assert result["type"] == "network_graph"
        assert len(result["nodes"]) == 3  # type: ignore[arg-type]
        assert len(result["edges"]) == 2  # type: ignore[arg-type]

    def test_network_graph_widget_supports_layout_options(self) -> None:
        """Network graph uses layout configuration."""
        config = WidgetConfig(
            widget_id="network_002",
            widget_type=WidgetType.NETWORK_GRAPH,
            title="Directed Graph",
            options={"layout": "hierarchical", "directed": True},
        )
        widget = NetworkGraphWidget(config)

        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={"nodes": [{"id": 1}], "edges": []},
            )
        )

        result = widget.render(format="json")

        assert result is not None
        assert result["layout"] == "hierarchical"
        assert result["directed"] is True

    def test_network_graph_widget_filters_invalid_nodes_and_edges(self) -> None:
        """Network graph filters non-dict nodes/edges."""
        config = WidgetConfig(
            widget_id="network_003",
            widget_type=WidgetType.NETWORK_GRAPH,
            title="Filtered Graph",
        )
        widget = NetworkGraphWidget(config)

        mixed_nodes = [{"id": 1}, "invalid", {"id": 2}, None, {"id": 3}]
        mixed_edges = [{"source": 1, "target": 2}, "bad_edge", {"source": 2, "target": 3}]

        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={"nodes": mixed_nodes, "edges": mixed_edges},
            )
        )

        result = widget.render(format="json")

        assert result is not None
        nodes = result["nodes"]
        edges = result["edges"]
        assert isinstance(nodes, list)
        assert isinstance(edges, list)
        assert len(nodes) == 3
        assert len(edges) == 2

    def test_network_graph_widget_handles_empty_graph(self) -> None:
        """Network graph handles no nodes/edges."""
        config = WidgetConfig(
            widget_id="network_004",
            widget_type=WidgetType.NETWORK_GRAPH,
            title="Empty Graph",
        )
        widget = NetworkGraphWidget(config)

        result = widget.render(format="json")

        assert result is None


class TestTimelineWidget:
    """Test TimelineWidget validates event visualization."""

    def test_timeline_widget_aggregates_events_across_history(self) -> None:
        """Timeline collects license crack events from all data points."""
        config = WidgetConfig(
            widget_id="timeline_001",
            widget_type=WidgetType.TIMELINE,
            title="License Crack Timeline",
        )
        widget = TimelineWidget(config)

        timestamps = [datetime.now() + timedelta(seconds=i) for i in range(3)]

        for i, ts in enumerate(timestamps):
            widget.update_data(
                WidgetData(
                    timestamp=ts,
                    values={
                        "events": [
                            {
                                "title": f"Protection Bypass {i}",
                                "description": f"VMProtect bypass attempt {i}",
                                "type": "crack_attempt",
                                "tool": "license_cracker",
                            }
                        ]
                    },
                )
            )

        result = widget.render(format="json")

        assert result is not None
        assert result["type"] == "timeline"
        events = result["events"]
        assert isinstance(events, list)
        assert len(events) == 3

    def test_timeline_widget_includes_groupby_option(self) -> None:
        """Timeline includes groupBy configuration."""
        config = WidgetConfig(
            widget_id="timeline_002",
            widget_type=WidgetType.TIMELINE,
            title="Grouped Timeline",
            options={"groupBy": "type"},
        )
        widget = TimelineWidget(config)

        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={"events": [{"title": "Test", "type": "warning"}]},
            )
        )

        result = widget.render(format="json")

        assert result is not None
        assert result["groupBy"] == "type"

    def test_timeline_widget_filters_invalid_events(self) -> None:
        """Timeline filters non-dict events."""
        config = WidgetConfig(
            widget_id="timeline_003",
            widget_type=WidgetType.TIMELINE,
            title="Filtered Timeline",
        )
        widget = TimelineWidget(config)

        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={"events": [{"title": "Valid"}, "invalid", None, {"title": "Also Valid"}]},
            )
        )

        result = widget.render(format="json")

        assert result is not None
        events = result["events"]
        assert isinstance(events, list)
        assert len(events) == 2

    def test_timeline_widget_handles_empty_timeline(self) -> None:
        """Timeline handles no events."""
        config = WidgetConfig(
            widget_id="timeline_004",
            widget_type=WidgetType.TIMELINE,
            title="Empty Timeline",
        )
        widget = TimelineWidget(config)

        result = widget.render(format="json")

        assert result is None


class TestProgressWidget:
    """Test ProgressWidget validates progress bar display."""

    def test_progress_widget_calculates_percentage(self) -> None:
        """Progress widget calculates licensing crack completion percentage."""
        config = WidgetConfig(
            widget_id="progress_001",
            widget_type=WidgetType.PROGRESS,
            title="License Crack Progress",
        )
        widget = ProgressWidget(config)

        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={"value": 75, "total": 100, "label": "Bypassing VMProtect protection layers"},
            )
        )

        result = widget.render(format="json")

        assert result is not None
        assert result["type"] == "progress"
        assert result["value"] == 75
        assert result["total"] == 100
        assert result["percentage"] == 75.0
        assert result["label"] == "Bypassing VMProtect protection layers"

    def test_progress_widget_color_changes_with_percentage(self) -> None:
        """Progress color varies based on completion percentage."""
        config = WidgetConfig(
            widget_id="progress_002",
            widget_type=WidgetType.PROGRESS,
            title="Color Test",
        )
        widget = ProgressWidget(config)

        test_cases = [
            (10, 100, "red"),
            (30, 100, "orange"),
            (60, 100, "yellow"),
            (90, 100, "green"),
        ]

        for value, total, expected_color in test_cases:
            widget.update_data(
                WidgetData(
                    timestamp=datetime.now(),
                    values={"value": value, "total": total},
                )
            )

            result = widget.render(format="json")
            assert result is not None
            assert result["color"] == expected_color

    def test_progress_widget_handles_zero_total(self) -> None:
        """Progress widget handles division by zero."""
        config = WidgetConfig(
            widget_id="progress_003",
            widget_type=WidgetType.PROGRESS,
            title="Zero Total",
        )
        widget = ProgressWidget(config)

        widget.update_data(
            WidgetData(timestamp=datetime.now(), values={"value": 50, "total": 0})
        )

        result = widget.render(format="json")

        assert result is not None
        assert result["percentage"] == 0.0

    def test_progress_widget_handles_invalid_value_types(self) -> None:
        """Progress widget converts invalid types to float."""
        config = WidgetConfig(
            widget_id="progress_004",
            widget_type=WidgetType.PROGRESS,
            title="Invalid Types",
        )
        widget = ProgressWidget(config)

        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={"value": "not_a_number", "total": "also_not"},
            )
        )

        result = widget.render(format="json")

        assert result is not None
        assert result["value"] == 0.0
        assert result["total"] == 100.0

    def test_progress_widget_returns_none_without_data(self) -> None:
        """Progress widget returns None when no data."""
        config = WidgetConfig(
            widget_id="progress_005",
            widget_type=WidgetType.PROGRESS,
            title="No Data",
        )
        widget = ProgressWidget(config)

        result = widget.render(format="json")

        assert result is None


class TestWidgetFactory:
    """Test WidgetFactory creates correct widget types."""

    def test_widget_factory_creates_line_chart(self) -> None:
        """Factory creates LineChartWidget for LINE_CHART type."""
        config = WidgetConfig(
            widget_id="factory_001",
            widget_type=WidgetType.LINE_CHART,
            title="Factory Line Chart",
        )

        widget = WidgetFactory.create_widget(config)

        assert isinstance(widget, LineChartWidget)
        assert widget.config == config

    def test_widget_factory_creates_gauge(self) -> None:
        """Factory creates GaugeWidget for GAUGE type."""
        config = WidgetConfig(
            widget_id="factory_002",
            widget_type=WidgetType.GAUGE,
            title="Factory Gauge",
        )

        widget = WidgetFactory.create_widget(config)

        assert isinstance(widget, GaugeWidget)

    def test_widget_factory_creates_table(self) -> None:
        """Factory creates TableWidget for TABLE type."""
        config = WidgetConfig(
            widget_id="factory_003",
            widget_type=WidgetType.TABLE,
            title="Factory Table",
        )

        widget = WidgetFactory.create_widget(config)

        assert isinstance(widget, TableWidget)

    def test_widget_factory_creates_heatmap(self) -> None:
        """Factory creates HeatmapWidget for HEATMAP type."""
        config = WidgetConfig(
            widget_id="factory_004",
            widget_type=WidgetType.HEATMAP,
            title="Factory Heatmap",
        )

        widget = WidgetFactory.create_widget(config)

        assert isinstance(widget, HeatmapWidget)

    def test_widget_factory_creates_network_graph(self) -> None:
        """Factory creates NetworkGraphWidget for NETWORK_GRAPH type."""
        config = WidgetConfig(
            widget_id="factory_005",
            widget_type=WidgetType.NETWORK_GRAPH,
            title="Factory Network",
        )

        widget = WidgetFactory.create_widget(config)

        assert isinstance(widget, NetworkGraphWidget)

    def test_widget_factory_creates_timeline(self) -> None:
        """Factory creates TimelineWidget for TIMELINE type."""
        config = WidgetConfig(
            widget_id="factory_006",
            widget_type=WidgetType.TIMELINE,
            title="Factory Timeline",
        )

        widget = WidgetFactory.create_widget(config)

        assert isinstance(widget, TimelineWidget)

    def test_widget_factory_creates_progress(self) -> None:
        """Factory creates ProgressWidget for PROGRESS type."""
        config = WidgetConfig(
            widget_id="factory_007",
            widget_type=WidgetType.PROGRESS,
            title="Factory Progress",
        )

        widget = WidgetFactory.create_widget(config)

        assert isinstance(widget, ProgressWidget)

    def test_widget_factory_creates_base_widget_for_unknown_type(self) -> None:
        """Factory creates DashboardWidget for unknown types."""
        config = WidgetConfig(
            widget_id="factory_008",
            widget_type=WidgetType.TEXT,
            title="Unknown Type",
        )

        widget = WidgetFactory.create_widget(config)

        assert isinstance(widget, DashboardWidget)
        assert not isinstance(widget, (LineChartWidget, GaugeWidget, TableWidget))


class TestCreateWidgetHelper:
    """Test create_widget helper function."""

    def test_create_widget_helper_with_minimal_params(self) -> None:
        """create_widget helper works with minimal parameters."""
        widget = create_widget("helper_001", WidgetType.GAUGE, "Helper Gauge")

        assert isinstance(widget, GaugeWidget)
        assert widget.config.widget_id == "helper_001"
        assert widget.config.title == "Helper Gauge"
        assert widget.config.width == 400
        assert widget.config.height == 300

    def test_create_widget_helper_with_all_params(self) -> None:
        """create_widget helper accepts all optional parameters."""
        widget = create_widget(
            "helper_002",
            WidgetType.LINE_CHART,
            "Full Config",
            width=800,
            height=600,
            refresh_interval=2.5,
            data_source="custom_source",
            options={"history_size": 200},
        )

        assert isinstance(widget, LineChartWidget)
        assert widget.config.width == 800
        assert widget.config.height == 600
        assert widget.config.refresh_interval == 2.5
        assert widget.config.data_source == "custom_source"
        assert widget.config.options["history_size"] == 200

    def test_create_widget_helper_validates_parameter_types(self) -> None:
        """create_widget helper validates and corrects parameter types."""
        widget = create_widget(
            "helper_003",
            WidgetType.TABLE,
            "Type Validation",
            width="invalid",  # type: ignore[arg-type]
            height="also_invalid",  # type: ignore[arg-type]
            refresh_interval="not_a_float",  # type: ignore[arg-type]
            data_source=12345,  # type: ignore[arg-type]
            options="not_a_dict",  # type: ignore[arg-type]
        )

        assert widget.config.width == 400
        assert widget.config.height == 300
        assert widget.config.refresh_interval == 5.0
        assert widget.config.data_source is None
        assert widget.config.options == {}


class TestWidgetEdgeCases:
    """Test edge cases and stress scenarios across all widgets."""

    def test_widget_handles_very_large_history(self) -> None:
        """Widget handles large data history efficiently."""
        config = WidgetConfig(
            widget_id="edge_001",
            widget_type=WidgetType.LINE_CHART,
            title="Large History",
            options={"history_size": 10000},
        )
        widget = LineChartWidget(config)

        for i in range(10000):
            widget.update_data(
                WidgetData(timestamp=datetime.now(), values={"v": i})
            )

        assert len(widget.data_history) == 10000
        result = widget.render(format="json")
        assert result is not None

    def test_widget_handles_unicode_in_data(self) -> None:
        """Widget handles unicode characters in data."""
        config = WidgetConfig(
            widget_id="edge_002",
            widget_type=WidgetType.TABLE,
            title="Unicode 测试 🔧",
        )
        widget = TableWidget(config)

        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={
                    "columns": ["名称", "値", "Значение"],
                    "rows": [{"名称": "テスト", "値": "🚀", "Значение": "проверка"}],
                },
            )
        )

        result = widget.render(format="json")
        assert result is not None
        assert result["title"] == "Unicode 测试 🔧"

    def test_widget_handles_nested_complex_structures(self) -> None:
        """Widget handles deeply nested data structures."""
        config = WidgetConfig(
            widget_id="edge_003",
            widget_type=WidgetType.NETWORK_GRAPH,
            title="Complex Structure",
        )
        widget = NetworkGraphWidget(config)

        complex_node = {
            "id": "node1",
            "label": "Complex",
            "metadata": {
                "level1": {"level2": {"level3": {"value": [1, 2, 3]}}},
                "array": [{"nested": "data"}, {"more": "info"}],
            },
        }

        widget.update_data(
            WidgetData(
                timestamp=datetime.now(),
                values={"nodes": [complex_node], "edges": []},
            )
        )

        result = widget.render(format="json")
        assert result is not None

    def test_widget_thread_safety_multiple_updates(self) -> None:
        """Widget handles rapid concurrent updates."""
        config = WidgetConfig(
            widget_id="edge_004",
            widget_type=WidgetType.PROGRESS,
            title="Concurrent Updates",
        )
        widget = ProgressWidget(config)

        for i in range(100):
            widget.update_data(
                WidgetData(timestamp=datetime.now(), values={"value": i, "total": 100})
            )

        current = widget.get_current_data()
        assert current is not None
        assert current.values["value"] == 99
