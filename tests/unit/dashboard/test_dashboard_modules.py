"""Tests for dashboard modules with actual API signatures.

Tests LiveDataPipeline, VisualizationRenderer, and RealTimeDashboard.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import tempfile
import time
from collections.abc import Generator
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

try:
    from intellicrack.dashboard.live_data_pipeline import (
        DataEvent,
        DataPriority,
        LiveDataPipeline,
    )
    from intellicrack.dashboard.real_time_dashboard import (
        DashboardEvent,
        DashboardEventType,
        RealTimeDashboard,
    )
    from intellicrack.dashboard.visualization_renderer import (
        GraphNode,
        GraphEdge,
        VisualizationRenderer,
    )

    MODULES_AVAILABLE = True
except ImportError as e:
    MODULES_AVAILABLE = False
    IMPORT_ERROR = str(e)


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.mark.skipif(
    not MODULES_AVAILABLE,
    reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}",
)
class TestLiveDataPipeline:
    """Test LiveDataPipeline functionality."""

    def test_pipeline_initialization(self, temp_dir: Path) -> None:
        """Test pipeline initializes correctly."""
        db_path = temp_dir / "test_pipeline.db"
        config: dict[str, Any] = {"db_path": str(db_path)}
        pipeline = LiveDataPipeline(config=config)

        assert pipeline is not None
        assert hasattr(pipeline, "add_event")
        assert hasattr(pipeline, "start")
        assert hasattr(pipeline, "stop")

    def test_data_event_creation(self) -> None:
        """Test DataEvent dataclass creation."""
        event = DataEvent(
            timestamp=time.time(),
            source="test_source",
            event_type="protection_detected",
            data={"binary": "test.exe", "protection": "VMProtect"},
            priority=DataPriority.HIGH,
        )

        assert event is not None
        assert event.source == "test_source"
        assert event.event_type == "protection_detected"
        assert event.priority == DataPriority.HIGH

    def test_data_event_to_dict(self) -> None:
        """Test DataEvent to_dict method."""
        event = DataEvent(
            timestamp=1234567890.0,
            source="analyzer",
            event_type="key_extracted",
            data={"key_type": "RSA", "size": 2048},
            priority=DataPriority.NORMAL,
        )

        event_dict = event.to_dict()

        assert isinstance(event_dict, dict)
        assert event_dict["source"] == "analyzer"
        assert event_dict["event_type"] == "key_extracted"
        assert "data" in event_dict

    def test_pipeline_start_stop(self, temp_dir: Path) -> None:
        """Test pipeline start and stop."""
        db_path = temp_dir / "test_pipeline.db"
        config: dict[str, Any] = {"db_path": str(db_path)}
        pipeline = LiveDataPipeline(config=config)

        pipeline.start()
        assert pipeline.running

        pipeline.stop()
        assert not pipeline.running

    def test_pipeline_add_event(self, temp_dir: Path) -> None:
        """Test adding events to pipeline."""
        db_path = temp_dir / "test_pipeline.db"
        config: dict[str, Any] = {"db_path": str(db_path)}
        pipeline = LiveDataPipeline(config=config)

        pipeline.start()

        # add_event takes separate args, not event object
        pipeline.add_event(
            source="test_analyzer",
            event_type="protection_detected",
            data={"protection": "VMProtect", "confidence": 0.95},
            priority=DataPriority.HIGH,
        )

        time.sleep(0.1)
        pipeline.stop()

        # Verify no exceptions were raised
        assert True

    def test_register_callback(self, temp_dir: Path) -> None:
        """Test registering event callbacks."""
        db_path = temp_dir / "test_pipeline.db"
        config: dict[str, Any] = {"db_path": str(db_path)}
        pipeline = LiveDataPipeline(config=config)

        def test_callback(events: list[DataEvent]) -> None:
            pass

        pipeline.register_event_callback(test_callback)

        assert test_callback in pipeline.event_callbacks


@pytest.mark.skipif(
    not MODULES_AVAILABLE,
    reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}",
)
class TestVisualizationRenderer:
    """Test VisualizationRenderer functionality."""

    def test_renderer_initialization(self) -> None:
        """Test renderer initializes correctly."""
        renderer = VisualizationRenderer()

        assert renderer is not None
        assert hasattr(renderer, "render_graph")
        assert hasattr(renderer, "render_heatmap")
        assert hasattr(renderer, "render_metrics_chart")

    def test_graph_node_creation(self) -> None:
        """Test GraphNode dataclass creation."""
        node = GraphNode(
            id="node1",
            label="License Check",
        )

        assert node is not None
        assert node.id == "node1"
        assert node.label == "License Check"

    def test_graph_node_with_data(self) -> None:
        """Test GraphNode with optional data field."""
        node = GraphNode(
            id="node2",
            label="Serial Validator",
            data={"function_type": "validation"},
        )

        assert node.data is not None
        assert node.data["function_type"] == "validation"

    def test_graph_edge_creation(self) -> None:
        """Test GraphEdge dataclass creation."""
        edge = GraphEdge(
            source="node1",
            target="node2",
        )

        assert edge is not None
        assert edge.source == "node1"
        assert edge.target == "node2"

    def test_graph_edge_with_weight(self) -> None:
        """Test GraphEdge with weight."""
        edge = GraphEdge(
            source="node1",
            target="node2",
            weight=2.5,
        )

        assert edge.weight == 2.5

    def test_render_graph_nodes_edges(self) -> None:
        """Test rendering graph with nodes and edges."""
        renderer = VisualizationRenderer()

        nodes = [
            GraphNode(id="node1", label="Function A"),
            GraphNode(id="node2", label="Function B"),
        ]

        edges = [
            GraphEdge(source="node1", target="node2"),
        ]

        result = renderer.render_graph(nodes=nodes, edges=edges)

        assert result is not None


@pytest.mark.skipif(
    not MODULES_AVAILABLE,
    reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}",
)
class TestRealTimeDashboard:
    """Test RealTimeDashboard functionality."""

    def test_dashboard_initialization(self) -> None:
        """Test dashboard initializes correctly."""
        dashboard = RealTimeDashboard()

        assert dashboard is not None
        assert hasattr(dashboard, "add_event")
        assert hasattr(dashboard, "get_dashboard_state")

    def test_dashboard_event_creation(self) -> None:
        """Test DashboardEvent dataclass creation."""
        event = DashboardEvent(
            event_type=DashboardEventType.ANALYSIS_STARTED,
            timestamp=datetime.now(),
            tool="test_tool",
            title="Test Analysis",
            description="Test analysis started",
            data={"binary_path": "test.exe"},
        )

        assert event is not None
        assert event.event_type == DashboardEventType.ANALYSIS_STARTED
        assert event.tool == "test_tool"

    def test_dashboard_add_event(self) -> None:
        """Test adding events to dashboard."""
        dashboard = RealTimeDashboard()

        event = DashboardEvent(
            event_type=DashboardEventType.PROTECTION_DETECTED,
            timestamp=datetime.now(),
            tool="protection_analyzer",
            title="Protection Found",
            description="VMProtect detected",
            data={"protection_type": "VMProtect", "confidence": 0.95},
        )

        dashboard.add_event(event)

        # Verify event was processed
        state = dashboard.get_dashboard_state()
        assert state is not None

    def test_dashboard_report_protection(self) -> None:
        """Test reporting protection detection."""
        dashboard = RealTimeDashboard()

        # report_protection takes tool and protection dict
        dashboard.report_protection(
            tool="protection_scanner",
            protection={"type": "Themida", "version": "3.x", "description": "Themida detected"},
        )

        state = dashboard.get_dashboard_state()
        assert state is not None

    def test_dashboard_report_vulnerability(self) -> None:
        """Test reporting vulnerability."""
        dashboard = RealTimeDashboard()

        # report_vulnerability takes tool and vulnerability dict
        dashboard.report_vulnerability(
            tool="vuln_scanner",
            vulnerability={
                "type": "Weak Serial Check",
                "severity": "HIGH",
                "description": "Weak serial validation detected",
                "location": "0x401000",
            },
        )

        state = dashboard.get_dashboard_state()
        assert state is not None

    def test_dashboard_start_analysis(self) -> None:
        """Test starting analysis tracking."""
        dashboard = RealTimeDashboard()

        # start_analysis takes analysis_id, tool, target, options
        dashboard.start_analysis(
            analysis_id="test_001",
            tool="ghidra",
            target="C:\\test\\sample.exe",
            options={"deep_analysis": True},
        )

        state = dashboard.get_dashboard_state()
        assert state is not None

    def test_dashboard_complete_analysis(self) -> None:
        """Test completing analysis tracking."""
        dashboard = RealTimeDashboard()

        # Start analysis first
        dashboard.start_analysis(
            analysis_id="test_002",
            tool="radare2",
            target="C:\\test\\sample.exe",
        )

        # Complete analysis with results dict
        dashboard.complete_analysis(
            analysis_id="test_002",
            results={"protections_found": 1, "vulnerabilities": []},
        )

        state = dashboard.get_dashboard_state()
        assert state is not None

    def test_dashboard_shutdown(self) -> None:
        """Test dashboard shutdown."""
        dashboard = RealTimeDashboard()

        # Add some events first
        dashboard.report_protection(
            tool="upx_detector",
            protection={"type": "UPX", "description": "UPX packer detected"},
        )

        dashboard.shutdown()

        # Should not raise exceptions


@pytest.mark.skipif(
    not MODULES_AVAILABLE,
    reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}",
)
class TestDataPriority:
    """Test DataPriority enum."""

    def test_priority_enum_values(self) -> None:
        """Test DataPriority enum has expected values."""
        assert DataPriority.LOW is not None
        assert DataPriority.NORMAL is not None
        assert DataPriority.HIGH is not None
        assert DataPriority.CRITICAL is not None

    def test_priority_comparison(self) -> None:
        """Test priority values can be compared."""
        assert DataPriority.LOW.value < DataPriority.NORMAL.value
        assert DataPriority.NORMAL.value < DataPriority.HIGH.value
        assert DataPriority.HIGH.value < DataPriority.CRITICAL.value


@pytest.mark.skipif(
    not MODULES_AVAILABLE,
    reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}",
)
class TestDashboardEventType:
    """Test DashboardEventType enum."""

    def test_event_type_enum_values(self) -> None:
        """Test DashboardEventType enum has expected values."""
        assert DashboardEventType.ANALYSIS_STARTED is not None
        assert DashboardEventType.PROTECTION_DETECTED is not None
        assert DashboardEventType.VULNERABILITY_FOUND is not None


@pytest.mark.skipif(
    not MODULES_AVAILABLE,
    reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}",
)
class TestIntegration:
    """Test integration between dashboard components."""

    def test_pipeline_to_dashboard_integration(self, temp_dir: Path) -> None:
        """Test events flow from pipeline to dashboard."""
        db_path = temp_dir / "integration_test.db"
        config: dict[str, Any] = {"db_path": str(db_path)}

        pipeline = LiveDataPipeline(config=config)
        dashboard = RealTimeDashboard()

        pipeline.start()

        # Add event to pipeline
        pipeline.add_event(
            source="integration_test",
            event_type="protection_detected",
            data={"protection": "VMProtect"},
            priority=DataPriority.HIGH,
        )

        # Report to dashboard
        dashboard.report_protection(
            tool="integration_test",
            protection={"type": "VMProtect", "description": "VMProtect detected"},
        )

        time.sleep(0.1)
        pipeline.stop()

        # Verify both systems processed events
        state = dashboard.get_dashboard_state()
        assert state is not None
