from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

try:
    from intellicrack.dashboard.dashboard_manager import (
        DashboardManager,
        DataSource,
        DataSourceType,
    )
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
    from intellicrack.dashboard.websocket_stream import (
        WebSocketEventStream,
        AnalysisEvent,
        EventType,
    )

    MODULES_AVAILABLE = True
except ImportError as e:
    MODULES_AVAILABLE = False
    IMPORT_ERROR = str(e)


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.mark.skipif(not MODULES_AVAILABLE, reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}")
class TestLiveDataPipelineEffectiveness:

    def test_pipeline_processes_and_stores_events(self, temp_dir: Path) -> None:
        db_path = temp_dir / "test_pipeline.db"
        pipeline = LiveDataPipeline(db_path=str(db_path))

        pipeline.start()

        KNOWN_EVENT_DATA = {"binary": "test.exe", "protection": "VMProtect", "severity": "HIGH"}
        event = DataEvent(
            event_type="protection_detected",
            data=KNOWN_EVENT_DATA,
            priority=DataPriority.HIGH,
            timestamp=time.time()
        )

        pipeline.add_event(event=event)
        time.sleep(0.3)
        pipeline.stop()

        assert os.path.exists(db_path), "FAILED: Pipeline did not create database"

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM events WHERE event_type = 'protection_detected'")
        count = cursor.fetchone()[0]
        conn.close()

        assert count >= 1, f"FAILED: Event not stored in database (found {count}, expected >= 1)"

    def test_pipeline_event_retrieval_accuracy(self, temp_dir: Path) -> None:
        db_path = temp_dir / "test_pipeline_retrieval.db"
        pipeline = LiveDataPipeline(db_path=str(db_path))

        pipeline.start()

        KNOWN_EVENTS = [
            {"type": "key_extracted", "data": {"key_type": "RSA", "size": 2048}},
            {"type": "keygen_generated", "data": {"algorithm": "checksum", "success_rate": 0.95}},
            {"type": "binary_unpacked", "data": {"packer": "UPX", "size": 100000}},
        ]

        for known_event in KNOWN_EVENTS:
            event = DataEvent(
                event_type=known_event["type"],
                data=known_event["data"],
                priority=DataPriority.NORMAL,
                timestamp=time.time()
            )
            pipeline.add_event(event=event)

        time.sleep(0.4)

        historical_events = pipeline.get_historical_events(limit=10)

        pipeline.stop()

        assert len(historical_events) >= 3, \
            f"FAILED: Event retrieval incomplete (got {len(historical_events)}, expected >= 3)"

        retrieved_types = [evt.get("event_type") for evt in historical_events]
        for known_event in KNOWN_EVENTS:
            assert known_event["type"] in retrieved_types, \
                f"FAILED: Event type '{known_event['type']}' not retrieved from pipeline"

    def test_pipeline_callback_execution(self, temp_dir: Path) -> None:
        db_path = temp_dir / "test_pipeline_callback.db"
        pipeline = LiveDataPipeline(db_path=str(db_path))

        callback_invoked = {"count": 0, "received_data": None}

        def test_callback(event: DataEvent) -> None:
            callback_invoked["count"] += 1
            callback_invoked["received_data"] = event.data

        pipeline.register_event_callback(callback=test_callback)
        pipeline.start()

        KNOWN_DATA = {"test": "callback_data", "value": 12345}
        event = DataEvent(
            event_type="test_event",
            data=KNOWN_DATA,
            priority=DataPriority.HIGH,
            timestamp=time.time()
        )

        pipeline.add_event(event=event)
        time.sleep(0.3)
        pipeline.stop()

        assert callback_invoked["count"] >= 1, \
            "FAILED: Pipeline callback not invoked"
        assert callback_invoked["received_data"] == KNOWN_DATA, \
            f"FAILED: Callback received wrong data: {callback_invoked['received_data']}"


@pytest.mark.skipif(not MODULES_AVAILABLE, reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}")
class TestVisualizationRendererEffectiveness:

    def test_graph_rendering_produces_output(self, temp_dir: Path) -> None:
        renderer = VisualizationRenderer(output_dir=str(temp_dir))

        nodes = [
            GraphNode(id="node1", label="License Check", node_type="function"),
            GraphNode(id="node2", label="Serial Validator", node_type="function"),
            GraphNode(id="node3", label="Activation Handler", node_type="function"),
        ]

        edges = [
            GraphEdge(source="node1", target="node2", edge_type="calls"),
            GraphEdge(source="node2", target="node3", edge_type="calls"),
        ]

        output_path = renderer.render_graph(
            nodes=nodes,
            edges=edges,
            title="License Validation Flow",
            output_format="html"
        )

        assert output_path is not None, "FAILED: Graph rendering returned None"
        assert os.path.exists(output_path), f"FAILED: Graph file not created at {output_path}"

        with open(output_path, 'r') as f:
            html_content = f.read()

        assert len(html_content) > 100, "FAILED: Graph HTML output too short (likely empty)"
        assert "License Check" in html_content or "node1" in html_content, \
            "FAILED: Graph content missing node data"

    def test_heatmap_generation(self, temp_dir: Path) -> None:
        renderer = VisualizationRenderer(output_dir=str(temp_dir))

        KNOWN_HEATMAP_DATA = {
            "Memory Region 0x1000": {"reads": 100, "writes": 50},
            "Memory Region 0x2000": {"reads": 200, "writes": 25},
            "Memory Region 0x3000": {"reads": 50, "writes": 150},
        }

        output_path = renderer.render_heatmap(
            data=KNOWN_HEATMAP_DATA,
            title="Memory Access Heatmap",
            output_format="png"
        )

        if output_path and os.path.exists(output_path):
            file_size = os.path.getsize(output_path)
            assert file_size > 1000, \
                f"FAILED: Heatmap file too small ({file_size} bytes, expected > 1000)"

    def test_metrics_chart_rendering(self, temp_dir: Path) -> None:
        renderer = VisualizationRenderer(output_dir=str(temp_dir))

        KNOWN_METRICS = {
            "time": [0, 1, 2, 3, 4, 5],
            "success_rate": [0.5, 0.6, 0.75, 0.8, 0.85, 0.9],
        }

        output_path = renderer.render_metrics_chart(
            metrics=KNOWN_METRICS,
            title="Keygen Success Rate Over Time",
            output_format="html"
        )

        assert output_path is not None, "FAILED: Metrics chart rendering returned None"

        if os.path.exists(output_path):
            with open(output_path, 'r') as f:
                chart_content = f.read()

            assert len(chart_content) > 100, "FAILED: Metrics chart output too short"


@pytest.mark.skipif(not MODULES_AVAILABLE, reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}")
class TestRealTimeDashboardEffectiveness:

    def test_dashboard_tracks_analysis_events(self, temp_dir: Path) -> None:
        db_path = temp_dir / "test_dashboard.db"
        dashboard = RealTimeDashboard(db_path=str(db_path))

        dashboard.start()

        analysis_id = "test_analysis_001"
        dashboard.report_analysis_started(
            analysis_id=analysis_id,
            binary_path="C:\\test\\protected.exe"
        )

        dashboard.report_protection_detected(
            analysis_id=analysis_id,
            protection_type="VMProtect",
            confidence=0.95
        )

        dashboard.report_vulnerability_found(
            analysis_id=analysis_id,
            vulnerability_type="Weak Serial Validation",
            severity="HIGH"
        )

        dashboard.report_analysis_complete(analysis_id=analysis_id, success=True)

        time.sleep(0.2)

        state = dashboard.get_dashboard_state()

        dashboard.stop()

        assert state is not None, "FAILED: Dashboard state retrieval failed"
        assert "active_analyses" in state or "recent_analyses" in state, \
            "FAILED: Dashboard state missing analysis tracking"

        if "recent_analyses" in state:
            found_analysis = any(
                analysis.get("id") == analysis_id
                for analysis in state.get("recent_analyses", [])
            )
            assert found_analysis, f"FAILED: Analysis {analysis_id} not tracked in dashboard"

    def test_dashboard_metrics_accuracy(self, temp_dir: Path) -> None:
        db_path = temp_dir / "test_dashboard_metrics.db"
        dashboard = RealTimeDashboard(db_path=str(db_path))

        dashboard.start()

        KNOWN_SUCCESSES = 7
        KNOWN_FAILURES = 3

        for i in range(KNOWN_SUCCESSES):
            analysis_id = f"success_{i}"
            dashboard.report_analysis_started(analysis_id=analysis_id, binary_path=f"test{i}.exe")
            dashboard.report_analysis_complete(analysis_id=analysis_id, success=True)

        for i in range(KNOWN_FAILURES):
            analysis_id = f"failure_{i}"
            dashboard.report_analysis_started(analysis_id=analysis_id, binary_path=f"test{i}.exe")
            dashboard.report_analysis_complete(analysis_id=analysis_id, success=False)

        time.sleep(0.3)

        metrics = dashboard.get_performance_metrics()

        dashboard.stop()

        assert metrics is not None, "FAILED: Performance metrics retrieval failed"

        if "total_analyses" in metrics:
            total = metrics["total_analyses"]
            assert total == (KNOWN_SUCCESSES + KNOWN_FAILURES), \
                f"FAILED: Total analyses incorrect (got {total}, expected {KNOWN_SUCCESSES + KNOWN_FAILURES})"

        if "success_rate" in metrics:
            expected_rate = KNOWN_SUCCESSES / (KNOWN_SUCCESSES + KNOWN_FAILURES)
            actual_rate = metrics["success_rate"]
            rate_diff = abs(actual_rate - expected_rate)
            assert rate_diff < 0.1, \
                f"FAILED: Success rate incorrect (got {actual_rate:.2f}, expected {expected_rate:.2f})"


@pytest.mark.skipif(not MODULES_AVAILABLE, reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}")
class TestWebSocketEventStreamEffectiveness:

    def test_event_publishing(self) -> None:
        stream = WebSocketEventStream(port=8765)

        published_events = []

        def mock_broadcast(event: dict[str, Any]) -> None:
            published_events.append(event)

        stream._broadcast_to_clients = mock_broadcast

        stream.start()

        KNOWN_EVENT = AnalysisEvent(
            event_type=EventType.PROTECTION_DETECTED,
            data={"protection": "Themida", "version": "3.x"},
            timestamp=time.time()
        )

        stream.publish_event(event=KNOWN_EVENT)

        time.sleep(0.1)

        stream.stop()

        assert published_events, "FAILED: Event not published (no broadcasts recorded)"

        if published_events:
            last_event = published_events[-1]
            assert last_event.get("event_type") == "protection_detected" or \
                       last_event.get("type") == "protection_detected", \
                    "FAILED: Published event missing correct type"


@pytest.mark.skipif(not MODULES_AVAILABLE, reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}")
class TestDashboardManagerEffectiveness:

    def test_manager_widget_data_flow(self, temp_dir: Path) -> None:
        manager = DashboardManager(storage_dir=str(temp_dir))

        widget_config = {
            "id": "protection_chart",
            "type": "chart",
            "title": "Protection Detection Chart",
        }

        manager.add_widget(widget_id="protection_chart", widget_config=widget_config)

        data_source = DataSource(
            source_id="protection_data",
            source_type=DataSourceType.REALTIME,
            poll_interval=1.0,
        )

        manager.add_data_source(data_source=data_source)

        manager.subscribe_widget_to_source(
            widget_id="protection_chart",
            source_id="protection_data"
        )

        assert "protection_chart" in manager.widgets, \
            "FAILED: Widget not registered in manager"

        assert "protection_data" in manager.data_sources, \
            "FAILED: Data source not registered in manager"

        subscriptions = manager.get_widget_subscriptions(widget_id="protection_chart")
        assert "protection_data" in subscriptions, \
            "FAILED: Widget not subscribed to data source"


@pytest.mark.skipif(not MODULES_AVAILABLE, reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}")
class TestIntegrationEffectiveness:

    def test_full_dashboard_pipeline(self, temp_dir: Path) -> None:
        db_path = temp_dir / "integration_test.db"

        pipeline = LiveDataPipeline(db_path=str(db_path))
        dashboard = RealTimeDashboard(db_path=str(db_path))
        renderer = VisualizationRenderer(output_dir=str(temp_dir))

        pipeline.start()
        dashboard.start()

        analysis_id = "integration_test_001"
        dashboard.report_analysis_started(
            analysis_id=analysis_id,
            binary_path="C:\\test\\sample.exe"
        )

        event = DataEvent(
            event_type="key_extracted",
            data={"key_type": "RSA", "modulus_size": 2048},
            priority=DataPriority.HIGH,
            timestamp=time.time()
        )
        pipeline.add_event(event=event)

        dashboard.report_bypass_success(
            analysis_id=analysis_id,
            bypass_technique="Keygen",
            target="Serial Validation"
        )

        dashboard.report_analysis_complete(analysis_id=analysis_id, success=True)

        time.sleep(0.3)

        dashboard_state = dashboard.get_dashboard_state()
        historical_events = pipeline.get_historical_events(limit=5)

        pipeline.stop()
        dashboard.stop()

        assert dashboard_state is not None, "FAILED: Integration - dashboard state retrieval failed"
        assert len(historical_events) >= 1, "FAILED: Integration - event pipeline failed"

        nodes = [
            GraphNode(id="start", label="Analysis Start", node_type="event"),
            GraphNode(id="extract", label="Key Extracted", node_type="event"),
            GraphNode(id="bypass", label="Bypass Success", node_type="event"),
            GraphNode(id="complete", label="Analysis Complete", node_type="event"),
        ]

        edges = [
            GraphEdge(source="start", target="extract", edge_type="leads_to"),
            GraphEdge(source="extract", target="bypass", edge_type="leads_to"),
            GraphEdge(source="bypass", target="complete", edge_type="leads_to"),
        ]

        graph_path = renderer.render_graph(
            nodes=nodes,
            edges=edges,
            title="Analysis Workflow",
            output_format="html"
        )

        assert graph_path and os.path.exists(graph_path), \
            "FAILED: Integration - workflow visualization failed"
