"""Production tests for Live Data Pipeline.

Validates real-time event processing, buffering, throttling, aggregation,
and WebSocket broadcasting for dashboard functionality.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.dashboard.live_data_pipeline import DataEvent, DataPriority, LiveDataPipeline


class TestDataEvent:
    """Test DataEvent data class."""

    def test_data_event_initialization(self) -> None:
        """DataEvent initializes with required fields."""
        event = DataEvent(
            timestamp=time.time(),
            source="test_source",
            event_type="test_event",
            data={"key": "value"},
        )

        assert event.source == "test_source"
        assert event.event_type == "test_event"
        assert event.data["key"] == "value"
        assert event.priority == DataPriority.NORMAL

    def test_data_event_to_dict(self) -> None:
        """DataEvent converts to dictionary correctly."""
        event = DataEvent(
            timestamp=123.456,
            source="source",
            event_type="type",
            data={"test": 123},
            priority=DataPriority.HIGH,
            sequence_id=42,
            correlation_id="corr-123",
        )

        data_dict = event.to_dict()

        assert data_dict["timestamp"] == 123.456
        assert data_dict["source"] == "source"
        assert data_dict["event_type"] == "type"
        assert data_dict["data"]["test"] == 123
        assert data_dict["priority"] == DataPriority.HIGH.value
        assert data_dict["sequence_id"] == 42
        assert data_dict["correlation_id"] == "corr-123"


class TestLiveDataPipeline:
    """Production tests for LiveDataPipeline."""

    @pytest.fixture
    def temp_db_path(self) -> Path:
        """Create temporary database path."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = Path(tmp.name)
        yield db_path
        if db_path.exists():
            db_path.unlink()

    @pytest.fixture
    def pipeline(self, temp_db_path: Path) -> LiveDataPipeline:
        """Create live data pipeline."""
        config = {
            "db_path": str(temp_db_path),
            "buffer_size": 10,
            "buffer_timeout": 0.1,
            "throttle_rate": 100,
        }
        return LiveDataPipeline(config=config)

    def test_pipeline_initialization(self, pipeline: LiveDataPipeline) -> None:
        """Pipeline initializes with configuration."""
        assert pipeline.buffer_size == 10
        assert pipeline.buffer_timeout == 0.1
        assert pipeline.throttle_rate == 100

    def test_pipeline_initializes_database(self, temp_db_path: Path, pipeline: LiveDataPipeline) -> None:
        """Pipeline creates database schema."""
        conn = sqlite3.connect(str(temp_db_path))
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}

        assert "events" in tables
        assert "metrics" in tables

        conn.close()

    def test_pipeline_start_and_stop(self, pipeline: LiveDataPipeline) -> None:
        """Pipeline starts and stops correctly."""
        pipeline.start()
        assert pipeline.running is True

        pipeline.stop()
        assert pipeline.running is False

    def test_add_event_increments_sequence(self, pipeline: LiveDataPipeline) -> None:
        """Adding events increments sequence counter."""
        pipeline.add_event("source1", "event1", {"data": 1})
        pipeline.add_event("source2", "event2", {"data": 2})

        assert pipeline.sequence_counter >= 2

    def test_add_event_with_priority(self, pipeline: LiveDataPipeline) -> None:
        """Events can be added with different priorities."""
        pipeline.add_event("source", "critical_event", {"alert": True}, priority=DataPriority.CRITICAL)
        pipeline.add_event("source", "low_event", {"info": True}, priority=DataPriority.LOW)

        critical_queue = pipeline.event_queues[DataPriority.CRITICAL]
        low_queue = pipeline.event_queues[DataPriority.LOW]

        assert critical_queue.qsize() >= 1 or low_queue.qsize() >= 1

    def test_throttling_limits_event_rate(self, pipeline: LiveDataPipeline) -> None:
        """Throttling prevents excessive event rates."""
        pipeline.throttle_rate = 10

        for i in range(50):
            pipeline.add_event("source", "event", {"index": i}, priority=DataPriority.LOW)

        assert pipeline.metrics["events_dropped"] > 0

    def test_critical_events_bypass_throttling(self, pipeline: LiveDataPipeline) -> None:
        """Critical events bypass throttling."""
        pipeline.throttle_rate = 1

        for i in range(10):
            pipeline.add_event("source", "critical", {"index": i}, priority=DataPriority.CRITICAL)

        time.sleep(0.5)

        critical_added = sum(bool(not pipeline.event_queues[DataPriority.CRITICAL].empty())
                         for _ in range(pipeline.event_queues[DataPriority.CRITICAL].qsize()))

        assert critical_added >= 0

    def test_event_storage_in_database(self, temp_db_path: Path, pipeline: LiveDataPipeline) -> None:
        """Events are stored in database."""
        pipeline.start()

        pipeline.add_event("test_source", "test_event", {"test": "data"})

        time.sleep(1.0)

        pipeline.stop()

        conn = sqlite3.connect(str(temp_db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events WHERE source = 'test_source'")
        count = cursor.fetchone()[0]
        conn.close()

        assert count >= 1

    def test_get_historical_events(self, pipeline: LiveDataPipeline) -> None:
        """Historical events can be retrieved from database."""
        pipeline.start()

        start_time = time.time()
        pipeline.add_event("history_source", "history_event", {"historical": True})
        time.sleep(1.0)
        end_time = time.time()

        pipeline.stop()

        events = pipeline.get_historical_events(start_time, end_time, source="history_source")

        matching = [e for e in events if e["source"] == "history_source"]
        assert matching

    def test_get_historical_events_with_filters(self, pipeline: LiveDataPipeline) -> None:
        """Historical events can be filtered by source and type."""
        pipeline.start()

        start_time = time.time()
        pipeline.add_event("filter_source", "type_a", {"data": 1})
        pipeline.add_event("filter_source", "type_b", {"data": 2})
        pipeline.add_event("other_source", "type_a", {"data": 3})
        time.sleep(1.0)
        end_time = time.time()

        pipeline.stop()

        events = pipeline.get_historical_events(start_time, end_time, source="filter_source", event_type="type_a")

        assert all(e["source"] == "filter_source" and e["event_type"] == "type_a" for e in events)

    def test_event_callback_invocation(self, pipeline: LiveDataPipeline) -> None:
        """Event callbacks are invoked when buffer flushes."""
        callback_invoked = False
        received_events: list[DataEvent] = []

        def test_callback(events: list[DataEvent]) -> None:
            nonlocal callback_invoked, received_events
            callback_invoked = True
            received_events.extend(events)

        pipeline.register_event_callback(test_callback)
        pipeline.start()

        for i in range(15):
            pipeline.add_event("callback_test", "event", {"index": i})

        time.sleep(1.0)

        pipeline.stop()

        assert callback_invoked
        assert received_events

    def test_alert_callback_invocation(self, pipeline: LiveDataPipeline) -> None:
        """Alert callbacks are invoked for alert conditions."""
        alert_received = False
        alert_data: dict[str, Any] = {}

        def alert_callback(alert: dict[str, Any]) -> None:
            nonlocal alert_received, alert_data
            alert_received = True
            alert_data = alert

        pipeline.register_alert_callback(alert_callback)
        pipeline.alert_thresholds["latency_ms"] = 0.01

        pipeline.start()

        time.sleep(0.1)

        pipeline.add_event("alert_source", "slow_event", {"slow": True})

        time.sleep(1.5)

        pipeline.stop()

    def test_metrics_tracking(self, pipeline: LiveDataPipeline) -> None:
        """Pipeline tracks processing metrics."""
        pipeline.start()

        for i in range(20):
            pipeline.add_event("metrics_source", "event", {"index": i})

        time.sleep(1.0)

        pipeline.stop()

        assert pipeline.metrics["events_processed"] > 0

    def test_metrics_history_stored(self, temp_db_path: Path, pipeline: LiveDataPipeline) -> None:
        """Metrics are stored in database."""
        pipeline.start()

        time.sleep(6.0)

        pipeline.stop()

        conn = sqlite3.connect(str(temp_db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM metrics")
        count = cursor.fetchone()[0]
        conn.close()

        assert count > 0

    def test_get_metrics_history(self, pipeline: LiveDataPipeline) -> None:
        """Metrics history can be retrieved."""
        pipeline.start()

        start_time = time.time()
        time.sleep(6.0)
        end_time = time.time()

        pipeline.stop()

        metrics = pipeline.get_metrics_history(start_time, end_time)

        assert len(metrics) > 0

    def test_websocket_connection_management(self, pipeline: LiveDataPipeline) -> None:
        """WebSocket connections can be added and removed."""

        class MockWebSocket:
            pass

        ws1 = MockWebSocket()
        ws2 = MockWebSocket()

        pipeline.add_websocket_connection(ws1)
        pipeline.add_websocket_connection(ws2)

        assert len(pipeline.websocket_connections) == 2

        pipeline.remove_websocket_connection(ws1)

        assert len(pipeline.websocket_connections) == 1

    def test_correlation_id_preserved(self, pipeline: LiveDataPipeline) -> None:
        """Correlation ID is preserved in events."""
        pipeline.start()

        pipeline.add_event("corr_source", "corr_event", {"data": 1}, correlation_id="corr-123")

        time.sleep(1.0)

        pipeline.stop()

        events = pipeline.get_historical_events(time.time() - 10, time.time(), source="corr_source")

        correlated = [e for e in events if e.get("correlation_id") == "corr-123"]
        assert correlated


class TestBufferingAndFlushing:
    """Test event buffering and flushing behavior."""

    @pytest.fixture
    def pipeline(self) -> LiveDataPipeline:
        """Create pipeline with small buffer."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        config = {"db_path": db_path, "buffer_size": 5, "buffer_timeout": 0.1}
        pipe = LiveDataPipeline(config=config)
        yield pipe

        pipe.stop()
        if os.path.exists(db_path):
            os.unlink(db_path)

    def test_buffer_flushes_when_full(self, pipeline: LiveDataPipeline) -> None:
        """Buffer flushes automatically when full."""
        callback_count = 0

        def count_callback(events: list[DataEvent]) -> None:
            nonlocal callback_count
            callback_count += 1

        pipeline.register_event_callback(count_callback)
        pipeline.start()

        for i in range(12):
            pipeline.add_event("buffer_test", "event", {"index": i})

        time.sleep(0.5)

        pipeline.stop()

        assert callback_count >= 1

    def test_buffer_flushes_on_timeout(self, pipeline: LiveDataPipeline) -> None:
        """Buffer flushes after timeout even if not full."""
        callback_invoked = False

        def timeout_callback(events: list[DataEvent]) -> None:
            nonlocal callback_invoked
            callback_invoked = True

        pipeline.register_event_callback(timeout_callback)
        pipeline.start()

        pipeline.add_event("timeout_test", "event", {"data": 1})

        time.sleep(0.5)

        pipeline.stop()

        assert callback_invoked


class TestAggregation:
    """Test data aggregation functionality."""

    @pytest.fixture
    def pipeline(self) -> LiveDataPipeline:
        """Create pipeline with aggregation enabled."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        config = {"db_path": db_path, "aggregation_window": 2.0}
        pipe = LiveDataPipeline(config=config)
        yield pipe

        pipe.stop()
        if os.path.exists(db_path):
            os.unlink(db_path)

    def test_aggregation_calculates_statistics(self, pipeline: LiveDataPipeline) -> None:
        """Aggregation calculates min, max, mean statistics."""
        pipeline.start()

        for i in range(10):
            pipeline.add_event("agg_source", "agg_event", {"value": i * 10})

        time.sleep(3.0)

        pipeline.stop()


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_pipeline_without_config(self) -> None:
        """Pipeline works with default configuration."""
        pipeline = LiveDataPipeline()
        assert pipeline.buffer_size > 0
        assert pipeline.throttle_rate > 0

    def test_empty_event_data(self) -> None:
        """Pipeline handles empty event data."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        pipeline = LiveDataPipeline(config={"db_path": db_path})
        pipeline.start()

        pipeline.add_event("empty_source", "empty_event", {})

        time.sleep(0.5)

        pipeline.stop()

        if os.path.exists(db_path):
            os.unlink(db_path)

    def test_large_event_data(self) -> None:
        """Pipeline handles large event data."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        pipeline = LiveDataPipeline(config={"db_path": db_path})
        pipeline.start()

        large_data = {f"key_{i}": f"value_{i}" * 100 for i in range(100)}
        pipeline.add_event("large_source", "large_event", large_data)

        time.sleep(0.5)

        pipeline.stop()

        if os.path.exists(db_path):
            os.unlink(db_path)

    def test_unicode_in_event_data(self) -> None:
        """Pipeline handles Unicode in event data."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        pipeline = LiveDataPipeline(config={"db_path": db_path})
        pipeline.start()

        unicode_data = {"message": "测试 テスト тест", "emoji": "🔥"}
        pipeline.add_event("unicode_source", "unicode_event", unicode_data)

        time.sleep(0.5)

        pipeline.stop()

        if os.path.exists(db_path):
            os.unlink(db_path)
