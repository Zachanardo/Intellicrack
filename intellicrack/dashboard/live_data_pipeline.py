"""Live Data Pipeline for Real-time Dashboard.

This module implements the live data pipeline that connects analysis events
to the WebSocket stream with buffering, throttling, and aggregation.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import asyncio
import json
import logging
import queue
import sqlite3
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, cast

import numpy as np


logger = logging.getLogger(__name__)


class DataPriority(Enum):
    """Priority levels for data events."""

    CRITICAL = 1  # Immediate delivery
    HIGH = 2  # Prioritized delivery
    NORMAL = 3  # Standard delivery
    LOW = 4  # Can be throttled/dropped


@dataclass
class DataEvent:
    """Data event for pipeline processing."""

    timestamp: float
    source: str
    event_type: str
    data: dict[str, Any]
    priority: DataPriority = DataPriority.NORMAL
    sequence_id: int = 0
    correlation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert pipeline event to dictionary representation.

        Returns:
            dict[str, Any]: Dictionary representation of the event with all fields.
        """
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "data": self.data,
            "priority": self.priority.value,
            "sequence_id": self.sequence_id,
            "correlation_id": self.correlation_id,
        }


class LiveDataPipeline:
    """Live data pipeline for real-time event processing."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize live data pipeline.

        Args:
            config: Pipeline configuration

        """
        self.config = config or {}
        self.logger = logger

        # Event queues by priority
        self.event_queues: dict[DataPriority, queue.PriorityQueue[tuple[float, DataEvent]]] = {
            priority: queue.PriorityQueue(maxsize=self.config.get("queue_size", 10000)) for priority in DataPriority
        }

        # Buffering configuration
        self.buffer_size = self.config.get("buffer_size", 100)
        self.buffer_timeout = self.config.get("buffer_timeout", 0.1)  # seconds
        self.event_buffer: list[DataEvent] = []
        self.buffer_lock = threading.Lock()

        # Throttling configuration
        self.throttle_rate = self.config.get("throttle_rate", 100)  # events per second
        self.throttle_window = 1.0  # seconds
        self.event_timestamps: deque[float] = deque(maxlen=self.throttle_rate)

        # Aggregation
        self.aggregation_window = self.config.get("aggregation_window", 5.0)  # seconds
        self.aggregators: dict[str, dict[str, list[DataEvent]]] = defaultdict(lambda: defaultdict(list))
        self.aggregation_lock = threading.Lock()

        # Metrics
        self.metrics = {
            "events_processed": 0,
            "events_dropped": 0,
            "events_buffered": 0,
            "avg_latency": 0.0,
            "throughput": 0.0,
            "queue_sizes": {},
        }
        self.metrics_lock = threading.Lock()

        # Historical data storage
        self.db_path = Path(self.config.get("db_path", "dashboard_events.db"))
        self._init_database()

        # WebSocket connections
        self.websocket_connections: set[object] = set()
        self.websocket_lock = threading.Lock()

        # Processing threads
        self.processing_thread: threading.Thread | None = None
        self.flush_thread: threading.Thread | None = None
        self.aggregation_thread: threading.Thread | None = None
        self.metrics_thread: threading.Thread | None = None
        self.running = False

        # Alert thresholds
        self.alert_thresholds = self.config.get(
            "alert_thresholds",
            {
                "error_rate": 0.1,  # 10% error rate
                "latency_ms": 100,  # 100ms latency
                "queue_size": 5000,  # Queue size threshold
            },
        )

        # Callbacks
        self.event_callbacks: list[Callable[[list[DataEvent]], Any]] = []
        self.alert_callbacks: list[Callable[[dict[str, Any]], Any]] = []

        # Sequence ID counter
        self.sequence_counter = 0
        self.sequence_lock = threading.Lock()

    def _init_database(self) -> None:
        """Initialize SQLite database for historical data."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Create events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                data TEXT NOT NULL,
                priority INTEGER NOT NULL,
                sequence_id INTEGER NOT NULL,
                correlation_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_source ON events(source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_correlation_id ON events(correlation_id)")

        # Create metrics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()

    def start(self) -> None:
        """Start the data pipeline."""
        if self.running:
            return

        self.running = True

        # Start processing threads
        self.processing_thread = threading.Thread(target=self._process_events, daemon=True)
        if self.processing_thread is not None:
            self.processing_thread.start()

        self.flush_thread = threading.Thread(target=self._flush_buffer_periodically, daemon=True)
        if self.flush_thread is not None:
            self.flush_thread.start()

        self.aggregation_thread = threading.Thread(target=self._aggregate_data, daemon=True)
        if self.aggregation_thread is not None:
            self.aggregation_thread.start()

        self.metrics_thread = threading.Thread(target=self._update_metrics, daemon=True)
        if self.metrics_thread is not None:
            self.metrics_thread.start()

        self.logger.info("Live data pipeline started")

    def stop(self) -> None:
        """Stop the data pipeline."""
        self.running = False

        # Flush remaining events
        self._flush_buffer()

        # Wait for threads to stop
        if self.processing_thread:
            self.processing_thread.join(timeout=2)
        if self.flush_thread:
            self.flush_thread.join(timeout=2)
        if self.aggregation_thread:
            self.aggregation_thread.join(timeout=2)
        if self.metrics_thread:
            self.metrics_thread.join(timeout=2)

        self.logger.info("Live data pipeline stopped")

    def add_event(
        self,
        source: str,
        event_type: str,
        data: dict[str, Any],
        priority: DataPriority = DataPriority.NORMAL,
        correlation_id: str | None = None,
    ) -> None:
        """Add event to the pipeline.

        Args:
            source: Event source (tool name)
            event_type: Type of event
            data: Event data
            priority: Event priority
            correlation_id: Optional correlation ID

        """
        # Generate sequence ID
        with self.sequence_lock:
            self.sequence_counter += 1
            sequence_id = self.sequence_counter

        # Create event
        event = DataEvent(
            timestamp=time.time(),
            source=source,
            event_type=event_type,
            data=data,
            priority=priority,
            sequence_id=sequence_id,
            correlation_id=correlation_id,
        )

        # Check throttling
        if not self._should_throttle(event):
            # Add to appropriate queue
            try:
                self.event_queues[priority].put_nowait((event.timestamp, event))

                with self.metrics_lock:
                    events_buffered = self.metrics["events_buffered"]
                    if isinstance(events_buffered, (int, float)):
                        self.metrics["events_buffered"] = events_buffered + 1

            except queue.Full:
                # Queue is full, drop low-priority events
                if priority == DataPriority.LOW:
                    with self.metrics_lock:
                        events_dropped = self.metrics["events_dropped"]
                        if isinstance(events_dropped, (int, float)):
                            self.metrics["events_dropped"] = events_dropped + 1
                    self.logger.warning("Dropped low-priority event from %s", source)
                else:
                    # Force add high-priority events
                    self.event_queues[priority].put((event.timestamp, event))
        else:
            with self.metrics_lock:
                events_dropped = self.metrics["events_dropped"]
                if isinstance(events_dropped, (int, float)):
                    self.metrics["events_dropped"] = events_dropped + 1

    def _should_throttle(self, event: DataEvent) -> bool:
        """Check if event should be throttled.

        Args:
            event: Event to check

        Returns:
            True if event should be throttled

        """
        if event.priority == DataPriority.CRITICAL:
            return False  # Never throttle critical events

        current_time = time.time()

        # Clean old timestamps
        while self.event_timestamps and current_time - self.event_timestamps[0] > self.throttle_window:
            self.event_timestamps.popleft()

        # Check rate
        if len(self.event_timestamps) >= self.throttle_rate:
            return True

        self.event_timestamps.append(current_time)
        return False

    def _process_events(self) -> None:
        """Process events from queues."""
        while self.running:
            try:
                # Process events by priority
                for priority in DataPriority:
                    if not self.event_queues[priority].empty():
                        try:
                            _, event = self.event_queues[priority].get_nowait()
                            self._process_single_event(event)
                        except queue.Empty:
                            pass

                time.sleep(0.001)  # Small delay to prevent CPU spinning

            except Exception as e:
                self.logger.exception("Error processing events: %s", e)

    def _process_single_event(self, event: DataEvent) -> None:
        """Process a single event.

        Args:
            event: Event to process

        """
        time.time()

        # Add to buffer
        with self.buffer_lock:
            self.event_buffer.append(event)

            # Check if buffer should be flushed
            if len(self.event_buffer) >= self.buffer_size:
                self._flush_buffer()

        # Update metrics
        latency = time.time() - event.timestamp
        with self.metrics_lock:
            events_processed = self.metrics["events_processed"]
            avg_latency = self.metrics["avg_latency"]
            if isinstance(events_processed, (int, float)):
                self.metrics["events_processed"] = events_processed + 1
            if isinstance(avg_latency, (int, float)):
                self.metrics["avg_latency"] = avg_latency * 0.9 + latency * 0.1

        # Check for alerts
        self._check_alerts(event, latency)

        # Store in database
        self._store_event(event)

        # Add to aggregation
        with self.aggregation_lock:
            self.aggregators[event.source][event.event_type].append(event)

    def _flush_buffer(self) -> None:
        """Flush event buffer to WebSocket connections."""
        with self.buffer_lock:
            if not self.event_buffer:
                return

            # Prepare batch message
            batch = {
                "type": "event_batch",
                "timestamp": time.time(),
                "events": [event.to_dict() for event in self.event_buffer],
                "count": len(self.event_buffer),
            }

            # Send to WebSocket connections
            self._broadcast_to_websockets(batch)

            # Notify callbacks
            for callback in self.event_callbacks:
                try:
                    callback(self.event_buffer)
                except Exception as e:
                    self.logger.exception("Error in event callback: %s", e)

            # Clear buffer
            self.event_buffer.clear()

    def _flush_buffer_periodically(self) -> None:
        """Periodically flush the buffer."""
        while self.running:
            time.sleep(self.buffer_timeout)
            self._flush_buffer()

    def _aggregate_data(self) -> None:
        """Aggregate data over time windows."""
        while self.running:
            time.sleep(self.aggregation_window)

            with self.aggregation_lock:
                current_time = time.time()

                for source, event_types in self.aggregators.items():
                    for event_type, events in event_types.items():
                        if events:
                            # Filter old events
                            recent_events = [e for e in events if current_time - e.timestamp <= self.aggregation_window]

                            if recent_events:
                                # Calculate aggregates
                                aggregated = self._calculate_aggregates(source, event_type, recent_events)

                                # Send aggregated data
                                self._send_aggregated_data(aggregated)

                            # Keep only recent events
                            event_types[event_type] = recent_events

    def _calculate_aggregates(self, source: str, event_type: str, events: list[DataEvent]) -> dict[str, Any]:
        """Calculate aggregates for events.

        Args:
            source: Event source
            event_type: Event type
            events: Events to aggregate

        Returns:
            Aggregated data

        """
        # Extract numeric values from events
        numeric_values: list[int | float] = []
        for event in events:
            numeric_values.extend(value for _key, value in event.data.items() if isinstance(value, (int, float)))
        aggregated = {
            "source": source,
            "event_type": event_type,
            "count": len(events),
            "window_start": min(e.timestamp for e in events),
            "window_end": max(e.timestamp for e in events),
            "rate": len(events) / self.aggregation_window,
        }

        if numeric_values:
            aggregated |= {
                "min": float(np.min(numeric_values)),
                "max": float(np.max(numeric_values)),
                "mean": float(np.mean(numeric_values)),
                "median": float(np.median(numeric_values)),
                "std": float(np.std(numeric_values)),
                "p95": float(np.percentile(numeric_values, 95)),
            }

        return aggregated

    def _send_aggregated_data(self, aggregated: dict[str, Any]) -> None:
        """Send aggregated data to clients.

        Args:
            aggregated: Aggregated data

        """
        message = {"type": "aggregated_data", "timestamp": time.time(), "data": aggregated}

        self._broadcast_to_websockets(message)

    def _update_metrics(self) -> None:
        """Update pipeline metrics."""
        while self.running:
            with self.metrics_lock:
                # Calculate throughput
                events_processed = self.metrics["events_processed"]
                start_time = self.metrics.get("start_time", time.time())
                if isinstance(events_processed, (int, float)) and isinstance(start_time, (int, float)):
                    self.metrics["throughput"] = events_processed / max(
                        1,
                        time.time() - start_time,
                    )

                # Update queue sizes
                self.metrics["queue_sizes"] = {priority.name: self.event_queues[priority].qsize() for priority in DataPriority}

                # Store metrics in database
                self._store_metrics()

            # Send metrics update
            self._send_metrics_update()

            time.sleep(5)  # Update every 5 seconds

    def _check_alerts(self, event: DataEvent, latency: float) -> None:
        """Check for alert conditions.

        Args:
            event: Processed event
            latency: Event latency

        """
        alerts = []

        # Check latency threshold
        if latency * 1000 > self.alert_thresholds.get("latency_ms", 100):
            alerts.append(
                {
                    "type": "high_latency",
                    "source": event.source,
                    "latency_ms": latency * 1000,
                    "threshold_ms": self.alert_thresholds["latency_ms"],
                },
            )

        # Check queue sizes
        alerts.extend(
            {
                "type": "queue_overflow",
                "priority": priority.name,
                "size": queue_obj.qsize(),
                "threshold": self.alert_thresholds["queue_size"],
            }
            for priority, queue_obj in self.event_queues.items()
            if queue_obj.qsize() > self.alert_thresholds.get("queue_size", 5000)
        )
        # Send alerts
        for alert in alerts:
            self._send_alert(alert)

    def _send_alert(self, alert: dict[str, Any]) -> None:
        """Send alert to clients.

        Args:
            alert: Alert data

        """
        message = {"type": "alert", "timestamp": time.time(), "alert": alert}

        self._broadcast_to_websockets(message)

        # Notify callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.exception("Error in alert callback: %s", e)

    def _send_metrics_update(self) -> None:
        """Send metrics update to clients."""
        with self.metrics_lock:
            message = {
                "type": "metrics_update",
                "timestamp": time.time(),
                "metrics": self.metrics.copy(),
            }

        self._broadcast_to_websockets(message)

    def _broadcast_to_websockets(self, message: dict[str, Any]) -> None:
        """Broadcast message to all WebSocket connections.

        Args:
            message: Message to broadcast

        """
        with self.websocket_lock:
            if not self.websocket_connections:
                return

            message_json = json.dumps(message)
            disconnected: set[object] = set()

            for connection in self.websocket_connections:
                try:
                    ws_connection = cast("Any", connection)
                    asyncio.run_coroutine_threadsafe(ws_connection.send(message_json), asyncio.get_event_loop())
                except Exception as e:
                    self.logger.exception("Error sending to WebSocket: %s", e)
                    disconnected.add(connection)

            # Remove disconnected clients
            self.websocket_connections -= disconnected

    def _store_event(self, event: DataEvent) -> None:
        """Store event in database.

        Args:
            event: Event to store

        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO events (timestamp, source, event_type, data, priority, sequence_id, correlation_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    event.timestamp,
                    event.source,
                    event.event_type,
                    json.dumps(event.data),
                    event.priority.value,
                    event.sequence_id,
                    event.correlation_id,
                ),
            )

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.exception("Error storing event: %s", e)

    def _store_metrics(self) -> None:
        """Store metrics in database."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            timestamp = time.time()

            for metric_name, metric_value in self.metrics.items():
                if isinstance(metric_value, (int, float)):
                    cursor.execute(
                        """
                        INSERT INTO metrics (timestamp, metric_name, metric_value)
                        VALUES (?, ?, ?)
                    """,
                        (timestamp, metric_name, metric_value),
                    )

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.exception("Error storing metrics: %s", e)

    def add_websocket_connection(self, connection: object) -> None:
        """Add WebSocket connection.

        Args:
            connection: WebSocket connection object

        """
        with self.websocket_lock:
            self.websocket_connections.add(connection)

    def remove_websocket_connection(self, connection: object) -> None:
        """Remove WebSocket connection.

        Args:
            connection: WebSocket connection object

        """
        with self.websocket_lock:
            self.websocket_connections.discard(connection)

    def register_event_callback(self, callback: Callable[[list[DataEvent]], Any]) -> None:
        """Register event callback.

        Args:
            callback: Callback function

        """
        self.event_callbacks.append(callback)

    def register_alert_callback(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        """Register alert callback.

        Args:
            callback: Callback function

        """
        self.alert_callbacks.append(callback)

    def get_historical_events(
        self,
        start_time: float,
        end_time: float,
        source: str | None = None,
        event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get historical events from database.

        Args:
            start_time: Start timestamp
            end_time: End timestamp
            source: Optional source filter
            event_type: Optional event type filter

        Returns:
            List of events

        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            query = """
                SELECT timestamp, source, event_type, data, priority, sequence_id, correlation_id
                FROM events
                WHERE timestamp >= ? AND timestamp <= ?
            """
            params: list[float | str] = [start_time, end_time]

            if source:
                query += " AND source = ?"
                params.append(source)

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)

            query += " ORDER BY timestamp ASC"

            cursor.execute(query, params)
            rows = cursor.fetchall()

            events = [
                {
                    "timestamp": row[0],
                    "source": row[1],
                    "event_type": row[2],
                    "data": json.loads(row[3]),
                    "priority": row[4],
                    "sequence_id": row[5],
                    "correlation_id": row[6],
                }
                for row in rows
            ]
            conn.close()
            return events

        except Exception as e:
            self.logger.exception("Error getting historical events: %s", e)
            return []

    def get_metrics_history(self, start_time: float, end_time: float, metric_name: str | None = None) -> list[dict[str, Any]]:
        """Get metrics history from database.

        Args:
            start_time: Start timestamp
            end_time: End timestamp
            metric_name: Optional metric name filter

        Returns:
            List of metrics

        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            query = """
                SELECT timestamp, metric_name, metric_value
                FROM metrics
                WHERE timestamp >= ? AND timestamp <= ?
            """
            params: list[float | str] = [start_time, end_time]

            if metric_name:
                query += " AND metric_name = ?"
                params.append(metric_name)

            query += " ORDER BY timestamp ASC"

            cursor.execute(query, params)
            rows = cursor.fetchall()

            metrics = [
                {
                    "timestamp": row[0],
                    "metric_name": row[1],
                    "metric_value": row[2],
                }
                for row in rows
            ]
            conn.close()
            return metrics

        except Exception as e:
            self.logger.exception("Error getting metrics history: %s", e)
            return []
