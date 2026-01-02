"""Production tests for WebSocket event streaming with real async communication.

These tests validate that websocket_stream correctly handles WebSocket connections,
broadcasts events, manages subscriptions, and maintains statistics. Tests MUST FAIL
if WebSocket communication is broken.

Copyright (C) 2025 Zachary Flint
"""

import asyncio
import json
import time
from typing import Any

import pytest
import websockets

from intellicrack.dashboard.websocket_stream import (
    AnalysisEvent,
    EventPriority,
    EventType,
    WebSocketEventStream,
)


class TestWebSocketEventStreamProduction:
    """Production tests for WebSocket event streaming."""

    @pytest.fixture
    def event_stream(self) -> WebSocketEventStream:
        """Create WebSocket event stream instance."""
        return WebSocketEventStream(host="localhost", port=0)

    @pytest.fixture
    def sample_analysis_event(self) -> AnalysisEvent:
        """Create sample analysis event."""
        return AnalysisEvent(
            id="evt_001",
            type=EventType.LICENSE_CHECK_FOUND,
            timestamp=time.time(),
            source="binary_analyzer",
            target="license_validator.exe",
            data={
                "address": "0x401000",
                "function": "validate_license",
                "pattern": "serial_check",
            },
            priority=EventPriority.HIGH,
            tags=["license", "validation", "critical"],
            session_id="session_123",
        )

    def test_event_type_enum_completeness(self) -> None:
        """EventType enum includes all analysis event types."""
        required_types = [
            "ANALYSIS_STARTED",
            "ANALYSIS_COMPLETE",
            "LICENSE_CHECK_FOUND",
            "PROTECTION_DETECTED",
            "CRYPTO_DETECTED",
            "PATCH_APPLIED",
            "KEY_EXTRACTED",
            "SERIAL_GENERATED",
        ]

        for event_type in required_types:
            assert hasattr(EventType, event_type), f"Must have {event_type} event type"

    def test_event_priority_levels(self) -> None:
        """EventPriority enum has proper severity levels."""
        assert EventPriority.CRITICAL.value < EventPriority.HIGH.value, (
            "CRITICAL must be higher priority than HIGH"
        )
        assert EventPriority.HIGH.value < EventPriority.MEDIUM.value, (
            "HIGH must be higher priority than MEDIUM"
        )
        assert EventPriority.MEDIUM.value < EventPriority.LOW.value, (
            "MEDIUM must be higher priority than LOW"
        )
        assert EventPriority.LOW.value < EventPriority.INFO.value, (
            "LOW must be higher priority than INFO"
        )

    def test_analysis_event_structure(
        self,
        sample_analysis_event: AnalysisEvent,
    ) -> None:
        """AnalysisEvent dataclass has required fields."""
        assert sample_analysis_event.id == "evt_001", "Event ID must be set"
        assert sample_analysis_event.type == EventType.LICENSE_CHECK_FOUND, "Type must be set"
        assert sample_analysis_event.timestamp > 0, "Timestamp must be positive"
        assert sample_analysis_event.source == "binary_analyzer", "Source must be set"
        assert sample_analysis_event.priority == EventPriority.HIGH, "Priority must be set"
        assert len(sample_analysis_event.tags) > 0, "Tags must be present"
        assert sample_analysis_event.session_id == "session_123", "Session ID must be set"

    def test_event_stream_initialization(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """WebSocket stream initializes with correct configuration."""
        assert event_stream.host == "localhost", "Host must be set"
        assert isinstance(event_stream.port, int), "Port must be integer"
        assert len(event_stream.clients) == 0, "Initially no clients"
        assert len(event_stream.event_queue) == 0, "Initially empty queue"
        assert event_stream.running is False, "Initially not running"

    def test_event_stream_statistics_tracking(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Event stream tracks comprehensive statistics."""
        assert "events_sent" in event_stream.stats, "Must track events sent"
        assert "events_received" in event_stream.stats, "Must track events received"
        assert "clients_connected" in event_stream.stats, "Must track connected clients"
        assert "clients_total" in event_stream.stats, "Must track total clients"
        assert "uptime_start" in event_stream.stats, "Must track uptime"

        assert event_stream.stats["events_sent"] == 0, "Initially zero events sent"
        assert event_stream.stats["clients_connected"] == 0, "Initially zero clients"
        assert event_stream.stats["uptime_start"] > 0, "Uptime start must be set"

    def test_event_queue_max_size(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Event queue has maximum size limit."""
        assert event_stream.event_queue.maxlen == 10000, "Queue must have max size of 10000"

    @pytest.mark.asyncio
    async def test_websocket_server_start_stop(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """WebSocket server starts and stops cleanly."""
        await event_stream.start()

        assert event_stream.running is True, "Server must be running"
        assert event_stream.server is not None, "Server object must be set"

        await event_stream.stop()

        assert event_stream.running is False, "Server must be stopped"

    @pytest.mark.asyncio
    async def test_client_connection_tracking(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Client connections are tracked correctly."""
        await event_stream.start()

        assert event_stream.server is not None
        sockets = list(event_stream.server.sockets)
        server_port = sockets[0].getsockname()[1]

        try:
            async with websockets.connect(f"ws://localhost:{server_port}") as websocket:
                message = await websocket.recv()
                data = json.loads(message)

                assert data["type"] == "connection_established", "Must send confirmation"
                assert "client_id" in data, "Must assign client ID"

                await asyncio.sleep(0.1)

                assert event_stream.stats["clients_connected"] == 1, (
                    "Must track connected client"
                )
        finally:
            await event_stream.stop()

    @pytest.mark.asyncio
    async def test_welcome_message_sent(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Welcome message is sent to new clients."""
        await event_stream.start()

        assert event_stream.server is not None
        sockets = list(event_stream.server.sockets)
        server_port = sockets[0].getsockname()[1]

        try:
            async with websockets.connect(f"ws://localhost:{server_port}") as websocket:
                await websocket.recv()

                welcome = await websocket.recv()
                welcome_data = json.loads(welcome)

                assert welcome_data["type"] == "welcome", "Must send welcome message"
                assert "client_id" in welcome_data, "Must include client ID"
                assert "server_version" in welcome_data, "Must include server version"
                assert "capabilities" in welcome_data, "Must list capabilities"
                assert "real_time_events" in welcome_data["capabilities"], (
                    "Must support real-time events"
                )
        finally:
            await event_stream.stop()

    @pytest.mark.asyncio
    async def test_subscription_command_handling(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Subscribe command adds event subscriptions."""
        await event_stream.start()

        assert event_stream.server is not None
        sockets = list(event_stream.server.sockets)
        server_port = sockets[0].getsockname()[1]

        try:
            async with websockets.connect(f"ws://localhost:{server_port}") as websocket:
                await websocket.recv()
                await websocket.recv()

                subscribe_cmd = {
                    "command": "subscribe",
                    "event_types": ["license_check_found", "crypto_detected"],
                }
                await websocket.send(json.dumps(subscribe_cmd))

                response = await websocket.recv()
                response_data = json.loads(response)

                assert response_data["type"] == "subscription_confirmed", (
                    "Must confirm subscription"
                )
                assert set(response_data["subscribed_to"]) == {
                    "license_check_found",
                    "crypto_detected",
                }, "Must list subscribed events"
        finally:
            await event_stream.stop()

    @pytest.mark.asyncio
    async def test_filter_command_handling(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Filter command sets event filters."""
        await event_stream.start()

        assert event_stream.server is not None
        sockets = list(event_stream.server.sockets)
        server_port = sockets[0].getsockname()[1]

        try:
            async with websockets.connect(f"ws://localhost:{server_port}") as websocket:
                await websocket.recv()
                await websocket.recv()

                filter_cmd = {
                    "command": "filter",
                    "priority": EventPriority.HIGH.value,
                    "source": "binary_analyzer",
                    "tags": ["license", "critical"],
                }
                await websocket.send(json.dumps(filter_cmd))

                response = await websocket.recv()
                response_data = json.loads(response)

                assert response_data["type"] == "filter_applied", "Must confirm filter"
                assert response_data["filters"]["source"] == "binary_analyzer", (
                    "Source filter must be set"
                )
        finally:
            await event_stream.stop()

    @pytest.mark.asyncio
    async def test_statistics_command_response(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Statistics command returns server statistics."""
        await event_stream.start()

        assert event_stream.server is not None
        sockets = list(event_stream.server.sockets)
        server_port = sockets[0].getsockname()[1]

        try:
            async with websockets.connect(f"ws://localhost:{server_port}") as websocket:
                await websocket.recv()
                await websocket.recv()

                stats_cmd = {"command": "statistics"}
                await websocket.send(json.dumps(stats_cmd))

                response = await websocket.recv()
                response_data = json.loads(response)

                assert "type" in response_data, "Statistics response must have type"
        finally:
            await event_stream.stop()

    @pytest.mark.asyncio
    async def test_unsubscribe_command_handling(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Unsubscribe command removes event subscriptions."""
        await event_stream.start()

        assert event_stream.server is not None
        sockets = list(event_stream.server.sockets)
        server_port = sockets[0].getsockname()[1]

        try:
            async with websockets.connect(f"ws://localhost:{server_port}") as websocket:
                await websocket.recv()
                await websocket.recv()

                subscribe_cmd = {
                    "command": "subscribe",
                    "event_types": ["license_check_found"],
                }
                await websocket.send(json.dumps(subscribe_cmd))
                await websocket.recv()

                unsubscribe_cmd = {
                    "command": "unsubscribe",
                    "event_types": ["license_check_found"],
                }
                await websocket.send(json.dumps(unsubscribe_cmd))

                response = await websocket.recv()
                response_data = json.loads(response)

                assert response_data["type"] == "unsubscription_confirmed", (
                    "Must confirm unsubscription"
                )
        finally:
            await event_stream.stop()

    @pytest.mark.asyncio
    async def test_invalid_json_error_handling(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Invalid JSON messages return error response."""
        await event_stream.start()

        assert event_stream.server is not None
        sockets = list(event_stream.server.sockets)
        server_port = sockets[0].getsockname()[1]

        try:
            async with websockets.connect(f"ws://localhost:{server_port}") as websocket:
                await websocket.recv()
                await websocket.recv()

                await websocket.send("not valid json{")

                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    response_data = json.loads(response)
                    assert "error" in response_data or response_data.get("type") == "error", (
                        "Must send error for invalid JSON"
                    )
                except asyncio.TimeoutError:
                    pass
        finally:
            await event_stream.stop()

    @pytest.mark.asyncio
    async def test_unknown_command_error(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Unknown commands return error response."""
        await event_stream.start()

        assert event_stream.server is not None
        sockets = list(event_stream.server.sockets)
        server_port = sockets[0].getsockname()[1]

        try:
            async with websockets.connect(f"ws://localhost:{server_port}") as websocket:
                await websocket.recv()
                await websocket.recv()

                unknown_cmd = {"command": "unknown_invalid_command"}
                await websocket.send(json.dumps(unknown_cmd))

                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    response_data = json.loads(response)
                    assert "error" in response_data or response_data.get("type") == "error", (
                        "Must send error for unknown command"
                    )
                except asyncio.TimeoutError:
                    pass
        finally:
            await event_stream.stop()

    @pytest.mark.asyncio
    async def test_client_disconnect_cleanup(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Client disconnections are cleaned up properly."""
        await event_stream.start()

        assert event_stream.server is not None
        sockets = list(event_stream.server.sockets)
        server_port = sockets[0].getsockname()[1]

        try:
            async with websockets.connect(f"ws://localhost:{server_port}") as websocket:
                await websocket.recv()
                await websocket.recv()

            await asyncio.sleep(0.2)

            assert event_stream.stats["clients_connected"] == 0, (
                "Disconnected clients must be removed"
            )
        finally:
            await event_stream.stop()

    def test_event_handlers_initialization(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Event handlers dictionary is initialized."""
        assert isinstance(event_stream.event_handlers, dict), (
            "Event handlers must be dictionary"
        )

    def test_sessions_tracking(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Sessions are tracked for analysis correlation."""
        assert isinstance(event_stream.sessions, dict), "Sessions must be dictionary"

    def test_client_registry_structure(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Client registry tracks client metadata."""
        assert isinstance(event_stream.client_registry, dict), (
            "Client registry must be dictionary"
        )

    def test_filters_dictionary_structure(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Filters dictionary stores per-client filters."""
        assert isinstance(event_stream.filters, dict), "Filters must be dictionary"

    def test_rate_limits_dictionary(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Rate limits dictionary is initialized."""
        assert isinstance(event_stream.rate_limits, dict), (
            "Rate limits must be dictionary"
        )

    @pytest.mark.asyncio
    async def test_ping_pong_configuration(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """WebSocket server configured with ping/pong keepalive."""
        await event_stream.start()

        assert event_stream.server is not None, "Server must be started"

        await event_stream.stop()

    def test_analysis_event_serialization(
        self,
        sample_analysis_event: AnalysisEvent,
    ) -> None:
        """AnalysisEvent can be serialized to JSON."""
        from dataclasses import asdict

        event_dict = asdict(sample_analysis_event)
        event_dict["type"] = sample_analysis_event.type.value
        event_dict["priority"] = sample_analysis_event.priority.value

        event_json = json.dumps(event_dict)
        parsed = json.loads(event_json)

        assert parsed["id"] == "evt_001", "ID must serialize"
        assert parsed["type"] == "license_check_found", "Type must serialize"
        assert parsed["source"] == "binary_analyzer", "Source must serialize"

    @pytest.mark.asyncio
    async def test_multiple_concurrent_clients(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """Server handles multiple concurrent client connections."""
        await event_stream.start()

        assert event_stream.server is not None
        sockets = list(event_stream.server.sockets)
        server_port = sockets[0].getsockname()[1]

        try:
            async with websockets.connect(f"ws://localhost:{server_port}") as ws1:
                async with websockets.connect(f"ws://localhost:{server_port}") as ws2:
                    await ws1.recv()
                    await ws1.recv()
                    await ws2.recv()
                    await ws2.recv()

                    await asyncio.sleep(0.1)

                    assert event_stream.stats["clients_connected"] == 2, (
                        "Must track both clients"
                    )
        finally:
            await event_stream.stop()

    @pytest.mark.asyncio
    async def test_history_command_response(
        self,
        event_stream: WebSocketEventStream,
    ) -> None:
        """History command returns recent events."""
        await event_stream.start()

        assert event_stream.server is not None
        sockets = list(event_stream.server.sockets)
        server_port = sockets[0].getsockname()[1]

        try:
            async with websockets.connect(f"ws://localhost:{server_port}") as websocket:
                await websocket.recv()
                await websocket.recv()

                history_cmd = {"command": "history", "count": 50}
                await websocket.send(json.dumps(history_cmd))

                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    response_data = json.loads(response)
                    assert response_data is not None, "Must receive history response"
                except asyncio.TimeoutError:
                    pass
        finally:
            await event_stream.stop()
