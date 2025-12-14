"""Real-time WebSocket Event Streaming for Analysis Dashboard.

This module provides WebSocket-based real-time streaming of analysis events
from all Intellicrack components to the web dashboard for visualization and monitoring.

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
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

import websockets
from websockets.server import WebSocketServerProtocol


logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of analysis events."""

    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETE = "analysis_complete"
    FUNCTION_DISCOVERED = "function_discovered"
    STRING_FOUND = "string_found"
    CRYPTO_DETECTED = "crypto_detected"
    LICENSE_CHECK_FOUND = "license_check_found"
    PROTECTION_DETECTED = "protection_detected"
    PATCH_APPLIED = "patch_applied"
    BREAKPOINT_HIT = "breakpoint_hit"
    API_CALL = "api_call"
    MEMORY_DUMP = "memory_dump"
    KEY_EXTRACTED = "key_extracted"
    SERIAL_GENERATED = "serial_generated"
    ACTIVATION_BYPASSED = "activation_bypassed"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    PROGRESS = "progress"
    CONTROL_FLOW = "control_flow"
    DATA_FLOW = "data_flow"
    CORRELATION = "correlation"


class EventPriority(Enum):
    """Event priority levels."""

    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


@dataclass
class AnalysisEvent:
    """Analysis event data structure."""

    id: str
    type: EventType
    timestamp: float
    source: str
    target: str | None
    data: dict[str, Any]
    priority: EventPriority
    tags: list[str]
    session_id: str


class WebSocketEventStream:
    """WebSocket-based real-time event streaming system."""

    def __init__(self, host: str = "localhost", port: int = 8765) -> None:
        """Initialize WebSocket stream server."""
        self.host = host
        self.port = port
        self.clients: set[WebSocketServerProtocol] = set()
        self.client_registry: dict[WebSocketServerProtocol, dict[str, Any]] = {}
        self.event_queue: deque = deque(maxlen=10000)
        self.event_handlers: dict[EventType, list[Callable]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.server = None
        self.running = False

        # Statistics
        self.stats = {
            "events_sent": 0,
            "events_received": 0,
            "clients_connected": 0,
            "clients_total": 0,
            "uptime_start": time.time(),
        }

        # Event filters
        self.filters: dict[str, dict[str, Any]] = {}

        # Rate limiting
        self.rate_limits: dict[str, dict[str, Any]] = {}

    async def start(self) -> None:
        """Start WebSocket server."""
        self.running = True
        self.server = await websockets.serve(self.handle_client, self.host, self.port, ping_interval=20, ping_timeout=10)
        logger.info(f"WebSocket stream server started on ws://{self.host}:{self.port}")

        # Start background tasks
        broadcaster_task = asyncio.create_task(self._event_broadcaster())
        stats_task = asyncio.create_task(self._statistics_updater())
        # Store task references to prevent garbage collection
        self._background_tasks = [broadcaster_task, stats_task]

    async def stop(self) -> None:
        """Stop WebSocket server."""
        self.running = False

        # Close all client connections
        for client in list(self.clients):
            await client.close()

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        logger.info("WebSocket stream server stopped")

    async def handle_client(self, websocket: WebSocketServerProtocol, path: str) -> None:
        """Handle new WebSocket client connection."""
        client_id = str(uuid.uuid4())
        client_info = {
            "id": client_id,
            "connected_at": time.time(),
            "remote_address": websocket.remote_address,
            "path": path,
            "filters": {},
            "subscriptions": set(),
        }

        # Add to clients and registry
        self.clients.add(websocket)
        self.client_registry[websocket] = client_info
        self.stats["clients_connected"] += 1
        self.stats["clients_total"] += 1

        logger.info(f"Client {client_id} connected from {websocket.remote_address} to path {path}")

        # Send initial connection confirmation
        await websocket.send(
            json.dumps({
                "type": "connection_established",
                "client_id": client_id,
                "timestamp": client_info["connected_at"],
            }),
        )

        # Send welcome message
        await self._send_welcome(websocket, client_id)

        try:
            # Handle client messages
            async for message in websocket:
                await self._handle_client_message(websocket, client_id, message)

        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client {client_id} disconnected")
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            # Remove client
            self.clients.discard(websocket)
            if websocket in self.client_registry:
                del self.client_registry[websocket]
            self.stats["clients_connected"] -= 1

            # Clean up filters and subscriptions
            if client_id in self.filters:
                del self.filters[client_id]
            if client_id in self.rate_limits:
                del self.rate_limits[client_id]

    async def _send_welcome(self, websocket: WebSocketServerProtocol, client_id: str) -> None:
        """Send welcome message to new client."""
        welcome = {
            "type": "welcome",
            "client_id": client_id,
            "server_version": "1.0.0",
            "timestamp": time.time(),
            "capabilities": [
                "real_time_events",
                "filtering",
                "subscriptions",
                "control_commands",
                "statistics",
            ],
        }
        await websocket.send(json.dumps(welcome))

    async def _handle_client_message(self, websocket: WebSocketServerProtocol, client_id: str, message: str) -> None:
        """Handle message from client."""
        try:
            data = json.loads(message)
            command = data.get("command")

            if command == "subscribe":
                await self._handle_subscribe(websocket, client_id, data)
            elif command == "unsubscribe":
                await self._handle_unsubscribe(websocket, client_id, data)
            elif command == "filter":
                await self._handle_filter(websocket, client_id, data)
            elif command == "control":
                await self._handle_control(websocket, client_id, data)
            elif command == "statistics":
                await self._send_statistics(websocket)
            elif command == "history":
                await self._send_history(websocket, data.get("count", 100))
            else:
                await self._send_error(websocket, f"Unknown command: {command}")

        except json.JSONDecodeError:
            await self._send_error(websocket, "Invalid JSON message")
        except Exception as e:
            await self._send_error(websocket, str(e))

    async def _handle_subscribe(self, websocket: WebSocketServerProtocol, client_id: str, data: dict[str, Any]) -> None:
        """Handle event subscription request."""
        event_types = data.get("event_types", [])

        if client_id not in self.filters:
            self.filters[client_id] = {"subscriptions": set()}

        for event_type in event_types:
            try:
                event_enum = EventType(event_type)
                self.filters[client_id]["subscriptions"].add(event_enum)
            except ValueError:
                await self._send_error(websocket, f"Invalid event type: {event_type}")

        # Send confirmation
        await websocket.send(json.dumps({"type": "subscription_confirmed", "subscribed_to": event_types}))

    async def _handle_unsubscribe(self, websocket: WebSocketServerProtocol, client_id: str, data: dict[str, Any]) -> None:
        """Handle unsubscribe request."""
        event_types = data.get("event_types", [])

        if client_id in self.filters:
            for event_type in event_types:
                try:
                    event_enum = EventType(event_type)
                    self.filters[client_id]["subscriptions"].discard(event_enum)
                except ValueError:
                    pass

        # Send confirmation
        await websocket.send(json.dumps({"type": "unsubscription_confirmed", "unsubscribed_from": event_types}))

    async def _handle_filter(self, websocket: WebSocketServerProtocol, client_id: str, data: dict[str, Any]) -> None:
        """Handle filter configuration."""
        if client_id not in self.filters:
            self.filters[client_id] = {}

        # Set filters
        if "priority" in data:
            self.filters[client_id]["priority"] = EventPriority(data["priority"])
        if "source" in data:
            self.filters[client_id]["source"] = data["source"]
        if "tags" in data:
            self.filters[client_id]["tags"] = set(data["tags"])

        # Send confirmation
        await websocket.send(
            json.dumps(
                {
                    "type": "filter_applied",
                    "filters": {
                        "priority": self.filters[client_id].get("priority", "").value if "priority" in self.filters[client_id] else None,
                        "source": self.filters[client_id].get("source"),
                        "tags": list(self.filters[client_id].get("tags", [])),
                    },
                },
            ),
        )

    async def _handle_control(self, websocket: WebSocketServerProtocol, client_id: str, data: dict[str, Any]) -> None:
        """Handle control commands from client."""
        action = data.get("action")
        target = data.get("target")
        params = data.get("params", {})

        # Execute control action
        result = await self._execute_control_action(action, target, params)

        # Send result
        await websocket.send(
            json.dumps(
                {
                    "type": "control_result",
                    "action": action,
                    "target": target,
                    "success": result["success"],
                    "data": result.get("data"),
                },
            ),
        )

    async def _execute_control_action(self, action: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute control action on analysis components."""
        result = {"success": False, "data": None}

        if action == "configure":
            # Configure analysis parameters
            self.publish_event(
                AnalysisEvent(
                    id=str(uuid.uuid4()),
                    type=EventType.INFO,
                    timestamp=time.time(),
                    source="dashboard",
                    target=target,
                    data={"action": "configure", "params": params},
                    priority=EventPriority.MEDIUM,
                    tags=["control", "configuration"],
                    session_id="",
                ),
            )
            result["success"] = True
            result["data"] = params

        elif action == "pause":
            # Pause analysis on target
            self.publish_event(
                AnalysisEvent(
                    id=str(uuid.uuid4()),
                    type=EventType.INFO,
                    timestamp=time.time(),
                    source="dashboard",
                    target=target,
                    data={"action": "pause"},
                    priority=EventPriority.HIGH,
                    tags=["control"],
                    session_id="",
                ),
            )
            result["success"] = True

        elif action == "resume":
            # Resume analysis on target
            self.publish_event(
                AnalysisEvent(
                    id=str(uuid.uuid4()),
                    type=EventType.INFO,
                    timestamp=time.time(),
                    source="dashboard",
                    target=target,
                    data={"action": "resume"},
                    priority=EventPriority.HIGH,
                    tags=["control"],
                    session_id="",
                ),
            )
            result["success"] = True

        elif action == "stop":
            # Stop analysis on target
            self.publish_event(
                AnalysisEvent(
                    id=str(uuid.uuid4()),
                    type=EventType.INFO,
                    timestamp=time.time(),
                    source="dashboard",
                    target=target,
                    data={"action": "stop"},
                    priority=EventPriority.HIGH,
                    tags=["control"],
                    session_id="",
                ),
            )
            result["success"] = True

        return result

    async def _send_statistics(self, websocket: WebSocketServerProtocol) -> None:
        """Send server statistics to client."""
        uptime = time.time() - self.stats["uptime_start"]

        stats = {
            "type": "statistics",
            "data": {
                "events_sent": self.stats["events_sent"],
                "events_received": self.stats["events_received"],
                "clients_connected": self.stats["clients_connected"],
                "clients_total": self.stats["clients_total"],
                "queue_size": len(self.event_queue),
                "uptime_seconds": uptime,
                "uptime_formatted": self._format_uptime(uptime),
            },
        }
        await websocket.send(json.dumps(stats))

    async def _send_history(self, websocket: WebSocketServerProtocol, count: int) -> None:
        """Send event history to client."""
        # Get recent events from queue
        events = list(self.event_queue)[-count:]

        # Convert to JSON-serializable format
        history = []
        for event in events:
            event_dict = asdict(event)
            event_dict["type"] = event.type.value
            event_dict["priority"] = event.priority.value
            history.append(event_dict)

        await websocket.send(json.dumps({"type": "history", "count": len(history), "events": history}))

    async def _send_error(self, websocket: WebSocketServerProtocol, error: str) -> None:
        """Send error message to client."""
        await websocket.send(json.dumps({"type": "error", "message": error, "timestamp": time.time()}))

    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human-readable format."""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{secs}s")

        return " ".join(parts)

    async def _event_broadcaster(self) -> None:
        """Broadcast events to connected clients."""
        while self.running:
            if self.event_queue and self.clients:
                batch = [self.event_queue.popleft() for _ in range(min(10, len(self.event_queue))) if self.event_queue]
                # Broadcast to clients
                for event in batch:
                    await self._broadcast_event(event)

            await asyncio.sleep(0.01)  # Small delay to prevent CPU spinning

    async def _broadcast_event(self, event: AnalysisEvent) -> None:
        """Broadcast event to all connected clients."""
        # Convert event to JSON
        event_dict = asdict(event)
        event_dict["type"] = event.type.value
        event_dict["priority"] = event.priority.value

        # Send to each client based on their filters
        disconnected_clients = []
        for client in self.clients:
            try:
                # Check if client should receive this event
                client_id = self._get_client_id(client)
                if self._should_send_to_client(client_id, event) and not self._is_rate_limited(client_id):
                    await client.send(json.dumps({"type": "event", "event": event_dict}))
                    self.stats["events_sent"] += 1

            except websockets.exceptions.ConnectionClosed:
                disconnected_clients.append(client)
            except Exception as e:
                logger.error(f"Error broadcasting to client: {e}")

        # Remove disconnected clients
        for client in disconnected_clients:
            self.clients.discard(client)

    def _get_client_id(self, websocket: WebSocketServerProtocol) -> str:
        """Get client ID from websocket connection."""
        # In production, maintain proper client ID mapping
        return id(websocket)

    def _should_send_to_client(self, client_id: str, event: AnalysisEvent) -> bool:
        """Check if event should be sent to specific client."""
        if client_id not in self.filters:
            return True  # No filters, send everything

        filters = self.filters[client_id]

        # Check subscriptions
        if "subscriptions" in filters and event.type not in filters["subscriptions"]:
            return False

        # Check priority filter
        if "priority" in filters and event.priority.value > filters["priority"].value:
            return False

        # Check source filter
        if "source" in filters and event.source != filters["source"]:
            return False

        # Check tag filters
        return not ("tags" in filters and all(tag not in event.tags for tag in filters["tags"]))

    def _is_rate_limited(self, client_id: str) -> bool:
        """Check if client is rate limited."""
        if client_id not in self.rate_limits:
            self.rate_limits[client_id] = {"messages": 0, "reset_time": time.time() + 1.0}

        rate_limit = self.rate_limits[client_id]

        # Reset counter if time window expired
        if time.time() > rate_limit["reset_time"]:
            rate_limit["messages"] = 0
            rate_limit["reset_time"] = time.time() + 1.0

        # Check limit (100 messages per second)
        if rate_limit["messages"] >= 100:
            return True

        rate_limit["messages"] += 1
        return False

    async def _statistics_updater(self) -> None:
        """Periodically broadcast statistics."""
        while self.running:
            await asyncio.sleep(30)  # Update every 30 seconds

            # Broadcast statistics event
            stats_event = AnalysisEvent(
                id=str(uuid.uuid4()),
                type=EventType.INFO,
                timestamp=time.time(),
                source="websocket_server",
                target=None,
                data={
                    "events_sent": self.stats["events_sent"],
                    "events_received": self.stats["events_received"],
                    "clients_connected": self.stats["clients_connected"],
                    "queue_size": len(self.event_queue),
                },
                priority=EventPriority.LOW,
                tags=["statistics", "monitoring"],
                session_id="",
            )

            self.event_queue.append(stats_event)

    def publish_event(self, event: AnalysisEvent) -> None:
        """Publish analysis event to stream."""
        self.event_queue.append(event)
        self.stats["events_received"] += 1

        # Call event handlers
        if event.type in self.event_handlers:
            for handler in self.event_handlers[event.type]:
                try:
                    handler(event)
                except Exception as e:
                    logger.error(f"Event handler error: {e}")

    def register_event_handler(self, event_type: EventType, handler: Callable) -> None:
        """Register handler for specific event type."""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)

    def create_session(self, session_id: str, metadata: dict[str, Any]) -> None:
        """Create new analysis session."""
        self.sessions[session_id] = {
            "id": session_id,
            "created_at": time.time(),
            "metadata": metadata,
            "events": [],
        }

        # Publish session start event
        self.publish_event(
            AnalysisEvent(
                id=str(uuid.uuid4()),
                type=EventType.ANALYSIS_STARTED,
                timestamp=time.time(),
                source="session_manager",
                target=None,
                data={"session_id": session_id, "metadata": metadata},
                priority=EventPriority.HIGH,
                tags=["session", "start"],
                session_id=session_id,
            ),
        )

    def end_session(self, session_id: str) -> None:
        """End analysis session."""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            duration = time.time() - session["created_at"]

            # Publish session end event
            self.publish_event(
                AnalysisEvent(
                    id=str(uuid.uuid4()),
                    type=EventType.ANALYSIS_COMPLETE,
                    timestamp=time.time(),
                    source="session_manager",
                    target=None,
                    data={
                        "session_id": session_id,
                        "duration": duration,
                        "event_count": len(session["events"]),
                    },
                    priority=EventPriority.HIGH,
                    tags=["session", "end"],
                    session_id=session_id,
                ),
            )

            del self.sessions[session_id]


class EventPublisher:
    """Helper class for publishing events from analysis components."""

    def __init__(self, stream: WebSocketEventStream, source: str) -> None:
        """Initialize event publisher."""
        self.stream = stream
        self.source = source

    def publish(
        self,
        event_type: EventType,
        data: dict[str, Any],
        target: str | None = None,
        priority: EventPriority = EventPriority.MEDIUM,
        tags: list[str] | None = None,
        session_id: str = "",
    ) -> None:
        """Publish event to stream."""
        event = AnalysisEvent(
            id=str(uuid.uuid4()),
            type=event_type,
            timestamp=time.time(),
            source=self.source,
            target=target,
            data=data,
            priority=priority,
            tags=tags or [],
            session_id=session_id,
        )
        self.stream.publish_event(event)

    def function_discovered(self, address: int, name: str, size: int) -> None:
        """Publish function discovery event."""
        self.publish(
            EventType.FUNCTION_DISCOVERED,
            {"address": f"0x{address:x}", "name": name, "size": size},
            tags=["discovery", "function"],
        )

    def string_found(self, address: int, value: str) -> None:
        """Publish string discovery event."""
        self.publish(
            EventType.STRING_FOUND,
            {"address": f"0x{address:x}", "value": value[:100]},
            tags=["discovery", "string"],
        )

    def crypto_detected(self, algorithm: str, address: int) -> None:
        """Publish crypto detection event."""
        self.publish(
            EventType.CRYPTO_DETECTED,
            {"algorithm": algorithm, "address": f"0x{address:x}"},
            priority=EventPriority.HIGH,
            tags=["crypto", "detection"],
        )

    def license_check_found(self, check_type: str, address: int) -> None:
        """Publish license check discovery event."""
        self.publish(
            EventType.LICENSE_CHECK_FOUND,
            {"type": check_type, "address": f"0x{address:x}"},
            priority=EventPriority.HIGH,
            tags=["license", "detection"],
        )

    def patch_applied(self, address: int, description: str) -> None:
        """Publish patch application event."""
        self.publish(
            EventType.PATCH_APPLIED,
            {"address": f"0x{address:x}", "description": description},
            priority=EventPriority.CRITICAL,
            tags=["patch", "modification"],
        )

    def progress(self, percentage: float, message: str) -> None:
        """Publish progress update."""
        self.publish(
            EventType.PROGRESS,
            {"percentage": percentage, "message": message},
            priority=EventPriority.LOW,
            tags=["progress", "status"],
        )
