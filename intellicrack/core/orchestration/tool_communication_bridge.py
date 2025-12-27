"""Real-time Inter-Process Communication Bridge for Analysis Tools.

This module provides a robust IPC system for orchestrating communication between
different analysis tools (Ghidra, Frida, Radare2, IDA Pro, x64dbg) with message
passing, result synchronization, and event streaming.

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
import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, cast

import msgpack
import zmq
import zmq.asyncio


logger = logging.getLogger(__name__)


class MessageType(Enum):
    """IPC message types for tool communication."""

    ANALYSIS_REQUEST = "analysis_request"
    ANALYSIS_RESULT = "analysis_result"
    FUNCTION_DISCOVERED = "function_discovered"
    STRING_FOUND = "string_found"
    CRYPTO_DETECTED = "crypto_detected"
    LICENSE_CHECK_FOUND = "license_check_found"
    PATCH_APPLIED = "patch_applied"
    BREAKPOINT_HIT = "breakpoint_hit"
    API_CALL_INTERCEPTED = "api_call_intercepted"
    MEMORY_DUMP = "memory_dump"
    REGISTER_STATE = "register_state"
    CONTROL_FLOW = "control_flow"
    SYMBOL_RESOLVED = "symbol_resolved"
    PROTECTION_DETECTED = "protection_detected"
    KEYGEN_REQUEST = "keygen_request"
    KEYGEN_RESULT = "keygen_result"
    SYNC_REQUEST = "sync_request"
    HEARTBEAT = "heartbeat"


class ToolType(Enum):
    """Analysis tool identifiers."""

    GHIDRA = "ghidra"
    FRIDA = "frida"
    RADARE2 = "radare2"
    IDA_PRO = "ida_pro"
    X64DBG = "x64dbg"
    YARA = "yara"
    ESIL = "esil"
    ORCHESTRATOR = "orchestrator"


@dataclass
class IPCMessage:
    """Structured IPC message for tool communication."""

    id: str
    source: ToolType
    destination: ToolType | None
    message_type: MessageType
    timestamp: float
    payload: dict[str, Any]
    correlation_id: str | None = None
    requires_response: bool = False
    priority: int = 5

    def to_bytes(self) -> bytes:
        """Serialize message to bytes using msgpack."""
        data_dict = asdict(self)
        data_dict["source"] = self.source.value
        data_dict["destination"] = self.destination.value if self.destination else None
        data_dict["message_type"] = self.message_type.value
        return cast("bytes", msgpack.packb(data_dict))

    @classmethod
    def from_bytes(cls, data: bytes) -> "IPCMessage":
        """Deserialize message from bytes."""
        msg_dict = msgpack.unpackb(data, raw=False)
        msg_dict["source"] = ToolType(msg_dict["source"])
        if msg_dict["destination"]:
            msg_dict["destination"] = ToolType(msg_dict["destination"])
        msg_dict["message_type"] = MessageType(msg_dict["message_type"])
        return cls(**msg_dict)


class ToolCommunicationBridge:
    """Central communication bridge for all analysis tools."""

    def __init__(self, orchestrator_port: int = 5555, auth_key: str | None = None) -> None:
        """Initialize the communication bridge."""
        self.orchestrator_port = orchestrator_port
        self.auth_key = auth_key or self._generate_auth_key()

        # ZeroMQ context and sockets
        self.context: zmq.Context[zmq.Socket[bytes]] = zmq.Context()
        self.publisher: zmq.Socket[bytes] | None = None
        self.subscriber: zmq.Socket[bytes] | None = None
        self.router: zmq.Socket[bytes] | None = None
        self.dealer_sockets: dict[ToolType, zmq.Socket[bytes]] = {}

        # Message handling
        self.message_handlers: dict[MessageType, list[Callable[[IPCMessage], Any]]] = defaultdict(list)
        self.pending_responses: dict[str, asyncio.Future[IPCMessage]] = {}
        self.message_history: list[IPCMessage] = []
        self.tool_registry: dict[ToolType, dict[str, Any]] = {}

        # Thread management
        self.running = False
        self.router_thread: threading.Thread | None = None
        self.subscriber_thread: threading.Thread | None = None

        # Performance metrics
        self.message_stats: dict[MessageType, int] = defaultdict(int)
        self.latency_stats: dict[MessageType, list[float]] = defaultdict(list)

        # Timeout configuration
        self.response_timeout: float = 30.0

    def _generate_auth_key(self) -> str:
        """Generate secure authentication key for IPC."""
        return hashlib.sha256(uuid.uuid4().bytes).hexdigest()

    def start(self) -> None:
        """Start the communication bridge."""
        self.running = True

        # Setup publisher socket for broadcasting
        pub_socket: zmq.Socket[bytes] = self.context.socket(zmq.PUB)
        pub_socket.bind(f"tcp://127.0.0.1:{self.orchestrator_port}")
        self.publisher = pub_socket

        # Setup router socket for request-reply
        router_socket: zmq.Socket[bytes] = self.context.socket(zmq.ROUTER)
        router_socket.bind(f"tcp://127.0.0.1:{self.orchestrator_port + 1}")
        self.router = router_socket

        # Setup subscriber for receiving broadcasts
        sub_socket: zmq.Socket[bytes] = self.context.socket(zmq.SUB)
        sub_socket.connect(f"tcp://127.0.0.1:{self.orchestrator_port}")
        sub_socket.setsockopt_string(zmq.SUBSCRIBE, "")
        self.subscriber = sub_socket

        # Start message processing threads
        router_thread = threading.Thread(target=self._router_loop, daemon=True)
        router_thread.start()
        self.router_thread = router_thread

        subscriber_thread = threading.Thread(target=self._subscriber_loop, daemon=True)
        subscriber_thread.start()
        self.subscriber_thread = subscriber_thread

        logger.info("Communication bridge started on port %d", self.orchestrator_port)

    def stop(self) -> None:
        """Stop the communication bridge."""
        self.running = False

        if self.publisher is not None:
            self.publisher.close()
        if self.subscriber is not None:
            self.subscriber.close()
        if self.router is not None:
            self.router.close()

        for socket in self.dealer_sockets.values():
            socket.close()

        self.context.term()
        logger.info("Communication bridge stopped")

    def register_tool(self, tool_type: ToolType, capabilities: dict[str, Any]) -> str:
        """Register a tool with the communication bridge."""
        tool_id = str(uuid.uuid4())

        self.tool_registry[tool_type] = {
            "id": tool_id,
            "capabilities": capabilities,
            "registered_at": time.time(),
            "last_heartbeat": time.time(),
            "status": "active",
        }

        # Create dealer socket for this tool
        dealer = self.context.socket(zmq.DEALER)
        dealer.connect(f"tcp://127.0.0.1:{self.orchestrator_port + 1}")
        dealer.setsockopt_string(zmq.IDENTITY, tool_id)
        self.dealer_sockets[tool_type] = dealer

        logger.info("Registered tool %s with ID %s", tool_type.value, tool_id)
        return tool_id

    def unregister_tool(self, tool_type: ToolType) -> None:
        """Unregister a tool from the bridge."""
        if tool_type in self.tool_registry:
            del self.tool_registry[tool_type]

        if tool_type in self.dealer_sockets:
            self.dealer_sockets[tool_type].close()
            del self.dealer_sockets[tool_type]

        logger.info("Unregistered tool %s", tool_type.value)

    def send_message(self, message: IPCMessage) -> str | None:
        """Send a message to a specific tool or broadcast."""
        # Add authentication
        message.payload["auth"] = self._generate_message_auth(message)

        # Record statistics
        self.message_stats[message.message_type] += 1
        self.message_history.append(message)

        # Trim history if too large
        if len(self.message_history) > 10000:
            self.message_history = self.message_history[-5000:]

        if message.destination:
            # Point-to-point message
            if message.destination in self.dealer_sockets:
                socket = self.dealer_sockets[message.destination]
                socket.send(message.to_bytes())
                logger.debug("Sent %s to %s", message.message_type.value, message.destination.value)

                if message.requires_response:
                    future: asyncio.Future[IPCMessage] = asyncio.Future()
                    self.pending_responses[message.id] = future
                    return message.id
        elif self.publisher is not None:
            self.publisher.send_multipart([message.source.value.encode(), message.to_bytes()])
            logger.debug("Broadcast %s from %s", message.message_type.value, message.source.value)

        return None

    def _generate_message_auth(self, message: IPCMessage) -> str:
        """Generate HMAC authentication for message."""
        msg_bytes = json.dumps(
            {
                "id": message.id,
                "source": message.source.value,
                "type": message.message_type.value,
                "timestamp": message.timestamp,
            },
        ).encode()

        return hmac.new(self.auth_key.encode(), msg_bytes, hashlib.sha256).hexdigest()

    def _verify_message_auth(self, message: IPCMessage) -> bool:
        """Verify message authentication."""
        if "auth" not in message.payload:
            return False

        expected_auth = self._generate_message_auth(message)
        return hmac.compare_digest(message.payload["auth"], expected_auth)

    def add_message_handler(self, message_type: MessageType, handler: Callable[[IPCMessage], Any]) -> None:
        """Add a message handler for a specific message type."""
        if message_type not in self.message_handlers:
            self.message_handlers[message_type] = []
        self.message_handlers[message_type].append(handler)

    async def send_and_wait(self, message: IPCMessage) -> IPCMessage | None:
        """Send message and wait for response."""
        message.requires_response = True
        msg_id = self.send_message(message)

        if msg_id and msg_id in self.pending_responses:
            try:
                future = self.pending_responses[msg_id]
                async with asyncio.timeout(self.response_timeout):
                    response: IPCMessage = await future
                del self.pending_responses[msg_id]
                return response
            except TimeoutError:
                logger.warning("Timeout waiting for response to %s", msg_id)
                del self.pending_responses[msg_id]
                return None

        return None

    def register_handler(self, message_type: MessageType, handler: Callable[[IPCMessage], Any]) -> None:
        """Register a message handler for specific message type."""
        self.message_handlers[message_type].append(handler)
        logger.debug("Registered handler for %s", message_type.value)

    def _router_loop(self) -> None:
        """Process request-reply messages."""
        if self.router is None:
            logger.error("Router socket is not initialized")
            return

        poller = zmq.Poller()
        poller.register(self.router, zmq.POLLIN)

        while self.running:
            try:
                sockets = dict(poller.poll(100))

                if self.router in sockets:
                    identity = self.router.recv()
                    empty = self.router.recv()
                    msg_bytes = self.router.recv()

                    if empty != b"":
                        logger.warning("Invalid ZeroMQ router protocol: expected empty delimiter, got %s", empty[:20])
                        continue

                    message = IPCMessage.from_bytes(msg_bytes)

                    if not self._verify_message_auth(message):
                        logger.warning("Authentication failed for message %s", message.id)
                        continue

                    self._handle_message(message, identity)

            except Exception as e:
                logger.exception("Router loop error: %s", e)

    def _subscriber_loop(self) -> None:
        """Process broadcast messages."""
        if self.subscriber is None:
            logger.error("Subscriber socket is not initialized")
            return

        while self.running:
            try:
                if self.subscriber.poll(100):
                    _topic, msg_bytes = self.subscriber.recv_multipart()
                    message = IPCMessage.from_bytes(msg_bytes)

                    if not self._verify_message_auth(message):
                        logger.warning("Authentication failed for broadcast %s", message.id)
                        continue

                    self._handle_message(message, None)

            except Exception as e:
                logger.exception("Subscriber loop error: %s", e)

    def _handle_message(self, message: IPCMessage, identity: bytes | None) -> None:
        """Handle incoming message."""
        start_time = time.time()

        # Check if this is a response to a pending request
        if message.correlation_id and message.correlation_id in self.pending_responses:
            future = self.pending_responses[message.correlation_id]
            if not future.done():
                future.set_result(message)

        # Call registered handlers
        for handler in self.message_handlers.get(message.message_type, []):
            try:
                response = handler(message)

                # Send response if required
                if message.requires_response and response and identity and self.router is not None:
                    response_msg = IPCMessage(
                        id=str(uuid.uuid4()),
                        source=ToolType.ORCHESTRATOR,
                        destination=message.source,
                        message_type=MessageType.ANALYSIS_RESULT,
                        timestamp=time.time(),
                        payload=response,
                        correlation_id=message.id,
                        requires_response=False,
                    )

                    response_msg.payload["auth"] = self._generate_message_auth(response_msg)
                    self.router.send_multipart([identity, b"", response_msg.to_bytes()])

            except Exception as e:
                logger.exception("Handler error for %s: %s", message.message_type.value, e)

        # Record latency
        latency = time.time() - start_time
        self.latency_stats[message.message_type].append(latency)

    def broadcast_analysis_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Broadcast an analysis event to all tools."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.ORCHESTRATOR,
            destination=None,
            message_type=MessageType.ANALYSIS_RESULT,
            timestamp=time.time(),
            payload={"event_type": event_type, "data": data},
        )
        self.send_message(message)

    def request_cross_reference(self, address: int, tool_type: ToolType) -> dict[str, Any] | None:
        """Request cross-reference analysis from specific tool."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.ORCHESTRATOR,
            destination=tool_type,
            message_type=MessageType.ANALYSIS_REQUEST,
            timestamp=time.time(),
            payload={"operation": "cross_reference", "address": address},
            requires_response=True,
        )

        # Synchronous wrapper for async operation
        loop = asyncio.new_event_loop()
        response = loop.run_until_complete(self.send_and_wait(message))
        loop.close()

        return response.payload if response else None

    def synchronize_breakpoints(self, breakpoints: list[int]) -> None:
        """Synchronize breakpoints across all debugging tools."""
        for tool in [ToolType.FRIDA, ToolType.X64DBG, ToolType.RADARE2]:
            if tool in self.tool_registry:
                message = IPCMessage(
                    id=str(uuid.uuid4()),
                    source=ToolType.ORCHESTRATOR,
                    destination=tool,
                    message_type=MessageType.SYNC_REQUEST,
                    timestamp=time.time(),
                    payload={"sync_type": "breakpoints", "breakpoints": breakpoints},
                )
                self.send_message(message)

    def share_function_signature(self, address: int, signature: dict[str, Any]) -> None:
        """Share discovered function signature with all tools."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.ORCHESTRATOR,
            destination=None,
            message_type=MessageType.FUNCTION_DISCOVERED,
            timestamp=time.time(),
            payload={"address": address, "signature": signature},
        )
        self.send_message(message)

    def coordinate_patch_operation(self, patches: list[dict[str, Any]]) -> bool:
        """Coordinate patch operation across tools."""
        success = True

        # First, verify patches with Radare2
        verify_msg = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.ORCHESTRATOR,
            destination=ToolType.RADARE2,
            message_type=MessageType.ANALYSIS_REQUEST,
            timestamp=time.time(),
            payload={"operation": "verify_patches", "patches": patches},
            requires_response=True,
        )

        loop = asyncio.new_event_loop()
        verification = loop.run_until_complete(self.send_and_wait(verify_msg))
        loop.close()

        if not verification or not verification.payload.get("valid", False):
            logger.exception("Patch verification failed")
            return False

        # Apply patches
        for patch in patches:
            apply_msg = IPCMessage(
                id=str(uuid.uuid4()),
                source=ToolType.ORCHESTRATOR,
                destination=ToolType.RADARE2,
                message_type=MessageType.ANALYSIS_REQUEST,
                timestamp=time.time(),
                payload={"operation": "apply_patch", "patch": patch},
                requires_response=True,
            )

            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(self.send_and_wait(apply_msg))
            loop.close()

            if not result or not result.payload.get("success", False):
                success = False
                break

            # Notify other tools
            self.broadcast_analysis_event("patch_applied", patch)

        return success

    def get_tool_status(self) -> dict[ToolType, dict[str, Any]]:
        """Get status of all registered tools."""
        status: dict[ToolType, dict[str, Any]] = {}
        current_time = time.time()

        for tool_type, info in self.tool_registry.items():
            heartbeat_age = current_time - info["last_heartbeat"]
            total_messages = sum(count for msg_type, count in self.message_stats.items())
            status[tool_type] = {
                "id": info["id"],
                "status": "active" if heartbeat_age < 30 else "inactive",
                "capabilities": info["capabilities"],
                "last_heartbeat": heartbeat_age,
                "message_count": total_messages,
            }

        return status

    def get_performance_metrics(self) -> dict[str, Any]:
        """Get communication performance metrics."""
        average_latency: dict[str, dict[str, float]] = {
            msg_type.value: {
                "avg": sum(latencies) / len(latencies),
                "min": min(latencies),
                "max": max(latencies),
            }
            for msg_type, latencies in self.latency_stats.items()
            if latencies
        }
        metrics: dict[str, Any] = {
            "total_messages": sum(self.message_stats.values()),
            "message_types": dict(self.message_stats),
            "average_latency": average_latency,
            "tools_connected": len(self.tool_registry),
        }

        return metrics


class ToolConnector:
    """Client connector for individual tools to communicate with bridge."""

    def __init__(self, tool_type: ToolType, bridge_host: str = "127.0.0.1", bridge_port: int = 5555) -> None:
        """Initialize tool connector."""
        self.tool_type = tool_type
        self.bridge_host = bridge_host
        self.bridge_port = bridge_port
        self.tool_id: str | None = None

        self.context: zmq.Context[zmq.Socket[bytes]] = zmq.Context()
        self.dealer: zmq.Socket[bytes] | None = None
        self.subscriber: zmq.Socket[bytes] | None = None
        self.message_handlers: dict[MessageType, list[Callable[[IPCMessage], Any]]] = defaultdict(list)
        self.running = False

    def connect(self) -> str:
        """Connect to the communication bridge."""
        dealer_socket: zmq.Socket[bytes] = self.context.socket(zmq.DEALER)
        tool_id = str(uuid.uuid4())
        dealer_socket.setsockopt_string(zmq.IDENTITY, tool_id)
        dealer_socket.connect(f"tcp://{self.bridge_host}:{self.bridge_port + 1}")
        self.dealer = dealer_socket
        self.tool_id = tool_id

        subscriber_socket: zmq.Socket[bytes] = self.context.socket(zmq.SUB)
        subscriber_socket.connect(f"tcp://{self.bridge_host}:{self.bridge_port}")
        subscriber_socket.setsockopt_string(zmq.SUBSCRIBE, "")
        self.subscriber = subscriber_socket

        self.running = True

        threading.Thread(target=self._process_messages, daemon=True).start()

        logger.info("Tool %s connected with ID %s", self.tool_type.value, self.tool_id)
        return self.tool_id

    def disconnect(self) -> None:
        """Disconnect from bridge."""
        self.running = False

        if self.dealer is not None:
            self.dealer.close()
        if self.subscriber is not None:
            self.subscriber.close()

        self.context.term()

    def send_result(self, result_type: MessageType, data: dict[str, Any]) -> None:
        """Send analysis result to bridge."""
        if self.dealer is None:
            logger.error("Dealer socket is not initialized")
            return

        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=self.tool_type,
            destination=ToolType.ORCHESTRATOR,
            message_type=result_type,
            timestamp=time.time(),
            payload=data,
        )

        self.dealer.send(message.to_bytes())

    def _process_messages(self) -> None:
        """Process incoming messages."""
        if self.dealer is None or self.subscriber is None:
            logger.error("Sockets are not initialized")
            return

        poller = zmq.Poller()
        poller.register(self.dealer, zmq.POLLIN)
        poller.register(self.subscriber, zmq.POLLIN)

        while self.running:
            try:
                sockets = dict(poller.poll(100))

                if self.dealer in sockets:
                    msg_bytes = self.dealer.recv()
                    message = IPCMessage.from_bytes(msg_bytes)
                    self._handle_message(message)

                if self.subscriber in sockets:
                    _topic, msg_bytes = self.subscriber.recv_multipart()
                    message = IPCMessage.from_bytes(msg_bytes)
                    self._handle_message(message)

            except Exception as e:
                logger.exception("Message processing error: %s", e)

    def _handle_message(self, message: IPCMessage) -> None:
        """Handle incoming message."""
        for handler in self.message_handlers.get(message.message_type, []):
            try:
                handler(message)
            except Exception as e:
                logger.exception("Handler error: %s", e)

    def register_handler(self, message_type: MessageType, handler: Callable[[IPCMessage], Any]) -> None:
        """Register message handler."""
        self.message_handlers[message_type].append(handler)
