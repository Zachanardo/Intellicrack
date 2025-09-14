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
import json
import socket
import struct
import threading
import time
import uuid
import zmq
import msgpack
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, Union
from pathlib import Path
from collections import defaultdict
import logging
import hashlib
import hmac

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
    destination: Optional[ToolType]
    message_type: MessageType
    timestamp: float
    payload: Dict[str, Any]
    correlation_id: Optional[str] = None
    requires_response: bool = False
    priority: int = 5

    def to_bytes(self) -> bytes:
        """Serialize message to bytes using msgpack."""
        return msgpack.packb(asdict(self))

    @classmethod
    def from_bytes(cls, data: bytes) -> 'IPCMessage':
        """Deserialize message from bytes."""
        msg_dict = msgpack.unpackb(data, raw=False)
        msg_dict['source'] = ToolType(msg_dict['source'])
        if msg_dict['destination']:
            msg_dict['destination'] = ToolType(msg_dict['destination'])
        msg_dict['message_type'] = MessageType(msg_dict['message_type'])
        return cls(**msg_dict)


class ToolCommunicationBridge:
    """Central communication bridge for all analysis tools."""

    def __init__(self, orchestrator_port: int = 5555, auth_key: Optional[str] = None):
        """Initialize the communication bridge."""
        self.orchestrator_port = orchestrator_port
        self.auth_key = auth_key or self._generate_auth_key()

        # ZeroMQ context and sockets
        self.context = zmq.Context()
        self.publisher = None
        self.subscriber = None
        self.router = None
        self.dealer_sockets: Dict[ToolType, zmq.Socket] = {}

        # Message handling
        self.message_handlers: Dict[MessageType, List[Callable]] = defaultdict(list)
        self.pending_responses: Dict[str, asyncio.Future] = {}
        self.message_history: List[IPCMessage] = []
        self.tool_registry: Dict[ToolType, Dict[str, Any]] = {}

        # Thread management
        self.running = False
        self.router_thread = None
        self.subscriber_thread = None

        # Performance metrics
        self.message_stats = defaultdict(int)
        self.latency_stats = defaultdict(list)

    def _generate_auth_key(self) -> str:
        """Generate secure authentication key for IPC."""
        return hashlib.sha256(uuid.uuid4().bytes).hexdigest()

    def start(self):
        """Start the communication bridge."""
        self.running = True

        # Setup publisher socket for broadcasting
        self.publisher = self.context.socket(zmq.PUB)
        self.publisher.bind(f"tcp://127.0.0.1:{self.orchestrator_port}")

        # Setup router socket for request-reply
        self.router = self.context.socket(zmq.ROUTER)
        self.router.bind(f"tcp://127.0.0.1:{self.orchestrator_port + 1}")

        # Setup subscriber for receiving broadcasts
        self.subscriber = self.context.socket(zmq.SUB)
        self.subscriber.connect(f"tcp://127.0.0.1:{self.orchestrator_port}")
        self.subscriber.setsockopt_string(zmq.SUBSCRIBE, "")

        # Start message processing threads
        self.router_thread = threading.Thread(target=self._router_loop, daemon=True)
        self.router_thread.start()

        self.subscriber_thread = threading.Thread(target=self._subscriber_loop, daemon=True)
        self.subscriber_thread.start()

        logger.info(f"Communication bridge started on port {self.orchestrator_port}")

    def stop(self):
        """Stop the communication bridge."""
        self.running = False

        # Close all sockets
        if self.publisher:
            self.publisher.close()
        if self.subscriber:
            self.subscriber.close()
        if self.router:
            self.router.close()

        for socket in self.dealer_sockets.values():
            socket.close()

        self.context.term()
        logger.info("Communication bridge stopped")

    def register_tool(self, tool_type: ToolType, capabilities: Dict[str, Any]) -> str:
        """Register a tool with the communication bridge."""
        tool_id = str(uuid.uuid4())

        self.tool_registry[tool_type] = {
            "id": tool_id,
            "capabilities": capabilities,
            "registered_at": time.time(),
            "last_heartbeat": time.time(),
            "status": "active"
        }

        # Create dealer socket for this tool
        dealer = self.context.socket(zmq.DEALER)
        dealer.connect(f"tcp://127.0.0.1:{self.orchestrator_port + 1}")
        dealer.setsockopt_string(zmq.IDENTITY, tool_id)
        self.dealer_sockets[tool_type] = dealer

        logger.info(f"Registered tool {tool_type.value} with ID {tool_id}")
        return tool_id

    def unregister_tool(self, tool_type: ToolType):
        """Unregister a tool from the bridge."""
        if tool_type in self.tool_registry:
            del self.tool_registry[tool_type]

        if tool_type in self.dealer_sockets:
            self.dealer_sockets[tool_type].close()
            del self.dealer_sockets[tool_type]

        logger.info(f"Unregistered tool {tool_type.value}")

    def send_message(self, message: IPCMessage) -> Optional[str]:
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
                logger.debug(f"Sent {message.message_type.value} to {message.destination.value}")

                if message.requires_response:
                    # Create future for response
                    future = asyncio.Future()
                    self.pending_responses[message.id] = future
                    return message.id
        else:
            # Broadcast message
            self.publisher.send_multipart([
                message.source.value.encode(),
                message.to_bytes()
            ])
            logger.debug(f"Broadcast {message.message_type.value} from {message.source.value}")

        return None

    def _generate_message_auth(self, message: IPCMessage) -> str:
        """Generate HMAC authentication for message."""
        msg_bytes = json.dumps({
            "id": message.id,
            "source": message.source.value,
            "type": message.message_type.value,
            "timestamp": message.timestamp
        }).encode()

        return hmac.new(
            self.auth_key.encode(),
            msg_bytes,
            hashlib.sha256
        ).hexdigest()

    def _verify_message_auth(self, message: IPCMessage) -> bool:
        """Verify message authentication."""
        if "auth" not in message.payload:
            return False

        expected_auth = self._generate_message_auth(message)
        return hmac.compare_digest(
            message.payload["auth"],
            expected_auth
        )

    async def send_and_wait(self, message: IPCMessage, timeout: float = 30.0) -> Optional[IPCMessage]:
        """Send message and wait for response."""
        message.requires_response = True
        msg_id = self.send_message(message)

        if msg_id and msg_id in self.pending_responses:
            try:
                future = self.pending_responses[msg_id]
                response = await asyncio.wait_for(future, timeout=timeout)
                del self.pending_responses[msg_id]
                return response
            except asyncio.TimeoutError:
                logger.warning(f"Timeout waiting for response to {msg_id}")
                del self.pending_responses[msg_id]
                return None

        return None

    def register_handler(self, message_type: MessageType, handler: Callable):
        """Register a message handler for specific message type."""
        self.message_handlers[message_type].append(handler)
        logger.debug(f"Registered handler for {message_type.value}")

    def _router_loop(self):
        """Process request-reply messages."""
        poller = zmq.Poller()
        poller.register(self.router, zmq.POLLIN)

        while self.running:
            try:
                sockets = dict(poller.poll(100))

                if self.router in sockets:
                    # Receive message with identity
                    identity = self.router.recv()
                    empty = self.router.recv()
                    msg_bytes = self.router.recv()

                    # Deserialize message
                    message = IPCMessage.from_bytes(msg_bytes)

                    # Verify authentication
                    if not self._verify_message_auth(message):
                        logger.warning(f"Authentication failed for message {message.id}")
                        continue

                    # Handle message
                    self._handle_message(message, identity)

            except Exception as e:
                logger.error(f"Router loop error: {e}")

    def _subscriber_loop(self):
        """Process broadcast messages."""
        while self.running:
            try:
                if self.subscriber.poll(100):
                    # Receive broadcast
                    topic, msg_bytes = self.subscriber.recv_multipart()
                    message = IPCMessage.from_bytes(msg_bytes)

                    # Verify authentication
                    if not self._verify_message_auth(message):
                        logger.warning(f"Authentication failed for broadcast {message.id}")
                        continue

                    # Handle broadcast
                    self._handle_message(message, None)

            except Exception as e:
                logger.error(f"Subscriber loop error: {e}")

    def _handle_message(self, message: IPCMessage, identity: Optional[bytes]):
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
                if message.requires_response and response and identity:
                    response_msg = IPCMessage(
                        id=str(uuid.uuid4()),
                        source=ToolType.ORCHESTRATOR,
                        destination=message.source,
                        message_type=MessageType.ANALYSIS_RESULT,
                        timestamp=time.time(),
                        payload=response,
                        correlation_id=message.id,
                        requires_response=False
                    )

                    # Add auth and send
                    response_msg.payload["auth"] = self._generate_message_auth(response_msg)
                    self.router.send_multipart([
                        identity,
                        b"",
                        response_msg.to_bytes()
                    ])

            except Exception as e:
                logger.error(f"Handler error for {message.message_type.value}: {e}")

        # Record latency
        latency = time.time() - start_time
        self.latency_stats[message.message_type].append(latency)

    def broadcast_analysis_event(self, event_type: str, data: Dict[str, Any]):
        """Broadcast an analysis event to all tools."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.ORCHESTRATOR,
            destination=None,
            message_type=MessageType.ANALYSIS_RESULT,
            timestamp=time.time(),
            payload={
                "event_type": event_type,
                "data": data
            }
        )
        self.send_message(message)

    def request_cross_reference(self, address: int, tool_type: ToolType) -> Optional[Dict[str, Any]]:
        """Request cross-reference analysis from specific tool."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.ORCHESTRATOR,
            destination=tool_type,
            message_type=MessageType.ANALYSIS_REQUEST,
            timestamp=time.time(),
            payload={
                "operation": "cross_reference",
                "address": address
            },
            requires_response=True
        )

        # Synchronous wrapper for async operation
        loop = asyncio.new_event_loop()
        response = loop.run_until_complete(
            self.send_and_wait(message, timeout=10.0)
        )
        loop.close()

        if response:
            return response.payload
        return None

    def synchronize_breakpoints(self, breakpoints: List[int]):
        """Synchronize breakpoints across all debugging tools."""
        for tool in [ToolType.FRIDA, ToolType.X64DBG, ToolType.RADARE2]:
            if tool in self.tool_registry:
                message = IPCMessage(
                    id=str(uuid.uuid4()),
                    source=ToolType.ORCHESTRATOR,
                    destination=tool,
                    message_type=MessageType.SYNC_REQUEST,
                    timestamp=time.time(),
                    payload={
                        "sync_type": "breakpoints",
                        "breakpoints": breakpoints
                    }
                )
                self.send_message(message)

    def share_function_signature(self, address: int, signature: Dict[str, Any]):
        """Share discovered function signature with all tools."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.ORCHESTRATOR,
            destination=None,
            message_type=MessageType.FUNCTION_DISCOVERED,
            timestamp=time.time(),
            payload={
                "address": address,
                "signature": signature
            }
        )
        self.send_message(message)

    def coordinate_patch_operation(self, patches: List[Dict[str, Any]]) -> bool:
        """Coordinate patch operation across tools."""
        success = True

        # First, verify patches with Radare2
        verify_msg = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.ORCHESTRATOR,
            destination=ToolType.RADARE2,
            message_type=MessageType.ANALYSIS_REQUEST,
            timestamp=time.time(),
            payload={
                "operation": "verify_patches",
                "patches": patches
            },
            requires_response=True
        )

        loop = asyncio.new_event_loop()
        verification = loop.run_until_complete(
            self.send_and_wait(verify_msg, timeout=15.0)
        )
        loop.close()

        if not verification or not verification.payload.get("valid", False):
            logger.error("Patch verification failed")
            return False

        # Apply patches
        for patch in patches:
            apply_msg = IPCMessage(
                id=str(uuid.uuid4()),
                source=ToolType.ORCHESTRATOR,
                destination=ToolType.RADARE2,
                message_type=MessageType.ANALYSIS_REQUEST,
                timestamp=time.time(),
                payload={
                    "operation": "apply_patch",
                    "patch": patch
                },
                requires_response=True
            )

            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(
                self.send_and_wait(apply_msg, timeout=10.0)
            )
            loop.close()

            if not result or not result.payload.get("success", False):
                success = False
                break

            # Notify other tools
            self.broadcast_analysis_event("patch_applied", patch)

        return success

    def get_tool_status(self) -> Dict[ToolType, Dict[str, Any]]:
        """Get status of all registered tools."""
        status = {}
        current_time = time.time()

        for tool_type, info in self.tool_registry.items():
            heartbeat_age = current_time - info["last_heartbeat"]
            status[tool_type] = {
                "id": info["id"],
                "status": "active" if heartbeat_age < 30 else "inactive",
                "capabilities": info["capabilities"],
                "last_heartbeat": heartbeat_age,
                "message_count": self.message_stats.get(tool_type, 0)
            }

        return status

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get communication performance metrics."""
        metrics = {
            "total_messages": sum(self.message_stats.values()),
            "message_types": dict(self.message_stats),
            "average_latency": {},
            "tools_connected": len(self.tool_registry)
        }

        for msg_type, latencies in self.latency_stats.items():
            if latencies:
                metrics["average_latency"][msg_type.value] = {
                    "avg": sum(latencies) / len(latencies),
                    "min": min(latencies),
                    "max": max(latencies)
                }

        return metrics


class ToolConnector:
    """Client connector for individual tools to communicate with bridge."""

    def __init__(self, tool_type: ToolType, bridge_host: str = "127.0.0.1",
                 bridge_port: int = 5555):
        """Initialize tool connector."""
        self.tool_type = tool_type
        self.bridge_host = bridge_host
        self.bridge_port = bridge_port
        self.tool_id = None

        self.context = zmq.Context()
        self.dealer = None
        self.subscriber = None
        self.message_handlers = defaultdict(list)
        self.running = False

    def connect(self) -> str:
        """Connect to the communication bridge."""
        # Setup dealer socket for request-reply
        self.dealer = self.context.socket(zmq.DEALER)
        self.tool_id = str(uuid.uuid4())
        self.dealer.setsockopt_string(zmq.IDENTITY, self.tool_id)
        self.dealer.connect(f"tcp://{self.bridge_host}:{self.bridge_port + 1}")

        # Setup subscriber for broadcasts
        self.subscriber = self.context.socket(zmq.SUB)
        self.subscriber.connect(f"tcp://{self.bridge_host}:{self.bridge_port}")
        self.subscriber.setsockopt_string(zmq.SUBSCRIBE, "")

        self.running = True

        # Start message processing
        threading.Thread(target=self._process_messages, daemon=True).start()

        logger.info(f"Tool {self.tool_type.value} connected with ID {self.tool_id}")
        return self.tool_id

    def disconnect(self):
        """Disconnect from bridge."""
        self.running = False

        if self.dealer:
            self.dealer.close()
        if self.subscriber:
            self.subscriber.close()

        self.context.term()

    def send_result(self, result_type: MessageType, data: Dict[str, Any]):
        """Send analysis result to bridge."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=self.tool_type,
            destination=ToolType.ORCHESTRATOR,
            message_type=result_type,
            timestamp=time.time(),
            payload=data
        )

        self.dealer.send(message.to_bytes())

    def _process_messages(self):
        """Process incoming messages."""
        poller = zmq.Poller()
        poller.register(self.dealer, zmq.POLLIN)
        poller.register(self.subscriber, zmq.POLLIN)

        while self.running:
            try:
                sockets = dict(poller.poll(100))

                # Handle dealer messages
                if self.dealer in sockets:
                    msg_bytes = self.dealer.recv()
                    message = IPCMessage.from_bytes(msg_bytes)
                    self._handle_message(message)

                # Handle broadcast messages
                if self.subscriber in sockets:
                    topic, msg_bytes = self.subscriber.recv_multipart()
                    message = IPCMessage.from_bytes(msg_bytes)
                    self._handle_message(message)

            except Exception as e:
                logger.error(f"Message processing error: {e}")

    def _handle_message(self, message: IPCMessage):
        """Handle incoming message."""
        for handler in self.message_handlers.get(message.message_type, []):
            try:
                handler(message)
            except Exception as e:
                logger.error(f"Handler error: {e}")

    def register_handler(self, message_type: MessageType, handler: Callable):
        """Register message handler."""
        self.message_handlers[message_type].append(handler)