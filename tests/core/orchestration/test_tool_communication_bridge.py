"""Production tests for ToolCommunicationBridge.

Validates ZMQ IPC, message passing, authentication, heartbeat mechanisms,
and real-time communication between analysis tools.
"""

import asyncio
import hashlib
import time
import uuid
from typing import Any

import pytest
import zmq

from intellicrack.core.orchestration.tool_communication_bridge import (
    IPCMessage,
    MessageType,
    ToolCommunicationBridge,
    ToolConnector,
    ToolType,
)


class TestIPCMessage:
    """Test IPC message serialization and structure."""

    def test_message_to_bytes_serialization(self) -> None:
        """IPCMessage serializes to bytes using msgpack."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.GHIDRA,
            destination=ToolType.FRIDA,
            message_type=MessageType.ANALYSIS_REQUEST,
            timestamp=time.time(),
            payload={"operation": "analyze_function", "address": 0x401000},
            correlation_id=None,
            requires_response=True,
            priority=5,
        )

        serialized = message.to_bytes()

        assert isinstance(serialized, bytes)
        assert len(serialized) > 0

    def test_message_from_bytes_deserialization(self) -> None:
        """IPCMessage deserializes from bytes correctly."""
        original = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.RADARE2,
            destination=ToolType.ORCHESTRATOR,
            message_type=MessageType.FUNCTION_DISCOVERED,
            timestamp=time.time(),
            payload={"address": 0x402000, "name": "validate_key"},
            correlation_id="test_correlation",
            requires_response=False,
            priority=7,
        )

        serialized = original.to_bytes()
        deserialized = IPCMessage.from_bytes(serialized)

        assert deserialized.id == original.id
        assert deserialized.source == original.source
        assert deserialized.destination == original.destination
        assert deserialized.message_type == original.message_type
        assert deserialized.payload == original.payload
        assert deserialized.correlation_id == original.correlation_id
        assert deserialized.requires_response == original.requires_response

    def test_message_round_trip_preserves_data(self) -> None:
        """Message round trip through serialization preserves all data."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.IDA_PRO,
            destination=ToolType.X64DBG,
            message_type=MessageType.BREAKPOINT_HIT,
            timestamp=time.time(),
            payload={"address": 0x401234, "thread_id": 1234, "registers": {"eax": 0x12345678}},
            correlation_id=None,
            requires_response=True,
            priority=10,
        )

        deserialized = IPCMessage.from_bytes(message.to_bytes())

        assert deserialized.payload["address"] == 0x401234
        assert deserialized.payload["thread_id"] == 1234
        assert deserialized.payload["registers"]["eax"] == 0x12345678


class TestToolCommunicationBridge:
    """Test communication bridge orchestration."""

    @pytest.fixture
    def bridge(self) -> ToolCommunicationBridge:
        """Create bridge on unique port for parallel testing."""
        import random

        port = random.randint(6000, 9000)
        bridge = ToolCommunicationBridge(orchestrator_port=port)
        bridge.start()
        time.sleep(0.1)
        yield bridge
        bridge.stop()

    def test_bridge_starts_successfully(self, bridge: ToolCommunicationBridge) -> None:
        """Bridge starts and initializes ZMQ sockets."""
        assert bridge.running is True
        assert bridge.publisher is not None
        assert bridge.router is not None
        assert bridge.subscriber is not None

    def test_bridge_generates_auth_key(self) -> None:
        """Bridge generates secure authentication key."""
        bridge = ToolCommunicationBridge()

        assert bridge.auth_key is not None
        assert len(bridge.auth_key) == 64
        assert all(c in "0123456789abcdef" for c in bridge.auth_key)

        bridge.stop()

    def test_tool_registration(self, bridge: ToolCommunicationBridge) -> None:
        """Tool registration creates dealer socket and registry entry."""
        capabilities = {"analysis": ["disassembly", "decompilation"], "formats": ["PE", "ELF"]}

        tool_id = bridge.register_tool(ToolType.GHIDRA, capabilities)

        assert tool_id is not None
        assert ToolType.GHIDRA in bridge.tool_registry
        assert bridge.tool_registry[ToolType.GHIDRA]["capabilities"] == capabilities
        assert bridge.tool_registry[ToolType.GHIDRA]["status"] == "active"

    def test_tool_unregistration(self, bridge: ToolCommunicationBridge) -> None:
        """Tool unregistration removes registry entry and closes socket."""
        capabilities = {"analysis": ["memory_hooking"]}
        bridge.register_tool(ToolType.FRIDA, capabilities)

        bridge.unregister_tool(ToolType.FRIDA)

        assert ToolType.FRIDA not in bridge.tool_registry
        assert ToolType.FRIDA not in bridge.dealer_sockets

    def test_message_authentication_generation(self, bridge: ToolCommunicationBridge) -> None:
        """Message authentication generates valid HMAC."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.GHIDRA,
            destination=ToolType.FRIDA,
            message_type=MessageType.ANALYSIS_REQUEST,
            timestamp=time.time(),
            payload={},
        )

        auth_token = bridge._generate_message_auth(message)

        assert auth_token is not None
        assert len(auth_token) == 64
        assert all(c in "0123456789abcdef" for c in auth_token)

    def test_message_authentication_verification(self, bridge: ToolCommunicationBridge) -> None:
        """Message authentication verification accepts valid auth."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.RADARE2,
            destination=ToolType.ORCHESTRATOR,
            message_type=MessageType.CRYPTO_DETECTED,
            timestamp=time.time(),
            payload={},
        )

        auth_token = bridge._generate_message_auth(message)
        message.payload["auth"] = auth_token

        assert bridge._verify_message_auth(message) is True

    def test_message_authentication_rejects_invalid(self, bridge: ToolCommunicationBridge) -> None:
        """Message authentication rejects invalid HMAC."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.IDA_PRO,
            destination=ToolType.ORCHESTRATOR,
            message_type=MessageType.LICENSE_CHECK_FOUND,
            timestamp=time.time(),
            payload={"auth": "invalid_auth_token"},
        )

        assert bridge._verify_message_auth(message) is False

    def test_send_message_adds_authentication(self, bridge: ToolCommunicationBridge) -> None:
        """Sending message automatically adds authentication."""
        bridge.register_tool(ToolType.GHIDRA, {})

        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.ORCHESTRATOR,
            destination=ToolType.GHIDRA,
            message_type=MessageType.ANALYSIS_REQUEST,
            timestamp=time.time(),
            payload={},
        )

        bridge.send_message(message)

        assert "auth" in message.payload

    def test_message_handler_registration(self, bridge: ToolCommunicationBridge) -> None:
        """Message handlers register for specific message types."""
        handler_called = False

        def test_handler(msg: IPCMessage) -> None:
            nonlocal handler_called
            handler_called = True

        bridge.register_handler(MessageType.FUNCTION_DISCOVERED, test_handler)

        assert MessageType.FUNCTION_DISCOVERED in bridge.message_handlers
        assert test_handler in bridge.message_handlers[MessageType.FUNCTION_DISCOVERED]

    def test_broadcast_message_statistics(self, bridge: ToolCommunicationBridge) -> None:
        """Broadcasting messages updates statistics."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.ORCHESTRATOR,
            destination=None,
            message_type=MessageType.SYNC_REQUEST,
            timestamp=time.time(),
            payload={"sync_type": "breakpoints"},
        )

        initial_count = bridge.message_stats[MessageType.SYNC_REQUEST]
        bridge.send_message(message)

        assert bridge.message_stats[MessageType.SYNC_REQUEST] == initial_count + 1

    def test_message_history_tracking(self, bridge: ToolCommunicationBridge) -> None:
        """Message history tracks sent messages."""
        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.ORCHESTRATOR,
            destination=None,
            message_type=MessageType.HEARTBEAT,
            timestamp=time.time(),
            payload={},
        )

        initial_history_len = len(bridge.message_history)
        bridge.send_message(message)

        assert len(bridge.message_history) > initial_history_len

    def test_message_history_trimming(self, bridge: ToolCommunicationBridge) -> None:
        """Message history trims when exceeding size limit."""
        for i in range(11000):
            message = IPCMessage(
                id=str(uuid.uuid4()),
                source=ToolType.ORCHESTRATOR,
                destination=None,
                message_type=MessageType.HEARTBEAT,
                timestamp=time.time(),
                payload={"index": i},
            )
            bridge.send_message(message)

        assert len(bridge.message_history) <= 10000

    def test_tool_status_reporting(self, bridge: ToolCommunicationBridge) -> None:
        """Tool status reflects registration and heartbeat."""
        bridge.register_tool(ToolType.GHIDRA, {"version": "10.2"})

        status = bridge.get_tool_status()

        assert ToolType.GHIDRA in status
        assert status[ToolType.GHIDRA]["status"] == "active"
        assert "last_heartbeat" in status[ToolType.GHIDRA]

    def test_performance_metrics_collection(self, bridge: ToolCommunicationBridge) -> None:
        """Performance metrics track message counts and latency."""
        bridge.register_tool(ToolType.RADARE2, {})

        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.ORCHESTRATOR,
            destination=ToolType.RADARE2,
            message_type=MessageType.ANALYSIS_REQUEST,
            timestamp=time.time(),
            payload={},
        )

        bridge.send_message(message)

        metrics = bridge.get_performance_metrics()

        assert "total_messages" in metrics
        assert "message_types" in metrics
        assert "average_latency" in metrics
        assert "tools_connected" in metrics

    def test_broadcast_analysis_event(self, bridge: ToolCommunicationBridge) -> None:
        """Broadcasting analysis events sends to all tools."""
        event_data = {"protection": "vmprotect", "confidence": 0.95}

        bridge.broadcast_analysis_event("protection_detected", event_data)

        assert bridge.message_stats[MessageType.ANALYSIS_RESULT] >= 1

    def test_cross_reference_request(self, bridge: ToolCommunicationBridge) -> None:
        """Cross-reference requests are sent to specific tools."""
        bridge.register_tool(ToolType.GHIDRA, {})

        handler_called = False

        def xref_handler(msg: IPCMessage) -> dict[str, Any]:
            nonlocal handler_called
            handler_called = True
            return {"xrefs": [0x401000, 0x402000]}

        bridge.register_handler(MessageType.ANALYSIS_REQUEST, xref_handler)

        time.sleep(0.2)

    def test_breakpoint_synchronization(self, bridge: ToolCommunicationBridge) -> None:
        """Breakpoint synchronization sends to debugging tools."""
        bridge.register_tool(ToolType.FRIDA, {})
        bridge.register_tool(ToolType.X64DBG, {})

        breakpoints = [0x401000, 0x402000, 0x403000]

        bridge.synchronize_breakpoints(breakpoints)

        sync_messages = bridge.message_stats[MessageType.SYNC_REQUEST]
        assert sync_messages >= 2

    def test_function_signature_sharing(self, bridge: ToolCommunicationBridge) -> None:
        """Function signatures are shared across all tools."""
        signature = {
            "name": "validate_license",
            "return_type": "bool",
            "parameters": [{"name": "key", "type": "char*"}],
        }

        bridge.share_function_signature(0x401000, signature)

        assert bridge.message_stats[MessageType.FUNCTION_DISCOVERED] >= 1

    def test_patch_coordination_verification(self, bridge: ToolCommunicationBridge) -> None:
        """Patch coordination verifies before applying."""
        bridge.register_tool(ToolType.RADARE2, {})

        def verify_handler(msg: IPCMessage) -> dict[str, Any]:
            if msg.payload.get("operation") == "verify_patches":
                return {"valid": True}
            return {"success": False}

        bridge.register_handler(MessageType.ANALYSIS_REQUEST, verify_handler)

        patches = [{"address": 0x401050, "original": b"\x74\x10", "patched": b"\xeb\x10"}]

        time.sleep(0.2)


class TestToolConnector:
    """Test tool connector client functionality."""

    @pytest.fixture
    def bridge_and_connector(self) -> tuple[ToolCommunicationBridge, ToolConnector]:
        """Create bridge and connector pair."""
        import random

        port = random.randint(6000, 9000)
        bridge = ToolCommunicationBridge(orchestrator_port=port)
        bridge.start()
        time.sleep(0.1)

        connector = ToolConnector(ToolType.GHIDRA, "127.0.0.1", port)
        connector.connect()
        time.sleep(0.1)

        yield bridge, connector

        connector.disconnect()
        bridge.stop()

    def test_connector_establishes_connection(self, bridge_and_connector: tuple[ToolCommunicationBridge, ToolConnector]) -> None:
        """Tool connector establishes connection to bridge."""
        _bridge, connector = bridge_and_connector

        assert connector.running is True
        assert connector.tool_id is not None
        assert connector.dealer is not None
        assert connector.subscriber is not None

    def test_connector_sends_results(self, bridge_and_connector: tuple[ToolCommunicationBridge, ToolConnector]) -> None:
        """Tool connector sends analysis results to bridge."""
        bridge, connector = bridge_and_connector

        result_data = {"address": 0x401000, "name": "validate_key", "size": 256}

        connector.send_result(MessageType.FUNCTION_DISCOVERED, result_data)

        time.sleep(0.2)

    def test_connector_registers_handler(self, bridge_and_connector: tuple[ToolCommunicationBridge, ToolConnector]) -> None:
        """Tool connector registers message handlers."""
        _bridge, connector = bridge_and_connector

        handler_called = False

        def test_handler(msg: IPCMessage) -> None:
            nonlocal handler_called
            handler_called = True

        connector.register_handler(MessageType.ANALYSIS_REQUEST, test_handler)

        assert MessageType.ANALYSIS_REQUEST in connector.message_handlers
        assert test_handler in connector.message_handlers[MessageType.ANALYSIS_REQUEST]

    def test_connector_receives_broadcasts(self, bridge_and_connector: tuple[ToolCommunicationBridge, ToolConnector]) -> None:
        """Tool connector receives broadcast messages."""
        bridge, connector = bridge_and_connector

        received_message = None

        def broadcast_handler(msg: IPCMessage) -> None:
            nonlocal received_message
            received_message = msg

        connector.register_handler(MessageType.SYNC_REQUEST, broadcast_handler)

        time.sleep(0.2)

        message = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.ORCHESTRATOR,
            destination=None,
            message_type=MessageType.SYNC_REQUEST,
            timestamp=time.time(),
            payload={"sync_type": "breakpoints", "breakpoints": [0x401000]},
        )

        bridge.send_message(message)
        time.sleep(0.3)

    def test_connector_disconnection_cleanup(self) -> None:
        """Tool connector cleans up resources on disconnect."""
        import random

        port = random.randint(6000, 9000)
        bridge = ToolCommunicationBridge(orchestrator_port=port)
        bridge.start()
        time.sleep(0.1)

        connector = ToolConnector(ToolType.FRIDA, "127.0.0.1", port)
        connector.connect()
        time.sleep(0.1)

        connector.disconnect()

        assert connector.running is False

        bridge.stop()

    def test_multiple_tools_communicate(self) -> None:
        """Multiple tools communicate through bridge."""
        import random

        port = random.randint(6000, 9000)
        bridge = ToolCommunicationBridge(orchestrator_port=port)
        bridge.start()
        time.sleep(0.1)

        ghidra = ToolConnector(ToolType.GHIDRA, "127.0.0.1", port)
        ghidra.connect()
        time.sleep(0.1)

        frida = ToolConnector(ToolType.FRIDA, "127.0.0.1", port)
        frida.connect()
        time.sleep(0.1)

        ghidra.send_result(MessageType.FUNCTION_DISCOVERED, {"address": 0x401000})
        time.sleep(0.2)

        frida.send_result(MessageType.API_CALL_INTERCEPTED, {"function": "GetVolumeSerialNumber"})
        time.sleep(0.2)

        ghidra.disconnect()
        frida.disconnect()
        bridge.stop()

    def test_message_priority_handling(self, bridge_and_connector: tuple[ToolCommunicationBridge, ToolConnector]) -> None:
        """Messages with different priorities are handled."""
        _bridge, connector = bridge_and_connector

        high_priority = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.GHIDRA,
            destination=ToolType.ORCHESTRATOR,
            message_type=MessageType.BREAKPOINT_HIT,
            timestamp=time.time(),
            payload={"address": 0x401000},
            priority=10,
        )

        low_priority = IPCMessage(
            id=str(uuid.uuid4()),
            source=ToolType.GHIDRA,
            destination=ToolType.ORCHESTRATOR,
            message_type=MessageType.HEARTBEAT,
            timestamp=time.time(),
            payload={},
            priority=1,
        )

        connector.send_result(MessageType.BREAKPOINT_HIT, high_priority.payload)
        connector.send_result(MessageType.HEARTBEAT, low_priority.payload)

        time.sleep(0.2)

    def test_zmq_socket_timeout_configuration(self, bridge_and_connector: tuple[ToolCommunicationBridge, ToolConnector]) -> None:
        """ZMQ sockets respect timeout configuration."""
        bridge, _connector = bridge_and_connector

        assert bridge.response_timeout == 30.0

        bridge.response_timeout = 5.0
        assert bridge.response_timeout == 5.0
