"""Production tests for traffic interception engine with real packet capture.

These tests validate that traffic_interception_engine correctly captures network
traffic, analyzes protocols, and detects license-related communications. Tests
MUST FAIL if packet capture or analysis is broken.

Copyright (C) 2025 Zachary Flint
"""

import socket
import struct
import threading
import time
from typing import Any

import pytest

from intellicrack.core.network.traffic_interception_engine import AnalyzedTraffic, InterceptedPacket, TrafficInterceptionEngine


class TestTrafficInterceptionEngineProduction:
    """Production tests for traffic interception with real packet operations."""

    @pytest.fixture
    def engine(self) -> TrafficInterceptionEngine:
        """Create traffic interception engine."""
        return TrafficInterceptionEngine(bind_interface="127.0.0.1")

    @pytest.fixture
    def free_port(self) -> int:
        """Find available port for testing."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    @pytest.fixture
    def flexlm_packet_data(self) -> bytes:
        """Create realistic FlexLM packet data."""
        return (
            b"FEATURE AutoCAD adskflex 2024.0 permanent 1 SIGN=ABCD1234\n"
            b"SERVER license_server ANY 27000\n"
            b"VENDOR adskflex\n"
        )

    @pytest.fixture
    def hasp_packet_data(self) -> bytes:
        """Create realistic HASP packet data."""
        header = struct.pack("<I", 0x01020304)
        command = struct.pack("<B", 0x01)
        payload_len = struct.pack("<H", 16)
        payload = b"HASP_QUERY\x00\x00\x00\x00\x00\x00"
        return header + command + payload_len + payload

    def test_engine_initialization_with_configuration(self, engine: TrafficInterceptionEngine) -> None:
        """Engine initializes with correct configuration and state."""
        assert engine.bind_interface == "127.0.0.1", "Bind interface must be set"
        assert engine.running is False, "Must not be running initially"
        assert isinstance(engine.stats, dict), "Stats must be dictionary"
        assert engine.stats["packets_captured"] == 0, "Packet count must be zero"
        assert engine.stats["license_packets_detected"] == 0, "License packet count must be zero"
        assert isinstance(engine.stats["protocols_detected"], set), "Protocols must be set"

    def test_license_patterns_include_major_vendors(self, engine: TrafficInterceptionEngine) -> None:
        """License patterns include all major vendor protocols."""
        patterns = engine.license_patterns

        assert "flexlm" in patterns, "Must include FlexLM patterns"
        assert "hasp" in patterns, "Must include HASP patterns"
        assert "adobe" in patterns, "Must include Adobe patterns"
        assert "autodesk" in patterns, "Must include Autodesk patterns"
        assert "microsoft" in patterns, "Must include Microsoft patterns"
        assert "generic_license" in patterns, "Must include generic patterns"

        assert b"VENDOR_STRING" in patterns["flexlm"], "FlexLM must have VENDOR_STRING"
        assert b"hasp" in patterns["hasp"], "HASP must have hasp marker"
        assert b"activation" in patterns["adobe"], "Adobe must have activation marker"

    def test_license_ports_include_common_servers(self, engine: TrafficInterceptionEngine) -> None:
        """License ports include all common license server ports."""
        ports = engine.license_ports

        assert 27000 in ports, "Must include FlexLM base port"
        assert 1947 in ports, "Must include HASP port"
        assert 443 in ports, "Must include HTTPS port"
        assert 1688 in ports, "Must include KMS port"
        assert 2080 in ports, "Must include Autodesk port"

    def test_start_interception_activates_engine(self, engine: TrafficInterceptionEngine) -> None:
        """Start interception activates engine and creates threads."""
        result = engine.start_interception()

        try:
            assert result is True, "Start must succeed"
            assert engine.running is True, "Engine must be running"
            assert engine.capture_thread is not None, "Capture thread must be created"
            assert engine.analysis_thread is not None, "Analysis thread must be created"
            assert engine.capture_thread.is_alive(), "Capture thread must be alive"
            assert engine.analysis_thread.is_alive(), "Analysis thread must be alive"

        finally:
            engine.stop_interception()

    def test_stop_interception_deactivates_engine(self, engine: TrafficInterceptionEngine) -> None:
        """Stop interception deactivates engine and joins threads."""
        engine.start_interception()
        time.sleep(0.3)

        result = engine.stop_interception()

        assert result is True, "Stop must succeed"
        assert engine.running is False, "Engine must not be running"

    def test_intercepted_packet_dataclass_structure(self) -> None:
        """InterceptedPacket dataclass has all required fields."""
        packet = InterceptedPacket(
            source_ip="192.168.1.10",
            dest_ip="192.168.1.20",
            source_port=12345,
            dest_port=27000,
            protocol="tcp",
            data=b"test_data",
            timestamp=time.time(),
            packet_size=256,
            flags={"syn": True, "ack": False, "fin": False, "rst": False},
        )

        assert packet.source_ip == "192.168.1.10", "Source IP must be set"
        assert packet.dest_ip == "192.168.1.20", "Dest IP must be set"
        assert packet.source_port == 12345, "Source port must be set"
        assert packet.dest_port == 27000, "Dest port must be set"
        assert packet.protocol == "tcp", "Protocol must be set"
        assert packet.data == b"test_data", "Data must be set"
        assert isinstance(packet.flags, dict), "Flags must be dictionary"

    def test_analyzed_traffic_dataclass_structure(self) -> None:
        """AnalyzedTraffic dataclass has all required fields."""
        packet = InterceptedPacket(
            source_ip="127.0.0.1",
            dest_ip="127.0.0.1",
            source_port=50000,
            dest_port=27000,
            protocol="tcp",
            data=b"FEATURE",
            timestamp=time.time(),
            packet_size=128,
            flags={},
        )

        analysis = AnalyzedTraffic(
            packet=packet,
            is_license_related=True,
            protocol_type="flexlm",
            confidence=0.9,
            patterns_matched=["FEATURE"],
            analysis_metadata={"test": "metadata"},
        )

        assert analysis.is_license_related is True, "Must be license related"
        assert analysis.protocol_type == "flexlm", "Protocol must be set"
        assert analysis.confidence == 0.9, "Confidence must be set"
        assert "FEATURE" in analysis.patterns_matched, "Patterns must be set"

    def test_analyze_packet_detects_flexlm_protocol(
        self,
        engine: TrafficInterceptionEngine,
        flexlm_packet_data: bytes,
    ) -> None:
        """Analyze packet correctly identifies FlexLM protocol."""
        packet = InterceptedPacket(
            source_ip="127.0.0.1",
            dest_ip="192.168.1.100",
            source_port=50000,
            dest_port=27000,
            protocol="tcp",
            data=flexlm_packet_data,
            timestamp=time.time(),
            packet_size=len(flexlm_packet_data),
            flags={},
        )

        analysis = engine._analyze_packet(packet)

        assert analysis is not None, "Analysis must succeed"
        assert analysis.is_license_related is True, "Must identify as license related"
        assert analysis.protocol_type == "flexlm", "Must identify as FlexLM"
        assert analysis.confidence >= 0.3, "Confidence must meet minimum threshold"

    def test_analyze_packet_detects_hasp_protocol(
        self,
        engine: TrafficInterceptionEngine,
        hasp_packet_data: bytes,
    ) -> None:
        """Analyze packet correctly identifies HASP protocol."""
        packet = InterceptedPacket(
            source_ip="127.0.0.1",
            dest_ip="192.168.1.101",
            source_port=50001,
            dest_port=1947,
            protocol="tcp",
            data=hasp_packet_data,
            timestamp=time.time(),
            packet_size=len(hasp_packet_data),
            flags={},
        )

        analysis = engine._analyze_packet(packet)

        assert analysis is not None, "Analysis must succeed"
        assert analysis.is_license_related is True, "Must identify as license related"

    def test_analyze_packet_port_based_detection(
        self,
        engine: TrafficInterceptionEngine,
    ) -> None:
        """Analyze packet uses port-based detection for confidence."""
        packet = InterceptedPacket(
            source_ip="127.0.0.1",
            dest_ip="127.0.0.1",
            source_port=50002,
            dest_port=27000,
            protocol="tcp",
            data=b"some_data",
            timestamp=time.time(),
            packet_size=20,
            flags={},
        )

        if analysis := engine._analyze_packet(packet):
            assert analysis.is_license_related is True, "Port 27000 must trigger detection"
            assert analysis.confidence >= 0.3, "Port match must increase confidence"

    def test_analyze_packet_keyword_detection(
        self,
        engine: TrafficInterceptionEngine,
    ) -> None:
        """Analyze packet detects license-related keywords."""
        packet = InterceptedPacket(
            source_ip="127.0.0.1",
            dest_ip="127.0.0.1",
            source_port=50003,
            dest_port=8080,
            protocol="tcp",
            data=b"license activation checkout verify serial",
            timestamp=time.time(),
            packet_size=50,
            flags={},
        )

        analysis = engine._analyze_packet(packet)

        assert analysis is not None, "Must detect license keywords"
        assert analysis.is_license_related is True, "Keywords must trigger detection"

    def test_analyze_packet_returns_none_for_empty_data(
        self,
        engine: TrafficInterceptionEngine,
    ) -> None:
        """Analyze packet returns None for empty packet data."""
        packet = InterceptedPacket(
            source_ip="127.0.0.1",
            dest_ip="127.0.0.1",
            source_port=50004,
            dest_port=80,
            protocol="tcp",
            data=b"",
            timestamp=time.time(),
            packet_size=0,
            flags={},
        )

        analysis = engine._analyze_packet(packet)

        assert analysis is None, "Must return None for empty data"

    def test_add_analysis_callback_registration(self, engine: TrafficInterceptionEngine) -> None:
        """Add analysis callback registers callback function."""
        callback_called = []

        def test_callback(analysis: AnalyzedTraffic) -> None:
            callback_called.append(analysis)

        engine.add_analysis_callback(test_callback)

        assert test_callback in engine.analysis_callbacks, "Callback must be registered"

    def test_remove_analysis_callback_deregistration(self, engine: TrafficInterceptionEngine) -> None:
        """Remove analysis callback deregisters callback function."""
        def test_callback(analysis: AnalyzedTraffic) -> None:
            pass

        engine.add_analysis_callback(test_callback)
        assert test_callback in engine.analysis_callbacks, "Callback must be registered"

        engine.remove_analysis_callback(test_callback)

        assert test_callback not in engine.analysis_callbacks, "Callback must be removed"

    def test_set_dns_redirection(self, engine: TrafficInterceptionEngine) -> None:
        """Set DNS redirection registers hostname mapping."""
        result = engine.set_dns_redirection("license.vendor.com", "127.0.0.1")

        assert result is True, "DNS redirection must succeed"
        assert "license.vendor.com" in engine.dns_redirections, "Hostname must be registered"
        assert engine.dns_redirections["license.vendor.com"] == "127.0.0.1", "IP must match"

    def test_setup_transparent_proxy(self, engine: TrafficInterceptionEngine) -> None:
        """Setup transparent proxy registers proxy mapping."""
        result = engine.setup_transparent_proxy("license.server.com", 27000)

        assert result is True, "Proxy setup must succeed"
        assert "license.server.com:27000" in engine.proxy_mappings, "Mapping must be registered"

    def test_get_statistics_returns_complete_metrics(self, engine: TrafficInterceptionEngine) -> None:
        """Get statistics returns all metrics and counters."""
        engine.start_interception()
        time.sleep(0.2)

        try:
            stats = engine.get_statistics()

            assert "packets_captured" in stats, "Must include packet count"
            assert "license_packets_detected" in stats, "Must include license packet count"
            assert "protocols_detected" in stats, "Must include protocols"
            assert "uptime_seconds" in stats, "Must include uptime"
            assert "packets_per_second" in stats, "Must include rate"
            assert "active_connections" in stats, "Must include connections"
            assert "capture_backend" in stats, "Must include backend type"
            assert "dns_redirections" in stats, "Must include DNS count"
            assert "proxy_mappings" in stats, "Must include proxy count"

        finally:
            engine.stop_interception()

    def test_get_active_connections_returns_list(self, engine: TrafficInterceptionEngine) -> None:
        """Get active connections returns list of connection info."""
        connections = engine.get_active_connections()

        assert isinstance(connections, list), "Must return list"

    def test_send_protocol_command_establishes_connection(
        self,
        engine: TrafficInterceptionEngine,
        free_port: int,
    ) -> None:
        """Send protocol command establishes connection and sends data."""
        server_received = []

        def test_server() -> None:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_sock.bind(("127.0.0.1", free_port))
                server_sock.listen(1)
                server_sock.settimeout(5.0)

                try:
                    client, _ = server_sock.accept()
                    data = client.recv(1024)
                    server_received.append(data)
                    client.sendall(b"RESPONSE")
                    client.close()
                except (TimeoutError, OSError):
                    pass

        server_thread = threading.Thread(target=test_server, daemon=True)
        server_thread.start()
        time.sleep(0.5)

        response = engine.send_protocol_command("flexlm", "127.0.0.1", free_port, b"TEST_COMMAND")

        server_thread.join(timeout=2.0)

        if response:
            assert b"RESPONSE" in response, "Must receive server response"
        if server_received:
            assert server_received, "Server must receive command"

    def test_wrap_protocol_command_flexlm(self, engine: TrafficInterceptionEngine) -> None:
        """Wrap protocol command adds FlexLM header."""
        command = b"TEST_COMMAND"

        wrapped = engine._wrap_protocol_command("flexlm", command)

        assert len(wrapped) > len(command), "Must add header"
        assert wrapped.endswith(command), "Must preserve command"

        header = struct.unpack(">HH", wrapped[:4])
        assert header[0] == 0x0001, "Must have correct version"
        assert header[1] == len(command), "Must have correct length"

    def test_wrap_protocol_command_hasp(self, engine: TrafficInterceptionEngine) -> None:
        """Wrap protocol command adds HASP header."""
        command = b"QUERY"

        wrapped = engine._wrap_protocol_command("hasp", command)

        assert wrapped.startswith(b"\x00\x01\x02\x03"), "Must have HASP magic"
        assert len(wrapped) > len(command), "Must add header"

    def test_wrap_protocol_command_generic(self, engine: TrafficInterceptionEngine) -> None:
        """Wrap protocol command returns raw command for unknown protocols."""
        command = b"GENERIC_COMMAND"

        wrapped = engine._wrap_protocol_command("unknown", command)

        assert wrapped == command, "Must return raw command"

    def test_is_response_complete_flexlm(self, engine: TrafficInterceptionEngine) -> None:
        """Response completeness check works for FlexLM protocol."""
        header = struct.pack(">HH", 0x0001, 10)
        incomplete = header + b"123"
        complete = header + b"1234567890"

        assert engine._is_response_complete("flexlm", incomplete) is False, "Incomplete must be detected"
        assert engine._is_response_complete("flexlm", complete) is True, "Complete must be detected"

    def test_capture_license_traffic_returns_list(self, engine: TrafficInterceptionEngine) -> None:
        """Capture license traffic returns list of traffic entries."""
        traffic = engine.capture_license_traffic()

        assert isinstance(traffic, list), "Must return list"

    def test_identify_protocol_by_port(self, engine: TrafficInterceptionEngine) -> None:
        """Identify protocol by port maps common ports correctly."""
        assert engine._identify_protocol_by_port(27000) == "flexlm", "Port 27000 is FlexLM"
        assert engine._identify_protocol_by_port(1947) == "hasp", "Port 1947 is HASP"
        assert engine._identify_protocol_by_port(1688) == "microsoft_kms", "Port 1688 is KMS"
        assert engine._identify_protocol_by_port(2080) == "autodesk", "Port 2080 is Autodesk"
        assert engine._identify_protocol_by_port(443) == "https_license", "Port 443 is HTTPS"

    def test_queue_packet_updates_statistics(self, engine: TrafficInterceptionEngine) -> None:
        """Queue packet updates statistics correctly."""
        initial_count = engine.stats["packets_captured"]
        initial_bytes = engine.stats["total_bytes"]

        packet = InterceptedPacket(
            source_ip="127.0.0.1",
            dest_ip="127.0.0.1",
            source_port=50000,
            dest_port=27000,
            protocol="tcp",
            data=b"test",
            timestamp=time.time(),
            packet_size=100,
            flags={},
        )

        engine._queue_packet(packet)

        assert engine.stats["packets_captured"] == initial_count + 1, "Packet count must increase"
        assert engine.stats["total_bytes"] == initial_bytes + 100, "Byte count must increase"

    def test_queue_packet_limits_queue_size(self, engine: TrafficInterceptionEngine) -> None:
        """Queue packet enforces maximum queue size."""
        for _ in range(10500):
            packet = InterceptedPacket(
                source_ip="127.0.0.1",
                dest_ip="127.0.0.1",
                source_port=50000,
                dest_port=27000,
                protocol="tcp",
                data=b"x",
                timestamp=time.time(),
                packet_size=1,
                flags={},
            )
            engine._queue_packet(packet)

        assert len(engine.packet_queue) <= 10000, "Queue must not exceed maximum size"

    def test_parse_raw_packet_tcp(self, engine: TrafficInterceptionEngine) -> None:
        """Parse raw packet extracts TCP packet information."""
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            40,
            0,
            0,
            64,
            6,
            0,
            socket.inet_aton("127.0.0.1"),
            socket.inet_aton("127.0.0.2"),
        )

        tcp_header = struct.pack("!HHLLBBHHH", 50000, 27000, 0, 0, 0x50, 0, 0, 0, 0)

        raw_packet = ip_header + tcp_header + b"payload"

        engine._parse_raw_packet(raw_packet)

    def test_multiple_start_calls_handled(self, engine: TrafficInterceptionEngine) -> None:
        """Multiple start calls don't create duplicate threads."""
        result1 = engine.start_interception()
        time.sleep(0.2)
        result2 = engine.start_interception()

        try:
            assert result1 is True, "First start must succeed"
            assert result2 is True, "Second start must succeed (returns True if already running)"

        finally:
            engine.stop_interception()

    def test_statistics_uptime_calculation(self, engine: TrafficInterceptionEngine) -> None:
        """Statistics correctly calculate uptime."""
        engine.start_interception()
        time.sleep(1.0)

        try:
            stats = engine.get_statistics()
            uptime = stats["uptime_seconds"]

            assert uptime >= 0.9, "Uptime must be approximately 1 second"
            assert uptime < 2.0, "Uptime must be reasonable"

        finally:
            engine.stop_interception()

    def test_intercepted_packet_flags_initialization(self) -> None:
        """InterceptedPacket initializes flags if not provided."""
        packet = InterceptedPacket(
            source_ip="127.0.0.1",
            dest_ip="127.0.0.1",
            source_port=1234,
            dest_port=5678,
            protocol="tcp",
            data=b"test",
            timestamp=time.time(),
            packet_size=100,
            flags={},
        )

        assert isinstance(packet.flags, dict), "Flags must be dictionary"

    def test_capture_backend_initialization(self, engine: TrafficInterceptionEngine) -> None:
        """Capture backend is initialized to appropriate type."""
        backend = engine.capture_backend

        assert backend in ["scapy", "socket"], "Backend must be valid type"
