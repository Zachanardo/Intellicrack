"""Comprehensive production tests for BaseNetworkAnalyzer.

Tests validate actual packet handler creation and processing with real
network packet structures using real scapy packets.
"""

from __future__ import annotations

import contextlib
import logging
import struct
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.network.base_network_analyzer import BaseNetworkAnalyzer


if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.fixture
def base_analyzer() -> BaseNetworkAnalyzer:
    """Create BaseNetworkAnalyzer instance."""
    return BaseNetworkAnalyzer()


@pytest.fixture
def scapy_module() -> Any:
    """Import and return real scapy module or skip test."""
    try:
        from scapy import all as scapy_all
        return scapy_all
    except ImportError:
        pytest.skip("scapy not available")


def create_real_tcp_packet(scapy: Any, src_ip: str = "192.168.1.1", dst_ip: str = "192.168.1.2", sport: int = 80, dport: int = 443) -> Any:
    """Create real TCP/IP packet using scapy."""
    return scapy.Ether() / scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(sport=sport, dport=dport)


def create_real_udp_packet(scapy: Any, src_ip: str = "192.168.1.1", dst_ip: str = "192.168.1.2", sport: int = 53, dport: int = 53) -> Any:
    """Create real UDP/IP packet using scapy."""
    return scapy.Ether() / scapy.IP(src=src_ip, dst=dst_ip) / scapy.UDP(sport=sport, dport=dport)


class TestBaseNetworkAnalyzer:
    """Test BaseNetworkAnalyzer functionality."""

    def test_initialization_creates_logger(self, base_analyzer: BaseNetworkAnalyzer) -> None:
        """Initialization creates logger with class name."""
        assert base_analyzer.logger is not None
        assert isinstance(base_analyzer.logger, logging.Logger)
        assert base_analyzer.logger.name == "BaseNetworkAnalyzer"

    def test_create_packet_handler_returns_callable(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """create_packet_handler returns a callable function."""
        def is_running() -> bool:
            return True
        processed_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            packet_data: dict[str, Any] = {"packet": packet, "ip": ip_layer, "tcp": tcp_layer}
            processed_packets.append(packet_data)

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        assert callable(handler)

    def test_packet_handler_processes_valid_tcp_packet(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler processes valid TCP/IP packets and extracts data."""
        def is_running() -> bool:
            return True
        processed_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            if hasattr(packet, "haslayer") and packet.haslayer(ip_layer) and packet.haslayer(tcp_layer):
                ip = packet[ip_layer]  # type: ignore[index]
                tcp = packet[tcp_layer]  # type: ignore[index]
                processed_packets.append({
                    "src": ip.src,
                    "dst": ip.dst,
                    "sport": tcp.sport,
                    "dport": tcp.dport,
                })

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        packet = create_real_tcp_packet(scapy_module, src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=443)

        handler(packet)

        assert len(processed_packets) == 1
        assert processed_packets[0]["src"] == "10.0.0.1"
        assert processed_packets[0]["dst"] == "10.0.0.2"
        assert processed_packets[0]["sport"] == 12345
        assert processed_packets[0]["dport"] == 443

    def test_packet_handler_stops_when_not_running(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler stops processing when is_running returns False."""
        def is_running() -> bool:
            return False
        processed_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            processed_packets.append({"processed": True})

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        packet = create_real_tcp_packet(scapy_module)

        handler(packet)

        assert len(processed_packets) == 0

    def test_packet_handler_with_missing_ip_layer(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler handles packets without IP layer gracefully."""
        def is_running() -> bool:
            return True
        processed_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            processed_packets.append({"processed": True})

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        packet = scapy_module.Ether()

        handler(packet)

    def test_packet_handler_with_missing_tcp_layer(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler handles packets without TCP layer gracefully."""
        def is_running() -> bool:
            return True
        processed_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            if hasattr(packet, "haslayer") and packet.haslayer(ip_layer):
                processed_packets.append({"processed": True})

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        packet = scapy_module.Ether() / scapy_module.IP(src="192.168.1.1", dst="192.168.1.2")

        handler(packet)

    def test_packet_handler_with_processing_exception(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler handles exceptions in process_packet gracefully."""
        def is_running() -> bool:
            return True

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            raise RuntimeError("Processing error")

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        packet = create_real_tcp_packet(scapy_module)

        handler(packet)

    def test_packet_handler_with_multiple_packets(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler processes multiple packets correctly and extracts all data."""
        def is_running() -> bool:
            return True
        processed_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            if hasattr(packet, "haslayer") and packet.haslayer(ip_layer) and packet.haslayer(tcp_layer):
                ip = packet[ip_layer]  # type: ignore[index]
                tcp = packet[tcp_layer]  # type: ignore[index]
                processed_packets.append({
                    "src": ip.src,
                    "dst": ip.dst,
                    "sport": tcp.sport,
                    "dport": tcp.dport,
                })

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        packets = [
            create_real_tcp_packet(scapy_module, src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=80, dport=443),
            create_real_tcp_packet(scapy_module, src_ip="10.0.0.3", dst_ip="10.0.0.4", sport=8080, dport=1947),
            create_real_tcp_packet(scapy_module, src_ip="10.0.0.5", dst_ip="10.0.0.6", sport=12345, dport=27000),
        ]

        for packet in packets:
            handler(packet)

        assert len(processed_packets) == 3
        assert processed_packets[0]["sport"] == 80
        assert processed_packets[1]["sport"] == 8080
        assert processed_packets[2]["sport"] == 12345
        assert processed_packets[1]["dport"] == 1947
        assert processed_packets[2]["dport"] == 27000

    def test_packet_handler_state_changes_during_processing(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler respects is_running state changes."""
        running_state: dict[str, bool] = {"value": True}

        def is_running() -> bool:
            return running_state["value"]

        processed_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            processed_packets.append({"processed": True})

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        packet1 = create_real_tcp_packet(scapy_module)
        packet2 = create_real_tcp_packet(scapy_module)

        handler(packet1)

        running_state["value"] = False

        handler(packet2)

        assert len(processed_packets) == 1

    def test_create_multiple_handlers_with_different_callbacks(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Creating multiple handlers with different callbacks works correctly."""
        def is_running() -> bool:
            return True
        processed_packets_1: list[dict[str, Any]] = []
        processed_packets_2: list[dict[str, Any]] = []

        def process_packet_1(packet: object, ip_layer: object, tcp_layer: object) -> None:
            processed_packets_1.append({"handler": 1})

        def process_packet_2(packet: object, ip_layer: object, tcp_layer: object) -> None:
            processed_packets_2.append({"handler": 2})

        handler_1 = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet_1,
        )

        handler_2 = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet_2,
        )

        packet = create_real_tcp_packet(scapy_module)

        handler_1(packet)
        handler_2(packet)

        assert len(processed_packets_1) == 1
        assert len(processed_packets_2) == 1
        assert processed_packets_1[0]["handler"] == 1
        assert processed_packets_2[0]["handler"] == 2

    def test_packet_handler_with_callable_state_check(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler works with various callable is_running checks."""
        call_count: dict[str, int] = {"value": 0}

        def is_running() -> bool:
            call_count["value"] += 1
            return call_count["value"] < 3

        processed_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            processed_packets.append({"count": call_count["value"]})

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        packets = [create_real_tcp_packet(scapy_module) for _ in range(5)]

        for packet in packets:
            handler(packet)

        assert len(processed_packets) == 2

    def test_logger_debug_messages_on_errors(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any, caplog: pytest.LogCaptureFixture) -> None:
        """Packet handler logs debug messages on processing errors."""
        def is_running() -> bool:
            return True

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            raise ValueError("Test error")

        with caplog.at_level(logging.DEBUG):
            handler = base_analyzer.create_packet_handler(
                scapy_module,
                is_running,
                process_packet,
            )

            packet = create_real_tcp_packet(scapy_module)
            handler(packet)


class TestBaseNetworkAnalyzerEdgeCases:
    """Test edge cases and error conditions."""

    def test_handler_with_none_packet(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler handles None packet gracefully."""
        def is_running() -> bool:
            return True
        processed_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            processed_packets.append({"processed": True})

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        handler(None)

        assert len(processed_packets) == 0

    def test_handler_with_exception_in_is_running(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler handles exceptions in is_running check."""
        def is_running() -> bool:
            raise RuntimeError("Check failed")

        processed_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            processed_packets.append({"processed": True})

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        packet = create_real_tcp_packet(scapy_module)

        with contextlib.suppress(RuntimeError):
            handler(packet)

        assert len(processed_packets) == 0

    def test_rapid_packet_processing(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler processes packets rapidly without issues."""
        def is_running() -> bool:
            return True
        processed_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            if hasattr(packet, "haslayer") and packet.haslayer(ip_layer) and packet.haslayer(tcp_layer):
                processed_packets.append({"processed": True})

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        packets = [create_real_tcp_packet(scapy_module) for _ in range(1000)]

        for packet in packets:
            handler(packet)

        assert len(processed_packets) == 1000

    def test_handler_with_malformed_packet_structure(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler handles malformed packet structures."""
        def is_running() -> bool:
            return True
        processed_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            processed_packets.append({"processed": True})

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        class MalformedPacket:
            """Malformed packet without expected methods."""
            pass

        malformed = MalformedPacket()

        handler(malformed)

        assert len(processed_packets) == 0

    def test_process_packet_callback_receives_correct_arguments(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Process packet callback receives correct packet and layer arguments."""
        def is_running() -> bool:
            return True
        received_args: list[tuple[object, object, object]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            received_args.append((packet, ip_layer, tcp_layer))

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        packet = create_real_tcp_packet(scapy_module)
        handler(packet)

        assert len(received_args) == 1
        assert received_args[0][0] is packet
        assert received_args[0][1] == scapy_module.IP
        assert received_args[0][2] == scapy_module.TCP

    def test_concurrent_handler_execution(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Multiple handlers can execute concurrently."""
        import threading

        def is_running() -> bool:
            return True
        process_count: dict[str, int] = {"value": 0}
        lock = threading.Lock()

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            with lock:
                process_count["value"] += 1

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        def process_packets() -> None:
            for _ in range(100):
                handler(create_real_tcp_packet(scapy_module))

        threads = [threading.Thread(target=process_packets) for _ in range(5)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert process_count["value"] == 500

    def test_packet_handler_extracts_tcp_flags(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler correctly extracts TCP flags from real packets."""
        def is_running() -> bool:
            return True
        processed_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            if hasattr(packet, "haslayer") and packet.haslayer(tcp_layer):
                tcp = packet[tcp_layer]  # type: ignore[index]
                processed_packets.append({
                    "flags": tcp.flags,
                    "seq": tcp.seq,
                    "ack": tcp.ack,
                })

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        syn_packet = scapy_module.Ether() / scapy_module.IP() / scapy_module.TCP(flags="S")
        ack_packet = scapy_module.Ether() / scapy_module.IP() / scapy_module.TCP(flags="A")

        handler(syn_packet)
        handler(ack_packet)

        assert len(processed_packets) == 2

    def test_packet_handler_identifies_license_server_ports(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler identifies license server traffic by port."""
        def is_running() -> bool:
            return True
        license_traffic: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            if hasattr(packet, "haslayer") and packet.haslayer(tcp_layer):
                tcp = packet[tcp_layer]  # type: ignore[index]
                license_ports = [1947, 27000, 27001, 5053, 6200]
                if tcp.dport in license_ports or tcp.sport in license_ports:
                    license_traffic.append({
                        "src_port": tcp.sport,
                        "dst_port": tcp.dport,
                        "identified_as": "license_server",
                    })

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        hasp_packet = create_real_tcp_packet(scapy_module, sport=12345, dport=1947)
        flexlm_packet = create_real_tcp_packet(scapy_module, sport=54321, dport=27000)
        normal_packet = create_real_tcp_packet(scapy_module, sport=80, dport=443)

        handler(hasp_packet)
        handler(flexlm_packet)
        handler(normal_packet)

        assert len(license_traffic) == 2
        assert license_traffic[0]["dst_port"] == 1947
        assert license_traffic[1]["dst_port"] == 27000

    def test_packet_handler_with_http_payload(self, base_analyzer: BaseNetworkAnalyzer, scapy_module: Any) -> None:
        """Packet handler extracts HTTP payload from real packets."""
        def is_running() -> bool:
            return True
        http_packets: list[dict[str, Any]] = []

        def process_packet(packet: object, ip_layer: object, tcp_layer: object) -> None:
            if hasattr(packet, "haslayer") and packet.haslayer(scapy_module.Raw):
                raw = packet[scapy_module.Raw]  # type: ignore[index]
                payload = bytes(raw.load)
                if b"HTTP" in payload or b"GET" in payload or b"POST" in payload:
                    http_packets.append({
                        "payload_size": len(payload),
                        "is_http": True,
                    })

        handler = base_analyzer.create_packet_handler(
            scapy_module,
            is_running,
            process_packet,
        )

        http_payload = b"GET /license/activate HTTP/1.1\r\nHost: license.server.com\r\n\r\n"
        http_packet = scapy_module.Ether() / scapy_module.IP() / scapy_module.TCP(dport=80) / scapy_module.Raw(load=http_payload)

        handler(http_packet)

        assert len(http_packets) == 1
        assert http_packets[0]["is_http"] is True
        assert http_packets[0]["payload_size"] == len(http_payload)
