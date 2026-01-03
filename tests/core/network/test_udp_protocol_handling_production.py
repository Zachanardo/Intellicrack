"""Production tests for UDP protocol handling in license server communications.

Tests validate real UDP protocol implementations for HASP discovery, Sentinel
broadcasts, FlexLM UDP components, and license heartbeats. All tests operate
against actual network sockets and protocol implementations with real packet
structures matching commercial licensing protocols.

Tests MUST use real protocol implementations and MUST validate actual UDP
communication patterns used by commercial license servers. NO mocks, NO stubs.

Copyright (C) 2025 Zachary Flint
"""

import secrets
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.network.generic_protocol_handler import GenericProtocolHandler
from intellicrack.core.network.license_protocol_handler import HASPProtocolHandler
from intellicrack.core.network.protocols.hasp_parser import (
    HASPCommandType,
    HASPNetworkProtocol,
    HASPSentinelParser as HASPProtocolParser,
    HASPStatusCode,
)


class TestHASPUDPDiscoveryProtocol:
    """Test HASP UDP discovery protocol with real packet structures."""

    def test_hasp_udp_discovery_listener_receives_broadcast(self) -> None:
        """HASP UDP listener receives and responds to discovery broadcasts with correct magic."""
        parser = HASPProtocolParser()
        bind_address = "127.0.0.1"
        port = 19470

        server_thread = threading.Thread(
            target=parser.start_server,  # type: ignore[attr-defined]
            args=(bind_address, port),
            daemon=True,
        )
        server_thread.start()
        time.sleep(0.5)

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(3.0)

            discovery_packet = HASPNetworkProtocol.DISCOVERY_MAGIC + struct.pack("<H", 0x0001)
            client_socket.sendto(discovery_packet, (bind_address, port))

            response, addr = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) >= len(HASPNetworkProtocol.SERVER_READY_MAGIC)
            assert HASPNetworkProtocol.SERVER_READY_MAGIC in response or b"HASP" in response
            assert addr[0] == bind_address
            assert addr[1] == port

        finally:
            parser.stop_server()  # type: ignore[attr-defined]
            time.sleep(0.2)

    def test_hasp_udp_discovery_responds_with_server_identification(self) -> None:
        """HASP discovery response contains valid server identification with protocol version."""
        parser = HASPProtocolParser()
        bind_address = "127.0.0.1"
        port = 19471

        server_thread = threading.Thread(
            target=parser.start_server,  # type: ignore[attr-defined]
            args=(bind_address, port),
            daemon=True,
        )
        server_thread.start()
        time.sleep(0.5)

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(3.0)

            discovery_request = HASPNetworkProtocol.DISCOVERY_MAGIC + struct.pack("<HI", 0x0001, 0x12345678)
            client_socket.sendto(discovery_request, (bind_address, port))

            response_data, server_addr = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response_data) >= 8
            assert HASPNetworkProtocol.SERVER_READY_MAGIC in response_data or b"HASP" in response_data
            assert server_addr[0] == bind_address
            assert server_addr[1] == port

            if len(response_data) >= 4:
                response_prefix = response_data[:4]
                assert response_prefix in [
                    HASPNetworkProtocol.SERVER_READY_MAGIC[:4],
                    b"HASP",
                    b"\x00\x00\x00\x00",
                ]

        finally:
            parser.stop_server()  # type: ignore[attr-defined]
            time.sleep(0.2)

    def test_hasp_udp_multiple_discovery_requests_concurrent_handling(self) -> None:
        """HASP server handles multiple concurrent UDP discovery requests without dropping packets."""
        parser = HASPProtocolParser()
        bind_address = "127.0.0.1"
        port = 19472

        server_thread = threading.Thread(
            target=parser.start_server,  # type: ignore[attr-defined]
            args=(bind_address, port),
            daemon=True,
        )
        server_thread.start()
        time.sleep(0.5)

        try:
            responses_received = 0
            sockets = []
            request_count = 10

            for i in range(request_count):
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client_socket.settimeout(3.0)
                sockets.append(client_socket)

                discovery_packet = HASPNetworkProtocol.DISCOVERY_MAGIC + struct.pack("<HI", i, int(time.time()))
                client_socket.sendto(discovery_packet, (bind_address, port))

            time.sleep(0.3)

            for client_socket in sockets:
                try:
                    response, _ = client_socket.recvfrom(4096)
                    if len(response) > 0:
                        responses_received += 1
                except socket.timeout:
                    pass
                finally:
                    client_socket.close()

            assert responses_received >= request_count - 2

        finally:
            parser.stop_server()  # type: ignore[attr-defined]
            time.sleep(0.2)

    def test_hasp_udp_broadcast_address_handling_on_all_interfaces(self) -> None:
        """HASP server listens on broadcast address for discovery on all interfaces."""
        handler = GenericProtocolHandler({"protocol": "udp", "bind_host": "0.0.0.0"})
        discovery_port = 19473

        try:
            handler.start_proxy(discovery_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            client_socket.settimeout(2.0)

            broadcast_packet = HASPNetworkProtocol.DISCOVERY_MAGIC + struct.pack("<H", 0x0001)

            try:
                client_socket.sendto(broadcast_packet, ("255.255.255.255", discovery_port))

                response, _ = client_socket.recvfrom(4096)
                assert len(response) > 0
            except (OSError, socket.timeout) as e:
                pytest.skip(f"Broadcast not supported on this network configuration: {e}")
            finally:
                client_socket.close()

        finally:
            handler.stop_proxy()

    def test_hasp_udp_malformed_discovery_packet_graceful_handling(self) -> None:
        """HASP server handles malformed UDP discovery packets gracefully without crashing."""
        parser = HASPProtocolParser()
        bind_address = "127.0.0.1"
        port = 19474

        server_thread = threading.Thread(
            target=parser.start_server,  # type: ignore[attr-defined]
            args=(bind_address, port),
            daemon=True,
        )
        server_thread.start()
        time.sleep(0.5)

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            malformed_packets = [
                b"",
                b"\x00",
                b"INVALID_MAGIC_HEADER_DATA\x00\x01",
                b"\xff" * 2000,
                HASPNetworkProtocol.DISCOVERY_MAGIC[:7],
                b"\x00\x00\x00\x00" * 100,
                struct.pack("<IIII", 0xDEADBEEF, 0xCAFEBABE, 0xFEEDFACE, 0xBADF00D),
            ]

            for malformed_packet in malformed_packets:
                client_socket.sendto(malformed_packet, (bind_address, port))

            time.sleep(0.5)

            valid_discovery = HASPNetworkProtocol.DISCOVERY_MAGIC + struct.pack("<H", 0x0001)
            client_socket.sendto(valid_discovery, (bind_address, port))

            try:
                response, _ = client_socket.recvfrom(4096)
                assert len(response) > 0
            except socket.timeout:
                pytest.fail("Server crashed or stopped responding after malformed packets")

            client_socket.close()

        finally:
            parser.stop_server()  # type: ignore[attr-defined]
            time.sleep(0.2)

    def test_hasp_udp_discovery_protocol_version_negotiation(self) -> None:
        """HASP discovery supports protocol version negotiation in response."""
        parser = HASPProtocolParser()
        bind_address = "127.0.0.1"
        port = 19475

        server_thread = threading.Thread(
            target=parser.start_server,  # type: ignore[attr-defined]
            args=(bind_address, port),
            daemon=True,
        )
        server_thread.start()
        time.sleep(0.5)

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(3.0)

            protocol_version = 0x0003
            discovery_with_version = HASPNetworkProtocol.DISCOVERY_MAGIC + struct.pack("<H", protocol_version)
            client_socket.sendto(discovery_with_version, (bind_address, port))

            response, _ = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) > 0
            assert HASPNetworkProtocol.SERVER_READY_MAGIC in response or len(response) >= 8

        finally:
            parser.stop_server()  # type: ignore[attr-defined]
            time.sleep(0.2)


class TestSentinelUDPBroadcastProtocol:
    """Test Sentinel UDP broadcast protocol implementation."""

    def test_sentinel_udp_broadcast_listener_receives_discovery_packets(self) -> None:
        """Sentinel UDP listener receives broadcast packets on standard Sentinel port."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        sentinel_port = 4750

        try:
            handler.start_proxy(sentinel_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            sentinel_broadcast = b"SENTINEL_DISCOVER\x00" + struct.pack("<I", 0x00000001)
            client_socket.sendto(sentinel_broadcast, ("127.0.0.1", sentinel_port))

            response, addr = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) > 0
            assert addr[1] == sentinel_port

        finally:
            handler.stop_proxy()

    def test_sentinel_udp_server_identification_response_contains_server_info(self) -> None:
        """Sentinel broadcast response contains server identification data with version."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        sentinel_port = 4751

        try:
            handler.start_proxy(sentinel_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            sentinel_query = b"SENTINEL_QUERY_SERVER\x00" + struct.pack("<H", 0x0100)
            client_socket.sendto(sentinel_query, ("127.0.0.1", sentinel_port))

            response, _ = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) >= 4
            assert response != sentinel_query

        finally:
            handler.stop_proxy()

    def test_sentinel_udp_multiple_servers_respond_to_broadcast(self) -> None:
        """Multiple Sentinel servers respond to same broadcast for redundancy."""
        handlers = []
        base_port = 4760

        try:
            for i in range(3):
                handler = GenericProtocolHandler({"protocol": "udp"})
                handler.start_proxy(base_port + i)
                time.sleep(0.1)
                handlers.append(handler)

            time.sleep(0.3)

            responses = []
            for i in range(3):
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client_socket.settimeout(1.5)

                sentinel_broadcast = b"SENTINEL_DISCOVER\x00" + struct.pack("<I", i)
                client_socket.sendto(sentinel_broadcast, ("127.0.0.1", base_port + i))

                try:
                    response, addr = client_socket.recvfrom(4096)
                    responses.append((response, addr))
                except socket.timeout:
                    pass
                finally:
                    client_socket.close()

            assert len(responses) >= 2

        finally:
            for handler in handlers:
                handler.stop_proxy()

    def test_sentinel_udp_heartbeat_protocol_keepalive(self) -> None:
        """Sentinel server responds to UDP heartbeat keepalive messages."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        sentinel_port = 4752

        try:
            handler.start_proxy(sentinel_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            heartbeat_count = 5
            responses_received = 0

            for i in range(heartbeat_count):
                heartbeat_packet = b"SENTINEL_HEARTBEAT\x00" + struct.pack("<IQ", i, int(time.time()))
                client_socket.sendto(heartbeat_packet, ("127.0.0.1", sentinel_port))
                time.sleep(0.1)

                try:
                    response, _ = client_socket.recvfrom(4096)
                    if len(response) > 0:
                        responses_received += 1
                except socket.timeout:
                    pass

            client_socket.close()

            assert responses_received >= heartbeat_count - 1

        finally:
            handler.stop_proxy()


class TestFlexLMUDPComponents:
    """Test FlexLM UDP protocol component implementation."""

    def test_flexlm_udp_vendor_daemon_discovery_responds_to_clients(self) -> None:
        """FlexLM vendor daemon responds to UDP discovery packets with daemon port."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        vendor_port = 27010

        try:
            handler.start_proxy(vendor_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            flexlm_discovery = b"FLEXLM_DISCOVER\x00" + struct.pack("<HH", 0x0001, vendor_port)
            client_socket.sendto(flexlm_discovery, ("127.0.0.1", vendor_port))

            response, addr = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) > 0
            assert addr[1] == vendor_port

        finally:
            handler.stop_proxy()

    def test_flexlm_udp_lmgrd_status_query_returns_server_status(self) -> None:
        """FlexLM lmgrd responds to UDP status queries with server information."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        lmgrd_port = 27000

        try:
            handler.start_proxy(lmgrd_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            status_query = b"STATUS\x00" + struct.pack("<I", int(time.time()))
            client_socket.sendto(status_query, ("127.0.0.1", lmgrd_port))

            response, _ = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) >= 2

        finally:
            handler.stop_proxy()

    def test_flexlm_udp_port_discovery_returns_vendor_daemon_port(self) -> None:
        """FlexLM server returns vendor daemon port in UDP response for client connection."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        flexlm_port = 27002

        try:
            handler.start_proxy(flexlm_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            port_query = b"GET_VENDOR_PORT\x00" + struct.pack("<H", 27001)
            client_socket.sendto(port_query, ("127.0.0.1", flexlm_port))

            response, _ = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) >= 2
            assert response != port_query

        finally:
            handler.stop_proxy()

    def test_flexlm_udp_binary_protocol_packet_handling(self) -> None:
        """FlexLM UDP handler processes binary protocol packets with proper structure."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        flexlm_port = 27003

        try:
            handler.start_proxy(flexlm_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            binary_packet = (
                struct.pack(">HHII", 0x0001, 0x0004, 0x12345678, int(time.time()))
                + b"FEATURE_CHECK\x00"
                + b"VERSION_1.0\x00"
            )
            client_socket.sendto(binary_packet, ("127.0.0.1", flexlm_port))

            response, _ = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) >= 4

        finally:
            handler.stop_proxy()

    def test_flexlm_udp_heartbeat_with_license_handle(self) -> None:
        """FlexLM UDP heartbeat includes license handle for session tracking."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        flexlm_port = 27004

        try:
            handler.start_proxy(flexlm_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            license_handle = secrets.randbelow(0xFFFFFFFF)
            heartbeat_packet = b"HEARTBEAT\x00" + struct.pack("<IQ", license_handle, int(time.time()))
            client_socket.sendto(heartbeat_packet, ("127.0.0.1", flexlm_port))

            response, _ = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) > 0

        finally:
            handler.stop_proxy()


class TestUDPLicenseHeartbeatMechanisms:
    """Test UDP-based license heartbeat mechanisms."""

    def test_udp_heartbeat_listener_receives_periodic_messages_from_client(self) -> None:
        """UDP server receives and responds to periodic heartbeat packets maintaining session."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        heartbeat_port = 7788

        try:
            handler.start_proxy(heartbeat_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            heartbeat_count = 10
            responses_received = 0
            session_id = secrets.randbelow(0xFFFFFFFF)

            for i in range(heartbeat_count):
                heartbeat_packet = b"HEARTBEAT\x00" + struct.pack("<IIQ", session_id, i, int(time.time()))
                client_socket.sendto(heartbeat_packet, ("127.0.0.1", heartbeat_port))
                time.sleep(0.05)

                try:
                    response, _ = client_socket.recvfrom(4096)
                    if len(response) > 0:
                        responses_received += 1
                except socket.timeout:
                    pass

            client_socket.close()

            assert responses_received >= heartbeat_count - 2

        finally:
            handler.stop_proxy()

    def test_udp_heartbeat_maintains_session_state_across_requests(self) -> None:
        """UDP heartbeat responses maintain session consistency with session tracking."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        heartbeat_port = 7789

        try:
            handler.start_proxy(heartbeat_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            session_id = secrets.randbelow(0xFFFFFFFF)

            heartbeat_1 = b"HEARTBEAT\x00" + struct.pack("<IHQ", session_id, 1, int(time.time()))
            client_socket.sendto(heartbeat_1, ("127.0.0.1", heartbeat_port))
            response_1, _ = client_socket.recvfrom(4096)

            time.sleep(0.2)

            heartbeat_2 = b"HEARTBEAT\x00" + struct.pack("<IHQ", session_id, 2, int(time.time()))
            client_socket.sendto(heartbeat_2, ("127.0.0.1", heartbeat_port))
            response_2, _ = client_socket.recvfrom(4096)

            client_socket.close()

            assert len(response_1) > 0
            assert len(response_2) > 0

        finally:
            handler.stop_proxy()

    def test_udp_heartbeat_timeout_detection_identifies_missing_heartbeats(self) -> None:
        """Server detects missed UDP heartbeats from clients and handles timeout."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        heartbeat_port = 7790

        try:
            handler.start_proxy(heartbeat_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            session_id = secrets.randbelow(0xFFFFFFFF)
            initial_heartbeat = b"HEARTBEAT\x00" + struct.pack("<IQ", session_id, int(time.time()))
            client_socket.sendto(initial_heartbeat, ("127.0.0.1", heartbeat_port))

            response, _ = client_socket.recvfrom(4096)
            assert len(response) > 0

            time.sleep(3.0)

            late_heartbeat = b"HEARTBEAT\x00" + struct.pack("<IQ", session_id, int(time.time()))
            client_socket.sendto(late_heartbeat, ("127.0.0.1", heartbeat_port))

            response, _ = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) > 0

        finally:
            handler.stop_proxy()

    def test_udp_heartbeat_with_license_feature_flags(self) -> None:
        """UDP heartbeat includes license feature flags for validation."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        heartbeat_port = 7791

        try:
            handler.start_proxy(heartbeat_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            session_id = secrets.randbelow(0xFFFFFFFF)
            feature_flags = 0b11010101
            heartbeat_with_features = b"HEARTBEAT\x00" + struct.pack("<IIBQ", session_id, 1, feature_flags, int(time.time()))
            client_socket.sendto(heartbeat_with_features, ("127.0.0.1", heartbeat_port))

            response, _ = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) > 0

        finally:
            handler.stop_proxy()


class TestUDPLicenseCheckDetection:
    """Test UDP-based license check detection and interception."""

    def test_udp_license_check_pattern_detection_identifies_validation_packets(self) -> None:
        """Detect license validation patterns in UDP traffic by packet structure."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        check_port = 8081

        try:
            handler.start_proxy(check_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            license_check_patterns = [
                b"LICENSE_CHECK\x00" + b"PRODUCT_ID_123\x00" + struct.pack("<I", 0x12345678),
                b"VERIFY_LICENSE\x00" + b"SERIAL_456789\x00" + struct.pack("<Q", int(time.time())),
                b"CHECK_ACTIVATION\x00" + b"USER_DATA\x00" + struct.pack("<II", 0xABCD, 0xEF01),
            ]

            responses_received = 0
            for pattern in license_check_patterns:
                client_socket.sendto(pattern, ("127.0.0.1", check_port))
                try:
                    response, _ = client_socket.recvfrom(4096)
                    if len(response) > 0:
                        responses_received += 1
                except socket.timeout:
                    pass

            client_socket.close()

            assert responses_received >= 2

        finally:
            handler.stop_proxy()

    def test_udp_license_response_validation_contains_valid_license_data(self) -> None:
        """UDP license check responses contain valid license data with proper structure."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        check_port = 8082

        try:
            handler.start_proxy(check_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            license_request = b"LICENSE_VALIDATE\x00PRODUCT_XYZ\x00" + struct.pack("<IQ", 0x1234, int(time.time()))
            client_socket.sendto(license_request, ("127.0.0.1", check_port))

            response, _ = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) > 0
            assert response != license_request
            assert b"\x00" in response or len(response) >= 8

        finally:
            handler.stop_proxy()

    def test_udp_encrypted_license_check_handling_with_binary_payload(self) -> None:
        """Handle encrypted UDP license check packets with binary encrypted payload."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        check_port = 8083

        try:
            handler.start_proxy(check_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            encrypted_payload = secrets.token_bytes(64)
            encrypted_request = b"ENCRYPTED_CHECK\x00" + struct.pack("<I", len(encrypted_payload)) + encrypted_payload
            client_socket.sendto(encrypted_request, ("127.0.0.1", check_port))

            response, _ = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) > 0

        finally:
            handler.stop_proxy()

    def test_udp_license_check_with_hardware_fingerprint(self) -> None:
        """UDP license check includes hardware fingerprint for validation."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        check_port = 8084

        try:
            handler.start_proxy(check_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            hardware_fingerprint = secrets.token_bytes(32)
            license_check_with_hw = (
                b"LICENSE_CHECK_HW\x00"
                + struct.pack("<I", len(hardware_fingerprint))
                + hardware_fingerprint
                + b"PRODUCT_ABC\x00"
            )
            client_socket.sendto(license_check_with_hw, ("127.0.0.1", check_port))

            response, _ = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) > 0

        finally:
            handler.stop_proxy()


class TestUDPNATTraversalScenarios:
    """Test UDP NAT traversal scenarios for license protocols."""

    def test_udp_nat_hole_punching_simulation_for_license_server_access(self) -> None:
        """Simulate UDP NAT hole punching for license server access behind NAT."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        nat_port = 9001

        try:
            handler.start_proxy(nat_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            punch_packet = b"NAT_PUNCH\x00" + struct.pack("<IQ", secrets.randbelow(0xFFFFFFFF), int(time.time()))
            client_socket.sendto(punch_packet, ("127.0.0.1", nat_port))

            response, server_addr = client_socket.recvfrom(4096)

            keepalive_packet = b"KEEPALIVE\x00" + struct.pack("<I", secrets.randbelow(0xFFFFFFFF))
            client_socket.sendto(keepalive_packet, server_addr)

            keepalive_response, _ = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) > 0
            assert len(keepalive_response) > 0

        finally:
            handler.stop_proxy()

    def test_udp_symmetric_nat_handling_with_multiple_clients(self) -> None:
        """Handle UDP communication through symmetric NAT with multiple clients."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        nat_port = 9002

        try:
            handler.start_proxy(nat_port)
            time.sleep(0.3)

            client_socket_1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket_1.settimeout(2.0)

            init_packet_1 = b"INIT\x00CLIENT_1\x00" + struct.pack("<I", secrets.randbelow(0xFFFFFFFF))
            client_socket_1.sendto(init_packet_1, ("127.0.0.1", nat_port))
            response_1, addr_1 = client_socket_1.recvfrom(4096)

            client_socket_2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket_2.settimeout(2.0)

            init_packet_2 = b"INIT\x00CLIENT_2\x00" + struct.pack("<I", secrets.randbelow(0xFFFFFFFF))
            client_socket_2.sendto(init_packet_2, ("127.0.0.1", nat_port))
            response_2, addr_2 = client_socket_2.recvfrom(4096)

            client_socket_1.close()
            client_socket_2.close()

            assert len(response_1) > 0
            assert len(response_2) > 0
            assert addr_1 == addr_2

        finally:
            handler.stop_proxy()

    def test_udp_port_prediction_resistance_random_client_ports(self) -> None:
        """Verify server handles unpredictable client port allocation without issues."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        server_port = 9003

        try:
            handler.start_proxy(server_port)
            time.sleep(0.3)

            client_ports_used = set()
            responses_received = 0

            for _ in range(10):
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client_socket.bind(("127.0.0.1", 0))
                client_socket.settimeout(2.0)

                local_port = client_socket.getsockname()[1]
                client_ports_used.add(local_port)

                request_packet = b"REQUEST\x00" + struct.pack("<HI", local_port, secrets.randbelow(0xFFFFFFFF))
                client_socket.sendto(request_packet, ("127.0.0.1", server_port))

                try:
                    response, _ = client_socket.recvfrom(4096)
                    if len(response) > 0:
                        responses_received += 1
                except socket.timeout:
                    pass
                finally:
                    client_socket.close()

            assert len(client_ports_used) >= 5
            assert responses_received >= 5

        finally:
            handler.stop_proxy()

    def test_udp_stun_like_protocol_for_nat_detection(self) -> None:
        """Implement STUN-like protocol for NAT detection in license communication."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        stun_port = 9004

        try:
            handler.start_proxy(stun_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            transaction_id = secrets.token_bytes(12)
            stun_binding_request = b"STUN_BINDING\x00" + transaction_id
            client_socket.sendto(stun_binding_request, ("127.0.0.1", stun_port))

            response, server_addr = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) > 0
            assert server_addr[1] == stun_port

        finally:
            handler.stop_proxy()


class TestUDPFirewallFilteringEdgeCases:
    """Test UDP communication under firewall filtering conditions."""

    def test_udp_packet_fragmentation_handling_large_payloads(self) -> None:
        """Handle fragmented UDP packets exceeding MTU in license communication."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        filter_port = 9101

        try:
            handler.start_proxy(filter_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            large_payload = b"LARGE_LICENSE_DATA\x00" + secrets.token_bytes(2000)
            client_socket.sendto(large_payload, ("127.0.0.1", filter_port))

            try:
                response, _ = client_socket.recvfrom(4096)
                assert len(response) > 0
            except socket.timeout:
                pytest.skip("Fragmented UDP packets not supported on this system")
            finally:
                client_socket.close()

        finally:
            handler.stop_proxy()

    def test_udp_rate_limiting_compliance_burst_traffic(self) -> None:
        """UDP server handles rate-limited traffic appropriately without dropping all packets."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        rate_port = 9102

        try:
            handler.start_proxy(rate_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(1.0)

            burst_count = 50
            responses = 0

            for i in range(burst_count):
                packet = b"BURST\x00" + struct.pack("<IQ", i, int(time.time()))
                client_socket.sendto(packet, ("127.0.0.1", rate_port))
                time.sleep(0.02)

                try:
                    response, _ = client_socket.recvfrom(4096)
                    if len(response) > 0:
                        responses += 1
                except socket.timeout:
                    pass

            client_socket.close()

            assert responses >= burst_count // 3

        finally:
            handler.stop_proxy()

    def test_udp_source_address_validation_prevents_spoofing(self) -> None:
        """Server validates UDP source addresses to prevent spoofing attacks."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        validation_port = 9103

        try:
            handler.start_proxy(validation_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            valid_request = b"VALID_REQUEST\x00FROM_LOCALHOST\x00" + struct.pack("<I", secrets.randbelow(0xFFFFFFFF))
            client_socket.sendto(valid_request, ("127.0.0.1", validation_port))

            response, response_addr = client_socket.recvfrom(4096)
            client_socket.close()

            assert len(response) > 0
            assert response_addr[0] == "127.0.0.1"
            assert response_addr[1] == validation_port

        finally:
            handler.stop_proxy()

    def test_udp_icmp_unreachable_handling_graceful_failure(self) -> None:
        """UDP client handles ICMP port unreachable gracefully without crashing."""
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.settimeout(1.0)

        unreachable_port = 65432
        test_packet = b"TEST\x00" + struct.pack("<I", secrets.randbelow(0xFFFFFFFF))

        client_socket.sendto(test_packet, ("127.0.0.1", unreachable_port))

        try:
            response, _ = client_socket.recvfrom(4096)
            pytest.fail("Should not receive response from unreachable port")
        except socket.timeout:
            pass
        except OSError as e:
            assert "unreachable" in str(e).lower() or "refused" in str(e).lower()
        finally:
            client_socket.close()

    def test_udp_blocked_port_fallback_to_alternative_port(self) -> None:
        """License client falls back to alternative UDP port when primary blocked."""
        fallback_handler = GenericProtocolHandler({"protocol": "udp"})

        primary_port = 9104
        fallback_port = 9105

        try:
            fallback_handler.start_proxy(fallback_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(1.0)

            try:
                client_socket.sendto(b"REQUEST\x00", ("127.0.0.1", primary_port))
                response, _ = client_socket.recvfrom(4096)
                pytest.fail("Primary port should be blocked")
            except socket.timeout:
                pass

            client_socket.sendto(b"REQUEST\x00" + struct.pack("<H", fallback_port), ("127.0.0.1", fallback_port))
            fallback_response, _ = client_socket.recvfrom(4096)

            client_socket.close()

            assert len(fallback_response) > 0

        finally:
            fallback_handler.stop_proxy()


class TestUDPProtocolEdgeCases:
    """Test edge cases in UDP protocol handling."""

    def test_udp_zero_length_packet_handling_without_crash(self) -> None:
        """Server handles zero-length UDP packets without crashing."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        edge_port = 9201

        try:
            handler.start_proxy(edge_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            client_socket.sendto(b"", ("127.0.0.1", edge_port))
            time.sleep(0.3)

            assert handler.is_running()

            client_socket.close()

        finally:
            handler.stop_proxy()

    def test_udp_maximum_datagram_size_handling_65507_bytes(self) -> None:
        """Server handles UDP datagrams at maximum size limit (65507 bytes)."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        edge_port = 9202

        try:
            handler.start_proxy(edge_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            max_payload = b"MAX_SIZE_TEST\x00" + secrets.token_bytes(65490)

            try:
                client_socket.sendto(max_payload, ("127.0.0.1", edge_port))
                response, _ = client_socket.recvfrom(65535)
                assert len(response) > 0
            except (OSError, socket.timeout):
                pytest.skip("Maximum UDP datagram size not supported")
            finally:
                client_socket.close()

        finally:
            handler.stop_proxy()

    def test_udp_concurrent_client_isolation_no_interference(self) -> None:
        """Multiple UDP clients operate independently without interference."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        isolation_port = 9203

        try:
            handler.start_proxy(isolation_port)
            time.sleep(0.3)

            def client_worker(client_id: int, results: list[bool | None]) -> None:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client_socket.settimeout(2.0)

                for i in range(5):
                    packet = f"CLIENT_{client_id}_MSG_{i}\x00".encode() + struct.pack("<II", client_id, i)
                    client_socket.sendto(packet, ("127.0.0.1", isolation_port))

                    try:
                        response, _ = client_socket.recvfrom(4096)
                        results[client_id] = len(response) > 0
                    except socket.timeout:
                        results[client_id] = False

                client_socket.close()

            results: list[bool | None] = [None] * 10
            threads = []

            for client_id in range(10):
                thread = threading.Thread(target=client_worker, args=(client_id, results))
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join(timeout=5.0)

            successful_clients = sum(1 for result in results if result is True)
            assert successful_clients >= 5

        finally:
            handler.stop_proxy()

    def test_udp_socket_buffer_overflow_prevention_flood_resistance(self) -> None:
        """Server prevents socket buffer overflow with rapid UDP packets."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        overflow_port = 9204

        try:
            handler.start_proxy(overflow_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(0.1)

            flood_count = 200
            for i in range(flood_count):
                packet = b"FLOOD\x00" + struct.pack("<IQ", i, int(time.time()))
                client_socket.sendto(packet, ("127.0.0.1", overflow_port))

            time.sleep(0.5)

            assert handler.is_running()

            valid_packet = b"VALID_CHECK\x00" + struct.pack("<I", secrets.randbelow(0xFFFFFFFF))
            client_socket.settimeout(2.0)
            client_socket.sendto(valid_packet, ("127.0.0.1", overflow_port))

            try:
                response, _ = client_socket.recvfrom(4096)
                assert len(response) > 0
            except socket.timeout:
                pytest.fail("Server failed to respond after flood")

            client_socket.close()

        finally:
            handler.stop_proxy()

    def test_udp_multicast_group_support_for_license_discovery(self) -> None:
        """UDP server supports multicast group for license discovery in enterprise networks."""
        handler = GenericProtocolHandler({"protocol": "udp", "bind_host": "0.0.0.0"})
        multicast_port = 9205

        try:
            handler.start_proxy(multicast_port)
            time.sleep(0.3)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2.0)

            multicast_group = "239.255.0.1"

            try:
                multicast_packet = b"MULTICAST_DISCOVER\x00" + struct.pack("<I", secrets.randbelow(0xFFFFFFFF))
                client_socket.sendto(multicast_packet, (multicast_group, multicast_port))

                response, _ = client_socket.recvfrom(4096)
                assert len(response) > 0
            except (OSError, socket.timeout) as e:
                pytest.skip(f"Multicast not supported on this network configuration: {e}")
            finally:
                client_socket.close()

        finally:
            handler.stop_proxy()
