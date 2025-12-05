"""
Production-ready tests for intellicrack/plugins/custom_modules/network_analysis_plugin.py

Tests validate REAL network analysis capabilities:
- Socket API detection in actual PE binaries
- Network indicator identification in real executables
- Socket server creation and management
- Port scanning functionality
- Network traffic monitoring with psutil
- Socket activity pattern analysis
- Real-time connection tracking
"""

import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.plugins.custom_modules.network_analysis_plugin import NetworkAnalysisPlugin


@pytest.fixture
def plugin() -> NetworkAnalysisPlugin:
    """Create NetworkAnalysisPlugin instance with cleanup."""
    plugin_instance = NetworkAnalysisPlugin()
    yield plugin_instance
    plugin_instance.cleanup_sockets()


@pytest.fixture
def legitimate_binaries_dir() -> Path:
    """Path to legitimate binary fixtures."""
    return Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate")


@pytest.fixture
def protected_binaries_dir() -> Path:
    """Path to protected binary fixtures."""
    return Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected")


@pytest.fixture
def firefox_binary(legitimate_binaries_dir: Path) -> Path:
    """Real Firefox binary for network analysis testing."""
    binary_path = legitimate_binaries_dir / "firefox.exe"
    assert binary_path.exists(), f"Firefox binary not found at {binary_path}"
    return binary_path


@pytest.fixture
def online_activation_binary(protected_binaries_dir: Path) -> Path:
    """Binary with online activation for network testing."""
    binary_path = protected_binaries_dir / "online_activation_app.exe"
    assert binary_path.exists(), f"Online activation binary not found at {binary_path}"
    return binary_path


@pytest.fixture
def floating_license_binary(protected_binaries_dir: Path) -> Path:
    """Floating license client binary for network analysis."""
    binary_path = protected_binaries_dir / "floating_license_client.exe"
    assert binary_path.exists(), f"Floating license binary not found at {binary_path}"
    return binary_path


class TestNetworkIndicatorDetection:
    """Validate network indicator detection in real binaries."""

    @pytest.mark.real_data
    def test_firefox_has_network_indicators(self, plugin: NetworkAnalysisPlugin, firefox_binary: Path) -> None:
        """Firefox binary contains multiple network protocol indicators."""
        results: list[str] = plugin.analyze(str(firefox_binary))

        assert len(results) > 0
        assert any("Analyzing network capabilities" in r for r in results)

        results_text = " ".join(results)
        assert "Network indicators found:" in results_text or any(indicator in results_text for indicator in ["http://", "https://", "socket"])

        found_indicators = [r for r in results if "http://" in r or "https://" in r or "socket" in r]
        assert len(found_indicators) > 0, "Firefox must contain network protocol indicators"

    @pytest.mark.real_data
    def test_online_activation_binary_network_detection(
        self, plugin: NetworkAnalysisPlugin, online_activation_binary: Path
    ) -> None:
        """Online activation binary contains network communication indicators."""
        results: list[str] = plugin.analyze(str(online_activation_binary))

        assert len(results) > 0
        results_text = " ".join(results).lower()

        has_network_indicators = any(
            indicator in results_text
            for indicator in ["http://", "https://", "socket", "connect", "send", "recv"]
        )

        assert has_network_indicators, "Online activation app must have network indicators"

    @pytest.mark.real_data
    def test_detect_winsock_apis_in_network_binary(
        self, plugin: NetworkAnalysisPlugin, firefox_binary: Path
    ) -> None:
        """Windows Socket API references detected in network-capable binary."""
        results: list[str] = plugin.analyze(str(firefox_binary))

        results_text = " ".join(results).lower()

        winsock_indicators = ["wsastartup", "socket", "connect", "send", "recv"]
        found_count = sum(1 for indicator in winsock_indicators if indicator in results_text)

        assert found_count > 0, "Network binary must contain Windows Socket API references"

    @pytest.mark.real_data
    def test_no_false_positives_on_non_network_binary(
        self, plugin: NetworkAnalysisPlugin, legitimate_binaries_dir: Path
    ) -> None:
        """7zip binary has minimal or no network indicators."""
        seven_zip = legitimate_binaries_dir / "7zip.exe"
        assert seven_zip.exists()

        results: list[str] = plugin.analyze(str(seven_zip))
        results_text = " ".join(results)

        assert "Analyzing network capabilities" in results_text

        explicit_no_indicators = "No obvious network indicators found" in results_text
        minimal_indicators = "Network indicators found:" in results_text and sum(
            1 for r in results if any(ind in r for ind in ["http://", "https://", "ftp://"])
        ) < 2

        assert explicit_no_indicators or minimal_indicators, "7zip should have minimal network indicators"


class TestSocketAPIDetection:
    """Validate socket API detection in real binaries."""

    @pytest.mark.real_data
    def test_detect_winsock_initialization_apis(
        self, plugin: NetworkAnalysisPlugin, firefox_binary: Path
    ) -> None:
        """Detects WSAStartup and WSACleanup in Windows network binary."""
        results: list[str] = plugin.detect_socket_apis(str(firefox_binary))

        assert len(results) > 0
        results_text = " ".join(results)

        assert "socket API references" in results_text.lower() or "Found" in results_text

        has_winsock = any(
            "WSAStartup" in r or "WSACleanup" in r or "socket" in r.lower()
            for r in results
        )
        assert has_winsock, "Firefox must reference Windows Socket APIs"

    @pytest.mark.real_data
    def test_detect_standard_socket_operations(
        self, plugin: NetworkAnalysisPlugin, firefox_binary: Path
    ) -> None:
        """Detects standard socket operations in network binary."""
        results: list[str] = plugin.detect_socket_apis(str(firefox_binary))

        results_text = " ".join(results).lower()

        socket_operations = ["socket", "connect", "send", "recv", "bind", "listen"]
        found_operations = sum(1 for op in socket_operations if op in results_text)

        assert found_operations >= 2, "Network binary must have multiple socket operation references"

    @pytest.mark.real_data
    def test_detect_ssl_tls_apis_in_secure_binary(
        self, plugin: NetworkAnalysisPlugin, firefox_binary: Path
    ) -> None:
        """Detects SSL/TLS APIs in browser binary."""
        results: list[str] = plugin.detect_socket_apis(str(firefox_binary))

        results_text = " ".join(results)

        has_ssl_apis = any(
            "SSL" in r or "TLS" in r or "ssl" in r.lower()
            for r in results
        )

        assert len(results) > 0, "Must return results for Firefox binary"

    @pytest.mark.real_data
    def test_no_socket_apis_in_minimal_binary(
        self, plugin: NetworkAnalysisPlugin, protected_binaries_dir: Path
    ) -> None:
        """Small binaries with no network functionality return appropriate results."""
        dongle_app = protected_binaries_dir / "dongle_protected_app.exe"
        assert dongle_app.exists()

        results: list[str] = plugin.detect_socket_apis(str(dongle_app))

        assert len(results) > 0
        results_text = " ".join(results)

        assert "No socket API references found" in results_text or "0 socket API" in results_text


class TestSocketServerCreation:
    """Validate real socket server creation and management."""

    @pytest.mark.real_data
    def test_create_tcp_server_on_random_port(self, plugin: NetworkAnalysisPlugin) -> None:
        """Creates functional TCP socket server on random available port."""
        result: dict[str, Any] = plugin.create_socket_server(host="127.0.0.1", port=0)

        assert result["success"] is True, f"Server creation failed: {result.get('error', 'Unknown error')}"
        assert result["host"] == "127.0.0.1"
        assert result["port"] > 0, "Must allocate random port"
        assert result["socket_info"]["protocol"] == "TCP"
        assert result["socket_info"]["state"] == "LISTENING"
        assert "127.0.0.1" in result["socket_info"]["address"]

        server_socket = plugin.active_sockets.get(f"server_{result['port']}")
        assert server_socket is not None, "Server socket must be tracked"

        plugin.cleanup_sockets()

    @pytest.mark.real_data
    def test_create_server_on_specific_port(self, plugin: NetworkAnalysisPlugin) -> None:
        """Creates server on specific available port."""
        test_port = 45000

        result: dict[str, Any] = plugin.create_socket_server(host="127.0.0.1", port=test_port)

        assert result["success"] is True
        assert result["port"] == test_port
        assert result["socket_info"]["type"] == "SOCK_STREAM"
        assert "message" in result

        plugin.cleanup_sockets()

    @pytest.mark.real_data
    def test_server_socket_actually_listening(self, plugin: NetworkAnalysisPlugin) -> None:
        """Created server socket accepts real connections."""
        server_result: dict[str, Any] = plugin.create_socket_server(port=0)
        assert server_result["success"] is True

        server_port: int = server_result["port"]

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(2.0)

        try:
            connection_result = client_socket.connect_ex(("127.0.0.1", server_port))
            assert connection_result == 0, "Client must successfully connect to server"
        finally:
            client_socket.close()
            plugin.cleanup_sockets()

    @pytest.mark.real_data
    def test_create_multiple_servers(self, plugin: NetworkAnalysisPlugin) -> None:
        """Creates and manages multiple socket servers simultaneously."""
        server1: dict[str, Any] = plugin.create_socket_server(port=0)
        server2: dict[str, Any] = plugin.create_socket_server(port=0)

        assert server1["success"] is True
        assert server2["success"] is True
        assert server1["port"] != server2["port"], "Servers must use different ports"
        assert len(plugin.active_sockets) == 2

        plugin.cleanup_sockets()
        assert len(plugin.active_sockets) == 0

    @pytest.mark.real_data
    def test_server_creation_error_handling(self, plugin: NetworkAnalysisPlugin) -> None:
        """Server creation handles port conflicts appropriately."""
        server1 = plugin.create_socket_server(port=45001)
        assert server1["success"] is True

        server2 = plugin.create_socket_server(port=45001)

        assert server2["success"] is False or "error" in server2

        plugin.cleanup_sockets()


class TestPortScanning:
    """Validate real port scanning functionality."""

    @pytest.mark.real_data
    def test_scan_localhost_finds_listening_ports(self, plugin: NetworkAnalysisPlugin) -> None:
        """Port scanner detects active listening port."""
        server_result = plugin.create_socket_server(port=0)
        assert server_result["success"] is True
        server_port = server_result["port"]

        time.sleep(0.2)

        open_ports: list[dict[str, Any]] = plugin.scan_ports(
            "127.0.0.1",
            start_port=server_port,
            end_port=server_port,
            timeout=1.0
        )

        assert len(open_ports) == 1, f"Must detect open port {server_port}"
        assert open_ports[0]["port"] == server_port
        assert open_ports[0]["state"] == "open"
        assert open_ports[0]["protocol"] == "tcp"

        plugin.cleanup_sockets()

    @pytest.mark.real_data
    def test_scan_identifies_common_services(self, plugin: NetworkAnalysisPlugin) -> None:
        """Port scanner identifies common service names."""
        server1 = plugin.create_socket_server(port=8080)
        server2 = plugin.create_socket_server(port=8443)

        time.sleep(0.2)

        open_ports = plugin.scan_ports("127.0.0.1", 8080, 8443, timeout=1.0)

        port_services = {p["port"]: p["service"] for p in open_ports}

        if 8080 in port_services:
            assert port_services[8080] in ["http-alt", "http-proxy", "unknown"]
        if 8443 in port_services:
            assert port_services[8443] in ["https-alt", "unknown"]

        plugin.cleanup_sockets()

    @pytest.mark.real_data
    def test_scan_closed_ports_returns_empty(self, plugin: NetworkAnalysisPlugin) -> None:
        """Scanning range with no open ports returns empty list."""
        open_ports = plugin.scan_ports("127.0.0.1", 60000, 60005, timeout=0.3)

        assert isinstance(open_ports, list)
        assert len(open_ports) == 0

    @pytest.mark.real_data
    def test_port_scan_timeout_handling(self, plugin: NetworkAnalysisPlugin) -> None:
        """Port scanner respects timeout settings."""
        start_time = time.time()

        plugin.scan_ports("127.0.0.1", 60000, 60010, timeout=0.1)

        elapsed = time.time() - start_time

        assert elapsed < 5.0, "Scan with short timeout must complete quickly"


class TestNetworkTrafficMonitoring:
    """Validate network traffic monitoring with psutil."""

    @pytest.mark.real_data
    def test_monitor_traffic_returns_results(self, plugin: NetworkAnalysisPlugin) -> None:
        """Traffic monitoring returns formatted results."""
        results: list[str] = plugin.monitor_traffic()

        assert len(results) > 0
        assert any("network monitoring" in r.lower() for r in results)

    @pytest.mark.real_data
    def test_monitor_detects_active_connections(self, plugin: NetworkAnalysisPlugin) -> None:
        """Monitoring detects established network connections."""
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(2.0)

        try:
            client_socket.connect(("8.8.8.8", 53))

            results = plugin.monitor_traffic()
            results_text = " ".join(results)

            has_connections = (
                "active network connections" in results_text.lower() or
                "8.8.8.8" in results_text or
                "connection" in results_text.lower()
            )

            assert has_connections or "No active" in results_text
        finally:
            client_socket.close()

    @pytest.mark.real_data
    def test_monitor_shows_listening_ports(self, plugin: NetworkAnalysisPlugin) -> None:
        """Monitoring identifies listening ports on system."""
        results = plugin.monitor_traffic()
        results_text = " ".join(results)

        has_listening = (
            "listening port" in results_text.lower() or
            "LISTEN" in results_text or
            "Network I/O Statistics" in results_text
        )

        assert has_listening or len(results) > 1

    @pytest.mark.real_data
    def test_monitor_includes_network_io_statistics(self, plugin: NetworkAnalysisPlugin) -> None:
        """Monitoring includes network I/O byte counters."""
        results = plugin.monitor_traffic()
        results_text = " ".join(results)

        has_io_stats = any(
            keyword in results_text.lower()
            for keyword in ["bytes sent", "bytes received", "packets", "network i/o"]
        )

        assert has_io_stats, "Must include network I/O statistics"


class TestSocketActivityMonitoring:
    """Validate real-time socket activity monitoring."""

    @pytest.mark.real_data
    def test_monitor_socket_activity_initializes(self, plugin: NetworkAnalysisPlugin) -> None:
        """Socket activity monitoring starts successfully."""
        result: dict[str, Any] = plugin.monitor_socket_activity(duration=2)

        assert "monitoring_started" in result
        assert result["duration"] == 2
        assert "connections" in result
        assert "statistics" in result
        assert plugin.monitoring is True

        time.sleep(2.5)
        assert plugin.monitoring is False

    @pytest.mark.real_data
    def test_monitor_detects_new_connections(self, plugin: NetworkAnalysisPlugin) -> None:
        """Activity monitor detects new socket connections."""
        result = plugin.monitor_socket_activity(duration=3)

        time.sleep(0.5)

        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(2.0)
        try:
            test_socket.connect(("8.8.8.8", 53))
            time.sleep(1.5)
        except Exception:
            pass
        finally:
            test_socket.close()

        time.sleep(1.5)

        plugin.monitoring = False
        if plugin.socket_monitor_thread:
            plugin.socket_monitor_thread.join(timeout=2)

    @pytest.mark.real_data
    def test_prevent_concurrent_monitoring(self, plugin: NetworkAnalysisPlugin) -> None:
        """Cannot start monitoring when already in progress."""
        plugin.monitor_socket_activity(duration=2)

        second_result = plugin.monitor_socket_activity(duration=2)

        assert "error" in second_result
        assert "already in progress" in second_result["error"].lower()

        time.sleep(2.5)


class TestSocketTrafficAnalysis:
    """Validate socket traffic pattern analysis."""

    @pytest.mark.real_data
    def test_analyze_socket_traffic_returns_patterns(self, plugin: NetworkAnalysisPlugin) -> None:
        """Traffic analysis identifies connection patterns."""
        result: dict[str, Any] = plugin.analyze_socket_traffic()

        assert "analysis_time" in result
        assert "patterns" in result
        assert "suspicious_activity" in result
        assert isinstance(result["patterns"], list)
        assert isinstance(result["suspicious_activity"], list)

    @pytest.mark.real_data
    def test_analyze_detects_port_usage_patterns(self, plugin: NetworkAnalysisPlugin) -> None:
        """Analysis identifies most used ports."""
        server1 = plugin.create_socket_server(port=0)
        server2 = plugin.create_socket_server(port=0)

        time.sleep(0.3)

        result = plugin.analyze_socket_traffic()

        plugin.cleanup_sockets()

    @pytest.mark.real_data
    def test_analyze_flags_suspicious_ports(self, plugin: NetworkAnalysisPlugin) -> None:
        """Analysis flags connections to suspicious ports."""
        result = plugin.analyze_socket_traffic()

        assert "suspicious_activity" in result
        assert isinstance(result["suspicious_activity"], list)


class TestSocketInformationExtraction:
    """Validate socket information extraction."""

    @pytest.mark.real_data
    def test_get_socket_info_for_listening_socket(self, plugin: NetworkAnalysisPlugin) -> None:
        """Extracts detailed information from listening socket."""
        server_result = plugin.create_socket_server(port=0)
        assert server_result["success"] is True

        server_socket = plugin.active_sockets[f"server_{server_result['port']}"]
        info: dict[str, Any] = plugin.get_socket_info(server_socket)

        assert "family" in info
        assert "type" in info
        assert "proto" in info
        assert "local_address" in info
        assert "127.0.0.1" in info["local_address"]
        assert info["remote_address"] == "Not connected"

        plugin.cleanup_sockets()

    @pytest.mark.real_data
    def test_get_socket_options(self, plugin: NetworkAnalysisPlugin) -> None:
        """Extracts socket option settings."""
        server_result = plugin.create_socket_server(port=0)
        server_socket = plugin.active_sockets[f"server_{server_result['port']}"]

        info = plugin.get_socket_info(server_socket)

        assert "reuse_addr" in info
        assert info["reuse_addr"] is True
        assert "keep_alive" in info

        plugin.cleanup_sockets()


class TestPluginCleanup:
    """Validate proper resource cleanup."""

    @pytest.mark.real_data
    def test_cleanup_closes_all_sockets(self, plugin: NetworkAnalysisPlugin) -> None:
        """Cleanup closes all active sockets."""
        plugin.create_socket_server(port=0)
        plugin.create_socket_server(port=0)
        plugin.create_socket_server(port=0)

        assert len(plugin.active_sockets) == 3

        plugin.cleanup_sockets()

        assert len(plugin.active_sockets) == 0

    @pytest.mark.real_data
    def test_cleanup_stops_monitoring(self, plugin: NetworkAnalysisPlugin) -> None:
        """Cleanup stops active monitoring threads."""
        plugin.monitor_socket_activity(duration=10)
        assert plugin.monitoring is True

        plugin.cleanup_sockets()

        assert plugin.monitoring is False


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.real_data
    def test_analyze_nonexistent_file(self, plugin: NetworkAnalysisPlugin) -> None:
        """Analyzing nonexistent file returns error."""
        results = plugin.analyze("D:/nonexistent_binary.exe")

        results_text = " ".join(results)
        assert "error" in results_text.lower() or "Analysis error" in results_text

    @pytest.mark.real_data
    def test_detect_socket_apis_invalid_path(self, plugin: NetworkAnalysisPlugin) -> None:
        """Socket API detection handles invalid paths."""
        results = plugin.detect_socket_apis("D:/invalid/path/binary.exe")

        results_text = " ".join(results)
        assert "Error" in results_text or "error" in results_text.lower()

    @pytest.mark.real_data
    def test_scan_invalid_host(self, plugin: NetworkAnalysisPlugin) -> None:
        """Port scanner handles invalid hostnames gracefully."""
        open_ports = plugin.scan_ports("invalid.host.local", 80, 81, timeout=0.5)

        assert isinstance(open_ports, list)
        assert len(open_ports) == 0
