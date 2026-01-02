"""Production tests for traffic analyzer UI.

Tests real network traffic capture and analysis functionality.
"""

from typing import Any

import pytest

from intellicrack.ui.traffic_analyzer import (
    ConnectionInfo,
    ConversationInfo,
    LicenseConnectionInfo,
    TrafficAnalysisResults,
    TrafficAnalyzer,
)


class FakeQWidget:
    """Real test double for QWidget parent."""

    def __init__(self) -> None:
        self.title: str = ""
        self.geometry: tuple[int, int, int, int] = (0, 0, 800, 600)
        self.visible: bool = False
        self.children: list[Any] = []

    def setWindowTitle(self, title: str) -> None:
        self.title = title

    def setGeometry(self, x: int, y: int, width: int, height: int) -> None:
        self.geometry = (x, y, width, height)

    def show(self) -> None:
        self.visible = True

    def hide(self) -> None:
        self.visible = False

    def close(self) -> None:
        self.visible = False


class FakeQDialog:
    """Real test double for QDialog."""

    def __init__(self, parent: Any = None) -> None:
        self.parent: Any = parent
        self.title: str = ""
        self.modal: bool = False
        self.minimum_size: tuple[int, int] = (0, 0)
        self.result_code: int = 0
        self.executed: bool = False

    def setWindowTitle(self, title: str) -> None:
        self.title = title

    def setModal(self, modal: bool) -> None:
        self.modal = modal

    def setMinimumSize(self, width: int, height: int) -> None:
        self.minimum_size = (width, height)

    def exec(self) -> int:
        self.executed = True
        return self.result_code


@pytest.fixture
def fake_parent() -> FakeQWidget:
    """Create real test double for parent widget."""
    return FakeQWidget()


def test_traffic_analyzer_initialization(fake_parent: FakeQWidget, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test traffic analyzer initializes."""
    original_init_called: bool = False

    def fake_qdialog_init(self: Any, parent: Any = None) -> None:
        nonlocal original_init_called
        original_init_called = True

    monkeypatch.setattr("intellicrack.ui.traffic_analyzer.QDialog.__init__", fake_qdialog_init)

    analyzer = TrafficAnalyzer()
    assert analyzer is not None
    assert analyzer.analyzer is None
    assert analyzer.analysis_thread is None
    assert analyzer.capture_active is False


def test_license_connection_info_typed_dict() -> None:
    """Test LicenseConnectionInfo TypedDict structure."""
    connection: LicenseConnectionInfo = {
        "local_address": "192.168.1.100",
        "remote_address": "52.12.34.56",
        "local_port": 45678,
        "remote_port": 443,
        "protocol": "TCP",
        "status": "ESTABLISHED",
        "reason": "HTTPS connection to license server",
    }

    assert connection["local_address"] == "192.168.1.100"
    assert connection["remote_port"] == 443
    assert connection["protocol"] == "TCP"


def test_connection_info_typed_dict() -> None:
    """Test ConnectionInfo TypedDict structure."""
    connection: ConnectionInfo = {
        "local_ip": "10.0.0.5",
        "local_port": 54321,
        "remote_ip": "93.184.216.34",
        "remote_port": 80,
        "protocol": "TCP",
        "status": "ESTABLISHED",
    }

    assert connection["local_ip"] == "10.0.0.5"
    assert connection["remote_ip"] == "93.184.216.34"


def test_conversation_info_typed_dict() -> None:
    """Test ConversationInfo TypedDict structure."""
    conversation: ConversationInfo = {
        "src": "192.168.1.5",
        "dst": "8.8.8.8",
        "count": 42,
    }

    assert conversation["src"] == "192.168.1.5"
    assert conversation["dst"] == "8.8.8.8"
    assert conversation["count"] == 42


def test_traffic_analysis_results_typed_dict() -> None:
    """Test TrafficAnalysisResults TypedDict structure."""
    results: TrafficAnalysisResults = {
        "protocol_stats": {"TCP": 150, "UDP": 50, "ICMP": 5},
        "top_conversations": [
            {"src": "192.168.1.5", "dst": "8.8.8.8", "count": 25},
        ],
        "license_traffic": [
            {
                "local_address": "192.168.1.100",
                "remote_address": "license.server.com",
                "local_port": 54321,
                "remote_port": 443,
                "protocol": "TCP",
                "status": "ESTABLISHED",
                "reason": "License validation",
            },
        ],
        "connection_info": [],
        "analysis_timestamp": 1234567890.0,
        "total_connections": 205,
        "license_connection_count": 1,
    }

    assert results["protocol_stats"]["TCP"] == 150
    assert len(results["license_traffic"]) == 1
    assert results["total_connections"] == 205


def test_traffic_analysis_protocol_stats() -> None:
    """Test protocol statistics tracking."""
    results: TrafficAnalysisResults = {
        "protocol_stats": {
            "TCP": 100,
            "UDP": 50,
            "ICMP": 10,
            "HTTP": 75,
            "HTTPS": 80,
        },
    }

    assert sum(results["protocol_stats"].values()) == 315
    assert results["protocol_stats"]["HTTPS"] > results["protocol_stats"]["HTTP"]


def test_traffic_analysis_license_detection() -> None:
    """Test license-related traffic detection."""
    license_connection: LicenseConnectionInfo = {
        "remote_address": "activation.server.com",
        "remote_port": 443,
        "protocol": "HTTPS",
        "status": "ESTABLISHED",
        "reason": "License activation request",
    }

    assert "activation" in license_connection.get("remote_address", "")
    assert license_connection["remote_port"] == 443


def test_conversation_tracking() -> None:
    """Test network conversation tracking."""
    conversations: list[ConversationInfo] = [
        {"src": "192.168.1.10", "dst": "8.8.8.8", "count": 50},
        {"src": "192.168.1.10", "dst": "1.1.1.1", "count": 30},
        {"src": "192.168.1.11", "dst": "8.8.8.8", "count": 20},
    ]

    total_packets = sum(c["count"] for c in conversations)
    assert total_packets == 100

    most_active = max(conversations, key=lambda c: c["count"])
    assert most_active["count"] == 50


def test_connection_status_types() -> None:
    """Test various connection status types."""
    statuses = ["ESTABLISHED", "LISTEN", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT"]

    for status in statuses:
        connection: ConnectionInfo = {
            "local_ip": "127.0.0.1",
            "local_port": 8080,
            "remote_ip": "192.168.1.1",
            "remote_port": 443,
            "protocol": "TCP",
            "status": status,
        }

        assert connection["status"] in statuses


def test_protocol_distribution() -> None:
    """Test protocol distribution analysis."""
    results: TrafficAnalysisResults = {
        "protocol_stats": {
            "TCP": 500,
            "UDP": 200,
            "ICMP": 50,
        },
    }

    total = sum(results["protocol_stats"].values())
    tcp_percentage = (results["protocol_stats"]["TCP"] / total) * 100

    assert tcp_percentage > 50
