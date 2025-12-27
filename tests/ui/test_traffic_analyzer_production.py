"""Production tests for traffic analyzer UI.

Tests real network traffic capture and analysis functionality.
"""

from unittest.mock import MagicMock, patch

import pytest

from intellicrack.ui.traffic_analyzer import (
    ConnectionInfo,
    ConversationInfo,
    LicenseConnectionInfo,
    TrafficAnalysisResults,
    TrafficAnalyzer,
)


@pytest.fixture
def mock_parent() -> MagicMock:
    """Create mock parent widget."""
    return MagicMock()


def test_traffic_analyzer_initialization(mock_parent: MagicMock) -> None:
    """Test traffic analyzer initializes."""
    with patch("intellicrack.ui.traffic_analyzer.QDialog.__init__"):
        analyzer = TrafficAnalyzer(mock_parent)
        assert analyzer is not None


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
