"""Production tests for dashboard integration.

Tests real tool integration with dashboard for monitoring and visualization.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from intellicrack.dashboard.dashboard_integration import (
    DashboardIntegration,
    ToolIntegration,
    create_dashboard_integration,
)


@pytest.fixture
def dashboard_integration() -> DashboardIntegration:
    """Create dashboard integration instance."""
    config = {
        "enable_websocket": False,
        "enable_http": False,
        "websocket_port": 8765,
        "http_port": 5000,
    }
    integration = DashboardIntegration(config)
    yield integration
    integration.shutdown()


def test_dashboard_integration_initialization(dashboard_integration: DashboardIntegration) -> None:
    """Test dashboard integration initializes."""
    assert dashboard_integration.dashboard_manager is not None
    assert len(dashboard_integration.tool_integrations) == 0
    assert len(dashboard_integration.active_analyses) == 0


def test_integrate_ghidra(dashboard_integration: DashboardIntegration) -> None:
    """Test Ghidra analyzer integration."""
    mock_ghidra = MagicMock()
    mock_ghidra.register_callback = MagicMock()

    dashboard_integration.integrate_ghidra(mock_ghidra)

    assert "ghidra" in dashboard_integration.tool_integrations
    integration = dashboard_integration.tool_integrations["ghidra"]
    assert integration.tool_name == "ghidra"
    assert integration.analyzer_instance is mock_ghidra


def test_integrate_frida(dashboard_integration: DashboardIntegration) -> None:
    """Test Frida analyzer integration."""
    mock_frida = MagicMock()

    dashboard_integration.integrate_frida(mock_frida)

    assert "frida" in dashboard_integration.tool_integrations


def test_integrate_radare2(dashboard_integration: DashboardIntegration) -> None:
    """Test Radare2 analyzer integration."""
    mock_r2 = MagicMock()

    dashboard_integration.integrate_radare2(mock_r2)

    assert "radare2" in dashboard_integration.tool_integrations


def test_start_analysis_monitoring(dashboard_integration: DashboardIntegration) -> None:
    """Test analysis monitoring startup."""
    dashboard_integration.start_analysis_monitoring(
        analysis_id="test_001",
        tool="ghidra",
        target="/path/to/binary.exe",
        options={"depth": "full"},
    )

    assert "test_001" in dashboard_integration.active_analyses
    analysis = dashboard_integration.active_analyses["test_001"]
    assert analysis["tool"] == "ghidra"
    assert analysis["target"] == "/path/to/binary.exe"


def test_complete_analysis_monitoring(dashboard_integration: DashboardIntegration) -> None:
    """Test analysis monitoring completion."""
    dashboard_integration.start_analysis_monitoring(
        analysis_id="test_002",
        tool="frida",
        target="/path/to/target",
    )

    results = {
        "functions": ["main", "setup"],
        "vulnerabilities": [{"type": "buffer_overflow"}],
    }

    dashboard_integration.complete_analysis_monitoring("test_002", results)

    assert "test_002" in dashboard_integration.active_analyses
    analysis = dashboard_integration.active_analyses["test_002"]
    assert "end_time" in analysis
    assert "duration" in analysis


def test_report_finding_vulnerability(dashboard_integration: DashboardIntegration) -> None:
    """Test vulnerability finding reporting."""
    finding_data = {
        "type": "buffer_overflow",
        "severity": "high",
        "location": "0x401000",
    }

    dashboard_integration.report_finding("vulnerability", "ghidra", finding_data)


def test_report_finding_protection(dashboard_integration: DashboardIntegration) -> None:
    """Test protection finding reporting."""
    finding_data = {
        "type": "ASLR",
        "enabled": True,
    }

    dashboard_integration.report_finding("protection", "radare2", finding_data)


def test_export_analysis_report(dashboard_integration: DashboardIntegration) -> None:
    """Test comprehensive report export."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        report_path = f.name

    try:
        dashboard_integration.start_analysis_monitoring(
            "test_003",
            "ghidra",
            "/binary",
        )

        dashboard_integration.export_analysis_report(report_path)

        assert Path(report_path).exists()

        with open(report_path) as f:
            data = json.load(f)

        assert "timestamp" in data
        assert "analyses" in data
        assert "findings" in data
    finally:
        Path(report_path).unlink(missing_ok=True)


def test_get_ghidra_metrics(dashboard_integration: DashboardIntegration) -> None:
    """Test Ghidra metrics retrieval."""
    mock_ghidra = MagicMock()
    mock_ghidra.get_analysis_stats.return_value = {"functions": 100}

    dashboard_integration.integrate_ghidra(mock_ghidra)

    metrics = dashboard_integration._get_ghidra_metrics()

    assert "functions" in metrics
    assert metrics["functions"] == 100


def test_get_frida_metrics(dashboard_integration: DashboardIntegration) -> None:
    """Test Frida metrics retrieval."""
    mock_frida = MagicMock()
    mock_frida.get_hook_stats.return_value = {"total": 15}
    mock_frida.get_intercept_count.return_value = 50

    dashboard_integration.integrate_frida(mock_frida)

    metrics = dashboard_integration._get_frida_metrics()

    assert "hooks_installed" in metrics
    assert metrics["hooks_installed"] == 15
    assert metrics["intercepts"] == 50


def test_tool_status_reporting(dashboard_integration: DashboardIntegration) -> None:
    """Test tool status reporting."""
    mock_ghidra = MagicMock()
    dashboard_integration.integrate_ghidra(mock_ghidra)

    status = dashboard_integration._get_ghidra_status()

    assert "status" in status
    assert status["status"] == "Active"


def test_create_dashboard_integration_factory() -> None:
    """Test dashboard integration factory function."""
    integration = create_dashboard_integration({"enable_websocket": False})

    assert isinstance(integration, DashboardIntegration)
    integration.shutdown()


def test_tool_integration_dataclass() -> None:
    """Test ToolIntegration dataclass."""
    mock_analyzer = MagicMock()

    integration = ToolIntegration(
        tool_name="test_tool",
        analyzer_instance=mock_analyzer,
        enabled=True,
    )

    assert integration.tool_name == "test_tool"
    assert integration.analyzer_instance is mock_analyzer
    assert integration.enabled is True


def test_get_dashboard_url(dashboard_integration: DashboardIntegration) -> None:
    """Test dashboard URL retrieval."""
    url = dashboard_integration.get_dashboard_url()

    assert isinstance(url, str)


def test_get_websocket_url(dashboard_integration: DashboardIntegration) -> None:
    """Test WebSocket URL retrieval."""
    url = dashboard_integration.get_websocket_url()

    assert isinstance(url, str)
