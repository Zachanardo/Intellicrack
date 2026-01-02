"""Production tests for terminal dashboard.

Tests real terminal UI metrics display and system monitoring.
"""

import time
from datetime import datetime

import pytest

from intellicrack.cli.terminal_dashboard import (
    AnalysisStats,
    SessionInfo,
    SystemMetrics,
    TerminalDashboard,
    create_dashboard,
)


@pytest.fixture
def dashboard() -> TerminalDashboard:
    """Create terminal dashboard."""
    return TerminalDashboard(update_interval=0.1)


def test_dashboard_initialization(dashboard: TerminalDashboard) -> None:
    """Test dashboard initializes correctly."""
    assert dashboard.update_interval == 0.1
    assert dashboard.running is False
    assert isinstance(dashboard.system_metrics, SystemMetrics)
    assert isinstance(dashboard.analysis_stats, AnalysisStats)
    assert isinstance(dashboard.session_info, SessionInfo)


def test_log_activity(dashboard: TerminalDashboard) -> None:
    """Test activity logging."""
    dashboard.log_activity("Test message", level="info")

    assert len(dashboard.activity_log) == 1
    activity = dashboard.activity_log[0]
    assert activity["message"] == "Test message"
    assert activity["level"] == "info"


def test_activity_log_limit(dashboard: TerminalDashboard) -> None:
    """Test activity log is limited."""
    for i in range(20):
        dashboard.log_activity(f"Message {i}")

    assert len(dashboard.activity_log) <= dashboard.max_activity_entries


def test_update_analysis_stats(dashboard: TerminalDashboard) -> None:
    """Test analysis statistics update."""
    dashboard.update_analysis_stats(
        total_binaries=10,
        analyses_completed=8,
        vulnerabilities_found=3,
    )

    assert dashboard.analysis_stats.total_binaries == 10
    assert dashboard.analysis_stats.analyses_completed == 8
    assert dashboard.analysis_stats.vulnerabilities_found == 3


def test_update_session_info(dashboard: TerminalDashboard) -> None:
    """Test session information update."""
    dashboard.update_session_info(
        commands_executed=5,
        current_binary="/path/to/binary.exe",
    )

    assert dashboard.session_info.commands_executed == 5
    assert dashboard.session_info.current_binary == "/path/to/binary.exe"


def test_increment_counter(dashboard: TerminalDashboard) -> None:
    """Test counter increment."""
    initial = dashboard.session_info.commands_executed

    dashboard.increment_counter("commands_executed")
    dashboard.increment_counter("commands_executed")

    assert dashboard.session_info.commands_executed == initial + 2


def test_system_metrics_update(dashboard: TerminalDashboard) -> None:
    """Test system metrics are updated."""
    dashboard._update_system_metrics()

    assert dashboard.system_metrics.cpu_percent >= 0
    assert dashboard.system_metrics.memory_percent >= 0
    assert dashboard.system_metrics.disk_usage >= 0


def test_system_metrics_history(dashboard: TerminalDashboard) -> None:
    """Test system metrics history tracking."""
    for _ in range(5):
        dashboard._update_system_metrics()
        time.sleep(0.05)

    assert len(dashboard.cpu_history) == 5
    assert len(dashboard.memory_history) == 5


def test_history_limit(dashboard: TerminalDashboard) -> None:
    """Test history is limited to max_history."""
    dashboard.max_history = 10

    for _ in range(20):
        dashboard._update_system_metrics()

    assert len(dashboard.cpu_history) <= 10
    assert len(dashboard.memory_history) <= 10


def test_create_status_summary(dashboard: TerminalDashboard) -> None:
    """Test status summary creation."""
    dashboard.update_analysis_stats(total_binaries=5, vulnerabilities_found=2)
    dashboard.update_session_info(commands_executed=10)

    summary = dashboard.create_status_summary()

    assert isinstance(summary, str)
    assert "5 binaries" in summary
    assert "2 vulnerabilities" in summary


def test_format_duration(dashboard: TerminalDashboard) -> None:
    """Test duration formatting."""
    assert "s" in dashboard._format_duration(30)
    assert "m" in dashboard._format_duration(120)
    assert "h" in dashboard._format_duration(7200)


def test_create_progress_bar(dashboard: TerminalDashboard) -> None:
    """Test progress bar creation."""
    bar = dashboard._create_progress_bar(50, 100, "Test", width=20)

    assert isinstance(bar, str)
    assert "Test" in bar
    assert "50" in bar


def test_get_trend(dashboard: TerminalDashboard) -> None:
    """Test trend calculation."""
    history_increasing = [10.0, 15.0, 20.0, 25.0, 30.0, 35.0]
    history_decreasing = [35.0, 30.0, 25.0, 20.0, 15.0, 10.0]
    history_stable = [20.0, 21.0, 20.0, 19.0, 20.0, 21.0]

    trend_up = dashboard._get_trend(history_increasing)
    trend_down = dashboard._get_trend(history_decreasing)
    trend_stable = dashboard._get_trend(history_stable)

    assert trend_up == "↗️"
    assert trend_down == "↘️"
    assert trend_stable == "→"


def test_calculate_commands_per_minute(dashboard: TerminalDashboard) -> None:
    """Test commands per minute calculation."""
    time.sleep(0.1)
    dashboard.session_info.commands_executed = 10

    cpm = dashboard._calculate_commands_per_minute()

    assert cpm > 0


def test_system_metrics_dataclass() -> None:
    """Test SystemMetrics dataclass."""
    metrics = SystemMetrics(
        cpu_percent=45.5,
        memory_percent=60.2,
        disk_usage=75.0,
        network_sent=1024,
        network_recv=2048,
        process_count=150,
        uptime=3600.0,
        load_average=[1.5, 1.2, 1.0],
    )

    assert metrics.cpu_percent == 45.5
    assert metrics.memory_percent == 60.2
    assert metrics.load_average == [1.5, 1.2, 1.0]


def test_analysis_stats_dataclass() -> None:
    """Test AnalysisStats dataclass."""
    stats = AnalysisStats(
        total_binaries=10,
        analyses_completed=8,
        vulnerabilities_found=5,
        active_projects=2,
        cache_hits=100,
        cache_misses=20,
        analysis_time_avg=15.5,
        last_analysis="binary.exe",
    )

    assert stats.total_binaries == 10
    assert stats.vulnerabilities_found == 5
    assert stats.cache_hits == 100


def test_session_info_dataclass() -> None:
    """Test SessionInfo dataclass."""
    start_time = datetime.now()
    session = SessionInfo(
        start_time=start_time,
        commands_executed=25,
        current_binary="test.exe",
        current_project="Project1",
        ai_queries=10,
        exports_created=3,
        errors_encountered=1,
    )

    assert session.start_time == start_time
    assert session.commands_executed == 25
    assert session.current_binary == "test.exe"


def test_create_dashboard_factory() -> None:
    """Test dashboard factory function."""
    dashboard = create_dashboard()

    assert isinstance(dashboard, TerminalDashboard)


def test_register_callback(dashboard: TerminalDashboard) -> None:
    """Test callback registration."""
    callback_called = False

    def test_callback() -> None:
        nonlocal callback_called
        callback_called = True

    dashboard.register_callback("test_event", test_callback)

    assert "test_event" in dashboard.callbacks
    assert test_callback in dashboard.callbacks["test_event"]
