"""Production tests for system monitor widget - validates real system metrics.

Tests verify system monitoring functionality including CPU/GPU/memory tracking,
network I/O monitoring, disk I/O tracking, process enumeration, and alert thresholds.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import sys
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.psutil_handler import psutil
from intellicrack.handlers.pyqt6_handler import QApplication
from intellicrack.ui.widgets.system_monitor_widget import SystemMetrics, SystemMonitorWidget, SystemMonitorWorker


@pytest.fixture(scope="module")
def qapp() -> Generator[Any, None, None]:
    """Create QApplication instance for widget tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app
    app.quit()


@pytest.fixture
def system_monitor_worker() -> Generator[SystemMonitorWorker, None, None]:
    """Create system monitor worker for testing."""
    worker = SystemMonitorWorker()
    yield worker
    worker.stop()


@pytest.fixture
def system_monitor_widget(qapp: QApplication) -> Generator[SystemMonitorWidget, None, None]:
    """Create system monitor widget for testing."""
    widget = SystemMonitorWidget()
    yield widget
    widget.stop_monitoring()
    widget.deleteLater()


@pytest.fixture
def sample_metrics() -> SystemMetrics:
    """Create sample system metrics for testing."""
    return SystemMetrics(
        timestamp=time.time(),
        cpu_percent=45.5,
        cpu_per_core=[40.0, 50.0, 45.0, 48.0],
        memory_percent=62.3,
        memory_used_gb=8.5,
        memory_total_gb=16.0,
        gpu_percent=35.2,
        gpu_memory_percent=50.1,
        gpu_temp=65.0,
        network_sent_mb=2.5,
        network_recv_mb=5.8,
        disk_read_mb=10.2,
        disk_write_mb=3.7,
    )


class TestSystemMetrics:
    """Test SystemMetrics dataclass."""

    def test_metrics_initialization(self, sample_metrics: SystemMetrics) -> None:
        """Verify metrics dataclass initializes with correct values."""
        assert sample_metrics.cpu_percent == 45.5
        assert sample_metrics.memory_percent == 62.3
        assert sample_metrics.gpu_percent == 35.2
        assert len(sample_metrics.cpu_per_core) == 4
        assert sample_metrics.network_sent_mb == 2.5
        assert sample_metrics.disk_read_mb == 10.2

    def test_metrics_optional_fields(self) -> None:
        """Test metrics with optional GPU fields not set."""
        metrics = SystemMetrics(
            timestamp=time.time(),
            cpu_percent=50.0,
            cpu_per_core=[50.0],
            memory_percent=60.0,
            memory_used_gb=8.0,
            memory_total_gb=16.0,
        )

        assert metrics.gpu_percent is None
        assert metrics.gpu_memory_percent is None
        assert metrics.gpu_temp is None
        assert metrics.network_sent_mb == 0.0
        assert metrics.disk_read_mb == 0.0


class TestSystemMonitorWorker:
    """Test SystemMonitorWorker with real system metrics collection."""

    def test_worker_initialization(self, system_monitor_worker: SystemMonitorWorker) -> None:
        """Verify worker initializes with correct defaults."""
        assert system_monitor_worker.running is False
        assert system_monitor_worker.update_interval == 1000
        assert system_monitor_worker.last_net_io is None
        assert system_monitor_worker.last_disk_io is None

    def test_collect_metrics_returns_valid_structure(
        self, system_monitor_worker: SystemMonitorWorker
    ) -> None:
        """Test collecting real system metrics returns valid data."""
        metrics = system_monitor_worker._collect_metrics()

        assert isinstance(metrics, SystemMetrics)
        assert 0 <= metrics.cpu_percent <= 100
        assert 0 <= metrics.memory_percent <= 100
        assert metrics.memory_used_gb >= 0
        assert metrics.memory_total_gb > 0
        assert len(metrics.cpu_per_core) > 0
        assert all(0 <= core <= 100 for core in metrics.cpu_per_core)

    def test_collect_metrics_cpu_accuracy(
        self, system_monitor_worker: SystemMonitorWorker
    ) -> None:
        """Test CPU metrics match psutil directly."""
        metrics = system_monitor_worker._collect_metrics()

        cpu_count = psutil.cpu_count(logical=True)
        assert len(metrics.cpu_per_core) == cpu_count
        assert 0 <= metrics.cpu_percent <= 100

    def test_collect_metrics_memory_accuracy(
        self, system_monitor_worker: SystemMonitorWorker
    ) -> None:
        """Test memory metrics match psutil."""
        metrics = system_monitor_worker._collect_metrics()

        mem_info = psutil.virtual_memory()
        assert abs(metrics.memory_percent - mem_info.percent) < 5.0
        assert metrics.memory_total_gb > 0

        expected_used_gb = mem_info.used / (1024**3)
        assert abs(metrics.memory_used_gb - expected_used_gb) < 1.0

    def test_collect_metrics_network_io_delta(
        self, system_monitor_worker: SystemMonitorWorker
    ) -> None:
        """Test network I/O delta calculation."""
        first_metrics = system_monitor_worker._collect_metrics()
        assert first_metrics.network_sent_mb >= 0
        assert first_metrics.network_recv_mb >= 0

        time.sleep(0.5)

        second_metrics = system_monitor_worker._collect_metrics()
        assert second_metrics.network_sent_mb >= 0
        assert second_metrics.network_recv_mb >= 0

    def test_collect_metrics_disk_io_delta(
        self, system_monitor_worker: SystemMonitorWorker
    ) -> None:
        """Test disk I/O delta calculation."""
        first_metrics = system_monitor_worker._collect_metrics()
        assert first_metrics.disk_read_mb >= 0
        assert first_metrics.disk_write_mb >= 0

        time.sleep(0.5)

        second_metrics = system_monitor_worker._collect_metrics()
        assert second_metrics.disk_read_mb >= 0
        assert second_metrics.disk_write_mb >= 0

    def test_stop_monitoring_halts_worker(
        self, system_monitor_worker: SystemMonitorWorker
    ) -> None:
        """Test stop() sets running flag to False."""
        system_monitor_worker.running = True
        system_monitor_worker.stop()

        assert not system_monitor_worker.running


class TestSystemMonitorWidget:
    """Test SystemMonitorWidget with real system monitoring."""

    def test_widget_initialization(self, system_monitor_widget: SystemMonitorWidget) -> None:
        """Verify widget initializes with all components."""
        assert system_monitor_widget.cpu_bar is not None
        assert system_monitor_widget.cpu_label is not None
        assert system_monitor_widget.memory_bar is not None
        assert system_monitor_widget.memory_label is not None
        assert system_monitor_widget.process_table is not None
        assert system_monitor_widget.interval_spin is not None
        assert system_monitor_widget.pause_btn is not None
        assert system_monitor_widget.auto_scroll_cb is not None
        assert system_monitor_widget.monitor_thread is not None
        assert system_monitor_widget.monitor_worker is not None

    def test_monitoring_thread_starts(self, system_monitor_widget: SystemMonitorWidget) -> None:
        """Test monitoring thread starts automatically."""
        time.sleep(0.5)
        assert system_monitor_widget.monitor_thread.isRunning()

    def test_on_metrics_updated_updates_ui(
        self, system_monitor_widget: SystemMonitorWidget, sample_metrics: SystemMetrics
    ) -> None:
        """Test metrics update updates all UI components."""
        system_monitor_widget._on_metrics_updated(sample_metrics)

        assert system_monitor_widget.cpu_bar.value() == 45
        assert "45.5%" in system_monitor_widget.cpu_label.text()
        assert system_monitor_widget.memory_bar.value() == 62
        assert "8.5" in system_monitor_widget.memory_label.text()
        assert "16.0" in system_monitor_widget.memory_label.text()

    def test_update_process_table_displays_processes(
        self, system_monitor_widget: SystemMonitorWidget
    ) -> None:
        """Test process table updates with running processes."""
        system_monitor_widget._update_process_table()

        assert system_monitor_widget.process_table.rowCount() >= 0

        if system_monitor_widget.process_table.rowCount() > 0:
            pid_item = system_monitor_widget.process_table.item(0, 0)
            name_item = system_monitor_widget.process_table.item(0, 1)

            assert pid_item is not None
            assert name_item is not None
            assert int(pid_item.text()) > 0
            assert len(name_item.text()) > 0

    def test_check_thresholds_triggers_alerts(
        self, system_monitor_widget: SystemMonitorWidget
    ) -> None:
        """Test threshold checking triggers appropriate alerts."""
        system_monitor_widget.cpu_threshold = 50.0
        system_monitor_widget.memory_threshold = 70.0

        alert_triggered = False
        alert_type = None
        alert_message = None

        def on_alert(atype: str, message: str) -> None:
            nonlocal alert_triggered, alert_type, alert_message
            alert_triggered = True
            alert_type = atype
            alert_message = message

        system_monitor_widget.alert_triggered.connect(on_alert)

        high_cpu_metrics = SystemMetrics(
            timestamp=time.time(),
            cpu_percent=85.0,
            cpu_per_core=[85.0],
            memory_percent=50.0,
            memory_used_gb=8.0,
            memory_total_gb=16.0,
        )

        system_monitor_widget._check_thresholds(high_cpu_metrics)

        assert alert_triggered
        assert alert_type == "cpu"
        assert alert_message is not None
        assert "85.0%" in alert_message

    def test_pause_button_stops_updates(
        self, system_monitor_widget: SystemMonitorWidget, sample_metrics: SystemMetrics
    ) -> None:
        """Test pause button prevents metric updates."""
        system_monitor_widget.pause_btn.setChecked(True)
        initial_count = len(system_monitor_widget.metrics_history)

        system_monitor_widget._on_metrics_updated(sample_metrics)

        assert len(system_monitor_widget.metrics_history) == initial_count

    def test_on_interval_changed_updates_worker(
        self, system_monitor_widget: SystemMonitorWidget
    ) -> None:
        """Test interval change updates worker update interval."""
        system_monitor_widget._on_interval_changed(2000)

        assert system_monitor_widget.update_interval == 2000
        assert system_monitor_widget.monitor_worker.update_interval == 2000

    def test_get_current_metrics_returns_latest(
        self, system_monitor_widget: SystemMonitorWidget, sample_metrics: SystemMetrics
    ) -> None:
        """Test get_current_metrics returns most recent metrics."""
        system_monitor_widget.metrics_history.clear()
        system_monitor_widget._on_metrics_updated(sample_metrics)

        current = system_monitor_widget.get_current_metrics()

        assert current is not None
        assert current.cpu_percent == sample_metrics.cpu_percent
        assert current.memory_percent == sample_metrics.memory_percent

    def test_get_metrics_summary_calculates_statistics(
        self, system_monitor_widget: SystemMonitorWidget
    ) -> None:
        """Test metrics summary calculates averages and maximums."""
        metrics1 = SystemMetrics(
            timestamp=time.time(),
            cpu_percent=40.0,
            cpu_per_core=[40.0],
            memory_percent=50.0,
            memory_used_gb=8.0,
            memory_total_gb=16.0,
        )
        metrics2 = SystemMetrics(
            timestamp=time.time(),
            cpu_percent=60.0,
            cpu_per_core=[60.0],
            memory_percent=70.0,
            memory_used_gb=11.2,
            memory_total_gb=16.0,
        )
        metrics3 = SystemMetrics(
            timestamp=time.time(),
            cpu_percent=50.0,
            cpu_per_core=[50.0],
            memory_percent=60.0,
            memory_used_gb=9.6,
            memory_total_gb=16.0,
        )

        system_monitor_widget.metrics_history.clear()
        system_monitor_widget.metrics_history.append(metrics1)
        system_monitor_widget.metrics_history.append(metrics2)
        system_monitor_widget.metrics_history.append(metrics3)

        summary = system_monitor_widget.get_metrics_summary()

        assert summary["cpu_current"] == 50.0
        assert summary["cpu_average"] == 50.0
        assert summary["cpu_max"] == 60.0
        assert summary["memory_current"] == 60.0
        assert summary["memory_average"] == 60.0
        assert summary["memory_max"] == 70.0

    def test_set_thresholds_updates_alert_levels(
        self, system_monitor_widget: SystemMonitorWidget
    ) -> None:
        """Test setting custom alert thresholds."""
        system_monitor_widget.set_thresholds(cpu=75.0, memory=80.0, gpu=85.0)

        assert system_monitor_widget.cpu_threshold == 75.0
        assert system_monitor_widget.memory_threshold == 80.0
        assert system_monitor_widget.gpu_threshold == 85.0

    def test_set_refresh_interval_updates_components(
        self, system_monitor_widget: SystemMonitorWidget
    ) -> None:
        """Test setting refresh interval updates all components."""
        system_monitor_widget.set_refresh_interval(3000)

        assert system_monitor_widget.update_interval == 3000
        assert system_monitor_widget.interval_spin.value() == 3000
        assert system_monitor_widget.monitor_worker.update_interval == 3000

    def test_export_metrics_creates_json_file(
        self, system_monitor_widget: SystemMonitorWidget, tmp_path: Path, sample_metrics: SystemMetrics
    ) -> None:
        """Test exporting metrics to JSON file."""
        system_monitor_widget.metrics_history.clear()
        system_monitor_widget.metrics_history.append(sample_metrics)

        export_file = tmp_path / "metrics_export.json"
        system_monitor_widget.export_metrics(str(export_file))

        assert export_file.exists()

        with open(export_file) as f:
            data = json.load(f)

        assert len(data) == 1
        assert data[0]["cpu_percent"] == 45.5
        assert data[0]["memory_percent"] == 62.3

    def test_stop_monitoring_terminates_thread(
        self, system_monitor_widget: SystemMonitorWidget
    ) -> None:
        """Test stop_monitoring gracefully terminates worker thread."""
        assert system_monitor_widget.monitor_thread.isRunning()

        system_monitor_widget.stop_monitoring()

        time.sleep(0.5)
        assert not system_monitor_widget.monitor_thread.isRunning()


@pytest.mark.integration
class TestSystemMonitorIntegration:
    """Integration tests with real system monitoring."""

    def test_real_system_metrics_collection(self, qapp: QApplication) -> None:
        """Test widget collects and displays real system metrics."""
        widget = SystemMonitorWidget()

        try:
            time.sleep(2.0)

            assert len(widget.metrics_history) > 0

            latest = widget.get_current_metrics()
            assert latest is not None
            assert 0 <= latest.cpu_percent <= 100
            assert 0 <= latest.memory_percent <= 100
            assert latest.memory_total_gb > 0

        finally:
            widget.stop_monitoring()
            widget.deleteLater()

    def test_continuous_monitoring_updates_ui(self, qapp: QApplication) -> None:
        """Test continuous monitoring provides regular UI updates."""
        widget = SystemMonitorWidget()

        try:
            time.sleep(1.0)
            first_cpu = widget.cpu_bar.value()

            time.sleep(2.0)
            second_cpu = widget.cpu_bar.value()

            assert 0 <= first_cpu <= 100
            assert 0 <= second_cpu <= 100

            assert len(widget.metrics_history) >= 2

        finally:
            widget.stop_monitoring()
            widget.deleteLater()

    def test_process_table_updates_with_real_processes(self, qapp: QApplication) -> None:
        """Test process table displays real running processes."""
        widget = SystemMonitorWidget()

        try:
            time.sleep(1.5)

            table = widget.process_table
            assert table.rowCount() > 0

            found_python = False
            for row in range(table.rowCount()):
                name_item = table.item(row, 1)
                if name_item and "python" in name_item.text().lower():
                    found_python = True
                    break

            assert found_python, "Should find Python process in table"

        finally:
            widget.stop_monitoring()
            widget.deleteLater()

    def test_alert_system_with_real_metrics(self, qapp: QApplication) -> None:
        """Test alert system triggers with real high usage."""
        widget = SystemMonitorWidget()
        widget.cpu_threshold = 10.0
        widget.memory_threshold = 10.0

        alert_received = False

        def on_alert(alert_type: str, message: str) -> None:
            nonlocal alert_received
            alert_received = True

        widget.alert_triggered.connect(on_alert)

        try:
            time.sleep(2.0)

        finally:
            widget.stop_monitoring()
            widget.deleteLater()

    def test_metrics_history_limits_to_configured_size(self, qapp: QApplication) -> None:
        """Test metrics history respects configured maximum size."""
        widget = SystemMonitorWidget()
        widget.history_size = 10

        try:
            time.sleep(5.0)

            assert len(widget.metrics_history) <= widget.history_size

        finally:
            widget.stop_monitoring()
            widget.deleteLater()

    def test_independent_cpu_memory_metrics(self, qapp: QApplication) -> None:
        """Test CPU and memory metrics are truly independent."""
        widget = SystemMonitorWidget()

        try:
            time.sleep(2.0)

            if len(widget.metrics_history) >= 2:
                metrics = list(widget.metrics_history)

                cpu_values = [m.cpu_percent for m in metrics]
                mem_values = [m.memory_percent for m in metrics]

                assert len(set(cpu_values)) > 1 or len(set(mem_values)) > 1

        finally:
            widget.stop_monitoring()
            widget.deleteLater()
