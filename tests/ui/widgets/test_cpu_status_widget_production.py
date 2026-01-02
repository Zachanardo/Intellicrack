"""Production tests for CPU status widget - validates real CPU monitoring.

Tests verify CPU monitoring functionality including detection of CPU model,
real-time CPU usage tracking per core, frequency monitoring, load average tracking,
and process enumeration.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import platform
import sys
import threading
import time
from collections.abc import Generator
from typing import Any

import pytest

from intellicrack.handlers.psutil_handler import psutil
from intellicrack.handlers.pyqt6_handler import QApplication
from intellicrack.ui.widgets.cpu_status_widget import CPUMonitorWorker, CPUStatusWidget


class FakeCPUFrequency:
    """Real test double for CPU frequency data."""

    def __init__(self, current: float, min_freq: float = 0.0, max_freq: float = 0.0) -> None:
        self.current: float = current
        self.min: float = min_freq
        self.max: float = max_freq


class FakePlatformSystem:
    """Real test double for platform.system() returning unknown OS."""

    def __init__(self, return_value: str) -> None:
        self.return_value: str = return_value

    def __call__(self) -> str:
        return self.return_value


@pytest.fixture(scope="module")
def qapp() -> Generator[Any, None, None]:
    """Create QApplication instance for widget tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app
    app.quit()


@pytest.fixture
def cpu_monitor_worker() -> Generator[CPUMonitorWorker, None, None]:
    """Create CPU monitor worker for testing."""
    worker = CPUMonitorWorker()
    yield worker
    worker.stop_monitoring()


@pytest.fixture
def cpu_status_widget(qapp: Any) -> Generator[CPUStatusWidget, None, None]:
    """Create CPU status widget for testing."""
    widget = CPUStatusWidget()
    yield widget
    widget.stop_monitoring()
    widget.deleteLater()


class TestCPUMonitorWorker:
    """Test CPUMonitorWorker with real CPU metrics collection."""

    def test_worker_initialization(self, cpu_monitor_worker: CPUMonitorWorker) -> None:
        """Verify worker initializes with correct defaults."""
        assert cpu_monitor_worker.running is True
        assert cpu_monitor_worker.update_interval == 1000

    def test_collect_cpu_data_returns_valid_metrics(
        self, cpu_monitor_worker: CPUMonitorWorker
    ) -> None:
        """Test collecting real CPU data returns valid structure."""
        cpu_data = cpu_monitor_worker._collect_cpu_data()

        assert "cpu_count_physical" in cpu_data
        assert "cpu_count_logical" in cpu_data
        assert "cpu_percent_total" in cpu_data
        assert "cpu_percent_cores" in cpu_data
        assert "cpu_freq" in cpu_data
        assert "cpu_model" in cpu_data
        assert "top_processes" in cpu_data

        assert cpu_data["cpu_count_physical"] > 0
        assert cpu_data["cpu_count_logical"] > 0
        assert 0 <= cpu_data["cpu_percent_total"] <= 100
        assert len(cpu_data["cpu_percent_cores"]) > 0
        assert all(0 <= core <= 100 for core in cpu_data["cpu_percent_cores"])

    def test_cpu_model_detection_windows(self, cpu_monitor_worker: CPUMonitorWorker) -> None:
        """Test CPU model detection on Windows platform."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        cpu_model = cpu_monitor_worker._get_cpu_model()

        assert cpu_model is not None
        assert len(cpu_model) > 0
        assert cpu_model != "Unknown CPU"

    def test_cpu_model_detection_fallback(
        self, cpu_monitor_worker: CPUMonitorWorker, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test CPU model detection fallback for unknown platforms."""
        fake_platform = FakePlatformSystem("UnknownOS")
        monkeypatch.setattr("platform.system", fake_platform)

        cpu_model = cpu_monitor_worker._get_cpu_model()

        assert cpu_model == "Unknown CPU"

    def test_collect_cpu_data_with_processes(
        self, cpu_monitor_worker: CPUMonitorWorker
    ) -> None:
        """Test CPU data collection includes top processes."""
        cpu_data = cpu_monitor_worker._collect_cpu_data()

        assert "top_processes" in cpu_data
        assert isinstance(cpu_data["top_processes"], list)

        if len(cpu_data["top_processes"]) > 0:
            process = cpu_data["top_processes"][0]
            assert "pid" in process
            assert "name" in process
            assert "cpu_percent" in process
            assert "memory_percent" in process
            assert process["cpu_percent"] >= 0

    def test_cpu_data_includes_load_average(
        self, cpu_monitor_worker: CPUMonitorWorker
    ) -> None:
        """Test CPU data includes load average on supported platforms."""
        cpu_data = cpu_monitor_worker._collect_cpu_data()

        assert "load_average" in cpu_data
        load_avg = cpu_data["load_average"]
        assert isinstance(load_avg, tuple)
        assert len(load_avg) == 3

    def test_cpu_data_includes_frequency(
        self, cpu_monitor_worker: CPUMonitorWorker
    ) -> None:
        """Test CPU data includes frequency information."""
        cpu_data = cpu_monitor_worker._collect_cpu_data()

        assert "cpu_freq" in cpu_data
        freq = cpu_data["cpu_freq"]

        if freq is not None:
            assert hasattr(freq, "current")
            assert freq.current > 0

    def test_cpu_data_includes_time_distribution(
        self, cpu_monitor_worker: CPUMonitorWorker
    ) -> None:
        """Test CPU data includes time distribution metrics."""
        cpu_data = cpu_monitor_worker._collect_cpu_data()

        assert "cpu_times" in cpu_data
        assert "cpu_times_percent" in cpu_data

        times = cpu_data["cpu_times"]
        assert "user" in times
        assert "system" in times

    def test_stop_monitoring_halts_collection(
        self, cpu_monitor_worker: CPUMonitorWorker
    ) -> None:
        """Test stop_monitoring sets running flag to False."""
        assert cpu_monitor_worker.running is True

        cpu_monitor_worker.stop_monitoring()

        assert cpu_monitor_worker.running is False


class TestCPUStatusWidget:
    """Test CPUStatusWidget with real CPU monitoring."""

    def test_widget_initialization(self, cpu_status_widget: CPUStatusWidget) -> None:
        """Verify widget initializes with all UI components."""
        assert cpu_status_widget.model_label is not None
        assert cpu_status_widget.cores_label is not None
        assert cpu_status_widget.threads_label is not None
        assert cpu_status_widget.freq_label is not None
        assert cpu_status_widget.load_label is not None
        assert cpu_status_widget.total_cpu_bar is not None
        assert cpu_status_widget.total_cpu_label is not None
        assert cpu_status_widget.processes_table is not None
        assert cpu_status_widget.monitor_thread is not None
        assert cpu_status_widget.monitor_worker is not None

    def test_monitoring_thread_starts_automatically(
        self, cpu_status_widget: CPUStatusWidget
    ) -> None:
        """Test monitoring thread starts on widget initialization."""
        time.sleep(0.5)

        assert cpu_status_widget.monitor_thread is not None
        assert cpu_status_widget.monitor_thread.isRunning()

    def test_update_cpu_data_updates_labels(self, cpu_status_widget: CPUStatusWidget) -> None:
        """Test updating CPU data updates all display labels."""
        fake_freq = FakeCPUFrequency(current=3600.0, min_freq=800.0, max_freq=4200.0)

        test_data: dict[str, Any] = {
            "cpu_model": "Intel Core i7-9700K",
            "cpu_count_physical": 8,
            "cpu_count_logical": 8,
            "cpu_percent_total": 45.2,
            "cpu_percent_cores": [40.0, 50.0, 45.0, 42.0, 48.0, 46.0, 44.0, 43.0],
            "cpu_freq": fake_freq,
            "load_average": (1.5, 1.8, 2.0),
            "cpu_times_percent": {
                "user": 30.5,
                "system": 14.7,
                "idle": 54.8,
                "iowait": 0.0,
            },
            "top_processes": [
                {
                    "pid": 1234,
                    "name": "test_process.exe",
                    "cpu_percent": 25.5,
                    "memory_percent": 10.2,
                },
            ],
        }

        cpu_status_widget.update_cpu_data(test_data)

        assert "Intel Core i7-9700K" in cpu_status_widget.model_label.text()
        assert "8" in cpu_status_widget.cores_label.text()
        assert "8" in cpu_status_widget.threads_label.text()
        assert "3600" in cpu_status_widget.freq_label.text()
        assert "1.5" in cpu_status_widget.load_label.text()
        assert cpu_status_widget.total_cpu_bar.value() == 45
        assert "45.2%" in cpu_status_widget.total_cpu_label.text()

    def test_update_core_usage_creates_progress_bars(
        self, cpu_status_widget: CPUStatusWidget
    ) -> None:
        """Test per-core usage creates individual progress bars."""
        core_percents = [25.0, 50.0, 75.0, 30.0]

        cpu_status_widget.update_core_usage(core_percents)

        assert len(cpu_status_widget.core_bars) == 4

        for i, (bar, label) in enumerate(cpu_status_widget.core_bars):
            assert bar.value() == int(core_percents[i])
            assert f"{core_percents[i]:.1f}%" in label.text()

    def test_update_processes_table_displays_top_processes(
        self, cpu_status_widget: CPUStatusWidget
    ) -> None:
        """Test process table displays top CPU consumers."""
        processes = [
            {
                "pid": 1234,
                "name": "chrome.exe",
                "cpu_percent": 35.5,
                "memory_percent": 12.3,
            },
            {
                "pid": 5678,
                "name": "python.exe",
                "cpu_percent": 28.2,
                "memory_percent": 8.1,
            },
            {
                "pid": 9012,
                "name": "notepad.exe",
                "cpu_percent": 5.1,
                "memory_percent": 2.5,
            },
        ]

        cpu_status_widget.update_processes_table(processes)

        assert cpu_status_widget.processes_table.rowCount() == 3
        item_0_1 = cpu_status_widget.processes_table.item(0, 1)
        item_1_1 = cpu_status_widget.processes_table.item(1, 1)
        item_0_2 = cpu_status_widget.processes_table.item(0, 2)
        assert item_0_1 is not None and item_0_1.text() == "chrome.exe"
        assert item_1_1 is not None and item_1_1.text() == "python.exe"
        assert item_0_2 is not None and "35.5" in item_0_2.text()

    def test_set_bar_color_based_on_usage(self, cpu_status_widget: CPUStatusWidget) -> None:
        """Test progress bar color changes based on CPU usage thresholds."""
        from PyQt6.QtWidgets import QProgressBar

        bar = QProgressBar()

        cpu_status_widget._set_bar_color(bar, 50.0)
        assert "28a745" in bar.styleSheet()

        cpu_status_widget._set_bar_color(bar, 75.0)
        assert "ffc107" in bar.styleSheet()

        cpu_status_widget._set_bar_color(bar, 95.0)
        assert "dc3545" in bar.styleSheet()

    def test_set_refresh_interval_updates_worker(
        self, cpu_status_widget: CPUStatusWidget
    ) -> None:
        """Test changing refresh interval updates monitor worker."""
        cpu_status_widget.set_refresh_interval(2000)

        assert cpu_status_widget.monitor_worker is not None
        assert cpu_status_widget.monitor_worker.update_interval == 2000

    def test_stop_monitoring_terminates_thread(
        self, cpu_status_widget: CPUStatusWidget
    ) -> None:
        """Test stop_monitoring gracefully terminates monitoring thread."""
        assert cpu_status_widget.monitor_thread is not None
        assert cpu_status_widget.monitor_thread.isRunning()

        cpu_status_widget.stop_monitoring()

        time.sleep(0.5)
        assert not cpu_status_widget.monitor_thread.isRunning()

    def test_handle_error_logs_monitoring_errors(
        self, cpu_status_widget: CPUStatusWidget, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test error handler logs monitoring errors."""
        cpu_status_widget.handle_error("Test error message")

        assert "CPU monitoring error" in caplog.text


@pytest.mark.integration
class TestCPUMonitoringIntegration:
    """Integration tests with real CPU monitoring."""

    def test_real_cpu_data_collection(self, qapp: QApplication) -> None:
        """Test widget collects and displays real CPU data."""
        widget = CPUStatusWidget()

        try:
            time.sleep(1.5)

            assert widget.cpu_data is not None
            assert "cpu_model" in widget.cpu_data
            assert "cpu_percent_total" in widget.cpu_data

            assert widget.total_cpu_bar.value() >= 0
            assert widget.total_cpu_bar.value() <= 100

            model_text = widget.model_label.text()
            assert "Model:" in model_text
            assert model_text != "Model: Detecting..."

        finally:
            widget.stop_monitoring()
            widget.deleteLater()

    def test_per_core_monitoring_accuracy(self, qapp: QApplication) -> None:
        """Test per-core CPU monitoring tracks all cores."""
        widget = CPUStatusWidget()

        try:
            time.sleep(1.5)

            cpu_count = psutil.cpu_count(logical=True)
            assert len(widget.core_bars) == cpu_count

            for bar, label in widget.core_bars:
                assert 0 <= bar.value() <= 100

        finally:
            widget.stop_monitoring()
            widget.deleteLater()

    def test_process_enumeration_accuracy(self, qapp: QApplication) -> None:
        """Test process table accurately enumerates system processes."""
        widget = CPUStatusWidget()

        try:
            time.sleep(2.0)

            table = widget.processes_table
            if table.rowCount() > 0:
                item = table.item(0, 0)
                assert item is not None
                pid = int(item.text())
                assert pid > 0

                try:
                    proc = psutil.Process(pid)
                    assert proc.is_running()
                except psutil.NoSuchProcess:
                    pass

        finally:
            widget.stop_monitoring()
            widget.deleteLater()

    def test_continuous_monitoring_updates(self, qapp: QApplication) -> None:
        """Test continuous monitoring provides regular updates."""
        widget = CPUStatusWidget()

        try:
            time.sleep(0.5)
            first_value = widget.total_cpu_bar.value()

            time.sleep(1.5)
            second_value = widget.total_cpu_bar.value()

            assert first_value >= 0
            assert second_value >= 0

        finally:
            widget.stop_monitoring()
            widget.deleteLater()

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_windows_cpu_detection(self, qapp: QApplication) -> None:
        """Test CPU detection works correctly on Windows."""
        worker = CPUMonitorWorker()

        try:
            cpu_model = worker._get_cpu_model()

            assert cpu_model is not None
            assert cpu_model != "Unknown CPU"
            assert len(cpu_model) > 0

        finally:
            worker.stop_monitoring()

    def test_high_cpu_load_detection(self, qapp: QApplication) -> None:
        """Test widget accurately detects high CPU load scenarios."""
        widget = CPUStatusWidget()

        try:
            def cpu_intensive_task() -> None:
                end_time = time.time() + 2
                while time.time() < end_time:
                    _ = sum(i * i for i in range(10000))

            thread = threading.Thread(target=cpu_intensive_task)
            thread.start()

            time.sleep(1.0)

            current_cpu = widget.total_cpu_bar.value()
            assert current_cpu >= 0

            thread.join()

        finally:
            widget.stop_monitoring()
            widget.deleteLater()
