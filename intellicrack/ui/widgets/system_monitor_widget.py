"""System Monitor Widget.

Provides real-time system monitoring including CPU, GPU, Memory usage,
network activity, and process information for the Dashboard tab.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QBrush, QCloseEvent, QColor
from PyQt6.QtWidgets import (
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.handlers.psutil_handler import psutil
from intellicrack.utils.logger import logger


try:
    import pyqtgraph as pg

    PYQTGRAPH_AVAILABLE = True
except ImportError:
    PYQTGRAPH_AVAILABLE = False

try:
    import GPUtil

    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False


@dataclass
class SystemMetrics:
    """Container for system metrics."""

    timestamp: float
    cpu_percent: float
    cpu_per_core: list[float]
    memory_percent: float
    memory_used_gb: float
    memory_total_gb: float
    gpu_percent: float | None = None
    gpu_memory_percent: float | None = None
    gpu_temp: float | None = None
    network_sent_mb: float = 0.0
    network_recv_mb: float = 0.0
    disk_read_mb: float = 0.0
    disk_write_mb: float = 0.0


class SystemMonitorWorker(QObject):
    """Worker thread for collecting system metrics."""

    metrics_updated = pyqtSignal(SystemMetrics)
    error_occurred = pyqtSignal(str)

    def __init__(self) -> None:
        """Initialize system monitor worker with performance tracking capabilities."""
        super().__init__()
        self.running = False
        self.update_interval = 1000  # ms
        self.last_net_io: Any = None
        self.last_disk_io: Any = None

    def run(self) -> None:
        """Run the monitoring loop."""
        self.running = True

        while self.running:
            try:
                metrics = self._collect_metrics()
                self.metrics_updated.emit(metrics)
            except Exception as e:
                self.error_occurred.emit(str(e))

            time.sleep(self.update_interval / 1000.0)

    def stop(self) -> None:
        """Stop the monitoring loop."""
        self.running = False

    def _collect_metrics(self) -> SystemMetrics:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)

        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used_gb = memory.used / (1024**3)
        memory_total_gb = memory.total / (1024**3)

        gpu_percent = None
        gpu_memory_percent = None
        gpu_temp = None

        if GPU_AVAILABLE:
            try:
                if gpus := GPUtil.getGPUs():
                    gpu = gpus[0]

                    gpu_load = gpu.load * 100 if gpu.load is not None else 0.0
                    gpu_percent = min(max(float(gpu_load), 0.0), 100.0)

                    gpu_mem_util = gpu.memoryUtil * 100 if gpu.memoryUtil is not None else 0.0
                    gpu_memory_percent = min(max(float(gpu_mem_util), 0.0), 100.0)

                    gpu_temperature = gpu.temperature if gpu.temperature is not None else 0.0
                    gpu_temp = min(max(float(gpu_temperature), 0.0), 150.0)
            except Exception as e:
                logger.debug(f"Failed to get GPU metrics: {e}")

        net_io: Any = psutil.net_io_counters()
        network_sent_mb = 0.0
        network_recv_mb = 0.0

        if self.last_net_io is not None:
            sent_delta = (net_io.bytes_sent - self.last_net_io.bytes_sent) / (1024**2)
            recv_delta = (net_io.bytes_recv - self.last_net_io.bytes_recv) / (1024**2)
            network_sent_mb = max(sent_delta, 0.0)
            network_recv_mb = max(recv_delta, 0.0)

        self.last_net_io = net_io

        disk_io: Any = psutil.disk_io_counters()
        disk_read_mb = 0.0
        disk_write_mb = 0.0

        if self.last_disk_io is not None:
            read_delta = (disk_io.read_bytes - self.last_disk_io.read_bytes) / (1024**2)
            write_delta = (disk_io.write_bytes - self.last_disk_io.write_bytes) / (1024**2)
            disk_read_mb = max(read_delta, 0.0)
            disk_write_mb = max(write_delta, 0.0)

        self.last_disk_io = disk_io

        return SystemMetrics(
            timestamp=time.time(),
            cpu_percent=cpu_percent,
            cpu_per_core=cpu_per_core,
            memory_percent=memory_percent,
            memory_used_gb=memory_used_gb,
            memory_total_gb=memory_total_gb,
            gpu_percent=gpu_percent,
            gpu_memory_percent=gpu_memory_percent,
            gpu_temp=gpu_temp,
            network_sent_mb=network_sent_mb,
            network_recv_mb=network_recv_mb,
            disk_read_mb=disk_read_mb,
            disk_write_mb=disk_write_mb,
        )


class SystemMonitorWidget(QWidget):
    """System monitoring widget for the Dashboard."""

    # Signals
    #: alert_type, message (type: str, str)
    alert_triggered = pyqtSignal(str, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize system monitor widget with performance tracking and alerts."""
        super().__init__(parent)

        # Configuration
        self.history_size = 60  # Keep 60 seconds of history
        self.update_interval = 1000  # Update every second

        # Alert thresholds
        self.cpu_threshold = 80.0
        self.memory_threshold = 85.0
        self.gpu_threshold = 90.0

        # Data storage
        self.metrics_history: deque[SystemMetrics] = deque(maxlen=self.history_size)

        # Worker thread
        self.monitor_thread = QThread()
        self.monitor_worker = SystemMonitorWorker()
        self.monitor_worker.moveToThread(self.monitor_thread)

        # Connect signals
        self.monitor_thread.started.connect(self.monitor_worker.run)
        self.monitor_worker.metrics_updated.connect(self._on_metrics_updated)
        self.monitor_worker.error_occurred.connect(self._on_error)

        self.setup_ui()
        self.start_monitoring()

    def setup_ui(self) -> None:
        """Set up the UI components."""
        layout = QVBoxLayout(self)

        # Controls
        controls_layout = QHBoxLayout()

        controls_layout.addWidget(QLabel("Update Interval:"))
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(500, 5000)
        self.interval_spin.setValue(self.update_interval)
        self.interval_spin.setSuffix(" ms")
        self.interval_spin.valueChanged.connect(self._on_interval_changed)
        controls_layout.addWidget(self.interval_spin)

        self.auto_scroll_cb = QCheckBox("Auto-scroll graphs")
        self.auto_scroll_cb.setChecked(True)
        controls_layout.addWidget(self.auto_scroll_cb)

        controls_layout.addStretch()

        self.pause_btn = QPushButton("Pause")
        self.pause_btn.setCheckable(True)
        self.pause_btn.toggled.connect(self._on_pause_toggled)
        controls_layout.addWidget(self.pause_btn)

        layout.addLayout(controls_layout)

        # Main content
        content_splitter = QSplitter(Qt.Orientation.Vertical)

        # Metrics overview
        metrics_group = QGroupBox("System Metrics")
        metrics_layout = QVBoxLayout(metrics_group)

        # CPU usage
        cpu_layout = QHBoxLayout()
        cpu_layout.addWidget(QLabel("CPU:"))
        self.cpu_bar = QProgressBar()
        self.cpu_bar.setTextVisible(True)
        cpu_layout.addWidget(self.cpu_bar)
        self.cpu_label = QLabel("0%")
        self.cpu_label.setMinimumWidth(50)
        cpu_layout.addWidget(self.cpu_label)
        metrics_layout.addLayout(cpu_layout)

        # Memory usage
        mem_layout = QHBoxLayout()
        mem_layout.addWidget(QLabel("Memory:"))
        self.memory_bar = QProgressBar()
        self.memory_bar.setTextVisible(True)
        mem_layout.addWidget(self.memory_bar)
        self.memory_label = QLabel("0.0 GB")
        self.memory_label.setMinimumWidth(80)
        mem_layout.addWidget(self.memory_label)
        metrics_layout.addLayout(mem_layout)

        # GPU usage (if available)
        if GPU_AVAILABLE:
            gpu_layout = QHBoxLayout()
            gpu_layout.addWidget(QLabel("GPU:"))
            self.gpu_bar = QProgressBar()
            self.gpu_bar.setTextVisible(True)
            gpu_layout.addWidget(self.gpu_bar)
            self.gpu_label = QLabel("0%")
            self.gpu_label.setMinimumWidth(50)
            gpu_layout.addWidget(self.gpu_label)
            metrics_layout.addLayout(gpu_layout)

        content_splitter.addWidget(metrics_group)

        # Graphs
        if PYQTGRAPH_AVAILABLE:
            graphs_group = QGroupBox("Performance Graphs")
            graphs_layout = QVBoxLayout(graphs_group)

            # CPU graph
            self.cpu_plot = pg.PlotWidget(title="CPU Usage")
            self.cpu_plot.setLabel("left", "Usage", units="%")
            self.cpu_plot.setLabel("bottom", "Time", units="s")
            self.cpu_plot.setYRange(0, 100)
            self.cpu_plot.showGrid(x=True, y=True)
            self.cpu_curve = self.cpu_plot.plot(pen=pg.mkPen(color=(255, 100, 100), width=2))
            graphs_layout.addWidget(self.cpu_plot)

            # Memory graph
            self.memory_plot = pg.PlotWidget(title="Memory Usage")
            self.memory_plot.setLabel("left", "Usage", units="%")
            self.memory_plot.setLabel("bottom", "Time", units="s")
            self.memory_plot.setYRange(0, 100)
            self.memory_plot.showGrid(x=True, y=True)
            self.memory_curve = self.memory_plot.plot(pen=pg.mkPen(color=(100, 100, 255), width=2))
            graphs_layout.addWidget(self.memory_plot)

            content_splitter.addWidget(graphs_group)

        # Process table
        process_group = QGroupBox("Top Processes")
        process_layout = QVBoxLayout(process_group)

        self.process_table = QTableWidget()
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels(
            [
                "PID",
                "Name",
                "CPU %",
                "Memory %",
                "Status",
            ],
        )
        if header := self.process_table.horizontalHeader():
            header.setStretchLastSection(True)
        process_layout.addWidget(self.process_table)

        content_splitter.addWidget(process_group)
        layout.addWidget(content_splitter)

    def start_monitoring(self) -> None:
        """Start system monitoring."""
        self.monitor_thread.start()

    def stop_monitoring(self) -> None:
        """Stop system monitoring."""
        if self.monitor_worker:
            self.monitor_worker.stop()
        if self.monitor_thread.isRunning():
            self.monitor_thread.quit()
            self.monitor_thread.wait()

    def _on_metrics_updated(self, metrics: SystemMetrics) -> None:
        """Handle new metrics data."""
        if self.pause_btn.isChecked():
            return

        # Store in history
        self.metrics_history.append(metrics)

        # Update progress bars with validated data to match graphs
        cpu_display_value = float(metrics.cpu_percent) if metrics.cpu_percent is not None else 0.0
        memory_display_value = float(metrics.memory_percent) if metrics.memory_percent is not None else 0.0

        self.cpu_bar.setValue(int(cpu_display_value))
        self.cpu_label.setText(f"{cpu_display_value:.1f}%")

        self.memory_bar.setValue(int(memory_display_value))
        self.memory_label.setText(f"{metrics.memory_used_gb:.1f}/{metrics.memory_total_gb:.1f} GB ({memory_display_value:.1f}%)")

        if GPU_AVAILABLE and hasattr(self, "gpu_bar") and metrics.gpu_percent is not None:
            gpu_display_value = float(metrics.gpu_percent)
            self.gpu_bar.setValue(int(gpu_display_value))
            self.gpu_label.setText(f"{gpu_display_value:.1f}%")

        # Update graphs
        if PYQTGRAPH_AVAILABLE:
            self._update_graphs()

        # Update process table
        self._update_process_table()

        # Check thresholds
        self._check_thresholds(metrics)

    def _update_graphs(self) -> None:
        """Update performance graphs."""
        if not self.metrics_history:
            return

        # Prepare data with validation
        times = list(range(len(self.metrics_history)))
        cpu_values = []
        memory_values = []

        for m in self.metrics_history:
            # Ensure CPU and memory values are truly independent
            cpu_val = float(m.cpu_percent) if m.cpu_percent is not None else 0.0
            mem_val = float(m.memory_percent) if m.memory_percent is not None else 0.0

            cpu_values.append(cpu_val)
            memory_values.append(mem_val)

        # Update CPU graph with red color for distinction
        self.cpu_curve.setData(times, cpu_values)

        # Update memory graph with blue color for distinction
        self.memory_curve.setData(times, memory_values)

        # Auto-scroll if enabled
        if self.auto_scroll_cb.isChecked():
            self.cpu_plot.setXRange(max(0, len(times) - self.history_size), len(times))
            self.memory_plot.setXRange(max(0, len(times) - self.history_size), len(times))

    def _update_process_table(self) -> None:
        """Update the process table with top processes."""
        try:
            # Get top processes by CPU usage
            processes = []
            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
                try:
                    pinfo = proc.info
                    if pinfo["cpu_percent"] > 0 or pinfo["memory_percent"] > 0:
                        processes.append(pinfo)
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.debug("Process access error during iteration: %s", e)

            # Sort by CPU usage
            processes.sort(key=lambda x: x["cpu_percent"], reverse=True)

            # Update table
            self.process_table.setRowCount(min(10, len(processes)))  # Show top 10

            for row, proc in enumerate(processes[:10]):
                self.process_table.setItem(row, 0, QTableWidgetItem(str(proc["pid"])))
                self.process_table.setItem(row, 1, QTableWidgetItem(proc["name"]))
                self.process_table.setItem(row, 2, QTableWidgetItem(f"{proc['cpu_percent']:.1f}"))
                self.process_table.setItem(row, 3, QTableWidgetItem(f"{proc['memory_percent']:.1f}"))
                self.process_table.setItem(row, 4, QTableWidgetItem(proc["status"]))

                # Highlight high usage
                if proc["cpu_percent"] > 50:
                    for col in range(5):
                        if item := self.process_table.item(row, col):
                            item.setBackground(QBrush(QColor(255, 200, 200)))

        except Exception as e:
            logger.debug("Error updating system monitor: %s", e)

    def _check_thresholds(self, metrics: SystemMetrics) -> None:
        """Check if any metrics exceed thresholds."""
        if metrics.cpu_percent > self.cpu_threshold:
            self.alert_triggered.emit("cpu", f"High CPU usage: {metrics.cpu_percent:.1f}%")
            self.cpu_bar.setStyleSheet("QProgressBar::chunk { background-color: #ff6666; }")
        else:
            self.cpu_bar.setStyleSheet("")

        if metrics.memory_percent > self.memory_threshold:
            self.alert_triggered.emit("memory", f"High memory usage: {metrics.memory_percent:.1f}%")
            self.memory_bar.setStyleSheet("QProgressBar::chunk { background-color: #ff6666; }")
        else:
            self.memory_bar.setStyleSheet("")

        if GPU_AVAILABLE and metrics.gpu_percent is not None:
            if metrics.gpu_percent > self.gpu_threshold:
                self.alert_triggered.emit("gpu", f"High GPU usage: {metrics.gpu_percent:.1f}%")
                if hasattr(self, "gpu_bar"):
                    self.gpu_bar.setStyleSheet("QProgressBar::chunk { background-color: #ff6666; }")
            elif hasattr(self, "gpu_bar"):
                self.gpu_bar.setStyleSheet("")

    def _on_interval_changed(self, value: int) -> None:
        """Handle update interval change."""
        self.update_interval = value
        if self.monitor_worker:
            self.monitor_worker.update_interval = value

    def _on_pause_toggled(self, checked: bool) -> None:
        """Handle pause button toggle."""
        if checked:
            self.pause_btn.setText("Resume")
        else:
            self.pause_btn.setText("Pause")

    def _on_error(self, error_msg: str) -> None:
        """Handle monitoring errors."""
        # Log error but don't show to user to avoid spam

    def get_current_metrics(self) -> SystemMetrics | None:
        """Get the most recent metrics."""
        return self.metrics_history[-1] if self.metrics_history else None

    def get_metrics_summary(self) -> dict[str, Any]:
        """Get a summary of recent metrics."""
        if not self.metrics_history:
            return {}

        cpu_values = [m.cpu_percent for m in self.metrics_history]
        memory_values = [m.memory_percent for m in self.metrics_history]

        summary = {
            "cpu_current": cpu_values[-1] if cpu_values else 0,
            "cpu_average": sum(cpu_values) / len(cpu_values) if cpu_values else 0,
            "cpu_max": max(cpu_values, default=0),
            "memory_current": memory_values[-1] if memory_values else 0,
            "memory_average": (sum(memory_values) / len(memory_values) if memory_values else 0),
            "memory_max": max(memory_values, default=0),
        }

        if gpu_values := [m.gpu_percent for m in self.metrics_history if m.gpu_percent is not None]:
            if GPU_AVAILABLE:
                summary |= {
                    "gpu_current": gpu_values[-1],
                    "gpu_average": sum(gpu_values) / len(gpu_values),
                    "gpu_max": max(gpu_values),
                }

        return summary

    def set_thresholds(self, cpu: float | None = None, memory: float | None = None, gpu: float | None = None) -> None:
        """Set alert thresholds."""
        if cpu is not None:
            self.cpu_threshold = cpu
        if memory is not None:
            self.memory_threshold = memory
        if gpu is not None:
            self.gpu_threshold = gpu

    def set_refresh_interval(self, interval_ms: int) -> None:
        """Set the refresh interval for monitoring."""
        self.update_interval = interval_ms
        if hasattr(self, "interval_spin"):
            self.interval_spin.setValue(interval_ms)
        if hasattr(self, "monitor_worker"):
            self.monitor_worker.update_interval = interval_ms

    def export_metrics(self, filepath: str) -> None:
        """Export metrics history to file."""
        import json

        data = [
            {
                "timestamp": metric.timestamp,
                "cpu_percent": metric.cpu_percent,
                "memory_percent": metric.memory_percent,
                "memory_used_gb": metric.memory_used_gb,
                "gpu_percent": metric.gpu_percent,
                "network_sent_mb": metric.network_sent_mb,
                "network_recv_mb": metric.network_recv_mb,
            }
            for metric in self.metrics_history
        ]
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    def closeEvent(self, event: QCloseEvent | None) -> None:
        """Handle widget close event."""
        self.stop_monitoring()
        if event is not None:
            event.accept()
