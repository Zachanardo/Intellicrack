"""CPU status widget for Intellicrack.

This module provides a widget for displaying CPU usage, temperature,
and performance metrics in the system monitoring interface.
"""
import platform
from typing import Any, Dict, List

import psutil
from PyQt6.QtCore import QObject, QThread, Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


class CPUMonitorWorker(QObject):
    """Worker thread for collecting CPU metrics"""

    cpu_data_ready = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self):
        """Initialize CPU monitor worker with performance tracking capabilities."""
        super().__init__()
        self.running = True

    def start_monitoring(self):
        """Start the monitoring process"""
        self.running = True
        self._monitor_loop()

    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.running = False

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                cpu_data = self._collect_cpu_data()
                self.cpu_data_ready.emit(cpu_data)
            except Exception as e:
                self.error_occurred.emit(str(e))

            # Sleep for update interval
            if self.running:
                self.thread().msleep(1000)  # 1 second update

    def _collect_cpu_data(self) -> Dict[str, Any]:
        """Collect comprehensive CPU data"""
        # Get CPU info
        cpu_info = {
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "cpu_percent_total": psutil.cpu_percent(interval=0.1),
            "cpu_percent_cores": psutil.cpu_percent(interval=0.1, percpu=True),
            "cpu_freq": psutil.cpu_freq(),
            "cpu_stats": psutil.cpu_stats()._asdict() if hasattr(psutil, "cpu_stats") else {},
            "load_average": psutil.getloadavg() if hasattr(psutil, "getloadavg") else (0, 0, 0),
            "cpu_times": psutil.cpu_times()._asdict(),
            "cpu_times_percent": psutil.cpu_times_percent(interval=0.1)._asdict()
        }

        # Get process info
        try:
            processes = []
            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                try:
                    pinfo = proc.info
                    if pinfo["cpu_percent"] > 0:
                        processes.append({
                            "pid": pinfo["pid"],
                            "name": pinfo["name"],
                            "cpu_percent": pinfo["cpu_percent"],
                            "memory_percent": pinfo["memory_percent"]
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Sort by CPU usage
            processes.sort(key=lambda x: x["cpu_percent"], reverse=True)
            cpu_info["top_processes"] = processes[:10]

        except Exception:
            cpu_info["top_processes"] = []

        # Get CPU name/model
        cpu_info["cpu_model"] = self._get_cpu_model()

        return cpu_info

    def _get_cpu_model(self) -> str:
        """Get CPU model name"""
        try:
            if platform.system() == "Windows":
                import wmi
                c = wmi.WMI()
                for processor in c.Win32_Processor():
                    return processor.Name
            elif platform.system() == "Linux":
                with open("/proc/cpuinfo", "r") as f:
                    for line in f:
                        if line.startswith("model name"):
                            return line.split(":")[1].strip()
            elif platform.system() == "Darwin":
                import subprocess
                return subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"]).decode().strip()
        except:
            pass

        return "Unknown CPU"


class CPUStatusWidget(QWidget):
    """CPU status monitoring widget"""

    def __init__(self, parent=None):
        """Initialize CPU status widget with performance monitoring and CPU detection."""
        super().__init__(parent)
        self.setMaximumHeight(50)
        self.setMinimumWidth(250)
        self._setup_ui()
        self._start_monitoring()
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)

        # CPU Info Group
        info_group = QGroupBox("CPU Information")
        info_layout = QGridLayout(info_group)

        self.model_label = QLabel("Model: Detecting...")
        self.model_label.setWordWrap(True)
        info_layout.addWidget(self.model_label, 0, 0, 1, 2)

        self.cores_label = QLabel("Cores: Detecting...")
        self.threads_label = QLabel("Threads: Detecting...")
        info_layout.addWidget(self.cores_label, 1, 0)
        info_layout.addWidget(self.threads_label, 1, 1)

        self.freq_label = QLabel("Frequency: Detecting...")
        self.load_label = QLabel("Load Average: Detecting...")
        info_layout.addWidget(self.freq_label, 2, 0)
        info_layout.addWidget(self.load_label, 2, 1)

        layout.addWidget(info_group)

        # Overall Usage Group
        usage_group = QGroupBox("CPU Usage")
        usage_layout = QVBoxLayout(usage_group)

        # Total CPU usage
        total_layout = QHBoxLayout()
        total_layout.addWidget(QLabel("Total:"))
        self.total_cpu_bar = QProgressBar()
        self.total_cpu_bar.setMaximum(100)
        self.total_cpu_label = QLabel("0%")
        total_layout.addWidget(self.total_cpu_bar)
        total_layout.addWidget(self.total_cpu_label)
        usage_layout.addLayout(total_layout)

        # Per-core usage
        self.cores_container = QWidget()
        self.cores_layout = QGridLayout(self.cores_container)
        usage_layout.addWidget(self.cores_container)

        layout.addWidget(usage_group)

        # CPU Times Group
        times_group = QGroupBox("CPU Time Distribution")
        times_layout = QGridLayout(times_group)

        self.time_labels = {}
        time_types = ["user", "system", "idle", "iowait"]
        for i, time_type in enumerate(time_types):
            label = QLabel(f"{time_type.capitalize()}:")
            value = QLabel("0%")
            self.time_labels[time_type] = value
            times_layout.addWidget(label, i // 2, (i % 2) * 2)
            times_layout.addWidget(value, i // 2, (i % 2) * 2 + 1)

        layout.addWidget(times_group)

        # Top Processes Group
        processes_group = QGroupBox("Top CPU Processes")
        processes_layout = QVBoxLayout(processes_group)

        self.processes_table = QTableWidget()
        self.processes_table.setColumnCount(4)
        self.processes_table.setHorizontalHeaderLabels(["PID", "Name", "CPU %", "Memory %"])
        self.processes_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.processes_table.setMaximumHeight(200)
        processes_layout.addWidget(self.processes_table)

        layout.addWidget(processes_group)

        layout.addStretch()

    def setup_monitoring(self):
        """Setup CPU monitoring thread"""
        self.monitor_thread = QThread()
        self.monitor_worker = CPUMonitorWorker()
        self.monitor_worker.moveToThread(self.monitor_thread)

        # Connect signals
        self.monitor_thread.started.connect(self.monitor_worker.start_monitoring)
        self.monitor_worker.cpu_data_ready.connect(self.update_cpu_data)
        self.monitor_worker.error_occurred.connect(self.handle_error)

    def start_monitoring(self):
        """Start CPU monitoring"""
        if not self.monitor_thread.isRunning():
            self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop CPU monitoring"""
        if self.monitor_thread.isRunning():
            self.monitor_worker.stop_monitoring()
            self.monitor_thread.quit()
            self.monitor_thread.wait()

    def update_cpu_data(self, data: Dict[str, Any]):
        """Update CPU data from monitor"""
        self.cpu_data = data

        # Update CPU info
        self.model_label.setText(f"Model: {data.get('cpu_model', 'Unknown')}")
        self.cores_label.setText(f"Cores: {data.get('cpu_count_physical', 0)}")
        self.threads_label.setText(f"Threads: {data.get('cpu_count_logical', 0)}")

        # Update frequency
        freq = data.get("cpu_freq")
        if freq:
            self.freq_label.setText(f"Frequency: {freq.current:.0f} MHz")

        # Update load average
        load = data.get("load_average", (0, 0, 0))
        self.load_label.setText(f"Load: {load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}")

        # Update total CPU usage
        total_cpu = data.get("cpu_percent_total", 0)
        self.total_cpu_bar.setValue(int(total_cpu))
        self.total_cpu_label.setText(f"{total_cpu:.1f}%")
        self._set_bar_color(self.total_cpu_bar, total_cpu)

        # Update per-core usage
        self.update_core_usage(data.get("cpu_percent_cores", []))

        # Update CPU times
        times_percent = data.get("cpu_times_percent", {})
        for time_type, label in self.time_labels.items():
            value = times_percent.get(time_type, 0)
            label.setText(f"{value:.1f}%")

        # Update top processes
        self.update_processes_table(data.get("top_processes", []))

    def update_core_usage(self, core_percents: List[float]):
        """Update per-core CPU usage display"""
        # Create core bars if needed
        while len(self.core_bars) < len(core_percents):
            row = len(self.core_bars) // 2
            col = (len(self.core_bars) % 2) * 3

            label = QLabel(f"Core {len(self.core_bars)}:")
            bar = QProgressBar()
            bar.setMaximum(100)
            percent_label = QLabel("0%")

            self.cores_layout.addWidget(label, row, col)
            self.cores_layout.addWidget(bar, row, col + 1)
            self.cores_layout.addWidget(percent_label, row, col + 2)

            self.core_bars.append((bar, percent_label))

        # Update core bars
        for i, percent in enumerate(core_percents):
            if i < len(self.core_bars):
                bar, label = self.core_bars[i]
                bar.setValue(int(percent))
                label.setText(f"{percent:.1f}%")
                self._set_bar_color(bar, percent)

    def update_processes_table(self, processes: List[Dict[str, Any]]):
        """Update top processes table"""
        self.processes_table.setRowCount(len(processes))

        for i, proc in enumerate(processes):
            self.processes_table.setItem(i, 0, QTableWidgetItem(str(proc["pid"])))
            self.processes_table.setItem(i, 1, QTableWidgetItem(proc["name"]))

            cpu_item = QTableWidgetItem(f"{proc['cpu_percent']:.1f}")
            if proc["cpu_percent"] > 50:
                cpu_item.setForeground(QColor(220, 53, 69))
            elif proc["cpu_percent"] > 25:
                cpu_item.setForeground(QColor(255, 193, 7))
            self.processes_table.setItem(i, 2, cpu_item)

            self.processes_table.setItem(i, 3, QTableWidgetItem(f"{proc['memory_percent']:.1f}"))

    def _set_bar_color(self, bar: QProgressBar, value: float):
        """Set progress bar color based on value"""
        if value >= 90:
            bar.setStyleSheet("QProgressBar::chunk { background-color: #dc3545; }")
        elif value >= 70:
            bar.setStyleSheet("QProgressBar::chunk { background-color: #ffc107; }")
        else:
            bar.setStyleSheet("QProgressBar::chunk { background-color: #28a745; }")

    def handle_error(self, error_msg: str):
        """Handle monitoring errors"""
        print(f"CPU monitoring error: {error_msg}")
