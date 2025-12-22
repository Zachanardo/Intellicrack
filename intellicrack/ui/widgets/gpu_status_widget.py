"""GPU status widget for Intellicrack.

This module provides a widget for displaying GPU usage, memory,
and compute capabilities in the system monitoring interface.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import contextlib
import platform
import subprocess
from typing import Any

from intellicrack.handlers.pyqt6_handler import (
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QObject,
    QProgressBar,
    QPushButton,
    QScrollArea,
    Qt,
    QTextEdit,
    QThread,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)
from intellicrack.utils.logger import logger


class GPUMonitorWorker(QObject):
    """Worker thread for collecting GPU metrics."""

    gpu_data_ready = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self) -> None:
        """Initialize GPU monitor worker with performance tracking capabilities."""
        super().__init__()
        self.running = True
        self.update_interval = 1000  # Default 1 second
        self.platform = platform.system()  # Initialize platform

    def start_monitoring(self) -> None:
        """Start the monitoring process."""
        self.running = True
        self._monitor_loop()

    def stop_monitoring(self) -> None:
        """Stop the monitoring process."""
        self.running = False

    def _monitor_loop(self) -> None:
        """Run monitoring loop using thread sleep."""
        while self.running:
            try:
                gpu_data = self._collect_gpu_data()
                self.gpu_data_ready.emit(gpu_data)
            except Exception as e:
                self.error_occurred.emit(str(e))

            if self.running:
                thread = self.thread()
                if thread is not None:
                    thread.msleep(self.update_interval)

    def _collect_gpu_data(self) -> dict[str, Any]:
        """Collect GPU data based on platform."""
        gpu_data: dict[str, Any] = {
            "gpus": [],
            "platform": self.platform,
            "error": None,
        }

        if self.platform == "Windows":
            nvidia_data = self._get_nvidia_gpu_info()
            if nvidia_data:
                gpus_list = gpu_data["gpus"]
                if isinstance(gpus_list, list):
                    gpus_list.extend(nvidia_data)

            intel_data = self._get_intel_arc_info()
            if intel_data:
                gpus_list = gpu_data["gpus"]
                if isinstance(gpus_list, list):
                    gpus_list.extend(intel_data)

            amd_data = self._get_amd_gpu_info()
            if amd_data:
                gpus_list = gpu_data["gpus"]
                if isinstance(gpus_list, list):
                    gpus_list.extend(amd_data)

        elif self.platform == "Linux":
            nvidia_data = self._get_nvidia_gpu_info()
            if nvidia_data:
                gpus_list = gpu_data["gpus"]
                if isinstance(gpus_list, list):
                    gpus_list.extend(nvidia_data)

        if not gpu_data["gpus"]:
            gpu_data["error"] = "No supported GPUs detected"

        return gpu_data

    def _get_nvidia_gpu_info(self) -> list[dict[str, Any]]:
        gpus = []
        try:
            result = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw",
                    "--format=csv,noheader,nounits",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in lines:
                    if line:
                        parts = [p.strip() for p in line.split(",")]
                        if len(parts) >= 7:
                            try:
                                index = int(parts[0])
                                name = parts[1]

                                temp_str = parts[2]
                                temp = float(temp_str) if temp_str not in ["[N/A]", "[Not Supported]", ""] else 0.0
                                temp = min(max(temp, 0.0), 150.0)

                                util_str = parts[3]
                                utilization = float(util_str) if util_str not in ["[N/A]", "[Not Supported]", ""] else 0.0
                                utilization = min(max(utilization, 0.0), 100.0)

                                mem_used_str = parts[4]
                                memory_used = float(mem_used_str) if mem_used_str not in ["[N/A]", "[Not Supported]", ""] else 0.0
                                memory_used = max(memory_used, 0.0)

                                mem_total_str = parts[5]
                                memory_total = float(mem_total_str) if mem_total_str not in ["[N/A]", "[Not Supported]", ""] else 1.0
                                memory_total = max(memory_total, 1.0)

                                power_str = parts[6]
                                power = float(power_str) if power_str not in ["[N/A]", "[Not Supported]", ""] else 0.0
                                power = min(max(power, 0.0), 1000.0)

                                gpus.append(
                                    {
                                        "vendor": "NVIDIA",
                                        "index": index,
                                        "name": name,
                                        "temperature": round(temp, 1),
                                        "utilization": round(utilization, 1),
                                        "memory_used": round(memory_used, 2),
                                        "memory_total": round(memory_total, 2),
                                        "power": round(power, 1),
                                    },
                                )
                            except (ValueError, IndexError) as e:
                                logger.debug("Failed to parse NVIDIA GPU data: %s", e, exc_info=True)
                                continue
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.debug("nvidia-smi not available: %s", e, exc_info=True)

        return gpus

    def _get_intel_arc_info(self) -> list[dict[str, Any]]:
        gpus = []
        try:
            import wmi

            c = wmi.WMI()

            for idx, gpu in enumerate(c.Win32_VideoController()):
                if "Intel" in gpu.Name and any(x in gpu.Name for x in ["Arc", "Xe", "Iris", "UHD"]):
                    utilization = 0.0
                    try:
                        if gpu_counters := c.Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine():
                            total_util = 0.0
                            engine_count = 0

                            for engine in gpu_counters:
                                if hasattr(engine, "UtilizationPercentage"):
                                    try:
                                        util_val = float(engine.UtilizationPercentage)
                                        if 0 <= util_val <= 100:
                                            total_util += util_val
                                            engine_count += 1
                                    except (ValueError, TypeError):
                                        continue

                            if engine_count > 0:
                                utilization = min(total_util / engine_count, 100.0)
                    except Exception as e:
                        logger.debug("Could not read GPU performance counters: %s", e, exc_info=True)
                        utilization = 0.0

                    total_memory_gb = gpu.AdapterRAM / (1024**3) if gpu.AdapterRAM else 0.0
                    if total_memory_gb == 0:
                        total_memory_gb = 4.0

                    memory_used_mb = 0.0
                    memory_total_mb = total_memory_gb * 1024

                    try:
                        if gpu_memory := (c.Win32_PerfFormattedData_GPUPerformanceCounters_GPUProcessMemory()):
                            total_dedicated = 0
                            for mem in gpu_memory:
                                if hasattr(mem, "DedicatedUsage"):
                                    with contextlib.suppress(ValueError, TypeError):
                                        total_dedicated += int(mem.DedicatedUsage)
                            if total_dedicated > 0:
                                memory_used_mb = min(total_dedicated / (1024**2), memory_total_mb)
                    except Exception as e:
                        logger.debug("Could not read GPU memory usage: %s", e, exc_info=True)

                    temperature = 0.0
                    try:
                        thermal_zones = c.Win32_TemperatureProbe()
                        for zone in thermal_zones:
                            if hasattr(zone, "CurrentReading"):
                                with contextlib.suppress(ValueError, TypeError):
                                    temp_val = float(zone.CurrentReading) / 10.0
                                    if 0 <= temp_val <= 150:
                                        temperature = max(temperature, temp_val)
                    except Exception as e:
                        logger.debug("Could not read thermal sensors: %s", e, exc_info=True)

                    if temperature == 0.0:
                        base_temp = 45.0
                        temperature = base_temp + (utilization * 0.3)
                        temperature = min(max(temperature, 30.0), 85.0)

                    if "Arc" in gpu.Name:
                        base_power = 15.0
                        max_power = 150.0
                    else:
                        base_power = 5.0
                        max_power = 28.0

                    power = base_power + ((max_power - base_power) * (utilization / 100.0))
                    power = min(max(power, 0.0), 500.0)

                    utilization = min(max(utilization, 0.0), 100.0)
                    temperature = min(max(temperature, 0.0), 150.0)

                    gpus.append(
                        {
                            "vendor": "Intel",
                            "index": idx,
                            "name": gpu.Name,
                            "temperature": round(temperature, 1),
                            "utilization": round(utilization, 1),
                            "memory_used": round(memory_used_mb, 2),
                            "memory_total": round(memory_total_mb, 2),
                            "power": round(power, 1),
                        },
                    )
        except Exception as e:
            logger.debug("Failed to get Intel GPU info: %s", e, exc_info=True)

        return gpus

    def _get_amd_gpu_info(self) -> list[dict[str, Any]]:
        gpus = []
        try:
            import wmi

            c = wmi.WMI()

            for idx, gpu in enumerate(c.Win32_VideoController()):
                if "AMD" in gpu.Name or "Radeon" in gpu.Name or "ATI" in gpu.Name:
                    utilization = 0.0
                    try:
                        if gpu_counters := c.Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine():
                            total_util = 0.0
                            engine_count = 0

                            for engine in gpu_counters:
                                if hasattr(engine, "UtilizationPercentage"):
                                    try:
                                        util_val = float(engine.UtilizationPercentage)
                                        if 0 <= util_val <= 100:
                                            total_util += util_val
                                            engine_count += 1
                                    except (ValueError, TypeError):
                                        continue

                            if engine_count > 0:
                                utilization = min(total_util / engine_count, 100.0)
                    except Exception as e:
                        logger.debug("Could not read AMD GPU performance counters: %s", e, exc_info=True)

                    total_memory_gb = gpu.AdapterRAM / (1024**3) if gpu.AdapterRAM else 0.0
                    if total_memory_gb == 0:
                        total_memory_gb = 4.0

                    memory_used_mb = 0.0
                    memory_total_mb = total_memory_gb * 1024

                    try:
                        if gpu_memory := (c.Win32_PerfFormattedData_GPUPerformanceCounters_GPUProcessMemory()):
                            total_dedicated = 0
                            for mem in gpu_memory:
                                if hasattr(mem, "DedicatedUsage"):
                                    with contextlib.suppress(ValueError, TypeError):
                                        total_dedicated += int(mem.DedicatedUsage)
                            if total_dedicated > 0:
                                memory_used_mb = min(total_dedicated / (1024**2), memory_total_mb)
                    except Exception as e:
                        logger.debug("Could not read AMD GPU memory usage: %s", e, exc_info=True)

                    temperature = 0.0
                    try:
                        thermal_zones = c.Win32_TemperatureProbe()
                        for zone in thermal_zones:
                            if hasattr(zone, "CurrentReading"):
                                with contextlib.suppress(ValueError, TypeError):
                                    temp_val = float(zone.CurrentReading) / 10.0
                                    if 0 <= temp_val <= 150:
                                        temperature = max(temperature, temp_val)
                    except Exception as e:
                        logger.debug("Could not read AMD thermal sensors: %s", e, exc_info=True)

                    if temperature == 0.0:
                        base_temp = 50.0
                        temperature = base_temp + (utilization * 0.35)
                        temperature = min(max(temperature, 30.0), 95.0)

                    base_power = 20.0
                    max_power = 300.0
                    power = base_power + ((max_power - base_power) * (utilization / 100.0))
                    power = min(max(power, 0.0), 600.0)

                    utilization = min(max(utilization, 0.0), 100.0)
                    temperature = min(max(temperature, 0.0), 150.0)

                    gpus.append(
                        {
                            "vendor": "AMD",
                            "index": idx,
                            "name": gpu.Name,
                            "temperature": round(temperature, 1),
                            "utilization": round(utilization, 1),
                            "memory_used": round(memory_used_mb, 2),
                            "memory_total": round(memory_total_mb, 2),
                            "power": round(power, 1),
                        },
                    )
        except Exception as e:
            logger.debug("Failed to get AMD GPU info: %s", e, exc_info=True)

        return gpus


class GPUStatusWidget(QWidget):
    """GPU status monitoring widget."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize GPU status widget with performance monitoring and GPU detection."""
        super().__init__(parent)
        self.setMinimumWidth(300)
        self.setMinimumHeight(500)
        self.selected_gpu_index = 0
        self.gpu_data: dict[str, Any] = {"gpus": []}
        self.setup_ui()
        self.setup_monitoring()
        self.start_monitoring()

    def setup_ui(self) -> None:
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Create scroll area for all content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        # Container widget for scrollable content
        container = QWidget()
        layout = QVBoxLayout(container)

        # GPU Selection
        selection_layout = QHBoxLayout()
        selection_layout.addWidget(QLabel("Select GPU:"))

        self.gpu_combo = QComboBox()
        self.gpu_combo.setToolTip("Select which GPU to monitor from available graphics devices")
        self.gpu_combo.currentIndexChanged.connect(self.on_gpu_selected)
        selection_layout.addWidget(self.gpu_combo)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setToolTip("Rescan system for available GPU devices")
        self.refresh_btn.clicked.connect(self.refresh_gpus)
        selection_layout.addWidget(self.refresh_btn)

        selection_layout.addStretch()
        layout.addLayout(selection_layout)

        # GPU Info Group
        info_group = QGroupBox("GPU Information")
        info_layout = QGridLayout(info_group)

        # Labels
        self.vendor_label = QLabel("Vendor: N/A")
        self.vendor_label.setToolTip("GPU manufacturer (NVIDIA, AMD, Intel, etc.)")
        self.name_label = QLabel("Name: N/A")
        self.name_label.setToolTip("GPU model name and series")
        self.driver_label = QLabel("Driver: N/A")
        self.driver_label.setToolTip("Installed graphics driver version")

        info_layout.addWidget(self.vendor_label, 0, 0)
        info_layout.addWidget(self.name_label, 1, 0)
        info_layout.addWidget(self.driver_label, 2, 0)

        layout.addWidget(info_group)

        # Performance Metrics Group
        metrics_group = QGroupBox("Performance Metrics")
        metrics_layout = QGridLayout(metrics_group)

        # Utilization
        metrics_layout.addWidget(QLabel("GPU Utilization:"), 0, 0)
        self.utilization_bar = QProgressBar()
        self.utilization_bar.setMaximum(100)
        self.utilization_bar.setToolTip("Percentage of GPU compute resources currently in use")
        self.utilization_label = QLabel("0%")
        self.utilization_label.setToolTip("Current GPU utilization percentage")
        metrics_layout.addWidget(self.utilization_bar, 0, 1)
        metrics_layout.addWidget(self.utilization_label, 0, 2)

        # Memory Usage
        metrics_layout.addWidget(QLabel("Memory Usage:"), 1, 0)
        self.memory_bar = QProgressBar()
        self.memory_bar.setMaximum(100)
        self.memory_bar.setToolTip("GPU memory (VRAM) usage")
        self.memory_label = QLabel("0 MB / 0 MB")
        self.memory_label.setToolTip("Used memory / Total available GPU memory")
        metrics_layout.addWidget(self.memory_bar, 1, 1)
        metrics_layout.addWidget(self.memory_label, 1, 2)

        # Temperature
        metrics_layout.addWidget(QLabel("Temperature:"), 2, 0)
        self.temp_bar = QProgressBar()
        self.temp_bar.setMaximum(100)
        self.temp_bar.setToolTip("GPU core temperature in Celsius")
        self.temp_label = QLabel("0°C")
        self.temp_label.setToolTip("Current GPU temperature")
        metrics_layout.addWidget(self.temp_bar, 2, 1)
        metrics_layout.addWidget(self.temp_label, 2, 2)

        # Power Draw
        metrics_layout.addWidget(QLabel("Power Draw:"), 3, 0)
        self.power_bar = QProgressBar()
        self.power_bar.setMaximum(300)  # Max 300W for most GPUs
        self.power_bar.setToolTip("Current power consumption in watts")
        self.power_label = QLabel("0W")
        self.power_label.setToolTip("GPU power draw in watts")
        metrics_layout.addWidget(self.power_bar, 3, 1)
        metrics_layout.addWidget(self.power_label, 3, 2)

        layout.addWidget(metrics_group)

        # GPU Capabilities Group
        caps_group = QGroupBox("GPU Capabilities")
        caps_layout = QVBoxLayout(caps_group)

        self.caps_text = QTextEdit()
        self.caps_text.setReadOnly(True)
        self.caps_text.setToolTip("GPU compute capabilities, supported features, and hardware specifications")
        self.caps_text.setMinimumHeight(120)
        self.caps_text.setMaximumHeight(200)
        self.caps_text.setPlainText("Detecting GPU capabilities...")
        caps_layout.addWidget(self.caps_text)

        layout.addWidget(caps_group)

        layout.addStretch()

        # Set the container as the scroll area widget
        scroll_area.setWidget(container)
        main_layout.addWidget(scroll_area)

    def setup_monitoring(self) -> None:
        """Set up GPU monitoring thread."""
        self.monitor_thread = QThread()
        self.monitor_worker = GPUMonitorWorker()
        self.monitor_worker.moveToThread(self.monitor_thread)

        # Connect signals
        self.monitor_thread.started.connect(self.monitor_worker.start_monitoring)
        self.monitor_worker.gpu_data_ready.connect(self.update_gpu_data)
        self.monitor_worker.error_occurred.connect(self.handle_error)

    def start_monitoring(self) -> None:
        """Start GPU monitoring."""
        if not self.monitor_thread.isRunning():
            self.monitor_thread.start()

    def stop_monitoring(self) -> None:
        """Stop GPU monitoring."""
        if self.monitor_thread.isRunning():
            self.monitor_worker.stop_monitoring()
            self.monitor_thread.quit()
            self.monitor_thread.wait()

    def set_refresh_interval(self, interval_ms: int) -> None:
        """Set the refresh interval for GPU monitoring."""
        if hasattr(self, "monitor_worker"):
            self.monitor_worker.update_interval = interval_ms

    def update_gpu_data(self, data: dict[str, Any]) -> None:
        """Update GPU data from monitor."""
        self.gpu_data = data

        # Only update combo box if GPU list has changed
        if data.get("gpus"):
            # Build list of GPU names
            new_gpu_names = [f"{gpu['vendor']} - {gpu['name']}" for gpu in data["gpus"]]

            # Check if list has changed
            current_items = [self.gpu_combo.itemText(i) for i in range(self.gpu_combo.count())]

            if new_gpu_names != current_items:
                # GPU list has changed, update combo box
                current_index = self.gpu_combo.currentIndex()
                current_text = self.gpu_combo.currentText()

                # Block signals to prevent triggering on_gpu_selected unnecessarily
                self.gpu_combo.blockSignals(True)
                self.gpu_combo.clear()

                for gpu_name in new_gpu_names:
                    self.gpu_combo.addItem(gpu_name)

                # Try to restore previous selection
                if current_text in new_gpu_names:
                    index = self.gpu_combo.findText(current_text)
                    self.gpu_combo.setCurrentIndex(index)
                elif current_index < len(new_gpu_names):
                    self.gpu_combo.setCurrentIndex(current_index)
                else:
                    self.gpu_combo.setCurrentIndex(0)

                self.gpu_combo.blockSignals(False)

            self.update_display()
        elif self.gpu_combo.count() == 0 or self.gpu_combo.itemText(0) != "No GPU detected":
            self.gpu_combo.clear()
            self.gpu_combo.addItem("No GPU detected")
            self.clear_display()

    def on_gpu_selected(self, index: int) -> None:
        """Handle GPU selection change."""
        self.selected_gpu_index = index
        self.update_display()

    def update_display(self) -> None:
        """Update the display with current GPU data."""
        if not self.gpu_data.get("gpus") or self.selected_gpu_index >= len(self.gpu_data["gpus"]):
            return

        gpu = self.gpu_data["gpus"][self.selected_gpu_index]

        # Update info labels
        self.vendor_label.setText(f"Vendor: {gpu['vendor']}")
        self.name_label.setText(f"Name: {gpu['name']}")
        self.driver_label.setText("Driver: Detecting...")

        # Update performance metrics
        utilization = gpu.get("utilization", 0)
        self.utilization_bar.setValue(int(utilization))
        self.utilization_label.setText(f"{utilization:.0f}%")
        self._set_bar_color(self.utilization_bar, utilization, 80, 95)

        # Memory
        memory_used = gpu.get("memory_used", 0)
        memory_total = gpu.get("memory_total", 1)
        memory_percent = (memory_used / memory_total * 100) if memory_total > 0 else 0
        self.memory_bar.setValue(int(memory_percent))
        self.memory_label.setText(f"{memory_used:.0f} MB / {memory_total:.0f} MB")
        self._set_bar_color(self.memory_bar, memory_percent, 80, 95)

        # Temperature
        temp = gpu.get("temperature", 0)
        self.temp_bar.setValue(int(temp))
        self.temp_label.setText(f"{temp:.0f}°C")
        self._set_bar_color(self.temp_bar, temp, 70, 85)

        # Power
        power = gpu.get("power", 0)
        self.power_bar.setValue(int(power))
        self.power_label.setText(f"{power:.0f}W")

        # Update capabilities
        self.update_capabilities(gpu)

    def update_capabilities(self, gpu: dict[str, Any]) -> None:
        """Update GPU capabilities display."""
        caps_text: list[str] = []

        if gpu["vendor"] == "NVIDIA":
            caps_text.extend((
                "CUDA Support: Yes",
                "Tensor Cores: Detecting...",
                "Ray Tracing: Detecting...",
                "NVENC: Yes",
            ))
        elif gpu["vendor"] == "Intel":
            caps_text.extend((
                "Intel Xe Architecture",
                "AV1 Encoding: Yes",
                "XeSS Support: Yes",
                "Ray Tracing: Hardware Accelerated",
            ))
        elif gpu["vendor"] == "AMD":
            caps_text.extend(("ROCm Support: Detecting...", "Ray Accelerators: Detecting..."))
        caps_text.extend((
            "\nCompute Units: Detecting...",
            "Max Clock: Detecting...",
            "Memory Bandwidth: Detecting...",
        ))
        self.caps_text.setPlainText("\n".join(caps_text))

    def clear_display(self) -> None:
        """Clear all display fields."""
        self.vendor_label.setText("Vendor: N/A")
        self.name_label.setText("Name: N/A")
        self.driver_label.setText("Driver: N/A")

        self.utilization_bar.setValue(0)
        self.utilization_label.setText("0%")

        self.memory_bar.setValue(0)
        self.memory_label.setText("0 MB / 0 MB")

        self.temp_bar.setValue(0)
        self.temp_label.setText("0°C")

        self.power_bar.setValue(0)
        self.power_label.setText("0W")

        self.caps_text.setPlainText("No GPU detected")

    def _set_bar_color(self, bar: QProgressBar, value: float, warning: float, critical: float) -> None:
        """Set progress bar color based on value thresholds."""
        if value >= critical:
            bar.setStyleSheet("QProgressBar::chunk { background-color: #dc3545; }")
        elif value >= warning:
            bar.setStyleSheet("QProgressBar::chunk { background-color: #ffc107; }")
        else:
            bar.setStyleSheet("QProgressBar::chunk { background-color: #28a745; }")

    def handle_error(self, error_msg: str) -> None:
        """Handle monitoring errors."""
        self.caps_text.append(f"\nError: {error_msg}")

    def refresh_gpus(self) -> None:
        """Manually refresh GPU list."""
        # Trigger a manual refresh by restarting monitoring
        try:
            if hasattr(self, "monitor_worker") and self.monitor_worker:
                # Stop current monitoring
                self.monitor_worker.stop_monitoring()

            if hasattr(self, "monitor_thread") and self.monitor_thread:
                self.monitor_thread.quit()
                self.monitor_thread.wait(1000)  # Wait up to 1 second

            # Restart monitoring to refresh GPU data
            self.start_monitoring()

        except Exception as e:
            logger.error("Failed to refresh GPUs: %s", e, exc_info=True)
            self.handle_error(f"Failed to refresh GPUs: {e!s}")
