from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QGroupBox, QGridLayout, QProgressBar, QComboBox,
    QPushButton, QTextEdit
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QObject
from PyQt6.QtGui import QFont, QPixmap, QPainter, QColor, QBrush
import platform
import subprocess
import json
from typing import Dict, List, Optional, Any


class GPUMonitorWorker(QObject):
    """Worker thread for collecting GPU metrics"""
    
    gpu_data_ready = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.platform = platform.system()
        
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
                gpu_data = self._collect_gpu_data()
                self.gpu_data_ready.emit(gpu_data)
            except Exception as e:
                self.error_occurred.emit(str(e))
            
            # Sleep for update interval
            if self.running:
                self.thread().msleep(1000)  # 1 second update
                
    def _collect_gpu_data(self) -> Dict[str, Any]:
        """Collect GPU data based on platform"""
        gpu_data = {
            "gpus": [],
            "platform": self.platform,
            "error": None
        }
        
        if self.platform == "Windows":
            # Try NVIDIA first
            nvidia_data = self._get_nvidia_gpu_info()
            if nvidia_data:
                gpu_data["gpus"].extend(nvidia_data)
            
            # Try Intel Arc
            intel_data = self._get_intel_arc_info()
            if intel_data:
                gpu_data["gpus"].extend(intel_data)
                
            # Try AMD
            amd_data = self._get_amd_gpu_info()
            if amd_data:
                gpu_data["gpus"].extend(amd_data)
                
        elif self.platform == "Linux":
            # Similar GPU detection for Linux
            nvidia_data = self._get_nvidia_gpu_info()
            if nvidia_data:
                gpu_data["gpus"].extend(nvidia_data)
                
        if not gpu_data["gpus"]:
            gpu_data["error"] = "No supported GPUs detected"
            
        return gpu_data
        
    def _get_nvidia_gpu_info(self) -> List[Dict[str, Any]]:
        """Get NVIDIA GPU information using nvidia-smi"""
        gpus = []
        try:
            # Run nvidia-smi command
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw", 
                 "--format=csv,noheader,nounits"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line:
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) >= 7:
                            gpus.append({
                                "vendor": "NVIDIA",
                                "index": int(parts[0]),
                                "name": parts[1],
                                "temperature": float(parts[2]) if parts[2] != '[N/A]' else 0,
                                "utilization": float(parts[3]) if parts[3] != '[N/A]' else 0,
                                "memory_used": float(parts[4]) if parts[4] != '[N/A]' else 0,
                                "memory_total": float(parts[5]) if parts[5] != '[N/A]' else 0,
                                "power": float(parts[6]) if parts[6] != '[N/A]' else 0
                            })
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
            
        return gpus
        
    def _get_intel_arc_info(self) -> List[Dict[str, Any]]:
        """Get Intel Arc GPU information"""
        gpus = []
        try:
            # Check if Intel GPU tools are available
            # This is a simplified example - real implementation would use Intel GPU tools
            import wmi
            c = wmi.WMI()
            
            for gpu in c.Win32_VideoController():
                if 'Intel' in gpu.Name and ('Arc' in gpu.Name or 'Xe' in gpu.Name):
                    gpus.append({
                        "vendor": "Intel",
                        "index": 0,
                        "name": gpu.Name,
                        "temperature": 0,  # Intel doesn't easily expose temperature
                        "utilization": 0,  # Would need Intel GPU tools
                        "memory_used": 0,
                        "memory_total": gpu.AdapterRAM / (1024**3) if gpu.AdapterRAM else 0,
                        "power": 0
                    })
        except:
            pass
            
        return gpus
        
    def _get_amd_gpu_info(self) -> List[Dict[str, Any]]:
        """Get AMD GPU information"""
        gpus = []
        # AMD GPU detection would go here
        # This would use rocm-smi on Linux or AMD tools on Windows
        return gpus


class GPUStatusWidget(QWidget):
    """GPU status monitoring widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.gpu_data = {}
        self.selected_gpu_index = 0
        
        self.setup_ui()
        self.setup_monitoring()
        
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        
        # GPU Selection
        selection_layout = QHBoxLayout()
        selection_layout.addWidget(QLabel("Select GPU:"))
        
        self.gpu_combo = QComboBox()
        self.gpu_combo.currentIndexChanged.connect(self.on_gpu_selected)
        selection_layout.addWidget(self.gpu_combo)
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_gpus)
        selection_layout.addWidget(self.refresh_btn)
        
        selection_layout.addStretch()
        layout.addLayout(selection_layout)
        
        # GPU Info Group
        info_group = QGroupBox("GPU Information")
        info_layout = QGridLayout(info_group)
        
        # Labels
        self.vendor_label = QLabel("Vendor: N/A")
        self.name_label = QLabel("Name: N/A")
        self.driver_label = QLabel("Driver: N/A")
        
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
        self.utilization_label = QLabel("0%")
        metrics_layout.addWidget(self.utilization_bar, 0, 1)
        metrics_layout.addWidget(self.utilization_label, 0, 2)
        
        # Memory Usage
        metrics_layout.addWidget(QLabel("Memory Usage:"), 1, 0)
        self.memory_bar = QProgressBar()
        self.memory_bar.setMaximum(100)
        self.memory_label = QLabel("0 MB / 0 MB")
        metrics_layout.addWidget(self.memory_bar, 1, 1)
        metrics_layout.addWidget(self.memory_label, 1, 2)
        
        # Temperature
        metrics_layout.addWidget(QLabel("Temperature:"), 2, 0)
        self.temp_bar = QProgressBar()
        self.temp_bar.setMaximum(100)
        self.temp_label = QLabel("0°C")
        metrics_layout.addWidget(self.temp_bar, 2, 1)
        metrics_layout.addWidget(self.temp_label, 2, 2)
        
        # Power Draw
        metrics_layout.addWidget(QLabel("Power Draw:"), 3, 0)
        self.power_bar = QProgressBar()
        self.power_bar.setMaximum(300)  # Max 300W for most GPUs
        self.power_label = QLabel("0W")
        metrics_layout.addWidget(self.power_bar, 3, 1)
        metrics_layout.addWidget(self.power_label, 3, 2)
        
        layout.addWidget(metrics_group)
        
        # GPU Capabilities Group
        caps_group = QGroupBox("GPU Capabilities")
        caps_layout = QVBoxLayout(caps_group)
        
        self.caps_text = QTextEdit()
        self.caps_text.setReadOnly(True)
        self.caps_text.setMaximumHeight(150)
        self.caps_text.setPlainText("Detecting GPU capabilities...")
        caps_layout.addWidget(self.caps_text)
        
        layout.addWidget(caps_group)
        
        layout.addStretch()
        
    def setup_monitoring(self):
        """Setup GPU monitoring thread"""
        self.monitor_thread = QThread()
        self.monitor_worker = GPUMonitorWorker()
        self.monitor_worker.moveToThread(self.monitor_thread)
        
        # Connect signals
        self.monitor_thread.started.connect(self.monitor_worker.start_monitoring)
        self.monitor_worker.gpu_data_ready.connect(self.update_gpu_data)
        self.monitor_worker.error_occurred.connect(self.handle_error)
        
    def start_monitoring(self):
        """Start GPU monitoring"""
        if not self.monitor_thread.isRunning():
            self.monitor_thread.start()
            
    def stop_monitoring(self):
        """Stop GPU monitoring"""
        if self.monitor_thread.isRunning():
            self.monitor_worker.stop_monitoring()
            self.monitor_thread.quit()
            self.monitor_thread.wait()
            
    def update_gpu_data(self, data: Dict[str, Any]):
        """Update GPU data from monitor"""
        self.gpu_data = data
        
        # Update GPU combo box
        current_text = self.gpu_combo.currentText()
        self.gpu_combo.clear()
        
        if data.get("gpus"):
            for i, gpu in enumerate(data["gpus"]):
                self.gpu_combo.addItem(f"{gpu['vendor']} - {gpu['name']}")
                
            # Try to restore previous selection
            index = self.gpu_combo.findText(current_text)
            if index >= 0:
                self.gpu_combo.setCurrentIndex(index)
            else:
                self.gpu_combo.setCurrentIndex(0)
                
            self.update_display()
        else:
            self.gpu_combo.addItem("No GPU detected")
            self.clear_display()
            
    def on_gpu_selected(self, index):
        """Handle GPU selection change"""
        self.selected_gpu_index = index
        self.update_display()
        
    def update_display(self):
        """Update the display with current GPU data"""
        if not self.gpu_data.get("gpus") or self.selected_gpu_index >= len(self.gpu_data["gpus"]):
            return
            
        gpu = self.gpu_data["gpus"][self.selected_gpu_index]
        
        # Update info labels
        self.vendor_label.setText(f"Vendor: {gpu['vendor']}")
        self.name_label.setText(f"Name: {gpu['name']}")
        self.driver_label.setText("Driver: Detecting...")
        
        # Update performance metrics
        utilization = gpu.get('utilization', 0)
        self.utilization_bar.setValue(int(utilization))
        self.utilization_label.setText(f"{utilization:.0f}%")
        self._set_bar_color(self.utilization_bar, utilization, 80, 95)
        
        # Memory
        memory_used = gpu.get('memory_used', 0)
        memory_total = gpu.get('memory_total', 1)
        memory_percent = (memory_used / memory_total * 100) if memory_total > 0 else 0
        self.memory_bar.setValue(int(memory_percent))
        self.memory_label.setText(f"{memory_used:.0f} MB / {memory_total:.0f} MB")
        self._set_bar_color(self.memory_bar, memory_percent, 80, 95)
        
        # Temperature
        temp = gpu.get('temperature', 0)
        self.temp_bar.setValue(int(temp))
        self.temp_label.setText(f"{temp:.0f}°C")
        self._set_bar_color(self.temp_bar, temp, 70, 85)
        
        # Power
        power = gpu.get('power', 0)
        self.power_bar.setValue(int(power))
        self.power_label.setText(f"{power:.0f}W")
        
        # Update capabilities
        self.update_capabilities(gpu)
        
    def update_capabilities(self, gpu: Dict[str, Any]):
        """Update GPU capabilities display"""
        caps_text = []
        
        if gpu['vendor'] == 'NVIDIA':
            caps_text.append("CUDA Support: Yes")
            caps_text.append("Tensor Cores: Detecting...")
            caps_text.append("Ray Tracing: Detecting...")
            caps_text.append("NVENC: Yes")
        elif gpu['vendor'] == 'Intel':
            caps_text.append("Intel Xe Architecture")
            caps_text.append("AV1 Encoding: Yes")
            caps_text.append("XeSS Support: Yes")
            caps_text.append("Ray Tracing: Hardware Accelerated")
        elif gpu['vendor'] == 'AMD':
            caps_text.append("ROCm Support: Detecting...")
            caps_text.append("Ray Accelerators: Detecting...")
            
        caps_text.append(f"\nCompute Units: Detecting...")
        caps_text.append(f"Max Clock: Detecting...")
        caps_text.append(f"Memory Bandwidth: Detecting...")
        
        self.caps_text.setPlainText('\n'.join(caps_text))
        
    def clear_display(self):
        """Clear all display fields"""
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
        
    def _set_bar_color(self, bar: QProgressBar, value: float, warning: float, critical: float):
        """Set progress bar color based on value thresholds"""
        if value >= critical:
            bar.setStyleSheet("QProgressBar::chunk { background-color: #dc3545; }")
        elif value >= warning:
            bar.setStyleSheet("QProgressBar::chunk { background-color: #ffc107; }")
        else:
            bar.setStyleSheet("QProgressBar::chunk { background-color: #28a745; }")
            
    def handle_error(self, error_msg: str):
        """Handle monitoring errors"""
        self.caps_text.append(f"\nError: {error_msg}")
        
    def refresh_gpus(self):
        """Manually refresh GPU list"""
        # Trigger a manual refresh
        pass