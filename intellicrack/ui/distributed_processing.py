"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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

import threading
import time
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from intellicrack.logger import logger

try:
    from PyQt6.QtCore import QObject, QThread, QTimer, pyqtSignal
    from PyQt6.QtWidgets import (
        QCheckBox,
        QComboBox,
        QDialog,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QProgressBar,
        QPushButton,
        QSpinBox,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )

    HAS_PYQT6 = True
except ImportError:
    logger.warning("PyQt6 not available for distributed processing UI")
    HAS_PYQT6 = False

    # Fallback base classes
    class QObject:
        pass

    class QThread:
        pass

    class QDialog:
        pass

    class QWidget:
        pass

    def pyqtSignal(*args):
        return None


class ProcessingStatus(Enum):
    """Status states for distributed processing tasks."""

    IDLE = "idle"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DistributedTask:
    """Represents a distributed processing task."""

    def __init__(self, task_id: str, task_type: str, parameters: Dict[str, Any]):
        """Initialize distributed task.

        Args:
            task_id: Unique identifier for the task
            task_type: Type of processing task (analysis, cracking, etc.)
            parameters: Task configuration parameters
        """
        self.task_id = task_id
        self.task_type = task_type
        self.parameters = parameters
        self.status = ProcessingStatus.QUEUED
        self.created_time = datetime.now()
        self.started_time: Optional[datetime] = None
        self.completed_time: Optional[datetime] = None
        self.progress = 0.0
        self.results: Optional[Dict[str, Any]] = None
        self.error_message: Optional[str] = None
        self.worker_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary representation."""
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "parameters": self.parameters,
            "status": self.status.value,
            "created_time": self.created_time.isoformat(),
            "started_time": self.started_time.isoformat() if self.started_time else None,
            "completed_time": self.completed_time.isoformat() if self.completed_time else None,
            "progress": self.progress,
            "results": self.results,
            "error_message": self.error_message,
            "worker_id": self.worker_id,
        }


class DistributedWorkerThread(QThread):
    """Worker thread for distributed processing tasks."""

    progress_updated = pyqtSignal(str, float) if HAS_PYQT6 else None
    task_completed = pyqtSignal(str, dict) if HAS_PYQT6 else None
    task_failed = pyqtSignal(str, str) if HAS_PYQT6 else None

    def __init__(self, worker_id: str, task_queue: List[DistributedTask]):
        """Initialize distributed worker thread.

        Args:
            worker_id: Unique identifier for this worker
            task_queue: Shared task queue to process
        """
        if HAS_PYQT6:
            super().__init__()
        self.worker_id = worker_id
        self.task_queue = task_queue
        self.current_task: Optional[DistributedTask] = None
        self.running = False
        self.queue_lock = threading.Lock()

    def run(self):
        """Main worker thread execution loop."""
        self.running = True
        logger.info(f"Distributed worker {self.worker_id} started")

        while self.running:
            task = self.get_next_task()
            if task:
                self.process_task(task)
            else:
                # No tasks available, wait before checking again
                time.sleep(1.0)

        logger.info(f"Distributed worker {self.worker_id} stopped")

    def get_next_task(self) -> Optional[DistributedTask]:
        """Get the next available task from the queue.

        Returns:
            Next task to process or None if queue is empty
        """
        with self.queue_lock:
            for task in self.task_queue:
                if task.status == ProcessingStatus.QUEUED:
                    task.status = ProcessingStatus.RUNNING
                    task.started_time = datetime.now()
                    task.worker_id = self.worker_id
                    return task
        return None

    def process_task(self, task: DistributedTask) -> None:
        """Process a distributed task.

        Args:
            task: Task to process
        """
        try:
            self.current_task = task
            logger.info(f"Worker {self.worker_id} processing task {task.task_id}")

            # Simulate different types of processing
            if task.task_type == "binary_analysis":
                results = self.process_binary_analysis(task)
            elif task.task_type == "password_cracking":
                results = self.process_password_cracking(task)
            elif task.task_type == "vulnerability_scan":
                results = self.process_vulnerability_scan(task)
            else:
                results = self.process_generic_task(task)

            # Mark task as completed
            task.status = ProcessingStatus.COMPLETED
            task.completed_time = datetime.now()
            task.results = results
            task.progress = 100.0

            if HAS_PYQT6 and self.task_completed:
                self.task_completed.emit(task.task_id, results)

            logger.info(f"Task {task.task_id} completed successfully")

        except Exception as e:
            logger.error(f"Task {task.task_id} failed: {e}")
            task.status = ProcessingStatus.FAILED
            task.completed_time = datetime.now()
            task.error_message = str(e)

            if HAS_PYQT6 and self.task_failed:
                self.task_failed.emit(task.task_id, str(e))

        finally:
            self.current_task = None

    def process_binary_analysis(self, task: DistributedTask) -> Dict[str, Any]:
        """Process binary analysis task.

        Args:
            task: Binary analysis task

        Returns:
            Analysis results
        """
        binary_path = task.parameters.get("binary_path")
        if not binary_path:
            raise ValueError("Binary path not specified")

        # Simulate analysis steps
        steps = [
            "Loading binary",
            "Analyzing sections",
            "Extracting strings",
            "Computing entropy",
            "Identifying functions",
            "Generating report",
        ]

        results = {
            "binary_path": binary_path,
            "analysis_steps": [],
            "sections": [],
            "strings_found": 0,
            "entropy_score": 0.0,
            "functions_identified": 0,
        }

        for i, step in enumerate(steps):
            if not self.running:
                raise Exception("Task cancelled")

            # Update progress
            progress = (i + 1) / len(steps) * 100
            task.progress = progress

            if HAS_PYQT6 and self.progress_updated:
                self.progress_updated.emit(task.task_id, progress)

            # Simulate processing time
            time.sleep(0.5)

            # Add step results
            results["analysis_steps"].append({"step": step, "completed": True, "timestamp": datetime.now().isoformat()})

        # Simulate final results
        results["sections"] = ["code", "data", "resources"]
        results["strings_found"] = 127
        results["entropy_score"] = 7.2
        results["functions_identified"] = 45

        return results

    def process_password_cracking(self, task: DistributedTask) -> Dict[str, Any]:
        """Process password cracking task.

        Args:
            task: Password cracking task

        Returns:
            Cracking results
        """
        hash_value = task.parameters.get("hash")
        wordlist = task.parameters.get("wordlist", "default")

        if not hash_value:
            raise ValueError("Hash value not specified")

        # Simulate cracking attempts
        total_attempts = task.parameters.get("max_attempts", 1000)

        results = {"hash": hash_value, "wordlist": wordlist, "attempts": 0, "found": False, "password": None, "time_elapsed": 0.0}

        start_time = time.time()

        for attempt in range(total_attempts):
            if not self.running:
                raise Exception("Task cancelled")

            # Update progress
            progress = (attempt + 1) / total_attempts * 100
            task.progress = progress

            if HAS_PYQT6 and self.progress_updated:
                self.progress_updated.emit(task.task_id, progress)

            # Simulate attempt
            time.sleep(0.01)
            results["attempts"] = attempt + 1

            # Simulate finding password at random point
            if attempt > 100 and attempt % 347 == 0:
                results["found"] = True
                results["password"] = f"password{attempt}"
                break

        results["time_elapsed"] = time.time() - start_time
        return results

    def process_vulnerability_scan(self, task: DistributedTask) -> Dict[str, Any]:
        """Process vulnerability scanning task.

        Args:
            task: Vulnerability scan task

        Returns:
            Scan results
        """
        target = task.parameters.get("target")
        scan_type = task.parameters.get("scan_type", "basic")

        if not target:
            raise ValueError("Target not specified")

        # Simulate vulnerability checks
        checks = [
            "Port scanning",
            "Service detection",
            "Version identification",
            "CVE database lookup",
            "Exploit validation",
            "Report generation",
        ]

        results = {"target": target, "scan_type": scan_type, "vulnerabilities": [], "ports_open": [], "services": [], "risk_level": "low"}

        for i, check in enumerate(checks):
            if not self.running:
                raise Exception("Task cancelled")

            # Update progress
            progress = (i + 1) / len(checks) * 100
            task.progress = progress

            if HAS_PYQT6 and self.progress_updated:
                self.progress_updated.emit(task.task_id, progress)

            # Simulate processing time
            time.sleep(0.3)

        # Simulate scan results
        results["ports_open"] = [80, 443, 22]
        results["services"] = ["HTTP", "HTTPS", "SSH"]
        results["vulnerabilities"] = [{"cve": "CVE-2023-1234", "severity": "medium"}, {"cve": "CVE-2023-5678", "severity": "low"}]
        results["risk_level"] = "medium"

        return results

    def process_generic_task(self, task: DistributedTask) -> Dict[str, Any]:
        """Process generic task type.

        Args:
            task: Generic task

        Returns:
            Processing results
        """
        # Simulate generic processing
        steps = task.parameters.get("steps", 10)

        results = {"task_type": task.task_type, "parameters": task.parameters, "processed_steps": 0, "status": "completed"}

        for step in range(steps):
            if not self.running:
                raise Exception("Task cancelled")

            # Update progress
            progress = (step + 1) / steps * 100
            task.progress = progress

            if HAS_PYQT6 and self.progress_updated:
                self.progress_updated.emit(task.task_id, progress)

            # Simulate processing
            time.sleep(0.2)
            results["processed_steps"] = step + 1

        return results

    def stop(self):
        """Stop the worker thread."""
        self.running = False


class DistributedProcessingDialog(QDialog):
    """Dialog for managing distributed processing tasks."""

    def __init__(self, parent=None):
        """Initialize distributed processing dialog."""
        if HAS_PYQT6:
            super().__init__(parent)
        self.setWindowTitle("Distributed Processing Manager")
        self.resize(800, 600)

        self.tasks: List[DistributedTask] = []
        self.workers: List[DistributedWorkerThread] = []
        self.task_counter = 0

        self.setup_ui()
        self.setup_timers()

    def setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)

        # Control panel
        control_group = QGroupBox("Control Panel")
        control_layout = QGridLayout(control_group)

        # Worker count
        control_layout.addWidget(QLabel("Workers:"), 0, 0)
        self.worker_count_spin = QSpinBox()
        self.worker_count_spin.setRange(1, 8)
        self.worker_count_spin.setValue(2)
        control_layout.addWidget(self.worker_count_spin, 0, 1)

        # Start/Stop buttons
        self.start_button = QPushButton("Start Workers")
        self.start_button.clicked.connect(self.start_workers)
        control_layout.addWidget(self.start_button, 0, 2)

        self.stop_button = QPushButton("Stop Workers")
        self.stop_button.clicked.connect(self.stop_workers)
        self.stop_button.setEnabled(False)
        control_layout.addWidget(self.stop_button, 0, 3)

        layout.addWidget(control_group)

        # Task management
        task_group = QGroupBox("Task Management")
        task_layout = QVBoxLayout(task_group)

        # Add task controls
        add_layout = QHBoxLayout()
        add_layout.addWidget(QLabel("Task Type:"))

        self.task_type_combo = QComboBox()
        self.task_type_combo.addItems(["binary_analysis", "password_cracking", "vulnerability_scan", "generic_task"])
        add_layout.addWidget(self.task_type_combo)

        self.add_task_button = QPushButton("Add Task")
        self.add_task_button.clicked.connect(self.add_sample_task)
        add_layout.addWidget(self.add_task_button)

        task_layout.addLayout(add_layout)
        layout.addWidget(task_group)

        # Task status display
        status_group = QGroupBox("Task Status")
        status_layout = QVBoxLayout(status_group)

        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        status_layout.addWidget(self.status_text)

        layout.addWidget(status_group)

        # Progress indicators
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout(progress_group)

        self.progress_bars: Dict[str, QProgressBar] = {}
        self.progress_layout = QVBoxLayout()
        progress_layout.addLayout(self.progress_layout)

        layout.addWidget(progress_group)

    def setup_timers(self):
        """Setup update timers."""
        if HAS_PYQT6:
            self.update_timer = QTimer()
            self.update_timer.timeout.connect(self.update_status)
            self.update_timer.start(1000)  # Update every second

    def start_workers(self):
        """Start distributed processing workers."""
        if self.workers:
            self.stop_workers()

        worker_count = self.worker_count_spin.value()
        logger.info(f"Starting {worker_count} distributed workers")

        for i in range(worker_count):
            worker_id = f"worker_{i + 1}"
            worker = DistributedWorkerThread(worker_id, self.tasks)

            if HAS_PYQT6:
                worker.progress_updated.connect(self.on_task_progress)
                worker.task_completed.connect(self.on_task_completed)
                worker.task_failed.connect(self.on_task_failed)
                worker.start()

            self.workers.append(worker)

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.update_status_text("Workers started")

    def stop_workers(self):
        """Stop all distributed processing workers."""
        logger.info("Stopping distributed workers")

        for worker in self.workers:
            worker.stop()
            if HAS_PYQT6:
                worker.wait(5000)  # Wait up to 5 seconds

        self.workers.clear()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.update_status_text("Workers stopped")

    def add_sample_task(self):
        """Add a sample task for testing."""
        self.task_counter += 1
        task_type = self.task_type_combo.currentText()
        task_id = f"task_{self.task_counter}"

        # Create sample parameters based on task type
        if task_type == "binary_analysis":
            parameters = {"binary_path": f"/path/to/sample_{self.task_counter}.exe"}
        elif task_type == "password_cracking":
            parameters = {"hash": f"hash_{self.task_counter}", "wordlist": "rockyou.txt"}
        elif task_type == "vulnerability_scan":
            parameters = {"target": f"192.168.1.{self.task_counter}", "scan_type": "basic"}
        else:
            parameters = {"steps": 5, "data": f"sample_data_{self.task_counter}"}

        task = DistributedTask(task_id, task_type, parameters)
        self.tasks.append(task)

        # Add progress bar
        if HAS_PYQT6:
            progress_bar = QProgressBar()
            progress_bar.setFormat(f"{task_id} - %p%")
            self.progress_layout.addWidget(progress_bar)
            self.progress_bars[task_id] = progress_bar

        self.update_status_text(f"Added task: {task_id} ({task_type})")
        logger.info(f"Added task {task_id} of type {task_type}")

    def on_task_progress(self, task_id: str, progress: float):
        """Handle task progress updates."""
        if task_id in self.progress_bars:
            self.progress_bars[task_id].setValue(int(progress))

    def on_task_completed(self, task_id: str, results: Dict[str, Any]):
        """Handle task completion."""
        self.update_status_text(f"Task {task_id} completed successfully")
        logger.info(f"Task {task_id} completed")

    def on_task_failed(self, task_id: str, error: str):
        """Handle task failure."""
        self.update_status_text(f"Task {task_id} failed: {error}")
        logger.error(f"Task {task_id} failed: {error}")

    def update_status(self):
        """Update task status display."""
        if not self.tasks:
            return

        status_counts = {}
        for task in self.tasks:
            status = task.status.value
            status_counts[status] = status_counts.get(status, 0) + 1

        status_summary = ", ".join([f"{status}: {count}" for status, count in status_counts.items()])
        self.update_status_text(f"Status summary - {status_summary}")

    def update_status_text(self, message: str):
        """Update status text display."""
        if HAS_PYQT6 and hasattr(self, "status_text"):
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.status_text.append(f"[{timestamp}] {message}")

    def closeEvent(self, event):
        """Handle dialog close event."""
        self.stop_workers()
        if HAS_PYQT6:
            super().closeEvent(event)


class DistributedProcessing:
    """Main distributed processing manager class."""

    def __init__(self):
        """Initialize distributed processing manager."""
        self.tasks: List[DistributedTask] = []
        self.workers: List[DistributedWorkerThread] = []
        self.dialog: Optional[DistributedProcessingDialog] = None

    def run_distributed_processing(self, main_app_instance=None):
        """Launch distributed processing interface.

        Args:
            main_app_instance: Main application instance (optional)
        """
        try:
            if not HAS_PYQT6:
                logger.warning("PyQt6 not available - distributed processing UI disabled")
                return

            logger.info("Launching distributed processing interface")

            if self.dialog is None:
                self.dialog = DistributedProcessingDialog(main_app_instance)

            self.dialog.show()
            self.dialog.raise_()
            self.dialog.activateWindow()

        except Exception as e:
            logger.error(f"Failed to launch distributed processing interface: {e}")
            raise

    def add_task(self, task_type: str, parameters: Dict[str, Any]) -> str:
        """Add a new distributed processing task.

        Args:
            task_type: Type of task to add
            parameters: Task configuration parameters

        Returns:
            Task ID of the added task
        """
        task_id = f"task_{len(self.tasks) + 1}_{int(time.time())}"
        task = DistributedTask(task_id, task_type, parameters)
        self.tasks.append(task)

        logger.info(f"Added distributed task {task_id} of type {task_type}")
        return task_id

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific task.

        Args:
            task_id: ID of task to check

        Returns:
            Task status information or None if not found
        """
        for task in self.tasks:
            if task.task_id == task_id:
                return task.to_dict()
        return None

    def get_all_tasks(self) -> List[Dict[str, Any]]:
        """Get status of all tasks.

        Returns:
            List of all task status information
        """
        return [task.to_dict() for task in self.tasks]

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a specific task.

        Args:
            task_id: ID of task to cancel

        Returns:
            True if task was cancelled, False if not found
        """
        for task in self.tasks:
            if task.task_id == task_id and task.status in [ProcessingStatus.QUEUED, ProcessingStatus.RUNNING]:
                task.status = ProcessingStatus.CANCELLED
                logger.info(f"Cancelled task {task_id}")
                return True
        return False
