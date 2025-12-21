"""
Comprehensive tests for distributed processing module.

This module contains production-ready tests for the distributed processing system
including task distribution, worker management, result aggregation, and real binary
analysis operations. Tests validate actual distributed processing logic with mocked
Qt UI components.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import hashlib
import os
import platform
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import capstone
import pefile
import pytest
import yara

from intellicrack.ui.distributed_processing import (
    BoundSignal,
    DistributedProcessing,
    DistributedProcessingDialog,
    DistributedTask,
    DistributedWorkerThread,
    HAS_PYQT6,
    ProcessingStatus,
    QDialog,
    QObject,
    QThread,
    QWidget,
    pyqtSignal,
)


def has_pyqt6() -> bool:
    """Check if PyQt6 is available."""
    try:
        from PyQt6.QtCore import QObject
        return True
    except ImportError:
        return False


class TestProcessingStatus:
    """Tests for ProcessingStatus enum."""

    def test_processing_status_enum_values(self) -> None:
        """ProcessingStatus enum contains all required status values."""
        assert ProcessingStatus.IDLE.value == "idle"
        assert ProcessingStatus.QUEUED.value == "queued"
        assert ProcessingStatus.RUNNING.value == "running"
        assert ProcessingStatus.COMPLETED.value == "completed"
        assert ProcessingStatus.FAILED.value == "failed"
        assert ProcessingStatus.CANCELLED.value == "cancelled"

    def test_processing_status_enum_membership(self) -> None:
        """All expected status values are members of ProcessingStatus enum."""
        expected_statuses = {"idle", "queued", "running", "completed", "failed", "cancelled"}
        actual_statuses = {status.value for status in ProcessingStatus}
        assert actual_statuses == expected_statuses

    def test_processing_status_uniqueness(self) -> None:
        """Each ProcessingStatus enum value is unique."""
        values = [status.value for status in ProcessingStatus]
        assert len(values) == len(set(values))


class TestDistributedTask:
    """Tests for DistributedTask class."""

    def test_distributed_task_initialization(self) -> None:
        """DistributedTask initializes with correct default values."""
        task_id = "test_task_001"
        task_type = "binary_analysis"
        parameters = {"binary_path": "/path/to/binary.exe"}

        task = DistributedTask(task_id, task_type, parameters)

        assert task.task_id == task_id
        assert task.task_type == task_type
        assert task.parameters == parameters
        assert task.status == ProcessingStatus.QUEUED
        assert isinstance(task.created_time, datetime)
        assert task.started_time is None
        assert task.completed_time is None
        assert task.progress == 0.0
        assert task.results is None
        assert task.error_message is None
        assert task.worker_id is None

    def test_distributed_task_to_dict(self) -> None:
        """DistributedTask.to_dict() returns complete dictionary representation."""
        task_id = "test_task_002"
        task_type = "password_cracking"
        parameters = {"hash": "abc123", "hash_type": "md5"}

        task = DistributedTask(task_id, task_type, parameters)
        task.status = ProcessingStatus.RUNNING
        task.started_time = datetime.now()
        task.progress = 45.5
        task.worker_id = "worker_1"

        task_dict = task.to_dict()

        assert task_dict["task_id"] == task_id
        assert task_dict["task_type"] == task_type
        assert task_dict["parameters"] == parameters
        assert task_dict["status"] == ProcessingStatus.RUNNING.value
        assert isinstance(task_dict["created_time"], str)
        assert isinstance(task_dict["started_time"], str)
        assert task_dict["completed_time"] is None
        assert task_dict["progress"] == 45.5
        assert task_dict["results"] is None
        assert task_dict["error_message"] is None
        assert task_dict["worker_id"] == "worker_1"

    def test_distributed_task_to_dict_with_results(self) -> None:
        """DistributedTask.to_dict() includes results and completion data."""
        task = DistributedTask("task_003", "vulnerability_scan", {"target": "app.exe"})
        task.status = ProcessingStatus.COMPLETED
        task.completed_time = datetime.now()
        task.results = {"vulnerabilities": 5, "protections": 3}

        task_dict = task.to_dict()

        assert task_dict["status"] == ProcessingStatus.COMPLETED.value
        assert isinstance(task_dict["completed_time"], str)
        assert task_dict["results"] == {"vulnerabilities": 5, "protections": 3}

    def test_distributed_task_to_dict_with_error(self) -> None:
        """DistributedTask.to_dict() includes error message for failed tasks."""
        task = DistributedTask("task_004", "license_analysis", {})
        task.status = ProcessingStatus.FAILED
        task.error_message = "File not found"
        task.completed_time = datetime.now()

        task_dict = task.to_dict()

        assert task_dict["status"] == ProcessingStatus.FAILED.value
        assert task_dict["error_message"] == "File not found"


class TestFallbackQObject:
    """Tests for fallback QObject implementation when PyQt6 unavailable."""

    def test_qobject_fallback_initialization(self) -> None:
        """Fallback QObject initializes with empty signals and slots."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        obj = QObject()
        assert obj._signals == {}
        assert obj._slots == {}
        assert obj._parent is None
        assert obj._children == []
        assert obj._properties == {}

    def test_qobject_fallback_parent_child_hierarchy(self) -> None:
        """Fallback QObject manages parent-child hierarchy correctly."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        parent = QObject()
        child = QObject()

        child.setParent(parent)
        assert child.parent() == parent
        assert child in parent.children()

    def test_qobject_fallback_property_management(self) -> None:
        """Fallback QObject stores and retrieves properties correctly."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        obj = QObject()
        obj.setProperty("test_prop", "test_value")
        assert obj.property("test_prop") == "test_value"

    def test_qobject_fallback_delete_later(self) -> None:
        """Fallback QObject.deleteLater() cleans up hierarchy."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        parent = QObject()
        child = QObject()
        child.setParent(parent)

        child.deleteLater()
        assert child not in parent.children()
        assert len(child.children()) == 0


class TestFallbackQThread:
    """Tests for fallback QThread implementation when PyQt6 unavailable."""

    def test_qthread_fallback_initialization(self) -> None:
        """Fallback QThread initializes as daemon thread."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        thread = QThread()
        assert thread.daemon
        assert not thread._running
        assert not thread._stop_event.is_set()

    def test_qthread_fallback_start_stop(self) -> None:
        """Fallback QThread starts and stops correctly."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        class TestThread(QThread):
            def run(self) -> None:
                while self._running and not self._stop_event.is_set():
                    time.sleep(0.1)

        thread = TestThread()
        thread.start()
        assert thread._running
        time.sleep(0.2)
        assert thread.isRunning()

        thread.quit()
        thread.join(timeout=1.0)
        assert not thread._running

    def test_qthread_fallback_interruption(self) -> None:
        """Fallback QThread handles interruption requests."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        thread = QThread()
        assert not thread.isInterruptionRequested()

        thread.requestInterruption()
        assert thread.isInterruptionRequested()


class TestFallbackPyqtSignal:
    """Tests for fallback pyqtSignal implementation when PyQt6 unavailable."""

    def test_pyqt_signal_fallback_initialization(self) -> None:
        """Fallback pyqtSignal initializes with empty slots."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        signal = pyqtSignal(str, int)
        assert signal.types == (str, int)
        assert signal.slots == []
        assert not signal._blocked

    def test_pyqt_signal_fallback_connect_disconnect(self) -> None:
        """Fallback pyqtSignal connects and disconnects slots."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        signal = pyqtSignal(str)
        slot_called = []

        def test_slot(value: str) -> None:
            slot_called.append(value)

        signal.connect(test_slot)
        assert test_slot in signal.slots

        signal.emit("test_value")
        assert slot_called == ["test_value"]

        signal.disconnect(test_slot)
        assert test_slot not in signal.slots

    def test_pyqt_signal_fallback_emit(self) -> None:
        """Fallback pyqtSignal emits to all connected slots."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        signal = pyqtSignal(int)
        results = []

        def slot1(value: int) -> None:
            results.append(value * 2)

        def slot2(value: int) -> None:
            results.append(value * 3)

        signal.connect(slot1)
        signal.connect(slot2)
        signal.emit(5)

        assert sorted(results) == [10, 15]

    def test_pyqt_signal_fallback_block_signals(self) -> None:
        """Fallback pyqtSignal blocks emission when requested."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        signal = pyqtSignal(str)
        slot_called = []

        signal.connect(lambda x: slot_called.append(x))
        signal.blockSignals(True)
        signal.emit("blocked")
        assert not slot_called

        signal.blockSignals(False)
        signal.emit("unblocked")
        assert slot_called == ["unblocked"]


class TestBoundSignal:
    """Tests for BoundSignal class."""

    def test_bound_signal_initialization(self) -> None:
        """BoundSignal initializes with signal and instance."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        signal = pyqtSignal(int)
        instance = QObject()
        bound = BoundSignal(signal, instance)

        assert bound.signal == signal
        assert bound.instance == instance
        assert bound.slots == []

    def test_bound_signal_connect_emit(self) -> None:
        """BoundSignal connects slots and emits correctly."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        signal = pyqtSignal(str)
        instance = QObject()
        bound = BoundSignal(signal, instance)

        received = []
        bound.connect(lambda x: received.append(x))
        bound.emit("test_message")

        assert received == ["test_message"]


class TestDistributedWorkerThread:
    """Tests for DistributedWorkerThread class."""

    @pytest.fixture
    def temp_binary(self, tmp_path: Path) -> Path:
        """Create a temporary test binary file."""
        binary_path = tmp_path / "test_binary.exe"
        with open(binary_path, "wb") as f:
            f.write(b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00")
            f.write(b"\x00" * 64)
            f.write(b"PE\x00\x00")
            f.write(b"\x64\x86" + b"\x00" * 18)
            f.write(b"\x0b\x02" + b"\x00" * 238)
            f.write(b"test_string_data" * 50)
            f.write(os.urandom(512))
        return binary_path

    @pytest.fixture
    def task_queue(self) -> list[DistributedTask]:
        """Create an empty task queue."""
        return []

    @pytest.fixture
    def worker(self, task_queue: list[DistributedTask]) -> DistributedWorkerThread:
        """Create a worker thread instance."""
        return DistributedWorkerThread("test_worker", task_queue)

    def test_worker_initialization(self, worker: DistributedWorkerThread, task_queue: list[DistributedTask]) -> None:
        """DistributedWorkerThread initializes with correct configuration."""
        assert worker.worker_id == "test_worker"
        assert worker.task_queue is task_queue
        assert worker.current_task is None
        assert not worker.running
        assert isinstance(worker.queue_lock, type(threading.Lock()))

    def test_worker_get_next_task_empty_queue(self, worker: DistributedWorkerThread) -> None:
        """Worker returns None when queue is empty."""
        task = worker.get_next_task()
        assert task is None

    def test_worker_get_next_task_queued_task(self, worker: DistributedWorkerThread, task_queue: list[DistributedTask]) -> None:
        """Worker retrieves and marks queued task as running."""
        test_task = DistributedTask("task_1", "binary_analysis", {})
        task_queue.append(test_task)

        retrieved_task = worker.get_next_task()

        assert retrieved_task is test_task
        assert retrieved_task.status == ProcessingStatus.RUNNING
        assert retrieved_task.worker_id == "test_worker"
        assert isinstance(retrieved_task.started_time, datetime)

    def test_worker_get_next_task_skips_running_tasks(self, worker: DistributedWorkerThread, task_queue: list[DistributedTask]) -> None:
        """Worker skips tasks already in RUNNING status."""
        running_task = DistributedTask("task_1", "binary_analysis", {})
        running_task.status = ProcessingStatus.RUNNING
        queued_task = DistributedTask("task_2", "password_cracking", {})

        task_queue.append(running_task)
        task_queue.append(queued_task)

        retrieved_task = worker.get_next_task()

        assert retrieved_task is queued_task
        assert retrieved_task.status == ProcessingStatus.RUNNING

    def test_worker_calculate_entropy(self, worker: DistributedWorkerThread) -> None:
        """Worker calculates Shannon entropy correctly."""
        uniform_data = bytes([0] * 256)
        entropy_uniform = worker._calculate_entropy(uniform_data)
        assert entropy_uniform == 0.0

        random_data = os.urandom(1024)
        entropy_random = worker._calculate_entropy(random_data)
        assert 6.0 <= entropy_random <= 8.0

        empty_data = b""
        entropy_empty = worker._calculate_entropy(empty_data)
        assert entropy_empty == 0.0

    def test_worker_extract_strings(self, worker: DistributedWorkerThread, temp_binary: Path) -> None:
        """Worker extracts ASCII strings from binary correctly."""
        strings = worker._extract_strings(str(temp_binary))

        assert len(strings) > 0
        assert any("test_string_data" in s for s in strings)
        assert all(len(s) >= 4 for s in strings)

    def test_worker_extract_strings_min_length(self, worker: DistributedWorkerThread, temp_binary: Path) -> None:
        """Worker respects minimum string length parameter."""
        strings_min4 = worker._extract_strings(str(temp_binary), min_length=4)
        strings_min10 = worker._extract_strings(str(temp_binary), min_length=10)

        assert all(len(s) >= 4 for s in strings_min4)
        assert all(len(s) >= 10 for s in strings_min10)
        assert len(strings_min10) <= len(strings_min4)

    def test_worker_identify_functions(self, worker: DistributedWorkerThread, temp_binary: Path) -> None:
        """Worker identifies functions using Capstone disassembler."""
        functions = worker._identify_functions(str(temp_binary))

        assert isinstance(functions, list)
        for func in functions:
            assert "address" in func
            assert "instruction" in func
            assert "type" in func
            assert func["type"] in ["prologue", "call"]

    def test_worker_compute_entropy_map(self, worker: DistributedWorkerThread, temp_binary: Path) -> None:
        """Worker computes entropy map with block offsets."""
        entropy_map = worker._compute_entropy_map(str(temp_binary), block_size=256)

        assert isinstance(entropy_map, dict)
        assert len(entropy_map) > 0

        for offset, entropy in entropy_map.items():
            assert offset.startswith("0x")
            assert isinstance(entropy, float)
            assert 0.0 <= entropy <= 8.0

    def test_worker_process_binary_analysis(self, worker: DistributedWorkerThread, temp_binary: Path) -> None:
        """Worker processes binary analysis task with real PE parsing."""
        task = DistributedTask("bin_task_1", "binary_analysis", {"binary_path": str(temp_binary)})

        results = worker.process_binary_analysis(task)

        assert results["binary_path"] == str(temp_binary)
        assert "file_type" in results
        assert "strings_found" in results
        assert len(results["strings_found"]) > 0
        assert "entropy_map" in results
        assert len(results["entropy_map"]) > 0
        assert "functions_identified" in results
        assert results["analysis_complete"] is True

    def test_worker_process_binary_analysis_creates_missing_binary(self, worker: DistributedWorkerThread, tmp_path: Path) -> None:
        """Worker creates minimal PE binary if file missing."""
        binary_path = tmp_path / "missing.exe"
        task = DistributedTask("bin_task_2", "binary_analysis", {"binary_path": str(binary_path)})

        results = worker.process_binary_analysis(task)

        assert os.path.exists(binary_path)
        assert results["binary_path"] == str(binary_path)

    def test_worker_generate_common_passwords(self, worker: DistributedWorkerThread) -> None:
        """Worker generates comprehensive password wordlist."""
        passwords = worker._generate_common_passwords()

        assert len(passwords) > 100
        assert "password" in passwords
        assert "password123" in passwords
        assert "admin" in passwords
        assert "qwerty" in passwords

    def test_worker_check_password(self, worker: DistributedWorkerThread) -> None:
        """Worker checks password hash correctly."""
        test_password = "testpass123"
        # lgtm[py/weak-sensitive-data-hashing] Test fixture generating hash for password cracking test
        correct_hash = hashlib.sha256(test_password.encode()).hexdigest()
        wrong_hash = hashlib.sha256(b"wrongpass").hexdigest()

        password, matches = worker._check_password(test_password, correct_hash, hashlib.sha256)
        assert password == test_password
        assert matches is True

        password, matches = worker._check_password(test_password, wrong_hash, hashlib.sha256)
        assert password == test_password
        assert matches is False

    def test_worker_process_password_cracking(self, worker: DistributedWorkerThread) -> None:
        """Worker processes password cracking task with real hash checking."""
        test_password = "password123"
        # lgtm[py/weak-sensitive-data-hashing] Test fixture generating MD5 hash for password cracking test
        test_hash = hashlib.md5(test_password.encode()).hexdigest()

        task = DistributedTask(
            "crack_task_1",
            "password_cracking",
            {"hash": test_hash, "hash_type": "md5", "max_attempts": 1000}
        )

        results = worker.process_password_cracking(task)

        assert results["hash"] == test_hash
        assert results["hash_type"] == "md5"
        assert results["attempts"] > 0
        assert "time_elapsed" in results
        assert results["time_elapsed"] >= 0

    def test_worker_process_password_cracking_generates_test_hash(self, worker: DistributedWorkerThread) -> None:
        """Worker generates test hash when none provided."""
        task = DistributedTask("crack_task_2", "password_cracking", {"hash_type": "sha256"})

        results = worker.process_password_cracking(task)

        assert len(results["hash"]) == 64
        assert results["hash_type"] == "sha256"

    def test_worker_scan_protections(self, worker: DistributedWorkerThread, tmp_path: Path) -> None:
        """Worker scans for protection mechanisms in binary."""
        binary_path = tmp_path / "protected.exe"
        with open(binary_path, "wb") as f:
            f.write(b"MZ" + os.urandom(1000))
            f.write(b"VMProtect")
            f.write(os.urandom(500))
            f.write(b"Themida")
            f.write(os.urandom(1000))

        protections = worker._scan_protections(str(binary_path))

        assert len(protections) >= 2
        protection_names = [p["name"] for p in protections]
        assert any("VMProtect" in name for name in protection_names)
        assert any("Themida" in name for name in protection_names)

    def test_worker_identify_weak_points(self, worker: DistributedWorkerThread, tmp_path: Path) -> None:
        """Worker identifies weak points in binary protection."""
        binary_path = tmp_path / "weak.exe"
        weak_points = worker._identify_weak_points(str(binary_path), [])

        assert len(weak_points) > 0
        assert any(wp["type"] == "unpacked_code" for wp in weak_points)
        assert any(wp["type"] == "no_anti_debug" for wp in weak_points)

    def test_worker_check_vulnerabilities_with_yara(self, worker: DistributedWorkerThread, tmp_path: Path) -> None:
        """Worker checks vulnerabilities using YARA rules."""
        binary_path = tmp_path / "vuln.exe"
        with open(binary_path, "wb") as f:
            f.write(b"strcmp" * 10)
            f.write(os.urandom(100))

        vulnerabilities = worker._check_vulnerabilities(str(binary_path))

        assert isinstance(vulnerabilities, list)

    def test_worker_analyze_bypass_techniques(self, worker: DistributedWorkerThread) -> None:
        """Worker analyzes applicable bypass techniques."""
        protections = [
            {"name": "UPX", "type": "packer"},
            {"name": "Anti-Debug", "type": "anti-debug"}
        ]
        weak_points = [
            {"type": "unpacked_code", "severity": "high"}
        ]

        techniques = worker._analyze_bypass_techniques(protections, weak_points)

        assert len(techniques) > 0
        assert any("Unpacking" in t["technique"] for t in techniques)
        assert any("Direct Patching" in t["technique"] for t in techniques)

    def test_worker_assess_risk(self, worker: DistributedWorkerThread) -> None:
        """Worker assesses risk based on protections and vulnerabilities."""
        protections = [{"name": "VMProtect", "type": "virtualizer"}]
        vulnerabilities = [{"severity": "high"}, {"severity": "medium"}]
        weak_points = [{"severity": "high"}]

        risk = worker._assess_risk(protections, vulnerabilities, weak_points)

        assert "score" in risk
        assert "level" in risk
        assert risk["level"] in ["critical", "high", "medium", "low"]
        assert risk["protections_count"] == 1
        assert risk["vulnerabilities_count"] == 2
        assert risk["weak_points_count"] == 1

    def test_worker_generate_recommendations(self, worker: DistributedWorkerThread) -> None:
        """Worker generates security recommendations based on risk."""
        high_risk = {"level": "critical", "score": 80}
        recommendations_high = worker._generate_recommendations(high_risk)
        assert len(recommendations_high) >= 4

        low_risk = {"level": "low", "score": 20}
        recommendations_low = worker._generate_recommendations(low_risk)
        assert len(recommendations_low) >= 2

    def test_worker_process_vulnerability_scan(self, worker: DistributedWorkerThread, temp_binary: Path) -> None:
        """Worker processes complete vulnerability scan."""
        task = DistributedTask(
            "vuln_task_1",
            "vulnerability_scan",
            {"target": str(temp_binary), "scan_type": "license_protection"}
        )

        results = worker.process_vulnerability_scan(task)

        assert results["target"] == str(temp_binary)
        assert results["scan_type"] == "license_protection"
        assert "protection_mechanisms" in results
        assert "weak_points" in results
        assert "vulnerabilities" in results
        assert "bypass_techniques" in results
        assert "risk_assessment" in results
        assert "recommendations" in results

    def test_worker_analyze_validation_methods(self, worker: DistributedWorkerThread, tmp_path: Path) -> None:
        """Worker analyzes license validation methods."""
        binary_path = tmp_path / "licensed.exe"
        with open(binary_path, "wb") as f:
            f.write(b"http" * 10)
            f.write(b"registry" * 5)
            f.write(b"trial" * 8)

        methods = worker._analyze_validation_methods(str(binary_path))

        assert len(methods) > 0
        method_types = [m["type"] for m in methods]
        assert "online" in method_types
        assert "offline" in method_types
        assert "time" in method_types

    def test_worker_identify_key_algorithms(self, worker: DistributedWorkerThread, tmp_path: Path) -> None:
        """Worker identifies cryptographic algorithms in binary."""
        binary_path = tmp_path / "crypto.exe"
        with open(binary_path, "wb") as f:
            f.write(b"RSA" * 5)
            f.write(b"AES" * 5)
            f.write(b"SHA256" * 5)

        algorithms = worker._identify_key_algorithms(str(binary_path))

        assert len(algorithms) > 0
        assert "RSA" in algorithms or "AES" in algorithms

    def test_worker_determine_license_type(self, worker: DistributedWorkerThread) -> None:
        """Worker determines license protection type correctly."""
        methods_online = [{"type": "online"}]
        assert worker._determine_license_type(methods_online, []) == "cloud_based"

        methods_hardware = [{"type": "hardware"}]
        assert worker._determine_license_type(methods_hardware, []) == "hardware_locked"

        methods_trial = [{"type": "time"}]
        assert worker._determine_license_type(methods_trial, []) == "trial_based"

        methods_none = []
        algorithms = ["RSA"]
        assert worker._determine_license_type(methods_none, algorithms) == "key_based"

    def test_worker_develop_bypass_strategies(self, worker: DistributedWorkerThread) -> None:
        """Worker develops appropriate bypass strategies."""
        strategies = worker._develop_bypass_strategies("cloud_based", [])
        assert len(strategies) > 0
        assert any("Server Emulation" in s["method"] for s in strategies)

        strategies = worker._develop_bypass_strategies("hardware_locked", [])
        assert any("Hardware Spoofing" in s["method"] for s in strategies)

        strategies = worker._develop_bypass_strategies("trial_based", [])
        assert any("Trial Reset" in s["method"] for s in strategies)

    def test_worker_calculate_confidence(self, worker: DistributedWorkerThread) -> None:
        """Worker calculates analysis confidence score correctly."""
        results_high = {
            "license_type": "cloud_based",
            "validation_methods": [{"type": "online"}, {"type": "hardware"}],
            "key_algorithms": ["RSA", "AES"],
            "bypass_strategies": [{"method": "test"}] * 5
        }
        confidence = worker._calculate_confidence(results_high)
        assert 0.5 <= confidence <= 1.0

        results_low = {
            "license_type": "unknown",
            "validation_methods": [],
            "key_algorithms": [],
            "bypass_strategies": []
        }
        confidence = worker._calculate_confidence(results_low)
        assert confidence < 0.3

    def test_worker_process_license_analysis(self, worker: DistributedWorkerThread, temp_binary: Path) -> None:
        """Worker processes complete license analysis task."""
        task = DistributedTask(
            "license_task_1",
            "license_analysis",
            {"target": str(temp_binary), "depth": "standard"}
        )

        results = worker.process_license_analysis(task)

        assert results["target"] == str(temp_binary)
        assert results["analysis_depth"] == "standard"
        assert "license_type" in results
        assert "validation_methods" in results
        assert "key_algorithms" in results
        assert "bypass_strategies" in results
        assert "confidence" in results
        assert 0.0 <= results["confidence"] <= 1.0

    def test_worker_process_generic_task_analyze(self, worker: DistributedWorkerThread, temp_binary: Path) -> None:
        """Worker processes generic analyze task."""
        task = DistributedTask(
            "generic_task_1",
            "generic_task",
            {"operation": "analyze", "target": str(temp_binary)}
        )

        results = worker.process_generic_task(task)

        assert results["operation"] == "analyze"
        assert results["target"] == str(temp_binary)
        assert results["processed_data"]["file_exists"] is True
        assert results["status"] == "completed"

    def test_worker_process_generic_task_process(self, worker: DistributedWorkerThread) -> None:
        """Worker processes generic process task."""
        task = DistributedTask(
            "generic_task_2",
            "generic_task",
            {"operation": "process", "data_size": 5000}
        )

        results = worker.process_generic_task(task)

        assert results["operation"] == "process"
        assert results["processed_data"]["bytes_processed"] == 5000
        assert results["processed_data"]["chunks"] == 5000 // 256

    def test_worker_process_task_success(self, worker: DistributedWorkerThread) -> None:
        """Worker processes task successfully and updates status."""
        task = DistributedTask("proc_task_1", "generic_task", {"operation": "analyze"})

        worker.process_task(task)

        assert task.status == ProcessingStatus.COMPLETED
        assert task.completed_time is not None
        assert task.results is not None
        assert task.progress == 100.0
        assert task.error_message is None

    def test_worker_process_task_failure(self, worker: DistributedWorkerThread) -> None:
        """Worker handles task processing failure correctly."""
        task = DistributedTask("proc_task_2", "invalid_task_type", {})

        with patch.object(worker, 'process_generic_task', side_effect=Exception("Test error")):
            worker.process_task(task)

        assert task.status == ProcessingStatus.FAILED
        assert task.completed_time is not None
        assert task.error_message == "Test error"

    def test_worker_update_progress(self, worker: DistributedWorkerThread) -> None:
        """Worker updates task progress correctly."""
        task = DistributedTask("progress_task", "binary_analysis", {})

        worker._update_progress(task, 50.0, "Processing")
        assert task.progress == 50.0

        worker._update_progress(task, 75.5, "Almost done")
        assert task.progress == 75.5

    def test_worker_update_progress_cancelled(self, worker: DistributedWorkerThread) -> None:
        """Worker raises exception when updating cancelled task."""
        task = DistributedTask("cancelled_task", "binary_analysis", {})
        worker.running = False

        with pytest.raises(Exception, match="Task cancelled"):
            worker._update_progress(task, 50.0, "Processing")

    def test_worker_stop(self, worker: DistributedWorkerThread) -> None:
        """Worker stops execution when stop() called."""
        worker.running = True
        worker.stop()
        assert not worker.running


class TestDistributedProcessingDialog:
    """Tests for DistributedProcessingDialog class."""

    @pytest.fixture
    def dialog(self) -> DistributedProcessingDialog:
        """Create dialog instance."""
        return DistributedProcessingDialog()

    def test_dialog_initialization(self, dialog: DistributedProcessingDialog) -> None:
        """DistributedProcessingDialog initializes with correct defaults."""
        assert dialog.tasks == []
        assert dialog.workers == []
        assert dialog.task_counter == 0

    @pytest.mark.skipif(not has_pyqt6(), reason="PyQt6 not available")
    def test_dialog_start_workers_pyqt6(self, dialog: DistributedProcessingDialog) -> None:
        """Dialog starts workers correctly with PyQt6."""
        dialog.worker_count_spin.setValue(3)
        dialog.start_workers()

        assert len(dialog.workers) == 3
        assert all(w.worker_id == f"worker_{i+1}" for i, w in enumerate(dialog.workers))
        assert not dialog.start_button.isEnabled()
        assert dialog.stop_button.isEnabled()

        dialog.stop_workers()

    def test_dialog_start_workers_fallback(self, dialog: DistributedProcessingDialog) -> None:
        """Dialog starts workers correctly without PyQt6."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        dialog.worker_count_spin._value = 2
        dialog.start_workers()

        assert len(dialog.workers) == 2

    def test_dialog_stop_workers(self, dialog: DistributedProcessingDialog) -> None:
        """Dialog stops all workers correctly."""
        dialog.worker_count_spin._value = 2
        dialog.start_workers()
        assert len(dialog.workers) > 0

        dialog.stop_workers()
        assert len(dialog.workers) == 0

    def test_dialog_add_sample_task_binary_analysis(self, dialog: DistributedProcessingDialog) -> None:
        """Dialog adds binary analysis task with correct parameters."""
        if HAS_PYQT6:
            dialog.task_type_combo.setCurrentText("binary_analysis")
        else:
            dialog.task_type_combo._current = "binary_analysis"

        dialog.add_sample_task()

        assert len(dialog.tasks) == 1
        task = dialog.tasks[0]
        assert task.task_type == "binary_analysis"
        assert "binary_path" in task.parameters

    def test_dialog_add_sample_task_password_cracking(self, dialog: DistributedProcessingDialog) -> None:
        """Dialog adds password cracking task with correct parameters."""
        if HAS_PYQT6:
            dialog.task_type_combo.setCurrentText("password_cracking")
        else:
            dialog.task_type_combo._current = "password_cracking"

        dialog.add_sample_task()

        assert len(dialog.tasks) == 1
        task = dialog.tasks[0]
        assert task.task_type == "password_cracking"
        assert "hash" in task.parameters
        assert "hash_type" in task.parameters
        assert len(task.parameters["hash"]) == 64

    def test_dialog_add_sample_task_vulnerability_scan(self, dialog: DistributedProcessingDialog) -> None:
        """Dialog adds vulnerability scan task with correct parameters."""
        if HAS_PYQT6:
            dialog.task_type_combo.setCurrentText("vulnerability_scan")
        else:
            dialog.task_type_combo._current = "vulnerability_scan"

        dialog.add_sample_task()

        assert len(dialog.tasks) == 1
        task = dialog.tasks[0]
        assert task.task_type == "vulnerability_scan"
        assert "target" in task.parameters
        assert "scan_type" in task.parameters

    def test_dialog_add_sample_task_license_analysis(self, dialog: DistributedProcessingDialog) -> None:
        """Dialog adds license analysis task with correct parameters."""
        if HAS_PYQT6:
            dialog.task_type_combo.setCurrentText("license_analysis")
        else:
            dialog.task_type_combo._current = "license_analysis"

        dialog.add_sample_task()

        assert len(dialog.tasks) == 1
        task = dialog.tasks[0]
        assert task.task_type == "license_analysis"
        assert "target" in task.parameters
        assert "depth" in task.parameters

    def test_dialog_add_multiple_tasks(self, dialog: DistributedProcessingDialog) -> None:
        """Dialog tracks multiple tasks correctly."""
        for _ in range(5):
            dialog.add_sample_task()

        assert len(dialog.tasks) == 5
        assert dialog.task_counter == 5

    def test_dialog_on_task_progress(self, dialog: DistributedProcessingDialog) -> None:
        """Dialog handles task progress updates."""
        dialog.add_sample_task()
        if HAS_PYQT6:
            task_id = dialog.tasks[0].task_id

            dialog.on_task_progress(task_id, 50.0)
            assert dialog.progress_bars[task_id].value() == 50

    def test_dialog_on_task_completed(self, dialog: DistributedProcessingDialog) -> None:
        """Dialog handles task completion."""
        dialog.add_sample_task()
        task_id = dialog.tasks[0].task_id
        results = {"status": "success"}

        dialog.on_task_completed(task_id, results)

    def test_dialog_on_task_failed(self, dialog: DistributedProcessingDialog) -> None:
        """Dialog handles task failure."""
        dialog.add_sample_task()
        task_id = dialog.tasks[0].task_id

        dialog.on_task_failed(task_id, "Test error")

    def test_dialog_update_status(self, dialog: DistributedProcessingDialog) -> None:
        """Dialog updates status display correctly."""
        dialog.add_sample_task()
        dialog.add_sample_task()
        dialog.tasks[0].status = ProcessingStatus.COMPLETED
        dialog.tasks[1].status = ProcessingStatus.RUNNING

        dialog.update_status()

    def test_dialog_update_status_text(self, dialog: DistributedProcessingDialog) -> None:
        """Dialog updates status text with timestamp."""
        dialog.update_status_text("Test message")


class TestDistributedProcessing:
    """Tests for DistributedProcessing manager class."""

    @pytest.fixture
    def manager(self) -> DistributedProcessing:
        """Create DistributedProcessing manager instance."""
        return DistributedProcessing()

    def test_manager_initialization(self, manager: DistributedProcessing) -> None:
        """DistributedProcessing initializes with empty tasks and workers."""
        assert manager.tasks == []
        assert manager.workers == []
        assert manager.dialog is None

    def test_manager_add_task(self, manager: DistributedProcessing) -> None:
        """Manager adds task and returns task ID."""
        task_id = manager.add_task("binary_analysis", {"binary_path": "/test.exe"})

        assert isinstance(task_id, str)
        assert len(manager.tasks) == 1
        assert manager.tasks[0].task_id == task_id
        assert manager.tasks[0].task_type == "binary_analysis"

    def test_manager_add_multiple_tasks(self, manager: DistributedProcessing) -> None:
        """Manager handles multiple task additions."""
        task_id1 = manager.add_task("binary_analysis", {})
        task_id2 = manager.add_task("password_cracking", {})
        task_id3 = manager.add_task("vulnerability_scan", {})

        assert len(manager.tasks) == 3
        assert task_id1 != task_id2 != task_id3

    def test_manager_get_task_status(self, manager: DistributedProcessing) -> None:
        """Manager retrieves task status by ID."""
        task_id = manager.add_task("license_analysis", {"target": "app.exe"})

        status = manager.get_task_status(task_id)

        assert status is not None
        assert status["task_id"] == task_id
        assert status["task_type"] == "license_analysis"
        assert status["status"] == ProcessingStatus.QUEUED.value

    def test_manager_get_task_status_not_found(self, manager: DistributedProcessing) -> None:
        """Manager returns None for non-existent task ID."""
        status = manager.get_task_status("nonexistent_task")
        assert status is None

    def test_manager_get_all_tasks(self, manager: DistributedProcessing) -> None:
        """Manager retrieves all task statuses."""
        manager.add_task("binary_analysis", {})
        manager.add_task("password_cracking", {})

        all_tasks = manager.get_all_tasks()

        assert len(all_tasks) == 2
        assert all(isinstance(task, dict) for task in all_tasks)
        assert all("task_id" in task for task in all_tasks)

    def test_manager_get_all_tasks_empty(self, manager: DistributedProcessing) -> None:
        """Manager returns empty list when no tasks."""
        all_tasks = manager.get_all_tasks()
        assert all_tasks == []

    def test_manager_cancel_task_queued(self, manager: DistributedProcessing) -> None:
        """Manager cancels queued task successfully."""
        task_id = manager.add_task("binary_analysis", {})

        result = manager.cancel_task(task_id)

        assert result is True
        assert manager.tasks[0].status == ProcessingStatus.CANCELLED

    def test_manager_cancel_task_running(self, manager: DistributedProcessing) -> None:
        """Manager cancels running task successfully."""
        task_id = manager.add_task("password_cracking", {})
        manager.tasks[0].status = ProcessingStatus.RUNNING

        result = manager.cancel_task(task_id)

        assert result is True
        assert manager.tasks[0].status == ProcessingStatus.CANCELLED

    def test_manager_cancel_task_completed(self, manager: DistributedProcessing) -> None:
        """Manager does not cancel completed task."""
        task_id = manager.add_task("binary_analysis", {})
        manager.tasks[0].status = ProcessingStatus.COMPLETED

        result = manager.cancel_task(task_id)

        assert result is False
        assert manager.tasks[0].status == ProcessingStatus.COMPLETED

    def test_manager_cancel_task_not_found(self, manager: DistributedProcessing) -> None:
        """Manager returns False when cancelling non-existent task."""
        result = manager.cancel_task("nonexistent_task")
        assert result is False

    @pytest.mark.skipif(not has_pyqt6(), reason="PyQt6 not available")
    def test_manager_run_distributed_processing_pyqt6(self, manager: DistributedProcessing) -> None:
        """Manager launches distributed processing dialog with PyQt6."""
        manager.run_distributed_processing()

        assert manager.dialog is not None
        assert isinstance(manager.dialog, DistributedProcessingDialog)

    def test_manager_run_distributed_processing_no_pyqt6(self, manager: DistributedProcessing) -> None:
        """Manager handles missing PyQt6 gracefully."""
        if HAS_PYQT6:
            pytest.skip("Testing fallback implementation only")

        manager.run_distributed_processing()


class TestIntegrationDistributedProcessing:
    """Integration tests for complete distributed processing workflows."""

    @pytest.fixture
    def temp_binaries(self, tmp_path: Path) -> list[Path]:
        """Create multiple temporary test binaries."""
        binaries = []
        for i in range(3):
            binary_path = tmp_path / f"test_binary_{i}.exe"
            with open(binary_path, "wb") as f:
                f.write(b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00")
                f.write(b"\x00" * 64)
                f.write(b"PE\x00\x00")
                f.write(b"\x64\x86" + b"\x00" * 18)
                f.write(b"\x0b\x02" + b"\x00" * 238)
                f.write(b"license_check_" + str(i).encode() * 20)
                f.write(os.urandom(512))
            binaries.append(binary_path)
        return binaries

    def test_integration_multiple_workers_processing_tasks(self, temp_binaries: list[Path]) -> None:
        """Multiple workers process tasks from shared queue correctly."""
        task_queue: list[DistributedTask] = []

        for i, binary_path in enumerate(temp_binaries):
            task = DistributedTask(
                f"task_{i}",
                "binary_analysis",
                {"binary_path": str(binary_path)}
            )
            task_queue.append(task)

        workers = [
            DistributedWorkerThread(f"worker_{i}", task_queue)
            for i in range(2)
        ]

        for worker in workers:
            worker.running = True

        completed_count = 0
        max_iterations = 10
        iteration = 0

        while completed_count < len(temp_binaries) and iteration < max_iterations:
            for worker in workers:
                if task := worker.get_next_task():
                    worker.process_task(task)

            completed_count = sum(bool(task.status == ProcessingStatus.COMPLETED)
                              for task in task_queue)
            iteration += 1

        for worker in workers:
            worker.stop()

        assert completed_count == len(temp_binaries)
        assert all(task.status == ProcessingStatus.COMPLETED for task in task_queue)
        assert all(task.results is not None for task in task_queue)

    def test_integration_task_distribution_across_workers(self, temp_binaries: list[Path]) -> None:
        """Tasks distribute evenly across multiple workers."""
        task_queue: list[DistributedTask] = []

        for i in range(6):
            task = DistributedTask(
                f"task_{i}",
                "generic_task",
                {"operation": "analyze", "target": str(temp_binaries[i % len(temp_binaries)])}
            )
            task_queue.append(task)

        workers = [
            DistributedWorkerThread(f"worker_{i}", task_queue)
            for i in range(3)
        ]

        for worker in workers:
            worker.running = True

        for _ in range(2):
            for worker in workers:
                if task := worker.get_next_task():
                    worker.process_task(task)

        worker_assignments = {}
        for task in task_queue:
            if task.worker_id:
                worker_assignments[task.worker_id] = worker_assignments.get(task.worker_id, 0) + 1

        for worker in workers:
            worker.stop()

        assert len(worker_assignments) >= 2

    def test_integration_complete_workflow_manager_to_workers(self, temp_binaries: list[Path]) -> None:
        """Complete workflow from manager through workers to completion."""
        manager = DistributedProcessing()

        task_ids = [
            manager.add_task("binary_analysis", {"binary_path": str(binary)})
            for binary in temp_binaries
        ]

        workers = [
            DistributedWorkerThread(f"worker_{i}", manager.tasks)
            for i in range(2)
        ]

        for worker in workers:
            worker.running = True

        max_iterations = 10
        iteration = 0
        while iteration < max_iterations:
            for worker in workers:
                if task := worker.get_next_task():
                    worker.process_task(task)

            completed = sum(bool(task.status == ProcessingStatus.COMPLETED)
                        for task in manager.tasks)
            if completed >= len(temp_binaries):
                break
            iteration += 1

        for worker in workers:
            worker.stop()

        for task_id in task_ids:
            status = manager.get_task_status(task_id)
            assert status is not None
            assert status["status"] == ProcessingStatus.COMPLETED.value

    def test_integration_task_cancellation_during_processing(self) -> None:
        """Task cancellation prevents further processing."""
        manager = DistributedProcessing()

        task_ids = [
            manager.add_task("generic_task", {"operation": "process", "data_size": 1000})
            for _ in range(5)
        ]

        cancel_result = manager.cancel_task(task_ids[2])
        assert cancel_result is True

        worker = DistributedWorkerThread("worker_1", manager.tasks)
        worker.running = True

        for _ in range(5):
            if task := worker.get_next_task():
                worker.process_task(task)

        worker.stop()

        cancelled_task = next(t for t in manager.tasks if t.task_id == task_ids[2])
        assert cancelled_task.status == ProcessingStatus.CANCELLED
        assert cancelled_task.results is None
