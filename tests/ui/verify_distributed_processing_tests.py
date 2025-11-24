"""
Quick verification script for distributed processing tests.

Runs a subset of tests without pytest to verify functionality.
"""

import hashlib
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from intellicrack.ui.distributed_processing import (
    DistributedProcessing,
    DistributedTask,
    DistributedWorkerThread,
    ProcessingStatus,
)


def test_task_creation() -> None:
    """Verify DistributedTask creation works."""
    print("Testing DistributedTask creation...")
    task = DistributedTask("test_001", "binary_analysis", {"path": "/test"})
    assert task.task_id == "test_001"
    assert task.status == ProcessingStatus.QUEUED
    assert task.progress == 0.0
    print("✓ Task creation successful")


def test_task_serialization() -> None:
    """Verify task serialization works."""
    print("Testing DistributedTask serialization...")
    task = DistributedTask("test_002", "password_cracking", {"hash": "abc123"})
    task_dict = task.to_dict()
    assert task_dict["task_id"] == "test_002"
    assert task_dict["task_type"] == "password_cracking"
    assert task_dict["status"] == "queued"
    print("✓ Task serialization successful")


def test_worker_entropy_calculation() -> None:
    """Verify entropy calculation works."""
    print("Testing entropy calculation...")
    worker = DistributedWorkerThread("worker_test", [])

    uniform_data = bytes([0] * 256)
    entropy = worker._calculate_entropy(uniform_data)
    assert entropy == 0.0, f"Expected 0.0, got {entropy}"

    random_data = os.urandom(1024)
    entropy = worker._calculate_entropy(random_data)
    assert 6.0 <= entropy <= 8.0, f"Expected 6-8, got {entropy}"

    print(f"✓ Entropy calculation successful (random data entropy: {entropy:.2f})")


def test_worker_string_extraction() -> None:
    """Verify string extraction works."""
    print("Testing string extraction...")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp.write(b"\x00\x01\x02")
        tmp.write(b"test_string_here")
        tmp.write(b"\xff\xfe")
        tmp.write(b"another_test_string")
        tmp.write(b"\x00" * 100)
        tmp_path = tmp.name

    try:
        worker = DistributedWorkerThread("worker_test", [])
        strings = worker._extract_strings(tmp_path, min_length=4)

        assert len(strings) > 0, "Should extract strings"
        assert any("test_string" in s for s in strings), f"Should find test_string, got {strings}"
        print(f"✓ String extraction successful ({len(strings)} strings found)")
    finally:
        os.unlink(tmp_path)


def test_worker_password_checking() -> None:
    """Verify password hash checking works."""
    print("Testing password hash checking...")

    worker = DistributedWorkerThread("worker_test", [])
    test_password = "testpass123"
    correct_hash = hashlib.sha256(test_password.encode()).hexdigest()

    password, matches = worker._check_password(test_password, correct_hash, hashlib.sha256)
    assert matches is True, "Should match correct hash"

    wrong_hash = hashlib.sha256(b"wrongpass").hexdigest()
    password, matches = worker._check_password(test_password, wrong_hash, hashlib.sha256)
    assert matches is False, "Should not match wrong hash"

    print("✓ Password checking successful")


def test_manager_operations() -> None:
    """Verify manager operations work."""
    print("Testing DistributedProcessing manager...")

    manager = DistributedProcessing()
    assert len(manager.tasks) == 0

    task_id = manager.add_task("binary_analysis", {"path": "/test.exe"})
    assert len(manager.tasks) == 1

    status = manager.get_task_status(task_id)
    assert status is not None
    assert status["task_id"] == task_id

    all_tasks = manager.get_all_tasks()
    assert len(all_tasks) == 1

    cancelled = manager.cancel_task(task_id)
    assert cancelled is True
    assert manager.tasks[0].status == ProcessingStatus.CANCELLED

    print("✓ Manager operations successful")


def test_worker_queue_operations() -> None:
    """Verify worker queue operations work."""
    print("Testing worker queue operations...")

    queue = []
    task1 = DistributedTask("task_1", "binary_analysis", {})
    task2 = DistributedTask("task_2", "password_cracking", {})
    queue.append(task1)
    queue.append(task2)

    worker = DistributedWorkerThread("worker_1", queue)

    retrieved = worker.get_next_task()
    assert retrieved is task1
    assert retrieved.status == ProcessingStatus.RUNNING
    assert retrieved.worker_id == "worker_1"

    retrieved2 = worker.get_next_task()
    assert retrieved2 is task2

    print("✓ Worker queue operations successful")


def test_common_password_generation() -> None:
    """Verify password generation works."""
    print("Testing common password generation...")

    worker = DistributedWorkerThread("worker_test", [])
    passwords = worker._generate_common_passwords()

    assert len(passwords) > 100, f"Should generate 100+ passwords, got {len(passwords)}"
    assert "password" in passwords
    assert "password123" in passwords
    assert "admin" in passwords

    print(f"✓ Password generation successful ({len(passwords)} passwords)")


def main() -> None:
    """Run all verification tests."""
    print("=" * 60)
    print("Distributed Processing Test Verification")
    print("=" * 60)
    print()

    tests = [
        test_task_creation,
        test_task_serialization,
        test_worker_entropy_calculation,
        test_worker_string_extraction,
        test_worker_password_checking,
        test_manager_operations,
        test_worker_queue_operations,
        test_common_password_generation,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
            print()
        except AssertionError as e:
            print(f"✗ Test failed: {e}")
            failed += 1
            print()
        except Exception as e:
            print(f"✗ Test error: {e}")
            failed += 1
            print()

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
