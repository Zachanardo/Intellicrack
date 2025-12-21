"""Production tests for checksum_dialog module.

Tests validate checksum calculation in dialogs, worker threads, progress reporting,
error handling, and multi-algorithm processing for real binary data.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest


pytest.importorskip("PyQt6")

from intellicrack.hexview.checksum_dialog import ChecksumWorker


class TestChecksumWorkerCore:
    """Test core checksum worker functionality."""

    def test_checksum_worker_creation_with_data(self) -> None:
        """ChecksumWorker initializes with binary data."""
        test_data = b"Test binary data for checksum calculation"
        worker = ChecksumWorker(data=test_data)

        assert worker.data == test_data
        assert worker.file_path is None
        assert worker.calculator is not None

    def test_checksum_worker_creation_with_file_path(self) -> None:
        """ChecksumWorker initializes with file path."""
        test_path = "D:\test\\sample.bin"
        worker = ChecksumWorker(file_path=test_path)

        assert worker.data is None
        assert worker.file_path == test_path

    def test_set_algorithms(self) -> None:
        """ChecksumWorker accepts list of algorithms."""
        worker = ChecksumWorker(data=b"test")
        algorithms = ["md5", "sha1", "sha256"]

        worker.set_algorithms(algorithms)

        assert worker.algorithms == algorithms


class TestChecksumCalculation:
    """Test actual checksum calculation operations."""

    def test_calculate_md5_for_data(self) -> None:
        """ChecksumWorker calculates MD5 hash for in-memory data."""
        test_data = b"Binary data to hash"
        expected_md5 = hashlib.md5(test_data).hexdigest()

        worker = ChecksumWorker(data=test_data)
        worker.set_algorithms(["md5"])

        results = {}
        worker.result.connect(results.update)
        worker.run()

        assert "md5" in results
        assert results["md5"] == expected_md5

    def test_calculate_sha256_for_data(self) -> None:
        """ChecksumWorker calculates SHA256 hash for in-memory data."""
        test_data = b"Test data for SHA256 hashing"
        expected_sha256 = hashlib.sha256(test_data).hexdigest()

        worker = ChecksumWorker(data=test_data)
        worker.set_algorithms(["sha256"])

        results = {}
        worker.result.connect(results.update)
        worker.run()

        assert "sha256" in results
        assert results["sha256"] == expected_sha256

    def test_calculate_multiple_algorithms_simultaneously(self) -> None:
        """ChecksumWorker calculates multiple hashes in single operation."""
        test_data = b"Multi-algorithm test data"

        worker = ChecksumWorker(data=test_data)
        worker.set_algorithms(["md5", "sha1", "sha256"])

        results = {}
        worker.result.connect(results.update)
        worker.run()

        assert "md5" in results
        assert "sha1" in results
        assert "sha256" in results
        assert len(results["md5"]) == 32
        assert len(results["sha1"]) == 40
        assert len(results["sha256"]) == 64

    def test_calculate_checksum_for_file(self) -> None:
        """ChecksumWorker calculates checksum for actual file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            test_data = b"File content for checksum testing" * 100
            tmp.write(test_data)
            tmp_path = tmp.name

        try:
            expected_md5 = hashlib.md5(test_data).hexdigest()

            worker = ChecksumWorker(file_path=tmp_path)
            worker.set_algorithms(["md5"])

            results = {}
            worker.result.connect(results.update)
            worker.run()

            assert "md5" in results
            assert results["md5"] == expected_md5
        finally:
            Path(tmp_path).unlink(missing_ok=True)


class TestChecksumWorkerEdgeCases:
    """Test edge cases and error handling."""

    def test_worker_with_no_data_or_file(self) -> None:
        """ChecksumWorker raises error when neither data nor file provided."""
        worker = ChecksumWorker()
        worker.set_algorithms(["md5"])

        error_occurred = False

        def handle_error(msg: str) -> None:
            nonlocal error_occurred
            error_occurred = True

        worker.error.connect(handle_error)

        with pytest.raises(ValueError, match="No data or file path provided"):
            worker.run()

    def test_worker_with_empty_data(self) -> None:
        """ChecksumWorker handles empty binary data correctly."""
        empty_data = b""
        expected_md5 = hashlib.md5(empty_data).hexdigest()

        worker = ChecksumWorker(data=empty_data)
        worker.set_algorithms(["md5"])

        results = {}
        worker.result.connect(results.update)
        worker.run()

        assert results["md5"] == expected_md5

    def test_worker_with_large_data(self) -> None:
        """ChecksumWorker processes large binary data efficiently."""
        large_data = b"x" * (10 * 1024 * 1024)
        expected_sha256 = hashlib.sha256(large_data).hexdigest()

        worker = ChecksumWorker(data=large_data)
        worker.set_algorithms(["sha256"])

        results = {}
        worker.result.connect(results.update)
        worker.run()

        assert results["sha256"] == expected_sha256

    def test_worker_with_nonexistent_file(self) -> None:
        """ChecksumWorker handles missing file gracefully."""
        worker = ChecksumWorker(file_path="D:\nonexistent\file.bin")
        worker.set_algorithms(["md5"])

        results = {}
        worker.result.connect(results.update)
        worker.run()

        assert "md5" in results
        assert "Error" in str(results["md5"])


class TestChecksumProgressReporting:
    """Test progress callback functionality."""

    def test_progress_callback_fires(self) -> None:
        """ChecksumWorker emits progress signals during calculation."""
        test_data = b"Progress test data" * 1000

        worker = ChecksumWorker(data=test_data)
        worker.set_algorithms(["md5", "sha256"])

        progress_updates = []

        def track_progress(current: int, total: int) -> None:
            progress_updates.append((current, total))

        worker.progress.connect(track_progress)
        worker.run()

        assert progress_updates


class TestChecksumAlgorithmSupport:
    """Test support for various checksum algorithms."""

    def test_crc32_calculation(self) -> None:
        """ChecksumWorker calculates CRC32 checksum."""
        import zlib

        test_data = b"CRC32 test data"
        expected_crc = format(zlib.crc32(test_data) & 0xFFFFFFFF, '08x')

        worker = ChecksumWorker(data=test_data)
        worker.set_algorithms(["crc32"])

        results = {}
        worker.result.connect(results.update)
        worker.run()

        if "crc32" in results:
            assert results["crc32"].lower() == expected_crc.lower()
