"""Comprehensive test suite for StreamingAnalysisManager.

Tests chunk-based processing, memory efficiency, and integration with analyzers.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import hashlib
from pathlib import Path

import pytest

from intellicrack.core.processing.streaming_analysis_manager import (
    ChunkContext,
    StreamingAnalysisManager,
    StreamingAnalyzer,
    StreamingConfig,
    StreamingProgress,
)


class DummyAnalyzer(StreamingAnalyzer):
    """Test analyzer for validating streaming functionality."""

    def __init__(self):
        """Initialize dummy analyzer."""
        self.chunks_analyzed = []
        self.initialized = False
        self.finalized = False

    def initialize_analysis(self, file_path: Path) -> None:
        """Initialize dummy analyzer."""
        self.initialized = True

    def analyze_chunk(self, context: ChunkContext) -> dict:
        """Analyze chunk and track it."""
        self.chunks_analyzed.append(
            {
                "offset": context.offset,
                "size": context.size,
                "chunk_number": context.chunk_number,
                "has_overlap": len(context.overlap_before) > 0 or len(context.overlap_after) > 0,
            }
        )
        return {"chunk_offset": context.offset, "data_length": context.size}

    def merge_results(self, results: list[dict]) -> dict:
        """Merge chunk results."""
        total_bytes = sum(r.get("data_length", 0) for r in results)
        return {"total_chunks": len(results), "total_bytes": total_bytes}

    def finalize_analysis(self, merged_results: dict) -> dict:
        """Finalize analysis."""
        self.finalized = True
        merged_results["completed"] = True
        return merged_results


class TestStreamingAnalysisManager:
    """Test suite for StreamingAnalysisManager."""

    def test_initialization_default_config(self):
        """Test manager initialization with default configuration."""
        manager = StreamingAnalysisManager()

        assert manager.config.chunk_size == 8 * 1024 * 1024
        assert manager.config.hash_chunk_size == 64 * 1024
        assert manager.config.large_file_threshold == 50 * 1024 * 1024
        assert manager.progress_callbacks == []

    def test_initialization_custom_config(self):
        """Test manager initialization with custom configuration."""
        config = StreamingConfig(
            chunk_size=16 * 1024 * 1024,
            hash_chunk_size=128 * 1024,
            large_file_threshold=100 * 1024 * 1024,
        )
        manager = StreamingAnalysisManager(config)

        assert manager.config.chunk_size == 16 * 1024 * 1024
        assert manager.config.hash_chunk_size == 128 * 1024
        assert manager.config.large_file_threshold == 100 * 1024 * 1024

    def test_read_chunks_basic(self, tmp_path):
        """Test basic chunk reading functionality."""
        test_file = tmp_path / "test.bin"
        test_data = b"A" * 1000
        test_file.write_bytes(test_data)

        manager = StreamingAnalysisManager(StreamingConfig(chunk_size=100, overlap_size=10))

        chunks = list(manager.read_chunks(test_file))

        assert len(chunks) == 10
        assert chunks[0].offset == 0
        assert chunks[0].size == 100
        assert chunks[0].chunk_number == 0
        assert chunks[0].data == b"A" * 100

    def test_read_chunks_with_overlap(self, tmp_path):
        """Test chunk reading with overlap for pattern matching."""
        test_file = tmp_path / "test.bin"
        test_data = b"B" * 500
        test_file.write_bytes(test_data)

        manager = StreamingAnalysisManager(StreamingConfig(chunk_size=100, overlap_size=20))

        chunks = list(manager.read_chunks(test_file))

        assert chunks[0].overlap_before == b""
        assert len(chunks[0].overlap_after) == 20

        assert len(chunks[1].overlap_before) == 20
        assert chunks[1].overlap_before == b"B" * 20

    def test_memory_mapped_access(self, tmp_path):
        """Test memory-mapped file access for random reads."""
        test_file = tmp_path / "test.bin"
        test_data = b"TestData" * 1000
        test_file.write_bytes(test_data)

        manager = StreamingAnalysisManager()

        file_handle, mm = manager.open_memory_mapped(test_file)
        try:
            assert mm[:8] == b"TestData"
            assert mm[100:108] == b"DataTest"
            assert len(mm) == len(test_data)
        finally:
            mm.close()
            file_handle.close()

    def test_analyze_streaming_basic(self, tmp_path):
        """Test basic streaming analysis workflow."""
        test_file = tmp_path / "test.bin"
        test_data = b"X" * 10000
        test_file.write_bytes(test_data)

        manager = StreamingAnalysisManager(StreamingConfig(chunk_size=1000))
        analyzer = DummyAnalyzer()

        results = manager.analyze_streaming(test_file, analyzer)

        assert results["status"] == "completed"
        assert results["streaming_mode"] is True
        assert results["total_bytes"] == 10000
        assert analyzer.initialized is True
        assert analyzer.finalized is True
        assert len(analyzer.chunks_analyzed) == 10

    def test_analyze_streaming_nonexistent_file(self):
        """Test streaming analysis with non-existent file."""
        manager = StreamingAnalysisManager()
        analyzer = DummyAnalyzer()

        results = manager.analyze_streaming(Path("/nonexistent/file.bin"), analyzer)

        assert "error" in results
        assert results["status"] == "failed"

    def test_progress_callbacks(self, tmp_path):
        """Test progress callback functionality."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Y" * 5000)

        manager = StreamingAnalysisManager(StreamingConfig(chunk_size=1000))
        analyzer = DummyAnalyzer()

        progress_updates = []

        def progress_callback(progress: StreamingProgress):
            progress_updates.append(
                {
                    "stage": progress.current_stage,
                    "bytes": progress.bytes_processed,
                    "chunks": progress.chunks_processed,
                }
            )

        manager.register_progress_callback(progress_callback)

        manager.analyze_streaming(test_file, analyzer)

        assert progress_updates
        assert any(p["stage"] == "initializing" for p in progress_updates)
        assert any(p["stage"] == "analyzing_chunks" for p in progress_updates)
        assert any(p["stage"] == "completed" for p in progress_updates)

    def test_calculate_hashes_streaming(self, tmp_path):
        """Test streaming hash calculation."""
        test_file = tmp_path / "test.bin"
        test_data = b"HashTestData" * 1000
        test_file.write_bytes(test_data)

        manager = StreamingAnalysisManager()

        hashes = manager.calculate_hashes_streaming(test_file)

        assert "sha256" in hashes
        assert "sha512" in hashes
        assert "sha3_256" in hashes
        assert "blake2b" in hashes

        expected_sha256 = hashlib.sha256(test_data).hexdigest()
        assert hashes["sha256"] == expected_sha256

    def test_scan_for_patterns_streaming(self, tmp_path):
        """Test streaming pattern scanning."""
        test_file = tmp_path / "test.bin"
        test_data = b"AAABBBCCCDDDEEE" + b"X" * 1000 + b"AAABBB" + b"Y" * 1000 + b"CCC"
        test_file.write_bytes(test_data)

        manager = StreamingAnalysisManager(StreamingConfig(chunk_size=500))

        patterns = [b"AAA", b"BBB", b"CCC"]
        results = manager.scan_for_patterns_streaming(test_file, patterns, context_bytes=8)

        assert b"AAA".hex() in results
        assert b"BBB".hex() in results
        assert b"CCC".hex() in results

        assert len(results[b"AAA".hex()]) >= 2
        assert len(results[b"BBB".hex()]) >= 2
        assert len(results[b"CCC".hex()]) >= 2

    def test_analyze_section_streaming(self, tmp_path):
        """Test section-specific streaming analysis."""
        test_file = tmp_path / "test.bin"
        test_data = b"\x00" * 100 + b"Text" * 100 + bytes(range(256)) + b"\xff" * 44
        test_file.write_bytes(test_data)

        manager = StreamingAnalysisManager()

        section_0 = manager.analyze_section_streaming(test_file, 0, 100)
        assert section_0["characteristics"] == "Empty/Padding"
        assert section_0["null_ratio"] > 0.9

        section_1 = manager.analyze_section_streaming(test_file, 100, 400)
        assert "Text" in section_1["characteristics"]
        assert section_1["printable_ratio"] > 0.8

        section_2 = manager.analyze_section_streaming(test_file, 500, 100)
        assert section_2["entropy"] > 0

    def test_should_use_streaming(self, tmp_path):
        """Test automatic streaming mode detection."""
        manager = StreamingAnalysisManager()

        small_file = tmp_path / "small.bin"
        small_file.write_bytes(b"X" * 1000)
        assert manager.should_use_streaming(small_file) is False

        large_file = tmp_path / "large.bin"
        large_file.write_bytes(b"X" * (60 * 1024 * 1024))
        assert manager.should_use_streaming(large_file) is True

    def test_checkpoint_save_load(self, tmp_path):
        """Test checkpoint saving and loading for resumable operations."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Z" * 5000)

        checkpoint_path = tmp_path / "checkpoint.json"

        manager = StreamingAnalysisManager(StreamingConfig(chunk_size=1000, enable_checkpointing=True))
        analyzer = DummyAnalyzer()

        results = manager.analyze_streaming(test_file, analyzer, checkpoint_path=checkpoint_path)

        assert results["status"] == "completed"

    def test_large_file_simulation(self, tmp_path):
        """Test streaming with simulated large file."""
        test_file = tmp_path / "large.bin"

        chunk_data = b"Pattern" * 1000
        with open(test_file, "wb") as f:
            for _ in range(100):
                f.write(chunk_data)

        file_size = test_file.stat().st_size
        assert file_size >= 700_000

        manager = StreamingAnalysisManager(StreamingConfig(chunk_size=10_000))
        analyzer = DummyAnalyzer()

        results = manager.analyze_streaming(test_file, analyzer)

        assert results["status"] == "completed"
        assert results["file_size"] == file_size
        assert len(analyzer.chunks_analyzed) >= 70


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
