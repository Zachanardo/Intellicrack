"""Comprehensive production tests for StreamingAnalysisManager with real binary data.

Tests validate actual binary stream parsing, chunk processing, and memory mapping
with real file operations and binary patterns.
"""

from __future__ import annotations

import hashlib
import secrets
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.processing.streaming_analysis_manager import (
    ChunkContext,
    StreamingAnalysisManager,
    StreamingAnalyzer,
    StreamingConfig,
    StreamingProgress,
)


if TYPE_CHECKING:
    from collections.abc import Iterator


class RealStreamingAnalyzer(StreamingAnalyzer):
    """Real analyzer implementation for testing."""

    def __init__(self) -> None:
        """Initialize analyzer with real state tracking."""
        self.chunk_count = 0
        self.total_bytes = 0

    def analyze_chunk(self, context: ChunkContext) -> dict[str, Any]:
        """Analyze chunk with real operations."""
        self.chunk_count += 1
        self.total_bytes += len(context.data)
        return {
            "chunk_number": context.chunk_number,
            "size": len(context.data),
            "offset": context.offset,
        }

    def merge_results(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Merge results from all chunks."""
        return {
            "total_chunks": len(results),
            "total_size": sum(r["size"] for r in results if "size" in r),
        }


class PatternSearchAnalyzer(StreamingAnalyzer):
    """Analyzer that searches for specific patterns."""

    def __init__(self, patterns: list[bytes]) -> None:
        """Initialize with patterns to search."""
        self.patterns = patterns
        self.matches: dict[bytes, list[int]] = {p: [] for p in patterns}

    def analyze_chunk(self, context: ChunkContext) -> dict[str, Any]:
        """Search for patterns in chunk."""
        search_data = context.overlap_before + context.data + context.overlap_after
        base_offset = context.offset - len(context.overlap_before)

        matches: dict[str, list[int]] = {}
        for pattern in self.patterns:
            pattern_matches: list[int] = []
            offset = 0
            while True:
                pos = search_data.find(pattern, offset)
                if pos == -1:
                    break
                pattern_matches.append(base_offset + pos)
                offset = pos + 1
            matches[pattern.hex()] = pattern_matches

        return {"matches": matches}

    def merge_results(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Merge all matches."""
        all_matches: dict[str, list[int]] = {}
        for result in results:
            if "matches" in result:
                for pattern, positions in result["matches"].items():
                    if pattern not in all_matches:
                        all_matches[pattern] = []
                    all_matches[pattern].extend(positions)

        return {"all_matches": all_matches}


@pytest.fixture
def streaming_manager() -> StreamingAnalysisManager:
    """Create StreamingAnalysisManager instance."""
    config = StreamingConfig(
        chunk_size=1024,
        overlap_size=64,
        hash_chunk_size=512,
        large_file_threshold=2048,
    )
    return StreamingAnalysisManager(config)


@pytest.fixture
def temp_binary_file() -> Iterator[Path]:
    """Create temporary binary file for testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        test_data = b"TESTDATA" * 500
        f.write(test_data)
        temp_path = Path(f.name)
    yield temp_path
    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def large_binary_file() -> Iterator[Path]:
    """Create large binary file for streaming tests."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        for i in range(1000):
            chunk = secrets.token_bytes(1024)
            f.write(chunk)
        temp_path = Path(f.name)
    yield temp_path
    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def binary_with_patterns() -> Iterator[Path]:
    """Create binary file with specific patterns."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        data = b"\x00" * 1000
        data += b"LICENSE_KEY_12345"
        data += b"\x00" * 1000
        data += b"ACTIVATION_CODE"
        data += b"\x00" * 1000
        data += b"LICENSE_KEY_67890"
        data += b"\x00" * 1000
        f.write(data)
        temp_path = Path(f.name)
    yield temp_path
    if temp_path.exists():
        temp_path.unlink()


class TestStreamingAnalysisManager:
    """Test StreamingAnalysisManager functionality."""

    def test_initialization_with_default_config(self) -> None:
        """StreamingAnalysisManager initializes with default config."""
        manager = StreamingAnalysisManager()

        assert manager.config is not None
        assert manager.config.chunk_size == 8 * 1024 * 1024
        assert manager.progress_callbacks == []

    def test_initialization_with_custom_config(self) -> None:
        """StreamingAnalysisManager uses custom config."""
        config = StreamingConfig(chunk_size=2048, overlap_size=128)
        manager = StreamingAnalysisManager(config)

        assert manager.config.chunk_size == 2048
        assert manager.config.overlap_size == 128

    def test_read_chunks_processes_file(self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path) -> None:
        """read_chunks generates correct chunk contexts."""
        chunks = list(streaming_manager.read_chunks(temp_binary_file))

        assert len(chunks) > 0
        assert all(isinstance(chunk, ChunkContext) for chunk in chunks)

        total_size = sum(chunk.size for chunk in chunks)
        file_size = temp_binary_file.stat().st_size
        assert total_size == file_size

    def test_read_chunks_includes_overlap(self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path) -> None:
        """read_chunks includes overlap between chunks."""
        chunks = list(streaming_manager.read_chunks(temp_binary_file))

        if len(chunks) > 1:
            second_chunk = chunks[1]
            assert len(second_chunk.overlap_before) > 0

    def test_read_chunks_sequential_offsets(self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path) -> None:
        """read_chunks produces sequential chunk offsets."""
        chunks = list(streaming_manager.read_chunks(temp_binary_file))

        for i in range(len(chunks) - 1):
            current = chunks[i]
            next_chunk = chunks[i + 1]
            assert next_chunk.offset == current.offset + current.size

    def test_analyze_streaming_with_real_analyzer(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """analyze_streaming processes file with analyzer."""
        analyzer = RealStreamingAnalyzer()

        result = streaming_manager.analyze_streaming(temp_binary_file, analyzer)

        assert result["status"] == "completed"
        assert result["streaming_mode"] is True
        assert result["chunks_processed"] > 0
        assert analyzer.chunk_count > 0

    def test_analyze_streaming_with_nonexistent_file(self, streaming_manager: StreamingAnalysisManager) -> None:
        """analyze_streaming handles nonexistent file."""
        analyzer = RealStreamingAnalyzer()
        fake_path = Path("/nonexistent/file.bin")

        result = streaming_manager.analyze_streaming(fake_path, analyzer)

        assert "error" in result
        assert result["status"] == "failed"

    def test_analyze_streaming_progress_callbacks(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """analyze_streaming calls progress callbacks."""
        progress_updates: list[StreamingProgress] = []

        def progress_callback(progress: StreamingProgress) -> None:
            progress_updates.append(progress)

        streaming_manager.register_progress_callback(progress_callback)
        analyzer = RealStreamingAnalyzer()

        streaming_manager.analyze_streaming(temp_binary_file, analyzer)

        assert len(progress_updates) > 0
        assert any(p.current_stage == "completed" for p in progress_updates)

    def test_calculate_hashes_streaming(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """calculate_hashes_streaming produces correct hashes."""
        hashes = streaming_manager.calculate_hashes_streaming(temp_binary_file)

        assert "sha256" in hashes
        assert "sha512" in hashes
        assert len(hashes["sha256"]) == 64
        assert len(hashes["sha512"]) == 128

    def test_calculate_hashes_streaming_matches_direct_hash(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """Streaming hash matches direct file hash."""
        streaming_hash = streaming_manager.calculate_hashes_streaming(temp_binary_file, ["sha256"])

        with open(temp_binary_file, "rb") as f:
            direct_hash = hashlib.sha256(f.read()).hexdigest()

        assert streaming_hash["sha256"] == direct_hash

    def test_calculate_hashes_with_custom_algorithms(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """calculate_hashes_streaming supports custom algorithms."""
        hashes = streaming_manager.calculate_hashes_streaming(temp_binary_file, ["md5", "sha1"])

        assert "md5" in hashes
        assert "sha1" in hashes
        assert len(hashes["md5"]) == 32
        assert len(hashes["sha1"]) == 40

    def test_scan_for_patterns_streaming_finds_patterns(
        self, streaming_manager: StreamingAnalysisManager, binary_with_patterns: Path
    ) -> None:
        """scan_for_patterns_streaming finds all pattern occurrences."""
        patterns = [b"LICENSE_KEY", b"ACTIVATION"]

        results = streaming_manager.scan_for_patterns_streaming(binary_with_patterns, patterns)

        assert len(results[b"LICENSE_KEY".hex()]) == 2
        assert len(results[b"ACTIVATION".hex()]) == 1

    def test_scan_for_patterns_includes_context(
        self, streaming_manager: StreamingAnalysisManager, binary_with_patterns: Path
    ) -> None:
        """Pattern scan includes context bytes around matches."""
        patterns = [b"LICENSE_KEY"]

        results = streaming_manager.scan_for_patterns_streaming(
            binary_with_patterns, patterns, context_bytes=10
        )

        matches = results[b"LICENSE_KEY".hex()]
        assert len(matches) > 0
        first_match = matches[0]

        assert "offset" in first_match
        assert "context_before" in first_match
        assert "context_after" in first_match
        assert "match" in first_match

    def test_scan_for_patterns_respects_max_matches(
        self, streaming_manager: StreamingAnalysisManager, binary_with_patterns: Path
    ) -> None:
        """Pattern scan respects max_matches_per_pattern limit."""
        patterns = [b"LICENSE_KEY"]

        results = streaming_manager.scan_for_patterns_streaming(
            binary_with_patterns, patterns, max_matches_per_pattern=1
        )

        assert len(results[b"LICENSE_KEY".hex()]) == 1

    def test_open_memory_mapped(self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path) -> None:
        """open_memory_mapped creates valid memory map."""
        file_handle, mm = streaming_manager.open_memory_mapped(temp_binary_file)

        try:
            assert mm is not None
            assert len(mm) == temp_binary_file.stat().st_size
            assert mm[0:8] == b"TESTDATA"
        finally:
            mm.close()
            file_handle.close()

    def test_analyze_section_streaming(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """analyze_section_streaming analyzes specific file section."""
        result = streaming_manager.analyze_section_streaming(temp_binary_file, offset=0, size=512)

        assert "entropy" in result
        assert "unique_bytes" in result
        assert "printable_ratio" in result
        assert "characteristics" in result

    def test_analyze_section_with_invalid_range(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """analyze_section_streaming handles invalid section range."""
        file_size = temp_binary_file.stat().st_size

        result = streaming_manager.analyze_section_streaming(
            temp_binary_file, offset=file_size + 1000, size=100
        )

        assert "error" in result

    def test_should_use_streaming(self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path) -> None:
        """should_use_streaming correctly determines when to stream."""
        file_size = temp_binary_file.stat().st_size

        should_stream = streaming_manager.should_use_streaming(temp_binary_file)

        if file_size > streaming_manager.config.large_file_threshold:
            assert should_stream is True
        else:
            assert should_stream is False

    def test_checkpoint_save_and_load(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """Checkpoint saving and loading works correctly."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            checkpoint_path = Path(f.name)

        try:
            results = [{"chunk": 0, "data": "test"}]
            progress = StreamingProgress(bytes_processed=1000, chunks_processed=1)

            streaming_manager._save_checkpoint(checkpoint_path, results, progress)

            loaded = streaming_manager.load_checkpoint(checkpoint_path)

            assert loaded is not None
            assert "results" in loaded
            assert "progress" in loaded
            assert loaded["progress"]["bytes_processed"] == 1000
        finally:
            if checkpoint_path.exists():
                checkpoint_path.unlink()

    def test_load_nonexistent_checkpoint(self, streaming_manager: StreamingAnalysisManager) -> None:
        """load_checkpoint returns None for nonexistent file."""
        result = streaming_manager.load_checkpoint(Path("/nonexistent/checkpoint.json"))

        assert result is None

    def test_progress_callback_with_exception(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """Progress callback exceptions don't break analysis."""
        def failing_callback(progress: StreamingProgress) -> None:
            raise RuntimeError("Callback error")

        streaming_manager.register_progress_callback(failing_callback)
        analyzer = RealStreamingAnalyzer()

        result = streaming_manager.analyze_streaming(temp_binary_file, analyzer)

        assert result["status"] == "completed"


class TestPatternSearchAnalyzer:
    """Test pattern search analyzer with real binary data."""

    def test_pattern_analyzer_finds_all_matches(
        self, streaming_manager: StreamingAnalysisManager, binary_with_patterns: Path
    ) -> None:
        """Pattern analyzer finds all pattern occurrences across chunks."""
        patterns = [b"LICENSE_KEY", b"ACTIVATION_CODE"]
        analyzer = PatternSearchAnalyzer(patterns)

        result = streaming_manager.analyze_streaming(binary_with_patterns, analyzer)

        assert "all_matches" in result
        all_matches = result["all_matches"]
        assert len(all_matches[b"LICENSE_KEY".hex()]) == 2
        assert len(all_matches[b"ACTIVATION_CODE".hex()]) == 1

    def test_pattern_analyzer_handles_chunk_boundaries(
        self, streaming_manager: StreamingAnalysisManager
    ) -> None:
        """Pattern analyzer finds patterns spanning chunk boundaries."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            data = b"\x00" * 1020
            data += b"BOUNDARY_PATTERN"
            data += b"\x00" * 1000
            f.write(data)
            temp_path = Path(f.name)

        try:
            patterns = [b"BOUNDARY_PATTERN"]
            analyzer = PatternSearchAnalyzer(patterns)

            result = streaming_manager.analyze_streaming(temp_path, analyzer)

            all_matches = result["all_matches"]
            assert len(all_matches[b"BOUNDARY_PATTERN".hex()]) == 1
        finally:
            if temp_path.exists():
                temp_path.unlink()


class TestStreamingEdgeCases:
    """Test edge cases and error conditions."""

    def test_analyze_empty_file(self, streaming_manager: StreamingAnalysisManager) -> None:
        """Streaming analysis handles empty file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            temp_path = Path(f.name)

        try:
            analyzer = RealStreamingAnalyzer()
            result = streaming_manager.analyze_streaming(temp_path, analyzer)

            assert result["status"] == "completed"
            assert result["chunks_processed"] == 0
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_analyze_single_byte_file(self, streaming_manager: StreamingAnalysisManager) -> None:
        """Streaming analysis handles single-byte file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x42")
            temp_path = Path(f.name)

        try:
            analyzer = RealStreamingAnalyzer()
            result = streaming_manager.analyze_streaming(temp_path, analyzer)

            assert result["status"] == "completed"
            assert analyzer.total_bytes == 1
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_chunk_exception_handling(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """analyze_streaming handles chunk processing exceptions."""
        class FailingAnalyzer(StreamingAnalyzer):
            def analyze_chunk(self, context: ChunkContext) -> dict[str, Any]:
                if context.chunk_number == 1:
                    raise RuntimeError("Chunk processing failed")
                return {"chunk": context.chunk_number}

            def merge_results(self, results: list[dict[str, Any]]) -> dict[str, Any]:
                return {"total": len(results)}

        analyzer = FailingAnalyzer()
        result = streaming_manager.analyze_streaming(temp_binary_file, analyzer)

        assert result["status"] == "completed"
        assert result["errors"] is not None

    def test_scan_patterns_with_no_matches(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """Pattern scan returns empty results when no matches found."""
        patterns = [b"NONEXISTENT_PATTERN"]

        results = streaming_manager.scan_for_patterns_streaming(temp_binary_file, patterns)

        assert len(results[b"NONEXISTENT_PATTERN".hex()]) == 0

    def test_scan_patterns_with_empty_pattern_list(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """Pattern scan handles empty pattern list."""
        results = streaming_manager.scan_for_patterns_streaming(temp_binary_file, [])

        assert results == {}

    def test_analyze_section_with_zero_size(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """analyze_section_streaming handles zero-size section."""
        result = streaming_manager.analyze_section_streaming(temp_binary_file, offset=0, size=0)

        assert "error" in result

    def test_analyze_section_with_negative_offset(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """analyze_section_streaming handles negative offset."""
        result = streaming_manager.analyze_section_streaming(temp_binary_file, offset=-100, size=10)

        assert "error" in result

    def test_hash_calculation_with_large_file(
        self, streaming_manager: StreamingAnalysisManager, large_binary_file: Path
    ) -> None:
        """Hash calculation works correctly for large files."""
        hashes = streaming_manager.calculate_hashes_streaming(large_binary_file, ["sha256"])

        assert "sha256" in hashes
        assert len(hashes["sha256"]) == 64

    def test_multiple_progress_callbacks(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """Multiple progress callbacks all receive updates."""
        callback1_calls: list[StreamingProgress] = []
        callback2_calls: list[StreamingProgress] = []

        def callback1(progress: StreamingProgress) -> None:
            callback1_calls.append(progress)

        def callback2(progress: StreamingProgress) -> None:
            callback2_calls.append(progress)

        streaming_manager.register_progress_callback(callback1)
        streaming_manager.register_progress_callback(callback2)

        analyzer = RealStreamingAnalyzer()
        streaming_manager.analyze_streaming(temp_binary_file, analyzer)

        assert len(callback1_calls) > 0
        assert len(callback2_calls) > 0
        assert len(callback1_calls) == len(callback2_calls)

    def test_section_classification(self, streaming_manager: StreamingAnalysisManager) -> None:
        """Section analysis correctly classifies different section types."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            encrypted_data = secrets.token_bytes(1024)
            f.write(encrypted_data)
            temp_path = Path(f.name)

        try:
            result = streaming_manager.analyze_section_streaming(temp_path, offset=0, size=1024)

            assert "characteristics" in result
            assert result["entropy"] > 7.0
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_read_chunks_custom_chunk_size(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """read_chunks uses custom chunk size when specified."""
        custom_chunk_size = 256
        chunks = list(streaming_manager.read_chunks(temp_binary_file, chunk_size=custom_chunk_size))

        for chunk in chunks[:-1]:
            assert chunk.size == custom_chunk_size

    def test_read_chunks_custom_overlap(
        self, streaming_manager: StreamingAnalysisManager, temp_binary_file: Path
    ) -> None:
        """read_chunks uses custom overlap size when specified."""
        custom_overlap = 32
        chunks = list(streaming_manager.read_chunks(temp_binary_file, overlap_size=custom_overlap))

        if len(chunks) > 1:
            assert len(chunks[1].overlap_before) <= custom_overlap
