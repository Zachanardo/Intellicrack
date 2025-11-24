"""Streaming Analysis Manager for Memory-Efficient Large Binary Processing.

Production-ready framework for analyzing multi-GB executables through chunk-based
processing, memory mapping, and streaming analysis. Provides a unified interface
for all analysis modules to handle large files without memory exhaustion.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import json
import logging
import mmap
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class StreamingConfig:
    """Configuration for streaming analysis operations."""

    chunk_size: int = 8 * 1024 * 1024
    hash_chunk_size: int = 64 * 1024
    large_file_threshold: int = 50 * 1024 * 1024
    max_memory_usage: int = 512 * 1024 * 1024
    enable_checkpointing: bool = True
    checkpoint_interval: int = 100 * 1024 * 1024
    overlap_size: int = 4096
    use_memory_mapping: bool = True


@dataclass
class ChunkContext:
    """Context information for a chunk being processed."""

    offset: int
    size: int
    chunk_number: int
    total_chunks: int
    data: bytes
    overlap_before: bytes = b""
    overlap_after: bytes = b""
    file_path: Path = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class StreamingProgress:
    """Progress tracking for streaming analysis."""

    bytes_processed: int = 0
    total_bytes: int = 0
    chunks_processed: int = 0
    total_chunks: int = 0
    current_stage: str = ""
    stage_progress: float = 0.0
    overall_progress: float = 0.0
    errors: list[str] = field(default_factory=list)


class StreamingAnalyzer(ABC):
    """Base class for analyzers that support streaming mode."""

    @abstractmethod
    def analyze_chunk(self, context: ChunkContext) -> dict[str, Any]:
        """Analyze a single chunk of data.

        Args:
            context: Chunk context with data and metadata

        Returns:
            Partial analysis results for this chunk

        """

    @abstractmethod
    def merge_results(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Merge results from multiple chunks into final analysis.

        Args:
            results: List of partial results from each chunk

        Returns:
            Merged final analysis results

        """

    def initialize_analysis(self, file_path: Path) -> None:  # noqa: B027
        """Initialize analyzer before processing begins.

        Args:
            file_path: Path to file being analyzed

        """

    def finalize_analysis(self, merged_results: dict[str, Any]) -> dict[str, Any]:
        """Finalize analysis after all chunks processed.

        Args:
            merged_results: Merged results from all chunks

        Returns:
            Final analysis results with any post-processing

        """
        return merged_results


class StreamingAnalysisManager:
    """Production-ready manager for streaming analysis of large binaries."""

    def __init__(self, config: StreamingConfig | None = None) -> None:
        """Initialize the streaming analysis manager.

        Args:
            config: Configuration for streaming operations

        """
        self.config = config or StreamingConfig()
        self.logger = logger
        self.progress_callbacks: list[Callable[[StreamingProgress], None]] = []

    def register_progress_callback(self, callback: Callable[[StreamingProgress], None]) -> None:
        """Register a callback for progress updates.

        Args:
            callback: Function to call with progress updates

        """
        self.progress_callbacks.append(callback)

    def _notify_progress(self, progress: StreamingProgress) -> None:
        """Notify all registered callbacks of progress update.

        Args:
            progress: Current progress state

        """
        for callback in self.progress_callbacks:
            try:
                callback(progress)
            except Exception as e:
                self.logger.error(f"Progress callback error: {e}")

    def read_chunks(
        self,
        file_path: Path,
        chunk_size: int | None = None,
        overlap_size: int | None = None,
    ) -> Iterator[ChunkContext]:
        """Generate chunks of file data with overlap for pattern matching.

        Args:
            file_path: Path to file
            chunk_size: Size of each chunk (uses config default if None)
            overlap_size: Overlap between chunks (uses config default if None)

        Yields:
            ChunkContext objects for each chunk

        """
        if chunk_size is None:
            chunk_size = self.config.chunk_size

        if overlap_size is None:
            overlap_size = self.config.overlap_size

        file_size = file_path.stat().st_size
        total_chunks = (file_size + chunk_size - 1) // chunk_size

        with open(file_path, "rb") as f:
            chunk_number = 0
            offset = 0
            previous_tail = b""

            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                overlap_before = previous_tail[-overlap_size:] if previous_tail else b""

                next_pos = f.tell()
                overlap_after = b""
                if next_pos < file_size:
                    overlap_after = f.read(overlap_size)
                    f.seek(next_pos)

                yield ChunkContext(
                    offset=offset,
                    size=len(chunk),
                    chunk_number=chunk_number,
                    total_chunks=total_chunks,
                    data=chunk,
                    overlap_before=overlap_before,
                    overlap_after=overlap_after,
                    file_path=file_path,
                )
                previous_tail = chunk
                offset += len(chunk)
                chunk_number += 1

    def open_memory_mapped(self, file_path: Path) -> tuple[Any, mmap.mmap]:
        """Open file with memory mapping for efficient random access.

        Args:
            file_path: Path to file

        Returns:
            Tuple of (file_handle, mmap_object)

        Raises:
            RuntimeError: If memory mapping fails

        """
        file_handle = open(file_path, "rb")  # noqa: SIM115
        try:
            if file_handle.fileno() == -1:
                raise OSError("Invalid file descriptor")
            mmap_obj = mmap.mmap(file_handle.fileno(), 0, access=mmap.ACCESS_READ)
            return file_handle, mmap_obj
        except (OSError, ValueError) as e:
            file_handle.close()
            raise RuntimeError(f"Failed to create memory map: {e}") from e

    def analyze_streaming(
        self,
        file_path: Path,
        analyzer: StreamingAnalyzer,
        checkpoint_path: Path | None = None,
    ) -> dict[str, Any]:
        """Perform streaming analysis using provided analyzer.

        Args:
            file_path: Path to binary file
            analyzer: Analyzer implementing StreamingAnalyzer interface
            checkpoint_path: Optional path for saving checkpoints

        Returns:
            Complete analysis results

        """
        try:
            file_path = Path(file_path)

            if not file_path.exists():
                return {"error": f"File not found: {file_path}", "status": "failed"}

            if not file_path.is_file():
                return {"error": f"Not a file: {file_path}", "status": "failed"}

            file_size = file_path.stat().st_size
            total_chunks = (file_size + self.config.chunk_size - 1) // self.config.chunk_size

            progress = StreamingProgress(
                total_bytes=file_size,
                total_chunks=total_chunks,
                current_stage="initializing",
            )

            self._notify_progress(progress)

            analyzer.initialize_analysis(file_path)

            chunk_results = []
            progress.current_stage = "analyzing_chunks"

            for context in self.read_chunks(file_path):
                try:
                    chunk_result = analyzer.analyze_chunk(context)
                    chunk_results.append(chunk_result)

                    progress.bytes_processed = context.offset + context.size
                    progress.chunks_processed = context.chunk_number + 1
                    progress.overall_progress = (progress.bytes_processed / progress.total_bytes) * 100

                    self._notify_progress(progress)

                    if (
                        checkpoint_path
                        and self.config.enable_checkpointing
                        and progress.bytes_processed % self.config.checkpoint_interval < self.config.chunk_size
                    ):
                        self._save_checkpoint(checkpoint_path, chunk_results, progress)

                except Exception as e:
                    error_msg = f"Error analyzing chunk {context.chunk_number}: {e}"
                    self.logger.error(error_msg)
                    progress.errors.append(error_msg)
                    chunk_results.append({"error": str(e), "chunk": context.chunk_number})

            progress.current_stage = "merging_results"
            self._notify_progress(progress)

            merged_results = analyzer.merge_results(chunk_results)

            progress.current_stage = "finalizing"
            self._notify_progress(progress)

            final_results = analyzer.finalize_analysis(merged_results)

            final_results.update(
                {
                    "status": "completed",
                    "streaming_mode": True,
                    "file_size": file_size,
                    "chunks_processed": total_chunks,
                    "errors": progress.errors or None,
                },
            )

            progress.current_stage = "completed"
            progress.overall_progress = 100.0
            self._notify_progress(progress)

            return final_results

        except Exception as e:
            self.logger.error(f"Streaming analysis failed: {e}")
            return {"error": str(e), "status": "failed"}

    def _save_checkpoint(
        self,
        checkpoint_path: Path,
        results: list[dict[str, Any]],
        progress: StreamingProgress,
    ) -> None:
        """Save analysis checkpoint for resumption.

        Args:
            checkpoint_path: Path to save checkpoint
            results: Partial results to save
            progress: Current progress state

        """
        try:
            checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

            checkpoint_data = {
                "results": results,
                "progress": {
                    "bytes_processed": progress.bytes_processed,
                    "chunks_processed": progress.chunks_processed,
                    "current_stage": progress.current_stage,
                },
            }

            with open(checkpoint_path, "w", encoding="utf-8") as f:
                json.dump(checkpoint_data, f, indent=2)

            self.logger.debug(f"Checkpoint saved: {checkpoint_path}")

        except Exception as e:
            self.logger.error(f"Failed to save checkpoint: {e}")

    def load_checkpoint(self, checkpoint_path: Path) -> dict[str, Any] | None:
        """Load analysis checkpoint to resume.

        Args:
            checkpoint_path: Path to checkpoint file

        Returns:
            Checkpoint data or None if failed

        """
        try:
            if not checkpoint_path.exists():
                return None

            with open(checkpoint_path, encoding="utf-8") as f:
                return json.load(f)

        except Exception as e:
            self.logger.error(f"Failed to load checkpoint: {e}")
            return None

    def calculate_hashes_streaming(
        self,
        file_path: Path,
        algorithms: list[str] | None = None,
    ) -> dict[str, str]:
        """Calculate file hashes using streaming to avoid memory loading.

        Args:
            file_path: Path to file
            algorithms: List of hash algorithms (default: sha256, sha512, sha3_256, blake2b)

        Returns:
            Dictionary of algorithm names to hex digests

        """
        if algorithms is None:
            algorithms = ["sha256", "sha512", "sha3_256", "blake2b"]

        try:
            hashers = {}
            for algo in algorithms:
                if algo == "sha256":
                    hashers[algo] = hashlib.sha256()
                elif algo == "sha512":
                    hashers[algo] = hashlib.sha512()
                elif algo == "sha3_256":
                    hashers[algo] = hashlib.sha3_256()
                elif algo == "blake2b":
                    hashers[algo] = hashlib.blake2b()
                elif algo == "md5":
                    hashers[algo] = hashlib.md5()  # noqa: S324
                elif algo == "sha1":
                    hashers[algo] = hashlib.sha1()  # noqa: S324

            file_size = file_path.stat().st_size
            progress = StreamingProgress(total_bytes=file_size, current_stage="hashing")

            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(self.config.hash_chunk_size)
                    if not chunk:
                        break

                    for hasher in hashers.values():
                        hasher.update(chunk)

                    progress.bytes_processed += len(chunk)
                    progress.overall_progress = (progress.bytes_processed / progress.total_bytes) * 100
                    self._notify_progress(progress)

            return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}

        except Exception as e:
            self.logger.error(f"Hash calculation failed: {e}")
            return {"error": str(e)}

    def scan_for_patterns_streaming(
        self,
        file_path: Path,
        patterns: list[bytes],
        context_bytes: int = 32,
        max_matches_per_pattern: int = 1000,
    ) -> dict[str, list[dict[str, Any]]]:
        """Scan large binary for byte patterns using streaming.

        Args:
            file_path: Path to binary file
            patterns: List of byte patterns to search for
            context_bytes: Number of bytes before/after match to include
            max_matches_per_pattern: Maximum matches to collect per pattern

        Returns:
            Dictionary mapping pattern hex to list of matches with context

        """
        try:
            results = {pattern.hex(): [] for pattern in patterns}
            overlap_size = max((len(p) for p in patterns), default=0)

            for context in self.read_chunks(file_path, overlap_size=overlap_size):
                search_data = context.overlap_before + context.data + context.overlap_after
                search_offset = context.offset - len(context.overlap_before)

                for pattern in patterns:
                    if len(results[pattern.hex()]) >= max_matches_per_pattern:
                        continue

                    offset = 0
                    while True:
                        pos = search_data.find(pattern, offset)
                        if pos == -1:
                            break

                        actual_offset = search_offset + pos

                        context_start = max(0, pos - context_bytes)
                        context_end = min(len(search_data), pos + len(pattern) + context_bytes)

                        results[pattern.hex()].append(
                            {
                                "offset": actual_offset,
                                "context_before": search_data[context_start:pos].hex(),
                                "match": pattern.hex(),
                                "context_after": search_data[pos + len(pattern) : context_end].hex(),
                            },
                        )

                        if len(results[pattern.hex()]) >= max_matches_per_pattern:
                            break

                        offset = pos + 1

            return results

        except Exception as e:
            self.logger.error(f"Pattern scanning failed: {e}")
            return {"error": str(e)}

    def analyze_section_streaming(
        self,
        file_path: Path,
        offset: int,
        size: int,
    ) -> dict[str, Any]:
        """Analyze a specific section using memory mapping.

        Args:
            file_path: Path to binary file
            offset: Starting offset of section
            size: Size of section

        Returns:
            Section analysis results

        """
        try:
            file_handle, mm = self.open_memory_mapped(file_path)
            try:
                if offset < 0 or offset + size > len(mm) or size <= 0:
                    return {"error": "Invalid section range"}

                section_data = mm[offset : offset + size]

                byte_counts = {}
                for byte in section_data:
                    byte_counts[byte] = byte_counts.get(byte, 0) + 1

                import math

                entropy = 0.0
                for count in byte_counts.values():
                    if count > 0:
                        probability = count / size
                        entropy -= probability * math.log2(probability)

                printable_count = sum(bool(32 <= byte <= 126) for byte in section_data)
                null_count = byte_counts.get(0, 0)
                high_entropy_count = sum(bool(byte > 127) for byte in section_data)

                return {
                    "offset": f"0x{offset:08x}",
                    "size": size,
                    "entropy": round(entropy, 4),
                    "unique_bytes": len(byte_counts),
                    "printable_ratio": round(printable_count / size, 4) if size > 0 else 0,
                    "null_ratio": round(null_count / size, 4) if size > 0 else 0,
                    "high_entropy_ratio": round(high_entropy_count / size, 4) if size > 0 else 0,
                    "characteristics": self._classify_section(
                        entropy,
                        printable_count / size if size > 0 else 0,
                        null_count / size if size > 0 else 0,
                    ),
                }

            finally:
                mm.close()
                file_handle.close()

        except Exception as e:
            self.logger.error(f"Section analysis failed: {e}")
            return {"error": str(e)}

    def _classify_section(self, entropy: float, printable_ratio: float, null_ratio: float) -> str:
        """Classify section characteristics.

        Args:
            entropy: Section entropy
            printable_ratio: Ratio of printable characters
            null_ratio: Ratio of null bytes

        Returns:
            Classification string

        """
        if null_ratio > 0.9:
            return "Empty/Padding"
        if entropy > 7.5:
            return "Encrypted/Compressed"
        if entropy < 2.0:
            return "Highly Repetitive"
        if printable_ratio > 0.8:
            return "Text/Strings"
        if printable_ratio < 0.1 and entropy > 5.0:
            return "Code/Binary Data"
        return "Structured Binary" if 4.0 <= entropy < 6.0 else "Mixed Content"

    def should_use_streaming(self, file_path: Path) -> bool:
        """Determine if streaming mode should be used.

        Args:
            file_path: Path to file

        Returns:
            True if file size exceeds threshold

        """
        try:
            file_size = file_path.stat().st_size
            return file_size > self.config.large_file_threshold
        except Exception:
            return False
