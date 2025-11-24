"""Streaming Entropy Analyzer for Large Binary Analysis.

Production-ready entropy analysis with chunk-based processing for multi-GB executables.
Provides detailed entropy analysis, section classification, and compression detection
without loading entire files into memory.

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

import logging
import math
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from intellicrack.core.processing.streaming_analysis_manager import ChunkContext, StreamingAnalysisManager, StreamingAnalyzer


logger = logging.getLogger(__name__)


@dataclass
class EntropyWindow:
    """Represents entropy analysis for a specific window of data.

    Attributes:
        offset: Byte offset where window begins in the binary file
        size: Size of the window in bytes
        entropy: Shannon entropy value for the window (0-8 bits)
        byte_distribution: Histogram of byte frequencies in window
        unique_bytes: Count of distinct byte values present
        printable_ratio: Proportion of ASCII printable characters (0.0-1.0)
        null_ratio: Proportion of null bytes (0x00) (0.0-1.0)
        high_entropy_ratio: Proportion of bytes with value > 127 (0.0-1.0)
        classification: Human-readable classification of window content

    """

    offset: int
    size: int
    entropy: float
    byte_distribution: dict[int, int] = field(default_factory=dict)
    unique_bytes: int = 0
    printable_ratio: float = 0.0
    null_ratio: float = 0.0
    high_entropy_ratio: float = 0.0
    classification: str = ""


class StreamingEntropyAnalyzer(StreamingAnalyzer):
    """Streaming analyzer for entropy analysis of large binaries.

    Performs chunk-based entropy calculation on multi-GB files without
    loading entire binary into memory. Analyzes Shannon entropy, byte
    distribution, and content classification to identify packed code,
    encryption, and compression protection mechanisms.
    """

    ENTROPY_THRESHOLDS: dict[str, float] = {
        "very_low": 2.0,
        "low": 4.0,
        "medium": 6.0,
        "high": 7.0,
        "very_high": 7.5,
    }

    def __init__(self, window_size: int = 1024 * 1024, stride: int = 512 * 1024) -> None:
        """Initialize streaming entropy analyzer.

        Args:
            window_size: Size of sliding window for entropy calculation (default 1MB)
            stride: Step size between windows (default 512KB)

        """
        self.window_size: int = window_size
        self.stride: int = stride
        self.global_byte_counts: defaultdict[int, int] = defaultdict(int)
        self.total_bytes: int = 0
        self.entropy_windows: list[EntropyWindow] = []
        self.high_entropy_regions: list[dict[str, Any]] = []

    def initialize_analysis(self, file_path: Path) -> None:
        """Initialize analyzer before entropy analysis begins.

        Args:
            file_path: Path to binary being analyzed

        """
        self.global_byte_counts = defaultdict(int)
        self.total_bytes = 0
        self.entropy_windows = []
        self.high_entropy_regions = []
        logger.info(f"Initialized streaming entropy analysis for: {file_path}")

    def analyze_chunk(self, context: ChunkContext) -> dict[str, Any]:
        """Analyze entropy in a single chunk.

        Args:
            context: Chunk context with data and metadata

        Returns:
            Partial entropy analysis for this chunk

        """
        try:
            chunk_data = context.data
            chunk_offset = context.offset

            byte_counts = defaultdict(int)
            for byte in chunk_data:
                byte_counts[byte] += 1
                self.global_byte_counts[byte] += 1
                self.total_bytes += 1

            chunk_entropy = self._calculate_entropy(byte_counts, len(chunk_data))

            unique_bytes = len(byte_counts)
            printable_count = sum(bool(32 <= byte <= 126) for byte in chunk_data)
            null_count = byte_counts.get(0, 0)
            high_entropy_count = sum(bool(byte > 127) for byte in chunk_data)

            printable_ratio = printable_count / len(chunk_data) if chunk_data else 0
            null_ratio = null_count / len(chunk_data) if chunk_data else 0
            high_entropy_ratio = high_entropy_count / len(chunk_data) if chunk_data else 0

            classification = self._classify_section(chunk_entropy, printable_ratio, null_ratio)

            windows = []
            for offset in range(0, len(chunk_data) - self.window_size + 1, self.stride):
                window_data = chunk_data[offset : offset + self.window_size]
                window_byte_counts = defaultdict(int)
                for byte in window_data:
                    window_byte_counts[byte] += 1

                window_entropy = self._calculate_entropy(window_byte_counts, len(window_data))

                window = {
                    "offset": chunk_offset + offset,
                    "size": len(window_data),
                    "entropy": round(window_entropy, 4),
                    "unique_bytes": len(window_byte_counts),
                }

                windows.append(window)

                if window_entropy > self.ENTROPY_THRESHOLDS["very_high"]:
                    self.high_entropy_regions.append(
                        {
                            "offset": chunk_offset + offset,
                            "size": len(window_data),
                            "entropy": round(window_entropy, 4),
                        },
                    )

            logger.debug(
                f"Chunk {context.chunk_number}/{context.total_chunks}: Entropy={chunk_entropy:.4f}, {len(windows)} windows analyzed",
            )

            return {
                "chunk_offset": chunk_offset,
                "chunk_size": len(chunk_data),
                "chunk_entropy": round(chunk_entropy, 4),
                "unique_bytes": unique_bytes,
                "printable_ratio": round(printable_ratio, 4),
                "null_ratio": round(null_ratio, 4),
                "high_entropy_ratio": round(high_entropy_ratio, 4),
                "classification": classification,
                "windows": windows,
                "byte_counts": dict(byte_counts),
            }

        except Exception as e:
            logger.error(f"Error analyzing entropy in chunk at offset 0x{context.offset:08x}: {e}")
            return {
                "chunk_offset": context.offset,
                "chunk_size": context.size,
                "error": str(e),
                "chunk_entropy": 0.0,
            }

    def merge_results(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Merge entropy analysis results from all chunks.

        Args:
            results: List of partial results from each chunk

        Returns:
            Merged entropy analysis results

        """
        try:
            all_windows = []
            chunk_entropies = []
            classifications = defaultdict(int)
            errors = []

            total_printable = 0
            total_null = 0
            total_high_entropy = 0
            total_bytes_counted = 0

            for chunk_result in results:
                if "error" in chunk_result:
                    errors.append(
                        f"Chunk at 0x{chunk_result.get('chunk_offset', 0):08x}: {chunk_result['error']}",
                    )
                    continue

                chunk_entropies.append(chunk_result.get("chunk_entropy", 0.0))
                classifications[chunk_result.get("classification", "Unknown")] += 1

                all_windows.extend(chunk_result.get("windows", []))

                chunk_size = chunk_result.get("chunk_size", 0)
                total_bytes_counted += chunk_size
                total_printable += chunk_size * chunk_result.get("printable_ratio", 0.0)
                total_null += chunk_size * chunk_result.get("null_ratio", 0.0)
                total_high_entropy += chunk_size * chunk_result.get("high_entropy_ratio", 0.0)

            global_entropy = self._calculate_entropy(dict(self.global_byte_counts), self.total_bytes)

            overall_printable_ratio = total_printable / total_bytes_counted if total_bytes_counted > 0 else 0
            overall_null_ratio = total_null / total_bytes_counted if total_bytes_counted > 0 else 0
            overall_high_entropy_ratio = total_high_entropy / total_bytes_counted if total_bytes_counted > 0 else 0

            entropy_distribution = self._calculate_entropy_distribution(chunk_entropies)

            merged = {
                "global_entropy": round(global_entropy, 4),
                "total_bytes": self.total_bytes,
                "unique_bytes": len(self.global_byte_counts),
                "average_chunk_entropy": round(np.mean(chunk_entropies), 4) if chunk_entropies else 0.0,
                "min_chunk_entropy": round(min(chunk_entropies), 4) if chunk_entropies else 0.0,
                "max_chunk_entropy": round(max(chunk_entropies), 4) if chunk_entropies else 0.0,
                "std_dev_entropy": round(np.std(chunk_entropies), 4) if chunk_entropies else 0.0,
                "overall_printable_ratio": round(overall_printable_ratio, 4),
                "overall_null_ratio": round(overall_null_ratio, 4),
                "overall_high_entropy_ratio": round(overall_high_entropy_ratio, 4),
                "entropy_distribution": entropy_distribution,
                "classification_distribution": dict(classifications),
                "total_windows": len(all_windows),
                "high_entropy_regions": self.high_entropy_regions[:100],
                "entropy_windows": all_windows[:1000],
            }

            if errors:
                merged["errors"] = errors

            logger.info(
                f"Merged {len(results)} chunk results: "
                f"Global entropy={global_entropy:.4f}, "
                f"{len(self.high_entropy_regions)} high-entropy regions",
            )

            return merged

        except Exception as e:
            logger.error(f"Error merging entropy results: {e}")
            return {"error": str(e), "global_entropy": 0.0}

    def finalize_analysis(self, merged_results: dict[str, Any]) -> dict[str, Any]:
        """Finalize entropy analysis with insights and recommendations.

        Args:
            merged_results: Merged results from all chunks

        Returns:
            Final analysis results with enhancements

        """
        try:
            global_entropy = merged_results.get("global_entropy", 0.0)
            high_entropy_regions = merged_results.get("high_entropy_regions", [])

            is_packed = global_entropy > self.ENTROPY_THRESHOLDS["high"]
            is_encrypted = global_entropy > self.ENTROPY_THRESHOLDS["very_high"]

            protection_indicators = []
            if is_encrypted:
                protection_indicators.append("High entropy suggests strong encryption or compression")
            if is_packed:
                protection_indicators.append("Elevated entropy indicates possible packing")

            if len(high_entropy_regions) > 10:
                protection_indicators.append(f"Multiple high-entropy regions ({len(high_entropy_regions)}) detected")

            byte_usage_efficiency = len(self.global_byte_counts) / 256.0

            merged_results |= {
                "is_packed": is_packed,
                "is_encrypted": is_encrypted,
                "protection_indicators": protection_indicators,
                "byte_usage_efficiency": round(byte_usage_efficiency, 4),
                "randomness_score": round((global_entropy / 8.0) * 100, 2),
                "summary": self._generate_summary(merged_results),
                "recommendations": self._generate_recommendations(merged_results),
            }

            logger.info(
                f"Finalized entropy analysis: "
                f"Packed={is_packed}, Encrypted={is_encrypted}, "
                f"Randomness={merged_results['randomness_score']}%",
            )

            return merged_results

        except Exception as e:
            logger.error(f"Error finalizing entropy analysis: {e}")
            merged_results["finalization_error"] = str(e)
            return merged_results

    def _calculate_entropy(self, byte_counts: dict[int, int], total_bytes: int) -> float:
        """Calculate Shannon entropy for byte distribution.

        Computes the Shannon entropy H = -sum(p_i * log2(p_i)) where p_i is
        the probability of byte value i. Entropy ranges from 0 (all bytes
        identical) to 8 (perfectly random distribution).

        Args:
            byte_counts: Dictionary mapping byte values (0-255) to occurrence counts
            total_bytes: Total number of bytes in the distribution

        Returns:
            Shannon entropy value between 0.0 and 8.0 bits

        """
        if total_bytes == 0:
            return 0.0

        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)

        return entropy

    def _classify_section(self, entropy: float, printable_ratio: float, null_ratio: float) -> str:
        """Classify binary section based on entropy and content characteristics.

        Uses heuristics to identify code, data, strings, padding, and encrypted
        sections based on entropy distribution and byte patterns. Supports
        detection of packing and encryption protection mechanisms.

        Args:
            entropy: Shannon entropy value (0.0-8.0 bits)
            printable_ratio: Proportion of ASCII printable bytes (0.0-1.0)
            null_ratio: Proportion of null bytes (0.0-1.0)

        Returns:
            Classification string describing section type

        """
        if null_ratio > 0.9:
            return "Empty/Padding"
        if entropy > self.ENTROPY_THRESHOLDS["very_high"]:
            return "Encrypted/Compressed"
        if entropy < self.ENTROPY_THRESHOLDS["very_low"]:
            return "Highly Repetitive"
        if printable_ratio > 0.8:
            return "Text/Strings"
        if printable_ratio < 0.1 and entropy > self.ENTROPY_THRESHOLDS["medium"]:
            return "Code/Binary Data"
        if self.ENTROPY_THRESHOLDS["low"] <= entropy < self.ENTROPY_THRESHOLDS["medium"]:
            return "Structured Binary"
        return "Mixed Content"

    def _calculate_entropy_distribution(self, entropies: list[float]) -> dict[str, int]:
        """Calculate distribution of entropy values across predefined thresholds.

        Categorizes entropy measurements into buckets (very_low, low, medium,
        high, very_high) to provide statistical summary of protection types.

        Args:
            entropies: List of entropy values from analyzed chunks

        Returns:
            Dictionary mapping threshold names to counts of values in each range

        """
        distribution = {"very_low": 0, "low": 0, "medium": 0, "high": 0, "very_high": 0}

        for entropy in entropies:
            if entropy < self.ENTROPY_THRESHOLDS["very_low"]:
                distribution["very_low"] += 1
            elif entropy < self.ENTROPY_THRESHOLDS["low"]:
                distribution["low"] += 1
            elif entropy < self.ENTROPY_THRESHOLDS["medium"]:
                distribution["medium"] += 1
            elif entropy < self.ENTROPY_THRESHOLDS["high"]:
                distribution["high"] += 1
            else:
                distribution["very_high"] += 1

        return distribution

    def _generate_summary(self, results: dict[str, Any]) -> str:
        """Generate human-readable summary of entropy analysis findings.

        Composes narrative description of entropy patterns detected, including
        identification of encryption, packing, and compression mechanisms that
        may be used as licensing protection.

        Args:
            results: Merged analysis results dictionary

        Returns:
            Human-readable summary string with key findings

        """
        global_entropy = results.get("global_entropy", 0.0)
        randomness = results.get("randomness_score", 0.0)
        is_packed = results.get("is_packed", False)
        is_encrypted = results.get("is_encrypted", False)

        summary = f"Global entropy: {global_entropy:.4f} (Randomness: {randomness}%). "

        if is_encrypted:
            summary += "Binary appears to be encrypted or heavily compressed. "
        elif is_packed:
            summary += "Binary shows signs of packing or obfuscation. "
        else:
            summary += "Binary has normal entropy distribution. "

        high_entropy_count = len(results.get("high_entropy_regions", []))
        if high_entropy_count > 0:
            summary += f"Detected {high_entropy_count} high-entropy regions. "

        return summary

    def _generate_recommendations(self, results: dict[str, Any]) -> list[str]:
        """Generate actionable recommendations for further analysis.

        Provides next steps for analyzing identified protection mechanisms,
        including unpacking strategies, dynamic analysis techniques, and
        decryption routine examination.

        Args:
            results: Merged analysis results dictionary

        Returns:
            List of recommendation strings for further investigation

        """
        recommendations = []

        if results.get("is_encrypted"):
            recommendations.extend(
                (
                    "Use unpacking tools before static analysis",
                    "Consider dynamic analysis to capture unpacked code",
                    "Check for custom decryption routines",
                )
            )
        if results.get("is_packed"):
            recommendations.extend(
                (
                    "Identify packer type using signature detection",
                    "Apply appropriate unpacking technique",
                )
            )
        high_entropy_regions = results.get("high_entropy_regions", [])
        if len(high_entropy_regions) > 20:
            recommendations.extend(
                (
                    "Multiple high-entropy regions suggest layered protection",
                    "Examine each region individually for crypto/packing",
                )
            )
        return recommendations


def analyze_entropy_streaming(
    binary_path: Path,
    window_size: int = 1024 * 1024,
    stride: int = 512 * 1024,
    progress_callback: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    """Perform streaming entropy analysis on large binary.

    Analyzes entropy distribution across a binary file without loading it
    entirely into memory. Detects compression, encryption, packing, and
    other protection mechanisms by examining Shannon entropy patterns.

    Args:
        binary_path: Path to binary file to analyze
        window_size: Size of sliding window for entropy calculation (default 1MB)
        stride: Step size between windows (default 512KB)
        progress_callback: Optional callback function for progress updates
            taking (current: int, total: int) parameters

    Returns:
        Complete entropy analysis results including global entropy, distribution,
        classification, high-entropy regions, and recommendations

    Raises:
        Exception: If file not found or analysis encounters errors

    """
    try:
        binary_path = Path(binary_path)

        if not binary_path.exists():
            return {"error": f"File not found: {binary_path}", "status": "failed"}

        analyzer = StreamingEntropyAnalyzer(window_size=window_size, stride=stride)

        manager = StreamingAnalysisManager()

        if progress_callback:
            manager.register_progress_callback(progress_callback)

        return manager.analyze_streaming(binary_path, analyzer)
    except Exception as e:
        logger.error(f"Streaming entropy analysis failed: {e}")
        return {"error": str(e), "status": "failed"}
