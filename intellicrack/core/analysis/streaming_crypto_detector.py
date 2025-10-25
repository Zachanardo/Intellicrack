"""Streaming Cryptographic Routine Detector for Large Binaries.

Production-ready streaming-enabled cryptographic detection for multi-GB executables.
Extends CryptographicRoutineDetector with chunk-based processing and result merging.

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
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from intellicrack.core.analysis.cryptographic_routine_detector import (
    CryptoDetection,
    CryptographicRoutineDetector,
)
from intellicrack.core.processing.streaming_analysis_manager import (
    ChunkContext,
    StreamingAnalysisManager,
    StreamingAnalyzer,
)

logger = logging.getLogger(__name__)


@dataclass
class ChunkCryptoResults:
    """Results from cryptographic detection in a single chunk."""

    chunk_offset: int
    chunk_size: int
    detections: list[CryptoDetection] = field(default_factory=list)
    constants_found: list[dict[str, Any]] = field(default_factory=list)
    algorithm_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))


class StreamingCryptoDetector(StreamingAnalyzer):
    """Streaming analyzer for cryptographic routine detection in large binaries."""

    def __init__(self, quick_mode: bool = False, use_radare2: bool = False):
        """Initialize streaming crypto detector.

        Args:
            quick_mode: Skip expensive analysis for faster processing
            use_radare2: Enable radare2 integration for enhanced analysis

        """
        self.quick_mode = quick_mode
        self.use_radare2 = use_radare2
        self.detector = CryptographicRoutineDetector()
        self.binary_path: Optional[Path] = None
        self.global_detections: list[CryptoDetection] = []
        self.detection_offsets: set[int] = set()

    def initialize_analysis(self, file_path: Path) -> None:
        """Initialize detector before chunk processing begins.

        Args:
            file_path: Path to binary being analyzed

        """
        self.binary_path = file_path
        self.global_detections = []
        self.detection_offsets = set()
        logger.info(f"Initialized streaming crypto detection for: {file_path}")

    def analyze_chunk(self, context: ChunkContext) -> dict[str, Any]:
        """Analyze a single chunk for cryptographic routines.

        Args:
            context: Chunk context with data and metadata

        Returns:
            Partial detection results for this chunk

        """
        try:
            search_data = context.overlap_before + context.data + context.overlap_after
            effective_offset = context.offset - len(context.overlap_before)

            detections = self.detector.detect_all(
                data=search_data,
                base_addr=effective_offset,
                use_radare2=False,
                quick_mode=self.quick_mode,
            )

            filtered_detections = []
            constants_found = []
            algorithm_counts = defaultdict(int)

            for detection in detections:
                actual_offset = detection.offset

                if actual_offset < context.offset or actual_offset >= context.offset + context.size:
                    continue

                if actual_offset in self.detection_offsets:
                    continue

                self.detection_offsets.add(actual_offset)
                filtered_detections.append(detection)
                algorithm_counts[detection.algorithm.name] += 1

                constants_found.append(
                    {
                        "offset": actual_offset,
                        "algorithm": detection.algorithm.name,
                        "variant": detection.variant,
                        "confidence": detection.confidence,
                    }
                )

            logger.debug(
                f"Chunk {context.chunk_number}/{context.total_chunks}: "
                f"Found {len(filtered_detections)} crypto routines at offset 0x{context.offset:08x}"
            )

            return {
                "chunk_offset": context.offset,
                "chunk_size": context.size,
                "detections": [self._serialize_detection(d) for d in filtered_detections],
                "constants_found": constants_found,
                "algorithm_counts": dict(algorithm_counts),
            }

        except Exception as e:
            logger.error(f"Error analyzing chunk at offset 0x{context.offset:08x}: {e}")
            return {
                "chunk_offset": context.offset,
                "chunk_size": context.size,
                "error": str(e),
                "detections": [],
                "constants_found": [],
                "algorithm_counts": {},
            }

    def merge_results(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Merge detection results from all chunks.

        Args:
            results: List of partial results from each chunk

        Returns:
            Merged detection results

        """
        try:
            all_detections = []
            all_constants = []
            total_algorithm_counts = defaultdict(int)
            chunks_with_crypto = 0
            errors = []

            for chunk_result in results:
                if "error" in chunk_result:
                    errors.append(
                        f"Chunk at 0x{chunk_result.get('chunk_offset', 0):08x}: " f"{chunk_result['error']}"
                    )
                    continue

                detections = chunk_result.get("detections", [])
                if detections:
                    chunks_with_crypto += 1
                    all_detections.extend(detections)

                all_constants.extend(chunk_result.get("constants_found", []))

                for algo, count in chunk_result.get("algorithm_counts", {}).items():
                    total_algorithm_counts[algo] += count

            all_detections.sort(key=lambda d: d.get("offset", 0))

            algorithm_distribution = []
            for algo, count in sorted(total_algorithm_counts.items(), key=lambda x: x[1], reverse=True):
                algorithm_distribution.append(
                    {
                        "algorithm": algo,
                        "occurrences": count,
                        "percentage": round((count / len(all_detections)) * 100, 2) if all_detections else 0,
                    }
                )

            merged = {
                "total_detections": len(all_detections),
                "detections": all_detections,
                "constants_found": all_constants,
                "algorithm_distribution": algorithm_distribution,
                "chunks_with_crypto": chunks_with_crypto,
                "total_chunks": len(results),
                "coverage": round((chunks_with_crypto / len(results)) * 100, 2) if results else 0,
            }

            if errors:
                merged["errors"] = errors

            logger.info(
                f"Merged {len(results)} chunk results: "
                f"{len(all_detections)} total detections across "
                f"{len(total_algorithm_counts)} algorithm types"
            )

            return merged

        except Exception as e:
            logger.error(f"Error merging detection results: {e}")
            return {"error": str(e), "total_detections": 0, "detections": []}

    def finalize_analysis(self, merged_results: dict[str, Any]) -> dict[str, Any]:
        """Finalize analysis with post-processing and enhanced metadata.

        Args:
            merged_results: Merged results from all chunks

        Returns:
            Final analysis results with enhancements

        """
        try:
            detections = merged_results.get("detections", [])

            licensing_relevant = []
            for detection in detections:
                algo = detection.get("algorithm", "")
                if algo in ["RSA", "AES", "ECC", "SHA256", "SHA512"]:
                    licensing_relevant.append(detection)

            unique_algorithms = list(set(d.get("algorithm", "") for d in detections))

            key_sizes = defaultdict(list)
            for detection in detections:
                if detection.get("key_size"):
                    key_sizes[detection["algorithm"]].append(detection["key_size"])

            complexity_score = self._calculate_complexity_score(merged_results)

            merged_results.update(
                {
                    "licensing_relevant_crypto": licensing_relevant,
                    "unique_algorithms": unique_algorithms,
                    "key_size_analysis": dict(key_sizes),
                    "complexity_score": complexity_score,
                    "analysis_summary": self._generate_summary(merged_results),
                }
            )

            logger.info(
                f"Finalized analysis: {len(unique_algorithms)} unique algorithms, "
                f"{len(licensing_relevant)} licensing-relevant routines"
            )

            return merged_results

        except Exception as e:
            logger.error(f"Error finalizing analysis: {e}")
            merged_results["finalization_error"] = str(e)
            return merged_results

    def _serialize_detection(self, detection: CryptoDetection) -> dict[str, Any]:
        """Convert CryptoDetection to serializable dictionary.

        Args:
            detection: CryptoDetection object

        Returns:
            Serializable dictionary representation

        """
        return {
            "algorithm": detection.algorithm.name,
            "offset": detection.offset,
            "size": detection.size,
            "confidence": detection.confidence,
            "variant": detection.variant,
            "key_size": detection.key_size,
            "mode": detection.mode,
            "details": detection.details,
            "code_refs": detection.code_refs[:10] if detection.code_refs else [],
            "data_refs": detection.data_refs[:10] if detection.data_refs else [],
        }

    def _calculate_complexity_score(self, results: dict[str, Any]) -> float:
        """Calculate cryptographic complexity score.

        Args:
            results: Merged detection results

        Returns:
            Complexity score (0-100)

        """
        score = 0.0

        num_algorithms = len(results.get("unique_algorithms", []))
        score += min(num_algorithms * 10, 40)

        total_detections = results.get("total_detections", 0)
        if total_detections > 50:
            score += 30
        elif total_detections > 20:
            score += 20
        elif total_detections > 5:
            score += 10

        licensing_relevant = results.get("licensing_relevant_crypto", [])
        if licensing_relevant:
            score += min(len(licensing_relevant) * 5, 30)

        return min(score, 100.0)

    def _generate_summary(self, results: dict[str, Any]) -> str:
        """Generate human-readable analysis summary.

        Args:
            results: Merged detection results

        Returns:
            Summary string

        """
        total = results.get("total_detections", 0)
        algorithms = results.get("unique_algorithms", [])
        licensing = len(results.get("licensing_relevant_crypto", []))

        summary = f"Detected {total} cryptographic routines across {len(algorithms)} algorithm types. "

        if licensing > 0:
            summary += f"{licensing} routines are relevant to licensing systems. "

        dist = results.get("algorithm_distribution", [])
        if dist:
            top_algo = dist[0]
            summary += f"Most common: {top_algo['algorithm']} ({top_algo['occurrences']} occurrences). "

        return summary


def analyze_crypto_streaming(
    binary_path: Path,
    quick_mode: bool = False,
    use_radare2: bool = False,
    progress_callback: Optional[Any] = None,
) -> dict[str, Any]:
    """Perform streaming cryptographic analysis on large binary.

    Args:
        binary_path: Path to binary file
        quick_mode: Skip expensive analysis for faster processing
        use_radare2: Enable radare2 integration
        progress_callback: Optional callback for progress updates

    Returns:
        Complete cryptographic analysis results

    """
    try:
        binary_path = Path(binary_path)

        if not binary_path.exists():
            return {"error": f"File not found: {binary_path}", "status": "failed"}

        analyzer = StreamingCryptoDetector(quick_mode=quick_mode, use_radare2=use_radare2)

        manager = StreamingAnalysisManager()

        if progress_callback:
            manager.register_progress_callback(progress_callback)

        checkpoint_path = binary_path.parent / f".{binary_path.name}.crypto_checkpoint.json"

        results = manager.analyze_streaming(binary_path, analyzer, checkpoint_path=checkpoint_path)

        if checkpoint_path.exists():
            try:
                checkpoint_path.unlink()
            except Exception as e:
                logger.debug(f"Failed to delete checkpoint file: {e}")

        return results

    except Exception as e:
        logger.error(f"Streaming crypto analysis failed: {e}")
        return {"error": str(e), "status": "failed"}
