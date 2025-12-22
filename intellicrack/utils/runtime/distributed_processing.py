"""Distributed processing utility functions.

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

from __future__ import annotations

import contextlib
import json
import logging
import multiprocessing
import os
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from intellicrack.handlers.torch_handler import TORCH_AVAILABLE, torch
from intellicrack.utils.type_safety import get_typed_item, validate_type

from ..analysis.entropy_utils import calculate_byte_entropy


if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType


def _check_torch_available() -> bool:
    """Return TORCH_AVAILABLE in a way that prevents mypy type narrowing."""
    return TORCH_AVAILABLE


logger = logging.getLogger(__name__)


def _is_torch_cuda_available() -> bool:
    """Check if torch CUDA is available at runtime.

    This function exists to prevent mypy from statically narrowing
    the TORCH_AVAILABLE and torch checks, which causes false
    'unreachable code' errors.
    """
    if not _check_torch_available():
        return False
    torch_mod: Any = torch
    if torch_mod is None:
        return False
    try:
        return bool(torch_mod.cuda.is_available())
    except Exception:
        return False


NUMPY_AVAILABLE: bool = False
np: ModuleType | None = None

try:
    from intellicrack.handlers.numpy_handler import (
        HAS_NUMPY as NUMPY_AVAILABLE,
        numpy as np,
    )
except ImportError as e:
    logger.exception("Import error in distributed_processing: %s", e)
    NUMPY_AVAILABLE = False
    np = None

GPU_AUTOLOADER_AVAILABLE: bool = False
_get_device: Callable[[], str | None] | None = None
_get_gpu_info: Callable[[], dict[str, Any]] | None = None
_to_device: Callable[[Any], Any] | None = None
_gpu_autoloader: Any = None

with contextlib.suppress(ImportError):
    from ..gpu_autoloader import (
        get_device as _imported_get_device,
        get_gpu_info as _imported_get_gpu_info,
        gpu_autoloader as _imported_gpu_autoloader,
        to_device as _imported_to_device,
    )

    GPU_AUTOLOADER_AVAILABLE = True
    _get_device = cast("Callable[[], str | None]", _imported_get_device)
    _get_gpu_info = cast("Callable[[], dict[str, Any]]", _imported_get_gpu_info)
    _to_device = cast("Callable[[Any], Any]", _imported_to_device)
    _gpu_autoloader = _imported_gpu_autoloader


def _get_torch_memory_allocated() -> int:
    """Get torch CUDA memory allocated in bytes."""
    if not _is_torch_cuda_available():
        return 0
    torch_mod: Any = torch
    if torch_mod is None:
        return 0
    try:
        return int(torch_mod.cuda.memory_allocated())
    except Exception:
        return 0


def _get_torch_memory_reserved() -> int:
    """Get torch CUDA memory reserved in bytes."""
    if not _is_torch_cuda_available():
        return 0
    torch_mod: Any = torch
    if torch_mod is None:
        return 0
    try:
        return int(torch_mod.cuda.memory_reserved())
    except Exception:
        return 0


def _torch_empty_cache() -> None:
    """Clear torch CUDA cache."""
    if not _is_torch_cuda_available():
        return
    torch_mod: Any = torch
    if torch_mod is None:
        return
    with contextlib.suppress(Exception):
        torch_mod.cuda.empty_cache()


def process_binary_chunks(
    binary_path: str,
    chunk_size: int = 1024 * 1024,
    processor_func: Callable[[bytes, dict[str, Any]], dict[str, Any]] | None = None,
    num_workers: int | None = None,
) -> dict[str, Any]:
    """Process a binary file in chunks using multiple workers.

    Args:
        binary_path: Path to the binary file
        chunk_size: Size of each chunk in bytes
        processor_func: Function to process each chunk
        num_workers: Number of worker processes

    Returns:
        Dict containing processing results

    """
    if num_workers is None:
        num_workers = multiprocessing.cpu_count()

    if processor_func is None:
        processor_func = _default_chunk_processor

    results: dict[str, Any] = {
        "file": binary_path,
        "file_size": os.path.getsize(binary_path),
        "chunk_size": chunk_size,
        "num_workers": num_workers,
        "chunks_processed": 0,
        "processing_time": 0,
        "chunk_results": [],
    }

    if _is_torch_cuda_available():
        initial_gpu_memory = {
            "allocated_mb": _get_torch_memory_allocated() / (1024 * 1024),
            "reserved_mb": _get_torch_memory_reserved() / (1024 * 1024),
        }
        results["initial_gpu_memory"] = initial_gpu_memory

    start_time = time.time()

    try:
        file_size: int = get_typed_item(results, "file_size", int)
        chunks: list[dict[str, int]] = []

        for offset in range(0, file_size, chunk_size):
            chunk_info: dict[str, int] = {
                "index": len(chunks),
                "offset": offset,
                "size": min(chunk_size, file_size - offset),
            }
            chunks.append(chunk_info)

        results["total_chunks"] = len(chunks)

        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            future_to_chunk = {executor.submit(process_chunk, binary_path, chunk, processor_func): chunk for chunk in chunks}

            chunk_results_list: list[dict[str, Any]] = validate_type(results["chunk_results"], list)
            for future in as_completed(future_to_chunk):
                chunk = future_to_chunk[future]
                try:
                    chunk_result = future.result()
                    chunk_results_list.append(chunk_result)
                    current_processed = get_typed_item(results, "chunks_processed", int)
                    results["chunks_processed"] = current_processed + 1
                except (OSError, ValueError, RuntimeError) as e:
                    logger.exception("Error processing chunk %s: %s", chunk["index"], e)
                    chunk_results_list.append(
                        {
                            "chunk": chunk,
                            "error": str(e),
                        },
                    )

        results["processing_time"] = time.time() - start_time

        if _is_torch_cuda_available():
            final_gpu_memory = {
                "allocated_mb": _get_torch_memory_allocated() / (1024 * 1024),
                "reserved_mb": _get_torch_memory_reserved() / (1024 * 1024),
            }
            results["final_gpu_memory"] = final_gpu_memory

            if "initial_gpu_memory" in results:
                initial_mem: dict[str, float] = validate_type(results["initial_gpu_memory"], dict)
                results["gpu_memory_delta"] = {
                    "allocated_delta_mb": final_gpu_memory["allocated_mb"] - initial_mem["allocated_mb"],
                    "reserved_delta_mb": final_gpu_memory["reserved_mb"] - initial_mem["reserved_mb"],
                }

        results["aggregated"] = _aggregate_chunk_results(chunk_results_list)

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in binary chunk processing: %s", e)
        results["error"] = str(e)

        _torch_empty_cache()

    return results


def process_chunk(
    binary_path: str,
    chunk_info: dict[str, int],
    processor_func: Callable[[bytes, dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """Process a single chunk of a binary file.

    Args:
        binary_path: Path to the binary file
        chunk_info: Information about the chunk
        processor_func: Function to process the chunk

    Returns:
        Dict containing chunk processing results

    """
    try:
        with open(binary_path, "rb") as f:
            f.seek(chunk_info["offset"])
            data = f.read(chunk_info["size"])

        result = processor_func(data, validate_type(chunk_info, dict))

        return {
            "chunk": chunk_info,
            "result": result,
            "success": True,
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in distributed_processing: %s", e)
        return {
            "chunk": chunk_info,
            "error": str(e),
            "success": False,
        }


def process_distributed_results(
    results: list[dict[str, Any]],
    aggregation_func: Callable[[list[dict[str, Any]]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Process and aggregate results from distributed processing.

    Args:
        results: List of results from distributed workers
        aggregation_func: Function to aggregate results

    Returns:
        Dict containing aggregated results

    """
    if aggregation_func is None:
        aggregation_func = _default_aggregation

    aggregated: dict[str, Any] = {
        "total_results": len(results),
        "successful": 0,
        "failed": 0,
        "aggregated_data": {},
    }

    successful_results: list[dict[str, Any]] = []
    failed_results: list[dict[str, Any]] = []

    for result in results:
        if result.get("success", False):
            successful_results.append(result)
            current_successful = get_typed_item(aggregated, "successful", int)
            aggregated["successful"] = current_successful + 1
        else:
            failed_results.append(result)
            current_failed = get_typed_item(aggregated, "failed", int)
            aggregated["failed"] = current_failed + 1

    if successful_results:
        aggregated["aggregated_data"] = aggregation_func(successful_results)

    if failed_results:
        aggregated["errors"] = [
            {
                "chunk": r.get("chunk", {}),
                "error": r.get("error", "Unknown error"),
            }
            for r in failed_results[:10]
        ]

    return aggregated


def run_distributed_analysis(
    binary_path: str,
    analysis_type: str = "comprehensive",
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run distributed analysis on a binary.

    Args:
        binary_path: Path to the binary file
        analysis_type: Type of analysis to perform
        config: Configuration for distributed processing

    Returns:
        Dict containing analysis results

    """
    if config is None:
        config = {
            "num_workers": multiprocessing.cpu_count(),
            "chunk_size": 1024 * 1024,
            "timeout": 3600,
            "backend": "multiprocessing",
        }

    if GPU_AUTOLOADER_AVAILABLE and _gpu_autoloader is not None:
        _gpu_autoloader()

    results: dict[str, Any] = {
        "binary": binary_path,
        "analysis_type": analysis_type,
        "config": config,
        "start_time": time.time(),
        "analyses": {},
    }

    if GPU_AUTOLOADER_AVAILABLE and _get_device is not None and _get_gpu_info is not None:
        results["gpu_device"] = _get_device()
        results["gpu_info"] = _get_gpu_info()

    try:
        analysis_tasks: dict[str, Callable[[], dict[str, Any]]] = {
            "entropy": lambda: run_distributed_entropy_analysis(binary_path, config),
            "patterns": lambda: run_distributed_pattern_search(binary_path, None, config),
            "strings": lambda: _distributed_string_extraction(binary_path, config),
            "hashing": lambda: _distributed_hash_calculation(binary_path, config),
        }

        tasks_to_run: list[str]
        if analysis_type == "comprehensive":
            tasks_to_run = list(analysis_tasks.keys())
        else:
            tasks_to_run = [analysis_type] if analysis_type in analysis_tasks else []

        analyses_dict: dict[str, Any] = validate_type(results["analyses"], dict)
        with ThreadPoolExecutor(max_workers=len(tasks_to_run)) as executor:
            future_to_task = {executor.submit(analysis_tasks[task]): task for task in tasks_to_run}

            for future in as_completed(future_to_task):
                task = future_to_task[future]
                try:
                    analyses_dict[task] = future.result()
                except (OSError, ValueError, RuntimeError) as e:
                    logger.exception("Error in %s analysis: %s", task, e)
                    analyses_dict[task] = {"error": str(e)}

        results["end_time"] = time.time()
        end_time = get_typed_item(results, "end_time", float)
        start_time_val = get_typed_item(results, "start_time", float)
        results["total_time"] = end_time - start_time_val

        _torch_empty_cache()

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in distributed analysis: %s", e)
        results["error"] = str(e)

        _torch_empty_cache()

    return results


def run_distributed_entropy_analysis(
    binary_path: str,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run distributed entropy analysis on a binary.

    Args:
        binary_path: Path to the binary file
        config: Configuration for distributed processing

    Returns:
        Dict containing entropy analysis results

    """
    if config is None:
        config = {"chunk_size": 1024 * 1024, "num_workers": None}

    def entropy_processor(data: bytes, chunk_info: dict[str, Any]) -> dict[str, Any]:
        """Calculate entropy for a chunk."""
        if not data:
            return {"entropy": 0.0}

        entropy = calculate_byte_entropy(data)

        freq: dict[int, int] = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        return {
            "entropy": entropy,
            "size": len(data),
            "unique_bytes": len(freq),
            "offset": chunk_info["offset"],
        }

    chunk_size_val: int = config.get("chunk_size", 1024 * 1024)
    num_workers_val: int | None = config.get("num_workers")

    results = process_binary_chunks(
        binary_path,
        chunk_size=chunk_size_val,
        processor_func=entropy_processor,
        num_workers=num_workers_val,
    )

    if results.get("aggregated"):
        chunk_results_list = validate_type(results["chunk_results"], list)
        entropies = [r["result"]["entropy"] for r in chunk_results_list if r.get("success") and "entropy" in r.get("result", {})]

        if entropies:
            results["statistics"] = {
                "average_entropy": sum(entropies) / len(entropies),
                "max_entropy": max(entropies),
                "min_entropy": min(entropies),
                "high_entropy_chunks": sum(e > 7.0 for e in entropies),
            }

            if results["statistics"]["average_entropy"] > 7.0:
                results["indicators"] = ["Possible packing or encryption detected"]

    return results


def run_distributed_pattern_search(
    binary_path: str,
    patterns: list[bytes] | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run distributed pattern search on a binary.

    Args:
        binary_path: Path to the binary file
        patterns: List of byte patterns to search for
        config: Configuration for distributed processing

    Returns:
        Dict containing pattern search results

    """
    if patterns is None:
        patterns = [
            b"license",
            b"LICENSE",
            b"License",
            b"trial",
            b"TRIAL",
            b"Trial",
            b"expire",
            b"EXPIRE",
            b"Expire",
            b"crack",
            b"CRACK",
            b"patch",
            b"PATCH",
            b"keygen",
            b"KEYGEN",
            b"serial",
            b"SERIAL",
        ]

    if config is None:
        config = {"chunk_size": 1024 * 1024, "num_workers": None}

    patterns_to_search = patterns

    def pattern_processor(data: bytes, chunk_info: dict[str, Any]) -> dict[str, Any]:
        """Search for _patterns in a chunk."""
        found_patterns: list[dict[str, Any]] = []

        for pattern in patterns_to_search:
            from ..binary.binary_io import find_all_pattern_offsets

            offsets = find_all_pattern_offsets(data, pattern)
            chunk_offset: int = chunk_info["offset"]
            for pos in offsets:
                found_patterns.append(
                    {
                        "pattern": pattern.hex(),
                        "pattern_text": pattern.decode("utf-8", errors="ignore"),
                        "offset": chunk_offset + pos,
                        "context_before": data[max(0, pos - 10) : pos].hex(),
                        "context_after": data[pos + len(pattern) : pos + len(pattern) + 10].hex(),
                    },
                )

        return {
            "patterns_found": len(found_patterns),
            "matches": found_patterns[:100],
        }

    chunk_size_val: int = config.get("chunk_size", 1024 * 1024)
    num_workers_val: int | None = config.get("num_workers")

    results = process_binary_chunks(
        binary_path,
        chunk_size=chunk_size_val,
        processor_func=pattern_processor,
        num_workers=num_workers_val,
    )

    all_matches: list[dict[str, Any]] = []
    chunk_results_list = validate_type(results.get("chunk_results", []), list)
    for chunk_result in chunk_results_list:
        if chunk_result.get("success") and "matches" in chunk_result.get("result", {}):
            all_matches.extend(chunk_result["result"]["matches"])

    pattern_summary: dict[str, dict[str, Any]] = {}
    for match in all_matches:
        pattern_text = match["pattern_text"]
        if pattern_text not in pattern_summary:
            pattern_summary[pattern_text] = {
                "count": 0,
                "first_offset": match["offset"],
                "offsets": [],
            }
        pattern_summary[pattern_text]["count"] += 1
        pattern_summary[pattern_text]["offsets"].append(match["offset"])

    results["pattern_summary"] = pattern_summary
    results["total_matches"] = len(all_matches)

    return results


def extract_binary_info(binary_path: str) -> dict[str, Any]:
    """Extract basic information from a binary file.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing binary information

    """
    info: dict[str, Any] = {
        "path": binary_path,
        "size": os.path.getsize(binary_path),
        "name": os.path.basename(binary_path),
    }

    try:
        stat = Path(binary_path).stat()
        info["created"] = time.ctime(stat.st_ctime)
        info["modified"] = time.ctime(stat.st_mtime)

        import hashlib

        sha256 = hashlib.sha256()

        with open(binary_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)

        info["sha256"] = sha256.hexdigest()

        with open(binary_path, "rb") as f:
            magic = f.read(4)

        if magic[:2] == b"MZ":
            info["format"] = "PE"
        elif magic == b"\x7fELF":
            info["format"] = "ELF"
        elif magic in [b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"]:
            info["format"] = "Mach-O"
        else:
            info["format"] = "Unknown"

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error extracting binary info: %s", e)
        info["error"] = str(e)

    return info


def extract_binary_features(binary_path: str) -> dict[str, Any]:
    """Extract features from a binary for analysis.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing extracted features

    """
    features: dict[str, Any] = {
        "file_size": 0,
        "entropy": 0.0,
        "strings_count": 0,
        "imports_count": 0,
        "sections_count": 0,
    }

    try:
        features["file_size"] = os.path.getsize(binary_path)

        entropy_result = run_distributed_entropy_analysis(binary_path)
        if "statistics" in entropy_result:
            features["entropy"] = entropy_result["statistics"]["average_entropy"]

        strings_result = _distributed_string_extraction(binary_path, {"min_length": 4})
        features["strings_count"] = strings_result.get("total_strings", 0)

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error extracting features: %s", e)
        features["error"] = str(e)

    return features


def run_gpu_accelerator(
    task_type: str,
    data: dict[str, Any],
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run GPU-accelerated processing for supported tasks.

    Args:
        task_type: Type of GPU task (pattern_matching, crypto, ml_inference)
        data: Input data for processing
        config: GPU configuration

    Returns:
        Dict containing GPU processing results

    """
    results: dict[str, Any] = {
        "task_type": task_type,
        "gpu_available": False,
        "backend": "cpu",
    }

    gpu_backends = _check_gpu_backends()

    if not gpu_backends["available"]:
        results["message"] = "No GPU acceleration available, falling back to CPU"
        results["cpu_result"] = _run_cpu_fallback(task_type, data)
        return results

    results["gpu_available"] = True
    results["backend"] = gpu_backends["backend"]

    effective_config: dict[str, Any] = config if config is not None else {}

    try:
        if task_type == "pattern_matching":
            results["result"] = _gpu_pattern_matching(data, effective_config)
        elif task_type == "crypto":
            results["result"] = _gpu_crypto_operations(data, effective_config)
        elif task_type == "ml_inference":
            results["result"] = _gpu_ml_inference(data, effective_config)
        else:
            results["error"] = f"Unsupported GPU task type: {task_type}"

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("GPU acceleration error: %s", e)
        results["error"] = str(e)
        results["cpu_result"] = _run_cpu_fallback(task_type, data)

    return results


def run_incremental_analysis(
    binary_path: str,
    cache_dir: str | None = None,
    force_full: bool = False,
) -> dict[str, Any]:
    """Run incremental analysis using cached results when possible.

    Args:
        binary_path: Path to the binary file
        cache_dir: Directory for cache storage
        force_full: Force full analysis ignoring cache

    Returns:
        Dict containing analysis results

    """
    if cache_dir is None:
        cache_dir = os.path.join(os.path.dirname(binary_path), ".intellicrack_cache")

    results: dict[str, Any] = {
        "binary": binary_path,
        "cache_dir": cache_dir,
        "cached_results": {},
        "new_results": {},
        "cache_hits": 0,
        "cache_misses": 0,
    }

    import hashlib

    with open(binary_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    results["file_hash"] = file_hash

    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, f"{file_hash}.json")

    cached_results_dict: dict[str, Any] = validate_type(results["cached_results"], dict)
    if os.path.exists(cache_file) and not force_full:
        try:
            with open(cache_file, encoding="utf-8") as f:
                cached_data = json.load(f)

            if cached_data.get("file_size") == os.path.getsize(binary_path):
                cached_results_dict |= cached_data.get("analyses", {})
                results["cache_hits"] = len(cached_results_dict)

        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Error loading cache: %s", e)

    required_analyses = ["entropy", "patterns", "strings", "features"]
    analyses_to_run: list[str] = []

    for analysis in required_analyses:
        if analysis not in cached_results_dict:
            analyses_to_run.append(analysis)
            current_misses = get_typed_item(results, "cache_misses", int)
            results["cache_misses"] = current_misses + 1

    new_results_dict: dict[str, Any] = validate_type(results["new_results"], dict)
    if analyses_to_run:
        new_analyses = run_distributed_analysis(
            binary_path,
            analysis_type="comprehensive",
        )

        new_results_dict |= new_analyses.get("analyses", {})

        all_results: dict[str, Any] = cached_results_dict | new_results_dict

        cache_data = {
            "file_hash": file_hash,
            "file_size": os.path.getsize(binary_path),
            "timestamp": time.time(),
            "analyses": all_results,
        }

        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2)
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error saving cache: %s", e)

    results["all_results"] = cached_results_dict | new_results_dict

    return results


def run_memory_optimized_analysis(
    binary_path: str,
    max_memory_mb: int = 1024,
) -> dict[str, Any]:
    """Run memory-optimized analysis for large binaries.

    Args:
        binary_path: Path to the binary file
        max_memory_mb: Maximum memory to use in MB

    Returns:
        Dict containing analysis results

    """
    file_size = os.path.getsize(binary_path)

    available_memory = max_memory_mb * 1024 * 1024 * 0.5
    num_workers = multiprocessing.cpu_count()
    chunk_size = int(available_memory / num_workers)

    chunk_size = max(1024 * 1024, min(chunk_size, 100 * 1024 * 1024))

    results: dict[str, Any] = {
        "binary": binary_path,
        "file_size": file_size,
        "max_memory_mb": max_memory_mb,
        "chunk_size": chunk_size,
        "num_workers": num_workers,
    }

    config: dict[str, Any] = {
        "chunk_size": chunk_size,
        "num_workers": num_workers,
        "memory_limit": max_memory_mb,
    }

    results["analysis"] = run_distributed_analysis(binary_path, config=config)

    return results


def run_pdf_report_generator(
    analysis_results: dict[str, Any],
    output_path: str | None = None,
) -> dict[str, Any]:
    """Generate a PDF report from analysis results.

    Args:
        analysis_results: Results from binary analysis
        output_path: Path for output PDF

    Returns:
        Dict containing report generation status

    """
    if output_path is None:
        output_path = "intellicrack_report.pdf"

    results: dict[str, Any] = {
        "output_path": output_path,
        "status": "pending",
    }

    try:
        from intellicrack.core.reporting.pdf_generator import PDFReportGenerator

        generator = PDFReportGenerator()

        if "binary" in analysis_results:
            generator.add_section("Binary Information", str(analysis_results.get("binary", {})))

        analyses_data = analysis_results.get("analyses")
        if isinstance(analyses_data, dict):
            for analysis_type, data in analyses_data.items():
                generator.add_section(f"{analysis_type.title()} Analysis", str(data))

        generator.generate_report(output_path=output_path)

        results["status"] = "success"
        results["message"] = f"Report generated: {output_path}"

    except ImportError as e:
        logger.exception("Import error in distributed_processing: %s", e)
        results["status"] = "error"
        results["message"] = "PDF generation not available"
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error generating PDF report: %s", e)
        results["status"] = "error"
        results["message"] = str(e)

    return results


def _default_chunk_processor(data: bytes, chunk_info: dict[str, Any]) -> dict[str, Any]:
    """Calculate basic statistics for a data chunk.

    Args:
        data: Byte data from the chunk
        chunk_info: Dictionary containing chunk metadata

    Returns:
        Dict containing size, offset, and non-zero byte count

    """
    return {
        "size": len(data),
        "offset": chunk_info["offset"],
        "non_zero_bytes": sum(b != 0 for b in data),
    }


def _default_aggregation(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate results from multiple chunk processing operations.

    Args:
        results: List of chunk processing results

    Returns:
        Dict containing aggregated totals and processing counts

    """
    total_size = 0
    total_non_zero = 0

    for result in results:
        if "result" in result:
            result_data = result["result"]
            total_size += result_data.get("size", 0)
            total_non_zero += result_data.get("non_zero_bytes", 0)

    return {
        "total_size": total_size,
        "total_non_zero_bytes": total_non_zero,
        "chunks_processed": len(results),
    }


def _aggregate_chunk_results(chunk_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate results from chunk processing operations.

    Args:
        chunk_results: List of chunk processing results

    Returns:
        Dict containing aggregated results or error if no successful chunks

    """
    if successful := [r for r in chunk_results if r.get("success")]:
        return _default_aggregation(successful)
    else:
        return {"error": "No successful chunk processing"}


def _distributed_string_extraction(
    binary_path: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Extract strings from binary using distributed processing.

    Args:
        binary_path: Path to the binary file
        config: Configuration dict with processing parameters

    Returns:
        Dict containing extracted strings and statistics

    """
    min_length: int = config.get("min_length", 4)

    def string_processor(data: bytes, chunk_info: dict[str, Any]) -> dict[str, Any]:
        """Extract printable strings from chunk."""
        strings: list[dict[str, Any]] = []
        current: list[str] = []
        current_offset = 0
        chunk_offset: int = chunk_info["offset"]

        for i, byte in enumerate(data):
            if 32 <= byte <= 126:
                if not current:
                    current_offset = i
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(
                        {
                            "text": "".join(current),
                            "offset": chunk_offset + current_offset,
                        },
                    )
                current = []

        if len(current) >= min_length:
            strings.append(
                {
                    "text": "".join(current),
                    "offset": chunk_offset + current_offset,
                },
            )

        return {
            "strings_count": len(strings),
            "strings": strings[:100],
            "chunk_offset": chunk_offset,
        }

    chunk_size_val: int = config.get("chunk_size", 1024 * 1024)
    num_workers_val: int | None = config.get("num_workers")

    results = process_binary_chunks(
        binary_path,
        chunk_size=chunk_size_val,
        processor_func=string_processor,
        num_workers=num_workers_val,
    )

    all_strings: list[dict[str, Any]] = []
    chunk_results_list = validate_type(results.get("chunk_results", []), list)
    for chunk_result in chunk_results_list:
        if chunk_result.get("success") and "strings" in chunk_result.get("result", {}):
            all_strings.extend(chunk_result["result"]["strings"])

    results["total_strings"] = len(all_strings)
    string_texts = [s.get("text", "") for s in all_strings if isinstance(s, dict)]
    results["unique_strings"] = len(set(string_texts))
    results["sample_strings"] = list(set(string_texts))[:50]

    return results


def _distributed_hash_calculation(
    binary_path: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Calculate multiple hash algorithms using distributed processing.

    Args:
        binary_path: Path to the binary file
        config: Configuration dict with hash algorithms and parameters

    Returns:
        Dict containing calculated hashes for each algorithm

    """
    import hashlib

    algorithms_config = config.get("hash_algorithms", ["md5", "sha1", "sha256", "sha512"])
    algorithms: list[str] = algorithms_config if isinstance(algorithms_config, list) else ["md5", "sha1", "sha256", "sha512"]
    chunk_size: int = config.get("chunk_size", 8192)
    max_workers_config = config.get("max_workers", len(algorithms))
    max_workers: int = max_workers_config if isinstance(max_workers_config, int) else len(algorithms)

    results: dict[str, Any] = {"hashes": {}, "config_used": config}

    def calculate_hash(algo: str) -> tuple[str, str]:
        """Calculate hash for given algorithm."""
        h = hashlib.new(algo)

        with open(binary_path, "rb") as f:
            while file_chunk := f.read(chunk_size):
                h.update(file_chunk)

        return algo, h.hexdigest()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_algo = {executor.submit(calculate_hash, algo): algo for algo in algorithms}

        hashes_dict: dict[str, str] = validate_type(results["hashes"], dict)
        for future in as_completed(future_to_algo):
            try:
                algo, hash_value = future.result()
                hashes_dict[algo] = hash_value
            except (OSError, ValueError, RuntimeError) as e:
                algo = future_to_algo[future]
                logger.exception("Error calculating %s: %s", algo, e)

    return results


def _check_gpu_backends() -> dict[str, Any]:
    """Check for available GPU acceleration backends.

    Returns:
        Dict containing GPU availability and device information

    """
    backends: dict[str, Any] = {
        "available": False,
        "backend": None,
        "devices": [],
    }

    if _is_torch_cuda_available():
        torch_mod: Any = torch
        if torch_mod is not None:
            try:
                backends["available"] = True
                backends["backend"] = "cuda"
                backends["devices"] = [f"cuda:{i}" for i in range(torch_mod.cuda.device_count())]
                return backends
            except Exception as e:
                logger.debug("CUDA backend check failed: %s", e)
    if not _check_torch_available():
        logger.debug("CUDA backend not available: PyTorch not installed")

    try:
        import pyopencl as cl

        if platforms := cl.get_platforms():
            backends["available"] = True
            backends["backend"] = "opencl"
            device_list: list[str] = cast("list[str]", backends["devices"])
            for platform in platforms:
                devices = platform.get_devices()
                device_list.extend([d.name for d in devices])
            return backends
    except ImportError:
        logger.debug("OpenCL backend not available: pyopencl not installed")

    return backends


def _run_cpu_fallback(task_type: str, data: Any) -> dict[str, Any]:
    """Execute CPU fallback processing when GPU is unavailable.

    Args:
        task_type: Type of processing task
        data: Input data for processing

    Returns:
        Dict containing CPU processing results

    """
    start_time = time.time()

    result: dict[str, Any] = {
        "backend": "cpu",
        "task_type": task_type,
        "message": "Processed on CPU",
        "data_info": {
            "type": type(data).__name__,
            "size": len(data) if hasattr(data, "__len__") else 1,
        },
    }

    if task_type == "hash_calculation" and isinstance(data, (str, bytes)):
        import hashlib

        hash_data = data.encode() if isinstance(data, str) else data
        result["cpu_hash"] = hashlib.sha256(hash_data).hexdigest()

    elif task_type == "analysis" and hasattr(data, "__len__"):
        data_len = len(data)
        result["analysis"] = {
            "item_count": data_len,
            "complexity": "low" if data_len < 1000 else "medium" if data_len < 10000 else "high",
        }

    elif task_type == "pattern_matching" and isinstance(data, (str, bytes)):
        search_str = data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else data

        patterns = ["license", "trial", "crack", "serial", "key"]
        matches = [pattern for pattern in patterns if pattern in search_str.lower()]
        result["pattern_matches"] = matches

    else:
        result["processed"] = True
        result["data_summary"] = str(data)[:100] if data else "No data"

    result["processing_time"] = time.time() - start_time
    return result


def _gpu_pattern_matching(
    data: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    """Execute GPU-accelerated pattern matching operations.

    Args:
        data: Input data containing search content
        config: Configuration with patterns and processing parameters

    Returns:
        Dict containing pattern matching results and performance metrics

    """
    start_time = time.time()
    patterns_found = 0
    backend = "cpu"

    try:
        gpu_available = False
        device_str = "cpu"

        if GPU_AUTOLOADER_AVAILABLE and _get_gpu_info is not None and _get_device is not None:
            gpu_info = _get_gpu_info()
            if gpu_info.get("available"):
                gpu_available = True
                device_result = _get_device()
                device_str = device_result if device_result is not None else "cpu"
        elif _is_torch_cuda_available():
            gpu_available = True
            device_str = "cuda"

        patterns: list[bytes] = config.get("patterns", [])
        search_data: bytes = data.get("data", b"")

        torch_mod: Any = torch
        if gpu_available and _check_torch_available() and torch_mod is not None:
            if patterns and search_data:
                device = torch_mod.device(device_str)

                data_tensor = torch_mod.tensor(list(search_data), dtype=torch_mod.uint8)
                if GPU_AUTOLOADER_AVAILABLE and _to_device is not None:
                    data_tensor = _to_device(data_tensor)
                else:
                    data_tensor = data_tensor.to(device)

                for pattern in patterns:
                    if isinstance(pattern, (bytes, bytearray)):
                        pattern_tensor = torch_mod.tensor(list(pattern), dtype=torch_mod.uint8)
                        if GPU_AUTOLOADER_AVAILABLE and _to_device is not None:
                            pattern_tensor = _to_device(pattern_tensor)
                        else:
                            pattern_tensor = pattern_tensor.to(device)
                        if len(pattern) <= len(search_data):
                            for i in range(len(search_data) - len(pattern) + 1):
                                if torch_mod.equal(data_tensor[i : i + len(pattern)], pattern_tensor):
                                    patterns_found += 1
                                    break

            backend = device_str
        else:
            for pattern in patterns:
                if pattern in search_data:
                    patterns_found += 1

            backend = "cpu"

    except ImportError as e:
        logger.exception("Import error in distributed_processing: %s", e)
        patterns_list: list[bytes] = config.get("patterns", [])
        search_bytes: bytes = data.get("data", b"")

        for pattern_ in patterns_list:
            if pattern_ in search_bytes:
                patterns_found += 1

        backend = "cpu"

    return {
        "patterns_found": patterns_found,
        "processing_time": time.time() - start_time,
        "backend": backend,
    }


def _gpu_crypto_operations(
    data: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    """Execute GPU-accelerated cryptographic operations.

    Args:
        data: Input data for cryptographic processing
        config: Configuration with operation type and parameters

    Returns:
        Dict containing cryptographic results and performance metrics

    """
    import hashlib

    operation: str = config.get("operation", "hash")
    input_data: bytes = data.get("data", b"")
    start_time = time.time()
    result_str: str
    backend: str

    try:
        import cupy as cp

        if operation == "hash":
            data_gpu = cp.asarray(list(input_data), dtype=cp.uint8)
            hash_value = int(cp.sum(data_gpu) % (2**32))
            result_str = f"{hash_value:08x}"
        else:
            result_str = hashlib.sha256(input_data).hexdigest()
        backend = "cuda"
    except ImportError as e:
        logger.exception("Import error in distributed_processing: %s", e)
        result_str = hashlib.sha256(input_data).hexdigest()
        backend = "cpu"

    return {
        "operation": operation,
        "result": result_str,
        "processing_time": time.time() - start_time,
        "backend": backend,
    }


def _gpu_ml_inference(
    data: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    """Execute GPU-accelerated machine learning inference.

    Args:
        data: Input data containing features for inference
        config: Configuration with model path and inference parameters

    Returns:
        Dict containing predictions, confidence scores and performance metrics

    """
    start_time = time.time()
    predictions: list[float] = [0.5]
    confidence: float = 0.0
    backend: str = "cpu"

    if not _check_torch_available():
        return {
            "error": "PyTorch not available",
            "backend": "cpu",
            "processing_time": time.time() - start_time,
        }

    torch_mod: Any = torch
    if torch_mod is None:
        return {
            "error": "PyTorch not available",
            "backend": "cpu",
            "processing_time": time.time() - start_time,
        }

    try:
        device_str: str
        if GPU_AUTOLOADER_AVAILABLE and _get_device is not None and _get_gpu_info is not None:
            device_result = _get_device()
            device_str = device_result if device_result is not None else "cpu"
            gpu_info = _get_gpu_info()
            backend = str(gpu_info.get("gpu_type", device_str))
        elif _is_torch_cuda_available():
            device_str = "cuda"
            backend = "cuda"
        else:
            device_str = "cpu"
            backend = "cpu"

        device = torch_mod.device(device_str)

        model_path = config.get("model_path")
        features = data.get("features", [])

        if model_path is not None and os.path.exists(str(model_path)) and features:
            model = torch_mod.load(str(model_path), map_location=device)
            model.eval()

            features_tensor = torch_mod.tensor(features, dtype=torch_mod.float32)
            if GPU_AUTOLOADER_AVAILABLE and _to_device is not None:
                features_tensor = _to_device(features_tensor)
            else:
                features_tensor = features_tensor.to(device)
            if len(features_tensor.shape) == 1:
                features_tensor = features_tensor.unsqueeze(0)

            with torch_mod.no_grad():
                output = model(features_tensor)
                if hasattr(output, "cpu"):
                    predictions = output.cpu().numpy().tolist()
                else:
                    predictions = [output.item()]

                if len(predictions) > 1 and np is not None:
                    exp_scores = np.exp(predictions)
                    confidence = float(np.max(exp_scores / np.sum(exp_scores)))
                else:
                    confidence = abs(predictions[0])
        else:
            predictions = [0.5]
            confidence = 0.0

    except (OSError, ValueError, RuntimeError) as e:
        logger.debug("GPU ML inference fallback: %s", e)
        predictions = [0.5]
        confidence = 0.0
        backend = "cpu"

    return {
        "predictions": predictions,
        "confidence": confidence,
        "processing_time": time.time() - start_time,
        "backend": backend,
    }


def run_dask_distributed_analysis(
    binary_path: str,
    analysis_func: Callable[[bytes], dict[str, Any]],
    chunk_size: int = 1024 * 1024,
    n_partitions: int | None = None,
) -> dict[str, Any]:
    """Run distributed binary analysis using Dask for large-scale processing.

    Args:
        binary_path: Path to the binary file
        analysis_func: Function to apply to each chunk
        chunk_size: Size of each chunk in bytes
        n_partitions: Number of partitions for Dask

    Returns:
        Dictionary with analysis results

    """
    try:
        import dask
        import dask.array as da
        import dask.bag as db
        from dask.distributed import (
            Client,
            as_completed as dask_as_completed,
        )
    except ImportError:
        return {
            "error": "Dask not available",
            "suggestion": "Install with: pip install dask[distributed]",
        }

    if np is None:
        return {
            "error": "NumPy not available",
            "suggestion": "Install with: pip install numpy",
        }

    start_time = time.time()
    results: dict[str, Any] = {
        "framework": "dask",
        "binary_path": binary_path,
        "chunk_size": chunk_size,
    }

    try:
        with open(binary_path, "rb") as f:
            binary_data = f.read()

        results["file_size"] = len(binary_data)

        from_array_func: Any = da.from_array
        data_array = from_array_func(np.frombuffer(binary_data, dtype=np.uint8), chunks=chunk_size)

        results["array_shape"] = data_array.shape
        results["array_chunks"] = len(data_array.chunks[0])

        if n_partitions is None:
            n_partitions = max(1, len(binary_data) // chunk_size)

        chunks: list[dict[str, Any]] = []
        for i in range(0, len(binary_data), chunk_size):
            chunk_data = binary_data[i : i + chunk_size]
            chunks.append(
                {
                    "data": chunk_data,
                    "offset": i,
                    "size": len(chunk_data),
                },
            )

        from_sequence_func: Any = db.from_sequence
        bag = from_sequence_func(chunks, npartitions=n_partitions)

        client: Client | None = None
        try:
            client_current_func: Any = Client.current
            client = client_current_func()
            results["distributed_mode"] = "existing_client"
        except ValueError:
            client = None
            results["distributed_mode"] = "local_threads"

        chunk_results: list[dict[str, Any]]
        if client is not None:
            futures = []
            for chunk_item in chunks:
                future = client.submit(
                    lambda c: {
                        "offset": c["offset"],
                        "size": c["size"],
                        "result": analysis_func(c["data"]),
                    },
                    chunk_item,
                )
                futures.append(future)

            chunk_results = []
            as_completed_func: Any = dask_as_completed
            for future in as_completed_func(futures):
                result = future.result()
                chunk_results.append(result)
        else:
            with dask.config.set(scheduler="threads"):
                analyzed = bag.map(
                    lambda chunk_item: {
                        "offset": chunk_item["offset"],
                        "size": chunk_item["size"],
                        "result": analysis_func(chunk_item["data"]),
                    },
                )

                chunk_results = list(analyzed.compute())

        results["chunk_results"] = chunk_results
        results["num_chunks"] = len(chunk_results)

        if chunk_results and "entropy" in chunk_results[0].get("result", {}):
            entropies = [r["result"]["entropy"] for r in chunk_results]
            results["entropy_stats"] = {
                "mean": float(np.mean(entropies)),
                "std": float(np.std(entropies)),
                "max": float(np.max(entropies)),
                "min": float(np.min(entropies)),
            }

        results["processing_time"] = time.time() - start_time
        results["success"] = True

    except Exception as e:
        logger.exception("Dask distributed analysis error: %s", e)
        results["error"] = str(e)
        results["success"] = False

    return results


def run_celery_distributed_analysis(
    binary_path: str,
    task_name: str = "binary_analysis",
    chunk_size: int = 1024 * 1024,
    queue_name: str = "intellicrack",
) -> dict[str, Any]:
    """Run distributed binary analysis using Celery task queue.

    Args:
        binary_path: Path to the binary file
        task_name: Name of the Celery task to execute
        chunk_size: Size of each chunk in bytes
        queue_name: Celery queue name

    Returns:
        Dictionary with analysis results

    """
    try:
        from celery import Celery, group
    except ImportError:
        return {"error": "Celery not available", "suggestion": "Install with: pip install celery"}

    if np is None:
        return {
            "error": "NumPy not available",
            "suggestion": "Install with: pip install numpy",
        }

    start_time = time.time()
    results: dict[str, Any] = {
        "framework": "celery",
        "binary_path": binary_path,
        "task_name": task_name,
        "queue_name": queue_name,
    }

    try:
        from intellicrack.utils.service_utils import get_service_url

        redis_url = get_service_url("redis_server")
        app = Celery("intellicrack", broker=f"{redis_url}/0")

        def _analyze_chunk_impl(chunk_data: dict[str, Any]) -> dict[str, Any]:
            """Analyze a binary chunk."""
            data_bytes: bytes = chunk_data["data"]
            entropy = calculate_byte_entropy(data_bytes)
            patterns_found: list[str] = []

            patterns = [b"LICENSE", b"TRIAL", b"EXPIRE", b"SERIAL"]
            for pattern in patterns:
                if pattern in data_bytes:
                    patterns_found.append(pattern.decode())

            return {
                "offset": chunk_data["offset"],
                "size": chunk_data["size"],
                "entropy": entropy,
                "patterns": patterns_found,
            }

        task_decorator: Any = app.task(name=f"intellicrack.{task_name}")
        analyze_chunk: Any = task_decorator(_analyze_chunk_impl)

        with open(binary_path, "rb") as f:
            binary_data = f.read()

        results["file_size"] = len(binary_data)

        chunks: list[dict[str, Any]] = []
        for i in range(0, len(binary_data), chunk_size):
            chunk_item: dict[str, Any] = {
                "data": binary_data[i : i + chunk_size],
                "offset": i,
                "size": min(chunk_size, len(binary_data) - i),
            }
            chunks.append(chunk_item)

        job = group(analyze_chunk.s(chunk_item) for chunk_item in chunks)
        result = job.apply_async(queue=queue_name)

        chunk_results: list[dict[str, Any]] = result.get(timeout=300)

        results["chunk_results"] = chunk_results
        results["num_chunks"] = len(chunk_results)
        results["processing_time"] = time.time() - start_time
        results["success"] = True

        if chunk_results:
            entropies = [r["entropy"] for r in chunk_results]
            results["entropy_stats"] = {
                "mean": float(np.mean(entropies)),
                "max": float(np.max(entropies)),
                "min": float(np.min(entropies)),
            }

            all_patterns: list[str] = []
            for r in chunk_results:
                all_patterns.extend(r.get("patterns", []))
            results["patterns_found"] = list(set(all_patterns))

    except Exception as e:
        logger.exception("Celery distributed analysis error: %s", e)
        results["error"] = str(e)
        results["success"] = False
        results["suggestion"] = "Ensure Celery broker (Redis/RabbitMQ) is running"

    return results


def run_joblib_parallel_analysis(
    binary_path: str,
    analysis_funcs: list[Callable[[bytes], dict[str, Any]]],
    n_jobs: int = -1,
    backend: str = "threading",
) -> dict[str, Any]:
    """Run parallel binary analysis using joblib for multi-core processing.

    Args:
        binary_path: Path to the binary file
        analysis_funcs: List of analysis functions to run in parallel
        n_jobs: Number of parallel jobs (-1 for all cores)
        backend: Joblib backend ('threading', 'multiprocessing', 'loky')

    Returns:
        Dictionary with parallel analysis results

    """
    try:
        import joblib
        from joblib import Parallel, delayed
    except ImportError:
        return {"error": "Joblib not available", "suggestion": "Install with: pip install joblib"}

    start_time = time.time()
    results: dict[str, Any] = {
        "framework": "joblib",
        "binary_path": binary_path,
        "backend": backend,
        "n_jobs": n_jobs if n_jobs != -1 else joblib.cpu_count(),
    }

    try:
        with open(binary_path, "rb") as f:
            binary_data = f.read()

        results["file_size"] = len(binary_data)

        def run_analysis(
            func: Callable[[bytes], dict[str, Any]],
            data: bytes,
            func_name: str,
        ) -> dict[str, Any]:
            """Run a single analysis function."""
            try:
                result = func(data)
                return {
                    "function": func_name,
                    "success": True,
                    "result": result,
                    "execution_time": time.time() - start_time,
                }
            except Exception as e:
                return {
                    "function": func_name,
                    "success": False,
                    "error": str(e),
                }

        with Parallel(n_jobs=n_jobs, backend=backend) as parallel:
            analysis_results: list[dict[str, Any]] = parallel(
                delayed(run_analysis)(func, binary_data, func.__name__) for func in analysis_funcs
            )

        results["analyses"] = analysis_results
        results["successful_analyses"] = sum(bool(r["success"]) for r in analysis_results)
        results["failed_analyses"] = sum(not r["success"] for r in analysis_results)

        aggregated: dict[str, Any] = {}
        for result_item in analysis_results:
            if result_item["success"] and "result" in result_item:
                func_name = result_item["function"]
                aggregated[func_name] = result_item["result"]

        results["aggregated_results"] = aggregated
        results["processing_time"] = time.time() - start_time
        results["success"] = True

    except Exception as e:
        logger.exception("Joblib parallel analysis error: %s", e)
        results["error"] = str(e)
        results["success"] = False

    return results


def run_joblib_mmap_analysis(
    binary_path: str,
    window_size: int = 4096,
    step_size: int = 1024,
    n_jobs: int = -1,
) -> dict[str, Any]:
    """Run memory-mapped parallel analysis using joblib for efficient large file processing.

    Args:
        binary_path: Path to the binary file
        window_size: Size of sliding window for analysis
        step_size: Step size for sliding window
        n_jobs: Number of parallel jobs

    Returns:
        Dictionary with memory-mapped analysis results

    """
    try:
        import mmap

        from joblib import Parallel, delayed
    except ImportError:
        return {"error": "Joblib not available", "suggestion": "Install with: pip install joblib"}

    if np is None:
        return {
            "error": "NumPy not available",
            "suggestion": "Install with: pip install numpy",
        }

    start_time = time.time()
    results: dict[str, Any] = {
        "framework": "joblib_mmap",
        "binary_path": binary_path,
        "window_size": window_size,
        "step_size": step_size,
    }

    try:
        file_size = os.path.getsize(binary_path)
        results["file_size"] = file_size

        def analyze_window(
            offset: int,
            win_size: int,
            file_path: str,
        ) -> dict[str, Any]:
            """Analyze a window of the file using memory mapping."""
            with (
                open(file_path, "rb") as f,
                mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped,
            ):
                end = min(offset + win_size, len(mmapped))
                window_data = mmapped[offset:end]

                entropy = calculate_byte_entropy(window_data)

                is_packed = entropy > 7.5

                ascii_strings: list[str] = []
                current_string = b""
                for byte in window_data:
                    if 32 <= byte <= 126:
                        current_string += bytes([byte])
                    else:
                        if len(current_string) >= 4:
                            ascii_strings.append(current_string.decode("ascii", errors="ignore"))
                        current_string = b""

                return {
                    "offset": offset,
                    "entropy": entropy,
                    "is_packed": is_packed,
                    "string_count": len(ascii_strings),
                    "notable_strings": [s for s in ascii_strings if any(k in s.lower() for k in ["license", "trial", "expire"])],
                }

        offsets = list(range(0, file_size - window_size + 1, step_size))

        with Parallel(n_jobs=n_jobs, backend="threading") as parallel:
            window_results: list[dict[str, Any]] = parallel(delayed(analyze_window)(offset, window_size, binary_path) for offset in offsets)

        results["window_results"] = window_results
        results["num_windows"] = len(window_results)

        entropies = [w["entropy"] for w in window_results]
        packed_regions = [w for w in window_results if w["is_packed"]]

        results["statistics"] = {
            "avg_entropy": float(np.mean(entropies)),
            "max_entropy": float(np.max(entropies)),
            "min_entropy": float(np.min(entropies)),
            "packed_regions": len(packed_regions),
            "packed_percentage": (len(packed_regions) / len(window_results)) * 100,
        }

        all_notable_strings: list[str] = []
        for w in window_results:
            all_notable_strings.extend(w.get("notable_strings", []))
        results["notable_strings"] = list(set(all_notable_strings))[:50]

        results["processing_time"] = time.time() - start_time
        results["success"] = True

    except Exception as e:
        logger.exception("Joblib mmap analysis error: %s", e)
        results["error"] = str(e)
        results["success"] = False

    return results


__all__ = [
    "extract_binary_features",
    "extract_binary_info",
    "process_binary_chunks",
    "process_chunk",
    "process_distributed_results",
    "run_celery_distributed_analysis",
    "run_dask_distributed_analysis",
    "run_distributed_analysis",
    "run_distributed_entropy_analysis",
    "run_distributed_pattern_search",
    "run_gpu_accelerator",
    "run_incremental_analysis",
    "run_joblib_mmap_analysis",
    "run_joblib_parallel_analysis",
    "run_memory_optimized_analysis",
    "run_pdf_report_generator",
]
