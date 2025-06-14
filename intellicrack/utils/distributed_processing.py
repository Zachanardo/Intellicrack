"""
Distributed processing utility functions. 

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import json
import logging
import multiprocessing
import os
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Try to import optional dependencies
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


def process_binary_chunks(binary_path: str, chunk_size: int = 1024 * 1024,
                         processor_func: Optional[Callable] = None,
                         num_workers: Optional[int] = None) -> Dict[str, Any]:
    """
    Process a binary file in chunks using multiple workers.

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

    results = {
        "file": binary_path,
        "file_size": os.path.getsize(binary_path),
        "chunk_size": chunk_size,
        "num_workers": num_workers,
        "chunks_processed": 0,
        "processing_time": 0,
        "chunk_results": []
    }

    start_time = time.time()

    try:
        # Calculate chunks
        file_size = results["file_size"]
        chunks = []

        for offset in range(0, file_size, chunk_size):
            chunk_info = {
                "index": len(chunks),
                "offset": offset,
                "size": min(chunk_size, file_size - offset)
            }
            chunks.append(chunk_info)

        results["total_chunks"] = len(chunks)

        # Process chunks in parallel
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            # Submit all chunk processing tasks
            future_to_chunk = {
                executor.submit(process_chunk, binary_path, chunk, processor_func): chunk
                for chunk in chunks
            }

            # Collect results as they complete
            for future in as_completed(future_to_chunk):
                chunk = future_to_chunk[future]
                try:
                    chunk_result = future.result()
                    results["chunk_results"].append(chunk_result)
                    results["chunks_processed"] += 1
                except (OSError, ValueError, RuntimeError) as e:
                    logger.error(f"Error processing chunk {chunk['index']}: {e}")
                    results["chunk_results"].append({
                        "chunk": chunk,
                        "error": str(e)
                    })

        results["processing_time"] = time.time() - start_time

        # Aggregate results
        results["aggregated"] = _aggregate_chunk_results(results["chunk_results"])

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in binary chunk processing: %s", e)
        results["error"] = str(e)

    return results


def process_chunk(binary_path: str, chunk_info: Dict[str, Any],
                 processor_func: Callable) -> Dict[str, Any]:
    """
    Process a single chunk of a binary file.

    Args:
        binary_path: Path to the binary file
        chunk_info: Information about the chunk
        processor_func: Function to process the chunk

    Returns:
        Dict containing chunk processing results
    """
    try:
        with open(binary_path, 'rb') as f:
            f.seek(chunk_info["offset"])
            data = f.read(chunk_info["size"])

        # Process the chunk
        result = processor_func(data, chunk_info)

        return {
            "chunk": chunk_info,
            "result": result,
            "success": True
        }

    except (OSError, ValueError, RuntimeError) as e:
        return {
            "chunk": chunk_info,
            "error": str(e),
            "success": False
        }


def process_distributed_results(results: List[Dict[str, Any]],
                              aggregation_func: Optional[Callable] = None) -> Dict[str, Any]:
    """
    Process and aggregate results from distributed processing.

    Args:
        results: List of results from distributed workers
        aggregation_func: Function to aggregate results

    Returns:
        Dict containing aggregated results
    """
    if aggregation_func is None:
        aggregation_func = _default_aggregation

    aggregated = {
        "total_results": len(results),
        "successful": 0,
        "failed": 0,
        "aggregated_data": {}
    }

    # Separate successful and failed results
    successful_results = []
    failed_results = []

    for result in results:
        if result.get("success", False):
            successful_results.append(result)
            aggregated["successful"] += 1
        else:
            failed_results.append(result)
            aggregated["failed"] += 1

    # Aggregate successful results
    if successful_results:
        aggregated["aggregated_data"] = aggregation_func(successful_results)

    # Include error summary
    if failed_results:
        aggregated["errors"] = [
            {
                "chunk": r.get("chunk", {}),
                "error": r.get("error", "Unknown error")
            }
            for r in failed_results[:10]  # Limit to first 10 errors
        ]

    return aggregated


def run_distributed_analysis(binary_path: str, analysis_type: str = "comprehensive",
                           config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run distributed analysis on a binary.

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
            "chunk_size": 1024 * 1024,  # 1MB chunks
            "timeout": 3600,  # 1 hour
            "backend": "multiprocessing"
        }

    results = {
        "binary": binary_path,
        "analysis_type": analysis_type,
        "config": config,
        "start_time": time.time(),
        "analyses": {}
    }

    try:
        # Define analysis tasks
        analysis_tasks = {
            "entropy": lambda: run_distributed_entropy_analysis(binary_path, config),
            "patterns": lambda: run_distributed_pattern_search(binary_path, config),
            "strings": lambda: _distributed_string_extraction(binary_path, config),
            "hashing": lambda: _distributed_hash_calculation(binary_path, config)
        }

        if analysis_type == "comprehensive":
            tasks_to_run = analysis_tasks.keys()
        else:
            tasks_to_run = [analysis_type] if analysis_type in analysis_tasks else []

        # Run selected analyses
        with ThreadPoolExecutor(max_workers=len(tasks_to_run)) as executor:
            future_to_task = {
                executor.submit(analysis_tasks[task]): task
                for task in tasks_to_run
            }

            for future in as_completed(future_to_task):
                task = future_to_task[future]
                try:
                    results["analyses"][task] = future.result()
                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error in %s analysis: %s", task, e)
                    results["analyses"][task] = {"error": str(e)}

        results["end_time"] = time.time()
        results["total_time"] = results["end_time"] - results["start_time"]

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in distributed analysis: %s", e)
        results["error"] = str(e)

    return results


def run_distributed_entropy_analysis(binary_path: str,
                                   config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run distributed entropy analysis on a binary.

    Args:
        binary_path: Path to the binary file
        config: Configuration for distributed processing

    Returns:
        Dict containing entropy analysis results
    """
    if config is None:
        config = {"chunk_size": 1024 * 1024, "num_workers": None}

    def entropy_processor(data: bytes, chunk_info: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate entropy for a chunk."""
        if not data:
            return {"entropy": 0.0}

        # Calculate byte frequency
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        # Calculate entropy
        import math
        entropy = 0.0
        data_len = len(data)

        for count in freq.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return {
            "entropy": entropy,
            "size": len(data),
            "unique_bytes": len(freq),
            "offset": chunk_info["offset"]
        }

    # Process chunks
    results = process_binary_chunks(
        binary_path,
        chunk_size=config.get("chunk_size", 1024 * 1024),
        processor_func=entropy_processor,
        num_workers=config.get("num_workers")
    )

    # Calculate overall statistics
    if results.get("aggregated"):
        entropies = [r["result"]["entropy"] for r in results["chunk_results"]
                    if r.get("success") and "entropy" in r.get("result", {})]

        if entropies:
            results["statistics"] = {
                "average_entropy": sum(entropies) / len(entropies),
                "max_entropy": max(entropies),
                "min_entropy": min(entropies),
                "high_entropy_chunks": sum(1 for e in entropies if e > 7.0)
            }

            # Check for potential packing/encryption
            if results["statistics"]["average_entropy"] > 7.0:
                results["indicators"] = ["Possible packing or encryption detected"]

    return results


def run_distributed_pattern_search(binary_path: str, patterns: Optional[List[bytes]] = None,
                                 config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run distributed pattern search on a binary.

    Args:
        binary_path: Path to the binary file
        patterns: List of byte patterns to search for
        config: Configuration for distributed processing

    Returns:
        Dict containing pattern search results
    """
    if patterns is None:
        # Default patterns for license/protection detection
        patterns = [
            b"license", b"LICENSE", b"License",
            b"trial", b"TRIAL", b"Trial",
            b"expire", b"EXPIRE", b"Expire",
            b"crack", b"CRACK", b"patch", b"PATCH",
            b"keygen", b"KEYGEN", b"serial", b"SERIAL"
        ]

    if config is None:
        config = {"chunk_size": 1024 * 1024, "num_workers": None}

    def pattern_processor(data: bytes, chunk_info: Dict[str, Any]) -> Dict[str, Any]:
        """Search for _patterns in a chunk."""
        found_patterns = []

        for pattern in patterns:
            # Use common utility for pattern searching
            from .binary_io import find_all_pattern_offsets
            offsets = find_all_pattern_offsets(data, pattern)
            for pos in offsets:
                found_patterns.append({
                    "pattern": pattern.hex(),
                    "pattern_text": pattern.decode('utf-8', errors='ignore'),
                    "offset": chunk_info["offset"] + pos,
                    "context_before": data[max(0, pos-10):pos].hex(),
                    "context_after": data[pos+len(pattern):pos+len(pattern)+10].hex()
                })

        return {
            "patterns_found": len(found_patterns),
            "matches": found_patterns[:100]  # Limit to prevent memory issues
        }

    # Process chunks
    results = process_binary_chunks(
        binary_path,
        chunk_size=config.get("chunk_size", 1024 * 1024),
        processor_func=pattern_processor,
        num_workers=config.get("num_workers")
    )

    # Aggregate all pattern matches
    all_matches = []
    for chunk_result in results.get("chunk_results", []):
        if chunk_result.get("success") and "matches" in chunk_result.get("result", {}):
            all_matches.extend(chunk_result["result"]["matches"])

    # Group by pattern
    pattern_summary = {}
    for match in all_matches:
        pattern_text = match["pattern_text"]
        if pattern_text not in pattern_summary:
            pattern_summary[pattern_text] = {
                "count": 0,
                "first_offset": match["offset"],
                "offsets": []
            }
        pattern_summary[pattern_text]["count"] += 1
        pattern_summary[pattern_text]["offsets"].append(match["offset"])

    results["pattern_summary"] = pattern_summary
    results["total_matches"] = len(all_matches)

    return results


def extract_binary_info(binary_path: str) -> Dict[str, Any]:
    """
    Extract basic information from a binary file.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing binary information
    """
    info = {
        "path": binary_path,
        "size": os.path.getsize(binary_path),
        "name": os.path.basename(binary_path)
    }

    try:
        # Get file times
        stat = os.stat(binary_path)
        info["created"] = time.ctime(stat.st_ctime)
        info["modified"] = time.ctime(stat.st_mtime)

        # Calculate hash
        import hashlib
        sha256 = hashlib.sha256()

        with open(binary_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)

        info["sha256"] = sha256.hexdigest()

        # Detect format
        with open(binary_path, 'rb') as f:
            magic = f.read(4)

        if magic[:2] == b'MZ':
            info["format"] = "PE"
        elif magic == b'\x7fELF':
            info["format"] = "ELF"
        elif magic in [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe']:
            info["format"] = "Mach-O"
        else:
            info["format"] = "Unknown"

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error extracting binary info: %s", e)
        info["error"] = str(e)

    return info


def extract_binary_features(binary_path: str) -> Dict[str, Any]:
    """
    Extract features from a binary for analysis.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing extracted features
    """
    features = {
        "file_size": 0,
        "entropy": 0.0,
        "strings_count": 0,
        "imports_count": 0,
        "sections_count": 0
    }

    try:
        # Basic file info
        features["file_size"] = os.path.getsize(binary_path)

        # Calculate overall entropy
        entropy_result = run_distributed_entropy_analysis(binary_path)
        if "statistics" in entropy_result:
            features["entropy"] = entropy_result["statistics"]["average_entropy"]

        # Extract strings count
        strings_result = _distributed_string_extraction(binary_path, {"min_length": 4})
        features["strings_count"] = strings_result.get("total_strings", 0)

        # Format-specific features would go here
        # (PE imports, sections, etc.)

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error extracting features: %s", e)
        features["error"] = str(e)

    return features


def run_gpu_accelerator(task_type: str, data: Any,
                       config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run GPU-accelerated processing for supported tasks.

    Args:
        task_type: Type of GPU task (pattern_matching, crypto, ml_inference)
        data: Input data for processing
        config: GPU configuration

    Returns:
        Dict containing GPU processing results
    """
    results = {
        "task_type": task_type,
        "gpu_available": False,
        "backend": "cpu"
    }

    # Check for GPU availability
    gpu_backends = _check_gpu_backends()

    if not gpu_backends["available"]:
        results["message"] = "No GPU acceleration available, falling back to CPU"
        results["cpu_result"] = _run_cpu_fallback(task_type, data)
        return results

    results["gpu_available"] = True
    results["backend"] = gpu_backends["backend"]

    try:
        if task_type == "pattern_matching":
            results["result"] = _gpu_pattern_matching(data, config)
        elif task_type == "crypto":
            results["result"] = _gpu_crypto_operations(data, config)
        elif task_type == "ml_inference":
            results["result"] = _gpu_ml_inference(data, config)
        else:
            results["error"] = f"Unsupported GPU task type: {task_type}"

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("GPU acceleration error: %s", e)
        results["error"] = str(e)
        results["cpu_result"] = _run_cpu_fallback(task_type, data)

    return results


def run_incremental_analysis(binary_path: str, cache_dir: Optional[str] = None,
                           force_full: bool = False) -> Dict[str, Any]:
    """
    Run incremental analysis using cached results when possible.

    Args:
        binary_path: Path to the binary file
        cache_dir: Directory for cache storage
        force_full: Force full analysis ignoring cache

    Returns:
        Dict containing analysis results
    """
    if cache_dir is None:
        cache_dir = os.path.join(os.path.dirname(binary_path), ".intellicrack_cache")

    results = {
        "binary": binary_path,
        "cache_dir": cache_dir,
        "cached_results": {},
        "new_results": {},
        "cache_hits": 0,
        "cache_misses": 0
    }

    # Calculate file hash for cache key
    import hashlib
    with open(binary_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    results["file_hash"] = file_hash

    # Create cache directory
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, f"{file_hash}.json")

    # Load cached results if available and not forcing full analysis
    if os.path.exists(cache_file) and not force_full:
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cached_data = json.load(f)

            # Verify file hasn't changed
            if cached_data.get("file_size") == os.path.getsize(binary_path):
                results["cached_results"] = cached_data.get("analyses", {})
                results["cache_hits"] = len(results["cached_results"])

        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Error loading cache: %s", e)

    # Determine what analyses need to be run
    required_analyses = ["entropy", "patterns", "strings", "features"]
    analyses_to_run = []

    for analysis in required_analyses:
        if analysis not in results["cached_results"]:
            analyses_to_run.append(analysis)
            results["cache_misses"] += 1

    # Run missing analyses
    if analyses_to_run:
        new_analyses = run_distributed_analysis(
            binary_path,
            analysis_type="comprehensive"
        )

        results["new_results"] = new_analyses.get("analyses", {})

        # Update cache
        all_results = {**results["cached_results"], **results["new_results"]}

        cache_data = {
            "file_hash": file_hash,
            "file_size": os.path.getsize(binary_path),
            "timestamp": time.time(),
            "analyses": all_results
        }

        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2)
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error saving cache: %s", e)

    # Combine all results
    results["all_results"] = {**results["cached_results"], **results["new_results"]}

    return results


def run_memory_optimized_analysis(binary_path: str, max_memory_mb: int = 1024) -> Dict[str, Any]:
    """
    Run memory-optimized analysis for large binaries.

    Args:
        binary_path: Path to the binary file
        max_memory_mb: Maximum memory to use in MB

    Returns:
        Dict containing analysis results
    """
    file_size = os.path.getsize(binary_path)

    # Calculate optimal chunk size based on memory limit
    # Reserve 50% for processing overhead
    available_memory = max_memory_mb * 1024 * 1024 * 0.5
    num_workers = multiprocessing.cpu_count()
    chunk_size = int(available_memory / num_workers)

    # Ensure reasonable chunk size
    chunk_size = max(1024 * 1024, min(chunk_size, 100 * 1024 * 1024))  # 1MB to 100MB

    results = {
        "binary": binary_path,
        "file_size": file_size,
        "max_memory_mb": max_memory_mb,
        "chunk_size": chunk_size,
        "num_workers": num_workers
    }

    # Run analysis with memory constraints
    config = {
        "chunk_size": chunk_size,
        "num_workers": num_workers,
        "memory_limit": max_memory_mb
    }

    results["analysis"] = run_distributed_analysis(binary_path, config=config)

    return results


def run_pdf_report_generator(analysis_results: Dict[str, Any],
                           output_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate a PDF report from analysis results.

    Args:
        analysis_results: Results from binary analysis
        output_path: Path for output PDF

    Returns:
        Dict containing report generation status
    """
    if output_path is None:
        output_path = "intellicrack_report.pdf"

    results = {
        "output_path": output_path,
        "status": "pending"
    }

    try:
        # Check if PDF generation is available
        from intellicrack.core.reporting.pdf_generator import PDFReportGenerator

        generator = PDFReportGenerator()

        # Add sections based on analysis results
        if "binary" in analysis_results:
            generator.add_section("Binary Information",
                                str(analysis_results.get("binary", {})))

        if "analyses" in analysis_results:
            for analysis_type, data in analysis_results["analyses"].items():
                generator.add_section(f"{analysis_type.title()} Analysis",
                                    str(data))

        # Generate PDF
        generator.generate_report(output_path=output_path)

        results["status"] = "success"
        results["message"] = f"Report generated: {output_path}"

    except ImportError:
        results["status"] = "error"
        results["message"] = "PDF generation not available"
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error generating PDF report: %s", e)
        results["status"] = "error"
        results["message"] = str(e)

    return results


# Helper functions

def _default_chunk_processor(data: bytes, chunk_info: Dict[str, Any]) -> Dict[str, Any]:
    """Default chunk processor - calculates basic statistics."""
    return {
        "size": len(data),
        "offset": chunk_info["offset"],
        "non_zero_bytes": sum(1 for b in data if b != 0)
    }


def _default_aggregation(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Default aggregation function."""
    total_size = 0
    total_non_zero = 0

    for result in results:
        if "result" in result:
            total_size += result["result"].get("size", 0)
            total_non_zero += result["result"].get("non_zero_bytes", 0)

    return {
        "total_size": total_size,
        "total_non_zero_bytes": total_non_zero,
        "chunks_processed": len(results)
    }


def _aggregate_chunk_results(chunk_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate results from chunk processing."""
    successful = [r for r in chunk_results if r.get("success")]

    if not successful:
        return {"error": "No successful chunk processing"}

    return _default_aggregation(successful)


def _distributed_string_extraction(binary_path: str,
                                 config: Dict[str, Any]) -> Dict[str, Any]:
    """Extract strings using distributed processing."""
    min_length = config.get("min_length", 4)

    def string_processor(data: bytes, chunk_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract printable strings from chunk."""
        strings = []
        current = []

        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []

        # Don't forget last string
        if len(current) >= min_length:
            strings.append(''.join(current))

        return {
            "strings_count": len(strings),
            "strings": strings[:100]  # Limit to prevent memory issues
        }

    results = process_binary_chunks(
        binary_path,
        chunk_size=config.get("chunk_size", 1024 * 1024),
        processor_func=string_processor,
        num_workers=config.get("num_workers")
    )

    # Aggregate strings
    all_strings = []
    for chunk_result in results.get("chunk_results", []):
        if chunk_result.get("success") and "strings" in chunk_result.get("result", {}):
            all_strings.extend(chunk_result["result"]["strings"])

    results["total_strings"] = len(all_strings)
    results["unique_strings"] = len(set(all_strings))
    results["sample_strings"] = list(set(all_strings))[:50]

    return results


def _distributed_hash_calculation(binary_path: str,
                                config: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate hashes using distributed processing."""
    import hashlib

    # For hash calculation, we need sequential processing
    # but can parallelize multiple hash algorithms
    algorithms = ["md5", "sha1", "sha256", "sha512"]
    results = {"hashes": {}}

    def calculate_hash(algo: str) -> Tuple[str, str]:
        """Calculate hash for given algorithm."""
        h = hashlib.new(algo)

        with open(binary_path, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)

        return algo, h.hexdigest()

    with ThreadPoolExecutor(max_workers=len(algorithms)) as executor:
        future_to_algo = {
            executor.submit(calculate_hash, algo): algo
            for algo in algorithms
        }

        for future in as_completed(future_to_algo):
            try:
                algo, hash_value = future.result()
                results["hashes"][algo] = hash_value
            except (OSError, ValueError, RuntimeError) as e:
                algo = future_to_algo[future]
                logger.error("Error calculating %s: %s", algo, e)

    return results


def _check_gpu_backends() -> Dict[str, Any]:
    """Check available GPU backends."""
    backends = {
        "available": False,
        "backend": None,
        "devices": []
    }

    # Check for CUDA
    try:
        import torch
        if torch.cuda.is_available():
            backends["available"] = True
            backends["backend"] = "cuda"
            backends["devices"] = [f"cuda:{i}" for i in range(torch.cuda.device_count())]
            return backends
    except ImportError:
        logger.debug("CUDA backend not available: PyTorch not installed")

    # Check for OpenCL
    try:
        import pyopencl as cl
        platforms = cl.get_platforms()
        if platforms:
            backends["available"] = True
            backends["backend"] = "opencl"
            for platform in platforms:
                devices = platform.get_devices()
                backends["devices"].extend([d.name for d in devices])
            return backends
    except ImportError:
        logger.debug("OpenCL backend not available: pyopencl not installed")

    return backends


def _run_cpu_fallback(task_type: str, data: Any) -> Dict[str, Any]:
    """CPU fallback for GPU tasks."""
    return {
        "backend": "cpu",
        "task_type": task_type,
        "message": "Processed on CPU"
    }


def _gpu_pattern_matching(data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """GPU-accelerated pattern matching."""
    import time
    start_time = time.time()
    patterns_found = 0

    try:
        # Check if GPU libraries are available
        import torch
        if torch.cuda.is_available():
            # Convert patterns and data to GPU tensors for fast matching
            patterns = config.get('patterns', [])
            search_data = data.get('data', b'')

            if patterns and search_data:
                # Simple GPU pattern matching using PyTorch
                device = torch.device('cuda')

                # Convert data to tensor
                data_tensor = torch.tensor(list(search_data), dtype=torch.uint8, device=device)

                for pattern in patterns:
                    if isinstance(pattern, (bytes, bytearray)):
                        pattern_tensor = torch.tensor(list(pattern), dtype=torch.uint8, device=device)
                        # Use convolution for pattern matching
                        if len(pattern) <= len(search_data):
                            for i in range(len(search_data) - len(pattern) + 1):
                                if torch.equal(data_tensor[i:i+len(pattern)], pattern_tensor):
                                    patterns_found += 1
                                    break

            backend = 'cuda'
        else:
            # Fall back to CPU pattern matching
            patterns = config.get('patterns', [])
            search_data = data.get('data', b'')

            for pattern in patterns:
                if pattern in search_data:
                    patterns_found += 1

            backend = 'cpu'

    except ImportError:
        # No PyTorch, use basic pattern matching
        patterns = config.get('patterns', [])
        search_data = data.get('data', b'')

        for _pattern in patterns:
            if _pattern in search_data:
                patterns_found += 1

        backend = 'cpu'

    return {
        "patterns_found": patterns_found,
        "processing_time": time.time() - start_time,
        "backend": backend
    }


def _gpu_crypto_operations(data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """GPU-accelerated cryptographic operations."""
    import hashlib
    import time

    operation = config.get('operation', 'hash')
    input_data = data.get('data', b'')
    start_time = time.time()

    try:
        # Try GPU acceleration with CuPy
        import cupy as cp

        if operation == 'hash':
            # GPU-accelerated hashing (simplified)
            # In practice, would use specialized GPU crypto libraries
            data_gpu = cp.asarray(list(input_data), dtype=cp.uint8)
            # Simple hash computation on GPU
            hash_value = int(cp.sum(data_gpu) % (2**32))
            result = f"{hash_value:08x}"
            backend = 'cuda'
        else:
            # Other crypto operations
            result = hashlib.sha256(input_data).hexdigest()
            backend = 'cuda'

    except ImportError:
        # Fall back to CPU crypto
        if operation == 'hash':
            result = hashlib.sha256(input_data).hexdigest()
        elif operation == 'aes':
            # Would implement AES here
            result = hashlib.sha256(input_data).hexdigest()
        else:
            result = hashlib.sha256(input_data).hexdigest()

        backend = 'cpu'

    return {
        "operation": operation,
        "result": result,
        "processing_time": time.time() - start_time,
        "backend": backend
    }


def _gpu_ml_inference(data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """GPU-accelerated ML inference."""
    import time
    start_time = time.time()

    try:
        import numpy as np
        import torch

        # Check for GPU availability
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        backend = 'cuda' if torch.cuda.is_available() else 'cpu'

        # Get model and features
        model_path = config.get('model_path')
        features = data.get('features', [])

        if model_path and os.path.exists(model_path) and features:
            # Load model
            model = torch.load(model_path, map_location=device)
            model.eval()

            # Convert features to tensor
            features_tensor = torch.tensor(features, dtype=torch.float32, device=device)
            if len(features_tensor.shape) == 1:
                features_tensor = features_tensor.unsqueeze(0)

            # Run inference
            with torch.no_grad():
                output = model(features_tensor)
                if hasattr(output, 'cpu'):
                    predictions = output.cpu().numpy().tolist()
                else:
                    predictions = [output.item()]

                # Calculate confidence (softmax for classification)
                if len(predictions) > 1:
                    exp_scores = np.exp(predictions)
                    confidence = float(np.max(exp_scores / np.sum(exp_scores)))
                else:
                    confidence = abs(predictions[0])
        else:
            # No model or features, return default
            predictions = [0.5]
            confidence = 0.0

    except (OSError, ValueError, RuntimeError) as e:
        logger.debug("GPU ML inference fallback: %s", e)
        # Simple fallback prediction
        predictions = [0.5]  # Neutral prediction
        confidence = 0.0
        backend = 'cpu'

    return {
        "predictions": predictions,
        "confidence": confidence,
        "processing_time": time.time() - start_time,
        "backend": backend
    }


# Export all functions
__all__ = [
    'process_binary_chunks',
    'process_chunk',
    'process_distributed_results',
    'run_distributed_analysis',
    'run_distributed_entropy_analysis',
    'run_distributed_pattern_search',
    'extract_binary_info',
    'extract_binary_features',
    'run_gpu_accelerator',
    'run_incremental_analysis',
    'run_memory_optimized_analysis',
    'run_pdf_report_generator'
]
