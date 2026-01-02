"""GPU-accelerated binary analysis functions.

This module provides GPU-accelerated implementations of common binary analysis
operations including pattern search and entropy calculation. It supports multiple
GPU frameworks with automatic detection and selection:

- PyTorch XPU: Intel GPU support via OneAPI
- CuPy: NVIDIA GPU via CUDA
- Numba CUDA: NVIDIA GPU via Numba JIT compilation
- PyCUDA: NVIDIA GPU via native CUDA interface

The module automatically detects available frameworks and selects the best one,
with automatic fallback to CPU if no GPU is available. All GPU operations include
proper memory management and error handling.

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
import os
import time
from typing import Any

from intellicrack.handlers.numpy_handler import numpy as np


logger: logging.Logger = logging.getLogger(__name__)

XPU_DEVICE: str = "xpu:0"

# GPU framework availability flags
PYCUDA_AVAILABLE: bool = False
CUPY_AVAILABLE: bool = False
NUMBA_CUDA_AVAILABLE: bool = False
XPU_AVAILABLE: bool = False
PYTORCH_AVAILABLE: bool = False

# Declare optional dependency variables at module level
torch: Any = None
cp: Any = None
cuda: Any = None
compiler: Any = None
gpuarray: Any = None
numba: Any = None
numba_cuda: Any = None

# Check if CUDA is disabled via environment
CUDA_DISABLED: bool = os.environ.get("CUDA_VISIBLE_DEVICES") == "-1"
INTEL_GPU_PREFERRED: bool = os.environ.get("INTELLICRACK_GPU_TYPE") == "intel"

# Try importing PyTorch with XPU support first if preferred
if INTEL_GPU_PREFERRED or not CUDA_DISABLED:
    try:
        import torch as _torch

        torch = _torch
        PYTORCH_AVAILABLE = True
        logger.debug("PyTorch available")

        try:
            if hasattr(torch, "xpu") and torch.xpu.is_available():
                XPU_AVAILABLE = True
                logger.info("PyTorch XPU initialized successfully - %d XPU device(s) found", torch.xpu.device_count())
                logger.info("PyTorch version: %s", torch.__version__)
                for i in range(torch.xpu.device_count()):
                    logger.info("XPU Device %d: %s", i, torch.xpu.get_device_name(i))
            else:
                logger.debug("Intel XPU not available")
        except Exception as e:
            logger.debug("PyTorch XPU initialization error: %s", e)
    except ImportError:
        logger.debug("PyTorch not available")

# Try importing CUDA frameworks only if not disabled
if not CUDA_DISABLED:
    try:
        import pycuda.autoinit
        import pycuda.driver as _cuda
        from pycuda import (
            compiler as _compiler,
            gpuarray as _gpuarray,
        )

        cuda = _cuda
        compiler = _compiler
        gpuarray = _gpuarray
        PYCUDA_AVAILABLE = True
        logger.info("PyCUDA initialized successfully")
    except ImportError:
        logger.debug("PyCUDA not available")
    except Exception as e:
        logger.debug("PyCUDA initialization failed: %s", e)

    try:
        import cupy as _cp

        cp = _cp
        CUPY_AVAILABLE = True
        logger.info("CuPy initialized successfully")
    except ImportError:
        logger.debug("CuPy not available")
    except Exception as e:
        logger.debug("CuPy initialization failed: %s", e)

    try:
        import numba as _numba
        from numba import cuda as _numba_cuda

        numba = _numba
        numba_cuda = _numba_cuda
        NUMBA_CUDA_AVAILABLE = True
        logger.info("Numba CUDA initialized successfully")
    except ImportError:
        logger.debug("Numba CUDA not available")
    except Exception as e:
        logger.debug("Numba CUDA initialization failed: %s", e)
else:
    logger.debug("CUDA disabled via CUDA_VISIBLE_DEVICES=-1")


class GPUAccelerator:
    """GPU acceleration for binary analysis tasks.

    Provides GPU-accelerated implementations of pattern search and entropy calculation
    using multiple GPU frameworks (PyTorch XPU, CuPy, Numba CUDA, PyCUDA) with
    automatic framework detection and CPU fallback.

    Attributes:
        framework (str): Name of the selected GPU framework ('xpu', 'cupy', 'numba',
            'pycuda', or 'cpu').
        device_info (dict[str, Any]): Information about the selected GPU device.

    """

    def __init__(self) -> None:
        """Initialize GPU accelerator.

        Detects the best available GPU framework and initializes device information.
        Supports PyTorch XPU, CuPy, Numba CUDA, and PyCUDA backends with automatic
        fallback to CPU when no GPU is available.

        Returns:
            None

        """
        self.framework: str = self._detect_best_framework()
        self.device_info: dict[str, Any] = self._get_device_info()
        logger.info("GPU Accelerator initialized with %s", self.framework)

    def _detect_best_framework(self) -> str:
        """Detect the best available GPU framework.

        Prioritizes Intel GPU (XPU) if preferred or only available, then checks for
        CUDA frameworks in order: CuPy, Numba CUDA, PyCUDA. Falls back to CPU if no
        GPU frameworks are available.

        Returns:
            str: Name of the best available GPU framework ('xpu', 'cupy', 'numba',
                'pycuda', or 'cpu').

        """
        # Prioritize Intel GPU if preferred or only option available
        if INTEL_GPU_PREFERRED and XPU_AVAILABLE:
            return "xpu"

        if CUDA_DISABLED:
            return "xpu" if XPU_AVAILABLE else "cpu"
        # Standard priority order for CUDA frameworks
        if CUPY_AVAILABLE:
            return "cupy"
        if NUMBA_CUDA_AVAILABLE:
            return "numba"
        if PYCUDA_AVAILABLE:
            return "pycuda"

        # Fall back to Intel GPU if available
        return "xpu" if XPU_AVAILABLE else "cpu"

    def _get_device_info(self) -> dict[str, Any]:
        """Get GPU device information.

        Retrieves device information from the currently selected GPU framework,
        including device name, compute capability, memory statistics, and other
        hardware-specific attributes.

        Returns:
            dict[str, Any]: Dictionary containing GPU device information with
                framework-specific keys and values. Empty dict if no GPU available.

        """
        if self.framework == "xpu" and XPU_AVAILABLE:
            return self._get_xpu_device_info()
        if self.framework == "cupy" and CUPY_AVAILABLE:
            return self._get_cupy_device_info()
        if self.framework == "pycuda" and PYCUDA_AVAILABLE:
            return self._get_pycuda_device_info()
        if self.framework == "numba" and NUMBA_CUDA_AVAILABLE:
            return self._get_numba_device_info()
        return {}

    def _get_xpu_device_info(self) -> dict[str, Any]:
        """Get Intel XPU device information.

        Retrieves detailed information about Intel XPU devices including device name,
        device count, driver version, and current memory allocation/reservation stats.

        Returns:
            dict[str, Any]: Dictionary with keys: 'name' (str), 'device_type' (str),
                'device_count' (int), 'driver_version' (str), 'memory_allocated' (int),
                'memory_reserved' (int). Empty dict if retrieval fails.

        Raises:
            Exception: Caught and logged if device info retrieval fails, returns empty dict.

        """
        info = {}
        try:
            device_count = torch.xpu.device_count()
            if device_count > 0:
                device_name = torch.xpu.get_device_name(0)
                memory_info = torch.xpu.memory_stats(0) if hasattr(torch.xpu, "memory_stats") else {}
                info = {
                    "name": device_name,
                    "device_type": "Intel XPU",
                    "device_count": device_count,
                    "driver_version": getattr(torch.xpu, "version", "Unknown"),
                    "memory_allocated": memory_info.get("allocated_bytes.all.current", 0),
                    "memory_reserved": memory_info.get("reserved_bytes.all.current", 0),
                }
        except Exception as e:
            logger.debug("Failed to get Intel XPU device info: %s", e)
        return info

    def _get_cupy_device_info(self) -> dict[str, Any]:
        """Get CuPy device information.

        Retrieves detailed information about NVIDIA GPU devices via CuPy including
        device name, compute capability, total/free memory, and multiprocessor count.

        Returns:
            dict[str, Any]: Dictionary with keys: 'name' (str), 'compute_capability'
                (tuple), 'memory_total' (int), 'memory_free' (int),
                'multiprocessor_count' (int). Empty dict if retrieval fails.

        Raises:
            Exception: Caught and logged if device info retrieval fails, returns empty dict.

        """
        info = {}
        try:
            device = cp.cuda.Device()
            info = {
                "name": device.name.decode(),
                "compute_capability": device.compute_capability,
                "memory_total": device.mem_info[1],
                "memory_free": device.mem_info[0],
                "multiprocessor_count": device.attributes["MultiProcessorCount"],
            }
        except Exception as e:
            logger.debug("Failed to get CuPy device info: %s", e)
        return info

    def _get_pycuda_device_info(self) -> dict[str, Any]:
        """Get PyCUDA device information.

        Retrieves detailed information about NVIDIA GPU devices via PyCUDA including
        device name, compute capability, total memory, and multiprocessor count.

        Returns:
            dict[str, Any]: Dictionary with keys: 'name' (str), 'compute_capability'
                (tuple), 'memory_total' (int), 'multiprocessor_count' (int).
                Empty dict if retrieval fails.

        Raises:
            Exception: Caught and logged if device info retrieval fails, returns empty dict.

        """
        info = {}
        try:
            device = cuda.Device(0)
            attributes = device.get_attributes()
            info = {
                "name": device.name(),
                "compute_capability": device.compute_capability(),
                "memory_total": device.total_memory(),
                "multiprocessor_count": attributes[cuda.device_attribute.MULTIPROCESSOR_COUNT],
            }
        except Exception as e:
            logger.debug("Failed to get PyCUDA device info: %s", e)
        return info

    def _get_numba_device_info(self) -> dict[str, Any]:
        """Get Numba CUDA device information.

        Retrieves detailed information about NVIDIA GPU devices via Numba CUDA including
        device name, compute capability, total/free memory.

        Returns:
            dict[str, Any]: Dictionary with keys: 'name' (str), 'compute_capability'
                (tuple), 'memory_total' (int), 'memory_free' (int).
                Empty dict if retrieval fails.

        Raises:
            Exception: Caught and logged if device info retrieval fails, returns empty dict.

        """
        info = {}
        try:
            device = numba_cuda.get_current_device()
            info = {
                "name": device.name.decode(),
                "compute_capability": device.compute_capability,
                "memory_total": device.get_memory_info()[1],
                "memory_free": device.get_memory_info()[0],
            }
        except Exception as e:
            logger.debug("Failed to get Numba device info: %s", e)
        return info

    def parallel_pattern_search(self, data: bytes, pattern: bytes) -> dict[str, Any]:
        """GPU-accelerated pattern search in binary data.

        Searches for all occurrences of a byte pattern in binary data using the best
        available GPU framework. Falls back to CPU if no GPU is available. Execution
        time and framework used are included in results.

        Args:
            data (bytes): Binary data to search in.
            pattern (bytes): Byte pattern to search for.

        Returns:
            dict[str, Any]: Dictionary with keys: 'match_count' (int), 'positions'
                (list[int]), 'execution_time' (float), 'framework' (str), and
                optionally 'matches' (list) with matched data.

        """
        start_time = time.time()

        if self.framework == "xpu" and XPU_AVAILABLE:
            result = self._xpu_pattern_search(data, pattern)
        elif self.framework == "cupy" and CUPY_AVAILABLE:
            result = self._cupy_pattern_search(data, pattern)
        elif self.framework == "numba" and NUMBA_CUDA_AVAILABLE:
            result = self._numba_pattern_search(data, pattern)
        elif self.framework == "pycuda" and PYCUDA_AVAILABLE:
            result = self._pycuda_pattern_search(data, pattern)
        else:
            result = self._cpu_pattern_search(data, pattern)

        result["execution_time"] = time.time() - start_time
        result["framework"] = self.framework
        return result

    def _xpu_pattern_search(self, data: bytes, pattern: bytes) -> dict[str, Any]:
        """Native PyTorch XPU implementation of pattern search.

        Uses Intel XPU for efficient pattern matching via sliding window approach
        with tensor operations. Results are limited to first 1000 matches for
        performance reasons.

        Args:
            data (bytes): Binary data to search in.
            pattern (bytes): Byte pattern to search for.

        Returns:
            dict[str, Any]: Dictionary with keys: 'match_count' (int), 'positions'
                (list[int]), 'matches' (list[dict]), 'method' (str).

        Raises:
            Exception: Caught and logged if XPU pattern search fails, falls back to CPU.

        """
        try:
            # Clear XPU cache for optimal performance
            torch.xpu.empty_cache()

            # Convert data to PyTorch tensors on Intel XPU
            with torch.xpu.device(0):
                data_np = np.frombuffer(data, dtype=np.uint8)
                pattern_np = np.frombuffer(pattern, dtype=np.uint8)

                # Create tensors on XPU device
                data_tensor = torch.from_numpy(data_np).to(device=XPU_DEVICE, dtype=torch.uint8)
                pattern_tensor = torch.from_numpy(pattern_np).to(device=XPU_DEVICE, dtype=torch.uint8)

            # Efficient pattern matching using sliding window approach
            data_len = data_tensor.size(0)
            pattern_len = pattern_tensor.size(0)

            if pattern_len > data_len:
                return {
                    "match_count": 0,
                    "positions": [],
                    "method": "xpu",
                }

            # Create sliding windows of data for comparison
            matches: list[dict[str, Any]] = []
            window_size = pattern_len

            # Use unfold to create sliding windows efficiently on GPU
            windows = data_tensor.unfold(0, window_size, 1)

            # Compare each window with the pattern
            pattern_expanded = pattern_tensor.unsqueeze(0).expand(windows.size(0), -1)
            matches_mask = torch.all(windows == pattern_expanded, dim=1)

            # Get positions of matches
            match_indices = torch.nonzero(matches_mask, as_tuple=False).squeeze(1)
            positions = match_indices.cpu().numpy().tolist()

            # Store actual matched data for analysis
            for idx in match_indices:
                if len(matches) < 1000:  # Limit for performance
                    matched_data = windows[idx].cpu().numpy().tolist()
                    matches.append({"position": idx.item(), "data": matched_data})

            # Limit to first 1000 matches for consistency
            if len(positions) > 1000:
                positions = positions[:1000]

            return {
                "match_count": len(positions),
                "positions": positions,
                "matches": matches,
                "method": "xpu",
            }

        except Exception as e:
            logger.exception("Intel XPU pattern search failed: %s", e)
            return self._cpu_pattern_search(data, pattern)

    def _cupy_pattern_search(self, data: bytes, pattern: bytes) -> dict[str, Any]:
        """CuPy implementation of pattern search.

        Uses NVIDIA GPU via CuPy with custom CUDA kernel for parallel pattern matching.
        Results are limited to first 1000 matches for performance reasons.

        Args:
            data (bytes): Binary data to search in.
            pattern (bytes): Byte pattern to search for.

        Returns:
            dict[str, Any]: Dictionary with keys: 'match_count' (int), 'positions'
                (list[int]), 'method' (str).

        Raises:
            Exception: Caught and logged if CuPy pattern search fails, falls back to CPU.

        """
        try:
            # Convert to GPU arrays
            data_gpu = cp.asarray(np.frombuffer(data, dtype=np.uint8))
            pattern_gpu = cp.asarray(np.frombuffer(pattern, dtype=np.uint8))

            # Create custom kernel for pattern matching
            kernel_code = """
            extern "C" __global__
            void pattern_match(const unsigned char* data, int data_size,
                             const unsigned char* pattern, int pattern_size,
                             int* matches, int* match_positions) {
                int idx = blockIdx.x * blockDim.x + threadIdx.x;
                if (idx <= data_size - pattern_size) {
                    bool match = true;
                    for (int i = 0; i < pattern_size; i++) {
                        if (data[idx + i] != pattern[i]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        int match_idx = atomicAdd(matches, 1);
                        if (match_idx < 1000) {  // Store first 1000 matches
                            match_positions[match_idx] = idx;
                        }
                    }
                }
            }
            """

            # Compile kernel
            kernel = cp.RawKernel(kernel_code, "pattern_match")

            # Allocate result arrays
            matches = cp.zeros(1, dtype=cp.int32)
            match_positions = cp.zeros(1000, dtype=cp.int32)

            # Launch kernel
            threads_per_block = 256
            blocks = (len(data_gpu) + threads_per_block - 1) // threads_per_block
            kernel(
                (blocks,),
                (threads_per_block,),
                (data_gpu, len(data_gpu), pattern_gpu, len(pattern_gpu), matches, match_positions),
            )

            # Get results
            match_count = int(matches.get())
            positions = match_positions[: min(match_count, 1000)].get().tolist()

            return {
                "match_count": match_count,
                "positions": positions,
                "method": "cupy_kernel",
            }

        except Exception as e:
            logger.exception("CuPy pattern search failed: %s", e)
            return self._cpu_pattern_search(data, pattern)

    def _numba_pattern_search(self, data: bytes, pattern: bytes) -> dict[str, Any]:
        """Numba CUDA implementation of pattern search.

        Uses Numba CUDA JIT compilation for GPU-accelerated pattern matching.
        Results are limited to first 1000 matches for performance reasons.

        Args:
            data (bytes): Binary data to search in.
            pattern (bytes): Byte pattern to search for.

        Returns:
            dict[str, Any]: Dictionary with keys: 'match_count' (int), 'positions'
                (list[int]), 'method' (str).

        Raises:
            Exception: Caught and logged if Numba pattern search fails, falls back to CPU.

        """
        try:
            data_np = np.frombuffer(data, dtype=np.uint8)
            pattern_np = np.frombuffer(pattern, dtype=np.uint8)

            kernel = self._create_pattern_match_kernel()

            # Transfer to GPU
            d_data = numba_cuda.to_device(data_np)
            d_pattern = numba_cuda.to_device(pattern_np)
            d_matches = numba_cuda.device_array(1, dtype=np.int32)
            d_positions = numba_cuda.device_array(1000, dtype=np.int32)

            # Configure kernel
            threads_per_block = 256
            blocks = (len(data_np) + threads_per_block - 1) // threads_per_block

            # Launch kernel
            kernel[blocks, threads_per_block](
                d_data,
                d_pattern,
                d_matches,
                d_positions,
            )

            # Get results
            match_count = int(d_matches.copy_to_host()[0])
            positions = d_positions.copy_to_host()[: min(match_count, 1000)].tolist()

            return {
                "match_count": match_count,
                "positions": positions,
                "method": "numba_cuda",
            }

        except Exception as e:
            logger.exception("Numba pattern search failed: %s", e)
            return self._cpu_pattern_search(data, pattern)

    def _create_pattern_match_kernel(self) -> Any:
        """Create Numba CUDA pattern matching kernel.

        Compiles and returns a Numba CUDA kernel function that performs parallel
        pattern matching on GPU arrays. Uses atomic operations for match counting.

        Returns:
            Any: Compiled Numba CUDA kernel function with signature (data, pattern,
                matches, positions) -> None.

        Raises:
            RuntimeError: If Numba CUDA is not available or not properly initialized.

        """
        if not NUMBA_CUDA_AVAILABLE or numba_cuda is None:
            raise RuntimeError("Numba CUDA not available")

        @numba_cuda.jit
        def pattern_match_kernel(
            data: Any,
            pattern: Any,
            matches: Any,
            positions: Any,
        ) -> None:
            """Numba CUDA kernel for parallel pattern matching.

            Performs byte-by-byte pattern comparison in parallel across GPU threads.
            Updates match count and stores matching positions using atomic operations.

            Args:
                data: GPU array of bytes to search.
                pattern: GPU array of pattern bytes to match.
                matches: GPU array storing total match count (length 1).
                positions: GPU array storing matched positions (length 1000).

            Returns:
                None

            """
            idx = numba_cuda.grid(1)
            if idx <= len(data) - len(pattern):
                match = True
                for i in range(len(pattern)):
                    if data[idx + i] != pattern[i]:
                        match = False
                        break

                if match:
                    match_idx = numba_cuda.atomic.add(matches, 0, 1)
                    if match_idx < len(positions):
                        positions[match_idx] = idx

        return pattern_match_kernel

    def _pycuda_pattern_search(self, data: bytes, pattern: bytes) -> dict[str, Any]:
        """PyCUDA implementation of pattern search.

        Uses PyCUDA with compiled CUDA kernel for GPU-accelerated pattern matching.
        Results are limited to first 1000 matches for performance reasons.

        Args:
            data (bytes): Binary data to search in.
            pattern (bytes): Byte pattern to search for.

        Returns:
            dict[str, Any]: Dictionary with keys: 'match_count' (int), 'positions'
                (list[int]), 'method' (str).

        Raises:
            Exception: Caught and logged if PyCUDA pattern search fails, falls back to CPU.

        """
        try:
            # Convert to numpy arrays
            data_np = np.frombuffer(data, dtype=np.uint8)
            pattern_np = np.frombuffer(pattern, dtype=np.uint8)

            # CUDA kernel
            kernel_code = """
            __global__ void pattern_match(unsigned char* data, int data_size,
                                         unsigned char* pattern, int pattern_size,
                                         int* matches, int* positions) {
                int idx = blockIdx.x * blockDim.x + threadIdx.x;
                if (idx <= data_size - pattern_size) {
                    bool match = true;
                    for (int i = 0; i < pattern_size; i++) {
                        if (data[idx + i] != pattern[i]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        int match_idx = atomicAdd(matches, 1);
                        if (match_idx < 1000) {
                            positions[match_idx] = idx;
                        }
                    }
                }
            }
            """

            # Compile kernel
            mod = compiler.SourceModule(kernel_code)
            pattern_match = mod.get_function("pattern_match")

            # Allocate GPU memory
            data_gpu = gpuarray.to_gpu(data_np)
            pattern_gpu = gpuarray.to_gpu(pattern_np)
            matches_gpu = gpuarray.zeros(1, dtype=np.int32)
            positions_gpu = gpuarray.zeros(1000, dtype=np.int32)

            # Launch kernel
            threads_per_block = 256
            blocks = (len(data_np) + threads_per_block - 1) // threads_per_block

            pattern_match(
                data_gpu,
                np.int32(len(data_np)),
                pattern_gpu,
                np.int32(len(pattern_np)),
                matches_gpu,
                positions_gpu,
                block=(threads_per_block, 1, 1),
                grid=(blocks, 1),
            )

            # Get results
            match_count = int(matches_gpu.get()[0])
            positions = positions_gpu.get()[: min(match_count, 1000)].tolist()

            return {
                "match_count": match_count,
                "positions": positions,
                "method": "pycuda",
            }

        except Exception as e:
            logger.exception("PyCUDA pattern search failed: %s", e)
            return self._cpu_pattern_search(data, pattern)

    def _cpu_pattern_search(self, data: bytes, pattern: bytes) -> dict[str, Any]:
        """CPU fallback for pattern search.

        Performs pattern matching on CPU using native Python string search method.
        Results are limited to first 1000 matches for performance and memory reasons.

        Args:
            data (bytes): Binary data to search in.
            pattern (bytes): Byte pattern to search for.

        Returns:
            dict[str, Any]: Dictionary with keys: 'match_count' (int), 'positions'
                (list[int]), 'method' (str).

        """
        positions = []
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
            if len(positions) >= 1000:  # Limit to first 1000 matches
                break

        return {
            "match_count": len(positions),
            "positions": positions,
            "method": "cpu",
        }

    def entropy_calculation(self, data: bytes, block_size: int = 1024) -> dict[str, Any]:
        """GPU-accelerated entropy calculation.

        Calculates Shannon entropy for fixed-size blocks of binary data using the best
        available GPU framework. Returns per-block entropies as well as aggregate
        statistics (average, min, max).

        Args:
            data (bytes): Binary data to analyze.
            block_size (int): Size of blocks for entropy calculation in bytes.
                Defaults to 1024.

        Returns:
            dict[str, Any]: Dictionary with keys: 'block_entropies' (list[float]),
                'average_entropy' (float), 'max_entropy' (float), 'min_entropy' (float),
                'execution_time' (float), 'framework' (str).

        """
        start_time = time.time()

        if self.framework == "xpu" and XPU_AVAILABLE:
            result = self._xpu_entropy(data, block_size)
        elif self.framework == "cupy" and CUPY_AVAILABLE:
            result = self._cupy_entropy(data, block_size)
        elif self.framework == "numba" and NUMBA_CUDA_AVAILABLE:
            result = self._numba_entropy(data, block_size)
        else:
            result = self._cpu_entropy(data, block_size)

        result["execution_time"] = time.time() - start_time
        result["framework"] = self.framework
        return result

    def _xpu_entropy(self, data: bytes, block_size: int) -> dict[str, Any]:
        """Native PyTorch XPU implementation of entropy calculation.

        Calculates Shannon entropy for each block using Intel XPU acceleration via
        PyTorch bincount and tensor operations for histogram generation.

        Args:
            data (bytes): Binary data to analyze.
            block_size (int): Size of blocks for entropy calculation in bytes.

        Returns:
            dict[str, Any]: Dictionary with keys: 'block_entropies' (list[float]),
                'average_entropy' (float), 'max_entropy' (float), 'min_entropy' (float),
                'method' (str).

        Raises:
            Exception: Caught and logged if XPU entropy calculation fails, falls back to CPU.

        """
        try:
            data_np = np.frombuffer(data, dtype=np.uint8)
            num_blocks = len(data_np) // block_size
            entropies = []

            # Process blocks on Intel XPU
            for i in range(num_blocks):
                block = data_np[i * block_size : (i + 1) * block_size]
                block_tensor = torch.from_numpy(block).to(device=XPU_DEVICE, dtype=torch.uint8)

                # Calculate histogram using bincount on XPU
                hist = torch.bincount(block_tensor, minlength=256).float()
                hist /= block_size

                # Calculate entropy: -sum(p * log2(p)) for p > 0
                hist_nonzero = hist[hist > 0]
                if len(hist_nonzero) > 0:
                    entropy = -torch.sum(hist_nonzero * torch.log2(hist_nonzero))
                    entropies.append(float(entropy.cpu().item()))
                else:
                    entropies.append(0.0)

            if entropies:
                return {
                    "block_entropies": entropies,
                    "average_entropy": float(np.mean(entropies)),
                    "max_entropy": float(np.max(entropies)),
                    "min_entropy": float(np.min(entropies)),
                    "method": "xpu",
                }
            return {
                "block_entropies": [],
                "average_entropy": 0.0,
                "max_entropy": 0.0,
                "min_entropy": 0.0,
                "method": "xpu",
            }

        except Exception as e:
            logger.exception("Intel XPU entropy calculation failed: %s", e)
            return self._cpu_entropy(data, block_size)

    def _cupy_entropy(self, data: bytes, block_size: int) -> dict[str, Any]:
        """CuPy implementation of entropy calculation.

        Calculates Shannon entropy for each block using CuPy GPU acceleration via
        bincount and log operations for histogram generation and entropy computation.

        Args:
            data (bytes): Binary data to analyze.
            block_size (int): Size of blocks for entropy calculation in bytes.

        Returns:
            dict[str, Any]: Dictionary with keys: 'block_entropies' (list[float]),
                'average_entropy' (float), 'max_entropy' (float), 'min_entropy' (float),
                'method' (str).

        Raises:
            Exception: Caught and logged if CuPy entropy calculation fails, falls back to CPU.

        """
        try:
            data_np = np.frombuffer(data, dtype=np.uint8)
            num_blocks = len(data_np) // block_size
            entropies = []

            for i in range(num_blocks):
                block = data_np[i * block_size : (i + 1) * block_size]
                block_gpu = cp.asarray(block)

                # Calculate histogram
                hist = cp.bincount(block_gpu, minlength=256).astype(cp.float32)
                hist /= block_size

                # Calculate entropy
                hist_nonzero = hist[hist > 0]
                entropy = -cp.sum(hist_nonzero * cp.log2(hist_nonzero))
                entropies.append(float(entropy.get()))

            return {
                "block_entropies": entropies,
                "average_entropy": np.mean(entropies),
                "max_entropy": np.max(entropies),
                "min_entropy": np.min(entropies),
                "method": "cupy",
            }

        except Exception as e:
            logger.exception("CuPy entropy calculation failed: %s", e)
            return self._cpu_entropy(data, block_size)

    def _numba_entropy(self, data: bytes, block_size: int) -> dict[str, Any]:
        """Numba CUDA implementation of entropy calculation.

        Calculates Shannon entropy for each block using Numba CUDA JIT-compiled kernels
        that compute histograms and entropy values in parallel on GPU.

        Args:
            data (bytes): Binary data to analyze.
            block_size (int): Size of blocks for entropy calculation in bytes.

        Returns:
            dict[str, Any]: Dictionary with keys: 'block_entropies' (list[float]),
                'average_entropy' (float), 'max_entropy' (float), 'min_entropy' (float),
                'method' (str).

        Raises:
            Exception: Caught and logged if Numba entropy calculation fails, falls back to CPU.

        """
        try:
            kernel = self._create_entropy_kernel()

            data_np = np.frombuffer(data, dtype=np.uint8)
            num_blocks = len(data_np) // block_size

            # Transfer to GPU
            d_data = numba_cuda.to_device(data_np)
            d_entropies = numba_cuda.device_array(num_blocks, dtype=np.float32)

            # Launch kernel
            threads_per_block = 256
            blocks = (num_blocks + threads_per_block - 1) // threads_per_block
            kernel[blocks, threads_per_block](d_data, block_size, d_entropies)

            # Get results
            entropies = d_entropies.copy_to_host().tolist()

            return {
                "block_entropies": entropies,
                "average_entropy": np.mean(entropies),
                "max_entropy": np.max(entropies),
                "min_entropy": np.min(entropies),
                "method": "numba_cuda",
            }

        except Exception as e:
            logger.exception("Numba entropy calculation failed: %s", e)
            return self._cpu_entropy(data, block_size)

    def _create_entropy_kernel(self) -> Any:
        """Create Numba CUDA entropy calculation kernel.

        Compiles and returns a Numba CUDA kernel that calculates Shannon entropy for
        data blocks using histogram computation and log-based entropy formula.

        Returns:
            Any: Compiled Numba CUDA kernel function with signature
                (data, block_size, entropies) -> None.

        Raises:
            RuntimeError: If Numba CUDA is not available or not properly initialized.

        """
        if not NUMBA_CUDA_AVAILABLE or numba_cuda is None or numba is None:
            raise RuntimeError("Numba CUDA not available")

        @numba_cuda.jit
        def entropy_kernel(
            data: Any,
            block_size: Any,
            entropies: Any,
        ) -> None:
            """Numba CUDA kernel for entropy calculation.

            Computes Shannon entropy for a data block in parallel on GPU. Each thread
            computes the entropy for one block using histogram computation.

            Args:
                data: GPU array of bytes to analyze.
                block_size: Size of each block in bytes.
                entropies: GPU array for storing computed entropy values.

            Returns:
                None

            """
            block_idx = numba_cuda.grid(1)
            if block_idx < len(entropies):
                # Calculate histogram for this block
                hist = numba_cuda.local.array(256, numba.float32)
                for i in range(256):
                    hist[i] = 0

                # Count byte occurrences
                start = block_idx * block_size
                end = min(start + block_size, len(data))
                for i in range(start, end):
                    hist[data[i]] += 1

                # Normalize and calculate entropy
                entropy = 0.0
                for i in range(256):
                    if hist[i] > 0:
                        p = hist[i] / block_size
                        entropy -= p * numba.cuda.libdevice.log2f(p)

                entropies[block_idx] = entropy

        return entropy_kernel

    def _cpu_entropy(self, data: bytes, block_size: int) -> dict[str, Any]:
        """CPU fallback for entropy calculation.

        Calculates Shannon entropy for each block using NumPy histogram and log
        operations for entropy computation on CPU.

        Args:
            data (bytes): Binary data to analyze.
            block_size (int): Size of blocks for entropy calculation in bytes.

        Returns:
            dict[str, Any]: Dictionary with keys: 'block_entropies' (list[float]),
                'average_entropy' (float), 'max_entropy' (float), 'min_entropy' (float),
                'method' (str).

        """
        data_np = np.frombuffer(data, dtype=np.uint8)
        num_blocks = len(data_np) // block_size
        entropies = []

        for i in range(num_blocks):
            block = data_np[i * block_size : (i + 1) * block_size]

            # Calculate histogram
            hist, _ = np.histogram(block, bins=256, range=(0, 255))
            hist = hist.astype(np.float32) / block_size

            # Calculate entropy
            hist_nonzero = hist[hist > 0]
            entropy = -np.sum(hist_nonzero * np.log2(hist_nonzero))
            entropies.append(entropy)

        return {
            "block_entropies": entropies,
            "average_entropy": np.mean(entropies) if entropies else 0,
            "max_entropy": np.max(entropies) if entropies else 0,
            "min_entropy": np.min(entropies) if entropies else 0,
            "method": "cpu",
        }

    def hash_computation(self, data: bytes, algorithms: list[str] | None = None) -> dict[str, Any]:
        """GPU-accelerated hash computation.

        Computes cryptographic hashes for binary data using supported algorithms.
        Currently supports CRC32 and Adler32, with GPU acceleration for CRC32 when
        CuPy is available.

        Args:
            data (bytes): Binary data to hash.
            algorithms (list[str] | None): List of hash algorithms to compute.
                Supported values: 'crc32', 'adler32'. Defaults to ['crc32', 'adler32'].

        Returns:
            dict[str, Any]: Dictionary with keys: 'hashes' (dict[str, str]),
                'execution_time' (float), 'framework' (str). Hash values are
                hexadecimal strings.

        """
        if algorithms is None:
            algorithms = ["crc32", "adler32"]

        start_time = time.time()
        results = {}

        for algo in algorithms:
            if algo == "crc32" and self.framework == "cupy" and CUPY_AVAILABLE:
                results[algo] = self._cupy_crc32(data)
            else:
                import zlib

                if algo == "crc32":
                    results[algo] = format(zlib.crc32(data) & 0xFFFFFFFF, "08x")
                elif algo == "adler32":
                    results[algo] = format(zlib.adler32(data) & 0xFFFFFFFF, "08x")

        return {
            "hashes": results,
            "execution_time": time.time() - start_time,
            "framework": self.framework,
        }

    def _cupy_crc32(self, data: bytes) -> str:
        """CuPy implementation of CRC32.

        Computes CRC32 checksum using CuPy with GPU acceleration. Falls back to
        zlib CPU implementation if CuPy computation fails.

        Args:
            data (bytes): Binary data to hash.

        Returns:
            str: Hexadecimal string representation of the CRC32 hash (8 characters).

        Raises:
            Exception: Caught and logged if CuPy CRC32 calculation fails, falls back to zlib.

        """
        try:
            # Simple CRC32 implementation for demonstration
            data_gpu = cp.asarray(np.frombuffer(data, dtype=np.uint8))

            # CRC32 polynomial
            polynomial = 0xEDB88320

            # Initialize CRC table on GPU
            crc_table = cp.zeros(256, dtype=cp.uint32)
            for i in range(256):
                crc = i
                for _ in range(8):
                    if crc & 1:
                        crc = (crc >> 1) ^ polynomial
                    else:
                        crc >>= 1
                crc_table[i] = crc

            # Calculate CRC32
            crc = cp.uint32(0xFFFFFFFF)
            for byte in data_gpu:
                crc = crc_table[(crc ^ byte) & 0xFF] ^ (crc >> 8)

            result = int((crc ^ 0xFFFFFFFF).get())
            return format(result & 0xFFFFFFFF, "08x")

        except Exception as e:
            logger.exception("CuPy CRC32 failed: %s", e)
            import zlib

            return format(zlib.crc32(data) & 0xFFFFFFFF, "08x")


# Global accelerator instance
gpu_accelerator: GPUAccelerator | None = None


def get_gpu_accelerator() -> GPUAccelerator:
    """Get or create GPU accelerator instance.

    Returns a singleton GPUAccelerator instance, creating one on first call.
    Subsequent calls return the cached instance.

    Returns:
        GPUAccelerator: The global GPU accelerator instance.

    """
    global gpu_accelerator
    if gpu_accelerator is None:
        gpu_accelerator = GPUAccelerator()
    return gpu_accelerator
