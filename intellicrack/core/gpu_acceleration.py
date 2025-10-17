"""GPU-accelerated binary analysis functions.

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

logger = logging.getLogger(__name__)

XPU_DEVICE = "xpu:0"

# GPU framework availability flags
PYCUDA_AVAILABLE = False
CUPY_AVAILABLE = False
NUMBA_CUDA_AVAILABLE = False
IPEX_AVAILABLE = False
PYTORCH_AVAILABLE = False

# Check if CUDA is disabled via environment
CUDA_DISABLED = os.environ.get("CUDA_VISIBLE_DEVICES") == "-1"
INTEL_GPU_PREFERRED = os.environ.get("INTELLICRACK_GPU_TYPE") == "intel"

# Try importing Intel Extension for PyTorch first if preferred
if INTEL_GPU_PREFERRED or not CUDA_DISABLED:
    try:
        import torch

        PYTORCH_AVAILABLE = True
        logger.debug("PyTorch available")

        try:
            from intellicrack.handlers.ipex_handler import HAS_IPEX, ipex

            if HAS_IPEX and torch.xpu.is_available():
                IPEX_AVAILABLE = True
                logger.info(f"Intel Extension for PyTorch initialized successfully - {torch.xpu.device_count()} XPU device(s) found")
                for i in range(torch.xpu.device_count()):
                    logger.info(f"XPU Device {i}: {torch.xpu.get_device_name(i)}")
            else:
                logger.debug("Intel XPU not available")
        except Exception as e:
            logger.debug("Intel Extension for PyTorch initialization error: %s", e)
    except ImportError:
        logger.debug("PyTorch not available")

# Try importing CUDA frameworks only if not disabled
if not CUDA_DISABLED:
    try:
        import pycuda.autoinit  # noqa: F401 - Required for CUDA initialization
        import pycuda.driver as cuda
        from pycuda import compiler, gpuarray

        PYCUDA_AVAILABLE = True
        logger.info("PyCUDA initialized successfully")
    except ImportError:
        logger.debug("PyCUDA not available")
    except Exception as e:
        logger.debug(f"PyCUDA initialization failed: {e}")

    try:
        import cupy as cp

        CUPY_AVAILABLE = True
        logger.info("CuPy initialized successfully")
    except ImportError:
        logger.debug("CuPy not available")
    except Exception as e:
        logger.debug(f"CuPy initialization failed: {e}")

    try:
        import numba
        from numba import cuda as numba_cuda

        NUMBA_CUDA_AVAILABLE = True
        logger.info("Numba CUDA initialized successfully")
    except ImportError:
        logger.debug("Numba CUDA not available")
    except Exception as e:
        logger.debug(f"Numba CUDA initialization failed: {e}")
else:
    logger.debug("CUDA disabled via CUDA_VISIBLE_DEVICES=-1")


class GPUAccelerator:
    """GPU acceleration for binary analysis tasks."""

    def __init__(self):
        """Initialize GPU accelerator."""
        self.framework = self._detect_best_framework()
        self.device_info = self._get_device_info()
        logger.info(f"GPU Accelerator initialized with {self.framework}")

    def _detect_best_framework(self) -> str:
        """Detect the best available GPU framework."""
        # Prioritize Intel GPU if preferred or only option available
        if INTEL_GPU_PREFERRED and IPEX_AVAILABLE:
            return "ipex"

        # If CUDA is disabled, check Intel GPU first
        if CUDA_DISABLED:
            if IPEX_AVAILABLE:
                return "ipex"
            return "cpu"

        # Standard priority order for CUDA frameworks
        if CUPY_AVAILABLE:
            return "cupy"
        if NUMBA_CUDA_AVAILABLE:
            return "numba"
        if PYCUDA_AVAILABLE:
            return "pycuda"

        # Fall back to Intel GPU if available
        if IPEX_AVAILABLE:
            return "ipex"

        return "cpu"

    def _get_device_info(self) -> dict[str, Any]:
        """Get GPU device information."""
        if self.framework == "ipex" and IPEX_AVAILABLE:
            return self._get_ipex_device_info()
        elif self.framework == "cupy" and CUPY_AVAILABLE:
            return self._get_cupy_device_info()
        elif self.framework == "pycuda" and PYCUDA_AVAILABLE:
            return self._get_pycuda_device_info()
        elif self.framework == "numba" and NUMBA_CUDA_AVAILABLE:
            return self._get_numba_device_info()
        return {}

    def _get_ipex_device_info(self) -> dict[str, Any]:
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
            logger.debug(f"Failed to get Intel XPU device info: {e}")
        return info

    def _get_cupy_device_info(self) -> dict[str, Any]:
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
            logger.debug(f"Failed to get CuPy device info: {e}")
        return info

    def _get_pycuda_device_info(self) -> dict[str, Any]:
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
            logger.debug(f"Failed to get PyCUDA device info: {e}")
        return info

    def _get_numba_device_info(self) -> dict[str, Any]:
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
            logger.debug(f"Failed to get Numba device info: {e}")
        return info

    def parallel_pattern_search(self, data: bytes, pattern: bytes) -> dict[str, Any]:
        """GPU-accelerated pattern search in binary data.

        Args:
            data: Binary data to search in
            pattern: Pattern to search for

        Returns:
            Dictionary with match count and positions

        """
        start_time = time.time()

        if self.framework == "ipex" and IPEX_AVAILABLE:
            result = self._ipex_pattern_search(data, pattern)
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

    def _ipex_pattern_search(self, data: bytes, pattern: bytes) -> dict[str, Any]:
        """Intel Extension for PyTorch implementation of pattern search."""
        try:
            # Apply IPEX optimizations for Intel GPU
            torch.xpu.empty_cache()  # Clear XPU cache for optimal performance

            # Enable IPEX optimizations
            with torch.xpu.device(0):
                ipex.optimize_for_inference()  # Apply IPEX inference optimizations

                # Convert data to PyTorch tensors on Intel XPU
                data_np = np.frombuffer(data, dtype=np.uint8)
                pattern_np = np.frombuffer(pattern, dtype=np.uint8)

                # Use IPEX-optimized tensor creation
                data_tensor = torch.from_numpy(data_np).to(device=XPU_DEVICE, dtype=torch.uint8)
                pattern_tensor = torch.from_numpy(pattern_np).to(device=XPU_DEVICE, dtype=torch.uint8)

                # Apply IPEX memory optimizations
                if hasattr(ipex, "optimize_memory_allocation"):
                    ipex.optimize_memory_allocation(data_tensor)
                    ipex.optimize_memory_allocation(pattern_tensor)

            # Efficient pattern matching using sliding window approach
            data_len = data_tensor.size(0)
            pattern_len = pattern_tensor.size(0)

            if pattern_len > data_len:
                return {
                    "match_count": 0,
                    "positions": [],
                    "method": "ipex_xpu",
                }

            # Create sliding windows of data for comparison
            matches = []
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
                "method": "ipex_xpu",
            }

        except Exception as e:
            logger.error(f"Intel XPU pattern search failed: {e}")
            return self._cpu_pattern_search(data, pattern)

    def _cupy_pattern_search(self, data: bytes, pattern: bytes) -> dict[str, Any]:
        """CuPy implementation of pattern search."""
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
            logger.error(f"CuPy pattern search failed: {e}")
            return self._cpu_pattern_search(data, pattern)

    def _numba_pattern_search(self, data: bytes, pattern: bytes) -> dict[str, Any]:
        """Numba CUDA implementation of pattern search."""
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
            logger.error(f"Numba pattern search failed: {e}")
            return self._cpu_pattern_search(data, pattern)

    def _create_pattern_match_kernel(self):
        @numba_cuda.jit
        def pattern_match_kernel(data, pattern, matches, positions):
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
        """PyCUDA implementation of pattern search."""
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
            logger.error(f"PyCUDA pattern search failed: {e}")
            return self._cpu_pattern_search(data, pattern)

    def _cpu_pattern_search(self, data: bytes, pattern: bytes) -> dict[str, Any]:
        """CPU fallback for pattern search."""
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

        Args:
            data: Binary data to analyze
            block_size: Size of blocks for entropy calculation

        Returns:
            Dictionary with entropy values

        """
        start_time = time.time()

        if self.framework == "ipex" and IPEX_AVAILABLE:
            result = self._ipex_entropy(data, block_size)
        elif self.framework == "cupy" and CUPY_AVAILABLE:
            result = self._cupy_entropy(data, block_size)
        elif self.framework == "numba" and NUMBA_CUDA_AVAILABLE:
            result = self._numba_entropy(data, block_size)
        else:
            result = self._cpu_entropy(data, block_size)

        result["execution_time"] = time.time() - start_time
        result["framework"] = self.framework
        return result

    def _ipex_entropy(self, data: bytes, block_size: int) -> dict[str, Any]:
        """Intel Extension for PyTorch implementation of entropy calculation."""
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
                hist = hist / block_size

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
                    "method": "ipex_xpu",
                }
            else:
                return {
                    "block_entropies": [],
                    "average_entropy": 0.0,
                    "max_entropy": 0.0,
                    "min_entropy": 0.0,
                    "method": "ipex_xpu",
                }

        except Exception as e:
            logger.error(f"Intel XPU entropy calculation failed: {e}")
            return self._cpu_entropy(data, block_size)

    def _cupy_entropy(self, data: bytes, block_size: int) -> dict[str, Any]:
        """CuPy implementation of entropy calculation."""
        try:
            data_np = np.frombuffer(data, dtype=np.uint8)
            num_blocks = len(data_np) // block_size
            entropies = []

            for i in range(num_blocks):
                block = data_np[i * block_size : (i + 1) * block_size]
                block_gpu = cp.asarray(block)

                # Calculate histogram
                hist = cp.bincount(block_gpu, minlength=256).astype(cp.float32)
                hist = hist / block_size

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
            logger.error(f"CuPy entropy calculation failed: {e}")
            return self._cpu_entropy(data, block_size)

    def _numba_entropy(self, data: bytes, block_size: int) -> dict[str, Any]:
        """Numba CUDA implementation of entropy calculation."""
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
            logger.error(f"Numba entropy calculation failed: {e}")
            return self._cpu_entropy(data, block_size)

    def _create_entropy_kernel(self):
        @numba_cuda.jit
        def entropy_kernel(data, block_size, entropies):
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
        """CPU fallback for entropy calculation."""
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

    def hash_computation(self, data: bytes, algorithms: list[str] = None) -> dict[str, Any]:
        """GPU-accelerated hash computation.

        Args:
            data: Binary data to hash
            algorithms: List of hash algorithms to compute

        Returns:
            Dictionary with hash values

        """
        if algorithms is None:
            algorithms = ["crc32", "adler32"]

        start_time = time.time()
        results = {}

        for algo in algorithms:
            if algo == "crc32" and self.framework == "cupy" and CUPY_AVAILABLE:
                results[algo] = self._cupy_crc32(data)
            else:
                # CPU fallback for now
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
        """CuPy implementation of CRC32."""
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
            logger.error(f"CuPy CRC32 failed: {e}")
            import zlib

            return format(zlib.crc32(data) & 0xFFFFFFFF, "08x")


# Global accelerator instance
gpu_accelerator = None


def get_gpu_accelerator() -> GPUAccelerator:
    """Get or create GPU accelerator instance."""
    global gpu_accelerator
    if gpu_accelerator is None:
        gpu_accelerator = GPUAccelerator()
    return gpu_accelerator
