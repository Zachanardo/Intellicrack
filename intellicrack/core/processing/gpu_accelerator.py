"""GPU Acceleration Module.

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

from intellicrack.handlers.numpy_handler import numpy as np
from intellicrack.handlers.opencl_handler import OPENCL_AVAILABLE, cl
from intellicrack.utils.logger import logger

from ...utils.core.import_checks import TENSORFLOW_AVAILABLE
from ...utils.gpu_autoloader import get_device, get_gpu_info, gpu_autoloader
from ...utils.logger import get_logger

# Optional GPU backend imports
try:
    import pyopencl.array as cl_array
except ImportError as e:
    logger.error("Import error in gpu_accelerator: %s", e)
    cl_array = None

try:
    import cupy as cp

    CUPY_AVAILABLE = True
except ImportError as e:
    logger.debug("Optional dependency cupy not available: %s", e)
    CUPY_AVAILABLE = False
    cp = None


logger = get_logger(__name__)


class GPUAccelerationManager:
    """Manages GPU acceleration for analysis operations using unified GPU autoloader."""

    def __init__(self, use_intel_pytorch: bool = True, prefer_intel: bool = True) -> None:
        """Initialize GPU acceleration manager.

        Args:
            use_intel_pytorch: Whether to try Intel Extension for PyTorch (default: True)
            prefer_intel: Whether to prefer Intel GPUs when multiple GPUs are available (default: True)

        """
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        self.use_intel_pytorch = use_intel_pytorch
        self.prefer_intel = prefer_intel

        # Use the unified GPU autoloader
        self.gpu_info = get_gpu_info()
        self.gpu_available = self.gpu_info["available"]
        self.gpu_type = self.gpu_info["type"]
        self.device = get_device()

        # Get torch reference if available - respect use_intel_pytorch setting
        if use_intel_pytorch:
            self._torch = gpu_autoloader.get_torch()
            self._ipex = gpu_autoloader.get_ipex()
        else:
            self._torch = gpu_autoloader.get_torch() if self.gpu_type != "intel_xpu" else None
            self._ipex = None
            if self.gpu_type == "intel_xpu" and not use_intel_pytorch:
                self.logger.info("Intel PyTorch disabled by configuration, falling back to OpenCL")

        # Legacy attributes for compatibility
        self.gpu_backend = self._determine_backend()
        self.context = None
        self.queue = None
        self.cl = cl
        self.cl_array = cl_array
        self.cupy = cp

        # Initialize OpenCL if available and needed
        if OPENCL_AVAILABLE and self.gpu_type not in ["intel_xpu", "nvidia_cuda", "amd_rocm"]:
            self._init_opencl()

    def _determine_backend(self) -> str | None:
        """Determine the backend based on GPU type and configuration."""
        if self.gpu_type == "intel_xpu":
            if self.use_intel_pytorch and self._ipex:
                return "intel_pytorch"
            if OPENCL_AVAILABLE:
                return "pyopencl"
            return "intel_pytorch"  # fallback even without IPEX
        if self.gpu_type == "nvidia_cuda":
            if CUPY_AVAILABLE:
                return "cupy"
            return "pytorch"
        if self.gpu_type == "amd_rocm":
            return "pytorch"
        if self.gpu_type == "directml":
            return "directml"
        if OPENCL_AVAILABLE:
            return "pyopencl"
        return None

    def _init_opencl(self) -> None:
        """Initialize OpenCL context if needed."""
        try:
            # Look for the best GPU device
            best_device = None
            best_platform = None

            for platform in cl.get_platforms():
                try:
                    devices = platform.get_devices(device_type=cl.device_type.GPU)
                    if devices:
                        best_device = devices[0]
                        best_platform = platform
                        break
                except Exception as e:
                    self.logger.debug(f"OpenCL platform error: {e}")
                    continue

            if best_device:
                self.context = cl.Context([best_device])
                self.queue = cl.CommandQueue(self.context)
                self.logger.info(f"OpenCL initialized: {best_platform.name}, {best_device.name}")

        except Exception as e:
            self.logger.debug(f"OpenCL initialization failed: {e}")

    def is_acceleration_available(self) -> bool:
        """Check if GPU acceleration is available."""
        return self.gpu_available

    def get_gpu_type(self) -> str | None:
        """Get the type of GPU acceleration available."""
        return self.gpu_type

    def get_backend(self) -> str | None:
        """Get the GPU backend type."""
        return self.gpu_backend

    def accelerate_pattern_matching(self, data: bytes, patterns: list[bytes]) -> list[int]:
        """GPU-accelerated pattern matching.

        Args:
            data: Binary data to search in
            patterns: List of byte patterns to search for

        Returns:
            List of match positions

        """
        if not self.gpu_available:
            self.logger.warning("GPU acceleration not available, falling back to CPU")
            return self._cpu_pattern_matching(data, patterns)

        try:
            if self.gpu_backend == "pyopencl" and self.context:
                return self._opencl_pattern_matching(data, patterns)
            if self.gpu_backend == "cupy" and cp:
                return self._cupy_pattern_matching(data, patterns)
            if self._torch:
                return self._torch_pattern_matching(data, patterns)
            self.logger.warning("Pattern matching not implemented for backend: %s", self.gpu_backend)
            return self._cpu_pattern_matching(data, patterns)
        except Exception as e:
            self.logger.error("GPU pattern matching failed: %s", e)
            return self._cpu_pattern_matching(data, patterns)

    def _cpu_pattern_matching(self, data: bytes, patterns: list[bytes]) -> list[int]:
        """Fallback CPU pattern matching."""
        matches = []
        for pattern in patterns:
            pos = 0
            while True:
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                matches.append(pos)
                pos += 1
        return sorted(matches)

    def _torch_pattern_matching(self, data: bytes, patterns: list[bytes]) -> list[int]:
        """PyTorch-based pattern matching for Intel XPU/CUDA/ROCm."""
        if not self._torch:
            return self._cpu_pattern_matching(data, patterns)

        all_matches = []

        # Convert data to tensor on device
        data_np = np.frombuffer(data, dtype=np.uint8)
        data_tensor = self._torch.tensor(data_np, dtype=self._torch.uint8, device=self.device)

        for pattern in patterns:
            pattern_np = np.frombuffer(pattern, dtype=np.uint8)
            pattern_tensor = self._torch.tensor(pattern_np, dtype=self._torch.uint8, device=self.device)

            # Use convolution for pattern matching
            if len(pattern) <= len(data):
                # Create a sliding window view
                windows = data_tensor.unfold(0, len(pattern), 1)

                # Compare each window with the pattern
                matches_mask = (windows == pattern_tensor).all(dim=1)

                # Get match positions
                match_positions = self._torch.where(matches_mask)[0].cpu().numpy().tolist()
                all_matches.extend(match_positions)

        # Synchronize if needed
        gpu_autoloader.synchronize()

        return sorted(all_matches)

    def _opencl_pattern_matching(self, data: bytes, patterns: list[bytes]) -> list[int]:
        """OpenCL-based pattern matching."""
        if not self.cl or not self.context:
            return self._cpu_pattern_matching(data, patterns)

        # OpenCL kernel for pattern matching
        kernel_source = """
        __kernel void pattern_match(
            __global const uchar* data,
            const int data_size,
            __global const uchar* pattern,
            const int pattern_size,
            __global int* matches,
            __global int* match_count
        ) {
            int gid = get_global_id(0);

            if (gid > data_size - pattern_size) {
                return;
            }

            int is_match = 1;
            for (int i = 0; i < pattern_size; i++) {
                if (data[gid + i] != pattern[i]) {
                    is_match = 0;
                    break;
                }
            }

            if (is_match) {
                int idx = atomic_inc(match_count);
                if (idx < 10000) {
                    matches[idx] = gid;
                }
            }
        }
        """

        program = self.cl.Program(self.context, kernel_source).build()

        all_matches = []

        for pattern in patterns:
            data_array = np.frombuffer(data, dtype=np.uint8)
            pattern_array = np.frombuffer(pattern, dtype=np.uint8)

            max_matches = 10000
            matches_array = np.zeros(max_matches, dtype=np.int32)
            match_count = np.zeros(1, dtype=np.int32)

            mf = self.cl.mem_flags
            data_buffer = self.cl.Buffer(self.context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=data_array)
            pattern_buffer = self.cl.Buffer(self.context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pattern_array)
            matches_buffer = self.cl.Buffer(self.context, mf.WRITE_ONLY, matches_array.nbytes)
            count_buffer = self.cl.Buffer(self.context, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=match_count)

            global_size = (len(data_array),)
            local_size = None

            program.pattern_match(
                self.queue,
                global_size,
                local_size,
                data_buffer,
                np.int32(len(data_array)),
                pattern_buffer,
                np.int32(len(pattern_array)),
                matches_buffer,
                count_buffer,
            )

            self.cl.enqueue_copy(self.queue, matches_array, matches_buffer)
            self.cl.enqueue_copy(self.queue, match_count, count_buffer)
            self.queue.finish()

            num_matches = match_count[0]
            if num_matches > 0:
                all_matches.extend(matches_array[: min(num_matches, max_matches)].tolist())

            self.logger.debug(f"OpenCL found {num_matches} matches for pattern of size {len(pattern)}")

        return sorted(all_matches)

    def _cupy_pattern_matching(self, data: bytes, patterns: list[bytes]) -> list[int]:
        """CUDA-based pattern matching using CuPy."""
        if not cp:
            return self._cpu_pattern_matching(data, patterns)

        # CUDA kernel for pattern matching
        pattern_match_kernel = cp.RawKernel(
            r"""
        extern "C" __global__
        void pattern_match(
            const unsigned char* data,
            const int data_size,
            const unsigned char* pattern,
            const int pattern_size,
            int* matches,
            int* match_count
        ) {
            int tid = blockDim.x * blockIdx.x + threadIdx.x;

            if (tid > data_size - pattern_size) {
                return;
            }

            bool is_match = true;
            for (int i = 0; i < pattern_size; i++) {
                if (data[tid + i] != pattern[i]) {
                    is_match = false;
                    break;
                }
            }

            if (is_match) {
                int idx = atomicAdd(match_count, 1);
                if (idx < 10000) {
                    matches[idx] = tid;
                }
            }
        }
        """,
            "pattern_match",
        )

        all_matches = []

        for pattern in patterns:
            data_gpu = cp.asarray(np.frombuffer(data, dtype=np.uint8))
            pattern_gpu = cp.asarray(np.frombuffer(pattern, dtype=np.uint8))

            max_matches = 10000
            matches_gpu = cp.zeros(max_matches, dtype=cp.int32)
            match_count_gpu = cp.zeros(1, dtype=cp.int32)

            threads_per_block = 256
            blocks_per_grid = (len(data) + threads_per_block - 1) // threads_per_block

            pattern_match_kernel(
                (blocks_per_grid,),
                (threads_per_block,),
                (data_gpu, len(data), pattern_gpu, len(pattern), matches_gpu, match_count_gpu),
            )

            cp.cuda.Stream.null.synchronize()

            num_matches = int(match_count_gpu.get()[0])
            if num_matches > 0:
                matches_cpu = matches_gpu[: min(num_matches, max_matches)].get()
                all_matches.extend(matches_cpu.tolist())

            self.logger.debug(f"CUDA found {num_matches} matches for pattern of size {len(pattern)}")

        return sorted(all_matches)


class GPUAccelerator(GPUAccelerationManager):
    """Legacy GPUAccelerator class for backward compatibility.

    Now inherits from GPUAccelerationManager and uses the unified GPU system.
    """

    def __init__(self) -> None:
        """Initialize the GPU accelerator using the new unified system."""
        super().__init__(use_intel_pytorch=True, prefer_intel=True)

        # Legacy attributes
        self.cuda_available = self.gpu_type == "nvidia_cuda"
        self.opencl_available = OPENCL_AVAILABLE
        self.tensorflow_available = TENSORFLOW_AVAILABLE and self.gpu_available
        self.pytorch_available = self._torch is not None
        self.intel_pytorch_available = self.gpu_type == "intel_xpu"

        # Legacy device lists
        self.cuda_devices = []
        self.opencl_devices = []
        self.tensorflow_devices = []
        self.pytorch_devices = []
        self.intel_devices = []

        # Populate legacy device info
        if self.gpu_available:
            device_info = {
                "index": 0,
                "name": self.gpu_info.get("device_name", "Unknown GPU"),
                "memory": self.gpu_info.get("total_memory", "Unknown"),
                "backend": self.gpu_backend,
            }

            if self.gpu_type == "nvidia_cuda":
                self.cuda_devices.append(device_info)
                self.pytorch_devices.append(device_info)
            elif self.gpu_type == "intel_xpu":
                self.intel_devices.append(device_info)
                self.pytorch_devices.append(device_info)
            elif self.gpu_type == "amd_rocm":
                self.pytorch_devices.append(device_info)

            if OPENCL_AVAILABLE:
                self.opencl_devices.append(device_info)

        # Legacy attributes
        self.selected_backend = self.gpu_backend
        self.detected_gpu_vendor = self._detect_vendor()
        self.detected_gpu_name = self.gpu_info.get("device_name", "Unknown")

        # Benchmarking and error handling
        self.backend_benchmarks = {}
        self.error_counts = {}
        self.blacklisted_backends = set()

    def _detect_vendor(self) -> str:
        """Detect GPU vendor from type."""
        if self.gpu_type and "intel" in self.gpu_type:
            return "Intel"
        if self.gpu_type and ("nvidia" in self.gpu_type or "cuda" in self.gpu_type):
            return "NVIDIA"
        if self.gpu_type and ("amd" in self.gpu_type or "rocm" in self.gpu_type):
            return "AMD"
        return "Unknown"

    def _check_available_backends(self) -> None:
        """Legacy method for compatibility."""

    def _select_preferred_backend(self) -> None:
        """Legacy method for compatibility."""

    def _run_initial_benchmarks(self) -> None:
        """Legacy method for compatibility."""


def create_gpu_acceleration_manager():
    """Create a GPU acceleration manager.

    Returns:
        GPUAccelerationManager: Configured GPU acceleration manager instance

    """
    try:
        return GPUAccelerationManager()
    except Exception as e:
        logger.error(f"Failed to create GPU acceleration manager: {e}")
        return None


def create_gpu_accelerator():
    """Create a GPU accelerator.

    Returns:
        GPUAccelerator: Configured GPU accelerator instance

    """
    try:
        return GPUAccelerator()
    except Exception as e:
        logger.error(f"Failed to create GPU accelerator: {e}")
        return None


def is_gpu_acceleration_available():
    """Check if GPU acceleration is available on this system.

    Returns:
        bool: True if GPU acceleration is available, False otherwise

    """
    try:
        gpu_info = get_gpu_info()
        return gpu_info.get("available", False)
    except Exception as e:
        logger.debug(f"GPU availability check failed: {e}")
        return False
