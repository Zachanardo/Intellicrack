"""
GPU Acceleration Module

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


import os
from typing import Any, Dict, List, Optional

# Optional GPU backend imports
try:
    import pyopencl as cl
    import pyopencl.array as cl_array
    OPENCL_AVAILABLE = True
except ImportError:
    OPENCL_AVAILABLE = False
    cl = None
    cl_array = None

try:
    import cupy as cp
    CUPY_AVAILABLE = True
except ImportError:
    CUPY_AVAILABLE = False
    cp = None

try:
    import intel_extension_for_pytorch as ipex
    import torch
    INTEL_PYTORCH_AVAILABLE = True
except ImportError:
    INTEL_PYTORCH_AVAILABLE = False
    torch = None
    ipex = None

from ...utils.core.import_checks import TENSORFLOW_AVAILABLE, tf
from ...utils.logger import get_logger

logger = get_logger(__name__)

class GPUAccelerationManager:
    """Manages GPU acceleration for analysis operations."""

    def __init__(self, use_intel_pytorch: bool = False):
        """Initialize GPU acceleration manager.

        Args:
            use_intel_pytorch: Whether to try Intel Extension for PyTorch (default: False)
        """
        self.gpu_available = False
        self.gpu_type = None
        self.gpu_backend = None
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")

        # Prioritize PyOpenCL as it works on all vendors (Intel, AMD, NVIDIA)
        if OPENCL_AVAILABLE:
            try:
                # Look for the best GPU device
                best_device = None
                best_platform = None

                for platform in cl.get_platforms():
                    try:
                        devices = platform.get_devices(device_type=cl.device_type.GPU)
                        if devices:
                            # Prefer discrete GPUs over integrated
                            for device in devices:
                                if best_device is None:
                                    best_device = device
                                    best_platform = platform
                                elif 'Intel' in device.name and 'Arc' in device.name:
                                    # Prefer Intel Arc GPUs
                                    best_device = device
                                    best_platform = platform
                                elif 'NVIDIA' in device.name or 'AMD' in device.name:
                                    # Also prefer discrete GPUs from NVIDIA/AMD
                                    best_device = device
                                    best_platform = platform
                    except (AttributeError, RuntimeError):
                        continue

                if best_device:
                    self.context = cl.Context([best_device])
                    self.queue = cl.CommandQueue(self.context)
                    self.cl = cl
                    self.cl_array = cl_array
                    self.gpu_backend = 'pyopencl'
                    self.gpu_available = True
                    self.gpu_type = f'OpenCL ({best_platform.name}, {best_device.name})'
                    self.logger.info("PyOpenCL GPU acceleration available: %s", self.gpu_type)

            except (OSError, ValueError, RuntimeError) as e:
                self.logger.debug("PyOpenCL initialization failed: %s", e)
        else:
            self.logger.info("PyOpenCL not available - install with: pip install pyopencl")

        # Only try CuPy if PyOpenCL is not available and we have NVIDIA GPU
        if not self.gpu_available and CUPY_AVAILABLE:
            try:
                # Verify it actually works
                test_array = cp.array([1, 2, 3])
                _test_result = cp.sum(test_array)

                self.cupy = cp
                self.gpu_backend = 'cupy'
                self.gpu_available = True
                self.gpu_type = 'CUDA (CuPy)'
                self.logger.info("CuPy GPU acceleration available")
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.debug("CuPy initialization failed: %s", e)

        # Only try Intel Extension for PyTorch if explicitly requested
        if not self.gpu_available and use_intel_pytorch and INTEL_PYTORCH_AVAILABLE:
            try:
                if torch.xpu.is_available():
                    self.torch = torch
                    self.ipex = ipex
                    self.gpu_backend = 'intel_pytorch'
                    self.gpu_available = True
                    self.gpu_type = f'Intel XPU ({torch.xpu.get_device_name(0)})'
                    self.logger.info("Intel PyTorch GPU acceleration available: %s", self.gpu_type)
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.debug("Intel PyTorch initialization failed: %s", e)

        if not self.gpu_available:
            self.logger.info("No GPU acceleration available. Install pyopencl for universal GPU support: pip install pyopencl")

    def is_acceleration_available(self) -> bool:
        """Check if GPU acceleration is available."""
        return self.gpu_available

    def get_gpu_type(self) -> Optional[str]:
        """Get the type of GPU acceleration available."""
        return self.gpu_type

    def get_backend(self) -> Optional[str]:
        """Get the GPU backend type."""
        return self.gpu_backend

    def accelerate_pattern_matching(self, data: bytes, patterns: List[bytes]) -> List[int]:
        """
        GPU-accelerated pattern matching.

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
            if self.gpu_backend == 'pyopencl':
                return self._opencl_pattern_matching(data, patterns)
            elif self.gpu_backend == 'cupy':
                return self._cupy_pattern_matching(data, patterns)
            else:
                self.logger.warning("Pattern matching not implemented for backend: %s", self.gpu_backend)
                return self._cpu_pattern_matching(data, patterns)
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("GPU pattern matching failed: %s", e)
            return self._cpu_pattern_matching(data, patterns)

    def _cpu_pattern_matching(self, data: bytes, patterns: List[bytes]) -> List[int]:
        """Fallback CPU pattern matching."""
        matches = []
        for _pattern in patterns:
            pos = 0
            while True:
                pos = data.find(_pattern, pos)
                if pos == -1:
                    break
                matches.append(pos)
                pos += 1
        return sorted(matches)

    def _opencl_pattern_matching(self, data: bytes, patterns: List[bytes]) -> List[int]:
        """OpenCL-based pattern matching."""
        if not self.cl:
            return self._cpu_pattern_matching(data, patterns)

        import numpy as np

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
            
            // Check if this position can fit the pattern
            if (gid > data_size - pattern_size) {
                return;
            }
            
            // Check for pattern match at this position
            int is_match = 1;
            for (int i = 0; i < pattern_size; i++) {
                if (data[gid + i] != pattern[i]) {
                    is_match = 0;
                    break;
                }
            }
            
            // If match found, atomically increment match count and store position
            if (is_match) {
                int idx = atomic_inc(match_count);
                if (idx < 10000) {  // Max matches limit
                    matches[idx] = gid;
                }
            }
        }
        """

        # Build the OpenCL program
        program = self.cl.Program(self.context, kernel_source).build()

        all_matches = []

        for pattern in patterns:
            # Convert to numpy arrays
            data_array = np.frombuffer(data, dtype=np.uint8)
            pattern_array = np.frombuffer(pattern, dtype=np.uint8)

            # Allocate result buffers
            max_matches = 10000
            matches_array = np.zeros(max_matches, dtype=np.int32)
            match_count = np.zeros(1, dtype=np.int32)

            # Create OpenCL buffers
            mf = self.cl.mem_flags
            data_buffer = self.cl.Buffer(self.context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=data_array)
            pattern_buffer = self.cl.Buffer(self.context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pattern_array)
            matches_buffer = self.cl.Buffer(self.context, mf.WRITE_ONLY, matches_array.nbytes)
            count_buffer = self.cl.Buffer(self.context, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=match_count)

            # Execute kernel
            global_size = (len(data_array),)
            local_size = None  # Let OpenCL choose

            program.pattern_match(
                self.queue, global_size, local_size,
                data_buffer, np.int32(len(data_array)),
                pattern_buffer, np.int32(len(pattern_array)),
                matches_buffer, count_buffer
            )

            # Read results
            self.cl.enqueue_copy(self.queue, matches_array, matches_buffer)
            self.cl.enqueue_copy(self.queue, match_count, count_buffer)
            self.queue.finish()

            # Extract valid matches
            num_matches = match_count[0]
            if num_matches > 0:
                all_matches.extend(matches_array[:min(num_matches, max_matches)].tolist())

            self.logger.debug(f"OpenCL found {num_matches} matches for pattern of size {len(pattern)}")

        return sorted(all_matches)

    def _cupy_pattern_matching(self, data: bytes, patterns: List[bytes]) -> List[int]:
        """CUDA-based pattern matching using CuPy."""
        if not cp:
            return self._cpu_pattern_matching(data, patterns)

        import numpy as np

        # CUDA kernel for pattern matching
        pattern_match_kernel = cp.RawKernel(r'''
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
            
            // Check if this thread's position can fit the pattern
            if (tid > data_size - pattern_size) {
                return;
            }
            
            // Check for pattern match at this position
            bool is_match = true;
            for (int i = 0; i < pattern_size; i++) {
                if (data[tid + i] != pattern[i]) {
                    is_match = false;
                    break;
                }
            }
            
            // If match found, atomically increment match count and store position
            if (is_match) {
                int idx = atomicAdd(match_count, 1);
                if (idx < 10000) {  // Max matches limit
                    matches[idx] = tid;
                }
            }
        }
        ''', 'pattern_match')

        all_matches = []

        for pattern in patterns:
            # Convert to GPU arrays
            data_gpu = cp.asarray(np.frombuffer(data, dtype=np.uint8))
            pattern_gpu = cp.asarray(np.frombuffer(pattern, dtype=np.uint8))

            # Allocate result buffers
            max_matches = 10000
            matches_gpu = cp.zeros(max_matches, dtype=cp.int32)
            match_count_gpu = cp.zeros(1, dtype=cp.int32)

            # Calculate grid and block dimensions
            threads_per_block = 256
            blocks_per_grid = (len(data) + threads_per_block - 1) // threads_per_block

            # Launch kernel
            pattern_match_kernel(
                (blocks_per_grid,), (threads_per_block,),
                (data_gpu, len(data), pattern_gpu, len(pattern), matches_gpu, match_count_gpu)
            )

            # Synchronize and get results
            cp.cuda.Stream.null.synchronize()

            # Copy results back to CPU
            num_matches = int(match_count_gpu.get()[0])
            if num_matches > 0:
                matches_cpu = matches_gpu[:min(num_matches, max_matches)].get()
                all_matches.extend(matches_cpu.tolist())

            self.logger.debug(f"CUDA found {num_matches} matches for pattern of size {len(pattern)}")

        return sorted(all_matches)


class GPUAccelerator:
    """
    GPU acceleration system for _computationally intensive analysis tasks.

    This system leverages GPU computing capabilities to accelerate specific
    analysis tasks such as pattern matching, entropy calculation, and
    cryptographic operations.
    """

    def __init__(self):
        """
        Initialize the GPU accelerator.
        """
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        self.cuda_available = False
        self.opencl_available = False
        self.opencl_memory_registry = {
            'total_allocated': 0,
            'peak_usage': 0,
            'buffers': {}
        }
        self.tensorflow_available = False
        self.pytorch_available = False

        # New attributes for GPU agnostic operation
        self.selected_backend = None
        self.opencl_context = None
        self.opencl_queue = None
        self.opencl_devices = []

        # Multi-GPU support
        self.cuda_devices = []
        self.tensorflow_devices = []
        self.pytorch_devices = []

        # Benchmarking and workload characteristics
        self.backend_benchmarks = {}
        self.workload_characteristics = {
            'pattern_matching': {'compute_intensity': 'medium', 'memory_usage': 'high'},
            'entropy_calculation': {'compute_intensity': 'low', 'memory_usage': 'medium'},
            'hash_calculation': {'compute_intensity': 'high', 'memory_usage': 'low'}
        }

        # Error handling and recovery
        self.error_counts = {'cuda': 0, 'opencl': 0, 'tensorflow': 0, 'pytorch': 0}
        self.max_errors_before_blacklist = 3
        self.blacklisted_backends = set()

        # Check for GPU acceleration libraries
        self._check_available_backends()

        # Select the preferred backend
        self._select_preferred_backend()

        # Run initial benchmarks
        try:
            self._run_initial_benchmarks()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.warning("Initial benchmark failed: %s", e)
            # Don't let benchmark failure prevent GPU usage

    def _check_available_backends(self):
        """
        Check which GPU acceleration backends are available.
        """
        # Check for CUDA via CuPy
        if CUPY_AVAILABLE:
            try:
                # Test basic CuPy functionality
                test_array = cp.array([1, 2, 3])
                _test_result = cp.sum(test_array)
                self.cuda_available = True
                self.logger.info("CUDA acceleration available via CuPy")

                # Get available CUDA devices
                try:
                    num_devices = cp.cuda.runtime.getDeviceCount()
                    for i in range(num_devices):
                        device_props = cp.cuda.runtime.getDeviceProperties(i)
                        self.cuda_devices.append({
                            'index': i,
                            'name': device_props['name'].decode('utf-8'),
                            'memory': device_props['totalGlobalMem'],
                            'compute_capability': f"{device_props['major']}.{device_props['minor']}",
                            'multiprocessors': device_props['multiProcessorCount'],
                            'max_threads_per_block': device_props['maxThreadsPerBlock']
                        })
                except (OSError, ValueError, RuntimeError) as e:
                    self.logger.debug("Error getting CUDA device properties: %s", e)

            except (OSError, ValueError, RuntimeError) as e:
                self.logger.debug("CUDA initialization failed: %s", e)

        # Check for OpenCL
        if OPENCL_AVAILABLE:
            try:
                platforms = cl.get_platforms()
                if platforms:
                    self.opencl_available = True
                    self.logger.info("OpenCL acceleration available")

                    # Get OpenCL devices
                    for platform in platforms:
                        try:
                            devices = platform.get_devices()
                            for device in devices:
                                self.opencl_devices.append({
                                    'platform': platform.name,
                                    'name': device.name,
                                    'type': cl.device_type.to_string(device.type),
                                    'memory': device.global_mem_size,
                                    'compute_units': device.max_compute_units,
                                    'max_work_group_size': device.max_work_group_size
                                })
                        except (OSError, ValueError, RuntimeError) as e:
                            self.logger.debug("Error getting OpenCL devices for platform %s: %s", platform.name, e)

            except (OSError, ValueError, RuntimeError) as e:
                self.logger.debug("OpenCL initialization failed: %s", e)

        # Check for TensorFlow GPU
        if TENSORFLOW_AVAILABLE:
            try:
                gpus = tf.config.list_physical_devices('GPU')
                if gpus:
                    self.tensorflow_available = True
                    self.logger.info(f"TensorFlow GPU acceleration available: {len(gpus)} devices")
                    for i, gpu in enumerate(gpus):
                        self.tensorflow_devices.append({
                            'index': i,
                            'name': gpu.name,
                            'device_type': gpu.device_type
                        })
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.debug("TensorFlow GPU check failed: %s", e)

        # Check for PyTorch CUDA
        if INTEL_PYTORCH_AVAILABLE:
            try:
                if torch.cuda.is_available():
                    self.pytorch_available = True
                    num_devices = torch.cuda.device_count()
                    self.logger.info("PyTorch CUDA acceleration available: %s devices", num_devices)
                    for i in range(num_devices):
                        props = torch.cuda.get_device_properties(i)
                        self.pytorch_devices.append({
                            'index': i,
                            'name': props.name,
                            'memory': props.total_memory,
                            'compute_capability': f"{props.major}.{props.minor}",
                            'multiprocessors': props.multi_processor_count
                        })
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.debug("PyTorch CUDA check failed: %s", e)

    def _select_preferred_backend(self):
        """
        Select the preferred GPU backend based on availability and performance.
        """
        # Priority order: OpenCL (universal), CUDA (high performance), TensorFlow, PyTorch
        if self.opencl_available and 'opencl' not in self.blacklisted_backends:
            self.selected_backend = 'opencl'
            # Initialize OpenCL context
            try:
                # Select first available GPU device
                for platform in cl.get_platforms():
                    try:
                        devices = platform.get_devices(device_type=cl.device_type.GPU)
                        if devices:
                            self.opencl_context = cl.Context(devices)
                            self.opencl_queue = cl.CommandQueue(self.opencl_context)
                            break
                    except (AttributeError, RuntimeError):
                        continue

                if not self.opencl_context:
                    # Fall back to any device
                    self.opencl_context = cl.create_some_context()
                    self.opencl_queue = cl.CommandQueue(self.opencl_context)

            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error("Failed to initialize OpenCL context: %s", e)
                self.blacklisted_backends.add('opencl')
                self.selected_backend = None

        elif self.cuda_available and 'cuda' not in self.blacklisted_backends:
            self.selected_backend = 'cuda'
        elif self.tensorflow_available and 'tensorflow' not in self.blacklisted_backends:
            self.selected_backend = 'tensorflow'
        elif self.pytorch_available and 'pytorch' not in self.blacklisted_backends:
            self.selected_backend = 'pytorch'
        else:
            self.logger.info("No suitable GPU backend available")

        if self.selected_backend:
            self.logger.info("Selected GPU backend: %s", self.selected_backend)

    def _run_initial_benchmarks(self):
        """
        Run initial benchmarks to assess backend performance.
        """
        if not self.selected_backend:
            return

        self.logger.info("Running initial GPU benchmarks...")

        # Simple benchmark operations
        benchmark_data = list(range(1000000))  # 1M integers

        try:
            import time
            start_time = time.time()

            if self.selected_backend == 'opencl':
                self._benchmark_opencl(benchmark_data)
            elif self.selected_backend == 'cuda':
                self._benchmark_cuda(benchmark_data)
            elif self.selected_backend == 'tensorflow':
                self._benchmark_tensorflow(benchmark_data)
            elif self.selected_backend == 'pytorch':
                self._benchmark_pytorch(benchmark_data)

            end_time = time.time()
            benchmark_time = end_time - start_time

            self.backend_benchmarks[self.selected_backend] = {
                'simple_operation_time': benchmark_time,
                'operations_per_second': len(benchmark_data) / benchmark_time
            }

            self.logger.info(f"Benchmark completed: {benchmark_time:.3f}s for {len(benchmark_data)} operations")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Benchmark failed: %s", e)
            self.error_counts[self.selected_backend] += 1

    def _benchmark_opencl(self, data):
        """Run OpenCL benchmark."""
        if not self.opencl_context:
            return

        import numpy as np

        # Convert data to numpy array
        np_data = np.array(data, dtype=np.float32)

        # Create OpenCL buffer
        data_buffer = cl.Buffer(self.opencl_context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=np_data)
        _result_buffer = cl.Buffer(self.opencl_context, cl.mem_flags.WRITE_ONLY, np_data.nbytes)

        # Simple kernel to double values
        kernel_source = """
        __kernel void double_values(__global const float* input, __global float* output) {
            int gid = get_global_id(0);
            output[gid] = input[gid] * 2.0f;
        }
        """

        program = cl.Program(self.opencl_context, kernel_source).build()
        kernel = program.double_values

        # Execute kernel
        kernel(self.opencl_queue, (len(data),), None, data_buffer, _result_buffer)
        self.opencl_queue.finish()

    def _benchmark_cuda(self, data):
        """Run CUDA benchmark."""
        if not cp:
            return

        # Convert to CuPy array and perform operation
        gpu_data = cp.array(data, dtype=cp.float32)
        _result = gpu_data * 2.0
        cp.cuda.Stream.null.synchronize()

    def _benchmark_tensorflow(self, data):
        """Run TensorFlow benchmark."""
        if not tf:
            return

        with tf.device('/GPU:0'):
            tensor_data = tf.constant(data, dtype=tf.float32)
            _result = tf.multiply(tensor_data, 2.0)

    def _benchmark_pytorch(self, data):
        """Run PyTorch benchmark."""
        if not torch:
            return

        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        tensor_data = torch.tensor(data, dtype=torch.float32, device=device)
        _result = tensor_data * 2.0
        if torch.cuda.is_available():
            torch.cuda.synchronize()

    def accelerate_pattern_matching(self, data: bytes, patterns: List[bytes]) -> List[int]:
        """
        GPU-accelerated pattern matching.

        Args:
            data: Binary data to search
            patterns: List of patterns to find

        Returns:
            List of match positions
        """
        if not self.selected_backend:
            return self._cpu_pattern_matching(data, patterns)

        try:
            if self.selected_backend == 'opencl':
                return self._opencl_pattern_matching(data, patterns)
            elif self.selected_backend == 'cuda':
                return self._cuda_pattern_matching(data, patterns)
            else:
                return self._cpu_pattern_matching(data, patterns)
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("GPU pattern matching failed: %s", e)
            self.error_counts[self.selected_backend] += 1
            return self._cpu_pattern_matching(data, patterns)

    def _cpu_pattern_matching(self, data: bytes, patterns: List[bytes]) -> List[int]:
        """CPU fallback for pattern matching."""
        matches = []
        for _pattern in patterns:
            pos = 0
            while True:
                pos = data.find(_pattern, pos)
                if pos == -1:
                    break
                matches.append(pos)
                pos += 1
        return sorted(matches)

    def _opencl_pattern_matching(self, data: bytes, patterns: List[bytes]) -> List[int]:
        """OpenCL pattern matching with custom kernels."""
        if not self.opencl_context:
            return self._cpu_pattern_matching(data, patterns)

        import numpy as np

        # OpenCL kernel for parallel pattern matching
        kernel_code = """
        __kernel void find_pattern(
            __global const uchar* data,
            const int data_size,
            __global const uchar* pattern,
            const int pattern_size,
            __global int* results,
            __global int* result_count
        ) {
            int gid = get_global_id(0);
            
            if (gid + pattern_size > data_size) {
                return;
            }
            
            // Check if pattern matches at this position
            int match = 1;
            for (int i = 0; i < pattern_size; i++) {
                if (data[gid + i] != pattern[i]) {
                    match = 0;
                    break;
                }
            }
            
            if (match) {
                int idx = atomic_inc(result_count);
                if (idx < 10000) {  // Limit results
                    results[idx] = gid;
                }
            }
        }
        """

        try:
            # Build program
            program = cl.Program(self.opencl_context, kernel_code).build()

            all_matches = []

            for pattern in patterns:
                # Convert to numpy arrays
                data_np = np.frombuffer(data, dtype=np.uint8)
                pattern_np = np.frombuffer(pattern, dtype=np.uint8)

                # Allocate buffers
                max_results = 10000
                results_np = np.zeros(max_results, dtype=np.int32)
                count_np = np.zeros(1, dtype=np.int32)

                # Create OpenCL buffers
                mf = cl.mem_flags
                data_buf = cl.Buffer(self.opencl_context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=data_np)
                pattern_buf = cl.Buffer(self.opencl_context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pattern_np)
                results_buf = cl.Buffer(self.opencl_context, mf.WRITE_ONLY, results_np.nbytes)
                count_buf = cl.Buffer(self.opencl_context, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=count_np)

                # Execute kernel
                global_size = (len(data_np),)
                program.find_pattern(
                    self.opencl_queue, global_size, None,
                    data_buf, np.int32(len(data_np)),
                    pattern_buf, np.int32(len(pattern_np)),
                    results_buf, count_buf
                )

                # Get results
                cl.enqueue_copy(self.opencl_queue, results_np, results_buf)
                cl.enqueue_copy(self.opencl_queue, count_np, count_buf)
                self.opencl_queue.finish()

                # Extract matches
                num_matches = count_np[0]
                if num_matches > 0:
                    all_matches.extend(results_np[:min(num_matches, max_results)].tolist())

            return sorted(all_matches)

        except Exception as e:
            self.logger.error(f"OpenCL pattern matching failed: {e}")
            return self._cpu_pattern_matching(data, patterns)

    def _cuda_pattern_matching(self, data: bytes, patterns: List[bytes]) -> List[int]:
        """CUDA pattern matching with custom kernels."""
        if not cp:
            return self._cpu_pattern_matching(data, patterns)

        import numpy as np

        # CUDA kernel code
        cuda_kernel = cp.RawKernel(r'''
        extern "C" __global__
        void find_pattern(
            const unsigned char* data,
            const int data_size,
            const unsigned char* pattern,
            const int pattern_size,
            int* results,
            int* result_count
        ) {
            int tid = blockDim.x * blockIdx.x + threadIdx.x;
            
            if (tid + pattern_size > data_size) {
                return;
            }
            
            // Check pattern match
            bool match = true;
            for (int i = 0; i < pattern_size; i++) {
                if (data[tid + i] != pattern[i]) {
                    match = false;
                    break;
                }
            }
            
            if (match) {
                int idx = atomicAdd(result_count, 1);
                if (idx < 10000) {
                    results[idx] = tid;
                }
            }
        }
        ''', 'find_pattern')

        try:
            all_matches = []

            for pattern in patterns:
                # Convert to GPU arrays
                data_gpu = cp.asarray(np.frombuffer(data, dtype=np.uint8))
                pattern_gpu = cp.asarray(np.frombuffer(pattern, dtype=np.uint8))

                # Allocate results
                max_results = 10000
                results_gpu = cp.zeros(max_results, dtype=cp.int32)
                count_gpu = cp.zeros(1, dtype=cp.int32)

                # Launch kernel
                threads = 256
                blocks = (len(data) + threads - 1) // threads

                cuda_kernel(
                    (blocks,), (threads,),
                    (data_gpu, len(data), pattern_gpu, len(pattern), results_gpu, count_gpu)
                )

                # Get results
                cp.cuda.Stream.null.synchronize()
                num_matches = int(count_gpu[0])

                if num_matches > 0:
                    matches = results_gpu[:min(num_matches, max_results)].get()
                    all_matches.extend(matches.tolist())

            return sorted(all_matches)

        except Exception as e:
            self.logger.error(f"CUDA pattern matching failed: {e}")
            return self._cpu_pattern_matching(data, patterns)

    def accelerate_entropy_calculation(self, data: bytes) -> float:
        """
        GPU-accelerated entropy calculation.

        Args:
            data: Binary data to analyze

        Returns:
            Entropy value
        """
        if not self.selected_backend:
            return self._cpu_entropy_calculation(data)

        try:
            if self.selected_backend == 'cuda' and cp:
                return self._cuda_entropy_calculation(data)
            else:
                return self._cpu_entropy_calculation(data)
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("GPU entropy calculation failed: %s", e)
            return self._cpu_entropy_calculation(data)

    def _cpu_entropy_calculation(self, data: bytes) -> float:
        """CPU entropy calculation."""
        if not data:
            return 0.0

        # Count byte frequencies
        frequencies = [0] * 256
        for _byte in data:
            frequencies[_byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for _freq in frequencies:
            if _freq > 0:
                prob = _freq / data_len
                import math
                entropy -= prob * math.log2(prob)

        return entropy

    def _cuda_entropy_calculation(self, data: bytes) -> float:
        """CUDA-accelerated entropy calculation."""
        import numpy as np

        # Convert to numpy array
        np_data = np.frombuffer(data, dtype=np.uint8)

        # Move to GPU
        gpu_data = cp.asarray(np_data)

        # Calculate histogram on GPU
        hist = cp.histogram(gpu_data, bins=256, range=(0, 256))[0]

        # Calculate entropy
        hist_norm = hist / len(data)

        # Remove zeros to avoid log(0)
        hist_norm = hist_norm[hist_norm > 0]

        # Calculate entropy using GPU operations
        entropy = -cp.sum(hist_norm * cp.log2(hist_norm))

        return float(entropy)

    def run_gpu_analysis(self, binary_path: Optional[str] = None, analysis_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Run GPU-accelerated binary analysis.

        Args:
            binary_path: Path to binary file to analyze (optional)
            analysis_type: Type of analysis to perform

        Returns:
            Analysis results dictionary
        """
        results = {
            'gpu_backend': self.selected_backend,
            'analysis_type': analysis_type,
            'binary_path': binary_path,
            'timestamp': None,
            'patterns_found': [],
            'entropy_analysis': {},
            'performance_metrics': {},
            'errors': []
        }

        try:
            import time
            start_time = time.time()
            results['timestamp'] = start_time

            if binary_path and os.path.exists(binary_path):
                # Load binary data
                with open(binary_path, 'rb') as f:
                    binary_data = f.read()

                # GPU-accelerated pattern matching
                if analysis_type in ("comprehensive", "pattern_matching"):
                    common_patterns = [
                        b'\x4D\x5A',  # PE header
                        b'\x7F\x45\x4C\x46',  # ELF header
                        b'\xFE\xED\xFA',  # Mach-O header
                        b'This program cannot be run in DOS mode',
                        b'kernel32.dll',
                        b'ntdll.dll'
                    ]
                    matches = self.accelerate_pattern_matching(binary_data, common_patterns)
                    results['patterns_found'] = matches
                    self.logger.info("Found %d pattern matches using GPU acceleration", len(matches))

                # GPU-accelerated entropy calculation
                if analysis_type in ("comprehensive", "entropy"):
                    entropy = self.accelerate_entropy_calculation(binary_data)
                    results['entropy_analysis'] = {
                        'overall_entropy': entropy,
                        'file_size': len(binary_data),
                        'entropy_per_kb': entropy / (len(binary_data) / 1024) if binary_data else 0
                    }
                    self.logger.info("Calculated entropy: %.3f using GPU acceleration", entropy)

            else:
                # Run without specific binary (benchmark mode)
                self.logger.info("Running GPU analysis in benchmark mode")
                test_data = bytes(range(256)) * 1000  # 256KB test data

                # Test pattern matching
                test_patterns = [b'\x00\x01', b'\xFF\xFE', b'\x90\x90']
                matches = self.accelerate_pattern_matching(test_data, test_patterns)
                results['patterns_found'] = matches

                # Test entropy calculation
                entropy = self.accelerate_entropy_calculation(test_data)
                results['entropy_analysis'] = {'test_entropy': entropy}

            # Performance metrics
            end_time = time.time()
            results['performance_metrics'] = {
                'total_time': end_time - start_time,
                'backend_used': self.selected_backend,
                'gpu_available': bool(self.selected_backend),
                'acceleration_status': self.get_acceleration_status()
            }

            self.logger.info("GPU analysis completed in %.3f seconds", end_time - start_time)

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"GPU analysis failed: {e}"
            self.logger.error(error_msg)
            results['errors'].append(error_msg)
            self.error_counts[self.selected_backend or 'unknown'] += 1

        return results

    def get_acceleration_status(self) -> Dict[str, Any]:
        """
        Get current GPU acceleration status.

        Returns:
            Status information dictionary
        """
        return {
            'selected_backend': self.selected_backend,
            'available_backends': {
                'cuda': self.cuda_available,
                'opencl': self.opencl_available,
                'tensorflow': self.tensorflow_available,
                'pytorch': self.pytorch_available
            },
            'devices': {
                'cuda': self.cuda_devices,
                'opencl': self.opencl_devices,
                'tensorflow': self.tensorflow_devices,
                'pytorch': self.pytorch_devices
            },
            'benchmarks': self.backend_benchmarks,
            'error_counts': self.error_counts,
            'blacklisted_backends': list(self.blacklisted_backends)
        }

    def cleanup(self):
        """Clean up GPU resources."""
        try:
            if self.opencl_context:
                # OpenCL cleanup happens automatically
                pass

            if self.selected_backend == 'cuda' and cp:
                # Clear GPU memory
                cp.get_default_memory_pool().free_all_blocks()

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("GPU cleanup error: %s", e)


# Convenience functions
def create_gpu_acceleration_manager(use_intel_pytorch: bool = False) -> GPUAccelerationManager:
    """
    Factory function to create GPU acceleration manager.

    Args:
        use_intel_pytorch: Whether to try Intel Extension for PyTorch

    Returns:
        GPUAccelerationManager instance
    """
    return GPUAccelerationManager(use_intel_pytorch)

def create_gpu_accelerator() -> GPUAccelerator:
    """
    Factory function to create GPU accelerator.

    Returns:
        GPUAccelerator instance
    """
    return GPUAccelerator()

def is_gpu_acceleration_available() -> bool:
    """
    Quick check if any GPU acceleration is available.

    Returns:
        True if GPU acceleration is available
    """
    manager = create_gpu_acceleration_manager()
    return manager.is_acceleration_available()
