"""
Distributed Processing Manager

This module provides distributed processing capabilities for analyzing large binary files
across multiple cores or machines. It supports various backend options including Ray, Dask,
and standard multiprocessing, with automatic backend selection and fallback mechanisms.

The manager supports:
- Multi-backend distributed computing (Ray, Dask, multiprocessing)
- Task-based processing with queue management
- Chunk-based binary file processing
- Pattern search, entropy analysis, and symbolic execution
- Performance monitoring and worker load balancing
- HTML report generation with detailed results
- Graceful error handling and recovery

Author: Intellicrack Development Team
"""

import logging
import math
import multiprocessing
import os
import queue
import re
import time
import traceback
from collections import Counter
from typing import Any, Callable, Dict, List, Optional, Union

try:
    import ray
    RAY_AVAILABLE = True
except ImportError:
    RAY_AVAILABLE = False

try:
    from dask.distributed import Client, progress
    DASK_AVAILABLE = True
except ImportError:
    DASK_AVAILABLE = False

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


class DistributedProcessingManager:
    """
    Distributed Processing Manager for Large Binaries.

    This class manages distributed processing of large binary files across multiple cores or machines,
    significantly improving analysis speed for large executables. It supports multiple backend options
    including Ray, Dask, and standard multiprocessing based on availability.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the distributed processing manager.

        Args:
            config: Dictionary with configuration options:
                   - num_workers: Number of worker processes (default: CPU count)
                   - chunk_size: Size of file chunks in bytes (default: 1MB)
                   - preferred_backend: 'ray', 'dask', or 'multiprocessing' (default: auto-detect)
        """
        self.config = config or {}
        self.logger = logging.getLogger("IntellicrackLogger.DistributedProcessing")

        # Basic configuration
        self.binary_path: Optional[str] = None
        self.num_workers = self.config.get('num_workers', multiprocessing.cpu_count())
        self.chunk_size = self.config.get('chunk_size', 1024 * 1024)  # 1MB default chunk size
        self.preferred_backend = self.config.get('preferred_backend', 'auto')

        # Task management
        self.tasks: List[Dict[str, Any]] = []
        self.workers: List[multiprocessing.Process] = []
        self.results: Dict[str, Any] = {}
        self.task_queue: Optional[multiprocessing.Queue] = None
        self.result_queue: Optional[multiprocessing.Queue] = None
        self.running: bool = False

        # Performance tracking
        self.worker_performance: Dict[int, Dict[str, Any]] = {}
        self.active_tasks: Dict[str, Dict[str, Any]] = {}
        self.worker_loads: Dict[int, float] = {}

        # Check available backends
        self._check_available_backends()

        self.logger.info("Distributed processing initialized with %s workers", self.num_workers)
        self.logger.info(f"Available backends: {', '.join(self._get_available_backends())}")

    def _check_available_backends(self) -> None:
        """Check which distributed computing backends are available."""
        # Check for Ray
        self.ray_available = RAY_AVAILABLE
        if self.ray_available:
            self.logger.info("Ray distributed computing available")
        else:
            self.logger.info("Ray distributed computing not available")

        # Check for Dask
        self.dask_available = DASK_AVAILABLE
        if self.dask_available:
            self.logger.info("Dask distributed computing available")
        else:
            self.logger.info("Dask distributed computing not available")

        # Always available
        self.multiprocessing_available = True

    def _get_available_backends(self) -> List[str]:
        """Get list of available backends."""
        backends = ['multiprocessing']
        if self.ray_available:
            backends.append('ray')
        if self.dask_available:
            backends.append('dask')
        return backends

    def _select_backend(self) -> str:
        """Select the best backend based on availability and preference."""
        if self.preferred_backend == 'ray' and self.ray_available:
            return 'ray'
        elif self.preferred_backend == 'dask' and self.dask_available:
            return 'dask'
        elif self.preferred_backend == 'multiprocessing' or self.preferred_backend == 'auto':
            # For auto, we prefer Ray > Dask > Multiprocessing
            if self.preferred_backend == 'auto':
                if self.ray_available:
                    return 'ray'
                elif self.dask_available:
                    return 'dask'
            return 'multiprocessing'
        else:
            self.logger.warning(f"Preferred backend '{self.preferred_backend}' not available, using multiprocessing")
            return 'multiprocessing'

    def set_binary(self, binary_path: str) -> bool:
        """
        Set the binary file to process.

        Args:
            binary_path: Path to the binary file

        Returns:
            bool: True if binary file exists, False otherwise
        """
        if not os.path.exists(binary_path):
            self.logger.error("Binary not found: %s", binary_path)
            return False

        self.binary_path = binary_path
        self.logger.info("Binary set: %s", binary_path)
        return True

    def add_task(self, task_type: str, task_params: Optional[Dict[str, Any]] = None, task_description: Optional[str] = None) -> int:
        """
        Add a task to the processing queue.

        Args:
            task_type: Type of task to run (e.g., 'analyze_section', 'find_patterns')
            task_params: Dictionary of parameters for the task
            task_description: Human-readable description of the task

        Returns:
            int: Task ID (index in task list)
        """
        task = {
            'id': len(self.tasks),
            'type': task_type,
            'params': task_params or {},
            'description': task_description or f"Task: {task_type}"
        }

        self.tasks.append(task)
        self.logger.info(f"Added task: {task_type} (ID: {task['id']})")
        return task['id']

    def process_binary_chunks(self, process_func: Optional[Callable[[bytes, int], Any]] = None) -> Optional[List[Any]]:
        """
        Process a binary file in chunks using distributed workers.

        Args:
            process_func: Function to process each chunk, takes (chunk_data, offset) as arguments

        Returns:
            list: Combined results from all chunks
        """
        if not self.binary_path:
            self.logger.error("No binary set")
            return None

        if process_func is None:
            # Default processing function (just returns basic info about the chunk)
            process_func = lambda chunk, offset: {"offset": offset, "size": len(chunk)}

        # Get file size
        file_size = os.path.getsize(self.binary_path)

        # Calculate number of chunks
        num_chunks = (file_size + self.chunk_size - 1) // self.chunk_size

        self.logger.info(f"Processing {self.binary_path} in {num_chunks} chunks of {self.chunk_size // (1024*1024)}MB each")

        # Choose backend based on availability
        backend = self._select_backend()
        self.logger.info("Using %s backend for processing", backend)

        if backend == 'ray':
            return self._process_with_ray(process_func, num_chunks)
        elif backend == 'dask':
            return self._process_with_dask(process_func, num_chunks)
        else:
            return self._process_with_multiprocessing(process_func, num_chunks)

    def _process_with_ray(self, process_func: Callable, num_chunks: int) -> Optional[List[Any]]:
        """
        Process binary chunks using Ray.

        Args:
            process_func: Function to process each chunk
            num_chunks: Number of chunks to process

        Returns:
            list: Results from all chunks
        """
        if not RAY_AVAILABLE:
            self.logger.error("Ray not available, falling back to multiprocessing")
            return self._process_with_multiprocessing(process_func, num_chunks)

        try:
            # Initialize Ray if not already initialized
            if not ray.is_initialized():
                ray.init(num_cpus=self.num_workers)

            # Define remote function
            @ray.remote
            def process_chunk(chunk_idx: int, binary_path: str, chunk_size: int) -> Any:
                """
                Process a specific chunk of the binary file in a distributed manner using Ray.

                This function is decorated with @ray.remote to enable distributed execution
                across multiple processes or nodes. It reads a specific chunk of the binary
                file based on the provided index, applies the processing function, and
                returns the results.

                Args:
                    chunk_idx: Index of the chunk to process
                    binary_path: Path to the binary file
                    chunk_size: Size of each chunk

                Returns:
                    Any: Result of applying the process_func to the chunk data and offset
                """
                offset = chunk_idx * chunk_size
                with open(binary_path, 'rb') as f:
                    f.seek(offset)
                    chunk_data = f.read(chunk_size)
                return process_func(chunk_data, offset)

            # Submit tasks
            tasks = []
            for i in range(num_chunks):
                tasks.append(process_chunk.remote(i, self.binary_path, self.chunk_size))

            # Get results with progress tracking
            results = []
            completed = 0
            for result in ray.get(tasks):
                results.append(result)
                completed += 1
                if completed % max(1, num_chunks // 10) == 0:  # Report every 10%
                    self.logger.info(f"Progress: {completed}/{num_chunks} chunks processed ({completed/num_chunks*100:.1f}%)")

            return results

        except Exception as e:
            self.logger.error("Error in Ray processing: %s", e)
            self.logger.info("Falling back to multiprocessing")
            return self._process_with_multiprocessing(process_func, num_chunks)

    def _process_with_dask(self, process_func: Callable, num_chunks: int) -> Optional[List[Any]]:
        """
        Process binary chunks using Dask.

        Args:
            process_func: Function to process each chunk
            num_chunks: Number of chunks to process

        Returns:
            list: Results from all chunks
        """
        if not DASK_AVAILABLE:
            self.logger.error("Dask not available, falling back to multiprocessing")
            return self._process_with_multiprocessing(process_func, num_chunks)

        try:
            # Create client
            client = Client(n_workers=self.num_workers)

            # Define function to read and process chunk
            def read_and_process_chunk(chunk_idx: int) -> Any:
                """
                Read and process a specific chunk of data from the binary file.

                This function handles the file I/O operations needed to read a specific
                chunk of the binary file based on the provided index. It calculates the
                file offset, reads the binary data, and applies the provided processing
                function to that data.

                Args:
                    chunk_idx: Index of the chunk to process

                Returns:
                    Any: Result of applying the process_func to the chunk data and offset
                """
                offset = chunk_idx * self.chunk_size
                with open(self.binary_path, 'rb') as f:
                    f.seek(offset)
                    chunk_data = f.read(self.chunk_size)
                return process_func(chunk_data, offset)

            # Create tasks
            futures = []
            for i in range(num_chunks):
                future = client.submit(read_and_process_chunk, i)
                futures.append(future)

            # Show progress
            progress(futures)

            # Compute results
            results = client.gather(futures)

            # Close client
            client.close()

            return list(results)

        except Exception as e:
            self.logger.error("Error in Dask processing: %s", e)
            self.logger.info("Falling back to multiprocessing")
            return self._process_with_multiprocessing(process_func, num_chunks)

    def _process_with_multiprocessing(self, process_func: Callable, num_chunks: int) -> List[Any]:
        """
        Process binary chunks using multiprocessing.

        Args:
            process_func: Function to process each chunk
            num_chunks: Number of chunks to process

        Returns:
            list: Results from all chunks
        """
        # Define function to read and process chunk
        def read_and_process_chunk(chunk_idx: int) -> Union[Any, Dict[str, Any]]:
            """
            Read a chunk from the binary file and process it.

            Args:
                chunk_idx: Index of the chunk to read.

            Returns:
                The result of process_func on the chunk data, or an error dict.
            """
            try:
                offset = chunk_idx * self.chunk_size
                with open(self.binary_path, 'rb') as f:
                    f.seek(offset)
                    chunk_data = f.read(self.chunk_size)
                return process_func(chunk_data, offset)
            except Exception as e:
                return {"error": str(e), "offset": offset, "chunk_idx": chunk_idx}

        # Create pool
        with multiprocessing.Pool(processes=self.num_workers) as pool:
            # Process chunks with progress tracking
            results = []
            for i, result in enumerate(pool.imap_unordered(read_and_process_chunk, range(num_chunks))):
                results.append(result)
                if (i + 1) % max(1, num_chunks // 10) == 0:  # Report every 10%
                    self.logger.info(f"Progress: {i+1}/{num_chunks} chunks processed ({(i+1)/num_chunks*100:.1f}%)")

        return results

    def start_processing(self) -> bool:
        """
        Start distributed processing of tasks using queue-based approach.

        Returns:
            bool: True if processing started successfully, False otherwise
        """
        if not self.binary_path:
            self.logger.error("No binary set")
            return False

        if not self.tasks:
            self.logger.warning("No tasks specified")
            return False

        if self.running:
            self.logger.warning("Already running")
            return False

        # Clear previous results
        self.results = {
            'tasks_completed': 0,
            'tasks_failed': 0,
            'total_processing_time': 0.0,
            'task_results': {}
        }

        try:
            # Initialize multiprocessing queues
            self.task_queue = multiprocessing.Queue()
            self.result_queue = multiprocessing.Queue()

            # Add tasks to queue
            for task in self.tasks:
                self.task_queue.put(task)

            # Add sentinel tasks to signal workers to exit
            for _ in range(self.num_workers):
                self.task_queue.put(None)

            # Start workers
            self.workers = []
            for i in range(self.num_workers):
                worker = multiprocessing.Process(
                    target=self._worker_process,
                    args=(i, self.task_queue, self.result_queue, self.binary_path, self.chunk_size)
                )
                worker.daemon = True
                worker.start()
                self.workers.append(worker)

            self.running = True
            self.logger.info("Started %s workers for task-based processing", self.num_workers)

            return True

        except Exception as e:
            self.logger.error("Error starting processing: %s", e)
            self.stop_processing()
            return False

    def _worker_process(self, worker_id: int, task_queue: multiprocessing.Queue, result_queue: multiprocessing.Queue,
                       binary_path: str, chunk_size: int) -> None:
        """
        Worker process function for task-based processing.

        Args:
            worker_id: ID of the worker
            task_queue: Queue for tasks
            result_queue: Queue for results
            binary_path: Path to the binary file
            chunk_size: Size of chunks for file processing
        """
        try:
            # Set up worker
            logger = logging.getLogger(f"IntellicrackLogger.Worker{worker_id}")
            logger.info("Worker %s started", worker_id)

            # Process tasks
            while True:
                # Get task from queue
                task = task_queue.get()

                # Check for sentinel
                if task is None:
                    logger.info("Worker %s shutting down", worker_id)
                    break

                # Process task
                start_time = time.time()
                logger.info(f"Worker {worker_id} processing task: {task['type']} (ID: {task['id']})")

                try:
                    # Process task based on type
                    if task['type'] == 'find_patterns':
                        result = self._task_find_patterns(worker_id, task, binary_path, chunk_size)
                    elif task['type'] == 'analyze_entropy':
                        result = self._task_analyze_entropy(worker_id, task, binary_path, chunk_size)
                    elif task['type'] == 'analyze_section':
                        result = self._task_analyze_section(worker_id, task, binary_path, chunk_size)
                    elif task['type'] == 'symbolic_execution':
                        result = self._task_symbolic_execution(worker_id, task, binary_path, chunk_size)
                    else:
                        # Generic task - process a chunk
                        result = self._task_generic(worker_id, task, binary_path, chunk_size)

                    # Add processing time
                    processing_time = time.time() - start_time
                    result['processing_time'] = processing_time
                    result['worker_id'] = worker_id
                    result['task_id'] = task['id']
                    result['success'] = True

                    # Put result in result queue
                    result_queue.put((worker_id, task, result))

                except Exception as e:
                    logger.error(f"Error processing task {task['id']}: {e}")
                    processing_time = time.time() - start_time
                    error_result = {
                        'error': str(e),
                        'traceback': traceback.format_exc(),
                        'worker_id': worker_id,
                        'task_id': task['id'],
                        'processing_time': processing_time,
                        'success': False
                    }
                    result_queue.put((worker_id, task, error_result))

        except Exception as e:
            logger.error("Worker %s error: %s", worker_id, e)

    def _task_find_patterns(self, worker_id: int, task: Dict[str, Any], binary_path: str, chunk_size: int) -> Dict[str, Any]:
        """Process a pattern-finding task."""
        logger = logging.getLogger(f"IntellicrackLogger.Worker{worker_id}")
        patterns = task['params'].get('patterns', [])
        chunk_start = task['params'].get('chunk_start', 0)
        chunk_end = task['params'].get('chunk_end', None)

        if not patterns:
            return {'error': "No patterns specified", 'matches': []}

        # Read specified chunk of file
        with open(binary_path, 'rb') as f:
            f.seek(chunk_start)
            if chunk_end is not None:
                chunk_data = f.read(chunk_end - chunk_start)
            else:
                chunk_data = f.read(chunk_size)

        # Search for patterns
        matches = []
        for pattern in patterns:
            try:
                pattern_bytes = pattern.encode() if isinstance(pattern, str) else pattern
                for match in re.finditer(re.escape(pattern_bytes), chunk_data):
                    matches.append({
                        'pattern': pattern,
                        'position': chunk_start + match.start(),
                        'match': match.group()
                    })
            except Exception as e:
                logger.warning("Error processing pattern %s: %s", pattern, e)

        logger.info(f"Found {len(matches)} pattern matches in chunk at offset {chunk_start}")
        return {'matches': matches, 'patterns_found': len(matches)}

    def _task_analyze_entropy(self, worker_id: int, task: Dict[str, Any], binary_path: str, chunk_size: int) -> Dict[str, Any]:
        """Process an entropy analysis task."""
        logger = logging.getLogger(f"IntellicrackLogger.Worker{worker_id}")
        chunk_start = task['params'].get('chunk_start', 0)
        chunk_end = task['params'].get('chunk_end', None)
        window_size = task['params'].get('window_size', 1024)  # Default 1KB windows

        # Read specified chunk of file
        with open(binary_path, 'rb') as f:
            f.seek(chunk_start)
            if chunk_end is not None:
                chunk_data = f.read(chunk_end - chunk_start)
            else:
                chunk_data = f.read(chunk_size)

        # Calculate overall entropy for the chunk
        chunk_entropy = self._calculate_entropy(chunk_data)

        # Calculate entropy for sliding windows
        window_results = []
        for i in range(0, len(chunk_data) - window_size + 1, window_size // 2):  # 50% overlap
            window_data = chunk_data[i:i+window_size]
            window_entropy = self._calculate_entropy(window_data)

            window_results.append({
                'offset': chunk_start + i,
                'size': len(window_data),
                'entropy': window_entropy
            })

        # Find high entropy regions
        high_entropy_regions = [w for w in window_results if w['entropy'] > 7.0]  # High entropy threshold

        logger.info("Analyzed entropy in chunk at offset %s: %f", chunk_start, chunk_entropy)
        return {
            'chunk_offset': chunk_start,
            'chunk_size': len(chunk_data),
            'chunk_entropy': chunk_entropy,
            'windows': window_results,
            'high_entropy_regions': high_entropy_regions,
            'high_entropy_count': len(high_entropy_regions)
        }

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        counts = Counter(data)
        total = len(data)
        entropy = -sum((count/total) * math.log2(count/total) for count in counts.values())
        return entropy

    def _task_analyze_section(self, worker_id: int, task: Dict[str, Any], binary_path: str, chunk_size: int) -> Dict[str, Any]:
        """Process a section analysis task."""
        logger = logging.getLogger(f"IntellicrackLogger.Worker{worker_id}")
        section_name = task['params'].get('section_name', None)

        if not section_name:
            return {'error': "No section name specified"}

        if not PEFILE_AVAILABLE:
            return {'error': "pefile not available for section analysis"}

        try:
            pe = pefile.PE(binary_path)

            section = next((s for s in pe.sections if s.Name.decode().strip('\x00') == section_name), None)
            if not section:
                return {'error': f"Section {section_name} not found"}

            section_data = section.get_data()
            entropy = self._calculate_entropy(section_data)

            # String extraction (simple)
            strings = []
            current_string = b""
            min_length = 4  # Minimum string length

            for byte in section_data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string.decode('ascii'))
                    current_string = b""

            # Add last string if needed
            if len(current_string) >= min_length:
                strings.append(current_string.decode('ascii'))

            logger.info(f"Analyzed section {section_name}: size={len(section_data)}, entropy={entropy:.2f}, strings={len(strings)}")

            return {
                'section_name': section_name,
                'section_size': len(section_data),
                'entropy': entropy,
                'strings_found': len(strings),
                'strings': strings[:100],  # Limit to first 100 strings
                'characteristics': section.Characteristics,
                'virtual_address': section.VirtualAddress,
                'pointer_to_raw_data': section.PointerToRawData,
                'size_of_raw_data': section.SizeOfRawData
            }

        except Exception as e:
            logger.error("Error analyzing section %s: %s", section_name, e)
            return {'error': str(e), 'section_name': section_name}

    def _task_symbolic_execution(self, worker_id: int, task: Dict[str, Any], binary_path: str, chunk_size: int) -> Dict[str, Any]:
        """Process a symbolic execution task."""
        logger = logging.getLogger(f"IntellicrackLogger.Worker{worker_id}")
        target_function = task['params'].get('target_function', None)
        max_states = task['params'].get('max_states', 100)
        max_time = task['params'].get('max_time', 300)  # 5 minutes timeout by default

        if not target_function:
            return {'error': "No target function specified"}

        if not ANGR_AVAILABLE:
            return {'error': "angr not available for symbolic execution"}

        logger.info("Starting symbolic execution of %s", target_function)

        try:
            # Load the binary with angr
            proj = angr.Project(binary_path, auto_load_libs=False)

            # Get function address (simplified)
            target_address = None
            try:
                # Try to resolve function by name in symbols
                for sym in proj.loader.main_object.symbols:
                    if sym.name == target_function and sym.type == 'function':
                        target_address = sym.rebased_addr
                        break
            except Exception as e:
                logger.error(f"Error resolving function address: {str(e)}")

            if target_address is None:
                return {'error': f"Could not resolve address for function {target_function}"}

            logger.info("Resolved %s to address 0x%d", target_function, target_address)

            # Create a starting state at the function
            initial_state = proj.factory.call_state(target_address)

            # Create a simulation manager
            simgr = proj.factory.simulation_manager(initial_state)

            # Simple exploration with timeout
            start_time = time.time()
            paths_explored = 0
            vulnerabilities = []

            while simgr.active and time.time() - start_time < max_time:
                simgr.step()
                paths_explored += len(simgr.active)

                if paths_explored >= max_states:
                    break

            total_time = time.time() - start_time

            result = {
                'target_function': target_function,
                'target_address': f"0x{target_address:x}",
                'paths_explored': paths_explored,
                'execution_time': total_time,
                'vulnerabilities_found': len(vulnerabilities),
                'vulnerabilities': vulnerabilities
            }

            logger.info(f"Symbolic execution completed: {result['paths_explored']} paths explored")
            return result

        except Exception as e:
            error_msg = f"Error during symbolic execution: {str(e)}"
            logger.error(error_msg)
            return {
                'error': error_msg,
                'target_function': target_function,
                'paths_explored': 0,
                'vulnerabilities_found': 0
            }

    def _task_generic(self, worker_id: int, task: Dict[str, Any], binary_path: str, chunk_size: int) -> Dict[str, Any]:
        """Process a generic task."""
        logger = logging.getLogger(f"IntellicrackLogger.Worker{worker_id}")
        chunk_start = task['params'].get('chunk_start', 0)

        # Read chunk of file
        with open(binary_path, 'rb') as f:
            f.seek(chunk_start)
            chunk_data = f.read(chunk_size)

        logger.info("Worker %s processed generic task on chunk at offset %s", worker_id, chunk_start)
        return {
            'worker_id': worker_id,
            'chunk_offset': chunk_start,
            'chunk_size': len(chunk_data),
            'task_type': task['type']
        }

    def collect_results(self, timeout: Optional[float] = None) -> bool:
        """
        Collect results from workers.

        Args:
            timeout: Timeout in seconds (None for no timeout)

        Returns:
            bool: True if results collected successfully, False otherwise
        """
        if not self.running:
            self.logger.warning("Not running")
            return False

        try:
            # Initialize results
            self.results = {
                'tasks_completed': 0,
                'tasks_failed': 0,
                'total_processing_time': 0.0,
                'task_results': {}
            }

            # Collect results
            tasks_remaining = len(self.tasks)
            start_time = time.time()

            while tasks_remaining > 0:
                # Check timeout
                if timeout is not None and time.time() - start_time > timeout:
                    self.logger.warning("Timeout after %s seconds", timeout)
                    break

                # Get result from queue
                try:
                    worker_id, task, result = self.result_queue.get(timeout=1.0)
                except queue.Empty:
                    # Check if all workers are still alive
                    if not any(worker.is_alive() for worker in self.workers):
                        self.logger.error("All workers have died")
                        break
                    continue

                # Process result
                task_type = task['type']
                self.logger.info("Processing result from worker %s for task %s", worker_id, task_type)

                # Initialize task type in results if not already present
                if task_type not in self.results['task_results']:
                    self.results['task_results'][task_type] = []

                # Add result to results
                self.results['task_results'][task_type].append(result)

                # Update statistics
                if result.get('success', False):
                    self.results['tasks_completed'] += 1
                else:
                    self.results['tasks_failed'] += 1

                self.results['total_processing_time'] += result.get('processing_time', 0.0)

                # Log progress
                total_tasks = self.results['tasks_completed'] + self.results['tasks_failed']
                self.logger.info(f"Progress: {total_tasks}/{len(self.tasks)} tasks processed")

                # Decrement tasks remaining
                tasks_remaining -= 1

            # Wait for workers to finish
            for worker in self.workers:
                worker.join(timeout=1.0)

            self.running = False
            self.logger.info("Collected results")

            return True

        except Exception as e:
            self.logger.error("Error collecting results: %s", e)
            return False

    def stop_processing(self) -> bool:
        """
        Stop distributed processing.

        Returns:
            bool: True if processing stopped successfully, False otherwise
        """
        if not self.running:
            return True

        try:
            # Terminate workers
            for worker in self.workers:
                worker.terminate()

            # Wait for workers to terminate
            for worker in self.workers:
                worker.join(timeout=1.0)

            # Clear queues
            if self.task_queue:
                while not self.task_queue.empty():
                    try:
                        self.task_queue.get_nowait()
                    except queue.Empty:
                        break

            if self.result_queue:
                while not self.result_queue.empty():
                    try:
                        self.result_queue.get_nowait()
                    except queue.Empty:
                        break

            self.running = False
            self.logger.info("Stopped processing")

            return True

        except Exception as e:
            self.logger.error("Error stopping processing: %s", e)
            return False

    def get_results(self) -> Dict[str, Any]:
        """
        Get the distributed processing results.

        Returns:
            dict: Processing results
        """
        return self.results

    def run_distributed_pattern_search(self, patterns: List[Union[str, bytes]], chunk_size_mb: int = 10) -> List[Dict[str, Any]]:
        """
        Search for patterns in a binary file using distributed processing.

        Args:
            patterns: List of patterns to search for (bytes or regex strings)
            chunk_size_mb: Size of each chunk in MB

        Returns:
            list: List of matches with their positions
        """
        if not self.binary_path:
            self.logger.error("No binary set")
            return []

        # Calculate chunk size
        chunk_size = chunk_size_mb * 1024 * 1024

        # Get file size
        file_size = os.path.getsize(self.binary_path)

        # Add tasks for each chunk
        self.tasks = []
        for offset in range(0, file_size, chunk_size):
            task = {
                'id': len(self.tasks),
                'type': 'find_patterns',
                'params': {
                    'patterns': patterns,
                    'chunk_start': offset,
                    'chunk_end': min(offset + chunk_size, file_size)
                },
                'description': f"Pattern search in chunk at offset {offset}"
            }
            self.tasks.append(task)

        # Start processing
        if not self.start_processing():
            return []

        # Collect results
        if not self.collect_results():
            return []

        # Process and combine results
        all_matches = []
        if 'find_patterns' in self.results['task_results']:
            for result in self.results['task_results']['find_patterns']:
                if result.get('success', False) and 'matches' in result:
                    all_matches.extend(result['matches'])

        # Sort by position
        all_matches.sort(key=lambda x: x['position'])

        return all_matches

    def run_distributed_entropy_analysis(self, window_size_kb: int = 64, chunk_size_mb: int = 10) -> Dict[str, Any]:
        """
        Calculate entropy of a binary file using distributed processing.

        Args:
            window_size_kb: Size of sliding window in KB
            chunk_size_mb: Size of each chunk in MB

        Returns:
            dict: Entropy analysis results
        """
        if not self.binary_path:
            self.logger.error("No binary set")
            return {}

        # Calculate sizes
        window_size = window_size_kb * 1024
        chunk_size = chunk_size_mb * 1024 * 1024

        # Get file size
        file_size = os.path.getsize(self.binary_path)

        # Add tasks for each chunk
        self.tasks = []
        for offset in range(0, file_size, chunk_size):
            task = {
                'id': len(self.tasks),
                'type': 'analyze_entropy',
                'params': {
                    'window_size': window_size,
                    'chunk_start': offset,
                    'chunk_end': min(offset + chunk_size, file_size)
                },
                'description': f"Entropy analysis of chunk at offset {offset}"
            }
            self.tasks.append(task)

        # Start processing
        if not self.start_processing():
            return {}

        # Collect results
        if not self.collect_results():
            return {}

        # Process and combine results
        all_windows = []
        chunk_entropies = []

        if 'analyze_entropy' in self.results['task_results']:
            for result in self.results['task_results']['analyze_entropy']:
                if result.get('success', False):
                    chunk_entropies.append((result['chunk_entropy'], result['chunk_size']))
                    all_windows.extend(result.get('windows', []))

        # Sort windows by offset
        all_windows.sort(key=lambda x: x['offset'])

        # Calculate overall entropy (weighted by chunk size)
        total_size = sum(size for _, size in chunk_entropies)
        overall_entropy = sum(entropy * size for entropy, size in chunk_entropies) / total_size if total_size > 0 else 0

        # Find high entropy regions
        high_entropy_regions = [w for w in all_windows if w['entropy'] > 7.0]

        return {
            'overall_entropy': overall_entropy,
            'windows': all_windows,
            'high_entropy_regions': high_entropy_regions,
            'high_entropy_count': len(high_entropy_regions)
        }

    def generate_report(self, filename: Optional[str] = None) -> Optional[str]:
        """
        Generate a report of the distributed processing results.

        Args:
            filename: Path to save the HTML report (None to return HTML as string)

        Returns:
            str or None: HTML report as string if filename is None, else path to saved file
        """
        if not self.results:
            self.logger.error("No results to report")
            return None

        # Generate HTML report
        html = f"""
        <html>
        <head>
            <title>Distributed Processing Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2, h3 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .success {{ color: green; }}
                .failure {{ color: red; }}
            </style>
        </head>
        <body>
            <h1>Distributed Processing Report</h1>
            <p>Binary: {self.binary_path}</p>

            <h2>Summary</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Workers</td><td>{self.num_workers}</td></tr>
                <tr><td>Tasks Completed</td><td>{self.results.get('tasks_completed', 0)}</td></tr>
                <tr><td>Tasks Failed</td><td>{self.results.get('tasks_failed', 0)}</td></tr>
                <tr><td>Total Processing Time</td><td>{self.results.get('total_processing_time', 0):.2f} seconds</td></tr>
            </table>
        """

        # Add task-specific results
        for task_type, results in self.results.get('task_results', {}).items():
            html += f"""
            <h2>{task_type.capitalize()} Results</h2>
            <p>Total: {len(results)}</p>
            """

        html += """
        </body>
        </html>
        """

        # Save to file if filename provided
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(html)
                self.logger.info("Report saved to %s", filename)
                return filename
            except Exception as e:
                self.logger.error("Error saving report: %s", e)
                return None
        else:
            return html

    def cleanup(self) -> None:
        """Clean up resources."""
        self.stop_processing()

        # Clean up Ray if initialized
        if RAY_AVAILABLE and ray.is_initialized():
            try:
                ray.shutdown()
            except Exception as e:
                self.logger.error("Error shutting down Ray: %s", e)


def create_distributed_manager(config: Optional[Dict[str, Any]] = None) -> DistributedProcessingManager:
    """
    Factory function to create a DistributedProcessingManager instance.

    Args:
        config: Configuration dictionary

    Returns:
        DistributedProcessingManager: Configured manager instance
    """
    return DistributedProcessingManager(config)


__all__ = ['DistributedProcessingManager', 'create_distributed_manager']
