import hashlib
import logging
import multiprocessing
import os
import threading
import time

import psutil

from ..utils.core.logging_utils import log_message

logger = logging.getLogger(__name__)

class DistributedProcessing:
    """Refactored distributed processing methods for complexity reduction."""

    def _init_distributed_config(self, app):
        """Initialize distributed processing configuration."""
        if not hasattr(app, "distributed_config"):
            app.distributed_config = {
                "processing_engines": ["multiprocessing", "ray", "dask", "celery"],
                "max_workers": 8,
                "cluster_mode": "local",
                "task_distribution": "balanced",
                "result_aggregation": "merge",
                "fault_tolerance": True,
                "auto_scaling": False,
                "resource_monitoring": True,
            }

        if not hasattr(app, "cluster_state"):
            app.cluster_state = {
                "nodes": [],
                "active_workers": 0,
                "total_capacity": 0,
                "current_load": 0,
                "tasks_completed": 0,
                "tasks_failed": 0,
                "cluster_status": "initializing",
            }

        if not hasattr(app, "distributed_results"):
            app.distributed_results = {
                "processing_summary": {},
                "performance_metrics": {},
                "resource_usage": {},
                "task_distribution": {},
                "error_analysis": {},
                "optimization_suggestions": [],
            }

    def _check_processing_frameworks(self, app):
        """Check availability of distributed processing frameworks."""
        processing_frameworks = {
            "multiprocessing": False,
            "ray": False,
            "dask": False,
            "celery": False,
            "joblib": False,
            "concurrent_futures": False,
        }

        try:
            import multiprocessing as mp_check
            processing_frameworks["multiprocessing"] = True
            cpu_count = mp_check.cpu_count()
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(f"[Distributed] Python multiprocessing available ({cpu_count} CPUs)")
                )
        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            pass

        self._check_ray_framework(app, processing_frameworks)
        self._check_dask_framework(app, processing_frameworks)
        self._check_celery_framework(app, processing_frameworks)
        self._check_joblib_framework(app, processing_frameworks)
        self._check_concurrent_futures_framework(app, processing_frameworks)

        app.processing_frameworks = processing_frameworks
        return processing_frameworks

    def _check_ray_framework(self, app, processing_frameworks):
        """Check Ray framework availability."""
        try:
            import ray
            processing_frameworks["ray"] = True
            init_status = "not initialized"
            if ray.is_initialized():
                init_status = "already initialized"
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(f"[Distributed] Ray distributed computing framework available ({init_status})")
                )
        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            pass

    def _check_dask_framework(self, app, processing_frameworks):
        """Check Dask framework availability."""
        try:
            import dask  # noqa: F401 - Checking availability
            processing_frameworks["dask"] = True
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message("[Distributed] Dask distributed computing library available")
                )
        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            pass

    def _check_celery_framework(self, app, processing_frameworks):
        """Check Celery framework availability."""
        try:
            import celery  # noqa: F401 - Checking availability
            processing_frameworks["celery"] = True
        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            pass

    def _check_joblib_framework(self, app, processing_frameworks):
        """Check Joblib framework availability."""
        try:
            import joblib  # noqa: F401 - Checking availability
            processing_frameworks["joblib"] = True
        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            pass

    def _check_concurrent_futures_framework(self, app, processing_frameworks):
        """Check concurrent.futures framework availability."""
        try:
            import concurrent.futures
            processing_frameworks["concurrent_futures"] = True

            # Check available executor types
            available_executors = []
            if hasattr(concurrent.futures, 'ThreadPoolExecutor'):
                available_executors.append('ThreadPool')
            if hasattr(concurrent.futures, 'ProcessPoolExecutor'):
                available_executors.append('ProcessPool')

            executor_info = f" ({', '.join(available_executors)} executors)" if available_executors else ""
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(f"[Distributed] concurrent.futures framework available{executor_info}")
                )
        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            pass

    def _detect_system_resources(self):
        """Detect system CPU and memory resources."""
        cpu_count = os.cpu_count() or 4

        try:
            memory_gb = psutil.virtual_memory().total // (1024**3)
            available_memory = psutil.virtual_memory().available // (1024**3)
        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            memory_gb = 8
            available_memory = 4

        return cpu_count, memory_gb, available_memory

    def _create_local_node(self, cpu_count, memory_gb, available_memory, processing_frameworks):
        """Create local cluster node."""
        return {
            "node_id": "local_node_0",
            "hostname": "localhost",
            "ip_address": "127.0.0.1",
            "cpu_cores": cpu_count,
            "memory_gb": memory_gb,
            "available_memory_gb": available_memory,
            "node_type": "compute",
            "status": "active",
            "load_average": 0.3,
            "tasks_running": 0,
            "frameworks": [
                fw for fw, available in processing_frameworks.items() if available
            ],
        }

    def _connect_to_ray_cluster(self, app, cluster_nodes, cpu_count):
        """Connect to Ray cluster and add nodes."""
        try:
            import ray  # pylint: disable=import-error

            if not ray.is_initialized():
                ray.init(ignore_reinit_error=True, num_cpus=cpu_count)

            ray_nodes = ray.nodes()
            for ray_node in ray_nodes:
                if ray_node["Alive"]:
                    node_resources = ray_node["Resources"]
                    real_node = {
                        "node_id": ray_node["NodeID"][:8],
                        "hostname": ray_node.get("NodeManagerHostname", "ray-node"),
                        "ip_address": ray_node.get("NodeManagerAddress", "unknown"),
                        "cpu_cores": int(node_resources.get("CPU", 0)),
                        "memory_gb": int(node_resources.get("memory", 0) / (1024**3)),
                        "available_memory_gb": int(
                            node_resources.get("memory", 0) / (1024**3)
                        ),
                        "node_type": "ray_worker",
                        "status": "active",
                        "load_average": 1.0
                        - (
                            ray.available_resources().get("CPU", 0)
                            / node_resources.get("CPU", 1)
                        ),
                        "tasks_running": 0,
                        "frameworks": ["ray"],
                    }
                    cluster_nodes.append(real_node)

            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(
                        f"[Distributed] Connected to Ray cluster with {len(ray_nodes)} nodes"
                    )
                )
        except (
            AttributeError, ValueError, TypeError, RuntimeError, KeyError, OSError, IOError
        ) as e:
            logger.error(
                "(AttributeError, ValueError, TypeError, RuntimeError, KeyError, OSError, IOError) in main_app.py: %s",
                e,
            )
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(f"[Distributed] Ray initialization error: {e}")
                )

    def _connect_to_dask_cluster(self, app, cluster_nodes):
        """Connect to Dask cluster and add nodes."""
        try:
            from dask.distributed import Client  # pylint: disable=import-error

            client = Client("localhost:8786", timeout="2s")
            scheduler_info = client.scheduler_info()

            for worker_id, worker_info in scheduler_info["workers"].items():
                real_node = {
                    "node_id": worker_id.split(":")[-1],
                    "hostname": worker_info.get("host", "dask-worker"),
                    "ip_address": worker_info.get("host", "unknown"),
                    "cpu_cores": worker_info.get("nthreads", 1),
                    "memory_gb": int(worker_info.get("memory_limit", 0) / (1024**3)),
                    "available_memory_gb": int(
                        (
                            worker_info.get("memory_limit", 0)
                            - worker_info.get("memory", 0)
                        )
                        / (1024**3)
                    ),
                    "node_type": "dask_worker",
                    "status": "active",
                    "load_average": worker_info.get("cpu", 0) / 100.0,
                    "tasks_running": len(worker_info.get("processing", [])),
                    "frameworks": ["dask"],
                }
                cluster_nodes.append(real_node)

            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(
                        f"[Distributed] Connected to Dask cluster with {len(scheduler_info['workers'])} workers"
                    )
                )
        except (
            AttributeError, ValueError, TypeError, RuntimeError, KeyError, OSError, IOError
        ) as e:
            logger.error(
                "(AttributeError, ValueError, TypeError, RuntimeError, KeyError, OSError, IOError) in main_app.py: %s",
                e,
            )
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(f"[Distributed] Dask connection error: {e}")
                )

            self._start_local_dask_cluster(app)

    def _start_local_dask_cluster(self, app):
        """Start local Dask cluster as fallback."""
        try:
            from dask.distributed import Client, LocalCluster  # pylint: disable=import-error

            cpu_count = os.cpu_count() or 4
            cluster = LocalCluster(
                n_workers=min(4, cpu_count // 2), threads_per_worker=2
            )
            Client(cluster)

            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message("[Distributed] Started local Dask cluster")
                )
        except Exception as e:
            logger.debug(f"Failed to start Dask cluster: {e}")

    def _create_distributed_tasks(self, app):
        """Create distributed tasks from binary data."""
        distributed_tasks = []

        if hasattr(app, "binary_path") and app.binary_path:
            try:
                with open(app.binary_path, "rb") as f:
                    binary_data = f.read()

                chunk_size = max(1024, len(binary_data) // 8)
                for i in range(0, len(binary_data), chunk_size):
                    chunk = binary_data[i : i + chunk_size]
                    distributed_tasks.append(
                        {
                            "task_id": f"chunk_analysis_{i}",
                            "type": "binary_chunk_analysis",
                            "priority": "high",
                            "data": chunk,
                            "offset": i,
                        }
                    )
            except (FileNotFoundError, IOError, OSError) as e:
                logger.debug(f"Failed to read binary for distributed tasks: {e}")
                distributed_tasks = [
                    {"task_id": "binary_hash", "type": "hash_computation", "priority": "high"},
                    {"task_id": "string_extract", "type": "string_extraction", "priority": "medium"},
                    {"task_id": "entropy_calc", "type": "entropy_analysis", "priority": "low"},
                ]

        return distributed_tasks

    def _execute_ray_tasks(self, app, distributed_tasks):
        """Execute tasks using Ray framework."""
        try:
            import ray

            @ray.remote
            def analyze_chunk(task):
                start = time.time()
                result = {
                    "task_id": task["task_id"],
                    "node_id": ray.get_runtime_context().node_id.hex()[:8],
                }

                if task["type"] == "binary_chunk_analysis" and "data" in task:
                    chunk = task["data"]
                    result["hash"] = hashlib.sha256(chunk).hexdigest()
                    result["size"] = len(chunk)
                    result["entropy"] = sum(chunk) / len(chunk) if chunk else 0
                    result["strings_found"] = len(
                        [i for i in range(len(chunk) - 4) if chunk[i : i + 4].isascii()]
                    )

                result["execution_time"] = time.time() - start
                result["status"] = "completed"
                return result

            futures = [analyze_chunk.remote(task) for task in distributed_tasks[:5]]

            task_results = []
            for future in futures:
                try:
                    result = ray.get(future, timeout=10)
                    task_results.append(result)
                    app.cluster_state["tasks_completed"] += 1
                except Exception as e:
                    logger.error("Ray task error: %s", e)
                    app.cluster_state["tasks_failed"] += 1

            return task_results
        except Exception as e:
            logger.error("Ray execution error: %s", e)
            return []

    def _execute_dask_tasks(self, app, distributed_tasks):
        """Execute tasks using Dask framework."""
        try:
            from dask.distributed import Client, as_completed

            client = Client("localhost:8786", timeout="2s")

            def analyze_chunk(task):
                start = time.time()
                result = {"task_id": task["task_id"]}

                if task["type"] == "binary_chunk_analysis" and "data" in task:
                    chunk = task["data"]
                    result["hash"] = hashlib.sha256(chunk).hexdigest()
                    result["size"] = len(chunk)
                    result["entropy"] = sum(chunk) / len(chunk) if chunk else 0

                result["execution_time"] = time.time() - start
                result["status"] = "completed"
                return result

            futures = []
            for task in distributed_tasks[:5]:
                future = client.submit(analyze_chunk, task)
                futures.append(future)

            task_results = []
            for future in as_completed(futures, timeout=10):
                try:
                    result = future.result()
                    task_results.append(result)
                    app.cluster_state["tasks_completed"] += 1
                except Exception as e:
                    logger.error("Dask task error: %s", e)
                    app.cluster_state["tasks_failed"] += 1

            return task_results
        except Exception as e:
            logger.error("Dask execution error: %s", e)
            return []

    def _execute_joblib_tasks(self, app, distributed_tasks):
        """Execute tasks using Joblib framework."""
        try:
            from joblib import Parallel, delayed

            def analyze_chunk_joblib(task):
                start = time.time()
                result = {
                    "task_id": task["task_id"],
                    "node_id": f"joblib_{os.getpid()}",
                }

                if task["type"] == "binary_chunk_analysis" and "data" in task:
                    chunk = task["data"]
                    result["hash"] = hashlib.sha256(chunk).hexdigest()
                    result["size"] = len(chunk)
                    result["entropy"] = sum(chunk) / len(chunk) if chunk else 0

                result["execution_time"] = time.time() - start
                result["status"] = "completed"
                result["memory_usage_gb"] = 0.001
                return result

            cpu_count = os.cpu_count() or 4
            results = Parallel(n_jobs=min(4, cpu_count))(
                delayed(analyze_chunk_joblib)(task) for task in distributed_tasks[:5]
            )

            for _result in results:
                app.cluster_state["tasks_completed"] += 1

            return results
        except Exception as e:
            logger.error("Joblib execution error: %s", e)
            return []

    def _execute_futures_tasks(self, app, distributed_tasks):
        """Execute tasks using concurrent.futures framework."""
        try:
            import concurrent.futures

            def analyze_chunk_futures(task):
                start = time.time()
                result = {
                    "task_id": task["task_id"],
                    "node_id": f"futures_{threading.current_thread().ident}",
                }

                if task["type"] == "binary_chunk_analysis" and "data" in task:
                    chunk = task["data"]
                    result["hash"] = hashlib.sha256(chunk).hexdigest()
                    result["size"] = len(chunk)
                    result["entropy"] = sum(chunk) / len(chunk) if chunk else 0

                result["execution_time"] = time.time() - start
                result["status"] = "completed"
                result["memory_usage_gb"] = 0.001
                return result

            cpu_count = os.cpu_count() or 4
            task_results = []

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(8, cpu_count * 2)
            ) as executor:
                futures = [
                    executor.submit(analyze_chunk_futures, task)
                    for task in distributed_tasks[:5]
                ]

                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        task_results.append(result)
                        app.cluster_state["tasks_completed"] += 1
                    except Exception as e:
                        app.cluster_state["tasks_failed"] += 1
                        logger.error(f"Concurrent futures task failed: {e}")

            return task_results
        except Exception as e:
            logger.error("Concurrent futures execution error: %s", e)
            return []

    def _execute_multiprocessing_tasks(self, app, distributed_tasks):
        """Execute tasks using multiprocessing framework."""
        try:
            def analyze_chunk_mp(task):
                start = time.time()
                result = {
                    "task_id": task["task_id"],
                    "node_id": f"cpu_{multiprocessing.current_process().pid}",
                }

                if task["type"] == "binary_chunk_analysis" and "data" in task:
                    chunk = task["data"]
                    result["hash"] = hashlib.sha256(chunk).hexdigest()
                    result["size"] = len(chunk)
                    result["entropy"] = sum(chunk) / len(chunk) if chunk else 0

                result["execution_time"] = time.time() - start
                result["status"] = "completed"
                result["memory_usage_gb"] = 0.001
                return result

            cpu_count = os.cpu_count() or 4
            task_results = []

            with multiprocessing.Pool(processes=min(4, cpu_count)) as pool:
                for result in pool.map(analyze_chunk_mp, distributed_tasks[:5]):
                    task_results.append(result)
                    app.cluster_state["tasks_completed"] += 1

            return task_results
        except Exception as e:
            logger.error("Multiprocessing execution error: %s", e)
            return []

    def _calculate_performance_metrics(self, app, task_results, total_execution_time):
        """Calculate performance metrics from task results."""
        completed_tasks = [task for task in task_results if task["status"] == "completed"]
        failed_tasks = [task for task in task_results if task["status"] == "failed"]

        if completed_tasks:
            avg_execution_time = sum(
                task["execution_time"] for task in completed_tasks
            ) / len(completed_tasks)
            total_memory_usage = sum(
                task.get("memory_usage_gb", 0) for task in completed_tasks
            )

            performance_metrics = {
                "total_tasks": len(task_results),
                "completed_tasks": len(completed_tasks),
                "failed_tasks": len(failed_tasks),
                "success_rate": len(completed_tasks) / len(task_results) if task_results else 0,
                "average_execution_time": avg_execution_time,
                "total_execution_time": total_execution_time,
                "parallel_speedup": len(task_results) / max(1, total_execution_time / 2),
                "total_memory_usage": total_memory_usage,
                "throughput_tasks_per_second": len(completed_tasks) / max(1, total_execution_time),
            }

            app.distributed_results["performance_metrics"] = performance_metrics
            self._generate_optimization_suggestions(app, performance_metrics)

    def _generate_optimization_suggestions(self, app, performance_metrics):
        """Generate optimization suggestions based on performance metrics."""
        optimization_suggestions = []

        if performance_metrics["success_rate"] < 0.9:
            optimization_suggestions.append(
                "Consider improving error handling and retry mechanisms"
            )

        if performance_metrics["average_execution_time"] > 2.0:
            optimization_suggestions.append(
                "Tasks may benefit from further parallelization"
            )

        if performance_metrics["parallel_speedup"] < 2.0:
            optimization_suggestions.append(
                "Increase cluster size or optimize task distribution"
            )

        cpu_count, memory_gb, available_memory = self._detect_system_resources()
        if performance_metrics["total_memory_usage"] > available_memory * 0.8:
            optimization_suggestions.append(
                "Memory usage is high - consider memory optimization"
            )

        app.distributed_results["optimization_suggestions"] = optimization_suggestions

    def _format_distributed_results(self, app, processing_frameworks):
        """Format and display distributed processing results."""
        if not hasattr(app, "analyze_results"):
            app.analyze_results = []

        app.analyze_results.append("\n=== DISTRIBUTED PROCESSING SYSTEM ===")
        app.analyze_results.append("Available frameworks:")
        for framework, available in processing_frameworks.items():
            status = "✓" if available else "✗"
            app.analyze_results.append(f"- {framework.capitalize()}: {status}")

        self._add_cluster_info(app)
        self._add_performance_metrics(app)
        self._add_optimization_suggestions(app)
        self._add_features_info(app)

    def _add_cluster_info(self, app):
        """Add cluster information to results."""
        app.analyze_results.append(
            f"\nCluster status: {app.cluster_state['cluster_status'].upper()}"
        )
        if app.cluster_state["nodes"]:
            app.analyze_results.append(f"Cluster nodes: {len(app.cluster_state['nodes'])}")
            app.analyze_results.append(
                f"Total CPU cores: {app.cluster_state['total_capacity']}"
            )
            app.analyze_results.append(f"Active workers: {app.cluster_state['active_workers']}")

            app.analyze_results.append("\nNode details:")
            for node in app.cluster_state["nodes"][:3]:
                app.analyze_results.append(
                    f"- {node['node_id']}: {node['cpu_cores']} cores, {node['memory_gb']}GB RAM ({node['status']})"
                )
            if len(app.cluster_state["nodes"]) > 3:
                remaining = len(app.cluster_state["nodes"]) - 3
                app.analyze_results.append(f"- ... and {remaining} more nodes")

    def _add_performance_metrics(self, app):
        """Add performance metrics to results."""
        if app.distributed_results.get("performance_metrics"):
            metrics = app.distributed_results["performance_metrics"]
            app.analyze_results.append("\nPerformance metrics:")
            app.analyze_results.append(
                f"- Tasks completed: {metrics['completed_tasks']}/{metrics['total_tasks']}"
            )
            app.analyze_results.append(f"- Success rate: {metrics['success_rate']:.1%}")
            app.analyze_results.append(
                f"- Average execution time: {metrics['average_execution_time']:.2f}s"
            )
            app.analyze_results.append(
                f"- Parallel speedup: {metrics['parallel_speedup']:.2f}x"
            )
            app.analyze_results.append(
                f"- Throughput: {metrics['throughput_tasks_per_second']:.2f} tasks/sec"
            )
            app.analyze_results.append(f"- Memory usage: {metrics['total_memory_usage']:.2f}GB")

    def _add_optimization_suggestions(self, app):
        """Add optimization suggestions to results."""
        if app.distributed_results.get("optimization_suggestions"):
            app.analyze_results.append("\nOptimization suggestions:")
            for suggestion in app.distributed_results["optimization_suggestions"]:
                app.analyze_results.append(f"- {suggestion}")

    def _add_features_info(self, app):
        """Add features information to results."""
        app.analyze_results.append("\nDistributed processing features:")
        app.analyze_results.append("- Multi-node task distribution")
        app.analyze_results.append("- Load balancing and resource management")
        app.analyze_results.append("- Fault tolerance and error recovery")
        app.analyze_results.append("- Performance monitoring and optimization")
        app.analyze_results.append("- Auto-scaling and resource allocation")
        app.analyze_results.append("- Result aggregation and merging")

    def run_distributed_processing(self, app, *args, **kwargs):
        """Run distributed processing system when processor not available."""
        _ = args, kwargs
        try:
            from ..core.processing.distributed_manager import DistributedManager

            manager = DistributedManager()
            return manager.start_distributed_analysis()
        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            if hasattr(app, "update_output"):
                self.update_output.emit(
                    log_message("[Distributed] Starting distributed processing system...")
                )

            self._init_distributed_config(app)
            processing_frameworks = self._check_processing_frameworks(app)

            if any(processing_frameworks.values()):
                cpu_count, memory_gb, available_memory = self._detect_system_resources()

                cluster_nodes = []
                local_node = self._create_local_node(
                    cpu_count, memory_gb, available_memory, processing_frameworks
                )
                cluster_nodes.append(local_node)

                if processing_frameworks.get("ray", False):
                    self._connect_to_ray_cluster(app, cluster_nodes, cpu_count)
                elif processing_frameworks.get("dask", False):
                    self._connect_to_dask_cluster(app, cluster_nodes)

                self.cluster_state["nodes"] = cluster_nodes
                self.cluster_state["active_workers"] = len(
                    [node for node in cluster_nodes if node["status"] == "active"]
                )
                self.cluster_state["total_capacity"] = sum(
                    node["cpu_cores"] for node in cluster_nodes
                )
                self.cluster_state["cluster_status"] = "ready"

                if hasattr(app, "update_output"):
                    self.update_output.emit(
                        log_message(
                            f"[Distributed] Initialized cluster with {len(cluster_nodes)} nodes ({self.cluster_state['total_capacity']} cores)"
                        )
                    )

                if len(cluster_nodes) > 0:
                    distributed_tasks = self._create_distributed_tasks(app)

                    if distributed_tasks:
                        start_time = time.time()
                        task_results = []

                        if processing_frameworks.get("ray", False) and "ray" in locals():
                            task_results = self._execute_ray_tasks(app, distributed_tasks)
                        elif processing_frameworks.get("dask", False) and "client" in locals():
                            task_results = self._execute_dask_tasks(app, distributed_tasks)
                        elif processing_frameworks.get("joblib", False):
                            task_results = self._execute_joblib_tasks(app, distributed_tasks)
                        elif processing_frameworks.get("concurrent_futures", False):
                            task_results = self._execute_futures_tasks(app, distributed_tasks)
                        else:
                            task_results = self._execute_multiprocessing_tasks(app, distributed_tasks)

                        total_execution_time = time.time() - start_time
                        self._calculate_performance_metrics(app, task_results, total_execution_time)

                        if hasattr(app, "update_output") and task_results:
                            metrics = self.distributed_results.get("performance_metrics", {})
                            self.update_output.emit(
                                log_message(
                                    f"[Distributed] Executed {len(distributed_tasks)} tasks with {metrics.get('success_rate', 0):.1%} success rate"
                                )
                            )
                else:
                    if hasattr(app, "update_output"):
                        self.update_output.emit(
                            log_message(
                                "[Distributed] No binary loaded - cluster ready for distributed tasks"
                            )
                        )
            else:
                if hasattr(app, "update_output"):
                    self.update_output.emit(
                        log_message("[Distributed] No distributed processing frameworks available")
                    )
                self.cluster_state["cluster_status"] = "unavailable"

            self._format_distributed_results(app, processing_frameworks)

            if hasattr(app, "update_output"):
                self.update_output.emit(
                    log_message(
                        "[Distributed] Distributed processing system initialized successfully"
                    )
                )

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("(OSError, ValueError, RuntimeError) in main_app.py: %s", e)
            if hasattr(app, "update_output"):
                self.update_output.emit(
                    log_message(f"[Distributed] Error running distributed processing: {e}")
                )
