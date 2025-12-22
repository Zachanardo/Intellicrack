"""Distributed analysis manager for cluster-based binary processing.

This module provides sophisticated distributed analysis capabilities for scaling
binary analysis across multiple machines. It supports both local multi-processing
and network-based clustering with task distribution, fault tolerance, and result
aggregation for large-scale software protection testing.

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

import contextlib
import hashlib
import heapq
import hmac
import json
import logging
import os
import pickle  # noqa: S403
import platform
import socket
import struct
import threading
import time
import traceback
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


try:
    import multiprocessing
    import multiprocessing.managers

    MULTIPROCESSING_AVAILABLE = True
except ImportError:
    MULTIPROCESSING_AVAILABLE = False

try:
    from intellicrack.core.processing.parallel_processing_manager import ParallelProcessingManager

    PARALLEL_MANAGER_AVAILABLE = True
except ImportError:
    PARALLEL_MANAGER_AVAILABLE = False


class TaskPriority(Enum):
    """Task priority levels for scheduling."""

    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    BACKGROUND = 4


class TaskStatus(Enum):
    """Task execution status."""

    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRY = "retry"
    CANCELLED = "cancelled"


class NodeStatus(Enum):
    """Worker node status."""

    STARTING = "starting"
    READY = "ready"
    BUSY = "busy"
    DEGRADED = "degraded"
    OFFLINE = "offline"


@dataclass
class AnalysisTask:
    """Distributed analysis task representation."""

    task_id: str
    task_type: str
    priority: TaskPriority
    binary_path: str
    params: dict[str, Any]
    status: TaskStatus
    created_at: float
    started_at: float | None = None
    completed_at: float | None = None
    assigned_node: str | None = None
    retry_count: int = 0
    max_retries: int = 3
    timeout: float = 3600.0
    result: dict[str, Any] | None = None
    error: str | None = None
    dependencies: list[str] | None = None
    chunk_info: dict[str, Any] | None = None

    def __lt__(self, other: object) -> bool:
        """Priority queue comparison.

        Args:
            other: Object to compare with.

        Returns:
            bool: True if this task has higher priority or earlier creation time.

        Raises:
            TypeError: If other is not an AnalysisTask instance.

        """
        if not isinstance(other, AnalysisTask):
            raise TypeError(f"Cannot compare AnalysisTask with {type(other).__name__}")
        if self.priority.value != other.priority.value:
            return self.priority.value < other.priority.value
        return self.created_at < other.created_at


@dataclass
class WorkerNode:
    """Distributed worker node representation."""

    node_id: str
    hostname: str
    ip_address: str
    port: int
    status: NodeStatus
    capabilities: dict[str, Any]
    current_load: float
    max_load: float
    active_tasks: list[str]
    completed_tasks: int
    failed_tasks: int
    last_heartbeat: float
    platform_info: dict[str, str]
    resource_usage: dict[str, float]


class DistributedAnalysisManager:
    """Distributed analysis manager for cluster-based binary processing.

    Provides sophisticated distributed analysis capabilities including:
    - Cluster node management with automatic registration and health monitoring
    - Priority-based task distribution and load balancing
    - Fault tolerance with automatic job recovery and retry
    - Result aggregation from distributed workers
    - Support for both local multi-processing and network clustering
    - Resource monitoring and allocation
    - Windows and Linux compatibility
    """

    HEARTBEAT_INTERVAL = 5.0
    NODE_TIMEOUT = 30.0
    TASK_CHECK_INTERVAL = 2.0
    MAX_TASK_RETRIES = 3
    DEFAULT_PORT = 9876
    PROTOCOL_VERSION = "1.0"

    def __init__(
        self,
        mode: str = "auto",
        config: dict[str, Any] | None = None,
        enable_networking: bool = True,
    ) -> None:
        """Initialize the distributed analysis manager.

        Args:
            mode: Execution mode - "local", "cluster", or "auto" (default: auto)
            config: Configuration dictionary with cluster settings
            enable_networking: Enable network-based clustering (default: True)

        """
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        self.enable_networking = enable_networking

        self._hmac_key = os.environ.get("INTELLICRACK_CLUSTER_KEY", "intellicrack-distributed-default-key").encode()

        self.mode = mode
        if mode == "auto":
            self.mode = "cluster" if enable_networking else "local"

        self.node_id = str(uuid.uuid4())
        self.is_coordinator = True
        self.coordinator_address: tuple[str, int] | None = None

        self.nodes: dict[str, WorkerNode] = {}
        self.tasks: dict[str, AnalysisTask] = {}
        self.task_queue: list[AnalysisTask] = []
        self.completed_results: dict[str, Any] = {}
        self.task_lock = threading.RLock()
        self.nodes_lock = threading.RLock()

        self.running = False
        self.background_threads: list[threading.Thread] = []

        self.local_manager: ParallelProcessingManager | None = None
        if PARALLEL_MANAGER_AVAILABLE and self.mode == "local":
            self.local_manager = ParallelProcessingManager(self.config)

        self.server_socket: socket.socket | None = None
        self.client_connections: dict[str, socket.socket] = {}

        self.performance_metrics: dict[str, Any] = {
            "tasks_submitted": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "total_processing_time": 0.0,
            "average_task_time": 0.0,
            "node_utilization": {},
            "task_distribution": defaultdict(int),
        }

        self._register_self_as_worker()
        self.logger.info("Distributed manager initialized in %s mode (Node ID: %s)", self.mode, self.node_id)

    def _register_self_as_worker(self) -> None:
        """Register this instance as a worker node."""
        worker_count = self.config.get("num_workers", multiprocessing.cpu_count() if MULTIPROCESSING_AVAILABLE else 4)

        worker_node = WorkerNode(
            node_id=self.node_id,
            hostname=socket.gethostname(),
            ip_address=self._get_local_ip(),
            port=self.config.get("port", self.DEFAULT_PORT),
            status=NodeStatus.READY,
            capabilities={
                "os": platform.system(),
                "arch": platform.machine(),
                "cpu_count": worker_count,
                "supports_frida": self._check_capability("frida"),
                "supports_radare2": self._check_capability("radare2"),
                "supports_angr": self._check_capability("angr"),
                "supports_pefile": self._check_capability("pefile"),
                "supports_lief": self._check_capability("lief"),
            },
            current_load=0.0,
            max_load=float(worker_count),
            active_tasks=[],
            completed_tasks=0,
            failed_tasks=0,
            last_heartbeat=time.time(),
            platform_info={
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
            },
            resource_usage={},
        )

        with self.nodes_lock:
            self.nodes[self.node_id] = worker_node

    def _get_local_ip(self) -> str:
        """Get local IP address for network communication."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            s.connect(("8.8.8.8", 80))
            sockname = s.getsockname()
            ip_address = str(sockname[0]) if isinstance(sockname, tuple) else "127.0.0.1"
            s.close()
            return ip_address
        except OSError:
            return "127.0.0.1"

    def _check_capability(self, module_name: str) -> bool:
        """Check if a module/capability is available."""
        try:
            __import__(module_name)
            return True
        except ImportError:
            return False

    def start_cluster(self, port: int | None = None) -> bool:
        """Start the cluster coordinator or worker node.

        Args:
            port: Port number for network communication (default: from config or 9876)

        Returns:
            bool: True if cluster started successfully

        """
        if self.running:
            self.logger.warning("Cluster already running")
            return False

        port = port or self.config.get("port", self.DEFAULT_PORT)

        try:
            self.running = True

            if self.mode == "cluster" and self.enable_networking:
                if self.is_coordinator:
                    self._start_coordinator_server(port)
                else:
                    self._connect_to_coordinator()

            heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            heartbeat_thread.start()
            self.background_threads.append(heartbeat_thread)

            task_monitor_thread = threading.Thread(target=self._task_monitor_loop, daemon=True)
            task_monitor_thread.start()
            self.background_threads.append(task_monitor_thread)

            if self.is_coordinator:
                scheduler_thread = threading.Thread(target=self._task_scheduler_loop, daemon=True)
                scheduler_thread.start()
                self.background_threads.append(scheduler_thread)

            self.logger.info("Cluster started on port %d (coordinator: %s)", port, self.is_coordinator)
            return True

        except OSError as e:
            self.logger.exception("Failed to start cluster: %s", e)
            self.running = False
            return False

    def _start_coordinator_server(self, port: int) -> None:
        """Start the coordinator server for network communication."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("127.0.0.1", port))
            self.server_socket.listen(10)
            self.server_socket.settimeout(1.0)

            self.coordinator_address = (self._get_local_ip(), port)

            accept_thread = threading.Thread(target=self._accept_connections_loop, daemon=True)
            accept_thread.start()
            self.background_threads.append(accept_thread)

            self.logger.info("Coordinator server started on %s", self.coordinator_address)

        except OSError as e:
            self.logger.exception("Failed to start coordinator server: %s", e)
            raise

    def _accept_connections_loop(self) -> None:
        """Accept incoming worker connections."""
        while self.running and self.server_socket:
            try:
                client_socket, client_address = self.server_socket.accept()
                self.logger.info("New connection from %s", client_address)

                handler_thread = threading.Thread(
                    target=self._handle_client_connection,
                    args=(client_socket, client_address),
                    daemon=True,
                )
                handler_thread.start()
                self.background_threads.append(handler_thread)

            except TimeoutError:
                continue
            except OSError as e:
                if self.running:
                    self.logger.exception("Error accepting connection: %s", e)
                break

    def _handle_client_connection(self, client_socket: socket.socket, client_address: tuple[str, int]) -> None:
        """Handle communication with a connected worker node."""
        node_id = None
        try:
            while self.running:
                message = self._receive_message(client_socket)
                if not message:
                    break

                msg_type = message.get("type")

                if msg_type == "register":
                    node_id_val = message.get("node_id")
                    node_info_val = message.get("node_info")
                    if isinstance(node_id_val, str) and isinstance(node_info_val, dict):
                        node_id = node_id_val
                        self._register_worker_node(node_id_val, node_info_val, client_socket)
                        self._send_message(client_socket, {"type": "registered", "status": "success"})

                elif msg_type == "heartbeat":
                    node_id_val = message.get("node_id")
                    status_val = message.get("status", {})
                    if isinstance(node_id_val, str) and isinstance(status_val, dict):
                        node_id = node_id_val
                        self._update_node_heartbeat(node_id_val, status_val)
                        self._send_message(client_socket, {"type": "heartbeat_ack"})

                elif msg_type == "task_result":
                    task_id_val = message.get("task_id")
                    result_val = message.get("result")
                    if isinstance(task_id_val, str) and isinstance(result_val, dict):
                        self._handle_task_result(task_id_val, result_val)
                        self._send_message(client_socket, {"type": "result_ack"})

                elif msg_type == "task_failed":
                    task_id_val = message.get("task_id")
                    error_val = message.get("error")
                    if isinstance(task_id_val, str) and isinstance(error_val, str):
                        self._handle_task_failure(task_id_val, error_val)
                        self._send_message(client_socket, {"type": "failure_ack"})

                elif msg_type == "request_task":
                    node_id_val = message.get("node_id")
                    if isinstance(node_id_val, str):
                        node_id = node_id_val
                        if task := self._assign_task_to_node(node_id_val):
                            self._send_message(
                                client_socket,
                                {
                                    "type": "task_assigned",
                                    "task": asdict(task),
                                },
                            )
                        else:
                            self._send_message(client_socket, {"type": "no_tasks"})

        except OSError as e:
            self.logger.exception("Client connection error from %s: %s", client_address, e)
        finally:
            if node_id:
                self._mark_node_offline(node_id)
            with contextlib.suppress(OSError, socket.error):
                client_socket.close()

    def _connect_to_coordinator(self) -> None:
        """Connect to a coordinator node as a worker."""
        coordinator_host = self.config.get("coordinator_host", "localhost")
        coordinator_port = self.config.get("coordinator_port", self.DEFAULT_PORT)

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((coordinator_host, coordinator_port))

            node_info = {
                "hostname": socket.gethostname(),
                "ip_address": self._get_local_ip(),
                "capabilities": self.nodes[self.node_id].capabilities,
                "platform_info": self.nodes[self.node_id].platform_info,
            }

            self._send_message(
                client_socket,
                {
                    "type": "register",
                    "node_id": self.node_id,
                    "node_info": node_info,
                },
            )

            response = self._receive_message(client_socket)
            if response and response.get("type") == "registered":
                self.coordinator_address = (coordinator_host, coordinator_port)
                self.logger.info("Connected to coordinator at %s", self.coordinator_address)

                comm_thread = threading.Thread(
                    target=self._worker_communication_loop,
                    args=(client_socket,),
                    daemon=True,
                )
                comm_thread.start()
                self.background_threads.append(comm_thread)
            else:
                raise ConnectionError("Failed to register with coordinator")

        except (OSError, ConnectionError) as e:
            self.logger.exception("Failed to connect to coordinator: %s", e)
            raise

    def _worker_communication_loop(self, coordinator_socket: socket.socket) -> None:
        """Worker communication loop with coordinator."""
        try:
            while self.running:
                self._send_message(
                    coordinator_socket,
                    {
                        "type": "request_task",
                        "node_id": self.node_id,
                    },
                )

                response = self._receive_message(coordinator_socket)
                if not response:
                    break

                if response.get("type") == "task_assigned":
                    task_data = response.get("task")
                    if isinstance(task_data, dict):
                        task = AnalysisTask(**task_data)
                        self._execute_task_locally(task, coordinator_socket)
                elif response.get("type") == "no_tasks":
                    time.sleep(2.0)

        except OSError as e:
            self.logger.exception("Worker communication error: %s", e)

    def _send_message(self, sock: socket.socket, message: dict[str, Any]) -> None:
        """Send a message over socket with length prefix and HMAC."""
        try:
            data = pickle.dumps(message)
            msg_hmac = hmac.new(self._hmac_key, data, hashlib.sha256).digest()
            payload = msg_hmac + data
            length = struct.pack("!I", len(payload))
            sock.sendall(length + payload)
        except (OSError, pickle.PickleError) as e:
            self.logger.exception("Error sending message: %s", e)
            raise

    def _receive_message(self, sock: socket.socket) -> dict[str, Any] | None:
        """Receive a message from socket with length prefix and HMAC verification."""
        try:
            length_data = self._recv_exactly(sock, 4)
            if not length_data:
                return None

            length = struct.unpack("!I", length_data)[0]
            payload = self._recv_exactly(sock, length)
            if not payload or len(payload) < 32:
                return None

            received_hmac = payload[:32]
            data = payload[32:]

            expected_hmac = hmac.new(self._hmac_key, data, hashlib.sha256).digest()
            if not hmac.compare_digest(received_hmac, expected_hmac):
                self.logger.exception("HMAC verification failed - potential data tampering detected")
                return None

            return pickle.loads(data) if data else None  # noqa: S301
        except (OSError, pickle.PickleError, struct.error) as e:
            self.logger.exception("Error receiving message: %s", e)
            return None

    def _recv_exactly(self, sock: socket.socket, length: int) -> bytes | None:
        """Receive exactly the specified number of bytes."""
        data = b""
        while len(data) < length:
            if chunk := sock.recv(length - len(data)):
                data += chunk
            else:
                return None
        return data

    def _register_worker_node(self, node_id: str, node_info: dict[str, Any], connection: socket.socket) -> None:
        """Register a new worker node."""
        with self.nodes_lock:
            worker_node = WorkerNode(
                node_id=node_id,
                hostname=node_info.get("hostname", "unknown"),
                ip_address=node_info.get("ip_address", "unknown"),
                port=0,
                status=NodeStatus.READY,
                capabilities=node_info.get("capabilities", {}),
                current_load=0.0,
                max_load=float(node_info.get("capabilities", {}).get("cpu_count", 4)),
                active_tasks=[],
                completed_tasks=0,
                failed_tasks=0,
                last_heartbeat=time.time(),
                platform_info=node_info.get("platform_info", {}),
                resource_usage={},
            )

            self.nodes[node_id] = worker_node
            self.client_connections[node_id] = connection
            self.logger.info("Registered worker node: %s (%s)", node_id, worker_node.hostname)

    def _update_node_heartbeat(self, node_id: str, status: dict[str, Any]) -> None:
        """Update node heartbeat and status."""
        with self.nodes_lock:
            if node_id in self.nodes:
                node = self.nodes[node_id]
                node.last_heartbeat = time.time()
                node.current_load = status.get("current_load", node.current_load)
                node.resource_usage = status.get("resource_usage", {})

                if status.get("status"):
                    with contextlib.suppress(ValueError):
                        node.status = NodeStatus(status["status"])

    def _mark_node_offline(self, node_id: str) -> None:
        """Mark a node as offline and reassign its tasks."""
        with self.nodes_lock:
            if node_id in self.nodes:
                self.nodes[node_id].status = NodeStatus.OFFLINE
                self.logger.warning("Node %s marked as offline", node_id)

                with self.task_lock:
                    for task_id in self.nodes[node_id].active_tasks[:]:
                        if task_id in self.tasks:
                            task = self.tasks[task_id]
                            task.status = TaskStatus.RETRY
                            task.assigned_node = None
                            task.retry_count += 1
                            heapq.heappush(self.task_queue, task)
                            self.logger.info("Reassigning task %s after node failure", task_id)

                self.nodes[node_id].active_tasks.clear()

    def _heartbeat_loop(self) -> None:
        """Send periodic heartbeat messages."""
        while self.running:
            try:
                with self.nodes_lock:
                    if self.node_id in self.nodes:
                        node = self.nodes[self.node_id]
                        node.last_heartbeat = time.time()

                time.sleep(self.HEARTBEAT_INTERVAL)

            except Exception as e:
                self.logger.exception("Heartbeat error: %s", e)

    def _task_monitor_loop(self) -> None:
        """Monitor task execution and handle timeouts."""
        while self.running:
            try:
                current_time = time.time()

                with self.nodes_lock:
                    for node_id, node in list(self.nodes.items()):
                        if (
                            node_id != self.node_id and current_time - node.last_heartbeat > self.NODE_TIMEOUT
                        ) and node.status != NodeStatus.OFFLINE:
                            self._mark_node_offline(node_id)

                with self.task_lock:
                    for task_id, task in list(self.tasks.items()):
                        if task.status == TaskStatus.RUNNING and task.started_at and current_time - task.started_at > task.timeout:
                            self.logger.warning("Task %s timed out", task_id)
                            self._handle_task_failure(task_id, "Task timeout exceeded")

                time.sleep(self.TASK_CHECK_INTERVAL)

            except Exception as e:
                self.logger.exception("Task monitor error: %s", e)

    def _task_scheduler_loop(self) -> None:
        """Schedule tasks to available worker nodes."""
        while self.running:
            try:
                if not self.task_queue:
                    time.sleep(0.5)
                    continue

                available_nodes = self._get_available_nodes()
                if not available_nodes:
                    time.sleep(1.0)
                    continue

                with self.task_lock:
                    while self.task_queue and available_nodes:
                        task = heapq.heappop(self.task_queue)

                        if task.retry_count > task.max_retries:
                            self.logger.exception("Task %s exceeded max retries", task.task_id)
                            task.status = TaskStatus.FAILED
                            task.error = "Maximum retry count exceeded"
                            continue

                        if best_node := self._select_best_node(task, available_nodes):
                            self._assign_task(task, best_node)
                            available_nodes = [n for n in available_nodes if n.node_id != best_node.node_id]

                time.sleep(0.1)

            except Exception as e:
                self.logger.exception("Task scheduler error: %s", e)
                time.sleep(1.0)

    def _get_available_nodes(self) -> list[WorkerNode]:
        """Get list of available worker nodes."""
        with self.nodes_lock:
            return [
                node
                for node in self.nodes.values()
                if node.status in (NodeStatus.READY, NodeStatus.BUSY) and node.current_load < node.max_load
            ]

    def _select_best_node(self, task: AnalysisTask, available_nodes: list[WorkerNode]) -> WorkerNode | None:
        """Select the best node for a task based on capabilities and load."""
        if not available_nodes:
            return None

        scored_nodes = []
        for node in available_nodes:
            score = 0.0

            load_factor = 1.0 - (node.current_load / node.max_load)
            score += load_factor * 10.0

            if (
                (task.task_type == "frida_analysis" and node.capabilities.get("supports_frida"))
                or (task.task_type == "radare2_analysis" and node.capabilities.get("supports_radare2"))
                or (task.task_type == "angr_analysis" and node.capabilities.get("supports_angr"))
            ):
                score += 5.0

            if node.platform_info.get("system") == "Windows":
                score += 2.0

            failure_rate = node.failed_tasks / max(node.completed_tasks + node.failed_tasks, 1)
            score -= failure_rate * 3.0

            scored_nodes.append((score, node))

        scored_nodes.sort(reverse=True, key=lambda x: x[0])
        return scored_nodes[0][1] if scored_nodes else None

    def _assign_task(self, task: AnalysisTask, node: WorkerNode) -> None:
        """Assign a task to a worker node."""
        task.assigned_node = node.node_id
        task.status = TaskStatus.ASSIGNED
        task.started_at = time.time()

        with self.nodes_lock:
            node.active_tasks.append(task.task_id)
            node.current_load += 1.0
            if node.current_load >= node.max_load:
                node.status = NodeStatus.BUSY

        self.logger.info("Assigned task %s to node %s", task.task_id, node.node_id)

    def _assign_task_to_node(self, node_id: str) -> AnalysisTask | None:
        """Assign next available task to requesting node."""
        with self.task_lock:
            if not self.task_queue:
                return None

            task = heapq.heappop(self.task_queue)

            with self.nodes_lock:
                if node_id in self.nodes:
                    self._assign_task(task, self.nodes[node_id])
                    return task

        return None

    def _execute_task_locally(self, task: AnalysisTask, coordinator_socket: socket.socket | None = None) -> None:
        """Execute a task locally on this worker node."""
        try:
            task.status = TaskStatus.RUNNING
            start_time = time.time()

            result = self._run_task_analysis(task)

            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()
            task.result = result

            if coordinator_socket:
                self._send_message(
                    coordinator_socket,
                    {
                        "type": "task_result",
                        "task_id": task.task_id,
                        "result": result,
                    },
                )
            else:
                self._handle_task_result(task.task_id, result)

            self.logger.info("Completed task %s in %.2fs", task.task_id, time.time() - start_time)

        except Exception as e:
            error_msg = f"Task execution failed: {e!s}\n{traceback.format_exc()}"
            self.logger.exception(error_msg)

            task.status = TaskStatus.FAILED
            task.error = error_msg

            if coordinator_socket:
                self._send_message(
                    coordinator_socket,
                    {
                        "type": "task_failed",
                        "task_id": task.task_id,
                        "error": error_msg,
                    },
                )
            else:
                self._handle_task_failure(task.task_id, error_msg)

    def _run_task_analysis(self, task: AnalysisTask) -> dict[str, Any]:
        """Run the actual binary analysis for a task."""
        binary_path = task.binary_path
        task_type = task.task_type
        params = task.params

        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        if task_type == "pattern_search":
            return self._task_pattern_search(binary_path, params)
        if task_type == "entropy_analysis":
            return self._task_entropy_analysis(binary_path, params)
        if task_type == "section_analysis":
            return self._task_section_analysis(binary_path, params)
        if task_type == "string_extraction":
            return self._task_string_extraction(binary_path, params)
        if task_type == "import_analysis":
            return self._task_import_analysis(binary_path, params)
        if task_type == "crypto_detection":
            return self._task_crypto_detection(binary_path, params)
        if task_type == "frida_analysis":
            return self._task_frida_analysis(binary_path, params)
        if task_type == "radare2_analysis":
            return self._task_radare2_analysis(binary_path, params)
        if task_type == "angr_analysis":
            return self._task_angr_analysis(binary_path, params)
        return self._task_generic_analysis(binary_path, params)

    def _task_pattern_search(self, binary_path: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute pattern search task."""
        import re

        patterns = params.get("patterns", [])
        chunk_start = params.get("chunk_start", 0)
        chunk_size = params.get("chunk_size", 1024 * 1024)

        matches = []
        with open(binary_path, "rb") as f:
            f.seek(chunk_start)
            data = f.read(chunk_size)

            for pattern in patterns:
                if isinstance(pattern, str):
                    pattern = pattern.encode()

                for match in re.finditer(re.escape(pattern), data):
                    matches.append({
                        "pattern": pattern.decode() if isinstance(pattern, bytes) else pattern,
                        "offset": chunk_start + match.start(),
                        "context": data[max(0, match.start() - 20) : match.end() + 20].hex(),
                    })

        return {
            "task_type": "pattern_search",
            "matches": matches,
            "patterns_searched": len(patterns),
            "chunk_analyzed": chunk_size,
        }

    def _task_entropy_analysis(self, binary_path: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute entropy analysis task."""
        import math
        from collections import Counter

        chunk_start = params.get("chunk_start", 0)
        chunk_size = params.get("chunk_size", 1024 * 1024)
        window_size = params.get("window_size", 256)

        with open(binary_path, "rb") as f:
            f.seek(chunk_start)
            data = f.read(chunk_size)

        def calculate_entropy(data_segment: bytes) -> float:
            if not data_segment:
                return 0.0
            counts = Counter(data_segment)
            total = len(data_segment)
            return -sum((count / total) * math.log2(count / total) for count in counts.values())

        overall_entropy = calculate_entropy(data)

        windows = []
        for i in range(0, len(data) - window_size + 1, window_size // 2):
            window_data = data[i : i + window_size]
            entropy = calculate_entropy(window_data)
            windows.append({
                "offset": chunk_start + i,
                "entropy": entropy,
                "high_entropy": entropy > 7.0,
            })

        return {
            "task_type": "entropy_analysis",
            "overall_entropy": overall_entropy,
            "window_count": len(windows),
            "high_entropy_regions": sum(bool(w["high_entropy"]) for w in windows),
            "windows": windows,
        }

    def _task_section_analysis(self, binary_path: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute PE section analysis task."""
        try:
            import pefile

            pe = pefile.PE(binary_path)
            section_name = params.get("section_name")

            sections_info = []
            for section in pe.sections:
                name = section.Name.decode().strip("\x00")
                if section_name and name != section_name:
                    continue

                sections_info.append({
                    "name": name,
                    "virtual_address": section.VirtualAddress,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "characteristics": section.Characteristics,
                    "entropy": section.get_entropy(),
                })

            return {
                "task_type": "section_analysis",
                "sections": sections_info,
                "section_count": len(sections_info),
            }

        except ImportError:
            return {"error": "pefile not available"}
        except Exception as e:
            self.logger.exception("Section analysis error: %s", e)
            return {"error": str(e)}

    def _task_string_extraction(self, binary_path: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute string extraction task."""
        chunk_start = params.get("chunk_start", 0)
        chunk_size = params.get("chunk_size", 1024 * 1024)
        min_length = params.get("min_length", 4)

        strings = []
        with open(binary_path, "rb") as f:
            f.seek(chunk_start)
            data = f.read(chunk_size)

            current_string = b""
            offset = 0

            for i, byte in enumerate(data):
                if 32 <= byte <= 126:
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= min_length:
                        strings.append({
                            "string": current_string.decode("ascii"),
                            "offset": chunk_start + offset,
                            "length": len(current_string),
                        })
                    current_string = b""
                    offset = i + 1

            if len(current_string) >= min_length:
                strings.append({
                    "string": current_string.decode("ascii"),
                    "offset": chunk_start + offset,
                    "length": len(current_string),
                })

        return {
            "task_type": "string_extraction",
            "strings": strings[:1000],
            "total_strings": len(strings),
        }

    def _task_import_analysis(self, binary_path: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute import table analysis task."""
        try:
            import pefile

            pe = pefile.PE(binary_path)
            imports = []

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode() if isinstance(entry.dll, bytes) else entry.dll
                    functions = []

                    for imp in entry.imports:
                        func_name = imp.name.decode() if imp.name and isinstance(imp.name, bytes) else str(imp.name)
                        functions.append({
                            "name": func_name,
                            "ordinal": imp.ordinal,
                            "address": imp.address,
                        })

                    imports.append({
                        "dll": dll_name,
                        "functions": functions,
                    })

            return {
                "task_type": "import_analysis",
                "imports": imports,
                "dll_count": len(imports),
                "total_imports": sum(len(i["functions"]) for i in imports),
            }

        except ImportError:
            return {"error": "pefile not available"}
        except Exception as e:
            self.logger.exception("Import analysis error: %s", e)
            return {"error": str(e)}

    def _task_crypto_detection(self, binary_path: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute cryptographic constant detection task."""
        chunk_start = params.get("chunk_start", 0)
        chunk_size = params.get("chunk_size", 1024 * 1024)

        crypto_constants = {
            "AES": [b"\x63\x7c\x77\x7b", b"\x09\x0e\x0b\x0d"],
            "DES": [b"\x1f\x8b\x08"],
            "RSA": [b"\x30\x82"],
            "MD5": [b"\x01\x23\x45\x67", b"\x89\xab\xcd\xef"],
            "SHA256": [b"\x6a\x09\xe6\x67", b"\xbb\x67\xae\x85"],
        }

        detections = []
        with open(binary_path, "rb") as f:
            f.seek(chunk_start)
            data = f.read(chunk_size)

            for algo, patterns in crypto_constants.items():
                for pattern in patterns:
                    offset = data.find(pattern)
                    if offset != -1:
                        detections.append({
                            "algorithm": algo,
                            "offset": chunk_start + offset,
                            "confidence": "high",
                        })

        return {
            "task_type": "crypto_detection",
            "detections": detections,
            "algorithms_found": len({d["algorithm"] for d in detections}),
        }

    def _task_frida_analysis(self, binary_path: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute Frida-based dynamic analysis task."""
        return {
            "task_type": "frida_analysis",
            "error": "Frida analysis requires runtime execution environment",
            "binary": binary_path,
        }

    def _task_radare2_analysis(self, binary_path: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute radare2-based analysis task."""
        try:
            import r2pipe

            r2 = r2pipe.open(binary_path)
            r2.cmd("aaa")

            functions = r2.cmdj("aflj") or []
            strings = r2.cmdj("izj") or []

            r2.quit()

            return {
                "task_type": "radare2_analysis",
                "function_count": len(functions),
                "string_count": len(strings),
                "functions": functions[:100],
                "strings": strings[:100],
            }

        except ImportError:
            return {"error": "r2pipe not available"}
        except Exception as e:
            self.logger.exception("Radare2 analysis error: %s", e)
            return {"error": str(e)}

    def _task_angr_analysis(self, binary_path: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute angr-based symbolic analysis task."""
        try:
            import angr

            proj = angr.Project(binary_path, auto_load_libs=False)

            cfg = proj.analyses.CFGFast()

            node_count = 0
            if hasattr(cfg, "graph") and hasattr(cfg.graph, "nodes"):
                try:
                    nodes_method: Callable[[], Any] = cfg.graph.nodes
                    nodes_result = nodes_method()
                    nodes_list: list[Any] = list(nodes_result)
                    node_count = len(nodes_list)
                except (TypeError, AttributeError):
                    node_count = 0
            elif hasattr(cfg, "model") and hasattr(cfg.model, "nodes"):
                try:
                    nodes_method_model: Callable[[], Any] = cfg.model.nodes
                    nodes_result_model = nodes_method_model()
                    nodes_list_model: list[Any] = list(nodes_result_model)
                    node_count = len(nodes_list_model)
                except (TypeError, AttributeError):
                    node_count = 0

            return {
                "task_type": "angr_analysis",
                "function_count": len(cfg.functions),
                "basic_block_count": node_count,
                "entry_point": hex(proj.entry),
                "architecture": proj.arch.name,
            }

        except ImportError:
            return {"error": "angr not available"}
        except Exception as e:
            self.logger.exception("Angr analysis error: %s", e)
            return {"error": str(e)}

    def _task_generic_analysis(self, binary_path: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute generic binary analysis task."""
        file_size = os.path.getsize(binary_path)

        with open(binary_path, "rb") as f:
            header = f.read(4)

        file_type = "Unknown"
        if header[:2] == b"MZ":
            file_type = "PE"
        elif header[:4] == b"\x7fELF":
            file_type = "ELF"

        return {
            "task_type": "generic_analysis",
            "file_size": file_size,
            "file_type": file_type,
            "params": params,
        }

    def _handle_task_result(self, task_id: str, result: dict[str, Any]) -> None:
        """Handle successful task completion."""
        with self.task_lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task.status = TaskStatus.COMPLETED
                task.completed_at = time.time()
                task.result = result

                self.completed_results[task_id] = result
                self.performance_metrics["tasks_completed"] += 1

                processing_time = task.completed_at - task.started_at if task.started_at else 0
                self.performance_metrics["total_processing_time"] += processing_time

                if task.assigned_node:
                    with self.nodes_lock:
                        if task.assigned_node in self.nodes:
                            node = self.nodes[task.assigned_node]
                            if task_id in node.active_tasks:
                                node.active_tasks.remove(task_id)
                            node.completed_tasks += 1
                            node.current_load = max(0, node.current_load - 1.0)
                            if node.status == NodeStatus.BUSY and node.current_load < node.max_load:
                                node.status = NodeStatus.READY

                self.logger.info("Task %s completed successfully", task_id)

    def _handle_task_failure(self, task_id: str, error: str) -> None:
        """Handle task failure and schedule retry if applicable."""
        with self.task_lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task.error = error
                task.retry_count += 1

                if task.retry_count <= task.max_retries:
                    task.status = TaskStatus.RETRY
                    task.assigned_node = None
                    heapq.heappush(self.task_queue, task)
                    self.logger.warning("Task %s failed, scheduling retry %d/%d", task_id, task.retry_count, task.max_retries)
                else:
                    task.status = TaskStatus.FAILED
                    self.performance_metrics["tasks_failed"] += 1
                    self.logger.exception("Task %s failed permanently after %d retries", task_id, task.retry_count)

                if task.assigned_node:
                    with self.nodes_lock:
                        if task.assigned_node in self.nodes:
                            node = self.nodes[task.assigned_node]
                            if task_id in node.active_tasks:
                                node.active_tasks.remove(task_id)
                            node.failed_tasks += 1
                            node.current_load = max(0, node.current_load - 1.0)
                            if node.status == NodeStatus.BUSY:
                                node.status = NodeStatus.READY

    def submit_task(
        self,
        task_type: str,
        binary_path: str,
        params: dict[str, Any] | None = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        timeout: float = 3600.0,
    ) -> str:
        """Submit a task for distributed analysis.

        Args:
            task_type: Type of analysis task
            binary_path: Path to binary file
            params: Task-specific parameters
            priority: Task priority level
            timeout: Task timeout in seconds

        Returns:
            str: Task ID

        """
        task_id = str(uuid.uuid4())

        task = AnalysisTask(
            task_id=task_id,
            task_type=task_type,
            priority=priority,
            binary_path=binary_path,
            params=params or {},
            status=TaskStatus.PENDING,
            created_at=time.time(),
            timeout=timeout,
        )

        with self.task_lock:
            self.tasks[task_id] = task
            heapq.heappush(self.task_queue, task)

        self.performance_metrics["tasks_submitted"] += 1
        self.performance_metrics["task_distribution"][task_type] += 1

        self.logger.info("Submitted task %s (%s) with priority %s", task_id, task_type, priority.name)
        return task_id

    def submit_binary_analysis(
        self,
        binary_path: str,
        chunk_size: int = 5 * 1024 * 1024,
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> list[str]:
        """Submit a complete binary analysis as multiple distributed tasks.

        Args:
            binary_path: Path to binary file
            chunk_size: Size of chunks for parallel processing
            priority: Task priority level

        Returns:
            list[str]: List of task IDs

        """
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        file_size = os.path.getsize(binary_path)
        task_ids = [self.submit_task("import_analysis", binary_path, {}, priority)]

        task_ids.append(self.submit_task("section_analysis", binary_path, {}, priority))

        for offset in range(0, file_size, chunk_size):
            chunk_params = {
                "chunk_start": offset,
                "chunk_size": min(chunk_size, file_size - offset),
            }

            task_ids.append(self.submit_task("entropy_analysis", binary_path, chunk_params, priority))
            task_ids.append(self.submit_task("string_extraction", binary_path, chunk_params, priority))
            task_ids.append(self.submit_task("crypto_detection", binary_path, chunk_params, priority))

        self.logger.info("Submitted %d tasks for binary analysis of %s", len(task_ids), binary_path)
        return task_ids

    def get_task_status(self, task_id: str) -> dict[str, Any] | None:
        """Get status of a specific task.

        Args:
            task_id: Task ID

        Returns:
            dict: Task status information or None if not found

        """
        with self.task_lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                return {
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "status": task.status.value,
                    "priority": task.priority.name,
                    "assigned_node": task.assigned_node,
                    "retry_count": task.retry_count,
                    "created_at": task.created_at,
                    "started_at": task.started_at,
                    "completed_at": task.completed_at,
                    "error": task.error,
                }
        return None

    def get_task_result(self, task_id: str, timeout: float | None = None) -> dict[str, Any] | None:
        """Get result of a completed task, optionally waiting for completion.

        Args:
            task_id: Task ID
            timeout: Maximum time to wait in seconds (None = no wait)

        Returns:
            dict: Task result or None if not completed

        """
        start_time = time.time()

        while True:
            with self.task_lock:
                if task_id in self.tasks:
                    task = self.tasks[task_id]
                    if task.status == TaskStatus.COMPLETED:
                        return task.result
                    if task.status == TaskStatus.FAILED:
                        return {"error": task.error, "status": "failed"}

            if timeout is None:
                return None

            if time.time() - start_time >= timeout:
                return None

            time.sleep(0.5)

    def wait_for_completion(self, task_ids: list[str] | None = None, timeout: float | None = None) -> dict[str, Any]:
        """Wait for all tasks (or specified tasks) to complete.

        Args:
            task_ids: List of task IDs to wait for (None = all tasks)
            timeout: Maximum time to wait in seconds

        Returns:
            dict: Completion summary

        """
        start_time = time.time()
        target_tasks = set(task_ids) if task_ids else None

        while True:
            with self.task_lock:
                if target_tasks:
                    remaining = [
                        tid
                        for tid in target_tasks
                        if tid in self.tasks
                        and self.tasks[tid].status
                        in (
                            TaskStatus.PENDING,
                            TaskStatus.ASSIGNED,
                            TaskStatus.RUNNING,
                            TaskStatus.RETRY,
                        )
                    ]
                else:
                    remaining = [
                        tid
                        for tid, task in self.tasks.items()
                        if task.status
                        in (
                            TaskStatus.PENDING,
                            TaskStatus.ASSIGNED,
                            TaskStatus.RUNNING,
                            TaskStatus.RETRY,
                        )
                    ]

                if not remaining:
                    break

            if timeout and time.time() - start_time >= timeout:
                return {
                    "status": "timeout",
                    "remaining_tasks": len(remaining),
                    "timeout": timeout,
                }

            time.sleep(1.0)

        return {
            "status": "completed",
            "total_time": time.time() - start_time,
        }

    def get_cluster_status(self) -> dict[str, Any]:
        """Get current cluster status and statistics.

        Returns:
            dict: Cluster status information

        """
        with self.nodes_lock:
            nodes_info = {
                node_id: {
                    "hostname": node.hostname,
                    "ip_address": node.ip_address,
                    "status": node.status.value,
                    "current_load": node.current_load,
                    "max_load": node.max_load,
                    "active_tasks": len(node.active_tasks),
                    "completed_tasks": node.completed_tasks,
                    "failed_tasks": node.failed_tasks,
                    "last_heartbeat": node.last_heartbeat,
                    "capabilities": node.capabilities,
                }
                for node_id, node in self.nodes.items()
            }
        with self.task_lock:
            task_stats = {
                "pending": sum(t.status == TaskStatus.PENDING for t in self.tasks.values()),
                "assigned": sum(t.status == TaskStatus.ASSIGNED for t in self.tasks.values()),
                "running": sum(t.status == TaskStatus.RUNNING for t in self.tasks.values()),
                "completed": sum(t.status == TaskStatus.COMPLETED for t in self.tasks.values()),
                "failed": sum(t.status == TaskStatus.FAILED for t in self.tasks.values()),
                "total": len(self.tasks),
            }

        return {
            "mode": self.mode,
            "is_coordinator": self.is_coordinator,
            "node_id": self.node_id,
            "running": self.running,
            "nodes": nodes_info,
            "node_count": len(self.nodes),
            "tasks": task_stats,
            "performance": self.performance_metrics,
        }

    def get_results_summary(self) -> dict[str, Any]:
        """Get summary of all completed results.

        Returns:
            dict: Results summary

        """
        with self.task_lock:
            results_by_type = defaultdict(list)
            for task_id, result in self.completed_results.items():
                if task_id in self.tasks:
                    task_type = self.tasks[task_id].task_type
                    results_by_type[task_type].append(result)

            return {
                "total_results": len(self.completed_results),
                "results_by_type": dict(results_by_type),
                "task_types": list(results_by_type.keys()),
            }

    def export_results(self, output_path: str) -> bool:
        """Export all results to a JSON file.

        Args:
            output_path: Path to output file

        Returns:
            bool: True if successful

        """
        try:
            results = {
                "cluster_status": self.get_cluster_status(),
                "completed_results": self.completed_results,
                "tasks": {},
            }

            with self.task_lock:
                for task_id, task in self.tasks.items():
                    results["tasks"][task_id] = {
                        "task_id": task.task_id,
                        "task_type": task.task_type,
                        "status": task.status.value,
                        "priority": task.priority.name,
                        "binary_path": task.binary_path,
                        "created_at": task.created_at,
                        "completed_at": task.completed_at,
                        "error": task.error,
                    }

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)

            self.logger.info("Exported results to %s", output_path)
            return True

        except (OSError, json.JSONDecodeError) as e:
            self.logger.exception("Failed to export results: %s", e)
            return False

    def shutdown(self) -> None:
        """Shutdown the distributed manager and cleanup resources."""
        self.logger.info("Shutting down distributed manager...")
        self.running = False

        for thread in self.background_threads:
            if thread.is_alive():
                thread.join(timeout=2.0)

        if self.server_socket:
            with contextlib.suppress(OSError, socket.error):
                self.server_socket.close()

        for conn in self.client_connections.values():
            with contextlib.suppress(OSError, socket.error):
                conn.close()

        if self.local_manager:
            self.local_manager.cleanup()

        self.logger.info("Distributed manager shutdown complete")


def create_distributed_manager(
    mode: str = "auto",
    config: dict[str, Any] | None = None,
    enable_networking: bool = True,
) -> DistributedAnalysisManager:
    """Create a DistributedAnalysisManager instance.

    Args:
        mode: Execution mode - "local", "cluster", or "auto"
        config: Configuration dictionary
        enable_networking: Enable network-based clustering

    Returns:
        DistributedAnalysisManager: Configured manager instance

    """
    return DistributedAnalysisManager(mode=mode, config=config, enable_networking=enable_networking)


__all__ = [
    "AnalysisTask",
    "DistributedAnalysisManager",
    "NodeStatus",
    "TaskPriority",
    "TaskStatus",
    "WorkerNode",
    "create_distributed_manager",
]
