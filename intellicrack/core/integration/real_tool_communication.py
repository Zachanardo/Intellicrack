#!/usr/bin/env python3
"""Real Tool Communication System.

Production-ready implementation for cross-tool integration:
- Shared memory IPC for tool communication
- Result serialization protocol
- Tool status monitoring
- Failure recovery mechanisms
- Result conflict resolution
- Performance load balancing
"""

import hashlib
import json
import logging
import mmap
import os
import queue
import struct
import sys
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

import lz4.frame
import msgpack
import psutil

logger = logging.getLogger(__name__)


class ToolType(Enum):
    """Supported analysis tools."""

    GHIDRA = "ghidra"
    FRIDA = "frida"
    RADARE2 = "radare2"
    IDA = "ida"
    X64DBG = "x64dbg"
    WINDBG = "windbg"
    OLLYDBG = "ollydbg"
    IMMUNITY = "immunity"


class MessageType(Enum):
    """IPC message types."""

    REQUEST = "request"
    RESPONSE = "response"
    STATUS = "status"
    HEARTBEAT = "heartbeat"
    DATA = "data"
    ERROR = "error"
    SYNC = "sync"
    CONFLICT = "conflict"


class SerializationFormat(Enum):
    """Serialization formats for data exchange."""

    JSON = "json"
    MSGPACK = "msgpack"
    PROTOBUF = "protobuf"
    BINARY = "binary"


@dataclass
class ToolMessage:
    """Message structure for tool communication."""

    source: ToolType
    destination: ToolType
    message_type: MessageType
    correlation_id: str
    timestamp: float
    data: object
    metadata: dict[str, object]


@dataclass
class ToolStatus:
    """Tool status information."""

    tool: ToolType
    pid: int
    status: str
    cpu_usage: float
    memory_usage: float
    queue_size: int
    last_heartbeat: float
    error_count: int
    success_count: int


class SharedMemoryManager:
    """Manages shared memory for inter-process communication."""

    def __init__(self, name: str, size: int = 1024 * 1024 * 10) -> None:  # 10MB default
        """Initialize the SharedMemoryManager with name and size.

        Args:
            name: Name for the shared memory segment.
            size: Size of the shared memory in bytes. Defaults to 10MB.

        """
        self.name = name
        self.size = size
        self.memory: mmap.mmap | None = None
        self.lock = threading.Lock()
        self._init_shared_memory()

    def _init_shared_memory(self) -> None:
        """Initialize shared memory segment."""
        if sys.platform == "win32":
            # Windows shared memory
            try:
                # Try to open existing shared memory
                self.memory = mmap.mmap(-1, self.size, tagname=self.name, access=mmap.ACCESS_WRITE)
            except (OSError, ValueError):
                # Create new shared memory
                self.memory = mmap.mmap(-1, self.size, tagname=self.name)
                # Initialize with header
                self._write_header()
        else:
            # Unix shared memory - use secure temp directory instead of /dev/shm
            import tempfile

            temp_dir = tempfile.gettempdir()
            shm_path = os.path.join(temp_dir, f"{self.name}")
            if not os.path.exists(shm_path):
                # Create shared memory file
                with open(shm_path, "wb") as f:
                    f.write(b"\x00" * self.size)

            with open(shm_path, "r+b") as f:
                self.memory = mmap.mmap(f.fileno(), self.size)
                if self.memory[0:4] != b"INTC":
                    self._write_header()

    def _write_header(self) -> None:
        """Write header to shared memory."""
        with self.lock:
            self.memory.seek(0)
            # Magic bytes
            self.memory.write(b"INTC")
            # Version
            self.memory.write(struct.pack("<I", 1))
            # Write pointer
            self.memory.write(struct.pack("<I", 64))
            # Read pointer
            self.memory.write(struct.pack("<I", 64))
            # Message count
            self.memory.write(struct.pack("<I", 0))

    def write_message(self, message: bytes) -> bool:
        """Write message to shared memory.

        Args:
            message: Raw bytes to write to shared memory.

        Returns:
            True if message was successfully written, False otherwise.

        """
        with self.lock:
            try:
                # Get write pointer
                self.memory.seek(8)
                write_ptr = struct.unpack("<I", self.memory.read(4))[0]

                # Check space available
                if write_ptr + len(message) + 8 > self.size:
                    # Wrap around or error
                    if len(message) + 8 + 64 > self.size:
                        logger.error("Message too large for shared memory")
                        return False
                    # Reset write pointer
                    write_ptr = 64

                # Write message size and data
                self.memory.seek(write_ptr)
                self.memory.write(struct.pack("<I", len(message)))
                self.memory.write(struct.pack("<I", int(time.time() * 1000000)))
                self.memory.write(message)

                # Update write pointer
                new_write_ptr = write_ptr + 8 + len(message)
                self.memory.seek(8)
                self.memory.write(struct.pack("<I", new_write_ptr))

                # Update message count
                self.memory.seek(16)
                msg_count = struct.unpack("<I", self.memory.read(4))[0]
                self.memory.seek(16)
                self.memory.write(struct.pack("<I", msg_count + 1))

                return True

            except Exception as e:
                logger.error(f"Failed to write message: {e}")
                return False

    def read_message(self) -> bytes | None:
        """Read message from shared memory.

        Returns:
            Message bytes if available, None if no messages in queue.

        """
        with self.lock:
            try:
                # Get read pointer
                self.memory.seek(12)
                read_ptr = struct.unpack("<I", self.memory.read(4))[0]

                # Get write pointer
                self.memory.seek(8)
                write_ptr = struct.unpack("<I", self.memory.read(4))[0]

                # Check if messages available
                if read_ptr == write_ptr:
                    return None

                # Read message size
                self.memory.seek(read_ptr)
                msg_size = struct.unpack("<I", self.memory.read(4))[0]
                struct.unpack("<I", self.memory.read(4))[0]

                # Check for corruption
                if msg_size > self.size or msg_size == 0:
                    # Reset pointers
                    self._reset_pointers()
                    return None

                # Read message data
                message = self.memory.read(msg_size)

                # Update read pointer
                new_read_ptr = read_ptr + 8 + msg_size
                if new_read_ptr >= self.size:
                    new_read_ptr = 64

                self.memory.seek(12)
                self.memory.write(struct.pack("<I", new_read_ptr))

                return message

            except Exception as e:
                logger.error(f"Failed to read message: {e}")
                return None

    def _reset_pointers(self) -> None:
        """Reset read/write pointers."""
        with self.lock:
            self.memory.seek(8)
            self.memory.write(struct.pack("<I", 64))  # Write pointer
            self.memory.write(struct.pack("<I", 64))  # Read pointer
            self.memory.write(struct.pack("<I", 0))  # Message count

    def close(self) -> None:
        """Close shared memory."""
        if self.memory:
            self.memory.close()


class SerializationProtocol:
    """Handles serialization/deserialization of tool messages."""

    @staticmethod
    def serialize(message: ToolMessage, format: SerializationFormat = SerializationFormat.MSGPACK) -> bytes:
        """Serialize message to bytes.

        Args:
            message: ToolMessage instance to serialize.
            format: Serialization format to use. Defaults to MSGPACK.

        Returns:
            Serialized message as bytes.

        """
        data = {
            "source": message.source.value,
            "destination": message.destination.value,
            "message_type": message.message_type.value,
            "correlation_id": message.correlation_id,
            "timestamp": message.timestamp,
            "data": message.data,
            "metadata": message.metadata,
        }

        if format == SerializationFormat.JSON:
            return json.dumps(data).encode("utf-8")
        if format == SerializationFormat.MSGPACK:
            packed = msgpack.packb(data)
            # Compress with LZ4 for efficiency
            return lz4.frame.compress(packed)
        # Default to msgpack
        return msgpack.packb(data)

    @staticmethod
    def deserialize(data: bytes, format: SerializationFormat = SerializationFormat.MSGPACK) -> ToolMessage | None:
        """Deserialize bytes to message.

        Args:
            data: Serialized message bytes.
            format: Serialization format used. Defaults to MSGPACK.

        Returns:
            Deserialized ToolMessage if successful, None on error.

        """
        try:
            if format == SerializationFormat.JSON:
                msg_dict = json.loads(data.decode("utf-8"))
            elif format == SerializationFormat.MSGPACK:
                # Try decompression first
                try:
                    decompressed = lz4.frame.decompress(data)
                    msg_dict = msgpack.unpackb(decompressed, raw=False)
                except (lz4.frame.LZ4FrameError, msgpack.ExtraData):
                    msg_dict = msgpack.unpackb(data, raw=False)
            else:
                msg_dict = msgpack.unpackb(data, raw=False)

            return ToolMessage(
                source=ToolType(msg_dict["source"]),
                destination=ToolType(msg_dict["destination"]),
                message_type=MessageType(msg_dict["message_type"]),
                correlation_id=msg_dict["correlation_id"],
                timestamp=msg_dict["timestamp"],
                data=msg_dict["data"],
                metadata=msg_dict.get("metadata", {}),
            )

        except Exception as e:
            logger.error(f"Failed to deserialize message: {e}")
            return None


class ToolMonitor:
    """Monitors tool status and health."""

    def __init__(self) -> None:
        """Initialize the ToolMonitor with empty tools dictionary and lock."""
        self.tools: dict[ToolType, ToolStatus] = {}
        self.lock = threading.Lock()
        self.monitoring = False
        self.monitor_thread: threading.Thread | None = None

    def register_tool(self, tool: ToolType, pid: int) -> None:
        """Register a tool for monitoring.

        Args:
            tool: Type of tool to register.
            pid: Process ID of the tool instance.

        """
        with self.lock:
            self.tools[tool] = ToolStatus(
                tool=tool,
                pid=pid,
                status="running",
                cpu_usage=0.0,
                memory_usage=0.0,
                queue_size=0,
                last_heartbeat=time.time(),
                error_count=0,
                success_count=0,
            )

    def update_status(self, tool: ToolType, **kwargs: object) -> None:
        """Update tool status.

        Args:
            tool: Type of tool to update.
            **kwargs: Arbitrary keyword arguments for status attributes.

        """
        with self.lock:
            if tool in self.tools:
                for key, value in kwargs.items():
                    if hasattr(self.tools[tool], key):
                        setattr(self.tools[tool], key, value)

    def start_monitoring(self) -> None:
        """Start monitoring tools."""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def _monitor_loop(self) -> None:
        """Run main monitoring loop."""
        while self.monitoring:
            with self.lock:
                for tool, status in list(self.tools.items()):
                    try:
                        # Check if process is alive
                        if not psutil.pid_exists(status.pid):
                            status.status = "dead"
                            continue

                        # Get process info
                        process = psutil.Process(status.pid)
                        status.cpu_usage = process.cpu_percent()
                        status.memory_usage = process.memory_info().rss / (1024 * 1024)  # MB

                        # Check heartbeat timeout
                        if time.time() - status.last_heartbeat > 30:
                            status.status = "unresponsive"
                        elif status.status == "unresponsive" and time.time() - status.last_heartbeat < 30:
                            status.status = "running"

                    except Exception as e:
                        logger.error(f"Failed to monitor {tool.value}: {e}")
                        status.status = "error"

            time.sleep(1)

    def stop_monitoring(self) -> None:
        """Stop monitoring tools."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

    def get_status(self, tool: ToolType) -> ToolStatus | None:
        """Get tool status.

        Args:
            tool: Type of tool to query.

        Returns:
            ToolStatus instance if tool is registered, None otherwise.

        """
        with self.lock:
            return self.tools.get(tool)

    def get_all_status(self) -> dict[ToolType, ToolStatus]:
        """Get all tool statuses.

        Returns:
            Dictionary mapping tool types to their status objects.

        """
        with self.lock:
            return self.tools.copy()


class FailureRecovery:
    """Handles failure recovery for tool communication."""

    def __init__(self) -> None:
        """Initialize the FailureRecovery with retry configuration."""
        self.retry_config = {"max_retries": 3, "base_delay": 1.0, "max_delay": 30.0, "exponential_base": 2}
        self.failed_messages: dict[str, list[ToolMessage]] = {}
        self.recovery_handlers: dict[ToolType, Callable] = {}

    def add_recovery_handler(self, tool: ToolType, handler: Callable) -> None:
        """Add recovery handler for a tool.

        Args:
            tool: Type of tool to add handler for.
            handler: Callable to handle message recovery.

        """
        self.recovery_handlers[tool] = handler

    def handle_failure(self, message: ToolMessage, error: Exception) -> bool:
        """Handle message failure.

        Args:
            message: ToolMessage that failed.
            error: Exception that caused the failure.

        Returns:
            True if retry was scheduled, False if max retries exceeded.

        """
        correlation_id = message.correlation_id

        # Track failed message
        if correlation_id not in self.failed_messages:
            self.failed_messages[correlation_id] = []
        self.failed_messages[correlation_id].append(message)

        # Check retry count
        retry_count = len(self.failed_messages[correlation_id])
        if retry_count > self.retry_config["max_retries"]:
            logger.error(f"Message {correlation_id} exceeded max retries")
            self._handle_permanent_failure(message, error)
            return False

        # Calculate retry delay
        delay = min(
            self.retry_config["base_delay"] * (self.retry_config["exponential_base"] ** (retry_count - 1)), self.retry_config["max_delay"],
        )

        # Schedule retry
        threading.Timer(delay, self._retry_message, args=[message]).start()
        logger.info(f"Scheduled retry for message {correlation_id} after {delay}s")

        return True

    def _retry_message(self, message: ToolMessage) -> None:
        """Retry sending a message.

        Args:
            message: ToolMessage to retry sending.

        """
        if message.destination in self.recovery_handlers:
            try:
                self.recovery_handlers[message.destination](message)
                # Success - clean up
                if message.correlation_id in self.failed_messages:
                    del self.failed_messages[message.correlation_id]
            except Exception as e:
                self.handle_failure(message, e)

    def _handle_permanent_failure(self, message: ToolMessage, error: Exception) -> None:
        """Handle permanent failure.

        Args:
            message: ToolMessage that permanently failed.
            error: Exception that caused the permanent failure.

        """
        logger.error(f"Permanent failure for message {message.correlation_id}: {error}")

        # Clean up
        if message.correlation_id in self.failed_messages:
            del self.failed_messages[message.correlation_id]

        # Notify failure handlers
        # In production, this would trigger alerts or fallback mechanisms


class ConflictResolver:
    """Resolves conflicts between tool results."""

    def __init__(self) -> None:
        """Initialize the ConflictResolver with resolution strategies and tool weights."""
        self.resolution_strategies = {
            "majority_vote": self._majority_vote,
            "weighted_average": self._weighted_average,
            "confidence_based": self._confidence_based,
            "timestamp_based": self._timestamp_based,
            "authority_based": self._authority_based,
        }
        self.tool_weights = {ToolType.GHIDRA: 1.0, ToolType.IDA: 1.2, ToolType.RADARE2: 0.9, ToolType.FRIDA: 0.8}

    def resolve(self, conflicts: list[ToolMessage], strategy: str = "confidence_based") -> object | None:
        """Resolve conflicts between tool results.

        Args:
            conflicts: List of conflicting ToolMessages to resolve.
            strategy: Resolution strategy name. Defaults to "confidence_based".

        Returns:
            Resolved result object, or None if resolution fails.

        """
        if strategy not in self.resolution_strategies:
            strategy = "confidence_based"

        resolver = self.resolution_strategies[strategy]
        return resolver(conflicts)

    def _majority_vote(self, messages: list[ToolMessage]) -> object | None:
        """Resolve by majority vote.

        Args:
            messages: List of ToolMessages to vote on.

        Returns:
            Data from the message with most votes, or None if no messages.

        """
        if not messages:
            return None

        # Count votes
        votes = {}
        for msg in messages:
            data_hash = hashlib.sha256(str(msg.data).encode()).hexdigest()
            if data_hash not in votes:
                votes[data_hash] = []
            votes[data_hash].append(msg)

        # Find majority
        max_votes = max(len(v) for v in votes.values())
        for _data_hash, voters in votes.items():
            if len(voters) == max_votes:
                return voters[0].data

        return None

    def _weighted_average(self, messages: list[ToolMessage]) -> object | None:
        """Resolve by weighted average.

        Args:
            messages: List of ToolMessages to calculate weighted average from.

        Returns:
            Weighted average result for numeric data, or majority vote result for non-numeric data.

        """
        if not messages:
            return None

        # Group by tool
        tool_results = {}
        for msg in messages:
            if msg.source not in tool_results:
                tool_results[msg.source] = []
            tool_results[msg.source].append(msg.data)

        # Calculate weighted result
        weighted_sum = 0
        total_weight = 0

        for tool, results in tool_results.items():
            weight = self.tool_weights.get(tool, 1.0)
            # For numeric results
            if all(isinstance(r, (int, float)) for r in results):
                avg_result = sum(results) / len(results)
                weighted_sum += avg_result * weight
                total_weight += weight

        if total_weight > 0:
            return weighted_sum / total_weight

        # For non-numeric, fall back to majority vote
        return self._majority_vote(messages)

    def _confidence_based(self, messages: list[ToolMessage]) -> object | None:
        """Resolve based on confidence scores.

        Args:
            messages: List of ToolMessages to resolve by confidence.

        Returns:
            Data from the message with highest confidence score, or None if no messages.

        """
        if not messages:
            return None

        # Extract confidence scores
        scored_messages = []
        for msg in messages:
            confidence = msg.metadata.get("confidence", 0.5)
            scored_messages.append((confidence, msg))

        # Sort by confidence
        scored_messages.sort(key=lambda x: x[0], reverse=True)

        # Return highest confidence result
        return scored_messages[0][1].data if scored_messages else None

    def _timestamp_based(self, messages: list[ToolMessage]) -> object | None:
        """Resolve based on most recent timestamp.

        Args:
            messages: List of ToolMessages to resolve by timestamp.

        Returns:
            Data from the most recent message, or None if no messages.

        """
        if not messages:
            return None

        # Sort by timestamp
        messages.sort(key=lambda x: x.timestamp, reverse=True)

        # Return most recent
        return messages[0].data

    def _authority_based(self, messages: list[ToolMessage]) -> object | None:
        """Resolve based on tool authority.

        Args:
            messages: List of ToolMessages to resolve by authority.

        Returns:
            Data from the message from the highest authority tool, or None if no messages.

        """
        if not messages:
            return None

        # Sort by tool weight
        messages.sort(key=lambda x: self.tool_weights.get(x.source, 1.0), reverse=True)

        # Return highest authority result
        return messages[0].data


class LoadBalancer:
    """Balances load across multiple tool instances."""

    def __init__(self) -> None:
        """Initialize the LoadBalancer with empty tool instances and task queues."""
        self.tool_instances: dict[ToolType, list[int]] = {}  # Tool -> PIDs
        self.task_queues: dict[ToolType, queue.Queue] = {}
        self.load_metrics: dict[int, dict[str, float]] = {}  # PID -> metrics
        self.lock = threading.Lock()

    def register_instance(self, tool: ToolType, pid: int) -> None:
        """Register a tool instance.

        Args:
            tool: Type of tool to register.
            pid: Process ID of the tool instance.

        """
        with self.lock:
            if tool not in self.tool_instances:
                self.tool_instances[tool] = []
                self.task_queues[tool] = queue.Queue()

            self.tool_instances[tool].append(pid)
            self.load_metrics[pid] = {"cpu": 0.0, "memory": 0.0, "queue_size": 0, "response_time": 0.0}

    def get_best_instance(self, tool: ToolType) -> int | None:
        """Get best instance for load balancing.

        Args:
            tool: Type of tool to find best instance for.

        Returns:
            Process ID of the best instance, or None if no instances available.

        """
        with self.lock:
            if tool not in self.tool_instances:
                return None

            instances = self.tool_instances[tool]
            if not instances:
                return None

            # Calculate load scores
            scores = []
            for pid in instances:
                metrics = self.load_metrics.get(pid, {})

                # Check if process is alive
                if not psutil.pid_exists(pid):
                    continue

                # Calculate composite score (lower is better)
                score = (
                    metrics.get("cpu", 0) * 0.3
                    + metrics.get("memory", 0) * 0.2
                    + metrics.get("queue_size", 0) * 10
                    + metrics.get("response_time", 0) * 0.5
                )
                scores.append((score, pid))

            if not scores:
                return None

            # Return instance with lowest load
            scores.sort(key=lambda x: x[0])
            return scores[0][1]

    def update_metrics(self, pid: int, **metrics: object) -> None:
        """Update instance metrics.

        Args:
            pid: Process ID of the instance to update.
            **metrics: Arbitrary keyword arguments for metric values.

        """
        with self.lock:
            if pid in self.load_metrics:
                self.load_metrics[pid].update(metrics)

    def distribute_task(self, tool: ToolType, task: object) -> bool:
        """Distribute task to best instance.

        Args:
            tool: Type of tool to distribute task to.
            task: Task object to distribute.

        Returns:
            True if task was successfully queued, False otherwise.

        """
        pid = self.get_best_instance(tool)
        if not pid:
            return False

        # Add to task queue
        if tool in self.task_queues:
            self.task_queues[tool].put((pid, task))
            self.update_metrics(pid, queue_size=self.task_queues[tool].qsize())
            return True

        return False


class RealToolCommunicator:
    """Run communicator for real tool integration."""

    def __init__(self, name: str = "intellicrack") -> None:
        """Initialize the RealToolCommunicator with all required components.

        Args:
            name: Name for the communicator instance. Defaults to "intellicrack".

        """
        self.name = name
        self.shared_memory = SharedMemoryManager(f"{name}_shm")
        self.monitor = ToolMonitor()
        self.recovery = FailureRecovery()
        self.resolver = ConflictResolver()
        self.balancer = LoadBalancer()
        self.running = False
        self.message_handlers: dict[ToolType, Callable] = {}
        self.worker_thread: threading.Thread | None = None

    def register_tool(self, tool: ToolType, pid: int, handler: Callable | None = None) -> None:
        """Register a tool with the communicator.

        Args:
            tool: Type of tool to register.
            pid: Process ID of the tool instance.
            handler: Optional message handler callable.

        """
        self.monitor.register_tool(tool, pid)
        self.balancer.register_instance(tool, pid)

        if handler:
            self.message_handlers[tool] = handler
            self.recovery.add_recovery_handler(tool, handler)

        logger.info(f"Registered tool {tool.value} with PID {pid}")

    def start(self) -> None:
        """Start the communicator."""
        self.running = True
        self.monitor.start_monitoring()
        self.worker_thread = threading.Thread(target=self._message_loop)
        self.worker_thread.daemon = True
        self.worker_thread.start()
        logger.info("Tool communicator started")

    def _message_loop(self) -> None:
        """Run main message processing loop."""
        while self.running:
            try:
                # Read message from shared memory
                raw_message = self.shared_memory.read_message()
                if not raw_message:
                    time.sleep(0.001)  # Small delay to prevent CPU spinning
                    continue

                # Deserialize message
                message = SerializationProtocol.deserialize(raw_message)
                if not message:
                    continue

                # Process message
                self._process_message(message)

            except Exception as e:
                logger.error(f"Error in message loop: {e}")

    def _process_message(self, message: ToolMessage) -> None:
        """Process incoming message.

        Args:
            message: ToolMessage to process.

        """
        # Update heartbeat
        if message.message_type == MessageType.HEARTBEAT:
            self.monitor.update_status(message.source, last_heartbeat=time.time())
            return

        # Handle status updates
        if message.message_type == MessageType.STATUS:
            self.monitor.update_status(message.source, **message.data)
            return

        # Route to handler
        if message.destination in self.message_handlers:
            handler = self.message_handlers[message.destination]
            try:
                handler(message)
                self.monitor.update_status(
                    message.destination, success_count=self.monitor.get_status(message.destination).success_count + 1,
                )
            except Exception as e:
                logger.error(f"Handler failed for {message.destination.value}: {e}")
                self.monitor.update_status(message.destination, error_count=self.monitor.get_status(message.destination).error_count + 1)
                self.recovery.handle_failure(message, e)

    def send_message(self, message: ToolMessage) -> bool:
        """Send a message to a tool.

        Args:
            message: ToolMessage to send.

        Returns:
            True if message was successfully sent, False otherwise.

        """
        try:
            # Serialize message
            serialized = SerializationProtocol.serialize(message)

            # Write to shared memory
            success = self.shared_memory.write_message(serialized)

            if not success:
                self.recovery.handle_failure(message, Exception("Failed to write to shared memory"))

            return success

        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            self.recovery.handle_failure(message, e)
            return False

    def broadcast_message(self, source: ToolType, data: object, message_type: MessageType = MessageType.DATA) -> None:
        """Broadcast message to all tools.

        Args:
            source: Source tool type sending the broadcast.
            data: Data object to broadcast.
            message_type: Type of message to send. Defaults to DATA.

        """
        for tool in ToolType:
            if tool != source:
                message = ToolMessage(
                    source=source,
                    destination=tool,
                    message_type=message_type,
                    correlation_id=hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:16],
                    timestamp=time.time(),
                    data=data,
                    metadata={},
                )
                self.send_message(message)

    def resolve_conflicts(self, messages: list[ToolMessage], strategy: str = "confidence_based") -> object | None:
        """Resolve conflicts between tool results.

        Args:
            messages: List of conflicting ToolMessages.
            strategy: Resolution strategy name. Defaults to "confidence_based".

        Returns:
            Resolved result object, or None if resolution fails.

        """
        return self.resolver.resolve(messages, strategy)

    def get_tool_status(self, tool: ToolType) -> ToolStatus | None:
        """Get status of a specific tool.

        Args:
            tool: Type of tool to query status for.

        Returns:
            ToolStatus instance if tool is registered, None otherwise.

        """
        return self.monitor.get_status(tool)

    def get_all_status(self) -> dict[ToolType, ToolStatus]:
        """Get status of all tools.

        Returns:
            Dictionary mapping tool types to their status objects.

        """
        return self.monitor.get_all_status()

    def stop(self) -> None:
        """Stop the communicator."""
        self.running = False
        self.monitor.stop_monitoring()

        if self.worker_thread:
            self.worker_thread.join(timeout=5)

        self.shared_memory.close()
        logger.info("Tool communicator stopped")


def main() -> None:
    """Demonstrate example usage of real tool communication.

    Runs as either server or client mode based on command line arguments.
    Server mode monitors multiple tools, client mode sends heartbeats.

    """
    import argparse

    parser = argparse.ArgumentParser(description="Real Tool Communication System")
    parser.add_argument("--mode", choices=["server", "client"], default="server", help="Run as server or client")
    parser.add_argument("--tool", choices=[t.value for t in ToolType], default="ghidra", help="Tool type for client mode")
    parser.add_argument("--pid", type=int, default=os.getpid(), help="Process ID to register")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    if args.mode == "server":
        # Run as server
        communicator = RealToolCommunicator()

        # Register example tools
        communicator.register_tool(ToolType.GHIDRA, os.getpid())
        communicator.register_tool(ToolType.RADARE2, os.getpid() + 1)
        communicator.register_tool(ToolType.FRIDA, os.getpid() + 2)

        communicator.start()

        print("Tool Communication Server Started")
        print("Press Ctrl+C to stop")

        try:
            while True:
                # Print status
                status = communicator.get_all_status()
                print("\nTool Status:")
                for tool, stat in status.items():
                    print(f"  {tool.value}: {stat.status} (PID: {stat.pid})")

                time.sleep(5)

        except KeyboardInterrupt:
            print("\nStopping server...")
            communicator.stop()

    else:
        # Run as client
        tool_type = ToolType(args.tool)

        # Create communicator
        communicator = RealToolCommunicator()

        def message_handler(msg: ToolMessage) -> None:
            print(f"Received message: {msg.data}")

        communicator.register_tool(tool_type, args.pid, message_handler)
        communicator.start()

        print(f"Tool Client ({tool_type.value}) Started")
        print("Press Ctrl+C to stop")

        try:
            # Send periodic heartbeats
            while True:
                heartbeat = ToolMessage(
                    source=tool_type,
                    destination=tool_type,
                    message_type=MessageType.HEARTBEAT,
                    correlation_id=hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:16],
                    timestamp=time.time(),
                    data={},
                    metadata={},
                )
                communicator.send_message(heartbeat)
                time.sleep(10)

        except KeyboardInterrupt:
            print("\nStopping client...")
            communicator.stop()


if __name__ == "__main__":
    main()
