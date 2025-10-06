"""Resource Management Framework for Intellicrack.

Provides context managers and automatic cleanup for VMs, containers, processes,
and other system resources. Ensures proper resource cleanup even on errors.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import atexit
import contextlib
import os
import shutil
import socket
import subprocess
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from intellicrack.handlers.psutil_handler import psutil

from ...utils.logger import get_logger
from ..logging.audit_logger import get_audit_logger

logger = get_logger(__name__)
audit_logger = get_audit_logger()

try:
    from ..terminal_manager import get_terminal_manager

    HAS_TERMINAL_MANAGER = True
except ImportError:
    HAS_TERMINAL_MANAGER = False
    logger.warning("Terminal manager not available for resource manager")


class ResourceType(Enum):
    """Types of managed resources."""

    PROCESS = "process"
    VM = "virtual_machine"
    CONTAINER = "container"
    FILE = "file"
    NETWORK = "network"
    MEMORY = "memory"
    THREAD = "thread"
    LOCK = "lock"
    TEMP_DIR = "temp_directory"


class ResourceState(Enum):
    """States of managed resources."""

    CREATED = "created"
    ACTIVE = "active"
    IDLE = "idle"
    CLEANING = "cleaning"
    CLEANED = "cleaned"
    FAILED = "failed"


class ResourceUsage:
    """Track resource usage statistics."""

    def __init__(self):
        """Initialize resource usage statistics tracker."""
        self.cpu_percent = 0.0
        self.memory_mb = 0.0
        self.disk_io_mb = 0.0
        self.network_io_mb = 0.0
        self.start_time = datetime.now()
        self.last_update = datetime.now()

    def update(self, process: psutil.Process):
        """Update usage statistics from a process."""
        try:
            self.cpu_percent = process.cpu_percent(interval=0.1)
            self.memory_mb = process.memory_info().rss / (1024 * 1024)

            io_counters = process.io_counters()
            self.disk_io_mb = (io_counters.read_bytes + io_counters.write_bytes) / (1024 * 1024)

            self.last_update = datetime.now()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def get_duration(self) -> timedelta:
        """Get resource usage duration."""
        return datetime.now() - self.start_time


class ManagedResource:
    """Base class for managed resources."""

    def __init__(
        self,
        resource_id: str,
        resource_type: ResourceType,
        cleanup_func: Callable | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        """Initialize a managed resource.

        Args:
            resource_id: Unique identifier for the resource
            resource_type: Type of the resource
            cleanup_func: Function to call for cleanup
            metadata: Additional resource metadata

        """
        self.resource_id = resource_id
        self.resource_type = resource_type
        self.cleanup_func = cleanup_func
        self.metadata = metadata or {}
        self.state = ResourceState.CREATED
        self.usage = ResourceUsage()
        self.created_at = datetime.now()
        self.cleaned_at: datetime | None = None

    def cleanup(self):
        """Clean up the resource."""
        if self.state == ResourceState.CLEANED:
            return

        self.state = ResourceState.CLEANING

        try:
            if self.cleanup_func:
                self.cleanup_func()
            self.state = ResourceState.CLEANED
            self.cleaned_at = datetime.now()
            logger.info(f"Cleaned up {self.resource_type.value}: {self.resource_id}")
        except Exception as e:
            self.state = ResourceState.FAILED
            logger.error(f"Failed to cleanup {self.resource_type.value} {self.resource_id}: {e}")
            raise

    def __del__(self):
        """Ensure cleanup on deletion."""
        if self.state not in (ResourceState.CLEANED, ResourceState.CLEANING):
            try:
                self.cleanup()
            except Exception as e:
                logger.debug("Error during resource cleanup: %s", e)


class ProcessResource(ManagedResource):
    """Managed process resource."""

    def __init__(self, process: subprocess.Popen, command: str):
        """Initialize process resource.

        Args:
            process: The subprocess.Popen instance
            command: Command that started the process

        """
        self.process = process
        self.command = command
        self.psutil_process = None

        try:
            self.psutil_process = psutil.Process(process.pid)
        except psutil.NoSuchProcess:
            pass

        super().__init__(
            resource_id=str(process.pid),
            resource_type=ResourceType.PROCESS,
            cleanup_func=self._cleanup_process,
            metadata={"command": command},
        )

    def _cleanup_process(self):
        """Clean up the process."""
        if self.process.poll() is None:
            # Try graceful termination first
            try:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if termination fails
                    self.process.kill()
                    self.process.wait()
            except Exception as e:
                logger.error(f"Error terminating process {self.resource_id}: {e}")

    def update_usage(self):
        """Update resource usage statistics."""
        if self.psutil_process:
            self.usage.update(self.psutil_process)


class VMResource(ManagedResource):
    """Managed virtual machine resource."""

    def __init__(self, vm_name: str, vm_process: subprocess.Popen | None = None):
        """Initialize VM resource.

        Args:
            vm_name: Name of the virtual machine
            vm_process: Optional process managing the VM

        """
        self.vm_name = vm_name
        self.vm_process = vm_process

        super().__init__(
            resource_id=vm_name,
            resource_type=ResourceType.VM,
            cleanup_func=self._cleanup_vm,
            metadata={"vm_name": vm_name},
        )

    def _cleanup_vm(self):
        """Clean up the virtual machine."""
        # Use QEMU monitor command to shutdown gracefully
        try:
            subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                [  # noqa: S607
                    "qemu-system-x86_64",
                    "-monitor",
                    f"unix:/tmp/qemu-{self.vm_name}.sock,server,nowait",
                    "-qmp",
                    f"unix:/tmp/qemu-{self.vm_name}-qmp.sock,server,nowait",
                ],
                check=False,
                input=b'{"execute":"quit"}\n',
                timeout=10,
            )
        except Exception as e:
            logger.warning(f"Failed to shutdown VM {self.vm_name} gracefully: {e}")

        # Kill process if still running
        if self.vm_process and self.vm_process.poll() is None:
            self.vm_process.kill()

        # Log VM shutdown
        audit_logger.log_vm_operation("stop", self.vm_name, success=True)


class ResourceManager:
    """Main resource management class."""

    def __init__(
        self,
        max_processes: int = 50,
        max_vms: int = 5,
        max_containers: int = 20,
        max_memory_mb: int = 4096,
        cleanup_interval: int = 60,
    ):
        """Initialize the resource manager.

        Args:
            max_processes: Maximum number of managed processes
            max_vms: Maximum number of VMs
            max_containers: Maximum number of containers
            max_memory_mb: Maximum memory usage in MB
            cleanup_interval: Interval for cleanup checks in seconds

        """
        self.max_processes = max_processes
        self.max_vms = max_vms
        self.max_containers = max_containers
        self.max_memory_mb = max_memory_mb
        self.cleanup_interval = cleanup_interval

        # Resource tracking
        self._resources: dict[str, ManagedResource] = {}
        self._resources_by_type: dict[ResourceType, set[str]] = defaultdict(set)
        self._lock = threading.RLock()

        # Cleanup thread (skip during testing)
        if not (os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS")):
            self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            self._cleanup_thread.start()
            logger.info("Resource cleanup thread started")
        else:
            logger.info("Skipping resource cleanup thread (testing mode)")
            self._cleanup_thread = None

        # Register cleanup on exit
        atexit.register(self.cleanup_all)

        logger.info("Resource manager initialized")

    def _cleanup_loop(self):
        """Background cleanup thread."""
        while True:
            try:
                time.sleep(self.cleanup_interval)
                self._check_resource_limits()
                self._cleanup_stale_resources()
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")

    def _check_resource_limits(self):
        """Check and enforce resource limits."""
        with self._lock:
            # Check process limit
            process_ids = self._resources_by_type.get(ResourceType.PROCESS, set())
            if len(process_ids) > self.max_processes:
                logger.warning(f"Process limit exceeded: {len(process_ids)}/{self.max_processes}")

            # Check memory usage
            total_memory = 0
            for resource_id in self._resources:
                resource = self._resources[resource_id]
                if isinstance(resource, ProcessResource):
                    resource.update_usage()
                    total_memory += resource.usage.memory_mb

            if total_memory > self.max_memory_mb:
                logger.warning(f"Memory limit exceeded: {total_memory:.1f}/{self.max_memory_mb} MB")

    def _cleanup_stale_resources(self):
        """Clean up stale or dead resources."""
        with self._lock:
            stale_resources = []

            for resource_id, resource in self._resources.items():
                # Check if process resources are still alive
                if isinstance(resource, ProcessResource):
                    if resource.process.poll() is not None:
                        stale_resources.append(resource_id)

            for resource_id in stale_resources:
                self.release_resource(resource_id)

    def register_resource(self, resource: ManagedResource) -> str:
        """Register a resource for management.

        Args:
            resource: The resource to manage

        Returns:
            Resource ID

        """
        with self._lock:
            # Check limits
            resource_count = len(self._resources_by_type.get(resource.resource_type, set()))

            if resource.resource_type == ResourceType.PROCESS and resource_count >= self.max_processes:
                raise RuntimeError(f"Process limit reached: {self.max_processes}")
            if resource.resource_type == ResourceType.VM and resource_count >= self.max_vms:
                raise RuntimeError(f"VM limit reached: {self.max_vms}")
            if resource.resource_type == ResourceType.CONTAINER and resource_count >= self.max_containers:
                raise RuntimeError(f"Container limit reached: {self.max_containers}")

            # Register resource
            self._resources[resource.resource_id] = resource
            self._resources_by_type[resource.resource_type].add(resource.resource_id)
            resource.state = ResourceState.ACTIVE

            logger.debug(f"Registered {resource.resource_type.value}: {resource.resource_id}")

            return resource.resource_id

    def release_resource(self, resource_id: str):
        """Release and cleanup a resource.

        Args:
            resource_id: ID of the resource to release

        """
        with self._lock:
            resource = self._resources.get(resource_id)
            if not resource:
                return

            try:
                resource.cleanup()

                # Remove from tracking
                del self._resources[resource_id]
                self._resources_by_type[resource.resource_type].discard(resource_id)

            except Exception as e:
                logger.error(f"Error releasing resource {resource_id}: {e}")

    def get_resource(self, resource_id: str) -> ManagedResource | None:
        """Get a managed resource by ID.

        Args:
            resource_id: Resource ID

        Returns:
            ManagedResource or None

        """
        return self._resources.get(resource_id)

    @contextlib.contextmanager
    def managed_process(self, command: str | list[str], **kwargs):
        """Context manager for managed processes.

        Args:
            command: Command to execute
            **kwargs: Arguments for subprocess.Popen

        Yields:
            ProcessResource instance

        """
        # Start process
        if isinstance(command, str):
            kwargs["shell"] = True

        process = subprocess.Popen(command, **kwargs)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
        resource = ProcessResource(process, str(command))

        try:
            self.register_resource(resource)
            yield resource
        finally:
            self.release_resource(resource.resource_id)

    @contextlib.contextmanager
    def managed_vm(self, vm_name: str, vm_process: subprocess.Popen | None = None):
        """Context manager for managed VMs.

        Args:
            vm_name: Name of the VM
            vm_process: Optional process managing the VM

        Yields:
            VMResource instance

        """
        resource = VMResource(vm_name, vm_process)

        try:
            self.register_resource(resource)
            audit_logger.log_vm_operation("start", vm_name, success=True)
            yield resource
        finally:
            self.release_resource(resource.resource_id)

    @contextlib.contextmanager
    def temp_directory(self, prefix: str = "intellicrack_"):
        """Context manager for temporary directories.

        Args:
            prefix: Directory name prefix

        Yields:
            Path to temporary directory

        """
        import tempfile

        temp_dir = tempfile.mkdtemp(prefix=prefix)
        temp_path = Path(temp_dir)

        def cleanup_temp():
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.error(f"Failed to remove temp directory {temp_dir}: {e}")

        resource = ManagedResource(resource_id=temp_dir, resource_type=ResourceType.TEMP_DIR, cleanup_func=cleanup_temp)

        try:
            self.register_resource(resource)
            yield temp_path
        finally:
            self.release_resource(resource.resource_id)

    def cleanup_all(self):
        """Clean up all managed resources."""
        with self._lock:
            logger.info(f"Cleaning up {len(self._resources)} resources")

            # Copy resource IDs to avoid modification during iteration
            resource_ids = list(self._resources.keys())

            for resource_id in resource_ids:
                try:
                    self.release_resource(resource_id)
                except Exception as e:
                    logger.error(f"Error cleaning up resource {resource_id}: {e}")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup_all()
        if exc_type:
            logger.error(f"Exception in resource manager context: {exc_type.__name__}: {exc_val}")
        return False

    def get_resource_usage_stats(self) -> dict[str, Any]:
        """Get comprehensive resource usage statistics."""
        with self._lock:
            stats = {
                "total_resources": len(self._resources),
                "by_type": {},
                "by_status": {},
                "memory_usage": self._get_memory_usage(),
                "limits": {
                    "max_processes": self.max_processes,
                    "max_vms": self.max_vms,
                    "max_containers": self.max_containers,
                    "max_memory_mb": self.max_memory_mb,
                },
                "cleanup_interval": self.cleanup_interval,
            }

            # Count by type
            for resource_type, resource_ids in self._resources_by_type.items():
                stats["by_type"][resource_type.value] = len(resource_ids)

            # Count by status
            status_counts = {}
            for resource in self._resources.values():
                status = resource.status.value
                status_counts[status] = status_counts.get(status, 0) + 1
            stats["by_status"] = status_counts

            return stats

    def _get_memory_usage(self) -> dict[str, int]:
        """Get current memory usage."""
        try:
            from intellicrack.handlers.psutil_handler import psutil

            process = psutil.Process()
            return {
                "rss_mb": process.memory_info().rss // 1024 // 1024,
                "vms_mb": process.memory_info().vms // 1024 // 1024,
                "percent": process.memory_percent(),
            }
        except ImportError:
            return {"rss_mb": 0, "vms_mb": 0, "percent": 0.0}
        except Exception as e:
            logger.warning(f"Failed to get memory usage: {e}")
            return {"rss_mb": 0, "vms_mb": 0, "percent": 0.0}

    def force_cleanup_by_type(self, resource_type: ResourceType) -> int:
        """Force cleanup of all resources of a specific type."""
        cleaned_count = 0
        with self._lock:
            resource_ids = list(self._resources_by_type.get(resource_type, set()))
            for resource_id in resource_ids:
                if self._cleanup_resource(resource_id):
                    cleaned_count += 1

        logger.info(f"Force cleaned {cleaned_count} resources of type {resource_type.value}")
        return cleaned_count

    def force_cleanup_expired(self, max_age_seconds: int = 3600) -> int:
        """Force cleanup of resources older than specified age."""
        cleaned_count = 0
        current_time = time.time()

        with self._lock:
            resource_ids = list(self._resources.keys())
            for resource_id in resource_ids:
                resource = self._resources.get(resource_id)
                if resource and (current_time - resource.created_at) > max_age_seconds:
                    if self._cleanup_resource(resource_id):
                        cleaned_count += 1

        logger.info(f"Force cleaned {cleaned_count} expired resources (older than {max_age_seconds}s)")
        return cleaned_count

    def set_resource_limits(self, **limits):
        """Update resource limits dynamically."""
        with self._lock:
            if "max_processes" in limits:
                self.max_processes = limits["max_processes"]
            if "max_vms" in limits:
                self.max_vms = limits["max_vms"]
            if "max_containers" in limits:
                self.max_containers = limits["max_containers"]
            if "max_memory_mb" in limits:
                self.max_memory_mb = limits["max_memory_mb"]
            if "cleanup_interval" in limits:
                self.cleanup_interval = limits["cleanup_interval"]

        logger.info(f"Updated resource limits: {limits}")

    def get_resources_by_owner(self, owner: str) -> list[ManagedResource]:
        """Get all resources owned by a specific entity."""
        with self._lock:
            return [r for r in self._resources.values() if r.metadata.get("owner") == owner]

    def cleanup_by_owner(self, owner: str) -> int:
        """Cleanup all resources owned by a specific entity."""
        cleaned_count = 0
        owned_resources = self.get_resources_by_owner(owner)

        for resource in owned_resources:
            if self._cleanup_resource(resource.resource_id):
                cleaned_count += 1

        logger.info(f"Cleaned {cleaned_count} resources owned by {owner}")
        return cleaned_count

    def emergency_cleanup(self) -> dict[str, int]:
        """Emergency cleanup of all resources."""
        logger.warning("Performing emergency cleanup of all resources")

        results = {}
        for resource_type in ResourceType:
            results[resource_type.value] = self.force_cleanup_by_type(resource_type)

        # Force garbage collection
        import gc

        gc.collect()

        return results

    def health_check(self) -> dict[str, Any]:
        """Perform health check on resource manager."""
        health = {
            "status": "healthy",
            "issues": [],
            "warnings": [],
            "stats": self.get_resource_usage_stats(),
        }

        with self._lock:
            # Check for resource limits
            if len(self._resources_by_type.get(ResourceType.PROCESS, set())) > self.max_processes:
                health["issues"].append(
                    f"Process count exceeds limit: {len(self._resources_by_type.get(ResourceType.PROCESS, set()))} > {self.max_processes}",
                )

            if len(self._resources_by_type.get(ResourceType.VM, set())) > self.max_vms:
                health["issues"].append(
                    f"VM count exceeds limit: {len(self._resources_by_type.get(ResourceType.VM, set()))} > {self.max_vms}",
                )

            if len(self._resources_by_type.get(ResourceType.CONTAINER, set())) > self.max_containers:
                health["issues"].append(
                    f"Container count exceeds limit: {len(self._resources_by_type.get(ResourceType.CONTAINER, set()))} > {self.max_containers}",
                )

            # Check for stuck resources
            current_time = time.time()
            stuck_resources = []
            for resource in self._resources.values():
                if resource.status == ResourceState.CLEANING and (current_time - resource.created_at) > 300:  # 5 minutes
                    stuck_resources.append(resource.resource_id)

            if stuck_resources:
                health["warnings"].append(f"Found {len(stuck_resources)} stuck resources in cleanup state")

            # Check memory usage
            memory_stats = self._get_memory_usage()
            if memory_stats.get("rss_mb", 0) > self.max_memory_mb:
                health["issues"].append(
                    f"Memory usage exceeds limit: {memory_stats['rss_mb']}MB > {self.max_memory_mb}MB",
                )

            # Check cleanup thread (skip during testing)
            if self._cleanup_thread is not None and not self._cleanup_thread.is_alive():
                health["issues"].append("Cleanup thread is not running")

        if health["issues"]:
            health["status"] = "unhealthy"
        elif health["warnings"]:
            health["status"] = "degraded"

        return health


class ResourceContext:
    """Context manager for managing multiple resources together."""

    def __init__(self, resource_manager: ResourceManager, owner: str = None):
        """Initialize resource context.

        Args:
            resource_manager: Resource manager instance
            owner: Optional owner identifier for resources

        """
        self.resource_manager = resource_manager
        self.owner = owner or f"context_{int(time.time())}"
        self.managed_resources: list[str] = []
        self._entered = False

    def __enter__(self):
        """Enter resource context."""
        self._entered = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit resource context with cleanup."""
        if self._entered:
            self.cleanup_all()
        return False

    def register_resource(
        self,
        resource_type: ResourceType,
        resource_handle: Any,
        cleanup_func: Callable = None,
        metadata: dict = None,
    ) -> str:
        """Register a resource in this context."""
        if not self._entered:
            raise RuntimeError("ResourceContext must be used as a context manager")

        if metadata is None:
            metadata = {}
        metadata["owner"] = self.owner
        metadata["context_managed"] = True

        resource_id = self.resource_manager.register_resource(resource_type, resource_handle, cleanup_func, metadata)
        self.managed_resources.append(resource_id)
        return resource_id

    def cleanup_all(self):
        """Cleanup all resources in this context."""
        cleaned_count = 0
        for resource_id in self.managed_resources[:]:  # Copy list to avoid modification during iteration
            if self.resource_manager._cleanup_resource(resource_id):
                cleaned_count += 1
                self.managed_resources.remove(resource_id)

        logger.info(f"ResourceContext cleaned {cleaned_count} resources for owner {self.owner}")
        return cleaned_count

    def get_resource_count(self) -> int:
        """Get number of active resources in this context."""
        return len(self.managed_resources)


class AutoCleanupResource:
    """Automatic cleanup decorator for functions that create resources."""

    def __init__(self, resource_manager: ResourceManager, resource_type: ResourceType):
        """Initialize auto-cleanup decorator.

        Args:
            resource_manager: Resource manager instance
            resource_type: Type of resource being managed

        """
        self.resource_manager = resource_manager
        self.resource_type = resource_type

    def __call__(self, func):
        """Decorator that automatically manages resource cleanup."""

        def wrapper(*args, **kwargs):
            with ResourceContext(self.resource_manager, f"auto_{func.__name__}") as ctx:
                # Execute function
                result = func(*args, **kwargs)

                # If result is a resource handle, register it
                if result is not None:
                    ctx.register_resource(
                        self.resource_type,
                        result,
                        metadata={"function": func.__name__, "auto_managed": True},
                    )

                return result

        return wrapper


# Global resource manager instance
resource_manager = ResourceManager()


def create_resource_context(owner: str = None) -> ResourceContext:
    """Create a new resource context."""
    return ResourceContext(resource_manager, owner)


def auto_cleanup(resource_type: ResourceType):
    """Decorator for automatic resource cleanup."""
    return AutoCleanupResource(resource_manager, resource_type)

    def get_usage_stats(self) -> dict[str, Any]:
        """Get resource usage statistics.

        Returns:
            Dictionary with usage statistics

        """
        with self._lock:
            stats = {
                "total_resources": len(self._resources),
                "by_type": {},
                "total_memory_mb": 0,
                "total_cpu_percent": 0,
            }

            for resource_type in ResourceType:
                count = len(self._resources_by_type.get(resource_type, set()))
                if count > 0:
                    stats["by_type"][resource_type.value] = count

            # Calculate totals
            for resource in self._resources.values():
                if isinstance(resource, ProcessResource):
                    resource.update_usage()
                    stats["total_memory_mb"] += resource.usage.memory_mb
                    stats["total_cpu_percent"] += resource.usage.cpu_percent

            return stats

    def list_resources(self, resource_type: ResourceType | None = None) -> list[dict[str, Any]]:
        """List managed resources.

        Args:
            resource_type: Optional filter by resource type

        Returns:
            List of resource information dictionaries

        """
        with self._lock:
            resources = []

            for resource_id, resource in self._resources.items():
                if resource_type and resource.resource_type != resource_type:
                    continue

                info = {
                    "resource_id": resource_id,
                    "type": resource.resource_type.value,
                    "state": resource.state.value,
                    "created_at": resource.created_at.isoformat(),
                    "metadata": resource.metadata,
                }

                if isinstance(resource, ProcessResource):
                    resource.update_usage()
                    info["usage"] = {
                        "cpu_percent": resource.usage.cpu_percent,
                        "memory_mb": resource.usage.memory_mb,
                        "duration": str(resource.usage.get_duration()),
                    }

                resources.append(info)

            return resources


class FallbackHandler:
    """Handles fallback mechanisms for unavailable tools and dependencies."""

    def __init__(self):
        """Initialize fallback handler with tool alternatives."""
        self.fallback_registry = {}
        self.python_alternatives = {}
        self._setup_builtin_fallbacks()

    def _setup_builtin_fallbacks(self):
        """Setup built-in fallback mechanisms."""
        # Binary analysis fallbacks
        self.fallback_registry["strings"] = self._strings_fallback
        self.fallback_registry["file"] = self._file_type_fallback
        self.fallback_registry["objdump"] = self._objdump_fallback
        self.fallback_registry["readelf"] = self._readelf_fallback

        # Networking fallbacks
        self.fallback_registry["nmap"] = self._nmap_fallback
        self.fallback_registry["netstat"] = self._netstat_fallback

        # Virtualization fallbacks
        self.fallback_registry["qemu"] = self._qemu_fallback

        # Debugging fallbacks
        self.fallback_registry["gdb"] = self._gdb_fallback

        # Fuzzing fallbacks
        self.fallback_registry["afl++"] = self._afl_fallback

        # Python alternatives registry
        self.python_alternatives.update(
            {
                "strings": ["re module for pattern extraction"],
                "file": ["python-magic", "mimetypes module"],
                "objdump": ["pefile for PE files", "pyelftools for ELF files"],
                "readelf": ["pyelftools"],
                "nmap": ["socket module", "scapy for advanced networking"],
                "netstat": ["psutil.net_connections()"],
                "gdb": ["pdb for Python debugging"],
                "afl++": ["Custom fuzzing with random mutations"],
            },
        )

    def get_fallback(self, tool_name: str, *args, **kwargs):
        """Get fallback implementation for a tool."""
        if tool_name in self.fallback_registry:
            try:
                return self.fallback_registry[tool_name](*args, **kwargs)
            except Exception as e:
                logger.error(f"Fallback for {tool_name} failed: {e}")
                return None

        logger.warning(f"No fallback available for tool: {tool_name}")
        return None

    def _strings_fallback(self, binary_path: str, min_length: int = 4) -> list[str]:
        """Python-based strings extraction fallback."""
        try:
            strings = []
            with open(binary_path, "rb") as f:
                data = f.read()

            # Extract ASCII strings
            import re

            ascii_pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
            ascii_strings = re.findall(ascii_pattern, data)
            strings.extend([s.decode("ascii") for s in ascii_strings])

            # Extract Unicode strings
            unicode_pattern = rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode() + rb",}"
            unicode_strings = re.findall(unicode_pattern, data)
            strings.extend([s.decode("utf-16le", errors="ignore").rstrip("\x00") for s in unicode_strings])

            return list(set(strings))  # Remove duplicates

        except Exception as e:
            logger.error(f"Strings fallback failed: {e}")
            return []

    def _file_type_fallback(self, file_path: str) -> str:
        """Python-based file type detection fallback."""
        try:
            # Try python-magic first
            try:
                import magic

                return magic.from_file(file_path)
            except ImportError:
                pass

            # Fallback to basic detection
            import mimetypes

            mime_type, _ = mimetypes.guess_type(file_path)

            # Check PE signature
            with open(file_path, "rb") as f:
                header = f.read(1024)
                if header.startswith(b"MZ"):
                    f.seek(60)
                    pe_offset = int.from_bytes(f.read(4), byteorder="little")
                    f.seek(pe_offset)
                    if f.read(4) == b"PE\x00\x00":
                        return "PE32 executable"

                # Check ELF signature
                if header.startswith(b"\x7fELF"):
                    return "ELF executable"

                # Check other common formats
                if header.startswith(b"\x89PNG"):
                    return "PNG image"
                if header.startswith(b"GIF8"):
                    return "GIF image"
                if header.startswith(b"\xff\xd8\xff"):
                    return "JPEG image"

            return mime_type or "Unknown file type"

        except Exception as e:
            logger.error(f"File type fallback failed: {e}")
            return "Unknown file type"

    def _objdump_fallback(self, binary_path: str, options: list[str] = None) -> str:
        """Python-based objdump fallback using pefile/pyelftools."""
        try:
            result = []

            # Try PE analysis
            try:
                from intellicrack.handlers.pefile_handler import pefile

                pe = pefile.PE(binary_path)

                if "-h" in (options or []):
                    # Headers
                    result.append(f"File: {binary_path}")
                    result.append(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
                    result.append(f"Number of sections: {pe.FILE_HEADER.NumberOfSections}")
                    result.append(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")

                if "-S" in (options or []):
                    # Section headers
                    result.append("\nSections:")
                    for section in pe.sections:
                        section_name = section.Name.decode().rstrip(chr(0))
                        result.append(
                            f"  {section_name}: VA={hex(section.VirtualAddress)}, Size={hex(section.Misc_VirtualSize)}",
                        )

                return "\n".join(result)

            except ImportError:
                pass

            # Try ELF analysis
            try:
                from intellicrack.handlers.pyelftools_handler import HAS_PYELFTOOLS, ELFFile

                if not HAS_PYELFTOOLS:
                    raise ImportError("pyelftools not available")

                with open(binary_path, "rb") as f:
                    elf = ELFFile(f)

                    if "-h" in (options or []):
                        result.append(f"File: {binary_path}")
                        result.append(f"Class: {elf.get_machine_arch()}")
                        result.append(f"Type: {elf.header['e_type']}")

                    if "-S" in (options or []):
                        result.append("\nSections:")
                        for section in elf.iter_sections():
                            result.append(
                                f"  {section.name}: Offset={hex(section['sh_offset'])}, Size={hex(section['sh_size'])}",
                            )

                return "\n".join(result)

            except ImportError:
                pass

            return "objdump fallback: Install pefile or pyelftools for detailed analysis"

        except Exception as e:
            logger.error(f"objdump fallback failed: {e}")
            return f"objdump fallback error: {e}"

    def _readelf_fallback(self, binary_path: str, options: list[str] = None) -> str:
        """Python-based readelf fallback using pyelftools."""
        try:
            from intellicrack.handlers.pyelftools_handler import HAS_PYELFTOOLS, ELFFile

            if not HAS_PYELFTOOLS:
                raise ImportError("pyelftools not available")

            result = []
            with open(binary_path, "rb") as f:
                elf = ELFFile(f)

                if "-h" in (options or []):
                    # ELF header
                    header = elf.header
                    result.append("ELF Header:")
                    result.append(f"  Class: {header['e_ident']['EI_CLASS']}")
                    result.append(f"  Data: {header['e_ident']['EI_DATA']}")
                    result.append(f"  Type: {header['e_type']}")
                    result.append(f"  Machine: {header['e_machine']}")
                    result.append(f"  Entry point: {hex(header['e_entry'])}")

                if "-S" in (options or []):
                    # Section headers
                    result.append("\nSection Headers:")
                    for section in elf.iter_sections():
                        result.append(
                            f"  [{section.name}] Type={section['sh_type']} Addr={hex(section['sh_addr'])} Size={hex(section['sh_size'])}",
                        )

            return "\n".join(result)

        except ImportError:
            return "readelf fallback: Install pyelftools for ELF analysis"
        except Exception as e:
            logger.error(f"readelf fallback failed: {e}")
            return f"readelf fallback error: {e}"

    def _nmap_fallback(self, target: str, ports: str = None) -> dict[str, Any]:
        """Python-based network scanning fallback."""
        try:
            import socket
            from concurrent.futures import ThreadPoolExecutor, as_completed

            def scan_port(host, port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        result = sock.connect_ex((host, port))
                        return port, result == 0
                except Exception:
                    return port, False

            # Parse target
            host = target.split("/")[0]  # Remove CIDR if present

            # Parse ports
            if ports:
                port_list = []
                for port_range in ports.split(","):
                    if "-" in port_range:
                        start, end = map(int, port_range.split("-"))
                        port_list.extend(range(start, end + 1))
                    else:
                        port_list.append(int(port_range))
            else:
                # Common ports
                port_list = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]

            open_ports = []
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(scan_port, host, port) for port in port_list]
                for future in as_completed(futures):
                    port, is_open = future.result()
                    if is_open:
                        open_ports.append(port)

            return {
                "host": host,
                "open_ports": sorted(open_ports),
                "scanned_ports": len(port_list),
                "method": "python_fallback",
            }

        except Exception as e:
            logger.error(f"nmap fallback failed: {e}")
            return {"error": str(e)}

    def _netstat_fallback(self) -> list[dict[str, Any]]:
        """Python-based netstat fallback using psutil."""
        try:
            from intellicrack.handlers.psutil_handler import psutil

            connections = []
            for conn in psutil.net_connections():
                connections.append(
                    {
                        "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "status": conn.status,
                        "pid": conn.pid,
                    },
                )

            return connections

        except ImportError:
            return [{"error": "psutil not available for netstat fallback"}]
        except Exception as e:
            logger.error(f"netstat fallback failed: {e}")
            return [{"error": str(e)}]

    def _qemu_fallback(self, *args, **kwargs) -> dict[str, Any]:
        """QEMU fallback using alternative emulation."""
        return {
            "status": "fallback",
            "message": "QEMU not available. Consider using Docker for containerized analysis.",
            "alternatives": [
                "Docker containers for isolated execution",
                "VirtualBox for full virtualization",
                "VMware for enterprise environments",
            ],
        }

    def _gdb_fallback(self, *args, **kwargs) -> dict[str, Any]:
        """GDB fallback for debugging."""
        return {
            "status": "fallback",
            "message": "GDB not available. Using Python debugging alternatives.",
            "alternatives": [
                "Python pdb for Python code debugging",
                "Static analysis for binary inspection",
                "Process monitoring with psutil",
            ],
        }

    def _afl_fallback(self, *args, **kwargs) -> dict[str, Any]:
        """AFL++ fallback fuzzing implementation."""
        return {
            "status": "fallback",
            "message": "AFL++ not available. Using custom Python fuzzing.",
            "implementation": "custom_python_fuzzer",
            "features": [
                "Random byte mutations",
                "Dictionary-based fuzzing",
                "Coverage tracking via trace",
            ],
        }

    def register_fallback(self, tool_name: str, fallback_func: Callable):
        """Register a custom fallback function."""
        self.fallback_registry[tool_name] = fallback_func
        logger.info(f"Registered fallback for {tool_name}")

    def list_available_fallbacks(self) -> dict[str, list[str]]:
        """List all available fallbacks."""
        return {
            "builtin_fallbacks": list(self.fallback_registry.keys()),
            "python_alternatives": self.python_alternatives,
        }


# Global fallback handler
fallback_handler = FallbackHandler()


def get_fallback_handler() -> FallbackHandler:
    """Get the global fallback handler."""
    return fallback_handler


def execute_with_fallback(
    tool_name: str,
    primary_command: list[str],
    fallback_args: tuple = None,
    fallback_kwargs: dict = None,
):
    """Execute command with automatic fallback on failure."""
    try:
        # Try primary command first
        result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
            primary_command, check=False, capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return {"status": "success", "output": result.stdout, "method": "primary"}
        raise subprocess.CalledProcessError(result.returncode, primary_command, result.stderr)

    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning(f"Primary command failed for {tool_name}: {e}")

        # Try fallback
        fallback_result = fallback_handler.get_fallback(tool_name, *(fallback_args or ()), **(fallback_kwargs or {}))

        if fallback_result is not None:
            return {"status": "fallback", "output": fallback_result, "method": "fallback"}
        return {"status": "error", "error": str(e), "method": "none"}


def validate_external_dependencies() -> dict[str, Any]:
    """Validate external tool dependencies and suggest fallbacks."""
    try:
        from ..config.external_tools_config import external_tools_manager

        # Check all tools
        tool_status = external_tools_manager.check_all_tools(force_check=True)
        missing_required = external_tools_manager.get_missing_required_tools()

        validation_result = {
            "status": "success" if not missing_required else "warning",
            "missing_required_tools": missing_required,
            "all_tools_status": tool_status,
            "fallback_configs": {},
            "recommendations": [],
        }

        # Generate fallback configurations for missing tools
        if missing_required:
            validation_result["fallback_configs"] = external_tools_manager.create_fallback_configs()
            validation_result["recommendations"].extend(
                [f"Install missing required tool: {tool}" for tool in missing_required],
            )

        # Add installation recommendations
        for tool_name, status in tool_status.items():
            if status != external_tools_manager.tools[tool_name].status.AVAILABLE:
                install_script = external_tools_manager.get_installation_script(tool_name)
                if install_script:
                    validation_result["recommendations"].append(f"Install {tool_name}: {install_script.strip()}")

        return validation_result

    except ImportError as e:
        logger.warning(f"External tools configuration not available: {e}")
        return {
            "status": "error",
            "error": "External tools configuration module not found",
            "missing_required_tools": [],
            "all_tools_status": {},
            "fallback_configs": {},
            "recommendations": ["Ensure external_tools_config.py is properly installed"],
        }


def setup_resource_monitoring():
    """Setup comprehensive resource monitoring."""

    def log_resource_stats():
        """Periodic resource statistics logging."""
        try:
            stats = resource_manager.get_resource_usage_stats()
            health = resource_manager.health_check()

            logger.info(
                f"Resource stats: {stats['total_resources']} total, Memory: {stats['memory_usage'].get('rss_mb', 0)}MB",
            )

            if health["status"] != "healthy":
                logger.warning(f"Resource health: {health['status']} - Issues: {health['issues']}")

            # Log tool validation periodically
            validation = validate_external_dependencies()
            if validation["missing_required_tools"]:
                logger.warning(f"Missing required tools: {validation['missing_required_tools']}")

        except Exception as e:
            logger.error(f"Failed to log resource stats: {e}")

    # Start monitoring thread (skip during testing)
    import threading

    def monitoring_loop():
        while True:
            try:
                time.sleep(300)  # Log every 5 minutes
                log_resource_stats()
            except Exception as e:
                logger.error(f"Resource monitoring error: {e}")
                time.sleep(60)  # Wait before retrying

    if not (os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS")):
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitoring_thread.start()
        logger.info("Resource monitoring started")
    else:
        logger.info("Skipping resource monitoring thread (testing mode)")


# Initialize monitoring on module import
try:
    setup_resource_monitoring()
except Exception as e:
    logger.warning(f"Failed to setup resource monitoring: {e}")


# Global resource manager instance
_resource_manager: ResourceManager | None = None


def get_resource_manager() -> ResourceManager:
    """Get the global resource manager instance."""
    global _resource_manager
    if _resource_manager is None:
        _resource_manager = ResourceManager()
    return _resource_manager
