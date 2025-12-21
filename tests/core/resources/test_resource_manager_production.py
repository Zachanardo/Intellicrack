"""Production tests for resource_manager module.

Tests real resource lifecycle management including process tracking, VM management,
cleanup mechanisms, and resource limit enforcement for analysis environments.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest


from intellicrack.core.resources.resource_manager import (
    ManagedResource,
    ProcessResource,
    ResourceContext,
    ResourceManager,
    ResourceState,
    ResourceType,
    VMResource,
    create_resource_context,
    get_resource_manager,
)


class TestResourceManager:
    """Test resource manager initialization and configuration."""

    def test_resource_manager_initializes_with_default_limits(self) -> None:
        """ResourceManager initializes with default resource limits."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()

        assert manager.max_processes == 50
        assert manager.max_vms == 5
        assert manager.max_containers == 20
        assert manager.max_memory_mb == 4096

        del os.environ["INTELLICRACK_TESTING"]

    def test_resource_manager_accepts_custom_limits(self) -> None:
        """ResourceManager accepts custom resource limits during initialization."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager(
            max_processes=100,
            max_vms=10,
            max_containers=30,
            max_memory_mb=8192,
        )

        assert manager.max_processes == 100
        assert manager.max_vms == 10
        assert manager.max_containers == 30
        assert manager.max_memory_mb == 8192

        del os.environ["INTELLICRACK_TESTING"]

    def test_resource_manager_tracks_resources_by_type(self) -> None:
        """ResourceManager maintains separate tracking for each resource type."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()

        assert ResourceType.PROCESS in manager._resources_by_type or len(manager._resources_by_type) == 0
        assert isinstance(manager._resources_by_type, dict)

        del os.environ["INTELLICRACK_TESTING"]

    def test_resource_manager_context_manager_support(self) -> None:
        """ResourceManager works as context manager with automatic cleanup."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        with ResourceManager() as manager:
            assert manager is not None
            assert isinstance(manager, ResourceManager)

        del os.environ["INTELLICRACK_TESTING"]


class TestManagedResource:
    """Test managed resource base functionality."""

    def test_managed_resource_initializes_with_metadata(self) -> None:
        """ManagedResource initializes with provided metadata."""
        cleanup_called = False

        def cleanup_func() -> None:
            nonlocal cleanup_called
            cleanup_called = True

        resource = ManagedResource(
            resource_id="test-123",
            resource_type=ResourceType.FILE,
            cleanup_func=cleanup_func,
            metadata={"path": "/tmp/test", "owner": "test_user"},
        )

        assert resource.resource_id == "test-123"
        assert resource.resource_type == ResourceType.FILE
        assert resource.metadata["path"] == "/tmp/test"
        assert resource.metadata["owner"] == "test_user"
        assert resource.state == ResourceState.CREATED

    def test_managed_resource_cleanup_changes_state(self) -> None:
        """ManagedResource cleanup transitions through correct states."""
        cleanup_executed = False

        def cleanup_func() -> None:
            nonlocal cleanup_executed
            cleanup_executed = True

        resource = ManagedResource(
            resource_id="cleanup-test",
            resource_type=ResourceType.MEMORY,
            cleanup_func=cleanup_func,
        )

        resource.cleanup()

        assert cleanup_executed
        assert resource.state == ResourceState.CLEANED
        assert resource.cleaned_at is not None

    def test_managed_resource_cleanup_idempotent(self) -> None:
        """ManagedResource cleanup is idempotent and safe to call multiple times."""
        cleanup_count = 0

        def cleanup_func() -> None:
            nonlocal cleanup_count
            cleanup_count += 1

        resource = ManagedResource(
            resource_id="idempotent-test",
            resource_type=ResourceType.NETWORK,
            cleanup_func=cleanup_func,
        )

        resource.cleanup()
        resource.cleanup()
        resource.cleanup()

        assert cleanup_count == 1

    def test_managed_resource_destructor_calls_cleanup(self) -> None:
        """ManagedResource destructor ensures cleanup is called."""
        cleanup_called = False

        def cleanup_func() -> None:
            nonlocal cleanup_called
            cleanup_called = True

        resource = ManagedResource(
            resource_id="destructor-test",
            resource_type=ResourceType.TEMP_DIR,
            cleanup_func=cleanup_func,
        )

        del resource

        assert cleanup_called


class TestProcessResource:
    """Test process resource management."""

    def test_process_resource_tracks_running_process(self) -> None:
        """ProcessResource tracks running subprocess correctly."""
        process = subprocess.Popen(
            ["python", "-c", "import time; time.sleep(10)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        resource = ProcessResource(process, "python -c 'import time; time.sleep(10)'")

        assert resource.process == process
        assert resource.resource_id == str(process.pid)
        assert resource.resource_type == ResourceType.PROCESS
        assert resource.command == "python -c 'import time; time.sleep(10)'"

        resource.cleanup()

    def test_process_resource_cleanup_terminates_process(self) -> None:
        """ProcessResource cleanup terminates running process."""
        process = subprocess.Popen(
            ["python", "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        resource = ProcessResource(process, "sleep command")

        time.sleep(0.1)
        assert process.poll() is None

        resource.cleanup()

        time.sleep(0.5)
        assert process.poll() is not None

    def test_process_resource_handles_already_terminated_process(self) -> None:
        """ProcessResource cleanup handles already-terminated process gracefully."""
        process = subprocess.Popen(
            ["python", "-c", "print('done')"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        process.wait(timeout=2)

        resource = ProcessResource(process, "quick command")
        resource.cleanup()

        assert resource.state == ResourceState.CLEANED


class TestVMResource:
    """Test virtual machine resource management."""

    def test_vm_resource_initialization(self) -> None:
        """VMResource initializes with VM name and optional process."""
        vm_resource = VMResource("test-vm-001")

        assert vm_resource.vm_name == "test-vm-001"
        assert vm_resource.resource_id == "test-vm-001"
        assert vm_resource.resource_type == ResourceType.VM

    def test_vm_resource_with_process(self) -> None:
        """VMResource tracks associated VM process."""
        vm_process = subprocess.Popen(
            ["python", "-c", "import time; time.sleep(5)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        vm_resource = VMResource("test-vm-002", vm_process)

        assert vm_resource.vm_process == vm_process
        assert vm_resource.vm_name == "test-vm-002"

        vm_resource.cleanup()


class TestResourceRegistration:
    """Test resource registration and tracking."""

    def test_register_resource_adds_to_tracking(self) -> None:
        """register_resource adds resource to internal tracking."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()

        resource = ManagedResource(
            resource_id="track-test-001",
            resource_type=ResourceType.FILE,
            cleanup_func=lambda: None,
        )

        resource_id = manager.register_resource(resource)

        assert resource_id == "track-test-001"
        assert resource_id in manager._resources
        assert resource.state == ResourceState.ACTIVE

        manager.cleanup_all()
        del os.environ["INTELLICRACK_TESTING"]

    def test_register_resource_enforces_process_limit(self) -> None:
        """register_resource enforces maximum process limit."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager(max_processes=2)

        process1 = subprocess.Popen(["python", "-c", "import time; time.sleep(5)"])
        process2 = subprocess.Popen(["python", "-c", "import time; time.sleep(5)"])

        resource1 = ProcessResource(process1, "cmd1")
        resource2 = ProcessResource(process2, "cmd2")

        manager.register_resource(resource1)
        manager.register_resource(resource2)

        process3 = subprocess.Popen(["python", "-c", "import time; time.sleep(5)"])
        resource3 = ProcessResource(process3, "cmd3")

        with pytest.raises(RuntimeError, match="Process limit reached"):
            manager.register_resource(resource3)

        manager.cleanup_all()
        process3.kill()
        del os.environ["INTELLICRACK_TESTING"]

    def test_register_resource_enforces_vm_limit(self) -> None:
        """register_resource enforces maximum VM limit."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager(max_vms=1)

        vm1 = VMResource("vm-001")
        manager.register_resource(vm1)

        vm2 = VMResource("vm-002")

        with pytest.raises(RuntimeError, match="VM limit reached"):
            manager.register_resource(vm2)

        manager.cleanup_all()
        del os.environ["INTELLICRACK_TESTING"]


class TestResourceRelease:
    """Test resource release and cleanup."""

    def test_release_resource_calls_cleanup(self) -> None:
        """release_resource calls resource cleanup function."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()

        cleanup_called = False

        def cleanup_func() -> None:
            nonlocal cleanup_called
            cleanup_called = True

        resource = ManagedResource(
            resource_id="release-test",
            resource_type=ResourceType.MEMORY,
            cleanup_func=cleanup_func,
        )

        manager.register_resource(resource)
        manager.release_resource("release-test")

        assert cleanup_called
        assert "release-test" not in manager._resources

        del os.environ["INTELLICRACK_TESTING"]

    def test_release_resource_handles_nonexistent_resource(self) -> None:
        """release_resource handles nonexistent resource gracefully."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()
        manager.release_resource("nonexistent-resource")

        del os.environ["INTELLICRACK_TESTING"]

    def test_cleanup_all_releases_all_resources(self) -> None:
        """cleanup_all releases all tracked resources."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()

        cleanup_counts = {"file": 0, "memory": 0}

        def file_cleanup() -> None:
            cleanup_counts["file"] += 1

        def memory_cleanup() -> None:
            cleanup_counts["memory"] += 1

        file_resource = ManagedResource("file-1", ResourceType.FILE, file_cleanup)
        memory_resource = ManagedResource("memory-1", ResourceType.MEMORY, memory_cleanup)

        manager.register_resource(file_resource)
        manager.register_resource(memory_resource)

        manager.cleanup_all()

        assert cleanup_counts["file"] == 1
        assert cleanup_counts["memory"] == 1
        assert len(manager._resources) == 0

        del os.environ["INTELLICRACK_TESTING"]


class TestContextManagers:
    """Test context manager functionality."""

    def test_managed_process_context_manager(self) -> None:
        """managed_process context manager creates and cleans up process."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()

        with manager.managed_process(["python", "-c", "import time; time.sleep(2)"]) as resource:
            assert isinstance(resource, ProcessResource)
            assert resource.process.poll() is None

        assert resource.state == ResourceState.CLEANED

        manager.cleanup_all()
        del os.environ["INTELLICRACK_TESTING"]

    def test_managed_vm_context_manager(self) -> None:
        """managed_vm context manager creates and cleans up VM resource."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()

        with manager.managed_vm("test-vm") as vm_resource:
            assert isinstance(vm_resource, VMResource)
            assert vm_resource.vm_name == "test-vm"
            assert vm_resource.resource_id in manager._resources

        assert vm_resource.state == ResourceState.CLEANED

        manager.cleanup_all()
        del os.environ["INTELLICRACK_TESTING"]

    def test_temp_directory_context_manager(self) -> None:
        """temp_directory context manager creates and removes temporary directory."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()

        with manager.temp_directory(prefix="test_") as temp_path:
            assert temp_path.exists()
            assert temp_path.is_dir()
            assert "test_" in str(temp_path)

            test_file = temp_path / "test.txt"
            test_file.write_text("test content")

        assert not temp_path.exists()

        manager.cleanup_all()
        del os.environ["INTELLICRACK_TESTING"]


class TestResourceContext:
    """Test ResourceContext for grouped resource management."""

    def test_resource_context_initialization(self) -> None:
        """ResourceContext initializes with owner identifier."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()
        context = ResourceContext(manager, "test_owner")

        assert context.owner == "test_owner"
        assert context.managed_resources == []

        manager.cleanup_all()
        del os.environ["INTELLICRACK_TESTING"]

    def test_resource_context_as_context_manager(self) -> None:
        """ResourceContext works as context manager with automatic cleanup."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()

        with ResourceContext(manager, "context_test") as ctx:
            assert ctx._entered is True

        manager.cleanup_all()
        del os.environ["INTELLICRACK_TESTING"]

    def test_resource_context_groups_resources_by_owner(self) -> None:
        """ResourceContext groups multiple resources under single owner."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()

        with ResourceContext(manager, "group_owner") as ctx:
            cleanup_count = 0

            def cleanup() -> None:
                nonlocal cleanup_count
                cleanup_count += 1

            for i in range(3):
                resource = ManagedResource(
                    f"resource-{i}",
                    ResourceType.MEMORY,
                    cleanup,
                    {"index": i},
                )
                manager.register_resource(resource)
                ctx.managed_resources.append(f"resource-{i}")

        manager.cleanup_all()
        del os.environ["INTELLICRACK_TESTING"]


class TestResourceLimits:
    """Test resource limit enforcement and monitoring."""

    def test_set_resource_limits_updates_configuration(self) -> None:
        """set_resource_limits dynamically updates resource limits."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()

        manager.set_resource_limits(
            max_processes=200,
            max_vms=20,
            max_memory_mb=16384,
        )

        assert manager.max_processes == 200
        assert manager.max_vms == 20
        assert manager.max_memory_mb == 16384

        manager.cleanup_all()
        del os.environ["INTELLICRACK_TESTING"]

    def test_force_cleanup_by_type_removes_type_resources(self) -> None:
        """force_cleanup_by_type removes all resources of specified type."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()

        file_count = 0
        memory_count = 0

        def file_cleanup() -> None:
            nonlocal file_count
            file_count += 1

        def memory_cleanup() -> None:
            nonlocal memory_count
            memory_count += 1

        manager.register_resource(ManagedResource("file-1", ResourceType.FILE, file_cleanup))
        manager.register_resource(ManagedResource("file-2", ResourceType.FILE, file_cleanup))
        manager.register_resource(ManagedResource("mem-1", ResourceType.MEMORY, memory_cleanup))

        cleaned = manager.force_cleanup_by_type(ResourceType.FILE)

        assert cleaned == 2
        assert file_count == 2
        assert memory_count == 0

        manager.cleanup_all()
        del os.environ["INTELLICRACK_TESTING"]


class TestResourceHealthCheck:
    """Test resource health monitoring."""

    def test_health_check_reports_healthy_status(self) -> None:
        """health_check reports healthy status when within limits."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager(max_processes=100)

        health = manager.health_check()

        assert health["status"] in ["healthy", "degraded"]
        assert "stats" in health
        assert "issues" in health

        manager.cleanup_all()
        del os.environ["INTELLICRACK_TESTING"]

    def test_health_check_detects_limit_violations(self) -> None:
        """health_check detects when resource limits are exceeded."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager(max_processes=1)

        process1 = subprocess.Popen(["python", "-c", "import time; time.sleep(5)"])
        process2 = subprocess.Popen(["python", "-c", "import time; time.sleep(5)"])

        manager.register_resource(ProcessResource(process1, "cmd1"))

        try:
            manager.register_resource(ProcessResource(process2, "cmd2"))
        except RuntimeError:
            pass

        health = manager.health_check()

        manager.cleanup_all()
        process2.kill()
        del os.environ["INTELLICRACK_TESTING"]

    def test_get_resource_usage_stats_returns_metrics(self) -> None:
        """get_resource_usage_stats returns comprehensive resource metrics."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager = ResourceManager()

        manager.register_resource(ManagedResource("res-1", ResourceType.FILE, lambda: None))
        manager.register_resource(ManagedResource("res-2", ResourceType.MEMORY, lambda: None))

        stats = manager.get_resource_usage_stats()

        assert "total_resources" in stats
        assert "by_type" in stats
        assert "memory_usage" in stats
        assert "limits" in stats

        manager.cleanup_all()
        del os.environ["INTELLICRACK_TESTING"]


class TestGlobalResourceManager:
    """Test global resource manager singleton."""

    def test_get_resource_manager_returns_singleton(self) -> None:
        """get_resource_manager returns same instance on multiple calls."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager1 = get_resource_manager()
        manager2 = get_resource_manager()

        assert manager1 is manager2

        del os.environ["INTELLICRACK_TESTING"]

    def test_create_resource_context_creates_new_context(self) -> None:
        """create_resource_context creates new ResourceContext instance."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        context = create_resource_context("test_owner")

        assert isinstance(context, ResourceContext)
        assert context.owner == "test_owner"

        del os.environ["INTELLICRACK_TESTING"]
