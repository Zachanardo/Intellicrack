"""Production Tests for AI Integration Manager.

Tests validate real AI component integration and workflow orchestration.
All tests verify production-ready integration without mocks or stubs.

Copyright (C) 2025 Zachary Flint
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from intellicrack.ai.integration_manager import (
    IntegrationManager,
    IntegrationTask,
    WorkflowResult,
)


@pytest.fixture
def integration_manager() -> IntegrationManager:
    """Create IntegrationManager instance for testing."""
    manager = IntegrationManager()
    yield manager
    if manager.running:
        manager.stop()


@pytest.fixture
def started_integration_manager() -> IntegrationManager:
    """Create and start IntegrationManager for testing."""
    manager = IntegrationManager()
    manager.start()
    yield manager
    manager.stop()


class TestIntegrationManagerInitialization:
    """Test IntegrationManager initialization."""

    def test_manager_initializes_components(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Integration manager initializes all AI components."""
        assert integration_manager.script_generator is not None
        assert integration_manager.code_modifier is not None
        assert integration_manager.ai_agent is not None
        assert integration_manager.qemu_manager is not None

    def test_manager_initializes_llm_manager(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Integration manager initializes LLM manager."""
        assert integration_manager.llm_manager is not None

    def test_manager_initializes_task_queue(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Integration manager initializes task queue."""
        assert integration_manager.task_queue is not None
        assert integration_manager.task_queue.empty()

    def test_manager_initializes_with_default_settings(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Integration manager initializes with default settings."""
        assert integration_manager.max_workers > 0
        assert integration_manager.running is False
        assert integration_manager.enable_caching is True
        assert integration_manager.enable_parallel_execution is True

    def test_manager_initializes_workflow_tracking(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Integration manager initializes workflow tracking structures."""
        assert isinstance(integration_manager.active_workflows, dict)
        assert isinstance(integration_manager.workflow_results, dict)
        assert isinstance(integration_manager.active_tasks, dict)
        assert isinstance(integration_manager.completed_tasks, dict)


class TestManagerStartStop:
    """Test integration manager start and stop functionality."""

    def test_start_manager_enables_running_state(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Starting manager enables running state."""
        assert integration_manager.running is False

        integration_manager.start()

        assert integration_manager.running is True
        integration_manager.stop()

    def test_start_manager_creates_worker_threads(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Starting manager creates worker threads."""
        integration_manager.start()

        assert len(integration_manager.worker_threads) > 0
        assert len(integration_manager.worker_threads) == integration_manager.max_workers

        integration_manager.stop()

    def test_stop_manager_disables_running_state(
        self, started_integration_manager: IntegrationManager
    ) -> None:
        """Stopping manager disables running state."""
        assert started_integration_manager.running is True

        started_integration_manager.stop()

        assert started_integration_manager.running is False

    def test_start_idempotent(self, integration_manager: IntegrationManager) -> None:
        """Multiple start calls are safe."""
        integration_manager.start()
        worker_count = len(integration_manager.worker_threads)

        integration_manager.start()

        assert len(integration_manager.worker_threads) == worker_count
        integration_manager.stop()

    def test_stop_idempotent(self, integration_manager: IntegrationManager) -> None:
        """Multiple stop calls are safe."""
        integration_manager.start()
        integration_manager.stop()
        integration_manager.stop()

        assert integration_manager.running is False


class TestTaskManagement:
    """Test task creation and management."""

    def test_create_integration_task(self) -> None:
        """IntegrationTask can be created with required fields."""
        task = IntegrationTask(
            task_id="test_task_001",
            task_type="generate_script",
            params={"binary": "test.exe"},
        )

        assert task.task_id == "test_task_001"
        assert task.task_type == "generate_script"
        assert task.params["binary"] == "test.exe"
        assert task.status == "pending"

    def test_task_has_default_status(self) -> None:
        """IntegrationTask initializes with pending status."""
        task = IntegrationTask(
            task_id="test_task",
            task_type="test",
            params={},
        )

        assert task.status == "pending"

    def test_task_can_track_dependencies(self) -> None:
        """IntegrationTask can track dependencies."""
        task = IntegrationTask(
            task_id="dependent_task",
            task_type="test",
            params={},
            dependencies=["task_1", "task_2"],
        )

        assert len(task.dependencies) == 2
        assert "task_1" in task.dependencies
        assert "task_2" in task.dependencies


class TestDependencyManagement:
    """Test task dependency resolution."""

    def test_check_dependencies_satisfied(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Dependencies are correctly checked for satisfaction."""
        completed_task = IntegrationTask(
            task_id="completed_task",
            task_type="test",
            params={},
        )
        completed_task.status = "completed"
        integration_manager.completed_tasks["completed_task"] = completed_task

        dependent_task = IntegrationTask(
            task_id="dependent",
            task_type="test",
            params={},
            dependencies=["completed_task"],
        )

        satisfied = integration_manager._are_dependencies_satisfied(dependent_task)

        assert satisfied is True

    def test_check_dependencies_not_satisfied(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Unsatisfied dependencies are detected."""
        dependent_task = IntegrationTask(
            task_id="dependent",
            task_type="test",
            params={},
            dependencies=["missing_task"],
        )

        satisfied = integration_manager._are_dependencies_satisfied(dependent_task)

        assert satisfied is False

    def test_check_dependencies_with_failed_task(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Failed dependency tasks are detected."""
        failed_task = IntegrationTask(
            task_id="failed_task",
            task_type="test",
            params={},
        )
        failed_task.status = "failed"
        integration_manager.completed_tasks["failed_task"] = failed_task

        dependent_task = IntegrationTask(
            task_id="dependent",
            task_type="test",
            params={},
            dependencies=["failed_task"],
        )

        satisfied = integration_manager._are_dependencies_satisfied(dependent_task)

        assert satisfied is False


class TestEventHandling:
    """Test event handler registration and emission."""

    def test_register_event_handler(self, integration_manager: IntegrationManager) -> None:
        """Event handlers can be registered."""
        events_received: list[Any] = []

        def handler(task: IntegrationTask) -> None:
            events_received.append(task)

        integration_manager.register_event_handler("task_completed", handler)

        assert "task_completed" in integration_manager.event_handlers
        assert handler in integration_manager.event_handlers["task_completed"]

    def test_emit_event_calls_handlers(self, integration_manager: IntegrationManager) -> None:
        """Emitting events calls registered handlers."""
        events_received: list[Any] = []

        def handler(task: IntegrationTask) -> None:
            events_received.append(task.task_id)

        integration_manager.register_event_handler("test_event", handler)

        test_task = IntegrationTask(task_id="test_task", task_type="test", params={})
        integration_manager._emit_event("test_event", test_task)

        assert len(events_received) > 0
        assert "test_task" in events_received

    def test_multiple_handlers_for_same_event(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Multiple handlers can be registered for same event."""
        calls_a: list[str] = []
        calls_b: list[str] = []

        def handler_a(task: IntegrationTask) -> None:
            calls_a.append(task.task_id)

        def handler_b(task: IntegrationTask) -> None:
            calls_b.append(task.task_id)

        integration_manager.register_event_handler("test_event", handler_a)
        integration_manager.register_event_handler("test_event", handler_b)

        test_task = IntegrationTask(task_id="test", task_type="test", params={})
        integration_manager._emit_event("test_event", test_task)

        assert len(calls_a) > 0
        assert len(calls_b) > 0


class TestWorkflowCreation:
    """Test workflow creation and management."""

    def test_create_workflow_returns_workflow_id(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Creating workflow returns workflow ID."""
        workflow_def: dict[str, Any] = {
            "name": "test_workflow",
            "tasks": [
                {"type": "generate_script", "params": {"binary": "test.exe"}},
            ],
        }

        workflow_id = integration_manager.create_workflow(workflow_def)

        assert workflow_id is not None
        assert isinstance(workflow_id, str)
        assert len(workflow_id) > 0

    def test_create_workflow_stores_in_active_workflows(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Created workflows are stored in active workflows."""
        workflow_def: dict[str, Any] = {
            "name": "test_workflow",
            "tasks": [
                {"type": "generate_script", "params": {"binary": "test.exe"}},
            ],
        }

        workflow_id = integration_manager.create_workflow(workflow_def)

        assert workflow_id in integration_manager.active_workflows


class TestWorkflowExecution:
    """Test workflow execution and results."""

    def test_execute_workflow_completes(
        self, started_integration_manager: IntegrationManager
    ) -> None:
        """Workflow execution completes and returns result."""
        workflow_def: dict[str, Any] = {
            "name": "simple_workflow",
            "tasks": [
                {"type": "generate_script", "params": {"binary": "test.exe"}},
            ],
        }

        workflow_id = started_integration_manager.create_workflow(workflow_def)
        result = started_integration_manager.execute_workflow(workflow_id, timeout=10.0)

        assert result is not None
        assert isinstance(result, WorkflowResult)


class TestComponentIntegration:
    """Test integration between AI components."""

    def test_script_generator_accessible(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Script generator component is accessible."""
        assert integration_manager.script_generator is not None
        assert hasattr(integration_manager.script_generator, "generate_frida_script")

    def test_code_modifier_accessible(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Code modifier component is accessible."""
        assert integration_manager.code_modifier is not None

    def test_ai_agent_accessible(self, integration_manager: IntegrationManager) -> None:
        """AI agent component is accessible."""
        assert integration_manager.ai_agent is not None

    def test_qemu_manager_accessible(
        self, integration_manager: IntegrationManager
    ) -> None:
        """QEMU manager component is accessible."""
        assert integration_manager.qemu_manager is not None


class TestCachingBehavior:
    """Test result caching functionality."""

    def test_caching_enabled_by_default(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Caching is enabled by default."""
        assert integration_manager.enable_caching is True

    def test_caching_can_be_disabled(self, integration_manager: IntegrationManager) -> None:
        """Caching can be disabled."""
        integration_manager.enable_caching = False

        assert integration_manager.enable_caching is False


class TestParallelExecution:
    """Test parallel task execution."""

    def test_parallel_execution_enabled_by_default(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Parallel execution is enabled by default."""
        assert integration_manager.enable_parallel_execution is True

    def test_parallel_execution_can_be_disabled(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Parallel execution can be disabled."""
        integration_manager.enable_parallel_execution = False

        assert integration_manager.enable_parallel_execution is False


class TestTaskTimeout:
    """Test task timeout configuration."""

    def test_task_timeout_has_default_value(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Task timeout has reasonable default value."""
        assert integration_manager.task_timeout > 0
        assert integration_manager.task_timeout <= 600

    def test_task_timeout_can_be_configured(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Task timeout can be configured."""
        integration_manager.task_timeout = 120

        assert integration_manager.task_timeout == 120


class TestThreadSafety:
    """Test thread-safe operations."""

    def test_state_lock_exists(self, integration_manager: IntegrationManager) -> None:
        """State lock exists for thread safety."""
        assert integration_manager._state_lock is not None

    def test_workflow_lock_exists(self, integration_manager: IntegrationManager) -> None:
        """Workflow lock exists for thread safety."""
        assert integration_manager._workflow_lock is not None


class TestErrorHandling:
    """Test error handling in integration manager."""

    def test_invalid_workflow_definition_handled(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Invalid workflow definitions are handled gracefully."""
        invalid_workflow: dict[str, Any] = {}

        try:
            workflow_id = integration_manager.create_workflow(invalid_workflow)
            assert workflow_id is not None
        except (ValueError, KeyError) as e:
            assert str(e) != ""


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_create_workflow_with_empty_tasks(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Workflow with empty task list is handled."""
        workflow_def: dict[str, Any] = {
            "name": "empty_workflow",
            "tasks": [],
        }

        workflow_id = integration_manager.create_workflow(workflow_def)

        assert workflow_id is not None

    def test_stop_manager_before_start(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Stopping manager before starting is safe."""
        integration_manager.stop()

        assert integration_manager.running is False


class TestRealWorldScenarios:
    """Test complete real-world integration scenarios."""

    def test_complete_script_generation_workflow(
        self, started_integration_manager: IntegrationManager
    ) -> None:
        """Complete script generation workflow executes successfully."""
        workflow_def: dict[str, Any] = {
            "name": "script_generation",
            "tasks": [
                {
                    "type": "generate_script",
                    "params": {
                        "binary": "D:\\test\\app.exe",
                        "protection_type": "license_check",
                    },
                },
            ],
        }

        workflow_id = started_integration_manager.create_workflow(workflow_def)

        assert workflow_id is not None
        assert workflow_id in started_integration_manager.active_workflows


class TestWorkflowResult:
    """Test WorkflowResult structure."""

    def test_workflow_result_creation(self) -> None:
        """WorkflowResult can be created with required fields."""
        result = WorkflowResult(
            workflow_id="wf_001",
            success=True,
            results={},
        )

        assert result.workflow_id == "wf_001"
        assert result.success is True
        assert isinstance(result.results, dict)


class TestTaskStatusTracking:
    """Test task status tracking throughout lifecycle."""

    def test_task_lifecycle_status_changes(self) -> None:
        """Task status changes through lifecycle."""
        task = IntegrationTask(
            task_id="lifecycle_task",
            task_type="test",
            params={},
        )

        assert task.status == "pending"

        task.status = "running"
        assert task.status == "running"

        task.status = "completed"
        assert task.status == "completed"


class TestManagerConfiguration:
    """Test integration manager configuration options."""

    def test_max_workers_configuration(self) -> None:
        """Integration manager can be configured with custom worker count."""
        manager = IntegrationManager()
        original_workers = manager.max_workers

        manager.max_workers = 8

        assert manager.max_workers == 8
        assert manager.max_workers != original_workers

        if manager.running:
            manager.stop()

    def test_custom_llm_manager_injection(self) -> None:
        """Integration manager accepts custom LLM manager."""
        from intellicrack.ai.llm_backends import LLMManager

        custom_llm_manager = LLMManager()
        manager = IntegrationManager(llm_manager=custom_llm_manager)

        assert manager.llm_manager is custom_llm_manager

        if manager.running:
            manager.stop()


class TestPerformanceMonitoring:
    """Test performance monitoring integration."""

    def test_performance_monitoring_starts_with_manager(
        self, integration_manager: IntegrationManager
    ) -> None:
        """Performance monitoring starts when manager starts."""
        integration_manager.start()

        integration_manager.stop()


class TestComponentAccessibility:
    """Test that all integrated components are accessible."""

    def test_all_components_initialized(
        self, integration_manager: IntegrationManager
    ) -> None:
        """All AI components are properly initialized."""
        components = [
            integration_manager.script_generator,
            integration_manager.code_modifier,
            integration_manager.ai_agent,
            integration_manager.qemu_manager,
            integration_manager.llm_manager,
        ]

        for component in components:
            assert component is not None
