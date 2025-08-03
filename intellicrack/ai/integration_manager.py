"""Integration Manager for AI Components

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

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from queue import Empty, Queue
from typing import Any

from ..utils.logger import get_logger
from .ai_script_generator import AIScriptGenerator, ScriptGenerationResult
from .autonomous_agent import AutonomousAgent
from .intelligent_code_modifier import IntelligentCodeModifier
from .llm_backends import LLMManager
from .performance_monitor import performance_monitor, profile_ai_operation

logger = get_logger(__name__)

# Import QEMU Test Manager with fallback
try:
    from .qemu_test_manager import QEMUTestManager
except ImportError:
    logger.warning("QEMUTestManager not available")

    class QEMUTestManager:
        """Fallback QEMUTestManager when real implementation not available."""

        def __init__(self, *_args, **_kwargs):
            """Initialize the fallback QEMU test manager.

            Args:
                *_args: Ignored positional arguments
                **_kwargs: Ignored keyword arguments

            """
            logger.warning("QEMUTestManager fallback initialized")

        def test_script_in_vm(self, script, target_binary, vm_config=None):
            """Fallback method for QEMU script testing."""
            logger.warning("QEMU testing not available, using fallback simulation")
            logger.info(f"Would test script on {target_binary} with config: {vm_config}")

            # Analyze script content for basic validation
            script_info = {}
            if script:
                script_info["length"] = len(script)
                script_info["type"] = "frida" if "Java.perform" in script else "unknown"

            return {
                "success": False,
                "output": f"QEMU testing not available (fallback mode) - Script: {script_info}",
                "errors": "QEMUTestManager not properly initialized",
                "exit_code": 1,
                "results": {
                    "simulated": True,
                    "fallback": True,
                    "script_analyzed": script_info,
                    "target": target_binary,
                    "config": vm_config,
                },
            }


@dataclass
class IntegrationTask:
    """Represents a task in the integration workflow."""

    task_id: str
    task_type: str
    description: str
    input_data: dict[str, Any]
    dependencies: list[str] = field(default_factory=list)
    status: str = "pending"  # pending, running, completed, failed
    result: Any = None
    error: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    priority: int = 1  # 1=high, 5=low


@dataclass
class WorkflowResult:
    """Result of a complete workflow execution."""

    workflow_id: str
    success: bool
    tasks_completed: int
    tasks_failed: int
    execution_time: float
    results: dict[str, Any]
    errors: list[str] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)


class IntegrationManager:
    """Manages integration and coordination of AI components."""

    def __init__(self, llm_manager: LLMManager | None = None):
        """Initialize the integration manager.

        Args:
            llm_manager: Optional LLM manager for AI components

        """
        self.logger = get_logger(__name__ + ".IntegrationManager")
        self.llm_manager = llm_manager or LLMManager()

        # Initialize components
        self.script_generator = AIScriptGenerator(self.llm_manager)
        self.code_modifier = IntelligentCodeModifier(self.llm_manager)
        self.autonomous_agent = AutonomousAgent(self.llm_manager)
        self.qemu_manager = QEMUTestManager()

        # Task management
        self.task_queue: Queue = Queue()
        self.active_tasks: dict[str, IntegrationTask] = {}
        self.completed_tasks: dict[str, IntegrationTask] = {}
        self.task_dependencies: dict[str, list[str]] = {}

        # Workflow management
        self.active_workflows: dict[str, dict[str, Any]] = {}
        self.workflow_results: dict[str, WorkflowResult] = {}

        # Execution control
        self.max_workers = 4
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.running = False
        self.worker_threads: list[threading.Thread] = []

        # Event handlers
        self.event_handlers: dict[str, list[Callable]] = {}

        # Optimization settings
        self.enable_caching = True
        self.enable_parallel_execution = True
        self.task_timeout = 300  # 5 minutes

        logger.info("Integration manager initialized")

    def start(self):
        """Start the integration manager."""
        if self.running:
            return

        self.running = True
        performance_monitor.start_monitoring()

        # Start worker threads
        for i in range(self.max_workers):
            thread = threading.Thread(
                target=self._worker_loop,
                name=f"IntegrationWorker-{i}",
                daemon=True,
            )
            thread.start()
            self.worker_threads.append(thread)

        logger.info(f"Integration manager started with {self.max_workers} workers")

    def stop(self):
        """Stop the integration manager."""
        if not self.running:
            return

        self.running = False

        # Wait for workers to finish
        for thread in self.worker_threads:
            thread.join(timeout=5.0)

        self.executor.shutdown(wait=True)
        performance_monitor.stop_monitoring()

        logger.info("Integration manager stopped")

    def _worker_loop(self):
        """Main worker loop for processing tasks."""
        while self.running:
            try:
                # Get task from queue (with timeout)
                try:
                    task = self.task_queue.get(timeout=1.0)
                except Empty as e:
                    self.logger.error("Empty in integration_manager: %s", e)
                    continue

                # Check dependencies
                if not self._are_dependencies_satisfied(task):
                    # Put back in queue and wait
                    self.task_queue.put(task)
                    time.sleep(0.5)
                    continue

                # Execute task
                self._execute_task(task)

            except Exception as e:
                logger.error(f"Error in worker loop: {e}")
                time.sleep(1.0)

    def _are_dependencies_satisfied(self, task: IntegrationTask) -> bool:
        """Check if task dependencies are satisfied."""
        for dep_id in task.dependencies:
            if dep_id not in self.completed_tasks:
                return False
            if self.completed_tasks[dep_id].status != "completed":
                return False
        return True

    @profile_ai_operation("integration.execute_task")
    def _execute_task(self, task: IntegrationTask):
        """Execute a single task."""
        task.status = "running"
        task.started_at = datetime.now()
        self.active_tasks[task.task_id] = task

        try:
            # Emit task started event
            self._emit_event("task_started", task)

            # Execute based on task type
            if task.task_type == "generate_script":
                result = self._execute_script_generation(task)
            elif task.task_type == "modify_code":
                result = self._execute_code_modification(task)
            elif task.task_type == "test_script":
                result = self._execute_script_testing(task)
            elif task.task_type == "autonomous_analysis":
                result = self._execute_autonomous_analysis(task)
            elif task.task_type == "combine_results":
                result = self._execute_result_combination(task)
            else:
                raise ValueError(f"Unknown task type: {task.task_type}")

            task.result = result
            task.status = "completed"
            task.completed_at = datetime.now()

            # Emit task completed event
            self._emit_event("task_completed", task)

        except Exception as e:
            task.error = str(e)
            task.status = "failed"
            task.completed_at = datetime.now()

            logger.error(f"Task {task.task_id} failed: {e}")
            self._emit_event("task_failed", task)

        finally:
            # Move from active to completed
            if task.task_id in self.active_tasks:
                del self.active_tasks[task.task_id]
            self.completed_tasks[task.task_id] = task

    def _execute_script_generation(self, task: IntegrationTask) -> ScriptGenerationResult:
        """Execute script generation task."""
        request = task.input_data["request"]
        script_type = task.input_data.get("script_type", "frida")

        if script_type == "frida":
            scripts = self.script_generator.generate_frida_script(request)
        elif script_type == "ghidra":
            scripts = self.script_generator.generate_ghidra_script(request)
        else:
            raise ValueError(f"Unknown script type: {script_type}")

        return {"scripts": scripts, "script_type": script_type}

    def _execute_code_modification(self, task: IntegrationTask) -> dict[str, Any]:
        """Execute code modification task."""
        request_data = task.input_data["request"]

        # Create modification request
        request = self.code_modifier.create_modification_request(**request_data)

        # Analyze and generate changes
        changes = self.code_modifier.analyze_modification_request(request)

        # Apply changes if requested
        apply_immediately = task.input_data.get("apply_immediately", False)
        if apply_immediately and changes:
            change_ids = [c.change_id for c in changes]
            apply_results = self.code_modifier.apply_changes(change_ids)
        else:
            apply_results = None

        return {
            "changes": changes,
            "apply_results": apply_results,
            "request": request,
        }

    def _execute_script_testing(self, task: IntegrationTask) -> dict[str, Any]:
        """Execute script testing task."""
        script = task.input_data["script"]
        target_binary = task.input_data["target_binary"]
        vm_config = task.input_data.get("vm_config", {})

        # Test script in QEMU
        results = self.qemu_manager.test_script_in_vm(script, target_binary, vm_config)

        return results

    def _execute_autonomous_analysis(self, task: IntegrationTask) -> dict[str, Any]:
        """Execute autonomous analysis task."""
        task_config = task.input_data["task_config"]

        # Run autonomous agent
        results = self.autonomous_agent.execute_autonomous_task(task_config)

        return results

    def _execute_result_combination(self, task: IntegrationTask) -> dict[str, Any]:
        """Combine results from dependent tasks."""
        dependency_results = {}

        for dep_id in task.dependencies:
            if dep_id in self.completed_tasks:
                dependency_results[dep_id] = self.completed_tasks[dep_id].result

        combination_logic = task.input_data.get("combination_logic", "merge")

        if combination_logic == "merge":
            # Simple merge of all results
            combined = {}
            for dep_id, result in dependency_results.items():
                if isinstance(result, dict):
                    combined.update(result)
                else:
                    combined[dep_id] = result
        elif combination_logic == "select_best":
            # Select best result based on criteria
            criteria = task.input_data.get("selection_criteria", "confidence")
            combined = self._select_best_result(dependency_results, criteria)
        else:
            combined = dependency_results

        return combined

    def _select_best_result(self, results: dict[str, Any], criteria: str) -> Any:
        """Select best result based on criteria."""
        if not results:
            return None

        if criteria == "confidence":
            # Select result with highest confidence
            best_result = None
            best_confidence = 0.0

            for result in results.values():
                if isinstance(result, dict) and "confidence" in result:
                    confidence = result["confidence"]
                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_result = result

            return best_result or list(results.values())[0]

        # Default: return first result
        return list(results.values())[0]

    def create_task(
        self,
        task_type: str,
        description: str,
        input_data: dict[str, Any],
        dependencies: list[str] = None,
        priority: int = 1,
    ) -> str:
        """Create a new integration task."""
        task_id = f"{task_type}_{int(time.time() * 1000)}"

        task = IntegrationTask(
            task_id=task_id,
            task_type=task_type,
            description=description,
            input_data=input_data,
            dependencies=dependencies or [],
            priority=priority,
        )

        # Add to queue
        self.task_queue.put(task)
        logger.info(f"Created task {task_id}: {description}")

        return task_id

    def create_workflow(self, workflow_definition: dict[str, Any]) -> str:
        """Create a complex workflow with multiple tasks."""
        workflow_id = f"workflow_{int(time.time() * 1000)}"

        workflow = {
            "id": workflow_id,
            "definition": workflow_definition,
            "tasks": {},
            "status": "created",
            "created_at": datetime.now(),
        }

        # Create tasks from definition
        tasks = workflow_definition.get("tasks", [])
        task_mapping = {}

        for task_def in tasks:
            # Map dependency names to task IDs
            dependencies = []
            for dep_name in task_def.get("dependencies", []):
                if dep_name in task_mapping:
                    dependencies.append(task_mapping[dep_name])

            task_id = self.create_task(
                task_type=task_def["type"],
                description=task_def.get("description", task_def["type"]),
                input_data=task_def["input"],
                dependencies=dependencies,
                priority=task_def.get("priority", 1),
            )

            task_mapping[task_def.get("name", task_id)] = task_id
            workflow["tasks"][task_id] = task_def

        self.active_workflows[workflow_id] = workflow
        logger.info(f"Created workflow {workflow_id} with {len(tasks)} tasks")

        return workflow_id

    def wait_for_task(self, task_id: str, timeout: float | None = None) -> IntegrationTask:
        """Wait for a task to complete."""
        start_time = time.time()

        while True:
            if task_id in self.completed_tasks:
                return self.completed_tasks[task_id]

            if timeout and time.time() - start_time > timeout:
                raise TimeoutError(f"Task {task_id} did not complete within {timeout} seconds")

            time.sleep(0.1)

    def wait_for_workflow(self, workflow_id: str, timeout: float | None = None) -> WorkflowResult:
        """Wait for a workflow to complete."""
        if workflow_id not in self.active_workflows:
            raise ValueError(f"Workflow {workflow_id} not found")

        workflow = self.active_workflows[workflow_id]
        task_ids = list(workflow["tasks"].keys())

        start_time = time.time()

        # Wait for all tasks to complete
        completed_tasks = {}
        failed_tasks = {}

        while len(completed_tasks) + len(failed_tasks) < len(task_ids):
            for task_id in task_ids:
                if task_id in completed_tasks or task_id in failed_tasks:
                    continue

                if task_id in self.completed_tasks:
                    task = self.completed_tasks[task_id]
                    if task.status == "completed":
                        completed_tasks[task_id] = task
                    elif task.status == "failed":
                        failed_tasks[task_id] = task

            if timeout and time.time() - start_time > timeout:
                raise TimeoutError(
                    f"Workflow {workflow_id} did not complete within {timeout} seconds"
                )

            time.sleep(0.1)

        # Create workflow result
        execution_time = time.time() - start_time

        results = {}
        errors = []
        artifacts = {}

        for task_id, task in completed_tasks.items():
            results[task_id] = task.result
            if hasattr(task.result, "artifacts"):
                artifacts[task_id] = task.result.artifacts

        for task_id, task in failed_tasks.items():
            errors.append(f"Task {task_id}: {task.error}")

        workflow_result = WorkflowResult(
            workflow_id=workflow_id,
            success=len(failed_tasks) == 0,
            tasks_completed=len(completed_tasks),
            tasks_failed=len(failed_tasks),
            execution_time=execution_time,
            results=results,
            errors=errors,
            artifacts=artifacts,
        )

        self.workflow_results[workflow_id] = workflow_result

        # Cleanup
        if workflow_id in self.active_workflows:
            del self.active_workflows[workflow_id]

        return workflow_result

    def get_task_status(self, task_id: str) -> dict[str, Any]:
        """Get status of a task."""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
        elif task_id in self.completed_tasks:
            task = self.completed_tasks[task_id]
        else:
            return {"status": "not_found"}

        return {
            "task_id": task.task_id,
            "status": task.status,
            "description": task.description,
            "created_at": task.created_at.isoformat(),
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            "error": task.error,
        }

    def get_workflow_status(self, workflow_id: str) -> dict[str, Any]:
        """Get status of a workflow."""
        if workflow_id in self.active_workflows:
            workflow = self.active_workflows[workflow_id]
            task_ids = list(workflow["tasks"].keys())

            completed = sum(
                1
                for tid in task_ids
                if tid in self.completed_tasks and self.completed_tasks[tid].status == "completed"
            )
            failed = sum(
                1
                for tid in task_ids
                if tid in self.completed_tasks and self.completed_tasks[tid].status == "failed"
            )
            running = sum(1 for tid in task_ids if tid in self.active_tasks)
            pending = len(task_ids) - completed - failed - running

            return {
                "workflow_id": workflow_id,
                "status": "running",
                "total_tasks": len(task_ids),
                "completed": completed,
                "failed": failed,
                "running": running,
                "pending": pending,
            }
        if workflow_id in self.workflow_results:
            result = self.workflow_results[workflow_id]
            return {
                "workflow_id": workflow_id,
                "status": "completed",
                "success": result.success,
                "tasks_completed": result.tasks_completed,
                "tasks_failed": result.tasks_failed,
                "execution_time": result.execution_time,
            }
        return {"status": "not_found"}

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending task."""
        # Remove from queue if pending
        # Note: This is a simplified implementation
        # A proper implementation would need a more sophisticated queue
        logger.info(f"Cancel request for task {task_id}")
        return True

    def add_event_handler(self, event_type: str, handler: Callable):
        """Add event handler."""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)

    def _emit_event(self, event_type: str, data: Any):
        """Emit event to handlers."""
        handlers = self.event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                handler(data)
            except Exception as e:
                logger.error(f"Error in event handler: {e}")

    def create_bypass_workflow(
        self, target_binary: str, bypass_type: str = "license_validation"
    ) -> str:
        """Create a complete bypass workflow."""
        workflow_def = {
            "name": "Complete Bypass Workflow",
            "description": f"End-to-end {bypass_type} bypass for {target_binary}",
            "tasks": [
                {
                    "name": "analyze_target",
                    "type": "autonomous_analysis",
                    "description": "Analyze target binary",
                    "input": {
                        "task_config": {
                            "objective": f"Analyze {target_binary} for {bypass_type}",
                            "target_file": target_binary,
                            "analysis_depth": "comprehensive",
                        },
                    },
                    "priority": 1,
                },
                {
                    "name": "generate_frida_script",
                    "type": "generate_script",
                    "description": "Generate Frida bypass script",
                    "input": {
                        "request": {
                            "target_info": {"file_path": target_binary},
                            "bypass_type": bypass_type,
                        },
                        "script_type": "frida",
                    },
                    "dependencies": ["analyze_target"],
                    "priority": 1,
                },
                {
                    "name": "generate_ghidra_script",
                    "type": "generate_script",
                    "description": "Generate Ghidra analysis script",
                    "input": {
                        "request": {
                            "target_info": {"file_path": target_binary},
                            "analysis_type": "static_analysis",
                        },
                        "script_type": "ghidra",
                    },
                    "dependencies": ["analyze_target"],
                    "priority": 2,
                },
                {
                    "name": "test_frida_script",
                    "type": "test_script",
                    "description": "Test Frida script in VM",
                    "input": {
                        "target_binary": target_binary,
                        "vm_config": {
                            "name": "test_vm",
                            "memory": 2048,
                            "architecture": "x86_64",
                        },
                    },
                    "dependencies": ["generate_frida_script"],
                    "priority": 2,
                },
                {
                    "name": "combine_results",
                    "type": "combine_results",
                    "description": "Combine all results",
                    "input": {
                        "combination_logic": "merge",
                    },
                    "dependencies": ["test_frida_script", "generate_ghidra_script"],
                    "priority": 3,
                },
            ],
        }

        return self.create_workflow(workflow_def)

    def get_performance_summary(self) -> dict[str, Any]:
        """Get performance summary for integration operations."""
        return performance_monitor.get_metrics_summary()

    def cleanup(self):
        """Cleanup resources and old data."""
        # Clean old completed tasks (keep last 100)
        if len(self.completed_tasks) > 100:
            sorted_tasks = sorted(
                self.completed_tasks.items(),
                key=lambda x: x[1].completed_at or datetime.min,
                reverse=True,
            )

            # Keep most recent 100
            self.completed_tasks = dict(sorted_tasks[:100])

        # Clean old workflow results (keep last 50)
        if len(self.workflow_results) > 50:
            sorted_workflows = sorted(
                self.workflow_results.items(),
                key=lambda x: x[1].workflow_id,
                reverse=True,
            )

            self.workflow_results = dict(sorted_workflows[:50])

        logger.info("Cleanup completed")

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if exc_type:
            logger.error(f"Integration manager exiting due to {exc_type.__name__}: {exc_val}")
            if exc_tb:
                logger.debug(
                    f"Exception traceback available: {exc_tb.tb_frame.f_code.co_filename}:{exc_tb.tb_lineno}"
                )
        self.stop()
        return False  # Don't suppress exceptions


# Global integration manager instance
integration_manager = IntegrationManager()
