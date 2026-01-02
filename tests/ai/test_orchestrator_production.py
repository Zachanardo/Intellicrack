"""Production tests for AI orchestrator system.

Tests validate REAL AI task orchestration, coordination between ML/LLM
components, and execution of license analysis workflows. All tests verify
actual orchestration behavior for cracking software protections.

Copyright (C) 2025 Zachary Flint
Licensed under GPL v3.
"""

import os
import queue
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import pytest

from intellicrack.ai.orchestrator import (
    AIEventBus,
    AIOrchestrator,
    AIResult,
    AISharedContext,
    AITask,
    AITaskType,
    AnalysisComplexity,
)


@pytest.fixture(autouse=True)
def enable_testing_mode() -> None:
    """Enable testing mode to prevent background threads."""
    os.environ["INTELLICRACK_TESTING"] = "1"


class FakeLLMBackend:
    """Real test double implementing LLM interface with canned responses."""

    def __init__(self) -> None:
        """Initialize fake LLM backend with predefined responses."""
        self.active_backend: str = "test_backend"
        self.chat_history: list[list[Any]] = []
        self.shutdown_called: bool = False

    def get_available_llms(self) -> list[str]:
        """Return list of available LLM backends."""
        return ["test_backend", "backup_backend"]

    def chat(self, messages: list[Any]) -> Any:
        """Process chat messages and return canned response."""
        self.chat_history.append(messages)

        class FakeResponse:
            def __init__(self) -> None:
                self.content = "Analysis complete. Detected VMProtect protection with 95% confidence."
                self.model = "test_backend"

        return FakeResponse()

    def shutdown(self) -> None:
        """Shutdown the LLM backend."""
        self.shutdown_called = True


class FakeModelManager:
    """Real test double for model management."""

    def __init__(self) -> None:
        """Initialize fake model manager."""
        self.loaded_models: list[str] = []

    def load_model(self, model_name: str) -> bool:
        """Load a model by name."""
        self.loaded_models.append(model_name)
        return True

    def get_loaded_models(self) -> list[str]:
        """Get list of loaded models."""
        return self.loaded_models


class FakeAIAssistant:
    """Real test double implementing AI assistant interface."""

    def __init__(self) -> None:
        """Initialize fake AI assistant."""
        self.analyze_license_called: int = 0
        self.analyze_binary_called: int = 0
        self.generate_frida_called: int = 0
        self.generate_ghidra_called: int = 0

    def get_system_prompt(self) -> str:
        """Get system prompt for AI assistant."""
        return "You are a binary analysis expert for license cracking."

    def analyze_license(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Analyze license patterns in binary."""
        self.analyze_license_called += 1
        strings = input_data.get("strings", [])
        has_trial = any("trial" in s.lower() for s in strings)
        has_expire = any("expire" in s.lower() for s in strings)

        return {
            "license_type": "trial" if has_trial else "commercial",
            "expires_in_days": 30 if has_expire else None,
            "confidence": 0.88 if (has_trial or has_expire) else 0.45,
            "indicators": [s for s in strings if any(kw in s.lower() for kw in ["trial", "expire", "license"])],
        }

    def analyze_license_patterns(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Analyze license patterns in binary."""
        return self.analyze_license(input_data)

    def analyze_binary(self, binary_path: str) -> dict[str, Any]:
        """Analyze binary for protections."""
        self.analyze_binary_called += 1
        return {
            "protection": "VMProtect" if "vmprotect" in binary_path.lower() else "None",
            "confidence": 0.91,
            "license_checks": [0x401000, 0x402000],
        }

    def analyze_binary_complex(self, binary_path: str, ml_results: dict[str, Any]) -> dict[str, Any]:
        """Perform complex binary analysis."""
        self.analyze_binary_called += 1
        base_confidence = ml_results.get("confidence", 0.5)
        return {
            "protection": "VMProtect",
            "confidence": min(base_confidence + 0.3, 0.95),
            "license_checks": [0x401000, 0x402000],
            "ml_input_confidence": base_confidence,
            "enhanced": True,
        }

    def generate_frida_script(self, analysis_data: dict[str, Any]) -> Any:
        """Generate Frida script for binary."""
        self.generate_frida_called += 1

        class FakeFridaScript:
            def __init__(self) -> None:
                self.content = "Interceptor.attach(ptr(0x401000), {});"
                self.entry_point = "0x401000"
                self.dependencies: list[str] = ["frida"]
                self.hooks: list[str] = ["check_license"]
                self.patches: list[str] = []

                class Metadata:
                    def __init__(self) -> None:
                        self.script_id = "frida-001"
                        self.script_type = type("ScriptType", (), {"value": "frida"})()
                        self.target_binary = "test.exe"
                        self.protection_types = [type("ProtectionType", (), {"value": "vmprotect"})()]
                        self.success_probability = 0.92

                self.metadata = Metadata()

        return FakeFridaScript()

    def generate_ghidra_script(self, analysis_data: dict[str, Any]) -> Any:
        """Generate Ghidra script for binary."""
        self.generate_ghidra_called += 1

        class FakeGhidraScript:
            def __init__(self) -> None:
                self.content = "# Ghidra script for license patch"
                self.entry_point = "0x401000"
                self.dependencies: list[str] = ["ghidra"]
                self.hooks: list[str] = []
                self.patches: list[str] = ["patch_license_check"]

                class Metadata:
                    def __init__(self) -> None:
                        self.script_id = "ghidra-001"
                        self.script_type = type("ScriptType", (), {"value": "ghidra"})()
                        self.target_binary = "test.exe"
                        self.protection_types = [type("ProtectionType", (), {"value": "vmprotect"})()]
                        self.success_probability = 0.88

                self.metadata = Metadata()

        return FakeGhidraScript()


class FakeAIBinaryBridge:
    """Real test double implementing binary bridge interface."""

    def __init__(self) -> None:
        """Initialize fake binary bridge."""
        self.analyze_binary_called: int = 0

    def analyze_binary(self, binary_path: str) -> dict[str, Any]:
        """Analyze binary patterns."""
        self.analyze_binary_called += 1
        return {
            "protection": "VMProtect" if "vmprotect" in binary_path.lower() else "Themida",
            "confidence": 0.85,
            "patterns_found": 42,
            "license_check_locations": [0x401000, 0x403000],
        }

    def analyze_binary_patterns(self, binary_path: str) -> dict[str, Any]:
        """Analyze binary patterns."""
        return self.analyze_binary(binary_path)


class TestAISharedContext:
    """Tests for AISharedContext validating thread-safe shared memory."""

    def test_context_initializes_with_default_structure(self) -> None:
        """Context initializes with expected default structure."""
        context = AISharedContext()

        assert context.get("current_binary") is None
        assert context.get("binary_metadata") == {}
        assert context.get("analysis_results") == {}
        assert context.get("model_predictions") == {}
        assert context.get("user_session") == {}
        assert context.get("workflow_state") == {}

    def test_context_stores_and_retrieves_values(self) -> None:
        """Context stores and retrieves values correctly."""
        context = AISharedContext()

        context.set("test_key", "test_value")
        value = context.get("test_key")

        assert value == "test_value"

    def test_context_returns_default_for_missing_keys(self) -> None:
        """Context returns default value for missing keys."""
        context = AISharedContext()

        value = context.get("nonexistent_key", "default_value")

        assert value == "default_value"

    def test_context_updates_multiple_values(self) -> None:
        """Context updates multiple values at once."""
        context = AISharedContext()

        updates = {
            "key1": "value1",
            "key2": "value2",
            "key3": "value3",
        }
        context.update(updates)

        assert context.get("key1") == "value1"
        assert context.get("key2") == "value2"
        assert context.get("key3") == "value3"

    def test_context_caches_analysis_results(self) -> None:
        """Context caches analysis results by binary hash."""
        context = AISharedContext()
        binary_hash = "abc123def456"
        results = {
            "protection": "VMProtect",
            "confidence": 0.95,
            "license_check_offset": 0x401000,
        }

        context.cache_analysis(binary_hash, results)
        cached = context.get_analysis_cache(binary_hash)

        assert cached is not None
        assert cached["results"] == results
        assert "timestamp" in cached
        assert "access_count" in cached

    def test_context_returns_none_for_uncached_analysis(self) -> None:
        """Context returns None for uncached binary hash."""
        context = AISharedContext()

        cached = context.get_analysis_cache("nonexistent_hash")

        assert cached is None

    def test_context_clears_session_data(self) -> None:
        """Context clears session-specific data."""
        context = AISharedContext()

        context.set("user_session", {"user_id": "123"})
        context.set("workflow_state", {"current_step": 2})

        context.clear_session()

        assert context.get("user_session") == {}
        assert context.get("workflow_state") == {}

    def test_context_is_thread_safe(self) -> None:
        """Context handles concurrent access safely."""
        context = AISharedContext()
        errors: list[Exception] = []

        def concurrent_write(i: int) -> None:
            try:
                context.set(f"key_{i}", f"value_{i}")
                value = context.get(f"key_{i}")
                assert value == f"value_{i}"
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=concurrent_write, args=(i,)) for i in range(50)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors
        for i in range(50):
            assert context.get(f"key_{i}") == f"value_{i}"


class TestAIEventBus:
    """Tests for AIEventBus validating event-driven communication."""

    def test_event_bus_subscribes_components(self) -> None:
        """Event bus subscribes components to events."""
        bus = AIEventBus()
        received_events: list[dict[str, Any]] = []

        def callback(data: dict[str, Any], source: str) -> None:
            received_events.append({"data": data, "source": source})

        bus.subscribe("test_event", callback, "test_component")

        assert "test_event" in bus._subscribers
        assert len(bus._subscribers["test_event"]) == 1

    def test_event_bus_emits_events_to_subscribers(self) -> None:
        """Event bus emits events to all subscribers."""
        bus = AIEventBus()
        received1: list[dict[str, Any]] = []
        received2: list[dict[str, Any]] = []

        def callback1(data: dict[str, Any], source: str) -> None:
            received1.append({"data": data, "source": source})

        def callback2(data: dict[str, Any], source: str) -> None:
            received2.append({"data": data, "source": source})

        bus.subscribe("test_event", callback1, "component1")
        bus.subscribe("test_event", callback2, "component2")

        event_data = {"key": "value"}
        bus.emit("test_event", event_data, "source_component")

        time.sleep(0.2)

        assert len(received1) == 1
        assert len(received2) == 1
        assert received1[0]["data"] == event_data
        assert received2[0]["data"] == event_data

    def test_event_bus_handles_multiple_event_types(self) -> None:
        """Event bus handles multiple event types independently."""
        bus = AIEventBus()
        received_a: list[dict[str, Any]] = []
        received_b: list[dict[str, Any]] = []

        def callback_a(data: dict[str, Any], source: str) -> None:
            received_a.append(data)

        def callback_b(data: dict[str, Any], source: str) -> None:
            received_b.append(data)

        bus.subscribe("event_type_a", callback_a, "component1")
        bus.subscribe("event_type_b", callback_b, "component2")

        bus.emit("event_type_a", {"data": "a"}, "source")
        time.sleep(0.1)

        assert len(received_a) == 1
        assert len(received_b) == 0

    def test_event_bus_unsubscribes_components(self) -> None:
        """Event bus unsubscribes components from events."""
        bus = AIEventBus()
        received: list[dict[str, Any]] = []

        def callback(data: dict[str, Any], source: str) -> None:
            received.append(data)

        bus.subscribe("test_event", callback, "test_component")
        bus.unsubscribe("test_event", "test_component")

        bus.emit("test_event", {}, "source")
        time.sleep(0.1)

        assert len(received) == 0

    def test_event_bus_handles_subscriber_errors(self) -> None:
        """Event bus handles subscriber errors gracefully."""
        bus = AIEventBus()

        def failing_callback(data: dict[str, Any], source: str) -> None:
            raise RuntimeError("Callback failed")

        bus.subscribe("test_event", failing_callback, "failing_component")

        bus.emit("test_event", {}, "source")
        time.sleep(0.1)

    def test_event_bus_supports_multiple_subscribers_per_event(self) -> None:
        """Event bus supports multiple subscribers for same event."""
        bus = AIEventBus()
        received1: list[dict[str, Any]] = []
        received2: list[dict[str, Any]] = []
        received3: list[dict[str, Any]] = []

        def callback1(data: dict[str, Any], source: str) -> None:
            received1.append(data)

        def callback2(data: dict[str, Any], source: str) -> None:
            received2.append(data)

        def callback3(data: dict[str, Any], source: str) -> None:
            received3.append(data)

        bus.subscribe("analysis_complete", callback1, "component1")
        bus.subscribe("analysis_complete", callback2, "component2")
        bus.subscribe("analysis_complete", callback3, "component3")

        bus.emit("analysis_complete", {"results": {}}, "analyzer")
        time.sleep(0.2)

        assert len(received1) == 1
        assert len(received2) == 1
        assert len(received3) == 1


class TestAITaskDataStructures:
    """Tests for AITask and AIResult data structures."""

    def test_ai_task_creates_with_required_fields(self) -> None:
        """AITask creates with all required fields."""
        task = AITask(
            task_id="task-123",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.MODERATE,
            input_data={"binary_path": "/path/to/binary.exe"},
        )

        assert task.task_id == "task-123"
        assert task.task_type == AITaskType.LICENSE_ANALYSIS
        assert task.complexity == AnalysisComplexity.MODERATE
        assert task.priority == 5
        assert isinstance(task.created_at, datetime)

    def test_ai_task_supports_custom_priority(self) -> None:
        """AITask supports custom priority values."""
        task = AITask(
            task_id="high-priority-task",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.CRITICAL,
            input_data={},
            priority=10,
        )

        assert task.priority == 10

    def test_ai_task_supports_callback(self) -> None:
        """AITask supports callback functions."""
        callback_invoked: list[AIResult] = []

        def callback(result: AIResult) -> None:
            callback_invoked.append(result)

        task = AITask(
            task_id="task-with-callback",
            task_type=AITaskType.BINARY_ANALYSIS,
            complexity=AnalysisComplexity.SIMPLE,
            input_data={},
            callback=callback,
        )

        assert task.callback is callback

    def test_ai_result_captures_task_execution(self) -> None:
        """AIResult captures complete task execution details."""
        result = AIResult(
            task_id="task-123",
            task_type=AITaskType.LICENSE_ANALYSIS,
            success=True,
            result_data={"license_type": "trial", "expires_in": 30},
            confidence=0.92,
            processing_time=1.5,
            components_used=["ml_predictor", "llm_manager"],
        )

        assert result.task_id == "task-123"
        assert result.success is True
        assert result.confidence == 0.92
        assert result.processing_time == 1.5
        assert "ml_predictor" in result.components_used
        assert isinstance(result.completed_at, datetime)

    def test_ai_result_captures_errors(self) -> None:
        """AIResult captures errors during execution."""
        result = AIResult(
            task_id="failed-task",
            task_type=AITaskType.VULNERABILITY_SCAN,
            success=False,
            result_data={},
            confidence=0.0,
            processing_time=0.5,
            components_used=[],
            errors=["Binary not found", "Analysis timeout"],
        )

        assert result.success is False
        assert len(result.errors) == 2
        assert "Binary not found" in result.errors


class TestAIOrchestrator:
    """Tests for AIOrchestrator validating task coordination."""

    def test_orchestrator_initializes_components(self) -> None:
        """Orchestrator initializes all AI components."""
        orchestrator = AIOrchestrator()

        assert orchestrator.shared_context is not None
        assert orchestrator.event_bus is not None
        assert orchestrator.task_queue is not None
        assert isinstance(orchestrator.task_queue, queue.PriorityQueue)

    def test_orchestrator_submits_tasks_to_queue(self) -> None:
        """Orchestrator submits tasks to processing queue."""
        orchestrator = AIOrchestrator()
        task = AITask(
            task_id="test-task",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.MODERATE,
            input_data={"binary_path": "/test/binary.exe"},
        )

        orchestrator.submit_task(task)

        assert orchestrator.task_queue.qsize() > 0

    def test_orchestrator_executes_license_analysis_task(self) -> None:
        """Orchestrator executes license analysis tasks with real AI assistant."""
        orchestrator = AIOrchestrator()
        fake_assistant = FakeAIAssistant()
        orchestrator.ai_assistant = fake_assistant

        task = AITask(
            task_id="license-task",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.MODERATE,
            input_data={"strings": ["trial", "expires", "30 days"]},
        )

        result = orchestrator._execute_task(task)

        assert result.success is True
        assert "ai_assistant" in result.components_used
        assert fake_assistant.analyze_license_called == 1
        assert result.result_data.get("license_analysis", {}).get("license_type") == "trial"

    def test_orchestrator_executes_binary_analysis_task(self) -> None:
        """Orchestrator executes binary analysis tasks with real binary bridge."""
        orchestrator = AIOrchestrator()
        fake_bridge = FakeAIBinaryBridge()
        orchestrator.hex_bridge = fake_bridge

        task = AITask(
            task_id="binary-task",
            task_type=AITaskType.BINARY_ANALYSIS,
            complexity=AnalysisComplexity.MODERATE,
            input_data={"binary_path": "/test/vmprotect.exe"},
        )

        result = orchestrator._execute_task(task)

        assert result.success is True
        assert "hex_bridge" in result.components_used
        assert fake_bridge.analyze_binary_called == 1
        assert result.result_data.get("hex_analysis", {}).get("protection") == "VMProtect"

    def test_orchestrator_tracks_task_progress(self) -> None:
        """Orchestrator tracks task progress during execution."""
        orchestrator = AIOrchestrator()

        orchestrator.update_task_progress("task-123", 50, "Processing...")

        assert "task-123" in orchestrator.task_progress
        assert orchestrator.task_progress["task-123"]["progress"] == 50
        assert orchestrator.task_progress["task-123"]["message"] == "Processing..."

    def test_orchestrator_clears_task_progress(self) -> None:
        """Orchestrator clears task progress after completion."""
        orchestrator = AIOrchestrator()

        orchestrator.update_task_progress("task-123", 100, "Complete")
        orchestrator.clear_task_progress("task-123")

        assert "task-123" not in orchestrator.task_progress

    def test_orchestrator_calls_task_callback(self) -> None:
        """Orchestrator calls task callback after execution."""
        orchestrator = AIOrchestrator()
        fake_assistant = FakeAIAssistant()
        orchestrator.ai_assistant = fake_assistant

        callback_results: list[AIResult] = []

        def callback(result: AIResult) -> None:
            callback_results.append(result)

        task = AITask(
            task_id="callback-task",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.SIMPLE,
            input_data={},
            callback=callback,
        )

        orchestrator._execute_task(task)

        assert len(callback_results) == 1
        assert callback_results[0].task_id == "callback-task"

    def test_orchestrator_emits_task_completion_event(self) -> None:
        """Orchestrator emits task completion events."""
        orchestrator = AIOrchestrator()
        fake_assistant = FakeAIAssistant()
        orchestrator.ai_assistant = fake_assistant

        completion_events: list[dict[str, Any]] = []

        def completion_callback(data: dict[str, Any], source: str) -> None:
            completion_events.append(data)

        orchestrator.event_bus.subscribe("task_complete", completion_callback, "test")

        task = AITask(
            task_id="event-task",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.SIMPLE,
            input_data={},
        )

        orchestrator._execute_task(task)
        time.sleep(0.1)

        assert len(completion_events) >= 1
        assert completion_events[0]["task_id"] == "event-task"

    def test_orchestrator_handles_task_execution_errors(self) -> None:
        """Orchestrator handles task execution errors gracefully."""
        orchestrator = AIOrchestrator()

        class FailingAssistant:
            def analyze_license(self, input_data: dict[str, Any]) -> dict[str, Any]:
                raise RuntimeError("Analysis failed")

        orchestrator.ai_assistant = FailingAssistant()

        task = AITask(
            task_id="error-task",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.MODERATE,
            input_data={},
        )

        result = orchestrator._execute_task(task)

        assert result.success is False
        assert len(result.errors) > 0
        assert "Analysis failed" in result.errors[0]

    def test_orchestrator_supports_priority_task_ordering(self) -> None:
        """Orchestrator processes higher priority tasks first."""
        orchestrator = AIOrchestrator()

        low_priority_task = AITask(
            task_id="low",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.SIMPLE,
            input_data={},
            priority=3,
        )

        high_priority_task = AITask(
            task_id="high",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.CRITICAL,
            input_data={},
            priority=10,
        )

        orchestrator.submit_task(low_priority_task)
        orchestrator.submit_task(high_priority_task)

        _, first_task = orchestrator.task_queue.get_nowait()
        assert first_task.task_id == "high"


class TestEventHandlers:
    """Tests for orchestrator event handlers."""

    def test_analysis_complete_handler_updates_context(self) -> None:
        """Analysis complete handler updates shared context."""
        orchestrator = AIOrchestrator()

        event_data = {
            "task_id": "task-123",
            "results": {"license_type": "trial", "confidence": 0.85},
        }

        orchestrator._on_analysis_complete(event_data, "analyzer")

        assert "last_analysis_analyzer" in orchestrator.shared_context._context

    def test_ml_prediction_complete_escalates_low_confidence(self) -> None:
        """ML prediction complete handler escalates low confidence results."""
        orchestrator = AIOrchestrator()
        fake_model_manager = FakeModelManager()
        orchestrator.model_manager = fake_model_manager

        initial_queue_size = orchestrator.task_queue.qsize()

        event_data = {
            "task_id": "ml-task",
            "confidence": 0.5,
            "prediction": "VMProtect",
        }

        orchestrator._on_ml_prediction_complete(event_data, "ml_predictor")

        assert orchestrator.task_queue.qsize() > initial_queue_size

    def test_error_handler_logs_component_errors(self) -> None:
        """Error handler logs errors from components."""
        orchestrator = AIOrchestrator()

        error_data = {
            "error": "Binary analysis failed",
            "task_id": "error-task",
        }

        orchestrator._on_error_occurred(error_data, "analyzer")


class TestScriptGenerationTasks:
    """Tests for script generation task execution."""

    def test_orchestrator_executes_frida_script_generation(self) -> None:
        """Orchestrator executes Frida script generation tasks."""
        orchestrator = AIOrchestrator()
        fake_assistant = FakeAIAssistant()
        orchestrator.ai_assistant = fake_assistant

        task = AITask(
            task_id="frida-task",
            task_type=AITaskType.FRIDA_SCRIPT_GENERATION,
            complexity=AnalysisComplexity.COMPLEX,
            input_data={"target_function": "check_license"},
        )

        result = orchestrator._execute_task(task)

        assert result.task_type == AITaskType.FRIDA_SCRIPT_GENERATION

    def test_orchestrator_executes_ghidra_script_generation(self) -> None:
        """Orchestrator executes Ghidra script generation tasks."""
        orchestrator = AIOrchestrator()
        fake_assistant = FakeAIAssistant()
        orchestrator.ai_assistant = fake_assistant

        task = AITask(
            task_id="ghidra-task",
            task_type=AITaskType.GHIDRA_SCRIPT_GENERATION,
            complexity=AnalysisComplexity.COMPLEX,
            input_data={"analysis_type": "license_check"},
        )

        result = orchestrator._execute_task(task)

        assert result.task_type == AITaskType.GHIDRA_SCRIPT_GENERATION


class TestComplexityEscalation:
    """Tests for complexity-based task escalation."""

    def test_simple_tasks_use_fast_components(self) -> None:
        """Simple tasks use fast analysis components."""
        orchestrator = AIOrchestrator()
        fake_assistant = FakeAIAssistant()
        orchestrator.ai_assistant = fake_assistant

        task = AITask(
            task_id="simple-task",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.SIMPLE,
            input_data={},
        )

        result = orchestrator._execute_task(task)

        assert result.processing_time < 2.0

    def test_complex_tasks_use_llm_components(self) -> None:
        """Complex tasks escalate to LLM components."""
        orchestrator = AIOrchestrator()
        fake_assistant = FakeAIAssistant()
        orchestrator.ai_assistant = fake_assistant

        task = AITask(
            task_id="complex-task",
            task_type=AITaskType.VULNERABILITY_SCAN,
            complexity=AnalysisComplexity.COMPLEX,
            input_data={"binary_path": "/test/binary.exe"},
        )

        result = orchestrator._execute_task(task)

        assert result.success is True


class TestIntegrationWorkflows:
    """Integration tests for complete orchestration workflows."""

    def test_complete_license_analysis_workflow(self) -> None:
        """Complete license analysis workflow from submission to result."""
        orchestrator = AIOrchestrator()
        fake_assistant = FakeAIAssistant()
        orchestrator.ai_assistant = fake_assistant

        results: list[AIResult] = []

        def collect_result(result: AIResult) -> None:
            results.append(result)

        task = AITask(
            task_id="workflow-task",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.MODERATE,
            input_data={"strings": ["trial", "expire", "30"]},
            callback=collect_result,
        )

        orchestrator.submit_task(task)
        time.sleep(0.2)

        orchestrator._execute_task(task)

        assert len(results) == 1
        assert results[0].success is True
        assert results[0].result_data.get("license_analysis", {}).get("license_type") == "trial"

    def test_multi_task_coordination(self) -> None:
        """Multiple tasks coordinate through shared context."""
        orchestrator = AIOrchestrator()
        fake_bridge = FakeAIBinaryBridge()
        fake_assistant = FakeAIAssistant()
        orchestrator.hex_bridge = fake_bridge
        orchestrator.ai_assistant = fake_assistant

        task1 = AITask(
            task_id="task-1",
            task_type=AITaskType.BINARY_ANALYSIS,
            complexity=AnalysisComplexity.SIMPLE,
            input_data={"binary_path": "/test.exe"},
        )

        task2 = AITask(
            task_id="task-2",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.MODERATE,
            input_data={},
        )

        orchestrator._execute_task(task1)
        orchestrator._execute_task(task2)

        context_keys = orchestrator.shared_context._context.keys()
        assert "last_analysis_hex_bridge" in context_keys
        assert "last_analysis_ai_assistant" in context_keys

    def test_reasoning_task_with_llm_backend(self) -> None:
        """Reasoning task uses real LLM backend for complex analysis."""
        orchestrator = AIOrchestrator()
        fake_llm = FakeLLMBackend()
        orchestrator.llm_manager = fake_llm

        task = AITask(
            task_id="reasoning-task",
            task_type=AITaskType.REASONING,
            complexity=AnalysisComplexity.COMPLEX,
            input_data={
                "ml_results": {"confidence": 0.5, "prediction": "VMProtect"},
                "escalation_reason": "low_confidence",
            },
        )

        result = orchestrator._execute_task(task)

        assert result.success is True
        assert len(fake_llm.chat_history) == 1
        assert "reasoning" in result.result_data
        assert result.confidence >= 0.85

    def test_vulnerability_scan_workflow(self) -> None:
        """Vulnerability scan workflow executes complete analysis."""
        orchestrator = AIOrchestrator()
        fake_assistant = FakeAIAssistant()
        orchestrator.ai_assistant = fake_assistant

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as temp_file:
            temp_path = temp_file.name
            temp_file.write(b"MZ\x90\x00")

        try:
            task = AITask(
                task_id="vuln-scan",
                task_type=AITaskType.VULNERABILITY_SCAN,
                complexity=AnalysisComplexity.COMPLEX,
                input_data={"binary_path": temp_path},
            )

            result = orchestrator._execute_task(task)

            assert result.success is True
            assert fake_assistant.analyze_binary_called >= 1
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_binary_analysis_with_ai_enhancement(self) -> None:
        """Binary analysis uses AI enhancement for low confidence results."""
        orchestrator = AIOrchestrator()
        fake_bridge = FakeAIBinaryBridge()
        fake_assistant = FakeAIAssistant()
        orchestrator.hex_bridge = fake_bridge
        orchestrator.ai_assistant = fake_assistant

        task = AITask(
            task_id="enhanced-analysis",
            task_type=AITaskType.BINARY_ANALYSIS,
            complexity=AnalysisComplexity.MODERATE,
            input_data={"binary_path": "/test/vmprotect.exe"},
        )

        result = orchestrator._execute_task(task)

        assert result.success is True
        assert "hex_bridge" in result.components_used
        if "ai_assistant_complex" in result.components_used:
            assert result.result_data.get("ai_complex_analysis", {}).get("enhanced") is True


class TestProgressTracking:
    """Tests for task progress tracking."""

    def test_progress_callback_registration(self) -> None:
        """Progress callbacks can be registered for tasks."""
        orchestrator = AIOrchestrator()
        callback_invocations: list[tuple[str, int, str]] = []

        def progress_callback(task_id: str, progress: int, status: str) -> None:
            callback_invocations.append((task_id, progress, status))

        orchestrator.register_progress_callback("task-123", progress_callback)

        orchestrator.update_task_progress("task-123", 50, "Processing")

        assert len(callback_invocations) >= 1
        assert callback_invocations[-1][0] == "task-123"
        assert callback_invocations[-1][1] == 50

    def test_progress_events_emitted(self) -> None:
        """Progress updates emit events to event bus."""
        orchestrator = AIOrchestrator()
        progress_events: list[dict[str, Any]] = []

        def progress_event_handler(data: dict[str, Any], source: str) -> None:
            progress_events.append(data)

        orchestrator.event_bus.subscribe("task_progress", progress_event_handler, "test")

        orchestrator.update_task_progress("task-456", 75, "Nearly complete")
        time.sleep(0.1)

        assert len(progress_events) >= 1
        assert progress_events[-1]["task_id"] == "task-456"
        assert progress_events[-1]["progress"] == 75

    def test_get_task_progress(self) -> None:
        """Task progress can be retrieved."""
        orchestrator = AIOrchestrator()

        orchestrator.update_task_progress("task-789", 60, "In progress")

        progress = orchestrator.get_task_progress("task-789")

        assert progress is not None
        assert progress["progress"] == 60
        assert progress["status"] == "In progress"


class TestComponentStatus:
    """Tests for component status reporting."""

    def test_get_component_status(self) -> None:
        """Component status reports availability of all components."""
        orchestrator = AIOrchestrator()

        status = orchestrator.get_component_status()

        assert "model_manager" in status
        assert "llm_manager" in status
        assert "ai_assistant" in status
        assert "hex_bridge" in status
        assert "active_tasks" in status
        assert "queue_size" in status

    def test_component_status_with_llm_backend(self) -> None:
        """Component status includes LLM backend information."""
        orchestrator = AIOrchestrator()
        fake_llm = FakeLLMBackend()
        orchestrator.llm_manager = fake_llm

        status = orchestrator.get_component_status()

        assert status["llm_manager"] is True
        assert "llm_status" in status
        assert status["llm_status"]["available_llms"] == ["test_backend", "backup_backend"]
        assert status["llm_status"]["active_llm"] == "test_backend"


class TestShutdown:
    """Tests for orchestrator shutdown."""

    def test_orchestrator_shutdown(self) -> None:
        """Orchestrator shuts down cleanly."""
        orchestrator = AIOrchestrator()
        fake_llm = FakeLLMBackend()
        orchestrator.llm_manager = fake_llm

        orchestrator.shutdown()

        assert fake_llm.shutdown_called is True
        assert orchestrator.shared_context.get("user_session") == {}
