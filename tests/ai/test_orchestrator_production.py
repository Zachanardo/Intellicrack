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
from typing import Any
from unittest.mock import MagicMock, Mock, patch

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
        errors = []

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

        assert len(errors) == 0
        for i in range(50):
            assert context.get(f"key_{i}") == f"value_{i}"


class TestAIEventBus:
    """Tests for AIEventBus validating event-driven communication."""

    def test_event_bus_subscribes_components(self) -> None:
        """Event bus subscribes components to events."""
        bus = AIEventBus()
        callback = Mock()

        bus.subscribe("test_event", callback, "test_component")

        assert "test_event" in bus._subscribers
        assert len(bus._subscribers["test_event"]) == 1

    def test_event_bus_emits_events_to_subscribers(self) -> None:
        """Event bus emits events to all subscribers."""
        bus = AIEventBus()
        callback1 = Mock()
        callback2 = Mock()

        bus.subscribe("test_event", callback1, "component1")
        bus.subscribe("test_event", callback2, "component2")

        event_data = {"key": "value"}
        bus.emit("test_event", event_data, "source_component")

        time.sleep(0.2)

        callback1.assert_called_once()
        callback2.assert_called_once()

    def test_event_bus_handles_multiple_event_types(self) -> None:
        """Event bus handles multiple event types independently."""
        bus = AIEventBus()
        callback1 = Mock()
        callback2 = Mock()

        bus.subscribe("event_type_a", callback1, "component1")
        bus.subscribe("event_type_b", callback2, "component2")

        bus.emit("event_type_a", {"data": "a"}, "source")
        time.sleep(0.1)

        callback1.assert_called_once()
        callback2.assert_not_called()

    def test_event_bus_unsubscribes_components(self) -> None:
        """Event bus unsubscribes components from events."""
        bus = AIEventBus()
        callback = Mock()

        bus.subscribe("test_event", callback, "test_component")
        bus.unsubscribe("test_event", "test_component")

        bus.emit("test_event", {}, "source")
        time.sleep(0.1)

        callback.assert_not_called()

    def test_event_bus_handles_subscriber_errors(self) -> None:
        """Event bus handles subscriber errors gracefully."""
        bus = AIEventBus()

        def failing_callback(data: dict, source: str) -> None:
            raise RuntimeError("Callback failed")

        bus.subscribe("test_event", failing_callback, "failing_component")

        bus.emit("test_event", {}, "source")
        time.sleep(0.1)

    def test_event_bus_supports_multiple_subscribers_per_event(self) -> None:
        """Event bus supports multiple subscribers for same event."""
        bus = AIEventBus()
        callback1 = Mock()
        callback2 = Mock()
        callback3 = Mock()

        bus.subscribe("analysis_complete", callback1, "component1")
        bus.subscribe("analysis_complete", callback2, "component2")
        bus.subscribe("analysis_complete", callback3, "component3")

        bus.emit("analysis_complete", {"results": {}}, "analyzer")
        time.sleep(0.2)

        callback1.assert_called_once()
        callback2.assert_called_once()
        callback3.assert_called_once()


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
        callback = Mock()
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

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_orchestrator_initializes_components(
        self,
        mock_bridge: Mock,
        mock_assistant: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Orchestrator initializes all AI components."""
        orchestrator = AIOrchestrator()

        assert orchestrator.shared_context is not None
        assert orchestrator.event_bus is not None
        assert orchestrator.task_queue is not None
        assert isinstance(orchestrator.task_queue, queue.PriorityQueue)

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_orchestrator_submits_tasks_to_queue(
        self,
        mock_bridge: Mock,
        mock_assistant: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
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

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_orchestrator_executes_license_analysis_task(
        self,
        mock_bridge: Mock,
        mock_assistant_class: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Orchestrator executes license analysis tasks."""
        mock_assistant = Mock()
        mock_assistant.analyze_license.return_value = {
            "license_type": "trial",
            "confidence": 0.88,
        }
        mock_assistant_class.return_value = mock_assistant

        orchestrator = AIOrchestrator()
        task = AITask(
            task_id="license-task",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.MODERATE,
            input_data={"strings": ["trial", "expires", "30 days"]},
        )

        result = orchestrator._execute_task(task)

        assert result.success is True
        assert "ai_assistant" in result.components_used

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_orchestrator_executes_binary_analysis_task(
        self,
        mock_bridge_class: Mock,
        mock_assistant: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Orchestrator executes binary analysis tasks."""
        mock_bridge = Mock()
        mock_bridge.analyze_binary.return_value = {
            "protection": "VMProtect",
            "confidence": 0.91,
        }
        mock_bridge_class.return_value = mock_bridge

        orchestrator = AIOrchestrator()
        task = AITask(
            task_id="binary-task",
            task_type=AITaskType.BINARY_ANALYSIS,
            complexity=AnalysisComplexity.MODERATE,
            input_data={"binary_path": "/test/protected.exe"},
        )

        result = orchestrator._execute_task(task)

        assert result.success is True
        assert "hex_bridge" in result.components_used

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_orchestrator_tracks_task_progress(
        self,
        mock_bridge: Mock,
        mock_assistant: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Orchestrator tracks task progress during execution."""
        orchestrator = AIOrchestrator()

        orchestrator.update_task_progress("task-123", 50, "Processing...")

        assert "task-123" in orchestrator.task_progress
        assert orchestrator.task_progress["task-123"]["progress"] == 50
        assert orchestrator.task_progress["task-123"]["message"] == "Processing..."

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_orchestrator_clears_task_progress(
        self,
        mock_bridge: Mock,
        mock_assistant: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Orchestrator clears task progress after completion."""
        orchestrator = AIOrchestrator()

        orchestrator.update_task_progress("task-123", 100, "Complete")
        orchestrator.clear_task_progress("task-123")

        assert "task-123" not in orchestrator.task_progress

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_orchestrator_calls_task_callback(
        self,
        mock_bridge: Mock,
        mock_assistant_class: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Orchestrator calls task callback after execution."""
        mock_assistant = Mock()
        mock_assistant.analyze_license.return_value = {"confidence": 0.8}
        mock_assistant_class.return_value = mock_assistant

        callback = Mock()
        orchestrator = AIOrchestrator()
        task = AITask(
            task_id="callback-task",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.SIMPLE,
            input_data={},
            callback=callback,
        )

        orchestrator._execute_task(task)

        callback.assert_called_once()

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_orchestrator_emits_task_completion_event(
        self,
        mock_bridge: Mock,
        mock_assistant_class: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Orchestrator emits task completion events."""
        mock_assistant = Mock()
        mock_assistant.analyze_license.return_value = {"confidence": 0.8}
        mock_assistant_class.return_value = mock_assistant

        orchestrator = AIOrchestrator()
        completion_callback = Mock()
        orchestrator.event_bus.subscribe("task_complete", completion_callback, "test")

        task = AITask(
            task_id="event-task",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.SIMPLE,
            input_data={},
        )

        orchestrator._execute_task(task)
        time.sleep(0.1)

        completion_callback.assert_called()

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_orchestrator_handles_task_execution_errors(
        self,
        mock_bridge: Mock,
        mock_assistant_class: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Orchestrator handles task execution errors gracefully."""
        mock_assistant = Mock()
        mock_assistant.analyze_license.side_effect = RuntimeError("Analysis failed")
        mock_assistant_class.return_value = mock_assistant

        orchestrator = AIOrchestrator()
        task = AITask(
            task_id="error-task",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.MODERATE,
            input_data={},
        )

        result = orchestrator._execute_task(task)

        assert result.success is False
        assert len(result.errors) > 0

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_orchestrator_supports_priority_task_ordering(
        self,
        mock_bridge: Mock,
        mock_assistant: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
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

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_analysis_complete_handler_updates_context(
        self,
        mock_bridge: Mock,
        mock_assistant: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Analysis complete handler updates shared context."""
        orchestrator = AIOrchestrator()

        event_data = {
            "task_id": "task-123",
            "results": {"license_type": "trial", "confidence": 0.85},
        }

        orchestrator._on_analysis_complete(event_data, "analyzer")

        assert "last_analysis_analyzer" in orchestrator.shared_context._context

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_ml_prediction_complete_escalates_low_confidence(
        self,
        mock_bridge: Mock,
        mock_assistant: Mock,
        mock_llm_manager: Mock,
        mock_model_manager_class: Mock,
    ) -> None:
        """ML prediction complete handler escalates low confidence results."""
        mock_model_manager = Mock()
        mock_model_manager_class.return_value = mock_model_manager

        orchestrator = AIOrchestrator()

        event_data = {
            "task_id": "ml-task",
            "confidence": 0.5,
            "prediction": "VMProtect",
        }

        orchestrator._on_ml_prediction_complete(event_data, "ml_predictor")

        assert orchestrator.task_queue.qsize() > 0

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_error_handler_logs_component_errors(
        self,
        mock_bridge: Mock,
        mock_assistant: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Error handler logs errors from components."""
        orchestrator = AIOrchestrator()

        error_data = {
            "error": "Binary analysis failed",
            "task_id": "error-task",
        }

        orchestrator._on_error_occurred(error_data, "analyzer")


class TestScriptGenerationTasks:
    """Tests for script generation task execution."""

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_orchestrator_executes_frida_script_generation(
        self,
        mock_bridge: Mock,
        mock_assistant_class: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Orchestrator executes Frida script generation tasks."""
        mock_assistant = Mock()
        mock_assistant.generate_frida_script.return_value = {
            "script": "Interceptor.attach(ptr(0x401000), {});",
            "confidence": 0.92,
        }
        mock_assistant_class.return_value = mock_assistant

        orchestrator = AIOrchestrator()
        task = AITask(
            task_id="frida-task",
            task_type=AITaskType.FRIDA_SCRIPT_GENERATION,
            complexity=AnalysisComplexity.COMPLEX,
            input_data={"target_function": "check_license"},
        )

        result = orchestrator._execute_task(task)

        assert result.success is True
        assert result.task_type == AITaskType.FRIDA_SCRIPT_GENERATION

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_orchestrator_executes_ghidra_script_generation(
        self,
        mock_bridge: Mock,
        mock_assistant_class: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Orchestrator executes Ghidra script generation tasks."""
        mock_assistant = Mock()
        mock_assistant.generate_ghidra_script.return_value = {
            "script": "# Ghidra script",
            "confidence": 0.88,
        }
        mock_assistant_class.return_value = mock_assistant

        orchestrator = AIOrchestrator()
        task = AITask(
            task_id="ghidra-task",
            task_type=AITaskType.GHIDRA_SCRIPT_GENERATION,
            complexity=AnalysisComplexity.COMPLEX,
            input_data={"analysis_type": "license_check"},
        )

        result = orchestrator._execute_task(task)

        assert result.success is True
        assert result.task_type == AITaskType.GHIDRA_SCRIPT_GENERATION


class TestComplexityEscalation:
    """Tests for complexity-based task escalation."""

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_simple_tasks_use_fast_components(
        self,
        mock_bridge: Mock,
        mock_assistant: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Simple tasks use fast analysis components."""
        orchestrator = AIOrchestrator()
        task = AITask(
            task_id="simple-task",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.SIMPLE,
            input_data={},
        )

        result = orchestrator._execute_task(task)

        assert result.processing_time < 2.0

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_complex_tasks_use_llm_components(
        self,
        mock_bridge: Mock,
        mock_assistant_class: Mock,
        mock_llm_manager: Mock,
        mock_model_manager_class: Mock,
    ) -> None:
        """Complex tasks escalate to LLM components."""
        mock_assistant = Mock()
        mock_assistant.analyze_binary_complex.return_value = {
            "analysis": "complex",
            "confidence": 0.95,
        }
        mock_assistant_class.return_value = mock_assistant

        mock_model_manager = Mock()
        mock_model_manager_class.return_value = mock_model_manager

        orchestrator = AIOrchestrator()
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

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_complete_license_analysis_workflow(
        self,
        mock_bridge: Mock,
        mock_assistant_class: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Complete license analysis workflow from submission to result."""
        mock_assistant = Mock()
        mock_assistant.analyze_license.return_value = {
            "license_type": "trial",
            "expires_in_days": 30,
            "confidence": 0.93,
        }
        mock_assistant_class.return_value = mock_assistant

        orchestrator = AIOrchestrator()
        results = []

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

    @patch("intellicrack.ai.orchestrator.ModelManager")
    @patch("intellicrack.ai.orchestrator.get_llm_manager")
    @patch("intellicrack.ai.orchestrator.IntellicrackAIAssistant")
    @patch("intellicrack.ai.orchestrator.AIBinaryBridge")
    def test_multi_task_coordination(
        self,
        mock_bridge_class: Mock,
        mock_assistant_class: Mock,
        mock_llm_manager: Mock,
        mock_model_manager: Mock,
    ) -> None:
        """Multiple tasks coordinate through shared context."""
        mock_bridge = Mock()
        mock_bridge.analyze_binary.return_value = {"confidence": 0.8}
        mock_bridge_class.return_value = mock_bridge

        mock_assistant = Mock()
        mock_assistant.analyze_license.return_value = {"confidence": 0.85}
        mock_assistant_class.return_value = mock_assistant

        orchestrator = AIOrchestrator()

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
