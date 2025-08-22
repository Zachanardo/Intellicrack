"""AI Orchestrator for Intellicrack

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

import json
import logging
import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from intellicrack.logger import logger

from ..utils.logger import get_logger

# Local imports
try:
    from ..hexview.ai_bridge import AIBinaryBridge
    from .ai_assistant_enhanced import IntellicrackAIAssistant
    from .llm_backends import LLMManager, LLMMessage, LLMResponse, get_llm_manager
    from .model_manager_module import ModelManager
except ImportError as e:
    logger.error("Import error in orchestrator: %s", e)
    # Fallback for testing
    ModelManager = None
    IntellicrackAIAssistant = None
    LLMManager = None
    get_llm_manager = None
    LLMMessage = None
    LLMResponse = None
    AIBinaryBridge = None

logger = get_logger(__name__)


class AnalysisComplexity(Enum):
    """Defines the complexity level of analysis tasks."""

    SIMPLE = "simple"  # Use fast detection tools only
    MODERATE = "moderate"  # Use detection tools + basic LLM
    COMPLEX = "complex"  # Use full agentic reasoning
    CRITICAL = "critical"  # Use all available AI resources


class AITaskType(Enum):
    """Types of AI tasks in the system."""

    VULNERABILITY_SCAN = "vulnerability_scan"
    LICENSE_ANALYSIS = "license_analysis"
    PATTERN_RECOGNITION = "pattern_recognition"
    CODE_GENERATION = "code_generation"
    BINARY_ANALYSIS = "binary_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    PATCHING = "patching"
    REASONING = "reasoning"
    # Script Generation Tasks
    FRIDA_SCRIPT_GENERATION = "frida_script_generation"
    GHIDRA_SCRIPT_GENERATION = "ghidra_script_generation"
    UNIFIED_SCRIPT_GENERATION = "unified_script_generation"
    SCRIPT_TESTING = "script_testing"
    SCRIPT_REFINEMENT = "script_refinement"
    AUTONOMOUS_WORKFLOW = "autonomous_workflow"


@dataclass
class AITask:
    """Represents an AI task to be processed."""

    task_id: str
    task_type: AITaskType
    complexity: AnalysisComplexity
    input_data: dict[str, Any]
    priority: int = 5  # 1-10, 10 being highest
    created_at: datetime = field(default_factory=datetime.now)
    context: dict[str, Any] = field(default_factory=dict)
    callback: Callable | None = None


@dataclass
class AIResult:
    """Represents the result of an AI task."""

    task_id: str
    task_type: AITaskType
    success: bool
    result_data: dict[str, Any]
    confidence: float
    processing_time: float
    components_used: list[str]
    completed_at: datetime = field(default_factory=datetime.now)
    errors: list[str] = field(default_factory=list)


class AISharedContext:
    """Shared context and memory for AI workflows."""

    def __init__(self):
        """Initialize the shared context for AI workflows.

        Creates a thread-safe context store for sharing data between AI components,
        including binary metadata, analysis results, model predictions, and workflow state.
        """
        self._context = {
            "current_binary": None,
            "binary_metadata": {},
            "analysis_results": {},
            "model_predictions": {},
            "user_session": {},
            "workflow_state": {},
            "cached_analyses": {},
            "global_patterns": [],
        }
        self._lock = threading.RLock()

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from shared context."""
        with self._lock:
            return self._context.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a value in shared context."""
        with self._lock:
            self._context[key] = value

    def update(self, updates: dict[str, Any]) -> None:
        """Update multiple values in shared context."""
        with self._lock:
            self._context.update(updates)

    def get_analysis_cache(self, binary_hash: str) -> dict | None:
        """Get cached analysis results for a binary."""
        with self._lock:
            return self._context["cached_analyses"].get(binary_hash)

    def cache_analysis(self, binary_hash: str, results: dict) -> None:
        """Cache analysis results for a binary."""
        with self._lock:
            self._context["cached_analyses"][binary_hash] = {
                "results": results,
                "timestamp": datetime.now(),
                "access_count": 0,
            }

    def clear_session(self) -> None:
        """Clear session-specific data."""
        with self._lock:
            self._context["user_session"] = {}
            self._context["workflow_state"] = {}


class AIEventBus:
    """Event bus for AI component communication."""

    def __init__(self):
        """Initialize the AI event bus for component communication.

        Creates a thread-safe publish-subscribe system for AI components
        to communicate through events.
        """
        self._subscribers = {}
        self._lock = threading.RLock()
        logger.info("AI Event Bus initialized")

    def subscribe(self, event_type: str, callback: Callable, component_name: str) -> None:
        """Subscribe to specific events."""
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []

            self._subscribers[event_type].append(
                {
                    "callback": callback,
                    "component": component_name,
                }
            )

        logger.debug("Component %s subscribed to %s", component_name, event_type)

    def emit(self, event_type: str, data: dict[str, Any], source_component: str) -> None:
        """Emit an event to all subscribers."""
        with self._lock:
            subscribers = self._subscribers.get(event_type, [])

        if subscribers:
            logger.debug(
                "Emitting %s from %s to %d subscribers",
                event_type,
                source_component,
                len(subscribers),
            )

            for _subscriber in subscribers:
                try:
                    # Call subscriber in a separate thread to avoid blocking
                    def call_subscriber(sub):
                        """Call a subscriber's callback function with event data.

                        Args:
                            sub: Subscriber dictionary containing 'callback' and 'component' keys

                        Executes the subscriber's callback with the event data and source component.
                        Catches and logs any errors that occur during callback execution.

                        """
                        try:
                            sub["callback"](data, source_component)
                        except (OSError, ValueError, RuntimeError) as e:
                            logger.error("Error in subscriber %s: %s", sub["component"], e)

                    threading.Thread(
                        target=lambda: call_subscriber(_subscriber), daemon=True
                    ).start()

                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error calling subscriber %s: %s", _subscriber["component"], e)

    def unsubscribe(self, event_type: str, component_name: str) -> None:
        """Unsubscribe a component from an event type."""
        with self._lock:
            if event_type in self._subscribers:
                self._subscribers[event_type] = [
                    _sub
                    for _sub in self._subscribers[event_type]
                    if _sub["component"] != component_name
                ]


class AIOrchestrator:
    """Central AI Orchestrator for Intellicrack

    Coordinates between fast ML models and intelligent LLM agents,
    creating a truly agentic environment that leverages the strengths
    of each component type.
    """

    def __init__(self):
        """Initialize the AI orchestrator.

        Sets up the shared context, event bus, task queue, and starts the task processing
        thread for coordinating AI component workflows.
        """
        self.logger = logging.getLogger(__name__ + ".AIOrchestrator")
        logger.info("Initializing AI Orchestrator...")

        # Initialize shared systems
        self.shared_context = AISharedContext()
        self.event_bus = AIEventBus()
        self.task_queue = queue.PriorityQueue()
        self.active_tasks = {}
        self.is_running = False

        # Progress tracking
        self.task_progress = {}
        self.progress_callbacks = {}

        # Initialize AI components
        self._initialize_components()

        # Set up event subscriptions
        self._setup_event_subscriptions()

        # Start task processing thread
        self.processing_thread = None
        self.start_processing()

        logger.info("AI Orchestrator initialized successfully")

    def _initialize_components(self):
        """Initialize all AI components."""
        logger.info("Initializing AI components...")

        # ML predictor functionality has been removed
        self.ml_predictor = None

        # Large model manager for complex reasoning
        try:
            if ModelManager:
                self.model_manager = ModelManager()
                logger.info("Model Manager initialized")
            else:
                self.model_manager = None
                logger.warning("Model Manager not available")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize Model Manager: %s", e)
            self.model_manager = None

        # LLM manager for GGUF and API-based models
        try:
            if get_llm_manager:
                self.llm_manager = get_llm_manager()
                logger.info("LLM Manager initialized for agentic workflows")
            else:
                self.llm_manager = None
                logger.warning("LLM Manager not available")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize LLM Manager: %s", e)
            self.llm_manager = None

        # AI assistant for tool-based workflows
        try:
            if IntellicrackAIAssistant:
                self.ai_assistant = IntellicrackAIAssistant()
                # Store the system prompt for use with LLM calls
                self.system_prompt = self.ai_assistant.get_system_prompt()
                logger.info("AI Assistant initialized with system prompt")
            else:
                self.ai_assistant = None
                self.system_prompt = None
                logger.warning("AI Assistant not available")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize AI Assistant: %s", e)
            self.ai_assistant = None
            self.system_prompt = None

        # Hex viewer AI bridge
        try:
            if AIBinaryBridge:
                self.hex_bridge = AIBinaryBridge()
                logger.info("Hex AI Bridge initialized")
            else:
                self.hex_bridge = None
                logger.warning("Hex AI Bridge not available")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize Hex Bridge: %s", e)
            self.hex_bridge = None

    def _setup_event_subscriptions(self):
        """Set up event subscriptions for component coordination."""
        # Subscribe to analysis completion events
        self.event_bus.subscribe("analysis_complete", self._on_analysis_complete, "orchestrator")
        self.event_bus.subscribe(
            "ml_prediction_complete", self._on_ml_prediction_complete, "orchestrator"
        )
        self.event_bus.subscribe("model_loaded", self._on_model_loaded, "orchestrator")
        self.event_bus.subscribe("error_occurred", self._on_error_occurred, "orchestrator")

    def _on_analysis_complete(self, data: dict[str, Any], source: str):
        """Handle analysis completion events."""
        logger.info("Analysis complete from %s: %s", source, data.get("task_id", "unknown"))

        # Update shared context with results
        if "results" in data:
            self.shared_context.update(
                {
                    f"last_analysis_{source}": data["results"],
                    f"last_analysis_time_{source}": datetime.now(),
                }
            )

    def _on_ml_prediction_complete(self, data: dict[str, Any], source: str):
        """Handle ML prediction completion events."""
        logger.info("ML prediction complete from %s", source)

        # Check if we need to escalate to complex analysis
        confidence = data.get("confidence", 0.0)
        if confidence < 0.7:  # Low confidence, use LLM for verification
            self._escalate_to_complex_analysis(data)

    def _on_model_loaded(self, data: dict[str, Any], source: str):
        """Handle model loading events."""
        logger.info("Model loaded in %s: %s", source, data.get("model_name", "unknown"))

    def _on_error_occurred(self, data: dict[str, Any], source: str):
        """Handle error events."""
        logger.error("Error in %s: %s", source, data.get("error", "unknown error"))

    def _escalate_to_complex_analysis(self, ml_data: dict[str, Any]):
        """Escalate low-confidence ML results to complex LLM analysis."""
        if self.model_manager:
            logger.info("Escalating to complex analysis due to low ML confidence")
            # Create complex analysis task
            task = AITask(
                task_id=f"escalated_{ml_data.get('task_id', 'unknown')}",
                task_type=AITaskType.REASONING,
                complexity=AnalysisComplexity.COMPLEX,
                input_data={
                    "ml_results": ml_data,
                    "escalation_reason": "low_confidence",
                },
            )
            self.submit_task(task)

    def start_processing(self):
        """Start the task processing thread."""
        if not self.is_running:
            self.is_running = True
            self.processing_thread = threading.Thread(target=self._process_tasks, daemon=True)
            self.processing_thread.start()
            logger.info("Task processing started")

    def stop_processing(self):
        """Stop the task processing thread."""
        self.is_running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        logger.info("Task processing stopped")

    def _process_tasks(self):
        """Main task processing loop."""
        while self.is_running:
            try:
                # Get next task (blocking with timeout)
                try:
                    # Priority queue returns (priority, task)
                    _, task = self.task_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                # Process the task
                self._execute_task(task)

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in task processing loop: %s", e)

    def _execute_task(self, task: AITask) -> AIResult:
        """Execute an AI task using the appropriate components."""
        start_time = datetime.now()
        result_data = {}
        components_used = []
        errors = []
        success = False
        confidence = 0.0

        try:
            logger.info(
                "Executing task %s (type: %s, complexity: %s)",
                task.task_id,
                task.task_type,
                task.complexity,
            )

            # Initialize progress tracking
            self.update_task_progress(task.task_id, 0, "Starting task execution...")

            # Route task based on type and complexity
            self.update_task_progress(task.task_id, 10, "Routing task to appropriate component...")

            if task.task_type == AITaskType.VULNERABILITY_SCAN:
                self.update_task_progress(task.task_id, 20, "Executing vulnerability scan...")
                result_data, components_used, confidence = self._execute_vulnerability_scan(task)
                success = True

            elif task.task_type == AITaskType.LICENSE_ANALYSIS:
                self.update_task_progress(task.task_id, 20, "Analyzing license patterns...")
                result_data, components_used, confidence = self._execute_license_analysis(task)
                success = True

            elif task.task_type == AITaskType.BINARY_ANALYSIS:
                self.update_task_progress(task.task_id, 20, "Performing binary analysis...")
                result_data, components_used, confidence = self._execute_binary_analysis(task)
                success = True

            elif task.task_type == AITaskType.REASONING:
                self.update_task_progress(task.task_id, 20, "Processing reasoning task...")
                result_data, components_used, confidence = self._execute_reasoning_task(task)
                success = True

            elif task.task_type == AITaskType.FRIDA_SCRIPT_GENERATION:
                self.update_task_progress(task.task_id, 20, "Generating Frida script...")
                result_data, components_used, confidence = self._execute_frida_script_generation(
                    task
                )
                success = True

            elif task.task_type == AITaskType.GHIDRA_SCRIPT_GENERATION:
                self.update_task_progress(task.task_id, 20, "Generating Ghidra script...")
                result_data, components_used, confidence = self._execute_ghidra_script_generation(
                    task
                )
                success = True

            elif task.task_type == AITaskType.UNIFIED_SCRIPT_GENERATION:
                self.update_task_progress(task.task_id, 20, "Generating unified scripts...")
                result_data, components_used, confidence = self._execute_unified_script_generation(
                    task
                )
                success = True

            elif task.task_type == AITaskType.SCRIPT_TESTING:
                self.update_task_progress(task.task_id, 20, "Testing generated scripts...")
                result_data, components_used, confidence = self._execute_script_testing(task)
                success = True

            elif task.task_type == AITaskType.SCRIPT_REFINEMENT:
                self.update_task_progress(task.task_id, 20, "Refining script quality...")
                result_data, components_used, confidence = self._execute_script_refinement(task)
                success = True

            elif task.task_type == AITaskType.AUTONOMOUS_WORKFLOW:
                self.update_task_progress(task.task_id, 20, "Executing autonomous workflow...")
                result_data, components_used, confidence = self._execute_autonomous_workflow(task)
                success = True

            else:
                self.update_task_progress(
                    task.task_id, 0, f"Error: Unknown task type {task.task_type}"
                )
                errors.append(f"Unknown task type: {task.task_type}")
                logger.warning("Unknown task type: %s", task.task_type)

        except (OSError, ValueError, RuntimeError) as e:
            errors.append(str(e))
            logger.error("Error executing task %s: %s", task.task_id, e)
            self.update_task_progress(task.task_id, 0, f"Error: {e!s}")

        # Update progress to completion
        if success:
            self.update_task_progress(task.task_id, 90, "Finalizing results...")

        # Create result
        processing_time = (datetime.now() - start_time).total_seconds()
        result = AIResult(
            task_id=task.task_id,
            task_type=task.task_type,
            success=success,
            result_data=result_data,
            confidence=confidence,
            processing_time=processing_time,
            components_used=components_used,
            errors=errors,
        )

        # Mark task as completed
        if success:
            self.update_task_progress(task.task_id, 100, "Task completed successfully!")
        else:
            self.update_task_progress(task.task_id, 0, "Task failed with errors")

        # Emit completion event
        self.event_bus.emit(
            "task_complete",
            {
                "task_id": task.task_id,
                "success": success,
                "result": result_data,
            },
            "orchestrator",
        )

        # Call callback if provided
        if task.callback:
            try:
                task.callback(result)
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in task callback: %s", e)

        # Clear progress tracking after short delay (keep for UI feedback)
        def clear_progress():
            import time

            time.sleep(5)  # Keep progress visible for 5 seconds
            self.clear_task_progress(task.task_id)

        threading.Thread(target=clear_progress, daemon=True).start()

        return result

    def _execute_vulnerability_scan(self, task: AITask) -> tuple:
        """Execute vulnerability scanning task."""
        components_used = []
        result_data = {}
        confidence = 0.0

        binary_path = task.input_data.get("binary_path")
        if not binary_path:
            raise ValueError("No binary_path provided for vulnerability scan")

        # ML prediction functionality has been removed
        ml_results = None
        confidence = 0.0

        # Escalate to LLM if complexity requires it or ML confidence is low
        if (
            task.complexity in [AnalysisComplexity.COMPLEX, AnalysisComplexity.CRITICAL]
            or confidence < 0.7
        ):
            if self.model_manager and self.ai_assistant:
                try:
                    # Use AI assistant for complex analysis
                    if hasattr(self.ai_assistant, "analyze_binary_complex"):
                        llm_results = self.ai_assistant.analyze_binary_complex(
                            binary_path, ml_results
                        )
                    elif hasattr(self.ai_assistant, "analyze_binary"):
                        llm_results = self.ai_assistant.analyze_binary(binary_path)
                    else:
                        raise AttributeError("No analysis method available")
                    result_data["llm_analysis"] = llm_results
                    components_used.append("ai_assistant")

                    # Combine confidences
                    confidence = max(confidence, llm_results.get("confidence", 0.0))

                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("LLM analysis failed: %s", e)

        return result_data, components_used, confidence

    def _execute_license_analysis(self, task: AITask) -> tuple:
        """Execute license analysis task."""
        components_used = []
        result_data = {}
        confidence = 0.0

        # License analysis typically requires LLM reasoning
        if self.ai_assistant:
            try:
                if hasattr(self.ai_assistant, "analyze_license_patterns"):
                    license_results = self.ai_assistant.analyze_license_patterns(task.input_data)
                elif hasattr(self.ai_assistant, "analyze_license"):
                    license_results = self.ai_assistant.analyze_license(task.input_data)
                else:
                    raise AttributeError("No license analysis method available")
                result_data["license_analysis"] = license_results
                components_used.append("ai_assistant")
                # License analysis is typically high confidence
                confidence = license_results.get("confidence", 0.8)

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("License analysis failed: %s", e)

        return result_data, components_used, confidence

    def _execute_binary_analysis(self, task: AITask) -> tuple:
        """Execute binary analysis task."""
        components_used = []
        result_data = {}
        confidence = 0.0

        binary_path = task.input_data.get("binary_path")

        # Use hex bridge for binary-specific analysis
        if self.hex_bridge:
            try:
                if hasattr(self.hex_bridge, "analyze_binary_patterns"):
                    hex_results = self.hex_bridge.analyze_binary_patterns(binary_path)
                elif hasattr(self.hex_bridge, "analyze_binary"):
                    hex_results = self.hex_bridge.analyze_binary(binary_path)
                else:
                    raise AttributeError("No binary analysis method available")
                result_data["hex_analysis"] = hex_results
                components_used.append("hex_bridge")
                confidence = hex_results.get("confidence", 0.7)

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Hex analysis failed: %s", e)

        # ML feature analysis functionality has been removed

        # Add AI-enhanced complex binary analysis
        if self.ai_assistant and hasattr(self.ai_assistant, "analyze_binary_complex"):
            try:
                # Prepare ML results for AI analysis
                ml_results_for_ai = {
                    "confidence": confidence,
                    "predictions": [],
                }

                # Include ML features if available
                if "ml_features" in result_data:
                    ml_results_for_ai["ml_features"] = result_data["ml_features"]

                # Include hex analysis patterns
                if "hex_analysis" in result_data:
                    ml_results_for_ai["hex_patterns"] = result_data["hex_analysis"]

                # Run AI complex analysis
                ai_complex_results = self.ai_assistant.analyze_binary_complex(
                    binary_path,
                    ml_results_for_ai,
                )

                if ai_complex_results and not ai_complex_results.get("error"):
                    result_data["ai_complex_analysis"] = ai_complex_results
                    components_used.append("ai_assistant_complex")
                    confidence = max(confidence, ai_complex_results.get("confidence", 0.0))

                    logger.info(
                        f"AI complex analysis completed with confidence: {ai_complex_results.get('confidence', 0.0)}"
                    )

            except Exception as e:
                logger.error(f"AI complex binary analysis failed: {e}")

        return result_data, components_used, confidence

    def _execute_reasoning_task(self, task: AITask) -> tuple:
        """Execute complex reasoning task."""
        components_used = []
        result_data = {}
        confidence = 0.0

        # Use LLM manager for reasoning tasks if available
        if self.llm_manager and self.llm_manager.get_available_llms():
            try:
                # Prepare reasoning messages with the AI assistant's system prompt
                system_content = (
                    self.system_prompt
                    if self.system_prompt
                    else """You are an autonomous binary analysis expert orchestrator integrated into Intellicrack.
                    You excel at autonomous workflow management and comprehensive analysis reasoning. Analyze provided data and autonomously orchestrate complete binary analysis workflows.
                    Provide expert-level reasoning about binary security, vulnerabilities, and comprehensive recommendations. Make autonomous decisions about workflow execution and tool orchestration.
                    Be specific, actionable, and focus on complete autonomous execution of security analysis workflows."""
                )

                messages = [
                    LLMMessage(role="system", content=system_content),
                    LLMMessage(
                        role="user",
                        content=f"Analyze this data and provide reasoning: {json.dumps(task.input_data, indent=2)}",
                    ),
                ]

                # Get LLM response
                response = self.llm_manager.chat(messages)

                if response and response.content:
                    reasoning_results = {
                        "analysis": response.content,
                        "confidence": 0.85,  # LLM reasoning typically high confidence
                        "model_used": response.model,
                        "reasoning_type": "llm_analysis",
                        "recommendations": self._extract_recommendations(response.content),
                    }

                    result_data["reasoning"] = reasoning_results
                    components_used.append("llm_manager")
                    confidence = 0.85

                    logger.info("LLM reasoning completed using model: %s", response.model)
                else:
                    logger.warning("LLM returned empty response")

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("LLM reasoning failed: %s", e)

        # Fallback to AI assistant if LLM not available
        elif self.ai_assistant:
            try:
                if hasattr(self.ai_assistant, "perform_reasoning"):
                    reasoning_results = self.ai_assistant.perform_reasoning(task.input_data)
                elif hasattr(self.ai_assistant, "analyze_complex"):
                    reasoning_results = self.ai_assistant.analyze_complex(task.input_data)
                else:
                    raise AttributeError("No reasoning method available")
                result_data["reasoning"] = reasoning_results
                components_used.append("ai_assistant")
                confidence = reasoning_results.get("confidence", 0.8)

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("AI Assistant reasoning failed: %s", e)

        return result_data, components_used, confidence

    def _extract_recommendations(self, content: str) -> list[str]:
        """Extract actionable recommendations from LLM response."""
        recommendations = []

        # Look for common recommendation patterns
        lines = content.split("\n")
        for _line in lines:
            line = _line.strip()
            if any(
                _keyword in line.lower()
                for _keyword in ["recommend", "suggest", "should", "consider"]
            ):
                if len(line) > 20 and len(line) < 200:  # Reasonable length
                    recommendations.append(line)

        return recommendations[:5]  # Limit to top 5 recommendations

    def _execute_frida_script_generation(self, task: AITask) -> tuple:
        """Execute Frida script generation task."""
        components_used = []
        result_data = {}
        confidence = 0.0

        try:
            # Import AI script generator
            from .ai_script_generator import AIScriptGenerator

            # Create script generator if not available
            script_generator = AIScriptGenerator(self)
            components_used.append("ai_script_generator")

            # Extract task parameters
            binary_path = task.input_data.get("binary_path", "unknown")
            analysis_data = task.input_data.get("analysis_data", {})

            # Generate Frida script
            generated_script = script_generator.generate_frida_script(analysis_data)

            if generated_script:
                result_data["script"] = generated_script.content
                result_data["metadata"] = {
                    "script_id": generated_script.metadata.script_id,
                    "script_type": generated_script.metadata.script_type.value,
                    "target_binary": generated_script.metadata.target_binary,
                    "protection_types": [
                        p.value for p in generated_script.metadata.protection_types
                    ],
                    "success_probability": generated_script.metadata.success_probability,
                    "entry_point": generated_script.entry_point,
                    "dependencies": generated_script.dependencies,
                    "hooks": generated_script.hooks,
                    "patches": generated_script.patches,
                }
                confidence = generated_script.metadata.success_probability

                logger.info(
                    "Generated Frida script for %s with %d%% confidence",
                    binary_path,
                    int(confidence * 100),
                )
            else:
                result_data["error"] = "Failed to generate Frida script"
                confidence = 0.0

        except Exception as e:
            logger.error("Frida script generation failed: %s", e)
            result_data["error"] = str(e)
            confidence = 0.0

        return result_data, components_used, confidence

    def _execute_ghidra_script_generation(self, task: AITask) -> tuple:
        """Execute Ghidra script generation task."""
        components_used = []
        result_data = {}
        confidence = 0.0

        try:
            # Import AI script generator
            from .ai_script_generator import AIScriptGenerator

            # Create script generator if not available
            script_generator = AIScriptGenerator(self)
            components_used.append("ai_script_generator")

            # Extract task parameters
            binary_path = task.input_data.get("binary_path", "unknown")
            analysis_data = task.input_data.get("analysis_data", {})

            # Generate Ghidra script
            generated_script = script_generator.generate_ghidra_script(analysis_data)

            if generated_script:
                result_data["script"] = generated_script.content
                result_data["metadata"] = {
                    "script_id": generated_script.metadata.script_id,
                    "script_type": generated_script.metadata.script_type.value,
                    "target_binary": generated_script.metadata.target_binary,
                    "protection_types": [
                        p.value for p in generated_script.metadata.protection_types
                    ],
                    "success_probability": generated_script.metadata.success_probability,
                    "entry_point": generated_script.entry_point,
                    "dependencies": generated_script.dependencies,
                    "hooks": generated_script.hooks,
                    "patches": generated_script.patches,
                }
                confidence = generated_script.metadata.success_probability

                logger.info(
                    "Generated Ghidra script for %s with %d%% confidence",
                    binary_path,
                    int(confidence * 100),
                )
            else:
                result_data["error"] = "Failed to generate Ghidra script"
                confidence = 0.0

        except Exception as e:
            logger.error("Ghidra script generation failed: %s", e)
            result_data["error"] = str(e)
            confidence = 0.0

        return result_data, components_used, confidence

    def _execute_unified_script_generation(self, task: AITask) -> tuple:
        """Execute unified script generation task (both Frida and Ghidra)."""
        components_used = []
        result_data = {}
        confidence = 0.0

        try:
            # Import AI script generator
            from .ai_script_generator import AIScriptGenerator

            # Create script generator if not available
            script_generator = AIScriptGenerator(self)
            components_used.append("ai_script_generator")

            # Extract task parameters
            binary_path = task.input_data.get("binary_path", "unknown")
            analysis_data = task.input_data.get("analysis_data", {})

            # Generate both scripts
            frida_script = script_generator.generate_frida_script(analysis_data)
            ghidra_script = script_generator.generate_ghidra_script(analysis_data)

            scripts = {}
            confidences = []

            if frida_script:
                scripts["frida"] = {
                    "script": frida_script.content,
                    "metadata": {
                        "script_id": frida_script.metadata.script_id,
                        "success_probability": frida_script.metadata.success_probability,
                        "entry_point": frida_script.entry_point,
                        "dependencies": frida_script.dependencies,
                        "hooks": frida_script.hooks,
                    },
                }
                confidences.append(frida_script.metadata.success_probability)

            if ghidra_script:
                scripts["ghidra"] = {
                    "script": ghidra_script.content,
                    "metadata": {
                        "script_id": ghidra_script.metadata.script_id,
                        "success_probability": ghidra_script.metadata.success_probability,
                        "entry_point": ghidra_script.entry_point,
                        "dependencies": ghidra_script.dependencies,
                        "patches": ghidra_script.patches,
                    },
                }
                confidences.append(ghidra_script.metadata.success_probability)

            result_data["scripts"] = scripts
            confidence = max(confidences) if confidences else 0.0

            logger.info(
                "Generated unified scripts for %s with %d%% max confidence",
                binary_path,
                int(confidence * 100),
            )

        except Exception as e:
            logger.error("Unified script generation failed: %s", e)
            result_data["error"] = str(e)
            confidence = 0.0

        return result_data, components_used, confidence

    def _execute_script_testing(self, task: AITask) -> tuple:
        """Execute script testing task."""
        components_used = []
        result_data = {}
        confidence = 0.0

        try:
            # Import QEMU test manager
            from .qemu_manager import QEMUManager

            # Create test manager
            test_manager = QEMUManager()
            components_used.append("qemu_manager")

            # Extract task parameters
            script_content = task.input_data.get("script_content", "")
            script_type = task.input_data.get("script_type", "frida")
            binary_path = task.input_data.get("binary_path", "unknown")

            # Create QEMU snapshot
            snapshot_id = test_manager.create_snapshot(binary_path)

            # Test script based on type
            if script_type.lower() == "frida":
                test_result = test_manager.test_frida_script(
                    snapshot_id, script_content, binary_path
                )
            else:
                test_result = test_manager.test_ghidra_script(
                    snapshot_id, script_content, binary_path
                )

            result_data["test_result"] = {
                "success": test_result.success,
                "output": test_result.output,
                "error": test_result.error,
                "exit_code": test_result.exit_code,
                "runtime_ms": test_result.runtime_ms,
                "snapshot_id": snapshot_id,
            }

            confidence = 0.9 if test_result.success else 0.3

            # Cleanup snapshot
            test_manager.cleanup_snapshot(snapshot_id)

            logger.info(
                "Script testing completed for %s: %s",
                binary_path,
                "SUCCESS" if test_result.success else "FAILED",
            )

        except Exception as e:
            logger.error("Script testing failed: %s", e)
            result_data["error"] = str(e)
            confidence = 0.0

        return result_data, components_used, confidence

    def _execute_script_refinement(self, task: AITask) -> tuple:
        """Execute script refinement task."""
        components_used = []
        result_data = {}
        confidence = 0.0

        try:
            # Import AI script generator
            from .ai_script_generator import AIScriptGenerator

            # Create script generator
            script_generator = AIScriptGenerator(self)
            components_used.append("ai_script_generator")

            # Extract task parameters
            original_script = task.input_data.get("original_script", "")
            test_results = task.input_data.get("test_results", {})
            analysis_data = task.input_data.get("analysis_data", {})

            # Refine script based on test results
            refined_script = script_generator.refine_script(
                original_script, test_results, analysis_data
            )

            if refined_script:
                result_data["refined_script"] = refined_script.content
                result_data["improvements"] = getattr(refined_script.metadata, "improvements", [])
                confidence = refined_script.metadata.success_probability

                logger.info(
                    "Script refinement completed with %d%% confidence", int(confidence * 100)
                )
            else:
                result_data["error"] = "Failed to refine script"
                confidence = 0.0

        except Exception as e:
            logger.error("Script refinement failed: %s", e)
            result_data["error"] = str(e)
            confidence = 0.0

        return result_data, components_used, confidence

    def _execute_autonomous_workflow(self, task: AITask) -> tuple:
        """Execute autonomous workflow task."""
        components_used = []
        result_data = {}
        confidence = 0.0

        try:
            # Import autonomous agent
            from .autonomous_agent import AutonomousAgent

            # Create autonomous agent
            agent = AutonomousAgent(orchestrator=self, cli_interface=None)
            components_used.append("autonomous_agent")

            # Extract task parameters
            user_request = task.input_data.get("user_request", "")

            # Process request autonomously
            workflow_result = agent.process_request(user_request)

            result_data.update(workflow_result)

            if workflow_result.get("status") == "success":
                confidence = 0.9
                scripts = workflow_result.get("scripts", [])
                logger.info(
                    "Autonomous workflow completed successfully with %d scripts", len(scripts)
                )
            else:
                confidence = 0.3
                logger.warning(
                    "Autonomous workflow failed: %s",
                    workflow_result.get("message", "Unknown error"),
                )

        except Exception as e:
            logger.error("Autonomous workflow failed: %s", e)
            result_data["error"] = str(e)
            confidence = 0.0

        return result_data, components_used, confidence

    def submit_task(self, task: AITask) -> str:
        """Submit a task for processing."""
        # Add to priority queue (negative priority for max-heap behavior)
        self.task_queue.put((-task.priority, task))
        self.active_tasks[task.task_id] = task

        logger.info("Task %s submitted with priority %s", task.task_id, task.priority)
        return task.task_id

    def get_task_status(self, task_id: str) -> dict[str, Any] | None:
        """Get the status of a task."""
        if task_id in self.active_tasks:
            return {
                "status": "active",
                "task": self.active_tasks[task_id],
            }
        return None

    def quick_vulnerability_scan(self, binary_path: str, callback: Callable | None = None) -> str:
        """Quick vulnerability scan using fast ML models."""
        task = AITask(
            task_id=f"vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            task_type=AITaskType.VULNERABILITY_SCAN,
            complexity=AnalysisComplexity.SIMPLE,
            input_data={"binary_path": binary_path},
            priority=7,
            callback=callback,
        )
        return self.submit_task(task)

    def complex_license_analysis(self, binary_path: str, callback: Callable | None = None) -> str:
        """Complex license analysis using LLM reasoning."""
        task = AITask(
            task_id=f"license_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.COMPLEX,
            input_data={"binary_path": binary_path},
            priority=8,
            callback=callback,
        )
        return self.submit_task(task)

    def comprehensive_analysis(self, binary_path: str, callback: Callable | None = None) -> str:
        """Comprehensive analysis using all available AI resources."""
        task = AITask(
            task_id=f"comprehensive_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            task_type=AITaskType.BINARY_ANALYSIS,
            complexity=AnalysisComplexity.CRITICAL,
            input_data={"binary_path": binary_path},
            priority=10,
            callback=callback,
        )
        return self.submit_task(task)

    def get_component_status(self) -> dict[str, Any]:
        """Get status of all AI components."""
        llm_status = {}
        if self.llm_manager:
            llm_status = {
                "available_llms": self.llm_manager.get_available_llms(),
                "active_llm": self.llm_manager.active_backend,
            }

        return {
            "model_manager": self.model_manager is not None,
            "llm_manager": self.llm_manager is not None,
            "llm_status": llm_status,
            "ai_assistant": self.ai_assistant is not None,
            "hex_bridge": self.hex_bridge is not None,
            "event_bus_subscribers": len(self.event_bus._subscribers),
            "active_tasks": len(self.active_tasks),
            "queue_size": self.task_queue.qsize(),
            "is_processing": self.is_running,
        }

    def register_progress_callback(
        self, task_id: str, callback: Callable[[str, int, str], None]
    ) -> None:
        """Register a progress callback for a specific task.

        Args:
            task_id: Task identifier
            callback: Function that takes (task_id, progress_percent, status_message)

        """
        self.progress_callbacks[task_id] = callback
        logger.debug(f"Registered progress callback for task {task_id}")

    def update_task_progress(self, task_id: str, progress: int, status: str = "") -> None:
        """Update progress for a specific task and notify callbacks.

        Args:
            task_id: Task identifier
            progress: Progress percentage (0-100)
            status: Status message

        """
        self.task_progress[task_id] = {
            "progress": progress,
            "status": status,
            "timestamp": datetime.now(),
        }

        # Emit progress event
        self.event_bus.emit(
            "task_progress",
            {
                "task_id": task_id,
                "progress": progress,
                "status": status,
            },
            "orchestrator",
        )

        # Call registered callback if exists
        if task_id in self.progress_callbacks:
            try:
                self.progress_callbacks[task_id](task_id, progress, status)
            except Exception as e:
                logger.error(f"Error calling progress callback for {task_id}: {e}")

        logger.debug(f"Task {task_id} progress: {progress}% - {status}")

    def get_task_progress(self, task_id: str) -> dict[str, Any] | None:
        """Get current progress for a task.

        Args:
            task_id: Task identifier

        Returns:
            Progress information or None if not found

        """
        return self.task_progress.get(task_id)

    def get_all_task_progress(self) -> dict[str, dict[str, Any]]:
        """Get progress information for all tasks."""
        return self.task_progress.copy()

    def clear_task_progress(self, task_id: str) -> None:
        """Clear progress information for a completed task."""
        self.task_progress.pop(task_id, None)
        self.progress_callbacks.pop(task_id, None)
        logger.debug(f"Cleared progress tracking for task {task_id}")

    def shutdown(self):
        """Shutdown the orchestrator and all components."""
        logger.info("Shutting down AI Orchestrator...")
        self.stop_processing()

        # Shutdown LLM manager
        if self.llm_manager:
            try:
                self.llm_manager.shutdown()
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error shutting down LLM manager: %s", e)

        self.shared_context.clear_session()
        logger.info("AI Orchestrator shutdown complete")


# Global orchestrator instance
_ORCHESTRATOR_INSTANCE = None


def get_orchestrator() -> AIOrchestrator:
    """Get the global AI orchestrator instance."""
    global _ORCHESTRATOR_INSTANCE  # pylint: disable=global-statement
    if _ORCHESTRATOR_INSTANCE is None:
        _ORCHESTRATOR_INSTANCE = AIOrchestrator()
    return _ORCHESTRATOR_INSTANCE


def shutdown_orchestrator():
    """Shutdown the global orchestrator instance."""
    global _ORCHESTRATOR_INSTANCE  # pylint: disable=global-statement
    if _ORCHESTRATOR_INSTANCE:
        _ORCHESTRATOR_INSTANCE.shutdown()
        _ORCHESTRATOR_INSTANCE = None
