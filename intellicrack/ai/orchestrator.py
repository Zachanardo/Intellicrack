"""
AI Orchestrator for Intellicrack 

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


import json
import queue
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

# Local imports
try:
    from ..hexview.ai_bridge import AIBinaryBridge
    from ..utils.logger import get_logger
    from .ai_assistant_enhanced import IntellicrackAIAssistant
    from .llm_backends import LLMManager, LLMMessage, LLMResponse, get_llm_manager
    from .ml_predictor import MLVulnerabilityPredictor
    from .model_manager_module import ModelManager
except ImportError:
    # Fallback for testing
    MLVulnerabilityPredictor = None
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
    SIMPLE = "simple"      # Use fast ML models only
    MODERATE = "moderate"  # Use ML + basic LLM
    COMPLEX = "complex"    # Use full agentic reasoning
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


@dataclass
class AITask:
    """Represents an AI task to be processed."""
    task_id: str
    task_type: AITaskType
    complexity: AnalysisComplexity
    input_data: Dict[str, Any]
    priority: int = 5  # 1-10, 10 being highest
    created_at: datetime = field(default_factory=datetime.now)
    context: Dict[str, Any] = field(default_factory=dict)
    callback: Optional[Callable] = None


@dataclass
class AIResult:
    """Represents the result of an AI task."""
    task_id: str
    task_type: AITaskType
    success: bool
    result_data: Dict[str, Any]
    confidence: float
    processing_time: float
    components_used: List[str]
    completed_at: datetime = field(default_factory=datetime.now)
    errors: List[str] = field(default_factory=list)


class AISharedContext:
    """Shared context and memory for AI workflows."""

    def __init__(self):
        self._context = {
            "current_binary": None,
            "binary_metadata": {},
            "analysis_results": {},
            "model_predictions": {},
            "user_session": {},
            "workflow_state": {},
            "cached_analyses": {},
            "global_patterns": []
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

    def update(self, updates: Dict[str, Any]) -> None:
        """Update multiple values in shared context."""
        with self._lock:
            self._context.update(updates)

    def get_analysis_cache(self, binary_hash: str) -> Optional[Dict]:
        """Get cached analysis results for a binary."""
        with self._lock:
            return self._context["cached_analyses"].get(binary_hash)

    def cache_analysis(self, binary_hash: str, results: Dict) -> None:
        """Cache analysis results for a binary."""
        with self._lock:
            self._context["cached_analyses"][binary_hash] = {
                "results": results,
                "timestamp": datetime.now(),
                "access_count": 0
            }

    def clear_session(self) -> None:
        """Clear session-specific data."""
        with self._lock:
            self._context["user_session"] = {}
            self._context["workflow_state"] = {}


class AIEventBus:
    """Event bus for AI component communication."""

    def __init__(self):
        self._subscribers = {}
        self._lock = threading.RLock()
        logger.info("AI Event Bus initialized")

    def subscribe(self, event_type: str, callback: Callable, component_name: str) -> None:
        """Subscribe to specific events."""
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []

            self._subscribers[event_type].append({
                "callback": callback,
                "component": component_name
            })

        logger.debug("Component %s subscribed to %s", component_name, event_type)

    def emit(self, event_type: str, data: Dict[str, Any], source_component: str) -> None:
        """Emit an event to all subscribers."""
        with self._lock:
            subscribers = self._subscribers.get(event_type, [])

        if subscribers:
            logger.debug("Emitting %s from %s to %d subscribers", event_type, source_component, len(subscribers))

            for _subscriber in subscribers:
                try:
                    # Call subscriber in a separate thread to avoid blocking
                    def call_subscriber(sub):
                        """
                        Call a subscriber's callback function with event data.
                        
                        Args:
                            sub: Subscriber dictionary containing 'callback' and 'component' keys
                            
                        Executes the subscriber's callback with the event data and source component.
                        Catches and logs any errors that occur during callback execution.
                        """
                        try:
                            sub["callback"](data, source_component)
                        except (OSError, ValueError, RuntimeError) as e:
                            logger.error("Error in subscriber %s: %s", sub['component'], e)

                    threading.Thread(target=lambda: call_subscriber(_subscriber), daemon=True).start()

                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error calling subscriber %s: %s", _subscriber['component'], e)

    def unsubscribe(self, event_type: str, component_name: str) -> None:
        """Unsubscribe a component from an event type."""
        with self._lock:
            if event_type in self._subscribers:
                self._subscribers[event_type] = [
                    _sub for _sub in self._subscribers[event_type]
                    if _sub["component"] != component_name
                ]


class AIOrchestrator:
    """
    Central AI Orchestrator for Intellicrack

    Coordinates between fast ML models and intelligent LLM agents,
    creating a truly agentic environment that leverages the strengths
    of each component type.
    """

    def __init__(self):
        logger.info("Initializing AI Orchestrator...")

        # Initialize shared systems
        self.shared_context = AISharedContext()
        self.event_bus = AIEventBus()
        self.task_queue = queue.PriorityQueue()
        self.active_tasks = {}
        self.is_running = False

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

        # Fast ML predictor for specific tasks
        try:
            if MLVulnerabilityPredictor:
                self.ml_predictor = MLVulnerabilityPredictor()
                logger.info("ML Vulnerability Predictor initialized")
            else:
                self.ml_predictor = None
                logger.warning("ML Vulnerability Predictor not available")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize ML Predictor: %s", e)
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
                logger.info("AI Assistant initialized")
            else:
                self.ai_assistant = None
                logger.warning("AI Assistant not available")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize AI Assistant: %s", e)
            self.ai_assistant = None

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
        self.event_bus.subscribe("ml_prediction_complete", self._on_ml_prediction_complete, "orchestrator")
        self.event_bus.subscribe("model_loaded", self._on_model_loaded, "orchestrator")
        self.event_bus.subscribe("error_occurred", self._on_error_occurred, "orchestrator")

    def _on_analysis_complete(self, data: Dict[str, Any], source: str):
        """Handle analysis completion events."""
        logger.info("Analysis complete from %s: %s", source, data.get('task_id', 'unknown'))

        # Update shared context with results
        if "results" in data:
            self.shared_context.update({
                f"last_analysis_{source}": data["results"],
                f"last_analysis_time_{source}": datetime.now()
            })

    def _on_ml_prediction_complete(self, data: Dict[str, Any], source: str):
        """Handle ML prediction completion events."""
        logger.info("ML prediction complete from %s", source)

        # Check if we need to escalate to complex analysis
        confidence = data.get("confidence", 0.0)
        if confidence < 0.7:  # Low confidence, use LLM for verification
            self._escalate_to_complex_analysis(data)

    def _on_model_loaded(self, data: Dict[str, Any], source: str):
        """Handle model loading events."""
        logger.info("Model loaded in %s: %s", source, data.get('model_name', 'unknown'))

    def _on_error_occurred(self, data: Dict[str, Any], source: str):
        """Handle error events."""
        logger.error("Error in %s: %s", source, data.get('error', 'unknown error'))

    def _escalate_to_complex_analysis(self, ml_data: Dict[str, Any]):
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
                    "escalation_reason": "low_confidence"
                }
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
            logger.info("Executing task %s (type: %s, complexity: %s)", task.task_id, task.task_type, task.complexity)

            # Route task based on type and complexity
            if task.task_type == AITaskType.VULNERABILITY_SCAN:
                result_data, components_used, confidence = self._execute_vulnerability_scan(task)
                success = True

            elif task.task_type == AITaskType.LICENSE_ANALYSIS:
                result_data, components_used, confidence = self._execute_license_analysis(task)
                success = True

            elif task.task_type == AITaskType.BINARY_ANALYSIS:
                result_data, components_used, confidence = self._execute_binary_analysis(task)
                success = True

            elif task.task_type == AITaskType.REASONING:
                result_data, components_used, confidence = self._execute_reasoning_task(task)
                success = True

            else:
                errors.append(f"Unknown task type: {task.task_type}")
                logger.warning("Unknown task type: %s", task.task_type)

        except (OSError, ValueError, RuntimeError) as e:
            errors.append(str(e))
            logger.error("Error executing task %s: %s", task.task_id, e)

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
            errors=errors
        )

        # Emit completion event
        self.event_bus.emit("task_complete", {
            "task_id": task.task_id,
            "success": success,
            "result": result_data
        }, "orchestrator")

        # Call callback if provided
        if task.callback:
            try:
                task.callback(result)
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in task callback: %s", e)

        return result

    def _execute_vulnerability_scan(self, task: AITask) -> tuple:
        """Execute vulnerability scanning task."""
        components_used = []
        result_data = {}
        confidence = 0.0

        binary_path = task.input_data.get("binary_path")
        if not binary_path:
            raise ValueError("No binary_path provided for vulnerability scan")

        # Always start with fast ML prediction
        if self.ml_predictor:
            try:
                # Check if method exists, fallback to alternative
                if hasattr(self.ml_predictor, 'predict_vulnerabilities'):
                    ml_results = self.ml_predictor.predict_vulnerabilities(binary_path)
                elif hasattr(self.ml_predictor, 'predict'):
                    ml_results = self.ml_predictor.predict(binary_path)
                else:
                    raise AttributeError("No prediction method available")
                result_data["ml_predictions"] = ml_results
                components_used.append("ml_predictor")
                confidence = ml_results.get("confidence", 0.0)

                # Emit ML completion event
                self.event_bus.emit("ml_prediction_complete", {
                    "task_id": task.task_id,
                    "results": ml_results,
                    "confidence": confidence
                }, "ml_predictor")

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("ML prediction failed: %s", e)

        # Escalate to LLM if complexity requires it or ML confidence is low
        if (task.complexity in [AnalysisComplexity.COMPLEX, AnalysisComplexity.CRITICAL] or
            confidence < 0.7):

            if self.model_manager and self.ai_assistant:
                try:
                    # Use AI assistant for complex analysis
                    if hasattr(self.ai_assistant, 'analyze_binary_complex'):
                        llm_results = self.ai_assistant.analyze_binary_complex(binary_path, ml_results)
                    elif hasattr(self.ai_assistant, 'analyze_binary'):
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
                if hasattr(self.ai_assistant, 'analyze_license_patterns'):
                    license_results = self.ai_assistant.analyze_license_patterns(task.input_data)
                elif hasattr(self.ai_assistant, 'analyze_license'):
                    license_results = self.ai_assistant.analyze_license(task.input_data)
                else:
                    raise AttributeError("No license analysis method available")
                result_data["license_analysis"] = license_results
                components_used.append("ai_assistant")
                confidence = license_results.get("confidence", 0.8)  # License analysis is typically high confidence

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
                if hasattr(self.hex_bridge, 'analyze_binary_patterns'):
                    hex_results = self.hex_bridge.analyze_binary_patterns(binary_path)
                elif hasattr(self.hex_bridge, 'analyze_binary'):
                    hex_results = self.hex_bridge.analyze_binary(binary_path)
                else:
                    raise AttributeError("No binary analysis method available")
                result_data["hex_analysis"] = hex_results
                components_used.append("hex_bridge")
                confidence = hex_results.get("confidence", 0.7)

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Hex analysis failed: %s", e)

        # Add ML analysis if available
        if self.ml_predictor:
            try:
                if hasattr(self.ml_predictor, 'analyze_binary_features'):
                    ml_results = self.ml_predictor.analyze_binary_features(binary_path)
                elif hasattr(self.ml_predictor, 'extract_features'):
                    ml_results = self.ml_predictor.extract_features(binary_path)
                else:
                    raise AttributeError("No feature analysis method available")
                result_data["ml_features"] = ml_results
                components_used.append("ml_predictor")
                confidence = max(confidence, ml_results.get("confidence", 0.0))

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("ML feature analysis failed: %s", e)

        return result_data, components_used, confidence

    def _execute_reasoning_task(self, task: AITask) -> tuple:
        """Execute complex reasoning task."""
        components_used = []
        result_data = {}
        confidence = 0.0

        # Use LLM manager for reasoning tasks if available
        if self.llm_manager and self.llm_manager.get_available_llms():
            try:
                # Prepare reasoning messages
                messages = [
                    LLMMessage(role="system", content="""You are an expert binary analysis AI assistant integrated into Intellicrack. 
                    Analyze the provided data and provide detailed reasoning about binary security, vulnerabilities, and recommendations.
                    Be specific, actionable, and focus on practical security implications."""),
                    LLMMessage(role="user", content=f"Analyze this data and provide reasoning: {json.dumps(task.input_data, indent=2)}")
                ]

                # Get LLM response
                response = self.llm_manager.chat(messages)

                if response and response.content:
                    reasoning_results = {
                        "analysis": response.content,
                        "confidence": 0.85,  # LLM reasoning typically high confidence
                        "model_used": response.model,
                        "reasoning_type": "llm_analysis",
                        "recommendations": self._extract_recommendations(response.content)
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
                if hasattr(self.ai_assistant, 'perform_reasoning'):
                    reasoning_results = self.ai_assistant.perform_reasoning(task.input_data)
                elif hasattr(self.ai_assistant, 'analyze_complex'):
                    reasoning_results = self.ai_assistant.analyze_complex(task.input_data)
                else:
                    raise AttributeError("No reasoning method available")
                result_data["reasoning"] = reasoning_results
                components_used.append("ai_assistant")
                confidence = reasoning_results.get("confidence", 0.8)

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("AI Assistant reasoning failed: %s", e)

        return result_data, components_used, confidence

    def _extract_recommendations(self, content: str) -> List[str]:
        """Extract actionable recommendations from LLM response."""
        recommendations = []

        # Look for common recommendation patterns
        lines = content.split('\n')
        for _line in lines:
            line = _line.strip()
            if any(_keyword in line.lower() for _keyword in ['recommend', 'suggest', 'should', 'consider']):
                if len(line) > 20 and len(line) < 200:  # Reasonable length
                    recommendations.append(line)

        return recommendations[:5]  # Limit to top 5 recommendations

    def submit_task(self, task: AITask) -> str:
        """Submit a task for processing."""
        # Add to priority queue (negative priority for max-heap behavior)
        self.task_queue.put((-task.priority, task))
        self.active_tasks[task.task_id] = task

        logger.info("Task %s submitted with priority %s", task.task_id, task.priority)
        return task.task_id

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of a task."""
        if task_id in self.active_tasks:
            return {
                "status": "active",
                "task": self.active_tasks[task_id]
            }
        return None

    def quick_vulnerability_scan(self, binary_path: str, callback: Optional[Callable] = None) -> str:
        """Quick vulnerability scan using fast ML models."""
        task = AITask(
            task_id=f"vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            task_type=AITaskType.VULNERABILITY_SCAN,
            complexity=AnalysisComplexity.SIMPLE,
            input_data={"binary_path": binary_path},
            priority=7,
            callback=callback
        )
        return self.submit_task(task)

    def complex_license_analysis(self, binary_path: str, callback: Optional[Callable] = None) -> str:
        """Complex license analysis using LLM reasoning."""
        task = AITask(
            task_id=f"license_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            task_type=AITaskType.LICENSE_ANALYSIS,
            complexity=AnalysisComplexity.COMPLEX,
            input_data={"binary_path": binary_path},
            priority=8,
            callback=callback
        )
        return self.submit_task(task)

    def comprehensive_analysis(self, binary_path: str, callback: Optional[Callable] = None) -> str:
        """Comprehensive analysis using all available AI resources."""
        task = AITask(
            task_id=f"comprehensive_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            task_type=AITaskType.BINARY_ANALYSIS,
            complexity=AnalysisComplexity.CRITICAL,
            input_data={"binary_path": binary_path},
            priority=10,
            callback=callback
        )
        return self.submit_task(task)

    def get_component_status(self) -> Dict[str, Any]:
        """Get status of all AI components."""
        llm_status = {}
        if self.llm_manager:
            llm_status = {
                "available_llms": self.llm_manager.get_available_llms(),
                "active_llm": self.llm_manager.active_backend
            }

        return {
            "ml_predictor": self.ml_predictor is not None,
            "model_manager": self.model_manager is not None,
            "llm_manager": self.llm_manager is not None,
            "llm_status": llm_status,
            "ai_assistant": self.ai_assistant is not None,
            "hex_bridge": self.hex_bridge is not None,
            "event_bus_subscribers": len(self.event_bus._subscribers),
            "active_tasks": len(self.active_tasks),
            "queue_size": self.task_queue.qsize(),
            "is_processing": self.is_running
        }

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
_orchestrator_instance = None


def get_orchestrator() -> AIOrchestrator:
    """Get the global AI orchestrator instance."""
    global _orchestrator_instance  # pylint: disable=global-statement
    if _orchestrator_instance is None:
        _orchestrator_instance = AIOrchestrator()
    return _orchestrator_instance


def shutdown_orchestrator():
    """Shutdown the global orchestrator instance."""
    global _orchestrator_instance  # pylint: disable=global-statement
    if _orchestrator_instance:
        _orchestrator_instance.shutdown()
        _orchestrator_instance = None
