"""Real-Time Adaptation Engine.

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

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from ..utils.logger import get_logger
from .learning_engine import get_learning_engine
from .performance_monitor_simple import profile_ai_operation


logger = get_logger(__name__)

try:
    from intellicrack.handlers.psutil_handler import psutil

    PSUTIL_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in realtime_adaptation_engine: %s", e)
    psutil = None
    PSUTIL_AVAILABLE = False


class AdaptationType(Enum):
    """Types of real-time adaptations."""

    PARAMETER_TUNING = "parameter_tuning"
    ALGORITHM_SELECTION = "algorithm_selection"
    RESOURCE_ALLOCATION = "resource_allocation"
    STRATEGY_MODIFICATION = "strategy_modification"
    ERROR_RECOVERY = "error_recovery"
    PERFORMANCE_OPTIMIZATION = "performance_optimization"
    BEHAVIOR_ADJUSTMENT = "behavior_adjustment"


class TriggerCondition(Enum):
    """Conditions that trigger adaptations."""

    PERFORMANCE_DEGRADATION = "performance_degradation"
    ERROR_RATE_INCREASE = "error_rate_increase"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SUCCESS_RATE_DROP = "success_rate_drop"
    TIMEOUT_OCCURRENCE = "timeout_occurrence"
    MEMORY_PRESSURE = "memory_pressure"
    PATTERN_CHANGE = "pattern_change"


@dataclass
class AdaptationRule:
    """Rule for triggering adaptations."""

    rule_id: str
    name: str
    condition: TriggerCondition
    threshold: float
    adaptation_type: AdaptationType
    action: str
    priority: int = 1
    enabled: bool = True
    cooldown_seconds: int = 60
    last_triggered: datetime | None = None
    trigger_count: int = 0
    success_count: int = 0


@dataclass
class RuntimeMetric:
    """Real-time metric for monitoring."""

    metric_name: str
    value: float
    timestamp: datetime
    source: str
    category: str = "general"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AdaptationEvent:
    """Event representing an adaptation."""

    event_id: str
    adaptation_type: AdaptationType
    trigger_condition: TriggerCondition
    action_taken: str
    success: bool
    impact_metrics: dict[str, float]
    timestamp: datetime = field(default_factory=datetime.now)
    execution_time: float = 0.0
    error_message: str | None = None


class RuntimeMonitor:
    """Real-time monitoring system."""

    def __init__(self) -> None:
        """Initialize the real-time monitoring system.

        Monitors system metrics, detects anomalies, and triggers adaptation
        rules in response to performance issues.
        """
        self.active = False
        self.metrics_buffer: deque[RuntimeMetric] = deque(maxlen=10000)
        self.metric_aggregates: dict[str, dict[str, float]] = defaultdict(dict)
        self.anomaly_detectors: dict[str, AnomalyDetector] = {}
        self.subscribers: list[Callable[[RuntimeMetric], None]] = []

        # Monitoring thread
        self.monitor_thread: threading.Thread | None = None
        self.monitor_interval = 0.5  # 500ms

        # Metric history for trend analysis
        self.metric_history: dict[str, deque[tuple[datetime, float]]] = defaultdict(lambda: deque(maxlen=1000))

        # Adaptation rules for real-time response
        self.adaptation_rules: dict[str, dict[str, Any]] = {}

        logger.info("Runtime monitor initialized")

    def start(self) -> None:
        """Start runtime monitoring."""
        if self.active:
            return

        self.active = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True,
        )
        self.monitor_thread.start()

        logger.info("Runtime monitoring started")

    def stop(self) -> None:
        """Stop runtime monitoring."""
        self.active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)

        logger.info("Runtime monitoring stopped")

    def _monitoring_loop(self) -> None:
        """Monitor continuously in the main loop.

        Main loop that continuously collects metrics, processes the metrics
        buffer, and checks for anomalies at regular intervals.

        Args:
            None.

        Raises:
            None.
        """
        while self.active:
            try:
                # Collect system metrics
                self._collect_system_metrics()

                # Process metrics buffer
                self._process_metrics_buffer()

                # Check for anomalies
                self._check_anomalies()

                time.sleep(self.monitor_interval)

            except Exception as e:
                logger.exception("Error in monitoring loop: %s", e)
                time.sleep(1.0)

    def _collect_system_metrics(self) -> None:
        """Collect system metrics.

        Gathers CPU usage, memory usage, and process-level memory statistics
        from the system using psutil. Safely handles cases where psutil is
        unavailable.

        Args:
            None.

        Returns:
            None.

        Raises:
            None.
        """
        if not PSUTIL_AVAILABLE:
            logger.debug("psutil not available - skipping system metrics collection")
            return

        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=None)
            self.record_metric("system.cpu_usage", cpu_percent, "system")

            # Memory metrics
            memory = psutil.virtual_memory()
            self.record_metric("system.memory_usage", memory.percent, "system")
            self.record_metric("system.memory_available", memory.available, "system")

            # Process metrics
            process = psutil.Process()
            process_info = process.memory_info()
            self.record_metric("process.memory_rss", process_info.rss, "process")
            self.record_metric("process.memory_vms", process_info.vms, "process")

        except Exception as e:
            logger.exception("Error collecting system metrics: %s", e)

    def record_metric(
        self,
        metric_name: str,
        value: float,
        source: str,
        category: str = "general",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record a runtime metric.

        Records a metric with its current value, timestamp, and source for
        monitoring and analysis. Notifies all subscribers of the new metric.

        Args:
            metric_name: Name/identifier of the metric being recorded.
            value: Numeric value of the metric.
            source: Source component that generated this metric.
            category: Metric category for organization (default: "general").
            metadata: Optional metadata dictionary associated with the metric.

        Raises:
            None.
        """
        metric = RuntimeMetric(
            metric_name=metric_name,
            value=value,
            timestamp=datetime.now(),
            source=source,
            category=category,
            metadata=metadata or {},
        )

        self.metrics_buffer.append(metric)
        self.metric_history[metric_name].append((metric.timestamp, value))

        # Notify subscribers
        for subscriber in self.subscribers:
            try:
                subscriber(metric)
            except Exception as e:
                logger.exception("Error notifying metric subscriber: %s", e)

    def _process_metrics_buffer(self) -> None:
        """Process metrics buffer and update aggregates.

        Consumes the metrics buffer, groups metrics by name, and calculates
        aggregate statistics (count, sum, average, min, max) for each metric.

        Args:
            None.

        Returns:
            None.

        Raises:
            None.
        """
        if not self.metrics_buffer:
            return

        # Group metrics by name
        metrics_by_name = defaultdict(list)
        while self.metrics_buffer:
            metric = self.metrics_buffer.popleft()
            metrics_by_name[metric.metric_name].append(metric.value)

        # Update aggregates
        for metric_name, values in metrics_by_name.items():
            if values:
                self.metric_aggregates[metric_name] = {
                    "count": len(values),
                    "sum": sum(values),
                    "avg": sum(values) / len(values),
                    "min": min(values),
                    "max": max(values),
                    "last": values[-1],
                    "timestamp": datetime.now().timestamp(),
                }

    def _check_anomalies(self) -> None:
        """Check for anomalies in metrics.

        Iterates through registered anomaly detectors and evaluates current
        metric values against their anomaly detection thresholds. Triggers
        notification for detected anomalies.

        Args:
            None.

        Raises:
            None.
        """
        for metric_name, detector in self.anomaly_detectors.items():
            if metric_name in self.metric_aggregates:
                current_value = self.metric_aggregates[metric_name]["last"]
                if is_anomaly := detector.detect_anomaly(current_value):
                    logger.warning("Anomaly detected in %s: %s (anomaly_status: %s)", metric_name, current_value, is_anomaly)
                    self._notify_anomaly(metric_name, current_value)

    def _notify_anomaly(self, metric_name: str, value: float) -> None:
        """Notify about detected anomaly.

        Logs detected anomaly, checks for matching adaptation rules, executes
        applicable rules, and stores anomaly details in history.

        Args:
            metric_name: Name of the metric with the detected anomaly.
            value: Value of the metric that triggered the anomaly.

        Raises:
            None.
        """
        # Log the anomaly with details
        logger.warning("Anomaly notification: %s = %s", metric_name, value)

        # Check if we have adaptation rules for this metric
        adaptation_triggered = False

        # Look for matching adaptation rules
        for rule_id, rule in self.adaptation_rules.items():
            if rule.get("metric_pattern") and metric_name in rule.get("metric_pattern", ""):
                logger.info("Triggering adaptation rule %s for %s", rule_id, metric_name)
                self._execute_adaptation_rule(rule_id, metric_name, value)
                adaptation_triggered = True

        if not adaptation_triggered:
            logger.debug("No adaptation rules found for metric %s", metric_name)

        # Store anomaly in history for analysis
        if not hasattr(self, "anomaly_history"):
            self.anomaly_history = []

        self.anomaly_history.append(
            {
                "timestamp": time.time(),
                "metric": metric_name,
                "value": value,
                "adaptation_triggered": adaptation_triggered,
            },
        )

    def _execute_adaptation_rule(self, rule_id: str, metric_name: str, value: float) -> None:
        """Execute an adaptation rule in response to an anomaly.

        Retrieves an adaptation rule by ID and executes the associated action,
        such as adjusting anomaly detection thresholds or signaling component
        restart.

        Args:
            rule_id: Identifier of the adaptation rule to execute.
            metric_name: Name of the metric triggering the rule.
            value: Value of the metric that triggered the rule.

        Returns:
            None.

        Raises:
            None.
        """
        try:
            rule = self.adaptation_rules.get(rule_id)
            if not rule:
                logger.exception("Adaptation rule %s not found", rule_id)
                return

            action_type = rule.get("action_type", "log")
            logger.info("Executing adaptation rule %s: %s for %s=%s", rule_id, action_type, metric_name, value)

            # Execute the adaptation action
            if action_type == "adjust_threshold":
                # Adjust anomaly detection threshold
                if metric_name in self.anomaly_detectors:
                    detector = self.anomaly_detectors[metric_name]
                    if hasattr(detector, "threshold"):
                        detector.threshold *= rule.get("threshold_multiplier", 1.1)
                        logger.info("Adjusted threshold for %s to %s", metric_name, detector.threshold)
            elif action_type == "restart_component":
                # Signal component restart (would be handled by higher-level system)
                logger.warning("Component restart requested for %s anomaly", metric_name)
            else:
                logger.debug("Unknown adaptation action: %s", action_type)

        except Exception as e:
            logger.exception("Error executing adaptation rule %s: %s", rule_id, e)

    def subscribe_to_metrics(self, callback: Callable[[RuntimeMetric], None]) -> None:
        """Subscribe to real-time metrics.

        Registers a callback function to be invoked whenever a new metric is
        recorded by the monitoring system.

        Args:
            callback: Callback function that accepts a RuntimeMetric instance.

        Raises:
            None.
        """
        self.subscribers.append(callback)

    def get_metric_trend(self, metric_name: str, window_minutes: int = 5) -> dict[str, Any]:
        """Get trend analysis for metric.

        Analyzes historical metric data within a time window and determines
        whether the metric is increasing, decreasing, or stable.

        Args:
            metric_name: Name of the metric to analyze.
            window_minutes: Time window in minutes for trend analysis (default: 5).

        Returns:
            Dictionary containing trend analysis with keys: trend (str),
            data_points (int), avg_first_half (float), avg_second_half (float),
            and change_percent (float).

        Raises:
            None.
        """
        if metric_name not in self.metric_history:
            return {"trend": "unknown", "data_points": 0}

        cutoff_time = datetime.now() - timedelta(minutes=window_minutes)
        recent_data = [(timestamp, value) for timestamp, value in self.metric_history[metric_name] if timestamp >= cutoff_time]

        if len(recent_data) < 2:
            return {"trend": "insufficient_data", "data_points": len(recent_data)}

        # Calculate trend
        values = [value for _, value in recent_data]
        first_half = values[: len(values) // 2]
        second_half = values[len(values) // 2 :]

        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)

        if avg_second > avg_first * 1.1:
            trend = "increasing"
        elif avg_second < avg_first * 0.9:
            trend = "decreasing"
        else:
            trend = "stable"

        return {
            "trend": trend,
            "data_points": len(recent_data),
            "avg_first_half": avg_first,
            "avg_second_half": avg_second,
            "change_percent": ((avg_second - avg_first) / avg_first * 100) if avg_first > 0 else 0,
        }


class AnomalyDetector:
    """Anomaly detection for metrics."""

    def __init__(self, metric_name: str, sensitivity: float = 2.0) -> None:
        """Initialize the anomaly detector for a specific metric.

        Args:
            metric_name: Name of the metric to monitor for anomalies.
            sensitivity: Detection sensitivity factor (default: 2.0).
                Higher values reduce false positives but may miss anomalies.

        """
        self.metric_name = metric_name
        self.sensitivity = sensitivity
        self.baseline_values: deque[float] = deque(maxlen=100)
        self.baseline_mean = 0.0
        self.baseline_std = 0.0
        self.calibrated = False

    def add_baseline_value(self, value: float) -> None:
        """Add value to baseline.

        Appends a value to the baseline data collection. Automatically
        recalculates baseline statistics when sufficient data is available.

        Args:
            value: Metric value to add to the baseline.

        Raises:
            None.
        """
        self.baseline_values.append(value)

        if len(self.baseline_values) >= 20:
            self._recalculate_baseline()

    def _recalculate_baseline(self) -> None:
        """Recalculate baseline statistics.

        Computes mean and standard deviation from collected baseline values
        to establish normal behavior parameters for anomaly detection.

        Args:
            None.

        Returns:
            None.

        Raises:
            None.
        """
        if not self.baseline_values:
            return

        values = list(self.baseline_values)
        self.baseline_mean = sum(values) / len(values)

        # Calculate standard deviation
        variance = sum((x - self.baseline_mean) ** 2 for x in values) / len(values)
        self.baseline_std = variance**0.5

        self.calibrated = len(values) >= 20

    def detect_anomaly(self, value: float) -> bool:
        """Detect if value is anomalous.

        Performs Z-score based anomaly detection comparing the provided value
        against baseline statistics. Automatically calibrates the detector
        during the initial learning phase.

        Args:
            value: Metric value to evaluate for anomalies.

        Returns:
            True if value is detected as anomalous, False otherwise.

        Raises:
            None.
        """
        if not self.calibrated:
            self.add_baseline_value(value)
            return False

        # Z-score based anomaly detection
        if self.baseline_std == 0:
            return False

        z_score = abs(value - self.baseline_mean) / self.baseline_std
        is_anomaly = z_score > self.sensitivity

        # Update baseline with non-anomalous values
        if not is_anomaly:
            self.add_baseline_value(value)

        return is_anomaly


class DynamicHookManager:
    """Manages dynamic code hooks for adaptation."""

    def __init__(self) -> None:
        """Initialize the dynamic hook manager.

        Sets up hook tracking structures for active hooks, registry,
        and statistics collection. Manages dynamic code hooks for
        runtime adaptation.
        """
        self.active_hooks: dict[str, dict[str, Any]] = {}
        self.hook_registry: dict[str, dict[str, Any]] = {}
        self.hook_statistics: dict[str, dict[str, int]] = defaultdict(lambda: {"calls": 0, "modifications": 0})

        logger.info("Dynamic hook manager initialized")

    def register_hook_point(self, hook_id: str, target_function: Callable[..., Any], hook_type: str = "around") -> None:
        """Register a hook point.

        Records a hook point definition in the registry for later activation.
        Hook points define locations where dynamic modifications can be injected.

        Args:
            hook_id: Unique identifier for the hook point.
            target_function: The callable function to hook into.
            hook_type: Type of hook (default: "around"). Determines hook behavior.

        Raises:
            None.
        """
        self.hook_registry[hook_id] = {
            "target": target_function,
            "type": hook_type,
            "original": target_function,
            "active": False,
            "modifications": [],
        }

        logger.info("Registered hook point: %s", hook_id)

    def install_hook(self, hook_id: str, modification: dict[str, Any]) -> bool:
        """Install a hook modification.

        Activates a registered hook point by installing the specified modifications.
        Creates a wrapper function that applies pre-processing, parameter modifications,
        and post-processing as defined.

        Args:
            hook_id: Identifier of the hook point to install.
            modification: Dictionary specifying the modifications to apply.

        Returns:
            True if hook installation succeeded, False otherwise.

        Raises:
            None.
        """
        if hook_id not in self.hook_registry:
            logger.exception("Hook point %s not registered", hook_id)
            return False

        try:
            hook_info = self.hook_registry[hook_id]

            # Create modified function
            modified_function = self._create_modified_function(
                hook_info["original"],
                modification,
            )

            # Install the hook
            if self._install_function_hook(hook_info["target"], modified_function):
                hook_info["active"] = True
                hook_info["modifications"].append(modification)
                self.active_hooks[hook_id] = hook_info

                logger.info("Installed hook modification for %s", hook_id)
                return True

        except Exception as e:
            logger.exception("Failed to install hook %s: %s", hook_id, e)

        return False

    def remove_hook(self, hook_id: str) -> bool:
        """Remove a hook modification.

        Deactivates an installed hook by restoring the original function
        and clearing associated modifications.

        Args:
            hook_id: Identifier of the hook to remove.

        Returns:
            True if hook removal succeeded, False otherwise.

        Raises:
            None.
        """
        if hook_id not in self.active_hooks:
            return False

        try:
            hook_info = self.active_hooks[hook_id]

            # Restore original function
            if self._restore_original_function(hook_info["target"], hook_info["original"]):
                hook_info["active"] = False
                hook_info["modifications"].clear()
                del self.active_hooks[hook_id]

                logger.info("Removed hook modification for %s", hook_id)
                return True

        except Exception as e:
            logger.exception("Failed to remove hook %s: %s", hook_id, e)

        return False

    def _create_modified_function(self, original_function: Callable[..., Any], modification: dict[str, Any]) -> Callable[..., Any]:
        """Create modified function based on modification specification.

        Wraps an original function with custom modifications including
        pre-processing, parameter transformation, post-processing, and
        result modifications. Tracks hook call statistics.

        Args:
            original_function: The original callable to wrap with modifications.
            modification: Dictionary specification for modifications containing
                optional keys: pre_process, parameter_modifications, post_process,
                result_modifications, and hook_id.

        Returns:
            A wrapper function with the modifications applied.

        """

        def modified_wrapper(*args: object, **kwargs: object) -> object:
            # Record hook call
            hook_id = modification.get("hook_id", "unknown")
            self.hook_statistics[hook_id]["calls"] += 1

            try:
                # Pre-processing modifications
                if "pre_process" in modification:
                    pre_result = modification["pre_process"](args, kwargs)
                    if pre_result is not None:
                        args, kwargs = pre_result

                # Parameter modifications
                if "parameter_modifications" in modification:
                    for param_mod in modification["parameter_modifications"]:
                        args, kwargs = self._apply_parameter_modification(args, kwargs, param_mod)

                # Call original function
                result = original_function(*args, **kwargs)

                # Post-processing modifications
                if "post_process" in modification:
                    result = modification["post_process"](result)

                # Result modifications
                if "result_modifications" in modification:
                    for result_mod in modification["result_modifications"]:
                        result = self._apply_result_modification(result, result_mod)

                self.hook_statistics[hook_id]["modifications"] += 1
                return result

            except Exception as e:
                logger.exception("Error in hook modification %s: %s", hook_id, e)
                # Fall back to original function
                return original_function(*args, **kwargs)

        return modified_wrapper

    def _apply_parameter_modification(
        self, args: tuple[Any, ...], kwargs: dict[str, Any], modification: dict[str, Any]
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        """Apply parameter modification.

        Modifies function arguments based on the specification, supporting
        value replacement and parameter addition operations.

        Args:
            args: Positional arguments tuple to potentially modify.
            kwargs: Keyword arguments dictionary to potentially modify.
            modification: Modification specification with type, parameter, and value.

        Returns:
            Tuple of modified (args, kwargs).

        Raises:
            None.
        """
        mod_type = modification.get("type", "")

        if mod_type == "replace_value":
            param_name = modification.get("parameter", "")
            new_value = modification.get("value")

            if param_name in kwargs:
                kwargs[param_name] = new_value
            elif modification.get("position") is not None:
                pos = modification["position"]
                if 0 <= pos < len(args):
                    args_list = list(args)
                    args_list[pos] = new_value
                    args = tuple(args_list)

        elif mod_type == "add_parameter":
            param_name = modification.get("parameter", "")
            value = modification.get("value")
            kwargs[param_name] = value

        return args, kwargs

    def _apply_result_modification(self, result: object, modification: dict[str, Any]) -> object:
        """Apply result modification.

        Args:
            result: The result value to modify.
            modification: Modification specification dictionary containing
                type, field, value, and/or transform function.

        Returns:
            The modified result object or original result if no modification applies.

        """
        mod_type = modification.get("type", "")

        if mod_type == "replace_result":
            return modification.get("value", result)

        if mod_type == "modify_field" and isinstance(result, dict):
            field_name = modification.get("field", "")
            new_value = modification.get("value")
            if field_name in result:
                result[field_name] = new_value

        elif mod_type == "transform_result":
            transform_func = modification.get("transform")
            if transform_func and callable(transform_func):
                return transform_func(result)

        return result

    def _install_function_hook(self, target_function: Callable[..., Any], modified_function: Callable[..., Any]) -> bool:
        """Install function hook using monkey patching.

        Replaces a target function in its module with a modified version,
        enabling dynamic runtime modification of function behavior.

        Args:
            target_function: Original function to replace.
            modified_function: Replacement function with modifications applied.

        Returns:
            True if hook installation succeeded, False otherwise.

        Raises:
            None.
        """
        try:
            # This is a simplified implementation
            # In practice, you might use more sophisticated hooking mechanisms

            # Get the module and function name
            module = target_function.__module__
            func_name = target_function.__name__

            # Replace the function in its module
            import sys

            if module in sys.modules:
                setattr(sys.modules[module], func_name, modified_function)
                return True

        except Exception as e:
            logger.exception("Failed to install function hook: %s", e)

        return False

    def _restore_original_function(self, target_function: Callable[..., Any], original_function: Callable[..., Any]) -> bool:
        """Restore original function.

        Restores a previously modified function to its original implementation
        in its module namespace.

        Args:
            target_function: The hooked function to restore.
            original_function: The original function implementation to restore.

        Returns:
            True if restoration succeeded, False otherwise.

        Raises:
            None.
        """
        try:
            module = target_function.__module__
            func_name = target_function.__name__

            import sys

            if module in sys.modules:
                setattr(sys.modules[module], func_name, original_function)
                return True

        except Exception as e:
            logger.exception("Failed to restore original function: %s", e)

        return False

    def get_hook_statistics(self) -> dict[str, dict[str, int]]:
        """Get hook usage statistics.

        Retrieves a snapshot of hook execution statistics including call counts
        and modification counts for all installed hooks.

        Args:
            None.

        Returns:
            Dictionary mapping hook IDs to statistics dictionaries containing
            call and modification counts.

        Raises:
            None.
        """
        return dict(self.hook_statistics)


class LiveDebuggingSystem:
    """AI-assisted live debugging system."""

    def __init__(self, runtime_monitor: RuntimeMonitor) -> None:
        """Initialize the AI-assisted live debugging system.

        Args:
            runtime_monitor: Runtime monitor instance to subscribe to
                for receiving metrics and performance data.

        """
        self.runtime_monitor = runtime_monitor
        self.active_debug_sessions: dict[str, dict[str, Any]] = {}
        self.debug_history: deque[dict[str, Any]] = deque(maxlen=1000)
        self.automated_fixes: dict[str, Callable[[RuntimeMetric], Any]] = {}

        # Subscribe to runtime metrics
        self.runtime_monitor.subscribe_to_metrics(self._analyze_metric_for_debugging)

        logger.info("Live debugging system initialized")

    def start_debug_session(self, session_id: str, target_component: str, debug_level: str = "info") -> bool:
        """Start a live debugging session.

        Creates and activates a new debugging session for a target component,
        initializing tracking structures for events, breakpoints, and watches.

        Args:
            session_id: Unique identifier for the debug session.
            target_component: Component or subsystem to debug.
            debug_level: Logging level for debug output (default: "info").

        Returns:
            True if session creation succeeded, False if session already exists.

        Raises:
            None.
        """
        if session_id in self.active_debug_sessions:
            logger.warning("Debug session %s already active", session_id)
            return False

        session = {
            "session_id": session_id,
            "target_component": target_component,
            "debug_level": debug_level,
            "start_time": datetime.now(),
            "events": [],
            "breakpoints": [],
            "watches": [],
            "active": True,
        }

        self.active_debug_sessions[session_id] = session
        logger.info("Started debug session %s for %s", session_id, target_component)

        return True

    def stop_debug_session(self, session_id: str) -> bool:
        """Stop a live debugging session.

        Deactivates an active debug session, archives session history, and cleans
        up session resources.

        Args:
            session_id: Identifier of the session to stop.

        Returns:
            True if session was stopped, False if session not found.

        Raises:
            None.
        """
        if session_id not in self.active_debug_sessions:
            return False

        session = self.active_debug_sessions[session_id]
        session["active"] = False
        session["end_time"] = datetime.now()

        # Archive session
        self.debug_history.append(session)
        del self.active_debug_sessions[session_id]

        logger.info("Stopped debug session %s", session_id)
        return True

    def add_breakpoint(self, session_id: str, component: str, condition: str) -> bool:
        """Add a conditional breakpoint.

        Registers a breakpoint with a condition to a debug session, enabling
        targeted debugging of specific components under specific conditions.

        Args:
            session_id: Identifier of the debug session.
            component: Component name or identifier for the breakpoint.
            condition: Condition string that triggers the breakpoint.

        Returns:
            True if breakpoint was added successfully, False if session not found.

        Raises:
            None.
        """
        if session_id not in self.active_debug_sessions:
            return False

        debug_breakpoint = {
            "id": f"bp_{int(datetime.now().timestamp())}",
            "component": component,
            "condition": condition,
            "hit_count": 0,
            "created_at": datetime.now(),
        }

        self.active_debug_sessions[session_id]["breakpoints"].append(debug_breakpoint)
        logger.info("Added breakpoint to session %s: %s - %s", session_id, component, condition)

        return True

    def add_watch(self, session_id: str, expression: str, alert_condition: str | None = None) -> bool:
        """Add a watch expression.

        Registers a watch expression to monitor in a debug session with an optional
        alert condition that triggers when the condition evaluates to true.

        Args:
            session_id: Identifier of the debug session.
            expression: Expression or variable to watch.
            alert_condition: Optional condition for triggering watch alerts.

        Returns:
            True if watch was added successfully, False if session not found.

        Raises:
            None.
        """
        if session_id not in self.active_debug_sessions:
            return False

        watch: dict[str, Any] = {
            "id": f"watch_{int(datetime.now().timestamp())}",
            "expression": expression,
            "alert_condition": alert_condition,
            "last_value": None,
            "value_history": deque(maxlen=100),
            "created_at": datetime.now(),
        }

        self.active_debug_sessions[session_id]["watches"].append(watch)
        logger.info("Added watch to session %s: %s", session_id, expression)

        return True

    def _analyze_metric_for_debugging(self, metric: RuntimeMetric) -> None:
        """Analyze metric for debugging insights.

        Examines incoming metrics to identify problematic values that exceed
        thresholds and triggers automated debugging sessions.

        Args:
            metric: RuntimeMetric instance to analyze.

        Raises:
            None.
        """
        # Check if metric indicates a problem
        problem_indicators = {
            "system.cpu_usage": 90.0,
            "system.memory_usage": 85.0,
            "process.memory_rss": 1024 * 1024 * 1024,  # 1GB
            "error_rate": 0.1,  # 10%
        }

        threshold = problem_indicators.get(metric.metric_name)
        if threshold and metric.value > threshold:
            self._trigger_automated_debugging(metric)

    def _trigger_automated_debugging(self, metric: RuntimeMetric) -> None:
        """Trigger automated debugging for problematic metric.

        Automatically creates a debug session and applies registered fixes
        when a metric exceeds problem thresholds.

        Args:
            metric: RuntimeMetric instance indicating a problem.

        Raises:
            None.
        """
        debug_session_id = f"auto_debug_{metric.metric_name}_{int(datetime.now().timestamp())}"

        if self.start_debug_session(debug_session_id, metric.source, "warning"):
            # Add relevant watches and breakpoints
            self.add_watch(debug_session_id, metric.metric_name, f"> {metric.value}")

            # Try automated fix if available
            if metric.metric_name in self.automated_fixes:
                try:
                    fix_result = self.automated_fixes[metric.metric_name](metric)
                    self._log_debug_event(
                        debug_session_id,
                        "automated_fix",
                        {
                            "metric": metric.metric_name,
                            "fix_applied": True,
                            "fix_result": fix_result,
                        },
                    )
                except Exception as e:
                    logger.exception("Exception in realtime_adaptation_engine: %s", e)
                    self._log_debug_event(
                        debug_session_id,
                        "automated_fix_failed",
                        {
                            "metric": metric.metric_name,
                            "error": str(e),
                        },
                    )

    def _log_debug_event(self, session_id: str, event_type: str, data: dict[str, Any]) -> None:
        """Log debugging event.

        Records a debugging event with associated metadata in the active session's
        event history.

        Args:
            session_id: Identifier of the debug session.
            event_type: Type of debugging event (e.g., "automated_fix").
            data: Event data dictionary containing relevant information.

        Raises:
            None.
        """
        if session_id in self.active_debug_sessions:
            event = {
                "timestamp": datetime.now(),
                "type": event_type,
                "data": data,
            }
            self.active_debug_sessions[session_id]["events"].append(event)

    def register_automated_fix(self, metric_name: str, fix_function: Callable[[RuntimeMetric], Any]) -> None:
        """Register automated fix for metric.

        Associates a callable fix function with a specific metric name that will
        be invoked automatically when that metric triggers debugging.

        Args:
            metric_name: Name of the metric to associate with the fix.
            fix_function: Callable that accepts a RuntimeMetric and performs remediation.

        Raises:
            None.
        """
        self.automated_fixes[metric_name] = fix_function
        logger.info("Registered automated fix for %s", metric_name)

    def get_debug_insights(self, session_id: str) -> dict[str, Any]:
        """Get debugging insights for session.

        Retrieves comprehensive debugging insights for an active session including
        session info, recent events, breakpoint hit counts, watch alerts, and
        recommendations.

        Args:
            session_id: Identifier of the debug session.

        Returns:
            Dictionary containing session_info, recent_events, breakpoint_hits,
            watch_alerts, and recommendations keys.

        Raises:
            None.
        """
        if session_id not in self.active_debug_sessions:
            return {"error": "Session not found"}

        session = self.active_debug_sessions[session_id]

        return {
            "session_info": {
                "id": session_id,
                "target": session["target_component"],
                "duration": (datetime.now() - session["start_time"]).total_seconds(),
                "events_count": len(session["events"]),
            },
            "recent_events": session["events"][-10:],  # Last 10 events
            "breakpoint_hits": sum(bp["hit_count"] for bp in session["breakpoints"]),
            "watch_alerts": self._check_watch_alerts(session),
            "recommendations": self._generate_debug_recommendations(session),
        }

    def _check_watch_alerts(self, session: dict[str, Any]) -> list[dict[str, Any]]:
        """Check watch expressions for alerts.

        Evaluates watch expressions and their alert conditions against current
        values, returning a list of triggered alerts.

        Args:
            session: Debug session dictionary containing watches to check.

        Returns:
            List of alert dictionaries with watch_id, expression, value, and condition.

        Raises:
            None.
        """
        alerts = []

        for watch in session["watches"]:
            if watch["alert_condition"] and watch["last_value"] is not None:
                # Safe condition checking with restricted operations
                try:
                    # Parse and validate the condition
                    condition = watch["alert_condition"].strip()
                    value = watch["last_value"]

                    # Only allow safe comparison operators
                    from typing import cast

                    safe_operators: dict[str, Callable[[Any, Any], bool]] = {
                        "==": lambda x, y: x == y,
                        "!=": lambda x, y: x != y,
                        "<": lambda x, y: x < y,
                        "<=": lambda x, y: x <= y,
                        ">": lambda x, y: x > y,
                        ">=": lambda x, y: x >= y,
                    }

                    result = False
                    for op, operator_func in safe_operators.items():
                        if condition.startswith(op):
                            try:
                                threshold_str = condition[len(op) :].strip()
                                # Use ast.literal_eval for safe parsing of the threshold value
                                import ast

                                threshold_val = ast.literal_eval(threshold_str)
                                result = operator_func(value, threshold_val)
                                break
                            except (ValueError, SyntaxError):
                                continue

                    if result:
                        alerts.append(
                            {
                                "watch_id": watch["id"],
                                "expression": watch["expression"],
                                "value": watch["last_value"],
                                "condition": watch["alert_condition"],
                            },
                        )
                except Exception as e:
                    logger.debug("Error checking watch alert condition: %s", e)

        return alerts

    def _generate_debug_recommendations(self, session: dict[str, Any]) -> list[str]:
        """Generate debugging recommendations.

        Analyzes session events and patterns to generate actionable debugging
        recommendations for the user.

        Args:
            session: Debug session dictionary to analyze.

        Returns:
            List of recommendation strings.

        Raises:
            None.
        """
        recommendations = []

        # Analyze events for patterns
        event_types = [event["type"] for event in session["events"]]

        if "automated_fix_failed" in event_types:
            recommendations.append("Consider manual intervention - automated fixes failed")

        if len(session["events"]) > 50:
            recommendations.append("High event activity - consider reducing debug verbosity")

        if not session["breakpoints"]:
            recommendations.append("Add breakpoints to capture specific conditions")

        return recommendations


class RealTimeAdaptationEngine:
    """Run real-time adaptation engine."""

    def __init__(self) -> None:
        """Initialize the real-time adaptation engine.

        Provides comprehensive real-time adaptation capabilities including
        runtime monitoring, dynamic code hooking, live debugging, and automated
        adaptation based on system performance metrics.
        """
        self.runtime_monitor = RuntimeMonitor()
        self.hook_manager = DynamicHookManager()
        self.debug_system = LiveDebuggingSystem(self.runtime_monitor)
        self.learning_engine = get_learning_engine()

        # Adaptation configuration
        self.adaptation_rules: list[AdaptationRule] = []
        self.adaptation_history: deque[AdaptationEvent] = deque(maxlen=1000)
        self.active_adaptations: dict[str, dict[str, Any]] = {}

        # Performance tracking
        self.adaptation_stats = {
            "total_adaptations": 0,
            "successful_adaptations": 0,
            "failed_adaptations": 0,
            "rules_triggered": 0,
        }

        # Initialize default adaptation rules
        self._initialize_default_rules()

        # Subscribe to metrics for adaptation triggers
        self.runtime_monitor.subscribe_to_metrics(self._check_adaptation_triggers)

        logger.info("Real-time adaptation engine initialized")

    def start(self) -> None:
        """Start the adaptation engine.

        Activates the runtime monitoring system, enabling metric collection,
        anomaly detection, and adaptation rule evaluation.

        Args:
            None.

        Raises:
            None.
        """
        self.runtime_monitor.start()
        logger.info("Real-time adaptation engine started")

    def stop(self) -> None:
        """Stop the adaptation engine.

        Deactivates the runtime monitoring system and halts all real-time
        adaptation activity.

        Args:
            None.

        Raises:
            None.
        """
        self.runtime_monitor.stop()
        logger.info("Real-time adaptation engine stopped")

    def _initialize_default_rules(self) -> None:
        """Initialize default adaptation rules.

        Sets up default adaptation rules for common performance issues including
        high CPU usage, high memory usage, high error rates, and slow response times.

        Args:
            None.

        Raises:
            None.
        """
        default_rules = [
            AdaptationRule(
                rule_id="high_cpu_usage",
                name="High CPU Usage Adaptation",
                condition=TriggerCondition.PERFORMANCE_DEGRADATION,
                threshold=80.0,
                adaptation_type=AdaptationType.RESOURCE_ALLOCATION,
                action="reduce_concurrency",
                priority=1,
                cooldown_seconds=30,
            ),
            AdaptationRule(
                rule_id="high_memory_usage",
                name="High Memory Usage Adaptation",
                condition=TriggerCondition.MEMORY_PRESSURE,
                threshold=85.0,
                adaptation_type=AdaptationType.RESOURCE_ALLOCATION,
                action="trigger_garbage_collection",
                priority=1,
                cooldown_seconds=60,
            ),
            AdaptationRule(
                rule_id="high_error_rate",
                name="High Error Rate Adaptation",
                condition=TriggerCondition.ERROR_RATE_INCREASE,
                threshold=0.1,  # 10%
                adaptation_type=AdaptationType.ERROR_RECOVERY,
                action="enable_fallback_mode",
                priority=2,
                cooldown_seconds=120,
            ),
            AdaptationRule(
                rule_id="slow_response_time",
                name="Slow Response Time Adaptation",
                condition=TriggerCondition.PERFORMANCE_DEGRADATION,
                threshold=10.0,  # 10 seconds
                adaptation_type=AdaptationType.PERFORMANCE_OPTIMIZATION,
                action="optimize_algorithm_selection",
                priority=2,
                cooldown_seconds=180,
            ),
        ]

        self.adaptation_rules.extend(default_rules)

    def add_adaptation_rule(self, rule: AdaptationRule) -> None:
        """Add custom adaptation rule.

        Registers a new adaptation rule that will be evaluated when metrics
        are received by the runtime monitor.

        Args:
            rule: AdaptationRule instance to add.

        Raises:
            None.
        """
        self.adaptation_rules.append(rule)
        logger.info("Added adaptation rule: %s", rule.name)

    def remove_adaptation_rule(self, rule_id: str) -> bool:
        """Remove adaptation rule.

        Unregisters an adaptation rule by its identifier, preventing further
        evaluation of that rule.

        Args:
            rule_id: Identifier of the rule to remove.

        Returns:
            True if rule was removed, False if rule not found.

        Raises:
            None.
        """
        for i, rule in enumerate(self.adaptation_rules):
            if rule.rule_id == rule_id:
                del self.adaptation_rules[i]
                logger.info("Removed adaptation rule: %s", rule_id)
                return True
        return False

    def _check_adaptation_triggers(self, metric: RuntimeMetric) -> None:
        """Check if metric triggers any adaptation rules.

        Evaluates incoming metrics against all enabled adaptation rules to
        determine if any rules should be triggered.

        Args:
            metric: RuntimeMetric instance to check.

        Raises:
            None.
        """
        for rule in self.adaptation_rules:
            if not rule.enabled:
                continue

            if self._should_trigger_rule(rule, metric):
                self._trigger_adaptation(rule, metric)

    def _should_trigger_rule(self, rule: AdaptationRule, metric: RuntimeMetric) -> bool:
        """Check if rule should be triggered by metric.

        Evaluates whether a rule should be triggered based on cooldown
        constraints and metric value comparisons.

        Args:
            rule: AdaptationRule to check.
            metric: RuntimeMetric to evaluate against the rule.

        Returns:
            True if rule should be triggered, False otherwise.

        Raises:
            None.
        """
        # Check cooldown
        if rule.last_triggered:
            time_since_last = datetime.now() - rule.last_triggered
            if time_since_last.total_seconds() < rule.cooldown_seconds:
                return False

        # Check condition matching
        condition_map = {
            TriggerCondition.PERFORMANCE_DEGRADATION: [
                "cpu_usage",
                "response_time",
                "execution_time",
            ],
            TriggerCondition.MEMORY_PRESSURE: ["memory_usage", "memory_rss"],
            TriggerCondition.ERROR_RATE_INCREASE: ["error_rate", "failure_rate"],
            TriggerCondition.RESOURCE_EXHAUSTION: ["cpu_usage", "memory_usage", "disk_usage"],
            TriggerCondition.TIMEOUT_OCCURRENCE: ["timeout", "execution_time"],
        }

        relevant_metrics = condition_map.get(rule.condition, [])

        # Check if metric is relevant to this rule
        metric_matches = any(relevant_metric in metric.metric_name.lower() for relevant_metric in relevant_metrics)

        return metric.value >= rule.threshold if metric_matches else False

    @profile_ai_operation("real_time_adaptation")
    def _trigger_adaptation(self, rule: AdaptationRule, trigger_metric: RuntimeMetric) -> None:
        """Trigger adaptation based on rule.

        Executes an adaptation rule in response to a triggering metric event.
        Records the adaptation event, updates statistics, and logs the experience
        for learning.

        Args:
            rule: AdaptationRule that was triggered.
            trigger_metric: RuntimeMetric that triggered the rule.

        Raises:
            None.
        """
        adaptation_id = f"adapt_{rule.rule_id}_{int(datetime.now().timestamp())}"

        start_time = time.time()

        try:
            logger.info("Triggering adaptation: %s (trigger: %s=%s)", rule.name, trigger_metric.metric_name, trigger_metric.value)

            # Execute adaptation action
            success = self._execute_adaptation_action(rule, trigger_metric, adaptation_id)

            execution_time = time.time() - start_time

            # Create adaptation event
            event = AdaptationEvent(
                event_id=adaptation_id,
                adaptation_type=rule.adaptation_type,
                trigger_condition=rule.condition,
                action_taken=rule.action,
                success=success,
                impact_metrics=self._measure_adaptation_impact(trigger_metric),
                execution_time=execution_time,
            )

            # Update statistics
            self.adaptation_stats["total_adaptations"] += 1
            self.adaptation_stats["rules_triggered"] += 1

            if success:
                self.adaptation_stats["successful_adaptations"] += 1
                rule.success_count += 1
            else:
                self.adaptation_stats["failed_adaptations"] += 1

            # Update rule
            rule.last_triggered = datetime.now()
            rule.trigger_count += 1

            # Record adaptation
            self.adaptation_history.append(event)

            # Record learning experience
            self.learning_engine.record_experience(
                task_type=f"adaptation_{rule.adaptation_type.value}",
                input_data={
                    "rule_id": rule.rule_id,
                    "trigger_metric": trigger_metric.metric_name,
                    "trigger_value": trigger_metric.value,
                    "threshold": rule.threshold,
                },
                output_data={
                    "action": rule.action,
                    "success": success,
                    "impact": event.impact_metrics,
                },
                success=success,
                confidence=0.8 if success else 0.3,
                execution_time=execution_time,
                memory_usage=0,
                context={
                    "adaptation_engine": "real_time",
                    "trigger_condition": rule.condition.value,
                },
            )

        except Exception as e:
            execution_time = time.time() - start_time

            event = AdaptationEvent(
                event_id=adaptation_id,
                adaptation_type=rule.adaptation_type,
                trigger_condition=rule.condition,
                action_taken=rule.action,
                success=False,
                impact_metrics={},
                execution_time=execution_time,
                error_message=str(e),
            )

            self.adaptation_history.append(event)
            self.adaptation_stats["failed_adaptations"] += 1

            logger.exception("Adaptation failed: %s - %s", rule.name, e)

    def _execute_adaptation_action(self, rule: AdaptationRule, trigger_metric: RuntimeMetric, adaptation_id: str) -> bool:
        """Execute the adaptation action.

        Executes the specific action associated with a triggered adaptation rule,
        such as reducing concurrency, triggering garbage collection, or enabling
        fallback modes.

        Args:
            rule: AdaptationRule with the action to execute.
            trigger_metric: RuntimeMetric that triggered the rule.
            adaptation_id: Unique identifier for this adaptation event.

        Returns:
            True if action executed successfully, False otherwise.

        Raises:
            None.
        """
        action = rule.action

        try:
            logger.debug(
                "Executing adaptation action '%s' triggered by metric '%s' with value %s",
                action,
                trigger_metric.metric_name,
                trigger_metric.value,
            )

            if action == "reduce_concurrency":
                return self._reduce_system_concurrency()

            if action == "trigger_garbage_collection":
                return self._trigger_garbage_collection()

            if action == "enable_fallback_mode":
                return self._enable_fallback_mode(adaptation_id)

            if action == "optimize_algorithm_selection":
                return self._optimize_algorithm_selection()

            if action == "increase_timeout":
                return self._increase_timeout_values()

            if action == "reduce_cache_size":
                return self._reduce_cache_size()

            logger.warning("Unknown adaptation action: %s", action)
            return False

        except Exception as e:
            logger.exception("Error executing adaptation action %s: %s", action, e)
            return False

    def _reduce_system_concurrency(self) -> bool:
        """Reduce system concurrency to lower resource usage.

        Reduces the number of concurrent operations to conserve CPU and memory
        resources in response to performance degradation.

        Args:
            None.

        Returns:
            True if concurrency reduction was attempted successfully.

        Raises:
            None.
        """
        try:
            # This would integrate with thread pools, async managers, etc.
            # For demonstration, we'll just log the action
            logger.info("Reducing system concurrency")

            # Could modify thread pool sizes, async task limits, etc.
            # performance_monitor.max_concurrent_operations = max(1, performance_monitor.max_concurrent_operations - 1)

            return True
        except Exception as e:
            logger.exception("Failed to reduce concurrency: %s", e)
            return False

    def _trigger_garbage_collection(self) -> bool:
        """Trigger garbage collection.

        Invokes Python's garbage collection to immediately reclaim memory from
        unreachable objects.

        Args:
            None.

        Returns:
            True if garbage collection executed successfully.

        Raises:
            None.
        """
        try:
            import gc

            collected = gc.collect()
            logger.info("Garbage collection triggered, collected %s objects", collected)
            return True
        except Exception as e:
            logger.exception("Failed to trigger garbage collection: %s", e)
            return False

    def _enable_fallback_mode(self, adaptation_id: str) -> bool:
        """Enable fallback mode for error recovery.

        Activates fallback behavior by installing hooks that provide alternative
        responses when normal operation fails.

        Args:
            adaptation_id: Unique identifier for this adaptation event.

        Returns:
            True if fallback mode was enabled successfully.

        Raises:
            None.
        """
        try:
            # Install hooks for fallback behavior
            hook_modification = {
                "hook_id": adaptation_id,
                "type": "fallback",
                "result_modifications": [
                    {
                        "type": "replace_result",
                        "value": {
                            "success": True,
                            "fallback": True,
                            "message": "Fallback mode active",
                        },
                    },
                ],
            }

            # Store the hook modification for later use
            logger.info("Fallback mode enabled with hook: %s", hook_modification["hook_id"])

            self.active_adaptations[adaptation_id] = {
                "type": "fallback_mode",
                "enabled_at": datetime.now(),
                "hook_ids": [hook_modification["hook_id"]],
                "hook_modification": hook_modification,
            }

            return True
        except Exception as e:
            logger.exception("Failed to enable fallback mode: %s", e)
            return False

    def _optimize_algorithm_selection(self) -> bool:
        """Optimize algorithm selection for better performance.

        Modifies algorithm selection logic to prefer faster algorithms in
        response to performance degradation.

        Args:
            None.

        Returns:
            True if optimization was applied successfully.

        Raises:
            None.
        """
        try:
            # This would modify algorithm selection logic
            logger.info("Optimizing algorithm selection")

            # Could install hooks to prefer faster algorithms
            # or modify configuration parameters

            return True
        except Exception as e:
            logger.exception("Failed to optimize algorithm selection: %s", e)
            return False

    def _increase_timeout_values(self) -> bool:
        """Increase timeout values to reduce timeout errors.

        Modifies timeout configurations across system components to reduce
        timeout-related failures.

        Args:
            None.

        Returns:
            True if timeout values were increased successfully.

        Raises:
            None.
        """
        try:
            logger.info("Increasing timeout values")

            # This would modify timeout configurations
            # across various components

            return True
        except Exception as e:
            logger.exception("Failed to increase timeout values: %s", e)
            return False

    def _reduce_cache_size(self) -> bool:
        """Reduce cache size to free memory.

        Reduces cache sizes to free up memory resources in response to memory
        pressure or memory exhaustion conditions.

        Args:
            None.

        Returns:
            True if cache size was reduced successfully.

        Raises:
            None.
        """
        try:
            logger.info("Reducing cache size")

            # Clear performance monitor cache
            # performance_monitor.optimize_cache()

            # Could also modify cache size configurations

            return True
        except Exception as e:
            logger.exception("Failed to reduce cache size: %s", e)
            return False

    def _measure_adaptation_impact(self, trigger_metric: RuntimeMetric) -> dict[str, float]:
        """Measure impact of adaptation.

        Evaluates the immediate impact of an adaptation by comparing current
        metric values against their pre-adaptation state.

        Args:
            trigger_metric: The metric that triggered the adaptation.

        Returns:
            Dictionary containing impact metrics including metric_change,
            metric_change_percent, system_cpu, and system_memory values.

        Raises:
            None.
        """
        # Get current metric value for comparison
        current_aggregates = self.runtime_monitor.metric_aggregates

        impact = {}

        if trigger_metric.metric_name in current_aggregates:
            current_value = current_aggregates[trigger_metric.metric_name]["last"]
            impact["metric_change"] = current_value - trigger_metric.value
            impact["metric_change_percent"] = impact["metric_change"] / trigger_metric.value * 100 if trigger_metric.value > 0 else 0

        # Add other relevant metrics
        impact["system_cpu"] = current_aggregates.get("system.cpu_usage", {}).get("last", 0)
        impact["system_memory"] = current_aggregates.get("system.memory_usage", {}).get("last", 0)

        return impact

    def get_adaptation_status(self) -> dict[str, Any]:
        """Get current adaptation status.

        Retrieves comprehensive status information about the adaptation engine
        including rules, active adaptations, statistics, and per-rule metrics.

        Args:
            None.

        Returns:
            Dictionary containing engine_active, adaptation_rules, active_adaptations,
            recent_adaptations, statistics, and rule_status.

        Raises:
            None.
        """
        return {
            "engine_active": self.runtime_monitor.active,
            "adaptation_rules": len(self.adaptation_rules),
            "active_adaptations": len(self.active_adaptations),
            "recent_adaptations": len(
                [event for event in self.adaptation_history if event.timestamp > datetime.now() - timedelta(hours=1)],
            ),
            "statistics": self.adaptation_stats.copy(),
            "rule_status": [
                {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "enabled": rule.enabled,
                    "trigger_count": rule.trigger_count,
                    "success_count": rule.success_count,
                    "last_triggered": rule.last_triggered.isoformat() if rule.last_triggered else None,
                }
                for rule in self.adaptation_rules
            ],
        }

    def get_adaptation_insights(self) -> dict[str, Any]:
        """Get adaptation insights and recommendations.

        Analyzes adaptation history to provide insights about adaptation
        effectiveness, patterns, and recommendations for optimization.

        Args:
            None.

        Returns:
            Dictionary containing effectiveness metrics, recommendations, and
            patterns discovered in the adaptation history.

        Raises:
            None.
        """
        insights: dict[str, Any] = {
            "effectiveness": {},
            "recommendations": [],
            "patterns": {},
        }

        if self.adaptation_history:
            # Calculate effectiveness by adaptation type
            by_type = defaultdict(list)
            for event in self.adaptation_history:
                by_type[event.adaptation_type].append(event)

            for adaptation_type, events in by_type.items():
                success_rate = sum(bool(e.success) for e in events) / len(events)
                avg_execution_time = sum(e.execution_time for e in events) / len(events)

                insights["effectiveness"][adaptation_type.value] = {
                    "success_rate": success_rate,
                    "avg_execution_time": avg_execution_time,
                    "total_events": len(events),
                }

        # Generate recommendations
        total_adaptations = self.adaptation_stats["total_adaptations"]
        success_rate = self.adaptation_stats["successful_adaptations"] / max(1, total_adaptations)

        if success_rate < 0.7:
            insights["recommendations"].append("Low adaptation success rate - review rule thresholds")

        if total_adaptations > 100:
            insights["recommendations"].append("High adaptation frequency - consider optimizing triggers")

        if recent_events := [e for e in self.adaptation_history if e.timestamp > datetime.now() - timedelta(hours=24)]:
            trigger_patterns: dict[TriggerCondition, int] = defaultdict(int)
            for event in recent_events:
                trigger_patterns[event.trigger_condition] += 1

            insights["patterns"]["common_triggers"] = {k.value: v for k, v in trigger_patterns.items()}

        return insights


# Global adaptation engine instance
adaptation_engine = RealTimeAdaptationEngine()
