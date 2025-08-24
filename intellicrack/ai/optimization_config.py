"""AI System Optimization Configuration.

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

import gc
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger
from .performance_monitor import performance_monitor

logger = get_logger(__name__)

try:
    from intellicrack.handlers.psutil_handler import psutil

    PSUTIL_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in optimization_config: %s", e)
    psutil = None
    PSUTIL_AVAILABLE = False


@dataclass
class OptimizationRule:
    """Configuration for optimization rules."""

    name: str
    metric_name: str
    threshold_type: str  # "warning", "critical"
    threshold_value: float
    action: str  # "log", "gc", "cache_clear", "custom"
    enabled: bool = True
    cooldown_seconds: int = 60
    custom_handler: Callable | None = None
    last_triggered: datetime | None = None


@dataclass
class CacheConfig:
    """Cache configuration."""

    max_size: int = 1000
    ttl_seconds: int = 300
    cleanup_interval: int = 60
    enable_lru: bool = True
    enable_stats: bool = True


@dataclass
class PerformanceConfig:
    """Performance optimization configuration."""

    enable_monitoring: bool = True
    monitoring_interval: float = 1.0
    max_history_size: int = 1000
    enable_gc_optimization: bool = True
    gc_threshold_mb: float = 100.0
    enable_cache_optimization: bool = True
    cache_config: CacheConfig = field(default_factory=CacheConfig)
    optimization_rules: list[OptimizationRule] = field(default_factory=list)


class OptimizationManager:
    """Manages AI system optimization."""

    def __init__(self, config: PerformanceConfig | None = None):
        """Initialize the optimization manager.

        Args:
            config: Performance configuration settings.
                   Uses default configuration if not provided.

        """
        self.config = config or self._create_default_config()
        self.active_optimizations: dict[str, bool] = {}
        self.optimization_stats: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()

        # Cache management
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "size": 0,
        }

        # GC optimization
        self.gc_stats = {
            "collections": 0,
            "objects_collected": 0,
            "memory_freed_mb": 0.0,
        }

        # Initialize optimization rules
        self._setup_optimization_rules()

        logger.info("Optimization manager initialized")

    def _create_default_config(self) -> PerformanceConfig:
        """Create default optimization configuration."""
        rules = [
            OptimizationRule(
                name="high_memory_usage",
                metric_name="system.memory_rss",
                threshold_type="warning",
                threshold_value=500 * 1024 * 1024,  # 500MB
                action="gc",
                cooldown_seconds=30,
            ),
            OptimizationRule(
                name="critical_memory_usage",
                metric_name="system.memory_rss",
                threshold_type="critical",
                threshold_value=1024 * 1024 * 1024,  # 1GB
                action="gc",
                cooldown_seconds=10,
            ),
            OptimizationRule(
                name="high_cpu_usage",
                metric_name="system.cpu_usage",
                threshold_type="warning",
                threshold_value=80.0,
                action="log",
                cooldown_seconds=60,
            ),
            OptimizationRule(
                name="slow_operations",
                metric_name="operation.execution_time",
                threshold_type="warning",
                threshold_value=10.0,
                action="log",
                cooldown_seconds=120,
            ),
            OptimizationRule(
                name="cache_overflow",
                metric_name="cache.size",
                threshold_type="warning",
                threshold_value=800,  # 80% of default max_size
                action="cache_clear",
                cooldown_seconds=30,
            ),
        ]

        return PerformanceConfig(optimization_rules=rules)

    def _setup_optimization_rules(self):
        """Set up optimization rules with performance monitor."""
        for rule in self.config.optimization_rules:
            if rule.enabled:
                performance_monitor.add_optimization_rule(
                    self._create_rule_handler(rule),
                )

    def _create_rule_handler(self, rule: OptimizationRule) -> Callable:
        """Create handler for optimization rule."""

        def handler(metric_name: str, level: str, value: float):
            # Check if rule applies
            if not self._rule_matches(rule, metric_name, level):
                return

            # Check cooldown
            if not self._check_cooldown(rule):
                return

            # Execute optimization action
            self._execute_optimization(rule, metric_name, level, value)

        return handler

    def _rule_matches(self, rule: OptimizationRule, metric_name: str, level: str) -> bool:
        """Check if rule matches the current metric and level."""
        if rule.threshold_type != level:
            return False

        # Support partial metric name matching
        if rule.metric_name in metric_name or metric_name.startswith(rule.metric_name):
            return True

        return False

    def _check_cooldown(self, rule: OptimizationRule) -> bool:
        """Check if rule is within cooldown period."""
        if rule.last_triggered is None:
            return True

        time_since_last = datetime.now() - rule.last_triggered
        return time_since_last.total_seconds() >= rule.cooldown_seconds

    def _execute_optimization(
        self, rule: OptimizationRule, metric_name: str, level: str, value: float
    ):
        """Execute optimization action."""
        with self.lock:
            try:
                logger.info(f"Executing optimization rule '{rule.name}' for {metric_name}={value}")

                if rule.action == "gc":
                    self._execute_garbage_collection()
                elif rule.action == "cache_clear":
                    self._execute_cache_clear()
                elif rule.action == "log":
                    self._execute_logging(rule, metric_name, level, value)
                elif rule.action == "custom" and rule.custom_handler:
                    rule.custom_handler(metric_name, level, value)

                # Update rule statistics
                rule.last_triggered = datetime.now()
                self._update_optimization_stats(rule.name, "executed")

            except Exception as e:
                logger.error(f"Error executing optimization rule '{rule.name}': {e}")
                self._update_optimization_stats(rule.name, "error")

    def _execute_garbage_collection(self):
        """Execute garbage collection optimization."""
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not available - skipping memory monitoring during GC")
            gc.collect()
            return

        try:
            process = psutil.Process()

            # Record memory before GC
            memory_before = process.memory_info().rss

            # Force garbage collection
            collected = gc.collect()

            # Record memory after GC
            memory_after = process.memory_info().rss
            memory_freed = memory_before - memory_after
            memory_freed_mb = memory_freed / 1024 / 1024

            # Update statistics
            self.gc_stats["collections"] += 1
            self.gc_stats["objects_collected"] += collected
            self.gc_stats["memory_freed_mb"] += memory_freed_mb

            logger.info(f"GC collected {collected} objects, freed {memory_freed_mb:.2f}MB")
        except Exception as e:
            logger.warning(f"Error during garbage collection monitoring: {e}")
            # Fallback - just run GC without monitoring
            collected = gc.collect()
            self.gc_stats["collections"] += 1
            self.gc_stats["objects_collected"] += collected

    def _execute_cache_clear(self):
        """Execute cache clearing optimization."""
        # Clear performance monitor cache
        cleared_entries = len(performance_monitor.performance_cache)
        performance_monitor.performance_cache.clear()

        # Update statistics
        self.cache_stats["evictions"] += cleared_entries
        self.cache_stats["size"] = 0

        logger.info(f"Cleared {cleared_entries} cache entries")

    def _execute_logging(self, rule: OptimizationRule, metric_name: str, level: str, value: float):
        """Execute logging optimization action."""
        log_message = f"Performance alert - {rule.name}: {metric_name}={value} ({level})"

        if level == "critical":
            logger.critical(log_message)
        elif level == "warning":
            logger.warning(log_message)
        else:
            logger.info(log_message)

    def _update_optimization_stats(self, rule_name: str, action: str):
        """Update optimization statistics."""
        if rule_name not in self.optimization_stats:
            self.optimization_stats[rule_name] = {
                "executed": 0,
                "error": 0,
                "last_execution": None,
            }

        self.optimization_stats[rule_name][action] += 1
        if action == "executed":
            self.optimization_stats[rule_name]["last_execution"] = datetime.now().isoformat()

    def add_custom_rule(self, rule: OptimizationRule):
        """Add custom optimization rule."""
        self.config.optimization_rules.append(rule)

        if rule.enabled:
            performance_monitor.add_optimization_rule(
                self._create_rule_handler(rule),
            )

        logger.info(f"Added custom optimization rule: {rule.name}")

    def enable_rule(self, rule_name: str):
        """Enable optimization rule."""
        for rule in self.config.optimization_rules:
            if rule.name == rule_name:
                rule.enabled = True
                logger.info(f"Enabled optimization rule: {rule_name}")
                return

        logger.warning(f"Optimization rule not found: {rule_name}")

    def disable_rule(self, rule_name: str):
        """Disable optimization rule."""
        for rule in self.config.optimization_rules:
            if rule.name == rule_name:
                rule.enabled = False
                logger.info(f"Disabled optimization rule: {rule_name}")
                return

        logger.warning(f"Optimization rule not found: {rule_name}")

    def get_optimization_summary(self) -> dict[str, Any]:
        """Get optimization summary."""
        return {
            "config": {
                "monitoring_enabled": self.config.enable_monitoring,
                "gc_optimization": self.config.enable_gc_optimization,
                "cache_optimization": self.config.enable_cache_optimization,
                "active_rules": len([r for r in self.config.optimization_rules if r.enabled]),
            },
            "gc_stats": self.gc_stats.copy(),
            "cache_stats": self.cache_stats.copy(),
            "rule_stats": self.optimization_stats.copy(),
            "performance_summary": performance_monitor.get_metrics_summary(timedelta(hours=1)),
        }

    def optimize_memory_usage(self):
        """Manual memory optimization."""
        logger.info("Running manual memory optimization")

        # Force garbage collection
        self._execute_garbage_collection()

        # Clear caches if enabled
        if self.config.enable_cache_optimization:
            self._execute_cache_clear()

        # Optimize performance monitor
        performance_monitor.optimize_cache()

        logger.info("Manual memory optimization completed")

    def optimize_cache_performance(self):
        """Optimize cache performance."""
        if not self.config.enable_cache_optimization:
            return

        logger.info("Running cache performance optimization")

        # Clean expired entries
        performance_monitor.optimize_cache()

        # Update cache statistics
        self.cache_stats["size"] = len(performance_monitor.performance_cache)

        logger.info("Cache performance optimization completed")

    def benchmark_optimizations(self) -> dict[str, float]:
        """Benchmark optimization effectiveness."""
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not available - returning simplified benchmark")
            return {"cpu_percent": 0.0, "memory_percent": 0.0}

        try:
            process = psutil.Process()

            # Baseline measurements
            baseline_memory = process.memory_info().rss
            baseline_objects = len(gc.get_objects())

            logger.debug(
                f"Baseline measurement: {baseline_memory} bytes memory, {baseline_objects} objects"
            )

            # Create some load
            test_data = []
            for i in range(1000):
                test_data.append({f"key_{i}": f"value_{i}" * 100})

            # Measure before optimization
            before_memory = process.memory_info().rss
            before_objects = len(gc.get_objects())

            # Run optimizations
            start_time = time.time()
            self.optimize_memory_usage()
            optimization_time = time.time() - start_time

            # Measure after optimization
            after_memory = process.memory_info().rss
            after_objects = len(gc.get_objects())

            # Calculate metrics
            memory_saved = (before_memory - after_memory) / 1024 / 1024
            objects_cleaned = before_objects - after_objects
            memory_efficiency = memory_saved / optimization_time if optimization_time > 0 else 0

            # Cleanup test data
            del test_data
            gc.collect()

            return {
                "optimization_time_seconds": optimization_time,
                "memory_saved_mb": memory_saved,
                "objects_cleaned": objects_cleaned,
                "memory_efficiency_mb_per_second": memory_efficiency,
                "baseline_memory_mb": baseline_memory / 1024 / 1024,
                "final_memory_mb": after_memory / 1024 / 1024,
            }
        except Exception as e:
            logger.warning(f"Error during performance benchmark: {e}")
            return {
                "optimization_time_seconds": 0.0,
                "memory_saved_mb": 0.0,
                "objects_cleaned": 0,
                "memory_efficiency_mb_per_second": 0.0,
                "baseline_memory_mb": 0.0,
                "final_memory_mb": 0.0,
            }

    def export_config(self, file_path: Path):
        """Export optimization configuration."""
        config_data = {
            "enable_monitoring": self.config.enable_monitoring,
            "monitoring_interval": self.config.monitoring_interval,
            "max_history_size": self.config.max_history_size,
            "enable_gc_optimization": self.config.enable_gc_optimization,
            "gc_threshold_mb": self.config.gc_threshold_mb,
            "enable_cache_optimization": self.config.enable_cache_optimization,
            "cache_config": {
                "max_size": self.config.cache_config.max_size,
                "ttl_seconds": self.config.cache_config.ttl_seconds,
                "cleanup_interval": self.config.cache_config.cleanup_interval,
                "enable_lru": self.config.cache_config.enable_lru,
                "enable_stats": self.config.cache_config.enable_stats,
            },
            "optimization_rules": [
                {
                    "name": rule.name,
                    "metric_name": rule.metric_name,
                    "threshold_type": rule.threshold_type,
                    "threshold_value": rule.threshold_value,
                    "action": rule.action,
                    "enabled": rule.enabled,
                    "cooldown_seconds": rule.cooldown_seconds,
                }
                for rule in self.config.optimization_rules
            ],
        }

        with open(file_path, "w") as f:
            json.dump(config_data, f, indent=2)

        logger.info(f"Optimization config exported to {file_path}")

    def import_config(self, file_path: Path):
        """Import optimization configuration."""
        try:
            with open(file_path) as f:
                config_data = json.load(f)

            # Update configuration
            self.config.enable_monitoring = config_data.get("enable_monitoring", True)
            self.config.monitoring_interval = config_data.get("monitoring_interval", 1.0)
            self.config.max_history_size = config_data.get("max_history_size", 1000)
            self.config.enable_gc_optimization = config_data.get("enable_gc_optimization", True)
            self.config.gc_threshold_mb = config_data.get("gc_threshold_mb", 100.0)
            self.config.enable_cache_optimization = config_data.get(
                "enable_cache_optimization", True
            )

            # Update cache config
            cache_config = config_data.get("cache_config", {})
            self.config.cache_config.max_size = cache_config.get("max_size", 1000)
            self.config.cache_config.ttl_seconds = cache_config.get("ttl_seconds", 300)
            self.config.cache_config.cleanup_interval = cache_config.get("cleanup_interval", 60)
            self.config.cache_config.enable_lru = cache_config.get("enable_lru", True)
            self.config.cache_config.enable_stats = cache_config.get("enable_stats", True)

            # Update optimization rules
            self.config.optimization_rules.clear()
            for rule_data in config_data.get("optimization_rules", []):
                rule = OptimizationRule(
                    name=rule_data["name"],
                    metric_name=rule_data["metric_name"],
                    threshold_type=rule_data["threshold_type"],
                    threshold_value=rule_data["threshold_value"],
                    action=rule_data["action"],
                    enabled=rule_data.get("enabled", True),
                    cooldown_seconds=rule_data.get("cooldown_seconds", 60),
                )
                self.config.optimization_rules.append(rule)

            # Re-setup optimization rules
            self._setup_optimization_rules()

            logger.info(f"Optimization config imported from {file_path}")

        except Exception as e:
            logger.error(f"Failed to import optimization config: {e}")

    def get_recommendations(self) -> list[str]:
        """Get optimization recommendations."""
        recommendations = []
        summary = self.get_optimization_summary()

        # Memory recommendations
        if self.gc_stats["memory_freed_mb"] > 50:
            recommendations.append(
                "Consider increasing GC frequency - significant memory is being freed"
            )

        # Cache recommendations
        cache_stats = summary["cache_stats"]
        if cache_stats["hits"] > 0:
            hit_rate = cache_stats["hits"] / (cache_stats["hits"] + cache_stats["misses"])
            if hit_rate < 0.5:
                recommendations.append("Low cache hit rate - consider increasing cache size or TTL")

        # Performance recommendations
        perf_summary = summary["performance_summary"]
        system_health = perf_summary.get("system_health", {})

        if system_health.get("score", 100) < 70:
            recommendations.append("System health is degraded - consider running optimizations")

        # Rule-specific recommendations
        for rule_name, stats in self.optimization_stats.items():
            if stats["executed"] > 10:
                recommendations.append(
                    f"Rule '{rule_name}' is triggering frequently - consider adjusting thresholds"
                )

        return recommendations


# Global optimization manager
optimization_manager = OptimizationManager()


def optimize_ai_performance():
    """Quick optimization of AI system performance."""
    optimization_manager.optimize_memory_usage()
    optimization_manager.optimize_cache_performance()


def get_performance_recommendations() -> list[str]:
    """Get performance optimization recommendations."""
    return optimization_manager.get_recommendations()


def benchmark_ai_optimizations() -> dict[str, float]:
    """Benchmark AI optimization effectiveness."""
    return optimization_manager.benchmark_optimizations()
