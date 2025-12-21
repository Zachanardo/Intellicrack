"""Production tests for AI system optimization configuration.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import gc
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.optimization_config import (
    CacheConfig,
    OptimizationManager,
    OptimizationRule,
    PerformanceConfig,
    benchmark_ai_optimizations,
    get_performance_recommendations,
    optimization_manager,
    optimize_ai_performance,
)


class TestOptimizationRule:
    """Test OptimizationRule dataclass configuration."""

    def test_optimization_rule_creation_with_all_fields(self) -> None:
        """OptimizationRule stores complete rule configuration."""
        handler_called = False

        def custom_handler(metric: str, level: str, value: float) -> None:
            nonlocal handler_called
            handler_called = True

        rule = OptimizationRule(
            name="test_rule",
            metric_name="test.metric",
            threshold_type="warning",
            threshold_value=100.0,
            action="custom",
            enabled=True,
            cooldown_seconds=30,
            custom_handler=custom_handler,
        )

        assert rule.name == "test_rule"
        assert rule.metric_name == "test.metric"
        assert rule.threshold_type == "warning"
        assert rule.threshold_value == 100.0
        assert rule.action == "custom"
        assert rule.enabled is True
        assert rule.cooldown_seconds == 30
        assert rule.custom_handler is not None
        assert rule.last_triggered is None

        rule.custom_handler("test.metric", "warning", 150.0)
        assert handler_called is True

    def test_optimization_rule_default_values(self) -> None:
        """OptimizationRule uses default enabled and cooldown values."""
        rule = OptimizationRule(
            name="default_rule",
            metric_name="memory",
            threshold_type="critical",
            threshold_value=500.0,
            action="gc",
        )

        assert rule.enabled is True
        assert rule.cooldown_seconds == 60
        assert rule.custom_handler is None
        assert rule.last_triggered is None

    def test_optimization_rule_disabled(self) -> None:
        """OptimizationRule can be created in disabled state."""
        rule = OptimizationRule(
            name="disabled_rule",
            metric_name="cpu",
            threshold_type="warning",
            threshold_value=80.0,
            action="log",
            enabled=False,
        )

        assert rule.enabled is False


class TestCacheConfig:
    """Test CacheConfig dataclass."""

    def test_cache_config_default_values(self) -> None:
        """CacheConfig initializes with sensible defaults."""
        config = CacheConfig()

        assert config.max_size == 1000
        assert config.ttl_seconds == 300
        assert config.cleanup_interval == 60
        assert config.enable_lru is True
        assert config.enable_stats is True

    def test_cache_config_custom_values(self) -> None:
        """CacheConfig accepts custom configuration values."""
        config = CacheConfig(
            max_size=5000,
            ttl_seconds=600,
            cleanup_interval=120,
            enable_lru=False,
            enable_stats=False,
        )

        assert config.max_size == 5000
        assert config.ttl_seconds == 600
        assert config.cleanup_interval == 120
        assert config.enable_lru is False
        assert config.enable_stats is False


class TestPerformanceConfig:
    """Test PerformanceConfig dataclass."""

    def test_performance_config_default_values(self) -> None:
        """PerformanceConfig initializes with default settings."""
        config = PerformanceConfig()

        assert config.enable_monitoring is True
        assert config.monitoring_interval == 1.0
        assert config.max_history_size == 1000
        assert config.enable_gc_optimization is True
        assert config.gc_threshold_mb == 100.0
        assert config.enable_cache_optimization is True
        assert isinstance(config.cache_config, CacheConfig)
        assert config.optimization_rules == []

    def test_performance_config_with_custom_cache(self) -> None:
        """PerformanceConfig accepts custom cache configuration."""
        cache_config = CacheConfig(max_size=2000, ttl_seconds=900)
        config = PerformanceConfig(cache_config=cache_config)

        assert config.cache_config.max_size == 2000
        assert config.cache_config.ttl_seconds == 900

    def test_performance_config_with_rules(self) -> None:
        """PerformanceConfig accepts optimization rules."""
        rules = [
            OptimizationRule(
                name="rule1",
                metric_name="memory",
                threshold_type="warning",
                threshold_value=100.0,
                action="gc",
            ),
            OptimizationRule(
                name="rule2",
                metric_name="cpu",
                threshold_type="critical",
                threshold_value=90.0,
                action="log",
            ),
        ]

        config = PerformanceConfig(optimization_rules=rules)

        assert len(config.optimization_rules) == 2
        assert config.optimization_rules[0].name == "rule1"
        assert config.optimization_rules[1].name == "rule2"


class TestOptimizationManager:
    """Test OptimizationManager functionality."""

    def test_manager_initialization_default_config(self) -> None:
        """OptimizationManager initializes with default configuration."""
        manager = OptimizationManager()

        assert manager.config is not None
        assert isinstance(manager.config, PerformanceConfig)
        assert manager.config.enable_monitoring is True
        assert len(manager.config.optimization_rules) > 0
        assert manager.active_optimizations == {}
        assert manager.optimization_stats == {}

    def test_manager_initialization_custom_config(self) -> None:
        """OptimizationManager accepts custom configuration."""
        custom_config = PerformanceConfig(
            enable_monitoring=False,
            monitoring_interval=2.0,
            max_history_size=500,
        )

        manager = OptimizationManager(config=custom_config)

        assert manager.config.enable_monitoring is False
        assert manager.config.monitoring_interval == 2.0
        assert manager.config.max_history_size == 500

    def test_manager_default_rules_created(self) -> None:
        """OptimizationManager creates default optimization rules."""
        manager = OptimizationManager()

        rule_names = [rule.name for rule in manager.config.optimization_rules]

        assert "high_memory_usage" in rule_names
        assert "critical_memory_usage" in rule_names
        assert "high_cpu_usage" in rule_names
        assert "slow_operations" in rule_names
        assert "cache_overflow" in rule_names

    def test_manager_cache_stats_initialized(self) -> None:
        """OptimizationManager initializes cache statistics."""
        manager = OptimizationManager()

        assert "hits" in manager.cache_stats
        assert "misses" in manager.cache_stats
        assert "evictions" in manager.cache_stats
        assert "size" in manager.cache_stats
        assert manager.cache_stats["hits"] == 0

    def test_manager_gc_stats_initialized(self) -> None:
        """OptimizationManager initializes garbage collection statistics."""
        manager = OptimizationManager()

        assert "collections" in manager.gc_stats
        assert "objects_collected" in manager.gc_stats
        assert "memory_freed_mb" in manager.gc_stats
        assert manager.gc_stats["collections"] == 0


class TestOptimizationExecution:
    """Test optimization execution functionality."""

    def test_execute_garbage_collection_updates_stats(self) -> None:
        """Garbage collection execution updates collection statistics."""
        manager = OptimizationManager()
        initial_collections = manager.gc_stats["collections"]

        manager._execute_garbage_collection()

        assert manager.gc_stats["collections"] == initial_collections + 1
        assert manager.gc_stats["objects_collected"] >= 0

    def test_execute_cache_clear_updates_stats(self) -> None:
        """Cache clearing execution updates cache statistics."""
        manager = OptimizationManager()

        manager._execute_cache_clear()

        assert manager.cache_stats["size"] == 0

    def test_execute_logging_action(self) -> None:
        """Logging optimization action executes without errors."""
        manager = OptimizationManager()
        rule = OptimizationRule(
            name="test_log",
            metric_name="test",
            threshold_type="warning",
            threshold_value=50.0,
            action="log",
        )

        manager._execute_logging(rule, "test.metric", "warning", 75.0)

    def test_custom_handler_execution(self) -> None:
        """Custom handler executes when rule action is custom."""
        manager = OptimizationManager()
        handler_args: list[tuple[str, str, float]] = []

        def custom_handler(metric: str, level: str, value: float) -> None:
            handler_args.append((metric, level, value))

        rule = OptimizationRule(
            name="custom_rule",
            metric_name="custom",
            threshold_type="warning",
            threshold_value=100.0,
            action="custom",
            custom_handler=custom_handler,
        )

        manager._execute_optimization(rule, "custom.metric", "warning", 150.0)

        assert len(handler_args) == 1
        assert handler_args[0] == ("custom.metric", "warning", 150.0)


class TestRuleManagement:
    """Test optimization rule management."""

    def test_add_custom_rule(self) -> None:
        """add_custom_rule adds new optimization rule."""
        manager = OptimizationManager()
        initial_count = len(manager.config.optimization_rules)

        custom_rule = OptimizationRule(
            name="custom_memory",
            metric_name="memory.custom",
            threshold_type="warning",
            threshold_value=200.0,
            action="gc",
        )

        manager.add_custom_rule(custom_rule)

        assert len(manager.config.optimization_rules) == initial_count + 1
        assert custom_rule in manager.config.optimization_rules

    def test_enable_rule_by_name(self) -> None:
        """enable_rule enables existing optimization rule."""
        manager = OptimizationManager()

        test_rule = OptimizationRule(
            name="test_enable",
            metric_name="test",
            threshold_type="warning",
            threshold_value=50.0,
            action="log",
            enabled=False,
        )
        manager.config.optimization_rules.append(test_rule)

        manager.enable_rule("test_enable")

        assert test_rule.enabled is True

    def test_disable_rule_by_name(self) -> None:
        """disable_rule disables existing optimization rule."""
        manager = OptimizationManager()

        manager.disable_rule("high_memory_usage")

        rule = next((r for r in manager.config.optimization_rules if r.name == "high_memory_usage"), None)
        assert rule is not None
        assert rule.enabled is False

    def test_enable_nonexistent_rule(self) -> None:
        """enable_rule handles nonexistent rule gracefully."""
        manager = OptimizationManager()

        manager.enable_rule("nonexistent_rule")

    def test_disable_nonexistent_rule(self) -> None:
        """disable_rule handles nonexistent rule gracefully."""
        manager = OptimizationManager()

        manager.disable_rule("nonexistent_rule")


class TestOptimizationSummary:
    """Test optimization summary and statistics."""

    def test_get_optimization_summary_structure(self) -> None:
        """get_optimization_summary returns complete summary structure."""
        manager = OptimizationManager()

        summary = manager.get_optimization_summary()

        assert "config" in summary
        assert "gc_stats" in summary
        assert "cache_stats" in summary
        assert "rule_stats" in summary
        assert "performance_summary" in summary

    def test_optimization_summary_config_details(self) -> None:
        """Optimization summary includes configuration details."""
        manager = OptimizationManager()

        summary = manager.get_optimization_summary()
        config = summary["config"]

        assert "monitoring_enabled" in config
        assert "gc_optimization" in config
        assert "cache_optimization" in config
        assert "active_rules" in config
        assert isinstance(config["active_rules"], int)

    def test_optimization_summary_gc_stats(self) -> None:
        """Optimization summary includes garbage collection statistics."""
        manager = OptimizationManager()
        manager._execute_garbage_collection()

        summary = manager.get_optimization_summary()
        gc_stats = summary["gc_stats"]

        assert "collections" in gc_stats
        assert "objects_collected" in gc_stats
        assert "memory_freed_mb" in gc_stats
        assert gc_stats["collections"] >= 1

    def test_optimization_summary_cache_stats(self) -> None:
        """Optimization summary includes cache statistics."""
        manager = OptimizationManager()

        summary = manager.get_optimization_summary()
        cache_stats = summary["cache_stats"]

        assert "hits" in cache_stats
        assert "misses" in cache_stats
        assert "evictions" in cache_stats
        assert "size" in cache_stats


class TestManualOptimization:
    """Test manual optimization operations."""

    def test_optimize_memory_usage_runs_gc(self) -> None:
        """optimize_memory_usage executes garbage collection."""
        manager = OptimizationManager()
        initial_collections = manager.gc_stats["collections"]

        manager.optimize_memory_usage()

        assert manager.gc_stats["collections"] > initial_collections

    def test_optimize_memory_usage_clears_cache(self) -> None:
        """optimize_memory_usage clears caches when enabled."""
        manager = OptimizationManager()
        manager.config.enable_cache_optimization = True

        manager.optimize_memory_usage()

        assert manager.cache_stats["size"] == 0

    def test_optimize_cache_performance_when_disabled(self) -> None:
        """optimize_cache_performance skips when cache optimization disabled."""
        manager = OptimizationManager()
        manager.config.enable_cache_optimization = False

        manager.optimize_cache_performance()

    def test_optimize_cache_performance_when_enabled(self) -> None:
        """optimize_cache_performance runs when cache optimization enabled."""
        manager = OptimizationManager()
        manager.config.enable_cache_optimization = True

        manager.optimize_cache_performance()


class TestBenchmarking:
    """Test optimization benchmarking functionality."""

    def test_benchmark_optimizations_returns_metrics(self) -> None:
        """benchmark_optimizations returns performance metrics."""
        manager = OptimizationManager()

        results = manager.benchmark_optimizations()

        assert "optimization_time_seconds" in results
        assert "memory_saved_mb" in results
        assert "objects_cleaned" in results
        assert "memory_efficiency_mb_per_second" in results
        assert "baseline_memory_mb" in results
        assert "final_memory_mb" in results

    def test_benchmark_optimizations_executes_full_cycle(self) -> None:
        """benchmark_optimizations executes complete optimization cycle."""
        manager = OptimizationManager()
        initial_collections = manager.gc_stats["collections"]

        results = manager.benchmark_optimizations()

        assert manager.gc_stats["collections"] > initial_collections
        assert results["optimization_time_seconds"] >= 0.0


class TestConfigurationPersistence:
    """Test configuration export and import functionality."""

    def test_export_config_creates_file(self) -> None:
        """export_config creates configuration file with correct structure."""
        manager = OptimizationManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test_config.json"

            manager.export_config(config_path)

            assert config_path.exists()

            with open(config_path) as f:
                data = json.load(f)

            assert "enable_monitoring" in data
            assert "cache_config" in data
            assert "optimization_rules" in data

    def test_export_config_includes_all_settings(self) -> None:
        """export_config includes all configuration settings."""
        manager = OptimizationManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "full_config.json"

            manager.export_config(config_path)

            with open(config_path) as f:
                data = json.load(f)

            assert "monitoring_interval" in data
            assert "max_history_size" in data
            assert "enable_gc_optimization" in data
            assert "gc_threshold_mb" in data
            assert "enable_cache_optimization" in data

    def test_import_config_loads_settings(self) -> None:
        """import_config loads configuration from file."""
        manager = OptimizationManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "import_config.json"

            config_data = {
                "enable_monitoring": False,
                "monitoring_interval": 5.0,
                "max_history_size": 2000,
                "enable_gc_optimization": False,
                "gc_threshold_mb": 200.0,
                "enable_cache_optimization": False,
                "cache_config": {"max_size": 3000, "ttl_seconds": 600},
                "optimization_rules": [],
            }

            with open(config_path, "w") as f:
                json.dump(config_data, f)

            manager.import_config(config_path)

            assert manager.config.enable_monitoring is False
            assert manager.config.monitoring_interval == 5.0
            assert manager.config.max_history_size == 2000
            assert manager.config.enable_gc_optimization is False
            assert manager.config.gc_threshold_mb == 200.0
            assert manager.config.enable_cache_optimization is False
            assert manager.config.cache_config.max_size == 3000

    def test_import_config_loads_rules(self) -> None:
        """import_config loads optimization rules from configuration."""
        manager = OptimizationManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "rules_config.json"

            config_data = {
                "enable_monitoring": True,
                "optimization_rules": [
                    {
                        "name": "imported_rule",
                        "metric_name": "test.metric",
                        "threshold_type": "warning",
                        "threshold_value": 150.0,
                        "action": "log",
                        "enabled": True,
                        "cooldown_seconds": 45,
                    },
                ],
            }

            with open(config_path, "w") as f:
                json.dump(config_data, f)

            manager.import_config(config_path)

            assert len(manager.config.optimization_rules) > 0
            imported_rule = next((r for r in manager.config.optimization_rules if r.name == "imported_rule"), None)
            assert imported_rule is not None
            assert imported_rule.metric_name == "test.metric"
            assert imported_rule.threshold_value == 150.0


class TestRecommendations:
    """Test optimization recommendations."""

    def test_get_recommendations_returns_list(self) -> None:
        """get_recommendations returns list of recommendation strings."""
        manager = OptimizationManager()

        recommendations = manager.get_recommendations()

        assert isinstance(recommendations, list)
        assert all(isinstance(rec, str) for rec in recommendations)

    def test_recommendations_for_high_memory_freed(self) -> None:
        """get_recommendations suggests GC frequency increase when memory freed is high."""
        manager = OptimizationManager()
        manager.gc_stats["memory_freed_mb"] = 100.0

        recommendations = manager.get_recommendations()

        gc_recommendation = any("GC frequency" in rec for rec in recommendations)
        assert gc_recommendation is True


class TestGlobalFunctions:
    """Test global optimization functions."""

    def test_optimize_ai_performance_executes(self) -> None:
        """optimize_ai_performance executes memory and cache optimization."""
        optimize_ai_performance()

    def test_get_performance_recommendations_returns_list(self) -> None:
        """get_performance_recommendations returns recommendation list."""
        recommendations = get_performance_recommendations()

        assert isinstance(recommendations, list)

    def test_benchmark_ai_optimizations_returns_metrics(self) -> None:
        """benchmark_ai_optimizations returns benchmark metrics."""
        results = benchmark_ai_optimizations()

        assert isinstance(results, dict)
        assert "optimization_time_seconds" in results


class TestRuleCooldown:
    """Test optimization rule cooldown functionality."""

    def test_check_cooldown_allows_first_trigger(self) -> None:
        """Cooldown check allows rule to trigger when never triggered."""
        manager = OptimizationManager()
        rule = OptimizationRule(
            name="test_cooldown",
            metric_name="test",
            threshold_type="warning",
            threshold_value=50.0,
            action="log",
            cooldown_seconds=30,
        )

        result = manager._check_cooldown(rule)

        assert result is True

    def test_check_cooldown_blocks_recent_trigger(self) -> None:
        """Cooldown check blocks rule triggered within cooldown period."""
        manager = OptimizationManager()
        rule = OptimizationRule(
            name="test_cooldown",
            metric_name="test",
            threshold_type="warning",
            threshold_value=50.0,
            action="log",
            cooldown_seconds=3600,
        )
        rule.last_triggered = datetime.now()

        result = manager._check_cooldown(rule)

        assert result is False

    def test_check_cooldown_allows_after_cooldown(self) -> None:
        """Cooldown check allows rule after cooldown period expires."""
        manager = OptimizationManager()
        rule = OptimizationRule(
            name="test_cooldown",
            metric_name="test",
            threshold_type="warning",
            threshold_value=50.0,
            action="log",
            cooldown_seconds=1,
        )
        rule.last_triggered = datetime.now() - timedelta(seconds=2)

        result = manager._check_cooldown(rule)

        assert result is True


class TestRuleMatching:
    """Test optimization rule matching logic."""

    def test_rule_matches_exact_metric_name(self) -> None:
        """Rule matches when metric name exactly matches."""
        manager = OptimizationManager()
        rule = OptimizationRule(
            name="test",
            metric_name="memory.rss",
            threshold_type="warning",
            threshold_value=100.0,
            action="gc",
        )

        result = manager._rule_matches(rule, "memory.rss", "warning")

        assert result is True

    def test_rule_matches_partial_metric_name(self) -> None:
        """Rule matches when metric name contains rule pattern."""
        manager = OptimizationManager()
        rule = OptimizationRule(
            name="test",
            metric_name="memory",
            threshold_type="warning",
            threshold_value=100.0,
            action="gc",
        )

        result = manager._rule_matches(rule, "system.memory.rss", "warning")

        assert result is True

    def test_rule_no_match_wrong_threshold_type(self) -> None:
        """Rule does not match when threshold type differs."""
        manager = OptimizationManager()
        rule = OptimizationRule(
            name="test",
            metric_name="memory",
            threshold_type="warning",
            threshold_value=100.0,
            action="gc",
        )

        result = manager._rule_matches(rule, "memory.rss", "critical")

        assert result is False

    def test_rule_no_match_different_metric(self) -> None:
        """Rule does not match when metric name is completely different."""
        manager = OptimizationManager()
        rule = OptimizationRule(
            name="test",
            metric_name="memory",
            threshold_type="warning",
            threshold_value=100.0,
            action="gc",
        )

        result = manager._rule_matches(rule, "cpu.usage", "warning")

        assert result is False


class TestGlobalOptimizationManager:
    """Test global optimization manager instance."""

    def test_global_optimization_manager_exists(self) -> None:
        """Global optimization_manager instance exists and is usable."""
        assert optimization_manager is not None
        assert isinstance(optimization_manager, OptimizationManager)

    def test_global_manager_has_default_config(self) -> None:
        """Global optimization manager has default configuration."""
        assert optimization_manager.config is not None
        assert len(optimization_manager.config.optimization_rules) > 0


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_execute_optimization_with_invalid_action(self) -> None:
        """Optimization execution handles invalid action gracefully."""
        manager = OptimizationManager()
        rule = OptimizationRule(
            name="invalid_action",
            metric_name="test",
            threshold_type="warning",
            threshold_value=50.0,
            action="invalid_action_type",
        )

        manager._execute_optimization(rule, "test.metric", "warning", 75.0)

    def test_import_config_with_missing_file(self) -> None:
        """import_config handles missing file gracefully."""
        manager = OptimizationManager()

        manager.import_config(Path("/nonexistent/config.json"))

    def test_import_config_with_invalid_json(self) -> None:
        """import_config handles invalid JSON gracefully."""
        manager = OptimizationManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "invalid.json"
            config_path.write_text("invalid json content")

            manager.import_config(config_path)
