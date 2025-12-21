"""Production tests for AI learning engine.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import gc
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Generator

import pytest

from intellicrack.ai.learning_engine import (
    AILearningDatabase,
    AILearningEngine,
    FailureAnalysis,
    FailureAnalysisEngine,
    LearningRecord,
    PatternEvolutionEngine,
    PatternRule,
    get_learning_engine,
)


@pytest.fixture
def temp_db_path() -> Generator[Path, None, None]:
    """Create a temporary database path with proper Windows cleanup."""
    tmpdir = tempfile.mkdtemp()
    yield Path(tmpdir) / "test_learning.db"
    gc.collect()
    try:
        shutil.rmtree(tmpdir, ignore_errors=True)
    except OSError:
        pass


class TestLearningRecord:
    """Test LearningRecord dataclass for license cracking experience storage."""

    def test_learning_record_creation_with_success(self) -> None:
        """LearningRecord stores successful license cracking experience."""
        record = LearningRecord(
            record_id="rec_001",
            task_type="vmprotect_keygen",
            input_hash="abc123",
            output_hash="def456",
            success=True,
            confidence=0.95,
            execution_time=1.234,
            memory_usage=1024000,
            context={"protection": "VMProtect 3.5", "method": "serial_generation"},
        )

        assert record.record_id == "rec_001"
        assert record.task_type == "vmprotect_keygen"
        assert record.success is True
        assert record.confidence == 0.95
        assert record.execution_time == 1.234
        assert record.memory_usage == 1024000
        assert record.error_message is None
        assert record.context["protection"] == "VMProtect 3.5"
        assert isinstance(record.timestamp, datetime)

    def test_learning_record_creation_with_failure(self) -> None:
        """LearningRecord stores failed license cracking attempt with error."""
        record = LearningRecord(
            record_id="rec_002",
            task_type="themida_patch",
            input_hash="ghi789",
            output_hash="jkl012",
            success=False,
            confidence=0.45,
            execution_time=3.567,
            memory_usage=2048000,
            error_message="Anti-debug detection triggered",
            context={"protection": "Themida 3.1", "stage": "unpacking"},
        )

        assert record.success is False
        assert record.confidence == 0.45
        assert record.error_message == "Anti-debug detection triggered"
        assert record.context["stage"] == "unpacking"

    def test_learning_record_default_context(self) -> None:
        """LearningRecord initializes with empty context by default."""
        record = LearningRecord(
            record_id="rec_003",
            task_type="trial_reset",
            input_hash="mno345",
            output_hash="pqr678",
            success=True,
            confidence=0.88,
            execution_time=0.456,
            memory_usage=512000,
        )

        assert record.context == {}
        assert record.error_message is None

    def test_learning_record_with_metadata(self) -> None:
        """LearningRecord stores metadata and learned patterns."""
        record = LearningRecord(
            record_id="rec_004",
            task_type="license_bypass",
            input_hash="stu901",
            output_hash="vwx234",
            success=True,
            confidence=0.92,
            execution_time=2.1,
            memory_usage=768000,
            metadata={"version": "1.0", "platform": "windows"},
            learned_patterns=["jz_to_jmp", "nop_slide"],
            improvement_suggestions=["Optimize pattern matching"],
        )

        assert record.metadata["version"] == "1.0"
        assert "jz_to_jmp" in record.learned_patterns
        assert len(record.improvement_suggestions) == 1


class TestPatternRule:
    """Test PatternRule dataclass for license bypass pattern storage."""

    def test_pattern_rule_creation(self) -> None:
        """PatternRule stores license bypass pattern and effectiveness metrics."""
        rule = PatternRule(
            rule_id="rule_001",
            pattern_name="jz_after_license_check",
            condition="task_type == 'license_validation'",
            action="patch_to_jmp",
            confidence=0.87,
            success_rate=0.85,
            usage_count=15,
        )

        assert rule.rule_id == "rule_001"
        assert rule.pattern_name == "jz_after_license_check"
        assert rule.action == "patch_to_jmp"
        assert rule.confidence == 0.87
        assert rule.success_rate == 0.85
        assert rule.usage_count == 15

    def test_pattern_rule_default_usage_count(self) -> None:
        """PatternRule defaults to zero usage count."""
        rule = PatternRule(
            rule_id="rule_002",
            pattern_name="serial_validation_pattern",
            condition="context contains 'serial'",
            action="generate_keygen",
            confidence=0.75,
            success_rate=0.80,
        )

        assert rule.usage_count == 0
        assert rule.last_used is None
        assert rule.effectiveness_score == 0.0
        assert isinstance(rule.created_at, datetime)

    def test_pattern_rule_with_effectiveness_score(self) -> None:
        """PatternRule stores effectiveness score."""
        rule = PatternRule(
            rule_id="rule_003",
            pattern_name="trial_expiry_bypass",
            condition="protection_type == 'time_based'",
            action="patch_time_check",
            confidence=0.92,
            success_rate=0.88,
            effectiveness_score=0.81,
        )

        assert rule.effectiveness_score == 0.81


class TestFailureAnalysis:
    """Test FailureAnalysis dataclass for license cracking failure tracking."""

    def test_failure_analysis_creation(self) -> None:
        """FailureAnalysis stores failure information and remediation strategies."""
        failure = FailureAnalysis(
            failure_id="fail_001",
            failure_type="anti_debug_trigger",
            frequency=5,
            impact_level="high",
            root_cause="Timing-based anti-debug detection",
            pattern_signature="timing_detection_v1",
            suggested_fixes=["Use kernel-level bypass", "Patch IsDebuggerPresent"],
        )

        assert failure.failure_id == "fail_001"
        assert failure.failure_type == "anti_debug_trigger"
        assert failure.frequency == 5
        assert failure.impact_level == "high"
        assert failure.root_cause == "Timing-based anti-debug detection"
        assert len(failure.suggested_fixes) == 2

    def test_failure_analysis_default_values(self) -> None:
        """FailureAnalysis has correct default values."""
        failure = FailureAnalysis(
            failure_id="fail_002",
            failure_type="checksum_verification",
            frequency=3,
            impact_level="medium",
            root_cause="CRC32 integrity check",
            pattern_signature="crc_check_v1",
            suggested_fixes=["Recalculate CRC after patching"],
        )

        assert failure.affected_components == []
        assert failure.mitigation_strategies == []
        assert failure.resolution_status == "open"


class TestAILearningDatabase:
    """Test AILearningDatabase for persistent storage."""

    def test_database_initialization(self, temp_db_path: Path) -> None:
        """Database initializes with correct schema."""
        db = AILearningDatabase(temp_db_path)

        assert db.db_path == temp_db_path
        assert temp_db_path.exists()

    def test_save_and_retrieve_learning_record(self, temp_db_path: Path) -> None:
        """Database saves and retrieves learning records correctly."""
        db = AILearningDatabase(temp_db_path)

        record = LearningRecord(
            record_id="test_rec_001",
            task_type="keygen_analysis",
            input_hash="hash123",
            output_hash="hash456",
            success=True,
            confidence=0.9,
            execution_time=1.5,
            memory_usage=500000,
        )

        db.save_learning_record(record)
        retrieved = db.get_learning_records(limit=1)

        assert len(retrieved) == 1
        assert retrieved[0].record_id == "test_rec_001"
        assert retrieved[0].success is True

    def test_save_and_retrieve_pattern_rule(self, temp_db_path: Path) -> None:
        """Database saves and retrieves pattern rules correctly."""
        db = AILearningDatabase(temp_db_path)

        rule = PatternRule(
            rule_id="test_rule_001",
            pattern_name="test_pattern",
            condition="task_type == 'test'",
            action="apply_test",
            confidence=0.85,
            success_rate=0.80,
        )

        db.save_pattern_rule(rule)
        retrieved = db.get_pattern_rules()

        assert len(retrieved) == 1
        assert retrieved[0].rule_id == "test_rule_001"


class TestAILearningEngine:
    """Test AILearningEngine for pattern learning and evolution."""

    def test_engine_initialization(self, temp_db_path: Path) -> None:
        """AILearningEngine initializes with correct configuration."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        try:
            engine = AILearningEngine(temp_db_path)

            assert engine.learning_enabled is True
            assert engine.learning_stats["records_processed"] == 0
            assert engine.database is not None
        finally:
            os.environ.pop("INTELLICRACK_TESTING", None)

    def test_record_experience(self, temp_db_path: Path) -> None:
        """Engine records learning experiences correctly."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        try:
            engine = AILearningEngine(temp_db_path)

            record_id = engine.record_experience(
                task_type="license_crack",
                input_data={"binary": "test.exe"},
                output_data={"patched": True},
                success=True,
                confidence=0.95,
                execution_time=2.5,
                memory_usage=1024000,
            )

            assert record_id != ""
            assert engine.learning_stats["records_processed"] == 1
        finally:
            os.environ.pop("INTELLICRACK_TESTING", None)

    def test_record_experience_disabled(self, temp_db_path: Path) -> None:
        """Engine skips recording when learning disabled."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        try:
            engine = AILearningEngine(temp_db_path)
            engine.learning_enabled = False

            record_id = engine.record_experience(
                task_type="test",
                input_data={},
                output_data={},
                success=True,
                confidence=0.5,
                execution_time=1.0,
                memory_usage=1000,
            )

            assert record_id == ""
        finally:
            os.environ.pop("INTELLICRACK_TESTING", None)

    def test_get_learning_insights(self, temp_db_path: Path) -> None:
        """Engine provides learning insights."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        try:
            engine = AILearningEngine(temp_db_path)

            insights = engine.get_learning_insights()

            assert "total_records" in insights
            assert "success_rate" in insights
            assert "learning_stats" in insights
            assert "pattern_insights" in insights
        finally:
            os.environ.pop("INTELLICRACK_TESTING", None)


class TestPatternEvolutionEngine:
    """Test PatternEvolutionEngine for pattern discovery and evolution."""

    def test_evolution_engine_initialization(self, temp_db_path: Path) -> None:
        """Evolution engine initializes with correct configuration."""
        db = AILearningDatabase(temp_db_path)
        engine = PatternEvolutionEngine(db)

        assert engine.evolution_threshold == 0.8
        assert engine.pattern_cache == {}

    def test_get_applicable_patterns_empty(self, temp_db_path: Path) -> None:
        """Evolution engine returns empty list when no patterns exist."""
        db = AILearningDatabase(temp_db_path)
        engine = PatternEvolutionEngine(db)

        patterns = engine.get_applicable_patterns({"target_type": "windows"})

        assert patterns == []

    def test_add_pattern(self, temp_db_path: Path) -> None:
        """Evolution engine adds new patterns correctly."""
        db = AILearningDatabase(temp_db_path)
        engine = PatternEvolutionEngine(db)

        pattern_data = {
            "feature_vector": [0.1, 0.2, 0.3],
            "important_features": [0, 2],
            "technique": "buffer_overflow",
            "target_type": "windows_exe",
            "confidence": 0.85,
        }

        rule = engine.add_pattern(
            pattern_type="success_pattern",
            pattern_data=pattern_data,
            source="test",
        )

        assert rule.confidence == 0.85
        assert "success_pattern" in rule.rule_id

    def test_get_insights(self, temp_db_path: Path) -> None:
        """Evolution engine provides pattern insights."""
        db = AILearningDatabase(temp_db_path)
        engine = PatternEvolutionEngine(db)

        insights = engine.get_insights()

        assert "total_patterns" in insights
        assert "evolution_status" in insights


class TestFailureAnalysisEngine:
    """Test FailureAnalysisEngine for failure pattern analysis."""

    def test_failure_engine_initialization(self, temp_db_path: Path) -> None:
        """Failure engine initializes with correct configuration."""
        db = AILearningDatabase(temp_db_path)
        engine = FailureAnalysisEngine(db)

        assert engine.analysis_threshold == 3
        assert engine.failure_patterns == {}

    def test_analyze_failures_insufficient_data(self, temp_db_path: Path) -> None:
        """Failure engine handles insufficient data gracefully."""
        db = AILearningDatabase(temp_db_path)
        engine = FailureAnalysisEngine(db)

        result = engine.analyze_failures()

        assert "message" in result
        assert "Insufficient" in result["message"]


class TestGlobalLearningEngine:
    """Test global learning engine singleton."""

    def test_get_learning_engine_returns_singleton(self) -> None:
        """get_learning_engine returns same instance on multiple calls."""
        engine1 = get_learning_engine()
        engine2 = get_learning_engine()

        assert engine1 is engine2

    def test_get_learning_engine_is_initialized(self) -> None:
        """get_learning_engine returns properly initialized engine."""
        engine = get_learning_engine()

        assert hasattr(engine, "learning_enabled")
        assert hasattr(engine, "database")
        assert hasattr(engine, "pattern_engine")
        assert hasattr(engine, "failure_engine")


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_learning_record_with_zero_execution_time(self) -> None:
        """LearningRecord handles zero execution time."""
        record = LearningRecord(
            record_id="edge_001",
            task_type="instant_patch",
            input_hash="abc",
            output_hash="def",
            success=True,
            confidence=1.0,
            execution_time=0.0,
            memory_usage=0,
        )

        assert record.execution_time == 0.0

    def test_pattern_rule_with_zero_success_rate(self) -> None:
        """PatternRule handles zero success rate."""
        rule = PatternRule(
            rule_id="edge_002",
            pattern_name="failing_pattern",
            condition="never_matches",
            action="no_action",
            confidence=0.0,
            success_rate=0.0,
        )

        assert rule.success_rate == 0.0

    def test_failure_analysis_with_empty_suggested_fixes(self) -> None:
        """FailureAnalysis handles empty suggested fixes list."""
        failure = FailureAnalysis(
            failure_id="edge_003",
            failure_type="unknown_failure",
            frequency=1,
            impact_level="low",
            root_cause="Unknown",
            pattern_signature="unknown_v1",
            suggested_fixes=[],
        )

        assert failure.suggested_fixes == []
