"""AI Learning & Evolution Engine.

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

import hashlib
import json
import logging
import os
import re
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from intellicrack.handlers.numpy_handler import numpy as np
from intellicrack.handlers.sqlite3_handler import sqlite3

from .performance_monitor_simple import profile_ai_operation


logger = logging.getLogger(__name__)


@dataclass
class LearningRecord:
    """Record of AI learning experience."""

    record_id: str
    task_type: str
    input_hash: str
    output_hash: str
    success: bool
    confidence: float
    execution_time: float
    memory_usage: int
    error_message: str | None = None
    context: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    learned_patterns: list[str] = field(default_factory=list)
    improvement_suggestions: list[str] = field(default_factory=list)


@dataclass
class PatternRule:
    """Learned pattern rule for AI improvement."""

    rule_id: str
    pattern_name: str
    condition: str
    action: str
    confidence: float
    success_rate: float
    usage_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    last_used: datetime | None = None
    effectiveness_score: float = 0.0


@dataclass
class FailureAnalysis:
    """Analysis of AI failure patterns."""

    failure_id: str
    failure_type: str
    frequency: int
    impact_level: str  # low, medium, high, critical
    root_cause: str
    suggested_fixes: list[str]
    pattern_signature: str
    affected_components: list[str] = field(default_factory=list)
    mitigation_strategies: list[str] = field(default_factory=list)
    resolution_status: str = "open"  # open, in_progress, resolved


class AILearningDatabase:
    """Persistent database for AI learning records."""

    def __init__(self, db_path: Path | None = None) -> None:
        """Initialize the AI learning database.

        Args:
            db_path: Optional path to the database file. If not provided,
                     defaults to ~/.intellicrack/ai_learning.db

        """
        self.db_path = db_path or Path.home() / ".intellicrack" / "ai_learning.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self._init_database()

    def _init_database(self) -> None:
        """Initialize database schema.

        Creates tables for learning records, pattern rules, and failure analyses.
        Also creates indexes for improved query performance.

        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS learning_records (
                    record_id TEXT PRIMARY KEY,
                    task_type TEXT NOT NULL,
                    input_hash TEXT NOT NULL,
                    output_hash TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    confidence REAL NOT NULL,
                    execution_time REAL NOT NULL,
                    memory_usage INTEGER NOT NULL,
                    error_message TEXT,
                    context TEXT,
                    metadata TEXT,
                    timestamp TEXT NOT NULL,
                    learned_patterns TEXT,
                    improvement_suggestions TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS pattern_rules (
                    rule_id TEXT PRIMARY KEY,
                    pattern_name TEXT NOT NULL,
                    condition TEXT NOT NULL,
                    action TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    success_rate REAL NOT NULL,
                    usage_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    last_used TEXT,
                    effectiveness_score REAL DEFAULT 0.0
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS failure_analyses (
                    failure_id TEXT PRIMARY KEY,
                    failure_type TEXT NOT NULL,
                    frequency INTEGER NOT NULL,
                    impact_level TEXT NOT NULL,
                    root_cause TEXT NOT NULL,
                    suggested_fixes TEXT NOT NULL,
                    pattern_signature TEXT NOT NULL,
                    affected_components TEXT,
                    mitigation_strategies TEXT,
                    resolution_status TEXT DEFAULT 'open'
                )
            """)

            # Create indexes for better performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_task_type ON learning_records(task_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_success ON learning_records(success)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON learning_records(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pattern_name ON pattern_rules(pattern_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_failure_type ON failure_analyses(failure_type)")

            conn.commit()

    def save_learning_record(self, record: LearningRecord) -> None:
        """Save learning record to database.

        Args:
            record: LearningRecord instance containing task execution data

        """
        with self.lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                    INSERT OR REPLACE INTO learning_records VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.record_id,
                    record.task_type,
                    record.input_hash,
                    record.output_hash,
                    record.success,
                    record.confidence,
                    record.execution_time,
                    record.memory_usage,
                    record.error_message,
                    json.dumps(record.context),
                    json.dumps(record.metadata),
                    record.timestamp.isoformat(),
                    json.dumps(record.learned_patterns),
                    json.dumps(record.improvement_suggestions),
                ),
            )
            conn.commit()

    def save_pattern_rule(self, rule: PatternRule) -> None:
        """Save pattern rule to database.

        Args:
            rule: PatternRule instance to persist

        """
        with self.lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                    INSERT OR REPLACE INTO pattern_rules VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule.rule_id,
                    rule.pattern_name,
                    rule.condition,
                    rule.action,
                    rule.confidence,
                    rule.success_rate,
                    rule.usage_count,
                    rule.created_at.isoformat(),
                    rule.last_used.isoformat() if rule.last_used else None,
                    rule.effectiveness_score,
                ),
            )
            conn.commit()

    def save_failure_analysis(self, analysis: FailureAnalysis) -> None:
        """Save failure analysis to database.

        Args:
            analysis: FailureAnalysis instance to persist

        """
        with self.lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                    INSERT OR REPLACE INTO failure_analyses VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis.failure_id,
                    analysis.failure_type,
                    analysis.frequency,
                    analysis.impact_level,
                    analysis.root_cause,
                    json.dumps(analysis.suggested_fixes),
                    analysis.pattern_signature,
                    json.dumps(analysis.affected_components),
                    json.dumps(analysis.mitigation_strategies),
                    analysis.resolution_status,
                ),
            )
            conn.commit()

    def get_learning_records(self, task_type: str | None = None, success: bool | None = None, limit: int = 1000) -> list[LearningRecord]:
        """Get learning records from database.

        Args:
            task_type: Optional filter by task type
            success: Optional filter by success status
            limit: Maximum number of records to retrieve

        Returns:
            List of LearningRecord instances matching the criteria

        """
        with sqlite3.connect(self.db_path) as conn:
            query = "SELECT * FROM learning_records WHERE 1=1"
            params: list[str | bool | int] = []

            if task_type:
                query += " AND task_type = ?"
                params.append(task_type)

            if success is not None:
                query += " AND success = ?"
                params.append(success)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor = conn.execute(query, params)
            records = []

            for row in cursor.fetchall():
                record = LearningRecord(
                    record_id=row[0],
                    task_type=row[1],
                    input_hash=row[2],
                    output_hash=row[3],
                    success=bool(row[4]),
                    confidence=row[5],
                    execution_time=row[6],
                    memory_usage=row[7],
                    error_message=row[8],
                    context=json.loads(row[9]) if row[9] else {},
                    metadata=json.loads(row[10]) if row[10] else {},
                    timestamp=datetime.fromisoformat(row[11]),
                    learned_patterns=json.loads(row[12]) if row[12] else [],
                    improvement_suggestions=json.loads(row[13]) if row[13] else [],
                )
                records.append(record)

            return records

    def get_recent_records(self, limit: int = 1000) -> list[dict[str, Any]]:
        """Get recent learning records as dictionaries for ML processing.

        Args:
            limit: Maximum number of records to retrieve

        Returns:
            List of dictionaries containing record data with exploit information

        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT record_id, task_type, input_hash, output_hash, success,
                       confidence, execution_time, memory_usage, error_message,
                       context, metadata, timestamp, learned_patterns, improvement_suggestions
                FROM learning_records
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )

            records = []
            for row in cursor.fetchall():
                context = json.loads(row[9]) if row[9] else {}
                metadata = json.loads(row[10]) if row[10] else {}

                exploit_data = {
                    "technique": context.get("technique", metadata.get("technique")),
                    "target_type": context.get("target_type", metadata.get("target_type")),
                    "complexity": context.get("complexity", metadata.get("complexity", "medium")),
                    "payload_size": context.get("payload_size", metadata.get("payload_size", 0)),
                    "target_entropy": context.get("target_entropy", metadata.get("target_entropy", 0.0)),
                    "protection_level": context.get("protection_level", metadata.get("protection_level", 0)),
                    "binary_size": context.get("binary_size", metadata.get("binary_size", 0)),
                    "import_count": context.get("import_count", metadata.get("import_count", 0)),
                    "section_count": context.get("section_count", metadata.get("section_count", 0)),
                }

                record = {
                    "record_id": row[0],
                    "task_type": row[1],
                    "input_hash": row[2],
                    "output_hash": row[3],
                    "success": bool(row[4]),
                    "confidence": row[5],
                    "execution_time": row[6],
                    "memory_usage": row[7],
                    "error_message": row[8],
                    "context": context,
                    "metadata": metadata,
                    "timestamp": row[11],
                    "learned_patterns": json.loads(row[12]) if row[12] else [],
                    "improvement_suggestions": json.loads(row[13]) if row[13] else [],
                    "exploit_data": exploit_data,
                }
                records.append(record)

            return records

    def get_pattern_rules(self, pattern_name: str | None = None) -> list[PatternRule]:
        """Get pattern rules from database.

        Args:
            pattern_name: Optional filter by pattern name

        Returns:
            List of PatternRule instances, sorted by effectiveness score

        """
        with sqlite3.connect(self.db_path) as conn:
            if pattern_name:
                cursor = conn.execute(
                    "SELECT * FROM pattern_rules WHERE pattern_name = ? ORDER BY effectiveness_score DESC",
                    (pattern_name,),
                )
            else:
                cursor = conn.execute("SELECT * FROM pattern_rules ORDER BY effectiveness_score DESC")

            rules = []
            for row in cursor.fetchall():
                rule = PatternRule(
                    rule_id=row[0],
                    pattern_name=row[1],
                    condition=row[2],
                    action=row[3],
                    confidence=row[4],
                    success_rate=row[5],
                    usage_count=row[6],
                    created_at=datetime.fromisoformat(row[7]),
                    last_used=datetime.fromisoformat(row[8]) if row[8] else None,
                    effectiveness_score=row[9],
                )
                rules.append(rule)

            return rules

    def get_failure_analyses(self, failure_type: str | None = None, resolution_status: str = "open") -> list[FailureAnalysis]:
        """Get failure analyses from database.

        Args:
            failure_type: Optional filter by failure type
            resolution_status: Filter by resolution status (default: "open")

        Returns:
            List of FailureAnalysis instances sorted by frequency

        """
        with sqlite3.connect(self.db_path) as conn:
            query = "SELECT * FROM failure_analyses WHERE resolution_status = ?"
            params = [resolution_status]

            if failure_type:
                query += " AND failure_type = ?"
                params.append(failure_type)

            query += " ORDER BY frequency DESC"

            cursor = conn.execute(query, params)
            analyses = []

            for row in cursor.fetchall():
                analysis = FailureAnalysis(
                    failure_id=row[0],
                    failure_type=row[1],
                    frequency=row[2],
                    impact_level=row[3],
                    root_cause=row[4],
                    suggested_fixes=json.loads(row[5]),
                    pattern_signature=row[6],
                    affected_components=json.loads(row[7]) if row[7] else [],
                    mitigation_strategies=json.loads(row[8]) if row[8] else [],
                    resolution_status=row[9],
                )
                analyses.append(analysis)

            return analyses


class PatternEvolutionEngine:
    """Engine for evolving AI patterns based on learning."""

    def __init__(self, database: AILearningDatabase) -> None:
        """Initialize the pattern evolution engine.

        Args:
            database: AI learning database instance for storing and retrieving patterns

        """
        self.database = database
        self.pattern_cache: dict[str, list[PatternRule]] = {}
        self.evolution_threshold = 0.8  # Minimum effectiveness for pattern promotion
        self.cache_ttl = 3600  # 1 hour cache TTL
        self.last_cache_update = datetime.now()

    @profile_ai_operation("pattern_evolution")
    def evolve_patterns(self) -> dict[str, Any]:
        """Evolve patterns based on learning data.

        Analyzes recent learning records to discover, improve, and deprecate patterns
        that guide AI decision-making and strategy selection.

        Returns:
            Dictionary with pattern evolution results including counts of new patterns,
            improved patterns, deprecated patterns, and generated insights

        """
        logger.debug("Entering PatternEvolutionEngine.evolve_patterns")
        logger.info("Starting pattern evolution process")

        recent_records = self.database.get_learning_records(limit=5000)
        logger.info("Retrieved %d learning records for analysis", len(recent_records))

        evolution_results: dict[str, Any] = {
            "patterns_analyzed": 0,
            "new_patterns_discovered": 0,
            "patterns_improved": 0,
            "patterns_deprecated": 0,
            "evolution_insights": [],
        }

        # Analyze success patterns
        success_patterns = self._analyze_success_patterns(recent_records)
        patterns_analyzed = evolution_results["patterns_analyzed"]
        if isinstance(patterns_analyzed, int):
            evolution_results["patterns_analyzed"] = patterns_analyzed + len(success_patterns)

        # Create new pattern rules
        new_rules = self._create_pattern_rules(success_patterns)
        new_patterns_discovered = evolution_results["new_patterns_discovered"]
        if isinstance(new_patterns_discovered, int):
            evolution_results["new_patterns_discovered"] = new_patterns_discovered + len(new_rules)

        # Improve existing patterns
        improved_rules = self._improve_existing_patterns(recent_records)
        patterns_improved = evolution_results["patterns_improved"]
        if isinstance(patterns_improved, int):
            evolution_results["patterns_improved"] = patterns_improved + len(improved_rules)

        # Deprecate ineffective patterns
        deprecated_rules = self._deprecate_ineffective_patterns()
        patterns_deprecated = evolution_results["patterns_deprecated"]
        if isinstance(patterns_deprecated, int):
            evolution_results["patterns_deprecated"] = patterns_deprecated + len(deprecated_rules)

        # Generate insights
        insights = self._generate_evolution_insights(recent_records)
        evolution_results["evolution_insights"] = insights

        self._update_pattern_cache()

        logger.info("Pattern evolution completed: %s", evolution_results)
        logger.debug("Exiting PatternEvolutionEngine.evolve_patterns")
        return evolution_results

    def _analyze_success_patterns(self, records: list[LearningRecord]) -> dict[str, Any]:
        """Analyze patterns in successful operations.

        Args:
            records: List of LearningRecord instances to analyze

        Returns:
            Dictionary of pattern categories with associated records

        """
        success_records = [r for r in records if r.success and r.confidence > 0.7]

        patterns: dict[str, Any] = {
            "task_type_success": defaultdict(list),
            "execution_time_patterns": defaultdict(list),
            "confidence_patterns": defaultdict(list),
            "context_patterns": defaultdict(list),
        }

        for record in success_records:
            # Task type patterns
            patterns["task_type_success"][record.task_type].append(record)

            # Execution time patterns
            time_bucket = self._bucket_execution_time(record.execution_time)
            patterns["execution_time_patterns"][time_bucket].append(record)

            # Confidence patterns
            conf_bucket = self._bucket_confidence(record.confidence)
            patterns["confidence_patterns"][conf_bucket].append(record)

            # Context patterns
            for key, value in record.context.items():
                pattern_key = f"{key}:{self._generalize_value(value)}"
                patterns["context_patterns"][pattern_key].append(record)

        return patterns

    def _bucket_execution_time(self, time: float) -> str:
        """Bucket execution time into categories.

        Args:
            time: Execution time in seconds

        Returns:
            str: The bucket category - "fast", "medium", "slow", or "very_slow"

        """
        if time < 1.0:
            return "fast"
        if time < 5.0:
            return "medium"
        return "slow" if time < 15.0 else "very_slow"

    def _bucket_confidence(self, confidence: float) -> str:
        """Bucket confidence into categories.

        Args:
            confidence: Confidence score between 0.0 and 1.0

        Returns:
            str: The bucket category - "very_high", "high", "medium", or "low"

        """
        if confidence >= 0.9:
            return "very_high"
        if confidence >= 0.8:
            return "high"
        return "medium" if confidence >= 0.7 else "low"

    def _generalize_value(self, value: object) -> str:
        """Generalize values for pattern matching.

        Args:
            value: Value to generalize for pattern abstraction

        Returns:
            Generalized string representation categorizing the value type

        """
        if isinstance(value, str):
            if len(value) > 50:
                return "long_string"
            if re.match(r"^[a-zA-Z0-9_]+$", value):
                return "identifier"
            return "url" if re.match(r"^https?://", value) else "string"
        if isinstance(value, (int, float)):
            if value < 0:
                return "negative_number"
            if value == 0:
                return "zero"
            return "small_number" if value < 100 else "large_number"
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, (list, tuple)):
            return f"list_size_{len(value)}"
        if isinstance(value, dict):
            return f"dict_size_{len(value)}"
        return "unknown"

    def _create_pattern_rules(self, patterns: dict[str, Any]) -> list[PatternRule]:
        """Create new pattern rules from discovered patterns.

        Args:
            patterns: Dictionary of analyzed patterns with records

        Returns:
            List of newly created PatternRule instances

        """
        new_rules = []

        # Task type success patterns
        for task_type, records in patterns["task_type_success"].items():
            if len(records) >= 5:  # Minimum threshold for pattern
                success_rate = len([r for r in records if r.success]) / len(records)
                avg_confidence = sum(r.confidence for r in records) / len(records)

                if success_rate > 0.8 and avg_confidence > 0.8:
                    rule = PatternRule(
                        rule_id=f"task_success_{task_type}_{int(datetime.now().timestamp())}",
                        pattern_name=f"high_success_task_{task_type}",
                        condition=f"task_type == '{task_type}'",
                        action="apply_high_confidence_strategy",
                        confidence=avg_confidence,
                        success_rate=success_rate,
                        effectiveness_score=success_rate * avg_confidence,
                    )
                    new_rules.append(rule)
                    self.database.save_pattern_rule(rule)

        # Context patterns
        for pattern_key, records in patterns["context_patterns"].items():
            if len(records) >= 3:
                success_rate = len([r for r in records if r.success]) / len(records)
                avg_confidence = sum(r.confidence for r in records) / len(records)

                if success_rate > 0.85:
                    rule = PatternRule(
                        rule_id=f"context_{pattern_key}_{int(datetime.now().timestamp())}",
                        pattern_name=f"context_pattern_{pattern_key}",
                        condition=f"context.{pattern_key.split(':')[0]} matches '{pattern_key.split(':')[1]}'",
                        action="apply_context_optimization",
                        confidence=avg_confidence,
                        success_rate=success_rate,
                        effectiveness_score=success_rate * avg_confidence,
                    )
                    new_rules.append(rule)
                    self.database.save_pattern_rule(rule)

        return new_rules

    def _improve_existing_patterns(self, records: list[LearningRecord]) -> list[PatternRule]:
        """Improve existing pattern rules based on new data.

        Args:
            records: List of recent LearningRecord instances

        Returns:
            List of PatternRule instances that were improved

        """
        existing_rules = self.database.get_pattern_rules()
        improved_rules = []

        for rule in existing_rules:
            # Find records that match this pattern
            matching_records = self._find_matching_records(rule, records)

            if len(matching_records) >= 5:
                # Calculate new metrics
                success_rate = len([r for r in matching_records if r.success]) / len(matching_records)
                avg_confidence = sum(r.confidence for r in matching_records) / len(matching_records)
                new_effectiveness = success_rate * avg_confidence

                # Update rule if improved
                if new_effectiveness > rule.effectiveness_score:
                    rule.success_rate = success_rate
                    rule.confidence = avg_confidence
                    rule.effectiveness_score = new_effectiveness
                    rule.usage_count += len(matching_records)

                    self.database.save_pattern_rule(rule)
                    improved_rules.append(rule)

        return improved_rules

    def _find_matching_records(self, rule: PatternRule, records: list[LearningRecord]) -> list[LearningRecord]:
        """Find records that match a pattern rule.

        Args:
            rule: PatternRule to match against
            records: List of LearningRecord instances to filter

        Returns:
            List of records matching the rule condition

        """
        return [record for record in records if self._evaluate_rule_condition(rule.condition, record)]

    def _evaluate_rule_condition(self, condition: str, record: LearningRecord) -> bool:
        """Evaluate if a record matches a rule condition.

        Args:
            condition: Condition string to evaluate
            record: LearningRecord to test against the condition

        Returns:
            True if the record matches the condition, False otherwise

        """
        try:
            # Simple pattern matching for demo
            if "task_type ==" in condition:
                task_type = condition.split("'")[1]
                return record.task_type == task_type

            if "confidence >" in condition:
                threshold = float(condition.split(">")[1].strip())
                return record.confidence > threshold

            if "context." in condition:
                # Extract context key and value
                parts = condition.split("matches")
                if len(parts) == 2:
                    key = parts[0].replace("context.", "").strip()
                    value = parts[1].strip().strip("'")
                    return key in record.context and str(record.context[key]) == value

            return False
        except Exception as e:
            logger.exception("Exception in learning_engine: %s", e, exc_info=True)
            return False

    def _deprecate_ineffective_patterns(self) -> list[PatternRule]:
        """Deprecate patterns with low effectiveness.

        Returns:
            List of PatternRule instances that were deprecated

        """
        all_rules = self.database.get_pattern_rules()
        deprecated_rules = []

        for rule in all_rules:
            # Deprecate rules with low effectiveness or usage
            if rule.effectiveness_score < 0.5 or (rule.usage_count > 10 and rule.success_rate < 0.6):
                # Mark as deprecated (could delete or move to archive)
                rule.effectiveness_score = 0.0
                self.database.save_pattern_rule(rule)
                deprecated_rules.append(rule)

        return deprecated_rules

    def _generate_evolution_insights(self, records: list[LearningRecord]) -> list[str]:
        """Generate insights from pattern evolution.

        Args:
            records: List of LearningRecord instances to analyze

        Returns:
            List of insight strings describing pattern evolution findings

        """
        # Success rate analysis
        total_records = len(records)
        successful_records = len([r for r in records if r.success])
        overall_success_rate = successful_records / total_records if total_records > 0 else 0

        insights = [f"Overall success rate: {overall_success_rate:.2%}"]
        # Task type analysis
        task_types = Counter(r.task_type for r in records)
        most_common_task = task_types.most_common(1)[0] if task_types else ("unknown", 0)
        insights.append(f"Most common task type: {most_common_task[0]} ({most_common_task[1]} occurrences)")

        # Performance analysis
        avg_execution_time = sum(r.execution_time for r in records) / len(records) if records else 0
        insights.append(f"Average execution time: {avg_execution_time:.3f}s")

        if failed_records := [r for r in records if not r.success]:
            error_types = Counter(r.error_message.split(":")[0] if r.error_message else "Unknown" for r in failed_records)
            most_common_error = error_types.most_common(1)[0]
            insights.append(f"Most common error: {most_common_error[0]} ({most_common_error[1]} occurrences)")

        return insights

    def _update_pattern_cache(self) -> None:
        """Update pattern cache with latest rules.

        Refreshes the in-memory cache of pattern rules for faster access.

        """
        self.pattern_cache.clear()
        all_rules = self.database.get_pattern_rules()

        for rule in all_rules:
            if rule.pattern_name not in self.pattern_cache:
                self.pattern_cache[rule.pattern_name] = []
            self.pattern_cache[rule.pattern_name].append(rule)

        self.last_cache_update = datetime.now()

    def add_pattern(
        self,
        pattern_type: str,
        pattern_data: dict[str, Any],
        source: str,
    ) -> PatternRule:
        """Add a new pattern discovered through ML or manual analysis.

        Args:
            pattern_type: Type of pattern (e.g., 'anomaly_based', 'success_pattern')
            pattern_data: Dictionary containing pattern characteristics and features
            source: Source of the pattern discovery (e.g., 'ml_discovery', 'manual')

        Returns:
            The created PatternRule object

        """
        feature_vector = pattern_data.get("feature_vector", [])
        important_features = pattern_data.get("important_features", [])
        technique = pattern_data.get("technique", "unknown")
        target_type = pattern_data.get("target_type", "unknown")
        confidence = pattern_data.get("confidence", 0.5)

        feature_sig = hashlib.sha256(str(feature_vector).encode()).hexdigest()[:8]
        pattern_name = f"{pattern_type}_{technique}_{target_type}_{feature_sig}"

        condition_parts = []
        if technique and technique != "unknown":
            condition_parts.append(f"technique == '{technique}'")
        if target_type and target_type != "unknown":
            condition_parts.append(f"target_type == '{target_type}'")
        if important_features:
            top_features = important_features[:3]
            condition_parts.append(f"important_features contains {top_features}")

        condition = " AND ".join(condition_parts) if condition_parts else f"{pattern_type}_detected"

        action_map = {
            "anomaly_based": "apply_anomaly_strategy",
            "success_pattern": "apply_success_strategy",
            "failure_avoidance": "avoid_failure_conditions",
            "optimization": "optimize_execution",
        }
        action = action_map.get(pattern_type, "apply_learned_strategy")

        timestamp = int(datetime.now().timestamp())
        rule = PatternRule(
            rule_id=f"{pattern_type}_{source}_{timestamp}_{feature_sig}",
            pattern_name=pattern_name,
            condition=condition,
            action=action,
            confidence=confidence,
            success_rate=confidence,
            usage_count=0,
            created_at=datetime.now(),
            effectiveness_score=confidence * 0.9,
        )

        self.database.save_pattern_rule(rule)

        if pattern_name not in self.pattern_cache:
            self.pattern_cache[pattern_name] = []
        self.pattern_cache[pattern_name].append(rule)

        logger.info(
            "Added new pattern: %s (type=%s, source=%s, confidence=%.2f)",
            pattern_name,
            pattern_type,
            source,
            confidence,
        )

        return rule

    def get_applicable_patterns(self, context: dict[str, Any]) -> list[PatternRule]:
        """Get patterns applicable to current context.

        Args:
            context: Context dictionary with target_type, platform, and complexity

        Returns:
            List of up to 10 most effective PatternRule instances applicable to context

        """
        # Update cache if needed
        if datetime.now() - self.last_cache_update > timedelta(seconds=self.cache_ttl):
            self._update_pattern_cache()

        applicable_patterns: list[PatternRule] = []

        # Use context to filter applicable patterns
        target_type = context.get("target_type", "unknown")
        platform = context.get("platform", "unknown")
        complexity = context.get("complexity", "medium")

        logger.debug("Finding patterns for context: target=%s, platform=%s, complexity=%s", target_type, platform, complexity)

        for pattern_list in self.pattern_cache.values():
            applicable_patterns.extend(pattern for pattern in pattern_list if pattern.effectiveness_score > self.evolution_threshold)
        # Sort by effectiveness
        applicable_patterns.sort(key=lambda p: p.effectiveness_score, reverse=True)

        return applicable_patterns[:10]  # Return top 10

    def get_insights(self) -> dict[str, Any]:
        """Get insights about pattern evolution and effectiveness.

        Returns:
            Dictionary containing pattern statistics, recommendations, and evolution status

        """
        try:
            # Get recent learning records for analysis
            recent_records = self.database.get_learning_records(limit=1000)

            if not recent_records:
                return {
                    "total_patterns": 0,
                    "avg_effectiveness": 0.0,
                    "pattern_categories": {},
                    "recommendations": ["No learning data available"],
                    "evolution_status": "inactive",
                }

            # Analyze patterns in cache
            total_patterns = sum(len(patterns) for patterns in self.pattern_cache.values())
            effective_patterns: list[PatternRule] = []

            for pattern_list in self.pattern_cache.values():
                effective_patterns.extend(pattern for pattern in pattern_list if pattern.effectiveness_score > self.evolution_threshold)
            # Calculate statistics
            avg_effectiveness = (
                sum(p.effectiveness_score for p in effective_patterns) / len(effective_patterns) if effective_patterns else 0.0
            )

            pattern_categories = {
                category: {
                    "total": len(patterns),
                    "effective": len([p for p in patterns if p.effectiveness_score > self.evolution_threshold]),
                    "avg_score": (sum(p.effectiveness_score for p in patterns) / len(patterns) if patterns else 0.0),
                }
                for category, patterns in self.pattern_cache.items()
            }
            # Generate recommendations
            recommendations = []
            if avg_effectiveness < 0.7:
                recommendations.append("Consider collecting more training data to improve pattern effectiveness")
            if total_patterns < 10:
                recommendations.append("Pattern library is small - more diverse scenarios needed")
            if not effective_patterns:
                recommendations.append("No highly effective patterns found - review learning criteria")

            return {
                "total_patterns": total_patterns,
                "effective_patterns": len(effective_patterns),
                "avg_effectiveness": avg_effectiveness,
                "pattern_categories": pattern_categories,
                "recommendations": recommendations,
                "evolution_status": "active" if effective_patterns else "learning",
                "cache_age": (datetime.now() - self.last_cache_update).total_seconds(),
                "threshold": self.evolution_threshold,
            }

        except Exception as e:
            logger.exception("Error getting pattern insights: %s", e, exc_info=True)
            return {
                "total_patterns": 0,
                "error": str(e),
                "evolution_status": "error",
            }


class FailureAnalysisEngine:
    """Engine for analyzing and learning from failures."""

    def __init__(self, database: AILearningDatabase) -> None:
        """Initialize the failure analysis engine.

        Args:
            database: AI learning database instance for storing failure analyses

        """
        self.database = database
        self.failure_patterns: dict[str, list[str]] = defaultdict(list)
        self.analysis_threshold = 3  # Minimum failures to analyze

    @profile_ai_operation("failure_analysis")
    def analyze_failures(self) -> dict[str, Any]:
        """Analyze failure patterns and create improvement strategies.

        Categorizes failures, identifies root causes, and generates mitigation strategies.

        Returns:
            Dictionary with failure analysis results including total failures by type,
            critical patterns, and improvement strategies

        """
        logger.debug("Entering FailureAnalysisEngine.analyze_failures")
        logger.info("Starting failure analysis")

        failed_records = self.database.get_learning_records(success=False, limit=2000)
        logger.info("Retrieved %d failed records for analysis", len(failed_records))

        if len(failed_records) < self.analysis_threshold:
            logger.debug("Exiting FailureAnalysisEngine.analyze_failures - insufficient data")
            return {"message": "Insufficient failure data for analysis"}

        analysis_results: dict[str, Any] = {
            "total_failures": len(failed_records),
            "failure_types": {},
            "critical_patterns": [],
            "improvement_strategies": [],
            "new_analyses": 0,
        }

        # Categorize failures
        failure_categories = self._categorize_failures(failed_records)
        analysis_results["failure_types"] = {k: len(v) for k, v in failure_categories.items()}

        # Analyze each category
        for failure_type, records in failure_categories.items():
            if len(records) >= self.analysis_threshold:
                if analysis := self._create_failure_analysis(failure_type, records):
                    self.database.save_failure_analysis(analysis)
                    new_analyses = analysis_results["new_analyses"]
                    if isinstance(new_analyses, int):
                        analysis_results["new_analyses"] = new_analyses + 1

                    if analysis.impact_level in ["high", "critical"]:
                        critical_patterns = analysis_results["critical_patterns"]
                        if isinstance(critical_patterns, list):
                            critical_patterns.append(analysis.pattern_signature)

        strategies = self._generate_improvement_strategies(failed_records)
        analysis_results["improvement_strategies"] = strategies

        logger.info("Failure analysis completed: %s", analysis_results)
        logger.debug("Exiting FailureAnalysisEngine.analyze_failures")
        return analysis_results

    def _categorize_failures(self, failed_records: list[LearningRecord]) -> dict[str, list[LearningRecord]]:
        """Categorize failures by type.

        Args:
            failed_records: List of failed LearningRecord instances

        Returns:
            Dictionary mapping failure types to lists of records

        """
        categories = defaultdict(list)

        for record in failed_records:
            if record.error_message:
                # Categorize by error type
                error_type = self._extract_error_type(record.error_message)
                categories[error_type].append(record)
            else:
                # Categorize by task type if no error message
                categories[f"{record.task_type}_failure"].append(record)

        return categories

    def _extract_error_type(self, error_message: str) -> str:
        """Extract error type from error message.

        Args:
            error_message: Error message string to parse

        Returns:
            String categorizing the error type (e.g., "timeout_error", "memory_error")

        """
        if "timeout" in error_message.lower():
            return "timeout_error"
        if "memory" in error_message.lower():
            return "memory_error"
        if "connection" in error_message.lower():
            return "connection_error"
        if "permission" in error_message.lower():
            return "permission_error"
        if "not found" in error_message.lower():
            return "not_found_error"
        if "invalid" in error_message.lower():
            return "validation_error"
        # Use first word of error as type
        first_word = error_message.split(maxsplit=1)[0] if error_message.split() else "unknown"
        return f"{first_word.lower()}_error"

    def _create_failure_analysis(self, failure_type: str, records: list[LearningRecord]) -> FailureAnalysis | None:
        """Create failure analysis from records.

        Args:
            failure_type: Type of failure being analyzed
            records: List of LearningRecord instances with this failure type

        Returns:
            FailureAnalysis instance or None if no records provided

        """
        if not records:
            return None

        # Calculate impact level
        impact_level = self._calculate_impact_level(records)

        # Find root cause
        root_cause = self._identify_root_cause(records)

        # Generate pattern signature
        pattern_signature = self._generate_pattern_signature(records)

        # Generate suggested fixes
        suggested_fixes = self._generate_suggested_fixes(failure_type, records)

        # Find affected components
        affected_components = self._identify_affected_components(records)

        # Generate mitigation strategies
        mitigation_strategies = self._generate_mitigation_strategies(failure_type, records)

        failure_id = f"{failure_type}_{hashlib.md5(pattern_signature.encode(), usedforsecurity=False).hexdigest()[:8]}"

        return FailureAnalysis(
            failure_id=failure_id,
            failure_type=failure_type,
            frequency=len(records),
            impact_level=impact_level,
            root_cause=root_cause,
            suggested_fixes=suggested_fixes,
            pattern_signature=pattern_signature,
            affected_components=affected_components,
            mitigation_strategies=mitigation_strategies,
        )

    def _calculate_impact_level(self, records: list[LearningRecord]) -> str:
        """Calculate impact level based on failure frequency and context.

        Args:
            records: List of LearningRecord instances representing failures

        Returns:
            str: The impact level - "critical", "high", "medium", or "low"

        """
        frequency = len(records)

        # Check if failures affect critical operations
        critical_tasks = ["generate_script", "modify_code", "autonomous_analysis"]
        critical_failures = sum(r.task_type in critical_tasks for r in records)

        if frequency >= 50 or critical_failures >= 20:
            return "critical"
        if frequency >= 20 or critical_failures >= 10:
            return "high"
        return "medium" if frequency >= 10 or critical_failures >= 5 else "low"

    def _identify_root_cause(self, records: list[LearningRecord]) -> str:
        """Identify root cause of failures.

        Args:
            records: List of LearningRecord instances representing failures

        Returns:
            String description of identified root cause

        """
        # Analyze common patterns in failed records
        common_contexts: dict[str, int] = defaultdict(int)
        common_metadata: dict[str, int] = defaultdict(int)

        for record in records:
            for key, value in record.context.items():
                common_contexts[f"{key}:{value}"] += 1

            for key, value in record.metadata.items():
                common_metadata[f"{key}:{value}"] += 1

        # Find most common context/metadata patterns
        if common_contexts:
            most_common_context = max(common_contexts.items(), key=lambda x: x[1])
            if most_common_context[1] >= len(records) * 0.5:  # 50% threshold
                return f"Common context pattern: {most_common_context[0]}"

        if common_metadata:
            most_common_meta = max(common_metadata.items(), key=lambda x: x[1])
            if most_common_meta[1] >= len(records) * 0.5:
                return f"Common metadata pattern: {most_common_meta[0]}"

        if error_messages := [r.error_message for r in records if r.error_message]:
            return f"Common error pattern in {len(error_messages)} cases"

        return "Root cause requires further investigation"

    def _generate_pattern_signature(self, records: list[LearningRecord]) -> str:
        """Generate unique signature for failure pattern.

        Args:
            records: List of LearningRecord instances with the same failure pattern

        Returns:
            Unique MD5 hash signature for the failure pattern

        """
        # Create signature based on task types, error messages, and contexts
        task_types = sorted({r.task_type for r in records})
        error_types = sorted({self._extract_error_type(r.error_message) for r in records if r.error_message})

        signature_parts = [
            f"tasks:{','.join(task_types)}",
            f"errors:{','.join(error_types)}",
            f"frequency:{len(records)}",
        ]

        signature = "|".join(signature_parts)
        return hashlib.md5(signature.encode(), usedforsecurity=False).hexdigest()

    def _generate_suggested_fixes(self, failure_type: str, records: list[LearningRecord]) -> list[str]:
        """Generate suggested fixes for failure type.

        Args:
            failure_type: Type of failure to generate fixes for
            records: List of LearningRecord instances with this failure type

        Returns:
            List of suggested fix strings

        """
        fixes = []

        # Analyze records to understand common failure patterns
        failure_patterns: dict[str, int] = {}
        for record in records:
            # LearningRecord doesn't have success_rate - records are already failures
            pattern = record.context.get("pattern_used", "unknown")
            if isinstance(pattern, str):
                failure_patterns[pattern] = failure_patterns.get(pattern, 0) + 1

        logger.debug("Analyzed %d records, found %d failure patterns", len(records), len(failure_patterns))

        if "timeout" in failure_type:
            fixes.extend(
                [
                    "Increase operation timeout values",
                    "Implement async processing for long operations",
                    "Add progress tracking and cancellation support",
                    "Optimize algorithm performance",
                ],
            )

        elif "memory" in failure_type:
            fixes.extend(
                [
                    "Implement memory usage monitoring",
                    "Add garbage collection triggers",
                    "Use streaming for large data processing",
                    "Implement memory cleanup in error paths",
                ],
            )

        elif "connection" in failure_type:
            fixes.extend(
                [
                    "Add connection retry logic",
                    "Implement connection pooling",
                    "Add network connectivity checks",
                    "Use exponential backoff for retries",
                ],
            )

        elif "permission" in failure_type:
            fixes.extend(
                [
                    "Add permission validation before operations",
                    "Implement graceful permission error handling",
                    "Add user guidance for permission issues",
                    "Use fallback methods when permissions limited",
                ],
            )

        else:
            fixes.extend(
                [
                    "Add comprehensive error handling",
                    "Implement input validation",
                    "Add logging for debugging",
                    "Create fallback mechanisms",
                ],
            )

        return fixes

    def _identify_affected_components(self, records: list[LearningRecord]) -> list[str]:
        """Identify components affected by failures.

        Args:
            records: List of LearningRecord instances representing failures

        Returns:
            List of component names affected by the failures

        """
        components = set()

        for record in records:
            # Extract component from task type
            if record.task_type:
                components.add(record.task_type)

            # Extract components from context
            if "component" in record.context:
                components.add(record.context["component"])

            # Extract from metadata
            if "module" in record.metadata:
                components.add(record.metadata["module"])

        return list(components)

    def _generate_mitigation_strategies(self, failure_type: str, records: list[LearningRecord]) -> list[str]:
        """Generate mitigation strategies.

        Args:
            failure_type: Type of failure to generate strategies for
            records: List of LearningRecord instances with this failure type

        Returns:
            List of mitigation strategy strings

        """
        strategies = []

        # Analyze records to understand what mitigation strategies might work
        # Note: These are failure records, so we analyze failure patterns
        successful_patterns: list[str] = []
        failed_patterns: list[str] = []

        for record in records:
            # LearningRecord doesn't have success_rate - these are all failures
            # We can look at confidence as a proxy
            strategy = record.context.get("strategy", "unknown")
            if isinstance(strategy, str):
                if record.confidence > 0.7:
                    successful_patterns.append(strategy)
                elif record.confidence < 0.3:
                    failed_patterns.append(strategy)

        logger.debug(
            "Analyzed %d records for %s: %d successful, %d failed patterns",
            len(records),
            failure_type,
            len(successful_patterns),
            len(failed_patterns),
        )

        # Add type-specific strategies based on failure_type
        if "timeout" in failure_type.lower():
            strategies.extend(
                [
                    "Increase timeout thresholds",
                    "Implement asynchronous processing",
                    "Add progress monitoring",
                ],
            )
        elif "memory" in failure_type.lower():
            strategies.extend(
                [
                    "Implement memory optimization",
                    "Add garbage collection triggers",
                    "Use streaming processing",
                ],
            )
        elif "network" in failure_type.lower():
            strategies.extend(
                [
                    "Add retry mechanisms",
                    "Implement connection pooling",
                    "Add network error handling",
                ],
            )

        strategies.extend(
            [
                "Implement comprehensive monitoring",
                "Add automated failure detection",
                "Create fallback mechanisms",
                "Implement graceful degradation",
            ],
        )

        if len(records) >= 20:
            strategies.append("Consider redesigning affected components")

        if len(records) >= 50:
            strategies.append("Implement circuit breaker pattern")

        return strategies

    def _generate_improvement_strategies(self, failed_records: list[LearningRecord]) -> list[str]:
        """Generate overall improvement strategies.

        Args:
            failed_records: List of all failed LearningRecord instances

        Returns:
            List of improvement strategy strings

        """
        strategies = []

        # Analyze failure trends
        recent_failures = [r for r in failed_records if r.timestamp > datetime.now() - timedelta(days=7)]

        if len(recent_failures) > len(failed_records) * 0.3:
            strategies.append("Failure rate increasing - immediate attention required")

        # Task-specific strategies
        task_failures: dict[str, int] = defaultdict(int)
        for record in failed_records:
            task_failures[record.task_type] += 1

        strategies.extend(
            f"Focus on improving {task_type} reliability ({count} failures)" for task_type, count in task_failures.items() if count >= 10
        )
        # General strategies
        strategies.extend(
            [
                "Implement proactive error prevention",
                "Enhance monitoring and alerting",
                "Create automated recovery procedures",
                "Develop comprehensive testing strategies",
            ],
        )

        return strategies


class AILearningEngine:
    """Run AI learning and evolution engine."""

    def __init__(self, db_path: Path | None = None) -> None:
        """Initialize the AI learning engine.

        Args:
            db_path: Optional path to the database file. If not provided,
                     defaults to ~/.intellicrack/ai_learning.db

        """
        self.database = AILearningDatabase(db_path)
        self.pattern_engine = PatternEvolutionEngine(self.database)
        self.failure_engine = FailureAnalysisEngine(self.database)

        # Learning configuration
        self.learning_enabled = True
        self.auto_evolution_interval = 3600  # 1 hour
        self.last_evolution = datetime.now()
        self.learning_stats = {
            "records_processed": 0,
            "patterns_discovered": 0,
            "failures_analyzed": 0,
        }

        # Initialize ML models
        self._init_ml_models()

        logger.info("AI Learning Engine initialized")

    def _init_ml_models(self) -> None:
        """Initialize machine learning models for pattern recognition and prediction.

        Sets up scikit-learn models for pattern classification, neural network learning,
        and anomaly detection on exploitation data.

        """
        try:
            from sklearn.ensemble import IsolationForest, RandomForestClassifier
            from sklearn.neural_network import MLPClassifier
            from sklearn.preprocessing import StandardScaler

            # Pattern classification model
            self.pattern_classifier = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
            )

            # Neural network for complex pattern learning
            self.neural_net = MLPClassifier(
                hidden_layer_sizes=(128, 64, 32),
                activation="relu",
                solver="adam",
                max_iter=1000,
                random_state=42,
            )

            # Anomaly detection for identifying new patterns
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42,
            )

            # Feature scaler
            self.scaler = StandardScaler()

            # Model states
            self.models_trained = False
            self.training_data = {
                "features": np.array([]),
                "labels": np.array([]),
                "metadata": [],
            }
            # Initialize feature dimensions
            self.feature_dim = None
            self.min_features = np.array([np.inf] * 20)  # Track min values for normalization
            self.max_features = np.array([-np.inf] * 20)  # Track max values for normalization

            logger.info("ML models initialized successfully")

        except ImportError as e:
            logger.warning("ML libraries not available: %s. Using fallback learning.", e)
            self.pattern_classifier = None
            self.neural_net = None
            self.anomaly_detector = None
            self.scaler = None
            self.models_trained = False

    @profile_ai_operation("record_learning")
    def record_experience(
        self,
        task_type: str,
        input_data: object,
        output_data: object,
        success: bool,
        confidence: float,
        execution_time: float,
        memory_usage: int,
        error_message: str | None = None,
        context: dict[str, object] | None = None,
        metadata: dict[str, object] | None = None,
    ) -> str:
        """Record AI learning experience.

        Args:
            task_type: Type of task executed
            input_data: Input data provided to the task
            output_data: Output data produced by the task
            success: Whether the task succeeded
            confidence: Confidence score for the result (0.0-1.0)
            execution_time: Time taken to execute in seconds
            memory_usage: Memory used in bytes
            error_message: Error message if task failed
            context: Context dictionary for task execution
            metadata: Additional metadata about the task

        Returns:
            Record ID string for the saved learning record

        """
        logger.debug("Entering AILearningEngine.record_experience for task_type=%s", task_type)
        if not self.learning_enabled:
            logger.debug("Learning disabled, skipping record")
            return ""

        # Create hashes for input/output
        input_hash = hashlib.sha256(str(input_data).encode()).hexdigest()
        output_hash = hashlib.sha256(str(output_data).encode()).hexdigest()

        record_id = f"{task_type}_{int(datetime.now().timestamp())}_{input_hash[:8]}"

        record = LearningRecord(
            record_id=record_id,
            task_type=task_type,
            input_hash=input_hash,
            output_hash=output_hash,
            success=success,
            confidence=confidence,
            execution_time=execution_time,
            memory_usage=memory_usage,
            error_message=error_message,
            context=context or {},
            metadata=metadata or {},
        )

        self.database.save_learning_record(record)
        self.learning_stats["records_processed"] += 1
        logger.info("Recorded learning experience: %s (success=%s)", record_id, success)

        if self._should_trigger_evolution():
            self._trigger_background_evolution()

        logger.debug("Exiting AILearningEngine.record_experience")
        return record_id

    def _should_trigger_evolution(self) -> bool:
        """Check if evolution should be triggered.

        Returns:
            True if enough time has passed since last evolution

        """
        time_since_last = datetime.now() - self.last_evolution
        return time_since_last.total_seconds() >= self.auto_evolution_interval

    def _trigger_background_evolution(self) -> None:
        """Trigger background evolution process.

        Spawns a daemon thread to run pattern evolution and failure analysis
        without blocking the main thread.

        """
        # Skip thread creation during testing
        if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
            logger.info("Skipping background evolution (testing mode)")
            return

        def evolution_worker() -> None:
            try:
                self.evolve_patterns()
                self.analyze_failures()
                self.last_evolution = datetime.now()
            except Exception as e:
                logger.exception("Error in background evolution: %s", e, exc_info=True)

        evolution_thread = threading.Thread(target=evolution_worker, daemon=True)
        evolution_thread.start()

    @profile_ai_operation("pattern_evolution")
    def evolve_patterns(self) -> dict[str, Any]:
        """Evolve AI patterns based on learning.

        Returns:
            Dictionary with pattern evolution results

        """
        results = self.pattern_engine.evolve_patterns()
        self.learning_stats["patterns_discovered"] += results.get("new_patterns_discovered", 0)
        return results

    @profile_ai_operation("failure_analysis")
    def analyze_failures(self) -> dict[str, Any]:
        """Analyze failures for learning.

        Returns:
            Dictionary with failure analysis results

        """
        results = self.failure_engine.analyze_failures()
        self.learning_stats["failures_analyzed"] += results.get("new_analyses", 0)
        return results

    def get_applicable_patterns(self, context: dict[str, Any]) -> list[PatternRule]:
        """Get patterns applicable to current context.

        Args:
            context: Context dictionary with target_type, platform, and complexity

        Returns:
            List of applicable PatternRule instances

        """
        return self.pattern_engine.get_applicable_patterns(context)

    def get_learning_insights(self) -> dict[str, Any]:
        """Get insights from learning data.

        Returns:
            Dictionary with learning statistics and pattern insights

        """
        recent_records = self.database.get_learning_records(limit=1000)

        return {
            "total_records": len(recent_records),
            "success_rate": (len([r for r in recent_records if r.success]) / len(recent_records) if recent_records else 0),
            "avg_confidence": (sum(r.confidence for r in recent_records) / len(recent_records) if recent_records else 0),
            "learning_stats": self.learning_stats.copy(),
            "pattern_insights": self.pattern_engine.get_insights(),
        }

    def record_exploit_chain_creation(
        self,
        vulnerability: object,
        chain: object,
        success: bool,
        execution_time: float | None = None,
        error_message: str | None = None,
    ) -> str:
        """Record exploit chain creation for learning.

        Args:
            vulnerability: Vulnerability object with vuln_type and severity
            chain: Exploit chain object with complexity and steps
            success: Whether chain creation succeeded
            execution_time: Time taken in seconds
            error_message: Error message if creation failed

        Returns:
            Record ID string for the saved learning record

        """
        # Create context from vulnerability
        context = {
            "vulnerability_type": str(vulnerability.vuln_type.value) if hasattr(vulnerability, "vuln_type") else "unknown",
            "severity": getattr(vulnerability, "severity", "unknown"),
            "exploitability": getattr(vulnerability, "exploitability", 0.0),
            "chain_complexity": str(chain.complexity.value) if hasattr(chain, "complexity") else "unknown",
            "steps_count": len(chain.steps) if hasattr(chain, "steps") else 0,
            "safety_verified": getattr(chain, "safety_verified", False),
        }

        # Create metadata from chain
        metadata = {
            "chain_id": getattr(chain, "chain_id", ""),
            "success_probability": getattr(chain, "success_probability", 0.0),
            "stealth_rating": getattr(chain, "stealth_rating", 0.0),
            "stability_rating": getattr(chain, "stability_rating", 0.0),
            "primitive_types": [step.step_type.value for step in chain.steps] if hasattr(chain, "steps") else [],
        }

        return self.record_experience(
            task_type="exploit_chain_building",
            input_data={
                "vuln_id": getattr(vulnerability, "vuln_id", ""),
                "vuln_type": str(vulnerability.vuln_type.value) if hasattr(vulnerability, "vuln_type") else "",
            },
            output_data={
                "chain_id": getattr(chain, "chain_id", ""),
                "success_probability": getattr(chain, "success_probability", 0.0),
            },
            success=success,
            confidence=getattr(chain, "success_probability", 0.0),
            execution_time=execution_time or 0.0,
            memory_usage=getattr(chain, "memory_footprint", 0),
            error_message=error_message,
            context=context,
            metadata=metadata,
        )

    def learn(self, min_samples: int = 50) -> None:
        """Perform actual machine learning based on collected data.

        Args:
            min_samples: Minimum number of samples required to train models

        """
        logger.debug("Entering AILearningEngine.learn with min_samples=%d", min_samples)
        if not self.learning_enabled:
            logger.info("Learning is disabled")
            logger.debug("Exiting AILearningEngine.learn")
            return

        if self.pattern_classifier is None:
            logger.warning("ML models not available, using database patterns only")
            logger.debug("Exiting AILearningEngine.learn")
            return

        try:
            recent_records = self.database.get_recent_records(limit=1000)
            logger.info("Retrieved %d records for learning", len(recent_records))

            if len(recent_records) < min_samples:
                logger.info("Not enough samples for training (%d/%d)", len(recent_records), min_samples)
                logger.debug("Exiting AILearningEngine.learn")
                return

            # Extract features and labels from records
            features = []
            labels = []
            metadata = []

            for record in recent_records:
                # Extract features from exploit data
                feature_vector = self._extract_features(record)
                if feature_vector is not None:
                    features.append(feature_vector)
                    labels.append(1 if record["success"] else 0)
                    metadata.append(
                        {
                            "technique": record["exploit_data"].get("technique"),
                            "target_type": record["exploit_data"].get("target_type"),
                            "timestamp": record["timestamp"],
                        },
                    )

            if len(features) < min_samples:
                logger.info("Not enough valid features extracted")
                return

            X = np.array(features)
            y = np.array(labels)

            # Scale features
            X_scaled = self.scaler.fit_transform(X)

            # Train pattern classifier
            logger.info("Training pattern classifier...")
            self.pattern_classifier.fit(X_scaled, y)

            # Train neural network
            logger.info("Training neural network...")
            self.neural_net.fit(X_scaled, y)

            # Train anomaly detector on successful exploits only
            successful_indices = np.where(y == 1)[0]
            if len(successful_indices) > 10:
                logger.info("Training anomaly detector...")
                X_successful = X_scaled[successful_indices]
                self.anomaly_detector.fit(X_successful)

            self.models_trained = True

            # Store training data for future reference
            self.training_data["features"] = features
            self.training_data["labels"] = labels
            self.training_data["metadata"] = metadata

            # Update learning stats
            self.learning_stats["records_processed"] += len(recent_records)

            # Discover new patterns
            self._discover_patterns(X_scaled, y, metadata)

            self.pattern_engine.evolve_patterns()

            logger.info("Learning completed. Processed %d samples.", len(features))
            logger.debug("Exiting AILearningEngine.learn")

        except Exception as e:
            logger.exception("Error during learning: %s", e, exc_info=True)

    def _extract_features(self, record: dict[str, Any]) -> list[float] | None:
        """Extract numerical features from a learning record.

        Args:
            record: Learning record containing exploit data

        Returns:
            Feature vector or None if extraction fails

        """
        try:
            exploit_data = record.get("exploit_data", {})

            features = [
                float(record.get("success", 0)),
                float(len(exploit_data.get("technique", ""))),
                float(len(exploit_data.get("target_type", ""))),
            ]
            # Extract timing features
            time_taken = exploit_data.get("execution_time", 0.0)
            features.append(float(time_taken))

            # Extract complexity features
            payload_size = exploit_data.get("payload_size", 0)
            features.append(float(payload_size))

            # Extract success rate features
            attempts = exploit_data.get("attempts", 1)
            features.append(float(attempts))

            # Extract protection level features
            protection_score = self._calculate_protection_score(exploit_data)
            features.append(float(protection_score))

            # Add technique-specific features
            technique = exploit_data.get("technique", "")
            technique_features = self._encode_technique(technique)
            features.extend(technique_features)

            # Add target-specific features
            target_type = exploit_data.get("target_type", "")
            target_features = self._encode_target_type(target_type)
            features.extend(target_features)

            return features

        except Exception as e:
            logger.debug("Failed to extract features: %s", e)
            return None

    def _calculate_protection_score(self, exploit_data: dict[str, Any]) -> float:
        """Calculate a protection score based on exploit data.

        Args:
            exploit_data: Dictionary containing exploit information

        Returns:
            Protection score (0.0 to 10.0)

        """
        score = 0.0

        # Check for various protections
        if exploit_data.get("has_aslr"):
            score += 2.0
        if exploit_data.get("has_dep"):
            score += 2.0
        if exploit_data.get("has_canary"):
            score += 2.0
        if exploit_data.get("has_cfi"):
            score += 2.0
        if exploit_data.get("has_custom_protection"):
            score += 2.0

        return min(score, 10.0)

    def _encode_technique(self, technique: str) -> list[float]:
        """Encode exploit technique as numerical features.

        Args:
            technique: Exploit technique name

        Returns:
            One-hot encoded vector

        """
        techniques = [
            "buffer_overflow",
            "heap_spray",
            "rop_chain",
            "return_to_libc",
            "format_string",
            "use_after_free",
            "integer_overflow",
            "race_condition",
        ]

        vector = [0.0] * len(techniques)
        if technique in techniques:
            vector[techniques.index(technique)] = 1.0

        return vector

    def _encode_target_type(self, target_type: str) -> list[float]:
        """Encode target type as numerical features.

        Args:
            target_type: Target application type

        Returns:
            One-hot encoded vector

        """
        target_types = [
            "windows_exe",
            "linux_elf",
            "macos_binary",
            "android_apk",
            "ios_app",
            "web_application",
            "firmware",
            "driver",
        ]

        vector = [0.0] * len(target_types)
        if target_type in target_types:
            vector[target_types.index(target_type)] = 1.0

        return vector

    def _discover_patterns(self, X: np.ndarray, y: np.ndarray, metadata: list[dict[str, Any]]) -> None:
        """Discover new patterns from trained models.

        Identifies anomalous successful exploits using trained models and creates
        new pattern rules from these discoveries.

        Args:
            X: Feature matrix of shape (n_samples, n_features)
            y: Binary labels (1 for successful, 0 for failed)
            metadata: List of metadata dictionaries for each sample

        """
        if not self.models_trained:
            return

        try:
            # Get feature importances from Random Forest
            importances = self.pattern_classifier.feature_importances_
            important_features = np.argsort(importances)[::-1][:5]

            # Find anomalies that were successful
            anomaly_predictions = self.anomaly_detector.predict(X)
            anomalous_successes = np.where((anomaly_predictions == -1) & (y == 1))[0]

            # Create new patterns from anomalies
            for idx in anomalous_successes:
                pattern_data = {
                    "feature_vector": X[idx].tolist(),
                    "important_features": important_features.tolist(),
                    "technique": metadata[idx].get("technique"),
                    "target_type": metadata[idx].get("target_type"),
                    "confidence": float(self.neural_net.predict_proba(X[idx : idx + 1])[0, 1]),
                }

                # Record the discovered pattern
                self.pattern_engine.add_pattern(
                    pattern_type="anomaly_based",
                    pattern_data=pattern_data,
                    source="ml_discovery",
                )

            self.learning_stats["patterns_discovered"] += len(anomalous_successes)
            logger.info("Discovered %d new patterns", len(anomalous_successes))

        except Exception as e:
            logger.exception("Error discovering patterns: %s", e, exc_info=True)

    def predict_success(self, exploit_data: dict[str, Any]) -> dict[str, Any]:
        """Predict the success probability of an exploit.

        Args:
            exploit_data: Dictionary containing exploit information

        Returns:
            Dictionary with prediction results from different models

        """
        if not self.models_trained:
            return {"status": "models_not_trained", "probability": 0.5}

        try:
            # Extract features
            features = self._extract_features({"exploit_data": exploit_data, "success": False})
            if features is None:
                return {"status": "feature_extraction_failed", "probability": 0.5}

            X = np.array([features])
            X_scaled = self.scaler.transform(X)

            # Get predictions from all models
            rf_prob = float(self.pattern_classifier.predict_proba(X_scaled)[0, 1])
            nn_prob = float(self.neural_net.predict_proba(X_scaled)[0, 1])

            # Check if it's an anomaly
            is_anomaly = self.anomaly_detector.predict(X_scaled)[0] == -1

            # Ensemble prediction
            ensemble_prob = (rf_prob + nn_prob) / 2

            return {
                "status": "success",
                "ensemble_probability": ensemble_prob,
                "random_forest_probability": rf_prob,
                "neural_network_probability": nn_prob,
                "is_anomaly": is_anomaly,
                "confidence": self._calculate_confidence(rf_prob, nn_prob),
            }

        except Exception as e:
            logger.exception("Error predicting success: %s", e, exc_info=True)
            return {"status": "prediction_error", "probability": 0.5, "error": str(e)}

    def _calculate_confidence(self, rf_prob: float, nn_prob: float) -> float:
        """Calculate confidence based on model agreement.

        Evaluates how well two models agree and how certain they are about
        their predictions.

        Args:
            rf_prob: Random Forest success probability (0.0-1.0)
            nn_prob: Neural Network success probability (0.0-1.0)

        Returns:
            Confidence score (0.0 to 1.0) based on model agreement and certainty

        """
        # High confidence when models agree
        agreement = 1.0 - abs(rf_prob - nn_prob)

        # Also consider distance from 0.5 (uncertainty)
        certainty = abs(0.5 - (rf_prob + nn_prob) / 2) * 2

        return (agreement + certainty) / 2


# Lazy initialization to avoid circular imports
_learning_engine = None


def get_learning_engine() -> AILearningEngine:
    """Get the global learning engine instance.

    Returns:
        Singleton AILearningEngine instance

    """
    global _learning_engine
    if _learning_engine is None:
        _learning_engine = AILearningEngine()
    return _learning_engine
