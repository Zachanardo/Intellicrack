"""
AI Learning & Evolution Engine

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

import hashlib
import json
import re
import sqlite3
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..utils.logger import get_logger
from .performance_monitor import profile_ai_operation

logger = get_logger(__name__)


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
    error_message: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    learned_patterns: List[str] = field(default_factory=list)
    improvement_suggestions: List[str] = field(default_factory=list)


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
    last_used: Optional[datetime] = None
    effectiveness_score: float = 0.0


@dataclass
class FailureAnalysis:
    """Analysis of AI failure patterns."""
    failure_id: str
    failure_type: str
    frequency: int
    impact_level: str  # low, medium, high, critical
    root_cause: str
    suggested_fixes: List[str]
    pattern_signature: str
    affected_components: List[str] = field(default_factory=list)
    mitigation_strategies: List[str] = field(default_factory=list)
    resolution_status: str = "open"  # open, in_progress, resolved


class AILearningDatabase:
    """Persistent database for AI learning records."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path.home() / ".intellicrack" / "ai_learning.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self._init_database()

    def _init_database(self):
        """Initialize database schema."""
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

    def save_learning_record(self, record: LearningRecord):
        """Save learning record to database."""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO learning_records VALUES 
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
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
                    json.dumps(record.improvement_suggestions)
                ))
                conn.commit()

    def save_pattern_rule(self, rule: PatternRule):
        """Save pattern rule to database."""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO pattern_rules VALUES 
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rule.rule_id,
                    rule.pattern_name,
                    rule.condition,
                    rule.action,
                    rule.confidence,
                    rule.success_rate,
                    rule.usage_count,
                    rule.created_at.isoformat(),
                    rule.last_used.isoformat() if rule.last_used else None,
                    rule.effectiveness_score
                ))
                conn.commit()

    def save_failure_analysis(self, analysis: FailureAnalysis):
        """Save failure analysis to database."""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO failure_analyses VALUES 
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    analysis.failure_id,
                    analysis.failure_type,
                    analysis.frequency,
                    analysis.impact_level,
                    analysis.root_cause,
                    json.dumps(analysis.suggested_fixes),
                    analysis.pattern_signature,
                    json.dumps(analysis.affected_components),
                    json.dumps(analysis.mitigation_strategies),
                    analysis.resolution_status
                ))
                conn.commit()

    def get_learning_records(self, task_type: Optional[str] = None,
                           success: Optional[bool] = None,
                           limit: int = 1000) -> List[LearningRecord]:
        """Get learning records from database."""
        with sqlite3.connect(self.db_path) as conn:
            query = "SELECT * FROM learning_records WHERE 1=1"
            params = []

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
                    improvement_suggestions=json.loads(row[13]) if row[13] else []
                )
                records.append(record)

            return records

    def get_pattern_rules(self, pattern_name: Optional[str] = None) -> List[PatternRule]:
        """Get pattern rules from database."""
        with sqlite3.connect(self.db_path) as conn:
            if pattern_name:
                cursor = conn.execute(
                    "SELECT * FROM pattern_rules WHERE pattern_name = ? ORDER BY effectiveness_score DESC",
                    (pattern_name,)
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
                    effectiveness_score=row[9]
                )
                rules.append(rule)

            return rules

    def get_failure_analyses(self, failure_type: Optional[str] = None,
                           resolution_status: str = "open") -> List[FailureAnalysis]:
        """Get failure analyses from database."""
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
                    resolution_status=row[9]
                )
                analyses.append(analysis)

            return analyses


class PatternEvolutionEngine:
    """Engine for evolving AI patterns based on learning."""

    def __init__(self, database: AILearningDatabase):
        self.database = database
        self.pattern_cache: Dict[str, List[PatternRule]] = {}
        self.evolution_threshold = 0.8  # Minimum effectiveness for pattern promotion
        self.cache_ttl = 3600  # 1 hour cache TTL
        self.last_cache_update = datetime.now()

    @profile_ai_operation("pattern_evolution")
    def evolve_patterns(self) -> Dict[str, Any]:
        """Evolve patterns based on learning data."""
        logger.info("Starting pattern evolution process")

        # Get recent learning records
        recent_records = self.database.get_learning_records(limit=5000)

        evolution_results = {
            "patterns_analyzed": 0,
            "new_patterns_discovered": 0,
            "patterns_improved": 0,
            "patterns_deprecated": 0,
            "evolution_insights": []
        }

        # Analyze success patterns
        success_patterns = self._analyze_success_patterns(recent_records)
        evolution_results["patterns_analyzed"] += len(success_patterns)

        # Create new pattern rules
        new_rules = self._create_pattern_rules(success_patterns)
        evolution_results["new_patterns_discovered"] += len(new_rules)

        # Improve existing patterns
        improved_rules = self._improve_existing_patterns(recent_records)
        evolution_results["patterns_improved"] += len(improved_rules)

        # Deprecate ineffective patterns
        deprecated_rules = self._deprecate_ineffective_patterns()
        evolution_results["patterns_deprecated"] += len(deprecated_rules)

        # Generate insights
        insights = self._generate_evolution_insights(recent_records)
        evolution_results["evolution_insights"] = insights

        # Update cache
        self._update_pattern_cache()

        logger.info(f"Pattern evolution completed: {evolution_results}")
        return evolution_results

    def _analyze_success_patterns(self, records: List[LearningRecord]) -> Dict[str, Any]:
        """Analyze patterns in successful operations."""
        success_records = [r for r in records if r.success and r.confidence > 0.7]

        patterns = {
            "task_type_success": defaultdict(list),
            "execution_time_patterns": defaultdict(list),
            "confidence_patterns": defaultdict(list),
            "context_patterns": defaultdict(list)
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
        """Bucket execution time into categories."""
        if time < 1.0:
            return "fast"
        elif time < 5.0:
            return "medium"
        elif time < 15.0:
            return "slow"
        else:
            return "very_slow"

    def _bucket_confidence(self, confidence: float) -> str:
        """Bucket confidence into categories."""
        if confidence >= 0.9:
            return "very_high"
        elif confidence >= 0.8:
            return "high"
        elif confidence >= 0.7:
            return "medium"
        else:
            return "low"

    def _generalize_value(self, value: Any) -> str:
        """Generalize values for pattern matching."""
        if isinstance(value, str):
            if len(value) > 50:
                return "long_string"
            elif re.match(r'^[a-zA-Z0-9_]+$', value):
                return "identifier"
            elif re.match(r'^https?://', value):
                return "url"
            else:
                return "string"
        elif isinstance(value, (int, float)):
            if value < 0:
                return "negative_number"
            elif value == 0:
                return "zero"
            elif value < 100:
                return "small_number"
            else:
                return "large_number"
        elif isinstance(value, bool):
            return str(value).lower()
        elif isinstance(value, (list, tuple)):
            return f"list_size_{len(value)}"
        elif isinstance(value, dict):
            return f"dict_size_{len(value)}"
        else:
            return "unknown"

    def _create_pattern_rules(self, patterns: Dict[str, Any]) -> List[PatternRule]:
        """Create new pattern rules from discovered patterns."""
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
                        effectiveness_score=success_rate * avg_confidence
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
                        effectiveness_score=success_rate * avg_confidence
                    )
                    new_rules.append(rule)
                    self.database.save_pattern_rule(rule)

        return new_rules

    def _improve_existing_patterns(self, records: List[LearningRecord]) -> List[PatternRule]:
        """Improve existing pattern rules based on new data."""
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

    def _find_matching_records(self, rule: PatternRule, records: List[LearningRecord]) -> List[LearningRecord]:
        """Find records that match a pattern rule."""
        matching_records = []

        for record in records:
            if self._evaluate_rule_condition(rule.condition, record):
                matching_records.append(record)

        return matching_records

    def _evaluate_rule_condition(self, condition: str, record: LearningRecord) -> bool:
        """Evaluate if a record matches a rule condition."""
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
        except Exception:
            return False

    def _deprecate_ineffective_patterns(self) -> List[PatternRule]:
        """Deprecate patterns with low effectiveness."""
        all_rules = self.database.get_pattern_rules()
        deprecated_rules = []

        for rule in all_rules:
            # Deprecate rules with low effectiveness or usage
            if (rule.effectiveness_score < 0.5 or
                (rule.usage_count > 10 and rule.success_rate < 0.6)):

                # Mark as deprecated (could delete or move to archive)
                rule.effectiveness_score = 0.0
                self.database.save_pattern_rule(rule)
                deprecated_rules.append(rule)

        return deprecated_rules

    def _generate_evolution_insights(self, records: List[LearningRecord]) -> List[str]:
        """Generate insights from pattern evolution."""
        insights = []

        # Success rate analysis
        total_records = len(records)
        successful_records = len([r for r in records if r.success])
        overall_success_rate = successful_records / total_records if total_records > 0 else 0

        insights.append(f"Overall success rate: {overall_success_rate:.2%}")

        # Task type analysis
        task_types = Counter(r.task_type for r in records)
        most_common_task = task_types.most_common(1)[0] if task_types else ("unknown", 0)
        insights.append(f"Most common task type: {most_common_task[0]} ({most_common_task[1]} occurrences)")

        # Performance analysis
        avg_execution_time = sum(r.execution_time for r in records) / len(records) if records else 0
        insights.append(f"Average execution time: {avg_execution_time:.3f}s")

        # Error analysis
        failed_records = [r for r in records if not r.success]
        if failed_records:
            error_types = Counter(r.error_message.split(':')[0] if r.error_message else "Unknown"
                                for r in failed_records)
            most_common_error = error_types.most_common(1)[0]
            insights.append(f"Most common error: {most_common_error[0]} ({most_common_error[1]} occurrences)")

        return insights

    def _update_pattern_cache(self):
        """Update pattern cache with latest rules."""
        self.pattern_cache.clear()
        all_rules = self.database.get_pattern_rules()

        for rule in all_rules:
            if rule.pattern_name not in self.pattern_cache:
                self.pattern_cache[rule.pattern_name] = []
            self.pattern_cache[rule.pattern_name].append(rule)

        self.last_cache_update = datetime.now()

    def get_applicable_patterns(self, context: Dict[str, Any]) -> List[PatternRule]:
        """Get patterns applicable to current context."""
        # Update cache if needed
        if datetime.now() - self.last_cache_update > timedelta(seconds=self.cache_ttl):
            self._update_pattern_cache()

        applicable_patterns = []

        # Use context to filter applicable patterns
        target_type = context.get('target_type', 'unknown')
        platform = context.get('platform', 'unknown')
        complexity = context.get('complexity', 'medium')

        logger.debug(f"Finding patterns for context: target={target_type}, platform={platform}, complexity={complexity}")

        for pattern_list in self.pattern_cache.values():
            for pattern in pattern_list:
                if pattern.effectiveness_score > self.evolution_threshold:
                    applicable_patterns.append(pattern)

        # Sort by effectiveness
        applicable_patterns.sort(key=lambda p: p.effectiveness_score, reverse=True)

        return applicable_patterns[:10]  # Return top 10

    def get_insights(self) -> Dict[str, Any]:
        """Get insights about pattern evolution and effectiveness."""
        try:
            # Get recent learning records for analysis
            recent_records = self.database.get_learning_records(limit=1000)

            if not recent_records:
                return {
                    "total_patterns": 0,
                    "avg_effectiveness": 0.0,
                    "pattern_categories": {},
                    "recommendations": ["No learning data available"],
                    "evolution_status": "inactive"
                }

            # Analyze patterns in cache
            total_patterns = sum(len(patterns) for patterns in self.pattern_cache.values())
            effective_patterns = []

            for pattern_list in self.pattern_cache.values():
                for pattern in pattern_list:
                    if pattern.effectiveness_score > self.evolution_threshold:
                        effective_patterns.append(pattern)

            # Calculate statistics
            avg_effectiveness = (
                sum(p.effectiveness_score for p in effective_patterns) / len(effective_patterns)
                if effective_patterns else 0.0
            )

            # Categorize patterns
            pattern_categories = {}
            for category, patterns in self.pattern_cache.items():
                pattern_categories[category] = {
                    "total": len(patterns),
                    "effective": len([p for p in patterns if p.effectiveness_score > self.evolution_threshold]),
                    "avg_score": sum(p.effectiveness_score for p in patterns) / len(patterns) if patterns else 0.0
                }

            # Generate recommendations
            recommendations = []
            if avg_effectiveness < 0.7:
                recommendations.append("Consider collecting more training data to improve pattern effectiveness")
            if total_patterns < 10:
                recommendations.append("Pattern library is small - more diverse scenarios needed")
            if len(effective_patterns) == 0:
                recommendations.append("No highly effective patterns found - review learning criteria")

            return {
                "total_patterns": total_patterns,
                "effective_patterns": len(effective_patterns),
                "avg_effectiveness": avg_effectiveness,
                "pattern_categories": pattern_categories,
                "recommendations": recommendations,
                "evolution_status": "active" if effective_patterns else "learning",
                "cache_age": (datetime.now() - self.last_cache_update).total_seconds(),
                "threshold": self.evolution_threshold
            }

        except Exception as e:
            logger.error(f"Error getting pattern insights: {e}")
            return {
                "total_patterns": 0,
                "error": str(e),
                "evolution_status": "error"
            }


class FailureAnalysisEngine:
    """Engine for analyzing and learning from failures."""

    def __init__(self, database: AILearningDatabase):
        self.database = database
        self.failure_patterns: Dict[str, List[str]] = defaultdict(list)
        self.analysis_threshold = 3  # Minimum failures to analyze

    @profile_ai_operation("failure_analysis")
    def analyze_failures(self) -> Dict[str, Any]:
        """Analyze failure patterns and create improvement strategies."""
        logger.info("Starting failure analysis")

        # Get failed learning records
        failed_records = self.database.get_learning_records(success=False, limit=2000)

        if len(failed_records) < self.analysis_threshold:
            return {"message": "Insufficient failure data for analysis"}

        analysis_results = {
            "total_failures": len(failed_records),
            "failure_types": {},
            "critical_patterns": [],
            "improvement_strategies": [],
            "new_analyses": 0
        }

        # Categorize failures
        failure_categories = self._categorize_failures(failed_records)
        analysis_results["failure_types"] = {k: len(v) for k, v in failure_categories.items()}

        # Analyze each category
        for failure_type, records in failure_categories.items():
            if len(records) >= self.analysis_threshold:
                analysis = self._create_failure_analysis(failure_type, records)
                if analysis:
                    self.database.save_failure_analysis(analysis)
                    analysis_results["new_analyses"] += 1

                    if analysis.impact_level in ["high", "critical"]:
                        analysis_results["critical_patterns"].append(analysis.pattern_signature)

        # Generate improvement strategies
        strategies = self._generate_improvement_strategies(failed_records)
        analysis_results["improvement_strategies"] = strategies

        logger.info(f"Failure analysis completed: {analysis_results}")
        return analysis_results

    def _categorize_failures(self, failed_records: List[LearningRecord]) -> Dict[str, List[LearningRecord]]:
        """Categorize failures by type."""
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
        """Extract error type from error message."""
        if "timeout" in error_message.lower():
            return "timeout_error"
        elif "memory" in error_message.lower():
            return "memory_error"
        elif "connection" in error_message.lower():
            return "connection_error"
        elif "permission" in error_message.lower():
            return "permission_error"
        elif "not found" in error_message.lower():
            return "not_found_error"
        elif "invalid" in error_message.lower():
            return "validation_error"
        else:
            # Use first word of error as type
            first_word = error_message.split()[0] if error_message.split() else "unknown"
            return f"{first_word.lower()}_error"

    def _create_failure_analysis(self, failure_type: str, records: List[LearningRecord]) -> Optional[FailureAnalysis]:
        """Create failure analysis from records."""
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

        failure_id = f"{failure_type}_{hashlib.md5(pattern_signature.encode()).hexdigest()[:8]}"

        analysis = FailureAnalysis(
            failure_id=failure_id,
            failure_type=failure_type,
            frequency=len(records),
            impact_level=impact_level,
            root_cause=root_cause,
            suggested_fixes=suggested_fixes,
            pattern_signature=pattern_signature,
            affected_components=affected_components,
            mitigation_strategies=mitigation_strategies
        )

        return analysis

    def _calculate_impact_level(self, records: List[LearningRecord]) -> str:
        """Calculate impact level based on failure frequency and context."""
        frequency = len(records)

        # Check if failures affect critical operations
        critical_tasks = ["generate_script", "modify_code", "autonomous_analysis"]
        critical_failures = sum(1 for r in records if r.task_type in critical_tasks)

        if frequency >= 50 or critical_failures >= 20:
            return "critical"
        elif frequency >= 20 or critical_failures >= 10:
            return "high"
        elif frequency >= 10 or critical_failures >= 5:
            return "medium"
        else:
            return "low"

    def _identify_root_cause(self, records: List[LearningRecord]) -> str:
        """Identify root cause of failures."""
        # Analyze common patterns in failed records
        common_contexts = defaultdict(int)
        common_metadata = defaultdict(int)

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

        # Fallback to error message analysis
        error_messages = [r.error_message for r in records if r.error_message]
        if error_messages:
            return f"Common error pattern in {len(error_messages)} cases"

        return "Root cause requires further investigation"

    def _generate_pattern_signature(self, records: List[LearningRecord]) -> str:
        """Generate unique signature for failure pattern."""
        # Create signature based on task types, error messages, and contexts
        task_types = sorted(set(r.task_type for r in records))
        error_types = sorted(set(self._extract_error_type(r.error_message)
                                for r in records if r.error_message))

        signature_parts = [
            f"tasks:{','.join(task_types)}",
            f"errors:{','.join(error_types)}",
            f"frequency:{len(records)}"
        ]

        signature = "|".join(signature_parts)
        return hashlib.md5(signature.encode()).hexdigest()

    def _generate_suggested_fixes(self, failure_type: str, records: List[LearningRecord]) -> List[str]:
        """Generate suggested fixes for failure type."""
        fixes = []

        # Analyze records to understand common failure patterns
        failure_patterns = {}
        for record in records:
            if record.success_rate < 0.5:  # Failed more than succeeded
                pattern = record.context.get('pattern_used', 'unknown')
                failure_patterns[pattern] = failure_patterns.get(pattern, 0) + 1

        logger.debug(f"Analyzed {len(records)} records, found {len(failure_patterns)} failure patterns")

        if "timeout" in failure_type:
            fixes.extend([
                "Increase operation timeout values",
                "Implement async processing for long operations",
                "Add progress tracking and cancellation support",
                "Optimize algorithm performance"
            ])

        elif "memory" in failure_type:
            fixes.extend([
                "Implement memory usage monitoring",
                "Add garbage collection triggers",
                "Use streaming for large data processing",
                "Implement memory cleanup in error paths"
            ])

        elif "connection" in failure_type:
            fixes.extend([
                "Add connection retry logic",
                "Implement connection pooling",
                "Add network connectivity checks",
                "Use exponential backoff for retries"
            ])

        elif "permission" in failure_type:
            fixes.extend([
                "Add permission validation before operations",
                "Implement graceful permission error handling",
                "Add user guidance for permission issues",
                "Use fallback methods when permissions limited"
            ])

        else:
            fixes.extend([
                "Add comprehensive error handling",
                "Implement input validation",
                "Add logging for debugging",
                "Create fallback mechanisms"
            ])

        return fixes

    def _identify_affected_components(self, records: List[LearningRecord]) -> List[str]:
        """Identify components affected by failures."""
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

    def _generate_mitigation_strategies(self, failure_type: str, records: List[LearningRecord]) -> List[str]:
        """Generate mitigation strategies."""
        strategies = []

        # Analyze records to understand what mitigation strategies might work
        successful_patterns = []
        failed_patterns = []

        for record in records:
            if record.success_rate > 0.7:
                successful_patterns.append(record.context.get('strategy', 'unknown'))
            elif record.success_rate < 0.3:
                failed_patterns.append(record.context.get('strategy', 'unknown'))

        logger.debug(f"Analyzed {len(records)} records for {failure_type}: {len(successful_patterns)} successful, {len(failed_patterns)} failed patterns")

        # Add type-specific strategies based on failure_type
        if 'timeout' in failure_type.lower():
            strategies.extend([
                "Increase timeout thresholds",
                "Implement asynchronous processing",
                "Add progress monitoring"
            ])
        elif 'memory' in failure_type.lower():
            strategies.extend([
                "Implement memory optimization",
                "Add garbage collection triggers",
                "Use streaming processing"
            ])
        elif 'network' in failure_type.lower():
            strategies.extend([
                "Add retry mechanisms",
                "Implement connection pooling",
                "Add network error handling"
            ])

        strategies.extend([
            "Implement comprehensive monitoring",
            "Add automated failure detection",
            "Create fallback mechanisms",
            "Implement graceful degradation"
        ])

        if len(records) >= 20:
            strategies.append("Consider redesigning affected components")

        if len(records) >= 50:
            strategies.append("Implement circuit breaker pattern")

        return strategies

    def _generate_improvement_strategies(self, failed_records: List[LearningRecord]) -> List[str]:
        """Generate overall improvement strategies."""
        strategies = []

        # Analyze failure trends
        recent_failures = [r for r in failed_records
                          if r.timestamp > datetime.now() - timedelta(days=7)]

        if len(recent_failures) > len(failed_records) * 0.3:
            strategies.append("Failure rate increasing - immediate attention required")

        # Task-specific strategies
        task_failures = defaultdict(int)
        for record in failed_records:
            task_failures[record.task_type] += 1

        for task_type, count in task_failures.items():
            if count >= 10:
                strategies.append(f"Focus on improving {task_type} reliability ({count} failures)")

        # General strategies
        strategies.extend([
            "Implement proactive error prevention",
            "Enhance monitoring and alerting",
            "Create automated recovery procedures",
            "Develop comprehensive testing strategies"
        ])

        return strategies


class AILearningEngine:
    """Main AI learning and evolution engine."""

    def __init__(self, db_path: Optional[Path] = None):
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
            "failures_analyzed": 0
        }

        logger.info("AI Learning Engine initialized")

    @profile_ai_operation("record_learning")
    def record_experience(self, task_type: str, input_data: Any, output_data: Any,
                         success: bool, confidence: float, execution_time: float,
                         memory_usage: int, error_message: Optional[str] = None,
                         context: Optional[Dict[str, Any]] = None,
                         metadata: Optional[Dict[str, Any]] = None) -> str:
        """Record AI learning experience."""
        if not self.learning_enabled:
            return ""

        # Create hashes for input/output
        input_hash = hashlib.md5(str(input_data).encode()).hexdigest()
        output_hash = hashlib.md5(str(output_data).encode()).hexdigest()

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
            metadata=metadata or {}
        )

        # Save to database
        self.database.save_learning_record(record)
        self.learning_stats["records_processed"] += 1

        # Trigger evolution if needed
        if self._should_trigger_evolution():
            self._trigger_background_evolution()

        return record_id

    def _should_trigger_evolution(self) -> bool:
        """Check if evolution should be triggered."""
        time_since_last = datetime.now() - self.last_evolution
        return time_since_last.total_seconds() >= self.auto_evolution_interval

    def _trigger_background_evolution(self):
        """Trigger background evolution process."""
        def evolution_worker():
            try:
                self.evolve_patterns()
                self.analyze_failures()
                self.last_evolution = datetime.now()
            except Exception as e:
                logger.error(f"Error in background evolution: {e}")

        evolution_thread = threading.Thread(target=evolution_worker, daemon=True)
        evolution_thread.start()

    @profile_ai_operation("pattern_evolution")
    def evolve_patterns(self) -> Dict[str, Any]:
        """Evolve AI patterns based on learning."""
        results = self.pattern_engine.evolve_patterns()
        self.learning_stats["patterns_discovered"] += results.get("new_patterns_discovered", 0)
        return results

    @profile_ai_operation("failure_analysis")
    def analyze_failures(self) -> Dict[str, Any]:
        """Analyze failures for learning."""
        results = self.failure_engine.analyze_failures()
        self.learning_stats["failures_analyzed"] += results.get("new_analyses", 0)
        return results

    def get_applicable_patterns(self, context: Dict[str, Any]) -> List[PatternRule]:
        """Get patterns applicable to current context."""
        return self.pattern_engine.get_applicable_patterns(context)

    def get_learning_insights(self) -> Dict[str, Any]:
        """Get insights from learning data."""
        recent_records = self.database.get_learning_records(limit=1000)

        insights = {
            "total_records": len(recent_records),
            "success_rate": len([r for r in recent_records if r.success]) / len(recent_records) if recent_records else 0,
            "avg_confidence": sum(r.confidence for r in recent_records) / len(recent_records) if recent_records else 0,
            "learning_stats": self.learning_stats.copy(),
            "pattern_insights": self.pattern_engine.get_insights()
        }

        return insights

    def record_exploit_chain_creation(self, vulnerability: Any, chain: Any, success: bool,
                                    execution_time: Optional[float] = None,
                                    error_message: Optional[str] = None) -> str:
        """Record exploit chain creation for learning."""
        # Create context from vulnerability
        context = {
            "vulnerability_type": str(vulnerability.vuln_type.value) if hasattr(vulnerability, 'vuln_type') else "unknown",
            "severity": getattr(vulnerability, 'severity', 'unknown'),
            "exploitability": getattr(vulnerability, 'exploitability', 0.0),
            "chain_complexity": str(chain.complexity.value) if hasattr(chain, 'complexity') else "unknown",
            "steps_count": len(chain.steps) if hasattr(chain, 'steps') else 0,
            "safety_verified": getattr(chain, 'safety_verified', False)
        }

        # Create metadata from chain
        metadata = {
            "chain_id": getattr(chain, 'chain_id', ''),
            "success_probability": getattr(chain, 'success_probability', 0.0),
            "stealth_rating": getattr(chain, 'stealth_rating', 0.0),
            "stability_rating": getattr(chain, 'stability_rating', 0.0),
            "primitive_types": [step.step_type.value for step in chain.steps] if hasattr(chain, 'steps') else []
        }

        return self.record_experience(
            task_type="exploit_chain_building",
            input_data={"vuln_id": getattr(vulnerability, 'vuln_id', ''),
                       "vuln_type": str(vulnerability.vuln_type.value) if hasattr(vulnerability, 'vuln_type') else ""},
            output_data={"chain_id": getattr(chain, 'chain_id', ''),
                        "success_probability": getattr(chain, 'success_probability', 0.0)},
            success=success,
            confidence=getattr(chain, 'success_probability', 0.0),
            execution_time=execution_time or 0.0,
            memory_usage=getattr(chain, 'memory_footprint', 0),
            error_message=error_message,
            context=context,
            metadata=metadata
        )


# Global learning engine instance
learning_engine = AILearningEngine()
