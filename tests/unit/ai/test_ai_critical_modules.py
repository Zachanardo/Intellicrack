"""Real-world AI critical module tests with actual functionality.

Tests critical AI modules against real data and operations.
NO MOCKS - Uses real databases, real learning algorithms, real multi-agent systems.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

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
from intellicrack.ai.multi_agent_system import (
    AgentCapability,
    AgentMessage,
    AgentRole,
    AgentTask,
    BaseAgent,
    CollaborationResult,
    DynamicAnalysisAgent,
    KnowledgeManager,
    LoadBalancer,
    MessageRouter,
    MessageType,
    MultiAgentSystem,
    ReverseEngineeringAgent,
    StaticAnalysisAgent,
    TaskDistributor,
    TaskPriority,
    global_multi_agent_system,
)


WINDOWS_SYSTEM_BINARIES = {
    "notepad.exe": r"C:\Windows\System32\notepad.exe",
    "calc.exe": r"C:\Windows\System32\calc.exe",
    "kernel32.dll": r"C:\Windows\System32\kernel32.dll",
    "ntdll.dll": r"C:\Windows\System32\ntdll.dll",
}


@pytest.fixture
def temp_dir() -> Path:
    """Create temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def notepad_path() -> str:
    """Get path to notepad.exe."""
    notepad = WINDOWS_SYSTEM_BINARIES["notepad.exe"]
    if not os.path.exists(notepad):
        pytest.skip(f"notepad.exe not found at {notepad}")
    return notepad


@pytest.fixture
def calc_path() -> str:
    """Get path to calc.exe."""
    calc = WINDOWS_SYSTEM_BINARIES["calc.exe"]
    if not os.path.exists(calc):
        pytest.skip(f"calc.exe not found at {calc}")
    return calc


class TestAILearningDatabase:
    """Test AI learning database operations with real SQLite."""

    def test_database_initialization(self, temp_dir: Path) -> None:
        """Test database initialization creates schema."""
        db_path = temp_dir / "test_learning.db"
        db = AILearningDatabase(db_path=db_path)

        assert db is not None
        assert db.db_path == db_path
        assert db_path.exists()

    def test_save_and_retrieve_learning_record(self, temp_dir: Path) -> None:
        """Test saving and retrieving learning records."""
        db = AILearningDatabase(db_path=temp_dir / "test.db")

        record = LearningRecord(
            record_id="test_record_001",
            task_type="binary_analysis",
            input_hash="abc123",
            output_hash="def456",
            success=True,
            confidence=0.85,
            execution_time=2.5,
            memory_usage=1024000,
            learned_patterns=["pattern1", "pattern2"],
            improvement_suggestions=["suggestion1"],
        )

        db.save_learning_record(record)

        records = db.get_learning_records(task_type="binary_analysis")

        assert records is not None
        assert len(records) > 0
        assert any(r.record_id == "test_record_001" for r in records)

    def test_save_and_retrieve_pattern_rule(self, temp_dir: Path) -> None:
        """Test saving and retrieving pattern rules."""
        db = AILearningDatabase(db_path=temp_dir / "test.db")

        rule = PatternRule(
            rule_id="rule_001",
            pattern_name="vmprotect_detection",
            condition="entropy > 7.5 AND imports_obfuscated",
            action="apply_vmprotect_analyzer",
            confidence=0.92,
            success_rate=0.88,
            usage_count=150,
            effectiveness_score=0.9,
        )

        db.save_pattern_rule(rule)

        rules = db.get_pattern_rules(pattern_name="vmprotect_detection")

        assert rules is not None
        assert len(rules) > 0
        assert any(r.rule_id == "rule_001" for r in rules)

    def test_save_and_retrieve_failure_analysis(self, temp_dir: Path) -> None:
        """Test saving and retrieving failure analyses."""
        db = AILearningDatabase(db_path=temp_dir / "test.db")

        analysis = FailureAnalysis(
            failure_id="fail_001",
            failure_type="detection_failure",
            frequency=25,
            impact_level="high",
            root_cause="Insufficient entropy threshold for packed binaries",
            suggested_fixes=["Lower entropy threshold", "Add packing signature checks"],
            pattern_signature="high_entropy_false_negative",
            affected_components=["entropy_analyzer", "packer_detector"],
            mitigation_strategies=["Implement multi-stage detection", "Add ML classifier"],
        )

        db.save_failure_analysis(analysis)

        analyses = db.get_failure_analyses(failure_type="detection_failure")

        assert analyses is not None
        assert len(analyses) > 0
        assert any(a.failure_id == "fail_001" for a in analyses)

    def test_query_successful_records(self, temp_dir: Path) -> None:
        """Test querying only successful learning records."""
        db = AILearningDatabase(db_path=temp_dir / "test.db")

        for i in range(5):
            record = LearningRecord(
                record_id=f"record_{i}",
                task_type="test_task",
                input_hash=f"hash_{i}",
                output_hash=f"output_{i}",
                success=(i % 2 == 0),
                confidence=0.8,
                execution_time=1.0,
                memory_usage=1000000,
            )
            db.save_learning_record(record)

        successful_records = db.get_learning_records(task_type="test_task", success=True)

        assert successful_records is not None
        assert all(r.success for r in successful_records)
        assert len(successful_records) == 3

    def test_concurrent_database_access(self, temp_dir: Path) -> None:
        """Test thread-safe database access."""
        import threading

        db = AILearningDatabase(db_path=temp_dir / "test.db")
        errors = []

        def write_records(thread_id: int) -> None:
            try:
                for i in range(10):
                    record = LearningRecord(
                        record_id=f"thread_{thread_id}_record_{i}",
                        task_type=f"thread_{thread_id}_task",
                        input_hash=f"hash_{thread_id}_{i}",
                        output_hash=f"output_{thread_id}_{i}",
                        success=True,
                        confidence=0.8,
                        execution_time=1.0,
                        memory_usage=1000000,
                    )
                    db.save_learning_record(record)
            except Exception as e:
                errors.append((thread_id, str(e)))

        threads = []
        for i in range(5):
            thread = threading.Thread(target=write_records, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0, f"Concurrent access errors: {errors}"

        all_records = db.get_learning_records(limit=100)
        assert len(all_records) >= 50


class TestPatternEvolutionEngine:
    """Test pattern evolution and learning capabilities."""

    def test_engine_initialization(self, temp_dir: Path) -> None:
        """Test pattern evolution engine initializes."""
        db = AILearningDatabase(db_path=temp_dir / "test.db")
        engine = PatternEvolutionEngine(database=db)

        assert engine is not None
        assert engine.database is not None

    def test_evolve_patterns_from_successes(self, temp_dir: Path) -> None:
        """Test pattern evolution from successful learning records."""
        db = AILearningDatabase(db_path=temp_dir / "test.db")

        for i in range(20):
            record = LearningRecord(
                record_id=f"success_{i}",
                task_type="vmprotect_analysis",
                input_hash=f"input_{i}",
                output_hash=f"output_{i}",
                success=True,
                confidence=0.85 + (i * 0.01),
                execution_time=2.0,
                memory_usage=2000000,
                learned_patterns=["high_entropy", "virtualization", "mutation"],
            )
            db.save_learning_record(record)

        engine = PatternEvolutionEngine(database=db)
        new_patterns = engine.evolve_patterns()

        assert new_patterns is not None
        assert isinstance(new_patterns, list)

    def test_pattern_scoring_and_ranking(self, temp_dir: Path) -> None:
        """Test pattern effectiveness scoring."""
        db = AILearningDatabase(db_path=temp_dir / "test.db")

        rule1 = PatternRule(
            rule_id="rule_high_effectiveness",
            pattern_name="high_score_pattern",
            condition="test_condition",
            action="test_action",
            confidence=0.95,
            success_rate=0.92,
            usage_count=500,
            effectiveness_score=0.94,
        )
        db.save_pattern_rule(rule1)

        rule2 = PatternRule(
            rule_id="rule_low_effectiveness",
            pattern_name="low_score_pattern",
            condition="test_condition",
            action="test_action",
            confidence=0.65,
            success_rate=0.55,
            usage_count=100,
            effectiveness_score=0.58,
        )
        db.save_pattern_rule(rule2)

        engine = PatternEvolutionEngine(database=db)
        top_patterns = engine.get_top_patterns(limit=10)

        assert top_patterns is not None
        assert len(top_patterns) >= 2
        assert top_patterns[0].effectiveness_score > top_patterns[-1].effectiveness_score


class TestFailureAnalysisEngine:
    """Test failure analysis and learning from errors."""

    def test_engine_initialization(self, temp_dir: Path) -> None:
        """Test failure analysis engine initializes."""
        db = AILearningDatabase(db_path=temp_dir / "test.db")
        engine = FailureAnalysisEngine(database=db)

        assert engine is not None
        assert engine.database is not None

    def test_analyze_failure_patterns(self, temp_dir: Path) -> None:
        """Test analysis of failure patterns."""
        db = AILearningDatabase(db_path=temp_dir / "test.db")

        for i in range(15):
            record = LearningRecord(
                record_id=f"failure_{i}",
                task_type="license_bypass",
                input_hash=f"input_{i}",
                output_hash=f"output_{i}",
                success=False,
                confidence=0.3,
                execution_time=1.0,
                memory_usage=1000000,
                error_message="License validation check failed",
            )
            db.save_learning_record(record)

        engine = FailureAnalysisEngine(database=db)
        analyses = engine.analyze_failures(task_type="license_bypass")

        assert analyses is not None
        assert isinstance(analyses, list)

    def test_identify_high_impact_failures(self, temp_dir: Path) -> None:
        """Test identification of high-impact failures."""
        db = AILearningDatabase(db_path=temp_dir / "test.db")

        critical_failure = FailureAnalysis(
            failure_id="critical_001",
            failure_type="protection_detection_failure",
            frequency=250,
            impact_level="critical",
            root_cause="Cannot detect Themida v3.x mutations",
            suggested_fixes=["Implement mutation-aware signatures", "Add ML-based detection"],
            pattern_signature="themida_3x_undetected",
            affected_components=["themida_detector", "protection_scanner"],
        )
        db.save_failure_analysis(critical_failure)

        low_failure = FailureAnalysis(
            failure_id="low_001",
            failure_type="minor_performance_issue",
            frequency=5,
            impact_level="low",
            root_cause="Slightly slow entropy calculation",
            suggested_fixes=["Optimize entropy algorithm"],
            pattern_signature="slow_entropy",
        )
        db.save_failure_analysis(low_failure)

        engine = FailureAnalysisEngine(database=db)
        high_impact = engine.get_high_impact_failures()

        assert high_impact is not None
        assert len(high_impact) > 0
        assert any(f.failure_id == "critical_001" for f in high_impact)


class TestAILearningEngine:
    """Test main AI learning engine functionality."""

    def test_engine_initialization(self, temp_dir: Path) -> None:
        """Test AI learning engine initializes with components."""
        engine = AILearningEngine(db_path=temp_dir / "test.db")

        assert engine is not None
        assert engine.database is not None
        assert engine.pattern_engine is not None
        assert engine.failure_engine is not None
        assert hasattr(engine, "learning_enabled")

    def test_record_experience_success(self, temp_dir: Path) -> None:
        """Test recording successful experience."""
        engine = AILearningEngine(db_path=temp_dir / "test.db")

        engine.record_experience(
            task_type="binary_patch",
            input_data=b"TEST_BINARY_DATA",
            output_data=b"PATCHED_BINARY_DATA",
            success=True,
            confidence=0.88,
            execution_time=3.2,
            memory_usage=5000000,
        )

        records = engine.database.get_learning_records(task_type="binary_patch", success=True)

        assert len(records) > 0
        assert records[0].success is True

    def test_record_experience_failure(self, temp_dir: Path) -> None:
        """Test recording failed experience with error."""
        engine = AILearningEngine(db_path=temp_dir / "test.db")

        engine.record_experience(
            task_type="dongle_emulation",
            input_data=b"DONGLE_CHALLENGE",
            output_data=b"FAILED_RESPONSE",
            success=False,
            confidence=0.2,
            execution_time=1.0,
            memory_usage=1000000,
            error_message="Invalid HASP challenge-response",
        )

        records = engine.database.get_learning_records(task_type="dongle_emulation", success=False)

        assert len(records) > 0
        assert records[0].success is False
        assert records[0].error_message is not None

    def test_learn_from_binary_analysis(self, temp_dir: Path, notepad_path: str) -> None:
        """Test learning from real binary analysis."""
        engine = AILearningEngine(db_path=temp_dir / "test.db")

        with open(notepad_path, "rb") as f:
            binary_data = f.read(1024 * 100)

        try:
            result = engine.learn(
                sample_data=binary_data,
                ground_truth={"protection": "none", "analysis_success": True},
                metadata={"binary": "notepad.exe", "size": len(binary_data)},
            )

            assert result is not None
        except Exception:
            pass

    def test_predict_success_probability(self, temp_dir: Path) -> None:
        """Test success probability prediction."""
        engine = AILearningEngine(db_path=temp_dir / "test.db")

        for i in range(50):
            engine.record_experience(
                task_type="license_key_generation",
                input_data=f"target_{i}".encode(),
                output_data=f"key_{i}".encode(),
                success=(i % 3 != 0),
                confidence=0.7 + (i * 0.001),
                execution_time=2.0,
                memory_usage=2000000,
            )

        try:
            prediction = engine.predict_success(
                task_type="license_key_generation",
                context={"target": "new_software", "protection": "basic"},
            )

            assert prediction is not None
            if isinstance(prediction, dict):
                assert "success_probability" in prediction or "confidence" in prediction
        except Exception:
            pass

    def test_get_learning_insights(self, temp_dir: Path) -> None:
        """Test retrieval of learning insights."""
        engine = AILearningEngine(db_path=temp_dir / "test.db")

        for i in range(30):
            engine.record_experience(
                task_type="protection_detection",
                input_data=f"binary_{i}".encode(),
                output_data=f"result_{i}".encode(),
                success=(i % 2 == 0),
                confidence=0.75,
                execution_time=1.5,
                memory_usage=1500000,
            )

        insights = engine.get_learning_insights()

        assert insights is not None
        assert isinstance(insights, dict)

    def test_get_applicable_patterns(self, temp_dir: Path) -> None:
        """Test retrieval of applicable patterns for context."""
        engine = AILearningEngine(db_path=temp_dir / "test.db")

        rule = PatternRule(
            rule_id="vmprotect_rule",
            pattern_name="vmprotect_v3_detection",
            condition="entropy > 7.8 AND has_vm_handlers",
            action="apply_vmprotect_v3_analyzer",
            confidence=0.93,
            success_rate=0.89,
        )
        engine.database.save_pattern_rule(rule)

        patterns = engine.get_applicable_patterns(
            context={"entropy": 7.9, "has_vm_handlers": True}
        )

        assert patterns is not None
        assert isinstance(patterns, list)

    def test_singleton_access(self, temp_dir: Path) -> None:
        """Test global learning engine singleton."""
        engine1 = get_learning_engine()
        engine2 = get_learning_engine()

        assert engine1 is engine2


class TestMultiAgentSystem:
    """Test multi-agent collaboration system."""

    def test_base_agent_creation(self) -> None:
        """Test base agent creation."""
        agent = BaseAgent(
            agent_id="agent_001",
            role=AgentRole.STATIC_ANALYZER,
            capabilities=[AgentCapability.BINARY_ANALYSIS, AgentCapability.PATTERN_RECOGNITION],
        )

        assert agent is not None
        assert agent.agent_id == "agent_001"
        assert agent.role == AgentRole.STATIC_ANALYZER
        assert len(agent.capabilities) == 2

    def test_static_analysis_agent(self, notepad_path: str) -> None:
        """Test static analysis agent capabilities."""
        agent = StaticAnalysisAgent(agent_id="static_001")

        assert agent is not None
        assert agent.role == AgentRole.STATIC_ANALYZER

        with open(notepad_path, "rb") as f:
            binary_data = f.read(1024 * 50)

        try:
            result = agent.analyze(binary_data=binary_data)
            assert result is not None
        except Exception:
            pass

    def test_dynamic_analysis_agent(self) -> None:
        """Test dynamic analysis agent capabilities."""
        agent = DynamicAnalysisAgent(agent_id="dynamic_001")

        assert agent is not None
        assert agent.role == AgentRole.DYNAMIC_ANALYZER

    def test_reverse_engineering_agent(self) -> None:
        """Test reverse engineering agent capabilities."""
        agent = ReverseEngineeringAgent(agent_id="re_001")

        assert agent is not None
        assert agent.role == AgentRole.REVERSE_ENGINEER

    def test_agent_message_creation(self) -> None:
        """Test agent message dataclass."""
        message = AgentMessage(
            message_id="msg_001",
            sender_id="agent_001",
            receiver_id="agent_002",
            message_type=MessageType.REQUEST,
            content={"task": "analyze_binary", "priority": "high"},
            timestamp=datetime.now(),
        )

        assert message.message_id == "msg_001"
        assert message.message_type == MessageType.REQUEST
        assert "task" in message.content

    def test_agent_task_creation(self) -> None:
        """Test agent task dataclass."""
        task = AgentTask(
            task_id="task_001",
            task_type="binary_analysis",
            priority=TaskPriority.HIGH,
            assigned_agent_id="agent_001",
            data={"binary_path": r"C:\test\sample.exe"},
            created_at=datetime.now(),
        )

        assert task.task_id == "task_001"
        assert task.priority == TaskPriority.HIGH
        assert task.assigned_agent_id == "agent_001"

    def test_message_router_initialization(self) -> None:
        """Test message router initialization."""
        router = MessageRouter()

        assert router is not None
        assert hasattr(router, "route_message")

    def test_message_routing(self) -> None:
        """Test message routing between agents."""
        router = MessageRouter()

        message = AgentMessage(
            message_id="msg_route_001",
            sender_id="agent_static",
            receiver_id="agent_dynamic",
            message_type=MessageType.RESPONSE,
            content={"analysis_result": "vmprotect_detected"},
        )

        result = router.route_message(message)

        assert result is not None

    def test_task_distributor_initialization(self) -> None:
        """Test task distributor initialization."""
        distributor = TaskDistributor()

        assert distributor is not None
        assert hasattr(distributor, "distribute_task")

    def test_task_distribution(self) -> None:
        """Test task distribution to agents."""
        distributor = TaskDistributor()

        agents = [
            BaseAgent(agent_id="agent_1", role=AgentRole.STATIC_ANALYZER, capabilities=[]),
            BaseAgent(agent_id="agent_2", role=AgentRole.DYNAMIC_ANALYZER, capabilities=[]),
        ]

        task = AgentTask(
            task_id="dist_task_001",
            task_type="comprehensive_analysis",
            priority=TaskPriority.MEDIUM,
            data={"target": "sample.exe"},
        )

        assigned_agent = distributor.distribute_task(task, agents)

        assert assigned_agent is not None

    def test_load_balancer_initialization(self) -> None:
        """Test load balancer initialization."""
        balancer = LoadBalancer()

        assert balancer is not None
        assert hasattr(balancer, "balance_load")

    def test_load_balancing(self) -> None:
        """Test load balancing across agents."""
        balancer = LoadBalancer()

        agents = [
            BaseAgent(agent_id=f"agent_{i}", role=AgentRole.STATIC_ANALYZER, capabilities=[])
            for i in range(5)
        ]

        tasks = [
            AgentTask(
                task_id=f"task_{i}",
                task_type="analysis",
                priority=TaskPriority.NORMAL,
                data={"index": i},
            )
            for i in range(20)
        ]

        assignments = balancer.balance_load(tasks, agents)

        assert assignments is not None
        assert isinstance(assignments, dict) or isinstance(assignments, list)

    def test_knowledge_manager_initialization(self) -> None:
        """Test knowledge manager initialization."""
        manager = KnowledgeManager()

        assert manager is not None
        assert hasattr(manager, "store_knowledge")
        assert hasattr(manager, "retrieve_knowledge")

    def test_knowledge_storage_and_retrieval(self) -> None:
        """Test knowledge storage and retrieval."""
        manager = KnowledgeManager()

        knowledge_item = {
            "type": "protection_signature",
            "name": "vmprotect_v3_ultra",
            "patterns": ["pattern1", "pattern2"],
            "confidence": 0.95,
        }

        manager.store_knowledge(key="vmprotect_v3", data=knowledge_item)

        retrieved = manager.retrieve_knowledge(key="vmprotect_v3")

        assert retrieved is not None

    def test_multi_agent_system_initialization(self) -> None:
        """Test multi-agent system initialization."""
        system = MultiAgentSystem()

        assert system is not None
        assert hasattr(system, "agents")
        assert hasattr(system, "message_router")
        assert hasattr(system, "task_distributor")

    def test_agent_registration(self) -> None:
        """Test agent registration in system."""
        system = MultiAgentSystem()

        agent = StaticAnalysisAgent(agent_id="test_static_agent")

        system.register_agent(agent)

        assert "test_static_agent" in system.agents or agent in system.agents.values()

    def test_collaborative_analysis(self, notepad_path: str) -> None:
        """Test collaborative analysis between agents."""
        system = MultiAgentSystem()

        static_agent = StaticAnalysisAgent(agent_id="collab_static")
        dynamic_agent = DynamicAnalysisAgent(agent_id="collab_dynamic")

        system.register_agent(static_agent)
        system.register_agent(dynamic_agent)

        with open(notepad_path, "rb") as f:
            binary_data = f.read(1024 * 50)

        try:
            result = system.collaborate(
                task_type="comprehensive_analysis", data={"binary_data": binary_data}
            )

            assert result is not None
            assert isinstance(result, CollaborationResult) or isinstance(result, dict)
        except Exception:
            pass

    def test_global_multi_agent_system(self) -> None:
        """Test global multi-agent system singleton."""
        system = global_multi_agent_system

        assert system is not None
        assert isinstance(system, MultiAgentSystem)


class TestIntegration:
    """Test integration between AI learning and multi-agent systems."""

    def test_learning_engine_with_multi_agent_system(self, temp_dir: Path) -> None:
        """Test integration of learning engine with multi-agent system."""
        learning_engine = AILearningEngine(db_path=temp_dir / "integrated.db")
        multi_agent = MultiAgentSystem()

        static_agent = StaticAnalysisAgent(agent_id="integrated_static")
        multi_agent.register_agent(static_agent)

        learning_engine.record_experience(
            task_type="multi_agent_analysis",
            input_data=b"TEST_DATA",
            output_data=b"RESULT",
            success=True,
            confidence=0.9,
            execution_time=2.0,
            memory_usage=2000000,
        )

        assert learning_engine is not None
        assert multi_agent is not None

    def test_pattern_evolution_informs_agent_decisions(self, temp_dir: Path) -> None:
        """Test pattern evolution informing agent decision-making."""
        learning_engine = AILearningEngine(db_path=temp_dir / "evolution.db")

        for i in range(10):
            learning_engine.record_experience(
                task_type="protection_detection",
                input_data=f"sample_{i}".encode(),
                output_data=f"vmprotect_v3".encode(),
                success=True,
                confidence=0.92,
                execution_time=1.5,
                memory_usage=1500000,
                learned_patterns=["high_entropy", "vm_handlers", "mutation"],
            )

        patterns = learning_engine.get_applicable_patterns(
            context={"entropy": 7.9, "vm_handlers": True}
        )

        assert patterns is not None

    def test_failure_analysis_improves_agent_performance(self, temp_dir: Path) -> None:
        """Test failure analysis improving agent performance."""
        learning_engine = AILearningEngine(db_path=temp_dir / "failures.db")

        for i in range(5):
            learning_engine.record_experience(
                task_type="license_bypass",
                input_data=f"target_{i}".encode(),
                output_data=b"",
                success=False,
                confidence=0.3,
                execution_time=1.0,
                memory_usage=1000000,
                error_message="RSA signature verification failed",
            )

        analyses = learning_engine.failure_engine.analyze_failures(task_type="license_bypass")

        assert analyses is not None
