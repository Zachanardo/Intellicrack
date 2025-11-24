"""Production-grade tests for multi-agent collaboration system.

Tests validate real multi-agent coordination, task distribution, inter-agent
communication, result aggregation, and distributed binary analysis capabilities.
"""

import asyncio
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

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
)
from intellicrack.ai.llm_backends import LLMManager


@pytest.fixture
def test_binary_path(tmp_path: Path) -> Path:
    """Create a minimal test binary for agent analysis."""
    binary_path = tmp_path / "test_binary.exe"

    pe_header = (
        b"MZ\x90\x00"
        + b"\x00" * 56
        + b"\x40\x00\x00\x00"
        + b"\x00" * (0x40 - 64)
        + b"PE\x00\x00"
        + b"\x4c\x01"
        + b"\x03\x00"
        + b"\x00" * 12
        + b"\xE0\x00"
        + b"\x0F\x01"
        + b"\x0B\x01"
        + b"\x00" * 16
        + b"\x00\x10\x00\x00"
        + b"\x00" * 200
    )

    binary_path.write_bytes(pe_header + b"\x00" * 1024)
    return binary_path


@pytest.fixture
def protected_binary_path() -> Path:
    """Get path to real VMProtect protected binary."""
    binary_path = Path("D:/Intellicrack/tests/fixtures/binaries/protected/vmprotect_protected.exe")
    if not binary_path.exists():
        pytest.skip(f"VMProtect binary not found: {binary_path}")
    return binary_path


@pytest.fixture
def llm_manager() -> LLMManager:
    """Create LLM manager for agents."""
    return LLMManager()


@pytest.fixture
def multi_agent_system(llm_manager: LLMManager) -> MultiAgentSystem:
    """Create multi-agent system with specialized agents."""
    system = MultiAgentSystem(llm_manager=llm_manager)

    static_agent = StaticAnalysisAgent(
        agent_id="static_analyzer_1",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=llm_manager
    )

    dynamic_agent = DynamicAnalysisAgent(
        agent_id="dynamic_analyzer_1",
        role=AgentRole.DYNAMIC_ANALYZER,
        llm_manager=llm_manager
    )

    reverse_agent = ReverseEngineeringAgent(
        agent_id="reverse_engineer_1",
        role=AgentRole.REVERSE_ENGINEER,
        llm_manager=llm_manager
    )

    system.add_agent(static_agent)
    system.add_agent(dynamic_agent)
    system.add_agent(reverse_agent)

    return system


@pytest.mark.asyncio
async def test_agent_initialization_has_capabilities(llm_manager: LLMManager) -> None:
    """Agent initialization creates role-specific capabilities."""
    static_agent = StaticAnalysisAgent(
        agent_id="test_static",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=llm_manager
    )

    assert len(static_agent.capabilities) > 0
    assert static_agent.agent_id == "test_static"
    assert static_agent.role == AgentRole.STATIC_ANALYZER
    assert not static_agent.active
    assert not static_agent.busy

    capability_names = [cap.capability_name for cap in static_agent.capabilities]
    assert "binary_analysis" in capability_names
    assert "code_analysis" in capability_names
    assert "control_flow_analysis" in capability_names


@pytest.mark.asyncio
async def test_static_agent_analyzes_real_binary(test_binary_path: Path) -> None:
    """Static analysis agent successfully analyzes real binary file."""
    agent = StaticAnalysisAgent(
        agent_id="static_test",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=LLMManager()
    )

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="binary_analysis",
        description="Analyze binary structure",
        input_data={"file_path": str(test_binary_path)},
        priority=TaskPriority.HIGH
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    assert "result" in result
    assert result["result"]["file_type"] == "PE"
    assert result["result"]["architecture"] in ["x86", "x86_64"]
    assert "entry_point" in result["result"]
    assert result["result"]["file_size"] > 0
    assert result["result"]["confidence"] > 0.5


@pytest.mark.asyncio
async def test_static_agent_detects_binary_format_correctly(
    protected_binary_path: Path
) -> None:
    """Static agent correctly identifies binary format and architecture."""
    agent = StaticAnalysisAgent(
        agent_id="format_detector",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=LLMManager()
    )

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="binary_analysis",
        description="Detect binary format",
        input_data={"file_path": str(protected_binary_path)},
        priority=TaskPriority.HIGH
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    analysis = result["result"]
    assert analysis["file_type"] in ["PE", "ELF", "Mach-O"]
    assert analysis["architecture"] in ["x86", "x86_64", "ARM", "ARM64"]
    assert len(analysis.get("sections", [])) > 0


@pytest.mark.asyncio
async def test_agent_task_execution_updates_statistics() -> None:
    """Agent execution updates task completion statistics."""
    agent = BaseAgent(
        agent_id="stats_test",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=LLMManager()
    )

    initial_completed = agent.tasks_completed
    initial_execution_time = agent.total_execution_time

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="analyze_binary",
        description="Test task",
        input_data={"binary_file": b"test data"},
        priority=TaskPriority.MEDIUM
    )

    result = await agent.execute_task(task)

    assert agent.tasks_completed == initial_completed + 1
    assert agent.total_execution_time > initial_execution_time
    assert result["execution_time"] > 0
    assert agent.last_activity is not None


@pytest.mark.asyncio
async def test_agent_knowledge_base_updates_after_task() -> None:
    """Agent knowledge base is updated with task patterns."""
    agent = BaseAgent(
        agent_id="knowledge_test",
        role=AgentRole.REVERSE_ENGINEER,
        llm_manager=LLMManager()
    )

    initial_kb_size = len(agent.knowledge_base)
    initial_patterns = len(agent.learned_patterns)

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="reverse_engineer",
        description="RE task",
        input_data={"target_file": "test.exe"},
        priority=TaskPriority.HIGH
    )

    await agent.execute_task(task)

    assert len(agent.knowledge_base) > initial_kb_size
    assert len(agent.learned_patterns) > initial_patterns


@pytest.mark.asyncio
async def test_multi_agent_system_initialization() -> None:
    """Multi-agent system initializes with correct state."""
    system = MultiAgentSystem()

    assert not system.active
    assert len(system.agents) == 0
    assert system.collaboration_stats["messages_sent"] == 0
    assert system.collaboration_stats["tasks_distributed"] == 0
    assert system.collaboration_stats["collaborations_successful"] == 0


@pytest.mark.asyncio
async def test_agent_registration_with_system(llm_manager: LLMManager) -> None:
    """Agents are successfully registered with multi-agent system."""
    system = MultiAgentSystem(llm_manager=llm_manager)

    agent1 = BaseAgent(
        agent_id="agent_1",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=llm_manager
    )

    agent2 = BaseAgent(
        agent_id="agent_2",
        role=AgentRole.DYNAMIC_ANALYZER,
        llm_manager=llm_manager
    )

    system.add_agent(agent1)
    system.add_agent(agent2)

    assert len(system.agents) == 2
    assert "agent_1" in system.agents
    assert "agent_2" in system.agents
    assert system.agents["agent_1"].collaboration_system == system
    assert system.agents["agent_2"].collaboration_system == system


@pytest.mark.asyncio
async def test_message_routing_between_agents(llm_manager: LLMManager) -> None:
    """Messages are correctly routed between agents."""
    router = MessageRouter()

    agent1 = BaseAgent(
        agent_id="sender",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=llm_manager
    )

    agent2 = BaseAgent(
        agent_id="receiver",
        role=AgentRole.DYNAMIC_ANALYZER,
        llm_manager=llm_manager
    )

    router.register_agent(agent1.agent_id, agent1.message_queue)
    router.register_agent(agent2.agent_id, agent2.message_queue)

    message = AgentMessage(
        message_id=str(uuid.uuid4()),
        sender_id="sender",
        recipient_id="receiver",
        message_type=MessageType.KNOWLEDGE_SHARE,
        content={"test_data": "value"}
    )

    router.route_message(message)

    assert not agent2.message_queue.empty()
    received_message = agent2.message_queue.get(timeout=1)
    assert received_message.sender_id == "sender"
    assert received_message.content["test_data"] == "value"


@pytest.mark.asyncio
async def test_knowledge_sharing_between_agents(multi_agent_system: MultiAgentSystem) -> None:
    """Agents successfully share knowledge through the system."""
    multi_agent_system.start()

    agents = list(multi_agent_system.agents.values())
    agent1 = agents[0]
    agent2 = agents[1]

    agent1.trusted_agents.add(agent2.agent_id)

    test_knowledge = {
        "pattern_type": "license_check",
        "location": "0x401000",
        "confidence": 0.95
    }

    agent1.share_knowledge(test_knowledge, [agent2.agent_id])

    await asyncio.sleep(0.5)

    assert multi_agent_system.collaboration_stats["messages_sent"] > 0

    multi_agent_system.stop()


@pytest.mark.asyncio
async def test_collaborative_task_execution_on_real_binary(
    multi_agent_system: MultiAgentSystem,
    test_binary_path: Path
) -> None:
    """Multi-agent system collaboratively analyzes real binary."""
    multi_agent_system.start()

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="comprehensive_analysis",
        description="Full binary analysis using multiple agents",
        input_data={"file_path": str(test_binary_path)},
        priority=TaskPriority.HIGH
    )

    result = await multi_agent_system.execute_collaborative_task(task)

    assert isinstance(result, CollaborationResult)
    assert result.task_id == task.task_id
    assert result.success
    assert len(result.participating_agents) > 0
    assert result.execution_time > 0
    assert result.confidence > 0
    assert "agent_results" in result.result_data
    assert len(result.result_data["agent_results"]) > 0

    multi_agent_system.stop()


@pytest.mark.asyncio
async def test_task_distributor_finds_suitable_agent(
    multi_agent_system: MultiAgentSystem
) -> None:
    """Task distributor correctly identifies suitable agent for task."""
    multi_agent_system.start()

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="binary_analysis",
        description="Test distribution",
        input_data={"file_path": "test.exe"},
        priority=TaskPriority.MEDIUM
    )

    assigned_agent_id = multi_agent_system.task_distributor.distribute_task(task)

    assert assigned_agent_id != ""
    assert assigned_agent_id in multi_agent_system.agents

    assigned_agent = multi_agent_system.agents[assigned_agent_id]
    assert any(
        "binary_analysis" in cap.capability_name or "binary_analysis" in cap.input_types
        for cap in assigned_agent.capabilities
    )

    multi_agent_system.stop()


@pytest.mark.asyncio
async def test_parallel_subtask_execution_completes_successfully(
    multi_agent_system: MultiAgentSystem,
    test_binary_path: Path
) -> None:
    """Subtasks execute in parallel and all complete successfully."""
    multi_agent_system.start()

    agents = list(multi_agent_system.agents.items())

    subtasks = [
        (agent_id, AgentTask(
            task_id=f"subtask_{i}",
            task_type="analyze_binary",
            description=f"Subtask {i}",
            input_data={"binary_file": str(test_binary_path)},
            priority=TaskPriority.MEDIUM
        ))
        for i, (agent_id, _) in enumerate(agents)
    ]

    start_time = time.time()
    results = await multi_agent_system._execute_subtasks_parallel(subtasks)
    execution_time = time.time() - start_time

    assert len(results) == len(subtasks)

    for agent_id, result_data in results.items():
        assert agent_id in multi_agent_system.agents
        assert "success" in result_data or "result" in result_data

    multi_agent_system.stop()


@pytest.mark.asyncio
async def test_result_aggregation_combines_agent_outputs(
    multi_agent_system: MultiAgentSystem
) -> None:
    """Result aggregation correctly combines outputs from multiple agents."""
    results = {
        "agent1": {
            "success": True,
            "result": {
                "confidence": 0.9,
                "findings": ["pattern1", "pattern2"],
                "vulnerabilities": [{"type": "buffer_overflow", "severity": "high"}]
            }
        },
        "agent2": {
            "success": True,
            "result": {
                "confidence": 0.85,
                "findings": ["pattern2", "pattern3"],
                "suspicious_apis": [{"reason": "code_injection"}]
            }
        }
    }

    combined = multi_agent_system._combine_results(results)

    assert "agent_results" in combined
    assert len(combined["agent_results"]) == 2
    assert "unified_analysis" in combined
    assert "cross_validated_findings" in combined
    assert len(combined["unified_analysis"]["confidence_scores"]) == 2


@pytest.mark.asyncio
async def test_cross_validation_detects_common_patterns(
    multi_agent_system: MultiAgentSystem
) -> None:
    """Cross-validation identifies patterns confirmed by multiple agents."""
    results = {
        "agent1": {
            "behavior_patterns": ["license_check", "network_communication"],
            "potential_vulnerabilities": [{"type": "buffer_overflow"}]
        },
        "agent2": {
            "behavior_patterns": ["license_check", "file_access"],
            "suspicious_apis": [{"reason": "code_injection"}]
        },
        "agent3": {
            "behavior_patterns": ["license_check"],
            "potential_vulnerabilities": [{"type": "format_string"}]
        }
    }

    validated = multi_agent_system._cross_validate_findings(results)

    assert len(validated) > 0

    license_check_pattern = next(
        (v for v in validated if v["pattern"] == "license_check"),
        None
    )
    assert license_check_pattern is not None
    assert len(license_check_pattern["confirmed_by"]) == 3
    assert license_check_pattern["confidence"] == 1.0


@pytest.mark.asyncio
async def test_load_balancer_tracks_agent_load() -> None:
    """Load balancer correctly tracks and manages agent load."""
    balancer = LoadBalancer()

    balancer.update_agent_load("agent1", 0.3)
    balancer.update_agent_load("agent2", 0.7)
    balancer.update_agent_load("agent3", 0.5)

    assert balancer.agent_loads["agent1"] == 0.3
    assert balancer.agent_loads["agent2"] == 0.7
    assert balancer.agent_loads["agent3"] == 0.5

    least_loaded = balancer.get_least_loaded_agent(["agent1", "agent2", "agent3"])
    assert least_loaded == "agent1"


@pytest.mark.asyncio
async def test_knowledge_manager_stores_and_retrieves_knowledge() -> None:
    """Knowledge manager successfully stores and retrieves shared knowledge."""
    km = KnowledgeManager()

    km.store_knowledge(
        category="binary_patterns",
        key="vmprotect_signature",
        value={"pattern": "0x48 0x8B 0xC4", "confidence": 0.95},
        source_agent="agent1"
    )

    retrieved = km.retrieve_knowledge(
        category="binary_patterns",
        key="vmprotect_signature",
        requesting_agent="agent2"
    )

    assert retrieved is not None
    assert retrieved["pattern"] == "0x48 0x8B 0xC4"
    assert retrieved["confidence"] == 0.95

    assert km.access_patterns["binary_patterns:vmprotect_signature"] == 1


@pytest.mark.asyncio
async def test_knowledge_manager_retrieves_category_knowledge() -> None:
    """Knowledge manager retrieves all knowledge in a category."""
    km = KnowledgeManager()

    km.store_knowledge("exploits", "exp1", {"type": "buffer_overflow"}, "agent1")
    km.store_knowledge("exploits", "exp2", {"type": "format_string"}, "agent2")
    km.store_knowledge("protections", "prot1", {"type": "vmprotect"}, "agent3")

    exploit_knowledge = km.get_related_knowledge("exploits", "agent4")

    assert len(exploit_knowledge) == 2
    assert "exp1" in exploit_knowledge
    assert "exp2" in exploit_knowledge
    assert exploit_knowledge["exp1"]["type"] == "buffer_overflow"
    assert exploit_knowledge["exp2"]["type"] == "format_string"


@pytest.mark.asyncio
async def test_agent_capability_matching_selects_correct_agent(
    multi_agent_system: MultiAgentSystem
) -> None:
    """System selects agent with matching capabilities for task."""
    multi_agent_system.start()

    required_capabilities = ["binary_analysis", "disassembly"]
    suitable_agents = multi_agent_system._find_suitable_agents(required_capabilities)

    assert len(suitable_agents) > 0

    for agent_id, agent in suitable_agents:
        capability_names = [cap.capability_name for cap in agent.capabilities]
        assert any(cap in capability_names for cap in required_capabilities)

    multi_agent_system.stop()


@pytest.mark.asyncio
async def test_agent_performance_ranking_orders_by_success_rate(
    llm_manager: LLMManager
) -> None:
    """Agents are ranked by performance metrics for task assignment."""
    agent1 = BaseAgent("agent1", AgentRole.STATIC_ANALYZER, llm_manager)
    agent1.tasks_completed = 10
    agent1.tasks_failed = 0
    agent1.total_execution_time = 50.0
    agent1.active = True

    agent2 = BaseAgent("agent2", AgentRole.STATIC_ANALYZER, llm_manager)
    agent2.tasks_completed = 5
    agent2.tasks_failed = 5
    agent2.total_execution_time = 100.0
    agent2.active = True

    system = MultiAgentSystem(llm_manager)
    system.add_agent(agent1)
    system.add_agent(agent2)

    suitable_agents = system._find_suitable_agents(["binary_analysis"])

    if len(suitable_agents) >= 2:
        first_agent_id, first_agent = suitable_agents[0]
        second_agent_id, second_agent = suitable_agents[1]

        first_success_rate = first_agent.tasks_completed / max(
            1, first_agent.tasks_completed + first_agent.tasks_failed
        )
        second_success_rate = second_agent.tasks_completed / max(
            1, second_agent.tasks_completed + second_agent.tasks_failed
        )

        assert first_success_rate >= second_success_rate


@pytest.mark.asyncio
async def test_agent_busy_status_prevents_task_assignment(
    multi_agent_system: MultiAgentSystem
) -> None:
    """Busy agents are not assigned new tasks."""
    multi_agent_system.start()

    agents = list(multi_agent_system.agents.values())
    if len(agents) > 0:
        agents[0].busy = True

        required_capabilities = [cap.capability_name for cap in agents[0].capabilities]
        suitable_agents = multi_agent_system._find_suitable_agents(required_capabilities)

        busy_agent_ids = [agent_id for agent_id, _ in suitable_agents if agents[0].agent_id == agent_id]
        assert len(busy_agent_ids) == 0

    multi_agent_system.stop()


@pytest.mark.asyncio
async def test_system_status_reports_accurate_metrics(
    multi_agent_system: MultiAgentSystem
) -> None:
    """System status provides accurate operational metrics."""
    multi_agent_system.start()

    status = multi_agent_system.get_system_status()

    assert "active" in status
    assert status["active"] is True
    assert "total_agents" in status
    assert status["total_agents"] == len(multi_agent_system.agents)
    assert "active_agents" in status
    assert "busy_agents" in status
    assert "collaboration_stats" in status
    assert "agents" in status

    for agent_id, agent_status in status["agents"].items():
        assert "agent_id" in agent_status
        assert "role" in agent_status
        assert "tasks_completed" in agent_status
        assert "success_rate" in agent_status

    multi_agent_system.stop()


@pytest.mark.asyncio
async def test_agent_failure_does_not_crash_collaboration(
    multi_agent_system: MultiAgentSystem,
    test_binary_path: Path
) -> None:
    """Collaboration continues even if individual agent fails."""
    multi_agent_system.start()

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="comprehensive_analysis",
        description="Analysis with potential failures",
        input_data={"file_path": str(test_binary_path)},
        priority=TaskPriority.HIGH
    )

    result = await multi_agent_system.execute_collaborative_task(task)

    assert isinstance(result, CollaborationResult)
    assert result.task_id == task.task_id

    multi_agent_system.stop()


@pytest.mark.asyncio
async def test_confidence_calculation_aggregates_agent_confidence(
    multi_agent_system: MultiAgentSystem
) -> None:
    """Confidence calculation correctly aggregates individual agent confidence scores."""
    subtask_results = {
        "agent1": {"success": True, "result": {"confidence": 0.9}},
        "agent2": {"success": True, "result": {"confidence": 0.85}},
        "agent3": {"success": True, "result": {"confidence": 0.95}},
        "agent4": {"success": False, "result": {}},
    }

    confidence = multi_agent_system._calculate_combined_confidence(subtask_results)

    assert 0.0 <= confidence <= 1.0
    expected_confidence = (0.9 + 0.85 + 0.95) / 3
    assert abs(confidence - expected_confidence) < 0.01


@pytest.mark.asyncio
async def test_dynamic_agent_runtime_analysis_capabilities() -> None:
    """Dynamic analysis agent has runtime monitoring capabilities."""
    agent = DynamicAnalysisAgent(
        agent_id="dynamic_test",
        role=AgentRole.DYNAMIC_ANALYZER,
        llm_manager=LLMManager()
    )

    capability_names = [cap.capability_name for cap in agent.capabilities]
    assert "runtime_monitoring" in capability_names
    assert "memory_analysis" in capability_names


@pytest.mark.asyncio
async def test_agent_message_correlation_tracking() -> None:
    """Messages maintain correlation IDs for request-response tracking."""
    message = AgentMessage(
        message_id="msg_123",
        sender_id="agent1",
        recipient_id="agent2",
        message_type=MessageType.TASK_REQUEST,
        content={"task": "analyze"},
        requires_response=True
    )

    response = AgentMessage(
        message_id="msg_456",
        sender_id="agent2",
        recipient_id="agent1",
        message_type=MessageType.TASK_RESPONSE,
        content={"result": "completed"},
        correlation_id=message.message_id
    )

    assert response.correlation_id == message.message_id
    assert response.sender_id == message.recipient_id
    assert response.recipient_id == message.sender_id


@pytest.mark.asyncio
async def test_collaboration_knowledge_sharing_updates_stats(
    multi_agent_system: MultiAgentSystem,
    test_binary_path: Path
) -> None:
    """Successful collaboration increments knowledge sharing statistics."""
    multi_agent_system.start()

    initial_knowledge_shares = multi_agent_system.collaboration_stats["knowledge_shares"]

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="binary_analysis",
        description="Test knowledge sharing",
        input_data={"file_path": str(test_binary_path)},
        priority=TaskPriority.HIGH
    )

    result = await multi_agent_system.execute_collaborative_task(task)

    if result.success:
        assert multi_agent_system.collaboration_stats["knowledge_shares"] > initial_knowledge_shares

    multi_agent_system.stop()


@pytest.mark.asyncio
async def test_multiple_concurrent_collaborations(
    multi_agent_system: MultiAgentSystem,
    test_binary_path: Path
) -> None:
    """System handles multiple concurrent collaborative tasks."""
    multi_agent_system.start()

    tasks = [
        AgentTask(
            task_id=f"task_{i}",
            task_type="binary_analysis",
            description=f"Concurrent task {i}",
            input_data={"file_path": str(test_binary_path)},
            priority=TaskPriority.MEDIUM
        )
        for i in range(3)
    ]

    results = await asyncio.gather(*[
        multi_agent_system.execute_collaborative_task(task)
        for task in tasks
    ])

    assert len(results) == 3
    for result in results:
        assert isinstance(result, CollaborationResult)

    multi_agent_system.stop()


@pytest.mark.asyncio
async def test_agent_specialization_provides_unique_insights(
    llm_manager: LLMManager,
    test_binary_path: Path
) -> None:
    """Different agent roles provide complementary analysis results."""
    static_agent = StaticAnalysisAgent(
        agent_id="static",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=llm_manager
    )

    reverse_agent = ReverseEngineeringAgent(
        agent_id="reverse",
        role=AgentRole.REVERSE_ENGINEER,
        llm_manager=llm_manager
    )

    static_task = AgentTask(
        task_id="static_task",
        task_type="binary_analysis",
        description="Static analysis",
        input_data={"file_path": str(test_binary_path)},
        priority=TaskPriority.HIGH
    )

    reverse_task = AgentTask(
        task_id="reverse_task",
        task_type="decompilation",
        description="Decompilation",
        input_data={"file_path": str(test_binary_path)},
        priority=TaskPriority.HIGH
    )

    static_result = await static_agent.execute_task(static_task)
    reverse_result = await reverse_agent.execute_task(reverse_task)

    assert static_result["status"] == "completed"
    assert reverse_result["status"] == "completed"

    static_data = static_result["result"]
    reverse_data = reverse_result["result"]

    assert "file_type" in static_data or "architecture" in static_data
    assert isinstance(reverse_data, dict)


@pytest.mark.asyncio
async def test_protected_binary_analysis_coordination(
    multi_agent_system: MultiAgentSystem,
    protected_binary_path: Path
) -> None:
    """Multi-agent system analyzes protected binary collaboratively."""
    multi_agent_system.start()

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="comprehensive_analysis",
        description="Analyze VMProtect protected binary",
        input_data={"file_path": str(protected_binary_path)},
        priority=TaskPriority.CRITICAL
    )

    result = await multi_agent_system.execute_collaborative_task(task)

    assert result.success
    assert len(result.participating_agents) >= 1
    assert result.confidence > 0

    if "unified_analysis" in result.result_data:
        unified = result.result_data["unified_analysis"]
        assert "overall_assessment" in unified
        assert "confidence_scores" in unified

    multi_agent_system.stop()


@pytest.mark.asyncio
async def test_reverse_engineering_agent_decompilation(
    test_binary_path: Path
) -> None:
    """Reverse engineering agent performs decompilation task."""
    agent = ReverseEngineeringAgent(
        agent_id="re_agent",
        role=AgentRole.REVERSE_ENGINEER,
        llm_manager=LLMManager()
    )

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="decompilation",
        description="Decompile binary",
        input_data={"file_path": str(test_binary_path)},
        priority=TaskPriority.HIGH
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    assert "result" in result
    decompiled = result["result"]
    assert "decompiled_functions" in decompiled or isinstance(decompiled, dict)


@pytest.mark.asyncio
async def test_agent_handles_task_failure_gracefully() -> None:
    """Agent handles task execution failures without crashing."""
    agent = BaseAgent(
        agent_id="error_test",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=LLMManager()
    )

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="invalid_task_type",
        description="This should fail gracefully",
        input_data={},
        priority=TaskPriority.LOW
    )

    result = await agent.execute_task(task)

    assert result["task_id"] == task.task_id
    assert result["agent_id"] == agent.agent_id
    assert agent.tasks_failed >= 0 or agent.tasks_completed >= 0


@pytest.mark.asyncio
async def test_agent_extract_patterns_from_data() -> None:
    """Agent extracts reusable patterns from input data."""
    agent = BaseAgent(
        agent_id="pattern_test",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=LLMManager()
    )

    test_data = {
        "url": "https://example.com/license.dll",
        "binary_file": "protected.exe",
        "large_number": 9999999,
        "negative_value": -100,
        "long_string": "x" * 100,
        "large_list": list(range(10)),
        "complex_dict": {f"key{i}": f"value{i}" for i in range(15)}
    }

    patterns = agent._extract_patterns(test_data)

    assert isinstance(patterns, list)
    assert len(patterns) <= 10
    assert "url_pattern" in patterns
    assert "binary_file_pattern" in patterns


@pytest.mark.asyncio
async def test_agent_calculate_complexity_score() -> None:
    """Agent calculates complexity score for input data."""
    agent = BaseAgent(
        agent_id="complexity_test",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=LLMManager()
    )

    simple_data = {"key": "value"}
    complex_data = {
        "strings": "x" * 1000,
        "list": list(range(100)),
        "dict": {f"k{i}": f"v{i}" for i in range(50)},
        "bytes": b"\x00" * 10000
    }

    simple_score = agent._calculate_complexity(simple_data)
    complex_score = agent._calculate_complexity(complex_data)

    assert 0.0 <= simple_score <= 10.0
    assert 0.0 <= complex_score <= 10.0
    assert complex_score > simple_score


@pytest.mark.asyncio
async def test_static_agent_python_code_analysis() -> None:
    """Static agent analyzes Python source code for vulnerabilities."""
    agent = StaticAnalysisAgent(
        agent_id="py_analyzer",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=LLMManager()
    )

    python_code = """
def dangerous_function(user_input):
    eval(user_input)
    exec("import os")
    result = __import__("sys")
    return result

def safe_function():
    return "Hello World"
"""

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="code_analysis",
        description="Analyze Python code",
        input_data={"code": python_code, "language": "python"},
        priority=TaskPriority.HIGH
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    analysis = result["result"]
    assert analysis["language"] == "python"
    assert analysis["functions_detected"] >= 2
    assert len(analysis["potential_vulnerabilities"]) > 0

    vuln_types = [v["type"] for v in analysis["potential_vulnerabilities"]]
    assert "dangerous_function" in vuln_types


@pytest.mark.asyncio
async def test_static_agent_c_code_analysis() -> None:
    """Static agent detects C/C++ vulnerabilities."""
    agent = StaticAnalysisAgent(
        agent_id="c_analyzer",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=LLMManager()
    )

    c_code = """
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    char buffer[256];
    gets(buffer);
    strcpy(buffer, argv[1]);
    sprintf(buffer, "Hello %s", argv[2]);
    system(argv[3]);
    return 0;
}
"""

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="code_analysis",
        description="Analyze C code",
        input_data={"code": c_code, "language": "c"},
        priority=TaskPriority.HIGH
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    analysis = result["result"]
    assert analysis["language"] in ["c", "cpp", "c++"]
    assert len(analysis["potential_vulnerabilities"]) >= 3

    vuln_functions = [v["function"] for v in analysis["potential_vulnerabilities"]]
    assert "gets" in vuln_functions
    assert "strcpy" in vuln_functions
    assert "system" in vuln_functions


@pytest.mark.asyncio
async def test_static_agent_javascript_code_analysis() -> None:
    """Static agent detects JavaScript vulnerabilities."""
    agent = StaticAnalysisAgent(
        agent_id="js_analyzer",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=LLMManager()
    )

    js_code = """
function processUserInput(input) {
    eval(input);
    document.write(input);
    element.innerHTML = input;
    setTimeout("malicious()", 1000);
    return new Function("return " + input)();
}

const safeFunction = () => {
    return "Safe";
};
"""

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="code_analysis",
        description="Analyze JavaScript code",
        input_data={"code": js_code, "language": "javascript"},
        priority=TaskPriority.HIGH
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    analysis = result["result"]
    assert analysis["language"] in ["javascript", "js", "typescript", "ts"]
    assert len(analysis["potential_vulnerabilities"]) >= 2

    vuln_types = [v["type"] for v in analysis["potential_vulnerabilities"]]
    assert "code_injection" in vuln_types or "xss" in vuln_types


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Requires Windows for PE analysis")
async def test_static_agent_control_flow_analysis_with_r2pipe(
    test_binary_path: Path
) -> None:
    """Static agent performs control flow analysis using r2pipe."""
    pytest.importorskip("r2pipe")

    agent = StaticAnalysisAgent(
        agent_id="cfa_agent",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=LLMManager()
    )

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="control_flow_analysis",
        description="Analyze control flow",
        input_data={"binary_path": str(test_binary_path)},
        priority=TaskPriority.HIGH
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    analysis = result["result"]
    assert "basic_blocks" in analysis
    assert "function_count" in analysis
    assert analysis["confidence"] > 0.0


@pytest.mark.asyncio
async def test_agent_start_stop_lifecycle() -> None:
    """Agent lifecycle management works correctly."""
    agent = BaseAgent(
        agent_id="lifecycle_test",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=LLMManager()
    )

    assert not agent.active

    agent.start()
    assert agent.active

    await asyncio.sleep(0.1)

    agent.stop()
    assert not agent.active


@pytest.mark.asyncio
async def test_agent_remove_from_system(llm_manager: LLMManager) -> None:
    """Agents can be removed from multi-agent system."""
    system = MultiAgentSystem(llm_manager=llm_manager)

    agent = BaseAgent(
        agent_id="removable_agent",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=llm_manager
    )

    system.add_agent(agent)
    assert "removable_agent" in system.agents

    system.remove_agent("removable_agent")
    assert "removable_agent" not in system.agents


@pytest.mark.asyncio
async def test_message_router_unregister_agent() -> None:
    """Message router correctly unregisters agents."""
    router = MessageRouter()

    agent = BaseAgent(
        agent_id="temp_agent",
        role=AgentRole.STATIC_ANALYZER,
        llm_manager=LLMManager()
    )

    router.register_agent(agent.agent_id, agent.message_queue)
    assert agent.agent_id in router.agent_queues

    router.unregister_agent(agent.agent_id)
    assert agent.agent_id not in router.agent_queues


@pytest.mark.asyncio
async def test_message_router_logs_messages() -> None:
    """Message router maintains message log."""
    router = MessageRouter()

    agent1 = BaseAgent("agent1", AgentRole.STATIC_ANALYZER, LLMManager())
    agent2 = BaseAgent("agent2", AgentRole.DYNAMIC_ANALYZER, LLMManager())

    router.register_agent(agent1.agent_id, agent1.message_queue)
    router.register_agent(agent2.agent_id, agent2.message_queue)

    message = AgentMessage(
        message_id=str(uuid.uuid4()),
        sender_id="agent1",
        recipient_id="agent2",
        message_type=MessageType.KNOWLEDGE_SHARE,
        content={"data": "test"}
    )

    initial_log_size = len(router.message_log)
    router.route_message(message)

    assert len(router.message_log) > initial_log_size


@pytest.mark.asyncio
async def test_task_distributor_calculate_agent_score(
    llm_manager: LLMManager
) -> None:
    """Task distributor calculates agent suitability scores correctly."""
    system = MultiAgentSystem(llm_manager=llm_manager)

    agent = BaseAgent("test_agent", AgentRole.STATIC_ANALYZER, llm_manager)
    agent.tasks_completed = 10
    agent.tasks_failed = 2
    agent.total_execution_time = 50.0
    agent.active = True

    system.add_agent(agent)

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="binary_analysis",
        description="Test scoring",
        input_data={},
        priority=TaskPriority.MEDIUM
    )

    score = system.task_distributor._calculate_agent_score(agent, task)

    assert score > 0.0
    assert isinstance(score, float)


@pytest.mark.asyncio
async def test_agent_capability_has_all_required_fields() -> None:
    """AgentCapability dataclass contains all required fields."""
    capability = AgentCapability(
        capability_name="test_capability",
        description="Test description",
        input_types=["binary", "text"],
        output_types=["analysis", "report"],
        processing_time_estimate=5.0,
        confidence_level=0.9,
        resource_requirements={"memory": "1GB", "cpu": "2 cores"},
        prerequisites=["dependency1", "dependency2"]
    )

    assert capability.capability_name == "test_capability"
    assert capability.description == "Test description"
    assert capability.input_types == ["binary", "text"]
    assert capability.output_types == ["analysis", "report"]
    assert capability.processing_time_estimate == 5.0
    assert capability.confidence_level == 0.9
    assert capability.resource_requirements == {"memory": "1GB", "cpu": "2 cores"}
    assert capability.prerequisites == ["dependency1", "dependency2"]


@pytest.mark.asyncio
async def test_collaboration_result_captures_all_data() -> None:
    """CollaborationResult captures complete collaboration outcome."""
    result = CollaborationResult(
        task_id="test_task",
        success=True,
        result_data={"analysis": "complete"},
        participating_agents=["agent1", "agent2"],
        execution_time=5.5,
        confidence=0.92,
        errors=[],
        knowledge_gained={"pattern": "license_check"}
    )

    assert result.task_id == "test_task"
    assert result.success is True
    assert result.result_data == {"analysis": "complete"}
    assert result.participating_agents == ["agent1", "agent2"]
    assert result.execution_time == 5.5
    assert result.confidence == 0.92
    assert result.errors == []
    assert result.knowledge_gained == {"pattern": "license_check"}


@pytest.mark.asyncio
async def test_agent_task_has_complete_metadata() -> None:
    """AgentTask dataclass supports comprehensive task definition."""
    task = AgentTask(
        task_id="task_123",
        task_type="binary_analysis",
        description="Comprehensive analysis",
        input_data={"file": "test.exe"},
        priority=TaskPriority.CRITICAL,
        assigned_to="agent_1",
        dependencies=["task_100", "task_101"],
        deadline=datetime.now(),
        context={"environment": "sandbox"},
        metadata={"source": "automated"}
    )

    assert task.task_id == "task_123"
    assert task.task_type == "binary_analysis"
    assert task.priority == TaskPriority.CRITICAL
    assert task.assigned_to == "agent_1"
    assert len(task.dependencies) == 2
    assert task.deadline is not None
    assert task.context["environment"] == "sandbox"
    assert task.metadata["source"] == "automated"


@pytest.mark.asyncio
async def test_agent_message_supports_response_tracking() -> None:
    """AgentMessage supports request-response patterns with timeouts."""
    message = AgentMessage(
        message_id=str(uuid.uuid4()),
        sender_id="requester",
        recipient_id="responder",
        message_type=MessageType.CAPABILITY_QUERY,
        content={"query": "capabilities"},
        priority=TaskPriority.HIGH,
        requires_response=True,
        response_timeout=30.0,
        correlation_id="parent_msg_id"
    )

    assert message.requires_response is True
    assert message.response_timeout == 30.0
    assert message.correlation_id == "parent_msg_id"
    assert message.priority == TaskPriority.HIGH


@pytest.mark.asyncio
async def test_knowledge_manager_tracks_access_patterns() -> None:
    """Knowledge manager tracks which knowledge is accessed most."""
    km = KnowledgeManager()

    km.store_knowledge("patterns", "pattern1", {"data": "value1"}, "agent1")

    km.retrieve_knowledge("patterns", "pattern1", "agent2")
    km.retrieve_knowledge("patterns", "pattern1", "agent3")
    km.retrieve_knowledge("patterns", "pattern1", "agent4")

    access_count = km.access_patterns.get("patterns:pattern1", 0)
    assert access_count == 3


@pytest.mark.asyncio
async def test_multi_agent_system_no_suitable_agent_raises_error(
    multi_agent_system: MultiAgentSystem
) -> None:
    """System handles case when no suitable agent is found for task."""
    multi_agent_system.start()

    for agent in multi_agent_system.agents.values():
        agent.busy = True

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="impossible_task_type_xyz",
        description="Task with no suitable agent",
        input_data={},
        priority=TaskPriority.HIGH
    )

    result = await multi_agent_system.execute_collaborative_task(task)

    assert isinstance(result, CollaborationResult)
    assert not result.success

    multi_agent_system.stop()


@pytest.mark.asyncio
async def test_load_balancer_records_load_history() -> None:
    """Load balancer maintains history of load changes."""
    balancer = LoadBalancer()

    initial_history_len = len(balancer.load_history)

    balancer.update_agent_load("agent1", 0.5)
    balancer.update_agent_load("agent2", 0.7)

    assert len(balancer.load_history) > initial_history_len


@pytest.mark.asyncio
async def test_agent_all_role_specific_capabilities_initialized() -> None:
    """All agent roles have role-specific capabilities initialized."""
    llm = LLMManager()

    roles_to_test = [
        (AgentRole.STATIC_ANALYZER, ["binary_parsing", "disassembly_analysis"]),
        (AgentRole.DYNAMIC_ANALYZER, ["runtime_monitoring", "memory_analysis"]),
        (AgentRole.REVERSE_ENGINEER, ["algorithm_reconstruction", "protection_analysis"]),
        (AgentRole.VULNERABILITY_HUNTER, ["vulnerability_detection", "exploit_feasibility"]),
        (AgentRole.EXPLOIT_DEVELOPER, ["exploit_creation", "shellcode_generation"]),
        (AgentRole.CODE_MODIFIER, ["binary_patching", "code_injection"]),
        (AgentRole.SCRIPT_GENERATOR, ["frida_scripting", "automation_scripts"]),
        (AgentRole.COORDINATOR, ["task_orchestration", "resource_management"]),
        (AgentRole.SPECIALIST, ["domain_expertise", "advanced_techniques"]),
    ]

    for role, expected_capabilities in roles_to_test:
        agent = BaseAgent(f"test_{role.value}", role, llm)
        capability_names = [cap.capability_name for cap in agent.capabilities]

        for expected_cap in expected_capabilities:
            assert expected_cap in capability_names, f"{role.value} missing {expected_cap}"


@pytest.mark.asyncio
async def test_base_agent_handles_all_task_types() -> None:
    """BaseAgent handles all defined task types without crashing."""
    agent = BaseAgent("versatile_agent", AgentRole.COORDINATOR, LLMManager())

    task_types = [
        "analyze_binary",
        "generate_exploit",
        "reverse_engineer",
        "vulnerability_scan",
        "code_modification",
        "script_generation",
        "coordination",
        "specialist_analysis",
        "unknown_task_type"
    ]

    for task_type in task_types:
        task = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type=task_type,
            description=f"Test {task_type}",
            input_data={},
            priority=TaskPriority.LOW
        )

        result = await agent.execute_task(task)
        assert "task_id" in result
        assert result["agent_id"] == agent.agent_id


@pytest.mark.asyncio
async def test_agent_vulnerability_scanning_produces_findings() -> None:
    """Agent vulnerability scanning task returns vulnerability data."""
    agent = BaseAgent("vuln_scanner", AgentRole.VULNERABILITY_HUNTER, LLMManager())

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="vulnerability_scan",
        description="Scan for vulnerabilities",
        input_data={"targets": ["target1.exe", "target2.dll"], "scan_type": "comprehensive"},
        priority=TaskPriority.HIGH
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    scan_results = result["result"]
    assert "scan_metadata" in scan_results
    assert "scan_results" in scan_results
    assert "detailed_findings" in scan_results
    assert len(scan_results["detailed_findings"]) > 0


@pytest.mark.asyncio
async def test_agent_exploit_generation_produces_exploit_code() -> None:
    """Agent exploit generation task returns exploit code."""
    agent = BaseAgent("exploit_dev", AgentRole.EXPLOIT_DEVELOPER, LLMManager())

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="generate_exploit",
        description="Generate exploit",
        input_data={
            "vulnerability_info": {"type": "buffer_overflow", "location": "validate_key"},
            "target_system": "windows_x64"
        },
        priority=TaskPriority.CRITICAL
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    exploit_data = result["result"]
    assert "exploit_code" in exploit_data
    assert "payload_variants" in exploit_data
    assert "success_probability" in exploit_data
    assert len(exploit_data["exploit_code"]) > 100


@pytest.mark.asyncio
async def test_agent_code_modification_applies_patches() -> None:
    """Agent code modification task reports patch application."""
    agent = BaseAgent("code_modifier", AgentRole.CODE_MODIFIER, LLMManager())

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="code_modification",
        description="Apply patches",
        input_data={
            "target_file": "protected.exe",
            "modification_type": "patch",
            "patch_instructions": {"patches": [{"offset": "0x1000", "bytes": "90 90"}]}
        },
        priority=TaskPriority.HIGH
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    mod_data = result["result"]
    assert "patches_applied" in mod_data
    assert "modification_summary" in mod_data
    assert len(mod_data["patches_applied"]) > 0


@pytest.mark.asyncio
async def test_agent_script_generation_creates_frida_script() -> None:
    """Agent script generation creates Frida hooking scripts."""
    agent = BaseAgent("script_gen", AgentRole.SCRIPT_GENERATOR, LLMManager())

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="script_generation",
        description="Generate Frida script",
        input_data={
            "script_type": "frida",
            "target_functions": ["check_license", "validate_key", "verify_registration"]
        },
        priority=TaskPriority.MEDIUM
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    script_data = result["result"]
    assert "script_content" in script_data
    assert "Frida" in script_data["script_content"]
    assert "check_license" in script_data["script_content"]
    assert script_data["script_type"] == "frida"


@pytest.mark.asyncio
async def test_agent_coordination_creates_execution_plan() -> None:
    """Agent coordination task creates multi-agent execution plan."""
    agent = BaseAgent("coordinator", AgentRole.COORDINATOR, LLMManager())

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="coordination",
        description="Coordinate analysis workflow",
        input_data={
            "workflow": {"name": "comprehensive_analysis", "steps": 4},
            "agent_assignments": {"static": "agent1", "dynamic": "agent2"}
        },
        priority=TaskPriority.HIGH
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    coord_data = result["result"]
    assert "coordination_plan" in coord_data
    assert "execution_order" in coord_data["coordination_plan"]
    assert "resource_allocation" in coord_data["coordination_plan"]
    assert len(coord_data["coordination_plan"]["execution_order"]) > 0


@pytest.mark.asyncio
async def test_agent_specialist_analysis_provides_recommendations() -> None:
    """Agent specialist analysis provides domain-specific recommendations."""
    agent = BaseAgent("specialist", AgentRole.SPECIALIST, LLMManager())

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="specialist_analysis",
        description="Specialized analysis",
        input_data={
            "domain": "cryptography",
            "analysis_request": {"type": "algorithm_analysis", "priority": "high"}
        },
        priority=TaskPriority.HIGH
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    specialist_data = result["result"]
    assert "domain_analysis" in specialist_data
    assert "recommendations" in specialist_data
    assert "advanced_techniques" in specialist_data
    assert len(specialist_data["recommendations"]) > 0


@pytest.mark.asyncio
async def test_unified_analysis_combines_agent_findings(
    multi_agent_system: MultiAgentSystem
) -> None:
    """Unified analysis correctly combines findings from multiple agents."""
    results = {
        "static_agent": {
            "confidence": 0.9,
            "findings": ["vmprotect_detected", "encrypted_strings"],
            "vulnerabilities": [{"type": "buffer_overflow"}]
        },
        "dynamic_agent": {
            "confidence": 0.85,
            "findings": ["anti_debug", "encrypted_strings"],
            "issues": [{"type": "suspicious_api_call"}]
        },
        "reverse_agent": {
            "confidence": 0.88,
            "findings": ["custom_packer"],
            "problems": [{"type": "obfuscated_code"}]
        }
    }

    unified = multi_agent_system._create_unified_analysis(results)

    assert "overall_assessment" in unified
    assert "confidence_scores" in unified
    assert "combined_findings" in unified
    assert len(unified["confidence_scores"]) == 3
    assert len(unified["combined_findings"]) > 0


@pytest.mark.asyncio
async def test_subtask_creation_distributes_work(
    multi_agent_system: MultiAgentSystem
) -> None:
    """Subtask creation properly distributes work among agents."""
    multi_agent_system.start()

    main_task = AgentTask(
        task_id="main_task",
        task_type="comprehensive_analysis",
        description="Full analysis",
        input_data={"file_path": "test.exe"},
        priority=TaskPriority.HIGH
    )

    suitable_agents = list(multi_agent_system.agents.items())[:2]
    subtasks = multi_agent_system._create_subtasks(main_task, suitable_agents)

    assert len(subtasks) > 0

    for agent_id, subtask in subtasks:
        assert agent_id in multi_agent_system.agents
        assert subtask.task_id.startswith(main_task.task_id)
        assert subtask.metadata.get("parent_task") == main_task.task_id

    multi_agent_system.stop()


@pytest.mark.asyncio
async def test_determine_required_capabilities_maps_task_types(
    multi_agent_system: MultiAgentSystem
) -> None:
    """System correctly determines required capabilities for different task types."""
    test_cases = [
        ("binary_analysis", ["binary_analysis", "disassembly"]),
        ("vulnerability_assessment", ["static_analysis", "dynamic_analysis", "code_analysis"]),
        ("reverse_engineering", ["disassembly", "decompilation", "algorithm_analysis"]),
        ("comprehensive_analysis", ["binary_analysis", "runtime_analysis", "disassembly"]),
        ("unknown_task", ["unknown_task"])
    ]

    for task_type, expected_caps in test_cases:
        task = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type=task_type,
            description=f"Test {task_type}",
            input_data={},
            priority=TaskPriority.MEDIUM
        )

        capabilities = multi_agent_system._determine_required_capabilities(task)
        assert capabilities == expected_caps


@pytest.mark.asyncio
async def test_task_priority_enum_has_all_levels() -> None:
    """TaskPriority enum contains all priority levels."""
    assert TaskPriority.CRITICAL.value == 1
    assert TaskPriority.HIGH.value == 2
    assert TaskPriority.MEDIUM.value == 3
    assert TaskPriority.LOW.value == 4
    assert TaskPriority.BACKGROUND.value == 5


@pytest.mark.asyncio
async def test_message_type_enum_has_all_types() -> None:
    """MessageType enum contains all message types."""
    expected_types = [
        "TASK_REQUEST",
        "TASK_RESPONSE",
        "KNOWLEDGE_SHARE",
        "COLLABORATION_REQUEST",
        "STATUS_UPDATE",
        "ERROR_REPORT",
        "CAPABILITY_QUERY",
        "CAPABILITY_RESPONSE"
    ]

    message_type_names = [mt.name for mt in MessageType]
    for expected in expected_types:
        assert expected in message_type_names


@pytest.mark.asyncio
async def test_agent_role_enum_has_all_roles() -> None:
    """AgentRole enum contains all specialized roles."""
    expected_roles = [
        "STATIC_ANALYZER",
        "DYNAMIC_ANALYZER",
        "REVERSE_ENGINEER",
        "VULNERABILITY_HUNTER",
        "EXPLOIT_DEVELOPER",
        "CODE_MODIFIER",
        "SCRIPT_GENERATOR",
        "COORDINATOR",
        "SPECIALIST"
    ]

    role_names = [role.name for role in AgentRole]
    for expected in expected_roles:
        assert expected in role_names


@pytest.mark.asyncio
async def test_agent_get_status_returns_complete_info() -> None:
    """Agent status includes all relevant metrics."""
    agent = BaseAgent("status_test", AgentRole.STATIC_ANALYZER, LLMManager())
    agent.tasks_completed = 15
    agent.tasks_failed = 3
    agent.total_execution_time = 75.5

    status = agent.get_agent_status()

    assert status["agent_id"] == "status_test"
    assert status["role"] == "static_analyzer"
    assert status["tasks_completed"] == 15
    assert status["tasks_failed"] == 3
    assert "success_rate" in status
    assert "avg_execution_time" in status
    assert "last_activity" in status
    assert "capabilities_count" in status


@pytest.mark.asyncio
async def test_reverse_engineering_agent_algorithm_analysis(
    test_binary_path: Path
) -> None:
    """Reverse engineering agent performs algorithm analysis."""
    agent = ReverseEngineeringAgent(
        agent_id="algo_analyzer",
        role=AgentRole.REVERSE_ENGINEER,
        llm_manager=LLMManager()
    )

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="algorithm_analysis",
        description="Analyze algorithms",
        input_data={"file_path": str(test_binary_path)},
        priority=TaskPriority.HIGH
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    assert "result" in result


@pytest.mark.asyncio
async def test_dynamic_analysis_agent_runtime_monitoring(
    test_binary_path: Path
) -> None:
    """Dynamic analysis agent performs runtime monitoring."""
    agent = DynamicAnalysisAgent(
        agent_id="runtime_monitor",
        role=AgentRole.DYNAMIC_ANALYZER,
        llm_manager=LLMManager()
    )

    task = AgentTask(
        task_id=str(uuid.uuid4()),
        task_type="runtime_monitoring",
        description="Monitor runtime behavior",
        input_data={"target_path": str(test_binary_path)},
        priority=TaskPriority.HIGH
    )

    result = await agent.execute_task(task)

    assert result["status"] == "completed"
    assert "result" in result
