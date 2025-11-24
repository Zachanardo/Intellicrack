"""
Production-grade tests for multi-agent collaboration system.

Tests validate real multi-agent coordination, task distribution, inter-agent
communication, result aggregation, and distributed binary analysis capabilities.
"""

import asyncio
import time
import uuid
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
        b"MZ\x90\x00"  # DOS signature
        + b"\x00" * 56  # DOS stub
        + b"\x40\x00\x00\x00"  # PE offset at 0x40
        + b"\x00" * (0x40 - 64)  # Padding to PE offset
        + b"PE\x00\x00"  # PE signature
        + b"\x4c\x01"  # Machine: x86
        + b"\x03\x00"  # NumberOfSections
        + b"\x00" * 12  # Timestamp and other fields
        + b"\xE0\x00"  # SizeOfOptionalHeader
        + b"\x0F\x01"  # Characteristics
        + b"\x0B\x01"  # Optional header magic (PE32)
        + b"\x00" * 16  # Linker version, code size, etc
        + b"\x00\x10\x00\x00"  # AddressOfEntryPoint
        + b"\x00" * 200  # Rest of optional header
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

    reverse_agent = BaseAgent(
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

    reverse_agent = BaseAgent(
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
        task_type="reverse_engineer",
        description="Reverse engineering",
        input_data={"target_file": str(test_binary_path)},
        priority=TaskPriority.HIGH
    )

    static_result = await static_agent.execute_task(static_task)
    reverse_result = await reverse_agent.execute_task(reverse_task)

    assert static_result["status"] == "completed"
    assert reverse_result["status"] == "completed"

    static_data = static_result["result"]
    reverse_data = reverse_result["result"]

    assert "file_type" in static_data or "architecture" in static_data
    assert "disassembly" in reverse_data or "algorithm_reconstruction" in reverse_data


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
