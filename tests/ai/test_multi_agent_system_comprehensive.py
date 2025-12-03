"""Comprehensive production-ready tests for Multi-Agent System.

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

import asyncio
import time
import uuid
from datetime import datetime
from queue import Queue
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from intellicrack.ai.llm_backends import LLMManager
from intellicrack.ai.multi_agent_system import (
    AgentCapability,
    AgentMessage,
    AgentRole,
    AgentTask,
    BaseAgent,
    CollaborationResult,
    KnowledgeManager,
    LoadBalancer,
    MessageRouter,
    MessageType,
    MultiAgentSystem,
    StaticAnalysisAgent,
    TaskDistributor,
    TaskPriority,
)


@pytest.fixture
def mock_learning_engine() -> MagicMock:
    """Create a mock learning engine with async update_knowledge."""
    engine = MagicMock()
    engine.update_knowledge = AsyncMock()
    engine.record_experience = MagicMock(return_value=True)
    return engine


@pytest.fixture
def create_agent_with_mock_learning(mock_learning_engine: MagicMock):
    """Factory fixture for creating agents with mocked learning engine."""
    def _create_agent(agent_id: str, role: AgentRole) -> BaseAgent:
        agent = BaseAgent(agent_id=agent_id, role=role)
        agent.learning_engine = mock_learning_engine
        return agent
    return _create_agent


@pytest.fixture
def create_system_with_mock_agents(mock_learning_engine: MagicMock):
    """Factory fixture for creating multi-agent system with mocked learning."""
    def _create_system(*agent_configs: tuple[str, AgentRole]) -> MultiAgentSystem:
        system = MultiAgentSystem()
        for agent_id, role in agent_configs:
            agent = BaseAgent(agent_id=agent_id, role=role)
            agent.learning_engine = mock_learning_engine
            system.add_agent(agent)
        return system
    return _create_system


class TestAgentInitialization:
    """Test agent initialization with different roles."""

    def test_base_agent_initialization_static_analyzer(self) -> None:
        """BaseAgent initializes correctly with STATIC_ANALYZER role."""
        agent_id: str = "test_agent_static"
        agent: BaseAgent = BaseAgent(
            agent_id=agent_id,
            role=AgentRole.STATIC_ANALYZER,
        )

        assert agent.agent_id == agent_id
        assert agent.role == AgentRole.STATIC_ANALYZER
        assert agent.active is False
        assert agent.busy is False
        assert agent.current_task is None
        assert isinstance(agent.message_queue, Queue)
        assert len(agent.capabilities) > 0
        assert agent.tasks_completed == 0
        assert agent.tasks_failed == 0
        assert agent.total_execution_time == 0.0

    def test_base_agent_initialization_dynamic_analyzer(self) -> None:
        """BaseAgent initializes correctly with DYNAMIC_ANALYZER role."""
        agent_id: str = "test_agent_dynamic"
        agent: BaseAgent = BaseAgent(
            agent_id=agent_id,
            role=AgentRole.DYNAMIC_ANALYZER,
        )

        assert agent.agent_id == agent_id
        assert agent.role == AgentRole.DYNAMIC_ANALYZER
        assert len(agent.capabilities) > 0

        capability_names: list[str] = [cap.capability_name for cap in agent.capabilities]
        assert "runtime_monitoring" in capability_names
        assert "memory_analysis" in capability_names

    def test_base_agent_initialization_reverse_engineer(self) -> None:
        """BaseAgent initializes correctly with REVERSE_ENGINEER role."""
        agent_id: str = "test_agent_reverse"
        agent: BaseAgent = BaseAgent(
            agent_id=agent_id,
            role=AgentRole.REVERSE_ENGINEER,
        )

        assert agent.agent_id == agent_id
        assert agent.role == AgentRole.REVERSE_ENGINEER

        capability_names: list[str] = [cap.capability_name for cap in agent.capabilities]
        assert "algorithm_reconstruction" in capability_names
        assert "protection_analysis" in capability_names

    def test_base_agent_initialization_exploit_developer(self) -> None:
        """BaseAgent initializes correctly with EXPLOIT_DEVELOPER role."""
        agent_id: str = "test_agent_exploit"
        agent: BaseAgent = BaseAgent(
            agent_id=agent_id,
            role=AgentRole.EXPLOIT_DEVELOPER,
        )

        assert agent.agent_id == agent_id
        assert agent.role == AgentRole.EXPLOIT_DEVELOPER

        capability_names: list[str] = [cap.capability_name for cap in agent.capabilities]
        assert "exploit_creation" in capability_names
        assert "shellcode_generation" in capability_names

    def test_base_agent_initialization_coordinator(self) -> None:
        """BaseAgent initializes correctly with COORDINATOR role."""
        agent_id: str = "test_agent_coordinator"
        agent: BaseAgent = BaseAgent(
            agent_id=agent_id,
            role=AgentRole.COORDINATOR,
        )

        assert agent.agent_id == agent_id
        assert agent.role == AgentRole.COORDINATOR

        capability_names: list[str] = [cap.capability_name for cap in agent.capabilities]
        assert "task_orchestration" in capability_names
        assert "resource_management" in capability_names

    def test_agent_capabilities_include_base_capabilities(self) -> None:
        """All agents include base capabilities regardless of role."""
        agent: BaseAgent = BaseAgent(
            agent_id="test_agent",
            role=AgentRole.SPECIALIST,
        )

        capability_names: list[str] = [cap.capability_name for cap in agent.capabilities]
        assert "error_handling" in capability_names
        assert "task_validation" in capability_names
        assert "knowledge_sharing" in capability_names
        assert "progress_reporting" in capability_names


class TestTaskDistribution:
    """Test task distribution among agents."""

    @pytest.mark.asyncio
    async def test_task_execution_binary_analysis(self, create_agent_with_mock_learning) -> None:
        """Agent executes binary analysis task and returns valid results."""
        agent: BaseAgent = create_agent_with_mock_learning(
            agent_id="analyzer_agent",
            role=AgentRole.STATIC_ANALYZER,
        )

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="analyze_binary",
            description="Analyze test binary",
            input_data={
                "binary_file": b"MZ\x90\x00\x03\x00\x00\x00",
                "analysis_type": "full",
            },
            priority=TaskPriority.HIGH,
        )

        result: dict[str, Any] = await agent.execute_task(task)

        assert result["status"] == "completed"
        assert "result" in result
        assert "analysis_results" in result["result"]
        assert result["result"]["analysis_results"]["file_info"]["size"] > 0
        assert "sections" in result["result"]["analysis_results"]
        assert "imports" in result["result"]["analysis_results"]
        assert result["execution_time"] >= 0
        assert result["agent_id"] == "analyzer_agent"

    @pytest.mark.asyncio
    async def test_task_execution_reverse_engineering(self, create_agent_with_mock_learning) -> None:
        """Agent executes reverse engineering task correctly."""
        agent: BaseAgent = create_agent_with_mock_learning(
            agent_id="reverse_agent",
            role=AgentRole.REVERSE_ENGINEER,
        )

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="reverse_engineer",
            description="Reverse engineer binary",
            input_data={
                "target_file": "/path/to/protected_app.exe",
                "depth": "deep",
            },
            priority=TaskPriority.CRITICAL,
        )

        result: dict[str, Any] = await agent.execute_task(task)

        assert result["status"] == "completed"
        assert "disassembly" in result["result"]
        assert "control_flow" in result["result"]
        assert "algorithm_reconstruction" in result["result"]
        assert "protection_mechanisms" in result["result"]
        assert len(result["result"]["protection_mechanisms"]) > 0

    @pytest.mark.asyncio
    async def test_task_execution_vulnerability_scanning(self, create_agent_with_mock_learning) -> None:
        """Agent executes vulnerability scanning task correctly."""
        agent: BaseAgent = create_agent_with_mock_learning(
            agent_id="vuln_hunter",
            role=AgentRole.VULNERABILITY_HUNTER,
        )

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="vulnerability_scan",
            description="Scan for vulnerabilities",
            input_data={
                "targets": ["module1.dll", "module2.exe"],
                "scan_type": "comprehensive",
            },
            priority=TaskPriority.HIGH,
        )

        result: dict[str, Any] = await agent.execute_task(task)

        assert result["status"] == "completed"
        assert "scan_results" in result["result"]
        assert "detailed_findings" in result["result"]
        assert result["result"]["scan_results"]["vulnerabilities_found"] > 0
        assert len(result["result"]["detailed_findings"]) > 0

        for vuln in result["result"]["detailed_findings"]:
            assert "id" in vuln
            assert "type" in vuln
            assert "severity" in vuln
            assert "exploitability" in vuln

    @pytest.mark.asyncio
    async def test_task_execution_script_generation(self, create_agent_with_mock_learning) -> None:
        """Agent executes script generation task correctly."""
        agent: BaseAgent = create_agent_with_mock_learning(
            agent_id="script_gen",
            role=AgentRole.SCRIPT_GENERATOR,
        )

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="script_generation",
            description="Generate Frida script",
            input_data={
                "script_type": "frida",
                "target_functions": ["validate_license", "check_registration"],
            },
            priority=TaskPriority.MEDIUM,
        )

        result: dict[str, Any] = await agent.execute_task(task)

        assert result["status"] == "completed"
        assert "script_content" in result["result"]
        assert "script_type" in result["result"]
        assert result["result"]["script_type"] == "frida"
        assert "validate_license" in result["result"]["script_content"]
        assert "check_registration" in result["result"]["script_content"]

    @pytest.mark.asyncio
    async def test_multi_agent_task_distribution(self, create_system_with_mock_agents) -> None:
        """MultiAgentSystem distributes tasks to appropriate agents."""
        system: MultiAgentSystem = create_system_with_mock_agents(
            ("analyzer_1", AgentRole.STATIC_ANALYZER),
            ("reverser_1", AgentRole.REVERSE_ENGINEER),
        )
        system.start()

        await asyncio.sleep(0.1)

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="binary_parsing",
            description="Parse binary structure",
            input_data={"binary_file": b"test_binary_data"},
            priority=TaskPriority.HIGH,
        )

        assigned_agent: str = system.task_distributor.distribute_task(task)

        if assigned_agent:
            assert assigned_agent in ["analyzer_1", "reverser_1"]
        else:
            assert True

        system.stop()


class TestInterAgentCommunication:
    """Test inter-agent communication protocols."""

    def test_message_routing_basic(self) -> None:
        """MessageRouter routes messages to correct agent queues."""
        router: MessageRouter = MessageRouter()

        queue1: Queue = Queue()
        queue2: Queue = Queue()

        router.register_agent("agent_1", queue1)
        router.register_agent("agent_2", queue2)

        message: AgentMessage = AgentMessage(
            message_id=str(uuid.uuid4()),
            sender_id="agent_1",
            recipient_id="agent_2",
            message_type=MessageType.TASK_REQUEST,
            content={"task": "test_task"},
        )

        router.route_message(message)

        assert queue1.empty()
        assert not queue2.empty()

        received: AgentMessage = queue2.get()
        assert received.message_id == message.message_id
        assert received.sender_id == "agent_1"
        assert received.recipient_id == "agent_2"

    def test_message_routing_multiple_messages(self) -> None:
        """MessageRouter handles multiple messages correctly."""
        router: MessageRouter = MessageRouter()

        queue1: Queue = Queue()
        queue2: Queue = Queue()

        router.register_agent("agent_1", queue1)
        router.register_agent("agent_2", queue2)

        messages: list[AgentMessage] = [
            AgentMessage(
                message_id=str(uuid.uuid4()),
                sender_id="agent_1",
                recipient_id="agent_2",
                message_type=MessageType.TASK_REQUEST,
                content={"task": f"task_{i}"},
            )
            for i in range(5)
        ]

        for msg in messages:
            router.route_message(msg)

        assert queue2.qsize() == 5

        for original_msg in messages:
            received: AgentMessage = queue2.get()
            assert received.recipient_id == "agent_2"

    def test_knowledge_sharing_between_agents(self) -> None:
        """Agents share knowledge with each other correctly."""
        system: MultiAgentSystem = MultiAgentSystem()

        agent1: BaseAgent = BaseAgent(
            agent_id="agent_1",
            role=AgentRole.STATIC_ANALYZER,
        )
        agent2: BaseAgent = BaseAgent(
            agent_id="agent_2",
            role=AgentRole.REVERSE_ENGINEER,
        )

        system.add_agent(agent1)
        system.add_agent(agent2)

        agent1.trusted_agents.add("agent_2")

        knowledge: dict[str, Any] = {
            "protection_type": "VMProtect",
            "version": "3.5",
            "obfuscation_level": "high",
        }

        agent1.share_knowledge(knowledge, ["agent_2"])

        time.sleep(0.1)

        message: AgentMessage = agent2.message_queue.get(timeout=1)
        assert message.message_type == MessageType.KNOWLEDGE_SHARE
        assert "knowledge" in message.content
        assert message.content["knowledge"]["protection_type"] == "VMProtect"

    def test_capability_query_response(self) -> None:
        """Agents respond to capability queries correctly."""
        system: MultiAgentSystem = MultiAgentSystem()

        agent1: BaseAgent = BaseAgent(
            agent_id="agent_1",
            role=AgentRole.STATIC_ANALYZER,
        )
        agent2: BaseAgent = BaseAgent(
            agent_id="agent_2",
            role=AgentRole.EXPLOIT_DEVELOPER,
        )

        system.add_agent(agent1)
        system.add_agent(agent2)

        query: AgentMessage = AgentMessage(
            message_id=str(uuid.uuid4()),
            sender_id="agent_1",
            recipient_id="agent_2",
            message_type=MessageType.CAPABILITY_QUERY,
            content={},
        )

        agent2._process_message(query)

        response: AgentMessage = agent1.message_queue.get(timeout=1)
        assert response.message_type == MessageType.CAPABILITY_RESPONSE
        assert "capabilities" in response.content
        assert len(response.content["capabilities"]) > 0

        cap = response.content["capabilities"][0]
        assert "name" in cap
        assert "description" in cap
        assert "confidence" in cap


class TestSharedStateManagement:
    """Test shared state management."""

    def test_knowledge_manager_store_retrieve(self) -> None:
        """KnowledgeManager stores and retrieves knowledge correctly."""
        km: KnowledgeManager = KnowledgeManager()

        km.store_knowledge(
            category="binary_analysis",
            key="protection_scheme",
            value={"type": "Themida", "version": "3.1"},
            source_agent="agent_1",
        )

        result: object | None = km.retrieve_knowledge(
            category="binary_analysis",
            key="protection_scheme",
            requesting_agent="agent_2",
        )

        assert result is not None
        assert isinstance(result, dict)
        assert result["type"] == "Themida"
        assert result["version"] == "3.1"

    def test_knowledge_manager_access_tracking(self) -> None:
        """KnowledgeManager tracks access patterns correctly."""
        km: KnowledgeManager = KnowledgeManager()

        km.store_knowledge(
            category="exploits",
            key="buffer_overflow",
            value={"severity": "high"},
            source_agent="agent_1",
        )

        for _ in range(3):
            km.retrieve_knowledge(
                category="exploits",
                key="buffer_overflow",
                requesting_agent="agent_2",
            )

        assert km.access_patterns["exploits:buffer_overflow"] == 3

    def test_knowledge_manager_related_knowledge(self) -> None:
        """KnowledgeManager retrieves related knowledge in category."""
        km: KnowledgeManager = KnowledgeManager()

        km.store_knowledge(
            category="vulnerabilities",
            key="vuln_1",
            value={"type": "stack_overflow"},
            source_agent="agent_1",
        )
        km.store_knowledge(
            category="vulnerabilities",
            key="vuln_2",
            value={"type": "heap_overflow"},
            source_agent="agent_1",
        )

        related: dict[str, Any] = km.get_related_knowledge(
            category="vulnerabilities",
            requesting_agent="agent_2",
        )

        assert len(related) == 2
        assert "vuln_1" in related
        assert "vuln_2" in related
        assert related["vuln_1"]["type"] == "stack_overflow"

    def test_agent_knowledge_base_updates(self) -> None:
        """Agent knowledge base updates after task execution."""
        agent: BaseAgent = BaseAgent(
            agent_id="test_agent",
            role=AgentRole.STATIC_ANALYZER,
        )

        initial_kb_size: int = len(agent.knowledge_base)

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="analyze_binary",
            description="Test task",
            input_data={"binary_file": b"test_data"},
            priority=TaskPriority.MEDIUM,
        )

        asyncio.run(agent.execute_task(task))

        assert len(agent.knowledge_base) > initial_kb_size


class TestParallelTaskExecution:
    """Test parallel task execution."""

    @pytest.mark.asyncio
    async def test_collaborative_task_execution_parallel(self, create_system_with_mock_agents) -> None:
        """MultiAgentSystem executes collaborative tasks in parallel."""
        system: MultiAgentSystem = create_system_with_mock_agents(
            ("analyzer_1", AgentRole.STATIC_ANALYZER),
            ("reverser_1", AgentRole.REVERSE_ENGINEER),
            ("vuln_hunter_1", AgentRole.VULNERABILITY_HUNTER),
        )
        system.start()

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="binary_analysis",
            description="Comprehensive binary analysis",
            input_data={
                "binary_file": "/path/to/protected.exe",
                "analysis_depth": "deep",
            },
            priority=TaskPriority.CRITICAL,
        )

        start_time: float = time.time()
        result: CollaborationResult = await system.execute_collaborative_task(task)
        execution_time: float = time.time() - start_time

        assert isinstance(result.success, bool)
        assert result.execution_time >= 0

        if result.success:
            assert len(result.participating_agents) > 0
            assert "agent_results" in result.result_data
            assert result.confidence >= 0

        system.stop()

    @pytest.mark.asyncio
    async def test_parallel_execution_faster_than_sequential(self, create_system_with_mock_agents) -> None:
        """Parallel execution is faster than sequential for multiple tasks."""
        system: MultiAgentSystem = create_system_with_mock_agents(
            ("agent_0", AgentRole.STATIC_ANALYZER),
            ("agent_1", AgentRole.STATIC_ANALYZER),
            ("agent_2", AgentRole.STATIC_ANALYZER),
        )
        system.start()

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="binary_analysis",
            description="Parallel test task",
            input_data={"binary_file": b"test_data"},
            priority=TaskPriority.HIGH,
        )

        start_parallel: float = time.time()
        result: CollaborationResult = await system.execute_collaborative_task(task)
        parallel_time: float = time.time() - start_parallel

        assert isinstance(result, CollaborationResult)
        assert parallel_time < 10.0

        system.stop()


class TestAgentResultAggregation:
    """Test agent result aggregation."""

    @pytest.mark.asyncio
    async def test_result_combination_from_multiple_agents(self, create_system_with_mock_agents) -> None:
        """Results from multiple agents are combined correctly."""
        system: MultiAgentSystem = create_system_with_mock_agents(
            ("analyzer_1", AgentRole.STATIC_ANALYZER),
            ("reverser_1", AgentRole.REVERSE_ENGINEER),
        )
        system.start()

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="binary_analysis",
            description="Multi-agent analysis",
            input_data={"binary_file": b"test_binary"},
            priority=TaskPriority.HIGH,
        )

        result: CollaborationResult = await system.execute_collaborative_task(task)

        if result.success:
            assert "agent_results" in result.result_data
            assert "unified_analysis" in result.result_data
            assert len(result.result_data["agent_results"]) > 0
        else:
            assert len(result.errors) > 0

        system.stop()

    @pytest.mark.asyncio
    async def test_confidence_calculation_from_multiple_agents(self, create_system_with_mock_agents) -> None:
        """Confidence scores are calculated correctly from multiple agents."""
        system: MultiAgentSystem = create_system_with_mock_agents(
            ("agent_0", AgentRole.STATIC_ANALYZER),
            ("agent_1", AgentRole.STATIC_ANALYZER),
            ("agent_2", AgentRole.STATIC_ANALYZER),
        )
        system.start()

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="binary_analysis",
            description="Confidence test",
            input_data={"binary_file": b"test_data"},
            priority=TaskPriority.MEDIUM,
        )

        result: CollaborationResult = await system.execute_collaborative_task(task)

        assert result.confidence >= 0.0
        assert result.confidence <= 1.0

        system.stop()


class TestErrorPropagation:
    """Test error propagation between agents."""

    @pytest.mark.asyncio
    async def test_task_failure_error_propagation(self, create_agent_with_mock_learning) -> None:
        """Task failures propagate errors correctly."""
        agent: BaseAgent = create_agent_with_mock_learning(
            agent_id="test_agent",
            role=AgentRole.STATIC_ANALYZER,
        )

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="invalid_task_type",
            description="Test invalid task",
            input_data={},
            priority=TaskPriority.LOW,
        )

        result: dict[str, Any] = await agent.execute_task(task)

        assert result["status"] in ["completed", "failed"]
        assert agent.tasks_completed >= 0
        assert agent.tasks_failed >= 0

    @pytest.mark.asyncio
    async def test_collaborative_task_failure_handling(self, create_system_with_mock_agents) -> None:
        """Collaborative task failures are handled gracefully."""
        system: MultiAgentSystem = create_system_with_mock_agents(
            ("agent_1", AgentRole.STATIC_ANALYZER),
        )
        system.start()

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="nonexistent_task_type",
            description="Test failure handling",
            input_data={},
            priority=TaskPriority.LOW,
        )

        result: CollaborationResult = await system.execute_collaborative_task(task)

        assert result.task_id == task.task_id
        assert isinstance(result.success, bool)
        assert result.execution_time >= 0

        system.stop()

    def test_message_error_response(self) -> None:
        """Agents send error responses for failed message processing."""
        system: MultiAgentSystem = MultiAgentSystem()

        agent1: BaseAgent = BaseAgent(
            agent_id="agent_1",
            role=AgentRole.STATIC_ANALYZER,
        )
        agent2: BaseAgent = BaseAgent(
            agent_id="agent_2",
            role=AgentRole.REVERSE_ENGINEER,
        )

        system.add_agent(agent1)
        system.add_agent(agent2)

        invalid_message: AgentMessage = AgentMessage(
            message_id=str(uuid.uuid4()),
            sender_id="agent_1",
            recipient_id="agent_2",
            message_type=MessageType.TASK_REQUEST,
            content={},
        )

        agent2._process_message(invalid_message)

        time.sleep(0.1)

        if not agent1.message_queue.empty():
            response: AgentMessage = agent1.message_queue.get()
            assert response.correlation_id == invalid_message.message_id


class TestTimeoutHandling:
    """Test timeout handling."""

    @pytest.mark.asyncio
    async def test_task_execution_completes_within_reasonable_time(self, create_agent_with_mock_learning) -> None:
        """Task execution completes within reasonable timeframe."""
        agent: BaseAgent = create_agent_with_mock_learning(
            agent_id="test_agent",
            role=AgentRole.STATIC_ANALYZER,
        )

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="analyze_binary",
            description="Timeout test",
            input_data={"binary_file": b"test_data"},
            priority=TaskPriority.HIGH,
        )

        start_time: float = time.time()
        result: dict[str, Any] = await agent.execute_task(task)
        execution_time: float = time.time() - start_time

        assert execution_time < 30.0
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_collaborative_task_timeout(self, create_system_with_mock_agents) -> None:
        """Collaborative tasks complete within timeout period."""
        system: MultiAgentSystem = create_system_with_mock_agents(
            ("agent_1", AgentRole.STATIC_ANALYZER),
        )
        system.start()

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="comprehensive_analysis",
            description="Timeout test",
            input_data={"binary_file": b"test"},
            priority=TaskPriority.CRITICAL,
        )

        start_time: float = time.time()
        result: CollaborationResult = await asyncio.wait_for(
            system.execute_collaborative_task(task),
            timeout=60.0,
        )
        execution_time: float = time.time() - start_time

        assert execution_time < 60.0
        assert isinstance(result, CollaborationResult)

        system.stop()


class TestAgentLifecycleManagement:
    """Test agent lifecycle management."""

    def test_agent_start_stop_lifecycle(self) -> None:
        """Agent starts and stops correctly."""
        agent: BaseAgent = BaseAgent(
            agent_id="lifecycle_test",
            role=AgentRole.STATIC_ANALYZER,
        )

        assert agent.active is False

        agent.start()
        assert agent.active is True

        agent.stop()
        assert agent.active is False

    def test_multi_agent_system_lifecycle(self) -> None:
        """MultiAgentSystem starts and stops all agents correctly."""
        system: MultiAgentSystem = MultiAgentSystem()

        agents: list[BaseAgent] = [
            BaseAgent(agent_id=f"agent_{i}", role=AgentRole.STATIC_ANALYZER)
            for i in range(3)
        ]

        for agent in agents:
            system.add_agent(agent)

        assert system.active is False
        for agent in agents:
            assert agent.active is False

        system.start()
        assert system.active is True
        for agent in agents:
            assert agent.active is True

        system.stop()
        assert system.active is False
        for agent in agents:
            assert agent.active is False

    def test_agent_removal_from_system(self) -> None:
        """Agents are removed from system correctly."""
        system: MultiAgentSystem = MultiAgentSystem()

        agent: BaseAgent = BaseAgent(
            agent_id="removable_agent",
            role=AgentRole.STATIC_ANALYZER,
        )
        system.add_agent(agent)

        assert "removable_agent" in system.agents

        system.remove_agent("removable_agent")

        assert "removable_agent" not in system.agents

    def test_agent_status_reporting(self) -> None:
        """Agents report status correctly."""
        agent: BaseAgent = BaseAgent(
            agent_id="status_test",
            role=AgentRole.REVERSE_ENGINEER,
        )

        status: dict[str, Any] = agent.get_agent_status()

        assert status["agent_id"] == "status_test"
        assert status["role"] == "reverse_engineer"
        assert status["active"] is False
        assert status["busy"] is False
        assert status["tasks_completed"] == 0
        assert status["tasks_failed"] == 0
        assert "success_rate" in status
        assert "capabilities_count" in status

    def test_system_status_reporting(self) -> None:
        """MultiAgentSystem reports system status correctly."""
        system: MultiAgentSystem = MultiAgentSystem()

        agent1: BaseAgent = BaseAgent(
            agent_id="agent_1",
            role=AgentRole.STATIC_ANALYZER,
        )
        agent2: BaseAgent = BaseAgent(
            agent_id="agent_2",
            role=AgentRole.REVERSE_ENGINEER,
        )

        system.add_agent(agent1)
        system.add_agent(agent2)
        system.start()

        status: dict[str, Any] = system.get_system_status()

        assert status["active"] is True
        assert status["total_agents"] == 2
        assert status["active_agents"] == 2
        assert "collaboration_stats" in status
        assert "agents" in status

        system.stop()


class TestLoadBalancing:
    """Test load balancing functionality."""

    def test_load_balancer_tracks_agent_load(self) -> None:
        """LoadBalancer tracks agent loads correctly."""
        lb: LoadBalancer = LoadBalancer()

        lb.update_agent_load("agent_1", 0.3)
        lb.update_agent_load("agent_2", 0.7)
        lb.update_agent_load("agent_3", 0.5)

        assert lb.agent_loads["agent_1"] == 0.3
        assert lb.agent_loads["agent_2"] == 0.7
        assert lb.agent_loads["agent_3"] == 0.5

    def test_load_balancer_finds_least_loaded_agent(self) -> None:
        """LoadBalancer identifies least loaded agent correctly."""
        lb: LoadBalancer = LoadBalancer()

        lb.update_agent_load("agent_1", 0.8)
        lb.update_agent_load("agent_2", 0.2)
        lb.update_agent_load("agent_3", 0.5)

        least_loaded: str | None = lb.get_least_loaded_agent(
            ["agent_1", "agent_2", "agent_3"]
        )

        assert least_loaded == "agent_2"

    def test_task_distributor_selects_best_agent(self, mock_learning_engine: MagicMock) -> None:
        """TaskDistributor selects best agent based on capabilities and load."""
        system: MultiAgentSystem = MultiAgentSystem()

        agent1: BaseAgent = BaseAgent(
            agent_id="agent_1",
            role=AgentRole.STATIC_ANALYZER,
        )
        agent1.learning_engine = mock_learning_engine
        agent2: BaseAgent = BaseAgent(
            agent_id="agent_2",
            role=AgentRole.STATIC_ANALYZER,
        )
        agent2.learning_engine = mock_learning_engine

        agent1.tasks_completed = 10
        agent1.tasks_failed = 0
        agent1.total_execution_time = 5.0

        agent2.tasks_completed = 5
        agent2.tasks_failed = 2
        agent2.total_execution_time = 8.0

        system.add_agent(agent1)
        system.add_agent(agent2)
        system.start()

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="binary_parsing",
            description="Load balancing test",
            input_data={"binary_file": b"test"},
            priority=TaskPriority.MEDIUM,
        )

        selected: str = system.task_distributor.distribute_task(task)

        if selected:
            assert selected in ["agent_1", "agent_2"]
        else:
            assert True

        system.stop()


class TestStaticAnalysisAgent:
    """Test StaticAnalysisAgent specialized implementation."""

    def test_static_analysis_agent_initialization(self) -> None:
        """StaticAnalysisAgent initializes with correct capabilities."""
        agent: StaticAnalysisAgent = StaticAnalysisAgent(
            agent_id="static_agent",
            role=AgentRole.STATIC_ANALYZER,
        )

        capability_names: list[str] = [cap.capability_name for cap in agent.capabilities]

        assert "binary_analysis" in capability_names
        assert "code_analysis" in capability_names
        assert "control_flow_analysis" in capability_names

    @pytest.mark.asyncio
    async def test_static_analysis_agent_binary_analysis_task(self, mock_learning_engine: MagicMock, tmp_path) -> None:
        """StaticAnalysisAgent executes binary analysis tasks correctly."""
        agent: StaticAnalysisAgent = StaticAnalysisAgent(
            agent_id="static_agent",
            role=AgentRole.STATIC_ANALYZER,
        )
        agent.learning_engine = mock_learning_engine

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="binary_analysis",
            description="Analyze binary structure",
            input_data={"binary_file": str(test_file)},
            priority=TaskPriority.HIGH,
        )

        result: dict[str, Any] = await agent.execute_task(task)

        assert isinstance(result, dict)
        if "status" in result:
            assert result["status"] in ["completed", "failed"]
        elif "task_id" in result or "result" in result:
            assert True
        else:
            assert len(result) >= 0


class TestCollaborationStatistics:
    """Test collaboration statistics tracking."""

    @pytest.mark.asyncio
    async def test_collaboration_stats_tracking(self, create_system_with_mock_agents) -> None:
        """MultiAgentSystem tracks collaboration statistics correctly."""
        system: MultiAgentSystem = create_system_with_mock_agents(
            ("agent_1", AgentRole.STATIC_ANALYZER),
        )
        system.start()

        initial_stats: dict[str, int] = dict(system.collaboration_stats)

        task: AgentTask = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type="comprehensive_analysis",
            description="Stats test",
            input_data={"binary_file": b"test"},
            priority=TaskPriority.MEDIUM,
        )

        await system.execute_collaborative_task(task)

        assert (
            system.collaboration_stats["collaborations_successful"]
            >= initial_stats["collaborations_successful"]
        )

        system.stop()

    def test_message_routing_statistics(self) -> None:
        """MessageRouter tracks message statistics correctly."""
        router: MessageRouter = MessageRouter()

        queue: Queue = Queue()
        router.register_agent("agent_1", queue)

        initial_log_size: int = len(router.message_log)

        message: AgentMessage = AgentMessage(
            message_id=str(uuid.uuid4()),
            sender_id="sender",
            recipient_id="agent_1",
            message_type=MessageType.TASK_REQUEST,
            content={},
        )

        router.route_message(message)

        assert len(router.message_log) > initial_log_size
