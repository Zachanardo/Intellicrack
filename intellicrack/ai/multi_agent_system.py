"""
Multi-Agent Collaboration System

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

import asyncio
import logging
import os
import threading
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from queue import Empty, PriorityQueue, Queue
from typing import Any, Dict, List, Optional, Set, Tuple

from ..utils.logger import get_logger
from .learning_engine_simple import get_learning_engine
from .llm_backends import LLMManager
from .performance_monitor import profile_ai_operation

logger = get_logger(__name__)


class AgentRole(Enum):
    """Specialized agent roles."""
    STATIC_ANALYZER = "static_analyzer"
    DYNAMIC_ANALYZER = "dynamic_analyzer"
    REVERSE_ENGINEER = "reverse_engineer"
    VULNERABILITY_HUNTER = "vulnerability_hunter"
    EXPLOIT_DEVELOPER = "exploit_developer"
    CODE_MODIFIER = "code_modifier"
    SCRIPT_GENERATOR = "script_generator"
    COORDINATOR = "coordinator"
    SPECIALIST = "specialist"


class MessageType(Enum):
    """Types of inter-agent messages."""
    TASK_REQUEST = "task_request"
    TASK_RESPONSE = "task_response"
    KNOWLEDGE_SHARE = "knowledge_share"
    COLLABORATION_REQUEST = "collaboration_request"
    STATUS_UPDATE = "status_update"
    ERROR_REPORT = "error_report"
    CAPABILITY_QUERY = "capability_query"
    CAPABILITY_RESPONSE = "capability_response"


class TaskPriority(Enum):
    """Task priority levels."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    BACKGROUND = 5


@dataclass
class AgentMessage:
    """Message between agents."""
    message_id: str
    sender_id: str
    recipient_id: str
    message_type: MessageType
    content: Dict[str, Any]
    priority: TaskPriority = TaskPriority.MEDIUM
    timestamp: datetime = field(default_factory=datetime.now)
    correlation_id: Optional[str] = None
    requires_response: bool = False
    response_timeout: Optional[float] = None


@dataclass
class AgentTask:
    """Task for agent execution."""
    task_id: str
    task_type: str
    description: str
    input_data: Dict[str, Any]
    priority: TaskPriority
    created_at: datetime = field(default_factory=datetime.now)
    assigned_to: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    deadline: Optional[datetime] = None
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentCapability:
    """Agent capability definition."""
    capability_name: str
    description: str
    input_types: List[str]
    output_types: List[str]
    processing_time_estimate: float
    confidence_level: float
    resource_requirements: Dict[str, Any] = field(default_factory=dict)
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class CollaborationResult:
    """Result of agent collaboration."""
    task_id: str
    success: bool
    result_data: Dict[str, Any]
    participating_agents: List[str]
    execution_time: float
    confidence: float
    errors: List[str] = field(default_factory=list)
    knowledge_gained: Dict[str, Any] = field(default_factory=dict)


class BaseAgent(ABC):
    """Base class for all specialized agents."""

    def __init__(self, agent_id: str, role: AgentRole, llm_manager: Optional[LLMManager] = None):
        """Initialize the base agent.

        Args:
            agent_id: Unique identifier for the agent
            role: Role of the agent from AgentRole enum
            llm_manager: Optional LLM manager for AI capabilities
        """
        self.logger = logging.getLogger(__name__ + ".BaseAgent")
        self.agent_id = agent_id
        self.role = role
        self.llm_manager = llm_manager or LLMManager()

        # Agent state
        self.active = False
        self.busy = False
        self.current_task: Optional[AgentTask] = None
        self.message_queue: Queue = Queue()
        self.response_waiters: Dict[str, Queue] = {}

        # Capabilities
        self.capabilities: List[AgentCapability] = []
        self.knowledge_base: Dict[str, Any] = {}
        self.learned_patterns: List[str] = []

        # Performance tracking
        self.tasks_completed = 0
        self.tasks_failed = 0
        self.total_execution_time = 0.0
        self.last_activity = datetime.now()

        # Communication
        self.collaboration_system: Optional["MultiAgentSystem"] = None
        self.trusted_agents: Set[str] = set()

        # Learning engine
        self.learning_engine = get_learning_engine()

        # Initialize capabilities
        self._initialize_capabilities()

        logger.info(f"Agent {self.agent_id} ({self.role.value}) initialized")

    @abstractmethod
    def _initialize_capabilities(self):
        """Initialize agent-specific capabilities."""
        pass

    @abstractmethod
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute a task specific to this agent."""
        # Implementation should use the task parameter to perform agent-specific work
        raise NotImplementedError(
            f"Subclasses must implement execute_task for task: {task.task_type}")

    def start(self):
        """Start the agent."""
        self.active = True

        # Start message processing loop
        self.message_thread = threading.Thread(
            target=self._message_processing_loop,
            daemon=True
        )
        self.message_thread.start()

        logger.info(f"Agent {self.agent_id} started")

    def stop(self):
        """Stop the agent."""
        self.active = False
        logger.info(f"Agent {self.agent_id} stopped")

    def _message_processing_loop(self):
        """Main message processing loop."""
        while self.active:
            try:
                message = self.message_queue.get(timeout=1.0)
                self._process_message(message)
            except Empty as e:
                self.logger.error("Empty in multi_agent_system: %s", e)
                continue
            except Exception as e:
                logger.error(
                    f"Error processing message in {self.agent_id}: {e}")

    def _process_message(self, message: AgentMessage):
        """Process incoming message."""
        try:
            if message.message_type == MessageType.TASK_REQUEST:
                self._handle_task_request(message)
            elif message.message_type == MessageType.KNOWLEDGE_SHARE:
                self._handle_knowledge_share(message)
            elif message.message_type == MessageType.COLLABORATION_REQUEST:
                self._handle_collaboration_request(message)
            elif message.message_type == MessageType.CAPABILITY_QUERY:
                self._handle_capability_query(message)
            elif message.message_type == MessageType.TASK_RESPONSE:
                self._handle_task_response(message)

        except Exception as e:
            logger.error(f"Error handling message {message.message_id}: {e}")
            self._send_error_response(message, str(e))

    def _handle_task_request(self, message: AgentMessage):
        """Handle task request from another agent."""
        task_data = message.content.get("task", {})

        if self.busy or not self._can_execute_task(task_data):
            self._send_task_rejection(
                message, "Agent busy or cannot execute task")
            return

        # Create task
        task = AgentTask(
            task_id=message.content.get("task_id", str(uuid.uuid4())),
            task_type=task_data.get("type", "unknown"),
            description=task_data.get("description", ""),
            input_data=task_data.get("input", {}),
            priority=TaskPriority(task_data.get("priority", 3)),
            context=task_data.get("context", {}),
            metadata=task_data.get("metadata", {})
        )

        # Execute task asynchronously
        asyncio.create_task(self._execute_task_async(task, message))

    async def _execute_task_async(self, task: AgentTask, original_message: AgentMessage):
        """Execute task asynchronously and send response."""
        self.busy = True
        self.current_task = task
        start_time = time.time()

        try:
            result = await self.execute_task(task)
            execution_time = time.time() - start_time

            self.tasks_completed += 1
            self.total_execution_time += execution_time
            self.last_activity = datetime.now()

            # Record learning experience
            self.learning_engine.record_experience(
                task_type=f"agent_{self.role.value}_{task.task_type}",
                input_data=task.input_data,
                output_data=result,
                success=True,
                confidence=result.get("confidence", 0.8),
                execution_time=execution_time,
                memory_usage=0,  # Could implement memory tracking
                context={"agent_role": self.role.value,
                         "agent_id": self.agent_id}
            )

            # Send success response
            self._send_task_response(original_message, True, result)

        except Exception as e:
            execution_time = time.time() - start_time
            self.tasks_failed += 1

            # Record learning experience for failure
            self.learning_engine.record_experience(
                task_type=f"agent_{self.role.value}_{task.task_type}",
                input_data=task.input_data,
                output_data={},
                success=False,
                confidence=0.0,
                execution_time=execution_time,
                memory_usage=0,
                error_message=str(e),
                context={"agent_role": self.role.value,
                         "agent_id": self.agent_id}
            )

            logger.error(f"Task execution failed in {self.agent_id}: {e}")
            self._send_task_response(
                original_message, False, {"error": str(e)})

        finally:
            self.busy = False
            self.current_task = None

    def _can_execute_task(self, task_data: Dict[str, Any]) -> bool:
        """Check if agent can execute the task."""
        task_type = task_data.get("type", "")

        # Check capabilities
        for capability in self.capabilities:
            if task_type in capability.input_types or task_type == capability.capability_name:
                return True

        return False

    def _handle_knowledge_share(self, message: AgentMessage):
        """Handle knowledge sharing from another agent."""
        knowledge = message.content.get("knowledge", {})
        source_agent = message.sender_id

        # Update knowledge base
        for key, value in knowledge.items():
            if key not in self.knowledge_base:
                self.knowledge_base[key] = {}

            self.knowledge_base[key][source_agent] = {
                "value": value,
                "timestamp": datetime.now(),
                "confidence": message.content.get("confidence", 0.8)
            }

        logger.info(
            f"Agent {self.agent_id} received knowledge from {source_agent}")

    def _handle_collaboration_request(self, message: AgentMessage):
        """Handle collaboration request."""
        collaboration_type = message.content.get("type", "")

        if collaboration_type == "capability_needed":
            required_capability = message.content.get("capability", "")
            if self._has_capability(required_capability):
                self._send_collaboration_response(message, True, {
                    "available": True,
                    "estimated_time": self._estimate_execution_time(required_capability),
                    "confidence": self._get_capability_confidence(required_capability)
                })
            else:
                self._send_collaboration_response(
                    message, False, {"available": False})

    def _handle_capability_query(self, message: AgentMessage):
        """Handle capability query."""
        capabilities_data = []
        for capability in self.capabilities:
            capabilities_data.append({
                "name": capability.capability_name,
                "description": capability.description,
                "input_types": capability.input_types,
                "output_types": capability.output_types,
                "confidence": capability.confidence_level,
                "estimated_time": capability.processing_time_estimate
            })

        response = AgentMessage(
            message_id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            recipient_id=message.sender_id,
            message_type=MessageType.CAPABILITY_RESPONSE,
            content={"capabilities": capabilities_data},
            correlation_id=message.message_id
        )

        self._send_message(response)

    def _handle_task_response(self, message: AgentMessage):
        """Handle task response."""
        correlation_id = message.correlation_id
        if correlation_id and correlation_id in self.response_waiters:
            self.response_waiters[correlation_id].put(message)

    def _send_task_response(self, original_message: AgentMessage, success: bool, result: Dict[str, Any]):
        """Send task response."""
        response = AgentMessage(
            message_id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            recipient_id=original_message.sender_id,
            message_type=MessageType.TASK_RESPONSE,
            content={
                "success": success,
                "result": result,
                "execution_time": time.time() - original_message.timestamp.timestamp()
            },
            correlation_id=original_message.message_id
        )

        self._send_message(response)

    def _send_task_rejection(self, original_message: AgentMessage, reason: str):
        """Send task rejection."""
        response = AgentMessage(
            message_id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            recipient_id=original_message.sender_id,
            message_type=MessageType.TASK_RESPONSE,
            content={
                "success": False,
                "result": {"error": f"Task rejected: {reason}"},
                "rejected": True
            },
            correlation_id=original_message.message_id
        )

        self._send_message(response)

    def _send_collaboration_response(self, original_message: AgentMessage, available: bool, data: Dict[str, Any]):
        """Send collaboration response."""
        response = AgentMessage(
            message_id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            recipient_id=original_message.sender_id,
            message_type=MessageType.TASK_RESPONSE,
            content={
                "available": available,
                "data": data
            },
            correlation_id=original_message.message_id
        )

        self._send_message(response)

    def _send_error_response(self, original_message: AgentMessage, error: str):
        """Send error response."""
        response = AgentMessage(
            message_id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            recipient_id=original_message.sender_id,
            message_type=MessageType.ERROR_REPORT,
            content={"error": error},
            correlation_id=original_message.message_id
        )

        self._send_message(response)

    def _send_message(self, message: AgentMessage):
        """Send message through collaboration system."""
        if self.collaboration_system:
            self.collaboration_system.route_message(message)

    def _has_capability(self, capability_name: str) -> bool:
        """Check if agent has specific capability."""
        return any(cap.capability_name == capability_name for cap in self.capabilities)

    def _estimate_execution_time(self, capability_name: str) -> float:
        """Estimate execution time for capability."""
        for capability in self.capabilities:
            if capability.capability_name == capability_name:
                return capability.processing_time_estimate
        return 0.0

    def _get_capability_confidence(self, capability_name: str) -> float:
        """Get confidence level for capability."""
        for capability in self.capabilities:
            if capability.capability_name == capability_name:
                return capability.confidence_level
        return 0.0

    def share_knowledge(self, knowledge: Dict[str, Any], target_agents: Optional[List[str]] = None):
        """Share knowledge with other agents."""
        if not self.collaboration_system:
            return

        if target_agents is None:
            # Share with all trusted agents
            target_agents = list(self.trusted_agents)

        for agent_id in target_agents:
            message = AgentMessage(
                message_id=str(uuid.uuid4()),
                sender_id=self.agent_id,
                recipient_id=agent_id,
                message_type=MessageType.KNOWLEDGE_SHARE,
                content={
                    "knowledge": knowledge,
                    "confidence": 0.8,
                    "source_role": self.role.value
                }
            )
            self._send_message(message)

    def get_agent_status(self) -> Dict[str, Any]:
        """Get current agent status."""
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "active": self.active,
            "busy": self.busy,
            "current_task": self.current_task.task_id if self.current_task else None,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "success_rate": self.tasks_completed / max(1, self.tasks_completed + self.tasks_failed),
            "avg_execution_time": self.total_execution_time / max(1, self.tasks_completed),
            "last_activity": self.last_activity.isoformat(),
            "capabilities_count": len(self.capabilities),
            "knowledge_base_size": len(self.knowledge_base),
            "trusted_agents": len(self.trusted_agents)
        }


class StaticAnalysisAgent(BaseAgent):
    """Agent specialized in static analysis."""

    def _initialize_capabilities(self):
        """Initialize static analysis capabilities."""
        self.capabilities = [
            AgentCapability(
                capability_name="binary_analysis",
                description="Analyze binary file structure and metadata",
                input_types=["binary_file", "file_path"],
                output_types=["analysis_report", "metadata"],
                processing_time_estimate=5.0,
                confidence_level=0.9
            ),
            AgentCapability(
                capability_name="code_analysis",
                description="Analyze source code for patterns and vulnerabilities",
                input_types=["source_code", "code_file"],
                output_types=["vulnerability_report", "code_metrics"],
                processing_time_estimate=10.0,
                confidence_level=0.85
            ),
            AgentCapability(
                capability_name="control_flow_analysis",
                description="Analyze control flow and call graphs",
                input_types=["binary_file", "disassembly"],
                output_types=["control_flow_graph", "call_graph"],
                processing_time_estimate=15.0,
                confidence_level=0.8
            )
        ]

    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute static analysis task."""
        task_type = task.task_type
        input_data = task.input_data

        if task_type == "binary_analysis":
            return await self._analyze_binary(input_data)
        elif task_type == "code_analysis":
            return await self._analyze_code(input_data)
        elif task_type == "control_flow_analysis":
            return await self._analyze_control_flow(input_data)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _analyze_binary(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform binary analysis."""
        file_path = input_data.get("file_path", "")

        logger.debug(f"Binary analysis agent analyzing: {file_path}")

        # Simulate binary analysis
        await asyncio.sleep(2.0)  # Simulate processing time

        analysis_result = {
            "file_type": "PE32",
            "architecture": "x86_64",
            "compiler": "MSVC",
            "sections": [".text", ".data", ".rdata"],
            "imports": ["kernel32.dll", "user32.dll"],
            "exports": [],
            "entry_point": "0x401000",
            "file_size": input_data.get("file_size", 0),
            "confidence": 0.9
        }

        # Share knowledge with other agents
        self.share_knowledge({
            "binary_metadata": analysis_result,
            "analysis_timestamp": datetime.now().isoformat()
        })

        return analysis_result

    async def _analyze_code(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform code analysis."""
        code = input_data.get("code", "")
        language = input_data.get("language", "unknown")

        # Simulate code analysis
        await asyncio.sleep(3.0)

        analysis_result = {
            "language": language,
            "lines_of_code": len(code.split("\n")),
            "functions_detected": 5,
            "classes_detected": 2,
            "potential_vulnerabilities": [
                {"type": "buffer_overflow", "line": 45, "severity": "high"},
                {"type": "sql_injection", "line": 78, "severity": "medium"}
            ],
            "code_quality_score": 0.75,
            "confidence": 0.85
        }

        return analysis_result

    async def _analyze_control_flow(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform control flow analysis."""
        binary_path = input_data.get("binary_path", "")

        logger.debug(f"Control flow analysis agent analyzing: {binary_path}")

        # Simulate control flow analysis
        await asyncio.sleep(5.0)

        result = {
            "basic_blocks": 120,
            "function_count": 25,
            "cyclomatic_complexity": 8.5,
            "call_graph_nodes": 45,
            "control_flow_anomalies": [
                {"type": "unreachable_code", "address": "0x401234"},
                {"type": "indirect_call", "address": "0x402456"}
            ],
            "confidence": 0.8
        }

        return result


class DynamicAnalysisAgent(BaseAgent):
    """Agent specialized in dynamic analysis."""

    def _initialize_capabilities(self):
        """Initialize dynamic analysis capabilities."""
        self.capabilities = [
            AgentCapability(
                capability_name="runtime_analysis",
                description="Analyze program behavior during execution",
                input_types=["executable", "process"],
                output_types=["runtime_behavior", "execution_trace"],
                processing_time_estimate=30.0,
                confidence_level=0.85
            ),
            AgentCapability(
                capability_name="memory_analysis",
                description="Analyze memory usage and heap/stack behavior",
                input_types=["process", "memory_dump"],
                output_types=["memory_report", "heap_analysis"],
                processing_time_estimate=20.0,
                confidence_level=0.8
            ),
            AgentCapability(
                capability_name="api_monitoring",
                description="Monitor API calls and system interactions",
                input_types=["process", "executable"],
                output_types=["api_trace", "system_interactions"],
                processing_time_estimate=25.0,
                confidence_level=0.9
            )
        ]

    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute dynamic analysis task."""
        task_type = task.task_type
        input_data = task.input_data

        if task_type == "runtime_analysis":
            return await self._analyze_runtime(input_data)
        elif task_type == "memory_analysis":
            return await self._analyze_memory(input_data)
        elif task_type == "api_monitoring":
            return await self._monitor_api_calls(input_data)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _analyze_runtime(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform runtime analysis."""
        executable = input_data.get("executable", "")

        logger.debug(
            f"Runtime analysis agent analyzing executable: {executable}")

        # Simulate runtime analysis
        await asyncio.sleep(10.0)

        result = {
            "execution_time": 5.2,
            "cpu_usage": 15.3,
            "memory_peak": 45.6,
            "file_operations": [
                {"type": "read", "file": "config.ini"},
                {"type": "write", "file": "output.log"}
            ],
            "network_connections": [
                {"host": os.environ.get("API_SERVER_HOST", "api.internal"), "port": 443, "protocol": "HTTPS"}
            ],
            "registry_operations": [
                {"operation": "read", "key": "HKLM\\Software\\Example"}
            ],
            "behavior_patterns": ["license_check", "network_communication"],
            "confidence": 0.85
        }

        return result

    async def _analyze_memory(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform memory analysis."""
        process_id = input_data.get("process_id", 0)

        logger.debug(f"Memory analysis agent analyzing process: {process_id}")

        # Simulate memory analysis
        await asyncio.sleep(8.0)

        result = {
            "heap_usage": 25.6,
            "stack_usage": 2.1,
            "memory_leaks": [],
            "buffer_overflows": [
                {"address": "0x7fff1234", "size": 256, "severity": "high"}
            ],
            "memory_protection": {
                "dep_enabled": True,
                "aslr_enabled": True,
                "stack_canaries": True
            },
            "confidence": 0.8
        }

        return result

    async def _monitor_api_calls(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor API calls."""
        process_id = input_data.get("process_id", 0)

        logger.debug(f"API monitoring agent monitoring process: {process_id}")

        # Simulate API monitoring
        await asyncio.sleep(15.0)

        result = {
            "api_calls": [
                {"function": "CreateFileA", "args": [
                    "config.dat"], "result": "success"},
                {"function": "RegOpenKeyExA", "args": [
                    "HKLM\\Software"], "result": "success"},
                {"function": "InternetConnectA", "args": [
                    os.environ.get("API_SERVER_HOST", "api.internal")], "result": "success"}
            ],
            "suspicious_apis": [
                {"function": "VirtualAlloc", "reason": "executable_memory"},
                {"function": "WriteProcessMemory", "reason": "code_injection"}
            ],
            "protection_bypasses": [
                {"type": "amsi_bypass", "detected": True},
                {"type": "etw_bypass", "detected": False}
            ],
            "confidence": 0.9
        }

        return result


class ReverseEngineeringAgent(BaseAgent):
    """Agent specialized in reverse engineering."""

    def _initialize_capabilities(self):
        """Initialize reverse engineering capabilities."""
        self.capabilities = [
            AgentCapability(
                capability_name="disassembly",
                description="Disassemble binary code",
                input_types=["binary_file", "code_bytes"],
                output_types=["assembly_code", "instruction_analysis"],
                processing_time_estimate=8.0,
                confidence_level=0.9
            ),
            AgentCapability(
                capability_name="decompilation",
                description="Decompile binary to higher-level code",
                input_types=["binary_file", "assembly_code"],
                output_types=["pseudo_code", "function_signatures"],
                processing_time_estimate=20.0,
                confidence_level=0.7
            ),
            AgentCapability(
                capability_name="algorithm_analysis",
                description="Analyze and identify algorithms",
                input_types=["assembly_code", "pseudo_code"],
                output_types=["algorithm_identification",
                              "complexity_analysis"],
                processing_time_estimate=15.0,
                confidence_level=0.8
            )
        ]

    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute reverse engineering task."""
        task_type = task.task_type
        input_data = task.input_data

        if task_type == "disassembly":
            return await self._disassemble_code(input_data)
        elif task_type == "decompilation":
            return await self._decompile_code(input_data)
        elif task_type == "algorithm_analysis":
            return await self._analyze_algorithms(input_data)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _disassemble_code(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Disassemble binary code."""
        binary_data = input_data.get("binary_data", b"")
        start_address = input_data.get("start_address", 0x401000)

        logger.debug(
            f"Disassembly agent processing {len(binary_data)} bytes starting at {hex(start_address)}")

        # Simulate disassembly
        await asyncio.sleep(3.0)

        result = {
            "assembly_instructions": [
                {"address": "0x401000", "instruction": "push ebp", "bytes": "55"},
                {"address": "0x401001", "instruction": "mov ebp, esp", "bytes": "8bec"},
                {"address": "0x401003", "instruction": "sub esp, 20", "bytes": "83ec14"}
            ],
            "function_boundaries": [
                {"start": "0x401000", "end": "0x401050", "name": "main"},
                {"start": "0x401060", "end": "0x4010a0", "name": "validate_license"}
            ],
            "cross_references": [
                {"from": "0x401020", "to": "0x401060", "type": "call"}
            ],
            "confidence": 0.9
        }

        return result

    async def _decompile_code(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Decompile code to higher level."""
        assembly_code = input_data.get("assembly_code", [])

        logger.debug(
            f"Decompilation agent processing {len(assembly_code)} assembly instructions")

        # Simulate decompilation
        await asyncio.sleep(12.0)

        result = {
            "pseudo_code": """
int validate_license(char* license_key) {
    if (license_key == NULL) {
        return 0;
    }

    if (strlen(license_key) < 16) {
        return 0;
    }

    if (strncmp(license_key, "LIC-", 4) != 0) {
        return 0;
    }

    return 1;
}
""",
            "function_signatures": [
                {"name": "validate_license", "parameters": [
                    "char*"], "return_type": "int"},
                {"name": "main", "parameters": [
                    "int", "char**"], "return_type": "int"}
            ],
            "variable_analysis": [
                {"name": "license_key", "type": "char*", "scope": "parameter"},
                {"name": "result", "type": "int", "scope": "local"}
            ],
            "confidence": 0.7
        }

        return result

    async def _analyze_algorithms(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze algorithms in code."""
        code = input_data.get("code", "")

        logger.debug(
            f"Algorithm analysis agent processing {len(code)} characters of code")

        # Simulate algorithm analysis
        await asyncio.sleep(10.0)

        result = {
            "identified_algorithms": [
                {"name": "string_comparison",
                    "complexity": "O(n)", "confidence": 0.9},
                {"name": "basic_validation",
                    "complexity": "O(1)", "confidence": 0.8}
            ],
            "cryptographic_functions": [],
            "obfuscation_techniques": [],
            "optimization_level": "medium",
            "compiler_patterns": ["msvc_2019"],
            "confidence": 0.8
        }

        return result


class MultiAgentSystem:
    """Multi-agent collaboration system."""

    def __init__(self, llm_manager: Optional[LLMManager] = None):
        """Initialize the multi-agent collaboration system.

        Args:
            llm_manager: Optional LLM manager instance. If None, creates a new
                        default LLMManager
        """
        self.llm_manager = llm_manager or LLMManager()
        self.agents: Dict[str, BaseAgent] = {}
        self.message_router = MessageRouter()
        self.task_distributor = TaskDistributor(self)
        self.knowledge_manager = KnowledgeManager()

        # System state
        self.active = False
        self.collaboration_stats = {
            "messages_sent": 0,
            "tasks_distributed": 0,
            "collaborations_successful": 0,
            "knowledge_shares": 0
        }

        logger.info("Multi-agent system initialized")

    def add_agent(self, agent: BaseAgent):
        """Add agent to the system."""
        agent.collaboration_system = self
        self.agents[agent.agent_id] = agent
        self.message_router.register_agent(agent.agent_id, agent.message_queue)

        logger.info(f"Added agent {agent.agent_id} to system")

    def remove_agent(self, agent_id: str):
        """Remove agent from system."""
        if agent_id in self.agents:
            agent = self.agents[agent_id]
            agent.stop()
            del self.agents[agent_id]
            self.message_router.unregister_agent(agent_id)

            logger.info(f"Removed agent {agent_id} from system")

    def start(self):
        """Start the multi-agent system."""
        self.active = True

        # Start all agents
        for agent in self.agents.values():
            agent.start()

        logger.info("Multi-agent system started")

    def stop(self):
        """Stop the multi-agent system."""
        self.active = False

        # Stop all agents
        for agent in self.agents.values():
            agent.stop()

        logger.info("Multi-agent system stopped")

    def route_message(self, message: AgentMessage):
        """Route message between agents."""
        self.message_router.route_message(message)
        self.collaboration_stats["messages_sent"] += 1

    @profile_ai_operation("multi_agent_collaboration")
    async def execute_collaborative_task(self, task: AgentTask) -> CollaborationResult:
        """Execute task using multiple agents."""
        start_time = time.time()
        participating_agents = []

        try:
            # Determine required capabilities
            required_capabilities = self._determine_required_capabilities(task)

            # Find suitable agents
            suitable_agents = self._find_suitable_agents(required_capabilities)

            if not suitable_agents:
                raise ValueError("No suitable agents found for task")

            # Distribute subtasks
            subtasks = self._create_subtasks(task, suitable_agents)

            # Execute subtasks in parallel
            subtask_results = await self._execute_subtasks_parallel(subtasks)

            # Combine results
            combined_result = self._combine_results(subtask_results)

            # Calculate overall confidence
            confidence = self._calculate_combined_confidence(subtask_results)

            execution_time = time.time() - start_time
            participating_agents = [
                agent_id for agent_id, _ in suitable_agents]

            # Record successful collaboration
            self.collaboration_stats["collaborations_successful"] += 1

            result = CollaborationResult(
                task_id=task.task_id,
                success=True,
                result_data=combined_result,
                participating_agents=participating_agents,
                execution_time=execution_time,
                confidence=confidence
            )

            # Share collaboration knowledge
            await self._share_collaboration_knowledge(task, result)

            return result

        except Exception as e:
            logger.error("Exception in multi_agent_system: %s", e)
            execution_time = time.time() - start_time

            return CollaborationResult(
                task_id=task.task_id,
                success=False,
                result_data={},
                participating_agents=participating_agents,
                execution_time=execution_time,
                confidence=0.0,
                errors=[str(e)]
            )

    def _determine_required_capabilities(self, task: AgentTask) -> List[str]:
        """Determine required capabilities for task."""
        task_type = task.task_type

        capability_map = {
            "binary_analysis": ["binary_analysis", "disassembly"],
            "vulnerability_assessment": ["static_analysis", "dynamic_analysis", "code_analysis"],
            "reverse_engineering": ["disassembly", "decompilation", "algorithm_analysis"],
            "comprehensive_analysis": ["binary_analysis", "runtime_analysis", "disassembly"]
        }

        return capability_map.get(task_type, [task_type])

    def _find_suitable_agents(self, required_capabilities: List[str]) -> List[Tuple[str, BaseAgent]]:
        """Find agents with required capabilities."""
        suitable_agents = []

        for agent_id, agent in self.agents.items():
            if not agent.active or agent.busy:
                continue

            agent_capabilities = [
                cap.capability_name for cap in agent.capabilities]

            # Check if agent has any required capability
            if any(cap in agent_capabilities for cap in required_capabilities):
                suitable_agents.append((agent_id, agent))

        # Sort by agent performance (success rate, avg execution time)
        suitable_agents.sort(key=lambda x: (
            x[1].tasks_completed /
            max(1, x[1].tasks_completed + x[1].tasks_failed),
            -x[1].total_execution_time / max(1, x[1].tasks_completed)
        ), reverse=True)

        return suitable_agents

    def _create_subtasks(self, main_task: AgentTask, suitable_agents: List[Tuple[str, BaseAgent]]) -> List[Tuple[str, AgentTask]]:
        """Create subtasks for agents."""
        subtasks = []

        for agent_id, agent in suitable_agents:
            # Create subtask based on agent capabilities
            for capability in agent.capabilities:
                if capability.capability_name in main_task.task_type or any(
                    cap_type in main_task.task_type for cap_type in capability.input_types
                ):
                    subtask = AgentTask(
                        task_id=f"{main_task.task_id}_{agent_id}",
                        task_type=capability.capability_name,
                        description=f"Subtask: {capability.description}",
                        input_data=main_task.input_data,
                        priority=main_task.priority,
                        context=main_task.context,
                        metadata={**main_task.metadata,
                                  "parent_task": main_task.task_id}
                    )
                    subtasks.append((agent_id, subtask))
                    break

        return subtasks

    async def _execute_subtasks_parallel(self, subtasks: List[Tuple[str, AgentTask]]) -> Dict[str, Dict[str, Any]]:
        """Execute subtasks in parallel."""
        async def execute_subtask(agent_id: str, subtask: AgentTask) -> Tuple[str, Dict[str, Any]]:
            agent = self.agents[agent_id]
            try:
                result = await agent.execute_task(subtask)
                return agent_id, {"success": True, "result": result}
            except Exception as e:
                logger.error("Exception in multi_agent_system: %s", e)
                return agent_id, {"success": False, "error": str(e)}

        # Execute all subtasks concurrently
        tasks = [execute_subtask(agent_id, subtask)
                 for agent_id, subtask in subtasks]
        results = await asyncio.gather(*tasks)

        return dict(results)

    def _combine_results(self, subtask_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Combine results from multiple agents."""
        combined = {
            "agent_results": {},
            "unified_analysis": {},
            "cross_validated_findings": []
        }

        successful_results = {}
        for agent_id, result_data in subtask_results.items():
            if result_data.get("success", False):
                successful_results[agent_id] = result_data["result"]
                combined["agent_results"][agent_id] = result_data["result"]

        # Create unified analysis
        if successful_results:
            combined["unified_analysis"] = self._create_unified_analysis(
                successful_results)
            combined["cross_validated_findings"] = self._cross_validate_findings(
                successful_results)

        return combined

    def _create_unified_analysis(self, results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Create unified analysis from multiple agent results."""
        unified = {
            "overall_assessment": "analysis_complete",
            "confidence_scores": {},
            "combined_findings": [],
            "recommendations": []
        }

        # Combine confidence scores
        for agent_id, result in results.items():
            if "confidence" in result:
                unified["confidence_scores"][agent_id] = result["confidence"]

        # Extract common findings
        all_findings = []
        for result in results.values():
            if "findings" in result:
                all_findings.extend(result["findings"])
            elif isinstance(result, dict):
                # Extract potential findings from result structure
                for key, value in result.items():
                    if "vulnerabilities" in key or "issues" in key or "problems" in key:
                        if isinstance(value, list):
                            all_findings.extend(value)

        unified["combined_findings"] = all_findings

        return unified

    def _cross_validate_findings(self, results: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Cross-validate findings between agents."""
        validated_findings = []

        # Simple cross-validation: look for common patterns
        finding_patterns = defaultdict(list)

        for agent_id, result in results.items():
            # Extract patterns from each result
            patterns = self._extract_patterns(result)
            for pattern in patterns:
                finding_patterns[pattern].append(agent_id)

        # Findings confirmed by multiple agents
        for pattern, confirming_agents in finding_patterns.items():
            if len(confirming_agents) >= 2:
                validated_findings.append({
                    "pattern": pattern,
                    "confirmed_by": confirming_agents,
                    "confidence": len(confirming_agents) / len(results)
                })

        return validated_findings

    def _extract_patterns(self, result: Dict[str, Any]) -> List[str]:
        """Extract patterns from agent result."""
        patterns = []

        # Extract patterns based on result structure
        if "behavior_patterns" in result:
            patterns.extend(result["behavior_patterns"])

        if "potential_vulnerabilities" in result:
            for vuln in result["potential_vulnerabilities"]:
                if isinstance(vuln, dict) and "type" in vuln:
                    patterns.append(f"vulnerability_{vuln['type']}")

        if "suspicious_apis" in result:
            for api in result["suspicious_apis"]:
                if isinstance(api, dict) and "reason" in api:
                    patterns.append(f"suspicious_{api['reason']}")

        return patterns

    def _calculate_combined_confidence(self, subtask_results: Dict[str, Dict[str, Any]]) -> float:
        """Calculate combined confidence from multiple agents."""
        confidences = []

        for result_data in subtask_results.values():
            if result_data.get("success", False):
                result = result_data["result"]
                if "confidence" in result:
                    confidences.append(result["confidence"])

        if not confidences:
            return 0.0

        # Use weighted average (could be more sophisticated)
        return sum(confidences) / len(confidences)

    async def _share_collaboration_knowledge(self, task: AgentTask, result: CollaborationResult):
        """Share knowledge gained from collaboration."""
        knowledge = {
            "collaboration_pattern": {
                "task_type": task.task_type,
                "participating_agents": result.participating_agents,
                "execution_time": result.execution_time,
                "success": result.success,
                "confidence": result.confidence
            },
            "effective_combinations": result.participating_agents if result.success else []
        }

        # Share with all agents that participated
        for agent_id in result.participating_agents:
            if agent_id in self.agents:
                agent = self.agents[agent_id]
                agent.share_knowledge(knowledge)

        self.collaboration_stats["knowledge_shares"] += 1

    def get_system_status(self) -> Dict[str, Any]:
        """Get multi-agent system status."""
        agent_statuses = {}
        for agent_id, agent in self.agents.items():
            agent_statuses[agent_id] = agent.get_agent_status()

        return {
            "active": self.active,
            "total_agents": len(self.agents),
            "active_agents": len([a for a in self.agents.values() if a.active]),
            "busy_agents": len([a for a in self.agents.values() if a.busy]),
            "collaboration_stats": self.collaboration_stats,
            "agents": agent_statuses
        }


class MessageRouter:
    """Routes messages between agents."""

    def __init__(self):
        """Initialize the message router for agent communication."""
        self.agent_queues: Dict[str, Queue] = {}
        self.message_log: deque = deque(maxlen=1000)

    def register_agent(self, agent_id: str, message_queue: Queue):
        """Register agent message queue."""
        self.agent_queues[agent_id] = message_queue

    def unregister_agent(self, agent_id: str):
        """Unregister agent."""
        if agent_id in self.agent_queues:
            del self.agent_queues[agent_id]

    def route_message(self, message: AgentMessage):
        """Route message to target agent."""
        if message.recipient_id in self.agent_queues:
            self.agent_queues[message.recipient_id].put(message)
            self.message_log.append({
                "timestamp": message.timestamp,
                "from": message.sender_id,
                "to": message.recipient_id,
                "type": message.message_type.value,
                "message_id": message.message_id
            })
        else:
            logger.warning(f"No route found for agent {message.recipient_id}")


class TaskDistributor:
    """Distributes tasks among agents."""

    def __init__(self, multi_agent_system: MultiAgentSystem):
        """Initialize the task distributor.

        Args:
            multi_agent_system: The parent multi-agent system that manages
                              agents and coordination
        """
        self.system = multi_agent_system
        self.task_queue: PriorityQueue = PriorityQueue()
        self.load_balancer = LoadBalancer()

    def distribute_task(self, task: AgentTask) -> str:
        """Distribute task to appropriate agent."""
        # Find best agent for task
        best_agent = self._find_best_agent(task)

        if best_agent:
            # Send task to agent
            message = AgentMessage(
                message_id=str(uuid.uuid4()),
                sender_id="task_distributor",
                recipient_id=best_agent.agent_id,
                message_type=MessageType.TASK_REQUEST,
                content={
                    "task_id": task.task_id,
                    "task": {
                        "type": task.task_type,
                        "description": task.description,
                        "input": task.input_data,
                        "priority": task.priority.value,
                        "context": task.context,
                        "metadata": task.metadata
                    }
                },
                priority=task.priority,
                requires_response=True
            )

            self.system.route_message(message)
            return best_agent.agent_id

        return ""

    def _find_best_agent(self, task: AgentTask) -> Optional[BaseAgent]:
        """Find best agent for task."""
        suitable_agents = []

        for agent in self.system.agents.values():
            if not agent.active or agent.busy:
                continue

            # Check if agent can handle task
            if agent._can_execute_task({"type": task.task_type}):
                score = self._calculate_agent_score(agent, task)
                suitable_agents.append((score, agent))

        if suitable_agents:
            # Return agent with highest score
            suitable_agents.sort(reverse=True)
            return suitable_agents[0][1]

        return None

    def _calculate_agent_score(self, agent: BaseAgent, task: AgentTask) -> float:
        """Calculate agent suitability score for task."""
        score = 0.0

        # Base score from success rate
        success_rate = agent.tasks_completed / \
            max(1, agent.tasks_completed + agent.tasks_failed)
        score += success_rate * 40

        # Performance score (inverse of avg execution time)
        avg_time = agent.total_execution_time / max(1, agent.tasks_completed)
        if avg_time > 0:
            score += min(20, 20 / avg_time)

        # Capability match score
        for capability in agent.capabilities:
            if task.task_type in capability.input_types or task.task_type == capability.capability_name:
                score += capability.confidence_level * 30

        # Recency score (more recent activity is better)
        time_since_activity = (
            datetime.now() - agent.last_activity).total_seconds()
        score += max(0, 10 - (time_since_activity / 3600))  # Decay over hours

        return score


class LoadBalancer:
    """Load balancer for agent tasks."""

    def __init__(self):
        """Initialize the load balancer for distributing tasks among agents."""
        self.agent_loads: Dict[str, float] = {}
        self.load_history: deque = deque(maxlen=100)

    def update_agent_load(self, agent_id: str, load: float):
        """Update agent load."""
        self.agent_loads[agent_id] = load
        self.load_history.append({
            "timestamp": datetime.now(),
            "agent_id": agent_id,
            "load": load
        })

    def get_least_loaded_agent(self, available_agents: List[str]) -> Optional[str]:
        """Get least loaded agent from available agents."""
        if not available_agents:
            return None

        min_load = float("inf")
        best_agent = None

        for agent_id in available_agents:
            load = self.agent_loads.get(agent_id, 0.0)
            if load < min_load:
                min_load = load
                best_agent = agent_id

        return best_agent


class KnowledgeManager:
    """Manages shared knowledge between agents."""

    def __init__(self):
        """Initialize the knowledge manager for sharing information between agents."""
        self.shared_knowledge: Dict[str, Dict[str, Any]] = {}
        self.knowledge_graph: Dict[str, Set[str]] = defaultdict(set)
        self.access_patterns: Dict[str, int] = defaultdict(int)

    def store_knowledge(self, category: str, key: str, value: Any, source_agent: str):
        """Store knowledge from agent."""
        if category not in self.shared_knowledge:
            self.shared_knowledge[category] = {}

        self.shared_knowledge[category][key] = {
            "value": value,
            "source": source_agent,
            "timestamp": datetime.now(),
            "access_count": 0
        }

        logger.debug(
            f"Knowledge stored in {category}:{key} by agent {source_agent}")

        # Update knowledge graph
        self.knowledge_graph[source_agent].add(f"{category}:{key}")

    def retrieve_knowledge(self, category: str, key: str, requesting_agent: str) -> Optional[Any]:
        """Retrieve knowledge for agent."""
        if category in self.shared_knowledge and key in self.shared_knowledge[category]:
            knowledge_item = self.shared_knowledge[category][key]
            knowledge_item["access_count"] += 1
            self.access_patterns[f"{category}:{key}"] += 1

            logger.debug(
                f"Knowledge retrieved from {category}:{key} by agent {requesting_agent}")
            return knowledge_item["value"]

        logger.debug(
            f"Knowledge not found for {category}:{key} requested by agent {requesting_agent}")
        return None

    def get_related_knowledge(self, category: str, requesting_agent: str) -> Dict[str, Any]:
        """Get all knowledge in category."""
        logger.debug(
            f"Agent '{requesting_agent}' requesting knowledge from category '{category}'")
        if category in self.shared_knowledge:
            return {k: v["value"] for k, v in self.shared_knowledge[category].items()}
        return {}


# Global multi-agent system instance
global_multi_agent_system = MultiAgentSystem()
