"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Fuzzing campaign orchestrator with multi-agent coordination for managing
complex fuzzing workflows and coordinating multiple fuzzing strategies.
"""

import asyncio
import json
import os
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from intellicrack.utils.logger import logger

try:
    from .fuzzing_engine import FuzzingEngine, FuzzingStrategy, FuzzingStats
    from .test_case_generator import TestCaseGenerator, GenerationStrategy
    from .neural_fuzzer import NeuralFuzzer, NetworkArchitecture
    from .coverage_tracker import CoverageTracker
    from .crash_analyzer import CrashAnalyzer
    FUZZING_AVAILABLE = True
except ImportError:
    FUZZING_AVAILABLE = False
    logger.warning("Fuzzing components not available")

try:
    from ...ai.multi_agent_system import MultiAgentSystem
    from ...ai.llm_backends import LLMBackends
    from ...ai.predictive_intelligence import PredictiveIntelligence
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False


class CampaignPhase(Enum):
    """Fuzzing campaign phases."""
    INITIALIZATION = "initialization"
    DISCOVERY = "discovery"
    EXPLORATION = "exploration"
    EXPLOITATION = "exploitation"
    REFINEMENT = "refinement"
    REPORTING = "reporting"
    COMPLETED = "completed"
    PAUSED = "paused"
    FAILED = "failed"


class AgentRole(Enum):
    """Multi-agent roles in fuzzing campaign."""
    COORDINATOR = "coordinator"
    STRATEGY_SELECTOR = "strategy_selector"
    COVERAGE_ANALYZER = "coverage_analyzer"
    CRASH_INVESTIGATOR = "crash_investigator"
    MUTATION_OPTIMIZER = "mutation_optimizer"
    NEURAL_TRAINER = "neural_trainer"
    PERFORMANCE_MONITOR = "performance_monitor"
    SAFETY_ENFORCER = "safety_enforcer"


class Priority(Enum):
    """Task priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class CampaignConfig:
    """Configuration for fuzzing campaign."""
    target_path: str
    target_args: List[str] = field(default_factory=list)
    timeout: int = 3600  # 1 hour default
    max_iterations: int = 10000
    max_crashes: int = 100
    coverage_target: float = 0.8
    strategies: List[FuzzingStrategy] = field(default_factory=lambda: [FuzzingStrategy.RANDOM])
    parallel_workers: int = 4
    use_neural_fuzzing: bool = True
    use_multi_agent: bool = True
    safety_checks: bool = True
    auto_scaling: bool = True


@dataclass
class AgentTask:
    """Task for multi-agent execution."""
    task_id: str
    agent_role: AgentRole
    task_type: str
    priority: Priority
    payload: Dict[str, Any]
    created_at: float
    deadline: Optional[float] = None
    dependencies: List[str] = field(default_factory=list)
    assigned_to: Optional[str] = None
    status: str = "pending"
    result: Optional[Any] = None


@dataclass
class CampaignMetrics:
    """Metrics for fuzzing campaign."""
    start_time: float
    end_time: Optional[float] = None
    total_executions: int = 0
    total_crashes: int = 0
    unique_crashes: int = 0
    coverage_achieved: float = 0.0
    strategies_used: List[str] = field(default_factory=list)
    agent_coordination_count: int = 0
    neural_generations: int = 0
    average_exec_time: float = 0.0
    total_data_generated: int = 0


@dataclass
class CampaignStatus:
    """Current status of fuzzing campaign."""
    campaign_id: str
    phase: CampaignPhase
    progress: float
    active_workers: int
    active_agents: int
    pending_tasks: int
    completed_tasks: int
    current_strategy: Optional[FuzzingStrategy]
    last_crash_time: Optional[float] = None
    last_coverage_increase: Optional[float] = None
    estimated_completion: Optional[float] = None


class FuzzingAgent:
    """Base class for fuzzing agents."""
    
    def __init__(self, agent_id: str, role: AgentRole):
        self.agent_id = agent_id
        self.role = role
        self.logger = logger.getChild(f"Agent_{agent_id}")
        self.is_active = False
        self.task_queue = asyncio.Queue()
        self.completed_tasks = []
        self.performance_metrics = {}
        
    async def start(self):
        """Start agent execution."""
        self.is_active = True
        self.logger.info(f"Agent {self.agent_id} ({self.role.value}) started")
        
        while self.is_active:
            try:
                # Get next task with timeout
                task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                await self.execute_task(task)
                self.task_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Agent error: {e}")
                
    async def stop(self):
        """Stop agent execution."""
        self.is_active = False
        self.logger.info(f"Agent {self.agent_id} stopped")
        
    async def assign_task(self, task: AgentTask):
        """Assign task to agent."""
        task.assigned_to = self.agent_id
        task.status = "assigned"
        await self.task_queue.put(task)
        
    async def execute_task(self, task: AgentTask):
        """Execute assigned task."""
        task.status = "executing"
        start_time = time.time()
        
        try:
            result = await self.process_task(task)
            task.result = result
            task.status = "completed"
            self.completed_tasks.append(task)
            
            # Update performance metrics
            execution_time = time.time() - start_time
            self.performance_metrics[task.task_type] = self.performance_metrics.get(task.task_type, 0) + execution_time
            
            self.logger.debug(f"Task {task.task_id} completed in {execution_time:.3f}s")
            
        except Exception as e:
            task.status = "failed"
            task.result = {"error": str(e)}
            self.logger.error(f"Task {task.task_id} failed: {e}")
            
    async def process_task(self, task: AgentTask) -> Any:
        """Process specific task based on agent role."""
        if self.role == AgentRole.COORDINATOR:
            return await self._coordinate_campaign(task)
        elif self.role == AgentRole.STRATEGY_SELECTOR:
            return await self._select_strategy(task)
        elif self.role == AgentRole.COVERAGE_ANALYZER:
            return await self._analyze_coverage(task)
        elif self.role == AgentRole.CRASH_INVESTIGATOR:
            return await self._investigate_crash(task)
        elif self.role == AgentRole.MUTATION_OPTIMIZER:
            return await self._optimize_mutations(task)
        elif self.role == AgentRole.NEURAL_TRAINER:
            return await self._train_neural_model(task)
        elif self.role == AgentRole.PERFORMANCE_MONITOR:
            return await self._monitor_performance(task)
        elif self.role == AgentRole.SAFETY_ENFORCER:
            return await self._enforce_safety(task)
        else:
            return {"status": "unknown_role"}
            
    async def _coordinate_campaign(self, task: AgentTask) -> Dict[str, Any]:
        """Coordinate overall campaign execution."""
        return {"action": "coordination", "status": "active"}
        
    async def _select_strategy(self, task: AgentTask) -> Dict[str, Any]:
        """Select optimal fuzzing strategy."""
        current_metrics = task.payload.get("metrics", {})
        coverage = current_metrics.get("coverage", 0.0)
        
        # Simple strategy selection logic
        if coverage < 0.3:
            strategy = FuzzingStrategy.COVERAGE_GUIDED
        elif coverage < 0.6:
            strategy = FuzzingStrategy.NEURAL_GUIDED
        else:
            strategy = FuzzingStrategy.EVOLUTIONARY
            
        return {"selected_strategy": strategy.value, "reason": f"coverage={coverage:.2f}"}
        
    async def _analyze_coverage(self, task: AgentTask) -> Dict[str, Any]:
        """Analyze coverage data for insights."""
        coverage_data = task.payload.get("coverage_data", {})
        
        insights = {
            "coverage_gaps": [],
            "hot_spots": [],
            "recommendations": []
        }
        
        # Analyze coverage patterns
        if "basic_blocks" in coverage_data:
            total_blocks = coverage_data.get("total_basic_blocks", 1)
            covered_blocks = len(coverage_data["basic_blocks"])
            coverage_ratio = covered_blocks / total_blocks
            
            if coverage_ratio < 0.5:
                insights["recommendations"].append("Increase exploration diversity")
            elif coverage_ratio > 0.8:
                insights["recommendations"].append("Focus on edge case testing")
                
        return insights
        
    async def _investigate_crash(self, task: AgentTask) -> Dict[str, Any]:
        """Investigate crash for exploitability."""
        crash_data = task.payload.get("crash_data", {})
        
        investigation = {
            "exploitability": "unknown",
            "root_cause": "unknown",
            "reproduction_steps": [],
            "mitigation_suggestions": []
        }
        
        # Basic crash analysis
        if "signal" in crash_data:
            signal = crash_data["signal"]
            if signal in [11, "SIGSEGV"]:
                investigation["exploitability"] = "potentially_high"
                investigation["root_cause"] = "memory_corruption"
            elif signal in [6, "SIGABRT"]:
                investigation["exploitability"] = "low"
                investigation["root_cause"] = "assertion_failure"
                
        return investigation
        
    async def _optimize_mutations(self, task: AgentTask) -> Dict[str, Any]:
        """Optimize mutation strategies based on feedback."""
        mutation_stats = task.payload.get("mutation_stats", {})
        
        optimization = {
            "recommended_mutators": [],
            "parameter_adjustments": {},
            "strategy_weights": {}
        }
        
        # Analyze mutation effectiveness
        for mutator, stats in mutation_stats.items():
            success_rate = stats.get("success_rate", 0.0)
            if success_rate > 0.1:
                optimization["recommended_mutators"].append(mutator)
                
        return optimization
        
    async def _train_neural_model(self, task: AgentTask) -> Dict[str, Any]:
        """Train neural fuzzing models."""
        training_data = task.payload.get("training_data", [])
        
        if not training_data:
            return {"status": "no_training_data"}
            
        # Simulate neural training (would use actual NeuralFuzzer in practice)
        await asyncio.sleep(0.1)  # Simulate training time
        
        return {
            "status": "training_completed",
            "samples_trained": len(training_data),
            "estimated_accuracy": 0.75
        }
        
    async def _monitor_performance(self, task: AgentTask) -> Dict[str, Any]:
        """Monitor system performance during fuzzing."""
        current_metrics = task.payload.get("metrics", {})
        
        performance = {
            "cpu_usage": "normal",
            "memory_usage": "normal",
            "disk_usage": "normal",
            "recommendations": []
        }
        
        # Basic performance analysis
        exec_rate = current_metrics.get("executions_per_second", 0)
        if exec_rate < 10:
            performance["recommendations"].append("Consider reducing worker count")
        elif exec_rate > 1000:
            performance["recommendations"].append("System performing well")
            
        return performance
        
    async def _enforce_safety(self, task: AgentTask) -> Dict[str, Any]:
        """Enforce safety constraints during fuzzing."""
        safety_data = task.payload.get("safety_data", {})
        
        safety_status = {
            "status": "safe",
            "violations": [],
            "actions_taken": []
        }
        
        # Check safety constraints
        resource_usage = safety_data.get("resource_usage", {})
        if resource_usage.get("memory_mb", 0) > 8000:
            safety_status["status"] = "warning"
            safety_status["violations"].append("High memory usage")
            safety_status["actions_taken"].append("Recommend scaling down")
            
        return safety_status


class FuzzingOrchestrator:
    """Main orchestrator for managing fuzzing campaigns with multi-agent coordination."""
    
    def __init__(self):
        self.logger = logger.getChild("FuzzingOrchestrator")
        
        # Core components
        self.fuzzing_engine = None
        self.test_generator = None
        self.neural_fuzzer = None
        self.coverage_tracker = None
        self.crash_analyzer = None
        
        # Multi-agent system
        self.agents: Dict[str, FuzzingAgent] = {}
        self.task_dispatcher = None
        self.coordination_loop_task = None
        
        # AI integration
        self.llm_backends = None
        self.multi_agent_system = None
        self.predictive_intelligence = None
        
        # Campaign management
        self.active_campaigns: Dict[str, Dict[str, Any]] = {}
        self.campaign_history = []
        
        # Performance tracking
        self.orchestrator_metrics = {
            "total_campaigns": 0,
            "successful_campaigns": 0,
            "total_coordination_events": 0,
            "average_campaign_duration": 0.0
        }
        
        self._initialize_components()
        
    def _initialize_components(self):
        """Initialize fuzzing and AI components."""
        try:
            if FUZZING_AVAILABLE:
                self.fuzzing_engine = FuzzingEngine()
                self.test_generator = TestCaseGenerator()
                self.neural_fuzzer = NeuralFuzzer()
                self.coverage_tracker = CoverageTracker()
                self.crash_analyzer = CrashAnalyzer()
                
            if AI_AVAILABLE:
                self.llm_backends = LLMBackends()
                self.multi_agent_system = MultiAgentSystem()
                self.predictive_intelligence = PredictiveIntelligence()
                
            self.logger.info("Orchestrator components initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            
    async def create_campaign(self, campaign_id: str, config: CampaignConfig) -> bool:
        """Create and start new fuzzing campaign."""
        if campaign_id in self.active_campaigns:
            self.logger.error(f"Campaign {campaign_id} already exists")
            return False
            
        try:
            # Validate configuration
            if not os.path.exists(config.target_path):
                self.logger.error(f"Target not found: {config.target_path}")
                return False
                
            # Initialize campaign
            campaign_data = {
                "id": campaign_id,
                "config": config,
                "status": CampaignStatus(
                    campaign_id=campaign_id,
                    phase=CampaignPhase.INITIALIZATION,
                    progress=0.0,
                    active_workers=0,
                    active_agents=0,
                    pending_tasks=0,
                    completed_tasks=0,
                    current_strategy=None
                ),
                "metrics": CampaignMetrics(start_time=time.time()),
                "agents": {},
                "tasks": [],
                "created_at": time.time()
            }
            
            self.active_campaigns[campaign_id] = campaign_data
            
            # Initialize agents for this campaign
            if config.use_multi_agent:
                await self._initialize_campaign_agents(campaign_id)
                
            # Start campaign execution
            asyncio.create_task(self._execute_campaign(campaign_id))
            
            self.orchestrator_metrics["total_campaigns"] += 1
            self.logger.info(f"Campaign {campaign_id} created and started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create campaign {campaign_id}: {e}")
            return False
            
    async def _initialize_campaign_agents(self, campaign_id: str):
        """Initialize agents for campaign."""
        agent_roles = [
            AgentRole.COORDINATOR,
            AgentRole.STRATEGY_SELECTOR,
            AgentRole.COVERAGE_ANALYZER,
            AgentRole.CRASH_INVESTIGATOR,
            AgentRole.MUTATION_OPTIMIZER
        ]
        
        campaign_data = self.active_campaigns[campaign_id]
        
        for role in agent_roles:
            agent_id = f"{campaign_id}_{role.value}"
            agent = FuzzingAgent(agent_id, role)
            
            campaign_data["agents"][agent_id] = agent
            campaign_data["status"].active_agents += 1
            
            # Start agent
            asyncio.create_task(agent.start())
            
        self.logger.info(f"Initialized {len(agent_roles)} agents for campaign {campaign_id}")
        
    async def _execute_campaign(self, campaign_id: str):
        """Execute fuzzing campaign with agent coordination."""
        campaign_data = self.active_campaigns[campaign_id]
        config = campaign_data["config"]
        status = campaign_data["status"]
        
        try:
            # Phase 1: Discovery
            status.phase = CampaignPhase.DISCOVERY
            await self._discovery_phase(campaign_id)
            
            # Phase 2: Exploration
            status.phase = CampaignPhase.EXPLORATION
            await self._exploration_phase(campaign_id)
            
            # Phase 3: Exploitation
            status.phase = CampaignPhase.EXPLOITATION
            await self._exploitation_phase(campaign_id)
            
            # Phase 4: Refinement
            status.phase = CampaignPhase.REFINEMENT
            await self._refinement_phase(campaign_id)
            
            # Phase 5: Reporting
            status.phase = CampaignPhase.REPORTING
            await self._reporting_phase(campaign_id)
            
            status.phase = CampaignPhase.COMPLETED
            status.progress = 1.0
            
            self.orchestrator_metrics["successful_campaigns"] += 1
            self.logger.info(f"Campaign {campaign_id} completed successfully")
            
        except Exception as e:
            status.phase = CampaignPhase.FAILED
            self.logger.error(f"Campaign {campaign_id} failed: {e}")
            
        finally:
            # Cleanup
            await self._cleanup_campaign(campaign_id)
            
    async def _discovery_phase(self, campaign_id: str):
        """Discovery phase: Initial target analysis and strategy selection."""
        campaign_data = self.active_campaigns[campaign_id]
        config = campaign_data["config"]
        
        # Task: Analyze target binary
        task = AgentTask(
            task_id=f"{campaign_id}_discovery_analyze",
            agent_role=AgentRole.COORDINATOR,
            task_type="analyze_target",
            priority=Priority.HIGH,
            payload={"target_path": config.target_path},
            created_at=time.time()
        )
        
        await self._dispatch_task(campaign_id, task)
        
        # Task: Select initial strategy
        strategy_task = AgentTask(
            task_id=f"{campaign_id}_discovery_strategy",
            agent_role=AgentRole.STRATEGY_SELECTOR,
            task_type="select_initial_strategy",
            priority=Priority.HIGH,
            payload={"target_info": {"type": "binary"}},
            created_at=time.time()
        )
        
        await self._dispatch_task(campaign_id, strategy_task)
        
        # Wait for discovery tasks to complete
        await asyncio.sleep(1.0)
        
        campaign_data["status"].progress = 0.2
        self.logger.info(f"Discovery phase completed for campaign {campaign_id}")
        
    async def _exploration_phase(self, campaign_id: str):
        """Exploration phase: Broad coverage gathering."""
        campaign_data = self.active_campaigns[campaign_id]
        
        # Task: Start coverage-guided fuzzing
        coverage_task = AgentTask(
            task_id=f"{campaign_id}_exploration_coverage",
            agent_role=AgentRole.COVERAGE_ANALYZER,
            task_type="track_coverage",
            priority=Priority.HIGH,
            payload={"phase": "exploration"},
            created_at=time.time()
        )
        
        await self._dispatch_task(campaign_id, coverage_task)
        
        # Start fuzzing workers
        if self.fuzzing_engine:
            # Simplified fuzzing execution
            await asyncio.sleep(2.0)  # Simulate fuzzing time
            
        campaign_data["status"].progress = 0.5
        self.logger.info(f"Exploration phase completed for campaign {campaign_id}")
        
    async def _exploitation_phase(self, campaign_id: str):
        """Exploitation phase: Targeted vulnerability discovery."""
        campaign_data = self.active_campaigns[campaign_id]
        
        # Task: Optimize mutations based on findings
        mutation_task = AgentTask(
            task_id=f"{campaign_id}_exploitation_mutations",
            agent_role=AgentRole.MUTATION_OPTIMIZER,
            task_type="optimize_mutations",
            priority=Priority.HIGH,
            payload={"mutation_stats": {}},
            created_at=time.time()
        )
        
        await self._dispatch_task(campaign_id, mutation_task)
        
        # Task: Train neural models if enabled
        if campaign_data["config"].use_neural_fuzzing:
            neural_task = AgentTask(
                task_id=f"{campaign_id}_exploitation_neural",
                agent_role=AgentRole.NEURAL_TRAINER,
                task_type="train_model",
                priority=Priority.MEDIUM,
                payload={"training_data": []},
                created_at=time.time()
            )
            
            await self._dispatch_task(campaign_id, neural_task)
            
        campaign_data["status"].progress = 0.8
        self.logger.info(f"Exploitation phase completed for campaign {campaign_id}")
        
    async def _refinement_phase(self, campaign_id: str):
        """Refinement phase: Deep analysis of findings."""
        campaign_data = self.active_campaigns[campaign_id]
        
        # Task: Investigate any crashes found
        crash_task = AgentTask(
            task_id=f"{campaign_id}_refinement_crashes",
            agent_role=AgentRole.CRASH_INVESTIGATOR,
            task_type="investigate_crashes",
            priority=Priority.CRITICAL,
            payload={"crash_data": {}},
            created_at=time.time()
        )
        
        await self._dispatch_task(campaign_id, crash_task)
        
        campaign_data["status"].progress = 0.9
        self.logger.info(f"Refinement phase completed for campaign {campaign_id}")
        
    async def _reporting_phase(self, campaign_id: str):
        """Reporting phase: Generate comprehensive reports."""
        campaign_data = self.active_campaigns[campaign_id]
        
        # Generate campaign report
        report = await self._generate_campaign_report(campaign_id)
        campaign_data["final_report"] = report
        
        campaign_data["status"].progress = 1.0
        self.logger.info(f"Reporting phase completed for campaign {campaign_id}")
        
    async def _dispatch_task(self, campaign_id: str, task: AgentTask):
        """Dispatch task to appropriate agent."""
        campaign_data = self.active_campaigns[campaign_id]
        agents = campaign_data["agents"]
        
        # Find agent with matching role
        target_agent = None
        for agent in agents.values():
            if agent.role == task.agent_role and agent.is_active:
                target_agent = agent
                break
                
        if target_agent:
            await target_agent.assign_task(task)
            campaign_data["tasks"].append(task)
            campaign_data["status"].pending_tasks += 1
            
            self.orchestrator_metrics["total_coordination_events"] += 1
            self.logger.debug(f"Task {task.task_id} dispatched to agent {target_agent.agent_id}")
        else:
            self.logger.warning(f"No available agent for role {task.agent_role.value}")
            
    async def _cleanup_campaign(self, campaign_id: str):
        """Clean up campaign resources."""
        if campaign_id not in self.active_campaigns:
            return
            
        campaign_data = self.active_campaigns[campaign_id]
        
        # Stop all agents
        for agent in campaign_data["agents"].values():
            await agent.stop()
            
        # Update metrics
        campaign_data["metrics"].end_time = time.time()
        duration = campaign_data["metrics"].end_time - campaign_data["metrics"].start_time
        
        # Update orchestrator metrics
        total_campaigns = self.orchestrator_metrics["total_campaigns"]
        current_avg = self.orchestrator_metrics["average_campaign_duration"]
        self.orchestrator_metrics["average_campaign_duration"] = (
            (current_avg * (total_campaigns - 1) + duration) / total_campaigns
        )
        
        # Move to history
        self.campaign_history.append(campaign_data)
        del self.active_campaigns[campaign_id]
        
        self.logger.info(f"Campaign {campaign_id} cleaned up")
        
    async def _generate_campaign_report(self, campaign_id: str) -> Dict[str, Any]:
        """Generate comprehensive campaign report."""
        campaign_data = self.active_campaigns[campaign_id]
        
        report = {
            "campaign_id": campaign_id,
            "config": campaign_data["config"].__dict__,
            "status": campaign_data["status"].__dict__,
            "metrics": campaign_data["metrics"].__dict__,
            "duration": time.time() - campaign_data["metrics"].start_time,
            "tasks_completed": len([t for t in campaign_data["tasks"] if t.status == "completed"]),
            "total_tasks": len(campaign_data["tasks"]),
            "agent_performance": {},
            "recommendations": [],
            "generated_at": datetime.now().isoformat()
        }
        
        # Agent performance summary
        for agent_id, agent in campaign_data["agents"].items():
            report["agent_performance"][agent_id] = {
                "role": agent.role.value,
                "completed_tasks": len(agent.completed_tasks),
                "performance_metrics": agent.performance_metrics
            }
            
        # Generate recommendations
        if campaign_data["metrics"].total_crashes > 0:
            report["recommendations"].append("Investigate crashes for exploitability")
        if campaign_data["metrics"].coverage_achieved < 0.5:
            report["recommendations"].append("Consider longer fuzzing duration for better coverage")
            
        return report
        
    def get_campaign_status(self, campaign_id: str) -> Optional[CampaignStatus]:
        """Get current status of campaign."""
        if campaign_id in self.active_campaigns:
            return self.active_campaigns[campaign_id]["status"]
        return None
        
    def list_active_campaigns(self) -> List[str]:
        """List all active campaign IDs."""
        return list(self.active_campaigns.keys())
        
    async def pause_campaign(self, campaign_id: str) -> bool:
        """Pause active campaign."""
        if campaign_id not in self.active_campaigns:
            return False
            
        campaign_data = self.active_campaigns[campaign_id]
        campaign_data["status"].phase = CampaignPhase.PAUSED
        
        # Pause all agents
        for agent in campaign_data["agents"].values():
            agent.is_active = False
            
        self.logger.info(f"Campaign {campaign_id} paused")
        return True
        
    async def resume_campaign(self, campaign_id: str) -> bool:
        """Resume paused campaign."""
        if campaign_id not in self.active_campaigns:
            return False
            
        campaign_data = self.active_campaigns[campaign_id]
        if campaign_data["status"].phase != CampaignPhase.PAUSED:
            return False
            
        # Resume agents
        for agent in campaign_data["agents"].values():
            agent.is_active = True
            asyncio.create_task(agent.start())
            
        campaign_data["status"].phase = CampaignPhase.EXPLORATION  # Resume from exploration
        self.logger.info(f"Campaign {campaign_id} resumed")
        return True
        
    async def abort_campaign(self, campaign_id: str) -> bool:
        """Abort active campaign."""
        if campaign_id not in self.active_campaigns:
            return False
            
        campaign_data = self.active_campaigns[campaign_id]
        campaign_data["status"].phase = CampaignPhase.FAILED
        
        await self._cleanup_campaign(campaign_id)
        self.logger.info(f"Campaign {campaign_id} aborted")
        return True
        
    def get_orchestrator_metrics(self) -> Dict[str, Any]:
        """Get orchestrator performance metrics."""
        return {
            **self.orchestrator_metrics,
            "active_campaigns": len(self.active_campaigns),
            "total_agents": sum(len(c["agents"]) for c in self.active_campaigns.values()),
            "components_available": {
                "fuzzing": FUZZING_AVAILABLE,
                "ai": AI_AVAILABLE
            }
        }
        
    def export_campaign_results(self, campaign_id: str, output_dir: str) -> bool:
        """Export campaign results to directory."""
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            # Look in both active and historical campaigns
            campaign_data = None
            if campaign_id in self.active_campaigns:
                campaign_data = self.active_campaigns[campaign_id]
            else:
                campaign_data = next((c for c in self.campaign_history if c["id"] == campaign_id), None)
                
            if not campaign_data:
                self.logger.error(f"Campaign {campaign_id} not found")
                return False
                
            # Export main report
            report_path = os.path.join(output_dir, f"campaign_{campaign_id}_report.json")
            if "final_report" in campaign_data:
                with open(report_path, "w") as f:
                    json.dump(campaign_data["final_report"], f, indent=2, default=str)
                    
            # Export detailed metrics
            metrics_path = os.path.join(output_dir, f"campaign_{campaign_id}_metrics.json")
            with open(metrics_path, "w") as f:
                json.dump(campaign_data["metrics"].__dict__, f, indent=2, default=str)
                
            self.logger.info(f"Campaign {campaign_id} results exported to {output_dir}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export campaign results: {e}")
            return False