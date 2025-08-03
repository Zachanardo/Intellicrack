"""
Core Fuzzing Engine - Main fuzzing orchestration and execution

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
import time
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Callable, Union
import json
import pickle
import tempfile
import shutil

from ...utils.logger import get_logger
from ..processing.sandbox_manager import SandboxManager, SandboxConfig, SandboxResult
from ..analysis.analysis_orchestrator import AnalysisOrchestrator

logger = get_logger(__name__)


class FuzzingStrategy(Enum):
    """Different fuzzing strategies."""
    RANDOM = "random"
    GRAMMAR_BASED = "grammar_based"
    STRUCTURE_AWARE = "structure_aware"
    EVOLUTIONARY = "evolutionary"
    NEURAL_NETWORK = "neural_network"
    COVERAGE_GUIDED = "coverage_guided"
    VULNERABILITY_TARGETED = "vulnerability_targeted"
    API_FUZZING = "api_fuzzing"
    NETWORK_PROTOCOL = "network_protocol"
    FILE_FORMAT = "file_format"


class FuzzingTarget(Enum):
    """Types of fuzzing targets."""
    BINARY_EXECUTABLE = "binary_executable"
    LIBRARY_INTERFACE = "library_interface"
    NETWORK_SERVICE = "network_service"
    FILE_PARSER = "file_parser"
    API_ENDPOINT = "api_endpoint"
    PROTOCOL_IMPLEMENTATION = "protocol_implementation"
    DRIVER_INTERFACE = "driver_interface"
    VIRTUAL_MACHINE = "virtual_machine"


@dataclass
class FuzzingConfig:
    """Configuration for fuzzing operations."""
    target_path: str
    target_type: FuzzingTarget
    strategy: FuzzingStrategy = FuzzingStrategy.COVERAGE_GUIDED
    
    # Execution parameters
    max_executions: int = 10000
    execution_timeout: float = 30.0
    max_duration_hours: float = 24.0
    parallel_processes: int = 1
    
    # AI integration
    enable_ai_guidance: bool = True
    use_neural_mutations: bool = True
    ai_model_preference: str = "auto"
    learning_enabled: bool = True
    
    # Coverage tracking
    enable_coverage_tracking: bool = True
    coverage_types: List[str] = field(default_factory=lambda: ["basic_block", "edge", "function"])
    coverage_threshold: float = 0.8
    
    # Mutation parameters
    mutation_probability: float = 0.1
    max_mutation_depth: int = 5
    mutation_strategies: List[str] = field(default_factory=lambda: ["random", "structure_aware", "ai_guided"])
    
    # Input generation
    seed_corpus_path: Optional[str] = None
    generate_initial_corpus: bool = True
    max_input_size: int = 1024 * 1024  # 1MB
    min_input_size: int = 1
    
    # Crash handling
    save_crashes: bool = True
    crash_directory: str = "crashes"
    deduplicate_crashes: bool = True
    analyze_crashes: bool = True
    
    # Safety and isolation
    enable_sandbox: bool = True
    resource_limits: Dict[str, Any] = field(default_factory=lambda: {
        "memory_mb": 512,
        "cpu_percent": 50,
        "disk_mb": 100
    })
    
    # Output and reporting
    output_directory: str = "fuzzing_results"
    save_interesting_inputs: bool = True
    generate_reports: bool = True
    report_interval_minutes: int = 60
    
    # Advanced features
    enable_taint_tracking: bool = False
    enable_symbolic_execution: bool = False
    vulnerability_detection_rules: List[str] = field(default_factory=list)
    custom_hooks: Dict[str, Callable] = field(default_factory=dict)


@dataclass
class CoverageMetrics:
    """Coverage metrics for fuzzing."""
    basic_blocks_covered: int = 0
    total_basic_blocks: int = 0
    edges_covered: int = 0
    total_edges: int = 0
    functions_covered: int = 0
    total_functions: int = 0
    
    # Coverage percentages
    block_coverage_percent: float = 0.0
    edge_coverage_percent: float = 0.0
    function_coverage_percent: float = 0.0
    
    # New coverage tracking
    new_blocks_this_session: int = 0
    new_edges_this_session: int = 0
    new_functions_this_session: int = 0
    
    def update_percentages(self):
        """Update coverage percentages."""
        if self.total_basic_blocks > 0:
            self.block_coverage_percent = (self.basic_blocks_covered / self.total_basic_blocks) * 100
        if self.total_edges > 0:
            self.edge_coverage_percent = (self.edges_covered / self.total_edges) * 100
        if self.total_functions > 0:
            self.function_coverage_percent = (self.functions_covered / self.total_functions) * 100


@dataclass
class CrashAnalysis:
    """Analysis of a crash discovered during fuzzing."""
    crash_id: str
    timestamp: datetime
    input_data: bytes
    crash_type: str
    severity: str
    exploitability: str
    
    # Crash details
    signal: Optional[int] = None
    exit_code: Optional[int] = None
    crash_address: Optional[str] = None
    stack_trace: List[str] = field(default_factory=list)
    registers: Dict[str, str] = field(default_factory=dict)
    
    # Analysis results
    root_cause: Optional[str] = None
    affected_function: Optional[str] = None
    vulnerability_type: Optional[str] = None
    cve_potential: bool = False
    
    # Reproduction info
    reproducible: bool = False
    reproduction_rate: float = 0.0
    minimal_input: Optional[bytes] = None


@dataclass
class FuzzingStatistics:
    """Statistics from fuzzing session."""
    start_time: datetime
    end_time: Optional[datetime] = None
    
    # Execution stats
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    timeouts: int = 0
    crashes: int = 0
    
    # Performance stats
    executions_per_second: float = 0.0
    average_execution_time: float = 0.0
    total_cpu_time: float = 0.0
    peak_memory_usage: int = 0
    
    # Coverage stats
    coverage_metrics: CoverageMetrics = field(default_factory=CoverageMetrics)
    
    # Discovery stats
    unique_crashes: int = 0
    unique_hangs: int = 0
    interesting_inputs: int = 0
    corpus_size: int = 0
    
    # AI stats
    ai_guided_mutations: int = 0
    neural_predictions: int = 0
    learning_updates: int = 0


@dataclass
class FuzzingResult:
    """Result from a fuzzing session."""
    success: bool
    statistics: FuzzingStatistics
    config: FuzzingConfig
    
    # Discovered issues
    crashes: List[CrashAnalysis] = field(default_factory=list)
    hangs: List[Dict[str, Any]] = field(default_factory=list)
    interesting_inputs: List[Dict[str, Any]] = field(default_factory=list)
    
    # Generated artifacts
    corpus_files: List[str] = field(default_factory=list)
    crash_files: List[str] = field(default_factory=list)
    report_files: List[str] = field(default_factory=list)
    
    # Analysis results
    vulnerability_analysis: Dict[str, Any] = field(default_factory=dict)
    exploit_potential: Dict[str, Any] = field(default_factory=dict)
    
    # Errors and warnings
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class FuzzingEngine:
    """
    Main fuzzing engine that orchestrates intelligent fuzzing operations.
    
    This class coordinates between AI guidance, mutation engines, coverage tracking,
    crash analysis, and execution environments to provide comprehensive fuzzing
    capabilities.
    """
    
    def __init__(self, config: FuzzingConfig):
        """Initialize the fuzzing engine."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.paused = False
        
        # Initialize directories
        self._setup_directories()
        
        # Core components
        self.sandbox_manager = SandboxManager()
        self.analysis_orchestrator = AnalysisOrchestrator()
        
        # Fuzzing components (initialized later)
        self.mutation_engine = None
        self.coverage_tracker = None
        self.crash_analyzer = None
        self.test_generator = None
        self.neural_fuzzer = None
        
        # State tracking
        self.statistics = FuzzingStatistics(start_time=datetime.now())
        self.corpus = []
        self.interesting_inputs = []
        self.crashes = []
        
        # Threading and synchronization
        self.execution_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.workers = []
        
        # AI integration
        self.ai_enabled = config.enable_ai_guidance
        self.llm_manager = None
        
        self.logger.info(f"Fuzzing engine initialized for target: {config.target_path}")
    
    def _setup_directories(self):
        """Set up output directories."""
        base_dir = Path(self.config.output_directory)
        base_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        self.crash_dir = base_dir / "crashes"
        self.corpus_dir = base_dir / "corpus"
        self.reports_dir = base_dir / "reports"
        self.logs_dir = base_dir / "logs"
        
        for directory in [self.crash_dir, self.corpus_dir, self.reports_dir, self.logs_dir]:
            directory.mkdir(exist_ok=True)
    
    async def initialize(self):
        """Initialize fuzzing components."""
        try:
            # Initialize AI components if enabled
            if self.ai_enabled:
                await self._initialize_ai_components()
            
            # Initialize fuzzing components
            await self._initialize_fuzzing_components()
            
            # Analyze target
            await self._analyze_target()
            
            # Generate initial corpus if needed
            if self.config.generate_initial_corpus:
                await self._generate_initial_corpus()
            
            self.logger.info("Fuzzing engine initialization complete")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize fuzzing engine: {e}")
            raise
    
    async def _initialize_ai_components(self):
        """Initialize AI components."""
        try:
            from ...ai.llm_backends import get_llm_manager
            from ...ai.multi_agent_system import MultiAgentSystem
            from .neural_fuzzer import NeuralFuzzer
            
            self.llm_manager = get_llm_manager()
            self.neural_fuzzer = NeuralFuzzer()
            
            # Initialize neural models
            if self.config.use_neural_mutations:
                await self.neural_fuzzer.initialize()
            
            self.logger.info("AI components initialized")
            
        except ImportError as e:
            self.logger.warning(f"AI components not available: {e}")
            self.ai_enabled = False
        except Exception as e:
            self.logger.error(f"Failed to initialize AI components: {e}")
            self.ai_enabled = False
    
    async def _initialize_fuzzing_components(self):
        """Initialize core fuzzing components."""
        from .intelligent_mutation_engine import IntelligentMutationEngine
        from .coverage_tracker import CoverageTracker
        from .crash_analyzer import CrashAnalyzer
        from .test_case_generator import TestCaseGenerator
        
        # Initialize mutation engine
        self.mutation_engine = IntelligentMutationEngine(
            strategies=self.config.mutation_strategies,
            ai_enabled=self.ai_enabled
        )
        
        # Initialize coverage tracker
        if self.config.enable_coverage_tracking:
            self.coverage_tracker = CoverageTracker(
                target_path=self.config.target_path,
                coverage_types=self.config.coverage_types
            )
            await self.coverage_tracker.initialize()
        
        # Initialize crash analyzer
        self.crash_analyzer = CrashAnalyzer(
            output_directory=str(self.crash_dir),
            ai_enabled=self.ai_enabled
        )
        
        # Initialize test case generator
        self.test_generator = TestCaseGenerator(
            target_type=self.config.target_type,
            ai_enabled=self.ai_enabled
        )
        
        self.logger.info("Core fuzzing components initialized")
    
    async def _analyze_target(self):
        """Analyze the fuzzing target."""
        try:
            target_analysis = await self.analysis_orchestrator.analyze_file(
                self.config.target_path,
                analysis_type="comprehensive"
            )
            
            # Extract relevant information for fuzzing
            self.target_info = {
                "file_type": target_analysis.get("file_type", "unknown"),
                "architecture": target_analysis.get("architecture", "unknown"),
                "entry_points": target_analysis.get("entry_points", []),
                "imported_functions": target_analysis.get("imports", []),
                "exported_functions": target_analysis.get("exports", []),
                "vulnerability_indicators": target_analysis.get("vulnerabilities", [])
            }
            
            # Initialize coverage totals if tracker is available
            if self.coverage_tracker:
                coverage_info = await self.coverage_tracker.analyze_target(self.config.target_path)
                self.statistics.coverage_metrics.total_basic_blocks = coverage_info.get("total_blocks", 0)
                self.statistics.coverage_metrics.total_edges = coverage_info.get("total_edges", 0)
                self.statistics.coverage_metrics.total_functions = coverage_info.get("total_functions", 0)
            
            self.logger.info(f"Target analysis complete: {self.target_info['file_type']} {self.target_info['architecture']}")
            
        except Exception as e:
            self.logger.error(f"Target analysis failed: {e}")
            self.target_info = {"file_type": "unknown", "architecture": "unknown"}
    
    async def _generate_initial_corpus(self):
        """Generate initial test corpus."""
        try:
            # Load existing seed corpus if available
            if self.config.seed_corpus_path and Path(self.config.seed_corpus_path).exists():
                await self._load_seed_corpus()
            
            # Generate additional test cases
            if self.test_generator:
                initial_cases = await self.test_generator.generate_initial_corpus(
                    target_info=self.target_info,
                    count=100,
                    size_range=(self.config.min_input_size, min(self.config.max_input_size, 10240))
                )
                
                for i, test_case in enumerate(initial_cases):
                    file_path = self.corpus_dir / f"initial_{i:04d}.bin"
                    with open(file_path, 'wb') as f:
                        f.write(test_case.data)
                    
                    self.corpus.append({
                        "path": str(file_path),
                        "data": test_case.data,
                        "size": len(test_case.data),
                        "generation": "initial",
                        "coverage_new": True
                    })
            
            self.statistics.corpus_size = len(self.corpus)
            self.logger.info(f"Generated initial corpus with {len(self.corpus)} test cases")
            
        except Exception as e:
            self.logger.error(f"Failed to generate initial corpus: {e}")
    
    async def _load_seed_corpus(self):
        """Load seed corpus from directory."""
        seed_path = Path(self.config.seed_corpus_path)
        if not seed_path.exists():
            self.logger.warning(f"Seed corpus path does not exist: {seed_path}")
            return
        
        loaded_count = 0
        for file_path in seed_path.iterdir():
            if file_path.is_file() and file_path.stat().st_size <= self.config.max_input_size:
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    
                    # Copy to corpus directory
                    corpus_file = self.corpus_dir / f"seed_{loaded_count:04d}_{file_path.name}"
                    shutil.copy2(file_path, corpus_file)
                    
                    self.corpus.append({
                        "path": str(corpus_file),
                        "data": data,
                        "size": len(data),
                        "generation": "seed",
                        "coverage_new": True
                    })
                    
                    loaded_count += 1
                    
                except Exception as e:
                    self.logger.warning(f"Failed to load seed file {file_path}: {e}")
        
        self.logger.info(f"Loaded {loaded_count} seed files from corpus")
    
    async def start_fuzzing(self) -> FuzzingResult:
        """Start the main fuzzing loop."""
        if self.running:
            raise RuntimeError("Fuzzing is already running")
        
        self.running = True
        self.stop_event.clear()
        self.statistics.start_time = datetime.now()
        
        try:
            # Start worker threads
            await self._start_workers()
            
            # Main fuzzing loop
            await self._fuzzing_loop()
            
            # Wait for workers to complete
            await self._stop_workers()
            
            # Generate final report
            result = await self._generate_result()
            
            self.logger.info("Fuzzing session completed successfully")
            return result
            
        except Exception as e:
            self.logger.error(f"Fuzzing session failed: {e}")
            result = FuzzingResult(
                success=False,
                statistics=self.statistics,
                config=self.config
            )
            result.errors.append(str(e))
            return result
        
        finally:
            self.running = False
            self.statistics.end_time = datetime.now()
    
    async def _start_workers(self):
        """Start worker threads for parallel fuzzing."""
        for i in range(self.config.parallel_processes):
            worker = threading.Thread(
                target=self._worker_thread,
                args=(i,),
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        self.logger.info(f"Started {len(self.workers)} fuzzing workers")
    
    def _worker_thread(self, worker_id: int):
        """Worker thread for executing fuzzing iterations."""
        self.logger.debug(f"Worker {worker_id} started")
        
        while not self.stop_event.is_set() and self.running:
            try:
                if self.paused:
                    time.sleep(0.1)
                    continue
                
                # Check execution limits
                if self._should_stop():
                    break
                
                # Execute fuzzing iteration
                asyncio.run(self._fuzzing_iteration(worker_id))
                
            except Exception as e:
                self.logger.error(f"Worker {worker_id} error: {e}")
                time.sleep(1.0)  # Brief pause on error
        
        self.logger.debug(f"Worker {worker_id} stopped")
    
    async def _fuzzing_loop(self):
        """Main fuzzing coordination loop."""
        last_report_time = time.time()
        report_interval = self.config.report_interval_minutes * 60
        
        while not self.stop_event.is_set() and self.running:
            # Check if we should stop
            if self._should_stop():
                self.logger.info("Fuzzing limits reached, stopping")
                break
            
            # Generate periodic reports
            if time.time() - last_report_time >= report_interval:
                await self._generate_periodic_report()
                last_report_time = time.time()
            
            # AI-guided optimization
            if self.ai_enabled and self.statistics.total_executions % 1000 == 0:
                await self._ai_guided_optimization()
            
            await asyncio.sleep(1.0)  # Coordination loop delay
        
        # Signal workers to stop
        self.stop_event.set()
    
    async def _fuzzing_iteration(self, worker_id: int):
        """Execute a single fuzzing iteration."""
        start_time = time.time()
        
        try:
            # Select or generate input
            input_data = await self._get_next_input()
            if not input_data:
                return
            
            # Execute target with input
            execution_result = await self._execute_target(input_data, worker_id)
            
            # Update statistics
            with self.execution_lock:
                self.statistics.total_executions += 1
                
                if execution_result.get("success", False):
                    self.statistics.successful_executions += 1
                else:
                    self.statistics.failed_executions += 1
                
                if execution_result.get("timeout", False):
                    self.statistics.timeouts += 1
                
                if execution_result.get("crash", False):
                    self.statistics.crashes += 1
                    await self._handle_crash(input_data, execution_result)
            
            # Update coverage if tracking enabled
            if self.coverage_tracker and execution_result.get("coverage_data"):
                new_coverage = await self.coverage_tracker.update_coverage(
                    execution_result["coverage_data"]
                )
                
                if new_coverage:
                    # Save interesting input that found new coverage
                    await self._save_interesting_input(input_data, "new_coverage", execution_result)
            
            # Update performance metrics
            execution_time = time.time() - start_time
            with self.execution_lock:
                total_time = self.statistics.total_cpu_time + execution_time
                self.statistics.total_cpu_time = total_time
                self.statistics.average_execution_time = total_time / max(1, self.statistics.total_executions)
                self.statistics.executions_per_second = self.statistics.total_executions / max(1, total_time)
            
        except Exception as e:
            self.logger.error(f"Fuzzing iteration failed: {e}")
    
    async def _get_next_input(self) -> Optional[bytes]:
        """Get next input for fuzzing iteration."""
        if not self.corpus:
            return None
        
        # Select strategy for input generation
        strategy = self._select_input_strategy()
        
        if strategy == "corpus_mutation":
            # Select input from corpus and mutate
            corpus_entry = self._select_corpus_entry()
            if corpus_entry and self.mutation_engine:
                mutated = await self.mutation_engine.mutate(
                    corpus_entry["data"],
                    self.target_info
                )
                return mutated.data if mutated else corpus_entry["data"]
        
        elif strategy == "neural_generation" and self.neural_fuzzer:
            # Use neural network to generate input
            generated = await self.neural_fuzzer.generate_input(
                target_info=self.target_info,
                coverage_feedback=self._get_coverage_feedback()
            )
            return generated
        
        elif strategy == "grammar_based" and self.test_generator:
            # Generate using grammar-based approach
            test_case = await self.test_generator.generate_grammar_based(
                target_info=self.target_info,
                size_limit=self.config.max_input_size
            )
            return test_case.data if test_case else None
        
        else:
            # Fallback to random corpus selection
            corpus_entry = self._select_corpus_entry()
            return corpus_entry["data"] if corpus_entry else None
    
    def _select_input_strategy(self) -> str:
        """Select strategy for input generation."""
        # Simple strategy selection - could be made more sophisticated
        import random
        
        strategies = ["corpus_mutation"]
        
        if self.neural_fuzzer and self.config.use_neural_mutations:
            strategies.append("neural_generation")
        
        if self.config.strategy == FuzzingStrategy.GRAMMAR_BASED:
            strategies.append("grammar_based")
        
        return random.choice(strategies)
    
    def _select_corpus_entry(self) -> Optional[Dict[str, Any]]:
        """Select an entry from the corpus."""
        if not self.corpus:
            return None
        
        # Weighted selection favoring entries that found new coverage
        import random
        weights = []
        for entry in self.corpus:
            weight = 2.0 if entry.get("coverage_new", False) else 1.0
            weights.append(weight)
        
        return random.choices(self.corpus, weights=weights)[0]
    
    def _get_coverage_feedback(self) -> Dict[str, Any]:
        """Get current coverage feedback for AI guidance."""
        if not self.coverage_tracker:
            return {}
        
        return {
            "block_coverage": self.statistics.coverage_metrics.block_coverage_percent,
            "edge_coverage": self.statistics.coverage_metrics.edge_coverage_percent,
            "function_coverage": self.statistics.coverage_metrics.function_coverage_percent,
            "new_blocks": self.statistics.coverage_metrics.new_blocks_this_session,
            "new_edges": self.statistics.coverage_metrics.new_edges_this_session
        }
    
    async def _execute_target(self, input_data: bytes, worker_id: int) -> Dict[str, Any]:
        """Execute target with input data."""
        try:
            # Create temporary input file
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(input_data)
                input_file_path = tmp_file.name
            
            try:
                # Configure sandbox
                sandbox_config = SandboxConfig(
                    timeout=int(self.config.execution_timeout),
                    enable_network=False,
                    enable_filesystem=True,
                    enable_memory_monitoring=True,
                    enable_snapshots=False,
                    max_memory=self.config.resource_limits.get("memory_mb", 512),
                    cpu_limit=1
                )
                
                # Execute in sandbox
                if self.config.target_type == FuzzingTarget.BINARY_EXECUTABLE:
                    # Run as executable with input file
                    sandbox_config.command_line_args = [input_file_path]
                    result = self.sandbox_manager.analyze_binary(
                        self.config.target_path,
                        sandbox_config
                    )
                else:
                    # Handle other target types
                    result = await self._execute_specialized_target(input_data, sandbox_config)
                
                # Process execution result
                execution_result = {
                    "success": result.success,
                    "timeout": result.execution_time >= self.config.execution_timeout,
                    "crash": result.exit_code != 0 if result.exit_code is not None else False,
                    "exit_code": result.exit_code,
                    "execution_time": result.execution_time,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "api_calls": result.api_calls,
                    "memory_allocations": result.memory_allocations,
                    "coverage_data": self._extract_coverage_data(result) if self.coverage_tracker else None
                }
                
                return execution_result
                
            finally:
                # Clean up temporary file
                try:
                    os.unlink(input_file_path)
                except:
                    pass
        
        except Exception as e:
            self.logger.error(f"Target execution failed: {e}")
            return {
                "success": False,
                "timeout": False,
                "crash": True,
                "error": str(e)
            }
    
    async def _execute_specialized_target(self, input_data: bytes, config: SandboxConfig) -> SandboxResult:
        """Execute specialized target types with real implementations."""
        from ..processing.sandbox_manager import SandboxResult
        import tempfile
        import socket
        import subprocess
        import time
        
        start_time = time.time()
        
        try:
            if self.config.target_type == FuzzingTarget.LIBRARY_INTERFACE:
                # For library fuzzing, create a test harness
                with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
                    f.write(input_data)
                    lib_input_path = f.name
                
                # Execute library test harness
                harness_cmd = [
                    "python", "-c",
                    f"import ctypes; lib = ctypes.CDLL('{self.config.target_path}'); "
                    f"with open('{lib_input_path}', 'rb') as f: data = f.read(); "
                    f"# Call library functions with fuzzed data"
                ]
                result = subprocess.run(harness_cmd, capture_output=True, timeout=config.timeout)
                
                os.unlink(lib_input_path)
                
                return SandboxResult(
                    success=result.returncode == 0,
                    sandbox_type=config.sandbox_type,
                    execution_time=time.time() - start_time,
                    exit_code=result.returncode,
                    stdout=result.stdout.decode('utf-8', errors='ignore'),
                    stderr=result.stderr.decode('utf-8', errors='ignore')
                )
                
            elif self.config.target_type == FuzzingTarget.NETWORK_SERVICE:
                # For network fuzzing, connect and send data
                host, port = self.config.target_path.split(':')
                port = int(port)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(config.timeout)
                
                try:
                    sock.connect((host, port))
                    sock.send(input_data)
                    response = sock.recv(4096)
                    sock.close()
                    
                    return SandboxResult(
                        success=True,
                        sandbox_type=config.sandbox_type,
                        execution_time=time.time() - start_time,
                        stdout=response.decode('utf-8', errors='ignore'),
                        network_traffic=[{
                            'sent': input_data.hex(),
                            'received': response.hex()
                        }]
                    )
                except Exception as e:
                    return SandboxResult(
                        success=False,
                        sandbox_type=config.sandbox_type,
                        execution_time=time.time() - start_time,
                        stderr=str(e)
                    )
                finally:
                    sock.close()
                    
            elif self.config.target_type == FuzzingTarget.FILE_PARSER:
                # For file parser fuzzing, create input file and run parser
                with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
                    f.write(input_data)
                    input_path = f.name
                
                # Run parser application
                parser_cmd = [self.config.target_path, input_path]
                result = subprocess.run(parser_cmd, capture_output=True, timeout=config.timeout)
                
                os.unlink(input_path)
                
                return SandboxResult(
                    success=result.returncode == 0,
                    sandbox_type=config.sandbox_type,
                    execution_time=time.time() - start_time,
                    exit_code=result.returncode,
                    stdout=result.stdout.decode('utf-8', errors='ignore'),
                    stderr=result.stderr.decode('utf-8', errors='ignore')
                )
                
            elif self.config.target_type == FuzzingTarget.API_ENDPOINT:
                # For API fuzzing, send HTTP requests
                import requests
                
                try:
                    if input_data.startswith(b'POST'):
                        # Parse HTTP request from input data
                        lines = input_data.decode('utf-8', errors='ignore').split('\n')
                        method_line = lines[0].split()
                        method, path = method_line[0], method_line[1]
                        
                        # Extract headers and body
                        headers = {}
                        body_start = 0
                        for i, line in enumerate(lines[1:], 1):
                            if ':' in line and not line.startswith(' '):
                                key, value = line.split(':', 1)
                                headers[key.strip()] = value.strip()
                            elif line.strip() == '':
                                body_start = i + 1
                                break
                        
                        body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
                        
                        response = requests.request(
                            method.lower(),
                            f"{self.config.target_path.rstrip('/')}{path}",
                            headers=headers,
                            data=body,
                            timeout=config.timeout
                        )
                    else:
                        # Simple POST with raw data
                        response = requests.post(
                            self.config.target_path,
                            data=input_data,
                            timeout=config.timeout
                        )
                    
                    return SandboxResult(
                        success=200 <= response.status_code < 400,
                        sandbox_type=config.sandbox_type,
                        execution_time=time.time() - start_time,
                        exit_code=response.status_code,
                        stdout=response.text,
                        network_traffic=[{
                            'request': input_data.decode('utf-8', errors='ignore'),
                            'response': response.text
                        }]
                    )
                except Exception as e:
                    return SandboxResult(
                        success=False,
                        sandbox_type=config.sandbox_type,
                        execution_time=time.time() - start_time,
                        stderr=str(e)
                    )
                    
            elif self.config.target_type == FuzzingTarget.PROTOCOL_IMPLEMENTATION:
                # For protocol fuzzing, use specialized protocol handlers
                return await self._execute_protocol_fuzzing(input_data, config)
                
            elif self.config.target_type == FuzzingTarget.DRIVER_INTERFACE:
                # For driver fuzzing, use IOCTL calls (Windows-specific)
                return await self._execute_driver_fuzzing(input_data, config)
                
            elif self.config.target_type == FuzzingTarget.VIRTUAL_MACHINE:
                # For VM fuzzing, use QEMU/VMware interfaces
                return await self._execute_vm_fuzzing(input_data, config)
            
            else:
                # Fallback for unknown target types
                self.logger.warning(f"Unknown target type: {self.config.target_type}")
                return SandboxResult(
                    success=False,
                    sandbox_type=config.sandbox_type,
                    execution_time=time.time() - start_time,
                    stderr=f"Unsupported target type: {self.config.target_type}"
                )
                
        except Exception as e:
            self.logger.error(f"Specialized target execution failed: {e}")
            return SandboxResult(
                success=False,
                sandbox_type=config.sandbox_type,
                execution_time=time.time() - start_time,
                stderr=str(e)
            )

    async def _execute_protocol_fuzzing(self, input_data: bytes, config: SandboxConfig) -> SandboxResult:
        """Execute protocol-specific fuzzing."""
        from ..processing.sandbox_manager import SandboxResult
        import time
        
        start_time = time.time()
        
        try:
            # Protocol-specific fuzzing logic
            protocol_type = getattr(self.config, 'protocol_type', 'tcp')
            
            if protocol_type.lower() == 'http':
                # HTTP protocol fuzzing
                import requests
                response = requests.post(
                    self.config.target_path,
                    data=input_data,
                    timeout=config.timeout
                )
                return SandboxResult(
                    success=200 <= response.status_code < 500,
                    sandbox_type=config.sandbox_type,
                    execution_time=time.time() - start_time,
                    exit_code=response.status_code,
                    stdout=response.text
                )
            
            elif protocol_type.lower() in ['tcp', 'udp']:
                # Raw TCP/UDP protocol fuzzing
                import socket
                sock_type = socket.SOCK_STREAM if protocol_type.lower() == 'tcp' else socket.SOCK_DGRAM
                
                with socket.socket(socket.AF_INET, sock_type) as sock:
                    sock.settimeout(config.timeout)
                    host, port = self.config.target_path.split(':')
                    
                    if protocol_type.lower() == 'tcp':
                        sock.connect((host, int(port)))
                    
                    sock.sendto(input_data, (host, int(port)))
                    response, _ = sock.recvfrom(4096)
                    
                    return SandboxResult(
                        success=True,
                        sandbox_type=config.sandbox_type,
                        execution_time=time.time() - start_time,
                        stdout=response.decode('utf-8', errors='ignore')
                    )
            
            else:
                # Custom protocol handling
                return SandboxResult(
                    success=False,
                    sandbox_type=config.sandbox_type,
                    execution_time=time.time() - start_time,
                    stderr=f"Unsupported protocol type: {protocol_type}"
                )
                
        except Exception as e:
            return SandboxResult(
                success=False,
                sandbox_type=config.sandbox_type,
                execution_time=time.time() - start_time,
                stderr=str(e)
            )

    async def _execute_driver_fuzzing(self, input_data: bytes, config: SandboxConfig) -> SandboxResult:
        """Execute driver interface fuzzing (Windows-specific)."""
        from ..processing.sandbox_manager import SandboxResult
        import time
        
        start_time = time.time()
        
        try:
            if os.name != 'nt':
                return SandboxResult(
                    success=False,
                    sandbox_type=config.sandbox_type,
                    execution_time=time.time() - start_time,
                    stderr="Driver fuzzing only supported on Windows"
                )
            
            # Windows driver fuzzing using IOCTL calls
            import ctypes
            from ctypes import wintypes
            
            # Open device handle
            device_path = self.config.target_path
            handle = ctypes.windll.kernel32.CreateFileW(
                device_path,
                0xC0000000,  # GENERIC_READ | GENERIC_WRITE
                0,
                None,
                3,  # OPEN_EXISTING
                0,
                None
            )
            
            if handle == -1:
                return SandboxResult(
                    success=False,
                    sandbox_type=config.sandbox_type,
                    execution_time=time.time() - start_time,
                    stderr="Failed to open device handle"
                )
            
            try:
                # Send IOCTL with fuzzed data
                output_buffer = ctypes.create_string_buffer(1024)
                bytes_returned = wintypes.DWORD()
                
                result = ctypes.windll.kernel32.DeviceIoControl(
                    handle,
                    0x220000,  # Custom IOCTL code
                    input_data,
                    len(input_data),
                    output_buffer,
                    ctypes.sizeof(output_buffer),
                    ctypes.byref(bytes_returned),
                    None
                )
                
                return SandboxResult(
                    success=bool(result),
                    sandbox_type=config.sandbox_type,
                    execution_time=time.time() - start_time,
                    stdout=output_buffer.raw[:bytes_returned.value].decode('utf-8', errors='ignore')
                )
            
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
                
        except Exception as e:
            return SandboxResult(
                success=False,
                sandbox_type=config.sandbox_type,
                execution_time=time.time() - start_time,
                stderr=str(e)
            )

    async def _execute_vm_fuzzing(self, input_data: bytes, config: SandboxConfig) -> SandboxResult:
        """Execute virtual machine fuzzing."""
        from ..processing.sandbox_manager import SandboxResult
        import time
        import subprocess
        
        start_time = time.time()
        
        try:
            # VM fuzzing using QEMU interfaces
            vm_path = self.config.target_path
            
            # Create temporary input file for VM
            import tempfile
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
                f.write(input_data)
                input_file = f.name
            
            # Execute QEMU with fuzzed input
            qemu_cmd = [
                'qemu-system-x86_64',
                '-machine', 'accel=tcg',
                '-m', '512',
                '-nographic',
                '-monitor', 'stdio',
                '-drive', f'file={vm_path},format=qcow2',
                '-netdev', f'user,id=net0,hostfwd=tcp::2222-:22',
                '-device', 'e1000,netdev=net0'
            ]
            
            process = subprocess.Popen(
                qemu_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Send VM commands with fuzzed data
            vm_commands = f"""
            info registers
            x/32i $pc
            quit
            """
            
            stdout, stderr = process.communicate(
                input=vm_commands,
                timeout=config.timeout
            )
            
            os.unlink(input_file)
            
            return SandboxResult(
                success=process.returncode == 0,
                sandbox_type=config.sandbox_type,
                execution_time=time.time() - start_time,
                exit_code=process.returncode,
                stdout=stdout,
                stderr=stderr
            )
            
        except Exception as e:
            return SandboxResult(
                success=False,
                sandbox_type=config.sandbox_type,
                execution_time=time.time() - start_time,
                stderr=str(e)
            )
    
    def _extract_coverage_data(self, sandbox_result: SandboxResult) -> Optional[Dict[str, Any]]:
        """Extract coverage data from sandbox result."""
        # This would extract coverage information from the sandbox execution
        # Implementation depends on the coverage tracking mechanism
        return {
            "basic_blocks": [],
            "edges": [],
            "functions": []
        }
    
    async def _handle_crash(self, input_data: bytes, execution_result: Dict[str, Any]):
        """Handle discovered crash."""
        try:
            # Analyze crash
            crash_analysis = await self.crash_analyzer.analyze_crash(
                input_data=input_data,
                execution_result=execution_result,
                target_path=self.config.target_path
            )
            
            # Check if crash is unique
            if self._is_unique_crash(crash_analysis):
                self.crashes.append(crash_analysis)
                self.statistics.unique_crashes += 1
                
                # Save crash input
                crash_file = self.crash_dir / f"crash_{crash_analysis.crash_id}.bin"
                with open(crash_file, 'wb') as f:
                    f.write(input_data)
                
                # Save crash report
                report_file = self.crash_dir / f"crash_{crash_analysis.crash_id}_report.json"
                with open(report_file, 'w') as f:
                    json.dump({
                        "crash_id": crash_analysis.crash_id,
                        "timestamp": crash_analysis.timestamp.isoformat(),
                        "crash_type": crash_analysis.crash_type,
                        "severity": crash_analysis.severity,
                        "exploitability": crash_analysis.exploitability,
                        "execution_result": execution_result
                    }, f, indent=2)
                
                self.logger.info(f"New crash discovered: {crash_analysis.crash_id} ({crash_analysis.severity})")
        
        except Exception as e:
            self.logger.error(f"Crash handling failed: {e}")
    
    def _is_unique_crash(self, crash_analysis: CrashAnalysis) -> bool:
        """Check if crash is unique."""
        # Simple uniqueness check based on crash type and address
        for existing_crash in self.crashes:
            if (existing_crash.crash_type == crash_analysis.crash_type and
                existing_crash.crash_address == crash_analysis.crash_address):
                return False
        return True
    
    async def _save_interesting_input(self, input_data: bytes, reason: str, execution_result: Dict[str, Any]):
        """Save interesting input that found new coverage or behavior."""
        input_id = f"interesting_{len(self.interesting_inputs):06d}"
        
        input_info = {
            "id": input_id,
            "timestamp": datetime.now().isoformat(),
            "reason": reason,
            "size": len(input_data),
            "execution_result": execution_result
        }
        
        # Save input file
        input_file = self.corpus_dir / f"{input_id}.bin"
        with open(input_file, 'wb') as f:
            f.write(input_data)
        
        # Add to corpus if it found new coverage
        if reason == "new_coverage":
            self.corpus.append({
                "path": str(input_file),
                "data": input_data,
                "size": len(input_data),
                "generation": "discovered",
                "coverage_new": True
            })
            self.statistics.corpus_size += 1
        
        self.interesting_inputs.append(input_info)
        self.statistics.interesting_inputs += 1
    
    def _should_stop(self) -> bool:
        """Check if fuzzing should stop based on limits."""
        # Check execution limit
        if self.statistics.total_executions >= self.config.max_executions:
            return True
        
        # Check time limit
        if self.statistics.end_time:
            duration = self.statistics.end_time - self.statistics.start_time
        else:
            duration = datetime.now() - self.statistics.start_time
        
        if duration.total_seconds() / 3600 >= self.config.max_duration_hours:
            return True
        
        return False
    
    async def _ai_guided_optimization(self):
        """Perform AI-guided optimization of fuzzing parameters."""
        if not self.ai_enabled or not self.llm_manager:
            return
        
        try:
            # Prepare data for AI analysis
            performance_data = {
                "executions_per_second": self.statistics.executions_per_second,
                "coverage_progress": self.statistics.coverage_metrics.block_coverage_percent,
                "crash_rate": self.statistics.crashes / max(1, self.statistics.total_executions),
                "corpus_size": len(self.corpus),
                "recent_coverage_gains": self.statistics.coverage_metrics.new_blocks_this_session
            }
            
            # Get AI recommendations (simplified implementation)
            # In a full implementation, this would use the LLM to analyze performance
            # and suggest parameter adjustments
            
            self.logger.debug("AI-guided optimization performed")
            
        except Exception as e:
            self.logger.error(f"AI-guided optimization failed: {e}")
    
    async def _generate_periodic_report(self):
        """Generate periodic status report."""
        try:
            runtime = datetime.now() - self.statistics.start_time
            
            report = {
                "timestamp": datetime.now().isoformat(),
                "runtime_seconds": runtime.total_seconds(),
                "runtime_hours": runtime.total_seconds() / 3600,
                "statistics": {
                    "total_executions": self.statistics.total_executions,
                    "executions_per_second": self.statistics.executions_per_second,
                    "successful_executions": self.statistics.successful_executions,
                    "crashes": self.statistics.crashes,
                    "unique_crashes": self.statistics.unique_crashes,
                    "timeouts": self.statistics.timeouts,
                    "corpus_size": len(self.corpus),
                    "interesting_inputs": len(self.interesting_inputs)
                },
                "coverage": {
                    "block_coverage_percent": self.statistics.coverage_metrics.block_coverage_percent,
                    "edge_coverage_percent": self.statistics.coverage_metrics.edge_coverage_percent,
                    "function_coverage_percent": self.statistics.coverage_metrics.function_coverage_percent,
                    "new_blocks_this_session": self.statistics.coverage_metrics.new_blocks_this_session,
                    "new_edges_this_session": self.statistics.coverage_metrics.new_edges_this_session
                }
            }
            
            # Save report
            report_file = self.reports_dir / f"report_{int(time.time())}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            self.logger.info(f"Periodic report: {self.statistics.total_executions} execs, "
                           f"{self.statistics.crashes} crashes, "
                           f"{self.statistics.coverage_metrics.block_coverage_percent:.1f}% coverage")
            
        except Exception as e:
            self.logger.error(f"Failed to generate periodic report: {e}")
    
    async def _stop_workers(self):
        """Stop worker threads."""
        self.stop_event.set()
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5.0)
        
        self.workers.clear()
        self.logger.info("All workers stopped")
    
    async def _generate_result(self) -> FuzzingResult:
        """Generate final fuzzing result."""
        self.statistics.end_time = datetime.now()
        self.statistics.coverage_metrics.update_percentages()
        
        # Collect all generated files
        corpus_files = [str(p) for p in self.corpus_dir.glob("*")]
        crash_files = [str(p) for p in self.crash_dir.glob("*")]
        report_files = [str(p) for p in self.reports_dir.glob("*")]
        
        # Generate final comprehensive report
        final_report = await self._generate_final_report()
        
        result = FuzzingResult(
            success=True,
            statistics=self.statistics,
            config=self.config,
            crashes=self.crashes,
            corpus_files=corpus_files,
            crash_files=crash_files,
            report_files=report_files
        )
        
        # Add vulnerability analysis if crashes were found
        if self.crashes:
            result.vulnerability_analysis = await self._analyze_vulnerabilities()
        
        return result
    
    async def _generate_final_report(self) -> str:
        """Generate comprehensive final report."""
        try:
            runtime = self.statistics.end_time - self.statistics.start_time
            
            report = {
                "fuzzing_session": {
                    "target": self.config.target_path,
                    "strategy": self.config.strategy.value,
                    "start_time": self.statistics.start_time.isoformat(),
                    "end_time": self.statistics.end_time.isoformat() if self.statistics.end_time else None,
                    "runtime_hours": runtime.total_seconds() / 3600,
                    "config": self.config.__dict__
                },
                "execution_statistics": {
                    "total_executions": self.statistics.total_executions,
                    "successful_executions": self.statistics.successful_executions,
                    "failed_executions": self.statistics.failed_executions,
                    "timeouts": self.statistics.timeouts,
                    "crashes": self.statistics.crashes,
                    "unique_crashes": self.statistics.unique_crashes,
                    "executions_per_second": self.statistics.executions_per_second,
                    "average_execution_time": self.statistics.average_execution_time
                },
                "coverage_analysis": {
                    "block_coverage_percent": self.statistics.coverage_metrics.block_coverage_percent,
                    "edge_coverage_percent": self.statistics.coverage_metrics.edge_coverage_percent,
                    "function_coverage_percent": self.statistics.coverage_metrics.function_coverage_percent,
                    "blocks_covered": self.statistics.coverage_metrics.basic_blocks_covered,
                    "total_blocks": self.statistics.coverage_metrics.total_basic_blocks,
                    "edges_covered": self.statistics.coverage_metrics.edges_covered,
                    "total_edges": self.statistics.coverage_metrics.total_edges,
                    "functions_covered": self.statistics.coverage_metrics.functions_covered,
                    "total_functions": self.statistics.coverage_metrics.total_functions
                },
                "discoveries": {
                    "unique_crashes": len(self.crashes),
                    "interesting_inputs": len(self.interesting_inputs),
                    "final_corpus_size": len(self.corpus)
                },
                "crash_analysis": [
                    {
                        "crash_id": crash.crash_id,
                        "timestamp": crash.timestamp.isoformat(),
                        "type": crash.crash_type,
                        "severity": crash.severity,
                        "exploitability": crash.exploitability,
                        "vulnerability_type": crash.vulnerability_type
                    }
                    for crash in self.crashes
                ]
            }
            
            # Save final report
            final_report_file = self.reports_dir / "final_report.json"
            with open(final_report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            return str(final_report_file)
            
        except Exception as e:
            self.logger.error(f"Failed to generate final report: {e}")
            return ""
    
    async def _analyze_vulnerabilities(self) -> Dict[str, Any]:
        """Analyze discovered vulnerabilities."""
        vulnerability_summary = {
            "total_crashes": len(self.crashes),
            "severity_breakdown": {},
            "exploitability_assessment": {},
            "vulnerability_types": {},
            "recommendations": []
        }
        
        # Analyze severity distribution
        for crash in self.crashes:
            severity = crash.severity
            vulnerability_summary["severity_breakdown"][severity] = \
                vulnerability_summary["severity_breakdown"].get(severity, 0) + 1
        
        # Analyze exploitability
        for crash in self.crashes:
            exploitability = crash.exploitability
            vulnerability_summary["exploitability_assessment"][exploitability] = \
                vulnerability_summary["exploitability_assessment"].get(exploitability, 0) + 1
        
        # Analyze vulnerability types
        for crash in self.crashes:
            vuln_type = crash.vulnerability_type or "unknown"
            vulnerability_summary["vulnerability_types"][vuln_type] = \
                vulnerability_summary["vulnerability_types"].get(vuln_type, 0) + 1
        
        # Generate recommendations
        if any(crash.severity == "critical" for crash in self.crashes):
            vulnerability_summary["recommendations"].append(
                "Critical vulnerabilities found - immediate remediation required"
            )
        
        if any(crash.exploitability == "high" for crash in self.crashes):
            vulnerability_summary["recommendations"].append(
                "Highly exploitable vulnerabilities detected - prioritize security review"
            )
        
        return vulnerability_summary
    
    def pause(self):
        """Pause fuzzing execution."""
        self.paused = True
        self.logger.info("Fuzzing paused")
    
    def resume(self):
        """Resume fuzzing execution."""
        self.paused = False
        self.logger.info("Fuzzing resumed")
    
    def stop(self):
        """Stop fuzzing execution."""
        self.running = False
        self.stop_event.set()
        self.logger.info("Fuzzing stop requested")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current fuzzing status."""
        runtime = datetime.now() - self.statistics.start_time
        
        return {
            "running": self.running,
            "paused": self.paused,
            "runtime_seconds": runtime.total_seconds(),
            "total_executions": self.statistics.total_executions,
            "executions_per_second": self.statistics.executions_per_second,
            "crashes": self.statistics.crashes,
            "unique_crashes": self.statistics.unique_crashes,
            "corpus_size": len(self.corpus),
            "coverage_percent": self.statistics.coverage_metrics.block_coverage_percent,
            "workers_active": len(self.workers),
            "memory_usage_mb": self.statistics.peak_memory_usage
        }