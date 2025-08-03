"""
Comprehensive Analysis Orchestrator

Coordinates multiple analysis engines to perform deep binary analysis,
including static analysis, dynamic analysis, entropy analysis, structure
analysis, and more.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import logging
import time
import json
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Callable

from PyQt6.QtCore import QObject, pyqtSignal

from .binary_analyzer import BinaryAnalyzer
from .dynamic_analyzer import DynamicAnalyzer
from .entropy_analyzer import EntropyAnalyzer
from .ghidra_decompiler import GhidraDecompiler
from .multi_format_analyzer import MultiFormatAnalyzer
from .radare2_enhanced_integration import Radare2EnhancedIntegration
from .vulnerability_engine import VulnerabilityEngine
from .yara_pattern_engine import YaraPatternEngine
from .obfuscation_pattern_analyzer import ObfuscationPatternAnalyzer
from .unified_model import (
    UnifiedBinaryModel, BinaryMetadata, FunctionInfo, SymbolDatabase,
    SectionInfo, ProtectionAnalysis, VulnerabilityAnalysis, RuntimeBehavior,
    AnalysisEvent, ValidationResult, AnalysisPhase, AnalysisSource,
    ConfidenceLevel, UnifiedModelBuilder, ResultMerger, ModelValidator,
    ModelSerializer
)
from .unified_model.model import ImportInfo, ExportInfo, StringInfo, ProtectionInfo


@dataclass
class FunctionBoundary:
    """Standardized function boundary data for cross-tool coordination"""
    address: int
    size: int
    name: str
    priority: float
    calls_count: int = 0
    complexity: int = 0
    is_library: bool = False
    matched_keywords: List[str] = field(default_factory=list)
    source_tool: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for legacy compatibility"""
        return {
            'address': self.address,
            'size': self.size,
            'name': self.name,
            'priority': self.priority,
            'calls_count': self.calls_count,
            'complexity': self.complexity,
            'is_library': self.is_library,
            'matched_keywords': self.matched_keywords,
            'source_tool': self.source_tool
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FunctionBoundary':
        """Create from dictionary for legacy compatibility"""
        return cls(
            address=data.get('address', 0),
            size=data.get('size', 0),
            name=data.get('name', ''),
            priority=data.get('priority', 0.0),
            calls_count=data.get('calls_count', 0),
            complexity=data.get('complexity', 0),
            is_library=data.get('is_library', False),
            matched_keywords=data.get('matched_keywords', []),
            source_tool=data.get('source_tool', 'unknown')
        )


@dataclass
class CrossToolValidationResult:
    """Results of cross-tool data validation"""
    is_valid: bool
    total_items: int
    valid_items: int
    invalid_items: int
    validation_errors: List[str] = field(default_factory=list)
    address_mapping_issues: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def validity_rate(self) -> float:
        """Calculate validity rate"""
        return self.valid_items / max(self.total_items, 1)


class CrossToolValidator:
    """Validation layer for inter-tool data integrity"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def validate_function_boundaries(self, boundaries: List[Dict[str, Any]], 
                                   memory_layout: Optional[Dict[str, Any]] = None) -> CrossToolValidationResult:
        """
        Validate function boundary data for cross-tool use.
        
        Args:
            boundaries: List of function boundary dictionaries
            memory_layout: Optional memory layout for address validation
            
        Returns:
            Validation results with detailed error information
        """
        result = CrossToolValidationResult(
            is_valid=True,
            total_items=len(boundaries),
            valid_items=0,
            invalid_items=0
        )
        
        for i, boundary in enumerate(boundaries):
            errors = []
            
            # Validate required fields
            required_fields = ['address', 'size', 'name']
            for field in required_fields:
                if field not in boundary:
                    errors.append(f"Missing required field: {field}")
                elif boundary[field] is None:
                    errors.append(f"Field {field} is None")
            
            # Validate address format
            address = boundary.get('address', 0)
            if not isinstance(address, int) or address <= 0:
                errors.append(f"Invalid address format: {address}")
            
            # Validate size
            size = boundary.get('size', 0)
            if not isinstance(size, int) or size < 0:
                errors.append(f"Invalid size: {size}")
            
            # Validate priority
            priority = boundary.get('priority', 0.0)
            if not isinstance(priority, (int, float)) or not 0.0 <= priority <= 1.0:
                errors.append(f"Invalid priority (must be 0.0-1.0): {priority}")
            
            # Validate against memory layout if provided
            if memory_layout and 'blocks' in memory_layout:
                if not self._validate_address_in_memory_blocks(address, memory_layout['blocks']):
                    errors.append(f"Address 0x{address:x} not in valid memory range")
                    result.address_mapping_issues.append({
                        'index': i,
                        'address': address,
                        'name': boundary.get('name', ''),
                        'issue': 'address_out_of_range'
                    })
            
            if errors:
                result.invalid_items += 1
                result.validation_errors.extend([f"Boundary {i} ({boundary.get('name', 'unknown')}): {error}" for error in errors])
            else:
                result.valid_items += 1
        
        result.is_valid = result.invalid_items == 0
        
        if not result.is_valid:
            self.logger.warning(f"Function boundary validation failed: {result.invalid_items}/{result.total_items} invalid")
        else:
            self.logger.info(f"Function boundary validation passed: {result.valid_items} boundaries validated")
        
        return result
    
    def _validate_address_in_memory_blocks(self, address: int, memory_blocks: List[Dict[str, Any]]) -> bool:
        """Check if address falls within any memory block"""
        for block in memory_blocks:
            start = block.get('start', 0)
            end = block.get('end', 0)
            if start <= address <= end:
                return True
        return False


class CoordinationLogger:
    """Enhanced logging for cross-tool coordination and debugging"""
    
    def __init__(self, logger_name: str = __name__):
        self.logger = logging.getLogger(logger_name)
        self.coordination_events = []
        self.performance_metrics = {}
        self.data_transfer_log = []
        self.decision_log = []
        
        # Configure structured logging format
        self._configure_logging()
    
    def _configure_logging(self):
        """Configure detailed logging format for coordination debugging"""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.DEBUG)
    
    def log_phase_start(self, phase: str, binary_path: str, context: Dict[str, Any] = None):
        """Log the start of an analysis phase"""
        event = {
            'timestamp': time.time(),
            'event_type': 'phase_start',
            'phase': phase,
            'binary_path': binary_path,
            'context': context or {}
        }
        self.coordination_events.append(event)
        self.logger.info(f"🚀 Starting phase: {phase} for {os.path.basename(binary_path)}")
        if context:
            self.logger.debug(f"   Context: {context}")
    
    def log_phase_complete(self, phase: str, duration: float, result_summary: Dict[str, Any]):
        """Log the completion of an analysis phase"""
        event = {
            'timestamp': time.time(),
            'event_type': 'phase_complete',
            'phase': phase,
            'duration': duration,
            'result_summary': result_summary
        }
        self.coordination_events.append(event)
        self.performance_metrics[phase] = duration
        self.logger.info(f"✅ Completed phase: {phase} in {duration:.2f}s")
        self.logger.debug(f"   Result summary: {result_summary}")
    
    def log_tool_coordination(self, source_tool: str, target_tool: str, 
                            data_type: str, data_size: int, metadata: Dict[str, Any] = None):
        """Log data transfer between analysis tools"""
        transfer = {
            'timestamp': time.time(),
            'source_tool': source_tool,
            'target_tool': target_tool,
            'data_type': data_type,
            'data_size': data_size,
            'metadata': metadata or {}
        }
        self.data_transfer_log.append(transfer)
        self.logger.info(f"🔄 Tool coordination: {source_tool} → {target_tool}")
        self.logger.debug(f"   Data type: {data_type}, Size: {data_size} items")
        if metadata:
            self.logger.debug(f"   Metadata: {metadata}")
    
    def log_decision_point(self, decision_type: str, criteria: Dict[str, Any], 
                          decision: str, rationale: str):
        """Log decision points in the analysis workflow"""
        decision_event = {
            'timestamp': time.time(),
            'decision_type': decision_type,
            'criteria': criteria,
            'decision': decision,
            'rationale': rationale
        }
        self.decision_log.append(decision_event)
        self.logger.info(f"🎯 Decision: {decision_type} → {decision}")
        self.logger.debug(f"   Criteria: {criteria}")
        self.logger.debug(f"   Rationale: {rationale}")
    
    def log_error_with_context(self, phase: str, error: Exception, 
                             context: Dict[str, Any] = None):
        """Log errors with full context for debugging"""
        error_info = {
            'timestamp': time.time(),
            'phase': phase,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context or {},
            'traceback': traceback.format_exc()
        }
        self.coordination_events.append(error_info)
        self.logger.error(f"❌ Error in {phase}: {error}")
        if context:
            self.logger.error(f"   Context: {context}")
        self.logger.debug(f"   Traceback: {traceback.format_exc()}")
    
    def log_state_checkpoint(self, checkpoint_type: str, state_summary: Dict[str, Any]):
        """Log state management operations"""
        self.logger.info(f"💾 State checkpoint: {checkpoint_type}")
        self.logger.debug(f"   State summary: {state_summary}")
    
    def log_performance_metric(self, metric_name: str, value: float, context: str = ""):
        """Log performance metrics"""
        self.performance_metrics[metric_name] = value
        self.logger.debug(f"📊 Performance metric: {metric_name} = {value:.3f}s {context}")
    
    def get_coordination_summary(self) -> Dict[str, Any]:
        """Get summary of all coordination events"""
        return {
            'total_events': len(self.coordination_events),
            'data_transfers': len(self.data_transfer_log),
            'decisions_made': len(self.decision_log),
            'performance_metrics': self.performance_metrics,
            'phases_completed': len([e for e in self.coordination_events if e.get('event_type') == 'phase_complete']),
            'errors_encountered': len([e for e in self.coordination_events if 'error_type' in e])
        }
    
    def save_coordination_log(self, log_path: str):
        """Save detailed coordination log for analysis"""
        try:
            log_data = {
                'summary': self.get_coordination_summary(),
                'coordination_events': self.coordination_events,
                'data_transfers': self.data_transfer_log,
                'decisions': self.decision_log,
                'performance_metrics': self.performance_metrics
            }
            with open(log_path, 'w') as f:
                json.dump(log_data, f, indent=2)
            self.logger.info(f"📝 Coordination log saved to {log_path}")
        except Exception as e:
            self.logger.error(f"Failed to save coordination log: {e}")





@dataclass
class AnalysisState:
    """State management for resumable analysis"""
    binary_path: str
    current_phase: Optional[AnalysisPhase] = None
    completed_phases: Set[AnalysisPhase] = field(default_factory=set)
    unified_model: Optional[UnifiedBinaryModel] = None
    tool_states: Dict[str, Any] = field(default_factory=dict)
    phase_results: Dict[AnalysisPhase, Dict[str, Any]] = field(default_factory=dict)
    analysis_start_time: float = field(default_factory=time.time)
    checkpoint_timestamp: float = field(default_factory=time.time)
    
    def is_phase_completed(self, phase: AnalysisPhase) -> bool:
        """Check if a phase has been completed"""
        return phase in self.completed_phases
    
    def mark_phase_completed(self, phase: AnalysisPhase, result: Dict[str, Any]):
        """Mark a phase as completed with its result"""
        self.completed_phases.add(phase)
        self.phase_results[phase] = result
        self.checkpoint_timestamp = time.time()
    
    def get_next_phase(self) -> Optional[AnalysisPhase]:
        """Get the next phase to execute"""
        all_phases = list(AnalysisPhase)
        for phase in all_phases:
            if not self.is_phase_completed(phase):
                return phase
        return None


@dataclass
class OrchestrationResult:
    """Result of orchestrated analysis with unified model"""
    binary_path: str
    success: bool
    unified_model: Optional[UnifiedBinaryModel] = None
    analysis_state: Optional[AnalysisState] = None
    phases_completed: List[AnalysisPhase] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    validation_errors: List[str] = field(default_factory=list)
    analysis_duration: float = 0.0
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    cross_tool_correlations: Dict[str, Any] = field(default_factory=dict)

    def add_error(self, phase: AnalysisPhase, error: str):
        """Add error for a phase"""
        self.errors.append(f"{phase.value}: {error}")

    def add_warning(self, phase: AnalysisPhase, warning: str):
        """Add warning for a phase"""
        self.warnings.append(f"{phase.value}: {warning}")
        
    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary"""
        return {
            "binary_path": self.binary_path,
            "success": self.success,
            "phases_completed": len(self.phases_completed),
            "total_phases": len(AnalysisPhase),
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "validation_errors": len(self.validation_errors),
            "analysis_duration": self.analysis_duration,
            "has_unified_model": self.unified_model is not None,
            "performance_metrics": self.performance_metrics,
            "cross_tool_correlations": self.cross_tool_correlations
        }


class AnalysisOrchestrator(QObject):
    """
    Orchestrates comprehensive binary analysis using multiple engines
    """

    # Signals
    phase_started = pyqtSignal(str)  # phase_name
    phase_completed = pyqtSignal(str, dict)  # phase_name, result
    phase_failed = pyqtSignal(str, str)  # phase_name, error
    progress_updated = pyqtSignal(int, int)  # current, total
    analysis_completed = pyqtSignal(OrchestrationResult)
    model_updated = pyqtSignal(UnifiedBinaryModel)  # unified_model

    def __init__(self):
        """Initialize the enhanced analysis orchestrator.

        Sets up all analysis engines with intelligent coordination, state management,
        and cross-tool integration for maintaining unified binary models.
        """
        super().__init__()

        # Core analyzers (loaded on demand for performance)
        self.binary_analyzer = None
        self.entropy_analyzer = None
        self.multi_format_analyzer = None
        self.dynamic_analyzer = None
        self.vulnerability_engine = None
        self.yara_engine = None
        self.radare2 = None
        self.ghidra_decompiler = None
        self.obfuscation_analyzer = None

        # Unified model components
        self.model_builder = None
        self.result_merger = ResultMerger()
        self.model_validator = ModelValidator()
        self.model_serializer = ModelSerializer()

        # Analysis state and coordination
        self.analysis_state = None
        self.cross_tool_data = {}  # Data shared between tools
        self.performance_tracker = {}

        # Analysis configuration
        self.enabled_phases = list(AnalysisPhase)
        self.timeout_per_phase = 300  # 5 minutes per phase
        self.max_parallel_tools = 3  # Limit concurrent tool execution
        self.enable_state_checkpoints = True
        self.checkpoint_interval = 60  # Save state every minute
        
        # Enhanced coordination logging
        self.coord_logger = CoordinationLogger(__name__)
        self.logger = self.coord_logger.logger
        
        # Cross-tool validation
        self.cross_tool_validator = CrossToolValidator(self.logger)

    def _load_tool(self, tool_name: str):
        """Load analysis tool on demand"""
        if tool_name == 'binary_analyzer' and self.binary_analyzer is None:
            self.binary_analyzer = BinaryAnalyzer()
        elif tool_name == 'entropy_analyzer' and self.entropy_analyzer is None:
            self.entropy_analyzer = EntropyAnalyzer()
        elif tool_name == 'multi_format_analyzer' and self.multi_format_analyzer is None:
            self.multi_format_analyzer = MultiFormatAnalyzer()
        elif tool_name == 'dynamic_analyzer' and self.dynamic_analyzer is None:
            self.dynamic_analyzer = DynamicAnalyzer()
        elif tool_name == 'vulnerability_engine' and self.vulnerability_engine is None:
            self.vulnerability_engine = VulnerabilityEngine()
        elif tool_name == 'yara_engine' and self.yara_engine is None:
            self.yara_engine = YaraPatternEngine()
        elif tool_name == 'radare2' and self.radare2 is None:
            self.radare2 = Radare2EnhancedIntegration()
        elif tool_name == 'ghidra_decompiler' and self.ghidra_decompiler is None:
            from .ghidra_decompiler import GhidraDecompiler
            # Will be initialized with binary path when needed
            self.logger.debug(f"Tool {tool_name} will be initialized when binary path is available")
        elif tool_name == 'obfuscation_analyzer' and self.obfuscation_analyzer is None:
            self.obfuscation_analyzer = ObfuscationPatternAnalyzer()

    def _get_tools_for_phase(self, phase: AnalysisPhase) -> List[str]:
        """Get list of tools involved in a specific phase"""
        tool_mapping = {
            AnalysisPhase.PREPARATION: [],
            AnalysisPhase.BASIC_INFO: ["BinaryAnalyzer"],
            AnalysisPhase.STATIC_ANALYSIS: ["Radare2", "BinaryAnalyzer", "ObfuscationAnalyzer"],
            AnalysisPhase.DECOMPILATION: ["Ghidra", "Radare2"],
            AnalysisPhase.ENTROPY_ANALYSIS: ["EntropyAnalyzer"],
            AnalysisPhase.STRUCTURE_ANALYSIS: ["MultiFormatAnalyzer"],
            AnalysisPhase.VULNERABILITY_SCAN: ["VulnerabilityEngine"],
            AnalysisPhase.PATTERN_MATCHING: ["YaraEngine", "ObfuscationAnalyzer"],
            AnalysisPhase.DYNAMIC_ANALYSIS: ["DynamicAnalyzer", "Ghidra"],
            AnalysisPhase.FINALIZATION: ["UnifiedModelBuilder", "ModelValidator"]
        }
        return tool_mapping.get(phase, [])

    def save_state(self, checkpoint_path: str) -> bool:
        """Save current analysis state for resumable analysis"""
        try:
            if not self.analysis_state:
                self.logger.warning("No analysis state to save")
                return False

            checkpoint_data = {
                'analysis_state': {
                    'binary_path': self.analysis_state.binary_path,
                    'current_phase': self.analysis_state.current_phase.value if self.analysis_state.current_phase else None,
                    'completed_phases': [phase.value for phase in self.analysis_state.completed_phases],
                    'tool_states': self.analysis_state.tool_states,
                    'phase_results': {phase.value: result for phase, result in self.analysis_state.phase_results.items()},
                    'analysis_start_time': self.analysis_state.analysis_start_time,
                    'checkpoint_timestamp': self.analysis_state.checkpoint_timestamp
                },
                'cross_tool_data': self.cross_tool_data,
                'performance_tracker': self.performance_tracker
            }

            # Save unified model separately due to size
            if self.analysis_state.unified_model:
                model_path = checkpoint_path.replace('.json', '_model.json')
                self.model_serializer.save_model(self.analysis_state.unified_model, model_path)
                checkpoint_data['unified_model_path'] = model_path

            with open(checkpoint_path, 'w') as f:
                json.dump(checkpoint_data, f, indent=2)

            self.logger.info(f"Analysis state saved to {checkpoint_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to save analysis state: {e}", exc_info=True)
            return False

    def restore_state(self, checkpoint_path: str) -> bool:
        """Restore analysis state from checkpoint"""
        try:
            if not os.path.exists(checkpoint_path):
                self.logger.error(f"Checkpoint file not found: {checkpoint_path}")
                return False

            with open(checkpoint_path, 'r') as f:
                checkpoint_data = json.load(f)

            # Restore analysis state
            state_data = checkpoint_data['analysis_state']
            self.analysis_state = AnalysisState(
                binary_path=state_data['binary_path'],
                current_phase=AnalysisPhase(state_data['current_phase']) if state_data['current_phase'] else None,
                completed_phases={AnalysisPhase(phase) for phase in state_data['completed_phases']},
                tool_states=state_data['tool_states'],
                phase_results={AnalysisPhase(phase): result for phase, result in state_data['phase_results'].items()},
                analysis_start_time=state_data['analysis_start_time'],
                checkpoint_timestamp=state_data['checkpoint_timestamp']
            )

            # Restore unified model if available
            if 'unified_model_path' in checkpoint_data:
                self.analysis_state.unified_model = self.model_serializer.load_model(checkpoint_data['unified_model_path'])

            # Restore cross-tool data
            self.cross_tool_data = checkpoint_data.get('cross_tool_data', {})
            self.performance_tracker = checkpoint_data.get('performance_tracker', {})

            self.logger.info(f"Analysis state restored from {checkpoint_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to restore analysis state: {e}", exc_info=True)
            return False

    def analyze_binary(self, binary_path: str, phases: Optional[List[AnalysisPhase]] = None, 
                      resume_from: Optional[str] = None) -> OrchestrationResult:
        """
        Perform intelligent orchestrated analysis with cross-tool coordination

        Args:
            binary_path: Path to the binary file
            phases: Optional list of phases to run (runs all if None)
            resume_from: Optional checkpoint path to resume analysis from

        Returns:
            OrchestrationResult with unified model and cross-tool correlations
        """
        start_time = time.time()
        result = OrchestrationResult(binary_path=binary_path, success=True)

        # Restore from checkpoint or initialize new analysis
        if resume_from and self.restore_state(resume_from):
            self.logger.info(f"Resuming analysis from checkpoint: {resume_from}")
            result.unified_model = self.analysis_state.unified_model
            result.phases_completed = list(self.analysis_state.completed_phases)
        else:
            # Initialize new analysis state
            self.analysis_state = AnalysisState(binary_path=binary_path)
            
            # Validate file exists
            if not os.path.exists(binary_path):
                result.success = False
                result.add_error(AnalysisPhase.PREPARATION, f"File not found: {binary_path}")
                self.analysis_completed.emit(result)
                return result

            # Initialize unified model
            self.analysis_state.unified_model = UnifiedBinaryModel.create_initial(binary_path)
            self.model_builder = UnifiedModelBuilder(binary_path, self.logger)

        # Use provided phases or determine remaining phases
        if phases:
            phases_to_run = [p for p in phases if not self.analysis_state.is_phase_completed(p)]
        else:
            phases_to_run = [p for p in self.enabled_phases if not self.analysis_state.is_phase_completed(p)]

        if not phases_to_run:
            self.logger.info("All requested phases already completed")
            result.unified_model = self.analysis_state.unified_model
            result.analysis_duration = time.time() - start_time
            return result

        total_phases = len(phases_to_run)
        self.logger.info(f"Starting analysis with {total_phases} phases: {[p.value for p in phases_to_run]}")

        # Execute analysis phases with intelligent coordination
        return self._execute_coordinated_analysis(phases_to_run, result, start_time)

    def _execute_coordinated_analysis(self, phases_to_run: List[AnalysisPhase], 
                                    result: OrchestrationResult, start_time: float) -> OrchestrationResult:
        """Execute analysis phases with intelligent cross-tool coordination"""
        
        self.coord_logger.log_phase_start("coordinated_execution", 
                                        self.analysis_state.binary_path, 
                                        {'phases_count': len(phases_to_run), 
                                         'phases': [p.value for p in phases_to_run]})
        
        for idx, phase in enumerate(phases_to_run):
            self.progress_updated.emit(idx, len(phases_to_run))
            phase_start_time = time.time()
            
            # Log phase start with context
            phase_context = {
                'phase_index': idx + 1,
                'total_phases': len(phases_to_run),
                'previous_phases_completed': len(result.phases_completed),
                'cross_tool_data_available': list(self.cross_tool_data.keys()),
                'unified_model_size': len(self.analysis_state.unified_model.metadata.exports) 
                                    if self.analysis_state.unified_model and hasattr(self.analysis_state.unified_model.metadata, 'exports') 
                                    else 0
            }
            
            self.coord_logger.log_phase_start(phase.value, self.analysis_state.binary_path, phase_context)
            
            try:
                self.phase_started.emit(phase.value)
                self.analysis_state.current_phase = phase
                
                # Execute phase with coordination
                phase_result = self._execute_phase_with_coordination(phase)
                
                # Track performance
                phase_duration = time.time() - phase_start_time
                result.performance_metrics[phase.value] = phase_duration
                
                # Log phase completion with detailed results
                phase_summary = {
                    'duration': phase_duration,
                    'success': phase_result.get('status') != 'error',
                    'data_generated': len(str(phase_result)),
                    'coordination_data_updated': phase.value in ['STATIC_ANALYSIS', 'DECOMPILATION'],
                    'tools_involved': self._get_tools_for_phase(phase)
                }
                
                self.coord_logger.log_phase_complete(phase.value, phase_duration, phase_summary)
                self.coord_logger.log_performance_metric(f"phase_{phase.value.lower()}", phase_duration)
                
                # Mark phase as completed
                self.analysis_state.mark_phase_completed(phase, phase_result)
                result.phases_completed.append(phase)
                
                # Log cross-tool data sharing
                if phase == AnalysisPhase.STATIC_ANALYSIS:
                    function_boundaries = self.cross_tool_data.get('radare2_function_boundaries', [])
                    if function_boundaries:
                        self.coord_logger.log_tool_coordination(
                            "Radare2", "Ghidra", "function_boundaries", 
                            len(function_boundaries),
                            {'high_priority_functions': len([f for f in function_boundaries if f.get('priority', 0) > 0.7])}
                        )
                
                # Save checkpoint if enabled
                if self.enable_state_checkpoints and phase_duration > self.checkpoint_interval:
                    checkpoint_path = f"{self.analysis_state.binary_path}.checkpoint.json"
                    self.save_state(checkpoint_path)
                    self.coord_logger.log_state_checkpoint("automatic_checkpoint", 
                                                         {'trigger': 'long_phase_duration', 
                                                          'duration': phase_duration})
                
                # Emit completion signal
                self.phase_completed.emit(phase.value, phase_result)
                
                # Update unified model after each phase
                if self.analysis_state.unified_model:
                    self.model_updated.emit(self.analysis_state.unified_model)
                    
            except Exception as e:
                # Enhanced error logging with full context
                error_context = {
                    'phase': phase.value,
                    'phase_index': idx + 1,
                    'elapsed_time': phase_duration if 'phase_duration' in locals() else time.time() - phase_start_time,
                    'cross_tool_data': list(self.cross_tool_data.keys()),
                    'analysis_state': {
                        'completed_phases': len(self.analysis_state.completed_phases),
                        'current_binary': os.path.basename(self.analysis_state.binary_path)
                    }
                }
                
                self.coord_logger.log_error_with_context(phase.value, e, error_context)
                
                error_msg = f"Phase {phase.value} failed: {str(e)}"
                result.add_error(phase, str(e))
                self.phase_failed.emit(phase.value, error_msg)
                
                # Graceful degradation - continue with other phases
                self.coord_logger.log_decision_point(
                    decision_type="error_recovery",
                    criteria={'failed_phase': phase.value, 'remaining_phases': len(phases_to_run) - idx - 1},
                    decision="continue_execution",
                    rationale="Continuing with remaining phases to maximize analysis coverage"
                )

        # Finalize analysis
        result.unified_model = self.analysis_state.unified_model
        result.analysis_state = self.analysis_state
        result.cross_tool_correlations = self.cross_tool_data
        result.analysis_duration = time.time() - start_time
        
        # Final validation
        if result.unified_model:
            validation_result = self.model_validator.validate_model(result.unified_model)
            if not validation_result.is_valid:
                result.validation_errors = [issue.message for issue in validation_result.issues]
                result.add_warning(AnalysisPhase.FINALIZATION, 
                                 f"Model validation found {validation_result.error_count} errors")

        self.progress_updated.emit(len(phases_to_run), len(phases_to_run))
        self.analysis_completed.emit(result)
        return result

    def _execute_phase_with_coordination(self, phase: AnalysisPhase) -> Dict[str, Any]:
        """Execute a single phase with cross-tool coordination"""
        
        if phase == AnalysisPhase.PREPARATION:
            return self._prepare_analysis()
        elif phase == AnalysisPhase.BASIC_INFO:
            return self._analyze_basic_info()
        elif phase == AnalysisPhase.STATIC_ANALYSIS:
            return self._perform_coordinated_static_analysis()
        elif phase == AnalysisPhase.DECOMPILATION:
            return self._perform_targeted_decompilation()
        elif phase == AnalysisPhase.ENTROPY_ANALYSIS:
            return self._perform_entropy_analysis()
        elif phase == AnalysisPhase.STRUCTURE_ANALYSIS:
            return self._analyze_structure()
        elif phase == AnalysisPhase.VULNERABILITY_SCAN:
            return self._scan_vulnerabilities()
        elif phase == AnalysisPhase.PATTERN_MATCHING:
            return self._match_patterns()
        elif phase == AnalysisPhase.DYNAMIC_ANALYSIS:
            return self._perform_intelligent_dynamic_analysis()
        elif phase == AnalysisPhase.FINALIZATION:
            return self._finalize_unified_model()
        else:
            return {"status": "skipped", "reason": "Unknown phase"}

    def _prepare_analysis(self) -> Dict[str, Any]:
        """Prepare for analysis"""
        binary_path = self.analysis_state.binary_path
        file_stat = os.stat(binary_path)
        return {
            "file_size": file_stat.st_size,
            "file_path": os.path.abspath(binary_path),
            "file_name": os.path.basename(binary_path),
            "modified_time": file_stat.st_mtime,
        }

    def _perform_coordinated_static_analysis(self) -> Dict[str, Any]:
        """Perform coordinated static analysis with Radare2 and prepare for Ghidra"""
        binary_path = self.analysis_state.binary_path
        self._load_tool('radare2')
        
        try:
            result = {}
            
            # Initialize radare2 session
            if self.radare2.open_binary(binary_path):
                # Get comprehensive analysis data
                result["imports"] = self.radare2.get_imports()
                result["exports"] = self.radare2.get_exports()
                result["sections"] = self.radare2.get_sections()
                result["strings"] = self.radare2.get_strings(min_length=5)
                result["functions"] = self.radare2.get_functions()
                
                # Extract function boundaries for Ghidra coordination
                function_boundaries = self._extract_function_boundaries_for_ghidra(result["functions"])
                self.cross_tool_data['radare2_function_boundaries'] = function_boundaries
                
                # Identify license-related functions for priority analysis
                license_functions = self._identify_license_related_functions(result)
                self.cross_tool_data['license_priority_functions'] = license_functions
                
                # Perform obfuscation pattern analysis
                obfuscation_result = self._perform_obfuscation_analysis(binary_path)
                result["obfuscation_analysis"] = obfuscation_result
                
                # Close session
                self.radare2.close()
                
            # Integrate results into unified model
            self._integrate_static_analysis(result)
            
            # Store cross-tool coordination data
            result['coordination_data'] = {
                'function_boundaries_count': len(self.cross_tool_data.get('radare2_function_boundaries', [])),
                'license_functions_identified': len(self.cross_tool_data.get('license_priority_functions', []))
            }
            
            return result
        except Exception as e:
            return {"error": str(e)}

    def _extract_function_boundaries_for_ghidra(self, functions: List[Dict]) -> List[Dict[str, Any]]:
        """Extract function boundaries from Radare2 for targeted Ghidra analysis with enhanced validation"""
        start_time = time.time()
        function_boundaries = []
        
        self.coord_logger.log_tool_coordination(
            source_tool="Radare2",
            target_tool="Ghidra", 
            data_type="function_boundaries",
            data_size=len(functions),
            metadata={"extraction_start": start_time}
        )
        
        priority_distribution = {'high': 0, 'medium': 0, 'low': 0}
        license_related_functions = 0
        crypto_related_functions = 0
        matched_keywords_tracking = []
        
        for func in functions:
            address = func.get('offset', 0)
            size = func.get('size', 0)
            name = func.get('name', f'sub_{address:x}')
            
            # Calculate priority based on function characteristics
            priority, matched_keywords = self._calculate_function_priority_enhanced(func)
            
            # Track priority distribution for logging
            if priority > 0.7:
                priority_distribution['high'] += 1
            elif priority > 0.4:
                priority_distribution['medium'] += 1
            else:
                priority_distribution['low'] += 1
            
            # Track function categories
            name_lower = name.lower()
            license_keywords = ['license', 'serial', 'key', 'valid', 'check', 'auth', 'trial', 'expire']
            crypto_keywords = ['crypt', 'hash', 'md5', 'sha', 'aes', 'rsa', 'encrypt', 'decrypt']
            
            if any(kw in name_lower for kw in license_keywords):
                license_related_functions += 1
            if any(kw in name_lower for kw in crypto_keywords):
                crypto_related_functions += 1
            
            # Create standardized function boundary
            boundary = FunctionBoundary(
                address=address,
                size=size,
                name=name,
                priority=priority,
                calls_count=len(func.get('callrefs', [])),
                complexity=func.get('cc', 0),
                is_library=name.startswith(('lib', 'api_', 'sub_')),
                matched_keywords=matched_keywords,
                source_tool="radare2"
            )
            
            # Convert to dict for legacy compatibility and add to results
            boundary_dict = boundary.to_dict()
            function_boundaries.append(boundary_dict)
            
            if matched_keywords:
                matched_keywords_tracking.append({
                    'name': name,
                    'address': address,
                    'keywords': matched_keywords,
                    'priority': priority
                })
        
        # Sort by priority (highest first)
        function_boundaries.sort(key=lambda x: x['priority'], reverse=True)
        
        # Validate function boundaries before passing to Ghidra
        validation_result = self.cross_tool_validator.validate_function_boundaries(function_boundaries)
        
        extraction_time = time.time() - start_time
        
        # Enhanced logging with validation results
        extraction_summary = {
            'total_functions': len(function_boundaries),
            'priority_distribution': priority_distribution,
            'license_related': license_related_functions,
            'crypto_related': crypto_related_functions,
            'high_priority_functions': len([f for f in function_boundaries if f['priority'] > 0.7]),
            'extraction_time': extraction_time,
            'validation_results': {
                'is_valid': validation_result.is_valid,
                'valid_count': validation_result.valid_items,
                'invalid_count': validation_result.invalid_items,
                'validity_rate': validation_result.validity_rate
            },
            'keyword_matches': len(matched_keywords_tracking)
        }
        
        self.coord_logger.log_performance_metric("function_boundary_extraction", extraction_time)
        self.coord_logger.log_decision_point(
            decision_type="function_prioritization",
            criteria={
                "total_functions": len(functions),
                "priority_threshold": 0.7,
                "license_keywords_weight": 0.8,
                "crypto_keywords_weight": 0.6,
                "validation_passed": validation_result.is_valid
            },
            decision=f"Selected {priority_distribution['high']} high-priority functions",
            rationale=f"Prioritized {license_related_functions} license-related and {crypto_related_functions} crypto-related functions with {validation_result.validity_rate:.1%} validation success"
        )
        
        # Log validation warnings if needed
        if not validation_result.is_valid:
            self.logger.warning(f"Function boundary validation found {validation_result.invalid_items} issues")
            for error in validation_result.validation_errors[:5]:  # Log first 5 errors
                self.logger.warning(f"   Validation error: {error}")
        
        self.logger.info(f"✅ Extracted {len(function_boundaries)} function boundaries for Ghidra in {extraction_time:.3f}s")
        self.logger.debug(f"   Priority distribution: {priority_distribution}")
        self.logger.debug(f"   License-related: {license_related_functions}, Crypto-related: {crypto_related_functions}")
        self.logger.debug(f"   Validation: {validation_result.valid_items}/{validation_result.total_items} valid ({validation_result.validity_rate:.1%})")
        
        return function_boundaries

    def _calculate_function_priority(self, func: Dict[str, Any]) -> float:
        """Calculate priority score for function analysis (legacy method)"""
        priority, _ = self._calculate_function_priority_enhanced(func)
        return priority

    def _calculate_function_priority_enhanced(self, func: Dict[str, Any]) -> tuple:
        """Calculate priority score for function analysis with keyword tracking"""
        priority = 0.0
        matched_keywords = []
        name = func.get('name', '').lower()
        
        # High priority for license-related keywords
        license_keywords = ['license', 'serial', 'key', 'valid', 'check', 'auth', 'trial', 'expire']
        license_matches = [kw for kw in license_keywords if kw in name]
        if license_matches:
            priority += 0.8
            matched_keywords.extend(license_matches)
        
        # Medium priority for crypto-related functions
        crypto_keywords = ['crypt', 'hash', 'md5', 'sha', 'aes', 'rsa', 'encrypt', 'decrypt']
        crypto_matches = [kw for kw in crypto_keywords if kw in name]
        if crypto_matches:
            priority += 0.6
            matched_keywords.extend(crypto_matches)
        
        # Additional security-related keywords
        security_keywords = ['protect', 'secure', 'verify', 'validate', 'bypass', 'crack']
        security_matches = [kw for kw in security_keywords if kw in name]
        if security_matches:
            priority += 0.5
            matched_keywords.extend(security_matches)
        
        # Time-related keywords (for trial/expiration logic)
        time_keywords = ['time', 'date', 'expire', 'timeout', 'timer']
        time_matches = [kw for kw in time_keywords if kw in name]
        if time_matches:
            priority += 0.4
            matched_keywords.extend(time_matches)
        
        # Priority based on complexity
        complexity = func.get('cc', 0)
        if complexity > 10:
            priority += 0.4
        elif complexity > 5:
            priority += 0.2
        
        # Priority based on calls
        calls_count = len(func.get('callrefs', []))
        if calls_count > 10:
            priority += 0.3
        elif calls_count > 5:
            priority += 0.1
        
        # Lower priority for obvious library functions
        if name.startswith(('lib', 'api_', 'thunk_')):
            priority *= 0.5
        
        # Boost priority for functions with multiple keyword matches
        if len(matched_keywords) > 1:
            priority += 0.2
        
        return min(priority, 1.0), matched_keywords  # Cap at 1.0

    def _identify_license_related_functions(self, static_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify functions likely related to licensing based on static analysis"""
        license_functions = []
        functions = static_results.get('functions', [])
        strings = static_results.get('strings', [])
        imports = static_results.get('imports', [])
        
        # Build license-related string context
        license_strings = set()
        for string_entry in strings:
            string_val = string_entry.get('string', '').lower()
            if any(keyword in string_val for keyword in ['license', 'serial', 'key', 'trial', 'expire', 'valid', 'auth']):
                license_strings.add(string_entry.get('vaddr', 0))
        
        # Identify license-related imports
        license_apis = set()
        for imp in imports:
            api_name = imp.get('name', '').lower()
            if any(keyword in api_name for keyword in ['reg', 'crypt', 'file', 'time', 'net']):
                license_apis.add(imp.get('name', ''))
        
        # Analyze functions for license indicators
        for func in functions:
            score = 0.0
            func_name = func.get('name', '').lower()
            func_addr = func.get('offset', 0)
            
            # Name-based scoring
            if any(keyword in func_name for keyword in ['license', 'serial', 'key', 'valid', 'check', 'auth']):
                score += 0.7
            
            # Cross-reference analysis (simplified - would need deeper analysis)
            if score > 0.3:
                license_function = {
                    'address': func_addr,
                    'name': func.get('name', ''),
                    'size': func.get('size', 0),
                    'license_score': score,
                    'reason': 'Static analysis heuristics'
                }
                license_functions.append(license_function)
        
        # Sort by license score
        license_functions.sort(key=lambda x: x['license_score'], reverse=True)
        
        self.logger.info(f"Identified {len(license_functions)} potential license-related functions")
        return license_functions

    def _perform_obfuscation_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Perform comprehensive obfuscation pattern analysis"""
        self._load_tool('obfuscation_analyzer')
        
        try:
            # Initialize obfuscation analyzer with current radare2 session
            if hasattr(self.radare2, 'r2') and self.radare2.r2:
                self.obfuscation_analyzer.r2 = self.radare2.r2
            
            # Perform comprehensive obfuscation analysis
            result = self.obfuscation_analyzer.analyze(binary_path)
            
            # Extract key metrics for coordination
            if 'summary' in result:
                summary = result['summary']
                self.cross_tool_data['obfuscation_level'] = summary.get('overall_obfuscation_level', 'minimal')
                self.cross_tool_data['obfuscation_patterns'] = summary.get('total_patterns_detected', 0)
                self.cross_tool_data['high_confidence_obfuscation'] = summary.get('high_confidence_patterns', 0)
            
            # Log obfuscation findings
            patterns_detected = result.get('summary', {}).get('total_patterns_detected', 0)
            obfuscation_level = result.get('summary', {}).get('overall_obfuscation_level', 'unknown')
            
            self.logger.info(f"Obfuscation analysis complete: {patterns_detected} patterns detected, level: {obfuscation_level}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Obfuscation analysis failed: {e}")
            return {
                'error': str(e),
                'analysis_time': 0.0,
                'summary': {
                    'total_patterns_detected': 0,
                    'overall_obfuscation_level': 'error'
                }
            }

    def _analyze_basic_info(self) -> Dict[str, Any]:
        """Get basic binary information"""
        binary_path = self.analysis_state.binary_path
        self._load_tool('binary_analyzer')
        
        try:
            result = self.binary_analyzer.analyze(binary_path)
            self._integrate_basic_analysis(result)
            return result
        except Exception as e:
            return {"error": str(e), "fallback": True}

    def _perform_targeted_decompilation(self) -> Dict[str, Any]:
        """Perform targeted Ghidra decompilation using Radare2 function boundaries"""
        binary_path = self.analysis_state.binary_path
        
        try:
            # Initialize Ghidra decompiler on demand
            if self.ghidra_decompiler is None:
                try:
                    from .ghidra_decompiler import GhidraDecompiler
                    self.ghidra_decompiler = GhidraDecompiler(binary_path)
                except Exception as e:
                    return {
                        "status": "skipped",
                        "reason": f"Ghidra not available: {str(e)}",
                        "error": str(e)
                    }
            
            result = {}
            
            # Get function boundaries from Radare2 coordination data
            function_boundaries = self.cross_tool_data.get('radare2_function_boundaries', [])
            license_priority_functions = self.cross_tool_data.get('license_priority_functions', [])
            
            if function_boundaries:
                # Focus on high-priority functions first
                priority_targets = [f for f in function_boundaries if f.get('priority', 0) > 0.5][:10]
                
                # Configure targeted analysis
                analysis_config = {
                    'target_functions': priority_targets,
                    'focus_areas': ['license_logic', 'crypto_operations', 'validation_routines'],
                    'max_functions': 10,  # Limit for performance
                    'analysis_depth': 'deep' if len(priority_targets) <= 5 else 'standard'
                }
                
                # Perform targeted decompilation
                decompilation_result = self._run_targeted_ghidra_analysis(analysis_config)
                result.update(decompilation_result)
                
                # Store coordination data for dynamic analysis
                self._prepare_dynamic_analysis_targets(result)
                
            else:
                # Fallback to license function analysis
                license_analysis = self.ghidra_decompiler.analyze_license_functions()
                if 'error' not in license_analysis:
                    result.update(license_analysis)
            
            # Integrate results into unified model
            if result.get('status') != 'error':
                self._integrate_decompilation_analysis(result)
            
            result['coordination_info'] = {
                'used_radare2_boundaries': len(function_boundaries),
                'analyzed_priority_functions': len(result.get('analyzed_functions', [])),
                'dynamic_targets_prepared': len(self.cross_tool_data.get('dynamic_analysis_targets', []))
            }
            
            return result
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }

    def _run_targeted_ghidra_analysis(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Run Ghidra analysis on specific target functions using address-based coordination"""
        target_functions = config.get('target_functions', [])
        max_functions = config.get('max_functions', 10)
        analysis_depth = config.get('analysis_depth', 'standard')
        
        result = {
            'status': 'success',
            'coordination_method': 'address_based',
            'analyzed_functions': [],
            'high_confidence_targets': [],
            'decompiled_code': {},
            'cross_tool_validation': {
                'total_targets': len(target_functions),
                'address_matches': 0,
                'name_matches': 0,
                'functions_created': 0,
                'validation_errors': []
            }
        }
        
        # Use the enhanced targeted analysis method for robust cross-tool coordination
        try:
            targeted_analysis = self.ghidra_decompiler.analyze_targeted_functions(
                function_boundaries=target_functions,
                max_functions=max_functions
            )
            
            if 'error' in targeted_analysis:
                result['status'] = 'error'
                result['error'] = targeted_analysis['error']
                return result
            
            # Process enhanced analysis results
            for analyzed_func in targeted_analysis.get('analyzed_functions', []):
                original_boundary = analyzed_func['original_boundary']
                decompilation_result = analyzed_func['decompilation_result']
                pattern_analysis = analyzed_func['pattern_analysis']
                cross_tool_metadata = analyzed_func['cross_tool_metadata']
                
                func_address = original_boundary['address']
                func_name = original_boundary['name']
                
                # Extract decompiled code
                decompiled_code = decompilation_result.get('decompiled_code', '')
                if decompiled_code:
                    result['decompiled_code'][func_name] = decompiled_code
                
                # Create comprehensive analysis entry
                analyzed_entry = {
                    'address': func_address,
                    'name': func_name,
                    'ghidra_name': cross_tool_metadata.get('ghidra_name', ''),
                    'size': original_boundary.get('size', 0),
                    'priority': original_boundary.get('priority', 0.0),
                    'decompiled_code': decompiled_code,
                    'pattern_analysis': pattern_analysis,
                    'cross_tool_validation': {
                        'address_match': cross_tool_metadata.get('address_match', False),
                        'name_consistency': cross_tool_metadata.get('radare2_name') == cross_tool_metadata.get('ghidra_name'),
                        'analysis_source': cross_tool_metadata.get('analysis_source', 'unknown'),
                        'coordination_method': 'address_based'
                    },
                    'license_confidence': pattern_analysis.get('confidence', 0.0)
                }
                
                result['analyzed_functions'].append(analyzed_entry)
                
                # Track validation metrics
                if cross_tool_metadata.get('address_match', False):
                    result['cross_tool_validation']['address_matches'] += 1
                
                if analyzed_entry['cross_tool_validation']['name_consistency']:
                    result['cross_tool_validation']['name_matches'] += 1
                
                if cross_tool_metadata.get('analysis_source') == 'created_function':
                    result['cross_tool_validation']['functions_created'] += 1
                
                # Mark as high confidence based on combined analysis
                combined_confidence = (
                    original_boundary.get('priority', 0.0) * 0.6 +
                    pattern_analysis.get('confidence', 0.0) * 0.4
                )
                
                if combined_confidence > 0.7:
                    result['high_confidence_targets'].append(analyzed_entry)
            
            # Add summary metrics from targeted analysis
            result['analysis_summary'] = {
                'total_analyzed': targeted_analysis.get('successful_decomps', 0),
                'total_failed': targeted_analysis.get('failed_decomps', 0),
                'success_rate': targeted_analysis.get('success_rate', 0.0),
                'functions_created': targeted_analysis.get('created_functions', 0),
                'address_validity_rate': targeted_analysis.get('validation_results', {}).get('address_validity_rate', 0.0)
            }
            
            # Log coordination success
            self.coord_logger.log_tool_coordination(
                source_tool="Radare2",
                target_tool="Ghidra",
                data_type="targeted_function_analysis",
                data_size=len(result['analyzed_functions']),
                metadata={
                    'coordination_method': 'address_based',
                    'success_rate': result['analysis_summary']['success_rate'],
                    'functions_created': result['analysis_summary']['functions_created'],
                    'address_matches': result['cross_tool_validation']['address_matches']
                }
            )
            
        except Exception as e:
            error_msg = f"Enhanced targeted analysis failed: {str(e)}"
            self.logger.error(error_msg)
            result['status'] = 'error'
            result['error'] = error_msg
            result['fallback_used'] = False
        
        return result

    def _analyze_decompiled_for_license_patterns(self, decompiled_code: str) -> Dict[str, Any]:
        """Analyze decompiled code for license-related patterns"""
        indicators = {
            'confidence': 0.0,
            'patterns_found': [],
            'api_calls': [],
            'string_patterns': [],
            'file_operations': [],
            'registry_operations': [],
            'network_operations': []
        }
        
        code_lower = decompiled_code.lower()
        
        # License validation patterns
        license_patterns = [
            ('license_check', r'licens[e|ing]'),
            ('serial_validation', r'serial|key'),
            ('trial_check', r'trial|expire|timeout'),
            ('activation_check', r'activ[e|ation]|register'),
            ('validation_routine', r'valid[ate|ation]|check|verify')
        ]
        
        for pattern_name, pattern in license_patterns:
            if pattern in code_lower:
                indicators['patterns_found'].append(pattern_name)
                indicators['confidence'] += 0.15
        
        # API call patterns
        api_patterns = [
            ('registry_access', ['regopen', 'regquery', 'regcreate']),
            ('file_access', ['createfile', 'readfile', 'writefile']),
            ('crypto_operations', ['crypt', 'hash', 'md5', 'sha']),
            ('network_operations', ['socket', 'connect', 'send', 'recv']),
            ('time_operations', ['gettime', 'systemtime', 'filetime'])
        ]
        
        for api_type, apis in api_patterns:
            found_apis = [api for api in apis if api in code_lower]
            if found_apis:
                indicators['api_calls'].extend(found_apis)
                indicators['confidence'] += len(found_apis) * 0.1
        
        # Cap confidence at 1.0
        indicators['confidence'] = min(indicators['confidence'], 1.0)
        
        return indicators

    def _prepare_dynamic_analysis_targets(self, decompilation_result: Dict[str, Any]):
        """Prepare dynamic analysis targets based on decompilation results"""
        dynamic_targets = {
            'monitor_functions': [],
            'hook_addresses': [],
            'watch_api_calls': [],
            'monitor_files': [],
            'monitor_registry_keys': [],
            'monitor_network_endpoints': []
        }
        
        # Extract targets from analyzed functions
        for func in decompilation_result.get('analyzed_functions', []):
            if func.get('license_indicators', {}).get('confidence', 0) > 0.5:
                dynamic_targets['monitor_functions'].append({
                    'address': func['address'],
                    'name': func['name'],
                    'reason': 'license_function'
                })
                
                # Extract API calls to monitor
                api_calls = func.get('license_indicators', {}).get('api_calls', [])
                dynamic_targets['watch_api_calls'].extend(api_calls)
        
        # Store for dynamic analysis phase
        self.cross_tool_data['dynamic_analysis_targets'] = dynamic_targets
        
        self.logger.info(f"Prepared {len(dynamic_targets['monitor_functions'])} functions for dynamic monitoring")

    def _perform_static_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Perform static analysis using radare2"""
        try:
            result = {}

            # Initialize radare2 session
            if self.radare2.open_binary(binary_path):
                # Get imports
                result["imports"] = self.radare2.get_imports()

                # Get exports
                result["exports"] = self.radare2.get_exports()

                # Get sections
                result["sections"] = self.radare2.get_sections()

                # Get strings
                result["strings"] = self.radare2.get_strings(min_length=5)

                # Get functions
                result["functions"] = self.radare2.get_functions()

                # Close session
                self.radare2.close()

            return result
        except Exception as e:
            return {"error": str(e)}

    def _perform_decompilation(self, binary_path: str) -> Dict[str, Any]:
        """Perform decompilation analysis using Ghidra"""
        try:
            result = {}
            
            # Initialize Ghidra decompiler on demand
            if self.ghidra_decompiler is None:
                try:
                    self.ghidra_decompiler = GhidraDecompiler(binary_path)
                except Exception as e:
                    # Ghidra might not be available
                    return {
                        "status": "skipped",
                        "reason": f"Ghidra not available: {str(e)}",
                        "error": str(e)
                    }
            
            # Analyze license functions
            license_analysis = self.ghidra_decompiler.analyze_license_functions()
            
            if 'error' in license_analysis:
                return {
                    "status": "error",
                    "error": license_analysis['error']
                }
            
            result["license_functions"] = license_analysis.get("license_functions", [])
            result["high_confidence_targets"] = license_analysis.get("high_confidence_targets", [])
            result["pattern_summary"] = license_analysis.get("pattern_summary", {})
            result["total_functions_analyzed"] = license_analysis.get("total_functions_analyzed", 0)
            result["license_related_functions"] = license_analysis.get("license_related_functions", 0)
            
            # If we have high confidence targets, decompile them fully
            if result["high_confidence_targets"]:
                result["decompiled_targets"] = {}
                for target in result["high_confidence_targets"][:5]:  # Limit to top 5
                    func_name = target.get("name")
                    if func_name:
                        decompiled = self.ghidra_decompiler.get_decompiled_code(func_name)
                        if decompiled:
                            result["decompiled_targets"][func_name] = decompiled
            
            result["status"] = "success"
            return result
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }

    def _perform_entropy_analysis(self) -> Dict[str, Any]:
        """Perform entropy analysis"""
        binary_path = self.analysis_state.binary_path
        self._load_tool('entropy_analyzer')
        
        try:
            result = {"sections": []}

            with open(binary_path, 'rb') as f:
                data = f.read()

            # Overall entropy
            overall_entropy = self.entropy_analyzer.calculate_entropy(data)
            result["overall_entropy"] = overall_entropy

            # Analyze in chunks
            chunk_size = 1024
            chunks = []
            for i in range(0, len(data), chunk_size):
                chunk_data = data[i:i+chunk_size]
                if chunk_data:
                    entropy = self.entropy_analyzer.calculate_entropy(chunk_data)
                    chunks.append({
                        "offset": i,
                        "size": len(chunk_data),
                        "entropy": entropy,
                        "suspicious": entropy > self.entropy_analyzer.high_entropy_threshold
                    })

            result["chunks"] = chunks
            result["high_entropy_chunks"] = [c for c in chunks if c["suspicious"]]

            # Integrate into unified model
            self._integrate_entropy_analysis(result)
            
            return result
        except Exception as e:
            return {"error": str(e)}

    def _analyze_structure(self) -> Dict[str, Any]:
        """Analyze binary structure"""
        binary_path = self.analysis_state.binary_path
        self._load_tool('multi_format_analyzer')
        
        try:
            result = self.multi_format_analyzer.analyze(binary_path)
            self._integrate_structure_analysis(result)
            return result
        except Exception as e:
            return {"error": str(e)}

    def _scan_vulnerabilities(self) -> Dict[str, Any]:
        """Scan for vulnerabilities"""
        binary_path = self.analysis_state.binary_path
        self._load_tool('vulnerability_engine')
        
        try:
            result = self.vulnerability_engine.scan(binary_path)
            self._integrate_vulnerability_analysis(result)
            return result
        except Exception as e:
            return {"error": str(e)}

    def _match_patterns(self) -> Dict[str, Any]:
        """Match YARA patterns and perform enhanced obfuscation analysis"""
        binary_path = self.analysis_state.binary_path
        self._load_tool('yara_engine')
        
        try:
            result = {}
            
            # YARA pattern matching
            rules_path = "data/yara_rules"
            if os.path.exists(rules_path):
                self.yara_engine.load_rules(rules_path)

            yara_result = self.yara_engine.scan(binary_path)
            result['yara_patterns'] = yara_result
            
            # Enhanced obfuscation pattern analysis (if not already done in static phase)
            if 'obfuscation_analysis' not in self.cross_tool_data:
                obfuscation_result = self._perform_obfuscation_analysis(binary_path)
                result['obfuscation_patterns'] = obfuscation_result
            else:
                # Use existing obfuscation analysis results
                result['obfuscation_patterns'] = self.cross_tool_data.get('obfuscation_analysis', {})
            
            self._integrate_pattern_analysis(result)
            return result
        except Exception as e:
            return {"error": str(e)}

    def _perform_intelligent_dynamic_analysis(self) -> Dict[str, Any]:
        """Perform dynamic analysis using insights from static analysis"""
        binary_path = self.analysis_state.binary_path
        
        try:
            # Get dynamic analysis targets from cross-tool data
            dynamic_targets = self.cross_tool_data.get('dynamic_analysis_targets', {})
            
            # Configure dynamic analysis based on static findings
            sandbox_config = self._configure_dynamic_analysis_from_static(dynamic_targets)
            
            # Try to use the new sandbox manager first
            try:
                from ..processing.sandbox_manager import SandboxManager, SandboxConfig, AnalysisDepth
                
                # Create enhanced sandbox configuration
                config = SandboxConfig(
                    analysis_depth=AnalysisDepth.DEEP if sandbox_config.get('high_priority', False) else AnalysisDepth.STANDARD,
                    timeout=self.timeout_per_phase,
                    enable_network=sandbox_config.get('monitor_network', False),
                    enable_filesystem=True,
                    enable_registry=True,
                    enable_api_hooks=True,
                    enable_memory_monitoring=True,
                    enable_snapshots=False,
                    custom_hooks=sandbox_config.get('custom_hooks', []),
                    monitor_apis=sandbox_config.get('monitor_apis', []),
                    watch_files=sandbox_config.get('watch_files', []),
                    watch_registry=sandbox_config.get('watch_registry', [])
                )
                
                # Create sandbox manager
                sandbox_manager = SandboxManager()
                
                # Run targeted analysis
                sandbox_result = sandbox_manager.analyze_binary(binary_path, config)
                
                # Process and correlate results
                result = self._process_intelligent_dynamic_results(sandbox_result, dynamic_targets)
                
                # Integrate into unified model
                self._integrate_dynamic_analysis(result)
                
                return result
                
            except ImportError:
                # Fallback to legacy dynamic analyzer
                return self._fallback_dynamic_analysis(binary_path)
                
        except Exception as e:
            return {"error": str(e)}

    def _configure_dynamic_analysis_from_static(self, dynamic_targets: Dict[str, Any]) -> Dict[str, Any]:
        """Configure dynamic analysis based on static analysis findings"""
        
        config = {
            'high_priority': False,
            'monitor_network': False,
            'custom_hooks': [],
            'monitor_apis': [],
            'watch_files': [],
            'watch_registry': [],
            'focus_areas': []
        }
        
        # Configure based on identified targets
        monitor_functions = dynamic_targets.get('monitor_functions', [])
        if monitor_functions:
            config['high_priority'] = len(monitor_functions) > 3
            config['custom_hooks'] = [func['address'] for func in monitor_functions]
            config['focus_areas'].append('license_validation')
        
        # API monitoring configuration
        watch_apis = dynamic_targets.get('watch_api_calls', [])
        if watch_apis:
            config['monitor_apis'] = list(set(watch_apis))  # Remove duplicates
            
            # Determine monitoring scope
            if any(api in ['socket', 'connect', 'send', 'recv'] for api in watch_apis):
                config['monitor_network'] = True
                config['focus_areas'].append('network_validation')
        
        # File monitoring
        watch_files = dynamic_targets.get('monitor_files', [])
        if watch_files:
            config['watch_files'] = watch_files
            config['focus_areas'].append('file_based_licensing')
        
        # Registry monitoring
        watch_registry = dynamic_targets.get('monitor_registry_keys', [])
        if watch_registry:
            config['watch_registry'] = watch_registry
            config['focus_areas'].append('registry_based_licensing')
        
        self.logger.info(f"Configured intelligent dynamic analysis: {config['focus_areas']}")
        return config

    def _process_intelligent_dynamic_results(self, sandbox_result, dynamic_targets: Dict[str, Any]) -> Dict[str, Any]:
        """Process and correlate dynamic analysis results with static findings"""
        
        result = {
            'status': 'success' if sandbox_result.success else 'error',
            'sandbox_type': sandbox_result.sandbox_type.value,
            'execution_time': sandbox_result.execution_time,
            'exit_code': sandbox_result.exit_code,
            'correlations': {},
            'enhanced_analysis': {}
        }
        
        # Correlate API calls with static predictions
        predicted_apis = set(dynamic_targets.get('watch_api_calls', []))
        observed_apis = set(call.get('api_name', '') for call in sandbox_result.api_calls)
        
        api_correlation = {
            'predicted_apis': list(predicted_apis),
            'observed_apis': list(observed_apis),
            'matched_apis': list(predicted_apis.intersection(observed_apis)),
            'unexpected_apis': list(observed_apis - predicted_apis),
            'correlation_score': len(predicted_apis.intersection(observed_apis)) / max(len(predicted_apis), 1)
        }
        result['correlations']['api_calls'] = api_correlation
        
        # Correlate function monitoring
        monitored_functions = dynamic_targets.get('monitor_functions', [])
        if monitored_functions:
            function_hits = []
            for call in sandbox_result.api_calls:
                call_addr = call.get('address', 0)
                for func in monitored_functions:
                    if func['address'] == call_addr:
                        function_hits.append({
                            'function': func['name'],
                            'address': func['address'],
                            'hit_count': 1,  # Simplified
                            'context': call.get('context', {})
                        })
            
            result['correlations']['function_monitoring'] = {
                'monitored_count': len(monitored_functions),
                'hit_count': len(function_hits),
                'hits': function_hits
            }
        
        # Enhanced license detection analysis
        license_indicators = self._analyze_dynamic_license_behavior(sandbox_result)
        result['enhanced_analysis']['license_behavior'] = license_indicators
        
        # Store cross-tool correlation data
        self.cross_tool_data['static_dynamic_correlation'] = result['correlations']
        
        return result

    def _analyze_dynamic_license_behavior(self, sandbox_result) -> Dict[str, Any]:
        """Analyze dynamic behavior for license-related patterns"""
        
        indicators = {
            'confidence': 0.0,
            'behaviors_detected': [],
            'suspicious_patterns': [],
            'validation_attempts': []
        }
        
        # Analyze file operations for license files
        license_file_patterns = ['license', 'serial', 'key', 'activation', '.lic', '.key']
        for file_op in sandbox_result.files_read:
            if any(pattern in file_op.lower() for pattern in license_file_patterns):
                indicators['behaviors_detected'].append('license_file_access')
                indicators['confidence'] += 0.2
        
        # Analyze registry operations
        license_reg_patterns = ['license', 'serial', 'key', 'trial', 'expire']
        for reg_key in getattr(sandbox_result, 'registry_keys_read', []):
            if any(pattern in reg_key.lower() for pattern in license_reg_patterns):
                indicators['behaviors_detected'].append('license_registry_access')
                indicators['confidence'] += 0.2
        
        # Analyze network behavior
        if sandbox_result.network_connections:
            indicators['behaviors_detected'].append('network_validation_attempt')
            indicators['confidence'] += 0.15
        
        # Time-based analysis
        if sandbox_result.execution_time > 5.0:  # Suspicious if takes too long
            indicators['suspicious_patterns'].append('extended_validation_time')
        
        indicators['confidence'] = min(indicators['confidence'], 1.0)
        return indicators

    def _fallback_dynamic_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Fallback dynamic analysis without static analysis integration"""
        self._load_tool('dynamic_analyzer')
        
        try:
            if hasattr(self.dynamic_analyzer, 'is_available') and self.dynamic_analyzer.is_available():
                result = self.dynamic_analyzer.analyze(binary_path)
                self._integrate_dynamic_analysis(result)
                return result
            else:
                return {"status": "skipped", "reason": "Dynamic analyzer not available"}
        except Exception as e:
            return {"error": str(e)}
    
    def _summarize_license_checks(self, license_checks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize license check findings"""
        if not license_checks:
            return {"found": False}
        
        summary = {
            "found": True,
            "types": {},
            "confidence": 0.0
        }
        
        # Count check types
        for check in license_checks:
            check_type = check.get('type', 'unknown')
            summary["types"][check_type] = summary["types"].get(check_type, 0) + 1
        
        # Calculate confidence based on variety and count
        type_count = len(summary["types"])
        total_checks = len(license_checks)
        
        if total_checks > 10 and type_count > 3:
            summary["confidence"] = 0.9
        elif total_checks > 5 and type_count > 2:
            summary["confidence"] = 0.7
        elif total_checks > 2:
            summary["confidence"] = 0.5
        else:
            summary["confidence"] = 0.3
        
        return summary

    def _finalize_analysis(self, result: OrchestrationResult) -> Dict[str, Any]:
        """Finalize and summarize analysis"""
        summary = {
            "total_phases": len(self.enabled_phases),
            "completed_phases": len(result.phases_completed),
            "errors": len(result.errors),
            "warnings": len(result.warnings)
        }

        # Add key findings
        findings = []

        # Check entropy results
        if AnalysisPhase.ENTROPY_ANALYSIS in result.phases_completed:
            entropy_data = result.results.get("entropy_analysis", {})
            if entropy_data.get("overall_entropy", 0) > 7.0:
                findings.append("High entropy detected - possible packing/encryption")

        # Check vulnerability results
        if AnalysisPhase.VULNERABILITY_SCAN in result.phases_completed:
            vuln_data = result.results.get("vulnerability_scan", {})
            if vuln_data.get("vulnerabilities"):
                findings.append(f"Found {len(vuln_data['vulnerabilities'])} potential vulnerabilities")

        summary["key_findings"] = findings
        return summary

    def _integrate_basic_analysis(self, result: Dict[str, Any]) -> None:
        """Integrate basic binary analysis results into unified model."""
        if self.model_builder and result and not result.get('error'):
            self.model_builder.integrate_basic_analysis(result)
            self.logger.debug("Integrated basic analysis results into unified model")

    def _integrate_static_analysis(self, result: Dict[str, Any]) -> None:
        """Integrate Radare2 static analysis results into unified model."""
        if self.model_builder and result and not result.get('error'):
            self.model_builder.integrate_radare2_analysis(result)
            self.logger.debug("Integrated Radare2 static analysis results into unified model")

    def _integrate_decompilation_analysis(self, result: Dict[str, Any]) -> None:
        """Integrate Ghidra decompilation results into unified model."""
        if self.model_builder and result and result.get('status') == 'success':
            self.model_builder.integrate_ghidra_analysis(result)
            self.logger.debug("Integrated Ghidra decompilation results into unified model")

    def _integrate_entropy_analysis(self, result: Dict[str, Any]) -> None:
        """Integrate entropy analysis results into unified model."""
        if self.model_builder and result and not result.get('error'):
            protection_result = {
                'packers': [],
                'obfuscation': []
            }
            
            overall_entropy = result.get('overall_entropy', 0)
            if overall_entropy > 7.5:
                protection_result['packers'].append({
                    'type': 'entropy_based_detection',
                    'name': 'high_entropy_packer',
                    'confidence': min(overall_entropy / 8.0, 1.0),
                    'details': f'Overall entropy: {overall_entropy:.3f}'
                })
            
            high_entropy_chunks = result.get('high_entropy_chunks', [])
            if len(high_entropy_chunks) > 5:
                protection_result['obfuscation'].append({
                    'type': 'data_obfuscation',
                    'name': 'high_entropy_sections',
                    'confidence': min(len(high_entropy_chunks) / 20.0, 1.0),
                    'details': f'{len(high_entropy_chunks)} high entropy chunks detected'
                })
            
            self.model_builder.integrate_protection_analysis(protection_result)
            self.logger.debug("Integrated entropy analysis results into unified model")

    def _integrate_structure_analysis(self, result: Dict[str, Any]) -> None:
        """Integrate structure analysis results into unified model."""
        if self.model_builder and result and not result.get('error'):
            if 'format_info' in result:
                basic_result = {
                    'format': result['format_info'].get('format', 'unknown'),
                    'file_info': {
                        'architecture': result['format_info'].get('architecture', 'unknown'),
                        'endianness': result['format_info'].get('endianness', 'unknown'),
                        'entry_point': result['format_info'].get('entry_point', 0)
                    }
                }
                self.model_builder.integrate_basic_analysis(basic_result)
            
            self.logger.debug("Integrated structure analysis results into unified model")

    def _integrate_vulnerability_analysis(self, result: Dict[str, Any]) -> None:
        """Integrate vulnerability scan results into unified model."""
        if self.model_builder and result and not result.get('error'):
            self.model_builder.integrate_vulnerability_analysis(result)
            self.logger.debug("Integrated vulnerability analysis results into unified model")

    def _integrate_pattern_analysis(self, result: Dict[str, Any]) -> None:
        """Integrate YARA pattern matching results into unified model."""
        if self.model_builder and result and not result.get('error'):
            protection_result = {
                'packers': [],
                'obfuscation': [],
                'anti_debug': [],
                'anti_vm': [],
                'licensing_mechanisms': []
            }
            
            matches = result.get('matches', [])
            for match in matches:
                rule_name = match.get('rule', '').lower()
                
                if any(packer in rule_name for packer in ['upx', 'aspack', 'pecompact', 'mpress']):
                    protection_result['packers'].append({
                        'type': 'yara_detection',
                        'name': match.get('rule', ''),
                        'confidence': 0.8,
                        'details': f"YARA rule match: {match.get('rule', '')}"
                    })
                elif any(obf in rule_name for obf in ['obfuscator', 'themida', 'vmprotect', 'confuser']):
                    protection_result['obfuscation'].append({
                        'type': 'yara_detection',
                        'name': match.get('rule', ''),
                        'confidence': 0.8,
                        'details': f"YARA rule match: {match.get('rule', '')}"
                    })
                elif 'antidebug' in rule_name or 'anti_debug' in rule_name:
                    protection_result['anti_debug'].append({
                        'type': 'yara_detection',
                        'name': match.get('rule', ''),
                        'confidence': 0.8,
                        'details': f"YARA rule match: {match.get('rule', '')}"
                    })
                elif 'antivm' in rule_name or 'anti_vm' in rule_name:
                    protection_result['anti_vm'].append({
                        'type': 'yara_detection',
                        'name': match.get('rule', ''),
                        'confidence': 0.8,
                        'details': f"YARA rule match: {match.get('rule', '')}"
                    })
                elif any(lic in rule_name for lic in ['license', 'serial', 'key', 'activation']):
                    protection_result['licensing_mechanisms'].append({
                        'type': 'yara_detection',
                        'name': match.get('rule', ''),
                        'confidence': 0.8,
                        'details': f"YARA rule match: {match.get('rule', '')}"
                    })
            
            self.model_builder.integrate_protection_analysis(protection_result)
            self.logger.debug("Integrated YARA pattern analysis results into unified model")

    def _integrate_dynamic_analysis(self, result: Dict[str, Any]) -> None:
        """Integrate dynamic analysis results into unified model."""
        if self.model_builder and result and result.get('status') != 'error':
            self.model_builder.integrate_dynamic_analysis(result)
            self.logger.debug("Integrated dynamic analysis results into unified model")

    def _finalize_unified_model(self) -> Dict[str, Any]:
        """Finalize the unified model and perform final validation."""
        if not self.model_builder:
            return {"status": "error", "error": "Model builder not initialized"}
        
        try:
            unified_model = self.model_builder.finalize_model()
            validation_result = self.model_validator.validate_model(unified_model)
            
            # Generate bypass recommendations if protections detected
            bypass_recommendations = None
            if unified_model.protection_analysis.detected_protections:
                try:
                    bypass_recommendations = self._generate_bypass_recommendations(unified_model)
                except Exception as e:
                    self.logger.warning(f"Failed to generate bypass recommendations: {e}")
            
            summary = {
                "status": "success",
                "model_valid": validation_result.is_valid,
                "validation_errors": validation_result.error_count,
                "validation_warnings": validation_result.warning_count,
                "total_functions": len(unified_model.function_analysis.functions),
                "total_sections": len(unified_model.section_analysis.sections),
                "total_imports": len(unified_model.symbol_db.imports),
                "total_exports": len(unified_model.symbol_db.exports),
                "protections_found": len(unified_model.protection_analysis.detected_protections),
                "vulnerabilities_found": len(unified_model.vulnerability_analysis.vulnerabilities),
                "analysis_events": len(unified_model.analysis_events),
                "data_confidence": unified_model.metadata.analysis_confidence,
                "bypass_recommendations_generated": bypass_recommendations is not None
            }
            
            # Store bypass recommendations in analysis state for UI access
            if bypass_recommendations:
                self.analysis_state.tool_states['bypass_recommendations'] = bypass_recommendations
                summary['total_recommendations'] = len(bypass_recommendations.get_all_recommendations())
                summary['high_confidence_recommendations'] = len(bypass_recommendations.get_high_confidence_recommendations())
            
            self.logger.info(f"Unified model finalized: {summary}")
            return summary
            
        except Exception as e:
            error_msg = f"Failed to finalize unified model: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return {"status": "error", "error": error_msg}

    def save_unified_model(self, output_path: str, compress: bool = True) -> bool:
        """
        Save the unified model to disk.
        
        Args:
            output_path: Path to save the model
            compress: Whether to use compression
            
        Returns:
            True if successful, False otherwise
        """
        if not self.model_builder or not self.model_builder.model:
            self.logger.error("No unified model available to save")
            return False
            
        format_type = self.model_serializer.SerializationFormat.JSON_COMPRESSED if compress else self.model_serializer.SerializationFormat.JSON
        return self.model_serializer.save_model(self.model_builder.model, output_path, format_type)

    def load_unified_model(self, input_path: str) -> Optional[UnifiedBinaryModel]:
        """
        Load a unified model from disk.
        
        Args:
            input_path: Path to load the model from
            
        Returns:
            UnifiedBinaryModel if successful, None otherwise
        """
        return self.model_serializer.load_model(input_path)

    def export_model_summary(self, output_path: str) -> bool:
        """
        Export a human-readable summary of the unified model.
        
        Args:
            output_path: Path to save the summary
            
        Returns:
            True if successful, False otherwise
        """
        if not self.model_builder or not self.model_builder.model:
            self.logger.error("No unified model available to export")
            return False
            
        return self.model_serializer.export_summary(self.model_builder.model, output_path)

    def _generate_bypass_recommendations(self, unified_model) -> Optional[Any]:
        """
        Generate AI-driven bypass recommendations based on detected protections.
        
        Args:
            unified_model: The finalized unified binary model
            
        Returns:
            BypassAnalysisResult with recommendations, or None if failed
        """
        try:
            # Import here to avoid circular dependencies
            from ...ai.protection_bypass_advisor import get_protection_bypass_advisor
            
            self.coord_logger.log_phase_start(
                "bypass_recommendation_generation",
                self.analysis_state.binary_path,
                {
                    'protections_detected': len(unified_model.protection_analysis.detected_protections),
                    'functions_analyzed': len(unified_model.function_analysis.functions)
                }
            )
            
            # Get bypass advisor and generate recommendations
            bypass_advisor = get_protection_bypass_advisor()
            recommendations = bypass_advisor.analyze_and_recommend(unified_model)
            
            # Log recommendation generation results
            self.coord_logger.log_phase_complete(
                "bypass_recommendation_generation",
                time.time() - time.time(),  # Duration will be calculated by advisor
                {
                    'total_recommendations': len(recommendations.get_all_recommendations()),
                    'immediate_bypasses': len(recommendations.immediate_bypasses),
                    'strategic_recommendations': len(recommendations.strategic_recommendations),
                    'vulnerability_exploits': len(recommendations.vulnerability_exploits),
                    'overall_difficulty': recommendations.overall_bypass_difficulty.name,
                    'success_probability': recommendations.overall_success_probability
                }
            )
            
            self.logger.info(f"Generated {len(recommendations.get_all_recommendations())} bypass recommendations")
            return recommendations
            
        except ImportError as e:
            self.logger.warning(f"Bypass advisor not available: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to generate bypass recommendations: {e}", exc_info=True)
            return None

    def get_bypass_recommendations(self):
        """
        Get bypass recommendations from the current analysis state.
        
        Returns:
            BypassAnalysisResult if available, None otherwise
        """
        if (self.analysis_state and 
            'bypass_recommendations' in self.analysis_state.tool_states):
            return self.analysis_state.tool_states['bypass_recommendations']
        return None
