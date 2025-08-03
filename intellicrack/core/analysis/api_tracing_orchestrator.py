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
"""

"""
API Tracing Orchestrator

This module orchestrates the complete API call tracing and analysis pipeline,
integrating all components for comprehensive behavioral analysis.

Features:
- Unified interface for API tracing pipeline
- Automatic integration with sandbox infrastructure
- Real-time analysis and alerting
- Comprehensive reporting and visualization
- Performance monitoring and optimization
- Integration with existing Intellicrack infrastructure
"""

import asyncio
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum, auto

from .api_call_tracer import APICallTracer, TracingConfiguration, APICall
from .api_pattern_analyzer import APIPatternAnalyzer, DetectedPattern
from .call_stack_analyzer import CallStackAnalyzer, CallChain, StackAnomaly
from .realtime_api_correlator import RealTimeAPICorrelator, CorrelationEvent
from ..reporting.api_trace_reporter import APITraceReporter, ReportFormat
from ..frida_manager import FridaManager, FridaOperationLogger
from ..processing.sandbox_manager import SandboxManager

logger = logging.getLogger(__name__)


class TracingMode(Enum):
    """API tracing modes."""
    PASSIVE = auto()      # Monitor without interference
    ACTIVE = auto()       # Active analysis with modification
    STEALTH = auto()      # Minimal footprint monitoring
    COMPREHENSIVE = auto() # Full analysis with all features


class TracingStatus(Enum):
    """Tracing status."""
    IDLE = auto()
    STARTING = auto()
    RUNNING = auto()
    STOPPING = auto()
    ERROR = auto()


@dataclass
class TracingSession:
    """Represents an active tracing session."""
    session_id: str
    target_process: Union[int, str]
    mode: TracingMode
    start_time: float
    status: TracingStatus
    configuration: TracingConfiguration
    statistics: Dict[str, Any]


class APITracingOrchestrator:
    """
    Orchestrates the complete API tracing and analysis pipeline.
    
    Provides a unified interface for comprehensive API call tracing,
    pattern analysis, and behavioral insights.
    """
    
    def __init__(self, sandbox_manager: Optional[SandboxManager] = None):
        """
        Initialize the API tracing orchestrator.
        
        Args:
            sandbox_manager: Optional sandbox manager for integration
        """
        self.sandbox_manager = sandbox_manager
        
        # Core components
        self.api_tracer = None
        self.pattern_analyzer = APIPatternAnalyzer()
        self.call_stack_analyzer = CallStackAnalyzer()
        self.correlator = RealTimeAPICorrelator()
        self.reporter = APITraceReporter()
        
        # Session management
        self.active_sessions = {}
        self.session_counter = 0
        
        # Event handlers
        self.event_handlers = {
            'pattern_detected': [],
            'anomaly_detected': [],
            'correlation_event': [],
            'session_started': [],
            'session_stopped': []
        }
        
        # Performance monitoring
        self.performance_monitor = TracingPerformanceMonitor()
        
        # Configuration
        self.default_config = TracingConfiguration(
            max_calls_per_second=5000,
            batch_size=50,
            batch_timeout_ms=200,
            enable_call_correlation=True,
            performance_mode=False
        )
        
        logger.info("API Tracing Orchestrator initialized")
    
    def start_tracing_session(self,
                             target_process: Union[int, str],
                             mode: TracingMode = TracingMode.COMPREHENSIVE,
                             config: Optional[TracingConfiguration] = None) -> str:
        """
        Start a new API tracing session.
        
        Args:
            target_process: Process ID or name to trace
            mode: Tracing mode
            config: Optional custom configuration
            
        Returns:
            Session ID for the new tracing session
        """
        try:
            session_id = f"trace_{self.session_counter}_{int(time.time())}"
            self.session_counter += 1
            
            # Use provided config or default
            session_config = config or self._get_mode_configuration(mode)
            
            # Create API tracer
            self.api_tracer = APICallTracer(session_config)
            
            # Create session object
            session = TracingSession(
                session_id=session_id,
                target_process=target_process,
                mode=mode,
                start_time=time.time(),
                status=TracingStatus.STARTING,
                configuration=session_config,
                statistics={}
            )
            
            self.active_sessions[session_id] = session
            
            # Start tracing components
            self._start_tracing_components(session)
            
            # Attach to target process
            if self.api_tracer.attach_to_process(target_process):
                session.status = TracingStatus.RUNNING
                logger.info("Started tracing session %s for process %s", session_id, target_process)
                
                # Notify event handlers
                self._notify_event_handlers('session_started', {
                    'session_id': session_id,
                    'target_process': target_process,
                    'mode': mode.name
                })
                
                return session_id
            else:
                session.status = TracingStatus.ERROR
                del self.active_sessions[session_id]
                raise RuntimeError(f"Failed to attach to process {target_process}")
                
        except Exception as e:
            logger.error("Failed to start tracing session: %s", e)
            raise
    
    def stop_tracing_session(self, session_id: str) -> bool:
        """
        Stop an active tracing session.
        
        Args:
            session_id: ID of session to stop
            
        Returns:
            True if session stopped successfully, False otherwise
        """
        if session_id not in self.active_sessions:
            logger.warning("Session not found: %s", session_id)
            return False
        
        try:
            session = self.active_sessions[session_id]
            session.status = TracingStatus.STOPPING
            
            # Stop tracing components
            self._stop_tracing_components()
            
            # Update session
            session.status = TracingStatus.IDLE
            session.statistics = self._gather_session_statistics()
            
            logger.info("Stopped tracing session %s", session_id)
            
            # Notify event handlers
            self._notify_event_handlers('session_stopped', {
                'session_id': session_id,
                'duration': time.time() - session.start_time,
                'statistics': session.statistics
            })
            
            return True
            
        except Exception as e:
            logger.error("Failed to stop tracing session %s: %s", session_id, e)
            return False
    
    def get_session_analysis(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get comprehensive analysis for a tracing session.
        
        Args:
            session_id: ID of session to analyze
            
        Returns:
            Analysis results or None if session not found
        """
        if session_id not in self.active_sessions:
            return None
        
        try:
            session = self.active_sessions[session_id]
            
            # Gather data from all components
            api_calls = self.api_tracer.get_api_calls() if self.api_tracer else []
            patterns = self.pattern_analyzer.get_recent_patterns(1000)
            call_chains = self.call_stack_analyzer.call_chains
            anomalies = self.call_stack_analyzer.detected_anomalies
            correlation_events = self.correlator.get_recent_events(1000)
            
            return {
                'session_info': {
                    'session_id': session_id,
                    'target_process': session.target_process,
                    'mode': session.mode.name,
                    'start_time': session.start_time,
                    'duration': time.time() - session.start_time,
                    'status': session.status.name
                },
                'api_calls': api_calls,
                'patterns': patterns,
                'call_chains': call_chains,
                'anomalies': anomalies,
                'correlation_events': correlation_events,
                'statistics': self._gather_session_statistics()
            }
            
        except Exception as e:
            logger.error("Failed to get session analysis for %s: %s", session_id, e)
            return None
    
    def generate_session_report(self,
                               session_id: str,
                               output_path: Path,
                               format: ReportFormat = ReportFormat.HTML) -> bool:
        """
        Generate comprehensive report for a tracing session.
        
        Args:
            session_id: ID of session to report on
            output_path: Path for output file
            format: Report format
            
        Returns:
            True if report generated successfully, False otherwise
        """
        analysis = self.get_session_analysis(session_id)
        if not analysis:
            logger.error("Cannot generate report for unknown session: %s", session_id)
            return False
        
        return self.reporter.generate_comprehensive_report(
            api_calls=analysis['api_calls'],
            patterns=analysis['patterns'],
            call_chains=analysis['call_chains'],
            anomalies=analysis['anomalies'],
            correlation_events=analysis['correlation_events'],
            output_path=output_path,
            format=format
        )
    
    def add_event_handler(self, event_type: str, handler: Callable) -> None:
        """
        Add event handler for tracing events.
        
        Args:
            event_type: Type of event ('pattern_detected', 'anomaly_detected', etc.)
            handler: Function to call when event occurs
        """
        if event_type in self.event_handlers:
            self.event_handlers[event_type].append(handler)
            logger.info("Added event handler for %s", event_type)
        else:
            logger.warning("Unknown event type: %s", event_type)
    
    def get_active_sessions(self) -> Dict[str, TracingSession]:
        """Get all active tracing sessions."""
        return self.active_sessions.copy()
    
    def get_orchestrator_statistics(self) -> Dict[str, Any]:
        """Get comprehensive orchestrator statistics."""
        stats = {
            'active_sessions': len(self.active_sessions),
            'total_sessions': self.session_counter,
            'performance_stats': self.performance_monitor.get_statistics()
        }
        
        # Add component statistics
        if self.api_tracer:
            stats['api_tracer'] = self.api_tracer.get_statistics()
        
        stats['pattern_analyzer'] = self.pattern_analyzer.get_pattern_statistics()
        stats['call_stack_analyzer'] = self.call_stack_analyzer.get_statistics()
        stats['correlator'] = self.correlator.get_statistics()
        
        return stats
    
    def _get_mode_configuration(self, mode: TracingMode) -> TracingConfiguration:
        """Get configuration for specific tracing mode."""
        base_config = self.default_config
        
        if mode == TracingMode.STEALTH:
            # Minimal footprint configuration
            return TracingConfiguration(
                max_calls_per_second=1000,
                batch_size=20,
                batch_timeout_ms=500,
                enable_memory_snapshots=False,
                enable_call_correlation=False,
                performance_mode=True
            )
        
        elif mode == TracingMode.PASSIVE:
            # Monitor-only configuration
            return TracingConfiguration(
                max_calls_per_second=3000,
                batch_size=30,
                batch_timeout_ms=300,
                enable_memory_snapshots=False,
                enable_call_correlation=True,
                performance_mode=False
            )
        
        elif mode == TracingMode.ACTIVE:
            # Active analysis configuration
            return TracingConfiguration(
                max_calls_per_second=5000,
                batch_size=50,
                batch_timeout_ms=200,
                enable_memory_snapshots=True,
                enable_call_correlation=True,
                performance_mode=False
            )
        
        elif mode == TracingMode.COMPREHENSIVE:
            # Full feature configuration
            return TracingConfiguration(
                max_calls_per_second=8000,
                batch_size=100,
                batch_timeout_ms=100,
                enable_memory_snapshots=True,
                enable_call_correlation=True,
                performance_mode=False
            )
        
        return base_config
    
    def _start_tracing_components(self, session: TracingSession) -> None:
        """Start all tracing components for a session."""
        try:
            # Start API tracer
            self.api_tracer.start_tracing()
            
            # Start correlator
            self.correlator.start_correlation()
            
            # Set up component integration
            self._setup_component_integration()
            
            logger.info("Started tracing components for session %s", session.session_id)
            
        except Exception as e:
            logger.error("Failed to start tracing components: %s", e)
            raise
    
    def _stop_tracing_components(self) -> None:
        """Stop all tracing components."""
        try:
            if self.api_tracer:
                self.api_tracer.stop_tracing()
            
            if self.correlator:
                self.correlator.stop_correlation()
            
            logger.info("Stopped all tracing components")
            
        except Exception as e:
            logger.error("Failed to stop tracing components: %s", e)
    
    def _setup_component_integration(self) -> None:
        """Set up integration between components."""
        # Set up real-time processing pipeline
        def process_api_call(api_call: APICall):
            """Process API call through analysis pipeline."""
            try:
                # Pattern analysis
                detected_patterns = self.pattern_analyzer.analyze_api_call(api_call)
                for pattern in detected_patterns:
                    self._notify_event_handlers('pattern_detected', {
                        'pattern': pattern,
                        'api_call': api_call
                    })
                
                # Call stack analysis
                anomalies = self.call_stack_analyzer.analyze_call_stack(api_call)
                for anomaly in anomalies:
                    self._notify_event_handlers('anomaly_detected', {
                        'anomaly': anomaly,
                        'api_call': api_call
                    })
                
                # Real-time correlation
                correlation_events = self.correlator.process_api_call(api_call)
                for event in correlation_events:
                    self._notify_event_handlers('correlation_event', {
                        'event': event,
                        'api_call': api_call
                    })
                
            except Exception as e:
                logger.error("Error in API call processing pipeline: %s", e)
        
        # Hook into API tracer if available
        if hasattr(self.api_tracer, 'add_call_handler'):
            self.api_tracer.add_call_handler(process_api_call)
    
    def _gather_session_statistics(self) -> Dict[str, Any]:
        """Gather statistics from all components."""
        stats = {}
        
        if self.api_tracer:
            stats['api_tracer'] = self.api_tracer.get_statistics()
        
        stats['pattern_analyzer'] = self.pattern_analyzer.get_pattern_statistics()
        stats['call_stack_analyzer'] = self.call_stack_analyzer.get_statistics()
        stats['correlator'] = self.correlator.get_statistics()
        
        return stats
    
    def _notify_event_handlers(self, event_type: str, event_data: Dict[str, Any]) -> None:
        """Notify registered event handlers."""
        for handler in self.event_handlers.get(event_type, []):
            try:
                handler(event_data)
            except Exception as e:
                logger.error("Error in event handler for %s: %s", event_type, e)
    
    # Sandbox integration methods
    def integrate_with_sandbox(self, sandbox_manager: SandboxManager) -> None:
        """
        Integrate orchestrator with sandbox manager.
        
        Args:
            sandbox_manager: Sandbox manager to integrate with
        """
        self.sandbox_manager = sandbox_manager
        
        # Set up automatic tracing for sandbox processes
        def on_sandbox_process_started(process_info):
            """Start tracing when sandbox process starts."""
            try:
                session_id = self.start_tracing_session(
                    target_process=process_info['pid'],
                    mode=TracingMode.COMPREHENSIVE
                )
                logger.info("Started automatic tracing for sandbox process %d (session: %s)",
                           process_info['pid'], session_id)
            except Exception as e:
                logger.error("Failed to start automatic tracing for sandbox process: %s", e)
        
        # Register sandbox event handler
        if hasattr(sandbox_manager, 'add_process_handler'):
            sandbox_manager.add_process_handler('process_started', on_sandbox_process_started)
    
    def trace_sandbox_execution(self,
                               target_binary: Path,
                               analysis_timeout: int = 300) -> Optional[str]:
        """
        Trace execution in sandbox environment.
        
        Args:
            target_binary: Binary to execute and trace
            analysis_timeout: Maximum analysis time in seconds
            
        Returns:
            Session ID if successful, None otherwise
        """
        if not self.sandbox_manager:
            logger.error("No sandbox manager available for sandbox tracing")
            return None
        
        try:
            # Start sandbox execution
            sandbox_result = self.sandbox_manager.execute_binary(
                str(target_binary),
                timeout=analysis_timeout
            )
            
            if sandbox_result and 'pid' in sandbox_result:
                # Start tracing session
                session_id = self.start_tracing_session(
                    target_process=sandbox_result['pid'],
                    mode=TracingMode.COMPREHENSIVE
                )
                
                logger.info("Started sandbox tracing session %s for %s", session_id, target_binary)
                return session_id
            else:
                logger.error("Failed to start sandbox execution for %s", target_binary)
                return None
                
        except Exception as e:
            logger.error("Failed to trace sandbox execution: %s", e)
            return None


class TracingPerformanceMonitor:
    """Monitor performance of the tracing orchestrator."""
    
    def __init__(self):
        """Initialize performance monitor."""
        self.metrics = {
            'api_calls_processed': 0,
            'patterns_detected': 0,
            'anomalies_found': 0,
            'correlation_events': 0,
            'processing_time_ms': 0,
            'memory_usage_mb': 0
        }
        self.start_time = time.time()
    
    def record_metric(self, name: str, value: Union[int, float]) -> None:
        """Record a performance metric."""
        if name in self.metrics:
            self.metrics[name] += value
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get performance statistics."""
        runtime = time.time() - self.start_time
        
        return {
            **self.metrics,
            'runtime_seconds': runtime,
            'calls_per_second': self.metrics['api_calls_processed'] / runtime if runtime > 0 else 0,
            'avg_processing_time_ms': (
                self.metrics['processing_time_ms'] / max(self.metrics['api_calls_processed'], 1)
            )
        }