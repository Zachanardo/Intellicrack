"""
Behavioral Protection System - Main Integration Point

This module serves as the main integration point for the behavior-based protection
detection system, providing a unified interface for the entire Intellicrack platform.

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
import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto

from .behavior_based_protection_detector import (
    BehaviorBasedProtectionDetector,
    DetectionResult,
    ProtectionFamily,
    BehaviorEvent,
    BehaviorType
)
from .behavioral_integration_manager import (
    BehavioralIntegrationManager,
    IntegrationStatus,
    ComponentStatus
)

# Import existing Intellicrack infrastructure
try:
    from ..app_context import AppContext
    from ..config_manager import ConfigManager
    from ..task_manager import TaskManager
    from ..protection_database import ProtectionPatternEngine
    from ...utils.logger import get_logger
    INTELLICRACK_INFRASTRUCTURE_AVAILABLE = True
except ImportError:
    INTELLICRACK_INFRASTRUCTURE_AVAILABLE = False
    from ...utils.logger import get_logger


class AnalysisMode(Enum):
    """Analysis operation modes."""
    PASSIVE_MONITORING = "passive_monitoring"
    ACTIVE_ANALYSIS = "active_analysis"
    DEEP_BEHAVIORAL = "deep_behavioral"
    REAL_TIME_ONLY = "real_time_only"
    BATCH_PROCESSING = "batch_processing"


class SystemState(Enum):
    """System operational states."""
    OFFLINE = "offline"
    INITIALIZING = "initializing"
    READY = "ready"
    ANALYZING = "analyzing"
    ERROR = "error"
    MAINTENANCE = "maintenance"


@dataclass
class AnalysisSession:
    """Represents an analysis session."""
    session_id: str
    start_time: float
    mode: AnalysisMode
    target_binary: Optional[Path] = None
    target_process: Optional[int] = None
    configuration: Dict[str, Any] = field(default_factory=dict)
    results: List[DetectionResult] = field(default_factory=list)
    status: str = "active"
    metadata: Dict[str, Any] = field(default_factory=dict)


class BehavioralProtectionSystem:
    """Main behavioral protection detection system controller."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize the behavioral protection system.
        
        Args:
            config_path: Optional path to configuration file
        """
        self.logger = get_logger(__name__)
        self.config_path = config_path
        self.state = SystemState.OFFLINE
        
        # Core components
        self.integration_manager = None
        self.behavior_detector = None
        self.app_context = None
        self.config_manager = None
        
        # Session management
        self.current_session = None
        self.session_history = []
        self.session_lock = threading.RLock()
        
        # Callbacks and event handlers
        self.detection_callbacks = []
        self.state_change_callbacks = []
        self.session_callbacks = []
        
        # Performance and monitoring
        self.system_metrics = {
            'initialization_time': 0.0,
            'total_sessions': 0,
            'total_detections': 0,
            'uptime_start': 0.0,
            'last_error': None,
            'component_health': {}
        }
        
        # Initialize system
        self._initialize_system()
    
    def _initialize_system(self):
        """Initialize the behavioral protection system."""
        init_start = time.time()
        self.state = SystemState.INITIALIZING
        
        try:
            self.logger.info("Initializing Behavioral Protection System...")
            
            # Load configuration
            self._load_configuration()
            
            # Initialize core components
            self._initialize_core_components()
            
            # Setup integration with existing Intellicrack infrastructure
            self._setup_intellicrack_integration()
            
            # Initialize monitoring and health checks
            self._initialize_monitoring()
            
            # Mark system as ready
            self.state = SystemState.READY
            self.system_metrics['initialization_time'] = time.time() - init_start
            self.system_metrics['uptime_start'] = time.time()
            
            self.logger.info(f"Behavioral Protection System initialized successfully "
                           f"in {self.system_metrics['initialization_time']:.2f} seconds")
            
            # Notify state change callbacks
            self._notify_state_change(SystemState.READY)
            
        except Exception as e:
            self.state = SystemState.ERROR
            self.system_metrics['last_error'] = str(e)
            self.logger.error(f"System initialization failed: {e}")
            raise
    
    def _load_configuration(self):
        """Load system configuration."""
        try:
            # Default configuration
            self.config = {
                'behavior_detector': {
                    'max_events': 100000,
                    'analysis_window': 30.0,
                    'min_confidence': 0.3,
                    'enable_realtime': True,
                    'enable_ml': True
                },
                'integration': {
                    'auto_start_components': True,
                    'error_retry_attempts': 3,
                    'component_timeout': 30.0
                },
                'analysis': {
                    'default_mode': AnalysisMode.ACTIVE_ANALYSIS.value,
                    'auto_export_results': True,
                    'export_directory': 'behavioral_analysis_results',
                    'session_timeout': 3600.0  # 1 hour
                },
                'monitoring': {
                    'health_check_interval': 10.0,
                    'performance_logging': True,
                    'detailed_metrics': False
                }
            }
            
            # Load from file if provided
            if self.config_path and self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    file_config = json.load(f)
                    self._merge_config(self.config, file_config)
                
                self.logger.info(f"Configuration loaded from {self.config_path}")
            else:
                self.logger.info("Using default configuration")
                
        except Exception as e:
            self.logger.error(f"Configuration loading error: {e}")
            # Continue with default configuration
    
    def _merge_config(self, base_config: Dict[str, Any], new_config: Dict[str, Any]):
        """Recursively merge configuration dictionaries."""
        for key, value in new_config.items():
            if key in base_config and isinstance(base_config[key], dict) and isinstance(value, dict):
                self._merge_config(base_config[key], value)
            else:
                base_config[key] = value
    
    def _initialize_core_components(self):
        """Initialize core behavioral analysis components."""
        try:
            # Initialize integration manager
            self.integration_manager = BehavioralIntegrationManager(
                self.config.get('integration', {})
            )
            
            # Initialize behavior detector
            self.behavior_detector = BehaviorBasedProtectionDetector(
                self.config.get('behavior_detector', {})
            )
            
            # Register detection callback
            self.integration_manager.register_detection_callback(
                self._on_protection_detected
            )
            
            self.logger.info("Core components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Core component initialization failed: {e}")
            raise
    
    def _setup_intellicrack_integration(self):
        """Setup integration with existing Intellicrack infrastructure."""
        if not INTELLICRACK_INFRASTRUCTURE_AVAILABLE:
            self.logger.warning("Intellicrack infrastructure not fully available")
            return
        
        try:
            # Initialize app context if available
            try:
                self.app_context = AppContext.get_instance()
                self.logger.info("Connected to Intellicrack app context")
            except Exception as e:
                self.logger.warning(f"App context not available: {e}")
            
            # Initialize config manager if available
            try:
                self.config_manager = ConfigManager.get_instance()
                self.logger.info("Connected to Intellicrack config manager")
            except Exception as e:
                self.logger.warning(f"Config manager not available: {e}")
            
            # Register with task manager if available
            try:
                task_manager = TaskManager.get_instance()
                task_manager.register_task_handler(
                    'behavioral_analysis',
                    self._handle_task_request
                )
                self.logger.info("Registered with Intellicrack task manager")
            except Exception as e:
                self.logger.warning(f"Task manager not available: {e}")
                
        except Exception as e:
            self.logger.error(f"Intellicrack integration setup failed: {e}")
            # Continue without full integration
    
    def _initialize_monitoring(self):
        """Initialize system monitoring and health checks."""
        try:
            monitoring_config = self.config.get('monitoring', {})
            
            if monitoring_config.get('health_check_interval', 0) > 0:
                # Start health check timer
                self.health_check_timer = threading.Timer(
                    monitoring_config['health_check_interval'],
                    self._perform_health_check
                )
                self.health_check_timer.daemon = True
                self.health_check_timer.start()
                
                self.logger.info("System monitoring initialized")
            
        except Exception as e:
            self.logger.error(f"Monitoring initialization failed: {e}")
    
    def start_analysis(self, 
                      target_binary: Optional[Path] = None,
                      target_process: Optional[int] = None,
                      mode: AnalysisMode = AnalysisMode.ACTIVE_ANALYSIS,
                      session_config: Optional[Dict[str, Any]] = None) -> str:
        """Start a new behavioral analysis session.
        
        Args:
            target_binary: Optional path to target binary
            target_process: Optional target process ID
            mode: Analysis mode
            session_config: Optional session-specific configuration
            
        Returns:
            Session ID
        """
        if self.state != SystemState.READY:
            raise RuntimeError(f"System not ready for analysis (state: {self.state.value})")
        
        try:
            with self.session_lock:
                # Stop any existing session
                if self.current_session:
                    self.stop_analysis()
                
                # Create new session
                session_id = f"session_{int(time.time())}_{len(self.session_history)}"
                
                self.current_session = AnalysisSession(
                    session_id=session_id,
                    start_time=time.time(),
                    mode=mode,
                    target_binary=target_binary,
                    target_process=target_process,
                    configuration=session_config or {},
                    metadata={
                        'created_by': 'behavioral_protection_system',
                        'system_state': self.state.value
                    }
                )
                
                # Start behavioral analysis
                success = self.integration_manager.start_behavioral_analysis(
                    target_binary, target_process
                )
                
                if not success:
                    raise RuntimeError("Failed to start behavioral analysis")
                
                # Update system state
                self.state = SystemState.ANALYZING
                self.system_metrics['total_sessions'] += 1
                
                # Notify callbacks
                self._notify_state_change(SystemState.ANALYZING)
                self._notify_session_start(self.current_session)
                
                self.logger.info(f"Started analysis session {session_id} "
                               f"(mode: {mode.value})")
                
                return session_id
                
        except Exception as e:
            self.logger.error(f"Failed to start analysis: {e}")
            self.state = SystemState.READY
            raise
    
    def stop_analysis(self) -> bool:
        """Stop the current analysis session.
        
        Returns:
            True if successfully stopped
        """
        try:
            with self.session_lock:
                if not self.current_session:
                    self.logger.warning("No active analysis session to stop")
                    return True
                
                # Stop behavioral analysis
                success = self.integration_manager.stop_behavioral_analysis()
                
                # Finalize session
                self.current_session.status = "completed"
                self.current_session.metadata['end_time'] = time.time()
                self.current_session.metadata['duration'] = (
                    time.time() - self.current_session.start_time
                )
                
                # Move to history
                self.session_history.append(self.current_session)
                session_id = self.current_session.session_id
                self.current_session = None
                
                # Update system state
                self.state = SystemState.READY
                
                # Notify callbacks
                self._notify_state_change(SystemState.READY)
                self._notify_session_end(session_id)
                
                self.logger.info(f"Stopped analysis session {session_id}")
                
                return success
                
        except Exception as e:
            self.logger.error(f"Failed to stop analysis: {e}")
            return False
    
    def get_analysis_results(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Get analysis results for a session.
        
        Args:
            session_id: Optional session ID (uses current session if None)
            
        Returns:
            Analysis results dictionary
        """
        try:
            # Get target session
            target_session = None
            
            if session_id is None:
                target_session = self.current_session
            else:
                # Search in history
                for session in self.session_history:
                    if session.session_id == session_id:
                        target_session = session
                        break
                
                # Check current session
                if not target_session and self.current_session:
                    if self.current_session.session_id == session_id:
                        target_session = self.current_session
            
            if not target_session:
                return {'error': f'Session {session_id} not found'}
            
            # Get behavioral analysis results
            behavioral_results = {}
            if self.integration_manager:
                behavioral_results = self.integration_manager.get_comprehensive_report()
            
            # Combine session data with behavioral results
            results = {
                'session_info': {
                    'session_id': target_session.session_id,
                    'start_time': target_session.start_time,
                    'mode': target_session.mode.value,
                    'target_binary': str(target_session.target_binary) if target_session.target_binary else None,
                    'target_process': target_session.target_process,
                    'status': target_session.status,
                    'configuration': target_session.configuration,
                    'metadata': target_session.metadata
                },
                'detection_results': target_session.results,
                'behavioral_analysis': behavioral_results,
                'system_info': {
                    'system_state': self.state.value,
                    'components_available': self.integration_manager is not None,
                    'analysis_mode_supported': True
                }
            }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error getting analysis results: {e}")
            return {'error': str(e)}
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status.
        
        Returns:
            System status dictionary
        """
        try:
            status = {
                'system_state': self.state.value,
                'current_session': None,
                'system_metrics': self.system_metrics.copy(),
                'configuration': self.config,
                'component_status': {},
                'capabilities': {
                    'behavioral_analysis': True,
                    'real_time_detection': True,
                    'ml_classification': True,
                    'signature_matching': True,
                    'temporal_analysis': True,
                    'multi_source_integration': True
                }
            }
            
            # Add current session info
            if self.current_session:
                status['current_session'] = {
                    'session_id': self.current_session.session_id,
                    'start_time': self.current_session.start_time,
                    'mode': self.current_session.mode.value,
                    'target_binary': str(self.current_session.target_binary) if self.current_session.target_binary else None,
                    'duration': time.time() - self.current_session.start_time,
                    'detection_count': len(self.current_session.results)
                }
            
            # Add component status
            if self.integration_manager:
                integration_status = self.integration_manager.get_integration_status()
                status['component_status'] = integration_status
            
            # Calculate uptime
            if self.system_metrics['uptime_start'] > 0:
                status['system_metrics']['uptime'] = time.time() - self.system_metrics['uptime_start']
            
            return status
            
        except Exception as e:
            self.logger.error(f"Error getting system status: {e}")
            return {
                'system_state': 'error',
                'error': str(e)
            }
    
    def export_session_data(self, session_id: str, export_path: Path) -> bool:
        """Export session data and results.
        
        Args:
            session_id: Session ID to export
            export_path: Path for export file
            
        Returns:
            True if export successful
        """
        try:
            # Get session results
            results = self.get_analysis_results(session_id)
            
            if 'error' in results:
                self.logger.error(f"Cannot export session {session_id}: {results['error']}")
                return False
            
            # Add export metadata
            results['export_metadata'] = {
                'export_time': time.time(),
                'exporter': 'behavioral_protection_system',
                'version': '1.0'
            }
            
            # Write to file
            with open(export_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            self.logger.info(f"Exported session {session_id} to {export_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Export failed for session {session_id}: {e}")
            return False
    
    def _on_protection_detected(self, result: DetectionResult):
        """Handle protection detection results."""
        try:
            # Add to current session if active
            if self.current_session:
                self.current_session.results.append(result)
            
            # Update system metrics
            self.system_metrics['total_detections'] += 1
            
            # Notify detection callbacks
            for callback in self.detection_callbacks:
                try:
                    callback(result)
                except Exception as e:
                    self.logger.error(f"Detection callback error: {e}")
            
            self.logger.info(f"Protection detected: {result.family.value} "
                           f"(confidence: {result.confidence:.2f})")
            
        except Exception as e:
            self.logger.error(f"Error handling protection detection: {e}")
    
    def _handle_task_request(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle task requests from Intellicrack task manager."""
        try:
            task_type = task_data.get('type')
            
            if task_type == 'start_behavioral_analysis':
                target_binary = task_data.get('target_binary')
                target_process = task_data.get('target_process')
                mode_str = task_data.get('mode', 'active_analysis')
                
                try:
                    mode = AnalysisMode(mode_str)
                except ValueError:
                    mode = AnalysisMode.ACTIVE_ANALYSIS
                
                session_id = self.start_analysis(
                    Path(target_binary) if target_binary else None,
                    target_process,
                    mode,
                    task_data.get('config')
                )
                
                return {
                    'success': True,
                    'session_id': session_id
                }
            
            elif task_type == 'stop_behavioral_analysis':
                success = self.stop_analysis()
                return {'success': success}
            
            elif task_type == 'get_status':
                return self.get_system_status()
            
            elif task_type == 'get_results':
                session_id = task_data.get('session_id')
                return self.get_analysis_results(session_id)
            
            else:
                return {
                    'success': False,
                    'error': f'Unknown task type: {task_type}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _perform_health_check(self):
        """Perform system health check."""
        try:
            # Check component health
            component_health = {}
            
            if self.integration_manager:
                integration_status = self.integration_manager.get_integration_status()
                component_health['integration_manager'] = integration_status.get('overall_health', 'unknown')
            
            if self.behavior_detector:
                detector_status = self.behavior_detector.get_system_status()
                component_health['behavior_detector'] = 'healthy' if detector_status.get('is_analyzing') is not None else 'unknown'
            
            # Update system metrics
            self.system_metrics['component_health'] = component_health
            
            # Calculate overall health
            health_values = list(component_health.values())
            if all(h == 'healthy' for h in health_values):
                overall_health = 'healthy'
            elif any(h == 'critical' for h in health_values):
                overall_health = 'critical'
            elif any(h == 'error' for h in health_values):
                overall_health = 'degraded'
            else:
                overall_health = 'unknown'
            
            self.system_metrics['overall_health'] = overall_health
            
            # Log health status
            if overall_health != 'healthy':
                self.logger.warning(f"System health check: {overall_health}")
            
            # Schedule next health check
            monitoring_config = self.config.get('monitoring', {})
            if monitoring_config.get('health_check_interval', 0) > 0:
                self.health_check_timer = threading.Timer(
                    monitoring_config['health_check_interval'],
                    self._perform_health_check
                )
                self.health_check_timer.daemon = True
                self.health_check_timer.start()
                
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            self.system_metrics['last_error'] = str(e)
    
    def _notify_state_change(self, new_state: SystemState):
        """Notify state change callbacks."""
        for callback in self.state_change_callbacks:
            try:
                callback(new_state)
            except Exception as e:
                self.logger.error(f"State change callback error: {e}")
    
    def _notify_session_start(self, session: AnalysisSession):
        """Notify session start callbacks."""
        for callback in self.session_callbacks:
            try:
                callback('start', session)
            except Exception as e:
                self.logger.error(f"Session start callback error: {e}")
    
    def _notify_session_end(self, session_id: str):
        """Notify session end callbacks."""
        for callback in self.session_callbacks:
            try:
                callback('end', session_id)
            except Exception as e:
                self.logger.error(f"Session end callback error: {e}")
    
    def register_detection_callback(self, callback: Callable[[DetectionResult], None]):
        """Register callback for protection detection events."""
        self.detection_callbacks.append(callback)
    
    def register_state_change_callback(self, callback: Callable[[SystemState], None]):
        """Register callback for system state changes."""
        self.state_change_callbacks.append(callback)
    
    def register_session_callback(self, callback: Callable[[str, Any], None]):
        """Register callback for session events."""
        self.session_callbacks.append(callback)
    
    def shutdown(self):
        """Shutdown the behavioral protection system."""
        try:
            self.logger.info("Shutting down Behavioral Protection System...")
            
            # Stop any active analysis
            if self.current_session:
                self.stop_analysis()
            
            # Stop health check timer
            if hasattr(self, 'health_check_timer'):
                self.health_check_timer.cancel()
            
            # Shutdown components
            if self.integration_manager:
                self.integration_manager.stop_behavioral_analysis()
            
            self.state = SystemState.OFFLINE
            self.logger.info("Behavioral Protection System shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Shutdown error: {e}")


# Global instance management
_global_instance = None
_instance_lock = threading.Lock()


def get_behavioral_protection_system(config_path: Optional[Path] = None) -> BehavioralProtectionSystem:
    """Get the global behavioral protection system instance.
    
    Args:
        config_path: Optional configuration file path
        
    Returns:
        Global system instance
    """
    global _global_instance
    
    with _instance_lock:
        if _global_instance is None:
            _global_instance = BehavioralProtectionSystem(config_path)
        
        return _global_instance


def shutdown_behavioral_protection_system():
    """Shutdown the global behavioral protection system."""
    global _global_instance
    
    with _instance_lock:
        if _global_instance is not None:
            _global_instance.shutdown()
            _global_instance = None