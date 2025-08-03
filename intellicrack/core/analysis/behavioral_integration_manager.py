"""
Behavioral Integration Manager

This module integrates the behavior-based protection detection system with
existing Intellicrack components, providing seamless data flow and coordination
between different analysis systems.

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
import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto

from .behavior_based_protection_detector import (
    BehaviorBasedProtectionDetector,
    BehaviorEvent,
    BehaviorType,
    DetectionResult,
    ProtectionFamily
)

# Import existing Intellicrack components
try:
    from .api_tracing_orchestrator import APITracingOrchestrator
    from .api_call_tracer import APICall, APICallTracer
    from .dynamic_analyzer import AdvancedDynamicAnalyzer
    from .memory_forensics_engine import MemoryForensicsEngine
    from .network_forensics_engine import NetworkForensicsEngine
    from ..processing.sandbox_manager import SandboxManager
    from ..network.traffic_analyzer import TrafficAnalyzer
    from ..frida_manager import FridaManager
    INTELLICRACK_COMPONENTS_AVAILABLE = True
except ImportError as e:
    INTELLICRACK_COMPONENTS_AVAILABLE = False
    print(f"Some Intellicrack components not available: {e}")

from ...utils.logger import get_logger


class IntegrationStatus(Enum):
    """Status of component integration."""
    NOT_INITIALIZED = "not_initialized"
    INITIALIZING = "initializing"
    READY = "ready"
    RUNNING = "running"
    ERROR = "error"
    STOPPED = "stopped"


@dataclass
class ComponentStatus:
    """Status information for integrated components."""
    name: str
    status: IntegrationStatus
    last_update: float
    error_message: Optional[str] = None
    data_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class DataSourceAdapter:
    """Adapter for converting different data sources to behavioral events."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.conversion_stats = {
            'total_conversions': 0,
            'conversion_errors': 0,
            'api_calls_converted': 0,
            'memory_events_converted': 0,
            'network_events_converted': 0
        }
    
    def convert_api_call(self, api_call: Any, source: str = "api_tracer") -> Optional[BehaviorEvent]:
        """Convert API call data to behavioral event."""
        try:
            # Handle different API call formats
            if hasattr(api_call, 'function_name'):
                # APICall object from api_call_tracer
                event = BehaviorEvent(
                    timestamp=getattr(api_call, 'timestamp', time.time()),
                    event_type=BehaviorType.API_SEQUENCE,
                    source=source,
                    data={
                        'api_name': api_call.function_name,
                        'module': getattr(api_call, 'module_name', 'unknown'),
                        'parameters': getattr(api_call, 'parameters', {}),
                        'return_value': getattr(api_call, 'return_value', None),
                        'thread_id': getattr(api_call, 'thread_id', None)
                    },
                    process_id=getattr(api_call, 'process_id', None),
                    thread_id=getattr(api_call, 'thread_id', None)
                )
            elif isinstance(api_call, dict):
                # Dictionary format
                event = BehaviorEvent(
                    timestamp=api_call.get('timestamp', time.time()),
                    event_type=BehaviorType.API_SEQUENCE,
                    source=source,
                    data={
                        'api_name': api_call.get('name', api_call.get('function_name', 'unknown')),
                        'module': api_call.get('module', 'unknown'),
                        'parameters': api_call.get('parameters', api_call.get('args', {})),
                        'return_value': api_call.get('return_value', api_call.get('result')),
                        'thread_id': api_call.get('thread_id')
                    },
                    process_id=api_call.get('process_id'),
                    thread_id=api_call.get('thread_id')
                )
            else:
                self.logger.warning(f"Unknown API call format: {type(api_call)}")
                return None
            
            self.conversion_stats['api_calls_converted'] += 1
            self.conversion_stats['total_conversions'] += 1
            return event
            
        except Exception as e:
            self.logger.error(f"Error converting API call: {e}")
            self.conversion_stats['conversion_errors'] += 1
            return None
    
    def convert_memory_event(self, memory_data: Any, source: str = "memory_monitor") -> List[BehaviorEvent]:
        """Convert memory analysis data to behavioral events."""
        events = []
        
        try:
            if isinstance(memory_data, dict):
                # Handle memory access logs
                if 'accesses' in memory_data:
                    for access in memory_data['accesses']:
                        event = BehaviorEvent(
                            timestamp=access.get('timestamp', time.time()),
                            event_type=BehaviorType.MEMORY_ACCESS,
                            source=source,
                            data={
                                'address': access.get('address'),
                                'size': access.get('size', 0),
                                'access_type': access.get('type', 'read'),
                                'protection': access.get('protection'),
                                'module': access.get('module')
                            },
                            process_id=memory_data.get('process_id')
                        )
                        events.append(event)
                
                # Handle memory allocations
                elif 'allocations' in memory_data:
                    for alloc in memory_data['allocations']:
                        event = BehaviorEvent(
                            timestamp=alloc.get('timestamp', time.time()),
                            event_type=BehaviorType.MEMORY_ACCESS,
                            source=source,
                            data={
                                'address': alloc.get('address'),
                                'size': alloc.get('size', 0),
                                'access_type': 'allocate',
                                'protection': alloc.get('protection'),
                                'allocation_type': alloc.get('type')
                            },
                            process_id=memory_data.get('process_id')
                        )
                        events.append(event)
            
            self.conversion_stats['memory_events_converted'] += len(events)
            self.conversion_stats['total_conversions'] += len(events)
            
        except Exception as e:
            self.logger.error(f"Error converting memory event: {e}")
            self.conversion_stats['conversion_errors'] += 1
        
        return events
    
    def convert_network_event(self, network_data: Any, source: str = "network_monitor") -> Optional[BehaviorEvent]:
        """Convert network traffic data to behavioral event."""
        try:
            if isinstance(network_data, dict):
                event = BehaviorEvent(
                    timestamp=network_data.get('timestamp', time.time()),
                    event_type=BehaviorType.NETWORK_ACTIVITY,
                    source=source,
                    data={
                        'protocol': network_data.get('protocol', 'unknown'),
                        'src_ip': network_data.get('src_ip'),
                        'dst_ip': network_data.get('dst_ip'),
                        'src_port': network_data.get('src_port'),
                        'dst_port': network_data.get('dst_port'),
                        'size': network_data.get('size', 0),
                        'direction': network_data.get('direction', 'unknown'),
                        'payload_summary': network_data.get('payload_summary')
                    },
                    process_id=network_data.get('process_id')
                )
                
                self.conversion_stats['network_events_converted'] += 1
                self.conversion_stats['total_conversions'] += 1
                return event
                
        except Exception as e:
            self.logger.error(f"Error converting network event: {e}")
            self.conversion_stats['conversion_errors'] += 1
        
        return None
    
    def convert_file_event(self, file_data: Any, source: str = "file_monitor") -> Optional[BehaviorEvent]:
        """Convert file system activity to behavioral event."""
        try:
            if isinstance(file_data, dict):
                event = BehaviorEvent(
                    timestamp=file_data.get('timestamp', time.time()),
                    event_type=BehaviorType.FILE_OPERATION,
                    source=source,
                    data={
                        'operation': file_data.get('operation', 'unknown'),
                        'file_path': file_data.get('path', file_data.get('file_path')),
                        'size': file_data.get('size', 0),
                        'success': file_data.get('success', True),
                        'error_code': file_data.get('error_code')
                    },
                    process_id=file_data.get('process_id')
                )
                
                self.conversion_stats['total_conversions'] += 1
                return event
                
        except Exception as e:
            self.logger.error(f"Error converting file event: {e}")
            self.conversion_stats['conversion_errors'] += 1
        
        return None
    
    def convert_registry_event(self, registry_data: Any, source: str = "registry_monitor") -> Optional[BehaviorEvent]:
        """Convert registry access to behavioral event."""
        try:
            if isinstance(registry_data, dict):
                event = BehaviorEvent(
                    timestamp=registry_data.get('timestamp', time.time()),
                    event_type=BehaviorType.REGISTRY_ACCESS,
                    source=source,
                    data={
                        'operation': registry_data.get('operation', 'unknown'),
                        'key_path': registry_data.get('key_path', registry_data.get('path')),
                        'value_name': registry_data.get('value_name'),
                        'value_data': registry_data.get('value_data'),
                        'value_type': registry_data.get('value_type'),
                        'success': registry_data.get('success', True)
                    },
                    process_id=registry_data.get('process_id')
                )
                
                self.conversion_stats['total_conversions'] += 1
                return event
                
        except Exception as e:
            self.logger.error(f"Error converting registry event: {e}")
            self.conversion_stats['conversion_errors'] += 1
        
        return None


class BehavioralIntegrationManager:
    """Manages integration between behavior detection and existing Intellicrack components."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.logger = get_logger(__name__)
        self.config = config or self._get_default_config()
        
        # Initialize behavior detector
        self.behavior_detector = BehaviorBasedProtectionDetector(
            self.config.get('behavior_detector', {})
        )
        
        # Data source adapter
        self.data_adapter = DataSourceAdapter()
        
        # Component status tracking
        self.component_status = {}
        self.integration_lock = threading.RLock()
        
        # Data collection state
        self.is_collecting = False
        self.collection_threads = {}
        
        # Integration callbacks
        self.detection_callbacks = []
        self.status_callbacks = []
        
        # Performance monitoring
        self.integration_stats = {
            'start_time': time.time(),
            'events_processed': 0,
            'errors_encountered': 0,
            'components_integrated': 0,
            'active_sources': 0
        }
        
        # Initialize component connections
        self._initialize_components()
        
        self.logger.info("Behavioral integration manager initialized")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default integration configuration."""
        return {
            'behavior_detector': {
                'max_events': 100000,
                'analysis_window': 30.0,
                'min_confidence': 0.3,
                'enable_realtime': True
            },
            'data_collection': {
                'api_tracing_enabled': True,
                'memory_monitoring_enabled': True,
                'network_monitoring_enabled': True,
                'file_monitoring_enabled': True,
                'registry_monitoring_enabled': True,
                'collection_interval': 0.1
            },
            'integration': {
                'auto_start_components': True,
                'error_retry_attempts': 3,
                'component_timeout': 30.0,
                'status_update_interval': 5.0
            },
            'performance': {
                'max_events_per_batch': 1000,
                'batch_processing_interval': 1.0,
                'memory_usage_limit': 1024 * 1024 * 1024  # 1GB
            }
        }
    
    def _initialize_components(self):
        """Initialize connections to Intellicrack components."""
        if not INTELLICRACK_COMPONENTS_AVAILABLE:
            self.logger.warning("Intellicrack components not fully available")
            return
        
        try:
            # Initialize API tracing integration
            self._initialize_api_tracing()
            
            # Initialize memory monitoring integration
            self._initialize_memory_monitoring()
            
            # Initialize network monitoring integration
            self._initialize_network_monitoring()
            
            # Initialize sandbox integration
            self._initialize_sandbox_integration()
            
            self.logger.info("Component initialization completed")
            
        except Exception as e:
            self.logger.error(f"Component initialization error: {e}")
    
    def _initialize_api_tracing(self):
        """Initialize API tracing integration."""
        try:
            self.component_status['api_tracer'] = ComponentStatus(
                name='api_tracer',
                status=IntegrationStatus.INITIALIZING,
                last_update=time.time()
            )
            
            # Register data source with behavior detector
            def get_api_events():
                return self._collect_api_events()
            
            self.behavior_detector.data_collector.register_source("api_tracer", get_api_events)
            
            self.component_status['api_tracer'].status = IntegrationStatus.READY
            self.integration_stats['components_integrated'] += 1
            
            self.logger.info("API tracing integration initialized")
            
        except Exception as e:
            self.component_status['api_tracer'] = ComponentStatus(
                name='api_tracer',
                status=IntegrationStatus.ERROR,
                last_update=time.time(),
                error_message=str(e)
            )
            self.logger.error(f"API tracing initialization error: {e}")
    
    def _initialize_memory_monitoring(self):
        """Initialize memory monitoring integration."""
        try:
            self.component_status['memory_monitor'] = ComponentStatus(
                name='memory_monitor',
                status=IntegrationStatus.INITIALIZING,
                last_update=time.time()
            )
            
            # Register data source
            def get_memory_events():
                return self._collect_memory_events()
            
            self.behavior_detector.data_collector.register_source("memory_monitor", get_memory_events)
            
            self.component_status['memory_monitor'].status = IntegrationStatus.READY
            self.integration_stats['components_integrated'] += 1
            
            self.logger.info("Memory monitoring integration initialized")
            
        except Exception as e:
            self.component_status['memory_monitor'] = ComponentStatus(
                name='memory_monitor',
                status=IntegrationStatus.ERROR,
                last_update=time.time(),
                error_message=str(e)
            )
            self.logger.error(f"Memory monitoring initialization error: {e}")
    
    def _initialize_network_monitoring(self):
        """Initialize network monitoring integration."""
        try:
            self.component_status['network_monitor'] = ComponentStatus(
                name='network_monitor',
                status=IntegrationStatus.INITIALIZING,
                last_update=time.time()
            )
            
            # Register data source
            def get_network_events():
                return self._collect_network_events()
            
            self.behavior_detector.data_collector.register_source("network_monitor", get_network_events)
            
            self.component_status['network_monitor'].status = IntegrationStatus.READY
            self.integration_stats['components_integrated'] += 1
            
            self.logger.info("Network monitoring integration initialized")
            
        except Exception as e:
            self.component_status['network_monitor'] = ComponentStatus(
                name='network_monitor',
                status=IntegrationStatus.ERROR,
                last_update=time.time(),
                error_message=str(e)
            )
            self.logger.error(f"Network monitoring initialization error: {e}")
    
    def _initialize_sandbox_integration(self):
        """Initialize sandbox manager integration."""
        try:
            self.component_status['sandbox_manager'] = ComponentStatus(
                name='sandbox_manager',
                status=IntegrationStatus.INITIALIZING,
                last_update=time.time()
            )
            
            # Sandbox integration will be handled through other components
            self.component_status['sandbox_manager'].status = IntegrationStatus.READY
            
            self.logger.info("Sandbox integration initialized")
            
        except Exception as e:
            self.component_status['sandbox_manager'] = ComponentStatus(
                name='sandbox_manager',
                status=IntegrationStatus.ERROR,
                last_update=time.time(),
                error_message=str(e)
            )
            self.logger.error(f"Sandbox integration error: {e}")
    
    def start_behavioral_analysis(self, target_binary: Optional[Path] = None,
                                target_process: Optional[int] = None) -> bool:
        """Start comprehensive behavioral analysis."""
        try:
            with self.integration_lock:
                if self.is_collecting:
                    self.logger.warning("Behavioral analysis already running")
                    return False
                
                # Start behavior detector
                self.behavior_detector.start_analysis(target_process)
                
                # Register detection callback
                self.behavior_detector.register_detection_callback(self._on_protection_detected)
                
                # Start data collection
                self._start_data_collection()
                
                # Update component statuses
                for component_name in self.component_status:
                    if self.component_status[component_name].status == IntegrationStatus.READY:
                        self.component_status[component_name].status = IntegrationStatus.RUNNING
                        self.component_status[component_name].last_update = time.time()
                
                self.is_collecting = True
                self.integration_stats['active_sources'] = len([
                    c for c in self.component_status.values() 
                    if c.status == IntegrationStatus.RUNNING
                ])
                
                self.logger.info(f"Started behavioral analysis"
                               f"{f' for binary: {target_binary}' if target_binary else ''}"
                               f"{f' for process: {target_process}' if target_process else ''}")
                
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to start behavioral analysis: {e}")
            return False
    
    def stop_behavioral_analysis(self) -> bool:
        """Stop behavioral analysis and data collection."""
        try:
            with self.integration_lock:
                if not self.is_collecting:
                    return True
                
                # Stop behavior detector
                self.behavior_detector.stop_analysis()
                
                # Stop data collection
                self._stop_data_collection()
                
                # Update component statuses
                for component_name in self.component_status:
                    if self.component_status[component_name].status == IntegrationStatus.RUNNING:
                        self.component_status[component_name].status = IntegrationStatus.READY
                        self.component_status[component_name].last_update = time.time()
                
                self.is_collecting = False
                self.integration_stats['active_sources'] = 0
                
                self.logger.info("Stopped behavioral analysis")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to stop behavioral analysis: {e}")
            return False
    
    def _start_data_collection(self):
        """Start data collection from all sources."""
        collection_config = self.config.get('data_collection', {})
        
        # Start API tracing collection
        if collection_config.get('api_tracing_enabled', True):
            self._start_api_collection()
        
        # Start memory monitoring collection
        if collection_config.get('memory_monitoring_enabled', True):
            self._start_memory_collection()
        
        # Start network monitoring collection
        if collection_config.get('network_monitoring_enabled', True):
            self._start_network_collection()
        
        # Start file system monitoring
        if collection_config.get('file_monitoring_enabled', True):
            self._start_file_collection()
        
        # Start registry monitoring
        if collection_config.get('registry_monitoring_enabled', True):
            self._start_registry_collection()
    
    def _stop_data_collection(self):
        """Stop all data collection threads."""
        for thread_name, thread in self.collection_threads.items():
            try:
                if thread and thread.is_alive():
                    # For production implementation, you would properly signal thread shutdown
                    self.logger.info(f"Stopping collection thread: {thread_name}")
            except Exception as e:
                self.logger.error(f"Error stopping thread {thread_name}: {e}")
        
        self.collection_threads.clear()
    
    def _collect_api_events(self) -> List[BehaviorEvent]:
        """Collect API events from tracing system."""
        events = []
        
        try:
            # This is a placeholder for actual API tracing integration
            # In a real implementation, this would interface with the
            # existing API tracing orchestrator
            
            # Example: Get recent API calls from the tracer
            # if hasattr(self, 'api_tracer') and self.api_tracer:
            #     api_calls = self.api_tracer.get_recent_calls()
            #     for api_call in api_calls:
            #         event = self.data_adapter.convert_api_call(api_call)
            #         if event:
            #             events.append(event)
            
            pass  # Placeholder implementation
            
        except Exception as e:
            self.logger.error(f"Error collecting API events: {e}")
            self.integration_stats['errors_encountered'] += 1
        
        return events
    
    def _collect_memory_events(self) -> List[BehaviorEvent]:
        """Collect memory events from forensics engine."""
        events = []
        
        try:
            # Placeholder for memory forensics integration
            # In real implementation, this would interface with
            # the memory forensics engine
            
            pass  # Placeholder implementation
            
        except Exception as e:
            self.logger.error(f"Error collecting memory events: {e}")
            self.integration_stats['errors_encountered'] += 1
        
        return events
    
    def _collect_network_events(self) -> List[BehaviorEvent]:
        """Collect network events from traffic analyzer."""
        events = []
        
        try:
            # Placeholder for network monitoring integration
            # In real implementation, this would interface with
            # the network forensics engine
            
            pass  # Placeholder implementation
            
        except Exception as e:
            self.logger.error(f"Error collecting network events: {e}")
            self.integration_stats['errors_encountered'] += 1
        
        return events
    
    def _start_api_collection(self):
        """Start API call collection thread."""
        def api_collection_worker():
            while self.is_collecting:
                try:
                    # Simulate API call collection
                    # In real implementation, this would actively collect from API tracer
                    time.sleep(self.config['data_collection']['collection_interval'])
                    
                except Exception as e:
                    self.logger.error(f"API collection error: {e}")
                    time.sleep(1.0)
        
        thread = threading.Thread(target=api_collection_worker, daemon=True)
        thread.start()
        self.collection_threads['api_collection'] = thread
    
    def _start_memory_collection(self):
        """Start memory monitoring collection thread."""
        def memory_collection_worker():
            while self.is_collecting:
                try:
                    # Simulate memory event collection
                    time.sleep(self.config['data_collection']['collection_interval'])
                    
                except Exception as e:
                    self.logger.error(f"Memory collection error: {e}")
                    time.sleep(1.0)
        
        thread = threading.Thread(target=memory_collection_worker, daemon=True)
        thread.start()
        self.collection_threads['memory_collection'] = thread
    
    def _start_network_collection(self):
        """Start network monitoring collection thread."""
        def network_collection_worker():
            while self.is_collecting:
                try:
                    # Simulate network event collection
                    time.sleep(self.config['data_collection']['collection_interval'])
                    
                except Exception as e:
                    self.logger.error(f"Network collection error: {e}")
                    time.sleep(1.0)
        
        thread = threading.Thread(target=network_collection_worker, daemon=True)
        thread.start()
        self.collection_threads['network_collection'] = thread
    
    def _start_file_collection(self):
        """Start file system monitoring collection thread."""
        def file_collection_worker():
            while self.is_collecting:
                try:
                    # Simulate file system event collection
                    time.sleep(self.config['data_collection']['collection_interval'])
                    
                except Exception as e:
                    self.logger.error(f"File collection error: {e}")
                    time.sleep(1.0)
        
        thread = threading.Thread(target=file_collection_worker, daemon=True)
        thread.start()
        self.collection_threads['file_collection'] = thread
    
    def _start_registry_collection(self):
        """Start registry monitoring collection thread."""
        def registry_collection_worker():
            while self.is_collecting:
                try:
                    # Simulate registry event collection
                    time.sleep(self.config['data_collection']['collection_interval'])
                    
                except Exception as e:
                    self.logger.error(f"Registry collection error: {e}")
                    time.sleep(1.0)
        
        thread = threading.Thread(target=registry_collection_worker, daemon=True)
        thread.start()
        self.collection_threads['registry_collection'] = thread
    
    def _on_protection_detected(self, result: DetectionResult):
        """Handle protection detection results."""
        self.logger.info(f"Protection detected: {result.family.value} "
                        f"(confidence: {result.confidence:.2f})")
        
        # Update component status with detection info
        for component_name in self.component_status:
            component = self.component_status[component_name]
            if component.status == IntegrationStatus.RUNNING:
                component.metadata['last_detection'] = {
                    'family': result.family.value,
                    'confidence': result.confidence,
                    'timestamp': time.time()
                }
        
        # Notify registered callbacks
        for callback in self.detection_callbacks:
            try:
                callback(result)
            except Exception as e:
                self.logger.error(f"Detection callback error: {e}")
    
    def register_detection_callback(self, callback: Callable[[DetectionResult], None]):
        """Register callback for protection detection notifications."""
        self.detection_callbacks.append(callback)
    
    def register_status_callback(self, callback: Callable[[Dict[str, ComponentStatus]], None]):
        """Register callback for component status updates."""
        self.status_callbacks.append(callback)
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive behavioral analysis report."""
        # Get behavior detector report
        behavior_report = self.behavior_detector.get_protection_report()
        
        # Get component status summary
        component_summary = {}
        for name, status in self.component_status.items():
            component_summary[name] = {
                'status': status.status.value,
                'last_update': status.last_update,
                'data_count': status.data_count,
                'error_message': status.error_message,
                'metadata': status.metadata
            }
        
        # Get integration statistics
        integration_stats = self.integration_stats.copy()
        integration_stats['uptime'] = time.time() - integration_stats['start_time']
        integration_stats['conversion_stats'] = self.data_adapter.conversion_stats.copy()
        
        # Combine reports
        comprehensive_report = {
            'behavioral_analysis': behavior_report,
            'component_integration': {
                'status_summary': component_summary,
                'integration_stats': integration_stats,
                'is_collecting': self.is_collecting,
                'components_available': INTELLICRACK_COMPONENTS_AVAILABLE
            },
            'system_health': {
                'overall_status': self._calculate_overall_status(),
                'error_rate': self._calculate_error_rate(),
                'data_flow_health': self._assess_data_flow_health()
            },
            'configuration': {
                'behavior_detector_config': self.behavior_detector.config,
                'integration_config': self.config,
                'active_data_sources': list(self.behavior_detector.data_collector.event_sources.keys())
            },
            'report_metadata': {
                'generation_time': time.time(),
                'report_version': '1.0',
                'components_integrated': len(self.component_status)
            }
        }
        
        return comprehensive_report
    
    def _calculate_overall_status(self) -> str:
        """Calculate overall system health status."""
        if not self.component_status:
            return 'unknown'
        
        error_count = sum(1 for c in self.component_status.values() 
                         if c.status == IntegrationStatus.ERROR)
        running_count = sum(1 for c in self.component_status.values() 
                           if c.status == IntegrationStatus.RUNNING)
        ready_count = sum(1 for c in self.component_status.values() 
                         if c.status == IntegrationStatus.READY)
        
        total_components = len(self.component_status)
        
        if error_count > total_components * 0.5:
            return 'critical'
        elif error_count > 0:
            return 'degraded'
        elif running_count > 0 or ready_count == total_components:
            return 'healthy'
        else:
            return 'unknown'
    
    def _calculate_error_rate(self) -> float:
        """Calculate error rate across all operations."""
        total_operations = (self.integration_stats['events_processed'] + 
                          self.data_adapter.conversion_stats['total_conversions'])
        
        if total_operations == 0:
            return 0.0
        
        total_errors = (self.integration_stats['errors_encountered'] + 
                       self.data_adapter.conversion_stats['conversion_errors'])
        
        return total_errors / total_operations
    
    def _assess_data_flow_health(self) -> Dict[str, Any]:
        """Assess the health of data flow through the system."""
        return {
            'data_sources_active': len(self.behavior_detector.data_collector.event_sources),
            'events_in_buffer': len(self.behavior_detector.data_collector.events),
            'buffer_utilization': len(self.behavior_detector.data_collector.events) / 
                                self.behavior_detector.data_collector.max_events,
            'realtime_processing': self.behavior_detector.realtime_engine.is_running,
            'collection_active': self.is_collecting
        }
    
    def export_integration_data(self, export_path: Path) -> bool:
        """Export integration data and reports."""
        try:
            comprehensive_report = self.get_comprehensive_report()
            
            with open(export_path, 'w') as f:
                json.dump(comprehensive_report, f, indent=2, default=str)
            
            self.logger.info(f"Exported integration data to {export_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            return False
    
    def get_integration_status(self) -> Dict[str, Any]:
        """Get current integration status summary."""
        return {
            'is_collecting': self.is_collecting,
            'components': {name: status.status.value for name, status in self.component_status.items()},
            'behavior_detector_status': self.behavior_detector.get_system_status(),
            'integration_stats': self.integration_stats,
            'overall_health': self._calculate_overall_status(),
            'data_flow_health': self._assess_data_flow_health()
        }