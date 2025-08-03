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
Comprehensive API Call Tracing and Analysis Engine

This module provides production-ready API call tracing capabilities for
comprehensive executable behavior analysis. Features include:

- Cross-platform API hooking (Windows/Linux)
- Real-time call logging with minimal performance impact
- Thread-safe operation with concurrent access support
- Comprehensive parameter and return value capture
- Call stack trace reconstruction
- Performance optimization and batching
- Integration with existing Frida infrastructure
"""

import asyncio
import json
import logging
import queue
import threading
import time
import traceback
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
import struct
import platform

from ...utils.core.import_checks import FRIDA_AVAILABLE, frida, psutil
from ..frida_manager import FridaOperationLogger, ProtectionDetector
from ..frida_constants import HookCategory, ProtectionType

logger = logging.getLogger(__name__)


class APICategory(Enum):
    """API call categories for classification and analysis."""
    REGISTRY = auto()
    FILE_SYSTEM = auto()
    NETWORK = auto()
    CRYPTOGRAPHIC = auto()
    SYSTEM_INFO = auto()
    PROCESS_THREAD = auto()
    MEMORY = auto()
    TIMING = auto()
    LICENSING = auto()
    ANTI_DEBUG = auto()
    ANTI_VM = auto()
    HARDWARE = auto()
    CLOUD_SERVICES = auto()
    UNKNOWN = auto()


class CallDirection(Enum):
    """Direction of API call for analysis."""
    ENTER = auto()
    EXIT = auto()
    EXCEPTION = auto()


@dataclass
class APICall:
    """Comprehensive API call information."""
    timestamp: float
    thread_id: int
    process_id: int
    module: str
    function: str
    direction: CallDirection
    parameters: List[Any] = field(default_factory=list)
    return_value: Any = None
    call_stack: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    category: APICategory = APICategory.UNKNOWN
    caller_address: Optional[int] = None
    return_address: Optional[int] = None
    error_code: Optional[int] = None
    memory_snapshot: Optional[Dict[str, Any]] = None
    sequence_id: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert API call to dictionary for serialization."""
        return {
            'timestamp': self.timestamp,
            'thread_id': self.thread_id,
            'process_id': self.process_id,
            'module': self.module,
            'function': self.function,
            'direction': self.direction.name,
            'parameters': self._serialize_parameters(),
            'return_value': self._serialize_value(self.return_value),
            'call_stack': self.call_stack,
            'execution_time_ms': self.execution_time_ms,
            'category': self.category.name,
            'caller_address': hex(self.caller_address) if self.caller_address else None,
            'return_address': hex(self.return_address) if self.return_address else None,
            'error_code': self.error_code,
            'sequence_id': self.sequence_id
        }
    
    def _serialize_parameters(self) -> List[Any]:
        """Serialize parameters for JSON compatibility."""
        return [self._serialize_value(param) for param in self.parameters]
    
    def _serialize_value(self, value: Any) -> Any:
        """Serialize individual values for JSON compatibility."""
        if isinstance(value, (int, float, str, bool, type(None))):
            return value
        elif isinstance(value, bytes):
            return f"<bytes:{len(value)}>"
        elif hasattr(value, '__dict__'):
            return f"<object:{type(value).__name__}>"
        else:
            return str(value)[:200]  # Truncate long strings


@dataclass
class TracingConfiguration:
    """Configuration for API call tracing."""
    enabled_categories: Set[APICategory] = field(default_factory=lambda: set(APICategory))
    max_call_stack_depth: int = 32
    max_parameter_size: int = 1024
    max_calls_per_second: int = 10000
    batch_size: int = 100
    batch_timeout_ms: int = 100
    enable_memory_snapshots: bool = False
    enable_call_correlation: bool = True
    log_directory: Optional[Path] = None
    performance_mode: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'enabled_categories': [cat.name for cat in self.enabled_categories],
            'max_call_stack_depth': self.max_call_stack_depth,
            'max_parameter_size': self.max_parameter_size,
            'max_calls_per_second': self.max_calls_per_second,
            'batch_size': self.batch_size,
            'batch_timeout_ms': self.batch_timeout_ms,
            'enable_memory_snapshots': self.enable_memory_snapshots,
            'enable_call_correlation': self.enable_call_correlation,
            'log_directory': str(self.log_directory) if self.log_directory else None,
            'performance_mode': self.performance_mode
        }


class APICallBuffer:
    """Thread-safe circular buffer for API calls with overflow protection."""
    
    def __init__(self, max_size: int = 100000):
        """
        Initialize API call buffer.
        
        Args:
            max_size: Maximum number of API calls to store
        """
        self.max_size = max_size
        self.calls = deque(maxlen=max_size)
        self.lock = threading.RLock()
        self.overflow_count = 0
        self.total_calls = 0
        
    def add_call(self, api_call: APICall) -> None:
        """
        Add API call to buffer.
        
        Args:
            api_call: API call to add
        """
        with self.lock:
            if len(self.calls) >= self.max_size:
                self.overflow_count += 1
            self.calls.append(api_call)
            self.total_calls += 1
            
    def get_calls(self, limit: Optional[int] = None) -> List[APICall]:
        """
        Get API calls from buffer.
        
        Args:
            limit: Maximum number of calls to return
            
        Returns:
            List of API calls (most recent first)
        """
        with self.lock:
            calls = list(self.calls)
            calls.reverse()  # Most recent first
            if limit:
                return calls[:limit]
            return calls
    
    def get_calls_by_timeframe(self, start_time: float, end_time: float) -> List[APICall]:
        """
        Get API calls within specified timeframe.
        
        Args:
            start_time: Start timestamp
            end_time: End timestamp
            
        Returns:
            List of API calls within timeframe
        """
        with self.lock:
            return [call for call in self.calls 
                   if start_time <= call.timestamp <= end_time]
    
    def clear(self) -> None:
        """Clear all calls from buffer."""
        with self.lock:
            self.calls.clear()
            self.overflow_count = 0
            self.total_calls = 0
    
    def get_statistics(self) -> Dict[str, int]:
        """Get buffer statistics."""
        with self.lock:
            return {
                'current_size': len(self.calls),
                'max_size': self.max_size,
                'overflow_count': self.overflow_count,
                'total_calls': self.total_calls
            }


class APICallTracer:
    """
    Comprehensive API call tracing engine.
    
    Provides production-ready API call monitoring with:
    - Cross-platform API hooking
    - Real-time call logging and analysis
    - Performance optimization
    - Thread-safe operation
    - Integration with existing Frida infrastructure
    """
    
    def __init__(self, config: Optional[TracingConfiguration] = None):
        """
        Initialize API call tracer.
        
        Args:
            config: Tracing configuration (uses defaults if None)
        """
        self.config = config or TracingConfiguration()
        self.call_buffer = APICallBuffer()
        self.session_registry = {}
        self.active_hooks = {}
        self.sequence_counter = 0
        self.sequence_lock = threading.Lock()
        
        # Statistics tracking
        self.stats = {
            'calls_traced': 0,
            'hooks_installed': 0,
            'categories_detected': defaultdict(int),
            'errors_encountered': 0,
            'start_time': time.time()
        }
        
        # Performance monitoring
        self.performance_monitor = APITracingPerformanceMonitor()
        
        # Integration with existing infrastructure
        self.frida_logger = FridaOperationLogger(str(self.config.log_directory) if self.config.log_directory else None)
        self.protection_detector = ProtectionDetector()
        
        # Thread management
        self.processing_thread = None
        self.running = False
        self.call_queue = queue.Queue(maxsize=50000)
        
        logger.info("API Call Tracer initialized with configuration: %s", self.config.to_dict())
    
    def start_tracing(self) -> None:
        """Start API call tracing."""
        if self.running:
            logger.warning("API tracing already running")
            return
            
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Start processing thread
        self.processing_thread = threading.Thread(target=self._process_api_calls, daemon=True)
        self.processing_thread.start()
        
        logger.info("API call tracing started")
        self.frida_logger.log_operation('start_tracing', {'timestamp': time.time()}, success=True)
    
    def stop_tracing(self) -> None:
        """Stop API call tracing."""
        if not self.running:
            return
            
        self.running = False
        
        # Wait for processing thread to finish
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=5.0)
        
        # Cleanup hooks
        self._cleanup_hooks()
        
        logger.info("API call tracing stopped")
        self.frida_logger.log_operation('stop_tracing', {
            'duration_seconds': time.time() - self.stats['start_time'],
            'total_calls': self.stats['calls_traced']
        }, success=True)
    
    def attach_to_process(self, process_identifier: Union[int, str]) -> bool:
        """
        Attach tracer to a process.
        
        Args:
            process_identifier: Process ID or name
            
        Returns:
            True if attachment successful, False otherwise
        """
        if not FRIDA_AVAILABLE:
            logger.error("Frida not available for process attachment")
            return False
        
        try:
            # Attach to process
            if isinstance(process_identifier, int):
                session = frida.attach(process_identifier)
            else:
                session = frida.attach(process_identifier)
            
            self.session_registry[session.pid] = session
            
            # Install API hooks
            self._install_api_hooks(session)
            
            logger.info("Successfully attached to process: %s (PID: %d)", 
                       process_identifier, session.pid)
            
            self.frida_logger.log_operation('attach_process', {
                'process_identifier': str(process_identifier),
                'pid': session.pid
            }, success=True)
            
            return True
            
        except Exception as e:
            logger.error("Failed to attach to process %s: %s", process_identifier, e)
            self.frida_logger.log_operation('attach_process', {
                'process_identifier': str(process_identifier),
                'error': str(e)
            }, success=False, error=str(e))
            return False
    
    def detach_from_process(self, process_id: int) -> bool:
        """
        Detach tracer from a process.
        
        Args:
            process_id: Process ID to detach from
            
        Returns:
            True if detachment successful, False otherwise
        """
        if process_id not in self.session_registry:
            logger.warning("No active session for PID: %d", process_id)
            return False
        
        try:
            session = self.session_registry[process_id]
            session.detach()
            del self.session_registry[process_id]
            
            # Remove hooks for this process
            hooks_to_remove = [hook_id for hook_id in self.active_hooks 
                             if self.active_hooks[hook_id].get('pid') == process_id]
            for hook_id in hooks_to_remove:
                del self.active_hooks[hook_id]
            
            logger.info("Successfully detached from process: %d", process_id)
            self.frida_logger.log_operation('detach_process', {'pid': process_id}, success=True)
            return True
            
        except Exception as e:
            logger.error("Failed to detach from process %d: %s", process_id, e)
            self.frida_logger.log_operation('detach_process', {
                'pid': process_id,
                'error': str(e)
            }, success=False, error=str(e))
            return False
    
    def _install_api_hooks(self, session) -> None:
        """Install comprehensive API hooks for the session."""
        try:
            # Load API tracing script
            script_path = Path(__file__).parent.parent.parent / "scripts" / "frida" / "api_tracing_engine.js"
            if not script_path.exists():
                logger.error("API tracing script not found: %s", script_path)
                return
            
            with open(script_path, 'r') as f:
                script_code = f.read()
            
            # Create and load script
            script = session.create_script(script_code)
            script.on('message', self._handle_frida_message)
            script.load()
            
            # Configure script with tracing parameters
            script.post({
                'type': 'configure',
                'config': self.config.to_dict()
            })
            
            # Store hook information
            hook_id = f"{session.pid}_{int(time.time())}"
            self.active_hooks[hook_id] = {
                'session': session,
                'script': script,
                'pid': session.pid,
                'timestamp': time.time()
            }
            
            self.stats['hooks_installed'] += 1
            logger.info("API hooks installed for PID: %d", session.pid)
            
        except Exception as e:
            logger.error("Failed to install API hooks for PID %d: %s", session.pid, e)
            self.stats['errors_encountered'] += 1
    
    def _handle_frida_message(self, message: Dict[str, Any], data: Optional[bytes]) -> None:
        """Handle messages from Frida script."""
        try:
            if message.get('type') == 'send':
                payload = message.get('payload', {})
                
                if payload.get('type') == 'api_call':
                    self._process_api_call_message(payload)
                elif payload.get('type') == 'error':
                    logger.error("Frida script error: %s", payload.get('message'))
                    self.stats['errors_encountered'] += 1
                elif payload.get('type') == 'batch':
                    # Handle batched API calls
                    for call_data in payload.get('calls', []):
                        self._process_api_call_message(call_data)
                        
        except Exception as e:
            logger.error("Error handling Frida message: %s", e)
            self.stats['errors_encountered'] += 1
    
    def _process_api_call_message(self, call_data: Dict[str, Any]) -> None:
        """Process individual API call message from Frida."""
        try:
            # Create API call object
            api_call = APICall(
                timestamp=call_data.get('timestamp', time.time()),
                thread_id=call_data.get('thread_id', 0),
                process_id=call_data.get('process_id', 0),
                module=call_data.get('module', ''),
                function=call_data.get('function', ''),
                direction=CallDirection[call_data.get('direction', 'ENTER')],
                parameters=call_data.get('parameters', []),
                return_value=call_data.get('return_value'),
                call_stack=call_data.get('call_stack', []),
                execution_time_ms=call_data.get('execution_time_ms', 0.0),
                caller_address=call_data.get('caller_address'),
                return_address=call_data.get('return_address'),
                error_code=call_data.get('error_code'),
                sequence_id=self._get_next_sequence_id()
            )
            
            # Categorize API call
            api_call.category = self._categorize_api_call(api_call)
            
            # Queue for processing
            if not self.call_queue.full():
                self.call_queue.put(api_call, block=False)
            else:
                logger.warning("API call queue full, dropping call")
                
        except Exception as e:
            logger.error("Error processing API call message: %s", e)
            self.stats['errors_encountered'] += 1
    
    def _categorize_api_call(self, api_call: APICall) -> APICategory:
        """Categorize API call based on function and module."""
        module = api_call.module.lower()
        function = api_call.function.lower()
        
        # Registry operations
        if 'reg' in function or 'registry' in function:
            return APICategory.REGISTRY
        
        # File system operations
        if any(keyword in function for keyword in ['file', 'create', 'open', 'read', 'write', 'delete']):
            return APICategory.FILE_SYSTEM
        
        # Network operations
        if any(keyword in function for keyword in ['socket', 'connect', 'send', 'recv', 'internet', 'http', 'wininet', 'winhttp']):
            return APICategory.NETWORK
        
        # Cryptographic operations
        if any(keyword in function for keyword in ['crypt', 'hash', 'encrypt', 'decrypt', 'cert']):
            return APICategory.CRYPTOGRAPHIC
        
        # System information
        if any(keyword in function for keyword in ['getsystem', 'getcomputer', 'getuserdata', 'getversion']):
            return APICategory.SYSTEM_INFO
        
        # Process/Thread operations
        if any(keyword in function for keyword in ['process', 'thread', 'createremote']):
            return APICategory.PROCESS_THREAD
        
        # Memory operations
        if any(keyword in function for keyword in ['virtual', 'heap', 'memory', 'alloc']):
            return APICategory.MEMORY
        
        # Timing operations
        if any(keyword in function for keyword in ['time', 'tick', 'performance', 'sleep']):
            return APICategory.TIMING
        
        # Anti-debugging
        if any(keyword in function for keyword in ['debugger', 'debug', 'isdebuggerpresent']):
            return APICategory.ANTI_DEBUG
        
        # License-related (based on known patterns)
        if any(keyword in function for keyword in ['license', 'trial', 'activate', 'validate']):
            return APICategory.LICENSING
        
        return APICategory.UNKNOWN
    
    def _get_next_sequence_id(self) -> int:
        """Get next sequence ID for API calls."""
        with self.sequence_lock:
            self.sequence_counter += 1
            return self.sequence_counter
    
    def _process_api_calls(self) -> None:
        """Background thread for processing API calls."""
        batch = []
        last_batch_time = time.time()
        
        while self.running:
            try:
                # Wait for API calls with timeout
                try:
                    api_call = self.call_queue.get(timeout=0.1)
                    batch.append(api_call)
                except queue.Empty:
                    continue
                
                # Process batch when full or timeout reached
                current_time = time.time()
                batch_timeout = (current_time - last_batch_time) * 1000 >= self.config.batch_timeout_ms
                
                if len(batch) >= self.config.batch_size or batch_timeout:
                    self._process_call_batch(batch)
                    batch.clear()
                    last_batch_time = current_time
                    
            except Exception as e:
                logger.error("Error in API call processing thread: %s", e)
                self.stats['errors_encountered'] += 1
        
        # Process remaining calls
        if batch:
            self._process_call_batch(batch)
    
    def _process_call_batch(self, batch: List[APICall]) -> None:
        """Process a batch of API calls."""
        for api_call in batch:
            # Add to buffer
            self.call_buffer.add_call(api_call)
            
            # Update statistics
            self.stats['calls_traced'] += 1
            self.stats['categories_detected'][api_call.category] += 1
            
            # Log to Frida logger
            self.frida_logger.log_hook(
                api_call.function,
                api_call.module,
                api_call.parameters,
                api_call.return_value
            )
            
            # Check for protection patterns
            if api_call.category in [APICategory.ANTI_DEBUG, APICategory.LICENSING, APICategory.ANTI_VM]:
                detected_protections = self.protection_detector.analyze_api_call(
                    api_call.module,
                    api_call.function,
                    api_call.parameters
                )
                
                for protection in detected_protections:
                    self.frida_logger.log_bypass_attempt(
                        protection,
                        f"API call detected: {api_call.module}!{api_call.function}",
                        success=False,  # Detection, not bypass
                        details={
                            'timestamp': api_call.timestamp,
                            'parameters': api_call.parameters[:3]  # First 3 params only
                        }
                    )
    
    def _cleanup_hooks(self) -> None:
        """Clean up all active hooks."""
        for hook_id, hook_info in list(self.active_hooks.items()):
            try:
                script = hook_info.get('script')
                if script:
                    script.unload()
                session = hook_info.get('session')
                if session:
                    session.detach()
            except Exception as e:
                logger.error("Error cleaning up hook %s: %s", hook_id, e)
        
        self.active_hooks.clear()
    
    def get_api_calls(self, 
                      limit: Optional[int] = None,
                      category_filter: Optional[Set[APICategory]] = None,
                      timeframe: Optional[Tuple[float, float]] = None) -> List[APICall]:
        """
        Get API calls with optional filtering.
        
        Args:
            limit: Maximum number of calls to return
            category_filter: Set of categories to include
            timeframe: (start_time, end_time) tuple for time filtering
            
        Returns:
            List of filtered API calls
        """
        if timeframe:
            calls = self.call_buffer.get_calls_by_timeframe(timeframe[0], timeframe[1])
        else:
            calls = self.call_buffer.get_calls(limit)
        
        if category_filter:
            calls = [call for call in calls if call.category in category_filter]
        
        return calls[:limit] if limit else calls
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive tracing statistics."""
        runtime = time.time() - self.stats['start_time']
        calls_per_second = self.stats['calls_traced'] / runtime if runtime > 0 else 0
        
        return {
            **self.stats,
            'runtime_seconds': runtime,
            'calls_per_second': calls_per_second,
            'buffer_stats': self.call_buffer.get_statistics(),
            'active_sessions': len(self.session_registry),
            'active_hooks': len(self.active_hooks),
            'performance_stats': self.performance_monitor.get_statistics()
        }
    
    def export_trace_data(self, output_path: Path, format: str = 'json') -> bool:
        """
        Export traced API calls to file.
        
        Args:
            output_path: Path for output file
            format: Export format ('json', 'csv', 'xml')
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            calls = self.get_api_calls()
            
            if format == 'json':
                with open(output_path, 'w') as f:
                    json.dump({
                        'metadata': {
                            'export_time': datetime.now().isoformat(),
                            'total_calls': len(calls),
                            'statistics': self.get_statistics()
                        },
                        'api_calls': [call.to_dict() for call in calls]
                    }, f, indent=2)
            
            elif format == 'csv':
                import csv
                with open(output_path, 'w', newline='') as f:
                    if calls:
                        writer = csv.DictWriter(f, fieldnames=calls[0].to_dict().keys())
                        writer.writeheader()
                        for call in calls:
                            writer.writerow(call.to_dict())
            
            else:
                logger.error("Unsupported export format: %s", format)
                return False
            
            logger.info("Exported %d API calls to %s", len(calls), output_path)
            return True
            
        except Exception as e:
            logger.error("Failed to export trace data: %s", e)
            return False


class APITracingPerformanceMonitor:
    """Monitor performance of API tracing operations."""
    
    def __init__(self):
        """Initialize performance monitor."""
        self.metrics = defaultdict(list)
        self.start_time = time.time()
        
    def record_metric(self, name: str, value: float) -> None:
        """Record a performance metric."""
        self.metrics[name].append({
            'timestamp': time.time(),
            'value': value
        })
        
        # Keep only recent metrics (last 1000)
        if len(self.metrics[name]) > 1000:
            self.metrics[name] = self.metrics[name][-1000:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get performance statistics."""
        stats = {}
        
        for metric_name, values in self.metrics.items():
            if values:
                recent_values = [v['value'] for v in values[-100:]]  # Last 100 values
                stats[metric_name] = {
                    'count': len(values),
                    'avg': sum(recent_values) / len(recent_values),
                    'min': min(recent_values),
                    'max': max(recent_values),
                    'recent_count': len(recent_values)
                }
        
        return stats