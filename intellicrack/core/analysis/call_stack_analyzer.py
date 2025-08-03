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
Call Stack Analysis Engine

This module provides comprehensive call stack analysis capabilities for
understanding code execution flow, detecting injection techniques, and
analyzing caller-callee relationships in API call traces.

Features:
- Call chain reconstruction and analysis
- Caller-callee relationship mapping
- Code injection detection through call stacks
- Return address analysis for exploit detection
- Function hooking and redirection detection
- Execution flow pattern analysis
- Stack frame correlation and validation
"""

import json
import logging
import re
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .api_call_tracer import APICall, APICategory, CallDirection

logger = logging.getLogger(__name__)


class StackAnomalyType(Enum):
    """Types of call stack anomalies that can be detected."""
    UNEXPECTED_CALLER = auto()
    MISSING_RETURN_ADDRESS = auto()
    INVALID_STACK_FRAME = auto()
    CODE_INJECTION = auto()
    HOOK_DETECTION = auto()
    RETURN_ADDRESS_MANIPULATION = auto()
    STACK_PIVOT = auto()
    ROP_CHAIN = auto()
    UNKNOWN_MODULE = auto()
    SUSPICIOUS_JUMP = auto()


class CallChainPattern(Enum):
    """Common call chain patterns."""
    LICENSE_VALIDATION_CHAIN = auto()
    PROTECTION_INITIALIZATION = auto()
    ANTI_DEBUG_SEQUENCE = auto()
    CRYPTOGRAPHIC_OPERATION = auto()
    NETWORK_COMMUNICATION = auto()
    FILE_OPERATION_CHAIN = auto()
    REGISTRY_ACCESS_CHAIN = auto()
    MEMORY_MANIPULATION = auto()
    UNKNOWN = auto()


@dataclass
class StackFrame:
    """Represents a single stack frame."""
    address: int
    module: str
    function: str
    offset: int = 0
    return_address: Optional[int] = None
    frame_pointer: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stack frame to dictionary."""
        return {
            'address': hex(self.address),
            'module': self.module,
            'function': self.function,
            'offset': self.offset,
            'return_address': hex(self.return_address) if self.return_address else None,
            'frame_pointer': hex(self.frame_pointer) if self.frame_pointer else None
        }


@dataclass
class CallChain:
    """Represents a sequence of related API calls."""
    chain_id: str
    api_calls: List[APICall]
    pattern_type: CallChainPattern
    start_time: float
    end_time: float
    confidence: float
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_ms(self) -> float:
        """Get duration of call chain in milliseconds."""
        return (self.end_time - self.start_time) * 1000
    
    @property
    def call_count(self) -> int:
        """Get number of calls in chain."""
        return len(self.api_calls)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert call chain to dictionary."""
        return {
            'chain_id': self.chain_id,
            'pattern_type': self.pattern_type.name,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration_ms': self.duration_ms,
            'call_count': self.call_count,
            'confidence': self.confidence,
            'anomalies': self.anomalies,
            'metadata': self.metadata,
            'first_call': self.api_calls[0].to_dict() if self.api_calls else None,
            'last_call': self.api_calls[-1].to_dict() if self.api_calls else None
        }


@dataclass
class StackAnomaly:
    """Represents a detected call stack anomaly."""
    anomaly_type: StackAnomalyType
    severity: str  # 'low', 'medium', 'high', 'critical'
    description: str
    api_call: APICall
    stack_frames: List[StackFrame]
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert anomaly to dictionary."""
        return {
            'anomaly_type': self.anomaly_type.name,
            'severity': self.severity,
            'description': self.description,
            'timestamp': self.timestamp,
            'api_call': self.api_call.to_dict(),
            'stack_frames': [frame.to_dict() for frame in self.stack_frames],
            'evidence': self.evidence
        }


class CallStackAnalyzer:
    """
    Comprehensive call stack analysis engine.
    
    Analyzes call stacks from API traces to detect anomalies, understand
    execution flow, and identify potential security issues.
    """
    
    def __init__(self, max_history: int = 10000):
        """
        Initialize call stack analyzer.
        
        Args:
            max_history: Maximum number of call stacks to maintain in history
        """
        self.max_history = max_history
        self.call_history = deque(maxlen=max_history)
        self.call_chains = []
        self.detected_anomalies = []
        self.module_registry = {}
        self.function_registry = defaultdict(set)
        self.call_graph = defaultdict(lambda: defaultdict(int))
        self.lock = threading.RLock()
        
        # Analysis statistics
        self.stats = {
            'total_stacks_analyzed': 0,
            'anomalies_detected': 0,
            'chains_identified': 0,
            'unique_modules': 0,
            'unique_functions': 0,
            'analysis_start_time': time.time()
        }
        
        # Known system modules for validation
        self.system_modules = {
            'kernel32.dll', 'ntdll.dll', 'user32.dll', 'advapi32.dll',
            'ole32.dll', 'oleaut32.dll', 'shell32.dll', 'wininet.dll',
            'winhttp.dll', 'crypt32.dll', 'cryptsp.dll', 'msvcrt.dll',
            'ucrtbase.dll', 'api-ms-win-core-*.dll'
        }
        
        logger.info("Call Stack Analyzer initialized")
    
    def analyze_call_stack(self, api_call: APICall) -> List[StackAnomaly]:
        """
        Analyze call stack for an API call.
        
        Args:
            api_call: API call with call stack information
            
        Returns:
            List of detected stack anomalies
        """
        with self.lock:
            self.call_history.append(api_call)
            self.stats['total_stacks_analyzed'] += 1
            
            # Parse stack frames
            stack_frames = self._parse_stack_frames(api_call.call_stack)
            
            # Update registries
            self._update_registries(api_call, stack_frames)
            
            # Detect anomalies
            anomalies = self._detect_stack_anomalies(api_call, stack_frames)
            
            # Update call graph
            self._update_call_graph(api_call, stack_frames)
            
            if anomalies:
                self.detected_anomalies.extend(anomalies)
                self.stats['anomalies_detected'] += len(anomalies)
                
                for anomaly in anomalies:
                    logger.warning("Stack anomaly detected: %s - %s", 
                                 anomaly.anomaly_type.name, anomaly.description)
            
            return anomalies
    
    def _parse_stack_frames(self, call_stack: List[str]) -> List[StackFrame]:
        """
        Parse call stack strings into StackFrame objects.
        
        Args:
            call_stack: List of call stack strings
            
        Returns:
            List of parsed StackFrame objects
        """
        frames = []
        
        for stack_entry in call_stack:
            if not stack_entry or not isinstance(stack_entry, str):
                continue
            
            try:
                # Parse common stack frame formats:
                # "module.dll!function+0x123"
                # "0x12345678 module.dll!function"
                # "module.dll+0x1234 (function)"
                
                frame = self._parse_single_stack_frame(stack_entry)
                if frame:
                    frames.append(frame)
                    
            except Exception as e:
                logger.debug("Failed to parse stack frame '%s': %s", stack_entry, e)
                continue
        
        return frames
    
    def _parse_single_stack_frame(self, stack_entry: str) -> Optional[StackFrame]:
        """Parse a single stack frame entry."""
        # Pattern 1: module.dll!function+0x123
        pattern1 = re.match(r'([^!]+)!([^+]+)(?:\+0x([a-fA-F0-9]+))?', stack_entry)
        if pattern1:
            module = pattern1.group(1)
            function = pattern1.group(2)
            offset = int(pattern1.group(3), 16) if pattern1.group(3) else 0
            
            return StackFrame(
                address=0,  # Will be filled if available
                module=module,
                function=function,
                offset=offset
            )
        
        # Pattern 2: 0x12345678 module.dll!function
        pattern2 = re.match(r'0x([a-fA-F0-9]+)\s+([^!]+)!([^+]+)', stack_entry)
        if pattern2:
            address = int(pattern2.group(1), 16)
            module = pattern2.group(2)
            function = pattern2.group(3)
            
            return StackFrame(
                address=address,
                module=module,
                function=function
            )
        
        # Pattern 3: module.dll+0x1234 (function)
        pattern3 = re.match(r'([^+]+)\+0x([a-fA-F0-9]+)\s*\(([^)]+)\)', stack_entry)
        if pattern3:
            module = pattern3.group(1)
            offset = int(pattern3.group(2), 16)
            function = pattern3.group(3)
            
            return StackFrame(
                address=0,
                module=module,
                function=function,
                offset=offset
            )
        
        return None
    
    def _update_registries(self, api_call: APICall, stack_frames: List[StackFrame]) -> None:
        """Update module and function registries."""
        # Update module registry
        if api_call.module not in self.module_registry:
            self.module_registry[api_call.module] = {
                'first_seen': time.time(),
                'call_count': 0,
                'functions': set()
            }
        
        self.module_registry[api_call.module]['call_count'] += 1
        self.module_registry[api_call.module]['functions'].add(api_call.function)
        
        # Update function registry
        self.function_registry[api_call.function].add(api_call.module)
        
        # Update for stack frames
        for frame in stack_frames:
            if frame.module not in self.module_registry:
                self.module_registry[frame.module] = {
                    'first_seen': time.time(),
                    'call_count': 0,
                    'functions': set()
                }
            
            self.module_registry[frame.module]['functions'].add(frame.function)
            self.function_registry[frame.function].add(frame.module)
        
        # Update unique counts
        self.stats['unique_modules'] = len(self.module_registry)
        self.stats['unique_functions'] = len(self.function_registry)
    
    def _detect_stack_anomalies(self, api_call: APICall, stack_frames: List[StackFrame]) -> List[StackAnomaly]:
        """Detect anomalies in the call stack."""
        anomalies = []
        
        # Check for unknown modules
        unknown_module_anomaly = self._check_unknown_modules(api_call, stack_frames)
        if unknown_module_anomaly:
            anomalies.append(unknown_module_anomaly)
        
        # Check for suspicious caller patterns
        suspicious_caller_anomaly = self._check_suspicious_callers(api_call, stack_frames)
        if suspicious_caller_anomaly:
            anomalies.append(suspicious_caller_anomaly)
        
        # Check for code injection indicators
        injection_anomaly = self._check_code_injection(api_call, stack_frames)
        if injection_anomaly:
            anomalies.append(injection_anomaly)
        
        # Check for hook detection
        hook_anomaly = self._check_hook_detection(api_call, stack_frames)
        if hook_anomaly:
            anomalies.append(hook_anomaly)
        
        # Check for ROP chain patterns
        rop_anomaly = self._check_rop_patterns(api_call, stack_frames)
        if rop_anomaly:
            anomalies.append(rop_anomaly)
        
        return anomalies
    
    def _check_unknown_modules(self, api_call: APICall, stack_frames: List[StackFrame]) -> Optional[StackAnomaly]:
        """Check for calls from unknown or suspicious modules."""
        suspicious_modules = []
        
        for frame in stack_frames:
            module_lower = frame.module.lower()
            
            # Check if module is known system module
            is_system_module = any(
                module_lower == sys_mod.lower() or 
                (sys_mod.endswith('*.dll') and module_lower.startswith(sys_mod[:-5]))
                for sys_mod in self.system_modules
            )
            
            if not is_system_module and not module_lower.endswith('.exe'):
                # Check if module looks suspicious
                if any(suspicious in module_lower for suspicious in ['inject', 'hook', 'patch', 'mod']):
                    suspicious_modules.append(frame.module)
        
        if suspicious_modules:
            return StackAnomaly(
                anomaly_type=StackAnomalyType.UNKNOWN_MODULE,
                severity='medium',
                description=f"Call from unknown/suspicious modules: {', '.join(suspicious_modules)}",
                api_call=api_call,
                stack_frames=stack_frames,
                evidence={'suspicious_modules': suspicious_modules}
            )
        
        return None
    
    def _check_suspicious_callers(self, api_call: APICall, stack_frames: List[StackFrame]) -> Optional[StackAnomaly]:
        """Check for suspicious caller patterns."""
        if len(stack_frames) < 2:
            return None
        
        immediate_caller = stack_frames[0]
        
        # Check for suspicious API combinations
        suspicious_combinations = [
            ('VirtualAlloc', 'WriteProcessMemory'),
            ('CreateRemoteThread', 'WriteProcessMemory'),
            ('SetWindowsHook', 'LoadLibrary'),
            ('NtCreateSection', 'NtMapViewOfSection')
        ]
        
        for combo in suspicious_combinations:
            if (api_call.function in combo and 
                any(combo[0] in frame.function or combo[1] in frame.function for frame in stack_frames)):
                
                return StackAnomaly(
                    anomaly_type=StackAnomalyType.UNEXPECTED_CALLER,
                    severity='high',
                    description=f"Suspicious API combination detected: {combo}",
                    api_call=api_call,
                    stack_frames=stack_frames,
                    evidence={'suspicious_combination': combo}
                )
        
        return None
    
    def _check_code_injection(self, api_call: APICall, stack_frames: List[StackFrame]) -> Optional[StackAnomaly]:
        """Check for code injection indicators."""
        injection_indicators = [
            'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
            'CreateRemoteThread', 'SetThreadContext', 'NtQueueApcThread'
        ]
        
        if api_call.function in injection_indicators:
            # Check parameters for injection patterns
            params = api_call.parameters
            
            suspicious_params = False
            if 'VirtualAlloc' in api_call.function and len(params) >= 3:
                # Check for RWX permissions (0x40)
                if params[2] == 0x40 or params[2] == 64:
                    suspicious_params = True
            
            elif 'WriteProcessMemory' in api_call.function:
                # Writing to remote process
                suspicious_params = True
            
            if suspicious_params:
                return StackAnomaly(
                    anomaly_type=StackAnomalyType.CODE_INJECTION,
                    severity='critical',
                    description=f"Code injection pattern detected in {api_call.function}",
                    api_call=api_call,
                    stack_frames=stack_frames,
                    evidence={'injection_api': api_call.function, 'parameters': params[:3]}
                )
        
        return None
    
    def _check_hook_detection(self, api_call: APICall, stack_frames: List[StackFrame]) -> Optional[StackAnomaly]:
        """Check for function hooking detection."""
        if len(stack_frames) < 2:
            return None
        
        # Look for non-standard call patterns
        for i, frame in enumerate(stack_frames[:-1]):
            next_frame = stack_frames[i + 1]
            
            # Check for jumps between unrelated modules
            if (frame.module.lower() != next_frame.module.lower() and 
                not self._are_related_modules(frame.module, next_frame.module)):
                
                return StackAnomaly(
                    anomaly_type=StackAnomalyType.HOOK_DETECTION,
                    severity='medium',
                    description=f"Suspicious module transition: {next_frame.module} -> {frame.module}",
                    api_call=api_call,
                    stack_frames=stack_frames,
                    evidence={
                        'transition': f"{next_frame.module} -> {frame.module}",
                        'frame_index': i
                    }
                )
        
        return None
    
    def _check_rop_patterns(self, api_call: APICall, stack_frames: List[StackFrame]) -> Optional[StackAnomaly]:
        """Check for ROP (Return-Oriented Programming) patterns."""
        if len(stack_frames) < 3:
            return None
        
        # Look for patterns indicating ROP chains
        small_offsets = 0
        for frame in stack_frames:
            if frame.offset > 0 and frame.offset < 32:  # Small offsets often indicate gadgets
                small_offsets += 1
        
        # High proportion of small offsets might indicate ROP
        if small_offsets > len(stack_frames) * 0.6:
            return StackAnomaly(
                anomaly_type=StackAnomalyType.ROP_CHAIN,
                severity='critical',
                description=f"Potential ROP chain detected ({small_offsets}/{len(stack_frames)} small offsets)",
                api_call=api_call,
                stack_frames=stack_frames,
                evidence={'small_offset_ratio': small_offsets / len(stack_frames)}
            )
        
        return None
    
    def _are_related_modules(self, module1: str, module2: str) -> bool:
        """Check if two modules are related (same family)."""
        module1_lower = module1.lower()
        module2_lower = module2.lower()
        
        # Same module
        if module1_lower == module2_lower:
            return True
        
        # Common system module families
        families = [
            ['kernel32.dll', 'kernelbase.dll'],
            ['user32.dll', 'win32u.dll'],
            ['ntdll.dll', 'win32u.dll'],
            ['ole32.dll', 'oleaut32.dll', 'combase.dll'],
            ['wininet.dll', 'winhttp.dll', 'urlmon.dll']
        ]
        
        for family in families:
            if module1_lower in family and module2_lower in family:
                return True
        
        # API set DLLs
        if ('api-ms-win-core' in module1_lower and 'api-ms-win-core' in module2_lower):
            return True
        
        return False
    
    def _update_call_graph(self, api_call: APICall, stack_frames: List[StackFrame]) -> None:
        """Update the call graph with caller-callee relationships."""
        if not stack_frames:
            return
        
        # Build call chain from stack frames
        call_chain = []
        
        # Add the current API call
        current_node = f"{api_call.module}!{api_call.function}"
        call_chain.append(current_node)
        
        # Add stack frame calls
        for frame in stack_frames:
            frame_node = f"{frame.module}!{frame.function}"
            call_chain.append(frame_node)
        
        # Update call graph with relationships
        for i in range(len(call_chain) - 1):
            caller = call_chain[i + 1]  # Higher up in stack
            callee = call_chain[i]     # Lower in stack
            self.call_graph[caller][callee] += 1
    
    def identify_call_chains(self, time_window_seconds: int = 10) -> List[CallChain]:
        """
        Identify related call chains within a time window.
        
        Args:
            time_window_seconds: Time window to group related calls
            
        Returns:
            List of identified call chains
        """
        with self.lock:
            if not self.call_history:
                return []
            
            chains = []
            current_time = time.time()
            
            # Group calls by time window and thread
            call_groups = defaultdict(list)
            
            for api_call in self.call_history:
                if current_time - api_call.timestamp <= time_window_seconds:
                    group_key = (api_call.thread_id, int(api_call.timestamp / time_window_seconds))
                    call_groups[group_key].append(api_call)
            
            # Analyze each group for chain patterns
            for group_key, group_calls in call_groups.items():
                if len(group_calls) >= 2:  # Need at least 2 calls for a chain
                    chain = self._analyze_call_group(group_calls, group_key)
                    if chain:
                        chains.append(chain)
            
            self.call_chains.extend(chains)
            self.stats['chains_identified'] += len(chains)
            
            return chains
    
    def _analyze_call_group(self, calls: List[APICall], group_key: Tuple) -> Optional[CallChain]:
        """Analyze a group of calls to identify chain patterns."""
        if len(calls) < 2:
            return None
        
        # Sort calls by timestamp
        calls.sort(key=lambda c: c.timestamp)
        
        # Analyze pattern
        pattern_type = self._identify_chain_pattern(calls)
        
        if pattern_type == CallChainPattern.UNKNOWN:
            return None
        
        # Calculate confidence based on pattern strength
        confidence = self._calculate_chain_confidence(calls, pattern_type)
        
        if confidence < 0.5:  # Minimum confidence threshold
            return None
        
        chain_id = f"{group_key[0]}_{group_key[1]}_{int(time.time())}"
        
        return CallChain(
            chain_id=chain_id,
            api_calls=calls,
            pattern_type=pattern_type,
            start_time=calls[0].timestamp,
            end_time=calls[-1].timestamp,
            confidence=confidence,
            metadata={
                'thread_id': group_key[0],
                'call_count': len(calls),
                'unique_modules': len(set(call.module for call in calls))
            }
        )
    
    def _identify_chain_pattern(self, calls: List[APICall]) -> CallChainPattern:
        """Identify the pattern type for a sequence of calls."""
        functions = [call.function.lower() for call in calls]
        modules = [call.module.lower() for call in calls]
        
        # License validation pattern
        if any('reg' in func for func in functions) and any('crypt' in func for func in functions):
            return CallChainPattern.LICENSE_VALIDATION_CHAIN
        
        # Network communication pattern
        if any('internet' in mod or 'winhttp' in mod for mod in modules):
            return CallChainPattern.NETWORK_COMMUNICATION
        
        # File operation pattern
        if any('file' in func or 'create' in func for func in functions):
            return CallChainPattern.FILE_OPERATION_CHAIN
        
        # Registry access pattern
        if any('reg' in func for func in functions):
            return CallChainPattern.REGISTRY_ACCESS_CHAIN
        
        # Cryptographic operation pattern
        if any('crypt' in func or 'hash' in func for func in functions):
            return CallChainPattern.CRYPTOGRAPHIC_OPERATION
        
        # Anti-debug pattern
        if any('debug' in func for func in functions):
            return CallChainPattern.ANTI_DEBUG_SEQUENCE
        
        # Memory manipulation pattern
        if any('virtual' in func or 'heap' in func for func in functions):
            return CallChainPattern.MEMORY_MANIPULATION
        
        return CallChainPattern.UNKNOWN
    
    def _calculate_chain_confidence(self, calls: List[APICall], pattern_type: CallChainPattern) -> float:
        """Calculate confidence score for identified chain pattern."""
        base_confidence = 0.5
        
        # Bonus for pattern-specific indicators
        if pattern_type == CallChainPattern.LICENSE_VALIDATION_CHAIN:
            # Look for license-related strings in parameters
            license_indicators = 0
            for call in calls:
                for param in call.parameters:
                    if isinstance(param, str) and 'license' in param.lower():
                        license_indicators += 1
            base_confidence += min(license_indicators * 0.1, 0.3)
        
        # Temporal consistency bonus
        if len(calls) > 1:
            time_gaps = []
            for i in range(1, len(calls)):
                gap = calls[i].timestamp - calls[i-1].timestamp
                time_gaps.append(gap)
            
            # Consistent timing patterns increase confidence
            if time_gaps:
                gap_std = statistics.stdev(time_gaps) if len(time_gaps) > 1 else 0
                if gap_std < 1.0:  # Low standard deviation in timing
                    base_confidence += 0.1
        
        # Thread consistency bonus
        if all(call.thread_id == calls[0].thread_id for call in calls):
            base_confidence += 0.1
        
        return min(base_confidence, 1.0)
    
    def get_call_graph_analysis(self) -> Dict[str, Any]:
        """Get analysis of the call graph."""
        with self.lock:
            if not self.call_graph:
                return {'nodes': 0, 'edges': 0, 'top_callers': [], 'top_callees': []}
            
            # Calculate node statistics
            all_nodes = set()
            total_edges = 0
            caller_counts = defaultdict(int)
            callee_counts = defaultdict(int)
            
            for caller, callees in self.call_graph.items():
                all_nodes.add(caller)
                for callee, count in callees.items():
                    all_nodes.add(callee)
                    total_edges += count
                    caller_counts[caller] += count
                    callee_counts[callee] += count
            
            # Find top callers and callees
            top_callers = sorted(caller_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            top_callees = sorted(callee_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            return {
                'nodes': len(all_nodes),
                'edges': total_edges,
                'top_callers': [{'function': caller, 'call_count': count} for caller, count in top_callers],
                'top_callees': [{'function': callee, 'call_count': count} for callee, count in top_callees],
                'graph_density': total_edges / (len(all_nodes) ** 2) if len(all_nodes) > 1 else 0
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive call stack analysis statistics."""
        with self.lock:
            runtime = time.time() - self.stats['analysis_start_time']
            
            # Calculate anomaly distribution
            anomaly_distribution = defaultdict(int)
            for anomaly in self.detected_anomalies:
                anomaly_distribution[anomaly.anomaly_type.name] += 1
            
            # Calculate chain pattern distribution
            chain_distribution = defaultdict(int)
            for chain in self.call_chains:
                chain_distribution[chain.pattern_type.name] += 1
            
            return {
                **self.stats,
                'runtime_seconds': runtime,
                'stacks_per_second': self.stats['total_stacks_analyzed'] / runtime if runtime > 0 else 0,
                'anomaly_distribution': dict(anomaly_distribution),
                'chain_distribution': dict(chain_distribution),
                'call_graph_stats': self.get_call_graph_analysis(),
                'recent_anomalies': len([a for a in self.detected_anomalies 
                                       if time.time() - a.timestamp < 300])  # Last 5 minutes
            }
    
    def export_analysis_data(self, output_path: str, include_call_graph: bool = True) -> bool:
        """
        Export call stack analysis data.
        
        Args:
            output_path: Path for output file
            include_call_graph: Whether to include call graph data
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            with self.lock:
                export_data = {
                    'export_timestamp': time.time(),
                    'statistics': self.get_statistics(),
                    'anomalies': [anomaly.to_dict() for anomaly in self.detected_anomalies],
                    'call_chains': [chain.to_dict() for chain in self.call_chains],
                    'module_registry': {
                        module: {
                            **info,
                            'functions': list(info['functions'])
                        }
                        for module, info in self.module_registry.items()
                    }
                }
                
                if include_call_graph:
                    export_data['call_graph'] = {
                        caller: dict(callees) 
                        for caller, callees in self.call_graph.items()
                    }
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info("Exported call stack analysis data to %s", output_path)
            return True
            
        except Exception as e:
            logger.error("Failed to export analysis data: %s", e)
            return False