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
Real-time API Call Correlation Engine

This module provides real-time correlation and analysis of API call events
to detect behavioral patterns, license validation sequences, and protection
mechanisms as they occur.

Features:
- Real-time event correlation across multiple API calls
- Behavioral pattern matching in real-time
- Anomaly detection for unusual API usage
- License check timing and frequency analysis
- Automated alerting for suspicious activities
- Performance-optimized streaming analysis
- Integration with existing pattern detection systems
"""

import asyncio
import json
import logging
import queue
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import statistics

from .api_call_tracer import APICall, APICategory, CallDirection
from .api_pattern_analyzer import DetectedPattern, PatternType, PatternSeverity

logger = logging.getLogger(__name__)


class CorrelationEventType(Enum):
    """Types of correlation events."""
    PATTERN_DETECTED = auto()
    ANOMALY_DETECTED = auto()
    THRESHOLD_EXCEEDED = auto()
    TIMING_ANOMALY = auto()
    FREQUENCY_SPIKE = auto()
    BEHAVIORAL_CHANGE = auto()
    LICENSE_VALIDATION = auto()
    PROTECTION_ACTIVATION = auto()
    UNKNOWN = auto()


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


@dataclass
class CorrelationEvent:
    """A real-time correlation event."""
    event_type: CorrelationEventType
    severity: AlertSeverity
    timestamp: float
    description: str
    api_calls: List[APICall]
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    event_id: str = ""
    
    def __post_init__(self):
        if not self.event_id:
            self.event_id = f"{self.event_type.name}_{int(self.timestamp)}_{id(self)}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.name,
            'severity': self.severity.name,
            'timestamp': self.timestamp,
            'description': self.description,
            'confidence': self.confidence,
            'metadata': self.metadata,
            'api_call_count': len(self.api_calls),
            'first_call': self.api_calls[0].to_dict() if self.api_calls else None,
            'last_call': self.api_calls[-1].to_dict() if self.api_calls else None
        }


@dataclass
class CorrelationRule:
    """Rule for real-time correlation analysis."""
    name: str
    event_type: CorrelationEventType
    severity: AlertSeverity
    description: str
    time_window_seconds: int = 30
    min_occurrences: int = 2
    max_occurrences: Optional[int] = None
    api_categories: Set[APICategory] = field(default_factory=set)
    function_patterns: List[str] = field(default_factory=list)
    parameter_patterns: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    
    def matches_call(self, api_call: APICall) -> bool:
        """Check if API call matches this rule."""
        if not self.enabled:
            return False
        
        # Check category filter
        if self.api_categories and api_call.category not in self.api_categories:
            return False
        
        # Check function patterns
        if self.function_patterns:
            function_lower = api_call.function.lower()
            if not any(pattern.lower() in function_lower for pattern in self.function_patterns):
                return False
        
        # Check parameter patterns
        if self.parameter_patterns:
            for param_key, param_value in self.parameter_patterns.items():
                if param_key == 'contains':
                    if not any(str(param_value).lower() in str(param).lower() 
                             for param in api_call.parameters):
                        return False
                elif param_key == 'count':
                    if len(api_call.parameters) < param_value:
                        return False
        
        return True


class FrequencyMonitor:
    """Monitor API call frequencies for anomaly detection."""
    
    def __init__(self, window_size_seconds: int = 60):
        """
        Initialize frequency monitor.
        
        Args:
            window_size_seconds: Time window for frequency calculations
        """
        self.window_size = window_size_seconds
        self.call_timestamps = defaultdict(lambda: deque())
        self.baseline_frequencies = {}
        self.frequency_stats = defaultdict(lambda: {'count': 0, 'last_update': 0})
        self.lock = threading.RLock()
    
    def record_call(self, api_call: APICall) -> Optional[Dict[str, Any]]:
        """
        Record API call and check for frequency anomalies.
        
        Args:
            api_call: API call to record
            
        Returns:
            Dictionary with frequency analysis if anomaly detected
        """
        with self.lock:
            call_key = f"{api_call.module}!{api_call.function}"
            current_time = api_call.timestamp
            
            # Add timestamp to window
            self.call_timestamps[call_key].append(current_time)
            
            # Remove old timestamps outside window
            cutoff_time = current_time - self.window_size
            while (self.call_timestamps[call_key] and 
                   self.call_timestamps[call_key][0] < cutoff_time):
                self.call_timestamps[call_key].popleft()
            
            # Calculate current frequency
            current_frequency = len(self.call_timestamps[call_key])
            
            # Update baseline if we have enough data
            if call_key not in self.baseline_frequencies:
                if current_frequency >= 10:  # Need at least 10 calls for baseline
                    self.baseline_frequencies[call_key] = current_frequency
                return None
            
            # Check for frequency spike
            baseline = self.baseline_frequencies[call_key]
            spike_threshold = baseline * 3  # 3x normal frequency
            
            if current_frequency > spike_threshold:
                return {
                    'function': call_key,
                    'current_frequency': current_frequency,
                    'baseline_frequency': baseline,
                    'spike_ratio': current_frequency / baseline,
                    'window_size_seconds': self.window_size
                }
            
            # Update baseline with exponential moving average
            alpha = 0.1  # Smoothing factor
            self.baseline_frequencies[call_key] = (
                alpha * current_frequency + (1 - alpha) * baseline
            )
            
            return None
    
    def get_frequency_stats(self) -> Dict[str, Any]:
        """Get frequency monitoring statistics."""
        with self.lock:
            current_time = time.time()
            active_functions = {}
            
            for func, timestamps in self.call_timestamps.items():
                if timestamps:
                    # Clean old timestamps
                    cutoff_time = current_time - self.window_size
                    while timestamps and timestamps[0] < cutoff_time:
                        timestamps.popleft()
                    
                    if timestamps:
                        active_functions[func] = {
                            'current_frequency': len(timestamps),
                            'baseline_frequency': self.baseline_frequencies.get(func, 0),
                            'last_call': timestamps[-1]
                        }
            
            return {
                'monitored_functions': len(self.call_timestamps),
                'active_functions': len(active_functions),
                'baseline_established': len(self.baseline_frequencies),
                'window_size_seconds': self.window_size,
                'top_active': sorted(
                    active_functions.items(),
                    key=lambda x: x[1]['current_frequency'],
                    reverse=True
                )[:10]
            }


class TimingAnalyzer:
    """Analyze timing patterns in API calls."""
    
    def __init__(self, sequence_window_seconds: int = 10):
        """
        Initialize timing analyzer.
        
        Args:
            sequence_window_seconds: Time window for sequence analysis
        """
        self.sequence_window = sequence_window_seconds
        self.call_sequences = defaultdict(list)
        self.timing_patterns = {}
        self.lock = threading.RLock()
    
    def analyze_timing(self, api_call: APICall) -> Optional[Dict[str, Any]]:
        """
        Analyze timing patterns for API call.
        
        Args:
            api_call: API call to analyze
            
        Returns:
            Timing analysis results if anomaly detected
        """
        with self.lock:
            sequence_key = f"{api_call.thread_id}_{api_call.module}"
            current_time = api_call.timestamp
            
            # Add to sequence
            self.call_sequences[sequence_key].append({
                'timestamp': current_time,
                'function': api_call.function,
                'category': api_call.category
            })
            
            # Remove old calls outside window
            cutoff_time = current_time - self.sequence_window
            self.call_sequences[sequence_key] = [
                call for call in self.call_sequences[sequence_key]
                if call['timestamp'] >= cutoff_time
            ]
            
            sequence = self.call_sequences[sequence_key]
            
            if len(sequence) < 3:
                return None
            
            # Analyze timing intervals
            intervals = []
            for i in range(1, len(sequence)):
                interval = sequence[i]['timestamp'] - sequence[i-1]['timestamp']
                intervals.append(interval)
            
            if len(intervals) < 2:
                return None
            
            # Check for suspicious timing patterns
            avg_interval = statistics.mean(intervals)
            std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
            
            # Very regular timing might indicate automated behavior
            if std_interval < 0.001 and avg_interval < 1.0:  # Very consistent sub-second timing
                return {
                    'pattern_type': 'regular_timing',
                    'avg_interval_ms': avg_interval * 1000,
                    'std_deviation_ms': std_interval * 1000,
                    'sequence_length': len(sequence),
                    'functions': [call['function'] for call in sequence[-5:]]  # Last 5
                }
            
            # Very fast sequential calls might indicate burst activity
            fast_calls = sum(1 for interval in intervals if interval < 0.01)  # < 10ms
            if fast_calls > len(intervals) * 0.8:  # 80% of calls are very fast
                return {
                    'pattern_type': 'burst_activity',
                    'fast_call_ratio': fast_calls / len(intervals),
                    'avg_interval_ms': avg_interval * 1000,
                    'sequence_length': len(sequence),
                    'functions': [call['function'] for call in sequence[-5:]]
                }
            
            return None
    
    def get_timing_statistics(self) -> Dict[str, Any]:
        """Get timing analysis statistics."""
        with self.lock:
            active_sequences = len([seq for seq in self.call_sequences.values() if seq])
            total_calls = sum(len(seq) for seq in self.call_sequences.values())
            
            return {
                'active_sequences': active_sequences,
                'total_calls_tracked': total_calls,
                'sequence_window_seconds': self.sequence_window,
                'avg_sequence_length': total_calls / active_sequences if active_sequences > 0 else 0
            }


class RealTimeAPICorrelator:
    """
    Real-time API call correlation and analysis engine.
    
    Provides real-time correlation of API call events to detect behavioral
    patterns, license validation sequences, and protection mechanisms.
    """
    
    def __init__(self, max_events: int = 50000):
        """
        Initialize real-time correlator.
        
        Args:
            max_events: Maximum number of events to keep in memory
        """
        self.max_events = max_events
        self.correlation_events = deque(maxlen=max_events)
        self.correlation_rules = {}
        self.event_handlers = []
        self.running = False
        
        # Analysis components
        self.frequency_monitor = FrequencyMonitor()
        self.timing_analyzer = TimingAnalyzer()
        
        # Processing pipeline
        self.processing_queue = queue.Queue(maxsize=10000)
        self.processing_thread = None
        
        # Statistics
        self.stats = {
            'calls_processed': 0,
            'events_generated': 0,
            'rules_triggered': defaultdict(int),
            'start_time': time.time()
        }
        
        self.lock = threading.RLock()
        
        # Initialize default correlation rules
        self._initialize_default_rules()
        
        logger.info("Real-time API Correlator initialized")
    
    def _initialize_default_rules(self) -> None:
        """Initialize default correlation rules."""
        
        # License validation sequence rule
        license_rule = CorrelationRule(
            name="license_validation_sequence",
            event_type=CorrelationEventType.LICENSE_VALIDATION,
            severity=AlertSeverity.HIGH,
            description="License validation sequence detected",
            time_window_seconds=15,
            min_occurrences=3,
            api_categories={APICategory.REGISTRY, APICategory.CRYPTOGRAPHIC, APICategory.LICENSING},
            function_patterns=["RegQueryValue", "CryptDecrypt", "license"]
        )
        self.correlation_rules[license_rule.name] = license_rule
        
        # Frequency spike rule
        frequency_rule = CorrelationRule(
            name="api_frequency_spike",
            event_type=CorrelationEventType.FREQUENCY_SPIKE,
            severity=AlertSeverity.MEDIUM,
            description="API call frequency spike detected",
            time_window_seconds=60,
            min_occurrences=50,
            api_categories={APICategory.ANTI_DEBUG, APICategory.TIMING}
        )
        self.correlation_rules[frequency_rule.name] = frequency_rule
        
        # Protection activation rule
        protection_rule = CorrelationRule(
            name="protection_activation",
            event_type=CorrelationEventType.PROTECTION_ACTIVATION,
            severity=AlertSeverity.CRITICAL,
            description="Protection mechanism activation detected",
            time_window_seconds=5,
            min_occurrences=2,
            api_categories={APICategory.ANTI_DEBUG, APICategory.ANTI_VM},
            function_patterns=["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]
        )
        self.correlation_rules[protection_rule.name] = protection_rule
        
        # Timing anomaly rule
        timing_rule = CorrelationRule(
            name="timing_anomaly",
            event_type=CorrelationEventType.TIMING_ANOMALY,
            severity=AlertSeverity.MEDIUM,
            description="Suspicious timing pattern detected",
            time_window_seconds=30,
            min_occurrences=10,
            function_patterns=["GetSystemTime", "GetTickCount", "QueryPerformanceCounter"]
        )
        self.correlation_rules[timing_rule.name] = timing_rule
    
    def start_correlation(self) -> None:
        """Start real-time correlation processing."""
        if self.running:
            logger.warning("Correlation already running")
            return
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Start processing thread
        self.processing_thread = threading.Thread(target=self._process_correlation_events, daemon=True)
        self.processing_thread.start()
        
        logger.info("Real-time API correlation started")
    
    def stop_correlation(self) -> None:
        """Stop real-time correlation processing."""
        if not self.running:
            return
        
        self.running = False
        
        # Wait for processing thread to finish
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=5.0)
        
        logger.info("Real-time API correlation stopped")
    
    def process_api_call(self, api_call: APICall) -> List[CorrelationEvent]:
        """
        Process API call for real-time correlation.
        
        Args:
            api_call: API call to process
            
        Returns:
            List of correlation events generated
        """
        if not self.running:
            return []
        
        # Queue for background processing
        try:
            self.processing_queue.put(api_call, block=False)
            self.stats['calls_processed'] += 1
        except queue.Full:
            logger.warning("Correlation processing queue full, dropping API call")
        
        return []
    
    def _process_correlation_events(self) -> None:
        """Background thread for processing correlation events."""
        batch = []
        last_batch_time = time.time()
        batch_timeout = 0.1  # 100ms batch timeout
        
        while self.running:
            try:
                # Collect API calls in batches
                try:
                    api_call = self.processing_queue.get(timeout=batch_timeout)
                    batch.append(api_call)
                except queue.Empty:
                    pass
                
                # Process batch when ready
                current_time = time.time()
                if (batch and 
                    (len(batch) >= 10 or 
                     current_time - last_batch_time >= batch_timeout)):
                    
                    self._process_api_call_batch(batch)
                    batch.clear()
                    last_batch_time = current_time
                
            except Exception as e:
                logger.error("Error in correlation processing thread: %s", e)
        
        # Process remaining batch
        if batch:
            self._process_api_call_batch(batch)
    
    def _process_api_call_batch(self, batch: List[APICall]) -> None:
        """Process a batch of API calls."""
        events = []
        
        for api_call in batch:
            # Frequency analysis
            frequency_result = self.frequency_monitor.record_call(api_call)
            if frequency_result:
                event = CorrelationEvent(
                    event_type=CorrelationEventType.FREQUENCY_SPIKE,
                    severity=AlertSeverity.MEDIUM,
                    timestamp=api_call.timestamp,
                    description=f"Frequency spike in {frequency_result['function']}",
                    api_calls=[api_call],
                    confidence=min(frequency_result['spike_ratio'] / 5.0, 1.0),
                    metadata=frequency_result
                )
                events.append(event)
            
            # Timing analysis
            timing_result = self.timing_analyzer.analyze_timing(api_call)
            if timing_result:
                event = CorrelationEvent(
                    event_type=CorrelationEventType.TIMING_ANOMALY,
                    severity=AlertSeverity.MEDIUM,
                    timestamp=api_call.timestamp,
                    description=f"Timing anomaly: {timing_result['pattern_type']}",
                    api_calls=[api_call],
                    confidence=0.7,
                    metadata=timing_result
                )
                events.append(event)
            
            # Rule-based correlation
            rule_events = self._check_correlation_rules(api_call)
            events.extend(rule_events)
        
        # Store and notify about events
        with self.lock:
            for event in events:
                self.correlation_events.append(event)
                self.stats['events_generated'] += 1
                
                # Notify event handlers
                for handler in self.event_handlers:
                    try:
                        handler(event)
                    except Exception as e:
                        logger.error("Error in event handler: %s", e)
                
                logger.info("Correlation event: %s - %s", 
                           event.event_type.name, event.description)
    
    def _check_correlation_rules(self, api_call: APICall) -> List[CorrelationEvent]:
        """Check API call against correlation rules."""
        events = []
        current_time = api_call.timestamp
        
        for rule_name, rule in self.correlation_rules.items():
            if not rule.matches_call(api_call):
                continue
            
            # Check for pattern within time window
            window_start = current_time - rule.time_window_seconds
            
            # Get recent matching calls
            matching_calls = []
            for stored_call in reversed(list(self.frequency_monitor.call_timestamps.get(
                f"{api_call.module}!{api_call.function}", []))):
                if isinstance(stored_call, float) and stored_call >= window_start:
                    # This is a timestamp, we need the actual call
                    # For now, use current call as representative
                    matching_calls.append(api_call)
                elif hasattr(stored_call, 'timestamp') and stored_call.timestamp >= window_start:
                    matching_calls.append(stored_call)
            
            # Add current call
            matching_calls.append(api_call)
            
            # Check occurrence thresholds
            if len(matching_calls) >= rule.min_occurrences:
                if rule.max_occurrences is None or len(matching_calls) <= rule.max_occurrences:
                    
                    # Calculate confidence based on how well the pattern matches
                    confidence = min(len(matching_calls) / rule.min_occurrences, 1.0)
                    
                    event = CorrelationEvent(
                        event_type=rule.event_type,
                        severity=rule.severity,
                        timestamp=current_time,
                        description=rule.description,
                        api_calls=matching_calls[-10:],  # Last 10 calls
                        confidence=confidence,
                        metadata={
                            'rule_name': rule_name,
                            'occurrence_count': len(matching_calls),
                            'time_window_seconds': rule.time_window_seconds
                        }
                    )
                    
                    events.append(event)
                    self.stats['rules_triggered'][rule_name] += 1
        
        return events
    
    def add_event_handler(self, handler: Callable[[CorrelationEvent], None]) -> None:
        """
        Add event handler for correlation events.
        
        Args:
            handler: Function to call when events are generated
        """
        self.event_handlers.append(handler)
        logger.info("Added correlation event handler")
    
    def remove_event_handler(self, handler: Callable[[CorrelationEvent], None]) -> None:
        """
        Remove event handler.
        
        Args:
            handler: Handler function to remove
        """
        if handler in self.event_handlers:
            self.event_handlers.remove(handler)
            logger.info("Removed correlation event handler")
    
    def add_correlation_rule(self, rule: CorrelationRule) -> bool:
        """
        Add custom correlation rule.
        
        Args:
            rule: Correlation rule to add
            
        Returns:
            True if rule added successfully, False if name exists
        """
        with self.lock:
            if rule.name in self.correlation_rules:
                logger.warning("Correlation rule already exists: %s", rule.name)
                return False
            
            self.correlation_rules[rule.name] = rule
            logger.info("Added correlation rule: %s", rule.name)
            return True
    
    def remove_correlation_rule(self, rule_name: str) -> bool:
        """
        Remove correlation rule.
        
        Args:
            rule_name: Name of rule to remove
            
        Returns:
            True if rule removed, False if not found
        """
        with self.lock:
            if rule_name in self.correlation_rules:
                del self.correlation_rules[rule_name]
                logger.info("Removed correlation rule: %s", rule_name)
                return True
            
            logger.warning("Correlation rule not found: %s", rule_name)
            return False
    
    def get_recent_events(self, 
                         count: int = 50,
                         event_type: Optional[CorrelationEventType] = None,
                         min_severity: Optional[AlertSeverity] = None) -> List[CorrelationEvent]:
        """
        Get recent correlation events with optional filtering.
        
        Args:
            count: Maximum number of events to return
            event_type: Filter by event type
            min_severity: Minimum severity level
            
        Returns:
            List of filtered correlation events
        """
        with self.lock:
            events = list(self.correlation_events)
            events.reverse()  # Most recent first
            
            # Apply filters
            if event_type:
                events = [e for e in events if e.event_type == event_type]
            
            if min_severity:
                severity_order = {
                    AlertSeverity.INFO: 0,
                    AlertSeverity.LOW: 1,
                    AlertSeverity.MEDIUM: 2,
                    AlertSeverity.HIGH: 3,
                    AlertSeverity.CRITICAL: 4
                }
                min_level = severity_order[min_severity]
                events = [e for e in events if severity_order[e.severity] >= min_level]
            
            return events[:count]
    
    def get_event_timeline(self, time_range_seconds: int = 300) -> Dict[str, Any]:
        """
        Get event timeline for specified time range.
        
        Args:
            time_range_seconds: Time range in seconds (default: 5 minutes)
            
        Returns:
            Timeline analysis with event distribution
        """
        current_time = time.time()
        start_time = current_time - time_range_seconds
        
        with self.lock:
            recent_events = [e for e in self.correlation_events 
                           if e.timestamp >= start_time]
            
            # Group events by type and severity
            type_counts = defaultdict(int)
            severity_counts = defaultdict(int)
            timeline_buckets = defaultdict(list)
            
            # Create time buckets (30 buckets for timeline)
            bucket_size = time_range_seconds / 30
            
            for event in recent_events:
                type_counts[event.event_type.name] += 1
                severity_counts[event.severity.name] += 1
                
                bucket_idx = int((event.timestamp - start_time) / bucket_size)
                timeline_buckets[bucket_idx].append(event)
            
            return {
                'time_range_seconds': time_range_seconds,
                'total_events': len(recent_events),
                'events_per_minute': (len(recent_events) / time_range_seconds) * 60,
                'type_distribution': dict(type_counts),
                'severity_distribution': dict(severity_counts),
                'timeline_buckets': {k: len(v) for k, v in timeline_buckets.items()},
                'peak_activity_bucket': max(timeline_buckets.items(), 
                                          key=lambda x: len(x[1]))[0] if timeline_buckets else None
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive correlation statistics."""
        with self.lock:
            runtime = time.time() - self.stats['start_time']
            
            return {
                **self.stats,
                'runtime_seconds': runtime,
                'calls_per_second': self.stats['calls_processed'] / runtime if runtime > 0 else 0,
                'events_per_call': self.stats['events_generated'] / max(self.stats['calls_processed'], 1),
                'rules_triggered': dict(self.stats['rules_triggered']),
                'active_rules': len([r for r in self.correlation_rules.values() if r.enabled]),
                'total_rules': len(self.correlation_rules),
                'queue_size': self.processing_queue.qsize(),
                'frequency_stats': self.frequency_monitor.get_frequency_stats(),
                'timing_stats': self.timing_analyzer.get_timing_statistics()
            }
    
    def export_correlation_data(self, output_path: str) -> bool:
        """
        Export correlation data to file.
        
        Args:
            output_path: Path for output file
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            with self.lock:
                export_data = {
                    'export_timestamp': time.time(),
                    'statistics': self.get_statistics(),
                    'recent_events': [e.to_dict() for e in list(self.correlation_events)[-1000:]],
                    'correlation_rules': [
                        {
                            'name': rule.name,
                            'event_type': rule.event_type.name,
                            'severity': rule.severity.name,
                            'description': rule.description,
                            'enabled': rule.enabled,
                            'time_window_seconds': rule.time_window_seconds,
                            'min_occurrences': rule.min_occurrences
                        }
                        for rule in self.correlation_rules.values()
                    ]
                }
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info("Exported correlation data to %s", output_path)
            return True
            
        except Exception as e:
            logger.error("Failed to export correlation data: %s", e)
            return False