"""
Behavioral Pattern Detector - Advanced pattern recognition for runtime behavior analysis.

This module provides sophisticated pattern detection algorithms to identify
license validation sequences, protection mechanism activation, and evasion techniques.

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

import json
import math
import re
import statistics
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import logging

try:
    import numpy as np
    import scipy.stats as stats
    STATISTICAL_ANALYSIS_AVAILABLE = True
except ImportError:
    STATISTICAL_ANALYSIS_AVAILABLE = False

try:
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    MACHINE_LEARNING_AVAILABLE = True
except ImportError:
    MACHINE_LEARNING_AVAILABLE = False

from intellicrack.logger import logger


class PatternType(Enum):
    """Types of behavioral patterns."""
    LICENSE_VALIDATION = auto()
    TRIAL_PERIOD_CHECK = auto()
    HARDWARE_FINGERPRINT = auto()
    TIME_BOMB_DETECTION = auto()
    NETWORK_VALIDATION = auto()
    REGISTRY_MANIPULATION = auto()
    FILE_INTEGRITY_CHECK = auto()
    ANTI_DEBUG_SEQUENCE = auto()
    VM_DETECTION = auto()
    SANDBOX_EVASION = auto()
    CODE_INJECTION = auto()
    PRIVILEGE_ESCALATION = auto()
    PERSISTENCE_MECHANISM = auto()
    UNKNOWN_PATTERN = auto()


class PatternSeverity(Enum):
    """Severity levels for detected patterns."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BehaviorSequence:
    """Represents a sequence of behavioral events."""
    events: List[Any]
    start_time: float
    end_time: float
    process_id: int
    thread_id: Optional[int] = None
    confidence: float = 0.0
    tags: Set[str] = field(default_factory=set)


@dataclass
class DetectedPattern:
    """Represents a detected behavioral pattern."""
    pattern_type: PatternType
    severity: PatternSeverity
    confidence: float
    description: str
    evidence: List[Any]
    metadata: Dict[str, Any]
    timestamp: float
    duration: float
    process_id: int
    affected_resources: List[str] = field(default_factory=list)
    mitigation_suggestions: List[str] = field(default_factory=list)


@dataclass
class PatternRule:
    """Defines a pattern detection rule."""
    name: str
    pattern_type: PatternType
    severity: PatternSeverity
    description: str
    event_sequence: List[Dict[str, Any]]
    time_window: float
    min_confidence: float
    max_false_positive_rate: float
    weight: float = 1.0
    enabled: bool = True


class BehavioralPatternDetector:
    """
    Advanced behavioral pattern detector for security analysis.
    
    This detector uses sophisticated algorithms to identify complex behavioral
    patterns that indicate license validation, protection mechanisms, and
    security-relevant activities.
    """

    def __init__(self, analysis_window: float = 300.0):
        """
        Initialize behavioral pattern detector.
        
        Args:
            analysis_window: Time window for pattern analysis in seconds
        """
        self.analysis_window = analysis_window
        self.logger = logging.getLogger(__name__)
        
        # Pattern detection state
        self.event_buffer: deque = deque(maxlen=50000)
        self.detected_patterns: List[DetectedPattern] = []
        self.pattern_rules = self._load_pattern_rules()
        
        # Sequence analysis
        self.active_sequences: Dict[str, BehaviorSequence] = {}
        self.completed_sequences: List[BehaviorSequence] = []
        
        # Statistical analysis
        self.event_statistics: Dict[str, Any] = {}
        self.baseline_metrics: Dict[str, float] = {}
        
        # Machine learning components
        if MACHINE_LEARNING_AVAILABLE:
            self.anomaly_detector = None
            self.sequence_clusterer = None
            self._initialize_ml_components()
        
        # Performance optimization
        self.last_analysis = time.time()
        self.analysis_interval = 5.0  # seconds
        self.pattern_cache: Dict[str, Any] = {}

    def _initialize_ml_components(self):
        """Initialize machine learning components."""
        try:
            # Initialize anomaly detection
            self.anomaly_detector = DBSCAN(eps=0.5, min_samples=5)
            
            # Initialize sequence clustering
            self.sequence_clusterer = DBSCAN(eps=0.3, min_samples=3)
            
            self.logger.info("Machine learning components initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize ML components: {e}")

    def add_events(self, events: List[Any]) -> List[DetectedPattern]:
        """
        Add events for pattern analysis.
        
        Args:
            events: List of events to analyze
            
        Returns:
            List of newly detected patterns
        """
        try:
            # Add events to buffer
            for event in events:
                self.event_buffer.append(event)
            
            # Perform analysis if enough time has passed
            current_time = time.time()
            if current_time - self.last_analysis >= self.analysis_interval:
                new_patterns = self._perform_pattern_analysis()
                self.last_analysis = current_time
                return new_patterns
            
            return []
            
        except Exception as e:
            self.logger.error(f"Error adding events for pattern analysis: {e}")
            return []

    def _perform_pattern_analysis(self) -> List[DetectedPattern]:
        """Perform comprehensive pattern analysis."""
        try:
            new_patterns = []
            
            # Rule-based pattern detection
            rule_patterns = self._detect_rule_based_patterns()
            new_patterns.extend(rule_patterns)
            
            # Sequence-based pattern detection
            sequence_patterns = self._detect_sequence_patterns()
            new_patterns.extend(sequence_patterns)
            
            # Statistical anomaly detection
            if STATISTICAL_ANALYSIS_AVAILABLE:
                anomaly_patterns = self._detect_statistical_anomalies()
                new_patterns.extend(anomaly_patterns)
            
            # Machine learning-based detection
            if MACHINE_LEARNING_AVAILABLE:
                ml_patterns = self._detect_ml_patterns()
                new_patterns.extend(ml_patterns)
            
            # Update statistics and baseline
            self._update_statistics()
            
            # Store detected patterns
            self.detected_patterns.extend(new_patterns)
            
            return new_patterns
            
        except Exception as e:
            self.logger.error(f"Error performing pattern analysis: {e}")
            return []

    def _detect_rule_based_patterns(self) -> List[DetectedPattern]:
        """Detect patterns using predefined rules."""
        detected_patterns = []
        
        try:
            for rule in self.pattern_rules:
                if not rule.enabled:
                    continue
                
                patterns = self._apply_pattern_rule(rule)
                detected_patterns.extend(patterns)
                
        except Exception as e:
            self.logger.error(f"Error in rule-based pattern detection: {e}")
        
        return detected_patterns

    def _apply_pattern_rule(self, rule: PatternRule) -> List[DetectedPattern]:
        """Apply a specific pattern rule to detect patterns."""
        patterns = []
        
        try:
            # Get events within time window
            current_time = time.time()
            window_start = current_time - rule.time_window
            
            relevant_events = [
                event for event in self.event_buffer
                if hasattr(event, 'timestamp') and event.timestamp >= window_start
            ]
            
            if len(relevant_events) < len(rule.event_sequence):
                return patterns
            
            # Look for event sequence matches
            for i in range(len(relevant_events) - len(rule.event_sequence) + 1):
                sequence_events = relevant_events[i:i+len(rule.event_sequence)]
                
                if self._matches_event_sequence(sequence_events, rule.event_sequence):
                    # Calculate pattern confidence
                    confidence = self._calculate_pattern_confidence(
                        sequence_events, rule
                    )
                    
                    if confidence >= rule.min_confidence:
                        pattern = DetectedPattern(
                            pattern_type=rule.pattern_type,
                            severity=rule.severity,
                            confidence=confidence,
                            description=rule.description,
                            evidence=sequence_events,
                            metadata={
                                'rule_name': rule.name,
                                'sequence_length': len(sequence_events),
                                'time_span': sequence_events[-1].timestamp - sequence_events[0].timestamp
                            },
                            timestamp=sequence_events[0].timestamp,
                            duration=sequence_events[-1].timestamp - sequence_events[0].timestamp,
                            process_id=getattr(sequence_events[0], 'process_id', 0)
                        )
                        
                        # Add mitigation suggestions based on pattern type
                        pattern.mitigation_suggestions = self._get_mitigation_suggestions(
                            rule.pattern_type
                        )
                        
                        patterns.append(pattern)
                        
        except Exception as e:
            self.logger.error(f"Error applying pattern rule {rule.name}: {e}")
        
        return patterns

    def _matches_event_sequence(self, events: List[Any], sequence_pattern: List[Dict[str, Any]]) -> bool:
        """Check if events match a sequence pattern."""
        try:
            if len(events) != len(sequence_pattern):
                return False
            
            for event, pattern in zip(events, sequence_pattern):
                if not self._event_matches_pattern(event, pattern):
                    return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Error matching event sequence: {e}")
            return False

    def _event_matches_pattern(self, event: Any, pattern: Dict[str, Any]) -> bool:
        """Check if a single event matches a pattern."""
        try:
            # Check event type
            if 'event_type' in pattern:
                event_type = getattr(event, 'event_type', None)
                if event_type and event_type.name != pattern['event_type']:
                    return False
            
            # Check attributes
            if 'attributes' in pattern:
                for attr_name, expected_value in pattern['attributes'].items():
                    actual_value = getattr(event, attr_name, None)
                    
                    if isinstance(expected_value, dict) and 'regex' in expected_value:
                        # Regex matching
                        if not re.search(expected_value['regex'], str(actual_value)):
                            return False
                    elif isinstance(expected_value, dict) and 'contains' in expected_value:
                        # Substring matching
                        if expected_value['contains'] not in str(actual_value):
                            return False
                    elif actual_value != expected_value:
                        return False
            
            # Check details
            if 'details' in pattern and hasattr(event, 'details'):
                for key, expected_value in pattern['details'].items():
                    if key not in event.details:
                        return False
                    
                    actual_value = event.details[key]
                    if isinstance(expected_value, dict) and 'regex' in expected_value:
                        if not re.search(expected_value['regex'], str(actual_value)):
                            return False
                    elif actual_value != expected_value:
                        return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Error matching event to pattern: {e}")
            return False

    def _calculate_pattern_confidence(self, events: List[Any], rule: PatternRule) -> float:
        """Calculate confidence score for detected pattern."""
        try:
            base_confidence = 0.5
            
            # Factor in rule weight
            confidence = base_confidence * rule.weight
            
            # Adjust based on sequence completeness
            if len(events) == len(rule.event_sequence):
                confidence += 0.2
            
            # Adjust based on timing consistency
            if self._has_consistent_timing(events):
                confidence += 0.1
            
            # Adjust based on context
            if self._has_supporting_context(events, rule):
                confidence += 0.2
            
            # Cap at maximum confidence
            return min(confidence, 1.0)
            
        except Exception as e:
            self.logger.debug(f"Error calculating pattern confidence: {e}")
            return 0.5

    def _has_consistent_timing(self, events: List[Any]) -> bool:
        """Check if events have consistent timing patterns."""
        try:
            if len(events) < 3:
                return True
            
            # Calculate intervals between events
            intervals = []
            for i in range(1, len(events)):
                interval = events[i].timestamp - events[i-1].timestamp
                intervals.append(interval)
            
            # Check for consistency in intervals
            if intervals:
                mean_interval = statistics.mean(intervals)
                std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
                
                # Consider timing consistent if standard deviation is low
                return std_dev < mean_interval * 0.5
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Error checking timing consistency: {e}")
            return False

    def _has_supporting_context(self, events: List[Any], rule: PatternRule) -> bool:
        """Check if events have supporting contextual evidence."""
        try:
            # Look for related events around the sequence
            sequence_start = events[0].timestamp - 10.0  # 10 seconds before
            sequence_end = events[-1].timestamp + 10.0   # 10 seconds after
            
            context_events = [
                event for event in self.event_buffer
                if (hasattr(event, 'timestamp') and 
                    sequence_start <= event.timestamp <= sequence_end and
                    event not in events)
            ]
            
            # Count supporting evidence
            support_count = 0
            
            for context_event in context_events:
                # Check for license-related context
                if rule.pattern_type == PatternType.LICENSE_VALIDATION:
                    if self._is_license_related_event(context_event):
                        support_count += 1
                
                # Check for anti-analysis context
                elif rule.pattern_type in [PatternType.ANTI_DEBUG_SEQUENCE, PatternType.VM_DETECTION]:
                    if self._is_anti_analysis_event(context_event):
                        support_count += 1
            
            # Consider context supportive if we have at least 2 supporting events
            return support_count >= 2
            
        except Exception as e:
            self.logger.debug(f"Error checking supporting context: {e}")
            return False

    def _detect_sequence_patterns(self) -> List[DetectedPattern]:
        """Detect patterns based on event sequences."""
        patterns = []
        
        try:
            # Group events by process
            process_events = defaultdict(list)
            
            current_time = time.time()
            window_start = current_time - self.analysis_window
            
            for event in self.event_buffer:
                if hasattr(event, 'timestamp') and event.timestamp >= window_start:
                    process_id = getattr(event, 'process_id', 0)
                    process_events[process_id].append(event)
            
            # Analyze sequences for each process
            for process_id, events in process_events.items():
                if len(events) >= 5:  # Minimum sequence length
                    sequence_patterns = self._analyze_event_sequence(events, process_id)
                    patterns.extend(sequence_patterns)
                    
        except Exception as e:
            self.logger.error(f"Error detecting sequence patterns: {e}")
        
        return patterns

    def _analyze_event_sequence(self, events: List[Any], process_id: int) -> List[DetectedPattern]:
        """Analyze event sequence for behavioral patterns."""
        patterns = []
        
        try:
            # Sort events by timestamp
            sorted_events = sorted(events, key=lambda e: getattr(e, 'timestamp', 0))
            
            # Detect license validation sequences
            license_patterns = self._detect_license_validation_sequence(sorted_events, process_id)
            patterns.extend(license_patterns)
            
            # Detect anti-analysis sequences
            anti_analysis_patterns = self._detect_anti_analysis_sequence(sorted_events, process_id)
            patterns.extend(anti_analysis_patterns)
            
            # Detect time-based patterns
            time_patterns = self._detect_time_based_patterns(sorted_events, process_id)
            patterns.extend(time_patterns)
            
            # Detect network validation patterns
            network_patterns = self._detect_network_validation_patterns(sorted_events, process_id)
            patterns.extend(network_patterns)
            
        except Exception as e:
            self.logger.error(f"Error analyzing event sequence: {e}")
        
        return patterns

    def _detect_license_validation_sequence(self, events: List[Any], process_id: int) -> List[DetectedPattern]:
        """Detect license validation behavioral sequences."""
        patterns = []
        
        try:
            # Look for typical license validation patterns
            license_indicators = []
            
            for event in events:
                # Registry access for license keys
                if (hasattr(event, 'event_type') and 
                    event.event_type.name == 'REGISTRY_ACCESS' and
                    hasattr(event, 'details')):
                    
                    key_path = event.details.get('key_path', '').lower()
                    if any(keyword in key_path for keyword in ['license', 'serial', 'key', 'activation']):
                        license_indicators.append(('registry', event))
                
                # File access for license files
                elif (hasattr(event, 'event_type') and 
                      event.event_type.name == 'FILE_ACCESS' and
                      hasattr(event, 'details')):
                    
                    file_path = event.details.get('file_path', '').lower()
                    if any(keyword in file_path for keyword in ['license', 'key', 'lic']):
                        license_indicators.append(('file', event))
                
                # API calls for hardware fingerprinting
                elif (hasattr(event, 'event_type') and 
                      event.event_type.name == 'API_CALL' and
                      hasattr(event, 'details')):
                    
                    api_name = event.details.get('api', '').lower()
                    if api_name in ['getvolumeinfoa', 'getvolumeinfow', 'getcomputernamea', 'getcomputernamew']:
                        license_indicators.append(('hardware', event))
                
                # Network connections to license servers
                elif (hasattr(event, 'event_type') and 
                      event.event_type.name == 'NETWORK_CONNECT' and
                      hasattr(event, 'tags') and
                      'license_server' in event.tags):
                    
                    license_indicators.append(('network', event))
            
            # If we have multiple types of license indicators in sequence
            if len(license_indicators) >= 3:
                indicator_types = [indicator[0] for indicator in license_indicators]
                
                # Check for comprehensive license validation
                if len(set(indicator_types)) >= 2:
                    pattern = DetectedPattern(
                        pattern_type=PatternType.LICENSE_VALIDATION,
                        severity=PatternSeverity.HIGH,
                        confidence=0.85,
                        description="Comprehensive license validation sequence detected",
                        evidence=[indicator[1] for indicator in license_indicators],
                        metadata={
                            'validation_methods': list(set(indicator_types)),
                            'indicator_count': len(license_indicators)
                        },
                        timestamp=license_indicators[0][1].timestamp,
                        duration=license_indicators[-1][1].timestamp - license_indicators[0][1].timestamp,
                        process_id=process_id
                    )
                    patterns.append(pattern)
                    
        except Exception as e:
            self.logger.error(f"Error detecting license validation sequence: {e}")
        
        return patterns

    def _detect_anti_analysis_sequence(self, events: List[Any], process_id: int) -> List[DetectedPattern]:
        """Detect anti-analysis behavioral sequences."""
        patterns = []
        
        try:
            anti_analysis_events = []
            
            for event in events:
                if hasattr(event, 'event_type') and hasattr(event, 'details'):
                    # Debugger detection
                    if (event.event_type.name == 'API_CALL' and
                        event.details.get('api', '').lower() in [
                            'isdebuggerpresent', 'checkremotedebuggerpresent',
                            'ntqueryinformationprocess'
                        ]):
                        anti_analysis_events.append(('debugger_check', event))
                    
                    # VM detection
                    elif (event.event_type.name == 'FILE_ACCESS' and
                          any(vm in event.details.get('file_path', '').lower() 
                              for vm in ['vmware', 'virtualbox', 'qemu'])):
                        anti_analysis_events.append(('vm_check', event))
                    
                    # Process enumeration
                    elif (event.event_type.name == 'API_CALL' and
                          event.details.get('api', '').lower() in [
                              'createtoolhelp32snapshot', 'process32first', 'process32next'
                          ]):
                        anti_analysis_events.append(('process_enum', event))
                    
                    # Timing checks
                    elif (event.event_type.name == 'API_CALL' and
                          event.details.get('api', '').lower() in [
                              'gettickcount', 'queryperformancecounter'
                          ]):
                        anti_analysis_events.append(('timing_check', event))
            
            # Detect anti-analysis sequences
            if len(anti_analysis_events) >= 3:
                technique_types = [event[0] for event in anti_analysis_events]
                
                if len(set(technique_types)) >= 2:
                    pattern = DetectedPattern(
                        pattern_type=PatternType.ANTI_DEBUG_SEQUENCE,
                        severity=PatternSeverity.HIGH,
                        confidence=0.9,
                        description="Multi-technique anti-analysis sequence detected",
                        evidence=[event[1] for event in anti_analysis_events],
                        metadata={
                            'techniques': list(set(technique_types)),
                            'technique_count': len(anti_analysis_events)
                        },
                        timestamp=anti_analysis_events[0][1].timestamp,
                        duration=anti_analysis_events[-1][1].timestamp - anti_analysis_events[0][1].timestamp,
                        process_id=process_id
                    )
                    patterns.append(pattern)
                    
        except Exception as e:
            self.logger.error(f"Error detecting anti-analysis sequence: {e}")
        
        return patterns

    def _detect_time_based_patterns(self, events: List[Any], process_id: int) -> List[DetectedPattern]:
        """Detect time-based behavioral patterns."""
        patterns = []
        
        try:
            time_events = []
            
            for event in events:
                if (hasattr(event, 'event_type') and 
                    event.event_type.name == 'API_CALL' and
                    hasattr(event, 'details')):
                    
                    api_name = event.details.get('api', '').lower()
                    if api_name in ['getsystemtime', 'getlocaltime', 'getfiletime']:
                        time_events.append(event)
            
            # Check for excessive time API calls (possible time bomb)
            if len(time_events) > 10:
                time_span = time_events[-1].timestamp - time_events[0].timestamp
                
                if time_span < 60.0:  # Many time calls in short period
                    pattern = DetectedPattern(
                        pattern_type=PatternType.TIME_BOMB_DETECTION,
                        severity=PatternSeverity.MEDIUM,
                        confidence=0.7,
                        description="Excessive time API calls detected (possible time bomb)",
                        evidence=time_events,
                        metadata={
                            'time_call_count': len(time_events),
                            'time_span': time_span
                        },
                        timestamp=time_events[0].timestamp,
                        duration=time_span,
                        process_id=process_id
                    )
                    patterns.append(pattern)
                    
        except Exception as e:
            self.logger.error(f"Error detecting time-based patterns: {e}")
        
        return patterns

    def _detect_network_validation_patterns(self, events: List[Any], process_id: int) -> List[DetectedPattern]:
        """Detect network-based validation patterns."""
        patterns = []
        
        try:
            network_events = []
            
            for event in events:
                if (hasattr(event, 'event_type') and 
                    hasattr(event, 'tags') and
                    ('license_server' in event.tags or 'license' in event.tags)):
                    network_events.append(event)
            
            # Check for license server communication patterns
            if len(network_events) >= 2:
                pattern = DetectedPattern(
                    pattern_type=PatternType.NETWORK_VALIDATION,
                    severity=PatternSeverity.MEDIUM,
                    confidence=0.8,
                    description="Network-based license validation detected",
                    evidence=network_events,
                    metadata={
                        'connection_count': len(network_events)
                    },
                    timestamp=network_events[0].timestamp,
                    duration=network_events[-1].timestamp - network_events[0].timestamp,
                    process_id=process_id
                )
                patterns.append(pattern)
                
        except Exception as e:
            self.logger.error(f"Error detecting network validation patterns: {e}")
        
        return patterns

    def _detect_statistical_anomalies(self) -> List[DetectedPattern]:
        """Detect patterns using statistical analysis."""
        patterns = []
        
        if not STATISTICAL_ANALYSIS_AVAILABLE:
            return patterns
        
        try:
            # Analyze event frequency anomalies
            frequency_patterns = self._detect_frequency_anomalies()
            patterns.extend(frequency_patterns)
            
            # Analyze timing anomalies
            timing_patterns = self._detect_timing_anomalies()
            patterns.extend(timing_patterns)
            
        except Exception as e:
            self.logger.error(f"Error detecting statistical anomalies: {e}")
        
        return patterns

    def _detect_frequency_anomalies(self) -> List[DetectedPattern]:
        """Detect anomalies in event frequency."""
        patterns = []
        
        try:
            # Count events by type in time windows
            window_size = 60.0  # 1-minute windows
            current_time = time.time()
            
            event_counts = defaultdict(list)
            
            # Group events into time windows
            for event in self.event_buffer:
                if hasattr(event, 'timestamp') and hasattr(event, 'event_type'):
                    window_index = int((event.timestamp - (current_time - self.analysis_window)) / window_size)
                    if window_index >= 0:
                        event_counts[event.event_type.name].append(window_index)
            
            # Analyze frequency patterns for each event type
            for event_type, window_indices in event_counts.items():
                if len(window_indices) > 10:  # Enough data for statistical analysis
                    # Count occurrences per window
                    window_counts = Counter(window_indices)
                    frequencies = list(window_counts.values())
                    
                    if len(frequencies) > 5:
                        # Calculate z-scores for outlier detection
                        mean_freq = np.mean(frequencies)
                        std_freq = np.std(frequencies)
                        
                        if std_freq > 0:
                            z_scores = [(f - mean_freq) / std_freq for f in frequencies]
                            
                            # Detect high-frequency anomalies
                            for i, z_score in enumerate(z_scores):
                                if z_score > 3.0:  # 3 standard deviations
                                    pattern = DetectedPattern(
                                        pattern_type=PatternType.UNKNOWN_PATTERN,
                                        severity=PatternSeverity.MEDIUM,
                                        confidence=min(z_score / 5.0, 1.0),
                                        description=f"High frequency anomaly detected for {event_type}",
                                        evidence=[],
                                        metadata={
                                            'event_type': event_type,
                                            'frequency': frequencies[i],
                                            'mean_frequency': mean_freq,
                                            'z_score': z_score
                                        },
                                        timestamp=current_time,
                                        duration=window_size,
                                        process_id=0
                                    )
                                    patterns.append(pattern)
                                    
        except Exception as e:
            self.logger.error(f"Error detecting frequency anomalies: {e}")
        
        return patterns

    def _detect_timing_anomalies(self) -> List[DetectedPattern]:
        """Detect anomalies in event timing."""
        patterns = []
        
        try:
            # Group events by process and analyze timing
            process_events = defaultdict(list)
            
            for event in self.event_buffer:
                if hasattr(event, 'timestamp') and hasattr(event, 'process_id'):
                    process_events[event.process_id].append(event.timestamp)
            
            # Analyze timing patterns for each process
            for process_id, timestamps in process_events.items():
                if len(timestamps) > 10:
                    timestamps.sort()
                    
                    # Calculate inter-event intervals
                    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                    
                    if len(intervals) > 5:
                        # Detect periodic patterns (possible automated behavior)
                        interval_groups = self._group_similar_intervals(intervals)
                        
                        for interval, count in interval_groups.items():
                            if count > 5 and 1.0 <= interval <= 300.0:  # 1 second to 5 minutes
                                pattern = DetectedPattern(
                                    pattern_type=PatternType.UNKNOWN_PATTERN,
                                    severity=PatternSeverity.LOW,
                                    confidence=min(count / 20.0, 1.0),
                                    description=f"Periodic behavior detected (interval: {interval:.1f}s)",
                                    evidence=[],
                                    metadata={
                                        'interval': interval,
                                        'occurrence_count': count,
                                        'process_id': process_id
                                    },
                                    timestamp=timestamps[0],
                                    duration=timestamps[-1] - timestamps[0],
                                    process_id=process_id
                                )
                                patterns.append(pattern)
                                
        except Exception as e:
            self.logger.error(f"Error detecting timing anomalies: {e}")
        
        return patterns

    def _group_similar_intervals(self, intervals: List[float], tolerance: float = 0.1) -> Dict[float, int]:
        """Group similar intervals together."""
        try:
            interval_groups = {}
            
            for interval in intervals:
                # Find existing group within tolerance
                found_group = False
                for group_interval in interval_groups:
                    if abs(interval - group_interval) <= tolerance * group_interval:
                        interval_groups[group_interval] += 1
                        found_group = True
                        break
                
                if not found_group:
                    interval_groups[interval] = 1
            
            return interval_groups
            
        except Exception as e:
            self.logger.debug(f"Error grouping intervals: {e}")
            return {}

    def _detect_ml_patterns(self) -> List[DetectedPattern]:
        """Detect patterns using machine learning."""
        patterns = []
        
        if not MACHINE_LEARNING_AVAILABLE:
            return patterns
        
        try:
            # Feature extraction for anomaly detection
            features = self._extract_features_for_ml()
            
            if len(features) > 10:
                # Normalize features
                scaler = StandardScaler()
                normalized_features = scaler.fit_transform(features)
                
                # Detect anomalies using clustering
                anomaly_labels = self.anomaly_detector.fit_predict(normalized_features)
                
                # Process anomalies
                for i, label in enumerate(anomaly_labels):
                    if label == -1:  # Anomaly
                        pattern = DetectedPattern(
                            pattern_type=PatternType.UNKNOWN_PATTERN,
                            severity=PatternSeverity.LOW,
                            confidence=0.6,
                            description="ML-detected behavioral anomaly",
                            evidence=[],
                            metadata={
                                'anomaly_index': i,
                                'feature_vector': features[i]
                            },
                            timestamp=time.time(),
                            duration=0.0,
                            process_id=0
                        )
                        patterns.append(pattern)
                        
        except Exception as e:
            self.logger.error(f"Error detecting ML patterns: {e}")
        
        return patterns

    def _extract_features_for_ml(self) -> List[List[float]]:
        """Extract features for machine learning analysis."""
        try:
            features = []
            
            # Group events by time windows
            window_size = 30.0  # 30-second windows
            current_time = time.time()
            window_start = current_time - self.analysis_window
            
            num_windows = int(self.analysis_window / window_size)
            
            for i in range(num_windows):
                window_start_time = window_start + i * window_size
                window_end_time = window_start_time + window_size
                
                window_events = [
                    event for event in self.event_buffer
                    if (hasattr(event, 'timestamp') and 
                        window_start_time <= event.timestamp < window_end_time)
                ]
                
                # Extract features for this window
                window_features = self._extract_window_features(window_events)
                features.append(window_features)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting ML features: {e}")
            return []

    def _extract_window_features(self, events: List[Any]) -> List[float]:
        """Extract features from events in a time window."""
        try:
            features = []
            
            # Basic event count
            features.append(float(len(events)))
            
            # Event type distribution
            event_types = defaultdict(int)
            for event in events:
                if hasattr(event, 'event_type'):
                    event_types[event.event_type.name] += 1
            
            # Add counts for common event types
            common_types = ['API_CALL', 'FILE_ACCESS', 'REGISTRY_ACCESS', 'NETWORK_CONNECT']
            for event_type in common_types:
                features.append(float(event_types.get(event_type, 0)))
            
            # Process diversity
            processes = set()
            for event in events:
                if hasattr(event, 'process_id'):
                    processes.add(event.process_id)
            features.append(float(len(processes)))
            
            # Confidence scores
            confidences = [getattr(event, 'confidence', 0.5) for event in events]
            if confidences:
                features.extend([
                    float(np.mean(confidences)),
                    float(np.std(confidences)),
                    float(max(confidences))
                ])
            else:
                features.extend([0.0, 0.0, 0.0])
            
            # Tag analysis
            tag_counts = defaultdict(int)
            for event in events:
                if hasattr(event, 'tags'):
                    for tag in event.tags:
                        tag_counts[tag] += 1
            
            # Add counts for important tags
            important_tags = ['license', 'suspicious', 'anti_analysis']
            for tag in important_tags:
                features.append(float(tag_counts.get(tag, 0)))
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting window features: {e}")
            return [0.0] * 10  # Return default feature vector

    def _update_statistics(self):
        """Update event statistics and baseline metrics."""
        try:
            current_time = time.time()
            
            # Update event type counts
            event_type_counts = defaultdict(int)
            for event in self.event_buffer:
                if hasattr(event, 'event_type'):
                    event_type_counts[event.event_type.name] += 1
            
            self.event_statistics['event_type_counts'] = dict(event_type_counts)
            self.event_statistics['total_events'] = len(self.event_buffer)
            self.event_statistics['last_update'] = current_time
            
            # Update baseline metrics if we have enough data
            if len(self.event_buffer) > 100:
                self._update_baseline_metrics()
                
        except Exception as e:
            self.logger.error(f"Error updating statistics: {e}")

    def _update_baseline_metrics(self):
        """Update baseline behavioral metrics."""
        try:
            # Calculate baseline event rates
            if len(self.event_buffer) > 10:
                timestamps = [getattr(event, 'timestamp', 0) for event in self.event_buffer]
                timestamps = [t for t in timestamps if t > 0]
                
                if len(timestamps) > 1:
                    time_span = max(timestamps) - min(timestamps)
                    if time_span > 0:
                        self.baseline_metrics['events_per_second'] = len(timestamps) / time_span
            
            # Calculate baseline confidence
            confidences = [getattr(event, 'confidence', 0.5) for event in self.event_buffer]
            if confidences:
                self.baseline_metrics['mean_confidence'] = statistics.mean(confidences)
                self.baseline_metrics['std_confidence'] = statistics.stdev(confidences) if len(confidences) > 1 else 0
            
        except Exception as e:
            self.logger.error(f"Error updating baseline metrics: {e}")

    def _load_pattern_rules(self) -> List[PatternRule]:
        """Load predefined pattern detection rules."""
        rules = []
        
        try:
            # License validation rule
            license_rule = PatternRule(
                name="license_validation_sequence",
                pattern_type=PatternType.LICENSE_VALIDATION,
                severity=PatternSeverity.HIGH,
                description="License validation sequence with multiple methods",
                event_sequence=[
                    {
                        'event_type': 'REGISTRY_ACCESS',
                        'details': {'key_path': {'contains': 'license'}}
                    },
                    {
                        'event_type': 'API_CALL',
                        'details': {'api': {'regex': '(GetVolumeInformation|GetComputerName)'}}
                    },
                    {
                        'event_type': 'NETWORK_CONNECT',
                        'attributes': {'tags': {'contains': 'license'}}
                    }
                ],
                time_window=120.0,
                min_confidence=0.7,
                max_false_positive_rate=0.1,
                weight=1.0
            )
            rules.append(license_rule)
            
            # Anti-debug sequence rule
            anti_debug_rule = PatternRule(
                name="anti_debug_sequence",
                pattern_type=PatternType.ANTI_DEBUG_SEQUENCE,
                severity=PatternSeverity.HIGH,
                description="Anti-debugging technique sequence",
                event_sequence=[
                    {
                        'event_type': 'API_CALL',
                        'details': {'api': 'IsDebuggerPresent'}
                    },
                    {
                        'event_type': 'API_CALL',
                        'details': {'api': {'regex': '(CheckRemoteDebugger|NtQueryInformation)'}}
                    }
                ],
                time_window=60.0,
                min_confidence=0.8,
                max_false_positive_rate=0.05,
                weight=1.2
            )
            rules.append(anti_debug_rule)
            
            # Time bomb detection rule
            time_bomb_rule = PatternRule(
                name="time_bomb_detection",
                pattern_type=PatternType.TIME_BOMB_DETECTION,
                severity=PatternSeverity.MEDIUM,
                description="Excessive time API calls indicating time bomb",
                event_sequence=[
                    {
                        'event_type': 'API_CALL',
                        'details': {'api': {'regex': '(GetSystemTime|GetLocalTime)'}}
                    }
                ] * 5,  # Pattern requires 5 time API calls
                time_window=30.0,
                min_confidence=0.6,
                max_false_positive_rate=0.2,
                weight=0.8
            )
            rules.append(time_bomb_rule)
            
        except Exception as e:
            self.logger.error(f"Error loading pattern rules: {e}")
        
        return rules

    def get_pattern_summary(self) -> Dict[str, Any]:
        """Get summary of detected patterns."""
        try:
            summary = {
                'total_patterns': len(self.detected_patterns),
                'patterns_by_type': {},
                'patterns_by_severity': {},
                'high_confidence_patterns': 0,
                'recent_patterns': 0
            }
            
            current_time = time.time()
            recent_threshold = current_time - 300.0  # Last 5 minutes
            
            for pattern in self.detected_patterns:
                # Count by type
                pattern_type = pattern.pattern_type.name
                summary['patterns_by_type'][pattern_type] = summary['patterns_by_type'].get(pattern_type, 0) + 1
                
                # Count by severity
                severity = pattern.severity.value
                summary['patterns_by_severity'][severity] = summary['patterns_by_severity'].get(severity, 0) + 1
                
                # Count high confidence patterns
                if pattern.confidence > 0.8:
                    summary['high_confidence_patterns'] += 1
                
                # Count recent patterns
                if pattern.timestamp > recent_threshold:
                    summary['recent_patterns'] += 1
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating pattern summary: {e}")
            return {}

    # Helper methods
    def _is_license_related_event(self, event: Any) -> bool:
        """Check if event is license-related."""
        try:
            if hasattr(event, 'tags') and any('license' in tag for tag in event.tags):
                return True
            
            if hasattr(event, 'details'):
                details_str = str(event.details).lower()
                if any(keyword in details_str for keyword in ['license', 'serial', 'activation']):
                    return True
            
            return False
            
        except Exception:
            return False

    def _is_anti_analysis_event(self, event: Any) -> bool:
        """Check if event is anti-analysis related."""
        try:
            if hasattr(event, 'tags') and any(tag in ['anti_analysis', 'suspicious'] for tag in event.tags):
                return True
            
            if hasattr(event, 'details'):
                details_str = str(event.details).lower()
                if any(keyword in details_str for keyword in ['debug', 'vm', 'virtual', 'analysis']):
                    return True
            
            return False
            
        except Exception:
            return False

    def _get_mitigation_suggestions(self, pattern_type: PatternType) -> List[str]:
        """Get mitigation suggestions for detected pattern type."""
        suggestions = {
            PatternType.LICENSE_VALIDATION: [
                "Analyze license validation logic for bypass opportunities",
                "Examine network communications to license servers",
                "Check for time-based license restrictions"
            ],
            PatternType.ANTI_DEBUG_SEQUENCE: [
                "Use advanced debugging techniques to bypass detection",
                "Patch anti-debug checks in the binary",
                "Use kernel-level debugging tools"
            ],
            PatternType.TIME_BOMB_DETECTION: [
                "Analyze time-based restrictions",
                "Consider time manipulation techniques",
                "Examine trial period implementation"
            ],
            PatternType.NETWORK_VALIDATION: [
                "Analyze network protocol for license validation",
                "Consider traffic interception and modification",
                "Examine certificate validation logic"
            ]
        }
        
        return suggestions.get(pattern_type, ["Further analysis recommended"])

if __name__ == "__main__":
    # Example usage
    detector = BehavioralPatternDetector()
    
    # Simulate adding events
    from runtime_behavior_monitor import MonitoredEvent, EventType
    
    test_events = [
        MonitoredEvent(
            event_type=EventType.REGISTRY_ACCESS,
            timestamp=time.time(),
            process_id=1234,
            details={'key_path': 'SOFTWARE\\MyApp\\License'}
        )
    ]
    
    patterns = detector.add_events(test_events)
    print(f"Detected {len(patterns)} patterns")
    
    summary = detector.get_pattern_summary()
    print(f"Pattern summary: {summary}")