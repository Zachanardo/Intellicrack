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
API Pattern Analysis Engine

This module provides sophisticated pattern analysis for API call sequences
to identify licensing mechanisms, protection schemes, and security-relevant
behavior patterns in real-time.

Features:
- License validation sequence detection
- Protection mechanism pattern recognition
- Trial period tracking through API calls
- Anti-analysis behavior identification
- Hardware fingerprinting detection
- Time-based protection analysis
- Network licensing pattern recognition
"""

import json
import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import threading
import statistics

from .api_call_tracer import APICall, APICategory, CallDirection

logger = logging.getLogger(__name__)


class PatternType(Enum):
    """Types of patterns that can be detected."""
    LICENSE_VALIDATION = auto()
    TRIAL_PERIOD_CHECK = auto()
    HARDWARE_FINGERPRINT = auto()
    ANTI_DEBUG_SEQUENCE = auto()
    ANTI_VM_SEQUENCE = auto()
    NETWORK_LICENSE_CHECK = auto()
    TIME_BOMB_DETECTION = auto()
    PROTECTION_INITIALIZATION = auto()
    INTEGRITY_CHECK = auto()
    REGISTRY_LICENSE_LOOKUP = auto()
    FILE_LICENSE_LOOKUP = auto()
    CRYPTOGRAPHIC_VALIDATION = auto()
    ONLINE_ACTIVATION = auto()
    UNKNOWN = auto()


class PatternSeverity(Enum):
    """Severity levels for detected patterns."""
    CRITICAL = auto()    # Immediate protection mechanism
    HIGH = auto()        # Important licensing check
    MEDIUM = auto()      # General protection activity
    LOW = auto()         # Background monitoring
    INFO = auto()        # Informational activity


@dataclass
class DetectedPattern:
    """A detected API call pattern."""
    pattern_type: PatternType
    severity: PatternSeverity
    confidence: float  # 0.0 to 1.0
    timestamp: float
    description: str
    api_calls: List[APICall]
    duration_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    sequence_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert pattern to dictionary for serialization."""
        return {
            'pattern_type': self.pattern_type.name,
            'severity': self.severity.name,
            'confidence': self.confidence,
            'timestamp': self.timestamp,
            'description': self.description,
            'duration_ms': self.duration_ms,
            'metadata': self.metadata,
            'sequence_id': self.sequence_id,
            'api_call_count': len(self.api_calls),
            'first_call': self.api_calls[0].to_dict() if self.api_calls else None,
            'last_call': self.api_calls[-1].to_dict() if self.api_calls else None
        }


class PatternRule:
    """Rule for detecting specific API call patterns."""
    
    def __init__(self, name: str, pattern_type: PatternType, 
                 severity: PatternSeverity, description: str):
        """
        Initialize pattern rule.
        
        Args:
            name: Unique rule name
            pattern_type: Type of pattern this rule detects
            severity: Severity level of this pattern
            description: Human-readable description
        """
        self.name = name
        self.pattern_type = pattern_type
        self.severity = severity
        self.description = description
        self.api_sequence = []
        self.time_window_ms = 5000  # 5 second default window
        self.min_confidence = 0.7
        self.metadata_extractors = []
        
    def add_api_requirement(self, module: str, function: str, 
                           parameters: Optional[Dict[str, Any]] = None,
                           order_strict: bool = False) -> 'PatternRule':
        """
        Add API call requirement to the pattern.
        
        Args:
            module: Module name (can use wildcards)
            function: Function name (can use wildcards)
            parameters: Optional parameter constraints
            order_strict: Whether order must be preserved
            
        Returns:
            Self for method chaining
        """
        self.api_sequence.append({
            'module': module,
            'function': function,
            'parameters': parameters or {},
            'order_strict': order_strict
        })
        return self
    
    def set_time_window(self, window_ms: int) -> 'PatternRule':
        """Set time window for pattern detection."""
        self.time_window_ms = window_ms
        return self
    
    def set_confidence_threshold(self, threshold: float) -> 'PatternRule':
        """Set minimum confidence threshold."""
        self.min_confidence = threshold
        return self
    
    def add_metadata_extractor(self, extractor_func) -> 'PatternRule':
        """Add metadata extraction function."""
        self.metadata_extractors.append(extractor_func)
        return self
    
    def matches_call(self, api_call: APICall, requirement: Dict[str, Any]) -> float:
        """
        Check if API call matches requirement.
        
        Args:
            api_call: API call to check
            requirement: Requirement specification
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        confidence = 0.0
        
        # Check module match
        module_pattern = requirement['module']
        if self._matches_pattern(api_call.module.lower(), module_pattern.lower()):
            confidence += 0.4
        
        # Check function match
        function_pattern = requirement['function']
        if self._matches_pattern(api_call.function.lower(), function_pattern.lower()):
            confidence += 0.4
        
        # Check parameters if specified
        param_requirements = requirement.get('parameters', {})
        if param_requirements:
            param_confidence = self._check_parameters(api_call.parameters, param_requirements)
            confidence += 0.2 * param_confidence
        else:
            confidence += 0.2  # No parameter requirements
        
        return min(confidence, 1.0)
    
    def _matches_pattern(self, text: str, pattern: str) -> bool:
        """Check if text matches pattern (supports wildcards)."""
        if '*' in pattern:
            regex_pattern = pattern.replace('*', '.*')
            return bool(re.match(regex_pattern, text))
        return pattern in text
    
    def _check_parameters(self, parameters: List[Any], requirements: Dict[str, Any]) -> float:
        """Check if parameters match requirements."""
        if not requirements:
            return 1.0
        
        confidence = 0.0
        checked_requirements = 0
        
        for req_name, req_value in requirements.items():
            checked_requirements += 1
            
            if req_name == 'count':
                if len(parameters) >= req_value:
                    confidence += 1.0
            elif req_name == 'contains':
                if any(str(req_value).lower() in str(param).lower() for param in parameters):
                    confidence += 1.0
            elif req_name == 'regex':
                if any(re.search(req_value, str(param)) for param in parameters):
                    confidence += 1.0
        
        return confidence / checked_requirements if checked_requirements > 0 else 1.0


class APIPatternAnalyzer:
    """
    Sophisticated API pattern analysis engine.
    
    Analyzes sequences of API calls to identify licensing mechanisms,
    protection schemes, and security-relevant behavior patterns.
    """
    
    def __init__(self, window_size: int = 1000):
        """
        Initialize pattern analyzer.
        
        Args:
            window_size: Number of recent API calls to maintain for analysis
        """
        self.window_size = window_size
        self.api_call_window = deque(maxlen=window_size)
        self.detected_patterns = []
        self.pattern_rules = {}
        self.analysis_stats = defaultdict(int)
        self.lock = threading.RLock()
        
        # Initialize built-in pattern rules
        self._initialize_pattern_rules()
        
        logger.info("API Pattern Analyzer initialized with %d rules", len(self.pattern_rules))
    
    def _initialize_pattern_rules(self) -> None:
        """Initialize built-in pattern detection rules."""
        
        # License validation sequence
        license_rule = PatternRule(
            "license_validation",
            PatternType.LICENSE_VALIDATION,
            PatternSeverity.CRITICAL,
            "License validation sequence detected"
        )
        license_rule.add_api_requirement("advapi32.dll", "*RegQueryValue*", {'contains': 'license'}) \
                   .add_api_requirement("advapi32.dll", "*Crypt*") \
                   .set_time_window(10000) \
                   .set_confidence_threshold(0.6)
        self.pattern_rules[license_rule.name] = license_rule
        
        # Trial period check
        trial_rule = PatternRule(
            "trial_period_check",
            PatternType.TRIAL_PERIOD_CHECK,
            PatternSeverity.HIGH,
            "Trial period validation detected"
        )
        trial_rule.add_api_requirement("kernel32.dll", "*GetSystemTime*") \
                 .add_api_requirement("*", "*", {'contains': 'trial'}) \
                 .add_api_requirement("advapi32.dll", "*RegQueryValue*") \
                 .set_time_window(15000) \
                 .set_confidence_threshold(0.5)
        self.pattern_rules[trial_rule.name] = trial_rule
        
        # Hardware fingerprinting
        hwid_rule = PatternRule(
            "hardware_fingerprint",
            PatternType.HARDWARE_FINGERPRINT,
            PatternSeverity.HIGH,
            "Hardware fingerprinting detected"
        )
        hwid_rule.add_api_requirement("kernel32.dll", "*GetVolumeInformation*") \
                .add_api_requirement("*", "*GetAdaptersInfo*") \
                .add_api_requirement("advapi32.dll", "*RegQueryValue*", {'contains': 'hardware'}) \
                .set_time_window(20000) \
                .set_confidence_threshold(0.6)
        self.pattern_rules[hwid_rule.name] = hwid_rule
        
        # Anti-debugging sequence
        antidebug_rule = PatternRule(
            "anti_debug_sequence",
            PatternType.ANTI_DEBUG_SEQUENCE,
            PatternSeverity.CRITICAL,
            "Anti-debugging sequence detected"
        )
        antidebug_rule.add_api_requirement("kernel32.dll", "*IsDebuggerPresent*") \
                     .add_api_requirement("kernel32.dll", "*CheckRemoteDebuggerPresent*") \
                     .add_api_requirement("ntdll.dll", "*NtQueryInformationProcess*") \
                     .set_time_window(5000) \
                     .set_confidence_threshold(0.7)
        self.pattern_rules[antidebug_rule.name] = antidebug_rule
        
        # Network license check
        network_license_rule = PatternRule(
            "network_license_check",
            PatternType.NETWORK_LICENSE_CHECK,
            PatternSeverity.HIGH,
            "Network license validation detected"
        )
        network_license_rule.add_api_requirement("wininet.dll", "*InternetOpen*") \
                           .add_api_requirement("wininet.dll", "*InternetConnect*") \
                           .add_api_requirement("wininet.dll", "*HttpSendRequest*") \
                           .add_api_requirement("advapi32.dll", "*Crypt*") \
                           .set_time_window(30000) \
                           .set_confidence_threshold(0.6)
        self.pattern_rules[network_license_rule.name] = network_license_rule
        
        # Time bomb detection
        timebomb_rule = PatternRule(
            "time_bomb_detection",
            PatternType.TIME_BOMB_DETECTION,
            PatternSeverity.CRITICAL,
            "Time bomb mechanism detected"
        )
        timebomb_rule.add_api_requirement("kernel32.dll", "*GetSystemTime*") \
                    .add_api_requirement("kernel32.dll", "*GetLocalTime*") \
                    .add_api_requirement("kernel32.dll", "*CompareFileTime*") \
                    .add_api_requirement("kernel32.dll", "*ExitProcess*") \
                    .set_time_window(10000) \
                    .set_confidence_threshold(0.8)
        self.pattern_rules[timebomb_rule.name] = timebomb_rule
        
        # Registry license lookup
        registry_license_rule = PatternRule(
            "registry_license_lookup",
            PatternType.REGISTRY_LICENSE_LOOKUP,
            PatternSeverity.MEDIUM,
            "Registry-based license lookup detected"
        )
        registry_license_rule.add_api_requirement("advapi32.dll", "*RegOpenKey*") \
                           .add_api_requirement("advapi32.dll", "*RegQueryValue*", {'contains': 'license'}) \
                           .add_api_requirement("advapi32.dll", "*RegCloseKey*") \
                           .set_time_window(5000) \
                           .set_confidence_threshold(0.5)
        self.pattern_rules[registry_license_rule.name] = registry_license_rule
        
        # File license lookup
        file_license_rule = PatternRule(
            "file_license_lookup",
            PatternType.FILE_LICENSE_LOOKUP,
            PatternSeverity.MEDIUM,
            "File-based license lookup detected"
        )
        file_license_rule.add_api_requirement("kernel32.dll", "*CreateFile*", {'contains': 'license'}) \
                        .add_api_requirement("kernel32.dll", "*ReadFile*") \
                        .add_api_requirement("advapi32.dll", "*Crypt*") \
                        .set_time_window(8000) \
                        .set_confidence_threshold(0.6)
        self.pattern_rules[file_license_rule.name] = file_license_rule
        
        # Online activation
        activation_rule = PatternRule(
            "online_activation",
            PatternType.ONLINE_ACTIVATION,
            PatternSeverity.HIGH,
            "Online activation sequence detected"
        )
        activation_rule.add_api_requirement("winhttp.dll", "*WinHttpOpen*") \
                     .add_api_requirement("winhttp.dll", "*WinHttpConnect*") \
                     .add_api_requirement("winhttp.dll", "*WinHttpSendRequest*") \
                     .add_api_requirement("advapi32.dll", "*RegSetValue*", {'contains': 'license'}) \
                     .set_time_window(45000) \
                     .set_confidence_threshold(0.7)
        self.pattern_rules[activation_rule.name] = activation_rule
    
    def analyze_api_call(self, api_call: APICall) -> List[DetectedPattern]:
        """
        Analyze a new API call for patterns.
        
        Args:
            api_call: New API call to analyze
            
        Returns:
            List of newly detected patterns
        """
        with self.lock:
            # Add to sliding window
            self.api_call_window.append(api_call)
            self.analysis_stats['total_calls_analyzed'] += 1
            
            # Analyze for patterns
            detected_patterns = []
            
            for rule_name, rule in self.pattern_rules.items():
                pattern = self._check_pattern_rule(rule, list(self.api_call_window))
                if pattern:
                    detected_patterns.append(pattern)
                    self.detected_patterns.append(pattern)
                    self.analysis_stats[f'pattern_{rule.pattern_type.name}'] += 1
                    
                    logger.info("Pattern detected: %s (confidence: %.2f)", 
                              pattern.description, pattern.confidence)
            
            return detected_patterns
    
    def _check_pattern_rule(self, rule: PatternRule, api_calls: List[APICall]) -> Optional[DetectedPattern]:
        """
        Check if a pattern rule matches in the API call sequence.
        
        Args:
            rule: Pattern rule to check
            api_calls: List of API calls to analyze
            
        Returns:
            DetectedPattern if rule matches, None otherwise
        """
        if not rule.api_sequence:
            return None
        
        # Get recent calls within time window
        current_time = time.time()
        window_start = current_time - (rule.time_window_ms / 1000.0)
        recent_calls = [call for call in api_calls if call.timestamp >= window_start]
        
        if len(recent_calls) < len(rule.api_sequence):
            return None
        
        # Try to match the pattern
        best_match = self._find_best_sequence_match(rule, recent_calls)
        
        if best_match and best_match['confidence'] >= rule.min_confidence:
            matched_calls = best_match['calls']
            
            # Extract metadata using rule extractors
            metadata = {}
            for extractor in rule.metadata_extractors:
                try:
                    metadata.update(extractor(matched_calls))
                except Exception as e:
                    logger.error("Error in metadata extractor: %s", e)
            
            # Calculate duration
            if len(matched_calls) > 1:
                duration_ms = (matched_calls[-1].timestamp - matched_calls[0].timestamp) * 1000
            else:
                duration_ms = 0.0
            
            # Create detected pattern
            pattern = DetectedPattern(
                pattern_type=rule.pattern_type,
                severity=rule.severity,
                confidence=best_match['confidence'],
                timestamp=current_time,
                description=rule.description,
                api_calls=matched_calls,
                duration_ms=duration_ms,
                metadata=metadata,
                sequence_id=f"{rule.name}_{int(current_time)}"
            )
            
            return pattern
        
        return None
    
    def _find_best_sequence_match(self, rule: PatternRule, api_calls: List[APICall]) -> Optional[Dict[str, Any]]:
        """
        Find the best matching sequence for a pattern rule.
        
        Args:
            rule: Pattern rule to match
            api_calls: List of API calls to search
            
        Returns:
            Dictionary with 'confidence' and 'calls' if match found
        """
        best_confidence = 0.0
        best_calls = []
        
        # Try different starting positions
        for start_idx in range(len(api_calls) - len(rule.api_sequence) + 1):
            match_result = self._try_sequence_match(rule, api_calls, start_idx)
            if match_result and match_result['confidence'] > best_confidence:
                best_confidence = match_result['confidence']
                best_calls = match_result['calls']
        
        if best_confidence > 0:
            return {'confidence': best_confidence, 'calls': best_calls}
        
        return None
    
    def _try_sequence_match(self, rule: PatternRule, api_calls: List[APICall], start_idx: int) -> Optional[Dict[str, Any]]:
        """
        Try to match pattern sequence starting at given index.
        
        Args:
            rule: Pattern rule to match
            api_calls: List of API calls
            start_idx: Starting index for matching
            
        Returns:
            Match result with confidence and calls
        """
        matched_calls = []
        total_confidence = 0.0
        requirement_idx = 0
        
        for call_idx in range(start_idx, len(api_calls)):
            if requirement_idx >= len(rule.api_sequence):
                break
            
            requirement = rule.api_sequence[requirement_idx]
            api_call = api_calls[call_idx]
            
            # Check if this call matches the current requirement
            confidence = rule.matches_call(api_call, requirement)
            
            if confidence > 0.3:  # Minimum threshold for individual matches
                matched_calls.append(api_call)
                total_confidence += confidence
                requirement_idx += 1
        
        # Check if we matched all requirements
        if requirement_idx == len(rule.api_sequence):
            avg_confidence = total_confidence / len(rule.api_sequence)
            return {'confidence': avg_confidence, 'calls': matched_calls}
        
        return None
    
    def get_recent_patterns(self, count: int = 10) -> List[DetectedPattern]:
        """
        Get most recently detected patterns.
        
        Args:
            count: Maximum number of patterns to return
            
        Returns:
            List of recent patterns (most recent first)
        """
        with self.lock:
            return sorted(self.detected_patterns, key=lambda p: p.timestamp, reverse=True)[:count]
    
    def get_patterns_by_type(self, pattern_type: PatternType) -> List[DetectedPattern]:
        """
        Get all patterns of a specific type.
        
        Args:
            pattern_type: Type of patterns to retrieve
            
        Returns:
            List of patterns of the specified type
        """
        with self.lock:
            return [p for p in self.detected_patterns if p.pattern_type == pattern_type]
    
    def get_patterns_by_severity(self, min_severity: PatternSeverity) -> List[DetectedPattern]:
        """
        Get patterns above minimum severity level.
        
        Args:
            min_severity: Minimum severity level
            
        Returns:
            List of patterns meeting severity criteria
        """
        severity_order = {
            PatternSeverity.INFO: 0,
            PatternSeverity.LOW: 1,
            PatternSeverity.MEDIUM: 2,
            PatternSeverity.HIGH: 3,
            PatternSeverity.CRITICAL: 4
        }
        
        min_level = severity_order[min_severity]
        
        with self.lock:
            return [p for p in self.detected_patterns 
                   if severity_order[p.severity] >= min_level]
    
    def analyze_pattern_timeline(self, time_range_seconds: int = 300) -> Dict[str, Any]:
        """
        Analyze pattern detection timeline over specified time range.
        
        Args:
            time_range_seconds: Time range to analyze (default: 5 minutes)
            
        Returns:
            Timeline analysis with pattern counts and timing
        """
        current_time = time.time()
        start_time = current_time - time_range_seconds
        
        with self.lock:
            recent_patterns = [p for p in self.detected_patterns 
                             if p.timestamp >= start_time]
            
            # Group by pattern type
            type_counts = defaultdict(int)
            severity_counts = defaultdict(int)
            timeline_buckets = defaultdict(list)
            
            # Create 10-second buckets for timeline
            bucket_size = time_range_seconds / 30  # 30 buckets
            
            for pattern in recent_patterns:
                type_counts[pattern.pattern_type.name] += 1
                severity_counts[pattern.severity.name] += 1
                
                # Assign to timeline bucket
                bucket_idx = int((pattern.timestamp - start_time) / bucket_size)
                timeline_buckets[bucket_idx].append(pattern)
            
            # Calculate pattern rates
            total_patterns = len(recent_patterns)
            patterns_per_minute = (total_patterns / time_range_seconds) * 60 if time_range_seconds > 0 else 0
            
            return {
                'time_range_seconds': time_range_seconds,
                'total_patterns': total_patterns,
                'patterns_per_minute': patterns_per_minute,
                'type_distribution': dict(type_counts),
                'severity_distribution': dict(severity_counts),
                'timeline_buckets': {k: len(v) for k, v in timeline_buckets.items()},
                'most_active_period': max(timeline_buckets.items(), key=lambda x: len(x[1]))[0] if timeline_buckets else None
            }
    
    def get_pattern_statistics(self) -> Dict[str, Any]:
        """Get comprehensive pattern analysis statistics."""
        with self.lock:
            total_patterns = len(self.detected_patterns)
            
            if total_patterns == 0:
                return {
                    'total_patterns': 0,
                    'analysis_stats': dict(self.analysis_stats),
                    'rules_loaded': len(self.pattern_rules)
                }
            
            # Calculate confidence statistics
            confidences = [p.confidence for p in self.detected_patterns]
            
            # Calculate duration statistics
            durations = [p.duration_ms for p in self.detected_patterns if p.duration_ms > 0]
            
            return {
                'total_patterns': total_patterns,
                'analysis_stats': dict(self.analysis_stats),
                'rules_loaded': len(self.pattern_rules),
                'confidence_stats': {
                    'avg': statistics.mean(confidences),
                    'min': min(confidences),
                    'max': max(confidences),
                    'median': statistics.median(confidences)
                },
                'duration_stats': {
                    'avg_ms': statistics.mean(durations) if durations else 0,
                    'min_ms': min(durations) if durations else 0,
                    'max_ms': max(durations) if durations else 0,
                    'median_ms': statistics.median(durations) if durations else 0
                },
                'pattern_types': list(set(p.pattern_type.name for p in self.detected_patterns)),
                'window_utilization': len(self.api_call_window) / self.window_size
            }
    
    def add_custom_rule(self, rule: PatternRule) -> bool:
        """
        Add custom pattern detection rule.
        
        Args:
            rule: Custom pattern rule to add
            
        Returns:
            True if rule added successfully, False if rule name exists
        """
        with self.lock:
            if rule.name in self.pattern_rules:
                logger.warning("Pattern rule already exists: %s", rule.name)
                return False
            
            self.pattern_rules[rule.name] = rule
            logger.info("Added custom pattern rule: %s", rule.name)
            return True
    
    def remove_rule(self, rule_name: str) -> bool:
        """
        Remove pattern detection rule.
        
        Args:
            rule_name: Name of rule to remove
            
        Returns:
            True if rule removed, False if not found
        """
        with self.lock:
            if rule_name in self.pattern_rules:
                del self.pattern_rules[rule_name]
                logger.info("Removed pattern rule: %s", rule_name)
                return True
            
            logger.warning("Pattern rule not found: %s", rule_name)
            return False
    
    def export_patterns(self, output_path: str, format: str = 'json') -> bool:
        """
        Export detected patterns to file.
        
        Args:
            output_path: Path for output file
            format: Export format ('json' or 'csv')
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            with self.lock:
                patterns = [p.to_dict() for p in self.detected_patterns]
            
            if format == 'json':
                with open(output_path, 'w') as f:
                    json.dump({
                        'export_timestamp': datetime.now().isoformat(),
                        'total_patterns': len(patterns),
                        'statistics': self.get_pattern_statistics(),
                        'patterns': patterns
                    }, f, indent=2)
            
            elif format == 'csv':
                import csv
                with open(output_path, 'w', newline='') as f:
                    if patterns:
                        writer = csv.DictWriter(f, fieldnames=patterns[0].keys())
                        writer.writeheader()
                        for pattern in patterns:
                            writer.writerow(pattern)
            
            else:
                logger.error("Unsupported export format: %s", format)
                return False
            
            logger.info("Exported %d patterns to %s", len(patterns), output_path)
            return True
            
        except Exception as e:
            logger.error("Failed to export patterns: %s", e)
            return False