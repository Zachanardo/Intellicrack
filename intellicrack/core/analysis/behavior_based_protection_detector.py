"""
Behavior-Based Protection Detection System

This module implements a comprehensive behavior-based protection detection system
that analyzes dynamic runtime behavior to identify protection mechanisms through
machine learning and temporal pattern analysis.

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
import numpy as np
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union, Callable
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import silhouette_score
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    import scipy.signal
    import scipy.stats
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

from ...utils.core.import_checks import PSUTIL_AVAILABLE, psutil
from ...utils.logger import get_logger


class ProtectionFamily(Enum):
    """Known protection families for classification."""
    DENUVO = "denuvo"
    VMPROTECT = "vmprotect"
    THEMIDA = "themida"
    ENIGMA = "enigma"
    SAFENET = "safenet"
    FLEXNET = "flexnet"
    HASP = "hasp"
    CUSTOM_LICENSE = "custom_license"
    TRIAL_PROTECTION = "trial_protection"
    ONLINE_ACTIVATION = "online_activation"
    HARDWARE_BINDING = "hardware_binding"
    TIME_BOMBING = "time_bombing"
    UNKNOWN = "unknown"


class BehaviorType(Enum):
    """Types of behavioral patterns."""
    API_SEQUENCE = "api_sequence"
    MEMORY_ACCESS = "memory_access"
    NETWORK_ACTIVITY = "network_activity"
    FILE_OPERATION = "file_operation"
    REGISTRY_ACCESS = "registry_access"
    TIMING_PATTERN = "timing_pattern"
    PERIODIC_BEHAVIOR = "periodic_behavior"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"


class DetectionConfidence(Enum):
    """Confidence levels for protection detection."""
    VERY_LOW = 0.1
    LOW = 0.3
    MEDIUM = 0.5
    HIGH = 0.7
    VERY_HIGH = 0.9
    CERTAIN = 0.99


@dataclass
class BehaviorEvent:
    """Represents a single behavioral event."""
    timestamp: float
    event_type: BehaviorType
    source: str
    data: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None
    process_id: Optional[int] = None
    thread_id: Optional[int] = None


@dataclass
class TemporalPattern:
    """Represents a temporal behavioral pattern."""
    pattern_id: str
    behavior_type: BehaviorType
    events: List[BehaviorEvent]
    frequency: float
    periodicity: Optional[float] = None
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProtectionSignature:
    """Behavioral signature for a protection mechanism."""
    family: ProtectionFamily
    signature_name: str
    patterns: List[TemporalPattern]
    feature_vector: np.ndarray
    confidence_threshold: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    """Result of protection detection analysis."""
    family: ProtectionFamily
    confidence: float
    evidence: List[TemporalPattern]
    signature_matches: List[str]
    classification_features: Dict[str, float]
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)


class BehaviorDataCollector:
    """Collects behavioral data from multiple sources."""
    
    def __init__(self, max_events: int = 100000):
        self.logger = get_logger(__name__)
        self.max_events = max_events
        self.events = deque(maxlen=max_events)
        self.event_sources = {}
        self.collection_lock = threading.RLock()
        self.is_collecting = False
        
    def register_source(self, source_name: str, source_callback: Callable):
        """Register a data source for behavioral events."""
        with self.collection_lock:
            self.event_sources[source_name] = source_callback
            self.logger.info(f"Registered behavior data source: {source_name}")
    
    def start_collection(self):
        """Start behavioral data collection."""
        with self.collection_lock:
            if self.is_collecting:
                return
            
            self.is_collecting = True
            self.collection_thread = threading.Thread(
                target=self._collection_worker,
                daemon=True
            )
            self.collection_thread.start()
            self.logger.info("Started behavioral data collection")
    
    def stop_collection(self):
        """Stop behavioral data collection."""
        with self.collection_lock:
            self.is_collecting = False
            self.logger.info("Stopped behavioral data collection")
    
    def add_event(self, event: BehaviorEvent):
        """Add a behavioral event to the collection."""
        with self.collection_lock:
            self.events.append(event)
    
    def get_events(self, since: Optional[float] = None, 
                  event_type: Optional[BehaviorType] = None,
                  source: Optional[str] = None) -> List[BehaviorEvent]:
        """Get behavioral events with optional filtering."""
        with self.collection_lock:
            events = list(self.events)
            
            if since is not None:
                events = [e for e in events if e.timestamp >= since]
            
            if event_type is not None:
                events = [e for e in events if e.event_type == event_type]
                
            if source is not None:
                events = [e for e in events if e.source == source]
            
            return events
    
    def _collection_worker(self):
        """Worker thread for continuous data collection."""
        while self.is_collecting:
            try:
                for source_name, callback in self.event_sources.items():
                    try:
                        events = callback()
                        if events:
                            for event in events:
                                self.add_event(event)
                    except Exception as e:
                        self.logger.error(f"Error collecting from {source_name}: {e}")
                
                time.sleep(0.1)  # Collect every 100ms
                
            except Exception as e:
                self.logger.error(f"Collection worker error: {e}")
                time.sleep(1.0)


class TemporalPatternAnalyzer:
    """Analyzes temporal patterns in behavioral data."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.pattern_cache = {}
        self.analysis_lock = threading.RLock()
        
    def analyze_patterns(self, events: List[BehaviorEvent],
                        time_window: float = 60.0) -> List[TemporalPattern]:
        """Analyze temporal patterns in behavioral events."""
        if not events:
            return []
        
        patterns = []
        
        # Group events by type
        events_by_type = defaultdict(list)
        for event in events:
            events_by_type[event.event_type].append(event)
        
        # Analyze patterns for each event type
        for event_type, type_events in events_by_type.items():
            if len(type_events) < 3:  # Need minimum events for pattern detection
                continue
                
            # Analyze frequency patterns
            freq_patterns = self._analyze_frequency_patterns(type_events, time_window)
            patterns.extend(freq_patterns)
            
            # Analyze sequence patterns
            seq_patterns = self._analyze_sequence_patterns(type_events)
            patterns.extend(seq_patterns)
            
            # Analyze periodic patterns
            periodic_patterns = self._analyze_periodic_patterns(type_events)
            patterns.extend(periodic_patterns)
        
        return patterns
    
    def _analyze_frequency_patterns(self, events: List[BehaviorEvent], 
                                  time_window: float) -> List[TemporalPattern]:
        """Analyze frequency-based patterns."""
        patterns = []
        
        if len(events) < 3:
            return patterns
        
        # Calculate event frequency
        timestamps = [e.timestamp for e in events]
        time_span = max(timestamps) - min(timestamps)
        
        if time_span <= 0:
            return patterns
        
        frequency = len(events) / time_span
        
        # Detect high-frequency bursts (potential protection checks)
        if frequency > 10:  # More than 10 events per second
            pattern = TemporalPattern(
                pattern_id=f"high_freq_{events[0].event_type.value}_{int(time.time())}",
                behavior_type=events[0].event_type,
                events=events,
                frequency=frequency,
                confidence=min(0.9, frequency / 50),  # Higher frequency = higher confidence
                metadata={
                    'pattern_type': 'high_frequency_burst',
                    'events_per_second': frequency,
                    'total_events': len(events),
                    'time_span': time_span
                }
            )
            patterns.append(pattern)
        
        return patterns
    
    def _analyze_sequence_patterns(self, events: List[BehaviorEvent]) -> List[TemporalPattern]:
        """Analyze sequence-based patterns."""
        patterns = []
        
        if len(events) < 5:
            return patterns
        
        # Look for repeating API call sequences (protection validation patterns)
        if events[0].event_type == BehaviorType.API_SEQUENCE:
            sequences = self._extract_api_sequences(events)
            
            for seq_signature, seq_events in sequences.items():
                if len(seq_events) >= 3:  # Repeated at least 3 times
                    pattern = TemporalPattern(
                        pattern_id=f"api_seq_{seq_signature}_{int(time.time())}",
                        behavior_type=BehaviorType.API_SEQUENCE,
                        events=seq_events,
                        frequency=len(seq_events),
                        confidence=min(0.8, len(seq_events) / 10),
                        metadata={
                            'pattern_type': 'repeating_sequence',
                            'sequence_signature': seq_signature,
                            'repetitions': len(seq_events)
                        }
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def _analyze_periodic_patterns(self, events: List[BehaviorEvent]) -> List[TemporalPattern]:
        """Analyze periodic behavioral patterns."""
        patterns = []
        
        if len(events) < 10 or not SCIPY_AVAILABLE:
            return patterns
        
        try:
            timestamps = np.array([e.timestamp for e in events])
            
            # Calculate inter-event intervals
            intervals = np.diff(timestamps)
            
            if len(intervals) < 5:
                return patterns
            
            # Use autocorrelation to detect periodicity
            autocorr = np.correlate(intervals, intervals, mode='full')
            autocorr = autocorr[autocorr.size // 2:]
            
            # Find peaks in autocorrelation (indicating periodic behavior)
            if len(autocorr) > 10:
                peaks, _ = scipy.signal.find_peaks(autocorr, height=np.max(autocorr) * 0.3)
                
                if len(peaks) > 0:
                    # Calculate approximate period
                    period = np.mean(intervals[peaks[:5]]) if len(peaks) >= 5 else intervals[peaks[0]]
                    
                    pattern = TemporalPattern(
                        pattern_id=f"periodic_{events[0].event_type.value}_{int(time.time())}",
                        behavior_type=events[0].event_type,
                        events=events,
                        frequency=1.0 / period if period > 0 else 0,
                        periodicity=period,
                        confidence=min(0.7, len(peaks) / 10),
                        metadata={
                            'pattern_type': 'periodic_behavior',
                            'period_seconds': period,
                            'detected_peaks': len(peaks),
                            'autocorr_strength': np.max(autocorr)
                        }
                    )
                    patterns.append(pattern)
        
        except Exception as e:
            self.logger.debug(f"Error in periodic pattern analysis: {e}")
        
        return patterns
    
    def _extract_api_sequences(self, events: List[BehaviorEvent]) -> Dict[str, List[BehaviorEvent]]:
        """Extract repeating API call sequences."""
        sequences = defaultdict(list)
        
        # Create sliding window of API calls
        window_size = 5
        for i in range(len(events) - window_size + 1):
            window = events[i:i + window_size]
            
            # Create signature from API names
            api_names = []
            for event in window:
                if 'api_name' in event.data:
                    api_names.append(event.data['api_name'])
            
            if len(api_names) == window_size:
                signature = '->'.join(api_names)
                sequences[signature].extend(window)
        
        return sequences


class MLProtectionClassifier:
    """Machine learning-based protection classification."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.models = {}
        self.scalers = {}
        self.feature_extractors = {}
        self.is_trained = False
        
        if ML_AVAILABLE:
            self._initialize_models()
        else:
            self.logger.warning("Scikit-learn not available, ML classification disabled")
    
    def _initialize_models(self):
        """Initialize machine learning models."""
        if not ML_AVAILABLE:
            return
        
        # Random Forest for supervised classification
        self.models['rf_classifier'] = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1
        )
        
        # Isolation Forest for anomaly detection
        self.models['isolation_forest'] = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        
        # DBSCAN for unsupervised clustering
        self.models['dbscan'] = DBSCAN(eps=0.5, min_samples=5)
        
        # Standard scaler for feature normalization
        self.scalers['standard'] = StandardScaler()
        
        self.logger.info("Initialized ML models for protection classification")
    
    def extract_features(self, patterns: List[TemporalPattern]) -> np.ndarray:
        """Extract feature vector from temporal patterns."""
        if not patterns:
            return np.array([])
        
        features = []
        
        # Feature 1: Pattern count by type
        pattern_counts = defaultdict(int)
        for pattern in patterns:
            pattern_counts[pattern.behavior_type] += 1
        
        # Normalize pattern counts
        total_patterns = len(patterns)
        for behavior_type in BehaviorType:
            features.append(pattern_counts[behavior_type] / total_patterns)
        
        # Feature 2: Average frequency
        frequencies = [p.frequency for p in patterns if p.frequency > 0]
        avg_frequency = np.mean(frequencies) if frequencies else 0
        features.append(avg_frequency)
        
        # Feature 3: Periodicity indicators
        periodic_patterns = [p for p in patterns if p.periodicity is not None]
        features.append(len(periodic_patterns) / total_patterns)
        
        if periodic_patterns:
            avg_period = np.mean([p.periodicity for p in periodic_patterns])
            features.append(avg_period)
        else:
            features.append(0)
        
        # Feature 4: Confidence scores
        avg_confidence = np.mean([p.confidence for p in patterns])
        features.append(avg_confidence)
        
        # Feature 5: Event density
        all_events = []
        for pattern in patterns:
            all_events.extend(pattern.events)
        
        if len(all_events) > 1:
            timestamps = [e.timestamp for e in all_events]
            time_span = max(timestamps) - min(timestamps)
            event_density = len(all_events) / time_span if time_span > 0 else 0
        else:
            event_density = 0
        
        features.append(event_density)
        
        # Feature 6: API sequence complexity
        api_patterns = [p for p in patterns if p.behavior_type == BehaviorType.API_SEQUENCE]
        api_complexity = len(api_patterns) / total_patterns if total_patterns > 0 else 0
        features.append(api_complexity)
        
        # Feature 7: Memory access patterns
        memory_patterns = [p for p in patterns if p.behavior_type == BehaviorType.MEMORY_ACCESS]
        memory_intensity = len(memory_patterns) / total_patterns if total_patterns > 0 else 0
        features.append(memory_intensity)
        
        # Feature 8: Network activity indicators
        network_patterns = [p for p in patterns if p.behavior_type == BehaviorType.NETWORK_ACTIVITY]
        network_activity = len(network_patterns) / total_patterns if total_patterns > 0 else 0
        features.append(network_activity)
        
        return np.array(features)
    
    def classify_protection(self, patterns: List[TemporalPattern]) -> Optional[DetectionResult]:
        """Classify protection family based on behavioral patterns."""
        if not ML_AVAILABLE or not patterns:
            return None
        
        try:
            # Extract features
            features = self.extract_features(patterns)
            if len(features) == 0:
                return None
            
            features = features.reshape(1, -1)
            
            # Use rule-based classification as fallback when ML models aren't trained
            if not self.is_trained:
                return self._rule_based_classification(patterns, features[0])
            
            # Scale features if scaler is fitted
            if hasattr(self.scalers['standard'], 'scale_'):
                features_scaled = self.scalers['standard'].transform(features)
            else:
                features_scaled = features
            
            # Get classification probabilities
            if hasattr(self.models['rf_classifier'], 'predict_proba'):
                probabilities = self.models['rf_classifier'].predict_proba(features_scaled)[0]
                classes = self.models['rf_classifier'].classes_
                
                # Find highest probability class
                max_idx = np.argmax(probabilities)
                predicted_family = ProtectionFamily(classes[max_idx])
                confidence = probabilities[max_idx]
            else:
                # Fallback to rule-based classification
                return self._rule_based_classification(patterns, features[0])
            
            # Check for anomalies
            anomaly_score = self.models['isolation_forest'].decision_function(features_scaled)[0]
            is_anomaly = anomaly_score < 0
            
            # Adjust confidence based on anomaly detection
            if is_anomaly:
                confidence *= 0.7  # Reduce confidence for anomalous patterns
            
            return DetectionResult(
                family=predicted_family,
                confidence=confidence,
                evidence=patterns,
                signature_matches=[],
                classification_features={
                    f'feature_{i}': float(features[0][i]) for i in range(len(features[0]))
                },
                analysis_metadata={
                    'ml_classification': True,
                    'anomaly_score': float(anomaly_score),
                    'is_anomaly': is_anomaly,
                    'feature_count': len(features[0])
                }
            )
        
        except Exception as e:
            self.logger.error(f"ML classification error: {e}")
            return self._rule_based_classification(patterns, features[0] if len(features) > 0 else np.array([]))
    
    def _rule_based_classification(self, patterns: List[TemporalPattern], 
                                 features: np.ndarray) -> DetectionResult:
        """Rule-based protection classification as fallback."""
        # Analyze pattern characteristics for rule-based classification
        api_patterns = [p for p in patterns if p.behavior_type == BehaviorType.API_SEQUENCE]
        periodic_patterns = [p for p in patterns if p.periodicity is not None]
        high_freq_patterns = [p for p in patterns if p.frequency > 10]
        
        # Classification rules
        family = ProtectionFamily.UNKNOWN
        confidence = 0.1
        reasoning = []
        
        # Rule 1: High-frequency API calls suggest VM-based protection
        if len(high_freq_patterns) >= 3 and len(api_patterns) >= 5:
            family = ProtectionFamily.VMPROTECT
            confidence = 0.6
            reasoning.append("High-frequency API patterns suggest virtualization protection")
        
        # Rule 2: Periodic network activity suggests online activation
        network_periodic = [p for p in periodic_patterns 
                          if p.behavior_type == BehaviorType.NETWORK_ACTIVITY]
        if len(network_periodic) >= 2:
            family = ProtectionFamily.ONLINE_ACTIVATION
            confidence = 0.7
            reasoning.append("Periodic network activity suggests online activation system")
        
        # Rule 3: Memory access patterns with high frequency suggest anti-debug
        memory_patterns = [p for p in patterns if p.behavior_type == BehaviorType.MEMORY_ACCESS]
        if len(memory_patterns) >= 4 and len(high_freq_patterns) >= 2:
            family = ProtectionFamily.THEMIDA
            confidence = 0.5
            reasoning.append("Complex memory patterns suggest advanced protection")
        
        # Rule 4: Registry access patterns suggest trial protection
        registry_patterns = [p for p in patterns if p.behavior_type == BehaviorType.REGISTRY_ACCESS]
        if len(registry_patterns) >= 3:
            family = ProtectionFamily.TRIAL_PROTECTION
            confidence = 0.6
            reasoning.append("Registry access patterns suggest trial/license validation")
        
        # Rule 5: Complex API sequences suggest custom licensing
        if len(api_patterns) >= 8:
            family = ProtectionFamily.CUSTOM_LICENSE
            confidence = 0.4
            reasoning.append("Complex API sequences suggest custom licensing scheme")
        
        return DetectionResult(
            family=family,
            confidence=confidence,
            evidence=patterns,
            signature_matches=reasoning,
            classification_features={
                'api_pattern_count': len(api_patterns),
                'periodic_pattern_count': len(periodic_patterns),
                'high_freq_pattern_count': len(high_freq_patterns),
                'total_patterns': len(patterns)
            },
            analysis_metadata={
                'ml_classification': False,
                'rule_based': True,
                'reasoning': reasoning
            }
        )


class BehavioralSignatureEngine:
    """Engine for creating and matching behavioral signatures."""
    
    def __init__(self, signature_db_path: Optional[Path] = None):
        self.logger = get_logger(__name__)
        self.signatures = {}
        self.signature_db_path = signature_db_path or Path("behavior_signatures.json")
        self.matching_lock = threading.RLock()
        
        self._load_signatures()
    
    def _load_signatures(self):
        """Load behavioral signatures from database."""
        try:
            if self.signature_db_path.exists():
                with open(self.signature_db_path, 'r') as f:
                    signature_data = json.load(f)
                    
                for family_name, sigs in signature_data.items():
                    family = ProtectionFamily(family_name)
                    self.signatures[family] = []
                    
                    for sig_data in sigs:
                        # Reconstruct signature from saved data
                        signature = self._reconstruct_signature(sig_data)
                        if signature:
                            self.signatures[family].append(signature)
                
                self.logger.info(f"Loaded {sum(len(sigs) for sigs in self.signatures.values())} behavioral signatures")
            else:
                self._create_default_signatures()
        
        except Exception as e:
            self.logger.error(f"Error loading signatures: {e}")
            self._create_default_signatures()
    
    def _create_default_signatures(self):
        """Create default behavioral signatures for known protections."""
        # Denuvo signatures
        denuvo_signatures = [
            self._create_signature(
                ProtectionFamily.DENUVO,
                "denuvo_anti_tamper",
                frequency_threshold=15.0,
                api_sequences=["NtQuerySystemInformation", "GetTickCount64", "QueryPerformanceCounter"],
                memory_patterns=["high_frequency_reads", "code_integrity_checks"]
            )
        ]
        
        # VMProtect signatures
        vmprotect_signatures = [
            self._create_signature(
                ProtectionFamily.VMPROTECT,
                "vmprotect_virtualization",
                frequency_threshold=20.0,
                api_sequences=["VirtualAlloc", "VirtualProtect", "FlushInstructionCache"],
                memory_patterns=["dynamic_code_generation", "virtual_machine_execution"]
            )
        ]
        
        # Themida signatures
        themida_signatures = [
            self._create_signature(
                ProtectionFamily.THEMIDA,
                "themida_protection",
                frequency_threshold=12.0,
                api_sequences=["SetUnhandledExceptionFilter", "GetThreadContext", "NtSetInformationThread"],
                memory_patterns=["exception_handling", "context_manipulation"]
            )
        ]
        
        self.signatures = {
            ProtectionFamily.DENUVO: denuvo_signatures,
            ProtectionFamily.VMPROTECT: vmprotect_signatures,
            ProtectionFamily.THEMIDA: themida_signatures
        }
        
        self.logger.info("Created default behavioral signatures")
    
    def _create_signature(self, family: ProtectionFamily, name: str,
                         frequency_threshold: float,
                         api_sequences: List[str],
                         memory_patterns: List[str]) -> ProtectionSignature:
        """Create a protection signature from behavioral characteristics."""
        # Create dummy patterns for signature
        patterns = []
        
        # Create API sequence pattern
        api_pattern = TemporalPattern(
            pattern_id=f"{name}_api",
            behavior_type=BehaviorType.API_SEQUENCE,
            events=[],
            frequency=frequency_threshold,
            metadata={'expected_apis': api_sequences}
        )
        patterns.append(api_pattern)
        
        # Create memory access pattern
        memory_pattern = TemporalPattern(
            pattern_id=f"{name}_memory",
            behavior_type=BehaviorType.MEMORY_ACCESS,
            events=[],
            frequency=frequency_threshold * 0.8,
            metadata={'expected_patterns': memory_patterns}
        )
        patterns.append(memory_pattern)
        
        # Create feature vector (simplified)
        feature_vector = np.array([
            frequency_threshold,
            len(api_sequences),
            len(memory_patterns),
            1.0 if frequency_threshold > 15 else 0.0
        ])
        
        return ProtectionSignature(
            family=family,
            signature_name=name,
            patterns=patterns,
            feature_vector=feature_vector,
            confidence_threshold=0.6,
            metadata={
                'api_sequences': api_sequences,
                'memory_patterns': memory_patterns,
                'frequency_threshold': frequency_threshold
            }
        )
    
    def match_signatures(self, patterns: List[TemporalPattern]) -> List[Tuple[ProtectionSignature, float]]:
        """Match behavioral patterns against known signatures."""
        matches = []
        
        with self.matching_lock:
            for family, signatures in self.signatures.items():
                for signature in signatures:
                    similarity = self._calculate_signature_similarity(patterns, signature)
                    
                    if similarity >= signature.confidence_threshold:
                        matches.append((signature, similarity))
        
        # Sort by similarity score
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches
    
    def _calculate_signature_similarity(self, patterns: List[TemporalPattern],
                                      signature: ProtectionSignature) -> float:
        """Calculate similarity between observed patterns and signature."""
        if not patterns:
            return 0.0
        
        similarity_scores = []
        
        # Check frequency patterns
        freq_similarity = self._compare_frequencies(patterns, signature)
        similarity_scores.append(freq_similarity)
        
        # Check API sequence patterns
        api_similarity = self._compare_api_sequences(patterns, signature)
        similarity_scores.append(api_similarity)
        
        # Check behavior type distribution
        type_similarity = self._compare_behavior_types(patterns, signature)
        similarity_scores.append(type_similarity)
        
        # Calculate weighted average
        weights = [0.4, 0.4, 0.2]  # Frequency and API patterns are most important
        weighted_similarity = sum(s * w for s, w in zip(similarity_scores, weights))
        
        return weighted_similarity
    
    def _compare_frequencies(self, patterns: List[TemporalPattern],
                           signature: ProtectionSignature) -> float:
        """Compare frequency characteristics."""
        pattern_freqs = [p.frequency for p in patterns if p.frequency > 0]
        if not pattern_freqs:
            return 0.0
        
        avg_freq = np.mean(pattern_freqs)
        expected_freq = signature.metadata.get('frequency_threshold', 10.0)
        
        # Calculate similarity using exponential decay
        freq_diff = abs(avg_freq - expected_freq)
        similarity = np.exp(-freq_diff / expected_freq)
        
        return similarity
    
    def _compare_api_sequences(self, patterns: List[TemporalPattern],
                             signature: ProtectionSignature) -> float:
        """Compare API sequence patterns."""
        api_patterns = [p for p in patterns if p.behavior_type == BehaviorType.API_SEQUENCE]
        if not api_patterns:
            return 0.0
        
        expected_apis = signature.metadata.get('api_sequences', [])
        if not expected_apis:
            return 0.5  # Neutral score if no API expectations
        
        # Extract observed API names from patterns
        observed_apis = set()
        for pattern in api_patterns:
            for event in pattern.events:
                if 'api_name' in event.data:
                    observed_apis.add(event.data['api_name'])
        
        # Calculate Jaccard similarity
        expected_set = set(expected_apis)
        intersection = len(observed_apis.intersection(expected_set))
        union = len(observed_apis.union(expected_set))
        
        if union == 0:
            return 0.0
        
        return intersection / union
    
    def _compare_behavior_types(self, patterns: List[TemporalPattern],
                              signature: ProtectionSignature) -> float:
        """Compare behavior type distributions."""
        # Count behavior types in observed patterns
        observed_types = defaultdict(int)
        for pattern in patterns:
            observed_types[pattern.behavior_type] += 1
        
        # Count behavior types in signature patterns
        expected_types = defaultdict(int)
        for pattern in signature.patterns:
            expected_types[pattern.behavior_type] += 1
        
        # Calculate distribution similarity
        all_types = set(observed_types.keys()).union(set(expected_types.keys()))
        if not all_types:
            return 1.0
        
        total_observed = sum(observed_types.values())
        total_expected = sum(expected_types.values())
        
        if total_observed == 0 or total_expected == 0:
            return 0.0
        
        similarity = 0.0
        for behavior_type in all_types:
            obs_freq = observed_types[behavior_type] / total_observed
            exp_freq = expected_types[behavior_type] / total_expected
            
            # Use cosine similarity for frequency distributions
            similarity += obs_freq * exp_freq
        
        return similarity
    
    def create_signature_from_patterns(self, family: ProtectionFamily,
                                     name: str,
                                     patterns: List[TemporalPattern]) -> ProtectionSignature:
        """Create a new behavioral signature from observed patterns."""
        # Extract feature vector from patterns
        feature_vector = np.array([
            len(patterns),
            np.mean([p.frequency for p in patterns if p.frequency > 0]),
            len([p for p in patterns if p.behavior_type == BehaviorType.API_SEQUENCE]),
            len([p for p in patterns if p.periodicity is not None])
        ])
        
        signature = ProtectionSignature(
            family=family,
            signature_name=name,
            patterns=patterns,
            feature_vector=feature_vector,
            confidence_threshold=0.5,
            metadata={
                'created_from_observation': True,
                'creation_time': time.time(),
                'pattern_count': len(patterns)
            }
        )
        
        # Add to signature database
        if family not in self.signatures:
            self.signatures[family] = []
        
        self.signatures[family].append(signature)
        self.logger.info(f"Created new signature '{name}' for {family.value}")
        
        return signature
    
    def _reconstruct_signature(self, sig_data: Dict[str, Any]) -> Optional[ProtectionSignature]:
        """Reconstruct signature from saved JSON data."""
        try:
            family = ProtectionFamily(sig_data['family'])
            
            # Reconstruct patterns
            patterns = []
            for pattern_data in sig_data.get('patterns', []):
                pattern = TemporalPattern(
                    pattern_id=pattern_data['pattern_id'],
                    behavior_type=BehaviorType(pattern_data['behavior_type']),
                    events=[],  # Events not stored in signatures
                    frequency=pattern_data['frequency'],
                    periodicity=pattern_data.get('periodicity'),
                    confidence=pattern_data.get('confidence', 0.0),
                    metadata=pattern_data.get('metadata', {})
                )
                patterns.append(pattern)
            
            signature = ProtectionSignature(
                family=family,
                signature_name=sig_data['signature_name'],
                patterns=patterns,
                feature_vector=np.array(sig_data['feature_vector']),
                confidence_threshold=sig_data['confidence_threshold'],
                metadata=sig_data.get('metadata', {})
            )
            
            return signature
            
        except Exception as e:
            self.logger.error(f"Error reconstructing signature: {e}")
            return None


class RealTimeClassificationEngine:
    """Real-time stream processing for behavior classification."""
    
    def __init__(self, window_size: float = 30.0):
        self.logger = get_logger(__name__)
        self.window_size = window_size
        self.event_buffer = deque()
        self.classification_callbacks = []
        self.processing_lock = threading.RLock()
        self.is_running = False
        
        # Initialize components
        self.pattern_analyzer = TemporalPatternAnalyzer()
        self.ml_classifier = MLProtectionClassifier()
        self.signature_engine = BehavioralSignatureEngine()
        
    def start_processing(self):
        """Start real-time classification processing."""
        with self.processing_lock:
            if self.is_running:
                return
            
            self.is_running = True
            self.processing_thread = threading.Thread(
                target=self._processing_worker,
                daemon=True
            )
            self.processing_thread.start()
            self.logger.info("Started real-time classification engine")
    
    def stop_processing(self):
        """Stop real-time classification processing."""
        with self.processing_lock:
            self.is_running = False
            self.logger.info("Stopped real-time classification engine")
    
    def add_event(self, event: BehaviorEvent):
        """Add behavioral event for real-time processing."""
        with self.processing_lock:
            self.event_buffer.append(event)
            
            # Remove old events outside the window
            current_time = time.time()
            while (self.event_buffer and 
                   current_time - self.event_buffer[0].timestamp > self.window_size):
                self.event_buffer.popleft()
    
    def register_callback(self, callback: Callable[[DetectionResult], None]):
        """Register callback for classification results."""
        self.classification_callbacks.append(callback)
    
    def _processing_worker(self):
        """Worker thread for real-time processing."""
        last_analysis = time.time()
        analysis_interval = 5.0  # Analyze every 5 seconds
        
        while self.is_running:
            try:
                current_time = time.time()
                
                if current_time - last_analysis >= analysis_interval:
                    self._perform_analysis()
                    last_analysis = current_time
                
                time.sleep(0.5)  # Check every 500ms
                
            except Exception as e:
                self.logger.error(f"Real-time processing error: {e}")
                time.sleep(1.0)
    
    def _perform_analysis(self):
        """Perform behavioral analysis on current window."""
        with self.processing_lock:
            if len(self.event_buffer) < 5:  # Need minimum events
                return
            
            events = list(self.event_buffer)
        
        try:
            # Analyze temporal patterns
            patterns = self.pattern_analyzer.analyze_patterns(events, self.window_size)
            
            if not patterns:
                return
            
            # Classify using ML
            ml_result = self.ml_classifier.classify_protection(patterns)
            
            # Match against signatures
            signature_matches = self.signature_engine.match_signatures(patterns)
            
            # Combine results for final detection
            final_result = self._combine_detection_results(ml_result, signature_matches, patterns)
            
            # Notify callbacks
            if final_result and final_result.confidence >= 0.3:
                for callback in self.classification_callbacks:
                    try:
                        callback(final_result)
                    except Exception as e:
                        self.logger.error(f"Callback error: {e}")
        
        except Exception as e:
            self.logger.error(f"Analysis error: {e}")
    
    def _combine_detection_results(self, ml_result: Optional[DetectionResult],
                                 signature_matches: List[Tuple[ProtectionSignature, float]],
                                 patterns: List[TemporalPattern]) -> Optional[DetectionResult]:
        """Combine ML and signature-based detection results."""
        # Start with ML result if available
        if ml_result and ml_result.confidence > 0.3:
            base_result = ml_result
        else:
            # Use signature-based result
            if signature_matches:
                best_signature, best_score = signature_matches[0]
                base_result = DetectionResult(
                    family=best_signature.family,
                    confidence=best_score,
                    evidence=patterns,
                    signature_matches=[best_signature.signature_name],
                    classification_features={},
                    analysis_metadata={'signature_based': True}
                )
            else:
                # No strong detection
                return None
        
        # Enhance with signature information
        if signature_matches:
            matching_signatures = [sig.signature_name for sig, score in signature_matches if score > 0.5]
            base_result.signature_matches.extend(matching_signatures)
            
            # Boost confidence if signatures agree with ML result
            if ml_result and signature_matches:
                for signature, score in signature_matches:
                    if signature.family == ml_result.family and score > 0.6:
                        base_result.confidence = min(0.95, base_result.confidence * 1.2)
                        break
        
        # Add real-time analysis metadata
        base_result.analysis_metadata.update({
            'real_time_analysis': True,
            'analysis_time': time.time(),
            'pattern_count': len(patterns),
            'signature_matches_count': len(signature_matches),
            'ml_available': ML_AVAILABLE
        })
        
        return base_result


class AdaptiveLearningSystem:
    """Adaptive learning system for improving detection accuracy."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.feedback_data = []
        self.learning_lock = threading.RLock()
        self.model_performance = defaultdict(list)
        
    def add_feedback(self, detection_result: DetectionResult, 
                    actual_family: ProtectionFamily, 
                    confidence_rating: float):
        """Add feedback for improving detection accuracy."""
        with self.learning_lock:
            feedback = {
                'timestamp': time.time(),
                'predicted_family': detection_result.family.value,
                'actual_family': actual_family.value,
                'predicted_confidence': detection_result.confidence,
                'user_confidence_rating': confidence_rating,
                'correct': detection_result.family == actual_family,
                'features': detection_result.classification_features
            }
            
            self.feedback_data.append(feedback)
            self.model_performance[detection_result.family].append(feedback)
            
            self.logger.info(f"Added feedback: {actual_family.value} "
                           f"({'correct' if feedback['correct'] else 'incorrect'})")
    
    def analyze_performance(self) -> Dict[str, Any]:
        """Analyze model performance from feedback data."""
        with self.learning_lock:
            if not self.feedback_data:
                return {'error': 'No feedback data available'}
            
            total_predictions = len(self.feedback_data)
            correct_predictions = sum(1 for f in self.feedback_data if f['correct'])
            accuracy = correct_predictions / total_predictions
            
            # Analyze by protection family
            family_performance = {}
            for family, feedback_list in self.model_performance.items():
                family_correct = sum(1 for f in feedback_list if f['correct'])
                family_total = len(feedback_list)
                family_accuracy = family_correct / family_total if family_total > 0 else 0
                
                family_performance[family.value] = {
                    'accuracy': family_accuracy,
                    'total_predictions': family_total,
                    'correct_predictions': family_correct
                }
            
            # Calculate confidence calibration
            confidence_bins = np.linspace(0, 1, 11)
            calibration_data = []
            
            for i in range(len(confidence_bins) - 1):
                bin_min, bin_max = confidence_bins[i], confidence_bins[i + 1]
                bin_feedback = [f for f in self.feedback_data 
                              if bin_min <= f['predicted_confidence'] < bin_max]
                
                if bin_feedback:
                    bin_accuracy = sum(1 for f in bin_feedback if f['correct']) / len(bin_feedback)
                    avg_confidence = np.mean([f['predicted_confidence'] for f in bin_feedback])
                    calibration_data.append({
                        'confidence_range': f"{bin_min:.1f}-{bin_max:.1f}",
                        'average_confidence': avg_confidence,
                        'actual_accuracy': bin_accuracy,
                        'sample_count': len(bin_feedback)
                    })
            
            return {
                'overall_accuracy': accuracy,
                'total_predictions': total_predictions,
                'correct_predictions': correct_predictions,
                'family_performance': family_performance,
                'confidence_calibration': calibration_data,
                'recent_accuracy': self._calculate_recent_accuracy()
            }
    
    def _calculate_recent_accuracy(self, hours: float = 24.0) -> float:
        """Calculate accuracy for recent predictions."""
        cutoff_time = time.time() - (hours * 3600)
        recent_feedback = [f for f in self.feedback_data if f['timestamp'] >= cutoff_time]
        
        if not recent_feedback:
            return 0.0
        
        correct = sum(1 for f in recent_feedback if f['correct'])
        return correct / len(recent_feedback)
    
    def suggest_improvements(self) -> List[str]:
        """Suggest improvements based on performance analysis."""
        suggestions = []
        performance = self.analyze_performance()
        
        if 'error' in performance:
            return ["Collect more feedback data to analyze performance"]
        
        # Overall accuracy suggestions
        if performance['overall_accuracy'] < 0.7:
            suggestions.append("Overall accuracy is low. Consider retraining models with more data.")
        
        # Family-specific suggestions
        for family, stats in performance['family_performance'].items():
            if stats['accuracy'] < 0.5 and stats['total_predictions'] >= 5:
                suggestions.append(f"Poor accuracy for {family}. Review signature patterns.")
        
        # Confidence calibration suggestions
        calibration = performance.get('confidence_calibration', [])
        overconfident_bins = [c for c in calibration 
                            if c['average_confidence'] - c['actual_accuracy'] > 0.2]
        
        if overconfident_bins:
            suggestions.append("Model appears overconfident. Consider confidence adjustment.")
        
        # Recent performance suggestions
        if performance['recent_accuracy'] < performance['overall_accuracy'] - 0.1:
            suggestions.append("Recent performance declined. Consider model retraining.")
        
        return suggestions if suggestions else ["Performance looks good. Continue monitoring."]


class BehaviorBasedProtectionDetector:
    """Main controller for behavior-based protection detection."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.logger = get_logger(__name__)
        self.config = config or self._get_default_config()
        
        # Initialize components
        self.data_collector = BehaviorDataCollector(
            max_events=self.config.get('max_events', 100000)
        )
        
        self.pattern_analyzer = TemporalPatternAnalyzer()
        self.ml_classifier = MLProtectionClassifier()
        self.signature_engine = BehavioralSignatureEngine(
            Path(self.config.get('signature_db_path', 'behavior_signatures.json'))
        )
        
        self.realtime_engine = RealTimeClassificationEngine(
            window_size=self.config.get('analysis_window', 30.0)
        )
        
        self.learning_system = AdaptiveLearningSystem()
        
        # Detection state
        self.is_analyzing = False
        self.analysis_results = {}
        self.detection_callbacks = []
        
        # Performance monitoring
        self.performance_stats = {
            'total_analyses': 0,
            'successful_detections': 0,
            'average_analysis_time': 0.0,
            'start_time': time.time()
        }
        
        self.logger.info("Initialized behavior-based protection detector")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            'max_events': 100000,
            'analysis_window': 30.0,
            'min_confidence': 0.3,
            'enable_realtime': True,
            'enable_ml': ML_AVAILABLE,
            'signature_db_path': 'behavior_signatures.json',
            'performance_monitoring': True,
            'adaptive_learning': True
        }
    
    def start_analysis(self, target_process: Optional[int] = None):
        """Start behavioral analysis and protection detection."""
        if self.is_analyzing:
            self.logger.warning("Analysis already running")
            return
        
        self.is_analyzing = True
        
        # Start data collection
        self._register_data_sources(target_process)
        self.data_collector.start_collection()
        
        # Start real-time processing if enabled
        if self.config.get('enable_realtime', True):
            self.realtime_engine.register_callback(self._on_detection_result)
            self.realtime_engine.start_processing()
        
        self.logger.info(f"Started behavior-based protection analysis"
                        f"{f' for process {target_process}' if target_process else ''}")
    
    def stop_analysis(self):
        """Stop behavioral analysis."""
        if not self.is_analyzing:
            return
        
        self.is_analyzing = False
        
        # Stop components
        self.data_collector.stop_collection()
        self.realtime_engine.stop_processing()
        
        self.logger.info("Stopped behavior-based protection analysis")
    
    def analyze_patterns(self, time_window: Optional[float] = None) -> List[DetectionResult]:
        """Perform comprehensive pattern analysis."""
        start_time = time.time()
        
        try:
            # Get behavioral events
            since_time = None
            if time_window:
                since_time = time.time() - time_window
            
            events = self.data_collector.get_events(since=since_time)
            
            if len(events) < 5:
                self.logger.warning("Insufficient behavioral data for analysis")
                return []
            
            # Analyze temporal patterns
            patterns = self.pattern_analyzer.analyze_patterns(events, time_window or 60.0)
            
            if not patterns:
                self.logger.info("No significant patterns detected")
                return []
            
            # Classify using multiple methods
            results = []
            
            # ML classification
            if self.config.get('enable_ml', True):
                ml_result = self.ml_classifier.classify_protection(patterns)
                if ml_result and ml_result.confidence >= self.config.get('min_confidence', 0.3):
                    results.append(ml_result)
            
            # Signature matching
            signature_matches = self.signature_engine.match_signatures(patterns)
            for signature, score in signature_matches:
                if score >= self.config.get('min_confidence', 0.3):
                    sig_result = DetectionResult(
                        family=signature.family,
                        confidence=score,
                        evidence=patterns,
                        signature_matches=[signature.signature_name],
                        classification_features={},
                        analysis_metadata={
                            'signature_based': True,
                            'signature_name': signature.signature_name
                        }
                    )
                    results.append(sig_result)
            
            # Update performance statistics
            analysis_time = time.time() - start_time
            self._update_performance_stats(analysis_time, len(results))
            
            # Store results
            self.analysis_results[time.time()] = {
                'patterns': patterns,
                'results': results,
                'analysis_time': analysis_time,
                'event_count': len(events)
            }
            
            self.logger.info(f"Analysis complete: {len(results)} detections in {analysis_time:.2f}s")
            return results
        
        except Exception as e:
            self.logger.error(f"Pattern analysis error: {e}")
            return []
    
    def get_protection_report(self) -> Dict[str, Any]:
        """Generate comprehensive protection detection report."""
        if not self.analysis_results:
            return {'error': 'No analysis results available'}
        
        # Aggregate results from all analyses
        all_results = []
        all_patterns = []
        
        for analysis_data in self.analysis_results.values():
            all_results.extend(analysis_data['results'])
            all_patterns.extend(analysis_data['patterns'])
        
        if not all_results:
            return {
                'summary': 'No protection mechanisms detected',
                'confidence': 0.0,
                'patterns_analyzed': len(all_patterns),
                'analysis_count': len(self.analysis_results)
            }
        
        # Analyze detection consensus
        family_votes = defaultdict(list)
        for result in all_results:
            family_votes[result.family].append(result.confidence)
        
        # Calculate consensus
        consensus_family = None
        consensus_confidence = 0.0
        
        for family, confidences in family_votes.items():
            avg_confidence = np.mean(confidences)
            if avg_confidence > consensus_confidence:
                consensus_confidence = avg_confidence
                consensus_family = family
        
        # Generate detailed report
        report = {
            'summary': {
                'detected_family': consensus_family.value if consensus_family else 'unknown',
                'confidence': consensus_confidence,
                'detection_count': len(all_results),
                'unique_families_detected': len(family_votes),
                'patterns_analyzed': len(all_patterns)
            },
            'family_analysis': {},
            'pattern_summary': self._summarize_patterns(all_patterns),
            'evidence_strength': self._calculate_evidence_strength(all_results),
            'recommendations': self._generate_recommendations(consensus_family, consensus_confidence),
            'performance_stats': self.performance_stats.copy(),
            'analysis_metadata': {
                'total_analyses': len(self.analysis_results),
                'ml_enabled': self.config.get('enable_ml', True),
                'realtime_enabled': self.config.get('enable_realtime', True),
                'report_generation_time': time.time()
            }
        }
        
        # Add family-specific analysis
        for family, confidences in family_votes.items():
            family_results = [r for r in all_results if r.family == family]
            
            report['family_analysis'][family.value] = {
                'detection_count': len(confidences),
                'average_confidence': np.mean(confidences),
                'max_confidence': max(confidences),
                'signature_matches': list(set(
                    match for result in family_results 
                    for match in result.signature_matches
                )),
                'evidence_patterns': len(set(
                    pattern.pattern_id for result in family_results
                    for pattern in result.evidence
                ))
            }
        
        return report
    
    def _register_data_sources(self, target_process: Optional[int] = None):
        """Register behavioral data sources."""
        # Register API tracing source
        def get_api_events():
            # This would interface with the existing API tracing system
            # For now, return empty list - this would be implemented based on
            # the existing API tracing infrastructure
            return []
        
        self.data_collector.register_source("api_tracer", get_api_events)
        
        # Register memory monitoring source
        def get_memory_events():
            # Interface with memory analysis components
            return []
        
        self.data_collector.register_source("memory_monitor", get_memory_events)
        
        # Register network monitoring source
        def get_network_events():
            # Interface with network monitoring components
            return []
        
        self.data_collector.register_source("network_monitor", get_network_events)
        
        # Register file system monitoring source
        def get_file_events():
            # Interface with file system monitoring
            return []
        
        self.data_collector.register_source("file_monitor", get_file_events)
    
    def _on_detection_result(self, result: DetectionResult):
        """Handle real-time detection results."""
        self.logger.info(f"Real-time detection: {result.family.value} "
                        f"(confidence: {result.confidence:.2f})")
        
        # Notify registered callbacks
        for callback in self.detection_callbacks:
            try:
                callback(result)
            except Exception as e:
                self.logger.error(f"Detection callback error: {e}")
    
    def register_detection_callback(self, callback: Callable[[DetectionResult], None]):
        """Register callback for detection notifications."""
        self.detection_callbacks.append(callback)
    
    def _update_performance_stats(self, analysis_time: float, detection_count: int):
        """Update performance statistics."""
        self.performance_stats['total_analyses'] += 1
        
        if detection_count > 0:
            self.performance_stats['successful_detections'] += 1
        
        # Update average analysis time
        current_avg = self.performance_stats['average_analysis_time']
        total_analyses = self.performance_stats['total_analyses']
        
        new_avg = ((current_avg * (total_analyses - 1)) + analysis_time) / total_analyses
        self.performance_stats['average_analysis_time'] = new_avg
    
    def _summarize_patterns(self, patterns: List[TemporalPattern]) -> Dict[str, Any]:
        """Summarize behavioral patterns."""
        if not patterns:
            return {}
        
        pattern_types = defaultdict(int)
        frequencies = []
        periodicities = []
        
        for pattern in patterns:
            pattern_types[pattern.behavior_type.value] += 1
            if pattern.frequency > 0:
                frequencies.append(pattern.frequency)
            if pattern.periodicity is not None:
                periodicities.append(pattern.periodicity)
        
        summary = {
            'total_patterns': len(patterns),
            'pattern_types': dict(pattern_types),
            'frequency_stats': {
                'mean': np.mean(frequencies) if frequencies else 0,
                'max': max(frequencies) if frequencies else 0,
                'min': min(frequencies) if frequencies else 0
            },
            'periodicity_stats': {
                'periodic_patterns': len(periodicities),
                'mean_period': np.mean(periodicities) if periodicities else 0
            }
        }
        
        return summary
    
    def _calculate_evidence_strength(self, results: List[DetectionResult]) -> Dict[str, Any]:
        """Calculate overall evidence strength."""
        if not results:
            return {'strength': 'none', 'score': 0.0}
        
        # Calculate evidence metrics
        max_confidence = max(r.confidence for r in results)
        avg_confidence = np.mean([r.confidence for r in results])
        evidence_count = sum(len(r.evidence) for r in results)
        signature_matches = sum(len(r.signature_matches) for r in results)
        
        # Calculate composite score
        confidence_score = (max_confidence * 0.6) + (avg_confidence * 0.4)
        evidence_score = min(1.0, evidence_count / 20.0)  # Normalize to 1.0
        signature_score = min(1.0, signature_matches / 5.0)  # Normalize to 1.0
        
        composite_score = (confidence_score * 0.5) + (evidence_score * 0.3) + (signature_score * 0.2)
        
        # Determine strength category
        if composite_score >= 0.8:
            strength = 'very_strong'
        elif composite_score >= 0.6:
            strength = 'strong'
        elif composite_score >= 0.4:
            strength = 'moderate'
        elif composite_score >= 0.2:
            strength = 'weak'
        else:
            strength = 'very_weak'
        
        return {
            'strength': strength,
            'score': composite_score,
            'max_confidence': max_confidence,
            'average_confidence': avg_confidence,
            'evidence_patterns': evidence_count,
            'signature_matches': signature_matches
        }
    
    def _generate_recommendations(self, family: Optional[ProtectionFamily], 
                                confidence: float) -> List[Dict[str, str]]:
        """Generate analysis and bypass recommendations."""
        recommendations = []
        
        if family is None or confidence < 0.3:
            recommendations.append({
                'type': 'analysis',
                'priority': 'medium',
                'title': 'Inconclusive Detection',
                'description': 'Protection detection was inconclusive. Consider longer analysis period.',
                'actions': [
                    'Extend behavioral monitoring duration',
                    'Increase behavioral data collection scope',
                    'Use complementary static analysis methods'
                ]
            })
            return recommendations
        
        # Family-specific recommendations
        if family == ProtectionFamily.DENUVO:
            recommendations.extend([
                {
                    'type': 'analysis',
                    'priority': 'high',
                    'title': 'Denuvo Anti-Tamper Detected',
                    'description': 'Advanced anti-tamper protection requiring specialized approach.',
                    'actions': [
                        'Focus on license validation bypass',
                        'Analyze performance impact patterns',
                        'Consider VM-based analysis for safety'
                    ]
                }
            ])
        
        elif family == ProtectionFamily.VMPROTECT:
            recommendations.extend([
                {
                    'type': 'analysis',
                    'priority': 'high',
                    'title': 'VMProtect Virtualization Detected',
                    'description': 'Code virtualization protection detected.',
                    'actions': [
                        'Use devirtualization tools',
                        'Focus on VM handler analysis',
                        'Consider dynamic analysis approaches'
                    ]
                }
            ])
        
        elif family == ProtectionFamily.ONLINE_ACTIVATION:
            recommendations.extend([
                {
                    'type': 'bypass',
                    'priority': 'medium',
                    'title': 'Online Activation System',
                    'description': 'Network-based license validation detected.',
                    'actions': [
                        'Analyze network traffic patterns',
                        'Identify license validation endpoints',
                        'Consider offline activation bypass'
                    ]
                }
            ])
        
        # Confidence-based recommendations
        if confidence >= 0.8:
            recommendations.append({
                'type': 'confidence',
                'priority': 'low',
                'title': 'High Confidence Detection',
                'description': 'Protection family identified with high confidence.',
                'actions': [
                    'Proceed with family-specific analysis',
                    'Apply targeted bypass strategies',
                    'Monitor for protection updates'
                ]
            })
        elif confidence < 0.5:
            recommendations.append({
                'type': 'confidence',
                'priority': 'medium',
                'title': 'Low Confidence Detection',
                'description': 'Protection detection confidence is low.',
                'actions': [
                    'Collect additional behavioral data',
                    'Cross-validate with static analysis',
                    'Consider manual verification'
                ]
            })
        
        return recommendations
    
    def add_training_data(self, patterns: List[TemporalPattern], 
                         family: ProtectionFamily):
        """Add training data for improving detection accuracy."""
        if not ML_AVAILABLE:
            self.logger.warning("ML not available for training")
            return
        
        # Create signature from patterns
        signature_name = f"{family.value}_observed_{int(time.time())}"
        signature = self.signature_engine.create_signature_from_patterns(
            family, signature_name, patterns
        )
        
        self.logger.info(f"Added training signature for {family.value}")
    
    def export_analysis_data(self, export_path: Path) -> bool:
        """Export analysis data for external processing."""
        try:
            export_data = {
                'analysis_results': self.analysis_results,
                'performance_stats': self.performance_stats,
                'config': self.config,
                'export_time': time.time(),
                'signatures_count': sum(len(sigs) for sigs in self.signature_engine.signatures.values())
            }
            
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Exported analysis data to {export_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            return False
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        return {
            'is_analyzing': self.is_analyzing,
            'components': {
                'data_collector': {
                    'is_collecting': self.data_collector.is_collecting,
                    'event_count': len(self.data_collector.events),
                    'sources_registered': len(self.data_collector.event_sources)
                },
                'realtime_engine': {
                    'is_running': self.realtime_engine.is_running,
                    'buffer_size': len(self.realtime_engine.event_buffer),
                    'callbacks_registered': len(self.realtime_engine.classification_callbacks)
                },
                'ml_classifier': {
                    'available': ML_AVAILABLE,
                    'is_trained': self.ml_classifier.is_trained if ML_AVAILABLE else False
                },
                'signature_engine': {
                    'signatures_loaded': sum(len(sigs) for sigs in self.signature_engine.signatures.values()),
                    'families_covered': len(self.signature_engine.signatures)
                }
            },
            'performance': self.performance_stats,
            'config': self.config,
            'dependencies': {
                'ml_available': ML_AVAILABLE,
                'scipy_available': SCIPY_AVAILABLE,
                'psutil_available': PSUTIL_AVAILABLE
            }
        }