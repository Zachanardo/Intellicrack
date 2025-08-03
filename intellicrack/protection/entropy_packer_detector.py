"""
Sophisticated Entropy-Based Packer Detection System

A comprehensive entropy analysis framework for detecting packed and compressed executables
with advanced multi-scale analysis, machine learning classification, and packer-specific
detection signatures. This system significantly enhances detection accuracy while minimizing
false positives through intelligent feature extraction and pattern recognition.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import math
import os
import struct
import threading
import time
import zlib
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from ..utils.logger import get_logger
from .intellicrack_protection_core import DetectionResult, ProtectionType

logger = get_logger(__name__)


class PackerFamily(Enum):
    """Known packer families with specific detection signatures"""
    UPX = "upx"
    ASPACK = "aspack"
    PECOMPACT = "pecompact"
    MPRESS = "mpress"
    NSPACK = "nspack"
    PETITE = "petite"
    KKRUNCHY = "kkrunchy"
    THEMIDA = "themida"
    VMPROTECT = "vmprotect"
    ENIGMA = "enigma"
    EXECRYPTOR = "execryptor"
    ARMADILLO = "armadillo"
    GENERIC = "generic"
    UNKNOWN = "unknown"


class EntropyAnalysisMode(Enum):
    """Different entropy analysis modes for various use cases"""
    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"
    REALTIME = "realtime"


@dataclass
class MultiScaleEntropyMetrics:
    """Advanced entropy metrics across multiple scales and dimensions"""
    # Basic entropy measurements
    shannon_entropy: float
    renyi_entropy: float
    kolmogorov_complexity_estimate: float
    
    # Multi-scale measurements
    byte_level_entropy: float
    word_level_entropy: float
    dword_level_entropy: float
    block_level_entropy: List[float]
    
    # Sliding window analysis
    window_entropies: List[float]
    entropy_variance: float
    entropy_skewness: float
    entropy_kurtosis: float
    
    # Section-based analysis
    section_entropies: Dict[str, float]
    high_entropy_sections: List[str]
    entropy_distribution: Dict[str, float]
    
    # Compression metrics
    compression_ratio: float
    compression_efficiency: float
    decompression_complexity: float
    
    # Pattern analysis
    repetitive_patterns: int
    entropy_transitions: List[Tuple[int, float]]
    anomalous_regions: List[Tuple[int, int, float]]
    
    # Statistical measures
    entropy_mean: float
    entropy_std: float
    entropy_range: float
    autocorrelation: float


@dataclass
class PackerSignature:
    """Entropy-based signature for specific packer identification"""
    family: PackerFamily
    entropy_range: Tuple[float, float]
    compression_range: Tuple[float, float]
    section_patterns: List[str]
    entropy_distribution: Dict[str, float]
    statistical_features: Dict[str, float]
    confidence_threshold: float
    detection_patterns: List[bytes]


@dataclass
class MLFeatureVector:
    """Machine learning feature vector for packer classification"""
    # Entropy features (20 features)
    overall_entropy: float
    entropy_variance: float
    entropy_skewness: float
    entropy_kurtosis: float
    max_entropy: float
    min_entropy: float
    entropy_range: float
    high_entropy_ratio: float
    entropy_transitions: int
    local_maxima: int
    local_minima: int
    entropy_gradient_mean: float
    entropy_gradient_std: float
    byte_entropy: float
    word_entropy: float
    dword_entropy: float
    block_entropy_mean: float
    block_entropy_std: float
    sliding_window_mean: float
    sliding_window_std: float
    
    # Compression features (10 features)
    compression_ratio: float
    compression_efficiency: float
    zlib_ratio: float
    bz2_ratio: float
    lzma_ratio: float
    decompression_time: float
    compression_variance: float
    best_compression: float
    worst_compression: float
    compression_stability: float
    
    # Structural features (15 features)
    file_size: float
    section_count: int
    executable_sections: int
    writable_sections: int
    import_count: int
    export_count: int
    resource_count: int
    overlay_size: float
    entry_point_section: int
    code_to_data_ratio: float
    section_size_variance: float
    section_entropy_correlation: float
    import_entropy: float
    string_entropy: float
    metadata_entropy: float
    
    # Pattern features (10 features)
    repetitive_bytes: int
    pattern_density: float
    instruction_density: float
    null_byte_ratio: float
    ascii_ratio: float
    unicode_ratio: float
    control_char_ratio: float
    printable_ratio: float
    binary_patterns: int
    obfuscation_indicators: int


@dataclass
class EntropyDetectionResult:
    """Comprehensive entropy-based detection result"""
    file_path: str
    analysis_mode: EntropyAnalysisMode
    metrics: MultiScaleEntropyMetrics
    ml_features: MLFeatureVector
    
    # Detection results
    is_packed: bool
    packer_family: PackerFamily
    confidence_score: float
    false_positive_probability: float
    
    # Detailed analysis
    entropy_visualizations: Dict[str, List[float]]
    anomalous_regions: List[Tuple[int, int, str]]
    unpacking_recommendations: List[str]
    
    # Performance metrics
    analysis_time: float
    memory_usage: int
    cache_hits: int
    
    # Integration data
    bypass_strategies: List[str]
    tool_recommendations: List[str]
    confidence_breakdown: Dict[str, float]


class AdvancedEntropyCalculator:
    """High-performance entropy calculation with multiple algorithms"""
    
    def __init__(self):
        self.cache = {}
        self.cache_lock = threading.Lock()
        self.max_cache_size = 1000
        
    def calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy with caching"""
        if not data:
            return 0.0
            
        # Generate cache key
        cache_key = hashlib.md5(data).hexdigest()
        
        with self.cache_lock:
            if cache_key in self.cache:
                return self.cache[cache_key]
        
        # Calculate entropy
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)
        
        # Remove zero probabilities to avoid log(0)
        probabilities = probabilities[probabilities > 0]
        
        # Calculate Shannon entropy
        entropy = -np.sum(probabilities * np.log2(probabilities))
        
        # Cache result
        with self.cache_lock:
            if len(self.cache) >= self.max_cache_size:
                # Remove oldest entry (simple LRU approximation)
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
            self.cache[cache_key] = entropy
            
        return entropy
    
    def calculate_renyi_entropy(self, data: bytes, alpha: float = 2.0) -> float:
        """Calculate Rényi entropy for more nuanced analysis"""
        if not data or alpha == 1.0:
            return self.calculate_shannon_entropy(data)
            
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)
        probabilities = probabilities[probabilities > 0]
        
        if alpha == float('inf'):
            # Max entropy (min probability)
            return -np.log2(np.max(probabilities))
        else:
            # General Rényi entropy
            return (1 / (1 - alpha)) * np.log2(np.sum(probabilities ** alpha))
    
    def estimate_kolmogorov_complexity(self, data: bytes) -> float:
        """Estimate Kolmogorov complexity using compression"""
        if not data:
            return 0.0
            
        # Use multiple compression algorithms for better estimation
        compressed_sizes = []
        
        try:
            compressed_sizes.append(len(zlib.compress(data, 9)))
        except Exception:
            pass
            
        try:
            import bz2
            compressed_sizes.append(len(bz2.compress(data, 9)))
        except Exception:
            pass
            
        try:
            import lzma
            compressed_sizes.append(len(lzma.compress(data, preset=9)))
        except Exception:
            pass
        
        if not compressed_sizes:
            return len(data)  # Fallback to original size
            
        # Use the best compression as complexity estimate
        best_compression = min(compressed_sizes)
        return best_compression / len(data)
    
    def calculate_multi_scale_entropy(self, data: bytes) -> Dict[str, float]:
        """Calculate entropy at multiple scales"""
        results = {}
        
        # Byte-level entropy
        results['byte'] = self.calculate_shannon_entropy(data)
        
        # Word-level entropy (16-bit)
        if len(data) >= 2:
            words = np.frombuffer(data[:len(data)//2*2], dtype=np.uint16)
            word_data = words.tobytes()
            results['word'] = self.calculate_shannon_entropy(word_data)
        else:
            results['word'] = 0.0
            
        # DWORD-level entropy (32-bit)
        if len(data) >= 4:
            dwords = np.frombuffer(data[:len(data)//4*4], dtype=np.uint32)
            dword_data = dwords.tobytes()
            results['dword'] = self.calculate_shannon_entropy(dword_data)
        else:
            results['dword'] = 0.0
            
        # Block-level entropy (fixed-size blocks)
        block_size = 1024
        block_entropies = []
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            if len(block) >= 64:  # Minimum block size for meaningful entropy
                block_entropies.append(self.calculate_shannon_entropy(block))
        
        results['block_mean'] = np.mean(block_entropies) if block_entropies else 0.0
        results['block_std'] = np.std(block_entropies) if block_entropies else 0.0
        
        return results
    
    def sliding_window_entropy(self, data: bytes, window_size: int = 1024, 
                             step_size: Optional[int] = None) -> List[float]:
        """Calculate entropy using sliding window for local analysis"""
        if step_size is None:
            step_size = window_size // 4
            
        entropies = []
        
        for i in range(0, len(data) - window_size + 1, step_size):
            window = data[i:i + window_size]
            entropy = self.calculate_shannon_entropy(window)
            entropies.append(entropy)
            
        return entropies


class PackerSignatureDatabase:
    """Database of entropy signatures for specific packer families"""
    
    def __init__(self):
        self.signatures = self._initialize_signatures()
        
    def _initialize_signatures(self) -> Dict[PackerFamily, PackerSignature]:
        """Initialize known packer signatures"""
        signatures = {}
        
        # UPX Signature
        signatures[PackerFamily.UPX] = PackerSignature(
            family=PackerFamily.UPX,
            entropy_range=(7.2, 7.9),
            compression_range=(0.2, 0.6),
            section_patterns=['UPX0', 'UPX1', '.UPX'],
            entropy_distribution={'high': 0.8, 'medium': 0.15, 'low': 0.05},
            statistical_features={
                'entropy_variance': 0.3,
                'compression_efficiency': 0.4,
                'transition_count': 2
            },
            confidence_threshold=0.85,
            detection_patterns=[b'UPX!', b'$Info: This file is packed with the UPX']
        )
        
        # ASPack Signature
        signatures[PackerFamily.ASPACK] = PackerSignature(
            family=PackerFamily.ASPACK,
            entropy_range=(7.0, 7.8),
            compression_range=(0.25, 0.65),
            section_patterns=['.aspack', '.adata'],
            entropy_distribution={'high': 0.75, 'medium': 0.2, 'low': 0.05},
            statistical_features={
                'entropy_variance': 0.4,
                'compression_efficiency': 0.35,
                'transition_count': 3
            },
            confidence_threshold=0.80,
            detection_patterns=[b'ASPack', b'aPLib']
        )
        
        # PECompact Signature
        signatures[PackerFamily.PECOMPACT] = PackerSignature(
            family=PackerFamily.PECOMPACT,
            entropy_range=(6.8, 7.7),
            compression_range=(0.3, 0.7),
            section_patterns=['.pecmp', 'PEC2'],
            entropy_distribution={'high': 0.7, 'medium': 0.25, 'low': 0.05},
            statistical_features={
                'entropy_variance': 0.35,
                'compression_efficiency': 0.3,
                'transition_count': 2
            },
            confidence_threshold=0.75,
            detection_patterns=[b'PECompact', b'PEC2']
        )
        
        # Themida/WinLicense Signature
        signatures[PackerFamily.THEMIDA] = PackerSignature(
            family=PackerFamily.THEMIDA,
            entropy_range=(7.5, 8.0),
            compression_range=(0.15, 0.45),
            section_patterns=['.Themida', '.WinLice'],
            entropy_distribution={'high': 0.9, 'medium': 0.08, 'low': 0.02},
            statistical_features={
                'entropy_variance': 0.2,
                'compression_efficiency': 0.6,
                'transition_count': 5
            },
            confidence_threshold=0.90,
            detection_patterns=[b'Themida', b'WinLicense', b'Oreans Technologies']
        )
        
        # VMProtect Signature
        signatures[PackerFamily.VMPROTECT] = PackerSignature(
            family=PackerFamily.VMPROTECT,
            entropy_range=(7.6, 8.0),
            compression_range=(0.1, 0.4),
            section_patterns=['.vmp', '.text'],
            entropy_distribution={'high': 0.95, 'medium': 0.04, 'low': 0.01},
            statistical_features={
                'entropy_variance': 0.15,
                'compression_efficiency': 0.7,
                'transition_count': 8
            },
            confidence_threshold=0.95,
            detection_patterns=[b'VMProtect', b'BoringSSL']
        )
        
        return signatures
    
    def match_signature(self, metrics: MultiScaleEntropyMetrics, 
                       data: bytes) -> Tuple[PackerFamily, float]:
        """Match entropy metrics against known signatures"""
        best_match = PackerFamily.UNKNOWN
        best_confidence = 0.0
        
        for family, signature in self.signatures.items():
            confidence = self._calculate_signature_confidence(metrics, data, signature)
            
            if confidence > signature.confidence_threshold and confidence > best_confidence:
                best_match = family
                best_confidence = confidence
                
        return best_match, best_confidence
    
    def _calculate_signature_confidence(self, metrics: MultiScaleEntropyMetrics,
                                      data: bytes, signature: PackerSignature) -> float:
        """Calculate confidence score for a specific signature"""
        score = 0.0
        
        # Entropy range check
        if signature.entropy_range[0] <= metrics.shannon_entropy <= signature.entropy_range[1]:
            score += 25.0
            
        # Compression range check
        if signature.compression_range[0] <= metrics.compression_ratio <= signature.compression_range[1]:
            score += 20.0
            
        # Pattern detection
        pattern_matches = sum(1 for pattern in signature.detection_patterns if pattern in data)
        score += min(pattern_matches * 15.0, 30.0)
        
        # Statistical features
        if abs(metrics.entropy_variance - signature.statistical_features.get('entropy_variance', 0)) < 0.1:
            score += 10.0
            
        if abs(metrics.compression_efficiency - signature.statistical_features.get('compression_efficiency', 0)) < 0.1:
            score += 10.0
            
        # Entropy distribution analysis
        high_entropy_ratio = len(metrics.high_entropy_sections) / max(len(metrics.section_entropies), 1)
        expected_high_ratio = signature.entropy_distribution.get('high', 0.5)
        
        if abs(high_entropy_ratio - expected_high_ratio) < 0.2:
            score += 15.0
            
        return min(score, 100.0)


class MLPackerClassifier:
    """Machine learning-based packer classification system"""
    
    def __init__(self):
        self.classifier = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_importance = {}
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        
    def extract_features(self, metrics: MultiScaleEntropyMetrics, 
                        file_path: str, data: bytes) -> MLFeatureVector:
        """Extract comprehensive feature vector for ML classification"""
        
        # Calculate additional metrics needed for features
        sliding_entropies = metrics.window_entropies
        compression_ratios = self._calculate_compression_ratios(data)
        structural_features = self._analyze_file_structure(file_path, data)
        pattern_features = self._analyze_patterns(data)
        
        return MLFeatureVector(
            # Entropy features
            overall_entropy=metrics.shannon_entropy,
            entropy_variance=metrics.entropy_variance,
            entropy_skewness=metrics.entropy_skewness,
            entropy_kurtosis=metrics.entropy_kurtosis,
            max_entropy=max(sliding_entropies) if sliding_entropies else 0.0,
            min_entropy=min(sliding_entropies) if sliding_entropies else 0.0,
            entropy_range=max(sliding_entropies) - min(sliding_entropies) if sliding_entropies else 0.0,
            high_entropy_ratio=len(metrics.high_entropy_sections) / max(len(metrics.section_entropies), 1),
            entropy_transitions=len(metrics.entropy_transitions),
            local_maxima=self._count_local_extrema(sliding_entropies, 'max'),
            local_minima=self._count_local_extrema(sliding_entropies, 'min'),
            entropy_gradient_mean=np.mean(np.gradient(sliding_entropies)) if sliding_entropies else 0.0,
            entropy_gradient_std=np.std(np.gradient(sliding_entropies)) if sliding_entropies else 0.0,
            byte_entropy=metrics.byte_level_entropy,
            word_entropy=metrics.word_level_entropy,
            dword_entropy=metrics.dword_level_entropy,
            block_entropy_mean=np.mean(metrics.block_level_entropy) if metrics.block_level_entropy else 0.0,
            block_entropy_std=np.std(metrics.block_level_entropy) if metrics.block_level_entropy else 0.0,
            sliding_window_mean=metrics.entropy_mean,
            sliding_window_std=metrics.entropy_std,
            
            # Compression features
            compression_ratio=metrics.compression_ratio,
            compression_efficiency=metrics.compression_efficiency,
            zlib_ratio=compression_ratios.get('zlib', 1.0),
            bz2_ratio=compression_ratios.get('bz2', 1.0),
            lzma_ratio=compression_ratios.get('lzma', 1.0),
            decompression_time=metrics.decompression_complexity,
            compression_variance=np.var(list(compression_ratios.values())),
            best_compression=min(compression_ratios.values()),
            worst_compression=max(compression_ratios.values()),
            compression_stability=np.std(list(compression_ratios.values())),
            
            # Structural features
            file_size=float(len(data)),
            section_count=len(metrics.section_entropies),
            executable_sections=structural_features.get('executable_sections', 0),
            writable_sections=structural_features.get('writable_sections', 0),
            import_count=structural_features.get('import_count', 0),
            export_count=structural_features.get('export_count', 0),
            resource_count=structural_features.get('resource_count', 0),
            overlay_size=float(structural_features.get('overlay_size', 0)),
            entry_point_section=structural_features.get('entry_point_section', 0),
            code_to_data_ratio=structural_features.get('code_to_data_ratio', 0.0),
            section_size_variance=structural_features.get('section_size_variance', 0.0),
            section_entropy_correlation=self._calculate_section_entropy_correlation(metrics),
            import_entropy=structural_features.get('import_entropy', 0.0),
            string_entropy=structural_features.get('string_entropy', 0.0),
            metadata_entropy=structural_features.get('metadata_entropy', 0.0),
            
            # Pattern features
            repetitive_bytes=metrics.repetitive_patterns,
            pattern_density=pattern_features.get('pattern_density', 0.0),
            instruction_density=pattern_features.get('instruction_density', 0.0),
            null_byte_ratio=pattern_features.get('null_byte_ratio', 0.0),
            ascii_ratio=pattern_features.get('ascii_ratio', 0.0),
            unicode_ratio=pattern_features.get('unicode_ratio', 0.0),
            control_char_ratio=pattern_features.get('control_char_ratio', 0.0),
            printable_ratio=pattern_features.get('printable_ratio', 0.0),
            binary_patterns=pattern_features.get('binary_patterns', 0),
            obfuscation_indicators=pattern_features.get('obfuscation_indicators', 0)
        )
    
    def _calculate_compression_ratios(self, data: bytes) -> Dict[str, float]:
        """Calculate compression ratios using multiple algorithms"""
        ratios = {}
        
        try:
            ratios['zlib'] = len(zlib.compress(data, 9)) / len(data)
        except Exception:
            ratios['zlib'] = 1.0
            
        try:
            import bz2
            ratios['bz2'] = len(bz2.compress(data, 9)) / len(data)
        except Exception:
            ratios['bz2'] = 1.0
            
        try:
            import lzma
            ratios['lzma'] = len(lzma.compress(data, preset=9)) / len(data)
        except Exception:
            ratios['lzma'] = 1.0
            
        return ratios
    
    def _analyze_file_structure(self, file_path: str, data: bytes) -> Dict[str, Any]:
        """Analyze file structure for feature extraction"""
        features = {
            'executable_sections': 0,
            'writable_sections': 0,
            'import_count': 0,
            'export_count': 0,
            'resource_count': 0,
            'overlay_size': 0,
            'entry_point_section': 0,
            'code_to_data_ratio': 0.0,
            'section_size_variance': 0.0,
            'import_entropy': 0.0,
            'string_entropy': 0.0,
            'metadata_entropy': 0.0
        }
        
        # Basic PE analysis (simplified)
        if len(data) > 64 and data.startswith(b'MZ'):
            try:
                # Get basic PE info
                pe_offset = struct.unpack('<L', data[60:64])[0]
                if pe_offset + 248 <= len(data):
                    num_sections = struct.unpack('<H', data[pe_offset + 6:pe_offset + 8])[0]
                    features['executable_sections'] = min(num_sections, 20)  # Cap for feature stability
                    
                    # Estimate imports (simplified)
                    features['import_count'] = min(data.count(b'dll') + data.count(b'DLL'), 100)
                    
                    # Calculate string entropy
                    strings = self._extract_strings(data)
                    if strings:
                        string_data = ' '.join(strings).encode('ascii', errors='ignore')
                        if string_data:
                            from ..protection.entropy_packer_detector import AdvancedEntropyCalculator
                            calc = AdvancedEntropyCalculator()
                            features['string_entropy'] = calc.calculate_shannon_entropy(string_data)
                            
            except Exception as e:
                logger.debug(f"PE analysis failed: {e}")
                
        return features
    
    def _analyze_patterns(self, data: bytes) -> Dict[str, Any]:
        """Analyze byte patterns for feature extraction"""
        features = {}
        
        # Calculate various ratios
        total_bytes = len(data)
        if total_bytes == 0:
            return {key: 0.0 for key in ['pattern_density', 'instruction_density', 'null_byte_ratio',
                                        'ascii_ratio', 'unicode_ratio', 'control_char_ratio', 
                                        'printable_ratio', 'binary_patterns', 'obfuscation_indicators']}
        
        # Null byte ratio
        features['null_byte_ratio'] = data.count(0) / total_bytes
        
        # ASCII printable ratio
        ascii_count = sum(1 for b in data if 32 <= b <= 126)
        features['ascii_ratio'] = ascii_count / total_bytes
        
        # Control character ratio
        control_count = sum(1 for b in data if b < 32 or b == 127)
        features['control_char_ratio'] = control_count / total_bytes
        
        # Printable ratio (ASCII printable + common extended)
        printable_count = sum(1 for b in data if 32 <= b <= 126 or b in [9, 10, 13])
        features['printable_ratio'] = printable_count / total_bytes
        
        # Pattern density (repetitive byte sequences)
        pattern_count = 0
        for i in range(min(len(data) - 3, 10000)):  # Limit for performance
            if i + 4 < len(data) and data[i:i+2] == data[i+2:i+4]:
                pattern_count += 1
        features['pattern_density'] = pattern_count / min(total_bytes, 10000)
        
        # Instruction density (x86 instruction patterns)
        instruction_patterns = [b'\x55', b'\x8b\xec', b'\x83\xec', b'\x68', b'\xe8', b'\xc3']
        instruction_count = sum(data.count(pattern) for pattern in instruction_patterns)
        features['instruction_density'] = instruction_count / total_bytes
        
        # Unicode ratio (simplified detection)
        unicode_patterns = [b'\x00\x00', b'\xff\xfe', b'\xfe\xff']
        unicode_count = sum(data.count(pattern) for pattern in unicode_patterns)
        features['unicode_ratio'] = unicode_count / max(total_bytes // 2, 1)
        
        # Binary patterns (common binary signatures)
        binary_patterns = [b'MZ', b'PE\x00\x00', b'\x7fELF', b'PK\x03\x04']
        features['binary_patterns'] = sum(1 for pattern in binary_patterns if pattern in data)
        
        # Obfuscation indicators
        obfuscation_patterns = [b'\x90\x90\x90', b'\xeb\x01', b'\x50\x58']  # NOPs, jumps, push/pop
        features['obfuscation_indicators'] = sum(data.count(pattern) for pattern in obfuscation_patterns)
        
        return features
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract ASCII strings from binary data"""
        strings = []
        current_string = []
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
                current_string = []
                
        # Check final string
        if len(current_string) >= min_length:
            strings.append(''.join(current_string))
            
        return strings[:100]  # Limit for performance
    
    def _count_local_extrema(self, values: List[float], extrema_type: str) -> int:
        """Count local maxima or minima in a series"""
        if len(values) < 3:
            return 0
            
        count = 0
        for i in range(1, len(values) - 1):
            if extrema_type == 'max':
                if values[i] > values[i-1] and values[i] > values[i+1]:
                    count += 1
            else:  # min
                if values[i] < values[i-1] and values[i] < values[i+1]:
                    count += 1
                    
        return count
    
    def _calculate_section_entropy_correlation(self, metrics: MultiScaleEntropyMetrics) -> float:
        """Calculate correlation between section sizes and entropies"""
        if len(metrics.section_entropies) < 2:
            return 0.0
            
        try:
            entropies = list(metrics.section_entropies.values())
            # Use indices as proxy for section sizes (simplified)
            sizes = list(range(len(entropies)))
            
            correlation = np.corrcoef(sizes, entropies)[0, 1]
            return correlation if not np.isnan(correlation) else 0.0
        except Exception:
            return 0.0
    
    def train_classifier(self, training_data: List[Tuple[MLFeatureVector, PackerFamily]]):
        """Train the ML classifier on labeled data"""
        if len(training_data) < 10:
            logger.warning("Insufficient training data for ML classifier")
            return False
            
        # Prepare training data
        X = []
        y = []
        
        for features, label in training_data:
            feature_array = self._feature_vector_to_array(features)
            X.append(feature_array)
            y.append(label.value)
            
        X = np.array(X)
        y = np.array(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train classifier
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42
        )
        
        self.classifier.fit(X_train_scaled, y_train)
        
        # Train anomaly detector
        self.anomaly_detector.fit(X_train_scaled)
        
        # Evaluate
        y_pred = self.classifier.predict(X_test_scaled)
        
        logger.info("Classifier training completed")
        logger.info(f"Classification Report:\n{classification_report(y_test, y_pred)}")
        
        # Store feature importance
        feature_names = self._get_feature_names()
        self.feature_importance = dict(zip(feature_names, self.classifier.feature_importances_))
        
        self.is_trained = True
        return True
    
    def classify_packer(self, features: MLFeatureVector) -> Tuple[PackerFamily, float, float]:
        """Classify packer family using trained ML model"""
        if not self.is_trained:
            return PackerFamily.UNKNOWN, 0.0, 1.0
            
        # Convert features to array
        feature_array = self._feature_vector_to_array(features).reshape(1, -1)
        
        # Scale features
        feature_scaled = self.scaler.transform(feature_array)
        
        # Predict
        prediction = self.classifier.predict(feature_scaled)[0]
        probabilities = self.classifier.predict_proba(feature_scaled)[0]
        confidence = max(probabilities)
        
        # Check for anomalies (potential false positives)
        anomaly_score = self.anomaly_detector.decision_function(feature_scaled)[0]
        # Convert anomaly score to probability (higher score = less anomalous)
        false_positive_prob = max(0.0, min(1.0, (0.5 - anomaly_score) / 0.5))
        
        try:
            packer_family = PackerFamily(prediction)
        except ValueError:
            packer_family = PackerFamily.UNKNOWN
            
        return packer_family, confidence, false_positive_prob
    
    def _feature_vector_to_array(self, features: MLFeatureVector) -> np.ndarray:
        """Convert feature vector to numpy array"""
        return np.array([
            # Entropy features
            features.overall_entropy, features.entropy_variance, features.entropy_skewness,
            features.entropy_kurtosis, features.max_entropy, features.min_entropy,
            features.entropy_range, features.high_entropy_ratio, features.entropy_transitions,
            features.local_maxima, features.local_minima, features.entropy_gradient_mean,
            features.entropy_gradient_std, features.byte_entropy, features.word_entropy,
            features.dword_entropy, features.block_entropy_mean, features.block_entropy_std,
            features.sliding_window_mean, features.sliding_window_std,
            
            # Compression features
            features.compression_ratio, features.compression_efficiency, features.zlib_ratio,
            features.bz2_ratio, features.lzma_ratio, features.decompression_time,
            features.compression_variance, features.best_compression, features.worst_compression,
            features.compression_stability,
            
            # Structural features
            features.file_size, features.section_count, features.executable_sections,
            features.writable_sections, features.import_count, features.export_count,
            features.resource_count, features.overlay_size, features.entry_point_section,
            features.code_to_data_ratio, features.section_size_variance,
            features.section_entropy_correlation, features.import_entropy,
            features.string_entropy, features.metadata_entropy,
            
            # Pattern features
            features.repetitive_bytes, features.pattern_density, features.instruction_density,
            features.null_byte_ratio, features.ascii_ratio, features.unicode_ratio,
            features.control_char_ratio, features.printable_ratio, features.binary_patterns,
            features.obfuscation_indicators
        ], dtype=np.float32)
    
    def _get_feature_names(self) -> List[str]:
        """Get ordered list of feature names"""
        return [
            'overall_entropy', 'entropy_variance', 'entropy_skewness', 'entropy_kurtosis',
            'max_entropy', 'min_entropy', 'entropy_range', 'high_entropy_ratio',
            'entropy_transitions', 'local_maxima', 'local_minima', 'entropy_gradient_mean',
            'entropy_gradient_std', 'byte_entropy', 'word_entropy', 'dword_entropy',
            'block_entropy_mean', 'block_entropy_std', 'sliding_window_mean', 'sliding_window_std',
            'compression_ratio', 'compression_efficiency', 'zlib_ratio', 'bz2_ratio',
            'lzma_ratio', 'decompression_time', 'compression_variance', 'best_compression',
            'worst_compression', 'compression_stability', 'file_size', 'section_count',
            'executable_sections', 'writable_sections', 'import_count', 'export_count',
            'resource_count', 'overlay_size', 'entry_point_section', 'code_to_data_ratio',
            'section_size_variance', 'section_entropy_correlation', 'import_entropy',
            'string_entropy', 'metadata_entropy', 'repetitive_bytes', 'pattern_density',
            'instruction_density', 'null_byte_ratio', 'ascii_ratio', 'unicode_ratio',
            'control_char_ratio', 'printable_ratio', 'binary_patterns', 'obfuscation_indicators'
        ]


class PerformanceOptimizer:
    """Performance optimization for entropy analysis of large files"""
    
    def __init__(self):
        self.cache = {}
        self.cache_lock = threading.Lock()
        self.max_workers = min(os.cpu_count() or 1, 8)
        self.memory_limit = 500 * 1024 * 1024  # 500MB limit
        
    def optimize_for_large_files(self, file_path: str, max_size: int = 100 * 1024 * 1024) -> bytes:
        """Optimize file reading for large files with sampling"""
        file_size = os.path.getsize(file_path)
        
        if file_size <= max_size:
            # Read entire file for small files
            with open(file_path, 'rb') as f:
                return f.read()
        else:
            # Use intelligent sampling for large files
            return self._sample_large_file(file_path, file_size, max_size)
    
    def _sample_large_file(self, file_path: str, file_size: int, target_size: int) -> bytes:
        """Sample large files intelligently for entropy analysis"""
        samples = []
        
        # Sample from beginning (headers, etc.)
        beginning_size = min(target_size // 4, 10 * 1024 * 1024)
        with open(file_path, 'rb') as f:
            samples.append(f.read(beginning_size))
            
        # Sample from middle sections
        middle_samples = 6
        middle_size = target_size // 2 // middle_samples
        
        for i in range(middle_samples):
            offset = beginning_size + (file_size - beginning_size - target_size // 4) * i // middle_samples
            with open(file_path, 'rb') as f:
                f.seek(offset)
                samples.append(f.read(middle_size))
                
        # Sample from end (overlay, resources)
        end_size = target_size // 4
        with open(file_path, 'rb') as f:
            f.seek(max(0, file_size - end_size))
            samples.append(f.read(end_size))
            
        return b''.join(samples)
    
    def parallel_entropy_analysis(self, data: bytes, window_size: int = 1024) -> List[float]:
        """Parallel sliding window entropy calculation"""
        if len(data) < window_size * 4:
            # Too small for parallel processing
            calc = AdvancedEntropyCalculator()
            return calc.sliding_window_entropy(data, window_size)
            
        # Split data into chunks for parallel processing
        chunk_size = len(data) // self.max_workers
        chunks = []
        
        for i in range(0, len(data), chunk_size):
            chunk_end = min(i + chunk_size + window_size, len(data))
            chunks.append(data[i:chunk_end])
            
        # Process chunks in parallel
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for chunk in chunks:
                calc = AdvancedEntropyCalculator()
                future = executor.submit(calc.sliding_window_entropy, chunk, window_size)
                futures.append(future)
                
            for future in as_completed(futures):
                try:
                    chunk_results = future.result()
                    results.extend(chunk_results)
                except Exception as e:
                    logger.error(f"Parallel entropy calculation failed: {e}")
                    
        return results
    
    def memory_efficient_analysis(self, file_path: str, mode: EntropyAnalysisMode) -> Optional[bytes]:
        """Memory-efficient file analysis based on available resources"""
        file_size = os.path.getsize(file_path)
        
        # Determine memory budget based on mode
        memory_budgets = {
            EntropyAnalysisMode.FAST: 50 * 1024 * 1024,      # 50MB
            EntropyAnalysisMode.STANDARD: 200 * 1024 * 1024,  # 200MB
            EntropyAnalysisMode.DEEP: 500 * 1024 * 1024,      # 500MB
            EntropyAnalysisMode.REALTIME: 20 * 1024 * 1024    # 20MB
        }
        
        budget = memory_budgets.get(mode, 200 * 1024 * 1024)
        
        if file_size <= budget:
            with open(file_path, 'rb') as f:
                return f.read()
        else:
            logger.info(f"File size ({file_size}) exceeds memory budget ({budget}), using sampling")
            return self.optimize_for_large_files(file_path, budget)


class SophisticatedEntropyPackerDetector:
    """Main entropy-based packer detection system"""
    
    def __init__(self, analysis_mode: EntropyAnalysisMode = EntropyAnalysisMode.STANDARD):
        self.analysis_mode = analysis_mode
        self.entropy_calculator = AdvancedEntropyCalculator()
        self.signature_db = PackerSignatureDatabase()
        self.ml_classifier = MLPackerClassifier()
        self.optimizer = PerformanceOptimizer()
        
        # Performance tracking
        self.analysis_stats = {
            'total_files_analyzed': 0,
            'cache_hits': 0,
            'average_analysis_time': 0.0,
            'memory_usage_peak': 0
        }
        
        logger.info(f"Sophisticated Entropy Packer Detector initialized in {analysis_mode.value} mode")
    
    def analyze_file(self, file_path: str, enable_ml: bool = True) -> EntropyDetectionResult:
        """Perform comprehensive entropy-based packer detection"""
        start_time = time.time()
        initial_memory = self._get_memory_usage()
        
        try:
            # Optimize file reading based on analysis mode
            data = self.optimizer.memory_efficient_analysis(file_path, self.analysis_mode)
            if data is None:
                raise ValueError("Failed to read file data")
                
            # Perform multi-scale entropy analysis
            metrics = self._comprehensive_entropy_analysis(data)
            
            # Extract ML features
            ml_features = self.ml_classifier.extract_features(metrics, file_path, data)
            
            # Signature-based detection
            sig_family, sig_confidence = self.signature_db.match_signature(metrics, data)
            
            # ML-based classification (if enabled and trained)
            ml_family = PackerFamily.UNKNOWN
            ml_confidence = 0.0
            false_positive_prob = 0.5
            
            if enable_ml and self.ml_classifier.is_trained:
                ml_family, ml_confidence, false_positive_prob = self.ml_classifier.classify_packer(ml_features)
            
            # Combine results for final decision
            final_family, final_confidence = self._combine_detection_results(
                sig_family, sig_confidence, ml_family, ml_confidence
            )
            
            # Determine if file is packed
            is_packed = self._determine_packing_status(metrics, final_confidence)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(final_family, metrics)
            
            # Create visualization data
            visualizations = self._create_visualizations(metrics)
            
            # Identify anomalous regions
            anomalous_regions = self._identify_anomalous_regions(metrics, data)
            
            # Calculate performance metrics
            analysis_time = time.time() - start_time
            peak_memory = self._get_memory_usage() - initial_memory
            
            # Update statistics
            self._update_statistics(analysis_time, peak_memory)
            
            result = EntropyDetectionResult(
                file_path=file_path,
                analysis_mode=self.analysis_mode,
                metrics=metrics,
                ml_features=ml_features,
                is_packed=is_packed,
                packer_family=final_family,
                confidence_score=final_confidence,
                false_positive_probability=false_positive_prob,
                entropy_visualizations=visualizations,
                anomalous_regions=anomalous_regions,
                unpacking_recommendations=recommendations,
                analysis_time=analysis_time,
                memory_usage=peak_memory,
                cache_hits=self.analysis_stats['cache_hits'],
                bypass_strategies=self._get_bypass_strategies(final_family),
                tool_recommendations=self._get_tool_recommendations(final_family),
                confidence_breakdown=self._calculate_confidence_breakdown(
                    sig_confidence, ml_confidence, metrics
                )
            )
            
            logger.info(f"Entropy analysis completed for {os.path.basename(file_path)} in {analysis_time:.2f}s")
            return result
            
        except Exception as e:
            logger.error(f"Entropy analysis failed for {file_path}: {e}")
            return self._create_error_result(file_path, str(e))
    
    def _comprehensive_entropy_analysis(self, data: bytes) -> MultiScaleEntropyMetrics:
        """Perform comprehensive multi-scale entropy analysis"""
        
        # Basic entropy calculations
        shannon_entropy = self.entropy_calculator.calculate_shannon_entropy(data)
        renyi_entropy = self.entropy_calculator.calculate_renyi_entropy(data)
        kolmogorov_estimate = self.entropy_calculator.estimate_kolmogorov_complexity(data)
        
        # Multi-scale entropy
        multi_scale = self.entropy_calculator.calculate_multi_scale_entropy(data)
        
        # Sliding window analysis
        if self.analysis_mode == EntropyAnalysisMode.FAST:
            window_entropies = self.entropy_calculator.sliding_window_entropy(data, 2048, 1024)
        elif self.analysis_mode == EntropyAnalysisMode.REALTIME:
            window_entropies = self.entropy_calculator.sliding_window_entropy(data, 4096, 2048)
        else:
            window_entropies = self.optimizer.parallel_entropy_analysis(data, 1024)
        
        # Statistical measures
        entropy_mean = np.mean(window_entropies) if window_entropies else 0.0
        entropy_std = np.std(window_entropies) if window_entropies else 0.0
        entropy_var = np.var(window_entropies) if window_entropies else 0.0
        entropy_skew = self._calculate_skewness(window_entropies)
        entropy_kurt = self._calculate_kurtosis(window_entropies)
        entropy_range = max(window_entropies) - min(window_entropies) if window_entropies else 0.0
        
        # Section-based analysis
        section_entropies = self._analyze_sections(data)
        high_entropy_sections = [name for name, entropy in section_entropies.items() if entropy > 7.0]
        
        # Compression analysis
        compression_ratio = len(zlib.compress(data, 9)) / len(data) if data else 1.0
        compression_efficiency = 1.0 - compression_ratio
        decompression_complexity = self._estimate_decompression_complexity(data)
        
        # Pattern analysis
        repetitive_patterns = self._count_repetitive_patterns(data)
        entropy_transitions = self._detect_entropy_transitions(window_entropies)
        anomalous_regions = self._detect_anomalous_entropy_regions(window_entropies, data)
        
        # Autocorrelation
        autocorr = self._calculate_autocorrelation(window_entropies)
        
        return MultiScaleEntropyMetrics(
            shannon_entropy=shannon_entropy,
            renyi_entropy=renyi_entropy,
            kolmogorov_complexity_estimate=kolmogorov_estimate,
            byte_level_entropy=multi_scale.get('byte', 0.0),
            word_level_entropy=multi_scale.get('word', 0.0),
            dword_level_entropy=multi_scale.get('dword', 0.0),
            block_level_entropy=window_entropies,
            window_entropies=window_entropies,
            entropy_variance=entropy_var,
            entropy_skewness=entropy_skew,
            entropy_kurtosis=entropy_kurt,
            section_entropies=section_entropies,
            high_entropy_sections=high_entropy_sections,
            entropy_distribution=self._calculate_entropy_distribution(section_entropies),
            compression_ratio=compression_ratio,
            compression_efficiency=compression_efficiency,
            decompression_complexity=decompression_complexity,
            repetitive_patterns=repetitive_patterns,
            entropy_transitions=entropy_transitions,
            anomalous_regions=anomalous_regions,
            entropy_mean=entropy_mean,
            entropy_std=entropy_std,
            entropy_range=entropy_range,
            autocorrelation=autocorr
        )
    
    def _analyze_sections(self, data: bytes) -> Dict[str, float]:
        """Analyze entropy of file sections"""
        sections = {}
        
        # Simple section analysis - divide file into logical parts
        section_size = max(len(data) // 8, 1024)
        
        for i in range(0, len(data), section_size):
            section_data = data[i:i + section_size]
            if len(section_data) >= 64:
                section_name = f"section_{i//section_size}"
                entropy = self.entropy_calculator.calculate_shannon_entropy(section_data)
                sections[section_name] = entropy
                
        return sections
    
    def _calculate_skewness(self, values: List[float]) -> float:
        """Calculate skewness of entropy values"""
        if len(values) < 3:
            return 0.0
        try:
            from scipy import stats
            return float(stats.skew(values))
        except ImportError:
            # Manual calculation if scipy not available
            mean_val = np.mean(values)
            std_val = np.std(values)
            if std_val == 0:
                return 0.0
            n = len(values)
            skew = (n / ((n-1) * (n-2))) * np.sum(((values - mean_val) / std_val) ** 3)
            return skew
    
    def _calculate_kurtosis(self, values: List[float]) -> float:
        """Calculate kurtosis of entropy values"""
        if len(values) < 4:
            return 0.0
        try:
            from scipy import stats
            return float(stats.kurtosis(values))
        except ImportError:
            # Manual calculation if scipy not available
            mean_val = np.mean(values)
            std_val = np.std(values)
            if std_val == 0:
                return 0.0
            n = len(values)
            kurt = (n * (n+1) / ((n-1) * (n-2) * (n-3))) * np.sum(((values - mean_val) / std_val) ** 4)
            kurt -= 3 * (n-1)**2 / ((n-2) * (n-3))
            return kurt
    
    def _calculate_entropy_distribution(self, section_entropies: Dict[str, float]) -> Dict[str, float]:
        """Calculate entropy distribution statistics"""
        if not section_entropies:
            return {"high": 0.0, "medium": 0.0, "low": 0.0}
            
        entropies = list(section_entropies.values())
        total = len(entropies)
        
        high_count = sum(1 for e in entropies if e > 7.0)
        medium_count = sum(1 for e in entropies if 5.0 <= e <= 7.0)
        low_count = sum(1 for e in entropies if e < 5.0)
        
        return {
            "high": high_count / total,
            "medium": medium_count / total,
            "low": low_count / total
        }
    
    def _estimate_decompression_complexity(self, data: bytes) -> float:
        """Estimate decompression computational complexity"""
        if not data:
            return 0.0
            
        start_time = time.time()
        try:
            decompressed = zlib.decompress(zlib.compress(data, 9))
            decomp_time = time.time() - start_time
            return decomp_time * 1000  # Convert to milliseconds
        except Exception:
            return 0.0
    
    def _count_repetitive_patterns(self, data: bytes) -> int:
        """Count repetitive byte patterns"""
        pattern_count = 0
        pattern_cache = set()
        
        # Look for 2-4 byte patterns
        for pattern_len in [2, 3, 4]:
            for i in range(min(len(data) - pattern_len, 10000)):  # Limit for performance
                pattern = data[i:i+pattern_len]
                if pattern not in pattern_cache:
                    pattern_cache.add(pattern)
                    if data.count(pattern) > 5:  # Pattern appears more than 5 times
                        pattern_count += 1
                        
        return pattern_count
    
    def _detect_entropy_transitions(self, window_entropies: List[float]) -> List[Tuple[int, float]]:
        """Detect significant entropy transitions"""
        transitions = []
        
        if len(window_entropies) < 3:
            return transitions
            
        threshold = np.std(window_entropies) * 2  # 2 standard deviations
        
        for i in range(1, len(window_entropies) - 1):
            change = abs(window_entropies[i] - window_entropies[i-1])
            if change > threshold:
                transitions.append((i, change))
                
        return transitions
    
    def _detect_anomalous_entropy_regions(self, window_entropies: List[float], 
                                        data: bytes) -> List[Tuple[int, int, float]]:
        """Detect regions with anomalous entropy patterns"""
        anomalies = []
        
        if len(window_entropies) < 5:
            return anomalies
            
        # Use median and MAD for outlier detection
        median_entropy = np.median(window_entropies)
        mad = np.median(np.abs(np.array(window_entropies) - median_entropy))
        threshold = median_entropy + 3 * mad
        
        window_size = len(data) // len(window_entropies) if window_entropies else 1024
        
        i = 0
        while i < len(window_entropies):
            if window_entropies[i] > threshold:
                # Found start of anomalous region
                start_idx = i
                while i < len(window_entropies) and window_entropies[i] > threshold:
                    i += 1
                end_idx = i - 1
                
                avg_entropy = np.mean(window_entropies[start_idx:end_idx+1])
                start_offset = start_idx * window_size
                end_offset = (end_idx + 1) * window_size
                
                anomalies.append((start_offset, end_offset, avg_entropy))
            else:
                i += 1
                
        return anomalies
    
    def _calculate_autocorrelation(self, values: List[float]) -> float:
        """Calculate autocorrelation of entropy values"""
        if len(values) < 2:
            return 0.0
            
        try:
            values_array = np.array(values)
            # Calculate lag-1 autocorrelation
            if len(values) > 1:
                correlation = np.corrcoef(values_array[:-1], values_array[1:])[0, 1]
                return correlation if not np.isnan(correlation) else 0.0
            return 0.0
        except Exception:
            return 0.0
    
    def _combine_detection_results(self, sig_family: PackerFamily, sig_confidence: float,
                                 ml_family: PackerFamily, ml_confidence: float) -> Tuple[PackerFamily, float]:
        """Combine signature and ML detection results"""
        
        # If both agree and have high confidence
        if sig_family == ml_family and sig_confidence > 0.7 and ml_confidence > 0.7:
            combined_confidence = (sig_confidence + ml_confidence) / 2 * 1.1  # Boost for agreement
            return sig_family, min(combined_confidence, 1.0)
        
        # Use the result with higher confidence
        if sig_confidence > ml_confidence:
            return sig_family, sig_confidence
        elif ml_confidence > 0.5:  # Only trust ML if reasonably confident
            return ml_family, ml_confidence
        else:
            return sig_family, sig_confidence
    
    def _determine_packing_status(self, metrics: MultiScaleEntropyMetrics, confidence: float) -> bool:
        """Determine if file is packed based on entropy metrics"""
        indicators = 0
        
        # High overall entropy
        if metrics.shannon_entropy > 7.0:
            indicators += 2
        elif metrics.shannon_entropy > 6.5:
            indicators += 1
            
        # Low compression ratio
        if metrics.compression_ratio < 0.4:
            indicators += 2
        elif metrics.compression_ratio < 0.6:
            indicators += 1
            
        # High entropy variance
        if metrics.entropy_variance > 1.0:
            indicators += 1
            
        # Multiple high entropy sections
        if len(metrics.high_entropy_sections) > 1:
            indicators += 1
            
        # Entropy transitions
        if len(metrics.entropy_transitions) > 3:
            indicators += 1
            
        # High confidence detection
        if confidence > 0.8:
            indicators += 2
        elif confidence > 0.6:
            indicators += 1
            
        return indicators >= 4
    
    def _generate_recommendations(self, packer_family: PackerFamily, 
                                metrics: MultiScaleEntropyMetrics) -> List[str]:
        """Generate unpacking recommendations based on detection"""
        recommendations = []
        
        if packer_family == PackerFamily.UPX:
            recommendations.extend([
                "Try standard UPX unpacker: upx -d file.exe",
                "If modified UPX, use manual unpacking with x64dbg",
                "Set breakpoint on VirtualAlloc for memory unpacking"
            ])
        elif packer_family == PackerFamily.THEMIDA:
            recommendations.extend([
                "Use Themida-specific unpacking tools",
                "Consider VM-based analysis due to anti-debug",
                "Focus on IAT reconstruction after unpacking"
            ])
        elif packer_family == PackerFamily.VMPROTECT:
            recommendations.extend([
                "Extremely difficult - consider dynamic analysis instead",
                "Use VMProtect devirtualization tools if available",
                "Focus on API monitoring rather than unpacking"
            ])
        else:
            # Generic recommendations
            if metrics.shannon_entropy > 7.5:
                recommendations.append("High entropy suggests strong packing/encryption")
            if metrics.compression_ratio < 0.3:
                recommendations.append("Low compression ratio indicates custom packing")
            if len(metrics.entropy_transitions) > 5:
                recommendations.append("Multiple entropy transitions suggest multi-stage unpacking")
                
            recommendations.extend([
                "Try generic unpacking tools (PEiD, Detect It Easy)",
                "Use dynamic analysis with API monitoring",
                "Set breakpoints on common unpacking APIs (VirtualAlloc, VirtualProtect)",
                "Monitor for OEP (Original Entry Point) detection"
            ])
        
        return recommendations
    
    def _create_visualizations(self, metrics: MultiScaleEntropyMetrics) -> Dict[str, List[float]]:
        """Create entropy visualization data"""
        return {
            "sliding_window_entropy": metrics.window_entropies,
            "section_entropies": list(metrics.section_entropies.values()),
            "entropy_transitions": [t[1] for t in metrics.entropy_transitions],
            "block_entropies": metrics.block_level_entropy
        }
    
    def _identify_anomalous_regions(self, metrics: MultiScaleEntropyMetrics, 
                                  data: bytes) -> List[Tuple[int, int, str]]:
        """Identify and categorize anomalous regions"""
        regions = []
        
        for start_offset, end_offset, avg_entropy in metrics.anomalous_regions:
            if avg_entropy > 7.8:
                category = "highly_packed"
            elif avg_entropy > 7.0:
                category = "packed_data"
            elif avg_entropy < 3.0:
                category = "padding_or_zeroes"
            else:
                category = "unusual_structure"
                
            regions.append((start_offset, end_offset, category))
            
        return regions
    
    def _get_bypass_strategies(self, packer_family: PackerFamily) -> List[str]:
        """Get bypass strategies for specific packer family"""
        strategies = {
            PackerFamily.UPX: [
                "Static unpacking with upx -d",
                "Dynamic unpacking with OEP detection",
                "Memory dumping after decompression"
            ],
            PackerFamily.THEMIDA: [
                "VM-based analysis to bypass anti-debug",
                "Hardware breakpoints for evasion",
                "Kernel-mode debugging"
            ],
            PackerFamily.VMPROTECT: [
                "Focus on API call analysis",
                "Virtual machine handler analysis",
                "Devirtualization tools"
            ]
        }
        
        return strategies.get(packer_family, [
            "Generic dynamic analysis",
            "API monitoring and hooking",
            "Memory dumping techniques"
        ])
    
    def _get_tool_recommendations(self, packer_family: PackerFamily) -> List[str]:
        """Get tool recommendations for analysis"""
        tools = {
            PackerFamily.UPX: ["UPX", "x64dbg", "PEiD"],
            PackerFamily.THEMIDA: ["x64dbg + ScyllaHide", "Themida Unpacker", "VMware"],
            PackerFamily.VMPROTECT: ["IDA Pro", "VMProtect Analyzer", "x64dbg"]
        }
        
        return tools.get(packer_family, [
            "x64dbg", "IDA Pro", "Detect It Easy", "PEiD"
        ])
    
    def _calculate_confidence_breakdown(self, sig_confidence: float, ml_confidence: float,
                                      metrics: MultiScaleEntropyMetrics) -> Dict[str, float]:
        """Calculate confidence breakdown by method"""
        return {
            "signature_based": sig_confidence,
            "machine_learning": ml_confidence,
            "entropy_analysis": min(metrics.shannon_entropy / 8.0 * 100, 100.0),
            "compression_analysis": (1.0 - metrics.compression_ratio) * 100,
            "pattern_analysis": min(len(metrics.entropy_transitions) * 10, 100.0)
        }
    
    def _get_memory_usage(self) -> int:
        """Get current memory usage in bytes"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss
        except ImportError:
            return 0
    
    def _update_statistics(self, analysis_time: float, memory_usage: int):
        """Update analysis statistics"""
        self.analysis_stats['total_files_analyzed'] += 1
        
        # Update average analysis time
        current_avg = self.analysis_stats['average_analysis_time']
        total_files = self.analysis_stats['total_files_analyzed']
        self.analysis_stats['average_analysis_time'] = (current_avg * (total_files - 1) + analysis_time) / total_files
        
        # Update peak memory usage
        if memory_usage > self.analysis_stats['memory_usage_peak']:
            self.analysis_stats['memory_usage_peak'] = memory_usage
    
    def _create_error_result(self, file_path: str, error_msg: str) -> EntropyDetectionResult:
        """Create error result for failed analysis"""
        empty_metrics = MultiScaleEntropyMetrics(
            shannon_entropy=0.0, renyi_entropy=0.0, kolmogorov_complexity_estimate=0.0,
            byte_level_entropy=0.0, word_level_entropy=0.0, dword_level_entropy=0.0,
            block_level_entropy=[], window_entropies=[], entropy_variance=0.0,
            entropy_skewness=0.0, entropy_kurtosis=0.0, section_entropies={},
            high_entropy_sections=[], entropy_distribution={},
            compression_ratio=1.0, compression_efficiency=0.0, decompression_complexity=0.0,
            repetitive_patterns=0, entropy_transitions=[], anomalous_regions=[],
            entropy_mean=0.0, entropy_std=0.0, entropy_range=0.0, autocorrelation=0.0
        )
        
        empty_features = MLFeatureVector(**{name: 0.0 for name in self.ml_classifier._get_feature_names()})
        
        return EntropyDetectionResult(
            file_path=file_path,
            analysis_mode=self.analysis_mode,
            metrics=empty_metrics,
            ml_features=empty_features,
            is_packed=False,
            packer_family=PackerFamily.UNKNOWN,
            confidence_score=0.0,
            false_positive_probability=1.0,
            entropy_visualizations={},
            anomalous_regions=[],
            unpacking_recommendations=[f"Analysis failed: {error_msg}"],
            analysis_time=0.0,
            memory_usage=0,
            cache_hits=0,
            bypass_strategies=[],
            tool_recommendations=[],
            confidence_breakdown={}
        )
    
    def train_ml_classifier(self, training_samples: List[Tuple[str, PackerFamily]]) -> bool:
        """Train ML classifier with labeled samples"""
        if len(training_samples) < 20:
            logger.warning("Insufficient training samples for ML classifier")
            return False
            
        logger.info(f"Training ML classifier with {len(training_samples)} samples")
        
        training_data = []
        failed_samples = 0
        
        for file_path, label in training_samples:
            try:
                if not os.path.exists(file_path):
                    logger.warning(f"Training sample not found: {file_path}")
                    continue
                    
                # Analyze file to extract features
                data = self.optimizer.memory_efficient_analysis(file_path, EntropyAnalysisMode.FAST)
                if data is None:
                    failed_samples += 1
                    continue
                    
                metrics = self._comprehensive_entropy_analysis(data)
                features = self.ml_classifier.extract_features(metrics, file_path, data)
                
                training_data.append((features, label))
                
            except Exception as e:
                logger.error(f"Failed to process training sample {file_path}: {e}")
                failed_samples += 1
                
        if failed_samples > 0:
            logger.warning(f"Failed to process {failed_samples} training samples")
            
        if len(training_data) < 10:
            logger.error("Too few valid training samples for ML classifier")
            return False
            
        return self.ml_classifier.train_classifier(training_data)
    
    def batch_analyze_directory(self, directory: str, recursive: bool = True,
                              file_extensions: List[str] = None) -> List[EntropyDetectionResult]:
        """Analyze all files in a directory"""
        if file_extensions is None:
            file_extensions = ['.exe', '.dll', '.sys', '.ocx', '.scr']
            
        results = []
        files_to_analyze = []
        
        # Collect files
        if recursive:
            for root, _, files in os.walk(directory):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in file_extensions):
                        files_to_analyze.append(os.path.join(root, file))
        else:
            for file in os.listdir(directory):
                if any(file.lower().endswith(ext) for ext in file_extensions):
                    file_path = os.path.join(directory, file)
                    if os.path.isfile(file_path):
                        files_to_analyze.append(file_path)
        
        logger.info(f"Analyzing {len(files_to_analyze)} files in {directory}")
        
        # Analyze files
        for file_path in files_to_analyze:
            try:
                result = self.analyze_file(file_path)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to analyze {file_path}: {e}")
                
        return results
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary and statistics"""
        return {
            "analysis_mode": self.analysis_mode.value,
            "ml_classifier_trained": self.ml_classifier.is_trained,
            "statistics": self.analysis_stats.copy(),
            "cache_size": len(self.entropy_calculator.cache),
            "signature_database_size": len(self.signature_db.signatures)
        }


# Integration function for existing protection detection system
def integrate_with_protection_core(file_path: str, 
                                 mode: EntropyAnalysisMode = EntropyAnalysisMode.STANDARD) -> List[DetectionResult]:
    """Integration function for existing protection detection system"""
    detector = SophisticatedEntropyPackerDetector(mode)
    result = detector.analyze_file(file_path)
    
    # Convert to DetectionResult format
    detections = []
    
    if result.is_packed and result.confidence_score > 0.5:
        detection = DetectionResult(
            name=f"Entropy-Based Packing Detection ({result.packer_family.value.title()})",
            type=ProtectionType.PACKER,
            confidence=result.confidence_score * 100,
            details={
                "entropy_metrics": {
                    "shannon_entropy": result.metrics.shannon_entropy,
                    "compression_ratio": result.metrics.compression_ratio,
                    "high_entropy_sections": result.metrics.high_entropy_sections
                },
                "ml_confidence": result.confidence_breakdown.get("machine_learning", 0.0),
                "false_positive_probability": result.false_positive_probability
            },
            bypass_recommendations=result.unpacking_recommendations
        )
        detections.append(detection)
    
    return detections


# Factory functions for different use cases
def create_fast_detector() -> SophisticatedEntropyPackerDetector:
    """Create detector optimized for speed"""
    return SophisticatedEntropyPackerDetector(EntropyAnalysisMode.FAST)


def create_deep_detector() -> SophisticatedEntropyPackerDetector:
    """Create detector optimized for accuracy"""
    return SophisticatedEntropyPackerDetector(EntropyAnalysisMode.DEEP)


def create_realtime_detector() -> SophisticatedEntropyPackerDetector:
    """Create detector optimized for real-time analysis"""
    return SophisticatedEntropyPackerDetector(EntropyAnalysisMode.REALTIME)