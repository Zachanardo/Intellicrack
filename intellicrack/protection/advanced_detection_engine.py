"""
Advanced Protection Detection Engine

Sophisticated multi-layered protection detection that goes beyond simple string matching.
Provides production-ready detection for modern protection schemes including advanced packers,
anti-analysis techniques, licensing systems, and code obfuscation.

Enhanced with sophisticated entropy-based packer detection for superior accuracy.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import math
import os
import struct
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..utils.logger import get_logger
from .intellicrack_protection_core import DetectionResult, ProtectionType
from .entropy_packer_detector import (
    SophisticatedEntropyPackerDetector, EntropyAnalysisMode, PackerFamily,
    integrate_with_protection_core
)

logger = get_logger(__name__)


class DetectionConfidence(Enum):
    """Detection confidence levels"""
    VERY_LOW = 25.0
    LOW = 40.0
    MEDIUM = 60.0
    HIGH = 80.0
    VERY_HIGH = 95.0


class AnalysisLayer(Enum):
    """Analysis layer types"""
    ENTROPY = "entropy"
    SIGNATURE = "signature"
    IMPORT_TABLE = "import_table"
    ANTI_ANALYSIS = "anti_analysis"
    BEHAVIORAL = "behavioral"
    SECTION_ANALYSIS = "section_analysis"
    CODE_PATTERNS = "code_patterns"


@dataclass
class EntropyMetrics:
    """Multi-dimensional entropy analysis results"""
    overall_entropy: float
    section_entropies: Dict[str, float]
    sliding_window_entropy: List[float]
    compression_ratio: float
    entropy_variance: float
    high_entropy_sections: List[str]
    packed_probability: float


@dataclass
class ImportTableAnalysis:
    """Import table obfuscation analysis"""
    total_imports: int
    suspicious_apis: List[str]
    obfuscated_imports: List[str]
    dynamic_loading_indicators: List[str]
    api_redirection_score: float
    import_entropy: float
    obfuscation_probability: float


@dataclass
class AntiAnalysisFindings:
    """Anti-analysis technique detection results"""
    anti_debug_techniques: List[str]
    anti_vm_techniques: List[str]
    timing_attack_patterns: List[str]
    environment_checks: List[str]
    evasion_score: float
    detection_probability: float


@dataclass
class BehavioralIndicators:
    """Behavioral analysis indicators"""
    file_structure_anomalies: List[str]
    code_flow_patterns: List[str]
    packing_indicators: List[str]
    protection_indicators: List[str]
    complexity_score: float
    sophistication_level: str


@dataclass
class AdvancedDetectionResult:
    """Comprehensive advanced detection result"""
    file_path: str
    entropy_metrics: EntropyMetrics
    import_analysis: ImportTableAnalysis
    anti_analysis: AntiAnalysisFindings
    behavioral: BehavioralIndicators
    detections: List[DetectionResult]
    overall_confidence: float
    protection_layers: int
    evasion_sophistication: str
    analysis_time: float


class AdvancedEntropyAnalyzer:
    """Multi-dimensional entropy analysis for sophisticated packing detection"""
    
    def __init__(self):
        self.window_size = 1024
        self.entropy_threshold = 7.0
        self.variance_threshold = 0.5
        
    def analyze_entropy(self, file_path: str) -> EntropyMetrics:
        """Perform comprehensive entropy analysis"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            if len(data) < 64:
                return self._create_empty_metrics()
                
            # Calculate overall entropy
            overall_entropy = self._calculate_entropy(data)
            
            # Section-based entropy analysis
            section_entropies = self._analyze_section_entropy(file_path, data)
            
            # Sliding window entropy
            sliding_entropies = self._sliding_window_entropy(data)
            
            # Compression ratio estimation
            compression_ratio = self._estimate_compression_ratio(data)
            
            # Entropy variance
            entropy_variance = self._calculate_entropy_variance(sliding_entropies)
            
            # High entropy sections
            high_entropy_sections = [
                name for name, entropy in section_entropies.items() 
                if entropy > self.entropy_threshold
            ]
            
            # Packed probability calculation
            packed_probability = self._calculate_packed_probability(
                overall_entropy, entropy_variance, compression_ratio, len(high_entropy_sections)
            )
            
            return EntropyMetrics(
                overall_entropy=overall_entropy,
                section_entropies=section_entropies,
                sliding_window_entropy=sliding_entropies,
                compression_ratio=compression_ratio,
                entropy_variance=entropy_variance,
                high_entropy_sections=high_entropy_sections,
                packed_probability=packed_probability
            )
            
        except Exception as e:
            logger.error(f"Entropy analysis failed for {file_path}: {e}")
            return self._create_empty_metrics()
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
            
        # Count byte frequencies
        byte_counts = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def _analyze_section_entropy(self, file_path: str, data: bytes) -> Dict[str, float]:
        """Analyze entropy for each section"""
        sections = {}
        
        try:
            # For PE files, try to parse sections
            if self._is_pe_file(data):
                sections = self._parse_pe_sections(data)
            elif self._is_elf_file(data):
                sections = self._parse_elf_sections(data)
            else:
                # Generic section analysis
                sections = self._generic_section_analysis(data)
                
        except Exception as e:
            logger.debug(f"Section parsing failed, using generic analysis: {e}")
            sections = self._generic_section_analysis(data)
            
        return sections
    
    def _sliding_window_entropy(self, data: bytes) -> List[float]:
        """Calculate entropy using sliding window"""
        entropies = []
        
        for i in range(0, len(data) - self.window_size, self.window_size // 4):
            window = data[i:i + self.window_size]
            entropy = self._calculate_entropy(window)
            entropies.append(entropy)
            
        return entropies
    
    def _estimate_compression_ratio(self, data: bytes) -> float:
        """Estimate compression ratio using zlib"""
        try:
            import zlib
            compressed = zlib.compress(data)
            return len(compressed) / len(data)
        except Exception:
            return 1.0
    
    def _calculate_entropy_variance(self, entropies: List[float]) -> float:
        """Calculate variance in entropy values"""
        if len(entropies) < 2:
            return 0.0
            
        mean = sum(entropies) / len(entropies)
        variance = sum((e - mean) ** 2 for e in entropies) / len(entropies)
        return variance
    
    def _calculate_packed_probability(self, overall_entropy: float, 
                                    entropy_variance: float,
                                    compression_ratio: float,
                                    high_entropy_count: int) -> float:
        """Calculate probability that file is packed"""
        score = 0.0
        
        # High entropy indicator
        if overall_entropy > 7.5:
            score += 40.0
        elif overall_entropy > 7.0:
            score += 25.0
        elif overall_entropy > 6.5:
            score += 10.0
            
        # Low compression ratio indicator
        if compression_ratio < 0.3:
            score += 30.0
        elif compression_ratio < 0.5:
            score += 20.0
        elif compression_ratio < 0.7:
            score += 10.0
            
        # High entropy variance (typical of packed files)
        if entropy_variance > 1.0:
            score += 20.0
        elif entropy_variance > 0.5:
            score += 10.0
            
        # Multiple high entropy sections
        score += min(high_entropy_count * 5.0, 15.0)
        
        return min(score, 100.0)
    
    def _is_pe_file(self, data: bytes) -> bool:
        """Check if file is PE format"""
        return len(data) > 64 and data.startswith(b'MZ')
    
    def _is_elf_file(self, data: bytes) -> bool:
        """Check if file is ELF format"""
        return len(data) > 16 and data.startswith(b'\x7fELF')
    
    def _parse_pe_sections(self, data: bytes) -> Dict[str, float]:
        """Parse PE sections and calculate entropy"""
        sections = {}
        
        try:
            # Basic PE parsing
            if len(data) < 1024:
                return sections
                
            # Get PE header offset
            pe_offset = struct.unpack('<L', data[60:64])[0]
            if pe_offset + 248 > len(data):
                return sections
                
            # Get number of sections
            num_sections = struct.unpack('<H', data[pe_offset + 6:pe_offset + 8])[0]
            
            # Section header starts after PE header
            section_offset = pe_offset + 248
            
            for i in range(min(num_sections, 20)):  # Limit to 20 sections
                if section_offset + 40 > len(data):
                    break
                    
                # Parse section header
                section_data = data[section_offset:section_offset + 40]
                name = section_data[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                virtual_size = struct.unpack('<L', section_data[8:12])[0]
                raw_size = struct.unpack('<L', section_data[16:20])[0]
                raw_offset = struct.unpack('<L', section_data[20:24])[0]
                
                # Calculate section entropy
                if raw_offset + raw_size <= len(data) and raw_size > 0:
                    section_bytes = data[raw_offset:raw_offset + raw_size]
                    sections[name] = self._calculate_entropy(section_bytes)
                    
                section_offset += 40
                
        except Exception as e:
            logger.debug(f"PE section parsing error: {e}")
            
        return sections
    
    def _parse_elf_sections(self, data: bytes) -> Dict[str, float]:
        """Parse ELF sections and calculate entropy"""
        sections = {}
        
        try:
            # Basic ELF parsing for 64-bit
            if len(data) < 64:
                return sections
                
            # Check if 64-bit ELF
            if data[4] == 2:  # ELFCLASS64
                # Parse ELF64 header
                section_header_offset = struct.unpack('<Q', data[40:48])[0]
                section_header_size = struct.unpack('<H', data[58:60])[0]
                section_count = struct.unpack('<H', data[60:62])[0]
                
                for i in range(min(section_count, 20)):
                    header_offset = section_header_offset + (i * section_header_size)
                    if header_offset + 64 > len(data):
                        break
                        
                    # Parse section header
                    section_offset = struct.unpack('<Q', data[header_offset + 24:header_offset + 32])[0]
                    section_size = struct.unpack('<Q', data[header_offset + 32:header_offset + 40])[0]
                    
                    if section_offset + section_size <= len(data) and section_size > 0:
                        section_bytes = data[section_offset:section_offset + section_size]
                        sections[f'section_{i}'] = self._calculate_entropy(section_bytes)
                        
        except Exception as e:
            logger.debug(f"ELF section parsing error: {e}")
            
        return sections
    
    def _generic_section_analysis(self, data: bytes) -> Dict[str, float]:
        """Generic section analysis for unknown formats"""
        sections = {}
        
        # Divide file into logical sections
        section_size = max(len(data) // 8, 1024)  # 8 sections minimum 1KB each
        
        for i in range(0, len(data), section_size):
            section_data = data[i:i + section_size]
            if len(section_data) >= 64:  # Minimum size for meaningful entropy
                sections[f'generic_section_{i//section_size}'] = self._calculate_entropy(section_data)
                
        return sections
    
    def _create_empty_metrics(self) -> EntropyMetrics:
        """Create empty entropy metrics for error cases"""
        return EntropyMetrics(
            overall_entropy=0.0,
            section_entropies={},
            sliding_window_entropy=[],
            compression_ratio=1.0,
            entropy_variance=0.0,
            high_entropy_sections=[],
            packed_probability=0.0
        )


class ModernProtectionSignatures:
    """Comprehensive signature database for modern protection schemes"""
    
    def __init__(self):
        self.signatures = self._load_protection_signatures()
        
    def _load_protection_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load comprehensive protection signatures"""
        return {
            # Advanced Packers
            'upx_advanced': {
                'patterns': [
                    b'UPX!',
                    b'$Info: This file is packed with the UPX',
                    b'UPX compression succeeded',
                    rb'\x60\x8B\xEC\x81\xEC.{0,20}\x8B\x45\x08'
                ],
                'type': ProtectionType.PACKER,
                'confidence': DetectionConfidence.VERY_HIGH,
                'variants': ['upx', 'upx_modified', 'upx_encrypted'],
                'bypass_recommendations': [
                    'Use upx -d to unpack if standard UPX',
                    'Dynamic unpacking with x64dbg + ScyllaHide',
                    'Memory dumping at OEP'
                ]
            },
            
            'themida': {
                'patterns': [
                    b'Themida',
                    b'WinLicense',
                    b'VMProtect',
                    rb'\x68.{4}\xE8.{4}\x5D\x81\xED',
                    b'Oreans Technologies'
                ],
                'type': ProtectionType.PROTECTOR,
                'confidence': DetectionConfidence.VERY_HIGH,
                'variants': ['themida_2x', 'themida_3x', 'winlicense'],
                'bypass_recommendations': [
                    'Use Themida/WinLicense unpacker tools',
                    'VM analysis with custom Themida scripts',
                    'Hardware breakpoints to bypass anti-debug'
                ]
            },
            
            'vmprotect': {
                'patterns': [
                    b'VMProtect',
                    rb'\x68.{4}\xE8.{4}\x8B\x44\x24\x04',
                    b'BoringSSL',  # VMProtect often includes this
                    rb'\x60\x8B\x74\x24\x24\x8B\x7C\x24\x28'
                ],
                'type': ProtectionType.PROTECTOR,
                'confidence': DetectionConfidence.VERY_HIGH,
                'variants': ['vmprotect_3x', 'vmprotect_ultimate'],
                'bypass_recommendations': [
                    'Dynamic analysis with VMProtect-aware tools',
                    'Devirtualization using specialized tools',
                    'Memory patching of virtual machine handlers'
                ]
            },
            
            'denuvo': {
                'patterns': [
                    b'denuvo',
                    b'Denuvo',
                    rb'\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x70\x10',
                    b'Steam_api64.dll',
                    b'activation_required'
                ],
                'type': ProtectionType.DRM,
                'confidence': DetectionConfidence.HIGH,
                'variants': ['denuvo_5x', 'denuvo_6x', 'denuvo_7x'],
                'bypass_recommendations': [
                    'Requires game-specific cracks',
                    'VM analysis for trigger identification',
                    'Hardware fingerprint spoofing'
                ]
            },
            
            'aspack': {
                'patterns': [
                    b'ASPack',
                    b'aPLib',
                    rb'\x60\xE8.{4}\x5D\x81\xED.{4}\xB9.{4}\x8D\xBD'
                ],
                'type': ProtectionType.PACKER,
                'confidence': DetectionConfidence.HIGH,
                'variants': ['aspack_2x'],
                'bypass_recommendations': [
                    'Generic unpacking with dynamic analysis',
                    'OEP detection and memory dumping'
                ]
            },
            
            'pecompact': {
                'patterns': [
                    b'PECompact',
                    b'PEC2',
                    rb'\x8B\xC0\x01\x05.{4}\xFF\x35.{4}\x50\xC3'
                ],
                'type': ProtectionType.PACKER,
                'confidence': DetectionConfidence.HIGH,
                'bypass_recommendations': [
                    'PECompact-specific unpackers',
                    'Dynamic unpacking techniques'
                ]
            },
            
            'enigma': {
                'patterns': [
                    b'The Enigma Protector',
                    b'enigma',
                    rb'\x55\x8B\xEC\x83\xEC\x0C\x53\x56\x57'
                ],
                'type': ProtectionType.PROTECTOR,
                'confidence': DetectionConfidence.HIGH,
                'bypass_recommendations': [
                    'Enigma-specific unpacking tools',
                    'Anti-anti-debug techniques'
                ]
            },
            
            # Anti-Analysis Patterns
            'anti_debug': {
                'patterns': [
                    b'IsDebuggerPresent',
                    b'CheckRemoteDebuggerPresent',
                    b'OutputDebugString',
                    b'GetTickCount',
                    rb'\x64\xA1\x30\x00\x00\x00',  # PEB access
                    rb'\x65\x8B\x15\x30\x00\x00\x00'  # TEB access
                ],
                'type': ProtectionType.PROTECTOR,
                'confidence': DetectionConfidence.MEDIUM,
                'bypass_recommendations': [
                    'Use ScyllaHide or TitanHide',
                    'Patch anti-debug checks',
                    'Use kernel-mode debugging'
                ]
            },
            
            'anti_vm': {
                'patterns': [
                    b'VMware',
                    b'VirtualBox',
                    b'VBOX',
                    b'vmmouse',
                    b'vmhgfs',
                    rb'\x0F\x01\xD0',  # SGDT instruction
                    rb'\x0F\x01\xC8'   # SIDT instruction
                ],
                'type': ProtectionType.PROTECTOR,
                'confidence': DetectionConfidence.MEDIUM,
                'bypass_recommendations': [
                    'VM evasion with pafish techniques',
                    'Hardware virtualization hiding',
                    'Registry and file system spoofing'
                ]
            }
        }
    
    def scan_signatures(self, data: bytes) -> List[DetectionResult]:
        """Scan for protection signatures"""
        detections = []
        
        for protection_name, sig_info in self.signatures.items():
            confidence = 0.0
            matched_patterns = []
            
            # Check each pattern
            for pattern in sig_info['patterns']:
                if isinstance(pattern, bytes):
                    if pattern in data:
                        matched_patterns.append(pattern)
                        confidence += 25.0
                else:
                    # Regex pattern
                    import re
                    if re.search(pattern, data):
                        matched_patterns.append(pattern)
                        confidence += 30.0
            
            # If we have matches, create detection
            if matched_patterns:
                final_confidence = min(confidence, sig_info['confidence'].value)
                
                detection = DetectionResult(
                    name=protection_name.replace('_', ' ').title(),
                    type=sig_info['type'],
                    confidence=final_confidence,
                    details={
                        'matched_patterns': len(matched_patterns),
                        'variants': sig_info.get('variants', [])
                    },
                    bypass_recommendations=sig_info.get('bypass_recommendations', [])
                )
                detections.append(detection)
        
        return detections


class ImportTableAnalyzer:
    """Advanced import table analysis for API obfuscation detection"""
    
    def __init__(self):
        self.suspicious_apis = {
            # Anti-debugging APIs
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugString',
            'GetTickCount', 'timeGetTime', 'QueryPerformanceCounter',
            
            # Dynamic loading APIs
            'LoadLibrary', 'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryEx',
            'GetProcAddress', 'LdrLoadDll', 'LdrGetProcedureAddress',
            
            # Memory manipulation
            'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
            'ReadProcessMemory', 'CreateRemoteThread',
            
            # Process manipulation
            'CreateProcess', 'ShellExecute', 'WinExec',
            
            # Registry access
            'RegOpenKey', 'RegCreateKey', 'RegSetValue', 'RegQueryValue',
            
            # File operations
            'CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile',
            
            # Network operations
            'WSAStartup', 'socket', 'connect', 'send', 'recv',
            'InternetOpen', 'InternetConnect', 'HttpOpenRequest'
        }
        
    def analyze_imports(self, file_path: str) -> ImportTableAnalysis:
        """Analyze import table for obfuscation indicators"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            if not self._is_pe_file(data):
                return self._create_empty_analysis()
                
            imports = self._extract_imports(data)
            
            # Analyze imports
            total_imports = len(imports)
            suspicious_apis = [api for api in imports if api in self.suspicious_apis]
            obfuscated_imports = self._detect_obfuscated_imports(imports)
            dynamic_indicators = self._detect_dynamic_loading(imports)
            
            # Calculate scores
            api_redirection_score = self._calculate_api_redirection_score(imports)
            import_entropy = self._calculate_import_entropy(imports)
            obfuscation_probability = self._calculate_obfuscation_probability(
                total_imports, len(suspicious_apis), len(obfuscated_imports), 
                api_redirection_score, import_entropy
            )
            
            return ImportTableAnalysis(
                total_imports=total_imports,
                suspicious_apis=suspicious_apis,
                obfuscated_imports=obfuscated_imports,
                dynamic_loading_indicators=dynamic_indicators,
                api_redirection_score=api_redirection_score,
                import_entropy=import_entropy,
                obfuscation_probability=obfuscation_probability
            )
            
        except Exception as e:
            logger.error(f"Import analysis failed for {file_path}: {e}")
            return self._create_empty_analysis()
    
    def _is_pe_file(self, data: bytes) -> bool:
        """Check if file is PE format"""
        return len(data) > 64 and data.startswith(b'MZ')
    
    def _extract_imports(self, data: bytes) -> List[str]:
        """Extract import function names from PE file"""
        imports = []
        
        try:
            # Basic PE import parsing
            if len(data) < 1024:
                return imports
                
            # Get PE header offset
            pe_offset = struct.unpack('<L', data[60:64])[0]
            if pe_offset + 248 > len(data):
                return imports
                
            # Get import table RVA
            import_table_rva = struct.unpack('<L', data[pe_offset + 128:pe_offset + 132])[0]
            if import_table_rva == 0:
                return imports
                
            # Convert RVA to file offset (simplified)
            import_offset = self._rva_to_offset(data, import_table_rva)
            if import_offset == 0:
                return imports
                
            # Parse import descriptors
            descriptor_offset = import_offset
            while descriptor_offset + 20 <= len(data):
                # Read import descriptor
                descriptor = data[descriptor_offset:descriptor_offset + 20]
                name_rva = struct.unpack('<L', descriptor[12:16])[0]
                
                if name_rva == 0:  # End of descriptors
                    break
                    
                # Get DLL name
                name_offset = self._rva_to_offset(data, name_rva)
                if name_offset > 0:
                    dll_name = self._read_cstring(data, name_offset)
                    
                    # Get function names from this DLL
                    thunk_rva = struct.unpack('<L', descriptor[16:20])[0]
                    if thunk_rva > 0:
                        dll_imports = self._parse_import_thunks(data, thunk_rva)
                        imports.extend(dll_imports)
                
                descriptor_offset += 20
                
        except Exception as e:
            logger.debug(f"Import extraction error: {e}")
            
        return imports
    
    def _rva_to_offset(self, data: bytes, rva: int) -> int:
        """Convert RVA to file offset (simplified)"""
        try:
            # Get PE header offset
            pe_offset = struct.unpack('<L', data[60:64])[0]
            
            # Get number of sections
            num_sections = struct.unpack('<H', data[pe_offset + 6:pe_offset + 8])[0]
            
            # Section headers start after PE header
            section_offset = pe_offset + 248
            
            # Find section containing this RVA
            for i in range(num_sections):
                if section_offset + 40 > len(data):
                    break
                    
                virtual_address = struct.unpack('<L', data[section_offset + 12:section_offset + 16])[0]
                virtual_size = struct.unpack('<L', data[section_offset + 8:section_offset + 12])[0]
                raw_offset = struct.unpack('<L', data[section_offset + 20:section_offset + 24])[0]
                
                if virtual_address <= rva < virtual_address + virtual_size:
                    return raw_offset + (rva - virtual_address)
                    
                section_offset += 40
                
        except Exception:
            pass
            
        return 0
    
    def _read_cstring(self, data: bytes, offset: int) -> str:
        """Read null-terminated string"""
        try:
            end = data.find(b'\x00', offset)
            if end == -1:
                end = len(data)
            return data[offset:end].decode('ascii', errors='ignore')
        except Exception:
            return ""
    
    def _parse_import_thunks(self, data: bytes, thunk_rva: int) -> List[str]:
        """Parse import thunks to get function names"""
        functions = []
        
        try:
            thunk_offset = self._rva_to_offset(data, thunk_rva)
            if thunk_offset == 0:
                return functions
                
            # Read thunks (assuming 32-bit for simplicity)
            current_offset = thunk_offset
            
            for _ in range(1000):  # Limit iterations
                if current_offset + 4 > len(data):
                    break
                    
                thunk_value = struct.unpack('<L', data[current_offset:current_offset + 4])[0]
                if thunk_value == 0:  # End of thunks
                    break
                    
                # Check if import by name (not ordinal)
                if thunk_value & 0x80000000 == 0:
                    # Import by name
                    name_offset = self._rva_to_offset(data, thunk_value + 2)  # Skip hint
                    if name_offset > 0:
                        func_name = self._read_cstring(data, name_offset)
                        if func_name:
                            functions.append(func_name)
                
                current_offset += 4
                
        except Exception as e:
            logger.debug(f"Thunk parsing error: {e}")
            
        return functions
    
    def _detect_obfuscated_imports(self, imports: List[str]) -> List[str]:
        """Detect potentially obfuscated imports"""
        obfuscated = []
        
        for import_name in imports:
            # Check for suspicious naming patterns
            if (len(import_name) < 3 or 
                any(char in import_name for char in '!@#$%^&*()+={}[]|\\:";\'<>?,./') or
                import_name.isdigit() or
                import_name.startswith('_') and len(import_name) > 10):
                obfuscated.append(import_name)
                
        return obfuscated
    
    def _detect_dynamic_loading(self, imports: List[str]) -> List[str]:
        """Detect dynamic loading indicators"""
        dynamic_indicators = []
        
        dynamic_apis = {
            'LoadLibrary', 'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryEx',
            'GetProcAddress', 'LdrLoadDll', 'LdrGetProcedureAddress'
        }
        
        for api in dynamic_apis:
            if api in imports:
                dynamic_indicators.append(api)
                
        return dynamic_indicators
    
    def _calculate_api_redirection_score(self, imports: List[str]) -> float:
        """Calculate API redirection probability score"""
        score = 0.0
        
        # Check for common redirection patterns
        redirection_apis = [
            'GetProcAddress', 'LoadLibrary', 'SetWindowsHookEx',
            'CreateThread', 'VirtualAlloc'
        ]
        
        for api in redirection_apis:
            if api in imports:
                score += 15.0
                
        # Check import/export ratio (low ratio suggests hiding)
        if len(imports) < 10:
            score += 20.0
        elif len(imports) < 5:
            score += 40.0
            
        return min(score, 100.0)
    
    def _calculate_import_entropy(self, imports: List[str]) -> float:
        """Calculate entropy of import names"""
        if not imports:
            return 0.0
            
        # Combine all import names
        import_text = ''.join(imports).lower()
        
        if not import_text:
            return 0.0
            
        # Calculate character frequency entropy
        char_counts = Counter(import_text)
        total_chars = len(import_text)
        
        entropy = 0.0
        for count in char_counts.values():
            probability = count / total_chars
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def _calculate_obfuscation_probability(self, total_imports: int, 
                                         suspicious_count: int,
                                         obfuscated_count: int,
                                         redirection_score: float,
                                         import_entropy: float) -> float:
        """Calculate overall import obfuscation probability"""
        score = 0.0
        
        # Low import count suggests hiding
        if total_imports < 5:
            score += 30.0
        elif total_imports < 10:
            score += 15.0
            
        # High suspicious API ratio
        if total_imports > 0:
            suspicious_ratio = suspicious_count / total_imports
            score += suspicious_ratio * 25.0
            
        # Obfuscated imports
        if obfuscated_count > 0:
            score += min(obfuscated_count * 10.0, 30.0)
            
        # API redirection score
        score += redirection_score * 0.3
        
        # Unusual entropy
        if import_entropy > 4.0:  # High entropy suggests obfuscation
            score += 20.0
        elif import_entropy < 2.0:  # Very low entropy also suspicious
            score += 15.0
            
        return min(score, 100.0)
    
    def _create_empty_analysis(self) -> ImportTableAnalysis:
        """Create empty import analysis for error cases"""
        return ImportTableAnalysis(
            total_imports=0,
            suspicious_apis=[],
            obfuscated_imports=[],
            dynamic_loading_indicators=[],
            api_redirection_score=0.0,
            import_entropy=0.0,
            obfuscation_probability=0.0
        )
class AntiAnalysisDetector:
    """Advanced anti-analysis technique detection"""
    
    def __init__(self):
        self.anti_debug_patterns = {
            # API-based detection
            'IsDebuggerPresent': b'IsDebuggerPresent',
            'CheckRemoteDebuggerPresent': b'CheckRemoteDebuggerPresent',
            'OutputDebugString': b'OutputDebugString',
            
            # Manual PEB checks
            'peb_being_debugged': rb'\x64\xA1\x30\x00\x00\x00\x8A\x40\x02',
            'peb_flags': rb'\x64\xA1\x30\x00\x00\x00\x8B\x40\x68',
            
            # Timing-based detection
            'rdtsc': rb'\x0F\x31',  # RDTSC instruction
            'get_tick_count': b'GetTickCount',
            'query_performance_counter': b'QueryPerformanceCounter',
            
            # Exception-based detection
            'int3_detection': rb'\xCC',  # INT3 breakpoint
            'icebp': rb'\xF1',  # ICEBP instruction
            
            # Hardware breakpoint detection
            'dr_registers': rb'\x0F\x21',  # MOV reg, DRx
        }
        
        self.anti_vm_patterns = {
            # VM artifacts
            'vmware_detection': [
                b'VMware', b'vmware', b'VMWARE',
                b'VMXh', b'VBoxService', b'vmmouse',
                b'vmhgfs', b'vboxmouse'
            ],
            'virtualbox_detection': [
                b'VirtualBox', b'VBOX', b'VBoxGuest',
                b'VBoxMouse', b'VBoxVideo'
            ],
            'qemu_detection': [
                b'QEMU', b'qemu', b'BOCHS'
            ],
            
            # VM-specific instructions
            'cpuid_vm_check': rb'\x0F\xA2',  # CPUID
            'sgdt': rb'\x0F\x01\xD0',  # SGDT
            'sidt': rb'\x0F\x01\xC8',  # SIDT
            'sldt': rb'\x0F\x00\xC0',  # SLDT
            
            # VM registry keys
            'vm_registry': [
                b'HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware',
                b'HKEY_LOCAL_MACHINE\\SOFTWARE\\Oracle\\VirtualBox'
            ]
        }
        
        self.timing_attack_patterns = {
            # Time measurement functions
            'rdtsc_timing': rb'\x0F\x31.*?\x0F\x31',  # Multiple RDTSC
            'gettickcount_timing': b'GetTickCount.*GetTickCount',
            
            # Sleep/delay functions
            'sleep_delay': [b'Sleep', b'WaitForSingleObject', b'timeBeginPeriod'],
            
            # Performance counter timing
            'perf_counter_timing': b'QueryPerformanceCounter.*QueryPerformanceCounter'
        }
        
        self.environment_checks = {
            # System information gathering
            'system_info': [
                b'GetSystemInfo', b'GetComputerName', b'GetUserName',
                b'GetVersionEx', b'GlobalMemoryStatus'
            ],
            
            # Process enumeration
            'process_enum': [
                b'CreateToolhelp32Snapshot', b'Process32First', b'Process32Next',
                b'EnumProcesses', b'GetModuleFileName'
            ],
            
            # File system checks
            'file_checks': [
                b'GetFileAttributes', b'FindFirstFile', b'GetDriveType'
            ],
            
            # Network checks
            'network_checks': [
                b'GetAdaptersInfo', b'gethostname', b'GetComputerNameEx'
            ]
        }
    
    def detect_anti_analysis(self, file_path: str) -> AntiAnalysisFindings:
        """Detect anti-analysis techniques"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            anti_debug = self._detect_anti_debug(data)
            anti_vm = self._detect_anti_vm(data)
            timing_attacks = self._detect_timing_attacks(data)
            env_checks = self._detect_environment_checks(data)
            
            # Calculate scores
            evasion_score = self._calculate_evasion_score(
                len(anti_debug), len(anti_vm), len(timing_attacks), len(env_checks)
            )
            detection_probability = self._calculate_detection_probability(evasion_score)
            
            return AntiAnalysisFindings(
                anti_debug_techniques=anti_debug,
                anti_vm_techniques=anti_vm,
                timing_attack_patterns=timing_attacks,
                environment_checks=env_checks,
                evasion_score=evasion_score,
                detection_probability=detection_probability
            )
            
        except Exception as e:
            logger.error(f"Anti-analysis detection failed for {file_path}: {e}")
            return self._create_empty_findings()
    
    def _detect_anti_debug(self, data: bytes) -> List[str]:
        """Detect anti-debugging techniques"""
        techniques = []
        
        for name, pattern in self.anti_debug_patterns.items():
            if isinstance(pattern, bytes):
                if pattern in data:
                    techniques.append(name)
            else:
                # Regex pattern
                import re
                if re.search(pattern, data):
                    techniques.append(name)
                    
        return techniques
    
    def _detect_anti_vm(self, data: bytes) -> List[str]:
        """Detect anti-VM techniques"""
        techniques = []
        
        for category, patterns in self.anti_vm_patterns.items():
            if isinstance(patterns, list):
                for pattern in patterns:
                    if pattern in data:
                        techniques.append(f"{category}_{pattern.decode('ascii', errors='ignore')}")
                        break
            elif isinstance(patterns, bytes):
                if patterns in data:
                    techniques.append(category)
                    
        return techniques
    
    def _detect_timing_attacks(self, data: bytes) -> List[str]:
        """Detect timing-based anti-analysis"""
        attacks = []
        
        for name, pattern in self.timing_attack_patterns.items():
            if isinstance(pattern, bytes):
                if pattern in data:
                    attacks.append(name)
            elif isinstance(pattern, list):
                for p in pattern:
                    if p in data:
                        attacks.append(f"{name}_{p.decode('ascii', errors='ignore')}")
            else:
                # Regex pattern
                import re
                if re.search(pattern, data):
                    attacks.append(name)
                    
        return attacks
    
    def _detect_environment_checks(self, data: bytes) -> List[str]:
        """Detect environment checking techniques"""
        checks = []
        
        for category, patterns in self.environment_checks.items():
            found_apis = []
            for pattern in patterns:
                if pattern in data:
                    found_apis.append(pattern.decode('ascii', errors='ignore'))
            
            if found_apis:
                checks.append(f"{category}: {', '.join(found_apis[:3])}")  # Limit output
                
        return checks
    
    def _calculate_evasion_score(self, debug_count: int, vm_count: int, 
                                timing_count: int, env_count: int) -> float:
        """Calculate overall evasion sophistication score"""
        score = 0.0
        
        # Anti-debug techniques
        score += min(debug_count * 15.0, 60.0)
        
        # Anti-VM techniques
        score += min(vm_count * 12.0, 48.0)
        
        # Timing attacks
        score += min(timing_count * 10.0, 30.0)
        
        # Environment checks
        score += min(env_count * 8.0, 24.0)
        
        return min(score, 100.0)
    
    def _calculate_detection_probability(self, evasion_score: float) -> float:
        """Calculate probability of anti-analysis presence"""
        # High evasion score indicates likely anti-analysis
        if evasion_score > 70.0:
            return 95.0
        elif evasion_score > 50.0:
            return 80.0
        elif evasion_score > 30.0:
            return 60.0
        elif evasion_score > 15.0:
            return 40.0
        else:
            return evasion_score
    
    def _create_empty_findings(self) -> AntiAnalysisFindings:
        """Create empty findings for error cases"""
        return AntiAnalysisFindings(
            anti_debug_techniques=[],
            anti_vm_techniques=[],
            timing_attack_patterns=[],
            environment_checks=[],
            evasion_score=0.0,
            detection_probability=0.0
        )


class BehavioralHeuristicsEngine:
    """Sophisticated behavioral analysis and heuristics"""
    
    def __init__(self):
        self.structure_analyzers = {
            'pe_analyzer': self._analyze_pe_structure,
            'elf_analyzer': self._analyze_elf_structure,
            'section_analyzer': self._analyze_section_anomalies
        }
        
    def analyze_behavior(self, file_path: str, entropy_metrics: EntropyMetrics) -> BehavioralIndicators:
        """Perform comprehensive behavioral analysis"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Detect file format
            file_format = self._detect_file_format(data)
            
            # Analyze structure anomalies
            structure_anomalies = self._analyze_file_structure(data, file_format)
            
            # Analyze code flow patterns
            code_patterns = self._analyze_code_patterns(data)
            
            # Detect packing indicators
            packing_indicators = self._detect_packing_indicators(data, entropy_metrics)
            
            # Detect protection indicators
            protection_indicators = self._detect_protection_indicators(data)
            
            # Calculate complexity score
            complexity_score = self._calculate_complexity_score(
                structure_anomalies, code_patterns, packing_indicators, protection_indicators
            )
            
            # Determine sophistication level
            sophistication = self._determine_sophistication_level(complexity_score, entropy_metrics)
            
            return BehavioralIndicators(
                file_structure_anomalies=structure_anomalies,
                code_flow_patterns=code_patterns,
                packing_indicators=packing_indicators,
                protection_indicators=protection_indicators,
                complexity_score=complexity_score,
                sophistication_level=sophistication
            )
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed for {file_path}: {e}")
            return self._create_empty_indicators()
    
    def _detect_file_format(self, data: bytes) -> str:
        """Detect file format"""
        if len(data) < 16:
            return "unknown"
            
        if data.startswith(b'MZ'):
            return "pe"
        elif data.startswith(b'\x7fELF'):
            return "elf"
        elif data.startswith(b'\xCA\xFE\xBA\xBE'):
            return "macho"
        else:
            return "unknown"
    
    def _analyze_file_structure(self, data: bytes, file_format: str) -> List[str]:
        """Analyze file structure for anomalies"""
        anomalies = []
        
        if file_format in self.structure_analyzers:
            analyzer = self.structure_analyzers[file_format]
            anomalies.extend(analyzer(data))
            
        # Generic structure checks
        anomalies.extend(self._generic_structure_checks(data))
        
        return anomalies
    
    def _analyze_pe_structure(self, data: bytes) -> List[str]:
        """Analyze PE structure anomalies"""
        anomalies = []
        
        try:
            if len(data) < 1024:
                return ["file_too_small"]
                
            # Get PE header offset
            pe_offset = struct.unpack('<L', data[60:64])[0]
            if pe_offset > len(data) - 248:
                anomalies.append("invalid_pe_header_offset")
                return anomalies
                
            # Check PE signature
            pe_signature = data[pe_offset:pe_offset + 4]
            if pe_signature != b'PE\x00\x00':
                anomalies.append("invalid_pe_signature")
                
            # Check number of sections
            num_sections = struct.unpack('<H', data[pe_offset + 6:pe_offset + 8])[0]
            if num_sections == 0:
                anomalies.append("no_sections")
            elif num_sections > 96:  # Unusual number of sections
                anomalies.append("excessive_sections")
                
            # Check entry point
            entry_point = struct.unpack('<L', data[pe_offset + 40:pe_offset + 44])[0]
            if entry_point == 0:
                anomalies.append("no_entry_point")
                
            # Check section characteristics
            section_offset = pe_offset + 248
            for i in range(min(num_sections, 20)):
                if section_offset + 40 > len(data):
                    break
                    
                characteristics = struct.unpack('<L', data[section_offset + 36:section_offset + 40])[0]
                
                # Executable + Writable sections are suspicious
                if (characteristics & 0x20000000) and (characteristics & 0x80000000):
                    anomalies.append("executable_writable_section")
                    
                section_offset += 40
                
        except Exception as e:
            logger.debug(f"PE structure analysis error: {e}")
            anomalies.append("pe_parsing_error")
            
        return anomalies
    
    def _analyze_elf_structure(self, data: bytes) -> List[str]:
        """Analyze ELF structure anomalies"""
        anomalies = []
        
        try:
            if len(data) < 64:
                return ["file_too_small"]
                
            # Check ELF class
            elf_class = data[4]
            if elf_class not in [1, 2]:  # 32-bit or 64-bit
                anomalies.append("invalid_elf_class")
                
            # Check entry point
            if elf_class == 2:  # 64-bit
                entry_point = struct.unpack('<Q', data[24:32])[0]
            else:  # 32-bit
                entry_point = struct.unpack('<L', data[24:28])[0]
                
            if entry_point == 0:
                anomalies.append("no_entry_point")
                
        except Exception as e:
            logger.debug(f"ELF structure analysis error: {e}")
            anomalies.append("elf_parsing_error")
            
        return anomalies
    
    def _analyze_section_anomalies(self, data: bytes) -> List[str]:
        """Analyze section-level anomalies"""
        anomalies = []
        
        # Check for suspicious section names
        suspicious_names = [b'UPX', b'.ASPack', b'.Themida', b'.VMProtect']
        for name in suspicious_names:
            if name in data:
                anomalies.append(f"suspicious_section_{name.decode('ascii', errors='ignore')}")
                
        return anomalies
    
    def _generic_structure_checks(self, data: bytes) -> List[str]:
        """Generic structure checks for all file types"""
        anomalies = []
        
        # Check for overlay
        file_size = len(data)
        if file_size > 10 * 1024 * 1024:  # Files larger than 10MB
            # Check if there's significant data at the end
            tail_data = data[-1024:]
            if b'\x00' * 512 not in tail_data:  # No large null blocks
                anomalies.append("possible_overlay")
                
        # Check for embedded files
        embedded_signatures = [b'MZ', b'PK\x03\x04', b'\x7fELF', b'\xCA\xFE\xBA\xBE']
        signature_count = 0
        for sig in embedded_signatures:
            signature_count += data.count(sig)
            
        if signature_count > 2:  # More than expected
            anomalies.append("embedded_files_detected")
            
        return anomalies
    
    def _analyze_code_patterns(self, data: bytes) -> List[str]:
        """Analyze code flow patterns"""
        patterns = []
        
        # Look for obfuscation patterns
        obfuscation_patterns = [
            rb'\x50\x58',  # PUSH EAX, POP EAX (no-op)
            rb'\x90+',     # Multiple NOPs
            rb'\xEB\x01',  # Short jump over next instruction
            rb'\x74\x03\x75\x01',  # Conditional jump patterns
        ]
        
        for pattern in obfuscation_patterns:
            import re
            if re.search(pattern, data):
                patterns.append(f"obfuscation_pattern_{pattern.hex()[:8]}")
                
        # Look for control flow patterns
        if b'\xC3' in data:  # RET instructions
            ret_count = data.count(b'\xC3')
            if ret_count > len(data) // 1000:  # Many returns
                patterns.append("excessive_returns")
                
        return patterns
    
    def _detect_packing_indicators(self, data: bytes, entropy_metrics: EntropyMetrics) -> List[str]:
        """Detect packing indicators"""
        indicators = []
        
        # High entropy sections
        if entropy_metrics.high_entropy_sections:
            indicators.append(f"high_entropy_sections_{len(entropy_metrics.high_entropy_sections)}")
            
        # Low compression ratio
        if entropy_metrics.compression_ratio < 0.4:
            indicators.append("low_compression_ratio")
            
        # Entropy variance
        if entropy_metrics.entropy_variance > 1.0:
            indicators.append("high_entropy_variance")
            
        # Small import table (often indicates packing)
        import_patterns = [b'kernel32.dll', b'ntdll.dll', b'LoadLibrary', b'GetProcAddress']
        import_count = sum(1 for pattern in import_patterns if pattern in data)
        
        if import_count < 2:
            indicators.append("minimal_imports")
            
        return indicators
    
    def _detect_protection_indicators(self, data: bytes) -> List[str]:
        """Detect protection scheme indicators"""
        indicators = []
        
        # Licensing patterns
        license_patterns = [
            b'license', b'activation', b'trial', b'demo',
            b'registration', b'serial', b'crack', b'keygen'
        ]
        
        for pattern in license_patterns:
            if pattern.lower() in data.lower():
                indicators.append(f"licensing_{pattern.decode('ascii')}")
                
        # DRM patterns
        drm_patterns = [
            b'Denuvo', b'Steam', b'Origin', b'Uplay',
            b'activation_required', b'online_verification'
        ]
        
        for pattern in drm_patterns:
            if pattern in data:
                indicators.append(f"drm_{pattern.decode('ascii', errors='ignore')}")
                
        return indicators
    
    def _calculate_complexity_score(self, structure_anomalies: List[str],
                                  code_patterns: List[str],
                                  packing_indicators: List[str],
                                  protection_indicators: List[str]) -> float:
        """Calculate overall complexity score"""
        score = 0.0
        
        # Structure anomalies
        score += len(structure_anomalies) * 10.0
        
        # Code patterns
        score += len(code_patterns) * 8.0
        
        # Packing indicators
        score += len(packing_indicators) * 12.0
        
        # Protection indicators
        score += len(protection_indicators) * 15.0
        
        return min(score, 100.0)
    
    def _determine_sophistication_level(self, complexity_score: float, 
                                      entropy_metrics: EntropyMetrics) -> str:
        """Determine sophistication level"""
        if complexity_score > 80.0 or entropy_metrics.packed_probability > 90.0:
            return "Very High"
        elif complexity_score > 60.0 or entropy_metrics.packed_probability > 70.0:
            return "High"
        elif complexity_score > 40.0 or entropy_metrics.packed_probability > 50.0:
            return "Medium"
        elif complexity_score > 20.0 or entropy_metrics.packed_probability > 30.0:
            return "Low"
        else:
            return "Very Low"
    
    def _create_empty_indicators(self) -> BehavioralIndicators:
        """Create empty indicators for error cases"""
        return BehavioralIndicators(
            file_structure_anomalies=[],
            code_flow_patterns=[],
            packing_indicators=[],
            protection_indicators=[],
            complexity_score=0.0,
            sophistication_level="Unknown"
        )


class AdvancedDetectionEngine:
    """Main orchestrator for advanced protection detection"""
    
    def __init__(self, enable_all_layers: bool = True, entropy_mode: EntropyAnalysisMode = EntropyAnalysisMode.STANDARD):
        """Initialize advanced detection engine"""
        self.enable_all_layers = enable_all_layers
        self.entropy_mode = entropy_mode
        
        # Initialize analysis components
        self.entropy_analyzer = AdvancedEntropyAnalyzer()
        self.signature_detector = ModernProtectionSignatures()
        self.import_analyzer = ImportTableAnalyzer()
        self.anti_analysis_detector = AntiAnalysisDetector()
        self.behavioral_engine = BehavioralHeuristicsEngine()
        
        # Initialize sophisticated entropy-based packer detector
        self.entropy_packer_detector = SophisticatedEntropyPackerDetector(entropy_mode)
        
        logger.info(f"Advanced Detection Engine initialized with entropy mode: {entropy_mode.value}")
    
    def analyze(self, file_path: str, deep_analysis: bool = True) -> AdvancedDetectionResult:
        """Perform comprehensive advanced detection analysis"""
        start_time = time.time()
        
        logger.info(f"Starting advanced detection analysis of {file_path}")
        
        try:
            # Read file data
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Initialize result
            all_detections = []
            
            # Layer 1: Sophisticated entropy-based packer detection
            logger.debug("Performing sophisticated entropy analysis...")
            
            # Use the new sophisticated entropy packer detector
            entropy_detections = integrate_with_protection_core(file_path, self.entropy_mode)
            all_detections.extend(entropy_detections)
            
            # Get detailed entropy analysis for other layers
            entropy_result = self.entropy_packer_detector.analyze_file(file_path, enable_ml=True)
            entropy_metrics = entropy_result.metrics
            
            # Add comprehensive entropy-based detection if sophisticated analysis finds packing
            if entropy_result.is_packed and entropy_result.confidence_score > 0.6:
                detection = DetectionResult(
                    name=f"Sophisticated Entropy Analysis - {entropy_result.packer_family.value.title()}",
                    type=ProtectionType.PACKER,
                    confidence=entropy_result.confidence_score * 100,
                    details={
                        'packer_family': entropy_result.packer_family.value,
                        'entropy_metrics': {
                            'shannon_entropy': entropy_metrics.shannon_entropy,
                            'compression_ratio': entropy_metrics.compression_ratio,
                            'entropy_variance': entropy_metrics.entropy_variance,
                            'high_entropy_sections': entropy_metrics.high_entropy_sections,
                            'anomalous_regions': len(entropy_result.anomalous_regions)
                        },
                        'ml_features_used': True,
                        'false_positive_probability': entropy_result.false_positive_probability,
                        'confidence_breakdown': entropy_result.confidence_breakdown
                    },
                    bypass_recommendations=entropy_result.unpacking_recommendations
                )
                all_detections.append(detection)
            
            # Layer 2: Advanced signature detection
            logger.debug("Performing signature analysis...")
            signature_detections = self.signature_detector.scan_signatures(data)
            all_detections.extend(signature_detections)
            
            # Layer 3: Import table obfuscation analysis
            logger.debug("Performing import table analysis...")
            import_analysis = self.import_analyzer.analyze_imports(file_path)
            
            if import_analysis.obfuscation_probability > 60.0:
                detection = DetectionResult(
                    name="Import Table Obfuscation",
                    type=ProtectionType.PROTECTOR,
                    confidence=import_analysis.obfuscation_probability,
                    details={
                        'suspicious_apis': import_analysis.suspicious_apis,
                        'obfuscated_imports': import_analysis.obfuscated_imports,
                        'dynamic_loading': import_analysis.dynamic_loading_indicators
                    },
                    bypass_recommendations=[
                        "API call tracing and reconstruction",
                        "Dynamic import resolution monitoring"
                    ]
                )
                all_detections.append(detection)
            
            # Layer 4: Anti-analysis technique detection
            logger.debug("Performing anti-analysis detection...")
            anti_analysis = self.anti_analysis_detector.detect_anti_analysis(file_path)
            
            if anti_analysis.detection_probability > 50.0:
                detection = DetectionResult(
                    name="Anti-Analysis Techniques",
                    type=ProtectionType.PROTECTOR,
                    confidence=anti_analysis.detection_probability,
                    details={
                        'anti_debug': anti_analysis.anti_debug_techniques,
                        'anti_vm': anti_analysis.anti_vm_techniques,
                        'timing_attacks': anti_analysis.timing_attack_patterns,
                        'env_checks': anti_analysis.environment_checks
                    },
                    bypass_recommendations=[
                        "Use ScyllaHide or TitanHide for anti-debug bypass",
                        "VM evasion with hardware virtualization hiding",
                        "Timing attack mitigation with controlled execution"
                    ]
                )
                all_detections.append(detection)
            
            # Layer 5: Enhanced behavioral analysis with entropy correlation
            if deep_analysis:
                logger.debug("Performing enhanced behavioral analysis...")
                # Use entropy metrics from sophisticated detector
                behavioral = self.behavioral_engine.analyze_behavior(file_path, entropy_metrics)
                
                # Enhance behavioral analysis with sophisticated entropy insights
                if entropy_result.is_packed:
                    # Add entropy-specific behavioral indicators
                    behavioral.packing_indicators.extend([
                        f"Entropy family: {entropy_result.packer_family.value}",
                        f"ML confidence: {entropy_result.confidence_breakdown.get('machine_learning', 0):.1f}%",
                        f"Anomalous regions: {len(entropy_result.anomalous_regions)}"
                    ])
                    
                    # Adjust complexity score based on entropy analysis
                    entropy_complexity_boost = min(entropy_result.confidence_score * 20, 30.0)
                    behavioral.complexity_score += entropy_complexity_boost
                
                if behavioral.complexity_score > 40.0:
                    detection = DetectionResult(
                        name=f"Enhanced Behavioral Complexity - {behavioral.sophistication_level}",
                        type=ProtectionType.PROTECTOR,
                        confidence=min(behavioral.complexity_score, 95.0),
                        details={
                            'structure_anomalies': behavioral.file_structure_anomalies,
                            'code_patterns': behavioral.code_flow_patterns,
                            'protection_indicators': behavioral.protection_indicators,
                            'entropy_enhanced': True,
                            'entropy_insights': {
                                'packer_family': entropy_result.packer_family.value,
                                'anomalous_regions': len(entropy_result.anomalous_regions),
                                'entropy_transitions': len(entropy_metrics.entropy_transitions)
                            }
                        },
                        bypass_recommendations=[
                            "Comprehensive structural analysis with entropy monitoring",
                            "Multi-stage unpacking approach guided by entropy transitions",
                            "Behavioral pattern emulation with sophisticated entropy awareness"
                        ] + entropy_result.bypass_strategies
                    )
                    all_detections.append(detection)
            else:
                # Quick behavioral check with basic entropy metrics
                behavioral = self.behavioral_engine.analyze_behavior(file_path, entropy_metrics)
                if not hasattr(behavioral, 'sophistication_level'):
                    behavioral.sophistication_level = "Quick Analysis"
            
            # Calculate overall metrics
            overall_confidence = self._calculate_overall_confidence(all_detections)
            protection_layers = len([d for d in all_detections if d.confidence > 60.0])
            evasion_sophistication = self._determine_evasion_sophistication(
                anti_analysis.evasion_score, behavioral.sophistication_level
            )
            
            analysis_time = time.time() - start_time
            
            result = AdvancedDetectionResult(
                file_path=file_path,
                entropy_metrics=entropy_metrics,
                import_analysis=import_analysis,
                anti_analysis=anti_analysis,
                behavioral=behavioral,
                detections=all_detections,
                overall_confidence=overall_confidence,
                protection_layers=protection_layers,
                evasion_sophistication=evasion_sophistication,
                analysis_time=analysis_time
            )
            
            logger.info(f"Advanced detection completed in {analysis_time:.2f}s - "
                       f"Found {len(all_detections)} detections with {overall_confidence:.1f}% confidence")
            
            return result
            
        except Exception as e:
            logger.error(f"Advanced detection analysis failed: {e}")
            return self._create_error_result(file_path, str(e))
    
    def _calculate_overall_confidence(self, detections: List[DetectionResult]) -> float:
        """Calculate overall confidence score"""
        if not detections:
            return 0.0
            
        # Weight by detection confidence and type importance
        total_weighted_confidence = 0.0
        total_weight = 0.0
        
        type_weights = {
            ProtectionType.PROTECTOR: 1.0,
            ProtectionType.PACKER: 0.9,
            ProtectionType.DRM: 1.0,
            ProtectionType.LICENSE: 0.8,
            ProtectionType.CRYPTOR: 0.9
        }
        
        for detection in detections:
            weight = type_weights.get(detection.type, 0.7)
            total_weighted_confidence += detection.confidence * weight
            total_weight += weight
            
        return total_weighted_confidence / total_weight if total_weight > 0 else 0.0
    
    def _determine_evasion_sophistication(self, evasion_score: float, 
                                        behavioral_level: str) -> str:
        """Determine overall evasion sophistication"""
        if evasion_score > 80.0 or behavioral_level == "Very High":
            return "Extremely Sophisticated"
        elif evasion_score > 60.0 or behavioral_level == "High":
            return "Highly Sophisticated"
        elif evasion_score > 40.0 or behavioral_level == "Medium":
            return "Moderately Sophisticated"
        elif evasion_score > 20.0 or behavioral_level == "Low":
            return "Basic Sophistication"
        else:
            return "Minimal Sophistication"
    
    def _create_error_result(self, file_path: str, error_msg: str) -> AdvancedDetectionResult:
        """Create error result for failed analysis"""
        return AdvancedDetectionResult(
            file_path=file_path,
            entropy_metrics=EntropyMetrics(
                overall_entropy=0.0,
                section_entropies={},
                sliding_window_entropy=[],
                compression_ratio=1.0,
                entropy_variance=0.0,
                high_entropy_sections=[],
                packed_probability=0.0
            ),
            import_analysis=ImportTableAnalysis(
                total_imports=0,
                suspicious_apis=[],
                obfuscated_imports=[],
                dynamic_loading_indicators=[],
                api_redirection_score=0.0,
                import_entropy=0.0,
                obfuscation_probability=0.0
            ),
            anti_analysis=AntiAnalysisFindings(
                anti_debug_techniques=[],
                anti_vm_techniques=[],
                timing_attack_patterns=[],
                environment_checks=[],
                evasion_score=0.0,
                detection_probability=0.0
            ),
            behavioral=BehavioralIndicators(
                file_structure_anomalies=[error_msg],
                code_flow_patterns=[],
                packing_indicators=[],
                protection_indicators=[],
                complexity_score=0.0,
                sophistication_level="Error"
            ),
            detections=[],
            overall_confidence=0.0,
            protection_layers=0,
            evasion_sophistication="Unknown",
            analysis_time=0.0
        )
    
    def get_analysis_summary(self, result: AdvancedDetectionResult) -> str:
        """Generate human-readable analysis summary"""
        lines = []
        lines.append(f"=== Advanced Protection Analysis ===")
        lines.append(f"File: {os.path.basename(result.file_path)}")
        lines.append(f"Analysis Time: {result.analysis_time:.2f}s")
        lines.append(f"Overall Confidence: {result.overall_confidence:.1f}%")
        lines.append(f"Protection Layers: {result.protection_layers}")
        lines.append(f"Evasion Sophistication: {result.evasion_sophistication}")
        lines.append("")
        
        # Enhanced Entropy Analysis
        lines.append("--- Sophisticated Entropy Analysis ---")
        lines.append(f"Shannon Entropy: {result.entropy_metrics.shannon_entropy:.3f}")
        if hasattr(result.entropy_metrics, 'packed_probability'):
            lines.append(f"Legacy Packed Probability: {result.entropy_metrics.packed_probability:.1f}%")
        lines.append(f"Compression Ratio: {result.entropy_metrics.compression_ratio:.3f}")
        if hasattr(result.entropy_metrics, 'entropy_variance'):
            lines.append(f"Entropy Variance: {result.entropy_metrics.entropy_variance:.3f}")
        if hasattr(result.entropy_metrics, 'entropy_transitions'):
            lines.append(f"Entropy Transitions: {len(result.entropy_metrics.entropy_transitions)}")
        if result.entropy_metrics.high_entropy_sections:
            lines.append(f"High Entropy Sections: {', '.join(result.entropy_metrics.high_entropy_sections)}")
        lines.append("")
        
        # Import Analysis
        lines.append("--- Import Analysis ---")
        lines.append(f"Total Imports: {result.import_analysis.total_imports}")
        lines.append(f"Obfuscation Probability: {result.import_analysis.obfuscation_probability:.1f}%")
        if result.import_analysis.suspicious_apis:
            lines.append(f"Suspicious APIs: {', '.join(result.import_analysis.suspicious_apis[:5])}")
        lines.append("")
        
        # Anti-Analysis
        lines.append("--- Anti-Analysis Detection ---")
        lines.append(f"Evasion Score: {result.anti_analysis.evasion_score:.1f}")
        if result.anti_analysis.anti_debug_techniques:
            lines.append(f"Anti-Debug: {', '.join(result.anti_analysis.anti_debug_techniques[:3])}")
        if result.anti_analysis.anti_vm_techniques:
            lines.append(f"Anti-VM: {', '.join(result.anti_analysis.anti_vm_techniques[:3])}")
        lines.append("")
        
        # Detections
        if result.detections:
            lines.append("--- Protection Detections ---")
            for detection in result.detections:
                lines.append(f"• {detection.name} ({detection.type.value}) - {detection.confidence:.1f}%")
        lines.append("")
        
        return "\n".join(lines)


# Factory functions for easy instantiation
def create_advanced_detection_engine(entropy_mode: EntropyAnalysisMode = EntropyAnalysisMode.STANDARD) -> AdvancedDetectionEngine:
    """Create and return an advanced detection engine instance"""
    return AdvancedDetectionEngine(enable_all_layers=True, entropy_mode=entropy_mode)

def create_fast_detection_engine() -> AdvancedDetectionEngine:
    """Create detection engine optimized for speed"""
    return AdvancedDetectionEngine(enable_all_layers=True, entropy_mode=EntropyAnalysisMode.FAST)

def create_deep_detection_engine() -> AdvancedDetectionEngine:
    """Create detection engine optimized for maximum accuracy"""
    return AdvancedDetectionEngine(enable_all_layers=True, entropy_mode=EntropyAnalysisMode.DEEP)

def create_realtime_detection_engine() -> AdvancedDetectionEngine:
    """Create detection engine optimized for real-time analysis"""
    return AdvancedDetectionEngine(enable_all_layers=True, entropy_mode=EntropyAnalysisMode.REALTIME)


# Global instance for convenient access
_global_advanced_engine = None

def get_advanced_detection_engine() -> AdvancedDetectionEngine:
    """Get or create global advanced detection engine instance"""
    global _global_advanced_engine
    if _global_advanced_engine is None:
        _global_advanced_engine = create_advanced_detection_engine()
    return _global_advanced_engine