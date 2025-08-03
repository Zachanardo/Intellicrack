"""
API Obfuscation Detection Engine

Specialized detection for API call obfuscation techniques including:
- Dynamic API loading (GetProcAddress/LoadLibrary)
- API hashing techniques
- Indirect function calls
- API call redirection
- Import table manipulation

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from ....utils.logger import get_logger

logger = get_logger(__name__)

try:
    import r2pipe
    R2_AVAILABLE = True
except ImportError:
    R2_AVAILABLE = False


@dataclass
class APIPattern:
    """Detected API obfuscation pattern"""
    address: int
    pattern_type: str
    api_name: Optional[str]
    confidence: float
    indicators: List[str]
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': self.address,
            'pattern_type': self.pattern_type,
            'api_name': self.api_name,
            'confidence': self.confidence,
            'indicators': self.indicators,
            'metadata': self.metadata
        }


@dataclass
class ImportTableAnalysis:
    """Import table analysis results"""
    total_imports: int
    direct_imports: int
    suspicious_imports: int
    missing_common_apis: List[str]
    dynamic_loading_apis: List[str]
    obfuscation_indicators: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_imports': self.total_imports,
            'direct_imports': self.direct_imports,
            'suspicious_imports': self.suspicious_imports,
            'missing_common_apis': self.missing_common_apis,
            'dynamic_loading_apis': self.dynamic_loading_apis,
            'obfuscation_indicators': self.obfuscation_indicators
        }


class APIObfuscationDetector:
    """Advanced API obfuscation detection engine"""
    
    def __init__(self, r2_session: Optional[Any] = None):
        """Initialize API obfuscation detector
        
        Args:
            r2_session: Optional radare2 session
        """
        self.r2 = r2_session
        self.logger = logger
        
        # Detection thresholds
        self.hash_confidence_threshold = 0.7
        self.dynamic_loading_threshold = 0.6
        self.indirect_call_threshold = 0.5
        
        # Common API hashing algorithms signatures
        self.hash_algorithms = {
            'ror13': self._detect_ror13_hash,
            'djb2': self._detect_djb2_hash,
            'fnv': self._detect_fnv_hash,
            'crc32': self._detect_crc32_hash,
            'sdbm': self._detect_sdbm_hash
        }
        
        # Known API hash databases (common hashes for reference)
        self.known_api_hashes = self._load_known_api_hashes()
        
    def detect_dynamic_api_loading(self) -> List[APIPattern]:
        """Detect dynamic API loading patterns
        
        Returns:
            List of detected dynamic loading patterns
        """
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            # Get all functions
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                
                # Analyze function for dynamic loading
                loading_pattern = self._analyze_dynamic_loading_function(func_addr)
                if loading_pattern:
                    patterns.append(loading_pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Dynamic API loading detection failed: {e}")
            return []
    
    def detect_api_hashing(self) -> List[APIPattern]:
        """Detect API hashing patterns
        
        Returns:
            List of detected API hashing patterns
        """
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                
                # Analyze function for hash calculation
                hash_patterns = self._analyze_hash_function(func_addr)
                patterns.extend(hash_patterns)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"API hashing detection failed: {e}")
            return []
    
    def detect_indirect_calls(self) -> List[APIPattern]:
        """Detect indirect API call patterns
        
        Returns:
            List of detected indirect call patterns
        """
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                
                # Analyze function for indirect calls
                indirect_patterns = self._analyze_indirect_calls(func_addr)
                patterns.extend(indirect_patterns)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Indirect call detection failed: {e}")
            return []
    
    def analyze_import_table(self) -> ImportTableAnalysis:
        """Analyze import table for manipulation indicators
        
        Returns:
            Import table analysis results
        """
        if not self.r2:
            return ImportTableAnalysis(0, 0, 0, [], [], [])
        
        try:
            # Get imports
            imports = self.r2.cmdj("iij") or []
            
            total_imports = len(imports)
            direct_imports = 0
            suspicious_imports = 0
            missing_common_apis = []
            dynamic_loading_apis = []
            obfuscation_indicators = []
            
            # Analyze each import
            import_names = []
            for imp in imports:
                name = imp.get('name', '')
                import_names.append(name.lower())
                
                # Check for direct vs suspicious imports
                if self._is_direct_import(name):
                    direct_imports += 1
                elif self._is_suspicious_import(name):
                    suspicious_imports += 1
                
                # Check for dynamic loading APIs
                if self._is_dynamic_loading_api(name):
                    dynamic_loading_apis.append(name)
            
            # Check for missing common APIs
            missing_common_apis = self._find_missing_common_apis(import_names)
            
            # Analyze obfuscation indicators
            obfuscation_indicators = self._analyze_import_obfuscation_indicators(
                imports, import_names, dynamic_loading_apis
            )
            
            return ImportTableAnalysis(
                total_imports=total_imports,
                direct_imports=direct_imports,
                suspicious_imports=suspicious_imports,
                missing_common_apis=missing_common_apis,
                dynamic_loading_apis=dynamic_loading_apis,
                obfuscation_indicators=obfuscation_indicators
            )
            
        except Exception as e:
            self.logger.error(f"Import table analysis failed: {e}")
            return ImportTableAnalysis(0, 0, 0, [], [], [])
    
    def detect_api_redirection(self) -> List[APIPattern]:
        """Detect API call redirection patterns
        
        Returns:
            List of detected redirection patterns
        """
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                
                # Check if function is an API wrapper/hook
                if self._is_api_wrapper(func_addr):
                    wrapper_pattern = self._analyze_api_wrapper(func_addr)
                    if wrapper_pattern:
                        patterns.append(wrapper_pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"API redirection detection failed: {e}")
            return []
    
    def _analyze_dynamic_loading_function(self, func_addr: int) -> Optional[APIPattern]:
        """Analyze function for dynamic API loading patterns"""
        if not self.r2:
            return None
        
        try:
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            
            indicators = []
            confidence = 0.0
            metadata = {}
            
            # Check for LoadLibrary calls
            if 'LoadLibrary' in disasm:
                indicators.append('calls_LoadLibrary')
                confidence += 0.4
                metadata['has_loadlibrary'] = True
            
            # Check for GetProcAddress calls
            if 'GetProcAddress' in disasm:
                indicators.append('calls_GetProcAddress')
                confidence += 0.4
                metadata['has_getprocaddress'] = True
            
            # Check for string building (for dynamic API names)
            if self._has_string_building_for_api(disasm):
                indicators.append('dynamic_api_name_building')
                confidence += 0.3
                metadata['builds_api_names'] = True
            
            # Check for loop patterns (resolving multiple APIs)
            if self._has_api_resolution_loop(disasm):
                indicators.append('api_resolution_loop')
                confidence += 0.2
                metadata['resolves_multiple_apis'] = True
            
            # Check for error handling (typical of dynamic loading)
            if self._has_api_error_handling(disasm):
                indicators.append('api_error_handling')
                confidence += 0.1
            
            if confidence > self.dynamic_loading_threshold:
                return APIPattern(
                    address=func_addr,
                    pattern_type='dynamic_api_loading',
                    api_name=None,
                    confidence=min(confidence, 1.0),
                    indicators=indicators,
                    metadata=metadata
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Dynamic loading analysis failed: {e}")
            return None
    
    def _analyze_hash_function(self, func_addr: int) -> List[APIPattern]:
        """Analyze function for API hashing patterns"""
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            
            # Test each hash algorithm
            for algo_name, detector in self.hash_algorithms.items():
                if detector(disasm):
                    # Check if followed by API resolution
                    if self._has_api_resolution_after_hash(disasm):
                        pattern = APIPattern(
                            address=func_addr,
                            pattern_type='api_hashing',
                            api_name=None,
                            confidence=0.8,
                            indicators=[f'{algo_name}_hash', 'api_resolution'],
                            metadata={'algorithm': algo_name}
                        )
                        patterns.append(pattern)
            
            # Check for custom hash algorithms
            if self._has_custom_hash_pattern(disasm) and self._has_api_resolution_after_hash(disasm):
                pattern = APIPattern(
                    address=func_addr,
                    pattern_type='api_hashing',
                    api_name=None,
                    confidence=0.6,
                    indicators=['custom_hash', 'api_resolution'],
                    metadata={'algorithm': 'custom'}
                )
                patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Hash function analysis failed: {e}")
            return []
    
    def _analyze_indirect_calls(self, func_addr: int) -> List[APIPattern]:
        """Analyze function for indirect call patterns"""
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            lines = disasm.split('\n')
            
            for line in lines:
                if self._is_indirect_call(line):
                    address = self._extract_address(line)
                    
                    # Analyze the context of the indirect call
                    call_type = self._classify_indirect_call(line, disasm)
                    
                    if call_type:
                        pattern = APIPattern(
                            address=address,
                            pattern_type='indirect_api_call',
                            api_name=None,
                            confidence=0.7,
                            indicators=['indirect_call', call_type],
                            metadata={'instruction': line.strip()}
                        )
                        patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Indirect call analysis failed: {e}")
            return []
    
    def _is_direct_import(self, api_name: str) -> bool:
        """Check if import is a direct, standard API"""
        # Standard Windows APIs that are commonly imported directly
        standard_apis = {
            'CreateFile', 'ReadFile', 'WriteFile', 'CloseHandle',
            'VirtualAlloc', 'VirtualFree', 'VirtualProtect',
            'CreateProcess', 'OpenProcess', 'TerminateProcess',
            'RegOpenKey', 'RegQueryValue', 'RegCloseKey',
            'MessageBox', 'GetWindowText', 'FindWindow'
        }
        
        return any(std_api in api_name for std_api in standard_apis)
    
    def _is_suspicious_import(self, api_name: str) -> bool:
        """Check if import is suspicious (might indicate obfuscation)"""
        suspicious_patterns = [
            'LoadLibrary', 'GetProcAddress', 'LdrLoadDll',
            'LdrGetProcedureAddress', 'NtQueryInformationProcess',
            'RtlHashUnicodeString', 'DecodePointer', 'EncodePointer'
        ]
        
        return any(pattern in api_name for pattern in suspicious_patterns)
    
    def _is_dynamic_loading_api(self, api_name: str) -> bool:
        """Check if API is used for dynamic loading"""
        dynamic_apis = [
            'LoadLibrary', 'LoadLibraryEx', 'GetProcAddress',
            'LdrLoadDll', 'LdrGetProcedureAddress',
            'GetModuleHandle', 'GetModuleFileName'
        ]
        
        return any(api in api_name for api in dynamic_apis)
    
    def _find_missing_common_apis(self, import_names: List[str]) -> List[str]:
        """Find commonly used APIs that are missing from imports"""
        common_apis = [
            'CreateFile', 'ReadFile', 'WriteFile', 'CloseHandle',
            'VirtualAlloc', 'MessageBox', 'GetCurrentProcess',
            'CreateThread', 'WaitForSingleObject'
        ]
        
        missing = []
        for api in common_apis:
            if not any(api.lower() in name for name in import_names):
                missing.append(api)
        
        return missing
    
    def _analyze_import_obfuscation_indicators(self, imports: List[Dict], 
                                            import_names: List[str], 
                                            dynamic_loading_apis: List[str]) -> List[str]:
        """Analyze import table for obfuscation indicators"""
        indicators = []
        
        # Too many dynamic loading APIs
        if len(dynamic_loading_apis) > 3:
            indicators.append('excessive_dynamic_loading_apis')
        
        # Very few direct imports (might be hidden)
        direct_count = sum(1 for name in import_names if self._is_direct_import(name))
        if direct_count < 5 and len(imports) > 10:
            indicators.append('few_direct_imports')
        
        # Unusual import patterns
        if any('Nt' in name for name in import_names):
            indicators.append('native_api_usage')
        
        if any('Rtl' in name for name in import_names):
            indicators.append('runtime_library_usage')
        
        # Check for import table padding or manipulation
        if len(set(import_names)) != len(import_names):
            indicators.append('duplicate_imports')
        
        return indicators