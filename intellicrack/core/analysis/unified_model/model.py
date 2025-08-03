"""
Unified Binary Model Core Data Structures

Comprehensive data model that consolidates analysis results from multiple tools
into validated, structured formats for security research and binary analysis.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from ....utils.logger import get_logger

logger = get_logger(__name__)


class AnalysisPhase(Enum):
    """Analysis phases for tracking tool execution"""
    PREPARATION = "preparation"
    BASIC_INFO = "basic_info"
    STATIC_ANALYSIS = "static_analysis"
    DECOMPILATION = "decompilation"
    ENTROPY_ANALYSIS = "entropy_analysis"
    STRUCTURE_ANALYSIS = "structure_analysis"
    VULNERABILITY_SCAN = "vulnerability_scan"
    PATTERN_MATCHING = "pattern_matching"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    FINALIZATION = "finalization"


class ConfidenceLevel(Enum):
    """Confidence levels for analysis results"""
    VERY_LOW = 0.1
    LOW = 0.3
    MEDIUM = 0.5
    HIGH = 0.7
    VERY_HIGH = 0.9
    CERTAIN = 1.0


class AnalysisSource(Enum):
    """Sources of analysis data"""
    BINARY_ANALYZER = "binary_analyzer"
    RADARE2 = "radare2"
    GHIDRA = "ghidra"
    YARA = "yara"
    VULNERABILITY_ENGINE = "vulnerability_engine"
    ENTROPY_ANALYZER = "entropy_analyzer"
    MULTI_FORMAT_ANALYZER = "multi_format_analyzer"
    DYNAMIC_ANALYZER = "dynamic_analyzer"
    SANDBOX_MANAGER = "sandbox_manager"
    DIE_DETECTOR = "die_detector"
    OBFUSCATION_ANALYZER = "obfuscation_analyzer"


@dataclass
class AnalysisEvent:
    """Record of when and how analysis was performed"""
    phase: AnalysisPhase
    source: AnalysisSource
    timestamp: float
    duration: float
    success: bool
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def datetime_str(self) -> str:
        """Human readable timestamp"""
        return datetime.fromtimestamp(self.timestamp).isoformat()


@dataclass
class ValidationIssue:
    """Data validation issue"""
    severity: str  # "error", "warning", "info"
    category: str  # "consistency", "completeness", "accuracy"
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    """Result of model validation"""
    is_valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    validation_timestamp: float = field(default_factory=time.time)
    validator_version: str = "1.0"

    @property
    def error_count(self) -> int:
        """Number of validation errors"""
        return len([i for i in self.issues if i.severity == "error"])

    @property
    def warning_count(self) -> int:
        """Number of validation warnings"""
        return len([i for i in self.issues if i.severity == "warning"])


@dataclass
class BinaryMetadata:
    """Core binary file metadata"""
    file_path: str
    file_size: int
    file_format: str  # PE, ELF, Mach-O, etc.
    architecture: str  # x86, x64, ARM, etc.
    
    # File hashes
    md5: Optional[str] = None
    sha1: Optional[str] = None  
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    
    # Timestamps
    creation_time: Optional[float] = None
    modification_time: Optional[float] = None
    access_time: Optional[float] = None
    
    # Analysis metadata
    analysis_start: float = field(default_factory=time.time)
    analysis_end: Optional[float] = None
    total_analysis_time: Optional[float] = None
    
    # File properties
    is_executable: bool = True
    is_library: bool = False
    is_packed: Optional[bool] = None
    has_debug_info: Optional[bool] = None
    
    # Format-specific metadata
    format_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Calculate derived fields"""
        if self.analysis_end and self.analysis_start:
            self.total_analysis_time = self.analysis_end - self.analysis_start

    @property
    def primary_hash(self) -> Optional[str]:
        """Primary hash for identification (SHA256 preferred)"""
        return self.sha256 or self.sha1 or self.md5

    @classmethod
    def from_file(cls, file_path: Union[str, Path]) -> 'BinaryMetadata':
        """Create metadata from file"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Get file stats
        stat = file_path.stat()
        
        # Calculate hashes
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                hashes = {
                    'md5': hashlib.md5(data).hexdigest(),
                    'sha1': hashlib.sha1(data).hexdigest(),
                    'sha256': hashlib.sha256(data).hexdigest(),
                    'sha512': hashlib.sha512(data).hexdigest()
                }
        except Exception as e:
            logger.warning(f"Failed to calculate hashes for {file_path}: {e}")
        
        return cls(
            file_path=str(file_path.absolute()),
            file_size=stat.st_size,
            file_format="unknown",  # Will be determined by analysis
            architecture="unknown",  # Will be determined by analysis
            creation_time=stat.st_ctime,
            modification_time=stat.st_mtime,
            access_time=stat.st_atime,
            **hashes
        )


@dataclass
class ImportInfo:
    """Information about an imported function or symbol"""
    name: str
    library: Optional[str] = None
    address: Optional[int] = None
    ordinal: Optional[int] = None
    is_delayed: bool = False
    
    # Analysis metadata
    sources: Set[AnalysisSource] = field(default_factory=set)
    confidence: float = 0.5
    first_seen: float = field(default_factory=time.time)
    
    def __hash__(self):
        return hash((self.name, self.library, self.address))


@dataclass  
class ExportInfo:
    """Information about an exported function or symbol"""
    name: str
    address: int
    ordinal: Optional[int] = None
    is_forwarded: bool = False
    forwarded_to: Optional[str] = None
    
    # Analysis metadata
    sources: Set[AnalysisSource] = field(default_factory=set)
    confidence: float = 0.5
    first_seen: float = field(default_factory=time.time)
    
    def __hash__(self):
        return hash((self.name, self.address))


@dataclass
class StringInfo:
    """Information about strings found in binary"""
    value: str
    address: Optional[int] = None
    encoding: str = "ascii"
    section: Optional[str] = None
    
    # Classification
    is_wide: bool = False
    is_encrypted: bool = False
    is_license_related: bool = False
    
    # Analysis metadata
    sources: Set[AnalysisSource] = field(default_factory=set)
    confidence: float = 0.5
    first_seen: float = field(default_factory=time.time)
    
    def __hash__(self):
        return hash((self.value, self.address))


@dataclass
class SymbolDatabase:
    """Consolidated symbol information from all analysis tools"""
    imports: Dict[str, ImportInfo] = field(default_factory=dict)  # name -> info
    exports: Dict[str, ExportInfo] = field(default_factory=dict)  # name -> info
    strings: Dict[str, StringInfo] = field(default_factory=dict)  # value -> info
    
    # Symbol statistics
    total_imports: int = 0
    total_exports: int = 0
    total_strings: int = 0
    unique_libraries: Set[str] = field(default_factory=set)
    
    def add_import(self, import_info: ImportInfo, source: AnalysisSource):
        """Add or merge import information"""
        key = import_info.name
        if key in self.imports:
            # Merge with existing
            existing = self.imports[key]
            existing.sources.add(source)
            if import_info.address and not existing.address:
                existing.address = import_info.address
            if import_info.library and not existing.library:
                existing.library = import_info.library
            # Update confidence based on multiple sources
            existing.confidence = min(0.95, existing.confidence * 1.2)
        else:
            # Add new import
            import_info.sources.add(source)
            self.imports[key] = import_info
            
        # Update statistics
        self.total_imports = len(self.imports)
        if import_info.library:
            self.unique_libraries.add(import_info.library)

    def add_export(self, export_info: ExportInfo, source: AnalysisSource):
        """Add or merge export information"""
        key = export_info.name
        if key in self.exports:
            # Merge with existing
            existing = self.exports[key]
            existing.sources.add(source)
            # Update confidence based on multiple sources
            existing.confidence = min(0.95, existing.confidence * 1.2)
        else:
            # Add new export
            export_info.sources.add(source)
            self.exports[key] = export_info
            
        # Update statistics
        self.total_exports = len(self.exports)

    def add_string(self, string_info: StringInfo, source: AnalysisSource):
        """Add or merge string information"""
        key = string_info.value
        if key in self.strings:
            # Merge with existing
            existing = self.strings[key]
            existing.sources.add(source)
            if string_info.address and not existing.address:
                existing.address = string_info.address
            if string_info.section and not existing.section:
                existing.section = string_info.section
            # Update confidence based on multiple sources
            existing.confidence = min(0.95, existing.confidence * 1.2)
        else:
            # Add new string
            string_info.sources.add(source)
            self.strings[key] = string_info
            
        # Update statistics
        self.total_strings = len(self.strings)

    def get_license_related_strings(self) -> List[StringInfo]:
        """Get strings that may be license-related"""
        license_keywords = [
            'license', 'serial', 'key', 'activation', 'trial', 'expire',
            'register', 'unlock', 'validate', 'authenticate', 'authorize'
        ]
        
        results = []
        for string_info in self.strings.values():
            if string_info.is_license_related:
                results.append(string_info)
            else:
                # Check if value contains license keywords
                value_lower = string_info.value.lower()
                if any(keyword in value_lower for keyword in license_keywords):
                    string_info.is_license_related = True
                    results.append(string_info)
        
        return results


@dataclass
class FunctionInfo:
    """Comprehensive function analysis information"""
    name: str
    address: int
    size: Optional[int] = None
    
    # Function characteristics
    is_imported: bool = False
    is_exported: bool = False
    is_license_related: bool = False
    is_crypto_related: bool = False
    
    # Analysis results
    disassembly: Optional[str] = None
    decompiled_code: Optional[str] = None
    signature: Optional[str] = None
    calling_convention: Optional[str] = None
    
    # Function metadata
    parameter_count: Optional[int] = None
    return_type: Optional[str] = None
    complexity_metrics: Dict[str, Any] = field(default_factory=dict)
    
    # Cross-references
    calls_to: List[int] = field(default_factory=list)  # Addresses this function calls
    called_by: List[int] = field(default_factory=list)  # Addresses that call this function
    api_calls: List[str] = field(default_factory=list)  # API functions called
    
    # Analysis metadata
    sources: Set[AnalysisSource] = field(default_factory=set)
    confidence: float = 0.5
    analysis_time: Optional[float] = None
    first_seen: float = field(default_factory=time.time)
    
    def __hash__(self):
        return hash((self.name, self.address))
    
    @property
    def is_analyzed(self) -> bool:
        """Check if function has been thoroughly analyzed"""
        return bool(self.decompiled_code or self.disassembly)


@dataclass
class SectionInfo:
    """Binary section information"""
    name: str
    address: int
    size: int
    file_offset: Optional[int] = None
    
    # Section characteristics
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = True
    
    # Analysis results
    entropy: Optional[float] = None
    is_packed: Optional[bool] = None
    contains_code: Optional[bool] = None
    contains_data: Optional[bool] = None
    
    # Section metadata
    raw_size: Optional[int] = None
    characteristics: Optional[int] = None
    
    # Analysis metadata
    sources: Set[AnalysisSource] = field(default_factory=set)
    confidence: float = 0.5
    first_seen: float = field(default_factory=time.time)
    
    def __hash__(self):
        return hash((self.name, self.address, self.size))
    
    @property
    def permissions(self) -> str:
        """Human readable permissions string"""
        perms = ""
        if self.is_readable:
            perms += "R"
        if self.is_writable:
            perms += "W"
        if self.is_executable:
            perms += "X"
        return perms or "---"


@dataclass
class ProtectionInfo:
    """Information about detected protection mechanism"""
    name: str
    type: str  # "packer", "protector", "obfuscator", "anti_debug", etc.
    confidence: float
    version: Optional[str] = None
    
    # Detection details
    detection_method: str = "unknown"  # "signature", "pattern", "behavior"
    detection_location: Optional[str] = None  # section, address, etc.
    
    # Protection characteristics
    is_vm_protection: bool = False
    is_encryption: bool = False
    is_anti_debug: bool = False
    is_anti_vm: bool = False
    
    # Analysis metadata
    sources: Set[AnalysisSource] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    
    def __hash__(self):
        return hash((self.name, self.type, self.version))


@dataclass
class ProtectionAnalysis:
    """Consolidated protection detection results"""
    protections: Dict[str, ProtectionInfo] = field(default_factory=dict)  # name -> info
    is_packed: bool = False
    is_obfuscated: bool = False
    has_anti_debug: bool = False
    has_anti_vm: bool = False
    
    # Overall assessment
    protection_level: str = "none"  # "none", "light", "moderate", "heavy", "extreme"
    bypass_difficulty: str = "unknown"  # "trivial", "easy", "moderate", "hard", "extreme"
    
    def add_protection(self, protection: ProtectionInfo, source: AnalysisSource):
        """Add or merge protection information"""
        key = f"{protection.name}_{protection.type}"
        if key in self.protections:
            # Merge with existing
            existing = self.protections[key]
            existing.sources.add(source)
            # Update confidence - multiple sources increase confidence
            existing.confidence = min(0.95, max(existing.confidence, protection.confidence) * 1.1)
        else:
            # Add new protection
            protection.sources.add(source)
            self.protections[key] = protection
        
        # Update overall flags
        if protection.type == "packer":
            self.is_packed = True
        elif protection.type == "obfuscator":
            self.is_obfuscated = True
        elif protection.is_anti_debug:
            self.has_anti_debug = True
        elif protection.is_anti_vm:
            self.has_anti_vm = True
        
        # Update protection level assessment
        self._assess_protection_level()
    
    def _assess_protection_level(self):
        """Assess overall protection level based on detected protections"""
        if not self.protections:
            self.protection_level = "none"
            self.bypass_difficulty = "trivial"
            return
        
        # Count high-confidence protections
        high_conf_protections = [p for p in self.protections.values() if p.confidence > 0.7]
        protection_count = len(high_conf_protections)
        
        # Check for VM protection
        has_vm_protection = any(p.is_vm_protection for p in high_conf_protections)
        
        # Assess level
        if has_vm_protection or protection_count >= 3:
            self.protection_level = "extreme"
            self.bypass_difficulty = "extreme"
        elif self.is_packed and (self.has_anti_debug or self.has_anti_vm):
            self.protection_level = "heavy"
            self.bypass_difficulty = "hard"
        elif protection_count >= 2:
            self.protection_level = "moderate"
            self.bypass_difficulty = "moderate"
        elif protection_count == 1:
            self.protection_level = "light"
            self.bypass_difficulty = "easy"
        else:
            self.protection_level = "none"
            self.bypass_difficulty = "trivial"


@dataclass
class ObfuscationPattern:
    """Individual obfuscation pattern detection"""
    type: str  # "control_flow_flattening", "string_encryption", etc.
    severity: str  # "low", "medium", "high", "critical"
    confidence: float
    addresses: List[int] = field(default_factory=list)
    description: str = ""
    indicators: List[str] = field(default_factory=list)
    detection_method: str = "heuristic"  # "heuristic", "ml", "signature"
    metadata: Dict[str, Any] = field(default_factory=dict)
    sources: Set[AnalysisSource] = field(default_factory=set)
    first_detected: float = field(default_factory=time.time)
    
    def __hash__(self):
        return hash((self.type, tuple(sorted(self.addresses))))


@dataclass
class ObfuscationFeatures:
    """ML-extracted obfuscation features for unified model"""
    # Control flow features
    cfg_complexity: float = 0.0
    cyclomatic_complexity: int = 0
    basic_block_count: int = 0
    jump_instruction_ratio: float = 0.0
    conditional_jump_ratio: float = 0.0
    indirect_jump_count: int = 0
    
    # String features
    string_entropy: float = 0.0
    encrypted_string_ratio: float = 0.0
    xor_pattern_count: int = 0
    base64_pattern_count: int = 0
    
    # API features
    dynamic_api_ratio: float = 0.0
    api_hash_count: int = 0
    indirect_call_ratio: float = 0.0
    import_table_entropy: float = 0.0
    
    # Code features
    instruction_entropy: float = 0.0
    nop_instruction_ratio: float = 0.0
    dead_code_ratio: float = 0.0
    polymorphic_pattern_count: int = 0
    
    # VM features
    vm_pattern_count: int = 0
    bytecode_section_count: int = 0
    handler_function_count: int = 0
    
    # Statistical features
    file_entropy: float = 0.0
    section_count: int = 0
    packed_section_ratio: float = 0.0


@dataclass
class MLClassificationResult:
    """Machine learning classification result for unified model"""
    obfuscation_type: str
    confidence: float
    probability_scores: Dict[str, float] = field(default_factory=dict)
    anomaly_score: float = 0.0
    cluster_id: int = -1
    feature_importance: Dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class ObfuscationAnalysis:
    """Comprehensive obfuscation analysis results"""
    # Pattern detection results
    patterns: Dict[str, ObfuscationPattern] = field(default_factory=dict)
    
    # Category analysis
    control_flow_obfuscation: bool = False
    string_obfuscation: bool = False
    api_obfuscation: bool = False
    code_transformation: bool = False
    virtualization_protection: bool = False
    
    # Overall assessment
    obfuscation_level: str = "none"  # "none", "light", "moderate", "heavy", "extreme"
    obfuscation_complexity: float = 0.0  # 0.0 - 1.0
    estimated_analysis_time: float = 0.0  # seconds to analyze/reverse
    
    # ML analysis results
    ml_features: Optional[ObfuscationFeatures] = None
    ml_classification: Optional[MLClassificationResult] = None
    ml_enabled: bool = False
    
    # Detection metadata
    analysis_duration: float = 0.0
    total_patterns_detected: int = 0
    high_confidence_patterns: int = 0
    sources: Set[AnalysisSource] = field(default_factory=set)
    
    def add_pattern(self, pattern: ObfuscationPattern, source: AnalysisSource):
        """Add or merge obfuscation pattern"""
        key = f"{pattern.type}_{hash(pattern)}"
        
        if key in self.patterns:
            # Merge with existing pattern
            existing = self.patterns[key]
            existing.sources.add(source)
            existing.confidence = min(0.95, max(existing.confidence, pattern.confidence) * 1.1)
        else:
            # Add new pattern
            pattern.sources.add(source)
            self.patterns[key] = pattern
        
        # Update category flags and assessment
        self._update_category_flags(pattern)
        self._assess_obfuscation_level()
    
    def _update_category_flags(self, pattern: ObfuscationPattern):
        """Update category flags based on pattern type"""
        pattern_type = pattern.type.lower()
        
        if any(cf in pattern_type for cf in ['control_flow', 'opaque_predicate', 'bogus_control']):
            self.control_flow_obfuscation = True
        elif any(str_obf in pattern_type for str_obf in ['string', 'xor', 'base64', 'encryption']):
            self.string_obfuscation = True
        elif any(api_obf in pattern_type for api_obf in ['api', 'dynamic_loading', 'indirect_call']):
            self.api_obfuscation = True
        elif any(code_tf in pattern_type for code_tf in ['instruction', 'metamorphic', 'polymorphic']):
            self.code_transformation = True
        elif any(vm_prot in pattern_type for vm_prot in ['virtualization', 'bytecode', 'vm_protection']):
            self.virtualization_protection = True
    
    def _assess_obfuscation_level(self):
        """Assess overall obfuscation level and complexity"""
        if not self.patterns:
            self.obfuscation_level = "none"
            self.obfuscation_complexity = 0.0
            return
        
        # Count high-confidence patterns
        high_conf_patterns = [p for p in self.patterns.values() if p.confidence > 0.7]
        self.high_confidence_patterns = len(high_conf_patterns)
        self.total_patterns_detected = len(self.patterns)
        
        # Calculate complexity based on pattern types and counts
        complexity = 0.0
        
        if self.virtualization_protection:
            complexity = max(complexity, 0.9)
        if self.control_flow_obfuscation:
            complexity = max(complexity, 0.6)
        if self.string_obfuscation:
            complexity = max(complexity, 0.4)
        if self.api_obfuscation:
            complexity = max(complexity, 0.5)
        if self.code_transformation:
            complexity = max(complexity, 0.7)
        
        # Adjust based on pattern count
        pattern_boost = min(0.3, len(high_conf_patterns) * 0.05)
        complexity = min(1.0, complexity + pattern_boost)
        
        self.obfuscation_complexity = complexity
        
        # Set level based on complexity
        if complexity >= 0.8:
            self.obfuscation_level = "extreme"
            self.estimated_analysis_time = 3600.0
        elif complexity >= 0.6:
            self.obfuscation_level = "heavy"
            self.estimated_analysis_time = 1800.0
        elif complexity >= 0.4:
            self.obfuscation_level = "moderate"
            self.estimated_analysis_time = 600.0
        elif complexity >= 0.2:
            self.obfuscation_level = "light"
            self.estimated_analysis_time = 300.0


@dataclass
class VulnerabilityInfo:
    """Information about detected vulnerability"""
    type: str
    severity: str  # "critical", "high", "medium", "low"
    description: str
    
    # Location information
    address: Optional[int] = None
    section: Optional[str] = None
    function: Optional[str] = None
    
    # Vulnerability details
    cve_id: Optional[str] = None
    exploit_available: bool = False
    
    # Analysis metadata
    sources: Set[AnalysisSource] = field(default_factory=set)
    confidence: float = 0.5
    first_seen: float = field(default_factory=time.time)
    
    def __hash__(self):
        return hash((self.type, self.description, self.address))


@dataclass
class VulnerabilityAnalysis:
    """Consolidated vulnerability assessment"""
    vulnerabilities: Dict[str, VulnerabilityInfo] = field(default_factory=dict)
    
    # Vulnerability statistics
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # Overall assessment
    risk_level: str = "unknown"  # "low", "medium", "high", "critical"
    exploitability: str = "unknown"  # "low", "medium", "high"
    
    def add_vulnerability(self, vuln: VulnerabilityInfo, source: AnalysisSource):
        """Add vulnerability to analysis"""
        key = f"{vuln.type}_{vuln.description}_{vuln.address}"
        if key in self.vulnerabilities:
            # Merge with existing
            existing = self.vulnerabilities[key]
            existing.sources.add(source)
            existing.confidence = min(0.95, existing.confidence * 1.2)
        else:
            # Add new vulnerability
            vuln.sources.add(source)
            self.vulnerabilities[key] = vuln
        
        # Update statistics
        self._update_statistics()
    
    def _update_statistics(self):
        """Update vulnerability statistics"""
        self.critical_count = len([v for v in self.vulnerabilities.values() if v.severity == "critical"])
        self.high_count = len([v for v in self.vulnerabilities.values() if v.severity == "high"])
        self.medium_count = len([v for v in self.vulnerabilities.values() if v.severity == "medium"])
        self.low_count = len([v for v in self.vulnerabilities.values() if v.severity == "low"])
        
        # Assess overall risk
        if self.critical_count > 0:
            self.risk_level = "critical"
            self.exploitability = "high"
        elif self.high_count > 0:
            self.risk_level = "high"
            self.exploitability = "high" if self.high_count > 2 else "medium"
        elif self.medium_count > 0:
            self.risk_level = "medium"
            self.exploitability = "medium"
        elif self.low_count > 0:
            self.risk_level = "low"
            self.exploitability = "low"


@dataclass
class RuntimeBehavior:
    """Dynamic analysis and runtime behavior information"""
    execution_successful: bool = False
    exit_code: Optional[int] = None
    execution_time: Optional[float] = None
    
    # Process behavior
    memory_usage: Dict[str, Any] = field(default_factory=dict)
    file_operations: List[Dict[str, Any]] = field(default_factory=list)
    registry_operations: List[Dict[str, Any]] = field(default_factory=list)
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    
    # API calls and hooking
    api_calls: List[Dict[str, Any]] = field(default_factory=list)
    license_checks: List[Dict[str, Any]] = field(default_factory=list)
    crypto_operations: List[Dict[str, Any]] = field(default_factory=list)
    
    # Anti-analysis behavior
    anti_debug_detected: bool = False
    anti_vm_detected: bool = False
    timing_checks: List[Dict[str, Any]] = field(default_factory=list)
    
    # Analysis metadata
    analysis_method: str = "unknown"  # "frida", "sandbox", "emulation"
    analysis_duration: Optional[float] = None
    sources: Set[AnalysisSource] = field(default_factory=set)


@dataclass
class UnifiedBinaryModel:
    """
    Comprehensive unified binary analysis model that consolidates results
    from multiple analysis tools into a validated, structured format.
    """
    
    # Core identification
    binary_path: str
    file_hash: str  # Primary SHA256 hash for identification
    
    # Consolidated analysis data
    metadata: BinaryMetadata
    functions: Dict[int, FunctionInfo] = field(default_factory=dict)  # address -> function
    symbols: SymbolDatabase = field(default_factory=SymbolDatabase)
    sections: Dict[str, SectionInfo] = field(default_factory=dict)  # name -> section
    protections: ProtectionAnalysis = field(default_factory=ProtectionAnalysis)
    vulnerabilities: VulnerabilityAnalysis = field(default_factory=VulnerabilityAnalysis)
    obfuscation: ObfuscationAnalysis = field(default_factory=ObfuscationAnalysis)
    runtime_behavior: Optional[RuntimeBehavior] = None
    
    # Analysis tracking
    tool_results: Dict[str, Any] = field(default_factory=dict)  # Raw results from tools
    analysis_timeline: List[AnalysisEvent] = field(default_factory=list)
    data_confidence: Dict[str, float] = field(default_factory=dict)  # Confidence per category
    
    # Model status
    validation_status: Optional[ValidationResult] = None
    is_complete: bool = False
    model_version: str = "1.0"
    created_timestamp: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    
    def __post_init__(self):
        """Initialize derived fields"""
        if not self.file_hash and self.metadata.primary_hash:
            self.file_hash = self.metadata.primary_hash

    @classmethod
    def create_initial(cls, binary_path: Union[str, Path]) -> 'UnifiedBinaryModel':
        """Create initial unified model from binary file"""
        binary_path = Path(binary_path)
        metadata = BinaryMetadata.from_file(binary_path)
        
        return cls(
            binary_path=str(binary_path.absolute()),
            file_hash=metadata.primary_hash or "unknown",
            metadata=metadata
        )
    
    def add_function(self, function: FunctionInfo, source: AnalysisSource):
        """Add or merge function information"""
        if function.address in self.functions:
            # Merge with existing function
            existing = self.functions[function.address]
            existing.sources.add(source)
            
            # Merge data preferring more detailed information
            if function.decompiled_code and not existing.decompiled_code:
                existing.decompiled_code = function.decompiled_code
            if function.disassembly and not existing.disassembly:
                existing.disassembly = function.disassembly
            if function.signature and not existing.signature:
                existing.signature = function.signature
            
            # Merge cross-references
            existing.calls_to.extend([addr for addr in function.calls_to if addr not in existing.calls_to])
            existing.called_by.extend([addr for addr in function.called_by if addr not in existing.called_by])
            existing.api_calls.extend([call for call in function.api_calls if call not in existing.api_calls])
            
            # Update confidence
            existing.confidence = min(0.95, existing.confidence * 1.2)
        else:
            # Add new function
            function.sources.add(source)
            self.functions[function.address] = function
        
        self.last_updated = time.time()
    
    def add_section(self, section: SectionInfo, source: AnalysisSource):
        """Add or merge section information"""
        if section.name in self.sections:
            # Merge with existing section
            existing = self.sections[section.name]
            existing.sources.add(source)
            
            # Update missing information
            if section.entropy is not None and existing.entropy is None:
                existing.entropy = section.entropy
            if section.file_offset is not None and existing.file_offset is None:
                existing.file_offset = section.file_offset
            
            # Update confidence
            existing.confidence = min(0.95, existing.confidence * 1.2)
        else:
            # Add new section
            section.sources.add(source)
            self.sections[section.name] = section
        
        self.last_updated = time.time()
    
    def add_analysis_event(self, event: AnalysisEvent):
        """Record analysis event"""
        self.analysis_timeline.append(event)
        self.last_updated = time.time()
    
    def set_runtime_behavior(self, behavior: RuntimeBehavior, source: AnalysisSource):
        """Set runtime behavior information"""
        if self.runtime_behavior is None:
            behavior.sources.add(source)
            self.runtime_behavior = behavior
        else:
            # Merge with existing behavior
            self.runtime_behavior.sources.add(source)
            # Merge data (prefer more detailed information)
            if behavior.api_calls:
                self.runtime_behavior.api_calls.extend(behavior.api_calls)
            if behavior.license_checks:
                self.runtime_behavior.license_checks.extend(behavior.license_checks)
            if behavior.file_operations:
                self.runtime_behavior.file_operations.extend(behavior.file_operations)
        
        self.last_updated = time.time()
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of analysis results"""
        return {
            "file_info": {
                "path": self.binary_path,
                "size": self.metadata.file_size,
                "format": self.metadata.file_format,
                "hash": self.file_hash
            },
            "analysis_stats": {
                "functions_found": len(self.functions),
                "imports_found": self.symbols.total_imports,
                "exports_found": self.symbols.total_exports,
                "strings_found": self.symbols.total_strings,
                "sections_found": len(self.sections),
                "protections_found": len(self.protections.protections),
                "vulnerabilities_found": len(self.vulnerabilities.vulnerabilities)
            },
            "protection_assessment": {
                "is_packed": self.protections.is_packed,
                "protection_level": self.protections.protection_level,
                "bypass_difficulty": self.protections.bypass_difficulty
            },
            "vulnerability_assessment": {
                "risk_level": self.vulnerabilities.risk_level,
                "critical_vulns": self.vulnerabilities.critical_count,
                "high_vulns": self.vulnerabilities.high_count
            },
            "analysis_metadata": {
                "tools_used": [event.source.value for event in self.analysis_timeline],
                "total_analysis_time": self.metadata.total_analysis_time,
                "is_complete": self.is_complete,
                "validation_passed": self.validation_status.is_valid if self.validation_status else None
            }
        }
    
    def get_license_indicators(self) -> Dict[str, Any]:
        """Get all license-related indicators found during analysis"""
        indicators = {
            "license_functions": [f for f in self.functions.values() if f.is_license_related],
            "license_strings": self.symbols.get_license_related_strings(),
            "license_api_calls": [],
            "license_protections": [p for p in self.protections.protections.values() if "license" in p.name.lower()],
            "runtime_license_checks": []
        }
        
        # Add runtime license checks if available
        if self.runtime_behavior:
            indicators["license_api_calls"] = self.runtime_behavior.license_checks
            indicators["runtime_license_checks"] = [
                check for check in self.runtime_behavior.api_calls
                if any(keyword in check.get("function", "").lower() 
                      for keyword in ["license", "serial", "key", "activation"])
            ]
        
        return indicators