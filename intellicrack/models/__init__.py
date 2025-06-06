"""
Intellicrack Models Package

This package provides data models and structures used throughout the Intellicrack framework.
It includes models for binary analysis results, vulnerability data, protection mechanisms,
and AI/ML model representations.

Key Features:
    - Data model definitions
    - Analysis result structures
    - Vulnerability representations
    - Protection mechanism models
    - Configuration models
    - Serialization support

Model Categories:
    - Binary models for file analysis
    - Vulnerability models for security findings
    - Protection models for security mechanisms
    - Analysis models for results storage
    - Configuration models for settings
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

# Set up package logger
logger = logging.getLogger(__name__)

# Enumerations
class BinaryType(Enum):
    """Supported binary file types."""
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    APK = "apk"
    UNKNOWN = "unknown"

class VulnerabilityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ProtectionType(Enum):
    """Types of protection mechanisms."""
    PACKER = "packer"
    OBFUSCATOR = "obfuscator"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    ENCRYPTION = "encryption"
    LICENSE = "license"

# Additional enumerations
class AnalysisType(Enum):
    """Types of analysis that can be performed."""
    STATIC = "static"
    DYNAMIC = "dynamic"
    HYBRID = "hybrid"
    AI_ASSISTED = "ai_assisted"

class PatchType(Enum):
    """Types of patches that can be applied."""
    NOP = "nop"
    JMP = "jmp"
    CALL = "call"
    DATA = "data"
    CUSTOM = "custom"

class LicenseType(Enum):
    """Types of licensing mechanisms."""
    TRIAL = "trial"
    SERIAL = "serial"
    ONLINE = "online"
    HARDWARE = "hardware"
    DONGLE = "dongle"
    CUSTOM = "custom"

# Data models
@dataclass
class BinaryInfo:
    """Model for binary file information."""
    file_path: str
    file_type: BinaryType
    architecture: str
    size: int
    hash_md5: str
    hash_sha256: str
    entry_point: Optional[int] = None
    sections: Optional[List[Dict[str, Any]]] = None
    imports: Optional[List[str]] = None
    exports: Optional[List[str]] = None
    strings: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class Vulnerability:
    """Model for vulnerability findings."""
    id: str
    name: str
    description: str
    level: VulnerabilityLevel
    location: str
    cve_id: Optional[str] = None
    remediation: Optional[str] = None
    confidence: float = 0.0
    references: Optional[List[str]] = None

@dataclass
class Protection:
    """Model for protection mechanisms."""
    type: ProtectionType
    name: str
    version: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    confidence: float = 0.0
    bypass_difficulty: Optional[str] = None

@dataclass
class Patch:
    """Model for a patch instruction."""
    address: int
    original_bytes: bytes
    new_bytes: bytes
    description: str
    type: PatchType = PatchType.CUSTOM
    verified: bool = False

@dataclass
class LicenseInfo:
    """Model for license information."""
    type: LicenseType
    algorithm: Optional[str] = None
    key_locations: Optional[List[int]] = None
    validation_functions: Optional[List[str]] = None
    network_endpoints: Optional[List[str]] = None
    hardware_checks: Optional[List[str]] = None
    details: Optional[Dict[str, Any]] = None

@dataclass
class NetworkActivity:
    """Model for network activity."""
    timestamp: str
    source: str
    destination: str
    protocol: str
    port: int
    data_size: int
    purpose: Optional[str] = None
    encrypted: bool = False

@dataclass
class AnalysisConfig:
    """Model for analysis configuration."""
    analysis_type: AnalysisType
    enable_ai: bool = True
    enable_network_analysis: bool = True
    enable_dynamic_analysis: bool = False
    timeout: int = 300  # seconds
    max_memory: int = 1024  # MB
    plugins: Optional[List[str]] = None
    custom_settings: Optional[Dict[str, Any]] = None

@dataclass
class AnalysisResult:
    """Model for analysis results."""
    binary_info: BinaryInfo
    vulnerabilities: List[Vulnerability]
    protections: List[Protection]
    license_info: Optional[LicenseInfo] = None
    network_activity: Optional[List[NetworkActivity]] = None
    suggested_patches: Optional[List[Patch]] = None
    timestamp: str = ""
    analysis_time: float = 0.0
    config: Optional[AnalysisConfig] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class AIModelConfig:
    """Model for AI model configuration."""
    model_path: str
    model_type: str
    context_length: int = 4096
    temperature: float = 0.7
    top_p: float = 0.9
    provider: str = "local"
    api_key: Optional[str] = None
    endpoint: Optional[str] = None

@dataclass
class PluginInfo:
    """Model for plugin information."""
    name: str
    version: str
    author: str
    description: str
    type: str  # "python", "frida", "ghidra"
    path: str
    enabled: bool = True
    config: Optional[Dict[str, Any]] = None

# Define package exports
__all__ = [
    # Enumerations
    'BinaryType',
    'VulnerabilityLevel',
    'ProtectionType',
    'AnalysisType',
    'PatchType',
    'LicenseType',

    # Data models
    'BinaryInfo',
    'Vulnerability',
    'Protection',
    'Patch',
    'LicenseInfo',
    'NetworkActivity',
    'AnalysisConfig',
    'AnalysisResult',
    'AIModelConfig',
    'PluginInfo',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
