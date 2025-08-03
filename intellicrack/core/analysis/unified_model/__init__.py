"""
Unified Binary Model Module

Provides a comprehensive, validated data structure that consolidates analysis results
from multiple tools (Radare2, Ghidra, YARA, etc.) into a coherent, structured format.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from .model import (
    UnifiedBinaryModel,
    BinaryMetadata,
    FunctionInfo,
    SymbolDatabase,
    SectionInfo,
    ProtectionAnalysis,
    VulnerabilityAnalysis,
    RuntimeBehavior,
    AnalysisEvent,
    ValidationResult,
    AnalysisPhase,
    AnalysisSource,
    ConfidenceLevel,
    ProtectionType,
    VulnerabilityType,
    ObfuscationAnalysis,
    ObfuscationPattern,
    ObfuscationFeatures,
    MLClassificationResult
)

from .builder import UnifiedModelBuilder
from .merger import ResultMerger
from .validator import ModelValidator, ValidationError
from .serializer import ModelSerializer, SerializationFormat

__all__ = [
    'UnifiedBinaryModel',
    'BinaryMetadata',
    'FunctionInfo', 
    'SymbolDatabase',
    'SectionInfo',
    'ProtectionAnalysis',
    'VulnerabilityAnalysis',
    'RuntimeBehavior',
    'AnalysisEvent',
    'ValidationResult',
    'AnalysisPhase',
    'AnalysisSource',
    'ConfidenceLevel',
    'ProtectionType',
    'VulnerabilityType',
    'ObfuscationAnalysis',
    'ObfuscationPattern',
    'ObfuscationFeatures',
    'MLClassificationResult',
    'UnifiedModelBuilder',
    'ResultMerger',
    'ModelValidator',
    'ValidationError',
    'ModelSerializer',
    'SerializationFormat'
]