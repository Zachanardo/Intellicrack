"""
Anti-Analysis Module - Compatibility Alias

This module provides compatibility aliases for the anti-analysis components.
Import the actual implementation from the main evasion module to avoid code duplication.
"""

# Import the AntiAnalysisEngine from the main evasion module to eliminate duplication
from . import AntiAnalysisEngine

# Also export the individual detector classes for compatibility
from ..anti_analysis.debugger_detector import DebuggerDetector
from ..anti_analysis.sandbox_detector import SandboxDetector
from ..anti_analysis.vm_detector import VMDetector


__all__ = ['AntiAnalysisEngine', 'DebuggerDetector', 'SandboxDetector', 'VMDetector']
