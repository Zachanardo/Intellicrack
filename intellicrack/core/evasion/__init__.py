"""
Evasion Module - Compatibility Alias

This module provides compatibility aliases for the anti-analysis components.
"""

# Import from the actual anti-analysis module
from ..anti_analysis.debugger_detector import DebuggerDetector
from ..anti_analysis.sandbox_detector import SandboxDetector
from ..anti_analysis.vm_detector import VMDetector


# Main anti-analysis engine
class AntiAnalysisEngine:
    """Engine for anti-analysis and evasion techniques."""

    def __init__(self):
        self.debugger_detector = DebuggerDetector()
        self.vm_detector = VMDetector()
        self.sandbox_detector = SandboxDetector()

    def detect_virtual_environment(self):
        """Detect if running in a virtual environment."""
        return self.vm_detector.detect_vm()

    def detect_debugger(self):
        """Detect if a debugger is attached."""
        return self.debugger_detector.detect_debugger()

    def detect_sandbox(self):
        """Detect if running in a sandbox."""
        return self.sandbox_detector.detect_sandbox()

__all__ = ['AntiAnalysisEngine', 'DebuggerDetector', 'VMDetector', 'SandboxDetector']
