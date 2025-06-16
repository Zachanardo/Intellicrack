"""
Anti-Analysis and Evasion Module

Provides comprehensive anti-analysis techniques including VM detection,
debugger detection, sandbox evasion, and behavior analysis bypass.
"""

from .api_obfuscation import APIObfuscator
from .base_detector import BaseDetector
from .debugger_detector import DebuggerDetector
from .process_hollowing import ProcessHollowing
from .sandbox_detector import SandboxDetector
from .timing_attacks import TimingAttackDefense
from .vm_detector import VMDetector


# Main anti-analysis engine (moved from evasion module)
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


__all__ = [
    'AntiAnalysisEngine',
    'BaseDetector',
    'VMDetector',
    'DebuggerDetector',
    'SandboxDetector',
    'TimingAttackDefense',
    'APIObfuscator',
    'ProcessHollowing'
]
