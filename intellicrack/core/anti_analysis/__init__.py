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

__all__ = [
    'BaseDetector',
    'VMDetector',
    'DebuggerDetector',
    'SandboxDetector',
    'TimingAttackDefense',
    'APIObfuscator',
    'ProcessHollowing'
]
