"""Anti-analysis module initialization for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from .advanced_debugger_bypass import (
    AdvancedDebuggerBypass,
    HypervisorDebugger,
    KernelHookManager,
    TimingNeutralizer,
    install_advanced_bypass,
)
from .api_obfuscation import APIObfuscator
from .base_detector import BaseDetector
from .debugger_bypass import DebuggerBypass, install_anti_antidebug
from .debugger_detector import DebuggerDetector
from .sandbox_detector import SandboxDetector
from .timing_attacks import TimingAttackDefense
from .vm_detector import VMDetector

"""
Anti-Analysis and Evasion Module

Provides comprehensive anti-analysis techniques including VM detection,
debugger detection, sandbox evasion, and behavior analysis bypass.
"""


# Main anti-analysis engine (moved from evasion module)
class AntiAnalysisEngine:
    """Engine for anti-analysis and evasion techniques."""

    def __init__(self):
        """Initialize the anti-analysis engine with detection components."""
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
    "AdvancedDebuggerBypass",
    "APIObfuscator",
    "AntiAnalysisEngine",
    "BaseDetector",
    "DebuggerBypass",
    "DebuggerDetector",
    "HypervisorDebugger",
    "KernelHookManager",
    "SandboxDetector",
    "TimingAttackDefense",
    "TimingNeutralizer",
    "VMDetector",
    "install_advanced_bypass",
    "install_anti_antidebug",
]
