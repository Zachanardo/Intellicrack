"""Tool bridges for external reverse engineering tools.

This package provides bridge interfaces for controlling external tools
including Ghidra, x64dbg, Frida, radare2, and direct binary/process manipulation.
"""

from __future__ import annotations

from .base import (
    BinaryOperationsBridge,
    BridgeCapabilities,
    BridgeState,
    DebuggerBridge,
    DisassemblyLine,
    DynamicAnalysisBridge,
    InstrumentationBridge,
    MemorySearchResult,
    StackFrame,
    StaticAnalysisBridge,
    ToolBridgeBase,
    WatchpointInfo,
)
from .binary import BinaryBridge
from .frida_bridge import FridaBridge
from .ghidra import GhidraBridge
from .installer import ToolInstaller
from .process import ProcessBridge
from .radare2 import Radare2Bridge
from .x64dbg import X64DbgBridge


__all__: list[str] = [
    "BinaryBridge",
    "BinaryOperationsBridge",
    "BridgeCapabilities",
    "BridgeState",
    "DebuggerBridge",
    "DisassemblyLine",
    "DynamicAnalysisBridge",
    "FridaBridge",
    "GhidraBridge",
    "InstrumentationBridge",
    "MemorySearchResult",
    "ProcessBridge",
    "Radare2Bridge",
    "StackFrame",
    "StaticAnalysisBridge",
    "ToolBridgeBase",
    "ToolInstaller",
    "WatchpointInfo",
    "X64DbgBridge",
]
