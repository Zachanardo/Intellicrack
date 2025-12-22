"""LLM Tools Package

Collection of tools that AI models can use for various analysis tasks.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any

from .binary_analysis_tool import BinaryAnalysisTool, create_binary_tool
from .firmware_analysis_tool import FirmwareAnalysisTool, create_firmware_analysis_tool
from .intellicrack_protection_analysis_tool import DIEAnalysisTool, create_die_tool
from .memory_forensics_tool import MemoryForensicsTool, create_memory_forensics_tool
from .script_generation_tool import ScriptGenerationTool, create_script_tool
from .yara_pattern_analysis_tool import YARAPatternAnalysisTool, create_yara_pattern_tool

__all__ = [
    "BinaryAnalysisTool",
    "DIEAnalysisTool",
    "FirmwareAnalysisTool",
    "MemoryForensicsTool",
    "ScriptGenerationTool",
    "YARAPatternAnalysisTool",
    "create_binary_tool",
    "create_die_tool",
    "create_firmware_analysis_tool",
    "create_memory_forensics_tool",
    "create_script_tool",
    "create_yara_pattern_tool",
    "get_all_tools",
    "register_tools_with_llm",
]


def get_all_tools() -> dict[str, Any]:
    """Get all available LLM tools"""
    return {
        "die_analysis": create_die_tool(),
        "binary_analysis": create_binary_tool(),
        "script_generation": create_script_tool(),
        "yara_pattern_analysis": create_yara_pattern_tool(),
        "firmware_analysis": create_firmware_analysis_tool(),
        "memory_forensics": create_memory_forensics_tool(),
    }


def register_tools_with_llm(llm_backend: Any) -> None:
    """Register all tools with an LLM backend

    Args:
        llm_backend: The LLM backend to register tools with

    """
    tools = get_all_tools()

    for tool_name, tool in tools.items():
        if hasattr(llm_backend, "register_tool"):
            register_func = getattr(llm_backend, "register_tool", None)
            if callable(register_func):
                register_func(tool_name, tool)
        elif hasattr(llm_backend, "add_tool"):
            add_tool_func = getattr(llm_backend, "add_tool", None)
            get_def_func = getattr(tool, "get_tool_definition", None)
            execute_func = getattr(tool, "execute", None)
            if callable(add_tool_func) and callable(get_def_func) and callable(execute_func):
                add_tool_func(get_def_func(), execute_func)
