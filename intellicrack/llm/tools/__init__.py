"""
LLM Tools Package

Collection of tools that AI models can use for various analysis tasks.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from .binary_analysis_tool import BinaryAnalysisTool, create_binary_tool
from .firmware_analysis_tool import FirmwareAnalysisTool, create_firmware_analysis_tool
from .intellicrack_protection_analysis_tool import DIEAnalysisTool, create_die_tool
from .memory_forensics_tool import MemoryForensicsTool, create_memory_forensics_tool
from .script_generation_tool import ScriptGenerationTool, create_script_tool
from .yara_pattern_analysis_tool import YARAPatternAnalysisTool, create_yara_pattern_tool

__all__ = [
    'DIEAnalysisTool',
    'create_die_tool',
    'BinaryAnalysisTool',
    'create_binary_tool',
    'ScriptGenerationTool',
    'create_script_tool',
    'YARAPatternAnalysisTool',
    'create_yara_pattern_tool',
    'FirmwareAnalysisTool',
    'create_firmware_analysis_tool',
    'MemoryForensicsTool',
    'create_memory_forensics_tool',
    'get_all_tools',
    'register_tools_with_llm'
]


def get_all_tools():
    """Get all available LLM tools"""
    return {
        'die_analysis': create_die_tool(),
        'binary_analysis': create_binary_tool(),
        'script_generation': create_script_tool(),
        'yara_pattern_analysis': create_yara_pattern_tool(),
        'firmware_analysis': create_firmware_analysis_tool(),
        'memory_forensics': create_memory_forensics_tool()
    }


def register_tools_with_llm(llm_backend):
    """
    Register all tools with an LLM backend

    Args:
        llm_backend: The LLM backend to register tools with
    """
    tools = get_all_tools()

    for tool_name, tool in tools.items():
        if hasattr(llm_backend, 'register_tool'):
            llm_backend.register_tool(tool_name, tool)
        elif hasattr(llm_backend, 'add_tool'):
            llm_backend.add_tool(tool.get_tool_definition(), tool.execute)
