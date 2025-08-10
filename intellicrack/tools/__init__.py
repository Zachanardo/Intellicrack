"""
Intellicrack Tools Package.

Copyright (C) 2025 Zachary Flint

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

import logging

# Set up package logger
logger = logging.getLogger(__name__)

# Import tool modules with error handling
try:
    from .plugin_test_generator import (
        MockDataGenerator,
        PluginTestGenerator,
        PluginTestRunner,
        TestCoverageAnalyzer,
    )
except ImportError as e:
    logger.warning("Failed to import plugin_test_generator: %s", e)
    PluginTestGenerator = None
    TestCoverageAnalyzer = None
    MockDataGenerator = None
    PluginTestRunner = None

try:
    from .plugin_ci_cd import CICDPipeline, GitHubActionsGenerator
except ImportError as e:
    logger.warning("Failed to import plugin_ci_cd: %s", e)
    CICDPipeline = None
    GitHubActionsGenerator = None

try:
    from .plugin_debugger import (
        Breakpoint,
        BreakpointType,
        DebuggerState,
        DebuggerThread,
        PluginDebugger,
        StackFrame,
    )
except ImportError as e:
    logger.warning("Failed to import plugin_debugger: %s", e)
    PluginDebugger = None
    DebuggerThread = None
    BreakpointType = None
    DebuggerState = None
    Breakpoint = None
    StackFrame = None

try:
    from .protection_analyzer_tool import (
        ProtectionAnalyzerTool,
        register_protection_analyzer_tool,
    )
except ImportError as e:
    logger.warning("Failed to import protection_analyzer_tool: %s", e)
    ProtectionAnalyzerTool = None
    register_protection_analyzer_tool = None

# Define package exports
__all__ = []

if PluginTestGenerator is not None:
    __all__.extend(
        ["PluginTestGenerator", "TestCoverageAnalyzer", "MockDataGenerator", "PluginTestRunner"]
    )

if CICDPipeline is not None:
    __all__.extend(["CICDPipeline", "GitHubActionsGenerator"])

if PluginDebugger is not None:
    __all__.extend(
        [
            "PluginDebugger",
            "DebuggerThread",
            "BreakpointType",
            "DebuggerState",
            "Breakpoint",
            "StackFrame",
        ]
    )

if ProtectionAnalyzerTool is not None:
    __all__.extend(["ProtectionAnalyzerTool", "register_protection_analyzer_tool"])

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
