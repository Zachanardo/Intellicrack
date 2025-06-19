"""
Intellicrack UI Widgets Package 

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import logging

# Set up package logger
logger = logging.getLogger(__name__)

# Import widget modules with error handling
try:
    from .hex_viewer import (
        AssemblyView,
        CallGraphWidget,
        CFGWidget,
        FilterPanel,
        GraphWidget,
        HeatmapWidget,
        HexViewer,
        LogViewer,
        ProgressWidget,
        SearchBar,
        StatusBar,
        TimelineWidget,
        ToolPanel,
    )
except ImportError as e:
    logger.warning("Failed to import widgets from hex_viewer: %s", e)
    # Define fallback classes
    class HexViewer:
        """Fallback class for HexViewer widget when hex_viewer module is not available."""
        pass
    class AssemblyView:
        """Fallback class for AssemblyView widget when hex_viewer module is not available."""
        pass
    class CFGWidget:
        """Fallback class for Control Flow Graph widget when hex_viewer module is not available."""
        pass
    class CallGraphWidget:
        """Fallback class for Call Graph widget when hex_viewer module is not available."""
        pass
    class SearchBar:
        """Fallback class for SearchBar widget when hex_viewer module is not available."""
        pass
    class FilterPanel:
        """Fallback class for FilterPanel widget when hex_viewer module is not available."""
        pass
    class ToolPanel:
        """Fallback class for ToolPanel widget when hex_viewer module is not available."""
        pass
    class HeatmapWidget:
        """Fallback class for HeatmapWidget when hex_viewer module is not available."""
        pass
    class GraphWidget:
        """Fallback class for GraphWidget when hex_viewer module is not available."""
        pass
    class TimelineWidget:
        """Fallback class for TimelineWidget when hex_viewer module is not available."""
        pass
    class ProgressWidget:
        """Fallback class for ProgressWidget when hex_viewer module is not available."""
        pass
    class StatusBar:
        """Fallback class for StatusBar widget when hex_viewer module is not available."""
        pass
    class LogViewer:
        """Fallback class for LogViewer widget when hex_viewer module is not available."""
        pass

# Import console widget
try:
    from .console_widget import ConsoleWidget
except ImportError as e:
    logger.warning("Failed to import console_widget: %s", e)
    ConsoleWidget = None

# Import plugin editor
try:
    from .plugin_editor import PluginEditor, PluginValidator, PythonHighlighter, JavaScriptHighlighter
except ImportError as e:
    logger.warning("Failed to import plugin_editor: %s", e)
    PluginEditor = None
    PluginValidator = None
    PythonHighlighter = None
    JavaScriptHighlighter = None

# Define common widget exports
__all__ = [
    # Analysis widgets
    'HexViewer',
    'AssemblyView',
    'CFGWidget',
    'CallGraphWidget',

    # Control widgets
    'SearchBar',
    'FilterPanel',
    'ToolPanel',

    # Visualization widgets
    'HeatmapWidget',
    'GraphWidget',
    'TimelineWidget',

    # Status widgets
    'ProgressWidget',
    'StatusBar',
    'LogViewer',
]

# Add ConsoleWidget if available
if ConsoleWidget is not None:
    __all__.append('ConsoleWidget')

# Add Plugin Editor classes if available
if PluginEditor is not None:
    __all__.extend(['PluginEditor', 'PluginValidator', 'PythonHighlighter', 'JavaScriptHighlighter'])

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
