"""
Intellicrack UI Widgets Package

This package provides custom UI widgets and components for the Intellicrack framework.
These widgets extend the base Qt functionality to provide specialized visualizations
and controls for binary analysis tasks.

Key Features:
    - Custom visualization widgets
    - Specialized input controls
    - Interactive analysis displays
    - Real-time data viewers
    - Enhanced UI components

Widget Categories:
    - Analysis widgets for displaying results
    - Control widgets for user interaction
    - Visualization widgets for data representation
    - Status widgets for progress monitoring
"""

import logging

# Set up package logger
logger = logging.getLogger(__name__)

# Import widget modules with error handling
try:
    from .hex_viewer import (
        HexViewer, AssemblyView, CFGWidget, CallGraphWidget,
        SearchBar, FilterPanel, ToolPanel,
        HeatmapWidget, GraphWidget, TimelineWidget,
        ProgressWidget, StatusBar, LogViewer
    )
except ImportError as e:
    logger.warning("Failed to import widgets from hex_viewer: %s", e)
    # Define fallback classes
    class HexViewer: pass
    class AssemblyView: pass
    class CFGWidget: pass
    class CallGraphWidget: pass
    class SearchBar: pass
    class FilterPanel: pass
    class ToolPanel: pass
    class HeatmapWidget: pass
    class GraphWidget: pass
    class TimelineWidget: pass
    class ProgressWidget: pass
    class StatusBar: pass
    class LogViewer: pass

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

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
