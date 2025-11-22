"""Intellicrack Real-time Dashboard Package.

This package provides real-time monitoring and visualization capabilities
for Intellicrack's binary analysis operations.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import logging


logger = logging.getLogger(__name__)

__version__ = "1.0.0"

# Lazy imports to prevent circular import issues
_dashboard_manager = None
_dashboard_widgets = None
_real_time_dashboard = None


def _lazy_import_dashboard_manager() -> object:
    """Lazy import of dashboard manager module."""
    global _dashboard_manager
    if _dashboard_manager is None:
        try:
            from . import dashboard_manager as _imported_dashboard_manager

            _dashboard_manager = _imported_dashboard_manager
        except ImportError as e:
            logger.warning("Dashboard manager not available: %s", e)
            _dashboard_manager = False
    return _dashboard_manager if _dashboard_manager is not False else None


def _lazy_import_dashboard_widgets() -> object:
    """Lazy import of dashboard widgets module."""
    global _dashboard_widgets
    if _dashboard_widgets is None:
        try:
            from . import dashboard_widgets as _imported_dashboard_widgets

            _dashboard_widgets = _imported_dashboard_widgets
        except ImportError as e:
            logger.warning("Dashboard widgets not available: %s", e)
            _dashboard_widgets = False
    return _dashboard_widgets if _dashboard_widgets is not False else None


def _lazy_import_real_time_dashboard() -> object:
    """Lazy import of real-time dashboard module."""
    global _real_time_dashboard
    if _real_time_dashboard is None:
        try:
            from . import real_time_dashboard as _imported_real_time_dashboard

            _real_time_dashboard = _imported_real_time_dashboard
        except ImportError as e:
            logger.warning("Real-time dashboard not available: %s", e)
            _real_time_dashboard = False
    return _real_time_dashboard if _real_time_dashboard is not False else None


# Create properties for lazy loading
dashboard_manager = property(lambda self: _lazy_import_dashboard_manager())
dashboard_widgets = property(lambda self: _lazy_import_dashboard_widgets())
real_time_dashboard = property(lambda self: _lazy_import_real_time_dashboard())


# For backwards compatibility, expose the classes and functions
def __getattr__(name: str) -> object:
    """Lazy attribute access for dashboard components."""
    if name in {
        "DashboardLayout",
        "DashboardManager",
        "DataSource",
        "DataSourceType",
        "create_dashboard_manager",
    }:
        if dm := _lazy_import_dashboard_manager():
            return getattr(dm, name)
    elif name in {
        "DashboardWidget",
        "GaugeWidget",
        "HeatmapWidget",
        "LineChartWidget",
        "NetworkGraphWidget",
        "ProgressWidget",
        "TableWidget",
        "TimelineWidget",
        "WidgetConfig",
        "WidgetData",
        "WidgetFactory",
        "WidgetType",
        "create_widget",
    }:
        if dw := _lazy_import_dashboard_widgets():
            return getattr(dw, name)
    elif name in (
        "AnalysisMetrics",
        "DashboardEvent",
        "DashboardEventType",
        "RealTimeDashboard",
        "create_dashboard",
    ):
        if rtd := _lazy_import_real_time_dashboard():
            return getattr(rtd, name)
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = [
    "AnalysisMetrics",
    "DashboardEvent",
    "DashboardEventType",
    "DashboardLayout",
    "DashboardManager",
    "DashboardWidget",
    "DataSource",
    "DataSourceType",
    "GaugeWidget",
    "HeatmapWidget",
    "LineChartWidget",
    "NetworkGraphWidget",
    "ProgressWidget",
    "RealTimeDashboard",
    "TableWidget",
    "TimelineWidget",
    "WidgetConfig",
    "WidgetData",
    "WidgetFactory",
    "WidgetType",
    "create_dashboard",
    "create_dashboard_manager",
    "create_widget",
]
