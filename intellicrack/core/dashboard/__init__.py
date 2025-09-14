"""Intellicrack Real-time Dashboard Package.

This package provides real-time monitoring and visualization capabilities
for Intellicrack's binary analysis operations.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from .real_time_dashboard import (
    RealTimeDashboard,
    DashboardEvent,
    DashboardEventType,
    AnalysisMetrics,
    create_dashboard
)

from .dashboard_widgets import (
    DashboardWidget,
    WidgetConfig,
    WidgetData,
    WidgetType,
    LineChartWidget,
    GaugeWidget,
    TableWidget,
    HeatmapWidget,
    NetworkGraphWidget,
    TimelineWidget,
    ProgressWidget,
    WidgetFactory,
    create_widget
)

from .dashboard_manager import (
    DashboardManager,
    DataSource,
    DataSourceType,
    DashboardLayout,
    create_dashboard_manager
)

__all__ = [
    # Real-time dashboard
    'RealTimeDashboard',
    'DashboardEvent',
    'DashboardEventType',
    'AnalysisMetrics',
    'create_dashboard',

    # Widgets
    'DashboardWidget',
    'WidgetConfig',
    'WidgetData',
    'WidgetType',
    'LineChartWidget',
    'GaugeWidget',
    'TableWidget',
    'HeatmapWidget',
    'NetworkGraphWidget',
    'TimelineWidget',
    'ProgressWidget',
    'WidgetFactory',
    'create_widget',

    # Manager
    'DashboardManager',
    'DataSource',
    'DataSourceType',
    'DashboardLayout',
    'create_dashboard_manager'
]

__version__ = "1.0.0"