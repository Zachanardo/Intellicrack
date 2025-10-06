"""Intellicrack Real-time Dashboard Package.

This package provides real-time monitoring and visualization capabilities
for Intellicrack's binary analysis operations.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from intellicrack.dashboard.dashboard_manager import DashboardLayout, DashboardManager, DataSource, DataSourceType, create_dashboard_manager
from intellicrack.dashboard.dashboard_widgets import (
    DashboardWidget,
    GaugeWidget,
    HeatmapWidget,
    LineChartWidget,
    NetworkGraphWidget,
    ProgressWidget,
    TableWidget,
    TimelineWidget,
    WidgetConfig,
    WidgetData,
    WidgetFactory,
    WidgetType,
    create_widget,
)
from intellicrack.dashboard.real_time_dashboard import (
    AnalysisMetrics,
    DashboardEvent,
    DashboardEventType,
    RealTimeDashboard,
    create_dashboard,
)

__all__ = [
    # Real-time dashboard
    "RealTimeDashboard",
    "DashboardEvent",
    "DashboardEventType",
    "AnalysisMetrics",
    "create_dashboard",
    # Widgets
    "DashboardWidget",
    "WidgetConfig",
    "WidgetData",
    "WidgetType",
    "LineChartWidget",
    "GaugeWidget",
    "TableWidget",
    "HeatmapWidget",
    "NetworkGraphWidget",
    "TimelineWidget",
    "ProgressWidget",
    "WidgetFactory",
    "create_widget",
    # Manager
    "DashboardManager",
    "DataSource",
    "DataSourceType",
    "DashboardLayout",
    "create_dashboard_manager",
]

__version__ = "1.0.0"
