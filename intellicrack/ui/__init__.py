"""Intellicrack User Interface Package.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging


logger = logging.getLogger(__name__)

_lazy_imports = {}


def __getattr__(name: str) -> object:
    """Lazy load UI module attributes to prevent circular imports."""
    if name in _lazy_imports:
        return _lazy_imports[name]

    if name == "IntellicrackMainWindow":
        try:
            from .main_window import IntellicrackMainWindow

            _lazy_imports[name] = IntellicrackMainWindow
            return IntellicrackMainWindow
        except ImportError as e:
            logger.warning("Failed to import main_window: %s", e)
            return None

    elif name == "DashboardManager":
        try:
            from .dashboard_manager import DashboardManager

            _lazy_imports[name] = DashboardManager
            return DashboardManager
        except ImportError as e:
            logger.warning("Failed to import dashboard_manager: %s", e)
            return None

    elif name in {
        "ComprehensiveR2Integration",
        "cleanup_integration",
        "get_comprehensive_integration",
        "get_integration_status",
        "integrate_radare2_comprehensive",
    }:
        try:
            from .comprehensive_integration import (
                ComprehensiveR2Integration,
                cleanup_integration,
                get_comprehensive_integration,
                get_integration_status,
                integrate_radare2_comprehensive,
            )

            _lazy_imports.update(
                {
                    "ComprehensiveR2Integration": ComprehensiveR2Integration,
                    "cleanup_integration": cleanup_integration,
                    "get_comprehensive_integration": get_comprehensive_integration,
                    "get_integration_status": get_integration_status,
                    "integrate_radare2_comprehensive": integrate_radare2_comprehensive,
                }
            )
            return _lazy_imports.get(name)
        except ImportError as e:
            logger.warning("Failed to import comprehensive_integration: %s", e)
            return None

    elif name in {
        "R2ConfigurationDialog",
        "R2IntegrationWidget",
        "R2ResultsViewer",
        "create_radare2_tab",
    }:
        try:
            from .radare2_integration_ui import R2ConfigurationDialog, R2IntegrationWidget, R2ResultsViewer, create_radare2_tab

            _lazy_imports.update(
                {
                    "R2ConfigurationDialog": R2ConfigurationDialog,
                    "R2IntegrationWidget": R2IntegrationWidget,
                    "R2ResultsViewer": R2ResultsViewer,
                    "create_radare2_tab": create_radare2_tab,
                }
            )
            return _lazy_imports.get(name)
        except ImportError as e:
            logger.warning("Failed to import radare2_integration_ui: %s", e)
            return None

    elif name in {
        "EnhancedAnalysisDashboard",
        "EnhancedMainWindow",
        "create_enhanced_application",
    }:
        try:
            from .enhanced_ui_integration import EnhancedAnalysisDashboard, EnhancedMainWindow, create_enhanced_application

            _lazy_imports.update(
                {
                    "EnhancedAnalysisDashboard": EnhancedAnalysisDashboard,
                    "EnhancedMainWindow": EnhancedMainWindow,
                    "create_enhanced_application": create_enhanced_application,
                }
            )
            return _lazy_imports.get(name)
        except ImportError as e:
            logger.warning("Failed to import enhanced_ui_integration: %s", e)
            return None

    elif name in {"R2UIManager", "create_r2_ui_manager"}:
        try:
            from .radare2_ui_manager import R2UIManager, create_r2_ui_manager

            _lazy_imports.update(
                {
                    "R2UIManager": R2UIManager,
                    "create_r2_ui_manager": create_r2_ui_manager,
                }
            )
            return _lazy_imports.get(name)
        except ImportError as e:
            logger.warning("Failed to import radare2_ui_manager: %s", e)
            return None

    elif name == "dialogs":
        try:
            from . import dialogs

            _lazy_imports["dialogs"] = dialogs
            return dialogs
        except ImportError as e:
            logger.warning("Failed to import dialogs: %s", e)
            return None

    elif name == "widgets":
        try:
            from . import widgets

            _lazy_imports["widgets"] = widgets
            return widgets
        except ImportError as e:
            logger.warning("Failed to import widgets: %s", e)
            return None

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = [
    "ComprehensiveR2Integration",
    "DashboardManager",
    "EnhancedAnalysisDashboard",
    "EnhancedMainWindow",
    "IntellicrackMainWindow",
    "R2ConfigurationDialog",
    "R2IntegrationWidget",
    "R2ResultsViewer",
    "R2UIManager",
    "cleanup_integration",
    "create_enhanced_application",
    "create_r2_ui_manager",
    "create_radare2_tab",
    "dialogs",
    "get_comprehensive_integration",
    "get_integration_status",
    "integrate_radare2_comprehensive",
    "widgets",
]

__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
