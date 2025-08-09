"""UI Tabs Module for Intellicrack.

This module provides tab components for the main application window.

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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

# Import tab classes using absolute imports
try:
    from intellicrack.ui.analysis_tab import AnalysisTab
except ImportError:
    AnalysisTab = None

try:
    from intellicrack.ui.analysis_tab_original import AnalysisTabOriginal
except ImportError:
    AnalysisTabOriginal = None

try:
    from intellicrack.ui.base_tab import BaseTab
except ImportError:
    BaseTab = None

try:
    from intellicrack.ui.base_tab_original import BaseTabOriginal
except ImportError:
    BaseTabOriginal = None

try:
    from intellicrack.ui.dashboard_tab import DashboardTab
except ImportError:
    DashboardTab = None

try:
    from intellicrack.ui.dashboard_tab_original import DashboardTabOriginal
except ImportError:
    DashboardTabOriginal = None

try:
    from intellicrack.ui.exploitation_tab import ExploitationTab
except ImportError:
    ExploitationTab = None

try:
    from intellicrack.ui.project_workspace_tab import ProjectWorkspaceTab
except ImportError:
    ProjectWorkspaceTab = None

try:
    from intellicrack.ui.settings_tab import SettingsTab
except ImportError:
    SettingsTab = None

try:
    from intellicrack.ui.tools_tab import ToolsTab
except ImportError:
    ToolsTab = None

try:
    from intellicrack.ui.ai_assistant_tab import AIAssistantTab
except ImportError:
    AIAssistantTab = None

# Export available tabs
__all__ = []

if AnalysisTab:
    __all__.append("AnalysisTab")
if AnalysisTabOriginal:
    __all__.append("AnalysisTabOriginal")
if BaseTab:
    __all__.append("BaseTab")
if BaseTabOriginal:
    __all__.append("BaseTabOriginal")
if DashboardTab:
    __all__.append("DashboardTab")
if DashboardTabOriginal:
    __all__.append("DashboardTabOriginal")
if ExploitationTab:
    __all__.append("ExploitationTab")
if ProjectWorkspaceTab:
    __all__.append("ProjectWorkspaceTab")
if SettingsTab:
    __all__.append("SettingsTab")
if ToolsTab:
    __all__.append("ToolsTab")
if AIAssistantTab:
    __all__.append("AIAssistantTab")