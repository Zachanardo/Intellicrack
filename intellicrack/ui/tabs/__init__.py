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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from typing import Any


_analysis_tab_cls: type[Any] | None
try:
    from intellicrack.ui.tabs.analysis_tab import AnalysisTab as _AnalysisTabImport

    _analysis_tab_cls = _AnalysisTabImport
except ImportError:
    _analysis_tab_cls = None
AnalysisTab: type[Any] | None = _analysis_tab_cls

_base_tab_cls: type[Any] | None
try:
    from intellicrack.ui.tabs.base_tab import BaseTab as _BaseTabImport

    _base_tab_cls = _BaseTabImport
except ImportError:
    _base_tab_cls = None
BaseTab: type[Any] | None = _base_tab_cls

_dashboard_tab_cls: type[Any] | None
try:
    from intellicrack.ui.tabs.dashboard_tab import DashboardTab as _DashboardTabImport

    _dashboard_tab_cls = _DashboardTabImport
except ImportError:
    _dashboard_tab_cls = None
DashboardTab: type[Any] | None = _dashboard_tab_cls

_exploitation_tab_cls: type[Any] | None
try:
    from intellicrack.ui.tabs.exploitation_tab import ExploitationTab as _ExploitationTabImport

    _exploitation_tab_cls = _ExploitationTabImport
except ImportError:
    _exploitation_tab_cls = None
ExploitationTab: type[Any] | None = _exploitation_tab_cls

_project_workspace_tab_cls: type[Any] | None
try:
    from intellicrack.ui.tabs.project_workspace_tab import ProjectWorkspaceTab as _ProjectWorkspaceTabImport

    _project_workspace_tab_cls = _ProjectWorkspaceTabImport
except ImportError:
    _project_workspace_tab_cls = None
ProjectWorkspaceTab: type[Any] | None = _project_workspace_tab_cls

_settings_tab_cls: type[Any] | None
try:
    from intellicrack.ui.tabs.settings_tab import SettingsTab as _SettingsTabImport

    _settings_tab_cls = _SettingsTabImport
except ImportError:
    _settings_tab_cls = None
SettingsTab: type[Any] | None = _settings_tab_cls

_tools_tab_cls: type[Any] | None
try:
    from intellicrack.ui.tabs.tools_tab import ToolsTab as _ToolsTabImport

    _tools_tab_cls = _ToolsTabImport
except ImportError:
    _tools_tab_cls = None
ToolsTab: type[Any] | None = _tools_tab_cls

_ai_assistant_tab_cls: type[Any] | None
try:
    from intellicrack.ui.tabs.ai_assistant_tab import AIAssistantTab as _AIAssistantTabImport

    _ai_assistant_tab_cls = _AIAssistantTabImport
except ImportError:
    _ai_assistant_tab_cls = None
AIAssistantTab: type[Any] | None = _ai_assistant_tab_cls

_terminal_tab_cls: type[Any] | None
try:
    from intellicrack.ui.tabs.terminal_tab import TerminalTab as _TerminalTabImport

    _terminal_tab_cls = _TerminalTabImport
except ImportError:
    _terminal_tab_cls = None
TerminalTab: type[Any] | None = _terminal_tab_cls

_workspace_tab_cls: type[Any] | None
try:
    from intellicrack.ui.tabs.workspace_tab import WorkspaceTab as _WorkspaceTabImport

    _workspace_tab_cls = _WorkspaceTabImport
except ImportError:
    _workspace_tab_cls = None
WorkspaceTab: type[Any] | None = _workspace_tab_cls

_adobe_injector_tab_cls: type[Any] | None
try:
    from intellicrack.ui.tabs.adobe_injector_tab import AdobeInjectorTab as _AdobeInjectorTabImport

    _adobe_injector_tab_cls = _AdobeInjectorTabImport
except ImportError:
    _adobe_injector_tab_cls = None
AdobeInjectorTab: type[Any] | None = _adobe_injector_tab_cls

__all__: list[str] = []

if AnalysisTab is not None:
    __all__.append("AnalysisTab")
if BaseTab is not None:
    __all__.append("BaseTab")
if DashboardTab is not None:
    __all__.append("DashboardTab")
if ExploitationTab is not None:
    __all__.append("ExploitationTab")
if ProjectWorkspaceTab is not None:
    __all__.append("ProjectWorkspaceTab")
if SettingsTab is not None:
    __all__.append("SettingsTab")
if ToolsTab is not None:
    __all__.append("ToolsTab")
if AIAssistantTab is not None:
    __all__.append("AIAssistantTab")
if TerminalTab is not None:
    __all__.append("TerminalTab")
if WorkspaceTab is not None:
    __all__.append("WorkspaceTab")
if AdobeInjectorTab is not None:
    __all__.append("AdobeInjectorTab")
