"""Centralized Style Manager for Intellicrack UI
Manages style application without inline setStyleSheet calls.

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

from typing import Dict

from intellicrack.handlers.pyqt6_handler import (
    QFrame,
    QLabel,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QWidget,
)


class StyleManager:
    """Production-ready centralized style manager for all UI widgets."""

    # Widget style mappings - define object names for widgets
    STYLE_MAPPINGS = {
        # Status labels
        "status_success": "statusSuccess",
        "status_error": "statusError",
        "status_warning": "statusWarning",
        "status_info": "statusInfo",
        "status_neutral": "statusNeutral",
        # Headers and titles
        "header_bold": "headerBold",
        "title_large": "titleLarge",
        "title_medium": "titleMedium",
        "header_medium": "headerMedium",
        "subtitle": "subtitle",
        # Descriptive text
        "description_text": "descriptionText",
        "hint_text": "hintText",
        "muted_text": "mutedText",
        "small_muted_text": "smallMutedText",
        "info_text": "infoText",
        # Buttons
        "primary_button": "primaryButton",
        "secondary_button": "secondaryButton",
        "danger_button": "dangerButton",
        "warning_button": "warningButton",
        "accent_button": "accentButton",
        "load_model_button": "loadModelButton",
        "generate_button": "generateButton",
        "continue_button": "continueButton",
        "run_analysis_button": "runAnalysisButton",
        "generate_script_button": "generateScriptButton",
        "clear_cache_button": "clearCacheButton",
        # Progress bars
        "model_loading_progress": "modelLoadingProgress",
        "loading_progress": "loadingProgress",
        "failed_progress": "failedProgress",
        "pending_progress": "pendingProgress",
        "completed_progress": "completedProgress",
        "initializing": "initializing",
        "splash_progress": "splashProgress",
        "cpu_high": "cpuHigh",
        "cpu_medium": "cpuMedium",
        "cpu_normal": "cpuNormal",
        "memory_high": "memoryHigh",
        "gpu_high": "gpuHigh",
        "gpu_medium": "gpuMedium",
        "gpu_normal": "gpuNormal",
        # Panels and containers
        "welcome_panel": "welcomePanel",
        "quick_start_panel": "quickStartPanel",
        "stage_widget": "stageWidget",
        "placeholder_panel": "placeholderPanel",
        "preview_text": "previewText",
        # Console and output
        "console_output": "consoleOutput",
        "output_console": "outputConsole",
        # Specialized widgets
        "drop_zone_active": "dropZoneActive",
        "drop_zone_inactive": "dropZoneInactive",
        "advanced_transparent": "advancedTransparent",
        "file_path_display": "filePathDisplay",
        # Cache management
        "cache_stats_label": "cacheStatsLabel",
        "cache_header_label": "cacheHeaderLabel",
        "cache_title_label": "cacheTitleLabel",
        # Hex viewer
        "hex_viewer": "hexViewer",
        # Project/binary labels
        "current_project_label": "currentProjectLabel",
        "current_binary_label": "currentBinaryLabel",
        # Status variations
        "installed_status": "installedStatus",
        "not_installed_status": "notInstalledStatus",
        "installing_status": "installingStatus",
        # Headers
        "header_label": "headerLabel",
        "stats_label": "statsLabel",
        # Plugin items
        "plugin_item": "pluginItem",
        # Frames
        "stats_frame": "statsFrame",
        # Activity log
        "activity_log": "activityLog",
    }

    @classmethod
    def apply_style(cls, widget: QWidget, style_name: str) -> None:
        """Apply a predefined style to a widget.

        Args:
            widget: The widget to style
            style_name: The name of the style to apply

        """
        if style_name in cls.STYLE_MAPPINGS:
            object_name = cls.STYLE_MAPPINGS[style_name]
            widget.setObjectName(object_name)
        else:
            print(f"Warning: Unknown style '{style_name}'")

    @classmethod
    def style_label(cls, label: QLabel, style_type: str) -> None:
        """Apply style to a QLabel.

        Args:
            label: The label to style
            style_type: Type of label style to apply

        """
        cls.apply_style(label, style_type)

    @classmethod
    def style_button(cls, button: QPushButton, style_type: str) -> None:
        """Apply style to a QPushButton.

        Args:
            button: The button to style
            style_type: Type of button style to apply

        """
        cls.apply_style(button, style_type)

    @classmethod
    def style_progress(cls, progress: QProgressBar, style_type: str) -> None:
        """Apply style to a QProgressBar.

        Args:
            progress: The progress bar to style
            style_type: Type of progress bar style to apply

        """
        cls.apply_style(progress, style_type)

    @classmethod
    def style_text_edit(cls, text_edit: QTextEdit, style_type: str) -> None:
        """Apply style to a QTextEdit.

        Args:
            text_edit: The text edit to style
            style_type: Type of text edit style to apply

        """
        cls.apply_style(text_edit, style_type)

    @classmethod
    def style_frame(cls, frame: QFrame, style_type: str) -> None:
        """Apply style to a QFrame.

        Args:
            frame: The frame to style
            style_type: Type of frame style to apply

        """
        cls.apply_style(frame, style_type)

    @classmethod
    def update_status_style(cls, label: QLabel, status: str) -> None:
        """Update status label style based on status.

        Args:
            label: The status label
            status: The status type ('success', 'error', 'warning', 'info', 'neutral')

        """
        status_map = {
            "success": "status_success",
            "error": "status_error",
            "warning": "status_warning",
            "info": "status_info",
            "neutral": "status_neutral",
            "installed": "installed_status",
            "not_installed": "not_installed_status",
            "installing": "installing_status",
        }

        if status in status_map:
            cls.style_label(label, status_map[status])
        else:
            cls.style_label(label, "status_neutral")

    @classmethod
    def update_progress_style(cls, progress: QProgressBar, state: str) -> None:
        """Update progress bar style based on state.

        Args:
            progress: The progress bar
            state: The state ('loading', 'failed', 'pending', 'completed', 'initializing')

        """
        state_map = {
            "loading": "loading_progress",
            "failed": "failed_progress",
            "pending": "pending_progress",
            "completed": "completed_progress",
            "initializing": "initializing",
        }

        if state in state_map:
            cls.style_progress(progress, state_map[state])

    @classmethod
    def update_cpu_progress_style(cls, progress: QProgressBar, usage: float) -> None:
        """Update CPU progress bar style based on usage.

        Args:
            progress: The progress bar
            usage: CPU usage percentage

        """
        if usage >= 80:
            cls.style_progress(progress, "cpu_high")
        elif usage >= 50:
            cls.style_progress(progress, "cpu_medium")
        else:
            cls.style_progress(progress, "cpu_normal")

    @classmethod
    def update_gpu_progress_style(cls, progress: QProgressBar, usage: float) -> None:
        """Update GPU progress bar style based on usage.

        Args:
            progress: The progress bar
            usage: GPU usage percentage

        """
        if usage >= 80:
            cls.style_progress(progress, "gpu_high")
        elif usage >= 50:
            cls.style_progress(progress, "gpu_medium")
        else:
            cls.style_progress(progress, "gpu_normal")

    @classmethod
    def update_memory_progress_style(cls, progress: QProgressBar, usage: float) -> None:
        """Update memory progress bar style based on usage.

        Args:
            progress: The progress bar
            usage: Memory usage percentage

        """
        if usage >= 80:
            cls.style_progress(progress, "memory_high")
        elif usage >= 50:
            cls.style_progress(progress, "cpu_medium")  # Reuse CPU medium style
        else:
            cls.style_progress(progress, "cpu_normal")  # Reuse CPU normal style

    @classmethod
    def style_drop_zone(cls, widget: QWidget, active: bool) -> None:
        """Style a drop zone widget.

        Args:
            widget: The drop zone widget
            active: Whether the drop zone is active

        """
        if active:
            cls.apply_style(widget, "drop_zone_active")
        else:
            cls.apply_style(widget, "drop_zone_inactive")

    @classmethod
    def remove_inline_styles(cls, widget: QWidget) -> None:
        """Remove any inline styles from a widget.

        Args:
            widget: The widget to clean

        """
        widget.setStyleSheet("")

    @classmethod
    def batch_apply_styles(cls, widgets: Dict[QWidget, str]) -> None:
        """Apply styles to multiple widgets at once.

        Args:
            widgets: Dictionary mapping widgets to their style names

        """
        for widget, style_name in widgets.items():
            cls.apply_style(widget, style_name)
