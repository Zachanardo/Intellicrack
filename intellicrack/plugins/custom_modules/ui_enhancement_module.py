#!/usr/bin/env python3
"""UI enhancement module plugin for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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

# Standard library imports
import json
import logging
import os
import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

# Third-party imports
from intellicrack.handlers.matplotlib_handler import Figure, FigureCanvasTkAgg
from intellicrack.handlers.tkinter_handler import (
    filedialog,
    messagebox,
    scrolledtext,
    tkinter as tk,
    ttk,
)


"""
UI Enhancement Module

Advanced UI enhancement system for Intellicrack's three-panel interface
providing real-time visualization, interactive analysis tools, and
comprehensive reporting capabilities for all protection analysis modules.

Author: Intellicrack Framework
Version: 2.0.0
License: GPL v3
"""


class UITheme(Enum):
    """UI themes available."""

    DARK = "dark"
    LIGHT = "light"
    HIGH_CONTRAST = "high_contrast"
    CYBERPUNK = "cyberpunk"


class PanelType(Enum):
    """Three-panel interface types."""

    FILE_EXPLORER = "file_explorer"
    ANALYSIS_VIEWER = "analysis_viewer"
    SCRIPT_GENERATOR = "script_generator"


class AnalysisState(Enum):
    """Analysis state tracking."""

    IDLE = "idle"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    GENERATING = "generating"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class UIConfig:
    """UI configuration settings."""

    theme: UITheme = UITheme.DARK
    font_family: str = "Consolas"
    font_size: int = 10
    auto_refresh: bool = True
    refresh_interval: int = 1000
    max_log_entries: int = 10000
    enable_animations: bool = True
    show_tooltips: bool = True
    panel_weights: tuple[int, int, int] = (1, 2, 1)

    def to_dict(self) -> dict[str, Any]:
        """Serialize UI configuration to a dictionary.

        Converts all configuration settings into a dictionary format
        suitable for JSON serialization or storage. Includes theme,
        font settings, refresh options, and panel layout weights.

        Returns:
            Dict containing all UI configuration parameters with
            string keys and JSON-serializable values

        """
        return {
            "theme": self.theme.value,
            "font_family": self.font_family,
            "font_size": self.font_size,
            "auto_refresh": self.auto_refresh,
            "refresh_interval": self.refresh_interval,
            "max_log_entries": self.max_log_entries,
            "enable_animations": self.enable_animations,
            "show_tooltips": self.show_tooltips,
            "panel_weights": self.panel_weights,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UIConfig":
        """Create UIConfig instance from dictionary data.

        Deserializes configuration data from a dictionary, typically
        loaded from JSON storage. Provides default values for any
        missing configuration parameters.

        Args:
            data: Dictionary containing UI configuration parameters

        Returns:
            UIConfig instance with settings from the dictionary

        """
        config = cls()
        config.theme = UITheme(data.get("theme", "dark"))
        config.font_family = data.get("font_family", "Consolas")
        config.font_size = data.get("font_size", 10)
        config.auto_refresh = data.get("auto_refresh", True)
        config.refresh_interval = data.get("refresh_interval", 1000)
        config.max_log_entries = data.get("max_log_entries", 10000)
        config.enable_animations = data.get("enable_animations", True)
        config.show_tooltips = data.get("show_tooltips", True)
        config.panel_weights = tuple(data.get("panel_weights", [1, 2, 1]))
        return config


@dataclass
class AnalysisResult:
    """Analysis result container."""

    target_file: str
    protection_type: str
    confidence: float
    bypass_methods: list[str]
    timestamp: datetime
    details: dict[str, Any] = field(default_factory=dict)
    generated_scripts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert enhancement result to dictionary representation."""
        return {
            "target_file": self.target_file,
            "protection_type": self.protection_type,
            "confidence": self.confidence,
            "bypass_methods": self.bypass_methods,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
            "generated_scripts": self.generated_scripts,
        }


class RealTimeChart:
    """Real-time data visualization."""

    def __init__(self, parent: tk.Widget, title: str = "Analysis Progress") -> None:
        """Initialize real-time chart widget with dark theme styling."""
        self.parent = parent
        self.title = title
        self.figure = Figure(figsize=(8, 4), dpi=100, facecolor="#2d2d2d")
        self.axis = self.figure.add_subplot(111, facecolor="#2d2d2d")

        # Style the plot for dark theme
        self.axis.tick_params(colors="white")
        self.axis.xaxis.label.set_color("white")
        self.axis.yaxis.label.set_color("white")
        self.axis.title.set_color("white")
        self.axis.spines["bottom"].set_color("white")
        self.axis.spines["top"].set_color("white")
        self.axis.spines["left"].set_color("white")
        self.axis.spines["right"].set_color("white")

        self.canvas = FigureCanvasTkAgg(self.figure, parent)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Data storage
        self.data_points = []
        self.max_points = 100

    def update_data(self, value: float, label: str = "") -> None:
        """Update chart with new data point."""
        current_time = time.time()
        self.data_points.append((current_time, value, label))

        # Keep only recent points
        if len(self.data_points) > self.max_points:
            self.data_points = self.data_points[-self.max_points :]

        self.refresh()

    def refresh(self) -> None:
        """Refresh the chart display."""
        if not self.data_points:
            return

        self.axis.clear()

        # Extract data
        times = [point[0] for point in self.data_points]
        values = [point[1] for point in self.data_points]

        # Plot line
        self.axis.plot(times, values, color="#00ff41", linewidth=2)
        self.axis.fill_between(times, values, alpha=0.3, color="#00ff41")

        # Styling
        self.axis.set_title(self.title, color="white", fontsize=12)
        self.axis.set_xlabel("Time", color="white")
        self.axis.set_ylabel("Value", color="white")
        self.axis.grid(True, alpha=0.3, color="white")

        # Format time axis
        if len(times) > 1:
            time_range = times[-1] - times[0]
            if time_range < 60:
                # Show seconds
                self.axis.set_xticklabels([f"{int(t - times[0])}s" for t in times[:: max(1, len(times) // 5)]])
            else:
                # Show minutes
                self.axis.set_xticklabels([f"{int((t - times[0]) / 60)}m" for t in times[:: max(1, len(times) // 5)]])

        self.canvas.draw()

    def clear_data(self) -> None:
        """Clear all data points and reset the chart display.

        Removes all stored data points and redraws the chart with
        an empty canvas, ready for new data collection.

        """
        self.data_points.clear()
        self.axis.clear()
        self.axis.set_title(self.title, color="white", fontsize=12)
        self.axis.set_xlabel("Time", color="white")
        self.axis.set_ylabel("Value", color="white")
        self.axis.grid(True, alpha=0.3, color="white")
        self.axis.tick_params(colors="white")
        self.axis.spines["bottom"].set_color("white")
        self.axis.spines["top"].set_color("white")
        self.axis.spines["left"].set_color("white")
        self.axis.spines["right"].set_color("white")
        self.canvas.draw()

    def update_pie_data(self, labels: list[str], values: list[float], title: str) -> None:
        """Update the chart with pie chart data for distribution visualization.

        Renders a pie chart showing the distribution of categories such as
        protection types or bypass success rates.

        Args:
            labels: List of category labels for each pie slice.
            values: List of numeric values corresponding to each label.
            title: Title to display above the pie chart.

        """
        if not labels or not values or len(labels) != len(values):
            self.clear_data()
            return

        total = sum(values)
        if total == 0:
            self.clear_data()
            return

        self.axis.clear()

        colors = [
            "#00ff41", "#ff4444", "#ffaa00", "#00aaff",
            "#ff00ff", "#00ffff", "#ffff00", "#ff8800",
            "#88ff00", "#0088ff", "#ff0088", "#8800ff"
        ]
        slice_colors = [colors[i % len(colors)] for i in range(len(labels))]

        _wedges, _texts, autotexts = self.axis.pie(
            values,
            labels=labels,
            colors=slice_colors,
            autopct=lambda pct: f"{pct:.1f}%" if pct > 5 else "",
            startangle=90,
            textprops={"color": "white", "fontsize": 9},
            wedgeprops={"edgecolor": "#2d2d2d", "linewidth": 1}
        )

        for autotext in autotexts:
            autotext.set_color("white")
            autotext.set_fontweight("bold")

        self.axis.set_title(title, color="white", fontsize=12, fontweight="bold")
        self.title = title
        self.canvas.draw()


class LogViewer:
    """Enhanced log viewer with filtering and search."""

    def __init__(self, parent: tk.Widget, config: UIConfig) -> None:
        """Initialize enhanced log viewer with filtering and search capabilities."""
        self.parent = parent
        self.config = config
        self.log_entries = []

        # Create log frame
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Toolbar
        self.toolbar = ttk.Frame(self.frame)
        self.toolbar.pack(fill=tk.X, padx=5, pady=2)

        # Search
        ttk.Label(self.toolbar, text="Search:").pack(side=tk.LEFT, padx=2)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self.toolbar, textvariable=self.search_var, width=20)
        self.search_entry.pack(side=tk.LEFT, padx=2)
        self.search_entry.bind("<KeyRelease>", self.on_search)

        # Log level filter
        ttk.Label(self.toolbar, text="Level:").pack(side=tk.LEFT, padx=(10, 2))
        self.level_var = tk.StringVar(value="ALL")
        self.level_combo = ttk.Combobox(
            self.toolbar,
            textvariable=self.level_var,
            values=["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            width=10,
            state="readonly",
        )
        self.level_combo.pack(side=tk.LEFT, padx=2)
        self.level_combo.bind("<<ComboboxSelected>>", self.on_filter_change)

        # Clear button
        self.clear_btn = ttk.Button(self.toolbar, text="Clear", command=self.clear_logs)
        self.clear_btn.pack(side=tk.RIGHT, padx=2)

        # Export button
        self.export_btn = ttk.Button(self.toolbar, text="Export", command=self.export_logs)
        self.export_btn.pack(side=tk.RIGHT, padx=2)

        # Text widget with scrollbar
        self.text_frame = ttk.Frame(self.frame)
        self.text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)

        self.text_widget = scrolledtext.ScrolledText(
            self.text_frame,
            wrap=tk.WORD,
            font=(config.font_family, config.font_size),
            bg="#1e1e1e",
            fg="#ffffff",
            insertbackground="#ffffff",
            selectbackground="#264f78",
        )
        self.text_widget.pack(fill=tk.BOTH, expand=True)

        # Configure text tags for different log levels
        self.text_widget.tag_configure("DEBUG", foreground="#888888")
        self.text_widget.tag_configure("INFO", foreground="#ffffff")
        self.text_widget.tag_configure("WARNING", foreground="#ffaa00")
        self.text_widget.tag_configure("ERROR", foreground="#ff4444")
        self.text_widget.tag_configure("CRITICAL", foreground="#ff0000", background="#440000")
        self.text_widget.tag_configure("TIMESTAMP", foreground="#00aaff")
        self.text_widget.tag_configure("SEARCH_HIGHLIGHT", background="#ffff00", foreground="#000000")

    def add_log(self, level: str, message: str, source: str = "") -> None:
        """Add log entry."""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        entry = {
            "timestamp": timestamp,
            "level": level,
            "source": source,
            "message": message,
        }

        self.log_entries.append(entry)

        # Limit entries
        if len(self.log_entries) > self.config.max_log_entries:
            self.log_entries = self.log_entries[-self.config.max_log_entries :]

        self.refresh_display()

    def refresh_display(self) -> None:
        """Refresh log display with current filters."""
        self.text_widget.delete(1.0, tk.END)

        search_term = self.search_var.get().lower()
        level_filter = self.level_var.get()

        for entry in self.log_entries:
            # Apply filters
            if level_filter != "ALL" and entry["level"] != level_filter:
                continue

            if search_term and search_term not in entry["message"].lower():
                continue

            # Format entry
            line = f"[{entry['timestamp']}] "
            if entry["source"]:
                line += f"{entry['source']}: "
            line += f"{entry['level']}: {entry['message']}\n"

            # Insert with appropriate tags
            start_pos = self.text_widget.index(f"{tk.END}-1c")
            self.text_widget.insert(tk.END, line)
            end_pos = self.text_widget.index(f"{tk.END}-1c")

            # Apply level tag
            self.text_widget.tag_add(entry["level"], start_pos, end_pos)

            # Highlight search terms
            if search_term:
                self.highlight_search_term(start_pos, end_pos, search_term)

        # Auto-scroll to bottom
        self.text_widget.see(tk.END)

    def highlight_search_term(self, start_pos: str, end_pos: str, search_term: str) -> None:
        """Highlight search terms in text."""
        content = self.text_widget.get(start_pos, end_pos)
        start_idx = 0

        while True:
            idx = content.lower().find(search_term, start_idx)
            if idx == -1:
                break

            # Calculate actual positions
            line_start = int(start_pos.split(".", maxsplit=1)[0])
            char_start = int(start_pos.split(".")[1])

            highlight_start = f"{line_start}.{char_start + idx}"
            highlight_end = f"{line_start}.{char_start + idx + len(search_term)}"

            self.text_widget.tag_add("SEARCH_HIGHLIGHT", highlight_start, highlight_end)
            start_idx = idx + 1

    def on_search(self, event: tk.Event | None = None) -> None:
        """Handle search input."""
        self.refresh_display()

    def on_filter_change(self, event: tk.Event | None = None) -> None:
        """Handle filter change."""
        self.refresh_display()

    def clear_logs(self) -> None:
        """Clear all log entries."""
        self.log_entries.clear()
        self.refresh_display()

    def export_logs(self) -> None:
        """Export logs to file."""
        if filename := filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[
                ("Log files", "*.log"),
                ("Text files", "*.txt"),
                ("All files", "*.*"),
            ],
        ):
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    for entry in self.log_entries:
                        line = f"[{entry['timestamp']}] "
                        if entry["source"]:
                            line += f"{entry['source']}: "
                        line += f"{entry['level']}: {entry['message']}\n"
                        f.write(line)

                messagebox.showinfo("Export", f"Logs exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export logs: {e}")


class ProgressTracker:
    """Advanced progress tracking with ETA."""

    def __init__(self, parent: tk.Widget, title: str = "Progress") -> None:
        """Initialize advanced progress tracker with ETA calculation."""
        self.parent = parent
        self.title = title
        self.start_time = None
        self.last_update = time.time()

        # Create progress frame
        self.frame = ttk.LabelFrame(parent, text=title)
        self.frame.pack(fill=tk.X, padx=5, pady=2)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.frame,
            variable=self.progress_var,
            mode="determinate",
            length=300,
        )
        self.progress_bar.pack(padx=10, pady=5)

        # Status labels
        self.status_frame = ttk.Frame(self.frame)
        self.status_frame.pack(fill=tk.X, padx=10, pady=2)

        self.status_label = ttk.Label(self.status_frame, text="Ready")
        self.status_label.pack(side=tk.LEFT)

        self.eta_label = ttk.Label(self.status_frame, text="")
        self.eta_label.pack(side=tk.RIGHT)

        # Speed tracking
        self.speed_history = []
        self.max_speed_history = 10

    def start(self, total_items: int = 100) -> None:
        """Start progress tracking."""
        self.total_items = total_items
        self.completed_items = 0
        self.start_time = time.time()
        self.last_update = self.start_time
        self.speed_history.clear()

        self.update_display()

    def update(self, completed: int, status: str = "") -> None:
        """Update progress."""
        if self.start_time is None:
            self.start()

        current_time = time.time()
        delta_items = completed - self.completed_items
        delta_time = current_time - self.last_update

        # Calculate speed
        if delta_time > 0 and delta_items > 0:
            speed = delta_items / delta_time
            self.speed_history.append(speed)
            if len(self.speed_history) > self.max_speed_history:
                self.speed_history.pop(0)

        self.completed_items = completed
        self.last_update = current_time

        if status:
            self.status_label.config(text=status)

        self.update_display()

    def update_display(self) -> None:
        """Update visual display."""
        if self.total_items > 0:
            percentage = (self.completed_items / self.total_items) * 100
            self.progress_var.set(percentage)

            # Calculate ETA
            if self.speed_history and self.completed_items > 0:
                avg_speed = sum(self.speed_history) / len(self.speed_history)
                if avg_speed > 0:
                    remaining_items = self.total_items - self.completed_items

                    eta_seconds = remaining_items / avg_speed
                    eta_str = self.format_time(eta_seconds)
                    self.eta_label.config(text=f"ETA: {eta_str}")
                else:
                    self.eta_label.config(text="ETA: calculating...")
            else:
                self.eta_label.config(text="")

        # Update window
        self.parent.update_idletasks()

    def format_time(self, seconds: float) -> str:
        """Format time duration."""
        if seconds < 60:
            return f"{int(seconds)}s"
        if seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}h {minutes}m"

    def finish(self, status: str = "Complete") -> None:
        """Finish progress tracking."""
        self.progress_var.set(100)
        self.status_label.config(text=status)
        self.eta_label.config(text="")
        self.parent.update_idletasks()


class FileExplorerPanel:
    """Enhanced file explorer with analysis integration."""

    def __init__(self, parent: tk.Widget, config: UIConfig, ui_controller: object) -> None:
        """Initialize enhanced file explorer with analysis integration."""
        self.parent = parent
        self.config = config
        self.ui_controller = ui_controller

        # Create main frame
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Toolbar
        self.create_toolbar()

        # File tree
        self.create_file_tree()

        # Status bar
        self.create_status_bar()

        # Context menu
        self.create_context_menu()

        # Current directory
        self.current_path = Path.cwd()
        self.refresh_tree()

    def create_toolbar(self) -> None:
        """Create file explorer toolbar."""
        self.toolbar = ttk.Frame(self.frame)
        self.toolbar.pack(fill=tk.X, padx=5, pady=2)

        # Navigation buttons
        self.back_btn = ttk.Button(self.toolbar, text="←", width=3, command=self.go_back)
        self.back_btn.pack(side=tk.LEFT, padx=1)

        self.up_btn = ttk.Button(self.toolbar, text="↑", width=3, command=self.go_up)
        self.up_btn.pack(side=tk.LEFT, padx=1)

        self.refresh_btn = ttk.Button(self.toolbar, text="⟳", width=3, command=self.refresh_tree)
        self.refresh_btn.pack(side=tk.LEFT, padx=1)

        # Path entry
        self.path_var = tk.StringVar(value=str(self.current_path))
        self.path_entry = ttk.Entry(self.toolbar, textvariable=self.path_var)
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.path_entry.bind("<Return>", self.on_path_change)

        # Browse button
        self.browse_btn = ttk.Button(self.toolbar, text="Browse", command=self.browse_folder)
        self.browse_btn.pack(side=tk.RIGHT, padx=1)

    def create_file_tree(self) -> None:
        """Create file tree widget."""
        tree_frame = ttk.Frame(self.frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)

        # Tree widget with scrollbars
        self.tree = ttk.Treeview(tree_frame, columns=("size", "modified", "type"), show="tree headings")

        # Configure columns
        self.tree.heading("#0", text="Name")
        self.tree.heading("size", text="Size")
        self.tree.heading("modified", text="Modified")
        self.tree.heading("type", text="Type")

        self.tree.column("#0", width=200)
        self.tree.column("size", width=100)
        self.tree.column("modified", width=150)
        self.tree.column("type", width=100)

        # Scrollbars
        v_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)

        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        # Pack widgets
        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Bind events
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-3>", self.on_right_click)
        self.tree.bind("<<TreeviewSelect>>", self.on_selection_change)

    def create_status_bar(self) -> None:
        """Create status bar."""
        self.status_frame = ttk.Frame(self.frame)
        self.status_frame.pack(fill=tk.X, padx=5, pady=2)

        self.status_label = ttk.Label(self.status_frame, text="Ready")
        self.status_label.pack(side=tk.LEFT)

        self.file_count_label = ttk.Label(self.status_frame, text="")
        self.file_count_label.pack(side=tk.RIGHT)

    def create_context_menu(self) -> None:
        """Create right-click context menu."""
        self.context_menu = tk.Menu(self.frame, tearoff=0)
        self.context_menu.add_command(label="Analyze File", command=self.analyze_selected)
        self.context_menu.add_command(label="Generate Scripts", command=self.generate_scripts)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Open in Explorer", command=self.open_in_explorer)
        self.context_menu.add_command(label="Copy Path", command=self.copy_path)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Properties", command=self.show_properties)

    def refresh_tree(self) -> None:
        """Refresh file tree."""
        try:
            # Clear existing items
            for item in self.tree.get_children():
                self.tree.delete(item)

            if not self.current_path.exists():
                self.status_label.config(text="Path does not exist")
                return

            # Add files and directories
            items = []
            file_count = 0
            dir_count = 0

            for item in sorted(self.current_path.iterdir()):
                try:
                    if item.is_dir():
                        icon = ""
                        size = ""
                        item_type = "Folder"
                        dir_count += 1
                    else:
                        icon = self.get_file_icon(item)
                        size = self.format_file_size(item.stat().st_size)
                        item_type = item.suffix.upper()[1:] if item.suffix else "File"
                        file_count += 1

                    modified = datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M")

                    tree_item = self.tree.insert(
                        "",
                        "end",
                        text=f"{icon} {item.name}",
                        values=(size, modified, item_type),
                        tags=("directory" if item.is_dir() else "file",),
                    )

                    # Store path in item
                    self.tree.set(tree_item, "path", str(item))

                    # Track items for further processing
                    items.append(
                        {
                            "tree_item": tree_item,
                            "path": item,
                            "is_dir": item.is_dir(),
                            "name": item.name,
                            "size": size,
                        },
                    )

                except OSError:
                    continue

            # Process items for enhanced functionality
            self._process_directory_items(items)

            # Update status
            status_text = f"{dir_count} folders, {file_count} files"
            self.status_label.config(text="Ready")
            self.file_count_label.config(text=status_text)

            # Update path entry
            self.path_var.set(str(self.current_path))

        except Exception as e:
            self.status_label.config(text=f"Error: {e}")

    def _process_directory_items(self, items: list) -> None:
        """Process directory items for enhanced functionality."""
        # Cache items for future operations like search, filtering, etc.
        self._cached_items = items

        # Pre-analyze files for type distribution
        if items:
            file_types = {}
            total_size = 0

            for item in items:
                if not item["is_dir"] and item["path"].suffix:
                    ext = item["path"].suffix.lower()
                    file_types[ext] = file_types.get(ext, 0) + 1

                    # Calculate total size if available
                    try:
                        if item["path"].exists():
                            total_size += item["path"].stat().st_size
                    except OSError as e:
                        self.logger.debug("Error updating status bar: %s", e)

            # Store analysis for tooltips and future reference
            self._directory_analysis = {
                "file_types": file_types,
                "total_size": total_size,
                "item_count": len(items),
            }

    def get_file_icon(self, file_path: Path) -> str:
        """Get icon for file type."""
        suffix = file_path.suffix.lower()

        icons = {
            ".exe": "[CFG]️",
            ".dll": "",
            ".sys": "[FAST]",
            ".bin": "",
            ".bat": "📋",
            ".cmd": "📋",
            ".ps1": "💠",
            ".py": "🐍",
            ".js": "🟨",
            ".jar": "[JAVA]",
            ".zip": "",
            ".rar": "",
            ".7z": "",
            ".pdf": "📄",
            ".txt": "📄",
            ".log": "📋",
            ".json": "[CFG]️",
            ".xml": "[CFG]️",
            ".cfg": "[CFG]️",
            ".ini": "[CFG]️",
        }

        return icons.get(suffix, "📄")

    def format_file_size(self, size: int) -> str:
        """Format file size in human readable format."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

    def on_double_click(self, event: tk.Event) -> None:
        """Handle double-click on tree item."""
        item = self.tree.selection()[0]
        item_path = Path(self.tree.set(item, "path"))

        if item_path.is_dir():
            self.current_path = item_path
            self.refresh_tree()
        else:
            # Analyze file
            self.analyze_file(item_path)

    def on_right_click(self, event: tk.Event) -> None:
        """Handle right-click on tree item."""
        if item := self.tree.identify_row(event.y):
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def on_selection_change(self, event: tk.Event) -> None:
        """Handle selection change."""
        if selection := self.tree.selection():
            item_path = Path(self.tree.set(selection[0], "path"))
            self.status_label.config(text=str(item_path))

    def on_path_change(self, event: tk.Event) -> None:
        """Handle path entry change."""
        try:
            new_path = Path(self.path_var.get())
            if new_path.is_dir():
                self.current_path = new_path
                self.refresh_tree()
        except Exception as e:
            messagebox.showerror("Invalid Path", f"Cannot navigate to path: {e}")
            self.path_var.set(str(self.current_path))

    def go_back(self) -> None:
        """Navigate back."""
        # Simple implementation - go to parent
        self.go_up()

    def go_up(self) -> None:
        """Navigate up one directory."""
        if self.current_path.parent != self.current_path:
            self.current_path = self.current_path.parent
            self.refresh_tree()

    def browse_folder(self) -> None:
        """Browse for folder."""
        if folder := filedialog.askdirectory(initialdir=str(self.current_path)):
            self.current_path = Path(folder)
            self.refresh_tree()

    def analyze_selected(self) -> None:
        """Analyze selected file."""
        if selection := self.tree.selection():
            item_path = Path(self.tree.set(selection[0], "path"))
            if item_path.is_file():
                self.analyze_file(item_path)

    def analyze_file(self, file_path: Path) -> None:
        """Trigger file analysis."""
        self.ui_controller.analyze_file(str(file_path))

    def generate_scripts(self) -> None:
        """Generate scripts for selected file."""
        if selection := self.tree.selection():
            item_path = Path(self.tree.set(selection[0], "path"))
            if item_path.is_file():
                self.ui_controller.generate_scripts(str(item_path))

    def open_in_explorer(self) -> None:
        """Open location in system explorer."""
        if selection := self.tree.selection():
            item_path = Path(self.tree.set(selection[0], "path"))

            if sys.platform == "win32":
                os.startfile(str(item_path.parent))  # noqa: S606  # Legitimate folder opening for security research file navigation
            elif sys.platform == "darwin":
                subprocess.run(["open", str(item_path.parent)], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
            else:
                subprocess.run(["xdg-open", str(item_path.parent)], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis

    def copy_path(self) -> None:
        """Copy file path to clipboard."""
        if selection := self.tree.selection():
            item_path = Path(self.tree.set(selection[0], "path"))
            self.parent.clipboard_clear()
            self.parent.clipboard_append(str(item_path))

    def show_properties(self) -> None:
        """Show file properties dialog."""
        if selection := self.tree.selection():
            item_path = Path(self.tree.set(selection[0], "path"))
            self.ui_controller.show_file_properties(item_path)


class AnalysisViewerPanel:
    """Central analysis viewer with real-time updates."""

    def __init__(self, parent: tk.Widget, config: UIConfig, ui_controller: object) -> None:
        """Initialize central analysis viewer with real-time updates."""
        self.parent = parent
        self.config = config
        self.ui_controller = ui_controller

        # Create main frame
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create tabs
        self.create_overview_tab()
        self.create_details_tab()
        self.create_visualization_tab()
        self.create_history_tab()

        # Current analysis
        self.current_analysis = None

    def create_overview_tab(self) -> None:
        """Create analysis overview tab."""
        self.overview_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.overview_frame, text="Overview")

        # Target file info
        info_frame = ttk.LabelFrame(self.overview_frame, text="Target File")
        info_frame.pack(fill=tk.X, padx=5, pady=5)

        self.file_info_text = scrolledtext.ScrolledText(
            info_frame,
            height=4,
            wrap=tk.WORD,
            font=(self.config.font_family, self.config.font_size),
            bg="#1e1e1e",
            fg="#ffffff",
        )
        self.file_info_text.pack(fill=tk.X, padx=5, pady=5)

        # Protection analysis
        protection_frame = ttk.LabelFrame(self.overview_frame, text="Protection Analysis")
        protection_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create protection details widgets
        details_frame = ttk.Frame(protection_frame)
        details_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(details_frame, text="Protection Type:").grid(row=0, column=0, sticky="w", padx=5)
        self.protection_type_label = ttk.Label(
            details_frame,
            text="Unknown",
            font=(self.config.font_family, self.config.font_size, "bold"),
        )
        self.protection_type_label.grid(row=0, column=1, sticky="w", padx=5)

        ttk.Label(details_frame, text="Confidence:").grid(row=1, column=0, sticky="w", padx=5)
        self.confidence_label = ttk.Label(details_frame, text="0%")
        self.confidence_label.grid(row=1, column=1, sticky="w", padx=5)

        # Confidence progress bar
        self.confidence_progress = ttk.Progressbar(details_frame, mode="determinate", length=200)
        self.confidence_progress.grid(row=1, column=2, sticky="w", padx=5)

        # Bypass methods
        bypass_frame = ttk.LabelFrame(protection_frame, text="Recommended Bypass Methods")
        bypass_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.bypass_listbox = tk.Listbox(
            bypass_frame,
            font=(self.config.font_family, self.config.font_size),
            bg="#1e1e1e",
            fg="#ffffff",
            selectbackground="#264f78",
        )
        self.bypass_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_details_tab(self) -> None:
        """Create detailed analysis tab."""
        self.details_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.details_frame, text="Details")

        # Create paned window for split view
        paned = ttk.PanedWindow(self.details_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left: Analysis tree
        left_frame = ttk.LabelFrame(paned, text="Analysis Results")
        paned.add(left_frame, weight=1)

        self.details_tree = ttk.Treeview(left_frame, columns=("value",), show="tree headings")
        self.details_tree.heading("#0", text="Property")
        self.details_tree.heading("value", text="Value")
        self.details_tree.column("#0", width=200)
        self.details_tree.column("value", width=300)

        tree_scroll = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.details_tree.yview)
        self.details_tree.configure(yscrollcommand=tree_scroll.set)

        self.details_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Right: Details view
        right_frame = ttk.LabelFrame(paned, text="Details")
        paned.add(right_frame, weight=1)

        self.details_text = scrolledtext.ScrolledText(
            right_frame,
            wrap=tk.WORD,
            font=(self.config.font_family, self.config.font_size),
            bg="#1e1e1e",
            fg="#ffffff",
        )
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Bind tree selection
        self.details_tree.bind("<<TreeviewSelect>>", self.on_details_select)

    def create_visualization_tab(self) -> None:
        """Create visualization tab."""
        self.viz_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.viz_frame, text="Visualization")

        # Control frame
        control_frame = ttk.Frame(self.viz_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(control_frame, text="Chart Type:").pack(side=tk.LEFT, padx=5)

        self.chart_type_var = tk.StringVar(value="Confidence Over Time")
        chart_combo = ttk.Combobox(
            control_frame,
            textvariable=self.chart_type_var,
            values=["Confidence Over Time", "Protection Distribution", "Bypass Success Rate"],
            state="readonly",
        )
        chart_combo.pack(side=tk.LEFT, padx=5)
        chart_combo.bind("<<ComboboxSelected>>", self.update_visualization)

        # Chart frame
        chart_frame = ttk.Frame(self.viz_frame)
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.chart = RealTimeChart(chart_frame, "Analysis Progress")

    def create_history_tab(self) -> None:
        """Create analysis history tab."""
        self.history_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.history_frame, text="History")

        # Toolbar
        toolbar = ttk.Frame(self.history_frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(toolbar, text="Clear History", command=self.clear_history).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Export History", command=self.export_history).pack(side=tk.LEFT, padx=5)

        # History tree
        self.history_tree = ttk.Treeview(
            self.history_frame,
            columns=("file", "protection", "confidence", "timestamp"),
            show="tree headings",
        )

        self.history_tree.heading("#0", text="#")
        self.history_tree.heading("file", text="File")
        self.history_tree.heading("protection", text="Protection")
        self.history_tree.heading("confidence", text="Confidence")
        self.history_tree.heading("timestamp", text="Timestamp")

        self.history_tree.column("#0", width=50)
        self.history_tree.column("file", width=300)
        self.history_tree.column("protection", width=150)
        self.history_tree.column("confidence", width=100)
        self.history_tree.column("timestamp", width=150)

        history_scroll = ttk.Scrollbar(self.history_frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=history_scroll.set)

        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        history_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Double-click to view details
        self.history_tree.bind("<Double-1>", self.on_history_double_click)

    def update_analysis(self, result: AnalysisResult) -> None:
        """Update analysis display with new results."""
        self.current_analysis = result

        # Update overview
        self.update_overview(result)

        # Update details
        self.update_details(result)

        # Update visualization
        self.update_visualization()

        # Add to history
        self.add_to_history(result)

    def update_overview(self, result: AnalysisResult) -> None:
        """Update overview tab."""
        # File info
        file_info = f"File: {result.target_file}\n"
        file_info += f"Size: {Path(result.target_file).stat().st_size if Path(result.target_file).exists() else 'Unknown'}\n"
        file_info += f"Modified: {datetime.fromtimestamp(Path(result.target_file).stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S') if Path(result.target_file).exists() else 'Unknown'}\n"
        file_info += f"Analysis Time: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"

        self.file_info_text.delete(1.0, tk.END)
        self.file_info_text.insert(1.0, file_info)

        # Protection details
        self.protection_type_label.config(text=result.protection_type)
        self.confidence_label.config(text=f"{result.confidence:.1f}%")
        self.confidence_progress["value"] = result.confidence

        # Color code confidence
        if result.confidence >= 80:
            color = "#00ff00"  # Green
        elif result.confidence >= 60:
            color = "#ffaa00"  # Orange
        else:
            color = "#ff4444"  # Red

        self.confidence_label.config(foreground=color)

        # Bypass methods
        self.bypass_listbox.delete(0, tk.END)
        for method in result.bypass_methods:
            self.bypass_listbox.insert(tk.END, method)

    def update_details(self, result: AnalysisResult) -> None:
        """Update details tab."""
        # Clear existing items
        for item in self.details_tree.get_children():
            self.details_tree.delete(item)

        # Add analysis details
        details = result.details

        for category, data in details.items():
            cat_item = self.details_tree.insert("", "end", text=category, values=("",))

            if isinstance(data, dict):
                for key, value in data.items():
                    self.details_tree.insert(cat_item, "end", text=key, values=(str(value),))
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    self.details_tree.insert(cat_item, "end", text=f"Item {i + 1}", values=(str(item),))
            else:
                self.details_tree.set(cat_item, "value", str(data))

        # Expand all items
        for item in self.details_tree.get_children():
            self.details_tree.item(item, open=True)

    def update_visualization(self, event: tk.Event | None = None) -> None:
        """Update visualization based on current chart type."""
        if not self.current_analysis:
            return

        chart_type = self.chart_type_var.get()

        if chart_type == "Confidence Over Time":
            self.chart.update_data(self.current_analysis.confidence, "Confidence")
        elif chart_type == "Protection Distribution":
            # Calculate protection distribution from current and historical data
            protection_counts = {}

            # Add current analysis protections
            if self.current_analysis and self.current_analysis.protections:
                for protection in self.current_analysis.protections:
                    prot_name = protection.protection_type
                    protection_counts[prot_name] = protection_counts.get(prot_name, 0) + 1

            # Add historical protections if available
            if hasattr(self, "analysis_history"):
                for analysis in self.analysis_history:
                    if analysis.protections:
                        for protection in analysis.protections:
                            prot_name = protection.protection_type
                            protection_counts[prot_name] = protection_counts.get(prot_name, 0) + 1

            # Update chart with distribution data
            if protection_counts:
                labels = list(protection_counts.keys())
                values = list(protection_counts.values())
                self.chart.update_pie_data(labels, values, "Protection Distribution")
            else:
                self.chart.clear_data()

        elif chart_type == "Bypass Success Rate":
            # Calculate bypass success rate from tracked data
            bypass_stats = {"Successful": 0, "Failed": 0, "Partial": 0}

            # Check current analysis for bypass recommendations
            if self.current_analysis and self.current_analysis.bypass_recommendations:
                for recommendation in self.current_analysis.bypass_recommendations:
                    # Estimate success based on confidence
                    if recommendation.confidence >= 0.8:
                        bypass_stats["Successful"] += 1
                    elif recommendation.confidence >= 0.5:
                        bypass_stats["Partial"] += 1
                    else:
                        bypass_stats["Failed"] += 1

            # Add historical bypass data if available
            if hasattr(self, "bypass_history"):
                for result in self.bypass_history:
                    bypass_stats[result["status"]] = bypass_stats.get(result["status"], 0) + 1

            # Update chart with success rate data
            if sum(bypass_stats.values()) > 0:
                labels = list(bypass_stats.keys())
                values = list(bypass_stats.values())
                self.chart.update_pie_data(labels, values, "Bypass Success Rate")
            else:
                self.chart.clear_data()

    def add_to_history(self, result: AnalysisResult) -> None:
        """Add analysis result to history."""
        item_count = len(self.history_tree.get_children()) + 1

        self.history_tree.insert(
            "",
            "end",
            text=str(item_count),
            values=(
                Path(result.target_file).name,
                result.protection_type,
                f"{result.confidence:.1f}%",
                result.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )

        if items := self.history_tree.get_children():
            self.history_tree.see(items[-1])

    def on_details_select(self, event: tk.Event) -> None:
        """Handle details tree selection."""
        if not (selection := self.details_tree.selection()):
            return
        item = selection[0]

        # Get item details
        item_text = self.details_tree.item(item, "text")
        item_value = self.details_tree.item(item, "values")[0] if self.details_tree.item(item, "values") else ""

        # Show in details text
        details_content = f"Property: {item_text}\n"
        if item_value:
            details_content += f"Value: {item_value}\n"

        if children := self.details_tree.get_children(item):
            details_content += "\nSub-properties:\n"
            for child in children:
                child_text = self.details_tree.item(child, "text")
                child_value = self.details_tree.item(child, "values")[0] if self.details_tree.item(child, "values") else ""
                details_content += f"  {child_text}: {child_value}\n"

        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(1.0, details_content)

    def on_history_double_click(self, event: tk.Event) -> None:
        """Handle history double-click to view details."""
        if not (selection := self.history_tree.selection()):
            return
        # Load historical analysis details
        item = self.history_tree.item(selection[0])
        values = item["values"]

        if len(values) >= 4:
            file_name = values[0]
            protection_type = values[1]
            confidence = values[2]
            timestamp = values[3]

            # Create detail window
            detail_window = tk.Toplevel(self.parent)
            detail_window.title(f"Analysis Details - {file_name}")
            detail_window.geometry("600x400")

            # Create detail frame
            detail_frame = ttk.Frame(detail_window, padding="10")
            detail_frame.pack(fill=tk.BOTH, expand=True)

            # Add details
            ttk.Label(detail_frame, text=f"File: {file_name}", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=5)
            ttk.Label(detail_frame, text=f"Protection Type: {protection_type}").pack(anchor="w", pady=2)
            ttk.Label(detail_frame, text=f"Confidence: {confidence}%").pack(anchor="w", pady=2)
            ttk.Label(detail_frame, text=f"Analyzed: {timestamp}").pack(anchor="w", pady=2)

            # Add text area for detailed info
            ttk.Label(detail_frame, text="Analysis Details:", font=("TkDefaultFont", 9, "bold")).pack(anchor="w", pady=(10, 5))

            detail_text = tk.Text(detail_frame, height=15, width=70, wrap=tk.WORD)
            detail_text.pack(fill=tk.BOTH, expand=True, pady=5)

            # Add scrollbar
            scrollbar = ttk.Scrollbar(detail_text)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            detail_text.config(yscrollcommand=scrollbar.set)
            scrollbar.config(command=detail_text.yview)

            # Populate with historical data if available
            detail_info = f"File: {file_name}\n"
            detail_info += f"Protection Type: {protection_type}\n"
            detail_info += f"Confidence Level: {confidence}%\n"
            detail_info += f"Analysis Timestamp: {timestamp}\n\n"

            # Add more details if stored in history
            if hasattr(self, "analysis_history_details"):
                history_key = f"{file_name}_{timestamp}"
                if history_key in self.analysis_history_details:
                    detail_info += "Detailed Analysis:\n"
                    detail_info += self.analysis_history_details[history_key]
            else:
                detail_info += "Detailed analysis data not available for this historical entry.\n"
                detail_info += "Future analyses will store complete details."

            detail_text.insert("1.0", detail_info)
            detail_text.config(state="disabled")

            # Add close button
            ttk.Button(detail_frame, text="Close", command=detail_window.destroy).pack(pady=10)

    def clear_history(self) -> None:
        """Clear analysis history."""
        if messagebox.askyesno("Clear History", "Are you sure you want to clear the analysis history?"):
            for item in self.history_tree.get_children():
                self.history_tree.delete(item)

    def export_history(self) -> None:
        """Export analysis history."""
        if not (
            filename := filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[
                    ("CSV files", "*.csv"),
                    ("JSON files", "*.json"),
                    ("All files", "*.*"),
                ],
            )
        ):
            return
        try:
            items = []
            for item in self.history_tree.get_children():
                values = self.history_tree.item(item, "values")
                items.append(
                    {
                        "file": values[0],
                        "protection": values[1],
                        "confidence": values[2],
                        "timestamp": values[3],
                    },
                )

            if filename.endswith(".json"):
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(items, f, indent=2)
            else:
                # CSV format
                import csv

                with open(filename, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=["file", "protection", "confidence", "timestamp"])
                    writer.writeheader()
                    writer.writerows(items)

            messagebox.showinfo("Export", f"History exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export history: {e}")


class ScriptGeneratorPanel:
    """Script generation and management panel."""

    def __init__(self, parent: tk.Widget, config: UIConfig, ui_controller: object) -> None:
        """Initialize script generation and management panel."""
        self.parent = parent
        self.config = config
        self.ui_controller = ui_controller

        # Create main frame
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Create notebook for script types
        self.notebook = ttk.Notebook(self.frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create script type tabs
        self.create_frida_tab()
        self.create_ghidra_tab()
        self.create_radare2_tab()
        self.create_custom_tab()

        # Script history
        self.script_history = []

    def create_frida_tab(self) -> None:
        """Create Frida script tab."""
        frida_frame = ttk.Frame(self.notebook)
        self.notebook.add(frida_frame, text="Frida Scripts")

        # Control panel
        control_frame = ttk.LabelFrame(frida_frame, text="Script Generation")
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # Target process
        ttk.Label(control_frame, text="Target Process:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.frida_process_var = tk.StringVar()
        process_entry = ttk.Entry(control_frame, textvariable=self.frida_process_var, width=30)
        process_entry.grid(row=0, column=1, sticky="w", padx=5, pady=2)

        ttk.Button(control_frame, text="Browse", command=self.browse_process).grid(row=0, column=2, padx=5, pady=2)

        # Script type
        ttk.Label(control_frame, text="Script Type:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.frida_type_var = tk.StringVar(value="License Bypass")
        type_combo = ttk.Combobox(
            control_frame,
            textvariable=self.frida_type_var,
            values=["License Bypass", "API Hook", "Memory Patch", "Crypto Hook", "Custom"],
            state="readonly",
        )
        type_combo.grid(row=1, column=1, sticky="w", padx=5, pady=2)

        # Generate button
        ttk.Button(control_frame, text="Generate Script", command=self.generate_frida_script).grid(row=1, column=2, padx=5, pady=2)

        # Script editor
        editor_frame = ttk.LabelFrame(frida_frame, text="Script Editor")
        editor_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.frida_editor = scrolledtext.ScrolledText(
            editor_frame,
            wrap=tk.NONE,
            font=(self.config.font_family, self.config.font_size),
            bg="#1e1e1e",
            fg="#ffffff",
            insertbackground="#ffffff",
        )
        self.frida_editor.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Syntax highlighting for JavaScript
        self.setup_js_syntax_highlighting(self.frida_editor)

        # Action buttons
        action_frame = ttk.Frame(frida_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(action_frame, text="Run Script", command=self.run_frida_script).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Save Script", command=self.save_frida_script).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Load Script", command=self.load_frida_script).pack(side=tk.LEFT, padx=5)

    def create_ghidra_tab(self) -> None:
        """Create Ghidra script tab."""
        ghidra_frame = ttk.Frame(self.notebook)
        self.notebook.add(ghidra_frame, text="Ghidra Scripts")

        # Similar structure to Frida tab but for Java/Ghidra scripts
        # Control panel
        control_frame = ttk.LabelFrame(ghidra_frame, text="Script Generation")
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # Target binary
        ttk.Label(control_frame, text="Target Binary:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.ghidra_binary_var = tk.StringVar()
        binary_entry = ttk.Entry(control_frame, textvariable=self.ghidra_binary_var, width=30)
        binary_entry.grid(row=0, column=1, sticky="w", padx=5, pady=2)

        ttk.Button(control_frame, text="Browse", command=self.browse_binary).grid(row=0, column=2, padx=5, pady=2)

        # Script type
        ttk.Label(control_frame, text="Script Type:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.ghidra_type_var = tk.StringVar(value="License Analysis")
        type_combo = ttk.Combobox(
            control_frame,
            textvariable=self.ghidra_type_var,
            values=[
                "License Analysis",
                "Crypto Detection",
                "Packer Analysis",
                "Key Generation",
                "Custom",
            ],
            state="readonly",
        )
        type_combo.grid(row=1, column=1, sticky="w", padx=5, pady=2)

        # Generate button
        ttk.Button(control_frame, text="Generate Script", command=self.generate_ghidra_script).grid(row=1, column=2, padx=5, pady=2)

        # Script editor
        editor_frame = ttk.LabelFrame(ghidra_frame, text="Script Editor")
        editor_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.ghidra_editor = scrolledtext.ScrolledText(
            editor_frame,
            wrap=tk.NONE,
            font=(self.config.font_family, self.config.font_size),
            bg="#1e1e1e",
            fg="#ffffff",
            insertbackground="#ffffff",
        )
        self.ghidra_editor.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Syntax highlighting for Java
        self.setup_java_syntax_highlighting(self.ghidra_editor)

        # Action buttons
        action_frame = ttk.Frame(ghidra_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(action_frame, text="Run in Ghidra", command=self.run_ghidra_script).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Save Script", command=self.save_ghidra_script).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Load Script", command=self.load_ghidra_script).pack(side=tk.LEFT, padx=5)

    def create_radare2_tab(self) -> None:
        """Create Radare2 script tab."""
        radare2_frame = ttk.Frame(self.notebook)
        self.notebook.add(radare2_frame, text="Radare2 Scripts")

        # Control panel
        control_frame = ttk.LabelFrame(radare2_frame, text="Script Generation")
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # Target binary
        ttk.Label(control_frame, text="Target Binary:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.r2_binary_var = tk.StringVar()
        binary_entry = ttk.Entry(control_frame, textvariable=self.r2_binary_var, width=30)
        binary_entry.grid(row=0, column=1, sticky="w", padx=5, pady=2)

        ttk.Button(control_frame, text="Browse", command=self.browse_r2_binary).grid(row=0, column=2, padx=5, pady=2)

        # Script type
        ttk.Label(control_frame, text="Script Type:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.r2_type_var = tk.StringVar(value="License Analysis")
        type_combo = ttk.Combobox(
            control_frame,
            textvariable=self.r2_type_var,
            values=[
                "License Analysis",
                "Keygen Assistant",
                "Patch Generation",
                "Analysis Script",
                "Custom",
            ],
            state="readonly",
        )
        type_combo.grid(row=1, column=1, sticky="w", padx=5, pady=2)

        # Generate button
        ttk.Button(control_frame, text="Generate Script", command=self.generate_r2_script).grid(row=1, column=2, padx=5, pady=2)

        # Script editor
        editor_frame = ttk.LabelFrame(radare2_frame, text="Script Editor")
        editor_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.r2_editor = scrolledtext.ScrolledText(
            editor_frame,
            wrap=tk.NONE,
            font=(self.config.font_family, self.config.font_size),
            bg="#1e1e1e",
            fg="#ffffff",
            insertbackground="#ffffff",
        )
        self.r2_editor.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Syntax highlighting for Python/R2
        self.setup_python_syntax_highlighting(self.r2_editor)

        # Action buttons
        action_frame = ttk.Frame(radare2_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(action_frame, text="Run Script", command=self.run_r2_script).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Save Script", command=self.save_r2_script).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Load Script", command=self.load_r2_script).pack(side=tk.LEFT, padx=5)

    def create_custom_tab(self) -> None:
        """Create custom script tab."""
        custom_frame = ttk.Frame(self.notebook)
        self.notebook.add(custom_frame, text="Custom Scripts")

        # Language selection
        lang_frame = ttk.LabelFrame(custom_frame, text="Script Language")
        lang_frame.pack(fill=tk.X, padx=5, pady=5)

        self.custom_lang_var = tk.StringVar(value="Python")
        lang_combo = ttk.Combobox(
            lang_frame,
            textvariable=self.custom_lang_var,
            values=["Python", "PowerShell", "Batch", "Bash", "JavaScript", "C++"],
            state="readonly",
        )
        lang_combo.pack(side=tk.LEFT, padx=5, pady=5)
        lang_combo.bind("<<ComboboxSelected>>", self.on_language_change)

        # Script editor
        editor_frame = ttk.LabelFrame(custom_frame, text="Script Editor")
        editor_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.custom_editor = scrolledtext.ScrolledText(
            editor_frame,
            wrap=tk.NONE,
            font=(self.config.font_family, self.config.font_size),
            bg="#1e1e1e",
            fg="#ffffff",
            insertbackground="#ffffff",
        )
        self.custom_editor.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Action buttons
        action_frame = ttk.Frame(custom_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(action_frame, text="Run Script", command=self.run_custom_script).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Save Script", command=self.save_custom_script).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Load Script", command=self.load_custom_script).pack(side=tk.LEFT, padx=5)

    def setup_js_syntax_highlighting(self, text_widget: tk.Text) -> None:
        """Configure JavaScript syntax highlighting."""
        # Define color schemes for different elements
        text_widget.tag_configure("keyword", foreground="#569cd6")
        text_widget.tag_configure("string", foreground="#ce9178")
        text_widget.tag_configure("comment", foreground="#6a9955")
        text_widget.tag_configure("function", foreground="#dcdcaa")
        text_widget.tag_configure("number", foreground="#b5cea8")

        # JavaScript keywords
        js_keywords = [
            "var",
            "let",
            "const",
            "function",
            "if",
            "else",
            "for",
            "while",
            "do",
            "break",
            "continue",
            "return",
            "try",
            "catch",
            "finally",
            "throw",
            "new",
            "this",
            "typeof",
            "instanceof",
            "true",
            "false",
            "null",
            "undefined",
        ]

        # Bind highlighting
        text_widget.bind(
            "<KeyRelease>",
            lambda e: (
                self.logger.debug("JS KeyRelease: %s", e)
                or self.highlight_syntax(text_widget, js_keywords)
            ),
        )

    def setup_java_syntax_highlighting(self, text_widget: tk.Text) -> None:
        """Configure Java syntax highlighting."""
        text_widget.tag_configure("keyword", foreground="#569cd6")
        text_widget.tag_configure("string", foreground="#ce9178")
        text_widget.tag_configure("comment", foreground="#6a9955")
        text_widget.tag_configure("type", foreground="#4ec9b0")
        text_widget.tag_configure("number", foreground="#b5cea8")

        java_keywords = [
            "public",
            "private",
            "protected",
            "class",
            "interface",
            "extends",
            "implements",
            "static",
            "final",
            "abstract",
            "void",
            "int",
            "String",
            "boolean",
            "if",
            "else",
            "for",
            "while",
            "do",
            "break",
            "continue",
            "return",
            "try",
            "catch",
            "finally",
            "throw",
            "throws",
            "new",
            "this",
            "super",
            "true",
            "false",
            "null",
        ]

        text_widget.bind(
            "<KeyRelease>",
            lambda e: (
                self.logger.debug("Java KeyRelease: %s", e)
                or self.highlight_syntax(text_widget, java_keywords)
            ),
        )

    def setup_python_syntax_highlighting(self, text_widget: tk.Text) -> None:
        """Configure Python syntax highlighting."""
        text_widget.tag_configure("keyword", foreground="#569cd6")
        text_widget.tag_configure("string", foreground="#ce9178")
        text_widget.tag_configure("comment", foreground="#6a9955")
        text_widget.tag_configure("builtin", foreground="#4ec9b0")
        text_widget.tag_configure("number", foreground="#b5cea8")

        python_keywords = [
            "def",
            "class",
            "if",
            "elif",
            "else",
            "for",
            "while",
            "break",
            "continue",
            "return",
            "try",
            "except",
            "finally",
            "raise",
            "import",
            "from",
            "as",
            "with",
            "lambda",
            "yield",
            "global",
            "nonlocal",
            "True",
            "False",
            "None",
        ]

        text_widget.bind(
            "<KeyRelease>",
            lambda e: (
                self.logger.debug("Python KeyRelease: %s", e)
                or self.highlight_syntax(text_widget, python_keywords)
            ),
        )

    def highlight_syntax(self, text_widget: tk.Text, keywords: list[str]) -> None:
        """Apply basic syntax highlighting to text widget."""
        content = text_widget.get(1.0, tk.END)

        # Clear existing tags
        for tag in ["keyword", "string", "comment", "number"]:
            text_widget.tag_remove(tag, 1.0, tk.END)

        # Highlight keywords
        for keyword in keywords:
            start = 1.0
            while True:
                pos = text_widget.search(f"\\b{keyword}\\b", start, tk.END, regexp=True)
                if not pos:
                    break
                end = f"{pos}+{len(keyword)}c"
                text_widget.tag_add("keyword", pos, end)
                start = end

        # Highlight strings
        for quote in ['"', "'"]:
            start = 1.0
            while True:
                start_pos = text_widget.search(quote, start, tk.END)
                if not start_pos:
                    break
                end_pos = text_widget.search(quote, f"{start_pos}+1c", tk.END)
                if not end_pos:
                    break
                text_widget.tag_add("string", start_pos, f"{end_pos}+1c")
                start = f"{end_pos}+1c"

        # Highlight comments
        lines = content.split("\n")
        for i, line in enumerate(lines):
            if "//" in line:  # JavaScript style
                comment_start = line.find("//")
                if comment_start >= 0:
                    text_widget.tag_add("comment", f"{i + 1}.{comment_start}", f"{i + 1}.end")
            elif "#" in line:  # Python style
                comment_start = line.find("#")
                if comment_start >= 0:
                    text_widget.tag_add("comment", f"{i + 1}.{comment_start}", f"{i + 1}.end")

    def browse_process(self) -> None:
        """Browse for target process."""
        if filename := filedialog.askopenfilename(
            title="Select Target Process",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")],
        ):
            self.frida_process_var.set(filename)

    def browse_binary(self) -> None:
        """Browse for target binary."""
        if filename := filedialog.askopenfilename(
            title="Select Target Binary",
            filetypes=[
                ("Executable files", "*.exe"),
                ("Library files", "*.dll"),
                ("All files", "*.*"),
            ],
        ):
            self.ghidra_binary_var.set(filename)

    def browse_r2_binary(self) -> None:
        """Browse for Radare2 target binary."""
        if filename := filedialog.askopenfilename(
            title="Select Target Binary",
            filetypes=[
                ("Executable files", "*.exe"),
                ("Library files", "*.dll"),
                ("All files", "*.*"),
            ],
        ):
            self.r2_binary_var.set(filename)

    def generate_frida_script(self) -> None:
        """Generate Frida script based on selections."""
        target = self.frida_process_var.get()
        script_type = self.frida_type_var.get()

        if not target:
            messagebox.showwarning("Missing Target", "Please select a target process.")
            return

        # Generate script using AI modules
        script_content = self.ui_controller.generate_frida_script(target, script_type)

        self.frida_editor.delete(1.0, tk.END)
        self.frida_editor.insert(1.0, script_content)

        # Add to history
        self.add_to_script_history("Frida", script_type, script_content)

    def generate_ghidra_script(self) -> None:
        """Generate Ghidra script based on selections."""
        target = self.ghidra_binary_var.get()
        script_type = self.ghidra_type_var.get()

        if not target:
            messagebox.showwarning("Missing Target", "Please select a target binary.")
            return

        # Generate script using AI modules
        script_content = self.ui_controller.generate_ghidra_script(target, script_type)

        self.ghidra_editor.delete(1.0, tk.END)
        self.ghidra_editor.insert(1.0, script_content)

        # Add to history
        self.add_to_script_history("Ghidra", script_type, script_content)

    def generate_r2_script(self) -> None:
        """Generate Radare2 script based on selections."""
        target = self.r2_binary_var.get()
        script_type = self.r2_type_var.get()

        if not target:
            messagebox.showwarning("Missing Target", "Please select a target binary.")
            return

        # Generate script using AI modules
        script_content = self.ui_controller.generate_r2_script(target, script_type)

        self.r2_editor.delete(1.0, tk.END)
        self.r2_editor.insert(1.0, script_content)

        # Add to history
        self.add_to_script_history("Radare2", script_type, script_content)

    def add_to_script_history(self, platform: str, script_type: str, content: str) -> None:
        """Add script to history."""
        timestamp = datetime.now()
        self.script_history.append(
            {
                "platform": platform,
                "type": script_type,
                "content": content,
                "timestamp": timestamp,
            },
        )

    def on_language_change(self, event: tk.Event | None = None) -> None:
        """Handle language change for custom scripts."""
        language = self.custom_lang_var.get()

        if language == "Python":
            self.setup_python_syntax_highlighting(self.custom_editor)
        elif language == "JavaScript":
            self.setup_js_syntax_highlighting(self.custom_editor)
        # Add more language highlighting as needed

    # Script execution methods
    def run_frida_script(self) -> None:
        """Run Frida script."""
        script = self.frida_editor.get(1.0, tk.END)
        target = self.frida_process_var.get()

        if not script.strip():
            messagebox.showwarning("Empty Script", "Please generate or enter a script.")
            return

        # Execute via UI controller
        self.ui_controller.execute_frida_script(script, target)

    def run_ghidra_script(self) -> None:
        """Run Ghidra script."""
        script = self.ghidra_editor.get(1.0, tk.END)
        target = self.ghidra_binary_var.get()

        if not script.strip():
            messagebox.showwarning("Empty Script", "Please generate or enter a script.")
            return

        # Execute via UI controller
        self.ui_controller.execute_ghidra_script(script, target)

    def run_r2_script(self) -> None:
        """Run Radare2 script."""
        script = self.r2_editor.get(1.0, tk.END)
        target = self.r2_binary_var.get()

        if not script.strip():
            messagebox.showwarning("Empty Script", "Please generate or enter a script.")
            return

        # Execute via UI controller
        self.ui_controller.execute_r2_script(script, target)

    def run_custom_script(self) -> None:
        """Run custom script."""
        script = self.custom_editor.get(1.0, tk.END)
        language = self.custom_lang_var.get()

        if not script.strip():
            messagebox.showwarning("Empty Script", "Please enter a script.")
            return

        # Execute via UI controller
        self.ui_controller.execute_custom_script(script, language)

    # Script save/load methods
    def save_frida_script(self) -> None:
        """Save Frida script to file."""
        script = self.frida_editor.get(1.0, tk.END)
        self.save_script_to_file(script, "Frida Script", [("JavaScript files", "*.js"), ("All files", "*.*")])

    def save_ghidra_script(self) -> None:
        """Save Ghidra script to file."""
        script = self.ghidra_editor.get(1.0, tk.END)
        self.save_script_to_file(script, "Ghidra Script", [("Java files", "*.java"), ("All files", "*.*")])

    def save_r2_script(self) -> None:
        """Save Radare2 script to file."""
        script = self.r2_editor.get(1.0, tk.END)
        self.save_script_to_file(script, "Radare2 Script", [("Python files", "*.py"), ("All files", "*.*")])

    def save_custom_script(self) -> None:
        """Save custom script to file."""
        script = self.custom_editor.get(1.0, tk.END)
        language = self.custom_lang_var.get()

        filetypes = {
            "Python": [("Python files", "*.py"), ("All files", "*.*")],
            "PowerShell": [("PowerShell files", "*.ps1"), ("All files", "*.*")],
            "Batch": [("Batch files", "*.bat"), ("All files", "*.*")],
            "Bash": [("Shell files", "*.sh"), ("All files", "*.*")],
            "JavaScript": [("JavaScript files", "*.js"), ("All files", "*.*")],
            "C++": [("C++ files", "*.cpp"), ("Header files", "*.h"), ("All files", "*.*")],
        }

        self.save_script_to_file(script, f"{language} Script", filetypes.get(language, [("All files", "*.*")]))

    def save_script_to_file(self, script: str, title: str, filetypes: list[tuple[str, str]]) -> None:
        """Save script content to file."""
        if filename := filedialog.asksaveasfilename(title=f"Save {title}", filetypes=filetypes):
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(script)
                messagebox.showinfo("Save", f"Script saved to {filename}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save script: {e}")

    def load_frida_script(self) -> None:
        """Load Frida script from file."""
        self.load_script_to_editor(self.frida_editor, "Frida Script", [("JavaScript files", "*.js"), ("All files", "*.*")])

    def load_ghidra_script(self) -> None:
        """Load Ghidra script from file."""
        self.load_script_to_editor(self.ghidra_editor, "Ghidra Script", [("Java files", "*.java"), ("All files", "*.*")])

    def load_r2_script(self) -> None:
        """Load Radare2 script from file."""
        self.load_script_to_editor(self.r2_editor, "Radare2 Script", [("Python files", "*.py"), ("All files", "*.*")])

    def load_custom_script(self) -> None:
        """Load custom script from file."""
        self.load_script_to_editor(self.custom_editor, "Custom Script", [("All files", "*.*")])

    def load_script_to_editor(self, editor: scrolledtext.ScrolledText, title: str, filetypes: list[tuple[str, str]]) -> None:
        """Load script from file into editor."""
        if filename := filedialog.askopenfilename(title=f"Load {title}", filetypes=filetypes):
            try:
                with open(filename, encoding="utf-8") as f:
                    content = f.read()

                editor.delete(1.0, tk.END)
                editor.insert(1.0, content)

            except Exception as e:
                messagebox.showerror("Load Error", f"Failed to load script: {e}")


class UIEnhancementModule:
    """Run UI enhancement module controller."""

    def __init__(self, root: tk.Tk = None) -> None:
        """Initialize main UI enhancement module controller."""
        if root is None:
            self.root = tk.Tk()
            self.root.title("Intellicrack - Advanced Binary Analysis & Exploitation Platform")
            self.root.geometry("1400x900")
            self.root.minsize(1000, 600)
        else:
            self.root = root

        # Initialize logging
        self.setup_logging()

        # Load configuration
        self.config = self.load_config()

        # Apply theme
        self.apply_theme()

        # Initialize components
        self.analysis_state = AnalysisState.IDLE
        self.current_target = None

        # Create main UI
        self.create_main_interface()

        # Initialize analysis modules
        self.initialize_analysis_modules()

        # Start auto-refresh if enabled
        if self.config.auto_refresh:
            self.start_auto_refresh()

    def setup_logging(self) -> None:
        """Configure logging for UI enhancement module."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("intellicrack_ui.log"),
                logging.StreamHandler(),
            ],
        )
        self.logger = logging.getLogger(__name__)

    def load_config(self) -> UIConfig:
        """Load UI configuration."""
        config_file = Path("ui_config.json")

        if config_file.exists():
            try:
                with open(config_file, encoding="utf-8") as f:
                    data = json.load(f)
                return UIConfig.from_dict(data)
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}")

        return UIConfig()

    def save_config(self) -> None:
        """Save UI configuration."""
        config_file = Path("ui_config.json")

        try:
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(self.config.to_dict(), f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")

    def apply_theme(self) -> None:
        """Apply selected theme."""
        if self.config.theme == UITheme.DARK:
            self.apply_dark_theme()
        elif self.config.theme == UITheme.LIGHT:
            self.apply_light_theme()
        elif self.config.theme == UITheme.HIGH_CONTRAST:
            self.apply_high_contrast_theme()
        elif self.config.theme == UITheme.CYBERPUNK:
            self.apply_cyberpunk_theme()

    def apply_dark_theme(self) -> None:
        """Apply dark theme."""
        style = ttk.Style()
        style.theme_use("clam")

        # Configure colors
        style.configure(".", background="#2d2d2d", foreground="#ffffff")
        style.configure("TFrame", background="#2d2d2d")
        style.configure("TLabel", background="#2d2d2d", foreground="#ffffff")
        style.configure("TButton", background="#404040", foreground="#ffffff")
        style.configure("TEntry", background="#404040", foreground="#ffffff", insertcolor="#ffffff")
        style.configure("TCombobox", background="#404040", foreground="#ffffff")
        style.configure("TNotebook", background="#2d2d2d")
        style.configure("TNotebook.Tab", background="#404040", foreground="#ffffff")
        style.configure("Treeview", background="#1e1e1e", foreground="#ffffff")
        style.configure("Treeview.Heading", background="#404040", foreground="#ffffff")

        # Configure root
        self.root.configure(bg="#2d2d2d")

    def apply_light_theme(self) -> None:
        """Apply light theme."""
        style = ttk.Style()
        style.theme_use("default")

    def apply_high_contrast_theme(self) -> None:
        """Apply high contrast theme."""
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background="#000000", foreground="#ffffff")
        style.configure("TFrame", background="#000000")
        style.configure("TLabel", background="#000000", foreground="#ffffff")
        style.configure("TButton", background="#ffffff", foreground="#000000")
        style.configure("TEntry", background="#ffffff", foreground="#000000")

        self.root.configure(bg="#000000")

    def apply_cyberpunk_theme(self) -> None:
        """Apply cyberpunk theme."""
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background="#0a0a0a", foreground="#00ff41")
        style.configure("TFrame", background="#0a0a0a")
        style.configure("TLabel", background="#0a0a0a", foreground="#00ff41")
        style.configure("TButton", background="#1a1a1a", foreground="#00ff41")
        style.configure("TEntry", background="#1a1a1a", foreground="#00ff41", insertcolor="#00ff41")

        self.root.configure(bg="#0a0a0a")

    def create_main_interface(self) -> None:
        """Create the main three-panel interface."""
        # Create main menu
        self.create_menu()

        # Create status bar
        self.create_status_bar()

        # Create main paned window for three panels
        self.main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create panels
        self.file_explorer = FileExplorerPanel(self.main_paned, self.config, self)
        self.analysis_viewer = AnalysisViewerPanel(self.main_paned, self.config, self)
        self.script_generator = ScriptGeneratorPanel(self.main_paned, self.config, self)

        # Add panels to paned window
        self.main_paned.add(self.file_explorer.frame, weight=self.config.panel_weights[0])
        self.main_paned.add(self.analysis_viewer.frame, weight=self.config.panel_weights[1])
        self.main_paned.add(self.script_generator.frame, weight=self.config.panel_weights[2])

        # Create log viewer
        log_frame = ttk.LabelFrame(self.root, text="System Log")
        log_frame.pack(fill=tk.BOTH, expand=False, padx=5, pady=5, ipady=100)

        self.log_viewer = LogViewer(log_frame, self.config)

        # Create progress tracker
        self.progress_tracker = ProgressTracker(self.root, "Analysis Progress")

        # Initial log entry
        self.log_viewer.add_log("INFO", "Intellicrack UI Enhanced Module initialized", "UI")

    def create_menu(self) -> None:
        """Create main menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open File...", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Open Folder...", command=self.open_folder, accelerator="Ctrl+Shift+O")
        file_menu.add_separator()
        file_menu.add_command(label="Recent Files", command=self.show_recent_files)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_application, accelerator="Ctrl+Q")

        # Analysis menu
        analysis_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Analysis", menu=analysis_menu)
        analysis_menu.add_command(label="Quick Scan", command=self.quick_scan)
        analysis_menu.add_command(label="Deep Analysis", command=self.deep_analysis)
        analysis_menu.add_command(label="Batch Analysis", command=self.batch_analysis)
        analysis_menu.add_separator()
        analysis_menu.add_command(label="Export Results", command=self.export_results)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Hex Editor", command=self.open_hex_editor)
        tools_menu.add_command(label="Disassembler", command=self.open_disassembler)
        tools_menu.add_command(label="String Extractor", command=self.open_string_extractor)
        tools_menu.add_separator()
        tools_menu.add_command(label="Plugin Manager", command=self.open_plugin_manager)

        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Toggle Panels", command=self.toggle_panels)
        view_menu.add_command(label="Reset Layout", command=self.reset_layout)
        view_menu.add_separator()
        view_menu.add_command(label="Preferences", command=self.show_preferences)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="Keyboard Shortcuts", command=self.show_shortcuts)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)

        # Bind keyboard shortcuts
        self.root.bind(
            "<Control-o>",
            lambda e: (self.logger.debug("Ctrl+O event: %s", e) or self.open_file()),
        )
        self.root.bind(
            "<Control-O>",
            lambda e: (self.logger.debug("Ctrl+Shift+O event: %s", e) or self.open_folder()),
        )
        self.root.bind(
            "<Control-q>",
            lambda e: (self.logger.debug("Ctrl+Q event: %s", e) or self.exit_application()),
        )
        self.root.bind(
            "<F5>",
            lambda e: (self.logger.debug("F5 event: %s", e) or self.refresh_current_view()),
        )

    def create_status_bar(self) -> None:
        """Create status bar."""
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        # Status label
        self.status_label = ttk.Label(self.status_frame, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=5)

        # Analysis state indicator
        self.state_label = ttk.Label(self.status_frame, text="Idle")
        self.state_label.pack(side=tk.LEFT, padx=10)

        # Target file label
        self.target_label = ttk.Label(self.status_frame, text="No target")
        self.target_label.pack(side=tk.LEFT, padx=10)

        # Memory usage
        self.memory_label = ttk.Label(self.status_frame, text="")
        self.memory_label.pack(side=tk.RIGHT, padx=5)

        # Update status periodically
        self.update_status()

    def initialize_analysis_modules(self) -> None:
        """Initialize analysis modules."""
        try:
            # Import analysis modules
            from .anti_anti_debug_suite import AntiAntiDebugSuite
            from .hardware_dongle_emulator import HardwareDongleEmulator
            from .intellicrack_core_engine import IntellicrackcoreEngine
            from .protection_classifier import ProtectionClassifier
            from .vm_protection_unwrapper import VMProtectionUnwrapper

            # Initialize modules
            self.core_engine = IntellicrackcoreEngine()
            self.protection_classifier = ProtectionClassifier()
            self.dongle_emulator = HardwareDongleEmulator()
            self.vm_unwrapper = VMProtectionUnwrapper()
            self.anti_debug = AntiAntiDebugSuite()

            self.log_viewer.add_log("INFO", "Analysis modules initialized successfully", "ModuleInit")

        except Exception as e:
            self.log_viewer.add_log("ERROR", f"Failed to initialize analysis modules: {e}", "ModuleInit")

    def start_auto_refresh(self) -> None:
        """Start auto-refresh timer."""

        def refresh() -> None:
            if self.config.auto_refresh:
                self.refresh_current_view()
                self.root.after(self.config.refresh_interval, refresh)

        self.root.after(self.config.refresh_interval, refresh)

    def refresh_current_view(self) -> None:
        """Refresh current view."""
        try:
            # Refresh file explorer
            self.file_explorer.refresh_tree()

            # Update memory usage
            from intellicrack.handlers.psutil_handler import psutil

            memory_percent = psutil.virtual_memory().percent
            self.memory_label.config(text=f"Memory: {memory_percent:.1f}%")

        except Exception as e:
            self.log_viewer.add_log("WARNING", f"Refresh error: {e}", "UI")

    def update_status(self) -> None:
        """Update status bar."""
        # Update analysis state
        state_colors = {
            AnalysisState.IDLE: "#888888",
            AnalysisState.SCANNING: "#ffaa00",
            AnalysisState.ANALYZING: "#00aaff",
            AnalysisState.GENERATING: "#aa00ff",
            AnalysisState.COMPLETE: "#00ff00",
            AnalysisState.ERROR: "#ff0000",
        }

        self.state_label.config(text=self.analysis_state.value.title())
        if hasattr(self.state_label, "configure"):
            try:
                self.state_label.configure(foreground=state_colors.get(self.analysis_state, "#ffffff"))
            except Exception as e:
                self.logger.debug("Error updating status bar: %s", e)

        # Update target
        if self.current_target:
            target_name = Path(self.current_target).name
            self.target_label.config(text=f"Target: {target_name}")
        else:
            self.target_label.config(text="No target")

        # Schedule next update
        self.root.after(1000, self.update_status)

    # Analysis methods
    def analyze_file(self, file_path: str) -> None:
        """Analyze selected file."""
        try:
            self.current_target = file_path
            self.analysis_state = AnalysisState.SCANNING

            self.log_viewer.add_log("INFO", f"Starting analysis of {file_path}", "Analysis")

            # Start progress tracking
            self.progress_tracker.start(100)

            # Perform analysis in background thread
            analysis_thread = threading.Thread(target=self._perform_analysis, args=(file_path,))
            analysis_thread.daemon = True
            analysis_thread.start()

        except Exception as e:
            self.log_viewer.add_log("ERROR", f"Failed to start analysis: {e}", "Analysis")
            self.analysis_state = AnalysisState.ERROR

    def _perform_analysis(self, file_path: str) -> None:
        """Perform file analysis in background."""
        try:
            # Update progress
            self.progress_tracker.update(10, "Initializing analysis...")

            # Classify protection
            self.analysis_state = AnalysisState.ANALYZING
            classification_result = self.protection_classifier.classify_file(file_path)

            self.progress_tracker.update(50, "Analyzing protection scheme...")

            # Generate bypass recommendations
            bypass_methods = []
            if hasattr(classification_result, "protection_type"):
                if "VMProtect" in classification_result.protection_type:
                    bypass_methods.append("VM Protection Unwrapper")
                if "Dongle" in classification_result.protection_type:
                    bypass_methods.append("Hardware Dongle Emulator")
                if "Anti-Debug" in classification_result.protection_type:
                    bypass_methods.append("Anti-Anti-Debug Suite")

            self.progress_tracker.update(80, "Generating recommendations...")

            # Create analysis result
            result = AnalysisResult(
                target_file=file_path,
                protection_type=getattr(classification_result, "protection_type", "Unknown"),
                confidence=getattr(classification_result, "confidence", 0.0) * 100,
                bypass_methods=bypass_methods,
                timestamp=datetime.now(),
                details=getattr(classification_result, "details", {}),
            )

            # Update UI in main thread
            self.root.after(0, self._analysis_complete, result)

        except Exception as e:
            self.log_viewer.add_log("ERROR", f"Analysis failed: {e}", "Analysis")
            self.root.after(0, self._analysis_error, str(e))

    def _analysis_complete(self, result: AnalysisResult) -> None:
        """Handle analysis completion."""
        self.analysis_state = AnalysisState.COMPLETE
        self.progress_tracker.finish("Analysis complete")

        # Update analysis viewer
        self.analysis_viewer.update_analysis(result)

        self.log_viewer.add_log(
            "INFO",
            f"Analysis complete: {result.protection_type} ({result.confidence:.1f}%)",
            "Analysis",
        )

    def _analysis_error(self, error_msg: str) -> None:
        """Handle analysis error."""
        self.analysis_state = AnalysisState.ERROR
        self.progress_tracker.finish("Analysis failed")

        self.log_viewer.add_log("ERROR", f"Analysis error: {error_msg}", "Analysis")

    def generate_scripts(self, file_path: str) -> None:
        """Generate scripts for target file."""
        try:
            self.log_viewer.add_log("INFO", f"Generating scripts for {file_path}", "ScriptGen")

            # Switch to script generator tab
            self.script_generator.notebook.select(0)  # Frida tab

            # Set target in appropriate fields
            self.script_generator.frida_process_var.set(file_path)
            self.script_generator.ghidra_binary_var.set(file_path)
            self.script_generator.r2_binary_var.set(file_path)

        except Exception as e:
            self.log_viewer.add_log("ERROR", f"Failed to prepare script generation: {e}", "ScriptGen")

    # Script generation methods
    def generate_frida_script(self, target: str, script_type: str) -> str:
        """Generate Frida script."""
        try:
            # Use core engine to generate script
            if hasattr(self, "core_engine"):
                return self.core_engine.generate_frida_script(target, script_type)
            # Fallback template
            return self._get_frida_template(target, script_type)
        except Exception as e:
            self.log_viewer.add_log("ERROR", f"Frida script generation failed: {e}", "ScriptGen")
            return f"// Error generating script: {e}"

    def generate_ghidra_script(self, target: str, script_type: str) -> str:
        """Generate Ghidra script."""
        try:
            if hasattr(self, "core_engine"):
                return self.core_engine.generate_ghidra_script(target, script_type)
            return self._get_ghidra_template(target, script_type)
        except Exception as e:
            self.log_viewer.add_log("ERROR", f"Ghidra script generation failed: {e}", "ScriptGen")
            return f"// Error generating script: {e}"

    def generate_r2_script(self, target: str, script_type: str) -> str:
        """Generate Radare2 script."""
        try:
            if hasattr(self, "core_engine"):
                return self.core_engine.generate_r2_script(target, script_type)
            return self._get_r2_template(target, script_type)
        except Exception as e:
            self.log_viewer.add_log("ERROR", f"Radare2 script generation failed: {e}", "ScriptGen")
            return f"# Error generating script: {e}"

    def _get_frida_template(self, target: str, script_type: str) -> str:
        """Get Frida script template."""
        templates = {
            "License Bypass": f"""// Frida License Bypass Script for {Path(target).name}
// Generated by Intellicrack UI Enhancement Module

Java.perform(function() {{
    console.log("[+] Starting license bypass for {Path(target).name}");

    // Hook common license validation functions
    var targetClass = Java.use("com.example.LicenseValidator");

    targetClass.isValid.implementation = function() {{
        console.log("[+] License validation bypassed");
        return true;
    }};

    targetClass.checkExpiry.implementation = function() {{
        console.log("[+] Expiry check bypassed");
        return false;
    }};

    console.log("[+] License bypass hooks installed");
}});""",
            "API Hook": f"""// Frida API Hook Script for {Path(target).name}
// Generated by Intellicrack UI Enhancement Module

Java.perform(function() {{
    console.log("[+] Starting API hooks for {Path(target).name}");

    // Hook target APIs
    var targetModule = Process.getModuleByName("{Path(target).name}");

    if (targetModule) {{
        console.log("[+] Target module found: " + targetModule.base);

        // Add your API hooks here
        Interceptor.attach(targetModule.base.add(0x1000), {{
            onEnter: function(args) {{
                console.log("[+] API called with args: " + args[0]);
            }},
            onLeave: function(retval) {{
                console.log("[+] API returned: " + retval);
            }}
        }});
    }}
}});""",
        }

        return templates.get(script_type, f"// Template for {script_type} not implemented")

    def _get_ghidra_template(self, target: str, script_type: str) -> str:
        """Get Ghidra script template."""
        templates = {
            "License Analysis": f"""// Ghidra License Analysis Script for {Path(target).name}
// Generated by Intellicrack UI Enhancement Module

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class LicenseAnalysis extends GhidraScript {{

    @Override
    public void run() throws Exception {{
        println("Starting license analysis for {Path(target).name}");

        // Search for license-related strings
        String[] licenseStrings = {{"license", "valid", "expired", "trial"}};

        for (String searchString : licenseStrings) {{
            findAndAnalyzeString(searchString);
        }}

        // Analyze potential license validation functions
        analyzeLicenseFunctions();

        println("License analysis complete");
    }}

    private void findAndAnalyzeString(String searchString) {{
        println("Searching for: " + searchString);
        Program program = getCurrentProgram();
        Memory memory = program.getMemory();
        AddressSetView searchSet = memory.getLoadedAndInitializedAddressSet();

        for (MemoryBlock block : memory.getBlocks()) {{
            if (block.isInitialized()) {{
                Address addr = block.getStart();
                while (addr != null && addr.compareTo(block.getEnd()) <= 0) {{
                    Data data = getDataAt(addr);
                    if (data != null && data.hasStringValue()) {{
                        String value = (String) data.getValue();
                        if (value != null && value.contains(searchString)) {{
                            println("Found at " + addr.toString() + ": " + value);

                            Reference[] refs = getReferencesTo(addr);
                            for (Reference ref : refs) {{
                                Address refAddr = ref.getFromAddress();
                                Function func = getFunctionContaining(refAddr);
                                if (func != null) {{
                                    println("  Referenced by: " + func.getName() + " at " + refAddr.toString());
                                }}
                            }}
                        }}
                    }}
                    addr = addr.next();
                }}
            }}
        }}
    }}

    private void analyzeLicenseFunctions() {{
        println("Analyzing license validation functions");
        Program program = getCurrentProgram();
        FunctionManager funcManager = program.getFunctionManager();

        String[] licenseKeywords = {{"license", "serial", "activation", "registration", "validate", "verify", "check"}};

        for (Function func : funcManager.getFunctions(true)) {{
            String funcName = func.getName().toLowerCase();
            for (String keyword : licenseKeywords) {{
                if (funcName.contains(keyword)) {{
                    println("Potential license function: " + func.getName() + " at " + func.getEntryPoint().toString());

                    AddressSetView body = func.getBody();
                    InstructionIterator instructions = program.getListing().getInstructions(body, true);
                    int callCount = 0;
                    while (instructions.hasNext()) {{
                        Instruction instr = instructions.next();
                        if (instr.getFlowType().isCall()) {{
                            callCount++;
                        }}
                    }}
                    println("  Calls: " + callCount);
                    println("  Size: " + body.getNumAddresses() + " bytes");
                    break;
                }}
            }}
        }}
    }}
}}""",
        }

        return templates.get(script_type, f"// Template for {script_type} not implemented")

    def _get_r2_template(self, target: str, script_type: str) -> str:
        """Get Radare2 script template."""
        license_template = '''#!/usr/bin/env python3
# Radare2 License Analysis Script for TARGET_NAME
# Generated by Intellicrack UI Enhancement Module

import r2pipe

def analyze_license_protection(binary_path):
    """Analyze license protection in binary"""

    # Open binary in radare2
    r2 = r2pipe.open(binary_path)

    print(f"[+] Analyzing {{binary_path}}")

    # Analyze binary
    r2.cmd("aaa")

    # Search for license-related strings
    license_strings = ["license", "valid", "expired", "trial", "activation"]

    for string in license_strings:
        results = r2.cmd(f"/ {{string}}")
        if results:
            print(f"[+] Found '{{string}}' references:")
            print(results)

    # Find potential license validation functions
    functions = r2.cmdj("aflj")

    for func in functions:
        name = func.get("name", "")
        if any(keyword in name.lower() for keyword in ["license", "valid", "check"]):
            print(f"[+] Potential license function: {{name}}")

    r2.quit()

if __name__ == "__main__":
    analyze_license_protection("TARGET_PATH")
'''

        templates = {
            "License Analysis": license_template.replace("TARGET_NAME", Path(target).name).replace("TARGET_PATH", target),
        }

        return templates.get(script_type, f"# Template for {script_type} not implemented")

    # Script execution methods
    def execute_frida_script(self, script: str, target: str) -> None:
        """Execute Frida script."""
        self.log_viewer.add_log("INFO", f"Executing Frida script on {target}", "ScriptExec")

        def run_frida() -> None:
            try:
                import frida

                try:
                    pid = int(target)
                    session = frida.attach(pid)
                except ValueError:
                    session = frida.attach(target)

                script_obj = session.create_script(script)

                def on_message(message: dict[str, Any], data: object) -> None:
                    if message["type"] == "send":
                        payload = message.get("payload", "")
                        self.root.after(0, lambda: self.log_viewer.add_log("INFO", str(payload), "Frida"))
                    elif message["type"] == "error":
                        stack = message.get("stack", "")
                        self.root.after(0, lambda: self.log_viewer.add_log("ERROR", stack, "Frida"))

                script_obj.on("message", on_message)
                script_obj.load()

                self.root.after(
                    0,
                    lambda: self.log_viewer.add_log("INFO", "Frida script loaded successfully", "ScriptExec"),
                )

            except Exception as e:
                self.root.after(
                    0,
                    lambda err=str(e): self.log_viewer.add_log("ERROR", f"Frida execution failed: {err}", "ScriptExec"),
                )

        import threading

        threading.Thread(target=run_frida, daemon=True).start()

    def execute_ghidra_script(self, script: str, target: str) -> None:
        """Execute Ghidra script."""
        self.log_viewer.add_log("INFO", f"Executing Ghidra script on {target}", "ScriptExec")

        def run_ghidra() -> None:
            try:
                import os
                import tempfile

                from intellicrack.utils.tools.ghidra_utils import execute_ghidra_script as run_ghidra_script

                with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
                    f.write(script)
                    script_path = f.name

                try:
                    result = run_ghidra_script(target, script_path)

                    if result.get("success"):
                        output = result.get("output", "")
                        self.root.after(
                            0,
                            lambda: self.log_viewer.add_log("INFO", f"Ghidra output:\n{output}", "Ghidra"),
                        )
                        self.root.after(
                            0,
                            lambda: self.log_viewer.add_log("INFO", "Ghidra script execution complete", "ScriptExec"),
                        )
                    else:
                        error = result.get("error", "Unknown error")
                        self.root.after(
                            0,
                            lambda: self.log_viewer.add_log("ERROR", f"Ghidra execution failed: {error}", "ScriptExec"),
                        )
                finally:
                    if os.path.exists(script_path):
                        Path(script_path).unlink()

            except Exception as e:
                self.root.after(
                    0,
                    lambda err=str(e): self.log_viewer.add_log("ERROR", f"Ghidra execution failed: {err}", "ScriptExec"),
                )

        import threading

        threading.Thread(target=run_ghidra, daemon=True).start()

    def execute_r2_script(self, script: str, target: str) -> None:
        """Execute Radare2 script."""
        self.log_viewer.add_log("INFO", f"Executing Radare2 script on {target}", "ScriptExec")

        def run_r2() -> None:
            try:
                import os
                import tempfile

                from intellicrack.utils.tools.radare2_utils import execute_r2_script as run_r2_script

                with tempfile.NamedTemporaryFile(mode="w", suffix=".r2", delete=False) as f:
                    f.write(script)
                    script_path = f.name

                try:
                    result = run_r2_script(target, script_path)

                    if result.get("success"):
                        output = result.get("output", "")
                        self.root.after(
                            0,
                            lambda: self.log_viewer.add_log("INFO", f"Radare2 output:\n{output}", "R2"),
                        )
                        self.root.after(
                            0,
                            lambda: self.log_viewer.add_log("INFO", "Radare2 script execution complete", "ScriptExec"),
                        )
                    else:
                        error = result.get("error", "Unknown error")
                        self.root.after(
                            0,
                            lambda: self.log_viewer.add_log("ERROR", f"Radare2 execution failed: {error}", "ScriptExec"),
                        )
                finally:
                    if os.path.exists(script_path):
                        Path(script_path).unlink()

            except Exception as e:
                self.root.after(
                    0,
                    lambda err=str(e): self.log_viewer.add_log("ERROR", f"Radare2 execution failed: {err}", "ScriptExec"),
                )

        import threading

        threading.Thread(target=run_r2, daemon=True).start()

    def execute_custom_script(self, script: str, language: str) -> None:
        """Execute custom script."""
        self.log_viewer.add_log("INFO", f"Executing {language} script", "ScriptExec")

        def run_custom() -> None:
            try:
                import os
                import subprocess
                import tempfile

                with tempfile.NamedTemporaryFile(mode="w", suffix=f".{language}", delete=False) as f:
                    f.write(script)
                    script_path = f.name

                try:
                    if language.lower() == "python":
                        result = subprocess.run(["python", script_path], capture_output=True, text=True, timeout=30)
                    elif language.lower() == "javascript":
                        result = subprocess.run(["node", script_path], capture_output=True, text=True, timeout=30)
                    elif language.lower() == "ruby":
                        result = subprocess.run(["ruby", script_path], capture_output=True, text=True, timeout=30)
                    else:
                        self.root.after(
                            0,
                            lambda: self.log_viewer.add_log("ERROR", f"Unsupported language: {language}", "ScriptExec"),
                        )
                        return

                    output = result.stdout + result.stderr
                    if result.returncode == 0:
                        self.root.after(
                            0,
                            lambda: self.log_viewer.add_log("INFO", f"Output:\n{output}", language),
                        )
                        self.root.after(
                            0,
                            lambda: self.log_viewer.add_log("INFO", f"{language} script execution complete", "ScriptExec"),
                        )
                    else:
                        self.root.after(
                            0,
                            lambda: self.log_viewer.add_log("ERROR", f"Script failed:\n{output}", "ScriptExec"),
                        )
                finally:
                    if os.path.exists(script_path):
                        Path(script_path).unlink()

            except subprocess.TimeoutExpired:
                self.root.after(
                    0,
                    lambda: self.log_viewer.add_log("ERROR", "Script execution timed out", "ScriptExec"),
                )
            except Exception as e:
                self.root.after(
                    0,
                    lambda err=str(e): self.log_viewer.add_log("ERROR", f"Script execution failed: {err}", "ScriptExec"),
                )

        import threading

        threading.Thread(target=run_custom, daemon=True).start()

    # File operations
    def open_file(self) -> None:
        """Open file dialog."""
        if filename := filedialog.askopenfilename(
            title="Open File",
            filetypes=[
                ("Executable files", "*.exe"),
                ("Library files", "*.dll"),
                ("Binary files", "*.bin"),
                ("All files", "*.*"),
            ],
        ):
            # Navigate file explorer to file location
            file_path = Path(filename)
            self.file_explorer.current_path = file_path.parent
            self.file_explorer.refresh_tree()

            # Start analysis
            self.analyze_file(filename)

    def open_folder(self) -> None:
        """Open folder dialog."""
        if folder := filedialog.askdirectory(title="Open Folder"):
            self.file_explorer.current_path = Path(folder)
            self.file_explorer.refresh_tree()

    def show_recent_files(self) -> None:
        """Show recent files dialog."""
        recent_dialog = tk.Toplevel(self.root)
        recent_dialog.title("Recent Files")
        recent_dialog.geometry("600x400")

        frame = ttk.Frame(recent_dialog, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Recent Files", font=("Arial", 12, "bold")).pack(pady=5)

        listbox_frame = ttk.Frame(frame)
        listbox_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        scrollbar = ttk.Scrollbar(listbox_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        recent_listbox = tk.Listbox(listbox_frame, yscrollcommand=scrollbar.set)
        recent_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=recent_listbox.yview)

        recent_files = self.config.get("recent_files", [])
        for file_path in recent_files:
            recent_listbox.insert(tk.END, file_path)

        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=5)

        def open_selected() -> None:
            selection = recent_listbox.curselection()
            if selection:
                file_path = recent_listbox.get(selection[0])
                if Path(file_path).exists():
                    self.file_explorer.current_path = Path(file_path).parent
                    self.file_explorer.refresh_tree()
                    recent_dialog.destroy()
                else:
                    messagebox.showerror("Error", f"File not found: {file_path}")

        def clear_recent() -> None:
            if messagebox.askyesno("Clear Recent Files", "Clear all recent files?"):
                self.config["recent_files"] = []
                self.save_config()
                recent_listbox.delete(0, tk.END)

        ttk.Button(button_frame, text="Open", command=open_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear All", command=clear_recent).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=recent_dialog.destroy).pack(side=tk.RIGHT, padx=5)

    def exit_application(self) -> None:
        """Exit application."""
        if messagebox.askyesno("Exit", "Are you sure you want to exit Intellicrack?"):
            self.save_config()
            self.root.quit()

    # Analysis operations
    def quick_scan(self) -> None:
        """Perform quick scan."""
        if self.current_target:
            self.log_viewer.add_log("INFO", "Starting quick scan", "Analysis")

            def run_scan() -> None:
                try:
                    from intellicrack.protection.icp_backend import IntellicrackProtectionBackend

                    backend = IntellicrackProtectionBackend()
                    results = backend.analyze_file(str(self.current_target), quick_mode=True)

                    self.root.after(
                        0,
                        lambda: self.log_viewer.add_log("INFO", "Quick scan complete", "Analysis"),
                    )

                    if results.get("protections_found"):
                        for protection in results["protections_found"]:
                            self.root.after(
                                0,
                                lambda p=protection: self.log_viewer.add_log("INFO", f"Detected: {p}", "Detection"),
                            )
                    else:
                        self.root.after(
                            0,
                            lambda: self.log_viewer.add_log("INFO", "No protections detected", "Analysis"),
                        )

                except Exception as e:
                    self.root.after(
                        0,
                        lambda err=str(e): self.log_viewer.add_log("ERROR", f"Quick scan failed: {err}", "Analysis"),
                    )

            import threading

            threading.Thread(target=run_scan, daemon=True).start()
        else:
            messagebox.showwarning("No Target", "Please select a file to analyze")

    def deep_analysis(self) -> None:
        """Perform deep analysis."""
        if self.current_target:
            self.log_viewer.add_log("INFO", "Starting deep analysis", "Analysis")

            def run_deep_analysis() -> None:
                try:
                    from intellicrack.protection.icp_backend import IntellicrackProtectionBackend
                    from intellicrack.protection.intellicrack_protection_advanced import AdvancedProtectionAnalyzer

                    backend = IntellicrackProtectionBackend()
                    results = backend.analyze_file(str(self.current_target), quick_mode=False)

                    self.root.after(
                        0,
                        lambda: self.log_viewer.add_log("INFO", "Running advanced analysis...", "Analysis"),
                    )

                    advanced = AdvancedProtectionAnalyzer()
                    advanced_results = advanced.analyze_binary(str(self.current_target))

                    self.root.after(
                        0,
                        lambda: self.log_viewer.add_log("INFO", "Deep analysis complete", "Analysis"),
                    )

                    if results.get("protections_found"):
                        for protection in results["protections_found"]:
                            self.root.after(
                                0,
                                lambda p=protection: self.log_viewer.add_log("INFO", f"Detected: {p}", "Detection"),
                            )

                    if advanced_results.get("entropy_sections"):
                        self.root.after(
                            0,
                            lambda: self.log_viewer.add_log("INFO", "Entropy analysis completed", "Analysis"),
                        )

                    if advanced_results.get("suspicious_patterns"):
                        for pattern in advanced_results["suspicious_patterns"]:
                            self.root.after(
                                0,
                                lambda p=pattern: self.log_viewer.add_log("WARN", f"Suspicious pattern: {p}", "Detection"),
                            )

                except Exception as e:
                    self.root.after(
                        0,
                        lambda err=str(e): self.log_viewer.add_log("ERROR", f"Deep analysis failed: {err}", "Analysis"),
                    )

            import threading

            threading.Thread(target=run_deep_analysis, daemon=True).start()
        else:
            messagebox.showwarning("No Target", "Please select a file to analyze")

    def batch_analysis(self) -> None:
        """Perform batch analysis."""
        folder = filedialog.askdirectory(title="Select Folder for Batch Analysis")

        if folder:
            self.log_viewer.add_log("INFO", f"Starting batch analysis of {folder}", "Analysis")

            def run_batch() -> None:
                try:
                    import os

                    from intellicrack.protection.icp_backend import IntellicrackProtectionBackend

                    backend = IntellicrackProtectionBackend()
                    target_extensions = [".exe", ".dll", ".so", ".dylib", ".bin"]

                    files_to_analyze = []
                    for root, _dirs, files in os.walk(folder):
                        for file in files:
                            if any(file.lower().endswith(ext) for ext in target_extensions):
                                files_to_analyze.append(os.path.join(root, file))

                    total_files = len(files_to_analyze)
                    self.root.after(
                        0,
                        lambda: self.log_viewer.add_log("INFO", f"Found {total_files} files to analyze", "Analysis"),
                    )

                    for idx, file_path in enumerate(files_to_analyze, 1):
                        try:
                            self.root.after(
                                0,
                                lambda i=idx, t=total_files, f=file_path: self.log_viewer.add_log(
                                    "INFO", f"Analyzing {i}/{t}: {os.path.basename(f)}", "Analysis"
                                ),
                            )

                            results = backend.analyze_file(file_path, quick_mode=True)

                            if results.get("protections_found"):
                                for protection in results["protections_found"]:
                                    self.root.after(
                                        0,
                                        lambda f=file_path, p=protection: self.log_viewer.add_log(
                                            "INFO", f"{os.path.basename(f)}: {p}", "Detection"
                                        ),
                                    )

                        except Exception as e:
                            self.root.after(
                                0,
                                lambda f=file_path, err=e: self.log_viewer.add_log(
                                    "ERROR",
                                    f"Failed to analyze {os.path.basename(f)}: {err}",
                                    "Analysis",
                                ),
                            )

                    self.root.after(
                        0,
                        lambda: self.log_viewer.add_log("INFO", "Batch analysis complete", "Analysis"),
                    )

                except Exception as e:
                    self.root.after(
                        0,
                        lambda err=str(e): self.log_viewer.add_log("ERROR", f"Batch analysis failed: {err}", "Analysis"),
                    )

            import threading

            threading.Thread(target=run_batch, daemon=True).start()

    def export_results(self) -> None:
        """Export analysis results."""
        if not (
            filename := filedialog.asksaveasfilename(
                title="Export Results",
                defaultextension=".json",
                filetypes=[
                    ("JSON files", "*.json"),
                    ("PDF files", "*.pdf"),
                    ("All files", "*.*"),
                ],
            )
        ):
            return
        self.log_viewer.add_log("INFO", f"Exporting results to {filename}", "Export")

        try:
            import json
            from datetime import datetime

            results_data = {
                "timestamp": datetime.now().isoformat(),
                "target": str(self.current_target) if self.current_target else None,
                "logs": [],
            }

            log_text = self.log_viewer.log_display.get("1.0", tk.END)
            results_data["logs"] = log_text.strip().split("\n")

            if filename.endswith(".json"):
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(results_data, f, indent=2)
            elif filename.endswith(".pdf"):
                from intellicrack.handlers.matplotlib_handler import PdfPages, plt

                with PdfPages(filename) as pdf:
                    fig, ax = plt.subplots(figsize=(8.5, 11))
                    ax.axis("off")

                    text_content = "Intellicrack Analysis Report\n\n"
                    text_content += f"Timestamp: {results_data['timestamp']}\n"
                    text_content += f"Target: {results_data['target']}\n\n"
                    text_content += "Logs:\n" + "\n".join(results_data["logs"][:100])

                    ax.text(
                        0.1,
                        0.9,
                        text_content,
                        transform=ax.transAxes,
                        fontsize=8,
                        verticalalignment="top",
                        family="monospace",
                    )

                    pdf.savefig(fig, bbox_inches="tight")
                    plt.close()
            else:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write("Intellicrack Analysis Report\n")
                    f.write(f"Timestamp: {results_data['timestamp']}\n")
                    f.write(f"Target: {results_data['target']}\n\n")
                    f.write("Logs:\n")
                    f.write("\n".join(results_data["logs"]))

            self.log_viewer.add_log("INFO", "Results exported successfully", "Export")
            messagebox.showinfo("Export Complete", f"Results exported to {filename}")

        except Exception as e:
            self.log_viewer.add_log("ERROR", f"Export failed: {e}", "Export")
            messagebox.showerror("Export Error", f"Failed to export results: {e}")

    # Tool operations
    def open_hex_editor(self) -> None:
        """Open hex editor."""
        if self.current_target:
            self.log_viewer.add_log("INFO", f"Opening hex editor for {self.current_target}", "Tools")

            hex_window = tk.Toplevel(self.root)
            hex_window.title(f"Hex Editor - {self.current_target.name}")
            hex_window.geometry("900x600")

            frame = ttk.Frame(hex_window, padding=10)
            frame.pack(fill=tk.BOTH, expand=True)

            text_frame = ttk.Frame(frame)
            text_frame.pack(fill=tk.BOTH, expand=True)

            scrollbar = ttk.Scrollbar(text_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            hex_text = tk.Text(text_frame, wrap=tk.NONE, yscrollcommand=scrollbar.set, font=("Courier", 9))
            hex_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=hex_text.yview)

            try:
                with open(self.current_target, "rb") as f:
                    data = f.read(1024 * 1024)

                for offset in range(0, len(data), 16):
                    chunk = data[offset : offset + 16]
                    hex_part = " ".join(f"{b:02X}" for b in chunk)
                    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                    line = f"{offset:08X}  {hex_part:<48}  {ascii_part}\n"
                    hex_text.insert(tk.END, line)

                hex_text.config(state=tk.DISABLED)

            except Exception as e:
                messagebox.showerror("Error", f"Failed to open hex editor: {e}")
                hex_window.destroy()
        else:
            messagebox.showwarning("No Target", "Please select a file first")

    def open_disassembler(self) -> None:
        """Open disassembler."""
        if self.current_target:
            self.log_viewer.add_log("INFO", f"Opening disassembler for {self.current_target}", "Tools")

            disasm_window = tk.Toplevel(self.root)
            disasm_window.title(f"Disassembler - {self.current_target.name}")
            disasm_window.geometry("1000x700")

            frame = ttk.Frame(disasm_window, padding=10)
            frame.pack(fill=tk.BOTH, expand=True)

            text_frame = ttk.Frame(frame)
            text_frame.pack(fill=tk.BOTH, expand=True)

            scrollbar = ttk.Scrollbar(text_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            disasm_text = tk.Text(text_frame, wrap=tk.NONE, yscrollcommand=scrollbar.set, font=("Courier", 9))
            disasm_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=disasm_text.yview)

            try:
                import pefile
                from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

                with open(self.current_target, "rb") as f:
                    data = f.read()

                try:
                    pe = pefile.PE(data=data)
                    is_64bit = pe.FILE_HEADER.Machine == 0x8664
                    mode = CS_MODE_64 if is_64bit else CS_MODE_32

                    for section in pe.sections:
                        if section.Characteristics & 0x20000000:
                            md = Cs(CS_ARCH_X86, mode)
                            section_data = section.get_data()
                            base_addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

                            disasm_text.insert(
                                tk.END,
                                f"Section: {section.Name.decode('utf-8', errors='ignore').strip()}\n",
                            )
                            disasm_text.insert(tk.END, f"Address: 0x{base_addr:08X}\n\n")

                            for count, insn in enumerate(md.disasm(section_data[: min(len(section_data), 4096)], base_addr)):
                                line = f"0x{insn.address:08X}:  {insn.mnemonic:8s} {insn.op_str}\n"
                                disasm_text.insert(tk.END, line)
                                if count >= 499:  # 500 instructions (0-indexed)
                                    disasm_text.insert(
                                        tk.END,
                                        "\n... (truncated, showing first 500 instructions)\n",
                                    )
                                    break

                            disasm_text.insert(tk.END, "\n" + "=" * 80 + "\n\n")

                except Exception:
                    md = Cs(CS_ARCH_X86, CS_MODE_32)
                    disasm_text.insert(tk.END, "Binary format not recognized, attempting raw disassembly...\n\n")

                    count = 0
                    for insn in md.disasm(data[: min(len(data), 4096)], 0x1000):
                        line = f"0x{insn.address:08X}:  {insn.mnemonic:8s} {insn.op_str}\n"
                        disasm_text.insert(tk.END, line)
                        count += 1
                        if count >= 500:
                            disasm_text.insert(tk.END, "\n... (truncated)\n")
                            break

                disasm_text.config(state=tk.DISABLED)

            except ImportError:
                messagebox.showerror("Error", "Capstone library not available")
                disasm_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to disassemble: {e}")
                disasm_window.destroy()
        else:
            messagebox.showwarning("No Target", "Please select a file first")

    def open_string_extractor(self) -> None:
        """Open string extractor."""
        if self.current_target:
            self.log_viewer.add_log("INFO", f"Extracting strings from {self.current_target}", "Tools")

            strings_window = tk.Toplevel(self.root)
            strings_window.title(f"Strings - {self.current_target.name}")
            strings_window.geometry("800x600")

            frame = ttk.Frame(strings_window, padding=10)
            frame.pack(fill=tk.BOTH, expand=True)

            text_frame = ttk.Frame(frame)
            text_frame.pack(fill=tk.BOTH, expand=True)

            scrollbar = ttk.Scrollbar(text_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            strings_text = tk.Text(text_frame, wrap=tk.NONE, yscrollcommand=scrollbar.set, font=("Courier", 9))
            strings_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=strings_text.yview)

            try:
                import re

                with open(self.current_target, "rb") as f:
                    data = f.read()

                ascii_strings = re.findall(rb"[ -~]{4,}", data)
                unicode_strings = re.findall(rb"(?:[ -~]\x00){4,}", data)

                strings_text.insert(tk.END, f"ASCII Strings ({len(ascii_strings)}):\n")
                strings_text.insert(tk.END, "=" * 80 + "\n\n")

                for s in ascii_strings[:1000]:
                    try:
                        decoded = s.decode("ascii")
                        strings_text.insert(tk.END, f"{decoded}\n")
                    except (UnicodeDecodeError, AttributeError):
                        pass

                if len(ascii_strings) > 1000:
                    strings_text.insert(tk.END, f"\n... ({len(ascii_strings) - 1000} more strings not shown)\n")

                strings_text.insert(tk.END, "\n\n" + "=" * 80 + "\n")
                strings_text.insert(tk.END, f"Unicode Strings ({len(unicode_strings)}):\n")
                strings_text.insert(tk.END, "=" * 80 + "\n\n")

                for s in unicode_strings[:1000]:
                    try:
                        decoded = s.decode("utf-16-le")
                        strings_text.insert(tk.END, f"{decoded}\n")
                    except (UnicodeDecodeError, AttributeError):
                        pass

                if len(unicode_strings) > 1000:
                    strings_text.insert(tk.END, f"\n... ({len(unicode_strings) - 1000} more strings not shown)\n")

                strings_text.config(state=tk.DISABLED)

            except Exception as e:
                messagebox.showerror("Error", f"Failed to extract strings: {e}")
                strings_window.destroy()
        else:
            messagebox.showwarning("No Target", "Please select a file first")

    def open_plugin_manager(self) -> None:
        """Open plugin manager."""
        self.log_viewer.add_log("INFO", "Opening plugin manager", "Tools")

        from intellicrack.ui.dialogs.plugin_manager_dialog import PluginManagerDialog

        try:
            dialog = PluginManagerDialog(self.root)
            dialog.exec()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open plugin manager: {e}")

    # View operations
    def toggle_panels(self) -> None:
        """Toggle panel visibility."""
        self.log_viewer.add_log("INFO", "Toggling panel visibility", "View")

        if hasattr(self, "file_explorer_visible"):
            self.file_explorer_visible = not self.file_explorer_visible
        else:
            self.file_explorer_visible = False

        if hasattr(self, "file_explorer") and self.file_explorer:
            if self.file_explorer_visible:
                self.file_explorer.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            else:
                self.file_explorer.pack_forget()

    def reset_layout(self) -> None:
        """Reset layout to default."""
        self.log_viewer.add_log("INFO", "Resetting layout to default", "View")
        # Reset panel weights
        weights = [1, 2, 1]
        for i, weight in enumerate(weights):
            self.main_paned.sash_place(i, weight * 100)

    def show_preferences(self) -> None:
        """Show preferences dialog."""
        self.show_preferences_dialog()

    def show_preferences_dialog(self) -> None:
        """Show preferences configuration dialog."""
        pref_window = tk.Toplevel(self.root)
        pref_window.title("Preferences")
        pref_window.geometry("500x400")
        pref_window.transient(self.root)
        pref_window.grab_set()

        # Create notebook for preference categories
        pref_notebook = ttk.Notebook(pref_window)
        pref_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # General preferences
        general_frame = ttk.Frame(pref_notebook)
        pref_notebook.add(general_frame, text="General")

        # Theme selection
        ttk.Label(general_frame, text="Theme:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        theme_var = tk.StringVar(value=self.config.theme.value)
        theme_combo = ttk.Combobox(
            general_frame,
            textvariable=theme_var,
            values=[theme.value for theme in UITheme],
            state="readonly",
        )
        theme_combo.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        # Font settings
        ttk.Label(general_frame, text="Font Family:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        font_var = tk.StringVar(value=self.config.font_family)
        font_combo = ttk.Combobox(
            general_frame,
            textvariable=font_var,
            values=["Consolas", "Courier New", "Monaco", "DejaVu Sans Mono"],
            state="readonly",
        )
        font_combo.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(general_frame, text="Font Size:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        font_size_var = tk.IntVar(value=self.config.font_size)
        font_size_spin = ttk.Spinbox(general_frame, from_=8, to=20, textvariable=font_size_var)
        font_size_spin.grid(row=2, column=1, sticky="w", padx=5, pady=5)

        # Auto-refresh settings
        auto_refresh_var = tk.BooleanVar(value=self.config.auto_refresh)
        auto_refresh_check = ttk.Checkbutton(general_frame, text="Enable auto-refresh", variable=auto_refresh_var)
        auto_refresh_check.grid(row=3, column=0, columnspan=2, sticky="w", padx=5, pady=5)

        ttk.Label(general_frame, text="Refresh Interval (ms):").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        refresh_var = tk.IntVar(value=self.config.refresh_interval)
        refresh_spin = ttk.Spinbox(general_frame, from_=500, to=10000, increment=500, textvariable=refresh_var)
        refresh_spin.grid(row=4, column=1, sticky="w", padx=5, pady=5)

        # Button frame
        button_frame = ttk.Frame(pref_window)
        button_frame.pack(fill=tk.X, padx=10, pady=5)

        def apply_preferences() -> None:
            # Update configuration
            self.config.theme = UITheme(theme_var.get())
            self.config.font_family = font_var.get()
            self.config.font_size = font_size_var.get()
            self.config.auto_refresh = auto_refresh_var.get()
            self.config.refresh_interval = refresh_var.get()

            # Apply changes
            self.apply_theme()
            self.save_config()

            pref_window.destroy()
            messagebox.showinfo("Preferences", "Preferences saved. Some changes may require restart.")

        def cancel_preferences() -> None:
            pref_window.destroy()

        ttk.Button(button_frame, text="Apply", command=apply_preferences).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=cancel_preferences).pack(side=tk.RIGHT, padx=5)

    def show_file_properties(self, file_path: Path) -> None:
        """Show file properties dialog."""
        prop_window = tk.Toplevel(self.root)
        prop_window.title(f"Properties - {file_path.name}")
        prop_window.geometry("400x300")
        prop_window.transient(self.root)
        prop_window.grab_set()

        # File info
        info_frame = ttk.LabelFrame(prop_window, text="File Information")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        if file_path.exists():
            stat = file_path.stat()

            info_text = f"""Name: {file_path.name}
Path: {file_path.parent}
Size: {stat.st_size:,} bytes
Created: {datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S")}
Modified: {datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")}
Accessed: {datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M:%S")}
Type: {file_path.suffix.upper()[1:] if file_path.suffix else "File"}
"""
        else:
            info_text = "File not found or inaccessible"

        info_label = ttk.Label(info_frame, text=info_text, justify=tk.LEFT)
        info_label.pack(padx=10, pady=10)

        # Close button
        ttk.Button(prop_window, text="Close", command=prop_window.destroy).pack(pady=10)

    # Help operations
    def show_documentation(self) -> None:
        """Show documentation."""
        # Open documentation in web browser
        webbrowser.open("https://github.com/intellicrack/docs")

    def show_shortcuts(self) -> None:
        """Show keyboard shortcuts."""
        shortcuts_text = """Keyboard Shortcuts:

File Operations:
Ctrl+O          Open File
Ctrl+Shift+O    Open Folder
Ctrl+Q          Exit

View Operations:
F5              Refresh Current View

Analysis Operations:
F9              Quick Scan
F10             Deep Analysis

Navigation:
Tab             Switch between panels
Ctrl+Tab        Switch between tabs
"""

        messagebox.showinfo("Keyboard Shortcuts", shortcuts_text)

    def show_about(self) -> None:
        """Show about dialog."""
        about_text = """Intellicrack UI Enhancement Module v2.0.0

Advanced binary analysis and exploitation platform with
AI-driven capabilities and enhanced user interface.

Features:
 Three-panel professional interface
 Real-time analysis visualization
 Multi-platform script generation
 Comprehensive logging system
 Customizable themes and layouts

Copyright © 2024 Intellicrack Framework
Licensed under GPL v3
"""

        messagebox.showinfo("About Intellicrack", about_text)

    def run(self) -> None:
        """Start the UI main loop."""
        try:
            self.log_viewer.add_log("INFO", "Starting Intellicrack UI Enhanced Interface", "Main")
            self.root.mainloop()
        except KeyboardInterrupt:
            self.log_viewer.add_log("INFO", "Received interrupt signal, shutting down", "Main")
        except Exception as e:
            self.log_viewer.add_log("ERROR", f"Unexpected error: {e}", "Main")
        finally:
            self.save_config()


def main() -> None:
    """Run the UI enhancement module application."""
    app = UIEnhancementModule()
    app.run()


if __name__ == "__main__":
    main()
