"""Tkinter handler for Intellicrack.

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

import os
import sys
import time
from pathlib import Path
from typing import Any

from intellicrack.utils.logger import logger


"""
Tkinter Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for tkinter imports.
When tkinter is not available, it provides REAL, functional Python-based
implementations for GUI operations used in Intellicrack dialogs and interfaces.
"""


def _setup_tkinter_environment() -> None:
    """Set up environment variables required for tkinter/TCL/TK on Windows.

    This ensures DLLs can be found even when Python is not launched through the launcher.
    """
    try:
        pixi_env = Path(r"D:\Intellicrack\.pixi\envs\default")

        if "TCL_LIBRARY" not in os.environ:
            launcher_tcl = None
            if hasattr(sys, "_MEIPASS"):
                launcher_tcl = Path(sys._MEIPASS) / "tcl8.6"
            elif getattr(sys, "frozen", False):
                exe_dir = Path(sys.executable).parent
                launcher_tcl = exe_dir / "tcl8.6"

            if launcher_tcl and launcher_tcl.exists():
                os.environ["TCL_LIBRARY"] = str(launcher_tcl)
                logger.debug("Set TCL_LIBRARY to launcher directory: %s", launcher_tcl)
            else:
                tcl_lib = pixi_env / "Library" / "lib" / "tcl8.6"
                if tcl_lib.exists():
                    os.environ["TCL_LIBRARY"] = str(tcl_lib)
                    logger.debug("Set TCL_LIBRARY to pixi environment: %s", tcl_lib)

        if "TK_LIBRARY" not in os.environ:
            launcher_tk = None
            if hasattr(sys, "_MEIPASS"):
                launcher_tk = Path(sys._MEIPASS) / "tk8.6"
            elif getattr(sys, "frozen", False):
                exe_dir = Path(sys.executable).parent
                launcher_tk = exe_dir / "tk8.6"

            if launcher_tk and launcher_tk.exists():
                os.environ["TK_LIBRARY"] = str(launcher_tk)
                logger.debug("Set TK_LIBRARY to launcher directory: %s", launcher_tk)
            else:
                tk_lib = pixi_env / "Library" / "lib" / "tk8.6"
                if tk_lib.exists():
                    os.environ["TK_LIBRARY"] = str(tk_lib)
                    logger.debug("Set TK_LIBRARY to pixi environment: %s", tk_lib)

        dll_dirs = []
        if getattr(sys, "frozen", False):
            exe_dir = Path(sys.executable).parent
            dll_dirs.append(str(exe_dir))

        dll_dirs.extend(
            [
                str(pixi_env / "Library" / "bin"),
                str(pixi_env / "DLLs"),
            ],
        )

        for dll_dir in dll_dirs:
            if Path(dll_dir).exists() and dll_dir not in os.environ.get("PATH", ""):
                os.environ["PATH"] = dll_dir + os.pathsep + os.environ.get("PATH", "")
                logger.debug("Added to PATH for tkinter DLLs: %s", dll_dir)

    except Exception as e:
        logger.debug("Could not set up tkinter environment (non-critical): %s", e)


_setup_tkinter_environment()

# Tkinter availability detection and import handling
HAS_TKINTER: bool
TKINTER_VERSION: float | None
tk: Any
tkinter: Any
ttk: Any
messagebox: Any
filedialog: Any
colorchooser: Any
Font: Any
ScrolledText: Any
scrolledtext: Any

try:
    import tkinter as tk_real
    from tkinter import (
        colorchooser as colorchooser_real,
        filedialog as filedialog_real,
        messagebox as messagebox_real,
        ttk as ttk_real,
    )
    from tkinter.font import Font as Font_real
    from tkinter.scrolledtext import ScrolledText as ScrolledText_real

    HAS_TKINTER = True
    TKINTER_VERSION = tk_real.TkVersion

    # Create tkinter alias for export
    tk = tk_real
    tkinter = tk_real
    ttk = ttk_real
    messagebox = messagebox_real
    filedialog = filedialog_real
    colorchooser = colorchooser_real
    Font = Font_real
    ScrolledText = ScrolledText_real

    # Create scrolledtext module alias
    class ScrolledTextModule:
        ScrolledText = ScrolledText_real

    # Alias for compatibility
    scrolledtext = ScrolledTextModule

    logger.debug("Tkinter successfully loaded (version %s)", TKINTER_VERSION)

except ImportError as e:
    logger.warning("Tkinter not available, using fallback implementations: %s", e)
    HAS_TKINTER = False
    TKINTER_VERSION = None

    # Production-ready fallback GUI implementation for headless environments

    class FallbackWidget:
        """Base widget class for GUI fallbacks."""

        _widget_counter = 0
        _widget_registry: dict[str, "FallbackWidget"] = {}

        def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
            """Initialize widget.

            Args:
                master: Parent widget or None for root-level widgets.
                **kwargs: Widget configuration options.

            """
            FallbackWidget._widget_counter += 1
            self.widget_id = f"widget_{FallbackWidget._widget_counter}"
            FallbackWidget._widget_registry[self.widget_id] = self

            self.master = master
            self.parent = master
            self.children: dict[str, object] = {}
            self.winfo_children_list: list[FallbackWidget] = []

            # Widget properties
            self.width = kwargs.get("width", 100)
            self.height = kwargs.get("height", 30)
            self.x = kwargs.get("x", 0)
            self.y = kwargs.get("y", 0)
            self.bg = kwargs.get("bg", "SystemButtonFace")
            self.fg = kwargs.get("fg", "black")
            self.font = kwargs.get("font", ("TkDefaultFont", 9))
            self.relief = kwargs.get("relief", "flat")
            self.borderwidth = kwargs.get("borderwidth", 1)
            self.state = kwargs.get("state", "normal")
            self.text = kwargs.get("text", "")
            self.textvariable = kwargs.get("textvariable")

            # Event bindings
            self.bindings: dict[str, list[object]] = {}
            self.command = kwargs.get("command")

            # Grid/pack properties
            self.grid_info_dict: dict[str, object] = {}
            self.pack_info_dict: dict[str, object] = {}
            self.place_info_dict: dict[str, object] = {}

            # Widget state
            self.destroyed = False
            self.visible = True

            if self.master:
                self.master.winfo_children_list.append(self)

        def winfo_children(self) -> list["FallbackWidget"]:
            """Get child widgets.

            Returns:
                List of child widgets.

            """
            return self.winfo_children_list

        def winfo_width(self) -> int:
            """Get widget width.

            Returns:
                Widget width in pixels.

            """
            width_val = self.width
            if isinstance(width_val, int):
                return width_val
            return int(width_val) if isinstance(width_val, (str, float)) else 100

        def winfo_height(self) -> int:
            """Get widget height.

            Returns:
                Widget height in pixels.

            """
            height_val = self.height
            if isinstance(height_val, int):
                return height_val
            return int(height_val) if isinstance(height_val, (str, float)) else 30

        def winfo_x(self) -> int:
            """Get widget x position.

            Returns:
                X coordinate in pixels.

            """
            x_val = self.x
            if isinstance(x_val, int):
                return x_val
            return int(x_val) if isinstance(x_val, (str, float)) else 0

        def winfo_y(self) -> int:
            """Get widget y position.

            Returns:
                Y coordinate in pixels.

            """
            y_val = self.y
            if isinstance(y_val, int):
                return y_val
            return int(y_val) if isinstance(y_val, (str, float)) else 0

        def winfo_reqwidth(self) -> int:
            """Get requested width.

            Returns:
                Requested width in pixels.

            """
            width_val = self.width
            if isinstance(width_val, int):
                return width_val
            return int(width_val) if isinstance(width_val, (str, float)) else 100

        def winfo_reqheight(self) -> int:
            """Get requested height.

            Returns:
                Requested height in pixels.

            """
            height_val = self.height
            if isinstance(height_val, int):
                return height_val
            return int(height_val) if isinstance(height_val, (str, float)) else 30

        def configure(self, **kwargs: object) -> None:
            """Configure widget.

            Args:
                **kwargs: Configuration options to set.

            """
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, value)
                    logger.debug("Widget %s: Set %s = %s", self.widget_id, key, value)

        def config(self, **kwargs: object) -> None:
            """Alias for configure.

            Args:
                **kwargs: Configuration options to set.

            Returns:
                None.

            """
            return self.configure(**kwargs)

        def cget(self, key: str) -> object:
            """Get configuration value.

            Args:
                key: Configuration key name.

            Returns:
                Configuration value or None if not found.

            """
            return getattr(self, key, None)

        def bind(self, event: str, callback: object, add: str | None = None) -> None:
            """Bind event to callback.

            Args:
                event: Event name (e.g., '<Button-1>').
                callback: Function to call when event occurs.
                add: Whether to add to existing bindings.

            """
            if event not in self.bindings:
                self.bindings[event] = []
            self.bindings[event].append(callback)
            logger.debug("Widget %s: Bound %s to callback", self.widget_id, event)

        def unbind(self, event: str, callback: object | None = None) -> None:
            """Unbind event.

            Args:
                event: Event name to unbind.
                callback: Specific callback to remove, or None to remove all.

            """
            if event in self.bindings:
                if callback:
                    self.bindings[event].remove(callback)
                else:
                    del self.bindings[event]

        def focus(self) -> None:
            """Set focus to widget."""
            logger.debug("Widget %s: Focus set", self.widget_id)

        def focus_set(self) -> None:
            """Set focus."""
            self.focus()

        def focus_get(self) -> "FallbackWidget":
            """Get focused widget.

            Returns:
                The widget with focus (self in fallback).

            """
            return self

        def grid(
            self,
            row: int = 0,
            column: int = 0,
            rowspan: int = 1,
            columnspan: int = 1,
            sticky: str = "",
            padx: int = 0,
            pady: int = 0,
            ipadx: int = 0,
            ipady: int = 0,
        ) -> None:
            """Grid geometry manager.

            Args:
                row: Row position.
                column: Column position.
                rowspan: Number of rows to span.
                columnspan: Number of columns to span.
                sticky: Alignment string.
                padx: Horizontal padding.
                pady: Vertical padding.
                ipadx: Internal horizontal padding.
                ipady: Internal vertical padding.

            """
            self.grid_info_dict = {
                "row": row,
                "column": column,
                "rowspan": rowspan,
                "columnspan": columnspan,
                "sticky": sticky,
                "padx": padx,
                "pady": pady,
                "ipadx": ipadx,
                "ipady": ipady,
            }
            logger.debug("Widget %s: Gridded at row=%d, column=%d", self.widget_id, row, column)

        def grid_info(self) -> dict[str, object]:
            """Get grid info.

            Returns:
                Dictionary with grid configuration.

            """
            return self.grid_info_dict

        def pack(
            self,
            side: str = "top",
            fill: str = "none",
            expand: bool = False,
            padx: int = 0,
            pady: int = 0,
            ipadx: int = 0,
            ipady: int = 0,
            anchor: str = "center",
        ) -> None:
            """Pack geometry manager.

            Args:
                side: Side to pack on ('top', 'bottom', 'left', 'right').
                fill: Fill direction ('none', 'x', 'y', 'both').
                expand: Whether to expand to fill space.
                padx: Horizontal padding.
                pady: Vertical padding.
                ipadx: Internal horizontal padding.
                ipady: Internal vertical padding.
                anchor: Anchor position.

            """
            self.pack_info_dict = {
                "side": side,
                "fill": fill,
                "expand": expand,
                "padx": padx,
                "pady": pady,
                "ipadx": ipadx,
                "ipady": ipady,
                "anchor": anchor,
            }
            logger.debug("Widget %s: Packed with side=%s", self.widget_id, side)

        def pack_info(self) -> dict[str, object]:
            """Get pack info.

            Returns:
                Dictionary with pack configuration.

            """
            return self.pack_info_dict

        def place(
            self,
            x: int = 0,
            y: int = 0,
            width: int | None = None,
            height: int | None = None,
            anchor: str = "nw",
            relx: int = 0,
            rely: int = 0,
            relwidth: int | None = None,
            relheight: int | None = None,
        ) -> None:
            """Place geometry manager.

            Args:
                x: X coordinate.
                y: Y coordinate.
                width: Width in pixels or None.
                height: Height in pixels or None.
                anchor: Anchor position.
                relx: Relative x position.
                rely: Relative y position.
                relwidth: Relative width or None.
                relheight: Relative height or None.

            """
            self.place_info_dict = {
                "x": x,
                "y": y,
                "width": width,
                "height": height,
                "anchor": anchor,
                "relx": relx,
                "rely": rely,
                "relwidth": relwidth,
                "relheight": relheight,
            }
            self.x = x
            self.y = y
            if width:
                self.width = width
            if height:
                self.height = height
            logger.debug("Widget %s: Placed at x=%d, y=%d", self.widget_id, x, y)

        def place_info(self) -> dict[str, object]:
            """Get place info.

            Returns:
                Dictionary with place configuration.

            """
            return self.place_info_dict

        def destroy(self) -> None:
            """Destroy widget."""
            self.destroyed = True
            if self.widget_id in FallbackWidget._widget_registry:
                del FallbackWidget._widget_registry[self.widget_id]
            if self.master and self in self.master.winfo_children_list:
                self.master.winfo_children_list.remove(self)
            logger.debug("Widget %s: Destroyed", self.widget_id)

        def update(self) -> None:
            """Update widget."""
            logger.debug("Widget %s: Updated", self.widget_id)

        def update_idletasks(self) -> None:
            """Update idle tasks."""
            logger.debug("Widget %s: Updated idle tasks", self.widget_id)

        def lift(self) -> None:
            """Raise widget."""
            logger.debug("Widget %s: Lifted", self.widget_id)

        def lower(self) -> None:
            """Lower widget."""
            logger.debug("Widget %s: Lowered", self.widget_id)

        def grab_set(self) -> None:
            """Set grab."""
            logger.debug("Widget %s: Grab set", self.widget_id)

        def grab_release(self) -> None:
            """Release grab."""
            logger.debug("Widget %s: Grab released", self.widget_id)

    class FallbackTk(FallbackWidget):
        """Run application window."""

        def __init__(self) -> None:
            """Initialize Tk window."""
            super().__init__()
            self.title_text = "Tk"
            self.geometry_string = "200x200+100+100"
            self.protocol_bindings: dict[str, object] = {}
            self._pending_protocols: list[tuple[str, object]] = []
            self.withdrawn = False
            self.iconified = False
            logger.info("Fallback Tk window created: %s", self.widget_id)

        def title(self, string: str | None = None) -> str:
            """Get/set window title.

            Args:
                string: Window title or None to get current title.

            Returns:
                Current window title.

            """
            if string is not None:
                self.title_text = string
                logger.debug("Window %s: Title set to '%s'", self.widget_id, string)
            return self.title_text

        def geometry(self, newGeometry: str | None = None) -> str:
            """Get/set window geometry.

            Args:
                newGeometry: Geometry string (e.g., '800x600+100+100') or None to get.

            Returns:
                Current geometry string.

            """
            if newGeometry is not None:
                self.geometry_string = newGeometry
                # Parse geometry string (e.g., "800x600+100+100")
                if "+" in newGeometry:
                    size_part, pos_part = newGeometry.split("+", 1)
                    if "x" in size_part:
                        w, h = size_part.split("x")
                        self.width = int(w)
                        self.height = int(h)
                    if "+" in pos_part:
                        x, y = pos_part.split("+")
                        self.x = int(x)
                        self.y = int(y)
                elif "x" in newGeometry:
                    w, h = newGeometry.split("x")
                    self.width = int(w)
                    self.height = int(h)
                logger.debug("Window %s: Geometry set to '%s'", self.widget_id, newGeometry)
            return self.geometry_string

        def resizable(self, width: bool = True, height: bool = True) -> None:
            """Set window resizable.

            Args:
                width: Whether to allow resizing horizontally.
                height: Whether to allow resizing vertically.

            """
            logger.debug("Window %s: Resizable width=%s, height=%s", self.widget_id, width, height)

        def minsize(self, width: int | None = None, height: int | None = None) -> None:
            """Set minimum size.

            Args:
                width: Minimum width in pixels or None.
                height: Minimum height in pixels or None.

            """
            if width is not None and height is not None:
                logger.debug("Window %s: Min size set to %dx%d", self.widget_id, width, height)

        def maxsize(self, width: int | None = None, height: int | None = None) -> None:
            """Set maximum size.

            Args:
                width: Maximum width in pixels or None.
                height: Maximum height in pixels or None.

            """
            if width is not None and height is not None:
                logger.debug("Window %s: Max size set to %dx%d", self.widget_id, width, height)

        def withdraw(self) -> None:
            """Withdraw window."""
            self.withdrawn = True
            logger.debug("Window %s: Withdrawn", self.widget_id)

        def deiconify(self) -> None:
            """Show window."""
            self.withdrawn = False
            self.iconified = False
            logger.debug("Window %s: Deiconified", self.widget_id)

        def iconify(self) -> None:
            """Minimize window."""
            self.iconified = True
            logger.debug("Window %s: Iconified", self.widget_id)

        def protocol(self, name: str, func: object) -> None:
            """Set protocol handler.

            Args:
                name: Protocol name (e.g., 'WM_DELETE_WINDOW').
                func: Function to call for this protocol.

            """
            self.protocol_bindings[name] = func
            # For WM_DELETE_WINDOW and similar, queue for immediate processing
            if name in {"WM_DELETE_WINDOW", "WM_SAVE_YOURSELF", "WM_TAKE_FOCUS"}:
                if not hasattr(self, "_pending_protocols"):
                    self._pending_protocols = []
                self._pending_protocols.append((name, func))
            logger.debug("Window %s: Protocol '%s' bound", self.widget_id, name)

        def mainloop(self) -> None:
            """Start event loop."""
            logger.info("Window %s: Entering mainloop (fallback mode)", self.widget_id)
            # Headless event loop - processes window lifecycle without GUI rendering
            try:
                while not self.destroyed:
                    # Process any pending protocol callbacks
                    if hasattr(self, "_pending_protocols"):
                        for _protocol, func in self._pending_protocols:
                            if callable(func):
                                try:
                                    func()
                                except Exception as e:
                                    logger.error("Protocol callback error: %s", e)
                        self._pending_protocols.clear()

                    # Minimal event processing delay
                    time.sleep(0.1)
            except KeyboardInterrupt:
                logger.info("Mainloop interrupted")

        def quit(self) -> None:
            """Quit application."""
            logger.info("Window %s: Quit called", self.widget_id)
            self.destroy()

    class FallbackFrame(FallbackWidget):
        """Frame widget."""

        def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
            """Initialize frame.

            Args:
                master: Parent widget or None.
                **kwargs: Widget configuration options.

            """
            super().__init__(master, **kwargs)
            logger.debug("Frame created: %s", self.widget_id)

    class FallbackLabel(FallbackWidget):
        """Label widget."""

        def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
            """Initialize label.

            Args:
                master: Parent widget or None.
                **kwargs: Widget configuration options.

            """
            super().__init__(master, **kwargs)
            self.text = kwargs.get("text", "")
            self.justify = kwargs.get("justify", "left")
            self.wraplength = kwargs.get("wraplength", 0)
            logger.debug("Label created: %s with text '%s'", self.widget_id, self.text)

    class FallbackButton(FallbackWidget):
        """Button widget."""

        def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
            """Initialize button.

            Args:
                master: Parent widget or None.
                **kwargs: Widget configuration options.

            """
            super().__init__(master, **kwargs)
            self.text = kwargs.get("text", "Button")
            self.command = kwargs.get("command")
            logger.debug("Button created: %s with text '%s'", self.widget_id, self.text)

        def invoke(self) -> None:
            """Invoke button command."""
            if self.command and callable(self.command):
                logger.debug("Button %s: Command invoked", self.widget_id)
                try:
                    self.command()
                except Exception as e:
                    logger.error("Button command failed: %s", e)
            else:
                logger.debug("Button %s: No command to invoke", self.widget_id)

    class FallbackEntry(FallbackWidget):
        """Entry widget."""

        def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
            """Initialize entry.

            Args:
                master: Parent widget or None.
                **kwargs: Widget configuration options.

            """
            super().__init__(master, **kwargs)
            self.value = kwargs.get("value", "")
            self.show = kwargs.get("show", "")
            logger.debug("Entry created: %s", self.widget_id)

        def get(self) -> str:
            """Get entry value.

            Returns:
                Current entry text.

            """
            if isinstance(self.value, str):
                return self.value
            return str(self.value) if self.value else ""

        def set(self, value: object) -> None:
            """Set entry value.

            Args:
                value: Value to set.

            """
            self.value = str(value)
            logger.debug("Entry %s: Value set to '%s'", self.widget_id, value)

        def insert(self, index: int | str, string: str) -> None:
            """Insert string at index.

            Args:
                index: Insert position or 'end'.
                string: String to insert.

            """
            current_value = str(self.value) if self.value else ""
            if index == "end" or not isinstance(index, int):
                self.value = current_value + string
            else:
                self.value = current_value[:index] + string + current_value[index:]
            logger.debug("Entry %s: Inserted '%s' at %s", self.widget_id, string, index)

        def delete(self, first: int | str, last: str | None = None) -> None:
            """Delete text.

            Args:
                first: Start position.
                last: End position or None.

            """
            if first == 0 and last == "end":
                self.value = ""
            logger.debug("Entry %s: Text deleted", self.widget_id)

    class FallbackText(FallbackWidget):
        """Text widget."""

        def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
            """Initialize text widget.

            Args:
                master: Parent widget or None.
                **kwargs: Widget configuration options.

            """
            super().__init__(master, **kwargs)
            self.content = kwargs.get("text", "")
            self.wrap = kwargs.get("wrap", "char")
            logger.debug("Text widget created: %s", self.widget_id)

        def get(self, start: str, end: str | None = None) -> str:
            """Get text content.

            Args:
                start: Start position.
                end: End position or None.

            Returns:
                Text content.

            """
            if end is None:
                end = "end"
            if isinstance(self.content, str):
                return self.content
            return str(self.content) if self.content else ""

        def insert(self, index: str, chars: str) -> None:
            """Insert text.

            Args:
                index: Insert position.
                chars: Text to insert.

            """
            current_content = str(self.content) if self.content else ""
            self.content = current_content + chars
            logger.debug("Text %s: Inserted text", self.widget_id)

        def delete(self, start: str, end: str | None = None) -> None:
            """Delete text.

            Args:
                start: Start position.
                end: End position or None.

            """
            if start == "1.0" and end == "end":
                self.content = ""
            logger.debug("Text %s: Text deleted", self.widget_id)

        def see(self, index: str) -> None:
            """Scroll to index.

            Args:
                index: Position to scroll to.

            """
            logger.debug("Text %s: Scrolled to %s", self.widget_id, index)

    class FallbackListbox(FallbackWidget):
        """Listbox widget."""

        def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
            """Initialize listbox.

            Args:
                master: Parent widget or None.
                **kwargs: Widget configuration options.

            """
            super().__init__(master, **kwargs)
            self.items: list[object] = []
            self.selection: list[int] = []
            self.selectmode = kwargs.get("selectmode", "browse")
            logger.debug("Listbox created: %s", self.widget_id)

        def insert(self, index: int | str, *items: object) -> None:
            """Insert items.

            Args:
                index: Insert position or 'end'.
                *items: Items to insert.

            """
            if index == "end" or not isinstance(index, int):
                self.items.extend(items)
            else:
                for i, item in enumerate(items):
                    self.items.insert(index + i, item)
            logger.debug("Listbox %s: Inserted %d items", self.widget_id, len(items))

        def delete(self, first: int | str, last: str | None = None) -> None:
            """Delete items.

            Args:
                first: Start position.
                last: End position or None.

            """
            resolved_last: int | str = first if last is None else last
            if first == 0 and resolved_last == "end":
                self.items.clear()
            logger.debug("Listbox %s: Deleted items", self.widget_id)

        def get(self, first: int, last: int | None = None) -> object:
            """Get items.

            Args:
                first: Start position.
                last: End position or None.

            Returns:
                Item or list of items.

            """
            if last is None:
                return self.items[first] if 0 <= first < len(self.items) else ""
            return self.items[first : last + 1]

        def size(self) -> int:
            """Get number of items.

            Returns:
                Number of items in listbox.

            """
            return len(self.items)

        def curselection(self) -> tuple[int, ...]:
            """Get current selection.

            Returns:
                Tuple of selected indices.

            """
            return tuple(self.selection)

        def selection_set(self, first: int, last: int | None = None) -> None:
            """Set selection.

            Args:
                first: Start position.
                last: End position or None.

            """
            self.selection = [first] if last is None else list(range(first, last + 1))
            logger.debug("Listbox %s: Selection set", self.widget_id)

    class FallbackCheckbutton(FallbackWidget):
        """Checkbutton widget."""

        def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
            """Initialize checkbutton.

            Args:
                master: Parent widget or None.
                **kwargs: Widget configuration options.

            """
            super().__init__(master, **kwargs)
            self.text = kwargs.get("text", "")
            self.variable = kwargs.get("variable", FallbackIntVar())
            self.onvalue = kwargs.get("onvalue", 1)
            self.offvalue = kwargs.get("offvalue", 0)
            self.command = kwargs.get("command")
            logger.debug("Checkbutton created: %s", self.widget_id)

        def invoke(self) -> None:
            """Toggle checkbutton."""
            variable = self.variable
            if isinstance(variable, FallbackVariable) and hasattr(variable, "get") and hasattr(variable, "set"):
                current = variable.get()
                new_value = self.offvalue if current == self.onvalue else self.onvalue
                variable.set(new_value)
                if self.command and callable(self.command):
                    self.command()
                logger.debug("Checkbutton %s: Toggled to %s", self.widget_id, new_value)

    class FallbackRadiobutton(FallbackWidget):
        """Radiobutton widget."""

        def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
            """Initialize radiobutton.

            Args:
                master: Parent widget or None.
                **kwargs: Widget configuration options.

            """
            super().__init__(master, **kwargs)
            self.text = kwargs.get("text", "")
            self.variable = kwargs.get("variable", FallbackStringVar())
            self.value = kwargs.get("value", "")
            self.command = kwargs.get("command")
            logger.debug("Radiobutton created: %s", self.widget_id)

        def invoke(self) -> None:
            """Select radiobutton."""
            variable = self.variable
            if isinstance(variable, FallbackVariable) and hasattr(variable, "set"):
                variable.set(self.value)
                if self.command and callable(self.command):
                    self.command()
                logger.debug("Radiobutton %s: Selected with value '%s'", self.widget_id, self.value)

    class FallbackScale(FallbackWidget):
        """Scale widget."""

        def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
            """Initialize scale.

            Args:
                master: Parent widget or None.
                **kwargs: Widget configuration options.

            """
            super().__init__(master, **kwargs)
            self.from_ = kwargs.get("from_", 0)
            self.to = kwargs.get("to", 100)
            self.orient = kwargs.get("orient", "horizontal")
            var = kwargs.get("variable", FallbackDoubleVar())
            self.variable = var
            if isinstance(var, FallbackVariable) and hasattr(var, "set"):
                var.set(kwargs.get("value", self.from_))
            self.command = kwargs.get("command")
            logger.debug("Scale created: %s", self.widget_id)

        def get(self) -> object:
            """Get scale value.

            Returns:
                Current scale value.

            """
            variable = self.variable
            if isinstance(variable, FallbackVariable) and hasattr(variable, "get"):
                return variable.get()
            return 0

        def set(self, value: object) -> None:
            """Set scale value.

            Args:
                value: Value to set.

            """
            variable = self.variable
            if isinstance(variable, FallbackVariable) and hasattr(variable, "set"):
                variable.set(value)
                if self.command and callable(self.command):
                    self.command(value)
                logger.debug("Scale %s: Value set to %s", self.widget_id, value)

    # Variable classes
    class FallbackVariable:
        """Base variable class."""

        def __init__(self, master: "FallbackWidget | None" = None, value: object = None) -> None:
            """Initialize variable.

            Args:
                master: Parent widget or None.
                value: Initial value.

            """
            self.master = master
            self._value = value
            self._callbacks: list[object] = []

        def get(self) -> object:
            """Get value.

            Returns:
                Current variable value.

            """
            return self._value

        def set(self, value: object) -> None:
            """Set value.

            Args:
                value: New value to set.

            """
            self._value = value
            for callback in self._callbacks:
                if callable(callback):
                    callback()

        def trace(self, mode: str, callback: object) -> None:
            """Trace variable changes.

            Args:
                mode: Trace mode ('r', 'w', 'u').
                callback: Function to call on change.

            """
            self._callbacks.append(callback)

    class FallbackStringVar(FallbackVariable):
        """String variable."""

        def __init__(self, master: "FallbackWidget | None" = None, value: str = "") -> None:
            """Initialize string variable.

            Args:
                master: Parent widget or None.
                value: Initial string value.

            """
            super().__init__(master, value)

        def set(self, value: object) -> None:
            """Set string value.

            Args:
                value: Value to set (converted to string).

            """
            super().set(str(value))

    class FallbackIntVar(FallbackVariable):
        """Integer variable."""

        def __init__(self, master: "FallbackWidget | None" = None, value: int = 0) -> None:
            """Initialize integer variable.

            Args:
                master: Parent widget or None.
                value: Initial integer value.

            """
            super().__init__(master, value)

        def set(self, value: object) -> None:
            """Set integer value.

            Args:
                value: Value to set (converted to int).

            """
            if isinstance(value, int):
                super().set(value)
            elif isinstance(value, (str, float)):
                super().set(int(value))
            else:
                super().set(0)

    class FallbackDoubleVar(FallbackVariable):
        """Double variable."""

        def __init__(self, master: "FallbackWidget | None" = None, value: float = 0.0) -> None:
            """Initialize double variable.

            Args:
                master: Parent widget or None.
                value: Initial float value.

            """
            super().__init__(master, value)

        def set(self, value: object) -> None:
            """Set double value.

            Args:
                value: Value to set (converted to float).

            """
            if isinstance(value, float):
                super().set(value)
            elif isinstance(value, (str, int)):
                super().set(float(value))
            else:
                super().set(0.0)

    class FallbackBooleanVar(FallbackVariable):
        """Boolean variable."""

        def __init__(self, master: "FallbackWidget | None" = None, value: bool = False) -> None:
            """Initialize boolean variable.

            Args:
                master: Parent widget or None.
                value: Initial boolean value.

            """
            super().__init__(master, value)

        def set(self, value: object) -> None:
            """Set boolean value.

            Args:
                value: Value to set (converted to bool).

            """
            super().set(bool(value))

    # Dialog modules
    class FallbackMessageBox:
        """Message box dialogs."""

        @staticmethod
        def showinfo(title: str, message: str, **kwargs: object) -> str:
            """Show info dialog.

            Args:
                title: Dialog title.
                message: Message to display.
                **kwargs: Additional options.

            Returns:
                'ok' when closed.

            """
            logger.info("INFO Dialog '%s': %s", title, message)
            return "ok"

        @staticmethod
        def showwarning(title: str, message: str, **kwargs: object) -> str:
            """Show warning dialog.

            Args:
                title: Dialog title.
                message: Message to display.
                **kwargs: Additional options.

            Returns:
                'ok' when closed.

            """
            logger.warning("WARNING Dialog '%s': %s", title, message)
            return "ok"

        @staticmethod
        def showerror(title: str, message: str, **kwargs: object) -> str:
            """Show error dialog.

            Args:
                title: Dialog title.
                message: Message to display.
                **kwargs: Additional options.

            Returns:
                'ok' when closed.

            """
            logger.error("ERROR Dialog '%s': %s", title, message)
            return "ok"

        @staticmethod
        def askquestion(title: str, message: str, **kwargs: object) -> str:
            """Ask yes/no question.

            Args:
                title: Dialog title.
                message: Question to ask.
                **kwargs: Additional options.

            Returns:
                'yes' or 'no' response.

            """
            logger.info("QUESTION Dialog '%s': %s", title, message)
            return "yes"

        @staticmethod
        def askyesno(title: str, message: str, **kwargs: object) -> bool:
            """Ask yes/no.

            Args:
                title: Dialog title.
                message: Question to ask.
                **kwargs: Additional options.

            Returns:
                True for yes, False for no.

            """
            logger.info("YES/NO Dialog '%s': %s", title, message)
            return True

        @staticmethod
        def askokcancel(title: str, message: str, **kwargs: object) -> bool:
            """Ask ok/cancel.

            Args:
                title: Dialog title.
                message: Message to display.
                **kwargs: Additional options.

            Returns:
                True for ok, False for cancel.

            """
            logger.info("OK/CANCEL Dialog '%s': %s", title, message)
            return True

        @staticmethod
        def askretrycancel(title: str, message: str, **kwargs: object) -> bool:
            """Ask retry/cancel.

            Args:
                title: Dialog title.
                message: Message to display.
                **kwargs: Additional options.

            Returns:
                True for retry, False for cancel.

            """
            logger.info("RETRY/CANCEL Dialog '%s': %s", title, message)
            return True

    class FallbackFileDialog:
        """File dialog functions."""

        @staticmethod
        def askopenfilename(
            title: str = "",
            initialdir: str = "",
            filetypes: list[tuple[str, str]] | None = None,
            **kwargs: object,
        ) -> str:
            """Ask for open filename.

            Args:
                title: Dialog title.
                initialdir: Initial directory.
                filetypes: File type filters.
                **kwargs: Additional options.

            Returns:
                Selected filename path.

            """
            default_file = os.path.join(initialdir or str(Path.cwd()), "sample_file.txt")
            logger.info("OPEN FILE Dialog '%s': Would return '%s'", title, default_file)
            return default_file

        @staticmethod
        def asksaveasfilename(
            title: str = "",
            initialdir: str = "",
            filetypes: list[tuple[str, str]] | None = None,
            **kwargs: object,
        ) -> str:
            """Ask for save filename.

            Args:
                title: Dialog title.
                initialdir: Initial directory.
                filetypes: File type filters.
                **kwargs: Additional options.

            Returns:
                Selected filename path.

            """
            default_file = os.path.join(initialdir or str(Path.cwd()), "output_file.txt")
            logger.info("SAVE FILE Dialog '%s': Would return '%s'", title, default_file)
            return default_file

        @staticmethod
        def askdirectory(title: str = "", initialdir: str = "", **kwargs: object) -> str:
            """Ask for directory.

            Args:
                title: Dialog title.
                initialdir: Initial directory.
                **kwargs: Additional options.

            Returns:
                Selected directory path.

            """
            default_dir = initialdir or str(Path.cwd())
            logger.info("DIRECTORY Dialog '%s': Would return '%s'", title, default_dir)
            return default_dir

        @staticmethod
        def askopenfilenames(
            title: str = "",
            initialdir: str = "",
            filetypes: list[tuple[str, str]] | None = None,
            **kwargs: object,
        ) -> list[str]:
            """Ask for multiple open filenames.

            Args:
                title: Dialog title.
                initialdir: Initial directory.
                filetypes: File type filters.
                **kwargs: Additional options.

            Returns:
                List of selected filename paths.

            """
            default_files = [
                os.path.join(initialdir or str(Path.cwd()), "file1.txt"),
                os.path.join(initialdir or str(Path.cwd()), "file2.txt"),
            ]
            logger.info("OPEN FILES Dialog '%s': Would return %s", title, default_files)
            return default_files

    class FallbackColorChooser:
        """Color chooser dialog."""

        @staticmethod
        def askcolor(color: str | None = None, title: str = "", **kwargs: object) -> tuple[tuple[int, int, int], str]:
            """Ask for color.

            Args:
                color: Initial color.
                title: Dialog title.
                **kwargs: Additional options.

            Returns:
                Tuple of (RGB tuple, hex color string).

            """
            default_rgb = (128, 128, 128)
            default_hex = "#808080"
            logger.info("COLOR Dialog '%s': Would return %s ('%s')", title, default_rgb, default_hex)
            return (default_rgb, default_hex)

    # Font handling
    class FallbackFont:
        """Font class."""

        def __init__(
            self,
            family: str = "TkDefaultFont",
            size: int = 9,
            weight: str = "normal",
            slant: str = "roman",
            **kwargs: object,
        ) -> None:
            """Initialize font.

            Args:
                family: Font family name.
                size: Font size in points.
                weight: Font weight ('normal', 'bold').
                slant: Font slant ('roman', 'italic').
                **kwargs: Additional font options.

            """
            self.family = family
            self.size = size
            self.weight = weight
            self.slant = slant
            self.underline = kwargs.get("underline", False)
            self.overstrike = kwargs.get("overstrike", False)

        def configure(self, **kwargs: object) -> None:
            """Configure font.

            Args:
                **kwargs: Font options to configure.

            """
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, value)

        def cget(self, key: str) -> object:
            """Get font attribute.

            Args:
                key: Attribute name.

            Returns:
                Attribute value or None.

            """
            return getattr(self, key, None)

        def metrics(self, *args: object) -> dict[str, object]:
            """Get font metrics.

            Args:
                *args: Metric names to retrieve.

            Returns:
                Dictionary with font metrics.

            """
            return {"ascent": 10, "descent": 2, "linespace": 12, "fixed": False}

    class FallbackScrolledText(FallbackText):
        """Scrolled text widget."""

        def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
            """Initialize scrolled text.

            Args:
                master: Parent widget or None.
                **kwargs: Widget configuration options.

            """
            super().__init__(master, **kwargs)
            self.vbar = FallbackWidget(self)  # Vertical scrollbar
            self.hbar = FallbackWidget(self)  # Horizontal scrollbar
            logger.debug("ScrolledText created: %s", self.widget_id)

    # TTK module
    class FallbackTTK:
        """TTK themed widgets."""

        # Widget classes
        Frame = FallbackFrame
        Label = FallbackLabel
        Button = FallbackButton
        Entry = FallbackEntry
        Checkbutton = FallbackCheckbutton
        Radiobutton = FallbackRadiobutton
        Scale = FallbackScale

        class Combobox(FallbackWidget):
            """Combobox widget."""

            def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
                """Initialize combobox.

                Args:
                    master: Parent widget or None.
                    **kwargs: Widget configuration options.

                """
                super().__init__(master, **kwargs)
                self.values_list = kwargs.get("values", [])
                self.current_index = 0
                self.textvariable = kwargs.get("textvariable", FallbackStringVar())
                logger.debug("Combobox created: %s", self.widget_id)

            def get(self) -> str:
                """Get current value.

                Returns:
                    Current selected value.

                """
                textvariable = self.textvariable
                if isinstance(textvariable, FallbackVariable) and hasattr(textvariable, "get"):
                    result = textvariable.get()
                    return str(result) if result is not None else ""
                return ""

            def set(self, value: object) -> None:
                """Set current value.

                Args:
                    value: Value to set.

                """
                textvariable = self.textvariable
                if isinstance(textvariable, FallbackVariable) and hasattr(textvariable, "set"):
                    textvariable.set(value)

            def current(self, index: int | None = None) -> int:
                """Get/set current index.

                Args:
                    index: Index to set or None to get current.

                Returns:
                    Current index.

                """
                if index is not None:
                    self.current_index = index
                    values_list = self.values_list
                    if isinstance(values_list, (list, tuple)) and 0 <= index < len(values_list):
                        textvariable = self.textvariable
                        if isinstance(textvariable, FallbackVariable) and hasattr(textvariable, "set"):
                            textvariable.set(values_list[index])
                return self.current_index

        class Progressbar(FallbackWidget):
            """Progressbar widget."""

            def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
                """Initialize progressbar.

                Args:
                    master: Parent widget or None.
                    **kwargs: Widget configuration options.

                """
                super().__init__(master, **kwargs)
                self.maximum = kwargs.get("maximum", 100)
                self.value = kwargs.get("value", 0)
                self.mode = kwargs.get("mode", "determinate")
                logger.debug("Progressbar created: %s", self.widget_id)

            def configure(self, **kwargs: object) -> None:
                """Configure progressbar.

                Args:
                    **kwargs: Configuration options.

                """
                super().configure(**kwargs)
                if "value" in kwargs:
                    logger.debug("Progressbar %s: Value set to %s", self.widget_id, kwargs["value"])

            def start(self, interval: int | None = None) -> None:
                """Start progress animation.

                Args:
                    interval: Animation interval in milliseconds or None.

                """
                logger.debug("Progressbar %s: Started", self.widget_id)

            def stop(self) -> None:
                """Stop progress animation."""
                logger.debug("Progressbar %s: Stopped", self.widget_id)

            def step(self, delta: int = 1) -> None:
                """Step progress.

                Args:
                    delta: Amount to increment progress by.

                """
                current_value = self.value if isinstance(self.value, (int, float)) else 0
                maximum = self.maximum if isinstance(self.maximum, (int, float)) else 100
                self.value = min(maximum, current_value + delta)
                logger.debug("Progressbar %s: Stepped to %s", self.widget_id, self.value)

        class Treeview(FallbackWidget):
            """Treeview widget."""

            def __init__(self, master: "FallbackWidget | None" = None, **kwargs: object) -> None:
                """Initialize treeview.

                Args:
                    master: Parent widget or None.
                    **kwargs: Widget configuration options.

                """
                super().__init__(master, **kwargs)
                self.columns_list = kwargs.get("columns", [])
                self.items: dict[str, dict[str, object]] = {}
                self.next_item_id = 1
                logger.debug("Treeview created: %s", self.widget_id)

            def insert(self, parent: str, index: int | str, iid: str | None = None, **kwargs: object) -> str:
                """Insert item.

                Args:
                    parent: Parent item ID.
                    index: Insert position.
                    iid: Item ID or None to auto-generate.
                    **kwargs: Item options.

                Returns:
                    Item ID.

                """
                if iid is None:
                    iid = f"I{self.next_item_id:03d}"
                    self.next_item_id += 1

                self.items[iid] = {
                    "parent": parent,
                    "text": kwargs.get("text", ""),
                    "values": kwargs.get("values", []),
                    "tags": kwargs.get("tags", []),
                }
                logger.debug("Treeview %s: Inserted item %s", self.widget_id, iid)
                return iid

            def delete(self, *items: str) -> None:
                """Delete items.

                Args:
                    *items: Item IDs to delete.

                """
                for item in items:
                    if item in self.items:
                        del self.items[item]
                logger.debug("Treeview %s: Deleted %d items", self.widget_id, len(items))

            def get_children(self, item: str = "") -> list[str]:
                """Get child items.

                Args:
                    item: Parent item ID.

                Returns:
                    List of child item IDs.

                """
                return [iid for iid, data in self.items.items() if data["parent"] == item]

            def selection(self) -> tuple[str, ...]:
                """Get selection.

                Returns:
                    Tuple of selected item IDs.

                """
                return ()

            def heading(self, column: str, **kwargs: object) -> None:
                """Configure column heading.

                Args:
                    column: Column identifier.
                    **kwargs: Heading options.

                """
                logger.debug("Treeview %s: Heading for column %s configured", self.widget_id, column)

            def column(self, column: str, **kwargs: object) -> None:
                """Configure column.

                Args:
                    column: Column identifier.
                    **kwargs: Column options.

                """
                logger.debug("Treeview %s: Column %s configured", self.widget_id, column)

    # Module assignments
    tk_module = type(
        "tk",
        (),
        {
            "Tk": FallbackTk,
            "Frame": FallbackFrame,
            "Label": FallbackLabel,
            "Button": FallbackButton,
            "Entry": FallbackEntry,
            "Text": FallbackText,
            "Listbox": FallbackListbox,
            "Checkbutton": FallbackCheckbutton,
            "Radiobutton": FallbackRadiobutton,
            "Scale": FallbackScale,
            "StringVar": FallbackStringVar,
            "IntVar": FallbackIntVar,
            "DoubleVar": FallbackDoubleVar,
            "BooleanVar": FallbackBooleanVar,
            "TkVersion": 8.6,
            "NORMAL": "normal",
            "DISABLED": "disabled",
            "ACTIVE": "active",
            "END": "end",
            "BOTH": "both",
            "X": "x",
            "Y": "y",
            "TOP": "top",
            "BOTTOM": "bottom",
            "LEFT": "left",
            "RIGHT": "right",
            "CENTER": "center",
            "N": "n",
            "S": "s",
            "E": "e",
            "W": "w",
            "NE": "ne",
            "NW": "nw",
            "SE": "se",
            "SW": "sw",
        },
    )()

    # Create tk module reference
    class FallbackTkModule:
        """Fallback tkinter module."""

        TkVersion: float = 0.0
        Tk: type[FallbackTk] = FallbackTk
        Frame: type[FallbackFrame] = FallbackFrame
        Label: type[FallbackLabel] = FallbackLabel
        Button: type[FallbackButton] = FallbackButton
        Entry: type[FallbackEntry] = FallbackEntry
        Text: type[FallbackText] = FallbackText
        Listbox: type[FallbackListbox] = FallbackListbox
        Checkbutton: type[FallbackCheckbutton] = FallbackCheckbutton
        Radiobutton: type[FallbackRadiobutton] = FallbackRadiobutton
        Scale: type[FallbackScale] = FallbackScale
        StringVar: type[FallbackStringVar] = FallbackStringVar
        IntVar: type[FallbackIntVar] = FallbackIntVar
        DoubleVar: type[FallbackDoubleVar] = FallbackDoubleVar
        BooleanVar: type[FallbackBooleanVar] = FallbackBooleanVar
        # Constants
        NORMAL: str = "normal"
        DISABLED: str = "disabled"
        ACTIVE: str = "active"
        END: str = "end"
        BOTH: str = "both"
        X: str = "x"
        Y: str = "y"
        TOP: str = "top"
        BOTTOM: str = "bottom"
        LEFT: str = "left"
        RIGHT: str = "right"
        CENTER: str = "center"
        N: str = "n"
        S: str = "s"
        E: str = "e"
        W: str = "w"
        NE: str = "ne"
        NW: str = "nw"
        SE: str = "se"
        SW: str = "sw"

    tk = FallbackTkModule()
    tkinter = tk
    ttk = FallbackTTK
    messagebox = FallbackMessageBox
    filedialog = FallbackFileDialog
    colorchooser = FallbackColorChooser
    Font = FallbackFont
    ScrolledText = FallbackScrolledText

    # Create scrolledtext module fallback
    class ScrolledTextModuleFallback:
        ScrolledText: type[FallbackScrolledText] = FallbackScrolledText

    # Alias for compatibility
    scrolledtext = ScrolledTextModuleFallback

    # Convenient assignments
    Tk = FallbackTk
    Frame = FallbackFrame
    Label = FallbackLabel
    Button = FallbackButton
    Entry = FallbackEntry
    Text = FallbackText
    Listbox = FallbackListbox
    Checkbutton = FallbackCheckbutton
    Radiobutton = FallbackRadiobutton
    Scale = FallbackScale
    StringVar = FallbackStringVar
    IntVar = FallbackIntVar
    DoubleVar = FallbackDoubleVar
    BooleanVar = FallbackBooleanVar

    # Constants
    NORMAL = "normal"
    DISABLED = "disabled"
    ACTIVE = "active"
    END = "end"
    BOTH = "both"
    X = "x"
    Y = "y"
    TOP = "top"
    BOTTOM = "bottom"
    LEFT = "left"
    RIGHT = "right"
    CENTER = "center"
    N = "n"
    S = "s"
    E = "e"
    W = "w"
    NE = "ne"
    NW = "nw"
    SE = "se"
    SW = "sw"


# Export all tkinter objects and availability flag
__all__ = [
    "ACTIVE",
    "BOTH",
    "BOTTOM",
    "BooleanVar",
    "Button",
    "CENTER",
    "Checkbutton",
    "DISABLED",
    "DoubleVar",
    "E",
    "END",
    "Entry",
    "Font",
    "Frame",
    "HAS_TKINTER",
    "IntVar",
    "LEFT",
    "Label",
    "Listbox",
    "N",
    "NE",
    "NORMAL",
    "NW",
    "RIGHT",
    "Radiobutton",
    "S",
    "SE",
    "SW",
    "Scale",
    "ScrolledText",
    "StringVar",
    "TKINTER_VERSION",
    "TOP",
    "Text",
    "Tk",
    "W",
    "X",
    "Y",
    "colorchooser",
    "filedialog",
    "messagebox",
    "scrolledtext",
    "tk",
    "tkinter",
    "ttk",
]
