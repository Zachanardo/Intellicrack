#!/usr/bin/env python3
"""
Terminal-based Hex Viewer with ncurses - Advanced hex editing capabilities for CLI

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import curses
import os
import sys
import time
from typing import Optional, List, Tuple, Dict, Any

try:
    import mmap
    MMAP_AVAILABLE = True
except ImportError:
    MMAP_AVAILABLE = False


class TerminalHexViewer:
    """Advanced terminal-based hex viewer using ncurses."""
    
    def __init__(self, filepath: str):
        """Initialize hex viewer with file path.
        
        Args:
            filepath: Path to file to view/edit
        """
        self.filepath = filepath
        self.file_size = 0
        self.data = None
        self.mmap_file = None
        self.file_handle = None
        
        # Display settings
        self.bytes_per_line = 16
        self.current_offset = 0
        self.cursor_offset = 0
        self.edit_mode = False
        self.hex_edit_mode = True  # True for hex, False for ASCII
        self.modified = False
        self.modifications = {}  # offset -> new_byte mapping
        
        # Search functionality
        self.search_pattern = ""
        self.search_results = []
        self.current_search_index = 0
        
        # Display state
        self.screen_height = 0
        self.screen_width = 0
        self.hex_area_height = 0
        self.status_line = 0
        self.help_visible = False
        
        # Color pairs
        self.colors = {
            'normal': 1,
            'cursor': 2,
            'modified': 3,
            'search': 4,
            'ascii': 5,
            'status': 6,
            'help': 7
        }
        
        self._load_file()
    
    def _load_file(self):
        """Load file data using memory mapping when possible."""
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"File not found: {self.filepath}")
        
        self.file_size = os.path.getsize(self.filepath)
        
        try:
            self.file_handle = open(self.filepath, 'r+b')
            if MMAP_AVAILABLE and self.file_size > 0:
                # Use memory mapping for efficient large file handling
                self.mmap_file = mmap.mmap(self.file_handle.fileno(), 0)
                self.data = self.mmap_file
            else:
                # Fallback to reading entire file
                with self.file_handle:
                    self.data = self.file_handle.read()
                self.file_handle = None
        except IOError as e:
            # Try read-only mode
            try:
                with open(self.filepath, 'rb') as f:
                    self.data = f.read()
                self.file_handle = None
            except IOError:
                raise IOError(f"Cannot open file: {e}")
    
    def _setup_colors(self):
        """Setup color pairs for the interface."""
        if not curses.has_colors():
            return
            
        curses.start_color()
        curses.use_default_colors()
        
        # Define color pairs
        curses.init_pair(self.colors['normal'], curses.COLOR_WHITE, -1)
        curses.init_pair(self.colors['cursor'], curses.COLOR_BLACK, curses.COLOR_YELLOW)
        curses.init_pair(self.colors['modified'], curses.COLOR_RED, -1)
        curses.init_pair(self.colors['search'], curses.COLOR_BLACK, curses.COLOR_GREEN)
        curses.init_pair(self.colors['ascii'], curses.COLOR_CYAN, -1)
        curses.init_pair(self.colors['status'], curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(self.colors['help'], curses.COLOR_YELLOW, curses.COLOR_BLACK)
    
    def run(self, stdscr):
        """Main application loop."""
        self.stdscr = stdscr
        self._setup_colors()
        
        # Configure curses
        curses.curs_set(0)  # Hide cursor
        stdscr.keypad(True)
        stdscr.timeout(100)  # Non-blocking input
        
        try:
            while True:
                self._update_screen_dimensions()
                self._draw_interface()
                
                key = stdscr.getch()
                if key == -1:  # No input
                    continue
                    
                if not self._handle_input(key):
                    break  # Exit requested
                    
        except KeyboardInterrupt:
            pass
        finally:
            self._cleanup()
    
    def _update_screen_dimensions(self):
        """Update screen dimensions and layout."""
        self.screen_height, self.screen_width = self.stdscr.getmaxyx()
        self.hex_area_height = self.screen_height - 3  # Leave room for status and help
        self.status_line = self.screen_height - 2
    
    def _draw_interface(self):
        """Draw the complete hex viewer interface."""
        self.stdscr.clear()
        
        if self.help_visible:
            self._draw_help()
        else:
            self._draw_hex_area()
            self._draw_status_line()
            self._draw_info_line()
        
        self.stdscr.refresh()
    
    def _draw_hex_area(self):
        """Draw the main hex viewing area."""
        lines_to_show = min(self.hex_area_height, 
                           (self.file_size - self.current_offset + self.bytes_per_line - 1) // self.bytes_per_line)
        
        for line_idx in range(lines_to_show):
            offset = self.current_offset + (line_idx * self.bytes_per_line)
            if offset >= self.file_size:
                break
                
            self._draw_hex_line(line_idx, offset)
    
    def _draw_hex_line(self, line_idx: int, offset: int):
        """Draw a single line of hex data."""
        y = line_idx
        
        # Draw offset
        offset_str = f"{offset:08X}"
        self.stdscr.addstr(y, 0, offset_str, curses.color_pair(self.colors['normal']))
        
        # Draw hex bytes
        hex_x = 10
        ascii_x = hex_x + (self.bytes_per_line * 3) + 2
        ascii_line = ""
        
        for byte_idx in range(self.bytes_per_line):
            byte_offset = offset + byte_idx
            if byte_offset >= self.file_size:
                break
                
            # Get byte value (check for modifications first)
            if byte_offset in self.modifications:
                byte_val = self.modifications[byte_offset]
                color = self.colors['modified']
            else:
                byte_val = self.data[byte_offset]
                color = self.colors['normal']
            
            # Highlight cursor position
            if byte_offset == self.cursor_offset:
                if self.edit_mode:
                    color = self.colors['cursor']
                else:
                    color = self.colors['search']
            
            # Highlight search results
            elif byte_offset in [r[0] for r in self.search_results]:
                color = self.colors['search']
            
            # Draw hex representation
            hex_str = f"{byte_val:02X}"
            hex_pos = hex_x + (byte_idx * 3)
            
            if hex_pos + 2 < self.screen_width:
                self.stdscr.addstr(y, hex_pos, hex_str, curses.color_pair(color))
            
            # Prepare ASCII representation
            if 32 <= byte_val <= 126:
                ascii_char = chr(byte_val)
            else:
                ascii_char = '.'
            ascii_line += ascii_char
        
        # Draw ASCII representation
        if ascii_x < self.screen_width:
            ascii_display = ascii_line[:self.screen_width - ascii_x]
            self.stdscr.addstr(y, ascii_x, ascii_display, curses.color_pair(self.colors['ascii']))
    
    def _draw_status_line(self):
        """Draw status line with current information."""
        if self.status_line >= self.screen_height:
            return
            
        # Prepare status information
        mode_str = "EDIT" if self.edit_mode else "VIEW"
        edit_type = "HEX" if self.hex_edit_mode else "ASCII"
        modified_str = "*" if self.modified else ""
        
        status = f" {mode_str}({edit_type}) | Offset: 0x{self.cursor_offset:08X} | "
        status += f"Size: {self.file_size} bytes | File: {os.path.basename(self.filepath)}{modified_str}"
        
        # Truncate if too long
        if len(status) > self.screen_width:
            status = status[:self.screen_width-3] + "..."
        
        # Pad to full width
        status = status.ljust(self.screen_width)
        
        try:
            self.stdscr.addstr(self.status_line, 0, status, 
                             curses.color_pair(self.colors['status']) | curses.A_BOLD)
        except curses.error:
            pass
    
    def _draw_info_line(self):
        """Draw information/help line."""
        info_line = self.status_line + 1
        if info_line >= self.screen_height:
            return
            
        if self.edit_mode:
            help_text = " ESC:Exit Edit | ENTER:Apply | TAB:Hex/ASCII | F1:Help "
        else:
            help_text = " q:Quit | e:Edit | /:Search | n:Next | p:Prev | g:Goto | F1:Help "
        
        help_text = help_text.ljust(self.screen_width)
        
        try:
            self.stdscr.addstr(info_line, 0, help_text, curses.color_pair(self.colors['help']))
        except curses.error:
            pass
    
    def _draw_help(self):
        """Draw help screen."""
        help_lines = [
            "Intellicrack Terminal Hex Viewer - Help",
            "",
            "Navigation:",
            "  Arrow Keys    - Move cursor",
            "  Page Up/Down  - Scroll by page",
            "  Home/End      - Go to start/end of file",
            "  g             - Go to specific offset",
            "",
            "Viewing:",
            "  /             - Search for hex pattern",
            "  n             - Next search result",
            "  p             - Previous search result",
            "",
            "Editing:",
            "  e             - Enter edit mode",
            "  ESC           - Exit edit mode",
            "  TAB           - Toggle hex/ASCII editing",
            "  ENTER         - Apply changes",
            "",
            "File Operations:",
            "  s             - Save changes",
            "  q             - Quit (prompts if modified)",
            "",
            "Other:",
            "  F1            - Toggle this help",
            "  r             - Refresh display",
            "",
            "Press any key to continue..."
        ]
        
        start_y = max(0, (self.screen_height - len(help_lines)) // 2)
        
        for i, line in enumerate(help_lines):
            y = start_y + i
            if y >= self.screen_height:
                break
                
            x = max(0, (self.screen_width - len(line)) // 2)
            try:
                self.stdscr.addstr(y, x, line, curses.color_pair(self.colors['help']))
            except curses.error:
                pass
    
    def _handle_input(self, key: int) -> bool:
        """Handle keyboard input. Returns False to exit."""
        if self.help_visible:
            self.help_visible = False
            return True
        
        if self.edit_mode:
            return self._handle_edit_input(key)
        else:
            return self._handle_view_input(key)
    
    def _handle_view_input(self, key: int) -> bool:
        """Handle input in view mode."""
        if key == ord('q'):
            if self.modified:
                # TODO: Add confirmation dialog
                pass
            return False
        
        elif key == ord('e'):
            self.edit_mode = True
            
        elif key == curses.KEY_F1:
            self.help_visible = True
            
        elif key == ord('/'):
            self._start_search()
            
        elif key == ord('n'):
            self._next_search_result()
            
        elif key == ord('p'):
            self._prev_search_result()
            
        elif key == ord('g'):
            self._goto_offset()
            
        elif key == ord('r'):
            pass  # Refresh (already done each loop)
            
        elif key == ord('s'):
            self._save_changes()
            
        # Navigation
        elif key == curses.KEY_UP:
            self._move_cursor(-self.bytes_per_line)
        elif key == curses.KEY_DOWN:
            self._move_cursor(self.bytes_per_line)
        elif key == curses.KEY_LEFT:
            self._move_cursor(-1)
        elif key == curses.KEY_RIGHT:
            self._move_cursor(1)
        elif key == curses.KEY_PPAGE:
            self._move_cursor(-self.hex_area_height * self.bytes_per_line)
        elif key == curses.KEY_NPAGE:
            self._move_cursor(self.hex_area_height * self.bytes_per_line)
        elif key == curses.KEY_HOME:
            self.cursor_offset = 0
            self.current_offset = 0
        elif key == curses.KEY_END:
            self.cursor_offset = max(0, self.file_size - 1)
            self._adjust_display()
        
        return True
    
    def _handle_edit_input(self, key: int) -> bool:
        """Handle input in edit mode."""
        if key == 27:  # ESC
            self.edit_mode = False
            
        elif key == ord('\t'):  # TAB
            self.hex_edit_mode = not self.hex_edit_mode
            
        elif key == ord('\n') or key == ord('\r'):  # ENTER
            self.edit_mode = False
            
        elif key == curses.KEY_F1:
            self.help_visible = True
            
        # Navigation (same as view mode)
        elif key == curses.KEY_UP:
            self._move_cursor(-self.bytes_per_line)
        elif key == curses.KEY_DOWN:
            self._move_cursor(self.bytes_per_line)
        elif key == curses.KEY_LEFT:
            self._move_cursor(-1)
        elif key == curses.KEY_RIGHT:
            self._move_cursor(1)
            
        # Edit input
        else:
            self._handle_edit_character(key)
        
        return True
    
    def _handle_edit_character(self, key: int):
        """Handle character input during editing."""
        if self.cursor_offset >= self.file_size:
            return
            
        if self.hex_edit_mode:
            # Hex editing
            if 48 <= key <= 57:  # 0-9
                digit = key - 48
                self._edit_hex_digit(digit)
            elif 65 <= key <= 70:  # A-F
                digit = key - 65 + 10
                self._edit_hex_digit(digit)
            elif 97 <= key <= 102:  # a-f
                digit = key - 97 + 10
                self._edit_hex_digit(digit)
        else:
            # ASCII editing
            if 32 <= key <= 126:  # Printable ASCII
                self.modifications[self.cursor_offset] = key
                self.modified = True
                self._move_cursor(1)
    
    def _edit_hex_digit(self, digit: int):
        """Edit a single hex digit."""
        current_byte = self.modifications.get(self.cursor_offset, self.data[self.cursor_offset])
        
        # For simplicity, replace the entire byte
        # In a full implementation, you might want to edit nibbles
        new_byte = (digit << 4) | (current_byte & 0x0F)
        self.modifications[self.cursor_offset] = new_byte
        self.modified = True
        self._move_cursor(1)
    
    def _move_cursor(self, delta: int):
        """Move cursor by delta bytes."""
        new_offset = max(0, min(self.file_size - 1, self.cursor_offset + delta))
        self.cursor_offset = new_offset
        self._adjust_display()
    
    def _adjust_display(self):
        """Adjust display offset to keep cursor visible."""
        lines_per_screen = self.hex_area_height
        bytes_per_screen = lines_per_screen * self.bytes_per_line
        
        # Check if cursor is above visible area
        if self.cursor_offset < self.current_offset:
            self.current_offset = (self.cursor_offset // self.bytes_per_line) * self.bytes_per_line
        
        # Check if cursor is below visible area
        elif self.cursor_offset >= self.current_offset + bytes_per_screen:
            self.current_offset = ((self.cursor_offset - bytes_per_screen + self.bytes_per_line) 
                                 // self.bytes_per_line) * self.bytes_per_line
            self.current_offset = max(0, self.current_offset)
    
    def _start_search(self):
        """Start search functionality (simplified)."""
        # In a full implementation, this would show an input dialog
        # For now, just search for a pattern
        self.search_pattern = "4D5A"  # Example: MZ header
        self._perform_search()
    
    def _perform_search(self):
        """Perform search for current pattern."""
        if not self.search_pattern:
            return
            
        self.search_results = []
        
        try:
            # Convert hex pattern to bytes
            pattern_bytes = bytes.fromhex(self.search_pattern)
            
            # Search through data
            search_start = 0
            while True:
                if hasattr(self.data, 'find'):
                    pos = self.data.find(pattern_bytes, search_start)
                else:
                    # Fallback for non-mmap data
                    try:
                        pos = self.data.index(pattern_bytes, search_start)
                    except ValueError:
                        pos = -1
                
                if pos == -1:
                    break
                    
                self.search_results.append((pos, len(pattern_bytes)))
                search_start = pos + 1
                
        except ValueError:
            # Invalid hex pattern
            pass
        
        if self.search_results:
            self.current_search_index = 0
            self._goto_search_result(0)
    
    def _next_search_result(self):
        """Go to next search result."""
        if not self.search_results:
            return
            
        self.current_search_index = (self.current_search_index + 1) % len(self.search_results)
        self._goto_search_result(self.current_search_index)
    
    def _prev_search_result(self):
        """Go to previous search result."""
        if not self.search_results:
            return
            
        self.current_search_index = (self.current_search_index - 1) % len(self.search_results)
        self._goto_search_result(self.current_search_index)
    
    def _goto_search_result(self, index: int):
        """Go to specific search result."""
        if 0 <= index < len(self.search_results):
            offset, length = self.search_results[index]
            self.cursor_offset = offset
            self._adjust_display()
    
    def _goto_offset(self):
        """Go to specific offset (simplified)."""
        # In a full implementation, this would show an input dialog
        # For now, just go to middle of file
        self.cursor_offset = self.file_size // 2
        self._adjust_display()
    
    def _save_changes(self):
        """Save modifications to file."""
        if not self.modified or not self.modifications:
            return
            
        try:
            if self.mmap_file:
                # Save via memory map
                for offset, byte_val in self.modifications.items():
                    self.mmap_file[offset] = byte_val
                self.mmap_file.flush()
            else:
                # Reopen file and apply changes
                with open(self.filepath, 'r+b') as f:
                    for offset, byte_val in self.modifications.items():
                        f.seek(offset)
                        f.write(bytes([byte_val]))
            
            self.modifications.clear()
            self.modified = False
            
        except IOError:
            # TODO: Show error message
            pass
    
    def _cleanup(self):
        """Clean up resources."""
        if self.mmap_file:
            self.mmap_file.close()
        if self.file_handle:
            self.file_handle.close()


def launch_hex_viewer(filepath: str):
    """Launch the terminal hex viewer.
    
    Args:
        filepath: Path to file to view
    """
    try:
        viewer = TerminalHexViewer(filepath)
        curses.wrapper(viewer.run)
    except Exception as e:
        print(f"Error launching hex viewer: {e}")
        return False
    return True


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: hex_viewer_cli.py <file>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        sys.exit(1)
    
    launch_hex_viewer(filepath)