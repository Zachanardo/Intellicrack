"""Advanced Search and Replace functionality for Hex Viewer.

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

import json
import logging
import re
from enum import Enum
from pathlib import Path
from typing import Any

from ..handlers.pyqt6_handler import (
    PYQT6_AVAILABLE,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QSpinBox,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QThread,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

logger = logging.getLogger(__name__)

__all__ = [
    "AdvancedSearchDialog",
    "FindAllDialog",
    "ReplaceDialog",
    "SearchEngine",
    "SearchHistory",
    "SearchResult",
    "SearchType",
]


class SearchType(Enum):
    """Types of search patterns."""

    HEX = "hex"
    TEXT = "text"
    REGEX = "regex"
    WILDCARD = "wildcard"


class SearchResult:
    """Represents a single search result."""

    def __init__(self, offset: int, length: int, data: bytes, context: bytes = None) -> None:
        """Initialize the SearchResult with offset, length, data, and context."""
        self.offset = offset
        self.length = length
        self.data = data
        self.context = context or b""

    def __str__(self) -> str:
        """Return string representation of the search result."""
        return f"SearchResult(offset=0x{self.offset:X}, length={self.length})"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "offset": self.offset,
            "length": self.length,
            "data": self.data.hex(),
            "context": self.context.hex() if self.context else "",
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SearchResult":
        """Create from dictionary."""
        return cls(
            offset=data["offset"],
            length=data["length"],
            data=bytes.fromhex(data["data"]),
            context=bytes.fromhex(data["context"]) if data["context"] else b"",
        )


class SearchHistory:
    """Manages search history persistence."""

    def __init__(self, max_entries: int = None) -> None:
        """Initialize the SearchHistory with maximum entries limit."""
        # Get configuration instance
        from intellicrack.core.config_manager import get_config
        config = get_config()

        # Use provided max_entries or get from config
        if max_entries is None:
            self.max_entries = config.get("hex_viewer.search.history_max_entries", 50)
        else:
            self.max_entries = max_entries
        self.history_file = Path.home() / ".intellicrack" / "hex_search_history.json"
        self.entries: list[dict[str, Any]] = []
        self.load_history()

    def add_search(self, pattern: str, search_type: SearchType, options: dict[str, Any]) -> None:
        """Add a search to history."""
        entry = {
            "pattern": pattern,
            "type": search_type.value,
            "options": options,
            "timestamp": __import__("time").time(),
        }

        # Remove duplicate if exists
        self.entries = [e for e in self.entries if e["pattern"] != pattern or e["type"] != search_type.value]

        # Add to front
        self.entries.insert(0, entry)

        # Maintain max entries
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[: self.max_entries]

        self.save_history()

    def get_recent_searches(self, search_type: SearchType | None = None, limit: int = 10) -> list[str]:
        """Get recent search patterns."""
        filtered_entries = self.entries
        if search_type:
            filtered_entries = [e for e in self.entries if e["type"] == search_type.value]

        return [e["pattern"] for e in filtered_entries[:limit]]

    def load_history(self) -> None:
        """Load history from file."""
        try:
            if self.history_file.exists():
                with open(self.history_file, encoding="utf-8") as f:
                    data = json.load(f)
                    self.entries = data.get("searches", [])
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Could not load search history: %s", e)
            self.entries = []

    def save_history(self) -> None:
        """Save history to file."""
        try:
            self.history_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump({"searches": self.entries}, f, indent=2)
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Could not save search history: %s", e)


class SearchEngine:
    """Core search engine for finding patterns in binary data."""

    def __init__(self, file_handler) -> None:
        """Initialize the SearchEngine with file handler and chunk size."""
        self.file_handler = file_handler

        # Get configuration instance
        from intellicrack.core.config_manager import get_config
        config = get_config()

        # Get chunk size from config (convert KB to bytes)
        chunk_size_kb = config.get("hex_viewer.search.search_chunk_size_kb", 256)
        self.chunk_size = chunk_size_kb * 1024

    def search(
        self,
        pattern: str | bytes,
        search_type: SearchType,
        start_offset: int = 0,
        case_sensitive: bool = True,
        whole_words: bool = False,
        direction: str = "forward",
    ) -> SearchResult | None:
        """Search for a single occurrence of a pattern.

        Args:
            pattern: Search pattern
            search_type: Type of search
            start_offset: Offset to start searching from
            case_sensitive: Whether search is case sensitive
            whole_words: Whether to match whole words only
            direction: Search direction ("forward" or "backward")

        Returns:
            First search result or None if not found

        """
        compiled_pattern = self._compile_pattern(pattern, search_type, case_sensitive)
        if not compiled_pattern:
            return None

        if direction == "forward":
            return self._search_forward(compiled_pattern, start_offset, whole_words)
        return self._search_backward(compiled_pattern, start_offset, whole_words)

    def search_all(
        self,
        pattern: str | bytes,
        search_type: SearchType,
        case_sensitive: bool = True,
        whole_words: bool = False,
        max_results: int = 1000,
    ) -> list[SearchResult]:
        """Search for all occurrences of a pattern.

        Args:
            pattern: Search pattern
            search_type: Type of search
            case_sensitive: Whether search is case sensitive
            whole_words: Whether to match whole words only
            max_results: Maximum number of results to return

        Returns:
            List of all search results

        """
        compiled_pattern = self._compile_pattern(pattern, search_type, case_sensitive)
        if not compiled_pattern:
            return []

        results = []
        file_size = self.file_handler.get_file_size()
        offset = 0
        overlap_size = len(pattern) if isinstance(pattern, bytes) else len(pattern.encode("utf-8"))

        while offset < file_size and len(results) < max_results:
            chunk_size = min(self.chunk_size, file_size - offset)
            chunk_data = self.file_handler.read(offset, chunk_size)

            if not chunk_data:
                break

            # Find all matches in this chunk
            chunk_results = self._find_matches_in_chunk(
                compiled_pattern,
                chunk_data,
                offset,
                search_type,
                whole_words,
            )

            results.extend(chunk_results)

            # Move to next chunk with overlap
            offset += chunk_size - overlap_size
            if offset <= 0:
                break

        return results[:max_results]

    def replace_all(
        self,
        find_pattern: str | bytes,
        replace_pattern: str | bytes,
        search_type: SearchType,
        case_sensitive: bool = True,
        whole_words: bool = False,
    ) -> list[tuple[int, int]]:
        """Replace all occurrences of a pattern.

        Args:
            find_pattern: Pattern to find
            replace_pattern: Pattern to replace with
            search_type: Type of search
            case_sensitive: Whether search is case sensitive
            whole_words: Whether to match whole words only

        Returns:
            List of (offset, length) tuples for replaced ranges

        """
        if self.file_handler.read_only:
            error_msg = "Cannot replace in read-only file"
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Find all occurrences
        results = self.search_all(find_pattern, search_type, case_sensitive, whole_words)

        if not results:
            return []

        # Convert replace pattern to bytes
        if isinstance(replace_pattern, str):
            replace_bytes = replace_pattern.encode("utf-8")
        else:
            replace_bytes = replace_pattern

        # Replace in reverse order to maintain offsets
        replaced_ranges = []
        for result in reversed(results):
            # Variable-length replacement implementation
            # First delete the old data, then insert the new data
            try:
                # Delete the original data at this offset
                if self.file_handler.delete(result.offset, result.length):
                    # Insert the replacement data at the same offset
                    if self.file_handler.insert(result.offset, replace_bytes):
                        replaced_ranges.append((result.offset, len(replace_bytes)))
                    else:
                        # If insert fails, try to restore the original data
                        # This is a best-effort recovery
                        original_data = self.file_handler.read(result.offset, result.length)
                        if original_data:
                            self.file_handler.insert(result.offset, original_data)
                        error_msg = f"Failed to insert replacement at offset {result.offset:#x}"
                        logger.error(error_msg)
                        raise RuntimeError(error_msg)
            except Exception as e:
                logger.error(f"Error during replace operation at offset {result.offset:#x}: {e}")
                # Continue with other replacements even if one fails
                continue

        return list(reversed(replaced_ranges))

    def _compile_pattern(self, pattern: str | bytes, search_type: SearchType, case_sensitive: bool) -> bytes | re.Pattern | None:
        """Compile pattern based on search type."""
        try:
            if search_type == SearchType.HEX:
                if isinstance(pattern, str):
                    hex_clean = pattern.replace(" ", "").replace("-", "")
                    return bytes.fromhex(hex_clean)
                return pattern

            if search_type == SearchType.TEXT:
                if isinstance(pattern, bytes):
                    text_pattern = pattern
                else:
                    text_pattern = pattern.encode("utf-8")

                if not case_sensitive:
                    # For case-insensitive text search, we'll handle this during matching
                    pass

                return text_pattern

            if search_type == SearchType.REGEX:
                flags = 0 if case_sensitive else re.IGNORECASE
                if isinstance(pattern, bytes):
                    pattern = pattern.decode("utf-8", errors="replace")
                return re.compile(pattern, flags)

            if search_type == SearchType.WILDCARD:
                # Convert wildcard to regex
                if isinstance(pattern, bytes):
                    pattern = pattern.decode("utf-8", errors="replace")

                # Escape special regex characters except * and ?
                escaped = re.escape(pattern)
                # Convert wildcard patterns
                escaped = escaped.replace(r"\*", ".*").replace(r"\?", ".")

                flags = 0 if case_sensitive else re.IGNORECASE
                return re.compile(escaped, flags)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error compiling pattern: %s", e)

        return None

    def _search_forward(self, compiled_pattern: bytes | re.Pattern, start_offset: int, whole_words: bool) -> SearchResult | None:
        """Search forward from ``start_offset``."""
        file_size = self.file_handler.get_file_size()
        offset = start_offset
        overlap_size = 100  # Reasonable overlap for pattern matching

        while offset < file_size:
            chunk_size = min(self.chunk_size, file_size - offset)
            chunk_data = self.file_handler.read(offset, chunk_size)

            if not chunk_data:
                break

            # Find first match in this chunk
            match = self._find_first_match_in_chunk(
                compiled_pattern,
                chunk_data,
                offset,
                whole_words,
            )

            if match:
                return match

            # Move to next chunk with overlap
            offset += chunk_size - overlap_size

        return None

    def _search_backward(self, compiled_pattern: bytes | re.Pattern, start_offset: int, whole_words: bool) -> SearchResult | None:
        """Search backward from ``start_offset``."""
        offset = min(start_offset, self.file_handler.get_file_size())
        overlap_size = 100

        while offset > 0:
            chunk_start = max(0, offset - self.chunk_size)
            chunk_size = offset - chunk_start
            chunk_data = self.file_handler.read(chunk_start, chunk_size)

            if not chunk_data:
                break

            # Find last match in this chunk
            matches = self._find_matches_in_chunk(
                compiled_pattern,
                chunk_data,
                chunk_start,
                SearchType.HEX,
                whole_words,
            )

            if matches:
                return matches[-1]  # Return last match (closest to start_offset)

            # Move to previous chunk with overlap
            offset = chunk_start + overlap_size

        return None

    def _find_matches_in_chunk(
        self,
        compiled_pattern: bytes | re.Pattern,
        chunk_data: bytes,
        chunk_offset: int,
        search_type: SearchType,
        whole_words: bool,
    ) -> list[SearchResult]:
        """Find all matches in a chunk of data."""
        matches = []
        _search_type = search_type  # Store for potential future use

        try:
            if isinstance(compiled_pattern, bytes):
                # Binary pattern search
                pos = 0
                while True:
                    pos = chunk_data.find(compiled_pattern, pos)
                    if pos == -1:
                        break

                    if not whole_words or self._is_whole_word_match(chunk_data, pos, len(compiled_pattern)):
                        # Get context around the match
                        context_start = max(0, pos - 16)
                        context_end = min(len(chunk_data), pos + len(compiled_pattern) + 16)
                        context = chunk_data[context_start:context_end]

                        match = SearchResult(
                            offset=chunk_offset + pos,
                            length=len(compiled_pattern),
                            data=compiled_pattern,
                            context=context,
                        )
                        matches.append(match)

                    pos += 1

            elif isinstance(compiled_pattern, re.Pattern):
                # Regex search
                text_data = chunk_data.decode("utf-8", errors="replace")
                for match in compiled_pattern.finditer(text_data):
                    start_pos = match.start()
                    end_pos = match.end()

                    # Convert character positions to exact byte positions
                    # Get the substring of the decoded text up to the start of the match
                    pre_match_str = text_data[:start_pos]
                    # Encode this substring back to bytes to get the exact byte offset
                    byte_start = len(pre_match_str.encode("utf-8", errors="replace"))

                    # Get the substring of the match itself
                    match_str = text_data[start_pos:end_pos]
                    # Encode the match string to get the exact byte length
                    byte_length = len(match_str.encode("utf-8", errors="replace"))

                    # The end of the match in bytes
                    byte_end = byte_start + byte_length

                    if byte_start < len(chunk_data) and byte_end <= len(chunk_data):
                        matched_data = chunk_data[byte_start:byte_end]

                        # Get context
                        context_start = max(0, byte_start - 16)
                        context_end = min(len(chunk_data), byte_end + 16)
                        context = chunk_data[context_start:context_end]

                        result = SearchResult(
                            offset=chunk_offset + byte_start,
                            length=byte_end - byte_start,
                            data=matched_data,
                            context=context,
                        )
                        matches.append(result)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error finding matches in chunk: %s", e)

        return matches

    def _find_first_match_in_chunk(
        self,
        compiled_pattern: bytes | re.Pattern,
        chunk_data: bytes,
        chunk_offset: int,
        whole_words: bool,
    ) -> SearchResult | None:
        """Find first match in a chunk of data."""
        matches = self._find_matches_in_chunk(
            compiled_pattern,
            chunk_data,
            chunk_offset,
            SearchType.HEX,
            whole_words,
        )
        return matches[0] if matches else None

    def _is_whole_word_match(self, data: bytes, pos: int, length: int) -> bool:
        """Check if a match is a whole word (for text searches).

        A word boundary is defined as:
        - Start/end of data
        - Transition between word and non-word characters
        - Word characters: alphanumeric (a-z, A-Z, 0-9) and underscore (_)
        - Non-word characters: everything else (whitespace, punctuation, control chars, etc.)

        Args:
            data: The data being searched
            pos: Position of the match
            length: Length of the match

        Returns:
            True if the match is a whole word, False otherwise

        """

        def is_word_char(byte_val: int) -> bool:
            """Check if a byte value is a word character.

            Word characters are:
            - a-z (97-122)
            - A-Z (65-90)
            - 0-9 (48-57)
            - underscore (95)
            """
            return (
                (48 <= byte_val <= 57)  # 0-9
                or (65 <= byte_val <= 90)  # A-Z
                or (97 <= byte_val <= 122)  # a-z
                or (byte_val == 95)  # underscore
            )

        # Check if match itself contains only word characters
        match_data = data[pos : pos + length]
        if not all(is_word_char(b) for b in match_data):
            # If the match contains non-word characters, it's not a "word"
            # But we still check boundaries for mixed content
            pass

        # Check left boundary
        if pos > 0:
            prev_char = data[pos - 1]
            first_match_char = data[pos]

            # Both are word characters = not a boundary
            if is_word_char(prev_char) and is_word_char(first_match_char):
                return False

        # Check right boundary
        if pos + length < len(data):
            next_char = data[pos + length]
            last_match_char = data[pos + length - 1]

            # Both are word characters = not a boundary
            if is_word_char(last_match_char) and is_word_char(next_char):
                return False

        # Additional checks for common word boundaries

        # Check for common punctuation boundaries
        if pos > 0:
            prev_char = data[pos - 1]
            # Common word delimiters in binary files
            if prev_char in b"()[]{},\"'`:;!?\\/|<>@#$%^&*+=~\x00\r\n\t ":
                # This is a good word boundary
                pass
            elif is_word_char(prev_char):
                # Previous is a word char, check if current starts a word
                if not is_word_char(data[pos]):
                    # Match doesn't start with word char, might be okay
                    pass
                else:
                    # Both are word chars, not a boundary
                    return False

        if pos + length < len(data):
            next_char = data[pos + length]
            # Common word delimiters
            if next_char in b"()[]{},\"'`:;!?\\/|<>@#$%^&*+=~\x00\r\n\t ":
                # This is a good word boundary
                pass
            elif is_word_char(next_char):
                # Next is a word char, check if match ends with word char
                if not is_word_char(data[pos + length - 1]):
                    # Match doesn't end with word char, might be okay
                    pass
                else:
                    # Both are word chars, not a boundary
                    return False

        return True


class SearchThread(QThread if PYQT6_AVAILABLE else object):
    """Background thread for long-running search operations."""

    #: Signal emitted when search progress updates (type: int)
    progress_updated = pyqtSignal(int) if PYQT6_AVAILABLE else None
    #: Signal emitted when a result is found (type: object)
    result_found = pyqtSignal(object) if PYQT6_AVAILABLE else None
    #: Signal emitted when search is completed (type: list)
    search_completed = pyqtSignal(list) if PYQT6_AVAILABLE else None

    def __init__(
        self,
        search_engine: SearchEngine,
        pattern: str,
        search_type: SearchType,
        find_all: bool = False,
        **kwargs,
    ) -> None:
        """Initialize the SearchThread with search parameters."""
        if PYQT6_AVAILABLE:
            super().__init__()
        self.search_engine = search_engine
        self.pattern = pattern
        self.search_type = search_type
        self.find_all = find_all
        self.kwargs = kwargs
        self.should_stop = False

    def run(self) -> None:
        """Run the search operation."""
        try:
            if self.find_all:
                results = self.search_engine.search_all(
                    self.pattern,
                    self.search_type,
                    **self.kwargs,
                )
                if self.search_completed:
                    self.search_completed.emit(results)
            else:
                result = self.search_engine.search(
                    self.pattern,
                    self.search_type,
                    **self.kwargs,
                )
                if result and self.result_found:
                    self.result_found.emit(result)
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Search thread error: %s", e)

    def stop(self) -> None:
        """Stop the search operation."""
        self.should_stop = True


class AdvancedSearchDialog(QDialog if PYQT6_AVAILABLE else object):
    """Advanced search dialog with comprehensive search options."""

    def __init__(self, parent=None, search_engine: SearchEngine = None) -> None:
        """Initialize the advanced search dialog with parent widget and search engine."""
        if not PYQT6_AVAILABLE:
            return

        super().__init__(parent)
        self.search_engine = search_engine
        self.search_history = SearchHistory()
        self.current_search_thread = None

        # Initialize UI attributes
        self.search_pattern_combo = None
        self.search_type_combo = None
        self.case_sensitive_check = None
        self.whole_words_check = None
        self.direction_group = None
        self.forward_radio = None
        self.backward_radio = None
        self.find_next_button = None
        self.find_previous_button = None
        self.search_status_label = None
        self.find_pattern_combo = None
        self.replace_pattern_edit = None
        self.replace_type_combo = None
        self.replace_case_sensitive_check = None
        self.replace_whole_words_check = None
        self.replace_button = None
        self.replace_all_button = None
        self.replace_status_label = None
        self.find_all_pattern_combo = None
        self.find_all_type_combo = None
        self.max_results_spin = None
        self.find_all_button = None
        self.cancel_search_button = None
        self.search_progress = None
        self.results_table = None
        self.history_list = None
        self.use_history_button = None
        self.clear_history_button = None

        self.setWindowTitle("Advanced Search")
        self.setModal(False)
        self.resize(600, 500)

        self.setup_ui()
        self.load_recent_searches()

    def setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)

        # Create tab widget
        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)

        # Search tab
        search_tab = self.create_search_tab()
        tab_widget.addTab(search_tab, "Search")

        # Replace tab
        replace_tab = self.create_replace_tab()
        tab_widget.addTab(replace_tab, "Replace")

        # Find All tab
        find_all_tab = self.create_find_all_tab()
        tab_widget.addTab(find_all_tab, "Find All")

        # History tab
        history_tab = self.create_history_tab()
        tab_widget.addTab(history_tab, "History")

        # Button box
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(self.close)
        layout.addWidget(button_box)

    def create_search_tab(self) -> QWidget:
        """Create the search tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Search input
        search_group = QGroupBox("Search Pattern")
        search_layout = QFormLayout(search_group)

        self.search_pattern_combo = QComboBox()
        self.search_pattern_combo.setEditable(True)
        search_layout.addRow("Pattern:", self.search_pattern_combo)

        self.search_type_combo = QComboBox()
        self.search_type_combo.addItems(["Hex", "Text", "Regex", "Wildcard"])
        search_layout.addRow("Type:", self.search_type_combo)

        layout.addWidget(search_group)

        # Search options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout(options_group)

        self.case_sensitive_check = QCheckBox("Case sensitive")
        options_layout.addWidget(self.case_sensitive_check)

        self.whole_words_check = QCheckBox("Match whole words only")
        options_layout.addWidget(self.whole_words_check)

        # Direction
        direction_layout = QHBoxLayout()
        self.direction_group = QButtonGroup()

        self.forward_radio = QRadioButton("Forward")
        self.forward_radio.setChecked(True)
        self.direction_group.addButton(self.forward_radio)
        direction_layout.addWidget(self.forward_radio)

        self.backward_radio = QRadioButton("Backward")
        self.direction_group.addButton(self.backward_radio)
        direction_layout.addWidget(self.backward_radio)

        options_layout.addLayout(direction_layout)
        layout.addWidget(options_group)

        # Search controls
        controls_layout = QHBoxLayout()

        self.find_next_button = QPushButton("Find Next")
        self.find_next_button.clicked.connect(self.find_next)
        controls_layout.addWidget(self.find_next_button)

        self.find_previous_button = QPushButton("Find Previous")
        self.find_previous_button.clicked.connect(self.find_previous)
        controls_layout.addWidget(self.find_previous_button)

        controls_layout.addStretch()
        layout.addLayout(controls_layout)

        # Status
        self.search_status_label = QLabel("Ready")
        layout.addWidget(self.search_status_label)

        layout.addStretch()
        return tab

    def create_replace_tab(self) -> QWidget:
        """Create the replace tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Find/Replace input
        replace_group = QGroupBox("Find and Replace")
        replace_layout = QFormLayout(replace_group)

        self.find_pattern_combo = QComboBox()
        self.find_pattern_combo.setEditable(True)
        replace_layout.addRow("Find:", self.find_pattern_combo)

        self.replace_pattern_edit = QLineEdit()
        replace_layout.addRow("Replace:", self.replace_pattern_edit)

        self.replace_type_combo = QComboBox()
        self.replace_type_combo.addItems(["Hex", "Text", "Regex"])
        replace_layout.addRow("Type:", self.replace_type_combo)

        layout.addWidget(replace_group)

        # Replace options
        replace_options_group = QGroupBox("Options")
        replace_options_layout = QVBoxLayout(replace_options_group)

        self.replace_case_sensitive_check = QCheckBox("Case sensitive")
        replace_options_layout.addWidget(self.replace_case_sensitive_check)

        self.replace_whole_words_check = QCheckBox("Match whole words only")
        replace_options_layout.addWidget(self.replace_whole_words_check)

        layout.addWidget(replace_options_group)

        # Replace controls
        replace_controls_layout = QHBoxLayout()

        self.replace_button = QPushButton("Replace")
        self.replace_button.clicked.connect(self.replace_current)
        replace_controls_layout.addWidget(self.replace_button)

        self.replace_all_button = QPushButton("Replace All")
        self.replace_all_button.clicked.connect(self.replace_all)
        replace_controls_layout.addWidget(self.replace_all_button)

        replace_controls_layout.addStretch()
        layout.addLayout(replace_controls_layout)

        # Replace status
        self.replace_status_label = QLabel("Ready")
        layout.addWidget(self.replace_status_label)

        layout.addStretch()
        return tab

    def create_find_all_tab(self) -> QWidget:
        """Create the find all tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Find All input
        find_all_group = QGroupBox("Find All Occurrences")
        find_all_layout = QFormLayout(find_all_group)

        self.find_all_pattern_combo = QComboBox()
        self.find_all_pattern_combo.setEditable(True)
        find_all_layout.addRow("Pattern:", self.find_all_pattern_combo)

        self.find_all_type_combo = QComboBox()
        self.find_all_type_combo.addItems(["Hex", "Text", "Regex", "Wildcard"])
        find_all_layout.addRow("Type:", self.find_all_type_combo)

        self.max_results_spin = QSpinBox()
        self.max_results_spin.setRange(1, 10000)
        self.max_results_spin.setValue(1000)
        find_all_layout.addRow("Max Results:", self.max_results_spin)

        layout.addWidget(find_all_group)

        # Find All controls
        find_all_controls_layout = QHBoxLayout()

        self.find_all_button = QPushButton("Find All")
        self.find_all_button.clicked.connect(self.find_all)
        find_all_controls_layout.addWidget(self.find_all_button)

        self.cancel_search_button = QPushButton("Cancel")
        self.cancel_search_button.clicked.connect(self.cancel_search)
        self.cancel_search_button.setEnabled(False)
        find_all_controls_layout.addWidget(self.cancel_search_button)

        find_all_controls_layout.addStretch()
        layout.addLayout(find_all_controls_layout)

        # Progress bar
        self.search_progress = QProgressBar()
        self.search_progress.setVisible(False)
        layout.addWidget(self.search_progress)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Offset", "Length", "Data", "Context"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.results_table)

        return tab

    def create_history_tab(self) -> QWidget:
        """Create the search history tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # History list
        history_group = QGroupBox("Search History")
        history_layout = QVBoxLayout(history_group)

        self.history_list = QListWidget()
        self.history_list.itemDoubleClicked.connect(self.use_history_item)
        history_layout.addWidget(self.history_list)

        # History controls
        history_controls_layout = QHBoxLayout()

        self.use_history_button = QPushButton("Use Selected")
        self.use_history_button.clicked.connect(self.use_selected_history)
        history_controls_layout.addWidget(self.use_history_button)

        self.clear_history_button = QPushButton("Clear History")
        self.clear_history_button.clicked.connect(self.clear_history)
        history_controls_layout.addWidget(self.clear_history_button)

        history_controls_layout.addStretch()
        history_layout.addLayout(history_controls_layout)

        layout.addWidget(history_group)
        return tab

    def load_recent_searches(self) -> None:
        """Load recent searches into combo boxes."""
        recent_searches = self.search_history.get_recent_searches(limit=10)

        for combo in [
            self.search_pattern_combo,
            self.find_pattern_combo,
            self.find_all_pattern_combo,
        ]:
            combo.clear()
            combo.addItems(recent_searches)
            combo.setCurrentText("")

        self.update_history_list()

    def update_history_list(self) -> None:
        """Update the history list widget."""
        self.history_list.clear()

        for entry in self.search_history.entries[:20]:  # Show last 20
            item_text = f"{entry['pattern']} ({entry['type']})"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, entry)
            self.history_list.addItem(item)

    def find_next(self) -> None:
        """Find next occurrence."""
        pattern = self.search_pattern_combo.currentText()
        if not pattern:
            return

        search_type = self._get_search_type(self.search_type_combo.currentText())

        # Add to history
        options = {
            "case_sensitive": self.case_sensitive_check.isChecked(),
            "whole_words": self.whole_words_check.isChecked(),
            "direction": "forward",
        }
        self.search_history.add_search(pattern, search_type, options)

        # Perform search
        if self.search_engine:
            try:
                result = self.search_engine.search(
                    pattern,
                    search_type,
                    case_sensitive=options["case_sensitive"],
                    whole_words=options["whole_words"],
                    direction="forward",
                )

                if result:
                    self.search_status_label.setText(f"Found at offset 0x{result.offset:X}")
                    # Emit signal to parent to highlight result
                    self.parent().hex_viewer.select_range(result.offset, result.offset + result.length)
                else:
                    self.search_status_label.setText("Pattern not found")

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in advanced_search: %s", e)
                self.search_status_label.setText(f"Search error: {e}")

    def find_previous(self) -> None:
        """Find previous occurrence."""
        pattern = self.search_pattern_combo.currentText()
        if not pattern:
            return

        search_type = self._get_search_type(self.search_type_combo.currentText())

        # Perform search
        if self.search_engine:
            try:
                result = self.search_engine.search(
                    pattern,
                    search_type,
                    case_sensitive=self.case_sensitive_check.isChecked(),
                    whole_words=self.whole_words_check.isChecked(),
                    direction="backward",
                )

                if result:
                    self.search_status_label.setText(f"Found at offset 0x{result.offset:X}")
                    # Emit signal to parent to highlight result
                    self.parent().hex_viewer.select_range(result.offset, result.offset + result.length)
                else:
                    self.search_status_label.setText("Pattern not found")

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in advanced_search: %s", e)
                self.search_status_label.setText(f"Search error: {e}")

    def replace_current(self) -> None:
        """Replace current selection."""
        # Implementation depends on hex viewer integration
        self.replace_status_label.setText("Replace functionality requires hex viewer integration")

    def replace_all(self) -> None:
        """Replace all occurrences."""
        find_pattern = self.find_pattern_combo.currentText()
        replace_pattern = self.replace_pattern_edit.text()

        if not find_pattern:
            return

        search_type = self._get_search_type(self.replace_type_combo.currentText())

        if self.search_engine:
            try:
                replaced_ranges = self.search_engine.replace_all(
                    find_pattern,
                    replace_pattern,
                    search_type,
                    case_sensitive=self.replace_case_sensitive_check.isChecked(),
                    whole_words=self.replace_whole_words_check.isChecked(),
                )

                self.replace_status_label.setText(f"Replaced {len(replaced_ranges)} occurrences")

            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error("Error in advanced_search: %s", e)
                self.replace_status_label.setText(f"Replace error: {e}")

    def find_all(self) -> None:
        """Find all occurrences."""
        pattern = self.find_all_pattern_combo.currentText()
        if not pattern:
            return

        search_type = self._get_search_type(self.find_all_type_combo.currentText())
        max_results = self.max_results_spin.value()

        # Clear previous results
        self.results_table.setRowCount(0)
        self.search_progress.setVisible(True)
        self.find_all_button.setEnabled(False)
        self.cancel_search_button.setEnabled(True)

        # Start search thread
        self.current_search_thread = SearchThread(
            self.search_engine,
            pattern,
            search_type,
            find_all=True,
            max_results=max_results,
        )

        if self.current_search_thread.search_completed:
            self.current_search_thread.search_completed.connect(self.on_find_all_completed)
        self.current_search_thread.start()

    def on_find_all_completed(self, results: list[SearchResult]) -> None:
        """Handle find all completion."""
        self.search_progress.setVisible(False)
        self.find_all_button.setEnabled(True)
        self.cancel_search_button.setEnabled(False)

        # Populate results table
        self.results_table.setRowCount(len(results))

        for i, result in enumerate(results):
            self.results_table.setItem(i, 0, QTableWidgetItem(f"0x{result.offset:X}"))
            self.results_table.setItem(i, 1, QTableWidgetItem(str(result.length)))
            self.results_table.setItem(i, 2, QTableWidgetItem(result.data.hex(" ")[:32] + "..."))
            self.results_table.setItem(i, 3, QTableWidgetItem(result.context.hex(" ")[:48] + "..."))

    def cancel_search(self) -> None:
        """Cancel current search."""
        if self.current_search_thread:
            self.current_search_thread.stop()
            self.current_search_thread.wait()

        self.search_progress.setVisible(False)
        self.find_all_button.setEnabled(True)
        self.cancel_search_button.setEnabled(False)

    def use_history_item(self, item: QListWidgetItem) -> None:
        """Use selected history item."""
        entry = item.data(Qt.UserRole)
        if entry:
            self.search_pattern_combo.setCurrentText(entry["pattern"])
            type_index = self.search_type_combo.findText(entry["type"].title())
            if type_index >= 0:
                self.search_type_combo.setCurrentIndex(type_index)

    def use_selected_history(self) -> None:
        """Use currently selected history item."""
        current_item = self.history_list.currentItem()
        if current_item:
            self.use_history_item(current_item)

    def clear_history(self) -> None:
        """Clear search history."""
        reply = QMessageBox.question(
            self,
            "Clear History",
            "Are you sure you want to clear the search history?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            self.search_history.entries.clear()
            self.search_history.save_history()
            self.update_history_list()

    def _get_search_type(self, type_str: str) -> SearchType:
        """Convert string to SearchType enum."""
        type_map = {
            "Hex": SearchType.HEX,
            "Text": SearchType.TEXT,
            "Regex": SearchType.REGEX,
            "Wildcard": SearchType.WILDCARD,
        }
        return type_map.get(type_str, SearchType.HEX)


class FindAllDialog(QDialog):
    """Dialog for displaying find all results."""

    def __init__(self, parent=None, results=None) -> None:
        """Initialize find all dialog."""
        super().__init__(parent)
        self.results = results or []
        self.setWindowTitle("Find All Results")
        self.setMinimumSize(800, 600)
        self.setup_ui()

    def setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        # Results info
        info_label = QLabel(f"Found {len(self.results)} matches")
        layout.addWidget(info_label)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Offset", "Hex", "ASCII", "Context"])
        self.results_table.horizontalHeader().setStretchLastSection(True)

        # Populate results
        self.results_table.setRowCount(len(self.results))
        for i, result in enumerate(self.results):
            self.results_table.setItem(i, 0, QTableWidgetItem(f"0x{result.offset:08X}"))
            self.results_table.setItem(i, 1, QTableWidgetItem(result.data.hex() if result.data else ""))
            ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in result.data) if result.data else ""
            self.results_table.setItem(i, 2, QTableWidgetItem(ascii_text))
            self.results_table.setItem(
                i,
                3,
                QTableWidgetItem(str(result.context_before) + " [MATCH] " + str(result.context_after)),
            )

        layout.addWidget(self.results_table)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(self.accept)
        layout.addWidget(button_box)


class ReplaceDialog(QDialog):
    """Dialog for replace operations."""

    def __init__(self, parent=None) -> None:
        """Initialize replace dialog."""
        super().__init__(parent)
        self.setWindowTitle("Replace")
        self.setMinimumSize(500, 300)
        self.setup_ui()

    def setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        # Find pattern
        find_group = QGroupBox("Find")
        find_layout = QFormLayout(find_group)

        self.find_pattern = QLineEdit()
        find_layout.addRow("Pattern:", self.find_pattern)

        self.find_type = QComboBox()
        self.find_type.addItems(["Hex", "Text"])
        find_layout.addRow("Type:", self.find_type)

        layout.addWidget(find_group)

        # Replace pattern
        replace_group = QGroupBox("Replace")
        replace_layout = QFormLayout(replace_group)

        self.replace_pattern = QLineEdit()
        replace_layout.addRow("Pattern:", self.replace_pattern)

        layout.addWidget(replace_group)

        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout(options_group)

        self.case_sensitive = QCheckBox("Case sensitive")
        options_layout.addWidget(self.case_sensitive)

        self.replace_all = QCheckBox("Replace all occurrences")
        options_layout.addWidget(self.replace_all)

        layout.addWidget(options_group)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
