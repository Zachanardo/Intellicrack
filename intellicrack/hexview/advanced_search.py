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

from __future__ import annotations

import json
import logging
import re
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

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


if TYPE_CHECKING:
    from re import Match, Pattern


logger = logging.getLogger(__name__)

__all__ = [
    "AdvancedSearchDialog",
    "BaseFileHandler",
    "FindAllDialog",
    "ReplaceDialog",
    "SearchEngine",
    "SearchHistory",
    "SearchResult",
    "SearchType",
]


class BaseFileHandler:
    """Base file handler class providing default implementations for SearchEngine.

    This class provides a concrete implementation that can be used directly
    or subclassed for specific file handling needs.
    """

    def __init__(self, file_path: Path | str | None = None) -> None:
        """Initialize the file handler with optional file path."""
        self.read_only: bool = True
        self._file_path: Path | None = Path(file_path) if file_path else None
        self._data: bytes = b""
        self._file_size: int = 0
        if self._file_path and self._file_path.exists():
            self._load_file()

    def _load_file(self) -> None:
        """Load file data into memory."""
        if self._file_path and self._file_path.exists():
            with open(self._file_path, "rb") as f:
                self._data = f.read()
            self._file_size = len(self._data)

    def get_file_size(self) -> int:
        """Get the total size of the file in bytes."""
        return self._file_size

    def read(self, offset: int, size: int) -> bytes:
        """Read data from the file at the given offset."""
        if offset < 0 or offset >= self._file_size:
            return b""
        end_offset = min(offset + size, self._file_size)
        return self._data[offset:end_offset]

    def delete(self, offset: int, length: int) -> bool:
        """Delete data from the file at the given offset."""
        if self.read_only:
            return False
        if offset < 0 or offset >= self._file_size:
            return False
        end_offset = min(offset + length, self._file_size)
        self._data = self._data[:offset] + self._data[end_offset:]
        self._file_size = len(self._data)
        return True

    def insert(self, offset: int, data: bytes) -> bool:
        """Insert data into the file at the given offset."""
        if self.read_only:
            return False
        if offset < 0 or offset > self._file_size:
            return False
        self._data = self._data[:offset] + data + self._data[offset:]
        self._file_size = len(self._data)
        return True


class SearchType(Enum):
    """Types of search patterns."""

    HEX = "hex"
    TEXT = "text"
    REGEX = "regex"
    WILDCARD = "wildcard"


class SearchResult:
    """Represents a single search result."""

    def __init__(self, offset: int, length: int, data: bytes, context: bytes | None = None) -> None:
        """Initialize the SearchResult with offset, length, data, and context."""
        self.offset = offset
        self.length = length
        self.data = data
        self.context = context if context is not None else b""

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
    def from_dict(cls, data: dict[str, Any]) -> SearchResult:
        """Create from dictionary."""
        return cls(
            offset=data["offset"],
            length=data["length"],
            data=bytes.fromhex(data["data"]),
            context=bytes.fromhex(data["context"]) if data["context"] else b"",
        )


class SearchHistory:
    """Manages search history persistence."""

    def __init__(self, max_entries: int | None = None) -> None:
        """Initialize the SearchHistory with maximum entries limit."""
        from intellicrack.core.config_manager import get_config

        config = get_config()

        if max_entries is None:
            config_value = config.get("hex_viewer.search.history_max_entries", 50)
            if isinstance(config_value, (int, float, str)):
                self.max_entries: int = int(config_value)
            else:
                self.max_entries = 50
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

        self.entries = [e for e in self.entries if e["pattern"] != pattern or e["type"] != search_type.value]

        self.entries.insert(0, entry)

        if len(self.entries) > self.max_entries:
            self.entries = self.entries[: self.max_entries]

        self.save_history()

    def get_recent_searches(self, search_type: SearchType | None = None, limit: int = 10) -> list[str]:
        """Get recent search patterns."""
        filtered_entries = self.entries
        if search_type:
            filtered_entries = [e for e in self.entries if e["type"] == search_type.value]

        return [str(e["pattern"]) for e in filtered_entries[:limit]]

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

    def __init__(self, file_handler: BaseFileHandler) -> None:
        """Initialize the SearchEngine with file handler and chunk size."""
        self.file_handler: BaseFileHandler = file_handler

        from intellicrack.core.config_manager import get_config

        config = get_config()

        chunk_size_kb = config.get("hex_viewer.search.search_chunk_size_kb", 256)
        if isinstance(chunk_size_kb, (int, float, str)):
            self.chunk_size: int = int(chunk_size_kb) * 1024
        else:
            self.chunk_size = 256 * 1024

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
        if compiled_pattern is not None:
            if direction == "forward":
                return self._search_forward(compiled_pattern, start_offset, whole_words)
            else:
                return self._search_backward(compiled_pattern, start_offset, whole_words)
        return None

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

        results: list[SearchResult] = []
        file_size = self.file_handler.get_file_size()
        offset = 0
        overlap_size = len(pattern) if isinstance(pattern, bytes) else len(pattern.encode("utf-8"))

        while offset < file_size and len(results) < max_results:
            chunk_size = min(self.chunk_size, file_size - offset)
            chunk_data = self.file_handler.read(offset, chunk_size)

            if not chunk_data:
                break

            chunk_results = self._find_matches_in_chunk(
                compiled_pattern,
                chunk_data,
                offset,
                search_type,
                whole_words,
            )

            results.extend(chunk_results)

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
            logger.exception(error_msg)
            raise ValueError(error_msg)

        results = self.search_all(find_pattern, search_type, case_sensitive, whole_words)

        if not results:
            return []

        if isinstance(replace_pattern, str):
            replace_bytes = replace_pattern.encode("utf-8")
        else:
            replace_bytes = replace_pattern

        replaced_ranges: list[tuple[int, int]] = []
        for result in reversed(results):
            try:
                if self.file_handler.delete(result.offset, result.length):
                    if self.file_handler.insert(result.offset, replace_bytes):
                        replaced_ranges.append((result.offset, len(replace_bytes)))
                    else:
                        if original_data := self.file_handler.read(result.offset, result.length):
                            self.file_handler.insert(result.offset, original_data)
                        error_msg = f"Failed to insert replacement at offset {result.offset:#x}"
                        logger.exception(error_msg)
                        raise RuntimeError(error_msg)
            except Exception as e:
                logger.exception("Error during replace operation at offset 0x%x: %s", result.offset, e)
                continue

        return list(reversed(replaced_ranges))

    def _compile_pattern(self, pattern: str | bytes, search_type: SearchType, case_sensitive: bool) -> bytes | Pattern[str] | None:
        """Compile pattern based on search type."""
        try:
            if search_type == SearchType.HEX:
                if isinstance(pattern, str):
                    hex_clean = pattern.replace(" ", "").replace("-", "")
                    return bytes.fromhex(hex_clean)
                return pattern

            if search_type == SearchType.TEXT:
                return pattern if isinstance(pattern, bytes) else pattern.encode("utf-8")
            if search_type == SearchType.REGEX:
                flags = 0 if case_sensitive else re.IGNORECASE
                pattern_str = pattern.decode("utf-8", errors="replace") if isinstance(pattern, bytes) else pattern
                return re.compile(pattern_str, flags)

            if search_type == SearchType.WILDCARD:
                pattern_str = pattern.decode("utf-8", errors="replace") if isinstance(pattern, bytes) else pattern

                escaped = re.escape(pattern_str)
                escaped = escaped.replace(r"\*", ".*").replace(r"\?", ".")

                flags = 0 if case_sensitive else re.IGNORECASE
                return re.compile(escaped, flags)

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error compiling pattern: %s", e)

        return None

    def _search_forward(
        self,
        compiled_pattern: bytes | Pattern[str],
        start_offset: int,
        whole_words: bool,
    ) -> SearchResult | None:
        """Search forward from ``start_offset``."""
        file_size = self.file_handler.get_file_size()
        offset = start_offset
        overlap_size = 100

        while offset < file_size:
            chunk_size = min(self.chunk_size, file_size - offset)
            chunk_data = self.file_handler.read(offset, chunk_size)

            if not chunk_data:
                break

            if match := self._find_first_match_in_chunk(
                compiled_pattern,
                chunk_data,
                offset,
                whole_words,
            ):
                return match

            offset += chunk_size - overlap_size

        return None

    def _search_backward(
        self,
        compiled_pattern: bytes | Pattern[str],
        start_offset: int,
        whole_words: bool,
    ) -> SearchResult | None:
        """Search backward from ``start_offset``."""
        offset = min(start_offset, self.file_handler.get_file_size())
        overlap_size = 100

        while offset > 0:
            chunk_start = max(0, offset - self.chunk_size)
            chunk_size = offset - chunk_start
            chunk_data = self.file_handler.read(chunk_start, chunk_size)

            if not chunk_data:
                break

            if matches := self._find_matches_in_chunk(
                compiled_pattern,
                chunk_data,
                chunk_start,
                SearchType.HEX,
                whole_words,
            ):
                return matches[-1]

            offset = chunk_start + overlap_size

        return None

    def _find_matches_in_chunk(
        self,
        compiled_pattern: bytes | Pattern[str],
        chunk_data: bytes,
        chunk_offset: int,
        search_type: SearchType,
        whole_words: bool,
    ) -> list[SearchResult]:
        """Find all matches in a chunk of data."""
        matches: list[SearchResult] = []

        case_sensitive = search_type != SearchType.TEXT
        is_binary_search = search_type in (SearchType.HEX, SearchType.WILDCARD)

        try:
            if isinstance(compiled_pattern, bytes):
                if is_binary_search or case_sensitive:
                    search_data = chunk_data
                    search_pattern = compiled_pattern
                else:
                    search_data = chunk_data.lower()
                    search_pattern = compiled_pattern.lower()

                pos = 0
                while True:
                    pos = search_data.find(search_pattern, pos)
                    if pos == -1:
                        break

                    if not whole_words or self._is_whole_word_match(chunk_data, pos, len(compiled_pattern)):
                        context_start = max(0, pos - 16)
                        context_end = min(len(chunk_data), pos + len(compiled_pattern) + 16)
                        context = chunk_data[context_start:context_end]

                        match_result = SearchResult(
                            offset=chunk_offset + pos,
                            length=len(compiled_pattern),
                            data=compiled_pattern,
                            context=context,
                        )
                        matches.append(match_result)

                    pos += 1

            elif isinstance(compiled_pattern, re.Pattern):
                text_data = chunk_data.decode("utf-8", errors="replace")
                for regex_match in compiled_pattern.finditer(text_data):
                    start_pos = regex_match.start()
                    end_pos = regex_match.end()

                    pre_match_str = text_data[:start_pos]
                    byte_start = len(pre_match_str.encode("utf-8", errors="replace"))

                    match_str = text_data[start_pos:end_pos]
                    byte_length = len(match_str.encode("utf-8", errors="replace"))

                    byte_end = byte_start + byte_length

                    if byte_start < len(chunk_data) and byte_end <= len(chunk_data):
                        matched_data = chunk_data[byte_start:byte_end]

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
            logger.exception("Error finding matches in chunk: %s", e)

        return matches

    def _find_first_match_in_chunk(
        self,
        compiled_pattern: bytes | Pattern[str],
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
            return (48 <= byte_val <= 57) or (65 <= byte_val <= 90) or (97 <= byte_val <= 122) or (byte_val == 95)

        if pos > 0:
            prev_char = data[pos - 1]
            first_match_char = data[pos]

            if is_word_char(prev_char) and is_word_char(first_match_char):
                return False

        if pos + length < len(data):
            next_char = data[pos + length]
            last_match_char = data[pos + length - 1]

            if is_word_char(last_match_char) and is_word_char(next_char):
                return False

        if pos > 0:
            prev_char = data[pos - 1]
            if prev_char in b"()[]{},\"'`:;!?\\/|<>@#$%^&*+=~\x00\r\n\t ":
                pass
            elif is_word_char(prev_char):
                if is_word_char(data[pos]):
                    return False

        if pos + length < len(data):
            next_char = data[pos + length]
            if next_char in b"()[]{},\"'`:;!?\\/|<>@#$%^&*+=~\x00\r\n\t ":
                pass
            elif is_word_char(next_char):
                if is_word_char(data[pos + length - 1]):
                    return False

        return True


_SearchThreadBase: type[QThread] | type[object]
_SearchThreadBase = QThread if PYQT6_AVAILABLE else object


class SearchThread(_SearchThreadBase):  # type: ignore[valid-type,misc]
    """Background thread for long-running search operations."""

    if PYQT6_AVAILABLE:
        progress_updated = pyqtSignal(int)
        result_found = pyqtSignal(object)
        search_completed = pyqtSignal(list)

    def __init__(
        self,
        search_engine: SearchEngine,
        pattern: str,
        search_type: SearchType,
        find_all: bool = False,
        case_sensitive: bool = True,
        whole_words: bool = False,
        max_results: int = 1000,
        start_offset: int = 0,
        direction: str = "forward",
    ) -> None:
        """Initialize the SearchThread with search parameters."""
        if PYQT6_AVAILABLE:
            super().__init__()
        self.search_engine = search_engine
        self.pattern = pattern
        self.search_type = search_type
        self.find_all = find_all
        self.case_sensitive = case_sensitive
        self.whole_words = whole_words
        self.max_results = max_results
        self.start_offset = start_offset
        self.direction = direction
        self.should_stop = False

    def run(self) -> None:
        """Run the search operation."""
        try:
            if self.find_all:
                results = self.search_engine.search_all(
                    self.pattern,
                    self.search_type,
                    case_sensitive=self.case_sensitive,
                    whole_words=self.whole_words,
                    max_results=self.max_results,
                )
                if PYQT6_AVAILABLE and hasattr(self, "search_completed"):
                    self.search_completed.emit(results)
            else:
                result = self.search_engine.search(
                    self.pattern,
                    self.search_type,
                    start_offset=self.start_offset,
                    case_sensitive=self.case_sensitive,
                    whole_words=self.whole_words,
                    direction=self.direction,
                )
                if result and PYQT6_AVAILABLE and hasattr(self, "result_found"):
                    self.result_found.emit(result)
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Search thread error: %s", e)

    def stop(self) -> None:
        """Stop the search operation."""
        self.should_stop = True


_AdvancedSearchDialogBase: type[QDialog] | type[object]
_AdvancedSearchDialogBase = QDialog if PYQT6_AVAILABLE else object


class AdvancedSearchDialog(_AdvancedSearchDialogBase):  # type: ignore[valid-type,misc]
    """Advanced search dialog with comprehensive search options."""

    def __init__(
        self,
        parent: QWidget | None = None,
        search_engine: SearchEngine | None = None,
    ) -> None:
        """Initialize the advanced search dialog with parent widget and search engine."""
        if not PYQT6_AVAILABLE:
            return

        super().__init__(parent)
        self.search_engine = search_engine
        self.search_history = SearchHistory()
        self.current_search_thread: SearchThread | None = None

        self.search_pattern_combo: QComboBox | None = None
        self.search_type_combo: QComboBox | None = None
        self.case_sensitive_check: QCheckBox | None = None
        self.whole_words_check: QCheckBox | None = None
        self.direction_group: QButtonGroup | None = None
        self.forward_radio: QRadioButton | None = None
        self.backward_radio: QRadioButton | None = None
        self.find_next_button: QPushButton | None = None
        self.find_previous_button: QPushButton | None = None
        self.search_status_label: QLabel | None = None
        self.find_pattern_combo: QComboBox | None = None
        self.replace_pattern_edit: QLineEdit | None = None
        self.replace_type_combo: QComboBox | None = None
        self.replace_case_sensitive_check: QCheckBox | None = None
        self.replace_whole_words_check: QCheckBox | None = None
        self.replace_button: QPushButton | None = None
        self.replace_all_button: QPushButton | None = None
        self.replace_status_label: QLabel | None = None
        self.find_all_pattern_combo: QComboBox | None = None
        self.find_all_type_combo: QComboBox | None = None
        self.max_results_spin: QSpinBox | None = None
        self.find_all_button: QPushButton | None = None
        self.cancel_search_button: QPushButton | None = None
        self.search_progress: QProgressBar | None = None
        self.results_table: QTableWidget | None = None
        self.history_list: QListWidget | None = None
        self.use_history_button: QPushButton | None = None
        self.clear_history_button: QPushButton | None = None

        self.setWindowTitle("Advanced Search")
        self.setModal(False)
        self.resize(600, 500)

        self.setup_ui()
        self.load_recent_searches()

    def setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)

        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)

        search_tab = self.create_search_tab()
        tab_widget.addTab(search_tab, "Search")

        replace_tab = self.create_replace_tab()
        tab_widget.addTab(replace_tab, "Replace")

        find_all_tab = self.create_find_all_tab()
        tab_widget.addTab(find_all_tab, "Find All")

        history_tab = self.create_history_tab()
        tab_widget.addTab(history_tab, "History")

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        button_box.rejected.connect(self.close)
        layout.addWidget(button_box)

    def create_search_tab(self) -> QWidget:
        """Create the search tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        search_group = QGroupBox("Search Pattern")
        search_layout = QFormLayout(search_group)

        self.search_pattern_combo = QComboBox()
        self.search_pattern_combo.setEditable(True)
        search_layout.addRow("Pattern:", self.search_pattern_combo)

        self.search_type_combo = QComboBox()
        self.search_type_combo.addItems(["Hex", "Text", "Regex", "Wildcard"])
        search_layout.addRow("Type:", self.search_type_combo)

        layout.addWidget(search_group)

        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout(options_group)

        self.case_sensitive_check = QCheckBox("Case sensitive")
        options_layout.addWidget(self.case_sensitive_check)

        self.whole_words_check = QCheckBox("Match whole words only")
        options_layout.addWidget(self.whole_words_check)

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

        controls_layout = QHBoxLayout()

        self.find_next_button = QPushButton("Find Next")
        self.find_next_button.clicked.connect(self.find_next)
        controls_layout.addWidget(self.find_next_button)

        self.find_previous_button = QPushButton("Find Previous")
        self.find_previous_button.clicked.connect(self.find_previous)
        controls_layout.addWidget(self.find_previous_button)

        controls_layout.addStretch()
        layout.addLayout(controls_layout)

        self.search_status_label = QLabel("Ready")
        layout.addWidget(self.search_status_label)

        layout.addStretch()
        return tab

    def create_replace_tab(self) -> QWidget:
        """Create the replace tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

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

        replace_options_group = QGroupBox("Options")
        replace_options_layout = QVBoxLayout(replace_options_group)

        self.replace_case_sensitive_check = QCheckBox("Case sensitive")
        replace_options_layout.addWidget(self.replace_case_sensitive_check)

        self.replace_whole_words_check = QCheckBox("Match whole words only")
        replace_options_layout.addWidget(self.replace_whole_words_check)

        layout.addWidget(replace_options_group)

        replace_controls_layout = QHBoxLayout()

        self.replace_button = QPushButton("Replace")
        self.replace_button.clicked.connect(self.replace_current)
        replace_controls_layout.addWidget(self.replace_button)

        self.replace_all_button = QPushButton("Replace All")
        self.replace_all_button.clicked.connect(self.replace_all)
        replace_controls_layout.addWidget(self.replace_all_button)

        replace_controls_layout.addStretch()
        layout.addLayout(replace_controls_layout)

        self.replace_status_label = QLabel("Ready")
        layout.addWidget(self.replace_status_label)

        layout.addStretch()
        return tab

    def create_find_all_tab(self) -> QWidget:
        """Create the find all tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

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

        self.search_progress = QProgressBar()
        self.search_progress.setVisible(False)
        layout.addWidget(self.search_progress)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Offset", "Length", "Data", "Context"])
        header = self.results_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.results_table)

        return tab

    def create_history_tab(self) -> QWidget:
        """Create the search history tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        history_group = QGroupBox("Search History")
        history_layout = QVBoxLayout(history_group)

        self.history_list = QListWidget()
        self.history_list.itemDoubleClicked.connect(self.use_history_item)
        history_layout.addWidget(self.history_list)

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
            if combo is not None:
                combo.clear()
                combo.addItems(recent_searches)
                combo.setCurrentText("")

        self.update_history_list()

    def update_history_list(self) -> None:
        """Update the history list widget."""
        if self.history_list is None:
            return

        self.history_list.clear()

        for entry in self.search_history.entries[:20]:
            item_text = f"{entry['pattern']} ({entry['type']})"
            item = QListWidgetItem(item_text)
            item.setData(Qt.ItemDataRole.UserRole, entry)
            self.history_list.addItem(item)

    def find_next(self) -> None:
        """Find next occurrence."""
        if self.search_pattern_combo is None:
            return

        pattern = self.search_pattern_combo.currentText()
        if not pattern:
            return

        if self.search_type_combo is None:
            return

        search_type = self._get_search_type(self.search_type_combo.currentText())

        if self.case_sensitive_check is None or self.whole_words_check is None:
            return

        options: dict[str, Any] = {
            "case_sensitive": self.case_sensitive_check.isChecked(),
            "whole_words": self.whole_words_check.isChecked(),
            "direction": "forward",
        }
        self.search_history.add_search(pattern, search_type, options)

        if self.search_engine:
            try:
                if result := self.search_engine.search(
                    pattern,
                    search_type,
                    case_sensitive=bool(options["case_sensitive"]),
                    whole_words=bool(options["whole_words"]),
                    direction="forward",
                ):
                    if self.search_status_label is not None:
                        self.search_status_label.setText(f"Found at offset 0x{result.offset:X}")
                    parent_widget = self.parent()
                    if parent_widget is not None and hasattr(parent_widget, "hex_viewer"):
                        hex_viewer = parent_widget.hex_viewer
                        if hasattr(hex_viewer, "select_range"):
                            hex_viewer.select_range(result.offset, result.offset + result.length)
                elif self.search_status_label is not None:
                    self.search_status_label.setText("Pattern not found")

            except (OSError, ValueError, RuntimeError) as e:
                logger.exception("Error in advanced_search: %s", e)
                if self.search_status_label is not None:
                    self.search_status_label.setText(f"Search error: {e}")

    def find_previous(self) -> None:
        """Find previous occurrence."""
        if self.search_pattern_combo is None:
            return

        pattern = self.search_pattern_combo.currentText()
        if not pattern:
            return

        if self.search_type_combo is None:
            return

        search_type = self._get_search_type(self.search_type_combo.currentText())

        if self.case_sensitive_check is None or self.whole_words_check is None:
            return

        if self.search_engine:
            try:
                if result := self.search_engine.search(
                    pattern,
                    search_type,
                    case_sensitive=self.case_sensitive_check.isChecked(),
                    whole_words=self.whole_words_check.isChecked(),
                    direction="backward",
                ):
                    if self.search_status_label is not None:
                        self.search_status_label.setText(f"Found at offset 0x{result.offset:X}")
                    parent_widget = self.parent()
                    if parent_widget is not None and hasattr(parent_widget, "hex_viewer"):
                        hex_viewer = parent_widget.hex_viewer
                        if hasattr(hex_viewer, "select_range"):
                            hex_viewer.select_range(result.offset, result.offset + result.length)
                elif self.search_status_label is not None:
                    self.search_status_label.setText("Pattern not found")

            except (OSError, ValueError, RuntimeError) as e:
                logger.exception("Error in advanced_search: %s", e)
                if self.search_status_label is not None:
                    self.search_status_label.setText(f"Search error: {e}")

    def replace_current(self) -> None:
        """Replace current selection."""
        if self.replace_status_label is not None:
            self.replace_status_label.setText("Replace functionality requires hex viewer integration")

    def replace_all(self) -> None:
        """Replace all occurrences."""
        if self.find_pattern_combo is None or self.replace_pattern_edit is None:
            return

        find_pattern = self.find_pattern_combo.currentText()
        replace_pattern = self.replace_pattern_edit.text()

        if not find_pattern:
            return

        if self.replace_type_combo is None:
            return

        search_type = self._get_search_type(self.replace_type_combo.currentText())

        if self.replace_case_sensitive_check is None or self.replace_whole_words_check is None:
            return

        if self.search_engine:
            try:
                replaced_ranges = self.search_engine.replace_all(
                    find_pattern,
                    replace_pattern,
                    search_type,
                    case_sensitive=self.replace_case_sensitive_check.isChecked(),
                    whole_words=self.replace_whole_words_check.isChecked(),
                )

                if self.replace_status_label is not None:
                    self.replace_status_label.setText(f"Replaced {len(replaced_ranges)} occurrences")

            except (OSError, ValueError, RuntimeError) as e:
                logger.exception("Error in advanced_search: %s", e)
                if self.replace_status_label is not None:
                    self.replace_status_label.setText(f"Replace error: {e}")

    def find_all(self) -> None:
        """Find all occurrences."""
        if self.find_all_pattern_combo is None:
            return

        pattern = self.find_all_pattern_combo.currentText()
        if not pattern:
            return

        if self.find_all_type_combo is None or self.max_results_spin is None:
            return

        search_type = self._get_search_type(self.find_all_type_combo.currentText())
        max_results = self.max_results_spin.value()

        if self.results_table is not None:
            self.results_table.setRowCount(0)
        if self.search_progress is not None:
            self.search_progress.setVisible(True)
        if self.find_all_button is not None:
            self.find_all_button.setEnabled(False)
        if self.cancel_search_button is not None:
            self.cancel_search_button.setEnabled(True)

        if self.search_engine is None:
            return

        self.current_search_thread = SearchThread(
            self.search_engine,
            pattern,
            search_type,
            find_all=True,
            max_results=max_results,
        )

        if self.current_search_thread is not None and PYQT6_AVAILABLE and hasattr(self.current_search_thread, "search_completed"):
            self.current_search_thread.search_completed.connect(self.on_find_all_completed)
            self.current_search_thread.start()

    def on_find_all_completed(self, results: list[SearchResult]) -> None:
        """Handle find all completion."""
        if self.search_progress is not None:
            self.search_progress.setVisible(False)
        if self.find_all_button is not None:
            self.find_all_button.setEnabled(True)
        if self.cancel_search_button is not None:
            self.cancel_search_button.setEnabled(False)

        if self.results_table is None:
            return

        self.results_table.setRowCount(len(results))

        for i, result in enumerate(results):
            self.results_table.setItem(i, 0, QTableWidgetItem(f"0x{result.offset:X}"))
            self.results_table.setItem(i, 1, QTableWidgetItem(str(result.length)))
            self.results_table.setItem(i, 2, QTableWidgetItem(result.data.hex(" ")[:32] + "..."))
            self.results_table.setItem(i, 3, QTableWidgetItem(result.context.hex(" ")[:48] + "..."))

    def cancel_search(self) -> None:
        """Cancel current search."""
        if self.current_search_thread is not None:
            self.current_search_thread.stop()
            if hasattr(self.current_search_thread, "wait"):
                self.current_search_thread.wait()

        if self.search_progress is not None:
            self.search_progress.setVisible(False)
        if self.find_all_button is not None:
            self.find_all_button.setEnabled(True)
        if self.cancel_search_button is not None:
            self.cancel_search_button.setEnabled(False)

    def use_history_item(self, item: QListWidgetItem) -> None:
        """Use selected history item."""
        entry = item.data(Qt.ItemDataRole.UserRole)
        if entry and self.search_pattern_combo is not None:
            self.search_pattern_combo.setCurrentText(str(entry["pattern"]))
            if self.search_type_combo is not None:
                type_index = self.search_type_combo.findText(str(entry["type"]).title())
                if type_index >= 0:
                    self.search_type_combo.setCurrentIndex(type_index)

    def use_selected_history(self) -> None:
        """Use currently selected history item."""
        if self.history_list is None:
            return

        current_item = self.history_list.currentItem()
        if current_item is not None:
            self.use_history_item(current_item)

    def clear_history(self) -> None:
        """Clear search history."""
        reply = QMessageBox.question(
            self,
            "Clear History",
            "Are you sure you want to clear the search history?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
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


_FindAllDialogBase: type[QDialog] | type[object]
_FindAllDialogBase = QDialog if PYQT6_AVAILABLE else object


class FindAllDialog(_FindAllDialogBase):  # type: ignore[valid-type,misc]
    """Dialog for displaying find all results."""

    def __init__(
        self,
        parent: QWidget | None = None,
        results: list[SearchResult] | None = None,
    ) -> None:
        """Initialize find all dialog."""
        if not PYQT6_AVAILABLE:
            return
        super().__init__(parent)
        self.results = results if results is not None else []
        self.results_table: QTableWidget | None = None
        self.setWindowTitle("Find All Results")
        self.setMinimumSize(800, 600)
        self.setup_ui()

    def setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        info_label = QLabel(f"Found {len(self.results)} matches")
        layout.addWidget(info_label)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Offset", "Hex", "ASCII", "Context"])
        header = self.results_table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(True)

        self.results_table.setRowCount(len(self.results))
        for i, result in enumerate(self.results):
            self.results_table.setItem(i, 0, QTableWidgetItem(f"0x{result.offset:08X}"))
            self.results_table.setItem(i, 1, QTableWidgetItem(result.data.hex() if result.data else ""))
            ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in result.data) if result.data else ""
            self.results_table.setItem(i, 2, QTableWidgetItem(ascii_text))
            context_hex = result.context.hex() if result.context else ""
            self.results_table.setItem(
                i,
                3,
                QTableWidgetItem(context_hex),
            )

        layout.addWidget(self.results_table)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        button_box.rejected.connect(self.accept)
        layout.addWidget(button_box)


_ReplaceDialogBase: type[QDialog] | type[object]
_ReplaceDialogBase = QDialog if PYQT6_AVAILABLE else object


class ReplaceDialog(_ReplaceDialogBase):  # type: ignore[valid-type,misc]
    """Dialog for replace operations."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize replace dialog."""
        if not PYQT6_AVAILABLE:
            return
        super().__init__(parent)
        self.find_pattern: QLineEdit | None = None
        self.find_type: QComboBox | None = None
        self.replace_pattern: QLineEdit | None = None
        self.case_sensitive: QCheckBox | None = None
        self.replace_all: QCheckBox | None = None
        self.setWindowTitle("Replace")
        self.setMinimumSize(500, 300)
        self.setup_ui()

    def setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        find_group = QGroupBox("Find")
        find_layout = QFormLayout(find_group)

        self.find_pattern = QLineEdit()
        find_layout.addRow("Pattern:", self.find_pattern)

        self.find_type = QComboBox()
        self.find_type.addItems(["Hex", "Text"])
        find_layout.addRow("Type:", self.find_type)

        layout.addWidget(find_group)

        replace_group = QGroupBox("Replace")
        replace_layout = QFormLayout(replace_group)

        self.replace_pattern = QLineEdit()
        replace_layout.addRow("Pattern:", self.replace_pattern)

        layout.addWidget(replace_group)

        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout(options_group)

        self.case_sensitive = QCheckBox("Case sensitive")
        options_layout.addWidget(self.case_sensitive)

        self.replace_all = QCheckBox("Replace all occurrences")
        options_layout.addWidget(self.replace_all)

        layout.addWidget(options_group)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
