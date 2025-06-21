"""
Hex data highlighting module for the hex viewer/editor.

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


import logging
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger('Intellicrack.HexView')


class HighlightType(Enum):
    """Enum for different highlight types."""
    SELECTION = auto()      # User selection
    SEARCH_RESULT = auto()  # Search result
    BOOKMARK = auto()       # User bookmark
    MODIFICATION = auto()   # Modified data
    AI_PATTERN = auto()     # AI-identified pattern
    STRUCTURE = auto()      # Structure highlight
    CUSTOM = auto()         # Custom user highlight


class HexHighlight:
    """
    Represents a highlighted region in hex data.

    This class stores information about a highlighted region including
    its position, appearance, and metadata.
    """

    def __init__(self, start: int, end: int, highlight_type: HighlightType = HighlightType.CUSTOM,
                 color: str = "#FFFF00", alpha: float = 0.3, description: str = "",
                 metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize a hex highlight.

        Args:
            start: Starting offset of the highlight
            end: Ending offset of the highlight (exclusive)
            highlight_type: Type of highlight
            color: Hex color code for the highlight
            alpha: Alpha transparency value (0.0-1.0)
            description: Description of the highlight
            metadata: Additional metadata for the highlight
        """
        self.start = start
        self.end = end
        self.highlight_type = highlight_type
        self.color = color
        self.alpha = max(0.0, min(1.0, alpha))  # Clamp to 0.0-1.0
        self.description = description
        self.metadata = metadata or {}
        self.id = id(self)  # Unique identifier for the highlight

        logger.debug(f"Created highlight: {self.start}-{self.end}, type: {self.highlight_type.name}")

    @property
    def size(self) -> int:
        """Get the size of the highlighted region."""
        return max(0, self.end - self.start)

    def overlaps(self, start: int, end: int) -> bool:
        """
        Check if this highlight overlaps with the specified region.

        Args:
            start: Starting offset of the region
            end: Ending offset of the region

        Returns:
            True if there is an overlap, False otherwise
        """
        return max(self.start, start) < min(self.end, end)

    def contains(self, offset: int) -> bool:
        """
        Check if this highlight contains the specified offset.

        Args:
            offset: Offset to check

        Returns:
            True if the offset is within the highlight, False otherwise
        """
        return self.start <= offset < self.end

    def get_rgba(self) -> Tuple[int, int, int, int]:
        """
        Get the RGBA values for this highlight.

        Returns:
            Tuple of (red, green, blue, alpha) values (0-255)
        """
        # Parse the hex color code
        color = self.color.lstrip('#')
        if len(color) == 3:
            color = ''.join(c+c for c in color)

        r, g, b = tuple(int(color[i:i+2], 16) for i in (0, 2, 4))
        a = int(self.alpha * 255)

        return (r, g, b, a)

    def __repr__(self) -> str:
        """Get a string representation of the highlight."""
        return (f"HexHighlight(start={self.start}, end={self.end}, "
                f"type={self.highlight_type.name}, color={self.color})")


class HexHighlighter:
    """
    Manages highlights for hex data.

    This class provides functionality for adding, removing, and querying
    highlights in binary data.
    """

    def __init__(self):
        """Initialize the hex highlighter."""
        self.highlights = []  # List of HexHighlight objects
        self.current_id = 0   # For generating unique IDs

    def add_highlight(self, start: int, end: int, highlight_type: HighlightType = HighlightType.CUSTOM,
                     color: str = "#FFFF00", alpha: float = 0.3, description: str = "",
                     metadata: Optional[Dict[str, Any]] = None) -> int:
        """
        Add a new highlight.

        Args:
            start: Starting offset of the highlight
            end: Ending offset of the highlight (exclusive)
            highlight_type: Type of highlight
            color: Hex color code for the highlight
            alpha: Alpha transparency value (0.0-1.0)
            description: Description of the highlight
            metadata: Additional metadata for the highlight

        Returns:
            ID of the created highlight
        """
        # Ensure start <= end
        if start > end:
            start, end = end, start

        # Create and add the highlight
        highlight = HexHighlight(start, end, highlight_type, color, alpha, description, metadata)
        self.highlights.append(highlight)

        logger.debug("Added highlight ID %s: %s-%s, type: %s", highlight.id, start, end, highlight_type.name)
        return highlight.id

    def remove_highlight(self, highlight_id: int) -> bool:
        """
        Remove a highlight by ID.

        Args:
            highlight_id: ID of the highlight to remove

        Returns:
            True if the highlight was removed, False if not found
        """
        for i, h in enumerate(self.highlights):
            if h.id == highlight_id:
                self.highlights.pop(i)
                logger.debug("Removed highlight ID %s", highlight_id)
                return True

        logger.debug("Highlight ID %s not found", highlight_id)
        return False

    def clear_highlights(self, highlight_type: Optional[HighlightType] = None) -> int:
        """
        Clear highlights, optionally of a specific type.

        Args:
            highlight_type: Type of highlights to clear, or None for all

        Returns:
            Number of highlights cleared
        """
        if highlight_type is None:
            count = len(self.highlights)
            self.highlights.clear()
            logger.debug("Cleared all %s highlights", count)
            return count

        # Clear highlights of the specified type
        original_count = len(self.highlights)
        self.highlights = [h for h in self.highlights if h.highlight_type != highlight_type]
        count = original_count - len(self.highlights)

        logger.debug("Cleared %s highlights of type %s", count, highlight_type.name)
        return count

    def get_highlights_for_region(self, start: int, end: int) -> List[HexHighlight]:
        """
        Get highlights that overlap with the specified region.

        Args:
            start: Starting offset of the region
            end: Ending offset of the region

        Returns:
            List of highlights that overlap with the region
        """
        return [h for h in self.highlights if h.overlaps(start, end)]

    def get_highlights_at_offset(self, offset: int) -> List[HexHighlight]:
        """
        Get highlights that contain the specified offset.

        Args:
            offset: Offset to check

        Returns:
            List of highlights that contain the offset
        """
        return [h for h in self.highlights if h.contains(offset)]

    def get_highlight_by_id(self, highlight_id: int) -> Optional[HexHighlight]:
        """
        Get a highlight by ID.

        Args:
            highlight_id: ID of the highlight to get

        Returns:
            The highlight, or None if not found
        """
        for h in self.highlights:
            if h.id == highlight_id:
                return h
        return None

    def get_highlight_count(self, highlight_type: Optional[HighlightType] = None) -> int:
        """
        Get the number of highlights, optionally of a specific type.

        Args:
            highlight_type: Type of highlights to count, or None for all

        Returns:
            Number of highlights
        """
        if highlight_type is None:
            return len(self.highlights)

        return sum(1 for h in self.highlights if h.highlight_type == highlight_type)

    def update_highlight(self, highlight_id: int, **kwargs) -> bool:
        """
        Update an existing highlight's properties.

        Args:
            highlight_id: ID of the highlight to update
            **kwargs: Properties to update (start, end, color, etc.)

        Returns:
            True if the highlight was updated, False if not found
        """
        highlight = self.get_highlight_by_id(highlight_id)
        if not highlight:
            logger.debug("Highlight ID %s not found for update", highlight_id)
            return False

        # Update the highlight properties
        for key, value in kwargs.items():
            if hasattr(highlight, key):
                setattr(highlight, key, value)

        logger.debug("Updated highlight ID %s with %s", highlight_id, kwargs)
        return True

    def add_bookmark(self, offset: int, size: int = 1, description: str = "",
                    color: str = "#0000FF") -> int:
        """
        Add a bookmark highlight.

        Args:
            offset: Offset of the bookmark
            size: Size of the bookmarked region
            description: Description of the bookmark
            color: Color of the bookmark highlight

        Returns:
            ID of the created bookmark highlight
        """
        return self.add_highlight(
            start=offset,
            end=offset + size,
            highlight_type=HighlightType.BOOKMARK,
            color=color,
            description=description,
            metadata={"bookmark": True}
        )

    def add_search_result(self, start: int, end: int, query: str = "",
                         color: str = "#00FF00") -> int:
        """
        Add a search result highlight.

        Args:
            start: Starting offset of the search result
            end: Ending offset of the search result
            query: Search query that produced this result
            color: Color of the search result highlight

        Returns:
            ID of the created search result highlight
        """
        return self.add_highlight(
            start=start,
            end=end,
            highlight_type=HighlightType.SEARCH_RESULT,
            color=color,
            description=f"Search result: {query}" if query else "Search result",
            metadata={"query": query}
        )

    def add_modification_highlight(self, start: int, end: int) -> int:
        """
        Add a modification highlight.

        Args:
            start: Starting offset of the modified region
            end: Ending offset of the modified region

        Returns:
            ID of the created modification highlight
        """
        return self.add_highlight(
            start=start,
            end=end,
            highlight_type=HighlightType.MODIFICATION,
            color="#FF0000",
            description="Modified data",
            metadata={"modified": True}
        )

    def add_ai_pattern_highlight(self, start: int, end: int, pattern_type: str,
                               confidence: float = 1.0, description: str = "") -> int:
        """
        Add an AI-identified pattern highlight.

        Args:
            start: Starting offset of the pattern
            end: Ending offset of the pattern
            pattern_type: Type of pattern identified
            confidence: Confidence level of the identification (0.0-1.0)
            description: Description of the pattern

        Returns:
            ID of the created pattern highlight
        """
        # Set color based on confidence level
        if confidence >= 0.8:
            color = "#8800FF"  # High confidence
        elif confidence >= 0.5:
            color = "#FF8800"  # Medium confidence
        else:
            color = "#FFCC00"  # Low confidence

        return self.add_highlight(
            start=start,
            end=end,
            highlight_type=HighlightType.AI_PATTERN,
            color=color,
            alpha=0.7,
            description=description or f"AI pattern: {pattern_type}",
            metadata={
                "pattern_type": pattern_type,
                "confidence": confidence,
                "ai_identified": True
            }
        )
