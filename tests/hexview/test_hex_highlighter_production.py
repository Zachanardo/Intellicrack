"""Production-Ready Tests for Hex Highlighter Module.

Tests REAL highlight management, region tracking, and color handling.
"""

import pytest

from intellicrack.hexview.hex_highlighter import HexHighlight, HexHighlighter, HighlightType


class TestHexHighlight:
    """Test HexHighlight data structure."""

    def test_hexhighlight_creates_with_valid_params(self) -> None:
        """HexHighlight must create with valid parameters."""
        highlight = HexHighlight(
            start=100,
            end=200,
            highlight_type=HighlightType.SELECTION,
            color="#FF0000",
            alpha=128,
            priority=5,
            description="Test highlight",
        )

        assert highlight.start == 100
        assert highlight.end == 200
        assert highlight.highlight_type == HighlightType.SELECTION
        assert highlight.color == "#FF0000"
        assert highlight.alpha == 128
        assert highlight.priority == 5

    def test_hexhighlight_validates_color_format(self) -> None:
        """HexHighlight must validate color format."""
        with pytest.raises(ValueError, match="Color must be in hex format"):
            HexHighlight(
                start=0,
                end=10,
                highlight_type=HighlightType.CUSTOM,
                color="FF0000",
            )

    def test_hexhighlight_validates_alpha_range(self) -> None:
        """HexHighlight must validate alpha range (0-255)."""
        with pytest.raises(ValueError, match="Alpha must be between 0 and 255"):
            HexHighlight(
                start=0,
                end=10,
                highlight_type=HighlightType.CUSTOM,
                color="#FF0000",
                alpha=256,
            )

    def test_hexhighlight_validates_range(self) -> None:
        """HexHighlight must validate start < end."""
        with pytest.raises(ValueError, match="Invalid range"):
            HexHighlight(
                start=100,
                end=50,
                highlight_type=HighlightType.CUSTOM,
                color="#FF0000",
            )

    def test_hexhighlight_size_calculation(self) -> None:
        """HexHighlight must calculate size correctly."""
        highlight = HexHighlight(
            start=100,
            end=200,
            highlight_type=HighlightType.CUSTOM,
        )

        assert highlight.size == 100

    def test_hexhighlight_overlap_detection(self) -> None:
        """HexHighlight must detect overlapping regions."""
        highlight = HexHighlight(
            start=100,
            end=200,
            highlight_type=HighlightType.CUSTOM,
        )

        assert highlight.overlaps(150, 250) is True
        assert highlight.overlaps(50, 150) is True
        assert highlight.overlaps(120, 180) is True

        assert highlight.overlaps(0, 50) is False
        assert highlight.overlaps(250, 300) is False

    def test_hexhighlight_contains_offset(self) -> None:
        """HexHighlight must detect if offset is contained."""
        highlight = HexHighlight(
            start=100,
            end=200,
            highlight_type=HighlightType.CUSTOM,
        )

        assert highlight.contains(100) is True
        assert highlight.contains(150) is True
        assert highlight.contains(199) is True

        assert highlight.contains(200) is False
        assert highlight.contains(50) is False
        assert highlight.contains(250) is False

    def test_hexhighlight_rgba_conversion(self) -> None:
        """HexHighlight must convert hex color to RGBA."""
        highlight = HexHighlight(
            start=0,
            end=10,
            highlight_type=HighlightType.CUSTOM,
            color="#FF8800",
            alpha=128,
        )

        r, g, b, a = highlight.get_rgba()

        assert r == 255
        assert g == 136
        assert b == 0

    def test_hexhighlight_unique_ids(self) -> None:
        """Each HexHighlight must have unique ID."""
        h1 = HexHighlight(0, 10, HighlightType.CUSTOM)
        h2 = HexHighlight(20, 30, HighlightType.CUSTOM)

        assert h1.id != h2.id


class TestHexHighlighter:
    """Test HexHighlighter highlight management."""

    def test_hexhighlighter_add_highlight(self) -> None:
        """HexHighlighter must add highlights and return ID."""
        highlighter = HexHighlighter()

        highlight_id = highlighter.add_highlight(
            start=100,
            end=200,
            highlight_type=HighlightType.SELECTION,
            color="#FFFF00",
        )

        assert isinstance(highlight_id, int)
        assert len(highlighter.highlights) == 1

    def test_hexhighlighter_remove_highlight(self) -> None:
        """HexHighlighter must remove highlights by ID."""
        highlighter = HexHighlighter()

        highlight_id = highlighter.add_highlight(
            start=100,
            end=200,
            highlight_type=HighlightType.CUSTOM,
        )

        success = highlighter.remove_highlight(highlight_id)

        assert success is True
        assert len(highlighter.highlights) == 0

    def test_hexhighlighter_remove_nonexistent_highlight(self) -> None:
        """HexHighlighter must return False for nonexistent highlight."""
        highlighter = HexHighlighter()

        success = highlighter.remove_highlight(9999)

        assert success is False

    def test_hexhighlighter_clear_all_highlights(self) -> None:
        """HexHighlighter must clear all highlights."""
        highlighter = HexHighlighter()

        highlighter.add_highlight(0, 10, HighlightType.CUSTOM)
        highlighter.add_highlight(20, 30, HighlightType.CUSTOM)
        highlighter.add_highlight(40, 50, HighlightType.CUSTOM)

        count = highlighter.clear_highlights()

        assert count == 3
        assert len(highlighter.highlights) == 0

    def test_hexhighlighter_clear_by_type(self) -> None:
        """HexHighlighter must clear highlights of specific type."""
        highlighter = HexHighlighter()

        highlighter.add_highlight(0, 10, HighlightType.SELECTION)
        highlighter.add_highlight(20, 30, HighlightType.SEARCH_RESULT)
        highlighter.add_highlight(40, 50, HighlightType.SEARCH_RESULT)

        count = highlighter.clear_highlights(HighlightType.SEARCH_RESULT)

        assert count == 2
        assert len(highlighter.highlights) == 1
        assert highlighter.highlights[0].highlight_type == HighlightType.SELECTION

    def test_hexhighlighter_get_highlights_for_region(self) -> None:
        """HexHighlighter must return highlights overlapping region."""
        highlighter = HexHighlighter()

        highlighter.add_highlight(100, 200, HighlightType.CUSTOM)
        highlighter.add_highlight(300, 400, HighlightType.CUSTOM)
        highlighter.add_highlight(500, 600, HighlightType.CUSTOM)

        overlapping = highlighter.get_highlights_for_region(150, 350)

        assert len(overlapping) == 2
        assert any(h.start == 100 for h in overlapping)
        assert any(h.start == 300 for h in overlapping)

    def test_hexhighlighter_get_highlights_at_offset(self) -> None:
        """HexHighlighter must return highlights containing offset."""
        highlighter = HexHighlighter()

        highlighter.add_highlight(100, 200, HighlightType.CUSTOM)
        highlighter.add_highlight(150, 250, HighlightType.CUSTOM)
        highlighter.add_highlight(300, 400, HighlightType.CUSTOM)

        highlights = highlighter.get_highlights_at_offset(175)

        assert len(highlights) == 2

    def test_hexhighlighter_get_highlight_by_id(self) -> None:
        """HexHighlighter must retrieve highlight by ID."""
        highlighter = HexHighlighter()

        highlight_id = highlighter.add_highlight(100, 200, HighlightType.CUSTOM)

        highlight = highlighter.get_highlight_by_id(highlight_id)

        assert highlight is not None
        assert highlight.id == highlight_id

    def test_hexhighlighter_get_nonexistent_highlight(self) -> None:
        """HexHighlighter must return None for nonexistent ID."""
        highlighter = HexHighlighter()

        highlight = highlighter.get_highlight_by_id(9999)

        assert highlight is None

    def test_hexhighlighter_get_count(self) -> None:
        """HexHighlighter must count highlights correctly."""
        highlighter = HexHighlighter()

        highlighter.add_highlight(0, 10, HighlightType.SELECTION)
        highlighter.add_highlight(20, 30, HighlightType.SEARCH_RESULT)
        highlighter.add_highlight(40, 50, HighlightType.SEARCH_RESULT)

        total_count = highlighter.get_highlight_count()
        search_count = highlighter.get_highlight_count(HighlightType.SEARCH_RESULT)

        assert total_count == 3
        assert search_count == 2

    def test_hexhighlighter_update_highlight(self) -> None:
        """HexHighlighter must update highlight properties."""
        highlighter = HexHighlighter()

        highlight_id = highlighter.add_highlight(
            100,
            200,
            HighlightType.CUSTOM,
            color="#FF0000",
        )

        success = highlighter.update_highlight(
            highlight_id,
            color="#00FF00",
            description="Updated",
        )

        assert success is True

        highlight = highlighter.get_highlight_by_id(highlight_id)
        assert highlight.color == "#00FF00"
        assert highlight.description == "Updated"

    def test_hexhighlighter_update_nonexistent_highlight(self) -> None:
        """HexHighlighter must return False when updating nonexistent highlight."""
        highlighter = HexHighlighter()

        success = highlighter.update_highlight(9999, color="#FF0000")

        assert success is False


class TestHexHighlighterSpecializedHighlights:
    """Test specialized highlight creation methods."""

    def test_add_bookmark(self) -> None:
        """add_bookmark must create bookmark highlight."""
        highlighter = HexHighlighter()

        bookmark_id = highlighter.add_bookmark(
            offset=100,
            size=10,
            description="Important location",
        )

        highlight = highlighter.get_highlight_by_id(bookmark_id)

        assert highlight is not None
        assert highlight.highlight_type == HighlightType.BOOKMARK
        assert highlight.start == 100
        assert highlight.end == 110
        assert highlight.metadata.get("bookmark") is True

    def test_add_search_result(self) -> None:
        """add_search_result must create search result highlight."""
        highlighter = HexHighlighter()

        result_id = highlighter.add_search_result(
            start=200,
            end=210,
            query="test",
        )

        highlight = highlighter.get_highlight_by_id(result_id)

        assert highlight is not None
        assert highlight.highlight_type == HighlightType.SEARCH_RESULT
        assert highlight.metadata.get("query") == "test"

    def test_add_modification_highlight(self) -> None:
        """add_modification_highlight must create modification highlight."""
        highlighter = HexHighlighter()

        mod_id = highlighter.add_modification_highlight(start=300, end=350)

        highlight = highlighter.get_highlight_by_id(mod_id)

        assert highlight is not None
        assert highlight.highlight_type == HighlightType.MODIFICATION
        assert highlight.color == "#FF0000"
        assert highlight.metadata.get("modified") is True

    def test_add_ai_pattern_highlight(self) -> None:
        """add_ai_pattern_highlight must create AI pattern highlight with confidence-based color."""
        highlighter = HexHighlighter()

        high_confidence = highlighter.add_ai_pattern_highlight(
            start=100,
            end=200,
            pattern_type="encrypted_data",
            confidence=0.95,
        )

        medium_confidence = highlighter.add_ai_pattern_highlight(
            start=300,
            end=400,
            pattern_type="packed_code",
            confidence=0.65,
        )

        low_confidence = highlighter.add_ai_pattern_highlight(
            start=500,
            end=600,
            pattern_type="unknown",
            confidence=0.30,
        )

        high_h = highlighter.get_highlight_by_id(high_confidence)
        medium_h = highlighter.get_highlight_by_id(medium_confidence)
        low_h = highlighter.get_highlight_by_id(low_confidence)

        assert high_h.color == "#8800FF"
        assert medium_h.color == "#FF8800"
        assert low_h.color == "#FFCC00"


class TestHighlightOverlapping:
    """Test overlapping highlight scenarios."""

    def test_multiple_overlapping_highlights(self) -> None:
        """HexHighlighter must handle multiple overlapping highlights."""
        highlighter = HexHighlighter()

        highlighter.add_highlight(100, 200, HighlightType.SELECTION)
        highlighter.add_highlight(150, 250, HighlightType.SEARCH_RESULT)
        highlighter.add_highlight(175, 225, HighlightType.AI_PATTERN)

        highlights_at_180 = highlighter.get_highlights_at_offset(180)

        assert len(highlights_at_180) == 3

    def test_nested_highlights(self) -> None:
        """HexHighlighter must handle nested highlights."""
        highlighter = HexHighlighter()

        outer = highlighter.add_highlight(100, 300, HighlightType.STRUCTURE)
        inner = highlighter.add_highlight(150, 200, HighlightType.SELECTION)

        highlights_at_175 = highlighter.get_highlights_at_offset(175)

        assert len(highlights_at_175) == 2


class TestHighlightEdgeCases:
    """Test highlight edge cases."""

    def test_zero_size_highlight(self) -> None:
        """HexHighlighter must handle single-byte highlights."""
        highlighter = HexHighlighter()

        highlight_id = highlighter.add_highlight(100, 101, HighlightType.CUSTOM)

        highlight = highlighter.get_highlight_by_id(highlight_id)
        assert highlight.size == 1

    def test_swapped_start_end(self) -> None:
        """HexHighlighter must swap start/end if reversed."""
        highlighter = HexHighlighter()

        highlight_id = highlighter.add_highlight(
            start=200,
            end=100,
            highlight_type=HighlightType.CUSTOM,
        )

        highlight = highlighter.get_highlight_by_id(highlight_id)
        assert highlight.start == 100
        assert highlight.end == 200

    def test_alpha_conversion(self) -> None:
        """HexHighlighter must convert alpha from 0.0-1.0 to 0-255."""
        highlighter = HexHighlighter()

        highlight_id = highlighter.add_highlight(
            start=0,
            end=10,
            highlight_type=HighlightType.CUSTOM,
            alpha=0.5,
        )

        highlight = highlighter.get_highlight_by_id(highlight_id)
        assert highlight.alpha == 127
