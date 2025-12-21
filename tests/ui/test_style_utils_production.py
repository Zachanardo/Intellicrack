"""Production tests for intellicrack.ui.style_utils.

Tests stylesheet generation functions for Qt progress bars and other UI elements.
Validates that generated stylesheets contain proper CSS syntax and expected properties.
"""

import pytest
import re
from intellicrack.ui.style_utils import (
    get_progress_bar_style,
    get_default_progress_bar_style,
    get_splash_progress_bar_style,
)


class TestProgressBarStyleGeneration:
    """Test progress bar stylesheet generation functions."""

    def test_get_progress_bar_style_default_parameters(self) -> None:
        """Default progress bar style contains all required CSS properties."""
        style = get_progress_bar_style()

        assert isinstance(style, str)
        assert len(style) > 0

        assert "QProgressBar" in style
        assert "QProgressBar::chunk" in style

        assert "border:" in style
        assert "border-radius:" in style
        assert "text-align:" in style
        assert "background-color:" in style


    def test_get_progress_bar_style_custom_border_width(self) -> None:
        """Custom border width is applied to generated stylesheet."""
        style = get_progress_bar_style(border_width=3)

        assert "border: 3px solid" in style


    def test_get_progress_bar_style_custom_border_color(self) -> None:
        """Custom border color is applied to generated stylesheet."""
        style = get_progress_bar_style(border_color="#ff0000")

        assert "#ff0000" in style


    def test_get_progress_bar_style_custom_background_color(self) -> None:
        """Custom background color is applied to generated stylesheet."""
        style = get_progress_bar_style(background_color="#123456")

        assert "#123456" in style


    def test_get_progress_bar_style_custom_chunk_color(self) -> None:
        """Custom chunk (progress) color is applied to generated stylesheet."""
        style = get_progress_bar_style(chunk_color="#00ff00")

        assert "#00ff00" in style


    def test_get_progress_bar_style_custom_border_radius(self) -> None:
        """Custom border radius is applied to generated stylesheet."""
        style = get_progress_bar_style(border_radius=10)

        assert "border-radius: 10px" in style


    def test_get_progress_bar_style_all_custom_parameters(self) -> None:
        """All custom parameters are correctly applied together."""
        style = get_progress_bar_style(
            border_width=5,
            border_color="#abcdef",
            background_color="#111111",
            chunk_color="#ffffff",
            border_radius=15,
        )

        assert "border: 5px solid #abcdef" in style
        assert "#111111" in style
        assert "#ffffff" in style
        assert "border-radius: 15px" in style


    def test_get_progress_bar_style_valid_css_syntax(self) -> None:
        """Generated stylesheet has valid CSS syntax."""
        style = get_progress_bar_style()

        assert "{" in style
        assert "}" in style

        open_braces = style.count("{")
        close_braces = style.count("}")
        assert open_braces == close_braces
        assert open_braces >= 2


    def test_get_progress_bar_style_contains_qprogressbar_selectors(self) -> None:
        """Generated stylesheet contains required Qt CSS selectors."""
        style = get_progress_bar_style()

        assert re.search(r"QProgressBar\s*{", style) is not None
        assert re.search(r"QProgressBar::chunk\s*{", style) is not None


    def test_get_progress_bar_style_zero_border_width(self) -> None:
        """Border width of 0 is valid and applied."""
        style = get_progress_bar_style(border_width=0)

        assert "border: 0px" in style


    def test_get_progress_bar_style_large_border_radius(self) -> None:
        """Large border radius values work correctly."""
        style = get_progress_bar_style(border_radius=100)

        assert "border-radius: 100px" in style


    def test_get_default_progress_bar_style_returns_valid_stylesheet(self) -> None:
        """Default progress bar style function returns valid stylesheet."""
        style = get_default_progress_bar_style()

        assert isinstance(style, str)
        assert len(style) > 0
        assert "QProgressBar" in style
        assert "QProgressBar::chunk" in style


    def test_get_default_progress_bar_style_uses_expected_colors(self) -> None:
        """Default style uses expected color scheme."""
        style = get_default_progress_bar_style()

        assert "#444" in style or "#2a2a2a" in style or "#0d7377" in style


    def test_get_splash_progress_bar_style_returns_valid_stylesheet(self) -> None:
        """Splash screen progress bar style returns valid stylesheet."""
        style = get_splash_progress_bar_style()

        assert isinstance(style, str)
        assert len(style) > 0
        assert "QProgressBar" in style
        assert "QProgressBar::chunk" in style


    def test_get_splash_progress_bar_style_uses_green_theme(self) -> None:
        """Splash style uses green color scheme."""
        style = get_splash_progress_bar_style()

        assert "#4CAF50" in style.upper() or "GREEN" in style.upper()


    def test_get_splash_progress_bar_style_different_from_default(self) -> None:
        """Splash style is different from default style."""
        default_style = get_default_progress_bar_style()
        splash_style = get_splash_progress_bar_style()

        assert default_style != splash_style


class TestProgressBarStyleCSSProperties:
    """Test specific CSS properties in generated stylesheets."""

    def test_progress_bar_has_text_alignment(self) -> None:
        """Progress bar stylesheet includes text alignment."""
        style = get_progress_bar_style()

        assert "text-align:" in style
        assert "center" in style


    def test_progress_bar_chunk_has_background_color(self) -> None:
        """Progress bar chunk has background color defined."""
        style = get_progress_bar_style()

        chunk_match = re.search(
            r"QProgressBar::chunk\s*{([^}]+)}",
            style,
            re.DOTALL
        )
        assert chunk_match is not None

        chunk_properties = chunk_match.group(1)
        assert "background-color:" in chunk_properties


    def test_progress_bar_chunk_has_border_radius(self) -> None:
        """Progress bar chunk has border radius defined."""
        style = get_progress_bar_style()

        chunk_match = re.search(
            r"QProgressBar::chunk\s*{([^}]+)}",
            style,
            re.DOTALL
        )
        assert chunk_match is not None

        chunk_properties = chunk_match.group(1)
        assert "border-radius:" in chunk_properties


class TestStyleUtilsColorValues:
    """Test color value handling in style utilities."""

    def test_hex_colors_with_hash_are_preserved(self) -> None:
        """Hex colors with # prefix are preserved correctly."""
        style = get_progress_bar_style(
            border_color="#123456",
            background_color="#abcdef",
            chunk_color="#fedcba",
        )

        assert "#123456" in style
        assert "#abcdef" in style
        assert "#fedcba" in style


    def test_named_colors_work_correctly(self) -> None:
        """Named CSS colors work correctly in stylesheets."""
        style = get_progress_bar_style(
            border_color="red",
            background_color="blue",
            chunk_color="green",
        )

        assert "red" in style
        assert "blue" in style
        assert "green" in style


    def test_rgb_colors_work_correctly(self) -> None:
        """RGB color values work correctly in stylesheets."""
        style = get_progress_bar_style(
            border_color="rgb(255, 0, 0)",
            background_color="rgb(0, 255, 0)",
            chunk_color="rgb(0, 0, 255)",
        )

        assert "rgb(255, 0, 0)" in style
        assert "rgb(0, 255, 0)" in style
        assert "rgb(0, 0, 255)" in style


    def test_rgba_colors_with_transparency(self) -> None:
        """RGBA color values with transparency work correctly."""
        style = get_progress_bar_style(
            border_color="rgba(255, 0, 0, 0.5)",
            background_color="rgba(0, 255, 0, 0.8)",
        )

        assert "rgba(255, 0, 0, 0.5)" in style
        assert "rgba(0, 255, 0, 0.8)" in style


class TestStyleUtilsEdgeCases:
    """Test edge cases and unusual inputs for style utilities."""

    def test_negative_border_width_still_generates_style(self) -> None:
        """Negative border width value still generates valid stylesheet."""
        style = get_progress_bar_style(border_width=-1)

        assert isinstance(style, str)
        assert "QProgressBar" in style


    def test_negative_border_radius_still_generates_style(self) -> None:
        """Negative border radius value still generates valid stylesheet."""
        style = get_progress_bar_style(border_radius=-5)

        assert isinstance(style, str)
        assert "QProgressBar" in style


    def test_very_large_numeric_values(self) -> None:
        """Very large numeric values generate valid stylesheets."""
        style = get_progress_bar_style(
            border_width=999999,
            border_radius=999999,
        )

        assert isinstance(style, str)
        assert "QProgressBar" in style


    def test_empty_string_colors(self) -> None:
        """Empty string color values generate stylesheets."""
        style = get_progress_bar_style(
            border_color="",
            background_color="",
            chunk_color="",
        )

        assert isinstance(style, str)
        assert "QProgressBar" in style


class TestStyleUtilsConsistency:
    """Test consistency across multiple style generations."""

    def test_same_parameters_produce_identical_styles(self) -> None:
        """Same parameters produce identical stylesheets."""
        style1 = get_progress_bar_style(
            border_width=2,
            border_color="#fff",
            background_color="#000",
            chunk_color="#f00",
            border_radius=5,
        )
        style2 = get_progress_bar_style(
            border_width=2,
            border_color="#fff",
            background_color="#000",
            chunk_color="#f00",
            border_radius=5,
        )

        assert style1 == style2


    def test_default_style_is_consistent(self) -> None:
        """Default style is consistent across calls."""
        style1 = get_default_progress_bar_style()
        style2 = get_default_progress_bar_style()

        assert style1 == style2


    def test_splash_style_is_consistent(self) -> None:
        """Splash style is consistent across calls."""
        style1 = get_splash_progress_bar_style()
        style2 = get_splash_progress_bar_style()

        assert style1 == style2
