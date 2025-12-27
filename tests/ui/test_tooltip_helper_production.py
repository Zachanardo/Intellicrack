"""Production tests for tooltip helper.

Tests tooltip definition retrieval and content validation.
"""

import pytest

from intellicrack.ui.tooltip_helper import get_tooltip_definitions


def test_get_tooltip_definitions_returns_dict() -> None:
    """Test tooltip definitions are returned as dictionary."""
    tooltips = get_tooltip_definitions()

    assert isinstance(tooltips, dict)
    assert len(tooltips) > 0


def test_tooltip_definitions_have_content() -> None:
    """Test all tooltip definitions have non-empty content."""
    tooltips = get_tooltip_definitions()

    for key, value in tooltips.items():
        assert isinstance(key, str)
        assert isinstance(value, str)
        assert len(key) > 0
        assert len(value) > 0


def test_tooltip_contains_static_analysis() -> None:
    """Test tooltips include static analysis buttons."""
    tooltips = get_tooltip_definitions()

    assert "Run Full Static Analysis" in tooltips
    assert "Disassemble" in tooltips
    assert "View CFG" in tooltips
    assert "Find ROP Gadgets" in tooltips


def test_tooltip_contains_protection_detection() -> None:
    """Test tooltips include protection detection."""
    tooltips = get_tooltip_definitions()

    assert "Scan for All Known Protections" in tooltips
    assert "Detect Packing/Obfuscation" in tooltips
    assert "Detect Commercial Protections" in tooltips


def test_tooltip_contains_protection_bypass() -> None:
    """Test tooltips include protection bypass options."""
    tooltips = get_tooltip_definitions()

    assert "Bypass TPM Protection" in tooltips


def test_tooltip_content_format() -> None:
    """Test tooltip content is properly formatted."""
    tooltips = get_tooltip_definitions()

    for key, value in tooltips.items():
        assert not value.startswith(" ")
        assert not value.endswith(" ")


def test_tooltip_descriptions_are_informative() -> None:
    """Test tooltip descriptions contain useful information."""
    tooltips = get_tooltip_definitions()

    static_analysis_tooltip = tooltips["Run Full Static Analysis"]
    assert "analysis" in static_analysis_tooltip.lower()
    assert "binary" in static_analysis_tooltip.lower()

    disassemble_tooltip = tooltips["Disassemble"]
    assert "assembly" in disassemble_tooltip.lower() or "instruction" in disassemble_tooltip.lower()


def test_tooltip_keys_are_unique() -> None:
    """Test all tooltip keys are unique."""
    tooltips = get_tooltip_definitions()

    keys = list(tooltips.keys())
    unique_keys = set(keys)

    assert len(keys) == len(unique_keys)


def test_tooltip_values_are_unique() -> None:
    """Test tooltip values are mostly unique."""
    tooltips = get_tooltip_definitions()

    values = list(tooltips.values())

    assert len(set(values)) > len(values) * 0.9
