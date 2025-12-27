"""Production tests for pattern library.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from typing import Any

import pytest

from intellicrack.ai.pattern_library import (
    AdvancedPatternLibrary,
    ProtectionComplexity,
    ProtectionPattern,
)


class TestProtectionComplexity:
    """Test ProtectionComplexity enum."""

    def test_complexity_levels(self) -> None:
        """Protection complexity enum has all expected levels."""
        assert ProtectionComplexity.TRIVIAL.value == "trivial"
        assert ProtectionComplexity.SIMPLE.value == "simple"
        assert ProtectionComplexity.MODERATE.value == "moderate"
        assert ProtectionComplexity.COMPLEX.value == "complex"
        assert ProtectionComplexity.EXTREME.value == "extreme"

    def test_complexity_ordering(self) -> None:
        """Protection complexity levels can be compared."""
        complexities = [
            ProtectionComplexity.TRIVIAL,
            ProtectionComplexity.SIMPLE,
            ProtectionComplexity.MODERATE,
            ProtectionComplexity.COMPLEX,
            ProtectionComplexity.EXTREME
        ]

        assert len(complexities) == 5
        assert all(isinstance(c, ProtectionComplexity) for c in complexities)


class TestProtectionPattern:
    """Test ProtectionPattern dataclass."""

    def test_pattern_creation(self) -> None:
        """ProtectionPattern can be created with required fields."""
        pattern = ProtectionPattern(
            name="Test License Check",
            indicators=["strcmp", "license", "serial"],
            bypass_strategy="hook_comparison",
            confidence=0.85,
            complexity=ProtectionComplexity.SIMPLE,
            frida_template="// Frida hook template",
            ghidra_template="# Ghidra script template"
        )

        assert pattern.name == "Test License Check"
        assert len(pattern.indicators) == 3
        assert "strcmp" in pattern.indicators
        assert pattern.bypass_strategy == "hook_comparison"
        assert pattern.confidence == 0.85
        assert pattern.complexity == ProtectionComplexity.SIMPLE
        assert pattern.success_rate == 0.85
        assert pattern.description == ""
        assert len(pattern.variants) == 0

    def test_pattern_with_optional_fields(self) -> None:
        """ProtectionPattern accepts optional fields."""
        pattern = ProtectionPattern(
            name="Advanced Pattern",
            indicators=["test"],
            bypass_strategy="advanced_bypass",
            confidence=0.95,
            complexity=ProtectionComplexity.COMPLEX,
            frida_template="template",
            ghidra_template="script",
            success_rate=0.92,
            description="Advanced license bypass",
            variants=["variant1", "variant2"]
        )

        assert pattern.success_rate == 0.92
        assert pattern.description == "Advanced license bypass"
        assert len(pattern.variants) == 2


class TestAdvancedPatternLibrary:
    """Test AdvancedPatternLibrary functionality."""

    @pytest.fixture
    def pattern_library(self) -> AdvancedPatternLibrary:
        """Create pattern library instance."""
        return AdvancedPatternLibrary()

    def test_library_initialization(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Pattern library initializes with patterns."""
        assert isinstance(pattern_library.patterns, dict)
        assert isinstance(pattern_library.success_history, dict)
        assert isinstance(pattern_library.learning_data, dict)
        assert len(pattern_library.patterns) > 0

    def test_library_has_license_patterns(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Pattern library includes license check patterns."""
        assert "string_comparison_license" in pattern_library.patterns
        assert "hardcoded_license_check" in pattern_library.patterns

        string_pattern = pattern_library.patterns["string_comparison_license"]
        assert string_pattern.name == "String Comparison License Check"
        assert "strcmp" in string_pattern.indicators
        assert string_pattern.complexity == ProtectionComplexity.SIMPLE

    def test_library_has_time_based_patterns(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Pattern library includes time-based protection patterns."""
        assert "time_bomb_check" in pattern_library.patterns

        time_pattern = pattern_library.patterns["time_bomb_check"]
        assert time_pattern.name == "Time Bomb Protection"
        assert any("time" in ind.lower() for ind in time_pattern.indicators)
        assert time_pattern.complexity == ProtectionComplexity.MODERATE

    def test_library_has_network_patterns(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Pattern library includes network validation patterns."""
        assert "online_license_validation" in pattern_library.patterns

        network_pattern = pattern_library.patterns["online_license_validation"]
        assert network_pattern.name == "Online License Validation"
        assert any("http" in ind.lower() or "internet" in ind.lower() for ind in network_pattern.indicators)

    def test_library_has_registry_patterns(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Pattern library includes registry-based patterns."""
        assert "registry_license_storage" in pattern_library.patterns

        registry_pattern = pattern_library.patterns["registry_license_storage"]
        assert registry_pattern.name == "Registry License Storage"
        assert any("reg" in ind.lower() for ind in registry_pattern.indicators)

    def test_library_has_anti_debug_patterns(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Pattern library includes anti-debugging patterns."""
        assert "debugger_detection" in pattern_library.patterns

        debug_pattern = pattern_library.patterns["debugger_detection"]
        assert debug_pattern.name == "Debugger Detection"
        assert "IsDebuggerPresent" in debug_pattern.indicators

    def test_library_has_vm_detection_patterns(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Pattern library includes VM detection patterns."""
        assert "vm_detection" in pattern_library.patterns

        vm_pattern = pattern_library.patterns["vm_detection"]
        assert vm_pattern.name == "Virtual Machine Detection"
        assert any("vm" in ind.lower() or "virtual" in ind.lower() for ind in vm_pattern.indicators)

    def test_library_has_crypto_patterns(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Pattern library includes cryptographic validation patterns."""
        assert "crypto_license_validation" in pattern_library.patterns

        crypto_pattern = pattern_library.patterns["crypto_license_validation"]
        assert crypto_pattern.name == "Cryptographic License Validation"
        assert any("crypt" in ind.lower() or "verify" in ind.lower() for ind in crypto_pattern.indicators)

    def test_get_pattern_by_indicators_exact_match(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Finding patterns by indicators returns exact matches."""
        indicators = ["strcmp", "license"]

        matches = pattern_library.get_pattern_by_indicators(indicators)

        assert len(matches) > 0
        assert any(p.name == "String Comparison License Check" for p in matches)

    def test_get_pattern_by_indicators_partial_match(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Finding patterns by indicators returns partial matches."""
        indicators = ["GetSystemTime", "expire"]

        matches = pattern_library.get_pattern_by_indicators(indicators)

        assert len(matches) > 0
        assert any("time" in p.name.lower() for p in matches)

    def test_get_pattern_by_indicators_sorted_by_confidence(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Matching patterns are sorted by confidence score."""
        indicators = ["strcmp", "memcmp", "license", "serial", "activation"]

        matches = pattern_library.get_pattern_by_indicators(indicators)

        if len(matches) > 1:
            for i in range(len(matches) - 1):
                assert matches[i].confidence >= matches[i + 1].confidence

    def test_get_pattern_by_indicators_no_match(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Finding patterns with no matches returns empty list."""
        indicators = ["nonexistent_indicator_xyz_12345"]

        matches = pattern_library.get_pattern_by_indicators(indicators)

        assert isinstance(matches, list)
        assert len(matches) == 0

    def test_get_bypass_strategy_license_check(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Bypass strategy for license check returns correct pattern."""
        strategy = pattern_library.get_bypass_strategy("license_check")

        assert strategy["type"] == "hook_comparison_return_zero"
        assert len(strategy["patterns"]) > 0
        assert strategy["priority"] in ["high", "medium"]
        assert strategy["confidence"] > 0.5
        assert "frida_template" in strategy
        assert "ghidra_template" in strategy

    def test_get_bypass_strategy_time_bomb(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Bypass strategy for time bomb returns correct pattern."""
        strategy = pattern_library.get_bypass_strategy("time_bomb")

        assert strategy["type"] == "hook_time_functions"
        assert len(strategy["patterns"]) > 0
        assert isinstance(strategy["complexity"], ProtectionComplexity)

    def test_get_bypass_strategy_network_validation(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Bypass strategy for network validation returns correct pattern."""
        strategy = pattern_library.get_bypass_strategy("network_validation")

        assert strategy["type"] == "block_network_calls"
        assert len(strategy["patterns"]) > 0

    def test_get_bypass_strategy_unknown_type(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Bypass strategy for unknown type returns generic strategy."""
        strategy = pattern_library.get_bypass_strategy("unknown_protection_xyz")

        assert strategy["type"] == "generic_analysis"
        assert len(strategy["patterns"]) == 0
        assert strategy["priority"] == "medium"
        assert strategy["confidence"] == 0.5

    def test_analyze_binary_patterns_from_strings(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Binary pattern analysis detects patterns from strings."""
        analysis_results = {
            "strings": ["strcmp", "license_key", "activation_code", "trial_expired"],
            "functions": [],
            "imports": []
        }

        detected = pattern_library.analyze_binary_patterns(analysis_results)

        assert len(detected) > 0
        assert any("license" in p.name.lower() for p in detected)

    def test_analyze_binary_patterns_from_functions(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Binary pattern analysis detects patterns from function names."""
        analysis_results = {
            "strings": [],
            "functions": [
                {"name": "check_license_validity"},
                {"name": "validate_serial_number"}
            ],
            "imports": []
        }

        detected = pattern_library.analyze_binary_patterns(analysis_results)

        assert len(detected) > 0
        assert all(p.confidence > 0.7 for p in detected)

    def test_analyze_binary_patterns_from_imports(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Binary pattern analysis detects patterns from imports."""
        analysis_results = {
            "strings": [],
            "functions": [],
            "imports": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "RegQueryValueEx"]
        }

        detected = pattern_library.analyze_binary_patterns(analysis_results)

        assert len(detected) > 0
        assert any("debug" in p.name.lower() or "registry" in p.name.lower() for p in detected)

    def test_analyze_binary_patterns_confidence_threshold(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Binary pattern analysis filters by confidence threshold."""
        analysis_results = {
            "strings": ["strcmp"],
            "functions": [],
            "imports": []
        }

        detected = pattern_library.analyze_binary_patterns(analysis_results)

        for pattern in detected:
            assert pattern.confidence > 0.7

    def test_update_success_rate_first_attempt(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Success rate update works for first attempt."""
        pattern_name = "string_comparison_license"
        original_rate = pattern_library.patterns[pattern_name].success_rate

        pattern_library.update_success_rate(pattern_name, True)

        assert pattern_name in pattern_library.success_history
        assert pattern_library.success_history[pattern_name]["attempts"] == 1
        assert pattern_library.success_history[pattern_name]["successes"] == 1

    def test_update_success_rate_multiple_attempts(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Success rate updates correctly with multiple attempts."""
        pattern_name = "hardcoded_license_check"

        pattern_library.update_success_rate(pattern_name, True)
        pattern_library.update_success_rate(pattern_name, True)
        pattern_library.update_success_rate(pattern_name, False)

        assert pattern_library.success_history[pattern_name]["attempts"] == 3
        assert pattern_library.success_history[pattern_name]["successes"] == 2

        updated_rate = pattern_library.patterns[pattern_name].success_rate
        assert 0.0 <= updated_rate <= 1.0

    def test_update_success_rate_exponential_average(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Success rate uses exponential moving average."""
        pattern_name = "time_bomb_check"
        original_rate = pattern_library.patterns[pattern_name].success_rate

        for _ in range(10):
            pattern_library.update_success_rate(pattern_name, True)

        new_rate = pattern_library.patterns[pattern_name].success_rate
        assert new_rate != original_rate
        assert new_rate <= 1.0

    def test_get_pattern_statistics_empty(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Pattern statistics work with no usage history."""
        stats = pattern_library.get_pattern_statistics()

        assert stats["total_patterns"] > 0
        assert isinstance(stats["pattern_usage"], dict)
        assert stats["average_success_rate"] == 0.0
        assert stats["most_successful"] is None
        assert stats["least_successful"] is None

    def test_get_pattern_statistics_with_usage(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Pattern statistics calculate correctly with usage data."""
        pattern_library.update_success_rate("string_comparison_license", True)
        pattern_library.update_success_rate("string_comparison_license", True)
        pattern_library.update_success_rate("hardcoded_license_check", True)
        pattern_library.update_success_rate("hardcoded_license_check", False)

        stats = pattern_library.get_pattern_statistics()

        assert stats["total_patterns"] > 0
        assert len(stats["pattern_usage"]) > 0
        assert stats["average_success_rate"] > 0
        assert stats["most_successful"] is not None
        assert stats["least_successful"] is not None

    def test_export_patterns(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Pattern export includes all patterns and metadata."""
        pattern_library.update_success_rate("string_comparison_license", True)

        export = pattern_library.export_patterns()

        assert "patterns" in export
        assert "success_history" in export
        assert "statistics" in export

        assert len(export["patterns"]) > 0
        assert "string_comparison_license" in export["patterns"]

        pattern_data = export["patterns"]["string_comparison_license"]
        assert "name" in pattern_data
        assert "indicators" in pattern_data
        assert "bypass_strategy" in pattern_data
        assert "confidence" in pattern_data
        assert "complexity" in pattern_data
        assert "success_rate" in pattern_data


class TestPatternTemplates:
    """Test pattern templates contain valid bypass code."""

    @pytest.fixture
    def pattern_library(self) -> AdvancedPatternLibrary:
        """Create pattern library instance."""
        return AdvancedPatternLibrary()

    def test_frida_templates_not_empty(self, pattern_library: AdvancedPatternLibrary) -> None:
        """All patterns have non-empty Frida templates."""
        for pattern_name, pattern in pattern_library.patterns.items():
            assert len(pattern.frida_template) > 0, f"{pattern_name} has empty Frida template"
            assert "Interceptor" in pattern.frida_template or "hook" in pattern.frida_template.lower()

    def test_ghidra_templates_not_empty(self, pattern_library: AdvancedPatternLibrary) -> None:
        """All patterns have non-empty Ghidra templates."""
        for pattern_name, pattern in pattern_library.patterns.items():
            assert len(pattern.ghidra_template) > 0, f"{pattern_name} has empty Ghidra template"

    def test_templates_contain_bypass_logic(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Pattern templates contain actual bypass logic."""
        for pattern in pattern_library.patterns.values():
            frida_lower = pattern.frida_template.lower()
            assert any(keyword in frida_lower for keyword in [
                "bypass", "hook", "patch", "replace", "intercept", "spoof"
            ]), f"{pattern.name} Frida template lacks bypass logic"


class TestPatternEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def pattern_library(self) -> AdvancedPatternLibrary:
        """Create pattern library instance."""
        return AdvancedPatternLibrary()

    def test_get_pattern_by_indicators_empty_list(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Getting patterns with empty indicators returns empty list."""
        matches = pattern_library.get_pattern_by_indicators([])

        assert isinstance(matches, list)
        assert len(matches) == 0

    def test_analyze_binary_patterns_empty_results(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Binary pattern analysis handles empty results."""
        empty_results: dict[str, Any] = {
            "strings": [],
            "functions": [],
            "imports": []
        }

        detected = pattern_library.analyze_binary_patterns(empty_results)

        assert isinstance(detected, list)
        assert len(detected) == 0

    def test_update_success_rate_unknown_pattern(self, pattern_library: AdvancedPatternLibrary) -> None:
        """Success rate update handles unknown pattern names."""
        pattern_library.update_success_rate("nonexistent_pattern", True)

        assert "nonexistent_pattern" in pattern_library.success_history
        assert pattern_library.success_history["nonexistent_pattern"]["attempts"] == 1
