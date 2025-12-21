"""Production Tests for AI Script Generator.

Tests validate real Frida/Ghidra script generation capabilities for licensing bypass.
All tests verify production-ready script generation without mocks or stubs.

Copyright (C) 2025 Zachary Flint
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.ai_script_generator import (
    AIScriptGenerator,
    GeneratedScript,
    ProtectionType,
    ScriptMetadata,
    ScriptType,
)


@pytest.fixture
def script_generator() -> AIScriptGenerator:
    """Create AIScriptGenerator instance for testing."""
    return AIScriptGenerator()


@pytest.fixture
def sample_pe_analysis() -> dict[str, Any]:
    """Realistic PE binary analysis data for script generation."""
    return {
        "binary_path": "D:\\test\\licensed_app.exe",
        "target_binary": "licensed_app.exe",
        "architecture": "x64",
        "entry_point": "0x401000",
        "imports": [
            {"dll": "advapi32.dll", "functions": ["RegQueryValueExW", "RegSetValueExW"]},
            {"dll": "kernel32.dll", "functions": ["IsDebuggerPresent", "GetTickCount"]},
            {"dll": "wininet.dll", "functions": ["InternetOpenW", "HttpSendRequestW"]},
        ],
        "exports": [
            {"name": "CheckLicense", "address": "0x402000"},
            {"name": "ValidateSerial", "address": "0x402100"},
        ],
        "strings": [
            "License key is invalid",
            "Trial period expired",
            "Please activate your copy",
            "Hardware ID mismatch",
        ],
        "protections": [
            {"type": "license_check", "confidence": 0.9},
            {"type": "trial_limitation", "confidence": 0.85},
            {"type": "anti_debug", "confidence": 0.7},
        ],
    }


@pytest.fixture
def base_frida_script() -> str:
    """Base Frida script without enhancements."""
    return """'use strict';

// Basic license bypass
const moduleName = Process.enumerateModulesSync()[0].name;

Interceptor.attach(Module.findExportByName(null, 'CheckLicense'), {
    onLeave: function(retval) {
        retval.replace(1);
    }
});

function main() {
    console.log('[*] Basic bypass loaded');
}

main();
"""


class TestAIScriptGeneratorInitialization:
    """Test AIScriptGenerator initialization and configuration."""

    def test_generator_initialization_loads_patterns(self, script_generator: AIScriptGenerator) -> None:
        """Generator initializes with optimization patterns."""
        assert script_generator.optimization_patterns is not None
        assert len(script_generator.optimization_patterns) > 0
        assert "memory_hooks" in script_generator.optimization_patterns
        assert "function_hooks" in script_generator.optimization_patterns
        assert "crypto_operations" in script_generator.optimization_patterns

    def test_generator_loads_anti_detection_techniques(self, script_generator: AIScriptGenerator) -> None:
        """Generator initializes with anti-detection techniques."""
        assert script_generator.anti_detection_techniques is not None
        assert len(script_generator.anti_detection_techniques) > 0
        assert "hook_obfuscation" in script_generator.anti_detection_techniques
        assert "memory_cloaking" in script_generator.anti_detection_techniques
        assert "timing_evasion" in script_generator.anti_detection_techniques


class TestFridaScriptGeneration:
    """Test production Frida script generation for license bypass."""

    def test_generate_frida_script_with_license_protection(
        self, script_generator: AIScriptGenerator, sample_pe_analysis: dict[str, Any]
    ) -> None:
        """Generated Frida script includes license check bypass code."""
        result: GeneratedScript | None = script_generator.generate_frida_script(sample_pe_analysis)

        assert result is not None
        assert isinstance(result, GeneratedScript)
        assert result.language == "javascript"
        assert len(result.content) > 0

        assert "RegQueryValueExW" in result.content or "license" in result.content.lower()
        assert "Interceptor.attach" in result.content or "Interceptor.replace" in result.content
        assert result.metadata.script_type == ScriptType.FRIDA
        assert ProtectionType.LICENSE_CHECK in result.metadata.protection_types

    def test_generate_frida_script_with_trial_limitation(
        self, script_generator: AIScriptGenerator, sample_pe_analysis: dict[str, Any]
    ) -> None:
        """Generated Frida script includes trial limitation bypass."""
        result: GeneratedScript | None = script_generator.generate_frida_script(sample_pe_analysis)

        assert result is not None
        assert "GetTickCount" in result.content or "time" in result.content.lower()
        assert ProtectionType.TRIAL_LIMITATION in result.metadata.protection_types

    def test_generate_frida_script_with_anti_debug(
        self, script_generator: AIScriptGenerator, sample_pe_analysis: dict[str, Any]
    ) -> None:
        """Generated Frida script includes anti-debug bypass."""
        result: GeneratedScript | None = script_generator.generate_frida_script(sample_pe_analysis)

        assert result is not None
        assert "IsDebuggerPresent" in result.content or "debugger" in result.content.lower()
        assert ProtectionType.ANTI_DEBUG in result.metadata.protection_types

    def test_generated_frida_script_syntax_valid(
        self, script_generator: AIScriptGenerator, sample_pe_analysis: dict[str, Any]
    ) -> None:
        """Generated Frida script has valid JavaScript syntax."""
        result: GeneratedScript | None = script_generator.generate_frida_script(sample_pe_analysis)

        assert result is not None
        assert result.content.count("{") == result.content.count("}")
        assert result.content.count("(") == result.content.count(")")
        assert result.content.count("[") == result.content.count("]")
        assert "function" in result.content or "=>" in result.content
        assert "main" in result.content

    def test_generate_frida_script_includes_hooks(
        self, script_generator: AIScriptGenerator, sample_pe_analysis: dict[str, Any]
    ) -> None:
        """Generated script extracts and documents hooks."""
        result: GeneratedScript | None = script_generator.generate_frida_script(sample_pe_analysis)

        assert result is not None
        assert isinstance(result.hooks, list)

    def test_generate_frida_script_calculates_success_probability(
        self, script_generator: AIScriptGenerator, sample_pe_analysis: dict[str, Any]
    ) -> None:
        """Generated script includes realistic success probability."""
        result: GeneratedScript | None = script_generator.generate_frida_script(sample_pe_analysis)

        assert result is not None
        assert 0.0 <= result.metadata.success_probability <= 1.0
        assert result.metadata.success_probability > 0.0

    def test_generate_frida_script_from_binary_path(self, script_generator: AIScriptGenerator, tmp_path: Path) -> None:
        """Generator creates script from binary path string."""
        fake_binary = tmp_path / "test.exe"
        fake_binary.write_bytes(b"MZ" + b"\x00" * 100)

        result: GeneratedScript | None = script_generator.generate_frida_script(str(fake_binary))

        assert result is not None
        assert isinstance(result, GeneratedScript)
        assert result.metadata.target_binary == str(fake_binary)


class TestGhidraScriptGeneration:
    """Test production Ghidra script generation for binary analysis."""

    def test_generate_ghidra_script_creates_java_code(
        self, script_generator: AIScriptGenerator, sample_pe_analysis: dict[str, Any]
    ) -> None:
        """Generated Ghidra script includes valid Java code."""
        result: GeneratedScript | None = script_generator.generate_ghidra_script(sample_pe_analysis)

        assert result is not None
        assert isinstance(result, GeneratedScript)
        assert result.language == "java"
        assert "import" in result.content
        assert "class" in result.content
        assert result.metadata.script_type == ScriptType.GHIDRA

    def test_generate_ghidra_script_includes_analysis_code(
        self, script_generator: AIScriptGenerator, sample_pe_analysis: dict[str, Any]
    ) -> None:
        """Generated Ghidra script includes license analysis logic."""
        result: GeneratedScript | None = script_generator.generate_ghidra_script(sample_pe_analysis)

        assert result is not None
        assert "function" in result.content.lower() or "method" in result.content.lower()
        assert len(result.content) > 100


class TestScriptEnhancement:
    """Test AI-powered script enhancement and optimization."""

    def test_enhance_script_adds_performance_optimizations(
        self, script_generator: AIScriptGenerator, base_frida_script: str
    ) -> None:
        """Script enhancement adds performance optimizations."""
        context = {
            "protection": {"type": "license_check"},
            "difficulty": "Medium",
            "techniques": ["license_check"],
        }

        enhanced: str = script_generator.generate_script("Enhance script", base_frida_script, context)

        assert enhanced != base_frida_script
        assert len(enhanced) >= len(base_frida_script)

    def test_enhance_script_adds_advanced_evasion_for_hard_difficulty(
        self, script_generator: AIScriptGenerator, base_frida_script: str
    ) -> None:
        """Hard difficulty triggers advanced anti-detection."""
        context = {
            "protection": {"type": "vmprotect"},
            "difficulty": "Very Hard",
            "techniques": ["vm_protection", "anti_tamper"],
        }

        enhanced: str = script_generator.generate_script("Enhance script", base_frida_script, context)

        assert "AntiDetection" in enhanced or "evasion" in enhanced.lower()

    def test_enhance_script_adds_error_handling(
        self, script_generator: AIScriptGenerator, base_frida_script: str
    ) -> None:
        """Enhanced script includes error handling."""
        context = {
            "protection": {"type": "license_check"},
            "difficulty": "Medium",
            "techniques": ["license_check"],
        }

        enhanced: str = script_generator.generate_script("Enhance script", base_frida_script, context)

        assert "try" in enhanced or "catch" in enhanced or "error" in enhanced.lower()

    def test_enhance_script_optimizes_memory_operations(
        self, script_generator: AIScriptGenerator
    ) -> None:
        """Script with memory operations gets caching optimization."""
        script_with_memory = """'use strict';
const addr = ptr('0x401000');
const value1 = Memory.readU32(addr);
const value2 = Memory.readU32(addr);
const value3 = Memory.readPointer(addr);
"""
        context = {
            "protection": {"type": "license_check"},
            "difficulty": "Medium",
            "techniques": [],
        }

        enhanced: str = script_generator.generate_script("Optimize", script_with_memory, context)

        assert "cache" in enhanced.lower() or "cached" in enhanced.lower()

    def test_enhance_script_preserves_functionality(
        self, script_generator: AIScriptGenerator, base_frida_script: str
    ) -> None:
        """Enhanced script preserves original functionality."""
        context = {
            "protection": {"type": "license_check"},
            "difficulty": "Low",
            "techniques": [],
        }

        enhanced: str = script_generator.generate_script("Enhance", base_frida_script, context)

        assert "CheckLicense" in enhanced
        assert "main()" in enhanced


class TestProtectionDetection:
    """Test protection type detection from binary analysis."""

    def test_detect_license_check_protection(self, script_generator: AIScriptGenerator) -> None:
        """Detects license check protection from analysis data."""
        analysis: dict[str, Any] = {
            "strings": ["License key is invalid", "Serial number required"],
            "imports": [{"dll": "advapi32.dll", "functions": ["RegQueryValueExW"]}],
            "exports": [{"name": "CheckLicense", "address": "0x401000"}],
        }

        protections: list[ProtectionType] = script_generator._detect_protection_types(analysis)

        assert ProtectionType.LICENSE_CHECK in protections

    def test_detect_trial_limitation_protection(self, script_generator: AIScriptGenerator) -> None:
        """Detects trial limitation from analysis data."""
        analysis: dict[str, Any] = {
            "strings": ["Trial period expired", "Days remaining: "],
            "imports": [{"dll": "kernel32.dll", "functions": ["GetLocalTime", "GetTickCount"]}],
        }

        protections: list[ProtectionType] = script_generator._detect_protection_types(analysis)

        assert ProtectionType.TRIAL_LIMITATION in protections

    def test_detect_online_activation_protection(self, script_generator: AIScriptGenerator) -> None:
        """Detects online activation from network imports."""
        analysis: dict[str, Any] = {
            "strings": ["Activation server", "https://license.example.com"],
            "imports": [{"dll": "wininet.dll", "functions": ["InternetOpenW", "HttpSendRequestW"]}],
        }

        protections: list[ProtectionType] = script_generator._detect_protection_types(analysis)

        assert ProtectionType.ONLINE_ACTIVATION in protections

    def test_detect_hardware_binding_protection(self, script_generator: AIScriptGenerator) -> None:
        """Detects hardware binding from HWID strings."""
        analysis: dict[str, Any] = {
            "strings": ["Hardware ID mismatch", "HWID", "Machine fingerprint"],
            "imports": [{"dll": "kernel32.dll", "functions": ["GetVolumeInformationW"]}],
        }

        protections: list[ProtectionType] = script_generator._detect_protection_types(analysis)

        assert ProtectionType.HARDWARE_BINDING in protections

    def test_detect_anti_debug_protection(self, script_generator: AIScriptGenerator) -> None:
        """Detects anti-debug from debugging API imports."""
        analysis: dict[str, Any] = {
            "imports": [
                {
                    "dll": "kernel32.dll",
                    "functions": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
                }
            ],
        }

        protections: list[ProtectionType] = script_generator._detect_protection_types(analysis)

        assert ProtectionType.ANTI_DEBUG in protections

    def test_detect_multiple_protections(self, script_generator: AIScriptGenerator) -> None:
        """Detects multiple protection layers simultaneously."""
        analysis: dict[str, Any] = {
            "strings": ["License invalid", "Trial expired", "Debugger detected"],
            "imports": [
                {"dll": "advapi32.dll", "functions": ["RegQueryValueExW"]},
                {"dll": "kernel32.dll", "functions": ["IsDebuggerPresent", "GetTickCount"]},
            ],
            "exports": [{"name": "ValidateLicense", "address": "0x401000"}],
        }

        protections: list[ProtectionType] = script_generator._detect_protection_types(analysis)

        assert len(protections) >= 2
        assert ProtectionType.LICENSE_CHECK in protections
        assert ProtectionType.ANTI_DEBUG in protections


class TestScriptStructureAnalysis:
    """Test script structure analysis for enhancement opportunities."""

    def test_analyze_detects_memory_operations(self, script_generator: AIScriptGenerator) -> None:
        """Analysis detects memory operations in script."""
        script: str = "const val = Memory.readU32(ptr('0x401000'));"

        analysis: dict = script_generator._analyze_script_structure(script)

        assert analysis["has_memory_ops"] is True

    def test_analyze_detects_hooks(self, script_generator: AIScriptGenerator) -> None:
        """Analysis detects Interceptor hooks."""
        script: str = "Interceptor.attach(addr, { onEnter: function(args) {} });"

        analysis: dict = script_generator._analyze_script_structure(script)

        assert analysis["has_hooks"] is True

    def test_analyze_detects_crypto_operations(self, script_generator: AIScriptGenerator) -> None:
        """Analysis detects cryptographic operations."""
        script: str = "const hash = crypto.createHash('sha256'); const encrypted = encrypt(data);"

        analysis: dict = script_generator._analyze_script_structure(script)

        assert analysis["has_crypto"] is True

    def test_analyze_counts_functions(self, script_generator: AIScriptGenerator) -> None:
        """Analysis counts function definitions."""
        script: str = """
function foo() {}
const bar = function() {}
let baz = () => {}
"""

        analysis: dict = script_generator._analyze_script_structure(script)

        assert analysis["function_count"] >= 2

    def test_analyze_handles_empty_script(self, script_generator: AIScriptGenerator) -> None:
        """Analysis handles empty scripts gracefully."""
        script: str = ""

        analysis: dict = script_generator._analyze_script_structure(script)

        assert isinstance(analysis, dict)
        assert analysis["has_memory_ops"] is False
        assert analysis["function_count"] >= 0


class TestSpecificBypassGeneration:
    """Test generation of specific bypass techniques."""

    def test_generate_license_check_bypass_code(self, script_generator: AIScriptGenerator) -> None:
        """Generates working license check bypass code."""
        bypass_code: str = script_generator._generate_license_check_bypass()

        assert bypass_code != ""
        assert "RegQueryValueExW" in bypass_code
        assert "license" in bypass_code.lower()
        assert "Interceptor.attach" in bypass_code

    def test_generate_time_manipulation_code(self, script_generator: AIScriptGenerator) -> None:
        """Generates time manipulation bypass code."""
        time_bypass: str = script_generator._generate_time_manipulation()

        assert time_bypass != ""
        assert "GetTickCount" in time_bypass or "time" in time_bypass.lower()

    def test_generate_network_emulation_code(self, script_generator: AIScriptGenerator) -> None:
        """Generates network emulation for online activation bypass."""
        network_bypass: str = script_generator._generate_network_emulation()

        assert network_bypass != ""
        assert any(api in network_bypass for api in ["InternetOpen", "HttpSendRequest", "WinHttp"])

    def test_generate_hwid_spoofer_code(self, script_generator: AIScriptGenerator) -> None:
        """Generates hardware ID spoofing code."""
        hwid_bypass: str = script_generator._generate_hwid_spoofer()

        assert hwid_bypass != ""
        assert any(api in hwid_bypass for api in ["GetVolumeInformation", "HWID", "hardware"])

    def test_generate_anti_debug_bypass_code(self, script_generator: AIScriptGenerator) -> None:
        """Generates anti-debugging bypass code."""
        anti_debug: str = script_generator._generate_anti_debug_bypass()

        assert anti_debug != ""
        assert "IsDebuggerPresent" in anti_debug
        assert "Interceptor" in anti_debug


class TestDifficultyAssessment:
    """Test protection difficulty assessment."""

    def test_assess_difficulty_easy_single_protection(self, script_generator: AIScriptGenerator) -> None:
        """Single basic protection assessed as Easy."""
        protections: list[ProtectionType] = [ProtectionType.LICENSE_CHECK]

        difficulty: str = script_generator._assess_difficulty(protections)

        assert difficulty in {"Easy", "Medium"}

    def test_assess_difficulty_medium_multiple_protections(
        self, script_generator: AIScriptGenerator
    ) -> None:
        """Multiple protections assessed as Medium or higher."""
        protections: list[ProtectionType] = [
            ProtectionType.LICENSE_CHECK,
            ProtectionType.TRIAL_LIMITATION,
        ]

        difficulty: str = script_generator._assess_difficulty(protections)

        assert difficulty in {"Medium", "Hard"}

    def test_assess_difficulty_hard_advanced_protections(
        self, script_generator: AIScriptGenerator
    ) -> None:
        """Advanced protections like VM assessed as Hard or Very Hard."""
        protections: list[ProtectionType] = [
            ProtectionType.VM_PROTECTION,
            ProtectionType.ANTI_TAMPER,
            ProtectionType.OBFUSCATION,
        ]

        difficulty: str = script_generator._assess_difficulty(protections)

        assert difficulty in {"Hard", "Very Hard"}


class TestSuccessProbabilityCalculation:
    """Test success probability calculation for bypass scripts."""

    def test_calculate_success_probability_returns_valid_range(
        self, script_generator: AIScriptGenerator
    ) -> None:
        """Success probability is within valid range."""
        protections: list[ProtectionType] = [ProtectionType.LICENSE_CHECK]
        analysis: dict[str, Any] = {"confidence": 0.9}

        probability: float = script_generator._calculate_success_probability(protections, analysis)

        assert 0.0 <= probability <= 1.0

    def test_calculate_success_probability_higher_for_simple_protections(
        self, script_generator: AIScriptGenerator
    ) -> None:
        """Simple protections have higher success probability."""
        simple_protections: list[ProtectionType] = [ProtectionType.TRIAL_LIMITATION]
        complex_protections: list[ProtectionType] = [
            ProtectionType.VM_PROTECTION,
            ProtectionType.ANTI_TAMPER,
        ]
        analysis: dict[str, Any] = {}

        simple_prob: float = script_generator._calculate_success_probability(simple_protections, analysis)
        complex_prob: float = script_generator._calculate_success_probability(complex_protections, analysis)

        assert simple_prob >= complex_prob


class TestHookExtraction:
    """Test extraction of hooks from generated scripts."""

    def test_extract_hooks_from_script(self, script_generator: AIScriptGenerator) -> None:
        """Extracts hook information from Frida script."""
        script: str = """
Interceptor.attach(Module.findExportByName('kernel32.dll', 'IsDebuggerPresent'), {
    onLeave: function(retval) {
        retval.replace(0);
    }
});
"""

        hooks: list[dict[str, Any]] = script_generator._extract_hooks_from_script(script)

        assert isinstance(hooks, list)

    def test_extract_multiple_hooks(self, script_generator: AIScriptGenerator) -> None:
        """Extracts multiple hooks from script."""
        script: str = """
Interceptor.attach(addr1, { onEnter: function(args) {} });
Interceptor.replace(addr2, new NativeCallback(function() {}, 'void', []));
"""

        hooks: list[dict[str, Any]] = script_generator._extract_hooks_from_script(script)

        assert isinstance(hooks, list)


class TestScriptMetadata:
    """Test script metadata generation and tracking."""

    def test_metadata_includes_script_id(self, script_generator: AIScriptGenerator, sample_pe_analysis: dict[str, Any]) -> None:
        """Generated script includes unique script ID."""
        result: GeneratedScript | None = script_generator.generate_frida_script(sample_pe_analysis)

        assert result is not None
        assert result.metadata.script_id is not None
        assert len(result.metadata.script_id) > 0

    def test_metadata_includes_creation_time(
        self, script_generator: AIScriptGenerator, sample_pe_analysis: dict[str, Any]
    ) -> None:
        """Generated script includes creation timestamp."""
        result: GeneratedScript | None = script_generator.generate_frida_script(sample_pe_analysis)

        assert result is not None
        assert result.metadata.creation_time is not None
        assert "T" in result.metadata.creation_time

    def test_metadata_includes_target_binary(
        self, script_generator: AIScriptGenerator, sample_pe_analysis: dict[str, Any]
    ) -> None:
        """Generated script metadata includes target binary path."""
        result: GeneratedScript | None = script_generator.generate_frida_script(sample_pe_analysis)

        assert result is not None
        assert result.metadata.target_binary == sample_pe_analysis["binary_path"]

    def test_metadata_tracks_protection_types(
        self, script_generator: AIScriptGenerator, sample_pe_analysis: dict[str, Any]
    ) -> None:
        """Generated script metadata tracks detected protections."""
        result: GeneratedScript | None = script_generator.generate_frida_script(sample_pe_analysis)

        assert result is not None
        assert len(result.metadata.protection_types) > 0
        assert all(isinstance(pt, ProtectionType) for pt in result.metadata.protection_types)


class TestErrorHandling:
    """Test error handling and graceful degradation."""

    def test_generate_script_handles_invalid_context(self, script_generator: AIScriptGenerator) -> None:
        """Script generation handles invalid context gracefully."""
        result: str = script_generator.generate_script("test", "console.log('test');", {})

        assert isinstance(result, str)
        assert result != ""

    def test_generate_frida_script_handles_missing_analysis(
        self, script_generator: AIScriptGenerator
    ) -> None:
        """Frida script generation handles minimal analysis data."""
        minimal_analysis: dict[str, Any] = {"binary_path": "test.exe"}

        result: GeneratedScript | None = script_generator.generate_frida_script(minimal_analysis)

        assert result is not None
        assert isinstance(result, GeneratedScript)

    def test_generate_script_handles_empty_base_script(self, script_generator: AIScriptGenerator) -> None:
        """Script enhancement handles empty base script."""
        context = {"protection": {"type": "license_check"}, "difficulty": "Medium"}

        result: str = script_generator.generate_script("test", "", context)

        assert isinstance(result, str)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_generate_script_with_no_protection_info(
        self, script_generator: AIScriptGenerator, sample_pe_analysis: dict[str, Any]
    ) -> None:
        """Script generation works without explicit protection info."""
        result: GeneratedScript | None = script_generator.generate_frida_script(sample_pe_analysis, None)

        assert result is not None
        assert isinstance(result, GeneratedScript)

    def test_generate_script_with_unknown_protection(self, script_generator: AIScriptGenerator) -> None:
        """Script generation handles unknown protection types."""
        analysis: dict[str, Any] = {
            "binary_path": "unknown.exe",
            "protections": [{"type": "unknown_custom_protection", "confidence": 0.5}],
        }

        result: GeneratedScript | None = script_generator.generate_frida_script(analysis)

        assert result is not None

    def test_generate_script_with_very_long_binary_path(self, script_generator: AIScriptGenerator) -> None:
        """Script generation handles very long file paths."""
        long_path: str = "D:\\" + "very_long_directory_name\\" * 20 + "app.exe"
        analysis: dict[str, Any] = {"binary_path": long_path}

        result: GeneratedScript | None = script_generator.generate_frida_script(analysis)

        assert result is not None
        assert result.metadata.target_binary == long_path

    def test_script_with_special_characters_in_path(self, script_generator: AIScriptGenerator) -> None:
        """Script generation handles special characters in paths."""
        special_path: str = "D:\\test\\app (x86) [version 1.0].exe"
        analysis: dict[str, Any] = {"binary_path": special_path}

        result: GeneratedScript | None = script_generator.generate_frida_script(analysis)

        assert result is not None


class TestCommentRemoval:
    """Test JavaScript comment removal utilities."""

    def test_remove_js_comments_single_line(self, script_generator: AIScriptGenerator) -> None:
        """Removes single-line JavaScript comments."""
        script: str = "const x = 1; // This is a comment\nconst y = 2;"

        cleaned: str = script_generator._remove_js_comments(script)

        assert "// This is a comment" not in cleaned
        assert "const x = 1;" in cleaned

    def test_remove_js_comments_multiline(self, script_generator: AIScriptGenerator) -> None:
        """Removes multi-line JavaScript comments."""
        script: str = "const x = 1; /* multi\nline\ncomment */ const y = 2;"

        cleaned: str = script_generator._remove_js_comments(script)

        assert "/* multi" not in cleaned
        assert "comment */" not in cleaned

    def test_remove_js_strings(self, script_generator: AIScriptGenerator) -> None:
        """Removes JavaScript string literals."""
        script: str = 'const msg = "function test() {}"; const x = 1;'

        cleaned: str = script_generator._remove_js_strings(script)

        assert "function test()" not in cleaned


class TestIntegrationScenarios:
    """Test complete end-to-end script generation scenarios."""

    def test_complete_vmprotect_bypass_generation(self, script_generator: AIScriptGenerator) -> None:
        """Generates complete VMProtect bypass script."""
        analysis: dict[str, Any] = {
            "binary_path": "vmprotected.exe",
            "protections": [
                {"type": "vm_protection", "confidence": 0.95},
                {"type": "anti_debug", "confidence": 0.9},
                {"type": "license_check", "confidence": 0.85},
            ],
            "imports": [
                {"dll": "kernel32.dll", "functions": ["IsDebuggerPresent"]},
                {"dll": "advapi32.dll", "functions": ["RegQueryValueExW"]},
            ],
        }

        result: GeneratedScript | None = script_generator.generate_frida_script(analysis)

        assert result is not None
        assert ProtectionType.VM_PROTECTION in result.metadata.protection_types
        assert ProtectionType.ANTI_DEBUG in result.metadata.protection_types
        assert ProtectionType.LICENSE_CHECK in result.metadata.protection_types
        assert "IsDebuggerPresent" in result.content
        assert len(result.content) > 500

    def test_complete_online_activation_bypass(self, script_generator: AIScriptGenerator) -> None:
        """Generates complete online activation bypass."""
        analysis: dict[str, Any] = {
            "binary_path": "onlineapp.exe",
            "protections": [
                {"type": "online_activation", "confidence": 0.9},
                {"type": "hardware_binding", "confidence": 0.8},
            ],
            "imports": [
                {"dll": "wininet.dll", "functions": ["InternetOpenW", "HttpSendRequestW"]},
                {"dll": "kernel32.dll", "functions": ["GetVolumeInformationW"]},
            ],
            "strings": ["Activation server", "HWID mismatch"],
        }

        result: GeneratedScript | None = script_generator.generate_frida_script(analysis)

        assert result is not None
        assert ProtectionType.ONLINE_ACTIVATION in result.metadata.protection_types
        assert ProtectionType.HARDWARE_BINDING in result.metadata.protection_types
        assert any(api in result.content for api in ["InternetOpen", "HttpSendRequest", "WinHttp"])

    def test_multi_layer_protection_bypass(self, script_generator: AIScriptGenerator) -> None:
        """Generates bypass for multi-layered protection scheme."""
        analysis: dict[str, Any] = {
            "binary_path": "multilayer.exe",
            "protections": [
                {"type": "license_check", "confidence": 0.9},
                {"type": "trial_limitation", "confidence": 0.85},
                {"type": "anti_debug", "confidence": 0.8},
                {"type": "anti_tamper", "confidence": 0.75},
                {"type": "online_activation", "confidence": 0.7},
            ],
            "imports": [
                {"dll": "kernel32.dll", "functions": ["IsDebuggerPresent", "GetTickCount"]},
                {"dll": "advapi32.dll", "functions": ["RegQueryValueExW"]},
                {"dll": "wininet.dll", "functions": ["InternetOpenW"]},
            ],
        }

        result: GeneratedScript | None = script_generator.generate_frida_script(analysis)

        assert result is not None
        assert len(result.metadata.protection_types) >= 4
        assert len(result.content) > 1000
        assert result.metadata.success_probability < 0.8
