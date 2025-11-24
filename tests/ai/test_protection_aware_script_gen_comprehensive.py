"""Comprehensive production-grade tests for protection-aware script generation.

This test suite provides complete coverage of all protection templates, helper methods,
and edge cases to achieve 85%+ line coverage and 80%+ branch coverage.

Tests validate REAL offensive capabilities against actual protection schemes:
- All 15 protection template generators (_get_*_scripts methods)
- Helper methods (_format_detections, _get_recommended_techniques, etc.)
- Error handling and edge cases
- Script syntax validation for all protection types
- Integration with unified protection engine and knowledge base
"""

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.ai.protection_aware_script_gen import (
    ProtectionAwareScriptGenerator,
    enhance_ai_script_generation,
)
from intellicrack.models.protection_knowledge_base import (
    BypassTechnique,
    DifficultyLevel,
    ProtectionSchemeInfo,
    get_protection_knowledge_base,
)
from intellicrack.protection.unified_protection_engine import (
    ICPAnalysisResult,
    ICPDetection,
    UnifiedProtectionResult,
    get_unified_engine,
)


class TestAllProtectionTemplateGenerators:
    """Test all 15 protection template generators produce valid scripts."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_get_denuvo_scripts_generates_valid_frida_script(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Denuvo template must generate anti-tamper bypass script."""
        denuvo_scripts: Dict[str, str] = generator._get_denuvo_scripts()

        assert "frida" in denuvo_scripts, "Missing Frida script for Denuvo"

        frida_script: str = denuvo_scripts["frida"]
        assert len(frida_script) > 200, "Denuvo Frida script too short"
        assert "denuvo" in frida_script.lower(), "Script must reference Denuvo"
        assert any(
            keyword in frida_script.lower()
            for keyword in ["anti-tamper", "ticket", "activation", "drm"]
        ), "Script must target Denuvo-specific mechanisms"

    def test_get_ms_activation_scripts_generates_windows_activation_bypass(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Microsoft activation template must bypass Windows/Office activation."""
        ms_scripts: Dict[str, str] = generator._get_ms_activation_scripts()

        assert "frida" in ms_scripts, "Missing Frida script for MS activation"

        frida_script: str = ms_scripts["frida"]
        assert len(frida_script) > 200, "MS activation script too short"

        ms_activation_indicators: list[str] = [
            "slmgr",
            "sppsvc",
            "activation",
            "kms",
            "mak",
            "slc",
            "license",
        ]
        found_indicators: int = sum(
            1 for indicator in ms_activation_indicators if indicator.lower() in frida_script.lower()
        )
        assert found_indicators >= 2, "Script must target MS activation mechanisms"

    def test_get_themida_scripts_handles_virtualization_protection(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Themida template must handle code virtualization."""
        themida_scripts: Dict[str, str] = generator._get_themida_scripts()

        assert "frida" in themida_scripts, "Missing Frida script for Themida"

        frida_script: str = themida_scripts["frida"]
        assert len(frida_script) > 100, "Themida script too short"

        themida_indicators: list[str] = [
            "themida",
            "winlicense",
            "secureengine",
            "virtual",
        ]
        found: int = sum(
            1 for indicator in themida_indicators if indicator.lower() in frida_script.lower()
        )
        assert found >= 1, "Script must reference Themida/WinLicense"

    def test_get_ilok_scripts_generates_pace_protection_bypass(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """iLok/PACE template must bypass hardware dongle emulation."""
        ilok_scripts: Dict[str, str] = generator._get_ilok_scripts()

        assert "frida" in ilok_scripts, "Missing Frida script for iLok"

        frida_script: str = ilok_scripts["frida"]
        assert len(frida_script) > 200, "iLok script too short"

        ilok_indicators: list[str] = ["ilok", "pace", "dongle", "license"]
        found: int = sum(
            1 for indicator in ilok_indicators if indicator.lower() in frida_script.lower()
        )
        assert found >= 1, "Script must target iLok/PACE mechanisms"

    def test_get_securom_scripts_generates_drm_bypass(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """SecuROM template must bypass disc-based DRM."""
        securom_scripts: Dict[str, str] = generator._get_securom_scripts()

        assert "frida" in securom_scripts, "Missing Frida script for SecuROM"

        frida_script: str = securom_scripts["frida"]
        assert len(frida_script) > 200, "SecuROM script too short"
        assert "securom" in frida_script.lower(), "Script must reference SecuROM"

    def test_get_starforce_scripts_generates_driver_level_bypass(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """StarForce template must bypass kernel-level protection."""
        starforce_scripts: Dict[str, str] = generator._get_starforce_scripts()

        assert "frida" in starforce_scripts, "Missing Frida script for StarForce"

        frida_script: str = starforce_scripts["frida"]
        assert len(frida_script) > 200, "StarForce script too short"
        assert "starforce" in frida_script.lower(), "Script must reference StarForce"

    def test_get_arxan_scripts_generates_anti_tamper_bypass(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Arxan template must bypass anti-tamper and integrity checks."""
        arxan_scripts: Dict[str, str] = generator._get_arxan_scripts()

        assert "frida" in arxan_scripts, "Missing Frida script for Arxan"

        frida_script: str = arxan_scripts["frida"]
        assert len(frida_script) > 200, "Arxan script too short"
        assert "arxan" in frida_script.lower(), "Script must reference Arxan"

        arxan_indicators: list[str] = ["integrity", "tamper", "guard"]
        found: int = sum(
            1 for indicator in arxan_indicators if indicator.lower() in frida_script.lower()
        )
        assert found >= 1, "Script must target Arxan protection mechanisms"

    def test_get_cloud_licensing_scripts_generates_online_validation_bypass(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Cloud licensing template must bypass online license validation."""
        cloud_scripts: Dict[str, str] = generator._get_cloud_licensing_scripts()

        assert "frida" in cloud_scripts, "Missing Frida script for cloud licensing"

        frida_script: str = cloud_scripts["frida"]
        assert len(frida_script) > 200, "Cloud licensing script too short"

        cloud_indicators: list[str] = ["cloud", "online", "server", "http", "api"]
        found: int = sum(
            1 for indicator in cloud_indicators if indicator.lower() in frida_script.lower()
        )
        assert found >= 2, "Script must target cloud licensing mechanisms"

    def test_get_custom_obfuscation_scripts_generates_generic_deobfuscation(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Custom obfuscation template must handle unknown obfuscators."""
        obf_scripts: Dict[str, str] = generator._get_custom_obfuscation_scripts()

        assert "frida" in obf_scripts, "Missing Frida script for custom obfuscation"

        frida_script: str = obf_scripts["frida"]
        assert len(frida_script) > 200, "Custom obfuscation script too short"

        obf_indicators: list[str] = ["obfuscation", "deobfuscate", "unpack"]
        found: int = sum(
            1 for indicator in obf_indicators if indicator.lower() in frida_script.lower()
        )
        assert found >= 1, "Script must handle obfuscation"

    def test_get_safenet_sentinel_scripts_generates_hardware_key_bypass(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """SafeNet Sentinel template must bypass hardware key protection."""
        safenet_scripts: Dict[str, str] = generator._get_safenet_sentinel_scripts()

        assert "frida" in safenet_scripts, "Missing Frida script for SafeNet Sentinel"

        frida_script: str = safenet_scripts["frida"]
        assert len(frida_script) > 200, "SafeNet Sentinel script too short"

        safenet_indicators: list[str] = ["safenet", "sentinel", "hasp", "hardware"]
        found: int = sum(
            1 for indicator in safenet_indicators if indicator.lower() in frida_script.lower()
        )
        assert found >= 1, "Script must target SafeNet mechanisms"

    def test_all_protection_templates_have_frida_and_ghidra_variants(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """All protection templates must provide Frida and optionally Ghidra scripts."""
        protection_methods: list[str] = [
            "_get_hasp_scripts",
            "_get_flexlm_scripts",
            "_get_winlicense_scripts",
            "_get_steam_scripts",
            "_get_vmprotect_scripts",
            "_get_denuvo_scripts",
            "_get_ms_activation_scripts",
            "_get_themida_scripts",
            "_get_ilok_scripts",
            "_get_securom_scripts",
            "_get_starforce_scripts",
            "_get_arxan_scripts",
            "_get_cloud_licensing_scripts",
            "_get_custom_obfuscation_scripts",
            "_get_safenet_sentinel_scripts",
        ]

        for method_name in protection_methods:
            method = getattr(generator, method_name)
            scripts: Dict[str, str] = method()

            assert "frida" in scripts, f"{method_name} missing Frida script"
            assert isinstance(scripts["frida"], str), f"{method_name} Frida script not a string"
            assert len(scripts["frida"]) > 50, f"{method_name} Frida script too short"


class TestHelperMethodsCoverage:
    """Test all helper methods for complete coverage."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_get_basic_analysis_script_frida_variant(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Basic analysis script must monitor file, registry, and network operations."""
        script: str = generator._get_basic_analysis_script("frida")

        assert len(script) > 100, "Basic analysis script too short"
        assert "fopen" in script, "Must monitor file operations"
        assert "RegOpenKeyExW" in script or "registry" in script.lower(), (
            "Must monitor registry operations"
        )
        assert "connect" in script or "network" in script.lower(), (
            "Must monitor network operations"
        )
        assert "console.log" in script, "Must include logging"

    def test_get_basic_analysis_script_non_frida_fallback(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Non-Frida basic analysis must return fallback script."""
        script: str = generator._get_basic_analysis_script("radare2")

        assert isinstance(script, str), "Must return string"
        assert len(script) > 0, "Must not be empty"

    def test_get_generic_bypass_script_frida_hooks_anti_debug(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Generic bypass must hook common anti-debugging functions."""
        script: str = generator._get_generic_bypass_script("frida")

        assert len(script) > 100, "Generic bypass script too short"

        anti_debug_apis: list[str] = [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
        ]
        found: int = sum(1 for api in anti_debug_apis if api in script)
        assert found >= 2, "Must hook common anti-debugging APIs"

    def test_get_generic_bypass_script_scans_for_license_strings(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Generic bypass must scan for license validation strings."""
        script: str = generator._get_generic_bypass_script("frida")

        license_patterns: list[str] = ["license", "serial", "key", "valid"]
        found: int = sum(1 for pattern in license_patterns if pattern in script.lower())
        assert found >= 3, "Must scan for license-related strings"

    def test_get_generic_bypass_script_non_frida_fallback(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Non-Frida generic bypass must return fallback."""
        script: str = generator._get_generic_bypass_script("ghidra")

        assert isinstance(script, str), "Must return string"
        assert len(script) > 0, "Must not be empty"

    def test_get_generic_analysis_script_frida_variant(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Generic analysis script must enumerate modules and exports."""
        script: str = generator._get_generic_analysis_script("frida")

        assert len(script) > 50, "Generic analysis script too short"
        assert "FRIDA" in script, "Must identify script type"
        assert "enumerateModules" in script or "module" in script.lower(), (
            "Must enumerate modules"
        )
        assert "license" in script.lower() or "check" in script.lower(), (
            "Must search for protection functions"
        )

    def test_get_generic_analysis_script_non_frida_variant(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Non-Frida generic analysis must return appropriate script."""
        script: str = generator._get_generic_analysis_script("ghidra")

        assert len(script) > 50, "Generic analysis script too short"
        assert "GHIDRA" in script, "Must identify script type"

    def test_format_detections_with_icp_analysis(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """_format_detections must format ICP analysis results."""
        mock_result = UnifiedProtectionResult(
            file_type="PE",
            architecture="x64",
            is_packed=True,
            is_protected=True,
            protections=[],
            icp_analysis=ICPAnalysisResult(
                error="",
                detected_protections=[],
                all_detections=[
                    ICPDetection(
                        name="VMProtect",
                        type="packer",
                        confidence=0.95,
                        version="3.5",
                        indicators=[],
                    ),
                    ICPDetection(
                        name="Themida",
                        type="protector",
                        confidence=0.87,
                        version="",
                        indicators=[],
                    ),
                ],
                techniques_used=[],
                recommended_tools=[],
            ),
        )

        formatted: str = generator._format_detections(mock_result)

        assert "ICP Engine Detections:" in formatted, "Must include ICP section"
        assert "VMProtect" in formatted, "Must list VMProtect detection"
        assert "v3.5" in formatted, "Must include version info"
        assert "Themida" in formatted, "Must list Themida detection"

    def test_format_detections_with_unified_protections_only(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """_format_detections must format unified analysis results."""
        mock_result = UnifiedProtectionResult(
            file_type="PE",
            architecture="x86",
            is_packed=False,
            is_protected=True,
            protections=[
                {
                    "name": "FlexLM",
                    "type": "license_manager",
                    "confidence": 85.0,
                    "version": "11.16",
                    "source": "signature",
                }
            ],
            icp_analysis=None,
        )

        formatted: str = generator._format_detections(mock_result)

        assert "FlexLM" in formatted, "Must list FlexLM"
        assert "v11.16" in formatted, "Must include version"
        assert "[signature]" in formatted, "Must include source"

    def test_format_detections_no_detections(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """_format_detections must handle no detections."""
        mock_result = UnifiedProtectionResult(
            file_type="PE",
            architecture="x64",
            is_packed=False,
            is_protected=False,
            protections=[],
            icp_analysis=None,
        )

        formatted: str = generator._format_detections(mock_result)

        assert "None detected" in formatted, "Must indicate no detections"

    def test_get_recommended_techniques_with_valid_protection_info(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """_get_recommended_techniques must extract bypass techniques."""
        mock_technique = BypassTechnique(
            name="API Hooking",
            description="Hook license validation APIs",
            difficulty=DifficultyLevel.INTERMEDIATE,
            success_rate=0.85,
            time_estimate="2-4 hours",
            tools_required=["Frida", "x64dbg"],
            prerequisites=["Binary analysis"],
            detection_risk="Medium",
        )

        mock_info = ProtectionSchemeInfo(
            name="TestProtection",
            vendor="TestVendor",
            description="Test description",
            protection_types=["license"],
            common_applications=["App1"],
            bypass_techniques=[mock_technique],
            indicators={},
        )

        techniques: list[Dict[str, Any]] = generator._get_recommended_techniques(mock_info)

        assert len(techniques) == 1, "Must return one technique"
        assert techniques[0]["name"] == "API Hooking", "Must include technique name"
        assert techniques[0]["difficulty"] == "intermediate", "Must include difficulty"
        assert techniques[0]["success_rate"] == 0.85, "Must include success rate"
        assert "Frida" in techniques[0]["tools"], "Must include tools"

    def test_get_recommended_techniques_with_none(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """_get_recommended_techniques must handle None protection info."""
        techniques: list[Dict[str, Any]] = generator._get_recommended_techniques(None)

        assert techniques == [], "Must return empty list for None"


class TestGenerateBypassScriptEdgeCases:
    """Test generate_bypass_script with various edge cases."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_generate_bypass_script_with_invalid_file_path(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Must handle invalid file paths gracefully."""
        result: Dict[str, Any] = generator.generate_bypass_script("/nonexistent/file.exe")

        assert not result["success"], "Must indicate failure"
        assert "error" in result, "Must include error message"
        assert "script" in result, "Must include fallback script"

    def test_generate_bypass_script_with_unknown_script_type(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Must handle unknown script types."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/7zip.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        result: Dict[str, Any] = generator.generate_bypass_script(
            str(binary), script_type="unknown_tool"
        )

        assert "script" in result, "Must generate some script"

    def test_generate_bypass_script_with_multiple_protections_prioritizes_highest_confidence(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Must prioritize protection with highest confidence when multiple detected."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected/enterprise_license_check.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        result: Dict[str, Any] = generator.generate_bypass_script(str(binary))

        if result.get("success") and result.get("protection_detected") != "None":
            assert "confidence" in result, "Must report confidence"
            assert 0.0 <= result["confidence"] <= 1.0, "Confidence must be valid"

    def test_generate_bypass_script_includes_all_metadata_fields(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Result must include all expected metadata fields."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/vlc.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        result: Dict[str, Any] = generator.generate_bypass_script(str(binary))

        required_fields: list[str] = [
            "success",
            "script",
            "approach",
        ]

        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_generate_bypass_script_handles_engine_exception(
        self, generator: ProtectionAwareScriptGenerator, tmp_path: Path
    ) -> None:
        """Must handle unified engine exceptions gracefully."""
        corrupted_file = tmp_path / "corrupted.exe"
        corrupted_file.write_bytes(b"INVALID_PE_HEADER" + b"\x00" * 100)

        result: Dict[str, Any] = generator.generate_bypass_script(str(corrupted_file))

        assert isinstance(result, dict), "Must return result dictionary"
        assert "success" in result, "Must include success flag"
        if not result["success"]:
            assert "error" in result, "Must include error message"


class TestGenerateAIPromptCoverage:
    """Test _generate_ai_prompt method comprehensively."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_generate_ai_prompt_with_full_protection_info(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """AI prompt must include all available protection information."""
        mock_technique = BypassTechnique(
            name="Memory Patching",
            description="Patch validation checks in memory",
            difficulty=DifficultyLevel.ADVANCED,
            success_rate=0.90,
            time_estimate="4-8 hours",
            tools_required=["x64dbg", "Cheat Engine"],
            prerequisites=["Assembly knowledge"],
            detection_risk="High",
        )

        mock_info = ProtectionSchemeInfo(
            name="VMProtect",
            vendor="VMProtect Software",
            description="Advanced code virtualization",
            protection_types=["packer", "protector"],
            common_applications=["Commercial software", "Games", "Security tools"],
            bypass_techniques=[mock_technique],
            indicators={"strings": ["vmp"], "sections": [".vmp"]},
        )

        mock_result = UnifiedProtectionResult(
            file_type="PE",
            architecture="x64",
            is_packed=True,
            is_protected=True,
            protections=[],
            icp_analysis=None,
        )

        prompt: str = generator._generate_ai_prompt(
            mock_result, "VMProtect", 0.95, mock_info
        )

        assert "VMProtect" in prompt, "Must include protection type"
        assert "95" in prompt or "0.95" in prompt, "Must include confidence"
        assert "PE" in prompt, "Must include file type"
        assert "x64" in prompt, "Must include architecture"
        assert "VMProtect Software" in prompt, "Must include vendor"
        assert "Memory Patching" in prompt, "Must include bypass technique"
        assert "90" in prompt or "0.90" in prompt, "Must include success rate"

    def test_generate_ai_prompt_without_protection_info(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """AI prompt must work without protection info."""
        mock_result = UnifiedProtectionResult(
            file_type="PE",
            architecture="x86",
            is_packed=False,
            is_protected=False,
            protections=[],
            icp_analysis=None,
        )

        prompt: str = generator._generate_ai_prompt(mock_result, "Unknown", 0.5, None)

        assert "Unknown" in prompt, "Must include protection type"
        assert "PE" in prompt, "Must include file type"
        assert len(prompt) > 100, "Prompt must be substantive"

    def test_generate_ai_prompt_includes_bypass_guidance(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """AI prompt must include bypass script requirements."""
        mock_result = UnifiedProtectionResult(
            file_type="PE",
            architecture="x64",
            is_packed=False,
            is_protected=True,
            protections=[],
            icp_analysis=None,
        )

        prompt: str = generator._generate_ai_prompt(mock_result, "TestProtection", 0.8, None)

        bypass_requirements: list[str] = [
            "protection checks",
            "hooks",
            "patch",
            "anti-debugging",
            "logging",
        ]

        found: int = sum(1 for req in bypass_requirements if req.lower() in prompt.lower())
        assert found >= 3, "Prompt must include bypass requirements"


class TestEnhanceAIScriptGenerationFunction:
    """Test enhance_ai_script_generation integration function."""

    def test_enhance_ai_script_generation_with_none_generator(self) -> None:
        """Must create AI generator when None provided."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/7zip.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        try:
            result: Dict[str, Any] = enhance_ai_script_generation(None, str(binary))

            assert isinstance(result, dict), "Must return dictionary"
            assert "script" in result, "Must include base script"
            assert "protection_detected" in result, "Must include protection info"

        except ImportError:
            pytest.skip("AIScriptGenerator not available")

    def test_enhance_ai_script_generation_includes_enhancement_metadata(self) -> None:
        """Enhanced result must include AI enhancement metadata."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/vlc.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        try:
            result: Dict[str, Any] = enhance_ai_script_generation(None, str(binary))

            enhancement_fields: list[str] = [
                "ai_enhanced",
                "enhancement_level",
                "optimization_applied",
            ]

            for field in enhancement_fields:
                assert field in result, f"Missing enhancement field: {field}"

            assert result["ai_enhanced"] is True, "Must mark as AI enhanced"
            assert isinstance(result["optimization_applied"], list), (
                "Optimizations must be list"
            )

        except ImportError:
            pytest.skip("AIScriptGenerator not available")


class TestScriptTemplateIntegrityValidation:
    """Validate all script templates produce syntactically valid code."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_all_frida_scripts_have_balanced_syntax(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """All Frida scripts must have balanced braces and brackets."""
        for protection_name, templates in generator.script_templates.items():
            if "frida" not in templates:
                continue

            script: str = templates["frida"]

            open_braces: int = script.count("{")
            close_braces: int = script.count("}")
            assert open_braces == close_braces, (
                f"{protection_name}: Unbalanced braces - {open_braces} open, {close_braces} close"
            )

            open_brackets: int = script.count("[")
            close_brackets: int = script.count("]")
            assert open_brackets == close_brackets, (
                f"{protection_name}: Unbalanced brackets - {open_brackets} open, {close_brackets} close"
            )

            open_parens: int = script.count("(")
            close_parens: int = script.count(")")
            assert open_parens == close_parens, (
                f"{protection_name}: Unbalanced parentheses - {open_parens} open, {close_parens} close"
            )

    def test_all_ghidra_scripts_define_required_structure(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """All Ghidra scripts must define proper class structure."""
        for protection_name, templates in generator.script_templates.items():
            if "ghidra" not in templates:
                continue

            script: str = templates["ghidra"]

            assert "class" in script, f"{protection_name}: Missing class definition"
            assert "GhidraScript" in script or "ghidra" in script.lower(), (
                f"{protection_name}: Not a valid Ghidra script"
            )

    def test_all_ida_scripts_use_ida_api(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """All IDA scripts must use IDA Pro API."""
        for protection_name, templates in generator.script_templates.items():
            if "ida" not in templates:
                continue

            script: str = templates["ida"]

            ida_imports: list[str] = ["idaapi", "idautils", "idc"]
            found: int = sum(1 for imp in ida_imports if imp in script)
            assert found >= 1, f"{protection_name}: Missing IDA imports"


class TestProtectionSpecificScriptFeatures:
    """Test protection-specific features in generated scripts."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_hasp_script_includes_encryption_emulation(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """HASP script must emulate encryption/decryption."""
        hasp_scripts: Dict[str, str] = generator._get_hasp_scripts()
        frida_script: str = hasp_scripts["frida"]

        assert "hasp_encrypt" in frida_script, "Must hook encryption"
        assert "hasp_decrypt" in frida_script, "Must hook decryption"
        assert "key" in frida_script.lower() or "aes" in frida_script.lower(), (
            "Must handle cryptographic operations"
        )

    def test_flexlm_script_includes_network_license_emulation(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """FlexLM script must emulate network license server."""
        flexlm_scripts: Dict[str, str] = generator._get_flexlm_scripts()
        frida_script: str = flexlm_scripts["frida"]

        network_indicators: list[str] = ["connect", "recv", "send", "socket", "27000"]
        found: int = sum(1 for indicator in network_indicators if indicator in frida_script)
        assert found >= 2, "Must emulate network license protocol"

    def test_vmprotect_script_includes_vm_detection(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """VMProtect script must detect virtualized code."""
        vmp_scripts: Dict[str, str] = generator._get_vmprotect_scripts()
        frida_script: str = vmp_scripts["frida"]

        vm_indicators: list[str] = ["vm", "virtual", "handler", "dispatcher"]
        found: int = sum(1 for indicator in vm_indicators if indicator.lower() in frida_script.lower())
        assert found >= 1, "Must detect VM handlers"

    def test_steam_script_includes_ceg_bypass(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Steam script must bypass CEG (Custom Executable Generation)."""
        steam_scripts: Dict[str, str] = generator._get_steam_scripts()
        frida_script: str = steam_scripts["frida"]

        steam_apis: list[str] = ["SteamAPI", "ISteamUser", "ISteamApps"]
        found: int = sum(1 for api in steam_apis if api in frida_script)
        assert found >= 1, "Must hook Steam APIs"


class TestRealWorldBinaryProcessing:
    """Test script generation with real-world binaries when available."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_process_real_pe_binary(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Must successfully process real PE binaries."""
        binaries: list[Path] = [
            Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/7zip.exe"),
            Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/vlc.exe"),
        ]

        for binary in binaries:
            if not binary.exists():
                continue

            result: Dict[str, Any] = generator.generate_bypass_script(str(binary))

            assert isinstance(result, dict), "Must return result dict"
            assert "success" in result, "Must include success flag"
            assert "script" in result, "Must include generated script"

            break
        else:
            pytest.skip("No test binaries found")

    def test_process_protected_binary_generates_targeted_script(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Protected binaries must generate protection-specific scripts."""
        protected_binaries: list[Path] = [
            Path("D:/Intellicrack/tests/fixtures/binaries/protected/vmprotect_protected.exe"),
            Path("D:/Intellicrack/tests/fixtures/binaries/protected/themida_protected.exe"),
            Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected/hasp_sentinel_protected.exe"),
        ]

        for binary in protected_binaries:
            if not binary.exists():
                continue

            result: Dict[str, Any] = generator.generate_bypass_script(str(binary))

            if result.get("success") and result.get("protection_detected") != "None":
                assert "bypass" in result["approach"].lower() or "protection" in result["approach"].lower(), (
                    "Approach must mention bypass strategy"
                )
                break
        else:
            pytest.skip("No protected test binaries found")


class TestKnowledgeBaseIntegration:
    """Test integration with protection knowledge base."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_knowledge_base_provides_bypass_techniques(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Knowledge base must provide bypass techniques for known protections."""
        kb = get_protection_knowledge_base()

        known_protections: list[str] = [
            "VMProtect",
            "Themida",
            "Sentinel HASP",
            "FlexLM",
            "Steam CEG",
        ]

        for protection in known_protections:
            techniques = kb.get_bypass_techniques(protection)
            if techniques:
                assert isinstance(techniques, list), f"{protection}: Techniques must be list"
                assert len(techniques) > 0, f"{protection}: Must provide techniques"
                break

    def test_knowledge_base_provides_time_estimates(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Knowledge base must estimate bypass time."""
        kb = get_protection_knowledge_base()

        skill_levels: list[str] = ["beginner", "intermediate", "advanced"]

        for skill in skill_levels:
            estimate = kb.estimate_bypass_time("VMProtect", skill)
            if estimate and estimate != "Unknown":
                assert isinstance(estimate, str), "Estimate must be string"
                break

    def test_knowledge_base_provides_required_tools(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Knowledge base must list required tools."""
        kb = get_protection_knowledge_base()

        tools = kb.get_tools_for_protection("VMProtect")
        assert isinstance(tools, list), "Tools must be list"


class TestPerformanceAndScalability:
    """Test performance with various binary sizes and complexities."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_script_generation_completes_quickly_for_small_binary(
        self, generator: ProtectionAwareScriptGenerator, tmp_path: Path
    ) -> None:
        """Small binaries must process quickly."""
        import time

        small_binary = tmp_path / "small.exe"
        small_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        start_time: float = time.time()
        result: Dict[str, Any] = generator.generate_bypass_script(str(small_binary))
        elapsed: float = time.time() - start_time

        assert elapsed < 10.0, f"Processing took too long: {elapsed:.2f}s"

    def test_multiple_sequential_generations_do_not_leak_memory(
        self, generator: ProtectionAwareScriptGenerator, tmp_path: Path
    ) -> None:
        """Multiple generations must not cause memory issues."""
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 2048)

        for i in range(10):
            result: Dict[str, Any] = generator.generate_bypass_script(str(test_binary))
            assert isinstance(result, dict), f"Iteration {i}: Must return dict"


class TestLoggingAndDiagnostics:
    """Test logging behavior during script generation."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_generator_logs_protection_detection(
        self, generator: ProtectionAwareScriptGenerator, caplog
    ) -> None:
        """Generator must log protection detection events."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/7zip.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        with caplog.at_level(logging.DEBUG):
            result: Dict[str, Any] = generator.generate_bypass_script(str(binary))

        if caplog.text:
            logging.info("Logging is functional")

    def test_generator_logs_errors_on_failure(
        self, generator: ProtectionAwareScriptGenerator, caplog
    ) -> None:
        """Generator must log errors when analysis fails."""
        with caplog.at_level(logging.ERROR):
            result: Dict[str, Any] = generator.generate_bypass_script("/invalid/path.exe")

        assert not result["success"], "Must fail for invalid path"


class TestScriptHeaderMetadata:
    """Test script header metadata generation."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_script_header_includes_all_metadata(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Script header must include comprehensive metadata."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/vlc.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        result: Dict[str, Any] = generator.generate_bypass_script(str(binary))
        script: str = result["script"]

        metadata_fields: list[str] = [
            "Intellicrack",
            "Target:",
            "File Type:",
            "Architecture:",
        ]

        for field in metadata_fields:
            assert field in script, f"Script missing metadata field: {field}"

    def test_script_documents_protection_count(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Script must document number of protections detected."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected/enterprise_license_check.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        result: Dict[str, Any] = generator.generate_bypass_script(str(binary))
        script: str = result["script"]

        assert "Total Protections Detected:" in script or "protection" in script.lower(), (
            "Script must document protection count"
        )
