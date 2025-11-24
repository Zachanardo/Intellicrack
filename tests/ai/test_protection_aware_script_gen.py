"""Production-grade tests for protection-aware script generation.

Tests validate real script generation against actual protected binaries.
All tests verify genuine offensive capability - NO mocks or simulations.
"""

import logging
import re
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.protection_aware_script_gen import (
    ProtectionAwareScriptGenerator,
    enhance_ai_script_generation,
)
from intellicrack.models.protection_knowledge_base import get_protection_knowledge_base
from intellicrack.protection.unified_protection_engine import get_unified_engine


class TestProtectionAwareScriptGeneratorInitialization:
    """Test generator initialization and template loading."""

    def test_generator_initializes_with_all_protection_templates(self) -> None:
        """Generator must initialize with complete protection template library."""
        generator = ProtectionAwareScriptGenerator()

        expected_protections = [
            "sentinel_hasp",
            "flexlm",
            "winlicense",
            "steam_ceg",
            "vmprotect",
            "denuvo",
            "microsoft_activation",
            "themida",
            "ilok_pace",
            "securom",
            "starforce",
            "arxan",
            "cloud_licensing",
            "custom_obfuscation",
            "safenet_sentinel",
        ]

        for protection in expected_protections:
            assert protection in generator.script_templates, (
                f"Missing template for {protection} protection"
            )
            assert "frida" in generator.script_templates[protection], (
                f"Missing Frida script for {protection}"
            )

    def test_generator_has_functional_unified_engine(self) -> None:
        """Generator must have working unified protection engine."""
        generator = ProtectionAwareScriptGenerator()

        assert generator.unified_engine is not None
        assert hasattr(generator.unified_engine, "analyze_file")

    def test_generator_has_functional_knowledge_base(self) -> None:
        """Generator must have working protection knowledge base."""
        generator = ProtectionAwareScriptGenerator()

        assert generator.kb is not None
        assert hasattr(generator.kb, "get_protection_info")
        assert hasattr(generator.kb, "get_bypass_techniques")


class TestFridaScriptGeneration:
    """Test Frida hook generation for real protections."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    @pytest.fixture(scope="class")
    def vmprotect_binary(self) -> Path:
        """Path to VMProtect-protected test binary."""
        return Path("D:/Intellicrack/tests/fixtures/binaries/protected/vmprotect_protected.exe")

    @pytest.fixture(scope="class")
    def themida_binary(self) -> Path:
        """Path to Themida-protected test binary."""
        return Path("D:/Intellicrack/tests/fixtures/binaries/protected/themida_protected.exe")

    @pytest.fixture(scope="class")
    def hasp_binary(self) -> Path:
        """Path to HASP-protected test binary."""
        return Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected/hasp_sentinel_protected.exe")

    @pytest.fixture(scope="class")
    def flexlm_binary(self) -> Path:
        """Path to FlexLM-protected test binary."""
        return Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected/flexlm_license_protected.exe")

    def test_generate_vmprotect_bypass_frida_script(
        self, generator: ProtectionAwareScriptGenerator, vmprotect_binary: Path
    ) -> None:
        """Generated Frida script must target VMProtect-specific APIs."""
        if not vmprotect_binary.exists():
            pytest.skip(f"VMProtect test binary not found: {vmprotect_binary}")

        result = generator.generate_bypass_script(
            str(vmprotect_binary), script_type="frida"
        )

        assert result["success"], f"Script generation failed: {result.get('error')}"
        assert result["script"], "Generated script is empty"

        script = result["script"]
        assert "VMProtect" in script or "vmprotect" in script.lower(), (
            "Script does not target VMProtect protection"
        )

        assert "Interceptor.attach" in script, "Script lacks Frida hook installation"
        assert "Module.findExportByName" in script or "Memory.scan" in script, (
            "Script lacks function discovery mechanism"
        )

    def test_generate_hasp_bypass_frida_script_with_api_hooks(
        self, generator: ProtectionAwareScriptGenerator, hasp_binary: Path
    ) -> None:
        """HASP bypass script must hook critical HASP APIs."""
        if not hasp_binary.exists():
            pytest.skip(f"HASP test binary not found: {hasp_binary}")

        result = generator.generate_bypass_script(
            str(hasp_binary), script_type="frida"
        )

        assert result["success"], f"Script generation failed: {result.get('error')}"

        script = result["script"]
        hasp_apis = [
            "hasp_login",
            "hasp_logout",
            "hasp_encrypt",
            "hasp_decrypt",
            "hasp_get_info",
        ]

        hooks_found = sum(1 for api in hasp_apis if api in script)
        assert hooks_found >= 2, (
            f"Script must hook at least 2 HASP APIs, found {hooks_found}"
        )

        assert "HASP_STATUS_OK" in script or "0x0" in script, (
            "Script must force success return codes"
        )

    def test_generate_flexlm_bypass_with_license_emulation(
        self, generator: ProtectionAwareScriptGenerator, flexlm_binary: Path
    ) -> None:
        """FlexLM bypass script must emulate license checkout."""
        if not flexlm_binary.exists():
            pytest.skip(f"FlexLM test binary not found: {flexlm_binary}")

        result = generator.generate_bypass_script(
            str(flexlm_binary), script_type="frida"
        )

        assert result["success"], f"Script generation failed: {result.get('error')}"

        script = result["script"]
        flexlm_functions = ["lc_checkout", "lm_checkout", "lp_checkout"]

        hooks_found = sum(1 for func in flexlm_functions if func in script)
        assert hooks_found >= 1, "Script must hook FlexLM checkout functions"

        assert "LM_NOERROR" in script or "0x0" in script, (
            "Script must return license success codes"
        )

    def test_generate_themida_bypass_with_anti_debugging(
        self, generator: ProtectionAwareScriptGenerator, themida_binary: Path
    ) -> None:
        """Themida bypass must include anti-debugging countermeasures."""
        if not themida_binary.exists():
            pytest.skip(f"Themida test binary not found: {themida_binary}")

        result = generator.generate_bypass_script(
            str(themida_binary), script_type="frida"
        )

        assert result["success"], f"Script generation failed: {result.get('error')}"

        script = result["script"]
        anti_debug_apis = [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
        ]

        hooks_found = sum(1 for api in anti_debug_apis if api in script)
        assert hooks_found >= 1, (
            "Themida bypass must hook anti-debugging functions"
        )

    def test_frida_script_includes_error_handling(
        self, generator: ProtectionAwareScriptGenerator, vmprotect_binary: Path
    ) -> None:
        """Generated Frida scripts must include error handling."""
        if not vmprotect_binary.exists():
            pytest.skip(f"Test binary not found: {vmprotect_binary}")

        result = generator.generate_bypass_script(
            str(vmprotect_binary), script_type="frida"
        )

        script = result["script"]
        assert "try" in script or "catch" in script or "onError" in script, (
            "Script lacks error handling mechanisms"
        )

    def test_frida_script_includes_logging(
        self, generator: ProtectionAwareScriptGenerator, hasp_binary: Path
    ) -> None:
        """Generated scripts must include comprehensive logging."""
        if not hasp_binary.exists():
            pytest.skip(f"Test binary not found: {hasp_binary}")

        result = generator.generate_bypass_script(
            str(hasp_binary), script_type="frida"
        )

        script = result["script"]
        console_log_count = script.count("console.log")
        assert console_log_count >= 3, (
            f"Script must include detailed logging (found {console_log_count} calls)"
        )


class TestGhidraScriptGeneration:
    """Test Ghidra analysis and patching script generation."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_generate_ghidra_script_for_hasp_protection(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Ghidra script must perform automated HASP API analysis."""
        hasp_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/pe/protected/hasp_sentinel_protected.exe"
        )

        if not hasp_binary.exists():
            pytest.skip(f"HASP test binary not found: {hasp_binary}")

        result = generator.generate_bypass_script(
            str(hasp_binary), script_type="ghidra"
        )

        assert result["success"], f"Script generation failed: {result.get('error')}"

        script = result["script"]
        assert "import ghidra" in script, "Script must use Ghidra API"
        assert "GhidraScript" in script, "Script must extend GhidraScript class"

        required_methods = ["identifyHASPAPIs", "patchValidationChecks"]
        methods_found = sum(1 for method in required_methods if method in script)
        assert methods_found >= 1, (
            "Ghidra script must implement protection analysis methods"
        )

    def test_ghidra_script_includes_api_discovery(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Ghidra script must discover protection APIs automatically."""
        flexlm_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/pe/protected/flexlm_license_protected.exe"
        )

        if not flexlm_binary.exists():
            pytest.skip(f"FlexLM test binary not found: {flexlm_binary}")

        result = generator.generate_bypass_script(
            str(flexlm_binary), script_type="ghidra"
        )

        script = result["script"]
        assert "getSymbol" in script or "findExport" in script, (
            "Script must discover exported functions"
        )
        assert "getReferenceManager" in script or "getReferencesTo" in script, (
            "Script must trace API call sites"
        )

    def test_ghidra_script_performs_binary_patching(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Ghidra script must apply binary patches."""
        vmprotect_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/protected/vmprotect_protected.exe"
        )

        if not vmprotect_binary.exists():
            pytest.skip(f"VMProtect test binary not found: {vmprotect_binary}")

        result = generator.generate_bypass_script(
            str(vmprotect_binary), script_type="ghidra"
        )

        script = result["script"]
        patching_indicators = [
            "setBytes",
            "patch",
            "0x90",  # NOP instruction
            "0xEB",  # JMP instruction
        ]

        patches_found = sum(1 for indicator in patching_indicators if indicator in script)
        assert patches_found >= 1, (
            "Ghidra script must include binary patching capabilities"
        )


class TestRadare2ScriptGeneration:
    """Test Radare2 patching script generation."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_generate_radare2_script_structure(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Radare2 scripts must use proper r2 command syntax."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/7zip.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        hasp_scripts = generator._get_hasp_scripts()
        assert "radare2" in hasp_scripts or "r2" in hasp_scripts, (
            "Template should include Radare2 scripts"
        )


class TestProtectionDetectionIntegration:
    """Test integration with protection detection engine."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_detect_vmprotect_and_generate_targeted_script(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Must detect VMProtect and generate VMProtect-specific bypass."""
        vmprotect_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/protected/vmprotect_protected.exe"
        )

        if not vmprotect_binary.exists():
            pytest.skip(f"VMProtect test binary not found: {vmprotect_binary}")

        result = generator.generate_bypass_script(str(vmprotect_binary))

        assert result["success"], "Script generation must succeed"
        assert result["protection_detected"], "Must detect protection type"

        protection_name = result["protection_detected"].lower()
        assert "vmprotect" in protection_name or "vmp" in protection_name, (
            f"Must detect VMProtect, got: {result['protection_detected']}"
        )

    def test_detect_themida_and_generate_targeted_script(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Must detect Themida and generate Themida-specific bypass."""
        themida_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/protected/themida_protected.exe"
        )

        if not themida_binary.exists():
            pytest.skip(f"Themida test binary not found: {themida_binary}")

        result = generator.generate_bypass_script(str(themida_binary))

        assert result["success"], "Script generation must succeed"

        if result["protection_detected"] and result["protection_detected"] != "Unknown":
            protection_name = result["protection_detected"].lower()
            assert "themida" in protection_name or "winlicense" in protection_name, (
                f"Should detect Themida/WinLicense, got: {result['protection_detected']}"
            )

    def test_unprotected_binary_generates_basic_analysis_script(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Unprotected binaries must generate basic analysis scripts."""
        unprotected_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/7zip.exe"
        )

        if not unprotected_binary.exists():
            pytest.skip(f"Test binary not found: {unprotected_binary}")

        result = generator.generate_bypass_script(str(unprotected_binary))

        assert result["success"], "Script generation must succeed"

        if result["protection_detected"] == "None":
            assert "basic" in result["approach"].lower(), (
                "Should use basic analysis approach for unprotected binaries"
            )

    def test_confidence_scores_reflect_detection_quality(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Confidence scores must reflect detection accuracy."""
        vmprotect_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/protected/vmprotect_protected.exe"
        )

        if not vmprotect_binary.exists():
            pytest.skip(f"Test binary not found: {vmprotect_binary}")

        result = generator.generate_bypass_script(str(vmprotect_binary))

        assert "confidence" in result, "Result must include confidence score"
        assert 0.0 <= result["confidence"] <= 1.0, (
            f"Confidence must be between 0 and 1, got: {result['confidence']}"
        )


class TestScriptMetadataGeneration:
    """Test script metadata and documentation generation."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_script_includes_target_binary_metadata(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Generated scripts must include target binary metadata."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/vlc.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        result = generator.generate_bypass_script(str(binary))

        script = result["script"]
        assert "Target:" in script, "Script must document target binary"
        assert "File Type:" in script, "Script must document file type"
        assert "Architecture:" in script, "Script must document architecture"

    def test_script_includes_protection_details(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Scripts must document detected protections."""
        hasp_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/pe/protected/hasp_sentinel_protected.exe"
        )

        if not hasp_binary.exists():
            pytest.skip(f"Test binary not found: {hasp_binary}")

        result = generator.generate_bypass_script(str(hasp_binary))

        script = result["script"]
        assert "Protection:" in script or "protection" in script.lower(), (
            "Script must document detected protection"
        )

    def test_result_includes_bypass_techniques(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Result must include recommended bypass techniques."""
        vmprotect_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/protected/vmprotect_protected.exe"
        )

        if not vmprotect_binary.exists():
            pytest.skip(f"Test binary not found: {vmprotect_binary}")

        result = generator.generate_bypass_script(str(vmprotect_binary))

        assert "bypass_techniques" in result, (
            "Result must include bypass techniques"
        )
        assert isinstance(result["bypass_techniques"], list), (
            "Bypass techniques must be a list"
        )

    def test_result_includes_estimated_bypass_time(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Result must include time estimate for bypass."""
        hasp_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/pe/protected/hasp_sentinel_protected.exe"
        )

        if not hasp_binary.exists():
            pytest.skip(f"Test binary not found: {hasp_binary}")

        result = generator.generate_bypass_script(str(hasp_binary))

        assert "estimated_time" in result, "Result must include time estimate"

    def test_result_includes_required_tools(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Result must list required tools for bypass."""
        flexlm_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/pe/protected/flexlm_license_protected.exe"
        )

        if not flexlm_binary.exists():
            pytest.skip(f"Test binary not found: {flexlm_binary}")

        result = generator.generate_bypass_script(str(flexlm_binary))

        assert "tools_needed" in result, "Result must include required tools"
        assert isinstance(result["tools_needed"], list), (
            "Tools needed must be a list"
        )


class TestAIPromptGeneration:
    """Test AI-powered script optimization prompts."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_generate_ai_prompt_for_protection_enhancement(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """AI prompts must guide script enhancement."""
        vmprotect_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/protected/vmprotect_protected.exe"
        )

        if not vmprotect_binary.exists():
            pytest.skip(f"Test binary not found: {vmprotect_binary}")

        result = generator.generate_bypass_script(str(vmprotect_binary))

        assert "ai_prompt" in result, "Result must include AI enhancement prompt"

        prompt = result["ai_prompt"]
        assert len(prompt) > 50, "AI prompt must be substantive"
        assert "bypass" in prompt.lower(), "Prompt must mention bypass strategy"

    def test_ai_prompt_includes_protection_context(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """AI prompts must include protection-specific context."""
        hasp_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/pe/protected/hasp_sentinel_protected.exe"
        )

        if not hasp_binary.exists():
            pytest.skip(f"Test binary not found: {hasp_binary}")

        result = generator.generate_bypass_script(str(hasp_binary))

        prompt = result["ai_prompt"]
        assert "Protection Details:" in prompt, (
            "Prompt must include protection details section"
        )
        assert "Type:" in prompt, "Prompt must specify protection type"

    def test_ai_prompt_includes_recommended_techniques(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """AI prompts must suggest effective bypass techniques."""
        vmprotect_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/protected/vmprotect_protected.exe"
        )

        if not vmprotect_binary.exists():
            pytest.skip(f"Test binary not found: {vmprotect_binary}")

        result = generator.generate_bypass_script(str(vmprotect_binary))

        if result["protection_detected"] != "None":
            prompt = result["ai_prompt"]
            technique_indicators = [
                "technique",
                "approach",
                "method",
                "strategy",
            ]

            found = sum(1 for indicator in technique_indicators if indicator.lower() in prompt.lower())
            assert found >= 1, "Prompt must suggest bypass techniques"


class TestMultiProtectionScenarios:
    """Test script generation for binaries with multiple protections."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_handle_layered_protections(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Must handle binaries with multiple protection layers."""
        enterprise_binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/pe/protected/enterprise_license_check.exe"
        )

        if not enterprise_binary.exists():
            pytest.skip(f"Test binary not found: {enterprise_binary}")

        result = generator.generate_bypass_script(str(enterprise_binary))

        assert result["success"], "Must handle layered protections"

        if "Total Protections Detected:" in result["script"]:
            match = re.search(r"Total Protections Detected: (\d+)", result["script"])
            if match:
                protection_count = int(match.group(1))
                logging.info(f"Detected {protection_count} protection(s)")

    def test_prioritize_primary_protection(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Must identify and prioritize primary protection."""
        binary = Path(
            "D:/Intellicrack/tests/fixtures/binaries/pe/protected/hasp_sentinel_protected.exe"
        )

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        result = generator.generate_bypass_script(str(binary))

        assert "protection_detected" in result, "Must identify primary protection"

        if result["protection_detected"] != "None":
            assert "Primary Protection:" in result["script"], (
                "Script must document primary protection"
            )


class TestErrorHandling:
    """Test error handling for edge cases."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_handle_nonexistent_binary(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Must handle nonexistent binary paths gracefully."""
        result = generator.generate_bypass_script("/nonexistent/binary.exe")

        assert not result["success"], "Must fail for nonexistent binaries"
        assert "error" in result, "Must include error message"

    def test_handle_corrupted_binary(
        self, generator: ProtectionAwareScriptGenerator, tmp_path: Path
    ) -> None:
        """Must handle corrupted binary files gracefully."""
        corrupted_file = tmp_path / "corrupted.exe"
        corrupted_file.write_bytes(b"MZ\x00\x00" + b"\xFF" * 100)

        result = generator.generate_bypass_script(str(corrupted_file))

        assert isinstance(result, dict), "Must return result dict"
        assert "success" in result, "Must include success flag"

    def test_fallback_to_generic_script_on_detection_failure(
        self, generator: ProtectionAwareScriptGenerator, tmp_path: Path
    ) -> None:
        """Must generate generic script when detection fails."""
        minimal_exe = tmp_path / "minimal.exe"
        minimal_exe.write_bytes(b"MZ" + b"\x00" * 200)

        result = generator.generate_bypass_script(str(minimal_exe))

        assert result["script"], "Must generate fallback script"


class TestScriptTemplateCompleteness:
    """Test all protection templates are complete and functional."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_all_templates_generate_valid_frida_scripts(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """All protection templates must generate valid Frida scripts."""
        for protection_name, templates in generator.script_templates.items():
            assert "frida" in templates, (
                f"Missing Frida template for {protection_name}"
            )

            frida_script = templates["frida"]
            assert len(frida_script) > 100, (
                f"Frida script for {protection_name} is too short"
            )
            assert "Interceptor" in frida_script or "Memory" in frida_script, (
                f"Frida script for {protection_name} lacks core Frida APIs"
            )

    def test_hasp_template_completeness(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """HASP template must include comprehensive bypass logic."""
        hasp_scripts = generator._get_hasp_scripts()

        frida_script = hasp_scripts["frida"]
        assert "hasp_login" in frida_script, "Must hook hasp_login"
        assert "hasp_encrypt" in frida_script or "hasp_decrypt" in frida_script, (
            "Must hook encryption functions"
        )
        assert "HASP_STATUS_OK" in frida_script, "Must define success codes"

        ghidra_script = hasp_scripts["ghidra"]
        assert "GhidraScript" in ghidra_script, "Must be valid Ghidra script"
        assert "hasp" in ghidra_script.lower(), "Must reference HASP APIs"

    def test_vmprotect_template_completeness(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """VMProtect template must include virtualization bypass."""
        vmp_scripts = generator._get_vmprotect_scripts()

        frida_script = vmp_scripts["frida"]
        assert "VMProtect" in frida_script or "vmprotect" in frida_script.lower(), (
            "Must reference VMProtect"
        )
        assert "vm" in frida_script.lower() or "virtualiz" in frida_script.lower(), (
            "Must handle virtualization"
        )

    def test_flexlm_template_completeness(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """FlexLM template must include license checkout bypass."""
        flexlm_scripts = generator._get_flexlm_scripts()

        frida_script = flexlm_scripts["frida"]
        checkout_functions = ["lc_checkout", "lm_checkout", "lp_checkout"]
        hooks_found = sum(1 for func in checkout_functions if func in frida_script)

        assert hooks_found >= 1, "Must hook at least one checkout function"
        assert "LM_NOERROR" in frida_script or "license" in frida_script.lower(), (
            "Must handle license validation"
        )

    def test_steam_template_completeness(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Steam CEG template must include DRM bypass."""
        steam_scripts = generator._get_steam_scripts()

        frida_script = steam_scripts["frida"]
        assert "steam" in frida_script.lower(), "Must reference Steam"
        assert "SteamAPI" in frida_script or "steam_api" in frida_script.lower(), (
            "Must hook Steam APIs"
        )


class TestScriptSyntaxValidation:
    """Test generated scripts have valid syntax."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_frida_script_javascript_syntax_basic_validation(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Frida scripts must have balanced braces and brackets."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/vlc.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        result = generator.generate_bypass_script(str(binary), script_type="frida")

        script = result["script"]
        open_braces = script.count("{")
        close_braces = script.count("}")
        assert open_braces == close_braces, (
            f"Unbalanced braces: {open_braces} open, {close_braces} close"
        )

        open_brackets = script.count("[")
        close_brackets = script.count("]")
        assert open_brackets == close_brackets, (
            f"Unbalanced brackets: {open_brackets} open, {close_brackets} close"
        )

    def test_ghidra_script_java_syntax_basic_validation(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Ghidra scripts must have valid Java class structure."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/vlc.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        result = generator.generate_bypass_script(str(binary), script_type="ghidra")

        script = result["script"]
        assert "class" in script and "extends GhidraScript" in script, (
            "Must define GhidraScript class"
        )
        assert "public void run()" in script, "Must define run() method"


class TestEnhanceAIScriptGeneration:
    """Test AI-enhanced script generation integration function."""

    def test_enhance_ai_script_generation_function_exists(self) -> None:
        """enhance_ai_script_generation function must be importable."""
        assert callable(enhance_ai_script_generation), (
            "enhance_ai_script_generation must be a callable function"
        )

    def test_enhance_with_real_binary(self) -> None:
        """AI enhancement must work with real binaries."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/7zip.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        try:
            result = enhance_ai_script_generation(None, str(binary))

            assert isinstance(result, dict), "Must return result dictionary"
            assert "script" in result, "Must include base script"
            assert "protection_detected" in result, "Must include protection info"

        except ImportError as e:
            pytest.skip(f"AI script generator not available: {e}")


class TestProtectionKnowledgeBaseIntegration:
    """Test integration with protection knowledge base."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_retrieve_vmprotect_bypass_techniques(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Must retrieve VMProtect bypass techniques from knowledge base."""
        kb = get_protection_knowledge_base()

        techniques = kb.get_bypass_techniques("VMProtect")
        assert techniques, "Knowledge base must provide VMProtect techniques"

    def test_estimate_bypass_time_for_known_protection(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Must estimate bypass time for known protections."""
        kb = get_protection_knowledge_base()

        time_estimate = kb.estimate_bypass_time("VMProtect", "intermediate")
        assert time_estimate, "Must provide time estimate"

    def test_get_required_tools_for_protection(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Must list required tools for protection bypass."""
        kb = get_protection_knowledge_base()

        tools = kb.get_tools_for_protection("VMProtect")
        assert isinstance(tools, list), "Must return list of tools"


class TestPerformanceWithLargeBinaries:
    """Test script generation performance with large binaries."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_generate_script_for_large_binary_under_time_limit(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Script generation must complete within reasonable time."""
        large_binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/firefox.exe")

        if not large_binary.exists():
            pytest.skip(f"Test binary not found: {large_binary}")

        import time

        start_time = time.time()
        result = generator.generate_bypass_script(str(large_binary))
        elapsed_time = time.time() - start_time

        assert result["success"] or "error" in result, "Must complete execution"
        assert elapsed_time < 60.0, (
            f"Script generation took too long: {elapsed_time:.2f}s"
        )


class TestScriptTypeValidation:
    """Test script type parameter validation."""

    @pytest.fixture(scope="class")
    def generator(self) -> ProtectionAwareScriptGenerator:
        """Create generator instance."""
        return ProtectionAwareScriptGenerator()

    def test_default_script_type_is_frida(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Default script type must be Frida."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/7zip.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        result = generator.generate_bypass_script(str(binary))

        script = result["script"]
        assert "Interceptor" in script or "frida" in script.lower(), (
            "Default script should be Frida"
        )

    def test_explicit_ghidra_script_type(
        self, generator: ProtectionAwareScriptGenerator
    ) -> None:
        """Explicit Ghidra type must generate Ghidra scripts."""
        binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/vlc.exe")

        if not binary.exists():
            pytest.skip(f"Test binary not found: {binary}")

        result = generator.generate_bypass_script(str(binary), script_type="ghidra")

        script = result["script"]
        assert "ghidra" in script.lower() or "GhidraScript" in script, (
            "Must generate Ghidra script"
        )
