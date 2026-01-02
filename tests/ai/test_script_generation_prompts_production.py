"""Production tests for Script Generation Prompts.

This file validates the ScriptGenerationPrompts class which manages specialized
prompts for AI-powered script generation for license bypass and protection
cracking. Tests verify prompt generation, formatting, and context building
for Frida and Ghidra exploitation scripts.

Copyright (C) 2025 Zachary Flint
"""

import re
from typing import Any

import pytest

from intellicrack.ai.script_generation_prompts import PromptType, ScriptGenerationPrompts, get_prompt_manager


class TestPromptType:
    """Test PromptType enum values."""

    def test_prompt_type_enum_values(self) -> None:
        """PromptType enum has expected values for script generation."""
        assert PromptType.FRIDA.value == "frida"
        assert PromptType.GHIDRA.value == "ghidra"
        assert PromptType.ANALYSIS.value == "analysis"
        assert PromptType.REFINEMENT.value == "refinement"
        assert PromptType.VALIDATION.value == "validation"

    def test_all_prompt_types_enumerated(self) -> None:
        """PromptType enum contains all expected types."""
        expected_types = {"frida", "ghidra", "analysis", "refinement", "validation"}
        actual_types = {pt.value for pt in PromptType}
        assert actual_types == expected_types


class TestScriptGenerationPromptsInitialization:
    """Test ScriptGenerationPrompts initialization."""

    def test_prompts_manager_initializes(self) -> None:
        """Prompts manager initializes with all prompt templates."""
        manager = ScriptGenerationPrompts()
        assert manager.prompts is not None
        assert len(manager.prompts) > 0

    def test_all_prompt_types_initialized(self) -> None:
        """All PromptType enum values have corresponding prompts."""
        manager = ScriptGenerationPrompts()
        for prompt_type in PromptType:
            assert prompt_type in manager.prompts

    def test_each_prompt_has_system_and_template(self) -> None:
        """Each prompt type has system and user_template keys."""
        manager = ScriptGenerationPrompts()
        for prompt_type in PromptType:
            prompt_data = manager.prompts[prompt_type]
            assert "system" in prompt_data
            assert "user_template" in prompt_data
            assert isinstance(prompt_data["system"], str)
            assert isinstance(prompt_data["user_template"], str)

    def test_system_prompts_contain_expert_instructions(self) -> None:
        """System prompts contain expert role definitions."""
        manager = ScriptGenerationPrompts()
        for prompt_type in PromptType:
            system = manager.prompts[prompt_type]["system"]
            assert len(system) > 50
            assert "expert" in system.lower() or "specialist" in system.lower() or "autonomous" in system.lower()


class TestFridaPrompts:
    """Test Frida-specific prompt generation."""

    def test_frida_system_prompt_emphasizes_completeness(self) -> None:
        """Frida system prompt enforces complete functional code."""
        manager = ScriptGenerationPrompts()
        system = manager.prompts[PromptType.FRIDA]["system"]
        assert "complete" in system.lower() or "functional" in system.lower()
        assert "production" in system.lower() or "operational" in system.lower()

    def test_frida_system_prompt_mentions_critical_requirements(self) -> None:
        """Frida system prompt specifies critical requirements."""
        manager = ScriptGenerationPrompts()
        system = manager.prompts[PromptType.FRIDA]["system"]
        assert "CRITICAL REQUIREMENTS" in system
        assert "Interceptor" in system or "hook" in system.lower()

    def test_frida_template_includes_binary_context_fields(self) -> None:
        """Frida user template has essential binary analysis fields."""
        manager = ScriptGenerationPrompts()
        template = manager.prompts[PromptType.FRIDA]["user_template"]
        required_fields = [
            "{binary_name}",
            "{protection_types}",
            "{analysis_summary}",
            "{architecture}",
            "{platform}",
        ]
        for field in required_fields:
            assert field in template

    def test_frida_template_requires_script_functionality(self) -> None:
        """Frida template includes functionality requirements section."""
        manager = ScriptGenerationPrompts()
        template = manager.prompts[PromptType.FRIDA]["user_template"]
        assert "{functionality_requirements}" in template
        assert "Script Functionality" in template or "Required Script" in template


class TestGhidraPrompts:
    """Test Ghidra-specific prompt generation."""

    def test_ghidra_system_prompt_specifies_api_usage(self) -> None:
        """Ghidra system prompt emphasizes correct API usage."""
        manager = ScriptGenerationPrompts()
        system = manager.prompts[PromptType.GHIDRA]["system"]
        assert "Ghidra" in system
        assert "API" in system or "api" in system.lower()

    def test_ghidra_system_prompt_requires_functional_code(self) -> None:
        """Ghidra system prompt enforces functional implementation."""
        manager = ScriptGenerationPrompts()
        system = manager.prompts[PromptType.GHIDRA]["system"]
        assert "functional" in system.lower() or "operational" in system.lower()
        assert "complete" in system.lower()

    def test_ghidra_template_includes_patching_objectives(self) -> None:
        """Ghidra template includes patching objectives."""
        manager = ScriptGenerationPrompts()
        template = manager.prompts[PromptType.GHIDRA]["user_template"]
        assert "{patching_objectives}" in template
        assert "Patching" in template

    def test_ghidra_template_includes_binary_characteristics(self) -> None:
        """Ghidra template has binary characteristics section."""
        manager = ScriptGenerationPrompts()
        template = manager.prompts[PromptType.GHIDRA]["user_template"]
        required_fields = ["{file_type}", "{architecture}", "{entry_point}", "{key_addresses}"]
        for field in required_fields:
            assert field in template


class TestAnalysisPrompts:
    """Test analysis prompt generation."""

    def test_analysis_system_prompt_focuses_on_identification(self) -> None:
        """Analysis system prompt focuses on protection identification."""
        manager = ScriptGenerationPrompts()
        system = manager.prompts[PromptType.ANALYSIS]["system"]
        assert "protection" in system.lower()
        assert "identify" in system.lower() or "analyze" in system.lower()

    def test_analysis_template_requests_structured_output(self) -> None:
        """Analysis template requests JSON formatted output."""
        manager = ScriptGenerationPrompts()
        template = manager.prompts[PromptType.ANALYSIS]["user_template"]
        assert "JSON" in template or "json" in template.lower()
        assert "structured" in template.lower()

    def test_analysis_template_includes_binary_data_field(self) -> None:
        """Analysis template accepts binary data input."""
        manager = ScriptGenerationPrompts()
        template = manager.prompts[PromptType.ANALYSIS]["user_template"]
        assert "{binary_data}" in template


class TestRefinementPrompts:
    """Test script refinement prompt generation."""

    def test_refinement_system_prompt_focuses_on_debugging(self) -> None:
        """Refinement system prompt focuses on debugging and improvement."""
        manager = ScriptGenerationPrompts()
        system = manager.prompts[PromptType.REFINEMENT]["system"]
        assert "debug" in system.lower() or "refine" in system.lower() or "improve" in system.lower()

    def test_refinement_template_accepts_test_feedback(self) -> None:
        """Refinement template includes test results and error feedback."""
        manager = ScriptGenerationPrompts()
        template = manager.prompts[PromptType.REFINEMENT]["user_template"]
        assert "{original_script}" in template
        assert "{test_results}" in template
        assert "{error_feedback}" in template

    def test_refinement_template_requests_fixes(self) -> None:
        """Refinement template requests error fixes and improvements."""
        manager = ScriptGenerationPrompts()
        template = manager.prompts[PromptType.REFINEMENT]["user_template"]
        assert "fix" in template.lower() or "improve" in template.lower()


class TestValidationPrompts:
    """Test script validation prompt generation."""

    def test_validation_system_prompt_covers_multiple_checks(self) -> None:
        """Validation system prompt includes syntax, logic, security checks."""
        manager = ScriptGenerationPrompts()
        system = manager.prompts[PromptType.VALIDATION]["system"]
        assert "syntax" in system.lower()
        assert "security" in system.lower() or "vulnerabilities" in system.lower()

    def test_validation_template_accepts_script_content(self) -> None:
        """Validation template accepts script content and type."""
        manager = ScriptGenerationPrompts()
        template = manager.prompts[PromptType.VALIDATION]["user_template"]
        assert "{script_type}" in template
        assert "{script_content}" in template

    def test_validation_template_requests_structured_results(self) -> None:
        """Validation template requests JSON structured results."""
        manager = ScriptGenerationPrompts()
        template = manager.prompts[PromptType.VALIDATION]["user_template"]
        assert "JSON" in template or "json" in template.lower()


class TestGetPrompt:
    """Test get_prompt method functionality."""

    def test_get_prompt_retrieves_prompt_data(self) -> None:
        """get_prompt retrieves complete prompt data for valid type."""
        manager = ScriptGenerationPrompts()
        prompt = manager.get_prompt(PromptType.FRIDA)
        assert "system" in prompt
        assert "user_template" in prompt

    def test_get_prompt_raises_for_invalid_type(self) -> None:
        """get_prompt raises ValueError for invalid prompt type."""
        manager = ScriptGenerationPrompts()
        with pytest.raises(ValueError, match="Unknown prompt type"):
            manager.get_prompt("invalid_type")  # type: ignore[arg-type]

    def test_get_prompt_formats_template_with_kwargs(self) -> None:
        """get_prompt formats user template with provided kwargs."""
        manager = ScriptGenerationPrompts()
        prompt = manager.get_prompt(
            PromptType.ANALYSIS,
            binary_data='{"name": "test.exe", "protections": ["vmprotect"]}',
        )
        assert "test.exe" in prompt["user_template"] or "vmprotect" in prompt["user_template"]

    def test_get_prompt_handles_missing_kwargs_gracefully(self) -> None:
        """get_prompt handles missing template parameters without crashing."""
        manager = ScriptGenerationPrompts()
        prompt = manager.get_prompt(PromptType.FRIDA, binary_name="protected.exe")
        assert prompt is not None
        assert "system" in prompt

    def test_get_prompt_returns_copy_not_reference(self) -> None:
        """get_prompt returns copy of prompt data, not original reference."""
        manager = ScriptGenerationPrompts()
        prompt1 = manager.get_prompt(PromptType.FRIDA)
        prompt2 = manager.get_prompt(PromptType.FRIDA)
        assert prompt1 is not prompt2


class TestBuildContextData:
    """Test build_context_data method."""

    @pytest.fixture
    def sample_binary_analysis(self) -> dict[str, Any]:
        """Create sample binary analysis data."""
        return {
            "binary_info": {
                "name": "protected_software.exe",
                "arch": "x86_64",
                "platform": "windows",
                "type": "PE",
            },
            "functions": [
                {"name": "check_license", "address": "0x401000"},
                {"name": "validate_serial", "address": "0x401200"},
                {"name": "main", "address": "0x401400"},
            ],
            "imports": ["CryptVerifySignatureW", "GetSystemTime", "RegOpenKeyExW"],
            "strings": ["License key invalid", "Trial period expired", "Demo version"],
            "protections": [
                {"type": "VMProtect", "confidence": 0.85},
                {"type": "Themida", "confidence": 0.60},
            ],
        }

    def test_build_context_extracts_binary_name(self, sample_binary_analysis: dict[str, Any]) -> None:
        """build_context_data extracts binary name from analysis."""
        manager = ScriptGenerationPrompts()
        context = manager.build_context_data(sample_binary_analysis)
        assert context["binary_name"] == "protected_software.exe"

    def test_build_context_extracts_architecture(self, sample_binary_analysis: dict[str, Any]) -> None:
        """build_context_data extracts architecture information."""
        manager = ScriptGenerationPrompts()
        context = manager.build_context_data(sample_binary_analysis)
        assert context["architecture"] == "x86_64"

    def test_build_context_extracts_platform(self, sample_binary_analysis: dict[str, Any]) -> None:
        """build_context_data extracts platform information."""
        manager = ScriptGenerationPrompts()
        context = manager.build_context_data(sample_binary_analysis)
        assert context["platform"] == "windows"

    def test_build_context_includes_key_functions(self, sample_binary_analysis: dict[str, Any]) -> None:
        """build_context_data includes key function names."""
        manager = ScriptGenerationPrompts()
        context = manager.build_context_data(sample_binary_analysis)
        assert "check_license" in context["key_functions"]
        assert "validate_serial" in context["key_functions"]

    def test_build_context_includes_imports(self, sample_binary_analysis: dict[str, Any]) -> None:
        """build_context_data includes import information."""
        manager = ScriptGenerationPrompts()
        context = manager.build_context_data(sample_binary_analysis)
        assert "CryptVerifySignatureW" in context["imports"]

    def test_build_context_filters_license_strings(self, sample_binary_analysis: dict[str, Any]) -> None:
        """build_context_data filters license-related strings."""
        manager = ScriptGenerationPrompts()
        context = manager.build_context_data(sample_binary_analysis)
        license_strings = context["license_strings"]
        assert "License key invalid" in license_strings or "Trial period expired" in license_strings

    def test_build_context_includes_analysis_summary(self, sample_binary_analysis: dict[str, Any]) -> None:
        """build_context_data includes protection analysis summary."""
        manager = ScriptGenerationPrompts()
        context = manager.build_context_data(sample_binary_analysis)
        summary = context["analysis_summary"]
        assert "VMProtect" in summary or "Themida" in summary
        assert "confidence" in summary.lower() or "%" in summary

    def test_build_context_handles_empty_analysis(self) -> None:
        """build_context_data handles empty analysis data gracefully."""
        manager = ScriptGenerationPrompts()
        context = manager.build_context_data({})
        assert context["binary_name"] == "unknown"
        assert context["architecture"] == "x64"

    def test_build_context_uses_protection_types_parameter(self, sample_binary_analysis: dict[str, Any]) -> None:
        """build_context_data uses provided protection_types."""
        manager = ScriptGenerationPrompts()
        context = manager.build_context_data(sample_binary_analysis, protection_types=["license", "trial"])
        assert "license" in context["protection_types"]
        assert "trial" in context["protection_types"]

    def test_build_context_defaults_protection_types(self, sample_binary_analysis: dict[str, Any]) -> None:
        """build_context_data defaults to license_check when no types provided."""
        manager = ScriptGenerationPrompts()
        context = manager.build_context_data(sample_binary_analysis)
        assert "license_check" in context["protection_types"]


class TestSummarizeAnalysis:
    """Test _summarize_analysis helper method."""

    def test_summarize_analysis_includes_protection_types(self) -> None:
        """_summarize_analysis includes detected protection types."""
        manager = ScriptGenerationPrompts()
        analysis = {
            "protections": [
                {"type": "VMProtect", "confidence": 0.90},
                {"type": "Themida", "confidence": 0.75},
            ],
        }
        summary = manager._summarize_analysis(analysis)
        assert "VMProtect" in summary
        assert "Themida" in summary

    def test_summarize_analysis_includes_confidence_levels(self) -> None:
        """_summarize_analysis includes confidence percentages."""
        manager = ScriptGenerationPrompts()
        analysis = {"protections": [{"type": "VMProtect", "confidence": 0.85}]}
        summary = manager._summarize_analysis(analysis)
        assert "85" in summary or "0.85" in summary

    def test_summarize_analysis_handles_no_protections(self) -> None:
        """_summarize_analysis handles empty protections list."""
        manager = ScriptGenerationPrompts()
        analysis: dict[str, list[Any]] = {"protections": []}
        summary = manager._summarize_analysis(analysis)
        assert "no specific protections" in summary.lower()


class TestBuildFunctionalityRequirements:
    """Test _build_functionality_requirements helper method."""

    def test_functionality_requirements_for_license_protection(self) -> None:
        """_build_functionality_requirements generates license bypass steps."""
        manager = ScriptGenerationPrompts()
        requirements = manager._build_functionality_requirements(["license_check"])
        assert "license" in requirements.lower()
        assert "validation" in requirements.lower() or "hook" in requirements.lower()

    def test_functionality_requirements_for_trial_protection(self) -> None:
        """_build_functionality_requirements generates trial bypass steps."""
        manager = ScriptGenerationPrompts()
        requirements = manager._build_functionality_requirements(["trial_timer"])
        assert "time" in requirements.lower() or "trial" in requirements.lower()
        assert "GetSystemTime" in requirements or "expire" in requirements.lower()

    def test_functionality_requirements_for_network_protection(self) -> None:
        """_build_functionality_requirements generates network bypass steps."""
        manager = ScriptGenerationPrompts()
        requirements = manager._build_functionality_requirements(["network_validation"])
        assert "network" in requirements.lower()
        assert "intercept" in requirements.lower() or "inject" in requirements.lower()

    def test_functionality_requirements_for_debug_protection(self) -> None:
        """_build_functionality_requirements generates anti-debug bypass steps."""
        manager = ScriptGenerationPrompts()
        requirements = manager._build_functionality_requirements(["debug_detection"])
        assert "debug" in requirements.lower()
        assert "IsDebuggerPresent" in requirements or "PEB" in requirements

    def test_functionality_requirements_combines_multiple_types(self) -> None:
        """_build_functionality_requirements combines requirements for multiple types."""
        manager = ScriptGenerationPrompts()
        requirements = manager._build_functionality_requirements(["license_check", "trial_timer"])
        assert "license" in requirements.lower()
        assert "time" in requirements.lower() or "trial" in requirements.lower()

    def test_functionality_requirements_defaults_for_empty_list(self) -> None:
        """_build_functionality_requirements provides defaults for empty list."""
        manager = ScriptGenerationPrompts()
        requirements = manager._build_functionality_requirements([])
        assert len(requirements) > 0
        assert "analyze" in requirements.lower() or "monitor" in requirements.lower()


class TestBuildPatchingObjectives:
    """Test _build_patching_objectives helper method."""

    def test_patching_objectives_for_license_protection(self) -> None:
        """_build_patching_objectives generates license patching steps."""
        manager = ScriptGenerationPrompts()
        objectives = manager._build_patching_objectives(["license_check"])
        assert "license" in objectives.lower()
        assert "patch" in objectives.lower() or "jump" in objectives.lower()

    def test_patching_objectives_for_trial_protection(self) -> None:
        """_build_patching_objectives generates trial patching steps."""
        manager = ScriptGenerationPrompts()
        objectives = manager._build_patching_objectives(["trial_timer"])
        assert "trial" in objectives.lower() or "time" in objectives.lower()
        assert "patch" in objectives.lower()

    def test_patching_objectives_for_network_protection(self) -> None:
        """_build_patching_objectives generates network patching steps."""
        manager = ScriptGenerationPrompts()
        objectives = manager._build_patching_objectives(["network_validation"])
        assert "network" in objectives.lower()
        assert "success" in objectives.lower() or "bypass" in objectives.lower()

    def test_patching_objectives_includes_nop_instructions(self) -> None:
        """_build_patching_objectives mentions NOP instruction patching."""
        manager = ScriptGenerationPrompts()
        objectives = manager._build_patching_objectives(["license_check"])
        assert "NOP" in objectives or "nop" in objectives.lower()

    def test_patching_objectives_defaults_for_empty_list(self) -> None:
        """_build_patching_objectives provides defaults for empty list."""
        manager = ScriptGenerationPrompts()
        objectives = manager._build_patching_objectives([])
        assert len(objectives) > 0
        assert "patch" in objectives.lower()


class TestGetAvailablePromptTypes:
    """Test get_available_prompt_types method."""

    def test_get_available_prompt_types_returns_list(self) -> None:
        """get_available_prompt_types returns list of strings."""
        manager = ScriptGenerationPrompts()
        types = manager.get_available_prompt_types()
        assert isinstance(types, list)
        assert all(isinstance(t, str) for t in types)

    def test_get_available_prompt_types_includes_all_types(self) -> None:
        """get_available_prompt_types includes all PromptType values."""
        manager = ScriptGenerationPrompts()
        types = manager.get_available_prompt_types()
        assert "frida" in types
        assert "ghidra" in types
        assert "analysis" in types
        assert "refinement" in types
        assert "validation" in types


class TestGetPromptRequirements:
    """Test get_prompt_requirements method."""

    def test_get_prompt_requirements_extracts_parameters(self) -> None:
        """get_prompt_requirements extracts template parameter names."""
        manager = ScriptGenerationPrompts()
        requirements = manager.get_prompt_requirements(PromptType.FRIDA)
        assert isinstance(requirements, list)
        assert "binary_name" in requirements
        assert "protection_types" in requirements

    def test_get_prompt_requirements_for_analysis_prompt(self) -> None:
        """get_prompt_requirements returns parameters for analysis prompt."""
        manager = ScriptGenerationPrompts()
        requirements = manager.get_prompt_requirements(PromptType.ANALYSIS)
        assert "binary_data" in requirements

    def test_get_prompt_requirements_for_refinement_prompt(self) -> None:
        """get_prompt_requirements returns parameters for refinement prompt."""
        manager = ScriptGenerationPrompts()
        requirements = manager.get_prompt_requirements(PromptType.REFINEMENT)
        assert "original_script" in requirements
        assert "test_results" in requirements
        assert "error_feedback" in requirements

    def test_get_prompt_requirements_returns_empty_for_invalid_type(self) -> None:
        """get_prompt_requirements returns empty list for invalid type."""
        manager = ScriptGenerationPrompts()
        requirements = manager.get_prompt_requirements("invalid_type")  # type: ignore[arg-type]
        assert requirements == []


class TestGlobalPromptManager:
    """Test global prompt manager singleton."""

    def test_get_prompt_manager_returns_instance(self) -> None:
        """get_prompt_manager returns ScriptGenerationPrompts instance."""
        manager = get_prompt_manager()
        assert isinstance(manager, ScriptGenerationPrompts)

    def test_get_prompt_manager_returns_singleton(self) -> None:
        """get_prompt_manager returns same instance on multiple calls."""
        manager1 = get_prompt_manager()
        manager2 = get_prompt_manager()
        assert manager1 is manager2


class TestRealWorldScenarios:
    """Test realistic license cracking workflow scenarios."""

    def test_complete_frida_script_generation_workflow(self) -> None:
        """Complete workflow: analyze binary, build context, generate Frida prompt."""
        manager = ScriptGenerationPrompts()

        binary_analysis = {
            "binary_info": {"name": "vmprotect_app.exe", "arch": "x86_64", "platform": "windows", "type": "PE"},
            "functions": [
                {"name": "check_license_key", "address": "0x401000"},
                {"name": "validate_signature", "address": "0x401500"},
            ],
            "imports": ["CryptVerifySignatureW", "RegQueryValueExW"],
            "strings": ["License expired", "Invalid serial number"],
            "protections": [{"type": "VMProtect", "confidence": 0.92}],
        }

        context = manager.build_context_data(binary_analysis, protection_types=["license", "trial"])

        prompt = manager.get_prompt(PromptType.FRIDA, **context)

        assert "vmprotect_app.exe" in prompt["user_template"]
        assert "check_license_key" in prompt["user_template"]
        assert "license" in prompt["user_template"].lower()
        assert "Frida" in prompt["system"]

    def test_complete_ghidra_patching_workflow(self) -> None:
        """Complete workflow: analyze binary, build context, generate Ghidra prompt."""
        manager = ScriptGenerationPrompts()

        binary_analysis = {
            "binary_info": {"name": "themida_app.exe", "arch": "x86", "platform": "windows", "type": "PE"},
            "functions": [{"name": "trial_check", "address": "0x401200"}],
            "imports": ["GetSystemTime"],
            "strings": ["Trial expired"],
            "protections": [{"type": "Themida", "confidence": 0.88}],
        }

        context = manager.build_context_data(binary_analysis, protection_types=["trial"])

        prompt = manager.get_prompt(PromptType.GHIDRA, **context)

        assert "themida_app.exe" in prompt["user_template"]
        assert "trial" in prompt["user_template"].lower()
        assert "Ghidra" in prompt["system"]

    def test_iterative_script_refinement_workflow(self) -> None:
        """Workflow: generate script, test fails, refine with error feedback."""
        manager = ScriptGenerationPrompts()

        original_script = """
Interceptor.attach(Module.findExportByName(null, 'check_license'), {
    onEnter: function(args) {
        console.log('License check called');
    }
});
"""

        test_results = {
            "passed": False,
            "error": "TypeError: Cannot read property 'onEnter' of null",
            "details": "Module.findExportByName returned null",
        }

        error_feedback = "The function check_license was not found. Try searching in the main module."

        prompt = manager.get_prompt(
            PromptType.REFINEMENT,
            original_script=original_script,
            test_results=str(test_results),
            error_feedback=error_feedback,
            performance_issues="None detected",
        )

        assert original_script in prompt["user_template"]
        assert "TypeError" in prompt["user_template"]
        assert "refine" in prompt["system"].lower() or "improve" in prompt["system"].lower()

    def test_multi_protection_analysis_and_generation(self) -> None:
        """Analyze binary with multiple protections and generate comprehensive script."""
        manager = ScriptGenerationPrompts()

        binary_analysis = {
            "binary_info": {"name": "multi_protected.exe", "arch": "x86_64", "platform": "windows", "type": "PE"},
            "functions": [
                {"name": "check_license", "address": "0x401000"},
                {"name": "check_trial", "address": "0x401200"},
                {"name": "verify_online", "address": "0x401400"},
            ],
            "imports": ["CryptVerifySignatureW", "GetSystemTime", "InternetOpenW"],
            "strings": ["License invalid", "Trial expired", "Server connection failed"],
            "protections": [
                {"type": "VMProtect", "confidence": 0.85},
                {"type": "Network License", "confidence": 0.70},
            ],
        }

        context = manager.build_context_data(binary_analysis, protection_types=["license", "trial", "network"])

        prompt = manager.get_prompt(PromptType.FRIDA, **context)

        assert "multi_protected.exe" in prompt["user_template"]
        assert "license" in prompt["user_template"].lower()
        assert "trial" in prompt["user_template"].lower()
        assert "network" in prompt["user_template"].lower()

    def test_script_validation_workflow(self) -> None:
        """Validate generated script for syntax, security, and best practices."""
        manager = ScriptGenerationPrompts()

        script_content = """
Interceptor.attach(Module.findExportByName('app.exe', 'license_check'), {
    onEnter: function(args) {
        console.log('Bypassing license check');
        this.context.eax = 1;
    },
    onLeave: function(retval) {
        retval.replace(1);
    }
});
"""

        prompt = manager.get_prompt(
            PromptType.VALIDATION,
            script_type="Frida JavaScript",
            script_content=script_content,
            validation_requirements="Check for syntax errors, API misuse, and security issues",
        )

        assert script_content in prompt["user_template"]
        assert "Frida JavaScript" in prompt["user_template"]
        assert "validation" in prompt["system"].lower()

    def test_prompt_parameter_requirements_validation(self) -> None:
        """Verify all required parameters for prompt types are documented."""
        manager = ScriptGenerationPrompts()

        frida_requirements = manager.get_prompt_requirements(PromptType.FRIDA)
        ghidra_requirements = manager.get_prompt_requirements(PromptType.GHIDRA)

        assert len(frida_requirements) > 5
        assert len(ghidra_requirements) > 5

        assert "binary_name" in frida_requirements
        assert "protection_types" in frida_requirements
        assert "binary_name" in ghidra_requirements
        assert "patching_objectives" in ghidra_requirements
