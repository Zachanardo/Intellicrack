"""
Unit tests for AI Script Generator

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

import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from intellicrack.ai.ai_script_generator import (
    AIScriptGenerator,
    GeneratedScript,
    ProtectionType,
    ScriptMetadata,
    ScriptTemplateEngine,
    ScriptType,
    ScriptValidator,
)
from intellicrack.ai.llm_backends import LLMManager, LLMResponse


class TestAIScriptGenerator:
    """Test cases for AI Script Generator."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_llm_manager = Mock(spec=LLMManager)
        self.generator = AIScriptGenerator(llm_manager=self.mock_llm_manager)

        # Mock LLM responses
        self.mock_frida_script = '''
Java.perform(function() {
    var LicenseChecker = Java.use("com.example.LicenseChecker");
    LicenseChecker.validateLicense.implementation = function(key) {
        console.log("[+] Bypassing license validation");
        return true;
    };
});
'''

        self.mock_ghidra_script = '''
from ghidra.app.script import GhidraScript

class LicensePatcher(GhidraScript):
    def run(self):
        program = getCurrentProgram()
        memory = program.getMemory()

        # Find license check function
        function_manager = program.getFunctionManager()
        license_func = function_manager.getFunctionAt(getAddressFactory().getAddress("0x401000"))

        if license_func:
            # Patch the function to always return true
            instruction = getInstructionAt(license_func.getEntryPoint())
            if instruction:
                clearListing(instruction, instruction)
                disassemble(instruction)
                print("License check function patched successfully")
'''

    def test_generator_initialization(self):
        """Test AI script generator initialization."""
        assert self.generator.llm_manager == self.mock_llm_manager
        assert isinstance(self.generator.validator, ScriptValidator)
        assert isinstance(self.generator.template_engine, ScriptTemplateEngine)
        assert len(self.generator.generated_scripts) == 0

    def test_generate_frida_script_success(self):
        """Test successful Frida script generation."""
        # Mock analysis data
        analysis_data = {
            "binary_info": {
                "name": "test_app.exe",
                "arch": "x64",
                "platform": "windows"
            },
            "protections": [
                {"type": "license_check", "confidence": 0.9}
            ],
            "functions": [
                {"name": "CheckLicense", "address": "0x401000"}
            ],
            "imports": ["GetSystemTime", "RegQueryValueEx"]
        }

        # Mock LLM response
        mock_response = LLMResponse(content=self.mock_frida_script, finish_reason="stop")
        self.mock_llm_manager.generate_script_content.return_value = self.mock_frida_script

        # Generate script
        result = self.generator.generate_script(
            script_type=ScriptType.FRIDA,
            analysis_data=analysis_data,
            protection_types=[ProtectionType.LICENSE_CHECK]
        )

        # Verify result
        assert result is not None
        assert isinstance(result, GeneratedScript)
        assert result.content == self.mock_frida_script
        assert result.metadata.script_type == ScriptType.FRIDA
        assert ProtectionType.LICENSE_CHECK in result.metadata.protection_types
        assert "test_app.exe" in result.metadata.target_binary

    def test_generate_ghidra_script_success(self):
        """Test successful Ghidra script generation."""
        analysis_data = {
            "binary_info": {
                "name": "protected_binary.exe",
                "arch": "x86",
                "platform": "windows"
            },
            "protections": [
                {"type": "license_check", "confidence": 0.95}
            ]
        }

        self.mock_llm_manager.generate_script_content.return_value = self.mock_ghidra_script

        result = self.generator.generate_script(
            script_type=ScriptType.GHIDRA,
            analysis_data=analysis_data,
            protection_types=[ProtectionType.LICENSE_CHECK]
        )

        assert result is not None
        assert result.content == self.mock_ghidra_script
        assert result.metadata.script_type == ScriptType.GHIDRA
        assert result.language == "python"

    def test_generate_script_llm_failure(self):
        """Test script generation when LLM fails."""
        self.mock_llm_manager.generate_script_content.return_value = None

        result = self.generator.generate_script(
            script_type=ScriptType.FRIDA,
            analysis_data={"binary_info": {"name": "test.exe"}},
            protection_types=[ProtectionType.LICENSE_CHECK]
        )

        assert result is None

    def test_script_validation_success(self):
        """Test script validation with valid script."""
        valid_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="test_001",
                script_type=ScriptType.FRIDA,
                target_binary="test.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content=self.mock_frida_script,
            language="javascript",
            entry_point="main"
        )

        # Mock successful validation
        self.mock_llm_manager.validate_script_syntax.return_value = {
            "valid": True,
            "errors": [],
            "warnings": []
        }

        result = self.generator.validate_script(valid_script)
        assert result["valid"] is True
        assert valid_script.validation_passed is True

    def test_script_validation_failure(self):
        """Test script validation with invalid script."""
        invalid_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="test_002",
                script_type=ScriptType.FRIDA,
                target_binary="test.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content="// TODO: Implement this function",
            language="javascript",
            entry_point="main"
        )

        self.mock_llm_manager.validate_script_syntax.return_value = {
            "valid": False,
            "errors": ["Contains placeholder TODO"],
            "warnings": []
        }

        result = self.generator.validate_script(invalid_script)
        assert result["valid"] is False
        assert len(result["errors"]) > 0
        assert invalid_script.validation_passed is False

    def test_script_refinement(self):
        """Test script refinement based on test results."""
        original_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="test_003",
                script_type=ScriptType.FRIDA,
                target_binary="test.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content="var broken = function() { throw 'error'; };",
            language="javascript",
            entry_point="main"
        )

        test_results = {
            "success": False,
            "error": "TypeError: Cannot read property",
            "execution_time": 0.5
        }

        refined_content = "var fixed = function() { return true; };"
        self.mock_llm_manager.refine_script_content.return_value = refined_content

        result = self.generator.refine_script(
            original_script,
            test_results,
            {"binary_info": {"name": "test.exe"}}
        )

        assert result is not None
        assert result.content == refined_content
        assert result.metadata.iterations == 2

    def test_context_optimization(self):
        """Test context optimization for large analysis data."""
        large_analysis_data = {
            "binary_info": {"name": "large_app.exe"},
            "functions": [{"name": f"func_{i}", "address": f"0x{i:06x}"} for i in range(1000)],
            "strings": [f"string_{i}" for i in range(5000)],
            "imports": [f"import_{i}" for i in range(500)]
        }

        optimized = self.generator.optimize_context_for_llm(large_analysis_data)

        # Should be reduced in size
        assert len(optimized["functions"]) <= 50
        assert len(optimized["strings"]) <= 100
        assert len(optimized["imports"]) <= 30

        # Essential info should be preserved
        assert "binary_info" in optimized
        assert optimized["binary_info"]["name"] == "large_app.exe"

    def test_save_and_load_script(self):
        """Test saving and loading generated scripts."""
        script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="test_004",
                script_type=ScriptType.FRIDA,
                target_binary="save_test.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content=self.mock_frida_script,
            language="javascript",
            entry_point="main"
        )

        # Test saving
        with tempfile.TemporaryDirectory() as temp_dir:
            save_path = Path(temp_dir) / "test_script.json"
            success = self.generator.save_script(script, str(save_path))
            assert success is True
            assert save_path.exists()

            # Test loading
            loaded_script = self.generator.load_script(str(save_path))
            assert loaded_script is not None
            assert loaded_script.metadata.script_id == script.metadata.script_id
            assert loaded_script.content == script.content

    def test_get_generation_history(self):
        """Test getting generation history."""
        # Generate a few scripts
        for i in range(3):
            self.mock_llm_manager.generate_script_content.return_value = f"script_{i}"
            self.generator.generate_script(
                script_type=ScriptType.FRIDA,
                analysis_data={"binary_info": {"name": f"test_{i}.exe"}},
                protection_types=[ProtectionType.LICENSE_CHECK]
            )

        history = self.generator.get_generation_history()
        assert len(history) == 3

        # Test filtering by script type
        frida_history = self.generator.get_generation_history(script_type=ScriptType.FRIDA)
        assert len(frida_history) == 3

        ghidra_history = self.generator.get_generation_history(script_type=ScriptType.GHIDRA)
        assert len(ghidra_history) == 0


class TestScriptValidator:
    """Test cases for Script Validator."""

    def setup_method(self):
        """Set up test fixtures."""
        self.validator = ScriptValidator()

    def test_validate_frida_script_valid(self):
        """Test validation of valid Frida script."""
        valid_frida = '''
Java.perform(function() {
    var Class = Java.use("com.example.Target");
    Class.method.implementation = function() {
        console.log("Hooked!");
        return true;
    };
});
'''

        result = self.validator.validate_script_content(valid_frida, ScriptType.FRIDA)
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    def test_validate_frida_script_invalid(self):
        """Test validation of invalid Frida script."""
        invalid_frida = '''
// TODO: Implement license bypass
var stub = function() {
    // PLACEHOLDER CODE
    return null;
};
'''

        result = self.validator.validate_script_content(invalid_frida, ScriptType.FRIDA)
        assert result["valid"] is False
        assert len(result["errors"]) > 0
        assert any("placeholder" in error.lower() for error in result["errors"])

    def test_validate_ghidra_script_valid(self):
        """Test validation of valid Ghidra script."""
        valid_ghidra = '''
from ghidra.app.script import GhidraScript

class ValidScript(GhidraScript):
    def run(self):
        program = getCurrentProgram()
        print("Script executed successfully")
        return True
'''

        result = self.validator.validate_script_content(valid_ghidra, ScriptType.GHIDRA)
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    def test_validate_ghidra_script_invalid(self):
        """Test validation of invalid Ghidra script."""
        invalid_ghidra = '''
# TODO: Implement this function
def stub_function():
    pass  # Implement later
'''

        result = self.validator.validate_script_content(invalid_ghidra, ScriptType.GHIDRA)
        assert result["valid"] is False
        assert len(result["errors"]) > 0

    def test_check_forbidden_patterns(self):
        """Test detection of forbidden patterns."""
        forbidden_content = '''
// TODO: Fix this
var mock_function = function() {
    // PLACEHOLDER implementation
    return NotImplemented;
};
'''

        errors = self.validator._check_forbidden_patterns(forbidden_content)
        assert len(errors) >= 3  # TODO, PLACEHOLDER, NotImplemented
        assert any("TODO" in error for error in errors)
        assert any("PLACEHOLDER" in error for error in errors)
        assert any("NotImplemented" in error for error in errors)

    def test_check_required_elements_frida(self):
        """Test checking required elements for Frida scripts."""
        # Valid script with required elements
        valid_script = '''
Java.perform(function() {
    var Module = Java.use("test");
    console.log("Hook installed");
    Interceptor.attach(ptr("0x12345"), {
        onEnter: function(args) {
            Memory.readUtf8String(args[0]);
        }
    });
});
'''

        errors = self.validator._check_required_elements(valid_script, ScriptType.FRIDA)
        assert len(errors) == 0

        # Invalid script missing required elements
        invalid_script = "var x = 1; console.log(x);"
        errors = self.validator._check_required_elements(invalid_script, ScriptType.FRIDA)
        assert len(errors) > 0

    def test_check_required_elements_ghidra(self):
        """Test checking required elements for Ghidra scripts."""
        # Valid script with required elements
        valid_script = '''
from ghidra.app.script import GhidraScript

class TestScript(GhidraScript):
    def run(self):
        return True
'''

        errors = self.validator._check_required_elements(valid_script, ScriptType.GHIDRA)
        assert len(errors) == 0

        # Invalid script missing required elements
        invalid_script = "print('Hello World')"
        errors = self.validator._check_required_elements(invalid_script, ScriptType.GHIDRA)
        assert len(errors) > 0


class TestScriptTemplateEngine:
    """Test cases for Script Template Engine."""

    def setup_method(self):
        """Set up test fixtures."""
        self.template_engine = ScriptTemplateEngine()

    def test_get_frida_template(self):
        """Test getting Frida script template."""
        template = self.template_engine.get_template(ScriptType.FRIDA, ProtectionType.LICENSE_CHECK)

        assert template is not None
        assert "Java.perform" in template
        assert "license" in template.lower()
        assert "implementation" in template

    def test_get_ghidra_template(self):
        """Test getting Ghidra script template."""
        template = self.template_engine.get_template(ScriptType.GHIDRA, ProtectionType.TRIAL_TIMER)

        assert template is not None
        assert "GhidraScript" in template
        assert "def run" in template
        assert "trial" in template.lower() or "time" in template.lower()

    def test_render_template_with_context(self):
        """Test rendering template with context data."""
        context = {
            "binary_name": "test_app.exe",
            "target_function": "CheckLicense",
            "target_address": "0x401000"
        }

        template = self.template_engine.get_template(ScriptType.FRIDA, ProtectionType.LICENSE_CHECK)
        rendered = self.template_engine.render_template(template, context)

        assert "test_app.exe" in rendered
        assert "CheckLicense" in rendered
        assert "0x401000" in rendered

    def test_get_available_templates(self):
        """Test getting list of available templates."""
        templates = self.template_engine.get_available_templates()

        assert len(templates) > 0
        assert any(t["script_type"] == ScriptType.FRIDA.value for t in templates)
        assert any(t["script_type"] == ScriptType.GHIDRA.value for t in templates)

    def test_custom_template_registration(self):
        """Test registering custom templates."""
        custom_template = '''
// Custom Frida template for {binary_name}
Java.perform(function() {
    console.log("Custom template for {target_function}");
});
'''

        success = self.template_engine.register_template(
            "custom_license",
            ScriptType.FRIDA,
            ProtectionType.LICENSE_CHECK,
            custom_template
        )

        assert success is True

        # Test retrieval
        retrieved = self.template_engine.get_template(
            ScriptType.FRIDA,
            ProtectionType.LICENSE_CHECK,
            template_name="custom_license"
        )

        assert retrieved == custom_template


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
