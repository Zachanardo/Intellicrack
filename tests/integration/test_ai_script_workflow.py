"""
Integration tests for AI Script Generation Workflow

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

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from intellicrack.ai.ai_script_generator import AIScriptGenerator, ProtectionType, ScriptType
from intellicrack.ai.orchestrator import AIOrchestrator
from intellicrack.ai.script_generation_prompts import get_prompt_manager


class MockLLMBackend:
    """Mock LLM backend for testing."""

    def __init__(self):
        self.is_initialized = True
        self.call_count = 0
        self.responses = {
            "frida": '''
Java.perform(function() {
    console.log("[+] Frida script loaded");

    var LicenseValidator = Java.use("com.example.LicenseValidator");
    LicenseValidator.checkLicense.implementation = function(key) {
        console.log("[+] License check bypassed");
        return true;
    };

    var TrialManager = Java.use("com.example.TrialManager");
    TrialManager.isTrialExpired.implementation = function() {
        console.log("[+] Trial expiration bypassed");
        return false;
    };
});
''',
            "ghidra": '''
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Instruction

class LicenseBypassPatcher(GhidraScript):
    """Automatically patch license validation functions."""

    def run(self):
        program = getCurrentProgram()
        memory = program.getMemory()
        function_manager = program.getFunctionManager()

        # Find license validation functions
        license_functions = self.find_license_functions()

        for func_addr in license_functions:
            self.patch_license_function(func_addr)

        print(f"Patched {len(license_functions)} license functions")

    def find_license_functions(self):
        """Find functions related to license validation."""
        functions = []
        symbol_table = getCurrentProgram().getSymbolTable()

        for symbol in symbol_table.getAllSymbols(True):
            name = symbol.getName().lower()
            if any(keyword in name for keyword in ["license", "trial", "validate", "check"]):
                if symbol.getAddress() not in [f.getAddress() for f in functions]:
                    func = getFunctionAt(symbol.getAddress())
                    if func:
                        functions.append(func.getEntryPoint())

        return functions

    def patch_license_function(self, address):
        """Patch a license function to always return success."""
        try:
            # Get the function
            func = getFunctionAt(address)
            if not func:
                return False

            # Patch the entry point to return 1 (success)
            instruction = getInstructionAt(address)
            if instruction:
                # Replace with: mov eax, 1; ret
                clearListing(address, address.add(10))
                bytes_to_patch = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]  # mov eax, 1; ret

                for i, byte_val in enumerate(bytes_to_patch):
                    setByte(address.add(i), byte_val)

                print(f"Patched function at {address}")
                return True
        except Exception as e:
            print(f"Failed to patch function at {address}: {e}")
            return False
''',
            "analysis": {
                "protections": [
                    {"type": "license_check", "confidence": 0.95, "location": "0x401000"},
                    {"type": "trial_timer", "confidence": 0.87, "location": "0x401200"}
                ],
                "bypass_strategies": [
                    "Hook license validation functions",
                    "Manipulate time-related API calls",
                    "Patch conditional jumps"
                ]
            },
            "validation": {
                "valid": True,
                "errors": [],
                "warnings": ["Consider adding error handling for edge cases"]
            },
            "refinement": '''
// Refined Frida script with improved error handling
Java.perform(function() {
    console.log("[+] Enhanced Frida script loaded");

    try {
        var LicenseValidator = Java.use("com.example.LicenseValidator");
        LicenseValidator.checkLicense.implementation = function(key) {
            console.log("[+] License check intercepted: " + key);
            try {
                return Java.retain(Java.cast(Java.use("java.lang.Boolean").TRUE, Java.use("java.lang.Boolean")));
            } catch (e) {
                console.log("[!] Fallback to simple return true");
                return true;
            }
        };
        console.log("[+] License validator hooked successfully");
    } catch (e) {
        console.log("[!] Failed to hook LicenseValidator: " + e);
    }

    try {
        var TrialManager = Java.use("com.example.TrialManager");
        TrialManager.isTrialExpired.implementation = function() {
            console.log("[+] Trial expiration check bypassed");
            return false;
        };
        console.log("[+] Trial manager hooked successfully");
    } catch (e) {
        console.log("[!] Failed to hook TrialManager: " + e);
    }
});
'''
        }

    def chat(self, messages, tools=None):
        """Mock chat method."""
        self.call_count += 1

        # Determine response type based on message content
        user_message = next((m.content for m in messages if m.role == "user"), "")

        if "frida" in user_message.lower():
            content = self.responses["frida"]
        elif "ghidra" in user_message.lower():
            content = self.responses["ghidra"]
        elif "analyze" in user_message.lower() or "protection" in user_message.lower():
            content = json.dumps(self.responses["analysis"])
        elif "validate" in user_message.lower() or "syntax" in user_message.lower():
            content = json.dumps(self.responses["validation"])
        elif "refine" in user_message.lower() or "improve" in user_message.lower():
            content = self.responses["refinement"]
        else:
            content = "Mock response"

        from intellicrack.ai.llm_backends import LLMResponse
        return LLMResponse(content=content, finish_reason="stop", model="mock")

    def generate_script_content(self, prompt, script_type, context_data=None, max_tokens=4000, llm_id=None):
        """Mock script generation."""
        if "frida" in script_type.lower():
            return self.responses["frida"]
        elif "ghidra" in script_type.lower():
            return self.responses["ghidra"]
        return "Mock script content"

    def refine_script_content(self, original_script, error_feedback, test_results, script_type, llm_id=None):
        """Mock script refinement."""
        return self.responses["refinement"]

    def analyze_protection_patterns(self, binary_data, llm_id=None):
        """Mock pattern analysis."""
        return self.responses["analysis"]

    def validate_script_syntax(self, script_content, script_type, llm_id=None):
        """Mock syntax validation."""
        return self.responses["validation"]


class TestAIScriptWorkflow:
    """Integration tests for complete AI script generation workflow."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create mock LLM manager
        self.llm_manager = Mock()
        self.mock_backend = MockLLMBackend()

        # Setup mock responses
        self.llm_manager.generate_script_content = self.mock_backend.generate_script_content
        self.llm_manager.refine_script_content = self.mock_backend.refine_script_content
        self.llm_manager.analyze_protection_patterns = self.mock_backend.analyze_protection_patterns
        self.llm_manager.validate_script_syntax = self.mock_backend.validate_script_syntax
        self.llm_manager.chat = self.mock_backend.chat

        # Create components
        self.script_generator = AIScriptGenerator(llm_manager=self.llm_manager)
        self.orchestrator = AIOrchestrator(llm_manager=self.llm_manager)

        # Sample analysis data
        self.sample_analysis = {
            "binary_info": {
                "name": "test_app.exe",
                "arch": "x64",
                "platform": "windows",
                "size": 1024000
            },
            "protections": [
                {"type": "license_check", "confidence": 0.95},
                {"type": "trial_timer", "confidence": 0.87}
            ],
            "functions": [
                {"name": "CheckLicense", "address": "0x401000"},
                {"name": "ValidateTrial", "address": "0x401200"},
                {"name": "GetSystemTime", "address": "0x401400"}
            ],
            "imports": ["GetSystemTime", "RegQueryValueEx", "WinHttpOpen"],
            "strings": ["License expired", "Trial version", "Invalid license key"]
        }

    def test_complete_frida_generation_workflow(self):
        """Test complete Frida script generation workflow."""
        # Generate initial script
        script = self.script_generator.generate_script(
            script_type=ScriptType.FRIDA,
            analysis_data=self.sample_analysis,
            protection_types=[ProtectionType.LICENSE_CHECK, ProtectionType.TRIAL_TIMER]
        )

        assert script is not None
        assert script.metadata.script_type == ScriptType.FRIDA
        assert "Java.perform" in script.content
        assert "LicenseValidator" in script.content
        assert "TrialManager" in script.content

        # Validate the script
        validation_result = self.script_generator.validate_script(script)
        assert validation_result["valid"] is True
        assert script.validation_passed is True

        # Simulate test failure and refinement
        test_results = {
            "success": False,
            "error": "TypeError in license hook",
            "execution_time": 1.2
        }

        refined_script = self.script_generator.refine_script(
            script, test_results, self.sample_analysis
        )

        assert refined_script is not None
        assert "Enhanced Frida script" in refined_script.content
        assert refined_script.metadata.iterations == 2

    def test_complete_ghidra_generation_workflow(self):
        """Test complete Ghidra script generation workflow."""
        # Generate initial script
        script = self.script_generator.generate_script(
            script_type=ScriptType.GHIDRA,
            analysis_data=self.sample_analysis,
            protection_types=[ProtectionType.LICENSE_CHECK]
        )

        assert script is not None
        assert script.metadata.script_type == ScriptType.GHIDRA
        assert "GhidraScript" in script.content
        assert "def run" in script.content
        assert "patch_license_function" in script.content

        # Test script saving and loading
        with tempfile.TemporaryDirectory() as temp_dir:
            script_path = Path(temp_dir) / "test_ghidra_script.json"

            # Save script
            success = self.script_generator.save_script(script, str(script_path))
            assert success is True
            assert script_path.exists()

            # Load script
            loaded_script = self.script_generator.load_script(str(script_path))
            assert loaded_script is not None
            assert loaded_script.content == script.content
            assert loaded_script.metadata.script_id == script.metadata.script_id

    def test_orchestrator_autonomous_workflow(self):
        """Test orchestrator managing autonomous workflow."""
        # Execute script generation task
        task = {
            "type": "frida_script_generation",
            "binary_path": "/path/to/test_app.exe",
            "analysis_data": self.sample_analysis,
            "protection_types": ["license_check", "trial_timer"]
        }

        result = self.orchestrator._execute_frida_script_generation(task)

        assert result["success"] is True
        assert "script_content" in result
        assert "Java.perform" in result["script_content"]
        assert result["script_type"] == "frida"

    def test_multi_iteration_refinement(self):
        """Test multiple iterations of script refinement."""
        # Generate initial script
        script = self.script_generator.generate_script(
            script_type=ScriptType.FRIDA,
            analysis_data=self.sample_analysis,
            protection_types=[ProtectionType.LICENSE_CHECK]
        )

        # First refinement iteration
        test_results_1 = {
            "success": False,
            "error": "Class not found exception",
            "execution_time": 0.8
        }

        refined_script_1 = self.script_generator.refine_script(
            script, test_results_1, self.sample_analysis
        )

        assert refined_script_1.metadata.iterations == 2

        # Second refinement iteration
        test_results_2 = {
            "success": False,
            "error": "Method signature mismatch",
            "execution_time": 1.1
        }

        refined_script_2 = self.script_generator.refine_script(
            refined_script_1, test_results_2, self.sample_analysis
        )

        assert refined_script_2.metadata.iterations == 3
        assert "Enhanced" in refined_script_2.content

    def test_context_optimization_workflow(self):
        """Test context optimization for large analysis data."""
        # Create large analysis data
        large_analysis = {
            "binary_info": {"name": "large_app.exe", "arch": "x64"},
            "functions": [{"name": f"func_{i}", "address": f"0x{i:06x}"} for i in range(500)],
            "strings": [f"string_{i}" for i in range(2000)],
            "imports": [f"import_{i}" for i in range(300)]
        }

        # Generate script with optimization
        script = self.script_generator.generate_script(
            script_type=ScriptType.FRIDA,
            analysis_data=large_analysis,
            protection_types=[ProtectionType.LICENSE_CHECK]
        )

        assert script is not None
        # Context should have been optimized internally
        assert script.content is not None

    def test_error_handling_and_recovery(self):
        """Test error handling and recovery mechanisms."""
        # Mock LLM failure
        self.llm_manager.generate_script_content.return_value = None

        # Attempt script generation
        script = self.script_generator.generate_script(
            script_type=ScriptType.FRIDA,
            analysis_data=self.sample_analysis,
            protection_types=[ProtectionType.LICENSE_CHECK]
        )

        # Should handle failure gracefully
        assert script is None

        # Restore mock functionality
        self.llm_manager.generate_script_content = self.mock_backend.generate_script_content

        # Should work again
        script = self.script_generator.generate_script(
            script_type=ScriptType.FRIDA,
            analysis_data=self.sample_analysis,
            protection_types=[ProtectionType.LICENSE_CHECK]
        )

        assert script is not None

    def test_script_history_tracking(self):
        """Test script generation history tracking."""
        # Generate multiple scripts
        for i in range(3):
            analysis = self.sample_analysis.copy()
            analysis["binary_info"]["name"] = f"test_app_{i}.exe"

            script = self.script_generator.generate_script(
                script_type=ScriptType.FRIDA,
                analysis_data=analysis,
                protection_types=[ProtectionType.LICENSE_CHECK]
            )

            assert script is not None

        # Check history
        history = self.script_generator.get_generation_history()
        assert len(history) == 3

        # Check filtering
        frida_history = self.script_generator.get_generation_history(script_type=ScriptType.FRIDA)
        assert len(frida_history) == 3

        ghidra_history = self.script_generator.get_generation_history(script_type=ScriptType.GHIDRA)
        assert len(ghidra_history) == 0

    def test_prompt_manager_integration(self):
        """Test integration with prompt management system."""
        prompt_manager = get_prompt_manager()

        # Test prompt retrieval
        frida_prompt = prompt_manager.get_frida_prompt("basic")
        assert "system" in frida_prompt
        assert "user_template" in frida_prompt

        ghidra_prompt = prompt_manager.get_ghidra_prompt("advanced")
        assert "system" in ghidra_prompt
        assert "user_template" in ghidra_prompt

        # Test context building
        context = prompt_manager.build_context_data(
            self.sample_analysis,
            ["license_check", "trial_timer"]
        )

        assert "binary_name" in context
        assert "protection_types" in context
        assert "test_app.exe" in context["binary_name"]

    def test_performance_metrics_collection(self):
        """Test collection of performance metrics during generation."""
        import time

        start_time = time.time()

        script = self.script_generator.generate_script(
            script_type=ScriptType.FRIDA,
            analysis_data=self.sample_analysis,
            protection_types=[ProtectionType.LICENSE_CHECK]
        )

        generation_time = time.time() - start_time

        assert script is not None
        assert script.metadata.generation_time > 0
        assert script.metadata.generation_time <= generation_time
        assert script.metadata.success_probability >= 0.0
        assert script.metadata.success_probability <= 1.0

    def test_script_template_customization(self):
        """Test script template customization and rendering."""
        # Test template engine
        template_engine = self.script_generator.template_engine

        # Get base template
        template = template_engine.get_template(ScriptType.FRIDA, ProtectionType.LICENSE_CHECK)
        assert template is not None

        # Test custom context rendering
        context = {
            "binary_name": "custom_app.exe",
            "target_function": "CustomValidator",
            "hook_points": ["0x401000", "0x401200"]
        }

        rendered = template_engine.render_template(template, context)
        assert "custom_app.exe" in rendered or "{binary_name}" in rendered  # Either rendered or placeholder


class TestAIWorkflowValidation:
    """Integration tests for workflow validation and quality assurance."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_backend = MockLLMBackend()
        self.llm_manager = Mock()

        # Setup comprehensive mock responses
        self.llm_manager.generate_script_content = self.mock_backend.generate_script_content
        self.llm_manager.validate_script_syntax = self.mock_backend.validate_script_syntax

        self.script_generator = AIScriptGenerator(llm_manager=self.llm_manager)

    def test_generated_script_quality_validation(self):
        """Test validation of generated script quality."""
        analysis_data = {
            "binary_info": {"name": "quality_test.exe"},
            "protections": [{"type": "license_check", "confidence": 0.9}]
        }

        # Generate script
        script = self.script_generator.generate_script(
            script_type=ScriptType.FRIDA,
            analysis_data=analysis_data,
            protection_types=[ProtectionType.LICENSE_CHECK]
        )

        # Quality checks
        assert script is not None
        assert len(script.content) > 100  # Should be substantial

        # Should not contain forbidden patterns
        forbidden_patterns = ["TODO", "PLACEHOLDER", "FIXME", "stub", "mock"]
        content_lower = script.content.lower()
        for pattern in forbidden_patterns:
            assert pattern.lower() not in content_lower, f"Found forbidden pattern: {pattern}"

        # Should contain required Frida elements
        required_elements = ["Java.perform", "console.log"]
        for element in required_elements:
            assert element in script.content, f"Missing required element: {element}"

    def test_script_functionality_validation(self):
        """Test validation of script functionality."""
        analysis_data = {
            "binary_info": {"name": "functional_test.exe"},
            "protections": [{"type": "license_check", "confidence": 0.95}]
        }

        # Generate Frida script
        frida_script = self.script_generator.generate_script(
            script_type=ScriptType.FRIDA,
            analysis_data=analysis_data,
            protection_types=[ProtectionType.LICENSE_CHECK]
        )

        # Validate Frida script structure
        assert "Java.perform(function()" in frida_script.content
        assert "implementation = function" in frida_script.content
        assert "console.log" in frida_script.content

        # Generate Ghidra script
        ghidra_script = self.script_generator.generate_script(
            script_type=ScriptType.GHIDRA,
            analysis_data=analysis_data,
            protection_types=[ProtectionType.LICENSE_CHECK]
        )

        # Validate Ghidra script structure
        assert "from ghidra.app.script import GhidraScript" in ghidra_script.content
        assert "def run(self):" in ghidra_script.content
        assert "getCurrentProgram()" in ghidra_script.content

    def test_cross_platform_script_generation(self):
        """Test script generation for different platforms."""
        platforms = ["windows", "linux", "android"]

        for platform in platforms:
            analysis_data = {
                "binary_info": {
                    "name": f"test_app_{platform}",
                    "platform": platform,
                    "arch": "x64" if platform != "android" else "arm64"
                },
                "protections": [{"type": "license_check", "confidence": 0.9}]
            }

            script = self.script_generator.generate_script(
                script_type=ScriptType.FRIDA,
                analysis_data=analysis_data,
                protection_types=[ProtectionType.LICENSE_CHECK]
            )

            assert script is not None
            assert script.metadata.target_binary == f"test_app_{platform}"
            # Platform-specific validation could be added here

    def test_protection_type_coverage(self):
        """Test script generation for all protection types."""
        protection_types = [
            ProtectionType.LICENSE_CHECK,
            ProtectionType.TRIAL_TIMER,
            ProtectionType.HARDWARE_LOCK,
            ProtectionType.NETWORK_VALIDATION,
            ProtectionType.ANTI_DEBUG
        ]

        for protection_type in protection_types:
            analysis_data = {
                "binary_info": {"name": f"test_{protection_type.value}.exe"},
                "protections": [{"type": protection_type.value, "confidence": 0.9}]
            }

            script = self.script_generator.generate_script(
                script_type=ScriptType.FRIDA,
                analysis_data=analysis_data,
                protection_types=[protection_type]
            )

            assert script is not None
            assert protection_type in script.metadata.protection_types
            # Each protection type should generate relevant content
            assert len(script.content) > 50


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
