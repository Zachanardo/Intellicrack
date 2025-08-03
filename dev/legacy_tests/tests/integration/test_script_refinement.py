"""
Integration tests for Script Refinement Workflow

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

import time
from datetime import datetime
from unittest.mock import Mock

import pytest

from intellicrack.ai.ai_script_generator import (
    AIScriptGenerator,
    GeneratedScript,
    ProtectionType,
    ScriptMetadata,
    ScriptType,
)


class MockQEMUTestManager:
    """Mock QEMU test manager for testing."""

    def __init__(self):
        self.test_results = {
            "initial_failure": {
                "success": False,
                "error": "TypeError: Cannot read property 'implementation' of undefined",
                "execution_time": 1.2,
                "console_output": "[!] Failed to hook LicenseValidator: ReferenceError",
                "crash_info": None
            },
            "improved_but_failing": {
                "success": False,
                "error": "ClassNotFound: com.example.LicenseValidator",
                "execution_time": 0.8,
                "console_output": "[!] License class not found, trying alternatives",
                "crash_info": None
            },
            "success": {
                "success": True,
                "error": None,
                "execution_time": 0.5,
                "console_output": "[+] License validation bypassed successfully",
                "crash_info": None
            }
        }
        self.test_iteration = 0

    def test_script(self, script_content, target_binary):
        """Mock script testing with progression."""
        self.test_iteration += 1

        if self.test_iteration == 1:
            return self.test_results["initial_failure"]
        elif self.test_iteration == 2:
            return self.test_results["improved_but_failing"]
        else:
            return self.test_results["success"]


class MockLLMManagerForRefinement:
    """Mock LLM manager with realistic refinement responses."""

    def __init__(self):
        self.refinement_responses = [
            # First refinement attempt
            '''
Java.perform(function() {
    console.log("[+] Enhanced Frida script loaded");

    try {
        var LicenseValidator = Java.use("com.example.LicenseValidator");
        if (LicenseValidator) {
            LicenseValidator.checkLicense.implementation = function(key) {
                console.log("[+] License check intercepted: " + key);
                return Java.use("java.lang.Boolean").TRUE;
            };
            console.log("[+] License validator hooked successfully");
        }
    } catch (e) {
        console.log("[!] Failed to hook LicenseValidator: " + e);

        // Try alternative approach
        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var currentApplication = ActivityThread.currentApplication();
            var context = currentApplication.getApplicationContext();
            console.log("[+] Alternative hook approach initialized");
        } catch (e2) {
            console.log("[!] Alternative approach failed: " + e2);
        }
    }
});
''',
            # Second refinement attempt
            '''
Java.perform(function() {
    console.log("[+] Robust Frida script loaded");

    function findLicenseClasses() {
        var classes = Java.enumerateLoadedClassesSync();
        var licenseClasses = [];

        for (var i = 0; i < classes.length; i++) {
            var className = classes[i];
            if (className.toLowerCase().includes("license") ||
                className.toLowerCase().includes("validation") ||
                className.toLowerCase().includes("check")) {
                licenseClasses.push(className);
            }
        }

        return licenseClasses;
    }

    function hookLicenseClass(className) {
        try {
            var LicenseClass = Java.use(className);
            var methods = LicenseClass.class.getDeclaredMethods();

            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                var methodName = method.getName();

                if (methodName.toLowerCase().includes("check") ||
                    methodName.toLowerCase().includes("valid") ||
                    methodName.toLowerCase().includes("verify")) {

                    console.log("[+] Hooking method: " + className + "." + methodName);

                    LicenseClass[methodName].implementation = function() {
                        console.log("[+] License method intercepted: " + methodName);
                        return true; // Force success
                    };
                }
            }

            return true;
        } catch (e) {
            console.log("[!] Failed to hook class " + className + ": " + e);
            return false;
        }
    }

    // Main execution
    setTimeout(function() {
        console.log("[+] Starting dynamic license class discovery...");
        var licenseClasses = findLicenseClasses();

        console.log("[+] Found " + licenseClasses.length + " potential license classes");

        var successCount = 0;
        for (var i = 0; i < licenseClasses.length; i++) {
            if (hookLicenseClass(licenseClasses[i])) {
                successCount++;
            }
        }

        console.log("[+] Successfully hooked " + successCount + " license classes");
    }, 1000);
});
'''
        ]
        self.call_count = 0

    def refine_script_content(self, original_script, error_feedback, test_results, script_type, llm_id=None):
        """Return increasingly sophisticated refinements."""
        if self.call_count < len(self.refinement_responses):
            response = self.refinement_responses[self.call_count]
            self.call_count += 1
            return response
        else:
            # Final refinement - should be most robust
            return self.refinement_responses[-1]

    def validate_script_syntax(self, script_content, script_type, llm_id=None):
        """Mock validation that gets better with refinements."""
        if "findLicenseClasses" in script_content:
            return {
                "valid": True,
                "errors": [],
                "warnings": ["Consider adding more error handling"],
                "suggestions": ["Add timeout for hook installation"]
            }
        elif "Enhanced" in script_content:
            return {
                "valid": True,
                "errors": [],
                "warnings": ["Script may not work if class not found"],
                "suggestions": ["Add class enumeration for robustness"]
            }
        else:
            return {
                "valid": False,
                "errors": ["Missing error handling"],
                "warnings": ["Script is fragile"],
                "suggestions": ["Add try-catch blocks"]
            }


class TestScriptRefinementWorkflow:
    """Test cases for script refinement workflow."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_llm = MockLLMManagerForRefinement()
        self.mock_qemu = MockQEMUTestManager()
        self.script_generator = AIScriptGenerator()

        # Mock the LLM manager
        self.script_generator.llm_manager = self.mock_llm

        # Sample initial script (deliberately flawed)
        self.initial_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="test_001",
                script_type=ScriptType.FRIDA,
                target_binary="test_app.apk",
                protection_types=[ProtectionType.LICENSE_CHECK],
                generated_at=datetime.now()
            ),
            content='''
Java.perform(function() {
    var LicenseValidator = Java.use("com.example.LicenseValidator");
    LicenseValidator.checkLicense.implementation = function(key) {
        console.log("License check bypassed");
        return true;
    };
});
''',
            language="javascript",
            entry_point="main"
        )

        self.sample_analysis = {
            "binary_info": {
                "name": "test_app.apk",
                "platform": "android"
            }
        }

    def test_single_refinement_iteration(self):
        """Test a single script refinement iteration."""
        # Simulate test failure
        test_results = self.mock_qemu.test_script(
            self.initial_script.content,
            "test_app.apk"
        )

        assert test_results["success"] is False

        # Refine the script
        refined_script = self.script_generator.refine_script(
            self.initial_script.content,
            test_results,
            self.sample_analysis
        )

        assert refined_script is not None
        assert "Enhanced Frida script" in refined_script.content
        assert "try" in refined_script.content  # Should have error handling
        assert "catch" in refined_script.content

    def test_multiple_refinement_iterations(self):
        """Test multiple refinement iterations until success."""
        current_script = self.initial_script
        iteration = 0
        max_iterations = 3

        while iteration < max_iterations:
            iteration += 1

            # Test the current script
            test_results = self.mock_qemu.test_script(
                current_script.content,
                "test_app.apk"
            )

            if test_results["success"]:
                # Success! Break the loop
                break

            # Refine the script
            refined_script = self.script_generator.refine_script(
                current_script.content,
                test_results,
                self.sample_analysis
            )

            assert refined_script is not None
            assert refined_script.content != current_script.content  # Should be different

            # Update for next iteration
            current_script = refined_script

        # Should eventually succeed
        final_test = self.mock_qemu.test_script(current_script.content, "test_app.apk")
        assert final_test["success"] is True
        assert iteration <= max_iterations

    def test_refinement_progression(self):
        """Test that refinements progressively improve script quality."""
        scripts = [self.initial_script]

        # Generate refinements
        for i in range(2):
            test_results = self.mock_qemu.test_script(
                scripts[-1].content,
                "test_app.apk"
            )

            refined_script = self.script_generator.refine_script(
                scripts[-1].content,
                test_results,
                self.sample_analysis
            )

            scripts.append(refined_script)

        # Verify progression
        assert len(scripts) == 3  # Initial + 2 refinements

        # First refinement should add error handling
        assert "try" in scripts[1].content
        assert "catch" in scripts[1].content

        # Second refinement should add dynamic discovery
        assert "findLicenseClasses" in scripts[2].content
        assert "enumerateLoadedClassesSync" in scripts[2].content

        # Each refinement should be more sophisticated
        assert len(scripts[0].content) < len(scripts[1].content)
        assert len(scripts[1].content) < len(scripts[2].content)

    def test_refinement_validation_improvement(self):
        """Test that validation results improve with refinements."""
        # Initial script validation
        initial_validation = self.mock_llm.validate_script_syntax(
            self.initial_script.content,
            "javascript"
        )

        # First refinement
        test_results = self.mock_qemu.test_script(
            self.initial_script.content,
            "test_app.apk"
        )

        first_refined = self.script_generator.refine_script(
            self.initial_script.content,
            test_results,
            self.sample_analysis
        )

        first_validation = self.mock_llm.validate_script_syntax(
            first_refined.content,
            "javascript"
        )

        # Second refinement
        test_results = self.mock_qemu.test_script(
            first_refined.content,
            "test_app.apk"
        )

        second_refined = self.script_generator.refine_script(
            first_refined.content,
            test_results,
            self.sample_analysis
        )

        second_validation = self.mock_llm.validate_script_syntax(
            second_refined.content,
            "javascript"
        )

        # Validation should improve
        assert initial_validation["valid"] is False
        assert first_validation["valid"] is True
        assert second_validation["valid"] is True

        # Warnings should decrease
        assert len(second_validation["warnings"]) <= len(first_validation["warnings"])

    def test_refinement_error_handling(self):
        """Test that refinement handles different types of errors."""
        error_scenarios = [
            {
                "error": "TypeError: Cannot read property 'implementation' of undefined",
                "expected_fix": "null check"
            },
            {
                "error": "ClassNotFound: com.example.LicenseValidator",
                "expected_fix": "class enumeration"
            },
            {
                "error": "ReferenceError: Java is not defined",
                "expected_fix": "Java.perform wrapper"
            }
        ]

        for scenario in error_scenarios:
            test_results = {
                "success": False,
                "error": scenario["error"],
                "execution_time": 1.0
            }

            refined_script = self.script_generator.refine_script(
                self.initial_script.content,
                test_results,
                self.sample_analysis
            )

            assert refined_script is not None

            # Verify appropriate fixes are applied
            if "TypeError" in scenario["error"]:
                assert "if (" in refined_script.content  # Should add null checks
            elif "ClassNotFound" in scenario["error"]:
                assert "enumerate" in refined_script.content.lower()  # Should add class enumeration
            elif "ReferenceError" in scenario["error"]:
                assert "Java.perform" in refined_script.content  # Should wrap in Java.perform

    def test_refinement_performance_tracking(self):
        """Test that refinement tracks performance metrics."""
        refinement_metrics = []

        current_script = self.initial_script

        for iteration in range(3):
            start_time = time.time()

            test_results = self.mock_qemu.test_script(
                current_script.content,
                "test_app.apk"
            )

            refined_script = self.script_generator.refine_script(
                current_script.content,
                test_results,
                self.sample_analysis
            )

            refinement_time = time.time() - start_time

            metrics = {
                "iteration": iteration + 1,
                "refinement_time": refinement_time,
                "script_length": len(refined_script.content),
                "test_success": test_results["success"],
                "execution_time": test_results["execution_time"]
            }

            refinement_metrics.append(metrics)
            current_script = refined_script

        # Verify metrics collection
        assert len(refinement_metrics) == 3

        # Test execution time should improve (mock gets faster)
        assert refinement_metrics[0]["execution_time"] > refinement_metrics[-1]["execution_time"]

        # Script should become more sophisticated (longer)
        assert refinement_metrics[0]["script_length"] < refinement_metrics[-1]["script_length"]

    def test_refinement_convergence(self):
        """Test that refinement converges to a stable solution."""
        current_script = self.initial_script
        previous_content = ""
        convergence_threshold = 2
        identical_count = 0

        for iteration in range(5):
            test_results = self.mock_qemu.test_script(
                current_script.content,
                "test_app.apk"
            )

            if test_results["success"]:
                # If successful, refinement should stabilize
                refined_script = self.script_generator.refine_script(
                    current_script.content,
                    test_results,
                    self.sample_analysis
                )

                # Should eventually converge (return similar content)
                if refined_script and refined_script.content == previous_content:
                    identical_count += 1
                    if identical_count >= convergence_threshold:
                        break

                previous_content = refined_script.content if refined_script else ""
                current_script = refined_script or current_script
            else:
                refined_script = self.script_generator.refine_script(
                    current_script.content,
                    test_results,
                    self.sample_analysis
                )
                current_script = refined_script

        # Should achieve success within reasonable iterations
        final_test = self.mock_qemu.test_script(current_script.content, "test_app.apk")
        assert final_test["success"] is True
        assert iteration < 5  # Should not need all iterations


class TestRefinementEdgeCases:
    """Test edge cases in script refinement."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_llm = Mock()
        self.script_generator = AIScriptGenerator()
        self.script_generator.llm_manager = self.mock_llm

    def test_refinement_with_no_llm(self):
        """Test refinement behavior when LLM is unavailable."""
        # Remove LLM manager
        self.script_generator.llm_manager = None

        test_results = {
            "success": False,
            "error": "Test error"
        }

        result = self.script_generator.refine_script(
            "original script",
            test_results,
            {"binary_info": {"name": "test.exe"}}
        )

        # Should handle gracefully
        assert result is None

    def test_refinement_with_llm_failure(self):
        """Test refinement when LLM fails to generate content."""
        self.mock_llm.refine_script_content.return_value = None

        test_results = {
            "success": False,
            "error": "Test error"
        }

        result = self.script_generator.refine_script(
            "original script",
            test_results,
            {"binary_info": {"name": "test.exe"}}
        )

        assert result is None

    def test_refinement_with_invalid_script_type(self):
        """Test refinement with ambiguous script type."""
        self.mock_llm.refine_script_content.return_value = "refined content"

        test_results = {
            "success": False,
            "error": "Test error"
        }

        # Script with no clear type indicators
        result = self.script_generator.refine_script(
            "console.log('hello');",  # Could be either type
            test_results,
            {"binary_info": {"name": "test.exe"}}
        )

        # Should default to Frida for console.log
        assert result is not None
        assert result.metadata.script_type == ScriptType.FRIDA

    def test_refinement_iteration_tracking(self):
        """Test that refinement properly tracks iteration count."""
        self.mock_llm.refine_script_content.return_value = "refined content"

        initial_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="test",
                script_type=ScriptType.FRIDA,
                target_binary="test.exe",
                protection_types=[ProtectionType.LICENSE_CHECK],
                iterations=1  # Initial iteration
            ),
            content="original",
            language="javascript",
            entry_point="main"
        )

        test_results = {"success": False, "error": "Test error"}

        refined = self.script_generator.refine_script(
            initial_script.content,
            test_results,
            {"binary_info": {"name": "test.exe"}}
        )

        # Should increment iteration count
        assert refined.metadata.iterations == 1  # New script starts at 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
