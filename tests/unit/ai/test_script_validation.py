"""
Unit tests for Script Validation System

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

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from intellicrack.ai.ai_script_generator import (
    ScriptValidator, ScriptType, ProtectionType,
    ScriptMetadata, GeneratedScript
)


class TestScriptValidator:
    """Comprehensive tests for script validation system."""

    def setup_method(self):
        """Set up test fixtures."""
        self.validator = ScriptValidator()

    def test_validator_initialization(self):
        """Test validator initialization with proper configuration."""
        assert len(self.validator.forbidden_patterns) > 0
        assert len(self.validator.required_frida_elements) > 0
        assert len(self.validator.required_ghidra_elements) > 0
        assert self.validator.max_context_tokens > 0
        assert 0 < self.validator.context_compression_ratio < 1

    def test_forbidden_pattern_detection(self):
        """Test detection of forbidden patterns in scripts."""
        test_cases = [
            {
                "content": "// TODO: Implement this function",
                "should_fail": True,
                "pattern": "TODO"
            },
            {
                "content": "var placeholder = function() { return null; };",
                "should_fail": True,
                "pattern": "placeholder"
            },
            {
                "content": "// FIXME: This is broken",
                "should_fail": True,
                "pattern": "FIXME"
            },
            {
                "content": "function stub() { /* Implement later */ }",
                "should_fail": True,
                "pattern": "stub"
            },
            {
                "content": "var mockData = { test: true };",
                "should_fail": True,
                "pattern": "mock"
            },
            {
                "content": "function realImplementation() { return true; }",
                "should_fail": False,
                "pattern": None
            }
        ]

        for case in test_cases:
            errors = self.validator._check_forbidden_patterns(case["content"])

            if case["should_fail"]:
                assert len(errors) > 0
                assert any(case["pattern"] in error for error in errors)
            else:
                forbidden_found = any(
                    pattern in case["content"] 
                    for pattern in self.validator.forbidden_patterns
                )
                assert not forbidden_found

    def test_frida_script_validation(self):
        """Test Frida-specific script validation."""
        # Valid Frida script
        valid_frida = '''
Java.perform(function() {
    console.log("[+] Frida script loaded");

    var LicenseChecker = Java.use("com.example.LicenseChecker");
    LicenseChecker.validateLicense.implementation = function(key) {
        console.log("[+] License validation intercepted");
        return true;
    };

    Interceptor.attach(Module.findExportByName(null, "strcmp"), {
        onEnter: function(args) {
            console.log("[+] String comparison intercepted");
            Memory.readUtf8String(args[0]);
        },
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
});
'''

        errors = self.validator._validate_frida_script(valid_frida)
        assert len(errors) == 0

        # Invalid Frida script - missing required elements
        invalid_frida_1 = '''
// Just a comment
var x = 1;
console.log(x);
'''

        errors = self.validator._validate_frida_script(invalid_frida_1)
        assert len(errors) > 0
        assert any("Missing required Frida element" in error for error in errors)

        # Invalid Frida script - no hooks
        invalid_frida_2 = '''
Java.perform(function() {
    console.log("No hooks here");
    var Module = Java.use("some.Module");
});
'''

        errors = self.validator._validate_frida_script(invalid_frida_2)
        assert len(errors) > 0
        assert any("No Interceptor hooks found" in error for error in errors)

    def test_ghidra_script_validation(self):
        """Test Ghidra-specific script validation."""
        # Valid Ghidra script
        valid_ghidra = '''
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address

class LicenseBypassScript(GhidraScript):
    def run(self):
        program = getCurrentProgram()
        memory = program.getMemory()

        # Find license functions
        function_manager = program.getFunctionManager()
        functions = function_manager.getFunctions(True)

        for function in functions:
            if "license" in function.getName().lower():
                print(f"Found license function: {function.getName()}")

        return True
'''

        errors = self.validator._validate_ghidra_script(valid_ghidra)
        assert len(errors) == 0

        # Invalid Ghidra script - missing imports
        invalid_ghidra_1 = '''
def some_function():
    print("This is not a proper Ghidra script")
    return True
'''

        errors = self.validator._validate_ghidra_script(invalid_ghidra_1)
        assert len(errors) > 0
        assert any("Missing required Ghidra element" in error for error in errors)

        # Invalid Ghidra script - no run method
        invalid_ghidra_2 = '''
from ghidra.app.script import GhidraScript

class BadScript(GhidraScript):
    def initialize(self):
        pass  # Missing run method
'''

        errors = self.validator._validate_ghidra_script(invalid_ghidra_2)
        assert len(errors) > 0
        assert any("No valid Ghidra script class or run method found" in error for error in errors)

    def test_syntax_validation_javascript(self):
        """Test JavaScript syntax validation."""
        # Valid JavaScript
        valid_js = '''
function test() {
    var x = {a: 1, b: 2};
    if (x.a === 1) {
        console.log("Valid syntax");
    }
    return true;
}
'''

        errors = self.validator._validate_syntax(valid_js, "javascript")
        assert len(errors) == 0

        # Invalid JavaScript - unmatched braces
        invalid_js_1 = '''
function test() {
    if (true) {
        console.log("Missing closing brace");
    // Missing closing brace
}
'''

        errors = self.validator._validate_syntax(invalid_js_1, "javascript")
        assert len(errors) > 0
        assert any("curly braces" in error for error in errors)

        # Invalid JavaScript - unmatched parentheses
        invalid_js_2 = '''
function test() {
    console.log("test";
    return true;
}
'''

        errors = self.validator._validate_syntax(invalid_js_2, "javascript")
        assert len(errors) > 0
        assert any("parentheses" in error for error in errors)

    def test_syntax_validation_python(self):
        """Test Python syntax validation."""
        # Valid Python
        valid_python = '''
def test_function():
    x = [1, 2, 3]
    for item in x:
        print(f"Item: {item}")
    return True
'''

        errors = self.validator._validate_syntax(valid_python, "python")
        assert len(errors) == 0

        # Invalid Python - syntax error
        invalid_python = '''
def test_function():
    x = [1, 2, 3
    for item in x:
        print(f"Item: {item}")
    return True
'''

        errors = self.validator._validate_syntax(invalid_python, "python")
        assert len(errors) > 0
        assert any("Python syntax error" in error for error in errors)

    def test_complete_script_validation(self):
        """Test complete script validation workflow."""
        # Create a valid script
        valid_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="test_valid",
                script_type=ScriptType.FRIDA,
                target_binary="test_app.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content='''
Java.perform(function() {
    console.log("[+] License bypass loaded");

    var LicenseValidator = Java.use("com.example.LicenseValidator");
    LicenseValidator.checkLicense.implementation = function(key) {
        console.log("[+] License check bypassed");
        return true;
    };

    Interceptor.attach(Module.findExportByName(null, "strcmp"), {
        onEnter: function(args) {
            Memory.readUtf8String(args[0]);
        },
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
});
''',
            language="javascript",
            entry_point="main"
        )

        is_valid, errors = self.validator.validate_script(valid_script)
        assert is_valid is True
        assert len(errors) == 0
        assert valid_script.validation_passed is True

        # Create an invalid script
        invalid_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="test_invalid",
                script_type=ScriptType.FRIDA,
                target_binary="test_app.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content='''
// TODO: Implement license bypass
function placeholder() {
    // FIXME: This is broken
    return null;
}
''',
            language="javascript",
            entry_point="main"
        )

        is_valid, errors = self.validator.validate_script(invalid_script)
        assert is_valid is False
        assert len(errors) > 0
        assert invalid_script.validation_passed is False

        # Should detect multiple issues
        error_text = " ".join(errors)
        assert "TODO" in error_text
        assert "placeholder" in error_text or "FIXME" in error_text

    def test_validation_edge_cases(self):
        """Test validation edge cases and error conditions."""
        # Empty script
        empty_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="test_empty",
                script_type=ScriptType.FRIDA,
                target_binary="test_app.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content="",
            language="javascript",
            entry_point="main"
        )

        is_valid, errors = self.validator.validate_script(empty_script)
        assert is_valid is False
        assert len(errors) > 0

        # Script with only comments
        comment_only_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="test_comments",
                script_type=ScriptType.FRIDA,
                target_binary="test_app.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content="// This is just a comment\n/* Another comment */",
            language="javascript",
            entry_point="main"
        )

        is_valid, errors = self.validator.validate_script(comment_only_script)
        assert is_valid is False
        assert any("Missing required" in error for error in errors)

        # Very long script (should still validate)
        long_content = "console.log('test');\n" * 1000  # 1000 lines
        long_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="test_long",
                script_type=ScriptType.FRIDA,
                target_binary="test_app.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content=f'''
Java.perform(function() {{
    Interceptor.attach(ptr("0x12345"), {{
        onEnter: function(args) {{
            {long_content}
            Memory.readUtf8String(args[0]);
        }}
    }});
    Module.findExportByName(null, "test");
}});
''',
            language="javascript",
            entry_point="main"
        )

        # Should still validate successfully despite length
        is_valid, errors = self.validator.validate_script(long_script)
        assert is_valid is True  # Content is valid, just long

    def test_validation_with_specific_errors(self):
        """Test validation with specific types of common errors."""
        test_cases = [
            {
                "name": "Missing Java.perform wrapper",
                "content": '''
var LicenseValidator = Java.use("com.example.LicenseValidator");
LicenseValidator.checkLicense.implementation = function(key) {
    return true;
};
''',
                "expected_error": "Missing required Frida element"
            },
            {
                "name": "No actual hooks",
                "content": '''
Java.perform(function() {
    console.log("No hooks here");
    var Module = Java.use("some.Module");
    Memory.alloc(1024);
});
''',
                "expected_error": "No Interceptor hooks found"
            },
            {
                "name": "Forbidden patterns",
                "content": '''
Java.perform(function() {
    // TODO: Add hooks here
    var stub = function() { return null; };
    Interceptor.attach(ptr("0x12345"), {
        onEnter: stub  // PLACEHOLDER
    });
});
''',
                "expected_error": "Contains forbidden pattern"
            }
        ]

        for case in test_cases:
            script = GeneratedScript(
                metadata=ScriptMetadata(
                    script_id=f"test_{case['name'].replace(' ', '_')}",
                    script_type=ScriptType.FRIDA,
                    target_binary="test_app.exe",
                    protection_types=[ProtectionType.LICENSE_CHECK]
                ),
                content=case["content"],
                language="javascript",
                entry_point="main"
            )

            is_valid, errors = self.validator.validate_script(script)
            assert is_valid is False

            error_text = " ".join(errors)
            assert case["expected_error"] in error_text

    def test_validation_performance(self):
        """Test validation performance with various script sizes."""
        import time

        # Small script
        small_content = '''
Java.perform(function() {
    console.log("Small script");
    Interceptor.attach(ptr("0x12345"), {
        onEnter: function(args) {
            Memory.readUtf8String(args[0]);
        }
    });
    Module.findExportByName(null, "test");
});
'''

        # Medium script
        medium_content = small_content + "\n// Additional code\n" * 100

        # Large script
        large_content = small_content + "\n// Additional code\n" * 1000

        for size, content in [("small", small_content), ("medium", medium_content), ("large", large_content)]:
            script = GeneratedScript(
                metadata=ScriptMetadata(
                    script_id=f"perf_test_{size}",
                    script_type=ScriptType.FRIDA,
                    target_binary="test_app.exe",
                    protection_types=[ProtectionType.LICENSE_CHECK]
                ),
                content=content,
                language="javascript",
                entry_point="main"
            )

            start_time = time.time()
            is_valid, errors = self.validator.validate_script(script)
            validation_time = time.time() - start_time

            # All should validate successfully
            assert is_valid is True

            # Validation should complete quickly (under 1 second even for large scripts)
            assert validation_time < 1.0

    def test_validation_consistency(self):
        """Test that validation results are consistent across multiple runs."""
        script_content = '''
Java.perform(function() {
    console.log("[+] Consistency test script");

    var LicenseValidator = Java.use("com.example.LicenseValidator");
    LicenseValidator.checkLicense.implementation = function(key) {
        console.log("[+] License validation bypassed");
        return true;
    };

    Interceptor.attach(Module.findExportByName(null, "strcmp"), {
        onEnter: function(args) {
            Memory.readUtf8String(args[0]);
        },
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
});
'''

        script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="consistency_test",
                script_type=ScriptType.FRIDA,
                target_binary="test_app.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content=script_content,
            language="javascript",
            entry_point="main"
        )

        # Run validation multiple times
        results = []
        for i in range(5):
            is_valid, errors = self.validator.validate_script(script)
            results.append((is_valid, len(errors)))

        # All results should be identical
        first_result = results[0]
        for result in results[1:]:
            assert result == first_result

        # Should be valid
        assert first_result[0] is True
        assert first_result[1] == 0


class TestAdvancedValidationFeatures:
    """Test advanced validation features and integration."""

    def setup_method(self):
        """Set up test fixtures."""
        self.validator = ScriptValidator()

    def test_context_aware_validation(self):
        """Test validation that considers script context and metadata."""
        # Script that's appropriate for license protection
        license_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="license_test",
                script_type=ScriptType.FRIDA,
                target_binary="license_app.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content='''
Java.perform(function() {
    console.log("[+] License bypass script");

    var LicenseChecker = Java.use("com.license.Checker");
    LicenseChecker.validate.implementation = function() {
        console.log("[+] License validation bypassed");
        return true;
    };

    Interceptor.attach(Module.findExportByName(null, "license_check"), {
        onEnter: function(args) {
            Memory.readUtf8String(args[0]);
        },
        onLeave: function(retval) {
            retval.replace(1);  // Force success
        }
    });
});
''',
            language="javascript",
            entry_point="main"
        )

        is_valid, errors = self.validator.validate_script(license_script)
        assert is_valid is True

        # Script for wrong protection type (time bomb script for license protection)
        mismatched_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="mismatch_test",
                script_type=ScriptType.FRIDA,
                target_binary="license_app.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]  # Claims to be license
            ),
            content='''
Java.perform(function() {
    console.log("[+] Time manipulation script");

    // This is clearly a time-related script, not license
    Interceptor.attach(Module.findExportByName("kernel32.dll", "GetSystemTime"), {
        onEnter: function(args) {
            console.log("[+] Time function hooked");
        }
    });

    Memory.alloc(1024);  // Required for syntax
});
''',
            language="javascript",
            entry_point="main"
        )

        # Should still be valid (content is technically correct)
        # But could flag as potential mismatch in advanced implementations
        is_valid, errors = self.validator.validate_script(mismatched_script)
        assert is_valid is True  # Basic validation passes

    def test_validation_with_dependencies(self):
        """Test validation considering script dependencies."""
        script_with_deps = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="deps_test",
                script_type=ScriptType.FRIDA,
                target_binary="app.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content='''
Java.perform(function() {
    console.log("[+] Script with dependencies");

    // Uses Frida APIs
    var Process = Java.use("java.lang.Process");
    Interceptor.attach(Module.findExportByName(null, "system"), {
        onEnter: function(args) {
            Memory.readUtf8String(args[0]);
        }
    });
});
''',
            language="javascript",
            entry_point="main",
            dependencies=["frida-java-bridge", "frida-gum"]
        )

        is_valid, errors = self.validator.validate_script(script_with_deps)
        assert is_valid is True

    def test_validation_security_checks(self):
        """Test validation includes security checks."""
        # Script with potentially dangerous operations
        dangerous_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="security_test",
                script_type=ScriptType.FRIDA,
                target_binary="app.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content='''
Java.perform(function() {
    console.log("[+] Script with file operations");

    // File system operations - potentially risky but valid for legitimate use
    var File = Java.use("java.io.File");
    Interceptor.attach(Module.findExportByName(null, "fopen"), {
        onEnter: function(args) {
            var filename = Memory.readUtf8String(args[0]);
            console.log("[+] File access: " + filename);
        }
    });

    Memory.alloc(1024);
});
''',
            language="javascript",
            entry_point="main"
        )

        # Should validate (legitimate file monitoring)
        is_valid, errors = self.validator.validate_script(dangerous_script)
        assert is_valid is True

    def test_validation_platform_specific(self):
        """Test validation considers platform-specific requirements."""
        # Android-specific script
        android_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="android_test",
                script_type=ScriptType.FRIDA,
                target_binary="app.apk",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content='''
Java.perform(function() {
    console.log("[+] Android license bypass");

    var ActivityThread = Java.use("android.app.ActivityThread");
    var Application = ActivityThread.currentApplication();
    var Context = Application.getApplicationContext();

    var LicenseValidator = Java.use("com.android.LicenseValidator");
    LicenseValidator.checkLicense.implementation = function() {
        console.log("[+] Android license check bypassed");
        return true;
    };

    Interceptor.attach(Module.findExportByName("libc.so", "strcmp"), {
        onEnter: function(args) {
            Memory.readUtf8String(args[0]);
        }
    });
});
''',
            language="javascript",
            entry_point="main"
        )

        is_valid, errors = self.validator.validate_script(android_script)
        assert is_valid is True

        # Windows-specific script  
        windows_script = GeneratedScript(
            metadata=ScriptMetadata(
                script_id="windows_test",
                script_type=ScriptType.FRIDA,
                target_binary="app.exe",
                protection_types=[ProtectionType.LICENSE_CHECK]
            ),
            content='''
Java.perform(function() {
    console.log("[+] Windows license bypass");

    // Windows-specific API hooks
    Interceptor.attach(Module.findExportByName("kernel32.dll", "CreateFileW"), {
        onEnter: function(args) {
            var filename = Memory.readUtf16String(args[0]);
            console.log("[+] File access: " + filename);
        }
    });

    Interceptor.attach(Module.findExportByName("advapi32.dll", "RegOpenKeyExW"), {
        onEnter: function(args) {
            console.log("[+] Registry access intercepted");
        },
        onLeave: function(retval) {
            Memory.readUtf8String(ptr(1));
        }
    });
});
''',
            language="javascript",
            entry_point="main"
        )

        is_valid, errors = self.validator.validate_script(windows_script)
        assert is_valid is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])