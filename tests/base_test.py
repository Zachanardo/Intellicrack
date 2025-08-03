"""
Base test class for Intellicrack tests.

CRITICAL: This base class enforces REAL data usage and provides utilities
for validating that features actually work, not just return mock data.
"""

import pytest
import hashlib
from pathlib import Path
import subprocess
import sys


class IntellicrackTestBase:
    """
    Base class for all Intellicrack tests.

    Enforces:
    - Real data usage (no mocks)
    - Actual functionality validation
    - Proper error handling for missing features
    """

    @classmethod
    def setup_class(cls):
        """Setup that runs once for the test class."""
        cls.validate_test_environment()

    @classmethod
    def validate_test_environment(cls):
        """Ensure test environment has real dependencies."""
        # Check for Intellicrack installation
        try:
            import intellicrack
        except ImportError:
            pytest.fail("Intellicrack must be properly installed for real testing")

    def assert_real_output(self, output, error_msg="Output appears to be mock/placeholder data"):
        """
        Validate that output is real, not mocked or placeholder.

        Checks for common indicators of fake data:
        - TODO/FIXME comments
        - Placeholder text
        - Hardcoded dummy values
        - Suspiciously perfect data
        """
        if output is None:
            pytest.fail(f"{error_msg}: Output is None")

        output_str = str(output).lower()

        # Check for placeholder indicators
        placeholder_indicators = [
            "todo", "fixme", "placeholder", "dummy", "mock", "fake",
            "example", "test123", "sample", "not implemented",
            "coming soon", "under construction"
        ]

        for indicator in placeholder_indicators:
            if indicator in output_str:
                pytest.fail(f"{error_msg}: Found '{indicator}' in output: {output}")

        # Check for suspiciously simple data
        if output_str in ["success", "ok", "done", "true", "false", "{}", "[]"]:
            pytest.fail(f"{error_msg}: Output is suspiciously simple: {output}")

    def assert_binary_analysis_real(self, analysis_result):
        """Validate that binary analysis produced real results."""
        assert analysis_result is not None, "Analysis returned None"

        # Should have real binary metadata
        assert "file_type" in analysis_result, "Missing file type"
        assert "architecture" in analysis_result, "Missing architecture"
        assert "entry_point" in analysis_result, "Missing entry point"

        # Entry point should be a real address, not 0 or placeholder
        entry = analysis_result["entry_point"]
        assert isinstance(entry, (int, str)), "Entry point should be numeric or hex string"
        if isinstance(entry, int):
            assert entry > 0, "Entry point cannot be 0"
        else:
            assert entry.startswith("0x"), "Entry point should be hex format"
            assert int(entry, 16) > 0, "Entry point cannot be 0"

        # Should have real sections
        if "sections" in analysis_result:
            assert len(analysis_result["sections"]) > 0, "No sections found"
            for section in analysis_result["sections"]:
                assert "name" in section, "Section missing name"
                assert "size" in section, "Section missing size"
                assert section["size"] > 0, "Section size cannot be 0"

    def assert_exploit_works(self, exploit_code):
        """Validate that generated exploit is real working code."""
        assert exploit_code is not None, "Exploit code is None"
        assert len(exploit_code) > 0, "Exploit code is empty"

        # Check it's not placeholder
        self.assert_real_output(exploit_code, "Exploit appears to be placeholder code")

        # Should contain actual shellcode or exploit primitives
        exploit_lower = exploit_code.lower()

        # Should have hex bytes or assembly
        has_shellcode = any([
            "\\x" in exploit_code,  # Hex bytes
            "0x" in exploit_code,   # Hex values
            "push" in exploit_lower,  # Assembly
            "mov" in exploit_lower,   # Assembly
            "call" in exploit_lower,  # Assembly
        ])

        assert has_shellcode, "Exploit doesn't contain real shellcode or assembly"

    def assert_ai_script_executable(self, script_code, script_type="frida"):
        """Validate that AI-generated script is real executable code."""
        assert script_code is not None, "Script code is None"
        assert len(script_code) > 50, "Script too short to be real"

        # Check it's not placeholder
        self.assert_real_output(script_code, f"{script_type} script appears to be placeholder")

        if script_type == "frida":
            # Should have Frida-specific constructs
            assert "Java.perform" in script_code or "Interceptor" in script_code, \
                "Missing Frida API calls"
            assert "function" in script_code or "=>" in script_code, \
                "Missing JavaScript functions"

        elif script_type == "ghidra":
            # Should have Ghidra-specific constructs
            assert "import ghidra" in script_code or "currentProgram" in script_code, \
                "Missing Ghidra imports or API"

    def assert_network_response_valid(self, response_data):
        """Validate that network response is real protocol data."""
        assert response_data is not None, "Response data is None"

        # Check it's not placeholder
        self.assert_real_output(response_data, "Network response appears to be fake")

        # Should have proper structure (not just success/ok)
        if isinstance(response_data, dict):
            assert len(response_data) > 1, "Response too simple to be real"
            # Should have protocol-specific fields
            assert any(key in response_data for key in [
                "license", "token", "session", "auth", "timestamp", "signature"
            ]), "Response missing protocol-specific fields"

    def run_and_capture_output(self, func, *args, **kwargs):
        """
        Run a function and capture its output, ensuring it's real.

        Returns the output and validates it's not mock data.
        """
        try:
            result = func(*args, **kwargs)
            self.assert_real_output(result)
            return result
        except NotImplementedError:
            pytest.fail(f"Function {func.__name__} is not implemented (stub detected)")
        except Exception as e:
            if "todo" in str(e).lower() or "not implemented" in str(e).lower():
                pytest.fail(f"Function {func.__name__} returned placeholder error: {e}")
            raise

    def validate_file_hash(self, file_path, expected_hash=None):
        """Validate file integrity with hash."""
        if not Path(file_path).exists():
            pytest.fail(f"File {file_path} does not exist")

        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        if expected_hash:
            assert file_hash == expected_hash, f"File hash mismatch for {file_path}"

        return file_hash

    def assert_performance_acceptable(self, func, max_time=2.0, iterations=1):
        """Ensure function performs within acceptable time limits."""
        import time

        total_time = 0
        for _ in range(iterations):
            start = time.time()
            func()
            total_time += time.time() - start

        avg_time = total_time / iterations
        assert avg_time < max_time, \
            f"Performance issue: {func.__name__} took {avg_time:.2f}s (max: {max_time}s)"


# Alias for backward compatibility
BaseIntellicrackTest = IntellicrackTestBase
