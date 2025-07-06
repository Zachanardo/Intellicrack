"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Example test module for Intellicrack.

This module provides example test cases demonstrating how to write tests
for the Intellicrack framework. It includes basic functionality tests and
serves as a template for other test modules.
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Add project root to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from intellicrack import CONFIG, IntellicrackApp
    from intellicrack.core.analysis import VulnerabilityEngine
    from intellicrack.utils import analyze_binary
except ImportError:
    IntellicrackApp = None
    CONFIG = None
    analyze_binary = None
    VulnerabilityEngine = None


class TestIntellicrackBasics(unittest.TestCase):
    """Basic tests for Intellicrack functionality."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.test_dir, "test.exe")

        # Create a dummy binary for testing
        with open(self.test_binary, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)  # Minimal PE header

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.test_dir)

    @unittest.skipIf(CONFIG is None, "Intellicrack module not available")
    def test_config_loading(self):
        """Test configuration loading."""
        self.assertIsInstance(CONFIG, dict)
        self.assertIn('analysis', CONFIG)
        self.assertIn('patching', CONFIG)

    @unittest.skipIf(analyze_binary is None, "analyze_binary function not available")
    def test_basic_analysis(self):
        """Test basic binary analysis."""
        result = analyze_binary(self.test_binary)
        self.assertIsInstance(result, dict)
        self.assertIn('file_type', result)
        self.assertIn('size', result)

    @unittest.skipIf(VulnerabilityEngine is None, "VulnerabilityEngine not available")
    @patch('intellicrack.core.analysis.vulnerability_engine.radare2')
    def test_vulnerability_detection(self, mock_r2):
        """Test vulnerability detection engine."""
        # Mock radare2 responses
        mock_r2_instance = MagicMock()
        mock_r2.return_value = mock_r2_instance

        engine = VulnerabilityEngine()
        result = engine.analyze(self.test_binary)

        self.assertIsInstance(result, dict)
        self.assertIn('vulnerabilities', result)


class TestIntellicrackIntegration(unittest.TestCase):
    """Integration tests for Intellicrack components."""

    @unittest.skipIf(IntellicrackApp is None, "IntellicrackApp not available")
    @patch('PyQt5.QtWidgets.QApplication')
    def test_app_initialization(self, mock_qapp):
        """Test application initialization."""
        # Mock Qt application
        mock_qapp.return_value = MagicMock()

        # This would normally create the GUI, but we're testing initialization
        app = IntellicrackApp()
        self.assertIsNotNone(app)

    def test_imports(self):
        """Test that all major modules can be imported."""
        modules_to_test = [
            'intellicrack',
            'intellicrack.core',
            'intellicrack.utils',
            'intellicrack.ai',
            'intellicrack.plugins'
        ]

        for module in modules_to_test:
            try:
                __import__(module)
            except ImportError as e:
                self.fail(f"Failed to import {module}: {e}")


class TestExampleWorkflows(unittest.TestCase):
    """Example workflow tests demonstrating common use cases."""

    def test_analysis_workflow(self):
        """Test a complete analysis workflow."""
        # This test demonstrates how a full analysis workflow would work
        # In a real test, this would use actual components

        workflow_steps = [
            "Load binary",
            "Detect file format",
            "Extract metadata",
            "Perform static analysis",
            "Identify protection mechanisms",
            "Generate report"
        ]

        for step in workflow_steps:
            # In a real test, each step would call actual functions
            self.assertIsInstance(step, str)  # Placeholder assertion

    def test_patching_workflow(self):
        """Test a complete patching workflow."""
        # This test demonstrates how a patching workflow would work

        patching_steps = [
            "Analyze target binary",
            "Identify patch points",
            "Generate patch candidates",
            "Validate patches",
            "Apply selected patches",
            "Verify patched binary"
        ]

        for step in patching_steps:
            # In a real test, each step would call actual functions
            self.assertIsInstance(step, str)  # Placeholder assertion


def run_example_tests():
    """Run all example tests and return results."""
    # Create test suite
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestIntellicrackBasics))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestIntellicrackIntegration))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestExampleWorkflows))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


if __name__ == '__main__':
    # Run tests when module is executed directly
    result = run_example_tests()

    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
