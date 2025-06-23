"""
Integration tests for Code Modification Workflow

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


from intellicrack.ai.intelligent_code_modifier import (
    IntelligentCodeModifier, CodeChange,
    ModificationType, ChangeStatus, CodeAnalyzer
)
from intellicrack.ai.llm_backends import LLMManager, LLMResponse


class TestCodeModificationWorkflow:
    """Integration tests for the complete code modification workflow."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.mock_llm_manager = Mock(spec=LLMManager)
        self.modifier = IntelligentCodeModifier(self.mock_llm_manager)

        # Create test files
        self.create_test_files()

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def create_test_files(self):
        """Create test files for modification."""
        # Python test file
        self.python_file = self.temp_dir / "test_module.py"
        self.python_file.write_text('''
import os
import sys
from typing import List, Dict

class LicenseValidator:
    """Validates software licenses."""

    def __init__(self):
        self.license_key = None
        self.is_valid = False

    def set_license_key(self, key: str) -> bool:
        """Set the license key."""
        self.license_key = key
        return self.validate_license()

    def validate_license(self) -> bool:
        """Validate the current license."""
        if not self.license_key:
            return False

        # Simple validation logic
        if len(self.license_key) < 10:
            return False

        if not self.license_key.startswith("LIC-"):
            return False

        self.is_valid = True
        return True

    def get_license_info(self) -> Dict[str, str]:
        """Get license information."""
        return {
            "key": self.license_key or "None",
            "valid": str(self.is_valid),
            "type": "Standard"
        }

def main():
    """Main function."""
    validator = LicenseValidator()
    validator.set_license_key("LIC-1234567890")
    print(validator.get_license_info())

if __name__ == "__main__":
    main()
''')

        # JavaScript test file
        self.js_file = self.temp_dir / "license_checker.js"
        self.js_file.write_text('''
const crypto = require('crypto');

class LicenseChecker {
    constructor() {
        this.licenseKey = null;
        this.isValid = false;
    }

    setLicenseKey(key) {
        this.licenseKey = key;
        return this.validateLicense();
    }

    validateLicense() {
        if (!this.licenseKey) {
            return false;
        }

        // Check license format
        if (this.licenseKey.length < 16) {
            return false;
        }

        // Check prefix
        if (!this.licenseKey.startsWith('KEY-')) {
            return false;
        }

        this.isValid = true;
        return true;
    }

    getLicenseInfo() {
        return {
            key: this.licenseKey || 'None',
            valid: this.isValid,
            type: 'Premium'
        };
    }
}

function main() {
    const checker = new LicenseChecker();
    checker.setLicenseKey('KEY-1234567890123456');
    console.log(checker.getLicenseInfo());
}

if (require.main === module) {
    main();
}

module.exports = LicenseChecker;
''')

    def test_complete_modification_workflow(self):
        """Test the complete modification workflow from request to application."""
        # Mock LLM response for Python file modification
        mock_response = LLMResponse(
            content='''```json
{
  "modifications": [
    {
      "type": "function_modification",
      "description": "Bypass license validation by always returning true",
      "start_line": 18,
      "end_line": 28,
      "original_code": "    def validate_license(self) -> bool:\\n        \\"\\"\\"Validate the current license.\\"\\"\\"\\n        if not self.license_key:\\n            return False\\n        \\n        # Simple validation logic\\n        if len(self.license_key) < 10:\\n            return False\\n        \\n        if not self.license_key.startswith(\\"LIC-\\"):\\n            return False\\n        \\n        self.is_valid = True\\n        return True",
      "modified_code": "    def validate_license(self) -> bool:\\n        \\"\\"\\"Validate the current license.\\"\\"\\"\\n        # Bypass: Always return True for any license\\n        self.is_valid = True\\n        return True",
      "reasoning": "Modified validation function to bypass license checks by always returning True, regardless of input",
      "confidence": 0.95,
      "impact": "This will bypass all license validation, allowing the software to run without a valid license"
    }
  ]
}
```''',
            model="test-model"
        )

        self.mock_llm_manager.chat.return_value = mock_response

        # Create modification request
        request = self.modifier.create_modification_request(
            description="Bypass license validation in the Python module",
            target_files=[str(self.python_file)],
            requirements=["Always return True for validation", "Maintain original function signature"],
            constraints=["Don't break existing functionality", "Keep code readable"]
        )

        # Analyze modifications
        changes = self.modifier.analyze_modification_request(request)

        # Verify changes were generated
        assert len(changes) == 1
        change = changes[0]

        assert change.modification_type == ModificationType.FUNCTION_MODIFICATION
        assert change.confidence == 0.95
        assert change.status == ChangeStatus.PENDING
        assert "bypass" in change.description.lower()

        # Preview changes
        preview = self.modifier.preview_changes([change.change_id])

        assert len(preview["changes"]) == 1
        assert len(preview["files_affected"]) == 1
        assert str(self.python_file) in preview["files_affected"]
        assert preview["total_changes"] == 1

        # Read original content
        original_content = self.python_file.read_text()

        # Apply changes
        results = self.modifier.apply_changes([change.change_id], create_backup=True)

        assert len(results["applied"]) == 1
        assert len(results["failed"]) == 0
        assert len(results["backups_created"]) == 1

        # Verify file was modified
        modified_content = self.python_file.read_text()
        assert modified_content != original_content
        assert "# Bypass: Always return True" in modified_content
        assert "if not self.license_key:" not in modified_content

        # Verify backup was created
        backup_path = Path(results["backups_created"][0])
        assert backup_path.exists()
        assert backup_path.read_text() == original_content

        # Check modification history
        history = self.modifier.get_modification_history(limit=10)
        assert len(history) == 1
        assert history[0]["status"] == "applied"
        assert history[0]["change_id"] == change.change_id

    def test_javascript_modification_workflow(self):
        """Test modification workflow for JavaScript files."""
        # Mock LLM response for JavaScript modification
        mock_response = LLMResponse(
            content='''```json
{
  "modifications": [
    {
      "type": "function_modification", 
      "description": "Modify validateLicense to always return true",
      "start_line": 12,
      "end_line": 26,
      "original_code": "    validateLicense() {\\n        if (!this.licenseKey) {\\n            return false;\\n        }\\n        \\n        // Check license format\\n        if (this.licenseKey.length < 16) {\\n            return false;\\n        }\\n        \\n        // Check prefix\\n        if (!this.licenseKey.startsWith('KEY-')) {\\n            return false;\\n        }\\n        \\n        this.isValid = true;\\n        return true;\\n    }",
      "modified_code": "    validateLicense() {\\n        // Bypass all validation checks\\n        this.isValid = true;\\n        return true;\\n    }",
      "reasoning": "Simplified validation to always return true, bypassing all checks",
      "confidence": 0.9,
      "impact": "License validation will always pass"
    }
  ]
}
```''',
            model="test-model"
        )

        self.mock_llm_manager.chat.return_value = mock_response

        # Create request for JavaScript file
        request = self.modifier.create_modification_request(
            description="Bypass license validation in JavaScript",
            target_files=[str(self.js_file)],
            requirements=["Always return true", "Remove validation logic"],
            constraints=["Keep existing interface"]
        )

        # Analyze and apply
        changes = self.modifier.analyze_modification_request(request)
        assert len(changes) == 1

        change = changes[0]
        results = self.modifier.apply_changes([change.change_id])

        assert len(results["applied"]) == 1

        # Verify modification
        modified_content = self.js_file.read_text()
        assert "// Bypass all validation checks" in modified_content
        assert "this.licenseKey.length < 16" not in modified_content

    def test_multiple_file_modification(self):
        """Test modification of multiple files in one request."""
        # Mock LLM to return different responses for each call
        responses = [
            LLMResponse(
                content='''```json
{
  "modifications": [
    {
      "type": "function_modification",
      "description": "Bypass Python license validation",
      "start_line": 18,
      "end_line": 28,
      "original_code": "    def validate_license(self) -> bool:\\n        \\"\\"\\"Validate the current license.\\"\\"\\"\\n        if not self.license_key:\\n            return False\\n        \\n        # Simple validation logic\\n        if len(self.license_key) < 10:\\n            return False\\n        \\n        if not self.license_key.startswith(\\"LIC-\\"):\\n            return False\\n        \\n        self.is_valid = True\\n        return True",
      "modified_code": "    def validate_license(self) -> bool:\\n        \\"\\"\\"Validate the current license.\\"\\"\\"\\n        self.is_valid = True\\n        return True",
      "reasoning": "Bypass license validation",
      "confidence": 0.9,
      "impact": "License always valid"
    }
  ]
}
```''',
                model="test-model"
            ),
            LLMResponse(
                content='''```json
{
  "modifications": [
    {
      "type": "function_modification",
      "description": "Bypass JavaScript license validation",
      "start_line": 12,
      "end_line": 26,
      "original_code": "    validateLicense() {\\n        if (!this.licenseKey) {\\n            return false;\\n        }\\n        \\n        // Check license format\\n        if (this.licenseKey.length < 16) {\\n            return false;\\n        }\\n        \\n        // Check prefix\\n        if (!this.licenseKey.startsWith('KEY-')) {\\n            return false;\\n        }\\n        \\n        this.isValid = true;\\n        return true;\\n    }",
      "modified_code": "    validateLicense() {\\n        this.isValid = true;\\n        return true;\\n    }",
      "reasoning": "Bypass JavaScript validation",
      "confidence": 0.85,
      "impact": "JavaScript license always valid"
    }
  ]
}
```''',
                model="test-model"
            )
        ]

        self.mock_llm_manager.chat.side_effect = responses

        # Create request for both files
        request = self.modifier.create_modification_request(
            description="Bypass license validation in both Python and JavaScript files",
            target_files=[str(self.python_file), str(self.js_file)],
            requirements=["Bypass all license checks"],
            constraints=["Maintain function signatures"]
        )

        # Analyze modifications
        changes = self.modifier.analyze_modification_request(request)

        # Should have changes for both files
        assert len(changes) == 2

        # Group changes by file
        changes_by_file = {}
        for change in changes:
            file_path = change.file_path
            if file_path not in changes_by_file:
                changes_by_file[file_path] = []
            changes_by_file[file_path].append(change)

        assert len(changes_by_file) == 2
        assert str(self.python_file) in changes_by_file
        assert str(self.js_file) in changes_by_file

        # Apply all changes
        change_ids = [change.change_id for change in changes]
        results = self.modifier.apply_changes(change_ids)

        assert len(results["applied"]) == 2
        assert len(results["failed"]) == 0

        # Verify both files were modified
        py_content = self.python_file.read_text()
        js_content = self.js_file.read_text()

        assert "self.is_valid = True" in py_content
        assert "this.isValid = true;" in js_content

    def test_change_rejection_workflow(self):
        """Test rejecting changes instead of applying them."""
        # Mock LLM response
        mock_response = LLMResponse(
            content='''```json
{
  "modifications": [
    {
      "type": "function_modification",
      "description": "Dangerous modification",
      "start_line": 18,
      "end_line": 28,
      "original_code": "original code",
      "modified_code": "modified code",
      "reasoning": "This change might break things",
      "confidence": 0.3,
      "impact": "High risk change"
    }
  ]
}
```''',
            model="test-model"
        )

        self.mock_llm_manager.chat.return_value = mock_response

        request = self.modifier.create_modification_request(
            description="Test modification",
            target_files=[str(self.python_file)]
        )

        changes = self.modifier.analyze_modification_request(request)
        assert len(changes) == 1

        change = changes[0]
        assert change.confidence == 0.3  # Low confidence

        # Reject the change
        results = self.modifier.reject_changes([change.change_id])

        assert len(results["rejected"]) == 1
        assert change.change_id in results["rejected"]

        # Verify change is no longer pending
        pending = self.modifier.get_pending_changes()
        assert len(pending) == 0

        # Verify it's in history as rejected
        history = self.modifier.get_modification_history()
        assert len(history) == 1
        assert history[0]["status"] == "rejected"

    def test_error_handling_in_workflow(self):
        """Test error handling throughout the modification workflow."""
        # Test with invalid file path
        request = self.modifier.create_modification_request(
            description="Test with invalid file",
            target_files=["/nonexistent/file.py"]
        )

        # Should handle gracefully
        changes = self.modifier.analyze_modification_request(request)
        # May return empty list or handle error gracefully

        # Test with malformed LLM response
        malformed_response = LLMResponse(
            content="This is not valid JSON for modifications",
            model="test-model"
        )

        self.mock_llm_manager.chat.return_value = malformed_response

        request = self.modifier.create_modification_request(
            description="Test with malformed response",
            target_files=[str(self.python_file)]
        )

        changes = self.modifier.analyze_modification_request(request)
        # Should handle gracefully and return empty or partial results

    def test_project_context_gathering(self):
        """Test gathering project context from multiple files."""
        # Create additional test files
        utils_file = self.temp_dir / "utils.py"
        utils_file.write_text('''
def helper_function():
    """A helper function."""
    return "helper"

class UtilityClass:
    def process_data(self, data):
        return data.upper()
''')

        config_file = self.temp_dir / "config.py"
        config_file.write_text('''
import os

DEBUG = True
LICENSE_SERVER = "https://example.com/license"

def get_config():
    return {
        "debug": DEBUG,
        "license_server": LICENSE_SERVER
    }
''')

        # Gather project context
        context = self.modifier.gather_project_context(str(self.temp_dir))

        # Should have analyzed multiple files
        assert len(context) >= 3  # At least our 3 Python files

        # Check specific files are included
        file_paths = set(context.keys())
        assert "test_module.py" in file_paths
        assert "utils.py" in file_paths
        assert "config.py" in file_paths

        # Check context information is extracted
        test_module_context = context["test_module.py"]
        assert test_module_context.language == "python"
        assert "LicenseValidator" in test_module_context.classes
        assert "validate_license" in test_module_context.functions
        assert len(test_module_context.imports) > 0

    def test_diff_generation_and_preview(self):
        """Test diff generation and change preview functionality."""
        # Create a simple change manually

        change = CodeChange(
            change_id="test_change_1",
            file_path=str(self.python_file),
            modification_type=ModificationType.FUNCTION_MODIFICATION,
            description="Test change for diff generation",
            original_code="    def validate_license(self) -> bool:\n        return False",
            modified_code="    def validate_license(self) -> bool:\n        return True",
            start_line=18,
            end_line=19,
            confidence=0.8,
            reasoning="Test reasoning"
        )

        # Add to pending changes
        self.modifier.pending_changes[change.change_id] = change

        # Generate preview
        preview = self.modifier.preview_changes([change.change_id])

        assert len(preview["changes"]) == 1
        assert preview["total_changes"] == 1
        assert preview["high_risk_changes"] == 0  # Confidence is 0.8 > threshold

        change_info = preview["changes"][0]
        assert change_info["change_id"] == change.change_id
        assert change_info["confidence"] == 0.8
        assert change_info["type"] == "function_modification"

        # Check diff is generated
        assert "diff" in change_info
        diff_content = change_info["diff"]
        assert "-        return False" in diff_content
        assert "+        return True" in diff_content


class TestCodeAnalyzer:
    """Tests for the CodeAnalyzer component."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = CodeAnalyzer()
        self.temp_dir = Path(tempfile.mkdtemp())

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_python_file_analysis(self):
        """Test Python file analysis with AST parsing."""
        python_file = self.temp_dir / "analysis_test.py"
        python_file.write_text('''
import os
import sys
from typing import List
from custom_module import CustomClass

class TestClass:
    def __init__(self):
        self.value = 0

    def method_one(self, param: str) -> bool:
        if param == "test":
            return True
        else:
            return False

    def method_two(self):
        for i in range(10):
            if i % 2 == 0:
                print(i)

def standalone_function():
    variable_one = "test"
    variable_two = 42
    return variable_one, variable_two

global_var = "global"
another_global = 123
''')

        context = self.analyzer.analyze_file(str(python_file))

        # Check basic info
        assert context.file_path == str(python_file)
        assert context.language == "python"

        # Check imports
        expected_imports = {"os", "sys", "typing", "custom_module"}
        assert set(context.imports) >= expected_imports

        # Check classes
        assert "TestClass" in context.classes

        # Check functions
        expected_functions = {"__init__", "method_one", "method_two", "standalone_function"}
        assert set(context.functions) >= expected_functions

        # Check variables
        expected_variables = {"global_var", "another_global", "variable_one", "variable_two"}
        assert set(context.variables) >= expected_variables

        # Check AST info
        assert "complexity" in context.ast_info
        assert context.ast_info["complexity"] > 1  # Should have some complexity

        # Check dependencies
        assert "custom_module" in context.dependencies
        assert "os" not in context.dependencies  # Standard library should be filtered

    def test_javascript_file_analysis(self):
        """Test JavaScript file analysis with regex patterns."""
        js_file = self.temp_dir / "analysis_test.js"
        js_file.write_text('''
const fs = require('fs');
const path = require('path');
import { helper } from './helper.js';
import customModule from 'custom-module';

class TestClass {
    constructor() {
        this.value = 0;
    }

    methodOne(param) {
        if (param === 'test') {
            return true;
        }
        return false;
    }

    methodTwo() {
        for (let i = 0; i < 10; i++) {
            console.log(i);
        }
    }
}

function standaloneFunction() {
    const variableOne = 'test';
    let variableTwo = 42;
    var variableThree = 'old-style';
    return [variableOne, variableTwo, variableThree];
}

const arrowFunction = (param) => {
    return param * 2;
};

const globalVar = 'global';
let anotherGlobal = 123;
''')

        context = self.analyzer.analyze_file(str(js_file))

        # Check basic info
        assert context.file_path == str(js_file)
        assert context.language == "javascript"

        # Check imports (both require and import styles)
        expected_imports = {"fs", "path", "./helper.js", "custom-module"}
        assert set(context.imports) >= expected_imports

        # Check classes
        assert "TestClass" in context.classes

        # Check functions
        expected_functions = {"methodOne", "methodTwo", "standaloneFunction", "arrowFunction"}
        function_names = set(context.functions)
        assert function_names >= expected_functions

        # Check variables
        expected_variables = {"variableOne", "variableTwo", "variableThree", "globalVar", "anotherGlobal"}
        assert set(context.variables) >= expected_variables

        # Check dependencies
        assert "custom-module" in context.dependencies

    def test_unsupported_file_analysis(self):
        """Test analysis of unsupported file types."""
        text_file = self.temp_dir / "readme.txt"
        text_file.write_text('''
This is a plain text file.
It has no code structure.
Just some text content.
''')

        context = self.analyzer.analyze_file(str(text_file))

        assert context.file_path == str(text_file)
        assert context.language == "unknown"
        assert len(context.imports) == 0
        assert len(context.classes) == 0
        assert len(context.functions) == 0
        assert len(context.variables) == 0

    def test_malformed_python_file(self):
        """Test analysis of Python file with syntax errors."""
        bad_python_file = self.temp_dir / "bad_syntax.py"
        bad_python_file.write_text('''
import os

def broken_function(
    # Missing closing parenthesis and colon

class IncompleteClass
    # Missing colon and body

if True
    print("Missing colon")
''')

        # Should handle gracefully
        context = self.analyzer.analyze_file(str(bad_python_file))

        assert context.file_path == str(bad_python_file)
        assert context.language == "python"
        # Should still extract some information despite syntax errors
        assert "os" in context.imports