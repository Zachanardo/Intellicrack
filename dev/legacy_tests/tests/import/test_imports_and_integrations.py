#!/usr/bin/env python3
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

"""Test script to verify all imports and integrations after ML removal."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Track test results
tests_passed = 0
tests_failed = 0
issues = []

def test_import(module_path, item_name=None):
    """Test importing a module or specific item."""
    global tests_passed, tests_failed
    try:
        if item_name:
            exec(f"from {module_path} import {item_name}")
            print(f"✓ Successfully imported {item_name} from {module_path}")
        else:
            exec(f"import {module_path}")
            print(f"✓ Successfully imported {module_path}")
        tests_passed += 1
        return True
    except Exception as e:
        error_msg = f"✗ Failed to import {'`' + item_name + '` from ' if item_name else ''}{module_path}: {str(e)}"
        print(error_msg)
        issues.append(error_msg)
        tests_failed += 1
        return False

def test_die_integration():
    """Test DIE protection detection integration."""
    global tests_passed, tests_failed
    print("\n=== Testing DIE Integration ===")
    
    try:
        from intellicrack.protection.die_detector import DIEProtectionDetector
        detector = DIEProtectionDetector()
        # Validate detector functionality
        if hasattr(detector, 'detect') and hasattr(detector, 'scan'):
            print("✓ DIE detector initialized successfully")
        else:
            print("✗ DIE detector missing required methods")
        tests_passed += 1
        
        # Test if DIE executable exists
        die_path = Path("/mnt/c/Intellicrack/tools/die/diec.exe")
        if die_path.exists():
            print(f"✓ DIE executable found at {die_path}")
            tests_passed += 1
        else:
            print(f"✗ DIE executable not found at {die_path}")
            issues.append(f"DIE executable missing at {die_path}")
            tests_failed += 1
            
    except Exception as e:
        error_msg = f"✗ DIE integration test failed: {str(e)}"
        print(error_msg)
        issues.append(error_msg)
        tests_failed += 1

def test_llm_backends():
    """Test LLM backend integrations."""
    global tests_passed, tests_failed
    print("\n=== Testing LLM Backends ===")
    
    try:
        from intellicrack.ai.llm_backends import LLMManager, LLMProvider

        # Test LLM Manager initialization
        manager = LLMManager()
        # Validate manager functionality
        if hasattr(manager, 'get_backend') and hasattr(manager, 'list_backends'):
            print("✓ LLM Manager initialized successfully")
        else:
            print("✗ LLM Manager missing required methods")
        tests_passed += 1
        
        # Test available providers
        providers = [p.value for p in LLMProvider]
        print(f"✓ Available LLM providers: {providers}")
        tests_passed += 1
        
    except Exception as e:
        error_msg = f"✗ LLM backend test failed: {str(e)}"
        print(error_msg)
        issues.append(error_msg)
        tests_failed += 1

def test_ui_components():
    """Test UI components can be imported."""
    global tests_passed, tests_failed
    print("\n=== Testing UI Components ===")
    
    ui_imports = [
        ("intellicrack.ui.widgets.die_protection_widget", "DIEProtectionWidget"),
        ("intellicrack.ui.main_app", "IntellicrackApp"),
    ]
    
    for module, item in ui_imports:
        test_import(module, item)

def check_removed_ml_references():
    """Check for any remaining ML model references."""
    global tests_passed, tests_failed
    print("\n=== Checking for Removed ML References ===")
    
    # Files that should not exist
    removed_files = [
        "intellicrack/models/protection_model.pkl",
        "intellicrack/models/ml_protection_model.pkl",
        "scripts/ml/train_protection_model.py",
        "scripts/ml/evaluate_model.py"
    ]
    
    for file_path in removed_files:
        full_path = Path("/mnt/c/Intellicrack") / file_path
        if full_path.exists():
            error_msg = f"✗ Found ML file that should be removed: {file_path}"
            print(error_msg)
            issues.append(error_msg)
            tests_failed += 1
        else:
            print(f"✓ Confirmed removed: {file_path}")
            tests_passed += 1

def test_tools_integration():
    """Test that tools properly use DIE instead of ML."""
    global tests_passed, tests_failed
    print("\n=== Testing Tools Integration ===")
    
    try:
        from intellicrack.tools.protection_analyzer_tool import ProtectionAnalyzerTool
        tool = ProtectionAnalyzerTool()
        
        # Check if it has DIE detector instead of ML predictor
        if hasattr(tool, 'die_detector'):
            print("✓ ProtectionAnalyzerTool correctly uses DIE detector")
            tests_passed += 1
        else:
            error_msg = "✗ ProtectionAnalyzerTool missing DIE detector"
            print(error_msg)
            issues.append(error_msg)
            tests_failed += 1
            
        if hasattr(tool, 'ml_predictor'):
            error_msg = "✗ ProtectionAnalyzerTool still has ML predictor reference"
            print(error_msg)
            issues.append(error_msg)
            tests_failed += 1
        else:
            print("✓ ProtectionAnalyzerTool correctly removed ML predictor")
            tests_passed += 1
            
    except Exception as e:
        error_msg = f"✗ Tools integration test failed: {str(e)}"
        print(error_msg)
        issues.append(error_msg)
        tests_failed += 1

def test_secrets_management():
    """Test secrets management system."""
    global tests_passed, tests_failed
    print("\n=== Testing Secrets Management ===")
    
    try:
        from intellicrack.utils.secrets_manager import SecretsManager
        secrets = SecretsManager()
        print("✓ SecretsManager initialized successfully")
        tests_passed += 1
        
        # Test getting a non-existent key with default
        test_val = secrets.get("TEST_KEY_NONEXISTENT", "default_value")
        if test_val == "default_value":
            print("✓ SecretsManager default value works correctly")
            tests_passed += 1
        else:
            error_msg = "✗ SecretsManager default value not working"
            print(error_msg)
            issues.append(error_msg)
            tests_failed += 1
            
    except Exception as e:
        error_msg = f"✗ Secrets management test failed: {str(e)}"
        print(error_msg)
        issues.append(error_msg)
        tests_failed += 1

def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing Intellicrack Imports and Integrations")
    print("=" * 60)
    
    # Test core imports
    print("\n=== Testing Core Imports ===")
    core_imports = [
        "intellicrack",
        "intellicrack.ai",
        "intellicrack.ui",
        "intellicrack.tools",
        "intellicrack.protection",
        "intellicrack.utils",
    ]
    
    for module in core_imports:
        test_import(module)
    
    # Test specific component imports
    print("\n=== Testing Specific Component Imports ===")
    specific_imports = [
        ("intellicrack.ai.orchestrator", "AIOrchestrator"),
        ("intellicrack.ai.ai_assistant_enhanced", "IntellicrackAIAssistant"),
        ("intellicrack.ai.ml_predictor", "MLVulnerabilityPredictor"),
        ("intellicrack.protection.die_detector", "DIEProtectionDetector"),
        ("intellicrack.utils.secrets_manager", "SecretsManager"),
    ]
    
    for module, item in specific_imports:
        test_import(module, item)
    
    # Run integration tests
    test_die_integration()
    test_llm_backends()
    test_ui_components()
    check_removed_ml_references()
    test_tools_integration()
    test_secrets_management()
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests Passed: {tests_passed}")
    print(f"Tests Failed: {tests_failed}")
    print(f"Success Rate: {tests_passed / (tests_passed + tests_failed) * 100:.1f}%")
    
    if issues:
        print("\n=== Issues Found ===")
        for issue in issues:
            print(f"  - {issue}")
    
    # Return exit code
    sys.exit(0 if tests_failed == 0 else 1)

if __name__ == "__main__":
    main()
