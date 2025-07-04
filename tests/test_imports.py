#!/usr/bin/env python3
"""
Test script to verify all imports work after ML module removal
"""

import sys
import traceback
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_import(module_path, description=""):
    """Test importing a module and report results"""
    try:
        __import__(module_path)
        print(f"✅ {module_path} - {description}")
        return True
    except Exception as e:
        print(f"❌ {module_path} - {description}")
        print(f"   Error: {e}")
        return False

def main():
    """Run comprehensive import tests"""
    print("Testing imports after ML module removal...")
    print("=" * 60)
    
    failed_imports = []
    
    # Core modules
    modules_to_test = [
        ("intellicrack.ai.ml_predictor", "ML Predictor (new stub)"),
        ("intellicrack.ai.coordination_layer", "AI Coordination Layer"),
        ("intellicrack.ai.vulnerability_research_integration", "Vulnerability Research Integration"),
        ("intellicrack.ai.orchestrator", "AI Orchestrator"),
        ("intellicrack.ai.llm_backends", "LLM Backends"),
        ("intellicrack.ai.protection_aware_script_gen", "Protection-Aware Script Generator"),
        ("intellicrack.utils.secrets_manager", "Secrets Manager"),
        ("intellicrack.protection.die_detector", "DIE Protection Detector"),
        ("intellicrack.ui.widgets.die_protection_widget", "DIE Protection Widget"),
        ("intellicrack.tools.protection_analyzer_tool", "Protection Analyzer Tool"),
        ("intellicrack.models", "Models Package"),
        ("intellicrack.core.config_manager", "Config Manager"),
        ("intellicrack.utils.api_client", "API Client"),
        ("intellicrack.plugins.remote_executor", "Remote Executor"),
    ]
    
    # Test each module
    for module_path, description in modules_to_test:
        if not test_import(module_path, description):
            failed_imports.append(module_path)
    
    print("\n" + "=" * 60)
    
    # Test main app import (most complex)
    print("\nTesting main application imports...")
    try:
        # Test key parts of main app
        from intellicrack.ui import main_app
        print("✅ Main app imported successfully")
        
        # Test if MLVulnerabilityPredictor is accessible
        if hasattr(main_app, 'MLVulnerabilityPredictor'):
            predictor = main_app.MLVulnerabilityPredictor()
            print("✅ MLVulnerabilityPredictor can be instantiated")
            print(f"   Predictor type: {type(predictor).__name__}")
        else:
            print("⚠️  MLVulnerabilityPredictor not found in main_app")
            
    except Exception as e:
        print(f"❌ Main app import failed: {e}")
        print("Traceback:")
        traceback.print_exc()
        failed_imports.append("intellicrack.ui.main_app")
    
    # Test secrets manager functionality
    print("\nTesting secrets manager functionality...")
    try:
        from intellicrack.utils.secrets_manager import get_secret, set_secret

        # Test setting and getting a secret
        set_secret("TEST_SECRET", "test_value")
        value = get_secret("TEST_SECRET")
        if value == "test_value":
            print("✅ Secrets manager works correctly")
        else:
            print(f"⚠️  Secrets manager issue: expected 'test_value', got '{value}'")
            
    except Exception as e:
        print(f"❌ Secrets manager test failed: {e}")
    
    # Test DIE detector
    print("\nTesting DIE detector...")
    try:
        from intellicrack.protection.die_detector import DIEProtectionDetector
        detector = DIEProtectionDetector()
        print("✅ DIE detector instantiated successfully")
        print(f"   Detector signatures loaded: {len(detector.signatures) if hasattr(detector, 'signatures') else 'N/A'}")
        
    except Exception as e:
        print(f"❌ DIE detector test failed: {e}")
    
    # Summary
    print("\n" + "=" * 60)
    if failed_imports:
        print(f"❌ FAILED: {len(failed_imports)} modules failed to import:")
        for module in failed_imports:
            print(f"   - {module}")
        return False
    else:
        print("✅ SUCCESS: All modules imported successfully!")
        return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
