#!/usr/bin/env python3
"""Quick configuration validation test"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

def test_imports():
    """Test that all new configuration modules can be imported"""
    try:
        from intellicrack.core.config_models import IntellicrackSettings
        print("✓ config_models imported successfully")
        
        from intellicrack.core.config_env import EnvironmentConfigLoader
        print("✓ config_env imported successfully")
        
        from intellicrack.core.config_validators import ConfigurationValidator
        print("✓ config_validators imported successfully")
        
        # Test basic Pydantic model creation
        settings = IntellicrackSettings()
        print("✓ IntellicrackSettings created successfully")
        
        return True
        
    except Exception as e:
        print(f"✗ Import error: {e}")
        return False

if __name__ == "__main__":
    success = test_imports()
    print("\n" + ("SUCCESS" if success else "FAILED"))