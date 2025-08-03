#!/usr/bin/env python3
"""Simple test for configuration validation system."""

import os
import sys
from pathlib import Path

# Add intellicrack to path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all new modules can be imported."""
    try:
        from intellicrack.core.config_models import IntellicrackSettings, create_default_directories_config
        from intellicrack.core.config_env import EnvironmentConfigLoader
        from intellicrack.core.config_validators import ConfigurationValidator
        print("✓ All new modules imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality."""
    try:
        from intellicrack.core.config_models import create_default_directories_config
        from intellicrack.core.config_env import EnvironmentConfigLoader
        
        # Test directory config creation
        dirs = create_default_directories_config()
        print(f"✓ Created directories config: {dirs.config}")
        
        # Test environment loader
        env_loader = EnvironmentConfigLoader()
        profile = env_loader.get_environment_profile()
        print(f"✓ Environment profile: {profile}")
        
        return True
    except Exception as e:
        print(f"✗ Basic functionality test failed: {e}")
        return False

def main():
    print("Simple Configuration Validation Test")
    print("=" * 40)
    
    success = True
    success &= test_imports()
    success &= test_basic_functionality()
    
    print("=" * 40)
    if success:
        print("✓ Basic tests passed!")
    else:
        print("✗ Some tests failed")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)