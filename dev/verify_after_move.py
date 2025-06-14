#!/usr/bin/env python3
"""
Verify and update paths after moving the project from 
C:\\Intellicrack\\Intellicrack_Project\\Intellicrack_Project to C:\\Intellicrack

Run this script after moving the project to ensure all paths are correct.
"""

import os
import sys
import json

# pylint: disable=too-complex
def verify_paths():
    """Verify that all paths are correct after the move."""
    
    print("Verifying Intellicrack paths after move...")
    print("=" * 60)
    
    # Expected new project root
    expected_root = r"C:\Intellicrack"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)  # Go up from dev/ to project root
    
    print(f"Script directory: {script_dir}")
    print(f"Project root: {project_root}")
    print(f"Expected root: {expected_root}")
    
    # Handle both Windows and WSL paths
    is_wsl = project_root.startswith('/mnt/')
    if is_wsl:
        # Convert WSL path to Windows path for comparison
        wsl_path = project_root.replace('/mnt/c/', 'C:\\').replace('/', '\\')
        print(f"WSL path converted: {wsl_path}")
        path_match = wsl_path.lower() == expected_root.lower()
    else:
        path_match = project_root.lower() == expected_root.lower()
    
    if not path_match:
        print(f"\n⚠️  WARNING: Project not in expected location!")
        print(f"   Expected: {expected_root}")
        print(f"   Actual: {project_root}")
        print("\nPlease move the project to C:\\Intellicrack before continuing.")
        return False
    
    print("\n✅ Project is in the correct location!")
    
    # Check config file
    print("\nChecking configuration file...")
    config_path = os.path.join(project_root, "intellicrack_config.json")
    
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Verify paths in config
        ml_model_path = config.get('ml_model_path', '')
        if 'Intellicrack_Project' in ml_model_path:
            print(f"❌ Config still has old path: {ml_model_path}")
            print("   This has been updated in the code but may need manual update if config was customized.")
        else:
            print(f"✅ ML model path is correct: {ml_model_path}")
        
        # Check other paths
        log_dir = config.get('log_dir', '')
        output_dir = config.get('output_dir', '')
        
        print(f"\nOther paths in config:")
        print(f"  Log directory: {log_dir}")
        print(f"  Output directory: {output_dir}")
    else:
        print("⚠️  Config file not found - will be created on first run")
    
    # Verify key directories exist
    print("\nChecking project structure...")
    important_dirs = [
        'intellicrack',
        'dependencies', 
        'models',
        'plugins',
        'tools',
        'reports',
        'logs'
    ]
    
    for dir_name in important_dirs:
        dir_path = os.path.join(project_root, dir_name)
        if os.path.exists(dir_path):
            print(f"✅ {dir_name}/ exists")
        else:
            print(f"⚠️  {dir_name}/ not found (will be created as needed)")
    
    # Test imports
    print("\nTesting Python imports...")
    try:
        import intellicrack
        print("✅ intellicrack package imports successfully")
        
        from intellicrack.utils.path_discovery import find_tool
        print("✅ Path discovery module imports successfully")
        
        from intellicrack.config import get_config
        print("✅ Config module imports successfully")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("\nMake sure to run from the project root directory.")
        return False
    
    # Test dynamic path discovery
    print("\nTesting dynamic path discovery...")
    try:
        from intellicrack.utils.path_discovery import find_tool
        
        tools_to_test = ['python', 'git']
        for tool in tools_to_test:
            path = find_tool(tool)
            if path:
                print(f"✅ Found {tool}: {path}")
            else:
                print(f"⚠️  {tool} not found (will prompt on first use)")
    except Exception as e:
        print(f"⚠️  Path discovery test failed: {e}")
    
    print("\n" + "=" * 60)
    print("Verification complete!")
    print("\nNext steps:")
    print("1. Run dependencies\\INSTALL.bat to ensure all dependencies are installed")
    print("2. Launch Intellicrack with RUN_INTELLICRACK.bat")
    print("3. Tools will be discovered automatically on first use")
    
    return True

if __name__ == '__main__':
    # Add project root to Python path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    sys.path.insert(0, project_root)
    
    success = verify_paths()
    sys.exit(0 if success else 1)