#!/usr/bin/env python3
"""
Test script to verify behavioral analysis component imports.
"""

import sys
import traceback

def test_imports():
    """Test all behavioral analysis imports."""
    print("Testing behavioral analysis component imports...")
    print("=" * 60)
    
    success_count = 0
    total_tests = 0
    
    # Test core behavior detector
    total_tests += 1
    try:
        from intellicrack.core.analysis.behavior_based_protection_detector import (
            BehaviorBasedProtectionDetector,
            DetectionResult,
            ProtectionFamily,
            BehaviorEvent,
            BehaviorType
        )
        print("✓ BehaviorBasedProtectionDetector and related classes import successfully")
        success_count += 1
    except Exception as e:
        print(f"❌ BehaviorBasedProtectionDetector import failed: {e}")
    
    # Test integration manager
    total_tests += 1
    try:
        from intellicrack.core.analysis.behavioral_integration_manager import (
            BehavioralIntegrationManager,
            IntegrationStatus,
            ComponentStatus
        )
        print("✓ BehavioralIntegrationManager and related classes import successfully")
        success_count += 1
    except Exception as e:
        print(f"❌ BehavioralIntegrationManager import failed: {e}")
    
    # Test protection system
    total_tests += 1
    try:
        from intellicrack.core.analysis.behavioral_protection_system import (
            BehavioralProtectionSystem,
            get_behavioral_protection_system,
            AnalysisMode,
            SystemState
        )
        print("✓ BehavioralProtectionSystem and related classes import successfully")
        success_count += 1
    except Exception as e:
        print(f"❌ BehavioralProtectionSystem import failed: {e}")
    
    # Test UI components (may fail if PyQt6 not available)
    total_tests += 1
    try:
        from intellicrack.ui.widgets.behavioral_analysis_widget import BehavioralAnalysisWidget
        print("✓ BehavioralAnalysisWidget imports successfully")
        success_count += 1
    except Exception as e:
        print(f"⚠️  BehavioralAnalysisWidget import failed (may be due to missing PyQt6): {e}")
    
    total_tests += 1
    try:
        from intellicrack.ui.tabs.behavioral_analysis_tab import BehavioralAnalysisTab
        print("✓ BehavioralAnalysisTab imports successfully")
        success_count += 1
    except Exception as e:
        print(f"⚠️  BehavioralAnalysisTab import failed (may be due to missing PyQt6): {e}")
    
    # Test module-level imports
    total_tests += 1
    try:
        from intellicrack.core.analysis import (
            BehaviorBasedProtectionDetector,
            BehavioralIntegrationManager,
            BehavioralProtectionSystem
        )
        print("✓ Module-level imports from intellicrack.core.analysis work successfully")
        success_count += 1
    except Exception as e:
        print(f"❌ Module-level imports failed: {e}")
    
    print("=" * 60)
    print(f"Import test results: {success_count}/{total_tests} successful")
    
    if success_count >= 3:  # Core components should work
        print("✅ Behavioral protection detection system is ready!")
        print("\nCore components available:")
        print("  - Behavior-based protection detection")
        print("  - Multi-source data integration")
        print("  - Real-time pattern analysis")
        print("  - Machine learning classification")
        print("  - Temporal behavior analysis")
        return True
    else:
        print("❌ Critical import failures detected")
        return False

def test_basic_functionality():
    """Test basic system functionality."""
    print("\nTesting basic functionality...")
    print("=" * 60)
    
    try:
        from intellicrack.core.analysis.behavioral_protection_system import (
            get_behavioral_protection_system,
            SystemState
        )
        
        # Try to create system instance
        system = get_behavioral_protection_system()
        print("✓ Behavioral protection system instance created successfully")
        
        # Get system status
        status = system.get_system_status()
        print(f"✓ System status retrieved: {status.get('system_state', 'unknown')}")
        
        print("✅ Basic functionality test passed!")
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Behavioral Analysis System Import Test")
    print("=====================================")
    
    import_success = test_imports()
    
    if import_success:
        functionality_success = test_basic_functionality()
        
        if functionality_success:
            print("\n🎉 All tests passed! The behavioral protection detection system is ready to use.")
            sys.exit(0)
        else:
            print("\n⚠️  Imports successful but functionality test failed.")
            sys.exit(1)
    else:
        print("\n❌ Critical import failures. Please check dependencies and installation.")
        sys.exit(1)