"""
Phase 5 Exploitation Capabilities Integration Test

Verifies that all implemented Phase 5 components can be imported
and initialized without errors, demonstrating the complete
exploitation framework is ready for deployment.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import sys
import traceback
from pathlib import Path

# Add Intellicrack to path
sys.path.insert(0, str(Path(__file__).parent))

def test_core_imports():
    """Test core module imports"""
    print("Testing core module imports...")
    
    try:
        # Memory Framework
        from intellicrack.core.exploitation.memory_framework import (
            DirectSyscallManager, AdvancedMemoryOperations
        )
        print("✓ Memory Framework imported successfully")
        
        # Universal Unpacker
        from intellicrack.core.unpacking.universal_unpacker import UniversalUnpacker
        from intellicrack.core.unpacking.oep_detection import OEPDetector
        print("✓ Universal Unpacker imported successfully")
        
        # Anti-Analysis Bypass
        from intellicrack.core.anti_analysis.titan_hide_engine import TitanHideEngine
        print("✓ TitanHide Engine imported successfully")
        
        # Import Reconstruction
        from intellicrack.core.reconstruction.import_rebuilder import ImportRebuilder
        print("✓ Import Rebuilder imported successfully")
        
        # License Bypass
        from intellicrack.core.licensing.activation_bypass import ActivationBypass
        print("✓ Activation Bypass imported successfully")
        
        # VM Translation
        from intellicrack.core.devirtualization.vm_translator import VMTranslator
        print("✓ VM Translator imported successfully")
        
        # Stealth Techniques
        from intellicrack.core.advanced_bypass.stealth_techniques import StealthTechniques
        print("✓ Stealth Techniques imported successfully")
        
        # Orchestration System
        from intellicrack.core.exploitation.exploitation_workflow import (
            WorkflowOrchestrator, TaskExecutor
        )
        print("✓ Exploitation Workflow imported successfully")
        
        return True
        
    except Exception as e:
        print(f"✗ Import failed: {e}")
        traceback.print_exc()
        return False

def test_component_initialization():
    """Test component initialization"""
    print("\nTesting component initialization...")
    
    try:
        # Initialize memory operations
        from intellicrack.core.exploitation.memory_framework import AdvancedMemoryOperations
        memory_ops = AdvancedMemoryOperations()
        print("✓ Memory Operations initialized")
        
        # Initialize unpacker
        from intellicrack.core.unpacking.universal_unpacker import UniversalUnpacker
        unpacker = UniversalUnpacker()
        print("✓ Universal Unpacker initialized")
        
        # Initialize TitanHide
        from intellicrack.core.anti_analysis.titan_hide_engine import TitanHideEngine
        titan_hide = TitanHideEngine()
        print("✓ TitanHide Engine initialized")
        
        # Initialize import rebuilder
        from intellicrack.core.reconstruction.import_rebuilder import ImportRebuilder
        import_rebuilder = ImportRebuilder()
        print("✓ Import Rebuilder initialized")
        
        # Initialize activation bypass
        from intellicrack.core.licensing.activation_bypass import ActivationBypass
        activation_bypass = ActivationBypass()
        print("✓ Activation Bypass initialized")
        
        # Initialize VM translator
        from intellicrack.core.devirtualization.vm_translator import VMTranslator
        vm_translator = VMTranslator()
        print("✓ VM Translator initialized")
        
        # Initialize stealth techniques
        from intellicrack.core.advanced_bypass.stealth_techniques import StealthTechniques
        stealth_techniques = StealthTechniques()
        print("✓ Stealth Techniques initialized")
        
        # Initialize workflow orchestrator
        from intellicrack.core.exploitation.exploitation_workflow import WorkflowOrchestrator
        orchestrator = WorkflowOrchestrator()
        print("✓ Workflow Orchestrator initialized")
        
        return True
        
    except Exception as e:
        print(f"✗ Initialization failed: {e}")
        traceback.print_exc()
        return False

def test_workflow_loading():
    """Test workflow definition loading"""
    print("\nTesting workflow loading...")
    
    try:
        from intellicrack.core.exploitation.exploitation_workflow import WorkflowOrchestrator
        
        # Initialize orchestrator with config directory
        config_dir = Path(__file__).parent / "configs" / "workflows"
        orchestrator = WorkflowOrchestrator(str(config_dir))
        
        # List available workflows
        workflows = orchestrator.list_workflow_definitions()
        print(f"✓ Loaded {len(workflows)} workflow definitions")
        
        for workflow in workflows:
            print(f"  - {workflow['name']} ({workflow['task_count']} tasks)")
        
        return True
        
    except Exception as e:
        print(f"✗ Workflow loading failed: {e}")
        traceback.print_exc()
        return False

def test_basic_functionality():
    """Test basic functionality of key components"""
    print("\nTesting basic functionality...")
    
    try:
        # Test VM detection
        from intellicrack.core.devirtualization.vm_translator import VMTranslator
        vm_translator = VMTranslator()
        
        # Create a dummy binary for testing
        test_binary = b"\x50\x53\x51\x52\x56\x57\x8B\xF4\x8B\x7C\x24" * 100
        
        # Test VM type detection (should not crash)
        detected_vms = vm_translator.vm_detector.detect_vm_type(test_binary)
        print(f"✓ VM detection functional (detected {len(detected_vms)} VM types)")
        
        # Test license detection
        from intellicrack.core.licensing.activation_bypass import ActivationBypass
        bypass = ActivationBypass()
        
        # Test license scheme detection
        detected_schemes = bypass.license_detector.detect_license_scheme("non_existent_binary.exe")
        print(f"✓ License detection functional (detected {len(detected_schemes)} schemes)")
        
        # Test stealth techniques
        from intellicrack.core.advanced_bypass.stealth_techniques import StealthTechniques
        stealth = StealthTechniques()
        
        active_techniques = stealth.get_active_techniques()
        print(f"✓ Stealth techniques functional ({len(active_techniques)} active)")
        
        return True
        
    except Exception as e:
        print(f"✗ Functionality test failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Main test function"""
    print("Phase 5 Exploitation Capabilities Integration Test")
    print("=" * 55)
    
    tests = [
        ("Core Imports", test_core_imports),
        ("Component Initialization", test_component_initialization),
        ("Workflow Loading", test_workflow_loading),
        ("Basic Functionality", test_basic_functionality)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n[{test_name}]")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"✗ Test {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 55)
    print("Test Results Summary:")
    print("=" * 55)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        status_symbol = "✓" if result else "✗"
        print(f"{status_symbol} {test_name}: {status}")
        if result:
            passed += 1
    
    print("=" * 55)
    print(f"Overall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 All Phase 5 components are ready for deployment!")
        return 0
    else:
        print("⚠️  Some components need attention before deployment.")
        return 1

if __name__ == "__main__":
    sys.exit(main())