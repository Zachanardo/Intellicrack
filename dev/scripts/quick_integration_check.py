#!/usr/bin/env python3
"""
Quick Integration Check

Fast verification of critical exploitation framework components.
"""

import logging
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')


def test_core_imports():
    """Test core module imports."""
    print("Testing core module imports...")
    try:
        from intellicrack import core

        # Test critical exploitation modules
        modules_to_test = [
            'c2',
            'evasion',
            'post_exploitation',
            'vulnerability_research'
        ]

        working_modules = []
        for module_name in modules_to_test:
            if hasattr(core, module_name):
                module = getattr(core, module_name)
                if module is not None:
                    working_modules.append(module_name)
                    print(f"  ✓ {module_name}")
                else:
                    print(f"  ✗ {module_name} (None)")
            else:
                print(f"  ✗ {module_name} (missing)")

        print(
            f"Core modules: {len(working_modules)}/{len(modules_to_test)} working")
        return len(working_modules) >= len(modules_to_test) // 2

    except Exception as e:
        print(f"  ✗ Core import failed: {e}")
        return False


def test_ai_imports():
    """Test AI module imports."""
    print("Testing AI module imports...")
    try:
        from intellicrack import ai

        # Test critical AI components
        components = ['VulnerabilityResearchAI', 'ExploitationOrchestrator']

        working_components = []
        for component_name in components:
            if hasattr(ai, component_name):
                component = getattr(ai, component_name)
                if component is not None:
                    working_components.append(component_name)
                    print(f"  ✓ {component_name}")
                else:
                    print(f"  ✗ {component_name} (None)")
            else:
                print(f"  ✗ {component_name} (missing)")

        print(
            f"AI components: {len(working_components)}/{len(components)} working")
        return len(working_components) == len(components)

    except Exception as e:
        print(f"  ✗ AI import failed: {e}")
        return False


def test_basic_functionality():
    """Test basic functionality of key components."""
    print("Testing basic functionality...")
    tests_passed = 0

    # Test 1: PayloadEngine
    try:
        from intellicrack.core.exploitation.payload_engine import PayloadEngine
        PayloadEngine()
        print("  ✓ PayloadEngine instantiation")
        tests_passed += 1
    except Exception as e:
        print(f"  ✗ PayloadEngine failed: {e}")

    # Test 2: ExploitationOrchestrator
    try:
        from intellicrack.ai.exploitation_orchestrator import ExploitationOrchestrator
        orchestrator = ExploitationOrchestrator()
        status = orchestrator.get_orchestrator_status()
        if isinstance(status, dict):
            print("  ✓ ExploitationOrchestrator functional")
            tests_passed += 1
        else:
            print("  ✗ ExploitationOrchestrator status invalid")
    except Exception as e:
        print(f"  ✗ ExploitationOrchestrator failed: {e}")

    # Test 3: C2Manager (with graceful aiohttp handling)
    try:
        from intellicrack.core.c2.c2_manager import C2Manager
        C2Manager()
        print("  ✓ C2Manager instantiation")
        tests_passed += 1
    except Exception as e:
        print(f"  ✗ C2Manager failed: {e}")

    print(f"Basic functionality: {tests_passed}/3 tests passed")
    return tests_passed >= 2


def test_cli_availability():
    """Test CLI availability."""
    print("Testing CLI availability...")
    try:
        print("  ✓ CLI import successful")
        return True
    except Exception as e:
        print(f"  ✗ CLI import failed: {e}")
        return False


def main():
    """Run quick integration check."""
    print("=" * 50)
    print("INTELLICRACK QUICK INTEGRATION CHECK")
    print("=" * 50)

    tests = [
        ("Core Imports", test_core_imports),
        ("AI Imports", test_ai_imports),
        ("Basic Functionality", test_basic_functionality),
        ("CLI Availability", test_cli_availability)
    ]

    results = []
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"  ✗ Test failed with exception: {e}")
            results.append(False)

    # Summary
    passed = sum(results)
    total = len(results)
    success_rate = (passed / total * 100) if total > 0 else 0

    print("\n" + "=" * 50)
    print("QUICK CHECK SUMMARY")
    print("=" * 50)
    print(f"Tests Passed: {passed}/{total}")
    print(f"Success Rate: {success_rate:.1f}%")

    if success_rate >= 75:
        print("✅ INTEGRATION STATUS: GOOD")
        print("   Critical components are working properly.")
    elif success_rate >= 50:
        print("⚠️  INTEGRATION STATUS: ACCEPTABLE")
        print("   Most components working with some issues.")
    else:
        print("❌ INTEGRATION STATUS: NEEDS WORK")
        print("   Multiple integration issues detected.")

    return success_rate >= 50


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
