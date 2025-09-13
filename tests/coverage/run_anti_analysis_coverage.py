#!/usr/bin/env python3
"""Simple runner for anti-analysis coverage analysis"""

import sys
import os
import importlib.util

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def main():
    print("=== ANTI-ANALYSIS INIT COVERAGE RUNNER ===\n")

    # Test basic imports first
    try:
        print("Testing basic imports...")
        import intellicrack.core.anti_analysis
        from intellicrack.core.anti_analysis import AntiAnalysisEngine
        print("✅ Basic imports successful")

        # Test engine creation
        engine = AntiAnalysisEngine()
        print("✅ AntiAnalysisEngine created successfully")

        # Test basic methods
        vm_result = engine.detect_virtual_environment()
        debugger_result = engine.detect_debugger()
        sandbox_result = engine.detect_sandbox()
        print("✅ All detection methods callable")

        print(f"VM Detection Result: {type(vm_result)} - {vm_result}")
        print(f"Debugger Detection Result: {type(debugger_result)} - {debugger_result}")
        print(f"Sandbox Detection Result: {type(sandbox_result)} - {sandbox_result}")

    except Exception as e:
        print(f"❌ Import/Basic functionality failed: {e}")
        return False

    # Try to import and run coverage analysis
    try:
        print("\n" + "="*50)
        print("Running coverage analysis...")

        # Import the coverage analysis module
        spec = importlib.util.spec_from_file_location(
            "coverage_analysis",
            "tests/unit/core/anti_analysis/anti_analysis_init_coverage_analysis.py"
        )
        coverage_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(coverage_module)

        # Run the analysis functions
        print("Testing functionality...")
        functionality_ok = coverage_module.test_functionality()

        print("\nAnalyzing coverage...")
        coverage_percent = coverage_module.analyze_coverage()

        print(f"\n=== FINAL RESULTS ===")
        print(f"Functionality Test: {'PASS' if functionality_ok else 'FAIL'}")
        print(f"Coverage: {coverage_percent:.1f}%")
        print(f"Coverage Target (80%+): {'ACHIEVED' if coverage_percent >= 80 else 'NOT MET'}")

        return coverage_percent >= 80 and functionality_ok

    except Exception as e:
        print(f"❌ Coverage analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    if success:
        print("\n🎉 COVERAGE ANALYSIS COMPLETE - ALL TARGETS MET")
        sys.exit(0)
    else:
        print("\n⚠️  COVERAGE ANALYSIS COMPLETE - SOME ISSUES FOUND")
        sys.exit(1)
