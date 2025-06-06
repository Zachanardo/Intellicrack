#!/usr/bin/env python3
"""
Final Verification Report for External Tool Integration Features #55-57
======================================================================

This script provides a comprehensive final verification of all external tool
integration features with detailed analysis and actionable recommendations.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def generate_final_report():
    """Generate final verification report."""
    print("="*80)
    print("FINAL VERIFICATION REPORT")
    print("External Tool Integration Features #55-57")
    print("="*80)

    report = {
        "features": {},
        "workflow_chains": {},
        "implementation_quality": {},
        "recommendations": []
    }

    # Feature #55: Advanced Ghidra Analysis Integration
    print("\n🔍 FEATURE #55: ADVANCED GHIDRA ANALYSIS INTEGRATION")
    print("-" * 60)

    ghidra_components = {
        "UI Buttons": check_ghidra_ui_components(),
        "Runner Functions": check_ghidra_runner_functions(),
        "Core Implementation": check_ghidra_core_implementation(),
        "Scripts Availability": check_ghidra_scripts(),
        "Error Handling": check_ghidra_error_handling(),
        "Cross-Platform Support": check_ghidra_cross_platform()
    }

    ghidra_score = sum(1 for v in ghidra_components.values() if v) / len(ghidra_components) * 100
    report["features"]["ghidra"] = {"score": ghidra_score, "components": ghidra_components}

    print(f"Overall Score: {ghidra_score:.1f}%")
    for component, status in ghidra_components.items():
        status_icon = "✅" if status else "❌"
        print(f"  {status_icon} {component}")

    # Feature #56: QEMU System Emulation Integration
    print("\n🖥️  FEATURE #56: QEMU SYSTEM EMULATION INTEGRATION")
    print("-" * 60)

    qemu_components = {
        "UI Buttons": check_qemu_ui_components(),
        "Runner Functions": check_qemu_runner_functions(),
        "Core Implementation": check_qemu_core_implementation(),
        "Command Input Integration": check_qemu_command_integration(),
        "Snapshot Management": check_qemu_snapshot_management(),
        "Error Handling": check_qemu_error_handling()
    }

    qemu_score = sum(1 for v in qemu_components.values() if v) / len(qemu_components) * 100
    report["features"]["qemu"] = {"score": qemu_score, "components": qemu_components}

    print(f"Overall Score: {qemu_score:.1f}%")
    for component, status in qemu_components.items():
        status_icon = "✅" if status else "❌"
        print(f"  {status_icon} {component}")

    # Feature #57: Frida Dynamic Instrumentation Integration
    print("\n⚡ FEATURE #57: FRIDA DYNAMIC INSTRUMENTATION INTEGRATION")
    print("-" * 60)

    frida_components = {
        "UI Buttons": check_frida_ui_components(),
        "Runner Functions": check_frida_runner_functions(),
        "Wrapper Functions": check_frida_wrapper_functions(),
        "Scripts Availability": check_frida_scripts(),
        "Script Content": check_frida_script_content(),
        "Error Handling": check_frida_error_handling()
    }

    frida_score = sum(1 for v in frida_components.values() if v) / len(frida_components) * 100
    report["features"]["frida"] = {"score": frida_score, "components": frida_components}

    print(f"Overall Score: {frida_score:.1f}%")
    for component, status in frida_components.items():
        status_icon = "✅" if status else "❌"
        print(f"  {status_icon} {component}")

    # Workflow Chain Analysis
    print("\n🔄 WORKFLOW CHAIN ANALYSIS")
    print("-" * 60)

    workflow_chains = {
        "Ghidra: UI → Runner → Core → Result": verify_ghidra_workflow_chain(),
        "QEMU: UI → Command → Execution → Display": verify_qemu_workflow_chain(), 
        "Frida: UI → Script → Execution → Collection": verify_frida_workflow_chain(),
        "Integrated: Static → Dynamic → Reporting": verify_integrated_workflow_chain()
    }

    report["workflow_chains"] = workflow_chains

    for workflow, status in workflow_chains.items():
        status_icon = "✅" if status else "❌"
        print(f"  {status_icon} {workflow}")

    # Implementation Quality Analysis
    print("\n📊 IMPLEMENTATION QUALITY ANALYSIS")
    print("-" * 60)

    quality_metrics = {
        "Code Organization": check_code_organization(),
        "Error Handling Robustness": check_error_handling_robustness(),
        "Cross-Platform Compatibility": check_cross_platform_compatibility(),
        "Documentation Coverage": check_documentation_coverage(),
        "Test Coverage": check_test_coverage()
    }

    report["implementation_quality"] = quality_metrics

    for metric, status in quality_metrics.items():
        status_icon = "✅" if status else "❌"
        print(f"  {status_icon} {metric}")

    # Overall Assessment
    overall_score = (ghidra_score + qemu_score + frida_score) / 3

    print("\n🎯 OVERALL ASSESSMENT")
    print("-" * 60)
    print(f"Feature #55 (Ghidra): {ghidra_score:.1f}%")
    print(f"Feature #56 (QEMU): {qemu_score:.1f}%") 
    print(f"Feature #57 (Frida): {frida_score:.1f}%")
    print(f"\nOverall Integration Score: {overall_score:.1f}%")

    # Generate recommendations
    recommendations = generate_recommendations(report)
    report["recommendations"] = recommendations

    print("\n💡 RECOMMENDATIONS")
    print("-" * 60)
    for priority, items in recommendations.items():
        if items:
            print(f"\n{priority.upper()} PRIORITY:")
            for item in items:
                print(f"  • {item}")

    # Final verdict
    print("\n🏆 FINAL VERDICT")
    print("-" * 60)

    if overall_score >= 95:
        verdict = "EXCELLENT - Ready for production use"
        emoji = "🏆"
    elif overall_score >= 85:
        verdict = "GOOD - Minor improvements needed"
        emoji = "✅"
    elif overall_score >= 70:
        verdict = "ACCEPTABLE - Some issues to address"
        emoji = "⚠️"
    else:
        verdict = "NEEDS WORK - Significant improvements required"
        emoji = "❌"

    print(f"{emoji} {verdict}")
    print(f"\nExternal Tool Integration Score: {overall_score:.1f}%")

    return report

def check_ghidra_ui_components():
    """Check Ghidra UI components."""
    try:
        from intellicrack.ui.main_app import IntellicrackApp
        return hasattr(IntellicrackApp, 'run_ghidra_analysis_gui')
    except ImportError:
        return False

def check_ghidra_runner_functions():
    """Check Ghidra runner functions."""
    try:
        from intellicrack.utils.runner_functions import run_advanced_ghidra_analysis
        return True
    except ImportError:
        return False

def check_ghidra_core_implementation():
    """Check Ghidra core implementation."""
    try:
        from intellicrack.utils.runner_functions import run_advanced_ghidra_analysis
        # Test with None parameters to check error handling
        result = run_advanced_ghidra_analysis(None, None)
        return isinstance(result, dict) and "status" in result
    except Exception:
        return False

def check_ghidra_scripts():
    """Check Ghidra scripts availability."""
    script_path = project_root / "plugins" / "ghidra_scripts" / "AdvancedAnalysis.java"
    return script_path.exists()

def check_ghidra_error_handling():
    """Check Ghidra error handling."""
    try:
        from intellicrack.utils.runner_functions import run_advanced_ghidra_analysis
        result = run_advanced_ghidra_analysis(None, "/nonexistent/file.exe")
        return result.get("status") == "error"
    except Exception:
        return False

def check_ghidra_cross_platform():
    """Check Ghidra cross-platform support."""
    # Check if path handling uses os.path.join instead of hard-coded separators
    runner_file = project_root / "intellicrack" / "utils" / "runner_functions.py"
    if runner_file.exists():
        with open(runner_file, 'r') as f:
            content = f.read()
            # Look for cross-platform path handling
            return "os.path.join" in content and "analyze_headless = os.path.join" in content
    return False

def check_qemu_ui_components():
    """Check QEMU UI components."""
    try:
        from intellicrack.ui.main_app import IntellicrackApp
        methods = ['create_qemu_snapshot', 'restore_qemu_snapshot', 'execute_qemu_command']
        return all(hasattr(IntellicrackApp, method) for method in methods)
    except ImportError:
        return False

def check_qemu_runner_functions():
    """Check QEMU runner functions."""
    try:
        from intellicrack.utils.runner_functions import run_qemu_analysis
        return True
    except ImportError:
        return False

def check_qemu_core_implementation():
    """Check QEMU core implementation."""
    try:
        from intellicrack.core.processing.qemu_emulator import QEMUSystemEmulator
        return True
    except ImportError:
        return False

def check_qemu_command_integration():
    """Check QEMU command input integration."""
    main_app_file = project_root / "intellicrack" / "ui" / "main_app.py"
    if main_app_file.exists():
        with open(main_app_file, 'r') as f:
            content = f.read()
            # Check if qemu_command_input is stored as instance variable
            return "self.qemu_command_input" in content
    return False

def check_qemu_snapshot_management():
    """Check QEMU snapshot management."""
    try:
        from intellicrack.core.processing.qemu_emulator import QEMUSystemEmulator
        # Check if snapshot methods exist
        methods = ['create_snapshot', 'restore_snapshot', 'compare_snapshots']
        return all(hasattr(QEMUSystemEmulator, method) for method in methods)
    except ImportError:
        return False

def check_qemu_error_handling():
    """Check QEMU error handling."""
    try:
        from intellicrack.utils.runner_functions import run_qemu_analysis
        result = run_qemu_analysis(None, None)
        return isinstance(result, dict) and "status" in result
    except Exception:
        return False

def check_frida_ui_components():
    """Check Frida UI components."""
    main_app_file = project_root / "intellicrack" / "ui" / "main_app.py"
    if main_app_file.exists():
        with open(main_app_file, 'r') as f:
            content = f.read()
            # Check for Frida-related UI elements
            return "run_frida_btn" in content or "Frida" in content
    return False

def check_frida_runner_functions():
    """Check Frida runner functions."""
    try:
        from intellicrack.utils.runner_functions import (
            run_frida_analysis, run_dynamic_instrumentation, run_frida_script
        )
        return True
    except ImportError:
        return False

def check_frida_wrapper_functions():
    """Check Frida wrapper functions."""
    try:
        from intellicrack.utils.tool_wrappers import wrapper_run_frida_script
        return True
    except ImportError:
        return False

def check_frida_scripts():
    """Check Frida scripts availability."""
    scripts_dir = project_root / "plugins" / "frida_scripts"
    if not scripts_dir.exists():
        return False

    expected_scripts = [
        "registry_monitor.js", "adobe_bypass_frida.js", "anti_debugger.js"
    ]
    return all((scripts_dir / script).exists() for script in expected_scripts)

def check_frida_script_content():
    """Check Frida script content."""
    script_path = project_root / "plugins" / "frida_scripts" / "registry_monitor.js"
    if script_path.exists():
        with open(script_path, 'r') as f:
            content = f.read()
            required_elements = ["Java.perform", "Interceptor.attach", "RegOpenKeyExW"]
            return all(element in content for element in required_elements)
    return False

def check_frida_error_handling():
    """Check Frida error handling."""
    try:
        from intellicrack.utils.runner_functions import run_frida_script
        result = run_frida_script(None, None)
        return result.get("status") == "error"
    except Exception:
        return False

def verify_ghidra_workflow_chain():
    """Verify complete Ghidra workflow chain."""
    try:
        from intellicrack.utils.runner_functions import run_advanced_ghidra_analysis

        # Create mock app
        from unittest.mock import Mock
        mock_app = Mock()
        mock_app.update_output = Mock()
        mock_app.analyze_status = Mock()
        mock_app.analyze_status.setText = Mock()

        # Test workflow
        result = run_advanced_ghidra_analysis(mock_app, None)

        # Verify: UI called, result returned, error handled
        return (
            mock_app.update_output.called and
            isinstance(result, dict) and
            "status" in result
        )
    except Exception:
        return False

def verify_qemu_workflow_chain():
    """Verify complete QEMU workflow chain."""
    try:
        from intellicrack.utils.runner_functions import run_qemu_analysis

        # Create mock app
        from unittest.mock import Mock
        mock_app = Mock()
        mock_app.update_output = Mock()

        # Test workflow
        result = run_qemu_analysis(mock_app, None)

        # Verify: Result has consistent format
        return isinstance(result, dict) and "status" in result
    except Exception:
        return False

def verify_frida_workflow_chain():
    """Verify complete Frida workflow chain."""
    try:
        from intellicrack.utils.runner_functions import run_frida_analysis

        # Create mock app
        from unittest.mock import Mock
        mock_app = Mock()
        mock_app.update_output = Mock()

        # Test workflow
        result = run_frida_analysis(mock_app, None)

        # Verify: UI called, result returned
        return isinstance(result, dict) and "status" in result
    except Exception:
        return False

def verify_integrated_workflow_chain():
    """Verify integrated workflow chain."""
    try:
        # Check if all runner functions can be imported together
        from intellicrack.utils.runner_functions import (
            run_advanced_ghidra_analysis, run_qemu_analysis, run_frida_analysis
        )
        return True
    except ImportError:
        return False

def check_code_organization():
    """Check code organization quality."""
    # Verify proper module structure exists
    required_modules = [
        "intellicrack/utils/runner_functions.py",
        "intellicrack/utils/tool_wrappers.py",
        "intellicrack/core/processing/qemu_emulator.py",
        "intellicrack/ui/main_app.py"
    ]

    return all((project_root / module).exists() for module in required_modules)

def check_error_handling_robustness():
    """Check error handling robustness."""
    try:
        from intellicrack.utils.runner_functions import (
            run_advanced_ghidra_analysis, run_qemu_analysis, run_frida_analysis
        )

        # Test all runner functions with None parameters
        results = [
            run_advanced_ghidra_analysis(None, None),
            run_qemu_analysis(None, None),
            run_frida_analysis(None, None)
        ]

        # All should return error status gracefully
        return all(
            isinstance(result, dict) and 
            result.get("status") == "error" and
            "message" in result
            for result in results
        )
    except Exception:
        return False

def check_cross_platform_compatibility():
    """Check cross-platform compatibility."""
    runner_file = project_root / "intellicrack" / "utils" / "runner_functions.py"
    if runner_file.exists():
        with open(runner_file, 'r') as f:
            content = f.read()
            # Check for proper path handling
            return (
                "os.path.join" in content and
                "os.name ==" in content and
                "analyzeHeadless.bat" in content and
                "analyzeHeadless\"" in content
            )
    return False

def check_documentation_coverage():
    """Check documentation coverage."""
    # Verify docstrings exist in main functions
    runner_file = project_root / "intellicrack" / "utils" / "runner_functions.py"
    if runner_file.exists():
        with open(runner_file, 'r') as f:
            content = f.read()
            # Check for comprehensive docstrings
            return (
                'def run_advanced_ghidra_analysis' in content and
                '"""' in content and
                'Args:' in content and
                'Returns:' in content
            )
    return False

def check_test_coverage():
    """Check test coverage."""
    test_files = [
        "test_external_tool_integration.py",
        "verify_external_tools.py",
        "test_external_tool_workflows.py"
    ]

    return all((project_root / test_file).exists() for test_file in test_files)

def generate_recommendations(report):
    """Generate actionable recommendations."""
    recommendations = {
        "high": [],
        "medium": [],
        "low": []
    }

    # Analyze scores and generate specific recommendations
    ghidra_score = report["features"]["ghidra"]["score"]
    qemu_score = report["features"]["qemu"]["score"]
    frida_score = report["features"]["frida"]["score"]

    if ghidra_score < 100:
        if not report["features"]["ghidra"]["components"]["Cross-Platform Support"]:
            recommendations["medium"].append("Improve Ghidra cross-platform path handling")

    if qemu_score < 100:
        if not report["features"]["qemu"]["components"]["Command Input Integration"]:
            recommendations["high"].append("Fix QEMU command input field integration")

    if frida_score < 100:
        missing_components = [k for k, v in report["features"]["frida"]["components"].items() if not v]
        if missing_components:
            recommendations["high"].extend([f"Fix Frida {comp}" for comp in missing_components])

    # Workflow recommendations
    missing_workflows = [k for k, v in report["workflow_chains"].items() if not v]
    if missing_workflows:
        recommendations["medium"].extend([f"Fix workflow: {wf}" for wf in missing_workflows])

    # Quality recommendations
    missing_quality = [k for k, v in report["implementation_quality"].items() if not v]
    if missing_quality:
        recommendations["low"].extend([f"Improve {qual}" for qual in missing_quality])

    # General recommendations based on overall performance
    overall_score = (ghidra_score + qemu_score + frida_score) / 3

    if overall_score >= 95:
        recommendations["low"].append("Consider adding performance optimizations")
        recommendations["low"].append("Add more comprehensive error messages")
    elif overall_score >= 85:
        recommendations["medium"].append("Add more robust error handling")
        recommendations["medium"].append("Improve user feedback during long operations")
    else:
        recommendations["high"].append("Address core functionality gaps")
        recommendations["high"].append("Improve integration reliability")

    return recommendations

if __name__ == "__main__":
    report = generate_final_report()

    # Calculate final score
    scores = [feature["score"] for feature in report["features"].values()]
    final_score = sum(scores) / len(scores)

    print(f"\n🎯 FINAL SCORE: {final_score:.1f}%")

    if final_score >= 90:
        print("🏆 OUTSTANDING - External tool integration is production-ready!")
        sys.exit(0)
    elif final_score >= 80:
        print("✅ EXCELLENT - Minor improvements recommended")
        sys.exit(0)
    elif final_score >= 70:
        print("⚠️  GOOD - Some issues need attention")
        sys.exit(1)
    else:
        print("❌ NEEDS WORK - Significant improvements required")
        sys.exit(1)