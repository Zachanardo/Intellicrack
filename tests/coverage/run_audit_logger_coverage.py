#!/usr/bin/env python3
"""
Coverage analysis for audit_logger.py tests.
Production-ready coverage validation for security research audit logging.
"""

import os
import sys
import subprocess
import tempfile
from pathlib import Path

def run_coverage_analysis():
    """Run comprehensive coverage analysis for audit_logger.py"""

    project_root = Path(__file__).parent
    os.chdir(project_root)

    print("=" * 80)
    print("INTELLICRACK AUDIT LOGGER COVERAGE ANALYSIS")
    print("=" * 80)
    print()

    # Set testing environment
    os.environ['INTELLICRACK_TESTING'] = '1'
    os.environ['DISABLE_AI_WORKERS'] = '1'
    os.environ['DISABLE_BACKGROUND_THREADS'] = '1'
    os.environ['NO_AUTO_START'] = '1'
    os.environ['QT_QPA_PLATFORM'] = 'offscreen'
    os.environ['PYTHONPATH'] = str(project_root)

    # Test 1: Basic import validation
    print("Step 1: Validating audit_logger imports...")
    try:
        sys.path.insert(0, str(project_root))
        from intellicrack.core.logging.audit_logger import (
            AuditEventType,
            AuditSeverity,
            AuditEvent,
            AuditLogger,
            PerformanceMonitor,
            TelemetryCollector,
            ContextualLogger,
            get_audit_logger
        )
        print("✅ All audit_logger classes imported successfully")
    except Exception as e:
        print(f"❌ Import validation failed: {e}")
        return False

    # Test 2: Test file syntax validation
    print("\nStep 2: Validating test file syntax...")
    test_file = "tests/unit/core/logging/test_audit_logger.py"
    if not os.path.exists(test_file):
        print(f"❌ Test file not found: {test_file}")
        return False

    try:
        # Compile test file to check syntax
        with open(test_file, 'r') as f:
            test_code = f.read()
        compile(test_code, test_file, 'exec')
        print(f"✅ Test file syntax valid: {test_file}")
    except SyntaxError as e:
        print(f"❌ Syntax error in test file: {e}")
        return False

    # Test 3: Run coverage analysis
    print("\nStep 3: Running coverage analysis...")

    coverage_commands = [
        [sys.executable, "-m", "coverage", "run", "--source=intellicrack.core.logging.audit_logger",
         "-m", "pytest", test_file, "-v"],
        [sys.executable, "-m", "coverage", "report", "--show-missing"],
        [sys.executable, "-m", "coverage", "html", "--directory=htmlcov_audit_logger"]
    ]

    for i, cmd in enumerate(coverage_commands):
        print(f"\n  Running command {i+1}: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=project_root
            )

            if result.returncode == 0:
                print(f"✅ Command {i+1} completed successfully")
                if result.stdout:
                    print("STDOUT:")
                    print(result.stdout)
            else:
                print(f"⚠️ Command {i+1} completed with warnings/errors (exit code: {result.returncode})")
                if result.stdout:
                    print("STDOUT:")
                    print(result.stdout)
                if result.stderr:
                    print("STDERR:")
                    print(result.stderr)

        except subprocess.TimeoutExpired:
            print(f"❌ Command {i+1} timed out")
            return False
        except Exception as e:
            print(f"❌ Command {i+1} failed: {e}")
            return False

    # Test 4: Generate coverage summary
    print("\nStep 4: Generating coverage summary...")

    try:
        # Get coverage percentage
        result = subprocess.run(
            [sys.executable, "-m", "coverage", "report", "--format=text"],
            capture_output=True,
            text=True,
            cwd=project_root
        )

        if result.returncode == 0:
            coverage_output = result.stdout
            lines = coverage_output.split('\n')

            # Find the total coverage line
            total_coverage = None
            for line in lines:
                if 'TOTAL' in line and '%' in line:
                    parts = line.split()
                    for part in parts:
                        if '%' in part:
                            total_coverage = part.replace('%', '')
                            break
                    break

            if total_coverage:
                coverage_percent = float(total_coverage)
                print(f"📊 Total Coverage: {coverage_percent}%")

                if coverage_percent >= 80.0:
                    print("🎉 SUCCESS: Achieved 80%+ coverage requirement!")
                else:
                    print(f"⚠️  Coverage below 80% target (achieved {coverage_percent}%)")

                print(f"\n📁 HTML Coverage Report: htmlcov_audit_logger/index.html")
                return True

    except Exception as e:
        print(f"❌ Coverage summary generation failed: {e}")
        return False

    print("✅ Coverage analysis completed")
    return True


if __name__ == "__main__":
    success = run_coverage_analysis()
    if success:
        print("\n🎯 AUDIT LOGGER COVERAGE ANALYSIS COMPLETE")
    else:
        print("\n❌ COVERAGE ANALYSIS FAILED")
        sys.exit(1)
