#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Test script for AI Complex Binary Analysis Integration

This script tests the integration of analyze_binary_complex() method
from ai_assistant_enhanced.py into various parts of the application.
"""

import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

from intellicrack.ai.ai_assistant_enhanced import IntellicrackAIAssistant
from intellicrack.ai.orchestrator import AIOrchestrator, AITask, AITaskType, AnalysisComplexity
from intellicrack.llm.tools.intellicrack_protection_analysis_tool import DIEAnalysisTool
from intellicrack.tools.protection_analyzer_tool import ProtectionAnalyzerTool
from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)


def test_direct_ai_assistant():
    """Test direct AI assistant complex analysis"""
    print("\n=== Testing Direct AI Assistant Complex Analysis ===")

    ai_assistant = IntellicrackAIAssistant()

    # Test with a sample binary path
    test_binary = "C:/Windows/System32/notepad.exe"

    if not os.path.exists(test_binary):
        print(f"Test binary not found: {test_binary}")
        return False

    # Prepare sample ML results
    ml_results = {
        "confidence": 0.85,
        "predictions": [
            {"name": "UPX Packer", "type": "packer", "confidence": 0.92},
            {"name": "VMProtect", "type": "protector", "confidence": 0.78}
        ]
    }

    try:
        result = ai_assistant.analyze_binary_complex(test_binary, ml_results)
        print(f"Success: {result.get('analysis_type')}")
        print(f"Confidence: {result.get('confidence', 0.0)}")
        print(f"Findings: {result.get('findings', [])}")
        print(f"Recommendations: {result.get('recommendations', [])}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def test_protection_analyzer_tool():
    """Test protection analyzer tool integration"""
    print("\n=== Testing Protection Analyzer Tool Integration ===")

    tool = ProtectionAnalyzerTool()
    test_binary = "C:/Windows/System32/notepad.exe"

    if not os.path.exists(test_binary):
        print(f"Test binary not found: {test_binary}")
        return False

    try:
        result = tool.analyze(test_binary, detailed=True)

        if result.get("success"):
            print("Protection analysis succeeded")

            # Check for AI complex analysis
            if "ai_complex_analysis" in result:
                ai_analysis = result["ai_complex_analysis"]
                print(f"AI Analysis Confidence: {ai_analysis.get('confidence', 0.0)}")
                print(f"AI Findings: {ai_analysis.get('findings', [])}")
                print(f"AI Recommendations: {ai_analysis.get('recommendations', [])}")
                return True
            else:
                print("Warning: AI complex analysis not found in results")
        else:
            print(f"Analysis failed: {result.get('error')}")

    except Exception as e:
        print(f"Error: {e}")

    return False


def test_die_analysis_tool():
    """Test DIE analysis tool integration"""
    print("\n=== Testing DIE Analysis Tool Integration ===")

    tool = DIEAnalysisTool()
    test_binary = "C:/Windows/System32/notepad.exe"

    if not os.path.exists(test_binary):
        print(f"Test binary not found: {test_binary}")
        return False

    try:
        result = tool.execute(
            file_path=test_binary,
            scan_mode="deep",
            extract_strings=True,
            analyze_entropy=True
        )

        if result.get("success"):
            print("DIE analysis succeeded")

            # Check for AI complex analysis
            if "ai_complex_analysis" in result:
                ai_analysis = result["ai_complex_analysis"]
                print(f"AI Analysis Confidence: {ai_analysis.get('confidence', 0.0)}")
                print(f"AI Findings: {ai_analysis.get('findings', [])}")
                print(f"AI Recommendations: {ai_analysis.get('recommendations', [])}")
                return True
            else:
                print("Warning: AI complex analysis not found in results")
        else:
            print(f"Analysis failed: {result.get('error')}")

    except Exception as e:
        print(f"Error: {e}")

    return False


def test_orchestrator_integration():
    """Test AI orchestrator integration"""
    print("\n=== Testing AI Orchestrator Integration ===")

    orchestrator = AIOrchestrator()
    test_binary = "C:/Windows/System32/notepad.exe"

    if not os.path.exists(test_binary):
        print(f"Test binary not found: {test_binary}")
        return False

    # Create a binary analysis task
    task = AITask(
        task_id="test_binary_analysis",
        task_type=AITaskType.BINARY_ANALYSIS,
        complexity=AnalysisComplexity.COMPLEX,
        input_data={"binary_path": test_binary},
        priority=8
    )

    try:
        # Submit task
        orchestrator.submit_task(task)

        # Wait for result (with timeout)
        import time
        max_wait = 30  # seconds
        start_time = time.time()

        while time.time() - start_time < max_wait:
            status = orchestrator.get_task_status(task.task_id)
            if status and status.get("status") == "completed":
                result = orchestrator.get_task_result(task.task_id)
                if result:
                    print("Orchestrator analysis completed")

                    # Check for AI complex analysis
                    if "ai_complex_analysis" in result.result_data:
                        ai_analysis = result.result_data["ai_complex_analysis"]
                        print(f"AI Analysis Confidence: {ai_analysis.get('confidence', 0.0)}")
                        print(f"AI Findings: {ai_analysis.get('findings', [])}")
                        print(f"AI Recommendations: {ai_analysis.get('recommendations', [])}")
                        return True
                    else:
                        print("Warning: AI complex analysis not found in orchestrator results")
                break
            time.sleep(1)
        else:
            print("Timeout waiting for orchestrator result")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        orchestrator.shutdown()

    return False


def main():
    """Run all integration tests"""
    print("Testing AI Complex Binary Analysis Integration")
    print("=" * 50)

    results = {
        "Direct AI Assistant": test_direct_ai_assistant(),
        "Protection Analyzer Tool": test_protection_analyzer_tool(),
        "DIE Analysis Tool": test_die_analysis_tool(),
        "AI Orchestrator": test_orchestrator_integration()
    }

    print("\n=== Test Results Summary ===")
    for test_name, passed in results.items():
        status = "PASSED" if passed else "FAILED"
        print(f"{test_name}: {status}")

    total_passed = sum(1 for passed in results.values() if passed)
    print(f"\nTotal: {total_passed}/{len(results)} tests passed")

    return total_passed == len(results)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
