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
Test script to demonstrate license pattern analysis integration
"""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from intellicrack.tools.protection_analyzer_tool import ProtectionAnalyzerTool


def test_license_pattern_analysis():
    """Test the license pattern analysis functionality"""
    print("=" * 60)
    print("License Pattern Analysis Integration Test")
    print("=" * 60)

    # Initialize the analyzer
    analyzer = ProtectionAnalyzerTool()

    # Test file path (you can change this to test with a real binary)
    test_file = "/path/to/test/binary.exe"  # Replace with actual binary path

    # Check if test file exists
    if not os.path.exists(test_file):
        print(f"\nTest file not found: {test_file}")
        print("Please update the test_file path to point to a real binary file.")
        print("\nDemonstrating with mock analysis...")

        # For demonstration, let's show what the output would look like
        mock_result = {
            "success": True,
            "file_info": {
                "name": "demo_binary.exe",
                "size_human": "2.5 MB"
            },
            "protection_analysis": {
                "total_licensing_schemes": 2,
                "detections": {
                    "LICENSE": [
                        {"name": "FlexLM License Manager", "confidence": 95},
                        {"name": "Custom Serial Validation", "confidence": 80}
                    ]
                }
            },
            "license_pattern_analysis": {
                "analysis_type": "license_pattern_analysis",
                "confidence": 0.85,
                "patterns_found": [
                    "License validation failed",
                    "Invalid serial number",
                    "Trial period expired"
                ],
                "license_type": "serial_based",
                "bypass_suggestions": [
                    "Identified serial_based licensing",
                    "Consider runtime analysis of license checks",
                    "Look for license validation functions"
                ],
                "protection_context": {
                    "has_network_apis": True,
                    "has_crypto_apis": True,
                    "has_registry_apis": True,
                    "likely_license_files": [
                        "license.dat",
                        "license.lic",
                        "license.key"
                    ]
                }
            }
        }

        print_analysis_results(mock_result)
        return

    # Perform actual analysis
    print(f"\nAnalyzing: {test_file}")
    print("This may take a moment...")

    result = analyzer.analyze(test_file, detailed=True)

    if result.get("success"):
        print_analysis_results(result)
    else:
        print(f"\nAnalysis failed: {result.get('error', 'Unknown error')}")


def print_analysis_results(result):
    """Pretty print analysis results"""
    print("\n" + "-" * 60)
    print("ANALYSIS RESULTS")
    print("-" * 60)

    # File info
    file_info = result.get("file_info", {})
    print(f"\nFile: {file_info.get('name', 'Unknown')}")
    print(f"Size: {file_info.get('size_human', 'Unknown')}")

    # Protection analysis
    protection = result.get("protection_analysis", {})
    print(f"\nLicensing Schemes Detected: {protection.get('total_licensing_schemes', 0)}")

    if protection.get("detections", {}).get("LICENSE"):
        print("\nLicense Protections:")
        for lic in protection["detections"]["LICENSE"]:
            print(f"  - {lic['name']} (Confidence: {lic['confidence']}%)")

    # License pattern analysis
    license_analysis = result.get("license_pattern_analysis", {})
    if license_analysis and not license_analysis.get("error"):
        print("\n" + "-" * 40)
        print("LICENSE PATTERN ANALYSIS")
        print("-" * 40)

        print(f"\nLicense Type: {license_analysis.get('license_type', 'Unknown')}")
        print(f"Confidence: {license_analysis.get('confidence', 0) * 100:.0f}%")

        patterns = license_analysis.get("patterns_found", [])
        if patterns:
            print(f"\nPatterns Found ({len(patterns)}):")
            for pattern in patterns[:5]:  # Show first 5
                print(f"  - {pattern}")

        suggestions = license_analysis.get("bypass_suggestions", [])
        if suggestions:
            print("\nBypass Suggestions:")
            for suggestion in suggestions:
                print(f"  - {suggestion}")

        context = license_analysis.get("protection_context", {})
        if context:
            print("\nProtection Context:")
            print(f"  - Network APIs: {'Yes' if context.get('has_network_apis') else 'No'}")
            print(f"  - Crypto APIs: {'Yes' if context.get('has_crypto_apis') else 'No'}")
            print(f"  - Registry APIs: {'Yes' if context.get('has_registry_apis') else 'No'}")

            license_files = context.get("likely_license_files", [])
            if license_files:
                print("  - Likely License Files:")
                for file in license_files[:3]:
                    print(f"    * {file}")

    # AI Complex Analysis
    ai_analysis = result.get("ai_complex_analysis", {})
    if ai_analysis and not ai_analysis.get("error"):
        print("\n" + "-" * 40)
        print("AI-ENHANCED ANALYSIS")
        print("-" * 40)

        print(f"\nConfidence: {ai_analysis.get('confidence', 0) * 100:.0f}%")

        findings = ai_analysis.get("findings", [])
        if findings:
            print("\nKey Findings:")
            for finding in findings[:3]:
                print(f"  - {finding}")

        recommendations = ai_analysis.get("recommendations", [])
        if recommendations:
            print("\nAI Recommendations:")
            for rec in recommendations[:3]:
                print(f"  - {rec}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_license_pattern_analysis()
