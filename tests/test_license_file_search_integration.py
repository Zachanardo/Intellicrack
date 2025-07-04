#!/usr/bin/env python3
"""
Test script to demonstrate license file search integration in Intellicrack

This script shows how the search_for_license_files() method from ai_file_tools.py
is integrated into the protection analysis workflow.
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intellicrack.tools.protection_analyzer_tool import ProtectionAnalyzerTool
from intellicrack.ai.ai_file_tools import get_ai_file_tools


def test_protection_analyzer_with_license_search():
    """Test the protection analyzer tool with license file search"""
    print("=" * 60)
    print("Testing Protection Analyzer with License File Search")
    print("=" * 60)
    
    # Get a test binary path (you can change this to any binary you want to test)
    test_binary = r"C:\Program Files\Adobe\Adobe Photoshop 2024\Photoshop.exe"
    
    if not os.path.exists(test_binary):
        print(f"Test binary not found: {test_binary}")
        print("Please update the test_binary path to a valid executable on your system.")
        return
    
    # Create analyzer tool
    analyzer = ProtectionAnalyzerTool()
    
    print(f"\nAnalyzing: {test_binary}")
    print("-" * 60)
    
    # Perform analysis
    results = analyzer.analyze(test_binary, detailed=True)
    
    if results.get("success"):
        # Display protection analysis
        protection = results["protection_analysis"]
        print(f"\nFile Type: {protection['file_type']}")
        print(f"Architecture: {protection['architecture']}")
        print(f"Compiler: {protection['compiler']}")
        print(f"Is Protected: {protection['is_protected']}")
        print(f"Total Detections: {protection['total_detections']}")
        print(f"Total Licensing Schemes: {protection['total_licensing_schemes']}")
        
        # Display detections
        if protection["detections"]:
            print("\nDetections:")
            for det_type, detections in protection["detections"].items():
                print(f"\n  {det_type.upper()}:")
                for det in detections:
                    print(f"    - {det['name']} (v{det.get('version', 'N/A')})")
        
        # Display license files found
        if results.get("license_files_found"):
            license_info = results["license_files_found"]
            files_found = license_info.get("files_found", [])
            
            print(f"\n\nLicense Files Found: {len(files_found)}")
            print("-" * 60)
            
            for file_info in files_found[:10]:  # Show up to 10
                print(f"\n  File: {file_info['name']}")
                print(f"  Path: {file_info['path']}")
                print(f"  Size: {file_info['size_str']}")
                print(f"  Type: {file_info.get('match_type', 'Unknown')}")
                if file_info.get('pattern_matched'):
                    print(f"  Pattern: {file_info['pattern_matched']}")
        
        # Display formatted report
        print("\n\nFormatted Report:")
        print("-" * 60)
        print(analyzer.format_for_display(results))
        
    else:
        print(f"Analysis failed: {results.get('error', 'Unknown error')}")


def test_direct_license_file_search():
    """Test direct license file search functionality"""
    print("\n\n" + "=" * 60)
    print("Testing Direct License File Search")
    print("=" * 60)
    
    # Test directory (Adobe installation directory)
    test_dir = r"C:\Program Files\Adobe\Adobe Photoshop 2024"
    
    if not os.path.exists(test_dir):
        print(f"Test directory not found: {test_dir}")
        print("Using current directory instead...")
        test_dir = os.getcwd()
    
    print(f"\nSearching for license files in: {test_dir}")
    print("-" * 60)
    
    # Get AI file tools
    ai_file_tools = get_ai_file_tools()
    
    # Search for license files
    results = ai_file_tools.search_for_license_files(test_dir)
    
    if results.get("status") == "success":
        files_found = results.get("files_found", [])
        print(f"\nTotal files found: {len(files_found)}")
        
        # Group by match type
        by_type = {}
        for file_info in files_found:
            match_type = file_info.get("match_type", "Unknown")
            if match_type not in by_type:
                by_type[match_type] = []
            by_type[match_type].append(file_info)
        
        # Display grouped results
        for match_type, files in by_type.items():
            print(f"\n{match_type} ({len(files)} files):")
            for file_info in files[:5]:  # Show up to 5 per type
                print(f"  - {file_info['name']} ({file_info['size_str']})")
        
        # Test reading a license file if found
        if files_found:
            print("\n\nReading first license file...")
            print("-" * 60)
            
            first_file = files_found[0]["path"]
            read_result = ai_file_tools.read_file(first_file, "Examine license file content")
            
            if read_result.get("status") == "success":
                content = read_result["content"]
                print(f"\nFile: {first_file}")
                print(f"Size: {read_result['metadata']['size_str']}")
                print(f"First 500 characters:")
                print("-" * 40)
                print(content[:500])
                if len(content) > 500:
                    print("\n... (truncated)")
    else:
        print(f"Search failed: {results.get('error', 'Unknown error')}")


def test_custom_patterns():
    """Test license file search with custom patterns"""
    print("\n\n" + "=" * 60)
    print("Testing License File Search with Custom Patterns")
    print("=" * 60)
    
    test_dir = os.getcwd()
    
    # Define custom patterns for specific licensing systems
    custom_patterns = [
        "*.hasp",
        "hasp_*.xml",
        "sentinel_*.dat",
        "flexlm_*.lic",
        "codemeter_*.wbb"
    ]
    
    print(f"\nSearching with custom patterns in: {test_dir}")
    print(f"Patterns: {custom_patterns}")
    print("-" * 60)
    
    # Get AI file tools
    ai_file_tools = get_ai_file_tools()
    
    # Search with custom patterns
    results = ai_file_tools.search_for_license_files(test_dir, custom_patterns)
    
    if results.get("status") == "success":
        files_found = results.get("files_found", [])
        print(f"\nTotal files found: {len(files_found)}")
        
        for file_info in files_found[:10]:
            print(f"\n  File: {file_info['name']}")
            print(f"  Pattern: {file_info.get('pattern_matched', 'N/A')}")
            print(f"  Size: {file_info['size_str']}")


if __name__ == "__main__":
    # Run all tests
    test_protection_analyzer_with_license_search()
    test_direct_license_file_search()
    test_custom_patterns()
    
    print("\n\nAll tests completed!")