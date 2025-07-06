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
Test script for directory analysis integration.
Tests the analyze_program_directory() method integration in the main application.
"""

import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from intellicrack.ai.ai_file_tools import get_ai_file_tools

def test_directory_analysis():
    """Test the directory analysis functionality."""
    print("Testing Directory Analysis Integration")
    print("=" * 50)
    
    # Initialize AI file tools
    ai_tools = get_ai_file_tools()
    
    # Test directory (use the project directory itself for testing)
    test_dir = project_root / "focused_licensing_data" / "commercial_adobe"
    
    if test_dir.exists():
        # Find an executable in the test directory
        executables = list(test_dir.glob("*.exe")) + list(test_dir.glob("*.dll"))
        
        if executables:
            test_executable = executables[0]
            print(f"Testing with executable: {test_executable}")
            print(f"Directory: {test_executable.parent}")
            
            # Perform directory analysis
            try:
                results = ai_tools.analyze_program_directory(str(test_executable))
                
                print("\nAnalysis Results:")
                print("-" * 30)
                print(f"Status: {results.get('status', 'Unknown')}")
                print(f"Program: {results.get('program_path', 'N/A')}")
                print(f"Directory: {results.get('program_directory', 'N/A')}")
                
                if results.get('license_files_found'):
                    print(f"\nFound {len(results['license_files_found'])} potential license files:")
                    for file_info in results['license_files_found'][:5]:
                        print(f"  - {file_info['name']} ({file_info['type']})")
                
                if results.get('analysis_summary'):
                    print("\nSummary:")
                    summary = results['analysis_summary']
                    if isinstance(summary, dict):
                        for key, value in summary.items():
                            print(f"  {key}: {value}")
                    else:
                        print(f"  {summary}")
                
            except Exception as e:
                print(f"Error during analysis: {e}")
                import traceback
                traceback.print_exc()
        else:
            print(f"No executables found in {test_dir}")
    else:
        print(f"Test directory not found: {test_dir}")
    
    print("\n" + "=" * 50)
    print("Directory Analysis Integration Test Complete")

if __name__ == "__main__":
    test_directory_analysis()