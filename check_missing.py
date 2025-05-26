#!/usr/bin/env python3
"""
Script to comprehensively check which functions from the original list
are still missing from the modular structure.
"""

import os
import subprocess
import sys

def check_function_exists(func_name, search_dir="intellicrack"):
    """Check if a function definition exists in the search directory."""
    try:
        # Use grep to search for function definition
        result = subprocess.run(
            ["grep", "-r", f"def {func_name}", search_dir],
            capture_output=True, text=True, cwd="/mnt/c/Intellicrack/Intellicrack_Project/Intellicrack_Project"
        )
        return result.returncode == 0 and len(result.stdout.strip()) > 0
    except Exception:
        return False

def main():
    # Read the standalone functions file
    functions_file = "/mnt/c/Intellicrack/Intellicrack_Project/Intellicrack_Project/standalone_functions.txt"
    
    missing_functions = []
    total_functions = 0
    
    print("Checking all standalone functions for integration...")
    
    with open(functions_file, 'r') as f:
        for line in f:
            func_name = line.strip()
            if func_name:  # Skip empty lines
                total_functions += 1
                if not check_function_exists(func_name):
                    missing_functions.append(func_name)
                
                # Progress indicator
                if total_functions % 50 == 0:
                    print(f"Checked {total_functions} functions...")
    
    print(f"\n=== RESULTS ===")
    print(f"Total functions checked: {total_functions}")
    print(f"Missing functions: {len(missing_functions)}")
    print(f"Integration rate: {((total_functions - len(missing_functions)) / total_functions * 100):.1f}%")
    
    if missing_functions:
        print(f"\n=== MISSING FUNCTIONS ===")
        for func in missing_functions:
            print(func)
        
        # Write missing functions to a file
        with open("missing_functions.txt", "w") as f:
            for func in missing_functions:
                f.write(func + "\n")
        print(f"\nMissing functions saved to missing_functions.txt")
    else:
        print("\n🎉 ALL FUNCTIONS ARE INTEGRATED! 🎉")

if __name__ == "__main__":
    main()