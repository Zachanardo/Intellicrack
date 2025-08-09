#!/usr/bin/env python3
"""Check for licensing headers in all Python files."""

import os
from pathlib import Path
import json

def check_file_for_header(filepath):
    """Check if a Python file has a licensing header."""
    try:
        # Normalize the path to handle Windows paths properly
        filepath = Path(filepath).resolve()
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Check for common license indicators
        license_indicators = [
            'Copyright',
            'LICENSE',
            'License',
            'GPL',
            'MIT',
            'BSD',
            'Apache',
            'This file is part of',
            '# Intellicrack -',
            'SPDX-License-Identifier'
        ]
        
        # Check first 20 lines for license header
        lines = content.split('\n')[:20]
        header_text = '\n'.join(lines).lower()
        
        has_header = any(indicator.lower() in header_text for indicator in license_indicators)
        
        return {
            'path': str(filepath),
            'has_header': has_header,
            'first_lines': lines[:5] if not has_header else []
        }
    except Exception as e:
        # Try to provide more detail about the error
        import traceback
        return {
            'path': str(filepath),
            'error': str(e),
            'error_type': type(e).__name__,
            'traceback': traceback.format_exc()
        }

def scan_directory(root_dir):
    """Scan all Python files in directory."""
    results = {
        'with_header': [],
        'without_header': [],
        'errors': []
    }
    
    intellicrack_dir = Path(root_dir) / 'intellicrack'
    
    # Get all Python files
    python_files = list(intellicrack_dir.rglob('*.py'))
    
    print(f"Found {len(python_files)} Python files to check...")
    
    for filepath in python_files:
        # Skip __pycache__ directories
        if '__pycache__' in str(filepath):
            continue
            
        result = check_file_for_header(filepath)
        
        if 'error' in result:
            results['errors'].append(result)
        elif result['has_header']:
            results['with_header'].append(result['path'])
        else:
            results['without_header'].append(result)
    
    return results

def main():
    """Main function."""
    root_dir = r'C:\Intellicrack'
    
    print("Scanning for licensing headers...")
    results = scan_directory(root_dir)
    
    # Print summary
    print(f"\n=== LICENSING HEADER CHECK RESULTS ===")
    print(f"Files WITH licensing header: {len(results['with_header'])}")
    print(f"Files WITHOUT licensing header: {len(results['without_header'])}")
    print(f"Files with errors: {len(results['errors'])}")
    
    if results['without_header']:
        print(f"\n=== FILES MISSING LICENSING HEADERS ({len(results['without_header'])}) ===")
        for file_info in results['without_header']:
            # Get relative path for cleaner output
            rel_path = file_info['path'].replace(root_dir + '\\', '')
            print(f"  - {rel_path}")
    
    # Save detailed results
    output_file = os.path.join(root_dir, 'licensing_header_report.json')
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nDetailed report saved to: {output_file}")
    
    # Create a simple text report
    text_report = os.path.join(root_dir, 'files_missing_headers.txt')
    with open(text_report, 'w') as f:
        f.write("FILES MISSING LICENSING HEADERS\n")
        f.write("=" * 50 + "\n\n")
        for file_info in results['without_header']:
            rel_path = file_info['path'].replace(root_dir + '\\', '')
            f.write(f"{rel_path}\n")
    
    print(f"Simple list saved to: {text_report}")
    
    return results

if __name__ == '__main__':
    main()