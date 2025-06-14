#!/usr/bin/env python3
"""Verify that logging format fixes didn't introduce issues."""

import re
import os

def check_logging_format(filepath):
    """Check for logging format/argument mismatches."""
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    issues = []
    for i, line in enumerate(lines, 1):
        # Match logging calls with % formatting
        patterns = [
            r'logger\.[a-z]+\("([^"]*)"(?:, (.+?))?\)',
            r'self\.logger\.[a-z]+\("([^"]*)"(?:, (.+?))?\)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                format_str = match.group(1)
                args_str = match.group(2) if match.group(2) else ""
                
                # Count format specifiers
                format_count = (
                    format_str.count('%s') + 
                    format_str.count('%d') + 
                    format_str.count('%f') +
                    format_str.count('%r')
                )
                
                # If no format specifiers, should have no args
                if format_count == 0 and args_str:
                    issues.append(f'{filepath}:{i} - No format specifiers but has args')
                elif format_count > 0 and not args_str:
                    issues.append(f'{filepath}:{i} - Has {format_count} format specifiers but no args')
    
    return issues

def main():
    """Verify logging fixes across the codebase."""
    all_issues = []
    file_count = 0
    
    for root, dirs, files in os.walk('/mnt/c/Intellicrack/intellicrack'):
        if '__pycache__' in root:
            continue
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                file_count += 1
                issues = check_logging_format(filepath)
                all_issues.extend(issues)
    
    print(f"Checked {file_count} Python files")
    
    if all_issues:
        print(f'\nFound {len(all_issues)} potential issues:')
        for issue in all_issues[:20]:  # Show first 20
            print(issue)
        if len(all_issues) > 20:
            print(f"... and {len(all_issues) - 20} more")
    else:
        print('No format/argument mismatches found!')

if __name__ == "__main__":
    main()