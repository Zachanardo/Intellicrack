#!/usr/bin/env python3
"""Check linting progress by comparing before and after."""

import subprocess
import re
from collections import Counter

def run_pylint():
    """Run pylint and get output."""
    try:
        result = subprocess.run(
            ['python3', '-m', 'pylint', 'intellicrack'],
            capture_output=True,
            text=True
        )
        return result.stdout + result.stderr
    except Exception as e:
        print(f"Error running pylint: {e}")
        return ""

def parse_pylint_output(output):
    """Parse pylint output and count issues by type."""
    issues = Counter()
    
    # Pattern to match pylint messages
    pattern = r'([A-Z]\d{4}): (.+?) \((.+?)\)'
    
    for line in output.split('\n'):
        match = re.search(pattern, line)
        if match:
            code = match.group(1)
            issues[code] += 1
    
    return issues

def main():
    """Check linting progress across the Intellicrack codebase."""
    print("Running pylint to check current status...")
    output = run_pylint()
    issues = parse_pylint_output(output)
    
    # Categories of issues
    errors = {k: v for k, v in issues.items() if k.startswith('E')}
    warnings = {k: v for k, v in issues.items() if k.startswith('W')}
    refactors = {k: v for k, v in issues.items() if k.startswith('R')}
    conventions = {k: v for k, v in issues.items() if k.startswith('C')}
    
    print("\n=== LINTING SUMMARY ===")
    print(f"Total issues: {sum(issues.values())}")
    print(f"\nErrors (E): {sum(errors.values())}")
    print(f"Warnings (W): {sum(warnings.values())}")
    print(f"Refactor suggestions (R): {sum(refactors.values())}")
    print(f"Convention violations (C): {sum(conventions.values())}")
    
    # Show specific counts for issues we've been fixing
    print("\n=== SPECIFIC ISSUES FIXED ===")
    fixed_codes = ['E1101', 'E0401', 'W1203', 'W0613', 'W0621']
    for code in fixed_codes:
        count = issues.get(code, 0)
        print(f"{code}: {count} remaining")
    
    # Show top remaining issues
    print("\n=== TOP REMAINING ISSUES ===")
    for code, count in sorted(issues.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{code}: {count}")

if __name__ == "__main__":
    main()