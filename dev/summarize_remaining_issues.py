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

"""Summarize remaining issues from error detection."""

import re
from collections import defaultdict


def main():
    """Analyze and summarize remaining issues."""
    with open('intellicrack_errors.txt', 'r') as f:
        content = f.read()

    # Extract issue counts
    issue_pattern = r'### (\w+) \((\d+) issues\) ###'
    issues = {}
    for match in re.finditer(issue_pattern, content):
        issue_type = match.group(1)
        count = int(match.group(2))
        issues[issue_type] = count

    print("="*60)
    print("REMAINING ISSUES SUMMARY")
    print("="*60)

    # Categorize issues
    false_positives = {
        'FILE_NOT_CLOSED': 'Files have proper cleanup in __del__ or close methods',
        'GLOBAL_USAGE': 'All have pylint disable comments',
        'RELATIVE_IMPORT': 'Best practice within packages',
        'STAR_IMPORT': 'Mostly in __init__.py files for re-export',
        'TODO_COMMENT': 'Most are false positives (license format strings with X characters)'
    }

    actual_issues = {
        'PICKLE_USAGE': 'Security concern - should use safer alternatives',
        'USER_INPUT': 'Should validate/sanitize user inputs',
        'HIGH_COMPLEXITY': 'Functions should be refactored',
        'LARGE_FILE': 'Files should be split for maintainability',
        'MISSING_DOCSTRING': 'Functions need documentation'
    }

    print("\nFALSE POSITIVES OR ACCEPTABLE:")
    total_false = 0
    for issue_type, reason in false_positives.items():
        if issue_type in issues:
            count = issues[issue_type]
            total_false += count
            print(f"  {issue_type}: {count} - {reason}")

    print(f"\nTotal false positives: {total_false}")

    print("\nACTUAL ISSUES TO ADDRESS:")
    total_actual = 0
    for issue_type, reason in actual_issues.items():
        if issue_type in issues:
            count = issues[issue_type]
            total_actual += count
            print(f"  {issue_type}: {count} - {reason}")

    print(f"\nTotal actual issues: {total_actual}")

    # Priority recommendations
    print("\nPRIORITY RECOMMENDATIONS:")
    print("1. PICKLE_USAGE (4) - Security risk, quick to fix")
    print("2. USER_INPUT (14) - Security risk, important for safety")
    print("3. MISSING_DOCSTRING (41) - Quick wins for documentation")
    print("4. HIGH_COMPLEXITY (199) - Refactor gradually over time")
    print("5. LARGE_FILE (18) - Major refactoring, lower priority")

    print("\nOVERALL:")
    print(f"Total reported issues: {sum(issues.values())}")
    print(
        f"False positives: {total_false} ({total_false/sum(issues.values())*100:.1f}%)")
    print(
        f"Actual issues: {total_actual} ({total_actual/sum(issues.values())*100:.1f}%)")


if __name__ == '__main__':
    main()
