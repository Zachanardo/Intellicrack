#!/usr/bin/env python3
"""
Fix indentation issues caused by the previous fix script.
"""

import re
from pathlib import Path


def fix_indentation_in_file(filepath: Path):
    """Fix indentation issues in a file."""
    content = filepath.read_text()
    lines = content.split('\n')
    fixed_lines = []
    skip_next = False

    for i, line in enumerate(lines):
        if skip_next:
            skip_next = False
            continue

        fixed_lines.append(line)

        # Check if this is an except clause followed by logger.debug with wrong indentation
        if 'except Exception as e:' in line and i + 1 < len(lines):
            next_line = lines[i + 1]
            if 'logger.debug' in next_line:
                # Count the indentation of the except line
                except_indent = len(line) - len(line.lstrip())
                # The logger.debug should have 4 more spaces
                expected_indent = except_indent + 4

                # Check if next line has wrong indentation
                actual_indent = len(next_line) - len(next_line.lstrip())
                if actual_indent < expected_indent:
                    # Fix the indentation
                    fixed_next_line = ' ' * expected_indent + next_line.lstrip()
                    fixed_lines.append(fixed_next_line)
                    skip_next = True
                    print(f"  Fixed indentation at line {i + 2}")
                else:
                    fixed_lines.append(next_line)
                    skip_next = True
            else:
                # No logger.debug, keep next line as is
                pass

    # Write back
    fixed_content = '\n'.join(fixed_lines)
    if fixed_content != content:
        filepath.write_text(fixed_content)
        return True
    return False


def fix_all_files():
    """Fix all Phase 1 files."""
    files = [
        Path(r"C:\Intellicrack\tests\validation_system\environment_validator.py"),
        Path(r"C:\Intellicrack\tests\validation_system\multi_environment_tester.py"),
        Path(r"C:\Intellicrack\tests\validation_system\anti_detection_verifier.py"),
        Path(r"C:\Intellicrack\tests\validation_system\fingerprint_randomizer.py"),
        Path(r"C:\Intellicrack\tests\validation_system\certified_ground_truth_profile.py")
    ]

    for filepath in files:
        if filepath.exists():
            print(f"Checking {filepath.name}...")
            if fix_indentation_in_file(filepath):
                print(f"  Fixed indentation issues in {filepath.name}")

            # Also add missing imports
            content = filepath.read_text()

            # Add logging import if logger is used but not imported
            if 'logger.' in content and 'import logging' not in content:
                # Add logging import after other imports
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if line.startswith('import ') or line.startswith('from '):
                        continue
                    else:
                        # Found the end of imports, insert logging
                        lines.insert(i, 'import logging')
                        lines.insert(i + 1, '')
                        lines.insert(i + 2, 'logger = logging.getLogger(__name__)')
                        print(f"  Added logging import to {filepath.name}")
                        break

                filepath.write_text('\n'.join(lines))

            # Remove unused random import if secrets is imported
            if 'import secrets' in content and 'import random' in content:
                # Check if random is actually used
                if not re.search(r'\brandom\.\w+', content):
                    content = content.replace('import random\n', '')
                    filepath.write_text(content)
                    print(f"  Removed unused random import from {filepath.name}")


def main():
    """Run fixes."""
    print("=== Fixing Indentation and Import Issues ===\n")
    fix_all_files()
    print("\n[+] Fixes completed")


if __name__ == "__main__":
    main()
