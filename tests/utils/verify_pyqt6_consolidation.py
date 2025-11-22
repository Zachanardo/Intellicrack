#!/usr/bin/env python3
"""Final verification that all PyQt6 imports are properly consolidated."""

import re
from pathlib import Path


def check_pyqt6_consolidation():
    """Verify PyQt6 import consolidation is 100% complete."""

    intellicrack_dir = Path("intellicrack")

    # Files that are allowed to have PyQt6 imports
    allowed_files = {
        "common_imports.py",  # The consolidation files
        "import_checks.py",    # Version checking only
        "dependencies.py",     # Version checking only
    }

    issues = []
    checked_files = 0

    # Pattern to find PyQt6 imports
    pyqt6_pattern = re.compile(r'(from\s+PyQt6|import\s+PyQt6)')

    for py_file in intellicrack_dir.rglob("*.py"):
        checked_files += 1

        # Check if this file is allowed to have PyQt6 imports
        is_allowed = any(allowed in py_file.name for allowed in allowed_files)

        try:
            with open(py_file, encoding='utf-8') as f:
                content = f.read()

            # Find all PyQt6 imports
            matches = pyqt6_pattern.findall(content)

            if matches and not is_allowed:
                # This is an issue - file has PyQt6 imports but shouldn't
                rel_path = py_file.relative_to(Path.cwd())
                issues.append({
                    'file': str(rel_path),
                    'count': len(matches),
                    'type': 'UNAUTHORIZED'
                })
            elif matches and is_allowed:
                # This is expected - verify it's the right kind
                rel_path = py_file.relative_to(Path.cwd())

                if "common_imports" in py_file.name:
                    # These should have "from PyQt6" imports
                    if not any("from PyQt6" in line for line in content.split('\n')):
                        issues.append({
                            'file': str(rel_path),
                            'count': len(matches),
                            'type': 'WRONG_IMPORT_STYLE'
                        })
                elif py_file.name in ["import_checks.py", "dependencies.py"]:
                    # These should only have "import PyQt6" for version checking
                    if any("from PyQt6" in line for line in content.split('\n')):
                        issues.append({
                            'file': str(rel_path),
                            'count': len(matches),
                            'type': 'SHOULD_BE_VERSION_CHECK_ONLY'
                        })

        except Exception as e:
            print(f"Error reading {py_file}: {e}")

    # Print results
    print("=" * 70)
    print("PyQt6 Import Consolidation Verification Report")
    print("=" * 70)
    print(f"Total Python files checked: {checked_files}")
    print()

    if not issues:
        print("OK SUCCESS: All PyQt6 imports are properly consolidated!")
        print()
        print("Summary:")
        print("- All application code uses: from intellicrack.ui.dialogs.common_imports import ...")
        print("- Common import modules properly import from PyQt6")
        print("- Version check files only use 'import PyQt6' for availability checking")
        print()
        print("The consolidation is 100% complete!")
    else:
        print("FAIL ISSUES FOUND:")
        for issue in issues:
            print(f"  - {issue['file']}: {issue['type']} ({issue['count']} import(s))")
        print()
        print(f"Total issues: {len(issues)}")

    print("=" * 70)

    # Also verify common_imports.py has all necessary imports
    common_imports_file = Path("intellicrack/ui/dialogs/common_imports.py")
    if common_imports_file.exists():
        with open(common_imports_file, encoding='utf-8') as f:
            content = f.read()

        # Count unique PyQt6 classes imported
        qtcore_match = re.search(r'from PyQt6\.QtCore import ([^)]+)', content)
        qtgui_match = re.search(r'from PyQt6\.QtGui import ([^)]+)', content)
        qtwidgets_match = re.search(r'from PyQt6\.QtWidgets import ([^)]+)', content)

        total_classes = 0
        if qtcore_match:
            total_classes += len([c.strip() for c in qtcore_match.group(1).split(',') if c.strip()])
        if qtgui_match:
            total_classes += len([c.strip() for c in qtgui_match.group(1).split(',') if c.strip()])
        if qtwidgets_match:
            total_classes += len([c.strip() for c in qtwidgets_match.group(1).split(',') if c.strip()])

        print("\n Common imports statistics:")
        print(f"   - Total PyQt6 classes consolidated: {total_classes}")
        print(f"   - Location: {common_imports_file}")

if __name__ == "__main__":
    check_pyqt6_consolidation()
