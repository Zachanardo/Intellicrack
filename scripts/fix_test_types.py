#!/usr/bin/env python3
"""
Comprehensive script to fix mypy type annotation issues in test files.
Handles fixtures, test methods, and helper functions.
"""
import re
import sys
from pathlib import Path


def fix_test_types(file_path: Path) -> int:
    """Fix type annotations in test file.

    Args:
        file_path: Path to the Python file to process.

    Returns:
        Number of fixes applied.
    """
    content = file_path.read_text(encoding='utf-8')
    original_content = content
    fixes = 0

    # Pattern for fixtures without return type
    # @pytest.fixture
    # def fixture_name(self) or def fixture_name():
    fixture_pattern = re.compile(
        r'(@pytest\.fixture(?:\([^)]*\))?)\n(\s*)(async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*:\s*$',
        re.MULTILINE
    )

    def fix_fixture(match: re.Match[str]) -> str:
        nonlocal fixes
        decorator = match.group(1)
        indent = match.group(2)
        async_kw = match.group(3) or ''
        func_name = match.group(4)
        params = match.group(5)

        # Check if return type already exists
        if '->' in params or match.group(0).count('->') > 0:
            return match.group(0)

        fixes += 1
        # Add Any type annotation for Generator fixtures
        return f'{decorator}\n{indent}{async_kw}def {func_name}({params}) -> Any:'

    content = fixture_pattern.sub(fix_fixture, content)

    # Pattern for test methods with untyped fixture parameters
    # def test_something(self, fixture1, fixture2):
    test_method_pattern = re.compile(
        r'^(\s*)(async\s+)?def\s+(test_\w+)\s*\(self,\s*([^)]+)\)\s*(?:->.*?)?\s*:',
        re.MULTILINE
    )

    def fix_test_params(match: re.Match[str]) -> str:
        nonlocal fixes
        indent = match.group(1)
        async_kw = match.group(2) or ''
        func_name = match.group(3)
        params_str = match.group(4)

        # Parse and type parameters
        params = [p.strip() for p in params_str.split(',')]
        typed_params: list[str] = []
        changed = False

        for param in params:
            if ':' not in param and '=' not in param and param.strip():
                # Untyped parameter - add Any type
                typed_params.append(f'{param.strip()}: Any')
                changed = True
            elif '=' in param and ':' not in param:
                # Has default but no type
                parts = param.split('=', 1)
                typed_params.append(f'{parts[0].strip()}: Any = {parts[1].strip()}')
                changed = True
            else:
                typed_params.append(param)

        if changed:
            fixes += 1
            new_params = ', '.join(typed_params)
            return f'{indent}{async_kw}def {func_name}(self, {new_params}) -> None:'
        return match.group(0)

    content = test_method_pattern.sub(fix_test_params, content)

    # Pattern for helper functions without return types that should return None
    helper_pattern = re.compile(
        r'^(\s*)(async\s+)?def\s+(_[a-z]\w*|setup\w*|teardown\w*)\s*\(([^)]*)\)\s*:(?!\s*$)',
        re.MULTILINE
    )

    def fix_helper(match: re.Match[str]) -> str:
        nonlocal fixes
        indent = match.group(1)
        async_kw = match.group(2) or ''
        func_name = match.group(3)
        params = match.group(4)

        # Skip if already has return type
        original_line = match.group(0)
        if '->' in original_line:
            return original_line

        fixes += 1
        return f'{indent}{async_kw}def {func_name}({params}) -> None:'

    content = helper_pattern.sub(fix_helper, content)

    # Ensure Any is imported if we added Any types
    if 'Any' in content and fixes > 0:
        # Check if Any is already imported
        if not re.search(r'from typing import.*\bAny\b', content) and \
           not re.search(r'from typing_extensions import.*\bAny\b', content):
            # Add Any import
            if 'from typing import' in content:
                content = re.sub(
                    r'(from typing import )([^\n]+)',
                    r'\1Any, \2',
                    content,
                    count=1
                )
            else:
                # Add import at top after other imports
                import_match = re.search(r'^(import|from)\s+', content, re.MULTILINE)
                if import_match:
                    insert_pos = import_match.start()
                    content = content[:insert_pos] + 'from typing import Any\n' + content[insert_pos:]
                else:
                    content = 'from typing import Any\n\n' + content

    if content != original_content:
        file_path.write_text(content, encoding='utf-8')
        print(f"  Fixed {fixes} issues in {file_path.name}")

    return fixes


def process_directory(dir_path: Path) -> int:
    """Process all Python files in directory recursively.

    Args:
        dir_path: Directory to process.

    Returns:
        Total fixes applied.
    """
    total_fixes = 0

    for py_file in dir_path.rglob('test_*.py'):
        if '__pycache__' in str(py_file):
            continue
        try:
            fixes = fix_test_types(py_file)
            total_fixes += fixes
        except Exception as e:
            print(f"  Error processing {py_file}: {e}")

    return total_fixes


def main() -> None:
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python fix_test_types.py <path>")
        sys.exit(1)

    path = Path(sys.argv[1])

    if path.is_file():
        fixes = fix_test_types(path)
    elif path.is_dir():
        fixes = process_directory(path)
    else:
        print(f"Path not found: {path}")
        sys.exit(1)

    print(f"\nTotal fixes applied: {fixes}")


if __name__ == '__main__':
    main()
