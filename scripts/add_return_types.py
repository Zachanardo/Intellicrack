#!/usr/bin/env python3
"""
Batch script to add -> None return type annotations to test methods.
This fixes the most common mypy --strict error: [no-untyped-def]
"""
import re
import sys
from pathlib import Path


def add_return_types(file_path: Path) -> int:
    """Add -> None to functions missing return type annotations.

    Args:
        file_path: Path to the Python file to process.

    Returns:
        Number of fixes applied.
    """
    content = file_path.read_text(encoding='utf-8')
    lines = content.split('\n')

    fixes = 0
    new_lines: list[str] = []

    # Pattern for function def that needs -> None
    # Matches: def func_name(args):
    # But NOT: def func_name(args) -> something:
    def_pattern = re.compile(r'^(\s*)(async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*:\s*$')

    # Pattern to detect if it already has a return type
    has_return_pattern = re.compile(r'\)\s*->\s*\S+\s*:')

    # Functions that should return None
    none_return_funcs = {
        'setup_method', 'teardown_method', 'setup_class', 'teardown_class',
        'setUp', 'tearDown', 'setUpClass', 'tearDownClass',
        '__init__', '__del__', '__enter__', '__setitem__', '__delitem__',
        'validate', 'configure', 'run', 'execute', 'process',
    }

    # Common helper prefixes that usually return None
    none_return_prefixes = ('test_', '_setup', '_teardown', '_init', '_configure',
                            '_validate', '_run', '_execute', '_process',
                            '_create_', '_generate_', '_write_', '_save_',
                            '_build_', '_do_', '_perform_', '_handle_')

    i = 0
    while i < len(lines):
        line = lines[i]

        # Check if it's a def line
        match = def_pattern.match(line)
        if match:
            indent = match.group(1)
            async_kw = match.group(2) or ''
            func_name = match.group(3)
            params = match.group(4)

            # Skip if it already has a return type (multiline might)
            if not has_return_pattern.search(line):
                # Check if it should return None
                should_add_none = (
                    func_name in none_return_funcs or
                    func_name.startswith(none_return_prefixes)
                )

                if should_add_none:
                    # Add -> None
                    new_line = f'{indent}{async_kw}def {func_name}({params}) -> None:'
                    new_lines.append(new_line)
                    fixes += 1
                    i += 1
                    continue

        new_lines.append(line)
        i += 1

    if fixes > 0:
        file_path.write_text('\n'.join(new_lines), encoding='utf-8')
        print(f"  Fixed {fixes} functions in {file_path.name}")

    return fixes


def process_directory(dir_path: Path) -> int:
    """Process all Python files in directory recursively.

    Args:
        dir_path: Directory to process.

    Returns:
        Total fixes applied.
    """
    total_fixes = 0

    for py_file in dir_path.rglob('*.py'):
        if '__pycache__' in str(py_file):
            continue
        try:
            fixes = add_return_types(py_file)
            total_fixes += fixes
        except Exception as e:
            print(f"  Error processing {py_file}: {e}")

    return total_fixes


def main() -> None:
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python add_return_types.py <path>")
        sys.exit(1)

    path = Path(sys.argv[1])

    if path.is_file():
        fixes = add_return_types(path)
    elif path.is_dir():
        fixes = process_directory(path)
    else:
        print(f"Path not found: {path}")
        sys.exit(1)

    print(f"\nTotal fixes applied: {fixes}")


if __name__ == '__main__':
    main()
