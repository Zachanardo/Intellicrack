"""Analyze test coverage for Intellicrack."""
import os
from pathlib import Path


source_dir = Path('intellicrack')
source_files = []
for f in source_dir.rglob('*.py'):
    if '__init__' not in f.name and '__pycache__' not in str(f):
        rel_path = str(f).replace('\\', '/')
        source_files.append(rel_path)

test_dir = Path('tests')
test_files = []
for f in test_dir.rglob('*.py'):
    if '__init__' not in f.name and '__pycache__' not in str(f) and 'conftest' not in f.name:
        rel_path = str(f).replace('\\', '/')
        test_files.append(rel_path)


def get_module_name(path):
    """Get the module name from the file path."""
    parts = path.split('/')
    name = parts[-1].replace('.py', '')
    return name


test_coverage = {}
for src in source_files:
    module = get_module_name(src)
    matching_tests = []
    for t in test_files:
        t_module = get_module_name(t)
        if t_module.startswith('test_') and module in t_module:
            matching_tests.append(t)
    test_coverage[src] = matching_tests

no_tests = [src for src, tests in test_coverage.items() if not tests]

print(f'Total source files: {len(source_files)}')
print(f'Total test files: {len(test_files)}')
print(f'Files with NO test coverage: {len(no_tests)}')
print()
print('=== SOURCE FILES WITH NO TEST COVERAGE ===')
for f in sorted(no_tests):
    print(f)
