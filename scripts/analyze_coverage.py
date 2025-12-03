#!/usr/bin/env python3
"""Analyze test coverage gaps in Intellicrack project."""
import os
import re
from collections import defaultdict
from pathlib import Path


def get_source_modules():
    """Get all source module names and paths."""
    modules = {}
    for root, dirs, files in os.walk('intellicrack'):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for f in files:
            if f.endswith('.py') and f != '__init__.py':
                module_name = f.replace('.py', '')
                full_path = os.path.join(root, f)
                modules[module_name] = full_path
    return modules


def get_test_targets():
    """Get all modules that have corresponding test files."""
    targets = defaultdict(list)
    for root, dirs, files in os.walk('tests'):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for f in files:
            if f.startswith('test_') and f.endswith('.py'):
                target = f.replace('test_', '').replace('.py', '')
                base_target = re.sub(r'_(comprehensive|advanced|gaps|validation|real|simple|basic|debug|integration)$', '', target)
                test_path = os.path.join(root, f)
                targets[base_target].append(test_path)
    return targets


def analyze_coverage():
    """Analyze test coverage and identify gaps."""
    source_modules = get_source_modules()
    test_targets = get_test_targets()

    covered = set(test_targets.keys())
    all_sources = set(source_modules.keys())
    uncovered = all_sources - covered

    print("=" * 80)
    print("INTELLICRACK TEST COVERAGE ANALYSIS")
    print("=" * 80)
    print(f"\nTotal source modules: {len(all_sources)}")
    print(f"Modules with tests: {len(covered)}")
    print(f"Modules WITHOUT tests: {len(uncovered)}")
    print(f"Coverage rate: {len(covered) / len(all_sources) * 100:.1f}%")

    priority_dirs = [
        'intellicrack/core/',
        'intellicrack/protection/',
        'intellicrack/plugins/',
        'intellicrack/ai/',
        'intellicrack/hexview/',
        'intellicrack/dashboard/',
        'intellicrack/ml/',
    ]

    print("\n" + "=" * 80)
    print("CRITICAL MODULES WITHOUT TESTS (by directory)")
    print("=" * 80)

    for priority_dir in priority_dirs:
        print(f"\n### {priority_dir} ###")
        count = 0
        for module_name in sorted(uncovered):
            module_path = source_modules.get(module_name, '')
            if priority_dir in module_path.replace('\\', '/'):
                print(f"  {module_path}")
                count += 1
        if count == 0:
            print("  (all modules have tests)")
        else:
            print(f"  Total: {count} uncovered")

    print("\n" + "=" * 80)
    print("TOP 50 CRITICAL UNCOVERED MODULES")
    print("=" * 80)

    critical_keywords = [
        'license', 'keygen', 'bypass', 'crack', 'patch', 'protection',
        'serial', 'activation', 'validation', 'exploit', 'frida', 'hook',
        'emulator', 'dongle', 'hardware', 'crypto', 'decrypt', 'inject'
    ]

    critical_uncovered = []
    for module_name in uncovered:
        module_path = source_modules.get(module_name, '')
        score = sum(1 for kw in critical_keywords if kw in module_name.lower() or kw in module_path.lower())
        if score > 0:
            critical_uncovered.append((score, module_name, module_path))

    critical_uncovered.sort(reverse=True)

    for i, (score, _name, path) in enumerate(critical_uncovered[:50]):
        print(f"{i + 1:2}. [score={score}] {path}")

    print("\n" + "=" * 80)
    print("ALL UNCOVERED MODULES BY PATH")
    print("=" * 80)

    uncovered_list = [(source_modules[m], m) for m in uncovered]
    uncovered_list.sort()

    for path, _name in uncovered_list:
        print(path)


if __name__ == '__main__':
    os.chdir(Path(__file__).parent.parent)
    analyze_coverage()
