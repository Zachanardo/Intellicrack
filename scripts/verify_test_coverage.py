#!/usr/bin/env python3
"""Automated Test Coverage Verification Script for Intellicrack.

This script verifies that every source file has corresponding tests and tracks
progress toward 100% test coverage.

Usage:
    python scripts/verify_test_coverage.py [--detailed] [--update-manifest]

Copyright (C) 2025 Zachary Flint
"""

import argparse
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple


def find_all_source_files(root_dir: Path) -> Set[str]:
    """Find all Python source files in intellicrack/."""
    source_files = set()

    for py_file in root_dir.rglob("*.py"):
        # Skip __init__.py, __main__.py, and test files
        if py_file.name in ("__init__.py", "__main__.py"):
            continue
        if "test_" in py_file.name or py_file.name.endswith("_test.py"):
            continue

        rel_path = py_file.relative_to(root_dir.parent)
        source_files.add(str(rel_path))

    return source_files


def find_all_test_files(test_dir: Path) -> Dict[str, List[str]]:
    """Find all test files and attempt to map to source files."""
    test_files = defaultdict(list)

    for test_file in test_dir.rglob("test_*.py"):
        test_files[test_file.name].append(str(test_file.relative_to(test_dir.parent)))

    return test_files


def infer_source_from_test(test_filename: str) -> str:
    """Attempt to infer source filename from test filename."""
    # test_vmprotect_detector.py -> vmprotect_detector.py
    # test_frida_integration.py -> frida_*.py (multiple possibilities)
    if test_filename.startswith("test_"):
        return test_filename[5:]  # Remove 'test_' prefix
    return test_filename


def analyze_coverage(source_root: Path, test_root: Path) -> Tuple[Set, Set, Dict]:
    """Analyze test coverage for all source files."""
    source_files = find_all_source_files(source_root)
    test_files = find_all_test_files(test_root)

    # Track coverage
    tested_files = set()
    untested_files = set()
    coverage_map = {}

    for source_file in source_files:
        source_name = Path(source_file).name

        # Look for corresponding test file
        test_name = f"test_{source_name}"

        if test_name in test_files:
            tested_files.add(source_file)
            coverage_map[source_file] = test_files[test_name]
        else:
            # Check if filename appears in any test file name
            partial_match = [tf for tf in test_files if source_name.replace(".py", "") in tf]
            if partial_match:
                tested_files.add(source_file)
                coverage_map[source_file] = [test_files[pm][0] for pm in partial_match]
            else:
                untested_files.add(source_file)

    return tested_files, untested_files, coverage_map


def generate_report(tested: Set, untested: Set, coverage_map: Dict, detailed: bool = False):
    """Generate coverage report."""
    total = len(tested) + len(untested)
    tested_pct = (len(tested) / total * 100) if total > 0 else 0
    untested_pct = (len(untested) / total * 100) if total > 0 else 0

    print("=" * 80)
    print("INTELLICRACK TEST COVERAGE VERIFICATION REPORT")
    print("=" * 80)
    print()
    print(f"Total Source Files: {total}")
    print(f"Files with Tests: {len(tested)} ({tested_pct:.1f}%)")
    print(f"Files without Tests: {len(untested)} ({untested_pct:.1f}%)")
    print()

    if tested_pct >= 100:
        print("✅ STATUS: 100% COVERAGE ACHIEVED!")
    elif tested_pct >= 90:
        print("🟢 STATUS: EXCELLENT (90%+ coverage)")
    elif tested_pct >= 75:
        print("🟡 STATUS: GOOD (75%+ coverage)")
    elif tested_pct >= 50:
        print("🟠 STATUS: MODERATE (50%+ coverage)")
    else:
        print("🔴 STATUS: CRITICAL (< 50% coverage)")

    print()
    print("=" * 80)

    # Group untested by directory
    if untested:
        print("\nUNTESTED FILES BY DIRECTORY:")
        print("=" * 80)

        by_dir = defaultdict(list)
        for f in sorted(untested):
            dir_name = str(Path(f).parent)
            by_dir[dir_name].append(Path(f).name)

        for dir_path in sorted(by_dir.keys()):
            files = by_dir[dir_path]
            print(f"\n{dir_path}/ ({len(files)} untested):")
            for filename in sorted(files)[: 10 if not detailed else None]:
                print(f"  - {filename}")
            if len(files) > 10 and not detailed:
                print(f"  ... and {len(files) - 10} more (use --detailed to see all)")

    if detailed and tested:
        print("\n" + "=" * 80)
        print("TESTED FILES:")
        print("=" * 80)

        by_dir = defaultdict(list)
        for f in sorted(tested):
            dir_name = str(Path(f).parent)
            by_dir[dir_name].append((Path(f).name, coverage_map.get(f, [])))

        for dir_path in sorted(by_dir.keys()):
            files = by_dir[dir_path]
            print(f"\n{dir_path}/ ({len(files)} tested):")
            for filename, test_paths in files[:10]:
                test_info = test_paths[0] if test_paths else "Unknown"
                print(f"  ✅ {filename} -> {test_info}")
            if len(files) > 10:
                print(f"  ... and {len(files) - 10} more")


def main():
    parser = argparse.ArgumentParser(description="Verify test coverage for Intellicrack")
    parser.add_argument("--detailed", action="store_true", help="Show detailed file lists")
    parser.add_argument("--update-manifest", action="store_true", help="Update FILE_MANIFEST.md with current status")
    args = parser.parse_args()

    # Paths
    project_root = Path(__file__).parent.parent
    source_root = project_root / "intellicrack"
    test_root = project_root / "tests"

    # Analyze
    tested, untested, coverage_map = analyze_coverage(source_root, test_root)

    # Report
    generate_report(tested, untested, coverage_map, args.detailed)

    # Update manifest if requested
    if args.update_manifest:
        print("\n" + "=" * 80)
        print("UPDATING MANIFEST...")
        print("=" * 80)
        # TODO: Implement manifest update logic
        print("⚠️  Manifest update not yet implemented")
        print("    Manually update TestingTODO_FILE_MANIFEST.md")

    print()
    return 0 if len(untested) == 0 else 1


if __name__ == "__main__":
    exit(main())
