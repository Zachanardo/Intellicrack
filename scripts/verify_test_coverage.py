#!/usr/bin/env python3
"""Automated Test Coverage Verification Script for Intellicrack.

This script verifies that every source file has corresponding tests and tracks
progress toward 100% test coverage.

Usage:
    python scripts/verify_test_coverage.py [--detailed] [--update-manifest]

Copyright (C) 2025 Zachary Flint
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Mapping, Set

COVERAGE_THRESHOLD_COMPLETE: int = 100
COVERAGE_THRESHOLD_EXCELLENT: int = 90
COVERAGE_THRESHOLD_GOOD: int = 75
COVERAGE_THRESHOLD_MODERATE: int = 50
DEFAULT_DISPLAY_LIMIT: int = 10


def find_all_source_files(root_dir: Path) -> set[str]:
    """Find all Python source files in intellicrack/."""
    source_files: set[str] = set()

    for py_file in root_dir.rglob("*.py"):
        if py_file.name in {"__init__.py", "__main__.py"}:
            continue
        if "test_" in py_file.name or py_file.name.endswith("_test.py"):
            continue

        rel_path = py_file.relative_to(root_dir.parent)
        source_files.add(str(rel_path))

    return source_files


def find_all_test_files(test_dir: Path) -> dict[str, list[str]]:
    """Find all test files and attempt to map to source files."""
    test_files: dict[str, list[str]] = defaultdict(list)

    for test_file in test_dir.rglob("test_*.py"):
        test_files[test_file.name].append(str(test_file.relative_to(test_dir.parent)))

    return test_files


def infer_source_from_test(test_filename: str) -> str:
    """Attempt to infer source filename from test filename."""
    if test_filename.startswith("test_"):
        return test_filename[5:]
    return test_filename


def analyze_coverage(
    source_root: Path, test_root: Path
) -> tuple[set[str], set[str], dict[str, list[str]]]:
    """Analyze test coverage for all source files."""
    source_files = find_all_source_files(source_root)
    test_files = find_all_test_files(test_root)

    tested_files: set[str] = set()
    untested_files: set[str] = set()
    coverage_map: dict[str, list[str]] = {}

    for source_file in source_files:
        source_name = Path(source_file).name
        test_name = f"test_{source_name}"

        if test_name in test_files:
            tested_files.add(source_file)
            coverage_map[source_file] = test_files[test_name]
        else:
            partial_match = [
                tf for tf in test_files if source_name.replace(".py", "") in tf
            ]
            if partial_match:
                tested_files.add(source_file)
                coverage_map[source_file] = [test_files[pm][0] for pm in partial_match]
            else:
                untested_files.add(source_file)

    return tested_files, untested_files, coverage_map


def generate_report(
    tested: set[str],
    untested: set[str],
    coverage_map: dict[str, list[str]],
    *,
    detailed: bool = False,
) -> None:
    """Generate coverage report."""
    total = len(tested) + len(untested)
    tested_pct = (len(tested) / total * COVERAGE_THRESHOLD_COMPLETE) if total > 0 else 0
    untested_pct = (len(untested) / total * COVERAGE_THRESHOLD_COMPLETE) if total > 0 else 0

    print("=" * 80)
    print("INTELLICRACK TEST COVERAGE VERIFICATION REPORT")
    print("=" * 80)
    print()
    print(f"Total Source Files: {total}")
    print(f"Files with Tests: {len(tested)} ({tested_pct:.1f}%)")
    print(f"Files without Tests: {len(untested)} ({untested_pct:.1f}%)")
    print()

    if tested_pct >= COVERAGE_THRESHOLD_COMPLETE:
        print("STATUS: 100% COVERAGE ACHIEVED!")
    elif tested_pct >= COVERAGE_THRESHOLD_EXCELLENT:
        print("STATUS: EXCELLENT (90%+ coverage)")
    elif tested_pct >= COVERAGE_THRESHOLD_GOOD:
        print("STATUS: GOOD (75%+ coverage)")
    elif tested_pct >= COVERAGE_THRESHOLD_MODERATE:
        print("STATUS: MODERATE (50%+ coverage)")
    else:
        print("STATUS: CRITICAL (< 50% coverage)")

    print()
    print("=" * 80)

    if untested:
        print("\nUNTESTED FILES BY DIRECTORY:")
        print("=" * 80)

        by_dir: dict[str, list[str]] = defaultdict(list)
        for f in sorted(untested):
            dir_name = str(Path(f).parent)
            by_dir[dir_name].append(Path(f).name)

        for dir_path in sorted(by_dir):
            files = by_dir[dir_path]
            print(f"\n{dir_path}/ ({len(files)} untested):")
            display_files = sorted(files) if detailed else sorted(files)[:DEFAULT_DISPLAY_LIMIT]
            for filename in display_files:
                print(f"  - {filename}")
            if len(files) > DEFAULT_DISPLAY_LIMIT and not detailed:
                remaining = len(files) - DEFAULT_DISPLAY_LIMIT
                print(f"  ... and {remaining} more (use --detailed to see all)")

    if detailed and tested:
        print("\n" + "=" * 80)
        print("TESTED FILES:")
        print("=" * 80)

        tested_by_dir: dict[str, list[tuple[str, list[str]]]] = defaultdict(list)
        for f in sorted(tested):
            dir_name = str(Path(f).parent)
            tested_by_dir[dir_name].append((Path(f).name, coverage_map.get(f, [])))

        for dir_path in sorted(tested_by_dir):
            tested_files: list[tuple[str, list[str]]] = tested_by_dir[dir_path]
            print(f"\n{dir_path}/ ({len(tested_files)} tested):")
            for source_name, source_test_paths in tested_files[:DEFAULT_DISPLAY_LIMIT]:
                test_info = source_test_paths[0] if source_test_paths else "Unknown"
                print(f"  {source_name} -> {test_info}")
            if len(tested_files) > DEFAULT_DISPLAY_LIMIT:
                remaining = len(tested_files) - DEFAULT_DISPLAY_LIMIT
                print(f"  ... and {remaining} more")


def update_manifest(
    project_root: Path,
    tested: Set[str],
    untested: Set[str],
    coverage_map: Mapping[str, list[str]],
) -> bool:
    """Update the test coverage manifest file with current status.

    Args:
        project_root: Root directory of the project.
        tested: Set of source files that have corresponding tests.
        untested: Set of source files without tests.
        coverage_map: Mapping of source files to their test files.

    Returns:
        True if manifest was successfully updated, False otherwise.

    """
    manifest_path = project_root / "docs" / "TEST_COVERAGE_MANIFEST.md"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    total = len(tested) + len(untested)
    tested_pct = (len(tested) / total * COVERAGE_THRESHOLD_COMPLETE) if total > 0 else 0

    timestamp = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    if tested_pct >= COVERAGE_THRESHOLD_COMPLETE:
        status_badge = "![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)"
        status_text = "COMPLETE"
    elif tested_pct >= COVERAGE_THRESHOLD_EXCELLENT:
        status_badge = f"![Coverage](https://img.shields.io/badge/coverage-{tested_pct:.0f}%25-green)"
        status_text = "EXCELLENT"
    elif tested_pct >= COVERAGE_THRESHOLD_GOOD:
        status_badge = f"![Coverage](https://img.shields.io/badge/coverage-{tested_pct:.0f}%25-yellowgreen)"
        status_text = "GOOD"
    elif tested_pct >= COVERAGE_THRESHOLD_MODERATE:
        status_badge = f"![Coverage](https://img.shields.io/badge/coverage-{tested_pct:.0f}%25-yellow)"
        status_text = "MODERATE"
    else:
        status_badge = f"![Coverage](https://img.shields.io/badge/coverage-{tested_pct:.0f}%25-red)"
        status_text = "CRITICAL"

    lines: list[str] = [
        "# Intellicrack Test Coverage Manifest",
        "",
        status_badge,
        "",
        f"**Last Updated:** {timestamp}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Source Files | {total} |",
        f"| Files with Tests | {len(tested)} |",
        f"| Files without Tests | {len(untested)} |",
        f"| Coverage Percentage | {tested_pct:.1f}% |",
        f"| Status | {status_text} |",
        "",
        "## Coverage Progress",
        "",
        _generate_progress_bar(tested_pct),
        "",
    ]

    if untested:
        by_dir: dict[str, list[str]] = defaultdict(list)
        for f in sorted(untested):
            dir_name = str(Path(f).parent)
            by_dir[dir_name].append(Path(f).name)

        lines.extend([
            "## Untested Files",
            "",
            "Files requiring test coverage:",
            "",
        ])

        for dir_path in sorted(by_dir):
            files = by_dir[dir_path]
            lines.append(f"### `{dir_path}/` ({len(files)} files)")
            lines.append("")
            for filename in sorted(files):
                lines.append(f"- [ ] `{filename}`")
            lines.append("")

    if tested:
        tested_by_dir: dict[str, list[tuple[str, list[str]]]] = defaultdict(list)
        for f in sorted(tested):
            dir_name = str(Path(f).parent)
            tested_by_dir[dir_name].append((Path(f).name, coverage_map.get(f, [])))

        lines.extend([
            "## Tested Files",
            "",
            "Files with test coverage:",
            "",
        ])

        for dir_path in sorted(tested_by_dir):
            tested_files_list: list[tuple[str, list[str]]] = tested_by_dir[dir_path]
            lines.append(f"### `{dir_path}/` ({len(tested_files_list)} files)")
            lines.append("")
            lines.append("| Source File | Test File |")
            lines.append("|-------------|-----------|")
            for source_name, source_tests in sorted(tested_files_list):
                test_info = source_tests[0] if source_tests else "Unknown"
                lines.append(f"| `{source_name}` | `{test_info}` |")
            lines.append("")

    lines.extend([
        "---",
        "",
        "*Generated by `scripts/verify_test_coverage.py`*",
    ])

    manifest_content = "\n".join(lines) + "\n"
    manifest_path.write_text(manifest_content, encoding="utf-8")
    return True


def _generate_progress_bar(percentage: float, width: int = 30) -> str:
    """Generate a text-based progress bar for the manifest.

    Args:
        percentage: Coverage percentage (0-100).
        width: Width of the progress bar in characters.

    Returns:
        Formatted progress bar string.

    """
    filled = int(width * percentage / COVERAGE_THRESHOLD_COMPLETE)
    empty = width - filled

    bar_filled = "X" * filled
    bar_empty = "-" * empty
    return f"`[{bar_filled}{bar_empty}]` {percentage:.1f}%"


def main() -> int:
    """Execute test coverage verification for Intellicrack project.

    Returns:
        Exit code: 0 if all files are tested, 1 if untested files exist.

    """
    parser = argparse.ArgumentParser(description="Verify test coverage for Intellicrack")
    parser.add_argument("--detailed", action="store_true", help="Show detailed file lists")
    parser.add_argument(
        "--update-manifest",
        action="store_true",
        help="Update TEST_COVERAGE_MANIFEST.md with current status",
    )
    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    source_root = project_root / "intellicrack"
    test_root = project_root / "tests"

    tested, untested, coverage_map = analyze_coverage(source_root, test_root)

    generate_report(tested, untested, coverage_map, detailed=args.detailed)

    if args.update_manifest:
        print("\n" + "=" * 80)
        print("UPDATING MANIFEST...")
        print("=" * 80)
        success = update_manifest(project_root, tested, untested, coverage_map)
        if success:
            manifest_path = project_root / "docs" / "TEST_COVERAGE_MANIFEST.md"
            print(f"Manifest updated: {manifest_path}")
        else:
            print("Failed to update manifest")
            return 1

    print()
    return 0 if len(untested) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
