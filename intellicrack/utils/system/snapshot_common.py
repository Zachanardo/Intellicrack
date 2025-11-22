"""Snapshot common utilities for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.

Common snapshot comparison utilities to avoid code duplication.
"""

import logging
from typing import Any


def validate_snapshots(
    snapshots_dict: dict[str, Any],
    snapshot1: str,
    snapshot2: str,
    logger: logging.Logger | None = None,
) -> tuple[bool, str | None]:
    """Validate that both snapshots exist.

    Args:
        snapshots_dict: Dictionary containing snapshots.
        snapshot1: Name of first snapshot.
        snapshot2: Name of second snapshot.
        logger: Optional logger instance.

    Returns:
        Tuple containing validation status and error message (None if valid).

    """
    if snapshot1 not in snapshots_dict:
        error_msg = f"Snapshot '{snapshot1}' not found"
        if logger:
            logger.error(error_msg)
        return False, error_msg

    if snapshot2 not in snapshots_dict:
        error_msg = f"Snapshot '{snapshot2}' not found"
        if logger:
            logger.error(error_msg)
        return False, error_msg

    return True, None


def log_comparison_start(
    snapshot1: str,
    snapshot2: str,
    logger: logging.Logger | None = None,
) -> None:
    """Log the start of snapshot comparison.

    Args:
        snapshot1: Name of first snapshot.
        snapshot2: Name of second snapshot.
        logger: Optional logger instance.

    """
    if logger:
        logger.info("Comparing snapshots: %s vs %s", snapshot1, snapshot2)


def start_snapshot_comparison(
    snapshots_dict: dict[str, Any],
    snapshot1: str,
    snapshot2: str,
    logger: logging.Logger | None = None,
) -> tuple[bool, dict[str, Any] | None, str | None]:
    """Start snapshot comparison with validation and logging.

    Args:
        snapshots_dict: Dictionary containing snapshots.
        snapshot1: Name of first snapshot.
        snapshot2: Name of second snapshot.
        logger: Optional logger instance.

    Returns:
        Tuple containing success status, snapshot data dict (with 's1' and 's2' keys if successful),
        and error message (None if successful).

    """
    # Validate snapshots exist
    is_valid, error_msg = validate_snapshots(snapshots_dict, snapshot1, snapshot2, logger)
    if not is_valid:
        return False, None, error_msg

    try:
        # Log comparison start
        log_comparison_start(snapshot1, snapshot2, logger)

        # Get snapshot data
        s1 = snapshots_dict[snapshot1]
        s2 = snapshots_dict[snapshot2]

        return True, {"s1": s1, "s2": s2}, None

    except Exception as e:
        error_msg = f"Error starting comparison: {e!s}"
        if logger:
            logger.error(error_msg)
        return False, None, error_msg


def get_snapshot_data(
    snapshots_dict: dict[str, Any],
    snapshot_name: str,
) -> dict[str, Any]:
    """Get snapshot data safely.

    Args:
        snapshots_dict: Dictionary containing snapshots.
        snapshot_name: Name of the snapshot.

    Returns:
        Snapshot data dictionary, or empty dict if snapshot not found.

    """
    return snapshots_dict.get(snapshot_name, {})


def compare_file_lists(
    files1_data: str | None,
    files2_data: str | None,
    limit: int = 100,
) -> dict[str, list[str]]:
    """Compare file lists between two snapshots.

    Args:
        files1_data: File data from first snapshot.
        files2_data: File data from second snapshot.
        limit: Maximum number of changes to return.

    Returns:
        Dictionary with 'new_files', 'deleted_files', and 'modified_files' lists.

    """
    files1 = set(files1_data.splitlines() if files1_data else [])
    files2 = set(files2_data.splitlines() if files2_data else [])

    new_files = list(files2 - files1)[:limit]
    deleted_files = list(files1 - files2)[:limit]
    modified_files = list(files1 & files2)[:limit]  # Files present in both

    return {
        "new_files": new_files,
        "deleted_files": deleted_files,
        "modified_files": modified_files,
    }
