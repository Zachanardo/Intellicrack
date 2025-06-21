"""
Snapshot comparison utilities for Intellicrack.

This module provides shared utilities for comparing system snapshots.
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


def compare_snapshots(snapshot1: Dict[str, Any],
                     snapshot2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two system snapshots and return differences.

    Args:
        snapshot1: First snapshot
        snapshot2: Second snapshot

    Returns:
        Dictionary containing differences between snapshots
    """
    differences = {
        "files": {
            "added": [],
            "removed": [],
            "modified": []
        },
        "registry": {
            "added": [],
            "removed": [],
            "modified": []
        },
        "network": {
            "new_connections": [],
            "closed_connections": []
        },
        "processes": {
            "started": [],
            "terminated": []
        }
    }

    try:
        # Compare files
        files1 = set(snapshot1.get("files", {}).keys())
        files2 = set(snapshot2.get("files", {}).keys())

        differences["files"]["added"] = list(files2 - files1)
        differences["files"]["removed"] = list(files1 - files2)

        # Check for modified files
        for file in files1 & files2:
            if snapshot1["files"][file] != snapshot2["files"][file]:
                differences["files"]["modified"].append(file)

        # Compare registry (Windows only)
        if "registry" in snapshot1 and "registry" in snapshot2:
            reg1 = set(snapshot1["registry"].keys())
            reg2 = set(snapshot2["registry"].keys())

            differences["registry"]["added"] = list(reg2 - reg1)
            differences["registry"]["removed"] = list(reg1 - reg2)

            # Check for modified registry entries
            for key in reg1 & reg2:
                if snapshot1["registry"][key] != snapshot2["registry"][key]:
                    differences["registry"]["modified"].append(key)

        # Compare network connections
        if "network" in snapshot1 and "network" in snapshot2:
            net1 = set(snapshot1["network"])
            net2 = set(snapshot2["network"])

            differences["network"]["new_connections"] = list(net2 - net1)
            differences["network"]["closed_connections"] = list(net1 - net2)

        # Compare processes
        if "processes" in snapshot1 and "processes" in snapshot2:
            proc1 = set(snapshot1["processes"])
            proc2 = set(snapshot2["processes"])

            differences["processes"]["started"] = list(proc2 - proc1)
            differences["processes"]["terminated"] = list(proc1 - proc2)

    except Exception as e:
        logger.error("Error comparing snapshots: %s", e)

    return differences
