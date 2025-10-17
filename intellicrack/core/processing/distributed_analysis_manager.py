"""Distributed analysis manager for coordinating multi-node analysis tasks."""

import logging
import os
from typing import Any

"""
Distributed Analysis Manager

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""


# QEMU emulator removed during VM framework consolidation
QEMUSystemEmulator = None
HAS_QEMU = False

__all__ = ["DistributedAnalysisManager"]


class DistributedAnalysisManager:
    """Manages distributed analysis across multiple VMs/containers.

    Coordinates binary analysis across different virtual environments to provide
    comprehensive security assessment and license validation testing.
    """

    def __init__(self, binary_path: str | None = None):
        """Initialize the distributed analysis manager.

        Args:
            binary_path: Path to the binary to analyze

        """
        self.binary_path = binary_path
        self.vms: list[dict[str, Any]] = []
        self.logger = logging.getLogger(__name__)

    def add_vm(self, vm_type: str = "qemu", arch: str = "x86_64", memory_mb: int = 2048) -> int:
        """Add a VM to the distributed analysis pool.

        Args:
            vm_type: Type of VM (qemu, virtualbox, etc.)
            arch: Architecture to emulate
            memory_mb: Amount of memory to allocate

        Returns:
            VM ID, or -1 if failed

        """
        if not HAS_QEMU and vm_type == "qemu":
            self.logger.error("QEMU support not available")
            return -1

        vm_id = len(self.vms)

        if vm_type == "qemu":
            try:
                vm = QEMUSystemEmulator(self.binary_path, architecture=arch)
                self.vms.append(
                    {
                        "id": vm_id,
                        "type": vm_type,
                        "arch": arch,
                        "memory_mb": memory_mb,
                        "instance": vm,
                        "status": "created",
                    }
                )
                self.logger.info("Added QEMU VM (ID: %s, Arch: %s)", vm_id, arch)
                return vm_id
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error("Failed to create QEMU VM: %s", e)
                return -1
        else:
            self.logger.error("Unsupported VM type: %s", vm_type)
            return -1

    def start_all(self) -> bool:
        """Start all VMs and containers in the pool.

        Returns:
            True if all started successfully, False otherwise

        """
        success = True

        # Start VMs
        for _vm in self.vms:
            if _vm["status"] == "created":
                self.logger.info(f"Starting VM {_vm['id']}...")
                try:
                    if _vm["instance"].start_system(memory_mb=_vm["memory_mb"]):
                        _vm["status"] = "running"
                        self.logger.info(f"VM {_vm['id']} started successfully")
                    else:
                        _vm["status"] = "failed"
                        self.logger.error(f"Failed to start VM {_vm['id']}")
                        success = False
                except (OSError, ValueError, RuntimeError) as e:
                    _vm["status"] = "failed"
                    self.logger.error(f"Exception starting VM {_vm['id']}: {e}")
                    success = False

        return success

    def run_distributed_analysis(self, analysis_type: str = "license_check") -> dict[str, Any]:
        """Run distributed analysis across all VMs and containers.

        Args:
            analysis_type: Type of analysis to run

        Returns:
            Analysis results from all VMs and containers

        """
        results = {
            "vms": [],
            "summary": {},
        }

        # Run analysis on VMs
        for _vm in self.vms:
            if _vm["status"] == "running":
                self.logger.info(f"Running {analysis_type} analysis on VM {_vm['id']}...")

                try:
                    # Create pre-analysis snapshot
                    _vm["instance"].create_snapshot("pre_analysis")

                    # Run the binary
                    if self.binary_path:
                        binary_name = os.path.basename(self.binary_path)
                        output = _vm["instance"].execute_command(
                            f"cd /mnt/host && chmod +x {binary_name} && ./{binary_name}",
                        )
                    else:
                        output = "No binary path specified"

                    # Create post-analysis snapshot
                    _vm["instance"].create_snapshot("post_analysis")

                    # Compare snapshots
                    diff = _vm["instance"].compare_snapshots("pre_analysis", "post_analysis")

                    results["vms"].append(
                        {
                            "vm_id": _vm["id"],
                            "arch": _vm["arch"],
                            "output": output,
                            "diff": diff,
                            "status": "completed",
                        }
                    )

                except (OSError, ValueError, RuntimeError) as e:
                    self.logger.error(f"Error analyzing VM {_vm['id']}: {e}")
                    results["vms"].append(
                        {
                            "vm_id": _vm["id"],
                            "arch": _vm["arch"],
                            "output": f"Error: {e}",
                            "diff": {},
                            "status": "error",
                        }
                    )

        # Generate summary
        running_vms = [_vm for _vm in self.vms if _vm["status"] == "running"]
        results["summary"] = {
            "vms_analyzed": len(running_vms),
            "total_nodes": len(self.vms),
            "successful_vm_analyses": len([_r for _r in results["vms"] if _r["status"] == "completed"]),
            "analysis_type": analysis_type,
        }

        return results

    def stop_all(self) -> bool:
        """Stop all VMs and containers in the pool.

        Returns:
            True if all stopped successfully, False otherwise

        """
        success = True

        # Stop VMs
        for _vm in self.vms:
            if _vm["status"] == "running":
                self.logger.info(f"Stopping VM {_vm['id']}...")
                try:
                    if _vm["instance"].stop_system():
                        _vm["status"] = "stopped"
                        self.logger.info(f"VM {_vm['id']} stopped successfully")
                    else:
                        _vm["status"] = "error"
                        self.logger.error(f"Failed to stop VM {_vm['id']}")
                        success = False
                except (OSError, ValueError, RuntimeError) as e:
                    _vm["status"] = "error"
                    self.logger.error(f"Exception stopping VM {_vm['id']}: {e}")
                    success = False

        return success

    def assign_task(self, node_id: int, task: str) -> bool:
        """Assign a specific task to a node (VM or container).

        Args:
            node_id: ID of the node
            task: Task description

        Returns:
            True if task assigned successfully

        """
        # Find the node in VMs
        for _vm in self.vms:
            if _vm["id"] == node_id:
                if "tasks" not in _vm:
                    _vm["tasks"] = []
                _vm["tasks"].append(task)
                self.logger.info(f"Assigned task '{task}' to VM {node_id}")
                return True

        self.logger.error("Node %s not found", node_id)
        return False

    def get_status(self) -> dict[str, Any]:
        """Get status of all nodes in the analysis pool.

        Returns:
            Status information for all VMs

        """
        return {
            "vms": [
                {
                    "id": vm["id"],
                    "type": vm["type"],
                    "arch": vm["arch"],
                    "status": vm["status"],
                    "tasks": vm.get("tasks", []),
                }
                for vm in self.vms
            ],
        }

    def cleanup(self) -> None:
        """Clean up all resources."""
        self.stop_all()

        # Clean up VM instances
        for _vm in self.vms:
            try:
                if hasattr(_vm["instance"], "cleanup"):
                    _vm["instance"].cleanup()
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error(f"Error cleaning up VM {_vm['id']}: {e}")

        self.vms.clear()

    def __del__(self):
        """Destructor to ensure cleanup."""
        self.cleanup()


def create_distributed_manager(binary_path: str | None = None) -> DistributedAnalysisManager:
    """Create a DistributedAnalysisManager.

    Args:
        binary_path: Path to binary for analysis

    Returns:
        Configured DistributedAnalysisManager instance

    """
    return DistributedAnalysisManager(binary_path)
