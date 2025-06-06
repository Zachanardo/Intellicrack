"""
Distributed Analysis Manager

This module provides distributed analysis capabilities across multiple VMs and containers,
enabling parallel analysis of binaries in different environments for comprehensive
security assessment.
"""

import logging
import os
from typing import Any, Dict, List, Optional

try:
    from ..processing.docker_container import DockerContainer
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False

try:
    from ..processing.qemu_emulator import QEMUSystemEmulator
    HAS_QEMU = True
except ImportError:
    HAS_QEMU = False

__all__ = ['DistributedAnalysisManager']


class DistributedAnalysisManager:
    """
    Manages distributed analysis across multiple VMs/containers.

    Coordinates binary analysis across different virtual environments to provide
    comprehensive security assessment and license validation testing.
    """

    def __init__(self, binary_path: Optional[str] = None):
        """
        Initialize the distributed analysis manager.

        Args:
            binary_path: Path to the binary to analyze
        """
        self.binary_path = binary_path
        self.vms: List[Dict[str, Any]] = []
        self.containers: List[Dict[str, Any]] = []
        self.logger = logging.getLogger(__name__)

    def add_vm(self, vm_type: str = "qemu", arch: str = "x86_64", memory_mb: int = 2048) -> int:
        """
        Add a VM to the distributed analysis pool.

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
                self.vms.append({
                    "id": vm_id,
                    "type": vm_type,
                    "arch": arch,
                    "memory_mb": memory_mb,
                    "instance": vm,
                    "status": "created"
                })
                self.logger.info("Added QEMU VM (ID: %s, Arch: %s)", vm_id, arch)
                return vm_id
            except Exception as e:
                self.logger.error("Failed to create QEMU VM: %s", e)
                return -1
        else:
            self.logger.error("Unsupported VM type: %s", vm_type)
            return -1

    def add_container(self, container_type: str = "docker", image: str = "ubuntu:latest") -> int:
        """
        Add a container to the distributed analysis pool.

        Args:
            container_type: Type of container (docker, podman, etc.)
            image: Container image to use

        Returns:
            Container ID, or -1 if failed
        """
        if not HAS_DOCKER and container_type == "docker":
            self.logger.error("Docker support not available")
            return -1

        container_id = len(self.containers)

        if container_type == "docker":
            try:
                instance = DockerContainer(self.binary_path, image)
                self.containers.append({
                    "id": container_id,
                    "type": container_type,
                    "image": image,
                    "instance": instance,
                    "status": "created"
                })
                self.logger.info("Added Docker container (ID: %s, Image: %s)", container_id, image)
                return container_id
            except Exception as e:
                self.logger.error("Failed to create Docker container: %s", e)
                return -1
        else:
            self.logger.error("Unsupported container type: %s", container_type)
            return -1

    def start_all(self) -> bool:
        """
        Start all VMs and containers in the pool.

        Returns:
            True if all started successfully, False otherwise
        """
        success = True

        # Start VMs
        for vm in self.vms:
            if vm["status"] == "created":
                self.logger.info(f"Starting VM {vm['id']}...")
                try:
                    if vm["instance"].start_system(memory_mb=vm["memory_mb"]):
                        vm["status"] = "running"
                        self.logger.info(f"VM {vm['id']} started successfully")
                    else:
                        vm["status"] = "failed"
                        self.logger.error(f"Failed to start VM {vm['id']}")
                        success = False
                except Exception as e:
                    vm["status"] = "failed"
                    self.logger.error(f"Exception starting VM {vm['id']}: {e}")
                    success = False

        # Start containers
        for container in self.containers:
            if container["status"] == "created":
                self.logger.info(f"Starting container {container['id']}...")
                try:
                    if container["instance"].start_container():
                        container["status"] = "running"
                        self.logger.info(f"Container {container['id']} started successfully")
                    else:
                        container["status"] = "failed"
                        self.logger.error(f"Failed to start container {container['id']}")
                        success = False
                except Exception as e:
                    container["status"] = "failed"
                    self.logger.error(f"Exception starting container {container['id']}: {e}")
                    success = False

        return success

    def run_distributed_analysis(self, analysis_type: str = "license_check") -> Dict[str, Any]:
        """
        Run distributed analysis across all VMs and containers.

        Args:
            analysis_type: Type of analysis to run

        Returns:
            Analysis results from all VMs and containers
        """
        results = {
            "vms": [],
            "containers": [],
            "summary": {}
        }

        # Run analysis on VMs
        for vm in self.vms:
            if vm["status"] == "running":
                self.logger.info(f"Running {analysis_type} analysis on VM {vm['id']}...")

                try:
                    # Create pre-analysis snapshot
                    vm["instance"].create_snapshot("pre_analysis")

                    # Run the binary
                    if self.binary_path:
                        binary_name = os.path.basename(self.binary_path)
                        output = vm["instance"].execute_command(
                            f"cd /mnt/host && chmod +x {binary_name} && ./{binary_name}"
                        )
                    else:
                        output = "No binary path specified"

                    # Create post-analysis snapshot
                    vm["instance"].create_snapshot("post_analysis")

                    # Compare snapshots
                    diff = vm["instance"].compare_snapshots("pre_analysis", "post_analysis")

                    results["vms"].append({
                        "vm_id": vm["id"],
                        "arch": vm["arch"],
                        "output": output,
                        "diff": diff,
                        "status": "completed"
                    })

                except Exception as e:
                    self.logger.error(f"Error analyzing VM {vm['id']}: {e}")
                    results["vms"].append({
                        "vm_id": vm["id"],
                        "arch": vm["arch"],
                        "output": f"Error: {e}",
                        "diff": {},
                        "status": "error"
                    })

        # Run analysis on containers
        for container in self.containers:
            if container["status"] == "running":
                self.logger.info(f"Running {analysis_type} analysis on container {container['id']}...")

                try:
                    # Create pre-analysis snapshot
                    container["instance"].create_snapshot("pre_analysis")

                    # Copy binary to container if needed
                    if self.binary_path:
                        binary_name = os.path.basename(self.binary_path)
                        copy_result = container["instance"].copy_file_to_container(
                            self.binary_path, f"/tmp/{binary_name}"
                        )

                        if copy_result:
                            # Run the binary in container
                            output = container["instance"].execute_command(
                                f"chmod +x /tmp/{binary_name} && /tmp/{binary_name}"
                            )
                        else:
                            output = "Failed to copy binary to container"
                    else:
                        output = "No binary path specified"

                    # Create post-analysis snapshot
                    container["instance"].create_snapshot("post_analysis")

                    # Compare snapshots and collect artifacts
                    diff = container["instance"].compare_snapshots("pre_analysis", "post_analysis")
                    artifacts = container["instance"].collect_analysis_artifacts()

                    results["containers"].append({
                        "container_id": container["id"],
                        "image": container["image"],
                        "output": output,
                        "diff": diff,
                        "artifacts": artifacts,
                        "status": "completed"
                    })

                except Exception as e:
                    self.logger.error(f"Error analyzing container {container['id']}: {e}")
                    results["containers"].append({
                        "container_id": container["id"],
                        "image": container["image"],
                        "output": f"Error: {e}",
                        "diff": {},
                        "artifacts": [],
                        "status": "error"
                    })

        # Generate summary
        running_vms = [vm for vm in self.vms if vm["status"] == "running"]
        running_containers = [c for c in self.containers if c["status"] == "running"]

        results["summary"] = {
            "vms_analyzed": len(running_vms),
            "containers_analyzed": len(running_containers),
            "total_nodes": len(self.vms) + len(self.containers),
            "successful_vm_analyses": len([r for r in results["vms"] if r["status"] == "completed"]),
            "successful_container_analyses": len([r for r in results["containers"] if r["status"] == "completed"]),
            "analysis_type": analysis_type
        }

        return results

    def stop_all(self) -> bool:
        """
        Stop all VMs and containers in the pool.

        Returns:
            True if all stopped successfully, False otherwise
        """
        success = True

        # Stop VMs
        for vm in self.vms:
            if vm["status"] == "running":
                self.logger.info(f"Stopping VM {vm['id']}...")
                try:
                    if vm["instance"].stop_system():
                        vm["status"] = "stopped"
                        self.logger.info(f"VM {vm['id']} stopped successfully")
                    else:
                        vm["status"] = "error"
                        self.logger.error(f"Failed to stop VM {vm['id']}")
                        success = False
                except Exception as e:
                    vm["status"] = "error"
                    self.logger.error(f"Exception stopping VM {vm['id']}: {e}")
                    success = False

        # Stop containers
        for container in self.containers:
            if container["status"] == "running":
                self.logger.info(f"Stopping container {container['id']}...")
                try:
                    if container["instance"].stop_container():
                        container["status"] = "stopped"
                        self.logger.info(f"Container {container['id']} stopped successfully")
                    else:
                        container["status"] = "error"
                        self.logger.error(f"Failed to stop container {container['id']}")
                        success = False
                except Exception as e:
                    container["status"] = "error"
                    self.logger.error(f"Exception stopping container {container['id']}: {e}")
                    success = False

        return success

    def assign_task(self, node_id: int, task: str) -> bool:
        """
        Assign a specific task to a node (VM or container).

        Args:
            node_id: ID of the node
            task: Task description

        Returns:
            True if task assigned successfully
        """
        # Find the node in VMs
        for vm in self.vms:
            if vm["id"] == node_id:
                if "tasks" not in vm:
                    vm["tasks"] = []
                vm["tasks"].append(task)
                self.logger.info(f"Assigned task '{task}' to VM {node_id}")
                return True

        # Find the node in containers
        for container in self.containers:
            if container["id"] == node_id:
                if "tasks" not in container:
                    container["tasks"] = []
                container["tasks"].append(task)
                self.logger.info(f"Assigned task '{task}' to container {node_id}")
                return True

        self.logger.error("Node %s not found", node_id)
        return False

    def get_status(self) -> Dict[str, Any]:
        """
        Get status of all nodes in the analysis pool.

        Returns:
            Status information for all VMs and containers
        """
        return {
            "vms": [
                {
                    "id": vm["id"],
                    "type": vm["type"],
                    "arch": vm["arch"],
                    "status": vm["status"],
                    "tasks": vm.get("tasks", [])
                }
                for vm in self.vms
            ],
            "containers": [
                {
                    "id": container["id"],
                    "type": container["type"],
                    "image": container["image"],
                    "status": container["status"],
                    "tasks": container.get("tasks", [])
                }
                for container in self.containers
            ]
        }

    def cleanup(self) -> None:
        """Clean up all resources."""
        self.stop_all()

        # Clean up VM instances
        for vm in self.vms:
            try:
                if hasattr(vm["instance"], "cleanup"):
                    vm["instance"].cleanup()
            except Exception as e:
                self.logger.error(f"Error cleaning up VM {vm['id']}: {e}")

        # Clean up container instances
        for container in self.containers:
            try:
                if hasattr(container["instance"], "cleanup"):
                    container["instance"].cleanup()
            except Exception as e:
                self.logger.error(f"Error cleaning up container {container['id']}: {e}")

        self.vms.clear()
        self.containers.clear()

    def __del__(self):
        """Destructor to ensure cleanup."""
        self.cleanup()


def create_distributed_manager(binary_path: Optional[str] = None) -> DistributedAnalysisManager:
    """
    Factory function to create a DistributedAnalysisManager.

    Args:
        binary_path: Path to binary for analysis

    Returns:
        Configured DistributedAnalysisManager instance
    """
    return DistributedAnalysisManager(binary_path)
