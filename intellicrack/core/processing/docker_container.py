"""
Docker Container Management for Distributed Analysis. 

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

#!/usr/bin/env python3
"""
Docker Container Management for Distributed Analysis.

This module provides comprehensive Docker container operations for distributed binary analysis
with container lifecycle management, state snapshots, and artifact collection.
"""

import os
import subprocess
import time
from typing import Any, Dict, Optional

from .base_snapshot_handler import BaseSnapshotHandler


class DockerContainer(BaseSnapshotHandler):
    """
    Manages Docker container operations for distributed analysis.

    This class provides a complete Docker container management interface for running
    isolated binary analysis tasks with state management and artifact collection.

    Features:
        - Container lifecycle management (start, stop, remove)
        - Command execution inside containers
        - File transfer operations (host to container)
        - State snapshot creation and comparison
        - Analysis artifact collection
        - Comprehensive error handling and logging
    """

    def __init__(self, binary_path: Optional[str] = None, image: str = "ubuntu:latest"):
        """
        Initialize Docker container manager.

        Args:
            binary_path: Path to the binary to analyze
            image: Docker image to use for the container

        Raises:
            RuntimeError: If Docker is not available on the system
        """
        super().__init__()
        self.binary_path = binary_path
        self.image = image
        self.container_id: Optional[str] = None
        self.container_name: Optional[str] = None

        # Validate binary path if provided
        if binary_path and not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        # Check Docker availability
        self._check_docker_availability()

        self.logger.info("DockerContainer initialized with image: %s", image)

    def _check_docker_availability(self) -> None:
        """
        Check if Docker is available and accessible.

        Raises:
            RuntimeError: If Docker is not available or accessible
        """
        try:
            from ...utils.subprocess_utils import run_subprocess_check
            result = run_subprocess_check(
                ["docker", "--version"],
                timeout=10,
                check=False
            )

            if result.returncode != 0:
                raise RuntimeError("Docker not available on this system")

            self.logger.info(f"Docker available: {result.stdout.strip()}")

            # Check if Docker daemon is running
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=10
            , check=False)

            if result.returncode != 0:
                raise RuntimeError("Docker daemon not running")

        except subprocess.TimeoutExpired:
            raise RuntimeError("Docker command timed out - daemon may not be running")
        except FileNotFoundError:
            raise RuntimeError("Docker command not found - Docker is not installed")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Docker initialization error: {str(e)}")
            raise RuntimeError(f"Docker initialization failed: {str(e)}")

    def start_container(self, privileged: bool = True, network_mode: str = "bridge") -> bool:
        """
        Start a Docker container with the specified image.

        Args:
            privileged: Whether to run container in privileged mode
            network_mode: Network mode for the container

        Returns:
            True if container started successfully, False otherwise
        """
        try:
            # Pull the image if not already available
            self.logger.info("Pulling Docker image: %s", self.image)
            result = subprocess.run(
                ["docker", "pull", self.image],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for image pulls
            , check=False)

            if result.returncode != 0:
                self.logger.warning("Failed to pull image (may already exist): %s", result.stderr)

            # Generate unique container name
            self.container_name = f"intellicrack_analysis_{int(time.time())}"

            # Build docker run command
            docker_cmd = [
                "docker", "run",
                "-d",  # Detached mode
                "--name", self.container_name,
                "--network", network_mode
            ]

            # Add privileged mode if requested
            if privileged:
                docker_cmd.append("--privileged")

            # Mount binary directory if binary path is provided
            if self.binary_path:
                binary_dir = os.path.dirname(os.path.abspath(self.binary_path))
                docker_cmd.extend(["-v", f"{binary_dir}:/mnt/host:ro"])

            # Add image and keep-alive command
            docker_cmd.extend([self.image, "tail", "-f", "/dev/null"])

            # Start the container
            self.logger.info("Starting Docker container: %s", self.container_name)
            from ...utils.subprocess_utils import run_subprocess_check
            result = run_subprocess_check(docker_cmd, timeout=60)

            if result.returncode != 0:
                self.logger.error("Failed to start container: %s", result.stderr)
                return False

            self.container_id = result.stdout.strip()
            self.logger.info("Container started successfully - ID: %s", self.container_id)

            # Verify container is running
            if not self._is_container_running():
                self.logger.error("Container started but is not running")
                return False

            return True

        except subprocess.TimeoutExpired:
            self.logger.error("Container start operation timed out")
            return False
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Error starting Docker container: {str(e)}")
            return False

    def stop_container(self, force: bool = False) -> bool:
        """
        Stop and remove the Docker container.

        Args:
            force: Whether to force stop the container

        Returns:
            True if container stopped successfully, False otherwise
        """
        if not self.container_id:
            self.logger.warning("No container ID available to stop")
            return False

        try:
            # Stop the container
            stop_cmd = ["docker", "stop"]
            if force:
                stop_cmd.append("-t")
                stop_cmd.append("0")  # Immediate stop

            stop_cmd.append(self.container_id)

            self.logger.info("Stopping container %s", self.container_id)
            result = subprocess.run(stop_cmd, capture_output=True, text=True, timeout=30, check=False)

            if result.returncode != 0:
                self.logger.warning("Failed to stop container gracefully: %s", result.stderr)
                if not force:
                    # Try force stop
                    return self.stop_container(force=True)

            # Remove the container
            self.logger.info("Removing container %s", self.container_id)
            result = subprocess.run(
                ["docker", "rm", self.container_id],
                capture_output=True,
                text=True,
                timeout=30
            , check=False)

            if result.returncode != 0:
                self.logger.warning("Failed to remove container: %s", result.stderr)

            self.logger.info("Container %s stopped and removed", self.container_id)
            self.container_id = None
            self.container_name = None
            return True

        except subprocess.TimeoutExpired:
            self.logger.error("Container stop operation timed out")
            return False
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Error stopping Docker container: {str(e)}")
            return False

    def _is_container_running(self) -> bool:
        """
        Check if the container is currently running.

        Returns:
            True if container is running, False otherwise
        """
        if not self.container_id:
            return False

        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", self.container_id],
                capture_output=True,
                text=True,
                timeout=10
            , check=False)

            return result.returncode == 0 and result.stdout.strip() == "true"

        except (OSError, ValueError, RuntimeError):
            return False

    def execute_command(self, command: str, timeout: int = 60, working_dir: Optional[str] = None) -> str:
        """
        Execute a command in the Docker container.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds
            working_dir: Working directory for the command

        Returns:
            Command output as string
        """
        if not self.container_id or not self._is_container_running():
            error_msg = "Container not running"
            self.logger.error(error_msg)
            return f"ERROR: {error_msg}"

        try:
            self.logger.debug("Executing in container: %s", command)

            # Build command
            docker_cmd = ["docker", "exec"]

            if working_dir:
                docker_cmd.extend(["-w", working_dir])

            docker_cmd.extend([self.container_id, "bash", "-c", command])

            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            , check=False)

            if result.returncode != 0:
                self.logger.warning("Command exited with status %s", result.returncode)
                self.logger.warning("Stderr: %s", result.stderr)
                return f"EXIT_CODE_{result.returncode}: {result.stdout}\nSTDERR: {result.stderr}"

            return result.stdout

        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after {timeout} seconds"
            self.logger.error(error_msg)
            return f"ERROR: {error_msg}"
        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error executing command: {str(e)}"
            self.logger.error(error_msg)
            return f"ERROR: {error_msg}"

    def copy_file_to_container(self, source_path: str, dest_path: str) -> bool:
        """
        Copy a file from host to the Docker container.

        Args:
            source_path: Source file path on host
            dest_path: Destination path in container

        Returns:
            True if file copied successfully, False otherwise
        """
        if not self.container_id or not self._is_container_running():
            self.logger.error("Container not running for file copy")
            return False

        if not os.path.exists(source_path):
            self.logger.error("Source file does not exist: %s", source_path)
            return False

        try:
            # Create target directory if it doesn't exist
            dest_dir = os.path.dirname(dest_path)
            if dest_dir:
                mkdir_result = self.execute_command(f"mkdir -p {dest_dir}")
                if "ERROR:" in mkdir_result:
                    self.logger.error("Failed to create directory %s: %s", dest_dir, mkdir_result)
                    return False

            # Copy file using docker cp
            self.logger.info("Copying %s to container:%s", source_path, dest_path)
            result = subprocess.run(
                ["docker", "cp", source_path, f"{self.container_id}:{dest_path}"],
                capture_output=True,
                text=True,
                timeout=60
            , check=False)

            if result.returncode != 0:
                self.logger.error("Failed to copy file: %s", result.stderr)
                return False

            # Verify file was copied
            verify_result = self.execute_command(f"test -f {dest_path} && echo 'SUCCESS' || echo 'FAILED'")
            if "SUCCESS" not in verify_result:
                self.logger.error("File copy verification failed: %s", verify_result)
                return False

            self.logger.info("File copied successfully to %s", dest_path)
            return True

        except subprocess.TimeoutExpired:
            self.logger.error("File copy operation timed out")
            return False
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Error copying file to container: {str(e)}")
            return False

    def create_snapshot(self, name: str) -> bool:
        """
        Create a snapshot of the container state.

        Args:
            name: Unique snapshot name

        Returns:
            True if snapshot created successfully, False otherwise
        """
        if not self.container_id or not self._is_container_running():
            self.logger.error("Container not running for snapshot creation")
            return False

        if name in self.snapshots:
            self.logger.warning("Snapshot %s already exists, overwriting", name)

        try:
            self.logger.info("Creating container snapshot: %s", name)

            # Get filesystem state (recent files only for performance)
            files = self.execute_command(
                "find / -type f -mtime -1 -not -path '/proc/*' -not -path '/sys/*' "
                "-not -path '/dev/*' -not -path '/tmp/*' 2>/dev/null | sort"
            )

            # Get process list
            processes = self.execute_command("ps aux --no-headers")

            # Get network connections
            network = self.execute_command("netstat -tuln 2>/dev/null")

            # Get environment variables
            env_vars = self.execute_command("env | sort")

            # Get disk usage
            disk_usage = self.execute_command("df -h")

            # Store snapshot
            self.snapshots[name] = {
                "timestamp": time.time(),
                "files": files,
                "processes": processes,
                "network": network,
                "environment": env_vars,
                "disk_usage": disk_usage
            }

            self.logger.info(f"Snapshot '{name}' created successfully")
            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Error creating container snapshot: {str(e)}")
            return False

    def compare_snapshots(self, snapshot1: str, snapshot2: str) -> Dict[str, Any]:
        """
        Compare two container snapshots.

        Args:
            snapshot1: First snapshot name
            snapshot2: Second snapshot name

        Returns:
            Dictionary containing differences between snapshots
        """
        # Use base class functionality to eliminate duplicate code
        return self.compare_snapshots_base(snapshot1, snapshot2)

    def _perform_platform_specific_comparison(self, s1: Dict[str, Any], s2: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform Docker-specific snapshot comparison logic.
        
        Args:
            s1: First snapshot data
            s2: Second snapshot data
            
        Returns:
            Dictionary containing Docker-specific comparison results
        """
        try:
            # Compare files
            files1 = set(s1["files"].splitlines() if s1.get("files") else [])
            files2 = set(s2["files"].splitlines() if s2.get("files") else [])

            new_files = list(files2 - files1)[:100]  # Limit output
            deleted_files = list(files1 - files2)[:100]

            # Compare processes
            processes1 = s1["processes"].splitlines() if s1.get("processes") else []
            processes2 = s2["processes"].splitlines() if s2.get("processes") else []

            # Extract command parts for comparison
            proc1 = set()
            proc2 = set()

            for _p in processes1:
                parts = _p.split()
                if len(parts) > 10:
                    proc1.add(' '.join(parts[10:]))

            for _p in processes2:
                parts = _p.split()
                if len(parts) > 10:
                    proc2.add(' '.join(parts[10:]))

            new_processes = list(proc2 - proc1)
            ended_processes = list(proc1 - proc2)

            # Compare network connections
            networks1 = set(s1["network"].splitlines() if s1.get("network") else [])
            networks2 = set(s2["network"].splitlines() if s2.get("network") else [])

            new_connections = list(networks2 - networks1)
            closed_connections = list(networks1 - networks2)

            # Compare environment variables
            env1 = set(s1["environment"].splitlines() if s1.get("environment") else [])
            env2 = set(s2["environment"].splitlines() if s2.get("environment") else [])

            new_env = list(env2 - env1)
            removed_env = list(env1 - env2)

            return {
                "timestamp1": s1["timestamp"],
                "timestamp2": s2["timestamp"],
                "new_files": new_files,
                "deleted_files": deleted_files,
                "new_processes": new_processes,
                "ended_processes": ended_processes,
                "new_connections": new_connections,
                "closed_connections": closed_connections,
                "new_env_vars": new_env,
                "removed_env_vars": removed_env,
                "total_changes": (len(new_files) + len(deleted_files) + len(new_processes) +
                                len(ended_processes) + len(new_connections) + len(closed_connections) +
                                len(new_env) + len(removed_env))
            }

        except Exception as e:
            self.logger.error(f"Docker-specific comparison failed: {e}")
            return {"docker_comparison_error": str(e)}

    def collect_analysis_artifacts(self) -> Dict[str, Any]:
        """
        Collect analysis artifacts from the container.

        Returns:
            Dictionary containing analysis artifacts and metadata
        """
        if not self.container_id or not self._is_container_running():
            error_msg = "Container not running for artifact collection"
            self.logger.error(error_msg)
            return {"error": error_msg}

        try:
            self.logger.info("Collecting analysis artifacts from container")

            # Check for recently modified files
            modified_files = self.execute_command(
                "find / -type f -mtime -1 -not -path '/proc/*' -not -path '/sys/*' "
                "-not -path '/dev/*' 2>/dev/null | head -50"
            )

            # Check for log entries
            logs = self.execute_command(
                "find /var/log -name '*.log' -type f -exec tail -10 {} + 2>/dev/null | head -100"
            )

            # Check for network activity
            network_connections = self.execute_command("netstat -tan 2>/dev/null")

            # Check for open files (limited output)
            open_files = self.execute_command(
                "lsof 2>/dev/null | grep -v '/lib/' | grep -v '/usr/lib/' | head -50"
            )

            # Check running processes
            processes = self.execute_command("ps aux --no-headers")

            # Check memory usage
            memory = self.execute_command("free -h")

            # Check disk usage
            disk = self.execute_command("df -h")

            artifacts = {
                "collection_timestamp": time.time(),
                "container_id": self.container_id,
                "modified_files": modified_files,
                "logs": logs,
                "network_connections": network_connections,
                "open_files": open_files,
                "processes": processes,
                "memory_usage": memory,
                "disk_usage": disk
            }

            self.logger.info("Analysis artifacts collected successfully")
            return artifacts

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error collecting analysis artifacts: {str(e)}"
            self.logger.error(error_msg)
            return {"error": error_msg}

    def get_container_status(self) -> Dict[str, Any]:
        """
        Get comprehensive container status information.

        Returns:
            Dictionary containing container status and metadata
        """
        status = {
            "container_id": self.container_id,
            "container_name": self.container_name,
            "image": self.image,
            "binary_path": self.binary_path,
            "is_running": self._is_container_running() if self.container_id else False,
            "snapshots": list(self.snapshots.keys()),
            "snapshot_count": len(self.snapshots)
        }

        if self.container_id and self._is_container_running():
            try:
                # Get container details
                inspect_result = subprocess.run(
                    ["docker", "inspect", self.container_id],
                    capture_output=True,
                    text=True,
                    timeout=10
                , check=False)

                if inspect_result.returncode == 0:
                    import json
                    container_info = json.loads(inspect_result.stdout)[0]
                    status.update({
                        "start_time": container_info["State"]["StartedAt"],
                        "status_detail": container_info["State"]["Status"],
                        "network_mode": container_info["HostConfig"]["NetworkMode"],
                        "privileged": container_info["HostConfig"]["Privileged"]
                    })

            except (OSError, ValueError, RuntimeError) as e:
                self.logger.warning("Failed to get detailed container status: %s", e)

        return status

    def cleanup(self) -> bool:
        """
        Clean up container and resources.

        Returns:
            True if cleanup successful, False otherwise
        """
        success = True

        # Stop container if running
        if self.container_id:
            if not self.stop_container():
                success = False

        # Clear snapshots
        self.snapshots.clear()

        self.logger.info("Container cleanup completed")
        return success

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()


# Export main class
__all__ = ['DockerContainer']
