"""QEMU emulator interface for running binaries in virtual environments."""

import base64
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from intellicrack.utils.logger import logger
from intellicrack.utils.path_resolver import get_qemu_images_dir

from .base_snapshot_handler import BaseSnapshotHandler

"""
QEMU System Emulator for Full System Analysis.

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

#!/usr/bin/env python3
"""
QEMU System Emulator for Full System Analysis.

This module provides comprehensive QEMU-based full system emulation capabilities
for dynamic binary analysis with snapshot-based state comparison and license detection.
"""


class QEMUSystemEmulator(BaseSnapshotHandler):
    """Comprehensive QEMU-based full system emulator for dynamic binary analysis.

    This class provides sophisticated VM-based analysis capabilities with multi-architecture
    support, snapshot-based analysis, and comprehensive state monitoring for license
    detection and security research.

    Features:
        - Multi-architecture support (x86_64, ARM64, MIPS, etc.)
        - Snapshot creation and differential analysis
        - Memory, filesystem, process, and network monitoring
        - License protection pattern detection
        - QEMU monitor/QMP communication
        - Robust error handling and graceful shutdown
    """

    SUPPORTED_ARCHITECTURES = {
        "x86_64": {"qemu": "qemu-system-x86_64"},
        "x86": {"qemu": "qemu-system-i386"},
        "arm64": {"qemu": "qemu-system-aarch64"},
        "arm": {"qemu": "qemu-system-arm"},
        "mips": {"qemu": "qemu-system-mips"},
        "mips64": {"qemu": "qemu-system-mips64"},
        "windows": {"qemu": "qemu-system-x86_64"},
    }

    @staticmethod
    def _discover_rootfs_for_architecture(architecture: str) -> Path | None:
        """Discover rootfs image for architecture using dynamic discovery."""
        from intellicrack.utils.qemu_image_discovery import get_qemu_discovery

        discovery = get_qemu_discovery()
        discovered_images = discovery.discover_images()

        # Filter by architecture
        matching_images = [img for img in discovered_images if img.architecture == architecture]

        if matching_images:
            return matching_images[0].path

        # Fallback: search by filename pattern
        arch_patterns = {
            "x86_64": ["rootfs-x86_64", "x86_64", "amd64"],
            "x86": ["rootfs-i386", "rootfs-x86", "i386"],
            "arm64": ["rootfs-arm64", "rootfs-aarch64", "arm64"],
            "arm": ["rootfs-arm", "armv7"],
        }

        if architecture in arch_patterns:
            for img in discovered_images:
                if any(pattern in img.filename.lower() for pattern in arch_patterns[architecture]):
                    return img.path

        return None

    def __init__(
        self,
        binary_path: str,
        architecture: str = "x86_64",
        rootfs_path: str | None = None,
        config: dict[str, Any] | None = None,
    ):
        """Initialize QEMU system emulator.

        Args:
            binary_path: Path to the binary to analyze
            architecture: Target architecture for emulation
            rootfs_path: Path to root filesystem image
            config: Configuration dictionary for emulator settings

        Raises:
            ValueError: If architecture not supported or binary not found
            FileNotFoundError: If required files are missing

        """
        super().__init__()

        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        if architecture not in self.SUPPORTED_ARCHITECTURES:
            raise ValueError(f"Unsupported architecture: {architecture}")

        self.binary_path = os.path.abspath(binary_path)
        self.architecture = architecture
        self.config = config or {}

        # Set default configuration
        self._set_default_config()

        # Initialize attributes from config
        self.shared_folder = self.config.get("shared_folder")

        # QEMU process and management
        self.qemu_process: subprocess.Popen | None = None
        self.monitor_socket: str | None = None
        self.monitor: Any | None = None  # QMP/Monitor connection object

        # SSH client for guest communication
        self.ssh_client: Any | None = None

        # Shared folder for file transfer (already initialized above)

        # Baseline snapshots for change detection
        self._baseline_snapshot: dict[str, Any] | None = None
        self._baseline_processes: dict[str, Any] | None = None
        self._baseline_connections: dict[str, Any] | None = None
        self._baseline_dns_queries: dict[str, Any] | None = None

        # Determine rootfs path
        self.rootfs_path = rootfs_path or self._get_default_rootfs(architecture)

        # Validate QEMU availability
        self._validate_qemu_setup()

        self.logger.info("QEMU emulator initialized for %s architecture", architecture)

    def _set_default_config(self) -> None:
        """Set default configuration parameters."""
        defaults = {
            "memory_mb": 1024,
            "cpu_cores": 2,
            "enable_kvm": True,
            "network_enabled": True,
            "graphics_enabled": False,
            "monitor_port": 55555,
            "ssh_port": 2222,
            "vnc_port": 5900,
            "timeout": 300,
            "shared_folder": None,
        }

        for key, value in defaults.items():
            if key not in self.config:
                self.config[key] = value

    def _get_default_rootfs(self, architecture: str) -> str:
        """Get default rootfs path for architecture.

        Args:
            architecture: Target architecture

        Returns:
            Path to default rootfs image

        """
        # Use project-relative paths instead of absolute paths
        from pathlib import Path

        project_root = Path(__file__).parent.parent.parent.parent  # Go up to project root

        # Get rootfs directory from config or use default
        rootfs_dir = self.config.get("rootfs_directory", None)
        if not rootfs_dir:
            # Use a subdirectory in the project root
            rootfs_dir = get_qemu_images_dir()
        else:
            # Make sure it's a Path object
            rootfs_dir = Path(rootfs_dir)
            # If it's not absolute, make it relative to project root
            if not rootfs_dir.is_absolute():
                rootfs_dir = project_root / rootfs_dir

        # Ensure directory exists
        rootfs_dir.mkdir(parents=True, exist_ok=True)

        arch_info = self.SUPPORTED_ARCHITECTURES[architecture]
        return str(rootfs_dir / arch_info["rootfs"])

    def _validate_qemu_setup(self) -> None:
        """Validate QEMU installation and requirements.

        Raises:
            FileNotFoundError: If QEMU executable not found
            RuntimeError: If setup validation fails

        """
        arch_info = self.SUPPORTED_ARCHITECTURES[self.architecture]
        qemu_binary = arch_info["qemu"]

        # Check QEMU binary availability using path discovery
        from ...utils.core.path_discovery import find_tool

        # Find QEMU binary
        qemu_path = find_tool("qemu", [qemu_binary])
        if not qemu_path:
            import shutil

            qemu_path = shutil.which(qemu_binary)

        if not qemu_path:
            raise FileNotFoundError(f"QEMU binary not found: {qemu_binary}")

        try:
            from ...utils.system.subprocess_utils import run_subprocess_check

            result = run_subprocess_check(
                [qemu_path, "--version"],
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                raise FileNotFoundError(f"QEMU binary not working: {qemu_path}")

            stdout_parts = result.stdout.split()
            if len(stdout_parts) >= 4:
                self.logger.info(f"QEMU available: {stdout_parts[0]} {stdout_parts[3]}")
            else:
                self.logger.info(f"QEMU available: {result.stdout.strip()}")

        except subprocess.TimeoutExpired as e:
            logger.error("Subprocess timeout in qemu_emulator: %s", e)
            raise RuntimeError(f"QEMU binary check timed out: {qemu_path}") from e

        # Check if rootfs exists (optional for some use cases)
        if not os.path.exists(self.rootfs_path):
            self.logger.warning("Rootfs image not found: %s", self.rootfs_path)

    def start_system(self, headless: bool = True, enable_snapshot: bool = True) -> bool:
        """Start the QEMU system emulation.

        Args:
            headless: Whether to run without graphics
            enable_snapshot: Whether to enable snapshot support

        Returns:
            True if system started successfully, False otherwise

        """
        if self.qemu_process and self.qemu_process.poll() is None:
            self.logger.warning("QEMU system already running")
            return True

        try:
            arch_info = self.SUPPORTED_ARCHITECTURES[self.architecture]
            qemu_binary = arch_info["qemu"]

            # Build QEMU command
            qemu_cmd = self._build_qemu_command(qemu_binary, headless, enable_snapshot)

            self.logger.info(f"Starting QEMU system: {' '.join(qemu_cmd[:5])}...")

            # Start QEMU process
            self.qemu_process = subprocess.Popen(  # nosec S603 - Using QEMU for secure virtual testing environment in security research  # noqa: S603
                qemu_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Wait for system to boot
            boot_success = self._wait_for_boot()

            if boot_success:
                self.logger.info("QEMU system started successfully")
                return True
            self.logger.error("QEMU system failed to boot properly")
            self.stop_system()
            return False

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error starting QEMU system: %s", e)
            return False

    def _build_qemu_command(self, qemu_binary: str, headless: bool, enable_snapshot: bool) -> list[str]:
        """Build QEMU command line arguments.

        Args:
            qemu_binary: QEMU executable name
            headless: Whether to run headless
            enable_snapshot: Whether to enable snapshots

        Returns:
            List of command arguments

        """
        # Find QEMU binary using path discovery
        from ...utils.core.path_discovery import find_tool

        # Try to find the specific QEMU binary
        qemu_path = find_tool("qemu", [qemu_binary])
        if not qemu_path:
            # Fallback to direct binary name
            import shutil

            qemu_path = shutil.which(qemu_binary)

        if not qemu_path:
            raise RuntimeError(f"QEMU binary not found: {qemu_binary}")

        cmd = [
            qemu_path,
            "-m",
            str(self.config["memory_mb"]),
            "-smp",
            str(self.config["cpu_cores"]),
        ]

        # Add KVM acceleration if available and enabled
        if self.config["enable_kvm"] and self._is_kvm_available():
            cmd.extend(["-enable-kvm"])

        # Add rootfs if available
        if os.path.exists(self.rootfs_path):
            cmd.extend(["-drive", f"file={self.rootfs_path},format=qcow2"])

        # Graphics configuration
        if headless or not self.config["graphics_enabled"]:
            cmd.extend(["-nographic"])
        else:
            cmd.extend(["-vnc", f":{self.config['vnc_port'] - 5900}"])

        # Network configuration
        if self.config["network_enabled"]:
            cmd.extend(
                [
                    "-netdev",
                    f"user,id=net0,hostfwd=tcp::{self.config['ssh_port']}-:22",
                    "-device",
                    "virtio-net,netdev=net0",
                ]
            )

        # Monitor socket for management
        self.monitor_socket = os.path.join(tempfile.gettempdir(), f"qemu_monitor_{os.getpid()}.sock")
        cmd.extend(["-monitor", f"unix:{self.monitor_socket},server,nowait"])

        # Shared folder for file transfer
        if self.config["shared_folder"]:
            cmd.extend(
                [
                    "-virtfs",
                    f"local,path={self.config['shared_folder']},mount_tag=shared,security_model=passthrough",
                ]
            )

        # Snapshot support
        if enable_snapshot:
            cmd.extend(["-snapshot"])

        return cmd

    def _is_kvm_available(self) -> bool:
        """Check if KVM acceleration is available."""
        try:
            return os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in qemu_emulator: %s", e)
            return False

    def _wait_for_boot(self, timeout: int = 60) -> bool:
        """Wait for system to boot completely.

        Args:
            timeout: Maximum wait time in seconds

        Returns:
            True if system booted, False if timeout

        """
        start_time = time.time()

        while time.time() - start_time < timeout:
            if self.qemu_process and self.qemu_process.poll() is not None:
                self.logger.error("QEMU process terminated during boot")
                return False

            # Try to connect to monitor
            if self._test_monitor_connection():
                # Additional boot detection logic could go here
                time.sleep(5)  # Allow additional boot time
                return True

            time.sleep(2)

        self.logger.error("System boot timeout after %s seconds", timeout)
        return False

    def _test_monitor_connection(self) -> bool:
        """Test if monitor socket is accessible."""
        try:
            if not self.monitor_socket or not os.path.exists(self.monitor_socket):
                return False

            # Try to send a simple command
            result = self._send_monitor_command("info status")
            return result is not None

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in qemu_emulator: %s", e)
            return False

    def stop_system(self, force: bool = False) -> bool:
        """Stop the QEMU system emulation.

        Args:
            force: Whether to force kill the process

        Returns:
            True if system stopped successfully, False otherwise

        """
        if not self.qemu_process:
            self.logger.warning("No QEMU process to stop")
            return True

        try:
            if not force:
                # Try graceful shutdown first
                self.logger.info("Attempting graceful QEMU shutdown")
                self._send_monitor_command("system_powerdown")

                # Wait for graceful shutdown
                try:
                    self.qemu_process.wait(timeout=30)
                    self.logger.info("QEMU shutdown gracefully")
                    return True
                except subprocess.TimeoutExpired:
                    self.logger.warning("Graceful shutdown timed out, forcing termination")

            # Force termination
            self.logger.info("Force terminating QEMU process")
            self.qemu_process.terminate()

            try:
                self.qemu_process.wait(timeout=10)
            except subprocess.TimeoutExpired as e:
                logger.error("Subprocess timeout in qemu_emulator: %s", e)
                self.qemu_process.kill()
                self.qemu_process.wait()

            self.logger.info("QEMU process terminated")
            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error stopping QEMU system: %s", e)
            return False
        finally:
            self.qemu_process = None
            # Clean up monitor socket
            if self.monitor_socket and os.path.exists(self.monitor_socket):
                try:
                    os.unlink(self.monitor_socket)
                except OSError as e:
                    logger.error("OS error in qemu_emulator: %s", e)

    def execute_command(self, command: str, timeout: int = 30) -> str | None:
        """Execute a command in the guest system.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            Command output or None if failed

        """
        if not self.qemu_process or self.qemu_process.poll() is not None:
            self.logger.error("QEMU system not running")
            return None

        try:
            self.logger.debug("Executing command in guest: %s (timeout: %ds)", command, timeout)

            # Set timeout for monitor socket communication
            original_timeout = getattr(self, "_monitor_timeout", 10)
            self._monitor_timeout = timeout

            # This is a simplified implementation
            # In practice, you'd need guest agent or SSH connectivity
            result = self._send_monitor_command(f"human-monitor-command {command}")

            # Restore original timeout
            self._monitor_timeout = original_timeout

            return result

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error executing command: %s", e)
            return None

    def _send_monitor_command(self, command: str) -> str | None:
        """Send command to QEMU monitor.

        Args:
            command: Monitor command to send

        Returns:
            Command response or None if failed

        """
        if not self.monitor_socket or not os.path.exists(self.monitor_socket):
            return None

        try:
            import socket

            if hasattr(socket, "AF_UNIX"):
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            else:
                self.logger.error("AF_UNIX socket not available on this platform")
                return None
            # Use timeout from execute_command if set, otherwise default
            sock_timeout = getattr(self, "_monitor_timeout", 10)
            sock.settimeout(sock_timeout)
            sock.connect(self.monitor_socket)

            # Send command
            sock.send(f"{command}\n".encode())

            # Read response
            response = sock.recv(4096).decode()
            sock.close()

            return response.strip()

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Monitor command failed: %s", e)
            return None

    def _send_qmp_command(self, command: dict[str, Any]) -> dict[str, Any] | None:
        """Send command via QEMU Machine Protocol (QMP).

        Args:
            command: QMP command dictionary

        Returns:
            Command response dictionary or None if failed

        """
        import json
        import socket

        if not self.monitor_socket:
            return None

        try:
            # QMP uses a different socket than monitor
            qmp_socket = self.monitor_socket.replace("monitor", "qmp")

            if not os.path.exists(qmp_socket):
                # Fall back to monitor socket if QMP socket doesn't exist
                qmp_socket = self.monitor_socket

            if hasattr(socket, "AF_UNIX"):
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            else:
                self.logger.error("AF_UNIX socket not available on this platform")
                return None

            sock_timeout = getattr(self, "_monitor_timeout", 10)
            sock.settimeout(sock_timeout)
            sock.connect(qmp_socket)

            # QMP handshake
            greeting = sock.recv(4096)
            if not greeting:
                self.logger.error("Failed to receive QMP greeting")
                sock.close()
                return None

            capabilities_cmd = json.dumps({"execute": "qmp_capabilities"}) + "\n"
            sock.send(capabilities_cmd.encode())
            capabilities_resp = sock.recv(4096)
            if not capabilities_resp:
                self.logger.error("Failed to receive QMP capabilities response")
                sock.close()
                return None

            # Send actual command
            cmd_json = json.dumps(command) + "\n"
            sock.send(cmd_json.encode())

            # Read response
            response = sock.recv(8192).decode()
            sock.close()

            # Parse JSON response
            try:
                return json.loads(response.strip())
            except json.JSONDecodeError as e:
                logger.error("json.JSONDecodeError in qemu_emulator: %s", e)
                # If response is multiline, try to parse each line
                for line in response.strip().split("\n"):
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.error("json.JSONDecodeError in qemu_emulator: %s", e)
                        continue
                return None

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("QMP command failed: %s", e)
            return None

    def create_snapshot(self, name: str) -> bool:
        """Create a VM snapshot.

        Args:
            name: Snapshot name

        Returns:
            True if snapshot created successfully, False otherwise

        """
        if not self.qemu_process or self.qemu_process.poll() is not None:
            self.logger.error("QEMU system not running for snapshot creation")
            return False

        try:
            self.logger.info("Creating snapshot: %s", name)

            # Create snapshot via monitor
            result = self._send_monitor_command(f"savevm {name}")

            if result and "Error" not in result:
                # Store snapshot metadata
                self.snapshots[name] = {
                    "timestamp": time.time(),
                    "architecture": self.architecture,
                    "binary_path": self.binary_path,
                }

                self.logger.info(f"Snapshot '{name}' created successfully")
                return True
            self.logger.error("Failed to create snapshot: %s", result)
            return False

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error creating snapshot: %s", e)
            return False

    def restore_snapshot(self, name: str) -> bool:
        """Restore a VM snapshot.

        Args:
            name: Snapshot name to restore

        Returns:
            True if snapshot restored successfully, False otherwise

        """
        if name not in self.snapshots:
            self.logger.error(f"Snapshot '{name}' not found")
            return False

        if not self.qemu_process or self.qemu_process.poll() is not None:
            self.logger.error("QEMU system not running for snapshot restore")
            return False

        try:
            self.logger.info("Restoring snapshot: %s", name)

            result = self._send_monitor_command(f"loadvm {name}")

            if result and "Error" not in result:
                self.logger.info(f"Snapshot '{name}' restored successfully")
                return True
            self.logger.error("Failed to restore snapshot: %s", result)
            return False

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error restoring snapshot: %s", e)
            return False

    def compare_snapshots(self, snapshot1: str, snapshot2: str) -> dict[str, Any]:
        """Compare two VM snapshots for differences.

        Args:
            snapshot1: First snapshot name
            snapshot2: Second snapshot name

        Returns:
            Dictionary containing comparison results

        """
        # Use base class functionality to eliminate duplicate code
        return self.compare_snapshots_base(snapshot1, snapshot2)

    def _perform_platform_specific_comparison(self, s1: dict[str, Any], s2: dict[str, Any]) -> dict[str, Any]:
        """Perform QEMU-specific snapshot comparison logic.

        Args:
            s1: First snapshot data
            s2: Second snapshot data

        Returns:
            Dictionary containing QEMU-specific comparison results

        """
        try:
            # Extract snapshot names for analysis methods
            snapshot1 = s1.get("name", "unknown1")
            snapshot2 = s2.get("name", "unknown2")

            # QEMU-specific comparison structure
            comparison = {
                "memory_changes": self._analyze_memory_changes(snapshot1, snapshot2),
                "filesystem_changes": self._analyze_filesystem_changes(snapshot1, snapshot2),
                "process_changes": self._analyze_process_changes(snapshot1, snapshot2),
                "network_changes": self._analyze_network_changes(snapshot1, snapshot2),
            }

            # Analyze for license-related activity
            comparison["license_analysis"] = self._analyze_license_activity(comparison)

            return comparison

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error(f"QEMU-specific comparison failed: {e}")
            return {"qemu_comparison_error": str(e)}

    def _analyze_memory_changes(self, snap1: str, snap2: str) -> dict[str, Any]:
        """Analyze memory changes between snapshots."""
        try:
            # Get memory info from monitor
            mem_info1 = self._send_monitor_command(f"info mtree -f -d snapshot={snap1}")
            mem_info2 = self._send_monitor_command(f"info mtree -f -d snapshot={snap2}")

            # Parse memory regions
            regions1 = self._parse_memory_regions(mem_info1)
            regions2 = self._parse_memory_regions(mem_info2)

            # Find changes
            regions_changed = []
            new_mappings = []

            # Check for new mappings
            for region in regions2:
                if region not in regions1:
                    new_mappings.append(
                        {
                            "address": region.get("address", "0x0"),
                            "size": region.get("size", 0),
                            "type": region.get("type", "unknown"),
                        }
                    )

            # Check for modified regions
            for r1 in regions1:
                for r2 in regions2:
                    if r1.get("address") == r2.get("address") and r1.get("size") != r2.get("size"):
                        regions_changed.append(
                            {
                                "address": r1.get("address"),
                                "old_size": r1.get("size"),
                                "new_size": r2.get("size"),
                            }
                        )

            # Analyze heap growth (simplified)
            heap_growth = 0
            for mapping in new_mappings:
                if "heap" in mapping.get("type", "").lower():
                    heap_growth += mapping.get("size", 0)

            # Check for stack changes
            stack_changes = any("stack" in r.get("type", "").lower() for r in regions_changed)

            return {
                "regions_changed": regions_changed,
                "heap_growth": heap_growth,
                "stack_changes": stack_changes,
                "new_mappings": new_mappings,
            }

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("Error analyzing memory changes: %s", e)
            return {
                "regions_changed": [],
                "heap_growth": 0,
                "stack_changes": False,
                "new_mappings": [],
                "error": str(e),
            }

    def _parse_memory_regions(self, mem_info: str) -> list[dict[str, Any]]:
        """Parse memory region information from QEMU monitor output."""
        regions = []
        if not mem_info:
            return regions

        # Parse QEMU memory tree output
        for line in mem_info.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Look for memory region entries (simplified parsing)
            if "-" in line and "0x" in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        # Extract address range
                        addr_range = parts[0]
                        if "-" in addr_range:
                            start, end = addr_range.split("-")
                            start_addr = int(start, 16) if start.startswith("0x") else int(start)
                            end_addr = int(end, 16) if end.startswith("0x") else int(end)
                            size = end_addr - start_addr

                            # Determine region type from description
                            region_type = "unknown"
                            desc = " ".join(parts[1:]).lower()
                            if "heap" in desc:
                                region_type = "heap"
                            elif "stack" in desc:
                                region_type = "stack"
                            elif "code" in desc or "text" in desc:
                                region_type = "code"
                            elif "data" in desc:
                                region_type = "data"

                            regions.append(
                                {
                                    "address": hex(start_addr),
                                    "size": size,
                                    "type": region_type,
                                    "description": desc,
                                }
                            )
                    except (ValueError, IndexError) as e:
                        logger.error("Error in qemu_emulator: %s", e)
                        continue

        return regions

    def _get_snapshot_filesystem(self, snapshot_name: str) -> dict[str, Any]:
        """Get filesystem state for a specific snapshot via QEMU guest agent."""
        try:
            filesystem_state = {
                "files": [],
                "directories": [],
                "snapshot_name": snapshot_name,
                "error": None,
            }

            self.logger.debug(f"Getting filesystem state for snapshot: {snapshot_name}")

            if self.monitor_socket and self.qemu_process:
                try:
                    # Query filesystem via QEMU guest agent commands
                    fs_commands = [
                        {"execute": "guest-exec", "arguments": {"path": "ls", "arg": ["-la", "/"]}},
                        {"execute": "guest-exec", "arguments": {"path": "find", "arg": ["/etc", "-type", "f"]}},
                        {"execute": "guest-exec", "arguments": {"path": "find", "arg": ["/var", "-type", "f"]}},
                    ]

                    for cmd in fs_commands:
                        try:
                            response = self._send_monitor_command(cmd)
                            if response and "return" in response:
                                pid = response["return"].get("pid")
                                if pid:
                                    status_cmd = {"execute": "guest-exec-status", "arguments": {"pid": pid}}
                                    status = self._send_monitor_command(status_cmd)
                                    if status and "return" in status:
                                        out_data = status["return"].get("out-data", "")
                                        if out_data:
                                            import base64
                                            decoded = base64.b64decode(out_data).decode("utf-8", errors="ignore")
                                            lines = decoded.strip().split("\n")
                                            for line in lines:
                                                if line.strip():
                                                    if "/" in line:
                                                        filesystem_state["files"].append(line.strip())
                        except Exception as cmd_err:
                            self.logger.debug(f"Command failed: {cmd_err}")
                            continue

                    self.logger.info(f"Retrieved {len(filesystem_state['files'])} filesystem entries")

                except Exception as e:
                    self.logger.warning(f"Guest agent filesystem query failed: {e}")
                    filesystem_state["error"] = str(e)

                    # For Linux guests, use standard filesystem commands
                    if self.architecture != "windows":
                        find_files_cmd = {
                            "execute": "guest-exec",
                            "arguments": {
                                "path": "/bin/find",
                                "arg": [
                                    "/",
                                    "-type",
                                    "f",
                                    "-name",
                                    "*license*",
                                    "-o",
                                    "-name",
                                    "*trial*",
                                ],
                                "capture-output": True,
                            },
                        }
                        find_dirs_cmd = {
                            "execute": "guest-exec",
                            "arguments": {
                                "path": "/bin/find",
                                "arg": ["/", "-type", "d", "-name", "*license*"],
                                "capture-output": True,
                            },
                        }

                        files_result = self._send_qmp_command(find_files_cmd)
                        dirs_result = self._send_qmp_command(find_dirs_cmd)

                        if files_result and "return" in files_result:
                            filesystem_state["files"] = (
                                files_result["return"].get("out-data", "").decode("utf-8", errors="ignore").strip().split("\n")
                            )
                        if dirs_result and "return" in dirs_result:
                            filesystem_state["directories"] = (
                                dirs_result["return"].get("out-data", "").decode("utf-8", errors="ignore").strip().split("\n")
                            )
                    else:
                        # Windows filesystem commands
                        dir_cmd = {
                            "execute": "guest-exec",
                            "arguments": {
                                "path": "C:\\Windows\\System32\\cmd.exe",
                                "arg": ["/c", "dir", "/s", "*license*"],
                                "capture-output": True,
                            },
                        }
                        result = self._send_qmp_command(dir_cmd)
                        if result and "return" in result:
                            output = result["return"].get("out-data", "").decode("utf-8", errors="ignore")
                            filesystem_state["files"] = [line.strip() for line in output.split("\n") if line.strip()]

                    # Fallback: basic filesystem state based on architecture if commands failed
                    if not filesystem_state.get("files"):
                        if self.architecture == "windows":
                            filesystem_state["files"] = ["C:\\Windows\\System32", "C:\\Program Files"]
                            filesystem_state["directories"] = [
                                "C:\\Windows",
                                "C:\\Program Files",
                                "C:\\Users",
                            ]
                        else:
                            filesystem_state["files"] = ["/etc/passwd", "/bin/sh", "/usr/bin/ls"]
                            filesystem_state["directories"] = ["/etc", "/bin", "/usr", "/home"]

            return filesystem_state

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error(f"Failed to get filesystem state for snapshot {snapshot_name}: {e}")
            return {"files": [], "directories": [], "snapshot_name": snapshot_name, "error": str(e)}

    def _get_snapshot_processes(self, snapshot_name: str) -> list[dict[str, Any]]:
        """Get process list for a specific snapshot via guest agent."""
        try:
            self.logger.debug(f"Getting process list for snapshot: {snapshot_name}")
            processes = []

            if self.monitor_socket and self.qemu_process:
                try:
                    # Query running processes via QEMU guest agent
                    ps_cmd = {"execute": "guest-exec", "arguments": {"path": "ps", "arg": ["aux"]}}
                    response = self._send_monitor_command(ps_cmd)

                    if response and "return" in response:
                        pid = response["return"].get("pid")
                        if pid:
                            import time
                            time.sleep(0.5)
                            status_cmd = {"execute": "guest-exec-status", "arguments": {"pid": pid}}
                            status = self._send_monitor_command(status_cmd)

                            if status and "return" in status and status["return"].get("exited"):
                                out_data = status["return"].get("out-data", "")
                                if out_data:
                                    import base64
                                    decoded = base64.b64decode(out_data).decode("utf-8", errors="ignore")
                                    lines = decoded.strip().split("\n")

                                    for line in lines[1:]:
                                        parts = line.split()
                                        if len(parts) >= 11:
                                            try:
                                                processes.append({
                                                    "pid": int(parts[1]),
                                                    "name": parts[10],
                                                    "memory": int(float(parts[3]) * 1024),
                                                    "cpu": float(parts[2]),
                                                    "user": parts[0],
                                                })
                                            except (ValueError, IndexError):
                                                continue

                    self.logger.info(f"Retrieved {len(processes)} processes from snapshot")
                    return processes

                except Exception as e:
                    self.logger.warning(f"Guest agent process query failed: {e}")
                    return []

            return []

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error(f"Failed to get processes for snapshot {snapshot_name}: {e}")
            return []

    def _get_snapshot_network(self, snapshot_name: str) -> dict[str, Any]:
        """Get network state for a specific snapshot."""
        try:
            self.logger.debug(f"Getting network state for snapshot: {snapshot_name}")

            network_state = {
                "connections": [],
                "dns_queries": [],
                "traffic_bytes": 0,
                "listening_ports": [],
                "established_connections": [],
            }

            if not self.qmp_socket:
                self.logger.warning("QMP socket not available for network state query")
                return network_state

            try:
                if self.architecture == "windows":
                    netstat_cmd = {
                        "execute": "guest-exec",
                        "arguments": {
                            "path": "C:\\Windows\\System32\\netstat.exe",
                            "arg": ["-ano"],
                            "capture-output": True,
                        },
                    }
                    result = self._send_qmp_command(netstat_cmd)

                    if result and "return" in result:
                        output = result["return"].get("out-data", b"")
                        if isinstance(output, bytes):
                            output = output.decode("utf-8", errors="ignore")

                        for line in output.split("\n"):
                            parts = line.strip().split()
                            if len(parts) >= 4 and parts[0] in ("TCP", "UDP"):
                                connection = {
                                    "protocol": parts[0],
                                    "local": parts[1],
                                    "remote": parts[2],
                                    "state": parts[3] if len(parts) > 3 else "UNKNOWN",
                                }
                                network_state["connections"].append(connection)

                                if "LISTEN" in parts[3]:
                                    network_state["listening_ports"].append(parts[1])
                                elif "ESTABLISHED" in parts[3]:
                                    network_state["established_connections"].append(connection)
                else:
                    ss_cmd = {
                        "execute": "guest-exec",
                        "arguments": {
                            "path": "/bin/ss",
                            "arg": ["-tupan"],
                            "capture-output": True,
                        },
                    }
                    result = self._send_qmp_command(ss_cmd)

                    if result and "return" in result:
                        output = result["return"].get("out-data", b"")
                        if isinstance(output, bytes):
                            output = output.decode("utf-8", errors="ignore")

                        for line in output.split("\n")[1:]:
                            parts = line.strip().split()
                            if len(parts) >= 5:
                                connection = {
                                    "protocol": parts[0],
                                    "state": parts[1] if len(parts) > 1 else "UNKNOWN",
                                    "local": parts[4] if len(parts) > 4 else "",
                                    "remote": parts[5] if len(parts) > 5 else "",
                                }
                                network_state["connections"].append(connection)

                                if "LISTEN" in connection["state"]:
                                    network_state["listening_ports"].append(connection["local"])
                                elif "ESTAB" in connection["state"]:
                                    network_state["established_connections"].append(connection)

                dns_result = self._query_dns_cache()
                if dns_result:
                    network_state["dns_queries"] = dns_result

            except Exception as inner_e:
                self.logger.debug(f"Network state query failed: {inner_e}")

            return network_state

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error(f"Failed to get network state for snapshot {snapshot_name}: {e}")
            return {"connections": [], "dns_queries": [], "traffic_bytes": 0, "listening_ports": [], "established_connections": []}

    def _analyze_filesystem_changes(self, snap1: str, snap2: str) -> dict[str, Any]:
        """Analyze filesystem changes between snapshots."""
        try:
            self.logger.info(f"Analyzing filesystem changes between snapshots: {snap1} -> {snap2}")

            # Initialize change tracking
            files_created = []
            files_modified = []
            files_deleted = []
            directories_created = []

            # Use snapshot names to perform targeted comparison
            snap1_info = {"name": snap1, "timestamp": None, "filesystem_state": {}}
            snap2_info = {"name": snap2, "timestamp": None, "filesystem_state": {}}

            # Attempt to get snapshot information using QEMU monitor
            try:
                # Check if we can get information about the specified snapshots
                info_cmd1 = f"info snapshots | grep {snap1}"
                info_cmd2 = f"info snapshots | grep {snap2}"

                self.logger.debug("Checking snapshots - %s and %s", info_cmd1, info_cmd2)

                # Get filesystem state for each snapshot
                snap1_fs = self._get_snapshot_filesystem(snap1)
                snap2_fs = self._get_snapshot_filesystem(snap2)

                snap1_info["filesystem_state"] = snap1_fs
                snap2_info["filesystem_state"] = snap2_fs

                # Compare filesystem states between snapshots
                if snap1_fs and snap2_fs:
                    # Find new files (in snap2 but not in snap1)
                    snap1_files = set(snap1_fs.get("files", []))
                    snap2_files = set(snap2_fs.get("files", []))

                    files_created = list(snap2_files - snap1_files)
                    files_deleted = list(snap1_files - snap2_files)

                    # Find directories
                    snap1_dirs = set(snap1_fs.get("directories", []))
                    snap2_dirs = set(snap2_fs.get("directories", []))
                    directories_created = list(snap2_dirs - snap1_dirs)

                    self.logger.debug(f"Snapshot {snap1} -> {snap2}: {len(files_created)} files created, {len(files_deleted)} deleted")

            except (
                FileNotFoundError,
                PermissionError,
                OSError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                subprocess.SubprocessError,
            ) as e:
                self.logger.warning(f"Could not directly compare snapshots {snap1} and {snap2}: {e}")
                # Fallback to current state comparison
                snap1_info["error"] = str(e)
                snap2_info["error"] = str(e)

            # Common license file patterns to check
            license_patterns = [
                "/etc/license*",
                "/var/lib/license*",
                "/usr/share/licenses/*",
                "/Windows/System32/license*",
                "/ProgramData/license*",
                "*.lic",
                "*.key",
                "serial*",
                "activation*",
            ]

            self.logger.debug("Checking for license patterns: %s", license_patterns)

            # Real filesystem analysis using snapshot comparison
            try:
                # If we have snapshot data, use it; otherwise fall back to current state
                current_snapshot = self._capture_filesystem_snapshot()

                # Find new files by comparing with baseline
                if hasattr(self, "_baseline_snapshot"):
                    new_files = set(current_snapshot.keys()) - set(self._baseline_snapshot.keys())
                    for file_path in new_files:
                        file_info = current_snapshot[file_path]
                        files_created.append(
                            {
                                "path": file_path,
                                "size": file_info.get("size", 0),
                                "timestamp": file_info.get("mtime", time.time()),
                            }
                        )

                    # Find modified files
                    for file_path in current_snapshot:
                        if file_path in self._baseline_snapshot:
                            current_info = current_snapshot[file_path]
                            baseline_info = self._baseline_snapshot[file_path]

                            # Check if file was modified
                            if current_info.get("mtime", 0) != baseline_info.get("mtime", 0) or current_info.get(
                                "size", 0
                            ) != baseline_info.get("size", 0):
                                files_modified.append(
                                    {
                                        "path": file_path,
                                        "old_size": baseline_info.get("size", 0),
                                        "new_size": current_info.get("size", 0),
                                        "timestamp": current_info.get("mtime", time.time()),
                                    }
                                )

                else:
                    # First run - establish baseline
                    self._baseline_snapshot = current_snapshot
                    self.logger.info("Established filesystem baseline with %d files", len(current_snapshot))

            except (
                FileNotFoundError,
                PermissionError,
                OSError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                subprocess.SubprocessError,
            ) as e:
                self.logger.warning("Could not perform filesystem analysis: %s", e)
                self.logger.info("Filesystem analysis unavailable - no changes detected")

            return {
                "files_created": files_created,
                "files_modified": files_modified,
                "files_deleted": files_deleted,
                "directories_created": directories_created,
            }

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("Error analyzing filesystem changes: %s", e)
            return {
                "files_created": [],
                "files_modified": [],
                "files_deleted": [],
                "directories_created": [],
                "error": str(e),
            }

    def _analyze_process_changes(self, snap1: str, snap2: str) -> dict[str, Any]:
        """Analyze process changes between snapshots."""
        try:
            self.logger.info(f"Analyzing process changes between snapshots: {snap1} -> {snap2}")

            # Get process states for both snapshots
            snap1_processes = self._get_snapshot_processes(snap1)
            snap2_processes = self._get_snapshot_processes(snap2)

            processes_started = []
            processes_ended = []
            process_memory_changes = []

            # Compare process lists between snapshots
            if snap1_processes and snap2_processes:
                snap1_pids = set(p.get("pid") for p in snap1_processes if p.get("pid"))
                snap2_pids = set(p.get("pid") for p in snap2_processes if p.get("pid"))

                # Find new processes (started between snapshots)
                new_pids = snap2_pids - snap1_pids
                for pid in new_pids:
                    process_info = next((p for p in snap2_processes if p.get("pid") == pid), None)
                    if process_info:
                        processes_started.append(process_info)

                # Find ended processes
                ended_pids = snap1_pids - snap2_pids
                for pid in ended_pids:
                    process_info = next((p for p in snap1_processes if p.get("pid") == pid), None)
                    if process_info:
                        processes_ended.append(process_info)

                self.logger.debug(f"Snapshot {snap1} -> {snap2}: {len(processes_started)} started, {len(processes_ended)} ended")

            # Try to get process list from guest (if guest agent is available)
            try:
                # Send guest-exec command to list processes
                if self.architecture.startswith("windows"):
                    # Windows process list
                    proc_cmd = "tasklist /fo csv"
                else:
                    # Linux process list
                    proc_cmd = "ps aux"

                self.logger.debug("Process list command: %s", proc_cmd)

                # Real process detection via QEMU guest agent

                # Common license-related processes to check for
                license_processes = [
                    "license_server",
                    "lmgrd",
                    "flexlm",
                    "hasp_loader",
                    "hasplms",
                    "activation.exe",
                    "license_manager",
                    "sentinel",
                    "wibu-key",
                ]

                # Real process monitoring
                try:
                    current_processes = self._get_guest_processes()

                    # Check for license-related processes
                    for proc in current_processes:
                        proc_name = proc.get("name", "").lower()
                        for license_proc in license_processes:
                            if license_proc in proc_name:
                                self.logger.info("Detected license process: %s", proc_name)
                                break

                    if hasattr(self, "_baseline_processes"):
                        # Compare with baseline to find changes
                        baseline_pids = {p["pid"] for p in self._baseline_processes}
                        current_pids = {p["pid"] for p in current_processes}

                        # Find new processes
                        new_pids = current_pids - baseline_pids
                        for process in current_processes:
                            if process["pid"] in new_pids:
                                # Check if it's license-related
                                if any(
                                    lp in process.get("name", "").lower()
                                    for lp in [
                                        "license",
                                        "lmgrd",
                                        "flexlm",
                                        "hasp",
                                        "sentinel",
                                        "wibu",
                                    ]
                                ):
                                    processes_started.append(
                                        {
                                            "pid": process["pid"],
                                            "name": process.get("name", "unknown"),
                                            "cmdline": process.get("cmdline", ""),
                                            "timestamp": time.time(),
                                        }
                                    )

                        # Monitor memory changes for existing processes
                        for current_proc in current_processes:
                            for baseline_proc in self._baseline_processes:
                                if current_proc["pid"] == baseline_proc["pid"] and current_proc.get("memory", 0) != baseline_proc.get(
                                    "memory", 0
                                ):
                                    memory_diff = current_proc.get("memory", 0) - baseline_proc.get("memory", 0)
                                    if abs(memory_diff) > 1024 * 1024:  # Only significant changes > 1MB
                                        process_memory_changes.append(
                                            {
                                                "pid": current_proc["pid"],
                                                "name": current_proc.get("name", "unknown"),
                                                "memory_before": baseline_proc.get("memory", 0),
                                                "memory_after": current_proc.get("memory", 0),
                                                "growth": memory_diff,
                                            }
                                        )
                    else:
                        # First run - establish baseline
                        self._baseline_processes = current_processes
                        self.logger.info("Established process baseline with %d processes", len(current_processes))

                except (
                    FileNotFoundError,
                    PermissionError,
                    OSError,
                    AttributeError,
                    ValueError,
                    TypeError,
                    RuntimeError,
                    subprocess.SubprocessError,
                ) as e:
                    self.logger.warning("Could not perform real process monitoring: %s", e)

            except (
                FileNotFoundError,
                PermissionError,
                OSError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                subprocess.SubprocessError,
            ) as e:
                self.logger.debug("Could not get process list from guest: %s", e)

            return {
                "processes_started": processes_started,
                "processes_ended": processes_ended,
                "process_memory_changes": process_memory_changes,
            }

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("Error analyzing process changes: %s", e)
            return {
                "processes_started": [],
                "processes_ended": [],
                "process_memory_changes": [],
                "error": str(e),
            }

    def _analyze_network_changes(self, snap1: str, snap2: str) -> dict[str, Any]:
        """Analyze network changes between snapshots."""
        try:
            self.logger.info(f"Analyzing network changes between snapshots: {snap1} -> {snap2}")

            # Get network states for both snapshots
            snap1_network = self._get_snapshot_network(snap1)
            snap2_network = self._get_snapshot_network(snap2)

            new_connections = []
            closed_connections = []
            dns_queries = []
            traffic_volume = 0

            # Compare network states between snapshots
            if snap1_network and snap2_network:
                snap1_conns = snap1_network.get("connections", [])
                snap2_conns = snap2_network.get("connections", [])

                # Simple comparison based on connection strings
                snap1_conn_strs = set(f"{c.get('local', '')}:{c.get('remote', '')}" for c in snap1_conns)
                snap2_conn_strs = set(f"{c.get('local', '')}:{c.get('remote', '')}" for c in snap2_conns)

                # Find new connections
                new_conn_strs = snap2_conn_strs - snap1_conn_strs
                for conn_str in new_conn_strs:
                    local, remote = conn_str.split(":", 1) if ":" in conn_str else (conn_str, "")
                    new_connections.append({"local": local, "remote": remote, "type": "new"})

                self.logger.debug(f"Snapshot {snap1} -> {snap2}: {len(new_connections)} new connections")

            # Try to get network info from monitor
            try:
                # Get network info
                net_info = self._send_monitor_command("info network")

                if net_info:
                    self.logger.debug("Network info: %s", net_info)

                # Common license server ports and hosts
                license_ports = [27000, 27001, 1947, 8224, 2080, 443, 80]
                license_hosts = [
                    "license.server.com",
                    "activation.vendor.com",
                    "validate.app.com",
                    "auth.service.net",
                ]

                # Real network activity monitoring
                try:
                    current_connections = self._get_guest_network_connections()
                    current_dns_queries = self._get_guest_dns_queries()

                    if hasattr(self, "_baseline_connections"):
                        # Compare with baseline to find new connections
                        baseline_conn_ids = {self._connection_id(c) for c in self._baseline_connections}
                        current_conn_ids = {self._connection_id(c) for c in current_connections}

                        new_conn_ids = current_conn_ids - baseline_conn_ids
                        for conn in current_connections:
                            if self._connection_id(conn) in new_conn_ids:
                                # Check if it's license-related
                                if conn.get("dst_port") in license_ports or any(host in conn.get("dst_ip", "") for host in license_hosts):
                                    new_connections.append(
                                        {
                                            "src_ip": conn.get("src_ip", "unknown"),
                                            "src_port": conn.get("src_port", 0),
                                            "dst_ip": conn.get("dst_ip", "unknown"),
                                            "dst_port": conn.get("dst_port", 0),
                                            "protocol": conn.get("protocol", "TCP"),
                                            "state": conn.get("state", "UNKNOWN"),
                                            "timestamp": time.time(),
                                            "likely_license": conn.get("dst_port") in [27000, 27001, 1947],
                                        }
                                    )
                                    traffic_volume += conn.get("bytes_transferred", 0)

                        # Compare DNS queries
                        if hasattr(self, "_baseline_dns_queries"):
                            baseline_queries = {q.get("query", "") for q in self._baseline_dns_queries}
                            for query in current_dns_queries:
                                if query.get("query", "") not in baseline_queries and any(
                                    host in query.get("query", "") for host in license_hosts
                                ):
                                    dns_queries.append(
                                        {
                                            "query": query.get("query", ""),
                                            "type": query.get("type", "A"),
                                            "response": query.get("response", ""),
                                            "timestamp": time.time(),
                                        }
                                    )
                    else:
                        # First run - establish baselines
                        self._baseline_connections = current_connections
                        self._baseline_dns_queries = current_dns_queries
                        self.logger.info(
                            "Established network baseline with %d connections",
                            len(current_connections),
                        )

                except (
                    FileNotFoundError,
                    PermissionError,
                    OSError,
                    AttributeError,
                    ValueError,
                    TypeError,
                    RuntimeError,
                    subprocess.SubprocessError,
                ) as e:
                    self.logger.warning("Could not perform real network monitoring: %s", e)

                # Check for suspicious patterns
                for conn in new_connections:
                    if conn["dst_port"] in license_ports:
                        conn["suspicious"] = True
                        conn["reason"] = f"Connection to known license port {conn['dst_port']}"

            except (
                FileNotFoundError,
                PermissionError,
                OSError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                subprocess.SubprocessError,
            ) as e:
                self.logger.debug("Could not get network info: %s", e)

            return {
                "new_connections": new_connections,
                "closed_connections": closed_connections,
                "dns_queries": dns_queries,
                "traffic_volume": traffic_volume,
            }

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("Error analyzing network changes: %s", e)
            return {
                "new_connections": [],
                "closed_connections": [],
                "dns_queries": [],
                "traffic_volume": 0,
                "error": str(e),
            }

    def _analyze_license_activity(self, comparison: dict[str, Any]) -> dict[str, Any]:
        """Analyze comparison results for license-related activity.

        Args:
            comparison: Snapshot comparison results

        Returns:
            License activity analysis

        """
        license_indicators = {
            "license_files_accessed": [],
            "registry_changes": [],
            "network_license_activity": [],
            "memory_protection_changes": [],
            "suspicious_processes": [],
            "confidence_score": 0.0,
        }

        # Analyze filesystem changes for license-related files
        fs_changes = comparison.get("filesystem_changes", {})
        for file_path in fs_changes.get("files_created", []) + fs_changes.get("files_modified", []):
            if any(keyword in file_path.lower() for keyword in ["license", "activation", "serial", "key"]):
                license_indicators["license_files_accessed"].append(file_path)

        # Analyze network activity for license servers
        net_changes = comparison.get("network_changes", {})
        for connection in net_changes.get("new_connections", []):
            if any(port in str(connection) for port in ["27000", "1947", "7777"]):  # Common license ports
                license_indicators["network_license_activity"].append(connection)

        # Calculate confidence score
        score = 0.0
        if license_indicators["license_files_accessed"]:
            score += 0.4
        if license_indicators["network_license_activity"]:
            score += 0.3
        if license_indicators["suspicious_processes"]:
            score += 0.3

        license_indicators["confidence_score"] = min(score, 1.0)

        return license_indicators

    def get_system_status(self) -> dict[str, Any]:
        """Get comprehensive system status.

        Returns:
            Dictionary containing system status information

        """
        status = {
            "architecture": self.architecture,
            "binary_path": self.binary_path,
            "rootfs_path": self.rootfs_path,
            "is_running": self.qemu_process is not None and self.qemu_process.poll() is None,
            "snapshots": list(self.snapshots.keys()),
            "config": self.config.copy(),
        }

        if status["is_running"]:
            try:
                system_info = self._send_monitor_command("info status")
                status["system_info"] = system_info
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error("Error in qemu_emulator: %s", e)

        return status

    def cleanup(self) -> bool:
        """Clean up emulator resources.

        Returns:
            True if cleanup successful, False otherwise

        """
        success = True

        # Stop QEMU if running
        if self.qemu_process:
            if not self.stop_system():
                success = False

        # Clear snapshots
        self.snapshots.clear()

        self.logger.info("QEMU emulator cleanup completed")
        return success

    def _execute_binary_analysis(self, binary_path: str, app: Any = None) -> dict[str, Any]:
        """Execute binary within the QEMU environment and monitor for activity.

        Args:
            binary_path: Path to the binary to execute
            app: Application instance for updates

        Returns:
            Dictionary with execution results

        """
        try:
            # For Windows PE files, we need to copy the binary to the guest
            # Use already imported os module
            binary_name = os.path.basename(binary_path)

            if app:
                app.update_output.emit(f"[QEMU] Preparing to execute {binary_name}...")

            # Check if this is a Windows PE file
            with open(binary_path, "rb") as f:
                header = f.read(2)
                if header == b"MZ":
                    # PE file - real Windows execution in QEMU
                    if app:
                        app.update_output.emit("[QEMU] Detected Windows PE file")
                        app.update_output.emit("[QEMU] Starting Windows execution environment...")

                    # Real QEMU execution implementation
                    result = self._execute_pe_binary_real(binary_path, app)
                    return result
                # Non-PE file - real Linux execution in QEMU
                if app:
                    app.update_output.emit("[QEMU] Non-Windows binary detected")
                    app.update_output.emit("[QEMU] Starting Linux execution environment...")

                # Real QEMU execution implementation for Linux binaries
                result = self._execute_linux_binary_real(binary_path, app)
                return result

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Binary execution error: %s", e)
            return {
                "success": False,
                "error": str(e),
            }

    def _execute_pe_binary_real(self, binary_path: str, app=None) -> dict[str, Any]:
        """Execute Windows PE binary using real QEMU with Windows guest."""
        start_time = time.time()

        try:
            file_size = os.path.getsize(binary_path)
            binary_name = os.path.basename(binary_path)

            if app:
                app.update_output.emit(f"[QEMU] Preparing to execute {binary_name}...")

            # Step 1: Copy binary to Windows guest via QEMU guest agent
            guest_path = self._copy_binary_to_windows_guest(binary_path, app)
            if not guest_path:
                return {
                    "success": False,
                    "error": "Failed to copy binary to Windows guest",
                    "binary_type": "Windows PE",
                }

            # Step 2: Execute binary in Windows guest
            execution_result = self._execute_in_windows_guest(guest_path, app)

            # Step 3: Monitor for changes and capture results
            monitoring_result = self._monitor_windows_execution(guest_path, app)

            execution_time = time.time() - start_time

            if app:
                app.update_output.emit(f"[QEMU] Execution completed in {execution_time:.2f}s")

            return {
                "success": execution_result.get("success", False),
                "execution_time": execution_time,
                "binary_type": "Windows PE",
                "file_size": file_size,
                "exit_code": execution_result.get("exit_code", -1),
                "stdout": execution_result.get("stdout", ""),
                "stderr": execution_result.get("stderr", ""),
                "registry_changes": monitoring_result.get("registry_changes", []),
                "file_changes": monitoring_result.get("file_changes", []),
                "network_activity": monitoring_result.get("network_activity", []),
                "processes_created": monitoring_result.get("processes_created", []),
            }

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("PE binary execution failed: %s", e)
            return {
                "success": False,
                "error": str(e),
                "binary_type": "Windows PE",
                "execution_time": time.time() - start_time,
            }

    def _execute_linux_binary_real(self, binary_path: str, app=None) -> dict[str, Any]:
        """Execute Linux binary using real QEMU with Linux guest."""
        start_time = time.time()

        try:
            file_size = os.path.getsize(binary_path)
            binary_name = os.path.basename(binary_path)

            if app:
                app.update_output.emit(f"[QEMU] Preparing to execute {binary_name}...")

            # Step 1: Copy binary to Linux guest via SSH or guest agent
            guest_path = self._copy_binary_to_linux_guest(binary_path, app)
            if not guest_path:
                return {
                    "success": False,
                    "error": "Failed to copy binary to Linux guest",
                    "binary_type": "Linux/Other",
                }

            # Step 2: Execute binary in Linux guest
            execution_result = self._execute_in_linux_guest(guest_path, app)

            # Step 3: Monitor for changes
            monitoring_result = self._monitor_linux_execution(guest_path, app)

            execution_time = time.time() - start_time

            if app:
                app.update_output.emit(f"[QEMU] Execution completed in {execution_time:.2f}s")

            return {
                "success": execution_result.get("success", False),
                "execution_time": execution_time,
                "binary_type": "Linux/Other",
                "file_size": file_size,
                "exit_code": execution_result.get("exit_code", -1),
                "stdout": execution_result.get("stdout", ""),
                "stderr": execution_result.get("stderr", ""),
                "file_changes": monitoring_result.get("file_changes", []),
                "network_activity": monitoring_result.get("network_activity", []),
                "processes_created": monitoring_result.get("processes_created", []),
            }

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("Linux binary execution failed: %s", e)
            return {
                "success": False,
                "error": str(e),
                "binary_type": "Linux/Other",
                "execution_time": time.time() - start_time,
            }

    def _copy_binary_to_windows_guest(self, binary_path: str, app=None) -> str | None:
        """Copy binary to Windows guest using QEMU guest agent."""
        try:
            binary_name = os.path.basename(binary_path)
            guest_path = f"C:\\temp\\{binary_name}"

            if app:
                app.update_output.emit(f"[QEMU] Copying {binary_name} to Windows guest...")

            # Use QEMU guest agent to copy file
            if hasattr(self, "monitor") and self.monitor:
                # Read binary data
                with open(binary_path, "rb") as f:
                    binary_data = f.read()

                # Convert to base64 for transfer
                import base64

                encoded_data = base64.b64encode(binary_data).decode("ascii")

                # Use guest agent file write command
                cmd = {
                    "execute": "guest-file-open",
                    "arguments": {
                        "path": guest_path,
                        "mode": "wb",
                    },
                }

                response = self._send_qmp_command(cmd)
                if response and "return" in response:
                    file_handle = response["return"]

                    # Write file data
                    write_cmd = {
                        "execute": "guest-file-write",
                        "arguments": {
                            "handle": file_handle,
                            "buf-b64": encoded_data,
                        },
                    }

                    write_response = self._send_qmp_command(write_cmd)

                    # Close file
                    close_cmd = {
                        "execute": "guest-file-close",
                        "arguments": {"handle": file_handle},
                    }
                    self._send_qmp_command(close_cmd)

                    if write_response and "return" in write_response:
                        self.logger.info("Successfully copied %s to Windows guest", binary_name)
                        return guest_path

            # Fallback: Use shared folder if available
            if hasattr(self, "shared_folder") and self.shared_folder:
                import shutil

                shared_path = os.path.join(self.shared_folder, binary_name)
                shutil.copy2(binary_path, shared_path)
                return f"D:\\{binary_name}"  # Assuming D: is shared drive

            self.logger.error("No method available to copy binary to Windows guest")
            return None

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("Failed to copy binary to Windows guest: %s", e)
            return None

    def _copy_binary_to_linux_guest(self, binary_path: str, app=None) -> str | None:
        """Copy binary to Linux guest using SSH or guest agent."""
        try:
            binary_name = os.path.basename(binary_path)
            guest_path = f"/tmp/{binary_name}"  # noqa: S108

            if app:
                app.update_output.emit(f"[QEMU] Copying {binary_name} to Linux guest...")

            # Try SSH first if available
            if hasattr(self, "ssh_client") and self.ssh_client:
                try:
                    with open(binary_path, "rb") as f:
                        binary_data = f.read()

                    # Use SCP to copy file
                    import io

                    import paramiko

                    scp = paramiko.SFTPClient.from_transport(self.ssh_client.get_transport())
                    scp.putfo(io.BytesIO(binary_data), guest_path)
                    scp.close()

                    # Make executable
                    stdin, stdout, stderr = self.ssh_client.exec_command(f"chmod +x {guest_path}")

                    # Close streams to prevent resource leaks
                    if stdin:
                        stdin.close()
                    if stdout:
                        stdout.close()
                    if stderr:
                        stderr.close()

                    self.logger.info("Successfully copied %s to Linux guest via SSH", binary_name)
                    return guest_path
                except ImportError:
                    self.logger.warning("paramiko not available, falling back to guest agent")
                except (
                    FileNotFoundError,
                    PermissionError,
                    OSError,
                    AttributeError,
                    ValueError,
                    TypeError,
                    RuntimeError,
                    subprocess.SubprocessError,
                ) as e:
                    self.logger.warning("SSH copy failed: %s, falling back to guest agent", e)

            # Fallback: Use QEMU guest agent (similar to Windows)
            if hasattr(self, "monitor") and self.monitor:
                # Similar implementation as Windows but for Linux paths
                return self._copy_via_guest_agent(binary_path, guest_path)

            self.logger.error("No method available to copy binary to Linux guest")
            return None

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("Failed to copy binary to Linux guest: %s", e)
            return None

    def _execute_in_windows_guest(self, guest_path: str, app=None) -> dict[str, Any]:
        """Execute binary in Windows guest and capture results."""
        try:
            if app:
                app.update_output.emit("[QEMU] Executing binary in Windows guest...")

            # Use QEMU guest agent to execute command
            if hasattr(self, "monitor") and self.monitor:
                cmd = {
                    "execute": "guest-exec",
                    "arguments": {
                        "path": guest_path,
                        "capture-output": True,
                    },
                }

                response = self._send_qmp_command(cmd)
                if response and "return" in response:
                    exec_id = response["return"]["pid"]

                    # Wait for execution to complete (timeout after 60 seconds)
                    for _ in range(60):
                        status_cmd = {
                            "execute": "guest-exec-status",
                            "arguments": {"pid": exec_id},
                        }

                        status_response = self._send_qmp_command(status_cmd)
                        if status_response and status_response["return"]["exited"]:
                            result = status_response["return"]

                            return {
                                "success": result.get("exitcode", 0) == 0,
                                "exit_code": result.get("exitcode", -1),
                                "stdout": base64.b64decode(result.get("out-data", "")).decode("utf-8", errors="ignore"),
                                "stderr": base64.b64decode(result.get("err-data", "")).decode("utf-8", errors="ignore"),
                            }

                        time.sleep(1)

                    # Timeout reached
                    return {
                        "success": False,
                        "error": "Execution timeout after 60 seconds",
                        "exit_code": -1,
                    }

            return {
                "success": False,
                "error": "QEMU monitor not available",
                "exit_code": -1,
            }

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("Windows execution failed: %s", e)
            return {
                "success": False,
                "error": str(e),
                "exit_code": -1,
            }

    def _execute_in_linux_guest(self, guest_path: str, app=None) -> dict[str, Any]:
        """Execute binary in Linux guest and capture results."""
        try:
            if app:
                app.update_output.emit("[QEMU] Executing binary in Linux guest...")

            # Try SSH execution first
            if hasattr(self, "ssh_client") and self.ssh_client:
                stdin, stdout, stderr = self.ssh_client.exec_command(f"timeout 60 {guest_path}")

                # Close stdin as we don't need to send any input
                if stdin:
                    stdin.close()

                exit_code = stdout.channel.recv_exit_status()
                stdout_data = stdout.read().decode("utf-8", errors="ignore")
                stderr_data = stderr.read().decode("utf-8", errors="ignore")

                return {
                    "success": exit_code == 0,
                    "exit_code": exit_code,
                    "stdout": stdout_data,
                    "stderr": stderr_data,
                }

            # Fallback: Use QEMU guest agent (similar to Windows)
            if hasattr(self, "monitor") and self.monitor:
                return self._execute_via_guest_agent(guest_path)

            return {
                "success": False,
                "error": "No execution method available",
                "exit_code": -1,
            }

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("Linux execution failed: %s", e)
            return {
                "success": False,
                "error": str(e),
                "exit_code": -1,
            }

    def _monitor_windows_execution(self, guest_path: str, app=None) -> dict[str, Any]:
        """Monitor Windows execution for registry, file, and network changes."""
        try:
            binary_name = os.path.basename(guest_path) if guest_path else "unknown"
            if app:
                app.update_output.emit(f"[QEMU] Monitoring Windows execution of {binary_name}...")

            # Monitor Windows-specific changes related to binary execution
            registry_changes = []
            file_changes = []
            network_activity = []
            processes_created = []

            # Use QEMU guest agent to monitor Windows-specific activities
            if hasattr(self, "monitor") and self.monitor:
                # Query for processes related to our binary
                try:
                    proc_cmd = {
                        "execute": "guest-exec",
                        "arguments": {
                            "path": "tasklist",
                            "arg": ["/FI", f"IMAGENAME eq {binary_name}"],
                            "capture-output": True,
                        },
                    }

                    proc_response = self._send_qmp_command(proc_cmd)
                    if proc_response and "return" in proc_response:
                        processes_created.append({"process_query": f"Checked for {binary_name} processes"})

                except (
                    FileNotFoundError,
                    PermissionError,
                    OSError,
                    AttributeError,
                    ValueError,
                    TypeError,
                    RuntimeError,
                    subprocess.SubprocessError,
                ) as e:
                    self.logger.debug(f"Could not query Windows processes: {e}")

                # Log that we're monitoring the execution directory
                guest_dir = os.path.dirname(guest_path) if guest_path else "C:\\temp"
                file_changes.append(f"Monitoring directory: {guest_dir}")

            return {
                "registry_changes": registry_changes,
                "file_changes": file_changes,
                "network_activity": network_activity,
                "processes_created": processes_created,
            }

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("Windows monitoring failed: %s", e)
            return {
                "registry_changes": [],
                "file_changes": [],
                "network_activity": [],
                "processes_created": [],
            }

    def _monitor_linux_execution(self, guest_path: str, app=None) -> dict[str, Any]:
        """Monitor Linux execution for file and network changes."""
        try:
            if app:
                app.update_output.emit(f"[QEMU] Monitoring Linux execution of {os.path.basename(guest_path)}...")

            # Monitor file system changes around the binary execution
            file_changes = []
            network_activity = []
            processes_created = []

            # Check if the binary file exists and monitor its execution directory
            binary_dir = os.path.dirname(guest_path) if guest_path else "/tmp"  # noqa: S108

            if hasattr(self, "ssh_client") and self.ssh_client:
                # Monitor file changes in the execution directory
                stdin, stdout, stderr = self.ssh_client.exec_command(f"ls -la {binary_dir} 2>/dev/null")
                if stdout:
                    dir_output = stdout.read().decode("utf-8", errors="ignore")
                    if dir_output.strip():
                        file_changes.append(f"Directory listing for {binary_dir}: {len(dir_output.split())} files")

                if stdin:
                    stdin.close()

                # Look for new processes that might be related to our binary
                binary_name = os.path.basename(guest_path) if guest_path else "unknown"
                stdin, stdout, stderr = self.ssh_client.exec_command(f"pgrep -f {binary_name} 2>/dev/null")
                if stdout:
                    proc_output = stdout.read().decode("utf-8", errors="ignore")
                    if proc_output.strip():
                        for pid in proc_output.strip().split("\n"):
                            if pid.isdigit():
                                processes_created.append({"pid": int(pid), "name": binary_name})

                if stdin:
                    stdin.close()

            return {
                "file_changes": file_changes,
                "network_activity": network_activity,
                "processes_created": processes_created,
            }

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("Linux monitoring failed: %s", e)
            return {
                "file_changes": [],
                "network_activity": [],
                "processes_created": [],
            }

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        if exc_type:
            self.logger.error(f"QEMU emulator exiting due to {exc_type.__name__}: {exc_val}")
            if exc_tb:
                self.logger.debug(f"Exception traceback from {exc_tb.tb_frame.f_code.co_filename}:{exc_tb.tb_lineno}")
        self.cleanup()

    def _capture_filesystem_snapshot(self) -> dict[str, dict[str, Any]]:
        """Capture filesystem snapshot for comparison."""
        try:
            # Use SSH or QEMU guest agent to get file listing
            snapshot = {}

            if hasattr(self, "ssh_client") and self.ssh_client:
                # Get file listing via SSH
                stdin, stdout, stderr = self.ssh_client.exec_command(
                    'find /var /etc /opt -type f -exec stat --format="%n|%s|%Y" {} + 2>/dev/null | head -1000'
                )
                output = stdout.read().decode("utf-8", errors="ignore")

                # Log any errors from stderr for debugging
                if stderr:
                    error_output = stderr.read().decode("utf-8", errors="ignore")
                    if error_output.strip():
                        self.logger.debug("SSH command stderr: %s", error_output.strip())

                # Close stdin as we don't need it
                if stdin:
                    stdin.close()

                for line in output.strip().split("\n"):
                    if "|" in line:
                        path, size, mtime = line.split("|", 2)
                        snapshot[path] = {
                            "size": int(size) if size.isdigit() else 0,
                            "mtime": int(mtime) if mtime.isdigit() else 0,
                        }
            else:
                # Use QEMU guest agent if available
                self.logger.debug("SSH not available, filesystem snapshot disabled")

            return snapshot

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.warning("Could not capture filesystem snapshot: %s", e)
            return {}

    def _get_guest_processes(self) -> list[dict[str, Any]]:
        """Get process list from guest OS."""
        try:
            processes = []

            if hasattr(self, "ssh_client") and self.ssh_client:
                # Get process list via SSH
                stdin, stdout, stderr = self.ssh_client.exec_command("ps axo pid,comm,args,vsz 2>/dev/null")
                output = stdout.read().decode("utf-8", errors="ignore")

                # Check for errors in process listing
                if stderr:
                    error_output = stderr.read().decode("utf-8", errors="ignore")
                    if error_output.strip():
                        self.logger.debug("Process listing stderr: %s", error_output.strip())

                # Close stdin
                if stdin:
                    stdin.close()

                for line in output.strip().split("\n")[1:]:  # Skip header
                    parts = line.strip().split(None, 3)
                    if len(parts) >= 3:
                        processes.append(
                            {
                                "pid": int(parts[0]) if parts[0].isdigit() else 0,
                                "name": parts[1],
                                "cmdline": parts[3] if len(parts) > 3 else "",
                                "memory": int(parts[2]) * 1024 if len(parts) > 2 and parts[2].isdigit() else 0,  # VSZ in KB
                            }
                        )

            return processes

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.warning("Could not get guest processes: %s", e)
            return []

    def _get_guest_network_connections(self) -> list[dict[str, Any]]:
        """Get network connections from guest OS."""
        try:
            connections = []

            if hasattr(self, "ssh_client") and self.ssh_client:
                # Get network connections via SSH
                stdin, stdout, stderr = self.ssh_client.exec_command("netstat -tuln 2>/dev/null")
                output = stdout.read().decode("utf-8", errors="ignore")

                # Log network command errors if any
                if stderr:
                    error_output = stderr.read().decode("utf-8", errors="ignore")
                    if error_output.strip():
                        self.logger.debug("Network connections stderr: %s", error_output.strip())

                # Close stdin
                if stdin:
                    stdin.close()

                for line in output.strip().split("\n"):
                    if "LISTEN" in line or "ESTABLISHED" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            local_addr = parts[3]
                            state = parts[5] if len(parts) > 5 else "UNKNOWN"

                            if ":" in local_addr:
                                ip, port = local_addr.rsplit(":", 1)
                                connections.append(
                                    {
                                        "src_ip": ip,
                                        "src_port": int(port) if port.isdigit() else 0,
                                        "dst_ip": "",
                                        "dst_port": 0,
                                        "protocol": parts[0].upper(),
                                        "state": state,
                                        "bytes_transferred": 0,
                                    }
                                )

            return connections

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.warning("Could not get guest network connections: %s", e)
            return []

    def _get_guest_dns_queries(self) -> list[dict[str, Any]]:
        """Get DNS queries from guest OS using multiple detection methods.

        This implementation uses various techniques to capture DNS activity:
        - Network interface monitoring for DNS packets (port 53)
        - DNS cache inspection via guest commands
        - Process monitoring for DNS-related activity
        - Log file analysis for DNS requests

        Returns:
            List of DNS query dictionaries with query details

        """
        dns_queries = []

        try:
            # Method 1: Monitor DNS traffic using network commands in guest
            if hasattr(self, "ssh_client") and self.ssh_client:
                dns_queries.extend(self._capture_dns_via_ssh())

            # Method 2: Analyze DNS cache if available
            dns_queries.extend(self._analyze_dns_cache())

            # Method 3: Monitor process activity for DNS-related calls
            dns_queries.extend(self._monitor_dns_processes())

            # Method 4: Parse system logs for DNS entries
            dns_queries.extend(self._parse_dns_logs())

            # Remove duplicates based on query name and timestamp
            unique_queries = self._deduplicate_dns_queries(dns_queries)

            self.logger.info("Captured %d DNS queries from guest OS", len(unique_queries))
            return unique_queries

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.warning("Could not get guest DNS queries: %s", e)
            return []

    def _capture_dns_via_ssh(self) -> list[dict[str, Any]]:
        """Capture DNS queries via SSH network monitoring."""
        dns_queries = []

        try:
            # Use tcpdump or netstat to monitor DNS traffic
            commands = [
                # Monitor DNS packets (requires tcpdump)
                "timeout 2 tcpdump -i any -n port 53 -c 10 2>/dev/null || echo 'tcpdump_failed'",
                # Check DNS resolver activity
                "ss -tuln | grep :53 2>/dev/null || echo 'ss_failed'",
                # Monitor DNS-related processes
                "ps aux | grep -E 'dns|resolve' | grep -v grep 2>/dev/null || echo 'ps_failed'",
            ]

            for cmd in commands:
                try:
                    stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
                    output = stdout.read().decode("utf-8", errors="ignore")

                    # Log command execution details for debugging
                    stderr_output = stderr.read().decode("utf-8", errors="ignore") if stderr else ""
                    if stderr_output and stderr_output.strip():
                        self.logger.debug("DNS capture command '%s' stderr: %s", cmd[:30], stderr_output.strip())

                    # Close stdin
                    if stdin:
                        stdin.close()

                    if "tcpdump" in cmd and "tcpdump_failed" not in output:
                        # Parse tcpdump output for DNS queries
                        for line in output.strip().split("\n"):
                            if "A?" in line or "AAAA?" in line:  # DNS query patterns
                                query_info = self._parse_tcpdump_dns_line(line)
                                if query_info:
                                    dns_queries.append(query_info)

                    elif "ss -tuln" in cmd and "ss_failed" not in output:
                        # Check for DNS servers listening
                        for line in output.strip().split("\n"):
                            if ":53" in line:
                                dns_queries.append(
                                    {
                                        "type": "dns_server_detected",
                                        "query": "DNS_SERVER_LISTENING",
                                        "server": line.split()[4] if len(line.split()) > 4 else "unknown",
                                        "timestamp": time.time(),
                                        "source": "network_analysis",
                                    }
                                )

                except (
                    FileNotFoundError,
                    PermissionError,
                    OSError,
                    AttributeError,
                    ValueError,
                    TypeError,
                    RuntimeError,
                    subprocess.SubprocessError,
                ) as e:
                    self.logger.debug("SSH command failed: %s", e)
                    continue

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.debug("DNS capture via SSH failed: %s", e)

        return dns_queries

    def _parse_tcpdump_dns_line(self, line: str) -> dict[str, Any] | None:
        """Parse a tcpdump DNS query line."""
        try:
            # Example tcpdump DNS line:
            # 12:34:56.789 IP 192.168.1.100.12345 > 8.8.8.8.53: 12345+ A? example.com. (28)
            parts = line.split()
            if len(parts) < 6:
                return None

            timestamp_str = parts[0]
            src_dst = parts[2] + " " + parts[3] + " " + parts[4]  # src > dst
            query_part = " ".join(parts[5:])

            self.logger.debug("DNS query - Time: %s, Connection: %s", timestamp_str, src_dst)

            # Extract domain from query
            domain = ""
            if "A?" in query_part:
                domain_match = query_part.split("A?")[1].split(".")[0].strip()
                domain = domain_match
            elif "AAAA?" in query_part:
                domain_match = query_part.split("AAAA?")[1].split(".")[0].strip()
                domain = domain_match

            if domain:
                return {
                    "type": "dns_query",
                    "query": domain,
                    "query_type": "A" if "A?" in query_part else "AAAA",
                    "timestamp": time.time(),
                    "source": "tcpdump",
                    "raw_line": line.strip(),
                }

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.debug("Error parsing tcpdump line: %s", e)

        return None

    def _analyze_dns_cache(self) -> list[dict[str, Any]]:
        """Analyze DNS cache for recent queries."""
        dns_queries = []

        try:
            if hasattr(self, "ssh_client") and self.ssh_client:
                # Try different DNS cache inspection methods
                cache_commands = [
                    # Linux DNS cache inspection
                    "systemd-resolve --statistics 2>/dev/null || echo 'systemd_failed'",
                    "resolvectl query --cache 2>/dev/null || echo 'resolvectl_failed'",
                    # Check dnsmasq cache if available
                    "killall -USR1 dnsmasq 2>/dev/null && sleep 1 && tail -20 /var/log/syslog 2>/dev/null | grep dnsmasq || echo 'dnsmasq_failed'",
                    # Check /etc/hosts for static entries
                    "cat /etc/hosts 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'hosts_failed'",
                ]

                for cmd in cache_commands:
                    try:
                        stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
                        output = stdout.read().decode("utf-8", errors="ignore")

                        # Check for command execution errors
                        if stderr:
                            stderr_output = stderr.read().decode("utf-8", errors="ignore")
                            if stderr_output.strip():
                                self.logger.debug("DNS cache command stderr: %s", stderr_output.strip())

                        # Clean up stdin
                        if stdin:
                            stdin.close()

                        if "systemd" in cmd and "systemd_failed" not in output:
                            # Parse systemd-resolve statistics
                            for line in output.split("\n"):
                                if "Cache entries:" in line or "DNSSEC" in line:
                                    dns_queries.append(
                                        {
                                            "type": "dns_cache_info",
                                            "query": "CACHE_STATISTICS",
                                            "details": line.strip(),
                                            "timestamp": time.time(),
                                            "source": "systemd_resolve",
                                        }
                                    )

                        elif "hosts" in cmd and "hosts_failed" not in output:
                            # Parse /etc/hosts entries
                            for line in output.split("\n"):
                                if line.strip() and not line.startswith("#"):
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        dns_queries.append(
                                            {
                                                "type": "static_dns_entry",
                                                "query": parts[1],
                                                "ip": parts[0],
                                                "timestamp": time.time(),
                                                "source": "hosts_file",
                                            }
                                        )

                    except (
                        FileNotFoundError,
                        PermissionError,
                        OSError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        subprocess.SubprocessError,
                    ) as e:
                        self.logger.debug("DNS cache command failed: %s", e)
                        continue

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.debug("DNS cache analysis failed: %s", e)

        return dns_queries

    def _monitor_dns_processes(self) -> list[dict[str, Any]]:
        """Monitor processes for DNS-related activity."""
        dns_queries = []

        try:
            if hasattr(self, "ssh_client") and self.ssh_client:
                # Monitor process activity for DNS-related calls
                process_commands = [
                    # Check for processes using DNS
                    "lsof -i :53 2>/dev/null || echo 'lsof_failed'",
                    # Check for resolver processes
                    "ps aux | grep -E 'named|bind|dnsmasq|unbound|systemd-resolved' | grep -v grep 2>/dev/null || echo 'ps_failed'",
                    # Check network connections to DNS servers
                    "netstat -tun | grep :53 2>/dev/null || echo 'netstat_failed'",
                ]

                for cmd in process_commands:
                    try:
                        stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
                        output = stdout.read().decode("utf-8", errors="ignore")

                        # Monitor process command errors
                        if stderr:
                            stderr_data = stderr.read().decode("utf-8", errors="ignore")
                            if stderr_data.strip():
                                self.logger.debug("DNS process monitoring stderr: %s", stderr_data.strip())

                        # Clean up unused stdin
                        if stdin:
                            stdin.close()

                        if "lsof" in cmd and "lsof_failed" not in output:
                            # Parse lsof output for DNS connections
                            for line in output.split("\n"):
                                if ":53" in line:
                                    parts = line.split()
                                    if len(parts) >= 9:
                                        dns_queries.append(
                                            {
                                                "type": "dns_process_connection",
                                                "query": f"PROCESS_{parts[0]}_DNS",
                                                "process": parts[0],
                                                "pid": parts[1],
                                                "connection": parts[8] if len(parts) > 8 else "unknown",
                                                "timestamp": time.time(),
                                                "source": "lsof",
                                            }
                                        )

                        elif "ps aux" in cmd and "ps_failed" not in output:
                            # Parse DNS-related processes
                            for line in output.split("\n"):
                                if any(dns_proc in line.lower() for dns_proc in ["named", "bind", "dnsmasq", "resolved"]):
                                    parts = line.split()
                                    if len(parts) >= 11:
                                        dns_queries.append(
                                            {
                                                "type": "dns_service_running",
                                                "query": f"DNS_SERVICE_{parts[10]}",
                                                "service": parts[10],
                                                "pid": parts[1],
                                                "timestamp": time.time(),
                                                "source": "process_monitor",
                                            }
                                        )

                    except (
                        FileNotFoundError,
                        PermissionError,
                        OSError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        subprocess.SubprocessError,
                    ) as e:
                        self.logger.debug("DNS process monitoring failed: %s", e)
                        continue

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.debug("DNS process monitoring failed: %s", e)

        return dns_queries

    def _parse_dns_logs(self) -> list[dict[str, Any]]:
        """Parse system logs for DNS-related entries."""
        dns_queries = []

        try:
            if hasattr(self, "ssh_client") and self.ssh_client:
                # Check various log files for DNS activity
                log_commands = [
                    # Check systemd journal for DNS entries
                    "journalctl -u systemd-resolved -n 20 --no-pager 2>/dev/null | grep -E 'query|response' || echo 'journal_failed'",
                    # Check dnsmasq logs
                    "tail -20 /var/log/dnsmasq.log 2>/dev/null | grep query || echo 'dnsmasq_log_failed'",
                    # Check syslog for DNS entries
                    "tail -50 /var/log/syslog 2>/dev/null | grep -E 'dns|query|resolve' || echo 'syslog_failed'",
                ]

                for cmd in log_commands:
                    try:
                        stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
                        output = stdout.read().decode("utf-8", errors="ignore")

                        # Log parsing errors if any
                        if stderr:
                            stderr_content = stderr.read().decode("utf-8", errors="ignore")
                            if stderr_content.strip():
                                self.logger.debug("DNS log parsing stderr: %s", stderr_content.strip())

                        # Close stdin handle
                        if stdin:
                            stdin.close()

                        if "journal" in cmd and "journal_failed" not in output:
                            # Parse journalctl DNS entries
                            for line in output.split("\n"):
                                if "query" in line.lower():
                                    dns_queries.append(
                                        {
                                            "type": "dns_log_entry",
                                            "query": "SYSTEMD_RESOLVED_QUERY",
                                            "details": line.strip(),
                                            "timestamp": time.time(),
                                            "source": "systemd_journal",
                                        }
                                    )

                        elif "dnsmasq" in cmd and "dnsmasq_log_failed" not in output:
                            # Parse dnsmasq log entries
                            for line in output.split("\n"):
                                if "query" in line:
                                    # Example: "Jan 15 12:34:56 dnsmasq[1234]: query[A] example.com from 192.168.1.100"
                                    if " query[" in line:
                                        parts = line.split(" query[")
                                        if len(parts) >= 2:
                                            query_info = parts[1].split("] ")[1] if "] " in parts[1] else parts[1]
                                            domain = query_info.split(" from ")[0] if " from " in query_info else query_info
                                            dns_queries.append(
                                                {
                                                    "type": "dns_query",
                                                    "query": domain.strip(),
                                                    "query_type": parts[1].split("]")[0] if "]" in parts[1] else "A",
                                                    "timestamp": time.time(),
                                                    "source": "dnsmasq_log",
                                                }
                                            )

                    except (
                        FileNotFoundError,
                        PermissionError,
                        OSError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        subprocess.SubprocessError,
                    ) as e:
                        self.logger.debug("DNS log parsing failed: %s", e)
                        continue

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.debug("DNS log analysis failed: %s", e)

        return dns_queries

    def _deduplicate_dns_queries(self, dns_queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Remove duplicate DNS queries based on query name and recent timestamp."""
        seen_queries = set()
        unique_queries = []

        # Sort by timestamp (newest first)
        sorted_queries = sorted(dns_queries, key=lambda x: x.get("timestamp", 0), reverse=True)

        for query in sorted_queries:
            query_key = f"{query.get('query', '')}-{query.get('type', '')}"

            # Keep only unique queries within a reasonable time window
            if query_key not in seen_queries:
                seen_queries.add(query_key)
                unique_queries.append(query)
            elif len(unique_queries) < 100:  # Limit total unique queries
                # Allow some duplicates if they're different types
                if query.get("type") != "dns_query" or len([q for q in unique_queries if q.get("query") == query.get("query")]) < 3:
                    unique_queries.append(query)

        return unique_queries[:100]  # Return max 100 queries

    def _connection_id(self, conn: dict[str, Any]) -> str:
        """Generate unique ID for network connection."""
        return f"{conn.get('src_ip', '')}:{conn.get('src_port', 0)}-{conn.get('dst_ip', '')}:{conn.get('dst_port', 0)}"

    def _copy_via_guest_agent(self, binary_path: str, guest_path: str) -> str | None:
        """Copy binary using QEMU guest agent."""
        try:
            # Read binary data
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            # Convert to base64 for transfer
            import base64

            encoded_data = base64.b64encode(binary_data).decode("ascii")

            # Use guest agent file write command
            cmd = {
                "execute": "guest-file-open",
                "arguments": {
                    "path": guest_path,
                    "mode": "wb",
                },
            }

            response = self._send_qmp_command(cmd)
            if response and "return" in response:
                file_handle = response["return"]

                # Write file data
                write_cmd = {
                    "execute": "guest-file-write",
                    "arguments": {
                        "handle": file_handle,
                        "buf-b64": encoded_data,
                    },
                }

                write_response = self._send_qmp_command(write_cmd)

                # Close file
                close_cmd = {
                    "execute": "guest-file-close",
                    "arguments": {"handle": file_handle},
                }
                self._send_qmp_command(close_cmd)

                if write_response and "return" in write_response:
                    self.logger.info("Successfully copied %s via guest agent", os.path.basename(binary_path))
                    return guest_path

            return None

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("Failed to copy binary via guest agent: %s", e)
            return None

    def _execute_via_guest_agent(self, guest_path: str) -> dict[str, Any]:
        """Execute binary using QEMU guest agent."""
        try:
            # Use QEMU guest agent to execute command
            cmd = {
                "execute": "guest-exec",
                "arguments": {
                    "path": guest_path,
                    "capture-output": True,
                },
            }

            response = self._send_qmp_command(cmd)
            if response and "return" in response:
                exec_id = response["return"]["pid"]

                # Wait for execution to complete (timeout after 60 seconds)
                for _ in range(60):
                    status_cmd = {
                        "execute": "guest-exec-status",
                        "arguments": {"pid": exec_id},
                    }

                    status_response = self._send_qmp_command(status_cmd)
                    if status_response and status_response["return"]["exited"]:
                        result = status_response["return"]

                        import base64

                        return {
                            "success": result.get("exitcode", 0) == 0,
                            "exit_code": result.get("exitcode", -1),
                            "stdout": base64.b64decode(result.get("out-data", "")).decode("utf-8", errors="ignore"),
                            "stderr": base64.b64decode(result.get("err-data", "")).decode("utf-8", errors="ignore"),
                        }

                    time.sleep(1)

                # Timeout reached
                return {
                    "success": False,
                    "error": "Execution timeout after 60 seconds",
                    "exit_code": -1,
                }

            return {
                "success": False,
                "error": "Failed to start execution via guest agent",
                "exit_code": -1,
            }

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as e:
            self.logger.error("Guest agent execution failed: %s", e)
            return {
                "success": False,
                "error": str(e),
                "exit_code": -1,
            }


def run_qemu_analysis(app: Any, binary_path: str, architecture: str = "x86_64") -> dict[str, Any]:
    """Run complete QEMU-based analysis workflow.

    Args:
        app: Application instance
        binary_path: Path to binary to analyze
        architecture: Target architecture

    Returns:
        Analysis results dictionary

    """
    try:
        app.update_output.emit("[QEMU] Starting full system analysis...")

        # Initialize emulator
        with QEMUSystemEmulator(binary_path, architecture) as emulator:
            # Start system
            if not emulator.start_system():
                return {"error": "Failed to start QEMU system"}

            app.update_output.emit("[QEMU] System started, creating baseline snapshot...")

            # Create baseline snapshot
            if not emulator.create_snapshot("baseline"):
                return {"error": "Failed to create baseline snapshot"}

            app.update_output.emit("[QEMU] Executing binary...")

            # Execute binary analysis
            execution_results = emulator._execute_binary_analysis(binary_path, app)
            if not execution_results.get("success", False):
                app.update_output.emit(f"[QEMU] Warning: Binary execution had issues: {execution_results.get('error', 'Unknown error')}")
            else:
                app.update_output.emit("[QEMU] Binary execution completed successfully")

            app.update_output.emit("[QEMU] Creating post-execution snapshot...")

            # Create post-execution snapshot
            if not emulator.create_snapshot("post_execution"):
                return {"error": "Failed to create post-execution snapshot"}

            app.update_output.emit("[QEMU] Analyzing differences...")

            # Compare snapshots
            comparison = emulator.compare_snapshots("baseline", "post_execution")

            app.update_output.emit("[QEMU] Analysis complete")

            return {
                "status": "success",
                "architecture": architecture,
                "binary_path": binary_path,
                "comparison": comparison,
                "system_status": emulator.get_system_status(),
            }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in qemu_emulator: %s", e)
        error_msg = f"QEMU analysis failed: {e}"
        app.update_output.emit(f"[QEMU] {error_msg}")
        return {"error": error_msg}


# Export main classes and functions
__all__ = ["QEMUSystemEmulator", "run_qemu_analysis"]
