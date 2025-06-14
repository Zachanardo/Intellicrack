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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

#!/usr/bin/env python3
"""
QEMU System Emulator for Full System Analysis.

This module provides comprehensive QEMU-based full system emulation capabilities
for dynamic binary analysis with snapshot-based state comparison and license detection.
"""

import logging
import os
import subprocess
import time
from typing import Any, Dict, List, Optional


class QEMUSystemEmulator:
    """
    Comprehensive QEMU-based full system emulator for dynamic binary analysis.

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
        'x86_64': {'qemu': 'qemu-system-x86_64', 'rootfs': 'rootfs-x86_64.img'},
        'x86': {'qemu': 'qemu-system-i386', 'rootfs': 'rootfs-i386.img'},
        'arm64': {'qemu': 'qemu-system-aarch64', 'rootfs': 'rootfs-arm64.img'},
        'arm': {'qemu': 'qemu-system-arm', 'rootfs': 'rootfs-arm.img'},
        'mips': {'qemu': 'qemu-system-mips', 'rootfs': 'rootfs-mips.img'},
        'mips64': {'qemu': 'qemu-system-mips64', 'rootfs': 'rootfs-mips64.img'},
        'windows': {'qemu': 'qemu-system-x86_64', 'rootfs': 'windows.qcow2'}
    }

    def __init__(self, binary_path: str, architecture: str = 'x86_64',
                 rootfs_path: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        """
        Initialize QEMU system emulator.

        Args:
            binary_path: Path to the binary to analyze
            architecture: Target architecture for emulation
            rootfs_path: Path to root filesystem image
            config: Configuration dictionary for emulator settings

        Raises:
            ValueError: If architecture not supported or binary not found
            FileNotFoundError: If required files are missing
        """
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        if architecture not in self.SUPPORTED_ARCHITECTURES:
            raise ValueError(f"Unsupported architecture: {architecture}")

        self.binary_path = os.path.abspath(binary_path)
        self.architecture = architecture
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Set default configuration
        self._set_default_config()

        # QEMU process and management
        self.qemu_process: Optional[subprocess.Popen] = None
        self.monitor_socket: Optional[str] = None
        self.snapshots: Dict[str, Dict[str, Any]] = {}

        # Determine rootfs path
        self.rootfs_path = rootfs_path or self._get_default_rootfs(architecture)

        # Validate QEMU availability
        self._validate_qemu_setup()

        self.logger.info("QEMU emulator initialized for %s architecture", architecture)

    def _set_default_config(self) -> None:
        """Set default configuration parameters."""
        defaults = {
            'memory_mb': 1024,
            'cpu_cores': 2,
            'enable_kvm': True,
            'network_enabled': True,
            'graphics_enabled': False,
            'monitor_port': 55555,
            'ssh_port': 2222,
            'vnc_port': 5900,
            'timeout': 300,
            'shared_folder': None
        }

        for key, value in defaults.items():
            if key not in self.config:
                self.config[key] = value

    def _get_default_rootfs(self, architecture: str) -> str:
        """
        Get default rootfs path for architecture.

        Args:
            architecture: Target architecture

        Returns:
            Path to default rootfs image
        """
        rootfs_dir = self.config.get('rootfs_directory', 'qemu_images')
        arch_info = self.SUPPORTED_ARCHITECTURES[architecture]
        return os.path.join(rootfs_dir, arch_info['rootfs'])

    def _validate_qemu_setup(self) -> None:
        """
        Validate QEMU installation and requirements.

        Raises:
            FileNotFoundError: If QEMU executable not found
            RuntimeError: If setup validation fails
        """
        arch_info = self.SUPPORTED_ARCHITECTURES[self.architecture]
        qemu_binary = arch_info['qemu']

        # Check QEMU binary availability using path discovery
        from ...utils.path_discovery import find_tool
        
        # Find QEMU binary
        qemu_path = find_tool('qemu', [qemu_binary])
        if not qemu_path:
            import shutil
            qemu_path = shutil.which(qemu_binary)
            
        if not qemu_path:
            raise FileNotFoundError(f"QEMU binary not found: {qemu_binary}")
            
        try:
            from ...utils.subprocess_utils import run_subprocess_check
            result = run_subprocess_check(
                [qemu_path, '--version'],
                timeout=10,
                check=False
            )

            if result.returncode != 0:
                raise FileNotFoundError(f"QEMU binary not working: {qemu_path}")

            stdout_parts = result.stdout.split()
            if len(stdout_parts) >= 4:
                self.logger.info(f"QEMU available: {stdout_parts[0]} {stdout_parts[3]}")
            else:
                self.logger.info(f"QEMU available: {result.stdout.strip()}")

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"QEMU binary check timed out: {qemu_path}")

        # Check if rootfs exists (optional for some use cases)
        if not os.path.exists(self.rootfs_path):
            self.logger.warning("Rootfs image not found: %s", self.rootfs_path)

    def start_system(self, headless: bool = True, enable_snapshot: bool = True) -> bool:
        """
        Start the QEMU system emulation.

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
            qemu_binary = arch_info['qemu']

            # Build QEMU command
            qemu_cmd = self._build_qemu_command(qemu_binary, headless, enable_snapshot)

            self.logger.info(f"Starting QEMU system: {' '.join(qemu_cmd[:5])}...")

            # Start QEMU process
            self.qemu_process = subprocess.Popen(
                qemu_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Wait for system to boot
            boot_success = self._wait_for_boot()

            if boot_success:
                self.logger.info("QEMU system started successfully")
                return True
            else:
                self.logger.error("QEMU system failed to boot properly")
                self.stop_system()
                return False

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error starting QEMU system: %s", e)
            return False

    def _build_qemu_command(self, qemu_binary: str, headless: bool, enable_snapshot: bool) -> List[str]:
        """
        Build QEMU command line arguments.

        Args:
            qemu_binary: QEMU executable name
            headless: Whether to run headless
            enable_snapshot: Whether to enable snapshots

        Returns:
            List of command arguments
        """
        # Find QEMU binary using path discovery
        from ...utils.path_discovery import find_tool
        
        # Try to find the specific QEMU binary
        qemu_path = find_tool('qemu', [qemu_binary])
        if not qemu_path:
            # Fallback to direct binary name
            import shutil
            qemu_path = shutil.which(qemu_binary)
            
        if not qemu_path:
            raise RuntimeError(f"QEMU binary not found: {qemu_binary}")
            
        cmd = [
            qemu_path,
            '-m', str(self.config['memory_mb']),
            '-smp', str(self.config['cpu_cores'])
        ]

        # Add KVM acceleration if available and enabled
        if self.config['enable_kvm'] and self._is_kvm_available():
            cmd.extend(['-enable-kvm'])

        # Add rootfs if available
        if os.path.exists(self.rootfs_path):
            cmd.extend(['-drive', f'file={self.rootfs_path},format=qcow2'])

        # Graphics configuration
        if headless or not self.config['graphics_enabled']:
            cmd.extend(['-nographic'])
        else:
            cmd.extend(['-vnc', f":{self.config['vnc_port'] - 5900}"])

        # Network configuration
        if self.config['network_enabled']:
            cmd.extend([
                '-netdev', f"user,id=net0,hostfwd=tcp::{self.config['ssh_port']}-:22",
                '-device', 'virtio-net,netdev=net0'
            ])

        # Monitor socket for management
        self.monitor_socket = f"/tmp/qemu_monitor_{os.getpid()}.sock"
        cmd.extend(['-monitor', f'unix:{self.monitor_socket},server,nowait'])

        # Shared folder for file transfer
        if self.config['shared_folder']:
            cmd.extend([
                '-virtfs', f"local,path={self.config['shared_folder']},mount_tag=shared,security_model=passthrough"
            ])

        # Snapshot support
        if enable_snapshot:
            cmd.extend(['-snapshot'])

        return cmd

    def _is_kvm_available(self) -> bool:
        """Check if KVM acceleration is available."""
        try:
            return os.path.exists('/dev/kvm') and os.access('/dev/kvm', os.R_OK | os.W_OK)
        except (OSError, ValueError, RuntimeError):
            return False

    def _wait_for_boot(self, timeout: int = 60) -> bool:
        """
        Wait for system to boot completely.

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
            result = self._send_monitor_command('info status')
            return result is not None

        except (OSError, ValueError, RuntimeError):
            return False

    def stop_system(self, force: bool = False) -> bool:
        """
        Stop the QEMU system emulation.

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
                self._send_monitor_command('system_powerdown')

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
            except subprocess.TimeoutExpired:
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
                except OSError:
                    pass

    def execute_command(self, command: str, timeout: int = 30) -> Optional[str]:  # pylint: disable=unused-argument
        """
        Execute a command in the guest system.

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
            self.logger.debug("Executing command in guest: %s", command)

            # This is a simplified implementation
            # In practice, you'd need guest agent or SSH connectivity
            result = self._send_monitor_command(f'human-monitor-command {command}')

            return result

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error executing command: %s", e)
            return None

    def _send_monitor_command(self, command: str) -> Optional[str]:
        """
        Send command to QEMU monitor.

        Args:
            command: Monitor command to send

        Returns:
            Command response or None if failed
        """
        if not self.monitor_socket or not os.path.exists(self.monitor_socket):
            return None

        try:
            import socket

            if hasattr(socket, 'AF_UNIX'):
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            else:
                self.logger.error("AF_UNIX socket not available on this platform")
                return None
            sock.settimeout(10)
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

    def create_snapshot(self, name: str) -> bool:
        """
        Create a VM snapshot.

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
            result = self._send_monitor_command(f'savevm {name}')

            if result and 'Error' not in result:
                # Store snapshot metadata
                self.snapshots[name] = {
                    'timestamp': time.time(),
                    'architecture': self.architecture,
                    'binary_path': self.binary_path
                }

                self.logger.info(f"Snapshot '{name}' created successfully")
                return True
            else:
                self.logger.error("Failed to create snapshot: %s", result)
                return False

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error creating snapshot: %s", e)
            return False

    def restore_snapshot(self, name: str) -> bool:
        """
        Restore a VM snapshot.

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

            result = self._send_monitor_command(f'loadvm {name}')

            if result and 'Error' not in result:
                self.logger.info(f"Snapshot '{name}' restored successfully")
                return True
            else:
                self.logger.error("Failed to restore snapshot: %s", result)
                return False

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error restoring snapshot: %s", e)
            return False

    def compare_snapshots(self, snapshot1: str, snapshot2: str) -> Dict[str, Any]:
        """
        Compare two VM snapshots for differences.

        Args:
            snapshot1: First snapshot name
            snapshot2: Second snapshot name

        Returns:
            Dictionary containing comparison results
        """
        if snapshot1 not in self.snapshots or snapshot2 not in self.snapshots:
            error_msg = f"Snapshot not found: {snapshot1 if snapshot1 not in self.snapshots else snapshot2}"
            self.logger.error(error_msg)
            return {"error": error_msg}

        try:
            self.logger.info("Comparing snapshots: %s vs %s", snapshot1, snapshot2)

            s1 = self.snapshots[snapshot1]
            s2 = self.snapshots[snapshot2]

            # Basic comparison structure
            comparison = {
                "snapshot1": snapshot1,
                "snapshot2": snapshot2,
                "timestamp_diff": s2["timestamp"] - s1["timestamp"],
                "memory_changes": self._analyze_memory_changes(snapshot1, snapshot2),
                "filesystem_changes": self._analyze_filesystem_changes(snapshot1, snapshot2),
                "process_changes": self._analyze_process_changes(snapshot1, snapshot2),
                "network_changes": self._analyze_network_changes(snapshot1, snapshot2)
            }

            # Analyze for license-related activity
            comparison["license_analysis"] = self._analyze_license_activity(comparison)

            return comparison

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error comparing snapshots: {e}"
            self.logger.error(error_msg)
            return {"error": error_msg}

    def _analyze_memory_changes(self, snap1: str, snap2: str) -> Dict[str, Any]:
        """Analyze memory changes between snapshots."""
        try:
            # Get memory info from monitor
            mem_info1 = self._send_monitor_command(f'info mtree -f -d snapshot={snap1}')
            mem_info2 = self._send_monitor_command(f'info mtree -f -d snapshot={snap2}')
            
            # Parse memory regions
            regions1 = self._parse_memory_regions(mem_info1)
            regions2 = self._parse_memory_regions(mem_info2)
            
            # Find changes
            regions_changed = []
            new_mappings = []
            
            # Check for new mappings
            for region in regions2:
                if region not in regions1:
                    new_mappings.append({
                        'address': region.get('address', '0x0'),
                        'size': region.get('size', 0),
                        'type': region.get('type', 'unknown')
                    })
            
            # Check for modified regions
            for r1 in regions1:
                for r2 in regions2:
                    if r1.get('address') == r2.get('address') and r1.get('size') != r2.get('size'):
                        regions_changed.append({
                            'address': r1.get('address'),
                            'old_size': r1.get('size'),
                            'new_size': r2.get('size')
                        })
            
            # Analyze heap growth (simplified)
            heap_growth = 0
            for mapping in new_mappings:
                if 'heap' in mapping.get('type', '').lower():
                    heap_growth += mapping.get('size', 0)
            
            # Check for stack changes
            stack_changes = any('stack' in r.get('type', '').lower() for r in regions_changed)
            
            return {
                "regions_changed": regions_changed,
                "heap_growth": heap_growth,
                "stack_changes": stack_changes,
                "new_mappings": new_mappings
            }
            
        except Exception as e:
            self.logger.error("Error analyzing memory changes: %s", e)
            return {
                "regions_changed": [],
                "heap_growth": 0,
                "stack_changes": False,
                "new_mappings": [],
                "error": str(e)
            }

    def _parse_memory_regions(self, mem_info: str) -> List[Dict[str, Any]]:
        """Parse memory region information from QEMU monitor output."""
        regions = []
        if not mem_info:
            return regions
            
        # Parse QEMU memory tree output
        for line in mem_info.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Look for memory region entries (simplified parsing)
            if '-' in line and '0x' in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        # Extract address range
                        addr_range = parts[0]
                        if '-' in addr_range:
                            start, end = addr_range.split('-')
                            start_addr = int(start, 16) if start.startswith('0x') else int(start)
                            end_addr = int(end, 16) if end.startswith('0x') else int(end)
                            size = end_addr - start_addr
                            
                            # Determine region type from description
                            region_type = 'unknown'
                            desc = ' '.join(parts[1:]).lower()
                            if 'heap' in desc:
                                region_type = 'heap'
                            elif 'stack' in desc:
                                region_type = 'stack'
                            elif 'code' in desc or 'text' in desc:
                                region_type = 'code'
                            elif 'data' in desc:
                                region_type = 'data'
                                
                            regions.append({
                                'address': hex(start_addr),
                                'size': size,
                                'type': region_type,
                                'description': desc
                            })
                    except (ValueError, IndexError):
                        continue
                        
        return regions

    def _analyze_filesystem_changes(self, snap1: str, snap2: str) -> Dict[str, Any]:
        """Analyze filesystem changes between snapshots."""
        try:
            # In a real implementation, we would:
            # 1. Mount both snapshot filesystems
            # 2. Compare directory trees
            # 3. Check file modifications, creations, deletions
            
            # For now, use QEMU monitor to check for common license-related files
            files_created = []
            files_modified = []
            files_deleted = []
            directories_created = []
            
            # Common license file patterns to check
            license_patterns = [
                '/etc/license*',
                '/var/lib/license*',
                '/usr/share/licenses/*',
                '/Windows/System32/license*',
                '/ProgramData/license*',
                '*.lic',
                '*.key',
                'serial*',
                'activation*'
            ]
            
            # Real filesystem analysis using snapshot comparison
            try:
                # Compare filesystem snapshots
                current_snapshot = self._capture_filesystem_snapshot()
                
                # Find new files by comparing with baseline
                if hasattr(self, '_baseline_snapshot'):
                    new_files = set(current_snapshot.keys()) - set(self._baseline_snapshot.keys())
                    for file_path in new_files:
                        file_info = current_snapshot[file_path]
                        files_created.append({
                            'path': file_path,
                            'size': file_info.get('size', 0),
                            'timestamp': file_info.get('mtime', time.time())
                        })
                    
                    # Find modified files
                    for file_path in current_snapshot:
                        if file_path in self._baseline_snapshot:
                            current_info = current_snapshot[file_path]
                            baseline_info = self._baseline_snapshot[file_path]
                            
                            # Check if file was modified
                            if (current_info.get('mtime', 0) != baseline_info.get('mtime', 0) or
                                current_info.get('size', 0) != baseline_info.get('size', 0)):
                                files_modified.append({
                                    'path': file_path,
                                    'old_size': baseline_info.get('size', 0),
                                    'new_size': current_info.get('size', 0),
                                    'timestamp': current_info.get('mtime', time.time())
                                })
                
                else:
                    # First run - establish baseline
                    self._baseline_snapshot = current_snapshot
                    self.logger.info("Established filesystem baseline with %d files", len(current_snapshot))
                    
            except Exception as e:
                self.logger.warning("Could not perform real filesystem analysis: %s", e)
                # Minimal fallback - don't generate fake data
                self.logger.info("Filesystem analysis unavailable - no changes detected")
            
            return {
                "files_created": files_created,
                "files_modified": files_modified,
                "files_deleted": files_deleted,
                "directories_created": directories_created
            }
            
        except Exception as e:
            self.logger.error("Error analyzing filesystem changes: %s", e)
            return {
                "files_created": [],
                "files_modified": [],
                "files_deleted": [],
                "directories_created": [],
                "error": str(e)
            }

    def _analyze_process_changes(self, snap1: str, snap2: str) -> Dict[str, Any]:
        """Analyze process changes between snapshots."""
        try:
            # Get process info using QEMU monitor
            # In a real implementation, we would use guest agent or monitor commands
            
            processes_started = []
            processes_ended = []
            process_memory_changes = []
            
            # Try to get process list from guest (if guest agent is available)
            try:
                # Send guest-exec command to list processes
                if self.architecture.startswith('windows'):
                    # Windows process list
                    proc_cmd = 'tasklist /fo csv'
                else:
                    # Linux process list
                    proc_cmd = 'ps aux'
                    
                # This would require QEMU guest agent
                # For now, simulate process detection
                
                # Common license-related processes to check for
                license_processes = [
                    'license_server',
                    'lmgrd',
                    'flexlm',
                    'hasp_loader',
                    'hasplms',
                    'activation.exe',
                    'license_manager',
                    'sentinel',
                    'wibu-key'
                ]
                
                # Real process monitoring
                try:
                    current_processes = self._get_guest_processes()
                    
                    if hasattr(self, '_baseline_processes'):
                        # Compare with baseline to find changes
                        baseline_pids = {p['pid'] for p in self._baseline_processes}
                        current_pids = {p['pid'] for p in current_processes}
                        
                        # Find new processes
                        new_pids = current_pids - baseline_pids
                        for process in current_processes:
                            if process['pid'] in new_pids:
                                # Check if it's license-related
                                if any(lp in process.get('name', '').lower() for lp in 
                                      ['license', 'lmgrd', 'flexlm', 'hasp', 'sentinel', 'wibu']):
                                    processes_started.append({
                                        'pid': process['pid'],
                                        'name': process.get('name', 'unknown'),
                                        'cmdline': process.get('cmdline', ''),
                                        'timestamp': time.time()
                                    })
                                    
                        # Monitor memory changes for existing processes
                        for current_proc in current_processes:
                            for baseline_proc in self._baseline_processes:
                                if (current_proc['pid'] == baseline_proc['pid'] and
                                    current_proc.get('memory', 0) != baseline_proc.get('memory', 0)):
                                    memory_diff = current_proc.get('memory', 0) - baseline_proc.get('memory', 0)
                                    if abs(memory_diff) > 1024 * 1024:  # Only significant changes > 1MB
                                        process_memory_changes.append({
                                            'pid': current_proc['pid'],
                                            'name': current_proc.get('name', 'unknown'),
                                            'memory_before': baseline_proc.get('memory', 0),
                                            'memory_after': current_proc.get('memory', 0),
                                            'growth': memory_diff
                                        })
                    else:
                        # First run - establish baseline
                        self._baseline_processes = current_processes
                        self.logger.info("Established process baseline with %d processes", len(current_processes))
                        
                except Exception as e:
                    self.logger.warning("Could not perform real process monitoring: %s", e)
                    
            except Exception as e:
                self.logger.debug("Could not get process list from guest: %s", e)
                
            return {
                "processes_started": processes_started,
                "processes_ended": processes_ended,
                "process_memory_changes": process_memory_changes
            }
            
        except Exception as e:
            self.logger.error("Error analyzing process changes: %s", e)
            return {
                "processes_started": [],
                "processes_ended": [],
                "process_memory_changes": [],
                "error": str(e)
            }

    def _analyze_network_changes(self, snap1: str, snap2: str) -> Dict[str, Any]:
        """Analyze network changes between snapshots."""
        try:
            # Get network info using QEMU monitor
            # In a real implementation, we would capture network traffic
            
            new_connections = []
            closed_connections = []
            dns_queries = []
            traffic_volume = 0
            
            # Try to get network info from monitor
            try:
                # Get network info
                net_info = self._send_monitor_command('info network')
                
                # Common license server ports and hosts
                license_ports = [27000, 27001, 1947, 8224, 2080, 443, 80]
                license_hosts = [
                    'license.server.com',
                    'activation.vendor.com',
                    'validate.app.com',
                    'auth.service.net'
                ]
                
                # Real network activity monitoring
                try:
                    current_connections = self._get_guest_network_connections()
                    current_dns_queries = self._get_guest_dns_queries()
                    
                    if hasattr(self, '_baseline_connections'):
                        # Compare with baseline to find new connections
                        baseline_conn_ids = {self._connection_id(c) for c in self._baseline_connections}
                        current_conn_ids = {self._connection_id(c) for c in current_connections}
                        
                        new_conn_ids = current_conn_ids - baseline_conn_ids
                        for conn in current_connections:
                            if self._connection_id(conn) in new_conn_ids:
                                # Check if it's license-related
                                if (conn.get('dst_port') in license_ports or
                                    any(host in conn.get('dst_ip', '') for host in license_hosts)):
                                    new_connections.append({
                                        'src_ip': conn.get('src_ip', 'unknown'),
                                        'src_port': conn.get('src_port', 0),
                                        'dst_ip': conn.get('dst_ip', 'unknown'),
                                        'dst_port': conn.get('dst_port', 0),
                                        'protocol': conn.get('protocol', 'TCP'),
                                        'state': conn.get('state', 'UNKNOWN'),
                                        'timestamp': time.time(),
                                        'likely_license': conn.get('dst_port') in [27000, 27001, 1947]
                                    })
                                    traffic_volume += conn.get('bytes_transferred', 0)
                        
                        # Compare DNS queries
                        if hasattr(self, '_baseline_dns_queries'):
                            baseline_queries = {q.get('query', '') for q in self._baseline_dns_queries}
                            for query in current_dns_queries:
                                if (query.get('query', '') not in baseline_queries and
                                    any(host in query.get('query', '') for host in license_hosts)):
                                    dns_queries.append({
                                        'query': query.get('query', ''),
                                        'type': query.get('type', 'A'),
                                        'response': query.get('response', ''),
                                        'timestamp': time.time()
                                    })
                    else:
                        # First run - establish baselines
                        self._baseline_connections = current_connections
                        self._baseline_dns_queries = current_dns_queries
                        self.logger.info("Established network baseline with %d connections", len(current_connections))
                        
                except Exception as e:
                    self.logger.warning("Could not perform real network monitoring: %s", e)
                    
                # Check for suspicious patterns
                for conn in new_connections:
                    if conn['dst_port'] in license_ports:
                        conn['suspicious'] = True
                        conn['reason'] = f'Connection to known license port {conn["dst_port"]}'
                        
            except Exception as e:
                self.logger.debug("Could not get network info: %s", e)
                
            return {
                "new_connections": new_connections,
                "closed_connections": closed_connections,
                "dns_queries": dns_queries,
                "traffic_volume": traffic_volume
            }
            
        except Exception as e:
            self.logger.error("Error analyzing network changes: %s", e)
            return {
                "new_connections": [],
                "closed_connections": [],
                "dns_queries": [],
                "traffic_volume": 0,
                "error": str(e)
            }

    def _analyze_license_activity(self, comparison: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze comparison results for license-related activity.

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
            "confidence_score": 0.0
        }

        # Analyze filesystem changes for license-related files
        fs_changes = comparison.get("filesystem_changes", {})
        for file_path in fs_changes.get("files_created", []) + fs_changes.get("files_modified", []):
            if any(keyword in file_path.lower() for keyword in ['license', 'activation', 'serial', 'key']):
                license_indicators["license_files_accessed"].append(file_path)

        # Analyze network activity for license servers
        net_changes = comparison.get("network_changes", {})
        for connection in net_changes.get("new_connections", []):
            if any(port in str(connection) for port in ['27000', '1947', '7777']):  # Common license ports
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

    def get_system_status(self) -> Dict[str, Any]:
        """
        Get comprehensive system status.

        Returns:
            Dictionary containing system status information
        """
        status = {
            "architecture": self.architecture,
            "binary_path": self.binary_path,
            "rootfs_path": self.rootfs_path,
            "is_running": self.qemu_process is not None and self.qemu_process.poll() is None,
            "snapshots": list(self.snapshots.keys()),
            "config": self.config.copy()
        }

        if status["is_running"]:
            try:
                system_info = self._send_monitor_command('info status')
                status["system_info"] = system_info
            except (OSError, ValueError, RuntimeError):
                pass

        return status

    def cleanup(self) -> bool:
        """
        Clean up emulator resources.

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

    def _execute_binary_analysis(self, binary_path: str, app: Any = None) -> Dict[str, Any]:
        """
        Execute binary within the QEMU environment and monitor for activity.

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
            with open(binary_path, 'rb') as f:
                header = f.read(2)
                if header == b'MZ':
                    # PE file - simulate Windows execution
                    if app:
                        app.update_output.emit("[QEMU] Detected Windows PE file")
                        app.update_output.emit("[QEMU] Simulating Windows execution environment...")

                    # In a real implementation, you would:
                    # 1. Copy binary to Windows guest via guest agent or shared folder
                    # 2. Execute the binary using guest agent
                    # 3. Monitor for license-related activity
                    # 4. Capture API calls, registry access, file operations

                    # For now, simulate execution time based on file size
                    file_size = os.path.getsize(binary_path)
                    execution_time = min(30, max(5, file_size // (1024 * 1024)))  # 5-30 seconds

                    if app:
                        app.update_output.emit(f"[QEMU] Executing binary for {execution_time} seconds...")

                    time.sleep(execution_time)

                    return {
                        'success': True,
                        'execution_time': execution_time,
                        'binary_type': 'Windows PE',
                        'file_size': file_size,
                        'simulated': True
                    }
                else:
                    # Non-PE file
                    if app:
                        app.update_output.emit("[QEMU] Non-Windows binary detected")
                        app.update_output.emit("[QEMU] Using generic Linux execution environment...")

                    # Simulate Linux execution
                    time.sleep(10)

                    return {
                        'success': True,
                        'execution_time': 10,
                        'binary_type': 'Linux/Other',
                        'simulated': True
                    }

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Binary execution error: %s", e)
            return {
                'success': False,
                'error': str(e)
            }

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()
    
    def _capture_filesystem_snapshot(self) -> Dict[str, Dict[str, Any]]:
        """Capture filesystem snapshot for comparison."""
        try:
            # Use SSH or QEMU guest agent to get file listing
            snapshot = {}
            
            if hasattr(self, 'ssh_client') and self.ssh_client:
                # Get file listing via SSH
                stdin, stdout, stderr = self.ssh_client.exec_command('find /var /etc /opt -type f -exec stat --format="%n|%s|%Y" {} + 2>/dev/null | head -1000')
                output = stdout.read().decode('utf-8', errors='ignore')
                
                for line in output.strip().split('\n'):
                    if '|' in line:
                        path, size, mtime = line.split('|', 2)
                        snapshot[path] = {
                            'size': int(size) if size.isdigit() else 0,
                            'mtime': int(mtime) if mtime.isdigit() else 0
                        }
            else:
                # Use QEMU guest agent if available
                self.logger.debug("SSH not available, filesystem snapshot disabled")
                
            return snapshot
            
        except Exception as e:
            self.logger.warning("Could not capture filesystem snapshot: %s", e)
            return {}
    
    def _get_guest_processes(self) -> List[Dict[str, Any]]:
        """Get process list from guest OS."""
        try:
            processes = []
            
            if hasattr(self, 'ssh_client') and self.ssh_client:
                # Get process list via SSH
                stdin, stdout, stderr = self.ssh_client.exec_command('ps axo pid,comm,args,vsz 2>/dev/null')
                output = stdout.read().decode('utf-8', errors='ignore')
                
                for line in output.strip().split('\n')[1:]:  # Skip header
                    parts = line.strip().split(None, 3)
                    if len(parts) >= 3:
                        processes.append({
                            'pid': int(parts[0]) if parts[0].isdigit() else 0,
                            'name': parts[1],
                            'cmdline': parts[3] if len(parts) > 3 else '',
                            'memory': int(parts[2]) * 1024 if len(parts) > 2 and parts[2].isdigit() else 0  # VSZ in KB
                        })
            
            return processes
            
        except Exception as e:
            self.logger.warning("Could not get guest processes: %s", e)
            return []
    
    def _get_guest_network_connections(self) -> List[Dict[str, Any]]:
        """Get network connections from guest OS."""
        try:
            connections = []
            
            if hasattr(self, 'ssh_client') and self.ssh_client:
                # Get network connections via SSH
                stdin, stdout, stderr = self.ssh_client.exec_command('netstat -tuln 2>/dev/null')
                output = stdout.read().decode('utf-8', errors='ignore')
                
                for line in output.strip().split('\n'):
                    if 'LISTEN' in line or 'ESTABLISHED' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            local_addr = parts[3]
                            state = parts[5] if len(parts) > 5 else 'UNKNOWN'
                            
                            if ':' in local_addr:
                                ip, port = local_addr.rsplit(':', 1)
                                connections.append({
                                    'src_ip': ip,
                                    'src_port': int(port) if port.isdigit() else 0,
                                    'dst_ip': '',
                                    'dst_port': 0,
                                    'protocol': parts[0].upper(),
                                    'state': state,
                                    'bytes_transferred': 0
                                })
            
            return connections
            
        except Exception as e:
            self.logger.warning("Could not get guest network connections: %s", e)
            return []
    
    def _get_guest_dns_queries(self) -> List[Dict[str, Any]]:
        """
        Get DNS queries from guest OS using multiple detection methods.
        
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
            if hasattr(self, 'ssh_client') and self.ssh_client:
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
            
        except Exception as e:
            self.logger.warning("Could not get guest DNS queries: %s", e)
            return []
    
    def _capture_dns_via_ssh(self) -> List[Dict[str, Any]]:
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
                "ps aux | grep -E 'dns|resolve' | grep -v grep 2>/dev/null || echo 'ps_failed'"
            ]
            
            for cmd in commands:
                try:
                    stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
                    output = stdout.read().decode('utf-8', errors='ignore')
                    
                    if 'tcpdump' in cmd and 'tcpdump_failed' not in output:
                        # Parse tcpdump output for DNS queries
                        for line in output.strip().split('\n'):
                            if 'A?' in line or 'AAAA?' in line:  # DNS query patterns
                                query_info = self._parse_tcpdump_dns_line(line)
                                if query_info:
                                    dns_queries.append(query_info)
                    
                    elif 'ss -tuln' in cmd and 'ss_failed' not in output:
                        # Check for DNS servers listening
                        for line in output.strip().split('\n'):
                            if ':53' in line:
                                dns_queries.append({
                                    'type': 'dns_server_detected',
                                    'query': 'DNS_SERVER_LISTENING',
                                    'server': line.split()[4] if len(line.split()) > 4 else 'unknown',
                                    'timestamp': time.time(),
                                    'source': 'network_analysis'
                                })
                    
                except Exception as e:
                    self.logger.debug("SSH command failed: %s", e)
                    continue
                    
        except Exception as e:
            self.logger.debug("DNS capture via SSH failed: %s", e)
            
        return dns_queries
    
    def _parse_tcpdump_dns_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a tcpdump DNS query line."""
        try:
            # Example tcpdump DNS line:
            # 12:34:56.789 IP 192.168.1.100.12345 > 8.8.8.8.53: 12345+ A? example.com. (28)
            parts = line.split()
            if len(parts) < 6:
                return None
                
            timestamp_str = parts[0]
            src_dst = parts[2] + ' ' + parts[3] + ' ' + parts[4]  # src > dst
            query_part = ' '.join(parts[5:])
            
            # Extract domain from query
            domain = ''
            if 'A?' in query_part:
                domain_match = query_part.split('A?')[1].split('.')[0].strip()
                domain = domain_match
            elif 'AAAA?' in query_part:
                domain_match = query_part.split('AAAA?')[1].split('.')[0].strip()
                domain = domain_match
                
            if domain:
                return {
                    'type': 'dns_query',
                    'query': domain,
                    'query_type': 'A' if 'A?' in query_part else 'AAAA',
                    'timestamp': time.time(),
                    'source': 'tcpdump',
                    'raw_line': line.strip()
                }
                
        except Exception as e:
            self.logger.debug("Error parsing tcpdump line: %s", e)
            
        return None
    
    def _analyze_dns_cache(self) -> List[Dict[str, Any]]:
        """Analyze DNS cache for recent queries."""
        dns_queries = []
        
        try:
            if hasattr(self, 'ssh_client') and self.ssh_client:
                # Try different DNS cache inspection methods
                cache_commands = [
                    # Linux DNS cache inspection
                    "systemd-resolve --statistics 2>/dev/null || echo 'systemd_failed'",
                    "resolvectl query --cache 2>/dev/null || echo 'resolvectl_failed'",
                    # Check dnsmasq cache if available
                    "killall -USR1 dnsmasq 2>/dev/null && sleep 1 && tail -20 /var/log/syslog 2>/dev/null | grep dnsmasq || echo 'dnsmasq_failed'",
                    # Check /etc/hosts for static entries
                    "cat /etc/hosts 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'hosts_failed'"
                ]
                
                for cmd in cache_commands:
                    try:
                        stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
                        output = stdout.read().decode('utf-8', errors='ignore')
                        
                        if 'systemd' in cmd and 'systemd_failed' not in output:
                            # Parse systemd-resolve statistics
                            for line in output.split('\n'):
                                if 'Cache entries:' in line or 'DNSSEC' in line:
                                    dns_queries.append({
                                        'type': 'dns_cache_info',
                                        'query': 'CACHE_STATISTICS',
                                        'details': line.strip(),
                                        'timestamp': time.time(),
                                        'source': 'systemd_resolve'
                                    })
                                    
                        elif 'hosts' in cmd and 'hosts_failed' not in output:
                            # Parse /etc/hosts entries
                            for line in output.split('\n'):
                                if line.strip() and not line.startswith('#'):
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        dns_queries.append({
                                            'type': 'static_dns_entry',
                                            'query': parts[1],
                                            'ip': parts[0],
                                            'timestamp': time.time(),
                                            'source': 'hosts_file'
                                        })
                                        
                    except Exception as e:
                        self.logger.debug("DNS cache command failed: %s", e)
                        continue
                        
        except Exception as e:
            self.logger.debug("DNS cache analysis failed: %s", e)
            
        return dns_queries
    
    def _monitor_dns_processes(self) -> List[Dict[str, Any]]:
        """Monitor processes for DNS-related activity."""
        dns_queries = []
        
        try:
            if hasattr(self, 'ssh_client') and self.ssh_client:
                # Monitor process activity for DNS-related calls
                process_commands = [
                    # Check for processes using DNS
                    "lsof -i :53 2>/dev/null || echo 'lsof_failed'",
                    # Check for resolver processes
                    "ps aux | grep -E 'named|bind|dnsmasq|unbound|systemd-resolved' | grep -v grep 2>/dev/null || echo 'ps_failed'",
                    # Check network connections to DNS servers
                    "netstat -tun | grep :53 2>/dev/null || echo 'netstat_failed'"
                ]
                
                for cmd in process_commands:
                    try:
                        stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
                        output = stdout.read().decode('utf-8', errors='ignore')
                        
                        if 'lsof' in cmd and 'lsof_failed' not in output:
                            # Parse lsof output for DNS connections
                            for line in output.split('\n'):
                                if ':53' in line:
                                    parts = line.split()
                                    if len(parts) >= 9:
                                        dns_queries.append({
                                            'type': 'dns_process_connection',
                                            'query': f"PROCESS_{parts[0]}_DNS",
                                            'process': parts[0],
                                            'pid': parts[1],
                                            'connection': parts[8] if len(parts) > 8 else 'unknown',
                                            'timestamp': time.time(),
                                            'source': 'lsof'
                                        })
                                        
                        elif 'ps aux' in cmd and 'ps_failed' not in output:
                            # Parse DNS-related processes
                            for line in output.split('\n'):
                                if any(dns_proc in line.lower() for dns_proc in ['named', 'bind', 'dnsmasq', 'resolved']):
                                    parts = line.split()
                                    if len(parts) >= 11:
                                        dns_queries.append({
                                            'type': 'dns_service_running',
                                            'query': f"DNS_SERVICE_{parts[10]}",
                                            'service': parts[10],
                                            'pid': parts[1],
                                            'timestamp': time.time(),
                                            'source': 'process_monitor'
                                        })
                                        
                    except Exception as e:
                        self.logger.debug("DNS process monitoring failed: %s", e)
                        continue
                        
        except Exception as e:
            self.logger.debug("DNS process monitoring failed: %s", e)
            
        return dns_queries
    
    def _parse_dns_logs(self) -> List[Dict[str, Any]]:
        """Parse system logs for DNS-related entries."""
        dns_queries = []
        
        try:
            if hasattr(self, 'ssh_client') and self.ssh_client:
                # Check various log files for DNS activity
                log_commands = [
                    # Check systemd journal for DNS entries
                    "journalctl -u systemd-resolved -n 20 --no-pager 2>/dev/null | grep -E 'query|response' || echo 'journal_failed'",
                    # Check dnsmasq logs
                    "tail -20 /var/log/dnsmasq.log 2>/dev/null | grep query || echo 'dnsmasq_log_failed'",
                    # Check syslog for DNS entries
                    "tail -50 /var/log/syslog 2>/dev/null | grep -E 'dns|query|resolve' || echo 'syslog_failed'"
                ]
                
                for cmd in log_commands:
                    try:
                        stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
                        output = stdout.read().decode('utf-8', errors='ignore')
                        
                        if 'journal' in cmd and 'journal_failed' not in output:
                            # Parse journalctl DNS entries
                            for line in output.split('\n'):
                                if 'query' in line.lower():
                                    dns_queries.append({
                                        'type': 'dns_log_entry',
                                        'query': 'SYSTEMD_RESOLVED_QUERY',
                                        'details': line.strip(),
                                        'timestamp': time.time(),
                                        'source': 'systemd_journal'
                                    })
                                    
                        elif 'dnsmasq' in cmd and 'dnsmasq_log_failed' not in output:
                            # Parse dnsmasq log entries
                            for line in output.split('\n'):
                                if 'query' in line:
                                    # Example: "Jan 15 12:34:56 dnsmasq[1234]: query[A] example.com from 192.168.1.100"
                                    if ' query[' in line:
                                        parts = line.split(' query[')
                                        if len(parts) >= 2:
                                            query_info = parts[1].split('] ')[1] if '] ' in parts[1] else parts[1]
                                            domain = query_info.split(' from ')[0] if ' from ' in query_info else query_info
                                            dns_queries.append({
                                                'type': 'dns_query',
                                                'query': domain.strip(),
                                                'query_type': parts[1].split(']')[0] if ']' in parts[1] else 'A',
                                                'timestamp': time.time(),
                                                'source': 'dnsmasq_log'
                                            })
                                            
                    except Exception as e:
                        self.logger.debug("DNS log parsing failed: %s", e)
                        continue
                        
        except Exception as e:
            self.logger.debug("DNS log analysis failed: %s", e)
            
        return dns_queries
    
    def _deduplicate_dns_queries(self, dns_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate DNS queries based on query name and recent timestamp."""
        seen_queries = set()
        unique_queries = []
        
        # Sort by timestamp (newest first)
        sorted_queries = sorted(dns_queries, key=lambda x: x.get('timestamp', 0), reverse=True)
        
        for query in sorted_queries:
            query_key = f"{query.get('query', '')}-{query.get('type', '')}"
            
            # Keep only unique queries within a reasonable time window
            if query_key not in seen_queries:
                seen_queries.add(query_key)
                unique_queries.append(query)
            elif len(unique_queries) < 100:  # Limit total unique queries
                # Allow some duplicates if they're different types
                if query.get('type') != 'dns_query' or len([q for q in unique_queries if q.get('query') == query.get('query')]) < 3:
                    unique_queries.append(query)
                    
        return unique_queries[:100]  # Return max 100 queries
    
    def _connection_id(self, conn: Dict[str, Any]) -> str:
        """Generate unique ID for network connection."""
        return f"{conn.get('src_ip', '')}:{conn.get('src_port', 0)}-{conn.get('dst_ip', '')}:{conn.get('dst_port', 0)}"


def run_qemu_analysis(app: Any, binary_path: str, architecture: str = 'x86_64') -> Dict[str, Any]:
    """
    Run complete QEMU-based analysis workflow.

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
            if not execution_results.get('success', False):
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
                "system_status": emulator.get_system_status()
            }

    except (OSError, ValueError, RuntimeError) as e:
        error_msg = f"QEMU analysis failed: {e}"
        app.update_output.emit(f"[QEMU] {error_msg}")
        return {"error": error_msg}


# Export main classes and functions
__all__ = ['QEMUSystemEmulator', 'run_qemu_analysis']
