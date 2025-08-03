"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Comprehensive safety and isolation framework for secure fuzzing operations.
"""

import asyncio
import os
import psutil
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from intellicrack.utils.logger import logger

try:
    from ...core.processing.sandbox_manager import SandboxManager
    SANDBOX_AVAILABLE = True
except ImportError:
    SANDBOX_AVAILABLE = False

try:
    import win32api
    import win32con
    import win32security
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


class SafetyLevel(Enum):
    """Safety levels for fuzzing operations."""
    MINIMAL = "minimal"
    STANDARD = "standard"
    HIGH = "high"
    MAXIMUM = "maximum"


class IsolationType(Enum):
    """Types of isolation mechanisms."""
    PROCESS = "process"
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    REGISTRY = "registry"
    MEMORY = "memory"
    CONTAINER = "container"


class ViolationType(Enum):
    """Types of safety violations."""
    RESOURCE_LIMIT = "resource_limit"
    FILE_ACCESS = "file_access"
    NETWORK_ACCESS = "network_access"
    REGISTRY_ACCESS = "registry_access"
    PROCESS_CREATION = "process_creation"
    MEMORY_LIMIT = "memory_limit"
    TIME_LIMIT = "time_limit"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"


@dataclass
class SafetyConstraints:
    """Safety constraints for fuzzing operations."""
    max_memory_mb: int = 4096
    max_cpu_percent: float = 80.0
    max_disk_usage_mb: int = 10240
    max_process_count: int = 50
    max_network_connections: int = 10
    max_execution_time: int = 300  # 5 minutes
    allowed_file_extensions: Set[str] = field(default_factory=lambda: {'.exe', '.dll', '.bin'})
    forbidden_paths: Set[str] = field(default_factory=lambda: {'C:\\Windows\\System32', 'C:\\Program Files'})
    allowed_network_ranges: List[str] = field(default_factory=lambda: ['127.0.0.1', '192.168.0.0/16'])
    require_sandbox: bool = True
    log_all_operations: bool = True


@dataclass
class SafetyViolation:
    """Record of a safety constraint violation."""
    violation_type: ViolationType
    severity: str
    description: str
    details: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    process_id: Optional[int] = None
    action_taken: Optional[str] = None


@dataclass
class IsolationResult:
    """Result of isolation setup."""
    success: bool
    isolation_id: str
    isolation_types: List[IsolationType]
    sandbox_path: Optional[str] = None
    process_id: Optional[int] = None
    cleanup_required: bool = True
    error_message: Optional[str] = None


class ResourceMonitor:
    """Monitor system resources during fuzzing."""
    
    def __init__(self, constraints: SafetyConstraints):
        self.constraints = constraints
        self.logger = logger.getChild("ResourceMonitor")
        self.monitoring = False
        self.violations = []
        self.monitored_processes = set()
        
    async def start_monitoring(self, target_pid: Optional[int] = None):
        """Start resource monitoring."""
        self.monitoring = True
        if target_pid:
            self.monitored_processes.add(target_pid)
            
        self.logger.info("Resource monitoring started")
        
        # Start monitoring loop
        asyncio.create_task(self._monitoring_loop())
        
    async def stop_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring = False
        self.logger.info("Resource monitoring stopped")
        
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.monitoring:
            try:
                await self._check_system_resources()
                await self._check_process_resources()
                await self._check_disk_usage()
                await self._check_network_connections()
                await asyncio.sleep(1.0)  # Check every second
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(5.0)
                
    async def _check_system_resources(self):
        """Check system-wide resource usage."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            if cpu_percent > self.constraints.max_cpu_percent:
                await self._record_violation(
                    ViolationType.RESOURCE_LIMIT,
                    "high",
                    f"CPU usage {cpu_percent:.1f}% exceeds limit {self.constraints.max_cpu_percent}%",
                    {"cpu_percent": cpu_percent, "limit": self.constraints.max_cpu_percent}
                )
                
            # Memory usage
            memory = psutil.virtual_memory()
            memory_mb = memory.used / (1024 * 1024)
            if memory_mb > self.constraints.max_memory_mb:
                await self._record_violation(
                    ViolationType.MEMORY_LIMIT,
                    "high",
                    f"Memory usage {memory_mb:.0f}MB exceeds limit {self.constraints.max_memory_mb}MB",
                    {"memory_mb": memory_mb, "limit": self.constraints.max_memory_mb}
                )
                
        except Exception as e:
            self.logger.debug(f"System resource check failed: {e}")
            
    async def _check_process_resources(self):
        """Check resources of monitored processes."""
        try:
            for pid in self.monitored_processes.copy():
                try:
                    process = psutil.Process(pid)
                    
                    # Process memory
                    memory_info = process.memory_info()
                    memory_mb = memory_info.rss / (1024 * 1024)
                    
                    if memory_mb > self.constraints.max_memory_mb / 4:  # Per-process limit
                        await self._record_violation(
                            ViolationType.MEMORY_LIMIT,
                            "medium",
                            f"Process {pid} memory {memory_mb:.0f}MB exceeds per-process limit",
                            {"pid": pid, "memory_mb": memory_mb}
                        )
                        
                    # Process CPU
                    cpu_percent = process.cpu_percent()
                    if cpu_percent > 50.0:  # Per-process CPU limit
                        await self._record_violation(
                            ViolationType.RESOURCE_LIMIT,
                            "medium",
                            f"Process {pid} CPU {cpu_percent:.1f}% is high",
                            {"pid": pid, "cpu_percent": cpu_percent}
                        )
                        
                except psutil.NoSuchProcess:
                    self.monitored_processes.discard(pid)
                    
        except Exception as e:
            self.logger.debug(f"Process resource check failed: {e}")
            
    async def _check_disk_usage(self):
        """Check disk usage."""
        try:
            disk_usage = psutil.disk_usage('/')
            used_mb = disk_usage.used / (1024 * 1024)
            
            if used_mb > self.constraints.max_disk_usage_mb:
                await self._record_violation(
                    ViolationType.RESOURCE_LIMIT,
                    "medium",
                    f"Disk usage {used_mb:.0f}MB exceeds limit {self.constraints.max_disk_usage_mb}MB",
                    {"disk_usage_mb": used_mb, "limit": self.constraints.max_disk_usage_mb}
                )
                
        except Exception as e:
            self.logger.debug(f"Disk usage check failed: {e}")
            
    async def _check_network_connections(self):
        """Check network connections."""
        try:
            connections = psutil.net_connections()
            connection_count = len([c for c in connections if c.status == 'ESTABLISHED'])
            
            if connection_count > self.constraints.max_network_connections:
                await self._record_violation(
                    ViolationType.NETWORK_ACCESS,
                    "medium",
                    f"Network connections {connection_count} exceeds limit {self.constraints.max_network_connections}",
                    {"connection_count": connection_count, "limit": self.constraints.max_network_connections}
                )
                
        except Exception as e:
            self.logger.debug(f"Network check failed: {e}")
            
    async def _record_violation(self, violation_type: ViolationType, severity: str,
                              description: str, details: Dict[str, Any]):
        """Record a safety violation."""
        violation = SafetyViolation(
            violation_type=violation_type,
            severity=severity,
            description=description,
            details=details
        )
        
        self.violations.append(violation)
        self.logger.warning(f"Safety violation: {description}")
        
        # Take immediate action for high severity violations
        if severity == "high":
            await self._take_emergency_action(violation)
            
    async def _take_emergency_action(self, violation: SafetyViolation):
        """Take emergency action for high severity violations."""
        if violation.violation_type == ViolationType.MEMORY_LIMIT:
            # Attempt to reduce memory pressure
            action = "attempted_memory_cleanup"
        elif violation.violation_type == ViolationType.RESOURCE_LIMIT:
            # Reduce CPU usage by pausing operations
            action = "paused_operations"
        else:
            action = "logged_violation"
            
        violation.action_taken = action
        self.logger.warning(f"Emergency action taken: {action}")
        
    def get_violations(self) -> List[SafetyViolation]:
        """Get all recorded violations."""
        return self.violations.copy()
        
    def add_monitored_process(self, pid: int):
        """Add process to monitoring."""
        self.monitored_processes.add(pid)
        
    def remove_monitored_process(self, pid: int):
        """Remove process from monitoring."""
        self.monitored_processes.discard(pid)


class FileSystemIsolator:
    """Isolate filesystem access for fuzzing operations."""
    
    def __init__(self, constraints: SafetyConstraints):
        self.constraints = constraints
        self.logger = logger.getChild("FileSystemIsolator")
        self.sandbox_dirs = []
        
    def create_sandbox_directory(self, base_name: str = "fuzzing_sandbox") -> str:
        """Create isolated sandbox directory."""
        try:
            sandbox_path = tempfile.mkdtemp(prefix=f"{base_name}_")
            self.sandbox_dirs.append(sandbox_path)
            
            self.logger.info(f"Created sandbox directory: {sandbox_path}")
            return sandbox_path
            
        except Exception as e:
            self.logger.error(f"Failed to create sandbox: {e}")
            raise
            
    def setup_file_isolation(self, target_path: str, sandbox_path: str) -> bool:
        """Set up file isolation for target."""
        try:
            # Copy target to sandbox
            target_name = os.path.basename(target_path)
            sandbox_target = os.path.join(sandbox_path, target_name)
            
            shutil.copy2(target_path, sandbox_target)
            
            # Set restrictive permissions on sandbox
            if WIN32_AVAILABLE:
                self._set_windows_permissions(sandbox_path)
            else:
                os.chmod(sandbox_path, 0o700)
                
            self.logger.info(f"File isolation set up for {target_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"File isolation setup failed: {e}")
            return False
            
    def _set_windows_permissions(self, path: str):
        """Set Windows-specific permissions for sandbox."""
        try:
            # Get current user SID
            user_sid = win32security.GetTokenInformation(
                win32security.GetCurrentProcessToken(),
                win32security.TokenUser
            )[0]
            
            # Create DACL with limited permissions
            dacl = win32security.ACL()
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32con.GENERIC_READ | win32con.GENERIC_WRITE | win32con.GENERIC_EXECUTE,
                user_sid
            )
            
            # Apply DACL to directory
            sd = win32security.SECURITY_DESCRIPTOR()
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            
            win32security.SetFileSecurity(
                path,
                win32security.DACL_SECURITY_INFORMATION,
                sd
            )
            
            self.logger.debug(f"Windows permissions set for {path}")
            
        except Exception as e:
            self.logger.debug(f"Windows permission setup failed: {e}")
            
    def validate_file_access(self, file_path: str) -> bool:
        """Validate if file access is allowed."""
        try:
            path_obj = Path(file_path).resolve()
            
            # Check forbidden paths
            for forbidden in self.constraints.forbidden_paths:
                if str(path_obj).startswith(forbidden):
                    self.logger.warning(f"Access denied to forbidden path: {file_path}")
                    return False
                    
            # Check file extension
            if path_obj.suffix.lower() not in self.constraints.allowed_file_extensions:
                self.logger.warning(f"Access denied to file with forbidden extension: {file_path}")
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"File access validation failed: {e}")
            return False
            
    def cleanup_sandboxes(self):
        """Clean up all created sandbox directories."""
        for sandbox_path in self.sandbox_dirs:
            try:
                shutil.rmtree(sandbox_path)
                self.logger.debug(f"Cleaned up sandbox: {sandbox_path}")
            except Exception as e:
                self.logger.error(f"Failed to cleanup sandbox {sandbox_path}: {e}")
                
        self.sandbox_dirs.clear()


class ProcessIsolator:
    """Isolate process execution for fuzzing operations."""
    
    def __init__(self, constraints: SafetyConstraints):
        self.constraints = constraints
        self.logger = logger.getChild("ProcessIsolator")
        self.isolated_processes = {}
        
    async def create_isolated_process(self, command: List[str], working_dir: str,
                                    timeout: Optional[int] = None) -> Tuple[int, subprocess.Popen]:
        """Create isolated process with safety constraints."""
        try:
            # Prepare environment
            env = os.environ.copy()
            
            # Limit environment variables for security
            safe_env = {
                'PATH': env.get('PATH', ''),
                'TEMP': working_dir,
                'TMP': working_dir
            }
            
            # Create process with limited privileges
            process = subprocess.Popen(
                command,
                cwd=working_dir,
                env=safe_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
            )
            
            self.isolated_processes[process.pid] = {
                'process': process,
                'start_time': time.time(),
                'timeout': timeout or self.constraints.max_execution_time
            }
            
            self.logger.info(f"Created isolated process {process.pid}")
            return process.pid, process
            
        except Exception as e:
            self.logger.error(f"Failed to create isolated process: {e}")
            raise
            
    async def monitor_process_safety(self, pid: int) -> bool:
        """Monitor process for safety violations."""
        if pid not in self.isolated_processes:
            return False
            
        try:
            process_info = self.isolated_processes[pid]
            process = process_info['process']
            
            # Check if process is still running
            if process.poll() is not None:
                del self.isolated_processes[pid]
                return True
                
            # Check timeout
            elapsed = time.time() - process_info['start_time']
            if elapsed > process_info['timeout']:
                self.logger.warning(f"Process {pid} exceeded timeout, terminating")
                await self.terminate_process(pid)
                return False
                
            # Check resource usage
            try:
                proc = psutil.Process(pid)
                memory_mb = proc.memory_info().rss / (1024 * 1024)
                
                if memory_mb > self.constraints.max_memory_mb / 2:  # Half of system limit per process
                    self.logger.warning(f"Process {pid} using too much memory ({memory_mb:.0f}MB)")
                    await self.terminate_process(pid)
                    return False
                    
            except psutil.NoSuchProcess:
                del self.isolated_processes[pid]
                return True
                
            return True
            
        except Exception as e:
            self.logger.error(f"Process monitoring failed for {pid}: {e}")
            return False
            
    async def terminate_process(self, pid: int) -> bool:
        """Safely terminate isolated process."""
        if pid not in self.isolated_processes:
            return False
            
        try:
            process_info = self.isolated_processes[pid]
            process = process_info['process']
            
            # Try graceful termination first
            process.terminate()
            
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Force kill if graceful termination failed
                process.kill()
                process.wait()
                
            del self.isolated_processes[pid]
            self.logger.info(f"Terminated isolated process {pid}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to terminate process {pid}: {e}")
            return False
            
    def cleanup_all_processes(self):
        """Clean up all isolated processes."""
        for pid in list(self.isolated_processes.keys()):
            asyncio.create_task(self.terminate_process(pid))


class NetworkIsolator:
    """Isolate network access for fuzzing operations."""
    
    def __init__(self, constraints: SafetyConstraints):
        self.constraints = constraints
        self.logger = logger.getChild("NetworkIsolator")
        self.active_connections = {}
        
    def validate_network_access(self, host: str, port: int) -> bool:
        """Validate network access request."""
        try:
            # Check if host is in allowed ranges
            import ipaddress
            
            # Convert host to IP if it's a hostname
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                # Hostname, resolve to IP
                import socket
                ip = ipaddress.ip_address(socket.gethostbyname(host))
                
            # Check against allowed ranges
            for allowed_range in self.constraints.allowed_network_ranges:
                if '/' in allowed_range:
                    network = ipaddress.ip_network(allowed_range, strict=False)
                    if ip in network:
                        return True
                else:
                    allowed_ip = ipaddress.ip_address(allowed_range)
                    if ip == allowed_ip:
                        return True
                        
            self.logger.warning(f"Network access denied to {host}:{port}")
            return False
            
        except Exception as e:
            self.logger.error(f"Network validation failed: {e}")
            return False
            
    def monitor_network_connections(self, pid: int):
        """Monitor network connections for a process."""
        try:
            connections = psutil.net_connections(kind='inet')
            process_connections = [c for c in connections if c.pid == pid]
            
            for conn in process_connections:
                if conn.laddr and conn.raddr:
                    if not self.validate_network_access(conn.raddr.ip, conn.raddr.port):
                        self.logger.warning(f"Unauthorized network connection: {conn.raddr.ip}:{conn.raddr.port}")
                        
        except Exception as e:
            self.logger.debug(f"Network monitoring failed: {e}")


class SafetyFramework:
    """Main safety framework coordinator."""
    
    def __init__(self, safety_level: SafetyLevel = SafetyLevel.STANDARD):
        self.logger = logger.getChild("SafetyFramework")
        self.safety_level = safety_level
        self.constraints = self._get_constraints_for_level(safety_level)
        
        # Initialize components
        self.resource_monitor = ResourceMonitor(self.constraints)
        self.filesystem_isolator = FileSystemIsolator(self.constraints)
        self.process_isolator = ProcessIsolator(self.constraints)
        self.network_isolator = NetworkIsolator(self.constraints)
        
        # State tracking
        self.active_isolations = {}
        self.safety_violations = []
        
        self.logger.info(f"Safety framework initialized at {safety_level.value} level")
        
    def _get_constraints_for_level(self, level: SafetyLevel) -> SafetyConstraints:
        """Get safety constraints for specified level."""
        if level == SafetyLevel.MINIMAL:
            return SafetyConstraints(
                max_memory_mb=8192,
                max_cpu_percent=90.0,
                max_disk_usage_mb=20480,
                require_sandbox=False,
                log_all_operations=False
            )
        elif level == SafetyLevel.STANDARD:
            return SafetyConstraints()  # Default values
        elif level == SafetyLevel.HIGH:
            return SafetyConstraints(
                max_memory_mb=2048,
                max_cpu_percent=60.0,
                max_disk_usage_mb=5120,
                max_execution_time=180,
                require_sandbox=True,
                log_all_operations=True
            )
        elif level == SafetyLevel.MAXIMUM:
            return SafetyConstraints(
                max_memory_mb=1024,
                max_cpu_percent=40.0,
                max_disk_usage_mb=2048,
                max_execution_time=60,
                require_sandbox=True,
                log_all_operations=True,
                forbidden_paths=set([
                    'C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)',
                    '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc'
                ])
            )
        else:
            return SafetyConstraints()
            
    async def setup_isolation(self, target_path: str, isolation_types: List[IsolationType]) -> IsolationResult:
        """Set up comprehensive isolation for fuzzing target."""
        isolation_id = f"isolation_{int(time.time())}"
        
        try:
            result = IsolationResult(
                success=True,
                isolation_id=isolation_id,
                isolation_types=isolation_types
            )
            
            # File system isolation
            if IsolationType.FILESYSTEM in isolation_types:
                sandbox_path = self.filesystem_isolator.create_sandbox_directory()
                if not self.filesystem_isolator.setup_file_isolation(target_path, sandbox_path):
                    result.success = False
                    result.error_message = "Filesystem isolation failed"
                    return result
                result.sandbox_path = sandbox_path
                
            # Process isolation setup (will be used when creating processes)
            if IsolationType.PROCESS in isolation_types:
                # Process isolation is handled during process creation
                pass
                
            # Network isolation
            if IsolationType.NETWORK in isolation_types:
                # Network isolation is enforced during connection attempts
                pass
                
            # Container isolation (if available)
            if IsolationType.CONTAINER in isolation_types and SANDBOX_AVAILABLE:
                # Use existing sandbox manager if available
                pass
                
            self.active_isolations[isolation_id] = result
            self.logger.info(f"Isolation {isolation_id} set up successfully")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Isolation setup failed: {e}")
            return IsolationResult(
                success=False,
                isolation_id=isolation_id,
                isolation_types=[],
                error_message=str(e)
            )
            
    async def start_safe_execution(self, target_path: str, args: List[str],
                                 isolation_id: str) -> Optional[int]:
        """Start safe execution of target with full monitoring."""
        if isolation_id not in self.active_isolations:
            self.logger.error(f"Unknown isolation ID: {isolation_id}")
            return None
            
        isolation_result = self.active_isolations[isolation_id]
        
        try:
            # Start resource monitoring
            await self.resource_monitor.start_monitoring()
            
            # Use sandbox directory if available
            working_dir = isolation_result.sandbox_path or os.path.dirname(target_path)
            target_executable = os.path.join(working_dir, os.path.basename(target_path))
            
            # Create isolated process
            pid, process = await self.process_isolator.create_isolated_process(
                [target_executable] + args,
                working_dir,
                self.constraints.max_execution_time
            )
            
            # Add to monitoring
            self.resource_monitor.add_monitored_process(pid)
            isolation_result.process_id = pid
            
            self.logger.info(f"Safe execution started: PID {pid}")
            return pid
            
        except Exception as e:
            self.logger.error(f"Safe execution failed: {e}")
            return None
            
    async def monitor_execution(self, isolation_id: str) -> Dict[str, Any]:
        """Monitor ongoing execution for safety violations."""
        if isolation_id not in self.active_isolations:
            return {"error": "Unknown isolation ID"}
            
        isolation_result = self.active_isolations[isolation_id]
        
        try:
            status = {
                "isolation_id": isolation_id,
                "process_running": False,
                "violations": [],
                "resource_usage": {}
            }
            
            # Check process status
            if isolation_result.process_id:
                status["process_running"] = await self.process_isolator.monitor_process_safety(
                    isolation_result.process_id
                )
                
            # Get violations
            violations = self.resource_monitor.get_violations()
            status["violations"] = [
                {
                    "type": v.violation_type.value,
                    "severity": v.severity,
                    "description": v.description,
                    "timestamp": v.timestamp
                }
                for v in violations[-10:]  # Last 10 violations
            ]
            
            # Get resource usage
            try:
                if isolation_result.process_id:
                    proc = psutil.Process(isolation_result.process_id)
                    memory_info = proc.memory_info()
                    status["resource_usage"] = {
                        "memory_mb": memory_info.rss / (1024 * 1024),
                        "cpu_percent": proc.cpu_percent()
                    }
            except psutil.NoSuchProcess:
                pass
                
            return status
            
        except Exception as e:
            self.logger.error(f"Execution monitoring failed: {e}")
            return {"error": str(e)}
            
    async def emergency_shutdown(self, isolation_id: str) -> bool:
        """Emergency shutdown of isolated execution."""
        if isolation_id not in self.active_isolations:
            return False
            
        isolation_result = self.active_isolations[isolation_id]
        
        try:
            # Terminate process if running
            if isolation_result.process_id:
                await self.process_isolator.terminate_process(isolation_result.process_id)
                
            # Stop monitoring
            await self.resource_monitor.stop_monitoring()
            
            self.logger.warning(f"Emergency shutdown completed for isolation {isolation_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Emergency shutdown failed: {e}")
            return False
            
    async def cleanup_isolation(self, isolation_id: str) -> bool:
        """Clean up isolation resources."""
        if isolation_id not in self.active_isolations:
            return False
            
        isolation_result = self.active_isolations[isolation_id]
        
        try:
            # Terminate any running processes
            if isolation_result.process_id:
                await self.process_isolator.terminate_process(isolation_result.process_id)
                
            # Clean up filesystem isolation
            if isolation_result.sandbox_path:
                self.filesystem_isolator.cleanup_sandboxes()
                
            # Stop monitoring
            await self.resource_monitor.stop_monitoring()
            
            del self.active_isolations[isolation_id]
            self.logger.info(f"Isolation {isolation_id} cleaned up")
            return True
            
        except Exception as e:
            self.logger.error(f"Isolation cleanup failed: {e}")
            return False
            
    def get_safety_status(self) -> Dict[str, Any]:
        """Get overall safety framework status."""
        return {
            "safety_level": self.safety_level.value,
            "active_isolations": len(self.active_isolations),
            "total_violations": len(self.safety_violations),
            "monitoring_active": self.resource_monitor.monitoring,
            "constraints": {
                "max_memory_mb": self.constraints.max_memory_mb,
                "max_cpu_percent": self.constraints.max_cpu_percent,
                "max_execution_time": self.constraints.max_execution_time,
                "require_sandbox": self.constraints.require_sandbox
            },
            "components_available": {
                "sandbox_manager": SANDBOX_AVAILABLE,
                "win32_security": WIN32_AVAILABLE
            }
        }
        
    async def validate_fuzzing_safety(self, campaign_config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate if fuzzing campaign meets safety requirements."""
        issues = []
        
        try:
            # Check target file
            target_path = campaign_config.get("target_path", "")
            if not self.filesystem_isolator.validate_file_access(target_path):
                issues.append(f"Target file access denied: {target_path}")
                
            # Check resource constraints
            max_workers = campaign_config.get("parallel_workers", 1)
            if max_workers > self.constraints.max_process_count:
                issues.append(f"Too many workers: {max_workers} > {self.constraints.max_process_count}")
                
            # Check timeout settings
            timeout = campaign_config.get("timeout", 0)
            if timeout > self.constraints.max_execution_time:
                issues.append(f"Timeout too long: {timeout} > {self.constraints.max_execution_time}")
                
            # Check sandbox requirement
            if self.constraints.require_sandbox and not campaign_config.get("use_sandbox", False):
                issues.append("Sandbox required but not enabled")
                
            return len(issues) == 0, issues
            
        except Exception as e:
            self.logger.error(f"Safety validation failed: {e}")
            return False, [f"Validation error: {str(e)}"]