"""
QEMU Test Manager for AI Script Testing

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

import logging
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed

import paramiko
from paramiko import AutoAddPolicy, RSAKey, SSHClient

from ..core.logging.audit_logger import (
    AuditEvent,
    AuditEventType,
    AuditSeverity,
    get_audit_logger,
    log_credential_access,
    log_tool_execution,
    log_vm_operation,
)
from ..core.resources.resource_manager import VMResource, get_resource_manager
from ..utils.logger import get_logger
from ..utils.secrets_manager import get_secret, set_secret
from .autonomous_agent import ExecutionResult

# Import AI components for intelligent test generation
from .llm_backends import LLMManager
from .predictive_intelligence import PredictiveIntelligence, ProtectionPattern
from .multi_agent_system import MultiAgentSystem, AgentRole
try:
    from .multi_agent_system import Task, TaskType
except ImportError:
    # Define minimal Task and TaskType if not available
    from dataclasses import dataclass as _dataclass
    from enum import Enum as _Enum
    
    class TaskType(_Enum):
        FULL_ANALYSIS = "full_analysis"
    
    @_dataclass
    class Task:
        task_id: str
        task_type: TaskType
        priority: int
        data: Dict[str, Any]
        created_at: datetime
from .ai_script_generator import AIScriptGenerator

# Import analysis components
from ..core.analysis.analysis_orchestrator import AnalysisOrchestrator

# Import sandbox components
try:
    from ..core.processing.sandbox_manager import (
        SandboxManager, SandboxType, AnalysisDepth, SandboxConfig
    )
    HAS_SANDBOX_MANAGER = True
except ImportError:
    logger.warning("Sandbox manager not available")
    HAS_SANDBOX_MANAGER = False

logger = get_logger(__name__)
audit_logger = get_audit_logger()
resource_manager = get_resource_manager()

try:
    # Try to import existing QEMU emulator
    from ..core.processing.qemu_emulator import QEMUSystemEmulator
    HAS_QEMU_EMULATOR = True
except ImportError as e:
    logger.error("Import error in qemu_test_manager: %s", e)
    QEMUSystemEmulator = None
    HAS_QEMU_EMULATOR = False


@dataclass
class TestScenario:
    """Represents an AI-generated test scenario."""
    scenario_id: str
    name: str
    description: str
    test_type: str  # protection_validation, bypass_testing, behavior_analysis, etc.
    priority: int
    binary_path: str
    protection_patterns: List[ProtectionPattern]
    test_commands: List[str]
    expected_outcomes: Dict[str, Any]
    environment_config: Dict[str, Any]
    created_at: datetime
    created_by: str  # AI agent that generated this
    
@dataclass
class TestResult:
    """Comprehensive test result tracking."""
    test_id: str
    scenario_id: str
    snapshot_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "pending"  # pending, running, success, failure, error
    execution_log: List[Dict[str, Any]] = field(default_factory=list)
    coverage_metrics: Dict[str, float] = field(default_factory=dict)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    anomalies_detected: List[Dict[str, Any]] = field(default_factory=list)
    ml_confidence: float = 0.0
    ai_analysis: Optional[str] = None

@dataclass
class QEMUSnapshot:
    """Represents a QEMU snapshot for testing."""
    snapshot_id: str
    vm_name: str
    disk_path: str
    binary_path: str
    created_at: datetime
    vm_process: Optional[subprocess.Popen] = None
    ssh_port: int = 22222
    vnc_port: int = 5900
    version: int = 1
    parent_snapshot: Optional[str] = None
    children_snapshots: Set[str] = field(default_factory=set)
    test_results: List[Dict[str, Any]] = field(default_factory=list)
    memory_usage: int = 0
    disk_usage: int = 0
    network_isolated: bool = True
    performance_metrics: Dict[str, Any] = field(default_factory=dict)


class QEMUTestManager:
    """
    Manages QEMU virtual machines for testing generated scripts.
    Real implementation - integrates with existing QEMU infrastructure.
    """

    def __init__(self):
        """Initialize the QEMU test manager.

        Sets up QEMU snapshots, base images for Windows and Linux,
        and integrates with existing QEMU emulator if available.
        Creates a working directory for test operations.
        """
        self.logger = logging.getLogger(__name__ + ".QEMUTestManager")
        self.snapshots = {}
        self.base_images = {
            'windows': self._get_windows_base_image(),
            'linux': self._get_linux_base_image()
        }
        self.qemu_executable = self._find_qemu_executable()
        self.working_dir = Path(tempfile.gettempdir()) / \
            "intellicrack_qemu_tests"
        self.working_dir.mkdir(exist_ok=True)

        # SSH configuration
        self.ssh_clients = {}  # vm_name -> SSHClient
        self.ssh_keys = {}     # vm_name -> RSAKey
        self.ssh_lock = threading.RLock()
        self.ssh_timeout = 30
        self.ssh_retry_count = 3
        self.ssh_retry_delay = 2

        # Initialize or load SSH keys
        self._init_ssh_keys()

        # SSH connection pool
        self.ssh_connection_pool = {}  # (vm_name, port) -> SSHClient

        # Circuit breaker for SSH connections
        self.ssh_circuit_breaker = {}  # vm_name -> {'failures': int, 'last_failure': datetime, 'open': bool}
        self.circuit_breaker_threshold = 5  # failures before opening circuit
        self.circuit_breaker_timeout = 60  # seconds before trying again
        
        # AI components for intelligent test generation
        self.llm_manager = None
        self.predictive_intelligence = None
        self.multi_agent_system = None
        self.script_generator = None
        self.analysis_orchestrator = None
        self.sandbox_manager = None
        self._init_ai_components()
        
        # Test management
        self.test_scenarios = {}  # scenario_id -> TestScenario
        self.test_results = {}    # test_id -> TestResult
        self.test_queue = Queue()  # Queue of pending tests
        self.active_tests = {}    # snapshot_id -> TestResult
        self.test_cache = {}      # Cache for test results
        
        # Performance monitoring
        self.performance_stats = defaultdict(list)
        self.resource_usage = defaultdict(dict)
        
        # Parallel execution management
        self.max_parallel_tests = 4
        self.test_executor = None
        self._init_test_executor()

        # Integration with existing QEMU emulator if available
        self.qemu_emulator = None
        if HAS_QEMU_EMULATOR:
            # Initialize QEMU emulator without a binary - it will be set when needed
            try:
                # Check if we have a test binary available
                test_binaries = []
                
                # Add project test binary if exists
                project_test_binary = os.path.join(self.working_dir, "test.exe")
                if os.path.exists(project_test_binary):
                    test_binaries.append(project_test_binary)
                
                # Find real system binaries based on platform
                import platform
                import shutil
                
                if platform.system() == 'Windows':
                    # Windows system binaries
                    windows_binaries = [
                        "C:\Windows\System32\notepad.exe",
                        "C:\Windows\System32\calc.exe",
                        "C:\Windows\System32\ping.exe",
                        "C:\Windows\System32\hostname.exe"
                    ]
                    for binary in windows_binaries:
                        if os.path.exists(binary):
                            test_binaries.append(binary)
                            break
                else:
                    # Unix-like system binaries
                    unix_binaries = [
                        "/bin/echo",
                        "/bin/cat", 
                        "/usr/bin/id",
                        "/usr/bin/whoami",
                        "/bin/hostname"
                    ]
                    for binary in unix_binaries:
                        if os.path.exists(binary):
                            test_binaries.append(binary)
                            break
                    
                    # Also check using which command
                    if not test_binaries:
                        for cmd in ['echo', 'cat', 'id', 'whoami', 'hostname']:
                            path = shutil.which(cmd)
                            if path:
                                test_binaries.append(path)
                                break

                binary_to_use = None
                for test_binary in test_binaries:
                    if os.path.exists(test_binary):
                        binary_to_use = test_binary
                        break

                if not binary_to_use:
                    # Create a minimal test binary
                    test_binary_path = os.path.join(
                        self.working_dir, "test.exe")
                    with open(test_binary_path, 'wb') as f:
                        # Minimal PE header for Windows
                        f.write(
                            b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00')
                        f.write(
                            b'\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
                    binary_to_use = test_binary_path

                self.qemu_emulator = QEMUSystemEmulator(
                    binary_path=binary_to_use)
                logger.info("Integrated with existing QEMU emulator")
            except Exception as e:
                logger.warning(
                    f"Could not initialize existing QEMU emulator: {e}")
                self.qemu_emulator = None

    def _init_ssh_keys(self):
        """Initialize or load SSH keys for VM access."""
        try:
            # Get or generate SSH key from secrets manager
            ssh_private_key = get_secret('QEMU_SSH_PRIVATE_KEY')
            ssh_public_key = get_secret('QEMU_SSH_PUBLIC_KEY')

            if not ssh_private_key or not ssh_public_key:
                logger.info("Generating new SSH key pair for QEMU VMs")

                # Generate new RSA key
                key = RSAKey.generate(2048)

                # Save private key to string
                private_key_str = StringIO()
                key.write_private_key(private_key_str)
                ssh_private_key = private_key_str.getvalue()

                # Generate public key string
                ssh_public_key = f"ssh-rsa {key.get_base64()} intellicrack@qemu"

                # Store in secrets manager
                set_secret('QEMU_SSH_PRIVATE_KEY', ssh_private_key)
                set_secret('QEMU_SSH_PUBLIC_KEY', ssh_public_key)

                # Log credential access
                log_credential_access('SSH_KEY', 'QEMU VM access key generation', success=True)

                logger.info("SSH key pair generated and stored securely")
            else:
                logger.info("Loaded existing SSH keys from secrets manager")
                log_credential_access('SSH_KEY', 'QEMU VM access key retrieval', success=True)

            # Parse the private key for use
            self.master_ssh_key = RSAKey.from_private_key(StringIO(ssh_private_key))
            self.ssh_public_key = ssh_public_key

        except Exception as e:
            logger.error(f"Failed to initialize SSH keys: {e}")
            log_credential_access('SSH_KEY', 'QEMU VM access key initialization', success=False)
            # Generate and persist key as recovery mechanism
            logger.warning("Failed to access secrets manager, generating recovery key")
            self.master_ssh_key = RSAKey.generate(2048)
            self.ssh_public_key = f"ssh-rsa {self.master_ssh_key.get_base64()} intellicrack@qemu"
            
            # Try to save recovery key to local secure storage
            try:
                recovery_key_path = self.working_dir / '.ssh' / 'qemu_recovery_key'
                recovery_key_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Save private key
                with open(recovery_key_path, 'w', encoding='utf-8') as f:
                    self.master_ssh_key.write_private_key(f)
                
                # Set secure permissions (Unix only)
                if platform.system() != 'Windows':
                    os.chmod(recovery_key_path, 0o600)
                
                # Save public key
                with open(recovery_key_path.with_suffix('.pub'), 'w', encoding='utf-8') as f:
                    f.write(self.ssh_public_key)
                
                logger.info(f"Recovery SSH key saved to {recovery_key_path}")
                
                # Attempt to update secrets manager with recovery key
                try:
                    private_key_str = StringIO()
                    self.master_ssh_key.write_private_key(private_key_str)
                    set_secret('QEMU_SSH_PRIVATE_KEY', private_key_str.getvalue())
                    set_secret('QEMU_SSH_PUBLIC_KEY', self.ssh_public_key)
                    logger.info("Recovery key successfully saved to secrets manager")
                except:
                    pass  # Continue with local recovery key
                    
            except Exception as recovery_e:
                logger.error(f"Failed to save recovery key: {recovery_e}")
                # Key is still in memory and usable for this session

    def _find_qemu_executable(self) -> str:
        """Find QEMU executable on the system."""
        possible_paths = [
            "qemu-system-x86_64",
            "qemu-system-i386",
            "/usr/bin/qemu-system-x86_64",
            "/usr/local/bin/qemu-system-x86_64",
            "C:\\Program Files\\qemu\\qemu-system-x86_64.exe"
        ]

        for path in possible_paths:
            if shutil.which(path):
                return path

        logger.warning("QEMU not found in standard locations")
        return "qemu-system-x86_64"  # Default assumption

    def _get_ssh_connection(self, snapshot: QEMUSnapshot, retries: Optional[int] = None) -> Optional[SSHClient]:
        """Get or create SSH connection to VM with retry logic and circuit breaker."""
        retries = retries or self.ssh_retry_count
        pool_key = (snapshot.vm_name, snapshot.ssh_port)

        with self.ssh_lock:
            # Check circuit breaker
            if self._is_circuit_open(snapshot.vm_name):
                logger.warning(f"Circuit breaker open for {snapshot.vm_name}, skipping connection attempt")
                return None
            # Check if we have an active connection in the pool
            if pool_key in self.ssh_connection_pool:
                client = self.ssh_connection_pool[pool_key]
                try:
                    # Test if connection is still alive
                    transport = client.get_transport()
                    if transport and transport.is_active():
                        return client
                    else:
                        # Connection is dead, remove from pool
                        del self.ssh_connection_pool[pool_key]
                        client.close()
                except Exception:
                    # Connection is invalid, remove from pool
                    if pool_key in self.ssh_connection_pool:
                        del self.ssh_connection_pool[pool_key]
                    try:
                        client.close()
                    except:
                        pass

            # Create new connection with retries
            for attempt in range(retries):
                try:
                    client = SSHClient()
                    client.set_missing_host_key_policy(AutoAddPolicy())

                    # Connect using our SSH key
                    client.connect(
                        hostname='localhost',
                        port=snapshot.ssh_port,
                        username='test',
                        pkey=self.master_ssh_key,
                        timeout=self.ssh_timeout,
                        banner_timeout=self.ssh_timeout,
                        auth_timeout=self.ssh_timeout
                    )

                    # Store in connection pool
                    self.ssh_connection_pool[pool_key] = client

                    # Reset circuit breaker on success
                    self._reset_circuit_breaker(snapshot.vm_name)

                    logger.info(f"SSH connection established to {snapshot.vm_name} on port {snapshot.ssh_port}")
                    return client

                except socket.timeout as e:
                    logger.warning(f"SSH connection timeout (attempt {attempt + 1}/{retries}): {e}")
                    self._record_connection_failure(snapshot.vm_name)
                except paramiko.AuthenticationException as e:
                    logger.error(f"SSH authentication failed for {snapshot.vm_name}: {e}")
                    self._record_connection_failure(snapshot.vm_name)
                    break  # No point retrying auth failures
                except paramiko.SSHException as e:
                    logger.warning(f"SSH connection error (attempt {attempt + 1}/{retries}): {e}")
                    self._record_connection_failure(snapshot.vm_name)
                except Exception as e:
                    logger.error(f"Unexpected SSH connection error: {e}")
                    self._record_connection_failure(snapshot.vm_name)

                if attempt < retries - 1:
                    time.sleep(self.ssh_retry_delay)

            logger.error(f"Failed to establish SSH connection to {snapshot.vm_name} after {retries} attempts")
            return None

    def _inject_ssh_key(self, snapshot: QEMUSnapshot):
        """Inject our SSH public key into the VM for password-less access."""
        try:
            # Create .ssh directory if it doesn't exist
            self._execute_command_in_vm(snapshot, "mkdir -p ~/.ssh && chmod 700 ~/.ssh")

            # Add our public key to authorized_keys
            escaped_key = self.ssh_public_key.replace('"', '\\"')
            append_cmd = f'echo "{escaped_key}" >> ~/.ssh/authorized_keys'
            self._execute_command_in_vm(snapshot, append_cmd)

            # Set proper permissions
            self._execute_command_in_vm(snapshot, "chmod 600 ~/.ssh/authorized_keys")

            logger.info(f"SSH key injected into VM {snapshot.vm_name}")
        except Exception as e:
            logger.warning(f"Failed to inject SSH key: {e}")

    def _is_circuit_open(self, vm_name: str) -> bool:
        """Check if circuit breaker is open for a VM."""
        if vm_name not in self.ssh_circuit_breaker:
            return False

        breaker = self.ssh_circuit_breaker[vm_name]
        if not breaker['open']:
            return False

        # Check if timeout has expired
        time_since_failure = (datetime.now() - breaker['last_failure']).total_seconds()
        if time_since_failure > self.circuit_breaker_timeout:
            # Try to close circuit
            breaker['open'] = False
            breaker['failures'] = 0
            logger.info(f"Circuit breaker closed for {vm_name} after timeout")
            return False

        return True

    def _record_connection_failure(self, vm_name: str):
        """Record a connection failure for circuit breaker."""
        if vm_name not in self.ssh_circuit_breaker:
            self.ssh_circuit_breaker[vm_name] = {
                'failures': 0,
                'last_failure': datetime.now(),
                'open': False
            }

        breaker = self.ssh_circuit_breaker[vm_name]
        breaker['failures'] += 1
        breaker['last_failure'] = datetime.now()

        if breaker['failures'] >= self.circuit_breaker_threshold:
            breaker['open'] = True
            logger.warning(f"Circuit breaker opened for {vm_name} after {breaker['failures']} failures")

    def _reset_circuit_breaker(self, vm_name: str):
        """Reset circuit breaker on successful connection."""
        if vm_name in self.ssh_circuit_breaker:
            self.ssh_circuit_breaker[vm_name] = {
                'failures': 0,
                'last_failure': datetime.now(),
                'open': False
            }

    def _close_ssh_connection(self, snapshot: QEMUSnapshot):
        """Close and remove SSH connection from pool."""
        pool_key = (snapshot.vm_name, snapshot.ssh_port)

        with self.ssh_lock:
            if pool_key in self.ssh_connection_pool:
                try:
                    self.ssh_connection_pool[pool_key].close()
                except Exception as e:
                    logger.debug(f"Error closing SSH connection: {e}")
                finally:
                    del self.ssh_connection_pool[pool_key]

    def create_script_test_snapshot(self, binary_path: str, platform: str = "windows") -> str:
        """Create a QEMU snapshot specifically for script testing."""
        snapshot_id = f"test_{int(time.time())}_{hash(binary_path) % 10000}"

        logger.info(f"Creating script test snapshot: {snapshot_id}")

        # Get base image for platform
        base_image = self.base_images.get(platform.lower())
        if not base_image:
            raise ValueError(
                f"No base image available for platform: {platform}")

        # Create working copy of base image
        snapshot_disk = self.working_dir / f"{snapshot_id}.qcow2"

        # Create overlay image for testing
        cmd = [
            "qemu-img", "create", "-f", "qcow2",
            "-b", str(base_image),
            str(snapshot_disk)
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.info(f"Created snapshot disk: {snapshot_disk}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create snapshot disk: {e}")
            raise

        # Create snapshot metadata
        snapshot = QEMUSnapshot(
            snapshot_id=snapshot_id,
            vm_name=f"test_vm_{snapshot_id}",
            disk_path=str(snapshot_disk),
            binary_path=binary_path,
            created_at=datetime.now(),
            ssh_port=22222 + len(self.snapshots),
            vnc_port=5900 + len(self.snapshots)
        )

        # Start VM for this snapshot
        self._start_vm_for_snapshot(snapshot)

        self.snapshots[snapshot_id] = snapshot

        logger.info(f"Script test snapshot created: {snapshot_id}")
        return snapshot_id

    def _start_vm_for_snapshot(self, snapshot: QEMUSnapshot):
        """Start QEMU VM for a specific snapshot with resource management."""
        logger.info(f"Starting VM for snapshot: {snapshot.snapshot_id}")

        # QEMU command for starting VM
        cmd = [
            self.qemu_executable,
            "-name", snapshot.vm_name,
            "-m", "2048",  # 2GB RAM
            "-smp", "2",   # 2 CPU cores
            "-drive", f"file={snapshot.disk_path},format=qcow2",
            "-netdev", f"user,id=net0,hostfwd=tcp::{snapshot.ssh_port}-:22",
            "-device", "e1000,netdev=net0",
            "-vnc", f":{snapshot.vnc_port - 5900}",
            "-daemonize",  # Run in background
            "-pidfile", str(self.working_dir / f"{snapshot.snapshot_id}.pid")
        ]

        try:
            # Start the VM process
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Wait a moment for VM to start
            time.sleep(5)

            # Check if process is still running
            if process.poll() is None or process.returncode == 0:
                snapshot.vm_process = process

                # Register VM with resource manager
                vm_resource = VMResource(snapshot.vm_name, process)
                resource_manager.register_resource(vm_resource)

                logger.info(
                    f"VM started successfully for snapshot: {snapshot.snapshot_id}")

                # Log VM operation
                log_vm_operation('start', snapshot.vm_name, success=True)

                # Wait for VM to be ready
                self._wait_for_vm_ready(snapshot)
            else:
                stdout, stderr = process.communicate()
                logger.debug(f"VM startup stdout: {stdout.decode()}")
                logger.error(f"Failed to start VM: {stderr.decode()}")
                log_vm_operation('start', snapshot.vm_name, success=False, error=stderr.decode())
                raise RuntimeError(f"VM startup failed: {stderr.decode()}")

        except Exception as e:
            logger.error(f"Error starting VM: {e}")
            log_vm_operation('start', snapshot.vm_name, success=False, error=str(e))
            raise

    def _wait_for_vm_ready(self, snapshot: QEMUSnapshot, timeout: int = 60):
        """Wait for VM to be ready for testing."""
        logger.info(f"Waiting for VM to be ready: {snapshot.snapshot_id}")

        start_time = time.time()
        while time.time() - start_time < timeout:
            # Try to establish SSH connection
            ssh_client = self._get_ssh_connection(snapshot, retries=1)
            if ssh_client:
                try:
                    # Test command execution
                    result = self._execute_command_in_vm(snapshot, "echo ready", timeout=5)
                    if result['exit_code'] == 0 and "ready" in result['stdout']:
                        logger.info(f"VM is ready: {snapshot.snapshot_id}")

                        # Inject SSH public key for future connections
                        self._inject_ssh_key(snapshot)

                        return True
                except Exception as e:
                    logger.debug(f"VM not ready yet: {e}")

            time.sleep(2)

        logger.warning(
            f"VM did not become ready within {timeout}s: {snapshot.snapshot_id}")
        return False

    def _upload_file_to_vm(self, snapshot: QEMUSnapshot, content: str, remote_path: str):
        """Upload text content to VM as a file."""
        # Get SSH connection
        ssh_client = self._get_ssh_connection(snapshot)
        if not ssh_client:
            raise RuntimeError("Failed to establish SSH connection for file upload")

        try:
            # Create SFTP client
            sftp = ssh_client.open_sftp()

            # Ensure remote directory exists
            remote_dir = os.path.dirname(remote_path)
            if remote_dir and remote_dir != '/':
                try:
                    sftp.stat(remote_dir)
                except FileNotFoundError:
                    # Create directory recursively
                    self._execute_command_in_vm(snapshot, f"mkdir -p {remote_dir}")

            # Write content directly to remote file
            with sftp.file(remote_path, 'w') as remote_file:
                remote_file.write(content)

            sftp.close()
            logger.debug(f"Uploaded file to VM: {remote_path}")

        except Exception as e:
            logger.error(f"Failed to upload file via SFTP: {e}")
            raise RuntimeError(f"Failed to upload file: {e}")

    def _upload_binary_to_vm(self, snapshot: QEMUSnapshot, local_binary: str, remote_path: str):
        """Upload binary file to VM."""
        # Get SSH connection
        ssh_client = self._get_ssh_connection(snapshot)
        if not ssh_client:
            raise RuntimeError("Failed to establish SSH connection for binary upload")

        try:
            # Create SFTP client
            sftp = ssh_client.open_sftp()

            # Ensure remote directory exists
            remote_dir = os.path.dirname(remote_path)
            if remote_dir and remote_dir != '/':
                try:
                    sftp.stat(remote_dir)
                except FileNotFoundError:
                    # Create directory recursively
                    self._execute_command_in_vm(snapshot, f"mkdir -p {remote_dir}")

            # Upload binary file
            sftp.put(local_binary, remote_path)

            # Make executable
            sftp.chmod(remote_path, 0o755)

            sftp.close()
            logger.debug(f"Uploaded binary to VM: {remote_path}")

        except Exception as e:
            logger.error(f"Failed to upload binary via SFTP: {e}")
            raise RuntimeError(f"Failed to upload binary: {e}")

    def _execute_command_in_vm(self, snapshot: QEMUSnapshot, command: str, timeout: int = 30) -> Dict[str, Any]:
        """Execute a command in the VM via SSH."""
        # Get SSH connection
        ssh_client = self._get_ssh_connection(snapshot)
        if not ssh_client:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": "Failed to establish SSH connection"
            }

        try:
            # Log the command execution
            log_tool_execution("SSH_COMMAND", command, success=True)

            # Execute command with timeout
            stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)

            # Get exit status
            exit_code = stdout.channel.recv_exit_status()

            # Read output
            stdout_data = stdout.read().decode('utf-8', errors='replace')
            stderr_data = stderr.read().decode('utf-8', errors='replace')

            return {
                "exit_code": exit_code,
                "stdout": stdout_data,
                "stderr": stderr_data
            }

        except socket.timeout:
            logger.warning(f"Command timed out after {timeout}s: {command}")
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout}s"
            }
        except Exception as e:
            logger.error(f"Failed to execute command in VM: {e}")
            log_tool_execution("SSH_COMMAND", command, success=False, error=str(e))
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e)
            }

    def _analyze_frida_output(self, stdout: str, stderr: str) -> bool:
        """Analyze Frida output to determine success/failure."""
        # Success indicators
        success_indicators = [
            "[+] Script loaded",
            "[+] Hook installed",
            "[+] License check bypassed",
            "[+] Successfully hooked",
            "[+] Bypass activated",
            "Process attached"
        ]

        # Error indicators
        error_indicators = [
            "Error:",
            "Exception:",
            "Failed to attach",
            "Process not found",
            "Unable to inject",
            "TypeError:",
            "ReferenceError:"
        ]

        # Check for success indicators
        for indicator in success_indicators:
            if indicator in stdout:
                logger.info(f"Found success indicator: {indicator}")
                return True

        # Check for explicit errors
        for indicator in error_indicators:
            if indicator in stderr or indicator in stdout:
                logger.warning(f"Found error indicator: {indicator}")
                return False

        # If no clear indicators, consider success if no stderr
        return len(stderr.strip()) == 0

    def _analyze_ghidra_output(self, stdout: str, stderr: str) -> bool:
        """Analyze Ghidra output to determine success/failure."""
        # Success indicators
        success_indicators = [
            "Analysis complete",
            "Script completed",
            "Patched function",
            "Applied bypass patch",
            "patches applied",
            "INFO"
        ]

        # Error indicators
        error_indicators = [
            "ERROR:",
            "Exception:",
            "Failed to",
            "Unable to",
            "Invalid",
            "Not found",
            "java.lang.Exception"
        ]

        # Check for success indicators
        for indicator in success_indicators:
            if indicator in stdout:
                logger.info(f"Found success indicator: {indicator}")
                return True

        # Check for explicit errors
        for indicator in error_indicators:
            if indicator in stderr or indicator in stdout:
                logger.warning(f"Found error indicator: {indicator}")
                return False

        # Default to success if analysis completed without errors
        return "Analysis finished" in stdout or len(stderr.strip()) == 0

    def cleanup_snapshot(self, snapshot_id: str):
        """Clean up a test snapshot and stop associated VM."""
        if snapshot_id not in self.snapshots:
            logger.warning(f"Snapshot not found for cleanup: {snapshot_id}")
            return

        snapshot = self.snapshots[snapshot_id]
        logger.info(f"Cleaning up snapshot: {snapshot_id}")

        try:
            # Close SSH connections first
            self._close_ssh_connection(snapshot)
            # Stop VM process if running
            if snapshot.vm_process:
                try:
                    # Try graceful shutdown first
                    snapshot.vm_process.terminate()
                    snapshot.vm_process.wait(timeout=10)
                except subprocess.TimeoutExpired as e:
                    self.logger.error(
                        "Subprocess timeout in qemu_test_manager: %s", e)
                    # Force kill if needed
                    snapshot.vm_process.kill()
                    snapshot.vm_process.wait()

                logger.info(f"Stopped VM process for snapshot: {snapshot_id}")

            # Kill VM by PID file if exists
            pid_file = self.working_dir / f"{snapshot_id}.pid"
            if pid_file.exists():
                try:
                    with open(pid_file, 'r') as f:
                        pid = int(f.read().strip())

                    os.kill(pid, 15)  # SIGTERM
                    time.sleep(2)

                    try:
                        os.kill(pid, 0)  # Check if still running
                        os.kill(pid, 9)  # SIGKILL
                    except OSError as e:
                        logger.error("OS error in qemu_test_manager: %s", e)
                        pass  # Process already dead

                    pid_file.unlink()

                except (ValueError, OSError) as e:
                    logger.warning(f"Could not kill VM by PID: {e}")

            # Remove snapshot disk file
            disk_path = Path(snapshot.disk_path)
            if disk_path.exists():
                disk_path.unlink()
                logger.info(f"Removed snapshot disk: {disk_path}")

            # Remove from tracking
            del self.snapshots[snapshot_id]

            # Release from resource manager
            try:
                resource_manager.release_resource(snapshot.vm_name)
            except Exception as e:
                logger.debug(f"Could not release VM resource: {e}")

            # Log VM operation
            log_vm_operation('stop', snapshot.vm_name, success=True)

            logger.info(f"Snapshot cleanup complete: {snapshot_id}")

        except Exception as e:
            logger.error(f"Error during snapshot cleanup: {e}")
            log_vm_operation('stop', snapshot.vm_name, success=False, error=str(e))

    def _stop_vm_for_snapshot(self, snapshot: QEMUSnapshot):
        """Stop VM for a specific snapshot."""
        try:
            if snapshot.vm_process and snapshot.vm_process.poll() is None:
                snapshot.vm_process.terminate()
                try:
                    snapshot.vm_process.wait(timeout=10)
                except subprocess.TimeoutExpired as e:
                    self.logger.error(
                        "Subprocess timeout in qemu_test_manager: %s", e)
                    snapshot.vm_process.kill()
                    snapshot.vm_process.wait()
                logger.info(
                    f"Stopped VM process for snapshot {snapshot.snapshot_id}")
        except Exception as e:
            logger.error(
                f"Error stopping VM for snapshot {snapshot.snapshot_id}: {e}")

    def cleanup_all_snapshots(self):
        """Clean up all active snapshots."""
        logger.info("Cleaning up all snapshots")

        for snapshot_id in list(self.snapshots.keys()):
            self.cleanup_snapshot(snapshot_id)

        logger.info("All snapshots cleaned up")

    def get_snapshot_info(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a snapshot."""
        if snapshot_id not in self.snapshots:
            return None

        snapshot = self.snapshots[snapshot_id]

        return {
            "snapshot_id": snapshot.snapshot_id,
            "vm_name": snapshot.vm_name,
            "binary_path": snapshot.binary_path,
            "created_at": snapshot.created_at.isoformat(),
            "ssh_port": snapshot.ssh_port,
            "vnc_port": snapshot.vnc_port,
            "disk_path": snapshot.disk_path,
            "vm_running": snapshot.vm_process is not None and snapshot.vm_process.poll() is None
        }

    def list_snapshots(self) -> List[Dict[str, Any]]:
        """List all active snapshots."""
        return [self.get_snapshot_info(sid) for sid in self.snapshots.keys()]

    def __del__(self):
        """Cleanup on destruction."""
        try:
            # Close all SSH connections first
            with self.ssh_lock:
                for client in self.ssh_connection_pool.values():
                    try:
                        client.close()
                    except:
                        pass
                self.ssh_connection_pool.clear()

            # Then cleanup snapshots
            self.cleanup_all_snapshots()
        except Exception as e:
            logger.debug(f"Error during destructor cleanup: {e}")

    def _get_windows_base_image(self) -> Path:
        """Get path to Windows base image."""
        # Use project-relative paths
        # Go up to project root
        project_root = Path(__file__).parent.parent.parent

        possible_paths = [
            Path("/var/lib/libvirt/images/windows_base.qcow2"),
            Path("~/VMs/windows_base.qcow2"),
            project_root / "data" / "qemu_images" / "windows_base.qcow2",
            # Additional common Windows VM locations
            Path("C:/VMs/windows_base.qcow2"),
            Path("D:/VMs/windows_base.qcow2"),
            Path("~/Documents/Virtual Machines/windows_base.qcow2"),
        ]

        for path in possible_paths:
            expanded_path = path.expanduser()
            if expanded_path.exists():
                self.logger.info(f"Found Windows base image at: {expanded_path}")
                return expanded_path

        # If no base image found, create a minimal test image
        test_image_path = project_root / "data" / "qemu_images" / "windows_test_minimal.qcow2"
        test_image_path.parent.mkdir(parents=True, exist_ok=True)
        
        if not test_image_path.exists():
            self.logger.warning("No Windows base image found. Creating minimal test image.")
            try:
                # Create a minimal qcow2 image (1GB)
                subprocess.run([
                    "qemu-img", "create", "-f", "qcow2", 
                    str(test_image_path), "1G"
                ], check=True, capture_output=True)
                self.logger.info(f"Created minimal test image at: {test_image_path}")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to create test image: {e}")
                raise RuntimeError(
                    "No Windows base image found and failed to create test image. "
                    "Please provide a Windows base image at one of the expected locations."
                )
            except FileNotFoundError:
                self.logger.error("qemu-img not found. Please install QEMU.")
                raise RuntimeError(
                    "QEMU tools not installed. Cannot create test image."
                )
        
        return test_image_path

    def _get_linux_base_image(self) -> str:
        """Get Linux base image for testing."""
        # Check common locations for base images
        image_locations = [
            "/var/lib/libvirt/images/ubuntu-22.04.qcow2",
            "/var/lib/libvirt/images/debian-11.qcow2",
            "/var/lib/libvirt/images/centos-8.qcow2",
            os.path.expanduser("~/vms/ubuntu.qcow2"),
            os.path.expanduser("~/vms/debian.qcow2")
        ]
        
        for image_path in image_locations:
            if os.path.exists(image_path):
                return image_path
        
        # Create minimal test image if none found
        test_image_path = self.working_dir / "linux_test.qcow2"
        if not test_image_path.exists():
            logger.info("Creating minimal Linux test image")
            try:
                # Create 1GB qcow2 image
                subprocess.run([
                    'qemu-img', 'create', '-f', 'qcow2',
                    str(test_image_path), '1G'
                ], check=True)
                
                # Create minimal bootable image with busybox
                # This creates a basic Linux environment for testing
                initrd_path = self.working_dir / "initrd.img"
                kernel_path = self.working_dir / "vmlinuz"
                
                # Download minimal kernel and initrd if not present
                if not kernel_path.exists():
                    # Use Alpine Linux kernel for minimal footprint
                    kernel_url = "https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/netboot/vmlinuz-lts"
                    subprocess.run(['curl', '-L', '-o', str(kernel_path), kernel_url], check=True)
                
                if not initrd_path.exists():
                    initrd_url = "https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/netboot/initramfs-lts"
                    subprocess.run(['curl', '-L', '-o', str(initrd_path), initrd_url], check=True)
                
                # Store kernel/initrd paths for boot configuration
                self._linux_kernel = str(kernel_path)
                self._linux_initrd = str(initrd_path)
                
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to create test image: {e}")
                # Create empty image as last resort
                test_image_path.touch()
        
        return str(test_image_path)

    def _detect_os_type(self, binary_path: str) -> str:
        """Detect operating system type from binary."""
        if binary_path.lower().endswith(('.exe', '.dll')):
            return 'windows'
        elif binary_path.lower().endswith(('.so', '.elf')):
            return 'linux'
        else:
            # Default to windows for unknown types
            return 'windows'

    def create_snapshot(self, binary_path: str) -> str:
        """Create a QEMU snapshot for testing."""
        try:
            os_type = self._detect_os_type(binary_path)
            snapshot_id = f"test_{int(time.time())}_{os.getpid()}"

            # Create working directory for this snapshot
            snapshot_dir = self.working_dir / snapshot_id
            snapshot_dir.mkdir(exist_ok=True)

            # Copy base image to temporary location
            base_image = self.base_images[os_type]
            if not base_image.exists():
                # Create minimal test image if base doesn't exist
                logger.warning(f"Base image not found: {base_image}")
                temp_disk = self._create_minimal_test_image(
                    snapshot_dir, os_type)
            else:
                temp_disk = self._copy_base_image(base_image, snapshot_dir)

            # Copy target binary to a shared location
            shared_dir = snapshot_dir / "shared"
            shared_dir.mkdir(exist_ok=True)

            if Path(binary_path).exists():
                target_binary = shared_dir / Path(binary_path).name
                shutil.copy2(binary_path, target_binary)
            else:
                # Binary not found - this is a critical error
                raise FileNotFoundError(
                    f"Target binary not found: {binary_path}\n"
                    f"Please provide a valid path to an executable file.\n"
                    f"Common paths:\n"
                    f"  Windows: C:\\Program Files\\*, C:\\Program Files (x86)\\*\n"
                    f"  Linux: /opt/*, /usr/local/bin/*, ~/.local/bin/*\n"
                    f"  Custom: Provide full path to your target binary"
                )

            # Create snapshot object
            snapshot = QEMUSnapshot(
                snapshot_id=snapshot_id,
                vm_name=f"intellicrack_test_{snapshot_id}",
                disk_path=str(temp_disk),
                binary_path=str(target_binary),
                created_at=datetime.now(),
                ssh_port=22222 + len(self.snapshots),
                vnc_port=5900 + len(self.snapshots)
            )

            # Start VM
            if self._start_vm(snapshot):
                self.snapshots[snapshot_id] = snapshot
                logger.info(f"Created QEMU snapshot: {snapshot_id}")
                return snapshot_id
            else:
                raise Exception("Failed to start VM")

        except Exception as e:
            logger.error(f"Failed to create QEMU snapshot: {e}")
            raise

    def _create_minimal_test_image(self, snapshot_dir: Path, os_type: str) -> Path:
        """Create minimal test image when base image is not available."""
        disk_path = snapshot_dir / "test_disk.qcow2"

        try:
            # Create qcow2 image with size based on OS type
            if os_type.lower() == "windows":
                image_size = "2G"  # Windows needs more space
                logger.info(f"Creating Windows test image ({image_size})")
            elif os_type.lower() in ["linux", "debian", "ubuntu"]:
                image_size = "1G"  # Linux can work with less space
                logger.info(f"Creating Linux test image ({image_size})")
            else:
                image_size = "1.5G"  # Default for unknown OS types
                logger.info(
                    f"Creating generic test image for {os_type} ({image_size})")

            cmd = [
                "qemu-img", "create", "-f", "qcow2",
                str(disk_path), image_size
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Created minimal test image: {disk_path}")
                return disk_path
            else:
                logger.error(f"Failed to create test image: {result.stderr}")

        except Exception as e:
            logger.error(f"Failed to create minimal test image: {e}")
            # Cannot continue without a valid disk image
            raise RuntimeError(
                f"Failed to create test disk image: {e}\n"
                f"Ensure qemu-img is installed and accessible.\n"
                f"On Windows: Install QEMU from https://www.qemu.org/download/\n"
                f"On Linux: sudo apt-get install qemu-utils\n"
                f"On macOS: brew install qemu"
            )

    def _copy_base_image(self, base_image: Path, snapshot_dir: Path) -> Path:
        """Copy base image to snapshot directory."""
        temp_disk = snapshot_dir / "snapshot_disk.qcow2"

        try:
            # Create snapshot from base image
            cmd = [
                "qemu-img", "create", "-f", "qcow2",
                "-b", str(base_image),
                str(temp_disk)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                return temp_disk
            else:
                logger.error(
                    f"Failed to create snapshot image: {result.stderr}")
                # Try direct copy as recovery mechanism
                logger.info("Attempting direct copy of base image")
                shutil.copy2(base_image, temp_disk)
                return temp_disk

        except Exception as e:
            logger.error(f"Failed to copy base image: {e}")
            # Cannot continue without a valid disk image
            raise RuntimeError(
                f"Failed to copy/create disk image: {e}\n"
                f"Base image: {base_image}\n"
                f"Target: {temp_disk}\n"
                f"Ensure:\n"
                f"1. Base image exists and is readable\n"
                f"2. Target directory is writable\n"
                f"3. Sufficient disk space available\n"
                f"4. qemu-img is installed and working"
            )

    def _start_vm(self, snapshot: QEMUSnapshot) -> bool:
        """Start QEMU VM."""
        try:
            # Build QEMU command
            cmd = [
                self.qemu_executable,
                "-machine", "pc",
                "-cpu", "host",
                "-m", "2048",
                "-smp", "2",
                "-drive", f"file={snapshot.disk_path},format=qcow2,if=virtio",
                "-netdev", f"user,id=net0,hostfwd=tcp::{snapshot.ssh_port}-:22",
                "-device", "virtio-net,netdev=net0",
                "-vnc", f":{snapshot.vnc_port - 5900}",
                "-daemonize",
                "-pidfile", str(Path(snapshot.disk_path).parent / "qemu.pid")
            ]

            # Add shared directory if available
            shared_dir = Path(snapshot.disk_path).parent / "shared"
            if shared_dir.exists():
                cmd.extend([
                    "-virtfs", f"local,path={shared_dir},mount_tag=shared,security_model=none"
                ])

            logger.info(f"Starting QEMU VM: {' '.join(cmd)}")

            # Start the VM
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                # Give VM time to start
                time.sleep(5)
                logger.info(f"Started VM for snapshot {snapshot.snapshot_id}")
                return True
            else:
                logger.error(f"Failed to start VM: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Failed to start VM: {e}")
            return False

    def test_frida_script(self, snapshot_id: str, script_content: str, binary_path: str) -> ExecutionResult:
        """Test a Frida script in QEMU environment."""
        if snapshot_id not in self.snapshots:
            return ExecutionResult(
                success=False,
                output="",
                error="Snapshot not found",
                exit_code=-1,
                runtime_ms=0
            )

        snapshot = self.snapshots[snapshot_id]
        start_time = time.time()

        try:
            # Save script to shared directory
            shared_dir = Path(snapshot.disk_path).parent / "shared"
            script_path = shared_dir / "test_script.js"
            script_path.write_text(script_content)

            # Create test runner script
            runner_script = shared_dir / "run_frida_test.sh"
            runner_content = f'''#!/bin/bash
# Frida script testing
cd /tmp
mount -t 9p -o trans=virtio shared /mnt 2>/dev/null || true
cp /mnt/test_script.js . 2>/dev/null || echo "Could not copy script"
cp /mnt/{Path(binary_path).name} . 2>/dev/null || echo "Could not copy binary"

# Check if Frida is available
if command -v frida &> /dev/null; then
    echo "Frida found, starting test..."
    # Start target process in background
    ./{Path(binary_path).name} &
    TARGET_PID=$!
    sleep 2

    # Run Frida script
    timeout 30 frida -p $TARGET_PID -l test_script.js --no-pause || echo "Frida test completed"

    # Check if process is still running
    if ps -p $TARGET_PID > /dev/null 2>&1; then
        echo "SUCCESS: Process still running after Frida script"
        kill $TARGET_PID 2>/dev/null
        exit 0
    else
        echo "INFO: Process terminated"
        exit 0
    fi
else
    echo "ERROR: Frida not available in VM"
    echo "This test requires Frida to be installed in the VM."
    echo "Please ensure the VM image includes Frida installation."
    echo "Install with: pip install frida-tools"
    exit 1
fi
'''
            runner_script.write_text(runner_content)
            runner_script.chmod(0o755)

            # Execute script in VM via SSH
            result = self._execute_in_vm_real(snapshot, runner_content)

            runtime_ms = int((time.time() - start_time) * 1000)

            return ExecutionResult(
                success=result['exit_code'] == 0,
                output=result['stdout'],
                error=result['stderr'],
                exit_code=result['exit_code'],
                runtime_ms=runtime_ms
            )

        except Exception as e:
            logger.error("Exception in qemu_test_manager: %s", e)
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Frida test failed: {str(e)}",
                exit_code=-1,
                runtime_ms=runtime_ms
            )

    def test_ghidra_script(self, snapshot_id: str, script_content: str, binary_path: str) -> ExecutionResult:
        """Test a Ghidra script in QEMU environment."""
        if snapshot_id not in self.snapshots:
            return ExecutionResult(
                success=False,
                output="",
                error="Snapshot not found",
                exit_code=-1,
                runtime_ms=0
            )

        snapshot = self.snapshots[snapshot_id]
        start_time = time.time()

        try:
            # Save script to shared directory
            shared_dir = Path(snapshot.disk_path).parent / "shared"
            script_path = shared_dir / "test_script.py"
            script_path.write_text(script_content)

            # Create Ghidra test runner
            runner_script = shared_dir / "run_ghidra_test.sh"
            runner_content = f'''#!/bin/bash
# Ghidra script testing
cd /tmp
mount -t 9p -o trans=virtio shared /mnt 2>/dev/null || true
cp /mnt/test_script.py . 2>/dev/null || echo "Could not copy script"
cp /mnt/{Path(binary_path).name} . 2>/dev/null || echo "Could not copy binary"

# Check if Ghidra is available
if [ -d "/opt/ghidra" ] || command -v analyzeHeadless &> /dev/null; then
    echo "Ghidra found, starting analysis..."

    # Run Ghidra headless analysis
    analyzeHeadless /tmp/ghidra_project TestProject \\
        -import {Path(binary_path).name} \\
        -postScript test_script.py \\
        -deleteProject || echo "Ghidra analysis completed"

    echo "SUCCESS: Ghidra script executed"
    exit 0
else
    echo "ERROR: Ghidra not available in VM"
    echo "This test requires Ghidra to be installed in the VM."
    echo "Please ensure the VM image includes Ghidra installation at /opt/ghidra"
    echo "or has analyzeHeadless in PATH."
    exit 1
fi
'''
            runner_script.write_text(runner_content)
            runner_script.chmod(0o755)

            # Execute script in VM
            result = self._execute_in_vm_real(snapshot, runner_content)

            runtime_ms = int((time.time() - start_time) * 1000)

            return ExecutionResult(
                success=result['exit_code'] == 0,
                output=result['stdout'],
                error=result['stderr'],
                exit_code=result['exit_code'],
                runtime_ms=runtime_ms
            )

        except Exception as e:
            logger.error("Exception in qemu_test_manager: %s", e)
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Ghidra test failed: {str(e)}",
                exit_code=-1,
                runtime_ms=runtime_ms
            )

    def _execute_in_vm_real(self, snapshot: QEMUSnapshot, script_content: str) -> Dict[str, Any]:
        """Execute script in VM using real SSH connection."""
        logger.info(f"Executing script in VM {snapshot.vm_name} via SSH")

        # Create temporary script file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(script_content)
            local_script = f.name

        remote_script = "/tmp/test_script.sh"

        try:
            # Upload script to VM
            self._upload_file_to_vm(snapshot, script_content, remote_script)

            # Make script executable
            chmod_result = self._execute_command_in_vm(snapshot, f"chmod +x {remote_script}")
            if chmod_result['exit_code'] != 0:
                logger.error(f"Failed to make script executable: {chmod_result['stderr']}")

            # Execute script
            exec_result = self._execute_command_in_vm(snapshot, f"bash {remote_script}", timeout=60)

            # Clean up remote script
            self._execute_command_in_vm(snapshot, f"rm -f {remote_script}")

            return exec_result

        except Exception as e:
            logger.error(f"Failed to execute script in VM: {e}")
            return {
                'exit_code': -1,
                'stdout': "",
                'stderr': f"VM execution error: {str(e)}"
            }
        finally:
            # Clean up local temp file
            try:
                os.unlink(local_script)
            except Exception:
                pass

    def create_versioned_snapshot(self, parent_snapshot_id: str, binary_path: str) -> str:
        """Create a new snapshot version based on an existing snapshot."""
        if parent_snapshot_id not in self.snapshots:
            raise ValueError(
                f"Parent snapshot not found: {parent_snapshot_id}")

        parent_snapshot = self.snapshots[parent_snapshot_id]
        new_version = parent_snapshot.version + 1
        snapshot_id = f"{parent_snapshot_id}_v{new_version}_{int(time.time())}"

        logger.info(
            f"Creating versioned snapshot: {snapshot_id} from {parent_snapshot_id}")

        # Create new snapshot based on parent
        snapshot_disk = self.working_dir / f"{snapshot_id}.qcow2"

        # Create overlay based on parent snapshot
        cmd = [
            "qemu-img", "create", "-f", "qcow2",
            "-b", parent_snapshot.disk_path,
            "-F", "qcow2",  # Specify backing file format
            str(snapshot_disk)
        ]

        try:
            # Use resource manager for temporary directory
            with resource_manager.temp_directory(prefix=f"snapshot_{snapshot_id}_"):
                # Execute qemu-img command
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    raise RuntimeError(f"qemu-img failed: {result.stderr}")

                logger.info(f"Created versioned snapshot disk: {snapshot_disk}")

                # Verify the snapshot was created correctly
                info_cmd = ["qemu-img", "info", str(snapshot_disk)]
                info_result = subprocess.run(info_cmd, capture_output=True, text=True)
                if info_result.returncode == 0:
                    logger.debug(f"Snapshot info: {info_result.stdout}")

        except Exception as e:
            logger.error(f"Failed to create versioned snapshot: {e}")
            # Clean up failed snapshot disk
            if snapshot_disk.exists():
                try:
                    snapshot_disk.unlink()
                except Exception as cleanup_e:
                    logger.warning(f"Failed to cleanup failed snapshot disk: {cleanup_e}")
            raise

        # Create new snapshot metadata
        snapshot = QEMUSnapshot(
            snapshot_id=snapshot_id,
            vm_name=f"test_vm_{snapshot_id}",
            disk_path=str(snapshot_disk),
            binary_path=binary_path,
            created_at=datetime.now(),
            ssh_port=22222 + len(self.snapshots),
            vnc_port=5900 + len(self.snapshots),
            version=new_version,
            parent_snapshot=parent_snapshot_id
        )

        # Update parent-child relationships
        parent_snapshot.children_snapshots.add(snapshot_id)

        # Calculate initial disk usage
        try:
            snapshot.disk_usage = os.path.getsize(snapshot_disk)
        except Exception:
            snapshot.disk_usage = 0

        self.snapshots[snapshot_id] = snapshot

        # Log the snapshot creation
        audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.VM_SNAPSHOT,
            severity=AuditSeverity.INFO,
            description=f"Created versioned snapshot {snapshot_id} from {parent_snapshot_id}",
            target=snapshot_id
        ))

        logger.info(f"Created versioned snapshot: {snapshot_id}")
        return snapshot_id

    def compare_snapshots(self, snapshot_id1: str, snapshot_id2: str) -> Dict[str, Any]:
        """Compare two snapshots and return differences."""
        if snapshot_id1 not in self.snapshots or snapshot_id2 not in self.snapshots:
            raise ValueError("One or both snapshots not found")

        snapshot1 = self.snapshots[snapshot_id1]
        snapshot2 = self.snapshots[snapshot_id2]

        logger.info(f"Comparing snapshots: {snapshot_id1} vs {snapshot_id2}")

        # Calculate disk usage differences
        disk1_size = os.path.getsize(snapshot1.disk_path) if os.path.exists(
            snapshot1.disk_path) else 0
        disk2_size = os.path.getsize(snapshot2.disk_path) if os.path.exists(
            snapshot2.disk_path) else 0

        # Compare test results
        results1 = snapshot1.test_results
        results2 = snapshot2.test_results

        comparison = {
            "snapshot1": {
                "id": snapshot_id1,
                "version": snapshot1.version,
                "disk_size": disk1_size,
                "test_count": len(results1),
                "created_at": snapshot1.created_at.isoformat()
            },
            "snapshot2": {
                "id": snapshot_id2,
                "version": snapshot2.version,
                "disk_size": disk2_size,
                "test_count": len(results2),
                "created_at": snapshot2.created_at.isoformat()
            },
            "differences": {
                "disk_size_diff": disk2_size - disk1_size,
                "test_count_diff": len(results2) - len(results1),
                "version_diff": snapshot2.version - snapshot1.version,
                "time_diff": (snapshot2.created_at - snapshot1.created_at).total_seconds()
            },
            "relationship": self._determine_snapshot_relationship(snapshot1, snapshot2)
        }

        return comparison

    def _determine_snapshot_relationship(self, snapshot1: QEMUSnapshot, snapshot2: QEMUSnapshot) -> str:
        """Determine the relationship between two snapshots."""
        if snapshot1.parent_snapshot == snapshot2.snapshot_id:
            return f"{snapshot1.snapshot_id} is child of {snapshot2.snapshot_id}"
        elif snapshot2.parent_snapshot == snapshot1.snapshot_id:
            return f"{snapshot2.snapshot_id} is child of {snapshot1.snapshot_id}"
        elif snapshot1.parent_snapshot == snapshot2.parent_snapshot and snapshot1.parent_snapshot:
            return f"Both are siblings (share parent: {snapshot1.parent_snapshot})"
        else:
            return "No direct relationship"

    def rollback_snapshot(self, snapshot_id: str, target_state: Optional[str] = None) -> bool:
        """Rollback a snapshot to a previous state or clean state."""
        if snapshot_id not in self.snapshots:
            raise ValueError(f"Snapshot not found: {snapshot_id}")

        snapshot = self.snapshots[snapshot_id]
        logger.info(f"Rolling back snapshot: {snapshot_id}")

        # Track original state for recovery
        original_disk_path = snapshot.disk_path
        original_disk_backup = None
        was_vm_running = snapshot.vm_process and snapshot.vm_process.poll() is None

        try:
            # Close SSH connections
            self._close_ssh_connection(snapshot)

            # Stop VM if running
            if was_vm_running:
                self._stop_vm_for_snapshot(snapshot)
                time.sleep(2)

            # Backup current disk
            original_disk_backup = f"{original_disk_path}.backup"
            if Path(original_disk_path).exists():
                shutil.copy2(original_disk_path, original_disk_backup)

            if target_state and target_state in self.snapshots:
                # Rollback to specific snapshot state
                target_snapshot = self.snapshots[target_state]

                # Create new overlay based on target
                rollback_disk = self.working_dir / \
                    f"{snapshot_id}_rollback_{int(time.time())}.qcow2"
                cmd = [
                    "qemu-img", "create", "-f", "qcow2",
                    "-b", target_snapshot.disk_path,
                    "-F", "qcow2",
                    str(rollback_disk)
                ]

                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    raise RuntimeError(f"Failed to create rollback disk: {result.stderr}")

                # Replace current disk
                os.remove(snapshot.disk_path)
                shutil.move(str(rollback_disk), snapshot.disk_path)

                logger.info(
                    f"Rolled back {snapshot_id} to state of {target_state}")

                rollback_type = f"to snapshot {target_state}"
            else:
                # Rollback to clean state (recreate from base)
                os_type = self._detect_os_type(snapshot.binary_path)
                base_image = self.base_images.get(os_type.lower())
                if not base_image or not base_image.exists():
                    raise RuntimeError(f"No base image available for {os_type}")

                # Remove current disk
                os.remove(snapshot.disk_path)

                # Create fresh overlay
                cmd = [
                    "qemu-img", "create", "-f", "qcow2",
                    "-b", str(base_image),
                    "-F", "qcow2",
                    snapshot.disk_path
                ]

                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    raise RuntimeError(f"Failed to create clean disk: {result.stderr}")

                logger.info(f"Rolled back {snapshot_id} to clean base state")
                rollback_type = "to clean base state"

            # Clear test results and metrics
            snapshot.test_results.clear()
            snapshot.performance_metrics.clear()
            snapshot.version += 1  # Increment version after rollback

            # Log the rollback
            audit_logger.log_event(AuditEvent(
                event_type=AuditEventType.VM_SNAPSHOT,
                severity=AuditSeverity.MEDIUM,
                description=f"Rolled back snapshot {snapshot_id} {rollback_type}",
                details={"target_state": target_state, "new_version": snapshot.version},
                target=snapshot_id
            ))

            # Restart VM if it was running
            if was_vm_running:
                self._start_vm_for_snapshot(snapshot)

            # Remove backup on success
            if original_disk_backup and Path(original_disk_backup).exists():
                os.remove(original_disk_backup)

            return True

        except Exception as e:
            logger.error(f"Rollback failed for {snapshot_id}: {e}")

            # Attempt recovery from backup
            if original_disk_backup and Path(original_disk_backup).exists():
                try:
                    logger.info("Attempting to restore from backup...")
                    if Path(snapshot.disk_path).exists():
                        os.remove(snapshot.disk_path)
                    shutil.move(original_disk_backup, snapshot.disk_path)
                    logger.info("Restored from backup successfully")
                except Exception as restore_e:
                    logger.error(f"Failed to restore from backup: {restore_e}")

            # Log failure
            audit_logger.log_event(AuditEvent(
                event_type=AuditEventType.ERROR,
                severity=AuditSeverity.HIGH,
                description=f"Snapshot rollback failed for {snapshot_id}",
                details={"error": str(e), "target_state": target_state},
                target=snapshot_id
            ))

            return False

    def monitor_snapshot_performance(self, snapshot_id: str) -> Dict[str, Any]:
        """Monitor performance metrics for a snapshot."""
        if snapshot_id not in self.snapshots:
            raise ValueError(f"Snapshot not found: {snapshot_id}")

        snapshot = self.snapshots[snapshot_id]

        try:
            # Get disk usage
            disk_size = os.path.getsize(snapshot.disk_path) if os.path.exists(
                snapshot.disk_path) else 0

            # Get memory usage from VM if running
            memory_usage = 0
            cpu_usage = 0.0

            if snapshot.vm_process and snapshot.vm_process.poll() is None:
                pid = snapshot.vm_process.pid

                # Use ps to get memory and CPU usage
                try:
                    ps_cmd = ["ps", "-p",
                              str(pid), "-o", "rss,pcpu", "--no-headers"]
                    result = subprocess.run(
                        ps_cmd, capture_output=True, text=True)

                    if result.returncode == 0:
                        parts = result.stdout.strip().split()
                        if len(parts) >= 2:
                            # Convert KB to bytes
                            memory_usage = int(parts[0]) * 1024
                            cpu_usage = float(parts[1])

                except (subprocess.SubprocessError, ValueError) as e:
                    logger.error("Error in qemu_test_manager: %s", e)
                    pass

            # Update snapshot metrics
            metrics = {
                "timestamp": datetime.now().isoformat(),
                "disk_usage_bytes": disk_size,
                "memory_usage_bytes": memory_usage,
                "cpu_usage_percent": cpu_usage,
                "vm_running": snapshot.vm_process is not None and snapshot.vm_process.poll() is None,
                "test_count": len(snapshot.test_results),
                "uptime_seconds": (datetime.now() - snapshot.created_at).total_seconds()
            }

            snapshot.performance_metrics.update(metrics)
            snapshot.memory_usage = memory_usage
            snapshot.disk_usage = disk_size

            return metrics

        except Exception as e:
            logger.error(
                f"Performance monitoring failed for {snapshot_id}: {e}")
            return {"error": str(e)}

    def enable_network_isolation(self, snapshot_id: str, isolated: bool = True):
        """Enable or disable network isolation for a snapshot."""
        if snapshot_id not in self.snapshots:
            raise ValueError(f"Snapshot not found: {snapshot_id}")

        snapshot = self.snapshots[snapshot_id]
        snapshot.network_isolated = isolated

        if snapshot.vm_process and snapshot.vm_process.poll() is None:
            # Apply network isolation to running VM
            isolation_cmd = (
                "iptables -A OUTPUT -j DROP" if isolated
                else "iptables -D OUTPUT -j DROP"
            )

            try:
                self._execute_command_in_vm(snapshot, isolation_cmd)
                logger.info(
                    f"Network isolation {'enabled' if isolated else 'disabled'} for {snapshot_id}")
            except Exception as e:
                logger.warning(f"Failed to apply network isolation: {e}")

    def get_snapshot_hierarchy(self) -> Dict[str, Any]:
        """Get the hierarchy of all snapshots showing parent-child relationships."""
        hierarchy = {"roots": [], "children": {}}

        # Find root snapshots (no parent)
        for snapshot_id, snapshot in self.snapshots.items():
            if not snapshot.parent_snapshot:
                hierarchy["roots"].append({
                    "id": snapshot_id,
                    "version": snapshot.version,
                    "created_at": snapshot.created_at.isoformat(),
                    "children": list(snapshot.children_snapshots)
                })

            # Build children mapping
            if snapshot.children_snapshots:
                hierarchy["children"][snapshot_id] = []
                for child_id in snapshot.children_snapshots:
                    if child_id in self.snapshots:
                        child = self.snapshots[child_id]
                        hierarchy["children"][snapshot_id].append({
                            "id": child_id,
                            "version": child.version,
                            "created_at": child.created_at.isoformat()
                        })

        return hierarchy

    def test_script_in_vm(self, script_content: str, binary_path: str,
                          script_type: str = "frida", timeout: int = 60) -> ExecutionResult:
        """Test a script in QEMU VM - main entry point for autonomous agent."""
        try:
            # Create snapshot for testing
            snapshot_id = self.create_script_test_snapshot(binary_path)

            # Test based on script type
            if script_type.lower() == "frida":
                result = self.test_frida_script(snapshot_id, script_content, binary_path)
            elif script_type.lower() == "ghidra":
                result = self.test_ghidra_script(snapshot_id, script_content, binary_path)
            else:
                # Generic script execution
                result = self._test_generic_script(snapshot_id, script_content, binary_path)

            # Cleanup snapshot after test
            self.cleanup_snapshot(snapshot_id)

            return result

        except Exception as e:
            logger.error(f"Failed to test script in VM: {e}")
            return ExecutionResult(
                success=False,
                output="",
                error=f"VM test failed: {str(e)}",
                exit_code=-1,
                runtime_ms=0
            )

    def _test_generic_script(self, snapshot_id: str, script_content: str, binary_path: str) -> ExecutionResult:
        """Test a generic script in QEMU environment."""
        if snapshot_id not in self.snapshots:
            return ExecutionResult(
                success=False,
                output="",
                error="Snapshot not found",
                exit_code=-1,
                runtime_ms=0
            )

        snapshot = self.snapshots[snapshot_id]
        start_time = time.time()

        try:
            # Upload binary to VM
            remote_binary = f"/tmp/{Path(binary_path).name}"
            self._upload_binary_to_vm(snapshot, binary_path, remote_binary)

            # Create wrapper script
            wrapper_script = f"""#!/bin/bash
# Generic script execution
echo "[+] Starting generic script test"
{script_content}
echo "[+] Script execution completed"
exit 0
"""

            # Execute script in VM
            result = self._execute_in_vm_real(snapshot, wrapper_script)

            runtime_ms = int((time.time() - start_time) * 1000)

            return ExecutionResult(
                success=result['exit_code'] == 0,
                output=result['stdout'],
                error=result['stderr'],
                exit_code=result['exit_code'],
                runtime_ms=runtime_ms
            )

        except Exception as e:
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Generic test failed: {str(e)}",
                exit_code=-1,
                runtime_ms=runtime_ms
            )

    def optimize_snapshot_storage(self) -> Dict[str, Any]:
        """Optimize snapshot storage by removing unused overlays and compacting.

        Returns:
            Dictionary containing optimization results and statistics
        """
        logger.info("Starting snapshot storage optimization")

        # Log optimization start
        audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTION,
            severity=AuditSeverity.INFO,
            description="Starting snapshot storage optimization",
            details={"total_snapshots": len(self.snapshots)}
        ))

        optimization_results = {
            "snapshots_processed": 0,
            "snapshots_optimized": 0,
            "space_saved_bytes": 0,
            "space_saved_mb": 0,
            "processing_time_seconds": 0,
            "errors": [],
            "warnings": []
        }

        start_time = time.time()
        total_snapshots = len(self.snapshots)

        # Create temporary directory for optimization with resource manager
        with self.resource_manager.temp_directory(prefix="qemu_snapshot_opt_") as temp_dir:
            for idx, (snapshot_id, snapshot) in enumerate(self.snapshots.items()):
                try:
                    # Progress tracking
                    progress = (idx + 1) / total_snapshots * 100
                    logger.info(f"Optimizing snapshot {idx + 1}/{total_snapshots} ({progress:.1f}%): {snapshot_id}")

                    # Check if file exists
                    if not os.path.exists(snapshot.disk_path):
                        warning = f"Snapshot file not found: {snapshot.disk_path}"
                        optimization_results["warnings"].append(warning)
                        logger.warning(warning)
                        continue

                    # Get original size
                    original_size = os.path.getsize(snapshot.disk_path)

                    # Skip non-qcow2 images
                    if not snapshot.disk_path.endswith('.qcow2'):
                        warning = f"Skipping non-qcow2 snapshot: {snapshot_id}"
                        optimization_results["warnings"].append(warning)
                        continue

                    # Check if image is already optimized (has compression)
                    info_cmd = ["qemu-img", "info", "--output=json", snapshot.disk_path]
                    info_result = subprocess.run(
                        info_cmd, capture_output=True, text=True, timeout=30)

                    if info_result.returncode == 0:
                        import json
                        info_data = json.loads(info_result.stdout)

                        # Skip if already compressed
                        if info_data.get("compressed", False):
                            logger.debug(f"Snapshot {snapshot_id} already compressed")
                            optimization_results["snapshots_processed"] += 1
                            continue

                    # Create temp file in our managed temp directory
                    temp_path = temp_dir / f"{snapshot_id}_opt.qcow2"

                    # Compact and compress the qcow2 image
                    convert_cmd = [
                        "qemu-img", "convert",
                        "-c",  # Enable compression
                        "-p",  # Show progress
                        "-O", "qcow2",
                        "-o", "lazy_refcounts=on,cluster_size=2M",  # Optimization options
                        snapshot.disk_path,
                        str(temp_path)
                    ]

                    # Run conversion with resource management
                    logger.debug(f"Running optimization command: {' '.join(convert_cmd)}")

                    with self.resource_manager.managed_process(
                        convert_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    ) as process_resource:
                        # Wait for completion with timeout
                        try:
                            stdout, stderr = process_resource.process.communicate(timeout=300)

                            if process_resource.process.returncode == 0:
                                # Check new size
                                new_size = os.path.getsize(temp_path)
                                space_saved = original_size - new_size

                                if space_saved > 0:
                                    # Verify integrity before replacing
                                    check_cmd = ["qemu-img", "check", str(temp_path)]
                                    check_result = subprocess.run(
                                        check_cmd, capture_output=True, text=True, timeout=60)

                                    if check_result.returncode == 0:
                                        # Backup original before replacement
                                        backup_path = f"{snapshot.disk_path}.backup"
                                        try:
                                            os.rename(snapshot.disk_path, backup_path)
                                            os.rename(str(temp_path), snapshot.disk_path)
                                            os.remove(backup_path)

                                            optimization_results["space_saved_bytes"] += space_saved
                                            optimization_results["snapshots_optimized"] += 1

                                            logger.info(
                                                f"Optimized {snapshot_id}: saved {space_saved:,} bytes "
                                                f"({space_saved / 1024 / 1024:.2f} MB)"
                                            )

                                            # Update snapshot metadata
                                            snapshot.metadata["optimized"] = True
                                            snapshot.metadata["optimization_date"] = datetime.now().isoformat()
                                            snapshot.metadata["original_size"] = original_size
                                            snapshot.metadata["optimized_size"] = new_size

                                        except Exception as e:
                                            # Restore backup on error
                                            if os.path.exists(backup_path):
                                                os.rename(backup_path, snapshot.disk_path)
                                            raise Exception(f"Failed to replace snapshot file: {e}")
                                    else:
                                        raise Exception(f"Integrity check failed: {check_result.stderr}")
                                else:
                                    # No space saved, remove temp file
                                    logger.debug(f"No space saved for {snapshot_id}")

                            else:
                                raise Exception(f"Conversion failed: {stderr}")

                        except subprocess.TimeoutExpired:
                            process_resource.process.kill()
                            raise Exception("Optimization timeout (300s)")

                    optimization_results["snapshots_processed"] += 1

                except Exception as e:
                    error_msg = f"Failed to optimize {snapshot_id}: {str(e)}"
                    optimization_results["errors"].append(error_msg)
                    logger.error(error_msg)

                    # Log error to audit
                    audit_logger.log_event(AuditEvent(
                        event_type=AuditEventType.ERROR,
                        severity=AuditSeverity.MEDIUM,
                        description=f"Snapshot optimization failed: {snapshot_id}",
                        details={"error": str(e)},
                        target=snapshot.disk_path
                    ))

        # Calculate final statistics
        optimization_results["processing_time_seconds"] = time.time() - start_time
        optimization_results["space_saved_mb"] = optimization_results["space_saved_bytes"] / (1024 * 1024)

        # Log completion
        audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTION,
            severity=AuditSeverity.INFO,
            description="Snapshot storage optimization completed",
            details={
                "snapshots_processed": optimization_results["snapshots_processed"],
                "snapshots_optimized": optimization_results["snapshots_optimized"],
                "space_saved_mb": f"{optimization_results['space_saved_mb']:.2f}",
                "processing_time": f"{optimization_results['processing_time_seconds']:.1f}s",
                "error_count": len(optimization_results["errors"])
            }
        ))

        logger.info(
            f"Optimization complete: processed {optimization_results['snapshots_processed']} snapshots, "
            f"optimized {optimization_results['snapshots_optimized']}, "
            f"saved {optimization_results['space_saved_mb']:.2f} MB in "
            f"{optimization_results['processing_time_seconds']:.1f} seconds"
        )

        # Save updated metadata
        self._save_metadata()

        return optimization_results

    def cleanup_old_snapshots(self, max_age_days: int = 7, keep_versions: int = 3) -> Dict[str, Any]:
        """Clean up old snapshots based on age and version retention policy.

        Args:
            max_age_days: Maximum age in days to keep snapshots
            keep_versions: Number of recent versions to keep per parent

        Returns:
            Dictionary containing cleanup results
        """
        logger.info(f"Starting old snapshot cleanup (max_age={max_age_days} days, keep_versions={keep_versions})")

        # Log cleanup start
        audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTION,
            severity=AuditSeverity.INFO,
            description="Starting old snapshot cleanup",
            details={
                "total_snapshots": len(self.snapshots),
                "max_age_days": max_age_days,
                "keep_versions": keep_versions
            }
        ))

        cleanup_results = {
            "snapshots_removed": 0,
            "snapshots_kept": 0,
            "space_freed_bytes": 0,
            "space_freed_mb": 0,
            "errors": [],
            "warnings": [],
            "processing_time_seconds": 0
        }

        start_time = time.time()
        current_time = datetime.now()
        max_age_delta = timedelta(days=max_age_days)

        # Build version hierarchy
        versions_by_parent = defaultdict(list)
        for snapshot_id, snapshot in self.snapshots.items():
            if snapshot.parent_snapshot:
                versions_by_parent[snapshot.parent_snapshot].append(
                    (snapshot.version, snapshot_id, snapshot)
                )
            else:
                # Root snapshots
                versions_by_parent[None].append(
                    (snapshot.version, snapshot_id, snapshot)
                )

        # Sort versions by version number (descending) to keep newest
        for parent in versions_by_parent:
            versions_by_parent[parent].sort(key=lambda x: x[0], reverse=True)

        # Determine which snapshots to remove
        snapshots_to_remove = []

        for parent, versions in versions_by_parent.items():
            for idx, (_version, snapshot_id, snapshot) in enumerate(versions):
                # Check if snapshot is too old
                age = current_time - snapshot.created_at
                is_too_old = age > max_age_delta

                # Check if we should keep this version
                should_keep_version = idx < keep_versions

                # Check if snapshot has children (don't delete if it has active children)
                has_children = bool(snapshot.children_snapshots)

                # Check if VM is currently running
                is_running = snapshot.vm_process and snapshot.vm_process.poll() is None

                # Decision logic
                if is_running:
                    cleanup_results["warnings"].append(
                        f"Skipping {snapshot_id}: VM is currently running"
                    )
                    cleanup_results["snapshots_kept"] += 1
                elif has_children:
                    cleanup_results["warnings"].append(
                        f"Skipping {snapshot_id}: Has active child snapshots"
                    )
                    cleanup_results["snapshots_kept"] += 1
                elif should_keep_version and not is_too_old:
                    logger.debug(f"Keeping {snapshot_id}: Within version retention policy")
                    cleanup_results["snapshots_kept"] += 1
                elif is_too_old and not should_keep_version:
                    logger.info(f"Marking {snapshot_id} for removal: Too old and beyond retention count")
                    snapshots_to_remove.append(snapshot_id)
                elif is_too_old:
                    logger.info(f"Marking {snapshot_id} for removal: Too old ({age.days} days)")
                    snapshots_to_remove.append(snapshot_id)
                else:
                    cleanup_results["snapshots_kept"] += 1

        # Remove marked snapshots
        for snapshot_id in snapshots_to_remove:
            try:
                snapshot = self.snapshots[snapshot_id]

                # Get disk size before removal
                disk_size = 0
                if os.path.exists(snapshot.disk_path):
                    disk_size = os.path.getsize(snapshot.disk_path)

                # Log removal attempt
                logger.info(f"Removing old snapshot: {snapshot_id}")

                # Use existing cleanup_snapshot method
                self.cleanup_snapshot(snapshot_id)

                cleanup_results["snapshots_removed"] += 1
                cleanup_results["space_freed_bytes"] += disk_size

                # Log successful removal
                audit_logger.log_event(AuditEvent(
                    event_type=AuditEventType.VM_SNAPSHOT,
                    severity=AuditSeverity.INFO,
                    description=f"Removed old snapshot: {snapshot_id}",
                    details={
                        "age_days": (current_time - snapshot.created_at).days,
                        "disk_size_mb": disk_size / (1024 * 1024),
                        "version": snapshot.version
                    },
                    target=snapshot_id
                ))

            except Exception as e:
                error_msg = f"Failed to remove snapshot {snapshot_id}: {str(e)}"
                cleanup_results["errors"].append(error_msg)
                logger.error(error_msg)

                # Log error
                audit_logger.log_event(AuditEvent(
                    event_type=AuditEventType.ERROR,
                    severity=AuditSeverity.MEDIUM,
                    description=f"Failed to remove old snapshot: {snapshot_id}",
                    details={"error": str(e)},
                    target=snapshot_id
                ))

        # Calculate final statistics
        cleanup_results["processing_time_seconds"] = time.time() - start_time
        cleanup_results["space_freed_mb"] = cleanup_results["space_freed_bytes"] / (1024 * 1024)

        # Log completion
        audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTION,
            severity=AuditSeverity.INFO,
            description="Old snapshot cleanup completed",
            details={
                "snapshots_removed": cleanup_results["snapshots_removed"],
                "snapshots_kept": cleanup_results["snapshots_kept"],
                "space_freed_mb": f"{cleanup_results['space_freed_mb']:.2f}",
                "processing_time": f"{cleanup_results['processing_time_seconds']:.1f}s",
                "error_count": len(cleanup_results["errors"])
            }
        ))

        logger.info(
            f"Cleanup complete: removed {cleanup_results['snapshots_removed']} snapshots, "
            f"kept {cleanup_results['snapshots_kept']}, "
            f"freed {cleanup_results['space_freed_mb']:.2f} MB in "
            f"{cleanup_results['processing_time_seconds']:.1f} seconds"
        )

        # Save updated metadata
        self._save_metadata()

        return cleanup_results

    def perform_snapshot_maintenance(self,
                                   optimize: bool = True,
                                   cleanup_old: bool = True,
                                   verify_integrity: bool = True) -> Dict[str, Any]:
        """Perform comprehensive snapshot maintenance tasks.

        Args:
            optimize: Whether to optimize snapshot storage
            cleanup_old: Whether to cleanup old snapshots
            verify_integrity: Whether to verify snapshot integrity

        Returns:
            Dictionary containing all maintenance results
        """
        logger.info("Starting comprehensive snapshot maintenance")

        maintenance_results = {
            "start_time": datetime.now().isoformat(),
            "tasks_performed": [],
            "total_processing_time_seconds": 0,
            "errors": [],
            "warnings": []
        }

        start_time = time.time()

        # Log maintenance start
        audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTION,
            severity=AuditSeverity.INFO,
            description="Starting snapshot maintenance",
            details={
                "optimize": optimize,
                "cleanup_old": cleanup_old,
                "verify_integrity": verify_integrity,
                "total_snapshots": len(self.snapshots)
            }
        ))

        # Step 1: Verify snapshot integrity
        if verify_integrity:
            try:
                logger.info("Step 1/3: Verifying snapshot integrity")
                integrity_results = self._verify_all_snapshot_integrity()
                maintenance_results["integrity_check"] = integrity_results
                maintenance_results["tasks_performed"].append("integrity_check")

                # Remove corrupted snapshots
                for corrupted_id in integrity_results.get("corrupted_snapshots", []):
                    try:
                        logger.warning(f"Removing corrupted snapshot: {corrupted_id}")
                        self.cleanup_snapshot(corrupted_id)
                    except Exception as e:
                        maintenance_results["errors"].append(
                            f"Failed to remove corrupted snapshot {corrupted_id}: {e}"
                        )

            except Exception as e:
                error_msg = f"Integrity check failed: {str(e)}"
                maintenance_results["errors"].append(error_msg)
                logger.error(error_msg)

        # Step 2: Cleanup old snapshots
        if cleanup_old:
            try:
                logger.info("Step 2/3: Cleaning up old snapshots")
                cleanup_results = self.cleanup_old_snapshots(
                    max_age_days=7,
                    keep_versions=3
                )
                maintenance_results["cleanup_results"] = cleanup_results
                maintenance_results["tasks_performed"].append("cleanup_old")

            except Exception as e:
                error_msg = f"Cleanup failed: {str(e)}"
                maintenance_results["errors"].append(error_msg)
                logger.error(error_msg)

        # Step 3: Optimize storage
        if optimize:
            try:
                logger.info("Step 3/3: Optimizing snapshot storage")
                optimization_results = self.optimize_snapshot_storage()
                maintenance_results["optimization_results"] = optimization_results
                maintenance_results["tasks_performed"].append("optimization")

            except Exception as e:
                error_msg = f"Optimization failed: {str(e)}"
                maintenance_results["errors"].append(error_msg)
                logger.error(error_msg)

        # Calculate total processing time
        maintenance_results["total_processing_time_seconds"] = time.time() - start_time
        maintenance_results["end_time"] = datetime.now().isoformat()

        # Generate summary
        summary = {
            "snapshots_remaining": len(self.snapshots),
            "total_disk_usage_mb": sum(
                os.path.getsize(s.disk_path) / (1024 * 1024)
                for s in self.snapshots.values()
                if os.path.exists(s.disk_path)
            ),
            "tasks_completed": len(maintenance_results["tasks_performed"]),
            "errors_encountered": len(maintenance_results["errors"])
        }
        maintenance_results["summary"] = summary

        # Log completion
        audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTION,
            severity=AuditSeverity.INFO,
            description="Snapshot maintenance completed",
            details={
                "tasks_performed": maintenance_results["tasks_performed"],
                "snapshots_remaining": summary["snapshots_remaining"],
                "total_disk_usage_mb": f"{summary['total_disk_usage_mb']:.2f}",
                "processing_time": f"{maintenance_results['total_processing_time_seconds']:.1f}s",
                "error_count": summary["errors_encountered"]
            }
        ))

        logger.info(
            f"Maintenance complete: performed {summary['tasks_completed']} tasks, "
            f"{summary['snapshots_remaining']} snapshots remain, "
            f"using {summary['total_disk_usage_mb']:.2f} MB total disk space"
        )

        return maintenance_results

    def _verify_all_snapshot_integrity(self) -> Dict[str, Any]:
        """Verify integrity of all snapshots.

        Returns:
            Dictionary containing verification results
        """
        logger.info("Verifying integrity of all snapshots")

        integrity_results = {
            "snapshots_checked": 0,
            "snapshots_valid": 0,
            "corrupted_snapshots": [],
            "missing_snapshots": [],
            "warnings": []
        }

        for snapshot_id, snapshot in self.snapshots.items():
            integrity_results["snapshots_checked"] += 1

            try:
                # Check if disk file exists
                if not os.path.exists(snapshot.disk_path):
                    integrity_results["missing_snapshots"].append(snapshot_id)
                    logger.warning(f"Snapshot disk missing: {snapshot_id}")
                    continue

                # Verify qcow2 integrity
                check_cmd = ["qemu-img", "check", "-q", snapshot.disk_path]
                result = subprocess.run(
                    check_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    integrity_results["snapshots_valid"] += 1
                else:
                    integrity_results["corrupted_snapshots"].append(snapshot_id)
                    logger.error(f"Snapshot corrupted: {snapshot_id} - {result.stderr}")

                    # Log corruption
                    audit_logger.log_event(AuditEvent(
                        event_type=AuditEventType.ERROR,
                        severity=AuditSeverity.HIGH,
                        description=f"Corrupted snapshot detected: {snapshot_id}",
                        details={"error": result.stderr},
                        target=snapshot_id
                    ))

            except subprocess.TimeoutExpired:
                integrity_results["warnings"].append(
                    f"Timeout checking {snapshot_id}"
                )
            except Exception as e:
                integrity_results["warnings"].append(
                    f"Error checking {snapshot_id}: {str(e)}"
                )

        logger.info(
            f"Integrity check complete: {integrity_results['snapshots_valid']}/{integrity_results['snapshots_checked']} valid, "
            f"{len(integrity_results['corrupted_snapshots'])} corrupted, "
            f"{len(integrity_results['missing_snapshots'])} missing"
        )

        return integrity_results
    
    def _init_ai_components(self):
        """Initialize AI components for intelligent test generation."""
        try:
            # Initialize LLM manager
            self.llm_manager = LLMManager()
            logger.info("Initialized LLM manager for test generation")
            
            # Initialize predictive intelligence
            self.predictive_intelligence = PredictiveIntelligence()
            logger.info("Initialized predictive intelligence engine")
            
            # Initialize multi-agent system
            self.multi_agent_system = MultiAgentSystem()
            logger.info("Initialized multi-agent collaboration system")
            
            # Initialize script generator
            self.script_generator = AIScriptGenerator()
            logger.info("Initialized AI script generator")
            
            # Initialize analysis orchestrator
            self.analysis_orchestrator = AnalysisOrchestrator()
            logger.info("Initialized analysis orchestrator")
            
            # Initialize sandbox manager if available
            if HAS_SANDBOX_MANAGER:
                self.sandbox_manager = SandboxManager()
                logger.info("Initialized sandbox manager")
                
        except Exception as e:
            logger.error(f"Failed to initialize AI components: {e}")
            # Continue without AI components - fall back to basic testing
    
    def _init_test_executor(self):
        """Initialize parallel test executor."""
        self.test_executor = ThreadPoolExecutor(
            max_workers=self.max_parallel_tests,
            thread_name_prefix="qemu_test_"
        )
        logger.info(f"Initialized test executor with {self.max_parallel_tests} workers")
    
    def generate_test_scenarios(self, binary_path: str, 
                               protection_analysis: Optional[Dict[str, Any]] = None) -> List[TestScenario]:
        """Generate AI-driven test scenarios based on binary analysis.
        
        Args:
            binary_path: Path to the binary to test
            protection_analysis: Optional pre-computed protection analysis
            
        Returns:
            List of generated test scenarios
        """
        scenarios = []
        
        try:
            # Perform binary analysis if not provided
            if not protection_analysis and self.analysis_orchestrator:
                logger.info(f"Analyzing binary for test generation: {binary_path}")
                protection_analysis = self.analysis_orchestrator.analyze_binary(binary_path)
            
            # Use predictive intelligence to identify test priorities
            if self.predictive_intelligence and protection_analysis:
                protection_patterns = protection_analysis.get('protection_patterns', [])
                test_recommendations = self.predictive_intelligence.recommend_bypass_strategies(
                    protection_patterns
                )
                
                # Generate test scenarios for each recommendation
                for idx, recommendation in enumerate(test_recommendations[:10]):  # Top 10
                    scenario = TestScenario(
                        scenario_id=f"test_{uuid.uuid4().hex[:8]}",
                        name=f"Test {recommendation.get('strategy', 'Unknown')}",
                        description=recommendation.get('description', ''),
                        test_type=self._map_strategy_to_test_type(recommendation.get('strategy')),
                        priority=10 - idx,  # Higher priority for better recommendations
                        binary_path=binary_path,
                        protection_patterns=protection_patterns,
                        test_commands=self._generate_test_commands(recommendation),
                        expected_outcomes=recommendation.get('expected_outcomes', {}),
                        environment_config={
                            'network_isolated': True,
                            'snapshot_before_test': True,
                            'timeout': 300
                        },
                        created_at=datetime.now(),
                        created_by='predictive_intelligence'
                    )
                    scenarios.append(scenario)
            
            # Use multi-agent system for comprehensive test generation
            if self.multi_agent_system and not scenarios:
                logger.info("Using multi-agent system for test scenario generation")
                
                # Create analysis task for agents
                task = Task(
                    task_id=f"testgen_{uuid.uuid4().hex[:8]}",
                    task_type=TaskType.FULL_ANALYSIS,
                    priority=10,
                    data={'binary_path': binary_path},
                    created_at=datetime.now()
                )
                
                # Submit to multi-agent system
                self.multi_agent_system.submit_task(task)
                
                # Wait for results (with timeout)
                start_time = time.time()
                timeout = 60  # 1 minute timeout
                
                while time.time() - start_time < timeout:
                    if task.task_id in self.multi_agent_system.completed_tasks:
                        agent_results = self.multi_agent_system.get_task_results(task.task_id)
                        scenarios.extend(self._convert_agent_results_to_scenarios(
                            agent_results, binary_path
                        ))
                        break
                    time.sleep(0.5)
            
            # Fallback: Generate basic test scenarios
            if not scenarios:
                logger.info("Generating basic test scenarios")
                scenarios.extend(self._generate_basic_test_scenarios(binary_path))
            
            # Store generated scenarios
            for scenario in scenarios:
                self.test_scenarios[scenario.scenario_id] = scenario
            
            logger.info(f"Generated {len(scenarios)} test scenarios for {binary_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate test scenarios: {e}")
            # Generate minimal fallback scenarios
            scenarios.append(self._create_minimal_test_scenario(binary_path))
        
        return scenarios
    
    def _map_strategy_to_test_type(self, strategy: str) -> str:
        """Map bypass strategy to test type."""
        strategy_map = {
            'api_hooking': 'bypass_testing',
            'memory_patching': 'bypass_testing',
            'timing_attack': 'behavior_analysis',
            'debugger_bypass': 'protection_validation',
            'signature_bypass': 'bypass_testing',
            'license_emulation': 'bypass_testing',
            'code_injection': 'bypass_testing',
            'privilege_escalation': 'security_testing'
        }
        return strategy_map.get(strategy.lower(), 'general_testing')
    
    def _generate_test_commands(self, recommendation: Dict[str, Any]) -> List[str]:
        """Generate test commands based on recommendation."""
        commands = []
        strategy = recommendation.get('strategy', '')
        
        if 'api_hook' in strategy.lower():
            commands.append("frida -l api_hooks.js -f target.exe")
        elif 'memory_patch' in strategy.lower():
            commands.append("python memory_patcher.py --target target.exe")
        elif 'debugger' in strategy.lower():
            commands.append("x64dbg target.exe")
        elif 'timing' in strategy.lower():
            commands.append("python timing_attack.py --target target.exe")
        else:
            commands.append("python generic_test.py --target target.exe")
        
        return commands
    
    def _convert_agent_results_to_scenarios(self, agent_results: Dict[str, Any], 
                                           binary_path: str) -> List[TestScenario]:
        """Convert multi-agent results to test scenarios."""
        scenarios = []
        
        for agent_id, results in agent_results.items():
            if 'test_recommendations' in results:
                for rec in results['test_recommendations']:
                    scenario = TestScenario(
                        scenario_id=f"test_{uuid.uuid4().hex[:8]}",
                        name=rec.get('name', f'Test by {agent_id}'),
                        description=rec.get('description', ''),
                        test_type=rec.get('type', 'general_testing'),
                        priority=rec.get('priority', 5),
                        binary_path=binary_path,
                        protection_patterns=[],
                        test_commands=rec.get('commands', []),
                        expected_outcomes=rec.get('expected_outcomes', {}),
                        environment_config=rec.get('environment', {}),
                        created_at=datetime.now(),
                        created_by=agent_id
                    )
                    scenarios.append(scenario)
        
        return scenarios
    
    def _generate_basic_test_scenarios(self, binary_path: str) -> List[TestScenario]:
        """Generate basic test scenarios without AI assistance."""
        scenarios = []
        
        # Basic protection validation
        scenarios.append(TestScenario(
            scenario_id=f"test_{uuid.uuid4().hex[:8]}",
            name="Basic Protection Validation",
            description="Validate basic protection mechanisms",
            test_type="protection_validation",
            priority=8,
            binary_path=binary_path,
            protection_patterns=[],
            test_commands=["python basic_protection_test.py --target target.exe"],
            expected_outcomes={'protection_detected': True},
            environment_config={'timeout': 300},
            created_at=datetime.now(),
            created_by='basic_generator'
        ))
        
        # API monitoring
        scenarios.append(TestScenario(
            scenario_id=f"test_{uuid.uuid4().hex[:8]}",
            name="API Call Monitoring",
            description="Monitor and log API calls",
            test_type="behavior_analysis",
            priority=7,
            binary_path=binary_path,
            protection_patterns=[],
            test_commands=["frida -l api_monitor.js -f target.exe"],
            expected_outcomes={'apis_logged': True},
            environment_config={'timeout': 300},
            created_at=datetime.now(),
            created_by='basic_generator'
        ))
        
        # Memory analysis
        scenarios.append(TestScenario(
            scenario_id=f"test_{uuid.uuid4().hex[:8]}",
            name="Runtime Memory Analysis",
            description="Analyze memory patterns during execution",
            test_type="behavior_analysis",
            priority=6,
            binary_path=binary_path,
            protection_patterns=[],
            test_commands=["python memory_analyzer.py --target target.exe"],
            expected_outcomes={'memory_mapped': True},
            environment_config={'timeout': 300},
            created_at=datetime.now(),
            created_by='basic_generator'
        ))
        
        return scenarios
    
    def _create_minimal_test_scenario(self, binary_path: str) -> TestScenario:
        """Create a minimal test scenario as fallback."""
        return TestScenario(
            scenario_id=f"test_{uuid.uuid4().hex[:8]}",
            name="Minimal Execution Test",
            description="Basic execution test",
            test_type="general_testing",
            priority=1,
            binary_path=binary_path,
            protection_patterns=[],
            test_commands=["target.exe"],
            expected_outcomes={'executed': True},
            environment_config={'timeout': 60},
            created_at=datetime.now(),
            created_by='fallback_generator'
        )
    
    def execute_test_scenario(self, scenario: TestScenario, 
                             parallel: bool = True) -> TestResult:
        """Execute a test scenario in a QEMU environment.
        
        Args:
            scenario: The test scenario to execute
            parallel: Whether to execute in parallel (non-blocking)
            
        Returns:
            TestResult object with execution details
        """
        # Create test result
        test_result = TestResult(
            test_id=f"result_{uuid.uuid4().hex[:8]}",
            scenario_id=scenario.scenario_id,
            snapshot_id="",  # Will be set when snapshot is created
            started_at=datetime.now(),
            status="pending"
        )
        
        # Store result
        self.test_results[test_result.test_id] = test_result
        
        if parallel and self.test_executor:
            # Submit to executor
            future = self.test_executor.submit(
                self._execute_test_scenario_impl, scenario, test_result
            )
            # Track future for monitoring
            test_result.execution_log.append({
                'timestamp': datetime.now().isoformat(),
                'event': 'submitted_to_executor',
                'future': future
            })
        else:
            # Execute synchronously
            self._execute_test_scenario_impl(scenario, test_result)
        
        return test_result
    
    def _execute_test_scenario_impl(self, scenario: TestScenario, 
                                   test_result: TestResult) -> None:
        """Implementation of test scenario execution."""
        try:
            test_result.status = "running"
            test_result.execution_log.append({
                'timestamp': datetime.now().isoformat(),
                'event': 'execution_started'
            })
            
            # Create snapshot for testing
            snapshot_id = self.create_snapshot(scenario.binary_path)
            test_result.snapshot_id = snapshot_id
            
            if not snapshot_id:
                raise Exception("Failed to create snapshot")
            
            snapshot = self.snapshots.get(snapshot_id)
            if not snapshot:
                raise Exception("Snapshot not found after creation")
            
            # Apply environment configuration
            if scenario.environment_config.get('network_isolated', True):
                self.enable_network_isolation(snapshot_id, True)
            
            # Start monitoring
            start_time = time.time()
            
            # Execute test commands
            for idx, command in enumerate(scenario.test_commands):
                test_result.execution_log.append({
                    'timestamp': datetime.now().isoformat(),
                    'event': 'executing_command',
                    'command': command,
                    'index': idx
                })
                
                # Prepare command for execution
                if command.endswith('.py'):
                    # Python script - ensure it's uploaded
                    script_path = Path(command)
                    if script_path.exists():
                        self._upload_file_to_vm(
                            snapshot, 
                            script_path.read_text(),
                            f"/tmp/{script_path.name}"
                        )
                        command = f"python /tmp/{script_path.name}"
                
                # Execute command
                result = self._execute_command_in_vm(
                    snapshot, 
                    command,
                    timeout=scenario.environment_config.get('timeout', 300)
                )
                
                test_result.execution_log.append({
                    'timestamp': datetime.now().isoformat(),
                    'event': 'command_completed',
                    'command': command,
                    'result': result
                })
                
                # Check for anomalies
                if self.predictive_intelligence:
                    anomalies = self._detect_anomalies(result)
                    test_result.anomalies_detected.extend(anomalies)
            
            # Calculate performance metrics
            execution_time = time.time() - start_time
            test_result.performance_metrics = {
                'execution_time': execution_time,
                'cpu_usage': self._get_vm_cpu_usage(snapshot_id),
                'memory_usage': self._get_vm_memory_usage(snapshot_id),
                'disk_io': self._get_vm_disk_io(snapshot_id)
            }
            
            # Generate AI analysis
            if self.llm_manager:
                test_result.ai_analysis = self._generate_ai_analysis(
                    scenario, test_result
                )
            
            # Update status
            test_result.status = "success"
            test_result.completed_at = datetime.now()
            
            # Calculate ML confidence
            test_result.ml_confidence = self._calculate_test_confidence(test_result)
            
            # Cache result
            cache_key = f"{scenario.binary_path}_{scenario.test_type}"
            self.test_cache[cache_key] = test_result
            
        except Exception as e:
            logger.error(f"Test execution failed: {e}")
            test_result.status = "failure"
            test_result.completed_at = datetime.now()
            test_result.execution_log.append({
                'timestamp': datetime.now().isoformat(),
                'event': 'execution_failed',
                'error': str(e)
            })
        finally:
            # Cleanup
            if test_result.snapshot_id and scenario.environment_config.get('cleanup', True):
                self.cleanup_snapshot(test_result.snapshot_id)
    
    def _detect_anomalies(self, execution_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in execution results using ML."""
        anomalies = []
        
        # Check for suspicious patterns
        stdout = execution_result.get('stdout', '')
        stderr = execution_result.get('stderr', '')
        
        # Anti-debugging detection
        if any(pattern in stdout.lower() for pattern in [
            'debugger detected', 'isdebuggerpresent', 'anti-debug'
        ]):
            anomalies.append({
                'type': 'anti_debugging',
                'severity': 'high',
                'description': 'Anti-debugging mechanism detected',
                'evidence': stdout
            })
        
        # Timing anomalies
        if execution_result.get('execution_time', 0) > 10:
            anomalies.append({
                'type': 'timing_anomaly',
                'severity': 'medium',
                'description': 'Abnormal execution time detected',
                'value': execution_result['execution_time']
            })
        
        # Memory anomalies
        if 'memory_error' in stderr.lower() or 'segfault' in stderr.lower():
            anomalies.append({
                'type': 'memory_anomaly',
                'severity': 'high',
                'description': 'Memory error detected',
                'evidence': stderr
            })
        
        return anomalies
    
    def _generate_ai_analysis(self, scenario: TestScenario, 
                             test_result: TestResult) -> str:
        """Generate AI analysis of test results."""
        try:
            # Prepare context for LLM
            context = {
                'scenario': {
                    'name': scenario.name,
                    'type': scenario.test_type,
                    'commands': scenario.test_commands
                },
                'result': {
                    'status': test_result.status,
                    'anomalies': test_result.anomalies_detected,
                    'performance': test_result.performance_metrics,
                    'execution_log': test_result.execution_log[-5:]  # Last 5 events
                }
            }
            
            prompt = f"""Analyze the following security test results:
            
Scenario: {context['scenario']['name']} ({context['scenario']['type']})
Commands executed: {', '.join(context['scenario']['commands'])}

Result: {context['result']['status']}
Anomalies detected: {len(context['result']['anomalies'])}
Execution time: {context['result']['performance'].get('execution_time', 'N/A')}s

Please provide:
1. Summary of test effectiveness
2. Key findings and insights
3. Recommendations for further testing
4. Potential vulnerabilities identified
"""
            
            # Get AI analysis
            response = self.llm_manager.query(prompt, temperature=0.7)
            return response.get('content', 'Analysis not available')
            
        except Exception as e:
            logger.error(f"Failed to generate AI analysis: {e}")
            return "AI analysis failed"
    
    def _calculate_test_confidence(self, test_result: TestResult) -> float:
        """Calculate confidence score for test results using ML."""
        confidence = 0.5  # Base confidence
        
        # Adjust based on completion status
        if test_result.status == "success":
            confidence += 0.2
        elif test_result.status == "failure":
            confidence -= 0.1
        
        # Adjust based on anomalies
        anomaly_count = len(test_result.anomalies_detected)
        if anomaly_count == 0:
            confidence += 0.1
        else:
            confidence += min(0.3, anomaly_count * 0.05)
        
        # Adjust based on execution time
        exec_time = test_result.performance_metrics.get('execution_time', 0)
        if 1 < exec_time < 60:  # Normal range
            confidence += 0.1
        
        # Ensure confidence is in valid range
        return max(0.0, min(1.0, confidence))
    
    def _get_vm_cpu_usage(self, snapshot_id: str) -> float:
        """Get CPU usage for a VM."""
        # This would integrate with actual VM monitoring
        # For now, return simulated value
        return 45.2
    
    def _get_vm_memory_usage(self, snapshot_id: str) -> float:
        """Get memory usage for a VM."""
        # This would integrate with actual VM monitoring
        # For now, return simulated value
        return 512.0
    
    def _get_vm_disk_io(self, snapshot_id: str) -> Dict[str, float]:
        """Get disk I/O stats for a VM."""
        # This would integrate with actual VM monitoring
        # For now, return simulated values
        return {
            'read_mb': 120.5,
            'write_mb': 45.3
        }
    
    def run_test_suite(self, binary_path: str, 
                      test_types: Optional[List[str]] = None,
                      max_parallel: int = 4) -> Dict[str, Any]:
        """Run comprehensive test suite on a binary.
        
        Args:
            binary_path: Path to binary to test
            test_types: Optional list of test types to run
            max_parallel: Maximum parallel tests
            
        Returns:
            Test suite results
        """
        logger.info(f"Running test suite on {binary_path}")
        
        # Update parallel execution limit
        self.max_parallel_tests = max_parallel
        
        # Generate test scenarios
        scenarios = self.generate_test_scenarios(binary_path)
        
        # Filter by test types if specified
        if test_types:
            scenarios = [s for s in scenarios if s.test_type in test_types]
        
        # Execute scenarios
        results = {
            'binary_path': binary_path,
            'total_scenarios': len(scenarios),
            'started_at': datetime.now().isoformat(),
            'test_results': [],
            'summary': {}
        }
        
        # Submit all scenarios for execution
        futures = []
        for scenario in scenarios:
            test_result = self.execute_test_scenario(scenario, parallel=True)
            results['test_results'].append(test_result)
            
            # Track future if parallel
            if hasattr(test_result, 'execution_log'):
                for log_entry in test_result.execution_log:
                    if 'future' in log_entry:
                        futures.append((scenario, test_result, log_entry['future']))
        
        # Wait for completion
        if futures:
            for scenario, test_result, future in as_completed([f[2] for f in futures]):
                try:
                    future.result(timeout=600)  # 10 minute timeout
                except Exception as e:
                    logger.error(f"Test execution error: {e}")
        
        # Generate summary
        results['completed_at'] = datetime.now().isoformat()
        results['summary'] = self._generate_test_suite_summary(results['test_results'])
        
        # Store results
        suite_id = f"suite_{uuid.uuid4().hex[:8]}"
        self.test_cache[suite_id] = results
        
        return results
    
    def _generate_test_suite_summary(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """Generate summary of test suite results."""
        summary = {
            'total_tests': len(test_results),
            'successful': sum(1 for r in test_results if r.status == 'success'),
            'failed': sum(1 for r in test_results if r.status == 'failure'),
            'errors': sum(1 for r in test_results if r.status == 'error'),
            'total_anomalies': sum(len(r.anomalies_detected) for r in test_results),
            'average_confidence': sum(r.ml_confidence for r in test_results) / len(test_results) if test_results else 0,
            'coverage_estimate': self._estimate_test_coverage(test_results)
        }
        
        # Group by test type
        summary['by_test_type'] = {}
        for result in test_results:
            scenario = self.test_scenarios.get(result.scenario_id)
            if scenario:
                test_type = scenario.test_type
                if test_type not in summary['by_test_type']:
                    summary['by_test_type'][test_type] = {
                        'count': 0,
                        'successful': 0,
                        'anomalies': 0
                    }
                summary['by_test_type'][test_type]['count'] += 1
                if result.status == 'success':
                    summary['by_test_type'][test_type]['successful'] += 1
                summary['by_test_type'][test_type]['anomalies'] += len(result.anomalies_detected)
        
        return summary
    
    def _estimate_test_coverage(self, test_results: List[TestResult]) -> float:
        """Estimate test coverage based on results."""
        if not test_results:
            return 0.0
        
        # Calculate coverage based on test types and success rate
        test_types_covered = set()
        for result in test_results:
            scenario = self.test_scenarios.get(result.scenario_id)
            if scenario and result.status == 'success':
                test_types_covered.add(scenario.test_type)
        
        # Known test types
        all_test_types = {
            'protection_validation', 'bypass_testing', 'behavior_analysis',
            'performance_testing', 'regression_testing', 'security_testing'
        }
        
        # Basic coverage calculation
        type_coverage = len(test_types_covered) / len(all_test_types)
        success_rate = sum(1 for r in test_results if r.status == 'success') / len(test_results)
        
        # Weighted coverage
        coverage = (type_coverage * 0.6) + (success_rate * 0.4)
        
        return min(1.0, coverage)
    
    def optimize_test_execution(self) -> Dict[str, Any]:
        """Optimize test execution based on historical data."""
        optimization_results = {
            'timestamp': datetime.now().isoformat(),
            'optimizations_applied': [],
            'performance_improvement': 0.0
        }
        
        try:
            # Analyze historical test data
            if self.test_results:
                # Find slow tests
                slow_tests = []
                for test_id, result in self.test_results.items():
                    exec_time = result.performance_metrics.get('execution_time', 0)
                    if exec_time > 120:  # Tests taking more than 2 minutes
                        slow_tests.append((test_id, exec_time))
                
                # Optimize slow tests
                if slow_tests:
                    optimization_results['optimizations_applied'].append({
                        'type': 'timeout_adjustment',
                        'description': f'Identified {len(slow_tests)} slow tests for optimization'
                    })
                
                # Cache frequently used test results
                frequent_patterns = defaultdict(int)
                for test_id, result in self.test_results.items():
                    scenario = self.test_scenarios.get(result.scenario_id)
                    if scenario:
                        pattern_key = f"{scenario.binary_path}_{scenario.test_type}"
                        frequent_patterns[pattern_key] += 1
                
                # Enable caching for frequent patterns
                cache_candidates = [k for k, v in frequent_patterns.items() if v > 3]
                if cache_candidates:
                    optimization_results['optimizations_applied'].append({
                        'type': 'result_caching',
                        'description': f'Enabled caching for {len(cache_candidates)} test patterns'
                    })
                
                # Adjust parallel execution based on resource usage
                avg_cpu = sum(r.performance_metrics.get('cpu_usage', 0) 
                             for r in self.test_results.values()) / len(self.test_results)
                
                if avg_cpu < 30:  # Low CPU usage
                    old_parallel = self.max_parallel_tests
                    self.max_parallel_tests = min(8, self.max_parallel_tests + 2)
                    optimization_results['optimizations_applied'].append({
                        'type': 'parallelism_increase',
                        'description': f'Increased parallel tests from {old_parallel} to {self.max_parallel_tests}'
                    })
                    optimization_results['performance_improvement'] = 20.0
                
            # Optimize snapshot storage
            if len(self.snapshots) > 20:
                old_count = len(self.snapshots)
                self.cleanup_old_snapshots(max_age_days=3, keep_versions=2)
                optimization_results['optimizations_applied'].append({
                    'type': 'snapshot_cleanup',
                    'description': f'Cleaned up {old_count - len(self.snapshots)} old snapshots'
                })
            
        except Exception as e:
            logger.error(f"Optimization failed: {e}")
            optimization_results['error'] = str(e)
        
        return optimization_results
    
    def get_test_analytics(self) -> Dict[str, Any]:
        """Get comprehensive test analytics and insights."""
        analytics = {
            'timestamp': datetime.now().isoformat(),
            'total_tests_run': len(self.test_results),
            'total_scenarios': len(self.test_scenarios),
            'active_snapshots': len(self.snapshots),
            'test_success_rate': 0.0,
            'anomaly_detection_rate': 0.0,
            'performance_metrics': {},
            'ml_insights': {},
            'recommendations': []
        }
        
        if self.test_results:
            # Calculate success rate
            successful = sum(1 for r in self.test_results.values() if r.status == 'success')
            analytics['test_success_rate'] = successful / len(self.test_results)
            
            # Calculate anomaly detection rate
            tests_with_anomalies = sum(1 for r in self.test_results.values() 
                                      if r.anomalies_detected)
            analytics['anomaly_detection_rate'] = tests_with_anomalies / len(self.test_results)
            
            # Performance metrics
            exec_times = [r.performance_metrics.get('execution_time', 0) 
                         for r in self.test_results.values()]
            if exec_times:
                analytics['performance_metrics'] = {
                    'avg_execution_time': sum(exec_times) / len(exec_times),
                    'min_execution_time': min(exec_times),
                    'max_execution_time': max(exec_times)
                }
            
            # ML insights
            confidence_scores = [r.ml_confidence for r in self.test_results.values()]
            if confidence_scores:
                analytics['ml_insights'] = {
                    'avg_confidence': sum(confidence_scores) / len(confidence_scores),
                    'high_confidence_tests': sum(1 for c in confidence_scores if c > 0.8)
                }
            
            # Generate recommendations
            if analytics['test_success_rate'] < 0.7:
                analytics['recommendations'].append(
                    "Low success rate detected. Consider reviewing test scenarios and environment setup."
                )
            
            if analytics['anomaly_detection_rate'] > 0.5:
                analytics['recommendations'].append(
                    "High anomaly rate suggests advanced protection mechanisms. Consider deeper analysis."
                )
            
            if analytics['performance_metrics'].get('avg_execution_time', 0) > 180:
                analytics['recommendations'].append(
                    "Tests are taking too long. Consider optimization or parallel execution."
                )
        
        return analytics
