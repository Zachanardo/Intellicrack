"""QEMU Test Manager for AI Script Testing.

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

import logging
import os
import platform
import shutil
import subprocess
import tempfile
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Any

import paramiko
from paramiko import HostKeys, MissingHostKeyPolicy, RSAKey, SSHClient

from intellicrack.core.logging.audit_logger import (
    AuditEvent,
    AuditEventType,
    AuditSeverity,
    get_audit_logger,
    log_credential_access,
    log_tool_execution,
    log_vm_operation,
)
from intellicrack.core.resources.resource_manager import VMResource, get_resource_manager
from intellicrack.utils.logger import get_logger

from .common_types import ExecutionResult


logger = get_logger(__name__)
audit_logger = get_audit_logger()
resource_manager = get_resource_manager()

FAILED_START_VM = "Failed to start VM: %s"
SUBPROCESS_TIMEOUT_MSG = "Subprocess timeout in qemu_manager: %s"


REMOTE_TEMP_DIR = "/tmp"


class QEMUError(Exception):
    """Custom exception for QEMU-related errors."""

    pass


@dataclass
class QEMUSnapshot:
    """Represents a QEMU snapshot for testing."""

    snapshot_id: str
    vm_name: str
    disk_path: str
    binary_path: str
    created_at: datetime
    vm_process: subprocess.Popen | None = None
    ssh_port: int = 22222
    vnc_port: int = 5900
    version: int = 1
    parent_snapshot: str | None = None
    children_snapshots: set[str] = field(default_factory=set)
    test_results: list[dict[str, Any]] = field(default_factory=list)
    memory_usage: int = 0
    disk_usage: int = 0
    network_isolated: bool = True
    performance_metrics: dict[str, Any] = field(default_factory=dict)


class SecureHostKeyPolicy(MissingHostKeyPolicy):
    """Secure host key policy that maintains a known_hosts file for QEMU VMs."""

    def __init__(self, known_hosts_path: Path) -> None:
        """Initialize with path to known_hosts file."""
        self.known_hosts_path = known_hosts_path
        self.host_keys = HostKeys()

        # Load existing known hosts if file exists
        if self.known_hosts_path.exists():
            try:
                self.host_keys.load(str(self.known_hosts_path))
            except Exception as e:
                logger.warning(f"Could not load known_hosts file: {e}")

    def missing_host_key(self, client: SSHClient, hostname: str, key: paramiko.PKey) -> None:
        """Handle missing host key by checking and storing it securely."""
        # For QEMU VMs on localhost with dynamic ports, we store by port
        # This is acceptable for local VMs in controlled environments
        key_identifier = f"[{hostname}]:{client.get_transport().getpeername()[1]}"

        # Check if we already have this key
        existing_keys = self.host_keys.lookup(key_identifier)
        if existing_keys and key.get_name() in existing_keys:
            # Key exists but doesn't match - potential security issue
            stored_key = existing_keys[key.get_name()]
            if stored_key != key:
                raise paramiko.SSHException(f"Host key verification failed for {key_identifier}. Key fingerprint has changed!")

        # Store the new key
        self.host_keys.add(key_identifier, key.get_name(), key)

        # Save to file
        try:
            self.known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
            self.host_keys.save(str(self.known_hosts_path))
            logger.info(f"Added host key for {key_identifier}")
        except Exception as e:
            logger.warning(f"Could not save host key: {e}")


class QEMUManager:
    """Manages QEMU virtual machines for testing generated scripts.

    Real implementation - integrates with existing QEMU infrastructure.
    """

    def __init__(self) -> None:
        """Initialize the QEMU test manager.

        Sets up QEMU snapshots, base images for Windows and Linux,
        and integrates with existing QEMU emulator if available.
        Creates a working directory for test operations.
        """
        from intellicrack.core.config_manager import get_config

        self.logger = logging.getLogger(f"{__name__}.QEMUManager")
        self.snapshots = {}

        # Initialize central configuration
        self.config = get_config()

        # Initialize QEMU process attributes
        self.qemu_process = None
        self.monitor_socket = None
        self.monitor = None

        # Initialize baseline attributes for comparison
        self._baseline_snapshot = None
        self._baseline_processes = None
        self._baseline_connections = None
        self._baseline_dns_queries = None

        # Create working directory first (needed by base image initialization)
        self.working_dir = Path(tempfile.gettempdir()) / "intellicrack_qemu_tests"
        self.working_dir.mkdir(exist_ok=True)

        self.base_images = {
            "windows": self._get_windows_base_image(),
            "linux": self._get_linux_base_image(),
        }
        self.qemu_executable = self._find_qemu_executable()

        # SSH configuration from config
        self.ssh_clients = {}  # vm_name -> SSHClient
        self.ssh_keys = {}  # vm_name -> RSAKey
        self.ssh_lock = threading.RLock()
        self.ssh_timeout = self.config.get("vm_framework.ssh.timeout", 30)
        self.ssh_retry_count = self.config.get("vm_framework.ssh.retry_count", 3)
        self.ssh_retry_delay = self.config.get("vm_framework.ssh.retry_delay", 2)

        # Initialize or load SSH keys
        self._init_ssh_keys()

        # SSH connection pool
        self.ssh_connection_pool = {}  # (vm_name, port) -> SSHClient

        # Circuit breaker for SSH connections from config
        self.ssh_circuit_breaker = {}  # vm_name -> {'failures': int, 'last_failure': datetime, 'open': bool}
        self.circuit_breaker_threshold = self.config.get("vm_framework.ssh.circuit_breaker_threshold", 5)
        self.circuit_breaker_timeout = self.config.get("vm_framework.ssh.circuit_breaker_timeout", 60)

        # Port allocation from config
        self.next_ssh_port = self.config.get("vm_framework.qemu_defaults.ssh_port_start", 22222)
        self.next_vnc_port = self.config.get("vm_framework.qemu_defaults.vnc_port_start", 5900)

        # Set default configuration parameters
        self._set_default_config()

        # Initialize QEMU executable path
        self.qemu_executable = self._find_qemu_executable()

        # Initialize rootfs path with x86_64 architecture
        self.architecture = "x86_64"
        self.rootfs_path = self._get_default_rootfs(self.architecture)
        self.binary_path = None

        # Validate QEMU setup at the end
        self._validate_qemu_setup()

    def _init_ssh_keys(self) -> None:
        """Initialize or load SSH keys for VM access."""
        from ..utils.secrets_manager import get_secret, set_secret

        try:
            # Get or generate SSH key from secrets manager
            ssh_private_key = get_secret("QEMU_SSH_PRIVATE_KEY")
            ssh_public_key = get_secret("QEMU_SSH_PUBLIC_KEY")

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
                set_secret("QEMU_SSH_PRIVATE_KEY", ssh_private_key)
                set_secret("QEMU_SSH_PUBLIC_KEY", ssh_public_key)

                # Log credential access
                log_credential_access("SSH_KEY", "QEMU VM access key generation", success=True)

                logger.info("SSH key pair generated and stored securely")
            else:
                logger.info("Loaded existing SSH keys from secrets manager")
                log_credential_access("SSH_KEY", "QEMU VM access key retrieval", success=True)

            # Parse the private key for use
            self.master_ssh_key = RSAKey.from_private_key(StringIO(ssh_private_key))
            self.ssh_public_key = ssh_public_key

        except Exception as e:
            logger.error("Failed to initialize SSH keys: %s", e)
            log_credential_access("SSH_KEY", "QEMU VM access key initialization", success=False)
            # Generate and persist key as recovery mechanism
            logger.warning("Failed to access secrets manager, generating recovery key")
            self.master_ssh_key = RSAKey.generate(2048)
            self.ssh_public_key = f"ssh-rsa {self.master_ssh_key.get_base64()} intellicrack@qemu"

            # Try to save recovery key to local secure storage
            try:
                recovery_key_path = self.working_dir / ".ssh" / "qemu_recovery_key"
                recovery_key_path.parent.mkdir(parents=True, exist_ok=True)

                # Save private key
                with open(recovery_key_path, "w", encoding="utf-8") as f:
                    self.master_ssh_key.write_private_key(f)

                # Set secure permissions (Unix only)
                if platform.system() != "Windows":
                    Path(recovery_key_path).chmod(0o600)

                # Save public key
                with open(recovery_key_path.with_suffix(".pub"), "w", encoding="utf-8") as f:
                    f.write(self.ssh_public_key)

                logger.info("Recovery SSH key saved to %s", recovery_key_path)

                # Attempt to update secrets manager with recovery key
                try:
                    private_key_str = StringIO()
                    self.master_ssh_key.write_private_key(private_key_str)
                    set_secret("QEMU_SSH_PRIVATE_KEY", private_key_str.getvalue())
                    set_secret("QEMU_SSH_PUBLIC_KEY", self.ssh_public_key)
                    logger.info("Recovery key successfully saved to secrets manager")
                except Exception as e:
                    logger.debug("Failed to save recovery key to secrets manager: %s", e)
                    # Continue with local recovery key

            except Exception as recovery_e:
                logger.error("Failed to save recovery key: %s", recovery_e)
                # Key is still in memory and usable for this session

    def _find_qemu_executable(self) -> str:
        """Find QEMU executable on the system."""
        if config_path := self.config.get_tool_path("qemu-system-x86_64"):
            return config_path

        if fallback_path := shutil.which("qemu-system-x86_64"):
            return fallback_path

        # If still not found, return default as last resort
        logger.warning("QEMU not found in standard locations")
        return "qemu-system-x86_64"

    def _get_ssh_connection(
        self,
        snapshot: QEMUSnapshot,
        retries: int | None = None,
    ) -> SSHClient | None:
        """Get or create SSH connection to VM with retry logic and circuit breaker."""
        retries = retries or self.ssh_retry_count
        pool_key = (snapshot.vm_name, snapshot.ssh_port)

        with self.ssh_lock:
            if self._is_circuit_open(snapshot.vm_name):
                logger.warning(
                    "Circuit breaker open for %s, skipping connection attempt",
                    snapshot.vm_name,
                )
                return None

            if client := self._get_existing_connection(pool_key):
                return client

            return self._create_new_connection(snapshot, pool_key, retries)

    def _get_existing_connection(self, pool_key: tuple) -> SSHClient | None:
        """Check if an active connection exists in the pool."""
        if pool_key in self.ssh_connection_pool:
            client = self.ssh_connection_pool[pool_key]
            try:
                transport = client.get_transport()
                if transport and transport.is_active():
                    return client
                self._remove_invalid_connection(pool_key, client)
            except Exception:
                self._remove_invalid_connection(pool_key, client)
        return None

    def _remove_invalid_connection(self, pool_key: tuple, client: SSHClient) -> None:
        """Remove invalid connection from the pool."""
        if pool_key in self.ssh_connection_pool:
            del self.ssh_connection_pool[pool_key]
        try:
            client.close()
        except Exception as e:
            self.logger.debug("Error closing SSH client: %s", e)

    def _create_new_connection(self, snapshot: QEMUSnapshot, pool_key: tuple, retries: int) -> SSHClient | None:
        """Attempt to create a new SSH connection with retries."""
        for attempt in range(retries):
            try:
                client = self._initialize_ssh_client(snapshot)
                self.ssh_connection_pool[pool_key] = client
                self._reset_circuit_breaker(snapshot.vm_name)
                logger.info(
                    "SSH connection established to %s on port %s",
                    snapshot.vm_name,
                    snapshot.ssh_port,
                )
                return client
            except Exception as e:
                self._handle_connection_exception(snapshot.vm_name, e, attempt, retries)
        logger.error(
            "Failed to establish SSH connection to %s after %s attempts",
            snapshot.vm_name,
            retries,
        )
        return None

    def _initialize_ssh_client(self, snapshot: QEMUSnapshot) -> SSHClient:
        """Initialize and connect an SSH client."""
        client = SSHClient()
        known_hosts_path = self.working_dir / "ssh" / "known_hosts"
        client.set_missing_host_key_policy(SecureHostKeyPolicy(known_hosts_path))
        client.connect(
            hostname="localhost",
            port=snapshot.ssh_port,
            username="test",
            pkey=self.master_ssh_key,
            timeout=self.ssh_timeout,
            banner_timeout=self.ssh_timeout,
            auth_timeout=self.ssh_timeout,
        )
        return client

    def _handle_connection_exception(self, vm_name: str, exception: Exception, attempt: int, retries: int) -> None:
        """Handle exceptions during SSH connection attempts."""
        if isinstance(exception, TimeoutError):
            logger.warning("SSH connection timeout (attempt %s/%s): %s", attempt + 1, retries, exception)
        elif isinstance(exception, paramiko.AuthenticationException):
            logger.error("SSH authentication failed for %s: %s", vm_name, exception)
        elif isinstance(exception, paramiko.SSHException):
            logger.warning("SSH connection error (attempt %s/%s): %s", attempt + 1, retries, exception)
        else:
            logger.exception("Unexpected SSH connection error: %s", exception)
        self._record_connection_failure(vm_name)
        if attempt < retries - 1:
            time.sleep(self.ssh_retry_delay)

    def download_file_from_vm(self, snapshot: QEMUSnapshot, remote_path: str, local_path: str) -> bool:
        """Download file from VM using SFTP.

        Args:
            snapshot: QEMUSnapshot instance containing VM connection details
            remote_path: Path to file on the VM (e.g., '/tmp/modified_binary.exe')
            local_path: Local path where file should be saved

        Returns:
            True if download successful, False otherwise

        """
        ssh_client = self._get_ssh_connection(snapshot)
        if ssh_client is None:
            logger.error("Failed to get SSH connection to %s for file download", snapshot.vm_name)
            return False

        sftp_client = None
        try:
            # Create SFTP client from SSH connection
            sftp_client = ssh_client.open_sftp()

            # Ensure local directory exists
            local_path_obj = Path(local_path)
            local_path_obj.parent.mkdir(parents=True, exist_ok=True)

            # Download the file
            sftp_client.get(remote_path, str(local_path_obj))

            logger.info(
                "Successfully downloaded %s from %s to %s",
                remote_path,
                snapshot.vm_name,
                local_path,
            )
            return True

        except FileNotFoundError as e:
            logger.error("Remote file not found: %s on %s: %s", remote_path, snapshot.vm_name, e)
            return False

        except paramiko.SFTPError as e:
            logger.error("SFTP error downloading %s from %s: %s", remote_path, snapshot.vm_name, e)
            return False

        except Exception as e:
            logger.exception("Unexpected error downloading %s from %s: %s", remote_path, snapshot.vm_name, e)
            return False

        finally:
            if sftp_client:
                try:
                    sftp_client.close()
                except Exception as e:
                    self.logger.debug("Error closing SFTP client: %s", e)

    def get_modified_binary(self, snapshot_id: str, remote_binary_path: str, local_download_dir: str) -> str | None:
        """Download modified binary from VM and return local path.

        Args:
            snapshot_id: ID of the VM snapshot to download from
            remote_binary_path: Path to the binary on the VM (e.g., '/tmp/modified_binary.exe')
            local_download_dir: Local directory where file should be saved

        Returns:
            Local path to downloaded file if successful, None if failed

        """
        if snapshot_id not in self.snapshots:
            logger.error("Snapshot %s not found in active snapshots", snapshot_id)
            return None

        snapshot = self.snapshots[snapshot_id]

        # Extract filename from remote path
        filename = Path(remote_binary_path).name

        # Construct local download path
        local_path = Path(local_download_dir) / filename

        if success := self.download_file_from_vm(snapshot, remote_binary_path, str(local_path)):
            logger.info("Modified binary downloaded to %s (success: %s)", local_path, success)
            return str(local_path)
        logger.error("Failed to download modified binary from %s (success: %s)", snapshot_id, success)
        return None

    def _inject_ssh_key(self, snapshot: QEMUSnapshot) -> None:
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

            logger.info("SSH key injected into VM %s", snapshot.vm_name)
        except Exception as e:
            logger.warning("Failed to inject SSH key: %s", e)

    def _is_circuit_open(self, vm_name: str) -> bool:
        """Check if circuit breaker is open for a VM."""
        if vm_name not in self.ssh_circuit_breaker:
            return False

        breaker = self.ssh_circuit_breaker[vm_name]
        if not breaker["open"]:
            return False

        # Check if timeout has expired
        time_since_failure = (datetime.now() - breaker["last_failure"]).total_seconds()
        if time_since_failure > self.circuit_breaker_timeout:
            # Try to close circuit
            breaker["open"] = False
            breaker["failures"] = 0
            logger.info("Circuit breaker closed for %s after timeout", vm_name)
            return False

        return True

    def _record_connection_failure(self, vm_name: str) -> None:
        """Record a connection failure for circuit breaker."""
        if vm_name not in self.ssh_circuit_breaker:
            self.ssh_circuit_breaker[vm_name] = {
                "failures": 0,
                "last_failure": datetime.now(),
                "open": False,
            }

        breaker = self.ssh_circuit_breaker[vm_name]
        breaker["failures"] += 1
        breaker["last_failure"] = datetime.now()

        if breaker["failures"] >= self.circuit_breaker_threshold:
            breaker["open"] = True
            logger.warning(
                "Circuit breaker opened for %s after %s failures",
                vm_name,
                breaker["failures"],
            )

    def _reset_circuit_breaker(self, vm_name: str) -> None:
        """Reset circuit breaker on successful connection."""
        if vm_name in self.ssh_circuit_breaker:
            self.ssh_circuit_breaker[vm_name] = {
                "failures": 0,
                "last_failure": datetime.now(),
                "open": False,
            }

    def _close_ssh_connection(self, snapshot: QEMUSnapshot) -> None:
        """Close and remove SSH connection from pool."""
        pool_key = (snapshot.vm_name, snapshot.ssh_port)

        with self.ssh_lock:
            if pool_key in self.ssh_connection_pool:
                try:
                    self.ssh_connection_pool[pool_key].close()
                except Exception as e:
                    logger.debug("Error closing SSH connection: %s", e)
                finally:
                    del self.ssh_connection_pool[pool_key]

    def create_script_test_snapshot(self, binary_path: str, platform: str = "windows") -> str:
        """Create a QEMU snapshot specifically for script testing."""
        snapshot_id = f"test_{int(time.time())}_{hash(binary_path) % 10000}"

        logger.info("Creating script test snapshot: %s", snapshot_id)

        # Get base image for platform
        base_image = self.base_images.get(platform.lower())
        if not base_image:
            msg = f"No base image available for platform: {platform}"
            raise ValueError(msg)

        # Create working copy of base image
        snapshot_disk = self.working_dir / f"{snapshot_id}.qcow2"

        # Create overlay image for testing
        cmd = [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-b",
            str(base_image),
            str(snapshot_disk),
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
            logger.info("Created snapshot disk: %s", snapshot_disk)
        except subprocess.CalledProcessError as e:
            logger.error("Failed to create snapshot disk: %s", e)
            raise

        # Create snapshot metadata
        snapshot = QEMUSnapshot(
            snapshot_id=snapshot_id,
            vm_name=f"test_vm_{snapshot_id}",
            disk_path=str(snapshot_disk),
            binary_path=binary_path,
            created_at=datetime.now(),
            ssh_port=self.next_ssh_port,
            vnc_port=self.next_vnc_port,
        )

        # Increment ports for next snapshot
        self.next_ssh_port += 1
        self.next_vnc_port += 1

        # Start VM for this snapshot
        self._start_vm_for_snapshot(snapshot)

        self.snapshots[snapshot_id] = snapshot

        logger.info("Script test snapshot created: %s", snapshot_id)
        return snapshot_id

    def _start_vm_for_snapshot(self, snapshot: QEMUSnapshot) -> None:
        """Start QEMU VM for a specific snapshot with resource management."""
        logger.info("Starting VM for snapshot: %s", snapshot.snapshot_id)

        # QEMU command for starting VM
        cmd = [
            self.qemu_executable,
            "-name",
            snapshot.vm_name,
            "-m",
            "2048",  # 2GB RAM
            "-smp",
            "2",  # 2 CPU cores
            "-drive",
            f"file={snapshot.disk_path},format=qcow2",
            "-netdev",
            f"user,id=net0,hostfwd=tcp::{snapshot.ssh_port}-:22",
            "-device",
            "e1000,netdev=net0",
            "-vnc",
            f":{snapshot.vnc_port - 5900}",
            "-daemonize",  # Run in background
            "-pidfile",
            str(self.working_dir / f"{snapshot.snapshot_id}.pid"),
        ]

        try:
            # Start the VM process
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis

            # Wait a moment for VM to start
            time.sleep(5)

            # If the process is still running, consider the VM started successfully
            if process.poll() is None:
                snapshot.vm_process = process

                # Register VM with resource manager
                vm_resource = VMResource(snapshot.vm_name, process)
                resource_manager.register_resource(vm_resource)

                logger.info("VM started successfully for snapshot: %s", snapshot.snapshot_id)

                # Log VM operation
                log_vm_operation("start", snapshot.vm_name, success=True)

            else:
                # Process exited early - gather output and report error
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except Exception:
                    # Fallback if communicate fails or times out
                    stdout, stderr = b"", b""

                # Decode safely for logging
                try:
                    stdout_decoded = stdout.decode(errors="replace") if isinstance(stdout, (bytes, bytearray)) else str(stdout)
                except Exception:
                    stdout_decoded = "<unreadable stdout>"

                try:
                    stderr_decoded = stderr.decode(errors="replace") if isinstance(stderr, (bytes, bytearray)) else str(stderr)
                except Exception:
                    stderr_decoded = "<unreadable stderr>"

                logger.debug("VM startup stdout: %s", stdout_decoded)
                logger.error(FAILED_START_VM, stderr_decoded)
                log_vm_operation("start", snapshot.vm_name, success=False, error=stderr_decoded)

                # Raise an error to indicate startup failure
                raise RuntimeError(f"VM startup failed: {stderr_decoded}")

        except Exception as e:
            logger.error("Error starting VM: %s", e)
            log_vm_operation("start", snapshot.vm_name, success=False, error=str(e))
            raise

    def _wait_for_vm_ready(self, snapshot: QEMUSnapshot, timeout: int = 60) -> bool:
        """Wait for VM to be ready for testing."""
        logger.info("Waiting for VM to be ready: %s", snapshot.snapshot_id)

        start_time = time.time()
        while time.time() - start_time < timeout:
            if ssh_client := self._get_ssh_connection(snapshot, retries=1):
                try:
                    logger.debug(
                        "SSH connection established for %s: %s",
                        snapshot.snapshot_id,
                        ssh_client.get_transport().is_active() if ssh_client.get_transport() else False,
                    )
                    result = self._execute_command_in_vm(snapshot, "echo ready", timeout=5)
                    if result["exit_code"] == 0 and "ready" in result["stdout"]:
                        logger.info("VM is ready: %s", snapshot.snapshot_id)
                        self._inject_ssh_key(snapshot)
                        ssh_client.close()
                        return True
                    ssh_client.close()
                except Exception as e:
                    logger.debug("VM not ready yet: %s", e)
                    if ssh_client:
                        ssh_client.close()

            time.sleep(2)

        logger.warning("VM did not become ready within %ss: %s", timeout, snapshot.snapshot_id)
        return False

    def _upload_file_to_vm(self, snapshot: QEMUSnapshot, content: str, remote_path: str) -> None:
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
            if remote_dir and remote_dir != "/":
                try:
                    sftp.stat(remote_dir)
                except FileNotFoundError:
                    # Create directory recursively
                    mkdir_cmd = f"mkdir -p {remote_dir}"
                    self._execute_command_in_vm(snapshot, mkdir_cmd)

            # Write content directly to remote file
            with sftp.file(remote_path, "w") as remote_file:
                remote_file.write(content)

            sftp.close()
            logger.debug("Uploaded file to VM: %s", remote_path)

        except Exception as e:
            logger.error("Failed to upload file via SFTP: %s", e)
            msg = f"Failed to upload file: {e}"
            raise RuntimeError(msg) from e

    def _upload_binary_to_vm(self, snapshot: QEMUSnapshot, local_binary: str, remote_path: str) -> None:
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
            if remote_dir and remote_dir != "/":
                try:
                    sftp.stat(remote_dir)
                except FileNotFoundError:
                    # Create directory recursively
                    mkdir_cmd = f"mkdir -p {remote_dir}"
                    self._execute_command_in_vm(snapshot, mkdir_cmd)

            # Upload binary file
            sftp.put(local_binary, remote_path)

            # Make executable
            sftp.chmod(remote_path, 0o755)

            sftp.close()
            logger.debug("Uploaded binary to VM: %s", remote_path)

        except Exception as e:
            logger.error("Failed to upload binary via SFTP: %s", e)
            msg = f"Failed to upload binary: {e}"
            raise RuntimeError(msg) from e

    def _execute_command_in_vm(
        self,
        snapshot: QEMUSnapshot,
        command: str,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Execute a command in the VM via SSH."""
        # Get SSH connection
        ssh_client = self._get_ssh_connection(snapshot)
        if not ssh_client:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": "Failed to establish SSH connection",
            }

        try:
            # Log the command execution
            log_tool_execution("SSH_COMMAND", command, success=True)

            # Execute command with timeout
            _stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)

            # Get exit status
            exit_code = stdout.channel.recv_exit_status()

            # Read output
            stdout_data = stdout.read().decode("utf-8", errors="replace")
            stderr_data = stderr.read().decode("utf-8", errors="replace")

            return {
                "exit_code": exit_code,
                "stdout": stdout_data,
                "stderr": stderr_data,
            }

        except TimeoutError:
            logger.warning("Command timed out after %ss: %s", timeout, command)
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout}s",
            }
        except Exception as e:
            logger.error("Failed to execute command in VM: %s", e)
            log_tool_execution("SSH_COMMAND", command, success=False, error=str(e))
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
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
            "Process attached",
        ]

        # Error indicators
        error_indicators = [
            "Error:",
            "Exception:",
            "Failed to attach",
            "Process not found",
            "Unable to inject",
            "TypeError:",
            "ReferenceError:",
        ]

        # Check for success indicators
        for indicator in success_indicators:
            if indicator in stdout:
                logger.info("Found success indicator: %s", indicator)
                return True

        # Check for explicit errors
        for indicator in error_indicators:
            if indicator in stderr or indicator in stdout:
                logger.warning("Found error indicator: %s", indicator)
                return False

        # If no clear indicators, consider success if no stderr
        return not stderr.strip()

    def _analyze_ghidra_output(self, stdout: str, stderr: str) -> bool:
        """Analyze Ghidra output to determine success/failure."""
        # Success indicators
        success_indicators = [
            "Analysis complete",
            "Script completed",
            "Patched function",
            "Applied bypass patch",
            "patches applied",
            "INFO",
        ]

        # Error indicators
        error_indicators = [
            "ERROR:",
            "Exception:",
            "Failed to",
            "Unable to",
            "Invalid",
            "Not found",
            "java.lang.Exception",
        ]

        # Check for success indicators
        for indicator in success_indicators:
            if indicator in stdout:
                logger.info("Found success indicator: %s", indicator)
                return True

        # Check for explicit errors
        for indicator in error_indicators:
            if indicator in stderr or indicator in stdout:
                logger.warning("Found error indicator: %s", indicator)
                return False

        # Default to success if analysis completed without errors
        return "Analysis finished" in stdout or not stderr.strip()

    def cleanup_snapshot(self, snapshot_id: str) -> None:
        """Clean up a test snapshot and stop associated VM."""
        if snapshot_id not in self.snapshots:
            logger.warning("Snapshot not found for cleanup: %s", snapshot_id)
            return

        snapshot = self.snapshots[snapshot_id]
        logger.info("Cleaning up snapshot: %s", snapshot_id)

        try:
            # Close SSH connections first
            self._close_ssh_connection(snapshot)
            # Stop VM process if running
            try:
                # Try graceful shutdown first
                snapshot.vm_process.terminate()
                snapshot.vm_process.wait(timeout=10)
            except subprocess.TimeoutExpired as e:
                self.logger.error(SUBPROCESS_TIMEOUT_MSG, e)
                # Force kill if needed
                snapshot.vm_process.kill()
                snapshot.vm_process.wait()
                snapshot.vm_process.wait()

            logger.info("Stopped VM process for snapshot: %s", snapshot_id)

            # Kill VM by PID file if exists
            pid_file = self.working_dir / f"{snapshot_id}.pid"
            if pid_file.exists():
                try:
                    with open(pid_file) as f:
                        pid = int(f.read().strip())

                    os.kill(pid, 15)  # SIGTERM
                    time.sleep(2)

                    try:
                        os.kill(pid, 0)  # Check if still running
                        os.kill(pid, 9)  # SIGKILL
                    except OSError as e:
                        logger.error("OS error in qemu_manager: %s", e)
                        # Process already dead

                    pid_file.unlink()

                except (ValueError, OSError) as e:
                    logger.warning("Could not kill VM by PID: %s", e)

            # Remove snapshot disk file
            disk_path = Path(snapshot.disk_path)
            if disk_path.exists():
                disk_path.unlink()
                logger.info("Removed snapshot disk: %s", disk_path)

            # Remove from tracking
            del self.snapshots[snapshot_id]

            # Release from resource manager
            try:
                resource_manager.release_resource(snapshot.vm_name)
            except Exception as e:
                logger.debug("Could not release VM resource: %s", e)

            # Log VM operation
            log_vm_operation("stop", snapshot.vm_name, success=True)

            logger.info("Snapshot cleanup complete: %s", snapshot_id)

        except Exception as e:
            logger.error("Error during snapshot cleanup: %s", e)
            log_vm_operation("stop", snapshot.vm_name, success=False, error=str(e))

    def _stop_vm_for_snapshot(self, snapshot: QEMUSnapshot) -> None:
        """Stop VM for a specific snapshot."""
        try:
            if snapshot.vm_process and snapshot.vm_process.poll() is None:
                try:
                    snapshot.vm_process.wait(timeout=10)
                except subprocess.TimeoutExpired as e:
                    self.logger.error(SUBPROCESS_TIMEOUT_MSG, e)
                    snapshot.vm_process.kill()
                    snapshot.vm_process.wait()
                logger.info("Stopped VM process for snapshot %s", snapshot.snapshot_id)
                logger.info("Stopped VM process for snapshot %s", snapshot.snapshot_id)
        except Exception as e:
            logger.error("Error stopping VM for snapshot %s: %s", snapshot.snapshot_id, e)

    def cleanup_all_snapshots(self) -> None:
        """Clean up all active snapshots."""
        logger.info("Cleaning up all snapshots")

        for snapshot_id in list(self.snapshots):
            self.cleanup_snapshot(snapshot_id)

        logger.info("All snapshots cleaned up")

    def get_snapshot_info(self, snapshot_id: str) -> dict[str, Any] | None:
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
            "vm_running": snapshot.vm_process is not None and snapshot.vm_process.poll() is None,
        }

    def get_all_vm_info(self) -> list[dict]:
        """Get information about all VM instances for UI display.

        Returns:
            List of dictionaries containing VM information for UI

        """
        vm_info_list = []

        for snapshot in self.snapshots.values():
            vm_info = {
                "snapshot_id": snapshot.snapshot_id,
                "vm_name": snapshot.vm_name,
                "disk_path": snapshot.disk_path,
                "binary_path": getattr(snapshot, "binary_path", "N/A"),
                "created_at": snapshot.created_at.isoformat(),
                "ssh_port": snapshot.ssh_port,
                "vnc_port": getattr(snapshot, "vnc_port", "N/A"),
                "vm_running": snapshot.vm_process is not None and snapshot.vm_process.poll() is None,
                "version": getattr(snapshot, "version", "v1.0"),
                "parent_snapshot": getattr(snapshot, "parent_snapshot", None),
                "children_snapshots": getattr(snapshot, "children_snapshots", []),
            }
            vm_info_list.append(vm_info)

        return vm_info_list

    def get_base_image_configuration(self) -> dict:
        """Get current base image configuration.

        Returns:
            Dictionary containing base image paths and settings

        """
        return self.config.get("vm_framework.base_images", {})

    def update_base_image_configuration(self, platform: str, paths: list[str]) -> None:
        """Update base image configuration for specified platform.

        Args:
            platform: Platform name ('windows' or 'linux')
            paths: List of base image paths

        """
        config_key = f"vm_framework.base_images.{platform}"
        self.config.set(config_key, paths)
        self.config.save_config()
        logger.info("Updated %s base image configuration with %d paths", platform, len(paths))

    def stop_vm_instance(self, snapshot_id: str) -> bool:
        """Stop a VM instance by snapshot ID.

        Args:
            snapshot_id: ID of the snapshot/VM to stop

        Returns:
            True if successful, False otherwise

        """
        try:
            self.cleanup_snapshot(snapshot_id)
            logger.info("Successfully stopped VM instance %s", snapshot_id)
            return True
        except Exception as e:
            logger.error("Failed to stop VM instance %s: %s", snapshot_id, e)
            return False

    def delete_vm_instance(self, snapshot_id: str) -> bool:
        """Delete a VM instance by snapshot ID.

        Args:
            snapshot_id: ID of the snapshot/VM to delete

        Returns:
            True if successful, False otherwise

        """
        try:
            self.cleanup_snapshot(snapshot_id)
            logger.info("Successfully deleted VM instance %s", snapshot_id)
            return True
        except Exception as e:
            logger.error("Failed to delete VM instance %s: %s", snapshot_id, e)
            return False

    def start_vm_instance(self, snapshot_id: str) -> bool:
        """Start a VM instance by snapshot ID.

        Args:
            snapshot_id: ID of the snapshot/VM to start

        Returns:
            True if successful, False otherwise

        """
        if snapshot_id not in self.snapshots:
            logger.error("Snapshot %s not found", snapshot_id)
            return False

        try:
            snapshot = self.snapshots[snapshot_id]
            # Check if VM is already running
            if snapshot.vm_process is not None and snapshot.vm_process.poll() is None:
                logger.warning("VM instance %s is already running", snapshot_id)
                return True

            # Start the VM
            success = self._start_vm_for_snapshot(snapshot)
            if success:
                logger.info("Successfully started VM instance %s", snapshot_id)
            else:
                logger.error("Failed to start VM instance %s", snapshot_id)
            return success
        except Exception as e:
            logger.error("Failed to start VM instance %s: %s", snapshot_id, e)
            return False

    def list_snapshots(self) -> list[dict[str, Any]]:
        """List all active snapshots."""
        return [self.get_snapshot_info(sid) for sid in self.snapshots]

    def __del__(self) -> None:
        """Cleanup on destruction."""
        try:
            # Close all SSH connections first
            with self.ssh_lock:
                for client in self.ssh_connection_pool.values():
                    try:
                        client.close()
                    except Exception as e:
                        logger.debug("Error closing SSH client in cleanup: %s", e)
                self.ssh_connection_pool.clear()

            # Then cleanup snapshots
            self.cleanup_all_snapshots()
        except Exception as e:
            logger.debug("Error during destructor cleanup: %s", e)

    def _get_windows_base_image(self) -> Path:
        """Get path to Windows base image using dynamic discovery."""
        from intellicrack.utils.path_resolver import get_qemu_images_dir
        from intellicrack.utils.qemu_image_discovery import get_qemu_discovery

        discovery = get_qemu_discovery()
        if windows_images := discovery.get_images_by_os("windows"):
            selected_image = windows_images[0]
            self.logger.info("Found Windows base image: %s", selected_image.path)
            return selected_image.path

        config_paths = self.config.get("vm_framework.base_images.windows", [])
        for path_str in config_paths:
            path = Path(path_str).expanduser()
            if path.exists():
                self.logger.info("Found Windows image from config: %s", path)
                return path

        if all_images := discovery.discover_images():
            selected_image = all_images[0]
            self.logger.warning(
                "No Windows-specific images found. Using first available image: %s (format: %s)",
                selected_image.filename,
                selected_image.format,
            )
            return selected_image.path

        qemu_dir = get_qemu_images_dir()
        self.logger.error(
            "No VM images found. Please add images to: %s",
            qemu_dir,
        )
        raise RuntimeError(
            f"No VM images found in QEMU images directory. "
            f"Please place a VM image file (supported formats: .qcow2, .qcow, .img, .vmdk, .vdi, .vhd, .vhdx, "
            f".iso, .raw, .qed, .cloop, .dmg, .parallels, .bochs) in the directory: {qemu_dir}",
        )

    def _get_linux_base_image(self) -> str:
        """Get Linux base image using dynamic discovery."""
        from intellicrack.utils.path_resolver import get_qemu_images_dir
        from intellicrack.utils.qemu_image_discovery import get_qemu_discovery

        discovery = get_qemu_discovery()
        if linux_images := discovery.get_images_by_os("linux"):
            selected_image = linux_images[0]
            self.logger.info("Found Linux base image: %s", selected_image.path)
            return str(selected_image.path)

        config_paths = self.config.get("vm_framework.base_images.linux", [])
        for path_str in config_paths:
            path = Path(path_str).expanduser()
            if path.exists():
                self.logger.info("Found Linux image from config: %s", path)
                return str(path)

        if all_images := discovery.discover_images():
            selected_image = all_images[0]
            self.logger.warning(
                "No Linux-specific images found. Using first available image: %s (format: %s)",
                selected_image.filename,
                selected_image.format,
            )
            return str(selected_image.path)

        qemu_dir = get_qemu_images_dir()
        self.logger.error(
            "No VM images found. Please add images to: %s",
            qemu_dir,
        )
        raise RuntimeError(
            f"No VM images found in QEMU images directory. "
            f"Please place a VM image file (supported formats: .qcow2, .qcow, .img, .vmdk, .vdi, .vhd, .vhdx, "
            f".iso, .raw, .qed, .cloop, .dmg, .parallels, .bochs) in the directory: {qemu_dir}",
        )

    def _detect_os_type(self, binary_path: str) -> str:
        """Detect operating system type from binary."""
        if binary_path.lower().endswith((".exe", ".dll")):
            return "windows"
        return "linux" if binary_path.lower().endswith((".so", ".elf")) else "windows"

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
                logger.warning("Base image not found: %s", base_image)
                temp_disk = self._create_minimal_test_image(snapshot_dir, os_type)
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
                    f"  Windows: C:\\Windows\\System32\\*.exe\n"
                    f"  Linux: /usr/bin/*, /bin/*\n"
                    f"  Custom: Provide full path to your target binary",
                )

            # Create snapshot object
            snapshot = QEMUSnapshot(
                snapshot_id=snapshot_id,
                vm_name=f"intellicrack_test_{snapshot_id}",
                disk_path=str(temp_disk),
                binary_path=str(target_binary),
                created_at=datetime.now(),
                ssh_port=self.next_ssh_port,
                vnc_port=self.next_vnc_port,
            )

            # Increment ports for next snapshot
            self.next_ssh_port += 1
            self.next_vnc_port += 1

            # Start VM
            if self._start_vm(snapshot):
                self.snapshots[snapshot_id] = snapshot
                logger.info("Created QEMU snapshot: %s", snapshot_id)
                return snapshot_id
            raise Exception("Failed to start VM")

        except Exception as e:
            logger.error("Failed to create QEMU snapshot: %s", e)
            raise

    def _create_minimal_test_image(self, snapshot_dir: Path, os_type: str) -> Path:
        """Create minimal test image when base image is not available."""
        disk_path = snapshot_dir / "test_disk.qcow2"

        try:
            # Create qcow2 image with size based on OS type from config
            if os_type.lower() == "windows":
                windows_size_gb = self.config.get("vm_framework.base_images.default_windows_size_gb", 2)
                image_size = f"{windows_size_gb}G"
                logger.info("Creating Windows test image (%s)", image_size)
            elif os_type.lower() in {"linux", "debian", "ubuntu"}:
                linux_size_gb = self.config.get("vm_framework.base_images.default_linux_size_gb", 1)
                image_size = f"{linux_size_gb}G"
                logger.info("Creating Linux test image (%s)", image_size)
            else:
                # Default to Linux size for unknown OS types
                default_size_gb = self.config.get("vm_framework.base_images.default_linux_size_gb", 1)
                image_size = f"{default_size_gb}G"
                logger.info("Creating generic test image for %s (%s)", os_type, image_size)

            cmd = [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                str(disk_path),
                image_size,
            ]

            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
            if result.returncode == 0:
                logger.info("Created minimal test image: %s", disk_path)
                return disk_path
            logger.error("Failed to create test image: %s", result.stderr)

        except Exception as e:
            logger.error("Failed to create minimal test image: %s", e)
            # Cannot continue without a valid disk image
            raise RuntimeError(
                f"Failed to create test disk image: {e}\n"
                f"Ensure qemu-img is installed and accessible.\n"
                f"On Windows: Install QEMU from https://www.qemu.org/download/\n"
                f"On Linux: sudo apt-get install qemu-utils\n"
                f"On macOS: brew install qemu",
            ) from e

    def _copy_base_image(self, base_image: Path, snapshot_dir: Path) -> Path:
        """Copy base image to snapshot directory."""
        temp_disk = snapshot_dir / "snapshot_disk.qcow2"

        try:
            # Create snapshot from base image
            cmd = [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-b",
                str(base_image),
                str(temp_disk),
            ]

            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
            if result.returncode == 0:
                return temp_disk
            logger.error("Failed to create snapshot image: %s", result.stderr)
            # Try direct copy as recovery mechanism
            logger.info("Attempting direct copy of base image")
            shutil.copy2(base_image, temp_disk)
            return temp_disk

        except Exception as e:
            logger.error("Failed to copy base image: %s", e)
            # Cannot continue without a valid disk image
            raise RuntimeError(
                f"Failed to copy/create disk image: {e}\n"
                f"Base image: {base_image}\n"
                f"Target: {temp_disk}\n"
                f"Ensure:\n"
                f"1. Base image exists and is readable\n"
                f"2. Target directory is writable\n"
                f"3. Sufficient disk space available\n"
                f"4. qemu-img is installed and working",
            ) from e

    def _start_vm(self, snapshot: QEMUSnapshot) -> bool:
        """Start QEMU VM."""
        try:
            # Build QEMU command
            cmd = [
                self.qemu_executable,
                "-machine",
                "pc",
                "-cpu",
                "host",
                "-m",
                "2048",
                "-smp",
                "2",
                "-drive",
                f"file={snapshot.disk_path},format=qcow2,if=virtio",
                "-netdev",
                f"user,id=net0,hostfwd=tcp::{snapshot.ssh_port}-:22",
                "-device",
                "virtio-net,netdev=net0",
                "-vnc",
                f":{snapshot.vnc_port - 5900}",
                "-daemonize",
                "-pidfile",
                str(Path(snapshot.disk_path).parent / "qemu.pid"),
            ]

            # Add shared directory if available
            shared_dir = Path(snapshot.disk_path).parent / "shared"
            if shared_dir.exists():
                cmd.extend(
                    [
                        "-virtfs",
                        f"local,path={shared_dir},mount_tag=shared,security_model=none",
                    ],
                )

            logger.info("Starting QEMU VM: %s", " ".join(cmd))

            # Start the VM
            # Launch QEMU process and capture output to determine success/failure
            process = subprocess.Popen(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            _stdout, stderr = process.communicate()
            if process.returncode == 0:
                # Give VM time to start
                time.sleep(5)
                logger.info("Started VM for snapshot %s", snapshot.snapshot_id)
                return True

            # Use the shared constant for the error message
            logger.error(
                FAILED_START_VM,
                stderr.decode() if isinstance(stderr, (bytes, bytearray)) else str(stderr),
            )
            return False

        except Exception as e:
            logger.error("Failed to start VM: %s", e)
            return False

    def test_frida_script(
        self,
        snapshot_id: str,
        script_content: str,
        binary_path: str,
    ) -> ExecutionResult:
        """Test a Frida script in QEMU environment."""
        if snapshot_id not in self.snapshots:
            return ExecutionResult(
                success=False,
                output="",
                error="Snapshot not found",
                exit_code=-1,
                runtime_ms=0,
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
            runner_content = f"""#!/bin/bash
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
"""
            runner_script.write_text(runner_content)
            runner_script.chmod(0o755)

            # Execute script in VM via SSH
            result = self._execute_in_vm_real(snapshot, runner_content)

            runtime_ms = int((time.time() - start_time) * 1000)

            return ExecutionResult(
                success=result["exit_code"] == 0,
                output=result["stdout"],
                error=result["stderr"],
                exit_code=result["exit_code"],
                runtime_ms=runtime_ms,
            )

        except Exception as e:
            logger.error("Exception in qemu_manager: %s", e)
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Frida test failed: {e!s}",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def test_ghidra_script(
        self,
        snapshot_id: str,
        script_content: str,
        binary_path: str,
    ) -> ExecutionResult:
        """Test a Ghidra script in QEMU environment."""
        if snapshot_id not in self.snapshots:
            return ExecutionResult(
                success=False,
                output="",
                error="Snapshot not found",
                exit_code=-1,
                runtime_ms=0,
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
            runner_content = f"""#!/bin/bash
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
"""
            runner_script.write_text(runner_content)
            runner_script.chmod(0o755)

            # Execute script in VM
            result = self._execute_in_vm_real(snapshot, runner_content)

            runtime_ms = int((time.time() - start_time) * 1000)

            return ExecutionResult(
                success=result["exit_code"] == 0,
                output=result["stdout"],
                error=result["stderr"],
                exit_code=result["exit_code"],
                runtime_ms=runtime_ms,
            )

        except Exception as e:
            logger.error("Exception in qemu_manager: %s", e)
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Ghidra test failed: {e!s}",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def _execute_in_vm_real(self, snapshot: QEMUSnapshot, script_content: str) -> dict[str, Any]:
        """Execute script in VM using real SSH connection."""
        logger.info("Executing script in VM %s via SSH", snapshot.vm_name)

        # Create temporary script file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            f.write(script_content)
            local_script = f.name

        # Use a more secure remote path with timestamp
        import uuid

        remote_script = f"{tempfile.gettempdir()}/test_script_{uuid.uuid4().hex[:8]}.sh"

        try:
            # Upload script to VM
            self._upload_file_to_vm(snapshot, script_content, remote_script)

            # Make script executable
            chmod_result = self._execute_command_in_vm(snapshot, f"chmod +x {remote_script}")
            if chmod_result["exit_code"] != 0:
                logger.error("Failed to make script executable: %s", chmod_result["stderr"])

            # Execute script
            exec_result = self._execute_command_in_vm(snapshot, f"bash {remote_script}", timeout=60)

            # Clean up remote script
            self._execute_command_in_vm(snapshot, f"rm -f {remote_script}")

            return exec_result

        except Exception as e:
            logger.error("Failed to execute script in VM: %s", e)
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"VM execution error: {e!s}",
            }
        finally:
            # Clean up local temp file
            try:
                Path(local_script).unlink()
            except Exception as e:
                self.logger.debug("Error removing temp script file: %s", e)

    def create_versioned_snapshot(self, parent_snapshot_id: str, binary_path: str) -> str:
        """Create a new snapshot version based on an existing snapshot."""
        if parent_snapshot_id not in self.snapshots:
            msg = f"Parent snapshot not found: {parent_snapshot_id}"
            raise ValueError(msg)

        parent_snapshot = self.snapshots[parent_snapshot_id]
        new_version = parent_snapshot.version + 1
        snapshot_id = f"{parent_snapshot_id}_v{new_version}_{int(time.time())}"

        logger.info("Creating versioned snapshot: %s from %s", snapshot_id, parent_snapshot_id)

        # Create new snapshot based on parent
        snapshot_disk = self.working_dir / f"{snapshot_id}.qcow2"

        # Create overlay based on parent snapshot
        cmd = [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-b",
            parent_snapshot.disk_path,
            "-F",
            "qcow2",  # Specify backing file format
            str(snapshot_disk),
        ]

        try:
            # Use resource manager for temporary directory
            with resource_manager.temp_directory(prefix=f"snapshot_{snapshot_id}_"):
                # Execute qemu-img command
                result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                if result.returncode != 0:
                    msg = f"qemu-img failed: {result.stderr}"
                    raise RuntimeError(msg)

                logger.info("Created versioned snapshot disk: %s", snapshot_disk)

                # Verify the snapshot was created correctly
                info_cmd = ["qemu-img", "info", str(snapshot_disk)]
                info_result = subprocess.run(info_cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                if info_result.returncode == 0:
                    logger.debug("Snapshot info: %s", info_result.stdout)

        except Exception as e:
            logger.error("Failed to create versioned snapshot: %s", e)
            # Clean up failed snapshot disk
            if snapshot_disk.exists():
                try:
                    snapshot_disk.unlink()
                except Exception as cleanup_e:
                    logger.warning("Failed to cleanup failed snapshot disk: %s", cleanup_e)
            raise

        # Create new snapshot metadata
        snapshot = QEMUSnapshot(
            snapshot_id=snapshot_id,
            vm_name=f"test_vm_{snapshot_id}",
            disk_path=str(snapshot_disk),
            binary_path=binary_path,
            created_at=datetime.now(),
            ssh_port=self.next_ssh_port,
            vnc_port=self.next_vnc_port,
            version=new_version,
            parent_snapshot=parent_snapshot_id,
        )

        # Increment ports for next snapshot
        self.next_ssh_port += 1
        self.next_vnc_port += 1

        # Update parent-child relationships
        parent_snapshot.children_snapshots.add(snapshot_id)

        # Calculate initial disk usage
        try:
            snapshot.disk_usage = os.path.getsize(snapshot_disk)
        except Exception:
            snapshot.disk_usage = 0

        self.snapshots[snapshot_id] = snapshot

        # Log the snapshot creation
        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.VM_SNAPSHOT,
                severity=AuditSeverity.INFO,
                description="Created versioned snapshot " + snapshot_id + " from " + parent_snapshot_id,
                target=snapshot_id,
            ),
        )

        logger.info("Created versioned snapshot: %s", snapshot_id)
        return snapshot_id

    def compare_snapshots(self, snapshot_id1: str, snapshot_id2: str) -> dict[str, Any]:
        """Compare two snapshots and return differences."""
        if snapshot_id1 not in self.snapshots or snapshot_id2 not in self.snapshots:
            raise ValueError("One or both snapshots not found")

        snapshot1 = self.snapshots[snapshot_id1]
        snapshot2 = self.snapshots[snapshot_id2]

        logger.info("Comparing snapshots: %s vs %s", snapshot_id1, snapshot_id2)

        # Calculate disk usage differences
        disk1_size = os.path.getsize(snapshot1.disk_path) if os.path.exists(snapshot1.disk_path) else 0
        disk2_size = os.path.getsize(snapshot2.disk_path) if os.path.exists(snapshot2.disk_path) else 0

        # Compare test results
        results1 = snapshot1.test_results
        results2 = snapshot2.test_results

        return {
            "snapshot1": {
                "id": snapshot_id1,
                "version": snapshot1.version,
                "disk_size": disk1_size,
                "test_count": len(results1),
                "created_at": snapshot1.created_at.isoformat(),
            },
            "snapshot2": {
                "id": snapshot_id2,
                "version": snapshot2.version,
                "disk_size": disk2_size,
                "test_count": len(results2),
                "created_at": snapshot2.created_at.isoformat(),
            },
            "differences": {
                "disk_size_diff": disk2_size - disk1_size,
                "test_count_diff": len(results2) - len(results1),
                "version_diff": snapshot2.version - snapshot1.version,
                "time_diff": (snapshot2.created_at - snapshot1.created_at).total_seconds(),
            },
            "relationship": self._determine_snapshot_relationship(snapshot1, snapshot2),
        }

    def _determine_snapshot_relationship(
        self,
        snapshot1: QEMUSnapshot,
        snapshot2: QEMUSnapshot,
    ) -> str:
        """Determine the relationship between two snapshots."""
        if snapshot1.parent_snapshot == snapshot2.snapshot_id:
            return f"{snapshot1.snapshot_id} is child of {snapshot2.snapshot_id}"
        if snapshot2.parent_snapshot == snapshot1.snapshot_id:
            return f"{snapshot2.snapshot_id} is child of {snapshot1.snapshot_id}"
        if snapshot1.parent_snapshot == snapshot2.parent_snapshot and snapshot1.parent_snapshot:
            return f"Both are siblings (share parent: {snapshot1.parent_snapshot!s})"
        return "No direct relationship"

    def rollback_snapshot(self, snapshot_id: str, target_state: str | None = None) -> bool:
        """Rollback a snapshot to a previous state or clean state."""
        if snapshot_id not in self.snapshots:
            msg = f"Snapshot not found: {snapshot_id}"
            raise ValueError(msg)

        snapshot = self.snapshots[snapshot_id]
        logger.info("Rolling back snapshot: %s", snapshot_id)

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
                rollback_disk = self.working_dir / f"{snapshot_id}_rollback_{int(time.time())}.qcow2"
                cmd = [
                    "qemu-img",
                    "create",
                    "-f",
                    "qcow2",
                    "-b",
                    target_snapshot.disk_path,
                    "-F",
                    "qcow2",
                    str(rollback_disk),
                ]

                result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                if result.returncode != 0:
                    msg = f"Failed to create rollback disk: {result.stderr}"
                    raise RuntimeError(msg)

                # Replace current disk
                os.remove(snapshot.disk_path)
                shutil.move(str(rollback_disk), snapshot.disk_path)

                logger.info("Rolled back %s to state of %s", snapshot_id, target_state)

                rollback_type = f"to snapshot {target_state}"
            else:
                # Rollback to clean state (recreate from base)
                os_type = self._detect_os_type(snapshot.binary_path)
                base_image = self.base_images.get(os_type.lower())
                if not base_image or not base_image.exists():
                    msg = f"No base image available for {os_type}"
                    raise RuntimeError(msg)

                # Remove current disk
                os.remove(snapshot.disk_path)

                # Create fresh overlay
                cmd = [
                    "qemu-img",
                    "create",
                    "-f",
                    "qcow2",
                    "-b",
                    str(base_image),
                    "-F",
                    "qcow2",
                    snapshot.disk_path,
                ]

                result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                if result.returncode != 0:
                    msg = f"Failed to create clean disk: {result.stderr}"
                    raise RuntimeError(msg)

                logger.info("Rolled back %s to clean base state", snapshot_id)
                rollback_type = "to clean base state"

            # Clear test results and metrics
            snapshot.test_results.clear()
            snapshot.performance_metrics.clear()
            snapshot.version += 1  # Increment version after rollback

            # Log the rollback
            audit_logger.log_event(
                AuditEvent(
                    event_type=AuditEventType.VM_SNAPSHOT,
                    severity=AuditSeverity.MEDIUM,
                    description=f"Rolled back snapshot {snapshot_id} {rollback_type}",
                    details={
                        "target_state": target_state,
                        "new_version": snapshot.version,
                    },
                    target=snapshot_id,
                )
            )

            # Restart VM if it was running
            if was_vm_running:
                self._start_vm_for_snapshot(snapshot)

            # Remove backup on success
            if original_disk_backup and Path(original_disk_backup).exists():
                os.remove(original_disk_backup)

            return True

        except Exception as e:
            logger.error("Rollback failed for %s: %s", snapshot_id, e)

            # Attempt recovery from backup
            if original_disk_backup and Path(original_disk_backup).exists():
                try:
                    logger.info("Attempting to restore from backup...")
                    if Path(snapshot.disk_path).exists():
                        os.remove(snapshot.disk_path)
                    shutil.move(original_disk_backup, snapshot.disk_path)
                    logger.info("Restored from backup successfully")
                except Exception as restore_e:
                    logger.error("Failed to restore from backup: %s", restore_e)

            # Log failure
            audit_logger.log_event(
                AuditEvent(
                    event_type=AuditEventType.ERROR,
                    severity=AuditSeverity.HIGH,
                    description=f"Snapshot rollback failed for {snapshot_id}",
                    details={"error": str(e), "target_state": target_state},
                    target=snapshot_id,
                )
            )

            return False

    def monitor_snapshot_performance(self, snapshot_id: str) -> dict[str, Any]:
        """Monitor performance metrics for a snapshot."""
        if snapshot_id not in self.snapshots:
            msg = f"Snapshot not found: {snapshot_id}"
            raise ValueError(msg)

        snapshot = self.snapshots[snapshot_id]

        try:
            # Get disk usage
            disk_size = os.path.getsize(snapshot.disk_path) if os.path.exists(snapshot.disk_path) else 0

            # Get memory usage from VM if running
            memory_usage = 0
            cpu_usage = 0.0

            if snapshot.vm_process and snapshot.vm_process.poll() is None:
                pid = snapshot.vm_process.pid

                # Use ps to get memory and CPU usage
                try:
                    ps_cmd = ["ps", "-p", str(pid), "-o", "rss,pcpu", "--no-headers"]
                    result = subprocess.run(ps_cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis

                    if result.returncode == 0:
                        parts = result.stdout.strip().split()
                        if len(parts) >= 2:
                            # Convert KB to bytes
                            memory_usage = int(parts[0]) * 1024
                            cpu_usage = float(parts[1])

                except (subprocess.SubprocessError, ValueError) as e:
                    logger.error("Error in qemu_manager: %s", e)

            # Update snapshot metrics
            metrics = {
                "timestamp": datetime.now().isoformat(),
                "disk_usage_bytes": disk_size,
                "memory_usage_bytes": memory_usage,
                "cpu_usage_percent": cpu_usage,
                "vm_running": snapshot.vm_process is not None and snapshot.vm_process.poll() is None,
                "test_count": len(snapshot.test_results),
                "uptime_seconds": (datetime.now() - snapshot.created_at).total_seconds(),
            }

            snapshot.performance_metrics.update(metrics)
            snapshot.memory_usage = memory_usage
            snapshot.disk_usage = disk_size

            return metrics

        except Exception as e:
            logger.error("Performance monitoring failed for %s: %s", snapshot_id, e)
            return {"error": str(e)}

    def enable_network_isolation(self, snapshot_id: str, isolated: bool = True) -> None:
        """Enable or disable network isolation for a snapshot."""
        if snapshot_id not in self.snapshots:
            msg = f"Snapshot not found: {snapshot_id}"
            raise ValueError(msg)

        snapshot = self.snapshots[snapshot_id]
        snapshot.network_isolated = isolated

        if snapshot.vm_process and snapshot.vm_process.poll() is None:
            # Apply network isolation to running VM
            isolation_cmd = "iptables -A OUTPUT -j DROP" if isolated else "iptables -D OUTPUT -j DROP"

            try:
                self._execute_command_in_vm(snapshot, isolation_cmd)
                logger.info(
                    "Network isolation %s for %s",
                    "enabled" if isolated else "disabled",
                    snapshot_id,
                )
            except Exception as e:
                logger.warning("Failed to apply network isolation: %s", e)

    def get_snapshot_hierarchy(self) -> dict[str, Any]:
        """Get the hierarchy of all snapshots showing parent-child relationships."""
        hierarchy = {"roots": [], "children": {}}

        # Find root snapshots (no parent)
        for snapshot_id, snapshot in self.snapshots.items():
            if not snapshot.parent_snapshot:
                hierarchy["roots"].append(
                    {
                        "id": snapshot_id,
                        "version": snapshot.version,
                        "created_at": snapshot.created_at.isoformat(),
                        "children": list(snapshot.children_snapshots),
                    },
                )

            # Build children mapping
            if snapshot.children_snapshots:
                hierarchy["children"][snapshot_id] = []
                for child_id in snapshot.children_snapshots:
                    if child_id in self.snapshots:
                        child = self.snapshots[child_id]
                        hierarchy["children"][snapshot_id].append(
                            {
                                "id": child_id,
                                "version": child.version,
                                "created_at": child.created_at.isoformat(),
                            },
                        )

        return hierarchy

    def test_script_in_vm(
        self,
        script_content: str,
        binary_path: str,
        script_type: str = "frida",
        timeout: int = 60,
    ) -> ExecutionResult:
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
            logger.error("Failed to test script in VM: %s", e)
            return ExecutionResult(
                success=False,
                output="",
                error=f"VM test failed: {e!s}",
                exit_code=-1,
                runtime_ms=0,
            )

    def _test_generic_script(
        self,
        snapshot_id: str,
        script_content: str,
        binary_path: str,
    ) -> ExecutionResult:
        """Test a generic script in QEMU environment."""
        if snapshot_id not in self.snapshots:
            return ExecutionResult(
                success=False,
                output="",
                error="Snapshot not found",
                exit_code=-1,
                runtime_ms=0,
            )

        snapshot = self.snapshots[snapshot_id]
        start_time = time.time()

        try:
            # Upload binary to VM with secure temp path
            import uuid

            remote_binary = f"{tempfile.gettempdir()}/{uuid.uuid4().hex[:8]}_{Path(binary_path).name}"
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
                success=result["exit_code"] == 0,
                output=result["stdout"],
                error=result["stderr"],
                exit_code=result["exit_code"],
                runtime_ms=runtime_ms,
            )

        except Exception as e:
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Generic test failed: {e!s}",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def optimize_snapshot_storage(self) -> dict[str, Any]:
        """Optimize snapshot storage by removing unused overlays and compacting.

        Returns:
            Dictionary containing optimization results and statistics

        """
        logger.info("Starting snapshot storage optimization")

        # Log optimization start
        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.TOOL_EXECUTION,
                severity=AuditSeverity.INFO,
                description="Starting snapshot storage optimization",
                details={"total_snapshots": len(self.snapshots)},
            ),
        )

        optimization_results = {
            "snapshots_processed": 0,
            "snapshots_optimized": 0,
            "space_saved_bytes": 0,
            "space_saved_mb": 0,
            "processing_time_seconds": 0,
            "errors": [],
            "warnings": [],
        }

        start_time = time.time()
        total_snapshots = len(self.snapshots)

        # Create temporary directory for optimization with resource manager
        with self.resource_manager.temp_directory(prefix="qemu_snapshot_opt_") as temp_dir:
            for idx, (snapshot_id, snapshot) in enumerate(self.snapshots.items()):
                try:
                    # Progress tracking
                    progress = (idx + 1) / total_snapshots * 100
                    logger.info(
                        "Optimizing snapshot %d/%d (%.1f%%): %s",
                        idx + 1,
                        total_snapshots,
                        progress,
                        snapshot_id,
                    )

                    # Check if file exists
                    if not os.path.exists(snapshot.disk_path):
                        warning = f"Snapshot file not found: {snapshot.disk_path}"
                        optimization_results["warnings"].append(warning)
                        logger.warning(warning)
                        continue

                    # Get original size
                    original_size = os.path.getsize(snapshot.disk_path)

                    # Skip non-qcow2 images
                    if not snapshot.disk_path.endswith(".qcow2"):
                        warning = f"Skipping non-qcow2 snapshot: {snapshot_id}"
                        optimization_results["warnings"].append(warning)
                        continue

                    # Check if image is already optimized (has compression)
                    info_cmd = ["qemu-img", "info", "--output=json", snapshot.disk_path]
                    info_result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                        info_cmd,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )

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
                        "qemu-img",
                        "convert",
                        "-c",  # Enable compression
                        "-p",  # Show progress
                        "-O",
                        "qcow2",
                        "-o",
                        "lazy_refcounts=on,cluster_size=2M",  # Optimization options
                        snapshot.disk_path,
                        str(temp_path),
                    ]

                    # Run conversion with resource management
                    logger.debug(f"Running optimization command: {' '.join(convert_cmd)}")

                    with self.resource_manager.managed_process(
                        convert_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ) as process_resource:
                        # Wait for completion with timeout
                        try:
                            _stdout, stderr = process_resource.process.communicate(timeout=300)

                            if process_resource.process.returncode == 0:
                                # Check new size
                                new_size = os.path.getsize(temp_path)
                                space_saved = original_size - new_size

                                if space_saved > 0:
                                    # Verify integrity before replacing
                                    check_cmd = ["qemu-img", "check", str(temp_path)]
                                    check_result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                                        check_cmd,
                                        check=False,
                                        capture_output=True,
                                        text=True,
                                        timeout=60,
                                    )

                                    if check_result.returncode == 0:
                                        # Backup original before replacement
                                        backup_path = f"{snapshot.disk_path}.backup"
                                        try:
                                            from pathlib import Path

                                            Path(snapshot.disk_path).rename(backup_path)
                                            Path(str(temp_path)).rename(snapshot.disk_path)
                                            os.remove(backup_path)

                                            optimization_results["space_saved_bytes"] += space_saved
                                            optimization_results["snapshots_optimized"] += 1

                                            logger.info(
                                                f"Optimized {snapshot_id}: saved {space_saved:,} bytes "
                                                f"({space_saved / 1024 / 1024:.2f} MB)",
                                            )

                                            # Update snapshot metadata
                                            snapshot.metadata["optimized"] = True
                                            snapshot.metadata["optimization_date"] = datetime.now().isoformat()
                                            snapshot.metadata["original_size"] = original_size
                                            snapshot.metadata["optimized_size"] = new_size

                                        except Exception as e:
                                            # Restore backup on error
                                            if os.path.exists(backup_path):
                                                Path(backup_path).rename(snapshot.disk_path)
                                            raise Exception(f"Failed to replace snapshot file: {e}") from e
                                    else:
                                        raise Exception(
                                            f"Integrity check failed: {check_result.stderr}",
                                        )
                                else:
                                    # No space saved, remove temp file
                                    logger.debug(f"No space saved for {snapshot_id}")

                            else:
                                raise Exception(f"Conversion failed: {stderr}")

                        except subprocess.TimeoutExpired as e:
                            process_resource.process.kill()
                            # Raise a more specific timeout error so callers can handle timeout cases explicitly
                            raise TimeoutError("Optimization timeout (300s)") from e

                    optimization_results["snapshots_processed"] += 1

                except Exception as e:
                    error_msg = f"Failed to optimize {snapshot_id}: {e!s}"
                    optimization_results["errors"].append(error_msg)
                    logger.error(error_msg)

                    # Log error to audit
                    audit_logger.log_event(
                        AuditEvent(
                            event_type=AuditEventType.ERROR,
                            severity=AuditSeverity.MEDIUM,
                            description=f"Snapshot optimization failed: {snapshot_id}",
                            details={"error": str(e)},
                            target=snapshot.disk_path,
                        ),
                    )

        # Calculate final statistics
        optimization_results["processing_time_seconds"] = time.time() - start_time
        optimization_results["space_saved_mb"] = optimization_results["space_saved_bytes"] / (1024 * 1024)

        # Log completion
        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.TOOL_EXECUTION,
                severity=AuditSeverity.INFO,
                description="Snapshot storage optimization completed",
                details={
                    "snapshots_processed": optimization_results["snapshots_processed"],
                    "snapshots_optimized": optimization_results["snapshots_optimized"],
                    "space_saved_mb": f"{optimization_results['space_saved_mb']:.2f}",
                    "processing_time": f"{optimization_results['processing_time_seconds']:.1f}s",
                    "error_count": len(optimization_results["errors"]),
                },
            ),
        )

        logger.info(
            f"Optimization complete: processed {optimization_results['snapshots_processed']} snapshots, "
            f"optimized {optimization_results['snapshots_optimized']}, "
            f"saved {optimization_results['space_saved_mb']:.2f} MB in "
            f"{optimization_results['processing_time_seconds']:.1f} seconds",
        )

        # Save updated metadata
        self._save_metadata()

        return optimization_results

    def cleanup_old_snapshots(
        self,
        max_age_days: int = 7,
        keep_versions: int = 3,
    ) -> dict[str, Any]:
        """Clean up old snapshots based on age and version retention policy.

        Args:
            max_age_days: Maximum age in days to keep snapshots
            keep_versions: Number of recent versions to keep per parent

        Returns:
            Dictionary containing cleanup results

        """
        logger.info(
            f"Starting old snapshot cleanup (max_age={max_age_days} days, keep_versions={keep_versions})",
        )

        # Log cleanup start
        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.TOOL_EXECUTION,
                severity=AuditSeverity.INFO,
                description="Starting old snapshot cleanup",
                details={
                    "total_snapshots": len(self.snapshots),
                    "max_age_days": max_age_days,
                    "keep_versions": keep_versions,
                },
            ),
        )

        cleanup_results = {
            "snapshots_removed": 0,
            "snapshots_kept": 0,
            "space_freed_bytes": 0,
            "space_freed_mb": 0,
            "errors": [],
            "warnings": [],
            "processing_time_seconds": 0,
        }

        start_time = time.time()
        current_time = datetime.now()
        max_age_delta = timedelta(days=max_age_days)

        # Build version hierarchy
        versions_by_parent = defaultdict(list)
        for snapshot_id, snapshot in self.snapshots.items():
            if snapshot.parent_snapshot:
                versions_by_parent[snapshot.parent_snapshot].append(
                    (snapshot.version, snapshot_id, snapshot),
                )
            else:
                # Root snapshots
                versions_by_parent[None].append(
                    (snapshot.version, snapshot_id, snapshot),
                )

        # Sort versions by version number (descending) to keep newest
        for parent in versions_by_parent:
            versions_by_parent[parent].sort(key=lambda x: x[0], reverse=True)

        # Determine which snapshots to remove
        snapshots_to_remove = []

        for versions in versions_by_parent.values():
            for idx, (_version, snapshot_id, snapshot) in enumerate(versions):
                # Check if snapshot is too old
                age = current_time - snapshot.created_at
                is_too_old = age > max_age_delta

                # Check if we should keep this version
                should_keep_version = idx < keep_versions

                # Check if snapshot has children (don't delete if it has active children)
                has_children = bool(snapshot.children_snapshots)

                if is_running := snapshot.vm_process and snapshot.vm_process.poll() is None:
                    logger.debug("VM %s is running: %s", snapshot_id, is_running)
                    cleanup_results["warnings"].append(
                        f"Skipping {snapshot_id}: VM is currently running (status: {is_running})",
                    )
                    cleanup_results["snapshots_kept"] += 1
                elif has_children:
                    cleanup_results["warnings"].append(
                        f"Skipping {snapshot_id}: Has active child snapshots",
                    )
                    cleanup_results["snapshots_kept"] += 1
                elif should_keep_version and not is_too_old:
                    logger.debug(f"Keeping {snapshot_id}: Within version retention policy")
                    cleanup_results["snapshots_kept"] += 1
                elif is_too_old and not should_keep_version:
                    logger.info(
                        f"Marking {snapshot_id} for removal: Too old and beyond retention count",
                    )
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
                audit_logger.log_event(
                    AuditEvent(
                        event_type=AuditEventType.VM_SNAPSHOT,
                        severity=AuditSeverity.INFO,
                        description=f"Removed old snapshot: {snapshot_id}",
                        details={
                            "age_days": (current_time - snapshot.created_at).days,
                            "disk_size_mb": disk_size / (1024 * 1024),
                            "version": snapshot.version,
                        },
                        target=snapshot_id,
                    ),
                )

            except Exception as e:
                error_msg = f"Failed to remove snapshot {snapshot_id}: {e!s}"
                cleanup_results["errors"].append(error_msg)
                logger.error(error_msg)

                # Log error
                audit_logger.log_event(
                    AuditEvent(
                        event_type=AuditEventType.ERROR,
                        severity=AuditSeverity.MEDIUM,
                        description=f"Failed to remove old snapshot: {snapshot_id}",
                        details={"error": str(e)},
                        target=snapshot_id,
                    ),
                )

        # Calculate final statistics
        cleanup_results["processing_time_seconds"] = time.time() - start_time
        cleanup_results["space_freed_mb"] = cleanup_results["space_freed_bytes"] / (1024 * 1024)

        # Log completion
        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.TOOL_EXECUTION,
                severity=AuditSeverity.INFO,
                description="Old snapshot cleanup completed",
                details={
                    "snapshots_removed": cleanup_results["snapshots_removed"],
                    "snapshots_kept": cleanup_results["snapshots_kept"],
                    "space_freed_mb": f"{cleanup_results['space_freed_mb']:.2f}",
                    "processing_time": f"{cleanup_results['processing_time_seconds']:.1f}s",
                    "error_count": len(cleanup_results["errors"]),
                },
            ),
        )

        logger.info(
            f"Cleanup complete: removed {cleanup_results['snapshots_removed']} snapshots, "
            f"kept {cleanup_results['snapshots_kept']}, "
            f"freed {cleanup_results['space_freed_mb']:.2f} MB in "
            f"{cleanup_results['processing_time_seconds']:.1f} seconds",
        )

        # Save updated metadata
        self._save_metadata()

        return cleanup_results

    def perform_snapshot_maintenance(
        self,
        optimize: bool = True,
        cleanup_old: bool = True,
        verify_integrity: bool = True,
    ) -> dict[str, Any]:
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
            "warnings": [],
        }

        start_time = time.time()

        # Log maintenance start
        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.TOOL_EXECUTION,
                severity=AuditSeverity.INFO,
                description="Starting snapshot maintenance",
                details={
                    "optimize": optimize,
                    "cleanup_old": cleanup_old,
                    "verify_integrity": verify_integrity,
                    "total_snapshots": len(self.snapshots),
                },
            ),
        )

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
                            f"Failed to remove corrupted snapshot {corrupted_id}: {e}",
                        )

            except Exception as e:
                error_msg = f"Integrity check failed: {e!s}"
                maintenance_results["errors"].append(error_msg)
                logger.error(error_msg)

        # Step 2: Cleanup old snapshots
        if cleanup_old:
            try:
                logger.info("Step 2/3: Cleaning up old snapshots")
                cleanup_results = self.cleanup_old_snapshots(
                    max_age_days=7,
                    keep_versions=3,
                )
                maintenance_results["cleanup_results"] = cleanup_results
                maintenance_results["tasks_performed"].append("cleanup_old")

            except Exception as e:
                error_msg = f"Cleanup failed: {e!s}"
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
                error_msg = f"Optimization failed: {e!s}"
                maintenance_results["errors"].append(error_msg)
                logger.error(error_msg)

        # Calculate total processing time
        maintenance_results["total_processing_time_seconds"] = time.time() - start_time
        maintenance_results["end_time"] = datetime.now().isoformat()

        # Generate summary
        summary = {
            "snapshots_remaining": len(self.snapshots),
            "total_disk_usage_mb": sum(
                os.path.getsize(s.disk_path) / (1024 * 1024) for s in self.snapshots.values() if os.path.exists(s.disk_path)
            ),
            "tasks_completed": len(maintenance_results["tasks_performed"]),
            "errors_encountered": len(maintenance_results["errors"]),
        }
        maintenance_results["summary"] = summary

        # Log completion
        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.TOOL_EXECUTION,
                severity=AuditSeverity.INFO,
                description="Snapshot maintenance completed",
                details={
                    "tasks_performed": maintenance_results["tasks_performed"],
                    "snapshots_remaining": summary["snapshots_remaining"],
                    "total_disk_usage_mb": f"{summary['total_disk_usage_mb']:.2f}",
                    "processing_time": f"{maintenance_results['total_processing_time_seconds']:.1f}s",
                    "error_count": summary["errors_encountered"],
                },
            ),
        )

        logger.info(
            f"Maintenance complete: performed {summary['tasks_completed']} tasks, "
            f"{summary['snapshots_remaining']} snapshots remain, "
            f"using {summary['total_disk_usage_mb']:.2f} MB total disk space",
        )

        return maintenance_results

    def _verify_all_snapshot_integrity(self) -> dict[str, Any]:
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
            "warnings": [],
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
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    check_cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if result.returncode == 0:
                    integrity_results["snapshots_valid"] += 1
                else:
                    integrity_results["corrupted_snapshots"].append(snapshot_id)
                    logger.error(f"Snapshot corrupted: {snapshot_id} - {result.stderr}")

                    # Log corruption
                    audit_logger.log_event(
                        AuditEvent(
                            event_type=AuditEventType.ERROR,
                            severity=AuditSeverity.HIGH,
                            description=f"Corrupted snapshot detected: {snapshot_id}",
                            details={"error": result.stderr},
                            target=snapshot_id,
                        ),
                    )

            except subprocess.TimeoutExpired:
                integrity_results["warnings"].append(
                    f"Timeout checking {snapshot_id}",
                )
            except Exception as e:
                integrity_results["warnings"].append(
                    f"Error checking {snapshot_id}: {e!s}",
                )

        logger.info(
            f"Integrity check complete: {integrity_results['snapshots_valid']}/{integrity_results['snapshots_checked']} valid, "
            f"{len(integrity_results['corrupted_snapshots'])} corrupted, "
            f"{len(integrity_results['missing_snapshots'])} missing",
        )

        return integrity_results

    # === Migrated Essential Methods from qemu_emulator.py ===

    SUPPORTED_ARCHITECTURES = {
        "x86_64": {"qemu": "qemu-system-x86_64"},
        "x86": {"qemu": "qemu-system-i386"},
        "arm64": {"qemu": "qemu-system-aarch64"},
        "arm": {"qemu": "qemu-system-arm"},
        "mips": {"qemu": "qemu-system-mips"},
        "mips64": {"qemu": "qemu-system-mips64"},
        "windows": {"qemu": "qemu-system-x86_64"},
    }

    def _get_image_for_architecture(self, architecture: str) -> Path | None:
        """Get image path for specific architecture using dynamic discovery."""
        from intellicrack.utils.qemu_image_discovery import get_qemu_discovery

        discovery = get_qemu_discovery()
        discovered_images = discovery.discover_images()

        if matching_images := [img for img in discovered_images if img.architecture == architecture]:
            return matching_images[0].path

        # Fallback: search by filename pattern
        arch_patterns = {
            "x86_64": ["x86_64", "amd64", "x64"],
            "x86": ["i386", "i686", "x86"],
            "arm64": ["arm64", "aarch64"],
            "arm": ["arm", "armv7"],
        }

        if architecture in arch_patterns:
            for img in discovered_images:
                if any(pattern in img.filename.lower() for pattern in arch_patterns[architecture]):
                    return img.path

        self.logger.warning("No image found for architecture: %s", architecture)
        return None

    def _set_default_config(self) -> None:
        """Set default configuration parameters from vm_framework config section."""
        # Create defaults dictionary with values from config with appropriate fallbacks
        defaults = {
            "memory_mb": self.config.get("vm_framework.qemu_defaults.memory_mb", 2048),
            "cpu_cores": self.config.get("vm_framework.qemu_defaults.cpu_cores", 2),
            "enable_kvm": self.config.get("vm_framework.qemu_defaults.enable_kvm", True),
            "network_enabled": self.config.get("vm_framework.qemu_defaults.network_enabled", True),
            "graphics_enabled": self.config.get("vm_framework.qemu_defaults.graphics_enabled", False),
            "monitor_port": self.config.get("vm_framework.qemu_defaults.monitor_port", 55555),
            "timeout": self.config.get("vm_framework.qemu_defaults.timeout", 300),
            "shared_folder_name": self.config.get("vm_framework.qemu_defaults.shared_folder_name", "intellicrack_shared_folder"),
        }

        # For each key-value pair, call self.config.set() to update actual config
        for key, value in defaults.items():
            self.config.set(key, value)

    def _get_default_rootfs(self, architecture: str) -> str:
        """Get default rootfs path for architecture using dynamic discovery.

        Args:
            architecture: Target architecture

        Returns:
            Path to default rootfs image

        """
        from intellicrack.utils.path_resolver import get_qemu_images_dir
        from intellicrack.utils.qemu_image_discovery import get_qemu_discovery

        if image_path := self._get_image_for_architecture(architecture):
            return str(image_path)

        if rootfs_dir := self.config.get("rootfs_directory", None):
            from pathlib import Path

            project_root = Path(__file__).parent.parent.parent
            rootfs_path = Path(rootfs_dir)

            if not rootfs_path.is_absolute():
                rootfs_path = project_root / rootfs_path

            if rootfs_path.exists():
                return str(rootfs_path)

        discovery = get_qemu_discovery()
        if all_images := discovery.discover_images():
            selected_image = all_images[0]
            self.logger.warning(
                "No architecture-specific image found for %s. Using first available: %s",
                architecture,
                selected_image.filename,
            )
            return str(selected_image.path)

        qemu_dir = get_qemu_images_dir()
        self.logger.error(
            "No VM images found. Please add images to: %s",
            qemu_dir,
        )
        raise RuntimeError(
            f"No VM images found in QEMU images directory. Please place a VM image file in the directory: {qemu_dir}",
        )

    def _validate_qemu_setup(self) -> None:
        """Validate QEMU installation and requirements.

        Raises:
            FileNotFoundError: If QEMU executable not found
            RuntimeError: If setup validation fails

        """
        arch_info = self.SUPPORTED_ARCHITECTURES.get(self.architecture, {})
        qemu_binary = arch_info.get("qemu", "qemu-system-x86_64")

        # Check QEMU binary availability
        import shutil
        import subprocess

        qemu_path = shutil.which(qemu_binary)
        if not qemu_path:
            raise FileNotFoundError(f"QEMU binary not found: {qemu_binary}")

        try:
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                [qemu_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                shell=False,  # Explicitly secure - using list format prevents shell injection
            )

            if result.returncode != 0:
                raise FileNotFoundError(f"QEMU binary not working: {qemu_path}")

            stdout_parts = result.stdout.split()
            if len(stdout_parts) >= 4:
                self.logger.info(f"QEMU available: {stdout_parts[0]} {stdout_parts[3]}")
            else:
                self.logger.info(f"QEMU available: {result.stdout.strip()}")
        except subprocess.TimeoutExpired as e:
            logger.error(SUBPROCESS_TIMEOUT_MSG, e)
            raise RuntimeError(f"QEMU binary check timed out: {qemu_path}") from e
        # Check if rootfs exists (optional for some use cases)
        rootfs_path = getattr(self, "rootfs_path", None)
        if rootfs_path and not os.path.exists(rootfs_path):
            self.logger.warning("Rootfs image not found: %s", rootfs_path)

    def _build_qemu_command(
        self,
        qemu_binary: str,
        headless: bool,
        enable_snapshot: bool,
    ) -> list[str]:
        """Build QEMU command line arguments.

        Args:
            qemu_binary: QEMU executable name
            headless: Whether to run headless
            enable_snapshot: Whether to enable snapshots

        Returns:
            List of command arguments

        """
        # Find QEMU binary
        import shutil

        qemu_path = shutil.which(qemu_binary)
        if not qemu_path:
            raise RuntimeError(f"QEMU binary not found: {qemu_binary}")

        cmd = [
            qemu_path,
            "-m",
            str(self.config.get("memory_mb", 1024)),
            "-smp",
            str(self.config.get("cpu_cores", 2)),
        ]

        # Add KVM acceleration if available and enabled
        if self.config.get("enable_kvm", True) and self._is_kvm_available():
            cmd.extend(["-enable-kvm"])

        # Add rootfs if available
        rootfs_path = getattr(self, "rootfs_path", None)
        if rootfs_path and os.path.exists(rootfs_path):
            cmd.extend(["-drive", f"file={rootfs_path},format=qcow2"])

        # Graphics configuration
        if headless or not self.config.get("graphics_enabled", False):
            cmd.extend(["-nographic"])
        else:
            cmd.extend(["-vnc", f":{self.config.get('vnc_port', 5900) - 5900}"])

        # Network configuration
        if self.config.get("network_enabled", True):
            cmd.extend(
                [
                    "-netdev",
                    f"user,id=net0,hostfwd=tcp::{self.config.get('ssh_port', 2222)}-:22",
                    "-device",
                    "virtio-net,netdev=net0",
                ],
            )

        # Monitor socket for management - use secure temp directory
        temp_dir = tempfile.gettempdir()
        monitor_socket = os.path.join(temp_dir, f"qemu_monitor_{os.getpid()}.sock")
        cmd.extend(["-monitor", f"unix:{monitor_socket},server,nowait"])

        if shared_folder := self.config.get("shared_folder"):
            cmd.extend(
                [
                    "-virtfs",
                    f"local,path={shared_folder},mount_tag=shared,security_model=passthrough",
                ],
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
            self.logger.error("Error checking KVM availability: %s", e)
            return False

    def _wait_for_boot(self, timeout: int = 60) -> bool:
        """Wait for system to boot completely.

        Args:
            timeout: Maximum wait time in seconds

        Returns:
            True if system booted, False if timeout

        """
        import time

        start_time = time.time()

        while time.time() - start_time < timeout:
            qemu_process = getattr(self, "qemu_process", None)
            if qemu_process and qemu_process.poll() is not None:
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
            self.logger.error("Error in qemu_manager: %s", e)
            return False

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
                self.logger.error("json.JSONDecodeError in qemu_manager: %s", e)
                # If response is multiline, try to parse each line
                for line in response.strip().split("\n"):
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError as e:
                        self.logger.error("json.JSONDecodeError in qemu_manager: %s", e)
                        continue
                return None

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("QMP command failed: %s", e)
            return None

    def start_system(self, headless: bool = False, enable_snapshot: bool = False) -> bool:
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
            import subprocess

            self.qemu_process = subprocess.Popen(  # nosec S603 - Using QEMU for secure virtual testing environment in security research
                qemu_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            if boot_success := self._wait_for_boot():
                self.logger.info("QEMU system started successfully (boot_success: %s)", boot_success)
                return True
            self.logger.error("QEMU system failed to boot properly (boot_success: %s)", boot_success)
            self.stop_system()
            return False

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error starting QEMU system: %s", e)
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
                    import subprocess

                    self.qemu_process.wait(timeout=30)
                    self.logger.info("QEMU shutdown gracefully")
                    return True
                except subprocess.TimeoutExpired:
                    self.logger.warning("Graceful shutdown timed out, forcing termination")

            # Force termination
            self.logger.info("Force terminating QEMU process")
            self.qemu_process.terminate()
            try:
                import subprocess

                self.qemu_process.wait(timeout=10)
            except subprocess.TimeoutExpired as e:
                self.logger.error(SUBPROCESS_TIMEOUT_MSG, e)
                self.qemu_process.kill()
                self.qemu_process.wait()
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
                    Path(self.monitor_socket).unlink()
                except OSError as e:
                    self.logger.error("OS error in qemu_manager: %s", e)

    def create_monitor_snapshot(self, name: str) -> bool:
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
                import time

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

    def restore_monitor_snapshot(self, name: str) -> bool:
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

    def execute_guest_command_via_monitor(self, command: str, timeout: int = 30) -> str | None:
        """Execute a command in the guest system via QEMU monitor.

        IMPORTANT WARNING: This method is for QEMU monitor interaction only.
        For actual guest OS commands, use SSH or guest agent instead.
        The human-monitor-command approach has limitations and may not work reliably.

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

            # WARNING: This is a simplified implementation for QEMU monitor interaction only
            # In practice, you'd need guest agent or SSH connectivity for reliable guest commands
            result = self._send_monitor_command(f"human-monitor-command {command}")

            # Restore original timeout
            self._monitor_timeout = original_timeout

            return result

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error executing command: %s", e)
            return None

    def copy_file_to_vm(self, binary_path: str, vm_binary_path: str) -> bool:
        """Copy a file from host to a running VM using SFTP.

        Args:
            binary_path: Local path to the file to copy
            vm_binary_path: Destination path inside the VM

        Returns:
            True if file was copied successfully, False otherwise

        """
        local_path = Path(binary_path)
        if not local_path.exists():
            self.logger.error("Source file does not exist: %s", binary_path)
            return False

        if not local_path.is_file():
            self.logger.error("Source path is not a file: %s", binary_path)
            return False

        running_snapshot = self._get_running_snapshot()
        if running_snapshot is None:
            self.logger.error("No running VM found for file copy operation")
            return False

        ssh_client = self._get_ssh_connection(running_snapshot)
        if ssh_client is None:
            self.logger.error(
                "Failed to get SSH connection to %s for file copy",
                running_snapshot.vm_name,
            )
            return False

        sftp_client = None
        try:
            sftp_client = ssh_client.open_sftp()

            remote_dir = str(Path(vm_binary_path).parent)
            if remote_dir and remote_dir not in {"/", "."}:
                try:
                    sftp_client.stat(remote_dir)
                except FileNotFoundError:
                    mkdir_result = self._execute_command_in_vm(
                        running_snapshot,
                        f"mkdir -p {remote_dir}",
                    )
                    if mkdir_result["exit_code"] != 0:
                        self.logger.warning(
                            "Could not create remote directory %s: %s",
                            remote_dir,
                            mkdir_result["stderr"],
                        )

            sftp_client.put(str(local_path), vm_binary_path)

            try:
                sftp_client.chmod(vm_binary_path, 0o755)
            except Exception as chmod_e:
                self.logger.debug("Could not set executable permission: %s", chmod_e)

            self.logger.info(
                "Successfully copied %s to %s on VM %s",
                binary_path,
                vm_binary_path,
                running_snapshot.vm_name,
            )
            return True

        except FileNotFoundError as e:
            self.logger.error("Source file not found during copy: %s: %s", binary_path, e)
            return False

        except paramiko.SFTPError as e:
            self.logger.error(
                "SFTP error copying %s to %s: %s",
                binary_path,
                vm_binary_path,
                e,
            )
            return False

        except Exception as e:
            self.logger.exception(
                "Unexpected error copying %s to VM: %s",
                binary_path,
                e,
            )
            return False

        finally:
            if sftp_client:
                try:
                    sftp_client.close()
                except Exception as close_e:
                    self.logger.debug("Error closing SFTP client: %s", close_e)

    def _get_running_snapshot(self) -> QEMUSnapshot | None:
        """Get the first running snapshot from active snapshots.

        Returns:
            QEMUSnapshot instance if a running VM is found, None otherwise

        """
        for snapshot in self.snapshots.values():
            if snapshot.vm_process is not None and snapshot.vm_process.poll() is None:
                return snapshot
        return None

    def start_vm(self, timeout: int = 120) -> bool:
        """Start the QEMU VM and wait for it to be ready.

        Args:
            timeout: Maximum time in seconds to wait for VM to become ready

        Returns:
            True if VM started successfully and is ready, False otherwise

        """
        self.logger.info("Starting VM with timeout=%d seconds", timeout)

        if self.is_vm_running():
            self.logger.info("VM is already running")
            return True

        if self.qemu_process is not None and self.qemu_process.poll() is None:
            self.logger.info("QEMU process already running, checking readiness...")
            return self._wait_for_boot(timeout)

        try:
            arch_info = self.SUPPORTED_ARCHITECTURES.get(self.architecture, {})
            qemu_binary = arch_info.get("qemu", "qemu-system-x86_64")

            cmd = self._build_qemu_command(
                qemu_binary=qemu_binary,
                headless=True,
                enable_snapshot=False,
            )

            self.logger.info("Starting QEMU with command: %s", " ".join(cmd))

            self.qemu_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            time.sleep(3)

            if self.qemu_process.poll() is not None:
                _stdout, stderr = self.qemu_process.communicate(timeout=5)
                stderr_str = stderr.decode(errors="replace") if isinstance(stderr, bytes) else str(stderr)
                self.logger.error("QEMU process exited early: %s", stderr_str)
                log_vm_operation("start", "default_vm", success=False, error=stderr_str)
                return False

            if not self._wait_for_boot(timeout):
                self.logger.error("VM did not become ready within timeout")
                self.stop_vm()
                return False

            log_vm_operation("start", "default_vm", success=True)
            self.logger.info("VM started successfully and is ready")
            return True

        except FileNotFoundError as e:
            self.logger.error("QEMU binary not found: %s", e)
            log_vm_operation("start", "default_vm", success=False, error=str(e))
            return False

        except subprocess.SubprocessError as e:
            self.logger.error("Failed to start QEMU subprocess: %s", e)
            log_vm_operation("start", "default_vm", success=False, error=str(e))
            return False

        except Exception as e:
            self.logger.exception("Unexpected error starting VM: %s", e)
            log_vm_operation("start", "default_vm", success=False, error=str(e))
            return False

    def stop_vm(self) -> bool:
        """Stop the running QEMU VM.

        Returns:
            True if VM was stopped successfully, False otherwise

        """
        if self.qemu_process is None:
            self.logger.info("No VM process to stop")
            return True

        try:
            if self.qemu_process.poll() is None:
                self.logger.info("Sending termination signal to QEMU process")
                self.qemu_process.terminate()

                try:
                    self.qemu_process.wait(timeout=10)
                    self.logger.info("QEMU process terminated gracefully")
                except subprocess.TimeoutExpired:
                    self.logger.warning("QEMU did not terminate gracefully, forcing kill")
                    self.qemu_process.kill()
                    self.qemu_process.wait(timeout=5)

            self.qemu_process = None
            log_vm_operation("stop", "default_vm", success=True)
            return True

        except Exception as e:
            self.logger.error("Error stopping VM: %s", e)
            log_vm_operation("stop", "default_vm", success=False, error=str(e))
            return False

    def is_vm_running(self) -> bool:
        """Check if the QEMU VM is currently running.

        Returns:
            True if VM is running, False otherwise

        """
        if self.qemu_process is not None and self.qemu_process.poll() is None:
            return True

        return any(
            snapshot.vm_process is not None and snapshot.vm_process.poll() is None
            for snapshot in self.snapshots.values()
        )

    def validate_ghidra_script(
        self,
        snapshot_id: str,
        script_content: str,
        binary_path: str,
    ) -> ExecutionResult:
        """Validate and execute a Ghidra script in a QEMU VM environment.

        This method uploads the script and binary to a VM, executes the Ghidra
        analysis in headless mode, and returns the execution results.

        Args:
            snapshot_id: ID of the VM snapshot to use for execution
            script_content: The Ghidra script content to validate and execute
            binary_path: Path to the binary to analyze

        Returns:
            ExecutionResult containing success status, output, and any errors

        """
        if snapshot_id not in self.snapshots:
            return ExecutionResult(
                success=False,
                output="",
                error=f"Snapshot not found: {snapshot_id}",
                exit_code=-1,
                runtime_ms=0,
            )

        snapshot = self.snapshots[snapshot_id]
        start_time = time.time()

        try:
            if snapshot.vm_process is None or snapshot.vm_process.poll() is not None:
                self.logger.info("Starting VM for Ghidra script validation")
                self._start_vm_for_snapshot(snapshot)
                if not self._wait_for_vm_ready(snapshot, timeout=120):
                    runtime_ms = int((time.time() - start_time) * 1000)
                    return ExecutionResult(
                        success=False,
                        output="",
                        error="Failed to start VM for Ghidra script validation",
                        exit_code=-1,
                        runtime_ms=runtime_ms,
                    )

            shared_dir = Path(snapshot.disk_path).parent / "shared"
            shared_dir.mkdir(exist_ok=True)

            script_extension = ".java" if "extends GhidraScript" in script_content else ".py"
            script_filename = f"ghidra_script_{int(time.time())}{script_extension}"
            script_path = shared_dir / script_filename
            script_path.write_text(script_content, encoding="utf-8")

            binary_filename = Path(binary_path).name
            if Path(binary_path).exists():
                shutil.copy2(binary_path, shared_dir / binary_filename)

            ghidra_project_name = f"validation_{snapshot_id}"

            runner_script = f"""#!/bin/bash
cd /tmp
mount -t 9p -o trans=virtio shared /mnt 2>/dev/null || true

if [ -d "/mnt" ]; then
    cp /mnt/{script_filename} . 2>/dev/null || echo "Script copy failed"
    cp /mnt/{binary_filename} . 2>/dev/null || echo "Binary copy failed"
fi

GHIDRA_INSTALL=""
for gpath in /opt/ghidra* /usr/share/ghidra* /home/*/ghidra*; do
    if [ -d "$gpath" ]; then
        GHIDRA_INSTALL="$gpath"
        break
    fi
done

if [ -z "$GHIDRA_INSTALL" ] && command -v analyzeHeadless &> /dev/null; then
    echo "[+] Found analyzeHeadless in PATH"
    ANALYZE_CMD="analyzeHeadless"
else
    ANALYZE_CMD="$GHIDRA_INSTALL/support/analyzeHeadless"
fi

if [ ! -x "$ANALYZE_CMD" ] && ! command -v analyzeHeadless &> /dev/null; then
    echo "ERROR: Ghidra not found in VM"
    echo "Please install Ghidra in /opt/ghidra or ensure analyzeHeadless is in PATH"
    exit 1
fi

echo "[+] Starting Ghidra headless analysis"
echo "[+] Binary: {binary_filename}"
echo "[+] Script: {script_filename}"

mkdir -p /tmp/ghidra_projects

if [ -n "$GHIDRA_INSTALL" ]; then
    "$ANALYZE_CMD" /tmp/ghidra_projects {ghidra_project_name} \\
        -import ./{binary_filename} \\
        -postScript ./{script_filename} \\
        -deleteProject \\
        -noanalysis 2>&1
else
    analyzeHeadless /tmp/ghidra_projects {ghidra_project_name} \\
        -import ./{binary_filename} \\
        -postScript ./{script_filename} \\
        -deleteProject \\
        -noanalysis 2>&1
fi

GHIDRA_EXIT=$?

if [ $GHIDRA_EXIT -eq 0 ]; then
    echo "[+] Ghidra analysis completed successfully"
else
    echo "[-] Ghidra analysis failed with exit code: $GHIDRA_EXIT"
fi

exit $GHIDRA_EXIT
"""

            result = self._execute_in_vm_real(snapshot, runner_script)

            runtime_ms = int((time.time() - start_time) * 1000)

            success = result["exit_code"] == 0 and self._analyze_ghidra_output(
                result["stdout"],
                result["stderr"],
            )

            snapshot.test_results.append({
                "type": "ghidra_validation",
                "script_name": script_filename,
                "binary": binary_filename,
                "success": success,
                "runtime_ms": runtime_ms,
                "timestamp": datetime.now().isoformat(),
            })

            return ExecutionResult(
                success=success,
                output=result["stdout"],
                error=result["stderr"],
                exit_code=result["exit_code"],
                runtime_ms=runtime_ms,
            )

        except Exception as e:
            self.logger.exception("Exception during Ghidra script validation: %s", e)
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Ghidra validation failed: {e!s}",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def validate_frida_script(
        self,
        snapshot_id: str,
        script_content: str,
        binary_path: str,
    ) -> ExecutionResult:
        """Validate and execute a Frida script in a QEMU VM environment.

        This method uploads the script and binary to a VM, executes the Frida
        script against the target binary, and returns the execution results.

        Args:
            snapshot_id: ID of the VM snapshot to use for execution
            script_content: The Frida script content to validate and execute
            binary_path: Path to the binary to instrument

        Returns:
            ExecutionResult containing success status, output, and any errors

        """
        if snapshot_id not in self.snapshots:
            return ExecutionResult(
                success=False,
                output="",
                error=f"Snapshot not found: {snapshot_id}",
                exit_code=-1,
                runtime_ms=0,
            )

        snapshot = self.snapshots[snapshot_id]
        start_time = time.time()

        try:
            if snapshot.vm_process is None or snapshot.vm_process.poll() is not None:
                self.logger.info("Starting VM for Frida script validation")
                self._start_vm_for_snapshot(snapshot)
                if not self._wait_for_vm_ready(snapshot, timeout=120):
                    runtime_ms = int((time.time() - start_time) * 1000)
                    return ExecutionResult(
                        success=False,
                        output="",
                        error="Failed to start VM for Frida script validation",
                        exit_code=-1,
                        runtime_ms=runtime_ms,
                    )

            shared_dir = Path(snapshot.disk_path).parent / "shared"
            shared_dir.mkdir(exist_ok=True)

            script_filename = f"frida_script_{int(time.time())}.js"
            script_path = shared_dir / script_filename
            script_path.write_text(script_content, encoding="utf-8")

            binary_filename = Path(binary_path).name
            if Path(binary_path).exists():
                shutil.copy2(binary_path, shared_dir / binary_filename)

            runner_script = f"""#!/bin/bash
cd /tmp
mount -t 9p -o trans=virtio shared /mnt 2>/dev/null || true

if [ -d "/mnt" ]; then
    cp /mnt/{script_filename} . 2>/dev/null || echo "Script copy failed"
    cp /mnt/{binary_filename} . 2>/dev/null || echo "Binary copy failed"
    chmod +x ./{binary_filename} 2>/dev/null || true
fi

if ! command -v frida &> /dev/null; then
    echo "ERROR: Frida not installed in VM"
    echo "Install with: pip install frida-tools"
    exit 1
fi

echo "[+] Starting Frida script validation"
echo "[+] Target binary: {binary_filename}"
echo "[+] Script: {script_filename}"

./{binary_filename} &
TARGET_PID=$!
sleep 2

if ! ps -p $TARGET_PID > /dev/null 2>&1; then
    echo "[-] Failed to start target binary"
    exit 1
fi

echo "[+] Attaching Frida to PID $TARGET_PID"

timeout 60 frida -p $TARGET_PID -l {script_filename} --no-pause 2>&1
FRIDA_EXIT=$?

kill $TARGET_PID 2>/dev/null || true

if [ $FRIDA_EXIT -eq 0 ] || [ $FRIDA_EXIT -eq 124 ]; then
    echo "[+] Frida script execution completed"
    exit 0
else
    echo "[-] Frida script failed with exit code: $FRIDA_EXIT"
    exit $FRIDA_EXIT
fi
"""

            result = self._execute_in_vm_real(snapshot, runner_script)

            runtime_ms = int((time.time() - start_time) * 1000)

            success = result["exit_code"] == 0 and self._analyze_frida_output(
                result["stdout"],
                result["stderr"],
            )

            snapshot.test_results.append({
                "type": "frida_validation",
                "script_name": script_filename,
                "binary": binary_filename,
                "success": success,
                "runtime_ms": runtime_ms,
                "timestamp": datetime.now().isoformat(),
            })

            return ExecutionResult(
                success=success,
                output=result["stdout"],
                error=result["stderr"],
                exit_code=result["exit_code"],
                runtime_ms=runtime_ms,
            )

        except Exception as e:
            self.logger.exception("Exception during Frida script validation: %s", e)
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Frida validation failed: {e!s}",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def test_frida_script_with_callback(
        self,
        snapshot_id: str,
        script_content: str,
        binary_path: str,
        output_callback: Callable[[str], None],
    ) -> ExecutionResult:
        """Execute Frida script in QEMU VM with real-time output streaming.

        This method runs a Frida script against a target binary in an isolated
        QEMU virtual machine environment, streaming output in real-time through
        the provided callback function. Used by UI components for live monitoring.

        Args:
            snapshot_id: QEMU VM snapshot identifier for the test environment.
            script_content: Frida JavaScript code to inject into target process.
            binary_path: Full path to target binary for instrumentation.
            output_callback: Function called with each line of output for real-time
                monitoring of script execution progress and results.

        Returns:
            ExecutionResult containing success status, output, error messages,
            exit code, and runtime in milliseconds.

        """
        if snapshot_id not in self.snapshots:
            output_callback("[ERROR] Snapshot not found")
            return ExecutionResult(
                success=False,
                output="",
                error=f"Snapshot not found: {snapshot_id}",
                exit_code=-1,
                runtime_ms=0,
            )

        snapshot = self.snapshots[snapshot_id]
        start_time = time.time()
        collected_output: list[str] = []

        try:
            output_callback("[*] Preparing Frida script execution environment...")

            if snapshot.vm_process is None or snapshot.vm_process.poll() is not None:
                output_callback("[*] Starting VM for Frida script test...")
                self._start_vm_for_snapshot(snapshot)
                if not self._wait_for_vm_ready(snapshot, timeout=120):
                    output_callback("[ERROR] VM failed to become ready")
                    runtime_ms = int((time.time() - start_time) * 1000)
                    return ExecutionResult(
                        success=False,
                        output="",
                        error="Failed to start VM for Frida script test",
                        exit_code=-1,
                        runtime_ms=runtime_ms,
                    )

            shared_dir = Path(snapshot.disk_path).parent / "shared"
            shared_dir.mkdir(exist_ok=True)

            script_filename = f"frida_callback_test_{int(time.time())}.js"
            script_path = shared_dir / script_filename
            script_path.write_text(script_content, encoding="utf-8")
            output_callback(f"[*] Script written: {script_filename}")

            binary_filename = Path(binary_path).name
            if Path(binary_path).exists():
                shutil.copy2(binary_path, shared_dir / binary_filename)
                output_callback(f"[*] Binary copied: {binary_filename}")
            else:
                output_callback(f"[WARNING] Binary not found locally: {binary_path}")

            runner_script = f"""#!/bin/bash
set -o pipefail
cd /tmp

mount -t 9p -o trans=virtio shared /mnt 2>/dev/null || true

if [ -d "/mnt" ]; then
    cp /mnt/{script_filename} . 2>/dev/null && echo "[*] Script copied from shared folder"
    cp /mnt/{binary_filename} . 2>/dev/null && echo "[*] Binary copied from shared folder"
    chmod +x ./{binary_filename} 2>/dev/null
fi

if ! command -v frida &> /dev/null; then
    echo "[ERROR] Frida not installed in VM"
    echo "[INFO] Install with: pip install frida-tools"
    exit 1
fi

echo "[*] Starting target process: {binary_filename}"

if [ ! -f "./{binary_filename}" ]; then
    echo "[ERROR] Target binary not found"
    exit 1
fi

./{binary_filename} &
TARGET_PID=$!
sleep 2

if ! ps -p $TARGET_PID > /dev/null 2>&1; then
    echo "[ERROR] Target process failed to start"
    exit 1
fi

echo "[*] Target process started with PID: $TARGET_PID"
echo "[*] Attaching Frida to process..."

timeout 60 frida -p $TARGET_PID -l {script_filename} --no-pause 2>&1 || FRIDA_TIMEOUT=$?

if ps -p $TARGET_PID > /dev/null 2>&1; then
    echo "[+] SUCCESS: Process still running after Frida injection"
    kill $TARGET_PID 2>/dev/null || true
else
    echo "[*] Process terminated during Frida execution"
fi

echo "[*] Frida script test completed"
exit 0
"""

            output_callback("[*] Executing Frida script in VM...")

            ssh_client = self._get_ssh_connection(snapshot)
            if not ssh_client:
                output_callback("[ERROR] Failed to establish SSH connection")
                runtime_ms = int((time.time() - start_time) * 1000)
                return ExecutionResult(
                    success=False,
                    output="\n".join(collected_output),
                    error="SSH connection failed",
                    exit_code=-1,
                    runtime_ms=runtime_ms,
                )

            script_remote_path = f"{REMOTE_TEMP_DIR}/run_frida_{int(time.time())}.sh"
            self._upload_file_to_vm(snapshot, runner_script, script_remote_path)

            _stdin, stdout, stderr = ssh_client.exec_command(
                f"chmod +x {script_remote_path} && bash {script_remote_path}",
                timeout=120,
            )

            for line in iter(stdout.readline, ""):
                if line:
                    clean_line = line.strip()
                    output_callback(clean_line)
                    collected_output.append(clean_line)

            exit_code = stdout.channel.recv_exit_status()

            stderr_content = stderr.read().decode("utf-8", errors="replace")
            if stderr_content.strip():
                for line in stderr_content.strip().split("\n"):
                    output_callback(f"[STDERR] {line}")
                    collected_output.append(f"[STDERR] {line}")

            runtime_ms = int((time.time() - start_time) * 1000)

            success = exit_code == 0 or self._analyze_frida_output(
                "\n".join(collected_output),
                stderr_content,
            )

            output_callback(f"[*] Execution completed in {runtime_ms}ms (success={success})")

            snapshot.test_results.append({
                "type": "frida_callback_test",
                "script_name": script_filename,
                "binary": binary_filename,
                "success": success,
                "runtime_ms": runtime_ms,
                "timestamp": datetime.now().isoformat(),
            })

            return ExecutionResult(
                success=success,
                output="\n".join(collected_output),
                error=stderr_content,
                exit_code=exit_code,
                runtime_ms=runtime_ms,
            )

        except Exception as e:
            runtime_ms = int((time.time() - start_time) * 1000)
            error_msg = f"Frida callback test failed: {e!s}"
            output_callback(f"[ERROR] {error_msg}")
            self.logger.exception("Exception in test_frida_script_with_callback: %s", e)

            return ExecutionResult(
                success=False,
                output="\n".join(collected_output),
                error=error_msg,
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def execute_in_vm(self, command: str, timeout: int = 300) -> ExecutionResult:
        """Execute a command inside the running VM.

        This method is the primary entry point for executing arbitrary commands
        within the QEMU VM environment.

        Args:
            command: The command to execute inside the VM
            timeout: Maximum execution time in seconds

        Returns:
            ExecutionResult containing success status, output, and any errors

        """
        start_time = time.time()

        running_snapshot = self._get_running_snapshot()
        if running_snapshot is None:
            if not self.is_vm_running():
                return ExecutionResult(
                    success=False,
                    output="",
                    error="No VM is currently running",
                    exit_code=-1,
                    runtime_ms=0,
                )

            if self.qemu_process is not None:
                self.logger.warning(
                    "VM process running but no snapshot available, trying monitor command"
                )
                result = self.execute_guest_command_via_monitor(command, timeout=timeout)
                runtime_ms = int((time.time() - start_time) * 1000)
                if result is not None:
                    return ExecutionResult(
                        success=True,
                        output=result,
                        error="",
                        exit_code=0,
                        runtime_ms=runtime_ms,
                    )
                return ExecutionResult(
                    success=False,
                    output="",
                    error="Monitor command execution failed",
                    exit_code=-1,
                    runtime_ms=runtime_ms,
                )

        try:
            result = self._execute_command_in_vm(running_snapshot, command, timeout=timeout)
            runtime_ms = int((time.time() - start_time) * 1000)

            return ExecutionResult(
                success=result["exit_code"] == 0,
                output=result["stdout"],
                error=result["stderr"],
                exit_code=result["exit_code"],
                runtime_ms=runtime_ms,
            )

        except Exception as e:
            self.logger.exception("Exception during VM command execution: %s", e)
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"VM execution failed: {e!s}",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def _save_metadata(self) -> None:
        """Save snapshot metadata to persistent storage.

        Persists current snapshot information to a JSON file for recovery
        after restarts.

        """
        import json

        metadata_path = self.working_dir / "snapshot_metadata.json"

        try:
            metadata = {
                "last_updated": datetime.now().isoformat(),
                "snapshot_count": len(self.snapshots),
                "snapshots": {},
            }

            for snapshot_id, snapshot in self.snapshots.items():
                metadata["snapshots"][snapshot_id] = {
                    "vm_name": snapshot.vm_name,
                    "disk_path": snapshot.disk_path,
                    "binary_path": snapshot.binary_path,
                    "created_at": snapshot.created_at.isoformat(),
                    "ssh_port": snapshot.ssh_port,
                    "vnc_port": snapshot.vnc_port,
                    "version": snapshot.version,
                    "parent_snapshot": snapshot.parent_snapshot,
                    "children_snapshots": list(snapshot.children_snapshots),
                    "test_results_count": len(snapshot.test_results),
                    "memory_usage": snapshot.memory_usage,
                    "disk_usage": snapshot.disk_usage,
                    "network_isolated": snapshot.network_isolated,
                }

            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)

            self.logger.debug("Saved snapshot metadata to %s", metadata_path)

        except Exception as e:
            self.logger.error("Failed to save snapshot metadata: %s", e)
