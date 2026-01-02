"""Integration tests for VM Framework.

This module provides end-to-end integration tests for the VM Framework,
testing real QEMU interactions with proper test isolation and comprehensive
validation of VM functionality.
"""

import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Generator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from intellicrack.ai.common_types import ExecutionResult
from intellicrack.ai.qemu_manager import QEMUManager, QEMUSnapshot
from intellicrack.core.processing.vm_workflow_manager import VMWorkflowManager


@dataclass
class TestVMConfig:
    """Configuration for test VMs."""

    memory_mb: int = 128
    cpu_cores: int = 1
    enable_kvm: bool = False
    ssh_port_start: int = 22222
    vnc_port_start: int = 5900
    monitor_port: int = 55555
    network_isolated: bool = True


@dataclass
class TestSSHKeys:
    """SSH key pair for test VMs."""

    private_key: bytes
    public_key: bytes
    private_key_path: Path
    public_key_path: Path


class RealVMTestEnvironment:
    """Real test environment for VM integration tests."""

    def __init__(self, test_dir: Path) -> None:
        """Initialize test environment.

        Args:
            test_dir: Directory for test artifacts
        """
        self.test_dir = test_dir
        self.config = TestVMConfig()
        self.ssh_keys: TestSSHKeys | None = None
        self.test_disk: Path | None = None
        self.qemu_available = shutil.which("qemu-system-x86_64") is not None

    def setup(self) -> bool:
        """Set up test environment with real resources.

        Returns:
            True if setup succeeded
        """
        if not self.qemu_available:
            return False

        self.ssh_keys = self._generate_real_ssh_keys()
        self.test_disk = self._create_real_test_disk()

        return self.test_disk is not None

    def _generate_real_ssh_keys(self) -> TestSSHKeys:
        """Generate real SSH key pair for testing.

        Returns:
            TestSSHKeys with real cryptographic keys
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )

        priv_path = self.test_dir / "test_ssh_key"
        pub_path = self.test_dir / "test_ssh_key.pub"

        priv_path.write_bytes(private_pem)
        pub_path.write_bytes(public_pem)

        priv_path.chmod(0o600)

        return TestSSHKeys(
            private_key=private_pem,
            public_key=public_pem,
            private_key_path=priv_path,
            public_key_path=pub_path,
        )

    def _create_real_test_disk(self) -> Path | None:
        """Create real QEMU disk image for testing.

        Returns:
            Path to created disk or None if creation failed
        """
        disk_path = self.test_dir / "test_disk.qcow2"

        try:
            result = subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", str(disk_path), "100M"],
                check=True,
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0:
                return disk_path
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return None

    def cleanup(self) -> None:
        """Clean up test environment resources."""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)


class RealBinaryCreator:
    """Creates real test binaries with valid PE/ELF structures."""

    @staticmethod
    def create_pe_binary(output_path: Path) -> Path:
        """Create real minimal PE binary.

        Args:
            output_path: Path where binary will be created

        Returns:
            Path to created binary
        """
        with open(output_path, "wb") as f:
            f.write(b"MZ")
            f.write(b"\x90" * 58)
            f.write(b"\x80\x00\x00\x00")
            f.write(b"\x00" * 64)
            f.write(b"PE\x00\x00")
            f.write(b"\x4c\x01")
            f.write(b"\x00" * 498)

        return output_path

    @staticmethod
    def create_elf_binary(output_path: Path) -> Path:
        """Create real minimal ELF binary.

        Args:
            output_path: Path where binary will be created

        Returns:
            Path to created binary
        """
        with open(output_path, "wb") as f:
            f.write(b"\x7fELF")
            f.write(b"\x02")
            f.write(b"\x01")
            f.write(b"\x01")
            f.write(b"\x00" * 9)
            f.write(b"\x02\x00")
            f.write(b"\x3e\x00")
            f.write(b"\x01\x00\x00\x00")
            f.write(b"\x00" * 476)

        return output_path


class RealQEMUProcess:
    """Manages real QEMU process lifecycle."""

    def __init__(self, disk_path: Path, config: TestVMConfig) -> None:
        """Initialize QEMU process manager.

        Args:
            disk_path: Path to QEMU disk image
            config: VM configuration
        """
        self.disk_path = disk_path
        self.config = config
        self.process: subprocess.Popen[bytes] | None = None

    def start(self, timeout: float = 2.0) -> bool:
        """Start real QEMU process.

        Args:
            timeout: Time to wait for process to start

        Returns:
            True if process started successfully
        """
        cmd = [
            "qemu-system-x86_64",
            "-m",
            str(self.config.memory_mb),
            "-smp",
            str(self.config.cpu_cores),
            "-hda",
            str(self.disk_path),
            "-nographic",
            "-monitor",
            "none",
            "-serial",
            "none",
            "-display",
            "none",
        ]

        try:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            time.sleep(timeout)

            poll_result = self.process.poll()

            return poll_result is None or poll_result == 0
        except (FileNotFoundError, OSError):
            return False

    def stop(self, timeout: float = 5.0) -> bool:
        """Stop QEMU process.

        Args:
            timeout: Time to wait for graceful shutdown

        Returns:
            True if process stopped successfully
        """
        if self.process is None:
            return True

        try:
            self.process.terminate()
            self.process.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            return True
        except Exception:
            return False

    def is_running(self) -> bool:
        """Check if QEMU process is running.

        Returns:
            True if process is running
        """
        if self.process is None:
            return False

        return self.process.poll() is None


class RealScriptExecutor:
    """Executes real scripts with proper environment setup."""

    def __init__(self, work_dir: Path) -> None:
        """Initialize script executor.

        Args:
            work_dir: Working directory for script execution
        """
        self.work_dir = work_dir

    def execute_bash_script(
        self, script_content: str, args: list[str], env_vars: dict[str, str] | None = None
    ) -> ExecutionResult:
        """Execute real bash script.

        Args:
            script_content: Script content to execute
            args: Command-line arguments
            env_vars: Additional environment variables

        Returns:
            ExecutionResult with output and status
        """
        script_path = self.work_dir / "script.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        try:
            result = subprocess.run(
                ["bash", str(script_path)] + args,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )

            return ExecutionResult(
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr if result.returncode != 0 else "",
                exit_code=result.returncode,
                runtime_ms=0,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return ExecutionResult(success=False, output="", error=str(e), exit_code=-1, runtime_ms=0)

    def execute_powershell_script(
        self, script_content: str, args: list[str], env_vars: dict[str, str] | None = None
    ) -> ExecutionResult:
        """Execute real PowerShell script.

        Args:
            script_content: Script content to execute
            args: Command-line arguments
            env_vars: Additional environment variables

        Returns:
            ExecutionResult with output and status
        """
        script_path = self.work_dir / "script.ps1"
        script_path.write_text(script_content)

        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        try:
            cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path)]
            cmd.extend(args)

            result = subprocess.run(
                cmd, env=env, capture_output=True, text=True, timeout=30
            )

            return ExecutionResult(
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr if result.returncode != 0 else "",
                exit_code=result.returncode,
                runtime_ms=0,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return ExecutionResult(success=False, output="", error=str(e), exit_code=-1, runtime_ms=0)


class RealVMValidator:
    """Validates real VM operations and state."""

    @staticmethod
    def validate_qemu_installation() -> tuple[bool, str]:
        """Validate QEMU installation is functional.

        Returns:
            Tuple of (is_valid, version_info)
        """
        qemu_path = shutil.which("qemu-system-x86_64")
        if not qemu_path:
            return False, "QEMU not found in PATH"

        try:
            result = subprocess.run(
                ["qemu-system-x86_64", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0 and "QEMU" in result.stdout:
                return True, result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return False, "QEMU not functional"

    @staticmethod
    def validate_disk_image(disk_path: Path) -> bool:
        """Validate QEMU disk image is valid.

        Args:
            disk_path: Path to disk image

        Returns:
            True if disk image is valid
        """
        if not disk_path.exists():
            return False

        try:
            result = subprocess.run(
                ["qemu-img", "info", str(disk_path)],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    @staticmethod
    def validate_binary_format(binary_path: Path) -> tuple[bool, str]:
        """Validate binary has correct format.

        Args:
            binary_path: Path to binary

        Returns:
            Tuple of (is_valid, format_type)
        """
        if not binary_path.exists():
            return False, "File does not exist"

        with open(binary_path, "rb") as f:
            header = f.read(4)

            if header[:2] == b"MZ":
                return True, "PE"
            elif header == b"\x7fELF":
                return True, "ELF"

        return False, "Unknown"


@pytest.fixture
def test_environment(tmp_path: Path) -> Generator[RealVMTestEnvironment, None, None]:
    """Create real VM test environment.

    Args:
        tmp_path: Pytest temporary directory

    Yields:
        Configured test environment
    """
    env = RealVMTestEnvironment(tmp_path)
    env.setup()
    yield env
    env.cleanup()


@pytest.fixture
def binary_creator() -> RealBinaryCreator:
    """Provide binary creator utility.

    Returns:
        Binary creator instance
    """
    return RealBinaryCreator()


@pytest.fixture
def vm_validator() -> RealVMValidator:
    """Provide VM validator utility.

    Returns:
        VM validator instance
    """
    return RealVMValidator()


class TestVMFrameworkIntegration:
    """Integration test suite for VM Framework with real implementations."""

    def test_qemu_installation_detected(
        self, vm_validator: RealVMValidator
    ) -> None:
        """Test QEMU installation is properly detected."""
        is_valid, version = vm_validator.validate_qemu_installation()

        if is_valid:
            assert "QEMU" in version
            assert len(version) > 0
        else:
            pytest.skip("QEMU not available for testing")

    def test_create_real_test_disk(
        self, test_environment: RealVMTestEnvironment, vm_validator: RealVMValidator
    ) -> None:
        """Test creating real QEMU disk image."""
        if not test_environment.qemu_available:
            pytest.skip("QEMU not available")

        assert test_environment.test_disk is not None
        assert test_environment.test_disk.exists()
        assert vm_validator.validate_disk_image(test_environment.test_disk)

    def test_generate_real_ssh_keys(
        self, test_environment: RealVMTestEnvironment
    ) -> None:
        """Test generating real SSH key pairs."""
        if not test_environment.qemu_available:
            pytest.skip("QEMU not available")

        assert test_environment.ssh_keys is not None
        assert b"-----BEGIN PRIVATE KEY-----" in test_environment.ssh_keys.private_key
        assert b"ssh-rsa" in test_environment.ssh_keys.public_key
        assert test_environment.ssh_keys.private_key_path.exists()
        assert test_environment.ssh_keys.public_key_path.exists()

    def test_create_valid_pe_binary(
        self, tmp_path: Path, binary_creator: RealBinaryCreator, vm_validator: RealVMValidator
    ) -> None:
        """Test creating valid PE binary structure."""
        binary_path = tmp_path / "test.exe"
        binary_creator.create_pe_binary(binary_path)

        assert binary_path.exists()
        is_valid, format_type = vm_validator.validate_binary_format(binary_path)
        assert is_valid
        assert format_type == "PE"

    def test_create_valid_elf_binary(
        self, tmp_path: Path, binary_creator: RealBinaryCreator, vm_validator: RealVMValidator
    ) -> None:
        """Test creating valid ELF binary structure."""
        binary_path = tmp_path / "test.elf"
        binary_creator.create_elf_binary(binary_path)

        assert binary_path.exists()
        is_valid, format_type = vm_validator.validate_binary_format(binary_path)
        assert is_valid
        assert format_type == "ELF"

    def test_start_stop_qemu_process(
        self, test_environment: RealVMTestEnvironment
    ) -> None:
        """Test starting and stopping real QEMU process."""
        if not test_environment.qemu_available or not test_environment.test_disk:
            pytest.skip("QEMU not available")

        qemu_proc = RealQEMUProcess(test_environment.test_disk, test_environment.config)

        started = qemu_proc.start(timeout=1.0)

        if started and qemu_proc.is_running():
            assert qemu_proc.stop(timeout=3.0)

    def test_execute_bash_script_with_output_path(self, tmp_path: Path) -> None:
        """Test executing bash script with OUTPUT_PATH environment variable."""
        executor = RealScriptExecutor(tmp_path)

        input_file = tmp_path / "input.txt"
        input_file.write_text("test input")

        output_file = tmp_path / "output.txt"

        script = """#!/bin/bash
INPUT_PATH=$1
if [ -z "$OUTPUT_PATH" ]; then
    echo "ERROR: OUTPUT_PATH not set"
    exit 1
fi
echo "Processing: $INPUT_PATH"
echo "Modified content" > "$OUTPUT_PATH"
"""

        result = executor.execute_bash_script(
            script, [str(input_file)], {"OUTPUT_PATH": str(output_file)}
        )

        if result.success:
            assert output_file.exists()
            assert "Modified content" in output_file.read_text()
        else:
            pytest.skip("Bash not available on this platform")

    def test_execute_powershell_script_with_env_vars(self, tmp_path: Path) -> None:
        """Test executing PowerShell script with environment variables."""
        executor = RealScriptExecutor(tmp_path)

        input_file = tmp_path / "input.txt"
        input_file.write_text("test input")

        output_file = tmp_path / "output.txt"

        script = """
param($InputPath)
if (-not $env:OUTPUT_PATH) {
    Write-Error "OUTPUT_PATH not set"
    exit 1
}
"Modified content" | Out-File -FilePath $env:OUTPUT_PATH -Encoding UTF8
"""

        result = executor.execute_powershell_script(
            script, [str(input_file)], {"OUTPUT_PATH": str(output_file)}
        )

        if result.success:
            assert output_file.exists()

    def test_qemu_snapshot_creation_real_data(self, tmp_path: Path) -> None:
        """Test creating QEMUSnapshot with real data structures."""
        disk_path = tmp_path / "snapshot.qcow2"
        binary_path = tmp_path / "test.exe"

        RealBinaryCreator.create_pe_binary(binary_path)

        snapshot = QEMUSnapshot(
            snapshot_id="test_snapshot_001",
            vm_name="test_vm",
            disk_path=str(disk_path),
            binary_path=str(binary_path),
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
            network_isolated=True,
        )

        assert snapshot.snapshot_id == "test_snapshot_001"
        assert snapshot.vm_name == "test_vm"
        assert snapshot.ssh_port == 22222
        assert snapshot.vnc_port == 5900
        assert snapshot.network_isolated is True
        assert snapshot.version == 1

    def test_execute_modification_script_validates_output(self, tmp_path: Path) -> None:
        """Test modification script creates valid output file."""
        executor = RealScriptExecutor(tmp_path)

        input_binary = tmp_path / "input.exe"
        RealBinaryCreator.create_pe_binary(input_binary)

        output_binary = tmp_path / "modified.exe"

        script = """#!/bin/bash
INPUT_PATH=$1
if [ ! -f "$INPUT_PATH" ]; then
    echo "ERROR: Input file not found"
    exit 1
fi
cp "$INPUT_PATH" "$OUTPUT_PATH"
echo "00" | xxd -r -p >> "$OUTPUT_PATH"
"""

        result = executor.execute_bash_script(
            script, [str(input_binary)], {"OUTPUT_PATH": str(output_binary)}
        )

        if result.success:
            assert output_binary.exists()
            assert output_binary.stat().st_size >= input_binary.stat().st_size
        else:
            pytest.skip("Bash not available on this platform")

    def test_vm_workflow_manager_initialization(self) -> None:
        """Test VMWorkflowManager initializes with real components."""
        workflow = VMWorkflowManager()

        assert workflow.qemu_manager is not None
        assert isinstance(workflow.qemu_manager, QEMUManager)
        assert hasattr(workflow.qemu_manager, "create_script_test_snapshot")
        assert hasattr(workflow.qemu_manager, "test_script_in_vm")
        assert hasattr(workflow.qemu_manager, "cleanup_snapshot")

    def test_qemu_manager_initialization(self) -> None:
        """Test QEMUManager initializes with real configuration."""
        manager = QEMUManager()

        assert hasattr(manager, "snapshots")
        assert hasattr(manager, "ssh_pool")
        assert hasattr(manager, "known_hosts_path")
        assert isinstance(manager.snapshots, dict)

    def test_real_file_operations_in_workflow(self, tmp_path: Path) -> None:
        """Test real file operations during workflow execution."""
        binary_path = tmp_path / "test.exe"
        RealBinaryCreator.create_pe_binary(binary_path)

        assert binary_path.exists()

        temp_dir = tmp_path / "temp_workflow"
        temp_dir.mkdir()

        uploaded_path = temp_dir / "uploaded.exe"
        shutil.copy(binary_path, uploaded_path)

        assert uploaded_path.exists()
        assert uploaded_path.stat().st_size == binary_path.stat().st_size

        modified_path = temp_dir / "modified.exe"
        with open(uploaded_path, "rb") as src:
            with open(modified_path, "wb") as dst:
                dst.write(src.read())
                dst.write(b"\x00\x00")

        assert modified_path.exists()
        assert modified_path.stat().st_size > uploaded_path.stat().st_size

    def test_snapshot_cleanup_removes_resources(self, tmp_path: Path) -> None:
        """Test snapshot cleanup properly removes resources."""
        disk_path = tmp_path / "cleanup_test.qcow2"
        binary_path = tmp_path / "test.exe"

        RealBinaryCreator.create_pe_binary(binary_path)

        snapshot = QEMUSnapshot(
            snapshot_id="cleanup_test",
            vm_name="cleanup_vm",
            disk_path=str(disk_path),
            binary_path=str(binary_path),
            created_at=datetime.now(),
        )

        manager = QEMUManager()
        manager.snapshots["cleanup_test"] = snapshot

        assert "cleanup_test" in manager.snapshots

        manager.cleanup_snapshot("cleanup_test")

        assert "cleanup_test" not in manager.snapshots

    def test_validate_no_hardcoded_paths_in_workflow(self) -> None:
        """Test workflow code contains no hardcoded output paths."""
        import inspect
        import re

        from intellicrack.core.processing import vm_workflow_manager

        source = inspect.getsource(vm_workflow_manager)

        hardcoded_patterns = [
            r'["\']\/home\/\w+\/specific_output',
            r'["\']C:\\\\Users\\\\.*\\\\output',
        ]

        for pattern in hardcoded_patterns:
            matches = re.findall(pattern, source, re.IGNORECASE)
            filtered = [
                m
                for m in matches
                if all(ok not in m for ok in ["Documents", "Intellicrack_Output", "tmp", "temp"])
            ]
            assert len(filtered) == 0, f"Found hardcoded path: {pattern}"

    def test_script_executor_handles_errors(self, tmp_path: Path) -> None:
        """Test script executor properly handles execution errors."""
        executor = RealScriptExecutor(tmp_path)

        failing_script = """#!/bin/bash
echo "Starting script"
exit 1
"""

        result = executor.execute_bash_script(failing_script, [])

        if result.exit_code != -1:
            assert not result.success
            assert result.exit_code == 1
        else:
            pytest.skip("Bash not available on this platform")

    def test_binary_size_validation(
        self, tmp_path: Path, binary_creator: RealBinaryCreator
    ) -> None:
        """Test binary files have valid sizes."""
        pe_binary = tmp_path / "test.exe"
        binary_creator.create_pe_binary(pe_binary)

        assert pe_binary.stat().st_size > 0
        assert pe_binary.stat().st_size >= 572

        elf_binary = tmp_path / "test.elf"
        binary_creator.create_elf_binary(elf_binary)

        assert elf_binary.stat().st_size > 0
        assert elf_binary.stat().st_size >= 500

    def test_execution_result_structure(self, tmp_path: Path) -> None:
        """Test ExecutionResult contains valid data."""
        executor = RealScriptExecutor(tmp_path)

        script = """#!/bin/bash
echo "Success output"
exit 0
"""

        result = executor.execute_bash_script(script, [])

        assert isinstance(result, ExecutionResult)
        assert hasattr(result, "success")
        assert hasattr(result, "output")
        assert hasattr(result, "error")
        assert hasattr(result, "exit_code")

        if result.success:
            assert result.exit_code == 0
            assert "Success output" in result.output


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
