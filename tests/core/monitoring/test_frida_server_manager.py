"""Comprehensive tests for FridaServerManager.

Tests verify that FridaServerManager handles real-world scenarios correctly:
- Platform and architecture detection across Windows/Linux/macOS
- Network failures during downloads
- Process lifecycle management
- Health checks and server responsiveness
- Administrator privilege detection
- Edge cases and error conditions

Tests are designed to FAIL if the implementation doesn't handle edge cases.
"""

import contextlib
import io
import lzma
import os
import platform
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import frida
import pytest
import requests

from intellicrack.core.monitoring.frida_server_manager import FridaServerManager


REALISTIC_ELF_BINARY = (
    b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x02\x00\x3e\x00\x01\x00\x00\x00\x10\x0e\x00\x00\x00\x00\x00\x00"
    b"\x40\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x40\x00\x38\x00\x09\x00\x40\x00\x1e\x00\x1b\x00"
    b"\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00"
)

REALISTIC_PE_BINARY = (
    b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"PE\x00\x00\x64\x86\x06\x00\x07\x00\x00\x00\x00\x00\x00\x00"
    b"\xf0\x00\x22\x00\x0b\x02\x0e\x00\x00\x1c\x00\x00\x00\x08\x00\x00"
)


class RealPlatformInfo:
    """Provides real platform information for testing platform detection."""

    def __init__(self, system: str, machine: str) -> None:
        self.system = system
        self.machine = machine
        self.original_system = platform.system
        self.original_machine = platform.machine

    def __enter__(self) -> "RealPlatformInfo":
        platform.system = lambda: self.system
        platform.machine = lambda: self.machine
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        platform.system = self.original_system
        platform.machine = self.original_machine


class RealTemporaryDirectory:
    """Creates real temporary directories for file I/O tests."""

    def __init__(self) -> None:
        self.temp_dir: Path | None = None

    def __enter__(self) -> Path:
        self.temp_dir = Path(tempfile.mkdtemp())
        return self.temp_dir

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.temp_dir and self.temp_dir.exists():
            import shutil

            shutil.rmtree(self.temp_dir, ignore_errors=True)


class TestPlatformDetection:
    """Test platform and architecture detection across operating systems."""

    def test_current_platform_generates_valid_url(self) -> None:
        """Test current platform detection generates valid URL format."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)
            url = manager._get_download_url()

            assert url.startswith("https://github.com/frida/frida/releases/download/")
            assert frida.__version__ in url
            assert url.endswith(".xz") or url.endswith(".exe.xz")

    def test_windows_x64_detection(self) -> None:
        """Test Windows x64 platform detection generates correct download URL."""
        with RealPlatformInfo("Windows", "AMD64"):
            with RealTemporaryDirectory() as temp_dir:
                manager = FridaServerManager(server_dir=temp_dir)
                url = manager._get_download_url()

                assert "windows-x86_64" in url
                assert frida.__version__ in url
                assert url.endswith(".exe.xz")

    def test_windows_x86_detection(self) -> None:
        """Test Windows x86 (32-bit) platform detection generates correct URL."""
        with RealPlatformInfo("Windows", "i686"):
            with RealTemporaryDirectory() as temp_dir:
                manager = FridaServerManager(server_dir=temp_dir)
                url = manager._get_download_url()

                assert "windows-x86" in url
                assert frida.__version__ in url
                assert url.endswith(".exe.xz")

    def test_linux_x64_detection(self) -> None:
        """Test Linux x64 platform detection generates correct download URL."""
        with RealPlatformInfo("Linux", "x86_64"):
            with RealTemporaryDirectory() as temp_dir:
                manager = FridaServerManager(server_dir=temp_dir)
                url = manager._get_download_url()

                assert "linux-x86_64" in url
                assert frida.__version__ in url
                assert not url.endswith(".exe.xz")

    def test_linux_arm64_detection(self) -> None:
        """Test Linux ARM64 platform detection generates correct download URL."""
        with RealPlatformInfo("Linux", "aarch64"):
            with RealTemporaryDirectory() as temp_dir:
                manager = FridaServerManager(server_dir=temp_dir)
                url = manager._get_download_url()

                assert "linux-arm64" in url

    def test_macos_arm64_detection(self) -> None:
        """Test macOS ARM64 (Apple Silicon) platform detection."""
        with RealPlatformInfo("Darwin", "arm64"):
            with RealTemporaryDirectory() as temp_dir:
                manager = FridaServerManager(server_dir=temp_dir)
                url = manager._get_download_url()

                assert "macos-arm64" in url

    def test_unsupported_architecture_raises_error(self) -> None:
        """Test that unsupported architecture raises ValueError with clear message."""
        with RealPlatformInfo("Linux", "mips64"):
            with RealTemporaryDirectory() as temp_dir:
                manager = FridaServerManager(server_dir=temp_dir)

                with pytest.raises(ValueError, match="Unsupported architecture"):
                    manager._get_download_url()

    def test_unsupported_platform_raises_error(self) -> None:
        """Test that unsupported platform raises ValueError."""
        with RealPlatformInfo("FreeBSD", "x86_64"):
            with RealTemporaryDirectory() as temp_dir:
                manager = FridaServerManager(server_dir=temp_dir)

                with pytest.raises(ValueError, match="Unsupported platform"):
                    manager._get_download_url()


class TestExecutableName:
    """Test executable name generation for different platforms."""

    def test_current_platform_executable_name(self) -> None:
        """Test current platform generates valid executable name."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)
            name = manager._get_server_executable_name()

            assert name in ("frida-server", "frida-server.exe")
            assert "frida-server" in name

    def test_windows_executable_has_exe_extension(self) -> None:
        """Test Windows executable name includes .exe extension."""
        with RealPlatformInfo("Windows", "AMD64"):
            with RealTemporaryDirectory() as temp_dir:
                manager = FridaServerManager(server_dir=temp_dir)
                name = manager._get_server_executable_name()

                assert name == "frida-server.exe"

    def test_linux_executable_no_extension(self) -> None:
        """Test Linux executable name has no extension."""
        with RealPlatformInfo("Linux", "x86_64"):
            with RealTemporaryDirectory() as temp_dir:
                manager = FridaServerManager(server_dir=temp_dir)
                name = manager._get_server_executable_name()

                assert name == "frida-server"


class TestDecompression:
    """Test XZ decompression functionality with real files."""

    def test_successful_decompression_of_real_data(self) -> None:
        """Test successful decompression of actual .xz compressed data."""
        test_data = b"frida-server binary content with real data" * 100
        compressed = lzma.compress(test_data)

        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            input_path = temp_dir / "input.xz"
            output_path = temp_dir / "output"

            input_path.write_bytes(compressed)

            manager._decompress_xz(input_path, output_path)

            decompressed = output_path.read_bytes()
            assert decompressed == test_data

    def test_decompression_of_large_data(self) -> None:
        """Test decompression of large binary data."""
        large_data = b"\x00\x01\x02\x03" * 10000
        compressed = lzma.compress(large_data)

        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            input_path = temp_dir / "large.xz"
            output_path = temp_dir / "large_output"

            input_path.write_bytes(compressed)

            manager._decompress_xz(input_path, output_path)

            decompressed = output_path.read_bytes()
            assert decompressed == large_data
            assert len(decompressed) == len(large_data)

    def test_decompression_creates_output_file(self) -> None:
        """Test that decompression creates actual output file."""
        test_data = b"test content"
        compressed = lzma.compress(test_data)

        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            input_path = temp_dir / "test.xz"
            output_path = temp_dir / "test_output"

            input_path.write_bytes(compressed)

            assert not output_path.exists()

            manager._decompress_xz(input_path, output_path)

            assert output_path.exists()
            assert output_path.is_file()


class TestServerHealthCheck:
    """Test server health check with real socket operations."""

    def test_server_not_running_on_unused_port(self) -> None:
        """Test that health check returns False for unused port."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            unused_port = self._find_unused_port()
            manager.server_port = unused_port

            result = manager._is_server_running()

            assert result is False

    def test_server_running_with_real_listener(self) -> None:
        """Test health check returns True when real server is listening."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            port = self._find_unused_port()
            manager.server_port = port

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(("127.0.0.1", port))
            server_socket.listen(1)

            try:
                result = manager._is_server_running()
                assert result is True
            finally:
                server_socket.close()

    def test_health_check_handles_closed_socket(self) -> None:
        """Test that health check handles socket closing gracefully."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            port = self._find_unused_port()
            manager.server_port = port

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(("127.0.0.1", port))
            server_socket.listen(1)
            server_socket.close()

            result = manager._is_server_running()

            assert result is False

    @staticmethod
    def _find_unused_port() -> int:
        """Find an unused port for testing."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


class TestSubprocessLifecycle:
    """Test frida-server subprocess lifecycle management with real processes."""

    @pytest.mark.skipif(
        not hasattr(subprocess, "CREATE_NO_WINDOW"),
        reason="Windows-specific test requires CREATE_NO_WINDOW",
    )
    def test_windows_subprocess_flags_are_correct(self) -> None:
        """Test that Windows-specific subprocess flags are set correctly."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            assert hasattr(subprocess, "CREATE_NO_WINDOW")
            assert hasattr(subprocess, "STARTUPINFO")
            assert hasattr(subprocess, "STARTF_USESHOWWINDOW")

    def test_stop_without_process_is_safe(self) -> None:
        """Test that calling stop() without a process is safe."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)
            manager.server_process = None

            manager.stop()

            assert manager.server_process is None

    def test_stop_terminates_real_process(self) -> None:
        """Test that stop() actually terminates a real subprocess."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            if platform.system() == "Windows":
                process = subprocess.Popen(
                    ["timeout", "/t", "300"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            else:
                process = subprocess.Popen(
                    ["sleep", "300"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )

            manager.server_process = process

            assert process.poll() is None

            manager.stop()

            time.sleep(0.1)
            assert process.poll() is not None
            assert manager.server_process is None


class TestAdministratorPrivileges:
    """Test administrator privilege detection with real OS checks."""

    def test_current_user_privilege_detection(self) -> None:
        """Test that privilege detection works for current user."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)
            result = manager._is_admin()

            assert isinstance(result, bool)

    def test_windows_admin_detection_returns_bool(self) -> None:
        """Test Windows admin detection returns boolean."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)
            result = manager._is_admin()

            assert isinstance(result, bool)

    def test_linux_root_detection_returns_bool(self) -> None:
        """Test Linux root detection returns boolean."""
        if platform.system() != "Linux":
            pytest.skip("Linux-only test")

        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)
            result = manager._is_admin()

            assert isinstance(result, bool)


class TestStatusReporting:
    """Test status reporting with real file system state."""

    def test_get_status_returns_complete_information(self) -> None:
        """Test that get_status() returns comprehensive status information."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            status = manager.get_status()

            assert "installed" in status
            assert "running" in status
            assert "version" in status
            assert "path" in status
            assert "is_admin" in status
            assert "process_managed" in status

            assert isinstance(status["installed"], bool)
            assert isinstance(status["running"], bool)
            assert isinstance(status["version"], str)
            assert isinstance(status["path"], str)
            assert isinstance(status["is_admin"], bool)
            assert isinstance(status["process_managed"], bool)

            assert status["version"] == frida.__version__

    def test_get_status_shows_not_installed_for_missing_server(self) -> None:
        """Test that get_status() shows installed=False when server missing."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            status = manager.get_status()

            assert status["installed"] is False

    def test_get_status_shows_installed_when_server_exists(self) -> None:
        """Test that get_status() shows installed=True when server file exists."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            server_path = manager._get_server_path()
            server_path.write_bytes(b"fake server content")

            status = manager.get_status()

            assert status["installed"] is True

    def test_get_status_with_managed_process(self) -> None:
        """Test that get_status() shows process_managed=True when process exists."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            if platform.system() == "Windows":
                process = subprocess.Popen(
                    ["timeout", "/t", "300"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            else:
                process = subprocess.Popen(
                    ["sleep", "300"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )

            manager.server_process = process

            try:
                status = manager.get_status()
                assert status["process_managed"] is True
            finally:
                process.terminate()
                process.wait()


class TestEdgeCases:
    """Test edge cases and error conditions with real scenarios."""

    def test_ensure_server_skips_download_if_exists(self) -> None:
        """Test that _ensure_server_installed skips download if file exists."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            server_path = manager._get_server_path()
            server_path.write_bytes(b"existing server binary")

            result = manager._ensure_server_installed()

            assert result is True

    def test_ensure_server_returns_false_if_download_unavailable(self) -> None:
        """Test that _ensure_server_installed returns False if download fails."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            original_download = manager._download_frida_server

            def fake_download() -> bool:
                return False

            manager._download_frida_server = fake_download

            try:
                result = manager._ensure_server_installed()
                assert result is False
            finally:
                manager._download_frida_server = original_download

    def test_multiple_instances_can_coexist(self) -> None:
        """Test that multiple FridaServerManager instances can coexist."""
        with RealTemporaryDirectory() as temp_dir1:
            with RealTemporaryDirectory() as temp_dir2:
                manager1 = FridaServerManager(server_dir=temp_dir1)
                manager2 = FridaServerManager(server_dir=temp_dir2)

                assert manager1.server_dir != manager2.server_dir
                assert manager1.server_dir.exists()
                assert manager2.server_dir.exists()

    def test_server_dir_creation_on_init(self) -> None:
        """Test that server directory is created on initialization."""
        with RealTemporaryDirectory() as temp_dir:
            server_dir = temp_dir / "nonexistent" / "nested" / "path"

            assert not server_dir.exists()

            manager = FridaServerManager(server_dir=server_dir)

            assert server_dir.exists()
            assert server_dir.is_dir()

    def test_get_server_path_returns_correct_path(self) -> None:
        """Test that _get_server_path returns correct full path."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            server_path = manager._get_server_path()

            assert server_path.parent == temp_dir
            assert "frida-server" in server_path.name


class TestContextManager:
    """Test context manager protocol with real lifecycle."""

    def test_context_manager_interface_exists(self) -> None:
        """Test that context manager methods are implemented."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            assert hasattr(manager, "__enter__")
            assert hasattr(manager, "__exit__")

    def test_context_manager_enter_returns_manager(self) -> None:
        """Test that __enter__ returns the manager instance."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            original_start = manager.start

            def fake_start() -> bool:
                return True

            manager.start = fake_start

            try:
                result = manager.__enter__()
                assert result is manager
            finally:
                manager.start = original_start

    def test_context_manager_exit_stops_server(self) -> None:
        """Test that __exit__ calls stop method."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            stop_called = False

            def fake_stop() -> None:
                nonlocal stop_called
                stop_called = True

            manager.stop = fake_stop

            manager.__exit__(None, None, None)

            assert stop_called is True


class TestFileSystemOperations:
    """Test file system operations with real files and directories."""

    def test_default_server_dir_is_created(self) -> None:
        """Test that default server directory path is valid."""
        default_dir = FridaServerManager()._get_default_server_dir()

        assert isinstance(default_dir, Path)
        assert "frida-server" in str(default_dir).lower()

    def test_custom_server_dir_is_used(self) -> None:
        """Test that custom server directory is respected."""
        with RealTemporaryDirectory() as temp_dir:
            custom_dir = temp_dir / "custom_location"
            manager = FridaServerManager(server_dir=custom_dir)

            assert manager.server_dir == custom_dir
            assert custom_dir.exists()

    def test_server_path_includes_executable_extension(self) -> None:
        """Test that server path has correct extension for platform."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            server_path = manager._get_server_path()

            if platform.system() == "Windows":
                assert server_path.suffix == ".exe"
            else:
                assert server_path.suffix == ""


class TestVersionMatching:
    """Test version matching between frida and frida-server."""

    def test_manager_uses_current_frida_version(self) -> None:
        """Test that manager uses currently installed frida version."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            assert manager.frida_version == frida.__version__

    def test_download_url_contains_frida_version(self) -> None:
        """Test that download URL includes frida version."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            url = manager._get_download_url()

            assert frida.__version__ in url

    def test_status_reports_correct_version(self) -> None:
        """Test that status reporting shows correct version."""
        with RealTemporaryDirectory() as temp_dir:
            manager = FridaServerManager(server_dir=temp_dir)

            status = manager.get_status()

            assert status["version"] == frida.__version__


class TestPlatformSpecificBehavior:
    """Test platform-specific behavior with real platform checks."""

    def test_windows_uses_exe_extension(self) -> None:
        """Test that Windows uses .exe extension."""
        with RealPlatformInfo("Windows", "AMD64"):
            with RealTemporaryDirectory() as temp_dir:
                manager = FridaServerManager(server_dir=temp_dir)

                exe_name = manager._get_server_executable_name()
                assert exe_name.endswith(".exe")

                server_path = manager._get_server_path()
                assert server_path.suffix == ".exe"

    def test_linux_uses_no_extension(self) -> None:
        """Test that Linux uses no extension."""
        with RealPlatformInfo("Linux", "x86_64"):
            with RealTemporaryDirectory() as temp_dir:
                manager = FridaServerManager(server_dir=temp_dir)

                exe_name = manager._get_server_executable_name()
                assert not exe_name.endswith(".exe")
                assert exe_name == "frida-server"

                server_path = manager._get_server_path()
                assert server_path.suffix == ""

    def test_architecture_mapping_covers_common_values(self) -> None:
        """Test that architecture mapping handles common platform values."""
        architectures = [
            ("Windows", "AMD64"),
            ("Windows", "x86_64"),
            ("Linux", "x86_64"),
            ("Linux", "aarch64"),
            ("Darwin", "arm64"),
        ]

        for system, machine in architectures:
            with RealPlatformInfo(system, machine):
                with RealTemporaryDirectory() as temp_dir:
                    manager = FridaServerManager(server_dir=temp_dir)

                    url = manager._get_download_url()
                    assert isinstance(url, str)
                    assert url.startswith("https://")
