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

import io
import lzma
import os
import socket
from pathlib import Path
from unittest import mock as test_doubles

import pytest
import requests

from intellicrack.core.monitoring.frida_server_manager import FridaServerManager

Mock = test_doubles.Mock
PropertyMock = test_doubles.PropertyMock
call = test_doubles.call
mock_open = test_doubles.mock_open
patch = test_doubles.patch

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


class TestPlatformDetection:
    """Test platform and architecture detection across operating systems."""

    @patch("platform.system")
    @patch("platform.machine")
    def test_windows_x64_detection(self, mock_machine, mock_system):
        """Test Windows x64 platform detection generates correct download URL."""
        mock_system.return_value = "Windows"
        mock_machine.return_value = "AMD64"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            url = manager._get_download_url()

            assert "windows-x86_64" in url
            assert "16.1.4" in url
            assert url.endswith(".exe.xz")

    @patch("platform.system")
    @patch("platform.machine")
    def test_windows_x86_detection(self, mock_machine, mock_system):
        """Test Windows x86 (32-bit) platform detection generates correct URL."""
        mock_system.return_value = "Windows"
        mock_machine.return_value = "i686"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            url = manager._get_download_url()

            assert "windows-x86" in url
            assert "16.1.4" in url

    @patch("platform.system")
    @patch("platform.machine")
    def test_linux_x64_detection(self, mock_machine, mock_system):
        """Test Linux x64 platform detection generates correct download URL."""
        mock_system.return_value = "Linux"
        mock_machine.return_value = "x86_64"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            url = manager._get_download_url()

            assert "linux-x86_64" in url
            assert "16.1.4" in url
            assert not url.endswith(".exe.xz")

    @patch("platform.system")
    @patch("platform.machine")
    def test_linux_arm64_detection(self, mock_machine, mock_system):
        """Test Linux ARM64 platform detection generates correct download URL."""
        mock_system.return_value = "Linux"
        mock_machine.return_value = "aarch64"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            url = manager._get_download_url()

            assert "linux-arm64" in url

    @patch("platform.system")
    @patch("platform.machine")
    def test_macos_arm64_detection(self, mock_machine, mock_system):
        """Test macOS ARM64 (Apple Silicon) platform detection."""
        mock_system.return_value = "Darwin"
        mock_machine.return_value = "arm64"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            url = manager._get_download_url()

            assert "macos-arm64" in url

    @patch("platform.system")
    @patch("platform.machine")
    def test_unsupported_architecture_raises_error(self, mock_machine, mock_system):
        """Test that unsupported architecture raises ValueError with clear message."""
        mock_system.return_value = "Linux"
        mock_machine.return_value = "mips64"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with pytest.raises(ValueError, match="Unsupported architecture"):
                manager._get_download_url()

    @patch("platform.system")
    @patch("platform.machine")
    def test_unsupported_platform_raises_error(self, mock_machine, mock_system):
        """Test that unsupported platform raises ValueError."""
        mock_system.return_value = "FreeBSD"
        mock_machine.return_value = "x86_64"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with pytest.raises(ValueError, match="Unsupported platform"):
                manager._get_download_url()


class TestExecutableName:
    """Test executable name generation for different platforms."""

    @patch("platform.system")
    def test_windows_executable_has_exe_extension(self, mock_system):
        """Test Windows executable name includes .exe extension."""
        mock_system.return_value = "Windows"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            name = manager._get_server_executable_name()

            assert name == "frida-server.exe"

    @patch("platform.system")
    def test_linux_executable_no_extension(self, mock_system):
        """Test Linux executable name has no extension."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            name = manager._get_server_executable_name()

            assert name == "frida-server"


class TestDownloadFunctionality:
    """Test frida-server download with real-world network scenarios."""

    @patch("platform.system")
    @patch("requests.get")
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.chmod")
    def test_successful_download_and_decompression(
        self, mock_chmod, mock_file, mock_get, mock_system
    ):
        """Test successful download, decompression, and chmod on Linux."""
        mock_system.return_value = "Linux"

        compressed_data = lzma.compress(REALISTIC_ELF_BINARY)
        mock_response = Mock()
        mock_response.iter_content.return_value = [compressed_data]
        mock_get.return_value = mock_response

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch.object(manager, "_decompress_xz") as mock_decompress:
                with patch.object(Path, "unlink"):
                    result = manager._download_frida_server()

                    assert result is True
                    mock_get.assert_called_once()
                    mock_decompress.assert_called_once()
                    mock_chmod.assert_called_once()

    @patch("platform.system")
    @patch("requests.get")
    def test_download_network_timeout(self, mock_get, mock_system):
        """Test that network timeout during download is handled gracefully."""
        mock_system.return_value = "Windows"
        mock_get.side_effect = requests.Timeout("Connection timeout")

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            result = manager._download_frida_server()

            assert result is False

    @patch("platform.system")
    @patch("requests.get")
    def test_download_http_error(self, mock_get, mock_system):
        """Test that HTTP errors (404, 500) during download are handled."""
        mock_system.return_value = "Windows"
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("404 Not Found")
        mock_get.return_value = mock_response

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            result = manager._download_frida_server()

            assert result is False

    @patch("platform.system")
    @patch("requests.get")
    def test_download_connection_error(self, mock_get, mock_system):
        """Test that connection errors (no internet) are handled."""
        mock_system.return_value = "Windows"
        mock_get.side_effect = requests.ConnectionError("No internet connection")

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            result = manager._download_frida_server()

            assert result is False


class TestDecompression:
    """Test XZ decompression functionality."""

    def test_successful_decompression(self):
        """Test successful decompression of .xz file."""
        test_data = b"frida-server binary content"
        compressed = lzma.compress(test_data)

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch("builtins.open", mock_open(read_data=compressed)):
                with patch("lzma.open") as mock_lzma:
                    mock_lzma.return_value.__enter__.return_value.read.return_value = (
                        test_data
                    )

                    manager._decompress_xz(Path("input.xz"), Path("output"))

                    mock_lzma.assert_called_once()

    def test_decompression_without_lzma_module(self):
        """Test that missing lzma module raises RuntimeError with clear message."""
        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch("builtins.open", mock_open()):
                with patch.dict("sys.modules", {"lzma": None}):
                    import sys

                    old_lzma = sys.modules.get("lzma")
                    sys.modules["lzma"] = None

                    try:
                        with pytest.raises(
                            RuntimeError, match="lzma module not available"
                        ):
                            manager._decompress_xz(Path("input.xz"), Path("output"))
                    finally:
                        if old_lzma:
                            sys.modules["lzma"] = old_lzma


class TestServerHealthCheck:
    """Test server health check and responsiveness detection."""

    @patch("socket.socket")
    def test_server_running_returns_true(self, mock_socket_class):
        """Test that health check returns True when server is responsive."""
        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_socket

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            result = manager._is_server_running()

            assert result is True
            mock_socket.connect_ex.assert_called_once_with(("127.0.0.1", 27042))
            mock_socket.close.assert_called_once()

    @patch("socket.socket")
    def test_server_not_running_returns_false(self, mock_socket_class):
        """Test that health check returns False when server is not responsive."""
        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 1
        mock_socket_class.return_value = mock_socket

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            result = manager._is_server_running()

            assert result is False

    @patch("socket.socket")
    def test_health_check_handles_socket_exception(self, mock_socket_class):
        """Test that socket exceptions during health check are handled gracefully."""
        mock_socket_class.side_effect = socket.error("Socket error")

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            result = manager._is_server_running()

            assert result is False


class TestSubprocessLifecycle:
    """Test frida-server subprocess lifecycle management."""

    @patch("platform.system")
    @patch("subprocess.Popen")
    @patch("time.sleep")
    def test_windows_subprocess_starts_with_correct_flags(
        self, mock_sleep, mock_popen, mock_system
    ):
        """Test that Windows subprocess starts with CREATE_NO_WINDOW flag."""
        mock_system.return_value = "Windows"
        mock_process = Mock()
        mock_popen.return_value = mock_process

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch.object(manager, "_ensure_server_installed", return_value=True):
                with patch.object(manager, "_is_admin", return_value=True):
                    with patch.object(manager, "_is_server_running") as mock_running:
                        mock_running.side_effect = [False, True]

                        result = manager.start()

                        assert result is True
                        mock_popen.assert_called_once()

                        call_kwargs = mock_popen.call_args[1]
                        assert "startupinfo" in call_kwargs
                        assert "creationflags" in call_kwargs

    @patch("platform.system")
    @patch("subprocess.Popen")
    @patch("time.sleep")
    def test_linux_subprocess_starts_without_windows_flags(
        self, mock_sleep, mock_popen, mock_system
    ):
        """Test that Linux subprocess starts without Windows-specific flags."""
        mock_system.return_value = "Linux"
        mock_process = Mock()
        mock_popen.return_value = mock_process

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch.object(manager, "_ensure_server_installed", return_value=True):
                with patch.object(manager, "_is_admin", return_value=True):
                    with patch.object(manager, "_is_server_running") as mock_running:
                        mock_running.side_effect = [False, True]

                        result = manager.start()

                        assert result is True
                        call_kwargs = mock_popen.call_args[1]
                        assert "startupinfo" not in call_kwargs
                        assert "creationflags" not in call_kwargs

    @patch("platform.system")
    def test_start_fails_if_server_never_responds(self, mock_system):
        """Test that start() returns False if server doesn't respond after 10 attempts."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch.object(manager, "_ensure_server_installed", return_value=True):
                with patch.object(manager, "_is_admin", return_value=True):
                    with patch.object(
                        manager, "_is_server_running", return_value=False
                    ):
                        with patch("subprocess.Popen"):
                            with patch("time.sleep"):
                                result = manager.start()

                                assert result is False

    @patch("platform.system")
    def test_stop_terminates_process_gracefully(self, mock_system):
        """Test that stop() terminates process with timeout and cleanup."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            mock_process = Mock()
            mock_process.wait.return_value = None
            manager.server_process = mock_process

            manager.stop()

            mock_process.terminate.assert_called_once()
            mock_process.wait.assert_called_once_with(timeout=5.0)
            assert manager.server_process is None

    @patch("platform.system")
    def test_stop_kills_process_if_terminate_times_out(self, mock_system):
        """Test that stop() kills process if terminate times out."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            mock_process = Mock()
            import subprocess

            mock_process.wait.side_effect = [
                subprocess.TimeoutExpired("cmd", 5),
                None,
            ]
            manager.server_process = mock_process

            manager.stop()

            mock_process.terminate.assert_called_once()
            mock_process.kill.assert_called_once()
            assert mock_process.wait.call_count == 2

    @patch("platform.system")
    def test_start_skips_if_already_running(self, mock_system):
        """Test that start() skips startup if server is already running."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch.object(manager, "_is_server_running", return_value=True):
                result = manager.start()

                assert result is True


class TestAdministratorPrivileges:
    """Test administrator privilege detection across platforms."""

    @patch("platform.system")
    @patch("ctypes.windll")
    def test_windows_admin_detection_true(self, mock_windll, mock_system):
        """Test Windows admin detection returns True when admin."""
        mock_system.return_value = "Windows"
        mock_windll.shell32.IsUserAnAdmin.return_value = 1

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            result = manager._is_admin()

            assert result is True

    @patch("platform.system")
    @patch("ctypes.windll")
    def test_windows_admin_detection_false(self, mock_windll, mock_system):
        """Test Windows admin detection returns False when not admin."""
        mock_system.return_value = "Windows"
        mock_windll.shell32.IsUserAnAdmin.return_value = 0

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            result = manager._is_admin()

            assert result is False

    @patch("platform.system")
    def test_linux_root_detection_true(self, mock_system):
        """Test Linux root detection returns True when UID is 0."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch("os.geteuid", return_value=0):
                result = manager._is_admin()
                assert result is True

    @patch("platform.system")
    def test_linux_root_detection_false(self, mock_system):
        """Test Linux root detection returns False when UID is not 0."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch("os.geteuid", return_value=1000):
                result = manager._is_admin()
                assert result is False

    @patch("platform.system")
    @patch("ctypes.windll")
    def test_admin_detection_handles_exceptions(self, mock_windll, mock_system):
        """Test that admin detection handles exceptions gracefully."""
        mock_system.return_value = "Windows"
        mock_windll.shell32.IsUserAnAdmin.side_effect = Exception("ctypes error")

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            result = manager._is_admin()

            assert result is False


class TestStatusReporting:
    """Test status reporting and introspection."""

    @patch("platform.system")
    def test_get_status_returns_complete_information(self, mock_system):
        """Test that get_status() returns comprehensive status information."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch.object(Path, "exists", return_value=True):
                with patch.object(manager, "_is_server_running", return_value=True):
                    with patch.object(manager, "_is_admin", return_value=False):
                        status = manager.get_status()

                        assert status["installed"] is True
                        assert status["running"] is True
                        assert status["version"] == "16.1.4"
                        assert status["is_admin"] is False
                        assert "path" in status
                        assert status["process_managed"] is False

    @patch("platform.system")
    def test_get_status_with_managed_process(self, mock_system):
        """Test that get_status() shows process_managed=True when process exists."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            manager.server_process = Mock()

            with patch.object(Path, "exists", return_value=True):
                with patch.object(manager, "_is_server_running", return_value=True):
                    with patch.object(manager, "_is_admin", return_value=True):
                        status = manager.get_status()

                        assert status["process_managed"] is True


class TestEdgeCases:
    """Test edge cases and error conditions."""

    @patch("platform.system")
    def test_ensure_server_downloads_if_missing(self, mock_system):
        """Test that _ensure_server_installed triggers download if file missing."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch.object(Path, "exists", return_value=False):
                with patch.object(
                    manager, "_download_frida_server", return_value=True
                ) as mock_download:
                    result = manager._ensure_server_installed()

                    assert result is True
                    mock_download.assert_called_once()

    @patch("platform.system")
    def test_ensure_server_skips_download_if_exists(self, mock_system):
        """Test that _ensure_server_installed skips download if file exists."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch.object(Path, "exists", return_value=True):
                with patch.object(
                    manager, "_download_frida_server"
                ) as mock_download:
                    result = manager._ensure_server_installed()

                    assert result is True
                    mock_download.assert_not_called()

    @patch("platform.system")
    def test_start_fails_if_download_fails(self, mock_system):
        """Test that start() returns False if download fails."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch.object(manager, "_ensure_server_installed", return_value=False):
                result = manager.start()

                assert result is False

    @patch("platform.system")
    def test_multiple_starts_are_idempotent(self, mock_system):
        """Test that calling start() multiple times is safe."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch.object(manager, "_is_server_running", return_value=True):
                result1 = manager.start()
                result2 = manager.start()
                result3 = manager.start()

                assert result1 is True
                assert result2 is True
                assert result3 is True

    @patch("platform.system")
    def test_stop_without_process_is_safe(self, mock_system):
        """Test that calling stop() without a process is safe."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()
            manager.server_process = None

            manager.stop()


class TestContextManager:
    """Test context manager protocol."""

    @patch("platform.system")
    def test_context_manager_starts_and_stops(self, mock_system):
        """Test that context manager properly starts and stops server."""
        mock_system.return_value = "Linux"

        with patch("frida.__version__", "16.1.4"):
            manager = FridaServerManager()

            with patch.object(manager, "start", return_value=True) as mock_start:
                with patch.object(manager, "stop") as mock_stop:
                    with manager:
                        pass

                    mock_start.assert_called_once()
                    mock_stop.assert_called_once()
