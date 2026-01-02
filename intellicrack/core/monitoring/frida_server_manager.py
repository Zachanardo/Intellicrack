"""Frida Server Lifecycle Manager.

Automatically downloads, starts, and manages frida-server for process monitoring.
Handles version matching, subprocess lifecycle, and health checks.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import ctypes
import logging
import os
import platform
import socket
import subprocess
import time
from pathlib import Path
from types import TracebackType

import frida
import requests


logger = logging.getLogger(__name__)


class FridaServerManager:
    """Automatic frida-server lifecycle management.

    Downloads frida-server matching installed frida version, manages subprocess,
    and performs health checks before allowing monitoring to proceed.
    """

    def __init__(self, server_dir: Path | None = None) -> None:
        """Initialize frida server manager.

        Args:
            server_dir: Directory to store frida-server (defaults to user data dir).

        """
        self.server_dir = server_dir or self._get_default_server_dir()
        self.server_dir.mkdir(parents=True, exist_ok=True)

        self.frida_version = frida.__version__
        self.server_process: subprocess.Popen[bytes] | None = None
        self.server_port = 27042

        self._platform = platform.system().lower()
        self._machine = platform.machine().lower()

    def _get_default_server_dir(self) -> Path:
        """Get default directory for frida-server storage.

        Returns:
            Path to frida-server storage directory.

        """
        if platform.system() == "Windows":
            base_dir = Path(os.getenv("LOCALAPPDATA", "")) or Path.home() / "AppData" / "Local"
        else:
            base_dir = Path.home() / ".local" / "share"

        return base_dir / "Intellicrack" / "frida-server"

    def _get_server_executable_name(self) -> str:
        """Get platform-specific frida-server executable name.

        Returns:
            Executable filename.

        """
        return "frida-server.exe" if self._platform == "windows" else "frida-server"

    def _get_server_path(self) -> Path:
        """Get full path to frida-server executable.

        Returns:
            Path to frida-server executable.

        """
        return self.server_dir / self._get_server_executable_name()

    def _get_download_url(self) -> str:
        """Get download URL for frida-server matching installed version.

        Returns:
            Download URL for frida-server release.

        Raises:
            ValueError: If platform/architecture combination is unsupported.

        """
        arch_map = {
            "amd64": "x86_64",
            "x86_64": "x86_64",
            "x86": "x86",
            "i386": "x86",
            "i686": "x86",
            "arm64": "arm64",
            "aarch64": "arm64",
        }

        arch = arch_map.get(self._machine.lower())
        if not arch:
            raise ValueError(f"Unsupported architecture: {self._machine}")

        if self._platform == "windows":
            filename = f"frida-server-{self.frida_version}-windows-{arch}.exe.xz"
        elif self._platform == "linux":
            filename = f"frida-server-{self.frida_version}-linux-{arch}.xz"
        elif self._platform == "darwin":
            filename = f"frida-server-{self.frida_version}-macos-{arch}.xz"
        else:
            raise ValueError(f"Unsupported platform: {self._platform}")

        return f"https://github.com/frida/frida/releases/download/{self.frida_version}/{filename}"

    def _is_admin(self) -> bool:
        """Check if running with administrator privileges.

        Returns:
            True if running as admin.

        """
        try:
            if self._platform == "windows":
                result = ctypes.windll.shell32.IsUserAnAdmin()
                return bool(result != 0)
            geteuid = getattr(os, "geteuid", None)
            if geteuid is not None:
                uid_result = geteuid()
                return bool(uid_result == 0)
            return False
        except Exception:
            return False

    def _download_frida_server(self) -> bool:
        """Download frida-server matching installed frida version.

        Returns:
            True if download successful.

        """
        try:
            url = self._get_download_url()
            logger.info("Downloading frida-server %s...", self.frida_version)
            logger.info("URL: %s", url)

            response = requests.get(url, timeout=60, stream=True)
            response.raise_for_status()

            compressed_path = self.server_dir / "frida-server.xz"

            with open(compressed_path, "wb") as f:
                import shutil

                shutil.copyfileobj(response.raw, f)

            logger.info("Decompressing frida-server...")
            self._decompress_xz(compressed_path, self._get_server_path())

            compressed_path.unlink()

            if self._platform != "windows":
                Path(self._get_server_path()).chmod(0o700)

            logger.info("Download complete!")
            return True

        except Exception as e:
            logger.exception("Download failed: %s", e)
            return False

    def _decompress_xz(self, input_path: Path, output_path: Path) -> None:
        """Decompress .xz file.

        Args:
            input_path: Path to compressed file.
            output_path: Path for decompressed output.

        Raises:
            RuntimeError: If lzma module is not available.

        """
        try:
            import lzma

            with lzma.open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
                f_out.write(f_in.read())
        except ImportError:
            raise RuntimeError("lzma module not available - cannot decompress frida-server") from None

    def _ensure_server_installed(self) -> bool:
        """Ensure frida-server is installed and available.

        Returns:
            True if server is available.

        """
        server_path = self._get_server_path()

        if server_path.exists():
            return True

        logger.info("frida-server not found, downloading...")
        return self._download_frida_server()

    def _is_server_running(self) -> bool:
        """Check if frida-server is running and responding.

        Returns:
            True if server is healthy.

        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex(("127.0.0.1", self.server_port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def start(self) -> bool:
        """Start frida-server if not already running.

        Returns:
            True if server started successfully or already running.

        """
        if self._is_server_running():
            logger.info("frida-server already running")
            return True

        if not self._ensure_server_installed():
            logger.exception("Failed to install frida-server")
            return False

        if not self._is_admin():
            logger.warning("Not running as administrator")
            logger.warning("Frida may have limited capabilities")

        try:
            server_path = self._get_server_path()
            logger.info("Starting frida-server from %s...", server_path)

            if self._platform == "windows":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = 0

                self.server_process = subprocess.Popen(
                    [str(server_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            else:
                self.server_process = subprocess.Popen([str(server_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            for _attempt in range(10):
                time.sleep(0.5)
                if self._is_server_running():
                    logger.info("frida-server started successfully!")
                    return True

            logger.warning("frida-server process started but not responding")
            return False

        except Exception as e:
            logger.exception("Failed to start frida-server: %s", e)
            return False

    def stop(self) -> None:
        """Stop frida-server if managed by this instance."""
        if self.server_process:
            try:
                self.server_process.terminate()
                try:
                    self.server_process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    self.server_process.kill()
                    self.server_process.wait()

                logger.info("frida-server stopped")
            except Exception as e:
                logger.exception("Error stopping frida-server: %s", e)
            finally:
                self.server_process = None

    def get_status(self) -> dict[str, bool | str]:
        """Get current frida-server status.

        Returns:
            Dictionary with status information.

        """
        return {
            "installed": self._get_server_path().exists(),
            "running": self._is_server_running(),
            "version": self.frida_version,
            "path": str(self._get_server_path()),
            "is_admin": self._is_admin(),
            "process_managed": self.server_process is not None,
        }

    def __enter__(self) -> "FridaServerManager":
        """Context manager entry.

        Returns:
            The FridaServerManager instance.

        """
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager exit.

        Args:
            exc_type: Exception type if an exception occurred.
            exc_val: Exception instance if an exception occurred.
            exc_tb: Exception traceback if an exception occurred.

        """
        self.stop()
