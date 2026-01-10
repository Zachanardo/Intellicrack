"""Tool installer and detector for Intellicrack.

This module handles automatic detection, downloading, and installation
of reverse engineering tools required by the platform.
"""

import asyncio
import hashlib
import os
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from ..core.logging import get_logger
from ..core.types import ToolError, ToolName

_logger = get_logger("bridges.installer")


@dataclass
class ToolInfo:
    """Information about a tool.

    Attributes:
        name: Tool name enum.
        display_name: Human-readable name.
        common_paths: Common installation paths to check.
        executables: Expected executable names.
        download_url: URL pattern for downloading.
        version_command: Command to get version.
        min_version: Minimum required version.
    """

    name: ToolName
    display_name: str
    common_paths: list[Path] = field(default_factory=list)
    executables: list[str] = field(default_factory=list)
    download_url: str = ""
    version_command: list[str] = field(default_factory=list)
    min_version: str = ""


@dataclass
class ToolVersion:
    """Parsed tool version.

    Attributes:
        major: Major version number.
        minor: Minor version number.
        patch: Patch version number.
        raw: Raw version string.
    """

    major: int = 0
    minor: int = 0
    patch: int = 0
    raw: str = ""

    def __str__(self) -> str:
        """Get string representation.

        Returns:
            Version string in major.minor.patch format.
        """
        return f"{self.major}.{self.minor}.{self.patch}"

    def __ge__(self, other: "ToolVersion") -> bool:
        """Compare versions.

        Args:
            other: Version to compare against.

        Returns:
            True if this version is greater or equal.
        """
        if self.major != other.major:
            return self.major >= other.major
        if self.minor != other.minor:
            return self.minor >= other.minor
        return self.patch >= other.patch


@dataclass
class InstallResult:
    """Result of tool installation.

    Attributes:
        success: Whether installation succeeded.
        path: Path to installed tool.
        version: Installed version.
        error: Error message if failed.
    """

    success: bool
    path: Path | None = None
    version: ToolVersion | None = None
    error: str | None = None


TOOL_REGISTRY: dict[ToolName, ToolInfo] = {
    ToolName.GHIDRA: ToolInfo(
        name=ToolName.GHIDRA,
        display_name="Ghidra",
        common_paths=[
            Path("C:/Program Files/ghidra"),
            Path("C:/Tools/ghidra"),
            Path("C:/ghidra"),
            Path("D:/Tools/ghidra"),
            Path(os.path.expanduser("~/ghidra")),
        ],
        executables=["ghidraRun.bat", "ghidraRun"],
        download_url="https://github.com/NationalSecurityAgency/ghidra/releases/latest",
        version_command=["ghidraRun.bat", "--version"],
        min_version="11.0",
    ),
    ToolName.X64DBG: ToolInfo(
        name=ToolName.X64DBG,
        display_name="x64dbg",
        common_paths=[
            Path("C:/Program Files/x64dbg"),
            Path("C:/Tools/x64dbg"),
            Path("C:/x64dbg"),
            Path("D:/Tools/x64dbg"),
        ],
        executables=["x64dbg.exe", "x96dbg.exe"],
        download_url="https://github.com/x64dbg/x64dbg/releases/latest",
        version_command=["x64dbg.exe", "-v"],
        min_version="2024.01.01",
    ),
    ToolName.RADARE2: ToolInfo(
        name=ToolName.RADARE2,
        display_name="radare2",
        common_paths=[
            Path("C:/Program Files/radare2"),
            Path("C:/Tools/radare2"),
            Path("C:/radare2"),
            Path("D:/Tools/radare2"),
        ],
        executables=["radare2.exe", "r2.exe"],
        download_url="https://github.com/radareorg/radare2/releases/latest",
        version_command=["radare2.exe", "-v"],
        min_version="5.9.0",
    ),
    ToolName.FRIDA: ToolInfo(
        name=ToolName.FRIDA,
        display_name="Frida",
        common_paths=[],
        executables=[],
        download_url="",
        version_command=["python", "-c", "import frida; print(frida.__version__)"],
        min_version="16.0.0",
    ),
    ToolName.PROCESS: ToolInfo(
        name=ToolName.PROCESS,
        display_name="Process Control",
        common_paths=[],
        executables=[],
        download_url="",
        version_command=[],
        min_version="",
    ),
    ToolName.BINARY: ToolInfo(
        name=ToolName.BINARY,
        display_name="Binary Operations",
        common_paths=[],
        executables=[],
        download_url="",
        version_command=[],
        min_version="",
    ),
}


class ToolInstaller:
    """Handles automatic tool detection and installation.

    Attributes:
        tools_directory: Base directory for tool installations.
        _http_client: HTTP client for downloads.
    """

    def __init__(self, tools_directory: Path) -> None:
        """Initialize the tool installer.

        Args:
            tools_directory: Directory where tools should be installed.
        """
        self.tools_directory = tools_directory
        self._http_client: httpx.AsyncClient | None = None

        self.tools_directory.mkdir(parents=True, exist_ok=True)

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client.

        Returns:
            Async HTTP client instance.
        """
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0),
                follow_redirects=True,
            )
        return self._http_client

    async def close(self) -> None:
        """Close HTTP client and cleanup resources."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def find_tool(self, tool: ToolName) -> Path | None:
        """Find an installed tool.

        Searches common installation paths first, then PATH,
        then the tools directory.

        Args:
            tool: The tool to find.

        Returns:
            Path to tool installation or None if not found.
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            _logger.warning("Unknown tool: %s", tool)
            return None

        if tool == ToolName.FRIDA:
            return await self._find_frida()

        if tool in (ToolName.PROCESS, ToolName.BINARY):
            return Path("builtin")

        for common_path in tool_info.common_paths:
            if common_path.exists():
                for exe in tool_info.executables:
                    exe_path = common_path / exe
                    if exe_path.exists():
                        _logger.info("Found %s at %s", tool_info.display_name, exe_path)
                        return common_path

        for exe in tool_info.executables:
            found = shutil.which(exe)
            if found is not None:
                found_path = Path(found).parent
                _logger.info("Found %s in PATH at %s", tool_info.display_name, found_path)
                return found_path

        tool_dir = self.tools_directory / tool.value
        if tool_dir.exists():
            for exe in tool_info.executables:
                exe_path = tool_dir / exe
                if exe_path.exists():
                    _logger.info(
                        "Found %s in tools directory at %s",
                        tool_info.display_name,
                        tool_dir,
                    )
                    return tool_dir

                for subdir in tool_dir.iterdir():
                    if subdir.is_dir():
                        exe_path = subdir / exe
                        if exe_path.exists():
                            _logger.info(
                                "Found %s at %s",
                                tool_info.display_name,
                                subdir,
                            )
                            return subdir

        _logger.debug("Tool %s not found", tool_info.display_name)
        return None

    async def _find_frida(self) -> Path | None:
        """Check if Frida Python package is installed.

        Returns:
            Path indicating Frida is installed, or None.
        """
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["python", "-c", "import frida; print(frida.__version__)"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                _logger.info("Frida is installed: version %s", result.stdout.strip())
                return Path("frida-python")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            _logger.debug("Frida check failed: %s", e)
        return None

    async def get_version(self, tool: ToolName, path: Path) -> ToolVersion | None:
        """Get the version of an installed tool.

        Args:
            tool: The tool to check.
            path: Path to the tool installation.

        Returns:
            Parsed version or None if couldn't determine.
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None or not tool_info.version_command:
            return None

        try:
            cmd = list(tool_info.version_command)

            if tool == ToolName.FRIDA:
                result = await asyncio.to_thread(
                    subprocess.run,
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            else:
                if path != Path("builtin"):
                    exe = path / cmd[0]
                    if exe.exists():
                        cmd[0] = str(exe)

                result = await asyncio.to_thread(
                    subprocess.run,
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=str(path) if path.is_dir() else None,
                )

            if result.returncode == 0:
                version_str = result.stdout.strip()
                return self._parse_version(version_str)

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            _logger.debug("Version check failed for %s: %s", tool, e)

        return None

    def _parse_version(self, version_str: str) -> ToolVersion:
        """Parse a version string.

        Args:
            version_str: Raw version string.

        Returns:
            Parsed ToolVersion.
        """
        import re

        version = ToolVersion(raw=version_str)

        match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version_str)
        if match:
            version.major = int(match.group(1))
            version.minor = int(match.group(2))
            if match.group(3):
                version.patch = int(match.group(3))

        return version

    async def verify_tool(self, tool: ToolName, path: Path) -> bool:
        """Verify a tool installation is valid.

        Args:
            tool: The tool to verify.
            path: Path to installation.

        Returns:
            True if installation is valid and meets minimum version.
        """
        if tool in (ToolName.PROCESS, ToolName.BINARY):
            return True

        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            return False

        if tool == ToolName.FRIDA:
            return path == Path("frida-python")

        for exe in tool_info.executables:
            exe_path = path / exe
            if exe_path.exists():
                version = await self.get_version(tool, path)
                if version is not None and tool_info.min_version:
                    min_ver = self._parse_version(tool_info.min_version)
                    if version >= min_ver:
                        return True
                    _logger.warning(
                        "%s version %s is below minimum %s",
                        tool_info.display_name,
                        version,
                        tool_info.min_version,
                    )
                    return False
                return True

        return False

    async def install_tool(self, tool: ToolName) -> InstallResult:
        """Download and install a tool.

        Args:
            tool: The tool to install.

        Returns:
            InstallResult with installation status.
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            return InstallResult(success=False, error=f"Unknown tool: {tool}")

        if tool == ToolName.FRIDA:
            return await self._install_frida()

        if tool in (ToolName.PROCESS, ToolName.BINARY):
            return InstallResult(success=True, path=Path("builtin"))

        if not tool_info.download_url:
            return InstallResult(
                success=False,
                error=f"No download URL configured for {tool_info.display_name}",
            )

        try:
            _logger.info("Installing %s...", tool_info.display_name)

            download_url = await self._get_latest_release_url(tool)
            if download_url is None:
                return InstallResult(
                    success=False,
                    error=f"Could not find download URL for {tool_info.display_name}",
                )

            download_path = await self._download_file(download_url)
            if download_path is None:
                return InstallResult(
                    success=False,
                    error=f"Download failed for {tool_info.display_name}",
                )

            install_path = await self._extract_archive(download_path, tool)

            download_path.unlink(missing_ok=True)

            version = await self.get_version(tool, install_path)
            _logger.info(
                "Installed %s version %s at %s",
                tool_info.display_name,
                version,
                install_path,
            )

            return InstallResult(
                success=True,
                path=install_path,
                version=version,
            )

        except Exception as e:
            _logger.exception("Failed to install %s", tool_info.display_name)
            return InstallResult(success=False, error=str(e))

    async def _install_frida(self) -> InstallResult:
        """Install Frida Python package.

        Returns:
            InstallResult with installation status.
        """
        try:
            _logger.info("Installing Frida via pip...")

            result = await asyncio.to_thread(
                subprocess.run,
                ["pip", "install", "--upgrade", "frida", "frida-tools"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                version_result = await asyncio.to_thread(
                    subprocess.run,
                    ["python", "-c", "import frida; print(frida.__version__)"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                version = self._parse_version(version_result.stdout.strip())
                _logger.info("Installed Frida version %s", version)
                return InstallResult(
                    success=True,
                    path=Path("frida-python"),
                    version=version,
                )

            return InstallResult(
                success=False,
                error=f"pip install failed: {result.stderr}",
            )

        except Exception as e:
            return InstallResult(success=False, error=str(e))

    async def _get_latest_release_url(self, tool: ToolName) -> str | None:
        """Get the latest release download URL from GitHub.

        Args:
            tool: Tool to get release for.

        Returns:
            Download URL or None if not found.
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None or not tool_info.download_url:
            return None

        if "github.com" not in tool_info.download_url:
            return tool_info.download_url

        parts = tool_info.download_url.replace("https://github.com/", "").split("/")
        if len(parts) < 2:
            return None

        owner = parts[0]
        repo = parts[1]
        api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"

        try:
            client = await self._get_client()
            response = await client.get(api_url)
            response.raise_for_status()
            data = response.json()

            for asset in data.get("assets", []):
                name = asset.get("name", "").lower()
                if tool == ToolName.GHIDRA:
                    if name.endswith(".zip") and "public" in name:
                        return asset.get("browser_download_url")
                elif tool == ToolName.X64DBG:
                    if name.endswith(".zip") and "snapshot" in name:
                        return asset.get("browser_download_url")
                elif tool == ToolName.RADARE2:
                    if "w64" in name and name.endswith(".zip"):
                        return asset.get("browser_download_url")

        except Exception as e:
            _logger.error("Failed to get release info: %s", e)

        return None

    async def _download_file(self, url: str) -> Path | None:
        """Download a file to temporary location.

        Args:
            url: URL to download.

        Returns:
            Path to downloaded file or None on failure.
        """
        try:
            client = await self._get_client()

            filename = url.split("/")[-1]
            temp_path = Path(tempfile.gettempdir()) / filename

            _logger.info("Downloading %s...", filename)

            async with client.stream("GET", url) as response:
                response.raise_for_status()
                total = int(response.headers.get("content-length", 0))
                downloaded = 0

                with open(temp_path, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0:
                            percent = (downloaded / total) * 100
                            if downloaded % (1024 * 1024) < 8192:
                                _logger.debug("Download progress: %.1f%%", percent)

            _logger.info("Downloaded %s (%d bytes)", filename, downloaded)
            return temp_path

        except Exception as e:
            _logger.error("Download failed: %s", e)
            return None

    async def _extract_archive(self, archive_path: Path, tool: ToolName) -> Path:
        """Extract an archive to the tools directory.

        Args:
            archive_path: Path to the archive.
            tool: Tool being extracted.

        Returns:
            Path to extracted tool.

        Raises:
            ToolError: If extraction fails.
        """
        tool_dir = self.tools_directory / tool.value
        tool_dir.mkdir(parents=True, exist_ok=True)

        _logger.info("Extracting to %s...", tool_dir)

        try:
            if archive_path.suffix == ".zip":
                await asyncio.to_thread(
                    self._extract_zip,
                    archive_path,
                    tool_dir,
                )
            else:
                raise ToolError(f"Unsupported archive format: {archive_path.suffix}")

            subdirs = [d for d in tool_dir.iterdir() if d.is_dir()]
            if len(subdirs) == 1:
                return subdirs[0]

            return tool_dir

        except Exception as e:
            _logger.exception("Extraction failed")
            raise ToolError(f"Failed to extract {archive_path}: {e}") from e

    def _extract_zip(self, archive_path: Path, dest_dir: Path) -> None:
        """Extract a zip archive.

        Args:
            archive_path: Path to zip file.
            dest_dir: Destination directory.
        """
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(dest_dir)

    async def ensure_tool(self, tool: ToolName) -> Path:
        """Ensure a tool is available, installing if necessary.

        Args:
            tool: The tool to ensure.

        Returns:
            Path to tool installation.

        Raises:
            ToolError: If tool cannot be found or installed.
        """
        path = await self.find_tool(tool)

        if path is not None:
            if await self.verify_tool(tool, path):
                return path
            _logger.warning("Found %s but verification failed", tool)

        result = await self.install_tool(tool)
        if result.success and result.path is not None:
            return result.path

        error_msg = result.error or "Unknown error"
        raise ToolError(f"Failed to ensure {tool}: {error_msg}")

    async def get_all_tool_status(self) -> dict[ToolName, tuple[bool, Path | None]]:
        """Get status of all tools.

        Returns:
            Dict mapping tool name to (available, path) tuple.
        """
        status: dict[ToolName, tuple[bool, Path | None]] = {}

        for tool in ToolName:
            path = await self.find_tool(tool)
            if path is not None:
                verified = await self.verify_tool(tool, path)
                status[tool] = (verified, path if verified else None)
            else:
                status[tool] = (False, None)

        return status
