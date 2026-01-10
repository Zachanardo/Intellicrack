"""Windows Sandbox implementation for isolated binary analysis.

This module provides integration with Windows Sandbox for safe
execution and behavioral monitoring of potentially malicious binaries.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from ..core.logging import get_logger
from .base import (
    ExecutionReport,
    FileChange,
    NetworkActivity,
    ProcessActivity,
    RegistryChange,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxState,
)

_logger = get_logger("sandbox.windows")


class WindowsSandbox(SandboxBase):
    """Windows Sandbox implementation for isolated binary testing.

    Uses the Windows Sandbox feature (available in Windows 10 Pro/Enterprise)
    to provide an isolated execution environment for binary analysis.

    Attributes:
        _process: Windows Sandbox process.
        _wsb_path: Path to the .wsb configuration file.
        _shared_folder: Path to the shared folder.
        _monitor_folder: Path to monitoring scripts folder.
    """

    SANDBOX_EXE = "WindowsSandbox.exe"
    SHARED_FOLDER_NAME = "IntellicrackShared"
    SANDBOX_SHARED_PATH = "C:\\Users\\WDAGUtilityAccount\\Desktop\\Shared"

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialize Windows Sandbox.

        Args:
            config: Optional sandbox configuration.
        """
        super().__init__(config)
        self._process: subprocess.Popen[bytes] | None = None
        self._wsb_path: Path | None = None
        self._shared_folder: Path | None = None
        self._monitor_folder: Path | None = None
        self._temp_dir: Path | None = None

    async def is_available(self) -> bool:
        """Check if Windows Sandbox is available.

        Returns:
            True if Windows Sandbox can be used.
        """
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["where", self.SANDBOX_EXE],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                _logger.debug("WindowsSandbox.exe not found in PATH")
                return False

            features_result = await asyncio.to_thread(
                subprocess.run,
                [
                    "powershell",
                    "-Command",
                    "(Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).State",
                ],
                capture_output=True,
                text=True,
            )

            if "Enabled" in features_result.stdout:
                _logger.info("Windows Sandbox is available")
                return True

            _logger.warning("Windows Sandbox feature is not enabled")
            return False

        except Exception as e:
            _logger.debug("Windows Sandbox availability check failed: %s", e)
            return False

    async def start(self) -> None:
        """Start the Windows Sandbox environment.

        Creates the shared folder structure, generates the .wsb configuration,
        and launches Windows Sandbox.

        Raises:
            SandboxError: If sandbox cannot be started.
        """
        if self._state.status == "running":
            _logger.warning("Sandbox already running")
            return

        self._state.status = "starting"
        self._state.last_error = None

        try:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="intellicrack_sandbox_"))
            self._shared_folder = self._temp_dir / self.SHARED_FOLDER_NAME
            self._shared_folder.mkdir(parents=True, exist_ok=True)

            self._monitor_folder = self._shared_folder / "monitor"
            self._monitor_folder.mkdir(exist_ok=True)

            input_folder = self._shared_folder / "input"
            input_folder.mkdir(exist_ok=True)

            output_folder = self._shared_folder / "output"
            output_folder.mkdir(exist_ok=True)

            logs_folder = self._shared_folder / "logs"
            logs_folder.mkdir(exist_ok=True)

            await self._create_monitor_scripts()

            self._wsb_path = self._temp_dir / "intellicrack.wsb"
            await self._generate_wsb_config()

            _logger.info("Starting Windows Sandbox with config: %s", self._wsb_path)

            self._process = await asyncio.to_thread(
                subprocess.Popen,
                [self.SANDBOX_EXE, str(self._wsb_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )

            await asyncio.sleep(15)

            if self._process.poll() is not None:
                raise SandboxError("Windows Sandbox terminated unexpectedly")

            self._state.status = "running"
            self._state.started_at = datetime.now()
            self._state.pid = self._process.pid

            _logger.info("Windows Sandbox started (PID: %d)", self._process.pid)

        except Exception as e:
            self._state.status = "error"
            self._state.last_error = str(e)
            await self._cleanup()
            raise SandboxError(f"Failed to start Windows Sandbox: {e}") from e

    async def stop(self) -> None:
        """Stop the Windows Sandbox environment.

        Terminates the sandbox process and cleans up resources.

        Raises:
            SandboxError: If sandbox cannot be stopped cleanly.
        """
        if self._state.status == "stopped":
            _logger.debug("Sandbox already stopped")
            return

        self._state.status = "stopping"

        try:
            if self._process is not None:
                await asyncio.to_thread(
                    subprocess.run,
                    ["taskkill", "/F", "/IM", "WindowsSandbox.exe"],
                    capture_output=True,
                )

                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(self._process.wait),
                        timeout=10,
                    )
                except asyncio.TimeoutError:
                    self._process.kill()

                self._process = None

            await self._cleanup()

            self._state.status = "stopped"
            self._state.pid = None
            _logger.info("Windows Sandbox stopped")

        except Exception as e:
            self._state.status = "error"
            self._state.last_error = str(e)
            raise SandboxError(f"Failed to stop Windows Sandbox: {e}") from e

    async def _cleanup(self) -> None:
        """Clean up temporary files and folders."""
        if self._temp_dir is not None and self._temp_dir.exists():
            try:
                await asyncio.to_thread(
                    shutil.rmtree,
                    self._temp_dir,
                    ignore_errors=True,
                )
            except Exception as e:
                _logger.warning("Failed to cleanup temp dir: %s", e)

        self._temp_dir = None
        self._shared_folder = None
        self._monitor_folder = None
        self._wsb_path = None

    async def _generate_wsb_config(self) -> None:
        """Generate the .wsb configuration file."""
        if self._wsb_path is None or self._shared_folder is None:
            raise SandboxError("Sandbox paths not initialized")

        config = ET.Element("Configuration")

        mapped_folders = ET.SubElement(config, "MappedFolders")
        folder = ET.SubElement(mapped_folders, "MappedFolder")
        ET.SubElement(folder, "HostFolder").text = str(self._shared_folder)
        ET.SubElement(folder, "SandboxFolder").text = self.SANDBOX_SHARED_PATH
        ET.SubElement(folder, "ReadOnly").text = "false"

        for host_path, sandbox_path, read_only in self._config.shared_folders:
            folder = ET.SubElement(mapped_folders, "MappedFolder")
            ET.SubElement(folder, "HostFolder").text = str(host_path)
            ET.SubElement(folder, "SandboxFolder").text = sandbox_path
            ET.SubElement(folder, "ReadOnly").text = "true" if read_only else "false"

        networking = "Enable" if self._config.network_enabled else "Disable"
        ET.SubElement(config, "Networking").text = networking

        if self._config.memory_limit_mb > 0:
            ET.SubElement(config, "MemoryInMB").text = str(self._config.memory_limit_mb)

        vgpu = "Enable" if self._config.video_enabled else "Disable"
        ET.SubElement(config, "vGPU").text = vgpu

        audio = "Enable" if self._config.audio_enabled else "Disable"
        ET.SubElement(config, "AudioInput").text = audio

        clipboard = "Enable" if self._config.clipboard_enabled else "Disable"
        ET.SubElement(config, "ClipboardRedirection").text = clipboard

        printer = "Enable" if self._config.printer_enabled else "Disable"
        ET.SubElement(config, "PrinterRedirection").text = printer

        if self._config.startup_commands:
            logon_command = ET.SubElement(config, "LogonCommand")
            command_text = " && ".join(self._config.startup_commands)
            ET.SubElement(logon_command, "Command").text = f"cmd.exe /c {command_text}"

        tree = ET.ElementTree(config)
        ET.indent(tree, space="  ")

        with open(self._wsb_path, "wb") as f:
            tree.write(f, encoding="utf-8", xml_declaration=True)

        _logger.debug("Generated WSB config: %s", self._wsb_path)

    async def _create_monitor_scripts(self) -> None:
        """Create behavioral monitoring scripts for the sandbox."""
        if self._monitor_folder is None:
            return

        file_monitor_ps1 = self._monitor_folder / "file_monitor.ps1"
        file_monitor_script = '''
$logPath = "C:\\Users\\WDAGUtilityAccount\\Desktop\\Shared\\logs\\file_changes.log"
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "C:\\"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true

$action = {
    $path = $Event.SourceEventArgs.FullPath
    $changeType = $Event.SourceEventArgs.ChangeType
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp|$changeType|$path" | Out-File -Append $logPath
}

Register-ObjectEvent $watcher "Created" -Action $action
Register-ObjectEvent $watcher "Changed" -Action $action
Register-ObjectEvent $watcher "Deleted" -Action $action
Register-ObjectEvent $watcher "Renamed" -Action $action

while ($true) { Start-Sleep -Seconds 1 }
'''
        file_monitor_ps1.write_text(file_monitor_script, encoding="utf-8")

        registry_monitor_ps1 = self._monitor_folder / "registry_monitor.ps1"
        registry_monitor_script = '''
$logPath = "C:\\Users\\WDAGUtilityAccount\\Desktop\\Shared\\logs\\registry_changes.log"

$baselineKeys = @(
    "HKLM:\\SOFTWARE",
    "HKCU:\\SOFTWARE",
    "HKLM:\\SYSTEM\\CurrentControlSet\\Services"
)

$baseline = @{}
foreach ($key in $baselineKeys) {
    try {
        $items = Get-ChildItem -Path $key -Recurse -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            $baseline[$item.PSPath] = $item.GetHashCode()
        }
    } catch {}
}

while ($true) {
    Start-Sleep -Seconds 5
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    foreach ($key in $baselineKeys) {
        try {
            $items = Get-ChildItem -Path $key -Recurse -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if (-not $baseline.ContainsKey($item.PSPath)) {
                    "$timestamp|Created|$($item.PSPath)" | Out-File -Append $logPath
                    $baseline[$item.PSPath] = $item.GetHashCode()
                }
            }
        } catch {}
    }
}
'''
        registry_monitor_ps1.write_text(registry_monitor_script, encoding="utf-8")

        network_monitor_ps1 = self._monitor_folder / "network_monitor.ps1"
        network_monitor_script = '''
$logPath = "C:\\Users\\WDAGUtilityAccount\\Desktop\\Shared\\logs\\network_activity.log"

while ($true) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $connections = Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue

    foreach ($conn in $connections) {
        $processName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name
        "$timestamp|$($conn.State)|$($conn.LocalAddress):$($conn.LocalPort)|$($conn.RemoteAddress):$($conn.RemotePort)|$processName" | Out-File -Append $logPath
    }

    Start-Sleep -Seconds 2
}
'''
        network_monitor_ps1.write_text(network_monitor_script, encoding="utf-8")

        process_monitor_ps1 = self._monitor_folder / "process_monitor.ps1"
        process_monitor_script = '''
$logPath = "C:\\Users\\WDAGUtilityAccount\\Desktop\\Shared\\logs\\process_activity.log"
$knownProcesses = @{}

while ($true) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $currentProcesses = Get-Process | Select-Object Id, Name, Path, StartTime

    foreach ($proc in $currentProcesses) {
        if (-not $knownProcesses.ContainsKey($proc.Id)) {
            $knownProcesses[$proc.Id] = $proc.Name
            $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
            "$timestamp|Created|$($proc.Id)|$($proc.Name)|$($proc.Path)|$cmdLine" | Out-File -Append $logPath
        }
    }

    $currentIds = $currentProcesses | ForEach-Object { $_.Id }
    $terminatedIds = $knownProcesses.Keys | Where-Object { $_ -notin $currentIds }

    foreach ($id in $terminatedIds) {
        "$timestamp|Terminated|$id|$($knownProcesses[$id])" | Out-File -Append $logPath
        $knownProcesses.Remove($id)
    }

    Start-Sleep -Seconds 1
}
'''
        process_monitor_ps1.write_text(process_monitor_script, encoding="utf-8")

        start_monitors_cmd = self._monitor_folder / "start_monitors.cmd"
        start_monitors_script = '''@echo off
start /min powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0file_monitor.ps1"
start /min powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0registry_monitor.ps1"
start /min powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0network_monitor.ps1"
start /min powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0process_monitor.ps1"
'''
        start_monitors_cmd.write_text(start_monitors_script, encoding="utf-8")

        _logger.debug("Created monitoring scripts in %s", self._monitor_folder)

    async def execute(
        self,
        command: str,
        timeout: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Execute a command in the sandbox.

        Args:
            command: Command to execute.
            timeout: Optional timeout override.
            working_directory: Optional working directory.

        Returns:
            Tuple of (exit_code, stdout, stderr).

        Raises:
            SandboxError: If execution fails.
        """
        if self._state.status != "running":
            raise SandboxError("Sandbox is not running")

        if self._shared_folder is None:
            raise SandboxError("Shared folder not initialized")

        effective_timeout = timeout or self._config.timeout_seconds

        script_name = f"exec_{int(time.time() * 1000)}.cmd"
        result_name = f"result_{int(time.time() * 1000)}.txt"

        script_path = self._shared_folder / "input" / script_name
        result_path = self._shared_folder / "output" / result_name

        sandbox_script_path = f"{self.SANDBOX_SHARED_PATH}\\input\\{script_name}"
        sandbox_result_path = f"{self.SANDBOX_SHARED_PATH}\\output\\{result_name}"

        cd_cmd = f'cd /d "{working_directory}"' if working_directory else ""
        script_content = f'''@echo off
{cd_cmd}
{command}
echo %ERRORLEVEL% > "{sandbox_result_path}"
'''
        script_path.write_text(script_content, encoding="utf-8")

        trigger_path = self._shared_folder / "input" / "trigger.cmd"
        trigger_content = f'''@echo off
call "{sandbox_script_path}"
'''
        trigger_path.write_text(trigger_content, encoding="utf-8")

        start_time = time.time()

        while time.time() - start_time < effective_timeout:
            await asyncio.sleep(1)

            if result_path.exists():
                try:
                    result_text = result_path.read_text(encoding="utf-8").strip()
                    exit_code = int(result_text) if result_text.isdigit() else -1
                    return (exit_code, "", "")
                except Exception as e:
                    _logger.warning("Failed to read result: %s", e)

        raise SandboxError(f"Command timed out after {effective_timeout} seconds")

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        timeout: int | None = None,
        monitor: bool = True,
    ) -> ExecutionReport:
        """Run a binary in the sandbox with monitoring.

        Args:
            binary_path: Path to the binary to run.
            args: Optional command line arguments.
            timeout: Optional timeout override.
            monitor: Whether to monitor behavior.

        Returns:
            ExecutionReport with results and activity.

        Raises:
            SandboxError: If execution fails.
        """
        if self._state.status != "running":
            raise SandboxError("Sandbox is not running")

        if not binary_path.exists():
            raise SandboxError(f"Binary not found: {binary_path}")

        if self._shared_folder is None:
            raise SandboxError("Shared folder not initialized")

        effective_timeout = timeout or self._config.timeout_seconds
        start_time = time.time()

        await self.copy_to_sandbox(binary_path, f"input\\{binary_path.name}")

        if monitor:
            logs_folder = self._shared_folder / "logs"
            for log_file in logs_folder.glob("*.log"):
                log_file.unlink()

            await self.execute(
                f'"{self.SANDBOX_SHARED_PATH}\\monitor\\start_monitors.cmd"',
                timeout=10,
            )
            await asyncio.sleep(2)

        args_str = " ".join(f'"{a}"' for a in (args or []))
        binary_sandbox_path = f"{self.SANDBOX_SHARED_PATH}\\input\\{binary_path.name}"
        command = f'"{binary_sandbox_path}" {args_str}'

        try:
            exit_code, stdout, stderr = await self.execute(
                command,
                timeout=effective_timeout,
            )
            result = "success"
        except SandboxError as e:
            if "timed out" in str(e):
                result = "timeout"
                exit_code = -1
                stdout = ""
                stderr = str(e)
            else:
                result = "error"
                exit_code = -1
                stdout = ""
                stderr = str(e)

        duration = time.time() - start_time

        file_changes: list[FileChange] = []
        registry_changes: list[RegistryChange] = []
        network_activity: list[NetworkActivity] = []
        process_activity: list[ProcessActivity] = []

        if monitor:
            await asyncio.sleep(2)
            file_changes = await self._parse_file_log()
            registry_changes = await self._parse_registry_log()
            network_activity = await self._parse_network_log()
            process_activity = await self._parse_process_log()

        return ExecutionReport(
            result=result,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            file_changes=file_changes,
            registry_changes=registry_changes,
            network_activity=network_activity,
            process_activity=process_activity,
        )

    async def _parse_file_log(self) -> list[FileChange]:
        """Parse file monitoring log."""
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "file_changes.log"
        if not log_path.exists():
            return []

        changes: list[FileChange] = []
        try:
            for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split("|")
                if len(parts) >= 3:
                    changes.append(
                        FileChange(
                            path=parts[2],
                            operation=parts[1].lower(),  # type: ignore[typeddict-item]
                            old_path=None,
                            timestamp=parts[0],
                            size=None,
                        )
                    )
        except Exception as e:
            _logger.warning("Failed to parse file log: %s", e)

        return changes

    async def _parse_registry_log(self) -> list[RegistryChange]:
        """Parse registry monitoring log."""
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "registry_changes.log"
        if not log_path.exists():
            return []

        changes: list[RegistryChange] = []
        try:
            for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split("|")
                if len(parts) >= 3:
                    changes.append(
                        RegistryChange(
                            key=parts[2],
                            value_name=None,
                            operation=parts[1].lower(),  # type: ignore[typeddict-item]
                            value_type=None,
                            value_data=None,
                            timestamp=parts[0],
                        )
                    )
        except Exception as e:
            _logger.warning("Failed to parse registry log: %s", e)

        return changes

    async def _parse_network_log(self) -> list[NetworkActivity]:
        """Parse network monitoring log."""
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "network_activity.log"
        if not log_path.exists():
            return []

        activities: list[NetworkActivity] = []
        try:
            for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split("|")
                if len(parts) >= 4:
                    local_parts = parts[2].rsplit(":", 1)
                    remote_parts = parts[3].rsplit(":", 1)

                    activities.append(
                        NetworkActivity(
                            protocol="tcp",
                            direction="outbound",
                            local_address=local_parts[0] if local_parts else "",
                            local_port=int(local_parts[1]) if len(local_parts) > 1 else 0,
                            remote_address=remote_parts[0] if remote_parts else "",
                            remote_port=int(remote_parts[1]) if len(remote_parts) > 1 else 0,
                            timestamp=parts[0],
                            bytes_sent=0,
                            bytes_received=0,
                        )
                    )
        except Exception as e:
            _logger.warning("Failed to parse network log: %s", e)

        return activities

    async def _parse_process_log(self) -> list[ProcessActivity]:
        """Parse process monitoring log."""
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "process_activity.log"
        if not log_path.exists():
            return []

        activities: list[ProcessActivity] = []
        try:
            for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split("|")
                if len(parts) >= 4:
                    activities.append(
                        ProcessActivity(
                            pid=int(parts[2]) if parts[2].isdigit() else 0,
                            name=parts[3],
                            path=parts[4] if len(parts) > 4 else None,
                            command_line=parts[5] if len(parts) > 5 else None,
                            parent_pid=None,
                            operation=parts[1].lower(),  # type: ignore[typeddict-item]
                            exit_code=None,
                            timestamp=parts[0],
                        )
                    )
        except Exception as e:
            _logger.warning("Failed to parse process log: %s", e)

        return activities

    async def copy_to_sandbox(self, source: Path, dest: str) -> None:
        """Copy a file into the sandbox.

        Args:
            source: Local source path.
            dest: Destination path relative to sandbox shared folder.

        Raises:
            SandboxError: If copy fails.
        """
        if self._shared_folder is None:
            raise SandboxError("Shared folder not initialized")

        if not source.exists():
            raise SandboxError(f"Source file not found: {source}")

        dest_path = self._shared_folder / dest
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.copy2, source, dest_path)
            _logger.debug("Copied %s to sandbox as %s", source, dest)
        except Exception as e:
            raise SandboxError(f"Failed to copy file to sandbox: {e}") from e

    async def copy_from_sandbox(self, source: str, dest: Path) -> None:
        """Copy a file from the sandbox.

        Args:
            source: Source path relative to sandbox shared folder.
            dest: Local destination path.

        Raises:
            SandboxError: If copy fails.
        """
        if self._shared_folder is None:
            raise SandboxError("Shared folder not initialized")

        source_path = self._shared_folder / source

        if not source_path.exists():
            raise SandboxError(f"Source file not found in sandbox: {source}")

        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.copy2, source_path, dest)
            _logger.debug("Copied %s from sandbox to %s", source, dest)
        except Exception as e:
            raise SandboxError(f"Failed to copy file from sandbox: {e}") from e
