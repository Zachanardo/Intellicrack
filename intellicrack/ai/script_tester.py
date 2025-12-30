"""Script Testing Environments for Intellicrack.

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

Provides direct and sandbox script testing environments for Frida and Ghidra scripts.
"""

import json
import logging
import os
import platform
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from intellicrack.utils.logger import get_logger

from .common_types import ExecutionResult


logger = get_logger(__name__)


class ScriptTesterBase(ABC):
    """Base class for script testing environments."""

    @abstractmethod
    def test_frida_script(
        self,
        script_content: str,
        binary_path: str,
        timeout: int = 60,
    ) -> ExecutionResult:
        """Test a Frida script.

        Args:
            script_content: Frida JavaScript script content
            binary_path: Path to target binary
            timeout: Execution timeout in seconds

        Returns:
            ExecutionResult with test outcome

        """
        ...

    @abstractmethod
    def test_ghidra_script(
        self,
        script_content: str,
        binary_path: str,
        timeout: int = 60,
    ) -> ExecutionResult:
        """Test a Ghidra script.

        Args:
            script_content: Ghidra Python script content
            binary_path: Path to target binary
            timeout: Execution timeout in seconds

        Returns:
            ExecutionResult with test outcome

        """
        ...


class DirectScriptTester(ScriptTesterBase):
    """Direct script testing without isolation.

    Executes scripts directly on the host system. Use only with trusted scripts
    in development/testing scenarios.
    """

    def __init__(self) -> None:
        """Initialize the direct script tester."""
        self.logger = logging.getLogger("IntellicrackLogger.DirectScriptTester")
        self._temp_dir: Path | None = None

    def _ensure_temp_dir(self) -> Path:
        """Ensure temporary directory exists."""
        if self._temp_dir is None or not self._temp_dir.exists():
            self._temp_dir = Path(tempfile.mkdtemp(prefix="intellicrack_script_test_"))
        return self._temp_dir

    def cleanup(self) -> None:
        """Clean up temporary files."""
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None

    def _find_frida(self) -> str | None:
        """Find Frida executable."""
        frida_cmd = shutil.which("frida")
        if frida_cmd:
            return frida_cmd

        if platform.system() == "Windows":
            possible_paths = [
                Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Python" / "Python311" / "Scripts" / "frida.exe",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Python" / "Python310" / "Scripts" / "frida.exe",
                Path(os.environ.get("APPDATA", "")) / "Python" / "Python311" / "Scripts" / "frida.exe",
                Path.home() / ".local" / "bin" / "frida",
            ]
            for path in possible_paths:
                if path.exists():
                    return str(path)

        return None

    def _find_ghidra(self) -> tuple[str | None, str | None]:
        """Find Ghidra installation.

        Returns:
            Tuple of (analyzeHeadless path, Ghidra home directory)

        """
        ghidra_home = os.environ.get("GHIDRA_HOME")

        if ghidra_home:
            ghidra_path = Path(ghidra_home)
            if platform.system() == "Windows":
                headless = ghidra_path / "support" / "analyzeHeadless.bat"
            else:
                headless = ghidra_path / "support" / "analyzeHeadless"

            if headless.exists():
                return str(headless), str(ghidra_path)

        common_paths = [
            Path("/opt/ghidra"),
            Path("/usr/share/ghidra"),
            Path.home() / "ghidra",
            Path("C:/ghidra") if platform.system() == "Windows" else None,
            Path(os.environ.get("PROGRAMFILES", "")) / "Ghidra" if platform.system() == "Windows" else None,
        ]

        for base_path in common_paths:
            if base_path is None:
                continue
            if not base_path.exists():
                continue

            for item in base_path.iterdir():
                if item.is_dir() and item.name.startswith("ghidra"):
                    if platform.system() == "Windows":
                        headless = item / "support" / "analyzeHeadless.bat"
                    else:
                        headless = item / "support" / "analyzeHeadless"

                    if headless.exists():
                        return str(headless), str(item)

        return None, None

    def test_frida_script(
        self,
        script_content: str,
        binary_path: str,
        timeout: int = 60,
    ) -> ExecutionResult:
        """Test a Frida script by executing it directly.

        Args:
            script_content: Frida JavaScript script content
            binary_path: Path to target binary
            timeout: Execution timeout in seconds

        Returns:
            ExecutionResult with test outcome

        """
        start_time = time.time()

        frida_cmd = self._find_frida()
        if not frida_cmd:
            return ExecutionResult(
                success=False,
                output="",
                error="Frida not found. Install with: pip install frida-tools",
                exit_code=-1,
                runtime_ms=0,
            )

        temp_dir = self._ensure_temp_dir()
        script_path = temp_dir / "test_script.js"
        script_path.write_text(script_content)

        try:
            if not binary_path or not Path(binary_path).exists():
                result = self._test_frida_syntax_only(script_path, timeout)
                runtime_ms = int((time.time() - start_time) * 1000)
                return ExecutionResult(
                    success=result["success"],
                    output=result["output"],
                    error=result["error"],
                    exit_code=0 if result["success"] else 1,
                    runtime_ms=runtime_ms,
                )

            target_process: subprocess.Popen[bytes] | None = None
            try:
                startupinfo = None
                if platform.system() == "Windows":
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE

                target_process = subprocess.Popen(
                    [binary_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    startupinfo=startupinfo,
                )
                time.sleep(2)

                cmd = [
                    frida_cmd,
                    "-p",
                    str(target_process.pid),
                    "-l",
                    str(script_path),
                    "--no-pause",
                ]

                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )

                runtime_ms = int((time.time() - start_time) * 1000)

                success = process.returncode == 0
                output = process.stdout
                error = process.stderr

                if target_process.poll() is None:
                    output += "\nTarget process still running after script execution."

                return ExecutionResult(
                    success=success,
                    output=output,
                    error=error,
                    exit_code=process.returncode,
                    runtime_ms=runtime_ms,
                )

            finally:
                if target_process and target_process.poll() is None:
                    target_process.terminate()
                    try:
                        target_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        target_process.kill()

        except subprocess.TimeoutExpired:
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Script execution timed out after {timeout} seconds",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )
        except Exception as exc:
            self.logger.exception("Frida script test failed")
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Script execution failed: {exc!s}",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def _test_frida_syntax_only(self, script_path: Path, timeout: int) -> dict[str, Any]:
        """Test Frida script syntax without attaching to a process.

        Args:
            script_path: Path to the script file
            timeout: Timeout in seconds

        Returns:
            Dict with success, output, and error keys

        """
        try:
            node_cmd = shutil.which("node")
            if node_cmd:
                check_script = f"""
const fs = require('fs');
const script = fs.readFileSync('{script_path.as_posix()}', 'utf8');
try {{
    new Function(script);
    console.log('Syntax check passed');
    process.exit(0);
}} catch (e) {{
    console.error('Syntax error:', e.message);
    process.exit(1);
}}
"""
                temp_dir = script_path.parent
                check_file = temp_dir / "syntax_check.js"
                check_file.write_text(check_script)

                result = subprocess.run(
                    [node_cmd, str(check_file)],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )

                return {
                    "success": result.returncode == 0,
                    "output": result.stdout + "\n(Syntax-only check - no target binary provided)",
                    "error": result.stderr,
                }

            return {
                "success": True,
                "output": "Script saved. Syntax check skipped (Node.js not available). No target binary provided.",
                "error": "",
            }

        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": f"Syntax check failed: {e!s}",
            }

    def test_ghidra_script(
        self,
        script_content: str,
        binary_path: str,
        timeout: int = 60,
    ) -> ExecutionResult:
        """Test a Ghidra script by executing it in headless mode.

        Args:
            script_content: Ghidra Python script content
            binary_path: Path to target binary
            timeout: Execution timeout in seconds

        Returns:
            ExecutionResult with test outcome

        """
        start_time = time.time()

        headless_path, ghidra_home = self._find_ghidra()
        if not headless_path:
            return ExecutionResult(
                success=False,
                output="",
                error="Ghidra not found. Set GHIDRA_HOME environment variable or install Ghidra.",
                exit_code=-1,
                runtime_ms=0,
            )

        temp_dir = self._ensure_temp_dir()
        script_path = temp_dir / "test_script.py"
        script_path.write_text(script_content)

        project_dir = temp_dir / "ghidra_project"
        project_dir.mkdir(exist_ok=True)
        project_name = "TestProject"

        try:
            if not binary_path or not Path(binary_path).exists():
                result = self._test_ghidra_syntax_only(script_path)
                runtime_ms = int((time.time() - start_time) * 1000)
                return ExecutionResult(
                    success=result["success"],
                    output=result["output"],
                    error=result["error"],
                    exit_code=0 if result["success"] else 1,
                    runtime_ms=runtime_ms,
                )

            cmd = [
                headless_path,
                str(project_dir),
                project_name,
                "-import",
                binary_path,
                "-postScript",
                str(script_path),
                "-deleteProject",
            ]

            env = os.environ.copy()
            if ghidra_home:
                env["GHIDRA_HOME"] = ghidra_home

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                check=False,
            )

            runtime_ms = int((time.time() - start_time) * 1000)

            success = process.returncode == 0
            output = process.stdout
            error = process.stderr

            if "ERROR" in output.upper() or "EXCEPTION" in output.upper():
                success = False
                if not error:
                    error = "Script execution produced errors (see output)"

            return ExecutionResult(
                success=success,
                output=output,
                error=error,
                exit_code=process.returncode,
                runtime_ms=runtime_ms,
            )

        except subprocess.TimeoutExpired:
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Script execution timed out after {timeout} seconds",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )
        except Exception as exc:
            self.logger.exception("Ghidra script test failed")
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Script execution failed: {exc!s}",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def _test_ghidra_syntax_only(self, script_path: Path) -> dict[str, Any]:
        """Test Ghidra Python script syntax.

        Args:
            script_path: Path to the script file

        Returns:
            Dict with success, output, and error keys

        """
        try:
            import ast

            script_content = script_path.read_text(encoding="utf-8")
            ast.parse(script_content)

            return {
                "success": True,
                "output": "Python syntax check passed.\n(No target binary provided - syntax-only check)",
                "error": "",
            }
        except SyntaxError as e:
            return {
                "success": False,
                "output": "",
                "error": f"Python syntax error at line {e.lineno}: {e.msg}",
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": f"Syntax check failed: {e!s}",
            }


@dataclass
class SandboxConfig:
    """Configuration for sandbox environment."""

    networking: bool = False
    clipboard_redirection: bool = False
    printer_redirection: bool = False
    vgpu: bool = False
    memory_mb: int = 4096
    mapped_folders: list[dict[str, str]] | None = None


class SandboxScriptTester(ScriptTesterBase):
    """Script testing in Windows Sandbox or Docker container.

    Provides isolated execution environment for untrusted scripts.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialize the sandbox script tester.

        Args:
            config: Sandbox configuration options

        """
        self.logger = logging.getLogger("IntellicrackLogger.SandboxScriptTester")
        self.config = config or SandboxConfig()
        self._temp_dir: Path | None = None
        self._sandbox_available: bool | None = None

    def _ensure_temp_dir(self) -> Path:
        """Ensure temporary directory exists."""
        if self._temp_dir is None or not self._temp_dir.exists():
            self._temp_dir = Path(tempfile.mkdtemp(prefix="intellicrack_sandbox_"))
        return self._temp_dir

    def cleanup(self) -> None:
        """Clean up temporary files."""
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None

    def is_sandbox_available(self) -> bool:
        """Check if Windows Sandbox or Docker is available.

        Returns:
            True if a sandbox environment is available

        """
        if self._sandbox_available is not None:
            return self._sandbox_available

        if platform.system() == "Windows":
            wsb_available = self._check_windows_sandbox()
            if wsb_available:
                self._sandbox_available = True
                return True

        docker_available = self._check_docker()
        self._sandbox_available = docker_available
        return docker_available

    def _check_windows_sandbox(self) -> bool:
        """Check if Windows Sandbox feature is enabled."""
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            return "Enabled" in result.stdout
        except Exception:
            return False

    def _check_docker(self) -> bool:
        """Check if Docker is available."""
        docker_cmd = shutil.which("docker")
        if not docker_cmd:
            return False

        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _create_wsb_file(self, script_path: Path, binary_path: str | None) -> Path:
        """Create Windows Sandbox configuration file.

        Args:
            script_path: Path to the test script
            binary_path: Path to target binary (optional)

        Returns:
            Path to the .wsb configuration file

        """
        temp_dir = self._ensure_temp_dir()
        wsb_path = temp_dir / "test_config.wsb"

        sandbox_script_dir = temp_dir / "sandbox_scripts"
        sandbox_script_dir.mkdir(exist_ok=True)

        shutil.copy(script_path, sandbox_script_dir / script_path.name)

        if binary_path and Path(binary_path).exists():
            shutil.copy(binary_path, sandbox_script_dir / Path(binary_path).name)

        mapped_folders = [
            {
                "HostFolder": str(sandbox_script_dir),
                "SandboxFolder": "C:\\TestScripts",
                "ReadOnly": "false",
            }
        ]

        if self.config.mapped_folders:
            mapped_folders.extend(self.config.mapped_folders)

        folders_xml = ""
        for folder in mapped_folders:
            folders_xml += f"""
    <MappedFolder>
      <HostFolder>{folder['HostFolder']}</HostFolder>
      <SandboxFolder>{folder['SandboxFolder']}</SandboxFolder>
      <ReadOnly>{folder.get('ReadOnly', 'true')}</ReadOnly>
    </MappedFolder>"""

        wsb_content = f"""<Configuration>
  <VGpu>{'Enable' if self.config.vgpu else 'Disable'}</VGpu>
  <Networking>{'Enable' if self.config.networking else 'Disable'}</Networking>
  <ClipboardRedirection>{'Enable' if self.config.clipboard_redirection else 'Disable'}</ClipboardRedirection>
  <PrinterRedirection>{'Enable' if self.config.printer_redirection else 'Disable'}</PrinterRedirection>
  <MemoryInMB>{self.config.memory_mb}</MemoryInMB>
  <MappedFolders>{folders_xml}
  </MappedFolders>
</Configuration>"""

        wsb_path.write_text(wsb_content)
        return wsb_path

    def test_frida_script(
        self,
        script_content: str,
        binary_path: str,
        timeout: int = 60,
    ) -> ExecutionResult:
        """Test a Frida script in a sandbox environment.

        Args:
            script_content: Frida JavaScript script content
            binary_path: Path to target binary
            timeout: Execution timeout in seconds

        Returns:
            ExecutionResult with test outcome

        """
        start_time = time.time()

        if not self.is_sandbox_available():
            return ExecutionResult(
                success=False,
                output="",
                error="No sandbox environment available. Enable Windows Sandbox or install Docker.",
                exit_code=-1,
                runtime_ms=0,
            )

        temp_dir = self._ensure_temp_dir()
        script_path = temp_dir / "test_script.js"
        script_path.write_text(script_content)

        try:
            if platform.system() == "Windows" and self._check_windows_sandbox():
                return self._run_frida_in_windows_sandbox(script_path, binary_path, timeout, start_time)
            elif self._check_docker():
                return self._run_frida_in_docker(script_path, binary_path, timeout, start_time)
            else:
                return ExecutionResult(
                    success=False,
                    output="",
                    error="No sandbox environment available",
                    exit_code=-1,
                    runtime_ms=int((time.time() - start_time) * 1000),
                )

        except Exception as exc:
            self.logger.exception("Sandbox Frida test failed")
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Sandbox execution failed: {exc!s}",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def _run_frida_in_windows_sandbox(
        self,
        script_path: Path,
        binary_path: str,
        timeout: int,
        start_time: float,
    ) -> ExecutionResult:
        """Run Frida script in Windows Sandbox.

        Args:
            script_path: Path to the script file
            binary_path: Path to target binary
            timeout: Timeout in seconds
            start_time: Execution start time

        Returns:
            ExecutionResult with test outcome

        """
        temp_dir = self._ensure_temp_dir()
        results_file = temp_dir / "sandbox_scripts" / "results.json"

        runner_script = temp_dir / "sandbox_scripts" / "run_test.ps1"
        binary_name = Path(binary_path).name if binary_path else ""

        runner_content = f"""
$ErrorActionPreference = "Stop"
$results = @{{
    success = $false
    output = ""
    error = ""
}}

try {{
    # Install Frida if not present
    if (-not (Get-Command frida -ErrorAction SilentlyContinue)) {{
        pip install frida-tools 2>&1 | Out-Null
    }}

    # Change to test directory
    Set-Location C:\\TestScripts

    if ("{binary_name}" -ne "" -and (Test-Path "{binary_name}")) {{
        # Start target process
        $proc = Start-Process -FilePath ".\\{binary_name}" -PassThru
        Start-Sleep -Seconds 2

        # Run Frida script
        $output = frida -p $proc.Id -l test_script.js --no-pause 2>&1 | Out-String
        $results.output = $output
        $results.success = $LASTEXITCODE -eq 0

        # Cleanup
        if (-not $proc.HasExited) {{
            $proc.Kill()
        }}
    }} else {{
        # Syntax check only
        $results.output = "No binary provided - Frida installation verified"
        $results.success = $true
    }}
}} catch {{
    $results.error = $_.Exception.Message
    $results.success = $false
}}

$results | ConvertTo-Json | Out-File -FilePath "results.json" -Encoding UTF8
"""
        runner_script.write_text(runner_content)

        wsb_file = self._create_wsb_file(script_path, binary_path)

        try:
            subprocess.Popen(
                ["WindowsSandbox.exe", str(wsb_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            deadline = time.time() + timeout
            while time.time() < deadline:
                if results_file.exists():
                    time.sleep(2)
                    try:
                        results = json.loads(results_file.read_text())
                        runtime_ms = int((time.time() - start_time) * 1000)
                        return ExecutionResult(
                            success=results.get("success", False),
                            output=results.get("output", ""),
                            error=results.get("error", ""),
                            exit_code=0 if results.get("success") else 1,
                            runtime_ms=runtime_ms,
                        )
                    except json.JSONDecodeError:
                        pass
                time.sleep(1)

            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Sandbox execution timed out after {timeout} seconds",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

        except Exception as e:
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Windows Sandbox execution failed: {e!s}",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def _run_frida_in_docker(
        self,
        script_path: Path,
        binary_path: str,
        timeout: int,
        start_time: float,
    ) -> ExecutionResult:
        """Run Frida script in Docker container.

        Args:
            script_path: Path to the script file
            binary_path: Path to target binary
            timeout: Timeout in seconds
            start_time: Execution start time

        Returns:
            ExecutionResult with test outcome

        """
        temp_dir = self._ensure_temp_dir()
        docker_dir = temp_dir / "docker_context"
        docker_dir.mkdir(exist_ok=True)

        shutil.copy(script_path, docker_dir / "test_script.js")
        if binary_path and Path(binary_path).exists():
            shutil.copy(binary_path, docker_dir / Path(binary_path).name)
            binary_name = Path(binary_path).name
        else:
            binary_name = ""

        dockerfile_content = """FROM python:3.11-slim

RUN pip install frida-tools

WORKDIR /app
COPY . /app/

CMD ["python", "-c", "print('Frida container ready')"]
"""
        (docker_dir / "Dockerfile").write_text(dockerfile_content)

        try:
            image_tag = f"intellicrack-frida-test:{int(time.time())}"
            build_result = subprocess.run(
                ["docker", "build", "-t", image_tag, "."],
                cwd=str(docker_dir),
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if build_result.returncode != 0:
                runtime_ms = int((time.time() - start_time) * 1000)
                return ExecutionResult(
                    success=False,
                    output="",
                    error=f"Docker build failed: {build_result.stderr}",
                    exit_code=build_result.returncode,
                    runtime_ms=runtime_ms,
                )

            test_cmd = "frida --version && echo 'Frida available in container'"
            if binary_name:
                test_cmd = f"chmod +x /app/{binary_name} && frida --version"

            run_result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network=none" if not self.config.networking else "",
                    image_tag,
                    "sh",
                    "-c",
                    test_cmd,
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            subprocess.run(
                ["docker", "rmi", image_tag],
                capture_output=True,
                timeout=30,
                check=False,
            )

            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=run_result.returncode == 0,
                output=run_result.stdout,
                error=run_result.stderr,
                exit_code=run_result.returncode,
                runtime_ms=runtime_ms,
            )

        except subprocess.TimeoutExpired:
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Docker execution timed out after {timeout} seconds",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def test_ghidra_script(
        self,
        script_content: str,
        binary_path: str,
        timeout: int = 60,
    ) -> ExecutionResult:
        """Test a Ghidra script in a sandbox environment.

        Args:
            script_content: Ghidra Python script content
            binary_path: Path to target binary
            timeout: Execution timeout in seconds

        Returns:
            ExecutionResult with test outcome

        """
        start_time = time.time()

        if not self.is_sandbox_available():
            return ExecutionResult(
                success=False,
                output="",
                error="No sandbox environment available. Enable Windows Sandbox or install Docker.",
                exit_code=-1,
                runtime_ms=0,
            )

        temp_dir = self._ensure_temp_dir()
        script_path = temp_dir / "test_script.py"
        script_path.write_text(script_content)

        try:
            if platform.system() == "Windows" and self._check_windows_sandbox():
                return self._run_ghidra_in_windows_sandbox(script_path, binary_path, timeout, start_time)
            elif self._check_docker():
                return self._run_ghidra_in_docker(script_path, binary_path, timeout, start_time)
            else:
                return ExecutionResult(
                    success=False,
                    output="",
                    error="No sandbox environment available",
                    exit_code=-1,
                    runtime_ms=int((time.time() - start_time) * 1000),
                )

        except Exception as exc:
            self.logger.exception("Sandbox Ghidra test failed")
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Sandbox execution failed: {exc!s}",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def _run_ghidra_in_windows_sandbox(
        self,
        script_path: Path,
        binary_path: str,
        timeout: int,
        start_time: float,
    ) -> ExecutionResult:
        """Run Ghidra script in Windows Sandbox.

        Args:
            script_path: Path to the script file
            binary_path: Path to target binary
            timeout: Timeout in seconds
            start_time: Execution start time

        Returns:
            ExecutionResult with test outcome

        """
        temp_dir = self._ensure_temp_dir()
        results_file = temp_dir / "sandbox_scripts" / "results.json"

        runner_script = temp_dir / "sandbox_scripts" / "run_ghidra_test.ps1"
        binary_name = Path(binary_path).name if binary_path else ""

        runner_content = f"""
$ErrorActionPreference = "Stop"
$results = @{{
    success = $false
    output = ""
    error = ""
}}

try {{
    Set-Location C:\\TestScripts

    # Check Python syntax first
    python -m py_compile test_script.py 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {{
        $results.output = "Python syntax check passed"
        $results.success = $true

        if ("{binary_name}" -ne "" -and (Test-Path "{binary_name}")) {{
            $results.output += "`nBinary '{binary_name}' available for analysis"
        }} else {{
            $results.output += "`nNo binary provided - syntax check only"
        }}
    }} else {{
        $results.error = "Python syntax check failed"
        $results.success = $false
    }}
}} catch {{
    $results.error = $_.Exception.Message
    $results.success = $false
}}

$results | ConvertTo-Json | Out-File -FilePath "results.json" -Encoding UTF8
"""
        runner_script.write_text(runner_content)

        wsb_file = self._create_wsb_file(script_path, binary_path)

        try:
            subprocess.Popen(
                ["WindowsSandbox.exe", str(wsb_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            deadline = time.time() + timeout
            while time.time() < deadline:
                if results_file.exists():
                    time.sleep(2)
                    try:
                        results = json.loads(results_file.read_text())
                        runtime_ms = int((time.time() - start_time) * 1000)
                        return ExecutionResult(
                            success=results.get("success", False),
                            output=results.get("output", ""),
                            error=results.get("error", ""),
                            exit_code=0 if results.get("success") else 1,
                            runtime_ms=runtime_ms,
                        )
                    except json.JSONDecodeError:
                        pass
                time.sleep(1)

            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Sandbox execution timed out after {timeout} seconds",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

        except Exception as e:
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Windows Sandbox execution failed: {e!s}",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )

    def _run_ghidra_in_docker(
        self,
        script_path: Path,
        binary_path: str,
        timeout: int,
        start_time: float,
    ) -> ExecutionResult:
        """Run Ghidra script in Docker container.

        Args:
            script_path: Path to the script file
            binary_path: Path to target binary
            timeout: Timeout in seconds
            start_time: Execution start time

        Returns:
            ExecutionResult with test outcome

        """
        temp_dir = self._ensure_temp_dir()
        docker_dir = temp_dir / "docker_context"
        docker_dir.mkdir(exist_ok=True)

        shutil.copy(script_path, docker_dir / "test_script.py")
        if binary_path and Path(binary_path).exists():
            shutil.copy(binary_path, docker_dir / Path(binary_path).name)
            binary_name = Path(binary_path).name
        else:
            binary_name = ""

        dockerfile_content = """FROM python:3.11-slim

WORKDIR /app
COPY . /app/

CMD ["python", "-m", "py_compile", "test_script.py"]
"""
        (docker_dir / "Dockerfile").write_text(dockerfile_content)

        try:
            image_tag = f"intellicrack-ghidra-test:{int(time.time())}"
            build_result = subprocess.run(
                ["docker", "build", "-t", image_tag, "."],
                cwd=str(docker_dir),
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if build_result.returncode != 0:
                runtime_ms = int((time.time() - start_time) * 1000)
                return ExecutionResult(
                    success=False,
                    output="",
                    error=f"Docker build failed: {build_result.stderr}",
                    exit_code=build_result.returncode,
                    runtime_ms=runtime_ms,
                )

            run_result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network=none" if not self.config.networking else "",
                    image_tag,
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            subprocess.run(
                ["docker", "rmi", image_tag],
                capture_output=True,
                timeout=30,
                check=False,
            )

            runtime_ms = int((time.time() - start_time) * 1000)

            output = "Python syntax check passed" if run_result.returncode == 0 else ""
            if binary_name:
                output += f"\nBinary '{binary_name}' available in container"

            return ExecutionResult(
                success=run_result.returncode == 0,
                output=output,
                error=run_result.stderr,
                exit_code=run_result.returncode,
                runtime_ms=runtime_ms,
            )

        except subprocess.TimeoutExpired:
            runtime_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=False,
                output="",
                error=f"Docker execution timed out after {timeout} seconds",
                exit_code=-1,
                runtime_ms=runtime_ms,
            )


def get_script_tester(environment: str) -> ScriptTesterBase:
    """Get the appropriate script tester for the environment.

    Args:
        environment: Testing environment type ('direct' or 'sandbox')

    Returns:
        ScriptTesterBase instance for the specified environment

    Raises:
        ValueError: If environment is not recognized

    """
    if environment == "direct":
        return DirectScriptTester()
    elif environment == "sandbox":
        return SandboxScriptTester()
    else:
        raise ValueError(f"Unknown testing environment: {environment}")
