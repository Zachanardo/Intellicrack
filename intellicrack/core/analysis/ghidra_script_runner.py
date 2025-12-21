"""Ghidra Script Runner - Production Implementation.

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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

try:
    from ...core.terminal_manager import get_terminal_manager

    HAS_TERMINAL_MANAGER = True
except ImportError:
    HAS_TERMINAL_MANAGER = False
    logger.warning("Terminal manager not available for Ghidra script runner")


@dataclass
class GhidraScript:
    """Represents a Ghidra script configuration."""

    name: str
    path: Path
    language: str  # "python" or "java"
    parameters: dict[str, Any]
    output_format: str  # "json", "xml", "text"
    timeout: int = 300  # seconds
    requires_project: bool = True
    description: str = ""


class GhidraScriptRunner:
    """Manages Ghidra script execution with dynamic script discovery."""

    def __init__(self, ghidra_path: Path) -> None:
        """Initialize the GhidraScriptRunner with the Ghidra path."""
        self.ghidra_path = ghidra_path
        self.headless_path = self._get_headless_path()
        self.scripts_dir = ghidra_path / "Ghidra" / "Features" / "Base" / "ghidra_scripts"

        self.intellicrack_scripts_dir = Path(__file__).parent.parent.parent / "scripts" / "ghidra"

        self.discovered_scripts: dict[str, GhidraScript] = {}
        self._discover_all_scripts()

    def _get_headless_path(self) -> Path:
        """Get path to headless analyzer."""
        if os.name == "nt":
            return self.ghidra_path / "support" / "analyzeHeadless.bat"
        return self.ghidra_path / "support" / "analyzeHeadless"

    def _discover_all_scripts(self) -> None:
        """Dynamically discover all Ghidra scripts from intellicrack scripts directory."""
        if not self.intellicrack_scripts_dir.exists():
            logger.warning("Intellicrack scripts directory not found: %s", self.intellicrack_scripts_dir)
            return

        for script_file in self.intellicrack_scripts_dir.glob("*.[pj][ya][vt][ah]*"):
            if script_file.name in {"__init__.py", "README.md"}:
                continue

            language = "python" if script_file.suffix == ".py" else "java"

            metadata = self._parse_script_metadata(script_file)

            script_key = script_file.stem.lower()

            self.discovered_scripts[script_key] = GhidraScript(
                name=script_file.stem,
                path=script_file,
                language=language,
                parameters=metadata.get("parameters", {}),
                output_format=metadata.get("output_format", "json"),
                timeout=int(metadata.get("timeout", 300)),
                requires_project=metadata.get("requires_project", "true").lower() == "true",
                description=metadata.get("description", f"{script_file.stem} Ghidra script"),
            )

        logger.info("Discovered %d Ghidra scripts from %s", len(self.discovered_scripts), self.intellicrack_scripts_dir)

    def _parse_script_metadata(self, script_path: Path) -> dict[str, Any]:
        """Parse metadata from script header comments.

        Supports both Python (#) and Java (//, /*) style comments.
        Looks for @key: value patterns in the first 100 lines.
        """
        metadata = {}

        try:
            with open(script_path, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line in lines[:100]:
                line_stripped = line.strip()

                if line_stripped.startswith("#") or line_stripped.startswith("//") or line_stripped.startswith("*"):
                    content = line_stripped.lstrip("#/*").strip()

                    if content.startswith("@") and ":" in content:
                        key_value = content[1:]
                        key, value = key_value.split(":", 1)
                        metadata[key.strip().lower()] = value.strip()

            return metadata

        except Exception as e:
            logger.debug("Could not parse metadata from %s: %s", script_path.name, e)
            return {}

    def run_script(
        self,
        binary_path: Path,
        script_name: str,
        output_dir: Path | None = None,
        parameters: dict[str, Any] | None = None,
        project_path: Path | None = None,
        use_terminal: bool = False,
    ) -> dict[str, Any]:
        """Run a Ghidra script on a binary.

        Args:
            binary_path: Path to binary to analyze
            script_name: Name of script to run
            output_dir: Optional output directory
            parameters: Optional script parameters
            project_path: Optional existing project path
            use_terminal: If True, show analysis progress in terminal (default: False)

        Returns:
            Dictionary with analysis results

        """
        # Get script configuration
        script = self._get_script(script_name)
        if not script:
            raise ValueError(f"Unknown script: {script_name}")

        # Merge parameters
        script_params = script.parameters.copy()
        if parameters:
            script_params.update(parameters)

        # Create temporary directories
        temp_dir = Path(tempfile.mkdtemp(prefix="ghidra_"))
        output_dir = output_dir or temp_dir / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Use provided project or create temporary
        if project_path:
            project_dir = project_path
            project_name = project_path.name
            delete_project = False
        else:
            project_dir = temp_dir / "project"
            project_name = "temp_analysis"
            delete_project = True

        try:
            # Prepare script parameters file
            params_file = temp_dir / "params.json"
            with open(params_file, "w") as f:
                json.dump(script_params, f)

            # Build command
            cmd = [
                str(self.headless_path),
                str(project_dir),
                project_name,
                "-import",
                str(binary_path),
                "-scriptPath",
                str(script.path.parent),
                "-postScript",
                script.path.name,
                str(params_file),  # Pass parameters file to script
                "-scriptlog",
                str(output_dir / "script.log"),
            ]

            if delete_project:
                cmd.append("-deleteProject")

            # Add output directory for scripts that need it
            if "output_dir" in script_params and script_params["output_dir"] is None:
                script_params["output_dir"] = str(output_dir)

            # Execute script
            if use_terminal and HAS_TERMINAL_MANAGER:
                logger.info("Running Ghidra script '%s' in terminal", script_name)
                terminal_mgr = get_terminal_manager()

                # Show script execution in terminal
                session_id = terminal_mgr.execute_command(command=cmd, capture_output=False, auto_switch=True, cwd=str(temp_dir))

                return {
                    "execution": {
                        "script": script_name,
                        "binary": str(binary_path),
                        "terminal_session": session_id,
                        "output_dir": str(output_dir),
                        "success": True,
                        "message": "Script running in terminal",
                    },
                }
            # Standard execution with captured output
            # Validate that cmd contains only safe, expected commands
            if not isinstance(cmd, list) or not all(isinstance(arg, str) for arg in cmd):
                raise ValueError(f"Unsafe command: {cmd}")
            temp_dir_path = str(temp_dir).replace(";", "").replace("|", "").replace("&", "")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=script.timeout,
                cwd=temp_dir_path,
                shell=False,
            )

            # Parse results based on output format
            results = self._parse_script_output(output_dir, script.output_format, result.stdout, result.stderr)

            # Add execution metadata
            results["execution"] = {
                "script": script_name,
                "binary": str(binary_path),
                "return_code": result.returncode,
                "success": result.returncode == 0,
            }

            return results

        except subprocess.TimeoutExpired:
            logger.exception("Script %s timed out after %d seconds", script_name, script.timeout)
            return {"error": "Script execution timed out"}

        except Exception as e:
            logger.exception("Failed to run script %s: %s", script_name, e)
            return {"error": str(e)}

        finally:
            # Clean up temporary directory
            if not project_path and temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    def run_script_chain(
        self,
        binary_path: Path,
        script_names: list[str],
        output_dir: Path,
        share_project: bool = True,
    ) -> dict[str, Any]:
        """Run multiple scripts in sequence, optionally sharing project."""
        results = {}
        project_path = None

        if share_project:
            # Create shared project for all scripts
            project_path = output_dir / "shared_project"
            project_path.mkdir(parents=True, exist_ok=True)

        try:
            for script_name in script_names:
                logger.info("Running script: %s", script_name)

                script_output_dir = output_dir / script_name
                script_output_dir.mkdir(parents=True, exist_ok=True)

                result = self.run_script(
                    binary_path=binary_path,
                    script_name=script_name,
                    output_dir=script_output_dir,
                    project_path=project_path,
                )

                results[script_name] = result

                # Stop chain if script fails
                if not result.get("execution", {}).get("success", False):
                    logger.error("Script %s failed, stopping chain", script_name)
                    break

            return results

        finally:
            # Clean up shared project if temporary
            if share_project and project_path and project_path.exists():
                shutil.rmtree(project_path, ignore_errors=True)

    def create_custom_script(
        self,
        name: str,
        code: str,
        language: str = "python",
        parameters: dict[str, Any] | None = None,
    ) -> GhidraScript:
        """Create a custom Ghidra script."""
        # Create custom scripts directory
        custom_dir = Path.home() / ".ghidra" / "scripts"
        custom_dir.mkdir(parents=True, exist_ok=True)

        # Generate script file
        script_path = custom_dir / f"{name}.{'py' if language == 'python' else 'java'}"

        # Add metadata header
        metadata_header = f"""# @metadata
# description: Custom script {name}
# output_format: json
# parameters: {json.dumps(parameters or {})}
# @end_metadata

"""

        # Write script
        with open(script_path, "w") as f:
            f.write(metadata_header)
            f.write(code)

        # Create script configuration
        script = GhidraScript(
            name=name,
            path=script_path,
            language=language,
            parameters=parameters or {},
            output_format="json",
            description=f"Custom script {name}",
        )

        # Register script
        self.custom_scripts[name] = script

        return script

    def _get_script(self, name: str) -> GhidraScript | None:
        """Get script by name (case-insensitive)."""
        name_lower = name.lower()

        if name_lower in self.discovered_scripts:
            return self.discovered_scripts[name_lower]

        if name in self.discovered_scripts:
            return self.discovered_scripts[name]

        for script in self.discovered_scripts.values():
            if script.name.lower() == name_lower or script.name == name:
                return script

        script_path = Path(name)
        if script_path.exists():
            language = "python" if script_path.suffix == ".py" else "java"
            metadata = self._parse_script_metadata(script_path)

            return GhidraScript(
                name=script_path.stem,
                path=script_path,
                language=language,
                parameters=metadata.get("parameters", {}),
                output_format=metadata.get("output_format", "json"),
                timeout=int(metadata.get("timeout", 300)),
                description=metadata.get("description", ""),
            )

        logger.warning("Script not found: %s", name)
        return None

    def _parse_script_output(self, output_dir: Path, format: str, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse script output based on format."""
        results = {"stdout": stdout, "stderr": stderr, "files": []}

        # List output files
        for file in output_dir.iterdir():
            if file.is_file():
                results["files"].append(str(file))

        # Parse based on format
        if format == "json":
            if json_files := list(output_dir.glob("*.json")):
                with open(json_files[0]) as f:
                    results["data"] = json.load(f)

        elif format == "text":
            if text_files := list(output_dir.glob("*.txt")):
                results["text_files"] = [str(f) for f in text_files]

        elif format == "xml":
            if xml_files := list(output_dir.glob("*.xml")):
                results["xml_file"] = str(xml_files[0])

        return results

    def list_available_scripts(self) -> list[dict[str, str]]:
        """List all dynamically discovered scripts."""
        return [
            {
                "name": name,
                "actual_name": script.name,
                "language": script.language,
                "description": script.description,
                "path": str(script.path.relative_to(self.intellicrack_scripts_dir)),
                "timeout": script.timeout,
            }
            for name, script in self.discovered_scripts.items()
        ]

    def validate_script(self, script_path: Path) -> bool:
        """Validate a Ghidra script."""
        try:
            if not script_path.exists():
                return False

            if script_path.suffix not in [".py", ".java"]:
                return False

            if script_path.suffix == ".py":
                code = Path(script_path).read_text()
                compile(code, str(script_path), "exec")

            return True

        except Exception as e:
            logger.exception("Script validation failed: %s", e)
            return False

    def refresh_scripts(self) -> int:
        """Refresh the list of discovered scripts from filesystem.

        Clears the current discovered scripts cache and re-scans the
        intellicrack scripts directory to find all available Ghidra scripts.

        Returns:
            Number of scripts discovered after refresh.

        """
        self.discovered_scripts.clear()
        self._discover_all_scripts()
        script_count = len(self.discovered_scripts)
        logger.info("Refreshed scripts: %d scripts found", script_count)
        return script_count
