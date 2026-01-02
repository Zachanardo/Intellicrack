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
    """Represents a Ghidra script configuration.

    Attributes:
        name: Script name identifier.
        path: Path to the script file.
        language: Programming language of the script ("python" or "java").
        parameters: Dictionary of script parameters and values.
        output_format: Expected output format ("json", "xml", or "text").
        timeout: Maximum execution time in seconds. Defaults to 300.
        requires_project: Whether script requires a Ghidra project. Defaults to True.
        description: Human-readable script description. Defaults to empty string.
    """

    name: str
    path: Path
    language: str
    parameters: dict[str, Any]
    output_format: str
    timeout: int = 300
    requires_project: bool = True
    description: str = ""


class GhidraScriptRunner:
    """Manages Ghidra script execution with dynamic script discovery."""

    def __init__(self, ghidra_path: Path) -> None:
        """Initialize the GhidraScriptRunner with the Ghidra path.

        Args:
            ghidra_path: Path to the Ghidra installation directory containing
                the headless analyzer and script libraries.
        """
        self.ghidra_path = ghidra_path
        self.headless_path = self._get_headless_path()
        self.scripts_dir = ghidra_path / "Ghidra" / "Features" / "Base" / "ghidra_scripts"

        self.intellicrack_scripts_dir = Path(__file__).parent.parent.parent / "scripts" / "ghidra"

        self.discovered_scripts: dict[str, GhidraScript] = {}
        self.custom_scripts: dict[str, GhidraScript] = {}
        self._discover_all_scripts()

    def _get_headless_path(self) -> Path:
        """Get path to the Ghidra headless analyzer executable.

        Resolves the platform-specific headless analyzer executable path,
        returning analyzeHeadless.bat on Windows or analyzeHeadless on Unix-like
        systems.

        Returns:
            Path: Path to the Ghidra headless analyzer executable in the
                Ghidra installation's support directory.
        """
        if os.name == "nt":
            return self.ghidra_path / "support" / "analyzeHeadless.bat"
        return self.ghidra_path / "support" / "analyzeHeadless"

    def _discover_all_scripts(self) -> None:
        """Dynamically discover all Ghidra scripts from intellicrack scripts directory.

        Scans the intellicrack scripts directory for Python and Java Ghidra scripts
        and parses their metadata to register them as available scripts.
        """
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

        Extracts metadata annotations from Ghidra script files by scanning the
        first 100 lines for @key: value patterns in comments. Supports both
        Python (#) and Java (//, /*) style comments. Metadata keys are
        normalized to lowercase and include description, output_format, timeout,
        parameters, and requires_project.

        Args:
            script_path: Path to the script file to parse for metadata
                annotations.

        Returns:
            dict[str, Any]: Dictionary containing parsed metadata key-value
                pairs extracted from script header comments. Returns an empty
                dictionary if parsing fails or no metadata is found.
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
        """Run a Ghidra script on a binary with optional parameter customization.

        Executes a registered Ghidra script against a binary file, managing
        temporary project creation, parameter passing, and output collection.
        Results are parsed based on the script's configured output format
        (json, xml, or text).

        Args:
            binary_path: Path to the binary file to analyze with the script.
            script_name: Name of the registered script to execute. Must match
                a discovered or custom script name.
            output_dir: Optional output directory for script results. If not
                provided, a temporary directory is created and cleaned up.
            parameters: Optional dictionary of script-specific parameters to
                override defaults defined in the script metadata.
            project_path: Optional path to an existing Ghidra project. If not
                provided, a temporary project is created for this execution.
            use_terminal: If True and terminal manager is available, show script
                execution progress in terminal; otherwise capture output.

        Returns:
            dict[str, Any]: Dictionary containing execution results with keys:
                'execution' (metadata about the script run),
                'stdout' (captured standard output),
                'stderr' (captured standard error),
                'files' (list of output files generated),
                'data' (parsed output for json format),
                or 'error' if execution failed.

        Raises:
            ValueError: If the specified script_name is not found in discovered
                or custom scripts and does not correspond to a valid file path.
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
        """Run multiple Ghidra scripts in sequence with optional project sharing.

        Executes a chain of scripts against a single binary, optionally reusing
        the same Ghidra project across all script executions to improve performance.
        Stops execution if any script in the chain fails.

        Args:
            binary_path: Path to the binary file to analyze with all scripts in
                the chain.
            script_names: List of script names to execute in sequence. Scripts
                are run in the order specified.
            output_dir: Directory to store output from all scripts. Each script
                gets its own subdirectory within this directory.
            share_project: If True, creates a shared Ghidra project and reuses
                it for all scripts. If False, creates a temporary project for
                each script execution. Defaults to True.

        Returns:
            dict[str, Any]: Dictionary mapping script names (str) to their
                execution result dictionaries (dict[str, Any]). Results follow
                the same format as run_script() return values.
        """
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
        """Create and register a custom Ghidra script.

        Creates a new Ghidra script file in the user's .ghidra/scripts directory
        with appropriate metadata header, writes the provided code, and registers
        the script for execution.

        Args:
            name: Name identifier for the custom script. Used to create the
                script file and as the script key in the custom_scripts registry.
            code: Complete script code to write to the file. Code should be
                valid Python or Java depending on the language parameter.
            language: Programming language for the script ("python" or "java").
                Defaults to "python". Determines file extension (.py or .java).
            parameters: Optional dictionary of script parameters and their
                default values. Parameters are included in the script metadata
                header for documentation. Defaults to None.

        Returns:
            GhidraScript: GhidraScript object configured for the created script,
                registered in the custom_scripts dictionary and ready for
                execution via run_script().
        """
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
        """Retrieve a script by name with flexible matching and fallback.

        Attempts to find a script by name using multiple matching strategies:
        first exact lowercase match, then exact name match, then case-insensitive
        comparison, and finally direct file path resolution if name is a valid file.

        Args:
            name: Script name to look up. Can be a script key, script name, or
                file path. Matching is performed in order of specificity.

        Returns:
            GhidraScript | None: GhidraScript object if found through any
                matching strategy, None if no matching script is found. Returns
                None and logs a warning if no match is located.
        """
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
        """Parse script output based on configured format.

        Extracts and parses script output from the output directory, including
        standard output/error streams and format-specific output files. Handles
        json, xml, and text formats with appropriate parsing and file collection.

        Args:
            output_dir: Directory containing script output files generated during
                execution.
            format: Expected output format ("json", "xml", or "text"). Determines
                how output files are parsed and included in results.
            stdout: Standard output stream captured from script execution.
            stderr: Standard error stream captured from script execution.

        Returns:
            dict[str, Any]: Dictionary containing parsed output with keys:
                'stdout' (standard output string),
                'stderr' (standard error string),
                'files' (list of output file paths),
                'data' (parsed json if format is json),
                'text_files' (list of text files if format is text),
                'xml_file' (first xml file if format is xml).
        """
        results: dict[str, Any] = {"stdout": stdout, "stderr": stderr, "files": []}

        # List output files
        for file in output_dir.iterdir():
            if file.is_file():
                file_list = results["files"]
                if isinstance(file_list, list):
                    file_list.append(str(file))

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

    def list_available_scripts(self) -> list[dict[str, str | int]]:
        """List all dynamically discovered Ghidra scripts with metadata.

        Generates a list of all discovered scripts including their metadata
        such as name, programming language, description, and timeout settings.

        Returns:
            list[dict[str, str | int]]: List of dictionaries containing script
                metadata. Each dictionary includes keys: 'name' (script key),
                'actual_name' (script name), 'language' (python/java),
                'description', 'path' (relative path), and 'timeout' (seconds).
        """
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
        """Validate a Ghidra script for correct format and syntax.

        Performs validation checks on a Ghidra script file including existence
        verification, file extension validation, and Python syntax compilation
        if the script is a Python script.

        Args:
            script_path: Path to the script file to validate. Must be a .py or
                .java file.

        Returns:
            bool: True if the script file exists, has a valid extension (.py or
                .java), and (for Python scripts) contains valid, compilable code.
                Returns False if any validation check fails or an exception occurs
                during validation.
        """
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
            int: Number of scripts discovered after refresh.
        """
        self.discovered_scripts.clear()
        self._discover_all_scripts()
        script_count = len(self.discovered_scripts)
        logger.info("Refreshed scripts: %d scripts found", script_count)
        return script_count
