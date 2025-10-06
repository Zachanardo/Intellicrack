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
from typing import Any, Dict, List, Optional

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
    parameters: Dict[str, Any]
    output_format: str  # "json", "xml", "text"
    timeout: int = 300  # seconds
    requires_project: bool = True
    description: str = ""


class GhidraScriptRunner:
    """Manages Ghidra script execution."""

    BUILTIN_SCRIPTS = {
        "function_analysis": GhidraScript(
            name="FunctionAnalysis",
            path=Path("FunctionID.py"),
            language="python",
            parameters={"detailed": True, "include_thunks": False},
            output_format="json",
            description="Analyze all functions in the binary",
        ),
        "string_extraction": GhidraScript(
            name="StringExtractor",
            path=Path("FindStrings.py"),
            language="python",
            parameters={"min_length": 4, "encoding": "UTF-8"},
            output_format="json",
            description="Extract all strings from the binary",
        ),
        "crypto_detection": GhidraScript(
            name="CryptoFinder",
            path=Path("FindCrypto.py"),
            language="python",
            parameters={"algorithms": ["AES", "RSA", "SHA256"]},
            output_format="json",
            description="Detect cryptographic algorithms",
        ),
        "import_analysis": GhidraScript(
            name="ImportAnalysis",
            path=Path("ImportSymbolScript.py"),
            language="python",
            parameters={"resolve_ordinals": True},
            output_format="json",
            description="Analyze imported functions",
        ),
        "export_analysis": GhidraScript(
            name="ExportAnalysis",
            path=Path("ExportSymbolScript.py"),
            language="python",
            parameters={},
            output_format="json",
            description="Analyze exported functions",
        ),
        "decompilation": GhidraScript(
            name="DecompileAll",
            path=Path("DecompileAllFunctionsScript.py"),
            language="python",
            parameters={"output_dir": None, "format": "c"},
            output_format="text",
            description="Decompile all functions to C pseudocode",
        ),
        "call_graph": GhidraScript(
            name="CallGraphBuilder",
            path=Path("GraphFunctionCalls.py"),
            language="python",
            parameters={"format": "dot", "max_depth": 10},
            output_format="text",
            description="Generate function call graph",
        ),
        "vtable_recovery": GhidraScript(
            name="VTableRecovery",
            path=Path("RecoverClassesFromRTTI.py"),
            language="python",
            parameters={"deep_analysis": True},
            output_format="json",
            description="Recover C++ virtual tables and classes",
        ),
        "license_finder": GhidraScript(
            name="LicenseFinder",
            path=Path("custom/FindLicenseChecks.py"),
            language="python",
            parameters={"patterns": ["license", "serial", "key", "activation"]},
            output_format="json",
            description="Find license validation routines",
        ),
        "anti_debug_detector": GhidraScript(
            name="AntiDebugDetector",
            path=Path("custom/DetectAntiDebug.py"),
            language="python",
            parameters={},
            output_format="json",
            description="Detect anti-debugging techniques",
        ),
    }

    def __init__(self, ghidra_path: Path):
        self.ghidra_path = ghidra_path
        self.headless_path = self._get_headless_path()
        self.scripts_dir = ghidra_path / "Ghidra" / "Features" / "Base" / "ghidra_scripts"
        self.custom_scripts: Dict[str, GhidraScript] = {}
        self._load_custom_scripts()

    def _get_headless_path(self) -> Path:
        """Get path to headless analyzer."""
        if os.name == "nt":
            return self.ghidra_path / "support" / "analyzeHeadless.bat"
        else:
            return self.ghidra_path / "support" / "analyzeHeadless"

    def _load_custom_scripts(self) -> None:
        """Load custom Ghidra scripts from user directory."""
        custom_dir = Path.home() / ".ghidra" / "scripts"
        if custom_dir.exists():
            for script_file in custom_dir.glob("*.py"):
                # Parse script metadata from header comments
                metadata = self._parse_script_metadata(script_file)
                if metadata:
                    self.custom_scripts[script_file.stem] = GhidraScript(
                        name=script_file.stem,
                        path=script_file,
                        language="python",
                        parameters=metadata.get("parameters", {}),
                        output_format=metadata.get("output_format", "text"),
                        description=metadata.get("description", ""),
                    )

    def _parse_script_metadata(self, script_path: Path) -> Optional[Dict[str, Any]]:
        """Parse metadata from script header comments."""
        try:
            with open(script_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            metadata = {}
            in_metadata = False

            for line in lines[:50]:  # Check first 50 lines
                if "@metadata" in line:
                    in_metadata = True
                    continue
                if "@end_metadata" in line:
                    break
                if in_metadata and line.strip().startswith("#"):
                    # Parse metadata line
                    content = line.strip()[1:].strip()
                    if ":" in content:
                        key, value = content.split(":", 1)
                        metadata[key.strip()] = value.strip()

            return metadata if metadata else None

        except Exception as e:
            logger.warning(f"Failed to parse script metadata from {script_path}: {e}")
            return None

    def run_script(
        self,
        binary_path: Path,
        script_name: str,
        output_dir: Optional[Path] = None,
        parameters: Optional[Dict[str, Any]] = None,
        project_path: Optional[Path] = None,
        use_terminal: bool = False,
    ) -> Dict[str, Any]:
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
                logger.info(f"Running Ghidra script '{script_name}' in terminal")
                terminal_mgr = get_terminal_manager()

                # Show script execution in terminal
                session_id = terminal_mgr.execute_command(command=cmd, capture_output=False, auto_switch=True, cwd=str(temp_dir))

                # For terminal execution, return session info
                # Results will be available in terminal output and log file
                results = {
                    "execution": {
                        "script": script_name,
                        "binary": str(binary_path),
                        "terminal_session": session_id,
                        "output_dir": str(output_dir),
                        "success": True,
                        "message": "Script running in terminal",
                    }
                }
                return results
            else:
                # Standard execution with captured output
                # Validate that cmd contains only safe, expected commands
                if not isinstance(cmd, list) or not all(isinstance(arg, str) for arg in cmd):
                    raise ValueError(f"Unsafe command: {cmd}")
                temp_dir_path = str(temp_dir).replace(";", "").replace("|", "").replace("&", "")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=script.timeout, cwd=temp_dir_path, shell=False)

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
            logger.error(f"Script {script_name} timed out after {script.timeout} seconds")
            return {"error": "Script execution timed out"}

        except Exception as e:
            logger.error(f"Failed to run script {script_name}: {e}")
            return {"error": str(e)}

        finally:
            # Clean up temporary directory
            if not project_path and temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    def run_script_chain(self, binary_path: Path, script_names: List[str], output_dir: Path, share_project: bool = True) -> Dict[str, Any]:
        """Run multiple scripts in sequence, optionally sharing project."""

        results = {}
        project_path = None

        if share_project:
            # Create shared project for all scripts
            project_path = output_dir / "shared_project"
            project_path.mkdir(parents=True, exist_ok=True)

        try:
            for script_name in script_names:
                logger.info(f"Running script: {script_name}")

                script_output_dir = output_dir / script_name
                script_output_dir.mkdir(parents=True, exist_ok=True)

                result = self.run_script(
                    binary_path=binary_path, script_name=script_name, output_dir=script_output_dir, project_path=project_path
                )

                results[script_name] = result

                # Stop chain if script fails
                if not result.get("execution", {}).get("success", False):
                    logger.error(f"Script {script_name} failed, stopping chain")
                    break

            return results

        finally:
            # Clean up shared project if temporary
            if share_project and project_path and project_path.exists():
                shutil.rmtree(project_path, ignore_errors=True)

    def create_custom_script(
        self, name: str, code: str, language: str = "python", parameters: Optional[Dict[str, Any]] = None
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

    def _get_script(self, name: str) -> Optional[GhidraScript]:
        """Get script by name."""
        # Check builtin scripts
        if name in self.BUILTIN_SCRIPTS:
            return self.BUILTIN_SCRIPTS[name]

        # Check custom scripts
        if name in self.custom_scripts:
            return self.custom_scripts[name]

        # Check if it's a path
        script_path = Path(name)
        if script_path.exists():
            return GhidraScript(
                name=script_path.stem,
                path=script_path,
                language="python" if script_path.suffix == ".py" else "java",
                parameters={},
                output_format="text",
            )

        return None

    def _parse_script_output(self, output_dir: Path, format: str, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse script output based on format."""

        results = {"stdout": stdout, "stderr": stderr, "files": []}

        # List output files
        for file in output_dir.iterdir():
            if file.is_file():
                results["files"].append(str(file))

        # Parse based on format
        if format == "json":
            # Look for JSON output file
            json_files = list(output_dir.glob("*.json"))
            if json_files:
                with open(json_files[0], "r") as f:
                    results["data"] = json.load(f)

        elif format == "xml":
            # Look for XML output file
            xml_files = list(output_dir.glob("*.xml"))
            if xml_files:
                results["xml_file"] = str(xml_files[0])

        elif format == "text":
            # Collect all text output
            text_files = list(output_dir.glob("*.txt"))
            if text_files:
                results["text_files"] = [str(f) for f in text_files]

        return results

    def list_available_scripts(self) -> List[Dict[str, str]]:
        """List all available scripts."""
        scripts = []

        # Add builtin scripts
        for name, script in self.BUILTIN_SCRIPTS.items():
            scripts.append({"name": name, "type": "builtin", "language": script.language, "description": script.description})

        # Add custom scripts
        for name, script in self.custom_scripts.items():
            scripts.append({"name": name, "type": "custom", "language": script.language, "description": script.description})

        return scripts

    def validate_script(self, script_path: Path) -> bool:
        """Validate a Ghidra script."""
        try:
            # Check file exists
            if not script_path.exists():
                return False

            # Check language
            if script_path.suffix not in [".py", ".java"]:
                return False

            # Try to parse for basic syntax (Python only)
            if script_path.suffix == ".py":
                with open(script_path, "r") as f:
                    code = f.read()
                compile(code, str(script_path), "exec")

            return True

        except Exception as e:
            logger.error(f"Script validation failed: {e}")
            return False
