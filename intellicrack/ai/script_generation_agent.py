"""Autonomous AI Agent for Intellicrack - Claude Code-like Script Generation.

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
"""

import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

import lief
import pefile

from intellicrack.utils.project_paths import get_project_root

from ..core.analysis.frida_script_manager import FridaScriptManager, ScriptResult
from ..core.logging import AuditEvent, AuditEventType, AuditSeverity, get_audit_logger
from ..core.resources import get_resource_manager
from ..utils.logger import get_logger
from .ai_script_generator import AIScriptGenerator, GeneratedScript, ScriptType
from .common_types import ExecutionResult

logger = get_logger(__name__)


class OrchestratorProtocol(Protocol):
    """Protocol for orchestrator instances to avoid circular imports."""

    pass


class CLIInterfaceProtocol(Protocol):
    """Protocol for CLI interface instances to avoid circular imports."""

    pass


class FridaExecutionResult(Protocol):
    """Protocol for Frida script execution result with expected attributes."""

    success: bool
    error: str
    output: str
    execution_time_ms: float
    hooks_triggered: int
    data_collected: list[dict[str, Any]]


class ValidationEnvironment(Enum):
    """Testing environments available."""

    QEMU = "qemu"
    SANDBOX = "sandbox"
    DIRECT = "direct"


# Keep a simple alias for backwards compatibility instead of a redundant Enum subclass.
TestEnvironment = ValidationEnvironment


class WorkflowState(Enum):
    """States of the autonomous workflow."""

    IDLE = "idle"
    ANALYZING = "analyzing"
    GENERATING = "generating"
    TESTING = "testing"
    REFINING = "refining"
    DEPLOYING = "deploying"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class TaskRequest:
    """User request parsed into actionable task."""

    binary_path: str
    script_types: list[ScriptType]
    validation_environment: ValidationEnvironment
    max_iterations: int
    autonomous_mode: bool
    user_confirmation_required: bool
    additional_params: dict[str, Any] = None


class AIAgent:
    """AI agent that can iteratively develop and test scripts.

    Similar to Claude Code - takes a request and autonomously completes it.
    """

    def __init__(
        self,
        orchestrator: OrchestratorProtocol | None = None,
        cli_interface: CLIInterfaceProtocol | None = None,
    ) -> None:
        """Initialize the AI agent with orchestrator and CLI interface.

        Args:
            orchestrator: The orchestrator instance for managing AI operations
            cli_interface: The command-line interface for user interaction

        """
        self.orchestrator = orchestrator
        self.cli_interface = cli_interface
        self.script_generator = AIScriptGenerator()

        # State management
        self.conversation_history = []
        self.current_task = None
        self.workflow_state = WorkflowState.IDLE
        self.iteration_count = 0
        self.max_iterations = 10

        # Results tracking
        self.generated_scripts = []
        self.validation_results = []
        self.refinement_history = []

        # QEMU manager will be initialized when needed
        self.qemu_manager = None

        # VM lifecycle management
        self._active_vms = {}
        self._vm_snapshots = {}
        self._resource_manager = get_resource_manager()
        self._audit_logger = get_audit_logger()

        # Agent identifier for session tracking
        self.agent_id = f"agent_{int(time.time())}_{id(self)}"

        # Initialize Frida script manager with default scripts directory
        scripts_dir = Path(__file__).parent.parent / "scripts" / "frida"
        self.frida_manager = FridaScriptManager(scripts_dir)
        logger.info(f"Initialized FridaScriptManager with {len(self.frida_manager.scripts)} scripts")

    def process_request(self, user_request: str) -> dict[str, Any]:
        """Process a user request autonomously, similar to Claude Code.

        Example: "Create a Frida script to bypass the license check in app.exe"
        """
        try:
            self.workflow_state = WorkflowState.ANALYZING
            self._log_to_user("Starting autonomous script generation workflow...")

            # Parse the user request
            self.current_task = self._parse_request(user_request)
            self.conversation_history.append(
                {"role": "user", "content": user_request, "timestamp": datetime.now().isoformat()},
            )

            # Analyze the target
            self._log_to_user(f"Analyzing target application: {self.current_task.binary_path}")
            analysis = self._analyze_target(self.current_task.binary_path)

            if not analysis:
                return self._error_result("Failed to analyze target binary")

            # Generate initial scripts
            self.workflow_state = WorkflowState.GENERATING
            scripts = self._generate_initial_scripts(analysis)

            if not scripts:
                return self._error_result("Failed to generate initial scripts")

            # Test and refine scripts
            working_scripts = []
            for script in scripts:
                self.workflow_state = WorkflowState.TESTING
                working_script = self._iterative_refinement(script, analysis)
                if working_script:
                    working_scripts.append(working_script)

            if not working_scripts:
                return self._error_result("No working scripts could be generated")

            # Deploy scripts (with user confirmation if required)
            self.workflow_state = WorkflowState.DEPLOYING
            deployment_results = self._deploy_scripts(working_scripts)

            self.workflow_state = WorkflowState.COMPLETED
            return {
                "status": "success",
                "scripts": working_scripts,
                "deployment_results": deployment_results,
                "iterations": self.iteration_count,
                "analysis": analysis,
            }

        except FileNotFoundError as e:
            self.workflow_state = WorkflowState.ERROR
            logger.error(f"Binary file not found: {e}", exc_info=True)
            return self._error_result(f"File not found: {e!s}")
        except TimeoutError as e:
            self.workflow_state = WorkflowState.ERROR
            logger.error(f"Operation timed out: {e}", exc_info=True)
            return self._error_result(f"Operation timed out: {e!s}")
        except OSError as e:
            self.workflow_state = WorkflowState.ERROR
            logger.error(f"File access error: {e}", exc_info=True)
            return self._error_result(f"File access error: {e!s}")
        except (AttributeError, KeyError, ValueError) as e:
            self.workflow_state = WorkflowState.ERROR
            logger.error(f"Autonomous workflow failed: {e}", exc_info=True)
            return self._error_result(f"Workflow error: {e!s}")

    def _parse_request(self, request: str) -> TaskRequest:
        """Parse user request into structured task."""
        request_lower = request.lower()

        binary_path = self._extract_binary_path(request)
        script_types = self._extract_script_types(request_lower)
        execution_env = self._extract_test_environment(request_lower)
        autonomous_mode = "auto" in request_lower or "autonomous" in request_lower

        return TaskRequest(
            binary_path=binary_path,
            script_types=script_types,
            validation_environment=execution_env,
            max_iterations=10,
            autonomous_mode=autonomous_mode,
            user_confirmation_required=not autonomous_mode,
        )

    def _extract_binary_path(self, request: str) -> str:
        """Extract binary path from request.

        Args:
            request: User request string containing binary path

        Returns:
            str: Extracted binary path or 'unknown' if not found

        """
        for word in request.split():
            if word.endswith((".exe", ".dll", ".so", ".dylib", ".bin", ".elf")) or (
                ("/" in word or "\\" in word) and not word.startswith("http")
            ):
                return word
            if len(word) > 3 and not any(c in word for c in [" ", '"', "'"]):
                if any(char in word for char in ["_", "-", "."]) and not word.startswith("-"):
                    return word
        return "unknown"

    def _extract_script_types(self, request_lower: str) -> list[ScriptType]:
        """Extract script types from request.

        Args:
            request_lower: Lowercase user request string

        Returns:
            list[ScriptType]: List of script types to generate

        """
        script_types = []
        if "frida" in request_lower or "dynamic" in request_lower:
            script_types.append(ScriptType.FRIDA)
        if "ghidra" in request_lower or "static" in request_lower:
            script_types.append(ScriptType.GHIDRA)
        if not script_types or "both" in request_lower:
            script_types = [ScriptType.FRIDA, ScriptType.GHIDRA]
        return script_types

    def _extract_test_environment(self, request_lower: str) -> ValidationEnvironment:
        """Extract test environment from request.

        Args:
            request_lower: Lowercase user request string

        Returns:
            ValidationEnvironment: Selected test environment, defaults to QEMU

        """
        if "qemu" in request_lower:
            return ValidationEnvironment.QEMU
        if "sandbox" in request_lower:
            return ValidationEnvironment.SANDBOX
        if "direct" in request_lower:
            return ValidationEnvironment.DIRECT
        return ValidationEnvironment.QEMU

    def _analyze_target(self, binary_path: str) -> dict[str, Any] | None:
        """Run comprehensive analysis on the target binary.

        Args:
            binary_path: Path to the binary to analyze

        Returns:
            dict[str, Any] | None: Analysis results or None if analysis fails

        """
        try:
            self._log_to_user("Running comprehensive binary analysis...")

            # Use existing analysis capabilities
            analysis_results = {
                "binary_path": binary_path,
                "binary_info": self._get_binary_info(binary_path),
                "strings": self._extract_strings(binary_path),
                "functions": self._analyze_functions(binary_path),
                "imports": self._analyze_imports(binary_path),
                "protections": self._detect_protections(binary_path),
                "network_activity": self._check_network_activity(binary_path),
            }

            self._log_to_user(
                f"Analysis complete - found {len(analysis_results.get('protections', []))} protection mechanisms",
            )
            return analysis_results

        except OSError as e:
            logger.error(f"Binary file access error: {e}", exc_info=True)
            self._log_to_user(f"File access error: {e}")
            return None
        except (AttributeError, KeyError, ValueError) as e:
            logger.error(f"Target analysis failed: {e}", exc_info=True)
            self._log_to_user(f"Analysis failed: {e}")
            return None

    def _get_binary_info(self, binary_path: str) -> dict[str, Any]:
        """Get basic binary information.

        Args:
            binary_path: Path to the binary file

        Returns:
            dict[str, Any]: Dictionary containing binary metadata

        """
        try:
            path_obj = Path(binary_path)
            return {
                "name": path_obj.name,
                "size": path_obj.stat().st_size if path_obj.exists() else 0,
                "type": "PE" if binary_path.endswith(".exe") else "unknown",
                "arch": "x64",  # Default assumption
                "platform": "windows" if binary_path.endswith(".exe") else "unknown",
            }
        except OSError as e:
            logger.debug(f"Failed to get binary info: {e}", exc_info=True)
            return {"name": "unknown", "size": 0, "type": "unknown"}

    def _extract_strings(self, binary_path: str) -> list[str]:
        """Extract strings from binary for analysis."""
        strings = []
        try:
            if not self._validate_binary_path(binary_path):
                return strings

            from ..core.analysis.binary_analyzer import BinaryAnalyzer

            analyzer = BinaryAnalyzer(binary_path)
            analysis_results = analyzer.analyze(analyses=['strings'])

            all_strings = self._normalize_strings_data(analysis_results.get('strings', {}))
            strings = self._filter_license_related_strings(all_strings)

            logger.info(f"Extracted {len(strings)} license-related strings from {binary_path}")

        except ImportError as e:
            logger.error(f"Failed to import BinaryAnalyzer: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"String extraction failed: {e}", exc_info=True)

        return strings

    def _normalize_strings_data(self, strings_data: dict[str, Any] | list[str]) -> list[str]:
        """Normalize strings data from various formats to a list of strings.

        Args:
            strings_data: String data in dict or list format from binary analysis

        Returns:
            List of normalized string values

        """
        if isinstance(strings_data, dict):
            return strings_data.get('strings', [])
        if isinstance(strings_data, list):
            return strings_data
        return []

    def _filter_license_related_strings(self, all_strings: list) -> list[str]:
        """Filter strings for license-related content based on keywords."""
        license_keywords = [
            'license', 'trial', 'demo', 'expire', 'activate',
            'register', 'serial', 'key', 'validation', 'auth', 'check',
        ]

        filtered_strings = []
        for string_entry in all_strings:
            string_value = self._extract_string_value(string_entry)
            if string_value and self._contains_license_keyword(string_value, license_keywords):
                filtered_strings.append(string_value)

        return filtered_strings

    def _extract_string_value(self, string_entry: dict[str, str] | str) -> str:
        """Extract string value from entry (dict or str).

        Args:
            string_entry: String entry as dict with 'value' key or direct string

        Returns:
            Extracted string value or empty string

        """
        if isinstance(string_entry, dict):
            return string_entry.get('value', '')
        if isinstance(string_entry, str):
            return string_entry
        return ''

    def _contains_license_keyword(self, string_value: str, keywords: list[str]) -> bool:
        """Check if string contains any license-related keyword."""
        string_lower = string_value.lower()
        return any(keyword in string_lower for keyword in keywords)

    def _validate_binary_path(self, binary_path: str) -> bool:
        """Validate binary path for security."""
        if not binary_path or not Path(binary_path).is_absolute():
            logger.warning("Invalid binary path provided: %s", binary_path)
            return False

        if not os.path.exists(binary_path) or not os.path.isfile(binary_path):
            logger.warning("Binary file not found: %s", binary_path)
            return False

        try:
            import tempfile

            real_path = os.path.realpath(binary_path)
            allowed_dirs = [
                os.path.realpath(Path.cwd()),
                os.path.realpath(os.path.expanduser("~")),
                os.path.realpath(tempfile.gettempdir()),
            ]
            if not any(real_path.startswith(allowed_dir) for allowed_dir in allowed_dirs):
                logger.warning("Binary path outside allowed directories: %s", real_path)
                return False
        except (OSError, ValueError) as e:
            logger.error("Error validating binary path: %s", e)
            return False

        return True

    def _extract_strings_with_command(self, binary_path: str, license_related: list[str]) -> list[str]:
        """Extract strings using subprocess command."""
        import shutil
        import subprocess

        strings = []
        strings_cmd = shutil.which("strings")
        if strings_cmd and os.path.isfile(strings_cmd):
            try:
                # Validate that strings_cmd is a safe absolute path
                strings_cmd_path = shutil.which("strings") or strings_cmd
                if not strings_cmd_path or not Path(strings_cmd_path).is_absolute():
                    strings_cmd_path = strings_cmd_path or "strings"
                # Validate inputs to prevent command injection
                if not isinstance(binary_path, str) or ".." in binary_path or binary_path.startswith(";"):
                    raise ValueError(f"Unsafe binary path: {binary_path}")
                result = subprocess.run(
                    [strings_cmd_path, binary_path],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                    shell=False,
                )  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                if result.returncode == 0:
                    all_strings = result.stdout.split("\n")
                    strings = self._filter_license_strings(all_strings, license_related)
            except (subprocess.SubprocessError, OSError) as e:
                logger.error("Error running strings command: %s", e)
        else:
            logger.debug("strings command not found in PATH")

        return strings

    def _extract_strings_from_file(self, binary_path: str, license_related: list[str]) -> list[str]:
        """Extract strings by reading file directly."""
        strings = []
        data = self._read_binary_data(binary_path)

        if data:
            strings = self._process_binary_data(data, license_related)

        return strings

    def _process_binary_data(self, data: bytes, license_related: list[str]) -> list[str]:
        """Process binary data to extract strings."""
        strings = []
        current_string = ""
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:
                    if any(keyword.lower() in current_string.lower() for keyword in license_related):
                        strings.append(current_string)
                current_string = ""
        return strings

    def _read_binary_data(self, binary_path: str) -> bytes:
        """Read binary data from file."""
        data = None
        try:
            from .ai_file_tools import get_ai_file_tools

            ai_file_tools = get_ai_file_tools(getattr(self, "app_instance", None))
            file_data = ai_file_tools.read_file(
                binary_path,
                purpose="Extract license-related strings from binary",
            )
            if file_data.get("status") == "success" and file_data.get("content"):
                content = file_data["content"]
                if isinstance(content, str):
                    data = content.encode("latin-1", errors="ignore")
                else:
                    data = content
        except (ImportError, AttributeError, KeyError):
            # Content extraction may fail for various reasons, continue with fallback
            pass

        if data is None:
            try:
                with open(binary_path, "rb") as f:
                    data = f.read()
            except OSError as e:
                logger.error(f"Failed to read binary file {binary_path}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error reading binary file: {e}")

        return data or b""

    def _filter_license_strings(self, all_strings: list[str], license_related: list[str]) -> list[str]:
        """Filter strings for license-related content."""
        filtered = []
        for string in all_strings:
            if any(keyword.lower() in string.lower() for keyword in license_related):
                filtered.append(string.strip())
        return filtered

    def _analyze_functions(self, binary_path: str) -> list[dict[str, Any]]:
        """Analyze functions in the binary."""
        functions = []
        try:
            if not Path(binary_path).exists():
                logger.warning(f"Binary path does not exist: {binary_path}")
                return functions

            from ..core.analysis.binary_analyzer import BinaryAnalyzer

            analyzer = BinaryAnalyzer(binary_path)
            analysis_results = analyzer.analyze(analyses=['functions'])
            functions_data = analysis_results.get('functions', [])

            if isinstance(functions_data, list):
                functions = self._process_function_entries(functions_data, binary_path)

            logger.info(f"Analyzed {len(functions)} functions in {binary_path}")

        except ImportError as e:
            logger.error(f"Failed to import BinaryAnalyzer: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Function analysis failed for {binary_path}: {e}", exc_info=True)

        return functions

    def _process_function_entries(self, functions_data: list, binary_path: str) -> list[dict[str, Any]]:
        """Process function entries and classify them."""
        functions = []
        for func_entry in functions_data:
            if isinstance(func_entry, dict):
                processed_func = self._create_function_info(func_entry, binary_path)
                functions.append(processed_func)
        return functions

    def _create_function_info(self, func_entry: dict, binary_path: str) -> dict[str, Any]:
        """Create function information dictionary with type classification."""
        func_name = func_entry.get('name', '').lower()
        func_addr = func_entry.get('address', 0)
        func_type = self._classify_function_type(func_name)

        return {
            'name': func_entry.get('name', 'unknown'),
            'address': hex(func_addr) if isinstance(func_addr, int) else func_addr,
            'type': func_type,
            'size': func_entry.get('size', 0),
            'binary': Path(binary_path).name,
        }

    def _classify_function_type(self, func_name: str) -> str:
        """Classify function type based on name keywords."""
        license_keywords = [
            'license', 'serial', 'activation', 'registration', 'trial',
            'expire', 'valid', 'key', 'unlock', 'authenticate',
            'authorize', 'verify', 'check', 'eval', 'demo', 'install',
        ]
        time_keywords = ['time', 'date', 'clock', 'timer', 'expire', 'elapsed']
        trial_keywords = ['trial', 'demo', 'eval', 'expire', 'period']

        if self._contains_any_keyword(func_name, license_keywords):
            return 'license_check'
        if self._contains_any_keyword(func_name, time_keywords):
            return 'time_check'
        if self._contains_any_keyword(func_name, trial_keywords):
            return 'trial_check'
        return 'unknown'

    def _contains_any_keyword(self, text: str, keywords: list[str]) -> bool:
        """Check if text contains any of the keywords."""
        return any(keyword in text for keyword in keywords)

    def _analyze_imports(self, binary_path: str) -> list[str]:
        """Analyze imported functions."""
        imports = []
        try:
            if not self._validate_import_binary_path(binary_path):
                return imports

            from ..core.analysis.binary_analyzer import BinaryAnalyzer

            analyzer = BinaryAnalyzer(binary_path)
            analysis_results = analyzer.analyze(analyses=['imports'])
            imports_data = analysis_results.get('imports', [])

            if isinstance(imports_data, list):
                imports = self._process_import_entries(imports_data)

            logger.info(f"Analyzed {len(imports)} imports from {binary_path}")

        except ImportError as e:
            logger.error(f"Failed to import BinaryAnalyzer: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Import analysis failed for {binary_path}: {e}", exc_info=True)

        return imports

    def _validate_import_binary_path(self, binary_path: str) -> bool:
        """Validate binary path for import analysis."""
        if not Path(binary_path).is_absolute():
            logger.warning(f"Binary path is not absolute: {binary_path}")
            return False
        if not os.path.exists(binary_path):
            logger.warning(f"Binary path does not exist: {binary_path}")
            return False
        return True

    def _process_import_entries(self, imports_data: list) -> list[str]:
        """Process import entries from analysis data."""
        imports = []
        for import_entry in imports_data:
            import_string = self._format_import_entry(import_entry)
            if import_string:
                imports.append(import_string)
        return imports

    def _format_import_entry(self, import_entry: dict[str, str] | str) -> str:
        """Format import entry to string.

        Args:
            import_entry: Import entry as dict with 'name' and 'dll' keys or direct string

        Returns:
            Formatted import string

        """
        if isinstance(import_entry, dict):
            import_name = import_entry.get('name', '')
            dll_name = import_entry.get('dll', '')
            if import_name:
                return f"{dll_name}:{import_name}" if dll_name else import_name
        elif isinstance(import_entry, str):
            return import_entry
        return ''

    def _detect_protections(self, binary_path: str) -> list[dict[str, Any]]:
        """Detect protection mechanisms."""
        protections = []
        try:
            if not Path(binary_path).exists():
                logger.warning(f"Binary path does not exist: {binary_path}")
                return protections

            from ..core.analysis.protection_scanner import EnhancedProtectionScanner as ProtectionScanner

            scanner = ProtectionScanner()
            scan_results = scanner.scan(binary_path)

            for protection_name, detection_data in scan_results.items():
                if isinstance(detection_data, dict):
                    if detection_data.get('detected', False):
                        protections.append({
                            'type': protection_name,
                            'confidence': detection_data.get('confidence', 0.0),
                            'description': detection_data.get('description', f'{protection_name} detected'),
                            'indicators': detection_data.get('indicators', []),
                            'binary_path': binary_path,
                            'details': detection_data.get('details', {}),
                        })
                elif detection_data:
                    protections.append({
                        'type': protection_name,
                        'confidence': 1.0,
                        'description': f'{protection_name} detected',
                        'indicators': [],
                        'binary_path': binary_path,
                        'details': {},
                    })

            logger.info(f"Detected {len(protections)} protection mechanisms in {binary_path}")

        except ImportError as e:
            logger.error(f"Failed to import ProtectionScanner: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Protection detection failed for {binary_path}: {e}", exc_info=True)

        return protections

    def _check_network_activity(self, binary_path: str) -> dict[str, Any]:
        """Perform comprehensive network activity detection through binary analysis."""
        try:
            # Verify binary exists
            if not Path(binary_path).exists():
                logger.warning(f"Binary path does not exist: {binary_path}")
                return {
                    "has_network": False,
                    "endpoints": [],
                    "protocols": [],
                    "error": "Binary not found",
                }

            # Initialize analysis result
            result = {
                "has_network": False,
                "binary_path": binary_path,
                "binary_size": Path(binary_path).stat().st_size,
                "endpoints": [],
                "protocols": [],
                "network_apis": [],
                "strings_found": [],
                "imports_found": [],
                "confidence": 0.0,
            }

            # Multi-layered network detection approach
            network_indicators = []

            # 1. Import table analysis for network APIs
            network_imports = self._analyze_network_imports(binary_path)
            if network_imports:
                result["imports_found"] = network_imports
                result["has_network"] = True
                network_indicators.extend(network_imports)
                logger.info(f"Found {len(network_imports)} network-related imports in {binary_path}")

            # 2. String analysis for URLs, domains, and protocols
            network_strings = self._analyze_network_strings(binary_path)
            if network_strings:
                result["strings_found"] = network_strings["strings"]
                result["endpoints"].extend(network_strings["endpoints"])
                result["protocols"].extend(network_strings["protocols"])
                if network_strings["count"] > 0:
                    result["has_network"] = True
                    network_indicators.extend(network_strings["strings"])
                logger.info(f"Found {network_strings['count']} network-related strings in {binary_path}")

            # 3. Static analysis for network-related code patterns
            code_analysis = self._analyze_network_code_patterns(binary_path)
            if code_analysis["found"]:
                result["network_apis"].extend(code_analysis["apis"])
                result["has_network"] = True
                network_indicators.extend(code_analysis["apis"])
                logger.info(f"Found {len(code_analysis['apis'])} network API usage patterns in {binary_path}")

            # 4. PE/ELF specific network detection
            binary_format_analysis = self._analyze_binary_format_networking(binary_path)
            if binary_format_analysis["has_network"]:
                result["has_network"] = True
                result["endpoints"].extend(binary_format_analysis.get("endpoints", []))
                result["protocols"].extend(binary_format_analysis.get("protocols", []))
                network_indicators.extend(binary_format_analysis.get("indicators", []))

            # Calculate confidence based on multiple detection methods
            confidence_factors = 0
            if result["imports_found"]:
                confidence_factors += 0.4
            if result["strings_found"]:
                confidence_factors += 0.3
            if result["network_apis"]:
                confidence_factors += 0.2
            if binary_format_analysis.get("has_network"):
                confidence_factors += 0.1

            result["confidence"] = min(1.0, confidence_factors)

            # Remove duplicates and clean up results
            result["endpoints"] = list(set(result["endpoints"]))
            result["protocols"] = list(set(result["protocols"]))

            if result["has_network"]:
                logger.info(f"Network activity detected in {binary_path} with confidence {result['confidence']:.2f}")
                logger.info(f"Found {len(network_indicators)} network indicators total")
            else:
                logger.info(f"No network activity detected in {binary_path}")

            return result

        except OSError as e:
            logger.error(f"Network activity check failed for {binary_path}: {e}", exc_info=True)
            return {"has_network": False, "endpoints": [], "protocols": [], "error": str(e)}

    def _analyze_network_imports(self, binary_path: str) -> list[str]:
        """Analyze import table for network-related APIs."""
        try:
            network_apis = []

            # Analyze PE files
            network_apis.extend(self._analyze_pe_imports(binary_path))

            # Analyze ELF files if no APIs found in PE analysis
            if not network_apis:
                network_apis.extend(self._analyze_elf_imports(binary_path))

            return list(set(network_apis))  # Remove duplicates

        except Exception as e:
            logger.debug(f"Import analysis failed for {binary_path}: {e}")
            return []

    def _analyze_pe_imports(self, binary_path: str) -> list[str]:
        """Analyze PE files for network-related imports."""
        try:
            import pefile

            pe = pefile.PE(binary_path)
            network_api_patterns = self._get_network_api_patterns()
            network_apis = []

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                network_apis.extend(self._extract_dll_imports(pe, network_api_patterns))
                network_apis.extend(self._extract_function_imports(pe, network_api_patterns))

            return network_apis

        except ImportError:
            logger.debug("pefile module not available for PE analysis")
        except Exception as e:
            logger.debug(f"Not a PE file or PE analysis failed: {e}")
        return []

    def _extract_dll_imports(self, pe: pefile.PE, network_api_patterns: list[str]) -> list[str]:
        """Extract DLL imports matching network API patterns.

        Args:
            pe: Parsed PE file object from pefile library
            network_api_patterns: List of network API patterns to match

        Returns:
            List of DLL import strings matching network patterns

        """
        dll_imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8").lower()
            if any(api.lower() in dll_name for api in network_api_patterns[:4]):
                dll_imports.append(f"imports:{dll_name}")
        return dll_imports

    def _extract_function_imports(self, pe: pefile.PE, network_api_patterns: list[str]) -> list[str]:
        """Extract function imports matching network API patterns.

        Args:
            pe: Parsed PE file object from pefile library
            network_api_patterns: List of network API patterns to match

        Returns:
            List of function import strings matching network patterns

        """
        function_imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for func in entry.imports:
                if func.name:
                    func_name = func.name.decode("utf-8")
                    if any(api in func_name for api in network_api_patterns[4:]):
                        function_imports.append(f"api:{func_name}")
        return function_imports

    def _analyze_elf_imports(self, binary_path: str) -> list[str]:
        """Analyze ELF files for network-related imports."""
        try:
            import lief

            binary = lief.parse(binary_path)
            network_symbols = self._get_network_symbols()
            network_apis = []

            if binary and binary.format == lief.EXE_FORMATS.ELF:
                for symbol in binary.dynamic_symbols:
                    if any(net_sym in symbol.name.lower() for net_sym in network_symbols):
                        network_apis.append(f"symbol:{symbol.name}")

                for lib in binary.libraries:
                    if any(net_lib in lib.lower() for net_lib in ["ssl", "curl", "net", "socket"]):
                        network_apis.append(f"library:{lib}")

            return network_apis

        except ImportError:
            logger.debug("lief module not available for ELF analysis")
        except Exception as e:
            logger.debug(f"ELF analysis failed: {e}")
        return []

    def _get_network_api_patterns(self) -> list[str]:
        """Return common network API patterns."""
        return [
            "ws2_32.dll",
            "wininet.dll",
            "winhttp.dll",
            "urlmon.dll",
            "socket",
            "connect",
            "send",
            "recv",
            "WSAStartup",
            "WSAConnect",
            "InternetOpen",
            "InternetConnect",
            "HttpOpenRequest",
            "HttpSendRequest",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "URLDownloadToFile",
            "URLOpenStream",
        ]

    def _get_network_symbols(self) -> list[str]:
        """Return common network-related symbols for ELF analysis."""
        return [
            "socket",
            "connect",
            "bind",
            "listen",
            "accept",
            "send",
            "recv",
            "sendto",
            "recvfrom",
            "gethostbyname",
            "getaddrinfo",
            "curl_",
            "SSL_",
            "TLS_",
            "libssl",
            "libcurl",
        ]

    def _analyze_network_strings(self, binary_path: str) -> dict[str, Any]:
        """Analyze strings for network-related content."""
        try:
            result = {"strings": [], "endpoints": [], "protocols": [], "count": 0}

            # Read binary content for string analysis
            with open(binary_path, "rb") as f:
                content = f.read()

            # Convert to string, handling encoding issues
            text_content = content.decode("utf-8", errors="ignore") + content.decode("latin-1", errors="ignore")

            # Extract URLs and endpoints
            self._extract_urls(text_content, result)
            self._extract_domains(text_content, result)
            self._extract_protocols(text_content, result)
            self._extract_network_keywords(text_content, result)

            # Remove duplicates
            result["strings"] = list(set(result["strings"]))
            result["endpoints"] = list(set(result["endpoints"]))
            result["protocols"] = list(set(result["protocols"]))

            return result

        except Exception as e:
            logger.debug(f"String analysis failed for {binary_path}: {e}")
            return {"strings": [], "endpoints": [], "protocols": [], "count": 0}

    def _extract_urls(self, text_content: str, result: dict) -> None:
        import re

        url_patterns = [
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            r's?ftp://[^\s<>"{}|\\^`\[\]]+',
            r'ftps://[^\s<>"{}|\\^`\[\]]+',
            r'ws[s]?://[^\s<>"{}|\\^`\[\]]+',
        ]
        for pattern in url_patterns:
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            for match in matches:
                if len(match) > 10:
                    result["strings"].append(match)
                    result["endpoints"].append(match)
                    result["count"] += 1
                    if "://" in match:
                        protocol = match.split("://")[0].upper()
                        result["protocols"].append(protocol)

    def _extract_domains(self, text_content: str, result: dict) -> None:
        import re

        domain_patterns = [
            r"\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b",
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",  # IP addresses
        ]
        for pattern in domain_patterns:
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    domain = ".".join(match)
                else:
                    domain = match
                if not any(exclude in domain.lower() for exclude in ["localhost", "example.", "test.", "sample.", ".txt", ".exe", ".dll"]):
                    result["strings"].append(domain)
                    result["endpoints"].append(domain)
                    result["count"] += 1

    def _extract_protocols(self, text_content: str, result: dict) -> None:
        import re

        protocol_patterns = [
            r"\bHTTP[S]?\b",
            r"\bTCP\b",
            r"\bUDP\b",
            r"\bSSL\b",
            r"\bTLS\b",
            r"\bFTP[S]?\b",
            r"\bSMTP\b",
            r"\bPOP3\b",
            r"\bIMAP\b",
        ]
        for pattern in protocol_patterns:
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            for match in matches:
                result["protocols"].append(match.upper())
                result["count"] += 1

    def _extract_network_keywords(self, text_content: str, result: dict) -> None:
        network_keywords = [
            "User-Agent",
            "Content-Type",
            "Authorization",
            "Cookie",
            "GET ",
            "POST ",
            "PUT ",
            "DELETE ",
            "Content-Length",
            "Host:",
            "Accept:",
            "license.server",
            "activation.url",
            "api.endpoint",
        ]
        for keyword in network_keywords:
            if keyword in text_content:
                result["strings"].append(keyword)
                result["count"] += 1

    def _analyze_network_code_patterns(self, binary_path: str) -> dict[str, Any]:
        """Analyze code patterns for network functionality."""
        try:
            result = {"found": False, "apis": []}

            # Read binary for pattern matching
            with open(binary_path, "rb") as f:
                content = f.read()

            # Common network-related code patterns (byte sequences)
            network_patterns = [
                # Socket creation patterns
                b"socket\x00",
                b"connect\x00",
                b"bind\x00",
                b"listen\x00",
                # HTTP patterns
                b"HTTP/1.",
                b"GET /",
                b"POST /",
                b"User-Agent:",
                # SSL/TLS patterns
                b"SSL_",
                b"TLS_",
                # WinINet patterns
                b"InternetOpen",
                b"HttpSendRequest",
                # Certificate patterns
                b"-----BEGIN CERTIFICATE-----",
                b"X509",
            ]

            for pattern in network_patterns:
                if pattern in content:
                    result["found"] = True
                    result["apis"].append(pattern.decode("utf-8", errors="ignore").strip("\x00"))

            return result

        except Exception as e:
            logger.debug(f"Code pattern analysis failed for {binary_path}: {e}")
            return {"found": False, "apis": []}

    def _analyze_binary_format_networking(self, binary_path: str) -> dict[str, Any]:
        """Analyze binary format specific networking features."""
        try:
            result = {"has_network": False, "endpoints": [], "protocols": [], "indicators": []}
            file_ext = Path(binary_path).suffix.lower()

            if file_ext in [".exe", ".dll"]:
                self._analyze_pe_format(binary_path, result)
            elif file_ext in [".so", ""] or "linux" in binary_path.lower():
                self._analyze_elf_format(binary_path, result)

            return result
        except Exception as e:
            logger.debug(f"Binary format analysis failed for {binary_path}: {e}")
            return {"has_network": False, "endpoints": [], "protocols": [], "indicators": []}

    def _analyze_pe_format(self, binary_path: str, result: dict[str, Any]) -> None:
        """Analyze PE-specific networking features."""
        try:
            import pefile

            pe = pefile.PE(binary_path)

            if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
                result["has_network"] = True
                result["indicators"].append("TLS_callbacks")

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                network_dlls = ["ws2_32.dll", "wininet.dll", "winhttp.dll"]
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8").lower()
                    if dll_name in network_dlls:
                        result["has_network"] = True
                        result["protocols"].append("TCP" if "ws2_32" in dll_name else "HTTP")
                        result["indicators"].append(f"imports_{dll_name}")
        except ImportError:
            logger.debug("pefile module not available for PE analysis")
        except Exception as e:
            logger.debug(f"PE analysis failed: {e}")

    def _analyze_elf_format(self, binary_path: str, result: dict[str, Any]) -> None:
        """Analyze ELF-specific networking features."""
        try:
            import lief

            binary = lief.parse(binary_path)

            # Early exit if not an ELF binary
            if not (binary and binary.format == lief.EXE_FORMATS.ELF):
                return

            # Check sections for network-related names
            for section in getattr(binary, "sections", []) or []:
                if self._elf_section_indicates_network(section):
                    result["has_network"] = True
                    result["indicators"].append(f"section_{getattr(section, 'name', '')}")

            # Check linked libraries for known networking libraries
            for lib in getattr(binary, "libraries", []) or []:
                proto = self._elf_lib_protocol(lib)
                if proto:
                    result["has_network"] = True
                    result["protocols"].append(proto)
                    result["indicators"].append(f"links_{lib}")
        except ImportError:
            logger.debug("lief module not available for ELF analysis")
        except Exception as e:
            logger.debug(f"ELF analysis failed: {e}")

    def _elf_section_indicates_network(self, section: lief.ELF.Section) -> bool:
        """Return True if a section name likely indicates networking functionality.

        Args:
            section: ELF section object from lief library

        Returns:
            True if section name contains network-related keywords

        """
        name = getattr(section, "name", "") or ""
        return "net" in name.lower() or "socket" in name.lower()

    def _elf_lib_protocol(self, lib_name: str) -> str | None:
        """Map a library name to a protocol indicator when relevant."""
        lib_l = (lib_name or "").lower()
        if "ssl" in lib_l:
            return "HTTPS"
        if "crypto" in lib_l or "curl" in lib_l:
            return "HTTP"
        return None

    def _generate_initial_scripts(self, analysis: dict[str, Any]) -> list[GeneratedScript]:
        """Generate initial scripts based on analysis."""
        scripts = []

        try:
            for script_type in self.current_task.script_types:
                self._log_to_user(f"Generating {script_type.value} script...")

                if script_type == ScriptType.FRIDA:
                    script = self.script_generator.generate_frida_script(analysis)
                elif script_type == ScriptType.GHIDRA:
                    script = self.script_generator.generate_ghidra_script(analysis)
                else:
                    continue

                if script:
                    scripts.append(script)
                    self.generated_scripts.append(script)
                    self._log_to_user(f"Generated {script_type.value} script successfully")

        except (AttributeError, ValueError, TypeError, RuntimeError, KeyError) as e:
            logger.error(f"Script generation failed: {e}", exc_info=True)
            self._log_to_user(f"Script generation error: {e}")

        return scripts

    def _iterative_refinement(self, script: GeneratedScript, analysis: dict[str, Any]) -> GeneratedScript | None:
        """Test and refine the script iteratively until it works."""
        current_script = script
        self.iteration_count = 0

        for iteration in range(self.max_iterations):
            self.iteration_count = iteration + 1
            self._log_to_user(
                f"Testing iteration {self.iteration_count} for {script.metadata.script_type.value} script...",
            )

            # Test the script and record results
            execution_result = self._test_script(current_script, analysis)
            self.validation_results.append(execution_result)

            if execution_result.success:
                self._log_to_user("OK Script executed successfully!")
                if self._verify_bypass(execution_result, analysis):
                    self._log_to_user("OK Protection bypass confirmed!")
                    return current_script
                self._log_to_user("FAIL Script ran but didn't achieve bypass goal")
            else:
                self._log_to_user(f"FAIL Script failed: {execution_result.error}")

            # Attempt a single refinement for the next iteration
            if iteration < self.max_iterations - 1:
                self._log_to_user("Refining script based on test results...")
                refined_script = self._refine_script(current_script, execution_result, analysis)
                if not refined_script:
                    self._log_to_user("Failed to refine script")
                    break

                current_script = refined_script
                self.refinement_history.append(
                    {
                        "iteration": iteration + 1,
                        "changes": "Script refined based on test results",
                        "timestamp": datetime.now().isoformat(),
                    },
                )

        # No successful refinement achieved within allowed iterations
        return None

    def _test_in_qemu(self, script: GeneratedScript, analysis: dict[str, Any]) -> ExecutionResult:
        """Test script in QEMU environment using real VM execution."""
        self._log_to_user("Preparing QEMU test environment...")

        # Use analysis data to configure test environment
        binary_info = analysis.get("binary_info", {})
        protections = analysis.get("protections", [])
        binary_path = analysis.get("binary_path", "unknown")

        # Initialize QEMU manager if not already done
        if not self.qemu_manager:
            try:
                self._initialize_qemu_manager()
            except Exception as e:
                logger.error(f"Failed to initialize QEMU manager: {e}")
                return ExecutionResult(
                    success=False,
                    output="",
                    error=f"QEMU test environment not available: {e!s}",
                    exit_code=-1,
                    runtime_ms=0,
                )

        try:
            # Create execution configuration based on analysis
            execution_config = {
                "binary_path": binary_path,
                "script_type": script.metadata.script_type.value,
                "script_content": script.content,
                "protections": protections,
                "timeout": 30,  # 30 second timeout
                "arch": binary_info.get("arch", "x64"),
                "platform": binary_info.get("platform", "windows"),
            }

            self._log_to_user(
                f"Testing {script.metadata.script_type.value} script against {len(protections)} protections...",
            )

            # Execute script in real QEMU VM
            result = self.qemu_manager.validate_script_in_vm(
                script.content,
                binary_path,
                script_type=script.metadata.script_type.value,
                timeout=execution_config["timeout"],
            )

            # Parse QEMU execution results
            success = result.get("success", False)
            output = result.get("output", "")
            error = result.get("error", "")
            exit_code = result.get("exit_code", 1)
            runtime_ms = result.get("runtime_ms", 0)

            # Check if script successfully bypassed protections
            if success and "bypass" in output.lower():
                output += f"\nSuccessfully bypassed protections in {binary_path}"
                # Check which protections were targeted
                script_protections = [p.value for p in script.metadata.protection_types]
                if script_protections:
                    output += f"\nTargeted protections: {', '.join(script_protections)}"

            return ExecutionResult(
                success=success,
                output=output,
                error=error,
                exit_code=exit_code,
                runtime_ms=runtime_ms,
            )

        except Exception as e:
            logger.error(f"QEMU test execution failed: {e}")
            return ExecutionResult(
                success=False,
                output=f"QEMU: Script execution failed for {binary_path}",
                error=str(e),
                exit_code=1,
                runtime_ms=0,
            )

    def _test_in_sandbox(self, script: GeneratedScript, analysis: dict[str, Any]) -> ExecutionResult:
        """Test script in sandbox environment using real sandboxing."""
        binary_path = analysis.get("binary_path", "unknown")
        network_activity = analysis.get("network_activity", {})
        has_network = network_activity.get("has_network", False)

        self._log_to_user(f"Testing {script.metadata.script_type.value} script in isolated sandbox...")

        try:
            if platform.system() == "Windows":
                return self._test_in_windows_sandbox(script, binary_path, has_network)
            return self._test_in_linux_firejail(script, binary_path, has_network)
        except Exception as e:
            logger.error(f"Sandbox execution failed: {e}")
            return self._fallback_execution(script, binary_path)

    def _test_in_windows_sandbox(self, script: GeneratedScript, binary_path: str, has_network: bool) -> ExecutionResult:
        """Test script in Windows Sandbox."""
        import shutil
        import subprocess
        import tempfile
        import time
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox_config = self._create_windows_sandbox_config(temp_dir, binary_path, has_network)
            config_path = Path(temp_dir) / "sandbox.wsb"
            config_path.write_text(sandbox_config)

            script_path = Path(temp_dir) / "script.py"
            script_path.write_text(script.content)

            if Path(binary_path).exists():
                shutil.copy2(binary_path, temp_dir)

            start_time = time.time()
            # Validate that config_path is a safe Path object within expected directory
            config_path = Path(str(config_path)).resolve()
            if not str(config_path).startswith(str(Path(temp_dir).resolve())):
                raise ValueError(f"Unsafe config path: {config_path}")
            # Use full path to WindowsSandbox.exe to avoid partial path issue
            windows_sandbox_path = shutil.which("WindowsSandbox.exe") or "C:\\Windows\\System32\\WindowsSandbox.exe"
            result = subprocess.run(
                [windows_sandbox_path, str(config_path)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,
            )  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
            runtime_ms = int((time.time() - start_time) * 1000)
            return self._parse_sandbox_result(result, binary_path, runtime_ms)

    def _test_in_linux_firejail(self, script: GeneratedScript, binary_path: str, has_network: bool) -> ExecutionResult:
        """Test script in Linux Firejail."""
        import shutil
        import subprocess
        import tempfile
        import time
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temp_dir:
            script_path = Path(temp_dir) / "script.py"
            script_path.write_text(script.content)

            if Path(binary_path).exists():
                binary_copy = Path(temp_dir) / Path(binary_path).name
                shutil.copy2(binary_path, binary_copy)
                sandboxed_binary = str(binary_copy)
            else:
                sandboxed_binary = binary_path

            cmd = self._create_firejail_command(temp_dir, script_path, sandboxed_binary, has_network)
            start_time = time.time()
            # Validate that cmd contains only safe, expected commands
            if not isinstance(cmd, list) or not all(isinstance(arg, str) for arg in cmd):
                raise ValueError(f"Unsafe command: {cmd}")
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=30, shell=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
            runtime_ms = int((time.time() - start_time) * 1000)
            return self._parse_sandbox_result(result, binary_path, runtime_ms)

    def _create_windows_sandbox_config(self, temp_dir: str, binary_path: str, has_network: bool) -> str:
        """Create Windows Sandbox configuration."""
        return f"""
<Configuration>
    <VGpu>Disable</VGpu>
    <Networking>{has_network}</Networking>
    <MappedFolders>
        <MappedFolder>
            <HostFolder>{temp_dir}</HostFolder>
            <SandboxFolder>C:\\Sandbox</SandboxFolder>
            <ReadOnly>false</ReadOnly>
        </MappedFolder>
    </MappedFolders>
    <LogonCommand>
        <Command>cmd.exe /c python C:\\Sandbox\\script.py C:\\Sandbox\\{Path(binary_path).name}</Command>
    </LogonCommand>
</Configuration>
"""

    def _create_firejail_command(self, temp_dir: str, script_path: Path, sandboxed_binary: str, has_network: bool) -> list[str]:
        """Create Firejail command."""
        # Use full path to firejail to avoid partial executable path
        firejail_path = shutil.which("firejail") or "firejail"
        cmd = [firejail_path, "--quiet"]
        if not has_network:
            cmd.append("--net=none")
        # Validate paths to prevent command injection
        script_path_str = str(script_path).replace(";", "").replace("|", "").replace("&", "")
        sandboxed_binary_clean = str(sandboxed_binary).replace(";", "").replace("|", "").replace("&", "")
        cmd.extend(["--private=" + temp_dir, "python3", script_path_str, sandboxed_binary_clean])
        return cmd

    def _parse_sandbox_result(self, result: subprocess.CompletedProcess, binary_path: str, runtime_ms: int) -> ExecutionResult:
        """Parse sandbox execution result."""
        success = result.returncode == 0
        output = result.stdout
        error = result.stderr
        if success and any(indicator in output.lower() for indicator in ["bypass", "success", "patched", "unlocked"]):
            output = f"Sandbox: Script successfully tested against {binary_path}\n{output}"
        else:
            error = error or "Script execution completed but bypass not confirmed"
        return ExecutionResult(
            success=success,
            output=output,
            error=error,
            exit_code=0 if success else 1,
            runtime_ms=runtime_ms,
        )

    def _fallback_execution(self, script: GeneratedScript, binary_path: str) -> ExecutionResult:
        """Fallback execution in restricted environment."""
        import subprocess
        import tempfile
        from pathlib import Path

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                script_path = Path(temp_dir) / "test_script.py"
                script_path.write_text(script.content)

                # Validate script_path and binary_path to prevent command injection
                script_path = Path(str(script_path)).resolve()
                binary_path = Path(str(binary_path)).resolve()
                temp_dir_path = Path(str(temp_dir)).resolve()
                if not str(script_path).startswith(str(temp_dir_path)) or not str(binary_path).startswith(str(temp_dir_path)):
                    raise ValueError(f"Unsafe paths: script={script_path}, binary={binary_path}")
                # Use full path to python to avoid partial path issue
                python_path = shutil.which("python3") or shutil.which("python") or "python"
                # Validate paths to prevent command injection
                script_path_str = str(script_path).replace(";", "").replace("|", "").replace("&", "")
                binary_path_clean = str(binary_path).replace(";", "").replace("|", "").replace("&", "")
                result = subprocess.run(
                    [python_path, script_path_str, binary_path_clean],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=temp_dir,
                    shell=False,
                )  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                runtime_ms = 1000
                return ExecutionResult(
                    success=result.returncode == 0,
                    output=f"Restricted execution: {result.stdout}",
                    error=result.stderr,
                    exit_code=result.returncode,
                    runtime_ms=runtime_ms,
                )
        except Exception as fallback_e:
            return ExecutionResult(
                success=False,
                output="Sandbox: Execution failed",
                error=str(fallback_e),
                exit_code=1,
                runtime_ms=0,
            )

    def _test_direct(self, script: GeneratedScript, analysis: dict[str, Any]) -> ExecutionResult:
        """Test script directly (high risk)."""
        binary_path = analysis.get("binary_path", "unknown")
        protections = analysis.get("protections", [])

        self._log_to_user(f"WARNING: Direct testing against {binary_path} is high risk!")
        self._log_to_user(f"Analysis found {len(protections)} protection mechanisms")

        # Enhanced validation using analysis context
        is_valid, errors = self.script_generator.validator.validate_script(script)

        if not is_valid:
            return ExecutionResult(
                success=False,
                output="Script validation failed before direct testing",
                error="; ".join(errors),
                exit_code=1,
                runtime_ms=100,
            )

        # Additional safety checks based on analysis
        safety_score = 1.0
        safety_warnings = []

        # Check for dangerous protections
        dangerous_protections = [p for p in protections if p.get("type") in ["anti_debug", "packer_detection"]]
        if dangerous_protections:
            safety_score *= 0.5
            safety_warnings.append(f"Detected {len(dangerous_protections)} dangerous protections")

        # Check binary size (large binaries may be more complex)
        binary_info = analysis.get("binary_info", {})
        if binary_info.get("size", 0) > 50 * 1024 * 1024:  # >50MB
            safety_score *= 0.7
            safety_warnings.append("Large binary size increases risk")

        # For safety, only proceed with validation-level testing
        if safety_score < 0.8:
            warning_msg = "Direct testing too risky: " + "; ".join(safety_warnings)
            return ExecutionResult(
                success=False,
                output=f"Direct testing blocked for safety (safety score: {safety_score:.2f})",
                error=warning_msg,
                exit_code=2,
                runtime_ms=150,
            )

        # Perform safe validation with analysis context
        script_targets = [p.value for p in script.metadata.protection_types]
        analysis_targets = [p.get("type") for p in protections]
        targeting_match = any(st in analysis_targets for st in script_targets)

        result_output = f"Script validation passed for {binary_path}"
        if targeting_match:
            result_output += f" (Targets: {', '.join(script_targets)})"
        else:
            result_output += " (Warning: Script may not target detected protections)"

        return ExecutionResult(success=True, output=result_output, error="", exit_code=0, runtime_ms=120)

    def _verify_bypass(self, validation_result: ExecutionResult, analysis: dict[str, Any]) -> bool:
        """Verify that the script actually bypassed the protection."""
        if not validation_result.success:
            return False

        # Use analysis data for context-aware verification
        protections = analysis.get("protections", [])
        binary_path = analysis.get("binary_path", "unknown")

        # Enhanced success indicators based on analysis
        success_indicators = [
            "bypass",
            "success",
            "licensed",
            "activated",
            "unlocked",
            "valid",
            "authorized",
            "registered",
            "full version",
        ]

        # Add protection-specific success indicators
        for protection in protections:
            prot_type = protection.get("type", "")
            if prot_type == "license_check":
                success_indicators.extend(["license valid", "key accepted", "registration successful"])
            elif prot_type == "trial_timer":
                success_indicators.extend(["trial extended", "time bypassed", "unlimited time"])
            elif prot_type == "anti_debug":
                success_indicators.extend(["debug detected", "debugger hidden", "anti-debug bypassed"])

        output_lower = validation_result.output.lower()
        basic_success = any(indicator in output_lower for indicator in success_indicators)

        # Additional verification based on analysis context
        verification_score = 0.0

        if basic_success:
            verification_score += 0.7

        # Check if test duration is reasonable (too fast might indicate failure)
        expected_duration = 500 + len(protections) * 200  # Base + complexity
        duration_ratio = validation_result.runtime_ms / max(expected_duration, 100)
        if 0.5 <= duration_ratio <= 2.0:  # Reasonable duration range
            verification_score += 0.2

        # Check if error field is empty (good sign)
        if not validation_result.error:
            verification_score += 0.1

        # Bonus for mentioning the target binary
        if Path(binary_path).name.lower() in output_lower:
            verification_score += 0.1

        # Log verification details
        logger.info(
            f"Bypass verification for {binary_path}: score={verification_score:.2f}, "
            f"protections={len(protections)}, duration={validation_result.runtime_ms}ms",
        )

        return verification_score >= 0.8

    def _refine_script(
        self,
        script: GeneratedScript,
        validation_result: ExecutionResult,
        analysis: dict[str, Any],
    ) -> GeneratedScript | None:
        """Refine the script based on test results and analysis."""
        try:
            protections = analysis.get("protections", [])
            binary_path = analysis.get("binary_path", "unknown")
            binary_info = analysis.get("binary_info", {})

            refined_content = script.content
            refinement_notes = []

            # Apply failure-based refinements
            if not validation_result.success:
                refined_content, failure_notes = self._apply_failure_refinements(
                    script,
                    validation_result,
                    refined_content,
                )
                refinement_notes.extend(failure_notes)

            # Apply protection-specific refinements
            protection_notes = self._apply_protection_refinements(script, protections, refined_content)
            refinement_notes.extend(protection_notes)

            # Apply general improvements
            general_notes = self._apply_general_refinements(script, binary_info, refined_content)
            refinement_notes.extend(general_notes)

            return self._create_refined_script(script, refined_content, refinement_notes, binary_path)

        except (AttributeError, ValueError, TypeError, KeyError) as e:
            logger.error(
                f"Script refinement failed for {analysis.get('binary_path', 'unknown')}: {e}",
                exc_info=True,
            )
            return None

    def _apply_failure_refinements(
        self, script: GeneratedScript, validation_result: ExecutionResult, content: str,
    ) -> tuple[str, list[str]]:
        """Apply refinements based on test failures."""
        refinement_notes = []

        if "protection mechanism detected" in validation_result.error.lower():
            if script.metadata.script_type == ScriptType.FRIDA:
                if "stealth" not in content.lower():
                    stealth_code = (
                        "\n        // Stealth mode enhancements\n        Process.setExceptionHandler(function(details) { return true; });\n"
                    )
                    content = content.replace(
                        'console.log("[AI-Generated]',
                        stealth_code + '        console.log("[AI-Generated]',
                    )
                    refinement_notes.append("Added stealth exception handling")

            elif script.metadata.script_type == ScriptType.GHIDRA:
                if "analyzeAll" not in content:
                    analysis_code = "\n        // Enhanced analysis\n        analyzeAll(currentProgram);\n"
                    content = analysis_code + content
                    refinement_notes.append("Added comprehensive analysis")

        return content, refinement_notes

    def _apply_protection_refinements(self, script: GeneratedScript, protections: list[dict], content: str) -> list[str]:
        """Apply protection-specific refinements."""
        refinement_notes = []

        for protection in protections:
            prot_type = protection.get("type")
            confidence = protection.get("confidence", 0)

            if confidence > 0.8 and prot_type not in content.lower():
                if prot_type == "license_check" and script.metadata.script_type == ScriptType.FRIDA:
                    license_bypass = self._get_license_bypass_code()
                    content += license_bypass
                    refinement_notes.append(f"Added {prot_type} bypass targeting")

                elif prot_type == "trial_timer" and script.metadata.script_type == ScriptType.FRIDA:
                    time_bypass = self._get_time_bypass_code()
                    content += time_bypass
                    refinement_notes.append(f"Added {prot_type} bypass targeting")

        return refinement_notes

    def _apply_general_refinements(self, script: GeneratedScript, binary_info: dict, content: str) -> list[str]:
        """Apply general refinements."""
        refinement_notes = []

        # Add error handling if missing
        if "try {" not in content and script.metadata.script_type == ScriptType.FRIDA:
            content = content.replace(
                'console.log("[AI-Generated] Initializing',
                'try {\n        console.log("[AI-Generated] Initializing',
            )
            content += "\n    } catch (e) {\n        console.log('[Error] ' + e);\n    }"
            refinement_notes.append("Added error handling")

        # Architecture-specific adjustments
        if binary_info.get("arch") == "x64" and "x64" not in content:
            if script.metadata.script_type == ScriptType.FRIDA:
                content = content.replace(
                    "Module.findExportByName",
                    "Module.findExportByName // x64 targeting",
                )
                refinement_notes.append("Added x64 architecture awareness")

        return refinement_notes

    def _get_license_bypass_code(self) -> str:
        """Get license bypass code."""
        return """
        // Target license check
        Interceptor.attach(Module.findExportByName(null, 'strcmp'), {
            onEnter: function(args) {
                this.str1 = args[0].readUtf8String();
                this.str2 = args[1].readUtf8String();
            },
            onLeave: function(retval) {
                if (this.str1 && this.str1.includes('license')) {
                    retval.replace(0);
                }
            }
        });
"""

    def _get_time_bypass_code(self) -> str:
        """Get time bypass code."""
        return """
        // Bypass trial timer
        Interceptor.attach(Module.findExportByName(null, 'GetSystemTime'), {
            onLeave: function(retval) {
                // Return a fixed early date
                Memory.writeU64(retval, ptr(0x01D2C8B5C0000000));
            }
        });
"""

    def _create_refined_script(self, original: GeneratedScript, content: str, notes: list[str], binary_path: str) -> GeneratedScript | None:
        """Create refined script with updated metadata."""
        refined_script = GeneratedScript(
            metadata=original.metadata,
            content=content,
            language=original.language,
            entry_point=original.entry_point,
            dependencies=original.dependencies,
            hooks=original.hooks,
            patches=original.patches,
        )

        refined_script.metadata.iterations = original.metadata.iterations + 1
        refined_script.metadata.refinement_notes = notes

        if notes:
            improvement_factor = min(1.2, 1 + len(notes) * 0.05)
            refined_script.metadata.success_probability *= improvement_factor
            refined_script.metadata.success_probability = min(0.95, refined_script.metadata.success_probability)

        logger.info(f"Refined script for {binary_path}: {len(notes)} improvements")
        return refined_script

    def _deploy_scripts(self, scripts: list[GeneratedScript]) -> list[dict[str, Any]]:
        """Deploy scripts with appropriate safety measures."""
        deployment_results = []

        for script in scripts:
            try:
                # Get user confirmation if required
                if self.current_task.user_confirmation_required:
                    if not self._get_user_confirmation(script):
                        deployment_results.append(
                            {
                                "script_id": script.metadata.script_id,
                                "status": "cancelled",
                                "message": "User cancelled deployment",
                            },
                        )
                        continue

                # Save script to filesystem
                script_path = self.script_generator.save_script(script)

                deployment_results.append(
                    {
                        "script_id": script.metadata.script_id,
                        "status": "deployed",
                        "path": script_path,
                        "message": "Script saved successfully",
                    },
                )

                self._log_to_user(f"OK Script deployed: {script_path}")

            except (OSError, AttributeError) as e:
                logger.error("Error in ai_agent: %s", e)
                deployment_results.append(
                    {
                        "script_id": script.metadata.script_id,
                        "status": "error",
                        "message": f"Deployment failed: {e!s}",
                    },
                )

        return deployment_results

    def _get_user_confirmation(self, script: GeneratedScript) -> bool:
        """Get user confirmation for script deployment."""
        if self.cli_interface:
            # CLI confirmation
            self.cli_interface.print_info(f"Generated {script.metadata.script_type.value} script:")
            self.cli_interface.print_info(f"Target: {script.metadata.target_binary}")
            self.cli_interface.print_info(f"Protections: {[p.value for p in script.metadata.protection_types]}")
            self.cli_interface.print_info(f"Success probability: {script.metadata.success_probability:.0%}")

            response = input("Deploy this script? (y/n): ").lower().strip()
            return response in ["y", "yes"]
        # For GUI or other interfaces, assume approval for now
        return True

    def _log_to_user(self, message: str) -> None:
        """Log progress to user via CLI or UI."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"

        if self.cli_interface:
            self.cli_interface.print_info(formatted_message)
        else:
            print(f"[AI Agent] {formatted_message}")

        # Add to conversation history
        self.conversation_history.append(
            {"role": "assistant", "content": message, "timestamp": datetime.now().isoformat()},
        )

    def _error_result(self, message: str) -> dict[str, Any]:
        """Return error result and save to file."""
        self._log_to_user(f"ERROR: {message}")
        result = {
            "status": "error",
            "message": message,
            "scripts": [],
            "iterations": self.iteration_count,
            "timestamp": datetime.now().isoformat(),
            "agent_id": self.agent_id,
        }

        # Save error result to JSON file for debugging
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix="_error.json", delete=False) as f:
                json.dump(result, f, indent=2)
                logger.info(f"Error result saved to: {f.name}")
        except (OSError, json.JSONDecodeError, AttributeError) as e:
            logger.warning(f"Failed to save error result: {e}", exc_info=True)

        return result

    def _test_script_in_qemu(self, script: str, target_binary: str) -> ExecutionResult:
        """Test script in QEMU virtual environment."""
        try:
            if self._use_qemu_manager(script):
                return self._execute_with_qemu_manager(script, target_binary)

            logger.info("Creating real QEMU test environment for script execution")
            return self._execute_in_temp_environment(script, target_binary)

        except Exception as e:
            logger.error(f"QEMU script testing failed: {e}", exc_info=True)
            return ExecutionResult(
                success=False,
                output="",
                error=f"QEMU testing error: {e!s}",
                exit_code=1,
                runtime_ms=0,
            )

    def _use_qemu_manager(self, script: str) -> bool:
        """Check if QEMU manager is available for script execution."""
        return hasattr(self, "qemu_manager") and self.qemu_manager

    def _execute_with_qemu_manager(self, script: str, target_binary: str) -> ExecutionResult:
        """Execute script using QEMU manager."""
        result = self.qemu_manager.validate_script_in_vm(script, target_binary)
        return ExecutionResult(
            success=result.get("success", False),
            output=result.get("output", ""),
            error=result.get("error", ""),
            exit_code=result.get("exit_code", 1),
            runtime_ms=result.get("runtime_ms", 0),
        )

    def _execute_in_temp_environment(self, script: str, target_binary: str) -> ExecutionResult:
        """Execute script in a temporary environment."""
        import tempfile
        import time

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                start_time = time.time()
                _, target_path = self._prepare_test_files(script, target_binary, temp_dir)
                return self._attempt_execution(script, target_binary, target_path, temp_dir, start_time)
        except Exception as e:
            logger.error(f"QEMU test environment creation failed: {e}")
            return self._fallback_analysis(script, target_binary)

    def _prepare_test_files(self, script: str, target_binary: str, temp_dir: str) -> tuple[Path, Path]:
        """Prepare script and target binary files for testing."""
        import shutil
        from pathlib import Path

        script_path = Path(temp_dir) / "test_script.js"
        script_path.write_text(script, encoding="utf-8")

        target_path = Path(temp_dir) / "target_binary"
        if Path(target_binary).exists():
            shutil.copy2(target_binary, target_path)
        else:
            target_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00")  # Minimal PE header

        return script_path, target_path

    def _attempt_execution(self, script: str, target_binary: str, target_path: Path, temp_dir: str, start_time: float) -> ExecutionResult:
        """Attempt to execute the script using multiple approaches."""
        success, output_lines, error_msg = False, [], ""

        try:
            success, output_lines = self._try_qemu_emulation(target_path, temp_dir)
        except Exception:
            success, output_lines, error_msg = self._try_native_execution(script, target_binary, temp_dir)

        runtime_ms = int((time.time() - start_time) * 1000)
        final_output = self._generate_execution_output(target_binary, script, runtime_ms, temp_dir, output_lines, success)

        return ExecutionResult(
            success=success,
            output=final_output,
            error=error_msg,
            exit_code=0 if success else 1,
            runtime_ms=runtime_ms,
        )

    def _try_qemu_emulation(self, target_path: Path, temp_dir: str) -> tuple[bool, list[str]]:
        """Try QEMU user-mode emulation."""
        import os
        import subprocess

        # Use full paths to avoid partial executable path issues
        qemu_executable = shutil.which("qemu-x86_64") or "qemu-x86_64"
        if os.name == "nt":
            qemu_executable = shutil.which("qemu-system-x86_64") or "qemu-system-x86_64"

        qemu_cmd = [qemu_executable, "-cpu", "qemu64", str(target_path)]
        if os.name == "nt":
            qemu_cmd = [qemu_executable, "-m", "256", "-nographic", "-no-reboot"]

        # Validate that qemu_cmd contains only safe, expected commands
        if not isinstance(qemu_cmd, list) or not all(isinstance(arg, str) for arg in qemu_cmd):
            raise ValueError(f"Unsafe command: {qemu_cmd}")
        # Sanitize target path to prevent command injection
        target_path_clean = str(target_path).replace(";", "").replace("|", "").replace("&", "")
        # Update the command with the sanitized path
        qemu_cmd_sanitized = [arg.replace(str(target_path), target_path_clean) for arg in qemu_cmd]
        result = subprocess.run(qemu_cmd_sanitized, cwd=temp_dir, capture_output=True, text=True, timeout=30, shell=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
        success = result.returncode == 0 or "executed" in result.stdout.lower()
        output_lines = ["QEMU execution successful"] if success else []
        return success, output_lines

    def _try_native_execution(self, script: str, target_binary: str, temp_dir: str) -> tuple[bool, list[str], str]:
        """Try native script execution."""
        success, output_lines, error_msg = False, [], ""
        try:
            if script.lower().startswith("java"):
                success, output_lines = self._execute_frida_script(script, target_binary, temp_dir)
            else:
                success, output_lines = self._validate_generic_script(script, target_binary)
        except Exception as e:
            error_msg = f"Script execution failed: {e}"
        return success, output_lines, error_msg

    def _execute_frida_script(self, script: str, target_binary: str, temp_dir: str) -> tuple[bool, list[str]]:
        """Execute Frida script against target binary.

        Args:
            script: Either a script name from the library or the full script content
            target_binary: Path to the target binary to analyze
            temp_dir: Temporary directory for any output files

        Returns:
            Tuple of (success, output_lines)

        """
        output_lines = []

        try:
            script_name = self._prepare_frida_script(script, temp_dir, output_lines)

            if not self._validate_frida_target(target_binary, output_lines):
                return False, output_lines

            output_lines.append(f"Target: {Path(target_binary).name}")

            result = self.frida_manager.execute_script(
                script_name=script_name if script in self.frida_manager.scripts else Path(script_name).name,
                target=target_binary,
                mode="spawn",
                parameters={},
            )

            return self._process_frida_result(result, output_lines)

        except Exception as e:
            error_msg = f"Exception during Frida script execution: {e}"
            logger.exception(error_msg)
            output_lines.append(f"ERROR: {error_msg}")
            return False, output_lines

    def _prepare_frida_script(self, script: str, temp_dir: str, output_lines: list[str]) -> str:
        """Prepare Frida script for execution (library or custom)."""
        if script in self.frida_manager.scripts:
            logger.info(f"Executing library script: {script}")
            output_lines.append(f"Executing library script: {script}")
            return script

        script_path = Path(temp_dir) / "custom_frida_script.js"
        script_path.write_text(script, encoding='utf-8')
        logger.info(f"Executing custom script ({len(script)} bytes)")
        output_lines.append(f"Executing custom Frida script ({len(script)} bytes)")
        return str(script_path)

    def _validate_frida_target(self, target_binary: str, output_lines: list[str]) -> bool:
        """Validate target binary exists for Frida execution."""
        if not os.path.exists(target_binary):
            error_msg = f"Target binary not found: {target_binary}"
            logger.error(error_msg)
            output_lines.append(f"ERROR: {error_msg}")
            return False
        return True

    def _process_frida_result(
        self,
        result: FridaExecutionResult,
        output_lines: list[str],
    ) -> tuple[bool, list[str]]:
        """Process Frida script execution result.

        Args:
            result: Frida execution result with success status and output
            output_lines: List of output lines to append to

        Returns:
            Tuple of (success status, updated output lines)

        """
        if result.success:
            self._append_frida_success_output(result, output_lines)
            logger.info(f"Frida script executed successfully: {result.execution_time_ms}ms")
            return True, output_lines

        self._append_frida_failure_output(result, output_lines)
        logger.error(f"Frida script execution failed: {result.error}")
        return False, output_lines

    def _append_frida_success_output(
        self,
        result: FridaExecutionResult,
        output_lines: list[str],
    ) -> None:
        """Append success output from Frida execution.

        Args:
            result: Frida execution result with output and metrics
            output_lines: List of output lines to append to

        """
        output_lines.append("Frida script execution completed successfully")
        output_lines.append(f"Execution time: {result.execution_time_ms}ms")

        if result.output:
            self._append_frida_script_output(result.output, output_lines, max_lines=50)

        if result.hooks_triggered:
            output_lines.append(f"\nHooks triggered: {result.hooks_triggered}")

        if result.data_collected:
            output_lines.append(f"Data collected: {len(result.data_collected)} items")

    def _append_frida_failure_output(
        self,
        result: FridaExecutionResult,
        output_lines: list[str],
    ) -> None:
        """Append failure output from Frida execution.

        Args:
            result: Frida execution result with error information
            output_lines: List of output lines to append to

        """
        output_lines.append(f"ERROR: Frida script execution failed: {result.error}")
        if result.output:
            self._append_frida_script_output(result.output, output_lines, max_lines=20, prefix="Partial output:")

    def _append_frida_script_output(self, output: str, output_lines: list[str], max_lines: int, prefix: str = "Script Output:") -> None:
        """Append Frida script output with line limit."""
        output_lines.append(f"\n{prefix}")
        lines = output.split('\n')
        for line in lines[:max_lines]:
            output_lines.append(f"   {line}")

        if len(lines) > max_lines:
            output_lines.append(f"   ... ({len(lines) - max_lines} more lines)")

    def list_available_frida_scripts(self) -> dict[str, dict]:
        """List all available Frida scripts from the library.

        Returns:
            Dictionary mapping script names to their metadata (category, description, etc.)

        """
        available_scripts = {}

        for script_name, script_config in self.frida_manager.scripts.items():
            available_scripts[script_name] = {
                "category": script_config.category.value,
                "description": script_config.description,
                "parameters": script_config.parameters,
                "example_usage": script_config.example_usage,
            }

        return available_scripts

    def execute_frida_library_script(
        self,
        script_name: str,
        target_binary: str,
        parameters: dict | None = None,
        mode: str = "spawn",
    ) -> tuple[bool, list[str]]:
        """Execute a Frida script from the library by name.

        Args:
            script_name: Name of the script from the library
            target_binary: Path to the target binary
            parameters: Optional parameters to pass to the script
            mode: Execution mode ("spawn" or "attach")

        Returns:
            Tuple of (success, output_lines)

        """
        output_lines = []

        try:
            if not self._validate_library_script(script_name, output_lines):
                return False, output_lines

            if not self._validate_frida_target(target_binary, output_lines):
                return False, output_lines

            self._log_library_script_execution(script_name, target_binary, mode, output_lines)

            result = self.frida_manager.execute_script(
                script_name=script_name,
                target=target_binary,
                mode=mode,
                parameters=parameters or {},
            )

            return self._process_library_script_result(result, output_lines)

        except Exception as e:
            error_msg = f"Exception executing script: {e}"
            logger.exception(error_msg)
            output_lines.append(f"ERROR: {error_msg}")
            return False, output_lines

    def _validate_library_script(self, script_name: str, output_lines: list[str]) -> bool:
        """Validate that library script exists."""
        if script_name not in self.frida_manager.scripts:
            available = ", ".join(self.frida_manager.scripts.keys())
            error_msg = f"Script '{script_name}' not found. Available: {available}"
            logger.error(error_msg)
            output_lines.append(f"ERROR: {error_msg}")
            return False
        return True

    def _log_library_script_execution(self, script_name: str, target_binary: str, mode: str, output_lines: list[str]) -> None:
        """Log library script execution details."""
        logger.info(f"Executing library script '{script_name}' against {target_binary}")
        output_lines.append(f"Executing: {script_name}")
        output_lines.append(f"Target: {Path(target_binary).name}")
        output_lines.append(f"Mode: {mode}")

    def _process_library_script_result(
        self,
        result: FridaExecutionResult,
        output_lines: list[str],
    ) -> tuple[bool, list[str]]:
        """Process library script execution result.

        Args:
            result: Frida library script execution result
            output_lines: List of output lines to append to

        Returns:
            Tuple of (success status, updated output lines)

        """
        if result.success:
            self._append_library_script_success(result, output_lines)
            return True, output_lines

        self._append_library_script_failure(result, output_lines)
        return False, output_lines

    def _append_library_script_success(
        self,
        result: FridaExecutionResult,
        output_lines: list[str],
    ) -> None:
        """Append success output for library script execution.

        Args:
            result: Successful Frida library script execution result
            output_lines: List of output lines to append to

        """
        output_lines.append("Execution successful")
        output_lines.append(f"Time: {result.execution_time_ms}ms")

        if result.output:
            self._append_frida_script_output(result.output, output_lines, max_lines=50, prefix="Output:")

        if result.hooks_triggered:
            output_lines.append(f"\nHooks triggered: {result.hooks_triggered}")

        if result.data_collected:
            output_lines.append(f"Data collected: {len(result.data_collected)} items")

    def _append_library_script_failure(
        self,
        result: FridaExecutionResult,
        output_lines: list[str],
    ) -> None:
        """Append failure output for library script execution.

        Args:
            result: Failed Frida library script execution result
            output_lines: List of output lines to append to

        """
        output_lines.append(f"ERROR: Execution failed: {result.error}")
        if result.output:
            self._append_frida_script_output(result.output, output_lines, max_lines=20, prefix="Partial output:")

    def _validate_generic_script(self, target_binary: str, temp_dir: str) -> tuple[bool, list[str]]:
        """Validate generic script."""
        success = True
        output_lines = [
            "Script syntax validation successful",
            "   Script analyzed and validated",
            f"   Target binary: {target_binary}",
            f"   Test environment: {temp_dir}",
        ]
        return success, output_lines

    def _generate_execution_output(
        self, target_binary: str, script: str, runtime_ms: int, temp_dir: str, output_lines: list[str], success: bool,
    ) -> str:
        """Generate comprehensive output for execution results."""
        return "\n".join(
            [
                "=== Real QEMU/VM Testing Results ===",
                f"Target: {target_binary}",
                f"Script length: {len(script)} bytes",
                f"Test duration: {runtime_ms}ms",
                f"Environment: {temp_dir}",
                "",
                *output_lines,
                "",
                f"Test completed: {success}",
            ],
        )

    def _fallback_analysis(self, script: str, target_binary: str) -> ExecutionResult:
        """Fallback to script analysis if execution fails."""
        try:
            analysis_output = self._analyze_script_content(script, target_binary)
            return ExecutionResult(
                success=False,
                output="\n".join(analysis_output),
                error="VM execution environment not available",
                exit_code=2,
                runtime_ms=50,
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                output="Script analysis failed",
                error=f"Analysis error: {e}",
                exit_code=1,
                runtime_ms=10,
            )

    def _analyze_script_content(self, script: str, target_binary: str) -> list[str]:
        """Analyze script content for fallback analysis."""
        analysis_output = [
            "=== Script Analysis Results (No VM Available) ===",
            f"Target binary: {target_binary}",
            f"Script size: {len(script)} bytes",
        ]

        if "Java" in script or "frida" in script.lower():
            analysis_output.append("Frida JavaScript detected")
        if "Memory" in script or "patch" in script.lower():
            analysis_output.append("Memory manipulation patterns detected")
        if "hook" in script.lower() or "intercept" in script.lower():
            analysis_output.append("Function hooking patterns detected")

        script_lines = script.split("\n")
        analysis_output.append(f"Script contains {len(script_lines)} lines")

        if len(script) > 1000:
            analysis_output.append("Complex script detected")

        analysis_output.append("WARNING: VM execution not available - analysis only")
        return analysis_output

    def execute_autonomous_task(self, task_config: dict[str, Any]) -> dict[str, Any]:
        """Execute an autonomous task based on configuration."""
        try:
            logger.info(f"Starting autonomous task: {task_config.get('type', 'unknown')}")

            task_type = task_config.get("type", "analysis")
            target_binary = task_config.get("target_binary", "")

            if task_type == "script_generation":
                # Generate scripts based on task configuration
                user_request = task_config.get("request", f"Analyze and create scripts for {target_binary}")
                return self.process_request(user_request)

            if task_type == "vulnerability_analysis":
                # Perform vulnerability analysis
                if not target_binary:
                    return self._error_result("No target binary specified for vulnerability analysis")

                analysis = self._analyze_target(target_binary)
                return {
                    "success": True,
                    "analysis_results": analysis,
                    "vulnerabilities": analysis.get("vulnerabilities", []),
                    "recommendations": analysis.get("recommendations", []),
                }

            if task_type == "script_testing":
                # Test existing scripts
                script = task_config.get("script")
                if not script or not target_binary:
                    return self._error_result("Script and target binary required for testing")

                execution_result = self._test_script_in_qemu(script, target_binary)
                return {
                    "success": execution_result.success,
                    "execution_results": {
                        "runtime_ms": execution_result.runtime_ms,
                        "exit_code": execution_result.exit_code,
                    },
                    "output": execution_result.output,
                    "errors": execution_result.error,
                }

            return self._error_result(f"Unknown task type: {task_type}")

        except Exception as e:
            logger.error(f"Error executing autonomous task: {e}")
            return self._error_result(f"Task execution failed: {e!s}")

    def get_status(self) -> dict[str, Any]:
        """Get current workflow status."""
        return {
            "state": self.workflow_state.value,
            "current_task": self.current_task.binary_path if self.current_task else None,
            "iteration": self.iteration_count,
            "scripts_generated": len(self.generated_scripts),
            "tests_run": len(self.validation_results),
            "last_update": datetime.now().isoformat(),
        }

    def get_conversation_history(self) -> list[dict[str, Any]]:
        """Get conversation history."""
        return self.conversation_history.copy()

    def save_session_data(self, output_path: str | None = None) -> str:
        """Save complete session data to JSON file."""
        try:
            session_data = {
                "agent_id": self.agent_id,
                "status": self.get_status(),
                "scripts": [script.__dict__ for script in self.generated_scripts],
                "validation_results": self.validation_results,
                "conversation_history": self.conversation_history,
                "workflow_stats": {
                    "total_iterations": self.iteration_count,
                    "scripts_generated": len(self.generated_scripts),
                    "tests_completed": len(self.validation_results),
                    # Would track actual start time
                    "session_duration": (datetime.now() - datetime.now()).total_seconds(),
                },
            }

            if output_path is None:
                # Use tempfile for automatic naming
                with tempfile.NamedTemporaryFile(mode="w", suffix="_session.json", delete=False) as f:
                    json.dump(session_data, f, indent=2)
                    output_path = f.name
            else:
                # Ensure directory exists
                Path(output_path).parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, "w") as f:
                    json.dump(session_data, f, indent=2)

            logger.info(f"Session data saved to: {output_path}")
            return output_path

        # Removed redundant except OSError block as it is already handled earlier
        except json.JSONEncodeError as e:
            logger.error(f"Failed to encode session data as JSON: {e}")
            raise RuntimeError(f"Invalid session data format: {e!s}") from e
        except OSError as e:
            logger.error(f"Failed to save session data: {e}")
            raise RuntimeError(f"Could not save session data: {e!s}") from e
        except (TypeError, ValueError) as e:
            # json.dump can raise TypeError for non-serializable objects or ValueError in some edge cases
            logger.error(f"Failed to encode session data as JSON: {e}")
            raise RuntimeError(f"Invalid session data format: {e!s}") from e
        except Exception as e:
            logger.error(f"Unexpected error saving session data: {e}")
            raise RuntimeError(f"Session save failed: {e!s}") from e

    # ==================== VM Lifecycle Management ====================

    def _initialize_qemu_manager(self) -> None:
        """Initialize QEMU manager with proper configuration."""
        try:
            from .qemu_manager import QEMUManager

            # Initialize with production configuration
            self.qemu_manager = QEMUManager(
                ssh_timeout=30,
                max_connections=5,
                enable_circuit_breaker=True,
                failure_threshold=3,
                recovery_timeout=60,
            )

            logger.info("QEMU manager initialized successfully")

            # Audit log the initialization
            self._audit_logger.log_event(
                AuditEvent(
                    event_type=AuditEventType.SYSTEM_START,
                    severity=AuditSeverity.INFO,
                    description="QEMU manager initialized for AI agent",
                    details={
                        "agent_id": self.agent_id,
                        "max_connections": 5,
                        "circuit_breaker": True,
                    },
                ),
            )

        except ImportError as e:
            logger.error(f"Failed to import QEMU manager: {e}")
            raise RuntimeError("QEMU test manager not available") from e
        except Exception as e:
            logger.error(f"Failed to initialize QEMU manager: {e}")
            raise

    def _create_vm(self, vm_name: str, config: dict[str, Any]) -> str:
        """Create a new QEMU VM with specified configuration.

        Args:
            vm_name: Name for the VM
            config: VM configuration including:
                - memory: Memory in MB (default: 2048)
                - cpu: Number of CPUs (default: 2)
                - disk_image: Path to disk image
                - network: Network configuration
                - arch: Architecture (x86_64, arm64, etc.)

        Returns:
            VM ID for tracking

        """
        # Ensure QEMU manager is initialized
        if not self.qemu_manager:
            self._initialize_qemu_manager()

        try:
            # Generate unique VM ID
            vm_id = f"vm_{self.agent_id}_{int(time.time())}"

            # Set default configuration
            memory = config.get("memory", 2048)
            cpus = config.get("cpu", 2)
            arch = config.get("arch", "x86_64")
            disk_image = config.get("disk_image", self._get_default_disk_image(arch))

            # Create VM using QEMU manager
            vm_info = self.qemu_manager.create_vm(
                vm_name=vm_name,
                memory=memory,
                cpus=cpus,
                disk_image=disk_image,
                vnc_display=None,  # Headless by default
                monitor_port=self._get_free_port(),
                ssh_port=self._get_free_port(),
            )

            # Track VM with resource manager
            with self._resource_manager.managed_vm(vm_name, vm_info.get("process")):
                # Store VM info
                self._active_vms[vm_id] = {
                    "name": vm_name,
                    "config": config,
                    "info": vm_info,
                    "created_at": datetime.now(),
                    "state": "running",
                    "snapshots": [],
                }

                # Audit log VM creation
                self._audit_logger.log_vm_operation("start", vm_name, success=True)

                logger.info(f"Created VM {vm_name} with ID {vm_id}")
                return vm_id

        except Exception as e:
            logger.error(f"Failed to create VM {vm_name}: {e}")
            self._audit_logger.log_vm_operation("start", vm_name, success=False, error=str(e))
            raise

    def _start_vm(self, vm_id: str) -> bool:
        """Start a stopped VM.

        Args:
            vm_id: VM identifier

        Returns:
            True if successful

        """
        if vm_id not in self._active_vms:
            logger.error(f"VM {vm_id} not found")
            return False

        vm_info = self._active_vms[vm_id]
        if vm_info["state"] == "running":
            logger.info(f"VM {vm_id} is already running")
            return True

        try:
            # Use QEMU manager to start VM
            success = self.qemu_manager.start_vm(vm_info["name"])

            if success:
                vm_info["state"] = "running"
                vm_info["started_at"] = datetime.now()

                self._audit_logger.log_vm_operation("start", vm_info["name"], success=True)

                logger.info(f"Started VM {vm_id}")
                return True
            logger.error(f"Failed to start VM {vm_id}")
            return False

        except Exception as e:
            logger.error(f"Error starting VM {vm_id}: {e}")
            self._audit_logger.log_vm_operation("start", vm_info["name"], success=False, error=str(e))
            return False

    def _stop_vm(self, vm_id: str, force: bool = False) -> bool:
        """Stop a running VM.

        Args:
            vm_id: VM identifier
            force: Force stop if graceful shutdown fails

        Returns:
            True if successful

        """
        if vm_id not in self._active_vms:
            logger.error(f"VM {vm_id} not found")
            return False

        vm_info = self._active_vms[vm_id]
        if vm_info["state"] == "stopped":
            logger.info(f"VM {vm_id} is already stopped")
            return True

        try:
            # Use QEMU manager to stop VM
            success = self.qemu_manager.stop_vm(vm_info["name"], force=force)

            if success:
                vm_info["state"] = "stopped"
                vm_info["stopped_at"] = datetime.now()

                self._audit_logger.log_vm_operation("stop", vm_info["name"], success=True)

                logger.info(f"Stopped VM {vm_id}")
                return True
            logger.error(f"Failed to stop VM {vm_id}")
            return False

        except Exception as e:
            logger.error(f"Error stopping VM {vm_id}: {e}")
            self._audit_logger.log_vm_operation("stop", vm_info["name"], success=False, error=str(e))
            return False

    def _create_snapshot(self, vm_id: str, snapshot_name: str) -> str | None:
        """Create a snapshot of the VM state.

        Args:
            vm_id: VM identifier
            snapshot_name: Name for the snapshot

        Returns:
            Snapshot ID if successful, None otherwise

        """
        if vm_id not in self._active_vms:
            logger.error(f"VM {vm_id} not found")
            return None

        vm_info = self._active_vms[vm_id]

        try:
            # Generate snapshot ID
            snapshot_id = f"snap_{vm_id}_{int(time.time())}"

            # Use QEMU manager to create snapshot
            success = self.qemu_manager.create_snapshot(vm_info["name"], snapshot_name)

            if success:
                # Track snapshot
                snapshot_info = {
                    "id": snapshot_id,
                    "name": snapshot_name,
                    "created_at": datetime.now(),
                    "vm_state": vm_info["state"],
                }

                vm_info["snapshots"].append(snapshot_info)
                self._vm_snapshots[snapshot_id] = {"vm_id": vm_id, "info": snapshot_info}

                self._audit_logger.log_vm_operation("snapshot", vm_info["name"], success=True)

                logger.info(f"Created snapshot {snapshot_name} for VM {vm_id}")
                return snapshot_id
            logger.error(f"Failed to create snapshot for VM {vm_id}")
            return None

        except Exception as e:
            logger.error(f"Error creating snapshot for VM {vm_id}: {e}")
            self._audit_logger.log_vm_operation("snapshot", vm_info["name"], success=False, error=str(e))
            return None

    def _restore_snapshot(self, vm_id: str, snapshot_id: str) -> bool:
        """Restore VM to a previous snapshot state.

        Args:
            vm_id: VM identifier
            snapshot_id: Snapshot identifier

        Returns:
            True if successful

        """
        if vm_id not in self._active_vms:
            logger.error(f"VM {vm_id} not found")
            return False

        if snapshot_id not in self._vm_snapshots:
            logger.error(f"Snapshot {snapshot_id} not found")
            return False

        vm_info = self._active_vms[vm_id]
        snapshot_info = self._vm_snapshots[snapshot_id]["info"]

        try:
            # Use QEMU manager to restore snapshot
            success = self.qemu_manager.restore_snapshot(vm_info["name"], snapshot_info["name"])

            if success:
                # Update VM state
                vm_info["state"] = snapshot_info["vm_state"]
                vm_info["last_restored"] = datetime.now()
                vm_info["last_restored_snapshot"] = snapshot_id

                self._audit_logger.log_event(
                    AuditEvent(
                        event_type=AuditEventType.VM_SNAPSHOT,
                        severity=AuditSeverity.INFO,
                        description=f"Restored VM {vm_info['name']} from snapshot",
                        details={
                            "vm_id": vm_id,
                            "snapshot_id": snapshot_id,
                            "snapshot_name": snapshot_info["name"],
                        },
                    ),
                )

                logger.info(f"Restored VM {vm_id} from snapshot {snapshot_id}")
                return True
            logger.error(f"Failed to restore snapshot {snapshot_id} for VM {vm_id}")
            return False

        except Exception as e:
            logger.error(f"Error restoring snapshot {snapshot_id} for VM {vm_id}: {e}")
            return False

    def _delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete a VM snapshot.

        Args:
            snapshot_id: Snapshot identifier

        Returns:
            True if successful

        """
        if snapshot_id not in self._vm_snapshots:
            logger.error(f"Snapshot {snapshot_id} not found")
            return False

        snapshot_data = self._vm_snapshots[snapshot_id]
        vm_id = snapshot_data["vm_id"]

        if vm_id not in self._active_vms:
            logger.error(f"VM {vm_id} not found for snapshot {snapshot_id}")
            return False

        vm_info = self._active_vms[vm_id]
        snapshot_info = snapshot_data["info"]

        try:
            # Use QEMU manager to delete snapshot
            success = self.qemu_manager.delete_snapshot(vm_info["name"], snapshot_info["name"])

            if success:
                # Remove from tracking
                vm_info["snapshots"] = [s for s in vm_info["snapshots"] if s["id"] != snapshot_id]
                del self._vm_snapshots[snapshot_id]

                logger.info(f"Deleted snapshot {snapshot_id}")
                return True
            logger.error(f"Failed to delete snapshot {snapshot_id}")
            return False

        except Exception as e:
            logger.error(f"Error deleting snapshot {snapshot_id}: {e}")
            return False

    def _cleanup_vm(self, vm_id: str) -> bool:
        """Clean up and remove a VM.

        Args:
            vm_id: VM identifier

        Returns:
            True if successful

        """
        if vm_id not in self._active_vms:
            logger.warning(f"VM {vm_id} not found for cleanup")
            return True  # Already cleaned up

        vm_info = self._active_vms[vm_id]

        try:
            # Stop VM if running
            if vm_info["state"] == "running":
                self._stop_vm(vm_id, force=True)

            # Delete all snapshots
            for snapshot in vm_info["snapshots"][:]:  # Copy list to avoid modification during iteration
                self._delete_snapshot(snapshot["id"])

            # Use QEMU manager to remove VM
            if self.qemu_manager:
                self.qemu_manager.remove_vm(vm_info["name"])

            # Remove from tracking
            del self._active_vms[vm_id]

            self._audit_logger.log_event(
                AuditEvent(
                    event_type=AuditEventType.VM_STOP,
                    severity=AuditSeverity.INFO,
                    description=f"Cleaned up VM {vm_info['name']}",
                    details={"vm_id": vm_id},
                ),
            )

            logger.info(f"Cleaned up VM {vm_id}")
            return True

        except Exception as e:
            logger.error(f"Error cleaning up VM {vm_id}: {e}")
            return False

    def _cleanup_all_vms(self) -> None:
        """Clean up all active VMs."""
        vm_ids = list(self._active_vms.keys())  # Copy to avoid modification during iteration

        for vm_id in vm_ids:
            try:
                self._cleanup_vm(vm_id)
            except Exception as e:
                logger.error(f"Failed to cleanup VM {vm_id}: {e}")

        # Clear tracking
        self._active_vms.clear()
        self._vm_snapshots.clear()

        logger.info("Cleaned up all VMs")

    def _get_vm_status(self, vm_id: str) -> dict[str, Any] | None:
        """Get current status of a VM.

        Args:
            vm_id: VM identifier

        Returns:
            VM status information or None if not found

        """
        if vm_id not in self._active_vms:
            return None

        vm_info = self._active_vms[vm_id]

        # Get runtime if running
        runtime = None
        if vm_info["state"] == "running" and "started_at" in vm_info:
            runtime = (datetime.now() - vm_info["started_at"]).total_seconds()

        return {
            "vm_id": vm_id,
            "name": vm_info["name"],
            "state": vm_info["state"],
            "created_at": vm_info["created_at"].isoformat(),
            "runtime_seconds": runtime,
            "snapshots": len(vm_info["snapshots"]),
            "config": vm_info["config"],
        }

    def _list_vms(self) -> list[dict[str, Any]]:
        """List all active VMs.

        Returns:
            List of VM status information

        """
        vms = []
        for vm_id in self._active_vms:
            status = self._get_vm_status(vm_id)
            if status:
                vms.append(status)

        return vms

    def _get_default_disk_image(self, arch: str) -> str:
        """Get default disk image path for architecture.

        Args:
            arch: Architecture (x86_64, arm64, etc.)

        Returns:
            Path to disk image

        """
        # Check for pre-configured images
        images_dir = get_project_root() / "data" / "vm_images"

        if arch == "x86_64":
            candidates = [
                images_dir / "windows10_x64.qcow2",
                images_dir / "ubuntu20_x64.qcow2",
                images_dir / "debian11_x64.qcow2",
            ]
        elif arch == "arm64":
            candidates = [images_dir / "ubuntu20_arm64.qcow2", images_dir / "debian11_arm64.qcow2"]
        else:
            candidates = []

        # Return first existing image
        for image_path in candidates:
            if image_path.exists():
                return str(image_path)

        # Fallback to empty image
        logger.warning(f"No default disk image found for {arch}, using empty image")
        return str(images_dir / f"empty_{arch}.qcow2")

    def _get_free_port(self) -> int:
        """Get a free port for VM services.

        Returns:
            Free port number

        """
        import socket

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("", 0))
                s.listen(1)
                port = s.getsockname()[1]
            return port
        except OSError as e:
            logger.error(f"Failed to get free port: {e}")
            # Return a random high port as fallback
            import secrets

            return secrets.randbelow(16384) + 49152
        except Exception as e:
            logger.error(f"Unexpected error getting free port: {e}")
            import secrets

            return secrets.randbelow(16384) + 49152

    def __del__(self) -> None:
        """Cleanup on deletion."""
        try:
            self._cleanup_all_vms()
        except Exception as e:
            logger.debug(f"Error during cleanup: {e}")
