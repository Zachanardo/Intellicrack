"""Radare2 Scripting Integration Engine.

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

import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ...utils.tools.radare2_utils import R2Exception, r2_session


logger = logging.getLogger(__name__)

try:
    from ...core.terminal_manager import get_terminal_manager

    HAS_TERMINAL_MANAGER = True
except ImportError:
    HAS_TERMINAL_MANAGER = False
    logger.warning("Terminal manager not available for radare2 scripting")


class R2ScriptingEngine:
    """Advanced radare2 scripting integration engine.

    Provides comprehensive scripting capabilities including:
    - r2pipe script execution
    - Custom r2 command sequences
    - JavaScript/Python script integration
    - Automated analysis workflows
    - Custom function analysis scripts
    - License validation script generation
    - Vulnerability detection scripts
    """

    def __init__(self, binary_path: str, radare2_path: str | None = None) -> None:
        """Initialize scripting engine."""
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)
        self.script_cache = {}

    def execute_custom_analysis(self, script_commands: list[str]) -> dict[str, Any]:
        """Execute custom analysis using r2 commands."""
        result = {
            "binary_path": self.binary_path,
            "commands_executed": script_commands,
            "command_results": [],
            "analysis_summary": {},
            "execution_time": 0,
            "errors": [],
        }

        try:
            with r2_session(self.binary_path, self.radare2_path) as r2:
                import time

                start_time = time.time()

                for i, command in enumerate(script_commands):
                    try:
                        # Execute command
                        if command.endswith("j"):  # JSON output expected
                            cmd_result = r2._execute_command(command, expect_json=True)
                        else:
                            cmd_result = r2._execute_command(command)

                        result["command_results"].append(
                            {
                                "command": command,
                                "result": cmd_result,
                                "success": True,
                                "index": i,
                            },
                        )

                    except R2Exception as e:
                        logger.error("R2Exception in radare2_scripting: %s", e)
                        result["command_results"].append(
                            {
                                "command": command,
                                "error": str(e),
                                "success": False,
                                "index": i,
                            },
                        )
                        result["errors"].append(f"Command {i}: {command} failed: {e}")

                result["execution_time"] = time.time() - start_time
                result["analysis_summary"] = self._generate_analysis_summary(result["command_results"])

        except R2Exception as e:
            result["error"] = str(e)
            self.logger.error(f"Script execution failed: {e}")

        return result

    def generate_license_analysis_script(self) -> list[str]:
        """Generate license analysis command sequence."""
        return [
            # Basic analysis
            "aaa",
            # Get function information
            "aflj",
            # Search for license-related strings
            "/j license",
            "/j registration",
            "/j trial",
            "/j serial",
            "/j key",
            "/j activation",
            "/j valid",
            # Get imports that might be license-related
            "iij",
            # Search for crypto functions
            "/j crypt",
            "/j encrypt",
            "/j decrypt",
            "/j hash",
            # Get all strings for analysis
            "izzj",
            # Look for registry operations
            "/j RegOpenKey",
            "/j RegQueryValue",
            "/j RegSetValue",
            # Check for time-based operations
            "/j GetSystemTime",
            "/j GetLocalTime",
            # Look for hardware fingerprinting
            "/j GetVolumeInformation",
            "/j GetComputerName",
            # Get section information
            "iSj",
            # Check for anti-debug
            "/j IsDebuggerPresent",
            "/j CheckRemoteDebugger",
        ]

    def generate_vulnerability_analysis_script(self) -> list[str]:
        """Generate vulnerability analysis command sequence."""
        return [
            # Comprehensive analysis
            "aaaa",
            # Get all functions
            "aflj",
            # Search for dangerous functions
            "/j strcpy",
            "/j strcat",
            "/j sprintf",
            "/j gets",
            "/j scanf",
            "/j memcpy",
            # Format string vulnerabilities
            "/j printf",
            "/j fprintf",
            "/j snprintf",
            # Memory management
            "/j malloc",
            "/j free",
            "/j realloc",
            "/j calloc",
            # Process injection APIs
            "/j VirtualAllocEx",
            "/j WriteProcessMemory",
            "/j CreateRemoteThread",
            # Privilege escalation
            "/j AdjustTokenPrivileges",
            "/j ImpersonateLoggedOnUser",
            # Network functions
            "/j socket",
            "/j connect",
            "/j send",
            "/j recv",
            # File operations
            "/j CreateFile",
            "/j ReadFile",
            "/j WriteFile",
            # Get import information
            "iij",
            # Get export information
            "iEj",
            # Check security features
            "ij~canary",
            "ij~nx",
            "ij~pic",
        ]

    def execute_license_analysis_workflow(self) -> dict[str, Any]:
        """Execute comprehensive license analysis workflow."""
        workflow_result = {
            "workflow_type": "license_analysis",
            "binary_path": self.binary_path,
            "license_functions": [],
            "license_strings": [],
            "license_imports": [],
            "crypto_usage": [],
            "validation_mechanisms": [],
            "bypass_opportunities": [],
            "analysis_confidence": 0.0,
        }

        try:
            # Generate and execute license analysis script
            script_commands = self.generate_license_analysis_script()
            execution_result = self.execute_custom_analysis(script_commands)

            if execution_result.get("error"):
                workflow_result["error"] = execution_result["error"]
                return workflow_result

            # Process results
            command_results = execution_result.get("command_results", [])

            # Extract license functions
            workflow_result["license_functions"] = self._extract_license_functions(command_results)

            # Extract license strings
            workflow_result["license_strings"] = self._extract_license_strings(command_results)

            # Extract license-related imports
            workflow_result["license_imports"] = self._extract_license_imports(command_results)

            # Extract crypto usage
            workflow_result["crypto_usage"] = self._extract_crypto_usage(command_results)

            # Identify validation mechanisms
            workflow_result["validation_mechanisms"] = self._identify_validation_mechanisms(command_results)

            # Find bypass opportunities
            workflow_result["bypass_opportunities"] = self._find_bypass_opportunities(workflow_result)

            # Calculate confidence
            workflow_result["analysis_confidence"] = self._calculate_analysis_confidence(workflow_result)

        except Exception as e:
            workflow_result["error"] = str(e)
            self.logger.error(f"License analysis workflow failed: {e}")

        return workflow_result

    def execute_vulnerability_analysis_workflow(self) -> dict[str, Any]:
        """Execute comprehensive vulnerability analysis workflow."""
        workflow_result = {
            "workflow_type": "vulnerability_analysis",
            "binary_path": self.binary_path,
            "buffer_overflow_risks": [],
            "format_string_risks": [],
            "memory_corruption_risks": [],
            "injection_risks": [],
            "privilege_escalation_risks": [],
            "network_security_risks": [],
            "overall_risk_score": 0.0,
            "security_recommendations": [],
        }

        try:
            # Generate and execute vulnerability analysis script
            script_commands = self.generate_vulnerability_analysis_script()
            execution_result = self.execute_custom_analysis(script_commands)

            if execution_result.get("error"):
                workflow_result["error"] = execution_result["error"]
                return workflow_result

            command_results = execution_result.get("command_results", [])

            # Analyze for different vulnerability types
            workflow_result["buffer_overflow_risks"] = self._analyze_buffer_overflow_risks(command_results)
            workflow_result["format_string_risks"] = self._analyze_format_string_risks(command_results)
            workflow_result["memory_corruption_risks"] = self._analyze_memory_corruption_risks(command_results)
            workflow_result["injection_risks"] = self._analyze_injection_risks(command_results)
            workflow_result["privilege_escalation_risks"] = self._analyze_privilege_escalation_risks(command_results)
            workflow_result["network_security_risks"] = self._analyze_network_security_risks(command_results)

            # Calculate overall risk score
            workflow_result["overall_risk_score"] = self._calculate_risk_score(workflow_result)

            # Generate security recommendations
            workflow_result["security_recommendations"] = self._generate_security_recommendations(workflow_result)

        except Exception as e:
            workflow_result["error"] = str(e)
            self.logger.error(f"Vulnerability analysis workflow failed: {e}")

        return workflow_result

    def create_custom_r2_script(self, script_name: str, commands: list[str], description: str = "") -> str:
        """Create custom r2 script file."""
        script_content = f"""#!/usr/bin/env r2
# {script_name}
# {description}
# Generated by Intellicrack R2 Scripting Engine

"""

        for command in commands:
            script_content += f"{command}\n"

        # Save script to temporary file
        script_dir = tempfile.gettempdir()
        script_path = os.path.join(script_dir, f"{script_name}.r2")

        try:
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(script_content)

            # Make script executable on Unix systems
            if os.name != "nt":
                Path(script_path).chmod(0o700)  # Owner-only executable script

            self.logger.info(f"Created r2 script: {script_path}")
            return script_path

        except Exception as e:
            self.logger.error(f"Failed to create script: {e}")
            raise

    def execute_r2_script_file(self, script_path: str, use_terminal: bool = False) -> dict[str, Any]:
        """Execute r2 script file.

        Args:
            script_path: Path to r2 script file
            use_terminal: If True, display output in terminal (default: False)

        Returns:
            Dictionary with execution results

        """
        result = {
            "script_path": script_path,
            "output": "",
            "errors": "",
            "return_code": 0,
            "execution_successful": False,
        }

        try:
            # Construct r2 command to execute script
            cmd = [
                self.radare2_path or "radare2",
                "-q",  # Quiet mode
                "-c",
                f". {script_path}",  # Execute script
                self.binary_path,
            ]

            # Execute command
            if use_terminal and HAS_TERMINAL_MANAGER:
                logger.info(f"Running r2 script in terminal: {script_path}")
                terminal_mgr = get_terminal_manager()

                # Show r2 execution in terminal
                session_id = terminal_mgr.execute_command(command=cmd, capture_output=False, auto_switch=True)

                # For terminal execution, return session info
                result["terminal_session"] = session_id
                result["execution_successful"] = True
                result["output"] = "Script running in terminal"
            else:
                # Standard execution with captured output
                process = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minute timeout
                )

                result["output"] = process.stdout
                result["errors"] = process.stderr
                result["return_code"] = process.returncode
                result["execution_successful"] = process.returncode == 0

        except subprocess.TimeoutExpired as e:
            logger.error("Subprocess timeout in radare2_scripting: %s", e)
            result["errors"] = "Script execution timed out"
        except Exception as e:
            result["errors"] = str(e)
            self.logger.error(f"Script execution failed: {e}")

        return result

    def generate_function_analysis_script(self, function_name: str) -> list[str]:
        """Generate script for detailed function analysis."""
        return [
            f"s {function_name}",  # Seek to function
            "pdf",  # Print disassembly of function
            "pdc",  # Print decompiled function
            "afi",  # Analyze function information
            "afvj",  # Get function variables in JSON
            "agfj",  # Get function graph in JSON
            "axtj",  # Get cross-references to function
            "axfj",  # Get cross-references from function
        ]

    def analyze_specific_function(self, function_name: str) -> dict[str, Any]:
        """Perform detailed analysis of specific function."""
        result = {
            "function_name": function_name,
            "disassembly": "",
            "decompiled_code": "",
            "function_info": {},
            "variables": [],
            "control_flow_graph": {},
            "cross_references_to": [],
            "cross_references_from": [],
            "analysis_insights": {},
        }

        try:
            # Generate function analysis script
            script_commands = self.generate_function_analysis_script(function_name)
            execution_result = self.execute_custom_analysis(script_commands)

            if execution_result.get("error"):
                result["error"] = execution_result["error"]
                return result

            command_results = execution_result.get("command_results", [])

            # Extract results
            for cmd_result in command_results:
                command = cmd_result.get("command", "")
                cmd_output = cmd_result.get("result", "")

                if command == "pdf":
                    result["disassembly"] = cmd_output
                elif command == "pdc":
                    result["decompiled_code"] = cmd_output
                elif command == "afi":
                    result["function_info"] = self._parse_function_info(cmd_output)
                elif command == "afvj":
                    result["variables"] = cmd_output if isinstance(cmd_output, list) else []
                elif command == "agfj":
                    result["control_flow_graph"] = cmd_output if isinstance(cmd_output, dict) else {}
                elif command == "axtj":
                    result["cross_references_to"] = cmd_output if isinstance(cmd_output, list) else []
                elif command == "axfj":
                    result["cross_references_from"] = cmd_output if isinstance(cmd_output, list) else []

            # Generate analysis insights
            result["analysis_insights"] = self._generate_function_insights(result)

        except Exception as e:
            result["error"] = str(e)
            self.logger.error(f"Function analysis failed: {e}")

        return result

    def create_automated_patcher_script(self, patches: list[dict[str, Any]]) -> str:
        """Create automated binary patcher script."""
        script_commands = [
            "# Automated Binary Patcher Script",
            "# Generated by Intellicrack",
            "",
            "aaa  # Analyze all",
            "",
        ]

        for i, patch in enumerate(patches):
            address = patch.get("address", "0x0")
            patch_bytes = patch.get("patch_bytes", "")
            description = patch.get("description", f"Patch {i + 1}")

            script_commands.extend(
                [
                    f"# {description}",
                    f"s {address}",
                    f"wx {patch_bytes}",
                    f"# Patched at {address}",
                    "",
                ],
            )

        script_commands.extend(
            [
                "# Save patched binary",
                "wtf patched_binary",
                "q",
            ],
        )

        return self.create_custom_r2_script("autopatcher", script_commands, "Automated binary patcher")

    def create_license_validator_script(self, validation_points: list[dict[str, Any]]) -> str:
        """Create license validation analysis script."""
        script_commands = [
            "# License Validation Analysis Script",
            "# Generated by Intellicrack",
            "",
            "aaa  # Analyze all",
            "",
        ]

        for point in validation_points:
            function_name = point.get("function_name", "")
            address = point.get("address", "")

            if function_name:
                # Use both function name and address for comprehensive analysis
                location_info = f"{function_name}"
                if address:
                    location_info += f" at {address}"

                script_commands.extend(
                    [
                        f"# Analyzing function: {location_info}",
                        f"s {function_name}",
                        "pdf",  # Disassemble
                        "pdc",  # Decompile
                        "afi",  # Function info
                        "/j license",  # Search for license strings
                        "/j valid",  # Search for validation strings
                        "/j key",  # Search for key strings
                        "",
                    ],
                )

                # If we have an address, add direct address analysis
                if address:
                    script_commands.extend(
                        [
                            f"# Direct address analysis for {address}",
                            f"s {address}",
                            "pd 20",  # Print disassembly at address
                            "px 64",  # Print hex dump
                            f"axf @ {address}",  # Cross-references from this address
                            "",
                        ],
                    )

        script_commands.extend(
            [
                "# Search for license-related imports",
                "ii~license",
                "ii~crypt",
                "ii~reg",
                "",
                "# Generate summary",
                "aflj",  # List all functions
                "q",
            ],
        )

        return self.create_custom_r2_script("license_analyzer", script_commands, "License validation analysis")

    # Helper methods for result processing
    def _generate_analysis_summary(self, command_results: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate summary of analysis results."""
        successful_commands = [r for r in command_results if r.get("success", False)]
        failed_commands = [r for r in command_results if not r.get("success", False)]

        return {
            "total_commands": len(command_results),
            "successful_commands": len(successful_commands),
            "failed_commands": len(failed_commands),
            "success_rate": len(successful_commands) / max(1, len(command_results)),
            "commands_with_results": len([r for r in successful_commands if r.get("result")]),
        }

    def _extract_license_functions(self, command_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Extract license-related functions from command results."""
        license_functions = []

        # Get function list
        functions_result = next((r for r in command_results if r.get("command") == "aflj"), None)
        if functions_result and functions_result.get("success"):
            functions = functions_result.get("result", [])
            if isinstance(functions, list):
                for func in functions:
                    func_name = func.get("name", "").lower()
                    if any(keyword in func_name for keyword in ["license", "valid", "check", "trial", "register"]):
                        license_functions.append(
                            {
                                "name": func.get("name", ""),
                                "address": hex(func.get("offset", 0)),
                                "size": func.get("size", 0),
                                "type": "license_related",
                            },
                        )

        return license_functions

    def _extract_license_strings(self, command_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Extract license-related strings from command results."""
        license_strings = []

        # Search results for license-related terms
        license_keywords = [
            "license",
            "registration",
            "trial",
            "serial",
            "key",
            "activation",
            "valid",
        ]

        for keyword in license_keywords:
            search_result = next((r for r in command_results if r.get("command") == f"/j {keyword}"), None)
            if search_result and search_result.get("success"):
                results = search_result.get("result", [])
                if isinstance(results, list):
                    license_strings.extend(
                        {
                            "keyword": keyword,
                            "address": hex(result.get("offset", 0)),
                            "context": "string_search",
                        }
                        for result in results
                    )
        return license_strings

    def _extract_license_imports(self, command_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Extract license-related imports from command results."""
        license_imports = []

        # Get imports
        imports_result = next((r for r in command_results if r.get("command") == "iij"), None)
        if imports_result and imports_result.get("success"):
            imports = imports_result.get("result", [])
            if isinstance(imports, list):
                license_api_keywords = ["reg", "crypt", "time", "volume", "computer"]

                for imp in imports:
                    imp_name = imp.get("name", "").lower()
                    if any(keyword in imp_name for keyword in license_api_keywords):
                        license_imports.append(
                            {
                                "name": imp.get("name", ""),
                                "library": imp.get("libname", ""),
                                "type": "license_related_api",
                            },
                        )

        return license_imports

    def _extract_crypto_usage(self, command_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Extract cryptographic usage from command results."""
        crypto_usage = []

        crypto_keywords = ["crypt", "encrypt", "decrypt", "hash"]

        for keyword in crypto_keywords:
            search_result = next((r for r in command_results if r.get("command") == f"/j {keyword}"), None)
            if search_result and search_result.get("success"):
                results = search_result.get("result", [])
                if isinstance(results, list) and results:
                    crypto_usage.append(
                        {
                            "algorithm_type": keyword,
                            "occurrences": len(results),
                            "addresses": [hex(r.get("offset", 0)) for r in results[:5]],  # Limit to 5
                        },
                    )

        return crypto_usage

    def _identify_validation_mechanisms(self, command_results: list[dict[str, Any]]) -> list[str]:
        """Identify validation mechanisms from command results."""
        mechanisms = []

        # Check for registry operations
        if any(
            r.get("command") in ["/j RegOpenKey", "/j RegQueryValue", "/j RegSetValue"] and r.get("success") and r.get("result")
            for r in command_results
        ):
            mechanisms.append("registry_validation")

        # Check for time operations
        if any(
            r.get("command") in ["/j GetSystemTime", "/j GetLocalTime"] and r.get("success") and r.get("result") for r in command_results
        ):
            mechanisms.append("time_based_validation")

        # Check for hardware fingerprinting
        if any(
            r.get("command") in ["/j GetVolumeInformation", "/j GetComputerName"] and r.get("success") and r.get("result")
            for r in command_results
        ):
            mechanisms.append("hardware_fingerprinting")

        # Check for crypto validation
        crypto_results = [r for r in command_results if "/j crypt" in r.get("command", "") and r.get("success") and r.get("result")]
        if crypto_results:
            mechanisms.append("cryptographic_validation")

        return mechanisms

    def _find_bypass_opportunities(self, workflow_result: dict[str, Any]) -> list[dict[str, Any]]:
        """Find bypass opportunities based on analysis."""
        license_functions = workflow_result.get("license_functions", [])
        validation_mechanisms = workflow_result.get("validation_mechanisms", [])

        opportunities = [
            {
                "type": "function_patch",
                "target": func["name"],
                "address": func["address"],
                "method": "nop_function_or_force_return_true",
                "difficulty": "easy",
                "success_probability": 0.9,
            }
            for func in license_functions
        ]
        # Registry bypass opportunities
        if "registry_validation" in validation_mechanisms:
            opportunities.append(
                {
                    "type": "registry_bypass",
                    "target": "registry_operations",
                    "method": "inject_license_registry_entries",
                    "difficulty": "easy",
                    "success_probability": 0.95,
                },
            )

        # Time bypass opportunities
        if "time_based_validation" in validation_mechanisms:
            opportunities.append(
                {
                    "type": "time_bypass",
                    "target": "time_checks",
                    "method": "hook_time_functions",
                    "difficulty": "medium",
                    "success_probability": 0.8,
                },
            )

        return opportunities

    def _calculate_analysis_confidence(self, workflow_result: dict[str, Any]) -> float:
        """Calculate confidence in analysis results."""
        # Number of license functions found
        license_functions = len(workflow_result.get("license_functions", []))
        # Number of license strings found
        license_strings = len(workflow_result.get("license_strings", []))
        confidence_factors = [
            min(1.0, license_functions / 5.0),
            min(1.0, license_strings / 10.0),
        ]
        # Number of validation mechanisms identified
        validation_mechanisms = len(workflow_result.get("validation_mechanisms", []))
        confidence_factors.append(min(1.0, validation_mechanisms / 3.0))

        # Average confidence
        return sum(confidence_factors) / max(1, len(confidence_factors))

    def _analyze_buffer_overflow_risks(self, command_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Analyze buffer overflow risks from command results."""
        risks = []

        dangerous_functions = ["strcpy", "strcat", "sprintf", "gets", "scanf", "memcpy"]

        for func_name in dangerous_functions:
            search_result = next((r for r in command_results if r.get("command") == f"/j {func_name}"), None)
            if search_result and search_result.get("success"):
                results = search_result.get("result", [])
                if isinstance(results, list) and results:
                    risks.append(
                        {
                            "function": func_name,
                            "risk_level": "high",
                            "occurrences": len(results),
                            "addresses": [hex(r.get("offset", 0)) for r in results[:3]],
                        },
                    )

        return risks

    def _analyze_format_string_risks(self, command_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Analyze format string risks from command results."""
        risks = []

        format_functions = ["printf", "fprintf", "snprintf"]

        for func_name in format_functions:
            search_result = next((r for r in command_results if r.get("command") == f"/j {func_name}"), None)
            if search_result and search_result.get("success"):
                results = search_result.get("result", [])
                if isinstance(results, list) and results:
                    risks.append(
                        {
                            "function": func_name,
                            "risk_level": "medium",
                            "occurrences": len(results),
                            "description": "Potential format string vulnerability",
                        },
                    )

        return risks

    def _analyze_memory_corruption_risks(self, command_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Analyze memory corruption risks from command results."""
        risks = []

        memory_functions = ["malloc", "free", "realloc", "calloc"]

        for func_name in memory_functions:
            search_result = next((r for r in command_results if r.get("command") == f"/j {func_name}"), None)
            if search_result and search_result.get("success"):
                results = search_result.get("result", [])
                if isinstance(results, list) and results:
                    risks.append(
                        {
                            "function": func_name,
                            "risk_level": "medium",
                            "occurrences": len(results),
                            "description": "Memory management function usage",
                        },
                    )

        return risks

    def _analyze_injection_risks(self, command_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Analyze code injection risks from command results."""
        risks = []

        injection_functions = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]

        for func_name in injection_functions:
            search_result = next((r for r in command_results if r.get("command") == f"/j {func_name}"), None)
            if search_result and search_result.get("success"):
                results = search_result.get("result", [])
                if isinstance(results, list) and results:
                    risks.append(
                        {
                            "function": func_name,
                            "risk_level": "critical",
                            "occurrences": len(results),
                            "description": "Code injection capability detected",
                        },
                    )

        return risks

    def _analyze_privilege_escalation_risks(self, command_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Analyze privilege escalation risks from command results."""
        risks = []

        priv_functions = ["AdjustTokenPrivileges", "ImpersonateLoggedOnUser"]

        for func_name in priv_functions:
            search_result = next((r for r in command_results if r.get("command") == f"/j {func_name}"), None)
            if search_result and search_result.get("success"):
                results = search_result.get("result", [])
                if isinstance(results, list) and results:
                    risks.append(
                        {
                            "function": func_name,
                            "risk_level": "high",
                            "occurrences": len(results),
                            "description": "Privilege escalation capability",
                        },
                    )

        return risks

    def _analyze_network_security_risks(self, command_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Analyze network security risks from command results."""
        risks = []

        network_functions = ["socket", "connect", "send", "recv"]

        for func_name in network_functions:
            search_result = next((r for r in command_results if r.get("command") == f"/j {func_name}"), None)
            if search_result and search_result.get("success"):
                results = search_result.get("result", [])
                if isinstance(results, list) and results:
                    risks.append(
                        {
                            "function": func_name,
                            "risk_level": "medium",
                            "occurrences": len(results),
                            "description": "Network communication capability",
                        },
                    )

        return risks

    def _calculate_risk_score(self, workflow_result: dict[str, Any]) -> float:
        """Calculate overall risk score."""
        risk_weights = {
            "buffer_overflow_risks": 3.0,
            "format_string_risks": 2.5,
            "injection_risks": 4.0,
            "privilege_escalation_risks": 3.5,
            "memory_corruption_risks": 2.0,
            "network_security_risks": 1.5,
        }

        total_score = 0.0
        max_possible_score = 0.0

        for risk_type, weight in risk_weights.items():
            risks = workflow_result.get(risk_type, [])
            risk_count = len(risks)

            # Calculate weighted score
            total_score += risk_count * weight
            max_possible_score += 10 * weight  # Assume max 10 risks per type

        # Normalize to 0-1 scale
        return min(1.0, total_score / max_possible_score) if max_possible_score > 0 else 0.0

    def _generate_security_recommendations(self, workflow_result: dict[str, Any]) -> list[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []

        if workflow_result.get("buffer_overflow_risks"):
            recommendations.extend((
                "Replace unsafe string functions with safe alternatives",
                "Enable stack canaries and DEP/NX protection",
            ))
        if workflow_result.get("format_string_risks"):
            recommendations.extend((
                "Use format string literals instead of variables",
                "Enable format string protection compiler flags",
            ))
        if workflow_result.get("injection_risks"):
            recommendations.extend((
                "Review process injection capabilities for legitimacy",
                "Implement strict input validation",
            ))
        if workflow_result.get("privilege_escalation_risks"):
            recommendations.extend((
                "Review privilege escalation code for necessity",
                "Implement least privilege principle",
            ))
        if workflow_result.get("overall_risk_score", 0) > 0.7:
            recommendations.append("Comprehensive security audit recommended")

        return recommendations

    def _parse_function_info(self, function_info_output: str) -> dict[str, Any]:
        """Parse function info output."""
        info = {}

        lines = function_info_output.split("\n")
        for line in lines:
            if ":" in line:
                key, value = line.split(":", 1)
                info[key.strip()] = value.strip()

        return info

    def _generate_function_insights(self, function_result: dict[str, Any]) -> dict[str, Any]:
        """Generate insights for function analysis."""
        insights = {
            "complexity": "unknown",
            "potential_issues": [],
            "interesting_features": [],
        }

        if decompiled := function_result.get("decompiled_code", ""):
            if len(decompiled.split("\n")) > 50:
                insights["complexity"] = "high"
            elif len(decompiled.split("\n")) > 20:
                insights["complexity"] = "medium"
            else:
                insights["complexity"] = "low"

            # Check for potential issues
            if any(keyword in decompiled.lower() for keyword in ["strcpy", "sprintf", "gets"]):
                insights["potential_issues"].append("unsafe_string_functions")

            if "malloc" in decompiled.lower() and "free" not in decompiled.lower():
                insights["potential_issues"].append("potential_memory_leak")

            # Check for interesting features
            if any(keyword in decompiled.lower() for keyword in ["license", "key", "valid"]):
                insights["interesting_features"].append("license_related_code")

            if any(keyword in decompiled.lower() for keyword in ["crypt", "hash", "encrypt"]):
                insights["interesting_features"].append("cryptographic_operations")

        return insights


def execute_license_analysis_script(binary_path: str, radare2_path: str | None = None) -> dict[str, Any]:
    """Execute license analysis workflow on a binary.

    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable

    Returns:
        License analysis results

    """
    engine = R2ScriptingEngine(binary_path, radare2_path)
    return engine.execute_license_analysis_workflow()


def execute_vulnerability_analysis_script(binary_path: str, radare2_path: str | None = None) -> dict[str, Any]:
    """Execute vulnerability analysis workflow on a binary.

    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable

    Returns:
        Vulnerability analysis results

    """
    engine = R2ScriptingEngine(binary_path, radare2_path)
    return engine.execute_vulnerability_analysis_workflow()


__all__ = [
    "R2ScriptingEngine",
    "execute_license_analysis_script",
    "execute_vulnerability_analysis_script",
]
