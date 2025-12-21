"""Comprehensive radare2 Integration Utilities.

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
import time
from collections.abc import Generator
from contextlib import contextmanager
from types import TracebackType
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    import r2pipe as r2pipe_type
    from r2pipe import open as r2pipe_open_type

from ...core.analysis.radare2_error_handler import get_error_handler, r2_error_context

try:
    from ...core.analysis.radare2_session_manager import (
        R2SessionWrapper,
        r2_session_pooled,
    )

    SESSION_MANAGER_AVAILABLE = True
except ImportError:
    SESSION_MANAGER_AVAILABLE = False

try:
    import r2pipe

    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False


logger = logging.getLogger(__name__)
error_handler = get_error_handler()


class R2Exception(Exception):
    """Customize exception for radare2 operations."""

    pass


class R2Session:
    """Advanced radare2 session manager with comprehensive analysis capabilities.

    This class provides a production-grade interface to radare2, featuring:
    - Decompilation and pseudocode generation
    - ESIL emulation and analysis
    - String and import/export analysis
    - Vulnerability detection
    - Binary diffing and comparison
    - Advanced scripting support
    """

    def __init__(self, binary_path: str, radare2_path: str | None = None) -> None:
        """Initialize radare2 session.

        Args:
            binary_path: Path to binary file
            radare2_path: Optional path to radare2 executable

        """
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.r2: Any = None
        self.logger = logging.getLogger(__name__)
        self.is_connected = False
        self.analysis_cache: dict[str, Any] = {}
        self.analysis_level = "aaa"

        if not R2PIPE_AVAILABLE:
            raise R2Exception("r2pipe not available - please install radare2-r2pipe")

    def __enter__(self) -> "R2Session":
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager exit."""
        if exc_type is not None:
            logger.error(f"Radare2 session exiting due to {exc_type.__name__}: {exc_val}")
            if exc_tb is not None:
                logger.debug(f"Exception traceback from {exc_tb.tb_frame.f_code.co_filename}:{exc_tb.tb_lineno}")
        self.disconnect()

    def connect(self) -> bool:
        """Establish connection to radare2."""
        with r2_error_context("r2_connect", binary_path=self.binary_path):
            try:
                if not os.path.exists(self.binary_path):
                    raise R2Exception(f"Binary file not found: {self.binary_path}")

                flags: list[str] = []
                if self.radare2_path and os.path.exists(self.radare2_path):
                    flags.extend(("-e", f"bin.radare2={self.radare2_path}"))
                self.r2 = r2pipe.open(self.binary_path, flags=flags)
                self.is_connected = True

                if self.r2 is not None:
                    self.r2.cmd(self.analysis_level)

                self.logger.info(f"Connected to radare2 for binary: {self.binary_path}")
                return True

            except Exception as e:
                self.logger.error(f"Failed to connect to radare2: {e}")
                error_handler.handle_error(e, "r2_connect", {"binary_path": self.binary_path, "r2_session": self})
                raise R2Exception(f"Connection failed: {e}") from e

    def disconnect(self) -> None:
        """Disconnect from radare2."""
        if self.r2 is not None:
            try:
                self.r2.quit()
            except Exception as e:
                self.logger.error("Exception in radare2_utils: %s", e)
        self.r2 = None
        self.is_connected = False
        self.logger.info("Disconnected from radare2")

    def _execute_command(self, cmd: str, expect_json: bool = False) -> str | dict[str, Any] | list[Any]:
        """Execute radare2 command with error handling.

        Args:
            cmd: radare2 command
            expect_json: Whether to parse result as JSON

        Returns:
            Command result

        """
        if not self.is_connected or self.r2 is None:
            raise R2Exception("Not connected to radare2")

        with r2_error_context("r2_command", command=cmd, binary_path=self.binary_path):
            try:
                if not expect_json:
                    result: str = self.r2.cmd(cmd)
                    return result
                json_result: dict[str, Any] | list[Any] | None = self.r2.cmdj(cmd)
                return json_result if json_result is not None else {}
            except Exception as e:
                self.logger.error(f"Command failed: {cmd}, Error: {e}")
                error_handler.handle_error(
                    e,
                    "r2_command",
                    {
                        "command": cmd,
                        "binary_path": self.binary_path,
                        "r2_session": self,
                        "expect_json": expect_json,
                    },
                )
                raise R2Exception(f"Command execution failed: {e}") from e

    def cmd(self, command: str) -> str:
        """Execute a radare2 command and return the result as a string.

        Args:
            command: The radare2 command to execute

        Returns:
            Command output as string

        """
        result = self._execute_command(command, expect_json=False)
        return str(result) if result else ""

    def cmdj(self, command: str) -> dict[str, Any] | list[Any]:
        """Execute a radare2 command and return the result as parsed JSON.

        Args:
            command: The radare2 command to execute (typically ending with 'j')

        Returns:
            Parsed JSON result as dict or list

        """
        result = self._execute_command(command, expect_json=True)
        return result if isinstance(result, (dict, list)) else {}

    def _parse_json(self, json_data: str | bytes | None) -> dict[str, Any] | list[Any]:
        """Parse JSON data from radare2 command output.

        Safely parses JSON string or bytes data returned from radare2 commands.
        Handles various edge cases including empty data, malformed JSON, and
        radare2-specific output quirks.

        Args:
            json_data: JSON string or bytes to parse, or None

        Returns:
            Parsed JSON as dictionary or list. Returns empty dict for invalid
            or empty input.

        """
        if json_data is None:
            return {}

        if isinstance(json_data, bytes):
            try:
                json_data = json_data.decode("utf-8", errors="replace")
            except (UnicodeDecodeError, AttributeError):
                return {}

        if not json_data or not isinstance(json_data, str):
            return {}

        json_str = json_data.strip()
        if not json_str:
            return {}

        try:
            import json
            result = json.loads(json_str)
            return result if isinstance(result, (dict, list)) else {}
        except json.JSONDecodeError:
            pass

        try:
            if json_str.startswith("[") or json_str.startswith("{"):
                brace_count = 0
                bracket_count = 0
                end_idx = 0
                in_string = False
                escape_next = False

                for i, char in enumerate(json_str):
                    if escape_next:
                        escape_next = False
                        continue
                    if char == "\\":
                        escape_next = True
                        continue
                    if char == '"':
                        in_string = not in_string
                        continue
                    if in_string:
                        continue
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                    elif char == "[":
                        bracket_count += 1
                    elif char == "]":
                        bracket_count -= 1

                    if brace_count == 0 and bracket_count == 0 and i > 0:
                        end_idx = i + 1
                        break

                if end_idx > 0:
                    import json
                    parsed = json.loads(json_str[:end_idx])
                    return parsed if isinstance(parsed, (dict, list)) else {}
        except (json.JSONDecodeError, ValueError, IndexError):
            pass

        self.logger.debug(f"Failed to parse JSON from radare2 output: {json_str[:100]}...")
        return {}

    def analyze_all(self, level: str = "aaa") -> bool:
        """Perform comprehensive analysis.

        Args:
            level: Analysis level (a, aa, aaa, aaaa)

        """
        try:
            self._execute_command(level)
            return True
        except R2Exception as e:
            self.logger.error("R2Exception in radare2_utils: %s", e)
            return False

    def get_info(self) -> dict[str, Any]:
        """Get binary information."""
        result = self._execute_command("ij", expect_json=True)
        return result if isinstance(result, dict) else {}

    def get_functions(self) -> list[dict[str, Any]]:
        """Get list of all functions."""
        result = self._execute_command("aflj", expect_json=True)
        return result if isinstance(result, list) else []

    def get_function_info(self, address: str | int) -> dict[str, Any]:
        """Get detailed function information."""
        addr = hex(address) if isinstance(address, int) else address
        result = self._execute_command(f"afij @ {addr}", expect_json=True)
        return result if isinstance(result, dict) else {}

    def decompile_function(self, address: str | int) -> str:
        """Decompile function to pseudocode.

        Args:
            address: Function address

        Returns:
            Decompiled pseudocode

        """
        addr = hex(address) if isinstance(address, int) else address
        result = self._execute_command(f"pdc @ {addr}")
        return result if isinstance(result, str) else str(result)

    def get_function_graph(self, address: str | int) -> dict[str, Any]:
        """Get function control flow graph with decompilation.

        Args:
            address: Function address

        Returns:
            Graph data with decompilation info

        """
        addr = hex(address) if isinstance(address, int) else address
        result = self._execute_command(f"pdgj @ {addr}", expect_json=True)
        return result if isinstance(result, dict) else {}

    def get_function_signature(self, address: str | int) -> str:
        """Get function signature."""
        addr = hex(address) if isinstance(address, int) else address
        result = self._execute_command(f"afv @ {addr}")
        return result if isinstance(result, str) else str(result)

    def get_strings(self, min_length: int = 4) -> list[dict[str, Any]]:
        """Get all strings from binary.

        Args:
            min_length: Minimum string length

        Returns:
            List of string entries with metadata

        """
        result = self._execute_command(f"izzj~{{length}}gte:{min_length}", expect_json=True)
        return result if isinstance(result, list) else []

    def get_strings_with_xrefs(self) -> list[dict[str, Any]]:
        """Get strings with cross-references."""
        result = self._execute_command("izzj", expect_json=True)
        return result if isinstance(result, list) else []

    def search_strings(self, pattern: str) -> list[dict[str, Any]]:
        """Search for strings matching pattern.

        Args:
            pattern: Search pattern

        Returns:
            Matching strings with locations

        """
        result = self._execute_command(f"/j {pattern}", expect_json=True)
        return result if isinstance(result, list) else []

    def get_license_strings(self) -> list[dict[str, Any]]:
        """Find potential license-related strings."""
        license_patterns = [
            "license",
            "registration",
            "activation",
            "serial",
            "key",
            "trial",
            "valid",
            "expire",
            "auth",
            "dongle",
            "hwid",
            "crack",
            "pirate",
            "illegal",
            "legitimate",
            "genuine",
        ]

        all_strings = []
        for pattern in license_patterns:
            try:
                if results := self.search_strings(pattern):
                    all_strings.extend(results)
            except R2Exception as e:
                self.logger.error("R2Exception in radare2_utils: %s", e)
                continue

        return all_strings

    def get_imports(self) -> list[dict[str, Any]]:
        """Get imported functions."""
        result = self._execute_command("iij", expect_json=True)
        return result if isinstance(result, list) else []

    def get_exports(self) -> list[dict[str, Any]]:
        """Get exported functions."""
        result = self._execute_command("iEj", expect_json=True)
        return result if isinstance(result, list) else []

    def get_symbols(self) -> list[dict[str, Any]]:
        """Get all symbols."""
        result = self._execute_command("isj", expect_json=True)
        return result if isinstance(result, list) else []

    def get_relocations(self) -> list[dict[str, Any]]:
        """Get relocations."""
        result = self._execute_command("irj", expect_json=True)
        return result if isinstance(result, list) else []

    def analyze_api_calls(self) -> dict[str, list[dict[str, Any]]]:
        """Analyze API calls and categorize them.

        Returns:
            Dictionary of API categories and their functions

        """
        imports = self.get_imports()

        api_categories: dict[str, list[dict[str, Any]]] = {
            "crypto": [],
            "network": [],
            "file": [],
            "registry": [],
            "process": [],
            "debug": [],
            "license": [],
        }

        crypto_apis = ["Crypt", "Cipher", "Encrypt", "Decrypt", "Hash", "AES", "RSA", "SHA", "MD5"]
        network_apis = ["socket", "connect", "send", "recv", "Http", "Internet", "Wininet"]
        file_apis = ["CreateFile", "ReadFile", "WriteFile", "DeleteFile", "FindFile"]
        registry_apis = ["RegOpen", "RegQuery", "RegSet", "RegDelete", "RegEnum"]
        process_apis = ["CreateProcess", "OpenProcess", "TerminateProcess", "GetModule"]
        debug_apis = ["IsDebuggerPresent", "CheckRemoteDebugger", "OutputDebugString"]
        license_apis = ["GetVolumeInformation", "GetComputerName", "GetUserName"]

        for imp in imports:
            name = imp.get("name", "").lower()

            if any(api.lower() in name for api in crypto_apis):
                api_categories["crypto"].append(imp)
            elif any(api.lower() in name for api in network_apis):
                api_categories["network"].append(imp)
            elif any(api.lower() in name for api in file_apis):
                api_categories["file"].append(imp)
            elif any(api.lower() in name for api in registry_apis):
                api_categories["registry"].append(imp)
            elif any(api.lower() in name for api in process_apis):
                api_categories["process"].append(imp)
            elif any(api.lower() in name for api in debug_apis):
                api_categories["debug"].append(imp)
            elif any(api.lower() in name for api in license_apis):
                api_categories["license"].append(imp)

        return api_categories

    # ESIL Analysis Engine
    def initialize_esil(self) -> bool:
        """Initialize ESIL emulation."""
        try:
            self._execute_command("aeim")
            return True
        except R2Exception as e:
            self.logger.error("R2Exception in radare2_utils: %s", e)
            return False

    def step_esil(self, address: str | int, steps: int = 1) -> str:
        """Step through ESIL instructions.

        Args:
            address: Starting address
            steps: Number of steps to execute

        Returns:
            ESIL execution result

        """
        addr = hex(address) if isinstance(address, int) else address
        result = self._execute_command(f"{steps}aes @ {addr}")
        return result if isinstance(result, str) else str(result)

    def get_esil_registers(self) -> dict[str, Any]:
        """Get ESIL register state."""
        result = self._execute_command("drj", expect_json=True)
        return result if isinstance(result, dict) else {}

    def emulate_function(self, address: str | int) -> dict[str, Any]:
        """Emulate function execution using ESIL.

        Args:
            address: Function address

        Returns:
            Emulation results

        """
        addr = hex(address) if isinstance(address, int) else address

        results = {
            "address": addr,
            "initial_registers": {},
            "final_registers": {},
            "execution_trace": [],
            "memory_accesses": [],
        }

        try:
            # Initialize ESIL
            if not self.initialize_esil():
                return results

            # Get initial register state
            results["initial_registers"] = self.get_esil_registers()

            if func_info := self.get_function_info(address):
                func_size = func_info.get("size", 100)

                # Step through function
                trace = self.step_esil(address, min(func_size // 4, 50))
                results["execution_trace"] = trace.split("\n") if trace else []

            # Get final register state
            results["final_registers"] = self.get_esil_registers()

        except R2Exception as e:
            logger.error("R2Exception in radare2_utils: %s", e)
            results["error"] = str(e)

        return results

    # Signature Analysis
    def apply_signatures(self) -> bool:
        """Apply FLIRT signatures."""
        try:
            self._execute_command("zf")
            return True
        except R2Exception as e:
            self.logger.error("R2Exception in radare2_utils: %s", e)
            return False

    def get_identified_functions(self) -> list[dict[str, Any]]:
        """Get functions identified by signatures."""
        functions = self.get_functions()
        return [f for f in functions if f.get("name", "").startswith("sym.")]

    # Vulnerability Detection
    def detect_vulnerabilities(self) -> dict[str, list[dict[str, Any]]]:
        """Detect potential vulnerabilities using radare2 analysis.

        Returns:
            Dictionary of vulnerability types and findings

        """
        vulnerabilities: dict[str, list[dict[str, Any]]] = {
            "buffer_overflow": [],
            "format_string": [],
            "use_after_free": [],
            "double_free": [],
            "null_pointer": [],
            "integer_overflow": [],
        }

        try:
            # Get all functions for analysis
            functions = self.get_functions()

            for func in functions[:20]:  # Limit analysis for performance
                func_addr = func.get("offset", 0)
                if not func_addr:
                    continue

                # Analyze function for vulnerabilities
                func_vulns = self._analyze_function_vulnerabilities(func_addr)

                for vuln_type, findings in func_vulns.items():
                    vulnerabilities[vuln_type].extend(findings)

        except R2Exception as e:
            self.logger.error(f"Vulnerability detection failed: {e}")

        return vulnerabilities

    def _analyze_function_vulnerabilities(self, address: str | int) -> dict[str, list[dict[str, Any]]]:
        """Analyze single function for vulnerabilities."""
        addr = hex(address) if isinstance(address, int) else address
        vulns: dict[str, list[dict[str, Any]]] = {
            "buffer_overflow": [],
            "format_string": [],
            "use_after_free": [],
            "double_free": [],
            "null_pointer": [],
            "integer_overflow": [],
        }

        try:
            # Get function disassembly
            disasm_result = self._execute_command(f"pdf @ {addr}")
            disasm = disasm_result if isinstance(disasm_result, str) else str(disasm_result)

            dangerous_functions = ["strcpy", "strcat", "sprintf", "gets", "scanf"]
            format_functions = ["printf", "fprintf", "sprintf", "snprintf"]
            memory_functions = ["malloc", "free", "realloc", "calloc"]

            lines = disasm.split("\n")
            for i, line in enumerate(lines):
                line_lower = line.lower()

                # Buffer overflow detection
                if any(func in line_lower for func in dangerous_functions):
                    vulns["buffer_overflow"].append(
                        {
                            "line": line.strip(),
                            "function": addr,
                            "type": "dangerous_function_call",
                            "line_number": i,
                        }
                    )

                # Format string detection
                if any(func in line_lower for func in format_functions) and ("mov" in line_lower and "%" in line_lower):
                    vulns["format_string"].append(
                        {
                            "line": line.strip(),
                            "function": addr,
                            "type": "potential_format_string",
                            "line_number": i,
                        }
                    )

                # Memory management issues
                if any(func in line_lower for func in memory_functions) and "free" in line_lower:
                    for j in range(i + 1, min(i + 10, len(lines))):
                        if "free" in lines[j].lower():
                            vulns["double_free"].append(
                                {
                                    "line": line.strip(),
                                    "function": addr,
                                    "type": "potential_double_free",
                                    "line_number": i,
                                }
                            )
                            break

                # Null pointer dereference
                if "mov" in line_lower and ("dword ptr [0]" in line_lower or "qword ptr [0]" in line_lower):
                    vulns["null_pointer"].append(
                        {
                            "line": line.strip(),
                            "function": addr,
                            "type": "null_pointer_dereference",
                            "line_number": i,
                        }
                    )

        except R2Exception as e:
            logger.error("R2Exception in radare2_utils: %s", e)
        return vulns

    def analyze_function_deeper(self, address: str | int) -> bool:
        """Perform deeper analysis on a specific function.

        Args:
            address: Function address

        Returns:
            True if analysis succeeded, False otherwise

        """
        addr = hex(address) if isinstance(address, int) else address
        try:
            # Perform function-specific analysis
            self._execute_command(f"af @ {addr}")  # Analyze function
            self._execute_command(f"afr @ {addr}")  # Analyze function references
            self._execute_command(f"afv @ {addr}")  # Analyze function variables
            self._execute_command(f"aft @ {addr}")  # Analyze function types
            return True
        except R2Exception as e:
            self.logger.error("R2Exception in radare2_utils: %s", e)
            return False

    def run_optimization_passes(self, address: str | int) -> bool:
        """Run optimization passes on a function for better decompilation.

        Args:
            address: Function address

        Returns:
            True if optimization succeeded, False otherwise

        """
        addr = hex(address) if isinstance(address, int) else address
        try:
            # Run radare2 optimization passes
            self._execute_command(f"aaa @ {addr}")  # Deep analysis
            self._execute_command(f"aac @ {addr}")  # Analyze function calls
            self._execute_command(f"aar @ {addr}")  # Analyze references
            return True
        except R2Exception as e:
            self.logger.error("R2Exception in radare2_utils: %s", e)
            return False


@contextmanager
def r2_session(
    binary_path: str, radare2_path: str | None = None, use_pooling: bool = True
) -> Generator["R2Session | R2SessionPoolAdapter", None, None]:
    """Context manager for radare2 sessions.

    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable
        use_pooling: Whether to use session pooling (default: True)

    Yields:
        R2Session instance or R2SessionWrapper instance

    """
    if use_pooling and SESSION_MANAGER_AVAILABLE:
        flags: list[str] = []
        if radare2_path and os.path.exists(radare2_path):
            flags.extend(["-e", f"bin.radare2={radare2_path}"])

        with r2_session_pooled(binary_path, flags=flags or None) as pooled_session:
            yield R2SessionPoolAdapter(pooled_session)
    else:
        session = R2Session(binary_path, radare2_path)
        try:
            session.connect()
            yield session
        finally:
            session.disconnect()


class R2SessionPoolAdapter:
    """Adapter to make R2SessionWrapper compatible with R2Session interface."""

    def __init__(self, session_wrapper: 'R2SessionWrapper'):
        """Initialize adapter.

        Args:
            session_wrapper: The underlying session wrapper

        """
        self.session_wrapper = session_wrapper
        self.binary_path = str(session_wrapper.binary_path)
        self.is_connected = session_wrapper.state.value == "active"
        self.logger = logging.getLogger(__name__)

    def _execute_command(self, cmd: str, expect_json: bool = False) -> str | dict[str, Any] | list[Any]:
        """Execute radare2 command with error handling.

        Args:
            cmd: radare2 command
            expect_json: Whether to parse result as JSON

        Returns:
            Command result

        """
        try:
            result = self.session_wrapper.execute(cmd, expect_json)
            if result is None:
                return {} if expect_json else ""
            return cast(str | dict[str, Any] | list[Any], result)
        except Exception as e:
            self.logger.error(f"Command failed: {cmd}, Error: {e}")
            error_handler.handle_error(
                e,
                "r2_command",
                {
                    "command": cmd,
                    "binary_path": self.binary_path,
                    "expect_json": expect_json,
                },
            )
            raise R2Exception(f"Command execution failed: {e}") from e

    def cmd(self, command: str) -> str:
        """Execute a radare2 command and return the result as a string.

        Args:
            command: The radare2 command to execute

        Returns:
            Command output as string

        """
        result = self._execute_command(command, expect_json=False)
        return str(result) if result else ""

    def cmdj(self, command: str) -> dict[str, Any] | list[Any]:
        """Execute a radare2 command and return the result as parsed JSON.

        Args:
            command: The radare2 command to execute (typically ending with 'j')

        Returns:
            Parsed JSON result as dict or list

        """
        result = self._execute_command(command, expect_json=True)
        return result if isinstance(result, (dict, list)) else {}

    def _parse_json(self, json_data: str | bytes | None) -> dict[str, Any] | list[Any]:
        """Parse JSON data from radare2 command output.

        Safely parses JSON string or bytes data returned from radare2 commands.
        Handles various edge cases including empty data, malformed JSON, and
        radare2-specific output quirks.

        Args:
            json_data: JSON string or bytes to parse, or None

        Returns:
            Parsed JSON as dictionary or list. Returns empty dict for invalid
            or empty input.

        """
        if json_data is None:
            return {}

        if isinstance(json_data, bytes):
            try:
                json_data = json_data.decode("utf-8", errors="replace")
            except (UnicodeDecodeError, AttributeError):
                return {}

        if not json_data or not isinstance(json_data, str):
            return {}

        json_str = json_data.strip()
        if not json_str:
            return {}

        try:
            import json
            result = json.loads(json_str)
            return result if isinstance(result, (dict, list)) else {}
        except json.JSONDecodeError:
            pass

        try:
            if json_str.startswith("[") or json_str.startswith("{"):
                brace_count = 0
                bracket_count = 0
                end_idx = 0
                in_string = False
                escape_next = False

                for i, char in enumerate(json_str):
                    if escape_next:
                        escape_next = False
                        continue
                    if char == "\\":
                        escape_next = True
                        continue
                    if char == '"':
                        in_string = not in_string
                        continue
                    if in_string:
                        continue
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                    elif char == "[":
                        bracket_count += 1
                    elif char == "]":
                        bracket_count -= 1

                    if brace_count == 0 and bracket_count == 0 and i > 0:
                        end_idx = i + 1
                        break

                if end_idx > 0:
                    import json
                    parsed = json.loads(json_str[:end_idx])
                    return parsed if isinstance(parsed, (dict, list)) else {}
        except (json.JSONDecodeError, ValueError, IndexError):
            pass

        self.logger.debug(f"Failed to parse JSON from radare2 output: {json_str[:100]}...")
        return {}

    def analyze_all(self, level: str = "aaa") -> bool:
        """Perform comprehensive analysis.

        Args:
            level: Analysis level (a, aa, aaa, aaaa)

        """
        try:
            self._execute_command(level)
            return True
        except R2Exception as e:
            self.logger.error("R2Exception in radare2_utils: %s", e)
            return False

    def get_info(self) -> dict[str, Any]:
        """Get binary information."""
        result = self._execute_command("ij", expect_json=True)
        return result if isinstance(result, dict) else {}

    def get_functions(self) -> list[dict[str, Any]]:
        """Get list of all functions."""
        result = self._execute_command("aflj", expect_json=True)
        return result if isinstance(result, list) else []

    def get_function_info(self, address: str | int) -> dict[str, Any]:
        """Get detailed function information."""
        addr = hex(address) if isinstance(address, int) else address
        result = self._execute_command(f"afij @ {addr}", expect_json=True)
        return result if isinstance(result, dict) else {}

    def decompile_function(self, address: str | int) -> str:
        """Decompile function to pseudocode.

        Args:
            address: Function address

        Returns:
            Decompiled pseudocode

        """
        addr = hex(address) if isinstance(address, int) else address
        result = self._execute_command(f"pdc @ {addr}")
        return result if isinstance(result, str) else str(result)

    def get_function_graph(self, address: str | int) -> dict[str, Any]:
        """Get function control flow graph with decompilation.

        Args:
            address: Function address

        Returns:
            Graph data with decompilation info

        """
        addr = hex(address) if isinstance(address, int) else address
        result = self._execute_command(f"pdgj @ {addr}", expect_json=True)
        return result if isinstance(result, dict) else {}

    def get_function_signature(self, address: str | int) -> str:
        """Get function signature."""
        addr = hex(address) if isinstance(address, int) else address
        result = self._execute_command(f"afv @ {addr}")
        return result if isinstance(result, str) else str(result)

    def get_strings(self, min_length: int = 4) -> list[dict[str, Any]]:
        """Get all strings from binary.

        Args:
            min_length: Minimum string length

        Returns:
            List of string entries with metadata

        """
        result = self._execute_command(f"izzj~{{length}}gte:{min_length}", expect_json=True)
        return result if isinstance(result, list) else []

    def get_strings_with_xrefs(self) -> list[dict[str, Any]]:
        """Get strings with cross-references."""
        result = self._execute_command("izzj", expect_json=True)
        return result if isinstance(result, list) else []

    def search_strings(self, pattern: str) -> list[dict[str, Any]]:
        """Search for strings matching pattern.

        Args:
            pattern: Search pattern

        Returns:
            Matching strings with locations

        """
        result = self._execute_command(f"/j {pattern}", expect_json=True)
        return result if isinstance(result, list) else []

    def get_license_strings(self) -> list[dict[str, Any]]:
        """Find potential license-related strings."""
        license_patterns = [
            "license",
            "registration",
            "activation",
            "serial",
            "key",
            "trial",
            "valid",
            "expire",
            "auth",
            "dongle",
            "hwid",
            "crack",
            "pirate",
            "illegal",
            "legitimate",
            "genuine",
        ]

        all_strings = []
        for pattern in license_patterns:
            try:
                if results := self.search_strings(pattern):
                    all_strings.extend(results)
            except R2Exception as e:
                self.logger.error("R2Exception in radare2_utils: %s", e)
                continue

        return all_strings

    def get_imports(self) -> list[dict[str, Any]]:
        """Get imported functions."""
        result = self._execute_command("iij", expect_json=True)
        return result if isinstance(result, list) else []

    def get_exports(self) -> list[dict[str, Any]]:
        """Get exported functions."""
        result = self._execute_command("iEj", expect_json=True)
        return result if isinstance(result, list) else []

    def get_symbols(self) -> list[dict[str, Any]]:
        """Get all symbols."""
        result = self._execute_command("isj", expect_json=True)
        return result if isinstance(result, list) else []

    def get_relocations(self) -> list[dict[str, Any]]:
        """Get relocations."""
        result = self._execute_command("irj", expect_json=True)
        return result if isinstance(result, list) else []

    def analyze_api_calls(self) -> dict[str, list[dict[str, Any]]]:
        """Analyze API calls and categorize them.

        Returns:
            Dictionary of API categories and their functions

        """
        imports = self.get_imports()

        api_categories: dict[str, list[dict[str, Any]]] = {
            "crypto": [],
            "network": [],
            "file": [],
            "registry": [],
            "process": [],
            "debug": [],
            "license": [],
        }

        crypto_apis = ["Crypt", "Cipher", "Encrypt", "Decrypt", "Hash", "AES", "RSA", "SHA", "MD5"]
        network_apis = ["socket", "connect", "send", "recv", "Http", "Internet", "Wininet"]
        file_apis = ["CreateFile", "ReadFile", "WriteFile", "DeleteFile", "FindFile"]
        registry_apis = ["RegOpen", "RegQuery", "RegSet", "RegDelete", "RegEnum"]
        process_apis = ["CreateProcess", "OpenProcess", "TerminateProcess", "GetModule"]
        debug_apis = ["IsDebuggerPresent", "CheckRemoteDebugger", "OutputDebugString"]
        license_apis = ["GetVolumeInformation", "GetComputerName", "GetUserName"]

        for imp in imports:
            name = imp.get("name", "").lower()

            if any(api.lower() in name for api in crypto_apis):
                api_categories["crypto"].append(imp)
            elif any(api.lower() in name for api in network_apis):
                api_categories["network"].append(imp)
            elif any(api.lower() in name for api in file_apis):
                api_categories["file"].append(imp)
            elif any(api.lower() in name for api in registry_apis):
                api_categories["registry"].append(imp)
            elif any(api.lower() in name for api in process_apis):
                api_categories["process"].append(imp)
            elif any(api.lower() in name for api in debug_apis):
                api_categories["debug"].append(imp)
            elif any(api.lower() in name for api in license_apis):
                api_categories["license"].append(imp)

        return api_categories

    def initialize_esil(self) -> bool:
        """Initialize ESIL emulation."""
        try:
            self._execute_command("aeim")
            return True
        except R2Exception as e:
            self.logger.error("R2Exception in radare2_utils: %s", e)
            return False

    def step_esil(self, address: str | int, steps: int = 1) -> str:
        """Step through ESIL instructions.

        Args:
            address: Starting address
            steps: Number of steps to execute

        Returns:
            ESIL execution result

        """
        addr = hex(address) if isinstance(address, int) else address
        result = self._execute_command(f"{steps}aes @ {addr}")
        return result if isinstance(result, str) else str(result)

    def get_esil_registers(self) -> dict[str, Any]:
        """Get ESIL register state."""
        result = self._execute_command("drj", expect_json=True)
        return result if isinstance(result, dict) else {}

    def emulate_function(self, address: str | int) -> dict[str, Any]:
        """Emulate function execution using ESIL.

        Args:
            address: Function address

        Returns:
            Emulation results

        """
        addr = hex(address) if isinstance(address, int) else address

        results = {
            "address": addr,
            "initial_registers": {},
            "final_registers": {},
            "execution_trace": [],
            "memory_accesses": [],
        }

        try:
            if not self.initialize_esil():
                return results

            results["initial_registers"] = self.get_esil_registers()

            if func_info := self.get_function_info(address):
                func_size = func_info.get("size", 100)

                trace = self.step_esil(address, min(func_size // 4, 50))
                results["execution_trace"] = trace.split("\n") if trace else []

            results["final_registers"] = self.get_esil_registers()

        except R2Exception as e:
            logger.error("R2Exception in radare2_utils: %s", e)
            results["error"] = str(e)

        return results

    def apply_signatures(self) -> bool:
        """Apply FLIRT signatures."""
        try:
            self._execute_command("zf")
            return True
        except R2Exception as e:
            self.logger.error("R2Exception in radare2_utils: %s", e)
            return False

    def get_identified_functions(self) -> list[dict[str, Any]]:
        """Get functions identified by signatures."""
        functions = self.get_functions()
        return [f for f in functions if f.get("name", "").startswith("sym.")]

    def detect_vulnerabilities(self) -> dict[str, list[dict[str, Any]]]:
        """Detect potential vulnerabilities using radare2 analysis.

        Returns:
            Dictionary of vulnerability types and findings

        """
        vulnerabilities: dict[str, list[dict[str, Any]]] = {
            "buffer_overflow": [],
            "format_string": [],
            "use_after_free": [],
            "double_free": [],
            "null_pointer": [],
            "integer_overflow": [],
        }

        try:
            functions = self.get_functions()

            for func in functions[:20]:
                func_addr = func.get("offset", 0)
                if not func_addr:
                    continue

                func_vulns = self._analyze_function_vulnerabilities(func_addr)

                for vuln_type, findings in func_vulns.items():
                    vulnerabilities[vuln_type].extend(findings)

        except R2Exception as e:
            self.logger.error(f"Vulnerability detection failed: {e}")

        return vulnerabilities

    def _analyze_function_vulnerabilities(self, address: str | int) -> dict[str, list[dict[str, Any]]]:
        """Analyze single function for vulnerabilities."""
        addr = hex(address) if isinstance(address, int) else address
        vulns: dict[str, list[dict[str, Any]]] = {
            "buffer_overflow": [],
            "format_string": [],
            "use_after_free": [],
            "double_free": [],
            "null_pointer": [],
            "integer_overflow": [],
        }

        try:
            disasm_result = self._execute_command(f"pdf @ {addr}")
            disasm = disasm_result if isinstance(disasm_result, str) else str(disasm_result)

            dangerous_functions = ["strcpy", "strcat", "sprintf", "gets", "scanf"]
            format_functions = ["printf", "fprintf", "sprintf", "snprintf"]
            memory_functions = ["malloc", "free", "realloc", "calloc"]

            lines = disasm.split("\n")
            for i, line in enumerate(lines):
                line_lower = line.lower()

                if any(func in line_lower for func in dangerous_functions):
                    vulns["buffer_overflow"].append(
                        {
                            "line": line.strip(),
                            "function": addr,
                            "type": "dangerous_function_call",
                            "line_number": i,
                        }
                    )

                if any(func in line_lower for func in format_functions) and ("mov" in line_lower and "%" in line_lower):
                    vulns["format_string"].append(
                        {
                            "line": line.strip(),
                            "function": addr,
                            "type": "potential_format_string",
                            "line_number": i,
                        }
                    )

                if any(func in line_lower for func in memory_functions) and "free" in line_lower:
                    for j in range(i + 1, min(i + 10, len(lines))):
                        if "free" in lines[j].lower():
                            vulns["double_free"].append(
                                {
                                    "line": line.strip(),
                                    "function": addr,
                                    "type": "potential_double_free",
                                    "line_number": i,
                                }
                            )
                            break

                if "mov" in line_lower and ("dword ptr [0]" in line_lower or "qword ptr [0]" in line_lower):
                    vulns["null_pointer"].append(
                        {
                            "line": line.strip(),
                            "function": addr,
                            "type": "null_pointer_dereference",
                            "line_number": i,
                        }
                    )

        except R2Exception as e:
            logger.error("R2Exception in radare2_utils: %s", e)
        return vulns

    def analyze_function_deeper(self, address: str | int) -> bool:
        """Perform deeper analysis on a specific function.

        Args:
            address: Function address

        Returns:
            True if analysis succeeded, False otherwise

        """
        addr = hex(address) if isinstance(address, int) else address
        try:
            self._execute_command(f"af @ {addr}")
            self._execute_command(f"afr @ {addr}")
            self._execute_command(f"afv @ {addr}")
            self._execute_command(f"aft @ {addr}")
            return True
        except R2Exception as e:
            self.logger.error("R2Exception in radare2_utils: %s", e)
            return False

    def run_optimization_passes(self, address: str | int) -> bool:
        """Run optimization passes on a function for better decompilation.

        Args:
            address: Function address

        Returns:
            True if optimization succeeded, False otherwise

        """
        addr = hex(address) if isinstance(address, int) else address
        try:
            self._execute_command(f"aaa @ {addr}")
            self._execute_command(f"aac @ {addr}")
            self._execute_command(f"aar @ {addr}")
            return True
        except R2Exception as e:
            self.logger.error("R2Exception in radare2_utils: %s", e)
            return False


class R2BinaryDiff:
    """Binary comparison and diffing using radare2."""

    def __init__(self, binary1: str, binary2: str):
        """Initialize binary diff.

        Args:
            binary1: Path to first binary
            binary2: Path to second binary

        """
        self.binary1 = binary1
        self.binary2 = binary2
        self.logger = logging.getLogger(__name__)

    def compare_functions(self) -> dict[str, Any]:
        """Compare functions between two binaries.

        Returns:
            Comparison results

        """
        results: dict[str, Any] = {
            "binary1": self.binary1,
            "binary2": self.binary2,
            "common_functions": [],
            "unique_to_binary1": [],
            "unique_to_binary2": [],
            "modified_functions": [],
        }

        try:
            with r2_session(self.binary1) as r2_1:
                with r2_session(self.binary2) as r2_2:
                    funcs1 = {f["name"]: f for f in r2_1.get_functions()}
                    funcs2 = {f["name"]: f for f in r2_2.get_functions()}

                    # Find common, unique, and modified functions
                    for name, func1 in funcs1.items():
                        if name in funcs2:
                            func2 = funcs2[name]
                            if func1.get("size") != func2.get("size"):
                                results["modified_functions"].append(
                                    {
                                        "name": name,
                                        "binary1_size": func1.get("size"),
                                        "binary2_size": func2.get("size"),
                                    }
                                )
                            else:
                                results["common_functions"].append(name)
                        else:
                            results["unique_to_binary1"].append(name)

                    for name in funcs2:
                        if name not in funcs1:
                            results["unique_to_binary2"].append(name)

        except Exception as e:
            self.logger.error(f"Binary comparison failed: {e}")
            results["error"] = str(e)

        return results

    def compare_strings(self) -> dict[str, Any]:
        """Compare strings between binaries."""
        results: dict[str, Any] = {
            "binary1": self.binary1,
            "binary2": self.binary2,
            "common_strings": [],
            "unique_to_binary1": [],
            "unique_to_binary2": [],
        }

        try:
            with r2_session(self.binary1) as r2_1:
                with r2_session(self.binary2) as r2_2:
                    strings1 = {s["string"]: s for s in r2_1.get_strings()}
                    strings2 = {s["string"]: s for s in r2_2.get_strings()}

                    # Compare strings
                    for string in strings1:
                        if string in strings2:
                            results["common_strings"].append(string)
                        else:
                            results["unique_to_binary1"].append(string)

                    for string in strings2:
                        if string not in strings1:
                            results["unique_to_binary2"].append(string)

        except Exception as e:
            self.logger.error(f"String comparison failed: {e}")
            results["error"] = str(e)

        return results


def analyze_binary_comprehensive(binary_path: str, radare2_path: str | None = None) -> dict[str, Any]:
    """Perform comprehensive radare2 analysis on a binary.

    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable

    Returns:
        Complete analysis results

    """
    results: dict[str, Any] = {
        "binary_path": binary_path,
        "timestamp": time.time(),
        "basic_info": {},
        "functions": [],
        "strings": [],
        "imports": [],
        "exports": [],
        "api_analysis": {},
        "vulnerabilities": {},
        "license_strings": [],
        "decompiled_samples": {},
        "esil_analysis": {},
        "errors": [],
    }

    try:
        with r2_session(binary_path, radare2_path) as r2:
            results["basic_info"] = r2.get_info()
            results["functions"] = r2.get_functions()
            results["strings"] = r2.get_strings()
            results["license_strings"] = r2.get_license_strings()
            results["imports"] = r2.get_imports()
            results["exports"] = r2.get_exports()
            results["api_analysis"] = r2.analyze_api_calls()
            results["vulnerabilities"] = r2.detect_vulnerabilities()

            functions_list: list[dict[str, Any]] = results["functions"][:5]
            decompiled_samples: dict[str, str] = {}
            for func in functions_list:
                if addr := func.get("offset"):
                    try:
                        if decompiled := r2.decompile_function(addr):
                            decompiled_samples[func["name"]] = decompiled
                    except R2Exception as e:
                        logger.error("R2Exception in radare2_utils: %s", e)
                        continue
            results["decompiled_samples"] = decompiled_samples

            if functions_list:
                main_func = functions_list[0]
                try:
                    esil_result = r2.emulate_function(main_func["offset"])
                    results["esil_analysis"] = esil_result
                except R2Exception as e:
                    logger.error("R2Exception in radare2_utils: %s", e)
    except Exception as e:
        error_msg = f"Comprehensive analysis failed: {e}"
        errors_list: list[str] = results["errors"]
        errors_list.append(error_msg)
        logging.getLogger(__name__).error(error_msg)

    return results


__all__ = [
    "R2BinaryDiff",
    "R2Exception",
    "R2Session",
    "R2SessionPoolAdapter",
    "SESSION_MANAGER_AVAILABLE",
    "analyze_binary_comprehensive",
    "r2_session",
]
