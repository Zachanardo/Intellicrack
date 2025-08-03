"""
Comprehensive radare2 Integration Utilities

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Union

from ...core.analysis.radare2_error_handler import get_error_handler, r2_error_context

try:
    import r2pipe

    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False


logger = logging.getLogger(__name__)
error_handler = get_error_handler()


class R2Exception(Exception):
    """Custom exception for radare2 operations."""

    pass


class R2Session:
    """
    Advanced radare2 session manager with comprehensive analysis capabilities.

    This class provides a production-grade interface to radare2, featuring:
    - Decompilation and pseudocode generation
    - ESIL emulation and analysis
    - String and import/export analysis
    - Vulnerability detection
    - Binary diffing and comparison
    - Advanced scripting support
    """

    def __init__(self, binary_path: str, radare2_path: Optional[str] = None):
        """
        Initialize radare2 session.

        Args:
            binary_path: Path to binary file
            radare2_path: Optional path to radare2 executable
        """
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.r2 = None
        self.logger = logging.getLogger(__name__)
        self.is_connected = False
        self.analysis_cache = {}
        self.analysis_level = "aaa"  # Default analysis level

        if not R2PIPE_AVAILABLE:
            raise R2Exception("r2pipe not available - please install radare2-r2pipe")

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if exc_type:
            logger.error(f"Radare2 session exiting due to {exc_type.__name__}: {exc_val}")
            if exc_tb:
                logger.debug(
                    f"Exception traceback from {exc_tb.tb_frame.f_code.co_filename}:{exc_tb.tb_lineno}"
                )
        self.disconnect()

    def connect(self) -> bool:
        """Establish connection to radare2."""
        with r2_error_context("r2_connect", binary_path=self.binary_path):
            try:
                if not os.path.exists(self.binary_path):
                    raise R2Exception(f"Binary file not found: {self.binary_path}")

                flags = []
                if self.radare2_path and os.path.exists(self.radare2_path):
                    flags.append("-e")
                    flags.append(f"bin.radare2={self.radare2_path}")

                self.r2 = r2pipe.open(self.binary_path, flags=flags)
                self.is_connected = True

                # Perform initial analysis
                self.r2.cmd(self.analysis_level)

                self.logger.info(f"Connected to radare2 for binary: {self.binary_path}")
                return True

            except Exception as e:
                self.logger.error(f"Failed to connect to radare2: {e}")
                error_handler.handle_error(
                    e, "r2_connect", {"binary_path": self.binary_path, "r2_session": self}
                )
                raise R2Exception(f"Connection failed: {e}")

    def disconnect(self):
        """Disconnect from radare2."""
        if self.r2:
            try:
                self.r2.quit()
            except Exception as e:
                self.logger.error("Exception in radare2_utils: %s", e)
                pass
            self.r2 = None
            self.is_connected = False
            self.logger.info("Disconnected from radare2")

    def _execute_command(self, cmd: str, expect_json: bool = False) -> Union[str, Dict, List]:
        """
        Execute radare2 command with error handling.

        Args:
            cmd: radare2 command
            expect_json: Whether to parse result as JSON

        Returns:
            Command result
        """
        if not self.is_connected:
            raise R2Exception("Not connected to radare2")

        with r2_error_context("r2_command", command=cmd, binary_path=self.binary_path):
            try:
                if expect_json:
                    result = self.r2.cmdj(cmd)
                    return result if result is not None else {}
                else:
                    return self.r2.cmd(cmd)
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
                raise R2Exception(f"Command execution failed: {e}")

    # Analysis Commands
    def analyze_all(self, level: str = "aaa") -> bool:
        """
        Perform comprehensive analysis.

        Args:
            level: Analysis level (a, aa, aaa, aaaa)
        """
        try:
            self._execute_command(level)
            return True
        except R2Exception as e:
            self.logger.error("R2Exception in radare2_utils: %s", e)
            return False

    def get_info(self) -> Dict[str, Any]:
        """Get binary information."""
        return self._execute_command("ij", expect_json=True)

    def get_functions(self) -> List[Dict[str, Any]]:
        """Get list of all functions."""
        return self._execute_command("aflj", expect_json=True)

    def get_function_info(self, address: Union[str, int]) -> Dict[str, Any]:
        """Get detailed function information."""
        addr = hex(address) if isinstance(address, int) else address
        return self._execute_command(f"afij @ {addr}", expect_json=True)

    # Decompilation Features
    def decompile_function(self, address: Union[str, int]) -> str:
        """
        Decompile function to pseudocode.

        Args:
            address: Function address

        Returns:
            Decompiled pseudocode
        """
        addr = hex(address) if isinstance(address, int) else address
        return self._execute_command(f"pdc @ {addr}")

    def get_function_graph(self, address: Union[str, int]) -> Dict[str, Any]:
        """
        Get function control flow graph with decompilation.

        Args:
            address: Function address

        Returns:
            Graph data with decompilation info
        """
        addr = hex(address) if isinstance(address, int) else address
        return self._execute_command(f"pdgj @ {addr}", expect_json=True)

    def get_function_signature(self, address: Union[str, int]) -> str:
        """Get function signature."""
        addr = hex(address) if isinstance(address, int) else address
        return self._execute_command(f"afv @ {addr}")

    # String Analysis
    def get_strings(self, min_length: int = 4) -> List[Dict[str, Any]]:
        """
        Get all strings from binary.

        Args:
            min_length: Minimum string length

        Returns:
            List of string entries with metadata
        """
        return self._execute_command(f"izzj~{{length}}gte:{min_length}", expect_json=True)

    def get_strings_with_xrefs(self) -> List[Dict[str, Any]]:
        """Get strings with cross-references."""
        return self._execute_command("izzj", expect_json=True)

    def search_strings(self, pattern: str) -> List[Dict[str, Any]]:
        """
        Search for strings matching pattern.

        Args:
            pattern: Search pattern

        Returns:
            Matching strings with locations
        """
        return self._execute_command(f"/j {pattern}", expect_json=True)

    def get_license_strings(self) -> List[Dict[str, Any]]:
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
                results = self.search_strings(pattern)
                if results:
                    all_strings.extend(results)
            except R2Exception as e:
                self.logger.error("R2Exception in radare2_utils: %s", e)
                continue

        return all_strings

    # Import/Export Analysis
    def get_imports(self) -> List[Dict[str, Any]]:
        """Get imported functions."""
        return self._execute_command("iij", expect_json=True)

    def get_exports(self) -> List[Dict[str, Any]]:
        """Get exported functions."""
        return self._execute_command("iEj", expect_json=True)

    def get_symbols(self) -> List[Dict[str, Any]]:
        """Get all symbols."""
        return self._execute_command("isj", expect_json=True)

    def get_relocations(self) -> List[Dict[str, Any]]:
        """Get relocations."""
        return self._execute_command("irj", expect_json=True)

    def analyze_api_calls(self) -> Dict[str, List[str]]:
        """
        Analyze API calls and categorize them.

        Returns:
            Dictionary of API categories and their functions
        """
        imports = self.get_imports()

        api_categories = {
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

    def step_esil(self, address: Union[str, int], steps: int = 1) -> str:
        """
        Step through ESIL instructions.

        Args:
            address: Starting address
            steps: Number of steps to execute

        Returns:
            ESIL execution result
        """
        addr = hex(address) if isinstance(address, int) else address
        return self._execute_command(f"{steps}aes @ {addr}")

    def get_esil_registers(self) -> Dict[str, Any]:
        """Get ESIL register state."""
        return self._execute_command("drj", expect_json=True)

    def emulate_function(self, address: Union[str, int]) -> Dict[str, Any]:
        """
        Emulate function execution using ESIL.

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

            # Get function info for emulation bounds
            func_info = self.get_function_info(address)
            if func_info:
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

    def get_identified_functions(self) -> List[Dict[str, Any]]:
        """Get functions identified by signatures."""
        functions = self.get_functions()
        return [f for f in functions if f.get("name", "").startswith("sym.")]

    # Vulnerability Detection
    def detect_vulnerabilities(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Detect potential vulnerabilities using radare2 analysis.

        Returns:
            Dictionary of vulnerability types and findings
        """
        vulnerabilities = {
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

    def _analyze_function_vulnerabilities(
        self, address: Union[str, int]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze single function for vulnerabilities."""
        addr = hex(address) if isinstance(address, int) else address
        vulns = {
            "buffer_overflow": [],
            "format_string": [],
            "use_after_free": [],
            "double_free": [],
            "null_pointer": [],
            "integer_overflow": [],
        }

        try:
            # Get function disassembly
            disasm = self._execute_command(f"pdf @ {addr}")

            # Check for dangerous functions
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
                if any(func in line_lower for func in format_functions):
                    if "mov" in line_lower and "%" in line_lower:
                        vulns["format_string"].append(
                            {
                                "line": line.strip(),
                                "function": addr,
                                "type": "potential_format_string",
                                "line_number": i,
                            }
                        )

                # Memory management issues
                if any(func in line_lower for func in memory_functions):
                    if "free" in line_lower:
                        # Check for double free by looking ahead
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
                if "mov" in line_lower and (
                    "dword ptr [0]" in line_lower or "qword ptr [0]" in line_lower
                ):
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
            pass

        return vulns

    def analyze_function_deeper(self, address: Union[str, int]) -> bool:
        """
        Perform deeper analysis on a specific function.

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

    def run_optimization_passes(self, address: Union[str, int]) -> bool:
        """
        Run optimization passes on a function for better decompilation.

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
def r2_session(binary_path: str, radare2_path: Optional[str] = None):
    """
    Context manager for radare2 sessions.

    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable

    Yields:
        R2Session instance
    """
    session = R2Session(binary_path, radare2_path)
    try:
        session.connect()
        yield session
    finally:
        session.disconnect()


class R2BinaryDiff:
    """Binary comparison and diffing using radare2."""

    def __init__(self, binary1: str, binary2: str):
        """
        Initialize binary diff.

        Args:
            binary1: Path to first binary
            binary2: Path to second binary
        """
        self.binary1 = binary1
        self.binary2 = binary2
        self.logger = logging.getLogger(__name__)

    def compare_functions(self) -> Dict[str, Any]:
        """
        Compare functions between two binaries.

        Returns:
            Comparison results
        """
        results = {
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

    def compare_strings(self) -> Dict[str, Any]:
        """Compare strings between binaries."""
        results = {
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
                    for string, _ in strings1.items():
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


def analyze_binary_comprehensive(
    binary_path: str, radare2_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Perform comprehensive radare2 analysis on a binary.

    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable

    Returns:
        Complete analysis results
    """
    results = {
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
            # Basic information
            results["basic_info"] = r2.get_info()

            # Function analysis
            results["functions"] = r2.get_functions()

            # String analysis
            results["strings"] = r2.get_strings()
            results["license_strings"] = r2.get_license_strings()

            # Import/Export analysis
            results["imports"] = r2.get_imports()
            results["exports"] = r2.get_exports()
            results["api_analysis"] = r2.analyze_api_calls()

            # Vulnerability detection
            results["vulnerabilities"] = r2.detect_vulnerabilities()

            # Decompile a few key functions
            functions = results["functions"][:5]  # Sample first 5 functions
            for func in functions:
                addr = func.get("offset")
                if addr:
                    try:
                        decompiled = r2.decompile_function(addr)
                        if decompiled:
                            results["decompiled_samples"][func["name"]] = decompiled
                    except R2Exception as e:
                        logger.error("R2Exception in radare2_utils: %s", e)
                        continue

            # ESIL analysis on main function if available
            if functions:
                main_func = functions[0]
                try:
                    esil_result = r2.emulate_function(main_func["offset"])
                    results["esil_analysis"] = esil_result
                except R2Exception as e:
                    logger.error("R2Exception in radare2_utils: %s", e)
                    pass

    except Exception as e:
        error_msg = f"Comprehensive analysis failed: {e}"
        results["errors"].append(error_msg)
        logging.getLogger(__name__).error(error_msg)

    return results


__all__ = ["R2Session", "R2Exception", "R2BinaryDiff", "r2_session", "analyze_binary_comprehensive"]
