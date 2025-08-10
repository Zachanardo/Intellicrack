"""Radare2 import/export analysis module for binary function analysis."""

import logging
from typing import Any

from intellicrack.logger import logger

from ...utils.tools.radare2_utils import R2Exception, R2Session, r2_session

"""
Radare2 Advanced Import/Export Analysis Engine

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


class R2ImportExportAnalyzer:
    """Advanced import/export analysis engine using radare2's comprehensive API detection.

    Provides sophisticated analysis for:
    - Windows API function imports
    - Linux system call analysis
    - DLL dependency analysis
    - Function export enumeration
    - API usage pattern analysis
    - License validation API detection
    - Crypto API identification
    - Anti-analysis API detection
    """

    def __init__(self, binary_path: str, radare2_path: str | None = None):
        """Initialize import/export analyzer.

        Args:
            binary_path: Path to binary file
            radare2_path: Optional path to radare2 executable

        """
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)
        self.api_cache = {}

    def analyze_imports_exports(self) -> dict[str, Any]:
        """Perform comprehensive import/export analysis on the binary.

        Returns:
            Complete import/export analysis results

        """
        result = {
            "binary_path": self.binary_path,
            "imports": [],
            "exports": [],
            "dll_dependencies": [],
            "symbols": [],
            "relocations": [],
            "api_categories": {},
            "suspicious_apis": [],
            "license_apis": [],
            "crypto_apis": [],
            "anti_analysis_apis": [],
            "network_apis": [],
            "file_system_apis": [],
            "registry_apis": [],
            "process_apis": [],
            "memory_apis": [],
            "debug_apis": [],
            "api_statistics": {},
            "security_assessment": {},
            "cross_references": {},
        }

        try:
            with r2_session(self.binary_path, self.radare2_path) as r2:
                # Get imports
                result["imports"] = self._analyze_imports(r2)

                # Get exports
                result["exports"] = self._analyze_exports(r2)

                # Get DLL dependencies
                result["dll_dependencies"] = self._analyze_dll_dependencies(r2)

                # Get symbols
                result["symbols"] = self._analyze_symbols(r2)

                # Get relocations
                result["relocations"] = self._analyze_relocations(r2)

                # Categorize APIs
                result["api_categories"] = self._categorize_apis(result["imports"])

                # Detect suspicious APIs
                result["suspicious_apis"] = self._detect_suspicious_apis(result["imports"])

                # Identify license-related APIs
                result["license_apis"] = self._identify_license_apis(result["imports"])

                # Identify crypto APIs
                result["crypto_apis"] = self._identify_crypto_apis(result["imports"])

                # Identify anti-analysis APIs
                result["anti_analysis_apis"] = self._identify_anti_analysis_apis(result["imports"])

                # Categorize by functionality
                result["network_apis"] = self._identify_network_apis(result["imports"])
                result["file_system_apis"] = self._identify_file_system_apis(result["imports"])
                result["registry_apis"] = self._identify_registry_apis(result["imports"])
                result["process_apis"] = self._identify_process_apis(result["imports"])
                result["memory_apis"] = self._identify_memory_apis(result["imports"])
                result["debug_apis"] = self._identify_debug_apis(result["imports"])

                # Generate statistics
                result["api_statistics"] = self._generate_api_statistics(result)

                # Perform security assessment
                result["security_assessment"] = self._perform_security_assessment(result)

                # Get cross-references for important APIs
                result["cross_references"] = self._get_api_cross_references(r2, result["imports"])

        except R2Exception as e:
            result["error"] = str(e)
            self.logger.error(f"Import/Export analysis failed: {e}")

        return result

    def _analyze_imports(self, r2: R2Session) -> list[dict[str, Any]]:
        """Analyze imported functions."""
        imports = []

        try:
            # Get imports using radare2
            import_data = r2._execute_command("iij", expect_json=True)

            if isinstance(import_data, list):
                for imp in import_data:
                    normalized_import = {
                        "name": imp.get("name", ""),
                        "address": imp.get("plt", 0),
                        "ordinal": imp.get("ordinal", 0),
                        "library": imp.get("libname", ""),
                        "type": imp.get("type", ""),
                        "bind": imp.get("bind", ""),
                        "is_weak": imp.get("is_weak", False),
                    }

                    # Add additional analysis
                    normalized_import["api_type"] = self._classify_api_type(
                        normalized_import["name"]
                    )
                    normalized_import["risk_level"] = self._assess_api_risk(
                        normalized_import["name"]
                    )
                    normalized_import["description"] = self._get_api_description(
                        normalized_import["name"]
                    )

                    imports.append(normalized_import)

            # Also get import information from other radare2 commands
            try:
                # Get PLT entries
                plt_data = r2._execute_command("iP", expect_json=False)
                if plt_data:
                    self._parse_plt_data(plt_data, imports)
            except R2Exception as e:
                logger.error("R2Exception in radare2_imports: %s", e)

        except R2Exception as e:
            self.logger.error(f"Failed to analyze imports: {e}")

        return imports

    def _analyze_exports(self, r2: R2Session) -> list[dict[str, Any]]:
        """Analyze exported functions."""
        exports = []

        try:
            # Get exports using radare2
            export_data = r2._execute_command("iEj", expect_json=True)

            if isinstance(export_data, list):
                for exp in export_data:
                    normalized_export = {
                        "name": exp.get("name", ""),
                        "address": exp.get("vaddr", 0),
                        "ordinal": exp.get("ordinal", 0),
                        "size": exp.get("size", 0),
                        "type": exp.get("type", ""),
                        "is_forwarded": exp.get("forwarder", "") != "",
                    }

                    # Add additional analysis
                    normalized_export["function_purpose"] = self._analyze_export_purpose(
                        normalized_export["name"]
                    )
                    normalized_export["api_category"] = self._classify_api_type(
                        normalized_export["name"]
                    )

                    exports.append(normalized_export)

        except R2Exception as e:
            self.logger.error(f"Failed to analyze exports: {e}")

        return exports

    def _analyze_dll_dependencies(self, r2: R2Session) -> list[dict[str, Any]]:
        """Analyze DLL dependencies and libraries."""
        dependencies = []

        try:
            # Get library dependencies
            lib_data = r2._execute_command("ilj", expect_json=True)

            if isinstance(lib_data, list):
                for lib in lib_data:
                    dependency = {
                        "name": lib.get("name", ""),
                        "path": lib.get("path", ""),
                        "base_address": lib.get("baddr", 0),
                        "size": lib.get("size", 0),
                    }

                    # Analyze library characteristics
                    dependency["library_type"] = self._classify_library_type(dependency["name"])
                    dependency["security_impact"] = self._assess_library_security_impact(
                        dependency["name"]
                    )
                    dependency["common_apis"] = self._get_common_apis_for_library(
                        dependency["name"]
                    )

                    dependencies.append(dependency)

        except R2Exception as e:
            self.logger.error(f"Failed to analyze DLL dependencies: {e}")

        return dependencies

    def _analyze_symbols(self, r2: R2Session) -> list[dict[str, Any]]:
        """Analyze symbols in the binary."""
        symbols = []

        try:
            # Get symbols
            symbol_data = r2._execute_command("isj", expect_json=True)

            if isinstance(symbol_data, list):
                for sym in symbol_data:
                    symbol = {
                        "name": sym.get("name", ""),
                        "address": sym.get("vaddr", 0),
                        "size": sym.get("size", 0),
                        "type": sym.get("type", ""),
                        "bind": sym.get("bind", ""),
                        "is_imported": sym.get("is_imported", False),
                    }

                    # Additional symbol analysis
                    symbol["symbol_category"] = self._categorize_symbol(symbol["name"])
                    symbol["relevance"] = self._assess_symbol_relevance(symbol["name"])

                    symbols.append(symbol)

        except R2Exception as e:
            self.logger.error(f"Failed to analyze symbols: {e}")

        return symbols

    def _analyze_relocations(self, r2: R2Session) -> list[dict[str, Any]]:
        """Analyze relocations in the binary."""
        relocations = []

        try:
            # Get relocations
            reloc_data = r2._execute_command("irj", expect_json=True)

            if isinstance(reloc_data, list):
                for reloc in reloc_data:
                    relocation = {
                        "address": reloc.get("vaddr", 0),
                        "type": reloc.get("type", ""),
                        "name": reloc.get("name", ""),
                        "addend": reloc.get("addend", 0),
                        "target": reloc.get("target", 0),
                    }

                    # Additional relocation analysis
                    relocation["relocation_purpose"] = self._analyze_relocation_purpose(relocation)

                    relocations.append(relocation)

        except R2Exception as e:
            self.logger.error(f"Failed to analyze relocations: {e}")

        return relocations

    def _categorize_apis(self, imports: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """Categorize APIs by functionality."""
        categories = {
            "system_info": [],
            "file_operations": [],
            "registry_operations": [],
            "network_operations": [],
            "process_management": [],
            "memory_management": [],
            "cryptography": [],
            "user_interface": [],
            "debugging": [],
            "security": [],
            "time_date": [],
            "error_handling": [],
        }

        for imp in imports:
            api_name = imp.get("name", "").lower()

            # System Information
            if any(
                pattern in api_name
                for pattern in ["getsysteminfo", "getversion", "getenvironmentvar"]
            ):
                categories["system_info"].append(imp)

            # File Operations
            elif any(
                pattern in api_name
                for pattern in ["createfile", "readfile", "writefile", "deletefile", "findfile"]
            ):
                categories["file_operations"].append(imp)

            # Registry Operations
            elif any(
                pattern in api_name
                for pattern in ["regopen", "regquery", "regset", "regdelete", "regenum"]
            ):
                categories["registry_operations"].append(imp)

            # Network Operations
            elif any(
                pattern in api_name
                for pattern in ["socket", "connect", "send", "recv", "wsastartup", "internetopen"]
            ):
                categories["network_operations"].append(imp)

            # Process Management
            elif any(
                pattern in api_name
                for pattern in ["createprocess", "openprocess", "terminateprocess", "getmodule"]
            ):
                categories["process_management"].append(imp)

            # Memory Management
            elif any(
                pattern in api_name
                for pattern in ["virtualloc", "heapalloc", "malloc", "free", "memcpy"]
            ):
                categories["memory_management"].append(imp)

            # Cryptography
            elif any(
                pattern in api_name
                for pattern in ["crypt", "hash", "encrypt", "decrypt", "generatekey"]
            ):
                categories["cryptography"].append(imp)

            # User Interface
            elif any(
                pattern in api_name
                for pattern in ["messagebox", "createwindow", "showwindow", "getdc"]
            ):
                categories["user_interface"].append(imp)

            # Debugging
            elif any(
                pattern in api_name
                for pattern in ["isdebuggerpresent", "outputdebugstring", "debugbreak"]
            ):
                categories["debugging"].append(imp)

            # Security
            elif any(
                pattern in api_name for pattern in ["adjusttoken", "lookupprivilege", "impersonate"]
            ):
                categories["security"].append(imp)

            # Time/Date
            elif any(
                pattern in api_name
                for pattern in ["getsystemtime", "getlocaltime", "filetimetosystemtime"]
            ):
                categories["time_date"].append(imp)

            # Error Handling
            elif any(
                pattern in api_name for pattern in ["getlasterror", "seterrormode", "formatmessage"]
            ):
                categories["error_handling"].append(imp)

        return categories

    def _detect_suspicious_apis(self, imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect suspicious API usage patterns."""
        suspicious = []

        suspicious_patterns = {
            "code_injection": [
                "virtualallocex",
                "writeprocessmemory",
                "createremotethread",
                "setwindowshookex",
            ],
            "process_hollowing": ["ntunmapviewofsection", "zwunmapviewofsection", "resumethread"],
            "persistence": ["regsetvalueex", "createservice", "setwinhook", "createfile.*startup"],
            "evasion": ["isdebuggerpresent", "checkremotedebugger", "gettickcount", "sleep"],
            "data_theft": ["cryptdecrypt", "cryptencrypt", "internetreadfile", "ftpputfile"],
            "privilege_escalation": [
                "adjusttokenprivileges",
                "seservicestatus",
                "impersonateloggedonuser",
            ],
        }

        for imp in imports:
            api_name = imp.get("name", "").lower()

            for category, patterns in suspicious_patterns.items():
                if any(pattern in api_name for pattern in patterns):
                    suspicious.append(
                        {
                            "api": imp,
                            "category": category,
                            "risk_level": "high",
                            "description": f'API commonly used for {category.replace("_", " ")}',
                        }
                    )
                    break

        return suspicious

    def _identify_license_apis(self, imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify APIs commonly used for license validation."""
        license_apis = []

        license_api_patterns = {
            "hardware_fingerprinting": [
                "getvolumeinformation",
                "getcomputername",
                "getusername",
                "getcurrenthwprofile",
            ],
            "registry_licensing": ["regopenkeyex", "regqueryvalueex", "regsetvalueex"],
            "file_licensing": ["createfile", "readfile", "writefile", "getfileattributes"],
            "network_licensing": ["internetopen", "internetconnect", "httpsendrequest"],
            "crypto_licensing": [
                "cryptcreatehash",
                "crypthashdata",
                "cryptdecrypt",
                "cryptencrypt",
            ],
            "time_licensing": ["getsystemtime", "getlocaltime", "comparesystemtime"],
        }

        for imp in imports:
            api_name = imp.get("name", "").lower()

            for category, patterns in license_api_patterns.items():
                if any(pattern in api_name for pattern in patterns):
                    license_apis.append(
                        {
                            "api": imp,
                            "license_category": category,
                            "usage_purpose": self._get_license_usage_purpose(category),
                            "bypass_difficulty": self._assess_bypass_difficulty(category),
                        }
                    )
                    break

        return license_apis

    def _identify_crypto_apis(self, imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify cryptographic APIs."""
        crypto_apis = []

        crypto_patterns = {
            "symmetric_crypto": ["cryptencrypt", "cryptdecrypt", "aes", "des"],
            "asymmetric_crypto": ["cryptsignhash", "cryptverifysignature", "rsa"],
            "hashing": ["cryptcreatehash", "crypthashdata", "cryptgethashparam"],
            "key_management": ["cryptgenkey", "cryptderivekey", "cryptdestroykey"],
            "random_generation": ["cryptgenrandom", "rtlgenrandom"],
            "certificate": ["certopensystemstore", "certfindcertificateinstore"],
        }

        for imp in imports:
            api_name = imp.get("name", "").lower()

            for category, patterns in crypto_patterns.items():
                if any(pattern in api_name for pattern in patterns):
                    crypto_apis.append(
                        {
                            "api": imp,
                            "crypto_category": category,
                            "algorithm_type": self._identify_crypto_algorithm(api_name),
                            "security_strength": self._assess_crypto_strength(api_name),
                        }
                    )
                    break

        return crypto_apis

    def _identify_anti_analysis_apis(self, imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify anti-analysis and anti-debugging APIs."""
        anti_analysis_apis = []

        anti_analysis_patterns = {
            "debugger_detection": [
                "isdebuggerpresent",
                "checkremotedebugger",
                "ntqueryinformationprocess",
            ],
            "vm_detection": [
                "getmodulehandle.*vbox",
                "getmodulehandle.*vmware",
                "createfile.*pipe",
            ],
            "analysis_evasion": ["virtualprotect", "gettickcount", "sleep", "timegettime"],
            "code_obfuscation": ["virtualalloc", "heapalloc", "memcpy", "memmove"],
        }

        for imp in imports:
            api_name = imp.get("name", "").lower()

            for category, patterns in anti_analysis_patterns.items():
                if any(pattern in api_name for pattern in patterns):
                    anti_analysis_apis.append(
                        {
                            "api": imp,
                            "anti_analysis_category": category,
                            "evasion_technique": self._identify_evasion_technique(category),
                            "countermeasure": self._suggest_countermeasure(category),
                        }
                    )
                    break

        return anti_analysis_apis

    def _identify_network_apis(self, imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify network-related APIs."""
        network_apis = []

        network_patterns = [
            "socket",
            "connect",
            "send",
            "recv",
            "wsastartup",
            "internetopen",
            "httpopen",
            "ftpopen",
        ]

        for imp in imports:
            api_name = imp.get("name", "").lower()
            if any(pattern in api_name for pattern in network_patterns):
                network_apis.append(
                    {
                        "api": imp,
                        "network_purpose": self._identify_network_purpose(api_name),
                        "protocol": self._identify_network_protocol(api_name),
                    }
                )

        return network_apis

    def _identify_file_system_apis(self, imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify file system APIs."""
        file_apis = []

        file_patterns = [
            "createfile",
            "readfile",
            "writefile",
            "deletefile",
            "copyfile",
            "movefile",
            "findfile",
        ]

        for imp in imports:
            api_name = imp.get("name", "").lower()
            if any(pattern in api_name for pattern in file_patterns):
                file_apis.append(
                    {
                        "api": imp,
                        "file_operation": self._identify_file_operation(api_name),
                        "access_type": self._identify_file_access_type(api_name),
                    }
                )

        return file_apis

    def _identify_registry_apis(self, imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify registry APIs."""
        registry_apis = []

        registry_patterns = ["regopen", "regclose", "regquery", "regset", "regdelete", "regenum"]

        for imp in imports:
            api_name = imp.get("name", "").lower()
            if any(pattern in api_name for pattern in registry_patterns):
                registry_apis.append(
                    {
                        "api": imp,
                        "registry_operation": self._identify_registry_operation(api_name),
                        "typical_usage": self._identify_registry_usage(api_name),
                    }
                )

        return registry_apis

    def _identify_process_apis(self, imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify process management APIs."""
        process_apis = []

        process_patterns = [
            "createprocess",
            "openprocess",
            "terminateprocess",
            "getmodule",
            "enumprocess",
        ]

        for imp in imports:
            api_name = imp.get("name", "").lower()
            if any(pattern in api_name for pattern in process_patterns):
                process_apis.append(
                    {
                        "api": imp,
                        "process_operation": self._identify_process_operation(api_name),
                        "security_implications": self._assess_process_security_implications(
                            api_name
                        ),
                    }
                )

        return process_apis

    def _identify_memory_apis(self, imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify memory management APIs."""
        memory_apis = []

        memory_patterns = [
            "virtualloc",
            "virtualfree",
            "heapalloc",
            "heapfree",
            "malloc",
            "free",
            "memcpy",
        ]

        for imp in imports:
            api_name = imp.get("name", "").lower()
            if any(pattern in api_name for pattern in memory_patterns):
                memory_apis.append(
                    {
                        "api": imp,
                        "memory_operation": self._identify_memory_operation(api_name),
                        "allocation_type": self._identify_allocation_type(api_name),
                    }
                )

        return memory_apis

    def _identify_debug_apis(self, imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify debugging-related APIs."""
        debug_apis = []

        debug_patterns = [
            "isdebuggerpresent",
            "outputdebugstring",
            "debugbreak",
            "waitfordebugevent",
        ]

        for imp in imports:
            api_name = imp.get("name", "").lower()
            if any(pattern in api_name for pattern in debug_patterns):
                debug_apis.append(
                    {
                        "api": imp,
                        "debug_purpose": self._identify_debug_purpose(api_name),
                        "anti_debug_potential": self._assess_anti_debug_potential(api_name),
                    }
                )

        return debug_apis

    # Helper methods for classification and analysis
    def _classify_api_type(self, api_name: str) -> str:
        """Classify API by its general type."""
        name_lower = api_name.lower()

        if any(pattern in name_lower for pattern in ["file", "read", "write"]):
            return "file_io"
        if any(pattern in name_lower for pattern in ["reg", "registry"]):
            return "registry"
        if any(pattern in name_lower for pattern in ["process", "thread"]):
            return "process_management"
        if any(pattern in name_lower for pattern in ["crypt", "hash"]):
            return "cryptography"
        if any(pattern in name_lower for pattern in ["socket", "internet", "http"]):
            return "network"
        return "general"

    def _assess_api_risk(self, api_name: str) -> str:
        """Assess the risk level of an API."""
        name_lower = api_name.lower()

        high_risk_apis = [
            "virtualallocex",
            "writeprocessmemory",
            "createremotethread",
            "isdebuggerpresent",
        ]
        medium_risk_apis = ["createprocess", "regsetvalue", "cryptencrypt", "internetopen"]

        if any(api in name_lower for api in high_risk_apis):
            return "high"
        if any(api in name_lower for api in medium_risk_apis):
            return "medium"
        return "low"

    def _get_api_description(self, api_name: str) -> str:
        """Get a description of what the API does."""
        api_descriptions = {
            "createfile": "Creates or opens a file or device",
            "readfile": "Reads data from a file",
            "writefile": "Writes data to a file",
            "regopenkeyex": "Opens a registry key",
            "regqueryvalueex": "Queries a registry value",
            "createprocess": "Creates a new process",
            "virtualallocex": "Allocates memory in another process",
            "isdebuggerpresent": "Checks if a debugger is present",
        }

        return api_descriptions.get(api_name.lower(), "Unknown API function")

    def _parse_plt_data(self, plt_data: str, imports: list[dict[str, Any]]):
        """Parse PLT data and add to imports."""
        import re

        # PLT entries typically have format like:
        # 0x00401000 plt.function_name
        # or
        # vaddr=0x00401000 paddr=0x00001000 type=FUNC name=plt.function_name
        plt_pattern = r"(?:vaddr=)?0x([0-9a-fA-F]+).*?(?:name=)?plt\.([a-zA-Z_][a-zA-Z0-9_]*)"

        seen_functions = set()

        for line in plt_data.split("\n"):
            match = re.search(plt_pattern, line)
            if match:
                address = int(match.group(1), 16)
                function_name = match.group(2)

                # Skip if we've already seen this function
                if function_name in seen_functions:
                    continue
                seen_functions.add(function_name)

                # Determine library based on function name
                lib_name = self._guess_library_from_function(function_name)

                # Add to imports
                imports.append(
                    {
                        "name": function_name,
                        "library": lib_name,
                        "address": hex(address),
                        "type": "plt",
                        "source": "PLT section",
                        "calling_convention": "cdecl",  # Default for PLT
                    }
                )

    def _guess_library_from_function(self, function_name: str) -> str:
        """Guess the library name based on the function name."""
        # Common function to library mappings
        function_library_map = {
            # libc functions
            "printf": "libc.so.6",
            "malloc": "libc.so.6",
            "free": "libc.so.6",
            "memcpy": "libc.so.6",
            "strlen": "libc.so.6",
            "strcpy": "libc.so.6",
            "strcmp": "libc.so.6",
            "fopen": "libc.so.6",
            "fclose": "libc.so.6",
            "fread": "libc.so.6",
            "fwrite": "libc.so.6",
            "exit": "libc.so.6",
            "getpid": "libc.so.6",
            "fork": "libc.so.6",
            "execve": "libc.so.6",
            # libpthread functions
            "pthread_create": "libpthread.so.0",
            "pthread_join": "libpthread.so.0",
            "pthread_mutex_lock": "libpthread.so.0",
            "pthread_mutex_unlock": "libpthread.so.0",
            # libdl functions
            "dlopen": "libdl.so.2",
            "dlsym": "libdl.so.2",
            "dlclose": "libdl.so.2",
            # libm functions
            "sin": "libm.so.6",
            "cos": "libm.so.6",
            "sqrt": "libm.so.6",
            "pow": "libm.so.6",
            # Windows API functions (for cross-platform analysis)
            "CreateFileA": "kernel32.dll",
            "CreateFileW": "kernel32.dll",
            "ReadFile": "kernel32.dll",
            "WriteFile": "kernel32.dll",
            "CreateProcessA": "kernel32.dll",
            "CreateProcessW": "kernel32.dll",
            "VirtualAlloc": "kernel32.dll",
            "VirtualProtect": "kernel32.dll",
            "LoadLibraryA": "kernel32.dll",
            "LoadLibraryW": "kernel32.dll",
            "GetProcAddress": "kernel32.dll",
            "MessageBoxA": "user32.dll",
            "MessageBoxW": "user32.dll",
            "CreateWindowExA": "user32.dll",
            "CreateWindowExW": "user32.dll",
            "RegOpenKeyExA": "advapi32.dll",
            "RegOpenKeyExW": "advapi32.dll",
            "CryptAcquireContextA": "advapi32.dll",
            "CryptAcquireContextW": "advapi32.dll",
        }

        # Check direct mapping
        if function_name in function_library_map:
            return function_library_map[function_name]

        # Check for common patterns
        func_lower = function_name.lower()

        # C runtime functions
        if func_lower.startswith("_") or func_lower in ["main", "atexit", "signal"]:
            return "libc.so.6"

        # Thread-related
        if "thread" in func_lower or "mutex" in func_lower:
            return "libpthread.so.0"

        # Math functions
        if func_lower in ["exp", "log", "tan", "atan", "ceil", "floor"]:
            return "libm.so.6"

        # Default to libc for unknown functions
        return "libc.so.6"

    def _classify_library_type(self, lib_name: str) -> str:
        """Classify library by its type."""
        name_lower = lib_name.lower()

        system_libs = ["kernel32", "user32", "advapi32", "ntdll"]
        crypto_libs = ["crypt32", "bcrypt"]
        network_libs = ["ws2_32", "wininet", "winhttp"]

        if any(lib in name_lower for lib in system_libs):
            return "system"
        if any(lib in name_lower for lib in crypto_libs):
            return "cryptography"
        if any(lib in name_lower for lib in network_libs):
            return "network"
        return "application"

    def _assess_library_security_impact(self, lib_name: str) -> str:
        """Assess the security impact of a library."""
        high_impact_libs = ["ntdll", "advapi32", "crypt32"]
        medium_impact_libs = ["kernel32", "user32", "ws2_32"]

        if any(lib in lib_name.lower() for lib in high_impact_libs):
            return "high"
        if any(lib in lib_name.lower() for lib in medium_impact_libs):
            return "medium"
        return "low"

    def _get_common_apis_for_library(self, lib_name: str) -> list[str]:
        """Get common APIs for a library."""
        common_apis = {
            "kernel32": ["CreateFile", "ReadFile", "WriteFile", "CreateProcess"],
            "user32": ["MessageBox", "CreateWindow", "ShowWindow"],
            "advapi32": ["RegOpenKeyEx", "RegQueryValueEx", "AdjustTokenPrivileges"],
            "ws2_32": ["WSAStartup", "socket", "connect", "send", "recv"],
        }

        return common_apis.get(lib_name.lower(), [])

    # Additional helper methods would continue here for all the categorization functions
    # Each function returns appropriate classifications based on API name analysis

    def _get_license_usage_purpose(self, category: str) -> str:
        """Get the purpose of license API usage."""
        purposes = {
            "hardware_fingerprinting": "Generate unique hardware identifier",
            "registry_licensing": "Store/retrieve license information",
            "file_licensing": "Read/write license files",
            "network_licensing": "Validate license online",
            "crypto_licensing": "Encrypt/decrypt license data",
            "time_licensing": "Check license expiration",
        }
        return purposes.get(category, "Unknown purpose")

    def _assess_bypass_difficulty(self, category: str) -> str:
        """Assess difficulty of bypassing license mechanism."""
        difficulty_map = {
            "hardware_fingerprinting": "medium",
            "registry_licensing": "low",
            "file_licensing": "low",
            "network_licensing": "high",
            "crypto_licensing": "high",
            "time_licensing": "medium",
        }
        return difficulty_map.get(category, "unknown")

    def _identify_crypto_algorithm(self, api_name: str) -> str:
        """Identify crypto algorithm from API name."""
        if "aes" in api_name.lower():
            return "AES"
        if "des" in api_name.lower():
            return "DES"
        if "rsa" in api_name.lower():
            return "RSA"
        if "hash" in api_name.lower():
            return "Hash"
        return "Unknown"

    def _assess_crypto_strength(self, api_name: str) -> str:
        """Assess cryptographic strength."""
        strong_algos = ["aes", "sha256", "rsa"]
        weak_algos = ["des", "md5", "rc4"]

        name_lower = api_name.lower()
        if any(algo in name_lower for algo in strong_algos):
            return "strong"
        if any(algo in name_lower for algo in weak_algos):
            return "weak"
        return "medium"

    def _identify_evasion_technique(self, category: str) -> str:
        """Identify evasion technique."""
        techniques = {
            "debugger_detection": "Anti-debugging",
            "vm_detection": "Anti-VM",
            "analysis_evasion": "Anti-analysis",
            "code_obfuscation": "Code obfuscation",
        }
        return techniques.get(category, "Unknown")

    def _suggest_countermeasure(self, category: str) -> str:
        """Suggest countermeasure for evasion technique."""
        countermeasures = {
            "debugger_detection": "Patch debugger checks or use stealthier debugger",
            "vm_detection": "Use physical machine or better VM hiding",
            "analysis_evasion": "Use dynamic analysis or emulation",
            "code_obfuscation": "Use deobfuscation tools or manual analysis",
        }
        return countermeasures.get(category, "Manual analysis required")

    # Additional identification methods for various API categories
    def _identify_network_purpose(self, api_name: str) -> str:
        """Identify network API purpose."""
        if "socket" in api_name.lower():
            return "Socket operations"
        if "http" in api_name.lower():
            return "HTTP communications"
        if "ftp" in api_name.lower():
            return "FTP operations"
        return "General networking"

    def _identify_network_protocol(self, api_name: str) -> str:
        """Identify network protocol."""
        if "tcp" in api_name.lower():
            return "TCP"
        if "udp" in api_name.lower():
            return "UDP"
        if "http" in api_name.lower():
            return "HTTP"
        return "Unknown"

    def _identify_file_operation(self, api_name: str) -> str:
        """Identify file operation type."""
        if "create" in api_name.lower():
            return "Create/Open"
        if "read" in api_name.lower():
            return "Read"
        if "write" in api_name.lower():
            return "Write"
        if "delete" in api_name.lower():
            return "Delete"
        return "Unknown"

    def _identify_file_access_type(self, api_name: str) -> str:
        """Identify file access type based on API name."""
        name_lower = api_name.lower()

        # Analyze API name for access patterns
        access_types = []

        # Read access patterns
        read_patterns = [
            "readfile",
            "getfileattributes",
            "getfilesize",
            "findfirst",
            "findnext",
            "getfileinformationbyhandle",
            "readfileex",
            "readfilescatter",
            "openfile",
            "createfile.*generic_read",
            "_read",
            "fread",
            "fgets",
            "getprivateprofilestring",
            "loadlibrary",
            "loadimage",
        ]

        # Write access patterns
        write_patterns = [
            "writefile",
            "setfileattributes",
            "setendoffile",
            "createfile.*generic_write",
            "writefileex",
            "writefilegather",
            "_write",
            "fwrite",
            "fputs",
            "setprivateprofilestring",
            "copyfile",
            "movefile",
            "deletefile",
            "createfile.*file_write",
            "flushfilebuffers",
        ]

        # Execute access patterns
        execute_patterns = [
            "createprocess",
            "shellexecute",
            "winexec",
            "loadlibrary",
            "createfile.*file_execute",
            "mapviewoffile.*file_map_execute",
        ]

        # Modify/Delete patterns
        modify_patterns = [
            "setfilepointer",
            "setfiletime",
            "setfilevaliddata",
            "deletefile",
            "removedirectory",
            "movefileex",
            "replaceifle",
            "truncatefile",
            "setfileinformationbyhandle",
        ]

        # Check for read access
        if any(pattern in name_lower for pattern in read_patterns):
            access_types.append("Read")

        # Check for write access
        if any(pattern in name_lower for pattern in write_patterns):
            access_types.append("Write")

        # Check for execute access
        if any(pattern in name_lower for pattern in execute_patterns):
            access_types.append("Execute")

        # Check for modify/delete access
        if any(pattern in name_lower for pattern in modify_patterns):
            access_types.append("Modify")

        # Check for specific access flags in CreateFile
        if "createfile" in name_lower:
            # Parse for specific access flags
            if "generic_all" in name_lower or "file_all_access" in name_lower:
                access_types = ["Read", "Write", "Execute", "Modify"]
            elif "generic_read" in name_lower or "file_read" in name_lower:
                if "Read" not in access_types:
                    access_types.append("Read")
            elif "generic_write" in name_lower or "file_write" in name_lower:
                if "Write" not in access_types:
                    access_types.append("Write")
            elif "generic_execute" in name_lower or "file_execute" in name_lower:
                if "Execute" not in access_types:
                    access_types.append("Execute")

        # Check for file mapping operations
        if "mapviewoffile" in name_lower:
            if "file_map_read" in name_lower:
                if "Read" not in access_types:
                    access_types.append("Read")
            elif "file_map_write" in name_lower:
                if "Write" not in access_types:
                    access_types.append("Write")
            elif "file_map_all_access" in name_lower:
                access_types = ["Read", "Write", "Execute"]

        # Check for directory operations
        if any(
            pattern in name_lower
            for pattern in ["createdirectory", "removedirectory", "findfirstfile"]
        ):
            if "Directory" not in access_types:
                access_types.append("Directory")

        # Default if no specific pattern matches
        if not access_types:
            # Try to make an educated guess based on common patterns
            if "open" in name_lower or "create" in name_lower:
                access_types.append("Read/Write")
            elif "get" in name_lower or "query" in name_lower:
                access_types.append("Read")
            elif "set" in name_lower or "put" in name_lower:
                access_types.append("Write")
            else:
                access_types.append("Unknown")

        # Format the result
        if len(access_types) == 1:
            return access_types[0]
        # Remove duplicates and sort
        unique_types = sorted(list(set(access_types)))
        return "/".join(unique_types)

    def _identify_registry_operation(self, api_name: str) -> str:
        """Identify registry operation."""
        if "open" in api_name.lower():
            return "Open key"
        if "query" in api_name.lower():
            return "Query value"
        if "set" in api_name.lower():
            return "Set value"
        return "Unknown"

    def _identify_registry_usage(self, api_name: str) -> str:
        """Identify typical registry usage based on API name."""
        name_lower = api_name.lower()

        # Analyze registry API patterns for specific usage types

        # License/Activation patterns
        license_patterns = [
            "software\\microsoft\\windows\\currentversion\\uninstall",
            "software\\licenses",
            "software\\registration",
            "activation",
            "serial",
            "productkey",
            "licensekey",
            "trial",
            "evaluation",
        ]

        # Configuration/Settings patterns
        config_patterns = [
            "software\\microsoft\\windows\\currentversion\\run",
            "software\\policies",
            "settings",
            "preferences",
            "configuration",
            "options",
            "parameters",
            "software\\classes",
        ]

        # Security/Permission patterns
        security_patterns = [
            "sam\\sam",
            "security\\policy",
            "system\\currentcontrolset\\control\\lsa",
            "software\\microsoft\\windows\\currentversion\\policies",
            "privileges",
            "accesscontrol",
            "permissions",
        ]

        # System Information patterns
        system_patterns = [
            "hardware\\description\\system",
            "system\\currentcontrolset\\control",
            "software\\microsoft\\windows nt\\currentversion",
            "processor",
            "bios",
            "systeminfo",
        ]

        # Persistence/Autostart patterns
        persistence_patterns = [
            "run",
            "runonce",
            "runonceex",
            "startup",
            "services",
            "software\\microsoft\\windows\\currentversion\\explorer\\shell folders",
            "userinit",
            "winlogon",
            "bootexecute",
        ]

        # Network Configuration patterns
        network_patterns = [
            "system\\currentcontrolset\\services\\tcpip",
            "software\\microsoft\\windows\\currentversion\\internet settings",
            "networkaddress",
            "proxy",
            "dns",
        ]

        # User/Account patterns
        user_patterns = [
            "software\\microsoft\\windows\\currentversion\\explorer",
            "identities",
            "profilelist",
            "userdata",
            "accounts",
        ]

        # Software Installation patterns
        install_patterns = [
            "uninstall",
            "installer",
            "components",
            "setup",
            "software\\microsoft\\windows\\currentversion\\installer",
            "installdate",
            "displayversion",
        ]

        # Check for specific usage patterns
        usage_types = []

        # Check against all pattern categories
        if any(pattern in name_lower for pattern in license_patterns):
            usage_types.append("License/Activation management")

        if any(pattern in name_lower for pattern in config_patterns):
            usage_types.append("Configuration/Settings management")

        if any(pattern in name_lower for pattern in security_patterns):
            usage_types.append("Security/Permission configuration")

        if any(pattern in name_lower for pattern in system_patterns):
            usage_types.append("System information retrieval")

        if any(pattern in name_lower for pattern in persistence_patterns):
            usage_types.append("Persistence/Autostart configuration")

        if any(pattern in name_lower for pattern in network_patterns):
            usage_types.append("Network configuration")

        if any(pattern in name_lower for pattern in user_patterns):
            usage_types.append("User profile management")

        if any(pattern in name_lower for pattern in install_patterns):
            usage_types.append("Software installation tracking")

        # Check for specific registry operations
        if "regqueryvalue" in name_lower or "reggetvalue" in name_lower:
            if not usage_types:
                usage_types.append("Registry value reading")
        elif "regsetvalue" in name_lower or "regcreatekeyex" in name_lower:
            if not usage_types:
                usage_types.append("Registry modification")
        elif "regdeletekey" in name_lower or "regdeletevalue" in name_lower:
            if not usage_types:
                usage_types.append("Registry cleanup")
        elif "regenumkey" in name_lower or "regenumvalue" in name_lower:
            if not usage_types:
                usage_types.append("Registry enumeration")
        elif "regopenkeyex" in name_lower:
            if not usage_types:
                usage_types.append("Registry access")

        # Check for specific hive references
        if "hkey_local_machine" in name_lower or "hklm" in name_lower:
            if "System-wide configuration" not in usage_types:
                usage_types.append("System-wide configuration")
        elif "hkey_current_user" in name_lower or "hkcu" in name_lower:
            if "User-specific configuration" not in usage_types:
                usage_types.append("User-specific configuration")
        elif "hkey_classes_root" in name_lower or "hkcr" in name_lower:
            if "File association management" not in usage_types:
                usage_types.append("File association management")

        # Default if no specific pattern matches
        if not usage_types:
            # Make educated guess based on operation type
            if "query" in name_lower or "get" in name_lower:
                usage_types.append("Registry information retrieval")
            elif "set" in name_lower or "create" in name_lower:
                usage_types.append("Registry configuration")
            elif "delete" in name_lower or "remove" in name_lower:
                usage_types.append("Registry cleanup")
            else:
                usage_types.append("General registry operation")

        # Format the result
        if len(usage_types) == 1:
            return usage_types[0]
        # Remove duplicates and join
        unique_types = list(dict.fromkeys(usage_types))  # Preserves order
        return "; ".join(unique_types)

    def _identify_process_operation(self, api_name: str) -> str:
        """Identify process operation."""
        if "create" in api_name.lower():
            return "Create process"
        if "open" in api_name.lower():
            return "Open process"
        if "terminate" in api_name.lower():
            return "Terminate process"
        return "Unknown"

    def _assess_process_security_implications(self, api_name: str) -> str:
        """Assess security implications of process APIs."""
        dangerous_apis = ["createremotethread", "writeprocessmemory"]
        if any(api in api_name.lower() for api in dangerous_apis):
            return "High - Potential code injection"
        return "Medium - Process manipulation"

    def _identify_memory_operation(self, api_name: str) -> str:
        """Identify memory operation."""
        if "alloc" in api_name.lower():
            return "Allocate"
        if "free" in api_name.lower():
            return "Free"
        if "copy" in api_name.lower():
            return "Copy"
        return "Unknown"

    def _identify_allocation_type(self, api_name: str) -> str:
        """Identify memory allocation type."""
        if "virtual" in api_name.lower():
            return "Virtual memory"
        if "heap" in api_name.lower():
            return "Heap memory"
        return "General"

    def _identify_debug_purpose(self, api_name: str) -> str:
        """Identify debug API purpose."""
        if "present" in api_name.lower():
            return "Debugger detection"
        if "output" in api_name.lower():
            return "Debug output"
        return "Debug control"

    def _assess_anti_debug_potential(self, api_name: str) -> str:
        """Assess anti-debug potential."""
        if "present" in api_name.lower():
            return "High"
        return "Low"

    def _categorize_symbol(self, symbol_name: str) -> str:
        """Categorize symbol by type."""
        if symbol_name.startswith("_"):
            return "private"
        if symbol_name.isupper():
            return "constant"
        return "public"

    def _assess_symbol_relevance(self, symbol_name: str) -> str:
        """Assess symbol relevance for analysis."""
        important_patterns = ["main", "entry", "init", "license", "key", "validate"]
        if any(pattern in symbol_name.lower() for pattern in important_patterns):
            return "high"
        return "low"

    def _analyze_export_purpose(self, export_name: str) -> str:
        """Analyze export function purpose."""
        if "main" in export_name.lower():
            return "Entry point"
        if "dll" in export_name.lower():
            return "DLL function"
        return "Library function"

    def _analyze_relocation_purpose(self, relocation: dict[str, Any]) -> str:
        """Analyze relocation purpose."""
        reloc_type = relocation.get("type", "")
        if "absolute" in reloc_type.lower():
            return "Absolute address relocation"
        if "relative" in reloc_type.lower():
            return "Relative address relocation"
        return "Unknown relocation"

    def _generate_api_statistics(self, result: dict[str, Any]) -> dict[str, Any]:
        """Generate comprehensive API statistics."""
        stats = {
            "total_imports": len(result.get("imports", [])),
            "total_exports": len(result.get("exports", [])),
            "total_symbols": len(result.get("symbols", [])),
            "dll_count": len(result.get("dll_dependencies", [])),
            "suspicious_api_count": len(result.get("suspicious_apis", [])),
            "license_api_count": len(result.get("license_apis", [])),
            "crypto_api_count": len(result.get("crypto_apis", [])),
            "anti_analysis_api_count": len(result.get("anti_analysis_apis", [])),
            "category_distribution": {},
        }

        # Calculate category distribution
        categories = result.get("api_categories", {})
        for category, apis in categories.items():
            stats["category_distribution"][category] = len(apis)

        return stats

    def _perform_security_assessment(self, result: dict[str, Any]) -> dict[str, Any]:
        """Perform overall security assessment."""
        assessment = {
            "risk_level": "low",
            "security_concerns": [],
            "recommendations": [],
            "threat_indicators": {},
        }

        # Analyze risk factors
        suspicious_count = len(result.get("suspicious_apis", []))
        anti_analysis_count = len(result.get("anti_analysis_apis", []))
        crypto_count = len(result.get("crypto_apis", []))

        # Determine overall risk level including crypto usage
        if suspicious_count > 5 or anti_analysis_count > 3 or crypto_count > 10:
            assessment["risk_level"] = "high"
        elif suspicious_count > 2 or anti_analysis_count > 1 or crypto_count > 5:
            assessment["risk_level"] = "medium"

        # Add security concerns
        if suspicious_count > 0:
            assessment["security_concerns"].append(
                f"Contains {suspicious_count} suspicious API calls"
            )
        if anti_analysis_count > 0:
            assessment["security_concerns"].append(
                f"Contains {anti_analysis_count} anti-analysis techniques"
            )
        if crypto_count > 0:
            assessment["security_concerns"].append(
                f"Uses {crypto_count} cryptographic APIs - potential license protection"
            )

        return assessment

    def _get_api_cross_references(
        self, r2: R2Session, imports: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Get cross-references for important APIs."""
        xrefs = {}

        # Focus on license and crypto APIs
        important_apis = [
            imp
            for imp in imports
            if self._classify_api_type(imp.get("name", "")) in ["cryptography"]
            or "license" in imp.get("name", "").lower()
        ]

        for api in important_apis[:10]:  # Limit for performance
            api_name = api.get("name", "")
            try:
                # Get cross-references to this API
                xref_data = r2._execute_command(f"axt sym.imp.{api_name}", expect_json=False)
                if xref_data:
                    xrefs[api_name] = xref_data.strip().split("\n")
            except R2Exception as e:
                self.logger.error("R2Exception in radare2_imports: %s", e)
                continue

        return xrefs


def analyze_binary_imports_exports(
    binary_path: str, radare2_path: str | None = None
) -> dict[str, Any]:
    """Perform comprehensive import/export analysis on a binary.

    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable

    Returns:
        Complete import/export analysis results

    """
    analyzer = R2ImportExportAnalyzer(binary_path, radare2_path)
    return analyzer.analyze_imports_exports()


__all__ = ["R2ImportExportAnalyzer", "analyze_binary_imports_exports"]
