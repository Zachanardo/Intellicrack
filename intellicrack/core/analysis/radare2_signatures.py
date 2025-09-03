"""Radare2 signature analysis module for pattern matching and function identification."""

import logging
from typing import Any

from intellicrack.logger import logger

from ...utils.tools.radare2_utils import R2Exception, R2Session, r2_session

"""
Radare2 FLIRT Signature Analysis and Function Identification Engine

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


class R2SignatureAnalyzer:
    """Advanced signature analysis engine using radare2's FLIRT and Zignature capabilities.

    Provides sophisticated function identification for:
    - Library function recognition
    - Compiler runtime identification
    - Crypto algorithm detection
    - Anti-analysis technique identification
    - License validation routine recognition
    - Known vulnerability pattern detection
    """

    def __init__(self, binary_path: str, radare2_path: str | None = None):
        """Initialize signature analyzer.

        Args:
            binary_path: Path to binary file
            radare2_path: Optional path to radare2 executable

        """
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)
        self.signature_cache = {}
        self.custom_signatures = {}

    def analyze_signatures(self) -> dict[str, Any]:
        """Perform comprehensive signature analysis on the binary.

        Returns:
            Complete signature analysis results

        """
        result = {
            "binary_path": self.binary_path,
            "flirt_signatures": {},
            "zignature_matches": {},
            "identified_functions": [],
            "library_functions": {},
            "compiler_artifacts": {},
            "crypto_functions": [],
            "anti_analysis_functions": [],
            "license_validation_functions": [],
            "vulnerability_signatures": [],
            "custom_pattern_matches": [],
            "signature_statistics": {},
            "unidentified_functions": [],
            "confidence_analysis": {},
        }

        try:
            with r2_session(self.binary_path, self.radare2_path) as r2:
                # Apply FLIRT signatures
                result["flirt_signatures"] = self._apply_flirt_signatures(r2)

                # Apply Zignatures
                result["zignature_matches"] = self._apply_zignatures(r2)

                # Get all functions and categorize identified ones
                all_functions = r2.get_functions()
                result["identified_functions"] = self._categorize_identified_functions(all_functions)

                # Analyze library functions
                result["library_functions"] = self._analyze_library_functions(r2, all_functions)

                # Detect compiler artifacts
                result["compiler_artifacts"] = self._detect_compiler_artifacts(r2, all_functions)

                # Identify crypto functions
                result["crypto_functions"] = self._identify_crypto_functions(r2, all_functions)

                # Detect anti-analysis functions
                result["anti_analysis_functions"] = self._detect_anti_analysis_functions(r2, all_functions)

                # Identify license validation functions
                result["license_validation_functions"] = self._identify_license_validation_functions(r2, all_functions)

                # Check for known vulnerability signatures
                result["vulnerability_signatures"] = self._check_vulnerability_signatures(r2, all_functions)

                # Apply custom pattern matching
                result["custom_pattern_matches"] = self._apply_custom_patterns(r2, all_functions)

                # Find unidentified functions
                result["unidentified_functions"] = self._find_unidentified_functions(all_functions)

                # Generate statistics
                result["signature_statistics"] = self._generate_signature_statistics(result)

                # Perform confidence analysis
                result["confidence_analysis"] = self._analyze_identification_confidence(result)

        except R2Exception as e:
            result["error"] = str(e)
            self.logger.error(f"Signature analysis failed: {e}")

        return result

    def _apply_flirt_signatures(self, r2: R2Session) -> dict[str, Any]:
        """Apply FLIRT signatures to identify library functions."""
        flirt_result = {
            "signatures_applied": 0,
            "functions_identified": 0,
            "signature_files_used": [],
            "matches": [],
        }

        try:
            # Apply FLIRT signatures
            r2._execute_command("zf")

            # Get information about applied signatures
            sig_info = r2._execute_command("zi")
            if sig_info:
                flirt_result["signature_info"] = sig_info.strip()

            # Get functions that were identified by signatures
            functions = r2.get_functions()
            identified_by_flirt = []

            for func in functions:
                func_name = func.get("name", "")
                # FLIRT-identified functions typically have specific naming patterns
                if (
                    func_name.startswith("sym.")
                    and not func_name.startswith("sym.imp.")
                    and not func_name.startswith("sym.entry")
                    and len(func_name) > 10
                ):
                    # Get more details about this function
                    func_addr = func.get("offset", 0)
                    if func_addr:
                        try:
                            func_info = r2.get_function_info(func_addr)
                            if func_info:
                                identified_by_flirt.append(
                                    {
                                        "name": func_name,
                                        "address": hex(func_addr),
                                        "size": func.get("size", 0),
                                        "signature_type": "flirt",
                                    }
                                )
                        except R2Exception as e:
                            logger.error("R2Exception in radare2_signatures: %s", e)
                            continue

            flirt_result["matches"] = identified_by_flirt
            flirt_result["functions_identified"] = len(identified_by_flirt)

        except R2Exception as e:
            flirt_result["error"] = str(e)
            self.logger.debug(f"FLIRT signature application failed: {e}")

        return flirt_result

    def _apply_zignatures(self, r2: R2Session) -> dict[str, Any]:
        """Apply Zignatures for function identification."""
        zignature_result = {
            "signatures_loaded": 0,
            "matches": [],
            "match_confidence": {},
        }

        try:
            # Check if zignatures are available
            zignature_info = r2._execute_command("z")

            # Verify zignature system is functional
            if not zignature_info or "no signatures" in zignature_info.lower():
                self.logger.warning("No zignatures available in radare2 session")
                return {"signatures": [], "signature_count": 0}

            # Search for zignature matches
            zignature_matches = r2._execute_command("zs")
            if zignature_matches:
                # Parse zignature results
                matches = []
                for line in zignature_matches.split("\n"):
                    if line.strip() and "match" in line.lower():
                        matches.append(line.strip())

                zignature_result["matches"] = matches

            # Get zignature statistics
            zignature_stats = r2._execute_command("zi")
            if zignature_stats:
                zignature_result["statistics"] = zignature_stats.strip()

        except R2Exception as e:
            zignature_result["error"] = str(e)
            self.logger.debug(f"Zignature analysis failed: {e}")

        return zignature_result

    def _categorize_identified_functions(self, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Categorize functions based on their names and signatures."""
        categorized = []

        for func in functions:
            func_name = func.get("name", "")
            func_addr = func.get("offset", 0)

            category = self._determine_function_category(func_name)

            categorized.append(
                {
                    "name": func_name,
                    "address": hex(func_addr) if func_addr else "0x0",
                    "size": func.get("size", 0),
                    "category": category,
                    "confidence": self._calculate_name_confidence(func_name),
                    "signature_source": self._determine_signature_source(func_name),
                }
            )

        return categorized

    def _determine_function_category(self, func_name: str) -> str:
        """Determine function category based on name patterns."""
        name_lower = func_name.lower()

        # System/API functions
        if func_name.startswith("sym.imp.") or any(prefix in name_lower for prefix in ["get", "set", "create", "delete", "open", "close"]):
            return "system_api"

        # C Runtime functions
        if func_name.startswith("sym._") or any(crt in name_lower for crt in ["malloc", "free", "printf", "scanf", "strlen", "strcmp"]):
            return "c_runtime"

        # Crypto functions
        if any(crypto in name_lower for crypto in ["crypt", "hash", "aes", "des", "rsa", "sha", "md5"]):
            return "cryptographic"

        # String functions
        if any(str_func in name_lower for str_func in ["str", "mem", "copy", "move"]):
            return "string_manipulation"

        # Network functions
        if any(net in name_lower for net in ["socket", "connect", "send", "recv", "http"]):
            return "network"

        # File I/O functions
        if any(file_func in name_lower for file_func in ["file", "read", "write", "seek"]):
            return "file_io"

        # Registry functions
        if any(reg in name_lower for reg in ["reg", "key", "value"]):
            return "registry"

        # User-defined functions
        if func_name.startswith("fcn.") or func_name.startswith("sub_"):
            return "user_defined"

        # Entry points
        if "entry" in name_lower or "main" in name_lower:
            return "entry_point"

        return "unknown"

    def _calculate_name_confidence(self, func_name: str) -> float:
        """Calculate confidence level for function identification."""
        # Higher confidence for imported functions
        if func_name.startswith("sym.imp."):
            return 0.95

        # High confidence for well-known C runtime functions
        known_crt = ["malloc", "free", "printf", "scanf", "strlen", "strcmp", "strcpy", "memcpy"]
        if any(crt in func_name.lower() for crt in known_crt):
            return 0.9

        # Medium confidence for API-like names
        if any(prefix in func_name.lower() for prefix in ["get", "set", "create", "delete"]):
            return 0.7

        # Low confidence for generic or mangled names
        if func_name.startswith("fcn.") or func_name.startswith("sub_"):
            return 0.3

        # Medium confidence for other recognized patterns
        return 0.6

    def _determine_signature_source(self, func_name: str) -> str:
        """Determine the source of function signature."""
        if func_name.startswith("sym.imp."):
            return "import_table"
        if func_name.startswith("sym._"):
            return "flirt_signature"
        if func_name.startswith("fcn."):
            return "analysis_heuristic"
        if func_name.startswith("sub_"):
            return "disassembly"
        return "signature_database"

    def _analyze_library_functions(self, r2: R2Session, functions: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze and categorize library functions."""
        library_analysis = {
            "c_runtime": [],
            "windows_api": [],
            "posix_api": [],
            "crypto_libraries": [],
            "network_libraries": [],
            "ui_libraries": [],
            "compression_libraries": [],
            "database_libraries": [],
            "r2_enhanced_info": {},
        }

        # Use r2 session to get additional library info
        try:
            # Get imports from r2
            imports = r2.run_command("ii")  # Import information
            import_libs = r2.run_command("il")  # Import libraries

            # Parse library dependencies
            library_analysis["r2_enhanced_info"]["imports"] = imports
            library_analysis["r2_enhanced_info"]["libraries"] = import_libs

            # Get PLT entries for better library function detection
            plt_entries = r2.run_command("afl~plt")
            library_analysis["r2_enhanced_info"]["plt_entries"] = plt_entries

        except Exception as e:
            self.logger.debug(f"Failed to get r2 library info: {e}")

        for func in functions:
            func_name = func.get("name", "")
            name_lower = func_name.lower()
            func_addr = func.get("offset", 0)

            # Use r2 to get function-specific info
            try:
                # Get function info from r2
                func_info = r2.run_command(f"afi @ {func_addr}")

                # Check if function is imported
                is_import = "import" in func_info or func_name.startswith("sym.imp.")

                # Get function size and complexity from r2
                func_size = r2.run_command(f"afi~size @ {func_addr}")

                # Enhance function data with r2 info
                func["r2_import"] = is_import
                func["r2_size"] = func_size
                func["r2_info"] = func_info

            except Exception as e:
                self.logger.debug(f"Failed to get r2 info for {func_name}: {e}")

            # C Runtime Library
            if any(crt in name_lower for crt in ["msvcrt", "ucrt", "libc", "malloc", "free", "printf"]):
                library_analysis["c_runtime"].append(func)

            # Windows API
            elif any(win_api in name_lower for win_api in ["kernel32", "user32", "advapi32", "ntdll"]):
                library_analysis["windows_api"].append(func)

            # POSIX API
            elif any(posix in name_lower for posix in ["pthread", "dlopen", "mmap", "fork"]):
                library_analysis["posix_api"].append(func)

            # Crypto Libraries
            elif any(crypto in name_lower for crypto in ["openssl", "crypto", "bcrypt", "crypt32"]):
                library_analysis["crypto_libraries"].append(func)

            # Network Libraries
            elif any(net in name_lower for net in ["ws2_32", "wininet", "winhttp", "socket"]):
                library_analysis["network_libraries"].append(func)

            # UI Libraries
            elif any(ui in name_lower for ui in ["gdi32", "comctl32", "shell32", "ole32"]):
                library_analysis["ui_libraries"].append(func)

            # Compression Libraries
            elif any(comp in name_lower for comp in ["zlib", "bzip2", "lzma", "deflate"]):
                library_analysis["compression_libraries"].append(func)

            # Database Libraries
            elif any(db in name_lower for db in ["sqlite", "odbc", "oledb"]):
                library_analysis["database_libraries"].append(func)

        return library_analysis

    def _detect_compiler_artifacts(self, r2: R2Session, functions: list[dict[str, Any]]) -> dict[str, Any]:
        """Detect compiler-specific artifacts and runtime functions."""
        compiler_artifacts = {
            "msvc_artifacts": [],
            "gcc_artifacts": [],
            "clang_artifacts": [],
            "borland_artifacts": [],
            "runtime_checks": [],
            "exception_handling": [],
            "stack_guards": [],
            "compiler_info": {},
            "build_info": {},
        }

        # Use r2 to detect compiler and build information
        try:
            # Get binary info for compiler detection
            binary_info = r2.run_command("iI")  # Binary information
            compiler_artifacts["build_info"]["binary_info"] = binary_info

            # Check for compiler signatures in strings
            compiler_strings = r2.run_command("iz~GCC|MSVC|clang|Borland")
            compiler_artifacts["compiler_info"]["strings"] = compiler_strings

            # Analyze entry point for compiler-specific initialization
            entry_point = r2.run_command("ie")  # Entry point
            entry_disasm = r2.run_command("pd 50 @ entry0")  # Disassemble entry

            # Store entry point information for analysis
            compiler_artifacts["entry_analysis"] = {
                "entry_point_info": entry_point,
                "entry_disasm": entry_disasm,
            }

            # Detect compiler from entry point patterns
            if "security_init_cookie" in entry_disasm:
                compiler_artifacts["compiler_info"]["detected"] = "MSVC"
            elif "__libc_start_main" in entry_disasm:
                compiler_artifacts["compiler_info"]["detected"] = "GCC/Linux"
            elif "_start" in entry_disasm and "note.ABI-tag" in binary_info:
                compiler_artifacts["compiler_info"]["detected"] = "GCC"

            # Get sections for additional compiler hints
            sections = r2.run_command("iS")  # Sections
            if ".gcc_except_table" in sections:
                compiler_artifacts["compiler_info"]["gcc_exceptions"] = True
            if ".msvcjmc" in sections:
                compiler_artifacts["compiler_info"]["msvc_jmc"] = True

        except Exception as e:
            self.logger.debug(f"Failed to get compiler info from r2: {e}")

        for func in functions:
            func_name = func.get("name", "")
            name_lower = func_name.lower()
            func_addr = func.get("offset", 0)

            # Use r2 to analyze function for compiler artifacts
            try:
                # Get function assembly
                func_asm = r2.run_command(f"pdf @ {func_addr}")

                # Check for stack canary setup
                if "fs:0x28" in func_asm or "__stack_chk_fail" in func_asm:
                    func["has_stack_protection"] = True

                # Check for SEH setup (Windows)
                if "__SEH_prolog" in func_asm or "fs:0" in func_asm:
                    func["has_seh"] = True

            except Exception as e:
                self.logger.debug(f"Failed to analyze {func_name}: {e}")

            # MSVC artifacts
            if any(msvc in name_lower for msvc in ["__security_", "__report_", "_crt", "_chk"]):
                compiler_artifacts["msvc_artifacts"].append(func)

            # GCC artifacts
            elif any(gcc in name_lower for gcc in ["__stack_chk", "__gxx_", "_gnu_"]):
                compiler_artifacts["gcc_artifacts"].append(func)

            # Exception handling
            elif any(eh in name_lower for eh in ["__eh_", "_except_", "__try", "__catch"]):
                compiler_artifacts["exception_handling"].append(func)

            # Stack protection
            elif any(stack in name_lower for stack in ["__stack_chk", "__guard", "_security_"]):
                compiler_artifacts["stack_guards"].append(func)

            # Runtime checks
            elif any(check in name_lower for check in ["__chk", "_check_", "__valid"]):
                compiler_artifacts["runtime_checks"].append(func)

        return compiler_artifacts

    def _identify_crypto_functions(self, r2: R2Session, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify cryptographic functions and algorithms."""
        crypto_functions = []

        crypto_patterns = {
            "aes": ["aes", "rijndael"],
            "des": ["des", "3des", "triple"],
            "rsa": ["rsa", "pubkey"],
            "hash": ["sha", "md5", "md4", "hash"],
            "random": ["rand", "random", "prng"],
            "crypto_api": ["crypt", "cipher", "encrypt", "decrypt"],
        }

        # Use r2 to search for crypto constants and patterns
        try:
            # Search for common crypto constants
            aes_sbox = r2.run_command("/x 637c777bf26b6fc5")  # AES S-box
            des_sbox = r2.run_command("/x 14041100001010400")  # DES permutation
            sha_const = r2.run_command("/x 67452301efcdab89")  # SHA-1 init

            # Search for crypto-related strings
            crypto_strings = r2.run_command("iz~crypt|cipher|aes|des|rsa|sha|md5")

            # Get cross-references to crypto imports
            crypto_imports = r2.run_command("ii~crypt|ssl|tls")

        except Exception as e:
            self.logger.debug(f"Failed to search for crypto patterns: {e}")
            aes_sbox = des_sbox = sha_const = crypto_strings = crypto_imports = ""

        for func in functions:
            func_name = func.get("name", "")
            name_lower = func_name.lower()
            func_addr = func.get("offset", 0)

            crypto_info = {
                "function": func,
                "crypto_type": None,
                "patterns_matched": [],
                "confidence": 0.0,
                "r2_analysis": {},
            }

            # Use r2 to analyze function for crypto operations
            try:
                # Get function disassembly
                func_asm = r2.run_command(f"pdr @ {func_addr}")  # Recursive disassemble

                # Check for crypto-specific instructions
                if "aesenc" in func_asm or "aesdec" in func_asm:
                    crypto_info["r2_analysis"]["aes_instructions"] = True
                    crypto_info["crypto_type"] = "aes"
                    crypto_info["confidence"] = 0.95

                # Check for rotate operations (common in crypto)
                if func_asm.count("rol") + func_asm.count("ror") > 10:
                    crypto_info["r2_analysis"]["rotation_heavy"] = True

                # Check for XOR operations (common in crypto)
                xor_count = func_asm.count("xor")
                if xor_count > 20:
                    crypto_info["r2_analysis"]["xor_heavy"] = True
                    crypto_info["r2_analysis"]["xor_count"] = xor_count

                # Check if function references crypto constants
                func_refs = r2.run_command(f"axf @ {func_addr}")
                if any(const in func_refs for const in [aes_sbox, des_sbox, sha_const]):
                    crypto_info["r2_analysis"]["references_crypto_constants"] = True
                    crypto_info["confidence"] = max(crypto_info["confidence"], 0.8)

                # Check if function name appears in crypto strings or imports
                if crypto_strings and func_name.lower() in crypto_strings.lower():
                    crypto_info["r2_analysis"]["mentioned_in_strings"] = True
                    crypto_info["confidence"] = max(crypto_info["confidence"], 0.7)

                if crypto_imports and func_name.lower() in crypto_imports.lower():
                    crypto_info["r2_analysis"]["related_to_crypto_imports"] = True
                    crypto_info["confidence"] = max(crypto_info["confidence"], 0.9)

            except Exception as e:
                self.logger.debug(f"Failed to analyze {func_name} for crypto: {e}")

            # Name-based detection with r2 enhancement
            for crypto_type, patterns in crypto_patterns.items():
                if any(pattern in name_lower for pattern in patterns):
                    crypto_info["crypto_type"] = crypto_type
                    crypto_info["patterns_matched"] = [p for p in patterns if p in name_lower]
                    base_confidence = self._calculate_crypto_confidence(func_name, patterns)

                    # Boost confidence if r2 analysis confirms crypto operations
                    if crypto_info["r2_analysis"]:
                        crypto_info["confidence"] = min(base_confidence + 0.2, 1.0)
                    else:
                        crypto_info["confidence"] = base_confidence
                    break

            # Add function if crypto indicators found
            if crypto_info["crypto_type"] or crypto_info["r2_analysis"]:
                crypto_functions.append(crypto_info)

        return crypto_functions

    def _calculate_crypto_confidence(self, func_name: str, patterns: list[str]) -> float:
        """Calculate confidence for crypto function identification."""
        name_lower = func_name.lower()
        matches = sum(1 for pattern in patterns if pattern in name_lower)

        # Higher confidence for more specific matches
        if "encrypt" in name_lower or "decrypt" in name_lower:
            return 0.9
        if "crypt" in name_lower:
            return 0.8
        if matches > 1:
            return 0.7
        return 0.6

    def _detect_anti_analysis_functions(self, r2: R2Session, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect anti-analysis and anti-debugging functions."""
        anti_analysis = []

        anti_patterns = {
            "debugger_detection": [
                "isdebuggerpresent",
                "checkremotedebugger",
                "ntqueryinformationprocess",
            ],
            "vm_detection": ["cpuid", "rdtsc", "sidt", "sgdt"],
            "analysis_evasion": ["virtualprotect", "virtualalloc", "createthread"],
            "packer_functions": ["unpack", "decrypt", "decompress", "inflate"],
        }

        # Use r2 to detect anti-analysis patterns
        try:
            # Search for common anti-debug tricks
            peb_access = r2.run_command("/x 6430:0000")  # fs:[30h] PEB access
            int3_scan = r2.run_command("/x cc")  # INT3 breakpoints
            rdtsc_scan = r2.run_command("/x 0f31")  # RDTSC instruction

            # Get all conditional jumps for anti-debug checks
            cond_jumps = r2.run_command("afl~jz|jnz|je|jne")

            # Search for obfuscation patterns
            jmp_patterns = r2.run_command("/x eb??eb")  # Jmp over jmp

        except Exception as e:
            self.logger.debug(f"Failed to scan for anti-analysis patterns: {e}")
            peb_access = int3_scan = rdtsc_scan = cond_jumps = jmp_patterns = ""

        for func in functions:
            func_name = func.get("name", "")
            name_lower = func_name.lower()
            func_addr = func.get("offset", 0)

            anti_info = {
                "function": func,
                "category": None,
                "patterns_matched": [],
                "risk_level": "low",
                "r2_analysis": {},
            }

            # Use r2 to analyze function for anti-analysis techniques
            try:
                # Get function disassembly
                func_asm = r2.run_command(f"pdf @ {func_addr}")

                # Check for PEB access (debugger detection)
                if "fs:[30h]" in func_asm or "fs:[0x30]" in func_asm or (peb_access and str(func_addr) in peb_access):
                    anti_info["r2_analysis"]["peb_access"] = True
                    anti_info["category"] = "debugger_detection"
                    anti_info["risk_level"] = "high"

                # Check for RDTSC (timing checks)
                if "rdtsc" in func_asm or (rdtsc_scan and str(func_addr) in rdtsc_scan):
                    anti_info["r2_analysis"]["rdtsc_usage"] = True
                    anti_info["category"] = "vm_detection"
                    anti_info["risk_level"] = "medium"

                # Check for INT3 breakpoint scanning
                if "int3" in func_asm or (int3_scan and str(func_addr) in int3_scan):
                    anti_info["r2_analysis"]["int3_scanning"] = True
                    anti_info["category"] = "debugger_detection"
                    anti_info["risk_level"] = "high"

                # Analyze conditional jump patterns for anti-debug logic
                if cond_jumps and func_name.lower() in cond_jumps.lower():
                    # Count conditional jumps in this function
                    cond_jump_count = func_asm.count("jz") + func_asm.count("jnz") + func_asm.count("je") + func_asm.count("jne")
                    if cond_jump_count > 5:  # High number of conditional jumps suggests complex logic
                        anti_info["r2_analysis"]["complex_conditional_logic"] = True
                        anti_info["r2_analysis"]["conditional_jump_count"] = cond_jump_count
                        anti_info["risk_level"] = "medium"

                # Check for INT3 scanning
                if "int3" in func_asm or "cc" in func_asm:
                    anti_info["r2_analysis"]["int3_detection"] = True
                    anti_info["category"] = "debugger_detection"
                    anti_info["risk_level"] = "high"

                # Check for obfuscation patterns
                if jmp_patterns and str(func_addr) in jmp_patterns:
                    anti_info["r2_analysis"]["obfuscation"] = True
                    anti_info["category"] = "analysis_evasion"

                # Get cross-references to check for suspicious API calls
                xrefs = r2.run_command(f"axtj @ {func_addr}")
                if "IsDebuggerPresent" in xrefs or "CheckRemoteDebugger" in xrefs:
                    anti_info["r2_analysis"]["debug_api_calls"] = True
                    anti_info["category"] = "debugger_detection"
                    anti_info["risk_level"] = "high"

            except Exception as e:
                self.logger.debug(f"Failed to analyze {func_name} for anti-analysis: {e}")

            # Name-based detection
            for category, patterns in anti_patterns.items():
                if any(pattern in name_lower for pattern in patterns):
                    anti_info["category"] = category
                    anti_info["patterns_matched"] = [p for p in patterns if p in name_lower]
                    anti_info["risk_level"] = self._calculate_anti_analysis_risk(func_name, category)
                    break

            # Add function if anti-analysis indicators found
            if anti_info["category"] or anti_info["r2_analysis"]:
                anti_analysis.append(anti_info)

        return anti_analysis

    def _calculate_anti_analysis_risk(self, func_name: str, category: str) -> str:
        """Calculate risk level for anti-analysis functions."""
        base_risk = "low"

        # Category-based risk assessment
        if category == "debugger_detection":
            base_risk = "high"
        elif category == "vm_detection":
            base_risk = "medium"
        elif category == "analysis_evasion":
            base_risk = "high"
        else:
            base_risk = "low"

        # Adjust risk based on function name patterns
        func_name_lower = func_name.lower()

        # High-risk function name patterns
        high_risk_patterns = ["check", "detect", "scan", "protect", "guard", "validate"]
        if any(pattern in func_name_lower for pattern in high_risk_patterns):
            if base_risk == "low":
                base_risk = "medium"
            elif base_risk == "medium":
                base_risk = "high"

        # Critical function name patterns (immediate threat)
        critical_patterns = ["isdebuggerpresent", "checkremotedebugger", "antidebug", "antivm"]
        if any(pattern in func_name_lower for pattern in critical_patterns):
            base_risk = "critical"

        return base_risk

    def _identify_license_validation_functions(self, r2: R2Session, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify potential license validation functions."""
        license_functions = []

        license_patterns = [
            "license",
            "registration",
            "activation",
            "validation",
            "authenticate",
            "verify",
            "check",
            "trial",
            "demo",
            "expire",
            "serial",
            "key",
        ]

        # Use r2 to search for license-related strings and patterns
        try:
            # Search for license-related strings
            license_strings = r2.run_command("iz~license|serial|key|trial|activation|registration")

            # Search for date/time comparisons (common in trial checks)
            time_calls = r2.run_command("ii~time|date|GetSystemTime|GetLocalTime")

            # Search for registry access (common for license storage)
            reg_calls = r2.run_command("ii~RegOpenKey|RegQueryValue|RegSetValue")

            # Search for crypto imports (license key validation)
            crypto_calls = r2.run_command("ii~CryptHashData|CryptVerifySignature|BCrypt")

        except Exception as e:
            self.logger.debug(f"Failed to search for license patterns: {e}")
            license_strings = time_calls = reg_calls = crypto_calls = ""

        for func in functions:
            func_name = func.get("name", "")
            name_lower = func_name.lower()
            func_addr = func.get("offset", 0)

            license_info = {
                "function": func,
                "patterns_matched": [],
                "confidence": 0.0,
                "license_type": None,
                "r2_analysis": {},
            }

            # Use r2 to analyze function for license validation patterns
            try:
                # Get function strings
                func_strings = r2.run_command(f"pds @ {func_addr}")

                # Check for license-related strings in function
                if any(lic in func_strings.lower() for lic in ["license", "serial", "activation", "trial"]):
                    license_info["r2_analysis"]["license_strings"] = True
                    license_info["confidence"] += 0.3

                # Get function imports
                func_imports = r2.run_command(f"afij @ {func_addr}")

                # Check for time/date functions (trial checks)
                if any(time_func in func_imports for time_func in ["time", "GetSystemTime", "GetLocalTime"]):
                    license_info["r2_analysis"]["time_checks"] = True
                    license_info["license_type"] = "trial_validation"
                    license_info["confidence"] += 0.2

                # Cross-reference with global license string analysis
                if license_strings and func_name.lower() in license_strings.lower():
                    license_info["r2_analysis"]["referenced_in_license_strings"] = True
                    license_info["confidence"] += 0.3

                # Check for registry functions (license storage)
                if any(reg_func in func_imports for reg_func in ["RegOpenKey", "RegQueryValue"]):
                    license_info["r2_analysis"]["registry_access"] = True
                    license_info["confidence"] += 0.2

                # Cross-reference with global time calls analysis
                if time_calls and func_name.lower() in time_calls.lower():
                    license_info["r2_analysis"]["uses_time_apis"] = True
                    license_info["license_type"] = "trial_validation"
                    license_info["confidence"] += 0.4

                # Cross-reference with global registry calls analysis
                if reg_calls and func_name.lower() in reg_calls.lower():
                    license_info["r2_analysis"]["uses_registry_apis"] = True
                    license_info["license_type"] = "registry_license"
                    license_info["confidence"] += 0.4

                # Check for crypto functions (key validation)
                if any(crypto_func in func_imports for crypto_func in ["Crypt", "Hash", "Verify"]):
                    license_info["r2_analysis"]["crypto_validation"] = True

                # Cross-reference with global crypto calls analysis
                if crypto_calls and func_name.lower() in crypto_calls.lower():
                    license_info["r2_analysis"]["uses_crypto_apis"] = True
                    license_info["license_type"] = "crypto_license"
                    license_info["confidence"] += 0.5

                # Analyze control flow complexity (license checks tend to be complex)
                func_blocks = r2.run_command(f"afbj @ {func_addr}")
                if func_blocks.count('"jump"') > 10:  # Many conditional branches
                    license_info["r2_analysis"]["complex_logic"] = True
                    license_info["confidence"] += 0.1

            except Exception as e:
                self.logger.debug(f"Failed to analyze {func_name} for license validation: {e}")

            # Name-based pattern matching
            matched_patterns = [pattern for pattern in license_patterns if pattern in name_lower]
            if matched_patterns:
                license_info["patterns_matched"] = matched_patterns
                base_confidence = len(matched_patterns) / len(license_patterns)
                license_info["confidence"] = min(license_info["confidence"] + base_confidence, 1.0)
                license_info["license_type"] = self._determine_license_type(func_name)

            # Add function if license indicators found
            if matched_patterns or license_info["r2_analysis"]:
                license_functions.append(license_info)

        return license_functions

    def _determine_license_type(self, func_name: str) -> str:
        """Determine the type of license validation."""
        name_lower = func_name.lower()

        if "trial" in name_lower or "demo" in name_lower:
            return "trial_validation"
        if "serial" in name_lower or "key" in name_lower:
            return "serial_key_validation"
        if "activation" in name_lower:
            return "activation_validation"
        if "registration" in name_lower:
            return "registration_validation"
        return "general_validation"

    def _check_vulnerability_signatures(self, r2: R2Session, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Check for known vulnerability signatures."""
        vulnerability_sigs = []

        vulnerable_functions = {
            "buffer_overflow": ["strcpy", "strcat", "sprintf", "gets", "scanf"],
            "format_string": ["printf", "fprintf", "snprintf"],
            "integer_overflow": ["malloc", "calloc", "realloc"],
            "use_after_free": ["free", "delete"],
            "race_condition": ["createthread", "createprocess"],
        }

        # Use r2 to analyze binary for vulnerability patterns
        try:
            # Get all dangerous function imports
            dangerous_imports = r2.run_command("ii~strcpy|strcat|sprintf|gets|scanf|printf")

            # Search for format string vulnerabilities
            format_string_pattern = r2.run_command("/x 2425")  # %% pattern

            # Get all calls to dangerous functions
            dangerous_calls = r2.run_command("axt @ sym.imp.strcpy")
            dangerous_calls += r2.run_command("axt @ sym.imp.strcat")
            dangerous_calls += r2.run_command("axt @ sym.imp.sprintf")

            # Check for stack protection
            canary_check = r2.run_command("iI~canary")
            has_canary = "canary" in canary_check.lower()

        except Exception as e:
            self.logger.debug(f"Failed to analyze vulnerability patterns: {e}")
            dangerous_imports = format_string_pattern = dangerous_calls = ""
            has_canary = False

        for func in functions:
            func_name = func.get("name", "")
            name_lower = func_name.lower()
            func_addr = func.get("offset", 0)

            vuln_info = {
                "function": func,
                "vulnerability_type": None,
                "risk_level": "low",
                "mitigation_needed": True,
                "r2_analysis": {},
            }

            # Use r2 to check for vulnerability patterns in function
            try:
                # Get function disassembly
                func_asm = r2.run_command(f"pdf @ {func_addr}")

                # Check for dangerous function calls
                if "call sym.imp.strcpy" in func_asm or "call sym.imp.strcat" in func_asm:
                    vuln_info["r2_analysis"]["unsafe_string_ops"] = True
                    vuln_info["vulnerability_type"] = "buffer_overflow"
                    vuln_info["risk_level"] = "high" if not has_canary else "medium"

                # Cross-reference with global dangerous imports analysis
                if dangerous_imports and func_name.lower() in dangerous_imports.lower():
                    vuln_info["r2_analysis"]["imports_dangerous_functions"] = True
                    vuln_info["risk_level"] = "high"

                # Check for format string vulnerabilities
                if "call sym.imp.printf" in func_asm and "%s" in func_asm:
                    # Check if format string is from user input
                    if "mov" in func_asm and "rdi" in func_asm:  # First argument
                        vuln_info["r2_analysis"]["format_string_risk"] = True
                        vuln_info["vulnerability_type"] = "format_string"

                # Cross-reference with global format string pattern analysis
                if format_string_pattern and str(func_addr) in format_string_pattern:
                    vuln_info["r2_analysis"]["contains_format_patterns"] = True
                    vuln_info["vulnerability_type"] = "format_string"
                    vuln_info["risk_level"] = "high"

                # Check for potential integer overflows
                if "imul" in func_asm and "malloc" in func_asm:
                    vuln_info["r2_analysis"]["integer_overflow_risk"] = True
                    vuln_info["vulnerability_type"] = "integer_overflow"

                # Check for use-after-free patterns
                if "call sym.imp.free" in func_asm:
                    # Check if pointer is used after free
                    lines = func_asm.split("\n")
                    for i, line in enumerate(lines):
                        if "call sym.imp.free" in line:
                            # Check next few instructions for pointer reuse
                            for j in range(i + 1, min(i + 10, len(lines))):
                                if "mov" in lines[j] and any(reg in lines[j] for reg in ["rax", "rbx", "rcx", "rdx"]):
                                    vuln_info["r2_analysis"]["potential_uaf"] = True
                                    vuln_info["vulnerability_type"] = "use_after_free"
                                    break

                # Analyze function complexity for race conditions
                if "pthread_create" in func_asm or "CreateThread" in func_asm:
                    # Check for shared resource access without locks
                    if "mutex" not in func_asm and "lock" not in func_asm:
                        vuln_info["r2_analysis"]["thread_safety_risk"] = True
                        vuln_info["vulnerability_type"] = "race_condition"

            except Exception as e:
                self.logger.debug(f"Failed to analyze {func_name} for vulnerabilities: {e}")

            # Name-based vulnerability detection
            for vuln_type, patterns in vulnerable_functions.items():
                if any(pattern in name_lower for pattern in patterns):
                    vuln_info["vulnerability_type"] = vuln_type
                    vuln_info["risk_level"] = self._calculate_vulnerability_risk(vuln_type)
                    break

            # Add function if vulnerability indicators found
            if vuln_info["vulnerability_type"] or vuln_info["r2_analysis"]:
                vulnerability_sigs.append(vuln_info)

        return vulnerability_sigs

    def _calculate_vulnerability_risk(self, vuln_type: str) -> str:
        """Calculate risk level for vulnerability types."""
        high_risk = ["buffer_overflow", "format_string", "use_after_free"]
        medium_risk = ["integer_overflow", "race_condition"]

        if vuln_type in high_risk:
            return "high"
        if vuln_type in medium_risk:
            return "medium"
        return "low"

    def _apply_custom_patterns(self, r2: R2Session, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Apply custom signature patterns for specific detection."""
        custom_matches = []

        # Custom patterns for license validation
        custom_patterns = {
            "license_check_complex": r"check.*license|license.*valid|validate.*key",
            "trial_expire": r"trial.*expire|demo.*time|time.*left",
            "registration_check": r"reg.*check|check.*reg|registered",
            "activation_routine": r"activate|activation|serial.*check",
        }

        # Use r2 to define and search for custom patterns
        try:
            # Define custom signatures in r2
            r2.run_command("zo license_sig 48 8b 05 ?? ?? ?? ?? 48 85 c0 74 ?? ff")  # Common license check pattern
            r2.run_command("zo time_check e8 ?? ?? ?? ?? 48 3b ?? 7? ??")  # Time comparison pattern
            r2.run_command("zo crypto_sig 48 89 ?? 24 ?? e8 ?? ?? ?? ?? 48 85 c0")  # Crypto validation pattern

            # Search for custom signatures
            custom_sig_matches = r2.run_command("zj")  # Get signature matches in JSON

            # Search for specific byte patterns
            xor_pattern = r2.run_command("/x 31c0")  # XOR eax, eax (common in checks)
            cmp_pattern = r2.run_command("/x 3d00000000")  # CMP eax, 0

        except Exception as e:
            self.logger.debug(f"Failed to apply custom signatures: {e}")
            custom_sig_matches = xor_pattern = cmp_pattern = ""

        for func in functions:
            func_name = func.get("name", "")
            func_addr = func.get("offset", 0)

            # Use r2 to check if function matches custom patterns
            try:
                # Get function info
                func_info = r2.run_command(f"afij @ {func_addr}")

                # Check if function contains custom signature matches
                if custom_sig_matches and str(func_addr) in custom_sig_matches:
                    pattern_match = {
                        "function": func,
                        "pattern_name": "r2_custom_signature",
                        "pattern": "Binary signature match",
                        "confidence": 0.9,
                        "r2_signature": True,
                    }
                    custom_matches.append(pattern_match)

                # Analyze function for specific patterns
                func_asm = r2.run_command(f"pdf @ {func_addr}")

                # Check for license validation patterns
                if "xor eax, eax" in func_asm and "test" in func_asm and "jz" in func_asm:
                    # Common pattern: xor eax,eax; test; jz (check and branch)
                    pattern_match = {
                        "function": func,
                        "pattern_name": "validation_check_pattern",
                        "pattern": "XOR-TEST-JZ validation pattern",
                        "confidence": 0.7,
                        "r2_analysis": {"validation_pattern": True},
                    }
                    custom_matches.append(pattern_match)

                # Check for time-based patterns
                if "call" in func_asm and "time" in func_asm and "cmp" in func_asm:
                    pattern_match = {
                        "function": func,
                        "pattern_name": "time_check_pattern",
                        "pattern": "Time comparison pattern",
                        "confidence": 0.8,
                        "r2_analysis": {"time_check": True},
                    }
                    custom_matches.append(pattern_match)

            except Exception as e:
                self.logger.debug(f"Failed to analyze {func_name} with custom patterns: {e}")

            # Regex pattern matching on function names
            for pattern_name, pattern in custom_patterns.items():
                import re

                if re.search(pattern, func_name, re.IGNORECASE):
                    # Enhance match with r2 analysis
                    confidence = 0.6
                    r2_enhanced = False

                    # Boost confidence if r2 analysis confirms pattern
                    if (
                        pattern_name == "license_check_complex"
                        and "r2_analysis" in locals()
                        and "validation_pattern" in locals().get("r2_analysis", {})
                    ):
                        confidence = 0.85
                        r2_enhanced = True
                    elif pattern_name == "trial_expire" and "r2_analysis" in locals() and "time_check" in locals().get("r2_analysis", {}):
                        confidence = 0.9
                        r2_enhanced = True

                    custom_matches.append(
                        {
                            "function": func,
                            "pattern_name": pattern_name,
                            "pattern": pattern,
                            "confidence": confidence,
                            "r2_enhanced": r2_enhanced,
                        }
                    )

        return custom_matches

    def _find_unidentified_functions(self, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Find functions that haven't been identified by signatures."""
        unidentified = []

        for func in functions:
            func_name = func.get("name", "")

            # Functions starting with these prefixes are typically unidentified
            if func_name.startswith("fcn.") or func_name.startswith("sub_") or func_name.startswith("loc_"):
                unidentified.append(func)

        return unidentified

    def _generate_signature_statistics(self, result: dict[str, Any]) -> dict[str, Any]:
        """Generate comprehensive signature statistics."""
        stats = {
            "total_functions": 0,
            "identified_functions": 0,
            "unidentified_functions": 0,
            "identification_rate": 0.0,
            "library_function_count": 0,
            "crypto_function_count": 0,
            "anti_analysis_count": 0,
            "license_validation_count": 0,
            "vulnerability_count": 0,
        }

        # Count functions
        identified_funcs = result.get("identified_functions", [])
        unidentified_funcs = result.get("unidentified_functions", [])

        stats["total_functions"] = len(identified_funcs) + len(unidentified_funcs)
        stats["identified_functions"] = len(identified_funcs)
        stats["unidentified_functions"] = len(unidentified_funcs)

        if stats["total_functions"] > 0:
            stats["identification_rate"] = stats["identified_functions"] / stats["total_functions"]

        # Count specialized functions
        library_funcs = result.get("library_functions", {})
        stats["library_function_count"] = sum(len(funcs) for funcs in library_funcs.values())

        stats["crypto_function_count"] = len(result.get("crypto_functions", []))
        stats["anti_analysis_count"] = len(result.get("anti_analysis_functions", []))
        stats["license_validation_count"] = len(result.get("license_validation_functions", []))
        stats["vulnerability_count"] = len(result.get("vulnerability_signatures", []))

        return stats

    def _analyze_identification_confidence(self, result: dict[str, Any]) -> dict[str, Any]:
        """Analyze confidence levels of function identification."""
        confidence_analysis = {
            "high_confidence": [],
            "medium_confidence": [],
            "low_confidence": [],
            "average_confidence": 0.0,
            "confidence_distribution": {},
        }

        identified_funcs = result.get("identified_functions", [])

        if not identified_funcs:
            return confidence_analysis

        confidences = []
        for func in identified_funcs:
            confidence = func.get("confidence", 0.0)
            confidences.append(confidence)

            if confidence >= 0.8:
                confidence_analysis["high_confidence"].append(func)
            elif confidence >= 0.5:
                confidence_analysis["medium_confidence"].append(func)
            else:
                confidence_analysis["low_confidence"].append(func)

        confidence_analysis["average_confidence"] = sum(confidences) / len(confidences)

        # Distribution
        confidence_analysis["confidence_distribution"] = {
            "high (>= 0.8)": len(confidence_analysis["high_confidence"]),
            "medium (0.5-0.8)": len(confidence_analysis["medium_confidence"]),
            "low (< 0.5)": len(confidence_analysis["low_confidence"]),
        }

        return confidence_analysis


def analyze_binary_signatures(binary_path: str, radare2_path: str | None = None) -> dict[str, Any]:
    """Perform comprehensive signature analysis on a binary.

    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable

    Returns:
        Complete signature analysis results

    """
    analyzer = R2SignatureAnalyzer(binary_path, radare2_path)
    return analyzer.analyze_signatures()


__all__ = ["R2SignatureAnalyzer", "analyze_binary_signatures"]
