"""Radare2 signature analysis module for pattern matching and function identification."""

import json as json_module
import logging
import re
from typing import Any

from intellicrack.utils.logger import logger

from ...utils.tools.radare2_utils import R2Exception, R2Session, R2SessionPoolAdapter, r2_session


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

    def __init__(self, binary_path: str, radare2_path: str | None = None) -> None:
        """Initialize signature analyzer.

        Args:
            binary_path: Path to binary file
            radare2_path: Optional path to radare2 executable

        """
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)
        self.signature_cache: dict[str, Any] = {}
        self.custom_signatures: dict[str, Any] = {}

    def analyze_signatures(self) -> dict[str, Any]:
        """Perform comprehensive signature analysis on the binary.

        Returns:
            Complete signature analysis results

        """
        result: dict[str, Any] = {
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
            self.logger.exception("Signature analysis failed: %s", e)

        return result

    def _apply_flirt_signatures(self, r2: R2Session | R2SessionPoolAdapter) -> dict[str, Any]:
        """Apply FLIRT signatures to identify library functions."""
        flirt_result: dict[str, Any] = {
            "signatures_applied": 0,
            "functions_identified": 0,
            "signature_files_used": [],
            "matches": [],
        }

        try:
            r2._execute_command("zf")

            sig_info = r2._execute_command("zi")
            if sig_info and isinstance(sig_info, str):
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
                    if func_addr := func.get("offset", 0):
                        try:
                            if func_info := r2.get_function_info(func_addr):
                                identified_by_flirt.append(
                                    {
                                        "name": func_name,
                                        "address": hex(func_addr),
                                        "size": func.get("size", 0),
                                        "signature_type": "flirt",
                                    },
                                )
                        except R2Exception as e:
                            logger.error("R2Exception in radare2_signatures: %s", e)
                            continue

            flirt_result["matches"] = identified_by_flirt
            flirt_result["functions_identified"] = len(identified_by_flirt)

        except R2Exception as e:
            flirt_result["error"] = str(e)
            self.logger.debug("FLIRT signature application failed: %s", e)

        return flirt_result

    def _apply_zignatures(self, r2: R2Session | R2SessionPoolAdapter) -> dict[str, Any]:
        """Apply Zignatures for function identification."""
        zignature_result: dict[str, Any] = {
            "signatures_loaded": 0,
            "matches": [],
            "match_confidence": {},
        }

        try:
            zignature_info = r2._execute_command("z")

            if not zignature_info or (isinstance(zignature_info, str) and "no signatures" in zignature_info.lower()):
                self.logger.warning("No zignatures available in radare2 session")
                return {"signatures": [], "signature_count": 0}

            zignature_matches = r2._execute_command("zs")
            if zignature_matches and isinstance(zignature_matches, str):
                matches = [line.strip() for line in zignature_matches.split("\n") if line.strip() and "match" in line.lower()]
                zignature_result["matches"] = matches

            zignature_stats = r2._execute_command("zi")
            if zignature_stats and isinstance(zignature_stats, str):
                zignature_result["statistics"] = zignature_stats.strip()

        except R2Exception as e:
            zignature_result["error"] = str(e)
            self.logger.debug("Zignature analysis failed: %s", e)

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
                },
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
        return "disassembly" if func_name.startswith("sub_") else "signature_database"

    def _analyze_library_functions(self, r2: R2Session | R2SessionPoolAdapter, functions: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze and categorize library functions."""
        library_analysis: dict[str, Any] = {
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

        try:
            imports_result = r2._execute_command("ii")
            import_libs_result = r2._execute_command("il")

            imports = imports_result if isinstance(imports_result, str) else str(imports_result)
            import_libs = import_libs_result if isinstance(import_libs_result, str) else str(import_libs_result)

            r2_enhanced: dict[str, Any] = library_analysis["r2_enhanced_info"]
            r2_enhanced["imports"] = imports
            r2_enhanced["libraries"] = import_libs

            plt_result = r2._execute_command("afl~plt")
            plt_entries = plt_result if isinstance(plt_result, str) else str(plt_result)
            r2_enhanced["plt_entries"] = plt_entries

        except Exception as e:
            self.logger.debug("Failed to get r2 library info: %s", e)

        c_runtime_list: list[dict[str, Any]] = library_analysis["c_runtime"]
        windows_api_list: list[dict[str, Any]] = library_analysis["windows_api"]
        posix_api_list: list[dict[str, Any]] = library_analysis["posix_api"]
        crypto_list: list[dict[str, Any]] = library_analysis["crypto_libraries"]
        network_list: list[dict[str, Any]] = library_analysis["network_libraries"]
        ui_list: list[dict[str, Any]] = library_analysis["ui_libraries"]
        compression_list: list[dict[str, Any]] = library_analysis["compression_libraries"]
        database_list: list[dict[str, Any]] = library_analysis["database_libraries"]

        for func in functions:
            func_name = func.get("name", "")
            name_lower = func_name.lower()
            func_addr = func.get("offset", 0)

            try:
                func_info_result = r2._execute_command(f"afi @ {func_addr}")
                func_info = func_info_result if isinstance(func_info_result, str) else str(func_info_result)

                is_import = "import" in func_info or func_name.startswith("sym.imp.")

                func_size_result = r2._execute_command(f"afi~size @ {func_addr}")
                func_size = func_size_result if isinstance(func_size_result, str) else str(func_size_result)

                func["r2_import"] = is_import
                func["r2_size"] = func_size
                func["r2_info"] = func_info

            except Exception as e:
                self.logger.debug("Failed to get r2 info for %s: %s", func_name, e)

            if any(crt in name_lower for crt in ["msvcrt", "ucrt", "libc", "malloc", "free", "printf"]):
                c_runtime_list.append(func)

            elif any(win_api in name_lower for win_api in ["kernel32", "user32", "advapi32", "ntdll"]):
                windows_api_list.append(func)

            elif any(posix in name_lower for posix in ["pthread", "dlopen", "mmap", "fork"]):
                posix_api_list.append(func)

            elif any(crypto in name_lower for crypto in ["openssl", "crypto", "bcrypt", "crypt32"]):
                crypto_list.append(func)

            elif any(net in name_lower for net in ["ws2_32", "wininet", "winhttp", "socket"]):
                network_list.append(func)

            elif any(ui in name_lower for ui in ["gdi32", "comctl32", "shell32", "ole32"]):
                ui_list.append(func)

            elif any(comp in name_lower for comp in ["zlib", "bzip2", "lzma", "deflate"]):
                compression_list.append(func)

            elif any(db in name_lower for db in ["sqlite", "odbc", "oledb"]):
                database_list.append(func)

        return library_analysis

    def _detect_compiler_artifacts(self, r2: R2Session | R2SessionPoolAdapter, functions: list[dict[str, Any]]) -> dict[str, Any]:
        """Detect compiler-specific artifacts and runtime functions."""
        compiler_artifacts: dict[str, Any] = {
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

        build_info: dict[str, Any] = compiler_artifacts["build_info"]
        compiler_info: dict[str, Any] = compiler_artifacts["compiler_info"]
        msvc_list: list[dict[str, Any]] = compiler_artifacts["msvc_artifacts"]
        gcc_list: list[dict[str, Any]] = compiler_artifacts["gcc_artifacts"]
        exception_list: list[dict[str, Any]] = compiler_artifacts["exception_handling"]
        stack_list: list[dict[str, Any]] = compiler_artifacts["stack_guards"]
        runtime_list: list[dict[str, Any]] = compiler_artifacts["runtime_checks"]

        binary_info = ""
        entry_disasm = ""

        try:
            binary_info_result = r2._execute_command("iI")
            binary_info = binary_info_result if isinstance(binary_info_result, str) else str(binary_info_result)
            build_info["binary_info"] = binary_info

            compiler_strings_result = r2._execute_command("iz~GCC|MSVC|clang|Borland")
            compiler_strings = compiler_strings_result if isinstance(compiler_strings_result, str) else str(compiler_strings_result)
            compiler_info["strings"] = compiler_strings

            entry_point_result = r2._execute_command("ie")
            entry_point = entry_point_result if isinstance(entry_point_result, str) else str(entry_point_result)
            entry_disasm_result = r2._execute_command("pd 50 @ entry0")
            entry_disasm = entry_disasm_result if isinstance(entry_disasm_result, str) else str(entry_disasm_result)

            compiler_artifacts["entry_analysis"] = {
                "entry_point_info": entry_point,
                "entry_disasm": entry_disasm,
            }

            if "security_init_cookie" in entry_disasm:
                compiler_info["detected"] = "MSVC"
            elif "__libc_start_main" in entry_disasm:
                compiler_info["detected"] = "GCC/Linux"
            elif "_start" in entry_disasm and "note.ABI-tag" in binary_info:
                compiler_info["detected"] = "GCC"

            sections_result = r2._execute_command("iS")
            sections = sections_result if isinstance(sections_result, str) else str(sections_result)
            if ".gcc_except_table" in sections:
                compiler_info["gcc_exceptions"] = True
            if ".msvcjmc" in sections:
                compiler_info["msvc_jmc"] = True

        except Exception as e:
            self.logger.debug("Failed to get compiler info from r2: %s", e)

        for func in functions:
            func_name = func.get("name", "")
            name_lower = func_name.lower()
            func_addr = func.get("offset", 0)

            try:
                func_asm_result = r2._execute_command(f"pdf @ {func_addr}")
                func_asm = func_asm_result if isinstance(func_asm_result, str) else str(func_asm_result)

                if "fs:0x28" in func_asm or "__stack_chk_fail" in func_asm:
                    func["has_stack_protection"] = True

                if "__SEH_prolog" in func_asm or "fs:0" in func_asm:
                    func["has_seh"] = True

            except Exception as e:
                self.logger.debug("Failed to analyze %s: %s", func_name, e)

            if any(msvc in name_lower for msvc in ["__security_", "__report_", "_crt", "_chk"]):
                msvc_list.append(func)

            elif any(gcc in name_lower for gcc in ["__stack_chk", "__gxx_", "_gnu_"]):
                gcc_list.append(func)

            elif any(eh in name_lower for eh in ["__eh_", "_except_", "__try", "__catch"]):
                exception_list.append(func)

            elif any(stack in name_lower for stack in ["__stack_chk", "__guard", "_security_"]):
                stack_list.append(func)

            elif any(check in name_lower for check in ["__chk", "_check_", "__valid"]):
                runtime_list.append(func)

        return compiler_artifacts

    def _identify_crypto_functions(self, r2: R2Session | R2SessionPoolAdapter, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify cryptographic functions and algorithms."""
        crypto_functions: list[dict[str, Any]] = []

        crypto_patterns: dict[str, list[str]] = {
            "aes": ["aes", "rijndael"],
            "des": ["des", "3des", "triple"],
            "rsa": ["rsa", "pubkey"],
            "hash": ["sha", "md5", "md4", "hash"],
            "random": ["rand", "random", "prng"],
            "crypto_api": ["crypt", "cipher", "encrypt", "decrypt"],
        }

        aes_sbox = ""
        des_sbox = ""
        sha_const = ""
        crypto_strings = ""
        crypto_imports = ""

        try:
            aes_sbox_result = r2._execute_command("/x 637c777bf26b6fc5")
            aes_sbox = aes_sbox_result if isinstance(aes_sbox_result, str) else str(aes_sbox_result)
            des_sbox_result = r2._execute_command("/x 14041100001010400")
            des_sbox = des_sbox_result if isinstance(des_sbox_result, str) else str(des_sbox_result)
            sha_const_result = r2._execute_command("/x 67452301efcdab89")
            sha_const = sha_const_result if isinstance(sha_const_result, str) else str(sha_const_result)

            crypto_strings_result = r2._execute_command("iz~crypt|cipher|aes|des|rsa|sha|md5")
            crypto_strings = crypto_strings_result if isinstance(crypto_strings_result, str) else str(crypto_strings_result)

            crypto_imports_result = r2._execute_command("ii~crypt|ssl|tls")
            crypto_imports = crypto_imports_result if isinstance(crypto_imports_result, str) else str(crypto_imports_result)

        except Exception as e:
            self.logger.debug("Failed to search for crypto patterns: %s", e)

        for func in functions:
            func_name = func.get("name", "")
            name_lower = func_name.lower()
            func_addr = func.get("offset", 0)

            r2_analysis: dict[str, Any] = {}
            crypto_type: str | None = None
            confidence: float = 0.0
            patterns_matched: list[str] = []

            try:
                func_asm_result = r2._execute_command(f"pdr @ {func_addr}")
                func_asm = func_asm_result if isinstance(func_asm_result, str) else str(func_asm_result)

                if "aesenc" in func_asm or "aesdec" in func_asm:
                    r2_analysis["aes_instructions"] = True
                    crypto_type = "aes"
                    confidence = 0.95

                if func_asm.count("rol") + func_asm.count("ror") > 10:
                    r2_analysis["rotation_heavy"] = True

                xor_count = func_asm.count("xor")
                if xor_count > 20:
                    r2_analysis["xor_heavy"] = True
                    r2_analysis["xor_count"] = xor_count

                func_refs_result = r2._execute_command(f"axf @ {func_addr}")
                func_refs = func_refs_result if isinstance(func_refs_result, str) else str(func_refs_result)
                if any(const in func_refs for const in [aes_sbox, des_sbox, sha_const] if const):
                    r2_analysis["references_crypto_constants"] = True
                    confidence = max(confidence, 0.8)

                if crypto_strings and func_name.lower() in crypto_strings.lower():
                    r2_analysis["mentioned_in_strings"] = True
                    confidence = max(confidence, 0.7)

                if crypto_imports and func_name.lower() in crypto_imports.lower():
                    r2_analysis["related_to_crypto_imports"] = True
                    confidence = max(confidence, 0.9)

            except Exception as e:
                self.logger.debug("Failed to analyze %s for crypto: %s", func_name, e)

            for ctype, patterns in crypto_patterns.items():
                if any(pattern in name_lower for pattern in patterns):
                    crypto_type = ctype
                    patterns_matched = [p for p in patterns if p in name_lower]
                    base_confidence = self._calculate_crypto_confidence(func_name, patterns)

                    if r2_analysis:
                        confidence = min(base_confidence + 0.2, 1.0)
                    else:
                        confidence = base_confidence
                    break

            if crypto_type or r2_analysis:
                crypto_info: dict[str, Any] = {
                    "function": func,
                    "crypto_type": crypto_type,
                    "patterns_matched": patterns_matched,
                    "confidence": confidence,
                    "r2_analysis": r2_analysis,
                }
                crypto_functions.append(crypto_info)

        return crypto_functions

    def _calculate_crypto_confidence(self, func_name: str, patterns: list[str]) -> float:
        """Calculate confidence for crypto function identification."""
        name_lower = func_name.lower()
        matches = sum(pattern in name_lower for pattern in patterns)

        # Higher confidence for more specific matches
        if "encrypt" in name_lower or "decrypt" in name_lower:
            return 0.9
        if "crypt" in name_lower:
            return 0.8
        return 0.7 if matches > 1 else 0.6

    def _detect_anti_analysis_functions(
        self, r2: R2Session | R2SessionPoolAdapter, functions: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Detect anti-analysis and anti-debugging functions."""
        anti_analysis: list[dict[str, Any]] = []

        anti_patterns: dict[str, list[str]] = {
            "debugger_detection": [
                "isdebuggerpresent",
                "checkremotedebugger",
                "ntqueryinformationprocess",
            ],
            "vm_detection": ["cpuid", "rdtsc", "sidt", "sgdt"],
            "analysis_evasion": ["virtualprotect", "virtualalloc", "createthread"],
            "packer_functions": ["unpack", "decrypt", "decompress", "inflate"],
        }

        peb_access = ""
        int3_scan = ""
        rdtsc_scan = ""
        cond_jumps = ""
        jmp_patterns = ""

        try:
            peb_result = r2._execute_command("/x 6430:0000")
            peb_access = peb_result if isinstance(peb_result, str) else str(peb_result)
            int3_result = r2._execute_command("/x cc")
            int3_scan = int3_result if isinstance(int3_result, str) else str(int3_result)
            rdtsc_result = r2._execute_command("/x 0f31")
            rdtsc_scan = rdtsc_result if isinstance(rdtsc_result, str) else str(rdtsc_result)

            cond_result = r2._execute_command("afl~jz|jnz|je|jne")
            cond_jumps = cond_result if isinstance(cond_result, str) else str(cond_result)

            jmp_result = r2._execute_command("/x eb??eb")
            jmp_patterns = jmp_result if isinstance(jmp_result, str) else str(jmp_result)

        except Exception as e:
            self.logger.debug("Failed to scan for anti-analysis patterns: %s", e)

        for func in functions:
            func_name = func.get("name", "")
            name_lower = func_name.lower()
            func_addr = func.get("offset", 0)

            r2_analysis: dict[str, Any] = {}
            category: str | None = None
            risk_level = "low"
            patterns_matched: list[str] = []

            try:
                func_asm_result = r2._execute_command(f"pdf @ {func_addr}")
                func_asm = func_asm_result if isinstance(func_asm_result, str) else str(func_asm_result)

                if "fs:[30h]" in func_asm or "fs:[0x30]" in func_asm or (peb_access and str(func_addr) in peb_access):
                    r2_analysis["peb_access"] = True
                    category = "debugger_detection"
                    risk_level = "high"

                if "rdtsc" in func_asm or (rdtsc_scan and str(func_addr) in rdtsc_scan):
                    r2_analysis["rdtsc_usage"] = True
                    category = "vm_detection"
                    risk_level = "medium"

                if "int3" in func_asm or (int3_scan and str(func_addr) in int3_scan):
                    r2_analysis["int3_scanning"] = True
                    category = "debugger_detection"
                    risk_level = "high"

                if cond_jumps and func_name.lower() in cond_jumps.lower():
                    cond_jump_count = func_asm.count("jz") + func_asm.count("jnz") + func_asm.count("je") + func_asm.count("jne")
                    if cond_jump_count > 5:
                        r2_analysis["complex_conditional_logic"] = True
                        r2_analysis["conditional_jump_count"] = cond_jump_count
                        risk_level = "medium"

                if "int3" in func_asm or "cc" in func_asm:
                    r2_analysis["int3_detection"] = True
                    category = "debugger_detection"
                    risk_level = "high"

                if jmp_patterns and str(func_addr) in jmp_patterns:
                    r2_analysis["obfuscation"] = True
                    category = "analysis_evasion"

                xrefs_result = r2._execute_command(f"axtj @ {func_addr}")
                xrefs = xrefs_result if isinstance(xrefs_result, str) else str(xrefs_result)
                if "IsDebuggerPresent" in xrefs or "CheckRemoteDebugger" in xrefs:
                    r2_analysis["debug_api_calls"] = True
                    category = "debugger_detection"
                    risk_level = "high"

            except Exception as e:
                self.logger.debug("Failed to analyze %s for anti-analysis: %s", func_name, e)

            for cat, patterns in anti_patterns.items():
                if any(pattern in name_lower for pattern in patterns):
                    category = cat
                    patterns_matched = [p for p in patterns if p in name_lower]
                    risk_level = self._calculate_anti_analysis_risk(func_name, cat)
                    break

            if category or r2_analysis:
                anti_info: dict[str, Any] = {
                    "function": func,
                    "category": category,
                    "patterns_matched": patterns_matched,
                    "risk_level": risk_level,
                    "r2_analysis": r2_analysis,
                }
                anti_analysis.append(anti_info)

        return anti_analysis

    def _calculate_anti_analysis_risk(self, func_name: str, category: str) -> str:
        """Calculate risk level for anti-analysis functions."""
        base_risk = "low"

        # Category-based risk assessment
        if category in ["debugger_detection", "analysis_evasion"]:
            base_risk = "high"
        elif category == "vm_detection":
            base_risk = "medium"
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

    def _identify_license_validation_functions(
        self, r2: R2Session | R2SessionPoolAdapter, functions: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Identify potential license validation functions."""
        license_functions: list[dict[str, Any]] = []

        license_patterns: list[str] = [
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

        license_strings = ""
        time_calls = ""
        reg_calls = ""
        crypto_calls = ""

        try:
            lic_result = r2._execute_command("iz~license|serial|key|trial|activation|registration")
            license_strings = lic_result if isinstance(lic_result, str) else str(lic_result)

            time_result = r2._execute_command("ii~time|date|GetSystemTime|GetLocalTime")
            time_calls = time_result if isinstance(time_result, str) else str(time_result)

            reg_result = r2._execute_command("ii~RegOpenKey|RegQueryValue|RegSetValue")
            reg_calls = reg_result if isinstance(reg_result, str) else str(reg_result)

            crypto_result = r2._execute_command("ii~CryptHashData|CryptVerifySignature|BCrypt")
            crypto_calls = crypto_result if isinstance(crypto_result, str) else str(crypto_result)

        except Exception as e:
            self.logger.debug("Failed to search for license patterns: %s", e)

        for func in functions:
            func_name = func.get("name", "")
            name_lower = func_name.lower()
            func_addr = func.get("offset", 0)

            r2_analysis: dict[str, Any] = {}
            confidence: float = 0.0
            license_type: str | None = None
            patterns_matched: list[str] = []

            try:
                func_strings_result = r2._execute_command(f"pds @ {func_addr}")
                func_strings = func_strings_result if isinstance(func_strings_result, str) else str(func_strings_result)

                if any(lic in func_strings.lower() for lic in ["license", "serial", "activation", "trial"]):
                    r2_analysis["license_strings"] = True
                    confidence += 0.3

                func_imports_result = r2._execute_command(f"afij @ {func_addr}")
                func_imports = func_imports_result if isinstance(func_imports_result, str) else str(func_imports_result)

                if any(time_func in func_imports for time_func in ["time", "GetSystemTime", "GetLocalTime"]):
                    r2_analysis["time_checks"] = True
                    license_type = "trial_validation"
                    confidence += 0.2

                if license_strings and func_name.lower() in license_strings.lower():
                    r2_analysis["referenced_in_license_strings"] = True
                    confidence += 0.3

                if any(reg_func in func_imports for reg_func in ["RegOpenKey", "RegQueryValue"]):
                    r2_analysis["registry_access"] = True
                    confidence += 0.2

                if time_calls and func_name.lower() in time_calls.lower():
                    r2_analysis["uses_time_apis"] = True
                    license_type = "trial_validation"
                    confidence += 0.4

                if reg_calls and func_name.lower() in reg_calls.lower():
                    r2_analysis["uses_registry_apis"] = True
                    license_type = "registry_license"
                    confidence += 0.4

                if any(crypto_func in func_imports for crypto_func in ["Crypt", "Hash", "Verify"]):
                    r2_analysis["crypto_validation"] = True

                if crypto_calls and func_name.lower() in crypto_calls.lower():
                    r2_analysis["uses_crypto_apis"] = True
                    license_type = "crypto_license"
                    confidence += 0.5

                func_blocks_result = r2._execute_command(f"afbj @ {func_addr}")
                func_blocks = func_blocks_result if isinstance(func_blocks_result, str) else str(func_blocks_result)
                if func_blocks.count('"jump"') > 10:
                    r2_analysis["complex_logic"] = True
                    confidence += 0.1

            except Exception as e:
                self.logger.debug("Failed to analyze %s for license validation: %s", func_name, e)

            patterns_matched = [pattern for pattern in license_patterns if pattern in name_lower]
            if patterns_matched:
                base_confidence = len(patterns_matched) / len(license_patterns)
                confidence = min(confidence + base_confidence, 1.0)
                license_type = self._determine_license_type(func_name)

            if patterns_matched or r2_analysis:
                license_info: dict[str, Any] = {
                    "function": func,
                    "patterns_matched": patterns_matched,
                    "confidence": confidence,
                    "license_type": license_type,
                    "r2_analysis": r2_analysis,
                }
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

    def _check_vulnerability_signatures(
        self, r2: R2Session | R2SessionPoolAdapter, functions: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Check for known vulnerability signatures."""
        vulnerability_sigs: list[dict[str, Any]] = []

        vulnerable_functions: dict[str, list[str]] = {
            "buffer_overflow": ["strcpy", "strcat", "sprintf", "gets", "scanf"],
            "format_string": ["printf", "fprintf", "snprintf"],
            "integer_overflow": ["malloc", "calloc", "realloc"],
            "use_after_free": ["free", "delete"],
            "race_condition": ["createthread", "createprocess"],
        }

        dangerous_imports = ""
        format_string_pattern = ""
        dangerous_calls = ""
        has_canary = False

        try:
            dangerous_result = r2._execute_command("ii~strcpy|strcat|sprintf|gets|scanf|printf")
            dangerous_imports = dangerous_result if isinstance(dangerous_result, str) else str(dangerous_result)

            format_result = r2._execute_command("/x 2425")
            format_string_pattern = format_result if isinstance(format_result, str) else str(format_result)

            calls1 = r2._execute_command("axt @ sym.imp.strcpy")
            calls1_str = calls1 if isinstance(calls1, str) else str(calls1)
            calls2 = r2._execute_command("axt @ sym.imp.strcat")
            calls2_str = calls2 if isinstance(calls2, str) else str(calls2)
            calls3 = r2._execute_command("axt @ sym.imp.sprintf")
            calls3_str = calls3 if isinstance(calls3, str) else str(calls3)
            dangerous_calls = calls1_str + calls2_str + calls3_str

            canary_result = r2._execute_command("iI~canary")
            canary_check = canary_result if isinstance(canary_result, str) else str(canary_result)
            has_canary = "canary" in canary_check.lower()

        except Exception as e:
            self.logger.debug("Failed to analyze vulnerability patterns: %s", e)

        for func in functions:
            func_name = func.get("name", "")
            name_lower = func_name.lower()
            func_addr = func.get("offset", 0)

            r2_analysis: dict[str, Any] = {}
            vulnerability_type: str | None = None
            risk_level = "low"

            try:
                func_asm_result = r2._execute_command(f"pdf @ {func_addr}")
                func_asm = func_asm_result if isinstance(func_asm_result, str) else str(func_asm_result)

                if "call sym.imp.strcpy" in func_asm or "call sym.imp.strcat" in func_asm:
                    r2_analysis["unsafe_string_ops"] = True
                    vulnerability_type = "buffer_overflow"
                    risk_level = "medium" if has_canary else "high"

                if dangerous_imports and func_name.lower() in dangerous_imports.lower():
                    r2_analysis["imports_dangerous_functions"] = True
                    risk_level = "high"

                if dangerous_calls:
                    func_addr_hex = hex(func_addr) if isinstance(func_addr, int) else str(func_addr)
                    if func_addr_hex in dangerous_calls or str(func_addr) in dangerous_calls:
                        if call_sites := [
                            line.strip() for line in dangerous_calls.split("\n") if func_addr_hex in line or str(func_addr) in line
                        ]:
                            r2_analysis["dangerous_call_sites"] = call_sites
                            r2_analysis["calls_unsafe_functions"] = True
                            if risk_level == "low":
                                risk_level = "medium"

                if "call sym.imp.printf" in func_asm and "%s" in func_asm and ("mov" in func_asm and "rdi" in func_asm):
                    r2_analysis["format_string_risk"] = True
                    vulnerability_type = "format_string"

                if format_string_pattern and str(func_addr) in format_string_pattern:
                    r2_analysis["contains_format_patterns"] = True
                    vulnerability_type = "format_string"
                    risk_level = "high"

                if "imul" in func_asm and "malloc" in func_asm:
                    r2_analysis["integer_overflow_risk"] = True
                    vulnerability_type = "integer_overflow"

                if "call sym.imp.free" in func_asm:
                    lines = func_asm.split("\n")
                    for i, line in enumerate(lines):
                        if "call sym.imp.free" in line:
                            for j in range(i + 1, min(i + 10, len(lines))):
                                if "mov" in lines[j] and any(reg in lines[j] for reg in ["rax", "rbx", "rcx", "rdx"]):
                                    r2_analysis["potential_uaf"] = True
                                    vulnerability_type = "use_after_free"
                                    break

                if ("pthread_create" in func_asm or "CreateThread" in func_asm) and ("mutex" not in func_asm and "lock" not in func_asm):
                    r2_analysis["thread_safety_risk"] = True
                    vulnerability_type = "race_condition"

            except Exception as e:
                self.logger.debug("Failed to analyze %s for vulnerabilities: %s", func_name, e)

            for vuln_type, patterns in vulnerable_functions.items():
                if any(pattern in name_lower for pattern in patterns):
                    vulnerability_type = vuln_type
                    risk_level = self._calculate_vulnerability_risk(vuln_type)
                    break

            if vulnerability_type or r2_analysis:
                vuln_info: dict[str, Any] = {
                    "function": func,
                    "vulnerability_type": vulnerability_type,
                    "risk_level": risk_level,
                    "mitigation_needed": True,
                    "r2_analysis": r2_analysis,
                }
                vulnerability_sigs.append(vuln_info)

        return vulnerability_sigs

    def _calculate_vulnerability_risk(self, vuln_type: str) -> str:
        """Calculate risk level for vulnerability types."""
        high_risk = ["buffer_overflow", "format_string", "use_after_free"]
        if vuln_type in high_risk:
            return "high"
        medium_risk = ["integer_overflow", "race_condition"]

        return "medium" if vuln_type in medium_risk else "low"

    def _apply_custom_patterns(self, r2: R2Session | R2SessionPoolAdapter, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Apply custom signature patterns for specific detection."""
        custom_matches: list[dict[str, Any]] = []

        custom_patterns: dict[str, str] = {
            "license_check_complex": r"check.*license|license.*valid|validate.*key",
            "trial_expire": r"trial.*expire|demo.*time|time.*left",
            "registration_check": r"reg.*check|check.*reg|registered",
            "activation_routine": r"activate|activation|serial.*check",
        }

        custom_sig_matches = ""
        xor_pattern = ""
        cmp_pattern = ""

        try:
            r2._execute_command("zo license_sig 48 8b 05 ?? ?? ?? ?? 48 85 c0 74 ?? ff")
            r2._execute_command("zo time_check e8 ?? ?? ?? ?? 48 3b ?? 7? ??")
            r2._execute_command("zo crypto_sig 48 89 ?? 24 ?? e8 ?? ?? ?? ?? 48 85 c0")

            sig_result = r2._execute_command("zj")
            custom_sig_matches = sig_result if isinstance(sig_result, str) else str(sig_result)

            xor_result = r2._execute_command("/x 31c0")
            xor_pattern = xor_result if isinstance(xor_result, str) else str(xor_result)
            cmp_result = r2._execute_command("/x 3d00000000")
            cmp_pattern = cmp_result if isinstance(cmp_result, str) else str(cmp_result)

        except Exception as e:
            self.logger.debug("Failed to apply custom signatures: %s", e)

        for func in functions:
            func_name = func.get("name", "")
            func_addr = func.get("offset", 0)

            try:
                func_info_result = r2._execute_command(f"afij @ {func_addr}")
                func_info = func_info_result if isinstance(func_info_result, str) else str(func_info_result)
                func_size = 0
                func_complexity = 0

                try:
                    func_info_data = json_module.loads(func_info) if func_info.strip() else []
                    if func_info_data and isinstance(func_info_data, list) and len(func_info_data) > 0:
                        fi = func_info_data[0]
                        if isinstance(fi, dict):
                            func_size = int(fi.get("size", 0))
                            func_complexity = int(fi.get("cc", 0))
                except (ValueError, KeyError, IndexError):
                    pass

                size_weight = min(1.0, func_size / 500) if func_size > 0 else 0.5
                complexity_weight = min(1.0, func_complexity / 10) if func_complexity > 0 else 0.5
                confidence_modifier = (size_weight + complexity_weight) / 2

                if custom_sig_matches and str(func_addr) in custom_sig_matches:
                    weighted_confidence = min(0.98, 0.9 * (0.8 + 0.4 * confidence_modifier))
                    pattern_match: dict[str, Any] = {
                        "function": func,
                        "pattern_name": "r2_custom_signature",
                        "pattern": "Binary signature match",
                        "confidence": weighted_confidence,
                        "r2_signature": True,
                        "func_size": func_size,
                        "func_complexity": func_complexity,
                    }
                    custom_matches.append(pattern_match)

                func_addr_hex = hex(func_addr) if isinstance(func_addr, int) else str(func_addr)
                xor_in_func = False
                cmp_in_func = False

                if xor_pattern and (func_addr_hex in xor_pattern or str(func_addr) in xor_pattern):
                    xor_in_func = True
                if cmp_pattern and (func_addr_hex in cmp_pattern or str(func_addr) in cmp_pattern):
                    cmp_in_func = True

                if xor_in_func and cmp_in_func:
                    weighted_confidence = min(0.95, 0.85 * (0.8 + 0.4 * confidence_modifier))
                    pattern_match = {
                        "function": func,
                        "pattern_name": "xor_cmp_license_check",
                        "pattern": "XOR+CMP validation pattern (license check signature)",
                        "confidence": weighted_confidence,
                        "r2_analysis": {
                            "xor_pattern_match": True,
                            "cmp_pattern_match": True,
                            "likely_license_validation": True,
                            "func_size": func_size,
                            "func_complexity": func_complexity,
                        },
                    }
                    custom_matches.append(pattern_match)
                elif xor_in_func or cmp_in_func:
                    weighted_confidence = min(0.80, 0.65 * (0.8 + 0.4 * confidence_modifier))
                    pattern_match = {
                        "function": func,
                        "pattern_name": "partial_license_check",
                        "pattern": "Partial validation pattern detected",
                        "confidence": weighted_confidence,
                        "r2_analysis": {
                            "xor_pattern_match": xor_in_func,
                            "cmp_pattern_match": cmp_in_func,
                            "func_size": func_size,
                            "func_complexity": func_complexity,
                        },
                    }
                    custom_matches.append(pattern_match)

                func_asm_result = r2._execute_command(f"pdf @ {func_addr}")
                func_asm = func_asm_result if isinstance(func_asm_result, str) else str(func_asm_result)

                if "xor eax, eax" in func_asm and "test" in func_asm and "jz" in func_asm:
                    weighted_confidence = min(0.85, 0.7 * (0.8 + 0.4 * confidence_modifier))
                    pattern_match = {
                        "function": func,
                        "pattern_name": "validation_check_pattern",
                        "pattern": "XOR-TEST-JZ validation pattern",
                        "confidence": weighted_confidence,
                        "r2_analysis": {"validation_pattern": True, "func_size": func_size, "func_complexity": func_complexity},
                    }
                    custom_matches.append(pattern_match)

                if "call" in func_asm and "time" in func_asm and "cmp" in func_asm:
                    weighted_confidence = min(0.90, 0.8 * (0.8 + 0.4 * confidence_modifier))
                    pattern_match = {
                        "function": func,
                        "pattern_name": "time_check_pattern",
                        "pattern": "Time comparison pattern",
                        "confidence": weighted_confidence,
                        "r2_analysis": {"time_check": True, "func_size": func_size, "func_complexity": func_complexity},
                    }
                    custom_matches.append(pattern_match)

            except Exception as e:
                self.logger.debug("Failed to analyze %s with custom patterns: %s", func_name, e)

            for pattern_name, pattern in custom_patterns.items():
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
                        },
                    )

        return custom_matches

    def _find_unidentified_functions(self, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Find functions that haven't been identified by signatures."""
        unidentified: list[dict[str, Any]] = []

        for func in functions:
            func_name = func.get("name", "")

            # Functions starting with these prefixes are typically unidentified
            if func_name.startswith("fcn.") or func_name.startswith("sub_") or func_name.startswith("loc_"):
                unidentified.append(func)

        return unidentified

    def _generate_signature_statistics(self, result: dict[str, Any]) -> dict[str, Any]:
        """Generate comprehensive signature statistics."""
        # Count functions
        identified_funcs = result.get("identified_functions", [])
        unidentified_funcs = result.get("unidentified_functions", [])

        stats = {
            "identification_rate": 0.0,
            "library_function_count": 0,
            "crypto_function_count": 0,
            "anti_analysis_count": 0,
            "license_validation_count": 0,
            "vulnerability_count": 0,
            "total_functions": len(identified_funcs) + len(unidentified_funcs),
            "identified_functions": len(identified_funcs),
            "unidentified_functions": len(unidentified_funcs),
        }
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
        high_confidence: list[dict[str, Any]] = []
        medium_confidence: list[dict[str, Any]] = []
        low_confidence: list[dict[str, Any]] = []

        confidence_analysis: dict[str, Any] = {
            "high_confidence": high_confidence,
            "medium_confidence": medium_confidence,
            "low_confidence": low_confidence,
            "average_confidence": 0.0,
            "confidence_distribution": {},
        }

        identified_funcs = result.get("identified_functions", [])

        if not identified_funcs:
            return confidence_analysis

        confidences: list[float] = []
        for func in identified_funcs:
            confidence = func.get("confidence", 0.0)
            confidences.append(float(confidence))

            if confidence >= 0.8:
                high_confidence.append(func)
            elif confidence >= 0.5:
                medium_confidence.append(func)
            else:
                low_confidence.append(func)

        confidence_analysis["average_confidence"] = sum(confidences) / len(confidences)

        confidence_analysis["confidence_distribution"] = {
            "high (>= 0.8)": len(high_confidence),
            "medium (0.5-0.8)": len(medium_confidence),
            "low (< 0.5)": len(low_confidence),
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
