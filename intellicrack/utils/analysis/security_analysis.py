"""Security analysis utility functions.

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
import re
from typing import Any

# Import availability checks from correct handlers
from intellicrack.handlers.capstone_handler import CAPSTONE_AVAILABLE
from intellicrack.handlers.pefile_handler import PEFILE_AVAILABLE
from intellicrack.handlers.psutil_handler import PSUTIL_AVAILABLE


logger = logging.getLogger(__name__)


# Import optional dependencies
try:
    from intellicrack.handlers.capstone_handler import capstone
except ImportError as e:
    logger.exception("Import error in security_analysis: %s", e)
    capstone = None

try:
    from intellicrack.handlers.psutil_handler import psutil
except ImportError as e:
    logger.exception("Import error in security_analysis: %s", e)
    psutil = None

try:
    from intellicrack.handlers.pefile_handler import pefile
except ImportError as e:
    logger.exception("Import error in security_analysis: %s", e)
    pefile = None


def check_buffer_overflow(binary_path: str, functions: list[str] | None = None) -> dict[str, Any]:
    """Check for potential buffer overflow vulnerabilities.

    Args:
        binary_path: Path to the binary file
        functions: List of specific functions to check (optional)

    Returns:
        Dict containing buffer overflow analysis results

    """
    results = {
        "vulnerable_functions": [],
        "unsafe_patterns": [],
        "stack_canaries": False,
        "dep_enabled": False,
        "aslr_enabled": False,
        "risk_level": "unknown",
    }

    # Default unsafe functions to check
    unsafe_functions = functions or [
        "strcpy",
        "strcat",
        "gets",
        "sprintf",
        "vsprintf",
        "scanf",
        "sscanf",
        "fscanf",
        "vfscanf",
        "vscanf",
        "vsscanf",
        "streadd",
        "strecpy",
        "strtrns",
        "realpath",
        "syslog",
        "getopt",
        "getpass",
        "getwd",
        "gets",
        "sprintf",
        "vsprintf",
        "strncpy",
        "strncat",
        "memcpy",
    ]

    try:
        # Check for unsafe function imports
        if PEFILE_AVAILABLE and binary_path.lower().endswith((".exe", ".dll")):
            pe = pefile.PE(binary_path)

            # Check security features
            if hasattr(pe, "OPTIONAL_HEADER"):
                dll_chars = getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0)
                results["dep_enabled"] = bool(dll_chars & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                results["aslr_enabled"] = bool(dll_chars & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE

            # Check imports for vulnerable functions
            # Also need DLL names for detailed analysis
            from ..binary.pe_common import iterate_pe_imports_with_dll

            def check_vulnerable_function(dll_name: str, func_name: str) -> dict[str, str] | None:
                if func_name.lower() in [f.lower() for f in unsafe_functions]:
                    return {
                        "function": func_name,
                        "dll": dll_name,
                        "risk": ("high" if func_name.lower() in {"gets", "strcpy", "sprintf"} else "medium"),
                    }
                return None

            # Use the common function to iterate imports
            vuln_funcs_list = results["vulnerable_functions"]
            if isinstance(vuln_funcs_list, list):
                import_results = iterate_pe_imports_with_dll(pe, check_vulnerable_function)
                if hasattr(import_results, "__iter__"):
                    for vuln_func in import_results:
                        vuln_funcs_list.append(vuln_func)

        # Check for _patterns in binary
        with open(binary_path, "rb") as f:
            data = f.read()

        # Look for format string patterns
        format_string_pattern = re.compile(rb"%[0-9]*[sdxnp]")
        format_strings = format_string_pattern.findall(data)
        if format_strings:
            unsafe_patterns_list = results["unsafe_patterns"]
            if isinstance(unsafe_patterns_list, list):
                unsafe_patterns_list.append({"pattern": "Format strings", "count": len(format_strings), "risk": "medium"})

        # Look for stack-based buffer patterns and vulnerability indicators
        if CAPSTONE_AVAILABLE:
            stack_analysis = _analyze_stack_patterns(binary_path, data)
            results.update(stack_analysis)
        else:
            # Fallback analysis without disassembly
            fallback_analysis = _analyze_patterns_without_disassembly(data)
            unsafe_patterns_list = results["unsafe_patterns"]
            if isinstance(unsafe_patterns_list, list):
                patterns_from_fallback = fallback_analysis.get("patterns", [])
                if isinstance(patterns_from_fallback, list):
                    unsafe_patterns_list.extend(patterns_from_fallback)
            results["stack_canaries"] = fallback_analysis.get("stack_canaries", False)

        # Additional vulnerability pattern detection
        vuln_patterns = _detect_vulnerability_patterns(data)
        unsafe_patterns_list = results["unsafe_patterns"]
        if isinstance(unsafe_patterns_list, list):
            unsafe_patterns_list.extend(vuln_patterns)

        # Check for ROP/JOP gadgets that could be exploited
        gadget_analysis = _analyze_rop_gadgets(data)
        gadget_count = gadget_analysis.get("gadget_count", 0)
        if isinstance(gadget_count, int) and gadget_count > 10:
            unsafe_patterns_list = results["unsafe_patterns"]
            if isinstance(unsafe_patterns_list, list):
                unsafe_patterns_list.append({"pattern": "ROP gadgets", "count": gadget_count, "risk": "high"})

        # Analyze string operations for potential buffer overflows
        string_analysis = _analyze_string_operations(data)
        unsafe_patterns_list = results["unsafe_patterns"]
        if isinstance(unsafe_patterns_list, list):
            unsafe_patterns_list.extend(string_analysis)

        # Calculate risk level
        risk_score = 0
        vuln_funcs_list = results["vulnerable_functions"]
        unsafe_patterns_list = results["unsafe_patterns"]
        risk_score += len(vuln_funcs_list) * 2 if isinstance(vuln_funcs_list, list) else 0
        risk_score += len(unsafe_patterns_list) if isinstance(unsafe_patterns_list, list) else 0
        risk_score -= 2 if results["dep_enabled"] else 0
        risk_score -= 2 if results["aslr_enabled"] else 0

        if risk_score >= 5:
            results["risk_level"] = "high"
        elif risk_score >= 2:
            results["risk_level"] = "medium"
        else:
            results["risk_level"] = "low"

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error checking buffer overflow: %s", e)
        results["error"] = str(e)

    return results


def _analyze_stack_patterns(binary_path: str, data: bytes) -> dict[str, Any]:
    """Analyze stack-based patterns using Capstone disassembly.

    Args:
        binary_path: Path to the binary file
        data: Binary data

    Returns:
        dict: Stack analysis results including patterns and canary detection

    """
    results: dict[str, Any] = {"patterns": [], "stack_canaries": False, "stack_operations": []}

    try:
        if not CAPSTONE_AVAILABLE:
            logger.warning("Capstone not available for stack pattern analysis")
            return results

        # Determine architecture
        is_64bit = b"PE\x00\x00d\x86" in data[:1024] or b"\x7fELF\x02" in data[:10]

        # Initialize Capstone disassembler
        if is_64bit:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

        # Look for stack-related patterns
        stack_patterns = {
            # Stack buffer allocations
            b"\x48\x83\xec": "Large stack allocation (64-bit)",
            b"\x83\xec": "Stack allocation (32-bit)",
            b"\x48\x81\xec": "Very large stack allocation (64-bit)",
            b"\x81\xec": "Very large stack allocation (32-bit)",
            # Stack canary checks
            b"\x64\x48\x8b\x04\x25\x28\x00\x00\x00": "Stack canary check (64-bit)",
            b"\x64\xa1\x14\x00\x00\x00": "Stack canary check (32-bit)",
            # Buffer operations
            b"\x48\x8d": "LEA instruction (potential buffer reference)",
            b"\x8d": "LEA instruction (potential buffer reference)",
        }

        for pattern, description in stack_patterns.items():
            occurrences = data.count(pattern)
            if occurrences > 0:
                patterns_list = results["patterns"]
                if isinstance(patterns_list, list):
                    patterns_list.append(
                        {
                            "pattern": description,
                            "count": occurrences,
                            "risk": "medium" if "canary" in description else "low",
                        },
                    )
                if "canary" in description:
                    results["stack_canaries"] = True

        # Disassemble and analyze instructions
        code_sections: list[tuple[int, bytes]] = []
        if PEFILE_AVAILABLE and binary_path.lower().endswith((".exe", ".dll")):
            try:
                pe = pefile.PE(binary_path)
                code_sections.extend(
                    (section.VirtualAddress, section.get_data())
                    for section in pe.sections
                    if section.Characteristics & 0x20000000
                )
            except (pefile.PEFormatError, Exception) as e:
                logger.exception("Error in security_analysis: %s", e)
                code_sections = [(0, data)]
        else:
            code_sections = [(0, data)]

        # Analyze instructions for stack operations
        dangerous_stack_ops = 0
        for base_addr, code_data in code_sections[:1]:  # Limit analysis to first code section
            for i in md.disasm(code_data[:10000], base_addr):  # Analyze first 10KB
                if (i.mnemonic in ["sub", "add"] and i.op_str.startswith("esp,")) or i.op_str.startswith("rsp,"):
                    try:
                        # Check for large stack allocations
                        size = int(i.op_str.split(",")[1].strip(), 16)
                        if size > 0x1000:  # 4KB threshold
                            stack_ops_list = results["stack_operations"]
                            if isinstance(stack_ops_list, list):
                                stack_ops_list.append(
                                    {
                                        "address": hex(i.address),
                                        "operation": f"{i.mnemonic} {i.op_str}",
                                        "size": size,
                                        "risk": "high" if size > 0x10000 else "medium",
                                    },
                                )
                            dangerous_stack_ops += 1
                    except Exception as e:
                        logger.exception("Error in security_analysis: %s", e)

        if dangerous_stack_ops > 0:
            patterns_list = results["patterns"]
            if isinstance(patterns_list, list):
                patterns_list.append({"pattern": "Large stack allocations", "count": dangerous_stack_ops, "risk": "high"})

    except Exception as e:
        logger.exception("Error in stack pattern analysis: %s", e)

    return results


def _analyze_patterns_without_disassembly(data: bytes) -> dict[str, Any]:
    """Fallback analysis without disassembly when Capstone is not available.

    Args:
        data: Binary data

    Returns:
        dict: Analysis results with patterns and stack canary detection

    """
    results: dict[str, Any] = {"patterns": [], "stack_canaries": False}

    try:
        # Look for common patterns indicating stack protection
        canary_patterns = [
            b"__stack_chk_fail",
            b"__stack_chk_guard",
            b"___stack_chk_fail",
            b"___stack_chk_guard",
            b"__security_cookie",
            b"__security_check_cookie",
        ]

        for pattern in canary_patterns:
            if pattern in data:
                results["stack_canaries"] = True
                patterns_list = results["patterns"]
                if isinstance(patterns_list, list):
                    patterns_list.append(
                        {
                            "pattern": f"Stack protection: {pattern.decode('utf-8', errors='ignore')}",
                            "count": 1,
                            "risk": "low",
                        },
                    )
                break

        # Look for unsafe function references
        unsafe_refs = {
            b"strcpy": "strcpy (no bounds checking)",
            b"strcat": "strcat (no bounds checking)",
            b"gets": "gets (extremely unsafe)",
            b"sprintf": "sprintf (no bounds checking)",
            b"vsprintf": "vsprintf (no bounds checking)",
            b"scanf": "scanf (unsafe input)",
            b"memcpy": "memcpy (no bounds checking)",
        }

        for func, desc in unsafe_refs.items():
            count = data.count(func + b"\x00")  # Look for null-terminated strings
            if count > 0:
                patterns_list = results["patterns"]
                if isinstance(patterns_list, list):
                    patterns_list.append(
                        {
                            "pattern": desc,
                            "count": count,
                            "risk": "high" if func in [b"gets", b"strcpy"] else "medium",
                        },
                    )

    except Exception as e:
        logger.exception("Error in pattern analysis without disassembly: %s", e)

    return results


def _detect_vulnerability_patterns(data: bytes) -> list[dict[str, Any]]:
    """Detect specific vulnerability patterns in binary data.

    Args:
        data: Binary data

    Returns:
        list: Detected vulnerability patterns

    """
    patterns = []

    try:
        # Look for common vulnerability indicators
        vuln_indicators = {
            # Command injection patterns
            b"system(": {"desc": "system() call", "risk": "high"},
            b"exec": {"desc": "exec family functions", "risk": "high"},
            b"popen": {"desc": "popen() call", "risk": "high"},
            # Path traversal
            b"..\\": {"desc": "Path traversal pattern (Windows)", "risk": "medium"},
            b"../": {"desc": "Path traversal pattern (Unix)", "risk": "medium"},
            # SQL injection indicators
            b"SELECT * FROM": {"desc": "SQL query pattern", "risk": "medium"},
            b"DROP TABLE": {"desc": "Dangerous SQL pattern", "risk": "high"},
            # Buffer operation patterns
            b"alloca": {"desc": "Stack allocation", "risk": "medium"},
            b"_alloca": {"desc": "Stack allocation", "risk": "medium"},
        }

        for pattern, info in vuln_indicators.items():
            count = data.count(pattern)
            if count > 0:
                patterns.append({"pattern": info["desc"], "count": count, "risk": info["risk"]})

        # Look for integer overflow patterns in x86 assembly
        overflow_patterns = [
            b"\xf7\xe0",  # mul eax
            b"\xf7\xe1",  # mul ecx
            b"\x0f\xaf",  # imul
            b"\x69",  # imul with immediate
            b"\x6b",  # imul with immediate (byte)
        ]

        overflow_count = sum(data.count(p) for p in overflow_patterns)
        if overflow_count > 10:
            patterns.append(
                {
                    "pattern": "Integer multiplication operations",
                    "count": overflow_count,
                    "risk": "medium",
                },
            )

    except Exception as e:
        logger.exception("Error detecting vulnerability patterns: %s", e)

    return patterns


def _analyze_rop_gadgets(data: bytes) -> dict[str, Any]:
    """Analyze ROP (Return Oriented Programming) gadgets.

    Args:
        data: Binary data

    Returns:
        dict: ROP gadget analysis results

    """
    results: dict[str, Any] = {"gadget_count": 0, "gadget_types": {}, "exploitability": "low"}

    try:
        # Common ROP gadget patterns (x86/x64)
        gadget_patterns = {
            b"\xc3": "ret",
            b"\xc2": "ret n",
            b"\xcb": "retf",
            b"\xca": "retf n",
            b"\x5d\xc3": "pop ebp; ret",
            b"\x58\xc3": "pop eax; ret",
            b"\x59\xc3": "pop ecx; ret",
            b"\x5a\xc3": "pop edx; ret",
            b"\x5b\xc3": "pop ebx; ret",
            b"\x5e\xc3": "pop esi; ret",
            b"\x5f\xc3": "pop edi; ret",
            b"\x94\xc3": "xchg eax, esp; ret",
            b"\xff\xe0": "jmp eax",
            b"\xff\xe4": "jmp esp",
            b"\xff\xd0": "call eax",
            b"\xff\xd4": "call esp",
        }

        # Count gadgets
        for pattern, gadget_type in gadget_patterns.items():
            count = data.count(pattern)
            if count > 0:
                gadget_count = results["gadget_count"]
                if isinstance(gadget_count, int):
                    results["gadget_count"] = gadget_count + count
                gadget_types = results["gadget_types"]
                if isinstance(gadget_types, dict):
                    if gadget_type not in gadget_types:
                        gadget_types[gadget_type] = 0
                    current_val = gadget_types[gadget_type]
                    if isinstance(current_val, int):
                        gadget_types[gadget_type] = current_val + count

        # Assess exploitability based on gadget diversity and count
        gadget_types = results["gadget_types"]
        unique_gadget_types = len(gadget_types) if isinstance(gadget_types, dict) else 0
        total_gadgets = results["gadget_count"]
        if isinstance(total_gadgets, int):
            if total_gadgets > 100 and unique_gadget_types > 5:
                results["exploitability"] = "high"
            elif total_gadgets > 50 and unique_gadget_types > 3:
                results["exploitability"] = "medium"
            else:
                results["exploitability"] = "low"

        # Look for specific useful gadget chains
        useful_chains = {
            b"\x58\x5b\xc3": "pop eax; pop ebx; ret",
            b"\x59\x5a\xc3": "pop ecx; pop edx; ret",
            b"\x83\xc4\x04\xc3": "add esp, 4; ret",
            b"\x83\xc4\x08\xc3": "add esp, 8; ret",
        }

        for chain, desc in useful_chains.items():
            if chain in data:
                gadget_types = results["gadget_types"]
                if isinstance(gadget_types, dict):
                    gadget_types[desc] = data.count(chain)
                gadget_count = results["gadget_count"]
                if isinstance(gadget_count, int):
                    results["gadget_count"] = gadget_count + data.count(chain)

    except Exception as e:
        logger.exception("Error analyzing ROP gadgets: %s", e)

    return results


def _analyze_string_operations(data: bytes) -> list[dict[str, Any]]:
    """Analyze string operations for potential buffer overflows.

    Args:
        data: Binary data

    Returns:
        list: Unsafe string operation patterns

    """
    patterns = []

    try:
        # String operation patterns that might indicate unsafe usage
        string_ops = {
            # Unsafe C string functions
            b"strcpy@@": "strcpy (unbounded copy)",
            b"strcat@@": "strcat (unbounded concatenation)",
            b"gets@@": "gets (never safe)",
            b"sprintf@@": "sprintf (unbounded format)",
            b"vsprintf@@": "vsprintf (unbounded format)",
            # Potentially unsafe if misused
            b"strncpy@@": "strncpy (may not null-terminate)",
            b"strncat@@": "strncat (size calculation errors)",
            b"snprintf@@": "snprintf (truncation issues)",
            b"memcpy@@": "memcpy (no bounds checking)",
            b"memmove@@": "memmove (no bounds checking)",
            # Windows specific
            b"lstrcpy": "lstrcpy (unbounded copy)",
            b"lstrcat": "lstrcat (unbounded concatenation)",
            b"wsprintf": "wsprintf (unbounded format)",
            b"StrCpy": "StrCpy (unbounded copy)",
            b"StrCat": "StrCat (unbounded concatenation)",
        }

        for pattern, desc in string_ops.items():
            # Look for both the pattern and variations
            count = 0
            count += data.count(pattern)
            # Also check without @@ suffix
            count += data.count(pattern.replace(b"@@", b""))

            if count > 0:
                risk = "high"
                if b"strn" in pattern or b"snprintf" in pattern:
                    risk = "medium"
                elif b"gets" in pattern or b"strcpy" in pattern:
                    risk = "critical"

                patterns.append({"pattern": f"String operation: {desc}", "count": count, "risk": risk})

        # Look for string length checks (good practice)
        safety_patterns = {
            b"strlen": "String length checks",
            b"strnlen": "Safe string length checks",
            b"wcslen": "Wide string length checks",
            b"StringCchLength": "Safe string length (Windows)",
            b"StringCbLength": "Safe string byte length (Windows)",
        }

        safety_count = sum(data.count(pattern) for pattern in safety_patterns)
        if safety_count > 0:
            patterns.append({"pattern": "String safety checks present", "count": safety_count, "risk": "low"})

        # Look for bounds checking patterns
        bounds_patterns = [
            b"boundary check",
            b"bounds check",
            b"buffer size",
            b"max length",
            b"sizeof",
        ]

        bounds_count = sum(data.count(p) for p in bounds_patterns)
        if bounds_count > 0:
            patterns.append({"pattern": "Bounds checking indicators", "count": bounds_count, "risk": "low"})

    except Exception as e:
        logger.exception("Error analyzing string operations: %s", e)

    return patterns


def check_for_memory_leaks(binary_path: str, process_pid: int | None = None) -> dict[str, Any]:
    """Check for potential memory leaks.

    Args:
        binary_path: Path to the binary file
        process_pid: Process ID for runtime analysis (optional)

    Returns:
        Dict containing memory leak analysis results

    """
    results = {
        "static_analysis": {
            "allocation_functions": [],
            "deallocation_functions": [],
            "potential_leaks": [],
        },
        "dynamic_analysis": {},
        "risk_level": "unknown",
    }

    # Memory management functions to track
    allocation_funcs = [
        "malloc",
        "calloc",
        "realloc",
        "new",
        "_malloc",
        "_calloc",
        "HeapAlloc",
        "VirtualAlloc",
        "GlobalAlloc",
        "LocalAlloc",
        "CoTaskMemAlloc",
        "SysAllocString",
        "operator new",
    ]

    deallocation_funcs = [
        "free",
        "delete",
        "_free",
        "HeapFree",
        "VirtualFree",
        "GlobalFree",
        "LocalFree",
        "CoTaskMemFree",
        "SysFreeString",
        "operator delete",
    ]

    try:
        # Static analysis
        if PEFILE_AVAILABLE and binary_path.lower().endswith((".exe", ".dll")):
            pe = pefile.PE(binary_path)

            # Use common utility function for PE import extraction
            from ..binary.pe_common import extract_pe_imports

            imports = extract_pe_imports(pe)
            for func_name in imports:
                if any(alloc in func_name.lower() for alloc in [f.lower() for f in allocation_funcs]):
                    static_analysis = results["static_analysis"]
                    if isinstance(static_analysis, dict):
                        alloc_funcs_list = static_analysis["allocation_functions"]
                        if isinstance(alloc_funcs_list, list):
                            alloc_funcs_list.append(func_name)
                elif any(dealloc in func_name.lower() for dealloc in [f.lower() for f in deallocation_funcs]):
                    static_analysis = results["static_analysis"]
                    if isinstance(static_analysis, dict):
                        dealloc_funcs_list = static_analysis["deallocation_functions"]
                        if isinstance(dealloc_funcs_list, list):
                            dealloc_funcs_list.append(func_name)

        # Check for imbalance
        static_analysis = results["static_analysis"]
        if isinstance(static_analysis, dict):
            alloc_funcs_list = static_analysis["allocation_functions"]
            dealloc_funcs_list = static_analysis["deallocation_functions"]
            alloc_count = len(alloc_funcs_list) if isinstance(alloc_funcs_list, list) else 0
            dealloc_count = len(dealloc_funcs_list) if isinstance(dealloc_funcs_list, list) else 0

            if alloc_count > 0 and dealloc_count == 0:
                potential_leaks = static_analysis["potential_leaks"]
                if isinstance(potential_leaks, list):
                    potential_leaks.append({"issue": "No deallocation functions found", "severity": "high"})
            elif alloc_count > dealloc_count * 2:
                potential_leaks = static_analysis["potential_leaks"]
                if isinstance(potential_leaks, list):
                    potential_leaks.append({"issue": "Allocation/deallocation imbalance", "severity": "medium"})

        # Dynamic analysis if process is running
        if process_pid and PSUTIL_AVAILABLE:
            try:
                process = psutil.Process(process_pid)

                # Sample memory usage
                samples = []
                for __ in range(5):
                    mem_info = process.memory_info()
                    samples.append({"rss": mem_info.rss, "vms": mem_info.vms})
                    import time

                    time.sleep(1)

                # Check for growth
                if len(samples) >= 2:
                    growth = samples[-1]["rss"] - samples[0]["rss"]
                    growth_rate = growth / (1024 * 1024)  # Convert to MB

                    results["dynamic_analysis"] = {
                        "initial_rss_mb": samples[0]["rss"] / (1024 * 1024),
                        "final_rss_mb": samples[-1]["rss"] / (1024 * 1024),
                        "growth_mb": growth_rate,
                        "samples": len(samples),
                    }

                    if growth_rate > 10:  # More than 10MB growth in 5 seconds
                        static_analysis = results["static_analysis"]
                        if isinstance(static_analysis, dict):
                            potential_leaks = static_analysis["potential_leaks"]
                            if isinstance(potential_leaks, list):
                                potential_leaks.append(
                                    {
                                        "issue": f"Rapid memory growth: {growth_rate:.2f} MB",
                                        "severity": "high",
                                    },
                                )

            except (OSError, ValueError, RuntimeError) as e:
                logger.exception("Error in dynamic memory analysis: %s", e)

        # Calculate risk level
        static_analysis = results["static_analysis"]
        if isinstance(static_analysis, dict):
            potential_leaks = static_analysis["potential_leaks"]
            if isinstance(potential_leaks, list):
                high_severity = sum(bool(isinstance(leak, dict) and leak.get("severity") == "high")
                                for leak in potential_leaks)
                medium_severity = sum(bool(isinstance(leak, dict) and leak.get("severity") == "medium")
                                  for leak in potential_leaks)
            else:
                high_severity = 0
                medium_severity = 0
        else:
            high_severity = 0
            medium_severity = 0

        if high_severity > 0:
            results["risk_level"] = "high"
        elif medium_severity > 0:
            results["risk_level"] = "medium"
        else:
            results["risk_level"] = "low"

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error checking for memory leaks: %s", e)
        results["error"] = str(e)

    return results


def check_memory_usage(process_pid: int) -> dict[str, Any]:
    """Check current memory usage of a process.

    Args:
        process_pid: Process ID to check

    Returns:
        Dict containing memory usage information

    """
    if not PSUTIL_AVAILABLE:
        return {"error": "psutil module not available"}

    try:
        process = psutil.Process(process_pid)

        # Get memory info
        mem_info = process.memory_info()
        mem_percent = process.memory_percent()

        results = {
            "pid": process_pid,
            "name": process.name(),
            "rss_mb": mem_info.rss / (1024 * 1024),
            "vms_mb": mem_info.vms / (1024 * 1024),
            "percent": mem_percent,
            "status": process.status(),
        }

        # Get detailed memory maps if available
        try:
            memory_maps = process.memory_maps()
            results["memory_regions"] = len(memory_maps)

            # Categorize memory regions
            categories = {"executable": 0, "writable": 0, "readable": 0, "private": 0, "shared": 0}

            for mmap in memory_maps:
                if "x" in mmap.perms:
                    categories["executable"] += 1
                if "w" in mmap.perms:
                    categories["writable"] += 1
                if "r" in mmap.perms:
                    categories["readable"] += 1
                if "p" in mmap.perms:
                    categories["private"] += 1
                if "s" in mmap.perms:
                    categories["shared"] += 1

            results["memory_categories"] = categories

        except (OSError, ValueError, RuntimeError) as e:
            logger.debug("Could not get memory maps: %s", e)

        # Check for high memory usage
        if mem_percent > 80:
            results["warning"] = "Very high memory usage"
        elif mem_percent > 50:
            results["warning"] = "High memory usage"

        return results

    except psutil.NoSuchProcess as e:
        logger.exception("No such process in security_analysis: %s", e)
        return {"error": f"Process {process_pid} not found"}
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error checking memory usage: %s", e)
        return {"error": str(e)}


def bypass_tpm_checks(binary_path: str) -> dict[str, Any]:
    """Generate patches to bypass TPM (Trusted Platform Module) checks.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing TPM bypass information

    """
    results: dict[str, Any] = {"tpm_functions": [], "patches": [], "method": "none"}

    # TPM-related functions
    tpm_functions = [
        "Tbsi_Context_Create",
        "Tbsi_Get_TCG_Log",
        "Tbsip_Submit_Command",
        "NCryptOpenStorageProvider",
        "NCryptCreatePersistedKey",
        "NCryptFinalizeKey",
        "BCryptOpenAlgorithmProvider",
        "BCryptGetProperty",
    ]

    try:
        if PEFILE_AVAILABLE and binary_path.lower().endswith((".exe", ".dll")):
            pe = pefile.PE(binary_path)

            # Find TPM-related imports
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore").lower()

                    # Check for TPM-related DLLs
                    if any(tmp_dll in dll_name for tmp_dll in ["tbs.dll", "ncrypt.dll", "bcrypt.dll"]):
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode("utf-8", errors="ignore")
                                if func_name in tpm_functions:
                                    tpm_funcs_list = results["tpm_functions"]
                                    if isinstance(tpm_funcs_list, list):
                                        tpm_funcs_list.append(
                                            {
                                                "function": func_name,
                                                "dll": dll_name,
                                                "address": hex(imp.address),
                                            },
                                        )

            if tpm_funcs_list := results["tpm_functions"]:
                results["method"] = "import_patching"

                # Create patches to return success for TPM functions
                if isinstance(tpm_funcs_list, list):
                    for tpm_func in tpm_funcs_list:
                        if isinstance(tpm_func, dict):
                            patches_list = results["patches"]
                            if isinstance(patches_list, list):
                                patches_list.append(
                                    {
                                        "type": "iat_hook",
                                        "function": tpm_func.get("function", ""),
                                        "original_address": tpm_func.get("address", ""),
                                        "patch": "return_success",
                                        "description": f"Hook {tpm_func.get('function', '')} to always return success",
                                    },
                                )

        # Additional bypass methods
        results["additional_methods"] = [
            {"method": "registry_emulation", "description": "Emulate TPM presence in registry"},
            {"method": "api_hooking", "description": "Hook TPM APIs at runtime"},
            {"method": "driver_emulation", "description": "Install TPM emulation driver"},
        ]

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error analyzing TPM checks: %s", e)
        results["error"] = str(e)

    return results


def scan_protectors(binary_path: str) -> dict[str, Any]:
    """Scan for various protection mechanisms.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing protection scan results

    """
    results: dict[str, Any] = {
        "protections_found": [],
        "anti_debug": [],
        "anti_vm": [],
        "packers": [],
        "obfuscation": [],
        "checksums": [],
    }

    try:
        with open(binary_path, "rb") as f:
            data = f.read()

        # Anti-debugging checks
        anti_debug_patterns = {
            b"IsDebuggerPresent": "IsDebuggerPresent API",
            b"CheckRemoteDebuggerPresent": "CheckRemoteDebuggerPresent API",
            b"NtQueryInformationProcess": "NtQueryInformationProcess API",
            b"OutputDebugString": "OutputDebugString API",
            b"NtSetInformationThread": "Thread hiding",
            b"\\x64\\x03": "FS:[30h] PEB check",
            b"\\xCC": "INT3 breakpoint",
        }

        for pattern, description in anti_debug_patterns.items():
            if pattern in data:
                results["anti_debug"].append({"technique": description, "pattern": pattern.hex()})
                results["protections_found"].append(f"Anti-debug: {description}")

        # Anti-VM checks
        anti_vm_patterns = {
            b"VMware": "VMware detection",
            b"VirtualBox": "VirtualBox detection",
            b"VBOX": "VirtualBox detection",
            b"Virtual HD": "Virtual hard disk detection",
            b"QEMU": "QEMU detection",
            b"Microsoft Corporation": "Hyper-V detection",
            b"innotek GmbH": "VirtualBox vendor detection",
        }

        for pattern, description in anti_vm_patterns.items():
            if pattern in data:
                results["anti_vm"].append({"technique": description, "pattern": pattern.hex()})
                results["protections_found"].append(f"Anti-VM: {description}")

        # Packer signatures
        packer_sigs = {
            b"UPX!": "UPX",
            b"ASPack": "ASPack",
            b".petite": "Petite",
            b"PECompact": "PECompact",
            b"Themida": "Themida",
            b".enigma": "Enigma Protector",
        }

        for sig, packer in packer_sigs.items():
            if sig in data:
                results["packers"].append({"packer": packer, "signature": sig.hex()})
                results["protections_found"].append(f"Packer: {packer}")

        # Check for high entropy sections (possible encryption/obfuscation)
        if PEFILE_AVAILABLE and binary_path.lower().endswith((".exe", ".dll")):
            pe = pefile.PE(binary_path)

            for section in pe.sections:
                if hasattr(section, "get_entropy"):
                    entropy = section.get_entropy()
                    if entropy > 7.0:
                        section_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                        results["obfuscation"].append(
                            {
                                "section": section_name,
                                "entropy": entropy,
                                "indication": "Possible packing/encryption",
                            },
                        )
                        results["protections_found"].append(f"High entropy section: {section_name}")

        # Checksum verification patterns
        checksum_patterns = {
            b"CRC32": "CRC32 checksum",
            b"MD5": "MD5 hash verification",
            b"SHA": "SHA hash verification",
        }

        for pattern, description in checksum_patterns.items():
            if pattern in data:
                results["checksums"].append({"type": description, "pattern": pattern.hex()})
                results["protections_found"].append(f"Checksum: {description}")

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error scanning protectors: %s", e)
        results_dict: dict[str, Any] = {"error": str(e)}
        return results_dict

    return results


def run_tpm_bypass(binary_path: str, output_path: str | None = None) -> dict[str, Any]:
    """Run TPM bypass on a binary.

    Args:
        binary_path: Path to the binary file
        output_path: Path for patched binary (optional)

    Returns:
        Dict containing bypass results

    """
    results = bypass_tpm_checks(binary_path)

    if output_path and results["patches"]:
        # This would apply the patches to create a new binary
        results["output_path"] = output_path
        results["status"] = "patches_generated"
        results["message"] = f"Generated {len(results['patches'])} patches for TPM bypass"
    else:
        results["status"] = "analysis_only"

    return results


def run_vm_bypass(binary_path: str, output_path: str | None = None) -> dict[str, Any]:
    """Run VM detection bypass on a binary.

    Args:
        binary_path: Path to the binary file
        output_path: Path for patched binary (optional)

    Returns:
        Dict containing bypass results

    """
    results: dict[str, Any] = {"vm_checks": [], "patches": [], "method": "none"}

    try:
        # Scan for VM detection
        scan_results = scan_protectors(binary_path)
        anti_vm = scan_results.get("anti_vm", [])
        if isinstance(anti_vm, list):
            results["vm_checks"] = anti_vm

        if vm_checks := results["vm_checks"]:
            results["method"] = "binary_patching"

            if isinstance(vm_checks, list):
                for check in vm_checks:
                    if isinstance(check, dict):
                        pattern_val = check.get("pattern", "")
                        technique_val = check.get("technique", "")
                        if isinstance(pattern_val, str):
                            patches_list = results["patches"]
                            if isinstance(patches_list, list):
                                patches_list.append(
                                    {
                                        "type": "pattern_replacement",
                                        "pattern": pattern_val,
                                        "replacement": "00" * (len(pattern_val) // 2),
                                        "description": f"Neutralize {technique_val}",
                                    },
                                )

        patches_list = results["patches"]
        if output_path and patches_list:
            results["output_path"] = output_path
            results["status"] = "patches_generated"
            patch_count = len(patches_list) if isinstance(patches_list, list) else 0
            results["message"] = f"Generated {patch_count} patches for VM bypass"
        else:
            results["status"] = "analysis_only"

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in VM bypass: %s", e)
        results["error"] = str(e)

    return results


# Export all functions
__all__ = [
    "_analyze_patterns_without_disassembly",
    "_analyze_rop_gadgets",
    "_analyze_stack_patterns",
    "_analyze_string_operations",
    "_detect_vulnerability_patterns",
    "bypass_tpm_checks",
    "check_buffer_overflow",
    "check_for_memory_leaks",
    "check_memory_usage",
    "run_tpm_bypass",
    "run_vm_bypass",
    "scan_protectors",
]
