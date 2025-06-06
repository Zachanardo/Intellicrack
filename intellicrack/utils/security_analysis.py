"""
Security analysis utility functions.

This module provides security analysis capabilities including buffer overflow
detection, memory leak detection, and various security checks.
"""

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Try to import optional dependencies
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


def check_buffer_overflow(binary_path: str, functions: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Check for potential buffer overflow vulnerabilities.

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
        "risk_level": "unknown"
    }

    # Default unsafe functions to check
    unsafe_functions = functions or [
        "strcpy", "strcat", "gets", "sprintf", "vsprintf",
        "scanf", "sscanf", "fscanf", "vfscanf", "vscanf",
        "vsscanf", "streadd", "strecpy", "strtrns", "realpath",
        "syslog", "getopt", "getpass", "getwd", "gets",
        "sprintf", "vsprintf", "strncpy", "strncat", "memcpy"
    ]

    try:
        # Check for unsafe function imports
        if PEFILE_AVAILABLE and binary_path.lower().endswith(('.exe', '.dll')):
            pe = pefile.PE(binary_path)

            # Check security features
            if hasattr(pe, 'OPTIONAL_HEADER'):
                dll_chars = getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0)
                results["dep_enabled"] = bool(dll_chars & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                results["aslr_enabled"] = bool(dll_chars & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE

            # Check imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            if func_name.lower() in [f.lower() for f in unsafe_functions]:
                                results["vulnerable_functions"].append({
                                    "function": func_name,
                                    "dll": entry.dll.decode('utf-8', errors='ignore'),
                                    "risk": "high" if func_name.lower() in ["gets", "strcpy", "sprintf"] else "medium"
                                })

        # Check for patterns in binary
        with open(binary_path, 'rb') as f:
            data = f.read()

        # Look for format string patterns
        format_string_pattern = re.compile(rb'%[0-9]*[sdxnp]')
        format_strings = format_string_pattern.findall(data)
        if format_strings:
            results["unsafe_patterns"].append({
                "pattern": "Format strings",
                "count": len(format_strings),
                "risk": "medium"
            })

        # Look for stack-based buffer patterns
        if CAPSTONE_AVAILABLE:
            # This would require disassembly analysis
            pass

        # Calculate risk level
        risk_score = 0
        risk_score += len(results["vulnerable_functions"]) * 2
        risk_score += len(results["unsafe_patterns"])
        risk_score -= 2 if results["dep_enabled"] else 0
        risk_score -= 2 if results["aslr_enabled"] else 0

        if risk_score >= 5:
            results["risk_level"] = "high"
        elif risk_score >= 2:
            results["risk_level"] = "medium"
        else:
            results["risk_level"] = "low"

    except Exception as e:
        logger.error(f"Error checking buffer overflow: {e}")
        results["error"] = str(e)

    return results


def check_for_memory_leaks(binary_path: str, process_pid: Optional[int] = None) -> Dict[str, Any]:
    """
    Check for potential memory leaks.

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
            "potential_leaks": []
        },
        "dynamic_analysis": {},
        "risk_level": "unknown"
    }

    # Memory management functions to track
    allocation_funcs = [
        "malloc", "calloc", "realloc", "new", "_malloc", "_calloc",
        "HeapAlloc", "VirtualAlloc", "GlobalAlloc", "LocalAlloc",
        "CoTaskMemAlloc", "SysAllocString", "operator new"
    ]

    deallocation_funcs = [
        "free", "delete", "_free", "HeapFree", "VirtualFree",
        "GlobalFree", "LocalFree", "CoTaskMemFree", "SysFreeString",
        "operator delete"
    ]

    try:
        # Static analysis
        if PEFILE_AVAILABLE and binary_path.lower().endswith(('.exe', '.dll')):
            pe = pefile.PE(binary_path)

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')

                            if any(alloc in func_name.lower() for alloc in [f.lower() for f in allocation_funcs]):
                                results["static_analysis"]["allocation_functions"].append(func_name)
                            elif any(dealloc in func_name.lower() for dealloc in [f.lower() for f in deallocation_funcs]):
                                results["static_analysis"]["deallocation_functions"].append(func_name)

        # Check for imbalance
        alloc_count = len(results["static_analysis"]["allocation_functions"])
        dealloc_count = len(results["static_analysis"]["deallocation_functions"])

        if alloc_count > 0 and dealloc_count == 0:
            results["static_analysis"]["potential_leaks"].append({
                "issue": "No deallocation functions found",
                "severity": "high"
            })
        elif alloc_count > dealloc_count * 2:
            results["static_analysis"]["potential_leaks"].append({
                "issue": "Allocation/deallocation imbalance",
                "severity": "medium"
            })

        # Dynamic analysis if process is running
        if process_pid and PSUTIL_AVAILABLE:
            try:
                process = psutil.Process(process_pid)

                # Sample memory usage
                samples = []
                for _ in range(5):
                    mem_info = process.memory_info()
                    samples.append({
                        "rss": mem_info.rss,
                        "vms": mem_info.vms
                    })
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
                        "samples": len(samples)
                    }

                    if growth_rate > 10:  # More than 10MB growth in 5 seconds
                        results["static_analysis"]["potential_leaks"].append({
                            "issue": f"Rapid memory growth: {growth_rate:.2f} MB",
                            "severity": "high"
                        })

            except Exception as e:
                logger.error(f"Error in dynamic memory analysis: {e}")

        # Calculate risk level
        high_severity = sum(1 for leak in results["static_analysis"]["potential_leaks"] if leak["severity"] == "high")
        medium_severity = sum(1 for leak in results["static_analysis"]["potential_leaks"] if leak["severity"] == "medium")

        if high_severity > 0:
            results["risk_level"] = "high"
        elif medium_severity > 0:
            results["risk_level"] = "medium"
        else:
            results["risk_level"] = "low"

    except Exception as e:
        logger.error(f"Error checking for memory leaks: {e}")
        results["error"] = str(e)

    return results


def check_memory_usage(process_pid: int) -> Dict[str, Any]:
    """
    Check current memory usage of a process.

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
            "status": process.status()
        }

        # Get detailed memory maps if available
        try:
            memory_maps = process.memory_maps()
            results["memory_regions"] = len(memory_maps)

            # Categorize memory regions
            categories = {
                "executable": 0,
                "writable": 0,
                "readable": 0,
                "private": 0,
                "shared": 0
            }

            for mmap in memory_maps:
                if 'x' in mmap.perms:
                    categories["executable"] += 1
                if 'w' in mmap.perms:
                    categories["writable"] += 1
                if 'r' in mmap.perms:
                    categories["readable"] += 1
                if 'p' in mmap.perms:
                    categories["private"] += 1
                if 's' in mmap.perms:
                    categories["shared"] += 1

            results["memory_categories"] = categories

        except Exception as e:
            logger.debug(f"Could not get memory maps: {e}")

        # Check for high memory usage
        if mem_percent > 80:
            results["warning"] = "Very high memory usage"
        elif mem_percent > 50:
            results["warning"] = "High memory usage"

        return results

    except psutil.NoSuchProcess:
        return {"error": f"Process {process_pid} not found"}
    except Exception as e:
        logger.error(f"Error checking memory usage: {e}")
        return {"error": str(e)}


def bypass_tpm_checks(binary_path: str) -> Dict[str, Any]:
    """
    Generate patches to bypass TPM (Trusted Platform Module) checks.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing TPM bypass information
    """
    results = {
        "tpm_functions": [],
        "patches": [],
        "method": "none"
    }

    # TPM-related functions
    tpm_functions = [
        "Tbsi_Context_Create",
        "Tbsi_Get_TCG_Log",
        "Tbsip_Submit_Command",
        "NCryptOpenStorageProvider",
        "NCryptCreatePersistedKey",
        "NCryptFinalizeKey",
        "BCryptOpenAlgorithmProvider",
        "BCryptGetProperty"
    ]

    try:
        if PEFILE_AVAILABLE and binary_path.lower().endswith(('.exe', '.dll')):
            pe = pefile.PE(binary_path)

            # Find TPM-related imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()

                    # Check for TPM-related DLLs
                    if any(tpm_dll in dll_name for tpm_dll in ['tbs.dll', 'ncrypt.dll', 'bcrypt.dll']):
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode('utf-8', errors='ignore')
                                if func_name in tpm_functions:
                                    results["tpm_functions"].append({
                                        "function": func_name,
                                        "dll": dll_name,
                                        "address": hex(imp.address)
                                    })

            # Generate bypass patches
            if results["tpm_functions"]:
                results["method"] = "import_patching"

                # Create patches to return success for TPM functions
                for tpm_func in results["tpm_functions"]:
                    results["patches"].append({
                        "type": "iat_hook",
                        "function": tpm_func["function"],
                        "original_address": tpm_func["address"],
                        "patch": "return_success",
                        "description": f"Hook {tpm_func['function']} to always return success"
                    })

        # Additional bypass methods
        results["additional_methods"] = [
            {
                "method": "registry_emulation",
                "description": "Emulate TPM presence in registry"
            },
            {
                "method": "api_hooking",
                "description": "Hook TPM APIs at runtime"
            },
            {
                "method": "driver_emulation",
                "description": "Install TPM emulation driver"
            }
        ]

    except Exception as e:
        logger.error(f"Error analyzing TPM checks: {e}")
        results["error"] = str(e)

    return results


def scan_protectors(binary_path: str) -> Dict[str, Any]:
    """
    Scan for various protection mechanisms.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing protection scan results
    """
    results = {
        "protections_found": [],
        "anti_debug": [],
        "anti_vm": [],
        "packers": [],
        "obfuscation": [],
        "checksums": []
    }

    try:
        with open(binary_path, 'rb') as f:
            data = f.read()

        # Anti-debugging checks
        anti_debug_patterns = {
            b"IsDebuggerPresent": "IsDebuggerPresent API",
            b"CheckRemoteDebuggerPresent": "CheckRemoteDebuggerPresent API",
            b"NtQueryInformationProcess": "NtQueryInformationProcess API",
            b"OutputDebugString": "OutputDebugString API",
            b"NtSetInformationThread": "Thread hiding",
            b"\\x64\\x03": "FS:[30h] PEB check",
            b"\\xCC": "INT3 breakpoint"
        }

        for pattern, description in anti_debug_patterns.items():
            if pattern in data:
                results["anti_debug"].append({
                    "technique": description,
                    "pattern": pattern.hex()
                })
                results["protections_found"].append(f"Anti-debug: {description}")

        # Anti-VM checks
        anti_vm_patterns = {
            b"VMware": "VMware detection",
            b"VirtualBox": "VirtualBox detection",
            b"VBOX": "VirtualBox detection",
            b"Virtual HD": "Virtual hard disk detection",
            b"QEMU": "QEMU detection",
            b"Microsoft Corporation": "Hyper-V detection",
            b"innotek GmbH": "VirtualBox vendor detection"
        }

        for pattern, description in anti_vm_patterns.items():
            if pattern in data:
                results["anti_vm"].append({
                    "technique": description,
                    "pattern": pattern.hex()
                })
                results["protections_found"].append(f"Anti-VM: {description}")

        # Packer signatures
        packer_sigs = {
            b"UPX!": "UPX",
            b"ASPack": "ASPack",
            b".petite": "Petite",
            b"PECompact": "PECompact",
            b"Themida": "Themida",
            b".enigma": "Enigma Protector"
        }

        for sig, packer in packer_sigs.items():
            if sig in data:
                results["packers"].append({
                    "packer": packer,
                    "signature": sig.hex()
                })
                results["protections_found"].append(f"Packer: {packer}")

        # Check for high entropy sections (possible encryption/obfuscation)
        if PEFILE_AVAILABLE and binary_path.lower().endswith(('.exe', '.dll')):
            pe = pefile.PE(binary_path)

            for section in pe.sections:
                if hasattr(section, 'get_entropy'):
                    entropy = section.get_entropy()
                    if entropy > 7.0:
                        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                        results["obfuscation"].append({
                            "section": section_name,
                            "entropy": entropy,
                            "indication": "Possible packing/encryption"
                        })
                        results["protections_found"].append(f"High entropy section: {section_name}")

        # Checksum verification patterns
        checksum_patterns = {
            b"CRC32": "CRC32 checksum",
            b"MD5": "MD5 hash verification",
            b"SHA": "SHA hash verification"
        }

        for pattern, description in checksum_patterns.items():
            if pattern in data:
                results["checksums"].append({
                    "type": description,
                    "pattern": pattern.hex()
                })
                results["protections_found"].append(f"Checksum: {description}")

    except Exception as e:
        logger.error(f"Error scanning protectors: {e}")
        results["error"] = str(e)

    return results


def run_tpm_bypass(binary_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Run TPM bypass on a binary.

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


def run_vm_bypass(binary_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Run VM detection bypass on a binary.

    Args:
        binary_path: Path to the binary file
        output_path: Path for patched binary (optional)

    Returns:
        Dict containing bypass results
    """
    results = {
        "vm_checks": [],
        "patches": [],
        "method": "none"
    }

    try:
        # Scan for VM detection
        scan_results = scan_protectors(binary_path)
        results["vm_checks"] = scan_results["anti_vm"]

        # Generate patches for each VM check
        if results["vm_checks"]:
            results["method"] = "binary_patching"

            for check in results["vm_checks"]:
                results["patches"].append({
                    "type": "pattern_replacement",
                    "pattern": check["pattern"],
                    "replacement": "00" * (len(check["pattern"]) // 2),
                    "description": f"Neutralize {check['technique']}"
                })

        if output_path and results["patches"]:
            results["output_path"] = output_path
            results["status"] = "patches_generated"
            results["message"] = f"Generated {len(results['patches'])} patches for VM bypass"
        else:
            results["status"] = "analysis_only"

    except Exception as e:
        logger.error(f"Error in VM bypass: {e}")
        results["error"] = str(e)

    return results


# Export all functions
__all__ = [
    'check_buffer_overflow',
    'check_for_memory_leaks',
    'check_memory_usage',
    'bypass_tpm_checks',
    'scan_protectors',
    'run_tpm_bypass',
    'run_vm_bypass'
]
