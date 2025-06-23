"""
Protection detection utilities for Intellicrack.

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


import hashlib
import logging
import os
import sys
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

from ..system.driver_utils import get_driver_path


def _get_driver_path(driver_name: str) -> str:
    """Get Windows driver path dynamically."""
    return get_driver_path(driver_name)


def detect_virtualization_protection(binary_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Detect virtualization-based protections.

    Args:
        binary_path: Path to binary to analyze

    Returns:
        Detection results
    """
    results = {
        "virtualization_detected": False,
        "protection_types": [],
        "indicators": [],
        "confidence": 0.0
    }

    # Log the binary being analyzed for virtualization protection
    if binary_path:
        logger.debug(f"Analyzing virtualization protection for binary: {binary_path}")

    try:
        # Check for known VM detection techniques
        vm_indicators = [
            "VirtualBox", "VMware", "QEMU", "Xen", "Hyper-V",
            "vbox", "vmtoolsd", "vmwareuser", "qemu-ga"
        ]

        # Check running processes (if possible)
        try:
            import psutil
            running_processes = [_p.info['name'].lower() for _p in psutil.process_iter(['name']) if _p.info['name']]

            for _indicator in vm_indicators:
                if any(_indicator.lower() in _proc for _proc in running_processes):
                    results["indicators"].append(f"VM process detected: {_indicator}")
                    results["virtualization_detected"] = True

        except ImportError:
            logger.debug("psutil not available for process checking")

        # Check registry for VM artifacts (Windows)
        if sys.platform == 'win32':
            try:
                import winreg
                vm_registry_keys = [
                    r"SOFTWARE\Oracle\VirtualBox Guest Additions",
                    r"SOFTWARE\VMware, Inc.\VMware Tools",
                    r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
                ]

                for _key_path in vm_registry_keys:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _key_path)
                        results["indicators"].append(f"VM registry key found: {_key_path}")
                        results["virtualization_detected"] = True
                        winreg.CloseKey(key)
                    except FileNotFoundError:
                        pass

            except ImportError:
                logger.debug("winreg not available")

        # Check for VM-specific files
        vm_files = [
            "/proc/scsi/scsi",  # Linux
            "/sys/class/dmi/id/product_name",  # Linux
            _get_driver_path("vboxguest.sys"),  # Windows VirtualBox
            _get_driver_path("vmhgfs.sys"),  # Windows VMware
        ]

        for _vm_file in vm_files:
            if os.path.exists(_vm_file):
                try:
                    with open(_vm_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().lower()
                        for _indicator in vm_indicators:
                            if _indicator.lower() in content:
                                results["indicators"].append(f"VM indicator in {_vm_file}: {_indicator}")
                                results["virtualization_detected"] = True
                except Exception:
                    pass

        # Calculate confidence
        if results["virtualization_detected"]:
            results["confidence"] = min(len(results["indicators"]) * 0.3, 1.0)
            results["protection_types"].append("VM Detection")

        logger.info(f"Virtualization detection complete: {results['virtualization_detected']}")

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in virtualization detection: %s", e)
        results["error"] = str(e)

    return results


def detect_commercial_protections(binary_path: str) -> Dict[str, Any]:
    """
    Detect commercial software protections.

    Args:
        binary_path: Path to binary to analyze

    Returns:
        Detection results
    """
    results = {
        "protections_found": [],
        "confidence_scores": {},
        "indicators": []
    }

    try:
        if not os.path.exists(binary_path):
            return {"error": "Binary file not found"}

        # Known protection signatures
        protection_signatures = {
            "UPX": [b"UPX!", b"$Info: This file is packed with the UPX"],
            "VMProtect": [b"VMProtect", b".vmp0", b".vmp1"],
            "Themida": [b"Themida", b"Oreans Technologies"],
            "Enigma": [b"Enigma", b"The Enigma Protector"],
            "ASPack": [b"ASPack", b"ByDwing"],
            "PECompact": [b"PECompact", b"Bitsum Technologies"],
            "Armadillo": [b"Armadillo", b"Silicon Realms"],
            "ExeCryptor": [b"ExeCryptor", b"StrongBit"],
            "CodeVirtualizer": [b"CodeVirtualizer", b"Oreans"],
            "WinLicense": [b"WinLicense", b"Oreans Technologies"],
        }

        # Read binary file
        with open(binary_path, 'rb') as f:
            binary_data = f.read()

        # Check for protection signatures
        for protection, signatures in protection_signatures.items():
            found_signatures = 0
            for signature in signatures:
                if signature in binary_data:
                    found_signatures += 1
                    results["indicators"].append(f"{protection} signature found: {signature}")

            if found_signatures > 0:
                confidence = min(found_signatures / len(signatures), 1.0)
                results["protections_found"].append(protection)
                results["confidence_scores"][protection] = confidence

        # Check section names for _protection indicators
        try:
            import pefile
            pe = pefile.PE(binary_path)

            protection_sections = {
                "UPX": ["UPX0", "UPX1", "UPX2"],
                "ASPack": [".aspack", ".adata"],
                "PECompact": [".pec1", ".pec2"],
                "Themida": [".themida", ".oreans"],
                "VMProtect": [".vmp0", ".vmp1", ".vmp2"],
            }

            section_names = [section.Name.decode('utf-8', errors='ignore').strip('\x00')
                           for section in pe.sections]

            for protection, sections in protection_sections.items():
                for section in sections:
                    if any(section.lower() in name.lower() for name in section_names):
                        if protection not in results["protections_found"]:
                            results["protections_found"].append(protection)
                        results["indicators"].append(f"{protection} section found: {section}")

            pe.close()

        except ImportError:
            logger.debug("pefile not available for section analysis")
        except (OSError, ValueError, RuntimeError) as e:
            logger.debug("PE analysis failed: %s", e)

        logger.info(f"Commercial protection detection complete: {len(results['protections_found'])} found")

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in commercial protection detection: %s", e)
        results["error"] = str(e)

    return results


def run_comprehensive_protection_scan(binary_path: str) -> Dict[str, Any]:
    """
    Run comprehensive protection scanning.

    Args:
        binary_path: Path to binary to analyze

    Returns:
        Comprehensive scan results
    """
    results = {
        "binary_path": binary_path,
        "total_protections": 0,
        "scan_results": {}
    }

    try:
        logger.info("Starting comprehensive protection scan: %s", binary_path)

        # Run virtualization detection
        vm_results = detect_virtualization_protection(binary_path)
        results["scan_results"]["virtualization"] = vm_results

        # Run commercial protection detection
        commercial_results = detect_commercial_protections(binary_path)
        results["scan_results"]["commercial"] = commercial_results

        # Run TPM detection
        try:
            from intellicrack.utils.system.process_utils import (
                detect_tpm_protection as detect_system_tpm,
            )
            tmp_results = detect_system_tpm()
            results["scan_results"]["tmp"] = tmp_results
        except ImportError:
            logger.debug("TPM detection not available")

        # Calculate total protections found
        total = 0
        if vm_results.get("virtualization_detected"):
            total += 1
        total += len(commercial_results.get("protections_found", []))

        results["total_protections"] = total

        logger.info("Comprehensive protection scan complete: %s protections found", total)

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in comprehensive protection scan: %s", e)
        results["error"] = str(e)

    return results


def generate_checksum(data: bytes, algorithm: str = "sha256") -> str:
    """
    Generate checksum for data.

    Args:
        data: Data to checksum
        algorithm: Hash algorithm to use

    Returns:
        Hex digest of checksum
    """
    try:
        hasher = hashlib.new(algorithm)
        hasher.update(data)
        return hasher.hexdigest()
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error generating checksum: %s", e)
        return ""


def detect_checksum_verification(binary_path: str) -> Dict[str, Any]:
    """
    Detect checksum verification in binary.

    Args:
        binary_path: Path to binary to analyze

    Returns:
        Detection results
    """
    results = {
        "checksum_verification_detected": False,
        "algorithms_found": [],
        "indicators": []
    }

    try:
        # Known checksum/hash function names
        hash_functions = [
            b"MD5", b"SHA1", b"SHA256", b"SHA512", b"CRC32",
            b"md5", b"sha1", b"sha256", b"sha512", b"crc32",
            b"HashData", b"CheckSum", b"VerifyHash", b"ComputeHash"
        ]

        with open(binary_path, 'rb') as f:
            binary_data = f.read()

        for hash_func in hash_functions:
            if hash_func in binary_data:
                results["checksum_verification_detected"] = True
                algo_name = hash_func.decode('utf-8', errors='ignore')
                if algo_name not in results["algorithms_found"]:
                    results["algorithms_found"].append(algo_name)
                results["indicators"].append(f"Hash function reference: {algo_name}")

        logger.info(f"Checksum verification detection: {results['checksum_verification_detected']}")

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error detecting checksum verification: %s", e)
        results["error"] = str(e)

    return results


def detect_self_healing_code(binary_path: str) -> Dict[str, Any]:
    """
    Detect self-healing/self-modifying code.

    Args:
        binary_path: Path to binary to analyze

    Returns:
        Detection results
    """
    results = {
        "self_healing_detected": False,
        "indicators": [],
        "techniques": []
    }

    try:
        # Indicators of self-modifying code
        self_mod_indicators = [
            b"VirtualProtect", b"VirtualAlloc", b"WriteProcessMemory",
            b"FlushInstructionCache", b"NtProtectVirtualMemory",
            b"mprotect", b"mmap", b"munmap"  # Linux equivalents
        ]

        with open(binary_path, 'rb') as f:
            binary_data = f.read()

        for indicator in self_mod_indicators:
            if indicator in binary_data:
                results["self_healing_detected"] = True
                func_name = indicator.decode('utf-8', errors='ignore')
                results["indicators"].append(f"Self-modification API: {func_name}")

                if "Protect" in func_name or "mprotect" in func_name:
                    results["techniques"].append("Memory protection modification")
                elif "Alloc" in func_name or "mmap" in func_name:
                    results["techniques"].append("Dynamic memory allocation")
                elif "Write" in func_name:
                    results["techniques"].append("Memory writing")

        logger.info(f"Self-healing code detection: {results['self_healing_detected']}")

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error detecting self-healing code: %s", e)
        results["error"] = str(e)

    return results


def detect_obfuscation(binary_path: str) -> Dict[str, Any]:
    """
    Detect code obfuscation techniques.

    Args:
        binary_path: Path to binary to analyze

    Returns:
        Detection results
    """
    results = {
        "obfuscation_detected": False,
        "techniques": [],
        "entropy_score": 0.0,
        "indicators": []
    }

    try:
        # Calculate entropy to detect obfuscation
        from intellicrack.core.analysis.core_analysis import calculate_entropy

        with open(binary_path, 'rb') as f:
            binary_data = f.read()

        entropy = calculate_entropy(binary_data)
        results["entropy_score"] = entropy

        if entropy > 7.5:
            results["obfuscation_detected"] = True
            results["techniques"].append("High entropy (likely packed/encrypted)")
            results["indicators"].append(f"High entropy score: {entropy:.2f}")

        # Check for _obfuscation indicators
        obfuscation_indicators = [
            b"GetProcAddress", b"LoadLibrary", b"VirtualAlloc",
            b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent",
            b"OutputDebugString", b"anti", b"debug", b"trace"
        ]

        api_count = 0
        for indicator in obfuscation_indicators:
            if indicator in binary_data:
                api_count += 1
                results["indicators"].append(f"Obfuscation API: {indicator.decode('utf-8', errors='ignore')}")

        if api_count > 3:
            results["obfuscation_detected"] = True
            results["techniques"].append("Anti-debugging APIs")

        logger.info(f"Obfuscation detection: {results['obfuscation_detected']}")

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error detecting obfuscation: %s", e)
        results["error"] = str(e)

    return results


def detect_anti_debugging_techniques(binary_path: str) -> Dict[str, Any]:
    """Detect anti-debugging techniques in binary.

    Args:
        binary_path: Path to binary to analyze

    Returns:
        Detection results including techniques found and confidence
    """
    results = {
        "anti_debug_detected": False,
        "techniques": [],
        "api_calls": [],
        "instructions": [],
        "indicators": [],
        "confidence": 0.0
    }

    try:
        if not os.path.exists(binary_path):
            return {"error": "Binary file not found"}

        # Anti-debugging API functions
        anti_debug_apis = [
            # Windows debugging APIs
            b"IsDebuggerPresent",
            b"CheckRemoteDebuggerPresent",
            b"NtQueryInformationProcess",
            b"NtSetInformationThread",
            b"OutputDebugString",
            b"NtQuerySystemInformation",
            b"GetTickCount",
            b"QueryPerformanceCounter",
            b"timeGetTime",
            b"rdtsc",
            # Linux/Unix debugging APIs
            b"ptrace",
            b"getppid",
            b"/proc/self/status",
            b"/proc/self/stat",
            b"/proc/self/cmdline"
        ]

        # Anti-debugging strings and indicators
        debug_strings = [
            b"debugger",
            b"IDA",
            b"OllyDbg",
            b"x64dbg",
            b"WinDbg",
            b"gdb",
            b"lldb",
            b"radare2",
            b"Immunity",
            b"SoftICE",
            b"SICE",
            b"ntice",
            b"iceext",
            b"Syser",
            b"TRW2000",
            b"Trace",
            b"debug"
        ]

        # Read binary data
        with open(binary_path, 'rb') as f:
            binary_data = f.read()

        # Check for anti-debugging APIs
        for anti_debug_api in anti_debug_apis:
            if anti_debug_api in binary_data:
                api_name = anti_debug_api.decode('utf-8', errors='ignore')
                results["api_calls"].append(api_name)
                results["indicators"].append(f"Anti-debug API found: {api_name}")
                results["anti_debug_detected"] = True

                # Categorize techniques
                if api_name in ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]:
                    if "Windows Debugger Detection" not in results["techniques"]:
                        results["techniques"].append("Windows Debugger Detection")
                elif api_name in ["GetTickCount", "QueryPerformanceCounter", "timeGetTime", "rdtsc"]:
                    if "Timing-based Detection" not in results["techniques"]:
                        results["techniques"].append("Timing-based Detection")
                elif api_name == "ptrace":
                    if "Linux ptrace Detection" not in results["techniques"]:
                        results["techniques"].append("Linux ptrace Detection")
                elif "NtQuery" in api_name or "NtSet" in api_name:
                    if "NT API Detection" not in results["techniques"]:
                        results["techniques"].append("NT API Detection")

        # Check for debugger strings
        for debug_string in debug_strings:
            if debug_string.lower() in binary_data.lower():
                str_name = debug_string.decode('utf-8', errors='ignore')
                results["indicators"].append(f"Debugger string found: {str_name}")
                if "Debugger Name Detection" not in results["techniques"]:
                    results["techniques"].append("Debugger Name Detection")
                results["anti_debug_detected"] = True

        # Check for specific x86/x64 anti-debugging instructions
        # INT 3 (CC) - Breakpoint instruction check
        int3_count = binary_data.count(b'\xCC')
        if int3_count > 50:  # Unusual number of INT3s
            results["instructions"].append("INT 3 flooding")
            results["indicators"].append(f"High INT3 count: {int3_count}")
            results["techniques"].append("INT3 Detection")
            results["anti_debug_detected"] = True

        # INT 2D (anti-debug interrupt)
        if b'\xCD\x2D' in binary_data:
            results["instructions"].append("INT 2D")
            results["indicators"].append("INT 2D anti-debug interrupt found")
            results["techniques"].append("INT 2D Detection")
            results["anti_debug_detected"] = True

        # Check for PEB access patterns (Windows)
        peb_patterns = [
            b'\x64\xA1\x30\x00\x00\x00',  # mov eax, fs:[30h] - 32-bit PEB
            b'\x65\x48\x8B\x04\x25\x60\x00\x00\x00',  # mov rax, gs:[60h] - 64-bit PEB
        ]

        for peb_pattern in peb_patterns:
            if peb_pattern in binary_data:
                results["instructions"].append("PEB Access")
                results["indicators"].append("Direct PEB access for debugger detection")
                if "PEB BeingDebugged Check" not in results["techniques"]:
                    results["techniques"].append("PEB BeingDebugged Check")
                results["anti_debug_detected"] = True

        # Check for exception-based anti-debugging
        exception_apis = [
            b"SetUnhandledExceptionFilter",
            b"RaiseException",
            b"__try",
            b"__except"
        ]

        exception_count = 0
        for exception_api in exception_apis:
            if exception_api in binary_data:
                exception_count += 1
                results["indicators"].append(f"Exception handling API: {exception_api.decode('utf-8', errors='ignore')}")

        if exception_count >= 2:
            results["techniques"].append("Exception-based Detection")
            results["anti_debug_detected"] = True

        # Check for hardware breakpoint detection
        if b"GetThreadContext" in binary_data or b"SetThreadContext" in binary_data:
            results["techniques"].append("Hardware Breakpoint Detection")
            results["indicators"].append("Thread context manipulation for DR register checking")
            results["anti_debug_detected"] = True

        # Calculate confidence based on findings
        if results["anti_debug_detected"]:
            # Base confidence on number and variety of techniques
            technique_score = len(results["techniques"]) * 0.15
            api_score = len(results["api_calls"]) * 0.05
            indicator_score = len(results["indicators"]) * 0.02

            results["confidence"] = min(technique_score + api_score + indicator_score, 1.0)

        # Try PE analysis for more detailed checks
        try:
            import pefile
            pe = pefile.PE(binary_path)

            # Check TLS callbacks (often used for anti-debugging)
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                results["techniques"].append("TLS Callback Detection")
                results["indicators"].append("TLS callbacks present (common anti-debug location)")
                results["anti_debug_detected"] = True

            pe.close()

        except ImportError:
            logger.debug("pefile not available for detailed PE analysis")
        except (OSError, ValueError, RuntimeError) as e:
            logger.debug("PE analysis failed: %s", e)

        logger.info(f"Anti-debugging detection complete: {results['anti_debug_detected']}")

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in anti-debugging detection: %s", e)
        results["error"] = str(e)

    return results


def scan_for_bytecode_protectors(binary_path):
    """Scan for bytecode protectors."""
    import time

    from .protection_utils import calculate_entropy

    results = {}

    try:
        # Define signatures for known protectors
        protector_signatures = {
            "Themida/WinLicense": {
                "patterns": [b"Themida", b"WinLicense"],
                "sections": [".themida", ".winlic"],
            },
            "VMProtect": {
                "patterns": [b"VMProtect", b"vmp"],
                "sections": [".vmp", "vmp"],
            },
            "Enigma": {
                "patterns": [b"Enigma"],
                "sections": [".enigma"],
            },
            "ASProtect": {
                "patterns": [b"ASProtect"],
                "sections": [".aspr"],
            },
            "Armadillo": {
                "patterns": [b"Armadillo", b"SLVcop"],
                "sections": [".rlp", ".tls"],
            },
            "PELock": {
                "patterns": [b"PELock"],
                "sections": [".pelock"],
            },
            "Obsidium": {
                "patterns": [b"Obsidium"],
                "sections": [".obsidium"],
            },
            "EXECryptor": {
                "patterns": [b"ExeCryptor"],
                "sections": [".exeenc"],
            }
        }

        try:
            import pefile
            pe = pefile.PE(binary_path)
        except ImportError:
            logger.warning("pefile not available, using fallback detection")
            pe = None

        # Check section names if PE parsing is available
        section_names = []
        high_entropy_sections = []

        if pe:
            section_names = [
                pe_section.Name.decode('utf-8', 'ignore').strip('\x00')
                for pe_section in pe.sections
            ]

            # Check for high entropy sections (common in packed/protected executables)
            for pe_section in pe.sections:
                section_name = pe_section.Name.decode('utf-8', 'ignore').strip('\x00')
                section_data = pe_section.get_data()
                entropy = calculate_entropy(section_data)

                if entropy > 7.0:
                    high_entropy_sections.append((section_name, entropy))

        # Read full binary data for pattern matching
        with open(binary_path, "rb") as f:
            binary_data = f.read()

        # Check each protector's signatures
        for protector_name, signature in protector_signatures.items():
            detected = False
            detection_info = {"detected": False}

            # Check for patterns in binary
            for sig_pattern in signature["patterns"]:
                if sig_pattern.lower() in binary_data.lower():
                    detected = True
                    detection_info["detected"] = True
                    detection_info["signature"] = sig_pattern.decode('utf-8', 'ignore')
                    break

            # Check for specific sections
            for sig_section in signature["sections"]:
                if any(sig_section.lower() in s.lower() for s in section_names):
                    detected = True
                    detection_info["detected"] = True
                    detection_info["section_name"] = sig_section

                    # Find section and calculate entropy if PE parsing is available
                    if pe:
                        matching_section = next(
                            (s for s in pe.sections if sig_section.lower() in s.Name.decode(
                                'utf-8', 'ignore').strip('\x00').lower()), None)
                        if matching_section:
                            entropy = calculate_entropy(matching_section.get_data())
                            detection_info["section_entropy"] = entropy

                    break

            # Add detailed detection information based on detected status
            if detected:
                # Add when the detection happened
                detection_info["detection_time"] = time.strftime('%Y-%m-%d %H:%M:%S')

                if "detection_stats" not in results:
                    results["detection_stats"] = {}
                if protector_name not in results["detection_stats"]:
                    results["detection_stats"][protector_name] = 0
                results["detection_stats"][protector_name] += 1

                # Add confidence level based on what triggered the detection
                if "signature" in detection_info and "section_name" in detection_info:
                    detection_info["confidence"] = "High"  # Both pattern and section found
                elif "signature" in detection_info:
                    detection_info["confidence"] = "Medium"  # Only pattern found
                elif "section_name" in detection_info:
                    detection_info["confidence"] = "Medium"  # Only section found
                else:
                    detection_info["confidence"] = "Low"  # Other detection method

            results[protector_name] = detection_info

        # Additional generic detection based on entropy
        if high_entropy_sections and not any(
                result_info.get("detected", False) for result_info in results.values()):
            results["Generic Packer/Protector"] = {
                "detected": True,
                "note": "High entropy sections detected, possible unknown protector",
                "high_entropy_sections": high_entropy_sections
            }

        # Additional checks for specific protectors
        if pe and hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            try:
                import_entries = getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
                for entry in import_entries:
                    dll_name = entry.dll.decode('utf-8', 'ignore').lower()
                    if "securengine" in dll_name:
                        if "Themida/WinLicense" not in results:
                            results["Themida/WinLicense"] = {"detected": False}
                        results["Themida/WinLicense"]["detected"] = True
                        results["Themida/WinLicense"]["import"] = dll_name
            except (OSError, ValueError, RuntimeError) as e:
                logger.warning("Error checking imports: %s", e)

    except (OSError, ValueError, RuntimeError) as e:
        results["error"] = str(e)
        logger.error("Error scanning for bytecode protectors: %s", e)

    return results


def detect_protection_mechanisms(binary_path: str) -> Dict[str, Any]:
    """Detect various protection mechanisms in a binary."""
    return run_comprehensive_protection_scan(binary_path)


def detect_packing_methods(binary_path: str) -> Dict[str, Any]:
    """Detect packing methods in a binary."""
    return scan_for_bytecode_protectors(binary_path)


def detect_all_protections(binary_path: str) -> Dict[str, Any]:
    """Detect all types of protections in a binary."""
    return run_comprehensive_protection_scan(binary_path)


def detect_anti_debug(binary_path: str) -> Dict[str, Any]:
    """Detect anti-debugging techniques in a binary."""
    return detect_anti_debugging_techniques(binary_path)


def detect_commercial_protectors(binary_path: str) -> Dict[str, Any]:
    """Detect commercial protectors in a binary."""
    return detect_commercial_protections(binary_path)


def detect_tpm_protection(binary_path: str) -> Dict[str, Any]:
    """Detect TPM-based protection in a binary."""
    results = {
        "tpm_detected": False,
        "indicators": [],
        "confidence": "Low"
    }

    try:
        with open(binary_path, 'rb') as f:
            data = f.read()

        tpm_indicators = [
            b"TPM",
            b"Trusted Platform Module",
            b"TrEE",
            b"tpm.dll",
            b"TBS.dll",
            b"Ncrypt.dll"
        ]

        for tpm_indicator in tpm_indicators:
            if tpm_indicator in data:
                results["tpm_detected"] = True
                results["indicators"].append(tpm_indicator.decode('utf-8', 'ignore'))
                results["confidence"] = "Medium"

    except (OSError, ValueError, RuntimeError) as e:
        results["error"] = str(e)
        logger.error("Error detecting TPM protection: %s", e)

    return results


def detect_anti_debugging(binary_path: str) -> Dict[str, Any]:
    """Alias for detect_anti_debugging_techniques."""
    return detect_anti_debugging_techniques(binary_path)


def detect_vm_detection(binary_path: str) -> Dict[str, Any]:
    """Detect VM detection techniques in a binary."""
    return detect_virtualization_protection(binary_path)


def detect_self_healing(binary_path: str) -> Dict[str, Any]:
    """Alias for detect_self_healing_code."""
    return detect_self_healing_code(binary_path)


# Export all functions
__all__ = [
    'detect_virtualization_protection',
    'detect_commercial_protections',
    'run_comprehensive_protection_scan',
    'generate_checksum',
    'detect_checksum_verification',
    'detect_self_healing_code',
    'detect_obfuscation',
    'detect_anti_debugging_techniques',
    'scan_for_bytecode_protectors',
    'detect_protection_mechanisms',
    'detect_packing_methods',
    'detect_all_protections',
    'detect_anti_debug',
    'detect_commercial_protectors',
    'detect_tpm_protection',
    'detect_anti_debugging',
    'detect_vm_detection',
]
