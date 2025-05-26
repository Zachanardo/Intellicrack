"""
Protection detection utilities for Intellicrack.

This module provides functions for detecting various software protections,
commercial protectors, and anti-analysis techniques.
"""

import os
import sys
import logging
import hashlib
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


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
    
    try:
        # Check for known VM detection techniques
        vm_indicators = [
            "VirtualBox", "VMware", "QEMU", "Xen", "Hyper-V",
            "vbox", "vmtoolsd", "vmwareuser", "qemu-ga"
        ]
        
        # Check running processes (if possible)
        try:
            import psutil
            running_processes = [p.info['name'].lower() for p in psutil.process_iter(['name']) if p.info['name']]
            
            for indicator in vm_indicators:
                if any(indicator.lower() in proc for proc in running_processes):
                    results["indicators"].append(f"VM process detected: {indicator}")
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
                
                for key_path in vm_registry_keys:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                        results["indicators"].append(f"VM registry key found: {key_path}")
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
            "C:\\Windows\\System32\\drivers\\vboxguest.sys",  # Windows VirtualBox
            "C:\\Windows\\System32\\drivers\\vmhgfs.sys",  # Windows VMware
        ]
        
        for vm_file in vm_files:
            if os.path.exists(vm_file):
                try:
                    with open(vm_file, 'r', errors='ignore') as f:
                        content = f.read().lower()
                        for indicator in vm_indicators:
                            if indicator.lower() in content:
                                results["indicators"].append(f"VM indicator in {vm_file}: {indicator}")
                                results["virtualization_detected"] = True
                except:
                    pass
        
        # Calculate confidence
        if results["virtualization_detected"]:
            results["confidence"] = min(len(results["indicators"]) * 0.3, 1.0)
            results["protection_types"].append("VM Detection")
        
        logger.info(f"Virtualization detection complete: {results['virtualization_detected']}")
        
    except Exception as e:
        logger.error(f"Error in virtualization detection: {e}")
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
        
        # Check section names for protection indicators
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
        except Exception as e:
            logger.debug(f"PE analysis failed: {e}")
        
        logger.info(f"Commercial protection detection complete: {len(results['protections_found'])} found")
        
    except Exception as e:
        logger.error(f"Error in commercial protection detection: {e}")
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
        logger.info(f"Starting comprehensive protection scan: {binary_path}")
        
        # Run virtualization detection
        vm_results = detect_virtualization_protection(binary_path)
        results["scan_results"]["virtualization"] = vm_results
        
        # Run commercial protection detection
        commercial_results = detect_commercial_protections(binary_path)
        results["scan_results"]["commercial"] = commercial_results
        
        # Run TPM detection
        try:
            from intellicrack.utils.process_utils import detect_tpm_protection
            tpm_results = detect_tpm_protection()
            results["scan_results"]["tpm"] = tmp_results
        except ImportError:
            logger.debug("TPM detection not available")
        
        # Calculate total protections found
        total = 0
        if vm_results.get("virtualization_detected"):
            total += 1
        total += len(commercial_results.get("protections_found", []))
        
        results["total_protections"] = total
        
        logger.info(f"Comprehensive protection scan complete: {total} protections found")
        
    except Exception as e:
        logger.error(f"Error in comprehensive protection scan: {e}")
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
    except Exception as e:
        logger.error(f"Error generating checksum: {e}")
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
        
    except Exception as e:
        logger.error(f"Error detecting checksum verification: {e}")
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
        
    except Exception as e:
        logger.error(f"Error detecting self-healing code: {e}")
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
        
        # Check for obfuscation indicators
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
        
    except Exception as e:
        logger.error(f"Error detecting obfuscation: {e}")
        results["error"] = str(e)
    
    return results


def scan_for_bytecode_protectors(binary_path):
    """Scan for bytecode protectors."""
    import time
    from .binary_utils import calculate_entropy
    
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
                section.Name.decode('utf-8', 'ignore').strip('\x00') 
                for section in pe.sections
            ]

            # Check for high entropy sections (common in packed/protected executables)
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                section_data = section.get_data()
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
            for pattern in signature["patterns"]:
                if pattern.lower() in binary_data.lower():
                    detected = True
                    detection_info["detected"] = True
                    detection_info["signature"] = pattern.decode('utf-8', 'ignore')
                    break

            # Check for specific sections
            for section in signature["sections"]:
                if any(section.lower() in s.lower() for s in section_names):
                    detected = True
                    detection_info["detected"] = True
                    detection_info["section_name"] = section

                    # Find section and calculate entropy if PE parsing is available
                    if pe:
                        matching_section = next(
                            (s for s in pe.sections if section.lower() in s.Name.decode(
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
                info.get("detected", False) for info in results.values()):
            results["Generic Packer/Protector"] = {
                "detected": True,
                "note": "High entropy sections detected, possible unknown protector",
                "high_entropy_sections": high_entropy_sections
            }

        # Additional checks for specific protectors
        if pe and hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            try:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', 'ignore').lower()
                    if "securengine" in dll_name:
                        if "Themida/WinLicense" not in results:
                            results["Themida/WinLicense"] = {"detected": False}
                        results["Themida/WinLicense"]["detected"] = True
                        results["Themida/WinLicense"]["import"] = dll_name
            except Exception as e:
                logger.warning(f"Error checking imports: {e}")

    except Exception as e:
        results["error"] = str(e)
        logger.error(f"Error scanning for bytecode protectors: {e}")

    return results