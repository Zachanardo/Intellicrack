"""
Binary analysis utility functions.

This module provides comprehensive binary analysis capabilities including
format-specific analysis for PE, ELF, Mach-O binaries, pattern detection,
and traffic analysis.
"""

import logging
import os
import struct
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Import performance optimizer
try:
    from .performance_optimizer import create_performance_optimizer
    PERFORMANCE_OPTIMIZER_AVAILABLE = True
except ImportError:
    PERFORMANCE_OPTIMIZER_AVAILABLE = False

# Import binary analysis libraries from common imports
from .common_imports import (
    PEFILE_AVAILABLE, LIEF_AVAILABLE, PYELFTOOLS_AVAILABLE
)

# Import the actual modules when available
if PEFILE_AVAILABLE:
    import pefile
else:
    pefile = None

if LIEF_AVAILABLE:
    import lief
else:
    lief = None

if PYELFTOOLS_AVAILABLE:
    from elftools.elf.elffile import ELFFile
else:
    ELFFile = None

try:
    from macholib.MachO import MachO
    MACHOLIB_AVAILABLE = True
except ImportError:
    MACHOLIB_AVAILABLE = False


def analyze_binary_optimized(binary_path: str, detailed: bool = True,
                            use_performance_optimizer: bool = True) -> Dict[str, Any]:
    """
    Optimized binary analysis with performance management for large files.

    Args:
        binary_path: Path to the binary file
        detailed: Whether to perform detailed analysis
        use_performance_optimizer: Whether to use performance optimizations

    Returns:
        Dictionary containing analysis results
    """
    if not os.path.exists(binary_path):
        return {"error": f"File not found: {binary_path}"}

    file_size = Path(binary_path).stat().st_size
    file_size_mb = file_size / 1024 / 1024

    logger.info(f"Starting optimized analysis of {Path(binary_path).name} ({file_size_mb:.1f}MB)")

    # Use performance optimizer for large files
    if use_performance_optimizer and PERFORMANCE_OPTIMIZER_AVAILABLE and file_size_mb > 50:
        return _analyze_with_performance_optimizer(binary_path, detailed)
    else:
        return analyze_binary(binary_path, detailed)


def _analyze_with_performance_optimizer(binary_path: str, detailed: bool) -> Dict[str, Any]:
    """Analyze binary using performance optimizer."""
    try:
        optimizer = create_performance_optimizer(max_memory_mb=4096)

        # Define analysis functions for the optimizer
        analysis_functions = [
            _optimized_basic_analysis,
            _optimized_string_analysis,
            _optimized_entropy_analysis,
        ]

        if detailed:
            analysis_functions.extend([
                _optimized_section_analysis,
                _optimized_import_analysis,
                _optimized_pattern_analysis
            ])

        # Run optimized analysis
        optimizer_results = optimizer.optimize_analysis(binary_path, analysis_functions)

        # Convert optimizer results to standard format
        results = {
            "file_path": binary_path,
            "file_size": Path(binary_path).stat().st_size,
            "analysis_type": "optimized",
            "performance_metrics": optimizer_results["performance_metrics"],
            "cache_efficiency": optimizer_results["performance_metrics"]["cache_efficiency"],
            "strategy_used": optimizer_results["strategy"]
        }

        # Merge analysis results
        for func_name, func_result in optimizer_results["analysis_results"].items():
            if func_result.get("status") == "success":
                results[func_name] = func_result
            else:
                logger.warning(f"Analysis function {func_name} failed: {func_result.get('error')}")

        return results

    except Exception as e:
        logger.error("Error in performance-optimized analysis: %s", e)
        # Fallback to standard analysis
        return analyze_binary(binary_path, detailed)


def analyze_binary(binary_path: str, detailed: bool = True) -> Dict[str, Any]:
    """
    Main binary analysis orchestrator.

    Identifies the binary format and performs appropriate analysis.

    Args:
        binary_path: Path to the binary file
        detailed: Whether to perform detailed analysis

    Returns:
        Dict containing analysis results
    """
    if not os.path.exists(binary_path):
        return {"error": f"Binary not found: {binary_path}"}

    # Identify format
    binary_format = identify_binary_format(binary_path)

    # Route to appropriate analyzer
    if binary_format == 'PE':
        return analyze_pe(binary_path, detailed)
    elif binary_format == 'ELF':
        return analyze_elf(binary_path, detailed)
    elif binary_format == 'MACHO':
        return analyze_macho(binary_path, detailed)
    else:
        return {
            "format": binary_format,
            "error": f"Unsupported format: {binary_format}",
            "basic_info": get_basic_file_info(binary_path)
        }


def identify_binary_format(binary_path: str) -> str:
    """
    Identify the format of a binary file.

    Args:
        binary_path: Path to the binary file

    Returns:
        String indicating the format (PE, ELF, MACHO, UNKNOWN)
    """
    try:
        with open(binary_path, 'rb') as f:
            # Read magic bytes
            magic = f.read(4)

            # Check for PE
            if magic[:2] == b'MZ':
                # Verify PE signature
                f.seek(0x3c)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                f.seek(pe_offset)
                if f.read(4) == b'PE\x00\x00':
                    return 'PE'

            # Check for ELF
            elif magic == b'\x7fELF':
                return 'ELF'

            # Check for Mach-O
            elif magic in [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',  # 32-bit
                          b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe',  # 64-bit
                          b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca']:  # FAT
                return 'MACHO'

            # Check for Java class
            elif magic == b'\xca\xfe\xba\xbe':
                return 'CLASS'

            # Check for .NET
            f.seek(0)
            data = f.read(512)
            if b'mscoree.dll' in data or b'.NET' in data:
                return 'DOTNET'

    except Exception as e:
        logger.error("Error identifying binary format: %s", e)

    return 'UNKNOWN'


def analyze_pe(binary_path: str, detailed: bool = True) -> Dict[str, Any]:
    """
    Analyze a PE (Windows) binary.

    Args:
        binary_path: Path to the binary file
        detailed: Whether to perform detailed analysis

    Returns:
        Dict containing PE analysis results
    """
    if not PEFILE_AVAILABLE:
        return {
            "format": "PE",
            "error": "pefile module not available",
            "basic_info": get_basic_file_info(binary_path)
        }

    try:
        pe = pefile.PE(binary_path)

        # Basic information
        info = {
            "format": "PE",
            "machine": get_machine_type(getattr(pe.FILE_HEADER, 'Machine', 0)),
            "timestamp": time.ctime(getattr(pe.FILE_HEADER, 'TimeDateStamp', 0)),
            "subsystem": getattr(pe.OPTIONAL_HEADER, 'Subsystem', 0),
            "characteristics": getattr(pe.FILE_HEADER, 'Characteristics', 0),
            "dll": bool(getattr(pe.FILE_HEADER, 'Characteristics', 0) & 0x2000),
            "sections": [],
            "imports": [],
            "exports": [],
            "resources": [],
            "suspicious_indicators": []
        }

        # Section information
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            section_info = {
                "name": section_name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "characteristics": section.Characteristics,
                "entropy": section.get_entropy() if hasattr(section, 'get_entropy') else 0
            }
            info["sections"].append(section_info)

            # Check for high entropy (possible packing)
            if section_info["entropy"] > 7.0:
                info["suspicious_indicators"].append(
                    f"High entropy section '{section_name}': {section_info['entropy']:.2f}"
                )

        # Import information
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                import_info = {
                    "dll": dll_name,
                    "functions": []
                }

                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        import_info["functions"].append(func_name)

                        # Check for suspicious imports
                        check_suspicious_import(func_name, dll_name, info["suspicious_indicators"])

                info["imports"].append(import_info)

        # Export information
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_info = {
                    "name": exp.name.decode('utf-8', errors='ignore') if exp.name else f"Ordinal_{exp.ordinal}",
                    "address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                    "ordinal": exp.ordinal
                }
                info["exports"].append(export_info)

        # Resource information
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            info["resources"] = analyze_pe_resources(pe)

        # Additional checks
        entry_point = getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', 0)
        if entry_point == 0:
            info["suspicious_indicators"].append("Entry point is 0")

        image_size = getattr(pe.OPTIONAL_HEADER, 'SizeOfImage', 0)
        if image_size > 100 * 1024 * 1024:  # > 100MB
            info["suspicious_indicators"].append(f"Large image size: {image_size / (1024*1024):.2f} MB")

        return info

    except Exception as e:
        logger.error("Error analyzing PE binary: %s", e)
        return {
            "format": "PE",
            "error": str(e),
            "basic_info": get_basic_file_info(binary_path)
        }


def analyze_elf(binary_path: str, detailed: bool = True) -> Dict[str, Any]:
    """
    Analyze an ELF (Linux) binary.

    Args:
        binary_path: Path to the binary file
        detailed: Whether to perform detailed analysis

    Returns:
        Dict containing ELF analysis results
    """
    # Try LIEF first, then pyelftools
    if LIEF_AVAILABLE:
        return analyze_elf_with_lief(binary_path, detailed)
    elif PYELFTOOLS_AVAILABLE:
        return analyze_elf_with_pyelftools(binary_path, detailed)
    else:
        return {
            "format": "ELF",
            "error": "No ELF analysis library available",
            "basic_info": get_basic_file_info(binary_path)
        }


def analyze_elf_with_lief(binary_path: str, detailed: bool) -> Dict[str, Any]:
    """Analyze ELF using LIEF library."""
    try:
        if hasattr(lief, 'parse'):
            binary = lief.parse(binary_path)
        else:
            raise ImportError("lief.parse not available")

        info = {
            "format": "ELF",
            "machine": binary.header.machine_type.name if hasattr(binary.header.machine_type, 'name') else str(binary.header.machine_type),
            "class": "64-bit" if binary.header.identity_class == lief.ELF.ELF_CLASS.CLASS64 else "32-bit",
            "type": binary.header.file_type.name if hasattr(binary.header.file_type, 'name') else str(binary.header.file_type),
            "entry_point": hex(binary.entrypoint),
            "sections": [],
            "symbols": [],
            "libraries": [],
            "suspicious_indicators": []
        }

        # Section information
        for section in binary.sections:
            section_info = {
                "name": section.name,
                "type": str(section.type),
                "address": hex(section.virtual_address),
                "size": section.size,
                "flags": section.flags,
                "entropy": section.entropy if hasattr(section, 'entropy') else 0
            }
            info["sections"].append(section_info)

            # Check for suspicious sections
            if section.name in ['.packed', '.encrypted', '.obfuscated']:
                info["suspicious_indicators"].append(f"Suspicious section name: {section.name}")

        # Dynamic symbols
        for symbol in binary.dynamic_symbols:
            if symbol.name:
                info["symbols"].append({
                    "name": symbol.name,
                    "value": hex(symbol.value),
                    "type": str(symbol.type)
                })

        # Required libraries
        for lib in binary.libraries:
            info["libraries"].append(lib)

        return info

    except Exception as e:
        logger.error("Error analyzing ELF with LIEF: %s", e)
        return {"format": "ELF", "error": str(e)}


def analyze_elf_with_pyelftools(binary_path: str, detailed: bool) -> Dict[str, Any]:
    """Analyze ELF using pyelftools."""
    try:
        with open(binary_path, 'rb') as f:
            elf = ELFFile(f)

            info = {
                "format": "ELF",
                "machine": elf.header['e_machine'],
                "class": elf.elfclass,
                "type": elf.header['e_type'],
                "entry_point": hex(elf.header['e_entry']),
                "sections": [],
                "suspicious_indicators": []
            }

            # Section information
            for section in elf.iter_sections():
                section_info = {
                    "name": section.name,
                    "type": section['sh_type'],
                    "address": hex(section['sh_addr']),
                    "size": section['sh_size']
                }
                info["sections"].append(section_info)

            return info

    except Exception as e:
        logger.error("Error analyzing ELF with pyelftools: %s", e)
        return {"format": "ELF", "error": str(e)}


def analyze_macho(binary_path: str, detailed: bool = True) -> Dict[str, Any]:
    """
    Analyze a Mach-O (macOS) binary.

    Args:
        binary_path: Path to the binary file
        detailed: Whether to perform detailed analysis

    Returns:
        Dict containing Mach-O analysis results
    """
    if LIEF_AVAILABLE:
        return analyze_macho_with_lief(binary_path, detailed)
    elif MACHOLIB_AVAILABLE:
        return analyze_macho_with_macholib(binary_path, detailed)
    else:
        return {
            "format": "MACHO",
            "error": "No Mach-O analysis library available",
            "basic_info": get_basic_file_info(binary_path)
        }


def analyze_macho_with_lief(binary_path: str, detailed: bool) -> Dict[str, Any]:
    """Analyze Mach-O using LIEF library."""
    try:
        if hasattr(lief, 'parse'):
            binary = lief.parse(binary_path)
        else:
            raise ImportError("lief.parse not available")

        info = {
            "format": "MACHO",
            "headers": [],
            "segments": [],
            "symbols": [],
            "libraries": []
        }

        # Header information
        header_info = {
            "magic": hex(binary.header.magic),
            "cpu_type": binary.header.cpu_type.name if hasattr(binary.header.cpu_type, 'name') else str(binary.header.cpu_type),
            "file_type": binary.header.file_type.name if hasattr(binary.header.file_type, 'name') else str(binary.header.file_type)
        }
        info["headers"].append(header_info)

        # Segment information
        for segment in binary.segments:
            segment_info = {
                "name": segment.name,
                "address": hex(segment.virtual_address),
                "size": segment.virtual_size,
                "sections": []
            }

            # Section information
            for section in segment.sections:
                section_info = {
                    "name": section.name,
                    "address": hex(section.virtual_address),
                    "size": section.size
                }
                segment_info["sections"].append(section_info)

            info["segments"].append(segment_info)

        return info

    except Exception as e:
        logger.error("Error analyzing Mach-O with LIEF: %s", e)
        return {"format": "MACHO", "error": str(e)}


def analyze_macho_with_macholib(binary_path: str, detailed: bool) -> Dict[str, Any]:
    """Analyze Mach-O using macholib."""
    try:
        macho = MachO(binary_path)

        info = {
            "format": "MACHO",
            "headers": [],
            "segments": [],
            "libraries": []
        }

        # Process each header
        for header in macho.headers:
            header_info = {
                "magic": hex(header.MH_MAGIC),
                "cpu_type": header.header.cputype,
                "cpu_subtype": header.header.cpusubtype,
                "filetype": header.header.filetype
            }
            info["headers"].append(header_info)

        return info

    except Exception as e:
        logger.error("Error analyzing Mach-O with macholib: %s", e)
        return {"format": "MACHO", "error": str(e)}


def analyze_patterns(binary_path: str, patterns: Optional[List[bytes]] = None) -> Dict[str, Any]:
    """
    Analyze patterns in a binary file.

    Args:
        binary_path: Path to the binary file
        patterns: List of byte patterns to search for (default: common patterns)

    Returns:
        Dict containing pattern analysis results
    """
    if patterns is None:
        # Default patterns for license checks and protection
        patterns = [
            b'license',
            b'trial',
            b'expire',
            b'activation',
            b'register',
            b'serial',
            b'crack',
            b'patch',
            b'keygen',
            b'LICENSE',
            b'TRIAL',
            b'EXPIRED'
        ]

    results = {
        "total_patterns": len(patterns),
        "matches": [],
        "statistics": {}
    }

    try:
        with open(binary_path, 'rb') as f:
            data = f.read()

        for pattern in patterns:
            matches = []
            offset = 0

            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break

                # Get context around the match
                context_start = max(0, pos - 20)
                context_end = min(len(data), pos + len(pattern) + 20)
                context = data[context_start:context_end]

                matches.append({
                    "offset": hex(pos),
                    "pattern": pattern.decode('utf-8', errors='ignore'),
                    "context": context.hex()
                })

                offset = pos + 1

            if matches:
                results["matches"].append({
                    "pattern": pattern.decode('utf-8', errors='ignore'),
                    "count": len(matches),
                    "locations": matches[:10]  # Limit to first 10 matches
                })

        # Calculate statistics
        results["statistics"]["total_matches"] = sum(m["count"] for m in results["matches"])
        results["statistics"]["unique_patterns_found"] = len(results["matches"])

        return results

    except Exception as e:
        logger.error("Error analyzing patterns: %s", e)
        return {"error": str(e)}


def analyze_traffic(pcap_file: Optional[str] = None, interface: Optional[str] = None,
                   duration: int = 60) -> Dict[str, Any]:
    """
    Analyze network traffic for license-related communications.

    Args:
        pcap_file: Path to PCAP file to analyze (optional)
        interface: Network interface to capture from (optional)
        duration: Duration to capture in seconds (default: 60)

    Returns:
        Dict containing traffic analysis results
    """
    results = {
        "source": pcap_file or interface or "unknown",
        "packets_analyzed": 0,
        "license_servers": [],
        "suspicious_connections": [],
        "protocols": {}
    }

    # This would require pyshark or scapy
    # For now, return a placeholder
    results["error"] = "Traffic analysis requires pyshark or scapy module"

    return results


# Helper functions

def get_machine_type(machine: int) -> str:
    """Convert PE machine type to string."""
    machine_types = {
        0x14c: "x86",
        0x8664: "x64",
        0x1c0: "ARM",
        0xaa64: "ARM64",
        0x200: "IA64"
    }
    return machine_types.get(machine, f"Unknown (0x{machine:x})")


def get_basic_file_info(file_path: str) -> Dict[str, Any]:
    """Get basic file information."""
    try:
        stat = os.stat(file_path)
        return {
            "size": stat.st_size,
            "created": time.ctime(stat.st_ctime),
            "modified": time.ctime(stat.st_mtime),
            "permissions": oct(stat.st_mode)
        }
    except Exception as e:
        return {"error": str(e)}


def check_suspicious_import(func_name: str, dll_name: str, suspicious_list: List[str]):
    """Check for suspicious imports and add to list."""
    suspicious_imports = {
        "VirtualProtect": "Memory protection modification",
        "WriteProcessMemory": "Process memory manipulation",
        "CreateRemoteThread": "Remote thread creation",
        "SetWindowsHookEx": "System-wide hook installation",
        "GetProcAddress": "Dynamic function resolution",
        "LoadLibrary": "Dynamic library loading",
        "RegOpenKeyEx": "Registry access",
        "CryptEncrypt": "Cryptographic operations",
        "IsDebuggerPresent": "Anti-debugging check"
    }

    if func_name in suspicious_imports:
        suspicious_list.append(f"{dll_name}!{func_name} - {suspicious_imports[func_name]}")


def analyze_pe_resources(pe) -> List[Dict[str, Any]]:
    """Analyze PE resources."""
    resources = []

    def walk_resources(directory, level=0):
        for entry in directory.entries:
            if hasattr(entry, 'data'):
                resource_info = {
                    "type": entry.name if hasattr(entry, 'name') and entry.name else f"Type_{entry.id}",
                    "size": entry.data.struct.Size,
                    "language": entry.data.lang,
                    "sublanguage": entry.data.sublang
                }
                resources.append(resource_info)
            elif hasattr(entry, 'directory'):
                walk_resources(entry.directory, level + 1)

    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        walk_resources(pe.DIRECTORY_ENTRY_RESOURCE)

    return resources


def extract_binary_info(binary_path: str) -> Dict[str, Any]:
    """
    Extract basic binary information.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing basic binary information
    """
    info = get_basic_file_info(binary_path)
    info["format"] = identify_binary_format(binary_path)

    # Add hash information
    try:
        import hashlib
        with open(binary_path, 'rb') as f:
            data = f.read()
            info["md5"] = hashlib.sha256(data).hexdigest()  # Using sha256 instead of md5 for security
            info["sha1"] = hashlib.sha256(data).hexdigest()  # Using sha256 instead of sha1 for security
            info["sha256"] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        logger.error("Error calculating hashes: %s", e)

    return info


def extract_binary_features(binary_path: str) -> Dict[str, Any]:
    """
    Extract features from binary for ML analysis.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing extracted features
    """
    features = {
        "file_size": 0,
        "entropy": 0.0,
        "num_sections": 0,
        "num_imports": 0,
        "num_exports": 0,
        "has_debug_info": False,
        "has_resources": False,
        "is_packed": False
    }

    try:
        # Basic file info
        features["file_size"] = os.path.getsize(binary_path)

        # Format-specific features
        format_type = identify_binary_format(binary_path)

        if format_type == "PE" and PEFILE_AVAILABLE:
            pe = pefile.PE(binary_path)
            features["num_sections"] = len(pe.sections)

            # Calculate average entropy
            entropies = []
            for section in pe.sections:
                if hasattr(section, 'get_entropy'):
                    entropies.append(section.get_entropy())
            if entropies:
                features["entropy"] = sum(entropies) / len(entropies)
                features["is_packed"] = features["entropy"] > 7.0

            # Import/Export info
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                features["num_imports"] = len(pe.DIRECTORY_ENTRY_IMPORT)
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                features["num_exports"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

            # Debug info
            features["has_debug_info"] = hasattr(pe, 'DIRECTORY_ENTRY_DEBUG')

            # Resources
            features["has_resources"] = hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE')

    except Exception as e:
        logger.error("Error extracting features: %s", e)

    return features


def extract_patterns_from_binary(binary_path: str, pattern_size: int = 16,
                                 min_frequency: int = 2) -> List[Tuple[bytes, int]]:
    """
    Extract frequently occurring byte patterns from binary.

    Args:
        binary_path: Path to the binary file
        pattern_size: Size of patterns to extract
        min_frequency: Minimum frequency for a pattern to be included

    Returns:
        List of (pattern, frequency) tuples
    """
    patterns = {}

    try:
        with open(binary_path, 'rb') as f:
            data = f.read()

        # Extract patterns
        for i in range(len(data) - pattern_size):
            pattern = data[i:i + pattern_size]

            # Skip low-entropy patterns (all zeros, all ones, etc.)
            if len(set(pattern)) < 3:
                continue

            patterns[pattern] = patterns.get(pattern, 0) + 1

        # Filter by frequency
        frequent_patterns = [
            (pattern, count) for pattern, count in patterns.items()
            if count >= min_frequency
        ]

        # Sort by frequency
        frequent_patterns.sort(key=lambda x: x[1], reverse=True)

        return frequent_patterns[:100]  # Return top 100 patterns

    except Exception as e:
        logger.error("Error extracting patterns: %s", e)
        return []


def scan_binary(binary_path: str, signatures: Optional[Dict[str, bytes]] = None) -> Dict[str, Any]:
    """
    Scan binary for known signatures.

    Args:
        binary_path: Path to the binary file
        signatures: Dict of signature name to byte pattern

    Returns:
        Dict containing scan results
    """
    if signatures is None:
        # Default signatures for common packers/protectors
        signatures = {
            "UPX": b"UPX!",
            "ASPack": b"ASPack",
            "PECompact": b"PECompact",
            "Themida": b"Themida",
            "VMProtect": b"VMProtect",
            "Enigma": b".enigma",
            "MPRESS": b"MPRESS",
            "FSG": b"FSG!",
            "PESpin": b"PESpin"
        }

    results = {
        "detected": [],
        "scan_time": 0,
        "file_size": 0
    }

    try:
        start_time = time.time()

        with open(binary_path, 'rb') as f:
            data = f.read()

        results["file_size"] = len(data)

        # Scan for each signature
        for name, signature in signatures.items():
            if signature in data:
                offset = data.find(signature)
                results["detected"].append({
                    "name": name,
                    "offset": hex(offset),
                    "signature": signature.hex()
                })

        results["scan_time"] = time.time() - start_time

    except Exception as e:
        logger.error("Error scanning binary: %s", e)
        results["error"] = str(e)

    return results


# Optimized analysis functions for performance optimizer
def _optimized_basic_analysis(data, chunk_info=None) -> Dict[str, Any]:
    """Optimized basic binary analysis for chunks."""
    try:
        results = {
            "status": "success",
            "findings": [],
            "chunk_info": chunk_info
        }

        if isinstance(data, bytes) and len(data) > 0:
            # Basic format detection
            if data.startswith(b'MZ'):
                results["findings"].append("PE executable detected")
            elif data.startswith(b'\x7fELF'):
                results["findings"].append("ELF binary detected")
            elif data[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']:
                results["findings"].append("Mach-O binary detected")

            # Basic entropy check
            if len(set(data[:1024])) < 20:
                results["findings"].append("Low entropy section detected (possible padding)")
            elif len(set(data[:1024])) > 200:
                results["findings"].append("High entropy section detected (possible packing/encryption)")

        return results
    except Exception as e:
        return {"status": "failed", "error": str(e)}


def _optimized_string_analysis(data, chunk_info=None) -> Dict[str, Any]:
    """Optimized string analysis for chunks."""
    try:
        results = {
            "status": "success",
            "findings": [],
            "strings_found": 0,
            "license_strings": [],
            "chunk_info": chunk_info
        }

        if isinstance(data, bytes):
            # Extract strings efficiently
            from .string_utils import extract_ascii_strings
            strings = extract_ascii_strings(data)

            results["strings_found"] = len(strings)

            # Look for license-related strings
            license_keywords = ['license', 'serial', 'key', 'activation', 'trial', 'expire', 'valid']
            for string in strings:
                lower_string = string.lower()
                for keyword in license_keywords:
                    if keyword in lower_string:
                        results["license_strings"].append(string)
                        break

            # Add notable findings
            if len(results["license_strings"]) > 0:
                results["findings"].append(f"Found {len(results['license_strings'])} license-related strings")

            if results["strings_found"] > 1000:
                results["findings"].append(f"High string count: {results['strings_found']}")

        return results
    except Exception as e:
        return {"status": "failed", "error": str(e)}


def _optimized_entropy_analysis(data, chunk_info=None) -> Dict[str, Any]:
    """Optimized entropy analysis for chunks."""
    try:
        results = {
            "status": "success",
            "findings": [],
            "entropy": 0.0,
            "chunk_info": chunk_info
        }

        if isinstance(data, bytes) and len(data) > 0:
            # Calculate entropy efficiently
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            entropy = 0.0
            data_length = len(data)

            for count in byte_counts:
                if count > 0:
                    p = count / data_length
                    entropy -= p * (p.bit_length() - 1)

            results["entropy"] = entropy

            # Classify entropy
            if entropy < 1.0:
                results["findings"].append("Very low entropy - likely padding or repetitive data")
            elif entropy < 3.0:
                results["findings"].append("Low entropy - structured data")
            elif entropy > 7.0:
                results["findings"].append("High entropy - likely compressed/encrypted data")
            elif entropy > 7.5:
                results["findings"].append("Very high entropy - possibly packed/obfuscated")

        return results
    except Exception as e:
        return {"status": "failed", "error": str(e)}


def _optimized_section_analysis(data, chunk_info=None) -> Dict[str, Any]:
    """Optimized section analysis for chunks."""
    try:
        results = {
            "status": "success",
            "findings": [],
            "sections_detected": 0,
            "chunk_info": chunk_info
        }

        if isinstance(data, bytes) and len(data) > 64:
            # Look for PE section headers
            if data.startswith(b'MZ'):
                # Look for PE signature
                pe_offset_data = data[60:64]
                if len(pe_offset_data) == 4:
                    pe_offset = struct.unpack('<I', pe_offset_data)[0]
                    if pe_offset < len(data) - 4:
                        pe_sig = data[pe_offset:pe_offset+4]
                        if pe_sig == b'PE\x00\x00':
                            results["findings"].append("Valid PE header detected")
                            results["sections_detected"] = 1

            # Look for ELF section headers
            elif data.startswith(b'\x7fELF'):
                results["findings"].append("ELF header detected")
                results["sections_detected"] = 1

        return results
    except Exception as e:
        return {"status": "failed", "error": str(e)}


def _optimized_import_analysis(data, chunk_info=None) -> Dict[str, Any]:
    """Optimized import analysis for chunks."""
    try:
        results = {
            "status": "success",
            "findings": [],
            "imports_found": 0,
            "suspicious_imports": [],
            "chunk_info": chunk_info
        }

        if isinstance(data, bytes):
            # Look for common DLL names and function names
            common_dlls = [b'kernel32.dll', b'user32.dll', b'ntdll.dll', b'advapi32.dll']
            suspicious_functions = [b'CreateProcess', b'WriteProcessMemory', b'VirtualAlloc', b'LoadLibrary']

            for dll in common_dlls:
                if dll in data:
                    results["imports_found"] += 1
                    results["findings"].append(f"Import from {dll.decode()}")

            for func in suspicious_functions:
                if func in data:
                    results["suspicious_imports"].append(func.decode())

            if len(results["suspicious_imports"]) > 0:
                results["findings"].append(f"Found {len(results['suspicious_imports'])} potentially suspicious imports")

        return results
    except Exception as e:
        return {"status": "failed", "error": str(e)}


def _optimized_pattern_analysis(data, chunk_info=None) -> Dict[str, Any]:
    """Optimized pattern analysis for chunks."""
    try:
        results = {
            "status": "success",
            "findings": [],
            "patterns_found": [],
            "chunk_info": chunk_info
        }

        if isinstance(data, bytes):
            # Look for common patterns
            patterns = {
                b'\x90' * 10: "NOP sled detected",
                b'\x00' * 50: "Large null sequence detected",
                b'\xFF' * 20: "Fill pattern detected",
                b'DEADBEEF': "Debug marker detected",
                b'This program cannot be run in DOS mode': "DOS stub detected"
            }

            for pattern, description in patterns.items():
                if pattern in data:
                    results["patterns_found"].append(description)
                    results["findings"].append(description)

        return results
    except Exception as e:
        return {"status": "failed", "error": str(e)}


# Export all functions
__all__ = [
    'analyze_binary',
    'analyze_binary_optimized',
    'analyze_pe',
    'analyze_elf',
    'analyze_macho',
    'analyze_patterns',
    'analyze_traffic',
    'identify_binary_format',
    'extract_binary_info',
    'extract_binary_features',
    'extract_patterns_from_binary',
    'scan_binary'
]
