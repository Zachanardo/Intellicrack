"""
Core analysis functions for Intellicrack.

This module contains the fundamental analysis functions that perform deep inspection
of binary files, including structure analysis, packing detection, and entropy calculation.
"""

import logging
import math
import os
from collections import Counter
from typing import Any, Dict, List, Optional

try:
    import pefile
except ImportError:
    pefile = None

logger = logging.getLogger(__name__)


# Import shared entropy calculation
from ...utils.protection_utils import calculate_entropy


def get_machine_type(machine: int) -> str:
    """Get human-readable machine type from PE machine value."""
    machine_types = {
        0x014c: "x86 (32-bit)",
        0x8664: "x64 (64-bit)",
        0x0200: "Intel Itanium",
        0x01c0: "ARM little endian",
        0x01c4: "ARM Thumb-2 little endian",
        0xaa64: "ARM64 little endian"
    }
    return machine_types.get(machine, f"Unknown (0x{machine:04X})")


def get_magic_type(magic: int) -> str:
    """Get human-readable magic type from PE optional header magic value."""
    magic_types = {
        0x10b: "PE32",
        0x20b: "PE32+",
        0x107: "ROM image"
    }
    return magic_types.get(magic, f"Unknown (0x{magic:04X})")


def get_characteristics(characteristics: int) -> str:
    """Get human-readable characteristics from PE file header."""
    char_flags = {
        0x0001: "RELOCS_STRIPPED",
        0x0002: "EXECUTABLE_IMAGE",
        0x0004: "LINE_NUMBERS_STRIPPED",
        0x0008: "LOCAL_SYMS_STRIPPED",
        0x0010: "AGGR_WS_TRIM",
        0x0020: "LARGE_ADDRESS_AWARE",
        0x0080: "BYTES_REVERSED_LO",
        0x0100: "32BIT_MACHINE",
        0x0200: "DEBUG_STRIPPED",
        0x0400: "REMOVABLE_RUN_FROM_SWAP",
        0x0800: "NET_RUN_FROM_SWAP",
        0x1000: "SYSTEM",
        0x2000: "DLL",
        0x4000: "UP_SYSTEM_ONLY",
        0x8000: "BYTES_REVERSED_HI"
    }

    flags = []
    for flag, name in char_flags.items():
        if characteristics & flag:
            flags.append(name)

    return " | ".join(flags) if flags else "None"


def get_pe_timestamp(timestamp: int) -> str:
    """Convert PE timestamp to human-readable format."""
    import datetime
    try:
        dt = datetime.datetime.fromtimestamp(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError):
        return "Invalid timestamp"


def analyze_binary_internal(binary_path: str, flags: Optional[List[str]] = None) -> List[str]:
    """
    Analyzes the binary file structure in detail.

    Performs comprehensive static analysis of a binary executable file,
    examining its PE header, sections, imports, exports, resources, and strings.
    Identifies suspicious characteristics like high-entropy sections,
    dangerous permissions, and license-related imports.

    Args:
        binary_path: Path to the binary file to analyze
        flags: Optional list of analysis flags to control behavior
               (e.g., "stealth" to skip string scanning)

    Returns:
        list: Analysis results as a list of formatted strings
    """
    if flags is None:
        flags = []

    results = []

    try:
        logger.info("Starting internal binary analysis for: %s. Flags: %s", binary_path, flags)
        results.append(f"Analyzing binary: {os.path.basename(binary_path)}")
        results.append(f"File size: {os.path.getsize(binary_path):,} bytes")

        if not pefile:
            results.append("ERROR: pefile library not available - install with 'pip install pefile'")
            return results

        pe = pefile.PE(binary_path)

        # Basic PE header information
        results.append("\nPE Header:")
        if pe and hasattr(pe, 'FILE_HEADER') and pe.FILE_HEADER:
            machine = getattr(pe.FILE_HEADER, "Machine", None)
            if machine is not None:
                results.append(f"Machine: 0x{machine:04X} ({get_machine_type(machine)})")
            num_sections = getattr(pe.FILE_HEADER, "NumberOfSections", None)
            if num_sections is not None:
                results.append(f"Number of sections: {num_sections}")
            timestamp = getattr(pe.FILE_HEADER, "TimeDateStamp", None)
            if timestamp is not None:
                results.append(f"Time date stamp: {hex(timestamp)} ({get_pe_timestamp(timestamp)})")
            characteristics = getattr(pe.FILE_HEADER, "Characteristics", None)
            if characteristics is not None:
                results.append(f"Characteristics: 0x{characteristics:04X} ({get_characteristics(characteristics)})")
        else:
            results.append("PE FILE_HEADER missing or invalid")

        # Optional header
        results.append("\nOptional Header:")
        if pe and hasattr(pe, 'OPTIONAL_HEADER') and pe.OPTIONAL_HEADER:
            magic = getattr(pe.OPTIONAL_HEADER, "Magic", None)
            if magic is not None:
                results.append(f"Magic: 0x{magic:04X} ({get_magic_type(magic)})")
            entry_point = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", None)
            if entry_point is not None:
                results.append(f"Entry point: 0x{entry_point:08X}")
            image_base = getattr(pe.OPTIONAL_HEADER, "ImageBase", None)
            if image_base is not None:
                results.append(f"Image base: 0x{image_base:08X}")

            # Handle checksum with case variations
            checksum_val = None
            if hasattr(pe.OPTIONAL_HEADER, "CheckSum"):
                checksum_val = pe.OPTIONAL_HEADER.CheckSum
            elif hasattr(pe.OPTIONAL_HEADER, "Checksum"):
                checksum_val = pe.OPTIONAL_HEADER.Checksum
            if checksum_val and checksum_val != 0:
                results.append(f"Checksum: 0x{checksum_val:08X}")
        else:
            results.append("PE OPTIONAL_HEADER missing or invalid")

        # Section information
        results.append("\nSections:")
        suspicious_sections = []

        if pe and hasattr(pe, 'sections') and pe.sections:
            for section in pe.sections:
                name = getattr(section, "Name", b"").decode('utf-8', errors='ignore').rstrip('\0')
                results.append(f"  {name}:")
                va = getattr(section, "VirtualAddress", None)
                if va is not None:
                    results.append(f"    Virtual Address: 0x{va:08X}")
                vsz = getattr(section, "Misc_VirtualSize", None)
                if vsz is not None:
                    results.append(f"    Virtual Size: 0x{vsz:08X} ({vsz:,} bytes)")
                rdsz = getattr(section, "SizeOfRawData", None)
                if rdsz is not None:
                    results.append(f"    Raw Data Size: 0x{rdsz:08X} ({rdsz:,} bytes)")

                # Calculate entropy for section
                try:
                    section_data = section.get_data()
                    entropy = calculate_entropy(section_data)
                    results.append(f"    Entropy: {entropy:.2f}")
                    if entropy > 7.0:
                        results.append("    WARNING: High entropy, possible encryption/compression")
                        suspicious_sections.append(name)
                except Exception as e:
                    results.append(f"    ERROR: Could not calculate entropy: {e}")

        # Import table analysis
        results.append("\nImports:")
        license_related_imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                results.append(f"  {dll_name}:")

                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        # Check for license-related imports
                        license_keywords = ['license', 'activation', 'validate', 'verify', 'check', 'auth']
                        if any(keyword in func_name.lower() for keyword in license_keywords):
                            license_related_imports.append(f"{dll_name}::{func_name}")
                        results.append(f"    {func_name}")

        if license_related_imports:
            results.append("\nLicense-related imports detected:")
            for imp in license_related_imports:
                results.append(f"  {imp}")

        # Export table analysis
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            results.append("\nExports:")
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    results.append(f"  {exp.name.decode('utf-8', errors='ignore')}")

        # Summary
        results.append("\nAnalysis Summary:")
        results.append(f"  Suspicious sections: {len(suspicious_sections)}")
        results.append(f"  License-related imports: {len(license_related_imports)}")

        pe.close()

    except Exception as e:
        logger.exception(f"Error analyzing binary: {binary_path}")
        results.append(f"ERROR: Failed to analyze binary - {str(e)}")

    return results


def enhanced_deep_license_analysis(binary_path: str) -> Dict[str, Any]:
    """
    Performs deep license analysis on a binary file.

    This function analyzes the binary for license-related patterns, validation routines,
    and protection mechanisms commonly used in commercial software.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        dict: Analysis results containing license-related findings
    """
    results = {
        "license_patterns": [],
        "validation_routines": [],
        "protection_mechanisms": [],
        "suspicious_strings": [],
        "network_calls": [],
        "registry_access": [],
        "file_operations": []
    }

    try:
        logger.info("Starting deep license analysis for: %s", binary_path)

        if not pefile:
            results["error"] = "pefile library not available"
            return results

        pe = pefile.PE(binary_path)

        # Analyze imports for license-related functions
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore').lower()

                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore').lower()

                        # Network-related functions
                        if any(net in func_name for net in ['inet', 'socket', 'winhttp', 'urlmon']):
                            results["network_calls"].append(f"{dll_name}::{func_name}")

                        # Registry-related functions
                        if any(reg in func_name for reg in ['reg', 'key', 'value']):
                            results["registry_access"].append(f"{dll_name}::{func_name}")

                        # File operation functions
                        if any(file_op in func_name for file_op in ['file', 'read', 'write', 'create']):
                            results["file_operations"].append(f"{dll_name}::{func_name}")

                        # License validation patterns
                        license_patterns = ['license', 'activation', 'validate', 'verify', 'check', 'auth', 'trial']
                        if any(pattern in func_name for pattern in license_patterns):
                            results["validation_routines"].append(f"{dll_name}::{func_name}")

        # Scan for strings (simplified version)
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            # Look for license-related strings
            license_keywords = [
                b'license', b'activation', b'trial', b'expired', b'invalid',
                b'registration', b'serial', b'product key', b'unlock',
                b'authenticate', b'verify', b'validation'
            ]

            for keyword in license_keywords:
                if keyword in data:
                    results["suspicious_strings"].append(keyword.decode('utf-8', errors='ignore'))

        except Exception as e:
            logger.warning("Could not scan strings in %s: %s", binary_path, e)

        # Identify protection mechanisms
        protection_indicators = []

        # Check for high-entropy sections (potential packing/encryption)
        if hasattr(pe, 'sections'):
            for section in pe.sections:
                try:
                    section_data = section.get_data()
                    entropy = calculate_entropy(section_data)
                    if entropy > 7.0:
                        section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\0')
                        protection_indicators.append(f"High entropy section: {section_name} ({entropy:.2f})")
                except (UnicodeDecodeError, AttributeError, ValueError):
                    pass

        results["protection_mechanisms"] = protection_indicators

        pe.close()

    except Exception as e:
        logger.exception(f"Error in deep license analysis: {binary_path}")
        results["error"] = str(e)

    return results


def detect_packing(binary_path: str) -> Dict[str, Any]:
    """
    Detects if a binary is packed or obfuscated.

    Analyzes various indicators that suggest the binary has been packed,
    compressed, or obfuscated to hide its true functionality.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        dict: Packing detection results
    """
    results = {
        "is_packed": False,
        "confidence": 0.0,
        "indicators": [],
        "entropy_analysis": {},
        "section_analysis": {},
        "import_analysis": {}
    }

    try:
        logger.info("Starting packing detection for: %s", binary_path)

        if not pefile:
            results["error"] = "pefile library not available"
            return results

        pe = pefile.PE(binary_path)

        # Entropy analysis - packed files typically have high entropy
        high_entropy_sections = 0
        total_sections = 0
        entropy_scores = []

        if hasattr(pe, 'sections'):
            for section in pe.sections:
                try:
                    section_data = section.get_data()
                    entropy = calculate_entropy(section_data)
                    section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\0')

                    entropy_scores.append(entropy)
                    total_sections += 1

                    if entropy > 7.0:
                        high_entropy_sections += 1
                        results["indicators"].append(f"High entropy section: {section_name} ({entropy:.2f})")

                except Exception as e:
                    logger.warning("Could not analyze section entropy: %s", e)

        # Calculate average entropy
        avg_entropy = sum(entropy_scores) / len(entropy_scores) if entropy_scores else 0
        results["entropy_analysis"] = {
            "average_entropy": avg_entropy,
            "high_entropy_sections": high_entropy_sections,
            "total_sections": total_sections,
            "entropy_scores": entropy_scores
        }

        # Section analysis - look for suspicious section names/characteristics
        suspicious_section_names = [
            'upx0', 'upx1', 'upx2', '.aspack', '.adata', '.boom', '.ccg',
            '.charmve', '.edata', '.ecode', '.edata', '.enigma1', '.enigma2',
            '.packed', '.pec1', '.pec2', '.petite', '.protect', '.seau',
            '.sforce3', '.spack', '.svkp', '.taz', '.tsuarch', '.tsustub',
            '.packed', '.wwpack', '.y0da'
        ]

        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\0').lower()
            if any(sus_name in section_name for sus_name in suspicious_section_names):
                results["indicators"].append(f"Suspicious section name: {section_name}")
                results["section_analysis"][section_name] = "Suspicious packer signature"

        # Import analysis - packed files often have minimal imports
        import_count = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    import_count += 1

        results["import_analysis"]["import_count"] = import_count

        if import_count < 10:
            results["indicators"].append(f"Unusually low import count: {import_count}")

        # Calculate confidence score
        confidence_factors = []

        # High entropy factor
        if avg_entropy > 7.0:
            confidence_factors.append(0.4)
        elif avg_entropy > 6.5:
            confidence_factors.append(0.2)

        # High entropy sections factor
        if high_entropy_sections > 0 and total_sections > 0:
            ratio = high_entropy_sections / total_sections
            confidence_factors.append(ratio * 0.3)

        # Low imports factor
        if import_count < 10:
            confidence_factors.append(0.2)
        elif import_count < 5:
            confidence_factors.append(0.3)

        # Suspicious section names
        if any("suspicious" in indicator.lower() for indicator in results["indicators"]):
            confidence_factors.append(0.3)

        # Calculate final confidence
        results["confidence"] = min(sum(confidence_factors), 1.0)
        results["is_packed"] = results["confidence"] > 0.5

        pe.close()

    except Exception as e:
        logger.exception(f"Error in packing detection: {binary_path}")
        results["error"] = str(e)

    return results


def decrypt_embedded_script(binary_path):
    """Decrypt embedded scripts in the binary."""
    results = [f"Searching for embedded scripts in {binary_path}..."]

    try:
        # Read the binary file
        with open(binary_path, "rb") as f:
            binary_data = f.read()

        # Look for script markers
        script_markers = [
            (b"<script>", b"</script>"),
            (b"BEGIN_SCRIPT", b"END_SCRIPT"),
            (b"#BEGIN_PY", b"#END_PY"),
            (b"/*SCRIPT_START*/", b"/*SCRIPT_END*/")
        ]

        found_scripts = []

        for start_marker, end_marker in script_markers:
            start_pos = 0
            while True:
                start_pos = binary_data.find(start_marker, start_pos)
                if start_pos == -1:
                    break

                end_pos = binary_data.find(
                    end_marker, start_pos + len(start_marker))
                if end_pos == -1:
                    break

                # Extract script content
                script_content = binary_data[start_pos +
                                             len(start_marker):end_pos]

                # Check if it's actually a script (look for script-like content)
                is_script = False
                script_keywords = [
                    b"function",
                    b"var ",
                    b"return",
                    b"import",
                    b"class",
                    b"def ",
                    b"print(",
                    b"console.log"]
                for keyword in script_keywords:
                    if keyword in script_content:
                        is_script = True
                        break

                if is_script:
                    try:
                        # Try to decode as UTF-8
                        decoded_script = script_content.decode(
                            'utf-8', errors='ignore')
                        found_scripts.append({
                            "offset": start_pos,
                            "marker": start_marker.decode('utf-8', errors='ignore'),
                            # Limit to first 1000 chars to avoid huge outputs
                            "content": decoded_script[:1000]
                        })
                    except Exception as e:
                        results.append(f"Error decoding script: {e}")

                start_pos = end_pos + len(end_marker)

        # Look for obfuscated scripts
        obfuscation_markers = [
            b"eval(", b"String.fromCharCode(", b"atob(", b"decrypt",
            b"base64.b64decode", b"base64_decode", b"fromBase64"
        ]

        for marker in obfuscation_markers:
            start_pos = 0
            while True:
                start_pos = binary_data.find(marker, start_pos)
                if start_pos == -1:
                    break

                # Extract context (100 bytes before and after)
                context_start = max(0, start_pos - 100)
                context_end = min(
                    len(binary_data),
                    start_pos + len(marker) + 100)
                context = binary_data[context_start:context_end]

                try:
                    decoded_context = context.decode('utf-8', errors='ignore')
                    found_scripts.append({
                        "offset": start_pos,
                        "marker": "Obfuscated: " + marker.decode('utf-8', errors='ignore'),
                        "content": decoded_context
                    })
                except Exception as e:
                    results.append(f"Error decoding obfuscated script: {e}")

                start_pos += len(marker)

        # Report findings
        if found_scripts:
            results.append(
                f"Found {
                    len(found_scripts)} potential embedded scripts:")

            for i, script in enumerate(found_scripts):
                results.append(
                    f"\nScript {
                        i +
                        1} at offset 0x{
                        script['offset']:X}:")
                results.append(f"Marker: {script['marker']}")
                results.append("Content preview:")

                # Show first few lines
                lines = script['content'].splitlines() if script.get('content') is not None else []
                for j, line in enumerate(lines[:10]):
                    results.append(f"  {j + 1}: {line}")

                if len(lines) > 10:
                    results.append(f"  ... plus {len(lines) - 10} more lines")

                # Try to determine script type
                if "function" in script['content'] and "var" in script['content']:
                    results.append("Type: JavaScript")
                elif "import" in script['content'] and "def " in script['content']:
                    results.append("Type: Python")
                elif "<?php" in script['content']:
                    results.append("Type: PHP")
                else:
                    results.append("Type: Unknown")
        else:
            results.append("No embedded scripts found.")

    except Exception as e:
        results.append(f"Error searching for embedded scripts: {e}")
        logger.error("Error in decrypt_embedded_script: %s", e)

    return results
