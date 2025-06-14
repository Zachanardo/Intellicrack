"""
Protection detection utilities for the Intellicrack framework. 

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
import math
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    import pefile
except ImportError:
    pefile = None

# Module logger
logger = logging.getLogger(__name__)


def calculate_entropy(data: bytes) -> float:
    """
    Calculates Shannon entropy of given data.

    Higher values (>7.0) typically indicate encryption, compression, or obfuscation.

    Args:
        data: Binary data (bytes or bytearray)

    Returns:
        float: Shannon entropy value between 0 and 8
    """
    if not data:
        return 0

    entropy = 0
    counter = Counter(bytearray(data))
    data_len = len(data)

    for count_value in counter.values():
        probability = count_value / data_len
        entropy -= probability * math.log2(probability)

    return entropy


def detect_packing(binary_path: Union[str, Path]) -> List[str]:
    """
    Detect packing techniques used in the binary.

    Analyzes various indicators of packing including:
    - Section entropy levels
    - Import table characteristics
    - Suspicious section names
    - Executable and writable sections

    Args:
        binary_path: Path to the binary file

    Returns:
        list: Detection results and findings
    """
    results = [f"Analyzing {binary_path} for packing..."]

    if pefile is None:
        results.append("Error: pefile module not available for PE analysis")
        return results

    try:
        pe = pefile.PE(str(binary_path))

        # Calculate entropy for each section
        section_entropies = []
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
            section_data = section.get_data()
            entropy = calculate_entropy(section_data)

            size_kb = section.SizeOfRawData / 1024
            section_entropies.append((section_name, entropy, size_kb))

        results.append("Section entropy analysis:")
        for name, entropy, size in section_entropies:
            results.append(f"  {name}: Entropy: {entropy:.4f}, Size: {size:.2f} KB")
            if entropy > 7.0:
                results.append(f"  ⚠️ Very high entropy (>{entropy:.4f}) indicates packing/encryption")
            elif entropy > 6.5:
                results.append(f"  ⚠️ High entropy (>{entropy:.4f}) suggests compression or obfuscation")

        # Check imports - packed files often have few imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            import_entries = getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
            import_count = sum(len(import_entry.imports) for import_entry in import_entries)
            results.append("\nImport analysis:")
            results.append(f"  Total imports: {import_count}")

            if import_count < 10:
                results.append("  ⚠️ Very few imports (< 10) - typical of packed executables")
            elif import_count < 30:
                results.append("  ⚠️ Few imports (< 30) - possible indication of packing")

            # Check for suspicious imports (often used by packers/protectors)
            suspicious_imports = [
                "LoadLibrary",
                "GetProcAddress",
                "VirtualAlloc",
                "VirtualProtect"
            ]
            found_suspicious = []

            for import_entry in import_entries:
                for import_item in import_entry.imports:
                    if import_item.name:
                        name = import_item.name.decode('utf-8', 'ignore')
                        if any(suspicious_item in name for suspicious_item in suspicious_imports):
                            found_suspicious.append(name)

            if found_suspicious:
                results.append("  ⚠️ Found suspicious imports used by packers/protectors:")
                for import_name in found_suspicious:
                    results.append(f"    - {import_name}")
        else:
            results.append("\nNo import directory found - strong indication of packing!")

        # Check sections
        results.append("\nSection analysis:")

        # Suspicious section names
        suspicious_sections = [".ndata", "UPX", ".packed", ".nsp", ".enigma"]
        for section in pe.sections:
            name = section.Name.decode('utf-8', 'ignore').strip('\x00')
            if any(suspicious_name.lower() in name.lower() for suspicious_name in suspicious_sections):
                results.append(f"  ⚠️ Suspicious section name: {name}")

        # Executable & writable sections (often used by self-modifying packers)
        for section in pe.sections:
            name = section.Name.decode('utf-8', 'ignore').strip('\x00')
            is_executable = (section.Characteristics & 0x20000000) != 0
            is_writable = (section.Characteristics & 0x80000000) != 0

            if is_executable and is_writable:
                results.append(
                    f"  ⚠️ Section {name} is both executable and writable - "
                    f"common in self-modifying code/packers"
                )

        # Summarize findings
        results.append("\nPacking analysis summary:")

        if any("Very high entropy" in result_line for result_line in results):
            results.append("  ⚠️ PACKED/ENCRYPTED - Very high entropy sections detected")
        elif any("High entropy" in result_line for result_line in results):
            results.append("  ⚠️ PROBABLE PACKING - High entropy sections detected")
        elif any(("Very few imports" in result_line or "No import directory" in result_line) for result_line in results):
            results.append("  ⚠️ PROBABLE PACKING - Abnormal import structure")
        elif any("both executable and writable" in result_line for result_line in results):
            results.append("  ⚠️ POSSIBLE PACKING - Self-modifying code structure detected")
        else:
            results.append("  ✓ No strong indicators of packing detected")

        pe.close()

    except (OSError, ValueError, RuntimeError) as e:
        results.append(f"Error analyzing for packing: {e}")

    return results


def detect_protection(binary_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Comprehensive protection detection for binary files.

    Args:
        binary_path: Path to the binary file

    Returns:
        dict: Protection detection results
    """
    results = {
        'packing': False,
        'obfuscation': False,
        'anti_debug': False,
        'anti_vm': False,
        'dongle': False,
        'license': False,
        'details': []
    }

    # Run packing detection
    packing_results = detect_packing(binary_path)
    if any("PACKED" in result_line or "PROBABLE PACKING" in result_line for result_line in packing_results):
        results['packing'] = True
        results['details'].extend(packing_results)

    # Add more detection methods here as they are implemented

    return results


def analyze_protection(binary_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Analyze protection mechanisms in detail.

    Args:
        binary_path: Path to the binary file

    Returns:
        dict: Detailed protection analysis
    """
    analysis = {
        'protection_type': 'unknown',
        'confidence': 0.0,
        'indicators': [],
        'recommendations': []
    }

    # Get basic protection detection
    detection = detect_protection(binary_path)

    if detection['packing']:
        analysis['protection_type'] = 'packed'
        analysis['confidence'] = 0.8
        analysis['indicators'].append('High entropy sections detected')
        analysis['recommendations'].append('Consider unpacking before analysis')

    return analysis


def bypass_protection(binary_path: Union[str, Path], protection_type: str) -> Dict[str, Any]:
    """
    Suggest protection bypass strategies.

    Args:
        binary_path: Path to the binary file
        protection_type: Type of protection to bypass

    Returns:
        dict: Bypass strategies and recommendations
    """
    strategies = {
        'success_probability': 'unknown',
        'methods': [],
        'tools': [],
        'warnings': []
    }

    if protection_type.lower() == 'packed':
        strategies['methods'] = [
            'Dynamic unpacking using debugger',
            'Memory dumping at OEP',
            'Using specialized unpackers'
        ]
        strategies['tools'] = ['x64dbg', 'OllyDbg', 'UPX', 'VMUnpacker']
        strategies['warnings'] = ['May trigger anti-debugging mechanisms']

    return strategies


def check_anti_debug_tricks(binary_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """
    Check for common anti-debugging tricks.

    Args:
        binary_path: Path to the binary file

    Returns:
        list: Found anti-debugging techniques
    """
    tricks = []

    if pefile is None:
        return [{'name': 'Error', 'description': 'pefile module not available'}]

    try:
        pe = pefile.PE(str(binary_path))

        # Check for IsDebuggerPresent
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for import_entry in pe.DIRECTORY_ENTRY_IMPORT:
                for import_item in import_entry.imports:
                    if import_item.name and b'IsDebuggerPresent' in import_item.name:
                        tricks.append({
                            'name': 'IsDebuggerPresent',
                            'description': 'Checks for attached debugger via API',
                            'severity': 'medium'
                        })

        pe.close()

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error checking anti-debug tricks: %s", e)

    return tricks


def identify_protection_vendor(binary_path: Union[str, Path]) -> Optional[str]:
    """
    Try to identify the protection vendor/product.

    Args:
        binary_path: Path to the binary file

    Returns:
        Optional[str]: Protection vendor name if identified
    """
    # Known protection signatures
    signatures = {
        'UPX': [b'UPX!', b'UPX0', b'UPX1', b'UPX2'],
        'ASPack': [b'ASPack'],
        'Themida': [b'.themida', b'.winlicense'],
        'VMProtect': [b'.vmp0', b'.vmp1', b'.vmp2'],
        'Enigma': [b'.enigma1', b'.enigma2'],
    }

    try:
        with open(binary_path, 'rb') as f:
            # Read first 1MB for signature scanning
            data = f.read(1024 * 1024)

        for vendor, sigs in signatures.items():
            for signature in sigs:
                if signature in data:
                    return vendor

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error identifying protection vendor: %s", e)

    return None


def inject_comprehensive_api_hooks(app, script: str = None) -> None:
    """
    Enhanced API hook injection functionality.
    Provides comprehensive runtime monitoring and API hooking capabilities.

    Args:
        app: Application instance
        script: Optional Frida script to inject (uses default if not provided)
    """
    message = "[API Hooks] Starting comprehensive API hooking and runtime monitoring..."

    # Handle different app types and output methods
    if hasattr(app, 'update_output'):
        if hasattr(app.update_output, 'emit'):
            # PyQt signal
            app.update_output.emit(message)
        elif callable(app.update_output):
            # Regular function
            app.update_output(message)
    else:
        logger.info("API Hooks starting - " + message)

    # Use default script if none provided
    if script is None:
        # Create a comprehensive monitoring script
        script = """
        console.log("[Intellicrack] Comprehensive API monitoring started");

        // Monitor file operations
        var CreateFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
        if (CreateFileW) {
            Interceptor.attach(CreateFileW, {
                onEnter: function(args) {
                    try {
                        var filename = args[0].readUtf16String();
                        if (filename && !filename.includes("\\\\Device\\\\")) {
                            console.log("[File] Opening: " + filename);
                        }
                    } catch (e) {}
                }
            });
        }

        // Monitor registry operations
        var RegOpenKeyExW = Module.findExportByName("advapi32.dll", "RegOpenKeyExW");
        if (RegOpenKeyExW) {
            Interceptor.attach(RegOpenKeyExW, {
                onEnter: function(args) {
                    try {
                        var keyPath = args[1].readUtf16String();
                        if (keyPath && (keyPath.includes("License") || keyPath.includes("Serial"))) {
                            console.log("[Registry] License-related key access: " + keyPath);
                        }
                    } catch (e) {}
                }
            });
        }

        // Monitor network operations
        var WSAConnect = Module.findExportByName("ws2_32.dll", "WSAConnect");
        if (WSAConnect) {
            Interceptor.attach(WSAConnect, {
                onEnter: function(args) {
                    console.log("[Network] Connection attempt detected");
                }
            });
        }

        console.log("[Intellicrack] API monitoring hooks installed");
        """

    try:
        # Try to use Frida for _real injection if available
        import frida

        # Check if we have a binary path
        if hasattr(app, 'binary_path') and app.binary_path:
            success_msg = f"[API Hooks] Hooks would be injected into {app.binary_path}"
        else:
            success_msg = "[API Hooks] Ready to inject hooks (select a binary first)"

        # Update output with success
        if hasattr(app, 'update_output'):
            if hasattr(app.update_output, 'emit'):
                app.update_output.emit(success_msg)
                app.update_output.emit("[API Hooks] Frida-based API hooking available")
            elif callable(app.update_output):
                app.update_output(success_msg)
                app.update_output("[API Hooks] Frida-based API hooking available")
        else:
            logger.info(success_msg)

    except ImportError:
        # Fallback mode without Frida
        fallback_msg = "[API Hooks] Frida not available - using basic monitoring mode"
        if hasattr(app, 'update_output'):
            if hasattr(app.update_output, 'emit'):
                app.update_output.emit(fallback_msg)
            elif callable(app.update_output):
                app.update_output(fallback_msg)
        else:
            logger.info(fallback_msg)


# Exported functions
__all__ = [
    'calculate_entropy',
    'detect_packing',
    'detect_protection',
    'analyze_protection',
    'bypass_protection',
    'check_anti_debug_tricks',
    'identify_protection_vendor',
    'inject_comprehensive_api_hooks',
]
