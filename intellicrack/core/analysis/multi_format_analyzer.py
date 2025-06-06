"""
Multi-format binary analyzer for various executable formats.

This module provides comprehensive analysis capabilities for different binary
formats including PE, ELF, Mach-O, .NET assemblies, and Java class files.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Optional imports for binary analysis
try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    from elftools.elf.elffile import ELFFile
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False

try:
    from macholib.MachO import MachO
    MACHOLIB_AVAILABLE = True
except ImportError:
    MACHOLIB_AVAILABLE = False

from ...utils.protection_utils import calculate_entropy


class MultiFormatBinaryAnalyzer:
    """
    Multi-format binary analyzer supporting PE, ELF, Mach-O, and other formats.

    This class provides a unified interface for analyzing different binary formats
    and extracting relevant information for security research and reverse engineering.
    """

    def __init__(self):
        """Initialize the multi-format binary analyzer."""
        self.logger = logging.getLogger(__name__)

        # Check for required dependencies
        self.lief_available = LIEF_AVAILABLE
        self.pefile_available = PEFILE_AVAILABLE
        self.pyelftools_available = PYELFTOOLS_AVAILABLE
        self.macholib_available = MACHOLIB_AVAILABLE

        self._check_available_backends()

    def _check_available_backends(self):
        """Check which binary analysis backends are available."""
        if self.lief_available:
            self.logger.info("LIEF multi-format binary analysis available")
        else:
            self.logger.info("LIEF multi-format binary analysis not available")

        if self.pefile_available:
            self.logger.info("pefile PE analysis available")
        else:
            self.logger.info("pefile PE analysis not available")

        if self.pyelftools_available:
            self.logger.info("pyelftools ELF analysis available")
        else:
            self.logger.info("pyelftools ELF analysis not available")

        if self.macholib_available:
            self.logger.info("macholib Mach-O analysis available")
        else:
            self.logger.info("macholib Mach-O analysis not available")

    def identify_format(self, binary_path: Union[str, Path]) -> str:
        """
        Identify the format of a binary file.

        Args:
            binary_path: Path to the binary file

        Returns:
            Format of the binary ('PE', 'ELF', 'MACHO', 'DOTNET', 'CLASS', 'UNKNOWN')
        """
        try:
            with open(binary_path, 'rb') as f:
                magic = f.read(4)

                # Check for PE format (MZ header)
                if magic.startswith(b'MZ'):
                    # Need to check if it's a .NET assembly
                    f.seek(0x3c)
                    pe_offset = int.from_bytes(f.read(4), byteorder='little')
                    f.seek(pe_offset + 0x18)
                    pe_magic = f.read(2)
                    if pe_magic in [b'\x0b\x01', b'\x07\x01']:  # 32-bit or 64-bit
                        # Check for CLI header
                        f.seek(pe_offset + 0x18 + 0x60)
                        cli_header = f.read(8)
                        if any(cli_header):
                            return 'DOTNET'
                    return 'PE'

                # Check for ELF format
                if magic.startswith(b'\x7fELF'):
                    return 'ELF'

                # Check for Mach-O format (32-bit or 64-bit)
                if magic in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                            b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
                    return 'MACHO'

                # Check for Java class file
                if magic.startswith(b'\xca\xfe\xba\xbe'):
                    return 'CLASS'

                return 'UNKNOWN'

        except Exception as e:
            self.logger.error(f"Error identifying binary format: {e}")
            return 'UNKNOWN'

    def analyze_binary(self, binary_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Analyze a binary file of any supported format.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary
        """
        # Identify format
        binary_format = self.identify_format(binary_path)

        # Choose appropriate analysis method
        if binary_format == 'PE':
            return self.analyze_pe(binary_path)
        elif binary_format == 'ELF':
            return self.analyze_elf(binary_path)
        elif binary_format == 'MACHO':
            return self.analyze_macho(binary_path)
        elif binary_format == 'DOTNET':
            return self.analyze_dotnet(binary_path)
        elif binary_format == 'CLASS':
            return self.analyze_java(binary_path)
        else:
            return {
                'format': 'UNKNOWN',
                'error': 'Unsupported binary format'
            }

    def analyze_pe(self, binary_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Analyze a PE (Windows) binary.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary
        """
        if not self.pefile_available:
            return {
                'format': 'PE',
                'error': 'pefile library not available'
            }

        try:
            pe = pefile.PE(str(binary_path))

            # Basic information
            info = {
                'format': 'PE',
                'machine': self._get_machine_type(getattr(pe.FILE_HEADER, 'Machine', 0)),
                'timestamp': self._get_pe_timestamp(getattr(pe.FILE_HEADER, 'TimeDateStamp', 0)),
                'subsystem': getattr(pe.OPTIONAL_HEADER, 'Subsystem', 0),
                'characteristics': self._get_characteristics(getattr(pe.FILE_HEADER, 'Characteristics', 0)),
                'sections': [],
                'imports': [],
                'exports': []
            }

            # Section information
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                section_info = {
                    'name': section_name,
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': hex(section.Characteristics),
                    'entropy': calculate_entropy(section.get_data())
                }
                info['sections'].append(section_info)

            # Import information
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', 'ignore')
                    imports = []

                    for imp in entry.imports:
                        if imp.name:
                            import_name = imp.name.decode('utf-8', 'ignore')
                            imports.append(import_name)

                    info['imports'].append({
                        'dll': dll_name,
                        'functions': imports
                    })

            # Export information
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        export_name = exp.name.decode('utf-8', 'ignore')
                        info['exports'].append({
                            'name': export_name,
                            'address': hex(exp.address)
                        })

            return info

        except Exception as e:
            self.logger.error(f"Error analyzing PE binary: {e}")
            return {
                'format': 'PE',
                'error': str(e)
            }

    def analyze_elf(self, binary_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Analyze an ELF (Linux) binary.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary
        """
        if not self.lief_available and not self.pyelftools_available:
            return {
                'format': 'ELF',
                'error': 'No ELF analysis backend available'
            }

        try:
            # Use LIEF if available
            if self.lief_available and hasattr(lief, 'parse'):
                binary = lief.parse(str(binary_path))

                # Basic information
                info = {
                    'format': 'ELF',
                    'machine': binary.header.machine_type.name,
                    'class': '64-bit' if binary.header.identity_class.name == 'CLASS64' else '32-bit',
                    'type': binary.header.file_type.name,
                    'entry_point': hex(binary.header.entrypoint),
                    'sections': [],
                    'symbols': [],
                    'dynamic': []
                }

                # Section information
                for section in binary.sections:
                    section_info = {
                        'name': section.name,
                        'type': section.type.name if hasattr(section.type, 'name') else str(section.type),
                        'address': hex(section.virtual_address),
                        'size': section.size
                    }

                    # Calculate entropy if section has content
                    if section.content and section.size > 0:
                        section_info['entropy'] = calculate_entropy(bytes(section.content))

                    info['sections'].append(section_info)

                # Symbol information
                for symbol in binary.symbols:
                    if symbol.name:
                        symbol_info = {
                            'name': symbol.name,
                            'type': symbol.type.name if hasattr(symbol.type, 'name') else str(symbol.type),
                            'value': hex(symbol.value),
                            'size': symbol.size
                        }
                        info['symbols'].append(symbol_info)

                return info

            # Use pyelftools if LIEF not available
            elif self.pyelftools_available:
                with open(binary_path, 'rb') as f:
                    elf = ELFFile(f)

                    # Basic information
                    info = {
                        'format': 'ELF',
                        'machine': elf.header['e_machine'],
                        'class': elf.header['e_ident']['EI_CLASS'],
                        'type': elf.header['e_type'],
                        'entry_point': hex(elf.header['e_entry']),
                        'sections': [],
                        'symbols': []
                    }

                    # Section information
                    for section in elf.iter_sections():
                        section_info = {
                            'name': section.name,
                            'type': section['sh_type'],
                            'address': hex(section['sh_addr']),
                            'size': section['sh_size']
                        }

                        info['sections'].append(section_info)

                    return info

        except Exception as e:
            self.logger.error(f"Error analyzing ELF binary: {e}")
            return {
                'format': 'ELF',
                'error': str(e)
            }

    def analyze_macho(self, binary_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Analyze a Mach-O (macOS) binary.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary
        """
        if not self.lief_available and not self.macholib_available:
            return {
                'format': 'MACHO',
                'error': 'No Mach-O analysis backend available'
            }

        try:
            # Use LIEF if available
            if self.lief_available and hasattr(lief, 'parse'):
                binary = lief.parse(str(binary_path))

                # Basic information
                info = {
                    'format': 'MACHO',
                    'headers': [],
                    'segments': [],
                    'symbols': [],
                    'libraries': []
                }

                # Header information
                header_info = {
                    'magic': hex(binary.magic),
                    'cpu_type': binary.header.cpu_type.name if hasattr(binary.header.cpu_type, 'name') else str(binary.header.cpu_type),
                    'file_type': binary.header.file_type.name if hasattr(binary.header.file_type, 'name') else str(binary.header.file_type)
                }
                info['headers'].append(header_info)

                # Segment information
                for segment in binary.segments:
                    segment_info = {
                        'name': segment.name,
                        'address': hex(segment.virtual_address),
                        'size': segment.virtual_size,
                        'sections': []
                    }

                    # Section information
                    for section in segment.sections:
                        section_info = {
                            'name': section.name,
                            'address': hex(section.virtual_address),
                            'size': section.size
                        }

                        segment_info['sections'].append(section_info)

                    info['segments'].append(segment_info)

                return info

            # Use macholib if LIEF not available
            elif self.macholib_available:
                macho = MachO(str(binary_path))

                # Basic information
                info = {
                    'format': 'MACHO',
                    'headers': [],
                    'segments': [],
                    'libraries': []
                }

                # Process each header
                for header in macho.headers:
                    header_info = {
                        'magic': hex(header.MH_MAGIC),
                        'cpu_type': header.header.cputype,
                        'cpu_subtype': header.header.cpusubtype,
                        'filetype': header.header.filetype
                    }
                    info['headers'].append(header_info)

                return info

        except Exception as e:
            self.logger.error(f"Error analyzing Mach-O binary: {e}")
            return {
                'format': 'MACHO',
                'error': str(e)
            }

    def analyze_dotnet(self, binary_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Analyze a .NET assembly.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary
        """
        # For now, return basic PE analysis with .NET note
        result = self.analyze_pe(binary_path)
        if 'error' not in result:
            result['note'] = 'This is a .NET assembly. Consider using specialized .NET analysis tools.'
        return result

    def analyze_java(self, binary_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Analyze a Java class file.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary
        """
        return {
            'format': 'CLASS',
            'note': 'Java class file analysis not yet implemented'
        }

    # Helper methods
    def _get_machine_type(self, machine_value: int) -> str:
        """Get readable machine type from Machine value."""
        machine_types = {
            0x0: "UNKNOWN",
            0x1d3: "AM33",
            0x8664: "AMD64",
            0x1c0: "ARM",
            0xaa64: "ARM64",
            0x1c4: "ARMNT",
            0xebc: "EBC",
            0x14c: "I386",
            0x200: "IA64",
            0x9041: "M32R",
            0x266: "MIPS16",
            0x366: "MIPSFPU",
            0x466: "MIPSFPU16",
            0x1f0: "POWERPC",
            0x1f1: "POWERPCFP",
            0x166: "R4000",
            0x5032: "RISCV32",
            0x5064: "RISCV64",
            0x5128: "RISCV128",
            0x1a2: "SH3",
            0x1a3: "SH3DSP",
            0x1a6: "SH4",
            0x1a8: "SH5",
            0x1c2: "THUMB",
            0x169: "WCEMIPSV2"
        }
        return machine_types.get(machine_value, f"UNKNOWN (0x{machine_value:04X})")

    def _get_pe_timestamp(self, timestamp: int) -> str:
        """Convert PE timestamp to readable date string."""
        try:
            return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return f"Invalid timestamp ({timestamp})"

    def _get_characteristics(self, characteristics: int) -> List[str]:
        """Convert PE characteristics flags to readable descriptions."""
        char_flags = {
            0x0001: "Relocation info stripped",
            0x0002: "Executable image",
            0x0004: "Line numbers stripped",
            0x0008: "Local symbols stripped",
            0x0010: "Aggressive WS trim",
            0x0020: "Large address aware",
            0x0080: "Bytes reversed lo",
            0x0100: "32-bit machine",
            0x0200: "Debug info stripped",
            0x0400: "Removable run from swap",
            0x0800: "Net run from swap",
            0x1000: "System file",
            0x2000: "DLL",
            0x4000: "Uniprocessor machine only",
            0x8000: "Bytes reversed hi"
        }

        result = []
        for flag, desc in char_flags.items():
            if characteristics & flag:
                result.append(desc)

        return result


def run_multi_format_analysis(app, binary_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Run analysis on a binary of any supported format.

    Args:
        app: Application instance with update_output signal
        binary_path: Optional path to binary (uses app.binary_path if not provided)

    Returns:
        Analysis results dictionary
    """
    from ...utils.logger import log_message

    # Use provided path or get from app
    path = binary_path or getattr(app, 'binary_path', None)
    if not path:
        app.update_output.emit(log_message("[Multi-Format] No binary selected."))
        return {'error': 'No binary selected'}

    app.update_output.emit(log_message("[Multi-Format] Starting multi-format binary analysis..."))

    # Create multi-format analyzer
    analyzer = MultiFormatBinaryAnalyzer()

    # Identify format
    binary_format = analyzer.identify_format(path)
    app.update_output.emit(log_message(f"[Multi-Format] Detected format: {binary_format}"))

    # Run analysis
    app.update_output.emit(log_message(f"[Multi-Format] Analyzing {binary_format} binary..."))
    results = analyzer.analyze_binary(path)

    # Check for error
    if 'error' in results:
        app.update_output.emit(log_message(f"[Multi-Format] Error: {results['error']}"))
        return results

    # Display results
    app.update_output.emit(log_message(f"[Multi-Format] Analysis completed for {binary_format} binary"))

    # Add to analyze results
    if not hasattr(app, "analyze_results"):
        app.analyze_results = []

    app.analyze_results.append(f"\n=== MULTI-FORMAT BINARY ANALYSIS ({binary_format}) ===")

    # Format-specific information
    if binary_format == 'PE':
        app.analyze_results.append(f"Machine: {results['machine']}")
        app.analyze_results.append(f"Timestamp: {results['timestamp']}")
        app.analyze_results.append(f"Characteristics: {results['characteristics']}")

        app.analyze_results.append("\nSections:")
        for section in results['sections']:
            entropy_str = f", Entropy: {section['entropy']:.2f}" if 'entropy' in section else ""
            app.analyze_results.append(f"  {section['name']} - VA: {section['virtual_address']}, Size: {section['virtual_size']}{entropy_str}")

        app.analyze_results.append("\nImports:")
        for imp in results['imports']:
            app.analyze_results.append(f"  {imp['dll']} - {len(imp['functions'])} functions")

        app.analyze_results.append("\nExports:")
        for exp in results['exports'][:10]:  # Limit to first 10
            app.analyze_results.append(f"  {exp['name']} - {exp['address']}")

    elif binary_format == 'ELF':
        app.analyze_results.append(f"Machine: {results['machine']}")
        app.analyze_results.append(f"Class: {results['class']}")
        app.analyze_results.append(f"Type: {results['type']}")
        app.analyze_results.append(f"Entry Point: {results['entry_point']}")

        app.analyze_results.append("\nSections:")
        for section in results['sections']:
            entropy_str = f", Entropy: {section['entropy']:.2f}" if 'entropy' in section else ""
            app.analyze_results.append(f"  {section['name']} - Addr: {section['address']}, Size: {section['size']}{entropy_str}")

        app.analyze_results.append("\nSymbols:")
        for symbol in results['symbols'][:10]:  # Limit to first 10
            app.analyze_results.append(f"  {symbol['name']} - {symbol['value']}")

    elif binary_format == 'MACHO':
        app.analyze_results.append(f"CPU Type: {results['headers'][0]['cpu_type']}")
        app.analyze_results.append(f"File Type: {results['headers'][0]['file_type']}")

        app.analyze_results.append("\nSegments:")
        for segment in results['segments']:
            app.analyze_results.append(f"  {segment['name']} - Addr: {segment['address']}, Size: {segment['size']}")

            app.analyze_results.append("  Sections:")
            for section in segment['sections']:
                app.analyze_results.append(f"    {section['name']} - Addr: {section['address']}, Size: {section['size']}")

    # Add recommendations based on format
    app.analyze_results.append("\nRecommendations:")
    if binary_format == 'PE':
        app.analyze_results.append("- Use standard Windows PE analysis techniques")
        app.analyze_results.append("- Check for high-entropy sections that may indicate packing or encryption")
    elif binary_format == 'ELF':
        app.analyze_results.append("- Use specialized ELF analysis tools for deeper inspection")
        app.analyze_results.append("- Consider using dynamic analysis with Linux-specific tools")
    elif binary_format == 'MACHO':
        app.analyze_results.append("- Use macOS-specific analysis tools for deeper inspection")
        app.analyze_results.append("- Check for code signing and entitlements")

    return results
