"""Binary analysis engine for comprehensive executable file examination.

This module provides core binary analysis capabilities for the Intellicrack
security research framework, supporting multiple executable formats and
offering detailed structural analysis, metadata extraction, and security
assessment features.

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
import struct
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Union


class BinaryAnalyzer:
    """Core binary analysis engine for executable file examination."""

    def __init__(self):
        """Initialize the binary analyzer.

        Sets up the core binary analysis engine with support for multiple
        executable formats including PE, ELF, Mach-O, DEX, and archives.
        Initializes format detection capabilities and analysis components.
        """
        self.logger = logging.getLogger(__name__)

        # Magic bytes for file format detection
        self.magic_bytes = {
            b"MZ": "PE",
            b"\x7fELF": "ELF",
            b"\xfe\xed\xfa\xce": "Mach-O (32-bit)",
            b"\xce\xfa\xed\xfe": "Mach-O (32-bit)",
            b"\xfe\xed\xfa\xcf": "Mach-O (64-bit)",
            b"\xcf\xfa\xed\xfe": "Mach-O (64-bit)",
            b"\xca\xfe\xba\xbe": "Java Class",
            b"dex\n": "Android DEX",
            b"PK\x03\x04": "ZIP/JAR/APK",
            b"\x89PNG": "PNG Image",
            b"\xff\xd8\xff": "JPEG Image",
            b"GIF8": "GIF Image",
            b"%PDF": "PDF Document"
        }

    def analyze(self, binary_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Perform comprehensive binary analysis.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary
        """
        try:
            binary_path = Path(binary_path)

            if not binary_path.exists():
                return {"error": f"File not found: {binary_path}"}

            if not binary_path.is_file():
                return {"error": f"Not a file: {binary_path}"}

            # Basic file information
            file_info = self._get_file_info(binary_path)

            # Detect file format
            file_format = self._detect_format(binary_path)

            # Calculate hashes
            hashes = self._calculate_hashes(binary_path)

            # Analyze based on format
            format_analysis = {}
            if file_format == "PE":
                format_analysis = self._analyze_pe(binary_path)
            elif file_format == "ELF":
                format_analysis = self._analyze_elf(binary_path)
            elif file_format.startswith("Mach-O"):
                format_analysis = self._analyze_macho(binary_path)
            elif file_format == "Android DEX":
                format_analysis = self._analyze_dex(binary_path)
            elif file_format in ["ZIP/JAR/APK"]:
                format_analysis = self._analyze_archive(binary_path)

            # String analysis
            strings_info = self._extract_strings(binary_path)

            # Entropy analysis
            entropy_info = self._analyze_entropy(binary_path)

            # Security analysis
            security_info = self._security_analysis(binary_path, file_format)

            return {
                "format": file_format,
                "path": str(binary_path),
                "file_info": file_info,
                "hashes": hashes,
                "format_analysis": format_analysis,
                "strings": strings_info,
                "entropy": entropy_info,
                "security": security_info,
                "analysis_status": "completed",
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error("Binary analysis failed: %s", e)
            return {"error": str(e), "analysis_status": "failed"}

    def _get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Extract basic file metadata."""
        try:
            stat = file_path.stat()
            return {
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
                "permissions": oct(stat.st_mode)[-3:] if hasattr(stat, "st_mode") else None
            }
        except Exception as e:
            return {"error": str(e)}

    def _detect_format(self, file_path: Path) -> str:
        """Detect file format using magic bytes."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(8)

            for magic, format_name in self.magic_bytes.items():
                if header.startswith(magic):
                    return format_name

            # Additional checks for text-based formats
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    text = f.read(1000)
                    if text.startswith("#!/"):
                        return "Script"
                    elif text.startswith("<?xml"):
                        return "XML"
                    elif text.startswith(("{", "[")):
                        return "JSON"
            except (UnicodeDecodeError, AttributeError):
                pass

            return "Unknown"
        except Exception as e:
            return f"Error: {e}"

    def _calculate_hashes(self, file_path: Path) -> Dict[str, str]:
        """Calculate various hashes of the file."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            return {
                "md5": hashlib.md5(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "sha512": hashlib.sha512(data).hexdigest()
            }
        except Exception as e:
            return {"error": str(e)}

    def _analyze_pe(self, file_path: Path) -> Dict[str, Any]:
        """Analyze PE (Windows executable) file."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            pe_info = {}

            # Check DOS header
            if data[:2] != b"MZ":
                return {"error": "Invalid DOS header"}

            # Get PE header offset
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]

            if pe_offset >= len(data) or data[pe_offset:pe_offset+4] != b"PE\x00\x00":
                return {"error": "Invalid PE header"}

            # Parse COFF header
            coff_header = data[pe_offset+4:pe_offset+24]
            machine, num_sections, timestamp, symbol_table_offset, num_symbols, optional_header_size, characteristics = \
                struct.unpack("<HHIIIHH", coff_header)

            pe_info.update({
                "machine": f"0x{machine:04x}",
                "num_sections": num_sections,
                "timestamp": datetime.fromtimestamp(timestamp).isoformat() if timestamp > 0 else "N/A",
                "characteristics": f"0x{characteristics:04x}",
                "sections": []
            })

            # Parse sections
            section_table_offset = pe_offset + 24 + optional_header_size
            for i in range(num_sections):
                section_offset = section_table_offset + (i * 40)
                if section_offset + 40 > len(data):
                    break

                section_data = data[section_offset:section_offset+40]
                name = section_data[:8].decode("utf-8", errors="ignore").rstrip("\x00")
                virtual_size, virtual_address, raw_size, raw_address = struct.unpack("<IIII", section_data[8:24])

                pe_info["sections"].append({
                    "name": name,
                    "virtual_address": f"0x{virtual_address:08x}",
                    "virtual_size": virtual_size,
                    "raw_size": raw_size,
                    "raw_address": f"0x{raw_address:08x}"
                })

            return pe_info

        except Exception as e:
            return {"error": str(e)}

    def _analyze_elf(self, file_path: Path) -> Dict[str, Any]:
        """Analyze ELF (Linux executable) file."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            if data[:4] != b"\x7fELF":
                return {"error": "Invalid ELF header"}

            elf_info = {}

            # Parse ELF header
            ei_class = data[4]
            ei_data = data[5]
            ei_version = data[6]

            elf_info.update({
                "class": "64-bit" if ei_class == 2 else "32-bit",
                "data": "little-endian" if ei_data == 1 else "big-endian",
                "version": ei_version,
                "segments": [],
                "sections": []
            })

            # Parse program headers (segments)
            if ei_class == 2:  # 64-bit
                e_type, e_machine, e_version, e_entry, e_phoff, e_shoff = struct.unpack("<HHIQQQQ", data[16:48])[:6]
                e_phentsize, e_phnum = struct.unpack("<HH", data[54:58])
            else:  # 32-bit
                e_type, e_machine, e_version, e_entry, e_phoff, e_shoff = struct.unpack("<HHIIII", data[16:36])[:6]
                e_phentsize, e_phnum = struct.unpack("<HH", data[42:46])

            elf_info.update({
                "type": {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, f"Unknown({e_type})"),
                "machine": f"0x{e_machine:04x}",
                "entry_point": f"0x{e_entry:08x}"
            })

            # Parse program headers
            for i in range(min(e_phnum, 20)):  # Limit to prevent excessive parsing
                ph_offset = e_phoff + (i * e_phentsize)
                if ph_offset + e_phentsize > len(data):
                    break

                if ei_class == 2:  # 64-bit
                    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                        struct.unpack("<IIQQQQQQ", data[ph_offset:ph_offset+56])
                else:  # 32-bit
                    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                        struct.unpack("<IIIIIIII", data[ph_offset:ph_offset+32])

                segment_types = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
                               5: "SHLIB", 6: "PHDR", 7: "TLS"}

                elf_info["segments"].append({
                    "type": segment_types.get(p_type, f"Unknown({p_type})"),
                    "offset": f"0x{p_offset:08x}",
                    "vaddr": f"0x{p_vaddr:08x}",
                    "filesz": p_filesz,
                    "memsz": p_memsz,
                    "flags": self._get_segment_flags(p_flags)
                })

            return elf_info

        except Exception as e:
            return {"error": str(e)}

    def _get_segment_flags(self, flags: int) -> str:
        """Convert segment flags to readable string."""
        flag_str = ""
        if flags & 0x1:  # PF_X
            flag_str += "X"
        if flags & 0x2:  # PF_W
            flag_str += "W"
        if flags & 0x4:  # PF_R
            flag_str += "R"
        return flag_str or "None"

    def _analyze_macho(self, file_path: Path) -> Dict[str, Any]:
        """Analyze Mach-O (macOS executable) file."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            if len(data) < 32:
                return {"error": "File too small for Mach-O"}

            magic = struct.unpack("<I", data[:4])[0]

            macho_info = {}

            # Determine architecture and endianness
            if magic == 0xfeedface:  # 32-bit little-endian
                is_64 = False
                endian = "<"
            elif magic == 0xfeedfacf:  # 64-bit little-endian
                is_64 = True
                endian = "<"
            elif magic == 0xcefaedfe:  # 32-bit big-endian
                is_64 = False
                endian = ">"
            elif magic == 0xcffaedfe:  # 64-bit big-endian
                is_64 = True
                endian = ">"
            else:
                return {"error": "Invalid Mach-O magic"}

            # Parse header
            if is_64:
                cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags = \
                    struct.unpack(endian + "IIIIII", data[4:28])
                offset = 32
            else:
                cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags = \
                    struct.unpack(endian + "IIIIII", data[4:28])
                offset = 28

            macho_info.update({
                "architecture": "64-bit" if is_64 else "32-bit",
                "cpu_type": f"0x{cpu_type:08x}",
                "file_type": file_type,
                "num_commands": ncmds,
                "commands_size": sizeofcmds,
                "flags": f"0x{flags:08x}",
                "load_commands": []
            })

            # Parse load commands (limit to prevent excessive parsing)
            for _i in range(min(ncmds, 50)):
                if offset + 8 > len(data):
                    break

                cmd, cmdsize = struct.unpack(endian + "II", data[offset:offset+8])

                macho_info["load_commands"].append({
                    "cmd": f"0x{cmd:08x}",
                    "cmdsize": cmdsize
                })

                offset += cmdsize

            return macho_info

        except Exception as e:
            return {"error": str(e)}

    def _analyze_dex(self, file_path: Path) -> Dict[str, Any]:
        """Analyze Android DEX file."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            if data[:4] != b"dex\n":
                return {"error": "Invalid DEX header"}

            dex_info = {
                "version": data[4:7].decode("utf-8", errors="ignore"),
                "file_size": len(data),
                "strings": []
            }

            # Parse DEX header
            if len(data) >= 0x70:
                checksum = struct.unpack("<I", data[8:12])[0]
                signature = data[12:32].hex()
                file_size = struct.unpack("<I", data[32:36])[0]
                header_size = struct.unpack("<I", data[36:40])[0]

                dex_info.update({
                    "checksum": f"0x{checksum:08x}",
                    "signature": signature,
                    "declared_size": file_size,
                    "header_size": header_size
                })

                # String IDs
                string_ids_size = struct.unpack("<I", data[56:60])[0]
                string_ids_off = struct.unpack("<I", data[60:64])[0]

                dex_info["string_count"] = string_ids_size

                # Extract some strings (limit to first 10)
                for i in range(min(string_ids_size, 10)):
                    try:
                        str_offset_addr = string_ids_off + (i * 4)
                        if str_offset_addr + 4 <= len(data):
                            str_offset = struct.unpack("<I", data[str_offset_addr:str_offset_addr+4])[0]
                            if str_offset < len(data):
                                # Simple ULEB128 decoding for string length
                                length = 0
                                shift = 0
                                pos = str_offset
                                while pos < len(data):
                                    byte = data[pos]
                                    pos += 1
                                    length |= (byte & 0x7f) << shift
                                    if (byte & 0x80) == 0:
                                        break
                                    shift += 7

                                if pos + length <= len(data):
                                    string = data[pos:pos+length].decode("utf-8", errors="ignore")
                                    dex_info["strings"].append(string)
                    except (UnicodeDecodeError, IndexError, struct.error):
                        continue

            return dex_info

        except Exception as e:
            return {"error": str(e)}

    def _analyze_archive(self, file_path: Path) -> Dict[str, Any]:
        """Analyze archive files (ZIP, JAR, APK)."""
        try:
            import zipfile

            archive_info = {
                "type": "Archive",
                "files": [],
                "total_files": 0,
                "compressed_size": 0,
                "uncompressed_size": 0
            }

            with zipfile.ZipFile(file_path, "r") as zf:
                archive_info["total_files"] = len(zf.filelist)

                # Check if it's an APK
                if "AndroidManifest.xml" in zf.namelist():
                    archive_info["type"] = "APK"
                # Check if it's a JAR
                elif any(name.endswith(".class") for name in zf.namelist()):
                    archive_info["type"] = "JAR"

                # Analyze files (limit to first 20)
                for _i, file_info in enumerate(zf.filelist[:20]):
                    archive_info["files"].append({
                        "filename": file_info.filename,
                        "compressed_size": file_info.compress_size,
                        "uncompressed_size": file_info.file_size,
                        "crc32": f"0x{file_info.CRC:08x}"
                    })

                    archive_info["compressed_size"] += file_info.compress_size
                    archive_info["uncompressed_size"] += file_info.file_size

                # Calculate compression ratio
                if archive_info["uncompressed_size"] > 0:
                    archive_info["compression_ratio"] = \
                        (1 - archive_info["compressed_size"] / archive_info["uncompressed_size"]) * 100

            return archive_info

        except Exception as e:
            return {"error": str(e)}

    def _extract_strings(self, file_path: Path) -> List[str]:
        """Extract printable strings from binary data."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            strings = []
            min_length = 4
            current_string = bytearray()

            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string.append(byte)
                else:
                    if len(current_string) >= min_length:
                        string = current_string.decode("ascii", errors="ignore")
                        if not all(c in "0123456789ABCDEFabcdef" for c in string):
                            strings.append(string)
                    current_string = bytearray()

            # Check last string
            if len(current_string) >= min_length:
                strings.append(current_string.decode("ascii", errors="ignore"))

            return strings[:100]  # Limit to 100 strings

        except Exception as e:
            return [f"Error extracting strings: {e}"]

    def _analyze_entropy(self, file_path: Path) -> Dict[str, Any]:
        """Analyze entropy distribution in the file."""
        try:
            import math

            with open(file_path, "rb") as f:
                data = f.read()

            # Calculate overall entropy
            byte_counts = {}
            for byte in data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1

            data_len = len(data)
            entropy = 0.0

            for count in byte_counts.values():
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)

            entropy_info = {
                "overall_entropy": round(entropy, 4),
                "file_size": data_len,
                "unique_bytes": len(byte_counts),
                "analysis": "Normal" if entropy < 7.0 else "High (possibly packed/encrypted)"
            }

            return entropy_info

        except Exception as e:
            return {"error": str(e)}

    def _security_analysis(self, file_path: Path, file_format: str) -> Dict[str, Any]:
        """Perform security-focused analysis."""
        try:
            security_info = {
                "risk_level": "Unknown",
                "suspicious_indicators": [],
                "recommendations": []
            }

            # Basic file size check
            file_size = file_path.stat().st_size
            if file_size == 0:
                security_info["suspicious_indicators"].append("Empty file")
                security_info["risk_level"] = "Low"
            elif file_size > 100 * 1024 * 1024:  # > 100MB
                security_info["suspicious_indicators"].append("Very large file size")
                security_info["risk_level"] = "Medium"
            else:
                security_info["risk_level"] = "Low"

            # Format-specific checks
            if file_format == "Unknown":
                security_info["suspicious_indicators"].append("Unknown file format")
                security_info["risk_level"] = "Medium"
            elif file_format in ["PE", "ELF", "Mach-O"]:
                security_info["recommendations"].append("Run in sandboxed environment")
                security_info["recommendations"].append("Scan with antivirus")

            return security_info

        except Exception as e:
            return {"error": str(e)}
