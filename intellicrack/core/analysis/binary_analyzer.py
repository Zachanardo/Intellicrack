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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import json
import logging
import mmap
import struct
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any


class BinaryAnalyzer:
    """Core binary analysis engine for executable file examination."""

    LARGE_FILE_THRESHOLD = 50 * 1024 * 1024
    CHUNK_SIZE = 8 * 1024 * 1024
    HASH_CHUNK_SIZE = 64 * 1024

    def __init__(self) -> None:
        """Initialize the binary analyzer.

        Sets up the core binary analysis engine with support for multiple
        executable formats including PE, ELF, Mach-O, DEX, and archives.
        Initializes format detection capabilities and analysis components.
        """
        self.logger = logging.getLogger(__name__)

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
            b"%PDF": "PDF Document",
        }

    def analyze(self, binary_path: str | Path, use_streaming: bool | None = None) -> dict[str, Any]:
        """Perform comprehensive binary analysis.

        Args:
            binary_path: Path to the binary file.
            use_streaming: Force streaming mode (None = auto-detect based on size).

        Returns:
            Analysis results dictionary with format, metadata, hashes, and security information.

        Raises:
            FileNotFoundError: If binary file does not exist.
            OSError: If file operations fail.
        """
        try:
            binary_path = Path(binary_path)

            if not binary_path.exists():
                return {"error": f"File not found: {binary_path}"}

            if not binary_path.is_file():
                return {"error": f"Not a file: {binary_path}"}

            file_info = self._get_file_info(binary_path)
            file_size = file_info.get("size", 0)

            if use_streaming is None:
                use_streaming = file_size > self.LARGE_FILE_THRESHOLD

            if use_streaming:
                self.logger.info("Using streaming analysis for large binary: %d bytes", file_size)
                return self._analyze_streaming(binary_path, file_info)

            file_format = self._detect_format(binary_path)
            hashes = self._calculate_hashes(binary_path)

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

            strings_info = self._extract_strings(binary_path)
            entropy_info = self._analyze_entropy(binary_path)
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
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            self.logger.exception("Binary analysis failed: %s", e)
            return {"error": str(e), "analysis_status": "failed"}

    def _analyze_streaming(self, binary_path: Path, file_info: dict[str, Any]) -> dict[str, Any]:
        """Perform streaming analysis for large binaries.

        Args:
            binary_path: Path to the binary file.
            file_info: Pre-computed file information.

        Returns:
            Analysis results dictionary with streaming mode enabled.

        Raises:
            OSError: If file cannot be read or analyzed.
        """
        try:
            file_format = self._detect_format_streaming(binary_path)
            hashes = self._calculate_hashes_streaming(binary_path)

            format_analysis = {}
            if file_format == "PE":
                format_analysis = self._analyze_pe_streaming(binary_path)
            elif file_format == "ELF":
                format_analysis = self._analyze_elf_streaming(binary_path)
            elif file_format.startswith("Mach-O"):
                format_analysis = self._analyze_macho_streaming(binary_path)

            strings_info = self._extract_strings_streaming(binary_path)
            entropy_info = self._analyze_entropy_streaming(binary_path)
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
                "streaming_mode": True,
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            self.logger.exception("Streaming analysis failed: %s", e)
            return {"error": str(e), "analysis_status": "failed"}

    def _open_mmap(self, file_path: Path) -> tuple[Any, Any]:
        """Open file with memory mapping for efficient large file access.

        Args:
            file_path: Path to file.

        Returns:
            Tuple of (file_handle, mmap_object).

        Raises:
            OSError: If file descriptor is invalid.
            RuntimeError: If memory map creation fails.
        """
        file_handle = open(file_path, "rb")  # noqa: SIM115
        try:
            if file_handle.fileno() == -1:
                raise OSError("Invalid file descriptor")
            mmap_obj = mmap.mmap(file_handle.fileno(), 0, access=mmap.ACCESS_READ)
            return file_handle, mmap_obj
        except (OSError, ValueError) as e:
            file_handle.close()
            raise RuntimeError(f"Failed to create memory map: {e}") from e

    def _read_chunks(self, file_path: Path, chunk_size: int | None = None) -> Iterator[tuple[bytes, int]]:
        """Generate chunks of file data for streaming analysis.

        Args:
            file_path: Path to file.
            chunk_size: Size of each chunk (default: CHUNK_SIZE).

        Yields:
            Tuple of (chunk_data, offset).

        Raises:
            OSError: If file cannot be opened or read.
        """
        if chunk_size is None:
            chunk_size = self.CHUNK_SIZE

        with open(file_path, "rb") as f:
            offset = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk, offset
                offset += len(chunk)

    def _detect_format_streaming(self, file_path: Path) -> str:
        """Detect file format using streaming read.

        Args:
            file_path: Path to file.

        Returns:
            Detected format string (e.g., "PE", "ELF", "Unknown").

        Raises:
            OSError: If file cannot be opened or read.
        """
        try:
            with open(file_path, "rb") as f:
                header = f.read(8)

            for magic, format_name in self.magic_bytes.items():
                if header.startswith(magic):
                    return format_name

            try:
                with open(file_path, encoding="utf-8") as f:
                    text = f.read(1000)
                    if text.startswith("#!/"):
                        return "Script"
                    if text.startswith("<?xml"):
                        return "XML"
                    if text.startswith(("{", "[")):
                        return "JSON"
            except (UnicodeDecodeError, AttributeError):
                pass

            return "Unknown"
        except Exception as e:
            return f"Error: {e}"

    def _calculate_hashes_streaming(self, file_path: Path, progress_callback: Callable[[int, int], None] | None = None) -> dict[str, str]:
        """Calculate file hashes using streaming to avoid loading entire file.

        Args:
            file_path: Path to file.
            progress_callback: Optional callback for progress updates (bytes_processed, total_bytes).

        Returns:
            Dictionary of hash algorithm names to hexadecimal digest strings.

        Raises:
            OSError: If file cannot be opened or read.
        """
        try:
            sha256_hash = hashlib.sha256()
            sha512_hash = hashlib.sha512()
            sha3_256_hash = hashlib.sha3_256()
            blake2b_hash = hashlib.blake2b()

            file_size = file_path.stat().st_size
            bytes_processed = 0

            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(self.HASH_CHUNK_SIZE)
                    if not chunk:
                        break

                    sha256_hash.update(chunk)
                    sha512_hash.update(chunk)
                    sha3_256_hash.update(chunk)
                    blake2b_hash.update(chunk)

                    bytes_processed += len(chunk)

                    if progress_callback:
                        progress_callback(bytes_processed, file_size)

            return {
                "sha256": sha256_hash.hexdigest(),
                "sha512": sha512_hash.hexdigest(),
                "sha3_256": sha3_256_hash.hexdigest(),
                "blake2b": blake2b_hash.hexdigest(),
            }
        except Exception as e:
            return {"error": str(e)}

    def _analyze_pe_streaming(self, file_path: Path) -> dict[str, Any]:
        """Analyze PE file using memory mapping for large files.

        Args:
            file_path: Path to PE file.

        Returns:
            PE analysis results including machine type, sections, and metadata.

        Raises:
            OSError: If file cannot be opened or memory-mapped.
            RuntimeError: If memory mapping fails.
        """
        try:
            file_handle, mm = self._open_mmap(file_path)
            try:
                pe_info: dict[str, Any] = {}

                if len(mm) < 64:
                    return {"error": "File too small for PE"}

                if mm[:2] != b"MZ":
                    return {"error": "Invalid DOS header"}

                pe_offset = struct.unpack("<I", mm[0x3C:0x40])[0]

                if pe_offset >= len(mm) or mm[pe_offset : pe_offset + 4] != b"PE\x00\x00":
                    return {"error": "Invalid PE header"}

                coff_header = mm[pe_offset + 4 : pe_offset + 24]
                (
                    machine,
                    num_sections,
                    timestamp,
                    _symbol_table_offset,
                    _num_symbols,
                    optional_header_size,
                    characteristics,
                ) = struct.unpack("<HHIIIHH", coff_header)

                pe_info |= {
                    "machine": f"0x{machine:04x}",
                    "num_sections": num_sections,
                    "timestamp": (datetime.fromtimestamp(timestamp).isoformat() if timestamp > 0 else "N/A"),
                    "characteristics": f"0x{characteristics:04x}",
                    "sections": [],
                }

                section_table_offset = pe_offset + 24 + optional_header_size
                for i in range(num_sections):
                    section_offset = section_table_offset + (i * 40)
                    if section_offset + 40 > len(mm):
                        break

                    section_data = mm[section_offset : section_offset + 40]
                    name = section_data[:8].decode("utf-8", errors="ignore").rstrip("\x00")
                    virtual_size, virtual_address, raw_size, raw_address = struct.unpack("<IIII", section_data[8:24])

                    pe_info["sections"].append(
                        {
                            "name": name,
                            "virtual_address": f"0x{virtual_address:08x}",
                            "virtual_size": virtual_size,
                            "raw_size": raw_size,
                            "raw_address": f"0x{raw_address:08x}",
                        },
                    )

                return pe_info

            finally:
                mm.close()
                file_handle.close()

        except Exception as e:
            return {"error": str(e)}

    def _analyze_elf_streaming(self, file_path: Path) -> dict[str, Any]:
        """Analyze ELF file using memory mapping.

        Args:
            file_path: Path to ELF file.

        Returns:
            ELF analysis results including class, architecture, segments, and metadata.

        Raises:
            OSError: If file cannot be opened or memory-mapped.
            RuntimeError: If memory mapping fails.
        """
        try:
            file_handle, mm = self._open_mmap(file_path)
            try:
                if len(mm) < 64:
                    return {"error": "File too small for ELF"}

                if mm[:4] != b"\x7fELF":
                    return {"error": "Invalid ELF header"}

                elf_info: dict[str, Any] = {}

                ei_class = mm[4]
                ei_data = mm[5]
                ei_version = mm[6]

                elf_info |= {
                    "class": "64-bit" if ei_class == 2 else "32-bit",
                    "data": "little-endian" if ei_data == 1 else "big-endian",
                    "version": ei_version,
                    "segments": [],
                    "sections": [],
                }

                if ei_class == 2:
                    e_type, e_machine, _, e_entry, e_phoff, _ = struct.unpack("<HHIQQQQ", mm[16:48])[:6]
                    e_phentsize, e_phnum = struct.unpack("<HH", mm[54:58])
                else:
                    e_type, e_machine, _, e_entry, e_phoff, _ = struct.unpack("<HHIIII", mm[16:36])[:6]
                    e_phentsize, e_phnum = struct.unpack("<HH", mm[42:46])

                elf_info |= {
                    "type": {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, f"Unknown({e_type})"),
                    "machine": f"0x{e_machine:04x}",
                    "entry_point": f"0x{e_entry:08x}",
                }

                for i in range(min(e_phnum, 20)):
                    ph_offset = e_phoff + (i * e_phentsize)
                    if ph_offset + e_phentsize > len(mm):
                        break

                    if ei_class == 2:
                        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack(
                            "<IIQQQQQQ",
                            mm[ph_offset : ph_offset + 56],
                        )
                    else:
                        p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = struct.unpack(
                            "<IIIIIIII",
                            mm[ph_offset : ph_offset + 32],
                        )

                    segment_types = {
                        0: "NULL",
                        1: "LOAD",
                        2: "DYNAMIC",
                        3: "INTERP",
                        4: "NOTE",
                        5: "SHLIB",
                        6: "PHDR",
                        7: "TLS",
                    }

                    elf_info["segments"].append(
                        {
                            "type": segment_types.get(p_type, f"Unknown({p_type})"),
                            "offset": f"0x{p_offset:08x}",
                            "vaddr": f"0x{p_vaddr:08x}",
                            "filesz": p_filesz,
                            "memsz": p_memsz,
                            "flags": self._get_segment_flags(p_flags),
                        },
                    )

                return elf_info

            finally:
                mm.close()
                file_handle.close()

        except Exception as e:
            return {"error": str(e)}

    def _analyze_macho_streaming(self, file_path: Path) -> dict[str, Any]:
        """Analyze Mach-O file using memory mapping.

        Args:
            file_path: Path to Mach-O file.

        Returns:
            Mach-O analysis results including architecture, load commands, and metadata.

        Raises:
            OSError: If file cannot be opened or memory-mapped.
            RuntimeError: If memory mapping fails.
        """
        try:
            file_handle, mm = self._open_mmap(file_path)
            try:
                if len(mm) < 32:
                    return {"error": "File too small for Mach-O"}

                magic = struct.unpack("<I", mm[:4])[0]

                macho_info: dict[str, Any] = {}

                if magic == 0xCEFAEDFE:
                    is_64 = False
                    endian = ">"
                elif magic == 0xCFFAEDFE:
                    is_64 = True
                    endian = ">"
                elif magic == 0xFEEDFACE:
                    is_64 = False
                    endian = "<"
                elif magic == 0xFEEDFACF:
                    is_64 = True
                    endian = "<"
                else:
                    return {"error": "Invalid Mach-O magic"}

                cpu_type, _, file_type, ncmds, sizeofcmds, flags = struct.unpack(f"{endian}IIIIII", mm[4:28])
                offset = 32 if is_64 else 28
                macho_info |= {
                    "architecture": "64-bit" if is_64 else "32-bit",
                    "cpu_type": f"0x{cpu_type:08x}",
                    "file_type": file_type,
                    "num_commands": ncmds,
                    "commands_size": sizeofcmds,
                    "flags": f"0x{flags:08x}",
                    "load_commands": [],
                }

                for _i in range(min(ncmds, 50)):
                    if offset + 8 > len(mm):
                        break

                    cmd, cmdsize = struct.unpack(f"{endian}II", mm[offset : offset + 8])

                    macho_info["load_commands"].append(
                        {
                            "cmd": f"0x{cmd:08x}",
                            "cmdsize": cmdsize,
                        },
                    )

                    offset += cmdsize

                return macho_info

            finally:
                mm.close()
                file_handle.close()

        except Exception as e:
            return {"error": str(e)}

    def _extract_strings_streaming(self, file_path: Path, max_strings: int = 100) -> list[str]:
        """Extract strings from large binary using streaming.

        Args:
            file_path: Path to file.
            max_strings: Maximum number of strings to extract.

        Returns:
            List of extracted printable ASCII strings.

        Raises:
            OSError: If file cannot be opened or read.
        """
        try:
            strings = []
            min_length = 4
            current_string = bytearray()

            for chunk, _offset in self._read_chunks(file_path):
                for byte in chunk:
                    if 32 <= byte <= 126:
                        current_string.append(byte)
                    else:
                        if len(current_string) >= min_length:
                            string = current_string.decode("ascii", errors="ignore")
                            if any(c not in "0123456789ABCDEFabcdef" for c in string):
                                strings.append(string)
                                if len(strings) >= max_strings:
                                    return strings
                        current_string = bytearray()

                if len(strings) >= max_strings:
                    break

            if len(current_string) >= min_length and len(strings) < max_strings:
                strings.append(current_string.decode("ascii", errors="ignore"))

            return strings

        except Exception as e:
            return [f"Error extracting strings: {e}"]

    def _analyze_entropy_streaming(self, file_path: Path) -> dict[str, Any]:
        """Analyze entropy using streaming for large files.

        Args:
            file_path: Path to file.

        Returns:
            Entropy analysis results including overall entropy, file size, and classification.

        Raises:
            OSError: If file cannot be opened or read.
        """
        try:
            import math

            byte_counts: dict[int, int] = {}
            total_bytes = 0

            for chunk, _offset in self._read_chunks(file_path):
                for byte in chunk:
                    byte_counts[byte] = byte_counts.get(byte, 0) + 1
                    total_bytes += 1

            entropy = 0.0
            for count in byte_counts.values():
                if count > 0:
                    probability = count / total_bytes
                    entropy -= probability * math.log2(probability)

            return {
                "overall_entropy": round(entropy, 4),
                "file_size": total_bytes,
                "unique_bytes": len(byte_counts),
                "analysis": ("Normal" if entropy < 7.0 else "High (possibly packed/encrypted)"),
            }
        except Exception as e:
            return {"error": str(e)}

    def analyze_with_progress(
        self,
        binary_path: str | Path,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ) -> dict[str, Any]:
        """Analyze binary with progress tracking for large files.

        Args:
            binary_path: Path to binary file.
            progress_callback: Callback function(stage, current, total). If provided,
                will be called with (stage_name, current_count, total_count).

        Returns:
            Analysis results dictionary with progress tracking enabled.

        Raises:
            FileNotFoundError: If binary file does not exist.
            OSError: If file operations fail.
        """
        try:
            binary_path = Path(binary_path)

            if not binary_path.exists():
                return {"error": f"File not found: {binary_path}"}

            if not binary_path.is_file():
                return {"error": f"Not a file: {binary_path}"}

            file_info = self._get_file_info(binary_path)
            file_info.get("size", 0)

            stages = [
                "format_detection",
                "hash_calculation",
                "format_analysis",
                "string_extraction",
                "entropy_analysis",
            ]
            current_stage = 0
            total_stages = len(stages)

            def update_progress(stage_name: str) -> None:
                """Update progress callback for current stage.

                Args:
                    stage_name: Name of the current analysis stage.

                Returns:
                    None.
                """
                nonlocal current_stage
                if progress_callback:
                    progress_callback(stage_name, current_stage, total_stages)
                current_stage += 1

            update_progress(stages[0])
            file_format = self._detect_format_streaming(binary_path)

            update_progress(stages[1])

            def hash_progress(current: int, total: int) -> None:
                """Report hash calculation progress.

                Args:
                    current: Number of bytes processed.
                    total: Total number of bytes to process.

                Returns:
                    None.
                """
                if progress_callback:
                    progress_callback(f"hash_calculation: {current}/{total}", current, total)

            hashes = self._calculate_hashes_streaming(binary_path, hash_progress)

            update_progress(stages[2])
            format_analysis = {}
            if file_format == "PE":
                format_analysis = self._analyze_pe_streaming(binary_path)
            elif file_format == "ELF":
                format_analysis = self._analyze_elf_streaming(binary_path)
            elif file_format.startswith("Mach-O"):
                format_analysis = self._analyze_macho_streaming(binary_path)

            update_progress(stages[3])
            strings_info = self._extract_strings_streaming(binary_path)

            update_progress(stages[4])
            entropy_info = self._analyze_entropy_streaming(binary_path)

            security_info = self._security_analysis(binary_path, file_format)

            if progress_callback:
                progress_callback("completed", total_stages, total_stages)

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
                "streaming_mode": True,
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            self.logger.exception("Analysis with progress failed: %s", e)
            return {"error": str(e), "analysis_status": "failed"}

    def save_analysis_checkpoint(self, analysis_results: dict[str, Any], checkpoint_path: str | Path) -> bool:
        """Save analysis checkpoint for resumable operations.

        Args:
            analysis_results: Partial or complete analysis results.
            checkpoint_path: Path to save checkpoint file.

        Returns:
            True if successful, False otherwise.

        Raises:
            OSError: If checkpoint file cannot be written.
        """
        try:
            checkpoint_path = Path(checkpoint_path)
            checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

            with open(checkpoint_path, "w", encoding="utf-8") as f:
                json.dump(analysis_results, f, indent=2)

            return True

        except Exception as e:
            self.logger.exception("Failed to save checkpoint: %s", e)
            return False

    def load_analysis_checkpoint(self, checkpoint_path: str | Path) -> dict[str, Any] | None:
        """Load analysis checkpoint to resume interrupted operations.

        Args:
            checkpoint_path: Path to checkpoint file.

        Returns:
            Checkpoint data dictionary or None if file not found or failed to load.

        Raises:
            OSError: If checkpoint file cannot be read.
            json.JSONDecodeError: If checkpoint file is not valid JSON.
        """
        try:
            checkpoint_path = Path(checkpoint_path)

            if not checkpoint_path.exists():
                return None

            with open(checkpoint_path, encoding="utf-8") as f:
                result: dict[str, Any] = json.load(f)
                return result

        except Exception as e:
            self.logger.exception("Failed to load checkpoint: %s", e)
            return None

    def scan_for_patterns_streaming(
        self, binary_path: str | Path, patterns: list[bytes], context_bytes: int = 32
    ) -> dict[str, list[dict[str, Any]]]:
        """Scan large binary for multiple byte patterns using streaming.

        Args:
            binary_path: Path to binary file.
            patterns: List of byte patterns to search for.
            context_bytes: Number of bytes before/after match to include.

        Returns:
            Dictionary mapping pattern hex string to list of matches with offsets and context.

        Raises:
            OSError: If file cannot be read.
        """
        try:
            binary_path = Path(binary_path)
            results: dict[str, list[dict[str, Any]]] = {pattern.hex(): [] for pattern in patterns}

            overlap_size = max(len(p) for p in patterns) - 1
            previous_chunk_tail = b""

            for chunk, chunk_offset in self._read_chunks(binary_path):
                search_data = previous_chunk_tail + chunk
                search_offset = chunk_offset - len(previous_chunk_tail)

                for pattern in patterns:
                    offset = 0
                    while True:
                        pos = search_data.find(pattern, offset)
                        if pos == -1:
                            break

                        actual_offset = search_offset + pos
                        context_start = max(0, pos - context_bytes)
                        context_end = min(len(search_data), pos + len(pattern) + context_bytes)
                        search_data[context_start:context_end]

                        results[pattern.hex()].append(
                            {
                                "offset": actual_offset,
                                "context_before": search_data[max(0, pos - context_bytes) : pos].hex(),
                                "match": pattern.hex(),
                                "context_after": search_data[pos + len(pattern) : context_end].hex(),
                            },
                        )

                        offset = pos + 1

                previous_chunk_tail = chunk[-overlap_size:] if len(chunk) > overlap_size else chunk

            return results

        except Exception as e:
            self.logger.exception("Pattern scanning failed: %s", e)
            return {"error": [{"error": str(e)}]}

    def scan_for_license_strings_streaming(self, binary_path: str | Path) -> list[dict[str, Any]]:
        """Scan large binary for licensing-related strings using streaming.

        Args:
            binary_path: Path to binary file.

        Returns:
            List of licensing-related string matches with offsets, patterns, and lengths (limited to 500 results).

        Raises:
            OSError: If file cannot be read.
        """
        license_patterns = [
            b"serial",
            b"license",
            b"activation",
            b"registration",
            b"product key",
            b"unlock code",
            b"trial",
            b"expired",
            b"validate",
            b"authenticate",
        ]

        try:
            binary_path = Path(binary_path)
            results = []

            for chunk, chunk_offset in self._read_chunks(binary_path):
                for i in range(len(chunk) - 4):
                    if 32 <= chunk[i] <= 126:
                        string_start = i
                        string_bytes = bytearray()

                        while i < len(chunk) and 32 <= chunk[i] <= 126:
                            string_bytes.append(chunk[i])
                            i += 1

                        if len(string_bytes) >= 6:
                            string_lower = string_bytes.lower()
                            for pattern in license_patterns:
                                if pattern in string_lower:
                                    try:
                                        decoded_string = string_bytes.decode("ascii", errors="ignore")
                                        results.append(
                                            {
                                                "offset": chunk_offset + string_start,
                                                "string": decoded_string,
                                                "pattern_matched": pattern.decode("ascii"),
                                                "length": len(string_bytes),
                                            },
                                        )
                                    except Exception as e:
                                        self.logger.debug("Error decoding license string at offset %d: %s", chunk_offset + string_start, e)
                                    break

            return results[:500]

        except Exception as e:
            self.logger.exception("License string scanning failed: %s", e)
            return [{"error": str(e)}]

    def analyze_sections_streaming(self, binary_path: str | Path, section_ranges: list[tuple[int, int]]) -> dict[str, Any]:
        """Analyze specific sections of large binary using memory mapping.

        Args:
            binary_path: Path to binary file.
            section_ranges: List of (start_offset, end_offset) tuples.

        Returns:
            Dictionary mapping section indices to analysis results including entropy and printable ratios.

        Raises:
            OSError: If file cannot be opened or memory-mapped.
            RuntimeError: If memory mapping fails.
        """
        try:
            binary_path = Path(binary_path)
            results: dict[str, Any] = {}

            file_handle, mm = self._open_mmap(binary_path)
            try:
                for idx, (start, end) in enumerate(section_ranges):
                    if start < 0 or end > len(mm) or start >= end:
                        results[f"section_{idx}"] = {"error": "Invalid range"}
                        continue

                    section_data = mm[start:end]
                    section_size = len(section_data)

                    byte_counts: dict[int, int] = {}
                    for byte in section_data:
                        byte_counts[byte] = byte_counts.get(byte, 0) + 1

                    import math

                    entropy = 0.0
                    for count in byte_counts.values():
                        if count > 0:
                            probability = count / section_size
                            entropy -= probability * math.log2(probability)

                    printable_count = sum(32 <= byte <= 126 for byte in section_data)
                    null_count = byte_counts.get(0, 0)

                    printable_ratio = round(printable_count / section_size, 4) if section_size > 0 else 0.0
                    null_ratio = round(null_count / section_size, 4) if section_size > 0 else 0.0

                    results[f"section_{idx}"] = {
                        "range": f"0x{start:08x}-0x{end:08x}",
                        "size": section_size,
                        "entropy": round(entropy, 4),
                        "unique_bytes": len(byte_counts),
                        "printable_ratio": printable_ratio,
                        "null_ratio": null_ratio,
                        "characteristics": self._classify_section_characteristics(
                            entropy, printable_count / section_size if section_size > 0 else 0.0
                        ),
                    }

                return results

            finally:
                mm.close()
                file_handle.close()

        except Exception as e:
            self.logger.exception("Section analysis failed: %s", e)
            return {"error": str(e)}

    def _classify_section_characteristics(self, entropy: float, printable_ratio: float) -> str:
        """Classify section characteristics based on entropy and printable content.

        Args:
            entropy: Section entropy value.
            printable_ratio: Ratio of printable characters.

        Returns:
            Characteristic classification string.
        """
        if entropy > 7.5:
            return "Encrypted/Compressed"
        if entropy < 2.0:
            return "Highly Repetitive/Padded"
        if printable_ratio > 0.8:
            return "Text/Strings"
        if printable_ratio < 0.1 and entropy > 5.0:
            return "Code/Binary Data"
        return "Structured Binary" if 4.0 <= entropy < 6.0 else "Mixed Content"

    def _get_file_info(self, file_path: Path) -> dict[str, Any]:
        """Extract basic file metadata.

        Args:
            file_path: Path to the file to analyze.

        Returns:
            Dictionary containing file size, creation time, modification time, access time, and permissions. Returns error dict on failure.
        """
        try:
            stat = file_path.stat()
            return {
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
                "permissions": oct(stat.st_mode)[-3:] if hasattr(stat, "st_mode") else None,
            }
        except Exception as e:
            return {"error": str(e)}

    def _detect_format(self, file_path: Path) -> str:
        """Detect file format using magic bytes.

        Args:
            file_path: Path to the file to identify.

        Returns:
            File format string such as PE, ELF, Mach-O, or Unknown.

        Raises:
            OSError: If file cannot be opened or read.
        """
        try:
            with open(file_path, "rb") as f:
                header = f.read(8)

            for magic, format_name in self.magic_bytes.items():
                if header.startswith(magic):
                    return format_name

            # Additional checks for text-based formats
            try:
                with open(file_path, encoding="utf-8") as f:
                    text = f.read(1000)
                    if text.startswith("#!/"):
                        return "Script"
                    if text.startswith("<?xml"):
                        return "XML"
                    if text.startswith(("{", "[")):
                        return "JSON"
            except (UnicodeDecodeError, AttributeError):
                pass

            return "Unknown"
        except Exception as e:
            return f"Error: {e}"

    def _calculate_hashes(self, file_path: Path) -> dict[str, str]:
        """Calculate various hashes of the file.

        Args:
            file_path: Path to the file to hash.

        Returns:
            Dictionary mapping hash algorithm names to hexadecimal digest strings.

        Raises:
            OSError: If file cannot be opened or read.
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            return {
                "sha256": hashlib.sha256(data).hexdigest(),
                "sha512": hashlib.sha512(data).hexdigest(),
                "sha3_256": hashlib.sha3_256(data).hexdigest(),
                "blake2b": hashlib.blake2b(data).hexdigest(),
            }
        except Exception as e:
            return {"error": str(e)}

    def _analyze_pe(self, file_path: Path) -> dict[str, Any]:
        """Analyze PE (Windows executable) file.

        Args:
            file_path: Path to the PE file to analyze.

        Returns:
            Dictionary containing PE header information, sections, and metadata.

        Raises:
            OSError: If file cannot be opened or read.
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            pe_info: dict[str, Any] = {}

            if data[:2] != b"MZ":
                return {"error": "Invalid DOS header"}

            # Get PE header offset
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]

            if pe_offset >= len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
                return {"error": "Invalid PE header"}

            # Parse COFF header
            coff_header = data[pe_offset + 4 : pe_offset + 24]
            (
                machine,
                num_sections,
                timestamp,
                _symbol_table_offset,
                _num_symbols,
                optional_header_size,
                characteristics,
            ) = struct.unpack("<HHIIIHH", coff_header)

            pe_info |= {
                "machine": f"0x{machine:04x}",
                "num_sections": num_sections,
                "timestamp": (datetime.fromtimestamp(timestamp).isoformat() if timestamp > 0 else "N/A"),
                "characteristics": f"0x{characteristics:04x}",
                "sections": [],
            }

            # Parse sections
            section_table_offset = pe_offset + 24 + optional_header_size
            for i in range(num_sections):
                section_offset = section_table_offset + (i * 40)
                if section_offset + 40 > len(data):
                    break

                section_data = data[section_offset : section_offset + 40]
                name = section_data[:8].decode("utf-8", errors="ignore").rstrip("\x00")
                virtual_size, virtual_address, raw_size, raw_address = struct.unpack("<IIII", section_data[8:24])

                pe_info["sections"].append(
                    {
                        "name": name,
                        "virtual_address": f"0x{virtual_address:08x}",
                        "virtual_size": virtual_size,
                        "raw_size": raw_size,
                        "raw_address": f"0x{raw_address:08x}",
                    },
                )

            return pe_info

        except Exception as e:
            return {"error": str(e)}

    def _analyze_elf(self, file_path: Path) -> dict[str, Any]:
        """Analyze ELF (Linux executable) file.

        Args:
            file_path: Path to the ELF file to analyze.

        Returns:
            Dictionary containing ELF header information, segments, and metadata.

        Raises:
            OSError: If file cannot be opened or read.
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            if data[:4] != b"\x7fELF":
                return {"error": "Invalid ELF header"}

            elf_info: dict[str, Any] = {}

            ei_class = data[4]
            ei_data = data[5]
            ei_version = data[6]

            elf_info |= {
                "class": "64-bit" if ei_class == 2 else "32-bit",
                "data": "little-endian" if ei_data == 1 else "big-endian",
                "version": ei_version,
                "segments": [],
                "sections": [],
            }

            # Parse program headers (segments)
            if ei_class == 2:  # 64-bit
                e_type, e_machine, _, e_entry, e_phoff, _ = struct.unpack("<HHIQQQQ", data[16:48])[:6]
                e_phentsize, e_phnum = struct.unpack("<HH", data[54:58])
            else:  # 32-bit
                e_type, e_machine, _, e_entry, e_phoff, _ = struct.unpack("<HHIIII", data[16:36])[:6]
                e_phentsize, e_phnum = struct.unpack("<HH", data[42:46])

            elf_info |= {
                "type": {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, f"Unknown({e_type})"),
                "machine": f"0x{e_machine:04x}",
                "entry_point": f"0x{e_entry:08x}",
            }

            # Parse program headers
            for i in range(min(e_phnum, 20)):  # Limit to prevent excessive parsing
                ph_offset = e_phoff + (i * e_phentsize)
                if ph_offset + e_phentsize > len(data):
                    break

                if ei_class == 2:  # 64-bit
                    p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack(
                        "<IIQQQQQQ",
                        data[ph_offset : ph_offset + 56],
                    )
                else:  # 32-bit
                    p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = struct.unpack(
                        "<IIIIIIII",
                        data[ph_offset : ph_offset + 32],
                    )

                segment_types = {
                    0: "NULL",
                    1: "LOAD",
                    2: "DYNAMIC",
                    3: "INTERP",
                    4: "NOTE",
                    5: "SHLIB",
                    6: "PHDR",
                    7: "TLS",
                }

                elf_info["segments"].append(
                    {
                        "type": segment_types.get(p_type, f"Unknown({p_type})"),
                        "offset": f"0x{p_offset:08x}",
                        "vaddr": f"0x{p_vaddr:08x}",
                        "filesz": p_filesz,
                        "memsz": p_memsz,
                        "flags": self._get_segment_flags(p_flags),
                    },
                )

            return elf_info

        except Exception as e:
            return {"error": str(e)}

    def _get_segment_flags(self, flags: int) -> str:
        """Convert segment flags to readable string.

        Args:
            flags: Binary flags value from ELF segment header.

        Returns:
            String representation of flags (e.g., "RWX", "R", or "None").
        """
        flag_str = ""
        if flags & 0x1:  # PF_X
            flag_str += "X"
        if flags & 0x2:  # PF_W
            flag_str += "W"
        if flags & 0x4:  # PF_R
            flag_str += "R"
        return flag_str or "None"

    def _analyze_macho(self, file_path: Path) -> dict[str, Any]:
        """Analyze Mach-O (macOS executable) file.

        Args:
            file_path: Path to the Mach-O file to analyze.

        Returns:
            Dictionary containing Mach-O header information, load commands, and metadata.

        Raises:
            OSError: If file cannot be opened or read.
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            if len(data) < 32:
                return {"error": "File too small for Mach-O"}

            magic = struct.unpack("<I", data[:4])[0]

            macho_info: dict[str, Any] = {}

            if magic == 0xCEFAEDFE:
                is_64 = False
                endian = ">"
            elif magic == 0xCFFAEDFE:
                is_64 = True
                endian = ">"
            elif magic == 0xFEEDFACE:
                is_64 = False
                endian = "<"
            elif magic == 0xFEEDFACF:
                is_64 = True
                endian = "<"
            else:
                return {"error": "Invalid Mach-O magic"}

            cpu_type, _, file_type, ncmds, sizeofcmds, flags = struct.unpack(f"{endian}IIIIII", data[4:28])
            # Parse header
            offset = 32 if is_64 else 28
            macho_info |= {
                "architecture": "64-bit" if is_64 else "32-bit",
                "cpu_type": f"0x{cpu_type:08x}",
                "file_type": file_type,
                "num_commands": ncmds,
                "commands_size": sizeofcmds,
                "flags": f"0x{flags:08x}",
                "load_commands": [],
            }

            # Parse load commands (limit to prevent excessive parsing)
            for _i in range(min(ncmds, 50)):
                if offset + 8 > len(data):
                    break

                cmd, cmdsize = struct.unpack(f"{endian}II", data[offset : offset + 8])

                macho_info["load_commands"].append(
                    {
                        "cmd": f"0x{cmd:08x}",
                        "cmdsize": cmdsize,
                    },
                )

                offset += cmdsize

            return macho_info

        except Exception as e:
            return {"error": str(e)}

    def _analyze_dex(self, file_path: Path) -> dict[str, Any]:
        """Analyze Android DEX file.

        Args:
            file_path: Path to the DEX file to analyze.

        Returns:
            Dictionary containing DEX header information, string count, and metadata.

        Raises:
            OSError: If file cannot be opened or read.
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            if data[:4] != b"dex\n":
                return {"error": "Invalid DEX header"}

            dex_info = {
                "version": data[4:7].decode("utf-8", errors="ignore"),
                "file_size": len(data),
                "strings": [],
            }

            # Parse DEX header
            if len(data) >= 0x70:
                checksum = struct.unpack("<I", data[8:12])[0]
                signature = data[12:32].hex()
                file_size = struct.unpack("<I", data[32:36])[0]
                header_size = struct.unpack("<I", data[36:40])[0]

                dex_info |= {
                    "checksum": f"0x{checksum:08x}",
                    "signature": signature,
                    "declared_size": file_size,
                    "header_size": header_size,
                }

                # String IDs
                string_ids_size = struct.unpack("<I", data[56:60])[0]
                string_ids_off = struct.unpack("<I", data[60:64])[0]

                dex_info["string_count"] = string_ids_size

                # Extract some strings (limit to first 10)
                for i in range(min(string_ids_size, 10)):
                    try:
                        str_offset_addr = string_ids_off + (i * 4)
                        if str_offset_addr + 4 <= len(data):
                            str_offset = struct.unpack("<I", data[str_offset_addr : str_offset_addr + 4])[0]
                            if str_offset < len(data):
                                # Simple ULEB128 decoding for string length
                                length = 0
                                shift = 0
                                pos = str_offset
                                while pos < len(data):
                                    byte = data[pos]
                                    pos += 1
                                    length |= (byte & 0x7F) << shift
                                    if (byte & 0x80) == 0:
                                        break
                                    shift += 7

                                if pos + length <= len(data):
                                    string = data[pos : pos + length].decode("utf-8", errors="ignore")
                                    strings_list = dex_info.get("strings")
                                    if isinstance(strings_list, list):
                                        strings_list.append(string)
                    except (UnicodeDecodeError, IndexError, struct.error):
                        continue

            return dex_info

        except Exception as e:
            return {"error": str(e)}

    def _analyze_archive(self, file_path: Path) -> dict[str, Any]:
        """Analyze archive files (ZIP, JAR, APK).

        Args:
            file_path: Path to the archive file to analyze.

        Returns:
            Dictionary containing archive information, file listing, and compression statistics.

        Raises:
            OSError: If archive file cannot be opened or read.
            zipfile.BadZipFile: If archive is corrupted or not a valid ZIP file.
        """
        try:
            import zipfile

            archive_info = {
                "type": "Archive",
                "files": [],
                "total_files": 0,
                "compressed_size": 0,
                "uncompressed_size": 0,
            }

            with zipfile.ZipFile(file_path, "r") as zf:
                archive_info["total_files"] = len(zf.filelist)

                # Check if it's an APK
                if "AndroidManifest.xml" in zf.namelist():
                    archive_info["type"] = "APK"
                # Check if it's a JAR
                elif any(name.endswith(".class") for name in zf.namelist()):
                    archive_info["type"] = "JAR"

                for file_info in zf.filelist[:20]:
                    files_list = archive_info.get("files")
                    if isinstance(files_list, list):
                        files_list.append(
                            {
                                "filename": file_info.filename,
                                "compressed_size": file_info.compress_size,
                                "uncompressed_size": file_info.file_size,
                                "crc32": f"0x{file_info.CRC:08x}",
                            },
                        )

                    compressed = archive_info.get("compressed_size")
                    uncompressed = archive_info.get("uncompressed_size")
                    if isinstance(compressed, int) and isinstance(uncompressed, int):
                        archive_info["compressed_size"] = compressed + file_info.compress_size
                        archive_info["uncompressed_size"] = uncompressed + file_info.file_size

                uncompressed_size = archive_info.get("uncompressed_size")
                compressed_size = archive_info.get("compressed_size")
                if isinstance(uncompressed_size, int) and isinstance(compressed_size, int) and uncompressed_size > 0:
                    archive_info["compression_ratio"] = (1 - compressed_size / uncompressed_size) * 100

            return archive_info

        except Exception as e:
            return {"error": str(e)}

    def _extract_strings(self, file_path: Path) -> list[str]:
        """Extract printable strings from binary data.

        Args:
            file_path: Path to the binary file to scan.

        Returns:
            List of extracted printable ASCII strings (limited to 100 strings).

        Raises:
            OSError: If file cannot be opened or read.
        """
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
                        if any(c not in "0123456789ABCDEFabcdef" for c in string):
                            strings.append(string)
                    current_string = bytearray()

            # Check last string
            if len(current_string) >= min_length:
                strings.append(current_string.decode("ascii", errors="ignore"))

            return strings[:100]  # Limit to 100 strings

        except Exception as e:
            return [f"Error extracting strings: {e}"]

    def _analyze_entropy(self, file_path: Path) -> dict[str, Any]:
        """Analyze entropy distribution in the file.

        Args:
            file_path: Path to the binary file to analyze.

        Returns:
            Dictionary containing overall entropy value, file size, unique byte count, and analysis classification.

        Raises:
            OSError: If file cannot be opened or read.
        """
        try:
            import math

            with open(file_path, "rb") as f:
                data = f.read()

            byte_counts: dict[int, int] = {}
            for byte in data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1

            data_len = len(data)
            entropy = 0.0

            for count in byte_counts.values():
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)

            return {
                "overall_entropy": round(entropy, 4),
                "file_size": data_len,
                "unique_bytes": len(byte_counts),
                "analysis": ("Normal" if entropy < 7.0 else "High (possibly packed/encrypted)"),
            }
        except Exception as e:
            return {"error": str(e)}

    def _security_analysis(self, file_path: Path, file_format: str) -> dict[str, Any]:
        """Perform security-focused analysis.

        Args:
            file_path: Path to the binary file to analyze.
            file_format: Detected file format string.

        Returns:
            Dictionary containing risk assessment, suspicious indicators, recommendations, and protection details.

        Raises:
            OSError: If file metadata cannot be accessed.
        """
        try:
            security_info: dict[str, Any] = {
                "risk_level": "Unknown",
                "suspicious_indicators": [],
                "recommendations": [],
                "protection_detected": None,
            }

            file_size = file_path.stat().st_size
            susp_indicators = security_info.get("suspicious_indicators")
            recommendations = security_info.get("recommendations")

            if file_size == 0:
                if isinstance(susp_indicators, list):
                    susp_indicators.append("Empty file")
                security_info["risk_level"] = "Low"
            elif file_size > 100 * 1024 * 1024:
                if isinstance(susp_indicators, list):
                    susp_indicators.append("Very large file size")
                security_info["risk_level"] = "Medium"
            else:
                security_info["risk_level"] = "Low"

            if file_format == "Unknown":
                if isinstance(susp_indicators, list):
                    susp_indicators.append("Unknown file format")
                security_info["risk_level"] = "Medium"
            elif file_format in {"PE", "ELF", "Mach-O"}:
                if isinstance(recommendations, list):
                    recommendations.append("Run in sandboxed environment")
                    recommendations.append("Scan with antivirus")

                try:
                    from intellicrack.core.protection_detection.arxan_detector import ArxanDetector

                    arxan_detector = ArxanDetector()
                    arxan_result = arxan_detector.detect(file_path)

                    if arxan_result.is_protected:
                        protection_info: dict[str, Any] = {
                            "type": "Arxan TransformIT",
                            "version": arxan_result.version.value,
                            "confidence": arxan_result.confidence,
                            "features": {
                                "anti_debugging": arxan_result.features.anti_debugging,
                                "anti_tampering": arxan_result.features.anti_tampering,
                                "rasp": arxan_result.features.rasp_protection,
                                "license_validation": arxan_result.features.license_validation,
                            },
                        }
                        security_info["protection_detected"] = protection_info
                        susp_indicators_refresh = security_info.get("suspicious_indicators")
                        recommendations_refresh = security_info.get("recommendations")
                        if isinstance(susp_indicators_refresh, list):
                            susp_indicators_refresh.append(
                                f"Protected with Arxan TransformIT {arxan_result.version.value}",
                            )
                        if isinstance(recommendations_refresh, list):
                            recommendations_refresh.append(
                                "Use Arxan bypass tools for analysis",
                            )

                except Exception as e:
                    self.logger.debug("Arxan detection failed: %s", e)

            return security_info

        except Exception as e:
            return {"error": str(e)}
