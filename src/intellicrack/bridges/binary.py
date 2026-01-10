"""Binary operations bridge for direct file manipulation.

This module provides binary file analysis and patching capabilities
using pefile, lief, and capstone without requiring external tools.
"""

import asyncio
import hashlib
import re
from pathlib import Path

import capstone
import lief
import pefile

from ..core.logging import get_logger
from ..core.types import (
    BinaryInfo,
    ExportInfo,
    ImportInfo,
    PatchInfo,
    SectionInfo,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from .base import BinaryOperationsBridge, BridgeCapabilities, BridgeState

_logger = get_logger("bridges.binary")


class BinaryBridge(BinaryOperationsBridge):
    """Bridge for direct binary file operations.

    Provides analysis and patching of PE, ELF, and Mach-O binaries
    using pefile, lief, and capstone libraries.

    Attributes:
        _binary_path: Path to the currently loaded binary.
        _pe: Parsed PE file (if PE format).
        _lief_binary: Parsed binary via lief.
        _data: Raw binary data.
        _modified: Whether binary has been modified.
    """

    def __init__(self) -> None:
        """Initialize the binary operations bridge."""
        super().__init__()
        self._binary_path: Path | None = None
        self._pe: pefile.PE | None = None
        self._lief_binary: lief.Binary | None = None
        self._data: bytearray | None = None
        self._modified: bool = False
        self._patches: list[PatchInfo] = []
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_patching=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64"],
            supported_formats=["pe", "elf", "macho", "raw"],
        )

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName.BINARY
        """
        return ToolName.BINARY

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.BINARY,
            description="Direct binary file operations - reading, patching, and analysis",
            functions=[
                ToolFunction(
                    name="binary.load_file",
                    description="Load a binary file for analysis and patching",
                    parameters=[
                        ToolParameter(
                            name="path",
                            type="string",
                            description="Path to the binary file",
                            required=True,
                        ),
                    ],
                    returns="BinaryInfo object with file details",
                ),
                ToolFunction(
                    name="binary.read_bytes",
                    description="Read bytes from the binary at a specific offset",
                    parameters=[
                        ToolParameter(
                            name="offset",
                            type="integer",
                            description="File offset to read from",
                            required=True,
                        ),
                        ToolParameter(
                            name="size",
                            type="integer",
                            description="Number of bytes to read",
                            required=True,
                        ),
                    ],
                    returns="Hex string of read bytes",
                ),
                ToolFunction(
                    name="binary.write_bytes",
                    description="Write bytes to the binary at a specific offset",
                    parameters=[
                        ToolParameter(
                            name="offset",
                            type="integer",
                            description="File offset to write at",
                            required=True,
                        ),
                        ToolParameter(
                            name="hex_data",
                            type="string",
                            description="Hex string of bytes to write",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="binary.search_pattern",
                    description="Search for a byte pattern in the binary",
                    parameters=[
                        ToolParameter(
                            name="hex_pattern",
                            type="string",
                            description="Hex pattern with ?? wildcards (e.g., '48 8B ?? ??')",
                            required=True,
                        ),
                        ToolParameter(
                            name="max_results",
                            type="integer",
                            description="Maximum number of results to return",
                            required=False,
                            default=100,
                        ),
                    ],
                    returns="List of offsets where pattern found",
                ),
                ToolFunction(
                    name="binary.disassemble_at",
                    description="Disassemble instructions at a file offset",
                    parameters=[
                        ToolParameter(
                            name="offset",
                            type="integer",
                            description="File offset to disassemble",
                            required=True,
                        ),
                        ToolParameter(
                            name="count",
                            type="integer",
                            description="Number of instructions to disassemble",
                            required=False,
                            default=10,
                        ),
                    ],
                    returns="Disassembly text",
                ),
                ToolFunction(
                    name="binary.get_sections",
                    description="Get all sections in the binary",
                    parameters=[],
                    returns="List of SectionInfo objects",
                ),
                ToolFunction(
                    name="binary.get_imports",
                    description="Get all imported functions",
                    parameters=[],
                    returns="List of ImportInfo objects",
                ),
                ToolFunction(
                    name="binary.get_exports",
                    description="Get all exported functions",
                    parameters=[],
                    returns="List of ExportInfo objects",
                ),
                ToolFunction(
                    name="binary.get_strings",
                    description="Get strings from the binary",
                    parameters=[
                        ToolParameter(
                            name="min_length",
                            type="integer",
                            description="Minimum string length",
                            required=False,
                            default=4,
                        ),
                    ],
                    returns="List of strings with their offsets",
                ),
                ToolFunction(
                    name="binary.calculate_checksum",
                    description="Calculate hash of the binary",
                    parameters=[
                        ToolParameter(
                            name="algorithm",
                            type="string",
                            description="Hash algorithm (md5, sha1, sha256)",
                            required=False,
                            default="sha256",
                            enum=["md5", "sha1", "sha256"],
                        ),
                    ],
                    returns="Hex digest of hash",
                ),
                ToolFunction(
                    name="binary.rva_to_offset",
                    description="Convert relative virtual address to file offset",
                    parameters=[
                        ToolParameter(
                            name="rva",
                            type="integer",
                            description="Relative virtual address",
                            required=True,
                        ),
                    ],
                    returns="File offset",
                ),
                ToolFunction(
                    name="binary.offset_to_rva",
                    description="Convert file offset to relative virtual address",
                    parameters=[
                        ToolParameter(
                            name="offset",
                            type="integer",
                            description="File offset",
                            required=True,
                        ),
                    ],
                    returns="Relative virtual address",
                ),
                ToolFunction(
                    name="binary.apply_patch",
                    description="Apply a patch to the binary",
                    parameters=[
                        ToolParameter(
                            name="offset",
                            type="integer",
                            description="File offset to patch",
                            required=True,
                        ),
                        ToolParameter(
                            name="hex_data",
                            type="string",
                            description="Hex string of new bytes",
                            required=True,
                        ),
                        ToolParameter(
                            name="description",
                            type="string",
                            description="Description of the patch",
                            required=False,
                            default="",
                        ),
                    ],
                    returns="PatchInfo object",
                ),
                ToolFunction(
                    name="binary.revert_patch",
                    description="Revert a previously applied patch",
                    parameters=[
                        ToolParameter(
                            name="offset",
                            type="integer",
                            description="Offset of patch to revert",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="binary.save",
                    description="Save the binary to file",
                    parameters=[
                        ToolParameter(
                            name="path",
                            type="string",
                            description="Path to save to (optional, uses original if not specified)",
                            required=False,
                        ),
                    ],
                    returns="Path where file was saved",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the binary operations bridge.

        Args:
            tool_path: Not used for this bridge.
        """
        self._state = BridgeState(connected=True, tool_running=True)
        _logger.info("Binary operations bridge initialized")

    async def shutdown(self) -> None:
        """Shutdown and cleanup resources."""
        self._pe = None
        self._lief_binary = None
        self._data = None
        self._binary_path = None
        self._modified = False
        self._patches = []
        await super().shutdown()
        _logger.info("Binary operations bridge shutdown")

    async def is_available(self) -> bool:
        """Check if binary operations are available.

        Returns:
            Always True since this uses built-in libraries.
        """
        return True

    async def load_file(self, path: Path) -> BinaryInfo:
        """Load a binary file for analysis.

        Args:
            path: Path to the binary file.

        Returns:
            BinaryInfo with file details.

        Raises:
            ToolError: If file cannot be loaded.
        """
        if not path.exists():
            raise ToolError(f"File not found: {path}")

        try:
            self._binary_path = path.resolve()
            self._data = bytearray(path.read_bytes())
            self._modified = False
            self._patches = []

            file_type = self._detect_format()

            if file_type == "pe":
                self._pe = await asyncio.to_thread(
                    pefile.PE,
                    data=bytes(self._data),
                )
                self._lief_binary = await asyncio.to_thread(
                    lief.parse,
                    bytes(self._data),
                )
            elif file_type in ("elf", "macho"):
                self._lief_binary = await asyncio.to_thread(
                    lief.parse,
                    bytes(self._data),
                )
            else:
                self._lief_binary = None
                self._pe = None

            md5_hash = hashlib.md5(self._data).hexdigest()
            sha256_hash = hashlib.sha256(self._data).hexdigest()

            arch, is_64 = self._detect_architecture()
            entry_point = self._get_entry_point()
            sections = await self._get_sections_internal()
            imports = await self._get_imports_internal()
            exports = await self._get_exports_internal()

            self._state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=True,
                target_path=self._binary_path,
            )

            _logger.info("Loaded binary: %s (%s, %s)", path.name, file_type, arch)

            return BinaryInfo(
                path=self._binary_path,
                name=path.name,
                size=len(self._data),
                md5=md5_hash,
                sha256=sha256_hash,
                file_type=file_type,
                architecture=arch,
                is_64bit=is_64,
                entry_point=entry_point,
                sections=sections,
                imports=imports,
                exports=exports,
            )

        except Exception as e:
            _logger.exception("Failed to load binary")
            raise ToolError(f"Failed to load binary: {e}") from e

    def _detect_format(self) -> str:
        """Detect the binary format.

        Returns:
            Format string: pe, elf, macho, or raw.
        """
        if self._data is None or len(self._data) < 4:
            return "raw"

        if self._data[:2] == b"MZ":
            return "pe"

        if self._data[:4] == b"\x7fELF":
            return "elf"

        if self._data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                               b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
            return "macho"

        return "raw"

    def _detect_architecture(self) -> tuple[str, bool]:
        """Detect the CPU architecture.

        Returns:
            Tuple of (architecture name, is_64bit).
        """
        if self._pe is not None:
            machine = self._pe.FILE_HEADER.Machine
            if machine == 0x8664:
                return "x86_64", True
            elif machine == 0x14c:
                return "x86", False
            elif machine == 0xAA64:
                return "arm64", True
            elif machine == 0x1c0:
                return "arm", False

        if self._lief_binary is not None:
            if hasattr(self._lief_binary, "header"):
                header = self._lief_binary.header
                if hasattr(header, "machine_type"):
                    mt = str(header.machine_type)
                    if "X86_64" in mt or "AMD64" in mt:
                        return "x86_64", True
                    elif "I386" in mt or "X86" in mt:
                        return "x86", False
                    elif "AARCH64" in mt:
                        return "arm64", True
                    elif "ARM" in mt:
                        return "arm", False

        return "unknown", False

    def _get_entry_point(self) -> int:
        """Get the entry point address.

        Returns:
            Entry point address or 0 if not found.
        """
        if self._pe is not None:
            return self._pe.OPTIONAL_HEADER.AddressOfEntryPoint

        if self._lief_binary is not None:
            return self._lief_binary.entrypoint

        return 0

    async def _get_sections_internal(self) -> list[SectionInfo]:
        """Get section information.

        Returns:
            List of section info.
        """
        sections: list[SectionInfo] = []

        if self._pe is not None:
            for section in self._pe.sections:
                name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
                entropy = await asyncio.to_thread(section.get_entropy)
                sections.append(
                    SectionInfo(
                        name=name,
                        virtual_address=section.VirtualAddress,
                        virtual_size=section.Misc_VirtualSize,
                        raw_size=section.SizeOfRawData,
                        characteristics=section.Characteristics,
                        entropy=entropy,
                    )
                )

        elif self._lief_binary is not None:
            for section in self._lief_binary.sections:
                data = bytes(section.content) if section.content else b""
                entropy = self._calculate_entropy(data)
                sections.append(
                    SectionInfo(
                        name=section.name,
                        virtual_address=section.virtual_address,
                        virtual_size=section.size,
                        raw_size=len(data),
                        characteristics=0,
                        entropy=entropy,
                    )
                )

        return sections

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data.

        Args:
            data: Bytes to analyze.

        Returns:
            Entropy value between 0 and 8.
        """
        if not data:
            return 0.0

        import math
        from collections import Counter

        counts = Counter(data)
        total = len(data)
        entropy = 0.0

        for count in counts.values():
            if count > 0:
                freq = count / total
                entropy -= freq * math.log2(freq)

        return entropy

    async def _get_imports_internal(self) -> list[ImportInfo]:
        """Get import information.

        Returns:
            List of import info.
        """
        imports: list[ImportInfo] = []

        if self._pe is not None and hasattr(self._pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace")
                for imp in entry.imports:
                    name = imp.name.decode("utf-8", errors="replace") if imp.name else ""
                    imports.append(
                        ImportInfo(
                            dll=dll_name,
                            function=name,
                            ordinal=imp.ordinal if not imp.name else None,
                            address=imp.address,
                        )
                    )

        elif self._lief_binary is not None:
            if hasattr(self._lief_binary, "imported_functions"):
                for func in self._lief_binary.imported_functions:
                    imports.append(
                        ImportInfo(
                            dll="",
                            function=func.name,
                            ordinal=None,
                            address=func.address,
                        )
                    )

        return imports

    async def _get_exports_internal(self) -> list[ExportInfo]:
        """Get export information.

        Returns:
            List of export info.
        """
        exports: list[ExportInfo] = []

        if self._pe is not None and hasattr(self._pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode("utf-8", errors="replace") if exp.name else ""
                exports.append(
                    ExportInfo(
                        name=name,
                        ordinal=exp.ordinal,
                        address=exp.address,
                    )
                )

        elif self._lief_binary is not None:
            if hasattr(self._lief_binary, "exported_functions"):
                for idx, func in enumerate(self._lief_binary.exported_functions):
                    exports.append(
                        ExportInfo(
                            name=func.name,
                            ordinal=idx,
                            address=func.address,
                        )
                    )

        return exports

    async def read_bytes(self, offset: int, size: int) -> bytes:
        """Read bytes from the binary.

        Args:
            offset: File offset.
            size: Number of bytes to read.

        Returns:
            Read bytes.

        Raises:
            ToolError: If read fails.
        """
        if self._data is None:
            raise ToolError("No binary loaded")

        if offset < 0 or offset >= len(self._data):
            raise ToolError(f"Invalid offset: {offset}")

        end = min(offset + size, len(self._data))
        return bytes(self._data[offset:end])

    async def write_bytes(self, offset: int, data: bytes) -> None:
        """Write bytes to the binary.

        Args:
            offset: File offset.
            data: Bytes to write.

        Raises:
            ToolError: If write fails.
        """
        if self._data is None:
            raise ToolError("No binary loaded")

        if offset < 0 or offset >= len(self._data):
            raise ToolError(f"Invalid offset: {offset}")

        end = offset + len(data)
        if end > len(self._data):
            raise ToolError("Write extends beyond file size")

        self._data[offset:end] = data
        self._modified = True
        _logger.debug("Wrote %d bytes at offset 0x%X", len(data), offset)

    async def apply_patch(self, patch: PatchInfo) -> bool:
        """Apply a patch to the binary.

        Args:
            patch: Patch information.

        Returns:
            True if patch applied successfully.

        Raises:
            ToolError: If patching fails.
        """
        if self._data is None:
            raise ToolError("No binary loaded")

        offset = patch.address

        original = await self.read_bytes(offset, len(patch.new_bytes))
        if original != patch.original_bytes:
            _logger.warning(
                "Original bytes mismatch at 0x%X: expected %s, found %s",
                offset,
                patch.original_bytes.hex(),
                original.hex(),
            )

        await self.write_bytes(offset, patch.new_bytes)

        patch_record = PatchInfo(
            address=offset,
            original_bytes=original,
            new_bytes=patch.new_bytes,
            description=patch.description,
            applied=True,
        )
        self._patches.append(patch_record)

        _logger.info(
            "Applied patch at 0x%X: %s -> %s (%s)",
            offset,
            original.hex(),
            patch.new_bytes.hex(),
            patch.description,
        )

        return True

    async def revert_patch(self, patch: PatchInfo) -> bool:
        """Revert a previously applied patch.

        Args:
            patch: Patch to revert.

        Returns:
            True if reverted successfully.

        Raises:
            ToolError: If revert fails.
        """
        if self._data is None:
            raise ToolError("No binary loaded")

        for idx, applied in enumerate(self._patches):
            if applied.address == patch.address and applied.applied:
                await self.write_bytes(patch.address, applied.original_bytes)
                self._patches[idx] = PatchInfo(
                    address=applied.address,
                    original_bytes=applied.original_bytes,
                    new_bytes=applied.new_bytes,
                    description=applied.description,
                    applied=False,
                )
                _logger.info("Reverted patch at 0x%X", patch.address)
                return True

        _logger.warning("No applied patch found at 0x%X", patch.address)
        return False

    async def save(self, path: Path | None = None) -> Path:
        """Save the binary to file.

        Args:
            path: Optional new path. Uses original if None.

        Returns:
            Path where file was saved.

        Raises:
            ToolError: If save fails.
        """
        if self._data is None:
            raise ToolError("No binary loaded")

        save_path = path or self._binary_path
        if save_path is None:
            raise ToolError("No save path specified")

        save_path.write_bytes(bytes(self._data))
        _logger.info("Saved binary to %s", save_path)

        if save_path == self._binary_path:
            self._modified = False

        return save_path

    async def search_pattern(
        self,
        pattern: bytes,
        start_offset: int = 0,
        max_results: int = 100,
    ) -> list[int]:
        """Search for byte pattern in the binary.

        Args:
            pattern: Byte pattern to find.
            start_offset: Starting offset.
            max_results: Maximum results to return.

        Returns:
            List of offsets where pattern found.

        Raises:
            ToolError: If search fails.
        """
        if self._data is None:
            raise ToolError("No binary loaded")

        results: list[int] = []
        data = bytes(self._data)

        offset = start_offset
        while len(results) < max_results:
            pos = data.find(pattern, offset)
            if pos == -1:
                break
            results.append(pos)
            offset = pos + 1

        return results

    async def search_pattern_with_wildcards(
        self,
        hex_pattern: str,
        start_offset: int = 0,
        max_results: int = 100,
    ) -> list[int]:
        """Search for hex pattern with wildcards.

        Args:
            hex_pattern: Hex pattern like '48 8B ?? ?? 00'.
            start_offset: Starting offset.
            max_results: Maximum results to return.

        Returns:
            List of offsets where pattern found.

        Raises:
            ToolError: If search fails.
        """
        if self._data is None:
            raise ToolError("No binary loaded")

        hex_pattern = hex_pattern.replace(" ", "")
        regex_pattern = ""
        i = 0
        while i < len(hex_pattern):
            if hex_pattern[i:i+2] == "??":
                regex_pattern += "."
                i += 2
            else:
                byte_val = int(hex_pattern[i:i+2], 16)
                regex_pattern += re.escape(chr(byte_val))
                i += 2

        compiled = re.compile(regex_pattern.encode("latin-1"), re.DOTALL)

        results: list[int] = []
        data = bytes(self._data)

        for match in compiled.finditer(data, start_offset):
            results.append(match.start())
            if len(results) >= max_results:
                break

        return results

    async def disassemble_at_offset(
        self,
        offset: int,
        count: int = 10,
    ) -> str:
        """Disassemble instructions at a file offset.

        Args:
            offset: File offset.
            count: Number of instructions.

        Returns:
            Disassembly text.

        Raises:
            ToolError: If disassembly fails.
        """
        if self._data is None:
            raise ToolError("No binary loaded")

        arch, is_64 = self._detect_architecture()

        if arch in ("x86", "x86_64"):
            cs_arch = capstone.CS_ARCH_X86
            cs_mode = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
        elif arch in ("arm", "arm64"):
            cs_arch = capstone.CS_ARCH_ARM64 if is_64 else capstone.CS_ARCH_ARM
            cs_mode = capstone.CS_MODE_ARM
        else:
            raise ToolError(f"Unsupported architecture: {arch}")

        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = True

        code = bytes(self._data[offset:offset + count * 15])
        base_addr = offset

        lines: list[str] = []
        instruction_count = 0

        for insn in md.disasm(code, base_addr):
            hex_bytes = " ".join(f"{b:02X}" for b in insn.bytes)
            lines.append(f"0x{insn.address:08X}:  {hex_bytes:<24} {insn.mnemonic} {insn.op_str}")
            instruction_count += 1
            if instruction_count >= count:
                break

        return "\n".join(lines)

    async def calculate_checksum(self, algorithm: str = "sha256") -> str:
        """Calculate hash of the binary.

        Args:
            algorithm: Hash algorithm (md5, sha1, sha256).

        Returns:
            Hex digest of hash.

        Raises:
            ToolError: If calculation fails.
        """
        if self._data is None:
            raise ToolError("No binary loaded")

        if algorithm == "md5":
            return hashlib.md5(self._data).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(self._data).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(self._data).hexdigest()
        else:
            raise ToolError(f"Unknown algorithm: {algorithm}")

    async def rva_to_offset(self, rva: int) -> int:
        """Convert RVA to file offset.

        Args:
            rva: Relative virtual address.

        Returns:
            File offset.

        Raises:
            ToolError: If conversion fails.
        """
        if self._pe is not None:
            return self._pe.get_offset_from_rva(rva)

        if self._lief_binary is not None:
            return self._lief_binary.rva_to_offset(rva)

        raise ToolError("RVA conversion not available for raw binaries")

    async def offset_to_rva(self, offset: int) -> int:
        """Convert file offset to RVA.

        Args:
            offset: File offset.

        Returns:
            Relative virtual address.

        Raises:
            ToolError: If conversion fails.
        """
        if self._pe is not None:
            return self._pe.get_rva_from_offset(offset)

        if self._lief_binary is not None:
            return self._lief_binary.offset_to_virtual_address(offset)

        raise ToolError("Offset conversion not available for raw binaries")

    async def get_strings(self, min_length: int = 4) -> list[tuple[int, str]]:
        """Extract strings from the binary.

        Args:
            min_length: Minimum string length.

        Returns:
            List of (offset, string) tuples.
        """
        if self._data is None:
            raise ToolError("No binary loaded")

        strings: list[tuple[int, str]] = []
        data = bytes(self._data)

        ascii_pattern = re.compile(
            rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
        )
        for match in ascii_pattern.finditer(data):
            strings.append((match.start(), match.group().decode("ascii")))

        return strings
