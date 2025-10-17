"""Advanced Intellicrack Protection Analysis Module.

Enhanced features for comprehensive protection analysis capabilities.

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

import concurrent.futures
import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# Secure XML parser import
import defusedxml.ElementTree as ElementTree

from ..utils.logger import get_logger
from .intellicrack_protection_core import (
    DetectionResult,
    IntellicrackProtectionCore,
    ProtectionAnalysis,
    ProtectionType,
)

logger = get_logger(__name__)


class ScanMode(Enum):
    """Protection analysis scan modes."""

    NORMAL = "normal"
    DEEP = "deep"
    HEURISTIC = "heuristic"
    ALL = "all"


class ExportFormat(Enum):
    """Export formats supported by protection analysis."""

    JSON = "json"
    XML = "xml"
    TEXT = "text"
    CSV = "csv"
    HTML = "html"


@dataclass
class EntropyInfo:
    """Entropy information for file sections."""

    section_name: str
    offset: int
    size: int
    entropy: float
    packed: bool = False
    encrypted: bool = False


@dataclass
class CertificateInfo:
    """Digital certificate information."""

    subject: str
    issuer: str
    serial_number: str
    valid_from: str
    valid_to: str
    algorithm: str
    is_valid: bool
    is_trusted: bool


@dataclass
class ResourceInfo:
    """Resource information from PE files."""

    type: str
    name: str
    language: str
    size: int
    offset: int
    data_hash: str


@dataclass
class StringInfo:
    """String information with encoding."""

    value: str
    offset: int
    encoding: str
    length: int
    suspicious: bool = False


@dataclass
class ImportHash:
    """Import hash for similarity analysis."""

    imphash: str
    imphash_sorted: str
    rich_header_hash: str | None = None


@dataclass
class AdvancedProtectionAnalysis(ProtectionAnalysis):
    """Extended protection analysis with additional features."""

    entropy_info: list[EntropyInfo] = field(default_factory=list)
    certificates: list[CertificateInfo] = field(default_factory=list)
    resources: list[ResourceInfo] = field(default_factory=list)
    suspicious_strings: list[StringInfo] = field(default_factory=list)
    import_hash: ImportHash | None = None
    heuristic_detections: list[DetectionResult] = field(default_factory=list)
    similarity_hash: str | None = None
    file_format_details: dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        file_path: str,
        file_type: str,
        architecture: str,
        detections: list[DetectionResult] | None = None,
        compiler: str | None = None,
        linker: str | None = None,
        is_packed: bool = False,
        is_protected: bool = False,
        has_overlay: bool = False,
        has_resources: bool = False,
        entry_point: str | None = None,
        sections: list[dict[str, Any]] | None = None,
        imports: list[str] | None = None,
        strings: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        entropy_info: list[EntropyInfo] | None = None,
        certificates: list[CertificateInfo] | None = None,
        resources: list[ResourceInfo] | None = None,
        suspicious_strings: list[StringInfo] | None = None,
        import_hash: ImportHash | None = None,
        heuristic_detections: list[DetectionResult] | None = None,
        similarity_hash: str | None = None,
        file_format_details: dict[str, Any] | None = None,
    ):
        """Initialize advanced protection analysis with comprehensive binary analysis data."""
        super().__init__(
            file_path=file_path,
            file_type=file_type,
            architecture=architecture,
            detections=detections or [],
            compiler=compiler,
            linker=linker,
            is_packed=is_packed,
            is_protected=is_protected,
            has_overlay=has_overlay,
            has_resources=has_resources,
            entry_point=entry_point,
            sections=sections or [],
            imports=imports or [],
            strings=strings or [],
            metadata=metadata or {},
        )
        self.entropy_info = entropy_info or []
        self.certificates = certificates or []
        self.resources = resources or []
        self.suspicious_strings = suspicious_strings or []
        self.import_hash = import_hash
        self.heuristic_detections = heuristic_detections or []
        self.similarity_hash = similarity_hash
        self.file_format_details = file_format_details or {}


class IntellicrackAdvancedProtection(IntellicrackProtectionCore):
    """Advanced Intellicrack protection analysis with full feature support."""

    def __init__(
        self,
        engine_path: str | None = None,
        custom_db_path: str | None = None,
        enable_cache: bool = True,
    ):
        """Initialize advanced protection analyzer.

        Args:
            engine_path: Path to protection engine executable
            custom_db_path: Path to custom signature database
            enable_cache: Enable result caching

        """
        super().__init__(engine_path)
        self.custom_db_path = custom_db_path or self._find_custom_db()
        self.cache_enabled = enable_cache
        self.result_cache = {} if enable_cache else None

    def _find_custom_db(self) -> str | None:
        """Find custom database directory."""
        if not self.engine_path:
            # No engine path, no custom db
            return None
        try:
            base_path = Path(self.engine_path).parent
            custom_db = base_path / "db_custom"
            if custom_db.exists():
                return str(custom_db)
        except (TypeError, ValueError):
            pass
        return None

    def detect_protections_advanced(
        self,
        file_path: str,
        scan_mode: ScanMode = ScanMode.NORMAL,
        enable_heuristic: bool = True,
        export_format: ExportFormat = ExportFormat.JSON,
        extract_strings: bool = True,
        max_string_length: int = 1000,
    ) -> AdvancedProtectionAnalysis:
        """Advanced protection detection with full analysis features.

        Args:
            file_path: Path to file to analyze
            scan_mode: Scanning mode to use
            enable_heuristic: Enable heuristic detection
            export_format: Output format
            extract_strings: Extract and analyze strings
            max_string_length: Maximum string length to extract

        Returns:
            AdvancedProtectionAnalysis with comprehensive results

        """
        # Check cache first
        if self.cache_enabled and file_path in self.result_cache:
            file_hash = self._calculate_file_hash(file_path)
            cached_result, cached_hash = self.result_cache[file_path]
            if file_hash == cached_hash:
                logger.debug(f"Returning cached result for {file_path}")
                return cached_result

        # Build command with advanced options
        cmd = [self.engine_path]

        # Add format option
        if export_format == ExportFormat.JSON:
            cmd.append("-j")
        elif export_format == ExportFormat.XML:
            cmd.append("-x")
        elif export_format == ExportFormat.CSV:
            cmd.append("-c")
        elif export_format == ExportFormat.HTML:
            cmd.append("-h")

        # Add scan mode options
        if scan_mode == ScanMode.DEEP:
            cmd.extend(["-d", "3"])  # Deep scan level 3
        elif scan_mode == ScanMode.HEURISTIC:
            cmd.append("-H")  # Heuristic mode
        elif scan_mode == ScanMode.ALL:
            cmd.extend(["-d", "3", "-H"])  # Deep + heuristic

        # Add other options
        if enable_heuristic and scan_mode != ScanMode.HEURISTIC:
            cmd.append("-H")

        if self.custom_db_path:
            cmd.extend(["--db", self.custom_db_path])

        # Add entropy calculation
        cmd.append("-e")  # Calculate entropy

        # Add file path
        cmd.append(file_path)

        try:
            # Run protection engine with extended timeout for deep scans
            timeout = 60 if scan_mode in [ScanMode.DEEP, ScanMode.ALL] else 30
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                cmd, check=False, capture_output=True, text=True, timeout=timeout, shell=False
            )

            if result.returncode != 0:
                logger.error(f"Protection engine execution failed: {result.stderr}")
                return AdvancedProtectionAnalysis(
                    file_path=file_path,
                    file_type="Error",
                    architecture="Unknown",
                )

            # Parse output based on format
            if export_format == ExportFormat.JSON:
                analysis = self._parse_advanced_json(file_path, result.stdout)
            elif export_format == ExportFormat.XML:
                analysis = self._parse_advanced_xml(file_path, result.stdout)
            else:
                # For text/CSV/HTML, we need to parse differently
                analysis = self._parse_advanced_text(file_path, result.stdout)

            # Extract additional information
            if extract_strings:
                analysis.suspicious_strings = self._extract_suspicious_strings(
                    file_path,
                    max_string_length,
                )

            # Calculate import hash
            analysis.import_hash = self._calculate_import_hash(file_path)

            # Calculate similarity hash
            analysis.similarity_hash = self._calculate_similarity_hash(file_path)

            # Cache result
            if self.cache_enabled:
                file_hash = self._calculate_file_hash(file_path)
                self.result_cache[file_path] = (analysis, file_hash)

            return analysis

        except subprocess.TimeoutExpired:
            logger.error(f"Protection analysis timed out for: {file_path}")
            return AdvancedProtectionAnalysis(
                file_path=file_path,
                file_type="Timeout",
                architecture="Unknown",
            )
        except Exception as e:
            logger.error(f"Error in advanced analysis: {e}")
            return AdvancedProtectionAnalysis(
                file_path=file_path,
                file_type="Error",
                architecture="Unknown",
            )

    def _parse_advanced_json(self, file_path: str, json_output: str) -> AdvancedProtectionAnalysis:
        """Parse advanced JSON output from protection engine."""
        # Start with basic parsing
        basic_analysis = self._parse_json_output(file_path, json.loads(json_output))

        # Convert to advanced analysis
        analysis = AdvancedProtectionAnalysis(
            file_path=basic_analysis.file_path,
            file_type=basic_analysis.file_type,
            architecture=basic_analysis.architecture,
            detections=basic_analysis.detections,
            compiler=basic_analysis.compiler,
            linker=basic_analysis.linker,
            is_packed=basic_analysis.is_packed,
            is_protected=basic_analysis.is_protected,
            has_overlay=basic_analysis.has_overlay,
            has_resources=basic_analysis.has_resources,
            entry_point=basic_analysis.entry_point,
            sections=basic_analysis.sections,
            imports=basic_analysis.imports,
            strings=basic_analysis.strings,
            metadata=basic_analysis.metadata,
        )

        # Parse additional information
        icp_data = json.loads(json_output)

        # Extract entropy information
        if "sections" in icp_data:
            for section in icp_data["sections"]:
                entropy_info = EntropyInfo(
                    section_name=section.get("name", ""),
                    offset=section.get("offset", 0),
                    size=section.get("size", 0),
                    entropy=section.get("entropy", 0.0),
                    packed=section.get("entropy", 0.0) > 7.0,
                    encrypted=section.get("entropy", 0.0) > 7.5,
                )
                analysis.entropy_info.append(entropy_info)

        # Extract certificate information
        if "certificates" in icp_data:
            for cert in icp_data["certificates"]:
                cert_info = CertificateInfo(
                    subject=cert.get("subject", ""),
                    issuer=cert.get("issuer", ""),
                    serial_number=cert.get("serial", ""),
                    valid_from=cert.get("valid_from", ""),
                    valid_to=cert.get("valid_to", ""),
                    algorithm=cert.get("algorithm", ""),
                    is_valid=cert.get("valid", False),
                    is_trusted=cert.get("trusted", False),
                )
                analysis.certificates.append(cert_info)

        # Extract resource information
        if "resources" in icp_data:
            for resource in icp_data["resources"]:
                resource_info = ResourceInfo(
                    type=resource.get("type", ""),
                    name=resource.get("name", ""),
                    language=resource.get("language", ""),
                    size=resource.get("size", 0),
                    offset=resource.get("offset", 0),
                    data_hash=resource.get("hash", ""),
                )
                analysis.resources.append(resource_info)

        # Extract heuristic detections
        if "heuristic" in icp_data:
            for heur in icp_data["heuristic"]:
                det_result = DetectionResult(
                    name=heur.get("name", "Unknown"),
                    version=heur.get("version"),
                    type=self._categorize_detection(heur.get("type", "")),
                    confidence=heur.get("confidence", 50.0),
                    details={"heuristic": True},
                )
                analysis.heuristic_detections.append(det_result)

        return analysis

    def _parse_advanced_xml(self, file_path: str, xml_output: str) -> AdvancedProtectionAnalysis:
        """Parse advanced XML output from protection engine."""
        analysis = AdvancedProtectionAnalysis(
            file_path=file_path,
            file_type="Unknown",
            architecture="Unknown",
        )

        try:
            root = ElementTree.fromstring(xml_output)

            # Parse file information
            file_elem = root.find("file")
            if file_elem is not None:
                analysis.file_type = file_elem.get("type", "Unknown")
                analysis.architecture = file_elem.get("arch", "Unknown")

            # Parse detections
            for detection in root.findall(".//detection"):
                det_result = DetectionResult(
                    name=detection.get("name", "Unknown"),
                    version=detection.get("version"),
                    type=self._categorize_detection(detection.get("type", "")),
                    confidence=float(detection.get("confidence", "100")),
                )
                analysis.detections.append(det_result)

            # Parse sections with entropy
            for section in root.findall(".//section"):
                entropy_info = EntropyInfo(
                    section_name=section.get("name", ""),
                    offset=int(section.get("offset", "0"), 16),
                    size=int(section.get("size", "0")),
                    entropy=float(section.get("entropy", "0.0")),
                )
                analysis.entropy_info.append(entropy_info)

        except ElementTree.ParseError as e:
            logger.error(f"XML parsing error: {e}")

        return analysis

    def _parse_advanced_text(self, file_path: str, text_output: str) -> AdvancedProtectionAnalysis:
        """Parse advanced text output from protection engine."""
        analysis = AdvancedProtectionAnalysis(
            file_path=file_path,
            file_type="Unknown",
            architecture="Unknown",
        )

        # Parse text output line by line
        lines = text_output.strip().split("\n")

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Parse file type
            if line.startswith("filetype:"):
                analysis.file_type = line.split(":", 1)[1].strip()
            elif line.startswith("arch:"):
                analysis.architecture = line.split(":", 1)[1].strip()
            elif line.startswith("mode:"):
                analysis.is_64bit = "64" in line
            elif line.startswith("endianess:"):
                analysis.endianess = line.split(":", 1)[1].strip()
            elif line.startswith("entrypoint:"):
                analysis.entry_point = line.split(":", 1)[1].strip()
            elif line.startswith("overlay:"):
                analysis.has_overlay = "yes" in line.lower()
            elif line.startswith("resources:"):
                analysis.has_resources = "yes" in line.lower()

            # Parse detections
            elif "protector" in line.lower() or "packer" in line.lower():
                # Try to extract detection info from text line
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    det_type = "protector" if "protector" in line.lower() else "packer"

                    det_result = DetectionResult(
                        name=name,
                        type=ProtectionType.PROTECTOR if det_type == "protector" else ProtectionType.PACKER,
                        confidence=80.0,  # Default confidence for text parsing
                        details={"raw": line},
                    )
                    analysis.detections.append(det_result)

                    if det_type == "protector":
                        analysis.is_protected = True
                    elif det_type == "packer":
                        analysis.is_packed = True

        return analysis

    def _extract_suspicious_strings(self, file_path: str, max_length: int) -> list[StringInfo]:
        """Extract suspicious strings from file."""
        suspicious_patterns = [
            "kernel32",
            "ntdll",
            "VirtualProtect",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "OutputDebugString",
            "license",
            "crack",
            "patch",
            "keygen",
            "serial",
            "registration",
            "trial",
            "eval",
            "demo",
            "unregistered",
            "http://",
            "https://",
            "ftp://",
            "cmd.exe",
            "powershell",
            "reg.exe",
            "wmic",
            "\\x00\\x00\\x00",
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "password",
            "passwd",
            "pwd",
            "admin",
            "root",
            "sa",
            "dbo",
        ]

        suspicious_strings = []

        try:
            # Use protection engine's string extraction
            cmd = [self.engine_path, "-s", file_path]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=30, shell=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line and len(line) < max_length:
                        # Check if string is suspicious
                        is_suspicious = any(pattern.lower() in line.lower() for pattern in suspicious_patterns)

                        if is_suspicious:
                            string_info = StringInfo(
                                value=line,
                                offset=0,  # Would need additional parsing
                                encoding="UTF-8",  # Assumption
                                length=len(line),
                                suspicious=True,
                            )
                            suspicious_strings.append(string_info)

        except Exception as e:
            logger.error(f"Error extracting strings: {e}")

        return suspicious_strings

    def _calculate_import_hash(self, file_path: str) -> ImportHash | None:
        """Calculate import hash for file using proper PE import table analysis."""
        try:
            import pefile
        except ImportError:
            logger.warning("pefile not available, using fallback import hash calculation")
            # Fallback implementation that analyzes PE structure manually
            return self._calculate_import_hash_manual(file_path)

        try:
            pe = pefile.PE(file_path)

            # Calculate standard imphash
            imphash = pe.get_imphash()

            # Calculate sorted imphash for comparison
            import_list = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8").lower() if isinstance(entry.dll, bytes) else entry.dll.lower()
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode("utf-8") if isinstance(imp.name, bytes) else imp.name
                            import_list.append(f"{dll_name}.{func_name}")

            # Create sorted imphash
            sorted_imports = sorted(import_list)
            sorted_string = ",".join(sorted_imports)
            import_hash_sorted = hashlib.sha256(sorted_string.encode()).hexdigest()

            # Calculate Rich header hash if present
            rich_header_hash = None
            if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
                # Hash the Rich header data
                rich_data = pe.get_data(pe.RICH_HEADER.start_offset, pe.RICH_HEADER.sizeof())
                rich_header_hash = hashlib.sha256(rich_data).hexdigest()

            pe.close()

            return ImportHash(
                imphash=imphash,
                imphash_sorted=import_hash_sorted,
                rich_header_hash=rich_header_hash,
            )
        except Exception as e:
            logger.error(f"Error calculating import hash with pefile: {e}")
            # Try manual fallback
            return self._calculate_import_hash_manual(file_path)

    def _calculate_import_hash_manual(self, file_path: str) -> ImportHash | None:  # noqa: C901
        """Manual PE import hash calculation without pefile library."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Check for MZ header
            if len(data) < 2 or data[:2] != b"MZ":
                return None

            # Get PE header offset
            pe_offset = int.from_bytes(data[0x3C:0x40], "little")
            if pe_offset + 4 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
                return None

            # Parse PE header to find import directory
            pe_header_offset = pe_offset
            size_of_optional_header = int.from_bytes(data[pe_offset + 20 : pe_offset + 22], "little")
            optional_header_offset = pe_offset + 24

            # Determine if PE32 or PE32+
            magic = int.from_bytes(data[optional_header_offset : optional_header_offset + 2], "little")
            is_pe32plus = magic == 0x20B

            # Get import directory RVA
            if is_pe32plus:
                import_dir_offset = optional_header_offset + 112
            else:
                import_dir_offset = optional_header_offset + 104

            if import_dir_offset + 8 > len(data):
                return None

            import_rva = int.from_bytes(data[import_dir_offset : import_dir_offset + 4], "little")
            import_size = int.from_bytes(data[import_dir_offset + 4 : import_dir_offset + 8], "little")

            # Build import string for hashing
            import_strings = []
            if import_rva > 0 and import_size > 0:
                # Parse PE sections to find correct file offset for import RVA
                section_header_offset = pe_header_offset + 24 + size_of_optional_header
                num_sections = int.from_bytes(data[pe_header_offset + 6 : pe_header_offset + 8], "little")

                import_file_offset = 0
                for i in range(num_sections):
                    section_offset = section_header_offset + (i * 40)
                    if section_offset + 40 > len(data):
                        break

                    virtual_size = int.from_bytes(data[section_offset + 8 : section_offset + 12], "little")
                    virtual_addr = int.from_bytes(data[section_offset + 12 : section_offset + 16], "little")
                    raw_size = int.from_bytes(data[section_offset + 16 : section_offset + 20], "little")
                    raw_addr = int.from_bytes(data[section_offset + 20 : section_offset + 24], "little")

                    # Check if import RVA falls within this section
                    if virtual_addr <= import_rva < virtual_addr + virtual_size:
                        # Validate raw size for section integrity
                        offset_in_section = import_rva - virtual_addr
                        if offset_in_section >= raw_size:
                            # Import table extends beyond raw section - possible corruption or packing
                            import_strings.append(f"[SECTION_OVERFLOW:{import_rva:08X}]")
                        # Convert RVA to file offset
                        import_file_offset = raw_addr + offset_in_section
                        break

                # Parse import descriptors if offset found
                if import_file_offset > 0 and import_file_offset < len(data) - 20:
                    descriptor_offset = import_file_offset

                    # Process each import descriptor (20 bytes each)
                    while descriptor_offset + 20 <= len(data):
                        # Import descriptor structure
                        original_first_thunk = int.from_bytes(data[descriptor_offset : descriptor_offset + 4], "little")
                        time_date_stamp = int.from_bytes(data[descriptor_offset + 4 : descriptor_offset + 8], "little")
                        forwarder_chain = int.from_bytes(data[descriptor_offset + 8 : descriptor_offset + 12], "little")
                        name_rva = int.from_bytes(data[descriptor_offset + 12 : descriptor_offset + 16], "little")
                        first_thunk = int.from_bytes(data[descriptor_offset + 16 : descriptor_offset + 20], "little")

                        # Check for end of import descriptors
                        if name_rva == 0:
                            break

                        # Analyze import descriptor characteristics
                        if time_date_stamp != 0 and time_date_stamp != 0xFFFFFFFF:
                            # Bound import - timestamp indicates pre-bound DLL
                            import_strings.append(f"[BOUND:{time_date_stamp:08X}]")

                        if forwarder_chain != 0xFFFFFFFF and forwarder_chain != 0:
                            # Forwarded imports detected
                            import_strings.append(f"[FORWARD:{forwarder_chain:08X}]")

                        # Validate thunks for IAT hooking detection
                        if first_thunk != 0 and original_first_thunk != 0:
                            # Both thunks present - normal import
                            if abs(first_thunk - original_first_thunk) > 0x10000:
                                # Suspicious thunk separation - possible IAT manipulation
                                import_strings.append(f"[IAT_ANOMALY:{first_thunk:08X}]")
                        elif first_thunk != 0 and original_first_thunk == 0:
                            # Only IAT present - could indicate runtime binding
                            import_strings.append(f"[DYNAMIC_IMPORT:{first_thunk:08X}]")

                        # Convert name RVA to file offset
                        name_file_offset = 0
                        for i in range(num_sections):
                            section_offset = section_header_offset + (i * 40)
                            if section_offset + 40 > len(data):
                                break

                            virtual_addr = int.from_bytes(data[section_offset + 12 : section_offset + 16], "little")
                            virtual_size = int.from_bytes(data[section_offset + 8 : section_offset + 12], "little")
                            raw_addr = int.from_bytes(data[section_offset + 20 : section_offset + 24], "little")

                            if virtual_addr <= name_rva < virtual_addr + virtual_size:
                                name_file_offset = raw_addr + (name_rva - virtual_addr)
                                break

                        # Extract DLL name
                        if name_file_offset > 0 and name_file_offset < len(data) - 100:
                            dll_name = b""
                            for j in range(100):
                                if name_file_offset + j >= len(data):
                                    break
                                byte = data[name_file_offset + j]
                                if byte == 0:
                                    break
                                dll_name += bytes([byte])

                            if dll_name:
                                import_strings.append(dll_name.decode("ascii", errors="ignore").lower())

                        descriptor_offset += 20

                        # Limit parsing to prevent excessive processing
                        if len(import_strings) > 100:
                            break

                # Fallback: Extract strings from import area if descriptor parsing fails
                if not import_strings and import_file_offset > 0:
                    import_area_end = min(import_file_offset + import_size, len(data))
                    import_area = data[import_file_offset:import_area_end]

                # Look for common DLL names and function names
                common_dlls = [
                    b"kernel32.dll",
                    b"user32.dll",
                    b"ntdll.dll",
                    b"advapi32.dll",
                    b"shell32.dll",
                    b"ole32.dll",
                    b"oleaut32.dll",
                    b"ws2_32.dll",
                ]

                for dll in common_dlls:
                    if dll in import_area:
                        dll_name = dll.decode("utf-8", errors="ignore").lower()
                        import_strings.append(dll_name)

            # Generate hash from whatever imports we found
            if import_strings:
                import_string = ",".join(import_strings)
                imphash = hashlib.sha256(import_string.encode()).hexdigest()
            else:
                # Fallback to hashing first 4KB of file if no imports found
                imphash = hashlib.sha256(data[:4096]).hexdigest()

            return ImportHash(
                imphash=imphash,
                imphash_sorted=imphash,
                rich_header_hash=None,
            )

        except Exception as e:
            logger.error(f"Error in manual import hash calculation: {e}")
            return None

    def _calculate_similarity_hash(self, file_path: str) -> str | None:
        """Calculate similarity hash using ssdeep fuzzy hashing or TLSH."""
        # Try ssdeep first
        try:
            import ssdeep

            with open(file_path, "rb") as f:
                file_data = f.read()
            return ssdeep.hash(file_data)
        except ImportError:
            logger.debug("ssdeep not available, trying TLSH")
        except Exception as e:
            logger.error(f"Error calculating ssdeep hash: {e}")

        # Try TLSH as alternative
        try:
            import tlsh

            with open(file_path, "rb") as f:
                file_data = f.read()
            # TLSH requires at least 50 bytes of data
            if len(file_data) >= 50:
                tlsh_hash = tlsh.hash(file_data)
                if tlsh_hash:
                    return f"tlsh:{tlsh_hash}"
        except ImportError:
            logger.debug("TLSH not available, using custom fuzzy hash")
        except Exception as e:
            logger.error(f"Error calculating TLSH hash: {e}")

        # Fallback: Custom rolling hash implementation for similarity
        try:
            return self._calculate_custom_fuzzy_hash(file_path)
        except Exception as e:
            logger.error(f"Error calculating custom fuzzy hash: {e}")
            return None

    def _calculate_custom_fuzzy_hash(self, file_path: str) -> str:
        """Calculate custom fuzzy hash using rolling hash and context triggering."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            if len(data) == 0:
                return "0::"

            # Determine block size based on file size
            file_size = len(data)
            block_size = 3
            while block_size * 64 < file_size:
                block_size *= 2

            # Calculate rolling hash using Adler-32 style algorithm
            window_size = 7  # Rolling window size
            threshold = block_size * 64

            # Build hash signatures
            hash_string = []
            block_hash = 0
            window_data = bytearray(window_size)

            for i in range(len(data)):
                # Update rolling window
                window_data[i % window_size] = data[i]

                # Calculate rolling hash
                if i >= window_size - 1:
                    # Simple rolling hash: sum of bytes in window
                    window_hash = sum(window_data)

                    # Check if we hit a reset point
                    if window_hash % threshold == threshold - 1:
                        # Generate block signature
                        if i > block_hash + window_size:
                            block_data = data[block_hash:i]
                            # Create signature from block
                            sig = 0
                            for j, byte in enumerate(block_data[:64]):  # Use first 64 bytes max
                                sig = (sig + byte * (j + 1)) % 256

                            # Convert to base64-like character
                            if sig < 26:
                                hash_char = chr(ord("A") + sig)
                            elif sig < 52:
                                hash_char = chr(ord("a") + sig - 26)
                            elif sig < 62:
                                hash_char = chr(ord("0") + sig - 52)
                            elif sig == 62:
                                hash_char = "+"
                            else:
                                hash_char = "/"

                            hash_string.append(hash_char)
                            block_hash = i

            # Generate final block signature if needed
            if block_hash < len(data) - window_size:
                remaining_data = data[block_hash:]
                sig = 0
                for j, byte in enumerate(remaining_data[:64]):
                    sig = (sig + byte * (j + 1)) % 256

                if sig < 26:
                    hash_char = chr(ord("A") + sig)
                elif sig < 52:
                    hash_char = chr(ord("a") + sig - 26)
                elif sig < 62:
                    hash_char = chr(ord("0") + sig - 52)
                elif sig == 62:
                    hash_char = "+"
                else:
                    hash_char = "/"

                hash_string.append(hash_char)

            # Format: blocksize:hash1:hash2
            # Where hash1 is the main hash and hash2 is a doubled block size hash
            main_hash = "".join(hash_string[:64]) if hash_string else ""

            # Calculate second hash with doubled block size
            double_block_size = block_size * 2
            double_threshold = double_block_size * 64
            hash_string_2 = []
            block_hash = 0

            for i in range(len(data)):
                window_data[i % window_size] = data[i]
                if i >= window_size - 1:
                    window_hash = sum(window_data)
                    if window_hash % double_threshold == double_threshold - 1:
                        if i > block_hash + window_size:
                            block_data = data[block_hash:i]
                            sig = 0
                            for j, byte in enumerate(block_data[:64]):
                                sig = (sig + byte * (j + 1)) % 256

                            if sig < 26:
                                hash_char = chr(ord("A") + sig)
                            elif sig < 52:
                                hash_char = chr(ord("a") + sig - 26)
                            elif sig < 62:
                                hash_char = chr(ord("0") + sig - 52)
                            elif sig == 62:
                                hash_char = "+"
                            else:
                                hash_char = "/"

                            hash_string_2.append(hash_char)
                            block_hash = i

            secondary_hash = "".join(hash_string_2[:64]) if hash_string_2 else ""

            # Return formatted fuzzy hash
            return f"{block_size}:{main_hash}:{secondary_hash}"

        except Exception as e:
            logger.error(f"Error in custom fuzzy hash calculation: {e}")
            # Last resort: return a simple hash
            with open(file_path, "rb") as f:
                return f"sha256:{hashlib.sha256(f.read()).hexdigest()}"

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate file hash for caching."""
        try:
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""

    def batch_analyze(
        self, file_paths: list[str], max_workers: int = 4, scan_mode: ScanMode = ScanMode.NORMAL
    ) -> dict[str, AdvancedProtectionAnalysis]:
        """Analyze multiple files in parallel.

        Args:
            file_paths: List of files to analyze
            max_workers: Maximum number of parallel workers
            scan_mode: Scan mode to use

        Returns:
            Dictionary mapping file paths to analysis results

        """
        results = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_path = {
                executor.submit(
                    self.detect_protections_advanced,
                    path,
                    scan_mode,
                ): path
                for path in file_paths
            }

            # Collect results
            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    results[path] = future.result()
                except Exception as e:
                    logger.error(f"Error analyzing {path}: {e}")
                    results[path] = AdvancedProtectionAnalysis(
                        file_path=path,
                        file_type="Error",
                        architecture="Unknown",
                    )

        return results

    def create_custom_signature(self, name: str, pattern: bytes, offset: int = 0, description: str = "") -> bool:
        """Create custom signature for protection analysis.

        Args:
            name: Signature name
            pattern: Byte pattern to match
            offset: Offset in file to check
            description: Signature description

        Returns:
            True if signature created successfully

        """
        if not self.custom_db_path:
            logger.error("Custom database path not set")
            return False

        try:
            # Create signature file
            sig_file = Path(self.custom_db_path) / f"{name}.sg"

            # Simple signature format (would need proper protection engine signature format)
            signature_content = f"""
// {description}
// Custom signature for {name}

init("custom", "{name}");

function detect(bShowType, bShowVersion, bShowOptions)
{{
    if(Binary.compare({offset}, "{pattern.hex()}"))==0)
    {{
        sName="{name}";
        bDetected=true;
    }}
}}
"""

            sig_file.write_text(signature_content)
            logger.info(f"Created custom signature: {sig_file}")
            return True

        except Exception as e:
            logger.error(f"Error creating signature: {e}")
            return False

    def export_to_yara(self, analysis: AdvancedProtectionAnalysis) -> str:
        """Export detection results as comprehensive YARA rules.

        Args:
            analysis: Analysis results to export

        Returns:
            YARA rule string with detailed detection patterns

        """
        yara_rules = []

        # Generate main detection rule
        main_rule_name = Path(analysis.file_path).stem.replace(" ", "_").replace("-", "_")

        # Build comprehensive strings section
        strings_section = []
        conditions_list = []

        # Add file format specific patterns
        if "PE" in analysis.file_type:
            strings_section.append("        $mz = { 4D 5A }  // MZ header")
            strings_section.append("        $pe = { 50 45 00 00 }  // PE signature")
            conditions_list.append("$mz at 0 and $pe")
        elif "ELF" in analysis.file_type:
            strings_section.append("        $elf = { 7F 45 4C 46 }  // ELF header")
            conditions_list.append("$elf at 0")

        # Add protection-specific patterns based on detections
        for _idx, detection in enumerate(analysis.detections):
            detection_strings = self._generate_detection_patterns(detection)
            for pattern in detection_strings:
                strings_section.append(f"        {pattern}")

            # Add detection-specific conditions
            if detection.type == ProtectionType.PACKER:
                conditions_list.append(f"// Packer detection: {detection.name}")
            elif detection.type == ProtectionType.PROTECTOR:
                conditions_list.append(f"// Protector detection: {detection.name}")

        # Add suspicious strings if found
        if analysis.suspicious_strings:
            for idx, sus_string in enumerate(analysis.suspicious_strings[:10]):  # Limit to 10
                # Escape special characters in string
                escaped_string = sus_string.value.replace("\\", "\\\\").replace('"', '\\"')
                strings_section.append(f'        $sus_str_{idx} = "{escaped_string}" nocase')
                conditions_list.append("any of ($sus_str_*)")

        # Add entropy-based detection
        if analysis.entropy_info:
            high_entropy_sections = [e for e in analysis.entropy_info if e.entropy > 7.0]
            if high_entropy_sections:
                strings_section.append("        // High entropy sections detected")
                for section in high_entropy_sections[:3]:  # Limit to 3
                    strings_section.append(f"        // Section {section.section_name}: entropy={section.entropy:.2f}")

        # Add import hash if available
        if analysis.import_hash:
            strings_section.append(f"        // Import hash: {analysis.import_hash.imphash}")

        # Generate main rule
        main_rule = f"""
import "pe"
import "math"

rule {main_rule_name}_Protection_Detection {{
    meta:
        description = "Comprehensive protection detection for {Path(analysis.file_path).name}"
        file_type = "{analysis.file_type}"
        architecture = "{analysis.architecture}"
        is_packed = {str(analysis.is_packed).lower()}
        is_protected = {str(analysis.is_protected).lower()}
        detections_count = {len(analysis.detections)}
        generated_by = "Intellicrack Advanced Protection Analysis"

    strings:
{chr(10).join(strings_section) if strings_section else "        // No specific strings patterns"}

    condition:
        {" and ".join(conditions_list[:3]) if conditions_list else "uint32(0) == 0x00"}
}}"""

        yara_rules.append(main_rule)

        # Generate individual rules for each detection
        for detection in analysis.detections:
            rule_name = detection.name.replace(" ", "_").replace("-", "_").replace(".", "_")

            # Generate detection-specific patterns
            detection_patterns = self._generate_detection_patterns(detection)

            # Build detection-specific rule
            detection_rule = f"""
rule {rule_name}_Specific {{
    meta:
        description = "Specific detection for {detection.name}"
        type = "{detection.type.value}"
        confidence = {detection.confidence}
        version = "{detection.version if detection.version else "unknown"}"

    strings:
{chr(10).join(["        " + p for p in detection_patterns]) if detection_patterns else "        // Detection-specific patterns"}

    condition:
        {self._generate_detection_condition(detection)}
}}"""

            yara_rules.append(detection_rule)

        # Generate heuristic detection rules if available
        if analysis.heuristic_detections:
            heuristic_rule = self._generate_heuristic_yara_rule(analysis.heuristic_detections)
            yara_rules.append(heuristic_rule)

        return "\n".join(yara_rules)

    def _generate_detection_patterns(self, detection: DetectionResult) -> list[str]:
        """Generate YARA patterns for specific detection."""
        patterns = []

        # Common packer/protector patterns
        packer_patterns = {
            "UPX": [
                "$upx1 = { 55 50 58 21 }  // UPX signature",
                "$upx2 = { 55 50 58 30 }  // UPX0 section",
            ],
            "ASPack": ["$aspack = { 60 E8 00 00 00 00 5D 81 ED }  // ASPack entry"],
            "PECompact": ["$pecompact = { 50 45 43 6F 6D 70 61 63 74 }  // PECompact"],
            "Themida": [
                "$themida1 = { 8B C5 8B D4 60 E8 00 00 00 00 }  // Themida",
                "$themida2 = { B8 ?? ?? ?? ?? 60 0B C0 74 }",
            ],
            "VMProtect": [
                "$vmp1 = { 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? }  // VMProtect",
                "$vmp2 = { 9C 60 68 00 00 00 00 8B 74 24 }",
            ],
            "Obsidium": ["$obsidium = { EB 02 ?? ?? E8 25 00 00 00 }  // Obsidium"],
            "Armadillo": ["$armadillo = { 60 E8 00 00 00 00 5D 50 51 }  // Armadillo"],
        }

        # Check if detection name matches known patterns
        for packer_name, packer_sigs in packer_patterns.items():
            if packer_name.lower() in detection.name.lower():
                patterns.extend(packer_sigs)
                break

        # Add generic patterns if no specific match
        if not patterns:
            if detection.type == ProtectionType.PACKER:
                patterns.append("$generic_packer = { [4-8] E8 ?? ?? ?? ?? [4-8] }  // Generic packer pattern")
            elif detection.type == ProtectionType.PROTECTOR:
                patterns.append("$anti_debug = { 64 A1 30 00 00 00 }  // Check PEB for debugging")
                patterns.append("$is_debugger = { FF 15 ?? ?? ?? ?? 85 C0 }  // IsDebuggerPresent")
            elif detection.type == ProtectionType.OBFUSCATOR:
                patterns.append("$obfuscated = { [10-20] ( E9 | E8 | EB ) ?? ?? ?? ?? }  // Jump obfuscation")
            elif detection.type == ProtectionType.CRYPTOR:
                patterns.append("$xor_loop = { 80 34 ?? ?? 40 3D ?? ?? ?? ?? }  // XOR decryption loop")

        return patterns

    def _generate_detection_condition(self, detection: DetectionResult) -> str:
        """Generate YARA condition for specific detection."""
        base_conditions = []

        # File type conditions
        if detection.type in [ProtectionType.PACKER, ProtectionType.PROTECTOR]:
            base_conditions.append("(uint16(0) == 0x5A4D or uint32(0) == 0x464c457f)")

        # Pattern matching conditions
        if detection.confidence >= 90:
            base_conditions.append("all of them")
        elif detection.confidence >= 70:
            base_conditions.append("any of them")
        else:
            base_conditions.append("1 of them")

        # File size conditions for certain protections
        if detection.type == ProtectionType.PACKER:
            base_conditions.append("filesize < 10MB")

        return " and ".join(base_conditions) if base_conditions else "any of them"

    def _generate_heuristic_yara_rule(self, heuristic_detections: list[DetectionResult]) -> str:
        """Generate YARA rule for heuristic detections."""
        rule = (
            """
rule Heuristic_Protection_Detection {
    meta:
        description = "Heuristic detection patterns"
        detection_count = """
            + str(len(heuristic_detections))
            + """

    strings:
        // Anti-debugging techniques
        $anti_dbg1 = { 64 A1 30 00 00 00 }  // PEB access
        $anti_dbg2 = { 64 A1 18 00 00 00 }  // TEB access
        $anti_dbg3 = "IsDebuggerPresent"
        $anti_dbg4 = "CheckRemoteDebuggerPresent"
        $anti_dbg5 = "NtQueryInformationProcess"

        // Anti-VM techniques
        $anti_vm1 = "VMware"
        $anti_vm2 = "VirtualBox"
        $anti_vm3 = "QEMU"
        $anti_vm4 = { 0F 3F 07 0B }  // SIDT instruction

        // Suspicious API combinations
        $api1 = "VirtualProtect"
        $api2 = "VirtualAlloc"
        $api3 = "WriteProcessMemory"
        $api4 = "CreateRemoteThread"

    condition:
        2 of ($anti_dbg*) or
        2 of ($anti_vm*) or
        3 of ($api*)
}"""
        )
        return rule

    def get_format_capabilities(self, file_path: str) -> dict[str, bool]:
        """Check what protection engine can detect for this file format.

        Args:
            file_path: Path to file

        Returns:
            Dictionary of capability flags

        """
        # Determine file type first
        basic_analysis = self.detect_protections(file_path)

        capabilities = {
            "packers": True,
            "protectors": True,
            "compilers": True,
            "certificates": "PE" in basic_analysis.file_type,
            "resources": "PE" in basic_analysis.file_type,
            "imports": "PE" in basic_analysis.file_type or "ELF" in basic_analysis.file_type,
            "entropy": True,
            "strings": True,
            "overlay": "PE" in basic_analysis.file_type,
            "heuristics": True,
            "signatures": True,
        }

        return capabilities


# Convenience function for advanced analysis
def advanced_analyze(file_path: str, scan_mode: ScanMode = ScanMode.DEEP, enable_heuristic: bool = True) -> AdvancedProtectionAnalysis:
    """Quick advanced analysis function."""
    analyzer = IntellicrackAdvancedProtection()
    return analyzer.detect_protections_advanced(
        file_path,
        scan_mode=scan_mode,
        enable_heuristic=enable_heuristic,
    )
