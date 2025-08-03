"""Advanced Intellicrack Protection Analysis Module

Enhanced features for comprehensive protection analysis capabilities.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import concurrent.futures
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger
from .intellicrack_protection_core import (
    DetectionResult,
    IntellicrackProtectionCore,
    ProtectionAnalysis,
    ProtectionType,
)

logger = get_logger(__name__)


class ScanMode(Enum):
    """Protection analysis scan modes"""

    NORMAL = "normal"
    DEEP = "deep"
    HEURISTIC = "heuristic"
    ALL = "all"


class ExportFormat(Enum):
    """Export formats supported by protection analysis"""

    JSON = "json"
    XML = "xml"
    TEXT = "text"
    CSV = "csv"
    HTML = "html"


@dataclass
class EntropyInfo:
    """Entropy information for file sections"""

    section_name: str
    offset: int
    size: int
    entropy: float
    packed: bool = False
    encrypted: bool = False


@dataclass
class CertificateInfo:
    """Digital certificate information"""

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
    """Resource information from PE files"""

    type: str
    name: str
    language: str
    size: int
    offset: int
    data_hash: str


@dataclass
class StringInfo:
    """String information with encoding"""

    value: str
    offset: int
    encoding: str
    length: int
    suspicious: bool = False


@dataclass
class ImportHash:
    """Import hash for similarity analysis"""

    imphash: str
    imphash_sorted: str
    rich_header_hash: str | None = None


@dataclass
class AdvancedProtectionAnalysis(ProtectionAnalysis):
    """Extended protection analysis with additional features"""

    entropy_info: list[EntropyInfo] = field(default_factory=list)
    certificates: list[CertificateInfo] = field(default_factory=list)
    resources: list[ResourceInfo] = field(default_factory=list)
    suspicious_strings: list[StringInfo] = field(default_factory=list)
    import_hash: ImportHash | None = None
    heuristic_detections: list[DetectionResult] = field(default_factory=list)
    similarity_hash: str | None = None
    file_format_details: dict[str, Any] = field(default_factory=dict)

    def __init__(self,
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
                 file_format_details: dict[str, Any] | None = None):
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
    """Advanced Intellicrack protection analysis with full feature support
    """

    def __init__(self, engine_path: str | None = None,
                 custom_db_path: str | None = None,
                 enable_cache: bool = True):
        """Initialize advanced protection analyzer

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
        """Find custom database directory"""
        base_path = Path(self.engine_path).parent
        custom_db = base_path / "db_custom"
        if custom_db.exists():
            return str(custom_db)
        return None

    def detect_protections_advanced(self,
                                  file_path: str,
                                  scan_mode: ScanMode = ScanMode.NORMAL,
                                  enable_heuristic: bool = True,
                                  export_format: ExportFormat = ExportFormat.JSON,
                                  extract_strings: bool = True,
                                  max_string_length: int = 1000) -> AdvancedProtectionAnalysis:
        """Advanced protection detection with full analysis features

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
            result = subprocess.run(cmd,
                                  check=False, capture_output=True,
                                  text=True,
                                  timeout=timeout)

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
                    file_path, max_string_length,
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
        """Parse advanced JSON output from protection engine"""
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
        die_data = json.loads(json_output)

        # Extract entropy information
        if "sections" in die_data:
            for section in die_data["sections"]:
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
        if "certificates" in die_data:
            for cert in die_data["certificates"]:
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
        if "resources" in die_data:
            for resource in die_data["resources"]:
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
        if "heuristic" in die_data:
            for heur in die_data["heuristic"]:
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
        """Parse advanced XML output from protection engine"""
        analysis = AdvancedProtectionAnalysis(
            file_path=file_path,
            file_type="Unknown",
            architecture="Unknown",
        )

        try:
            root = ET.fromstring(xml_output)

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

        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")

        return analysis

    def _parse_advanced_text(self, file_path: str, text_output: str) -> AdvancedProtectionAnalysis:
        """Parse advanced text output from protection engine"""
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
        """Extract suspicious strings from file"""
        suspicious_patterns = [
            "kernel32", "ntdll", "VirtualProtect", "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent", "OutputDebugString", "license",
            "crack", "patch", "keygen", "serial", "registration", "trial",
            "eval", "demo", "unregistered", "http://", "https://", "ftp://",
            "cmd.exe", "powershell", "reg.exe", "wmic", "\\x00\\x00\\x00",
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "password",
            "passwd", "pwd", "admin", "root", "sa", "dbo",
        ]

        suspicious_strings = []

        try:
            # Use protection engine's string extraction
            cmd = [self.engine_path, "-s", file_path]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line and len(line) < max_length:
                        # Check if string is suspicious
                        is_suspicious = any(pattern.lower() in line.lower()
                                          for pattern in suspicious_patterns)

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
        """Calculate import hash for file"""
        try:
            # Use pefile or similar library to calculate imphash
            # This is a placeholder implementation
            with open(file_path, "rb") as f:
                data = f.read(1024)  # Read first 1KB
                imphash = hashlib.md5(data).hexdigest()

            return ImportHash(
                imphash=imphash,
                imphash_sorted=imphash,  # Would need proper implementation
                rich_header_hash=None,
            )
        except Exception as e:
            logger.error(f"Error calculating import hash: {e}")
            return None

    def _calculate_similarity_hash(self, file_path: str) -> str | None:
        """Calculate similarity hash (ssdeep or similar)"""
        try:
            # This would use ssdeep or similar fuzzy hashing
            # Placeholder implementation using SHA256
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Error calculating similarity hash: {e}")
            return None

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate file hash for caching"""
        try:
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return ""

    def batch_analyze(self, file_paths: list[str],
                     max_workers: int = 4,
                     scan_mode: ScanMode = ScanMode.NORMAL) -> dict[str, AdvancedProtectionAnalysis]:
        """Analyze multiple files in parallel

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

    def create_custom_signature(self,
                              name: str,
                              pattern: bytes,
                              offset: int = 0,
                              description: str = "") -> bool:
        """Create custom signature for protection analysis

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
        """Export detection results as YARA rules

        Args:
            analysis: Analysis results to export

        Returns:
            YARA rule string

        """
        yara_rules = []

        for detection in analysis.detections:
            rule_name = detection.name.replace(" ", "_").replace("-", "_")
            rule = f"""
rule {rule_name}_Detection {{
    meta:
        description = "Detection for {detection.name}"
        type = "{detection.type.value}"
        confidence = {detection.confidence}

    strings:
        // Add specific strings based on detection

    condition:
        // Add conditions based on detection type
        uint16(0) == 0x5A4D  // MZ header for PE files
}}
"""
            yara_rules.append(rule)

        return "\n".join(yara_rules)

    def get_format_capabilities(self, file_path: str) -> dict[str, bool]:
        """Check what protection engine can detect for this file format

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
def advanced_analyze(file_path: str,
                    scan_mode: ScanMode = ScanMode.DEEP,
                    enable_heuristic: bool = True) -> AdvancedProtectionAnalysis:
    """Quick advanced analysis function"""
    analyzer = IntellicrackAdvancedProtection()
    return analyzer.detect_protections_advanced(
        file_path,
        scan_mode=scan_mode,
        enable_heuristic=enable_heuristic,
    )


# Backward compatibility alias
DIEAdvancedDetector = IntellicrackAdvancedProtection
