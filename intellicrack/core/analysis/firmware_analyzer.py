"""
Firmware Analyzer

Advanced firmware analysis and embedded file extraction using Binwalk.
Provides comprehensive firmware security analysis, embedded file extraction,
and integration with Intellicrack's protection analysis workflow.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ...utils.logger import get_logger

logger = get_logger(__name__)

try:
    import binwalk
    BINWALK_AVAILABLE = True
except ImportError:
    BINWALK_AVAILABLE = False
    logger.warning("Binwalk not available - firmware analysis disabled")


class FirmwareType(Enum):
    """Types of firmware detected"""
    ROUTER_FIRMWARE = "router"
    IOT_DEVICE = "iot_device"
    BOOTLOADER = "bootloader"
    KERNEL_IMAGE = "kernel"
    FILESYSTEM = "filesystem"
    BIOS_UEFI = "bios_uefi"
    EMBEDDED_BINARY = "embedded_binary"
    UNKNOWN = "unknown"


class SecurityFindingType(Enum):
    """Types of security findings"""
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"
    BACKDOOR_BINARY = "backdoor_binary"
    VULNERABLE_COMPONENT = "vulnerable_component"
    WEAK_ENCRYPTION = "weak_encryption"
    DEBUG_INTERFACE = "debug_interface"
    DEFAULT_PASSWORD = "default_password"


@dataclass
class FirmwareSignature:
    """Single firmware signature detection"""
    offset: int
    signature_name: str
    description: str
    file_type: str
    size: Optional[int] = None
    confidence: float = 1.0

    @property
    def is_executable(self) -> bool:
        """Check if signature indicates executable content"""
        executable_types = ["elf", "pe", "binary", "bootloader", "kernel"]
        return any(etype in self.file_type.lower() for etype in executable_types)

    @property
    def is_filesystem(self) -> bool:
        """Check if signature indicates filesystem"""
        fs_types = ["squashfs", "cramfs", "jffs2", "yaffs", "ext", "fat", "ntfs"]
        return any(fs in self.file_type.lower() for fs in fs_types)


@dataclass
class ExtractedFile:
    """Information about an extracted file"""
    file_path: str
    original_offset: int
    file_type: str
    size: int
    hash: str
    is_executable: bool = False
    permissions: str = ""
    extracted_strings: List[str] = field(default_factory=list)
    security_analysis: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_path(cls, file_path: str, original_offset: int = 0) -> 'ExtractedFile':
        """Create ExtractedFile from filesystem path"""
        try:
            stat_info = os.stat(file_path)

            # Calculate file hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            # Determine file type
            file_type = "unknown"
            if os.access(file_path, os.X_OK):
                file_type = "executable"
            elif file_path.endswith(('.txt', '.log', '.conf', '.cfg')):
                file_type = "text"
            elif file_path.endswith(('.bin', '.fw', '.img')):
                file_type = "binary"

            return cls(
                file_path=file_path,
                original_offset=original_offset,
                file_type=file_type,
                size=stat_info.st_size,
                hash=file_hash,
                is_executable=os.access(file_path, os.X_OK),
                permissions=oct(stat_info.st_mode)[-3:]
            )
        except Exception as e:
            logger.error(f"Error creating ExtractedFile from {file_path}: {e}")
            return cls(
                file_path=file_path,
                original_offset=original_offset,
                file_type="error",
                size=0,
                hash="",
                is_executable=False
            )


@dataclass
class SecurityFinding:
    """Security-related finding in firmware"""
    finding_type: SecurityFindingType
    description: str
    file_path: str
    offset: int
    severity: str  # "critical", "high", "medium", "low"
    confidence: float
    evidence: str = ""
    remediation: str = ""

    @property
    def is_critical(self) -> bool:
        """Check if finding is critical severity"""
        return self.severity == "critical"


@dataclass
class FirmwareExtraction:
    """Results of firmware extraction process"""
    extracted_files: List[ExtractedFile] = field(default_factory=list)
    extraction_directory: str = ""
    success: bool = False
    errors: List[str] = field(default_factory=list)
    total_extracted: int = 0
    extraction_time: float = 0.0

    @property
    def executable_files(self) -> List[ExtractedFile]:
        """Get all executable files"""
        return [f for f in self.extracted_files if f.is_executable]

    @property
    def text_files(self) -> List[ExtractedFile]:
        """Get all text/config files"""
        return [f for f in self.extracted_files if f.file_type in ["text", "config"]]


@dataclass
class FirmwareAnalysisResult:
    """Complete firmware analysis results"""
    file_path: str
    firmware_type: FirmwareType = FirmwareType.UNKNOWN
    signatures: List[FirmwareSignature] = field(default_factory=list)
    extractions: Optional[FirmwareExtraction] = None
    entropy_analysis: Dict[str, Any] = field(default_factory=dict)
    security_findings: List[SecurityFinding] = field(default_factory=list)
    analysis_time: float = 0.0
    error: Optional[str] = None

    @property
    def has_extractions(self) -> bool:
        """Check if any files were extracted"""
        return self.extractions is not None and self.extractions.success

    @property
    def critical_findings(self) -> List[SecurityFinding]:
        """Get critical security findings"""
        return [f for f in self.security_findings if f.is_critical]

    @property
    def embedded_executables(self) -> List[ExtractedFile]:
        """Get embedded executable files"""
        if not self.has_extractions:
            return []
        return self.extractions.executable_files


class FirmwareAnalyzer:
    """
    Advanced firmware analysis engine using Binwalk.
    
    Provides comprehensive firmware security analysis including:
    - Embedded file extraction and analysis
    - Security vulnerability detection
    - Hardcoded credential discovery
    - Bootloader and kernel analysis
    - Integration with ICP backend for unified results
    """

    def __init__(self, work_directory: Optional[str] = None):
        """Initialize the firmware analyzer with working directory configuration."""
        if work_directory:
            self.work_directory = Path(work_directory)
        else:
            # Create temporary directory
            self.work_directory = Path(tempfile.mkdtemp(prefix="firmware_analysis_"))
        
        self.work_directory.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("IntellicrackLogger.FirmwareAnalyzer")
        
        # Storage for analysis results
        self.extracted_files = []
        self.analysis_results = {}  # Prevent infinite recursion

    def analyze_firmware(
        self,
        file_path: str,
        extract_files: bool = True,
        analyze_security: bool = True,
        extraction_depth: int = 2
    ) -> FirmwareAnalysisResult:
        """
        Perform comprehensive firmware analysis
        
        Args:
            file_path: Path to firmware file
            extract_files: Whether to extract embedded files
            analyze_security: Whether to perform security analysis
            extraction_depth: Maximum extraction depth
            
        Returns:
            FirmwareAnalysisResult with complete analysis
        """
        start_time = time.time()

        if not os.path.exists(file_path):
            return FirmwareAnalysisResult(
                file_path=file_path,
                error=f"File not found: {file_path}"
            )

        if not BINWALK_AVAILABLE:
            return FirmwareAnalysisResult(
                file_path=file_path,
                error="Binwalk not available"
            )

        try:
            result = FirmwareAnalysisResult(file_path=file_path)

            # Track analyzed files to prevent infinite recursion
            abs_path = os.path.abspath(file_path)
            if abs_path in self.analyzed_files:
                logger.debug(f"File already analyzed: {abs_path}")
                return result
            self.analyzed_files.add(abs_path)

            # Step 1: Signature scanning
            logger.info(f"Scanning firmware signatures: {file_path}")
            result.signatures = self._scan_signatures(file_path)

            # Step 2: Determine firmware type
            result.firmware_type = self._determine_firmware_type(file_path, result.signatures)

            # Step 3: Entropy analysis
            logger.info("Performing entropy analysis")
            result.entropy_analysis = self._analyze_entropy(file_path)

            # Step 4: File extraction
            if extract_files and result.signatures:
                logger.info("Extracting embedded files")
                result.extractions = self._extract_embedded_files(
                    file_path,
                    max_depth=min(extraction_depth, self.extraction_depth_limit)
                )

            # Step 5: Security analysis
            if analyze_security:
                logger.info("Performing security analysis")
                result.security_findings = self._analyze_security(file_path, result.extractions)

            result.analysis_time = time.time() - start_time
            logger.info(f"Firmware analysis complete: {len(result.signatures)} signatures, "
                       f"{len(result.security_findings)} security findings")

            return result

        except Exception as e:
            logger.error(f"Firmware analysis error: {e}")
            return FirmwareAnalysisResult(
                file_path=file_path,
                error=str(e),
                analysis_time=time.time() - start_time
            )

    def _scan_signatures(self, file_path: str) -> List[FirmwareSignature]:
        """Scan for firmware signatures using Binwalk"""
        signatures = []

        try:
            # Use binwalk for signature scanning
            for module in binwalk.scan(file_path, signature=True, quiet=True):
                for result in module.results:
                    signature = FirmwareSignature(
                        offset=result.offset,
                        signature_name=result.description.split(',')[0].strip(),
                        description=result.description,
                        file_type=self._extract_file_type(result.description),
                        size=getattr(result, 'size', None)
                    )
                    signatures.append(signature)

        except Exception as e:
            logger.error(f"Signature scanning failed: {e}")
            # Fallback to basic file type detection
            signatures.append(FirmwareSignature(
                offset=0,
                signature_name="Unknown Binary",
                description="Binary file (signature scan failed)",
                file_type="binary"
            ))

        return signatures

    def _extract_file_type(self, description: str) -> str:
        """Extract file type from Binwalk description"""
        desc_lower = description.lower()

        # Map common descriptions to file types
        type_mappings = {
            'elf': 'elf',
            'pe32': 'pe',
            'squashfs': 'squashfs',
            'cramfs': 'cramfs',
            'jffs2': 'jffs2',
            'kernel': 'kernel',
            'bootloader': 'bootloader',
            'certificate': 'certificate',
            'private key': 'private_key',
            'zip': 'archive',
            'gzip': 'archive',
            'tar': 'archive'
        }

        for keyword, file_type in type_mappings.items():
            if keyword in desc_lower:
                return file_type

        return "binary"

    def _determine_firmware_type(self, file_path: str, signatures: List[FirmwareSignature]) -> FirmwareType:
        """Determine the type of firmware based on signatures and filename"""
        filename = os.path.basename(file_path).lower()

        # Check filename patterns
        if any(pattern in filename for pattern in ['router', 'openwrt', 'ddwrt']):
            return FirmwareType.ROUTER_FIRMWARE
        elif any(pattern in filename for pattern in ['bios', 'uefi']):
            return FirmwareType.BIOS_UEFI
        elif 'kernel' in filename or 'vmlinuz' in filename:
            return FirmwareType.KERNEL_IMAGE
        elif 'boot' in filename:
            return FirmwareType.BOOTLOADER

        # Check signatures
        for sig in signatures:
            if 'kernel' in sig.description.lower():
                return FirmwareType.KERNEL_IMAGE
            elif 'bootloader' in sig.description.lower():
                return FirmwareType.BOOTLOADER
            elif any(fs in sig.description.lower() for fs in ['squashfs', 'cramfs', 'jffs2']):
                return FirmwareType.FILESYSTEM

        # Default based on file size and structure
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # > 10MB
                return FirmwareType.ROUTER_FIRMWARE
            elif file_size > 1 * 1024 * 1024:  # > 1MB
                return FirmwareType.IOT_DEVICE
        except:
            pass

        return FirmwareType.UNKNOWN

    def _analyze_entropy(self, file_path: str) -> Dict[str, Any]:
        """Analyze file entropy to detect encryption/compression"""
        entropy_analysis = {
            "file_entropy": 0.0,
            "encrypted_regions": [],
            "compressed_regions": [],
            "analysis_blocks": []
        }

        try:
            # Use binwalk for entropy analysis
            for module in binwalk.scan(file_path, entropy=True, quiet=True):
                for result in module.results:
                    block_info = {
                        "offset": result.offset,
                        "entropy": getattr(result, 'entropy', 0.0),
                        "description": result.description
                    }
                    entropy_analysis["analysis_blocks"].append(block_info)

                    # Classify high entropy regions
                    entropy_val = getattr(result, 'entropy', 0.0)
                    if entropy_val > 7.5:
                        entropy_analysis["encrypted_regions"].append({
                            "offset": result.offset,
                            "entropy": entropy_val,
                            "likely_type": "encrypted"
                        })
                    elif entropy_val > 6.5:
                        entropy_analysis["compressed_regions"].append({
                            "offset": result.offset,
                            "entropy": entropy_val,
                            "likely_type": "compressed"
                        })

            # Calculate overall file entropy
            if entropy_analysis["analysis_blocks"]:
                avg_entropy = sum(b.get("entropy", 0) for b in entropy_analysis["analysis_blocks"])
                avg_entropy /= len(entropy_analysis["analysis_blocks"])
                entropy_analysis["file_entropy"] = round(avg_entropy, 3)

        except Exception as e:
            logger.error(f"Entropy analysis failed: {e}")
            # Fallback to basic entropy calculation
            try:
                entropy_analysis["file_entropy"] = self._calculate_basic_entropy(file_path)
            except:
                entropy_analysis["file_entropy"] = 0.0

        return entropy_analysis

    def _calculate_basic_entropy(self, file_path: str) -> float:
        """Calculate basic Shannon entropy"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)  # Read first 1MB

            if not data:
                return 0.0

            # Calculate byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)

            return round(entropy, 3)
        except Exception as e:
            logger.error(f"Basic entropy calculation failed: {e}")
            return 0.0

    def _extract_embedded_files(self, file_path: str, max_depth: int = 2) -> FirmwareExtraction:
        """Extract embedded files using Binwalk"""
        start_time = time.time()
        extraction = FirmwareExtraction()

        # Create temporary extraction directory
        extraction_dir = tempfile.mkdtemp(prefix="firmware_extract_", dir=self.work_directory)
        extraction.extraction_directory = extraction_dir

        try:
            # Use binwalk for extraction
            for module in binwalk.scan(file_path,
                                     extract=True,
                                     directory=extraction_dir,
                                     quiet=True):
                extraction.success = True

                # Process extracted files
                for extracted_path in Path(extraction_dir).rglob("*"):
                    if extracted_path.is_file():
                        try:
                            extracted_file = ExtractedFile.from_path(str(extracted_path))

                            # Analyze extracted file
                            self._analyze_extracted_file(extracted_file)

                            extraction.extracted_files.append(extracted_file)
                            extraction.total_extracted += 1

                        except Exception as e:
                            logger.warning(f"Error processing extracted file {extracted_path}: {e}")
                            extraction.errors.append(f"Failed to process {extracted_path}: {e}")

            # Recursive extraction if depth allows
            if max_depth > 1 and extraction.extracted_files:
                for extracted_file in extraction.extracted_files[:10]:  # Limit to first 10 files
                    if extracted_file.size > 1024 and extracted_file.file_type == "binary":
                        try:
                            sub_result = self.analyze_firmware(
                                extracted_file.file_path,
                                extract_files=True,
                                analyze_security=False,
                                extraction_depth=max_depth - 1
                            )
                            if sub_result.has_extractions:
                                extraction.extracted_files.extend(sub_result.extractions.extracted_files)
                                extraction.total_extracted += sub_result.extractions.total_extracted
                        except Exception as e:
                            logger.debug(f"Recursive extraction failed for {extracted_file.file_path}: {e}")

        except Exception as e:
            logger.error(f"File extraction failed: {e}")
            extraction.success = False
            extraction.errors.append(str(e))

        extraction.extraction_time = time.time() - start_time
        return extraction

    def _analyze_extracted_file(self, extracted_file: ExtractedFile):
        """Analyze an individual extracted file"""
        try:
            # Extract strings from the file
            extracted_file.extracted_strings = self._extract_strings(extracted_file.file_path)

            # Security analysis
            extracted_file.security_analysis = self._analyze_file_security(extracted_file.file_path)

        except Exception as e:
            logger.debug(f"Failed to analyze extracted file {extracted_file.file_path}: {e}")

    def _extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """Extract printable strings from file"""
        strings = []
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)  # Read up to 1MB

            current_string = ""
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                    current_string = ""

            # Don't forget the last string
            if len(current_string) >= min_length:
                strings.append(current_string)

            # Limit to most interesting strings
            return strings[:100]

        except Exception as e:
            logger.debug(f"String extraction failed for {file_path}: {e}")
            return []

    def _analyze_file_security(self, file_path: str) -> Dict[str, Any]:
        """Perform security analysis on a file"""
        security_info = {
            "has_credentials": False,
            "has_crypto_keys": False,
            "suspicious_strings": [],
            "file_permissions": "",
            "is_setuid": False
        }

        try:
            # Check file permissions
            stat_info = os.stat(file_path)
            security_info["file_permissions"] = oct(stat_info.st_mode)[-3:]
            security_info["is_setuid"] = bool(stat_info.st_mode & 0o4000)

            # Analyze strings for security issues
            strings = self._extract_strings(file_path)
            for string in strings:
                if self._is_suspicious_string(string):
                    security_info["suspicious_strings"].append(string)

                if self._looks_like_credential(string):
                    security_info["has_credentials"] = True

                if self._looks_like_crypto_key(string):
                    security_info["has_crypto_keys"] = True

        except Exception as e:
            logger.debug(f"Security analysis failed for {file_path}: {e}")

        return security_info

    def _analyze_security(self, file_path: str, extractions: Optional[FirmwareExtraction]) -> List[SecurityFinding]:
        """Perform comprehensive security analysis"""
        findings = []

        # Analyze main firmware file
        findings.extend(self._scan_for_credentials(file_path))
        findings.extend(self._scan_for_crypto_keys(file_path))
        findings.extend(self._scan_for_backdoors(file_path))

        # Analyze extracted files
        if extractions and extractions.success:
            for extracted_file in extractions.extracted_files:
                try:
                    # Check for security issues in extracted files
                    if extracted_file.security_analysis.get("has_credentials"):
                        findings.append(SecurityFinding(
                            finding_type=SecurityFindingType.HARDCODED_CREDENTIALS,
                            description="Hardcoded credentials found in extracted file",
                            file_path=extracted_file.file_path,
                            offset=0,
                            severity="high",
                            confidence=0.8,
                            evidence=str(extracted_file.security_analysis.get("suspicious_strings", [])[:3])
                        ))

                    if extracted_file.security_analysis.get("is_setuid"):
                        findings.append(SecurityFinding(
                            finding_type=SecurityFindingType.VULNERABLE_COMPONENT,
                            description="SetUID binary found - potential privilege escalation",
                            file_path=extracted_file.file_path,
                            offset=0,
                            severity="medium",
                            confidence=0.9,
                            evidence=f"Permissions: {extracted_file.security_analysis.get('file_permissions')}"
                        ))

                except Exception as e:
                    logger.debug(f"Security analysis failed for {extracted_file.file_path}: {e}")

        return findings

    def _scan_for_credentials(self, file_path: str) -> List[SecurityFinding]:
        """Scan for hardcoded credentials"""
        findings = []

        try:
            strings = self._extract_strings(file_path)

            # Common credential patterns
            credential_patterns = [
                (r'password\s*[=:]\s*["\']?([^"\'\s]{4,})', "password"),
                (r'admin["\']?\s*[=:]\s*["\']?([^"\'\s]{4,})', "admin_password"),
                (r'root["\']?\s*[=:]\s*["\']?([^"\'\s]{4,})', "root_password"),
                (r'key\s*[=:]\s*["\']?([A-Za-z0-9+/]{20,})', "api_key"),
                (r'secret\s*[=:]\s*["\']?([A-Za-z0-9+/]{16,})', "secret"),
            ]

            for string in strings:
                for pattern, cred_type in credential_patterns:
                    matches = re.finditer(pattern, string, re.IGNORECASE)
                    for match in matches:
                        findings.append(SecurityFinding(
                            finding_type=SecurityFindingType.HARDCODED_CREDENTIALS,
                            description=f"Hardcoded {cred_type} detected",
                            file_path=file_path,
                            offset=0,  # String offset not available
                            severity="critical" if cred_type.endswith("password") else "high",
                            confidence=0.7,
                            evidence=match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0),
                            remediation=f"Remove hardcoded {cred_type} and use secure configuration"
                        ))

        except Exception as e:
            logger.debug(f"Credential scanning failed: {e}")

        return findings

    def _scan_for_crypto_keys(self, file_path: str) -> List[SecurityFinding]:
        """Scan for cryptographic keys"""
        findings = []

        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            # Look for PEM-encoded keys
            pem_patterns = [
                b"-----BEGIN PRIVATE KEY-----",
                b"-----BEGIN RSA PRIVATE KEY-----",
                b"-----BEGIN DSA PRIVATE KEY-----",
                b"-----BEGIN EC PRIVATE KEY-----",
                b"-----BEGIN CERTIFICATE-----"
            ]

            for pattern in pem_patterns:
                offset = content.find(pattern)
                if offset != -1:
                    key_type = pattern.decode().replace("-----BEGIN ", "").replace("-----", "")
                    findings.append(SecurityFinding(
                        finding_type=SecurityFindingType.PRIVATE_KEY if "PRIVATE" in key_type else SecurityFindingType.CERTIFICATE,
                        description=f"{key_type} found in firmware",
                        file_path=file_path,
                        offset=offset,
                        severity="critical" if "PRIVATE" in key_type else "medium",
                        confidence=0.95,
                        evidence=pattern.decode(),
                        remediation="Remove embedded cryptographic material"
                    ))

        except Exception as e:
            logger.debug(f"Crypto key scanning failed: {e}")

        return findings

    def _scan_for_backdoors(self, file_path: str) -> List[SecurityFinding]:
        """Scan for potential backdoors"""
        findings = []

        try:
            strings = self._extract_strings(file_path)

            # Use subprocess to check for additional system tools
            try:
                result = subprocess.run(['file', file_path], capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and 'executable' in result.stdout.lower():
                    findings.append(SecurityFinding(
                        finding_type=SecurityFindingType.BACKDOOR_BINARY,
                        description="Executable file detected via system file command",
                        file_path=file_path,
                        offset=0,
                        severity="medium",
                        confidence=0.8,
                        evidence=result.stdout.strip()[:100],
                        remediation="Verify executable legitimacy"
                    ))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Suspicious string patterns that might indicate backdoors
            backdoor_patterns = [
                (r'telnetd.*-l.*sh', "Telnet backdoor"),
                (r'nc.*-l.*-e', "Netcat backdoor"),
                (r'/bin/sh.*&', "Background shell"),
                (r'busybox.*telnetd', "BusyBox telnet service"),
                (r'debug.*interface', "Debug interface"),
                (r'maintenance.*mode', "Maintenance mode"),
            ]

            for string in strings:
                for pattern, description in backdoor_patterns:
                    if re.search(pattern, string, re.IGNORECASE):
                        findings.append(SecurityFinding(
                            finding_type=SecurityFindingType.BACKDOOR_BINARY,
                            description=description + " detected",
                            file_path=file_path,
                            offset=0,
                            severity="high",
                            confidence=0.6,
                            evidence=string[:100],
                            remediation="Review and remove suspicious functionality"
                        ))

        except Exception as e:
            logger.debug(f"Backdoor scanning failed: {e}")

        return findings

    def _is_suspicious_string(self, string: str) -> bool:
        """Check if a string looks suspicious"""
        suspicious_keywords = [
            "password", "passwd", "secret", "key", "token", "admin", "root",
            "debug", "test", "backdoor", "shell", "cmd", "execute"
        ]

        string_lower = string.lower()
        return any(keyword in string_lower for keyword in suspicious_keywords)

    def _looks_like_credential(self, string: str) -> bool:
        """Check if string looks like a credential"""
        # Simple heuristics for credential detection
        if len(string) < 4:
            return False

        credential_indicators = [
            ("password", 6), ("passwd", 5), ("admin", 4), ("root", 4),
            ("user", 4), ("login", 5), ("auth", 4)
        ]

        string_lower = string.lower()
        for indicator, min_len in credential_indicators:
            if indicator in string_lower and len(string) >= min_len:
                return True

        return False

    def _looks_like_crypto_key(self, string: str) -> bool:
        """Check if string looks like a cryptographic key"""
        # Base64-like patterns of sufficient length
        if len(string) >= 20:
            # Check for base64 characteristics
            base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
            if len(set(string) - base64_chars) == 0:
                return True

        # Hex patterns
        if len(string) >= 32:
            try:
                int(string, 16)
                return True
            except ValueError:
                pass

        return False

    def generate_icp_supplemental_data(self, analysis_result: FirmwareAnalysisResult) -> Dict[str, Any]:
        """
        Generate supplemental data for ICP backend integration
        
        Args:
            analysis_result: Firmware analysis results
            
        Returns:
            Dictionary with supplemental firmware data for ICP
        """
        if analysis_result.error:
            return {"error": analysis_result.error}

        supplemental_data = {
            "firmware_analysis": {
                "firmware_type": analysis_result.firmware_type.value,
                "signatures_found": len(analysis_result.signatures),
                "files_extracted": analysis_result.extractions.total_extracted if analysis_result.has_extractions else 0,
                "security_findings": len(analysis_result.security_findings),
                "analysis_time": analysis_result.analysis_time
            },
            "embedded_components": [],
            "security_indicators": [],
            "entropy_indicators": [],
            "extracted_executables": []
        }

        # Process signatures
        for sig in analysis_result.signatures:
            supplemental_data["embedded_components"].append({
                "type": sig.file_type,
                "name": sig.signature_name,
                "offset": sig.offset,
                "size": sig.size,
                "confidence": sig.confidence,
                "is_executable": sig.is_executable,
                "is_filesystem": sig.is_filesystem
            })

        # Process security findings
        for finding in analysis_result.security_findings:
            supplemental_data["security_indicators"].append({
                "type": finding.finding_type.value,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "description": finding.description,
                "file": finding.file_path,
                "remediation": finding.remediation
            })

        # Process entropy analysis
        if analysis_result.entropy_analysis:
            supplemental_data["entropy_indicators"] = {
                "file_entropy": analysis_result.entropy_analysis.get("file_entropy", 0.0),
                "encrypted_regions": len(analysis_result.entropy_analysis.get("encrypted_regions", [])),
                "compressed_regions": len(analysis_result.entropy_analysis.get("compressed_regions", []))
            }

        # Process extracted executables
        if analysis_result.has_extractions:
            for exe_file in analysis_result.embedded_executables:
                supplemental_data["extracted_executables"].append({
                    "file_path": exe_file.file_path,
                    "size": exe_file.size,
                    "hash": exe_file.hash,
                    "permissions": exe_file.permissions,
                    "security_analysis": exe_file.security_analysis
                })

        return supplemental_data

    def export_analysis_report(self, analysis_result: FirmwareAnalysisResult, output_path: str) -> Tuple[bool, str]:
        """
        Export firmware analysis results to JSON report
        
        Args:
            analysis_result: Analysis results to export
            output_path: Path to save the JSON report
            
        Returns:
            Tuple of (success, message)
        """
        try:
            report_data = {
                "analysis_metadata": {
                    "file_path": analysis_result.file_path,
                    "analysis_time": analysis_result.analysis_time,
                    "firmware_type": analysis_result.firmware_type.value,
                    "timestamp": time.time()
                },
                "signatures": [
                    {
                        "offset": sig.offset,
                        "name": sig.signature_name,
                        "description": sig.description,
                        "file_type": sig.file_type,
                        "size": sig.size,
                        "confidence": sig.confidence
                    }
                    for sig in analysis_result.signatures
                ],
                "security_findings": [
                    {
                        "type": finding.finding_type.value,
                        "description": finding.description,
                        "severity": finding.severity,
                        "confidence": finding.confidence,
                        "evidence": finding.evidence,
                        "remediation": finding.remediation
                    }
                    for finding in analysis_result.security_findings
                ],
                "entropy_analysis": analysis_result.entropy_analysis,
                "error": analysis_result.error
            }

            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)

            return True, f"Report exported to {output_path}"

        except Exception as e:
            return False, f"Failed to export report: {e}"

    def cleanup_extractions(self, extraction_directory: str):
        """Clean up extraction directory"""
        try:
            if os.path.exists(extraction_directory):
                shutil.rmtree(extraction_directory)
                logger.debug(f"Cleaned up extraction directory: {extraction_directory}")
        except Exception as e:
            logger.warning(f"Failed to cleanup extraction directory: {e}")


# Singleton instance
_firmware_analyzer: Optional[FirmwareAnalyzer] = None


def get_firmware_analyzer() -> Optional[FirmwareAnalyzer]:
    """Get or create the firmware analyzer singleton"""
    global _firmware_analyzer
    if _firmware_analyzer is None and BINWALK_AVAILABLE:
        try:
            _firmware_analyzer = FirmwareAnalyzer()
        except Exception as e:
            logger.error(f"Failed to initialize firmware analyzer: {e}")
            return None
    return _firmware_analyzer


def is_binwalk_available() -> bool:
    """Check if Binwalk functionality is available"""
    return BINWALK_AVAILABLE


def analyze_firmware_file(file_path: str) -> Optional[FirmwareAnalysisResult]:
    """Quick firmware analysis function for integration"""
    analyzer = get_firmware_analyzer()
    if analyzer:
        return analyzer.analyze_firmware(file_path)
    return None
