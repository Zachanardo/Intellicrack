"""Firmware Analysis Tool for LLM Integration.

Provides AI models with the ability to run comprehensive firmware analysis
using Binwalk to detect embedded files, security issues, and firmware patterns.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
from typing import Any

from ...core.analysis.firmware_analyzer import get_firmware_analyzer, is_binwalk_available
from ...utils.logger import get_logger


logger = get_logger(__name__)


class FirmwareAnalysisTool:
    """LLM tool for running firmware analysis using Binwalk"""

    def __init__(self) -> None:
        """Initialize firmware analysis tool.

        Initializes the firmware analyzer and prepares an empty analysis cache
        for storing previously computed firmware analysis results.
        """
        self.analyzer = get_firmware_analyzer()
        self.analysis_cache: dict[str, Any] = {}

    def get_tool_definition(self) -> dict[str, Any]:
        """Get tool definition for LLM registration.

        Returns:
            dict[str, Any]: Tool definition dictionary containing tool name,
                description, and parameter schema for LLM integration. Schema
                includes file_path, extract_files, analyze_security,
                extraction_depth, include_strings, and detailed_output
                parameters.
        """
        return {
            "name": "firmware_analysis",
            "description": "Analyze firmware files using Binwalk to detect embedded files, security vulnerabilities, and firmware components",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the firmware file to analyze",
                    },
                    "extract_files": {
                        "type": "boolean",
                        "description": "Extract embedded files from firmware",
                        "default": True,
                    },
                    "analyze_security": {
                        "type": "boolean",
                        "description": "Perform security analysis on firmware and extracted files",
                        "default": True,
                    },
                    "extraction_depth": {
                        "type": "integer",
                        "description": "Maximum depth for recursive extraction (1-3)",
                        "minimum": 1,
                        "maximum": 3,
                        "default": 2,
                    },
                    "include_strings": {
                        "type": "boolean",
                        "description": "Extract and analyze strings from firmware",
                        "default": True,
                    },
                    "detailed_output": {
                        "type": "boolean",
                        "description": "Include detailed entropy and component analysis",
                        "default": True,
                    },
                },
                "required": ["file_path"],
            },
        }

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        """Execute firmware analysis.

        Performs comprehensive firmware analysis on the specified file using
        Binwalk. Supports extraction of embedded files, security analysis,
        and generation of bypass recommendations. Results are cached for
        performance optimization.

        Args:
            **kwargs: Tool parameters including file_path (required), extract_files,
                analyze_security, extraction_depth, include_strings, and
                detailed_output flags.

        Returns:
            dict[str, Any]: Analysis results containing success status, firmware
                signatures, security findings, extraction summary, bypass
                recommendations, and optional detailed analysis. Returns error
                dictionary if analysis fails or Binwalk is unavailable.

        Raises:
            FileNotFoundError: Implicitly handled if file_path does not exist.
            Exception: Caught and returned as error in result dictionary during
                firmware analysis execution.
        """
        file_path = kwargs.get("file_path")
        if not file_path or not os.path.exists(file_path):
            return {"success": False, "error": f"File not found: {file_path}"}

        if not is_binwalk_available():
            return {"success": False, "error": "Binwalk not available"}

        # Get parameters
        extract_files = kwargs.get("extract_files", True)
        analyze_security = kwargs.get("analyze_security", True)
        extraction_depth = kwargs.get("extraction_depth", 2)
        include_strings = kwargs.get("include_strings", True)
        detailed_output = kwargs.get("detailed_output", True)

        try:
            # Check cache
            cache_key = f"{file_path}:{extract_files}:{analyze_security}:{extraction_depth}"
            if cache_key in self.analysis_cache:
                logger.debug(f"Returning cached firmware analysis for {file_path}")
                cached_result: dict[str, Any] = self.analysis_cache[cache_key]
                cached_result["from_cache"] = True
                return cached_result

            # Run firmware analysis
            if not self.analyzer:
                return {"success": False, "error": "Firmware analyzer not initialized"}

            analysis_result = self.analyzer.analyze_firmware(
                file_path=file_path,
                extract_files=extract_files,
                analyze_security=analyze_security,
                extraction_depth=extraction_depth,
            )

            if analysis_result.error:
                return {"success": False, "error": analysis_result.error}

            # Build result for LLM consumption
            result: dict[str, Any] = {
                "success": True,
                "file_path": file_path,
                "analysis_time": analysis_result.analysis_time,
                "firmware_type": analysis_result.firmware_type.value,
                "signatures_found": len(analysis_result.signatures),
                "security_findings": len(analysis_result.security_findings),
                "firmware_signatures": self._format_signatures(analysis_result.signatures),
                "security_assessment": self._assess_security_findings(analysis_result.security_findings),
                "extraction_summary": self._format_extraction_summary(analysis_result.extractions),
                "bypass_recommendations": self._generate_bypass_recommendations(analysis_result),
                "from_cache": False,
            }

            # Add detailed analysis if requested
            if detailed_output:
                result["detailed_analysis"] = {
                    "entropy_analysis": analysis_result.entropy_analysis,
                    "embedded_components": self._analyze_embedded_components(analysis_result.signatures),
                    "firmware_classification": self._classify_firmware(analysis_result),
                    "attack_surface": self._analyze_attack_surface(analysis_result),
                }

            # Add extraction details if files were extracted
            if analysis_result.has_extractions and analysis_result.extractions:
                result["extracted_files"] = self._format_extracted_files(analysis_result.extractions.extracted_files)

                if include_strings:
                    result["interesting_strings"] = self._extract_interesting_strings(analysis_result.extractions.extracted_files)

            # Add security findings details
            if analysis_result.security_findings:
                result["security_findings_detailed"] = self._format_security_findings(analysis_result.security_findings)

            # Generate ICP supplemental data
            if self.analyzer:
                supplemental_data = self.analyzer.generate_icp_supplemental_data(analysis_result)
                result["icp_supplemental_data"] = supplemental_data

            # Cache result
            self.analysis_cache[cache_key] = result

            return result

        except Exception as e:
            logger.error(f"Firmware analysis error: {e}")
            return {"success": False, "error": str(e)}

    def _format_signatures(self, signatures: list[Any]) -> list[dict[str, Any]]:
        """Format firmware signatures for LLM consumption.

        Converts Binwalk firmware signature objects into structured dictionaries
        suitable for LLM analysis. Each signature includes offset, name, type,
        size, confidence, and flags indicating if it represents an executable
        or filesystem component.

        Args:
            signatures: List of firmware signature objects to format. Each
                signature must have offset, signature_name, description,
                file_type, size, confidence, is_executable, and
                is_filesystem attributes.

        Returns:
            list[dict[str, Any]]: List of formatted signature dictionaries
                containing offset, name, description, file_type, size,
                confidence, is_executable, and is_filesystem keys for each
                firmware signature.
        """
        formatted_signatures: list[dict[str, Any]] = []

        for sig in signatures:
            sig_data: dict[str, Any] = {
                "offset": sig.offset,
                "name": sig.signature_name,
                "description": sig.description,
                "file_type": sig.file_type,
                "size": sig.size,
                "confidence": sig.confidence,
                "is_executable": sig.is_executable,
                "is_filesystem": sig.is_filesystem,
            }
            formatted_signatures.append(sig_data)

        return formatted_signatures

    def _assess_security_findings(self, findings: list[Any]) -> dict[str, Any]:
        """Assess security implications of firmware findings.

        Analyzes security findings from firmware analysis and calculates an
        overall risk assessment. Categorizes findings by severity level,
        computes a normalized security score (0-10), and identifies primary
        concerns and immediate threats for LLM-based analysis.

        Args:
            findings: List of security finding objects to assess. Each finding
                must have severity, is_critical, description, and other
                attributes for severity-based categorization.

        Returns:
            dict[str, Any]: Assessment dictionary containing overall_risk_level
                (critical/high/medium/low), critical_findings count,
                high_findings count, medium_findings count, low_findings count,
                security_score (0-10.0), primary_concerns list, and
                immediate_threats list for critical findings.
        """
        assessment: dict[str, Any] = {
            "overall_risk_level": "low",
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "security_score": 0.0,
            "primary_concerns": [],
            "immediate_threats": [],
        }

        if not findings:
            return assessment

        # Categorize findings by severity
        for finding in findings:
            severity = finding.severity.lower()
            if severity == "critical":
                assessment["critical_findings"] = int(assessment["critical_findings"]) + 1
                assessment["immediate_threats"].append(finding.description)
            elif severity == "high":
                assessment["high_findings"] = int(assessment["high_findings"]) + 1
                assessment["primary_concerns"].append(finding.description)
            elif severity == "medium":
                assessment["medium_findings"] = int(assessment["medium_findings"]) + 1
            else:
                assessment["low_findings"] = int(assessment["low_findings"]) + 1

        # Calculate security score (0-10 scale)
        critical_findings: int = int(assessment["critical_findings"])
        high_findings: int = int(assessment["high_findings"])
        medium_findings: int = int(assessment["medium_findings"])
        low_findings: int = int(assessment["low_findings"])

        score = (
            critical_findings * 3.0
            + high_findings * 2.0
            + medium_findings * 1.0
            + low_findings * 0.5
        )
        assessment["security_score"] = min(score, 10.0)

        # Determine overall risk level
        security_score: float = float(assessment["security_score"])
        if critical_findings > 0 or security_score >= 7.0:
            assessment["overall_risk_level"] = "critical"
        elif high_findings > 0 or security_score >= 5.0:
            assessment["overall_risk_level"] = "high"
        elif medium_findings > 0 or security_score >= 3.0:
            assessment["overall_risk_level"] = "medium"

        return assessment

    def _format_extraction_summary(self, extractions: Any | None) -> dict[str, Any]:
        """Format extraction summary for LLM consumption.

        Converts Binwalk extraction results into a summarized format for LLM
        analysis. Includes success status, file counts, extraction timing,
        output directory, and any errors encountered during extraction.

        Args:
            extractions: Extraction results object containing extraction status,
                file counts, timestamps, and error information, or None if no
                extractions were performed during firmware analysis.

        Returns:
            dict[str, Any]: Summary dictionary containing extraction_successful
                flag, total_files count, executable_files count, text_files
                count, extraction_time, extraction_directory path, and
                extraction_errors list. Returns minimal dict with success=False
                if extractions object is None or extraction failed.
        """
        if not extractions or not extractions.success:
            return {
                "extraction_successful": False,
                "total_files": 0,
                "executable_files": 0,
                "text_files": 0,
                "extraction_errors": [],
            }

        return {
            "extraction_successful": extractions.success,
            "total_files": extractions.total_extracted,
            "executable_files": len(extractions.executable_files),
            "text_files": len(extractions.text_files),
            "extraction_time": extractions.extraction_time,
            "extraction_directory": extractions.extraction_directory,
            "extraction_errors": extractions.errors,
        }

    def _generate_bypass_recommendations(self, analysis_result: Any) -> list[dict[str, Any]]:
        """Generate bypass recommendations based on firmware analysis.

        Analyzes firmware signatures and security findings to generate targeted
        bypass recommendations. Identifies exploitation vectors including
        embedded executables, hardcoded credentials, private keys, and
        firmware-type-specific vulnerabilities for penetration testing
        and licensing protection bypass analysis.

        Args:
            analysis_result: Firmware analysis result object containing
                signatures, security_findings, firmware_type, has_extractions,
                embedded_executables, and extracted data for comprehensive
                bypass opportunity identification.

        Returns:
            list[dict[str, Any]]: List of recommendation dictionaries, each
                containing target (vulnerability type), method (approach),
                tools (recommended tools), difficulty (low/medium/high),
                description (recommendation summary), and technical_details
                (implementation-specific information).
        """
        recommendations: list[dict[str, Any]] = []

        # Check for embedded executables
        if analysis_result.has_extractions and analysis_result.embedded_executables:
            recommendations.append(
                {
                    "target": "Embedded Executables",
                    "method": "Binary Analysis",
                    "tools": ["Ghidra", "IDA Pro", "Radare2"],
                    "difficulty": "medium",
                    "description": f"Analyze {len(analysis_result.embedded_executables)} embedded executables for vulnerabilities",
                    "technical_details": "Extract and reverse engineer embedded binaries",
                }
            )

        # Check for security findings
        for finding in analysis_result.security_findings:
            if finding.is_critical:
                if finding.finding_type.value == "HARDCODED_CREDENTIALS":
                    recommendations.append(
                        {
                            "target": "Hardcoded Credentials",
                            "method": "Credential Extraction",
                            "tools": ["String analysis", "Binary editor"],
                            "difficulty": "low",
                            "description": "Extract and utilize hardcoded credentials",
                            "technical_details": f"Found at: {finding.file_path}",
                        }
                    )
                elif finding.finding_type.value == "PRIVATE_KEY":
                    recommendations.append(
                        {
                            "target": "Private Key",
                            "method": "Cryptographic Attack",
                            "tools": ["OpenSSL", "Key analysis tools"],
                            "difficulty": "medium",
                            "description": "Extract and utilize embedded private keys",
                            "technical_details": f"Key type: {finding.evidence}",
                        }
                    )

        # Check for firmware type specific recommendations
        firmware_type = analysis_result.firmware_type.value
        if firmware_type == "router":
            recommendations.append(
                {
                    "target": "Router Firmware",
                    "method": "Firmware Exploitation",
                    "tools": ["Firmware analysis toolkit", "UART access"],
                    "difficulty": "high",
                    "description": "Exploit router-specific vulnerabilities and backdoors",
                    "technical_details": "Check for default credentials and known CVEs",
                }
            )
        elif firmware_type == "iot_device":
            recommendations.append(
                {
                    "target": "IoT Device Firmware",
                    "method": "IoT Exploitation",
                    "tools": ["IoT security tools", "Hardware debugging"],
                    "difficulty": "medium",
                    "description": "Exploit IoT-specific attack vectors",
                    "technical_details": "Focus on weak authentication and update mechanisms",
                }
            )

        return recommendations

    def _format_extracted_files(self, extracted_files: list[Any]) -> list[dict[str, Any]]:
        """Format extracted files information.

        Converts Binwalk extracted file objects into structured dictionaries
        for LLM analysis. Limits output to first 20 files for performance.
        Includes file metadata, hash, executable status, and security analysis
        results for each extracted file.

        Args:
            extracted_files: List of extracted file objects containing file_path,
                original_offset, file_type, size, hash, is_executable,
                permissions, security_analysis, and extracted_strings
                attributes.

        Returns:
            list[dict[str, Any]]: List of formatted file dictionaries (max 20)
                containing file_path, original_offset, file_type, size, hash,
                is_executable, permissions, security_analysis, and optional
                interesting_strings (first 5 strings per file) keys.
        """
        formatted_files: list[dict[str, Any]] = []

        for file_obj in extracted_files[:20]:  # Limit to first 20 files
            file_data: dict[str, Any] = {
                "file_path": file_obj.file_path,
                "original_offset": file_obj.original_offset,
                "file_type": file_obj.file_type,
                "size": file_obj.size,
                "hash": file_obj.hash,
                "is_executable": file_obj.is_executable,
                "permissions": file_obj.permissions,
                "security_analysis": file_obj.security_analysis,
            }

            # Add interesting strings if available
            if file_obj.extracted_strings:
                file_data["interesting_strings"] = file_obj.extracted_strings[:5]  # Top 5 strings

            formatted_files.append(file_data)

        return formatted_files

    def _extract_interesting_strings(self, extracted_files: list[Any]) -> list[dict[str, Any]]:
        """Extract interesting strings from extracted files.

        Filters strings from extracted files for security-relevant keywords
        including passwords, credentials, keys, API endpoints, and URLs.
        Categorizes each string by type and limits output to 50 most
        interesting items for LLM consumption.

        Args:
            extracted_files: List of extracted file objects containing
                extracted_strings attributes. Each file object must have
                file_path and extracted_strings (list of strings) attributes
                for filtering and categorization.

        Returns:
            list[dict[str, Any]]: List of interesting string dictionaries
                (max 50) containing string (truncated to 100 chars), file
                (basename of source file), and category
                (credentials/cryptographic/network/api/other) keys.
        """
        interesting_strings: list[dict[str, Any]] = []

        for file_obj in extracted_files:
            if file_obj.extracted_strings:
                interesting_strings.extend(
                    {
                        "string": string[:100],  # Limit length
                        "file": os.path.basename(file_obj.file_path),
                        "category": self._categorize_string(string),
                    }
                    for string in file_obj.extracted_strings
                    if any(
                        keyword in string.lower()
                        for keyword in [
                            "password",
                            "admin",
                            "root",
                            "key",
                            "secret",
                            "token",
                            "api",
                            "url",
                            "http",
                        ]
                    )
                )
        return interesting_strings[:50]  # Limit to 50 most interesting

    def _categorize_string(self, string: str) -> str:
        """Categorize a string based on content.

        Analyzes string content to classify it into security-relevant categories
        for easier identification of sensitive information during firmware
        analysis. Uses keyword matching for credentials, cryptographic material,
        network endpoints, and API references.

        Args:
            string: String to categorize. Analyzed for keywords indicating
                credentials, cryptographic keys, network endpoints, or API
                references.

        Returns:
            str: Category classification - 'credentials' for password/admin/root
                keywords, 'cryptographic' for key/secret/token/cert keywords,
                'network' for http/url/ftp/ssh keywords, 'api' for
                api/endpoint/service keywords, or 'other' for unclassified
                strings.
        """
        string_lower = string.lower()

        if any(cred in string_lower for cred in ["password", "passwd", "admin", "root"]):
            return "credentials"
        elif any(crypto in string_lower for crypto in ["key", "secret", "token", "cert"]):
            return "cryptographic"
        elif any(net in string_lower for net in ["http", "url", "ftp", "ssh"]):
            return "network"
        elif any(api in string_lower for api in ["api", "endpoint", "service"]):
            return "api"
        else:
            return "other"

    def _format_security_findings(self, findings: list[Any]) -> list[dict[str, Any]]:
        """Format security findings for detailed analysis.

        Converts firmware security finding objects into structured dictionaries
        for LLM-based security analysis. Includes finding type, description,
        location information, severity assessment, confidence level, and
        remediation guidance.

        Args:
            findings: List of security finding objects to format. Each finding
                must have finding_type, description, file_path, offset,
                severity, confidence, evidence, remediation, and is_critical
                attributes for comprehensive security analysis.

        Returns:
            list[dict[str, Any]]: List of formatted finding dictionaries
                containing type, description, file_path, offset, severity,
                confidence, evidence, remediation, and is_critical keys for
                detailed security assessment and remediation planning.
        """
        formatted_findings: list[dict[str, Any]] = []

        for finding in findings:
            finding_data: dict[str, Any] = {
                "type": finding.finding_type.value,
                "description": finding.description,
                "file_path": finding.file_path,
                "offset": finding.offset,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
                "is_critical": finding.is_critical,
            }
            formatted_findings.append(finding_data)

        return formatted_findings

    def _analyze_embedded_components(self, signatures: list[Any]) -> dict[str, Any]:
        """Analyze embedded components detected in firmware.

        Categorizes firmware signatures by component type including filesystems,
        executables, archives, certificates, and miscellaneous components.
        Provides structured component analysis for LLM-based firmware
        assessment and attack surface identification.

        Args:
            signatures: List of firmware signature objects to analyze. Each
                signature must have file_type, signature_name, offset, size,
                is_filesystem, and is_executable attributes for proper
                categorization.

        Returns:
            dict[str, Any]: Dictionary with five component category keys
                (filesystems, executables, archives, certificates, other),
                each containing a list of dictionaries with type, name, offset,
                and size for components matching that category.
        """
        components: dict[str, Any] = {
            "filesystems": [],
            "executables": [],
            "archives": [],
            "certificates": [],
            "other": [],
        }

        for sig in signatures:
            if sig.is_filesystem:
                components["filesystems"].append(
                    {
                        "type": sig.file_type,
                        "name": sig.signature_name,
                        "offset": sig.offset,
                        "size": sig.size,
                    }
                )
            elif sig.is_executable:
                components["executables"].append(
                    {
                        "type": sig.file_type,
                        "name": sig.signature_name,
                        "offset": sig.offset,
                        "size": sig.size,
                    }
                )
            elif "archive" in sig.file_type.lower():
                components["archives"].append(
                    {
                        "type": sig.file_type,
                        "name": sig.signature_name,
                        "offset": sig.offset,
                        "size": sig.size,
                    }
                )
            elif "certificate" in sig.file_type.lower():
                components["certificates"].append(
                    {
                        "type": sig.file_type,
                        "name": sig.signature_name,
                        "offset": sig.offset,
                        "size": sig.size,
                    }
                )
            else:
                components["other"].append(
                    {
                        "type": sig.file_type,
                        "name": sig.signature_name,
                        "offset": sig.offset,
                        "size": sig.size,
                    }
                )

        return components

    def _classify_firmware(self, analysis_result: Any) -> dict[str, Any]:
        """Classify firmware based on analysis results.

        Performs detailed firmware classification by analyzing signatures to
        determine complexity, architecture, security features, and component
        presence. Supports ARM, MIPS, and x86 architecture detection.
        Identifies bootloaders, filesystems, and encryption mechanisms.

        Args:
            analysis_result: Firmware analysis result object containing
                firmware_type and signatures attributes. Signatures are analyzed
                for architecture hints, bootloader presence, filesystem
                components, and encryption indicators.

        Returns:
            dict[str, Any]: Classification dictionary containing primary_type,
                complexity (simple/moderate/advanced), architecture
                (ARM/MIPS/x86/unknown), bootloader_present flag,
                filesystem_present flag, encryption_present flag, confidence
                score, optional encryption_details list, and security_features
                list of identified security mechanisms.
        """
        classification: dict[str, Any] = {
            "primary_type": analysis_result.firmware_type.value,
            "complexity": "simple",
            "architecture": "unknown",
            "bootloader_present": False,
            "filesystem_present": False,
            "encryption_present": False,
            "confidence": 0.8,
        }

        # Analyze signatures for classification
        has_bootloader = False
        has_filesystem = False
        has_encryption = False

        for sig in analysis_result.signatures:
            if "bootloader" in sig.description.lower():
                has_bootloader = True
                classification["bootloader_present"] = True
            elif sig.is_filesystem:
                has_filesystem = True
                classification["filesystem_present"] = True
            elif "encrypt" in sig.description.lower():
                has_encryption = True
                classification["encryption_present"] = True

        # Analyze encryption details if found
        if has_encryption:
            encryption_details: list[dict[str, Any]] = [
                {
                    "type": sig.description,
                    "offset": (
                        hex(sig.offset) if hasattr(sig, "offset") else "unknown"
                    ),
                    "confidence": getattr(sig, "confidence", "unknown"),
                }
                for sig in analysis_result.signatures
                if "encrypt" in sig.description.lower()
            ]
            classification["encryption_details"] = encryption_details
            classification["security_features"] = classification.get("security_features", []) + ["encryption"]

        # Determine complexity
        component_count = len(analysis_result.signatures)
        if component_count > 10 and has_bootloader and has_filesystem:
            classification["complexity"] = "advanced"
        elif component_count > 5:
            classification["complexity"] = "moderate"

        # Try to determine architecture from signatures
        for sig in analysis_result.signatures:
            if "arm" in sig.description.lower():
                classification["architecture"] = "ARM"
                break
            elif "mips" in sig.description.lower():
                classification["architecture"] = "MIPS"
                break
            elif "x86" in sig.description.lower():
                classification["architecture"] = "x86"
                break

        return classification

    def _analyze_attack_surface(self, analysis_result: Any) -> dict[str, Any]:
        """Analyze potential attack surface of firmware.

        Examines extracted firmware files for evidence of exposed network
        interfaces, web services, debug mechanisms, and exposed services.
        Calculates overall attack surface risk assessment based on interface
        count for threat modeling and exploitation planning.

        Args:
            analysis_result: Firmware analysis result object containing
                has_extractions flag and extractions object with extracted_files
                list. Each file object must have extracted_strings attribute
                for network/debug/API indicator detection.

        Returns:
            dict[str, Any]: Attack surface dictionary containing
                network_interfaces count, web_interfaces count,
                debug_interfaces count, exposed_services list (Remote access,
                Web interface, etc.), potential_vulnerabilities list (Debug
                interface, etc.), and risk_assessment (low/medium/high) based
                on total interface count.
        """
        attack_surface: dict[str, Any] = {
            "network_interfaces": 0,
            "web_interfaces": 0,
            "debug_interfaces": 0,
            "exposed_services": [],
            "potential_vulnerabilities": [],
            "risk_assessment": "low",
        }

        # Analyze extracted files for attack surface indicators
        if analysis_result.has_extractions and analysis_result.extractions:
            for file_obj in analysis_result.extractions.extracted_files:
                if file_obj.extracted_strings:
                    for string in file_obj.extracted_strings:
                        string_lower = string.lower()

                        if "telnet" in string_lower or "ssh" in string_lower:
                            attack_surface["network_interfaces"] = int(attack_surface["network_interfaces"]) + 1
                            attack_surface["exposed_services"].append("Remote access")
                        elif "http" in string_lower or "web" in string_lower:
                            attack_surface["web_interfaces"] = int(attack_surface["web_interfaces"]) + 1
                            attack_surface["exposed_services"].append("Web interface")
                        elif "debug" in string_lower or "uart" in string_lower:
                            attack_surface["debug_interfaces"] = int(attack_surface["debug_interfaces"]) + 1
                            attack_surface["potential_vulnerabilities"].append("Debug interface")

        # Assess overall risk
        network_interfaces: int = int(attack_surface["network_interfaces"])
        web_interfaces: int = int(attack_surface["web_interfaces"])
        debug_interfaces: int = int(attack_surface["debug_interfaces"])
        total_interfaces = network_interfaces + web_interfaces + debug_interfaces

        if total_interfaces > 5:
            attack_surface["risk_assessment"] = "high"
        elif total_interfaces > 2:
            attack_surface["risk_assessment"] = "medium"

        return attack_surface


def create_firmware_analysis_tool() -> FirmwareAnalysisTool:
    """Factory function to create firmware analysis tool.

    Instantiates and returns a configured FirmwareAnalysisTool instance
    ready for firmware analysis operations via LLM integration.

    Returns:
        FirmwareAnalysisTool: Initialized firmware analysis tool instance
            with Binwalk analyzer and empty analysis cache.
    """
    return FirmwareAnalysisTool()
