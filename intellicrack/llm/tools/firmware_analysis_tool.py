"""Firmware Analysis Tool for LLM Integration

Provides AI models with the ability to run comprehensive firmware analysis
using Binwalk to detect embedded files, security issues, and firmware patterns.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
from typing import Any, Dict, List, Optional

from ...core.analysis.firmware_analyzer import get_firmware_analyzer, is_binwalk_available
from ...utils.logger import get_logger

logger = get_logger(__name__)


class FirmwareAnalysisTool:
    """LLM tool for running firmware analysis using Binwalk"""

    def __init__(self):
        """Initialize firmware analysis tool"""
        self.analyzer = get_firmware_analyzer()
        self.analysis_cache = {}

    def get_tool_definition(self) -> dict[str, Any]:
        """Get tool definition for LLM registration

        Returns:
            Tool definition dictionary

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

    def execute(self, **kwargs) -> dict[str, Any]:
        """Execute firmware analysis

        Args:
            **kwargs: Tool parameters

        Returns:
            Analysis results dictionary

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
                cached_result = self.analysis_cache[cache_key]
                cached_result["from_cache"] = True
                return cached_result

            # Run firmware analysis
            analysis_result = self.analyzer.analyze_firmware(
                file_path=file_path,
                extract_files=extract_files,
                analyze_security=analyze_security,
                extraction_depth=extraction_depth,
            )

            if analysis_result.error:
                return {"success": False, "error": analysis_result.error}

            # Build result for LLM consumption
            result = {
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
            if analysis_result.has_extractions:
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
        """Format firmware signatures for LLM consumption"""
        formatted_signatures = []

        for sig in signatures:
            sig_data = {
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
        """Assess security implications of firmware findings"""
        assessment = {
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
                assessment["critical_findings"] += 1
                assessment["immediate_threats"].append(finding.description)
            elif severity == "high":
                assessment["high_findings"] += 1
                assessment["primary_concerns"].append(finding.description)
            elif severity == "medium":
                assessment["medium_findings"] += 1
            else:
                assessment["low_findings"] += 1

        # Calculate security score (0-10 scale)
        score = (
            assessment["critical_findings"] * 3.0
            + assessment["high_findings"] * 2.0
            + assessment["medium_findings"] * 1.0
            + assessment["low_findings"] * 0.5
        )
        assessment["security_score"] = min(score, 10.0)

        # Determine overall risk level
        if assessment["critical_findings"] > 0 or assessment["security_score"] >= 7.0:
            assessment["overall_risk_level"] = "critical"
        elif assessment["high_findings"] > 0 or assessment["security_score"] >= 5.0:
            assessment["overall_risk_level"] = "high"
        elif assessment["medium_findings"] > 0 or assessment["security_score"] >= 3.0:
            assessment["overall_risk_level"] = "medium"

        return assessment

    def _format_extraction_summary(self, extractions: Any | None) -> dict[str, Any]:
        """Format extraction summary for LLM consumption"""
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
        """Generate bypass recommendations based on firmware analysis"""
        recommendations = []

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
        """Format extracted files information"""
        formatted_files = []

        for file_obj in extracted_files[:20]:  # Limit to first 20 files
            file_data = {
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
        """Extract interesting strings from extracted files"""
        interesting_strings = []

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
        """Categorize a string based on content"""
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
        """Format security findings for detailed analysis"""
        formatted_findings = []

        for finding in findings:
            finding_data = {
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
        """Analyze embedded components detected in firmware"""
        components = {
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
        """Classify firmware based on analysis results"""
        classification = {
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
            encryption_details = [
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
        """Analyze potential attack surface of firmware"""
        attack_surface = {
            "network_interfaces": 0,
            "web_interfaces": 0,
            "debug_interfaces": 0,
            "exposed_services": [],
            "potential_vulnerabilities": [],
            "risk_assessment": "low",
        }

        # Analyze extracted files for attack surface indicators
        if analysis_result.has_extractions:
            for file_obj in analysis_result.extractions.extracted_files:
                if file_obj.extracted_strings:
                    for string in file_obj.extracted_strings:
                        string_lower = string.lower()

                        if "telnet" in string_lower or "ssh" in string_lower:
                            attack_surface["network_interfaces"] += 1
                            attack_surface["exposed_services"].append("Remote access")
                        elif "http" in string_lower or "web" in string_lower:
                            attack_surface["web_interfaces"] += 1
                            attack_surface["exposed_services"].append("Web interface")
                        elif "debug" in string_lower or "uart" in string_lower:
                            attack_surface["debug_interfaces"] += 1
                            attack_surface["potential_vulnerabilities"].append("Debug interface")

        # Assess overall risk
        total_interfaces = attack_surface["network_interfaces"] + attack_surface["web_interfaces"] + attack_surface["debug_interfaces"]

        if total_interfaces > 5:
            attack_surface["risk_assessment"] = "high"
        elif total_interfaces > 2:
            attack_surface["risk_assessment"] = "medium"

        return attack_surface


def create_firmware_analysis_tool() -> FirmwareAnalysisTool:
    """Factory function to create firmware analysis tool"""
    return FirmwareAnalysisTool()
