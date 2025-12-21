"""Protection Analysis Tool for LLM Integration

Provides AI models with the ability to run comprehensive protection analysis
and interpret detection results from multiple engines.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
from typing import Any

from ...ai.interactive_assistant import IntellicrackAIAssistant
from ...protection.intellicrack_protection_advanced import (
    AdvancedProtectionAnalysis,
    CertificateInfo,
    EntropyInfo,
    IntellicrackAdvancedProtection,
    ScanMode,
    StringInfo,
)
from ...protection.intellicrack_protection_core import DetectionResult, ProtectionType
from ...utils.logger import get_logger

logger = get_logger(__name__)


class DIEAnalysisTool:
    """LLM tool for running protection analysis and interpreting results"""

    def __init__(self) -> None:
        """Initialize protection analysis tool"""
        self.detector: IntellicrackAdvancedProtection = IntellicrackAdvancedProtection()
        self.analysis_cache: dict[str, dict[str, Any]] = {}
        self.ai_assistant: IntellicrackAIAssistant = IntellicrackAIAssistant()

    def get_tool_definition(self) -> dict[str, Any]:
        """Get tool definition for LLM registration

        Returns:
            Tool definition dictionary

        """
        return {
            "name": "die_analysis",
            "description": "Run Intellicrack Protection Engine analysis on binary files to detect protections, packers, and licensing schemes",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the binary file to analyze",
                    },
                    "scan_mode": {
                        "type": "string",
                        "enum": ["normal", "deep", "heuristic", "all"],
                        "description": "Scan mode: normal (fast), deep (thorough), heuristic (AI-based), all (comprehensive)",
                        "default": "deep",
                    },
                    "extract_strings": {
                        "type": "boolean",
                        "description": "Extract and analyze suspicious strings",
                        "default": True,
                    },
                    "analyze_entropy": {
                        "type": "boolean",
                        "description": "Perform entropy analysis to detect packing/encryption",
                        "default": True,
                    },
                    "check_certificates": {
                        "type": "boolean",
                        "description": "Extract and verify digital certificates",
                        "default": True,
                    },
                    "export_format": {
                        "type": "string",
                        "enum": ["json", "text", "yara"],
                        "description": "Output format for results",
                        "default": "json",
                    },
                },
                "required": ["file_path"],
            },
        }

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        """Execute DIE analysis

        Args:
            **kwargs: Tool parameters

        Returns:
            Analysis results dictionary

        """
        file_path = kwargs.get("file_path")
        if not file_path or not isinstance(file_path, str) or not os.path.exists(file_path):
            return {"success": False, "error": f"File not found: {file_path}"}

        # Get parameters
        scan_mode_str_raw = kwargs.get("scan_mode", "deep")
        scan_mode_str = scan_mode_str_raw if isinstance(scan_mode_str_raw, str) else "deep"
        scan_mode = ScanMode[scan_mode_str.upper()]
        extract_strings_raw = kwargs.get("extract_strings", True)
        extract_strings = extract_strings_raw if isinstance(extract_strings_raw, bool) else True
        analyze_entropy_raw = kwargs.get("analyze_entropy", True)
        analyze_entropy = analyze_entropy_raw if isinstance(analyze_entropy_raw, bool) else True
        check_certificates_raw = kwargs.get("check_certificates", True)
        check_certificates = check_certificates_raw if isinstance(check_certificates_raw, bool) else True
        export_format_raw = kwargs.get("export_format", "json")
        export_format = export_format_raw if isinstance(export_format_raw, str) else "json"

        try:
            # Check cache
            cache_key = f"{file_path}:{scan_mode_str}"
            if cache_key in self.analysis_cache:
                logger.debug(f"Returning cached analysis for {file_path}")
                cached_result = self.analysis_cache[cache_key].copy()
                cached_result["from_cache"] = True
                return cached_result

            # Run advanced analysis
            analysis = self.detector.detect_protections_advanced(
                file_path=file_path,
                scan_mode=scan_mode,
                enable_heuristic=scan_mode in [ScanMode.HEURISTIC, ScanMode.ALL],
                extract_strings=extract_strings,
            )

            # Build result
            result = {
                "success": True,
                "file_path": file_path,
                "file_type": analysis.file_type,
                "architecture": analysis.architecture,
                "is_packed": analysis.is_packed,
                "is_protected": analysis.is_protected,
                "protections": self._format_protections(analysis),
                "bypass_recommendations": self._generate_bypass_recommendations(analysis),
                "from_cache": False,
            }

            # Add entropy analysis if requested
            if analyze_entropy and analysis.entropy_info:
                result["entropy_analysis"] = self._format_entropy_analysis(analysis.entropy_info)

            # Add certificate info if requested
            if check_certificates and analysis.certificates:
                result["certificates"] = self._format_certificates(analysis.certificates)

            # Add suspicious strings if found
            if extract_strings and analysis.suspicious_strings:
                result["suspicious_strings"] = self._format_strings(analysis.suspicious_strings)

            # Add import hash for similarity analysis
            if analysis.import_hash:
                result["import_hash"] = {
                    "imphash": analysis.import_hash.imphash,
                    "imphash_sorted": analysis.import_hash.imphash_sorted,
                }

            # Add heuristic detections
            if analysis.heuristic_detections:
                result["heuristic_detections"] = [
                    {"name": det.name, "type": det.type.value, "confidence": det.confidence} for det in analysis.heuristic_detections
                ]

            # Check if license pattern analysis is needed
            has_license_protection = False
            if analysis.detections:
                for detection in analysis.detections:
                    if detection.type in [
                        ProtectionType.LICENSE,
                        ProtectionType.DONGLE,
                        ProtectionType.DRM,
                    ]:
                        has_license_protection = True
                        break

            # Run license pattern analysis if relevant
            if has_license_protection or self._should_analyze_license_patterns(analysis):
                license_patterns = self._analyze_license_patterns_for_llm(file_path, analysis)
                if license_patterns and not license_patterns.get("error"):
                    result["license_pattern_analysis"] = license_patterns

            # Run AI-enhanced complex binary analysis
            try:
                # Prepare ML results from protection analysis
                ml_results = {"confidence": result.get("confidence", 0.0), "predictions": []}

                # Convert protection detections to ML predictions format
                if result.get("protections"):
                    for protection in result["protections"]:
                        ml_results["predictions"].append(
                            {
                                "name": protection.get("name", "Unknown"),
                                "type": protection.get("type", "unknown"),
                                "confidence": protection.get("confidence", 0.0),
                                "category": protection.get("category", "unknown"),
                            }
                        )

                # Run AI complex analysis
                ai_analysis = self.ai_assistant.analyze_binary_complex(file_path, ml_results)

                # Add AI analysis to results
                if ai_analysis and not ai_analysis.get("error"):
                    result["ai_complex_analysis"] = {
                        "confidence": ai_analysis.get("confidence", 0.0),
                        "findings": ai_analysis.get("findings", []),
                        "recommendations": ai_analysis.get("recommendations", []),
                        "ml_integration": ai_analysis.get("ml_integration", {}),
                    }

                    # Merge AI recommendations with existing bypass recommendations
                    if ai_analysis.get("recommendations") and result.get("bypass_recommendations"):
                        for rec in ai_analysis["recommendations"]:
                            # Add AI recommendations as a special category
                            if "AI-Enhanced Analysis" not in result["bypass_recommendations"]:
                                result["bypass_recommendations"]["AI-Enhanced Analysis"] = []
                            result["bypass_recommendations"]["AI-Enhanced Analysis"].append(rec)

            except Exception as e:
                logger.warning(f"AI complex analysis failed: {e}")
                result["ai_complex_analysis"] = {"error": str(e), "confidence": 0.0}

            # Handle export formats
            if export_format == "yara":
                result["yara_rules"] = self.detector.export_to_yara(analysis)
            elif export_format == "text":
                result["text_report"] = self._generate_text_report(analysis)

            # Cache result
            self.analysis_cache[cache_key] = result

            return result

        except Exception as e:
            logger.error(f"DIE analysis error: {e}")
            return {"success": False, "error": str(e)}

    def _format_protections(self, analysis: AdvancedProtectionAnalysis) -> list[dict[str, Any]]:
        """Format protection detections for LLM consumption"""
        protections: list[dict[str, Any]] = []

        for detection in analysis.detections:
            protection: dict[str, Any] = {
                "name": detection.name,
                "type": detection.type.value,
                "confidence": detection.confidence,
                "category": self._categorize_protection(detection.type),
            }

            if detection.version:
                protection["version"] = detection.version

            if detection.details:
                protection["details"] = detection.details

            protections.append(protection)

        return protections

    def _categorize_protection(self, protection_type: ProtectionType) -> str:
        """Categorize protection type for AI understanding"""
        categories: dict[ProtectionType, str] = {
            ProtectionType.PACKER: "compression",
            ProtectionType.PROTECTOR: "anti-tampering",
            ProtectionType.CRYPTOR: "encryption",
            ProtectionType.LICENSE: "licensing",
            ProtectionType.DRM: "digital_rights",
            ProtectionType.DONGLE: "hardware_protection",
            ProtectionType.UNKNOWN: "unknown",
        }
        return categories.get(protection_type, "unknown")

    def _generate_bypass_recommendations(self, analysis: AdvancedProtectionAnalysis) -> dict[str, list[str]]:
        """Generate bypass recommendations based on detections"""
        return {
            detection.name: (
                detection.bypass_recommendations or self._get_generic_bypass_methods(detection.type)
            )
            for detection in analysis.detections
        }

    def _get_generic_bypass_methods(self, protection_type: ProtectionType) -> list[str]:
        """Get generic bypass methods by protection type"""
        methods: dict[ProtectionType, list[str]] = {
            ProtectionType.PACKER: [
                "Use unpacking tools (UPX, PEiD)",
                "Dump process memory after unpacking",
                "Set breakpoint at OEP (Original Entry Point)",
                "Use Scylla for import reconstruction",
            ],
            ProtectionType.PROTECTOR: [
                "Identify and bypass anti-debug checks",
                "Use kernel-mode debugger",
                "Patch integrity checks",
                "Use hardware breakpoints",
            ],
            ProtectionType.LICENSE: [
                "Locate license validation routines",
                "Patch conditional jumps",
                "Generate valid license keys",
                "Emulate license server responses",
            ],
            ProtectionType.DRM: [
                "Identify DRM initialization",
                "Hook DRM API calls",
                "Bypass online verification",
                "Extract decryption keys",
            ],
            ProtectionType.DONGLE: [
                "Emulate dongle responses",
                "Identify dongle communication protocol",
                "Create virtual dongle driver",
                "Patch dongle check routines",
            ],
        }
        return methods.get(protection_type, ["Manual analysis required"])

    def _format_entropy_analysis(self, entropy_info: list[EntropyInfo]) -> dict[str, Any]:
        """Format entropy analysis for AI interpretation"""
        sections_list: list[dict[str, Any]] = []
        packed_sections: list[str] = []
        encrypted_sections: list[str] = []

        analysis: dict[str, Any] = {
            "sections": sections_list,
            "packed_sections": packed_sections,
            "encrypted_sections": encrypted_sections,
            "average_entropy": 0.0,
            "max_entropy": 0.0,
            "packing_likelihood": "low",
        }

        total_entropy = 0.0
        max_entropy_value = 0.0

        for info in entropy_info:
            section_data: dict[str, Any] = {
                "name": info.section_name,
                "offset": hex(info.offset),
                "size": info.size,
                "entropy": round(info.entropy, 3),
                "status": "normal",
            }

            if info.encrypted:
                section_data["status"] = "encrypted"
                encrypted_sections.append(info.section_name)
            elif info.packed:
                section_data["status"] = "packed"
                packed_sections.append(info.section_name)

            sections_list.append(section_data)
            total_entropy += info.entropy
            max_entropy_value = max(max_entropy_value, info.entropy)

        analysis["max_entropy"] = max_entropy_value

        if entropy_info:
            analysis["average_entropy"] = round(total_entropy / len(entropy_info), 3)

            # Determine packing likelihood
            if max_entropy_value > 7.5:
                analysis["packing_likelihood"] = "very_high"
            elif max_entropy_value > 7.0:
                analysis["packing_likelihood"] = "high"
            elif max_entropy_value > 6.5:
                analysis["packing_likelihood"] = "medium"
            else:
                analysis["packing_likelihood"] = "low"

        return analysis

    def _format_certificates(self, certificates: list[CertificateInfo]) -> list[dict[str, Any]]:
        """Format certificate information"""
        cert_list = []

        for cert in certificates:
            cert_data = {
                "subject": cert.subject,
                "issuer": cert.issuer,
                "valid": cert.is_valid,
                "trusted": cert.is_trusted,
                "algorithm": cert.algorithm,
            }

            if cert.valid_from:
                cert_data["valid_from"] = cert.valid_from
            if cert.valid_to:
                cert_data["valid_to"] = cert.valid_to

            cert_list.append(cert_data)

        return cert_list

    def _format_strings(self, strings: list[StringInfo]) -> list[dict[str, Any]]:
        """Format suspicious strings"""
        return [
            {
                "value": s.value[:100],  # Limit length
                "offset": hex(s.offset) if s.offset else "unknown",
                "encoding": s.encoding,
                "category": self._categorize_string(s.value),
            }
            for s in strings[:50]  # Limit to top 50
        ]

    def _categorize_string(self, string: str) -> str:
        """Categorize suspicious string"""
        string_lower = string.lower()

        if any(api in string_lower for api in ["kernel32", "ntdll", "virtualprotect"]):
            return "api_call"
        elif any(debug in string_lower for debug in ["debugger", "ollydbg", "ida"]):
            return "anti_debug"
        elif any(lic in string_lower for lic in ["license", "serial", "registration"]):
            return "licensing"
        elif any(net in string_lower for net in ["http://", "https://", "ftp://"]):
            return "network"
        elif any(cmd in string_lower for cmd in ["cmd.exe", "powershell", "reg.exe"]):
            return "system_command"
        else:
            return "other"

    def _generate_text_report(self, analysis: AdvancedProtectionAnalysis) -> str:
        """Generate human-readable text report"""
        lines = []

        lines.append("DIE Analysis Report")
        lines.append("=" * 50)
        lines.append(f"File: {analysis.file_path}")
        lines.append(f"Type: {analysis.file_type}")
        lines.append(f"Architecture: {analysis.architecture}")
        lines.append("")

        if analysis.is_packed or analysis.is_protected:
            lines.append("Status:")
            if analysis.is_packed:
                lines.append("  - File is PACKED")
            if analysis.is_protected:
                lines.append("  - File is PROTECTED")
            lines.append("")

        if analysis.detections:
            lines.append(f"Protections Detected ({len(analysis.detections)}):")
            for det in analysis.detections:
                lines.append(f"  - {det.name} [{det.type.value}]")
                if det.version:
                    lines.append(f"    Version: {det.version}")
                if det.confidence < 100:
                    lines.append(f"    Confidence: {det.confidence}%")
            lines.append("")

        if analysis.entropy_info:
            lines.append("Entropy Analysis:")
            for info in analysis.entropy_info:
                status = "PACKED" if info.packed else "ENCRYPTED" if info.encrypted else "Normal"
                lines.append(f"  - {info.section_name}: {info.entropy:.2f} ({status})")
            lines.append("")

        if analysis.certificates:
            lines.append("Digital Certificates:")
            for cert in analysis.certificates:
                lines.append(f"  - {cert.subject}")
                lines.append(f"    Issuer: {cert.issuer}")
                lines.append(f"    Valid: {'Yes' if cert.is_valid else 'No'}")
            lines.append("")

        return "\n".join(lines)

    def analyze_batch(self, file_paths: list[str], scan_mode: str = "normal") -> dict[str, Any]:
        """Analyze multiple files in batch

        Args:
            file_paths: List of file paths
            scan_mode: Scan mode to use

        Returns:
            Batch analysis results

        """
        analyzed_count = 0
        error_count = 0
        protections_found = 0
        files_dict: dict[str, Any] = {}

        results: dict[str, Any] = {
            "success": True,
            "total_files": len(file_paths),
            "analyzed": analyzed_count,
            "errors": error_count,
            "protections_found": protections_found,
            "files": files_dict,
        }

        mode = ScanMode[scan_mode.upper()]

        # Use batch analysis from detector
        batch_results = self.detector.batch_analyze(file_paths, max_workers=4, scan_mode=mode)

        for file_path, analysis in batch_results.items():
            if analysis.file_type != "Error":
                analyzed_count += 1
                if analysis.detections:
                    protections_found += 1

                files_dict[file_path] = {
                    "type": analysis.file_type,
                    "protected": bool(analysis.detections),
                    "protections": [d.name for d in analysis.detections],
                }
            else:
                error_count += 1
                files_dict[file_path] = {"error": "Analysis failed"}

        results["analyzed"] = analyzed_count
        results["errors"] = error_count
        results["protections_found"] = protections_found

        return results

    def compare_files(self, file1: str, file2: str) -> dict[str, Any]:
        """Compare two files for protection similarities

        Args:
            file1: First file path
            file2: Second file path

        Returns:
            Comparison results

        """
        # Analyze both files
        analysis1 = self.detector.detect_protections_advanced(file1)
        analysis2 = self.detector.detect_protections_advanced(file2)

        # Compare results
        comparison = {
            "file1": os.path.basename(file1),
            "file2": os.path.basename(file2),
            "same_protections": [],
            "unique_to_file1": [],
            "unique_to_file2": [],
            "similarity_score": 0.0,
        }

        # Get protection names
        protections1 = {d.name for d in analysis1.detections}
        protections2 = {d.name for d in analysis2.detections}

        # Find common and unique protections
        same_prots = list(protections1 & protections2)
        unique_to_file1 = list(protections1 - protections2)
        unique_to_file2 = list(protections2 - protections1)

        comparison["same_protections"] = same_prots
        comparison["unique_to_file1"] = unique_to_file1
        comparison["unique_to_file2"] = unique_to_file2

        # Calculate similarity score
        if protections1 or protections2:
            common_count = len(same_prots)
            total_unique = len(protections1 | protections2)
            comparison["similarity_score"] = round(common_count / total_unique * 100, 2) if total_unique > 0 else 0.0

        # Compare import hashes if available
        if analysis1.import_hash and analysis2.import_hash:
            comparison["import_hash_match"] = analysis1.import_hash.imphash == analysis2.import_hash.imphash

        return comparison

    def _should_analyze_license_patterns(self, analysis: AdvancedProtectionAnalysis) -> bool:
        """Determine if license pattern analysis would be beneficial"""
        # Check for license-related imports
        if hasattr(analysis, "imports") and analysis.imports:
            license_imports = [
                "license",
                "serial",
                "activation",
                "key",
                "hasp",
                "sentinel",
                "flexlm",
            ]
            for import_dll in analysis.imports:
                if any(keyword in import_dll.lower() for keyword in license_imports):
                    return True

        # Check if it's a commercial application
        if analysis.compiler:
            commercial_compilers = ["visual c++", "visual studio", "delphi", "borland"]
            if any(comp in analysis.compiler.lower() for comp in commercial_compilers):
                return True

        # Check for suspicious strings related to licensing
        if analysis.suspicious_strings:
            for string_info in analysis.suspicious_strings:
                if any(keyword in string_info.value.lower() for keyword in ["license", "serial", "key"]):
                    return True

        return False

    def _analyze_license_patterns_for_llm(self, file_path: str, analysis: AdvancedProtectionAnalysis) -> dict[str, Any]:
        """Analyze license patterns for LLM consumption"""
        try:
            # Prepare input data for AI license analysis
            patterns_list: list[dict[str, Any]] = []
            strings_list: list[str] = []
            input_data: dict[str, Any] = {"patterns": patterns_list, "strings": strings_list, "binary_path": file_path}

            # Extract relevant strings from analysis
            if analysis.suspicious_strings:
                license_keywords = [
                    "license",
                    "serial",
                    "key",
                    "activation",
                    "trial",
                    "expire",
                    "register",
                    "unlock",
                    "demo",
                    "evaluation",
                ]
                for string_info in analysis.suspicious_strings:
                    if any(keyword in string_info.value.lower() for keyword in license_keywords):
                        strings_list.append(string_info.value)
                        if len(strings_list) >= 50:
                            break

            # Add detection patterns
            if analysis.detections:
                patterns_list.extend(
                    {
                        "name": detection.name,
                        "type": detection.type.value,
                        "version": detection.version,
                        "confidence": detection.confidence,
                    }
                    for detection in analysis.detections
                    if detection.type
                    in [
                        ProtectionType.LICENSE,
                        ProtectionType.DONGLE,
                        ProtectionType.DRM,
                    ]
                )
            # Call AI assistant's license pattern analysis
            license_analysis = self.ai_assistant.analyze_license_patterns(input_data)

            # Enhance with additional context
            if license_analysis and not license_analysis.get("error"):
                # Add import context
                license_analysis["import_context"] = {
                    "has_network_apis": self._check_for_network_apis(analysis),
                    "has_crypto_apis": self._check_for_crypto_apis(analysis),
                    "has_registry_apis": self._check_for_registry_apis(analysis),
                }

                # Add protection-specific recommendations
                if license_analysis.get("license_type") != "unknown":
                    license_analysis["llm_guidance"] = self._get_license_llm_guidance(license_analysis["license_type"], analysis.detections)

            return license_analysis

        except Exception as e:
            logger.warning(f"License pattern analysis failed: {e}")
            return {"error": str(e)}

    def _check_for_network_apis(self, analysis: AdvancedProtectionAnalysis) -> bool:
        """Check if network APIs are imported"""
        if not hasattr(analysis, "imports") or not analysis.imports:
            return False
        network_dlls = ["ws2_32.dll", "winhttp.dll", "wininet.dll"]
        return any(dll in analysis.imports for dll in network_dlls)

    def _check_for_crypto_apis(self, analysis: AdvancedProtectionAnalysis) -> bool:
        """Check if crypto APIs are imported"""
        if not hasattr(analysis, "imports") or not analysis.imports:
            return False
        crypto_dlls = ["crypt32.dll", "advapi32.dll", "bcrypt.dll"]
        return any(dll in analysis.imports for dll in crypto_dlls)

    def _check_for_registry_apis(self, analysis: AdvancedProtectionAnalysis) -> bool:
        """Check if registry APIs are imported"""
        if not hasattr(analysis, "imports") or not analysis.imports:
            return False
        return "advapi32.dll" in analysis.imports

    def _get_license_llm_guidance(self, license_type: str, detections: list[DetectionResult]) -> str:
        """Get LLM-specific guidance for license analysis"""
        guidance = f"Detected {license_type} licensing. "

        if license_type == "trial_based":
            guidance += "Look for time/date checks, trial counters, and expiration logic. "
            guidance += "Check registry or local storage for trial state persistence."
        elif license_type == "serial_based":
            guidance += "Focus on serial validation routines, checksum algorithms, and key generation logic. "
            guidance += "Look for string comparisons and mathematical validation functions."
        elif license_type == "activation_based":
            guidance += "Analyze network communication for activation servers. "
            guidance += "Check for hardware fingerprinting and machine ID generation."

        # Add protection-specific guidance
        for detection in detections:
            if detection.type == ProtectionType.LICENSE:
                name_lower = detection.name.lower()
                if "flexlm" in name_lower:
                    guidance += " FlexLM detected: Check for lmgrd daemon communication and license.dat parsing."
                elif "hasp" in name_lower:
                    guidance += " HASP detected: Monitor hasp_login calls and feature ID checks."
                elif "codemeter" in name_lower:
                    guidance += " CodeMeter detected: Analyze CmContainer access and license queries."

        return guidance


def create_die_tool() -> DIEAnalysisTool:
    """Factory function to create DIE analysis tool"""
    return DIEAnalysisTool()
