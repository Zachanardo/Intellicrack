#!/usr/bin/env python3
"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

"""
Protection Analyzer Tool

A tool that can be called by users or LLMs to thoroughly analyze
software protection schemes and provide detailed findings using Intellicrack's protection detection engine.
"""

import os
from pathlib import Path
from typing import Any

from ..ai.interactive_assistant import IntellicrackAIAssistant
from ..ai.ai_file_tools import get_ai_file_tools
from ..protection.intellicrack_protection_core import (
    DetectionResult,
    ProtectionAnalysis,
    ProtectionType,
)
from ..protection.protection_detector import get_protection_detector
from ..utils.logger import get_logger

logger = get_logger(__name__)


class ProtectionAnalyzerTool:
    """Analyzes binaries for protection schemes and provides comprehensive findings.

    This tool can be:
    1. Called directly by users through the UI
    2. Used by LLMs as a tool to gather protection information
    """

    def __init__(self) -> None:
        """Initialize protection analyzer tool with detector, AI assistant, and file tools."""
        self.detector = get_protection_detector()
        self.ai_assistant = IntellicrackAIAssistant()
        self.ai_file_tools = get_ai_file_tools()

    def analyze(self, binary_path: str, detailed: bool = True) -> dict[str, Any]:
        """Perform comprehensive protection analysis on a binary.

        Args:
            binary_path: Path to the binary to analyze.
            detailed: Whether to include detailed technical information.

        Returns:
            dict[str, Any]: Comprehensive analysis results formatted for both human and LLM consumption.
        """
        if not os.path.exists(binary_path):
            return {"success": False, "error": f"File not found: {binary_path}"}

        try:
            result = self.detector.detect_protections(binary_path)

            analysis: dict[str, Any] = {
                "success": True,
                "file_info": self._get_file_info(binary_path),
                "protection_analysis": self._build_protection_analysis(result),
                "technical_details": self._get_technical_details(result) if detailed else None,
                "bypass_guidance": self._get_bypass_guidance(result),
                "tool_recommendations": self._get_tool_recommendations(result),
                "llm_context": self._build_llm_context(result),
            }

            try:
                ml_results: dict[str, Any] = {"confidence": 0.85, "predictions": []}

                if result and hasattr(result, "detections"):
                    predictions_list: list[dict[str, Any]] = ml_results["predictions"]
                    predictions_list.extend(
                        {
                            "name": detection.name,
                            "type": (
                                detection.type.value
                                if hasattr(detection.type, "value")
                                else str(detection.type)
                            ),
                            "confidence": detection.confidence,
                        }
                        for detection in result.detections
                    )
                ai_analysis = self.ai_assistant.analyze_binary_complex(binary_path, ml_results)

                if ai_analysis and not ai_analysis.get("error"):
                    analysis["ai_complex_analysis"] = ai_analysis

                    if ai_analysis.get("recommendations"):
                        bypass_guidance = analysis.get("bypass_guidance")
                        if bypass_guidance is None or not isinstance(bypass_guidance, dict):
                            analysis["bypass_guidance"] = {}
                            bypass_guidance = analysis["bypass_guidance"]
                        if "ai_enhanced" not in bypass_guidance:
                            bypass_guidance["ai_enhanced"] = []
                        ai_enhanced_list: list[Any] = bypass_guidance["ai_enhanced"]
                        ai_enhanced_list.extend(ai_analysis["recommendations"])

                has_license_protection = False
                if result and hasattr(result, "detections"):
                    for detection in result.detections:
                        if detection.type in [
                            ProtectionType.LICENSE,
                            ProtectionType.DONGLE,
                            ProtectionType.DRM,
                        ]:
                            has_license_protection = True
                            break

                if has_license_protection or (detailed and self._should_analyze_license_patterns(result)):
                    license_analysis = self._analyze_license_patterns(binary_path, result)
                    if license_analysis and not license_analysis.get("error"):
                        analysis["license_pattern_analysis"] = license_analysis

                        if license_analysis.get("bypass_suggestions"):
                            bypass_guidance = analysis.get("bypass_guidance")
                            if bypass_guidance is None or not isinstance(bypass_guidance, dict):
                                analysis["bypass_guidance"] = {}
                                bypass_guidance = analysis["bypass_guidance"]
                            if "license_patterns" not in bypass_guidance:
                                bypass_guidance["license_patterns"] = []
                            license_patterns_list: list[Any] = bypass_guidance["license_patterns"]
                            license_patterns_list.extend(license_analysis["bypass_suggestions"])

                    try:
                        binary_dir = os.path.dirname(os.path.abspath(binary_path))
                        license_file_results = self.ai_file_tools.search_for_license_files(binary_dir)

                        if license_file_results.get("status") == "success" and license_file_results.get("files_found"):
                            analysis["license_files_found"] = license_file_results

                            if license_files_to_read := [
                                file_info["path"]
                                for file_info in license_file_results[
                                    "files_found"
                                ][:3]
                            ]:
                                read_results = self.ai_file_tools.read_multiple_files(
                                    license_files_to_read,
                                    f"Analyze license files for {os.path.basename(binary_path)}",
                                )

                                if read_results.get("status") == "success":
                                    analysis["license_file_contents"] = read_results

                                    bypass_guidance = analysis.get("bypass_guidance")
                                    if bypass_guidance is None or not isinstance(bypass_guidance, dict):
                                        analysis["bypass_guidance"] = {}
                                        bypass_guidance = analysis["bypass_guidance"]
                                    bypass_guidance["license_files_note"] = (
                                        f"Found {len(license_file_results['files_found'])} potential license files. "
                                        "These may contain license keys, configuration, or validation data."
                                    )
                    except Exception as e:
                        logger.warning(f"License file search failed: {e}")

            except Exception as e:
                logger.warning(f"AI complex analysis failed: {e}")
                analysis["ai_complex_analysis"] = {"error": str(e)}

            return analysis

        except Exception as e:
            logger.error(f"Error analyzing {binary_path}: {e}")
            return {"success": False, "error": str(e)}

    def _get_file_info(self, binary_path: str) -> dict[str, Any]:
        """Get basic file information.

        Args:
            binary_path: Path to the binary file.

        Returns:
            dict[str, Any]: File information including path, name, size, extension, and directory.
        """
        path = Path(binary_path)
        return {
            "path": str(path.absolute()),
            "name": path.name,
            "size": path.stat().st_size,
            "size_human": self._format_size(path.stat().st_size),
            "extension": path.suffix,
            "directory": str(path.parent),
        }

    def _format_size(self, size: int) -> str:
        """Format size in human readable form.

        Args:
            size: Size in bytes.

        Returns:
            str: Human-readable size string (e.g., "1.50 MB").
        """
        size_float: float = float(size)
        for unit in ["B", "KB", "MB", "GB"]:
            if size_float < 1024.0:
                return f"{size_float:.2f} {unit}"
            size_float /= 1024.0
        return f"{size_float:.2f} TB"

    def _build_protection_analysis(self, die_result: ProtectionAnalysis) -> dict[str, Any]:
        """Build the main protection analysis section.

        Args:
            die_result: Protection analysis result from detector.

        Returns:
            dict[str, Any]: Comprehensive protection analysis organized by detection type.
        """
        detections_by_type: dict[str, list[dict[str, Any]]] = {}
        for detection in die_result.detections:
            det_type = detection.type.value
            if det_type not in detections_by_type:
                detections_by_type[det_type] = []
            detections_by_type[det_type].append(
                {
                    "name": detection.name,
                    "version": detection.version,
                    "confidence": detection.confidence,
                }
            )

        return {
            "file_type": die_result.file_type,
            "architecture": die_result.architecture,
            "compiler": die_result.compiler,
            "is_packed": die_result.is_packed,
            "is_protected": die_result.is_protected,
            "has_overlay": die_result.has_overlay,
            "detections": detections_by_type,
            "total_detections": len(die_result.detections),
            "total_licensing_schemes": len(
                [
                    d
                    for d in die_result.detections
                    if d.type
                    in [
                        ProtectionType.LICENSE,
                        ProtectionType.DONGLE,
                        ProtectionType.DRM,
                    ]
                ]
            ),
            "protection_summary": self._get_protection_summary(die_result),
        }

    def _get_protection_summary(self, die_result: ProtectionAnalysis) -> str:
        """Get a summary of all protections detected.

        Args:
            die_result: Protection analysis result from detector.

        Returns:
            str: Human-readable summary of detected protections.
        """
        if not die_result.detections:
            return "No protections detected"

        protection_names: list[str] = []
        for detection in die_result.detections:
            if detection.type in [
                ProtectionType.PACKER,
                ProtectionType.PROTECTOR,
                ProtectionType.LICENSE,
                ProtectionType.DONGLE,
                ProtectionType.DRM,
            ]:
                ver_str = f" v{detection.version}" if detection.version else ""
                protection_names.append(f"{detection.name}{ver_str}")

        if not protection_names:
            return "No significant protections detected"

        return ", ".join(protection_names)

    def _get_bypass_difficulty(self, die_result: ProtectionAnalysis) -> str:
        """Estimate bypass difficulty based on detections.

        Args:
            die_result: Protection analysis result from detector.

        Returns:
            str: Difficulty level (None, Low, Medium, High, Very High).
        """
        if not die_result.detections:
            return "None"

        difficult_protections = ["Denuvo", "VMProtect", "Themida", "SecuROM"]
        moderate_protections = ["HASP", "Sentinel", "CodeMeter", "FlexLM", "ASProtect"]
        easy_protections = ["UPX", "ASPack", "PECompact"]

        max_difficulty = "Low"
        for detection in die_result.detections:
            name_lower = detection.name.lower()
            if any(p.lower() in name_lower for p in difficult_protections):
                return "Very High"
            elif any(p.lower() in name_lower for p in moderate_protections):
                max_difficulty = "High"
            elif any(p.lower() in name_lower for p in easy_protections) and max_difficulty == "Low":
                max_difficulty = "Medium"

        return max_difficulty

    def _get_technical_details(self, die_result: ProtectionAnalysis) -> dict[str, Any]:
        """Extract technical details from DIE analysis.

        Args:
            die_result: Protection analysis result from detector.

        Returns:
            dict[str, Any]: Technical details including binary characteristics, sections, and imports.
        """
        details: dict[str, Any] = {
            "binary_characteristics": {
                "file_type": die_result.file_type,
                "architecture": die_result.architecture,
                "compiler": die_result.compiler,
                "is_packed": die_result.is_packed,
                "is_protected": die_result.is_protected,
                "has_overlay": die_result.has_overlay,
                "has_resources": die_result.has_resources,
            },
            "sections": die_result.sections[:5] if die_result.sections else [],
            "imports_summary": {
                "total_dlls": len(die_result.imports),
                "sample_imports": die_result.imports[:10],
            },
        }

        if die_result.detections:
            details["protection_indicators"] = self._get_protection_indicators_from_die(die_result)

        return details

    def _get_protection_indicators_from_die(self, die_result: ProtectionAnalysis) -> list[str]:
        """Get specific indicators from DIE detections.

        Args:
            die_result: Protection analysis result from detector.

        Returns:
            list[str]: List of specific protection indicators detected in the binary.
        """
        indicators: list[str] = []

        if die_result.is_packed:
            indicators.append("Code packing/encryption detected")
        if die_result.is_protected:
            indicators.append("Protection scheme applied")
        if die_result.has_overlay:
            indicators.append("Overlay data present")

        for detection in die_result.detections:
            name_lower = detection.name.lower()
            if "hasp" in name_lower:
                indicators.extend(
                    (
                        "Hardware dongle communication detected",
                        "HASP API imports found",
                    )
                )
            elif "flexlm" in name_lower or "flexnet" in name_lower:
                indicators.extend(
                    (
                        "License file references detected",
                        "Network license manager patterns",
                    )
                )
            elif "steam" in name_lower:
                indicators.extend(
                    (
                        "Steam API integration detected",
                        "CEG wrapping patterns found",
                    )
                )
            elif "denuvo" in name_lower:
                indicators.extend(
                    (
                        "Heavy virtualization detected",
                        "Multiple integrity check triggers",
                    )
                )
            elif "vmprotect" in name_lower:
                indicators.extend(("Code virtualization detected", ".vmp sections present"))
            elif "themida" in name_lower or "winlicense" in name_lower:
                indicators.extend(
                    (
                        "SecureEngine protection detected",
                        "Advanced anti-debugging present",
                    )
                )
        return list(set(indicators))

    def _get_bypass_guidance(self, die_result: ProtectionAnalysis) -> dict[str, Any]:
        """Provide bypass guidance based on DIE detections.

        Args:
            die_result: Protection analysis result from detector.

        Returns:
            dict[str, Any]: Bypass guidance including approach, technique, and difficulty score.
        """
        if not die_result.detections:
            return {
                "approach": "No bypass needed",
                "description": "The binary appears to be unprotected. Standard analysis techniques should work.",
                "estimated_time": "N/A",
                "difficulty_score": 0,
            }

        main_protection: DetectionResult | None = next(
            (
                detection
                for detection in die_result.detections
                if detection.type
                in [
                    ProtectionType.PROTECTOR,
                    ProtectionType.LICENSE,
                    ProtectionType.DONGLE,
                    ProtectionType.DRM,
                ]
            ),
            None,
        )
        if not main_protection:
            for detection in die_result.detections:
                if detection.type == ProtectionType.PACKER:
                    main_protection = detection
                    break

        if not main_protection:
            return {
                "approach": "Standard analysis",
                "description": "No significant protections detected. Use standard RE tools.",
                "estimated_time": "Minimal",
                "difficulty_score": 1,
            }

        guidance: dict[str, Any] = {
            "approach": f"{main_protection.name} bypass required",
            "protection_type": main_protection.type.value,
            "estimated_time": self._estimate_bypass_time(main_protection.name),
            "difficulty_score": self._difficulty_to_score(self._get_bypass_difficulty(die_result)),
        }

        if main_protection.bypass_recommendations:
            guidance["recommendations"] = main_protection.bypass_recommendations
            guidance["primary_technique"] = main_protection.bypass_recommendations[0]

        guidance["analysis_tips"] = self._get_analysis_tips(main_protection)

        return guidance

    def _difficulty_to_score(self, difficulty: str) -> int:
        """Convert difficulty to numeric score (0-10).

        Args:
            difficulty: Difficulty level as string.

        Returns:
            int: Numeric difficulty score from 0 to 10.
        """
        scores: dict[str, int] = {
            "None": 0,
            "Trivial": 1,
            "Low": 3,
            "Medium": 5,
            "High": 7,
            "Very High": 9,
            "Extreme": 10,
            "Unknown": 5,
        }
        return scores.get(difficulty, 5)

    def _estimate_bypass_time(self, protection_name: str) -> str:
        """Estimate bypass time based on protection.

        Args:
            protection_name: Name of the protection scheme.

        Returns:
            str: Estimated time to bypass the protection.
        """
        name_lower = protection_name.lower()

        if any(p in name_lower for p in ["upx", "aspack", "pecompact"]):
            return "5-30 minutes"
        elif any(p in name_lower for p in ["hasp", "sentinel", "flexlm", "crypkey"]):
            return "1-4 hours"
        elif any(p in name_lower for p in ["themida", "vmprotect", "asprotect", "enigma"]):
            return "4-24 hours"
        elif any(p in name_lower for p in ["denuvo", "securom"]):
            return "Days to weeks"
        else:
            return "Varies"

    def _get_analysis_tips(self, detection: DetectionResult) -> list[str]:
        """Get analysis tips for a specific detection.

        Args:
            detection: Detection result with protection information.

        Returns:
            list[str]: List of analysis tips specific to the detected protection.
        """
        tips: list[str] = []

        if detection.type == ProtectionType.PACKER:
            tips.extend(
                [
                    "Set breakpoint at OEP (Original Entry Point)",
                    "Monitor VirtualAlloc/VirtualProtect calls",
                    "Use process dumper after unpacking",
                ]
            )
        elif detection.type in [ProtectionType.PROTECTOR, ProtectionType.CRYPTOR]:
            tips.extend(
                [
                    "Use anti-anti-debug plugins",
                    "Monitor API hooks and redirections",
                    "Check for VM detection routines",
                ]
            )
        elif detection.type in [ProtectionType.LICENSE, ProtectionType.DONGLE]:
            tips.extend(
                [
                    "Monitor license validation APIs",
                    "Check registry/file access for license data",
                    "Use API hooking to bypass checks",
                ]
            )

        return tips[:5]

    def _get_tool_recommendations(self, die_result: ProtectionAnalysis) -> list[dict[str, str]]:
        """Recommend tools based on DIE detections.

        Args:
            die_result: Protection analysis result from detector.

        Returns:
            list[dict[str, str]]: List of recommended tools with names and purposes.
        """
        tools: list[dict[str, str]] = []
        seen: set[str] = set()

        basic_tools: list[dict[str, str]] = [
            {"name": "x64dbg", "purpose": "Dynamic analysis"},
            {"name": "IDA Pro", "purpose": "Static analysis"},
            {"name": "Ghidra", "purpose": "Free disassembler"},
        ]

        for detection in die_result.detections:
            name_lower = detection.name.lower()

            if detection.type == ProtectionType.PACKER:
                if "upx" in name_lower:
                    tools.append({"name": "UPX", "purpose": "Official unpacker"})
                elif "aspack" in name_lower:
                    tools.append({"name": "ASPack Unpacker", "purpose": "Unpacking tool"})
                else:
                    tools.append({"name": "Scylla", "purpose": "Import reconstruction"})

            elif detection.type == ProtectionType.PROTECTOR:
                if "themida" in name_lower or "winlicense" in name_lower:
                    tools.append({"name": "Themida Unpacker", "purpose": "Devirtualization"})
                elif "vmprotect" in name_lower:
                    tools.append({"name": "VMProtect Devirtualizer", "purpose": "VM analysis"})
                tools.append({"name": "ScyllaHide", "purpose": "Anti-anti-debug"})

            elif detection.type in [ProtectionType.LICENSE, ProtectionType.DONGLE]:
                if "hasp" in name_lower:
                    tools.append({"name": "HASP Emulator", "purpose": "Dongle emulation"})
                elif "flexlm" in name_lower:
                    tools.append({"name": "FlexLM Tools", "purpose": "License analysis"})
                tools.append({"name": "API Monitor", "purpose": "API call tracing"})

        all_tools = basic_tools.copy()
        for tool in tools:
            if tool["name"] not in seen:
                seen.add(tool["name"])
                all_tools.append(tool)

        return all_tools[:8]

    def _build_llm_context(self, die_result: ProtectionAnalysis) -> dict[str, Any]:
        """Build context specifically formatted for LLM consumption.

        Args:
            die_result: Protection analysis result from detector.

        Returns:
            dict[str, Any]: Context formatted for LLM processing and analysis.
        """
        protection_summary = self._get_protection_summary(die_result)

        context: dict[str, Any] = {
            "summary": f"Binary analysis complete: {protection_summary}",
            "file_type": die_result.file_type,
            "architecture": die_result.architecture,
            "is_protected": die_result.is_protected or die_result.is_packed,
            "key_characteristics": [],
        }

        key_chars: list[str] = context["key_characteristics"]
        if die_result.is_packed:
            key_chars.append("Packed/Encrypted code")
        if die_result.is_protected:
            key_chars.append("Protection scheme applied")
        if die_result.has_overlay:
            key_chars.append("Overlay data present")
        if len(die_result.detections) > 3:
            key_chars.append("Multiple protections detected")

        if die_result.detections:
            context["detections"] = []
            detections_list: list[dict[str, Any]] = context["detections"]
            for detection in die_result.detections:
                det_info: dict[str, Any] = {
                    "name": detection.name,
                    "type": detection.type.value,
                    "version": detection.version,
                }
                if detection.bypass_recommendations:
                    det_info["primary_bypass"] = detection.bypass_recommendations[0]
                detections_list.append(det_info)

            if main_protection := next(
                (
                    detection.name
                    for detection in die_result.detections
                    if detection.type
                    in [
                        ProtectionType.PROTECTOR,
                        ProtectionType.LICENSE,
                        ProtectionType.DONGLE,
                        ProtectionType.DRM,
                    ]
                ),
                None,
            ):
                context["main_protection"] = main_protection
                context["llm_guidance"] = self._get_llm_specific_guidance(main_protection)
            else:
                context["llm_guidance"] = "No significant protections. Focus on standard analysis."
        else:
            context["llm_guidance"] = "Binary appears unprotected. Standard analysis techniques apply."

        return context

    def _get_llm_specific_guidance(self, protection_name: str) -> str:
        """Get LLM-specific guidance for the protection.

        Args:
            protection_name: Name of the protection scheme.

        Returns:
            str: LLM-specific guidance for analyzing the protection.
        """
        name_lower = protection_name.lower()

        if "hasp" in name_lower or "sentinel" in name_lower:
            return "Hardware dongle protection. Focus on hasp_login API and feature ID validation."
        elif "flexlm" in name_lower or "flexnet" in name_lower:
            return "Network license manager. Look for license.dat parsing and server communication."
        elif "winlicense" in name_lower or "themida" in name_lower:
            return "Heavy virtualization. Unpacking required before analysis. Check for SecureEngine."
        elif "vmprotect" in name_lower:
            return "Code virtualization. Look for .vmp sections and VM handlers."
        elif "steam" in name_lower:
            return "Steam wrapper. Use Steamless or similar for unwrapping. Monitor Steam API calls."
        elif "denuvo" in name_lower:
            return "Extreme protection with 100+ triggers. Professional challenge requiring months."
        elif "upx" in name_lower:
            return "Simple packer. Use 'upx -d' or manual unpacking at OEP."
        elif "aspack" in name_lower:
            return "Commercial packer. Set breakpoint on GetProcAddress for unpacking."
        else:
            return f"Protection: {protection_name}. Analyze specific implementation for bypass approach."

    def _should_analyze_license_patterns(self, result: ProtectionAnalysis) -> bool:
        """Determine if license pattern analysis would be beneficial.

        Args:
            result: Protection analysis result from detector.

        Returns:
            bool: True if license pattern analysis should be performed.
        """
        if hasattr(result, "imports"):
            license_imports = [
                "license",
                "serial",
                "activation",
                "key",
                "hasp",
                "sentinel",
                "flexlm",
            ]
            for import_dll in result.imports:
                if any(keyword in import_dll.lower() for keyword in license_imports):
                    return True

        if hasattr(result, "compiler") and result.compiler:
            commercial_compilers = ["visual c++", "visual studio", "delphi", "borland"]
            if any(comp in result.compiler.lower() for comp in commercial_compilers):
                return True

        return False

    def _analyze_license_patterns(self, binary_path: str, result: ProtectionAnalysis) -> dict[str, Any]:
        """Analyze license patterns using AI assistant.

        Args:
            binary_path: Path to the binary file.
            result: Protection analysis result from detector.

        Returns:
            dict[str, Any]: License pattern analysis results.
        """
        try:
            strings_data = self._extract_strings_from_binary(binary_path)

            input_data: dict[str, Any] = {
                "patterns": [],
                "strings": strings_data.get("license_related_strings", [])[:50],
                "binary_path": binary_path,
            }

            if hasattr(result, "detections"):
                patterns_list: list[dict[str, Any]] = input_data["patterns"]
                patterns_list.extend(
                    {
                        "name": detection.name,
                        "type": detection.type.value,
                        "version": detection.version,
                        "confidence": detection.confidence,
                    }
                    for detection in result.detections
                    if detection.type
                    in [
                        ProtectionType.LICENSE,
                        ProtectionType.DONGLE,
                        ProtectionType.DRM,
                    ]
                )
            license_analysis = self.ai_assistant.analyze_license_patterns(input_data)

            if license_analysis and not license_analysis.get("error"):
                license_analysis["protection_context"] = self._get_license_protection_context(result)

            return license_analysis

        except Exception as e:
            logger.warning(f"License pattern analysis failed: {e}")
            return {"error": str(e)}

    def _extract_strings_from_binary(self, binary_path: str) -> dict[str, Any]:
        """Extract strings from binary with focus on license-related patterns.

        Args:
            binary_path: Path to the binary file.

        Returns:
            dict[str, Any]: Extracted license-related strings and metadata.
        """
        try:
            try:
                from ..core.analysis.radare2_strings import R2StringAnalyzer

                analyzer = R2StringAnalyzer(binary_path)
                string_results = analyzer.analyze_all_strings(min_length=6)

                license_strings: list[str] = []
                license_strings.extend(string_results.get("license_strings", []))
                license_strings.extend(string_results.get("error_message_strings", []))
                license_strings.extend(string_results.get("version_strings", []))

                return {
                    "license_related_strings": license_strings[:100],
                    "total_strings": string_results.get("total_strings", 0),
                }
            except ImportError:
                pass

            import subprocess

            try:
                result = subprocess.run(["strings", "-n", "6", binary_path], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    all_strings = result.stdout.split("\n")

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
                    license_strings_result: list[str] = []

                    for string in all_strings:
                        if any(keyword in string.lower() for keyword in license_keywords):
                            license_strings_result.append(string)
                            if len(license_strings_result) >= 100:
                                break

                    return {
                        "license_related_strings": license_strings_result,
                        "total_strings": len(all_strings),
                    }
            except (subprocess.SubprocessError, FileNotFoundError):
                pass

            return {"license_related_strings": [], "total_strings": 0}

        except Exception as e:
            logger.warning(f"String extraction failed: {e}")
            return {"license_related_strings": [], "total_strings": 0, "error": str(e)}

    def _get_license_protection_context(self, result: ProtectionAnalysis) -> dict[str, Any]:
        """Get additional context for license protection analysis.

        Args:
            result: Protection analysis result from detector.

        Returns:
            dict[str, Any]: Additional context for license protection analysis.
        """
        context: dict[str, Any] = {
            "has_network_apis": False,
            "has_crypto_apis": False,
            "has_registry_apis": False,
            "likely_license_files": [],
        }

        if hasattr(result, "imports"):
            network_dlls = ["ws2_32.dll", "winhttp.dll", "wininet.dll"]
            crypto_dlls = ["crypt32.dll", "advapi32.dll", "bcrypt.dll"]

            for import_dll in result.imports:
                dll_lower = import_dll.lower()
                if any(net_dll in dll_lower for net_dll in network_dlls):
                    context["has_network_apis"] = True
                if any(crypto_dll in dll_lower for crypto_dll in crypto_dlls):
                    context["has_crypto_apis"] = True
                if "advapi32.dll" in dll_lower:
                    context["has_registry_apis"] = True

        context["likely_license_files"] = [
            "license.dat",
            "license.lic",
            "license.key",
            "activation.dat",
            "registration.key",
        ]

        return context

    def format_for_display(self, analysis: dict[str, Any]) -> str:
        """Format analysis results for human-readable display.

        Args:
            analysis: Analysis results dictionary.

        Returns:
            str: Formatted analysis report for display.
        """
        if not analysis.get("success"):
            return f"Analysis failed: {analysis.get('error', 'Unknown error')}"

        protection = analysis["protection_analysis"]
        file_info = analysis["file_info"]

        output: list[str] = [
            "=" * 60,
            "PROTECTION ANALYSIS REPORT",
            "=" * 60,
            f"\nFile: {file_info['name']}",
            f"Size: {file_info['size_human']}",
            f"Path: {file_info['path']}",
            f"\nFile Type: {protection['file_type']}",
            f"Architecture: {protection['architecture']}",
        ]
        if protection.get("compiler"):
            output.append(f"Compiler: {protection['compiler']}")

        output.extend(
            (
                f"\nPacked: {'Yes' if protection['is_packed'] else 'No'}",
                f"Protected: {'Yes' if protection['is_protected'] else 'No'}",
            )
        )
        if protection.get("detections"):
            output.append("\nDetections:")
            for det_type, detections in protection["detections"].items():
                output.append(f"\n  {det_type.upper()}:")
                for det in detections:
                    ver_str = f" v{det['version']}" if det.get("version") else ""
                    conf_str = f" ({det['confidence']:.0f}%)" if det.get("confidence", 100) < 100 else ""
                    output.append(f"    - {det['name']}{ver_str}{conf_str}")
        else:
            output.append("\nNo protections detected")

        if guidance := analysis.get("bypass_guidance", {}):
            output.extend(
                (
                    f"\nBypass Approach: {guidance.get('approach', 'Unknown')}",
                    f"Estimated Time: {guidance.get('estimated_time', 'Unknown')}",
                    f"Difficulty Score: {guidance.get('difficulty_score', 0)}/10",
                )
            )
            if "recommended_technique" in guidance:
                tech = guidance["recommended_technique"]
                output.extend(
                    (
                        f"\nRecommended Technique: {tech['name']}",
                        f"  Success Rate: {tech['success_rate']:.0%}",
                        f"  Time: {tech['time_estimate']}",
                    )
                )
        if tools := analysis.get("tool_recommendations", []):
            output.append("\nRecommended Tools:")
            output.extend(f"  - {tool['name']}: {tool['purpose']}" for tool in tools)
        license_files = analysis.get("license_files_found", {})
        if license_files.get("files_found"):
            output.append("\nLicense Files Found:")
            for file_info_item in license_files["files_found"][:5]:
                output.append(f"  - {file_info_item['name']} ({file_info_item['size_str']})")
                if file_info_item.get("match_type"):
                    output.append(f"    Type: {file_info_item['match_type']}")

        output.append("\n" + "=" * 60)

        return "\n".join(output)


def register_protection_analyzer_tool() -> dict[str, Any]:
    """Register this tool for LLM usage.

    Returns:
        dict[str, Any]: Tool registration configuration for LLM integration.
    """
    def handler(params: dict[str, Any]) -> dict[str, Any]:
        return ProtectionAnalyzerTool().analyze(params["file_path"], params.get("detailed", True))

    return {
        "name": "analyze_protection",
        "description": "Analyze a binary file to detect and identify software protection schemes",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the binary file to analyze",
                },
                "detailed": {
                    "type": "boolean",
                    "description": "Include detailed technical information",
                    "default": True,
                },
            },
            "required": ["file_path"],
        },
        "handler": handler,
    }
