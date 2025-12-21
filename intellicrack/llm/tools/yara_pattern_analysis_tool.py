"""YARA Pattern Analysis Tool for LLM Integration

Provides AI models with the ability to run YARA pattern matching and analysis
on binary files to detect protection patterns and security indicators.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
from typing import Any, Dict, List

from ...core.analysis.yara_pattern_engine import get_yara_engine, is_yara_available
from ...utils.logger import get_logger

logger = get_logger(__name__)


class YARAPatternAnalysisTool:
    """LLM tool for running YARA pattern analysis on binary files"""

    def __init__(self):
        """Initialize YARA pattern analysis tool"""
        self.engine = get_yara_engine()
        self.analysis_cache = {}

    def get_tool_definition(self) -> dict[str, Any]:
        """Get tool definition for LLM registration

        Returns:
            Tool definition dictionary

        """
        return {
            "name": "yara_pattern_analysis",
            "description": "Run YARA pattern matching on binary files to detect protection patterns, anti-debug mechanisms, packers, and security indicators",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the binary file to analyze",
                    },
                    "rule_categories": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [
                                "PROTECTION",
                                "PACKER",
                                "LICENSING",
                                "ANTI_DEBUG",
                                "ANTI_VM",
                                "CRYPTOR",
                                "ALL",
                            ],
                        },
                        "description": "Categories of YARA rules to run (default: ALL)",
                        "default": ["ALL"],
                    },
                    "custom_rules": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional custom YARA rules to include",
                        "default": [],
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Analysis timeout in seconds",
                        "default": 60,
                    },
                    "include_strings": {
                        "type": "boolean",
                        "description": "Include matched string data in results",
                        "default": True,
                    },
                    "detailed_output": {
                        "type": "boolean",
                        "description": "Include detailed pattern analysis and metadata",
                        "default": True,
                    },
                },
                "required": ["file_path"],
            },
        }

    def execute(self, **kwargs) -> dict[str, Any]:
        """Execute YARA pattern analysis

        Args:
            **kwargs: Tool parameters

        Returns:
            Analysis results dictionary

        """
        file_path = kwargs.get("file_path")
        if not file_path or not os.path.exists(file_path):
            return {"success": False, "error": f"File not found: {file_path}"}

        if not is_yara_available():
            return {"success": False, "error": "YARA engine not available"}

        # Get parameters
        rule_categories = kwargs.get("rule_categories", ["ALL"])
        custom_rules = kwargs.get("custom_rules", [])
        timeout = kwargs.get("timeout", 60)
        include_strings = kwargs.get("include_strings", True)
        detailed_output = kwargs.get("detailed_output", True)

        try:
            # Check cache
            cache_key = f"{file_path}:{':'.join(rule_categories)}:{len(custom_rules)}"
            if cache_key in self.analysis_cache:
                logger.debug(f"Returning cached YARA analysis for {file_path}")
                cached_result = self.analysis_cache[cache_key]
                cached_result["from_cache"] = True
                return cached_result

            # Determine which rule categories to use
            categories_to_scan = []
            if "ALL" in rule_categories:
                categories_to_scan = [
                    "PROTECTION",
                    "PACKER",
                    "LICENSING",
                    "ANTI_DEBUG",
                    "ANTI_VM",
                    "CRYPTOR",
                ]
            else:
                categories_to_scan = rule_categories

            # Validate categories and log scanning scope
            valid_categories = [
                "PROTECTION",
                "PACKER",
                "LICENSING",
                "ANTI_DEBUG",
                "ANTI_VM",
                "CRYPTOR",
            ]
            filtered_categories = [cat for cat in categories_to_scan if cat in valid_categories]

            if len(filtered_categories) != len(categories_to_scan):
                invalid_cats = [cat for cat in categories_to_scan if cat not in valid_categories]
                logger.warning(f"Invalid YARA categories ignored: {invalid_cats}")

            logger.info(f"Scanning {file_path} with YARA categories: {filtered_categories}")

            # Run YARA analysis
            analysis_result = self.engine.scan_file(file_path=file_path, timeout=timeout)

            if analysis_result.error:
                return {"success": False, "error": analysis_result.error}

            # Build result for LLM consumption
            result = {
                "success": True,
                "file_path": file_path,
                "scan_time": analysis_result.scan_time,
                "total_matches": len(analysis_result.matches),
                "total_rules": analysis_result.total_rules,
                "pattern_matches": self._format_pattern_matches(analysis_result.matches, include_strings),
                "security_assessment": self._assess_security_findings(analysis_result.matches),
                "bypass_recommendations": self._generate_bypass_recommendations(analysis_result.matches),
                "from_cache": False,
            }

            # Add detailed analysis if requested
            if detailed_output:
                result["detailed_analysis"] = {
                    "pattern_categories": self._categorize_patterns(analysis_result.matches),
                    "confidence_analysis": self._analyze_confidence_levels(analysis_result.matches),
                    "threat_indicators": self._extract_threat_indicators(analysis_result.matches),
                    "protection_layers": self._analyze_protection_layers(analysis_result.matches),
                }

            # Generate ICP supplemental data
            if self.engine:
                supplemental_data = self.engine.generate_icp_supplemental_data(analysis_result)
                result["icp_supplemental_data"] = supplemental_data

            # Cache result
            self.analysis_cache[cache_key] = result

            return result

        except Exception as e:
            logger.error(f"YARA pattern analysis error: {e}")
            return {"success": False, "error": str(e)}

    def _format_pattern_matches(self, matches: list[Any], include_strings: bool) -> list[dict[str, Any]]:
        """Format pattern matches for LLM consumption"""
        formatted_matches = []

        for match in matches:
            match_data = {
                "rule_name": match.rule_name,
                "category": match.category.value if hasattr(match.category, "value") else str(match.category),
                "confidence": match.confidence,
                "description": match.description,
                "severity": match.severity,
                "tags": match.tags,
                "offset": match.offset,
            }

            if include_strings and match.matched_strings:
                match_data["matched_strings"] = [
                    {
                        "identifier": s.identifier,
                        "value": s.value[:100] if len(s.value) > 100 else s.value,  # Limit string length
                        "offset": s.offset,
                        "length": s.length,
                    }
                    for s in match.matched_strings[:10]  # Limit to first 10 strings
                ]

            if hasattr(match, "metadata") and match.metadata:
                match_data["metadata"] = match.metadata

            formatted_matches.append(match_data)

        return formatted_matches

    def _assess_security_findings(self, matches: list[Any]) -> dict[str, Any]:
        """Assess security implications of pattern matches"""
        assessment: dict[str, Any] = {
            "overall_threat_level": "low",
            "protection_complexity": "basic",
            "anti_analysis_present": False,
            "encryption_indicators": False,
            "packing_indicators": False,
            "licensing_indicators": False,
            "security_score": 0.0,
            "high_confidence_matches": 0,
            "findings_summary": [],
        }

        if not matches:
            return assessment

        total_score: float = 0.0

        protection_categories: dict[str, int] = {
            "ANTI_DEBUG": 0,
            "ANTI_VM": 0,
            "PACKER": 0,
            "CRYPTOR": 0,
            "LICENSING": 0,
            "PROTECTION": 0,
        }

        for match in matches:
            if match.confidence >= 0.8:
                assessment["high_confidence_matches"] += 1
                total_score += 2.0
            elif match.confidence >= 0.6:
                total_score += 1.5
            else:
                total_score += 1.0

            # Categorize findings
            category = match.category.value if hasattr(match.category, "value") else str(match.category)
            if category in protection_categories:
                protection_categories[category] += 1

            # Set specific indicators
            if category == "ANTI_DEBUG" or "anti" in match.rule_name.lower():
                assessment["anti_analysis_present"] = True
            elif category == "CRYPTOR" or "encrypt" in match.rule_name.lower():
                assessment["encryption_indicators"] = True
            elif category == "PACKER" or "pack" in match.rule_name.lower():
                assessment["packing_indicators"] = True
            elif category == "LICENSING" or "license" in match.rule_name.lower():
                assessment["licensing_indicators"] = True

        # Normalize security score (0-10 scale)
        assessment["security_score"] = min(total_score, 10.0)

        # Determine threat level
        if assessment["security_score"] >= 7.0:
            assessment["overall_threat_level"] = "critical"
        elif assessment["security_score"] >= 5.0:
            assessment["overall_threat_level"] = "high"
        elif assessment["security_score"] >= 3.0:
            assessment["overall_threat_level"] = "medium"

        # Determine protection complexity
        unique_categories = sum(count > 0 for count in protection_categories.values())
        if unique_categories >= 4:
            assessment["protection_complexity"] = "advanced"
        elif unique_categories >= 2:
            assessment["protection_complexity"] = "moderate"

        # Generate findings summary
        for category, count in protection_categories.items():
            if count > 0:
                assessment["findings_summary"].append(f"{count} {category.lower()} patterns detected")

        return assessment

    def _generate_bypass_recommendations(self, matches: list[Any]) -> list[dict[str, Any]]:
        """Generate bypass recommendations based on pattern matches"""
        recommendations = []
        processed_categories = set()

        for match in matches:
            category = match.category.value if hasattr(match.category, "value") else str(match.category)

            # Avoid duplicate recommendations for same category
            if category in processed_categories:
                continue
            processed_categories.add(category)

            if category == "ANTI_DEBUG":
                recommendations.append(
                    {
                        "target": "Anti-Debug Protection",
                        "method": "Debug Environment Hiding",
                        "tools": ["ScyllaHide", "TitanHide", "Phantom"],
                        "difficulty": "medium",
                        "description": "Use debugger hiding tools to bypass anti-debug checks",
                        "technical_details": f"Pattern detected: {match.rule_name}",
                    }
                )

            elif category == "ANTI_VM":
                recommendations.append(
                    {
                        "target": "Anti-VM Protection",
                        "method": "VM Environment Masking",
                        "tools": ["Pafish", "VMware stealth", "Hardware ID spoofing"],
                        "difficulty": "high",
                        "description": "Modify VM characteristics to appear as physical machine",
                        "technical_details": f"Pattern detected: {match.rule_name}",
                    }
                )

            elif category == "PACKER":
                recommendations.append(
                    {
                        "target": "Packer Protection",
                        "method": "Unpacking",
                        "tools": ["UPX", "PEiD", "Detect It Easy", "OllyDump"],
                        "difficulty": "medium",
                        "description": "Identify and unpack the binary to access original code",
                        "technical_details": f"Packer pattern: {match.rule_name}",
                    }
                )

            elif category == "CRYPTOR":
                recommendations.append(
                    {
                        "target": "Encryption/Cryptor",
                        "method": "Cryptographic Analysis",
                        "tools": ["Cryptool", "Key extraction", "Memory dumping"],
                        "difficulty": "high",
                        "description": "Analyze encryption algorithms and extract keys",
                        "technical_details": f"Crypto pattern: {match.rule_name}",
                    }
                )

            elif category == "LICENSING":
                recommendations.append(
                    {
                        "target": "License Protection",
                        "method": "License Bypass",
                        "tools": ["Keygen", "Patch tools", "License emulation"],
                        "difficulty": "medium",
                        "description": "Bypass or emulate license checking mechanisms",
                        "technical_details": f"License pattern: {match.rule_name}",
                    }
                )

        return recommendations

    def _categorize_patterns(self, matches: list[Any]) -> dict[str, list[str]]:
        """Categorize detected patterns by type"""
        categories = {}

        for match in matches:
            category = match.category.value if hasattr(match.category, "value") else str(match.category)
            if category not in categories:
                categories[category] = []
            categories[category].append(match.rule_name)

        return categories

    def _analyze_confidence_levels(self, matches: list[Any]) -> dict[str, Any]:
        """Analyze confidence levels of matches"""
        if not matches:
            return {"average": 0.0, "high_confidence_count": 0, "low_confidence_count": 0}

        confidences = [match.confidence for match in matches]
        high_conf = sum(c >= 0.8 for c in confidences)
        low_conf = sum(c < 0.6 for c in confidences)

        return {
            "average": round(sum(confidences) / len(confidences), 3),
            "high_confidence_count": high_conf,
            "low_confidence_count": low_conf,
            "total_matches": len(matches),
        }

    def _extract_threat_indicators(self, matches: list[Any]) -> list[dict[str, Any]]:
        """Extract specific threat indicators from matches"""
        indicators = []

        for match in matches:
            if match.confidence >= 0.7:  # Only high-confidence threats
                indicator = {
                    "type": match.category.value if hasattr(match.category, "value") else str(match.category),
                    "name": match.rule_name,
                    "severity": match.severity,
                    "confidence": match.confidence,
                    "description": match.description,
                }

                # Add specific threat classification
                if "backdoor" in match.rule_name.lower():
                    indicator["threat_class"] = "backdoor"
                elif "trojan" in match.rule_name.lower():
                    indicator["threat_class"] = "trojan"
                elif "rootkit" in match.rule_name.lower():
                    indicator["threat_class"] = "rootkit"
                else:
                    indicator["threat_class"] = "protection"

                indicators.append(indicator)

        return indicators

    def _analyze_protection_layers(self, matches: list[Any]) -> dict[str, Any]:
        """Analyze layered protection schemes"""
        layers = {
            "packing_layer": False,
            "encryption_layer": False,
            "anti_analysis_layer": False,
            "licensing_layer": False,
            "total_layers": 0,
            "complexity_assessment": "simple",
        }

        for match in matches:
            category = match.category.value if hasattr(match.category, "value") else str(match.category)

            if category == "PACKER" and not layers["packing_layer"]:
                layers["packing_layer"] = True
                layers["total_layers"] += 1
            elif category == "CRYPTOR" and not layers["encryption_layer"]:
                layers["encryption_layer"] = True
                layers["total_layers"] += 1
            elif category in ["ANTI_DEBUG", "ANTI_VM"] and not layers["anti_analysis_layer"]:
                layers["anti_analysis_layer"] = True
                layers["total_layers"] += 1
            elif category == "LICENSING" and not layers["licensing_layer"]:
                layers["licensing_layer"] = True
                layers["total_layers"] += 1

        # Assess complexity based on layer count
        if layers["total_layers"] >= 3:
            layers["complexity_assessment"] = "advanced"
        elif layers["total_layers"] >= 2:
            layers["complexity_assessment"] = "moderate"

        return layers

    def analyze_custom_patterns(self, file_path: str, custom_rules_text: str) -> dict[str, Any]:
        """Analyze file with custom YARA rules provided as text

        Args:
            file_path: Path to file to analyze
            custom_rules_text: YARA rules as text string

        Returns:
            Analysis results

        """
        try:
            if not is_yara_available():
                return {"success": False, "error": "YARA engine not available"}

            # Parse and validate custom rules
            if not custom_rules_text.strip():
                return {"success": False, "error": "No custom rules provided"}

            # Create custom rule and scan
            # Note: This creates a temporary rule - for production use consider proper rule management
            temp_rule_name = f"custom_rule_{hash(custom_rules_text) % 10000}"
            if self.engine.create_custom_rule(custom_rules_text, temp_rule_name):
                custom_result = self.engine.scan_file(file_path)
            else:
                raise ValueError("Failed to compile custom YARA rules")

            return {
                "success": True,
                "file_path": file_path,
                "custom_rules_used": True,
                "matches": self._format_pattern_matches(custom_result.matches, True),
                "total_matches": len(custom_result.matches),
                "scan_time": custom_result.scan_time,
            }

        except Exception as e:
            logger.error(f"Custom YARA analysis error: {e}")
            return {"success": False, "error": str(e)}


def create_yara_pattern_tool() -> YARAPatternAnalysisTool:
    """Factory function to create YARA pattern analysis tool"""
    return YARAPatternAnalysisTool()
