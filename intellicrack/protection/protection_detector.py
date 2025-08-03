"""Main Protection Detection Module

This module serves as the primary interface for protection detection in Intellicrack.
It uses the unified protection engine which provides comprehensive protection detection
through multiple analysis methods.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
from typing import Any

from ..utils.logger import get_logger
from .intellicrack_protection_core import (
    DetectionResult,
    ProtectionAnalysis,
    ProtectionType,
)
from .unified_protection_engine import (
    UnifiedProtectionEngine,
    UnifiedProtectionResult,
)

logger = get_logger(__name__)


class ProtectionDetector:
    """Main protection detection interface for Intellicrack

    This class provides a seamless interface to the unified protection engine,
    making it appear as if all detection capabilities are native to Intellicrack.
    """

    def __init__(self, enable_protection: bool = True, enable_heuristics: bool = True):
        """Initialize the protection detector

        Args:
            enable_protection: Enable protection analysis
            enable_heuristics: Enable behavioral analysis

        """
        self.engine = UnifiedProtectionEngine(
            enable_protection=enable_protection,
            enable_heuristics=enable_heuristics,
        )

    def detect_protections(self, file_path: str, deep_scan: bool = True) -> ProtectionAnalysis:
        """Analyze a binary file for protections

        This method maintains backward compatibility with the original DIE detector
        interface while using the unified engine underneath.

        Args:
            file_path: Path to the binary file to analyze
            deep_scan: Perform comprehensive analysis

        Returns:
            ProtectionAnalysis object with all detection results

        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Use unified engine
        unified_result = self.engine.analyze(file_path, deep_scan=deep_scan)

        # Convert to legacy format for compatibility
        return self._convert_to_legacy_format(unified_result)

    def analyze(self, file_path: str, deep_scan: bool = True) -> UnifiedProtectionResult:
        """Perform unified protection analysis

        This is the modern interface that returns the full unified result.

        Args:
            file_path: Path to the binary file to analyze
            deep_scan: Perform comprehensive analysis

        Returns:
            UnifiedProtectionResult with comprehensive analysis

        """
        return self.engine.analyze(file_path, deep_scan=deep_scan)

    def get_quick_summary(self, file_path: str) -> dict[str, Any]:
        """Get a quick protection summary without deep analysis

        Args:
            file_path: Path to the binary file

        Returns:
            Dictionary with quick summary information

        """
        return self.engine.get_quick_summary(file_path)

    def analyze_directory(self, directory: str, recursive: bool = True,
                         deep_scan: bool = False) -> list[ProtectionAnalysis]:
        """Analyze all executable files in a directory

        Args:
            directory: Directory path to scan
            recursive: Whether to scan subdirectories
            deep_scan: Perform deep analysis on each file

        Returns:
            List of ProtectionAnalysis results

        """
        results = []
        extensions = [".exe", ".dll", ".sys", ".ocx", ".scr", ".com", ".so", ".dylib"]

        if recursive:
            for root, _dirs, files in os.walk(directory):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in extensions):
                        file_path = os.path.join(root, file)
                        try:
                            analysis = self.detect_protections(file_path, deep_scan=deep_scan)
                            results.append(analysis)
                        except Exception as e:
                            logger.error(f"Error analyzing {file_path}: {e}")
        else:
            for file in os.listdir(directory):
                if any(file.lower().endswith(ext) for ext in extensions):
                    file_path = os.path.join(directory, file)
                    if os.path.isfile(file_path):
                        try:
                            analysis = self.detect_protections(file_path, deep_scan=deep_scan)
                            results.append(analysis)
                        except Exception as e:
                            logger.error(f"Error analyzing {file_path}: {e}")

        return results

    def get_bypass_strategies(self, file_path: str) -> list[dict[str, Any]]:
        """Get bypass strategies for protections detected in a file

        Args:
            file_path: Path to the binary file

        Returns:
            List of bypass strategy dictionaries

        """
        result = self.engine.analyze(file_path)
        return result.bypass_strategies

    def _convert_to_legacy_format(self, unified_result: UnifiedProtectionResult) -> ProtectionAnalysis:
        """Convert unified result to legacy ProtectionAnalysis format

        This ensures backward compatibility with existing code.
        """
        analysis = ProtectionAnalysis(
            file_path=unified_result.file_path,
            file_type=unified_result.file_type,
            architecture=unified_result.architecture,
            is_packed=unified_result.is_packed,
            is_protected=unified_result.is_protected,
        )

        # Convert protections
        for protection in unified_result.protections:
            det_result = DetectionResult(
                name=protection["name"],
                version=protection.get("version"),
                type=self._map_protection_type(protection["type"]),
                confidence=protection.get("confidence", 100.0),
                details=protection.get("details", {}),
                bypass_recommendations=protection.get("bypass_recommendations", []),
            )
            analysis.detections.append(det_result)

        # Copy DIE-specific data if available
        if unified_result.die_analysis:
            die = unified_result.die_analysis
            analysis.has_overlay = die.has_overlay
            analysis.has_resources = die.has_resources
            analysis.entry_point = die.entry_point
            analysis.sections = die.sections
            analysis.imports = die.imports
            analysis.strings = die.strings

        # Add metadata
        analysis.metadata = {
            "analysis_time": unified_result.analysis_time,
            "engines_used": unified_result.engines_used,
            "confidence_score": unified_result.confidence_score,
        }

        return analysis

    def _map_protection_type(self, type_str: str) -> ProtectionType:
        """Map string protection type to enum"""
        type_map = {
            "packer": ProtectionType.PACKER,
            "protector": ProtectionType.PROTECTOR,
            "compiler": ProtectionType.COMPILER,
            "installer": ProtectionType.INSTALLER,
            "library": ProtectionType.LIBRARY,
            "overlay": ProtectionType.OVERLAY,
            "cryptor": ProtectionType.CRYPTOR,
            "dongle": ProtectionType.DONGLE,
            "license": ProtectionType.LICENSE,
            "drm": ProtectionType.DRM,
            "antidebug": ProtectionType.PROTECTOR,
            "obfuscator": ProtectionType.PROTECTOR,
        }

        return type_map.get(type_str.lower(), ProtectionType.UNKNOWN)

    def get_summary(self, analysis: ProtectionAnalysis) -> str:
        """Get a human-readable summary of the analysis"""
        lines = []
        lines.append(f"File: {os.path.basename(analysis.file_path)}")
        lines.append(f"Type: {analysis.file_type} ({analysis.architecture})")

        if analysis.compiler:
            lines.append(f"Compiler: {analysis.compiler}")

        status_flags = []
        if analysis.is_packed:
            status_flags.append("PACKED")
        if analysis.is_protected:
            status_flags.append("PROTECTED")

        if status_flags:
            lines.append(f"Status: {' | '.join(status_flags)}")

        if analysis.detections:
            lines.append("\nProtections Detected:")
            for det in analysis.detections:
                ver_str = f" v{det.version}" if det.version else ""
                conf_str = f" [{det.confidence:.0f}%]" if det.confidence < 100 else ""
                lines.append(f"  • {det.name}{ver_str} ({det.type.value}){conf_str}")

        if "confidence_score" in analysis.metadata:
            lines.append(f"\nOverall Confidence: {analysis.metadata['confidence_score']:.0f}%")

        if "engines_used" in analysis.metadata:
            lines.append(f"Analysis Methods: {', '.join(analysis.metadata['engines_used'])}")

        return "\n".join(lines)

    def export_results(self, analysis: ProtectionAnalysis, output_format: str = "json") -> str:
        """Export analysis results in various formats

        Args:
            analysis: ProtectionAnalysis to export
            output_format: Format to export ("json", "text", "csv")

        Returns:
            Formatted string of results

        """
        if output_format == "json":
            import json

            # Convert to dict for JSON serialization
            data = {
                "file_path": analysis.file_path,
                "file_type": analysis.file_type,
                "architecture": analysis.architecture,
                "is_packed": analysis.is_packed,
                "is_protected": analysis.is_protected,
                "compiler": analysis.compiler,
                "detections": [
                    {
                        "name": d.name,
                        "version": d.version,
                        "type": d.type.value,
                        "confidence": d.confidence,
                        "bypass_recommendations": d.bypass_recommendations,
                    }
                    for d in analysis.detections
                ],
                "metadata": analysis.metadata,
            }
            return json.dumps(data, indent=2)

        if output_format == "text":
            return self.get_summary(analysis)

        if output_format == "csv":
            lines = ["File,Type,Architecture,Protection,Version,Category,Confidence"]
            for det in analysis.detections:
                lines.append(
                    f"{analysis.file_path},{analysis.file_type},{analysis.architecture},"
                    f"{det.name},{det.version or 'N/A'},{det.type.value},{det.confidence:.0f}",
                )
            return "\n".join(lines)

        raise ValueError(f"Unknown output format: {output_format}")


# Global detector instance
_global_detector = None

def get_protection_detector() -> ProtectionDetector:
    """Get or create global protection detector instance"""
    global _global_detector
    if _global_detector is None:
        _global_detector = ProtectionDetector()
    return _global_detector


# Convenience functions for quick analysis
def quick_analyze(file_path: str) -> ProtectionAnalysis:
    """Quick analysis function for one-off use"""
    detector = get_protection_detector()
    return detector.detect_protections(file_path, deep_scan=False)


def deep_analyze(file_path: str) -> UnifiedProtectionResult:
    """Deep analysis with full unified result"""
    detector = get_protection_detector()
    return detector.analyze(file_path, deep_scan=True)


if __name__ == "__main__":
    # Example usage
    import sys
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        detector = ProtectionDetector()

        # Quick analysis
        print("=== QUICK ANALYSIS ===")
        summary = detector.get_quick_summary(target_file)
        print(f"Protected: {summary['protected']}")
        print(f"Main Protection: {summary.get('main_protection', 'None')}")
        print(f"Confidence: {summary['confidence']:.0f}%")

        # Full analysis
        print("\n=== FULL ANALYSIS ===")
        analysis = detector.detect_protections(target_file)
        print(detector.get_summary(analysis))

        # Bypass strategies
        print("\n=== BYPASS STRATEGIES ===")
        strategies = detector.get_bypass_strategies(target_file)
        for strategy in strategies:
            print(f"\n{strategy['name']} ({strategy['difficulty']})")
            print(f"  {strategy['description']}")
            if "tools" in strategy:
                print(f"  Tools: {', '.join(strategy['tools'])}")
    else:
        print("Usage: python protection_detector.py <binary_file>")
