"""Unified Protection Analysis Engine.

Seamlessly integrates protection detection and custom analysis into a single unified interface.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
import concurrent.futures
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..utils.logger import get_logger
from .analysis_cache import AnalysisCache, get_analysis_cache
from .icp_backend import ICPScanResult, get_icp_backend
from .icp_backend import ScanMode as ICPScanMode
from .intellicrack_protection_advanced import (
    AdvancedProtectionAnalysis,
    IntellicrackAdvancedProtection,
    ScanMode,
)

logger = get_logger(__name__)


class AnalysisSource(Enum):
    """Source of protection analysis."""

    PROTECTION_ENGINE = "protection_engine"
    HEURISTIC = "heuristic"
    SIGNATURE = "signature"
    HYBRID = "hybrid"
    ICP = "icp"
    ML_MODEL = "ml_model"
    UNIFIED_ENGINE = "unified_engine"


@dataclass
class UnifiedProtectionResult:
    """Unified protection analysis result combining all sources."""

    file_path: str
    file_type: str
    architecture: str

    # Combined detections from all sources
    protections: list[dict[str, Any]] = field(default_factory=list)
    confidence_score: float = 0.0

    # Detailed results from each engine
    protection_analysis: AdvancedProtectionAnalysis | None = None
    icp_analysis: ICPScanResult | None = None

    # Unified features
    is_packed: bool = False
    is_protected: bool = False
    is_obfuscated: bool = False
    has_anti_debug: bool = False
    has_anti_vm: bool = False
    has_licensing: bool = False

    # Bypass recommendations (aggregated and prioritized)
    bypass_strategies: list[dict[str, Any]] = field(default_factory=list)

    # Performance metrics
    analysis_time: float = 0.0
    engines_used: list[str] = field(default_factory=list)


class UnifiedProtectionEngine:
    """Unified engine that seamlessly combines multiple protection analysis methods."""

    def __init__(
        self,
        enable_protection: bool = True,
        enable_heuristics: bool = True,
        cache_config: dict[str, Any] | None = None,
    ):
        """Initialize unified protection engine.

        Args:
            enable_protection: Enable protection analysis
            enable_heuristics: Enable heuristic analysis
            cache_config: Cache configuration options

        """
        self.enable_protection = enable_protection
        self.enable_heuristics = enable_heuristics

        # Initialize engines
        self.protection_detector = IntellicrackAdvancedProtection() if enable_protection else None

        # Initialize advanced cache
        if cache_config:
            self.cache = AnalysisCache(**cache_config)
        else:
            self.cache = get_analysis_cache()

    def analyze(
        self, file_path: str, deep_scan: bool = True, timeout: int = 60
    ) -> UnifiedProtectionResult:
        """Perform unified protection analysis.

        Args:
            file_path: Path to file to analyze
            deep_scan: Perform deep analysis
            timeout: Analysis timeout in seconds

        Returns:
            Unified protection analysis result

        """
        import time

        start_time = time.time()

        # Check cache
        scan_options = f"deep_scan:{deep_scan},timeout:{timeout}"
        cached_result = self.cache.get(file_path, scan_options)
        if cached_result is not None:
            logger.debug(f"Using cached analysis for {file_path}")
            return cached_result

        # Initialize result
        result = UnifiedProtectionResult(
            file_path=file_path,
            file_type="Unknown",
            architecture="Unknown",
        )

        # Run analyses in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}

            # Submit protection analysis
            if self.protection_detector:
                futures["protection"] = executor.submit(
                    self._run_protection_analysis,
                    file_path,
                    deep_scan,
                )

            # Submit ICP analysis
            futures["icp"] = executor.submit(
                self._run_icp_analysis,
                file_path,
                deep_scan,
            )

            # Submit heuristic analysis
            if self.enable_heuristics:
                futures["heuristic"] = executor.submit(
                    self._run_heuristic_analysis,
                    file_path,
                )

            # Collect results with timeout
            for name, future in futures.items():
                try:
                    if name == "protection":
                        protection_result = future.result(timeout=timeout)
                        if protection_result:
                            result.protection_analysis = protection_result
                            result.engines_used.append("Protection Analysis")
                            self._merge_protection_results(result, protection_result)

                    elif name == "icp":
                        icp_result = future.result(timeout=timeout)
                        if icp_result and not icp_result.error:
                            result.icp_analysis = icp_result
                            result.engines_used.append("ICP Engine")
                            self._merge_icp_results(result, icp_result)

                    elif name == "heuristic":
                        heur_result = future.result(timeout=timeout // 3)
                        if heur_result:
                            result.engines_used.append("Heuristic")
                            self._merge_heuristic_results(result, heur_result)

                except concurrent.futures.TimeoutError:
                    logger.warning(f"{name} analysis timed out")
                except Exception as e:
                    logger.error(f"{name} analysis error: {e}")

        # Post-process and consolidate results
        self._consolidate_results(result)

        # Generate unified bypass strategies
        self._generate_bypass_strategies(result)

        # Calculate overall confidence
        self._calculate_confidence(result)

        # Set analysis time
        result.analysis_time = time.time() - start_time

        # Cache result
        self.cache.put(file_path, result, scan_options)

        return result

    def _run_protection_analysis(
        self, file_path: str, deep_scan: bool
    ) -> AdvancedProtectionAnalysis | None:
        """Run protection analysis."""
        try:
            scan_mode = ScanMode.DEEP if deep_scan else ScanMode.NORMAL
            return self.protection_detector.detect_protections_advanced(
                file_path,
                scan_mode=scan_mode,
                enable_heuristic=True,
                extract_strings=True,
            )
        except Exception as e:
            logger.error(f"Protection analysis error: {e}")
            return None

    def _run_heuristic_analysis(self, file_path: str) -> dict[str, Any] | None:
        """Run heuristic analysis."""
        try:
            heuristics = {}

            # File size heuristics
            file_size = os.path.getsize(file_path)
            if file_size < 10240:  # Less than 10KB
                heuristics["small_file"] = True
                heuristics["possible_dropper"] = True

            # Read file header
            header = None
            try:
                from ..ai.ai_file_tools import get_ai_file_tools

                ai_file_tools = get_ai_file_tools(getattr(self, "app_instance", None))
                file_data = ai_file_tools.read_file(
                    file_path,
                    purpose="Protection analysis - read file header for pattern detection",
                )
                if file_data.get("status") == "success" and file_data.get("content"):
                    content = file_data["content"]
                    if isinstance(content, str):
                        header = content.encode("latin-1", errors="ignore")[:1024]
                    else:
                        header = content[:1024]
            except (ImportError, AttributeError, KeyError):
                pass

            # Fallback to direct file reading if AIFileTools not available
            if header is None:
                with open(file_path, "rb") as f:
                    header = f.read(1024)

            # Check for suspicious patterns
            suspicious_patterns = [
                b"This program cannot be run in DOS mode",
                b"kernel32.dll",
                b"VirtualProtect",
                b"IsDebuggerPresent",
                b"GetTickCount",
                b"LoadLibrary",
                b"GetProcAddress",
            ]

            found_patterns = []
            for pattern in suspicious_patterns:
                if pattern in header:
                    found_patterns.append(pattern.decode("utf-8", errors="ignore"))

            if found_patterns:
                heuristics["suspicious_imports"] = found_patterns

            # Check for high entropy sections (possible packing)
            import math

            def calculate_entropy(data):
                if not data:
                    return 0
                entropy = 0
                for x in range(256):
                    p_x = data.count(x) / len(data)
                    if p_x > 0:
                        entropy += -p_x * math.log2(p_x)
                return entropy

            entropy = calculate_entropy(header)
            if entropy > 7.5:
                heuristics["high_entropy_header"] = True
                heuristics["likely_packed"] = True

            return heuristics

        except Exception as e:
            logger.error(f"Heuristic analysis error: {e}")
            return None

    def _merge_protection_results(
        self, result: UnifiedProtectionResult, protection_analysis: AdvancedProtectionAnalysis
    ):
        """Merge protection results into unified result."""
        result.file_type = protection_analysis.file_type
        result.architecture = protection_analysis.architecture
        result.is_packed = protection_analysis.is_packed
        result.is_protected = protection_analysis.is_protected

        # Convert detections to unified format
        for detection in protection_analysis.detections:
            protection = {
                "name": detection.name,
                "type": detection.type.value,
                "source": AnalysisSource.PROTECTION_ENGINE,
                "confidence": detection.confidence,
                "version": detection.version,
                "details": detection.details,
                "bypass_recommendations": detection.bypass_recommendations,
            }
            result.protections.append(protection)

        # Check for specific protection types
        for detection in protection_analysis.detections:
            if "debug" in detection.type.value.lower():
                result.has_anti_debug = True
            elif "vm" in detection.type.value.lower():
                result.has_anti_vm = True
            elif (
                "license" in detection.type.value.lower()
                or "dongle" in detection.type.value.lower()
            ):
                result.has_licensing = True

    def _merge_heuristic_results(self, result: UnifiedProtectionResult, heuristics: dict[str, Any]):
        """Merge heuristic results into unified result."""
        if heuristics.get("likely_packed"):
            result.is_packed = True
            protection = {
                "name": "Heuristic Packing Detection",
                "type": "packer",
                "source": AnalysisSource.HEURISTIC,
                "confidence": 70.0,
                "details": heuristics,
            }
            result.protections.append(protection)

        if heuristics.get("suspicious_imports"):
            result.has_anti_debug = True
            protection = {
                "name": "Suspicious API Usage",
                "type": "anti-analysis",
                "source": AnalysisSource.HEURISTIC,
                "confidence": 60.0,
                "details": {"apis": heuristics["suspicious_imports"]},
            }
            result.protections.append(protection)

    def _run_icp_analysis(self, file_path: str, deep_scan: bool) -> ICPScanResult | None:
        """Run ICP engine analysis."""
        try:
            # Convert scan mode
            icp_mode = ICPScanMode.DEEP if deep_scan else ICPScanMode.NORMAL

            # Run async analysis in sync context
            icp_backend = get_icp_backend()
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(
                    icp_backend.analyze_file(file_path, icp_mode),
                )
                return result
            finally:
                loop.close()
        except Exception as e:
            logger.error(f"ICP analysis error: {e}")
            return None

    def _merge_icp_results(self, result: UnifiedProtectionResult, icp_result: ICPScanResult):
        """Merge ICP engine results into unified result."""
        # Update file info if not already set
        if result.file_type == "Unknown" and icp_result.file_infos:
            result.file_type = icp_result.file_infos[0].filetype

        # Update packed/protected flags
        if icp_result.is_packed:
            result.is_packed = True
        if icp_result.is_protected:
            result.is_protected = True

        # Add detections
        for detection in icp_result.all_detections:
            # Map ICP types to our types
            protection_type = self._map_icp_type(detection.type)

            protection = {
                "name": detection.name,
                "type": protection_type,
                "source": AnalysisSource.SIGNATURE,
                "confidence": detection.confidence * 100,
                "version": detection.version,
                "details": {
                    "icp_type": detection.type,
                    "info": detection.info,
                    "string": detection.string,
                },
            }
            result.protections.append(protection)

            # Update feature flags based on type
            if protection_type == "anti-debug":
                result.has_anti_debug = True
            elif protection_type == "anti-vm":
                result.has_anti_vm = True
            elif protection_type == "license":
                result.has_licensing = True

    def _map_icp_type(self, icp_type: str) -> str:
        """Map ICP detection types to our unified types."""
        type_mapping = {
            "Packer": "packer",
            "Protector": "protector",
            "Cryptor": "cryptor",
            "Obfuscator": "obfuscator",
            "License": "license",
            "DRM": "drm",
            "Anti-Debug": "anti-debug",
            "Anti-Dump": "anti-dump",
            "Anti-VM": "anti-vm",
            "Dongle": "dongle",
            "Unknown": "unknown",
        }
        return type_mapping.get(icp_type, "unknown")

    def _consolidate_results(self, result: UnifiedProtectionResult):
        """Consolidate and deduplicate results from multiple sources."""
        # Group protections by name
        protection_groups = {}
        for protection in result.protections:
            name = protection["name"]
            if name not in protection_groups:
                protection_groups[name] = []
            protection_groups[name].append(protection)

        # Merge duplicate detections
        consolidated = []
        for name, group in protection_groups.items():
            if len(group) == 1:
                consolidated.append(group[0])
            else:
                # Merge multiple detections of same protection
                merged = {
                    "name": name,
                    "type": group[0]["type"],
                    "source": AnalysisSource.HYBRID,
                    "confidence": max(p["confidence"] for p in group),
                    "sources": [p["source"] for p in group],
                    "details": {},
                }

                # Merge bypass recommendations
                bypass_recs = []
                for p in group:
                    if "bypass_recommendations" in p:
                        bypass_recs.extend(p.get("bypass_recommendations", []))

                if bypass_recs:
                    merged["bypass_recommendations"] = list(set(bypass_recs))

                consolidated.append(merged)

        result.protections = consolidated

    def _generate_bypass_strategies(self, result: UnifiedProtectionResult):
        """Generate comprehensive bypass strategies."""
        strategies = []

        # Analyze protection combinations
        protection_types = set(p["type"] for p in result.protections)

        # Packer bypass strategies
        if "packer" in protection_types or result.is_packed:
            strategies.append(
                {
                    "name": "Dynamic Unpacking",
                    "description": "Use dynamic analysis to dump unpacked memory",
                    "tools": ["x64dbg", "ScyllaHide", "Process Dump"],
                    "difficulty": "Medium",
                    "steps": [
                        "Run in debugger with anti-anti-debug plugins",
                        "Set breakpoint at OEP (Original Entry Point)",
                        "Dump process memory after unpacking",
                        "Fix imports with Scylla",
                    ],
                }
            )

        # Anti-debug bypass strategies
        if result.has_anti_debug or "antidebug" in protection_types:
            strategies.append(
                {
                    "name": "Anti-Debug Bypass",
                    "description": "Bypass debugger detection mechanisms",
                    "tools": ["ScyllaHide", "TitanHide", "x64dbg plugins"],
                    "difficulty": "Medium",
                    "steps": [
                        "Enable ScyllaHide with all options",
                        "Use kernel-mode hiding if necessary",
                        "Patch IsDebuggerPresent checks",
                        "Handle timing-based detection",
                    ],
                }
            )

        # License/DRM bypass strategies
        if result.has_licensing or "license" in protection_types:
            strategies.append(
                {
                    "name": "License Validation Bypass",
                    "description": "Bypass license checking routines",
                    "tools": ["IDA Pro", "x64dbg", "API Monitor"],
                    "difficulty": "Hard",
                    "steps": [
                        "Trace license validation calls",
                        "Identify key decision points",
                        "Patch conditional jumps",
                        "Emulate valid license responses",
                    ],
                }
            )

        # Obfuscation strategies
        if result.is_obfuscated or "obfuscator" in protection_types:
            strategies.append(
                {
                    "name": "Deobfuscation",
                    "description": "Remove code obfuscation",
                    "tools": ["de4dot", "IDA Pro", "Custom scripts"],
                    "difficulty": "Hard",
                    "steps": [
                        "Identify obfuscation type",
                        "Use automated deobfuscators",
                        "Manual pattern analysis",
                        "Reconstruct control flow",
                    ],
                }
            )

        result.bypass_strategies = strategies

    def _calculate_confidence(self, result: UnifiedProtectionResult):
        """Calculate overall confidence score."""
        if not result.protections:
            result.confidence_score = 0.0
            return

        # Weight by source reliability
        source_weights = {
            AnalysisSource.PROTECTION_ENGINE: 0.9,
            AnalysisSource.HEURISTIC: 0.5,
            AnalysisSource.SIGNATURE: 0.8,
            AnalysisSource.HYBRID: 1.0,
        }

        total_weighted_confidence = 0.0
        total_weight = 0.0

        for protection in result.protections:
            source = protection.get("source", AnalysisSource.PROTECTION_ENGINE)
            weight = source_weights.get(source, 0.5)
            confidence = protection.get("confidence", 50.0)

            total_weighted_confidence += confidence * weight
            total_weight += weight

        if total_weight > 0:
            result.confidence_score = total_weighted_confidence / total_weight
        else:
            result.confidence_score = 0.0

    def get_quick_summary(self, file_path: str) -> dict[str, Any]:
        """Get quick protection summary without deep analysis."""
        # Try to get cached result first
        cached_result = self.cache.get(file_path, "deep_scan:False,timeout:60")
        if cached_result is None:
            cached_result = self.cache.get(file_path, "deep_scan:True,timeout:60")

        if cached_result is not None:
            return {
                "protected": bool(cached_result.protections),
                "protection_count": len(cached_result.protections),
                "main_protection": cached_result.protections[0]["name"]
                if cached_result.protections
                else None,
                "confidence": cached_result.confidence_score,
            }

        # Quick protection scan
        if self.protection_detector:
            try:
                analysis = self.protection_detector.detect_protections_advanced(
                    file_path,
                    scan_mode=ScanMode.NORMAL,
                    enable_heuristic=False,
                )

                return {
                    "protected": bool(analysis.detections),
                    "protection_count": len(analysis.detections),
                    "main_protection": analysis.detections[0].name if analysis.detections else None,
                    "confidence": 80.0,
                }
            except Exception as e:
                logger.debug(f"Quick protection scan failed: {e}")

        return {
            "protected": False,
            "protection_count": 0,
            "main_protection": None,
            "confidence": 0.0,
        }

    def analyze_file(
        self, file_path: str, deep_scan: bool = True, timeout: int = 60
    ) -> UnifiedProtectionResult:
        """Backward-compatible alias for analyze method.

        Args:
            file_path: Path to file to analyze
            deep_scan: Perform deep analysis
            timeout: Analysis timeout in seconds

        Returns:
            Unified protection analysis result

        """
        return self.analyze(file_path, deep_scan, timeout)

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return self.cache.get_cache_info()

    def clear_cache(self) -> None:
        """Clear all cached results."""
        self.cache.clear()
        logger.info("Analysis cache cleared")

    def cleanup_cache(self) -> int:
        """Clean up invalid cache entries.

        Returns:
            Number of entries removed

        """
        removed = self.cache.cleanup_invalid()
        logger.info(f"Cleaned up {removed} invalid cache entries")
        return removed

    def save_cache(self) -> None:
        """Manually save cache to disk."""
        self.cache.save_cache()

    def remove_from_cache(self, file_path: str) -> bool:
        """Remove specific file from cache.

        Args:
            file_path: Path to file to remove from cache

        Returns:
            True if removed, False if not found

        """
        removed = False
        # Try to remove both deep and shallow scan results
        removed |= self.cache.remove(file_path, "deep_scan:True,timeout:60")
        removed |= self.cache.remove(file_path, "deep_scan:False,timeout:60")

        if removed:
            logger.debug(f"Removed {file_path} from cache")

        return removed

    def invalidate_cache_for_file(self, file_path: str) -> None:
        """Invalidate cache entries for a specific file
        This is useful when a file has been modified.
        """
        self.remove_from_cache(file_path)

    def get_cache_size(self) -> tuple[int, float]:
        """Get cache size information.

        Returns:
            Tuple of (entry_count, size_in_mb)

        """
        stats = self.cache.get_stats()
        return stats.total_entries, stats.total_size_bytes / (1024 * 1024)


# Singleton instance for easy access
_unified_engine = None


def get_unified_engine() -> UnifiedProtectionEngine:
    """Get or create unified protection engine instance."""
    global _unified_engine
    if _unified_engine is None:
        _unified_engine = UnifiedProtectionEngine()
    return _unified_engine
