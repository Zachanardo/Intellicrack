"""Unified Protection Analysis Engine.

Seamlessly integrates protection detection and custom analysis into a single unified interface.

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
# pylint: disable=cyclic-import

from __future__ import annotations

import asyncio
import bz2
import concurrent.futures
import math
import os
import zlib
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import numpy as np

try:
    import lzma

    HAS_LZMA = True
except ImportError:
    HAS_LZMA = False
    lzma = None


from ..utils.logger import get_logger
from .analysis_cache import AnalysisCache, get_analysis_cache

if TYPE_CHECKING:
    from .icp_backend import ICPScanResult
    from .intellicrack_protection_advanced import (
        AdvancedProtectionAnalysis,
    )

logger = get_logger(__name__)

if not HAS_LZMA:
    logger.warning("LZMA module not available - using zlib compression fallback")


def _get_advanced_protection() -> type[AdvancedProtectionAnalysis]:
    """Get the IntellicrackAdvancedProtection class.

    Returns:
        The IntellicrackAdvancedProtection class type for lazy loading.

    """
    from .intellicrack_protection_advanced import IntellicrackAdvancedProtection

    return IntellicrackAdvancedProtection


def _get_scan_mode() -> object:
    """Get the ScanMode enum from protection analysis module.

    Returns:
        The ScanMode enum type for lazy loading.

    """
    from .intellicrack_protection_advanced import ScanMode

    return ScanMode


def _get_icp_scan_mode() -> object:
    """Get the ScanMode enum from ICP backend module.

    Returns:
        The ICP ScanMode enum type for lazy loading.

    """
    from .icp_backend import ScanMode as ICPScanMode

    return ICPScanMode


def _get_icp_backend_func() -> object:
    """Get the get_icp_backend function from ICP backend module.

    Returns:
        The get_icp_backend function for lazy loading.

    """
    from .icp_backend import get_icp_backend

    return get_icp_backend


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
    ) -> None:
        """Initialize unified protection engine.

        Args:
            enable_protection: Enable protection analysis
            enable_heuristics: Enable heuristic analysis
            cache_config: Cache configuration options

        """
        self.enable_protection = enable_protection
        self.enable_heuristics = enable_heuristics

        # Initialize engines
        self.protection_detector = _get_advanced_protection()() if enable_protection else None

        # Initialize advanced cache
        if cache_config:
            self.cache = AnalysisCache(**cache_config)
        else:
            self.cache = get_analysis_cache()

    def analyze(self, file_path: str, deep_scan: bool = True, timeout: int = 60) -> UnifiedProtectionResult:
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

    def _run_protection_analysis(self, file_path: str, deep_scan: bool) -> AdvancedProtectionAnalysis | None:
        """Run protection analysis."""
        try:
            ScanMode = _get_scan_mode()
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

            # Advanced entropy analysis with multiple techniques
            entropy_results = self._perform_advanced_entropy_analysis(header)

            # Determine if packed based on multiple factors
            packing_indicators = 0

            if entropy_results["shannon_entropy"] > 7.5:
                packing_indicators += 2
                heuristics["high_shannon_entropy"] = entropy_results["shannon_entropy"]

            if entropy_results["sliding_window_max"] > 7.8:
                packing_indicators += 2
                heuristics["sliding_window_peak"] = entropy_results["sliding_window_max"]

            if entropy_results["kolmogorov_complexity"] > 0.85:
                packing_indicators += 1
                heuristics["high_kolmogorov"] = entropy_results["kolmogorov_complexity"]

            if entropy_results["best_compression_ratio"] < 0.15:
                packing_indicators += 2
                heuristics["highly_compressible"] = entropy_results["best_compression_ratio"]

            if not entropy_results["chi_square_random"]:
                packing_indicators += 1
                heuristics["chi_square_pvalue"] = entropy_results["chi_square_pvalue"]

            # Multi-factor decision
            if packing_indicators >= 4:
                heuristics["likely_packed"] = True
                heuristics["packing_confidence"] = min(100, packing_indicators * 15)
                heuristics["entropy_analysis"] = entropy_results

            return heuristics

        except Exception as e:
            logger.error(f"Heuristic analysis error: {e}")
            return None

    def _merge_protection_results(self, result: UnifiedProtectionResult, protection_analysis: AdvancedProtectionAnalysis) -> None:
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
            elif "license" in detection.type.value.lower() or "dongle" in detection.type.value.lower():
                result.has_licensing = True

    def _merge_heuristic_results(self, result: UnifiedProtectionResult, heuristics: dict[str, Any]) -> None:
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
            ICPScanMode = _get_icp_scan_mode()
            icp_mode = ICPScanMode.DEEP if deep_scan else ICPScanMode.NORMAL

            get_icp_backend = _get_icp_backend_func()
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

    def _merge_icp_results(self, result: UnifiedProtectionResult, icp_result: ICPScanResult) -> None:
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

    def _consolidate_results(self, result: UnifiedProtectionResult) -> None:
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

    def _generate_bypass_strategies(self, result: UnifiedProtectionResult) -> None:
        """Generate comprehensive bypass strategies."""
        strategies = []

        # Analyze protection combinations
        protection_types = {p["type"] for p in result.protections}

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
                },
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
                },
            )

        # License/DRM bypass strategies
        if result.has_licensing or "license" in protection_types:
            strategies.append(
                {
                    "name": "License Validation Bypass",
                    "description": "Bypass license checking routines",
                    "tools": ["Ghidra", "x64dbg", "API Monitor"],
                    "difficulty": "Hard",
                    "steps": [
                        "Trace license validation calls",
                        "Identify key decision points",
                        "Patch conditional jumps",
                        "Emulate valid license responses",
                    ],
                },
            )

        # Obfuscation strategies
        if result.is_obfuscated or "obfuscator" in protection_types:
            strategies.append(
                {
                    "name": "Deobfuscation",
                    "description": "Remove code obfuscation",
                    "tools": ["de4dot", "Ghidra", "Custom scripts"],
                    "difficulty": "Hard",
                    "steps": [
                        "Identify obfuscation type",
                        "Use automated deobfuscators",
                        "Manual pattern analysis",
                        "Reconstruct control flow",
                    ],
                },
            )

        result.bypass_strategies = strategies

    def _calculate_confidence(self, result: UnifiedProtectionResult) -> None:
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
                "main_protection": cached_result.protections[0]["name"] if cached_result.protections else None,
                "confidence": cached_result.confidence_score,
            }

        # Quick protection scan
        if self.protection_detector:
            try:
                ScanMode = _get_scan_mode()
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

    def analyze_file(self, file_path: str, deep_scan: bool = True, timeout: int = 60) -> UnifiedProtectionResult:
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
        """Invalidate cache entries for a specific file.

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

    def _perform_advanced_entropy_analysis(self, data: bytes) -> dict[str, Any]:
        """Perform comprehensive entropy analysis using multiple techniques.

        Args:
            data: Binary data to analyze

        Returns:
            Dictionary containing results from multiple entropy analysis methods

        """
        results = {
            "shannon_entropy": self._calculate_shannon_entropy(data),
            "sliding_window_analysis": {},
            "kolmogorov_complexity": 0.0,
            "compression_ratios": {},
            "chi_square_random": False,
            "chi_square_pvalue": 1.0,
            "byte_distribution": {},
            "entropy_variance": 0.0,
        }

        # Sliding window entropy analysis
        window_entropies = self._sliding_window_entropy(data)
        if window_entropies:
            results["sliding_window_max"] = max(window_entropies)
            results["sliding_window_min"] = min(window_entropies)
            results["sliding_window_avg"] = sum(window_entropies) / len(window_entropies)
            results["sliding_window_std"] = np.std(window_entropies) if len(window_entropies) > 1 else 0
            results["entropy_variance"] = np.var(window_entropies) if len(window_entropies) > 1 else 0

        # Kolmogorov complexity estimation via compression
        results["kolmogorov_complexity"] = self._estimate_kolmogorov_complexity(data)

        # Compression ratio analysis
        results["compression_ratios"] = self._analyze_compression_ratios(data)
        results["best_compression_ratio"] = min(results["compression_ratios"].values()) if results["compression_ratios"] else 1.0

        # Chi-square randomness test
        chi_result = self._chi_square_test(data)
        results["chi_square_random"] = chi_result["is_random"]
        results["chi_square_pvalue"] = chi_result["p_value"]
        results["chi_square_statistic"] = chi_result["statistic"]

        # Byte frequency distribution analysis
        results["byte_distribution"] = self._analyze_byte_distribution(data)

        return results

    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data.

        Args:
            data: Binary data to analyze

        Returns:
            Shannon entropy value (0-8 bits)

        """
        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts = Counter(data)
        data_len = len(data)

        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def _sliding_window_entropy(self, data: bytes, window_size: int = 256, step_size: int = 128) -> list[float]:
        """Calculate entropy using sliding window technique.

        Args:
            data: Binary data to analyze
            window_size: Size of sliding window
            step_size: Step size for window movement

        Returns:
            List of entropy values for each window position

        """
        if len(data) < window_size:
            return [self._calculate_shannon_entropy(data)]

        entropies = []
        for i in range(0, len(data) - window_size + 1, step_size):
            window_data = data[i : i + window_size]
            entropy = self._calculate_shannon_entropy(window_data)
            entropies.append(entropy)

        return entropies

    def _estimate_kolmogorov_complexity(self, data: bytes) -> float:
        """Estimate Kolmogorov complexity using compression ratio.

        Args:
            data: Binary data to analyze

        Returns:
            Estimated complexity (0-1, higher means more complex/random)

        """
        if not data:
            return 0.0

        try:
            if HAS_LZMA:
                compressed = lzma.compress(data, preset=9)
                complexity = len(compressed) / len(data)
                return min(1.0, complexity)
            compressed = zlib.compress(data, level=9)
            complexity = len(compressed) / len(data)
            return min(1.0, complexity)
        except Exception:
            try:
                compressed = zlib.compress(data, level=9)
                complexity = len(compressed) / len(data)
                return min(1.0, complexity)
            except Exception:
                return 1.0

    def _analyze_compression_ratios(self, data: bytes) -> dict[str, float]:
        """Analyze compression ratios using multiple algorithms.

        Args:
            data: Binary data to analyze

        Returns:
            Dictionary of compression algorithm names to compression ratios

        """
        if not data:
            return {}

        original_size = len(data)
        ratios = {}

        compression_methods = [
            ("zlib", lambda d: zlib.compress(d, level=9)),
            ("gzip", lambda d: zlib.compress(d, level=9)),
            ("bz2", lambda d: bz2.compress(d, compresslevel=9)),
        ]

        if HAS_LZMA:
            compression_methods.append(("lzma", lambda d: lzma.compress(d, preset=9)))

        for name, compress_func in compression_methods:
            try:
                compressed = compress_func(data)
                ratio = len(compressed) / original_size
                ratios[name] = ratio
            except Exception:
                ratios[name] = 1.0

        return ratios

    def _chi_square_test(self, data: bytes, significance_level: float = 0.05) -> dict[str, Any]:
        """Perform chi-square test for randomness.

        Args:
            data: Binary data to analyze
            significance_level: Significance level for hypothesis testing

        Returns:
            Dictionary containing test results

        """
        if not data:
            return {"is_random": False, "p_value": 1.0, "statistic": 0.0}

        # Expected frequency for uniform distribution
        expected_freq = len(data) / 256

        # Count observed frequencies
        observed = Counter(data)

        # Calculate chi-square statistic
        chi_square = 0.0
        for byte_val in range(256):
            observed_freq = observed.get(byte_val, 0)
            chi_square += ((observed_freq - expected_freq) ** 2) / expected_freq

        # Degrees of freedom = 256 - 1 = 255
        degrees_of_freedom = 255

        # Critical value for significance level (approximation)
        # For df=255 and alpha=0.05, critical value ≈ 293
        critical_value = 293

        # Simple p-value approximation
        # For large df, chi-square distribution approaches normal
        mean = degrees_of_freedom
        std_dev = math.sqrt(2 * degrees_of_freedom)
        z_score = (chi_square - mean) / std_dev

        # Approximate p-value using normal distribution
        # This is a simplified calculation
        if z_score > 3:
            p_value = 0.001
        elif z_score > 2:
            p_value = 0.05
        elif z_score > 1:
            p_value = 0.16
        else:
            p_value = 0.5

        is_random = chi_square < critical_value

        return {
            "is_random": is_random,
            "p_value": p_value,
            "statistic": chi_square,
            "critical_value": critical_value,
            "degrees_of_freedom": degrees_of_freedom,
        }

    def _analyze_byte_distribution(self, data: bytes) -> dict[str, Any]:
        """Analyze byte value distribution characteristics.

        Args:
            data: Binary data to analyze

        Returns:
            Dictionary containing distribution statistics

        """
        if not data:
            return {}

        byte_counts = Counter(data)

        # Calculate distribution statistics
        frequencies = list(byte_counts.values())
        unique_bytes = len(byte_counts)

        # Calculate uniformity score (0-1, 1 = perfectly uniform)
        expected_freq = len(data) / 256
        deviations = [abs(byte_counts.get(i, 0) - expected_freq) for i in range(256)]
        max_deviation = max(deviations)
        uniformity = 1 - (max_deviation / expected_freq) if expected_freq > 0 else 0

        # Find most and least common bytes
        most_common = byte_counts.most_common(5)
        least_common_bytes = [b for b in range(256) if byte_counts.get(b, 0) == 0]

        return {
            "unique_bytes": unique_bytes,
            "uniformity_score": max(0, min(1, uniformity)),
            "most_common_bytes": [(byte, count / len(data)) for byte, count in most_common],
            "zero_frequency_bytes": len(least_common_bytes),
            "byte_coverage": unique_bytes / 256,
            "frequency_variance": np.var(frequencies) if frequencies else 0,
        }


# Singleton instance for easy access
_unified_engine = None


def get_unified_engine() -> UnifiedProtectionEngine:
    """Get or create unified protection engine instance."""
    global _unified_engine
    if _unified_engine is None:
        _unified_engine = UnifiedProtectionEngine()
    return _unified_engine
