"""Streaming YARA Scanner for Large Binary Analysis.

Production-ready YARA scanning with chunk-based processing for multi-GB executables.
Efficiently scans large binaries without loading entire file into memory.

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

import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from intellicrack.core.processing.streaming_analysis_manager import (
    ChunkContext,
    StreamingAnalysisManager,
    StreamingAnalyzer,
    StreamingProgress,
)


logger = logging.getLogger(__name__)


@dataclass
class StreamingYaraMatch:
    """Represents a YARA match found during streaming analysis.

    Attributes:
        rule_name: Name of the YARA rule that matched
        namespace: YARA rule namespace if defined
        offset: Byte offset in binary where match occurred
        matched_data: Hex string of matched data (truncated to 100 chars)
        string_identifier: YARA string identifier (e.g., $s1, $regex1)
        tags: List of YARA rule tags (protection, licensing, crypto, etc.)
        meta: Dictionary of rule metadata from YARA definition

    """

    rule_name: str
    namespace: str
    offset: int
    matched_data: str
    string_identifier: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


class StreamingYaraScanner(StreamingAnalyzer):
    """Streaming YARA scanner for memory-efficient analysis of large binaries.

    Scans multi-GB binaries with YARA rules without loading entire file into
    memory. Detects licensing protection patterns, encryption signatures,
    cryptographic routines, and anti-analysis mechanisms relevant to software
    protection systems.
    """

    def __init__(
        self,
        rules_path: Path | None = None,
        rules_source: str | None = None,
        max_matches_per_rule: int = 1000,
    ) -> None:
        """Initialize streaming YARA scanner.

        Args:
            rules_path: Path to YARA rules file (optional)
            rules_source: YARA rules as string (alternative to rules_path)
            max_matches_per_rule: Maximum matches to collect per rule (default 1000)

        Raises:
            ImportError: If yara-python module is not installed

        """
        if not YARA_AVAILABLE:
            raise ImportError("YARA is not available. Install with: pip install yara-python")

        self.rules_path: Path | None = rules_path
        self.rules_source: str | None = rules_source
        self.max_matches_per_rule: int = max_matches_per_rule
        self.rules: Any = None
        self.match_offsets: set[int] = set()
        self.rule_match_counts: dict[str, int] = defaultdict(int)

    def initialize_analysis(self, file_path: Path) -> None:
        """Initialize YARA rules before scanning begins.

        Loads YARA rules from file, source string, or defaults. Compiles rules
        into YARA rule object for efficient matching during streaming analysis.

        Args:
            file_path: Path to binary being analyzed

        Raises:
            Exception: If YARA rule compilation fails

        """
        try:
            if self.rules_source:
                self.rules = yara.compile(source=self.rules_source)
                logger.info("Compiled YARA rules from source string")
            elif self.rules_path and self.rules_path.exists():
                self.rules = yara.compile(filepath=str(self.rules_path))
                logger.info("Compiled YARA rules from: %s", self.rules_path)
            else:
                default_rules = self._get_default_rules()
                self.rules = yara.compile(source=default_rules)
                logger.info("Using default licensing protection YARA rules")

            self.match_offsets = set()
            self.rule_match_counts = defaultdict(int)

        except Exception as e:
            logger.exception("Failed to compile YARA rules: %s", e)
            raise

    def analyze_chunk(self, context: ChunkContext) -> dict[str, Any]:
        """Scan a single chunk with YARA rules.

        Matches data in chunk against compiled YARA rules. Handles overlapping
        regions between chunks to avoid missing matches that span chunk
        boundaries. Deduplicates matches and enforces per-rule limits.

        Args:
            context: Chunk context containing data, offset, and overlap regions

        Returns:
            Dictionary with chunk offset, size, matches found, and error status

        """
        try:
            if not self.rules:
                return {
                    "chunk_offset": context.offset,
                    "matches": [],
                    "error": "YARA rules not loaded",
                }

            search_data = context.overlap_before + context.data + context.overlap_after
            effective_offset = context.offset - len(context.overlap_before)

            matches = self.rules.match(data=search_data)

            chunk_matches = []

            for match in matches:
                if self.rule_match_counts[match.rule] >= self.max_matches_per_rule:
                    continue

                for string_match in match.strings:
                    for instance in string_match.instances:
                        actual_offset = effective_offset + instance.offset

                        if actual_offset < context.offset or actual_offset >= context.offset + context.size:
                            continue

                        if actual_offset in self.match_offsets:
                            continue

                        self.match_offsets.add(actual_offset)
                        self.rule_match_counts[match.rule] += 1

                        chunk_matches.append(
                            {
                                "rule": match.rule,
                                "namespace": match.namespace,
                                "offset": actual_offset,
                                "matched_data": instance.matched_data.hex()[:100],
                                "string_identifier": string_match.identifier,
                                "tags": match.tags,
                                "meta": match.meta,
                            },
                        )

            logger.debug(
                "Chunk %d/%d: Found %d YARA matches",
                context.chunk_number,
                context.total_chunks,
                len(chunk_matches),
            )

            return {
                "chunk_offset": context.offset,
                "chunk_size": context.size,
                "matches": chunk_matches,
                "rules_matched": len({m["rule"] for m in chunk_matches}),
            }

        except Exception as e:
            logger.exception("Error scanning chunk at offset 0x%08x: %s", context.offset, e)
            return {
                "chunk_offset": context.offset,
                "chunk_size": context.size,
                "error": str(e),
                "matches": [],
            }

    def merge_results(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Merge YARA matches from all chunks.

        Aggregates matches across all chunks, eliminates duplicates, calculates
        rule distribution, and computes coverage statistics for the scan.

        Args:
            results: List of partial results from each chunk

        Returns:
            Merged dictionary with total matches, rule distribution, and coverage

        """
        try:
            all_matches = []
            rules_matched: set[str] = set()
            chunks_with_matches = 0
            errors = []

            for chunk_result in results:
                if "error" in chunk_result:
                    errors.append(
                        f"Chunk at 0x{chunk_result.get('chunk_offset', 0):08x}: {chunk_result['error']}",
                    )
                    continue

                if matches := chunk_result.get("matches", []):
                    chunks_with_matches += 1
                    all_matches.extend(matches)
                    rules_matched.update(m["rule"] for m in matches)

            all_matches.sort(key=lambda m: m.get("offset", 0))

            rule_distribution: dict[str, int] = defaultdict(int)
            for match in all_matches:
                rule_distribution[match["rule"]] += 1

            top_rules = sorted(rule_distribution.items(), key=lambda x: x[1], reverse=True)[:10]

            merged = {
                "total_matches": len(all_matches),
                "unique_rules_matched": len(rules_matched),
                "matches": all_matches,
                "rule_distribution": [{"rule": rule, "count": count} for rule, count in top_rules],
                "chunks_with_matches": chunks_with_matches,
                "total_chunks": len(results),
                "coverage": round((chunks_with_matches / len(results)) * 100, 2) if results else 0,
            }

            if errors:
                merged["errors"] = errors

            logger.info(
                "Merged %d chunk results: %d total matches for %d unique rules",
                len(results),
                len(all_matches),
                len(rules_matched),
            )

            return merged

        except Exception as e:
            logger.exception("Error merging YARA results: %s", e)
            return {"error": str(e), "total_matches": 0, "matches": []}

    def finalize_analysis(self, merged_results: dict[str, Any]) -> dict[str, Any]:
        """Finalize YARA analysis with categorization and insights.

        Categorizes matches into protection, licensing, cryptographic, and
        anti-analysis types based on rule tags and names. Generates summary
        for user consumption.

        Args:
            merged_results: Merged results from all chunks

        Returns:
            Final analysis results with categorized matches and summary

        """
        try:
            matches = merged_results.get("matches", [])

            protection_matches = []
            license_matches = []
            crypto_matches = []
            anti_analysis_matches = []

            for match in matches:
                tags = match.get("tags", [])
                rule = match.get("rule", "").lower()

                if any(tag in ["protection", "protector", "packer"] for tag in tags):
                    protection_matches.append(match)
                elif any(tag in ["license", "licensing", "registration"] for tag in tags):
                    license_matches.append(match)
                elif any(tag in ["crypto", "cryptography", "encryption"] for tag in tags):
                    crypto_matches.append(match)
                elif any(tag in ["anti_debug", "anti_vm", "anti_analysis"] for tag in tags):
                    anti_analysis_matches.append(match)

                if ("license" in rule or "serial" in rule or "activation" in rule) and match not in license_matches:
                    license_matches.append(match)

            merged_results |= {
                "categorized_matches": {
                    "protection": protection_matches,
                    "licensing": license_matches,
                    "cryptographic": crypto_matches,
                    "anti_analysis": anti_analysis_matches,
                },
                "licensing_protection_detected": len(license_matches) > 0,
                "summary": self._generate_summary(merged_results, license_matches),
            }

            logger.info(
                "Finalized YARA analysis: %d licensing matches, %d protection matches",
                len(license_matches),
                len(protection_matches),
            )

            return merged_results

        except Exception as e:
            logger.exception("Error finalizing YARA analysis: %s", e)
            merged_results["finalization_error"] = str(e)
            return merged_results

    def _generate_summary(self, results: dict[str, Any], license_matches: list[dict[str, Any]]) -> str:
        """Generate human-readable summary of YARA scan results.

        Composes narrative describing detected patterns including licensing,
        protection, and cryptographic signatures. Highlights most common rules.

        Args:
            results: Merged scan results dictionary
            license_matches: List of licensing-related matches from analysis

        Returns:
            Human-readable summary string with key findings

        """
        total = results.get("total_matches", 0)
        unique_rules = results.get("unique_rules_matched", 0)

        summary = f"Found {total} total matches across {unique_rules} YARA rules. "

        if license_matches:
            summary += f"Detected {len(license_matches)} licensing-related patterns. "

        if dist := results.get("rule_distribution", []):
            top_rule = dist[0]
            summary += f"Most common rule: {top_rule['rule']} ({top_rule['count']} matches). "

        return summary

    def _get_default_rules(self) -> str:
        """Get default YARA rules for licensing protection detection.

        Provides built-in rules for detecting common software protection
        mechanisms including FlexLM, HASP, Denuvo, VMProtect, Themida,
        RSA keys, and license validation functions.

        Returns:
            YARA rule definitions as string

        """
        return """
rule License_String_Pattern {
    meta:
        description = "Detects common license validation strings"
        category = "licensing"
    strings:
        $s1 = "license" nocase
        $s2 = "serial" nocase
        $s3 = "activation" nocase
        $s4 = "registration" nocase
        $s5 = "product key" nocase
        $s6 = "trial" nocase
    condition:
        any of ($s*)
}

rule RSA_Public_Key {
    meta:
        description = "Detects RSA public key structures"
        category = "crypto"
    strings:
        $rsa1 = { 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 }
        $rsa2 = { 30 81 89 02 81 81 00 }
        $rsa3 = { 30 82 02 22 30 0D }
    condition:
        any of them
}

rule VMProtect_Detection {
    meta:
        description = "Detects VMProtect protection"
        category = "protection"
    strings:
        $vmp1 = "VMProtect" ascii
        $vmp2 = ".vmp0" ascii
        $vmp3 = ".vmp1" ascii
        $vmp4 = { 68 00 00 00 00 E8 }
    condition:
        any of them
}

rule Themida_Detection {
    meta:
        description = "Detects Themida protection"
        category = "protection"
    strings:
        $themida1 = "Themida" ascii
        $themida2 = ".themida" ascii
        $themida3 = { B8 00 00 00 00 60 0B C0 74 58 }
    condition:
        any of them
}

rule Denuvo_Detection {
    meta:
        description = "Detects Denuvo protection"
        category = "protection"
    strings:
        $denuvo1 = "Denuvo" ascii
        $denuvo2 = ".denu" ascii
        $denuvo3 = "denuvo32.dll" ascii
        $denuvo4 = "denuvo64.dll" ascii
    condition:
        any of them
}

rule FlexLM_License {
    meta:
        description = "Detects FlexLM licensing"
        category = "licensing"
    strings:
        $flex1 = "FlexNet" ascii
        $flex2 = "FLEXlm" ascii
        $flex3 = "FLEXLM_DIAGNOSTICS" ascii
        $flex4 = { 46 4C 45 58 4C 4D }
    condition:
        any of them
}

rule HASP_Dongle {
    meta:
        description = "Detects HASP dongle protection"
        category = "licensing"
    strings:
        $hasp1 = "HASP" ascii
        $hasp2 = "Sentinel" ascii
        $hasp3 = "aksusb" ascii
        $hasp4 = "hardlock" ascii
    condition:
        any of them
}

rule License_Check_Function {
    meta:
        description = "Detects potential license validation functions"
        category = "licensing"
    strings:
        $func1 = "CheckLicense" ascii
        $func2 = "ValidateLicense" ascii
        $func3 = "VerifySerial" ascii
        $func4 = "IsLicensed" ascii
        $func5 = "GetLicenseInfo" ascii
    condition:
        any of them
}
"""


def scan_binary_streaming(
    binary_path: Path,
    rules_path: Path | None = None,
    rules_source: str | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    """Perform streaming YARA scan on large binary.

    Scans large binary files with YARA rules for licensing protection,
    encryption, packing, and anti-analysis patterns without loading entire
    file into memory. Supports custom rules or default licensing detection.

    Args:
        binary_path: Path to binary file to scan
        rules_path: Optional path to YARA rules file
        rules_source: Optional YARA rules as string
        progress_callback: Optional callback function for progress updates
            taking (current: int, total: int) parameters

    Returns:
        Complete YARA scan results including matches, categorization, coverage,
        and summary of detected protection patterns

    Raises:
        Exception: If file not found or scanning encounters errors

    """
    try:
        binary_path = Path(binary_path)

        if not binary_path.exists():
            return {"error": f"File not found: {binary_path}", "status": "failed"}

        scanner = StreamingYaraScanner(rules_path=rules_path, rules_source=rules_source)

        manager = StreamingAnalysisManager()

        if progress_callback:

            def wrapper(progress: StreamingProgress) -> None:
                progress_callback(progress.bytes_processed, progress.total_bytes)

            manager.register_progress_callback(wrapper)

        return manager.analyze_streaming(binary_path, scanner)
    except Exception as e:
        logger.exception("Streaming YARA scan failed: %s", e)
        return {"error": str(e), "status": "failed"}
