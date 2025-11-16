"""Denuvo Anti-Tamper Advanced Detection and Analysis Module.

This module provides sophisticated detection and analysis of Denuvo Anti-Tamper
protection across all major versions (4.x through 7.x+). It identifies obfuscated
implementations, VM-protected code, integrity checks, timing validations, and
activation triggers.

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

import math
import os
from dataclasses import dataclass
from typing import Any

from ..handlers.lief_handler import Binary
from ..utils.logger import get_logger

logger = get_logger(__name__)

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False
    logger.warning("LIEF not available, Denuvo analysis will be limited")

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logger.warning("Capstone not available, disassembly analysis disabled")


@dataclass
class DenuvoVersion:
    """Denuvo version information."""

    major: int
    minor: int
    name: str
    confidence: float


@dataclass
class DenuvoTrigger:
    """Denuvo activation trigger information."""

    address: int
    type: str
    function_name: str
    confidence: float
    description: str


@dataclass
class IntegrityCheck:
    """Integrity check routine information."""

    address: int
    type: str
    target: str
    algorithm: str
    confidence: float


@dataclass
class TimingCheck:
    """Timing check information."""

    address: int
    method: str
    threshold: int
    confidence: float


@dataclass
class VMRegion:
    """Virtual machine protected region."""

    start_address: int
    end_address: int
    entry_points: list[int]
    handler_count: int
    confidence: float


@dataclass
class DenuvoAnalysisResult:
    """Comprehensive Denuvo analysis results."""

    detected: bool
    confidence: float
    version: DenuvoVersion | None
    triggers: list[DenuvoTrigger]
    integrity_checks: list[IntegrityCheck]
    timing_checks: list[TimingCheck]
    vm_regions: list[VMRegion]
    encrypted_sections: list[dict[str, Any]]
    bypass_recommendations: list[str]
    analysis_details: dict[str, Any]


class DenuvoAnalyzer:
    """Advanced Denuvo Anti-Tamper detection and analysis engine."""

    DENUVO_V4_SIGNATURES = [
        b"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20\x48\x8B\xF9\xE8",
        b"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x48\x8D\x0D",
        b"\x48\x89\x4C\x24\x08\x48\x83\xEC\x38\x48\x8B\x44\x24\x40",
        b"\x4C\x8B\xDC\x49\x89\x5B\x08\x49\x89\x6B\x10\x49\x89\x73\x18\x57\x48\x83\xEC\x50",
    ]

    DENUVO_V5_SIGNATURES = [
        b"\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56",
        b"\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x6C\x24",
        b"\x48\x89\x54\x24\x10\x48\x89\x4C\x24\x08\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56",
        b"\xE8\x00\x00\x00\x00\x58\x48\x2D\x05\x00\x00\x00",
    ]

    DENUVO_V6_SIGNATURES = [
        b"\x48\x89\x5C\x24\x10\x48\x89\x74\x24\x18\x55\x57\x41\x56\x48\x8D\xAC\x24",
        b"\x4C\x8B\xD1\x48\x8D\x0D",
        b"\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x0F\x84",
        b"\x66\x0F\x1F\x44\x00\x00\x48\x8B\x01\xFF\x50",
    ]

    DENUVO_V7_SIGNATURES = [
        b"\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x30\x48\x8B\xF9\x48\x8D\x0D",
        b"\x40\x53\x48\x83\xEC\x30\x48\x8B\xD9\x48\x8B\x0D",
        b"\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x01\x48\x8D\x05",
        b"\x48\x89\x4C\x24\x08\x48\x83\xEC\x48\x48\x8B\x05",
    ]

    INTEGRITY_CHECK_PATTERNS = [
        b"\x0F\xB6\x04\x0F\x03\xC8\xC1\xC1",
        b"\x33\xC0\x85\xD2\x74\x00\x8A\x01\x03\xC8",
        b"\x8B\x44\x24\x04\x85\xC0\x74\x00\x56\x8B\x74\x24\x0C",
        b"\xF7\xD0\x23\xC1\x33\xC2\xC1\xC0",
    ]

    TIMING_CHECK_PATTERNS = [
        b"\x0F\x31\x48\x8B\xC8\x48\xC1\xE1\x20\x48\x0B\xC8",
        b"\x0F\x31\x89\x45\x00\x89\x55\x00",
        b"\xF3\x0F\x16\x05",
        b"\x65\x48\x8B\x04\x25\x30\x00\x00\x00\x8B\x80",
    ]

    VM_HANDLER_PATTERNS = [
        b"\xFF\x24\xC5",
        b"\x48\x8B\x04\xC8\xFF\xE0",
        b"\x41\xFF\x24\xC0",
        b"\x48\x8B\x84\xC1\x00\x00\x00\x00\xFF\xE0",
    ]

    TRIGGER_PATTERNS = [
        b"\xE8\x00\x00\x00\x00\x84\xC0\x0F\x84",
        b"\xE8\x00\x00\x00\x00\x85\xC0\x0F\x85",
        b"\xFF\x15\x00\x00\x00\x00\x84\xC0\x74",
        b"\xFF\x15\x00\x00\x00\x00\x85\xC0\x75",
    ]

    def __init__(self) -> None:
        """Initialize Denuvo analyzer."""
        self.md = None
        if CAPSTONE_AVAILABLE:
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.md.detail = True

    def analyze(self, binary_path: str) -> DenuvoAnalysisResult:
        """Perform comprehensive Denuvo analysis.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            DenuvoAnalysisResult with complete analysis

        """
        if not os.path.exists(binary_path):
            return self._create_negative_result("Binary file not found")

        if not LIEF_AVAILABLE:
            return self._analyze_without_lief(binary_path)

        try:
            binary = lief.parse(binary_path)
            if binary is None:
                return self._analyze_without_lief(binary_path)

            confidence_scores = []
            version = None
            triggers = []
            integrity_checks = []
            timing_checks = []
            vm_regions = []
            encrypted_sections = []
            analysis_details = {}

            version_result = self._detect_version(binary, binary_path)
            if version_result:
                version = version_result
                confidence_scores.append(version_result.confidence)
                analysis_details["version_detection"] = f"Detected {version_result.name}"

            encrypted_result = self._detect_encrypted_sections(binary)
            if encrypted_result:
                encrypted_sections = encrypted_result
                if encrypted_result:
                    confidence_scores.append(0.85)
                    analysis_details["encrypted_sections"] = len(encrypted_result)

            vm_result = self._detect_vm_regions(binary)
            if vm_result:
                vm_regions = vm_result
                if vm_result:
                    confidence_scores.append(0.80)
                    analysis_details["vm_regions"] = len(vm_result)

            integrity_result = self._detect_integrity_checks(binary)
            if integrity_result:
                integrity_checks = integrity_result
                if integrity_result:
                    confidence_scores.append(0.75)
                    analysis_details["integrity_checks"] = len(integrity_result)

            timing_result = self._detect_timing_checks(binary)
            if timing_result:
                timing_checks = timing_result
                if timing_result:
                    confidence_scores.append(0.70)
                    analysis_details["timing_checks"] = len(timing_result)

            trigger_result = self._detect_triggers(binary)
            if trigger_result:
                triggers = trigger_result
                if trigger_result:
                    confidence_scores.append(0.65)
                    analysis_details["triggers"] = len(trigger_result)

            if confidence_scores:
                overall_confidence = sum(confidence_scores) / len(confidence_scores)
                detected = overall_confidence >= 0.60
            else:
                overall_confidence = 0.0
                detected = False

            bypass_recommendations = self._generate_bypass_recommendations(
                version, triggers, integrity_checks, timing_checks, vm_regions,
            )

            return DenuvoAnalysisResult(
                detected=detected,
                confidence=overall_confidence,
                version=version,
                triggers=triggers,
                integrity_checks=integrity_checks,
                timing_checks=timing_checks,
                vm_regions=vm_regions,
                encrypted_sections=encrypted_sections,
                bypass_recommendations=bypass_recommendations,
                analysis_details=analysis_details,
            )

        except Exception as e:
            logger.error(f"Denuvo analysis failed: {e}")
            return self._create_negative_result(f"Analysis error: {e}")

    def _analyze_without_lief(self, binary_path: str) -> DenuvoAnalysisResult:
        """Perform basic analysis without LIEF.

        Args:
            binary_path: Path to binary

        Returns:
            Basic analysis result

        """
        try:
            with open(binary_path, "rb") as f:
                data = f.read()

            confidence_scores = []
            version = None

            for sig_list, ver_name in [
                (self.DENUVO_V7_SIGNATURES, "Denuvo 7.x+"),
                (self.DENUVO_V6_SIGNATURES, "Denuvo 6.x"),
                (self.DENUVO_V5_SIGNATURES, "Denuvo 5.x"),
                (self.DENUVO_V4_SIGNATURES, "Denuvo 4.x"),
            ]:
                for sig in sig_list:
                    if sig in data:
                        major = int(ver_name.split()[1].split('.')[0])
                        version = DenuvoVersion(
                            major=major,
                            minor=0,
                            name=ver_name,
                            confidence=0.75,
                        )
                        confidence_scores.append(0.75)
                        break
                if version:
                    break

            high_entropy_sections = self._detect_high_entropy_sections_raw(data)
            if high_entropy_sections > 0:
                confidence_scores.append(0.70)

            if confidence_scores:
                overall_confidence = sum(confidence_scores) / len(confidence_scores)
                detected = overall_confidence >= 0.60
            else:
                overall_confidence = 0.0
                detected = False

            return DenuvoAnalysisResult(
                detected=detected,
                confidence=overall_confidence,
                version=version,
                triggers=[],
                integrity_checks=[],
                timing_checks=[],
                vm_regions=[],
                encrypted_sections=[],
                bypass_recommendations=["LIEF library required for advanced analysis"],
                analysis_details={"mode": "basic", "lief_available": False},
            )

        except Exception as e:
            logger.error(f"Basic Denuvo analysis failed: {e}")
            return self._create_negative_result(f"Basic analysis error: {e}")

    def _detect_version(self, binary: Binary, binary_path: str) -> DenuvoVersion | None:
        """Detect Denuvo version from binary signatures.

        Args:
            binary: LIEF binary object
            binary_path: Path to binary for raw analysis

        Returns:
            DenuvoVersion or None if not detected

        """
        try:
            with open(binary_path, "rb") as f:
                data = f.read()

            version_checks = [
                (self.DENUVO_V7_SIGNATURES, 7, "Denuvo 7.x+", 0.90),
                (self.DENUVO_V6_SIGNATURES, 6, "Denuvo 6.x", 0.85),
                (self.DENUVO_V5_SIGNATURES, 5, "Denuvo 5.x", 0.80),
                (self.DENUVO_V4_SIGNATURES, 4, "Denuvo 4.x", 0.75),
            ]

            for signatures, major, name, base_confidence in version_checks:
                match_count = 0
                for sig in signatures:
                    if sig in data:
                        match_count += 1

                if match_count > 0:
                    confidence = base_confidence * (match_count / len(signatures))
                    if confidence >= 0.60:
                        return DenuvoVersion(
                            major=major,
                            minor=0,
                            name=name,
                            confidence=confidence,
                        )

            return None

        except Exception as e:
            logger.debug(f"Version detection failed: {e}")
            return None

    def _detect_encrypted_sections(self, binary: Binary) -> list[dict[str, Any]]:
        """Detect encrypted sections with high entropy.

        Args:
            binary: LIEF binary object

        Returns:
            List of encrypted section information

        """
        encrypted_sections = []

        try:
            for section in binary.sections:
                content = bytes(section.content)
                if len(content) < 256:
                    continue

                entropy = self._calculate_entropy(content)

                if entropy > 7.2:
                    encrypted_sections.append({
                        "name": section.name,
                        "virtual_address": section.virtual_address,
                        "size": section.size,
                        "entropy": entropy,
                        "characteristics": section.characteristics,
                    })

            return encrypted_sections

        except Exception as e:
            logger.debug(f"Encrypted section detection failed: {e}")
            return []

    def _detect_vm_regions(self, binary: Binary) -> list[VMRegion]:
        """Detect Denuvo VM-protected regions.

        Args:
            binary: LIEF binary object

        Returns:
            List of VM regions

        """
        vm_regions = []

        try:
            for section in binary.sections:
                if not (section.characteristics & 0x20000000):
                    continue

                content = bytes(section.content)
                if len(content) < 1024:
                    continue

                handler_matches = []
                for pattern in self.VM_HANDLER_PATTERNS:
                    offset = 0
                    while True:
                        pos = content.find(pattern, offset)
                        if pos == -1:
                            break
                        handler_matches.append(section.virtual_address + pos)
                        offset = pos + 1

                if len(handler_matches) >= 5:
                    entry_points = self._find_vm_entry_points(content, section.virtual_address)

                    confidence = min(0.95, 0.60 + (len(handler_matches) * 0.05))

                    vm_regions.append(VMRegion(
                        start_address=section.virtual_address,
                        end_address=section.virtual_address + section.size,
                        entry_points=entry_points,
                        handler_count=len(handler_matches),
                        confidence=confidence,
                    ))

            return vm_regions

        except Exception as e:
            logger.debug(f"VM region detection failed: {e}")
            return []

    def _detect_integrity_checks(self, binary: Binary) -> list[IntegrityCheck]:
        """Detect integrity check routines.

        Args:
            binary: LIEF binary object

        Returns:
            List of integrity checks

        """
        integrity_checks = []

        try:
            for section in binary.sections:
                if not (section.characteristics & 0x20000000):
                    continue

                content = bytes(section.content)

                for pattern in self.INTEGRITY_CHECK_PATTERNS:
                    offset = 0
                    while True:
                        pos = content.find(pattern, offset)
                        if pos == -1:
                            break

                        address = section.virtual_address + pos

                        check_type, algorithm = self._identify_integrity_algorithm(
                            content[pos:pos+50] if pos+50 < len(content) else content[pos:],
                        )

                        integrity_checks.append(IntegrityCheck(
                            address=address,
                            type=check_type,
                            target="code_section",
                            algorithm=algorithm,
                            confidence=0.75,
                        ))

                        offset = pos + 1

                        if len(integrity_checks) >= 100:
                            break

                if len(integrity_checks) >= 100:
                    break

            return integrity_checks

        except Exception as e:
            logger.debug(f"Integrity check detection failed: {e}")
            return []

    def _detect_timing_checks(self, binary: Binary) -> list[TimingCheck]:
        """Detect timing-based anti-debugging checks.

        Args:
            binary: LIEF binary object

        Returns:
            List of timing checks

        """
        timing_checks = []

        try:
            for section in binary.sections:
                if not (section.characteristics & 0x20000000):
                    continue

                content = bytes(section.content)

                for pattern in self.TIMING_CHECK_PATTERNS:
                    offset = 0
                    while True:
                        pos = content.find(pattern, offset)
                        if pos == -1:
                            break

                        address = section.virtual_address + pos

                        method = self._identify_timing_method(
                            content[pos:pos+30] if pos+30 < len(content) else content[pos:],
                        )

                        timing_checks.append(TimingCheck(
                            address=address,
                            method=method,
                            threshold=1000,
                            confidence=0.70,
                        ))

                        offset = pos + 1

                        if len(timing_checks) >= 50:
                            break

                if len(timing_checks) >= 50:
                    break

            return timing_checks

        except Exception as e:
            logger.debug(f"Timing check detection failed: {e}")
            return []

    def _detect_triggers(self, binary: Binary) -> list[DenuvoTrigger]:
        """Detect Denuvo activation triggers.

        Args:
            binary: LIEF binary object

        Returns:
            List of triggers

        """
        triggers = []

        try:
            for section in binary.sections:
                if not (section.characteristics & 0x20000000):
                    continue

                content = bytes(section.content)

                for pattern in self.TRIGGER_PATTERNS:
                    offset = 0
                    while True:
                        pos = content.find(pattern, offset)
                        if pos == -1:
                            break

                        address = section.virtual_address + pos

                        trigger_type, description = self._identify_trigger_type(
                            content[pos:pos+40] if pos+40 < len(content) else content[pos:],
                        )

                        triggers.append(DenuvoTrigger(
                            address=address,
                            type=trigger_type,
                            function_name=f"trigger_{address:x}",
                            confidence=0.65,
                            description=description,
                        ))

                        offset = pos + 1

                        if len(triggers) >= 30:
                            break

                if len(triggers) >= 30:
                    break

            return triggers

        except Exception as e:
            logger.debug(f"Trigger detection failed: {e}")
            return []

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data.

        Args:
            data: Bytes to analyze

        Returns:
            Entropy value (0.0 to 8.0)

        """
        if not data:
            return 0.0

        entropy = 0.0
        byte_counts = [0] * 256

        for byte in data:
            byte_counts[byte] += 1

        data_len = len(data)
        for count in byte_counts:
            if count == 0:
                continue
            probability = count / data_len
            entropy -= probability * math.log2(probability)

        return entropy

    def _find_vm_entry_points(self, content: bytes, base_address: int) -> list[int]:
        """Find VM entry points in section.

        Args:
            content: Section content
            base_address: Section base address

        Returns:
            List of entry point addresses

        """
        entry_points = []

        entry_patterns = [
            b"\xE8\x00\x00\x00\x00\x58\x48\x2D",
            b"\x48\x8D\x0D\x00\x00\x00\x00\xE8",
            b"\xFF\x15\x00\x00\x00\x00\x48\x8B",
        ]

        for pattern in entry_patterns:
            offset = 0
            while True:
                pos = content.find(pattern, offset)
                if pos == -1:
                    break
                entry_points.append(base_address + pos)
                offset = pos + 1

                if len(entry_points) >= 20:
                    return entry_points

        return entry_points

    def _identify_integrity_algorithm(self, code: bytes) -> tuple[str, str]:
        """Identify integrity check algorithm from code.

        Args:
            code: Code bytes to analyze

        Returns:
            Tuple of (check_type, algorithm)

        """
        if b"\x03\xC8\xC1\xC1" in code:
            return ("hash_check", "CRC32")
        if b"\x33\xC0\x85\xD2" in code:
            return ("hash_check", "custom_hash")
        if b"\xF7\xD0\x23\xC1" in code:
            return ("hash_check", "checksum")
        return ("integrity_check", "unknown")

    def _identify_timing_method(self, code: bytes) -> str:
        """Identify timing check method from code.

        Args:
            code: Code bytes to analyze

        Returns:
            Timing method name

        """
        if b"\x0F\x31" in code:
            return "RDTSC"
        if b"\xF3\x0F\x16" in code:
            return "QueryPerformanceCounter"
        if b"\x65\x48\x8B\x04\x25\x30" in code:
            return "PEB_timing"
        return "unknown_timing"

    def _identify_trigger_type(self, code: bytes) -> tuple[str, str]:
        """Identify trigger type from code.

        Args:
            code: Code bytes to analyze

        Returns:
            Tuple of (trigger_type, description)

        """
        if b"\xE8\x00\x00\x00\x00\x84\xC0\x0F\x84" in code:
            return ("validation_trigger", "License validation check")
        if b"\xE8\x00\x00\x00\x00\x85\xC0\x0F\x85" in code:
            return ("activation_trigger", "Activation verification")
        if b"\xFF\x15\x00\x00\x00\x00\x84\xC0\x74" in code:
            return ("api_trigger", "API validation call")
        return ("generic_trigger", "Generic protection trigger")

    def _detect_high_entropy_sections_raw(self, data: bytes) -> int:
        """Detect high entropy sections in raw binary data.

        Args:
            data: Raw binary data

        Returns:
            Count of high entropy sections

        """
        section_size = 4096
        high_entropy_count = 0

        for i in range(0, len(data), section_size):
            chunk = data[i:i+section_size]
            if len(chunk) < 256:
                continue

            entropy = self._calculate_entropy(chunk)
            if entropy > 7.2:
                high_entropy_count += 1

        return high_entropy_count

    def _generate_bypass_recommendations(
        self,
        version: DenuvoVersion | None,
        triggers: list[DenuvoTrigger],
        integrity_checks: list[IntegrityCheck],
        timing_checks: list[TimingCheck],
        vm_regions: list[VMRegion],
    ) -> list[str]:
        """Generate bypass recommendations based on analysis.

        Args:
            version: Detected Denuvo version
            triggers: Detected triggers
            integrity_checks: Detected integrity checks
            timing_checks: Detected timing checks
            vm_regions: Detected VM regions

        Returns:
            List of bypass recommendations

        """
        recommendations = []

        if version:
            if version.major >= 7:
                recommendations.append(
                    "Denuvo 7.x+ detected - Consider VM devirtualization approach",
                )
                recommendations.append(
                    "Use Scylla Hide or similar anti-anti-debugging tools",
                )
            elif version.major >= 5:
                recommendations.append(
                    "Denuvo 5.x/6.x detected - Focus on trigger point analysis",
                )
                recommendations.append(
                    "Monitor activation server communication for offline bypass",
                )
            else:
                recommendations.append(
                    "Denuvo 4.x detected - Older version, more susceptible to patching",
                )

        if triggers:
            recommendations.append(
                f"Found {len(triggers)} activation triggers - NOP or bypass recommended",
            )
            recommendations.append(
                "Use Frida or similar hooking framework to intercept triggers",
            )

        if integrity_checks:
            recommendations.append(
                f"Found {len(integrity_checks)} integrity checks - Patch or hook hash functions",
            )
            recommendations.append(
                "Consider memory dumping after integrity checks complete",
            )

        if timing_checks:
            recommendations.append(
                f"Found {len(timing_checks)} timing checks - Hook RDTSC and timing APIs",
            )
            recommendations.append(
                "Use ScyllaHide RDTSC feature or manual timing manipulation",
            )

        if vm_regions:
            recommendations.append(
                f"Found {len(vm_regions)} VM-protected regions - Devirtualization required",
            )
            recommendations.append(
                "Consider VMProtect devirtualization tools adapted for Denuvo",
            )

        if not recommendations:
            recommendations.append(
                "Advanced analysis required - Consider manual reversing with IDA/Ghidra",
            )

        return recommendations

    def _create_negative_result(self, reason: str) -> DenuvoAnalysisResult:
        """Create negative analysis result.

        Args:
            reason: Reason for negative result

        Returns:
            Negative DenuvoAnalysisResult

        """
        return DenuvoAnalysisResult(
            detected=False,
            confidence=0.0,
            version=None,
            triggers=[],
            integrity_checks=[],
            timing_checks=[],
            vm_regions=[],
            encrypted_sections=[],
            bypass_recommendations=[],
            analysis_details={"error": reason},
        )
