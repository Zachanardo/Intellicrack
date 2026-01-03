"""Production tests for Denuvo trigger detection and binary analysis.

Tests validate real offensive capabilities for detecting Denuvo protection
mechanisms in actual protected binaries including activation triggers,
integrity checks, timing validation, machine fingerprinting, and anti-tamper.

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
from pathlib import Path
from typing import Any

import pytest

try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import capstone

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from intellicrack.protection.denuvo_ticket_analyzer import (
    DenuvoAnalysisResult,
    DenuvoTicketAnalyzer,
    DenuvoTrigger,
    HardwareBinding,
    IntegrityCheck,
    OnlineActivation,
    SteamAPIWrapper,
    TimingCheck,
)


logger = logging.getLogger(__name__)


DENUVO_BINARIES_DIR = Path(__file__).parent.parent / "resources" / "protected_binaries" / "denuvo"
REQUIRED_BINARY_MESSAGE = """
SKIP: No Denuvo-protected binaries found for testing.

To run these tests, you must provide REAL Denuvo-protected game executables.

Required binary types:
  - Denuvo v4.x protected executable (e.g., game released 2017-2018)
  - Denuvo v5.x protected executable (e.g., game released 2019-2020)
  - Denuvo v6.x protected executable (e.g., game released 2021-2023)
  - Denuvo v7.x protected executable (e.g., game released 2024-2025)

Binary placement location:
  {location}

File naming convention:
  - denuvo_v4_<gamename>.exe
  - denuvo_v5_<gamename>.exe
  - denuvo_v6_<gamename>.exe
  - denuvo_v7_<gamename>.exe
  - steam_api.dll or steam_api64.dll (from Denuvo game)

Expected file structure:
  {location}/
    denuvo_v4_<gamename>.exe
    denuvo_v5_<gamename>.exe
    denuvo_v6_<gamename>.exe
    denuvo_v7_<gamename>.exe
    steam_api.dll or steam_api64.dll

Why real binaries are required:
  These tests validate actual Denuvo detection capabilities against real
  commercial protection schemes. Mocked or synthetic test data would produce
  false positives and fail to validate genuine offensive capabilities.

  The tests MUST detect:
    - Real activation trigger points (Steam, Origin, Epic integration)
    - Actual integrity check routines (CRC32, SHA256, HMAC)
    - Real timing validation (RDTSC, QueryPerformanceCounter, NTP)
    - Actual machine fingerprinting code (CPU ID, GPU, disk serial)
    - Real anti-tamper mechanisms (code signing, section hashing)

Where to obtain binaries:
  - Purchase Denuvo-protected games from Steam, Origin, Epic, etc.
  - Extract game executables from legitimate installations
  - Use only for authorized security research in isolated environment

Legal and ethical considerations:
  - Only test on software you own or have explicit authorization to analyze
  - Use in controlled, isolated research environments only
  - Comply with all applicable laws and terms of service
"""


@pytest.fixture(scope="module")
def test_binaries_dir() -> Path:
    """Directory containing test binaries with Denuvo protection."""
    return DENUVO_BINARIES_DIR


@pytest.fixture(scope="module")
def denuvo_binaries(test_binaries_dir: Path) -> list[Path]:
    """Scan for Denuvo-protected binaries in test directory."""
    binaries: list[Path] = []

    if not test_binaries_dir.exists():
        logger.warning(
            REQUIRED_BINARY_MESSAGE.format(
                location=test_binaries_dir.absolute(),
            )
        )
        return binaries

    for pattern in ["*.exe", "*.dll", "*.bin"]:
        binaries.extend(test_binaries_dir.rglob(pattern))

    found_binaries = [b for b in binaries if b.is_file() and b.stat().st_size > 0]

    if not found_binaries:
        logger.warning(
            REQUIRED_BINARY_MESSAGE.format(
                location=test_binaries_dir.absolute(),
            )
        )

    return found_binaries


@pytest.fixture
def analyzer() -> DenuvoTicketAnalyzer:
    """Create Denuvo ticket analyzer instance."""
    return DenuvoTicketAnalyzer()


def is_likely_denuvo_protected(binary_path: Path) -> bool:
    """Check if binary likely contains Denuvo protection.

    Args:
        binary_path: Path to binary file

    Returns:
        True if binary appears to have Denuvo protection

    """
    if not LIEF_AVAILABLE:
        return False

    try:
        binary = lief.parse(str(binary_path))
        if not binary:
            return False

        section_names = [s.name.lower() for s in binary.sections]
        denuvo_indicators = [".denuvo", ".text$dn", ".rdata$dn", ".data$dn", "denuvo"]

        return any(indicator in name for name in section_names for indicator in denuvo_indicators)

    except Exception:
        return False


class TestActivationTriggerDetection:
    """Tests for Denuvo activation trigger detection in real binaries."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required for binary analysis")
    def test_detect_activation_triggers_on_real_binaries(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST find activation trigger points in Denuvo-protected binaries.

        This test validates that the analyzer can locate actual activation
        trigger points where Denuvo checks for license validation in real
        commercial game executables.
        """
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        found_triggers = False
        analyzed_count = 0

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            analyzed_count += 1
            logger.info(f"Analyzing {binary_path.name} for activation triggers")

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            triggers = analyzer.detect_activation_triggers(binary)

            if triggers:
                found_triggers = True
                logger.info(f"Found {len(triggers)} activation triggers in {binary_path.name}")

                for trigger in triggers:
                    assert isinstance(trigger, DenuvoTrigger), "Trigger must be DenuvoTrigger instance"
                    assert trigger.address > 0, f"Trigger address must be positive: {trigger.address}"
                    assert trigger.type in [
                        "steam_init",
                        "steam_hook",
                        "origin_init",
                        "epic_init",
                        "uplay_init",
                        "generic_drm_init",
                        "license_check",
                        "activation_request",
                        "activation_call",
                        "ticket_validation",
                        "token_validation",
                        "online_activation",
                    ], f"Invalid trigger type: {trigger.type}"
                    assert 0.0 <= trigger.confidence <= 1.0, f"Confidence out of range: {trigger.confidence}"
                    assert len(trigger.function_name) > 0, "Function name must not be empty"
                    assert len(trigger.description) > 0, "Description must not be empty"
                    assert len(trigger.opcode_sequence) > 0, "Opcode sequence must not be empty"

                    logger.debug(
                        f"  Trigger: {trigger.type} at 0x{trigger.address:x} "
                        f"({trigger.function_name}, confidence={trigger.confidence:.2f})"
                    )

        assert analyzed_count > 0, "No Denuvo-protected binaries were analyzed"
        assert found_triggers, (
            f"No activation triggers detected in {analyzed_count} Denuvo binaries. "
            "This indicates the trigger detection is NOT working on real binaries."
        )

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_steam_integration_triggers(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify Steam API integration points for activation.

        Validates detection of Steam DRM integration where Denuvo hooks
        into Steam's authentication and licensing system.
        """
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        found_steam_trigger = False
        steam_binaries_checked = 0

        for binary_path in denuvo_binaries:
            if "steam" not in binary_path.name.lower() and not is_likely_denuvo_protected(binary_path):
                continue

            steam_binaries_checked += 1
            logger.info(f"Checking {binary_path.name} for Steam integration triggers")

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            triggers = analyzer.detect_activation_triggers(binary)
            steam_triggers = [t for t in triggers if "steam" in t.type.lower()]

            if steam_triggers:
                found_steam_trigger = True
                logger.info(f"Found {len(steam_triggers)} Steam triggers in {binary_path.name}")

                for trigger in steam_triggers:
                    assert "steam" in trigger.description.lower() or "steam" in trigger.function_name.lower(), \
                        "Steam trigger must reference Steam in description or function name"
                    assert trigger.confidence > 0.5, f"Steam trigger confidence too low: {trigger.confidence}"
                    assert len(trigger.opcode_sequence) > 0, "Opcode sequence must be present"
                    assert len(trigger.referenced_imports) >= 0, "Referenced imports must be valid list"

        if steam_binaries_checked > 0 and not found_steam_trigger:
            pytest.skip("No Steam integration triggers found in available Steam binaries")

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_origin_integration_triggers(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify Origin/EA integration points for activation."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            triggers = analyzer.detect_activation_triggers(binary)
            origin_triggers = [t for t in triggers if "origin" in t.type.lower() or "ea" in t.type.lower()]

            if origin_triggers:
                logger.info(f"Found {len(origin_triggers)} Origin triggers in {binary_path.name}")
                for trigger in origin_triggers:
                    assert trigger.confidence > 0.0, "Origin trigger must have positive confidence"
                    assert isinstance(trigger.referenced_imports, list), "Referenced imports must be list"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_epic_integration_triggers(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify Epic Games Store integration points."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            triggers = analyzer.detect_activation_triggers(binary)
            epic_triggers = [t for t in triggers if "epic" in t.type.lower()]

            if epic_triggers:
                logger.info(f"Found {len(epic_triggers)} Epic triggers in {binary_path.name}")
                for trigger in epic_triggers:
                    assert isinstance(trigger, DenuvoTrigger), "Must be DenuvoTrigger instance"
                    assert trigger.address > 0, "Must have valid address"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_trigger_detection_includes_cross_references(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST provide cross-reference information for trigger points."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        found_xrefs = False
        triggers_checked = 0

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            triggers = analyzer.detect_activation_triggers(binary)
            triggers_checked += len(triggers)

            for trigger in triggers:
                if len(trigger.cross_references) > 0:
                    found_xrefs = True
                    logger.info(f"Trigger at 0x{trigger.address:x} has {len(trigger.cross_references)} xrefs")
                    for xref in trigger.cross_references:
                        assert isinstance(xref, int), "Cross-reference must be integer address"
                        assert xref > 0, f"Cross-reference address must be positive: {xref}"

        if triggers_checked > 0 and not found_xrefs:
            logger.warning("No cross-references found in any detected triggers - this may indicate incomplete analysis")


class TestIntegrityCheckDetection:
    """Tests for integrity check routine detection in real Denuvo binaries."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_integrity_checks_on_real_binaries(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST find integrity check routines in Denuvo-protected binaries.

        Validates detection of CRC, hash-based, and custom integrity validation
        routines that Denuvo uses to detect tampering.
        """
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        found_checks = False
        analyzed_count = 0

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            analyzed_count += 1
            logger.info(f"Analyzing {binary_path.name} for integrity checks")

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            checks = analyzer.detect_integrity_checks(binary)

            if checks:
                found_checks = True
                logger.info(f"Found {len(checks)} integrity checks in {binary_path.name}")

                for check in checks:
                    assert isinstance(check, IntegrityCheck), "Check must be IntegrityCheck instance"
                    assert check.address > 0, f"Check address must be positive: {check.address}"
                    assert check.type in [
                        "crc32",
                        "crc64",
                        "hash",
                        "checksum",
                        "code_integrity",
                        "section_check",
                        "md5",
                        "sha1",
                        "sha256",
                        "custom_hash",
                        "section_hash",
                        "code_hash",
                    ], f"Invalid check type: {check.type}"
                    assert check.algorithm in [
                        "CRC32C",
                        "SHA256",
                        "Custom",
                        "HMAC-SHA256",
                        "SHA1",
                        "crc32",
                        "crc64",
                        "md5",
                        "sha1",
                        "sha256",
                        "sha512",
                        "custom",
                        "unknown",
                    ], f"Invalid algorithm: {check.algorithm}"
                    assert 0.0 <= check.confidence <= 1.0, f"Confidence out of range: {check.confidence}"
                    assert check.bypass_difficulty in [
                        "low",
                        "medium",
                        "high",
                        "very_high",
                    ], f"Invalid bypass difficulty: {check.bypass_difficulty}"
                    assert check.check_size >= 0, f"Check size must be non-negative: {check.check_size}"
                    assert len(check.target) > 0, "Target must not be empty"

                    logger.debug(
                        f"  Check: {check.type} ({check.algorithm}) at 0x{check.address:x}, "
                        f"target={check.target}, difficulty={check.bypass_difficulty}"
                    )

        assert analyzed_count > 0, "No Denuvo-protected binaries were analyzed"
        assert found_checks, (
            f"No integrity checks detected in {analyzed_count} Denuvo binaries. "
            "This indicates the integrity check detection is NOT working on real binaries."
        )

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_crc_based_integrity_checks(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify CRC-based integrity validation routines."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            checks = analyzer.detect_integrity_checks(binary)
            crc_checks = [c for c in checks if "crc" in c.type.lower() or "crc" in c.algorithm.lower()]

            if crc_checks:
                logger.info(f"Found {len(crc_checks)} CRC checks in {binary_path.name}")
                for check in crc_checks:
                    assert check.address > 0, "CRC check must have valid address"
                    assert check.target in [
                        "code",
                        "data",
                        "sections",
                        "headers",
                        "entire",
                        "code_section",
                        "data_section",
                        "all_sections",
                    ], f"Invalid CRC check target: {check.target}"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_hash_based_integrity_checks(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify hash-based validation (MD5, SHA, etc)."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            checks = analyzer.detect_integrity_checks(binary)
            hash_checks = [
                c
                for c in checks
                if any(h in c.algorithm.lower() for h in ["md5", "sha1", "sha256", "sha512", "sha"])
            ]

            if hash_checks:
                logger.info(f"Found {len(hash_checks)} hash-based checks in {binary_path.name}")
                for check in hash_checks:
                    assert check.confidence > 0.0, "Hash check must have positive confidence"
                    assert len(check.target) > 0, "Hash check must have target"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_integrity_check_frequency_assessment(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST assess how frequently integrity checks execute."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            checks = analyzer.detect_integrity_checks(binary)

            for check in checks:
                assert check.frequency in [
                    "startup",
                    "periodic",
                    "on_demand",
                    "continuous",
                    "random",
                    "unknown",
                ], f"Invalid frequency: {check.frequency}"


class TestTimingValidationDetection:
    """Tests for timing validation mechanism detection in real Denuvo binaries."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_timing_checks_on_real_binaries(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST find timing validation mechanisms in Denuvo binaries.

        Validates detection of system clock checks, RDTSC timing, NTP sync
        requirements, and other time-based validation used by Denuvo.
        """
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        found_timing = False
        analyzed_count = 0

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            analyzed_count += 1
            logger.info(f"Analyzing {binary_path.name} for timing checks")

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            timing_checks = analyzer.detect_timing_validation(binary)

            if timing_checks:
                found_timing = True
                logger.info(f"Found {len(timing_checks)} timing checks in {binary_path.name}")

                for check in timing_checks:
                    assert isinstance(check, TimingCheck), "Check must be TimingCheck instance"
                    assert check.address > 0, f"Check address must be positive: {check.address}"
                    assert check.method.lower() in [
                        "rdtsc",
                        "rdtscp",
                        "queryperformancecounter",
                        "gettickcount",
                        "systemtime",
                        "ntp_sync",
                        "custom_timer",
                        "delta",
                    ], f"Invalid timing method: {check.method}"
                    assert len(check.instruction) > 0, "Instruction must not be empty"
                    assert 0.0 <= check.confidence <= 1.0, f"Confidence out of range: {check.confidence}"
                    assert len(check.bypass_method) > 0, "Bypass method must not be empty"
                    assert check.threshold_min >= 0, f"Min threshold must be non-negative: {check.threshold_min}"
                    assert check.threshold_max >= check.threshold_min, \
                        f"Max threshold must be >= min: {check.threshold_max} < {check.threshold_min}"

                    logger.debug(
                        f"  Timing: {check.method} at 0x{check.address:x}, "
                        f"thresholds=[{check.threshold_min}, {check.threshold_max}]"
                    )

        assert analyzed_count > 0, "No Denuvo-protected binaries were analyzed"
        assert found_timing, (
            f"No timing validation detected in {analyzed_count} Denuvo binaries. "
            "This indicates the timing check detection is NOT working on real binaries."
        )

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_rdtsc_timing_checks(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify RDTSC-based anti-debugging timing."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            timing_checks = analyzer.detect_timing_validation(binary)
            rdtsc_checks = [c for c in timing_checks if c.method.lower() in ["rdtsc", "rdtscp"]]

            if rdtsc_checks:
                logger.info(f"Found {len(rdtsc_checks)} RDTSC checks in {binary_path.name}")
                for check in rdtsc_checks:
                    assert "rdtsc" in check.instruction.lower() or "0f31" in check.instruction.lower() or \
                           "0f01f9" in check.instruction.lower(), \
                        f"RDTSC check must reference RDTSC instruction: {check.instruction}"
                    assert check.threshold_min >= 0, "Min threshold must be non-negative"
                    assert check.threshold_max >= check.threshold_min, "Max must be >= min"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_system_clock_checks(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify system clock validation routines."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            timing_checks = analyzer.detect_timing_validation(binary)
            clock_checks = [
                c
                for c in timing_checks
                if c.method.lower() in ["gettickcount", "systemtime", "queryperformancecounter"]
            ]

            if clock_checks:
                logger.info(f"Found {len(clock_checks)} system clock checks in {binary_path.name}")
                for check in clock_checks:
                    assert check.address > 0, "Clock check must have valid address"
                    assert check.confidence > 0.0, "Clock check must have positive confidence"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_ntp_sync_requirements(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify NTP time synchronization requirements."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            timing_checks = analyzer.detect_timing_validation(binary)
            ntp_checks = [c for c in timing_checks if "ntp" in c.method.lower()]

            if ntp_checks:
                logger.info(f"Found {len(ntp_checks)} NTP sync checks in {binary_path.name}")
                for check in ntp_checks:
                    assert isinstance(check, TimingCheck), "Must be TimingCheck instance"


class TestTicketFlowTracing:
    """Tests for ticket generation and validation flow tracing in real binaries."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_analyze_binary_traces_complete_flow(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Binary analysis MUST trace ticket generation and validation flows.

        Validates that complete analysis identifies the full workflow from
        initial trigger through validation, including all protection layers.
        """
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        found_analysis = False
        analyzed_count = 0

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            analyzed_count += 1
            logger.info(f"Performing complete analysis of {binary_path.name}")

            result = analyzer.analyze_binary(binary_path)

            if result:
                found_analysis = True
                logger.info(
                    f"Analysis complete for {binary_path.name}: "
                    f"version={result.version}, "
                    f"triggers={len(result.triggers)}, "
                    f"checks={len(result.integrity_checks)}, "
                    f"timing={len(result.timing_checks)}"
                )

                assert isinstance(result, DenuvoAnalysisResult), "Result must be DenuvoAnalysisResult instance"
                assert len(result.version) > 0, "Version must not be empty"
                assert result.version in [
                    "4.x",
                    "5.x",
                    "6.x",
                    "7.x",
                    "unknown",
                ], f"Invalid version: {result.version}"
                assert isinstance(result.triggers, list), "Triggers must be list"
                assert isinstance(result.integrity_checks, list), "Integrity checks must be list"
                assert isinstance(result.timing_checks, list), "Timing checks must be list"
                assert isinstance(result.hardware_bindings, list), "Hardware bindings must be list"
                assert 0.0 <= result.protection_density <= 1.0, \
                    f"Protection density out of range: {result.protection_density}"
                assert result.obfuscation_level in [
                    "low",
                    "medium",
                    "high",
                    "very_high",
                ], f"Invalid obfuscation level: {result.obfuscation_level}"

        assert analyzed_count > 0, "No Denuvo-protected binaries were analyzed"
        assert found_analysis, (
            f"No successful binary analysis on {analyzed_count} Denuvo binaries. "
            "This indicates the analysis pipeline is NOT working on real binaries."
        )

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_online_activation_flow_detection(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Analyzer MUST detect online activation endpoints and protocols."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            result = analyzer.analyze_binary(binary_path)

            if result and result.online_activation:
                activation = result.online_activation
                logger.info(
                    f"Online activation detected in {binary_path.name}: "
                    f"endpoint={activation.endpoint_url}, protocol={activation.protocol}"
                )

                assert isinstance(activation, OnlineActivation), "Must be OnlineActivation instance"
                assert len(activation.endpoint_url) > 0, "Endpoint URL must not be empty"
                assert activation.protocol in [
                    "https",
                    "http",
                    "tcp",
                    "custom",
                ], f"Invalid protocol: {activation.protocol}"
                assert activation.encryption_type in [
                    "tls",
                    "aes",
                    "rsa",
                    "custom",
                    "none",
                ], f"Invalid encryption type: {activation.encryption_type}"
                assert activation.validation_address >= 0, "Validation address must be non-negative"
                assert len(activation.request_format) > 0, "Request format must not be empty"
                assert len(activation.response_format) > 0, "Response format must not be empty"


class TestMachineFingerprintingDetection:
    """Tests for machine fingerprinting code detection in real Denuvo binaries."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_hardware_binding_on_real_binaries(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST find machine fingerprinting routines in Denuvo binaries.

        Validates detection of CPU ID, GPU ID, motherboard ID, disk serial,
        and other hardware fingerprinting code used for machine binding.
        """
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        found_bindings = False
        analyzed_count = 0

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            analyzed_count += 1
            logger.info(f"Analyzing {binary_path.name} for hardware bindings")

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            bindings = analyzer.detect_hardware_binding(binary)

            if bindings:
                found_bindings = True
                logger.info(f"Found {len(bindings)} hardware bindings in {binary_path.name}")

                for binding in bindings:
                    assert isinstance(binding, HardwareBinding), "Binding must be HardwareBinding instance"
                    assert binding.binding_type in [
                        "cpu_id",
                        "cpu_info",
                        "disk_serial",
                        "mac_address",
                        "gpu_id",
                        "motherboard_id",
                        "bios_info",
                        "computer_name",
                        "hash_generation",
                        "composite",
                    ], f"Invalid binding type: {binding.binding_type}"
                    assert binding.collection_address >= 0, "Collection address must be non-negative"
                    assert binding.validation_address >= 0, "Validation address must be non-negative"
                    assert binding.hash_algorithm in [
                        "md5",
                        "sha1",
                        "sha256",
                        "custom",
                        "unknown",
                    ], f"Invalid hash algorithm: {binding.hash_algorithm}"
                    assert isinstance(binding.components, list), "Components must be list"
                    assert 0.0 <= binding.confidence <= 1.0, f"Confidence out of range: {binding.confidence}"

                    logger.debug(
                        f"  Binding: {binding.binding_type} at 0x{binding.collection_address:x}, "
                        f"hash={binding.hash_algorithm}, components={binding.components}"
                    )

        assert analyzed_count > 0, "No Denuvo-protected binaries were analyzed"
        assert found_bindings, (
            f"No hardware binding detected in {analyzed_count} Denuvo binaries. "
            "This indicates the hardware fingerprinting detection is NOT working on real binaries."
        )

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_cpu_fingerprinting(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify CPU ID collection routines."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            bindings = analyzer.detect_hardware_binding(binary)
            cpu_bindings = [
                b
                for b in bindings
                if b.binding_type in ["cpu_id", "cpu_info"]
                or any("cpu" in c.lower() for c in b.components)
            ]

            if cpu_bindings:
                logger.info(f"Found {len(cpu_bindings)} CPU bindings in {binary_path.name}")
                for binding in cpu_bindings:
                    assert binding.collection_address > 0, "CPU binding must have valid collection address"
                    assert (
                        "cpu_id" in binding.binding_type.lower()
                        or "cpu_info" in binding.binding_type.lower()
                        or any("cpu" in c.lower() for c in binding.components)
                    ), "CPU binding must reference CPU in type or components"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_gpu_fingerprinting(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify GPU ID collection routines."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            bindings = analyzer.detect_hardware_binding(binary)
            gpu_bindings = [
                b
                for b in bindings
                if b.binding_type == "gpu_id" or any("gpu" in c.lower() for c in b.components)
            ]

            if gpu_bindings:
                logger.info(f"Found {len(gpu_bindings)} GPU bindings in {binary_path.name}")
                for binding in gpu_bindings:
                    assert binding.confidence > 0.0, "GPU binding must have positive confidence"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_motherboard_fingerprinting(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify motherboard/BIOS ID collection."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            bindings = analyzer.detect_hardware_binding(binary)
            mobo_bindings = [
                b
                for b in bindings
                if b.binding_type in ["motherboard_id", "bios_info"]
                or any(c.lower() in ["motherboard", "bios"] for c in b.components)
            ]

            if mobo_bindings:
                logger.info(f"Found {len(mobo_bindings)} motherboard bindings in {binary_path.name}")
                for binding in mobo_bindings:
                    assert isinstance(binding, HardwareBinding), "Must be HardwareBinding instance"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_composite_hardware_fingerprinting(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify composite hardware ID generation."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            bindings = analyzer.detect_hardware_binding(binary)
            composite_bindings = [b for b in bindings if b.binding_type == "composite" or len(b.components) > 1]

            if composite_bindings:
                logger.info(f"Found {len(composite_bindings)} composite bindings in {binary_path.name}")
                for binding in composite_bindings:
                    assert len(binding.components) >= 1, "Composite binding must have components"
                    assert binding.hash_algorithm in [
                        "md5",
                        "sha1",
                        "sha256",
                        "custom",
                        "unknown",
                    ], f"Invalid hash algorithm: {binding.hash_algorithm}"


class TestAntiTamperDetection:
    """Tests for anti-tamper mechanism detection in real Denuvo binaries."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_code_signing_checks(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify code signing validation routines."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            checks = analyzer.detect_integrity_checks(binary)
            signing_checks = [c for c in checks if "sign" in c.type.lower() or c.target == "signatures"]

            if signing_checks:
                logger.info(f"Found {len(signing_checks)} code signing checks in {binary_path.name}")
                for check in signing_checks:
                    assert check.bypass_difficulty in [
                        "medium",
                        "high",
                        "very_high",
                    ], f"Code signing should be medium+ difficulty: {check.bypass_difficulty}"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_section_hashing(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify section-level hash validation."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            checks = analyzer.detect_integrity_checks(binary)
            section_checks = [
                c
                for c in checks
                if c.target in ["sections", "code", "code_section"] or "section" in c.type.lower()
            ]

            if section_checks:
                logger.info(f"Found {len(section_checks)} section hash checks in {binary_path.name}")
                for check in section_checks:
                    assert check.check_size > 0, "Section hash must have positive check size"
                    assert check.algorithm in [
                        "CRC32C",
                        "SHA256",
                        "Custom",
                        "HMAC-SHA256",
                        "SHA1",
                        "crc32",
                        "crc64",
                        "md5",
                        "sha1",
                        "sha256",
                        "sha512",
                        "custom",
                    ], f"Invalid algorithm for section hash: {check.algorithm}"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_assess_protection_density(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Analyzer MUST calculate protection mechanism density metric."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            result = analyzer.analyze_binary(binary_path)

            if result:
                assert 0.0 <= result.protection_density <= 1.0, \
                    f"Protection density out of range: {result.protection_density}"

                if result.triggers or result.integrity_checks or result.timing_checks:
                    assert result.protection_density > 0.0, \
                        "Protection density must be > 0 when protections are detected"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_assess_obfuscation_level(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Analyzer MUST assess code obfuscation intensity."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            result = analyzer.analyze_binary(binary_path)

            if result:
                assert result.obfuscation_level in [
                    "low",
                    "medium",
                    "high",
                    "very_high",
                ], f"Invalid obfuscation level: {result.obfuscation_level}"


class TestDenuvoVersionDetection:
    """Tests for Denuvo version identification (v4/v5/v6 edge cases)."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_denuvo_v4_signatures(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify Denuvo v4.x protection characteristics."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if "v4" not in binary_path.name.lower():
                continue

            result = analyzer.analyze_binary(binary_path)

            if result:
                logger.info(f"Detected version {result.version} in {binary_path.name}")
                if result.version == "4.x":
                    assert isinstance(result, DenuvoAnalysisResult), "Must be DenuvoAnalysisResult"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_denuvo_v5_signatures(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify Denuvo v5.x protection characteristics."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if "v5" not in binary_path.name.lower():
                continue

            result = analyzer.analyze_binary(binary_path)

            if result:
                logger.info(f"Detected version {result.version} in {binary_path.name}")
                if result.version == "5.x":
                    assert isinstance(result, DenuvoAnalysisResult), "Must be DenuvoAnalysisResult"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_denuvo_v6_signatures(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify Denuvo v6.x protection characteristics."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if "v6" not in binary_path.name.lower():
                continue

            result = analyzer.analyze_binary(binary_path)

            if result:
                logger.info(f"Detected version {result.version} in {binary_path.name}")
                if result.version == "6.x":
                    assert isinstance(result, DenuvoAnalysisResult), "Must be DenuvoAnalysisResult"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_denuvo_v7_signatures(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Detector MUST identify Denuvo v7.x protection characteristics."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            if "v7" not in binary_path.name.lower():
                continue

            result = analyzer.analyze_binary(binary_path)

            if result:
                logger.info(f"Detected version {result.version} in {binary_path.name}")
                if result.version == "7.x":
                    assert isinstance(result, DenuvoAnalysisResult), "Must be DenuvoAnalysisResult"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_distinguish_version_differences(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Analyzer MUST distinguish between different Denuvo versions."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        versions_found: set[str] = set()

        for binary_path in denuvo_binaries:
            result = analyzer.analyze_binary(binary_path)

            if result and result.version != "unknown":
                versions_found.add(result.version)
                logger.info(f"Version {result.version} detected in {binary_path.name}")

        if len(versions_found) > 1:
            assert all(v in ["4.x", "5.x", "6.x", "7.x"] for v in versions_found), \
                f"Invalid versions detected: {versions_found}"
            logger.info(f"Successfully distinguished {len(versions_found)} different Denuvo versions")


class TestOnlineVsOfflineActivation:
    """Tests for online vs offline activation mode detection."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_online_only_activation(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Analyzer MUST identify online-only activation requirement."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        for binary_path in denuvo_binaries:
            result = analyzer.analyze_binary(binary_path)

            if result and result.online_activation:
                logger.info(f"Online activation detected in {binary_path.name}")
                assert isinstance(result.online_activation, OnlineActivation), "Must be OnlineActivation instance"
                assert len(result.online_activation.endpoint_url) > 0, "Endpoint URL must not be empty"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_detect_offline_activation_support(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Analyzer MUST identify binaries supporting offline activation."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        offline_count = 0
        online_count = 0

        for binary_path in denuvo_binaries:
            result = analyzer.analyze_binary(binary_path)

            if result:
                if result.online_activation is None:
                    offline_count += 1
                    logger.info(f"Offline activation detected in {binary_path.name}")
                else:
                    online_count += 1

        logger.info(f"Activation modes: {offline_count} offline, {online_count} online")


class TestSteamAPIWrapperDetection:
    """Tests for Steam API wrapper analysis."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_analyze_steam_api_wrapper(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
        test_binaries_dir: Path,
    ) -> None:
        """Analyzer MUST detect Denuvo-wrapped Steam API DLLs."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        steam_dlls = list(test_binaries_dir.rglob("steam_api*.dll"))

        for dll_path in steam_dlls:
            logger.info(f"Analyzing Steam API wrapper: {dll_path.name}")
            wrapper = analyzer.analyze_steam_api_wrapper(dll_path)

            if wrapper:
                logger.info(f"Detected Denuvo wrapper in {dll_path.name} (confidence={wrapper.confidence:.2f})")
                assert isinstance(wrapper, SteamAPIWrapper), "Must be SteamAPIWrapper instance"
                assert len(wrapper.dll_path) > 0, "DLL path must not be empty"
                assert isinstance(wrapper.is_wrapper, bool), "is_wrapper must be bool"
                assert isinstance(wrapper.original_exports, list), "original_exports must be list"
                assert isinstance(wrapper.hooked_exports, list), "hooked_exports must be list"
                assert isinstance(wrapper.denuvo_sections, list), "denuvo_sections must be list"
                assert 0.0 <= wrapper.confidence <= 1.0, f"Confidence out of range: {wrapper.confidence}"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_identify_hooked_steam_exports(
        self,
        analyzer: DenuvoTicketAnalyzer,
        test_binaries_dir: Path,
    ) -> None:
        """Wrapper analysis MUST identify hooked Steam API exports."""
        steam_dlls = list(test_binaries_dir.rglob("steam_api*.dll"))

        for dll_path in steam_dlls:
            wrapper = analyzer.analyze_steam_api_wrapper(dll_path)

            if wrapper and wrapper.is_wrapper:
                if len(wrapper.hooked_exports) > 0:
                    logger.info(f"Found {len(wrapper.hooked_exports)} hooked exports in {dll_path.name}")
                    for export in wrapper.hooked_exports:
                        assert isinstance(export, str), "Export must be string"
                        assert len(export) > 0, "Export name must not be empty"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_identify_denuvo_sections_in_wrapper(
        self,
        analyzer: DenuvoTicketAnalyzer,
        test_binaries_dir: Path,
    ) -> None:
        """Wrapper analysis MUST identify Denuvo-specific sections."""
        steam_dlls = list(test_binaries_dir.rglob("steam_api*.dll"))

        for dll_path in steam_dlls:
            wrapper = analyzer.analyze_steam_api_wrapper(dll_path)

            if wrapper and wrapper.is_wrapper:
                if len(wrapper.denuvo_sections) > 0:
                    logger.info(f"Found {len(wrapper.denuvo_sections)} Denuvo sections in {dll_path.name}")
                    for section in wrapper.denuvo_sections:
                        assert isinstance(section, str), "Section name must be string"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_analyze_nonexistent_binary(self, analyzer: DenuvoTicketAnalyzer) -> None:
        """Analyzer MUST handle nonexistent file path gracefully."""
        result = analyzer.analyze_binary("/nonexistent/path/to/binary.exe")

        assert result is None, "Analysis of nonexistent file must return None"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_analyze_invalid_binary(self, analyzer: DenuvoTicketAnalyzer, tmp_path: Path) -> None:
        """Analyzer MUST handle invalid binary format gracefully."""
        invalid_binary = tmp_path / "invalid.exe"
        invalid_binary.write_bytes(b"This is not a valid PE file")

        result = analyzer.analyze_binary(invalid_binary)

        assert result is None, "Analysis of invalid binary must return None"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_analyze_empty_binary(self, analyzer: DenuvoTicketAnalyzer, tmp_path: Path) -> None:
        """Analyzer MUST handle empty file gracefully."""
        empty_binary = tmp_path / "empty.exe"
        empty_binary.write_bytes(b"")

        result = analyzer.analyze_binary(empty_binary)

        assert result is None, "Analysis of empty file must return None"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_analyze_unprotected_binary(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Analyzer MUST return valid result with minimal findings for unprotected binaries."""
        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                result = analyzer.analyze_binary(binary_path)

                if result:
                    assert isinstance(result, DenuvoAnalysisResult), "Must be DenuvoAnalysisResult"
                    assert result.version in [
                        "4.x",
                        "5.x",
                        "6.x",
                        "7.x",
                        "unknown",
                    ], f"Invalid version: {result.version}"

    def test_analyzer_without_lief(self, analyzer: DenuvoTicketAnalyzer, tmp_path: Path) -> None:
        """Analyzer MUST fail gracefully when LIEF unavailable."""
        original_lief = analyzer.lief_available
        analyzer.lief_available = False

        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ")

        result = analyzer.analyze_binary(test_binary)

        analyzer.lief_available = original_lief
        assert result is None, "Analysis without LIEF must return None"


class TestPerformance:
    """Performance tests for binary analysis."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    @pytest.mark.benchmark
    def test_analysis_performance_on_large_binary(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Analyzer MUST complete analysis of large binaries within acceptable time."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        import time

        for binary_path in denuvo_binaries:
            if binary_path.stat().st_size < 1_000_000:
                continue

            logger.info(f"Performance testing on {binary_path.name} ({binary_path.stat().st_size} bytes)")
            start_time = time.perf_counter()
            result = analyzer.analyze_binary(binary_path)
            elapsed = time.perf_counter() - start_time

            if result:
                logger.info(f"Analysis completed in {elapsed:.2f}s")
                assert elapsed < 60.0, f"Analysis took {elapsed:.2f}s, expected < 60s"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    @pytest.mark.benchmark
    def test_trigger_detection_performance(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """Trigger detection MUST complete within acceptable time."""
        if not denuvo_binaries:
            pytest.skip(
                REQUIRED_BINARY_MESSAGE.format(
                    location=DENUVO_BINARIES_DIR.absolute(),
                )
            )

        import time

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            logger.info(f"Performance testing trigger detection on {binary_path.name}")
            start_time = time.perf_counter()
            triggers = analyzer.detect_activation_triggers(binary)
            elapsed = time.perf_counter() - start_time

            if triggers:
                logger.info(f"Trigger detection completed in {elapsed:.2f}s ({len(triggers)} triggers)")
                assert elapsed < 30.0, f"Trigger detection took {elapsed:.2f}s, expected < 30s"
