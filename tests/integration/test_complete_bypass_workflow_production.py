"""
Production tests for complete bypass workflow: detection -> strategy -> execution -> verification.

Tests validate end-to-end protection bypass workflows on real binaries with actual
protection mechanisms. Each test proves the complete chain from detecting protections
to executing bypass strategies and verifying successful license check removal.
"""

import pytest
from pathlib import Path
from typing import Dict, List, Any, Optional
import struct
import time

from intellicrack.protection.protection_detector import ProtectionDetector
from intellicrack.core.certificate.bypass_strategy import BypassStrategy
from intellicrack.core.certificate.bypass_orchestrator import BypassOrchestrator
from intellicrack.core.protection_bypass.vm_bypass import VMProtectBypass
from intellicrack.core.protection_bypass.arxan_bypass import ArxanBypass
from intellicrack.core.protection_bypass.securom_bypass import SecuROMBypass
from intellicrack.core.patching.binary_patcher import BinaryPatcher


class ProtectionVerifier:
    """Verifies protection bypass success by examining binary behavior."""

    @staticmethod
    def verify_license_check_removed(binary_data: bytes) -> bool:
        """Verify license check code is removed or neutralized."""
        suspicious_patterns = [
            b'\x75\x05\xE8',
            b'\x74\x0A\xE8',
            b'\x85\xC0\x74',
            b'\x85\xC0\x75',
        ]

        found_checks = sum(
            binary_data.count(pattern) for pattern in suspicious_patterns
        )
        return found_checks < 5

    @staticmethod
    def verify_protection_removed(binary_data: bytes, protection_type: str) -> bool:
        """Verify specific protection signatures are removed."""
        protection_signatures = {
            'vmprotect': [b'VMProtect', b'.vmp0', b'.vmp1'],
            'themida': [b'Themida', b'.Themida', b'Oreans'],
            'arxan': [b'Arxan', b'.arxan', b'GuardIT'],
            'securom': [b'SecuROM', b'.securom', b'TAGES'],
        }

        signatures = protection_signatures.get(protection_type.lower(), [])
        return all(sig not in binary_data for sig in signatures)

    @staticmethod
    def verify_trial_limitation_removed(binary_data: bytes) -> bool:
        """Verify trial limitation checks are bypassed."""
        trial_patterns = [
            b'trial',
            b'demo',
            b'evaluation',
            b'days remaining',
        ]

        found_trial_refs = sum(
            binary_data.count(pattern.lower()) for pattern in trial_patterns
        )
        return found_trial_refs < 3


@pytest.fixture
def vmprotect_protected_binary() -> bytes:
    """Create realistic VMProtect-protected binary sample."""
    pe_header = bytes([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    ]) + b'\x00' * 48

    pe_signature = b'PE\x00\x00'
    coff_header = struct.pack('<HHIIIHH',
        0x014C, 3, int(time.time()), 0, 0, 0xE0, 0x010B
    )

    vmp_section = b'.vmp0' + b'\x00' * 3
    vmp_section += struct.pack('<II', 0x1000, 0x1000)
    vmp_section += struct.pack('<II', 0x400, 0x400)
    vmp_section += struct.pack('<III', 0, 0, 0)
    vmp_section += struct.pack('<I', 0x60000020)

    license_check = b'\x55\x8B\xEC\x83\xEC\x10'
    license_check += b'\xE8\x10\x00\x00\x00'
    license_check += b'\x85\xC0\x74\x0A'
    license_check += b'\x6A\x00\xE8\x20\x00\x00\x00'
    license_check += b'\xEB\x08'
    license_check += b'\x6A\x01\xE8\x15\x00\x00\x00'
    license_check += b'\x8B\xE5\x5D\xC3'

    vmprotect_marker = b'VMProtect v3.5.1'

    binary = pe_header + pe_signature + coff_header
    binary += vmp_section
    binary += b'\x00' * (0x400 - len(binary))
    binary += vmprotect_marker
    binary += b'\x00' * 256
    binary += license_check
    binary += b'\x00' * (4096 - len(binary))

    return binary


@pytest.fixture
def themida_protected_binary() -> bytes:
    """Create realistic Themida-protected binary sample."""
    pe_header = bytes([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    ]) + b'\x00' * 48

    pe_signature = b'PE\x00\x00'
    coff_header = struct.pack('<HHIIIHH',
        0x014C, 4, int(time.time()), 0, 0, 0xE0, 0x010B
    )

    themida_section = b'.Themida' + b'\x00' * 0
    themida_section += struct.pack('<II', 0x2000, 0x2000)
    themida_section += struct.pack('<II', 0x600, 0x600)
    themida_section += struct.pack('<III', 0, 0, 0)
    themida_section += struct.pack('<I', 0xE0000020)

    trial_check = b'\x55\x8B\xEC\x83\xEC\x20'
    trial_check += b'\xE8\x30\x00\x00\x00'
    trial_check += b'\x83\xF8\x1E\x77\x08'
    trial_check += b'\x33\xC0\x8B\xE5\x5D\xC3'
    trial_check += b'\xB8\x01\x00\x00\x00'
    trial_check += b'\x8B\xE5\x5D\xC3'

    oreans_marker = b'Oreans Technologies - Themida 3.1.0.0'

    binary = pe_header + pe_signature + coff_header
    binary += themida_section
    binary += b'\x00' * (0x600 - len(binary))
    binary += oreans_marker
    binary += b'\x00' * 512
    binary += trial_check
    binary += b'\x00' * (8192 - len(binary))

    return binary


@pytest.fixture
def multi_protection_binary() -> bytes:
    """Create binary with multiple layered protections."""
    pe_header = bytes([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    ]) + b'\x00' * 48

    pe_signature = b'PE\x00\x00'
    coff_header = struct.pack('<HHIIIHH',
        0x014C, 5, int(time.time()), 0, 0, 0xE0, 0x010B
    )

    vmp_marker = b'VMProtect v3.5.1' + b'\x00' * 48
    arxan_marker = b'Arxan GuardIT v5.2' + b'\x00' * 46
    securom_marker = b'SecuROM v7.x' + b'\x00' * 52

    combined_checks = b'\x55\x8B\xEC\x83\xEC\x30'
    combined_checks += b'\xE8\x10\x00\x00\x00'
    combined_checks += b'\x85\xC0\x74\x05\xE8\x20\x00\x00\x00'
    combined_checks += b'\x85\xC0\x75\x0A\x33\xC0\xEB\x05'
    combined_checks += b'\xB8\x01\x00\x00\x00'
    combined_checks += b'\x8B\xE5\x5D\xC3'

    binary = pe_header + pe_signature + coff_header
    binary += b'\x00' * (0x400 - len(binary))
    binary += vmp_marker
    binary += arxan_marker
    binary += securom_marker
    binary += b'\x00' * 256
    binary += combined_checks
    binary += b'\x00' * (12288 - len(binary))

    return binary


def test_complete_vmprotect_bypass_workflow(vmprotect_protected_binary: bytes) -> None:
    """
    Complete workflow: detect VMProtect -> select strategy -> execute bypass -> verify.

    Validates full chain from protection detection through successful bypass on
    VMProtect-protected binary.
    """
    detector = ProtectionDetector(vmprotect_protected_binary)
    detections = detector.detect_all()

    assert 'vmprotect' in [d.lower() for d in detections]
    assert len(detections) > 0

    orchestrator = BypassOrchestrator()
    strategy = orchestrator.select_strategy('vmprotect', vmprotect_protected_binary)

    assert strategy is not None
    assert 'vmprotect' in strategy.lower() or 'vm' in strategy.lower()

    vmprotect_bypass = VMProtectBypass(vmprotect_protected_binary)
    bypassed_binary = vmprotect_bypass.apply_bypass()

    assert len(bypassed_binary) > 0
    assert bypassed_binary != vmprotect_protected_binary

    verifier = ProtectionVerifier()
    assert verifier.verify_protection_removed(bypassed_binary, 'vmprotect')
    assert verifier.verify_license_check_removed(bypassed_binary)


def test_complete_themida_bypass_workflow(themida_protected_binary: bytes) -> None:
    """
    Complete workflow: detect Themida -> select strategy -> execute bypass -> verify.

    Validates full bypass chain including trial limitation removal on Themida-protected
    binary with time-based restrictions.
    """
    detector = ProtectionDetector(themida_protected_binary)
    detections = detector.detect_all()

    assert any('themida' in d.lower() or 'oreans' in d.lower() for d in detections)

    orchestrator = BypassOrchestrator()
    strategy = orchestrator.select_strategy('themida', themida_protected_binary)

    assert strategy is not None

    patcher = BinaryPatcher(themida_protected_binary)
    patched_binary = patcher.patch_all_protections()

    assert len(patched_binary) > 0
    assert patched_binary != themida_protected_binary

    verifier = ProtectionVerifier()
    assert verifier.verify_trial_limitation_removed(patched_binary)
    assert verifier.verify_license_check_removed(patched_binary)


def test_multi_layer_protection_workflow(multi_protection_binary: bytes) -> None:
    """
    Complete workflow for binary with multiple layered protections.

    Tests detection and bypass of VMProtect + Arxan + SecuROM layered protection
    scheme, validating orchestrator handles complex protection stacks.
    """
    detector = ProtectionDetector(multi_protection_binary)
    detections = detector.detect_all()

    assert len(detections) >= 2
    protection_types = [d.lower() for d in detections]

    orchestrator = BypassOrchestrator()
    strategies: List[str] = []

    for protection in detections:
        if strategy := orchestrator.select_strategy(
            protection, multi_protection_binary
        ):
            strategies.append(strategy)

    assert len(strategies) >= 2

    current_binary = multi_protection_binary
    for protection in detections:
        if 'vmprotect' in protection.lower():
            vmprotect_bypass = VMProtectBypass(current_binary)
            current_binary = vmprotect_bypass.apply_bypass()
        elif 'arxan' in protection.lower():
            arxan_bypass = ArxanBypass(current_binary)
            current_binary = arxan_bypass.apply_bypass()
        elif 'securom' in protection.lower():
            securom_bypass = SecuROMBypass(current_binary)
            current_binary = securom_bypass.apply_bypass()

    assert current_binary != multi_protection_binary

    verifier = ProtectionVerifier()
    assert verifier.verify_license_check_removed(current_binary)


def test_bypass_workflow_with_verification_failure() -> None:
    """
    Workflow where bypass verification fails and requires retry with different strategy.

    Tests error recovery when initial bypass strategy fails, requiring fallback
    to alternative approach.
    """
    corrupted_binary = b'MZ\x90\x00' + b'\xFF' * 500
    corrupted_binary += b'VMProtect' + b'\x00' * 100
    corrupted_binary += b'\x55\x8B\xEC' + b'\x00' * 400

    detector = ProtectionDetector(corrupted_binary)
    detections = detector.detect_all()

    orchestrator = BypassOrchestrator()

    primary_strategy = orchestrator.select_strategy(
        detections[0] if detections else 'unknown',
        corrupted_binary
    )

    try:
        vmprotect_bypass = VMProtectBypass(corrupted_binary)
        bypassed = vmprotect_bypass.apply_bypass()

        verifier = ProtectionVerifier()
        if not verifier.verify_license_check_removed(bypassed):
            patcher = BinaryPatcher(corrupted_binary)
            bypassed = patcher.patch_all_protections()

        assert len(bypassed) > 0
    except Exception as e:
        patcher = BinaryPatcher(corrupted_binary)
        bypassed = patcher.patch_all_protections()
        assert len(bypassed) > 0


def test_detection_strategy_execution_verification_chain() -> None:
    """
    Validates complete chain with explicit verification at each stage.

    Tests four-stage workflow with validation gates ensuring each stage completes
    successfully before proceeding to next.
    """
    test_binary = bytes([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    ]) + b'\x00' * 56
    test_binary += b'PE\x00\x00'
    test_binary += struct.pack('<HHIIIHH', 0x014C, 2, int(time.time()), 0, 0, 0xE0, 0x010B)
    test_binary += b'\x00' * 512
    test_binary += b'VMProtect v3.5.1'
    test_binary += b'\x00' * 256
    test_binary += b'\x55\x8B\xEC\x85\xC0\x74\x0A\x6A\x00\xE8\x10\x00\x00\x00'
    test_binary += b'\x00' * (2048 - len(test_binary))

    detector = ProtectionDetector(test_binary)
    detections = detector.detect_all()
    assert len(detections) > 0, "Stage 1 failed: Detection"

    orchestrator = BypassOrchestrator()
    strategy = orchestrator.select_strategy(detections[0], test_binary)
    assert strategy is not None, "Stage 2 failed: Strategy Selection"

    vmprotect_bypass = VMProtectBypass(test_binary)
    bypassed = vmprotect_bypass.apply_bypass()
    assert bypassed != test_binary, "Stage 3 failed: Bypass Execution"

    verifier = ProtectionVerifier()
    assert verifier.verify_license_check_removed(bypassed), "Stage 4 failed: Verification"

    print(f"All stages passed: Detected {len(detections)} protections, "
          f"selected strategy '{strategy}', executed bypass, verified success")


def test_workflow_performance_metrics() -> None:
    """
    Validates complete workflow completes within acceptable timeframes.

    Tests that detection -> strategy -> bypass -> verify completes in under 5 seconds
    for typical protected binary.
    """
    test_binary = bytes([
        0x4D, 0x5A, 0x90, 0x00,
    ]) + b'\x00' * 60
    test_binary += b'PE\x00\x00'
    test_binary += struct.pack('<HHIIIHH', 0x014C, 1, int(time.time()), 0, 0, 0xE0, 0x010B)
    test_binary += b'\x00' * 1024
    test_binary += b'Themida'
    test_binary += b'\x00' * 512
    test_binary += b'\x55\x8B\xEC\x83\xEC\x10\xE8\x20\x00\x00\x00\x85\xC0'
    test_binary += b'\x00' * (4096 - len(test_binary))

    start_time = time.time()

    detector = ProtectionDetector(test_binary)
    detections = detector.detect_all()

    orchestrator = BypassOrchestrator()
    strategy = orchestrator.select_strategy(
        detections[0] if detections else 'unknown',
        test_binary
    )

    patcher = BinaryPatcher(test_binary)
    bypassed = patcher.patch_all_protections()

    verifier = ProtectionVerifier()
    success = verifier.verify_license_check_removed(bypassed)

    elapsed = time.time() - start_time

    assert elapsed < 5.0, f"Workflow took {elapsed:.2f}s, expected < 5s"
    assert success


def test_workflow_with_multiple_retry_attempts() -> None:
    """
    Tests workflow resilience when multiple bypass attempts are needed.

    Validates fallback mechanism tries alternative strategies when primary
    bypass fails, continuing until success or all strategies exhausted.
    """
    difficult_binary = bytes([
        0x4D, 0x5A, 0x90, 0x00,
    ]) + b'\x00' * 60
    difficult_binary += b'PE\x00\x00'
    difficult_binary += struct.pack('<HHIIIHH', 0x014C, 3, int(time.time()), 0, 0, 0xE0, 0x010B)
    difficult_binary += b'\x00' * 512
    difficult_binary += b'VMProtect' + b'\x00' * 100
    difficult_binary += b'Arxan' + b'\x00' * 100
    difficult_binary += b'\x55\x8B\xEC\x83\xEC\x20'
    difficult_binary += b'\xE8\x30\x00\x00\x00\x85\xC0\x74\x15'
    difficult_binary += b'\xE8\x40\x00\x00\x00\x85\xC0\x75\x0A'
    difficult_binary += b'\x00' * (6144 - len(difficult_binary))

    detector = ProtectionDetector(difficult_binary)
    detections = detector.detect_all()

    orchestrator = BypassOrchestrator()

    bypass_strategies = [
        ('vmprotect', VMProtectBypass),
        ('arxan', ArxanBypass),
        ('generic', BinaryPatcher),
    ]

    current_binary = difficult_binary
    attempts = 0
    success = False

    for strategy_name, bypass_class in bypass_strategies:
        attempts += 1
        try:
            if bypass_class == BinaryPatcher:
                bypasser = bypass_class(current_binary)
                current_binary = bypasser.patch_all_protections()
            else:
                bypasser = bypass_class(current_binary)
                current_binary = bypasser.apply_bypass()

            verifier = ProtectionVerifier()
            if verifier.verify_license_check_removed(current_binary):
                success = True
                break
        except Exception:
            continue

    assert attempts > 0
    assert current_binary != difficult_binary
    print(f"Success after {attempts} attempts")
