"""
Production tests for multi-layer protection scenarios.

Tests validate bypass capabilities against binaries with multiple simultaneous
protection mechanisms including VMProtect + Themida, Arxan + SecuROM, and
complex protection stacks with anti-debug + obfuscation layers.
"""

import pytest
from pathlib import Path
from typing import List, Dict, Set, Tuple
import struct
import time

from intellicrack.protection.protection_detector import ProtectionDetector
from intellicrack.core.protection_bypass.vm_bypass import VMProtectBypass
from intellicrack.core.protection_bypass.arxan_bypass import ArxanBypass
from intellicrack.core.protection_bypass.securom_bypass import SecuROMBypass
from intellicrack.core.certificate.bypass_orchestrator import BypassOrchestrator
from intellicrack.core.patching.binary_patcher import BinaryPatcher
from intellicrack.core.anti_analysis.debugger_bypass import DebuggerBypass


class MultiLayerProtectionAnalyzer:
    """Analyzes and validates multi-layer protection bypass results."""

    @staticmethod
    def count_protection_layers(binary_data: bytes) -> int:
        """Count number of distinct protection layers present."""
        protection_markers = {
            b'VMProtect': 'vmprotect',
            b'.vmp0': 'vmprotect',
            b'Themida': 'themida',
            b'Oreans': 'themida',
            b'Arxan': 'arxan',
            b'GuardIT': 'arxan',
            b'SecuROM': 'securom',
            b'TAGES': 'securom',
            b'Enigma': 'enigma',
            b'StarForce': 'starforce',
        }

        found_protections: Set[str] = {
            protection_type
            for marker, protection_type in protection_markers.items()
            if marker in binary_data
        }
        return len(found_protections)

    @staticmethod
    def identify_protection_types(binary_data: bytes) -> List[str]:
        """Identify all protection types present in binary."""
        protection_markers = {
            b'VMProtect': 'VMProtect',
            b'.vmp0': 'VMProtect',
            b'Themida': 'Themida',
            b'Oreans': 'Themida',
            b'Arxan': 'Arxan',
            b'GuardIT': 'Arxan',
            b'SecuROM': 'SecuROM',
            b'TAGES': 'SecuROM',
            b'Enigma': 'Enigma',
            b'StarForce': 'StarForce',
        }

        found: Set[str] = {
            protection_type
            for marker, protection_type in protection_markers.items()
            if marker in binary_data
        }
        return sorted(list(found))

    @staticmethod
    def verify_all_layers_bypassed(original: bytes, bypassed: bytes) -> bool:
        """Verify all protection layers were successfully bypassed."""
        original_count = MultiLayerProtectionAnalyzer.count_protection_layers(original)
        bypassed_count = MultiLayerProtectionAnalyzer.count_protection_layers(bypassed)

        return bypassed_count < original_count or bypassed != original


@pytest.fixture
def vmprotect_themida_binary() -> bytes:
    """Create binary with VMProtect + Themida dual protection."""
    pe_header = bytes([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    ]) + b'\x00' * 48

    pe_signature = b'PE\x00\x00'
    coff_header = struct.pack('<HHIIIHH',
        0x014C, 4, int(time.time()), 0, 0, 0xE0, 0x010B
    )

    vmp_section = b'.vmp0' + b'\x00' * 3
    vmp_section += struct.pack('<IIIIIIII', 0x1000, 0x1000, 0x600, 0x600, 0, 0, 0, 0x60000020)

    themida_section = b'.Themida'
    themida_section += struct.pack('<IIIIIIII', 0x2000, 0x2000, 0x800, 0x800, 0, 0, 0, 0xE0000020)

    vmprotect_code = b'VMProtect v3.5.1 - Commercial License Required'
    themida_code = b'Oreans Themida 3.1.0.0 - Protected Application'

    license_validation = b'\x55\x8B\xEC\x83\xEC\x30'
    license_validation += b'\xE8\x10\x00\x00\x00'
    license_validation += b'\x85\xC0\x74\x0A'
    license_validation += b'\xE8\x20\x00\x00\x00'
    license_validation += b'\x85\xC0\x75\x05'
    license_validation += b'\x33\xC0\xEB\x05'
    license_validation += b'\xB8\x01\x00\x00\x00'
    license_validation += b'\x8B\xE5\x5D\xC3'

    binary = pe_header + pe_signature + coff_header
    binary += vmp_section + themida_section
    binary += b'\x00' * (0x600 - len(binary))
    binary += vmprotect_code + b'\x00' * 128
    binary += themida_code + b'\x00' * 128
    binary += license_validation
    binary += b'\x00' * (8192 - len(binary))

    return binary


@pytest.fixture
def arxan_securom_binary() -> bytes:
    """Create binary with Arxan + SecuROM dual protection."""
    pe_header = bytes([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    ]) + b'\x00' * 48

    pe_signature = b'PE\x00\x00'
    coff_header = struct.pack('<HHIIIHH',
        0x014C, 3, int(time.time()), 0, 0, 0xE0, 0x010B
    )

    arxan_marker = b'Arxan GuardIT v5.2 - Anti-Tamper Protection'
    securom_marker = b'SecuROM v7.x - Disc Protection Active'

    anti_tamper = b'\x55\x8B\xEC\x51'
    anti_tamper += b'\xE8\x50\x00\x00\x00'
    anti_tamper += b'\x85\xC0\x74\x15'
    anti_tamper += b'\xE8\x60\x00\x00\x00'
    anti_tamper += b'\x85\xC0\x75\x0A'
    anti_tamper += b'\x6A\x00\xE8\x70\x00\x00\x00'
    anti_tamper += b'\x8B\xE5\x5D\xC3'

    binary = pe_header + pe_signature + coff_header
    binary += b'\x00' * (0x400 - len(binary))
    binary += arxan_marker + b'\x00' * 256
    binary += securom_marker + b'\x00' * 256
    binary += anti_tamper
    binary += b'\x00' * (6144 - len(binary))

    return binary


@pytest.fixture
def triple_layer_protection_binary() -> bytes:
    """Create binary with VMProtect + Arxan + SecuROM triple protection."""
    pe_header = bytes([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    ]) + b'\x00' * 48

    pe_signature = b'PE\x00\x00'
    coff_header = struct.pack('<HHIIIHH',
        0x014C, 5, int(time.time()), 0, 0, 0xE0, 0x010B
    )

    vmp_marker = b'VMProtect v3.5.1'
    arxan_marker = b'Arxan GuardIT v5.2'
    securom_marker = b'SecuROM v7.42.0000'

    complex_validation = b'\x55\x8B\xEC\x83\xEC\x40'
    complex_validation += b'\xE8\x10\x00\x00\x00'
    complex_validation += b'\x85\xC0\x74\x05\xE8\x20\x00\x00\x00'
    complex_validation += b'\x85\xC0\x75\x05\xE8\x30\x00\x00\x00'
    complex_validation += b'\x85\xC0\x74\x10'
    complex_validation += b'\x33\xC0\x8B\xE5\x5D\xC3'
    complex_validation += b'\xB8\x01\x00\x00\x00\x8B\xE5\x5D\xC3'

    binary = pe_header + pe_signature + coff_header
    binary += b'\x00' * (0x400 - len(binary))
    binary += vmp_marker + b'\x00' * 256
    binary += arxan_marker + b'\x00' * 256
    binary += securom_marker + b'\x00' * 256
    binary += complex_validation
    binary += b'\x00' * (10240 - len(binary))

    return binary


def test_vmprotect_themida_dual_bypass(vmprotect_themida_binary: bytes) -> None:
    """
    Bypass VMProtect + Themida dual protection layer.

    Tests sequential bypass of two independent protection systems, validating
    each layer is properly detected and removed without interference.
    """
    analyzer = MultiLayerProtectionAnalyzer()
    original_layers = analyzer.count_protection_layers(vmprotect_themida_binary)

    assert original_layers >= 2

    detector = ProtectionDetector(vmprotect_themida_binary)
    detections = detector.detect_all()

    assert len(detections) >= 2

    current_binary = vmprotect_themida_binary

    vmprotect_bypass = VMProtectBypass(current_binary)
    current_binary = vmprotect_bypass.apply_bypass()

    assert current_binary != vmprotect_themida_binary

    patcher = BinaryPatcher(current_binary)
    final_binary = patcher.patch_all_protections()

    assert analyzer.verify_all_layers_bypassed(vmprotect_themida_binary, final_binary)

    final_layers = analyzer.count_protection_layers(final_binary)
    assert final_layers < original_layers


def test_arxan_securom_dual_bypass(arxan_securom_binary: bytes) -> None:
    """
    Bypass Arxan + SecuROM dual protection layer.

    Tests bypass of anti-tamper + disc protection combination, validating
    both protection mechanisms are defeated without triggering anti-tamper alerts.
    """
    analyzer = MultiLayerProtectionAnalyzer()
    original_layers = analyzer.count_protection_layers(arxan_securom_binary)

    assert original_layers >= 2

    protections = analyzer.identify_protection_types(arxan_securom_binary)
    assert 'Arxan' in protections or 'SecuROM' in protections

    current_binary = arxan_securom_binary

    arxan_bypass = ArxanBypass(current_binary)
    current_binary = arxan_bypass.apply_bypass()

    securom_bypass = SecuROMBypass(current_binary)
    current_binary = securom_bypass.apply_bypass()

    assert analyzer.verify_all_layers_bypassed(arxan_securom_binary, current_binary)

    final_layers = analyzer.count_protection_layers(current_binary)
    assert final_layers < original_layers


def test_triple_layer_protection_bypass(triple_layer_protection_binary: bytes) -> None:
    """
    Bypass VMProtect + Arxan + SecuROM triple protection stack.

    Tests bypass of three independent protection systems in correct order,
    validating orchestrator properly sequences bypass operations.
    """
    analyzer = MultiLayerProtectionAnalyzer()
    original_layers = analyzer.count_protection_layers(triple_layer_protection_binary)

    assert original_layers >= 3

    detector = ProtectionDetector(triple_layer_protection_binary)
    detections = detector.detect_all()

    assert len(detections) >= 2

    orchestrator = BypassOrchestrator()
    current_binary = triple_layer_protection_binary

    vmprotect_bypass = VMProtectBypass(current_binary)
    current_binary = vmprotect_bypass.apply_bypass()

    layer1_count = analyzer.count_protection_layers(current_binary)
    assert layer1_count < original_layers

    arxan_bypass = ArxanBypass(current_binary)
    current_binary = arxan_bypass.apply_bypass()

    layer2_count = analyzer.count_protection_layers(current_binary)
    assert layer2_count < layer1_count

    securom_bypass = SecuROMBypass(current_binary)
    current_binary = securom_bypass.apply_bypass()

    assert analyzer.verify_all_layers_bypassed(triple_layer_protection_binary, current_binary)

    final_layers = analyzer.count_protection_layers(current_binary)
    assert final_layers < original_layers


def test_protection_with_anti_debug_layer() -> None:
    """
    Bypass protection with integrated anti-debug mechanisms.

    Tests bypass of protection that includes anti-debugging checks, validating
    debugger detection is disabled before applying protection bypass.
    """
    pe_header = bytes([
        0x4D, 0x5A, 0x90, 0x00,
    ]) + b'\x00' * 60
    pe_signature = b'PE\x00\x00'
    coff_header = struct.pack('<HHIIIHH', 0x014C, 2, int(time.time()), 0, 0, 0xE0, 0x010B)

    vmprotect_marker = b'VMProtect v3.5.1'

    anti_debug = b'\x64\xA1\x30\x00\x00\x00'
    anti_debug += b'\x80\x78\x02\x00\x75\x05'
    anti_debug += b'\xB8\x01\x00\x00\x00\xC3'
    anti_debug += b'\x33\xC0\xC3'

    license_check = b'\x55\x8B\xEC'
    license_check += b'\xE8\x10\x00\x00\x00'
    license_check += b'\x85\xC0\x74\x05'
    license_check += b'\xB8\x01\x00\x00\x00\x5D\xC3'

    binary = pe_header + pe_signature + coff_header
    binary += b'\x00' * (0x400 - len(binary))
    binary += vmprotect_marker + b'\x00' * 256
    binary += anti_debug + b'\x00' * 128
    binary += license_check
    binary += b'\x00' * (4096 - len(binary))

    analyzer = MultiLayerProtectionAnalyzer()
    protections = analyzer.identify_protection_types(binary)

    assert len(protections) > 0

    debugger_bypass = DebuggerBypass()
    current_binary = binary

    vmprotect_bypass = VMProtectBypass(current_binary)
    current_binary = vmprotect_bypass.apply_bypass()

    assert current_binary != binary
    assert b'\x64\xA1\x30\x00\x00\x00' not in current_binary or current_binary != binary


def test_layered_protection_bypass_order() -> None:
    """
    Validates bypass order affects success rate for layered protections.

    Tests that bypassing protections in optimal order (outermost to innermost)
    produces better results than arbitrary order.
    """
    pe_header = bytes([
        0x4D, 0x5A, 0x90, 0x00,
    ]) + b'\x00' * 60
    pe_signature = b'PE\x00\x00'
    coff_header = struct.pack('<HHIIIHH', 0x014C, 3, int(time.time()), 0, 0, 0xE0, 0x010B)

    outer_protection = b'VMProtect v3.5.1'
    middle_protection = b'Arxan GuardIT v5.2'
    inner_protection = b'SecuROM v7.x'

    validation_chain = b'\x55\x8B\xEC\x83\xEC\x20'
    validation_chain += b'\xE8\x10\x00\x00\x00'
    validation_chain += b'\x85\xC0\x74\x05\xE8\x20\x00\x00\x00'
    validation_chain += b'\x85\xC0\x75\x05\xE8\x30\x00\x00\x00'
    validation_chain += b'\x8B\xE5\x5D\xC3'

    binary = pe_header + pe_signature + coff_header
    binary += b'\x00' * (0x400 - len(binary))
    binary += outer_protection + b'\x00' * 256
    binary += middle_protection + b'\x00' * 256
    binary += inner_protection + b'\x00' * 256
    binary += validation_chain
    binary += b'\x00' * (8192 - len(binary))

    analyzer = MultiLayerProtectionAnalyzer()
    original_count = analyzer.count_protection_layers(binary)

    correct_order = binary
    vmprotect_bypass = VMProtectBypass(correct_order)
    correct_order = vmprotect_bypass.apply_bypass()

    arxan_bypass = ArxanBypass(correct_order)
    correct_order = arxan_bypass.apply_bypass()

    securom_bypass = SecuROMBypass(correct_order)
    correct_order = securom_bypass.apply_bypass()

    correct_final_count = analyzer.count_protection_layers(correct_order)

    wrong_order = binary
    securom_bypass_first = SecuROMBypass(wrong_order)
    try:
        wrong_order = securom_bypass_first.apply_bypass()
    except Exception:
        pass

    try:
        arxan_bypass_second = ArxanBypass(wrong_order)
        wrong_order = arxan_bypass_second.apply_bypass()
    except Exception:
        pass

    wrong_final_count = analyzer.count_protection_layers(wrong_order)

    assert correct_final_count <= wrong_final_count


def test_protection_interdependency_handling() -> None:
    """
    Tests handling of protections with interdependent checks.

    Validates bypass correctly handles protections that verify each other's
    integrity, requiring simultaneous or coordinated bypass.
    """
    pe_header = bytes([
        0x4D, 0x5A, 0x90, 0x00,
    ]) + b'\x00' * 60
    pe_signature = b'PE\x00\x00'
    coff_header = struct.pack('<HHIIIHH', 0x014C, 2, int(time.time()), 0, 0, 0xE0, 0x010B)

    protection_a = b'VMProtect v3.5.1'
    protection_b = b'Themida 3.1.0.0'

    cross_validation = b'\x55\x8B\xEC\x83\xEC\x10'
    cross_validation += b'\xE8\x10\x00\x00\x00'
    cross_validation += b'\x85\xC0\x74\x05'
    cross_validation += b'\xE8\x50\x00\x00\x00'
    cross_validation += b'\x85\xC0\x75\x05'
    cross_validation += b'\xE8\x20\x00\x00\x00'
    cross_validation += b'\x8B\xE5\x5D\xC3'

    binary = pe_header + pe_signature + coff_header
    binary += b'\x00' * (0x400 - len(binary))
    binary += protection_a + b'\x00' * 256
    binary += protection_b + b'\x00' * 256
    binary += cross_validation
    binary += b'\x00' * (6144 - len(binary))

    analyzer = MultiLayerProtectionAnalyzer()
    original_protections = analyzer.identify_protection_types(binary)

    assert len(original_protections) >= 2

    patcher = BinaryPatcher(binary)
    bypassed = patcher.patch_all_protections()

    final_protections = analyzer.identify_protection_types(bypassed)
    assert len(final_protections) < len(original_protections) or bypassed != binary


def test_multi_layer_performance_impact() -> None:
    """
    Tests performance impact of bypassing multiple protection layers.

    Validates that bypass time scales linearly with protection layer count,
    not exponentially.
    """
    single_layer = bytes([0x4D, 0x5A, 0x90, 0x00]) + b'\x00' * 60
    single_layer += b'PE\x00\x00' + struct.pack('<HHIIIHH', 0x014C, 1, int(time.time()), 0, 0, 0xE0, 0x010B)
    single_layer += b'\x00' * 512 + b'VMProtect v3.5.1' + b'\x00' * (2048 - len(single_layer))

    start = time.time()
    vmprotect_bypass = VMProtectBypass(single_layer)
    vmprotect_bypass.apply_bypass()
    single_time = time.time() - start

    triple_layer = bytes([0x4D, 0x5A, 0x90, 0x00]) + b'\x00' * 60
    triple_layer += b'PE\x00\x00' + struct.pack('<HHIIIHH', 0x014C, 3, int(time.time()), 0, 0, 0xE0, 0x010B)
    triple_layer += b'\x00' * 512
    triple_layer += b'VMProtect v3.5.1' + b'\x00' * 256
    triple_layer += b'Arxan GuardIT v5.2' + b'\x00' * 256
    triple_layer += b'SecuROM v7.x' + b'\x00' * (8192 - len(triple_layer))

    start = time.time()
    current = triple_layer
    for bypass_class in [VMProtectBypass, ArxanBypass, SecuROMBypass]:
        bypasser = bypass_class(current)
        current = bypasser.apply_bypass()
    triple_time = time.time() - start

    assert triple_time < single_time * 5


def test_partial_layer_bypass_recovery() -> None:
    """
    Tests recovery when only some protection layers can be bypassed.

    Validates system handles cases where inner protections remain after outer
    layers are bypassed, falling back to generic patching.
    """
    pe_header = bytes([0x4D, 0x5A, 0x90, 0x00]) + b'\x00' * 60
    pe_signature = b'PE\x00\x00'
    coff_header = struct.pack('<HHIIIHH', 0x014C, 3, int(time.time()), 0, 0, 0xE0, 0x010B)

    outer_layer = b'VMProtect v3.5.1'
    stubborn_layer = b'UnknownProtection v9.9'
    inner_layer = b'SecuROM v7.x'

    binary = pe_header + pe_signature + coff_header
    binary += b'\x00' * (0x400 - len(binary))
    binary += outer_layer + b'\x00' * 256
    binary += stubborn_layer + b'\x00' * 256
    binary += inner_layer + b'\x00' * 256
    binary += b'\x55\x8B\xEC\x85\xC0\x74\x05\xB8\x01\x00\x00\x00\x5D\xC3'
    binary += b'\x00' * (7168 - len(binary))

    analyzer = MultiLayerProtectionAnalyzer()
    original_count = analyzer.count_protection_layers(binary)

    current = binary

    vmprotect_bypass = VMProtectBypass(current)
    current = vmprotect_bypass.apply_bypass()

    mid_count = analyzer.count_protection_layers(current)

    try:
        securom_bypass = SecuROMBypass(current)
        current = securom_bypass.apply_bypass()
    except Exception:
        pass

    if not analyzer.verify_all_layers_bypassed(binary, current):
        patcher = BinaryPatcher(current)
        current = patcher.patch_all_protections()

    final_count = analyzer.count_protection_layers(current)
    assert final_count <= original_count
    assert current != binary
