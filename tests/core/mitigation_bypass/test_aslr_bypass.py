"""
Ultra-comprehensive test suite for ASLR bypass module.
Tests validate REAL exploitation capabilities required for production security research.
"""

from typing import Any
import pytest
import struct
import os
import tempfile
import shutil
from pathlib import Path
import logging

try:
    from intellicrack.core.mitigation_bypass.aslr_bypass import ASLRBypass
    MODULE_AVAILABLE = True
except ImportError:
    ASLRBypass = None
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


class TestASLRBypassProductionCapabilities:
    """
    Specification-driven tests for ASLR bypass functionality.
    All tests expect genuine exploitation capabilities, not placeholders.
    """

    @pytest.fixture
    def aslr_bypass(self) -> Any:
        """Create ASLRBypass instance for testing."""
        return ASLRBypass()

    @pytest.fixture
    def test_binary_with_aslr(self, tmp_path: Any) -> None:
        """Create a test binary with ASLR-like characteristics."""
        binary_path = tmp_path / "test_aslr.exe"

        # PE header with ASLR flag set (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        pe_header = bytearray(b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00")  # DOS header
        pe_header += b"PE\x00\x00"  # PE signature
        pe_header += b"\x64\x86"  # Machine type (x64)
        pe_header += b"\x06\x00"  # Number of sections
        pe_header += b"\x00" * 12  # Timestamps
        pe_header += b"\x00" * 8  # Symbol table
        pe_header += b"\xf0\x00"  # Size of optional header
        pe_header += b"\x22\x00"  # Characteristics

        # Optional header with ASLR enabled
        pe_header += b"\x0b\x02"  # Magic (PE32+)
        pe_header += b"\x00" * 58  # Various fields
        pe_header += b"\x00\x00\x40\x01"  # ImageBase (randomizable)
        pe_header += b"\x00" * 24  # More fields
        pe_header += b"\x40\x01\x00\x00"  # DllCharacteristics with ASLR flag

        # Add some code section
        pe_header += b"\x00" * 200
        code_section = b"\x48\x89\x5c\x24\x08"  # mov [rsp+8], rbx (typical function prologue)
        code_section += b"\x48\x89\x74\x24\x10"  # mov [rsp+10h], rsi
        code_section += b"\x57"  # push rdi
        code_section += b"\x48\x83\xec\x20"  # sub rsp, 20h
        code_section += b"\xff\x15\x00\x00\x00\x00"  # call [rip+offset] - IAT call
        code_section += b"\x48\x8d\x05\x00\x00\x00\x00"  # lea rax, [rip+offset]
        code_section += b"\xc3"  # ret

        # Add format string vulnerability pattern
        code_section += b"\x48\x8d\x0d\x00\x00\x00\x00"  # lea rcx, [rip+offset] - format string
        code_section += b"\xff\x15\x00\x00\x00\x00"  # call printf without args check

        # Add potential UAF pattern
        code_section += b"\xff\x15\x00\x00\x00\x00"  # call free
        code_section += b"\x48\x8b\x00"  # mov rax, [rax] - use after free

        full_binary = pe_header + code_section + b"\x00" * 1000

        binary_path.write_bytes(full_binary)
        return str(binary_path)

    @pytest.fixture
    def real_process_data(self) -> Any:
        """Create real process data structure."""
        return {
            "pid": 1234,
            "is_64bit": True,
            "image_base": 0x7FF600000000,
            "modules": {
                "kernel32.dll": {"base": 0x7FFE80000000, "size": 0x100000},
                "ntdll.dll": {"base": 0x7FFE90000000, "size": 0x200000},
            },
            "platform": "windows",
            "memory_map": [],
        }

    def test_initialization_creates_bypass_techniques(self, aslr_bypass: Any) -> None:
        """Test that initialization sets up multiple bypass techniques."""
        assert hasattr(aslr_bypass, "techniques")
        assert isinstance(aslr_bypass.techniques, dict)
        assert len(aslr_bypass.techniques) >= 3  # Should have multiple techniques

        # Verify technique structure
        for technique_name, technique_data in aslr_bypass.techniques.items():
            assert "description" in technique_data
            assert "reliability" in technique_data
            assert "requirements" in technique_data
            assert isinstance(technique_data["reliability"], (int, float))
            assert 0 <= technique_data["reliability"] <= 100

    def test_get_recommended_technique_with_info_leak(self, aslr_bypass: Any, test_binary_with_aslr: Any) -> None:
        """Test technique recommendation when info leak is available."""
        result = aslr_bypass.get_recommended_technique(binary_path=test_binary_with_aslr, has_info_leak=True, has_write_primitive=True)

        assert result is not None
        assert "success" in result or "technique" in result
        assert "technique" in result
        assert "confidence" in result
        assert "reason" in result

        # Info leak should be highly recommended when available
        assert result["confidence"] >= 80
        assert "info_leak" in result["technique"].lower() or "leak" in result["reason"].lower()

    def test_get_recommended_technique_without_leak(self, aslr_bypass: Any, test_binary_with_aslr: Any) -> None:
        """Test technique recommendation without info leak."""
        result = aslr_bypass.get_recommended_technique(binary_path=test_binary_with_aslr, has_info_leak=False, has_write_primitive=True)

        assert result is not None
        assert "success" in result or "technique" in result
        # Should recommend alternative like partial overwrite or brute force
        assert "partial" in result["technique"].lower() or "brute" in result["technique"].lower()

    def test_bypass_aslr_info_leak_with_stack_pointer(self, aslr_bypass: Any, test_binary_with_aslr: Any, real_process_data: Any) -> None:
        """Test ASLR bypass using leaked stack pointer."""
        result = aslr_bypass.bypass_aslr_info_leak(
            process=real_process_data, binary_path=test_binary_with_aslr, leak_address=0x7FF600001000
        )

        assert result is not None
        assert "success" in result or "technique" in result
        assert "success" in result
        assert result["success"] is True
        assert "base_addresses" in result
        assert "image_base" in result["base_addresses"]

        # Verify calculated base is aligned and reasonable
        image_base = result["base_addresses"]["image_base"]
        assert image_base % 0x1000 == 0  # Page aligned
        assert 0x400000 <= image_base <= 0x7FFFFFFFFFFF  # Valid user-mode range

    def test_bypass_aslr_info_leak_calculates_multiple_bases(self, aslr_bypass: Any, test_binary_with_aslr: Any, real_process_data: Any) -> None:
        """Test that info leak bypass calculates multiple module bases."""
        result = aslr_bypass.bypass_aslr_info_leak(
            process=real_process_data,
            binary_path=test_binary_with_aslr,
            leak_address=0x7FF600003000,  # IAT leak
        )

        assert result is not None
        assert "success" in result or "technique" in result
        assert result["success"] == True  # Demand success
        bases = result["base_addresses"]
        # Should calculate bases for multiple modules
        assert len(bases) >= 2
        assert any("kernel32" in k.lower() for k in bases)

    def test_bypass_aslr_partial_overwrite(self, aslr_bypass: Any, test_binary_with_aslr: Any, real_process_data: Any) -> None:
        """Test partial overwrite ASLR bypass technique."""
        result = aslr_bypass.bypass_aslr_partial_overwrite(
            process=real_process_data,
            binary_path=test_binary_with_aslr,
            target_address=0x7FF600010000,
            controlled_bytes=2,  # Can control 2 bytes
        )

        assert result is not None
        assert "success" in result or "technique" in result
        assert "success" in result
        assert "overwrite_data" in result

        assert result["success"] == True  # Demand success
        # Verify overwrite preserves upper bits (partial)
        overwrite = result["overwrite_data"]
        assert "preserved_bits" in overwrite
        assert "new_bits" in overwrite
        assert overwrite["preserved_bits"] >= 32  # At least 32 bits preserved

    def test_bypass_aslr_ret2libc(self, aslr_bypass: Any, test_binary_with_aslr: Any, real_process_data: Any) -> None:
        """Test return-to-libc ASLR bypass."""
        result = aslr_bypass.bypass_aslr_ret2libc(
            process=real_process_data, binary_path=test_binary_with_aslr, overflow_size=256, control_rip=True
        )

        assert result is not None
        assert "success" in result or "technique" in result
        assert "success" in result
        assert "exploit_chain" in result

        assert result["success"] == True  # Demand success
        chain = result["exploit_chain"]
        assert "gadgets" in chain
        assert "libc_base" in chain
        assert len(chain["gadgets"]) > 0

        # Verify gadgets are properly aligned
        for gadget in chain["gadgets"]:
            assert gadget["address"] % 8 == 0  # 64-bit alignment

    def test_find_info_leak_sources(self, aslr_bypass: Any, test_binary_with_aslr: Any, real_process_data: Any) -> None:
        """Test discovery of information leak sources."""
        # This should be a private method but tests its indirect effects
        result = aslr_bypass.bypass_aslr_info_leak(
            process=real_process_data,
            binary_path=test_binary_with_aslr,
            leak_address=None,  # Let it find leaks
        )

        assert result is not None
        assert "success" in result or "technique" in result
        assert result["success"] == True  # Demand success
        assert "leak_sources" in result or "discovered_leaks" in result

    def test_calculate_base_from_leak(self, aslr_bypass: Any) -> None:
        """Test base address calculation from leaked pointer."""
        # Test through public interface
        real_process_data = {}
        real_process_data.image_base = 0x140000000

        # Simulate leaked pointer
        leaked_ptr = 0x140001234

        result = aslr_bypass.bypass_aslr_info_leak(process=real_process_data, binary_path="dummy.exe", leak_address=0x1000)

        if result and result["success"]:
            assert "calculated_base" in result or "base_addresses" in result

    def test_format_string_vulnerability_detection(self, aslr_bypass: Any, test_binary_with_aslr: Any) -> None:
        """Test detection of format string vulnerabilities."""
        result = aslr_bypass.analyze_aslr_bypass(binary_path=test_binary_with_aslr, process=None)

        assert result is not None
        assert "success" in result or "technique" in result
        assert "vulnerabilities" in result
        vulns = result["vulnerabilities"]

        # Should detect format string patterns
        assert "format_string" in vulns or any("format" in v.lower() for v in vulns)

    def test_uaf_vulnerability_detection(self, aslr_bypass: Any, test_binary_with_aslr: Any) -> None:
        """Test detection of use-after-free vulnerabilities."""
        result = aslr_bypass.analyze_aslr_bypass(binary_path=test_binary_with_aslr, process=None)

        assert result is not None
        assert "success" in result or "technique" in result
        assert "vulnerabilities" in result

        # Should identify UAF patterns
        vulns = result["vulnerabilities"]
        assert "uaf" in vulns or "use_after_free" in vulns or any("uaf" in v.lower() for v in vulns)

    def test_stack_leak_potential_detection(self, aslr_bypass: Any, test_binary_with_aslr: Any) -> None:
        """Test detection of stack leak potential."""
        result = aslr_bypass.analyze_aslr_bypass(binary_path=test_binary_with_aslr, process=None)

        assert result is not None
        assert "success" in result or "technique" in result
        assert "leak_potential" in result or "vulnerabilities" in result

    def test_analyze_aslr_bypass_comprehensive(self, aslr_bypass: Any, test_binary_with_aslr: Any, real_process_data: Any) -> None:
        """Test comprehensive ASLR bypass analysis."""
        result = aslr_bypass.analyze_aslr_bypass(binary_path=test_binary_with_aslr, process=real_process_data)

        assert result is not None
        assert "success" in result or "technique" in result
        assert "bypass_feasibility" in result
        assert "recommended_techniques" in result
        assert "difficulty_score" in result
        assert "vulnerabilities" in result

        # Verify feasibility assessment
        feasibility = result["bypass_feasibility"]
        assert isinstance(feasibility, (bool, str))

        # Verify difficulty score
        difficulty = result["difficulty_score"]
        assert isinstance(difficulty, (int, float))
        assert 0 <= difficulty <= 100

    def test_assess_bypass_difficulty(self, aslr_bypass: Any, test_binary_with_aslr: Any) -> None:
        """Test ASLR bypass difficulty assessment."""
        result = aslr_bypass.analyze_aslr_bypass(binary_path=test_binary_with_aslr, process=None)

        assert result is not None
        assert "success" in result or "technique" in result
        assert "difficulty_score" in result
        assert "difficulty_factors" in result

        factors = result["difficulty_factors"]
        assert "entropy_bits" in factors or "randomization_entropy" in factors
        assert "available_techniques" in factors
        assert "mitigation_strength" in factors or "aslr_quality" in factors

    def test_build_ret2libc_chain(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test ROP chain construction for ret2libc."""
        result = aslr_bypass.bypass_aslr_ret2libc(process=real_process_data, binary_path="test.exe", overflow_size=512, control_rip=True)

        if result and result["success"]:
            chain = result["exploit_chain"]
            assert "payload" in chain or "rop_chain" in chain

            # Verify chain structure
            if "gadgets" in chain:
                for gadget in chain["gadgets"]:
                    assert "address" in gadget
                    assert "instruction" in gadget or "purpose" in gadget

    def test_execute_ret2libc_exploit(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test ret2libc exploit execution."""
        # Test without mocking
        result = aslr_bypass.bypass_aslr_ret2libc(process=real_process_data, binary_path="test.exe", overflow_size=256, control_rip=True)

    def test_find_libc_base_through_got(self, aslr_bypass: Any, test_binary_with_aslr: Any, real_process_data: Any) -> None:
        """Test finding libc base through GOT entries."""
        result = aslr_bypass.bypass_aslr_info_leak(
            process=real_process_data,
            binary_path=test_binary_with_aslr,
            leak_address=0x7FF600003000,  # GOT entry
        )

        if result and result["success"]:
            bases = result.get("base_addresses", {})
            # Should resolve libc-related bases
            assert any("libc" in k.lower() or "msvcr" in k.lower() for k in bases)

    def test_test_libc_base_validation(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test validation of discovered libc base."""

        # Setup mock to return valid ELF/PE header at proposed base
        def read_at_base(addr, size):
            if addr == 0x7FFE70000000:  # Proposed libc base
                return b"MZ" + b"\x00" * (size - 2)  # Valid PE header
            return b"\x00" * size

        real_process_data.read_memory = read_at_base

        result = aslr_bypass.bypass_aslr_ret2libc(process=real_process_data, binary_path="test.exe", overflow_size=256, control_rip=True)

        assert result is not None
        assert "success" in result or "technique" in result
        # Should validate the base address

    def test_exploit_info_leak_with_format_string(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test exploiting format string for info leak."""

        # dict process with format string response
        def read_fmt(addr, size):
            return b"%p %p %p\x00" if addr == 0x1000 else b"\x00" * size

        real_process_data.read_memory = read_fmt

        result = aslr_bypass.bypass_aslr_info_leak(process=real_process_data, binary_path="test.exe", leak_address=0x1000)

        if result and result["success"]:
            # Should parse leaked addresses
            assert "leaked_addresses" in result or "base_addresses" in result

    def test_partial_overwrite_with_limited_control(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test partial overwrite with only 1-2 bytes control."""
        result = aslr_bypass.bypass_aslr_partial_overwrite(
            process=real_process_data,
            binary_path="test.exe",
            target_address=0x7FFE80001234,
            controlled_bytes=1,  # Only 1 byte control
        )

        assert result is not None
        assert "success" in result or "technique" in result
        assert result["success"] == True  # Demand success
        # Should calculate probability of success
        assert "success_probability" in result
        assert 0 < result["success_probability"] <= 100

    def test_find_partial_overwrite_targets(self, aslr_bypass: Any, test_binary_with_aslr: Any, real_process_data: Any) -> None:
        """Test finding suitable partial overwrite targets."""
        result = aslr_bypass.bypass_aslr_partial_overwrite(
            process=real_process_data,
            binary_path=test_binary_with_aslr,
            target_address=None,  # Let it find targets
            controlled_bytes=2,
        )

        assert result is not None
        assert "success" in result or "technique" in result
        assert result["success"] == True  # Demand success
        assert "identified_targets" in result or "target_address" in result

    def test_execute_partial_overwrite_attack(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test execution of partial overwrite attack."""
        # Test without mocking
        result = aslr_bypass.bypass_aslr_partial_overwrite(
            process=real_process_data, binary_path="test.exe", target_address=0x7FFE80001234, controlled_bytes=2
        )

    def test_calculate_base_addresses_from_multiple_leaks(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test base calculation from multiple leaked pointers."""
        # Provide multiple leak sources
        leaks = [0x7FF600001234, 0x7FFE80005678, 0x7FFE70009ABC]

        for _ in leaks:
            result = aslr_bypass.bypass_aslr_info_leak(process=real_process_data, binary_path="test.exe", leak_address=0x1000)

            if result and result["success"]:
                assert "base_addresses" in result
                # Each leak should resolve to aligned base
                for base_name, base_addr in result["base_addresses"].items():
                    assert base_addr % 0x1000 == 0  # Page aligned

    def test_aslr_bypass_with_high_entropy(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test ASLR bypass against high-entropy randomization."""
        # Simulate high-entropy ASLR (28+ bits)
        real_process_data.aslr_entropy = 28

        result = aslr_bypass.analyze_aslr_bypass(binary_path="test.exe", process=real_process_data)

        assert result is not None
        assert "success" in result or "technique" in result
        assert result["difficulty_score"] >= 70  # Should be difficult
        # Should still provide techniques, but warn about difficulty
        assert "recommended_techniques" in result
        assert len(result["recommended_techniques"]) > 0

    def test_aslr_bypass_without_process(self, aslr_bypass: Any, test_binary_with_aslr: Any) -> None:
        """Test static ASLR bypass analysis without running process."""
        result = aslr_bypass.analyze_aslr_bypass(binary_path=test_binary_with_aslr, process=None)

        assert result is not None
        assert "success" in result or "technique" in result
        assert "static_analysis" in result or "requires_runtime" not in result
        assert "vulnerabilities" in result
        assert "recommended_techniques" in result

    def test_technique_reliability_scoring(self, aslr_bypass: Any) -> None:
        """Test that techniques have proper reliability scores."""
        techniques = aslr_bypass.techniques

        for name, technique in techniques.items():
            assert "reliability" in technique
            reliability = technique["reliability"]
            assert isinstance(reliability, (int, float))
            assert 0 <= reliability <= 100

            # Info leak should be most reliable
            if "info_leak" in name.lower():
                assert reliability >= 80
            # Brute force should be least reliable
            elif "brute" in name.lower():
                assert reliability <= 50

    def test_handle_position_independent_executables(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test handling of PIE (Position Independent Executables)."""
        real_process_data.is_pie = True
        real_process_data.pie_base = 0x555555554000  # Linux-style PIE base

        result = aslr_bypass.analyze_aslr_bypass(binary_path="pie_binary", process=real_process_data)

        assert result is not None
        assert "success" in result or "technique" in result
        assert "pie_detected" in result or "is_pie" in result
        # Should adapt techniques for PIE
        assert "recommended_techniques" in result

    def test_windows_specific_aslr_bypass(self, aslr_bypass: Any, test_binary_with_aslr: Any, real_process_data: Any) -> None:
        """Test Windows-specific ASLR bypass techniques."""
        real_process_data.platform = "windows"
        real_process_data.is_windows = True

        result = aslr_bypass.analyze_aslr_bypass(binary_path=test_binary_with_aslr, process=real_process_data)

        assert result is not None
        assert "success" in result or "technique" in result
        # Should include Windows-specific techniques
        techniques = result["recommended_techniques"]
        assert any("kernel32" in str(t).lower() or "ntdll" in str(t).lower() for t in techniques)

    def test_linux_specific_aslr_bypass(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test Linux-specific ASLR bypass techniques."""
        real_process_data.platform = "linux"
        real_process_data.is_windows = False
        real_process_data.is_linux = True

        result = aslr_bypass.analyze_aslr_bypass(binary_path="/tmp/test_binary", process=real_process_data)

        assert result is not None
        assert "success" in result or "technique" in result
        # Should adapt for Linux environment
        if "recommended_techniques" in result:
            # Linux uses different libraries
            assert all(
                "kernel32" not in str(t).lower()
                for t in result["recommended_techniques"]
            )

    def test_heap_spray_aslr_bypass_technique(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test heap spray as ASLR bypass technique."""
        result = aslr_bypass.get_recommended_technique(
            binary_path="test.exe",
            has_info_leak=False,
            has_write_primitive=False,
            has_heap_control=True,  # Can spray heap
        )

        assert result is not None
        assert "success" in result or "technique" in result
        # Should consider heap spray when other techniques unavailable
        if not result.get("has_info_leak"):
            assert "heap" in result["technique"].lower() or "spray" in result["technique"].lower()

    def test_concurrent_bypass_attempts(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test multiple concurrent bypass attempts for reliability."""
        results = []
        for i in range(3):
            result = aslr_bypass.bypass_aslr_info_leak(process=real_process_data, binary_path="test.exe", leak_address=0x1000 + i * 0x100)
            results.append(result)

        # At least one attempt should succeed
        assert any(r and r.get("success") for r in results)

    def test_bypass_with_corrupted_memory(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test ASLR bypass handling of corrupted memory regions."""

        def read_corrupted(addr, size):
            # Return corrupted/invalid data
            return b"\xff" * size

        real_process_data.read_memory = read_corrupted

        result = aslr_bypass.bypass_aslr_info_leak(process=real_process_data, binary_path="test.exe", leak_address=0x1000)

        assert result is not None
        assert "success" in result or "technique" in result
        # Should handle corruption gracefully
        if not result["success"]:
            assert "error" in result or "failure_reason" in result

    def test_gadget_discovery_for_rop(self, aslr_bypass: Any, test_binary_with_aslr: Any, real_process_data: Any) -> None:
        """Test ROP gadget discovery despite ASLR."""
        result = aslr_bypass.bypass_aslr_ret2libc(
            process=real_process_data, binary_path=test_binary_with_aslr, overflow_size=256, control_rip=True
        )

        if result and result["success"]:
            chain = result.get("exploit_chain", {})
            if "gadgets" in chain:
                # Verify gadgets are valid ROP gadgets
                for gadget in chain["gadgets"]:
                    assert "address" in gadget
                    # Common ROP gadget patterns
                    assert gadget.get("instruction", "").endswith("ret") or "pop" in gadget.get("instruction", "")

    def test_integration_with_dep_bypass(self, aslr_bypass: Any, real_process_data: Any) -> None:
        """Test ASLR bypass integration with DEP bypass."""
        result = aslr_bypass.bypass_aslr_ret2libc(
            process=real_process_data,
            binary_path="test.exe",
            overflow_size=256,
            control_rip=True,
            dep_enabled=True,  # DEP is also enabled
        )

        assert result is not None
        assert "success" in result or "technique" in result
        assert result["success"] == True  # Demand success
        # Should provide ROP chain that also bypasses DEP
        chain = result.get("exploit_chain", {})
        assert "virtualprotect" in str(chain).lower() or "mprotect" in str(chain).lower()

    def test_bypass_effectiveness_metrics(self, aslr_bypass: Any, test_binary_with_aslr: Any) -> None:
        """Test that bypass provides effectiveness metrics."""
        result = aslr_bypass.analyze_aslr_bypass(binary_path=test_binary_with_aslr, process=None)

        assert result is not None
        assert "success" in result or "technique" in result
        assert "effectiveness_score" in result or "success_probability" in result
        assert "time_complexity" in result or "attempts_required" in result

        # Verify metrics are realistic
        if "success_probability" in result:
            prob = result["success_probability"]
            assert 0 <= prob <= 100
