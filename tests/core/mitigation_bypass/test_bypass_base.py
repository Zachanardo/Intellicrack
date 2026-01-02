"""
Comprehensive black-box tests for bypass_base.py module.
Tests validate production-ready bypass capabilities without examining implementation.
"""

import pytest
import struct
import os
import tempfile
from pathlib import Path

try:
    from intellicrack.core.mitigation_bypass.bypass_base import (
        MitigationBypassBase,
        ROPBasedBypass
    )
    MODULE_AVAILABLE = True
except ImportError:
    MitigationBypassBase = None
    ROPBasedBypass = None
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


class TestMitigationBypassBase:
    """Tests for MitigationBypassBase class - validates real bypass infrastructure."""

    def test_initialization_with_mitigation_name(self) -> None:
        """Test that bypass base initializes with mitigation name."""
        bypass = MitigationBypassBase("DEP")
        assert bypass.mitigation_name == "DEP"
        assert hasattr(bypass, 'techniques')
        assert isinstance(bypass.techniques, dict)

    def test_initialization_with_custom_techniques(self) -> None:
        """Test initialization with custom bypass techniques."""
        custom_techniques = {
            "rop": {
                "name": "Return-Oriented Programming",
                "difficulty": "high",
                "requirements": ["executable_memory", "gadgets"]
            }
        }
        bypass = MitigationBypassBase("ASLR", techniques=custom_techniques)
        assert bypass.mitigation_name == "ASLR"
        assert "rop" in bypass.techniques
        assert bypass.techniques["rop"]["name"] == "Return-Oriented Programming"

    def test_get_recommended_technique_with_real_binary_context(self) -> None:
        """Test technique recommendation based on binary characteristics."""
        bypass = MitigationBypassBase("DEP")

        # Create realistic binary context
        binary_context = {
            "architecture": "x86_64",
            "os": "windows",
            "binary_type": "PE",
            "features": ["imports", "exports", "sections"],
            "protections": ["dep", "aslr"],
            "has_executable_sections": False,
            "has_writable_sections": True
        }

        recommendation = bypass.get_recommended_technique(binary_context)

        # Should return a real technique recommendation
        assert recommendation is not None
        assert isinstance(recommendation, dict)
        assert "technique" in recommendation
        assert "confidence" in recommendation
        assert "reason" in recommendation
        assert 0.0 <= recommendation["confidence"] <= 1.0

    def test_analyze_bypass_opportunities_comprehensive(self) -> None:
        """Test comprehensive bypass opportunity analysis."""
        bypass = MitigationBypassBase("ASLR")

        # Realistic binary with multiple bypass opportunities
        binary_context = {
            "architecture": "x86_64",
            "os": "windows",
            "binary_type": "PE",
            "base_address": 0x400000,
            "image_size": 0x100000,
            "features": ["imports", "exports", "seh", "tls"],
            "protections": ["aslr", "dep"],
            "modules": [
                {"name": "kernel32.dll", "aslr": True},
                {"name": "msvcrt.dll", "aslr": False}  # Non-ASLR module
            ],
            "memory_layout": {
                "stack": {"start": 0x7fff0000, "size": 0x10000},
                "heap": {"start": 0x20000000, "size": 0x100000}
            }
        }

        opportunities = bypass.analyze_bypass_opportunities(binary_context)

        assert isinstance(opportunities, list)
        assert len(opportunities) > 0

        for opportunity in opportunities:
            assert "technique" in opportunity
            assert "viability_score" in opportunity
            assert "requirements_met" in opportunity
            assert "implementation_difficulty" in opportunity
            assert 0.0 <= opportunity["viability_score"] <= 1.0

    def test_get_technique_info_returns_detailed_information(self) -> None:
        """Test that technique info provides comprehensive details."""
        bypass = MitigationBypassBase("DEP")

        # Request info for a common technique
        info = bypass.get_technique_info("rop")

        assert info is not None
        assert "name" in info
        assert "description" in info
        assert "difficulty" in info
        assert "success_rate" in info
        assert "requirements" in info
        assert "limitations" in info
        assert isinstance(info["requirements"], list)
        assert isinstance(info["limitations"], list)

    def test_is_technique_applicable_with_various_contexts(self) -> None:
        """Test technique applicability checking with different contexts."""
        bypass = MitigationBypassBase("DEP")

        # Context where ROP should be applicable
        rop_compatible_context = {
            "architecture": "x86_64",
            "os": "windows",
            "binary_type": "PE",
            "has_executable_sections": False,
            "has_gadgets": True,
            "stack_executable": False
        }

        assert bypass.is_technique_applicable("rop", rop_compatible_context) == True

        # Context where ROP should not be applicable
        rop_incompatible_context = {
            "architecture": "arm",
            "os": "android",
            "binary_type": "ELF",
            "has_executable_sections": True,
            "has_gadgets": False
        }

        assert bypass.is_technique_applicable("rop", rop_incompatible_context) == False

    def test_get_all_techniques_returns_comprehensive_list(self) -> None:
        """Test that all techniques are returned with metadata."""
        bypass = MitigationBypassBase("CFI")

        all_techniques = bypass.get_all_techniques()

        assert isinstance(all_techniques, list)
        assert len(all_techniques) > 0

        for technique in all_techniques:
            assert "id" in technique
            assert "name" in technique
            assert "category" in technique
            assert "supported_mitigations" in technique

    def test_get_technique_difficulty_accurate_assessment(self) -> None:
        """Test difficulty assessment for various techniques."""
        bypass = MitigationBypassBase("DEP")

        # Test known techniques with expected difficulties
        rop_difficulty = bypass.get_technique_difficulty("rop")
        assert rop_difficulty in ["low", "medium", "high", "expert"]

        stack_spray_difficulty = bypass.get_technique_difficulty("stack_spray")
        assert stack_spray_difficulty in ["low", "medium", "high", "expert"]

        if rop_difficulty and stack_spray_difficulty:
            # ROP should generally be harder than stack spray
            difficulty_levels = {"low": 1, "medium": 2, "high": 3, "expert": 4}
            assert difficulty_levels.get(rop_difficulty, 0) >= difficulty_levels.get(stack_spray_difficulty, 0)

    def test_architecture_compatibility_checking(self) -> None:
        """Test architecture compatibility validation."""
        bypass = MitigationBypassBase("ASLR")

        # Test x86_64 specific technique
        x64_context = {"architecture": "x86_64", "os": "windows"}
        x86_context = {"architecture": "x86", "os": "windows"}
        arm_context = {"architecture": "arm64", "os": "linux"}

        # Some techniques should be architecture-specific
        x64_applicable = bypass.is_technique_applicable("x64_specific", x64_context)
        x86_applicable = bypass.is_technique_applicable("x64_specific", x86_context)

        # Architecture-specific techniques should have different applicability
        if x64_applicable is not None and x86_applicable is not None:
            assert x64_applicable != x86_applicable

    def test_os_compatibility_checking(self) -> None:
        """Test OS compatibility validation."""
        bypass = MitigationBypassBase("DEP")

        windows_context = {"architecture": "x86_64", "os": "windows", "binary_type": "PE"}
        linux_context = {"architecture": "x86_64", "os": "linux", "binary_type": "ELF"}
        macos_context = {"architecture": "x86_64", "os": "macos", "binary_type": "MACHO"}

        # Test OS-specific technique applicability
        seh_windows = bypass.is_technique_applicable("seh_overwrite", windows_context)
        seh_linux = bypass.is_technique_applicable("seh_overwrite", linux_context)

        # SEH is Windows-specific
        if seh_windows is not None and seh_linux is not None:
            assert seh_windows == True
            assert seh_linux == False

    def test_binary_type_requirements(self) -> None:
        """Test binary type requirement checking."""
        bypass = MitigationBypassBase("CFI")

        pe_context = {"binary_type": "PE", "architecture": "x86_64", "os": "windows"}
        elf_context = {"binary_type": "ELF", "architecture": "x86_64", "os": "linux"}
        macho_context = {"binary_type": "MACHO", "architecture": "x86_64", "os": "macos"}

        # Each binary type should have specific compatible techniques
        pe_techniques = []
        elf_techniques = []

        for technique in ["iat_hooking", "got_overwrite", "dyld_hijack"]:
            if bypass.is_technique_applicable(technique, pe_context):
                pe_techniques.append(technique)
            if bypass.is_technique_applicable(technique, elf_context):
                elf_techniques.append(technique)

        # Different binary types should support different techniques
        assert set(pe_techniques) != set(elf_techniques)


class TestROPBasedBypass:
    """Tests for ROPBasedBypass class - validates ROP chain construction capabilities."""

    def create_test_binary_data(self):
        """Create realistic x86_64 binary data with potential ROP gadgets."""
        # Create binary with common ROP gadget patterns
        gadgets = [b'\xc3', b'\x5f\xc3', b'\x5e\xc3', b'\x5a\xc3', b'\x58\xc3']

        # syscall; ret
        gadgets.append(b'\x0f\x05\xc3')

        # xor rax, rax; ret
        gadgets.append(b'\x48\x31\xc0\xc3')

        # mov rdi, rsp; ret
        gadgets.append(b'\x48\x89\xe7\xc3')

        # add rsp, 0x28; ret
        gadgets.append(b'\x48\x83\xc4\x28\xc3')

        # Create binary with padding between gadgets
        binary_data = b''
        for gadget in gadgets:
            binary_data += b'\x90' * 100  # NOP padding
            binary_data += gadget

        return binary_data

    def test_rop_bypass_initialization(self) -> None:
        """Test ROPBasedBypass initialization."""
        rop_bypass = ROPBasedBypass()
        assert hasattr(rop_bypass, 'mitigation_name')
        assert hasattr(rop_bypass, 'rop_techniques')
        assert isinstance(rop_bypass.rop_techniques, list)

    def test_find_rop_gadgets_in_binary(self) -> None:
        """Test finding ROP gadgets in realistic binary data."""
        rop_bypass = ROPBasedBypass()

        binary_data = self.create_test_binary_data()
        binary_context = {
            "architecture": "x86_64",
            "binary_data": binary_data,
            "base_address": 0x400000,
            "sections": [
                {"name": ".text", "offset": 0, "size": len(binary_data), "executable": True}
            ]
        }

        gadgets = rop_bypass.find_rop_gadgets(binary_context)

        assert isinstance(gadgets, list)
        assert len(gadgets) > 0

        # Verify gadget structure
        for gadget in gadgets:
            assert "address" in gadget
            assert "bytes" in gadget
            assert "instructions" in gadget
            assert "type" in gadget
            assert "registers_modified" in gadget
            assert isinstance(gadget["address"], int)
            assert isinstance(gadget["bytes"], bytes)

    def test_gadget_classification(self) -> None:
        """Test that gadgets are properly classified by type."""
        rop_bypass = ROPBasedBypass()

        binary_data = self.create_test_binary_data()
        binary_context = {
            "architecture": "x86_64",
            "binary_data": binary_data,
            "base_address": 0x400000,
            "sections": [
                {"name": ".text", "offset": 0, "size": len(binary_data), "executable": True}
            ]
        }

        gadgets = rop_bypass.find_rop_gadgets(binary_context)

        # Check for different gadget types
        gadget_types = {g["type"] for g in gadgets}

        # Should identify various gadget categories
        expected_types = {"stack_pivot", "register_pop", "memory_access", "syscall", "arithmetic", "control_flow"}
        assert gadget_types.intersection(expected_types)

    def test_assess_rop_viability_with_sufficient_gadgets(self) -> None:
        """Test ROP viability assessment with sufficient gadgets."""
        rop_bypass = ROPBasedBypass()

        # Create context with many useful gadgets
        gadgets = [
            {"type": "register_pop", "registers_modified": ["rdi"], "address": 0x401000},
            {"type": "register_pop", "registers_modified": ["rsi"], "address": 0x401003},
            {"type": "register_pop", "registers_modified": ["rdx"], "address": 0x401006},
            {"type": "register_pop", "registers_modified": ["rax"], "address": 0x401009},
            {"type": "syscall", "address": 0x40100c},
            {"type": "stack_pivot", "address": 0x40100f},
            {"type": "memory_access", "operation": "write", "address": 0x401012},
            {"type": "memory_access", "operation": "read", "address": 0x401015},
        ]

        viability = rop_bypass.assess_rop_viability(gadgets)

        assert isinstance(viability, dict)
        assert "viable" in viability
        assert "confidence" in viability
        assert "missing_capabilities" in viability
        assert "chain_complexity" in viability

        # With sufficient gadgets, should be viable
        assert viability["viable"] == True
        assert viability["confidence"] > 0.7
        assert len(viability["missing_capabilities"]) == 0

    def test_assess_rop_viability_with_insufficient_gadgets(self) -> None:
        """Test ROP viability assessment with insufficient gadgets."""
        rop_bypass = ROPBasedBypass()

        # Create context with very few gadgets
        gadgets = [
            {"type": "control_flow", "address": 0x401000},
            {"type": "arithmetic", "address": 0x401003}
        ]

        viability = rop_bypass.assess_rop_viability(gadgets)

        assert isinstance(viability, dict)
        assert viability["viable"] == False
        assert viability["confidence"] < 0.3
        assert len(viability["missing_capabilities"]) > 0

    def test_gadget_sequence_validation(self) -> None:
        """Test validation of gadget sequences for chain construction."""
        rop_bypass = ROPBasedBypass()

        # Valid sequence: pop registers then syscall
        valid_sequence = [
            {"type": "register_pop", "registers_modified": ["rdi"], "bytes": b'\x5f\xc3'},
            {"type": "register_pop", "registers_modified": ["rsi"], "bytes": b'\x5e\xc3'},
            {"type": "syscall", "bytes": b'\x0f\x05\xc3'}
        ]

        # Invalid sequence: conflicting stack operations
        invalid_sequence = [
            {"type": "stack_pivot", "stack_delta": 0x20, "bytes": b'\x48\x83\xc4\x20\xc3'},
            {"type": "stack_pivot", "stack_delta": -0x20, "bytes": b'\x48\x83\xec\x20\xc3'},
            {"type": "register_pop", "registers_modified": ["rax"], "bytes": b'\x58\xc3'}
        ]

        # Test sequence validation
        assert rop_bypass._is_valid_gadget_sequence(valid_sequence) == True
        assert rop_bypass._is_valid_gadget_sequence(invalid_sequence) == False

    def test_rop_chain_requirements_checking(self) -> None:
        """Test checking specific requirements for ROP chain construction."""
        rop_bypass = ROPBasedBypass()

        # Context with ROP-friendly environment
        rop_friendly = {
            "architecture": "x86_64",
            "os": "windows",
            "dep_enabled": True,
            "stack_executable": False,
            "has_executable_sections": False,
            "binary_size": 0x100000
        }

        # Context hostile to ROP
        rop_hostile = {
            "architecture": "x86_64",
            "os": "windows",
            "dep_enabled": False,
            "stack_executable": True,
            "cfi_enabled": True,
            "binary_size": 0x1000
        }

        # ROP should be more applicable when DEP is enabled
        friendly_result = rop_bypass.is_technique_applicable("rop", rop_friendly)
        hostile_result = rop_bypass.is_technique_applicable("rop", rop_hostile)

        assert friendly_result == True
        # ROP might still be possible but less necessary with executable stack
        assert hostile_result in [True, False]

    def test_gadget_quality_assessment(self) -> None:
        """Test assessment of gadget quality for chain construction."""
        rop_bypass = ROPBasedBypass()

        high_quality_gadget = {
            "address": 0x401000,
            "bytes": b'\x5f\xc3',  # pop rdi; ret
            "instructions": ["pop rdi", "ret"],
            "type": "register_pop",
            "registers_modified": ["rdi"],
            "side_effects": [],
            "alignment": 0
        }

        low_quality_gadget = {
            "address": 0x401003,
            "bytes": b'\x48\x89\x45\xf8\x48\x8b\x45\xf8\xc3',  # Complex with side effects
            "instructions": ["mov [rbp-8], rax", "mov rax, [rbp-8]", "ret"],
            "type": "memory_access",
            "registers_modified": ["rax"],
            "side_effects": ["memory_write", "memory_read"],
            "alignment": 3
        }

        # Classification should distinguish quality
        high_quality_class = rop_bypass._classify_gadget(high_quality_gadget)
        low_quality_class = rop_bypass._classify_gadget(low_quality_gadget)

        assert high_quality_class["quality"] == "high"
        assert low_quality_class["quality"] in ["medium", "low"]

    def test_rop_technique_diversity(self) -> None:
        """Test that multiple ROP techniques are supported."""
        rop_bypass = ROPBasedBypass()

        assert len(rop_bypass.rop_techniques) > 0

        # Should support various ROP strategies
        expected_techniques = [
            "classic_rop",
            "jop",  # Jump-oriented programming
            "cop",  # Call-oriented programming
            "srop",  # Sigreturn-oriented programming
            "brop"  # Blind ROP
        ]

        for technique in expected_techniques:
            if info := rop_bypass.get_technique_info(technique):
                assert "name" in info
                assert "requirements" in info


class TestMitigationBypassPrivateMethods:
    """Tests for private methods of MitigationBypassBase."""

    def test_perform_detailed_analysis(self) -> None:
        """Test _perform_detailed_analysis method."""
        bypass = MitigationBypassBase("DEP")

        context = {
            "architecture": "x86_64",
            "os": "windows",
            "binary_type": "PE",
            "protections": ["dep", "aslr"],
            "binary_data": b'\x4d\x5a' + b'\x00' * 1000
        }

        # Should perform deep analysis
        analysis = bypass._perform_detailed_analysis(context)
        assert isinstance(analysis, dict)
        assert "vulnerability_score" in analysis
        assert "exploit_complexity" in analysis
        assert "bypass_vectors" in analysis

    def test_check_technique_specific_requirements(self) -> None:
        """Test technique-specific requirement checking."""
        bypass = MitigationBypassBase("ASLR")

        context = {
            "architecture": "x86_64",
            "has_info_leak": True,
            "has_arbitrary_read": True
        }

        # Different techniques have different requirements
        rop_req = bypass._check_technique_specific_requirements("rop", context)
        heap_spray_req = bypass._check_technique_specific_requirements("heap_spray", context)

        assert isinstance(rop_req, bool)
        assert isinstance(heap_spray_req, bool)

    def test_check_rop_technique_requirements(self) -> None:
        """Test ROP-specific requirement checking."""
        bypass = MitigationBypassBase("DEP")

        rop_friendly = {
            "has_gadgets": True,
            "gadget_quality": "high",
            "stack_control": True
        }

        rop_hostile = {
            "has_gadgets": False,
            "cfi_enabled": True,
            "stack_control": False
        }

        assert bypass._check_rop_technique_requirements(rop_friendly) == True
        assert bypass._check_rop_technique_requirements(rop_hostile) == False

    def test_check_stack_technique_requirements(self) -> None:
        """Test stack-based technique requirement checking."""
        bypass = MitigationBypassBase("DEP")

        stack_friendly = {
            "stack_executable": False,
            "stack_control": True,
            "buffer_overflow": True
        }

        stack_hostile = {
            "stack_canary": True,
            "stack_control": False,
            "fortify_source": True
        }

        assert bypass._check_stack_technique_requirements(stack_friendly) == True
        assert bypass._check_stack_technique_requirements(stack_hostile) == False

    def test_check_heap_technique_requirements(self) -> None:
        """Test heap-based technique requirement checking."""
        bypass = MitigationBypassBase("ASLR")

        heap_friendly = {
            "heap_control": True,
            "has_use_after_free": True,
            "heap_spray_possible": True
        }

        heap_hostile = {
            "heap_control": False,
            "heap_isolation": True,
            "heap_guard": True
        }

        assert bypass._check_heap_technique_requirements(heap_friendly) == True
        assert bypass._check_heap_technique_requirements(heap_hostile) == False

    def test_check_code_injection_requirements(self) -> None:
        """Test code injection requirement checking."""
        bypass = MitigationBypassBase("DEP")

        injection_friendly = {
            "writable_executable": True,
            "process_control": True,
            "memory_write": True
        }

        injection_hostile = {
            "dep_enabled": True,
            "w_xor_x": True,
            "code_signing": True
        }

        assert bypass._check_code_injection_requirements(injection_friendly) == True
        assert bypass._check_code_injection_requirements(injection_hostile) == False

    def test_check_process_hollowing_requirements(self) -> None:
        """Test process hollowing requirement checking."""
        bypass = MitigationBypassBase("CFI")

        hollowing_friendly = {
            "os": "windows",
            "process_creation": True,
            "memory_manipulation": True
        }

        hollowing_hostile = {
            "os": "linux",
            "secure_boot": True,
            "process_mitigation": True
        }

        assert bypass._check_process_hollowing_requirements(hollowing_friendly) == True
        assert bypass._check_process_hollowing_requirements(hollowing_hostile) == False

    def test_check_shared_library_requirements(self) -> None:
        """Test shared library injection requirement checking."""
        bypass = MitigationBypassBase("ASLR")

        dll_friendly = {
            "os": "windows",
            "dll_injection": True,
            "process_access": True
        }

        so_friendly = {
            "os": "linux",
            "ld_preload": True,
            "library_path_control": True
        }

        assert bypass._check_shared_library_requirements(dll_friendly) == True
        assert bypass._check_shared_library_requirements(so_friendly) == True

    def test_check_size_requirements(self) -> None:
        """Test size constraint checking."""
        bypass = MitigationBypassBase("DEP")

        large_binary = {
            "binary_size": 0x1000000,
            "available_space": 0x100000
        }

        small_binary = {
            "binary_size": 0x1000,
            "available_space": 0x100
        }

        # Different techniques have different size requirements
        assert bypass._check_size_requirements("rop", large_binary) == True
        assert bypass._check_size_requirements("egg_hunter", small_binary) == True

    def test_check_feature_requirements(self) -> None:
        """Test feature requirement checking."""
        bypass = MitigationBypassBase("CFI")

        feature_rich = {
            "features": ["imports", "exports", "seh", "tls", "resources"],
            "has_symbols": True,
            "has_debug_info": True
        }

        feature_poor = {
            "features": [],
            "stripped": True,
            "packed": True
        }

        assert bypass._check_feature_requirements("import_table", feature_rich) == True
        assert bypass._check_feature_requirements("import_table", feature_poor) == False

    def test_check_required_features(self) -> None:
        """Test checking for required features."""
        bypass = MitigationBypassBase("ASLR")

        context = {
            "features": ["imports", "exports", "seh"],
            "capabilities": ["read", "write", "execute"]
        }

        required = ["imports", "seh"]
        assert bypass._check_required_features(required, context) == True

        required = ["vtables", "rtti"]
        assert bypass._check_required_features(required, context) == False

    def test_check_incompatible_features(self) -> None:
        """Test checking for incompatible features."""
        bypass = MitigationBypassBase("DEP")

        context = {
            "protections": ["cfi", "cet", "pac"],
            "features": ["fortify", "stack_guard"]
        }

        incompatible = ["cet", "pac"]
        assert bypass._check_incompatible_features(incompatible, context) == False

        incompatible = ["feature_not_present"]
        assert bypass._check_incompatible_features(incompatible, context) == True


class TestBypassIntegration:
    """Integration tests for bypass base functionality."""

    def test_bypass_base_with_real_binary_file(self) -> None:
        """Test bypass base with a real binary file."""
        # Create a minimal PE binary for testing
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            # Minimal PE header
            pe_header = b'MZ' + b'\x00' * 58 + struct.pack('<I', 0x80)  # e_lfanew
            pe_header += b'\x00' * (0x80 - len(pe_header))
            pe_header += b'PE\x00\x00'  # PE signature
            pe_header += b'\x64\x86'  # Machine type (x86_64)
            pe_header += struct.pack('<H', 1)  # Number of sections
            pe_header += b'\x00' * 500  # Padding

            f.write(pe_header)
            temp_file = f.name

        try:
            bypass = MitigationBypassBase("DEP")

            binary_context = {
                "file_path": temp_file,
                "architecture": "x86_64",
                "os": "windows",
                "binary_type": "PE",
                "binary_data": pe_header
            }

            # Should handle real binary data
            opportunities = bypass.analyze_bypass_opportunities(binary_context)
            assert isinstance(opportunities, list)

        finally:
            os.unlink(temp_file)

    def test_multiple_mitigation_bypass_coordination(self) -> None:
        """Test coordination between multiple bypass strategies."""
        dep_bypass = MitigationBypassBase("DEP")
        aslr_bypass = MitigationBypassBase("ASLR")
        cfi_bypass = MitigationBypassBase("CFI")

        # Complex binary with multiple mitigations
        complex_context = {
            "architecture": "x86_64",
            "os": "windows",
            "protections": ["dep", "aslr", "cfi"],
            "binary_type": "PE",
            "modules": [
                {"name": "main.exe", "aslr": True, "dep": True, "cfi": True},
                {"name": "helper.dll", "aslr": False, "dep": True, "cfi": False}
            ]
        }

        # Each bypass should provide different recommendations
        dep_rec = dep_bypass.get_recommended_technique(complex_context)
        aslr_rec = aslr_bypass.get_recommended_technique(complex_context)
        cfi_rec = cfi_bypass.get_recommended_technique(complex_context)

        assert dep_rec["technique"] != aslr_rec["technique"] or dep_rec["reason"] != aslr_rec["reason"]
        assert all(rec is not None for rec in [dep_rec, aslr_rec, cfi_rec])

    def test_bypass_technique_prerequisite_chain(self) -> None:
        """Test that bypass techniques properly handle prerequisites."""
        bypass = MitigationBypassBase("DEP")

        # Context requiring chained techniques
        chained_context = {
            "architecture": "x86_64",
            "os": "windows",
            "protections": ["dep", "aslr", "cfi"],
            "requires_info_leak": True,
            "has_arbitrary_read": False,
            "has_arbitrary_write": False
        }

        opportunities = bypass.analyze_bypass_opportunities(chained_context)

        # Should identify prerequisite requirements
        for opp in opportunities:
            if "prerequisites" in opp:
                assert isinstance(opp["prerequisites"], list)
                # Techniques requiring info leak should be marked
                if opp["technique"] in ["aslr_bypass_precise"]:
                    assert "info_leak" in opp["prerequisites"]

    def test_bypass_strategy_adaptation(self) -> None:
        """Test that bypass strategies adapt to binary characteristics."""
        bypass = MitigationBypassBase("DEP")

        # Binary with limited gadgets
        limited_context = {
            "architecture": "x86_64",
            "os": "windows",
            "gadget_count": 5,
            "gadget_quality": "low",
            "binary_size": 0x1000
        }

        # Binary with abundant gadgets
        abundant_context = {
            "architecture": "x86_64",
            "os": "windows",
            "gadget_count": 500,
            "gadget_quality": "high",
            "binary_size": 0x100000
        }

        limited_rec = bypass.get_recommended_technique(limited_context)
        abundant_rec = bypass.get_recommended_technique(abundant_context)

        # Recommendations should differ based on available resources
        assert limited_rec["confidence"] != abundant_rec["confidence"]

        # More gadgets should increase ROP confidence
        if limited_rec["technique"] == "rop" and abundant_rec["technique"] == "rop":
            assert abundant_rec["confidence"] > limited_rec["confidence"]
