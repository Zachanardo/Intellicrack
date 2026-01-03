"""Production tests for ROP generator - NO MOCKS.

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


from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.rop_generator import ROPChainGenerator

SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
KERNEL32 = SYSTEM32 / "kernel32.dll"
NTDLL = SYSTEM32 / "ntdll.dll"
USER32 = SYSTEM32 / "user32.dll"
MSVCRT = SYSTEM32 / "msvcrt.dll"


@pytest.fixture
def kernel32_generator() -> ROPChainGenerator:
    """Generator configured with kernel32.dll."""
    gen = ROPChainGenerator({"arch": "x86_64", "max_chain_length": 20, "max_gadget_size": 10})
    assert gen.set_binary(str(KERNEL32)), "Failed to set kernel32.dll as binary"
    return gen


@pytest.fixture
def ntdll_generator() -> ROPChainGenerator:
    """Generator configured with ntdll.dll."""
    gen = ROPChainGenerator({"arch": "x86_64", "max_chain_length": 20, "max_gadget_size": 10})
    assert gen.set_binary(str(NTDLL)), "Failed to set ntdll.dll as binary"
    return gen


@pytest.fixture
def user32_generator() -> ROPChainGenerator:
    """Generator configured with user32.dll."""
    gen = ROPChainGenerator({"arch": "x86_64", "max_chain_length": 20, "max_gadget_size": 10})
    assert gen.set_binary(str(USER32)), "Failed to set user32.dll as binary"
    return gen


@pytest.fixture
def temp_pe_binary() -> Path:
    """Create a minimal PE binary with known gadget sequences."""
    pe_header = (
        b"MZ"
        + b"\x90" * 58
        + struct.pack("<I", 0x80)
        + b"\x00" * 64
        + b"PE\x00\x00"
        + b"\x64\x86"
        + struct.pack("<H", 1)
        + b"\x00" * 16
        + struct.pack("<H", 0xE0)
        + struct.pack("<H", 0x020B)
        + b"\x00" * 106
    )

    gadget_code = (
        b"\x58\xc3"
        b"\x59\xc3"
        b"\x5a\xc3"
        b"\x5b\xc3"
        b"\x5c\xc3"
        b"\x5d\xc3"
        b"\x5e\xc3"
        b"\x5f\xc3"
        b"\x31\xc0\xc3"
        b"\x31\xc9\xc3"
        b"\x89\xc0\xc3"
        b"\xc3"
        b"\xc2\x04\x00"
    )

    code_section = gadget_code + b"\x00" * (4096 - len(gadget_code))

    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(pe_header + code_section)
        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


class TestROPGeneratorInitialization:
    """Test ROP generator initialization and configuration."""

    def test_initialization_default_config(self) -> None:
        """Generator initializes with default configuration."""
        gen = ROPChainGenerator()

        assert gen.config == {}
        assert gen.binary_path is None
        assert gen.gadgets == []
        assert gen.chains == []
        assert gen.target_functions == []
        assert gen.max_chain_length == 20
        assert gen.max_gadget_size == 10
        assert gen.arch == "x86_64"

    def test_initialization_custom_config(self) -> None:
        """Generator initializes with custom configuration."""
        config = {"max_chain_length": 30, "max_gadget_size": 15, "arch": "x86"}

        gen = ROPChainGenerator(config)

        assert gen.config == config
        assert gen.max_chain_length == 30
        assert gen.max_gadget_size == 15
        assert gen.arch == "x86"

    def test_set_binary_valid_dll(self) -> None:
        """Set binary succeeds with valid Windows DLL."""
        gen = ROPChainGenerator()

        result = gen.set_binary(str(KERNEL32))

        assert result is True
        assert gen.binary_path == str(KERNEL32)

    def test_set_binary_invalid_path(self) -> None:
        """Set binary fails with invalid path."""
        gen = ROPChainGenerator()

        result = gen.set_binary("D:\\nonexistent\\fake.dll")

        assert result is False
        assert gen.binary_path is None

    def test_set_binary_empty_path(self) -> None:
        """Set binary fails with empty path."""
        gen = ROPChainGenerator()

        result = gen.set_binary("")

        assert result is False


class TestGadgetDiscoveryKernel32:
    """Test gadget discovery in kernel32.dll."""

    def test_find_gadgets_discovers_gadgets(self, kernel32_generator: ROPChainGenerator) -> None:
        """Find gadgets discovers real gadgets in kernel32.dll."""
        result = kernel32_generator.find_gadgets()

        assert result is True
        assert len(kernel32_generator.gadgets) > 0
        assert isinstance(kernel32_generator.gadgets, list)

    def test_find_gadgets_discovers_minimum_gadgets(self, kernel32_generator: ROPChainGenerator) -> None:
        """Find gadgets discovers substantial number of gadgets."""
        kernel32_generator.find_gadgets()

        assert len(kernel32_generator.gadgets) >= 10, "Should find at least 10 gadgets in kernel32.dll"

    def test_gadgets_have_required_fields(self, kernel32_generator: ROPChainGenerator) -> None:
        """Discovered gadgets contain required fields."""
        kernel32_generator.find_gadgets()

        for gadget in kernel32_generator.gadgets[:10]:
            assert "address" in gadget
            assert "instruction" in gadget
            assert "type" in gadget
            assert isinstance(gadget["address"], (int, str))
            assert isinstance(gadget["instruction"], str)
            assert isinstance(gadget["type"], str)

    def test_gadgets_have_valid_addresses(self, kernel32_generator: ROPChainGenerator) -> None:
        """Gadget addresses are within valid ranges."""
        kernel32_generator.find_gadgets()

        for gadget in kernel32_generator.gadgets[:20]:
            addr = gadget["address"]
            if isinstance(addr, str):
                addr = int(addr, 16)
            assert addr > 0, f"Address should be positive: {hex(addr)}"
            assert addr < 0xFFFFFFFFFFFFFFFF, f"Address should be valid: {hex(addr)}"

    def test_find_gadgets_discovers_pop_ret_gadgets(self, kernel32_generator: ROPChainGenerator) -> None:
        """Find gadgets discovers pop/ret gadgets."""
        kernel32_generator.find_gadgets()

        pop_ret_gadgets = [g for g in kernel32_generator.gadgets if g["type"] == "pop_reg"]

        assert pop_ret_gadgets, "Should find pop/ret gadgets in kernel32.dll"

    def test_find_gadgets_discovers_ret_gadgets(self, kernel32_generator: ROPChainGenerator) -> None:
        """Find gadgets discovers pure ret gadgets."""
        kernel32_generator.find_gadgets()

        ret_gadgets = [g for g in kernel32_generator.gadgets if g["type"] == "ret"]

        assert ret_gadgets, "Should find ret gadgets in kernel32.dll"

    def test_gadget_instructions_are_valid(self, kernel32_generator: ROPChainGenerator) -> None:
        """Gadget instructions contain valid assembly mnemonics."""
        kernel32_generator.find_gadgets()

        valid_mnemonics = ["pop", "ret", "mov", "xor", "add", "sub", "push", "jmp", "call", "inc", "dec"]

        for gadget in kernel32_generator.gadgets[:30]:
            instr = gadget["instruction"].lower()
            has_valid_mnemonic = any(mnem in instr for mnem in valid_mnemonics)
            assert has_valid_mnemonic, f"Invalid instruction: {instr}"

    def test_gadgets_end_with_control_transfer(self, kernel32_generator: ROPChainGenerator) -> None:
        """Gadgets end with control transfer instructions."""
        kernel32_generator.find_gadgets()

        control_keywords = ["ret", "jmp", "call"]

        for gadget in kernel32_generator.gadgets[:20]:
            instr = gadget["instruction"].lower()
            has_control_transfer = any(kw in instr for kw in control_keywords)
            assert has_control_transfer, f"Gadget doesn't end with control transfer: {instr}"

    def test_find_gadgets_clears_previous_gadgets(self, kernel32_generator: ROPChainGenerator) -> None:
        """Find gadgets clears previously found gadgets."""
        kernel32_generator.find_gadgets()
        first_count = len(kernel32_generator.gadgets)

        kernel32_generator.find_gadgets()
        second_count = len(kernel32_generator.gadgets)

        assert second_count > 0
        assert first_count == second_count

    def test_find_gadgets_without_binary_fails(self) -> None:
        """Find gadgets fails when no binary is set."""
        gen = ROPChainGenerator()

        result = gen.find_gadgets()

        assert result is False
        assert len(gen.gadgets) == 0


class TestGadgetDiscoveryNtdll:
    """Test gadget discovery in ntdll.dll."""

    def test_find_gadgets_ntdll_discovers_gadgets(self, ntdll_generator: ROPChainGenerator) -> None:
        """Find gadgets discovers real gadgets in ntdll.dll."""
        result = ntdll_generator.find_gadgets()

        assert result is True
        assert len(ntdll_generator.gadgets) > 0

    def test_ntdll_gadgets_minimum_count(self, ntdll_generator: ROPChainGenerator) -> None:
        """Ntdll contains substantial number of gadgets."""
        ntdll_generator.find_gadgets()

        assert len(ntdll_generator.gadgets) >= 10, "Should find at least 10 gadgets in ntdll.dll"

    def test_ntdll_gadgets_have_diverse_types(self, ntdll_generator: ROPChainGenerator) -> None:
        """Ntdll gadgets include diverse types."""
        ntdll_generator.find_gadgets()

        gadget_types = {g["type"] for g in ntdll_generator.gadgets}

        assert len(gadget_types) > 1, "Should find multiple gadget types"

    def test_ntdll_gadgets_include_arithmetic(self, ntdll_generator: ROPChainGenerator) -> None:
        """Ntdll gadgets include arithmetic operations."""
        ntdll_generator.find_gadgets()

        arith_gadgets = [g for g in ntdll_generator.gadgets if g["type"] in ["arith_reg", "logic_reg"]]

        assert arith_gadgets, "Should find arithmetic/logic gadgets"


class TestGadgetClassification:
    """Test gadget classification functionality."""

    def test_gadget_type_classification(self, kernel32_generator: ROPChainGenerator) -> None:
        """Gadgets are classified into appropriate types."""
        kernel32_generator.find_gadgets()

        valid_types = ["pop_reg", "ret", "mov_reg_reg", "arith_reg", "logic_reg", "inc_dec_reg", "misc", "jmp_reg", "call_reg"]

        for gadget in kernel32_generator.gadgets:
            assert gadget["type"] in valid_types, f"Invalid gadget type: {gadget['type']}"

    def test_pop_gadget_classification(self, kernel32_generator: ROPChainGenerator) -> None:
        """Pop gadgets are correctly classified."""
        kernel32_generator.find_gadgets()

        pop_gadgets = [g for g in kernel32_generator.gadgets if g["type"] == "pop_reg"]

        for gadget in pop_gadgets[:5]:
            assert "pop" in gadget["instruction"].lower(), f"Pop gadget missing 'pop': {gadget['instruction']}"

    def test_ret_gadget_classification(self, kernel32_generator: ROPChainGenerator) -> None:
        """Ret gadgets are correctly classified."""
        kernel32_generator.find_gadgets()

        ret_gadgets = [g for g in kernel32_generator.gadgets if g["type"] == "ret"]

        for gadget in ret_gadgets[:5]:
            instr = gadget["instruction"].lower()
            assert "ret" in instr or instr == "ret", f"Ret gadget invalid: {gadget['instruction']}"

    def test_gadget_size_field_present(self, kernel32_generator: ROPChainGenerator) -> None:
        """Gadgets have size field."""
        kernel32_generator.find_gadgets()

        for gadget in kernel32_generator.gadgets[:10]:
            assert "size" in gadget
            assert isinstance(gadget["size"], int)
            assert gadget["size"] > 0


class TestGadgetFiltering:
    """Test gadget filtering and deduplication."""

    def test_gadgets_are_unique(self, kernel32_generator: ROPChainGenerator) -> None:
        """Discovered gadgets are unique."""
        kernel32_generator.find_gadgets()

        instructions = [g["instruction"] for g in kernel32_generator.gadgets]
        unique_instructions = set(instructions)

        assert len(instructions) == len(unique_instructions), "Gadgets contain duplicates"

    def test_gadgets_sorted_by_address(self, kernel32_generator: ROPChainGenerator) -> None:
        """Gadgets are sorted by address."""
        kernel32_generator.find_gadgets()

        addresses = []
        for g in kernel32_generator.gadgets:
            addr = g["address"]
            if isinstance(addr, str):
                addr = int(addr, 16)
            addresses.append(addr)

        assert addresses == sorted(addresses), "Gadgets not sorted by address"

    def test_gadget_count_within_limit(self, kernel32_generator: ROPChainGenerator) -> None:
        """Gadget count respects reasonable limits."""
        kernel32_generator.find_gadgets()

        assert len(kernel32_generator.gadgets) <= 200, "Too many gadgets returned (exceeds limit)"


class TestChainGeneration:
    """Test ROP chain generation."""

    def test_generate_chains_succeeds(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate chains succeeds with valid configuration."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("check_license", None, "License check function")

        result = kernel32_generator.generate_chains()

        assert result is True
        assert len(kernel32_generator.chains) > 0

    def test_generate_chains_adds_default_targets(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate chains adds default targets when none specified."""
        kernel32_generator.find_gadgets()

        result = kernel32_generator.generate_chains()

        assert result is True
        assert len(kernel32_generator.target_functions) > 0

    def test_generate_chains_finds_gadgets_automatically(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate chains finds gadgets if not already found."""
        kernel32_generator.add_target_function("validate_key", None, "Key validation")

        result = kernel32_generator.generate_chains()

        assert result is True
        assert len(kernel32_generator.gadgets) > 0
        assert len(kernel32_generator.chains) > 0

    def test_generate_chains_without_binary_fails(self) -> None:
        """Generate chains fails when no binary is set."""
        gen = ROPChainGenerator()

        result = gen.generate_chains()

        assert result is False
        assert len(gen.chains) == 0

    def test_chains_have_required_fields(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generated chains contain required fields."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("strcmp", None, "String comparison")
        kernel32_generator.generate_chains()

        for chain in kernel32_generator.chains:
            assert "target" in chain
            assert "gadgets" in chain
            assert "payload" in chain
            assert "length" in chain
            assert "description" in chain
            assert isinstance(chain["gadgets"], list)
            assert isinstance(chain["payload"], list)

    def test_chains_contain_gadgets(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generated chains contain actual gadgets."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("memcmp", None, "Memory comparison")
        kernel32_generator.generate_chains()

        for chain in kernel32_generator.chains:
            assert len(chain["gadgets"]) > 0, "Chain has no gadgets"
            assert chain["length"] == len(chain["gadgets"])

    def test_chain_gadgets_are_from_discovered_set(self, kernel32_generator: ROPChainGenerator) -> None:
        """Chain gadgets come from discovered gadget set."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("is_activated", None, "Activation check")
        kernel32_generator.generate_chains()

        discovered_addresses = {g["address"] for g in kernel32_generator.gadgets}

        for chain in kernel32_generator.chains:
            for gadget in chain["gadgets"]:
                assert gadget["address"] in discovered_addresses, f"Chain uses undiscovered gadget: {gadget['address']}"

    def test_generate_chains_clears_previous_chains(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate chains clears previously generated chains."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("check_license", None, "License check")
        kernel32_generator.generate_chains()
        first_count = len(kernel32_generator.chains)

        kernel32_generator.generate_chains()
        second_count = len(kernel32_generator.chains)

        assert first_count > 0
        assert second_count == first_count


class TestTargetFunctionManagement:
    """Test target function management."""

    def test_add_target_function_basic(self) -> None:
        """Add target function succeeds."""
        gen = ROPChainGenerator()

        gen.add_target_function("check_license", "0x401000", "License validation function")

        assert len(gen.target_functions) == 1
        assert gen.target_functions[0]["name"] == "check_license"
        assert gen.target_functions[0]["address"] == "0x401000"
        assert gen.target_functions[0]["description"] == "License validation function"

    def test_add_target_function_without_address(self) -> None:
        """Add target function without address."""
        gen = ROPChainGenerator()

        gen.add_target_function("validate_key", None, "Key validation")

        assert len(gen.target_functions) == 1
        assert gen.target_functions[0]["address"] is None

    def test_add_target_function_without_description(self) -> None:
        """Add target function uses default description."""
        gen = ROPChainGenerator()

        gen.add_target_function("is_activated", None, None)

        assert len(gen.target_functions) == 1
        assert "is_activated" in gen.target_functions[0]["description"]

    def test_add_multiple_target_functions(self) -> None:
        """Add multiple target functions."""
        gen = ROPChainGenerator()

        gen.add_target_function("check_license", None, "License check")
        gen.add_target_function("validate_key", None, "Key validation")
        gen.add_target_function("is_activated", None, "Activation check")

        assert len(gen.target_functions) == 3

    def test_default_targets_include_license_functions(self) -> None:
        """Default targets include license-related functions."""
        gen = ROPChainGenerator()

        gen._add_default_targets()

        assert len(gen.target_functions) > 0

        target_names = [t["name"] for t in gen.target_functions]
        license_targets = ["check_license", "validate_key", "is_activated", "memcmp", "strcmp"]

        found_license_targets = [name for name in target_names if name in license_targets]
        assert (
            found_license_targets
        ), "Default targets should include license functions"


class TestChainTypes:
    """Test different chain type generation."""

    def test_license_bypass_chain_generation(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate license bypass chain."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("check_license", None, "License check")

        result = kernel32_generator.generate_chains()

        assert result is True
        license_chains = [c for c in kernel32_generator.chains if "license" in c["target"]["name"].lower()]
        assert license_chains

    def test_comparison_bypass_chain_generation(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate comparison bypass chain."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("strcmp", None, "String comparison")

        result = kernel32_generator.generate_chains()

        assert result is True
        comparison_chains = [c for c in kernel32_generator.chains if "strcmp" in c["target"]["name"].lower()]
        assert comparison_chains

    def test_memory_comparison_chain_generation(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate memory comparison chain."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("memcmp", None, "Memory comparison")

        result = kernel32_generator.generate_chains()

        assert result is True
        memcmp_chains = [c for c in kernel32_generator.chains if "memcmp" in c["target"]["name"].lower()]
        assert memcmp_chains


class TestChainValidation:
    """Test chain validation logic."""

    def test_generated_chains_are_valid(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generated chains pass validation."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("check_license", None, "License check")
        kernel32_generator.generate_chains()

        for chain in kernel32_generator.chains:
            assert len(chain["gadgets"]) > 0, "Chain has no gadgets"
            assert chain["length"] > 0, "Chain length is zero"

    def test_chains_have_reasonable_length(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generated chains have reasonable length."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("validate_key", None, "Key validation")
        kernel32_generator.generate_chains()

        for chain in kernel32_generator.chains:
            assert chain["length"] <= kernel32_generator.max_chain_length, f"Chain exceeds max length: {chain['length']}"
            assert chain["length"] > 0, "Chain has zero length"

    def test_chains_include_metadata(self, kernel32_generator: ROPChainGenerator) -> None:
        """Chains include useful metadata."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("is_activated", None, "Activation check")
        kernel32_generator.generate_chains()

        for chain in kernel32_generator.chains:
            assert "description" in chain
            assert isinstance(chain["description"], str)
            assert len(chain["description"]) > 0


class TestGetResults:
    """Test result retrieval."""

    def test_get_results_structure(self, kernel32_generator: ROPChainGenerator) -> None:
        """Get results returns proper structure."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("check_license", None, "License check")
        kernel32_generator.generate_chains()

        results = kernel32_generator.get_results()

        assert "gadgets" in results
        assert "chains" in results
        assert "target_functions" in results
        assert "summary" in results
        assert isinstance(results["gadgets"], list)
        assert isinstance(results["chains"], list)
        assert isinstance(results["target_functions"], list)
        assert isinstance(results["summary"], dict)

    def test_get_results_summary_counts(self, kernel32_generator: ROPChainGenerator) -> None:
        """Get results summary has correct counts."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("validate_key", None, "Key validation")
        kernel32_generator.generate_chains()

        results = kernel32_generator.get_results()

        assert results["summary"]["total_gadgets"] == len(kernel32_generator.gadgets)
        assert results["summary"]["total_chains"] == len(kernel32_generator.chains)
        assert results["summary"]["total_targets"] == len(kernel32_generator.target_functions)


class TestGetStatistics:
    """Test statistics retrieval."""

    def test_get_statistics_empty(self) -> None:
        """Get statistics returns empty dict without gadgets."""
        gen = ROPChainGenerator()

        stats = gen.get_statistics()

        assert stats == {}

    def test_get_statistics_with_gadgets(self, kernel32_generator: ROPChainGenerator) -> None:
        """Get statistics returns proper data with gadgets."""
        kernel32_generator.find_gadgets()

        stats = kernel32_generator.get_statistics()

        assert "gadget_types" in stats
        assert "average_chain_length" in stats
        assert "architecture" in stats
        assert "max_chain_length" in stats
        assert isinstance(stats["gadget_types"], dict)
        assert stats["architecture"] == "x86_64"

    def test_statistics_gadget_type_counts(self, kernel32_generator: ROPChainGenerator) -> None:
        """Statistics include gadget type counts."""
        kernel32_generator.find_gadgets()

        stats = kernel32_generator.get_statistics()

        gadget_types = stats["gadget_types"]
        total_count = sum(gadget_types.values())

        assert total_count == len(kernel32_generator.gadgets)
        assert all(count > 0 for count in gadget_types.values())

    def test_statistics_average_chain_length(self, kernel32_generator: ROPChainGenerator) -> None:
        """Statistics calculate average chain length correctly."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("check_license", None, "License check")
        kernel32_generator.generate_chains()

        stats = kernel32_generator.get_statistics()

        if kernel32_generator.chains:
            expected_avg = sum(c["length"] for c in kernel32_generator.chains) / len(kernel32_generator.chains)
            assert stats["average_chain_length"] == expected_avg


class TestClearAnalysis:
    """Test analysis clearing."""

    def test_clear_analysis_clears_gadgets(self, kernel32_generator: ROPChainGenerator) -> None:
        """Clear analysis clears gadgets."""
        kernel32_generator.find_gadgets()
        assert len(kernel32_generator.gadgets) > 0

        kernel32_generator.clear_analysis()

        assert len(kernel32_generator.gadgets) == 0

    def test_clear_analysis_clears_chains(self, kernel32_generator: ROPChainGenerator) -> None:
        """Clear analysis clears chains."""
        kernel32_generator.find_gadgets()
        kernel32_generator.generate_chains()
        assert len(kernel32_generator.chains) > 0

        kernel32_generator.clear_analysis()

        assert len(kernel32_generator.chains) == 0

    def test_clear_analysis_clears_targets(self, kernel32_generator: ROPChainGenerator) -> None:
        """Clear analysis clears target functions."""
        kernel32_generator.add_target_function("check_license", None, "License check")
        assert len(kernel32_generator.target_functions) > 0

        kernel32_generator.clear_analysis()

        assert len(kernel32_generator.target_functions) == 0

    def test_clear_analysis_preserves_config(self, kernel32_generator: ROPChainGenerator) -> None:
        """Clear analysis preserves configuration."""
        original_config = kernel32_generator.config
        original_binary = kernel32_generator.binary_path

        kernel32_generator.clear_analysis()

        assert kernel32_generator.config == original_config
        assert kernel32_generator.binary_path == original_binary


class TestGenerateChainMethod:
    """Test generate_chain method."""

    def test_generate_chain_for_target_name(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate chain for target name."""
        kernel32_generator.find_gadgets()

        chain = kernel32_generator.generate_chain("check_license")

        assert isinstance(chain, list)
        assert len(chain) > 0

    def test_generate_chain_creates_gadget_list(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate chain returns list of gadgets."""
        kernel32_generator.find_gadgets()

        chain = kernel32_generator.generate_chain("validate_key")

        for gadget in chain:
            assert "address" in gadget
            assert "instruction" in gadget
            assert "type" in gadget

    def test_generate_chain_without_gadgets_finds_them(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate chain finds gadgets if not available."""
        chain = kernel32_generator.generate_chain("is_activated")

        assert len(chain) > 0
        assert len(kernel32_generator.gadgets) > 0

    def test_generate_chain_respects_max_length(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate chain respects max_length parameter."""
        kernel32_generator.find_gadgets()

        chain = kernel32_generator.generate_chain("check_license", max_length=5)

        assert len(chain) <= 5

    def test_generate_chain_adds_to_collection(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate chain adds result to chains collection."""
        kernel32_generator.find_gadgets()
        initial_count = len(kernel32_generator.chains)

        kernel32_generator.generate_chain("validate_key")

        assert len(kernel32_generator.chains) > initial_count

    def test_generate_chain_for_address_target(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate chain for address target."""
        kernel32_generator.find_gadgets()

        chain = kernel32_generator.generate_chain("0x401000")

        assert isinstance(chain, list)

    def test_generate_chain_auto_detects_type(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate chain auto-detects chain type."""
        kernel32_generator.find_gadgets()

        license_chain = kernel32_generator.generate_chain("check_license")
        comparison_chain = kernel32_generator.generate_chain("strcmp")

        assert len(license_chain) > 0
        assert len(comparison_chain) > 0


class TestPatternBasedGadgetSearch:
    """Test pattern-based gadget search fallback."""

    def test_pattern_search_finds_pop_ret_patterns(self, temp_pe_binary: Path) -> None:
        """Pattern search finds pop/ret sequences."""
        gen = ROPChainGenerator({"arch": "x86_64"})
        gen.set_binary(str(temp_pe_binary))

        gen.find_gadgets()

        pop_ret_gadgets = [g for g in gen.gadgets if "pop" in g["instruction"].lower() and "ret" in g["instruction"].lower()]
        assert pop_ret_gadgets, "Pattern search should find pop/ret gadgets"

    def test_pattern_search_finds_xor_ret_patterns(self, temp_pe_binary: Path) -> None:
        """Pattern search finds xor/ret sequences."""
        gen = ROPChainGenerator({"arch": "x86_64"})
        gen.set_binary(str(temp_pe_binary))

        gen.find_gadgets()

        xor_ret_gadgets = [g for g in gen.gadgets if "xor" in g["instruction"].lower()]
        assert xor_ret_gadgets, "Pattern search should find xor/ret gadgets"

    def test_pattern_search_finds_simple_ret(self, temp_pe_binary: Path) -> None:
        """Pattern search finds simple ret instruction."""
        gen = ROPChainGenerator({"arch": "x86_64"})
        gen.set_binary(str(temp_pe_binary))

        gen.find_gadgets()

        ret_gadgets = [g for g in gen.gadgets if g["instruction"].lower().strip() == "ret"]
        assert ret_gadgets, "Pattern search should find simple ret"


class TestChainBuildingForLicenseBypass:
    """Test chain building for license bypass scenarios."""

    def test_license_bypass_chain_structure(self, kernel32_generator: ROPChainGenerator) -> None:
        """License bypass chain has proper structure."""
        kernel32_generator.find_gadgets()

        chain = kernel32_generator.generate_chain("check_license")

        assert len(chain) > 0
        assert any("address" in g for g in chain)

    def test_license_bypass_uses_appropriate_gadgets(self, kernel32_generator: ROPChainGenerator) -> None:
        """License bypass chain uses appropriate gadget types."""
        kernel32_generator.find_gadgets()

        chain = kernel32_generator.generate_chain("validate_license")

        gadget_types = {g["type"] for g in chain}
        useful_types = {"pop_reg", "ret", "mov_reg_reg", "logic_reg", "arith_reg"}

        assert len(gadget_types & useful_types) > 0, "License bypass should use useful gadget types"


class TestChainBuildingForComparisonBypass:
    """Test chain building for comparison bypass scenarios."""

    def test_comparison_bypass_chain_structure(self, kernel32_generator: ROPChainGenerator) -> None:
        """Comparison bypass chain has proper structure."""
        kernel32_generator.find_gadgets()

        chain = kernel32_generator.generate_chain("strcmp")

        assert len(chain) > 0

    def test_memcmp_bypass_chain_generation(self, kernel32_generator: ROPChainGenerator) -> None:
        """Memcmp bypass chain generation."""
        kernel32_generator.find_gadgets()

        chain = kernel32_generator.generate_chain("memcmp")

        assert len(chain) > 0


class TestArchitectureSupport:
    """Test architecture-specific functionality."""

    def test_x86_64_architecture(self) -> None:
        """X86_64 architecture configuration."""
        gen = ROPChainGenerator({"arch": "x86_64"})

        assert gen.arch == "x86_64"

    def test_x86_architecture(self) -> None:
        """X86 (32-bit) architecture configuration."""
        gen = ROPChainGenerator({"arch": "x86"})

        assert gen.arch == "x86"

    def test_architecture_affects_requirements(self) -> None:
        """Architecture affects chain requirements."""
        gen_64 = ROPChainGenerator({"arch": "x86_64"})
        gen_32 = ROPChainGenerator({"arch": "x86"})

        req_64 = gen_64._get_chain_requirements("license_bypass")
        req_32 = gen_32._get_chain_requirements("license_bypass")

        assert req_64["required_registers"] != req_32["required_registers"]


class TestUser32Gadgets:
    """Test gadget discovery in user32.dll."""

    def test_user32_gadget_discovery(self, user32_generator: ROPChainGenerator) -> None:
        """Find gadgets in user32.dll."""
        result = user32_generator.find_gadgets()

        assert result is True
        assert len(user32_generator.gadgets) > 0

    def test_user32_chain_generation(self, user32_generator: ROPChainGenerator) -> None:
        """Generate chains with user32.dll gadgets."""
        user32_generator.find_gadgets()

        chain = user32_generator.generate_chain("check_license")

        assert len(chain) > 0


class TestMultipleDLLAnalysis:
    """Test analysis across multiple Windows DLLs."""

    def test_kernel32_vs_ntdll_gadget_counts(self, kernel32_generator: ROPChainGenerator, ntdll_generator: ROPChainGenerator) -> None:
        """Compare gadget counts between kernel32 and ntdll."""
        kernel32_generator.find_gadgets()
        ntdll_generator.find_gadgets()

        k32_count = len(kernel32_generator.gadgets)
        ntdll_count = len(ntdll_generator.gadgets)

        assert k32_count > 0
        assert ntdll_count > 0

    def test_different_dlls_different_gadgets(self, kernel32_generator: ROPChainGenerator, ntdll_generator: ROPChainGenerator) -> None:
        """Different DLLs produce different gadget sets."""
        kernel32_generator.find_gadgets()
        ntdll_generator.find_gadgets()

        k32_addrs = {g["address"] for g in kernel32_generator.gadgets}
        ntdll_addrs = {g["address"] for g in ntdll_generator.gadgets}

        overlap = k32_addrs & ntdll_addrs
        assert len(overlap) == 0, "Different DLLs should have non-overlapping addresses"


class TestGadgetUtilityDetection:
    """Test gadget utility detection."""

    def test_stack_control_utility_detection(self, kernel32_generator: ROPChainGenerator) -> None:
        """Stack control utility is detected."""
        kernel32_generator.find_gadgets()

        if stack_control_gadgets := [
            g
            for g in kernel32_generator.gadgets
            if "stack_control" in g.get("useful_for", [])
        ]:
            for gadget in stack_control_gadgets[:3]:
                assert "pop" in gadget["instruction"].lower()

    def test_zero_register_utility_detection(self, kernel32_generator: ROPChainGenerator) -> None:
        """Zero register utility is detected."""
        kernel32_generator.find_gadgets()

        if zero_reg_gadgets := [
            g
            for g in kernel32_generator.gadgets
            if "zero_register" in g.get("useful_for", [])
        ]:
            for gadget in zero_reg_gadgets[:3]:
                assert "xor" in gadget["instruction"].lower()


class TestChainComplexityScoring:
    """Test chain complexity scoring."""

    def test_complexity_score_calculation(self, kernel32_generator: ROPChainGenerator) -> None:
        """Complexity score is calculated."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("check_license", None, "License check")
        kernel32_generator.generate_chains()

        for chain in kernel32_generator.chains:
            if "complexity_score" in chain:
                assert isinstance(chain["complexity_score"], int)
                assert chain["complexity_score"] > 0

    def test_longer_chains_higher_complexity(self, kernel32_generator: ROPChainGenerator) -> None:
        """Longer chains have higher complexity scores."""
        kernel32_generator.find_gadgets()

        if len(kernel32_generator.gadgets) >= 5:
            short_chain = kernel32_generator.gadgets[:2]
            long_chain = kernel32_generator.gadgets[:5]

            short_complexity = kernel32_generator._calculate_chain_complexity(short_chain)
            long_complexity = kernel32_generator._calculate_chain_complexity(long_chain)

            assert long_complexity > short_complexity


class TestSuccessProbabilityEstimation:
    """Test success probability estimation."""

    def test_success_probability_in_range(self, kernel32_generator: ROPChainGenerator) -> None:
        """Success probability is in valid range."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("validate_key", None, "Key validation")
        kernel32_generator.generate_chains()

        for chain in kernel32_generator.chains:
            if "success_probability" in chain:
                prob = chain["success_probability"]
                assert 0.0 <= prob <= 1.0, f"Invalid probability: {prob}"

    def test_success_probability_considers_chain_length(self, kernel32_generator: ROPChainGenerator) -> None:
        """Success probability considers chain length."""
        kernel32_generator.find_gadgets()

        if len(kernel32_generator.gadgets) >= 8:
            short_chain = kernel32_generator.gadgets[:2]
            long_chain = kernel32_generator.gadgets[:8]

            requirements = {"min_gadgets": 1, "required_gadgets": ["ret"]}

            short_prob = kernel32_generator._estimate_success_probability(short_chain, requirements)
            long_prob = kernel32_generator._estimate_success_probability(long_chain, requirements)

            assert short_prob >= long_prob


class TestTargetParsing:
    """Test target specification parsing."""

    def test_parse_target_function_name(self) -> None:
        """Parse target function name."""
        gen = ROPChainGenerator()

        result = gen._parse_target("check_license")

        assert result["name"] == "check_license"
        assert result["address"] is None

    def test_parse_target_address(self) -> None:
        """Parse target address."""
        gen = ROPChainGenerator()

        result = gen._parse_target("0x401000")

        assert result["type"] == "address"
        assert result["address"] == "0x401000"

    def test_parse_target_with_library(self) -> None:
        """Parse target with library specification."""
        gen = ROPChainGenerator()

        result = gen._parse_target("MessageBoxA@user32.dll")

        assert result["name"] == "MessageBoxA"
        assert result["library"] == "user32.dll"
        assert result["type"] == "import"

    def test_parse_target_bypass_keywords(self) -> None:
        """Parse target with bypass keywords."""
        gen = ROPChainGenerator()

        result = gen._parse_target("validate_license_key")

        assert result["type"] == "bypass"


class TestReportGeneration:
    """Test report generation."""

    def test_generate_report_without_chains_fails(self) -> None:
        """Generate report fails without chains."""
        gen = ROPChainGenerator()

        result = gen.generate_report()

        assert result is None

    def test_generate_report_returns_html(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate report returns HTML content."""
        kernel32_generator.find_gadgets()
        kernel32_generator.generate_chains()

        html = kernel32_generator.generate_report()

        assert html is not None
        assert isinstance(html, str)
        assert "<html>" in html.lower()
        assert "</html>" in html.lower()

    def test_generate_report_contains_gadget_info(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate report contains gadget information."""
        kernel32_generator.find_gadgets()
        kernel32_generator.generate_chains()

        html = kernel32_generator.generate_report()

        assert html is not None
        assert "gadget" in html.lower()

    def test_generate_report_contains_chain_info(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate report contains chain information."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("check_license", None, "License check")
        kernel32_generator.generate_chains()

        html = kernel32_generator.generate_report()

        assert html is not None
        assert "chain" in html.lower()

    def test_generate_report_saves_to_file(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate report saves to file."""
        kernel32_generator.find_gadgets()
        kernel32_generator.generate_chains()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".html") as f:
            temp_path = f.name

        try:
            result = kernel32_generator.generate_report(temp_path)

            assert result == temp_path
            assert Path(temp_path).exists()
            assert Path(temp_path).stat().st_size > 0
        finally:
            if Path(temp_path).exists():
                Path(temp_path).unlink()


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_find_gadgets_with_corrupted_binary(self) -> None:
        """Find gadgets handles corrupted binary gracefully."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
            f.write(b"\x00" * 1024)
            temp_path = Path(f.name)

        try:
            gen = ROPChainGenerator()
            gen.set_binary(str(temp_path))

            result = gen.find_gadgets()

            assert isinstance(result, bool)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_find_gadgets_with_very_small_binary(self) -> None:
        """Find gadgets handles very small binary."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
            f.write(b"MZ")
            temp_path = Path(f.name)

        try:
            gen = ROPChainGenerator()
            gen.set_binary(str(temp_path))

            result = gen.find_gadgets()

            assert isinstance(result, bool)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_generate_chain_with_empty_target(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generate chain handles empty target."""
        kernel32_generator.find_gadgets()

        chain = kernel32_generator.generate_chain("")

        assert isinstance(chain, list)

    def test_set_binary_with_nonexecutable_file(self) -> None:
        """Set binary handles non-executable file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("not a binary")
            temp_path = Path(f.name)

        try:
            gen = ROPChainGenerator()
            result = gen.set_binary(str(temp_path))

            assert isinstance(result, bool)
        finally:
            if temp_path.exists():
                temp_path.unlink()


class TestGadgetAddressRanges:
    """Test gadget address validation and ranges."""

    def test_all_gadget_addresses_valid_hex(self, kernel32_generator: ROPChainGenerator) -> None:
        """All gadget addresses are valid hex values."""
        kernel32_generator.find_gadgets()

        for gadget in kernel32_generator.gadgets:
            addr = gadget["address"]
            if isinstance(addr, str):
                if addr.startswith("0x"):
                    addr_int = int(addr, 16)
                    assert addr_int >= 0
                else:
                    assert addr.isdigit() or addr.startswith("0x")


class TestChainPayloadGeneration:
    """Test chain payload generation."""

    def test_chain_payload_not_empty(self, kernel32_generator: ROPChainGenerator) -> None:
        """Chain payload is not empty."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("check_license", None, "License check")
        kernel32_generator.generate_chains()

        for chain in kernel32_generator.chains:
            assert len(chain["payload"]) > 0, "Chain payload should not be empty"

    def test_chain_payload_contains_addresses(self, kernel32_generator: ROPChainGenerator) -> None:
        """Chain payload contains gadget addresses."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("validate_key", None, "Key validation")
        kernel32_generator.generate_chains()

        for chain in kernel32_generator.chains:
            payload = chain["payload"]
            assert all(isinstance(item, str) for item in payload), "Payload items should be strings"


class TestRealWorldEffectiveness:
    """Test real-world effectiveness of ROP chains."""

    def test_generated_chains_use_real_gadgets(self, kernel32_generator: ROPChainGenerator) -> None:
        """Generated chains use real discovered gadgets."""
        kernel32_generator.find_gadgets()
        discovered_gadgets = {g["address"] for g in kernel32_generator.gadgets}

        kernel32_generator.add_target_function("check_license", None, "License check")
        kernel32_generator.generate_chains()

        for chain in kernel32_generator.chains:
            for gadget in chain["gadgets"]:
                assert gadget["address"] in discovered_gadgets, "Chain uses undiscovered gadget"

    def test_chains_target_license_mechanisms(self, kernel32_generator: ROPChainGenerator) -> None:
        """Chains effectively target license mechanisms."""
        kernel32_generator.find_gadgets()

        license_targets = ["check_license", "validate_key", "is_activated"]
        for target in license_targets:
            kernel32_generator.add_target_function(target, None, f"License target: {target}")

        kernel32_generator.generate_chains()

        assert len(kernel32_generator.chains) >= len(license_targets), "Should generate chains for all license targets"

    def test_chains_include_control_flow_gadgets(self, kernel32_generator: ROPChainGenerator) -> None:
        """Chains include control flow gadgets."""
        kernel32_generator.find_gadgets()
        kernel32_generator.add_target_function("check_license", None, "License check")
        kernel32_generator.generate_chains()

        for chain in kernel32_generator.chains:
            gadget_types = {g["type"] for g in chain["gadgets"]}
            control_types = {"ret", "jmp_reg", "call_reg"}

            assert len(gadget_types & control_types) > 0, "Chain should include control flow gadgets"
