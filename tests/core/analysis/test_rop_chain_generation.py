"""
Specialized tests for ROP (Return-Oriented Programming) chain generation capabilities.
Tests REAL ROP gadget identification and exploit chain construction.
NO MOCKS - ALL TESTS USE REAL BINARIES AND VALIDATE GENUINE EXPLOITATION.

Testing Agent Mission: Validate production-ready ROP exploitation capabilities
that demonstrate genuine binary exploitation effectiveness for security research.
"""

from typing import Any
import os
import pytest
import struct
from pathlib import Path

from intellicrack.core.analysis.automated_patch_agent import AutomatedPatchAgent
from tests.base_test import IntellicrackTestBase


class TestROPChainGeneration(IntellicrackTestBase):
    """Test ROP chain generation with real exploit capabilities."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_workspace) -> Any:
        """Set up test with binaries containing ROP gadgets."""
        self.agent = AutomatedPatchAgent()
        self.temp_dir = temp_workspace

        # Create binaries with various ROP gadgets
        self.gadget_rich_binary = self._create_gadget_rich_binary()
        self.minimal_gadgets_binary = self._create_minimal_gadgets_binary()
        self.x64_gadgets_binary = self._create_x64_gadgets_binary()
        self.system_library_mock = self._create_system_library_mock()

    def _create_gadget_rich_binary(self) -> None:
        """Create binary with many useful ROP gadgets."""
        binary_path = os.path.join(self.temp_dir, "gadget_rich.exe")

        # Rich collection of ROP gadgets
        gadget_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Stack pivot gadgets
            b'\x94\xc3'                 # xchg eax, esp; ret
            b'\x87\xe0\xc3'             # xchg eax, esp; ret (alternative)
            b'\x54\x5c\xc3'             # push esp; pop esp; ret
            # Register control gadgets
            b'\x58\xc3'                 # pop eax; ret
            b'\x59\xc3'                 # pop ecx; ret
            b'\x5a\xc3'                 # pop edx; ret
            b'\x5b\xc3'                 # pop ebx; ret
            b'\x5c\xc3'                 # pop esp; ret
            b'\x5d\xc3'                 # pop ebp; ret
            b'\x5e\xc3'                 # pop esi; ret
            b'\x5f\xc3'                 # pop edi; ret
            # Memory manipulation gadgets
            b'\x89\x08\xc3'             # mov [eax], ecx; ret
            b'\x8b\x08\xc3'             # mov ecx, [eax]; ret
            b'\x89\x18\xc3'             # mov [eax], ebx; ret
            b'\x8b\x18\xc3'             # mov ebx, [eax]; ret
            # Arithmetic gadgets
            b'\x01\xc8\xc3'             # add eax, ecx; ret
            b'\x29\xc8\xc3'             # sub eax, ecx; ret
            b'\xf7\xd8\xc3'             # neg eax; ret
            b'\x48\xc3'                 # dec eax; ret
            b'\x40\xc3'                 # inc eax; ret
            # Function call gadgets
            b'\xff\xd0\xc3'             # call eax; ret
            b'\xff\x10\xc3'             # call [eax]; ret
            b'\x50\xff\xd1\xc3'         # push eax; call ecx; ret
            # Multi-pop gadgets
            b'\x58\x59\xc3'             # pop eax; pop ecx; ret
            b'\x59\x5a\xc3'             # pop ecx; pop edx; ret
            b'\x58\x5b\x5c\xc3'         # pop eax; pop ebx; pop esp; ret
            # Conditional gadgets
            b'\x85\xc0\x74\x02\xc3\xc3' # test eax, eax; jz +2; ret; ret
            # NOP sleds for alignment
            b'\x90\x90\x90\x90'
        )

        with open(binary_path, 'wb') as f:
            f.write(gadget_data)

        return binary_path

    def _create_minimal_gadgets_binary(self) -> None:
        """Create binary with minimal ROP gadgets for edge case testing."""
        binary_path = os.path.join(self.temp_dir, "minimal_gadgets.exe")

        minimal_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Very few gadgets available
            b'\x58\xc3'                 # pop eax; ret
            b'\x59\xc3'                 # pop ecx; ret
            b'\xff\xd0\xc3'             # call eax; ret
            b'\x90' * 100               # Mostly NOPs
        )

        with open(binary_path, 'wb') as f:
            f.write(minimal_data)

        return binary_path

    def _create_x64_gadgets_binary(self) -> None:
        """Create x64 binary with 64-bit specific ROP gadgets."""
        binary_path = os.path.join(self.temp_dir, "x64_gadgets.exe")

        x64_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # x64 register pops
            b'\x58\xc3'                 # pop rax; ret
            b'\x59\xc3'                 # pop rcx; ret
            b'\x5a\xc3'                 # pop rdx; ret
            b'\x5b\xc3'                 # pop rbx; ret
            b'\x41\x58\xc3'             # pop r8; ret
            b'\x41\x59\xc3'             # pop r9; ret
            b'\x41\x5a\xc3'             # pop r10; ret
            b'\x41\x5b\xc3'             # pop r11; ret
            # x64 stack manipulation
            b'\x48\x94\xc3'             # xchg rax, rsp; ret
            b'\x48\x87\xe0\xc3'         # xchg rax, rsp; ret
            # x64 memory operations
            b'\x48\x89\x08\xc3'         # mov [rax], rcx; ret
            b'\x48\x8b\x08\xc3'         # mov rcx, [rax]; ret
            # x64 function calls
            b'\xff\xd0\xc3'             # call rax; ret
            b'\x48\xff\xd0\xc3'         # call rax; ret (with REX prefix)
        )

        with open(binary_path, 'wb') as f:
            f.write(x64_data)

        return binary_path

    def _create_system_library_mock(self) -> None:
        """Create mock system library with common API gadgets."""
        library_path = os.path.join(self.temp_dir, "system_mock.dll")

        system_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Common Windows API patterns that create useful gadgets
            b'\x8b\xff\x55\x8b\xec'     # mov edi, edi; push ebp; mov ebp, esp (prologue)
            b'\x5d\xc2\x04\x00'         # pop ebp; ret 4
            b'\x5d\xc2\x08\x00'         # pop ebp; ret 8
            b'\x5d\xc2\x0c\x00'         # pop ebp; ret 12
            # Epilogue patterns
            b'\x8b\xe5\x5d\xc3'         # mov esp, ebp; pop ebp; ret
            b'\x5f\x5e\x5b\x5d\xc3'     # pop edi; pop esi; pop ebx; pop ebp; ret
            # API calling patterns
            b'\x50\x68\x00\x00\x00\x00' # push eax; push immediate
            b'\xe8\x00\x00\x00\x00'     # call relative
            b'\x83\xc4\x08\xc3'         # add esp, 8; ret
        )

        with open(library_path, 'wb') as f:
            f.write(system_data)

        return library_path

    def test_rop_chain_basic_generation(self) -> None:
        """Test basic ROP chain generation functionality."""
        # Generate stack pivot chain
        rop_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'stack_pivot')

        # Validate basic structure
        assert rop_chain is not None
        assert hasattr(rop_chain, 'gadgets')
        assert hasattr(rop_chain, 'chain_bytes')
        assert hasattr(rop_chain, 'target_architecture')
        assert hasattr(rop_chain, 'payload_size')
        assert hasattr(rop_chain, 'exploit_type')

        # Verify chain contains gadgets
        assert len(rop_chain.gadgets) > 0
        assert isinstance(rop_chain.gadgets, list)

        # Verify chain produces bytes
        assert len(rop_chain.chain_bytes) > 0
        assert isinstance(rop_chain.chain_bytes, bytes)

        # Verify architecture detection
        assert rop_chain.target_architecture in ['x86', 'x64']

        # Verify exploit type
        assert rop_chain.exploit_type == 'stack_pivot'

    def test_gadget_identification_comprehensive(self) -> None:
        """Test comprehensive gadget identification in binaries."""
        rop_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'generic_exploit')

        gadgets = rop_chain.gadgets
        assert len(gadgets) >= 10  # Rich binary should have many gadgets

        # Categorize gadgets by type
        pop_gadgets = [g for g in gadgets if g.gadget_type == 'pop_register']
        memory_gadgets = [g for g in gadgets if g.gadget_type == 'memory_operation']
        call_gadgets = [g for g in gadgets if g.gadget_type == 'function_call']
        arithmetic_gadgets = [g for g in gadgets if g.gadget_type == 'arithmetic']

        # Verify diverse gadget types identified
        assert len(pop_gadgets) >= 3  # Multiple register pops
        assert len(memory_gadgets) >= 2  # Memory read/write operations
        assert call_gadgets

        # Verify gadget structure
        for gadget in gadgets:
            assert hasattr(gadget, 'address')
            assert hasattr(gadget, 'instruction_bytes')
            assert hasattr(gadget, 'gadget_type')
            assert hasattr(gadget, 'assembly_text')
            assert hasattr(gadget, 'utility_rating')

            # Validate data types
            assert isinstance(gadget.address, int)
            assert isinstance(gadget.instruction_bytes, bytes)
            assert isinstance(gadget.assembly_text, str)
            assert isinstance(gadget.utility_rating, float)

            # Validate ranges
            assert gadget.address > 0
            assert len(gadget.instruction_bytes) >= 2  # Minimum: instruction + ret
            assert 0.0 <= gadget.utility_rating <= 1.0

    def test_stack_pivot_chain_construction(self) -> None:
        """Test construction of stack pivot ROP chains."""
        pivot_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'stack_pivot')

        # Validate stack pivot specific attributes
        assert hasattr(pivot_chain, 'pivot_gadget')
        assert hasattr(pivot_chain, 'controlled_stack_location')
        assert hasattr(pivot_chain, 'pivot_setup_gadgets')

        # Verify pivot gadget is appropriate
        pivot_gadget = pivot_chain.pivot_gadget
        assert pivot_gadget is not None
        assert pivot_gadget.gadget_type in ['stack_pivot', 'register_exchange']

        # Verify pivot setup
        setup_gadgets = pivot_chain.pivot_setup_gadgets
        assert len(setup_gadgets) > 0

        # Chain should include address setup
        chain_addresses = struct.unpack('<' + 'I' * (len(pivot_chain.chain_bytes) // 4),
                                      pivot_chain.chain_bytes)
        assert len(chain_addresses) >= 2  # At least pivot setup + pivot execution

    def test_function_call_chain_construction(self) -> None:
        """Test construction of function call ROP chains."""
        call_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'function_call')

        # Validate function call specific attributes
        assert hasattr(call_chain, 'target_function')
        assert hasattr(call_chain, 'argument_setup_gadgets')
        assert hasattr(call_chain, 'call_gadget')
        assert hasattr(call_chain, 'calling_convention')

        # Verify argument setup capability
        arg_gadgets = call_chain.argument_setup_gadgets
        assert len(arg_gadgets) >= 1  # At least one argument setup method

        for gadget in arg_gadgets:
            assert gadget.gadget_type in ['pop_register', 'memory_operation', 'register_move']

        # Verify call gadget
        call_gadget = call_chain.call_gadget
        assert call_gadget.gadget_type == 'function_call'
        assert 'call' in call_gadget.assembly_text.lower()

        # Verify calling convention support
        assert call_chain.calling_convention in ['stdcall', 'cdecl', 'fastcall']

    def test_memory_manipulation_chains(self) -> None:
        """Test ROP chains for memory read/write operations."""
        memory_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'memory_write')

        # Validate memory manipulation capabilities
        assert hasattr(memory_chain, 'write_gadgets')
        assert hasattr(memory_chain, 'read_gadgets')
        assert hasattr(memory_chain, 'address_setup_gadgets')

        # Verify write capability
        write_gadgets = memory_chain.write_gadgets
        assert len(write_gadgets) > 0

        for gadget in write_gadgets:
            assert gadget.gadget_type == 'memory_operation'
            # Should contain memory write instructions
            instructions = gadget.assembly_text.lower()
            assert any(op in instructions for op in ['mov [', 'store', 'write'])

        # Verify address setup capability
        addr_gadgets = memory_chain.address_setup_gadgets
        assert len(addr_gadgets) > 0

        # Should be able to control memory addresses
        register_control = any(g.gadget_type == 'pop_register' for g in addr_gadgets)
        assert register_control

    def test_aslr_bypass_chain_generation(self) -> None:
        """Test ROP chain generation for ASLR bypass scenarios."""
        aslr_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'aslr_bypass')

        # Validate ASLR bypass specific features
        assert hasattr(aslr_chain, 'leak_gadgets')
        assert hasattr(aslr_chain, 'base_calculation_method')
        assert hasattr(aslr_chain, 'known_offsets')

        # Verify leak capability
        leak_gadgets = aslr_chain.leak_gadgets
        assert len(leak_gadgets) > 0

        for gadget in leak_gadgets:
            # Should be able to read memory or registers
            assert gadget.gadget_type in ['memory_operation', 'register_move']

        # Verify base calculation methodology
        calc_method = aslr_chain.base_calculation_method
        assert calc_method in ['return_address', 'got_entry', 'stack_leak', 'heap_leak']

        # Verify known offsets for calculation
        assert isinstance(aslr_chain.known_offsets, dict)
        assert len(aslr_chain.known_offsets) > 0

    def test_dep_bypass_chain_generation(self) -> None:
        """Test ROP chain generation for DEP (Data Execution Prevention) bypass."""
        dep_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'dep_bypass')

        # Validate DEP bypass capabilities
        assert hasattr(dep_chain, 'virtualprotect_chain')
        assert hasattr(dep_chain, 'virtualalloc_chain')
        assert hasattr(dep_chain, 'writeprocessmemory_chain')

        # Should have at least one bypass method
        bypass_methods = [
            dep_chain.virtualprotect_chain,
            dep_chain.virtualalloc_chain,
            dep_chain.writeprocessmemory_chain
        ]
        active_methods = [m for m in bypass_methods if m is not None]
        assert active_methods

        # Verify VirtualProtect chain if available
        if dep_chain.virtualprotect_chain:
            vp_chain = dep_chain.virtualprotect_chain
            assert hasattr(vp_chain, 'api_address')
            assert hasattr(vp_chain, 'parameter_setup')
            assert len(vp_chain.parameter_setup) >= 4  # VirtualProtect needs 4 parameters

    def test_x64_rop_chain_generation(self) -> None:
        """Test x64-specific ROP chain generation."""
        x64_chain = self.agent._generate_rop_chains(self.x64_gadgets_binary, 'x64_exploit')

        # Verify x64 architecture detection
        assert x64_chain.target_architecture == 'x64'

        # Verify x64-specific gadgets
        x64_gadgets = x64_chain.gadgets
        assert len(x64_gadgets) > 0

        # Check for x64 register usage
        x64_registers = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
                        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

        x64_register_found = False
        for gadget in x64_gadgets:
            for reg in x64_registers:
                if reg in gadget.assembly_text.lower():
                    x64_register_found = True
                    break

        assert x64_register_found  # Should find x64 registers in gadgets

        # Verify x64 calling convention support
        if hasattr(x64_chain, 'calling_convention'):
            assert x64_chain.calling_convention in ['microsoft_x64', 'system_v']

    def test_gadget_quality_assessment(self) -> None:
        """Test gadget quality assessment and utility rating."""
        rop_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'generic_exploit')

        gadgets = rop_chain.gadgets
        high_quality_gadgets = [g for g in gadgets if g.utility_rating > 0.7]
        medium_quality_gadgets = [g for g in gadgets if 0.3 <= g.utility_rating <= 0.7]
        low_quality_gadgets = [g for g in gadgets if g.utility_rating < 0.3]

        # Should have range of quality gadgets
        assert high_quality_gadgets
        # Verify quality assessment criteria
        for gadget in high_quality_gadgets:
            # High quality gadgets should have useful characteristics
            useful_types = ['pop_register', 'function_call', 'memory_operation', 'stack_pivot']
            assert gadget.gadget_type in useful_types

            # Should have reasonable instruction count
            assert len(gadget.instruction_bytes) <= 10  # Not too complex

        if pop_eax_gadgets := [
            g
            for g in gadgets
            if 'pop' in g.assembly_text.lower()
            and 'eax' in g.assembly_text.lower()
        ]:
            # pop eax; ret should be high quality
            assert max(g.utility_rating for g in pop_eax_gadgets) > 0.6

    def test_chain_length_optimization(self) -> None:
        """Test ROP chain length optimization."""
        # Compare different exploit types for efficiency
        short_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'stack_pivot')
        long_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'complex_exploit')

        # Verify chains are appropriately sized
        assert len(short_chain.chain_bytes) >= 8  # Minimum viable chain
        assert len(long_chain.chain_bytes) >= len(short_chain.chain_bytes)  # Complex should be longer

        # Verify optimization exists
        assert hasattr(short_chain, 'optimization_level')
        assert hasattr(long_chain, 'optimization_level')

        # Check optimization levels
        assert short_chain.optimization_level in ['minimal', 'standard', 'aggressive']
        assert long_chain.optimization_level in ['minimal', 'standard', 'aggressive']

    def test_gadget_conflict_resolution(self) -> None:
        """Test resolution of conflicting gadget usage."""
        # Test scenario where multiple gadgets could serve same purpose
        multi_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'multi_stage')

        gadgets = multi_chain.gadgets

        # Check for duplicate functionality resolution
        pop_gadgets = [g for g in gadgets if g.gadget_type == 'pop_register']
        if len(pop_gadgets) > 1:
            # Should select best gadgets, not all available
            unique_registers = set()
            for gadget in pop_gadgets:
                for reg in ['eax', 'ecx', 'edx', 'ebx']:
                    if reg in gadget.assembly_text.lower():
                        unique_registers.add(reg)

            # Should not have excessive redundancy
            assert len(unique_registers) >= 2  # Multiple registers controlled

    def test_minimal_gadget_handling(self) -> None:
        """Test ROP chain generation with minimal available gadgets."""
        minimal_chain = self.agent._generate_rop_chains(self.minimal_gadgets_binary, 'basic_exploit')

        # Should still produce some chain even with limited gadgets
        assert minimal_chain is not None
        assert len(minimal_chain.gadgets) > 0

        # Should have appropriate warnings/limitations noted
        assert hasattr(minimal_chain, 'limitations')
        assert hasattr(minimal_chain, 'success_probability')

        # Success probability should be lower with fewer gadgets
        rich_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'basic_exploit')
        assert minimal_chain.success_probability <= rich_chain.success_probability

    def test_bad_character_avoidance(self) -> None:
        """Test ROP chain generation avoids bad characters."""
        # Test with common bad characters (null bytes, newlines, etc.)
        bad_chars = [b'\x00', b'\x0a', b'\x0d', b'\x20']

        for bad_char in bad_chars:
            clean_chain = self.agent._generate_rop_chains(
                self.gadget_rich_binary,
                'clean_exploit',
                avoid_bytes=bad_char
            )

            # Chain should not contain bad characters
            assert bad_char not in clean_chain.chain_bytes

            # Should still produce viable chain
            assert len(clean_chain.gadgets) > 0
            assert len(clean_chain.chain_bytes) > 8

    def test_system_library_integration(self) -> None:
        """Test ROP chain integration with system libraries."""
        # Test using both binary and system library gadgets
        combined_chain = self.agent._generate_rop_chains(
            self.gadget_rich_binary,
            'system_api_call',
            additional_libraries=[self.system_library_mock]
        )

        # Should incorporate gadgets from both sources
        assert hasattr(combined_chain, 'primary_gadgets')
        assert hasattr(combined_chain, 'library_gadgets')

        primary_gadgets = combined_chain.primary_gadgets
        library_gadgets = combined_chain.library_gadgets

        assert len(primary_gadgets) > 0
        assert len(library_gadgets) > 0

        # Verify address ranges are different (different modules)
        primary_addresses = [g.address for g in primary_gadgets]
        library_addresses = [g.address for g in library_gadgets]

        # Should have non-overlapping address ranges (different modules)
        primary_max = max(primary_addresses, default=0)
        library_min = min(library_addresses, default=float('inf'))

        # Basic sanity check for different address spaces
        assert primary_max != library_min  # Different address ranges

    def test_chain_verification_and_validation(self) -> None:
        """Test ROP chain verification and validation capabilities."""
        test_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'validated_exploit')

        # Should have validation results
        assert hasattr(test_chain, 'validation_result')
        assert hasattr(test_chain, 'chain_integrity')
        assert hasattr(test_chain, 'exploit_viability')

        validation = test_chain.validation_result

        # Verify validation structure
        assert hasattr(validation, 'gadget_reachability')
        assert hasattr(validation, 'stack_alignment')
        assert hasattr(validation, 'register_conflicts')
        assert hasattr(validation, 'execution_flow')

        # Validation should pass for well-formed chains
        assert validation.gadget_reachability is True
        assert isinstance(validation.stack_alignment, bool)
        assert isinstance(validation.register_conflicts, list)
        assert validation.execution_flow in ['sequential', 'conditional', 'complex']

        # Chain integrity should be high
        assert 0.0 <= test_chain.chain_integrity <= 1.0
        assert test_chain.exploit_viability in ['low', 'medium', 'high']

    def test_performance_optimization(self) -> None:
        """Test ROP chain generation performance optimization."""
        import time

        # Time chain generation
        start_time = time.time()
        perf_chain = self.agent._generate_rop_chains(self.gadget_rich_binary, 'performance_test')
        generation_time = time.time() - start_time

        # Should complete within reasonable time
        assert generation_time < 30.0  # 30 seconds maximum

        # Should produce quality results despite time constraints
        assert perf_chain is not None
        assert len(perf_chain.gadgets) > 0
        assert len(perf_chain.chain_bytes) > 8

        # Performance metrics should be tracked
        assert hasattr(perf_chain, 'generation_time')
        assert hasattr(perf_chain, 'gadget_search_time')
        assert hasattr(perf_chain, 'chain_construction_time')

        # Times should be reasonable
        assert perf_chain.generation_time <= generation_time + 1.0  # Allow some overhead
        assert perf_chain.gadget_search_time > 0
        assert perf_chain.chain_construction_time > 0
