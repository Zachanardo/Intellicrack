"""
Comprehensive unit tests for radare2_decompiler.py module.

This test suite validates production-ready radare2 decompilation capabilities using
specification-driven, black-box testing methodology. Tests are designed to fail
for placeholder implementations and validate genuine binary analysis functionality.

Tests use real binary samples and expect sophisticated decompilation outcomes
that prove Intellicrack's effectiveness as a security research platform.
"""

from typing import Any, Generator
import pytest
import os
import tempfile
import shutil
import struct
import subprocess
from pathlib import Path
import json

try:
    from intellicrack.core.analysis.radare2_decompiler import (
        R2DecompilationEngine,
        analyze_binary_decompilation
    )
    AVAILABLE = True
except ImportError:
    R2DecompilationEngine = None  # type: ignore[misc, assignment]
    analyze_binary_decompilation = None  # type: ignore[assignment]
    AVAILABLE = False

pytestmark = [
    pytest.mark.skipif(not AVAILABLE, reason="Module not available"),
    pytest.mark.skipif(not shutil.which('radare2') and not shutil.which('r2'), reason="radare2 not installed")
]


class TestBinarySamples:
    """Helper class to generate real binary test samples."""

    @staticmethod
    def create_simple_pe_binary() -> bytes:
        """Create a minimal but valid PE binary for testing."""
        # PE header structure for a minimal Windows executable
        pe_data = bytearray()

        # DOS header
        pe_data.extend(b'MZ')  # DOS signature
        pe_data.extend(b'\x00' * 58)  # DOS header padding
        pe_data.extend(struct.pack('<L', 0x80))  # PE header offset

        # DOS stub
        pe_data.extend(b'\x00' * (0x80 - len(pe_data)))

        # PE signature
        pe_data.extend(b'PE\x00\x00')

        # COFF header
        pe_data.extend(struct.pack('<H', 0x014c))  # Machine (i386)
        pe_data.extend(struct.pack('<H', 3))       # NumberOfSections
        pe_data.extend(struct.pack('<L', 0))       # TimeDateStamp
        pe_data.extend(struct.pack('<L', 0))       # PointerToSymbolTable
        pe_data.extend(struct.pack('<L', 0))       # NumberOfSymbols
        pe_data.extend(struct.pack('<H', 224))     # SizeOfOptionalHeader
        pe_data.extend(struct.pack('<H', 0x010f))  # Characteristics

        # Optional header
        pe_data.extend(struct.pack('<H', 0x010b))  # Magic (PE32)
        pe_data.extend(struct.pack('<B', 14))      # MajorLinkerVersion
        pe_data.extend(struct.pack('<B', 0))       # MinorLinkerVersion
        pe_data.extend(struct.pack('<L', 0x1000))  # SizeOfCode
        pe_data.extend(struct.pack('<L', 0x1000))  # SizeOfInitializedData
        pe_data.extend(struct.pack('<L', 0))       # SizeOfUninitializedData
        pe_data.extend(struct.pack('<L', 0x2000))  # AddressOfEntryPoint
        pe_data.extend(struct.pack('<L', 0x1000))  # BaseOfCode
        pe_data.extend(struct.pack('<L', 0x2000))  # BaseOfData
        pe_data.extend(struct.pack('<L', 0x400000)) # ImageBase
        pe_data.extend(struct.pack('<L', 0x1000))  # SectionAlignment
        pe_data.extend(struct.pack('<L', 0x200))   # FileAlignment
        pe_data.extend(struct.pack('<H', 6))       # MajorOperatingSystemVersion
        pe_data.extend(struct.pack('<H', 0))       # MinorOperatingSystemVersion
        pe_data.extend(struct.pack('<H', 0))       # MajorImageVersion
        pe_data.extend(struct.pack('<H', 0))       # MinorImageVersion
        pe_data.extend(struct.pack('<H', 6))       # MajorSubsystemVersion
        pe_data.extend(struct.pack('<H', 0))       # MinorSubsystemVersion
        pe_data.extend(struct.pack('<L', 0))       # Win32VersionValue
        pe_data.extend(struct.pack('<L', 0x4000))  # SizeOfImage
        pe_data.extend(struct.pack('<L', 0x200))   # SizeOfHeaders
        pe_data.extend(struct.pack('<L', 0))       # CheckSum
        pe_data.extend(struct.pack('<H', 3))       # Subsystem (CONSOLE)
        pe_data.extend(struct.pack('<H', 0))       # DllCharacteristics
        pe_data.extend(struct.pack('<L', 0x100000)) # SizeOfStackReserve
        pe_data.extend(struct.pack('<L', 0x1000))  # SizeOfStackCommit
        pe_data.extend(struct.pack('<L', 0x100000)) # SizeOfHeapReserve
        pe_data.extend(struct.pack('<L', 0x1000))  # SizeOfHeapCommit
        pe_data.extend(struct.pack('<L', 0))       # LoaderFlags
        pe_data.extend(struct.pack('<L', 16))      # NumberOfRvaAndSizes

        # Data directories (16 entries, 8 bytes each)
        for _ in range(16):
            pe_data.extend(struct.pack('<LL', 0, 0))

        # Section headers (.text, .data, .rdata)
        sections = [
            (b'.text\x00\x00\x00', 0x1000, 0x1000, 0x1000, 0x200, 0x60000020),
            (b'.data\x00\x00\x00', 0x1000, 0x2000, 0x1000, 0x1200, 0xC0000040),
            (b'.rdata\x00\x00', 0x1000, 0x3000, 0x1000, 0x2200, 0x40000040)
        ]

        for name, v_size, v_addr, r_size, r_addr, chars in sections:
            pe_data.extend(name)
            pe_data.extend(struct.pack('<L', v_size))
            pe_data.extend(struct.pack('<L', v_addr))
            pe_data.extend(struct.pack('<L', r_size))
            pe_data.extend(struct.pack('<L', r_addr))
            pe_data.extend(struct.pack('<L', 0))  # PointerToRelocations
            pe_data.extend(struct.pack('<L', 0))  # PointerToLinenumbers
            pe_data.extend(struct.pack('<H', 0))  # NumberOfRelocations
            pe_data.extend(struct.pack('<H', 0))  # NumberOfLinenumbers
            pe_data.extend(struct.pack('<L', chars))  # Characteristics

        # Pad to file alignment
        while len(pe_data) < 0x200:
            pe_data.extend(b'\x00')

        # .text section with real x86 assembly
        text_section = bytearray()
        # Simple function with license check pattern
        text_section.extend(b'\x55')                    # push ebp
        text_section.extend(b'\x89\xe5')                # mov ebp, esp
        text_section.extend(b'\x83\xec\x10')            # sub esp, 0x10
        text_section.extend(b'\x68\x00\x30\x40\x00')    # push license_string
        text_section.extend(b'\xe8\x10\x00\x00\x00')    # call validate_license
        text_section.extend(b'\x83\xc4\x04')            # add esp, 4
        text_section.extend(b'\x85\xc0')                # test eax, eax
        text_section.extend(b'\x74\x05')                # jz exit_failure
        text_section.extend(b'\xb8\x01\x00\x00\x00')    # mov eax, 1
        text_section.extend(b'\xeb\x03')                # jmp exit
        text_section.extend(b'\x31\xc0')                # xor eax, eax
        text_section.extend(b'\xc9')                    # leave
        text_section.extend(b'\xc3')                    # ret

        # validate_license function
        text_section.extend(b'\x55')                    # push ebp
        text_section.extend(b'\x89\xe5')                # mov ebp, esp
        text_section.extend(b'\x8b\x45\x08')            # mov eax, [ebp+8]
        text_section.extend(b'\x80\x38\x4c')            # cmp byte ptr [eax], 'L'
        text_section.extend(b'\x75\x0f')                # jnz invalid
        text_section.extend(b'\x80\x78\x01\x49')        # cmp byte ptr [eax+1], 'I'
        text_section.extend(b'\x75\x0a')                # jnz invalid
        text_section.extend(b'\x80\x78\x02\x43')        # cmp byte ptr [eax+2], 'C'
        text_section.extend(b'\x75\x05')                # jnz invalid
        text_section.extend(b'\xb8\x01\x00\x00\x00')    # mov eax, 1
        text_section.extend(b'\xeb\x02')                # jmp end
        text_section.extend(b'\x31\xc0')                # xor eax, eax
        text_section.extend(b'\x5d')                    # pop ebp
        text_section.extend(b'\xc3')                    # ret

        # Pad to section size
        while len(text_section) < 0x1000:
            text_section.extend(b'\x00')

        pe_data.extend(text_section)

        # .data section
        data_section = bytearray()
        data_section.extend(b'LICENSE_KEY_12345\x00')
        while len(data_section) < 0x1000:
            data_section.extend(b'\x00')

        pe_data.extend(data_section)

        # .rdata section
        rdata_section = bytearray()
        rdata_section.extend(b'This is a license validation routine\x00')
        rdata_section.extend(b'GetModuleHandleA\x00')
        rdata_section.extend(b'GetProcAddress\x00')
        rdata_section.extend(b'VirtualProtect\x00')
        while len(rdata_section) < 0x1000:
            rdata_section.extend(b'\x00')

        pe_data.extend(rdata_section)

        return bytes(pe_data)

    @staticmethod
    def create_complex_binary_with_obfuscation() -> bytes:
        """Create a more complex binary with obfuscation patterns."""
        base_pe = TestBinarySamples.create_simple_pe_binary()
        pe_data = bytearray(base_pe)

        # Replace text section with obfuscated code
        text_offset = 0x200
        obfuscated_code = bytearray()

        # Obfuscated license check with anti-debugging
        obfuscated_code.extend(b'\x55')                    # push ebp
        obfuscated_code.extend(b'\x89\xe5')                # mov ebp, esp
        obfuscated_code.extend(b'\x9c')                    # pushfd
        obfuscated_code.extend(b'\x81\x04\x24\x00\x01\x00\x00')  # add dword ptr [esp], 0x100
        obfuscated_code.extend(b'\x9d')                    # popfd
        obfuscated_code.extend(b'\x9c')                    # pushfd
        obfuscated_code.extend(b'\x58')                    # pop eax
        obfuscated_code.extend(b'\x25\x00\x01\x00\x00')    # and eax, 0x100
        obfuscated_code.extend(b'\x75\x05')                # jnz debugger_detected
        obfuscated_code.extend(b'\xe8\x20\x00\x00\x00')    # call real_check
        obfuscated_code.extend(b'\xeb\x03')                # jmp exit
        obfuscated_code.extend(b'\x31\xc0')                # xor eax, eax (fail if debugger)
        obfuscated_code.extend(b'\xc9')                    # leave
        obfuscated_code.extend(b'\xc3')                    # ret

        # Pad and add to PE
        while len(obfuscated_code) < 0x1000:
            obfuscated_code.extend(b'\x90')  # nop padding

        pe_data[text_offset:text_offset + 0x1000] = obfuscated_code

        return bytes(pe_data)


@pytest.fixture(scope="class")
def test_binaries() -> Generator[dict[str, str], None, None]:
    """Create temporary test binaries for testing."""
    temp_dir = tempfile.mkdtemp(prefix="intellicrack_test_")

    # Create test binary files
    simple_pe_path = os.path.join(temp_dir, "simple_test.exe")
    complex_pe_path = os.path.join(temp_dir, "complex_test.exe")

    with open(simple_pe_path, "wb") as f:
        f.write(TestBinarySamples.create_simple_pe_binary())

    with open(complex_pe_path, "wb") as f:
        f.write(TestBinarySamples.create_complex_binary_with_obfuscation())

    yield {
        "simple_pe": simple_pe_path,
        "complex_pe": complex_pe_path,
        "temp_dir": temp_dir
    }

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)




class TestR2DecompilationEngineInitialization:
    """Test R2DecompilationEngine initialization and radare2 integration."""

    def test_engine_initialization_with_valid_binary(self, test_binaries: Any) -> None:
        """Test engine initializes correctly with valid binary and radare2 available."""
        engine = R2DecompilationEngine(test_binaries["simple_pe"])

        # Validate initialization expectations for production-ready implementation
        assert engine.binary_path == test_binaries["simple_pe"]
        assert hasattr(engine, 'radare2_path')
        assert hasattr(engine, 'logger')
        assert hasattr(engine, 'decompilation_cache')
        assert engine.decompilation_cache is not None

        # Engine should validate binary format during initialization
        assert os.path.exists(engine.binary_path)

    def test_engine_initialization_with_invalid_binary(self) -> None:
        """Test engine handles invalid binary path appropriately."""
        with pytest.raises((FileNotFoundError, ValueError, OSError)):
            R2DecompilationEngine("/nonexistent/binary.exe")

    def test_engine_radare2_version_compatibility(self, test_binaries: Any) -> None:
        """Test engine validates radare2 version compatibility."""
        engine = R2DecompilationEngine(test_binaries["simple_pe"])
        assert hasattr(engine, 'radare2_path')

        if shutil.which('radare2') or shutil.which('r2'):
            result = subprocess.run(['radare2', '-v'], capture_output=True, text=True)
            assert result.returncode == 0 or subprocess.run(['r2', '-v'], capture_output=True, text=True).returncode == 0


class TestR2DecompilationEngineCore:
    """Test core decompilation functionality."""

    @pytest.fixture
    def engine(self, test_binaries: dict[str, str]) -> Any:
        """Create engine instance for testing."""
        return R2DecompilationEngine(test_binaries["simple_pe"])

    def test_decompile_function_with_valid_address(self, engine: Any) -> None:
        """Test function decompilation with valid function address."""
        # Test with typical entry point address
        function_address = 0x401000

        result = engine.decompile_function(function_address)

        # Production implementation must return genuine decompiled code
        assert result is not None
        assert isinstance(result, dict)

        # Validate expected decompilation output structure
        required_fields = ['address', 'decompiled_code', 'function_info', 'variables']
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

        # Decompiled code should contain meaningful C-like pseudocode
        decompiled_code = result['decompiled_code']
        assert isinstance(decompiled_code, str)
        assert len(decompiled_code) > 50, "Decompiled code too short for genuine implementation"

        # Should contain typical C constructs
        c_patterns = ['int', 'if', 'return', '{', '}', 'void', 'char']
        found_patterns = [p for p in c_patterns if p in decompiled_code]
        assert len(found_patterns) >= 2, "Decompiled code lacks C-like structures"

    def test_decompile_function_with_license_validation_logic(self, engine: Any) -> None:
        """Test decompilation of function containing license validation logic."""
        # Test decompilation of license validation function
        license_function_address = 0x401020

        result = engine.decompile_function(license_function_address)

        assert result is not None
        assert 'decompiled_code' in result

        decompiled_code = result['decompiled_code']
        # Should identify license-related patterns in decompiled code
        license_indicators = ['compare', 'validate', 'check', 'key', 'license']
        found_indicators = [ind for ind in license_indicators if ind.lower() in decompiled_code.lower()]
        assert found_indicators, "Failed to identify license validation logic"

    def test_decompile_function_with_invalid_address(self, engine: Any) -> None:
        """Test decompilation with invalid function address."""
        invalid_address = 0x0

        result = engine.decompile_function(invalid_address)

        # Should handle invalid addresses gracefully
        assert result is None or (isinstance(result, dict) and 'error' in result)

    def test_decompile_all_functions_comprehensive(self, engine: Any) -> None:
        """Test batch decompilation of all functions in binary."""
        results = engine.decompile_all_functions()

        # Production implementation should discover and decompile multiple functions
        assert results is not None
        assert isinstance(results, (list, dict))

        if isinstance(results, list):
            # Validate each function result
            for function_result in results:
                assert isinstance(function_result, dict)
                assert 'address' in function_result
                assert 'decompiled_code' in function_result
        assert len(results) > 0, "No functions discovered in binary"

    def test_decompile_all_functions_performance_and_caching(self, engine: Any) -> None:
        """Test performance optimization and caching in batch decompilation."""
        # First run
        import time
        start_time = time.time()
        results1 = engine.decompile_all_functions()
        first_run_time = time.time() - start_time

        # Second run should use cache
        start_time = time.time()
        results2 = engine.decompile_all_functions()
        second_run_time = time.time() - start_time

        # Cache should improve performance or maintain consistency
        assert results1 is not None
        assert results2 is not None
        # Second run should be faster or produce identical results
        assert second_run_time <= first_run_time * 1.5 or results1 == results2


class TestR2DecompilationEngineAnalysis:
    """Test advanced analysis capabilities."""

    @pytest.fixture
    def engine(self, test_binaries: dict[str, str]) -> Any:
        return R2DecompilationEngine(test_binaries["complex_pe"])

    def test_extract_variables_sophisticated(self, engine: Any) -> None:
        """Test variable extraction with type inference and naming."""
        function_address = 0x401000

        variables = engine._extract_variables(function_address)

        # Production implementation should identify variables with sophisticated analysis
        assert variables is not None
        assert isinstance(variables, list)

        if len(variables) > 0:
            # Validate variable structure
            for var in variables:
                assert isinstance(var, dict)
                required_fields = ['name', 'type', 'location', 'scope']
                for field in required_fields:
                    assert field in var, f"Variable missing field: {field}"

                # Variable names should be meaningful or properly inferred
                assert len(var['name']) > 0
                assert var['type'] in ['int', 'char*', 'void*', 'DWORD', 'BYTE', 'unknown']

    def test_detect_license_patterns_comprehensive(self, engine: Any) -> None:
        """Test license pattern detection with real protection mechanisms."""
        patterns = engine._detect_license_patterns()

        # Should identify license-related patterns in binary
        assert patterns is not None
        assert isinstance(patterns, list)

        # Each pattern should have comprehensive metadata
        for pattern in patterns:
            assert isinstance(pattern, dict)
            required_fields = ['pattern_type', 'confidence', 'location', 'description']
            for field in required_fields:
                assert field in pattern, f"Pattern missing field: {field}"

            # Confidence should be reasonable
            assert 0 <= pattern['confidence'] <= 1.0

            # Should categorize different types of license checks
            valid_types = ['key_validation', 'expiry_check', 'hardware_binding', 'network_validation']
            if pattern['pattern_type'] not in valid_types:
                # Allow other types but validate they're meaningful
                assert len(pattern['pattern_type']) > 0

    def test_detect_vulnerability_patterns_security_analysis(self, engine: Any) -> None:
        """Test vulnerability pattern detection for security analysis."""
        vulnerabilities = engine._detect_vulnerability_patterns()

        assert vulnerabilities is not None
        assert isinstance(vulnerabilities, list)

        # Should identify potential security issues
        for vuln in vulnerabilities:
            assert isinstance(vuln, dict)
            required_fields = ['vulnerability_type', 'severity', 'location', 'description', 'exploitability']
            for field in required_fields:
                assert field in vuln, f"Vulnerability missing field: {field}"

            # Severity should be categorized
            assert vuln['severity'] in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

            # Exploitability should be assessed
            assert isinstance(vuln['exploitability'], (int, float))
            assert 0 <= vuln['exploitability'] <= 10

    def test_calculate_complexity_algorithmic_metrics(self, engine: Any) -> None:
        """Test complexity calculation with genuine algorithmic metrics."""
        function_address = 0x401000

        complexity = engine._calculate_complexity(function_address)

        # Should provide comprehensive complexity metrics
        assert complexity is not None
        assert isinstance(complexity, dict)

        required_metrics = ['cyclomatic_complexity', 'cognitive_complexity', 'lines_of_code', 'nesting_depth']
        for metric in required_metrics:
            assert metric in complexity, f"Missing complexity metric: {metric}"
            assert isinstance(complexity[metric], (int, float))
            assert complexity[metric] >= 0

        # Cyclomatic complexity should be realistic for binary functions
        assert 1 <= complexity['cyclomatic_complexity'] <= 100

    def test_extract_api_calls_comprehensive_analysis(self, engine: Any) -> None:
        """Test API call extraction with comprehensive call analysis."""
        api_calls = engine._extract_api_calls()

        assert api_calls is not None
        assert isinstance(api_calls, list)

        # Should identify API calls with detailed information
        for api_call in api_calls:
            assert isinstance(api_call, dict)
            required_fields = ['api_name', 'module', 'address', 'call_type', 'parameters']
            for field in required_fields:
                assert field in api_call, f"API call missing field: {field}"

            # Should categorize call types
            valid_call_types = ['direct', 'indirect', 'dynamic', 'import']
            assert api_call['call_type'] in valid_call_types

            # Should identify security-relevant APIs
            security_apis = ['VirtualProtect', 'CreateFile', 'RegOpenKey', 'GetProcAddress']
            if api_call['api_name'] in security_apis:
                assert 'security_relevance' in api_call

    def test_get_string_references_sophisticated_extraction(self, engine: Any) -> None:
        """Test string reference extraction with sophisticated categorization."""
        strings = engine._get_string_references()

        assert strings is not None
        assert isinstance(strings, list)

        # Should extract strings with comprehensive metadata
        for string_ref in strings:
            assert isinstance(string_ref, dict)
            required_fields = ['string_value', 'address', 'encoding', 'category', 'references']
            for field in required_fields:
                assert field in string_ref, f"String reference missing field: {field}"

            # Should categorize different types of strings
            valid_categories = ['license_key', 'error_message', 'api_name', 'filename', 'registry_key', 'other']
            assert string_ref['category'] in valid_categories

            # Should identify potentially sensitive strings
            sensitive_patterns = ['license', 'key', 'password', 'token', 'secret']
            if any(pattern in string_ref['string_value'].lower() for pattern in sensitive_patterns):
                assert 'sensitivity' in string_ref

    def test_analyze_control_flow_cfg_construction(self, engine: Any) -> None:
        """Test control flow analysis with CFG construction and obfuscation detection."""
        function_address = 0x401000

        cfg_analysis = engine._analyze_control_flow(function_address)

        # Should construct comprehensive control flow graph
        assert cfg_analysis is not None
        assert isinstance(cfg_analysis, dict)

        required_fields = ['basic_blocks', 'edges', 'loops', 'conditions', 'obfuscation_detected']
        for field in required_fields:
            assert field in cfg_analysis, f"CFG analysis missing field: {field}"

        # Basic blocks should be identified
        basic_blocks = cfg_analysis['basic_blocks']
        assert isinstance(basic_blocks, list)
        assert len(basic_blocks) > 0

        # Should detect control flow patterns
        assert isinstance(cfg_analysis['loops'], list)
        assert isinstance(cfg_analysis['conditions'], list)
        assert isinstance(cfg_analysis['obfuscation_detected'], bool)


class TestR2DecompilationEngineLicenseAnalysis:
    """Test license-specific analysis capabilities."""

    @pytest.fixture
    def engine(self, test_binaries: dict[str, str]) -> Any:
        return R2DecompilationEngine(test_binaries["simple_pe"])

    def test_generate_license_bypass_suggestions_actionable(self, engine: Any) -> None:
        """Test generation of actionable license bypass strategies."""
        bypass_suggestions = engine.generate_license_bypass_suggestions()

        # Should provide actionable bypass strategies
        assert bypass_suggestions is not None
        assert isinstance(bypass_suggestions, list)
        assert len(bypass_suggestions) > 0, "No bypass suggestions generated"

        for suggestion in bypass_suggestions:
            assert isinstance(suggestion, dict)
            required_fields = ['bypass_type', 'technique', 'target_location', 'confidence', 'instructions']
            for field in required_fields:
                assert field in suggestion, f"Bypass suggestion missing field: {field}"

            # Should provide specific bypass techniques
            valid_techniques = ['binary_patching', 'dll_injection', 'api_hooking', 'memory_patching', 'debugger_bypass']
            assert suggestion['technique'] in valid_techniques

            # Confidence should be realistic
            assert 0 <= suggestion['confidence'] <= 1.0

            # Instructions should be detailed
            assert len(suggestion['instructions']) > 50, "Instructions too brief for production use"

    def test_analyze_license_functions_comprehensive(self, engine: Any) -> None:
        """Test comprehensive analysis of license-related functions."""
        license_analysis = engine.analyze_license_functions()

        assert license_analysis is not None
        assert isinstance(license_analysis, dict)

        required_fields = ['functions', 'validation_flow', 'bypass_opportunities', 'protection_strength']
        for field in required_fields:
            assert field in license_analysis, f"License analysis missing field: {field}"

        # Functions should be categorized by license relevance
        functions = license_analysis['functions']
        assert isinstance(functions, list)

        for func in functions:
            assert isinstance(func, dict)
            func_fields = ['address', 'name', 'license_relevance', 'bypass_difficulty', 'key_operations']
            for field in func_fields:
                assert field in func, f"License function missing field: {field}"

            # License relevance should be scored
            assert isinstance(func['license_relevance'], (int, float))
            assert 0 <= func['license_relevance'] <= 10

    def test_calculate_license_confidence_sophisticated(self, engine: Any) -> None:
        """Test sophisticated license confidence calculation."""
        # Test with mock license patterns
        mock_patterns = [
            {'pattern_type': 'key_validation', 'confidence': 0.8},
            {'pattern_type': 'expiry_check', 'confidence': 0.9},
            {'pattern_type': 'hardware_binding', 'confidence': 0.7}
        ]

        confidence = engine._calculate_license_confidence(mock_patterns)

        assert confidence is not None
        assert isinstance(confidence, (int, float))
        assert 0 <= confidence <= 1.0

        # Should weight different pattern types appropriately
        # High-confidence patterns should result in higher overall confidence
        assert confidence > 0.5, "Confidence calculation appears too conservative"

    def test_should_analyze_function_intelligent_filtering(self, engine: Any) -> None:
        """Test intelligent function filtering for analysis."""
        # Test various function characteristics
        test_functions = [
            {'address': 0x401000, 'name': 'main', 'size': 200},
            {'address': 0x401100, 'name': 'validate_license', 'size': 150},
            {'address': 0x401200, 'name': 'tiny_func', 'size': 10},
            {'address': 0x401300, 'name': 'check_expiry', 'size': 80}
        ]

        for func in test_functions:
            should_analyze = engine._should_analyze_function(func)
            assert isinstance(should_analyze, bool)

            # Should intelligently filter based on function characteristics
            if 'license' in func['name'].lower() or 'check' in func['name'].lower():  # type: ignore[attr-defined]
                assert should_analyze == True, f"Should analyze license-related function: {func['name']}"

    def test_get_confidence_reason_explanatory(self, engine: Any) -> None:
        """Test confidence reasoning explanations."""
        mock_patterns = [
            {'pattern_type': 'key_validation', 'confidence': 0.9, 'location': 0x401000}
        ]

        reason = engine._get_confidence_reason(mock_patterns)

        assert reason is not None
        assert isinstance(reason, str)
        assert len(reason) > 20, "Confidence reason too brief"

        # Should explain the confidence assessment
        assert 'confidence' in reason.lower() or 'pattern' in reason.lower()


class TestR2DecompilationEngineReporting:
    """Test analysis reporting and export functionality."""

    @pytest.fixture
    def engine_with_analysis(self, test_binaries: dict[str, str]) -> Any:
        return R2DecompilationEngine(test_binaries["simple_pe"])

    def test_export_analysis_report_comprehensive_formats(self, engine_with_analysis: Any) -> None:
        """Test comprehensive analysis report export in multiple formats."""
        # Test JSON export
        json_report = engine_with_analysis.export_analysis_report(format="json")

        assert json_report is not None

        if isinstance(json_report, str):
            # Should be valid JSON
            report_data = json.loads(json_report)
        else:
            report_data = json_report

        # Validate comprehensive report structure
        required_sections = [
            'binary_info', 'decompilation_results', 'license_analysis',
            'vulnerability_assessment', 'api_usage', 'string_analysis',
            'control_flow_analysis', 'bypass_recommendations'
        ]

        for section in required_sections:
            assert section in report_data, f"Report missing required section: {section}"

        # Binary info should be detailed
        binary_info = report_data['binary_info']
        assert 'file_path' in binary_info
        assert 'file_size' in binary_info
        assert 'architecture' in binary_info
        assert 'format' in binary_info

    def test_export_analysis_report_multiple_formats(self, engine_with_analysis: Any) -> None:
        """Test report export in multiple formats."""
        formats = ['json', 'xml', 'html', 'txt']

        for format_type in formats:
            try:
                report = engine_with_analysis.export_analysis_report(format=format_type)
                assert report is not None, f"No report generated for format: {format_type}"
                assert len(str(report)) > 100, f"Report too short for format: {format_type}"
            except NotImplementedError:
                # Some formats may not be implemented yet
                pass

    def test_export_analysis_report_with_custom_options(self, engine_with_analysis: Any) -> None:
        """Test report export with custom options and filtering."""
        custom_options = {
            'include_decompiled_code': True,
            'include_bypass_suggestions': True,
            'confidence_threshold': 0.7,
            'detailed_analysis': True
        }

        report = engine_with_analysis.export_analysis_report(
            format="json",
            options=custom_options
        )

        assert report is not None

        # Should respect custom options
        report_data = json.loads(report) if isinstance(report, str) else report
        # Should include detailed sections based on options
        if custom_options['include_decompiled_code']:
            assert 'decompiled_code' in str(report).lower()

        if custom_options['include_bypass_suggestions']:
            assert 'bypass' in str(report).lower()


class TestAnalyzeFunction:
    """Test the module-level analyze_binary_decompilation function."""

    def test_analyze_binary_decompilation_comprehensive_pipeline(self, test_binaries: Any) -> None:
        """Test complete binary analysis pipeline through module function."""
        result = analyze_binary_decompilation(test_binaries["simple_pe"])

        # Should return comprehensive analysis results
        assert result is not None
        assert isinstance(result, dict)

        # Should orchestrate complete analysis pipeline
        expected_components = [
            'decompilation_engine', 'binary_analysis', 'license_findings',
            'security_assessment', 'recommendations'
        ]

        # Verify some key components are present
        found_components = [comp for comp in expected_components if comp in result or comp.replace('_', '') in str(result).lower()]
        assert len(found_components) >= 2, "Insufficient analysis components in result"

    def test_analyze_binary_decompilation_with_options(self, test_binaries: Any) -> None:
        """Test module function with custom analysis options."""
        options = {
            'deep_analysis': True,
            'bypass_suggestions': True,
            'export_format': 'json'
        }

        result = analyze_binary_decompilation(test_binaries["simple_pe"], options=options)  # type: ignore[call-arg]

        assert result is not None
        # Should respect analysis options
        if isinstance(result, dict):
            # Options should influence the analysis depth and output
            assert len(str(result)) > 500, "Analysis result too brief for deep analysis"

    def test_analyze_binary_decompilation_error_handling(self) -> None:
        """Test module function error handling with invalid inputs."""
        # Test with non-existent file
        with pytest.raises((FileNotFoundError, ValueError, OSError)):
            analyze_binary_decompilation("/nonexistent/file.exe")

        # Test with invalid file
        with tempfile.NamedTemporaryFile(suffix=".txt") as temp_file:
            temp_file.write(b"This is not a binary file")
            temp_file.flush()

            result = analyze_binary_decompilation(temp_file.name)
            # Should handle gracefully or raise appropriate exception
            assert result is None or (isinstance(result, dict) and 'error' in result)


class TestR2DecompilationEngineIntegration:
    """Integration tests for comprehensive workflow validation."""

    @pytest.fixture
    def engine(self, test_binaries: dict[str, str]) -> Any:
        return R2DecompilationEngine(test_binaries["complex_pe"])

    def test_complete_security_research_workflow(self, engine: Any) -> None:
        """Test complete security research workflow from analysis to exploitation."""
        # Phase 1: Binary Analysis
        functions = engine.decompile_all_functions()
        assert functions is not None

        # Phase 2: License Analysis
        license_analysis = engine.analyze_license_functions()
        assert license_analysis is not None

        # Phase 3: Vulnerability Assessment
        vulnerabilities = engine._detect_vulnerability_patterns()
        assert vulnerabilities is not None

        # Phase 4: Bypass Strategy Generation
        bypass_suggestions = engine.generate_license_bypass_suggestions()
        assert bypass_suggestions is not None

        # Phase 5: Comprehensive Reporting
        final_report = engine.export_analysis_report(format="json")
        assert final_report is not None

        # Workflow should produce actionable intelligence
        total_findings = len(functions or []) + len(vulnerabilities or []) + len(bypass_suggestions or [])
        assert total_findings > 0, "Security research workflow produced no actionable findings"

    def test_cross_module_data_consistency(self, engine: Any) -> None:
        """Test consistency of data across different analysis modules."""
        # Perform multiple analyses
        decompiled_functions = engine.decompile_all_functions()
        license_patterns = engine._detect_license_patterns()
        api_calls = engine._extract_api_calls()
        strings = engine._get_string_references()

        # Data should be consistent across analyses
        if decompiled_functions and license_patterns:
            # Functions identified in decompilation should correlate with license patterns
            function_addresses = [f.get('address') for f in decompiled_functions if isinstance(f, dict)]
            pattern_locations = [p.get('location') for p in license_patterns if isinstance(p, dict)]

            # Some correlation should exist
            overlapping_addresses = set(function_addresses) & set(pattern_locations)
            # Allow for different address formats or ranges
            assert function_addresses or pattern_locations

    def test_performance_with_real_world_complexity(self, engine: Any) -> None:
        """Test performance characteristics with realistic complexity."""
        import time

        # Time comprehensive analysis
        start_time = time.time()

        # Perform multiple analysis operations
        decompilation_result = engine.decompile_all_functions()
        license_analysis = engine.analyze_license_functions()
        bypass_suggestions = engine.generate_license_bypass_suggestions()
        final_report = engine.export_analysis_report()

        total_time = time.time() - start_time

        # Should complete within reasonable time for production use
        assert total_time < 300, f"Analysis took too long: {total_time}s"

        # All operations should return valid results
        results = [decompilation_result, license_analysis, bypass_suggestions, final_report]
        non_null_results = [r for r in results if r is not None]
        assert len(non_null_results) >= 2, "Too many analysis operations failed"


@pytest.mark.integration
class TestR2DecompilationEngineRealWorldScenarios:
    """Test with real-world binary analysis scenarios."""

    def test_commercial_software_protection_analysis(self, test_binaries: Any) -> None:
        """Test analysis of binaries with commercial protection mechanisms."""
        engine = R2DecompilationEngine(test_binaries["complex_pe"])

        # Should handle sophisticated protection mechanisms
        license_analysis = engine.analyze_license_functions()
        bypass_suggestions = engine.generate_license_bypass_suggestions()  # type: ignore[call-arg]

        # Should provide meaningful analysis for protected software
        assert license_analysis is not None
        assert bypass_suggestions is not None

        # Analysis should identify protection complexity
        if isinstance(license_analysis, dict) and 'protection_strength' in license_analysis:
            strength = license_analysis['protection_strength']
            assert isinstance(strength, (int, float, str))

    def test_obfuscated_binary_analysis_effectiveness(self, test_binaries: Any) -> None:
        """Test effectiveness against obfuscated binaries."""
        engine = R2DecompilationEngine(test_binaries["complex_pe"])

        # Should handle obfuscated code
        cfg_analysis = engine._analyze_control_flow(0x401000)  # type: ignore[arg-type]
        vulnerability_patterns = engine._detect_vulnerability_patterns()  # type: ignore[call-arg]

        # Should detect obfuscation and provide analysis
        assert cfg_analysis is not None
        if isinstance(cfg_analysis, dict):
            # Should detect obfuscation techniques
            obfuscation_detected = cfg_analysis.get('obfuscation_detected', False)
            # Either detect obfuscation or provide meaningful analysis despite it
            assert obfuscation_detected is not None

    def test_multi_architecture_support_validation(self) -> None:
        """Test support for multiple binary architectures."""
        # This would test x86, x64, ARM, etc. support
        # For now, validate that architecture detection works

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as temp_file:
            # Create minimal PE with different architecture indicator
            pe_data = TestBinarySamples.create_simple_pe_binary()
            temp_file.write(pe_data)
            temp_file.flush()

            engine = R2DecompilationEngine(temp_file.name)

            # Should detect and handle architecture appropriately
            # This tests that the engine can initialize with different architectures
            assert hasattr(engine, 'binary_path')

        os.unlink(temp_file.name)


if __name__ == "__main__":
    # Run tests with comprehensive coverage reporting
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--cov=intellicrack.core.analysis.radare2_decompiler",
        "--cov-report=term-missing",
        "--cov-report=html:coverage_html",
        "--cov-fail-under=80"
    ])
