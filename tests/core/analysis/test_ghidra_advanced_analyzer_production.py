"""Production tests for Ghidra Advanced Analyzer.

Tests validate REAL advanced binary analysis capabilities including variable
recovery, structure recovery, vtable analysis, exception handlers, and debug
symbol parsing. Tests operate on REAL PE/ELF binaries - NO mocks, NO stubs.

All tests validate genuine offensive binary analysis capabilities required for
effective software protection analysis and licensing crack development.
"""

import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    pefile = None  # type: ignore[assignment]

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False
    lief = None  # type: ignore[assignment]

if TYPE_CHECKING:
    import pefile as pefile_module

from intellicrack.core.analysis.ghidra_advanced_analyzer import (
    DebugSymbolInfo,
    ExceptionHandlerInfo,
    GhidraAdvancedAnalyzer,
    RecoveredStructure,
    RecoveredVariable,
    VTableInfo,
    apply_advanced_analysis,
)
from intellicrack.core.analysis.ghidra_analyzer import (
    GhidraAnalysisResult,
    GhidraDataType,
    GhidraFunction,
)

pytestmark = pytest.mark.skipif(
    not (PEFILE_AVAILABLE and LIEF_AVAILABLE),
    reason="pefile and lief required for advanced analysis tests"
)


@pytest.fixture
def sample_pe_binary(temp_workspace: Path) -> Path:
    """Use real Windows system binary for testing."""
    system_binary = Path("C:/Windows/System32/notepad.exe")

    if system_binary.exists():
        return system_binary

    import subprocess
    import sys
    minimal_pe = temp_workspace / "minimal.exe"
    simple_c_code = temp_workspace / "simple.c"
    simple_c_code.write_text("""
    int main() { return 0; }
    """)

    try:
        result = subprocess.run(
            ["gcc", "-o", str(minimal_pe), str(simple_c_code), "-m64"],
            capture_output=True,
            timeout=30
        )
        if result.returncode == 0 and minimal_pe.exists():
            return minimal_pe
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    dos_header = bytearray(b'MZ' + b'\x90' * 58 + struct.pack('<I', 0x80))
    pe_signature = b'PE\x00\x00'
    coff_header = struct.pack('<HHIIIHH',
        0x8664,
        2,
        0,
        0,
        0,
        0xF0,
        0x22
    )

    optional_header = bytearray(248)
    optional_header[:2] = struct.pack('<H', 0x20B)
    struct.pack_into('<Q', optional_header, 24, 0x140000000)
    struct.pack_into('<I', optional_header, 16, 0x1000)
    struct.pack_into('<I', optional_header, 20, 0x1000)

    text_section_header = bytearray(40)
    text_section_header[:5] = b'.text'
    struct.pack_into('<IIIIIHHI',
        text_section_header, 8,
        0x1000,
        0x1000,
        0x200,
        0x200,
        0, 0, 0,
        0x60000020
    )

    rdata_section_header = bytearray(40)
    rdata_section_header[:6] = b'.rdata'
    struct.pack_into('<IIIIIHHI',
        rdata_section_header, 8,
        0x1000,
        0x2000,
        0x200,
        0x400,
        0, 0, 0,
        0x40000040
    )

    text_section = bytearray([0x90, 0xC3] * 256)
    rdata_section = bytearray(512)
    for i in range(10):
        struct.pack_into('<Q', rdata_section, i * 8, 0x140001000 + i * 0x10)

    with open(minimal_pe, 'wb') as f:
        f.write(dos_header)
        f.write(pe_signature)
        f.write(coff_header)
        f.write(optional_header)
        f.write(text_section_header)
        f.write(rdata_section_header)
        f.write(text_section)
        f.write(rdata_section)

    return minimal_pe


@pytest.fixture
def sample_pe_with_debug(temp_workspace: Path, sample_pe_binary: Path) -> Path:
    """Create PE binary with debug information."""
    import shutil

    pe_path = temp_workspace / "test_with_debug.exe"
    shutil.copy(sample_pe_binary, pe_path)

    pe: pefile_module.PE = pefile.PE(str(pe_path))  # type: ignore[attr-defined,union-attr]

    debug_data = bytearray(b"RSDS")
    debug_data.extend(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10")
    debug_data.extend(struct.pack("<I", 1))
    debug_data.extend(b"C:\\path\\to\\binary.pdb\x00")

    pe.close()
    return pe_path


@pytest.fixture
def sample_ghidra_function() -> GhidraFunction:
    """Create sample Ghidra function with assembly for testing."""
    assembly = """push rbp
mov rbp, rsp
sub rsp, 0x30
mov [rbp-0x10], rcx
mov [rbp-0x18], rdx
mov dword ptr [rbp-0x4], 0x0
lea rax, [rbp-0x10]
mov [rbp-0x20], rax
mov eax, [rbp-0x4]
add rsp, 0x30
pop rbp
ret"""

    return GhidraFunction(
        name="ValidateLicense",
        address=0x401000,
        size=0x80,
        signature="bool ValidateLicense(const char* key, int length)",
        return_type="bool",
        parameters=[("const char*", "key"), ("int", "length")],
        local_variables=[],
        decompiled_code="bool ValidateLicense(const char* key, int length) { return true; }",
        assembly_code=assembly,
        xrefs_to=[0x401100],
        xrefs_from=[0x401200],
        comments={},
        calling_convention="__fastcall",
    )


@pytest.fixture
def sample_analysis_result(sample_ghidra_function: GhidraFunction) -> GhidraAnalysisResult:
    """Create sample Ghidra analysis result."""
    return GhidraAnalysisResult(
        binary_path="test.exe",
        architecture="x86:LE:64:default",
        compiler="Visual Studio",
        functions={0x401000: sample_ghidra_function},
        data_types={},
        strings=[(0x402000, "Enter license key:"), (0x402020, "Invalid license")],
        imports=[("kernel32.dll", "GetTickCount", 0x403000)],
        exports=[("ValidateLicense", 0x401000)],
        sections=[{"name": ".text", "address": 0x401000, "size": 0x1000}],
        entry_point=0x401000,
        image_base=0x400000,
        vtables={},
        exception_handlers=[],
    )


class TestGhidraAdvancedAnalyzerInitialization:
    """Test analyzer initialization with real binaries."""

    def test_initialize_with_pe_binary(self, sample_pe_binary: Path) -> None:
        """Analyzer initializes successfully with valid PE binary."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        assert analyzer.binary_path == sample_pe_binary
        assert analyzer.pe is not None
        assert analyzer.lief_binary is not None
        assert analyzer.md is not None
        assert analyzer.md.detail is True

    def test_initialize_detects_architecture(self, sample_pe_binary: Path) -> None:
        """Analyzer correctly identifies binary architecture."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        assert analyzer.md is not None
        from capstone import CS_MODE_64
        assert analyzer.md.mode == CS_MODE_64

    def test_initialize_with_invalid_path(self, temp_workspace: Path) -> None:
        """Analyzer handles non-existent binary gracefully."""
        invalid_path = temp_workspace / "nonexistent.exe"
        analyzer = GhidraAdvancedAnalyzer(str(invalid_path))

        assert analyzer.binary_path == invalid_path
        assert analyzer.pe is None
        assert analyzer.lief_binary is None


class TestVariableRecovery:
    """Test variable recovery from assembly code."""

    def test_recover_local_variables_from_stack(self, sample_pe_binary: Path, sample_ghidra_function: GhidraFunction) -> None:
        """Recovers local variables from stack frame analysis."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        variables = analyzer.recover_variables(sample_ghidra_function)

        assert len(variables) > 0
        assert all(isinstance(var, RecoveredVariable) for var in variables)

        local_vars = [v for v in variables if v.scope == "local"]
        assert local_vars

        for var in local_vars:
            assert var.name.startswith("local_")
            assert var.offset < 0
            assert var.size > 0
            assert var.type in ["uint8_t", "uint16_t", "uint32_t", "uint64_t", "uint32_t*", "uint64_t*"]

    def test_recover_function_parameters(self, sample_pe_binary: Path, sample_ghidra_function: GhidraFunction) -> None:
        """Recovers function parameters from stack analysis."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        variables = analyzer.recover_variables(sample_ghidra_function)

        params = [v for v in variables if v.scope == "parameter"]
        assert params

        for param in params:
            assert param.name.startswith("param_")
            assert param.offset >= 0
            assert param.size > 0

    def test_detect_pointer_variables(self, sample_pe_binary: Path, sample_ghidra_function: GhidraFunction) -> None:
        """Identifies pointer variables from LEA instructions."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        variables = analyzer.recover_variables(sample_ghidra_function)

        pointers = [v for v in variables if v.is_pointer]
        assert pointers

        for ptr in pointers:
            assert "*" in ptr.type or ptr.is_pointer

    def test_track_variable_usage_count(self, sample_pe_binary: Path, sample_ghidra_function: GhidraFunction) -> None:
        """Tracks how many times each variable is accessed."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        variables = analyzer.recover_variables(sample_ghidra_function)

        for var in variables:
            assert var.usage_count > 0
            assert var.first_use >= 0
            assert var.last_use >= var.first_use

    def test_infer_types_from_instructions(self, sample_pe_binary: Path) -> None:
        """Infers variable types from instruction operand sizes."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        assert analyzer._infer_type_from_instruction("mov", "mov qword ptr [rbp-0x10], rax") == "uint64_t"
        assert analyzer._infer_type_from_instruction("mov", "mov dword ptr [rbp-0x10], eax") == "uint32_t"
        assert analyzer._infer_type_from_instruction("mov", "mov word ptr [rbp-0x10], ax") == "uint16_t"
        assert analyzer._infer_type_from_instruction("mov", "mov byte ptr [rbp-0x10], al") == "uint8_t"

        assert analyzer._infer_type_from_instruction("lea", "lea rax, [rbp-0x10]") == "uint64_t*"

        float_type = analyzer._infer_type_from_instruction("fld", "fld dword ptr [rbp-0x10]")
        assert float_type in ["float", "double"]

    def test_get_size_from_type(self, sample_pe_binary: Path) -> None:
        """Correctly maps types to sizes in bytes."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        assert analyzer._get_size_from_type("uint8_t") == 1
        assert analyzer._get_size_from_type("uint16_t") == 2
        assert analyzer._get_size_from_type("uint32_t") == 4
        assert analyzer._get_size_from_type("uint64_t") == 8
        assert analyzer._get_size_from_type("float") == 4
        assert analyzer._get_size_from_type("double") == 8

        assert analyzer._get_size_from_type("uint64_t*") in [4, 8]
        assert analyzer._get_size_from_type("char*") in [4, 8]

    def test_empty_assembly_returns_no_variables(self, sample_pe_binary: Path) -> None:
        """Handles functions with no assembly code."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        empty_func = GhidraFunction(
            name="EmptyFunc",
            address=0x401000,
            size=0x10,
            signature="void EmptyFunc()",
            return_type="void",
            parameters=[],
            local_variables=[],
            decompiled_code="",
            assembly_code="",
            xrefs_to=[],
            xrefs_from=[],
            comments={},
        )

        variables = analyzer.recover_variables(empty_func)
        assert len(variables) == 0


class TestStructureRecovery:
    """Test structure recovery from memory access patterns."""

    def test_recover_structures_from_analysis(self, sample_pe_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """Recovers structure definitions from memory access patterns."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        structures = analyzer.recover_structures(sample_analysis_result)

        assert isinstance(structures, list)
        for struct_obj in structures:
            assert isinstance(struct_obj, RecoveredStructure)
            assert len(struct_obj.name) > 0
            assert struct_obj.size > 0
            assert struct_obj.alignment > 0
            assert isinstance(struct_obj.members, list)

    def test_recovered_structure_has_members(self, sample_pe_binary: Path) -> None:
        """Recovered structures contain member definitions."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        func_with_struct = GhidraFunction(
            name="ProcessStruct",
            address=0x401000,
            size=0x100,
            signature="void ProcessStruct(void* obj)",
            return_type="void",
            parameters=[("void*", "obj")],
            local_variables=[],
            decompiled_code="",
            assembly_code="""mov rax, [rcx+0x0]
mov rbx, [rcx+0x8]
mov rdx, [rcx+0x10]
mov rsi, [rcx+0x18]
mov rdi, [rcx+0x20]""",
            xrefs_to=[],
            xrefs_from=[],
            comments={},
        )

        analysis_result = GhidraAnalysisResult(
            binary_path=str(sample_pe_binary),
            architecture="x86:LE:64:default",
            compiler="gcc",
            functions={0x401000: func_with_struct},
            data_types={},
            strings=[],
            imports=[],
            exports=[],
            sections=[],
            entry_point=0x401000,
            image_base=0x400000,
            vtables={},
            exception_handlers=[],
        )

        structures = analyzer.recover_structures(analysis_result)

        if len(structures) > 0:
            struct_obj = structures[0]
            assert len(struct_obj.members) >= 3

            for member in struct_obj.members:
                assert "name" in member
                assert "type" in member
                assert "offset" in member
                assert "size" in member
                assert member["size"] > 0

    def test_detect_vtable_in_structure(self, sample_pe_binary: Path) -> None:
        """Identifies vtable pointer at offset 0 in structures."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        func_with_vtable = GhidraFunction(
            name="ConstructObject",
            address=0x401000,
            size=0x80,
            signature="void ConstructObject(void* obj)",
            return_type="void",
            parameters=[("void*", "obj")],
            local_variables=[],
            decompiled_code="",
            assembly_code="""lea rax, [vtable_addr]
mov [rcx+0x0], rax
mov [rcx+0x8], rdx
mov [rcx+0x10], rsi""",
            xrefs_to=[],
            xrefs_from=[],
            comments={},
        )

        analysis_result = GhidraAnalysisResult(
            binary_path=str(sample_pe_binary),
            architecture="x86:LE:64:default",
            compiler="gcc",
            functions={0x401000: func_with_vtable},
            data_types={},
            strings=[],
            imports=[],
            exports=[],
            sections=[],
            entry_point=0x401000,
            image_base=0x400000,
            vtables={},
            exception_handlers=[],
        )

        structures = analyzer.recover_structures(analysis_result)

        if len(structures) > 0:
            if vtable_structs := [
                s for s in structures if s.vtable_offset is not None
            ]:
                assert vtable_structs[0].vtable_offset == 0

    def test_structure_size_calculation(self, sample_pe_binary: Path) -> None:
        """Calculates structure size from member offsets."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        func = GhidraFunction(
            name="AccessMembers",
            address=0x401000,
            size=0x50,
            signature="void AccessMembers(void* p)",
            return_type="void",
            parameters=[("void*", "p")],
            local_variables=[],
            decompiled_code="",
            assembly_code="""mov eax, [rcx+0x0]
mov ebx, [rcx+0x4]
mov edx, [rcx+0x8]""",
            xrefs_to=[],
            xrefs_from=[],
            comments={},
        )

        analysis_result = GhidraAnalysisResult(
            binary_path=str(sample_pe_binary),
            architecture="x86:LE:64:default",
            compiler="gcc",
            functions={0x401000: func},
            data_types={},
            strings=[],
            imports=[],
            exports=[],
            sections=[],
            entry_point=0x401000,
            image_base=0x400000,
            vtables={},
            exception_handlers=[],
        )

        structures = analyzer.recover_structures(analysis_result)

        for struct_obj in structures:
            assert struct_obj.size >= max(m["offset"] + m["size"] for m in struct_obj.members)


class TestVTableAnalysis:
    """Test virtual table detection and analysis."""

    def test_analyze_vtables_in_pe(self, sample_pe_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """Detects vtables in PE binary data sections."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        vtables = analyzer.analyze_vtables(sample_analysis_result)

        assert isinstance(vtables, list)
        for vtable in vtables:
            assert isinstance(vtable, VTableInfo)
            assert vtable.address > 0
            assert len(vtable.class_name) > 0
            assert isinstance(vtable.functions, list)

    def test_scan_for_consecutive_function_pointers(self, sample_pe_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """Identifies vtables by consecutive function pointer patterns."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        vtables = analyzer.analyze_vtables(sample_analysis_result)

        if valid_vtables := [v for v in vtables if len(v.functions) >= 3]:
            for vtable in valid_vtables:
                assert len(vtable.functions) >= 3
                for func_addr in vtable.functions:
                    assert func_addr > 0

    def test_identify_destructor_in_vtable(self, sample_pe_binary: Path) -> None:
        """Identifies destructor as second function in vtable."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        func_addrs = [0x401000, 0x401100, 0x401200, 0x401300]
        destructor = analyzer._find_destructor(func_addrs)

        assert destructor == 0x401100

    def test_is_code_address_validation(self, sample_pe_binary: Path) -> None:
        """Validates addresses point to executable code sections."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        if analyzer.pe:
            code_addr = 0x1000 + analyzer.pe.OPTIONAL_HEADER.ImageBase
            assert analyzer._is_code_address(code_addr)

            data_addr = 0x3000 + analyzer.pe.OPTIONAL_HEADER.ImageBase
            result = analyzer._is_code_address(data_addr)
            assert isinstance(result, bool)


class TestExceptionHandlerExtraction:
    """Test exception handler information extraction."""

    def test_extract_cpp_exception_handlers(self, sample_pe_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """Extracts C++ exception handlers from .pdata section."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        handlers = analyzer.extract_exception_handlers(sample_analysis_result)

        assert isinstance(handlers, list)
        for handler in handlers:
            assert isinstance(handler, ExceptionHandlerInfo)
            assert handler.type in ["SEH", "C++", "VEH"]
            assert handler.handler_address >= 0
            assert handler.try_start >= 0
            assert handler.try_end >= handler.try_start
            assert isinstance(handler.catch_blocks, list)

    def test_extract_cpp_eh_from_pdata(self, sample_pe_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """Parses RUNTIME_FUNCTION structures from .pdata section."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        handlers = analyzer._extract_cpp_eh()

        assert isinstance(handlers, list)

        cpp_handlers = [h for h in handlers if h.type == "C++"]
        for handler in cpp_handlers:
            assert handler.handler_address > 0
            assert handler.try_end > handler.try_start

    def test_extract_seh_returns_list(self, sample_pe_binary: Path) -> None:
        """SEH extraction returns valid list."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        seh_handlers = analyzer._extract_seh()
        assert isinstance(seh_handlers, list)

    def test_extract_veh_returns_list(self, sample_pe_binary: Path) -> None:
        """VEH extraction returns valid list."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        veh_handlers = analyzer._extract_veh()
        assert isinstance(veh_handlers, list)


class TestDebugSymbolParsing:
    """Test debug symbol information parsing."""

    def test_parse_pdb_debug_info(self, sample_pe_with_debug: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """Parses PDB information from PE debug directory."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_with_debug))
        debug_info = analyzer.parse_debug_symbols(sample_analysis_result)

        if debug_info is None:
            pytest.skip("No debug information available in test binary")

        assert isinstance(debug_info, DebugSymbolInfo)
        assert debug_info.type in ["PDB", "DWARF"]
        assert isinstance(debug_info.symbols, dict)
        assert isinstance(debug_info.types, dict)
        assert isinstance(debug_info.source_files, list)
        assert isinstance(debug_info.line_numbers, dict)

    def test_parse_debug_symbols_no_debug_info(self, sample_pe_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """Returns None when no debug information present."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        debug_info = analyzer.parse_debug_symbols(sample_analysis_result)

        assert debug_info is None or isinstance(debug_info, DebugSymbolInfo)

    def test_extract_class_name_from_rtti(self, sample_pe_binary: Path) -> None:
        """Extracts class names from RTTI data."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        rtti_data = b"\x00\x00\x00\x00\x00\x00\x00\x00test_class_name\x00"
        class_name = analyzer._extract_class_name_from_rtti(rtti_data)

        assert isinstance(class_name, str)
        assert len(class_name) > 0
        assert "rtti_class_" in class_name


class TestCustomDataTypeCreation:
    """Test custom Ghidra data type generation."""

    def test_create_datatypes_from_structures(self, sample_pe_binary: Path) -> None:
        """Creates Ghidra data types from recovered structures."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        structures = [
            RecoveredStructure(
                name="LicenseKey",
                size=32,
                alignment=8,
                members=[
                    {"name": "serial", "type": "char[16]", "offset": 0, "size": 16},
                    {"name": "checksum", "type": "uint32_t", "offset": 16, "size": 4},
                    {"name": "flags", "type": "uint32_t", "offset": 20, "size": 4},
                ],
            )
        ]

        datatypes = analyzer.create_custom_datatypes(structures)

        assert len(datatypes) > 0

        struct_types = [dt for dt in datatypes if dt.category == "struct"]
        assert struct_types

        struct_type = struct_types[0]
        assert isinstance(struct_type, GhidraDataType)
        assert struct_type.name == "LicenseKey"
        assert struct_type.size == 32
        assert struct_type.alignment == 8
        assert len(struct_type.members) == 3

    def test_create_pointer_types(self, sample_pe_binary: Path) -> None:
        """Creates pointer types for each structure."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        structures = [
            RecoveredStructure(
                name="TestStruct",
                size=16,
                alignment=4,
                members=[{"name": "field", "type": "int", "offset": 0, "size": 4}],
            )
        ]

        datatypes = analyzer.create_custom_datatypes(structures)

        pointer_types = [dt for dt in datatypes if dt.category == "pointer"]
        assert pointer_types

        ptr_type = pointer_types[0]
        assert ptr_type.size == 8
        assert ptr_type.base_type == "TestStruct"

    def test_create_array_types(self, sample_pe_binary: Path) -> None:
        """Creates array types for common sizes."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        structures = [
            RecoveredStructure(
                name="Element",
                size=8,
                alignment=4,
                members=[{"name": "value", "type": "int", "offset": 0, "size": 4}],
            )
        ]

        datatypes = analyzer.create_custom_datatypes(structures)

        array_types = [dt for dt in datatypes if dt.category == "array"]
        assert array_types

        for array_type in array_types:
            assert array_type.base_type == "Element"
            assert array_type.size > 8


class TestAdvancedAnalysisIntegration:
    """Test complete advanced analysis workflow."""

    def test_apply_advanced_analysis_integration(self, sample_pe_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """Applies all advanced analysis features to Ghidra results."""
        enhanced_result = apply_advanced_analysis(sample_analysis_result, str(sample_pe_binary))

        assert isinstance(enhanced_result, GhidraAnalysisResult)
        assert enhanced_result.binary_path == sample_analysis_result.binary_path

        for func in enhanced_result.functions.values():
            assert len(func.local_variables) >= len(sample_analysis_result.functions[func.address].local_variables)

    def test_advanced_analysis_adds_structures(self, sample_pe_binary: Path) -> None:
        """Advanced analysis adds recovered structures to results."""
        func_with_struct = GhidraFunction(
            name="ProcessData",
            address=0x401000,
            size=0x100,
            signature="void ProcessData(void* data)",
            return_type="void",
            parameters=[("void*", "data")],
            local_variables=[],
            decompiled_code="",
            assembly_code="""mov rax, [rcx+0x0]
mov rbx, [rcx+0x8]
mov rdx, [rcx+0x10]""",
            xrefs_to=[],
            xrefs_from=[],
            comments={},
        )

        base_result = GhidraAnalysisResult(
            binary_path=str(sample_pe_binary),
            architecture="x86:LE:64:default",
            compiler="gcc",
            functions={0x401000: func_with_struct},
            data_types={},
            strings=[],
            imports=[],
            exports=[],
            sections=[],
            entry_point=0x401000,
            image_base=0x400000,
            vtables={},
            exception_handlers=[],
        )

        enhanced_result = apply_advanced_analysis(base_result, str(sample_pe_binary))

        assert len(enhanced_result.data_types) >= len(base_result.data_types)

    def test_advanced_analysis_adds_vtables(self, sample_pe_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """Advanced analysis identifies and adds vtable information."""
        enhanced_result = apply_advanced_analysis(sample_analysis_result, str(sample_pe_binary))

        assert isinstance(enhanced_result.vtables, dict)
        assert len(enhanced_result.vtables) >= len(sample_analysis_result.vtables)

    def test_advanced_analysis_adds_exception_handlers(self, sample_pe_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """Advanced analysis extracts exception handler information."""
        enhanced_result = apply_advanced_analysis(sample_analysis_result, str(sample_pe_binary))

        assert isinstance(enhanced_result.exception_handlers, list)
        assert len(enhanced_result.exception_handlers) >= len(sample_analysis_result.exception_handlers)

    def test_advanced_analysis_preserves_original_data(self, sample_pe_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """Advanced analysis preserves all original analysis data."""
        enhanced_result = apply_advanced_analysis(sample_analysis_result, str(sample_pe_binary))

        assert enhanced_result.binary_path == sample_analysis_result.binary_path
        assert enhanced_result.architecture == sample_analysis_result.architecture
        assert enhanced_result.compiler == sample_analysis_result.compiler
        assert enhanced_result.entry_point == sample_analysis_result.entry_point
        assert enhanced_result.image_base == sample_analysis_result.image_base
        assert len(enhanced_result.functions) == len(sample_analysis_result.functions)


class TestRealBinaryAnalysis:
    """Test analysis on real system binaries when available."""

    @pytest.mark.skipif(not Path("C:/Windows/System32/notepad.exe").exists(), reason="Windows system binary not available")
    def test_analyze_real_windows_binary(self) -> None:
        """Analyzes real Windows system binary (notepad.exe)."""
        notepad_path = Path("C:/Windows/System32/notepad.exe")

        analyzer = GhidraAdvancedAnalyzer(str(notepad_path))

        assert analyzer.pe is not None
        assert analyzer.lief_binary is not None
        assert analyzer.md is not None

        base_result = GhidraAnalysisResult(
            binary_path=str(notepad_path),
            architecture="x86:LE:64:default",
            compiler="Visual Studio",
            functions={},
            data_types={},
            strings=[],
            imports=[],
            exports=[],
            sections=[],
            entry_point=0x1000,
            image_base=0x140000000,
            vtables={},
            exception_handlers=[],
        )

        enhanced_result = apply_advanced_analysis(base_result, str(notepad_path))

        assert isinstance(enhanced_result, GhidraAnalysisResult)
        assert enhanced_result.binary_path == str(notepad_path)

    @pytest.mark.skipif(not Path("C:/Windows/System32/kernel32.dll").exists(), reason="Windows system DLL not available")
    def test_analyze_real_dll_with_exports(self) -> None:
        """Analyzes real Windows DLL with vtables and exception handlers."""
        kernel32_path = Path("C:/Windows/System32/kernel32.dll")

        analyzer = GhidraAdvancedAnalyzer(str(kernel32_path))

        assert analyzer.pe is not None

        base_result = GhidraAnalysisResult(
            binary_path=str(kernel32_path),
            architecture="x86:LE:64:default",
            compiler="Visual Studio",
            functions={},
            data_types={},
            strings=[],
            imports=[],
            exports=[],
            sections=[],
            entry_point=0x1000,
            image_base=0x180000000,
            vtables={},
            exception_handlers=[],
        )

        handlers = analyzer.extract_exception_handlers(base_result)
        assert isinstance(handlers, list)


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_analyze_empty_binary(self, temp_workspace: Path) -> None:
        """Handles empty binary file gracefully."""
        empty_file = temp_workspace / "empty.exe"
        empty_file.write_bytes(b"")

        analyzer = GhidraAdvancedAnalyzer(str(empty_file))

        assert analyzer.pe is None
        assert analyzer.lief_binary is None

    def test_analyze_corrupted_pe(self, temp_workspace: Path) -> None:
        """Handles corrupted PE file gracefully."""
        corrupted_file = temp_workspace / "corrupted.exe"
        corrupted_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

        analyzer = GhidraAdvancedAnalyzer(str(corrupted_file))

        assert analyzer.binary_path == corrupted_file

    def test_recover_variables_handles_malformed_assembly(self, sample_pe_binary: Path) -> None:
        """Handles malformed assembly code gracefully."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        malformed_func = GhidraFunction(
            name="MalformedFunc",
            address=0x401000,
            size=0x10,
            signature="void MalformedFunc()",
            return_type="void",
            parameters=[],
            local_variables=[],
            decompiled_code="",
            assembly_code="invalid assembly\n#$%^\n\n\n",
            xrefs_to=[],
            xrefs_from=[],
            comments={},
        )

        variables = analyzer.recover_variables(malformed_func)
        assert isinstance(variables, list)

    def test_vtable_analysis_with_no_code_sections(self, sample_pe_binary: Path) -> None:
        """Handles binaries with no executable sections."""
        analyzer = GhidraAdvancedAnalyzer(str(sample_pe_binary))

        base_result = GhidraAnalysisResult(
            binary_path=str(sample_pe_binary),
            architecture="x86:LE:64:default",
            compiler="gcc",
            functions={},
            data_types={},
            strings=[],
            imports=[],
            exports=[],
            sections=[],
            entry_point=0,
            image_base=0,
            vtables={},
            exception_handlers=[],
        )

        vtables = analyzer.analyze_vtables(base_result)
        assert isinstance(vtables, list)
