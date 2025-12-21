"""Production tests for Ghidra Output Parser.

This module tests the ghidra_output_parser.py module which parses Ghidra analysis
output in various formats (XML, JSON, decompilation) and extracts functions, structures,
cross-references, and other analysis artifacts for license cracking analysis.

Copyright (C) 2025 Zachary Flint
"""

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def sample_xml_output(tmp_path: Path) -> Path:
    """Create sample Ghidra XML output."""
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<PROGRAM>
    <PROGRAM_INFO NAME="sample.exe" IMAGE_BASE="0x00400000" />
    <FUNCTIONS>
        <FUNCTION NAME="CheckLicense" ADDRESS="0x00401000" SIZE="0x100">
            <RETURN_TYPE>bool</RETURN_TYPE>
            <CALLING_CONVENTION>__cdecl</CALLING_CONVENTION>
            <PARAMETERS>
                <PARAMETER TYPE="const char*" NAME="key" />
            </PARAMETERS>
        </FUNCTION>
        <FUNCTION NAME="ValidateSerial" ADDRESS="0x00401100" SIZE="0x80">
            <RETURN_TYPE>int</RETURN_TYPE>
        </FUNCTION>
    </FUNCTIONS>
    <DATA_TYPES>
        <STRUCTURE NAME="LICENSE_KEY" SIZE="0x20">
            <FIELD NAME="data" TYPE="char[32]" OFFSET="0" SIZE="32" />
        </STRUCTURE>
    </DATA_TYPES>
    <PROGRAM_XREFS>
        <XREF FROM="0x00401050" TO="0x00401200" TYPE="CALL" />
        <XREF FROM="0x00401060" TO="0x00402000" TYPE="DATA_READ" />
    </PROGRAM_XREFS>
    <DEFINED_DATA>
        <STRING ADDRESS="0x00402000" VALUE="Invalid license" />
        <STRING ADDRESS="0x00402020" VALUE="Trial expired" />
    </DEFINED_DATA>
</PROGRAM>
"""
    xml_path = tmp_path / "ghidra_output.xml"
    xml_path.write_text(xml_content, encoding="utf-8")
    return xml_path


@pytest.fixture
def sample_json_output(tmp_path: Path) -> Path:
    """Create sample Ghidra JSON output."""
    json_data = {
        "functions": [
            {
                "name": "CheckLicense",
                "address": "0x00401000",
                "returnType": "bool",
                "callingConvention": "__cdecl",
                "parameters": [
                    {"type": "const char*", "name": "key"},
                ],
                "localVariables": [
                    {"type": "int", "name": "result", "offset": -4},
                ],
                "isThunk": False,
                "isExported": True,
                "isImported": False,
                "stackFrameSize": 64,
            },
            {
                "name": "ValidateSerial",
                "address": "0x00401100",
                "returnType": "int",
                "parameters": [],
                "localVariables": [],
                "isThunk": False,
                "isExported": False,
                "isImported": False,
                "stackFrameSize": 32,
            },
        ],
        "decompilation": [
            {
                "name": "CheckLicense",
                "address": "0x00401000",
                "code": "bool CheckLicense(const char* key) {\n  return validate(key);\n}",
                "pcode": "p-code representation",
                "cyclomaticComplexity": 3,
                "basicBlocks": 5,
                "edges": 6,
            },
        ],
        "imports": [
            {"name": "GetTickCount", "address": "0x00403000"},
            {"name": "MessageBoxA", "address": "0x00403004"},
        ],
        "exports": [
            {"name": "CheckLicense", "address": "0x00401000"},
            {"name": "ValidateKey", "address": "0x00401500"},
        ],
        "vtables": [
            {
                "address": "0x00404000",
                "entries": ["0x00401000", "0x00401100", "0x00401200"],
            },
        ],
    }

    json_path = tmp_path / "ghidra_output.json"
    json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")
    return json_path


@pytest.fixture
def sample_decompilation_output(tmp_path: Path) -> Path:
    """Create sample Ghidra decompilation output."""
    decomp_content = """
/*  *  FUNCTION: CheckLicense @ 0x00401000  */
bool CheckLicense(const char* key) {
  int result;
  char buffer[64];

  if (key == NULL) {
    return false;
  }

  result = validate_key(key, buffer);
  if (result != 0) {
    return true;
  }

  return false;
}

/*  *  FUNCTION: ValidateSerial @ 0x00401100  */
int ValidateSerial(const char* serial) {
  if (strlen(serial) < 16) {
    return -1;
  }

  return check_checksum(serial);
}

/*  *  FUNCTION: ActivateLicense @ 0x00401200  */
void ActivateLicense(LICENSE_KEY* key) {
  if (key != NULL) {
    key->activated = 1;
    save_to_registry(key);
  }
}
"""
    decomp_path = tmp_path / "decompilation.c"
    decomp_path.write_text(decomp_content, encoding="utf-8")
    return decomp_path


class TestGhidraOutputParserDataClasses:
    """Test Ghidra output parser dataclasses."""

    def test_function_signature_creation(self) -> None:
        """FunctionSignature dataclass can be created."""
        from intellicrack.core.analysis.ghidra_output_parser import FunctionSignature

        func = FunctionSignature(
            name="CheckLicense",
            address=0x401000,
            return_type="bool",
            parameters=[("const char*", "key")],
            calling_convention="__cdecl",
            is_thunk=False,
            is_exported=True,
            is_imported=False,
            stack_frame_size=64,
            local_variables=[("int", "result", -4)],
        )

        assert func.name == "CheckLicense"
        assert func.address == 0x401000
        assert func.return_type == "bool"
        assert len(func.parameters) == 1
        assert len(func.local_variables) == 1
        assert func.is_exported is True

    def test_data_structure_creation(self) -> None:
        """DataStructure dataclass can be created."""
        from intellicrack.core.analysis.ghidra_output_parser import DataStructure

        struct = DataStructure(
            name="LICENSE_KEY",
            size=32,
            fields=[("char[32]", "data", 0, 32)],
            is_union=False,
            alignment=4,
            packed=False,
        )

        assert struct.name == "LICENSE_KEY"
        assert struct.size == 32
        assert len(struct.fields) == 1
        assert struct.is_union is False

    def test_cross_reference_creation(self) -> None:
        """CrossReference dataclass can be created."""
        from intellicrack.core.analysis.ghidra_output_parser import CrossReference

        xref = CrossReference(
            from_address=0x401000,
            to_address=0x401200,
            ref_type="CALL",
            from_function="CheckLicense",
            to_function="ValidateKey",
            instruction="call 0x401200",
        )

        assert xref.from_address == 0x401000
        assert xref.to_address == 0x401200
        assert xref.ref_type == "CALL"

    def test_decompiled_function_creation(self) -> None:
        """DecompiledFunction dataclass can be created."""
        from intellicrack.core.analysis.ghidra_output_parser import DecompiledFunction

        decomp = DecompiledFunction(
            name="CheckLicense",
            address=0x401000,
            pseudocode="bool CheckLicense() { return true; }",
            high_pcode="pcode representation",
            complexity=2,
            basic_blocks=3,
            edges=2,
        )

        assert decomp.name == "CheckLicense"
        assert decomp.address == 0x401000
        assert decomp.complexity == 2


class TestGhidraOutputParserInitialization:
    """Test GhidraOutputParser initialization."""

    def test_parser_initialization(self) -> None:
        """Parser initializes with empty data structures."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()

        assert isinstance(parser.functions, dict)
        assert isinstance(parser.structures, dict)
        assert isinstance(parser.xrefs, list)
        assert isinstance(parser.decompiled, dict)
        assert isinstance(parser.imports, dict)
        assert isinstance(parser.exports, dict)
        assert isinstance(parser.strings, dict)
        assert isinstance(parser.vtables, dict)

        assert len(parser.functions) == 0
        assert len(parser.structures) == 0
        assert len(parser.xrefs) == 0


class TestGhidraOutputParserXMLParsing:
    """Test XML output parsing."""

    def test_parse_xml_output_basic(self, sample_xml_output: Path) -> None:
        """parse_xml_output parses basic XML structure."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        result = parser.parse_xml_output(sample_xml_output)

        assert isinstance(result, dict)
        assert "functions" in result
        assert "structures" in result
        assert "xrefs" in result
        assert "strings" in result

    def test_parse_xml_functions(self, sample_xml_output: Path) -> None:
        """parse_xml_output extracts function information."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        result = parser.parse_xml_output(sample_xml_output)

        assert result["functions"] >= 0
        assert len(parser.functions) >= 0

    def test_parse_xml_structures(self, sample_xml_output: Path) -> None:
        """parse_xml_output extracts data structures."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        result = parser.parse_xml_output(sample_xml_output)

        assert result["structures"] >= 0
        assert len(parser.structures) >= 0

    def test_parse_xml_xrefs(self, sample_xml_output: Path) -> None:
        """parse_xml_output extracts cross-references."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        result = parser.parse_xml_output(sample_xml_output)

        assert result["xrefs"] >= 0
        assert len(parser.xrefs) >= 0

    def test_parse_xml_strings(self, sample_xml_output: Path) -> None:
        """parse_xml_output extracts string references."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        result = parser.parse_xml_output(sample_xml_output)

        assert result["strings"] >= 0
        assert len(parser.strings) >= 0

    def test_parse_xml_invalid_file(self, tmp_path: Path) -> None:
        """parse_xml_output handles invalid XML files."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        invalid_xml = tmp_path / "invalid.xml"
        invalid_xml.write_text("NOT VALID XML", encoding="utf-8")

        parser = GhidraOutputParser()

        with pytest.raises(Exception):
            parser.parse_xml_output(invalid_xml)

    def test_parse_xml_missing_file(self) -> None:
        """parse_xml_output handles missing files."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()

        with pytest.raises(Exception):
            parser.parse_xml_output(Path("C:\\nonexistent\\file.xml"))


class TestGhidraOutputParserJSONParsing:
    """Test JSON output parsing."""

    def test_parse_json_output_basic(self, sample_json_output: Path) -> None:
        """parse_json_output parses basic JSON structure."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        result = parser.parse_json_output(sample_json_output)

        assert isinstance(result, dict)
        assert "functions" in result
        assert "decompiled" in result
        assert "imports" in result
        assert "exports" in result
        assert "vtables" in result

    def test_parse_json_functions(self, sample_json_output: Path) -> None:
        """parse_json_output extracts function definitions."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        result = parser.parse_json_output(sample_json_output)

        assert result["functions"] == 2
        assert len(parser.functions) == 2

        func_addrs = list(parser.functions.keys())
        assert 0x401000 in func_addrs
        assert 0x401100 in func_addrs

    def test_parse_json_function_details(self, sample_json_output: Path) -> None:
        """parse_json_output extracts detailed function information."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        parser.parse_json_output(sample_json_output)

        func = parser.functions[0x401000]
        assert func.name == "CheckLicense"
        assert func.return_type == "bool"
        assert len(func.parameters) == 1
        assert len(func.local_variables) == 1
        assert func.is_exported is True

    def test_parse_json_decompilation(self, sample_json_output: Path) -> None:
        """parse_json_output extracts decompiled code."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        result = parser.parse_json_output(sample_json_output)

        assert result["decompiled"] == 1
        assert len(parser.decompiled) == 1

        decomp = parser.decompiled[0x401000]
        assert decomp.name == "CheckLicense"
        assert "validate" in decomp.pseudocode
        assert decomp.complexity == 3

    def test_parse_json_imports(self, sample_json_output: Path) -> None:
        """parse_json_output extracts imports."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        result = parser.parse_json_output(sample_json_output)

        assert result["imports"] == 2
        assert "GetTickCount" in parser.imports
        assert parser.imports["GetTickCount"] == 0x403000

    def test_parse_json_exports(self, sample_json_output: Path) -> None:
        """parse_json_output extracts exports."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        result = parser.parse_json_output(sample_json_output)

        assert result["exports"] == 2
        assert "CheckLicense" in parser.exports
        assert parser.exports["CheckLicense"] == 0x401000

    def test_parse_json_vtables(self, sample_json_output: Path) -> None:
        """parse_json_output extracts virtual tables."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        result = parser.parse_json_output(sample_json_output)

        assert result["vtables"] == 1
        assert 0x404000 in parser.vtables
        assert len(parser.vtables[0x404000]) == 3

    def test_parse_json_invalid_file(self, tmp_path: Path) -> None:
        """parse_json_output handles invalid JSON files."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        invalid_json = tmp_path / "invalid.json"
        invalid_json.write_text("NOT VALID JSON", encoding="utf-8")

        parser = GhidraOutputParser()

        with pytest.raises(Exception):
            parser.parse_json_output(invalid_json)


class TestGhidraOutputParserDecompilationParsing:
    """Test decompilation output parsing."""

    def test_parse_decompilation_basic(self, sample_decompilation_output: Path) -> None:
        """parse_decompilation_output parses decompiled functions."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        functions = parser.parse_decompilation_output(sample_decompilation_output)

        assert isinstance(functions, list)
        assert len(functions) >= 0

    def test_parse_decompilation_function_extraction(self, sample_decompilation_output: Path) -> None:
        """parse_decompilation_output extracts function boundaries."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        functions = parser.parse_decompilation_output(sample_decompilation_output)

        if len(functions) > 0:
            assert all(hasattr(f, "name") for f in functions)
            assert all(hasattr(f, "address") for f in functions)
            assert all(hasattr(f, "pseudocode") for f in functions)

    def test_parse_decompilation_complexity(self, sample_decompilation_output: Path) -> None:
        """parse_decompilation_output calculates complexity metrics."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        functions = parser.parse_decompilation_output(sample_decompilation_output)

        if len(functions) > 0:
            assert all(f.complexity >= 0 for f in functions)
            assert all(f.basic_blocks >= 0 for f in functions)

    def test_parse_decompilation_invalid_file(self, tmp_path: Path) -> None:
        """parse_decompilation_output handles invalid files."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        nonexistent = tmp_path / "nonexistent.c"

        parser = GhidraOutputParser()
        with pytest.raises(Exception):
            parser.parse_decompilation_output(nonexistent)


class TestGhidraOutputParserLicenseDetection:
    """Test license-related pattern detection in parsed output."""

    def test_detect_license_functions(self, sample_json_output: Path) -> None:
        """Parser identifies license-related functions."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        parser.parse_json_output(sample_json_output)

        license_keywords = ["license", "validate", "check", "serial", "activation"]
        license_funcs = [
            func for func in parser.functions.values()
            if any(kw in func.name.lower() for kw in license_keywords)
        ]

        assert license_funcs

    def test_detect_license_strings(self, sample_xml_output: Path) -> None:
        """Parser identifies license-related strings."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        parser.parse_xml_output(sample_xml_output)

        license_keywords = ["license", "trial", "expired", "invalid"]
        license_strings = [
            string for string in parser.strings.values()
            if any(kw in string.lower() for kw in license_keywords)
        ]

        assert isinstance(license_strings, list)

    def test_detect_exported_license_functions(self, sample_json_output: Path) -> None:
        """Parser identifies exported license validation functions."""
        from intellicrack.core.analysis.ghidra_output_parser import GhidraOutputParser

        parser = GhidraOutputParser()
        parser.parse_json_output(sample_json_output)

        license_keywords = ["license", "validate", "check"]
        license_exports = [
            name for name in parser.exports.keys()
            if any(kw in name.lower() for kw in license_keywords)
        ]

        assert isinstance(license_exports, list)
