"""Production tests for Ghidra results compatibility module.

This module tests the ghidra_results.py compatibility layer that re-exports
GhidraAnalysisResult from ghidra_analyzer for backward compatibility.

Copyright (C) 2025 Zachary Flint
"""

import sys
from pathlib import Path
from typing import Any

import pytest


def create_test_ghidra_function(
    name: str = "TestFunction",
    address: int = 0x401000,
    size: int = 128,
    signature: str = "void TestFunction(void)",
    return_type: str = "void",
    parameters: list[tuple[str, str]] | None = None,
    local_variables: list[tuple[str, str, int]] | None = None,
) -> Any:
    """Create a test GhidraFunction with all required fields."""
    from intellicrack.core.analysis.ghidra_analyzer import GhidraFunction

    return GhidraFunction(
        name=name,
        address=address,
        size=size,
        signature=signature,
        return_type=return_type,
        parameters=parameters or [],
        local_variables=local_variables or [],
        decompiled_code=f"{signature} {{ return; }}",
        assembly_code="push rbp\nmov rbp, rsp\npop rbp\nret",
        xrefs_to=[],
        xrefs_from=[],
        comments={},
    )


def create_test_analysis_result(**kwargs: Any) -> Any:
    """Create a test GhidraAnalysisResult with default values."""
    from intellicrack.core.analysis.ghidra_results import GhidraAnalysisResult

    defaults = {
        "binary_path": "C:\\test\\sample.exe",
        "architecture": "x86:LE:64:default",
        "compiler": "Visual Studio",
        "functions": {},
        "data_types": {},
        "strings": [],
        "imports": [],
        "exports": [],
        "sections": [{"name": ".text", "address": 0x401000, "size": 0x1000}],
        "entry_point": 0x401000,
        "image_base": 0x400000,
        "vtables": {},
        "exception_handlers": [],
    }
    defaults.update(kwargs)
    return GhidraAnalysisResult(**defaults)


@pytest.fixture
def mock_ghidra_result() -> dict[str, Any]:
    """Create mock Ghidra analysis result data."""
    return {
        "binary_path": "C:\\test\\sample.exe",
        "architecture": "x86:LE:64:default",
        "compiler": "Visual Studio",
        "functions": {
            0x401000: {
                "name": "main",
                "address": 0x401000,
                "size": 256,
                "signature": "int main(int argc, char** argv)",
                "return_type": "int",
                "parameters": [("int", "argc"), ("char**", "argv")],
                "local_variables": [("int", "result", -4), ("char*", "buffer", -32)],
            },
        },
        "data_types": {
            "LICENSE_INFO": {
                "name": "LICENSE_INFO",
                "size": 64,
                "category": "struct",
                "members": [
                    {"name": "serial", "type": "char[32]", "offset": 0},
                    {"name": "expiry", "type": "time_t", "offset": 32},
                    {"name": "valid", "type": "bool", "offset": 40},
                ],
                "alignment": 8,
            },
        },
        "strings": [
            (0x402000, "License key validation failed"),
            (0x402030, "Trial period expired"),
        ],
        "imports": [
            ("kernel32.dll", "GetTickCount", 0x403000),
            ("user32.dll", "MessageBoxA", 0x403004),
        ],
        "exports": [
            ("CheckLicense", 0x401500),
            ("ValidateKey", 0x401600),
        ],
    }


class TestGhidraResultsCompatibility:
    """Test ghidra_results.py compatibility module."""

    def test_ghidra_analysis_result_import(self) -> None:
        """GhidraAnalysisResult can be imported from ghidra_results."""
        from intellicrack.core.analysis.ghidra_results import GhidraAnalysisResult

        assert GhidraAnalysisResult is not None
        assert hasattr(GhidraAnalysisResult, "__dataclass_fields__")

    def test_ghidra_analysis_result_fields(self) -> None:
        """GhidraAnalysisResult has all required fields."""
        from intellicrack.core.analysis.ghidra_results import GhidraAnalysisResult

        required_fields = [
            "binary_path",
            "architecture",
            "compiler",
            "functions",
            "data_types",
            "strings",
            "imports",
            "exports",
            "sections",
            "entry_point",
            "image_base",
            "vtables",
            "exception_handlers",
        ]

        dataclass_fields = GhidraAnalysisResult.__dataclass_fields__
        for field in required_fields:
            assert field in dataclass_fields, f"Missing required field: {field}"

    def test_ghidra_analysis_result_instantiation(self, mock_ghidra_result: dict[str, Any]) -> None:
        """GhidraAnalysisResult can be instantiated with valid data."""
        from intellicrack.core.analysis.ghidra_analyzer import GhidraFunction, GhidraDataType
        from intellicrack.core.analysis.ghidra_results import GhidraAnalysisResult

        functions_dict = {}
        for addr, func_data in mock_ghidra_result["functions"].items():
            functions_dict[addr] = GhidraFunction(
                name=func_data["name"],
                address=func_data["address"],
                size=func_data["size"],
                signature=func_data["signature"],
                return_type=func_data["return_type"],
                parameters=func_data["parameters"],
                local_variables=func_data["local_variables"],
                decompiled_code="int main(int argc, char** argv) { return 0; }",
                assembly_code="push rbp\nmov rbp, rsp\nxor eax, eax\npop rbp\nret",
                xrefs_to=[0x400500, 0x400600],
                xrefs_from=[0x401100, 0x401200],
                comments={0: "Entry point", 10: "Return"},
            )

        data_types_dict = {}
        for name, dt_data in mock_ghidra_result["data_types"].items():
            data_types_dict[name] = GhidraDataType(
                name=dt_data["name"],
                size=dt_data["size"],
                category=dt_data["category"],
                members=dt_data["members"],
                alignment=dt_data["alignment"],
            )

        result = GhidraAnalysisResult(
            binary_path=mock_ghidra_result["binary_path"],
            architecture=mock_ghidra_result["architecture"],
            compiler=mock_ghidra_result["compiler"],
            functions=functions_dict,
            data_types=data_types_dict,
            strings=mock_ghidra_result["strings"],
            imports=mock_ghidra_result["imports"],
            exports=mock_ghidra_result["exports"],
            sections=[{"name": ".text", "address": 0x401000, "size": 0x1000}],
            entry_point=0x401000,
            image_base=0x400000,
            vtables={},
            exception_handlers=[],
        )

        assert result.binary_path == mock_ghidra_result["binary_path"]
        assert result.architecture == mock_ghidra_result["architecture"]
        assert result.compiler == mock_ghidra_result["compiler"]
        assert len(result.functions) == 1
        assert len(result.data_types) == 1
        assert len(result.strings) == 2
        assert len(result.imports) == 2
        assert len(result.exports) == 2
        assert result.entry_point == 0x401000
        assert result.image_base == 0x400000

    def test_backward_compatibility_import(self) -> None:
        """ghidra_results exports same class as ghidra_analyzer."""
        from intellicrack.core.analysis.ghidra_analyzer import GhidraAnalysisResult as OriginalClass
        from intellicrack.core.analysis.ghidra_results import GhidraAnalysisResult as CompatClass

        assert CompatClass is OriginalClass

    def test_all_exports(self) -> None:
        """Module exports only GhidraAnalysisResult."""
        from intellicrack.core.analysis import ghidra_results

        assert hasattr(ghidra_results, "__all__")
        assert ghidra_results.__all__ == ["GhidraAnalysisResult"]

    def test_ghidra_function_dataclass(self) -> None:
        """GhidraFunction dataclass is properly structured."""
        from intellicrack.core.analysis.ghidra_analyzer import GhidraFunction

        func = GhidraFunction(
            name="CheckLicense",
            address=0x401000,
            size=128,
            signature="bool CheckLicense(const char* key)",
            return_type="bool",
            parameters=[("const char*", "key")],
            local_variables=[("char", "buffer", -64), ("int", "result", -4)],
            decompiled_code="bool CheckLicense(const char* key) { return validate(key); }",
            assembly_code="push rbp\nmov rbp, rsp\ncall validate\npop rbp\nret",
            xrefs_to=[0x400900],
            xrefs_from=[0x401500],
            comments={0: "License validation function"},
        )

        assert func.name == "CheckLicense"
        assert func.address == 0x401000
        assert func.size == 128
        assert len(func.parameters) == 1
        assert len(func.local_variables) == 2

    def test_ghidra_datatype_dataclass(self) -> None:
        """GhidraDataType dataclass is properly structured."""
        from intellicrack.core.analysis.ghidra_analyzer import GhidraDataType

        dt = GhidraDataType(
            name="LICENSE_KEY",
            size=32,
            category="struct",
            members=[
                {"name": "data", "type": "char[32]", "offset": 0},
            ],
            alignment=4,
        )

        assert dt.name == "LICENSE_KEY"
        assert dt.size == 32
        assert dt.category == "struct"
        assert len(dt.members) == 1
        assert dt.alignment == 4


class TestGhidraResultsDataIntegrity:
    """Test data integrity of Ghidra results structures."""

    def test_function_with_no_parameters(self) -> None:
        """GhidraFunction handles functions with no parameters."""
        func = create_test_ghidra_function(
            name="GetLicenseStatus",
            address=0x401000,
            size=64,
            signature="int GetLicenseStatus(void)",
            return_type="int",
            parameters=[],
            local_variables=[],
        )

        assert len(func.parameters) == 0
        assert len(func.local_variables) == 0

    def test_function_with_complex_signature(self) -> None:
        """GhidraFunction handles complex function signatures."""
        func = create_test_ghidra_function(
            name="ValidateLicenseEx",
            address=0x401200,
            size=512,
            signature="HRESULT ValidateLicenseEx(HWND hwnd, LPCTSTR key, DWORD flags, LPVOID* result)",
            return_type="HRESULT",
            parameters=[
                ("HWND", "hwnd"),
                ("LPCTSTR", "key"),
                ("DWORD", "flags"),
                ("LPVOID*", "result"),
            ],
            local_variables=[
                ("HRESULT", "hr", -4),
                ("BYTE", "buffer", -256),
                ("DWORD", "checksum", -260),
            ],
        )

        assert len(func.parameters) == 4
        assert len(func.local_variables) == 3
        assert func.return_type == "HRESULT"

    def test_datatype_with_nested_structures(self) -> None:
        """GhidraDataType handles nested structure definitions."""
        from intellicrack.core.analysis.ghidra_analyzer import GhidraDataType

        dt = GhidraDataType(
            name="LICENSE_CONTEXT",
            size=128,
            category="struct",
            members=[
                {"name": "header", "type": "LICENSE_HEADER", "offset": 0},
                {"name": "key_data", "type": "KEY_DATA", "offset": 32},
                {"name": "validation", "type": "VALIDATION_INFO", "offset": 64},
                {"name": "flags", "type": "DWORD", "offset": 96},
            ],
            alignment=8,
        )

        assert len(dt.members) == 4
        assert dt.members[0]["type"] == "LICENSE_HEADER"
        assert dt.members[3]["offset"] == 96

    def test_analysis_result_with_no_exports(self, mock_ghidra_result: dict[str, Any]) -> None:
        """GhidraAnalysisResult handles binaries with no exports."""
        result = create_test_analysis_result(
            binary_path=mock_ghidra_result["binary_path"],
            architecture=mock_ghidra_result["architecture"],
            compiler=mock_ghidra_result["compiler"],
            imports=mock_ghidra_result["imports"],
            exports=[],
        )

        assert len(result.exports) == 0
        assert len(result.imports) == 2

    def test_analysis_result_with_large_string_table(self, mock_ghidra_result: dict[str, Any]) -> None:
        """GhidraAnalysisResult handles large string tables."""
        large_strings = [
            (0x400000 + i * 0x100, f"License string {i}")
            for i in range(1000)
        ]

        result = create_test_analysis_result(
            binary_path=mock_ghidra_result["binary_path"],
            strings=large_strings,
        )

        assert len(result.strings) == 1000
        assert result.strings[0][1] == "License string 0"
        assert result.strings[999][1] == "License string 999"


class TestGhidraResultsLicenseDetection:
    """Test Ghidra results for license-related pattern detection."""

    def test_detect_license_validation_functions(self, mock_ghidra_result: dict[str, Any]) -> None:
        """Identify license validation functions from results."""
        license_funcs = {
            0x401000: create_test_ghidra_function(
                name="CheckLicense",
                address=0x401000,
                size=256,
                signature="bool CheckLicense(const char*)",
                return_type="bool",
                parameters=[("const char*", "key")],
                local_variables=[],
            ),
            0x401100: create_test_ghidra_function(
                name="ValidateSerial",
                address=0x401100,
                size=128,
                signature="int ValidateSerial(const char*)",
                return_type="int",
                parameters=[("const char*", "serial")],
                local_variables=[],
            ),
        }

        result = create_test_analysis_result(
            binary_path=mock_ghidra_result["binary_path"],
            functions=license_funcs,
        )

        license_keywords = ["license", "validate", "check", "serial", "activation"]
        license_related = [
            func for func in result.functions.values()
            if any(kw in func.name.lower() for kw in license_keywords)
        ]

        assert len(license_related) == 2
        assert license_related[0].name == "CheckLicense"
        assert license_related[1].name == "ValidateSerial"

    def test_detect_license_strings(self, mock_ghidra_result: dict[str, Any]) -> None:
        """Identify license-related strings from results."""
        license_strings = [
            (0x402000, "Invalid license key"),
            (0x402020, "Trial period expired"),
            (0x402040, "Please activate your copy"),
            (0x402060, "Registration successful"),
            (0x402080, "Product key:"),
        ]

        result = create_test_analysis_result(
            binary_path=mock_ghidra_result["binary_path"],
            strings=license_strings,
        )

        license_keywords = ["license", "trial", "activate", "registration", "product key"]
        license_related = [
            s for s in result.strings
            if any(kw in s[1].lower() for kw in license_keywords)
        ]

        assert len(license_related) == 5
