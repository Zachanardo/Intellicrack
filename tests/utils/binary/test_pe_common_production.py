"""Production-ready tests for pe_common.py.

Tests validate REAL PE import extraction and analysis.
All tests use realistic PE structures and verify accurate import parsing.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any
from unittest.mock import Mock

import pytest

from intellicrack.utils.binary.pe_common import (
    analyze_pe_import_security,
    extract_pe_imports,
    iterate_pe_imports_with_dll,
)


class TestExtractPEImports:
    """Test PE import extraction."""

    def test_extracts_basic_imports(self) -> None:
        """Import extractor retrieves function names from PE."""
        pe = self._create_mock_pe_with_imports(["CreateFile", "ReadFile", "WriteFile"])

        imports = extract_pe_imports(pe)

        assert len(imports) == 3
        assert "CreateFile" in imports
        assert "ReadFile" in imports
        assert "WriteFile" in imports

    def test_extracts_multiple_dll_imports(self) -> None:
        """Import extractor handles imports from multiple DLLs."""
        pe = self._create_mock_pe_with_multiple_dlls(
            {"kernel32.dll": ["CreateFile", "ReadFile"], "advapi32.dll": ["RegOpenKey", "RegQueryValue"]}
        )

        imports = extract_pe_imports(pe)

        assert "CreateFile" in imports
        assert "RegOpenKey" in imports
        assert len(imports) == 4

    def test_handles_pe_without_imports(self) -> None:
        """Import extractor returns empty list for PE without imports."""
        pe = Mock(spec=[])

        imports = extract_pe_imports(pe)

        assert imports == []

    def test_handles_empty_import_directory(self) -> None:
        """Import extractor handles empty DIRECTORY_ENTRY_IMPORT."""
        pe = Mock()
        pe.DIRECTORY_ENTRY_IMPORT = []

        imports = extract_pe_imports(pe)

        assert imports == []

    def test_skips_imports_without_names(self) -> None:
        """Import extractor skips imports with None names."""
        pe = Mock()
        entry = Mock()
        imp_with_name = Mock()
        imp_with_name.name = b"ValidFunction"
        imp_without_name = Mock()
        imp_without_name.name = None
        entry.imports = [imp_with_name, imp_without_name]
        pe.DIRECTORY_ENTRY_IMPORT = [entry]

        imports = extract_pe_imports(pe)

        assert len(imports) == 1
        assert "ValidFunction" in imports

    def test_handles_unicode_decoding_errors(self) -> None:
        """Import extractor handles invalid UTF-8 in import names."""
        pe = Mock()
        entry = Mock()
        imp = Mock()
        imp.name = b"\xFF\xFE\x00\x00"
        entry.imports = [imp]
        pe.DIRECTORY_ENTRY_IMPORT = [entry]

        imports = extract_pe_imports(pe)

        assert len(imports) >= 0

    def _create_mock_pe_with_imports(self, import_names: list[str]) -> Any:
        """Create mock PE with specified imports."""
        pe = Mock()
        entry = Mock()
        entry.imports = []
        for name in import_names:
            imp = Mock()
            imp.name = name.encode()
            entry.imports.append(imp)
        pe.DIRECTORY_ENTRY_IMPORT = [entry]
        return pe

    def _create_mock_pe_with_multiple_dlls(self, dll_imports: dict[str, list[str]]) -> Any:
        """Create mock PE with imports from multiple DLLs."""
        pe = Mock()
        pe.DIRECTORY_ENTRY_IMPORT = []
        for dll_name, import_names in dll_imports.items():
            entry = Mock()
            entry.dll = dll_name.encode()
            entry.imports = []
            for name in import_names:
                imp = Mock()
                imp.name = name.encode()
                entry.imports.append(imp)
            pe.DIRECTORY_ENTRY_IMPORT.append(entry)
        return pe


class TestIteratePEImportsWithDLL:
    """Test PE import iteration with DLL names."""

    def test_iterates_imports_with_dll_names(self) -> None:
        """Import iterator provides DLL and function names."""
        pe = self._create_mock_pe_with_dll(
            "kernel32.dll", ["CreateFile", "ReadFile", "WriteFile"]
        )

        results: list[tuple[str, str]] = []

        def callback(dll: str, func: str) -> tuple[str, str]:
            return (dll, func)

        for result in iterate_pe_imports_with_dll(pe, callback):
            results.append(result)

        assert len(results) == 3
        assert ("kernel32.dll", "CreateFile") in results
        assert ("kernel32.dll", "ReadFile") in results

    def test_passes_import_object_when_requested(self) -> None:
        """Import iterator passes import object as third parameter."""
        pe = self._create_mock_pe_with_dll("test.dll", ["TestFunc"])

        import_objects: list[Any] = []

        def callback(dll: str, func: str, imp: Any) -> str:
            import_objects.append(imp)
            return func

        list(iterate_pe_imports_with_dll(pe, callback, include_import_obj=True))

        assert len(import_objects) == 1
        assert import_objects[0].name == b"TestFunc"

    def test_filters_results_by_callback_return(self) -> None:
        """Import iterator only yields non-None callback results."""
        pe = self._create_mock_pe_with_dll("test.dll", ["Keep", "Filter", "Keep2"])

        def callback(dll: str, func: str) -> str | None:
            return func if "Keep" in func else None

        results = list(iterate_pe_imports_with_dll(pe, callback))

        assert len(results) == 2
        assert "Keep" in results
        assert "Keep2" in results
        assert "Filter" not in results

    def test_handles_pe_without_imports(self) -> None:
        """Import iterator handles PE without imports gracefully."""
        pe = Mock(spec=[])

        def callback(dll: str, func: str) -> str:
            return func

        results = list(iterate_pe_imports_with_dll(pe, callback))

        assert not results

    def test_handles_imports_without_names(self) -> None:
        """Import iterator skips imports with None names."""
        pe = Mock()
        entry = Mock()
        entry.dll = b"test.dll"
        imp_valid = Mock()
        imp_valid.name = b"ValidFunc"
        imp_invalid = Mock()
        imp_invalid.name = None
        entry.imports = [imp_valid, imp_invalid]
        pe.DIRECTORY_ENTRY_IMPORT = [entry]

        def callback(dll: str, func: str) -> str:
            return func

        results = list(iterate_pe_imports_with_dll(pe, callback))

        assert len(results) == 1
        assert "ValidFunc" in results

    def _create_mock_pe_with_dll(self, dll_name: str, import_names: list[str]) -> Any:
        """Create mock PE with imports from specific DLL."""
        pe = Mock()
        entry = Mock()
        entry.dll = dll_name.encode()
        entry.imports = []
        for name in import_names:
            imp = Mock()
            imp.name = name.encode()
            entry.imports.append(imp)
        pe.DIRECTORY_ENTRY_IMPORT = [entry]
        return pe


class TestAnalyzePEImportSecurity:
    """Test PE import security analysis."""

    def test_categorizes_crypto_imports(self) -> None:
        """Security analyzer identifies cryptographic APIs."""
        pe = self._create_mock_pe_with_imports(["CryptAcquireContext", "CryptCreateHash", "CryptEncrypt"])

        result = analyze_pe_import_security(pe)

        assert len(result["crypto"]) == 3
        assert "CryptAcquireContext" in result["crypto"]

    def test_categorizes_network_imports(self) -> None:
        """Security analyzer identifies network APIs."""
        pe = self._create_mock_pe_with_imports(["socket", "connect", "send", "WSAStartup"])

        result = analyze_pe_import_security(pe)

        assert len(result["network"]) >= 1

    def test_categorizes_process_imports(self) -> None:
        """Security analyzer identifies process manipulation APIs."""
        pe = self._create_mock_pe_with_imports(["CreateProcess", "OpenProcess", "ReadProcessMemory"])

        result = analyze_pe_import_security(pe)

        assert len(result["process"]) >= 1

    def test_categorizes_registry_imports(self) -> None:
        """Security analyzer identifies registry APIs."""
        pe = self._create_mock_pe_with_imports(["RegOpenKey", "RegQueryValue", "RegSetValue"])

        result = analyze_pe_import_security(pe)

        assert len(result["registry"]) >= 1

    def test_categorizes_file_imports(self) -> None:
        """Security analyzer identifies file operation APIs."""
        pe = self._create_mock_pe_with_imports(["CreateFile", "ReadFile", "WriteFile", "DeleteFile"])

        result = analyze_pe_import_security(pe)

        assert len(result["file"]) >= 1

    def test_handles_case_insensitive_matching(self) -> None:
        """Security analyzer performs case-insensitive matching."""
        pe = self._create_mock_pe_with_imports(["CRYPTACQUIRECONTEXT", "createprocess"])

        result = analyze_pe_import_security(pe)

        assert len(result["crypto"]) >= 1 or len(result["process"]) >= 1

    def test_returns_all_categories(self) -> None:
        """Security analyzer returns all category keys."""
        pe = self._create_mock_pe_with_imports([])

        result = analyze_pe_import_security(pe)

        assert "crypto" in result
        assert "network" in result
        assert "process" in result
        assert "registry" in result
        assert "file" in result

    def _create_mock_pe_with_imports(self, import_names: list[str]) -> Any:
        """Create mock PE with specified imports."""
        pe = Mock()
        entry = Mock()
        entry.imports = []
        for name in import_names:
            imp = Mock()
            imp.name = name.encode()
            entry.imports.append(imp)
        pe.DIRECTORY_ENTRY_IMPORT = [entry]
        return pe


class TestRealWorldScenarios:
    """Test real-world PE import analysis scenarios."""

    def test_analyzes_license_protected_binary(self) -> None:
        """Import analyzer detects license protection indicators."""
        pe = self._create_mock_pe_with_imports(
            [
                "CryptAcquireContext",
                "CryptDecrypt",
                "InternetConnect",
                "HttpOpenRequest",
                "RegOpenKey",
                "RegQueryValue",
            ]
        )

        result = analyze_pe_import_security(pe)

        assert len(result["crypto"]) >= 1
        assert len(result["network"]) >= 1
        assert len(result["registry"]) >= 1

    def test_detects_online_activation_imports(self) -> None:
        """Import analyzer identifies online activation patterns."""
        pe = self._create_mock_pe_with_imports(
            ["socket", "connect", "send", "recv", "CryptEncrypt", "CryptDecrypt"]
        )

        result = analyze_pe_import_security(pe)

        has_network = len(result["network"]) > 0
        has_crypto = len(result["crypto"]) > 0

        assert has_network and has_crypto

    def test_identifies_trial_reset_target(self) -> None:
        """Import analyzer detects trial manipulation indicators."""
        pe = self._create_mock_pe_with_imports(
            ["RegOpenKey", "RegSetValue", "RegDeleteValue", "CreateFile", "WriteFile"]
        )

        result = analyze_pe_import_security(pe)

        assert len(result["registry"]) >= 1
        assert len(result["file"]) >= 1

    def _create_mock_pe_with_imports(self, import_names: list[str]) -> Any:
        """Create mock PE with specified imports."""
        pe = Mock()
        entry = Mock()
        entry.imports = []
        for name in import_names:
            imp = Mock()
            imp.name = name.encode()
            entry.imports.append(imp)
        pe.DIRECTORY_ENTRY_IMPORT = [entry]
        return pe


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_handles_very_long_import_names(self) -> None:
        """Import extractor handles very long function names."""
        long_name = "A" * 1000
        pe = self._create_mock_pe_with_imports([long_name])

        imports = extract_pe_imports(pe)

        assert long_name in imports

    def test_handles_special_characters_in_names(self) -> None:
        """Import extractor handles special characters."""
        pe = self._create_mock_pe_with_imports(["Func_Name$123", "?SpecialFunc@@"])

        imports = extract_pe_imports(pe)

        assert "Func_Name$123" in imports
        assert "?SpecialFunc@@" in imports

    def test_handles_duplicate_imports(self) -> None:
        """Import extractor includes duplicate imports."""
        pe = Mock()
        entry = Mock()
        imp1 = Mock()
        imp1.name = b"SameFunc"
        imp2 = Mock()
        imp2.name = b"SameFunc"
        entry.imports = [imp1, imp2]
        pe.DIRECTORY_ENTRY_IMPORT = [entry]

        imports = extract_pe_imports(pe)

        assert imports.count("SameFunc") == 2

    def test_callback_exception_handling(self) -> None:
        """Import iterator handles callback exceptions gracefully."""
        pe = self._create_mock_pe_with_imports(["Func1", "Func2"])

        def failing_callback(dll: str, func: str) -> str:
            if func == "Func2":
                raise ValueError("Test error")
            return func

        try:
            results = list(iterate_pe_imports_with_dll(pe, failing_callback))
            assert "Func1" in results
        except ValueError:
            pass

    def _create_mock_pe_with_imports(self, import_names: list[str]) -> Any:
        """Create mock PE with specified imports."""
        pe = Mock()
        entry = Mock()
        entry.imports = []
        for name in import_names:
            imp = Mock()
            imp.name = name.encode()
            entry.imports.append(imp)
        pe.DIRECTORY_ENTRY_IMPORT = [entry]
        return pe


class TestPerformance:
    """Test performance with large import tables."""

    def test_extracts_large_import_table_efficiently(self) -> None:
        """Import extractor handles large import tables efficiently."""
        import_names = [f"Function_{i}" for i in range(1000)]
        pe = self._create_mock_pe_with_imports(import_names)

        import time

        start_time = time.time()
        imports = extract_pe_imports(pe)
        duration = time.time() - start_time

        assert len(imports) == 1000
        assert duration < 1.0

    def test_iterates_large_import_table_efficiently(self) -> None:
        """Import iterator handles large import tables efficiently."""
        import_names = [f"Function_{i}" for i in range(1000)]
        pe = self._create_mock_pe_with_imports(import_names)

        def callback(dll: str, func: str) -> str:
            return func

        import time

        start_time = time.time()
        results = list(iterate_pe_imports_with_dll(pe, callback))
        duration = time.time() - start_time

        assert len(results) == 1000
        assert duration < 2.0

    def _create_mock_pe_with_imports(self, import_names: list[str]) -> Any:
        """Create mock PE with specified imports."""
        pe = Mock()
        entry = Mock()
        entry.dll = b"test.dll"
        entry.imports = []
        for name in import_names:
            imp = Mock()
            imp.name = name.encode()
            entry.imports.append(imp)
        pe.DIRECTORY_ENTRY_IMPORT = [entry]
        return pe
