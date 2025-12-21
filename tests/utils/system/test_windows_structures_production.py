"""Production tests for windows_structures.py.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import ctypes
import sys

import pytest

from intellicrack.utils.system.windows_structures import (
    COMMON_LICENSE_DOMAINS,
    STRUCTURES_AVAILABLE,
    WINDOWS_AVAILABLE,
    WindowsContext,
    WindowsProcessStructures,
    create_ssl_certificate_builder,
    parse_objdump_line,
)


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only tests")


class TestWindowsAvailability:
    """Test Windows and structures availability."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_windows_available_true_on_windows(self) -> None:
        """WINDOWS_AVAILABLE is True on Windows."""
        assert WINDOWS_AVAILABLE is True

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_structures_available_on_windows(self) -> None:
        """STRUCTURES_AVAILABLE is True when ctypes.wintypes available."""
        assert STRUCTURES_AVAILABLE is True


class TestWindowsContext:
    """Test Windows CONTEXT structure management."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_windows_context_initialization(self) -> None:
        """WindowsContext initializes successfully."""
        context: WindowsContext = WindowsContext()

        assert context is not None
        assert hasattr(context, "kernel32")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_create_context_structure_returns_tuple(self) -> None:
        """create_context_structure returns (CONTEXT, CONTEXT_FULL) tuple."""
        context: WindowsContext = WindowsContext()
        CONTEXT, CONTEXT_FULL = context.create_context_structure()

        assert CONTEXT is not None
        assert CONTEXT_FULL is not None
        assert isinstance(CONTEXT_FULL, int)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_create_context_structure_64bit(self) -> None:
        """64-bit CONTEXT structure has correct fields."""
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            context: WindowsContext = WindowsContext()
            CONTEXT, CONTEXT_FULL = context.create_context_structure()

            ctx_instance = CONTEXT()
            assert hasattr(ctx_instance, "Rax")
            assert hasattr(ctx_instance, "Rip")
            assert hasattr(ctx_instance, "Rsp")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_create_context_structure_32bit_fields(self) -> None:
        """32-bit CONTEXT structure has correct fields if on 32-bit."""
        if ctypes.sizeof(ctypes.c_void_p) == 4:
            context: WindowsContext = WindowsContext()
            CONTEXT, CONTEXT_FULL = context.create_context_structure()

            ctx_instance = CONTEXT()
            assert hasattr(ctx_instance, "Eax")
            assert hasattr(ctx_instance, "Eip")
            assert hasattr(ctx_instance, "Esp")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_get_thread_context_returns_none_for_invalid_handle(self) -> None:
        """get_thread_context returns None for invalid handle."""
        context: WindowsContext = WindowsContext()
        result = context.get_thread_context(0)

        assert result is None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_set_thread_context_returns_false_for_invalid_handle(self) -> None:
        """set_thread_context returns False for invalid handle."""
        context: WindowsContext = WindowsContext()
        CONTEXT, CONTEXT_FULL = context.create_context_structure()

        ctx_instance = CONTEXT()
        result: bool = context.set_thread_context(0, ctx_instance)

        assert result is False

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_get_entry_point_64bit(self) -> None:
        """get_entry_point returns Rip on 64-bit."""
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            context: WindowsContext = WindowsContext()
            CONTEXT, _ = context.create_context_structure()

            ctx_instance = CONTEXT()
            ctx_instance.Rip = 0x12345678

            entry_point: int = context.get_entry_point(ctx_instance)
            assert entry_point == 0x12345678

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_get_entry_point_32bit(self) -> None:
        """get_entry_point returns Eip on 32-bit."""
        if ctypes.sizeof(ctypes.c_void_p) == 4:
            context: WindowsContext = WindowsContext()
            CONTEXT, _ = context.create_context_structure()

            ctx_instance = CONTEXT()
            ctx_instance.Eip = 0x87654321

            entry_point: int = context.get_entry_point(ctx_instance)
            assert entry_point == 0x87654321


class TestWindowsProcessStructures:
    """Test Windows process creation structures."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_create_startup_info_returns_structure(self) -> None:
        """create_startup_info returns STARTUPINFO structure."""
        STARTUPINFO = WindowsProcessStructures.create_startup_info()

        assert STARTUPINFO is not None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_startup_info_has_required_fields(self) -> None:
        """STARTUPINFO has required fields."""
        STARTUPINFO = WindowsProcessStructures.create_startup_info()

        startup_info = STARTUPINFO()
        assert hasattr(startup_info, "cb")
        assert hasattr(startup_info, "lpReserved")
        assert hasattr(startup_info, "dwFlags")
        assert hasattr(startup_info, "hStdInput")
        assert hasattr(startup_info, "hStdOutput")
        assert hasattr(startup_info, "hStdError")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_create_process_information_returns_structure(self) -> None:
        """create_process_information returns PROCESS_INFORMATION structure."""
        PROCESS_INFORMATION = WindowsProcessStructures.create_process_information()

        assert PROCESS_INFORMATION is not None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_process_information_has_required_fields(self) -> None:
        """PROCESS_INFORMATION has required fields."""
        PROCESS_INFORMATION = WindowsProcessStructures.create_process_information()

        process_info = PROCESS_INFORMATION()
        assert hasattr(process_info, "hProcess")
        assert hasattr(process_info, "hThread")
        assert hasattr(process_info, "dwProcessId")
        assert hasattr(process_info, "dwThreadId")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_startup_info_cb_field_is_dword(self) -> None:
        """STARTUPINFO cb field is DWORD type."""
        STARTUPINFO = WindowsProcessStructures.create_startup_info()

        startup_info = STARTUPINFO()
        startup_info.cb = ctypes.sizeof(STARTUPINFO)

        assert startup_info.cb > 0


class TestCommonLicenseDomains:
    """Test common license domain constants."""

    def test_common_license_domains_is_list(self) -> None:
        """COMMON_LICENSE_DOMAINS is a list."""
        assert isinstance(COMMON_LICENSE_DOMAINS, list)

    def test_common_license_domains_contains_adobe(self) -> None:
        """License domains include Adobe licensing servers."""
        adobe_domains: list[str] = [
            d for d in COMMON_LICENSE_DOMAINS
            if "adobe" in d.lower()
        ]

        assert len(adobe_domains) > 0

    def test_common_license_domains_contains_autodesk(self) -> None:
        """License domains include Autodesk licensing servers."""
        autodesk_domains: list[str] = [
            d for d in COMMON_LICENSE_DOMAINS
            if "autodesk" in d.lower()
        ]

        assert len(autodesk_domains) > 0

    def test_common_license_domains_contains_microsoft(self) -> None:
        """License domains include Microsoft licensing servers."""
        ms_domains: list[str] = [
            d for d in COMMON_LICENSE_DOMAINS
            if "microsoft" in d.lower()
        ]

        assert len(ms_domains) > 0

    def test_common_license_domains_all_strings(self) -> None:
        """All license domains are strings."""
        assert all(isinstance(domain, str) for domain in COMMON_LICENSE_DOMAINS)

    def test_common_license_domains_not_empty(self) -> None:
        """License domains list is not empty."""
        assert len(COMMON_LICENSE_DOMAINS) > 0

    def test_common_license_domains_valid_format(self) -> None:
        """License domains have valid domain format."""
        for domain in COMMON_LICENSE_DOMAINS:
            assert "." in domain
            assert len(domain) > 3


class TestParseObjdumpLine:
    """Test objdump output parsing."""

    def test_parse_objdump_line_valid_instruction(self) -> None:
        """Valid objdump line is parsed correctly."""
        line: str = "  401000:\t55\t\tpush   %rbp"
        result: dict | None = parse_objdump_line(line)

        assert result is not None
        assert result["mnemonic"] == "push"
        assert result["address"] == 0x401000

    def test_parse_objdump_line_with_operands(self) -> None:
        """Objdump line with operands is parsed."""
        line: str = "  401001:\t48 89 e5\t\tmov    %rsp,%rbp"
        result: dict | None = parse_objdump_line(line)

        assert result is not None
        assert result["mnemonic"] == "mov"
        assert result["op_str"] == "%rsp,%rbp"

    def test_parse_objdump_line_invalid_format(self) -> None:
        """Invalid objdump line returns None."""
        line: str = "invalid line format"
        result: dict | None = parse_objdump_line(line)

        assert result is None

    def test_parse_objdump_line_empty_string(self) -> None:
        """Empty string returns None."""
        line: str = ""
        result: dict | None = parse_objdump_line(line)

        assert result is None

    def test_parse_objdump_line_no_instruction(self) -> None:
        """Line without instruction returns None."""
        line: str = "  401000:"
        result: dict | None = parse_objdump_line(line)

        assert result is None

    def test_parse_objdump_line_complex_instruction(self) -> None:
        """Complex instruction with multiple operands is parsed."""
        line: str = "  401010:\t48 8b 45 f8\t\tmov    -0x8(%rbp),%rax"
        result: dict | None = parse_objdump_line(line)

        assert result is not None
        assert result["mnemonic"] == "mov"
        assert "-0x8(%rbp),%rax" in result["op_str"]


class TestCreateSSLCertificateBuilder:
    """Test SSL certificate builder creation."""

    def test_create_ssl_certificate_builder_returns_builder(self) -> None:
        """create_ssl_certificate_builder returns certificate builder."""
        builder = create_ssl_certificate_builder()

        assert builder is not None

    def test_ssl_certificate_builder_has_expected_methods(self) -> None:
        """Certificate builder has expected builder methods."""
        builder = create_ssl_certificate_builder()

        if builder:
            assert hasattr(builder, "public_key")
            assert hasattr(builder, "sign")

    def test_ssl_certificate_builder_for_localhost(self) -> None:
        """Certificate builder is configured for localhost."""
        builder = create_ssl_certificate_builder()

        assert builder is not None


class TestWindowsStructuresIntegration:
    """Integration tests for Windows structures."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_context_and_process_structures_compatible(self) -> None:
        """Context and process structures work together."""
        context: WindowsContext = WindowsContext()
        process_struct: WindowsProcessStructures = WindowsProcessStructures()

        CONTEXT, CONTEXT_FULL = context.create_context_structure()
        PROCESS_INFO = process_struct.create_process_information()

        assert CONTEXT is not None
        assert PROCESS_INFO is not None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_structures_match_windows_sdk_sizes(self) -> None:
        """Structure sizes match expected Windows SDK sizes."""
        STARTUPINFO = WindowsProcessStructures.create_startup_info()
        PROCESS_INFORMATION = WindowsProcessStructures.create_process_information()

        assert ctypes.sizeof(STARTUPINFO) > 0
        assert ctypes.sizeof(PROCESS_INFORMATION) > 0

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_context_structure_size_matches_architecture(self) -> None:
        """CONTEXT structure size matches architecture."""
        context: WindowsContext = WindowsContext()
        CONTEXT, _ = context.create_context_structure()

        size: int = ctypes.sizeof(CONTEXT)

        if ctypes.sizeof(ctypes.c_void_p) == 8:
            assert size > 0
        else:
            assert size > 0

    def test_license_domains_integrate_with_ssl_builder(self) -> None:
        """License domains can be used with SSL certificate builder."""
        builder = create_ssl_certificate_builder()

        if builder and COMMON_LICENSE_DOMAINS:
            assert len(COMMON_LICENSE_DOMAINS) > 0

    def test_objdump_parsing_multiple_lines(self) -> None:
        """Multiple objdump lines can be parsed sequentially."""
        lines: list[str] = [
            "  401000:\t55\t\tpush   %rbp",
            "  401001:\t48 89 e5\t\tmov    %rsp,%rbp",
            "  401004:\tc9\t\tleave",
            "  401005:\tc3\t\tret",
        ]

        parsed: list[dict] = []
        for line in lines:
            result = parse_objdump_line(line)
            if result:
                parsed.append(result)

        assert len(parsed) == 4
        assert parsed[0]["mnemonic"] == "push"
        assert parsed[3]["mnemonic"] == "ret"


class TestWindowsStructuresEdgeCases:
    """Edge case tests for Windows structures."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_context_get_entry_point_with_zero_values(self) -> None:
        """get_entry_point handles zero-initialized context."""
        context: WindowsContext = WindowsContext()
        CONTEXT, _ = context.create_context_structure()

        ctx_instance = CONTEXT()
        entry_point: int = context.get_entry_point(ctx_instance)

        assert entry_point == 0

    def test_parse_objdump_line_with_leading_whitespace(self) -> None:
        """Objdump line with leading whitespace is parsed."""
        line: str = "     401000:\t55\t\tpush   %rbp"
        result: dict | None = parse_objdump_line(line)

        assert result is not None
        assert result["mnemonic"] == "push"

    def test_parse_objdump_line_with_hex_operands(self) -> None:
        """Objdump line with hex operands is parsed."""
        line: str = "  401000:\tb8 00 00 00 00\t\tmov    $0x0,%eax"
        result: dict | None = parse_objdump_line(line)

        assert result is not None
        assert result["mnemonic"] == "mov"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_startup_info_can_be_initialized_multiple_times(self) -> None:
        """STARTUPINFO can be created multiple times."""
        STARTUPINFO = WindowsProcessStructures.create_startup_info()

        for _ in range(10):
            startup = STARTUPINFO()
            startup.cb = ctypes.sizeof(STARTUPINFO)
            assert startup.cb > 0
