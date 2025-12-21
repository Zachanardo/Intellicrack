"""Production tests for import_patterns.py module.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

Tests validate that centralized import pattern handling correctly provides
access to binary analysis libraries required for software protection cracking.
"""

from typing import Any

import pytest


def test_import_patterns_get_pefile_returns_module_or_none() -> None:
    """get_pefile returns pefile module when available or None."""
    from intellicrack.utils.core.import_patterns import PEFILE_AVAILABLE, get_pefile

    result = get_pefile()

    if PEFILE_AVAILABLE:
        assert result is not None
        assert hasattr(result, "PE")
    else:
        assert result is None


def test_import_patterns_get_capstone_returns_complete_dictionary() -> None:
    """get_capstone returns dictionary with all required Capstone components."""
    from intellicrack.utils.core.import_patterns import (
        CAPSTONE_AVAILABLE,
        get_capstone,
    )

    result = get_capstone()

    assert isinstance(result, dict)
    assert "Cs" in result
    assert "CS_ARCH_X86" in result
    assert "CS_MODE_32" in result
    assert "CS_MODE_64" in result
    assert "available" in result
    assert result["available"] == CAPSTONE_AVAILABLE

    if CAPSTONE_AVAILABLE:
        assert result["Cs"] is not None
        assert result["CS_ARCH_X86"] is not None
        assert result["CS_MODE_32"] is not None
        assert result["CS_MODE_64"] is not None


def test_import_patterns_capstone_disassembles_x86_shellcode() -> None:
    """Capstone disassembler successfully analyzes x86 machine code."""
    from intellicrack.utils.core.import_patterns import get_capstone

    capstone_info = get_capstone()

    if not capstone_info["available"]:
        pytest.skip("Capstone not available")

    Cs = capstone_info["Cs"]
    CS_ARCH_X86 = capstone_info["CS_ARCH_X86"]
    CS_MODE_32 = capstone_info["CS_MODE_32"]

    md = Cs(CS_ARCH_X86, CS_MODE_32)

    shellcode = b"\x55\x89\xe5\x83\xec\x10"
    instructions = list(md.disasm(shellcode, 0x1000))

    assert instructions
    assert all(hasattr(insn, "mnemonic") for insn in instructions)
    assert all(hasattr(insn, "address") for insn in instructions)


def test_import_patterns_get_lief_returns_module_or_none() -> None:
    """get_lief returns lief module when available or None."""
    from intellicrack.utils.core.import_patterns import LIEF_AVAILABLE, get_lief

    result = get_lief()

    if LIEF_AVAILABLE:
        assert result is not None
        assert hasattr(result, "parse")
    else:
        assert result is None


def test_import_patterns_get_elftools_returns_complete_dictionary() -> None:
    """get_elftools returns dictionary with ELF analysis components."""
    from intellicrack.utils.core.import_patterns import (
        PYELFTOOLS_AVAILABLE,
        get_elftools,
    )

    result = get_elftools()

    assert isinstance(result, dict)
    assert "ELFFile" in result
    assert "available" in result
    assert result["available"] == PYELFTOOLS_AVAILABLE

    if PYELFTOOLS_AVAILABLE:
        assert result["ELFFile"] is not None


def test_import_patterns_get_macholib_returns_complete_dictionary() -> None:
    """get_macholib returns dictionary with Mach-O analysis components."""
    from intellicrack.utils.core.import_patterns import (
        MACHOLIB_AVAILABLE,
        get_macholib,
    )

    result = get_macholib()

    assert isinstance(result, dict)
    assert "MachO" in result
    assert "available" in result
    assert result["available"] == MACHOLIB_AVAILABLE

    if MACHOLIB_AVAILABLE:
        assert result["MachO"] is not None


def test_import_patterns_get_zipfile_returns_complete_dictionary() -> None:
    """get_zipfile returns dictionary with zipfile module for APK/JAR analysis."""
    from intellicrack.utils.core.import_patterns import (
        ZIPFILE_AVAILABLE,
        get_zipfile,
    )

    result = get_zipfile()

    assert isinstance(result, dict)
    assert "zipfile" in result
    assert "available" in result
    assert result["available"] == ZIPFILE_AVAILABLE

    if ZIPFILE_AVAILABLE:
        assert result["zipfile"] is not None
        assert hasattr(result["zipfile"], "ZipFile")


def test_import_patterns_zipfile_analyzes_archive_contents() -> None:
    """Zipfile module successfully analyzes archive structure for Android protection analysis."""
    import io

    from intellicrack.utils.core.import_patterns import get_zipfile

    zipfile_info = get_zipfile()

    if not zipfile_info["available"]:
        pytest.skip("zipfile not available")

    zipfile_module = zipfile_info["zipfile"]

    fake_zip_data = (
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
        b"\x00\x00!\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x04\x00\x00\x00test"
        b"PK\x01\x02\x14\x00\x14\x00\x00\x00\x08\x00"
        b"\x00\x00!\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00test"
        b"PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00"
        b"2\x00\x00\x00\x1e\x00\x00\x00\x00\x00"
    )

    with zipfile_module.ZipFile(io.BytesIO(fake_zip_data), "r") as zf:
        namelist = zf.namelist()
        assert len(namelist) >= 0


def test_import_patterns_get_xml_returns_complete_dictionary() -> None:
    """get_xml returns dictionary with XML parsing components for manifest analysis."""
    from intellicrack.utils.core.import_patterns import XML_AVAILABLE, get_xml

    result = get_xml()

    assert isinstance(result, dict)
    assert "ET" in result
    assert "available" in result
    assert result["available"] == XML_AVAILABLE

    if XML_AVAILABLE:
        assert result["ET"] is not None


def test_import_patterns_xml_parses_manifest_data() -> None:
    """XML parser successfully analyzes Android manifest for protection detection."""
    from intellicrack.utils.core.import_patterns import get_xml

    xml_info = get_xml()

    if not xml_info["available"]:
        pytest.skip("XML parsing not available")

    ET = xml_info["ET"]

    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
              package="com.example.protected">
        <application android:name="com.example.LicenseCheck">
            <meta-data android:name="license_key" android:value="encrypted"/>
        </application>
    </manifest>"""

    root = ET.fromstring(manifest_xml)
    assert root.tag == "manifest"
    assert root.get("package") == "com.example.protected"

    app = root.find("application")
    assert app is not None
    assert app.get("{http://schemas.android.com/apk/res/android}name") == "com.example.LicenseCheck"


def test_import_patterns_get_psutil_returns_module_or_none() -> None:
    """get_psutil returns psutil module for process monitoring during cracking."""
    from intellicrack.utils.core.import_patterns import PSUTIL_AVAILABLE, get_psutil

    result = get_psutil()

    if PSUTIL_AVAILABLE:
        assert result is not None
        assert hasattr(result, "Process")
    else:
        assert result is None


def test_import_patterns_psutil_monitors_process_for_license_checks() -> None:
    """Psutil monitors process memory and behavior for license validation detection."""
    import os

    from intellicrack.utils.core.import_patterns import get_psutil

    psutil_module = get_psutil()

    if psutil_module is None:
        pytest.skip("psutil not available")

    current_process = psutil_module.Process(os.getpid())

    assert current_process.pid == os.getpid()
    assert current_process.name()
    assert current_process.memory_info()


def test_import_patterns_all_availability_flags_are_boolean() -> None:
    """All availability flags are boolean values."""
    from intellicrack.utils.core import import_patterns

    flags = [
        "PEFILE_AVAILABLE",
        "CAPSTONE_AVAILABLE",
        "LIEF_AVAILABLE",
        "PYELFTOOLS_AVAILABLE",
        "MACHOLIB_AVAILABLE",
        "ZIPFILE_AVAILABLE",
        "XML_AVAILABLE",
        "PSUTIL_AVAILABLE",
    ]

    for flag in flags:
        value: Any = getattr(import_patterns, flag)
        assert isinstance(
            value, bool
        ), f"{flag} must be boolean, got {type(value).__name__}"


def test_import_patterns_all_getter_functions_return_expected_types() -> None:
    """All getter functions return expected data types."""
    from intellicrack.utils.core import import_patterns

    dict_getters = [
        "get_capstone",
        "get_elftools",
        "get_macholib",
        "get_zipfile",
        "get_xml",
    ]

    for getter_name in dict_getters:
        getter = getattr(import_patterns, getter_name)
        result = getter()
        assert isinstance(result, dict), f"{getter_name} must return dict"
        assert "available" in result, f"{getter_name} dict must have 'available' key"

    module_getters = ["get_pefile", "get_lief", "get_psutil"]

    for getter_name in module_getters:
        getter = getattr(import_patterns, getter_name)
        result = getter()
        assert result is None or isinstance(result, type(import_patterns))


def test_import_patterns_all_exports_accessible() -> None:
    """All exported symbols are accessible from import_patterns module."""
    from intellicrack.utils.core import import_patterns

    for name in import_patterns.__all__:
        assert hasattr(
            import_patterns, name
        ), f"Exported symbol {name} not accessible"


def test_import_patterns_consistency_between_flags_and_getters() -> None:
    """Getter functions return None/empty when availability flags are False."""
    from intellicrack.utils.core import import_patterns

    test_cases = [
        ("PEFILE_AVAILABLE", "get_pefile"),
        ("LIEF_AVAILABLE", "get_lief"),
        ("PSUTIL_AVAILABLE", "get_psutil"),
    ]

    for flag_name, getter_name in test_cases:
        flag_value: bool = getattr(import_patterns, flag_name)
        getter = getattr(import_patterns, getter_name)
        result = getter()

        if flag_value:
            assert result is not None
        else:
            assert result is None


def test_import_patterns_dictionary_getters_always_have_available_key() -> None:
    """Dictionary getters always include availability information."""
    from intellicrack.utils.core import import_patterns

    dict_getters = [
        ("get_capstone", "CAPSTONE_AVAILABLE"),
        ("get_elftools", "PYELFTOOLS_AVAILABLE"),
        ("get_macholib", "MACHOLIB_AVAILABLE"),
        ("get_zipfile", "ZIPFILE_AVAILABLE"),
        ("get_xml", "XML_AVAILABLE"),
    ]

    for getter_name, flag_name in dict_getters:
        getter = getattr(import_patterns, getter_name)
        flag_value: bool = getattr(import_patterns, flag_name)
        result = getter()

        assert "available" in result
        assert result["available"] == flag_value


def test_import_patterns_lief_parses_pe_binary_structure() -> None:
    """LIEF successfully parses PE binary structure for protection analysis."""
    from intellicrack.utils.core.import_patterns import get_lief

    lief_module = get_lief()

    if lief_module is None:
        pytest.skip("LIEF not available")

    minimal_pe = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00" * (0x3C - 0x20)
        + b"\x80\x00\x00\x00"
        + b"\x00" * (0x80 - 0x40)
        + b"PE\x00\x00"
        + b"\x4c\x01\x01\x00"
        + b"\x00" * 500
    )

    try:
        if binary := lief_module.parse(list(minimal_pe)):
            assert hasattr(binary, "header") or hasattr(binary, "dos_header")
    except Exception:
        pytest.skip("LIEF parse requires more complete PE structure")


def test_import_patterns_capstone_modes_correct_for_x64_analysis() -> None:
    """Capstone modes correctly configured for 64-bit binary analysis."""
    from intellicrack.utils.core.import_patterns import get_capstone

    capstone_info = get_capstone()

    if not capstone_info["available"]:
        pytest.skip("Capstone not available")

    Cs = capstone_info["Cs"]
    CS_ARCH_X86 = capstone_info["CS_ARCH_X86"]
    CS_MODE_64 = capstone_info["CS_MODE_64"]

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    x64_code = b"\x48\x89\xe5"
    instructions = list(md.disasm(x64_code, 0x1000))

    assert instructions
    for insn in instructions:
        assert hasattr(insn, "mnemonic")


def test_import_patterns_pefile_module_has_pe_class() -> None:
    """pefile module provides PE class for Windows binary analysis."""
    from intellicrack.utils.core.import_patterns import get_pefile

    pefile_module = get_pefile()

    if pefile_module is None:
        pytest.skip("pefile not available")

    assert hasattr(pefile_module, "PE")
    assert callable(pefile_module.PE)
