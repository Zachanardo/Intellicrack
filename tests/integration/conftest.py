"""Shared fixtures and configuration for Intellicrack integration tests.

Provides reusable fixtures, test data, and utilities for integration testing.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import hashlib
import json
import socket
import struct
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from collections.abc import Generator


try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


@pytest.fixture(scope="session")
def real_binary_root() -> Path:
    """Root directory for real protected binaries."""
    return Path(__file__).parent / "real_binary_tests" / "binaries"


@pytest.fixture(scope="session")
def test_data_root() -> Path:
    """Root directory for test data files."""
    return Path(__file__).parent / "test_data"


@pytest.fixture
def temp_workspace() -> Generator[Path, None, None]:
    """Temporary workspace that auto-cleans after test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        yield workspace


@pytest.fixture
def isolated_registry_hive(temp_workspace: Path) -> Path:
    """Isolated registry hive for testing without affecting system registry."""
    hive_path = temp_workspace / "test_registry.dat"
    return hive_path


@pytest.fixture(scope="function")
def dynamic_port() -> int:
    """Allocate a dynamic TCP port for testing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture(scope="session")
def sample_pe_binary(test_data_root: Path) -> bytes:
    """Minimal valid PE binary for testing."""
    pe_dos_header = (
        b"MZ"  # e_magic
        + b"\x90\x00"  # e_cblp
        + b"\x03\x00"  # e_cp
        + b"\x00\x00"  # e_crlc
        + b"\x04\x00"  # e_cparhdr
        + b"\x00\x00"  # e_minalloc
        + b"\xFF\xFF"  # e_maxalloc
        + b"\x00\x00"  # e_ss
        + b"\xB8\x00"  # e_sp
        + b"\x00\x00"  # e_csum
        + b"\x00\x00"  # e_ip
        + b"\x00\x00"  # e_cs
        + b"\x40\x00"  # e_lfarlc
        + b"\x00\x00"  # e_ovno
        + b"\x00" * 8  # e_res
        + b"\x00\x00"  # e_oemid
        + b"\x00\x00"  # e_oeminfo
        + b"\x00" * 20  # e_res2
        + b"\x80\x00\x00\x00"  # e_lfanew (offset to PE header)
    )

    dos_stub = b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21" + b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7

    pe_signature = b"PE\x00\x00"

    coff_header = (
        b"\x4C\x01"  # Machine (x86)
        + b"\x03\x00"  # NumberOfSections
        + b"\x00" * 4  # TimeDateStamp
        + b"\x00" * 4  # PointerToSymbolTable
        + b"\x00" * 4  # NumberOfSymbols
        + b"\xE0\x00"  # SizeOfOptionalHeader
        + b"\x0F\x01"  # Characteristics
    )

    optional_header = (
        b"\x0B\x01"  # Magic (PE32)
        + b"\x00" * 2  # Linker version
        + b"\x00\x10\x00\x00"  # SizeOfCode
        + b"\x00\x10\x00\x00"  # SizeOfInitializedData
        + b"\x00\x00\x00\x00"  # SizeOfUninitializedData
        + b"\x00\x10\x00\x00"  # AddressOfEntryPoint
        + b"\x00\x10\x00\x00"  # BaseOfCode
        + b"\x00\x20\x00\x00"  # BaseOfData
        + b"\x00\x00\x40\x00"  # ImageBase
        + b"\x00\x10\x00\x00"  # SectionAlignment
        + b"\x00\x02\x00\x00"  # FileAlignment
        + b"\x00" * 16  # OS/Image/Subsystem versions
        + b"\x00\x00\x00\x00"  # Win32VersionValue
        + b"\x00\x50\x00\x00"  # SizeOfImage
        + b"\x00\x02\x00\x00"  # SizeOfHeaders
        + b"\x00" * 4  # CheckSum
        + b"\x03\x00"  # Subsystem (Console)
        + b"\x00\x00"  # DllCharacteristics
        + b"\x00" * 20  # Stack/Heap sizes
        + b"\x00" * 4  # LoaderFlags
        + b"\x10\x00\x00\x00"  # NumberOfRvaAndSizes
        + b"\x00" * 128  # Data directories
    )

    section_header = (
        b".text\x00\x00\x00"  # Name
        + b"\x00\x10\x00\x00"  # VirtualSize
        + b"\x00\x10\x00\x00"  # VirtualAddress
        + b"\x00\x10\x00\x00"  # SizeOfRawData
        + b"\x00\x02\x00\x00"  # PointerToRawData
        + b"\x00" * 12  # Relocations/LineNumbers
        + b"\x60\x00\x00\x20"  # Characteristics
    )

    section_data = b"\x90" * 0x1000  # NOP sled

    binary = (
        pe_dos_header
        + dos_stub
        + b"\x00" * (0x80 - len(pe_dos_header) - len(dos_stub))
        + pe_signature
        + coff_header
        + optional_header
        + section_header
        + b"\x00" * (0x200 - len(pe_signature) - len(coff_header) - len(optional_header) - len(section_header))
        + section_data
    )

    return binary


@pytest.fixture(scope="session")
def sample_flexlm_license() -> bytes:
    """Sample FlexLM license file for testing."""
    license_content = """SERVER license-server ANY 27000
DAEMON testd /path/to/testd
FEATURE TestApp testd 1.0 permanent uncounted HOSTID=ANY \\
    SIGN="0123456789ABCDEF0123456789ABCDEF"
INCREMENT TestFeature testd 1.0 permanent 10 HOSTID=ANY \\
    SIGN="FEDCBA9876543210FEDCBA9876543210"
"""
    return license_content.encode()


@pytest.fixture(scope="session")
def sample_hasp_commands() -> dict[str, bytes]:
    """Sample HASP dongle commands for testing."""
    return {
        "login": struct.pack("<IIII", 0x01, 42, 0x12345678, 16),
        "logout": struct.pack("<II", 0x02, 1),
        "encrypt": struct.pack("<II", 0x10, 1) + b"test_data_to_encrypt",
        "decrypt": struct.pack("<II", 0x11, 1) + b"encrypted_test_data_",
        "get_info": struct.pack("<II", 0x14, 1),
    }


@pytest.fixture
def mock_hardware_profile() -> dict[str, Any]:
    """Mock hardware profile for testing."""
    return {
        "cpu_id": "BFEBFBFF000906E9",
        "cpu_name": "Intel(R) Core(TM) i7-9700K",
        "motherboard_serial": "MOCK123456789",
        "bios_serial": "BIOS-MOCK-001",
        "disk_serial": ["1234-5678", "ABCD-EFGH"],
        "mac_addresses": ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"],
        "system_uuid": "12345678-1234-1234-1234-123456789012",
    }


@pytest.fixture
def test_license_keys() -> dict[str, list[str]]:
    """Collection of test license keys for various algorithm types."""
    return {
        "simple_checksum": [
            "ABCD-1234-EFGH-5678",
            "TEST-AAAA-BBBB-CCCC",
            "MOCK-0000-1111-2222",
        ],
        "crc32": [
            "12345678-ABCDEFGH",
            "AAAABBBB-CCCCDDDD",
        ],
        "base64_encoded": [
            "VGVzdExpY2Vuc2VLZXkxMjM0NTY=",
            "TW9ja0tleUZvclRlc3Rpbmc=",
        ],
        "numeric": [
            "1234567890123456",
            "9876543210987654",
        ],
    }


@pytest.fixture
def network_protocol_samples() -> dict[str, bytes]:
    """Sample network protocol packets for testing."""
    return {
        "flexlm_request": b"SIGN=0123456789ABCDEF VENDOR=TestVendor FEATURE=TestApp VERSION=1.0\n",
        "hasp_discovery": struct.pack("<HHI", 0x5350, 0x01, 0),
        "http_license_check": (
            b"POST /api/validate HTTP/1.1\r\n"
            b"Host: license-server.example.com\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 45\r\n"
            b"\r\n"
            b'{"product_id":"test123","license":"ABC-123"}'
        ),
    }


@pytest.fixture(scope="session")
def skip_if_no_real_binaries(real_binary_root: Path) -> None:
    """Skip test if no real binaries are available."""
    if not any(real_binary_root.rglob("*.exe")):
        pytest.skip(
            "No real binaries available. "
            "Place protected executables in tests/integration/real_binary_tests/binaries/ "
            "to enable integration testing against real protections."
        )


@pytest.fixture
def skip_if_no_admin_privileges() -> None:
    """Skip test if admin/elevated privileges not available."""
    import ctypes
    import sys

    if sys.platform == "win32":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                pytest.skip("Test requires administrator privileges")
        except Exception:
            pytest.skip("Cannot determine admin status")


@pytest.fixture
def performance_threshold() -> dict[str, float]:
    """Performance thresholds for integration tests (in seconds)."""
    return {
        "binary_analysis": 5.0,
        "keygen_single": 0.5,
        "keygen_bulk_100": 10.0,
        "protection_detection": 2.0,
        "license_server_response": 0.1,
        "hardware_spoof_apply": 1.0,
    }


@pytest.fixture(autouse=True)
def test_isolation() -> Generator[None, None, None]:
    """Ensure test isolation and cleanup."""
    import gc
    import warnings

    warnings.filterwarnings("ignore", category=DeprecationWarning)

    yield

    gc.collect()


@pytest.fixture
def binary_hash_validator() -> type:
    """Utility class for validating binary integrity after modifications."""

    class BinaryHashValidator:
        """Validates binary modifications don't corrupt structure."""

        @staticmethod
        def compute_hash(data: bytes) -> str:
            """Compute SHA256 hash of binary data."""
            return hashlib.sha256(data).hexdigest()

        @staticmethod
        def verify_pe_structure(data: bytes) -> bool:
            """Verify PE structure remains valid."""
            if not PEFILE_AVAILABLE:
                return True

            try:
                import pefile

                pe = pefile.PE(data=data)
                return pe.is_exe() or pe.is_dll()
            except Exception:
                return False

        @staticmethod
        def compare_sections(original: bytes, modified: bytes) -> dict[str, Any]:
            """Compare PE sections between original and modified binaries."""
            if not PEFILE_AVAILABLE:
                return {"status": "pefile_unavailable"}

            try:
                import pefile

                pe_orig = pefile.PE(data=original)
                pe_mod = pefile.PE(data=modified)

                results = {
                    "section_count_match": len(pe_orig.sections) == len(pe_mod.sections),
                    "sections_changed": [],
                }

                for orig_sec, mod_sec in zip(pe_orig.sections, pe_mod.sections):
                    if orig_sec.get_data() != mod_sec.get_data():
                        results["sections_changed"].append(
                            {
                                "name": orig_sec.Name.decode("utf-8", errors="ignore").strip("\x00"),
                                "original_hash": hashlib.sha256(orig_sec.get_data()).hexdigest()[:16],
                                "modified_hash": hashlib.sha256(mod_sec.get_data()).hexdigest()[:16],
                            }
                        )

                return results

            except Exception as e:
                return {"status": "error", "error": str(e)}

    return BinaryHashValidator


@pytest.fixture
def license_protocol_validator() -> type:
    """Utility class for validating license protocol responses."""

    class LicenseProtocolValidator:
        """Validates license protocol responses match expected formats."""

        @staticmethod
        def validate_flexlm_response(response: bytes) -> bool:
            """Validate FlexLM response format."""
            try:
                response_str = response.decode("utf-8", errors="ignore")
                return (
                    ("FEATURE=" in response_str or "INCREMENT" in response_str)
                    and "SIGN=" in response_str
                )
            except Exception:
                return False

        @staticmethod
        def validate_hasp_response(command_type: int, response: bytes) -> bool:
            """Validate HASP response format for command type."""
            if len(response) < 4:
                return False

            if command_type == 0x01:
                session_handle = struct.unpack("<I", response[:4])[0]
                return session_handle > 0

            return True

        @staticmethod
        def validate_http_license_response(response: bytes) -> bool:
            """Validate HTTP license response."""
            try:
                response_str = response.decode("utf-8", errors="ignore")
                return "HTTP" in response_str and ("200" in response_str or "valid" in response_str.lower())
            except Exception:
                return False

    return LicenseProtocolValidator


@pytest.fixture(scope="session")
def integration_test_config() -> dict[str, Any]:
    """Global configuration for integration tests."""
    return {
        "timeout_seconds": 30,
        "max_retries": 3,
        "enable_logging": True,
        "log_level": "INFO",
        "skip_slow_tests": False,
        "parallel_execution": False,
    }


def pytest_configure(config: Any) -> None:
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "requires_real_binaries: Test requires real protected binaries to execute",
    )
    config.addinivalue_line(
        "markers",
        "requires_admin: Test requires administrator/root privileges",
    )
    config.addinivalue_line(
        "markers",
        "requires_frida: Test requires Frida framework to be available",
    )
    config.addinivalue_line(
        "markers",
        "slow_integration: Test takes significant time (>10 seconds)",
    )
    config.addinivalue_line(
        "markers",
        "network_dependent: Test requires network connectivity",
    )


def pytest_collection_modifyitems(config: Any, items: list[Any]) -> None:
    """Modify test collection to add markers based on test names."""
    for item in items:
        if "real_binary" in item.nodeid:
            item.add_marker(pytest.mark.requires_real_binaries)

        if "admin" in item.nodeid or "privileges" in item.nodeid:
            item.add_marker(pytest.mark.requires_admin)

        if "frida" in item.nodeid.lower():
            item.add_marker(pytest.mark.requires_frida)

        if "performance" in item.nodeid or "bulk" in item.nodeid:
            item.add_marker(pytest.mark.slow_integration)

        if "network" in item.nodeid or "protocol" in item.nodeid or "ssl" in item.nodeid:
            item.add_marker(pytest.mark.network_dependent)
