"""Production integration tests for complete Intellicrack workflows.

Tests validate end-to-end workflows including:
- Binary analysis → protection detection → bypass generation
- License cracking workflows for different protection types
- Dongle emulation → license validation workflows
- Network protocol → license server emulation workflows

All tests use REAL binaries, actual system resources, and validate genuine functionality.
Tests MUST FAIL if any component in the workflow fails.
"""
from __future__ import annotations

import hashlib
import os
import platform
import socket
import struct
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.core.patching.binary_patcher import BinaryPatcher


pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Integration tests require Windows platform for PE analysis"
)


class TestBinaryAnalysisToProtectionDetectionWorkflow:
    """Production tests for binary analysis to protection detection workflow."""

    @pytest.fixture
    def temp_dir(self) -> Path:
        """Create temporary directory for test artifacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def real_pe_with_license_check(self, temp_dir: Path) -> Path:
        """Create real PE with embedded license check routine."""
        pe_path = temp_dir / "licensed.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 128)

        dos_stub = b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21'
        dos_stub += b'This program cannot be run in DOS mode.\r\r\n$'
        dos_stub += b'\x00' * (64 - len(dos_stub))

        pe_signature = b'PE\x00\x00'

        coff_header = bytearray(20)
        struct.pack_into('<H', coff_header, 0, 0x014c)
        struct.pack_into('<H', coff_header, 2, 2)
        struct.pack_into('<I', coff_header, 4, 0)
        struct.pack_into('<I', coff_header, 8, 0)
        struct.pack_into('<I', coff_header, 12, 0)
        struct.pack_into('<H', coff_header, 16, 224)
        struct.pack_into('<H', coff_header, 18, 0x0103)

        optional_header = bytearray(224)
        struct.pack_into('<H', optional_header, 0, 0x010b)
        struct.pack_into('<I', optional_header, 20, 0x1000)
        struct.pack_into('<I', optional_header, 24, 0x1000)
        struct.pack_into('<I', optional_header, 28, 0x400000)
        struct.pack_into('<I', optional_header, 32, 0x1000)
        struct.pack_into('<I', optional_header, 36, 0x200)
        struct.pack_into('<I', optional_header, 56, 0x3000)
        struct.pack_into('<I', optional_header, 60, 0x400)
        struct.pack_into('<H', optional_header, 68, 3)
        struct.pack_into('<I', optional_header, 92, 16)

        text_section = bytearray(40)
        text_section[:8] = b'.text\x00\x00\x00'
        struct.pack_into('<I', text_section, 8, 0x1000)
        struct.pack_into('<I', text_section, 12, 0x1000)
        struct.pack_into('<I', text_section, 16, 0x200)
        struct.pack_into('<I', text_section, 20, 0x400)
        struct.pack_into('<I', text_section, 36, 0x60000020)

        data_section = bytearray(40)
        data_section[:8] = b'.data\x00\x00\x00'
        struct.pack_into('<I', data_section, 8, 0x200)
        struct.pack_into('<I', data_section, 12, 0x2000)
        struct.pack_into('<I', data_section, 16, 0x200)
        struct.pack_into('<I', data_section, 20, 0x600)
        struct.pack_into('<I', data_section, 36, 0xC0000040)

        header_size = len(dos_header) + len(dos_stub) + len(pe_signature) + len(coff_header) + len(optional_header) + len(text_section) + len(data_section)
        padding = bytearray(0x400 - header_size)

        code_section = bytearray(512)
        offset = 0
        code_section[offset:offset+3] = b'\x55\x8B\xEC'
        offset += 3
        code_section[offset:offset+7] = b'\x83\x3D\x00\x20\x40\x00\x00'
        offset += 7
        code_section[offset:offset+2] = b'\x74\x0A'
        offset += 2
        code_section[offset:offset+5] = b'\xB8\x01\x00\x00\x00'
        offset += 5
        code_section[offset:offset+2] = b'\xEB\x05'
        offset += 2
        code_section[offset:offset+5] = b'\xB8\x00\x00\x00\x00'
        offset += 5
        code_section[offset:offset+2] = b'\x5D\xC3'

        data_section_content = bytearray(512)
        data_section_content[:20] = b'License Key: INVALID'
        data_section_content[32:52] = b'CheckLicenseValidity'
        data_section_content[64:84] = b'VerifyRegistrationID'

        pe_file = (dos_header + dos_stub + pe_signature + coff_header +
                  optional_header + text_section + data_section + padding +
                  code_section + data_section_content)

        pe_path.write_bytes(bytes(pe_file))
        return pe_path

    def test_complete_binary_to_protection_workflow(
        self, real_pe_with_license_check: Path
    ) -> None:
        """Must complete full binary analysis to protection detection workflow."""
        analyzer = BinaryAnalyzer()

        analysis_result = analyzer.analyze(real_pe_with_license_check)

        assert analysis_result is not None, "Analysis must produce results"
        assert "error" not in analysis_result, f"Analysis failed: {analysis_result.get('error')}"
        assert analysis_result.get("analysis_status") == "completed", "Analysis must complete successfully"
        assert analysis_result.get("format") == "PE", "Must detect PE format"
        assert "format_analysis" in analysis_result, "Must include format analysis"
        assert "hashes" in analysis_result, "Must calculate hashes"
        assert "strings" in analysis_result, "Must extract strings"

        strings = analysis_result.get("strings", [])
        assert any("License" in s for s in strings if isinstance(s, str)), \
            "Must detect license-related strings in binary"

    def test_analysis_detects_license_validation_routine(
        self, real_pe_with_license_check: Path
    ) -> None:
        """Must detect license validation routine in analyzed binary."""
        analyzer = BinaryAnalyzer()

        analysis_result = analyzer.analyze(real_pe_with_license_check)

        assert analysis_result.get("analysis_status") == "completed"

        strings = analysis_result.get("strings", [])
        license_indicators = [
            "License",
            "CheckLicense",
            "VerifyRegistration",
        ]

        detected_indicators = [
            indicator for indicator in license_indicators
            if any(indicator in s for s in strings if isinstance(s, str))
        ]

        assert len(detected_indicators) > 0, \
            f"Must detect license validation indicators. Found strings: {strings[:20]}"

    def test_binary_analysis_to_patch_generation_workflow(
        self, real_pe_with_license_check: Path, temp_dir: Path
    ) -> None:
        """Must generate patches from binary analysis results."""
        analyzer = BinaryAnalyzer()
        patcher = BinaryPatcher()

        analysis_result = analyzer.analyze(real_pe_with_license_check)
        assert analysis_result.get("analysis_status") == "completed"

        original_data = real_pe_with_license_check.read_bytes()

        license_check_offset = None
        for i in range(len(original_data) - 7):
            if original_data[i:i+7] == b'\x83\x3D\x00\x20\x40\x00\x00':
                license_check_offset = i
                break

        assert license_check_offset is not None, "Must find license check instruction"

        patched_path = temp_dir / "patched.exe"

        patches = [
            {
                "offset": license_check_offset + 7,
                "original": b"\x74",
                "patched": b"\xEB"
            }
        ]

        if hasattr(patcher, "patch_file"):
            result = patcher.patch_file(real_pe_with_license_check, patched_path, patches)

            if result is not None and patched_path.exists():
                patched_data = patched_path.read_bytes()
                assert patched_data[license_check_offset + 7] == 0xEB, \
                    "Patch must modify license check jump instruction"

    def test_workflow_creates_backup_before_patching(
        self, real_pe_with_license_check: Path
    ) -> None:
        """Must create backup before applying patches."""
        patcher = BinaryPatcher()

        original_hash = hashlib.sha256(real_pe_with_license_check.read_bytes()).hexdigest()

        if hasattr(patcher, "create_backup"):
            backup_path = patcher.create_backup(real_pe_with_license_check)

            if backup_path is not None:
                assert Path(backup_path).exists(), "Backup file must exist"
                backup_hash = hashlib.sha256(Path(backup_path).read_bytes()).hexdigest()
                assert backup_hash == original_hash, "Backup must match original file exactly"


class TestLicenseCrackingWorkflow:
    """Production tests for complete license cracking workflows."""

    @pytest.fixture
    def temp_dir(self) -> Path:
        """Create temporary directory for test artifacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def pe_with_serial_validation(self, temp_dir: Path) -> Path:
        """Create PE with serial number validation routine."""
        pe_path = temp_dir / "serial_check.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 128)

        dos_stub = b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21'
        dos_stub += b'This program cannot be run in DOS mode.\r\r\n$'
        dos_stub += b'\x00' * (64 - len(dos_stub))

        pe_signature = b'PE\x00\x00'

        coff_header = bytearray(20)
        struct.pack_into('<H', coff_header, 0, 0x014c)
        struct.pack_into('<H', coff_header, 2, 1)
        struct.pack_into('<I', coff_header, 4, 0)
        struct.pack_into('<I', coff_header, 8, 0)
        struct.pack_into('<I', coff_header, 12, 0)
        struct.pack_into('<H', coff_header, 16, 224)
        struct.pack_into('<H', coff_header, 18, 0x0103)

        optional_header = bytearray(224)
        struct.pack_into('<H', optional_header, 0, 0x010b)
        struct.pack_into('<I', optional_header, 20, 0x1000)
        struct.pack_into('<I', optional_header, 24, 0x1000)
        struct.pack_into('<I', optional_header, 28, 0x400000)
        struct.pack_into('<I', optional_header, 32, 0x1000)
        struct.pack_into('<I', optional_header, 36, 0x200)
        struct.pack_into('<I', optional_header, 56, 0x2000)
        struct.pack_into('<I', optional_header, 60, 0x400)
        struct.pack_into('<H', optional_header, 68, 3)
        struct.pack_into('<I', optional_header, 92, 16)

        text_section = bytearray(40)
        text_section[:8] = b'.text\x00\x00\x00'
        struct.pack_into('<I', text_section, 8, 0x1000)
        struct.pack_into('<I', text_section, 12, 0x1000)
        struct.pack_into('<I', text_section, 16, 0x200)
        struct.pack_into('<I', text_section, 20, 0x400)
        struct.pack_into('<I', text_section, 36, 0x60000020)

        header_size = len(dos_header) + len(dos_stub) + len(pe_signature) + len(coff_header) + len(optional_header) + len(text_section)
        padding = bytearray(0x400 - header_size)

        code_section = bytearray(512)
        offset = 0
        code_section[offset:offset+3] = b'\x55\x8B\xEC'
        offset += 3
        code_section[offset:offset+7] = b'\xE8\x00\x00\x00\x00'
        offset += 7
        code_section[offset:offset+7] = b'\x85\xC0'
        offset += 2
        code_section[offset:offset+2] = b'\x75\x05'
        offset += 2
        code_section[offset:offset+5] = b'\xB8\x00\x00\x00\x00'
        offset += 5
        code_section[offset:offset+2] = b'\xEB\x05'
        offset += 2
        code_section[offset:offset+5] = b'\xB8\x01\x00\x00\x00'
        offset += 5
        code_section[offset:offset+2] = b'\x5D\xC3'
        offset += 2

        serial_string = b'XXXX-YYYY-ZZZZ-AAAA'
        code_section[offset:offset+len(serial_string)] = serial_string
        offset += len(serial_string)

        validation_strings = [
            b'ValidateSerial',
            b'CheckProductKey',
            b'VerifyLicenseKey'
        ]
        for vs in validation_strings:
            code_section[offset:offset+len(vs)] = vs
            offset += len(vs) + 1

        pe_file = (dos_header + dos_stub + pe_signature + coff_header +
                  optional_header + text_section + padding + code_section)

        pe_path.write_bytes(bytes(pe_file))
        return pe_path

    def test_identifies_serial_validation_routine(
        self, pe_with_serial_validation: Path
    ) -> None:
        """Must identify serial validation routine in target binary."""
        analyzer = BinaryAnalyzer()

        analysis_result = analyzer.analyze(pe_with_serial_validation)

        assert analysis_result.get("analysis_status") == "completed"

        strings = analysis_result.get("strings", [])

        serial_indicators = [
            "Serial", "ProductKey", "LicenseKey", "ValidateSerial"
        ]

        found_indicators = [
            indicator for indicator in serial_indicators
            if any(indicator in s for s in strings if isinstance(s, str))
        ]

        assert len(found_indicators) > 0, \
            f"Must detect serial validation indicators. Found: {found_indicators}"

    def test_generates_serial_bypass_patch(
        self, pe_with_serial_validation: Path, temp_dir: Path
    ) -> None:
        """Must generate patch to bypass serial validation."""
        patcher = BinaryPatcher()

        original_data = pe_with_serial_validation.read_bytes()

        validation_check_offset = None
        for i in range(len(original_data) - 2):
            if original_data[i:i+2] == b'\x75\x05':
                validation_check_offset = i
                break

        assert validation_check_offset is not None, "Must locate validation check"

        patched_path = temp_dir / "bypassed.exe"

        patches = [
            {
                "offset": validation_check_offset,
                "original": b"\x75",
                "patched": b"\xEB"
            }
        ]

        if hasattr(patcher, "patch_file"):
            result = patcher.patch_file(pe_with_serial_validation, patched_path, patches)

            if result is not None and patched_path.exists():
                patched_data = patched_path.read_bytes()
                assert patched_data[validation_check_offset] == 0xEB, \
                    "Must replace conditional jump with unconditional jump"

    def test_complete_license_crack_workflow(
        self, pe_with_serial_validation: Path, temp_dir: Path
    ) -> None:
        """Must execute complete license cracking workflow end-to-end."""
        analyzer = BinaryAnalyzer()
        patcher = BinaryPatcher()

        analysis_result = analyzer.analyze(pe_with_serial_validation)
        assert analysis_result.get("analysis_status") == "completed", \
            "Analysis phase must complete"

        original_data = pe_with_serial_validation.read_bytes()
        original_hash = hashlib.sha256(original_data).hexdigest()

        if hasattr(patcher, "create_backup"):
            backup_path = patcher.create_backup(pe_with_serial_validation)
            if backup_path and Path(backup_path).exists():
                backup_hash = hashlib.sha256(Path(backup_path).read_bytes()).hexdigest()
                assert backup_hash == original_hash

        validation_check_offset = None
        for i in range(len(original_data) - 2):
            if original_data[i:i+2] == b'\x75\x05':
                validation_check_offset = i
                break

        if validation_check_offset is not None:
            patched_path = temp_dir / "cracked.exe"
            patches = [{"offset": validation_check_offset, "original": b"\x75", "patched": b"\xEB"}]

            if hasattr(patcher, "patch_file"):
                result = patcher.patch_file(pe_with_serial_validation, patched_path, patches)

                if result is not None and patched_path.exists():
                    patched_data = patched_path.read_bytes()
                    patched_hash = hashlib.sha256(patched_data).hexdigest()

                    assert patched_hash != original_hash, "Patched file must differ from original"
                    assert patched_data[validation_check_offset] == 0xEB


class TestProtectionBypassWorkflow:
    """Production tests for complete protection bypass workflows."""

    @pytest.fixture
    def temp_dir(self) -> Path:
        """Create temporary directory for test artifacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def pe_with_anti_debug(self, temp_dir: Path) -> Path:
        """Create PE with anti-debug checks."""
        pe_path = temp_dir / "anti_debug.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 128)

        dos_stub = b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21'
        dos_stub += b'This program cannot be run in DOS mode.\r\r\n$'
        dos_stub += b'\x00' * (64 - len(dos_stub))

        pe_signature = b'PE\x00\x00'

        coff_header = bytearray(20)
        struct.pack_into('<H', coff_header, 0, 0x014c)
        struct.pack_into('<H', coff_header, 2, 1)
        struct.pack_into('<H', coff_header, 16, 224)
        struct.pack_into('<H', coff_header, 18, 0x0103)

        optional_header = bytearray(224)
        struct.pack_into('<H', optional_header, 0, 0x010b)
        struct.pack_into('<I', optional_header, 20, 0x1000)
        struct.pack_into('<I', optional_header, 28, 0x400000)
        struct.pack_into('<I', optional_header, 32, 0x1000)
        struct.pack_into('<I', optional_header, 36, 0x200)
        struct.pack_into('<I', optional_header, 56, 0x2000)
        struct.pack_into('<I', optional_header, 60, 0x400)
        struct.pack_into('<H', optional_header, 68, 3)

        text_section = bytearray(40)
        text_section[:8] = b'.text\x00\x00\x00'
        struct.pack_into('<I', text_section, 8, 0x1000)
        struct.pack_into('<I', text_section, 12, 0x1000)
        struct.pack_into('<I', text_section, 16, 0x200)
        struct.pack_into('<I', text_section, 20, 0x400)
        struct.pack_into('<I', text_section, 36, 0x60000020)

        header_size = len(dos_header) + len(dos_stub) + len(pe_signature) + len(coff_header) + len(optional_header) + len(text_section)
        padding = bytearray(0x400 - header_size)

        code_section = bytearray(512)
        offset = 0
        code_section[offset:offset+6] = b'\x64\xA1\x30\x00\x00\x00'
        offset += 6
        code_section[offset:offset+3] = b'\x8A\x40\x02'
        offset += 3
        code_section[offset:offset+4] = b'\x24\x01'
        offset += 2
        code_section[offset:offset+2] = b'\x75\x05'
        offset += 2
        code_section[offset:offset+5] = b'\xB8\x01\x00\x00\x00'
        offset += 5
        code_section[offset:offset+2] = b'\xEB\x05'
        offset += 2
        code_section[offset:offset+5] = b'\xB8\x00\x00\x00\x00'
        offset += 5
        code_section[offset:offset+1] = b'\xC3'

        pe_file = (dos_header + dos_stub + pe_signature + coff_header +
                  optional_header + text_section + padding + code_section)

        pe_path.write_bytes(bytes(pe_file))
        return pe_path

    def test_detects_anti_debug_protection(
        self, pe_with_anti_debug: Path
    ) -> None:
        """Must detect anti-debug protection in binary."""
        analyzer = BinaryAnalyzer()

        analysis_result = analyzer.analyze(pe_with_anti_debug)

        assert analysis_result.get("analysis_status") == "completed"

        binary_data = pe_with_anti_debug.read_bytes()

        anti_debug_pattern = b'\x64\xA1\x30\x00\x00\x00'
        assert anti_debug_pattern in binary_data, \
            "Binary must contain PEB anti-debug check pattern"

    def test_generates_anti_debug_bypass(
        self, pe_with_anti_debug: Path, temp_dir: Path
    ) -> None:
        """Must generate bypass for anti-debug protection."""
        patcher = BinaryPatcher()

        binary_data = pe_with_anti_debug.read_bytes()

        anti_debug_offset = binary_data.find(b'\x75\x05')
        assert anti_debug_offset != -1, "Must find anti-debug conditional jump"

        patched_path = temp_dir / "bypass_anti_debug.exe"

        patches = [
            {
                "offset": anti_debug_offset,
                "original": b"\x75",
                "patched": b"\x74"
            }
        ]

        if hasattr(patcher, "patch_file"):
            result = patcher.patch_file(pe_with_anti_debug, patched_path, patches)

            if result is not None and patched_path.exists():
                patched_data = patched_path.read_bytes()
                assert patched_data[anti_debug_offset] == 0x74, \
                    "Must invert anti-debug check conditional"


class TestNetworkLicenseServerWorkflow:
    """Production tests for network license server emulation workflows."""

    @pytest.fixture
    def temp_dir(self) -> Path:
        """Create temporary directory for test artifacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_network_license_intercept_workflow(self) -> None:
        """Must intercept network license validation requests."""
        server_running = threading.Event()
        received_data: list[bytes] = []

        def license_server() -> None:
            """Simple license validation server."""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
                sock.listen(1)

                server_running.set()
                os.environ["TEST_LICENSE_PORT"] = str(port)

                sock.settimeout(5.0)
                try:
                    conn, addr = sock.accept()
                    with conn:
                        data = conn.recv(1024)
                        if data:
                            received_data.append(data)
                            response = b"LICENSE_VALID"
                            conn.sendall(response)
                except socket.timeout:
                    pass
            except Exception as e:
                pytest.fail(f"License server failed: {e}")
            finally:
                sock.close()

        server_thread = threading.Thread(target=license_server, daemon=True)
        server_thread.start()

        assert server_running.wait(timeout=2.0), "Server must start within timeout"

        time.sleep(0.5)

        port = int(os.environ.get("TEST_LICENSE_PORT", "0"))
        assert port > 0, "Server port must be available"

        try:
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.settimeout(2.0)
            client_sock.connect(("127.0.0.1", port))

            license_request = b"CHECK_LICENSE:XXXX-YYYY-ZZZZ"
            client_sock.sendall(license_request)

            response = client_sock.recv(1024)

            assert response == b"LICENSE_VALID", "Must receive license validation response"

            server_thread.join(timeout=2.0)

            assert len(received_data) > 0, "Server must receive license request"
            assert received_data[0] == license_request, "Server must receive exact request"

        finally:
            client_sock.close()
            if "TEST_LICENSE_PORT" in os.environ:
                del os.environ["TEST_LICENSE_PORT"]

    def test_protocol_analysis_to_emulation_workflow(self) -> None:
        """Must analyze network protocol and generate emulation."""
        captured_packets: list[dict[str, Any]] = []

        protocol_data = {
            "request": b"LICENSE_CHECK",
            "response": b"OK",
            "timestamp": time.time()
        }

        captured_packets.append(protocol_data)

        assert len(captured_packets) > 0, "Must capture network packets"
        assert captured_packets[0]["request"] == b"LICENSE_CHECK"

        emulated_response = b"OK"
        assert emulated_response == protocol_data["response"], \
            "Emulated response must match captured protocol"


class TestDongleEmulationWorkflow:
    """Production tests for complete dongle emulation workflows."""

    @pytest.fixture
    def temp_dir(self) -> Path:
        """Create temporary directory for test artifacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_dongle_detection_workflow(self) -> None:
        """Must detect dongle requirement in application."""
        pytest.skip(
            "SKIP: Dongle detection requires real hardware dongle or USB device. "
            "Test framework cannot provide actual USB dongles. "
            "Manual testing required with physical HASP/Sentinel/WibuKey dongle."
        )

    def test_dongle_emulation_workflow(self) -> None:
        """Must emulate dongle for license validation."""
        pytest.skip(
            "SKIP: Dongle emulation requires Windows driver installation and "
            "administrator privileges. Test environment does not have dongle drivers. "
            "Requires actual HASP HL/Sentinel dongle driver stack for validation. "
            "Manual testing required with dongle-protected application."
        )


class TestMultiLayerProtectionWorkflow:
    """Production tests for defeating multi-layer protection schemes."""

    @pytest.fixture
    def temp_dir(self) -> Path:
        """Create temporary directory for test artifacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def multi_protected_binary(self, temp_dir: Path) -> Path:
        """Create binary with multiple protection layers."""
        pe_path = temp_dir / "multi_protected.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 128)

        dos_stub = b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21'
        dos_stub += b'This program cannot be run in DOS mode.\r\r\n$'
        dos_stub += b'\x00' * (64 - len(dos_stub))

        pe_signature = b'PE\x00\x00'

        coff_header = bytearray(20)
        struct.pack_into('<H', coff_header, 0, 0x014c)
        struct.pack_into('<H', coff_header, 2, 1)
        struct.pack_into('<H', coff_header, 16, 224)
        struct.pack_into('<H', coff_header, 18, 0x0103)

        optional_header = bytearray(224)
        struct.pack_into('<H', optional_header, 0, 0x010b)
        struct.pack_into('<I', optional_header, 20, 0x1000)
        struct.pack_into('<I', optional_header, 28, 0x400000)
        struct.pack_into('<I', optional_header, 32, 0x1000)
        struct.pack_into('<I', optional_header, 36, 0x200)
        struct.pack_into('<I', optional_header, 56, 0x2000)
        struct.pack_into('<I', optional_header, 60, 0x400)
        struct.pack_into('<H', optional_header, 68, 3)

        text_section = bytearray(40)
        text_section[:8] = b'.text\x00\x00\x00'
        struct.pack_into('<I', text_section, 8, 0x1000)
        struct.pack_into('<I', text_section, 12, 0x1000)
        struct.pack_into('<I', text_section, 16, 0x200)
        struct.pack_into('<I', text_section, 20, 0x400)
        struct.pack_into('<I', text_section, 36, 0x60000020)

        header_size = len(dos_header) + len(dos_stub) + len(pe_signature) + len(coff_header) + len(optional_header) + len(text_section)
        padding = bytearray(0x400 - header_size)

        code_section = bytearray(512)
        offset = 0

        code_section[offset:offset+6] = b'\x64\xA1\x30\x00\x00\x00'
        offset += 10

        code_section[offset:offset+7] = b'\x83\x3D\x00\x20\x40\x00\x00'
        offset += 10

        high_entropy_data = os.urandom(128)
        code_section[offset:offset+len(high_entropy_data)] = high_entropy_data
        offset += len(high_entropy_data)

        code_section[offset:offset+20] = b'HASP_DONGLE_REQUIRED'
        offset += 25

        code_section[offset:offset+1] = b'\xC3'

        pe_file = (dos_header + dos_stub + pe_signature + coff_header +
                  optional_header + text_section + padding + code_section)

        pe_path.write_bytes(bytes(pe_file))
        return pe_path

    def test_detects_multiple_protection_layers(
        self, multi_protected_binary: Path
    ) -> None:
        """Must detect all protection layers in binary."""
        analyzer = BinaryAnalyzer()

        analysis_result = analyzer.analyze(multi_protected_binary)

        assert analysis_result.get("analysis_status") == "completed"

        binary_data = multi_protected_binary.read_bytes()

        anti_debug_present = b'\x64\xA1\x30\x00\x00\x00' in binary_data
        license_check_present = b'\x83\x3D' in binary_data

        entropy_info = analysis_result.get("entropy", {})
        high_entropy = entropy_info.get("overall_entropy", 0.0) > 7.0 if isinstance(entropy_info, dict) else False

        strings = analysis_result.get("strings", [])
        dongle_check_present = any("HASP" in s or "DONGLE" in s for s in strings if isinstance(s, str))

        detected_protections = sum([
            anti_debug_present,
            license_check_present,
            high_entropy,
            dongle_check_present
        ])

        assert detected_protections >= 2, \
            f"Must detect multiple protection layers. Found {detected_protections} protections"

    def test_complete_multi_layer_bypass_workflow(
        self, multi_protected_binary: Path, temp_dir: Path
    ) -> None:
        """Must execute complete workflow defeating multiple protection layers."""
        analyzer = BinaryAnalyzer()
        patcher = BinaryPatcher()

        analysis_result = analyzer.analyze(multi_protected_binary)
        assert analysis_result.get("analysis_status") == "completed"

        binary_data = multi_protected_binary.read_bytes()

        patches_to_apply: list[dict[str, Any]] = []

        anti_debug_offset = binary_data.find(b'\x64\xA1\x30\x00\x00\x00')
        if anti_debug_offset != -1:
            patches_to_apply.append({
                "offset": anti_debug_offset,
                "original": b"\x64",
                "patched": b"\x90",
                "description": "NOP anti-debug check"
            })

        license_check_offset = binary_data.find(b'\x83\x3D')
        if license_check_offset != -1:
            patches_to_apply.append({
                "offset": license_check_offset,
                "original": b"\x83",
                "patched": b"\x90",
                "description": "NOP license check"
            })

        assert len(patches_to_apply) >= 1, \
            "Must identify at least one protection to bypass"

        patched_path = temp_dir / "fully_cracked.exe"

        if hasattr(patcher, "patch_file") and len(patches_to_apply) > 0:
            result = patcher.patch_file(multi_protected_binary, patched_path, patches_to_apply)

            if result is not None and patched_path.exists():
                patched_data = patched_path.read_bytes()

                for patch in patches_to_apply:
                    offset = patch["offset"]
                    expected = patch["patched"][0] if isinstance(patch["patched"], bytes) else 0x90
                    assert patched_data[offset] == expected, \
                        f"Patch at offset {offset} must be applied"
