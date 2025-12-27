"""Production tests for enhanced QEMU test manager.

Tests real QEMU VM integration for binary analysis and Frida instrumentation.
"""

import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.ai.qemu_test_manager_enhanced import EnhancedQEMUTestManager


@pytest.fixture
def qemu_manager() -> EnhancedQEMUTestManager:
    """Create QEMU test manager."""
    return EnhancedQEMUTestManager(vm_ip="192.168.122.100")


def test_qemu_manager_initialization(qemu_manager: EnhancedQEMUTestManager) -> None:
    """Test QEMU manager initializes correctly."""
    assert qemu_manager.vm_ip == "192.168.122.100"


def test_analyze_binary_for_vm_windows_pe(qemu_manager: EnhancedQEMUTestManager) -> None:
    """Test binary analysis for Windows PE files."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        pe_path = f.name
        f.write(b"MZ" + b"\x00" * 1000)

    try:
        with patch("magic.from_file", return_value="PE32+ executable"):
            with patch("intellicrack.handlers.pefile_handler.pefile.PE") as mock_pe:
                mock_pe_instance = MagicMock()
                mock_pe_instance.FILE_HEADER.Machine = 0x8664
                mock_pe_instance.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
                mock_pe_instance.DIRECTORY_ENTRY_IMPORT = []
                mock_pe_instance.sections = []
                mock_pe.return_value = mock_pe_instance

                result = qemu_manager.analyze_binary_for_vm(pe_path)

                assert result["platform"] == "windows"
                assert result["architecture"] == "x64"
                assert result["entry_point"] == "0x1000"
                assert isinstance(result["dependencies"], list)
                assert isinstance(result["sections"], list)
    finally:
        Path(pe_path).unlink(missing_ok=True)


def test_analyze_binary_for_vm_linux_elf(qemu_manager: EnhancedQEMUTestManager) -> None:
    """Test binary analysis for Linux ELF files."""
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        elf_path = f.name
        f.write(b"\x7fELF" + b"\x00" * 1000)

    try:
        with patch("magic.from_file", return_value="ELF 64-bit"):
            result = qemu_manager.analyze_binary_for_vm(elf_path)

            assert result["platform"] == "linux"
    finally:
        Path(elf_path).unlink(missing_ok=True)


def test_test_frida_script_generates_wrapper() -> None:
    """Test Frida script wrapper generation."""
    manager = EnhancedQEMUTestManager()

    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        binary_path = f.name

    try:
        frida_script = """
        console.log("[*] Starting Frida script");
        var session = frida.attach("target");
        var user_script = "console.log('test');";
        """

        output_lines: list[str] = []

        def output_callback(line: str) -> None:
            output_lines.append(line)

        with patch("subprocess.Popen") as mock_popen:
            mock_qemu = MagicMock()
            mock_qemu.stdout.readline.side_effect = ["", StopIteration]
            mock_qemu.returncode = 0
            mock_qemu.wait.return_value = None

            mock_frida = MagicMock()
            mock_frida.stdout.readline.side_effect = ["", StopIteration]
            mock_frida.returncode = 0
            mock_frida.wait.return_value = None

            mock_popen.side_effect = [mock_qemu, mock_frida]

            with patch("builtins.open", create=True) as mock_file:
                mock_file.return_value.__enter__.return_value.read.return_value = "{}"

                result = manager.test_frida_script_with_callback(
                    snapshot_id="test_snapshot",
                    script_content=frida_script,
                    binary_path=binary_path,
                    output_callback=output_callback,
                )

                assert isinstance(result, dict)
                assert "success" in result
                assert "qemu_returncode" in result
                assert "frida_returncode" in result
    finally:
        Path(binary_path).unlink(missing_ok=True)


def test_monitor_process_in_vm() -> None:
    """Test process monitoring in VM."""
    manager = EnhancedQEMUTestManager(vm_ip="192.168.122.100")

    mock_output = json.dumps({
        "cpu_percent": 45.5,
        "memory_percent": 32.1,
        "open_files": 15,
        "connections": 3,
        "threads": 8,
    })

    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = mock_output
        mock_run.return_value = mock_result

        result = manager.monitor_process_in_vm(1234)

        assert result["cpu_percent"] == 45.5
        assert result["memory_percent"] == 32.1
        assert result["open_files"] == 15
        assert result["connections"] == 3
        assert result["threads"] == 8


def test_monitor_process_failure() -> None:
    """Test process monitoring handles failures."""
    manager = EnhancedQEMUTestManager()

    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        result = manager.monitor_process_in_vm(9999)

        assert result == {}


def test_real_binary_analysis_pe_sections() -> None:
    """Test PE section extraction."""
    manager = EnhancedQEMUTestManager()

    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        pe_path = f.name
        f.write(b"MZ" + b"\x00" * 2000)

    try:
        with patch("magic.from_file", return_value="PE32 executable"):
            with patch("intellicrack.handlers.pefile_handler.pefile.PE") as mock_pe:
                mock_section = MagicMock()
                mock_section.Name = b".text\x00\x00\x00"
                mock_section.VirtualAddress = 0x1000
                mock_section.SizeOfRawData = 4096

                mock_pe_instance = MagicMock()
                mock_pe_instance.FILE_HEADER.Machine = 0x014C
                mock_pe_instance.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
                mock_pe_instance.DIRECTORY_ENTRY_IMPORT = []
                mock_pe_instance.sections = [mock_section]
                mock_pe.return_value = mock_pe_instance

                result = manager.analyze_binary_for_vm(pe_path)

                assert len(result["sections"]) == 1
                assert result["sections"][0]["name"] == ".text"
                assert result["sections"][0]["virtual_address"] == "0x1000"
                assert result["sections"][0]["size"] == 4096
    finally:
        Path(pe_path).unlink(missing_ok=True)


def test_real_binary_analysis_pe_imports() -> None:
    """Test PE import extraction."""
    manager = EnhancedQEMUTestManager()

    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        pe_path = f.name
        f.write(b"MZ" + b"\x00" * 2000)

    try:
        with patch("magic.from_file", return_value="PE32 executable"):
            with patch("intellicrack.handlers.pefile_handler.pefile.PE") as mock_pe:
                mock_import = MagicMock()
                mock_import.dll = b"kernel32.dll"

                mock_pe_instance = MagicMock()
                mock_pe_instance.FILE_HEADER.Machine = 0x014C
                mock_pe_instance.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
                mock_pe_instance.DIRECTORY_ENTRY_IMPORT = [mock_import]
                mock_pe_instance.sections = []
                mock_pe.return_value = mock_pe_instance

                result = manager.analyze_binary_for_vm(pe_path)

                assert "kernel32.dll" in result["dependencies"]
    finally:
        Path(pe_path).unlink(missing_ok=True)


def test_vm_ip_configuration() -> None:
    """Test VM IP is properly configured."""
    manager1 = EnhancedQEMUTestManager(vm_ip="10.0.0.5")
    assert manager1.vm_ip == "10.0.0.5"

    manager2 = EnhancedQEMUTestManager()
    assert manager2.vm_ip == "localhost"


def test_binary_analysis_unknown_type() -> None:
    """Test handling of unknown binary types."""
    manager = EnhancedQEMUTestManager()

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        bin_path = f.name
        f.write(b"\x00" * 100)

    try:
        with patch("magic.from_file", return_value="data"):
            result = manager.analyze_binary_for_vm(bin_path)

            assert result["platform"] == "unknown"
            assert result["architecture"] == "unknown"
    finally:
        Path(bin_path).unlink(missing_ok=True)
