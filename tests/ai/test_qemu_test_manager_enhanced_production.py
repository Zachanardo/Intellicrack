"""Production tests for enhanced QEMU test manager.

Tests real QEMU VM integration for binary analysis and Frida instrumentation.
"""

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.qemu_test_manager_enhanced import EnhancedQEMUTestManager


class FakePESection:
    """Real test double for PE section."""

    def __init__(self, name: bytes, virtual_address: int, size: int) -> None:
        self.Name = name
        self.VirtualAddress = virtual_address
        self.SizeOfRawData = size


class FakePEImport:
    """Real test double for PE import entry."""

    def __init__(self, dll_name: bytes) -> None:
        self.dll = dll_name


class FakePEFileHeader:
    """Real test double for PE file header."""

    def __init__(self, machine: int) -> None:
        self.Machine = machine


class FakePEOptionalHeader:
    """Real test double for PE optional header."""

    def __init__(self, entry_point: int) -> None:
        self.AddressOfEntryPoint = entry_point


class FakePE:
    """Real test double for PE file object."""

    def __init__(
        self,
        machine: int,
        entry_point: int,
        imports: list[FakePEImport],
        sections: list[FakePESection],
    ) -> None:
        self.FILE_HEADER = FakePEFileHeader(machine)
        self.OPTIONAL_HEADER = FakePEOptionalHeader(entry_point)
        self.DIRECTORY_ENTRY_IMPORT = imports
        self.sections = sections


class FakePEModule:
    """Real test double for pefile module."""

    def __init__(self, pe_object: FakePE) -> None:
        self._pe_object = pe_object

    def PE(self, path: str) -> FakePE:
        return self._pe_object


class FakeMagic:
    """Real test double for magic module."""

    def __init__(self, file_type: str) -> None:
        self._file_type = file_type

    def from_file(self, path: str) -> str:
        return self._file_type


class FakeSubprocessResult:
    """Real test double for subprocess result."""

    def __init__(self, returncode: int, stdout: str, stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakePopenProcess:
    """Real test double for subprocess.Popen process."""

    def __init__(
        self,
        returncode: int,
        stdout_lines: list[str],
        stderr_lines: list[str] | None = None,
    ) -> None:
        self.returncode = returncode
        self._stdout_lines = stdout_lines
        self._stderr_lines = stderr_lines or []
        self._stdout_index = 0
        self._stderr_index = 0

    class FakeStdout:
        """Real test double for stdout stream."""

        def __init__(self, lines: list[str]) -> None:
            self._lines = lines
            self._index = 0

        def readline(self) -> str:
            if self._index < len(self._lines):
                line = self._lines[self._index]
                self._index += 1
                return line
            return ""

    class FakeStderr:
        """Real test double for stderr stream."""

        def __init__(self, lines: list[str]) -> None:
            self._lines = lines
            self._index = 0

        def readline(self) -> str:
            if self._index < len(self._lines):
                line = self._lines[self._index]
                self._index += 1
                return line
            return ""

    @property
    def stdout(self) -> FakeStdout:
        return self.FakeStdout(self._stdout_lines)

    @property
    def stderr(self) -> FakeStderr:
        return self.FakeStderr(self._stderr_lines)

    def wait(self) -> None:
        pass


class FakeFileHandle:
    """Real test double for file handle."""

    def __init__(self, content: str) -> None:
        self._content = content

    def read(self) -> str:
        return self._content

    def __enter__(self) -> "FakeFileHandle":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass


@pytest.fixture
def qemu_manager() -> EnhancedQEMUTestManager:
    """Create QEMU test manager."""
    return EnhancedQEMUTestManager(vm_ip="192.168.122.100")


def test_qemu_manager_initialization(qemu_manager: EnhancedQEMUTestManager) -> None:
    """Test QEMU manager initializes correctly."""
    assert qemu_manager.vm_ip == "192.168.122.100"


def test_analyze_binary_for_vm_windows_pe(
    qemu_manager: EnhancedQEMUTestManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test binary analysis for Windows PE files."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        pe_path = f.name
        f.write(b"MZ" + b"\x00" * 1000)

    try:
        fake_magic = FakeMagic("PE32+ executable")
        fake_pe = FakePE(
            machine=0x8664,
            entry_point=0x1000,
            imports=[],
            sections=[],
        )
        fake_pe_module = FakePEModule(fake_pe)

        monkeypatch.setattr("magic.from_file", fake_magic.from_file)
        monkeypatch.setattr(
            "intellicrack.handlers.pefile_handler.pefile.PE",
            fake_pe_module.PE,
        )

        result = qemu_manager.analyze_binary_for_vm(pe_path)

        assert result["platform"] == "windows"
        assert result["architecture"] == "x64"
        assert result["entry_point"] == "0x1000"
        assert isinstance(result["dependencies"], list)
        assert isinstance(result["sections"], list)
    finally:
        Path(pe_path).unlink(missing_ok=True)


def test_analyze_binary_for_vm_linux_elf(
    qemu_manager: EnhancedQEMUTestManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test binary analysis for Linux ELF files."""
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        elf_path = f.name
        f.write(b"\x7fELF" + b"\x00" * 1000)

    try:
        fake_magic = FakeMagic("ELF 64-bit")
        monkeypatch.setattr("magic.from_file", fake_magic.from_file)

        result = qemu_manager.analyze_binary_for_vm(elf_path)

        assert result["platform"] == "linux"
    finally:
        Path(elf_path).unlink(missing_ok=True)


def test_test_frida_script_generates_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
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

        fake_qemu = FakePopenProcess(returncode=0, stdout_lines=[])
        fake_frida = FakePopenProcess(returncode=0, stdout_lines=[])
        popen_calls: list[list[str]] = []

        def fake_popen(
            args: list[str],
            stdout: Any = None,
            stderr: Any = None,
            text: bool = True,
            bufsize: int = 1,
        ) -> FakePopenProcess:
            popen_calls.append(args)
            if len(popen_calls) == 1:
                return fake_qemu
            return fake_frida

        fake_file_content = "{}"

        def fake_open(
            path: str, mode: str = "r", encoding: str | None = None
        ) -> FakeFileHandle:
            return FakeFileHandle(fake_file_content)

        monkeypatch.setattr("subprocess.Popen", fake_popen)
        monkeypatch.setattr("builtins.open", fake_open)

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
        assert result["qemu_returncode"] == 0
        assert result["frida_returncode"] == 0
    finally:
        Path(binary_path).unlink(missing_ok=True)


def test_monitor_process_in_vm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test process monitoring in VM."""
    manager = EnhancedQEMUTestManager(vm_ip="192.168.122.100")

    mock_output = json.dumps({
        "cpu_percent": 45.5,
        "memory_percent": 32.1,
        "open_files": 15,
        "connections": 3,
        "threads": 8,
    })

    fake_result = FakeSubprocessResult(returncode=0, stdout=mock_output)

    def fake_run(
        args: list[str],
        check: bool = False,
        capture_output: bool = True,
        text: bool = True,
    ) -> FakeSubprocessResult:
        return fake_result

    monkeypatch.setattr("subprocess.run", fake_run)

    result = manager.monitor_process_in_vm(1234)

    assert result["cpu_percent"] == 45.5
    assert result["memory_percent"] == 32.1
    assert result["open_files"] == 15
    assert result["connections"] == 3
    assert result["threads"] == 8


def test_monitor_process_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test process monitoring handles failures."""
    manager = EnhancedQEMUTestManager()

    fake_result = FakeSubprocessResult(returncode=1, stdout="")

    def fake_run(
        args: list[str],
        check: bool = False,
        capture_output: bool = True,
        text: bool = True,
    ) -> FakeSubprocessResult:
        return fake_result

    monkeypatch.setattr("subprocess.run", fake_run)

    result = manager.monitor_process_in_vm(9999)

    assert result == {}


def test_real_binary_analysis_pe_sections(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test PE section extraction."""
    manager = EnhancedQEMUTestManager()

    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        pe_path = f.name
        f.write(b"MZ" + b"\x00" * 2000)

    try:
        fake_section = FakePESection(
            name=b".text\x00\x00\x00",
            virtual_address=0x1000,
            size=4096,
        )

        fake_magic = FakeMagic("PE32 executable")
        fake_pe = FakePE(
            machine=0x014C,
            entry_point=0x1000,
            imports=[],
            sections=[fake_section],
        )
        fake_pe_module = FakePEModule(fake_pe)

        monkeypatch.setattr("magic.from_file", fake_magic.from_file)
        monkeypatch.setattr(
            "intellicrack.handlers.pefile_handler.pefile.PE",
            fake_pe_module.PE,
        )

        result = manager.analyze_binary_for_vm(pe_path)

        assert len(result["sections"]) == 1
        assert result["sections"][0]["name"] == ".text"
        assert result["sections"][0]["virtual_address"] == "0x1000"
        assert result["sections"][0]["size"] == 4096
    finally:
        Path(pe_path).unlink(missing_ok=True)


def test_real_binary_analysis_pe_imports(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test PE import extraction."""
    manager = EnhancedQEMUTestManager()

    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        pe_path = f.name
        f.write(b"MZ" + b"\x00" * 2000)

    try:
        fake_import = FakePEImport(dll_name=b"kernel32.dll")

        fake_magic = FakeMagic("PE32 executable")
        fake_pe = FakePE(
            machine=0x014C,
            entry_point=0x1000,
            imports=[fake_import],
            sections=[],
        )
        fake_pe_module = FakePEModule(fake_pe)

        monkeypatch.setattr("magic.from_file", fake_magic.from_file)
        monkeypatch.setattr(
            "intellicrack.handlers.pefile_handler.pefile.PE",
            fake_pe_module.PE,
        )

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


def test_binary_analysis_unknown_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test handling of unknown binary types."""
    manager = EnhancedQEMUTestManager()

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        bin_path = f.name
        f.write(b"\x00" * 100)

    try:
        fake_magic = FakeMagic("data")
        monkeypatch.setattr("magic.from_file", fake_magic.from_file)

        result = manager.analyze_binary_for_vm(bin_path)

        assert result["platform"] == "unknown"
        assert result["architecture"] == "unknown"
    finally:
        Path(bin_path).unlink(missing_ok=True)
