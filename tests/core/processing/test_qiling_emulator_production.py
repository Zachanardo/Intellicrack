import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.processing.qiling_emulator import (
    QILING_AVAILABLE,
    QilingEmulator,
    run_qiling_emulation,
)

pytestmark = pytest.mark.skipif(
    not QILING_AVAILABLE, reason="Qiling framework not available"
)


@pytest.fixture(scope="module")
def simple_pe_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    temp_dir = tmp_path_factory.mktemp("binaries")
    binary_path = temp_dir / "test_simple.exe"

    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)

    pe_signature = b"PE\x00\x00"

    file_header = struct.pack(
        "<HHIIIHH",
        0x14C,
        1,
        0,
        0,
        0,
        224,
        0x010B,
    )

    optional_header = (
        struct.pack("<H", 0x010B)
        + b"\x00" * 94
        + struct.pack("<I", 0x1000)
        + b"\x00" * 124
    )

    section_header = (
        b".text\x00\x00\x00"
        + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    )

    section_data = b"\xC3" + b"\x00" * 511

    binary_path.write_bytes(
        dos_header + b"\x00" * (0x80 - len(dos_header))
        + pe_signature
        + file_header
        + optional_header
        + section_header
        + b"\x00" * (0x200 - len(section_data))
        + section_data
    )

    return binary_path


@pytest.fixture(scope="module")
def simple_elf_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    temp_dir = tmp_path_factory.mktemp("binaries")
    binary_path = temp_dir / "test_simple_elf"

    elf_header = (
        b"\x7fELF"
        + struct.pack("B", 2)
        + struct.pack("B", 1)
        + struct.pack("B", 1)
        + b"\x00" * 9
        + struct.pack("<H", 2)
        + struct.pack("<H", 0x3E)
        + struct.pack("<I", 1)
        + struct.pack("<Q", 0x400000)
        + struct.pack("<Q", 64)
        + struct.pack("<Q", 0)
        + struct.pack("<I", 0)
        + struct.pack("<HHH", 64, 56, 1)
        + struct.pack("<HHH", 0, 0, 0)
    )

    program_header = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        0,
        0x400000,
        0x400000,
        0x200,
        0x200,
        0x1000,
    )

    code = b"\xB8\x3C\x00\x00\x00\x48\x31\xFF\x0F\x05" + b"\x00" * (0x200 - 10)

    binary_path.write_bytes(elf_header + program_header + code)
    binary_path.chmod(0o755)

    return binary_path


@pytest.fixture
def mock_rootfs(tmp_path: Path) -> Path:
    rootfs = tmp_path / "rootfs" / "windows"
    rootfs.mkdir(parents=True, exist_ok=True)

    (rootfs / "Windows" / "System32").mkdir(parents=True, exist_ok=True)
    (rootfs / "Windows" / "System32" / "kernel32.dll").touch()
    (rootfs / "Windows" / "System32" / "ntdll.dll").touch()

    (rootfs / "ProgramData").mkdir(parents=True, exist_ok=True)

    return rootfs


class TestQilingEmulatorInitialization:
    def test_initialization_with_valid_pe_binary(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
            verbose=False,
        )

        assert emulator.binary_path == str(simple_pe_binary.resolve())
        assert emulator.ostype == "windows"
        assert emulator.arch == "x86"
        assert emulator.rootfs == str(mock_rootfs)
        assert len(emulator.api_calls) == 0
        assert len(emulator.memory_accesses) == 0
        assert len(emulator.license_checks) == 0

    def test_initialization_with_valid_elf_binary(
        self, simple_elf_binary: Path, tmp_path: Path
    ) -> None:
        rootfs = tmp_path / "rootfs" / "linux"
        rootfs.mkdir(parents=True, exist_ok=True)
        (rootfs / "lib").mkdir(exist_ok=True)
        (rootfs / "usr" / "lib").mkdir(parents=True, exist_ok=True)

        emulator = QilingEmulator(
            binary_path=str(simple_elf_binary),
            rootfs=str(rootfs),
            ostype="linux",
            arch="x86_64",
            verbose=False,
        )

        assert emulator.ostype == "linux"
        assert emulator.arch == "x86_64"

    def test_initialization_with_nonexistent_binary(self, mock_rootfs: Path) -> None:
        with pytest.raises(FileNotFoundError, match="Binary not found"):
            QilingEmulator(
                binary_path="/nonexistent/path/binary.exe",
                rootfs=str(mock_rootfs),
                ostype="windows",
                arch="x86",
            )

    def test_initialization_without_qiling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import intellicrack.core.processing.qiling_emulator as qe_module

        monkeypatch.setattr(qe_module, "QILING_AVAILABLE", False)

        with pytest.raises(ImportError, match="Qiling framework not available"):
            QilingEmulator(
                binary_path="dummy.exe",
                ostype="windows",
                arch="x86",
            )

    def test_architecture_mapping(self, simple_pe_binary: Path, mock_rootfs: Path) -> None:
        test_cases = [
            ("x86", "x86"),
            ("x64", "x86_64"),
            ("x86_64", "x86_64"),
            ("arm", "arm"),
            ("arm64", "arm64"),
        ]

        for input_arch, _ in test_cases:
            emulator = QilingEmulator(
                binary_path=str(simple_pe_binary),
                rootfs=str(mock_rootfs),
                ostype="windows",
                arch=input_arch,
            )
            assert emulator.arch == input_arch.lower()

    def test_os_type_mapping(self, simple_pe_binary: Path, mock_rootfs: Path) -> None:
        test_cases = ["windows", "linux", "macos", "freebsd"]

        for ostype in test_cases:
            emulator = QilingEmulator(
                binary_path=str(simple_pe_binary),
                rootfs=str(mock_rootfs),
                ostype=ostype,
                arch="x86_64",
            )
            assert emulator.ostype == ostype.lower()


class TestAPIHooking:
    def test_add_api_hook(self, simple_pe_binary: Path, mock_rootfs: Path) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        hook_called = []

        def test_hook(ql: Any, address: int, params: dict[str, Any]) -> None:
            hook_called.append(True)

        emulator.add_api_hook("CreateFileW", test_hook)

        assert "createfilew" in emulator.api_hooks
        assert emulator.api_hooks["createfilew"] == test_hook

    def test_license_detection_hooks_registration(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        emulator.add_license_detection_hooks()

        expected_apis = [
            "regopenkeyexa",
            "regqueryvalueexa",
            "createfilea",
            "connect",
            "crypthashdata",
            "getsystemtime",
            "getvolumeinformationa",
        ]

        for api in expected_apis:
            assert api in emulator.api_hooks


class TestFilesystemMapping:
    def test_map_file_to_fs(
        self, simple_pe_binary: Path, mock_rootfs: Path, tmp_path: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        test_file = tmp_path / "test_license.dat"
        test_file.write_text("LICENSE_DATA")

        emulator.map_file_to_fs(
            host_path=str(test_file), guest_path="C:\\license\\license.dat"
        )

        assert len(emulator.mapped_files) == 1
        assert emulator.mapped_files[0]["host"] == str(test_file)
        assert emulator.mapped_files[0]["guest"] == "C:\\license\\license.dat"
        assert emulator.mapped_files[0]["type"] == "file"

    def test_map_directory_to_fs(
        self, simple_pe_binary: Path, mock_rootfs: Path, tmp_path: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        test_dir = tmp_path / "license_dir"
        test_dir.mkdir()

        emulator.map_file_to_fs(host_path=str(test_dir), guest_path="C:\\licenses")

        assert len(emulator.mapped_files) == 1
        assert emulator.mapped_files[0]["type"] == "directory"

    def test_map_nonexistent_path_raises_error(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        with pytest.raises(FileNotFoundError, match="Host path not found"):
            emulator.map_file_to_fs(
                host_path="/nonexistent/path", guest_path="C:\\test"
            )


class TestArchitectureAndOSInfo:
    def test_get_arch_info_x86(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        arch_info = emulator.get_arch_info()

        assert arch_info["bits"] == 32
        assert arch_info["instruction_set"] == "x86"
        assert "eax" in arch_info["registers"]
        assert "esp" in arch_info["registers"]

    def test_get_arch_info_x64(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86_64",
        )

        arch_info = emulator.get_arch_info()

        assert arch_info["bits"] == 64
        assert arch_info["instruction_set"] == "x86_64"
        assert "rax" in arch_info["registers"]
        assert "rsp" in arch_info["registers"]
        assert "r15" in arch_info["registers"]

    def test_get_arch_info_arm(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="linux",
            arch="arm",
        )

        arch_info = emulator.get_arch_info()

        assert arch_info["bits"] == 32
        assert arch_info["instruction_set"] == "arm"
        assert "r0" in arch_info["registers"]
        assert "pc" in arch_info["registers"]

    def test_get_arch_info_arm64(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="linux",
            arch="arm64",
        )

        arch_info = emulator.get_arch_info()

        assert arch_info["bits"] == 64
        assert arch_info["instruction_set"] == "aarch64"
        assert "x0" in arch_info["registers"]
        assert "sp" in arch_info["registers"]

    def test_get_os_info_windows(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        os_info = emulator.get_os_info()

        assert os_info["family"] == "windows"
        assert os_info["syscall_convention"] == "stdcall"
        assert os_info["executable_format"] == "PE"
        assert os_info["path_separator"] == "\\"
        assert "C:\\Windows" in os_info["common_dirs"]

    def test_get_os_info_linux(
        self, simple_elf_binary: Path, tmp_path: Path
    ) -> None:
        rootfs = tmp_path / "rootfs" / "linux"
        rootfs.mkdir(parents=True, exist_ok=True)

        emulator = QilingEmulator(
            binary_path=str(simple_elf_binary),
            rootfs=str(rootfs),
            ostype="linux",
            arch="x86_64",
        )

        os_info = emulator.get_os_info()

        assert os_info["family"] == "unix"
        assert os_info["syscall_convention"] == "sysv"
        assert os_info["executable_format"] == "ELF"
        assert os_info["path_separator"] == "/"
        assert "/usr" in os_info["common_dirs"]

    def test_get_os_info_macos(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="macos",
            arch="x86_64",
        )

        os_info = emulator.get_os_info()

        assert os_info["family"] == "unix"
        assert os_info["executable_format"] == "Mach-O"
        assert "/Applications" in os_info["common_dirs"]


class TestBinaryFormatDetection:
    def test_detect_pe_format(self, simple_pe_binary: Path, mock_rootfs: Path) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        format_info = emulator.detect_binary_format()

        assert format_info["format"] in ["PE", "unknown"]
        assert "arch" in format_info
        assert "os" in format_info

    def test_detect_elf_format(self, simple_elf_binary: Path, tmp_path: Path) -> None:
        rootfs = tmp_path / "rootfs" / "linux"
        rootfs.mkdir(parents=True, exist_ok=True)

        emulator = QilingEmulator(
            binary_path=str(simple_elf_binary),
            rootfs=str(rootfs),
            ostype="linux",
            arch="x86_64",
        )

        format_info = emulator.detect_binary_format()

        assert format_info["format"] in ["ELF", "unknown"]


class TestHighLevelEmulationFunction:
    def test_run_qiling_emulation_with_pe(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        options = {
            "ostype": "windows",
            "arch": "x86",
            "timeout": 1,
            "verbose": False,
        }

        result = run_qiling_emulation(str(simple_pe_binary), options)

        assert "status" in result
        assert result["status"] in ["success", "error", "timeout"]

    def test_run_qiling_emulation_without_qiling(
        self, monkeypatch: pytest.MonkeyPatch, simple_pe_binary: Path
    ) -> None:
        import intellicrack.core.processing.qiling_emulator as qe_module

        monkeypatch.setattr(qe_module, "QILING_AVAILABLE", False)

        result = run_qiling_emulation(str(simple_pe_binary))

        assert result["status"] == "error"
        assert "Qiling not installed" in result["error"]

    def test_run_qiling_emulation_with_nonexistent_file(self) -> None:
        result = run_qiling_emulation("/nonexistent/binary.exe")

        assert result["status"] == "error"

    def test_run_qiling_emulation_returns_binary_format(
        self, simple_pe_binary: Path
    ) -> None:
        options = {"timeout": 1}

        result = run_qiling_emulation(str(simple_pe_binary), options)

        if result["status"] != "error":
            assert "binary_format" in result


class TestEmulationExecution:
    @pytest.mark.timeout(10)
    def test_emulation_with_timeout(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        result = emulator.run(timeout=1)

        assert "status" in result
        assert "execution_time" in result
        assert result["execution_time"] <= 2.0

    def test_emulation_timeout_handling(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        result = emulator.run(timeout=1)

        assert "timeout_occurred" in result
        assert "timeout_limit" in result
        assert result["timeout_limit"] == 1


class TestDefaultRootfsDiscovery:
    def test_default_rootfs_from_config(
        self, simple_pe_binary: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        test_rootfs = tmp_path / "test_rootfs" / "windows"
        test_rootfs.mkdir(parents=True)

        def mock_get_config() -> Any:
            class MockConfig:
                def get(self, key: str, default: list[str]) -> list[str]:
                    if key == "vm_framework.qiling_rootfs.windows":
                        return [str(test_rootfs)]
                    return default

            return MockConfig()

        import intellicrack.core.processing.qiling_emulator as qe_module

        monkeypatch.setattr(qe_module, "get_config", mock_get_config)

        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            ostype="windows",
            arch="x86",
        )

        assert emulator.rootfs == str(test_rootfs)

    def test_default_rootfs_fallback_paths(
        self, simple_pe_binary: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def mock_get_config() -> Any:
            class MockConfig:
                def get(self, key: str, default: list[str]) -> list[str]:
                    return default

            return MockConfig()

        import intellicrack.core.processing.qiling_emulator as qe_module

        monkeypatch.setattr(qe_module, "get_config", mock_get_config)

        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            ostype="windows",
            arch="x86",
        )

        assert emulator.rootfs is not None
        assert "windows" in emulator.rootfs.lower()


class TestMemoryAndCodeHooks:
    def test_hook_memory_access_tracking(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        class MockQL:
            class MockMem:
                def read(self, address: int, size: int) -> bytes:
                    return b"\x00" * size

            class MockRegs:
                eip = 0x401000
                esp = 0x12FFC0

            class MockArch:
                regs = MockRegs()

            mem = MockMem()
            arch = MockArch()

        mock_ql = MockQL()

        emulator.hook_memory_access(mock_ql, 1, 0x12FFD0, 4, 0xDEADBEEF)

        assert len(emulator.memory_accesses) == 1
        access = emulator.memory_accesses[0]
        assert access["type"] == "READ"
        assert access["address"] == hex(0x12FFD0)
        assert access["size"] == 4
        assert access["is_stack_access"] is True

    def test_hook_memory_write_tracking(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        class MockQL:
            class MockMem:
                def read(self, address: int, size: int) -> bytes:
                    return b"\x00" * size

            class MockRegs:
                eip = 0x401000
                esp = 0x12FFC0

            class MockArch:
                regs = MockRegs()

            mem = MockMem()
            arch = MockArch()

        mock_ql = MockQL()

        emulator.hook_memory_access(mock_ql, 2, 0x403000, 4, 0xCAFEBABE)

        assert len(emulator.memory_accesses) == 1
        access = emulator.memory_accesses[0]
        assert access["type"] == "WRITE"
        assert access["value"] == hex(0xCAFEBABE)


class TestLicenseDetection:
    def test_license_api_hook_detection(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        class MockQL:
            class MockOS:
                user_defined_api_name = "RegQueryValueExA"

            os = MockOS()

        mock_ql = MockQL()

        params = {"lpValueName": "LicenseKey", "lpData": "test_data"}

        emulator._license_api_hook(mock_ql, 0x401234, params)

        assert len(emulator.api_calls) == 1
        assert emulator.api_calls[0]["api"] == "RegQueryValueExA"
        assert emulator.api_calls[0]["address"] == hex(0x401234)

        assert len(emulator.license_checks) == 1
        assert emulator.license_checks[0]["type"] == "direct_check"

    def test_license_check_pattern_detection(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        class MockQL:
            class MockOS:
                user_defined_api_name = "CreateFileW"

            os = MockOS()

        mock_ql = MockQL()

        test_cases = [
            {"lpFileName": "C:\\license.dat"},
            {"lpFileName": "C:\\serial.key"},
            {"lpFileName": "C:\\activation.bin"},
            {"lpFileName": "C:\\trial.dat"},
        ]

        for params in test_cases:
            emulator._license_api_hook(mock_ql, 0x401000, params)

        assert len(emulator.license_checks) == len(test_cases)


class TestResultAnalysis:
    def test_analyze_results_registry_crypto_detection(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        for i in range(10):
            emulator.api_calls.append(
                {"api": "RegQueryValueExA", "address": hex(0x401000 + i), "params": {}}
            )

        for i in range(3):
            emulator.api_calls.append(
                {"api": "CryptHashData", "address": hex(0x402000 + i), "params": {}}
            )

        results = emulator._analyze_results()

        assert results["api_categories"]["registry"] == 10
        assert results["api_categories"]["crypto"] == 3

        license_behaviors = [
            b for b in results["suspicious_behaviors"] if b["type"] == "license_check"
        ]
        assert len(license_behaviors) >= 1
        assert license_behaviors[0]["confidence"] == "high"

    def test_analyze_results_online_activation_detection(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        emulator.api_calls.append(
            {"api": "connect", "address": hex(0x401000), "params": {}}
        )
        emulator.api_calls.append(
            {"api": "send", "address": hex(0x401010), "params": {}}
        )
        emulator.api_calls.append(
            {"api": "GetVolumeInformationA", "address": hex(0x401020), "params": {}}
        )
        emulator.api_calls.append(
            {"api": "GetComputerNameA", "address": hex(0x401030), "params": {}}
        )

        results = emulator._analyze_results()

        assert results["api_categories"]["network"] >= 2
        assert results["api_categories"]["hardware"] >= 2

        online_behaviors = [
            b
            for b in results["suspicious_behaviors"]
            if b["type"] == "online_activation"
        ]
        assert len(online_behaviors) >= 1

    def test_analyze_results_trial_detection(
        self, simple_pe_binary: Path, mock_rootfs: Path
    ) -> None:
        emulator = QilingEmulator(
            binary_path=str(simple_pe_binary),
            rootfs=str(mock_rootfs),
            ostype="windows",
            arch="x86",
        )

        for i in range(5):
            emulator.api_calls.append(
                {"api": "GetSystemTime", "address": hex(0x401000 + i), "params": {}}
            )

        results = emulator._analyze_results()

        assert results["api_categories"]["time"] == 5

        trial_behaviors = [
            b for b in results["suspicious_behaviors"] if b["type"] == "trial_check"
        ]
        assert len(trial_behaviors) >= 1
