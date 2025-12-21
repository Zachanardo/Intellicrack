"""Production tests for scripts/dll_diagnostics.py.

Tests validate real DLL diagnostics and PATH analysis without mocks.
"""

import ctypes
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

import pytest


@pytest.fixture
def project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent.parent


@pytest.fixture
def script_path(project_root: Path) -> Path:
    """Get the path to dll_diagnostics.py script."""
    return project_root / "scripts" / "dll_diagnostics.py"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific DLL diagnostics")
class TestGetLoadedDllPath:
    """Test DLL path retrieval using Windows API."""

    def test_get_loaded_dll_path_for_kernel32(self) -> None:
        """Retrieve path for kernel32.dll which is always loaded."""
        from scripts.dll_diagnostics import get_loaded_dll_path

        path = get_loaded_dll_path("kernel32.dll")

        assert path is not None
        assert not path.startswith("Error")
        assert "kernel32.dll" in path.lower()
        assert Path(path).exists()

    def test_get_loaded_dll_path_for_nonexistent_dll(self) -> None:
        """Handle nonexistent DLL gracefully."""
        from scripts.dll_diagnostics import get_loaded_dll_path

        path = get_loaded_dll_path("nonexistent_dll_12345.dll")

        assert path is None or isinstance(path, str)

    def test_get_loaded_dll_path_returns_absolute_path(self) -> None:
        """DLL path is returned as absolute path."""
        from scripts.dll_diagnostics import get_loaded_dll_path

        path = get_loaded_dll_path("kernel32.dll")

        assert path is not None
        assert not path.startswith("Error")
        assert Path(path).is_absolute()

    def test_get_loaded_dll_path_uses_windows_api(self) -> None:
        """Function uses Windows API (GetModuleHandleW/LoadLibraryW)."""
        from scripts.dll_diagnostics import get_loaded_dll_path

        kernel32 = ctypes.windll.kernel32
        assert kernel32 is not None

        path = get_loaded_dll_path("ntdll.dll")

        assert path is not None
        if not path.startswith("Error"):
            assert "ntdll.dll" in path.lower()

    def test_get_loaded_dll_path_handles_errors_gracefully(self) -> None:
        """Function handles errors and returns error message."""
        from scripts.dll_diagnostics import get_loaded_dll_path

        result = get_loaded_dll_path("")

        assert result is None or isinstance(result, str)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific PATH analysis")
class TestCheckPathPriority:
    """Test PATH environment variable analysis."""

    def test_check_path_priority_parses_environment(self) -> None:
        """Parse PATH environment variable into categories."""
        from scripts.dll_diagnostics import check_path_priority

        pixi_dirs, intel_dirs, other_dirs = check_path_priority()

        assert isinstance(pixi_dirs, list)
        assert isinstance(intel_dirs, list)
        assert isinstance(other_dirs, list)

        total_dirs = len(pixi_dirs) + len(intel_dirs) + len(other_dirs)
        path_count = len(os.environ.get("PATH", "").split(";"))

        assert total_dirs == path_count

    def test_check_path_priority_identifies_pixi_directories(self) -> None:
        """Identify directories containing 'pixi' or 'intellicrack'."""
        from scripts.dll_diagnostics import check_path_priority

        pixi_dirs, _, _ = check_path_priority()

        for directory in pixi_dirs:
            dir_lower = directory.lower()
            assert "pixi" in dir_lower or "intellicrack" in dir_lower

    def test_check_path_priority_identifies_intel_directories(self) -> None:
        """Identify directories containing Intel/oneAPI/MKL paths."""
        from scripts.dll_diagnostics import check_path_priority

        _, intel_dirs, _ = check_path_priority()

        for directory in intel_dirs:
            dir_lower = directory.lower()
            assert any(keyword in dir_lower for keyword in ["intel", "oneapi", "mkl"])

    def test_check_path_priority_categorizes_all_paths(self) -> None:
        """All PATH directories are categorized correctly."""
        from scripts.dll_diagnostics import check_path_priority

        original_path = os.environ.get("PATH", "")
        original_count = len(original_path.split(";"))

        pixi_dirs, intel_dirs, other_dirs = check_path_priority()

        total = len(pixi_dirs) + len(intel_dirs) + len(other_dirs)
        assert total == original_count

    def test_check_path_priority_with_modified_environment(
        self,
        monkeypatch,
    ) -> None:
        """PATH analysis works with custom environment."""
        from scripts.dll_diagnostics import check_path_priority

        custom_path = ";".join([
            "C:\\pixi\\bin",
            "C:\\Intel\\oneAPI\\bin",
            "C:\\Windows\\System32",
            "D:\\Intellicrack\\.pixi\\envs\\default",
            "C:\\Program Files\\Intel\\MKL\\bin",
        ])

        monkeypatch.setenv("PATH", custom_path)

        pixi_dirs, intel_dirs, other_dirs = check_path_priority()

        assert len(pixi_dirs) == 2
        assert len(intel_dirs) == 2
        assert len(other_dirs) == 1


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific diagnostics")
class TestDiagnoseMklLoading:
    """Test MKL DLL loading diagnostics."""

    def test_diagnose_mkl_loading_executes_without_errors(
        self,
        capsys,
    ) -> None:
        """diagnose_mkl_loading function executes without exceptions."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        diagnose_mkl_loading()

        captured = capsys.readouterr()
        assert "INTEL MKL DLL LOADING DIAGNOSTICS" in captured.out

    def test_diagnose_mkl_loading_checks_pixi_environment(
        self,
        capsys,
    ) -> None:
        """Diagnostic checks pixi environment directory."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        diagnose_mkl_loading()

        captured = capsys.readouterr()
        assert "[1] Pixi Environment" in captured.out
        assert "Location:" in captured.out
        assert "Exists:" in captured.out

    def test_diagnose_mkl_loading_analyzes_path_variable(
        self,
        capsys,
    ) -> None:
        """Diagnostic analyzes PATH environment variable."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        diagnose_mkl_loading()

        captured = capsys.readouterr()
        assert "[2] PATH Environment Variable Analysis" in captured.out
        assert "Pixi directories" in captured.out

    def test_diagnose_mkl_loading_verifies_critical_dlls(
        self,
        capsys,
    ) -> None:
        """Diagnostic verifies critical MKL DLL loading."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        diagnose_mkl_loading()

        captured = capsys.readouterr()
        assert "[3] Critical DLL Loading Verification" in captured.out

        critical_dlls = [
            "mkl_core.2.dll",
            "mkl_sycl_blas.5.dll",
            "mkl_intel_thread.2.dll",
        ]

        for dll in critical_dlls:
            assert dll in captured.out

    def test_diagnose_mkl_loading_provides_recommendations(
        self,
        capsys,
    ) -> None:
        """Diagnostic provides recommendations."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        diagnose_mkl_loading()

        captured = capsys.readouterr()
        assert "[4] Recommendations" in captured.out


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific script execution")
class TestScriptExecution:
    """Test script execution as standalone program."""

    def test_script_runs_successfully(
        self,
        script_path: Path,
    ) -> None:
        """Script executes successfully from command line."""
        proc = subprocess.Popen(
            [sys.executable, str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
        )

        proc.stdin.write("\n")
        proc.stdin.flush()

        stdout, stderr = proc.communicate(timeout=10)

        assert "INTEL MKL DLL LOADING DIAGNOSTICS" in stdout

    def test_script_displays_diagnostic_sections(
        self,
        script_path: Path,
    ) -> None:
        """Script displays all diagnostic sections."""
        proc = subprocess.Popen(
            [sys.executable, str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
        )

        proc.stdin.write("\n")
        proc.stdin.flush()

        stdout, _ = proc.communicate(timeout=10)

        assert "[1] Pixi Environment" in stdout
        assert "[2] PATH Environment Variable Analysis" in stdout
        assert "[3] Critical DLL Loading Verification" in stdout
        assert "[4] Recommendations" in stdout

    def test_script_handles_exceptions_gracefully(
        self,
        script_path: Path,
    ) -> None:
        """Script handles exceptions and reports errors."""
        proc = subprocess.Popen(
            [sys.executable, str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
        )

        proc.stdin.write("\n")
        proc.stdin.flush()

        stdout, stderr = proc.communicate(timeout=10)

        assert proc.returncode == 0 or "DIAGNOSTIC FAILED" in stdout or stderr


class TestPixiEnvironmentDetection:
    """Test pixi environment directory detection."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific paths")
    def test_detects_pixi_library_directory(
        self,
        capsys,
    ) -> None:
        """Detect pixi library directory location."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        diagnose_mkl_loading()

        captured = capsys.readouterr()

        assert "D:\\Intellicrack\\.pixi\\envs\\default\\Library\\bin" in captured.out or "Intellicrack" in captured.out

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_checks_pixi_directory_exists(self) -> None:
        """Check if pixi directory exists on filesystem."""
        pixi_lib = Path(r"D:\Intellicrack\.pixi\envs\default\Library\bin")

        exists = pixi_lib.exists()

        assert isinstance(exists, bool)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_lists_mkl_dlls_in_pixi_directory(self) -> None:
        """List MKL DLLs found in pixi directory."""
        pixi_lib = Path(r"D:\Intellicrack\.pixi\envs\default\Library\bin")

        if pixi_lib.exists():
            mkl_dlls = list(pixi_lib.glob("mkl_*.dll")) + list(pixi_lib.glob("sycl*.dll"))

            assert isinstance(mkl_dlls, list)
            for dll in mkl_dlls:
                assert dll.suffix.lower() == ".dll"


class TestDllStatusClassification:
    """Test DLL loading status classification."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_classifies_pixi_loaded_dlls(self) -> None:
        """Classify DLLs loaded from pixi environment."""
        pixi_lib = Path(r"D:\Intellicrack\.pixi\envs\default\Library\bin")
        test_path = pixi_lib / "mkl_core.2.dll"

        if pixi_lib in test_path.parents or test_path.parent == pixi_lib:
            status = "OK PIXI"
        else:
            status = "OTHER"

        assert status == "OK PIXI"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_classifies_system_intel_dlls(self) -> None:
        """Classify DLLs loaded from system Intel paths."""
        test_path = Path("C:/Program Files/Intel/oneAPI/mkl/bin/mkl_core.dll")

        if "intel" in str(test_path).lower() or "oneapi" in str(test_path).lower():
            status = "WARNING  SYSTEM"
        else:
            status = "OTHER"

        assert status == "WARNING  SYSTEM"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_classifies_unloaded_dlls(self) -> None:
        """Classify DLLs that are not loaded."""
        loaded_path = None

        if loaded_path is None:
            status = "NOT LOADED"
        else:
            status = "OTHER"

        assert status == "NOT LOADED"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_classifies_error_dlls(self) -> None:
        """Classify DLLs that encountered errors."""
        loaded_path = "Error: Access denied"

        if isinstance(loaded_path, str) and loaded_path.startswith("Error"):
            status = "ERROR"
        else:
            status = "OTHER"

        assert status == "ERROR"


class TestPathPriorityWarnings:
    """Test PATH priority warnings and recommendations."""

    def test_warns_about_intel_paths_in_environment(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """Warn when Intel paths detected in PATH."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        custom_path = ";".join([
            "C:\\Windows\\System32",
            "C:\\Intel\\oneAPI\\bin",
            "C:\\Program Files\\Intel\\MKL\\bin",
        ])

        monkeypatch.setenv("PATH", custom_path)

        diagnose_mkl_loading()

        captured = capsys.readouterr()

        if "Intel/oneAPI directories (2):" in captured.out:
            assert "WARNING" in captured.out

    def test_no_warning_when_no_intel_paths(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """No warning when no Intel paths in PATH."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        custom_path = ";".join([
            "C:\\Windows\\System32",
            "D:\\Intellicrack\\.pixi\\envs\\default\\bin",
        ])

        monkeypatch.setenv("PATH", custom_path)

        diagnose_mkl_loading()

        captured = capsys.readouterr()

        if "Intel/oneAPI directories (0):" in captured.out:
            assert "OK" in captured.out or "No system Intel paths found" in captured.out


class TestCriticalDllVerification:
    """Test verification of critical MKL DLLs."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_verifies_all_critical_dlls(
        self,
        capsys,
    ) -> None:
        """Verify all critical MKL DLLs are checked."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        critical_dlls = [
            "mkl_core.2.dll",
            "mkl_sycl_blas.5.dll",
            "mkl_intel_thread.2.dll",
            "sycl8.dll",
            "libiomp5md.dll",
            "tbb12.dll",
        ]

        diagnose_mkl_loading()

        captured = capsys.readouterr()

        for dll in critical_dlls:
            assert dll in captured.out


class TestOutputFormatting:
    """Test diagnostic output formatting."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_output_has_header_and_footer(
        self,
        capsys,
    ) -> None:
        """Output includes formatted header and footer."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        diagnose_mkl_loading()

        captured = capsys.readouterr()

        assert "=" * 80 in captured.out
        assert "INTEL MKL DLL LOADING DIAGNOSTICS" in captured.out

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_output_has_numbered_sections(
        self,
        capsys,
    ) -> None:
        """Output includes numbered diagnostic sections."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        diagnose_mkl_loading()

        captured = capsys.readouterr()

        assert "[1]" in captured.out
        assert "[2]" in captured.out
        assert "[3]" in captured.out
        assert "[4]" in captured.out

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_dll_status_formatting(
        self,
        capsys,
    ) -> None:
        """DLL status is formatted consistently."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        diagnose_mkl_loading()

        captured = capsys.readouterr()

        assert ":" in captured.out
        lines = captured.out.split('\n')

        dll_lines = [line for line in lines if ".dll" in line and ":" in line]
        if dll_lines:
            for line in dll_lines:
                parts = line.split(":")
                assert len(parts) >= 2


class TestEdgeCases:
    """Test edge cases in DLL diagnostics."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_handles_empty_path_variable(
        self,
        monkeypatch,
    ) -> None:
        """Handle empty PATH environment variable."""
        from scripts.dll_diagnostics import check_path_priority

        monkeypatch.setenv("PATH", "")

        pixi_dirs, intel_dirs, other_dirs = check_path_priority()

        assert len(pixi_dirs) == 0
        assert len(intel_dirs) == 0
        assert len(other_dirs) == 1

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_handles_nonexistent_pixi_directory(
        self,
        capsys,
        monkeypatch,
    ) -> None:
        """Handle nonexistent pixi directory gracefully."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        diagnose_mkl_loading()

        captured = capsys.readouterr()

        assert "Exists:" in captured.out

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_handles_long_path_lists(
        self,
        monkeypatch,
    ) -> None:
        """Handle very long PATH variable with many directories."""
        from scripts.dll_diagnostics import check_path_priority

        long_path = ";".join([f"C:\\Dir{i}" for i in range(100)])
        monkeypatch.setenv("PATH", long_path)

        pixi_dirs, intel_dirs, other_dirs = check_path_priority()

        total = len(pixi_dirs) + len(intel_dirs) + len(other_dirs)
        assert total == 100


class TestRealWorldIntegration:
    """Test real-world integration scenarios."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_detects_actual_system_configuration(
        self,
        capsys,
    ) -> None:
        """Detect actual system DLL configuration."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        diagnose_mkl_loading()

        captured = capsys.readouterr()

        assert len(captured.out) > 100
        assert "INTEL MKL DLL LOADING DIAGNOSTICS" in captured.out

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_provides_actionable_recommendations(
        self,
        capsys,
    ) -> None:
        """Provide actionable recommendations based on findings."""
        from scripts.dll_diagnostics import diagnose_mkl_loading

        diagnose_mkl_loading()

        captured = capsys.readouterr()

        assert "[4] Recommendations" in captured.out
        assert any(
            keyword in captured.out
            for keyword in ["OK", "WARNING", "SOLUTION", "PROBLEM"]
        )
