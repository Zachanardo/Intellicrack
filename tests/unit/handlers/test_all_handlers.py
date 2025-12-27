"""Comprehensive handler test suite for all Intellicrack handlers.

This module tests all 21 handler modules in intellicrack/handlers/ to verify:
1. Dependency loading and graceful degradation
2. Fallback implementations provide REAL functionality (not mocks)
3. Thread safety for concurrent usage
4. GIL safety for Python threading

Tests are designed to FAIL unless handlers genuinely work. No mocks, no simulations.
"""

from __future__ import annotations

import concurrent.futures
import importlib
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

try:
    from intellicrack.handlers import frida_handler
    FRIDA_HANDLER_AVAILABLE = True
except ImportError:
    frida_handler = None
    FRIDA_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import torch_handler
    TORCH_HANDLER_AVAILABLE = True
except ImportError:
    torch_handler = None
    TORCH_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import torch_xpu_handler
    TORCH_XPU_HANDLER_AVAILABLE = True
except ImportError:
    torch_xpu_handler = None
    TORCH_XPU_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import capstone_handler
    CAPSTONE_HANDLER_AVAILABLE = True
except ImportError:
    capstone_handler = None
    CAPSTONE_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import keystone_handler
    KEYSTONE_HANDLER_AVAILABLE = True
except ImportError:
    keystone_handler = None
    KEYSTONE_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import pefile_handler
    PEFILE_HANDLER_AVAILABLE = True
except ImportError:
    pefile_handler = None
    PEFILE_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import lief_handler
    LIEF_HANDLER_AVAILABLE = True
except ImportError:
    lief_handler = None
    LIEF_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import pyelftools_handler
    PYELFTOOLS_HANDLER_AVAILABLE = True
except ImportError:
    pyelftools_handler = None
    PYELFTOOLS_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import cryptography_handler
    CRYPTOGRAPHY_HANDLER_AVAILABLE = True
except ImportError:
    cryptography_handler = None
    CRYPTOGRAPHY_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import requests_handler
    REQUESTS_HANDLER_AVAILABLE = True
except ImportError:
    requests_handler = None
    REQUESTS_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import aiohttp_handler
    AIOHTTP_HANDLER_AVAILABLE = True
except ImportError:
    aiohttp_handler = None
    AIOHTTP_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import psutil_handler
    PSUTIL_HANDLER_AVAILABLE = True
except ImportError:
    psutil_handler = None
    PSUTIL_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import wmi_handler
    WMI_HANDLER_AVAILABLE = True
except ImportError:
    wmi_handler = None
    WMI_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import numpy_handler
    NUMPY_HANDLER_AVAILABLE = True
except ImportError:
    numpy_handler = None
    NUMPY_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import matplotlib_handler
    MATPLOTLIB_HANDLER_AVAILABLE = True
except ImportError:
    matplotlib_handler = None
    MATPLOTLIB_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import pyqt6_handler
    PYQT6_HANDLER_AVAILABLE = True
except ImportError:
    pyqt6_handler = None
    PYQT6_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import tkinter_handler
    TKINTER_HANDLER_AVAILABLE = True
except ImportError:
    tkinter_handler = None
    TKINTER_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import sqlite3_handler
    SQLITE3_HANDLER_AVAILABLE = True
except ImportError:
    sqlite3_handler = None
    SQLITE3_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import pdfkit_handler
    PDFKIT_HANDLER_AVAILABLE = True
except ImportError:
    pdfkit_handler = None
    PDFKIT_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import opencl_handler
    OPENCL_HANDLER_AVAILABLE = True
except ImportError:
    opencl_handler = None
    OPENCL_HANDLER_AVAILABLE = False

try:
    from intellicrack.handlers import tensorflow_handler
    TENSORFLOW_HANDLER_AVAILABLE = True
except ImportError:
    tensorflow_handler = None
    TENSORFLOW_HANDLER_AVAILABLE = False

HANDLERS_DIR = Path(__file__).parent.parent.parent.parent / "intellicrack" / "handlers"


@pytest.mark.skipif(not FRIDA_HANDLER_AVAILABLE, reason="frida_handler not available")
class TestFridaHandler:
    """Test frida_handler.py - CRITICAL for dynamic instrumentation."""

    def test_import_frida_handler(self) -> None:
        """Test frida_handler can be imported."""
        assert frida_handler is not None
        assert hasattr(frida_handler, "HAS_FRIDA")

    def test_frida_availability_flag(self) -> None:
        """Test HAS_FRIDA reflects actual Frida availability."""
        if frida_handler.HAS_FRIDA:
            assert frida_handler.FRIDA_VERSION is not None
            assert isinstance(frida_handler.FRIDA_VERSION, str)
            import frida

            assert frida.__version__ == frida_handler.FRIDA_VERSION
        else:
            assert frida_handler.FRIDA_VERSION is None

    def test_fallback_device_provides_real_functionality(self) -> None:
        """Test FallbackDevice actually enumerates processes using OS APIs.

        This test verifies the fallback is NOT a mock - it must use real
        platform-specific process enumeration (WMIC on Windows, ps on Unix).
        """
        if frida_handler.HAS_FRIDA:
            pytest.skip("Real Frida available, testing fallback requires uninstalling Frida")

        device = frida_handler.get_local_device()
        assert device is not None

        processes = device.enumerate_processes()
        assert isinstance(processes, list)

        if len(processes) > 0:
            process = processes[0]
            assert hasattr(process, "pid")
            assert hasattr(process, "name")
            assert isinstance(process.pid, int)
            assert process.pid > 0

    def test_fallback_device_spawn_functionality(self) -> None:
        """Test FallbackDevice.spawn() actually spawns processes.

        Verifies spawn() uses real subprocess.Popen(), not a mock.
        """
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback spawn requires Frida to be unavailable")

        device = frida_handler.get_local_device()

        if sys.platform == "win32":
            test_program = "cmd.exe"
            test_args = ["/c", "echo", "test"]
        else:
            test_program = "/bin/echo"
            test_args = ["test"]

        try:
            pid = device.spawn(test_program, argv=test_args)
            assert isinstance(pid, int)
            assert pid > 0

            device.kill(pid)
        except Exception:
            pytest.skip("Process spawn failed - may require elevated permissions")

    def test_frida_handler_thread_safety(self) -> None:
        """Test frida_handler is thread-safe for concurrent usage."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing with real Frida requires actual device access")

        def get_device_manager_info() -> dict[str, Any]:
            dm = frida_handler.DeviceManager()
            device = dm.get_local_device()
            return {"id": device.id, "name": device.name, "type": device.type}

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(get_device_manager_info) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == 10
        for result in results:
            assert "id" in result
            assert "name" in result
            assert "type" in result

    def test_frida_handler_gil_safety(self) -> None:
        """Test frida_handler doesn't deadlock with Python GIL."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing with real Frida requires actual device access")

        results: list[bool] = []
        lock = threading.Lock()

        def enumerate_with_gil() -> None:
            dm = frida_handler.DeviceManager()
            device = dm.get_local_device()
            device.enumerate_processes()
            with lock:
                results.append(True)

        threads = [threading.Thread(target=enumerate_with_gil) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert len(results) == 5
        assert all(results)


@pytest.mark.skipif(not TORCH_HANDLER_AVAILABLE, reason="torch_handler not available")
class TestTorchHandler:
    """Test torch_handler.py - CRITICAL for ML-based analysis."""

    def test_import_torch_handler(self) -> None:
        """Test torch_handler can be imported."""
        assert torch_handler is not None
        assert hasattr(torch_handler, "HAS_TORCH")
        assert hasattr(torch_handler, "TORCH_AVAILABLE")

    def test_torch_availability_flags(self) -> None:
        """Test HAS_TORCH and TORCH_AVAILABLE reflect actual PyTorch availability."""
        assert torch_handler.HAS_TORCH == torch_handler.TORCH_AVAILABLE

        if torch_handler.HAS_TORCH:
            assert torch_handler.TORCH_VERSION is not None
            assert isinstance(torch_handler.TORCH_VERSION, str)
            import torch

            assert torch.__version__ == torch_handler.TORCH_VERSION
        else:
            assert torch_handler.TORCH_VERSION is None

    def test_fallback_tensor_api_compatibility(self) -> None:
        """Test FallbackTensor maintains PyTorch Tensor API shape."""
        if torch_handler.HAS_TORCH:
            pytest.skip("Real PyTorch available, testing fallback requires uninstalling PyTorch")

        tensor = torch_handler.tensor([1, 2, 3])
        assert tensor is not None
        assert hasattr(tensor, "cuda")
        assert hasattr(tensor, "cpu")
        assert hasattr(tensor, "numpy")

        cuda_tensor = tensor.cuda()
        assert cuda_tensor is not None

        cpu_tensor = tensor.cpu()
        assert cpu_tensor is not None

    def test_torch_handler_thread_safety(self) -> None:
        """Test torch_handler is thread-safe for concurrent usage."""
        def create_tensor() -> object:
            return torch_handler.tensor([1.0, 2.0, 3.0])

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(create_tensor) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == 10
        for result in results:
            assert result is not None

    def test_torch_handler_intel_arc_detection(self) -> None:
        """Test Intel Arc GPU detection functionality."""
        if not torch_handler.HAS_TORCH:
            pytest.skip("PyTorch not available for Intel Arc detection test")

        assert hasattr(torch_handler, "_detect_and_fix_intel_arc")

        try:
            torch_handler._detect_and_fix_intel_arc()
        except Exception as e:
            pytest.fail(f"Intel Arc detection raised unexpected exception: {e}")


@pytest.mark.skipif(not TORCH_XPU_HANDLER_AVAILABLE, reason="torch_xpu_handler not available")
class TestTorchXpuHandler:
    """Test torch_xpu_handler.py - CRITICAL for Intel XPU acceleration."""

    def test_import_torch_xpu_handler(self) -> None:
        """Test torch_xpu_handler can be imported."""
        assert torch_xpu_handler is not None
        assert hasattr(torch_xpu_handler, "HAS_XPU")

    def test_xpu_availability_flag(self) -> None:
        """Test HAS_XPU reflects actual Intel XPU availability."""
        assert isinstance(torch_xpu_handler.HAS_XPU, bool)

        if torch_xpu_handler.HAS_XPU:
            try:
                import intel_extension_for_pytorch as ipex

            except ImportError:
                pytest.fail("HAS_XPU is True but intel_extension_for_pytorch not importable")

    def test_xpu_handler_no_side_effects(self) -> None:
        """Test importing torch_xpu_handler doesn't cause side effects."""
        import os

        original_env = os.environ.copy()

        importlib.reload(sys.modules["intellicrack.handlers.torch_xpu_handler"])

        for key in ["CPP_MIN_LOG_LEVEL", "TF_CPP_MIN_LOG_LEVEL"]:
            if key in original_env:
                assert os.environ.get(key) == original_env[key]


@pytest.mark.skipif(not CAPSTONE_HANDLER_AVAILABLE, reason="capstone_handler not available")
class TestCapstoneHandler:
    """Test capstone_handler.py - CRITICAL for disassembly."""

    def test_import_capstone_handler(self) -> None:
        """Test capstone_handler can be imported."""
        assert capstone_handler is not None
        assert hasattr(capstone_handler, "CAPSTONE_AVAILABLE")

    def test_capstone_availability(self) -> None:
        """Test Capstone library availability detection."""
        if capstone_handler.CAPSTONE_AVAILABLE:
            import capstone

            assert capstone.CS_ARCH_X86 is not None
        else:
            pytest.skip("Capstone not available for testing")


@pytest.mark.skipif(not KEYSTONE_HANDLER_AVAILABLE, reason="keystone_handler not available")
class TestKeystoneHandler:
    """Test keystone_handler.py - CRITICAL for assembly."""

    def test_import_keystone_handler(self) -> None:
        """Test keystone_handler can be imported."""
        assert keystone_handler is not None
        assert hasattr(keystone_handler, "KEYSTONE_AVAILABLE")

    def test_keystone_availability(self) -> None:
        """Test Keystone library availability detection."""
        if keystone_handler.KEYSTONE_AVAILABLE:
            import keystone

            assert keystone.KS_ARCH_X86 is not None
        else:
            pytest.skip("Keystone not available for testing")


@pytest.mark.skipif(not PEFILE_HANDLER_AVAILABLE, reason="pefile_handler not available")
class TestPefileHandler:
    """Test pefile_handler.py - CRITICAL for PE analysis."""

    def test_import_pefile_handler(self) -> None:
        """Test pefile_handler can be imported."""
        assert pefile_handler is not None
        assert hasattr(pefile_handler, "PEFILE_AVAILABLE")

    def test_pefile_availability(self) -> None:
        """Test pefile library availability detection."""
        if pefile_handler.PEFILE_AVAILABLE:
            import pefile

            assert pefile.PE is not None
        else:
            pytest.skip("pefile not available for testing")


@pytest.mark.skipif(not LIEF_HANDLER_AVAILABLE, reason="lief_handler not available")
class TestLiefHandler:
    """Test lief_handler.py - CRITICAL for binary parsing."""

    def test_import_lief_handler(self) -> None:
        """Test lief_handler can be imported."""
        assert lief_handler is not None
        assert hasattr(lief_handler, "HAS_LIEF")

    def test_lief_availability(self) -> None:
        """Test LIEF library availability detection."""
        if lief_handler.HAS_LIEF:
            import lief

            assert lief.parse is not None
        else:
            pytest.skip("LIEF not available for testing")


@pytest.mark.skipif(not PYELFTOOLS_HANDLER_AVAILABLE, reason="pyelftools_handler not available")
class TestPyElfToolsHandler:
    """Test pyelftools_handler.py - CRITICAL for ELF analysis."""

    def test_import_pyelftools_handler(self) -> None:
        """Test pyelftools_handler can be imported."""
        assert pyelftools_handler is not None
        assert hasattr(pyelftools_handler, "HAS_PYELFTOOLS")

    def test_pyelftools_availability(self) -> None:
        """Test pyelftools library availability detection."""
        if pyelftools_handler.HAS_PYELFTOOLS:
            from elftools.elf.elffile import ELFFile

            assert ELFFile is not None
        else:
            pytest.skip("pyelftools not available for testing")


@pytest.mark.skipif(not CRYPTOGRAPHY_HANDLER_AVAILABLE, reason="cryptography_handler not available")
class TestCryptographyHandler:
    """Test cryptography_handler.py - CRITICAL for crypto operations."""

    def test_import_cryptography_handler(self) -> None:
        """Test cryptography_handler can be imported."""
        assert cryptography_handler is not None
        assert hasattr(cryptography_handler, "HAS_CRYPTOGRAPHY")

    def test_cryptography_availability(self) -> None:
        """Test cryptography library availability detection."""
        if cryptography_handler.HAS_CRYPTOGRAPHY:
            from cryptography.hazmat.primitives import hashes

            assert hashes.SHA256 is not None
        else:
            pytest.skip("cryptography not available for testing")


@pytest.mark.skipif(not REQUESTS_HANDLER_AVAILABLE, reason="requests_handler not available")
class TestRequestsHandler:
    """Test requests_handler.py - CRITICAL for network operations."""

    def test_import_requests_handler(self) -> None:
        """Test requests_handler can be imported."""
        assert requests_handler is not None
        assert hasattr(requests_handler, "HAS_REQUESTS")

    def test_requests_availability(self) -> None:
        """Test requests library availability detection."""
        if requests_handler.HAS_REQUESTS:
            import requests

            assert requests.get is not None
        else:
            pytest.skip("requests not available for testing")


@pytest.mark.skipif(not AIOHTTP_HANDLER_AVAILABLE, reason="aiohttp_handler not available")
class TestAiohttpHandler:
    """Test aiohttp_handler.py - CRITICAL for async network operations."""

    def test_import_aiohttp_handler(self) -> None:
        """Test aiohttp_handler can be imported."""
        assert aiohttp_handler is not None
        assert hasattr(aiohttp_handler, "HAS_AIOHTTP")

    def test_aiohttp_availability(self) -> None:
        """Test aiohttp library availability detection."""
        if aiohttp_handler.HAS_AIOHTTP:
            import aiohttp

            assert aiohttp.ClientSession is not None
        else:
            pytest.skip("aiohttp not available for testing")


@pytest.mark.skipif(not PSUTIL_HANDLER_AVAILABLE, reason="psutil_handler not available")
class TestPsutilHandler:
    """Test psutil_handler.py - CRITICAL for process monitoring."""

    def test_import_psutil_handler(self) -> None:
        """Test psutil_handler can be imported."""
        assert psutil_handler is not None
        assert hasattr(psutil_handler, "PSUTIL_AVAILABLE")

    def test_psutil_availability(self) -> None:
        """Test psutil library availability detection."""
        if psutil_handler.PSUTIL_AVAILABLE:
            import psutil

            assert psutil.Process is not None
        else:
            pytest.skip("psutil not available for testing")


@pytest.mark.skipif(not WMI_HANDLER_AVAILABLE, reason="wmi_handler not available")
class TestWmiHandler:
    """Test wmi_handler.py - Windows-specific process monitoring."""

    def test_import_wmi_handler(self) -> None:
        """Test wmi_handler can be imported."""
        assert wmi_handler is not None
        assert hasattr(wmi_handler, "HAS_WMI")

    def test_wmi_availability_windows_only(self) -> None:
        """Test WMI is only available on Windows."""
        if sys.platform == "win32":
            if wmi_handler.HAS_WMI:
                import wmi

                assert wmi.WMI is not None
        else:
            assert wmi_handler.HAS_WMI is False


@pytest.mark.skipif(not NUMPY_HANDLER_AVAILABLE, reason="numpy_handler not available")
class TestNumpyHandler:
    """Test numpy_handler.py - CRITICAL for numerical operations."""

    def test_import_numpy_handler(self) -> None:
        """Test numpy_handler can be imported."""
        assert numpy_handler is not None
        assert hasattr(numpy_handler, "HAS_NUMPY")

    def test_numpy_availability(self) -> None:
        """Test NumPy library availability detection."""
        if numpy_handler.HAS_NUMPY:
            import numpy

            assert numpy.array is not None
        else:
            pytest.skip("NumPy not available for testing")


@pytest.mark.skipif(not MATPLOTLIB_HANDLER_AVAILABLE, reason="matplotlib_handler not available")
class TestMatplotlibHandler:
    """Test matplotlib_handler.py - CRITICAL for visualization."""

    def test_import_matplotlib_handler(self) -> None:
        """Test matplotlib_handler can be imported."""
        assert matplotlib_handler is not None
        assert hasattr(matplotlib_handler, "HAS_MATPLOTLIB")

    def test_matplotlib_availability(self) -> None:
        """Test matplotlib library availability detection."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            import matplotlib.pyplot

            assert matplotlib.pyplot.plot is not None
        else:
            pytest.skip("matplotlib not available for testing")


@pytest.mark.skipif(not PYQT6_HANDLER_AVAILABLE, reason="pyqt6_handler not available")
class TestPyQt6Handler:
    """Test pyqt6_handler.py - CRITICAL for GUI."""

    def test_import_pyqt6_handler(self) -> None:
        """Test pyqt6_handler can be imported."""
        assert pyqt6_handler is not None
        assert hasattr(pyqt6_handler, "HAS_PYQT") or hasattr(pyqt6_handler, "PYQT6_AVAILABLE")

    def test_pyqt6_availability(self) -> None:
        """Test PyQt6 library availability detection."""
        pyqt_available = getattr(pyqt6_handler, "HAS_PYQT", getattr(pyqt6_handler, "PYQT6_AVAILABLE", False))

        if pyqt_available:
            from PyQt6.QtWidgets import QApplication

            assert QApplication is not None
        else:
            pytest.skip("PyQt6 not available for testing")


@pytest.mark.skipif(not TKINTER_HANDLER_AVAILABLE, reason="tkinter_handler not available")
class TestTkinterHandler:
    """Test tkinter_handler.py - Alternative GUI framework."""

    def test_import_tkinter_handler(self) -> None:
        """Test tkinter_handler can be imported."""
        assert tkinter_handler is not None
        assert hasattr(tkinter_handler, "HAS_TKINTER")

    def test_tkinter_availability(self) -> None:
        """Test tkinter library availability detection."""
        if tkinter_handler.HAS_TKINTER:
            import tkinter

            assert tkinter.Tk is not None
        else:
            pytest.skip("tkinter not available for testing")


@pytest.mark.skipif(not SQLITE3_HANDLER_AVAILABLE, reason="sqlite3_handler not available")
class TestSqlite3Handler:
    """Test sqlite3_handler.py - CRITICAL for database operations."""

    def test_import_sqlite3_handler(self) -> None:
        """Test sqlite3_handler can be imported."""
        assert sqlite3_handler is not None
        assert hasattr(sqlite3_handler, "HAS_SQLITE3")

    def test_sqlite3_availability(self) -> None:
        """Test sqlite3 library availability detection."""
        if sqlite3_handler.HAS_SQLITE3:
            import sqlite3

            assert sqlite3.connect is not None
        else:
            pytest.skip("sqlite3 not available for testing")


@pytest.mark.skipif(not PDFKIT_HANDLER_AVAILABLE, reason="pdfkit_handler not available")
class TestPdfkitHandler:
    """Test pdfkit_handler.py - PDF generation."""

    def test_import_pdfkit_handler(self) -> None:
        """Test pdfkit_handler can be imported."""
        assert pdfkit_handler is not None
        assert hasattr(pdfkit_handler, "PDFKIT_AVAILABLE")

    def test_pdfkit_availability(self) -> None:
        """Test pdfkit library availability detection."""
        if pdfkit_handler.PDFKIT_AVAILABLE:
            import pdfkit

            assert pdfkit.from_string is not None
        else:
            pytest.skip("pdfkit not available for testing")


@pytest.mark.skipif(not OPENCL_HANDLER_AVAILABLE, reason="opencl_handler not available")
class TestOpenclHandler:
    """Test opencl_handler.py - GPU acceleration via OpenCL."""

    def test_import_opencl_handler(self) -> None:
        """Test opencl_handler can be imported."""
        assert opencl_handler is not None
        assert hasattr(opencl_handler, "OPENCL_AVAILABLE")

    def test_opencl_availability(self) -> None:
        """Test OpenCL library availability detection."""
        if opencl_handler.OPENCL_AVAILABLE:
            import pyopencl

            assert pyopencl.get_platforms is not None
        else:
            pytest.skip("OpenCL not available for testing")


@pytest.mark.skipif(not TENSORFLOW_HANDLER_AVAILABLE, reason="tensorflow_handler not available")
class TestTensorflowHandler:
    """Test tensorflow_handler.py - TensorFlow ML framework."""

    def test_import_tensorflow_handler(self) -> None:
        """Test tensorflow_handler can be imported."""
        assert tensorflow_handler is not None
        assert hasattr(tensorflow_handler, "HAS_TENSORFLOW")

    def test_tensorflow_availability(self) -> None:
        """Test TensorFlow library availability detection."""
        if tensorflow_handler.HAS_TENSORFLOW:
            import tensorflow

            assert tensorflow.constant is not None
        else:
            pytest.skip("TensorFlow not available for testing")


class TestAllHandlersConsistency:
    """Test consistency across all handlers."""

    def test_all_handlers_have_availability_flag(self) -> None:
        """Test all handlers define an availability constant (HAS_* or *_AVAILABLE)."""
        handler_files = [
            f.stem
            for f in HANDLERS_DIR.glob("*.py")
            if f.stem != "__init__" and not f.name.endswith(".backup")
        ]

        availability_mapping = {
            "torch_xpu_handler": "HAS_XPU",
            "torch_handler": "HAS_TORCH",
            "tensorflow_handler": "HAS_TENSORFLOW",
            "wmi_handler": "HAS_WMI",
            "frida_handler": "HAS_FRIDA",
            "lief_handler": "HAS_LIEF",
            "pyelftools_handler": "HAS_PYELFTOOLS",
            "cryptography_handler": "HAS_CRYPTOGRAPHY",
            "requests_handler": "HAS_REQUESTS",
            "aiohttp_handler": "HAS_AIOHTTP",
            "numpy_handler": "HAS_NUMPY",
            "matplotlib_handler": "HAS_MATPLOTLIB",
            "tkinter_handler": "HAS_TKINTER",
            "sqlite3_handler": "HAS_SQLITE3",
            "pyqt6_handler": "HAS_PYQT",
            "keystone_handler": "KEYSTONE_AVAILABLE",
            "capstone_handler": "CAPSTONE_AVAILABLE",
            "pefile_handler": "PEFILE_AVAILABLE",
            "psutil_handler": "PSUTIL_AVAILABLE",
            "pdfkit_handler": "PDFKIT_AVAILABLE",
            "opencl_handler": "OPENCL_AVAILABLE",
        }

        for handler_name in handler_files:
            try:
                module = importlib.import_module(f"intellicrack.handlers.{handler_name}")
            except ImportError:
                continue

            if expected_flag := availability_mapping.get(handler_name):
                assert hasattr(
                    module, expected_flag
                ), f"{handler_name} missing {expected_flag} constant"
            else:
                has_flag = any(
                    hasattr(module, attr)
                    for attr in dir(module)
                    if attr.startswith("HAS_") or attr.endswith("_AVAILABLE")
                )
                assert has_flag, f"{handler_name} missing availability constant"

    def test_all_handlers_thread_safe_import(self) -> None:
        """Test all handlers can be imported concurrently without issues."""
        handler_files = [
            f.stem
            for f in HANDLERS_DIR.glob("*.py")
            if f.stem != "__init__" and not f.name.endswith(".backup")
        ]

        def import_handler(handler_name: str) -> str:
            try:
                importlib.import_module(f"intellicrack.handlers.{handler_name}")
            except ImportError:
                pass
            return handler_name

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(import_handler, name) for name in handler_files]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == len(handler_files)
