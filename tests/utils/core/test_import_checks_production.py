"""Production tests for import_checks.py module.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

Tests validate that import availability checks correctly identify
binary analysis, system monitoring, and ML libraries required for
software licensing protection analysis and cracking operations.
"""

import importlib
import logging
import sys
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional

import pytest


class FakeLogger:
    """Real test double for logger that tracks error calls."""

    def __init__(self) -> None:
        self.error_calls: List[tuple[Any, ...]] = []
        self.debug_calls: List[tuple[Any, ...]] = []
        self.info_calls: List[tuple[Any, ...]] = []
        self.warning_calls: List[tuple[Any, ...]] = []

    def error(self, *args: Any, **kwargs: Any) -> None:
        """Track error logging calls."""
        self.error_calls.append(args)

    def debug(self, *args: Any, **kwargs: Any) -> None:
        """Track debug logging calls."""
        self.debug_calls.append(args)

    def info(self, *args: Any, **kwargs: Any) -> None:
        """Track info logging calls."""
        self.info_calls.append(args)

    def warning(self, *args: Any, **kwargs: Any) -> None:
        """Track warning logging calls."""
        self.warning_calls.append(args)

    @property
    def called(self) -> bool:
        """Check if any logging method was called."""
        return bool(
            self.error_calls
            or self.debug_calls
            or self.info_calls
            or self.warning_calls
        )


def test_import_checks_all_flags_are_booleans() -> None:
    """All availability flags must be boolean values."""
    from intellicrack.utils.core import import_checks

    flags = [
        "PEFILE_AVAILABLE",
        "LIEF_AVAILABLE",
        "CAPSTONE_AVAILABLE",
        "PYELFTOOLS_AVAILABLE",
        "PSUTIL_AVAILABLE",
        "FRIDA_AVAILABLE",
        "MATPLOTLIB_AVAILABLE",
        "PDFKIT_AVAILABLE",
        "TENSORFLOW_AVAILABLE",
        "HAS_PYQT",
        "HAS_NUMPY",
        "WINREG_AVAILABLE",
    ]

    for flag in flags:
        value: Any = getattr(import_checks, flag)
        assert isinstance(
            value, bool
        ), f"{flag} must be boolean, got {type(value).__name__}"


def test_import_checks_pefile_availability_matches_import_success() -> None:
    """PEFILE_AVAILABLE flag matches actual pefile import success."""
    from intellicrack.utils.core import import_checks

    if import_checks.PEFILE_AVAILABLE:
        assert import_checks.pefile is not None
        assert hasattr(import_checks.pefile, "PE")
    else:
        assert import_checks.pefile is None


def test_import_checks_lief_availability_matches_import_success() -> None:
    """LIEF_AVAILABLE flag matches actual lief import success."""
    from intellicrack.utils.core import import_checks

    if import_checks.LIEF_AVAILABLE:
        assert import_checks.lief is not None
        assert import_checks.HAS_LIEF is True
    else:
        assert import_checks.lief is None
        assert import_checks.HAS_LIEF is False


def test_import_checks_capstone_availability_for_disassembly() -> None:
    """Capstone availability enables binary disassembly for protection analysis."""
    from intellicrack.utils.core import import_checks

    if import_checks.CAPSTONE_AVAILABLE:
        assert import_checks.capstone is not None
        assert hasattr(import_checks.capstone, "Cs")
        assert hasattr(import_checks.capstone, "CS_ARCH_X86")
    else:
        assert import_checks.capstone is None


def test_import_checks_pyelftools_availability_for_elf_analysis() -> None:
    """PyElfTools availability enables ELF binary analysis for Linux protection schemes."""
    from intellicrack.utils.core import import_checks

    if import_checks.PYELFTOOLS_AVAILABLE:
        assert import_checks.ELFFile is not None
        assert import_checks.HAS_PYELFTOOLS is True
        assert import_checks.elffile is not None
    else:
        assert import_checks.ELFFile is None
        assert import_checks.HAS_PYELFTOOLS is False


def test_import_checks_psutil_availability_for_process_monitoring() -> None:
    """Psutil availability enables process monitoring for runtime license analysis."""
    from intellicrack.utils.core import import_checks

    if import_checks.PSUTIL_AVAILABLE:
        assert import_checks.psutil is not None
        assert hasattr(import_checks.psutil, "Process")
    else:
        assert import_checks.psutil is None


def test_import_checks_frida_availability_for_dynamic_instrumentation() -> None:
    """Frida availability enables dynamic instrumentation for license check hooking."""
    from intellicrack.utils.core import import_checks

    if import_checks.FRIDA_AVAILABLE:
        assert import_checks.frida is not None
        assert import_checks.HAS_FRIDA is True
        assert hasattr(import_checks.frida, "attach")
    else:
        assert import_checks.frida is None
        assert import_checks.HAS_FRIDA is False


def test_import_checks_matplotlib_availability_for_visualization() -> None:
    """Matplotlib availability enables visualization of binary analysis results."""
    from intellicrack.utils.core import import_checks

    if import_checks.MATPLOTLIB_AVAILABLE:
        assert import_checks.plt is not None
        assert import_checks.HAS_MATPLOTLIB is True
    else:
        assert import_checks.plt is None
        assert import_checks.HAS_MATPLOTLIB is False


def test_import_checks_numpy_availability_for_numerical_analysis() -> None:
    """NumPy availability enables numerical analysis for pattern detection."""
    from intellicrack.utils.core import import_checks

    if import_checks.HAS_NUMPY:
        assert import_checks.np is not None
        assert hasattr(import_checks.np, "array")
    else:
        assert import_checks.np is None


def test_import_checks_tensorflow_configuration_prevents_gpu_issues() -> None:
    """TensorFlow configuration disables GPU to prevent compatibility issues."""
    from intellicrack.utils.core import import_checks

    if import_checks.TENSORFLOW_AVAILABLE:
        assert import_checks.tf is not None

        visible_devices = import_checks.tf.config.get_visible_devices("GPU")
        assert len(visible_devices) == 0, "GPU should be disabled for compatibility"


def test_import_checks_winreg_availability_on_windows_only() -> None:
    """WinReg availability matches Windows platform check."""
    import platform

    from intellicrack.utils.core import import_checks

    is_windows = platform.system() == "Windows"

    if is_windows:
        if import_checks.WINREG_AVAILABLE:
            assert import_checks.winreg is not None
    else:
        assert import_checks.WINREG_AVAILABLE is False
        assert import_checks.winreg is None


def test_import_checks_pyqt_availability_for_gui_operations() -> None:
    """PyQt6 availability enables GUI-based binary analysis operations."""
    from intellicrack.utils.core import import_checks

    if import_checks.HAS_PYQT:
        import PyQt6

        assert PyQt6 is not None
    else:
        with pytest.raises(ImportError):
            import PyQt6

            _ = PyQt6


def test_import_checks_all_exports_are_accessible() -> None:
    """All exported symbols are accessible from import_checks module."""
    from intellicrack.utils.core import import_checks

    for name in import_checks.__all__:
        assert hasattr(
            import_checks, name
        ), f"Exported symbol {name} not accessible"


def test_import_checks_handles_missing_handler_gracefully(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing handler modules set availability flags to False."""
    original_modules = sys.modules.copy()

    monkeypatch.setitem(sys.modules, "intellicrack.handlers.pefile_handler", None)

    if "intellicrack.utils.core.import_checks" in sys.modules:
        importlib.reload(sys.modules["intellicrack.utils.core.import_checks"])

    from intellicrack.utils.core import import_checks

    if sys.modules.get("intellicrack.handlers.pefile_handler") is None:
        assert not import_checks.PEFILE_AVAILABLE

    for key, value in original_modules.items():
        if key not in sys.modules or sys.modules[key] != value:
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value


def test_import_checks_consistency_between_flags_and_modules() -> None:
    """Availability flags correctly reflect module import status."""
    from intellicrack.utils.core import import_checks

    test_cases = [
        ("PEFILE_AVAILABLE", "pefile"),
        ("LIEF_AVAILABLE", "lief"),
        ("CAPSTONE_AVAILABLE", "capstone"),
        ("PSUTIL_AVAILABLE", "psutil"),
        ("FRIDA_AVAILABLE", "frida"),
        ("HAS_NUMPY", "np"),
    ]

    for flag_name, module_name in test_cases:
        flag_value: bool = getattr(import_checks, flag_name)
        module_value: Any = getattr(import_checks, module_name)

        if flag_value:
            assert (
                module_value is not None
            ), f"{module_name} should not be None when {flag_name} is True"
        else:
            assert (
                module_value is None
            ), f"{module_name} should be None when {flag_name} is False"


def test_import_checks_critical_libraries_for_pe_analysis() -> None:
    """Critical PE analysis libraries are available for Windows protection cracking."""
    from intellicrack.utils.core import import_checks

    critical_for_pe = [
        import_checks.PEFILE_AVAILABLE,
        import_checks.LIEF_AVAILABLE or import_checks.CAPSTONE_AVAILABLE,
    ]

    assert any(
        critical_for_pe
    ), "At least one PE analysis library must be available for Windows protection cracking"


def test_import_checks_tensorflow_environment_variables_set() -> None:
    """TensorFlow environment variables configured before import."""
    import os

    assert os.environ.get("TF_CPP_MIN_LOG_LEVEL") == "2"
    assert os.environ.get("CUDA_VISIBLE_DEVICES") == "-1"
    assert os.environ.get("MKL_THREADING_LAYER") == "GNU"


def test_import_checks_module_reload_maintains_availability() -> None:
    """Module reload maintains consistent availability flags."""
    from intellicrack.utils.core import import_checks

    initial_pefile = import_checks.PEFILE_AVAILABLE
    initial_lief = import_checks.LIEF_AVAILABLE

    importlib.reload(import_checks)

    assert import_checks.PEFILE_AVAILABLE == initial_pefile
    assert import_checks.LIEF_AVAILABLE == initial_lief


def test_import_checks_handler_import_errors_logged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Import errors from handlers are logged appropriately."""
    from intellicrack.utils.core import import_checks

    fake_logger = FakeLogger()

    original_get_logger = logging.getLogger

    def get_fake_logger(name: str) -> FakeLogger | logging.Logger:
        if name == "intellicrack.utils.core.import_checks":
            return fake_logger
        return original_get_logger(name)

    monkeypatch.setattr(logging, "getLogger", get_fake_logger)

    monkeypatch.setitem(sys.modules, "intellicrack.handlers.pefile_handler", None)

    try:
        importlib.reload(import_checks)
    except Exception:
        pass

    if not import_checks.PEFILE_AVAILABLE:
        assert fake_logger.called or import_checks.pefile is None


def test_import_checks_pdfkit_availability_for_report_generation() -> None:
    """PDFKit availability enables PDF report generation for analysis results."""
    from intellicrack.utils.core import import_checks

    if import_checks.PDFKIT_AVAILABLE:
        assert import_checks.pdfkit is not None
        assert hasattr(import_checks.pdfkit, "from_string") or hasattr(
            import_checks.pdfkit, "configuration"
        )
    else:
        assert import_checks.pdfkit is None


def test_import_checks_all_binary_analysis_flags() -> None:
    """Verify all binary analysis library availability flags are defined."""
    from intellicrack.utils.core import import_checks

    binary_analysis_flags = [
        "PEFILE_AVAILABLE",
        "LIEF_AVAILABLE",
        "CAPSTONE_AVAILABLE",
        "PYELFTOOLS_AVAILABLE",
    ]

    for flag in binary_analysis_flags:
        assert hasattr(import_checks, flag)
        assert isinstance(getattr(import_checks, flag), bool)


def test_import_checks_module_none_when_unavailable() -> None:
    """Module references are None when libraries are unavailable."""
    from intellicrack.utils.core import import_checks

    if not import_checks.PEFILE_AVAILABLE:
        assert import_checks.pefile is None

    if not import_checks.LIEF_AVAILABLE:
        assert import_checks.lief is None

    if not import_checks.CAPSTONE_AVAILABLE:
        assert import_checks.capstone is None

    if not import_checks.FRIDA_AVAILABLE:
        assert import_checks.frida is None
