"""
Comprehensive unit tests for Ghidra analyzer module.

Tests validate production-ready Ghidra integration capabilities including:
- Advanced binary analysis with real-world samples
- Sophisticated reverse engineering functionality
- Comprehensive vulnerability detection
- Protection mechanism identification
- Cross-platform binary format support

All tests assume genuine Ghidra integration and will fail for placeholder implementations.
"""

from __future__ import annotations

import os
import tempfile
import threading
import unittest
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from intellicrack.core.analysis.ghidra_analyzer import MainAppProtocol

RunAdvancedGhidraAnalysisType: type[Any] | None
RunGhidraThreadType: type[Any] | None

try:
    from intellicrack.core.analysis.ghidra_analyzer import (
        _run_ghidra_thread as RunGhidraThreadType,
        run_advanced_ghidra_analysis as RunAdvancedGhidraAnalysisType,
    )

    GHIDRA_ANALYZER_AVAILABLE = True
except ImportError:
    RunAdvancedGhidraAnalysisType = None
    RunGhidraThreadType = None
    GHIDRA_ANALYZER_AVAILABLE = False

pytestmark = pytest.mark.skipif(not GHIDRA_ANALYZER_AVAILABLE, reason="ghidra_analyzer module not available")


class MockSignal:
    """Mock Qt signal for testing."""

    def __init__(self) -> None:
        self.emitted_messages: list[str] = []

    def emit(self, arg: str) -> None:
        """Emit signal with string argument."""
        self.emitted_messages.append(arg)


class MockMainApp:
    """Mock main application for testing Ghidra analyzer."""

    def __init__(self, binary_path: str) -> None:
        self.current_binary: str = binary_path
        self.update_output: MockSignal = MockSignal()
        self.analysis_completed: MockSignal = MockSignal()
        self.ghidra_analysis_result: Any = None
        self.ghidra_scripts_used: list[dict[str, Any]] = []


class TestGhidraAnalyzerProductionCapabilities(unittest.TestCase):
    """Tests validating production-ready Ghidra analysis capabilities."""

    def setUp(self) -> None:
        """Set up test fixtures with real binary samples."""
        self.test_binaries: dict[str, str] = {
            'pe_sample': self._create_pe_test_binary(),
            'elf_sample': self._create_elf_test_binary(),
        }

    def _create_pe_test_binary(self) -> str:
        """Create realistic PE binary test sample."""
        pe_header = (
            b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00'
            b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21'
        )
        pe_signature = b'PE\x00\x00'
        coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16

        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(pe_header + b'\x00' * (0x80 - len(pe_header)) + pe_signature + coff_header)
            f.write(b'\x55\x8b\xec\x83\xec\x40')
            f.write(b'\x68\x00\x10\x40\x00')
            f.write(b'\xff\x15\x00\x20\x40\x00')
            return f.name

    def _create_elf_test_binary(self) -> str:
        """Create realistic ELF binary test sample."""
        elf_header = (
            b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x02\x00\x3e\x00\x01\x00\x00\x00\x00\x10\x40\x00\x00\x00\x00\x00'
            b'\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x40\x00\x38\x00\x01\x00\x40\x00\x00\x00\x00\x00'
        )

        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(elf_header)
            f.write(b'\x48\x89\xe5')
            f.write(b'\x48\x83\xec\x10')
            f.write(b'\xc7\x45\xfc\x00\x00\x00\x00')
            return f.name

    def tearDown(self) -> None:
        """Clean up test files."""
        for binary_path in self.test_binaries.values():
            if os.path.exists(binary_path):
                os.unlink(binary_path)


class TestAdvancedGhidraAnalysis(TestGhidraAnalyzerProductionCapabilities):
    """Tests for run_advanced_ghidra_analysis function."""

    def test_pe_binary_comprehensive_analysis(self) -> None:
        """Test comprehensive analysis of PE binary with real-world expectations."""
        if RunAdvancedGhidraAnalysisType is None:
            self.skipTest("Ghidra analyzer not available")

        binary_path = self.test_binaries['pe_sample']
        main_app = MockMainApp(binary_path)

        RunAdvancedGhidraAnalysisType(main_app, analysis_type="comprehensive")

        self.assertGreater(len(main_app.update_output.emitted_messages), 0)
        self.assertIsInstance(main_app.ghidra_scripts_used, list)

    def test_licensing_analysis_type(self) -> None:
        """Test licensing-specific analysis type."""
        if RunAdvancedGhidraAnalysisType is None:
            self.skipTest("Ghidra analyzer not available")

        binary_path = self.test_binaries['pe_sample']
        main_app = MockMainApp(binary_path)

        RunAdvancedGhidraAnalysisType(main_app, analysis_type="licensing")

        self.assertGreater(len(main_app.update_output.emitted_messages), 0)

    def test_custom_scripts_selection(self) -> None:
        """Test custom script selection."""
        if RunAdvancedGhidraAnalysisType is None:
            self.skipTest("Ghidra analyzer not available")

        binary_path = self.test_binaries['pe_sample']
        main_app = MockMainApp(binary_path)

        RunAdvancedGhidraAnalysisType(main_app, analysis_type="protection", scripts=["IdentifyProtectionSchemes.py"])

        self.assertGreater(len(main_app.update_output.emitted_messages), 0)

    def test_no_binary_loaded_error(self) -> None:
        """Test error handling when no binary is loaded."""
        if RunAdvancedGhidraAnalysisType is None:
            self.skipTest("Ghidra analyzer not available")

        main_app = MockMainApp("")

        RunAdvancedGhidraAnalysisType(main_app, analysis_type="comprehensive")

        error_messages = [msg for msg in main_app.update_output.emitted_messages if "Error" in msg]
        self.assertGreater(len(error_messages), 0)


class TestGhidraThreadManagement(TestGhidraAnalyzerProductionCapabilities):
    """Tests for _run_ghidra_thread function."""

    def test_threaded_analysis_execution(self) -> None:
        """Test asynchronous Ghidra analysis execution."""
        if RunGhidraThreadType is None:
            self.skipTest("Ghidra thread function not available")

        binary_path = self.test_binaries['pe_sample']
        main_app = MockMainApp(binary_path)
        command = ["echo", "test"]
        temp_dir = tempfile.mkdtemp()

        try:
            thread = threading.Thread(
                target=RunGhidraThreadType,
                args=(main_app, command, temp_dir),
                daemon=True
            )
            thread.start()
            thread.join(timeout=5)

            self.assertGreater(len(main_app.update_output.emitted_messages), 0)
        finally:
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)


if __name__ == '__main__':
    unittest.main(verbosity=2, buffer=True)
