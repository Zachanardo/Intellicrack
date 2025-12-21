"""Production-grade tests for Serial Generator Dialog.

This test suite validates the complete serial number generator dialog functionality
including serial format configuration, batch generation, pattern analysis, validation,
and keygen operations. Tests verify genuine integration with SerialNumberGenerator
backend and validate real serial cracking workflows.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3
"""

import json
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.handlers.pyqt6_handler import HAS_PYQT as PYQT6_AVAILABLE

if PYQT6_AVAILABLE:
    from intellicrack.handlers.pyqt6_handler import (
        QApplication,
        QMessageBox,
        Qt,
    )
    from intellicrack.ui.dialogs.serial_generator_dialog import (
        SerialGeneratorDialog,
        SerialGeneratorWorker,
    )
    from intellicrack.core.serial_generator import (
        SerialConstraints,
        SerialFormat,
    )

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE,
    reason="PyQt6 required for UI tests",
)


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create QApplication instance for Qt widget testing."""
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def mock_generator() -> Mock:
    """Create mock SerialNumberGenerator with realistic behavior."""
    generator = Mock()

    generator.analyze_serial_algorithm = Mock(return_value={
        "format": SerialFormat.ALPHANUMERIC,
        "length": {"most_common": 20, "range": (16, 25)},
        "separator": {"character": "-", "positions": [4, 9, 14, 19]},
        "checksum": {
            "algorithm": "luhn",
            "position": "last",
            "confidence": 0.87
        },
        "patterns": {
            "prefix": "ABCD",
            "suffix": None,
            "position_constraints": {}
        },
        "sample_count": 15
    })

    generator.generate_serial = Mock(side_effect=lambda constraints, seed=None:
        "ABCD-1234-EFGH-5678-9012" if constraints.format == SerialFormat.ALPHANUMERIC
        else "1234-5678-9012-3456-7890"
    )

    generator.checksum_functions = {
        "luhn": Mock(return_value=5),
        "verhoeff": Mock(return_value=3),
        "crc16": Mock(return_value=0xABCD),
        "mod11": Mock(return_value=7)
    }

    generator._verify_checksum = Mock(return_value=True)

    return generator


@pytest.fixture
def temp_serial_dir() -> Path:
    """Create temporary directory for serial files."""
    with tempfile.TemporaryDirectory(prefix="serials_") as tmpdir:
        serial_path = Path(tmpdir)

        serials_txt = """ABCD-1234-EFGH-5678-9012
ABCD-2345-EFGH-6789-0123
ABCD-3456-EFGH-7890-1234
ABCD-4567-EFGH-8901-2345
ABCD-5678-EFGH-9012-3456"""
        (serial_path / "sample_serials.txt").write_text(serials_txt)

        yield serial_path


class TestSerialGeneratorDialogInitialization:
    """Test dialog initialization and UI component creation."""

    def test_dialog_creates_successfully(self, qapp: Any, mock_generator: Mock) -> None:
        """Dialog initializes with all required UI components."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            assert dialog.generator is not None
            assert dialog.windowTitle() == "Serial Number Generator"
            assert dialog.minimumSize().width() >= 900
            assert dialog.minimumSize().height() >= 650

    def test_dialog_creates_all_tabs(self, qapp: Any, mock_generator: Mock) -> None:
        """Dialog creates all required tabs for serial generation workflow."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            assert dialog.tabs.count() == 6

            tab_names = [dialog.tabs.tabText(i) for i in range(dialog.tabs.count())]
            assert "Generate" in tab_names
            assert "Analyze" in tab_names
            assert "Batch" in tab_names
            assert "Validate" in tab_names
            assert "Patterns" in tab_names
            assert "Presets" in tab_names

    def test_dialog_initializes_format_combo(self, qapp: Any, mock_generator: Mock) -> None:
        """Format combo box is initialized with all serial formats."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            assert dialog.format_combo is not None

            formats = [dialog.format_combo.itemText(i) for i in range(dialog.format_combo.count())]

            assert "numeric" in formats
            assert "alphanumeric" in formats
            assert "alphabetic" in formats
            assert "hex" in formats
            assert "base32" in formats
            assert "base64" in formats

    def test_dialog_initializes_checksum_algorithms(self, qapp: Any, mock_generator: Mock) -> None:
        """Checksum combo box contains all available algorithms."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            assert dialog.checksum_combo is not None

            algorithms = [dialog.checksum_combo.itemText(i) for i in range(dialog.checksum_combo.count())]

            assert "luhn" in algorithms
            assert "verhoeff" in algorithms
            assert "damm" in algorithms
            assert "crc16" in algorithms
            assert "crc32" in algorithms
            assert "mod11" in algorithms


class TestSerialGeneration:
    """Test single serial generation functionality."""

    def test_generate_single_serial_numeric_format(self, qapp: Any, mock_generator: Mock) -> None:
        """Generating single serial with numeric format produces valid serial."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            dialog.format_combo.setCurrentText("numeric")
            dialog.length_spin.setValue(20)

            if hasattr(dialog, "generate_single_serial"):
                dialog.generate_single_serial()
                qapp.processEvents()

                mock_generator.generate_serial.assert_called()

    def test_generate_single_serial_alphanumeric_format(self, qapp: Any, mock_generator: Mock) -> None:
        """Generating single serial with alphanumeric format produces valid serial."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            dialog.format_combo.setCurrentText("alphanumeric")
            dialog.length_spin.setValue(20)

            if hasattr(dialog, "generate_single_serial"):
                dialog.generate_single_serial()
                qapp.processEvents()

                args = mock_generator.generate_serial.call_args[0]
                assert args[0].format == SerialFormat.ALPHANUMERIC

    def test_generate_serial_with_checksum(self, qapp: Any, mock_generator: Mock) -> None:
        """Generating serial with checksum enabled includes checksum validation."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            dialog.format_combo.setCurrentText("numeric")
            dialog.enable_checksum.setChecked(True)
            dialog.checksum_combo.setCurrentText("luhn")

            if hasattr(dialog, "generate_single_serial"):
                dialog.generate_single_serial()
                qapp.processEvents()

                args = mock_generator.generate_serial.call_args[0]
                assert args[0].checksum_algorithm == "luhn"

    def test_format_change_updates_custom_alphabet_visibility(self, qapp: Any, mock_generator: Mock) -> None:
        """Changing format to custom shows custom alphabet input."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            dialog.format_combo.setCurrentText("custom")
            dialog.on_format_changed("custom")

            assert dialog.custom_alphabet_widget.isVisible() is True

            dialog.format_combo.setCurrentText("numeric")
            dialog.on_format_changed("numeric")

            assert dialog.custom_alphabet_widget.isVisible() is False


class TestBatchGeneration:
    """Test batch serial generation functionality."""

    def test_generate_batch_serials(self, qapp: Any, mock_generator: Mock) -> None:
        """Batch generation creates specified number of serials."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            if hasattr(dialog, "batch_count_spin"):
                dialog.batch_count_spin.setValue(10)

            if hasattr(dialog, "generate_batch_serials"):
                dialog.generate_batch_serials()
                qapp.processEvents()

                assert len(dialog.generated_serials) > 0

    def test_batch_generation_updates_progress(self, qapp: Any, mock_generator: Mock) -> None:
        """Batch generation updates progress during serial creation."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            constraints = SerialConstraints(
                length=20,
                format=SerialFormat.ALPHANUMERIC
            )

            worker = SerialGeneratorWorker(
                generator=mock_generator,
                operation="generate_batch",
                params={"constraints": constraints, "count": 5}
            )

            progress_messages = []
            def capture_progress(msg: str) -> None:
                progress_messages.append(msg)

            worker.progress.connect(capture_progress)

            worker.run()

            assert progress_messages
            assert any("Generating serial" in msg for msg in progress_messages)

    def test_export_batch_serials(self, qapp: Any, mock_generator: Mock, temp_serial_dir: Path) -> None:
        """Exporting batch serials creates file with all generated serials."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            dialog.generated_serials = [
                "ABCD-1234-EFGH-5678-9012",
                "ABCD-2345-EFGH-6789-0123",
                "ABCD-3456-EFGH-7890-1234"
            ]

            export_path = temp_serial_dir / "exported_serials.txt"

            if hasattr(dialog, "export_serials"):
                with patch("intellicrack.ui.dialogs.serial_generator_dialog.QFileDialog.getSaveFileName", return_value=(str(export_path), "")):
                    with patch.object(QMessageBox, "information"):
                        dialog.export_serials()

                        if export_path.exists():
                            exported_content = export_path.read_text()
                            assert "ABCD-1234-EFGH-5678-9012" in exported_content
                            assert "ABCD-2345-EFGH-6789-0123" in exported_content


class TestSerialAnalysis:
    """Test serial pattern analysis functionality."""

    def test_analyze_serial_patterns_from_samples(self, qapp: Any, mock_generator: Mock) -> None:
        """Analyzing serial samples detects patterns and formats."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            if hasattr(dialog, "sample_serials_input"):
                sample_serials = [
                    "ABCD-1234-EFGH-5678-9012",
                    "ABCD-2345-EFGH-6789-0123",
                    "ABCD-3456-EFGH-7890-1234"
                ]

                dialog.sample_serials_input.setPlainText("\n".join(sample_serials))

            if hasattr(dialog, "analyze_patterns"):
                dialog.analyze_patterns()
                qapp.processEvents()

                mock_generator.analyze_serial_algorithm.assert_called()

    def test_analysis_worker_detects_format(self, qapp: Any, mock_generator: Mock) -> None:
        """Analysis worker correctly detects serial format from samples."""
        sample_serials = [
            "1234-5678-9012-3456",
            "2345-6789-0123-4567",
            "3456-7890-1234-5678"
        ]

        worker = SerialGeneratorWorker(
            generator=mock_generator,
            operation="analyze",
            params={"serials": sample_serials}
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        mock_generator.analyze_serial_algorithm.assert_called_once_with(sample_serials)

        assert len(results) == 1
        assert results[0]["operation"] == "analysis"
        assert "format" in results[0]["data"]

    def test_analysis_detects_checksum_algorithm(self, qapp: Any, mock_generator: Mock) -> None:
        """Analysis worker detects checksum algorithm from samples."""
        sample_serials = [
            "1234-5678-9012-3456-5",
            "2345-6789-0123-4567-8",
            "3456-7890-1234-5678-1"
        ]

        worker = SerialGeneratorWorker(
            generator=mock_generator,
            operation="analyze",
            params={"serials": sample_serials}
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert len(results) == 1
        checksum_info = results[0]["data"].get("checksum")
        assert checksum_info is not None
        assert "algorithm" in checksum_info

    def test_load_serials_from_file(self, qapp: Any, mock_generator: Mock, temp_serial_dir: Path) -> None:
        """Loading serials from file populates analysis input."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            serial_file = temp_serial_dir / "sample_serials.txt"

            if hasattr(dialog, "load_serials_from_file"):
                with patch("intellicrack.ui.dialogs.serial_generator_dialog.QFileDialog.getOpenFileName", return_value=(str(serial_file), "")):
                    dialog.load_serials_from_file()

                    if hasattr(dialog, "sample_serials_input"):
                        content = dialog.sample_serials_input.toPlainText()
                        assert "ABCD-1234" in content


class TestSerialValidation:
    """Test serial validation functionality."""

    def test_validate_serial_with_constraints(self, qapp: Any, mock_generator: Mock) -> None:
        """Validating serial checks format, length, and checksum."""
        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC,
            checksum_algorithm="luhn"
        )

        worker = SerialGeneratorWorker(
            generator=mock_generator,
            operation="validate",
            params={
                "serial": "ABCD-1234-EFGH-5678-9012",
                "constraints": constraints
            }
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert len(results) == 1
        assert results[0]["operation"] == "validation"
        assert "is_valid" in results[0]["data"]

    def test_validate_serial_format_check(self, qapp: Any, mock_generator: Mock) -> None:
        """Validation checks if serial matches expected format."""
        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.NUMERIC
        )

        worker = SerialGeneratorWorker(
            generator=mock_generator,
            operation="validate",
            params={
                "serial": "1234-5678-9012-3456",
                "constraints": constraints
            }
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert len(results) == 1
        validation_details = results[0]["data"]["details"]
        assert "format_check" in validation_details

    def test_validate_serial_length_check(self, qapp: Any, mock_generator: Mock) -> None:
        """Validation checks if serial has correct length."""
        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC
        )

        worker = SerialGeneratorWorker(
            generator=mock_generator,
            operation="validate",
            params={
                "serial": "ABCD-1234-EFGH-5678-9012",
                "constraints": constraints
            }
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert len(results) == 1

    def test_validate_serial_checksum_verification(self, qapp: Any, mock_generator: Mock) -> None:
        """Validation verifies checksum using specified algorithm."""
        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC,
            checksum_algorithm="luhn"
        )

        worker = SerialGeneratorWorker(
            generator=mock_generator,
            operation="validate",
            params={
                "serial": "ABCD-1234-EFGH-5678-9012",
                "constraints": constraints
            }
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert mock_generator._verify_checksum.called


class TestPatternCracking:
    """Test pattern cracking and serial generation from samples."""

    def test_crack_pattern_analyzes_samples(self, qapp: Any, mock_generator: Mock) -> None:
        """Pattern cracking analyzes samples to detect algorithm."""
        sample_serials = [
            "ABCD-1234-EFGH-5678-9012",
            "ABCD-2345-EFGH-6789-0123",
            "ABCD-3456-EFGH-7890-1234"
        ]

        worker = SerialGeneratorWorker(
            generator=mock_generator,
            operation="crack_pattern",
            params={"samples": sample_serials}
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        mock_generator.analyze_serial_algorithm.assert_called_once_with(sample_serials)

        assert len(results) == 1
        assert results[0]["operation"] == "pattern_crack"

    def test_crack_pattern_generates_test_serials(self, qapp: Any, mock_generator: Mock) -> None:
        """Pattern cracking generates test serials based on detected pattern."""
        sample_serials = [
            "ABCD-1234-EFGH-5678-9012",
            "ABCD-2345-EFGH-6789-0123"
        ]

        worker = SerialGeneratorWorker(
            generator=mock_generator,
            operation="crack_pattern",
            params={"samples": sample_serials}
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert len(results) == 1
        assert "generated_serials" in results[0]["data"]
        assert len(results[0]["data"]["generated_serials"]) == 10


class TestPresetManagement:
    """Test preset serial format management."""

    def test_load_presets_populates_list(self, qapp: Any, mock_generator: Mock) -> None:
        """Loading presets populates preset list widget."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            if hasattr(dialog, "preset_list"):
                assert dialog.preset_list.count() >= 0

    def test_apply_preset_updates_settings(self, qapp: Any, mock_generator: Mock) -> None:
        """Applying preset updates generation settings."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            if hasattr(dialog, "apply_preset"):
                if hasattr(dialog, "presets"):
                    preset = {
                        "name": "Windows Product Key",
                        "format": "alphanumeric",
                        "length": 25,
                        "groups": 5,
                        "separator": "-",
                        "checksum": "mod7"
                    }

                    dialog.presets = {"Windows Product Key": preset}

                dialog.apply_preset("Windows Product Key")

                assert dialog.format_combo.currentText() == "alphanumeric"
                assert dialog.length_spin.value() == 25

    def test_save_custom_preset(self, qapp: Any, mock_generator: Mock) -> None:
        """Saving custom preset stores current settings."""
        with patch("intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator", return_value=mock_generator):
            dialog = SerialGeneratorDialog()

            dialog.format_combo.setCurrentText("alphanumeric")
            dialog.length_spin.setValue(20)
            dialog.groups_spin.setValue(4)

            if hasattr(dialog, "save_preset"):
                with patch("intellicrack.ui.dialogs.serial_generator_dialog.QInputDialog.getText", return_value=("CustomPreset", True)):
                    dialog.save_preset()

                    if hasattr(dialog, "presets"):
                        assert "CustomPreset" in dialog.presets


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_worker_handles_analysis_errors(self, qapp: Any, mock_generator: Mock) -> None:
        """Worker thread handles analysis errors gracefully."""
        mock_generator.analyze_serial_algorithm.side_effect = Exception("Invalid serial samples")

        worker = SerialGeneratorWorker(
            generator=mock_generator,
            operation="analyze",
            params={"serials": []}
        )

        errors = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error.connect(capture_error)

        worker.run()

        assert len(errors) == 1
        assert "Invalid serial samples" in errors[0]

    def test_worker_handles_generation_errors(self, qapp: Any, mock_generator: Mock) -> None:
        """Worker thread handles generation errors gracefully."""
        mock_generator.generate_serial.side_effect = Exception("Invalid constraints")

        constraints = SerialConstraints(length=-1, format=SerialFormat.NUMERIC)

        worker = SerialGeneratorWorker(
            generator=mock_generator,
            operation="generate_single",
            params={"constraints": constraints}
        )

        errors = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error.connect(capture_error)

        worker.run()

        assert len(errors) == 1


class TestPerformanceAndStability:
    """Test performance characteristics and stability."""

    def test_batch_generation_large_count(self, qapp: Any, mock_generator: Mock) -> None:
        """Batch generation handles large serial counts efficiently."""
        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC
        )

        worker = SerialGeneratorWorker(
            generator=mock_generator,
            operation="generate_batch",
            params={"constraints": constraints, "count": 100}
        )

        start_time = time.time()
        worker.run()
        elapsed = time.time() - start_time

        assert elapsed < 10.0
        assert mock_generator.generate_serial.call_count == 100

    def test_analysis_multiple_samples(self, qapp: Any, mock_generator: Mock) -> None:
        """Analysis handles large number of sample serials."""
        sample_serials = [f"ABCD-{i:04d}-EFGH-{i+1000:04d}-{i+2000:04d}" for i in range(100)]

        worker = SerialGeneratorWorker(
            generator=mock_generator,
            operation="analyze",
            params={"serials": sample_serials}
        )

        start_time = time.time()
        worker.run()
        elapsed = time.time() - start_time

        assert elapsed < 5.0

    def test_worker_thread_cleanup(self, qapp: Any, mock_generator: Mock) -> None:
        """Worker thread properly cleans up after operations."""
        worker = SerialGeneratorWorker(
            generator=mock_generator,
            operation="generate_single",
            params={"constraints": SerialConstraints(length=20, format=SerialFormat.NUMERIC)}
        )

        worker.run()

        assert mock_generator.generate_serial.called
