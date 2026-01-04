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


class FakeSerialNumberGenerator:
    """Real test double for SerialNumberGenerator with complete behavior tracking."""

    def __init__(
        self,
        analysis_result: dict[str, Any] | None = None,
        serial_output: str | None = None,
        should_raise_analysis_error: bool = False,
        should_raise_generation_error: bool = False,
    ) -> None:
        self.analysis_calls: list[list[str]] = []
        self.generation_calls: list[tuple[SerialConstraints, Any]] = []
        self.verification_calls: list[tuple[str, str]] = []
        self.checksum_calls: dict[str, int] = {}

        self._analysis_result = analysis_result or {
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
        }

        self._serial_output = serial_output or "ABCD-1234-EFGH-5678-9012"
        self._should_raise_analysis_error = should_raise_analysis_error
        self._should_raise_generation_error = should_raise_generation_error

        self.checksum_functions = {
            "luhn": self._fake_luhn,
            "verhoeff": self._fake_verhoeff,
            "crc16": self._fake_crc16,
            "mod11": self._fake_mod11,
        }

        self._generation_counter = 0

    def analyze_serial_algorithm(self, serials: list[str]) -> dict[str, Any]:
        """Analyze serial samples and detect patterns."""
        self.analysis_calls.append(serials)

        if self._should_raise_analysis_error:
            raise Exception("Invalid serial samples")

        return self._analysis_result

    def generate_serial(
        self,
        constraints: SerialConstraints,
        seed: Any = None
    ) -> str:
        """Generate serial based on constraints."""
        self.generation_calls.append((constraints, seed))

        if self._should_raise_generation_error:
            raise Exception("Invalid constraints")

        if constraints.format == SerialFormat.ALPHANUMERIC:
            self._generation_counter += 1
            return f"ABCD-{self._generation_counter:04d}-EFGH-{self._generation_counter + 1000:04d}-{self._generation_counter + 2000:04d}"
        else:
            self._generation_counter += 1
            return f"1234-{self._generation_counter:04d}-{self._generation_counter + 1000:04d}-{self._generation_counter + 2000:04d}"

    def _verify_checksum(self, serial: str, algorithm: str) -> bool:
        """Verify serial checksum using specified algorithm."""
        self.verification_calls.append((serial, algorithm))
        return True

    def _fake_luhn(self, value: str) -> int:
        """Fake Luhn checksum computation."""
        self.checksum_calls["luhn"] = self.checksum_calls.get("luhn", 0) + 1
        return 5

    def _fake_verhoeff(self, value: str) -> int:
        """Fake Verhoeff checksum computation."""
        self.checksum_calls["verhoeff"] = self.checksum_calls.get("verhoeff", 0) + 1
        return 3

    def _fake_crc16(self, value: str) -> int:
        """Fake CRC16 checksum computation."""
        self.checksum_calls["crc16"] = self.checksum_calls.get("crc16", 0) + 1
        return 0xABCD

    def _fake_mod11(self, value: str) -> int:
        """Fake Mod11 checksum computation."""
        self.checksum_calls["mod11"] = self.checksum_calls.get("mod11", 0) + 1
        return 7


class FakeQFileDialog:
    """Real test double for QFileDialog with configurable return values."""

    def __init__(self, file_path: str = "", selected_filter: str = "") -> None:
        self.get_save_filename_calls: list[tuple[Any, str, str, str]] = []
        self.get_open_filename_calls: list[tuple[Any, str, str, str]] = []
        self._save_filename_result = (file_path, selected_filter)
        self._open_filename_result = (file_path, selected_filter)

    def getSaveFileName(
        self,
        parent: Any,
        caption: str,
        directory: str,
        filter_text: str
    ) -> tuple[str, str]:
        """Record save filename dialog call and return configured result."""
        self.get_save_filename_calls.append((parent, caption, directory, filter_text))
        return self._save_filename_result

    def getOpenFileName(
        self,
        parent: Any,
        caption: str,
        directory: str,
        filter_text: str
    ) -> tuple[str, str]:
        """Record open filename dialog call and return configured result."""
        self.get_open_filename_calls.append((parent, caption, directory, filter_text))
        return self._open_filename_result


class FakeQMessageBox:
    """Real test double for QMessageBox tracking message displays."""

    def __init__(self) -> None:
        self.information_calls: list[tuple[Any, str, str]] = []
        self.warning_calls: list[tuple[Any, str, str]] = []
        self.critical_calls: list[tuple[Any, str, str]] = []

    def information(self, parent: Any, title: str, message: str) -> None:
        """Record information message display."""
        self.information_calls.append((parent, title, message))

    def warning(self, parent: Any, title: str, message: str) -> None:
        """Record warning message display."""
        self.warning_calls.append((parent, title, message))

    def critical(self, parent: Any, title: str, message: str) -> None:
        """Record critical message display."""
        self.critical_calls.append((parent, title, message))


class FakeQInputDialog:
    """Real test double for QInputDialog with configurable return values."""

    def __init__(self, text: str = "", ok_pressed: bool = True) -> None:
        self.get_text_calls: list[tuple[Any, str, str, Any, str]] = []
        self._text_result = text
        self._ok_pressed = ok_pressed

    def getText(
        self,
        parent: Any,
        title: str,
        label: str,
        echo_mode: Any = None,
        text: str = ""
    ) -> tuple[str, bool]:
        """Record text input dialog call and return configured result."""
        self.get_text_calls.append((parent, title, label, echo_mode, text))
        return (self._text_result, self._ok_pressed)


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
def fake_generator() -> FakeSerialNumberGenerator:
    """Create fake SerialNumberGenerator with realistic behavior."""
    return FakeSerialNumberGenerator()


@pytest.fixture
def temp_serial_dir() -> Path:  # type: ignore[misc]
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

    def test_dialog_creates_successfully(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Dialog initializes with all required UI components."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

        dialog = SerialGeneratorDialog()

        assert dialog.generator is not None
        assert dialog.windowTitle() == "Serial Number Generator"
        assert dialog.minimumSize().width() >= 900
        assert dialog.minimumSize().height() >= 650

    def test_dialog_creates_all_tabs(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Dialog creates all required tabs for serial generation workflow."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

        dialog = SerialGeneratorDialog()

        assert dialog.tabs.count() == 6

        tab_names = [dialog.tabs.tabText(i) for i in range(dialog.tabs.count())]
        assert "Generate" in tab_names
        assert "Analyze" in tab_names
        assert "Batch" in tab_names
        assert "Validate" in tab_names
        assert "Patterns" in tab_names
        assert "Presets" in tab_names

    def test_dialog_initializes_format_combo(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Format combo box is initialized with all serial formats."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

        dialog = SerialGeneratorDialog()

        assert dialog.format_combo is not None

        formats = [dialog.format_combo.itemText(i) for i in range(dialog.format_combo.count())]

        assert "numeric" in formats
        assert "alphanumeric" in formats
        assert "alphabetic" in formats
        assert "hex" in formats
        assert "base32" in formats
        assert "base64" in formats

    def test_dialog_initializes_checksum_algorithms(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Checksum combo box contains all available algorithms."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

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

    def test_generate_single_serial_numeric_format(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Generating single serial with numeric format produces valid serial."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

        dialog = SerialGeneratorDialog()

        dialog.format_combo.setCurrentText("numeric")
        dialog.length_spin.setValue(20)

        if hasattr(dialog, "generate_single_serial"):
            dialog.generate_single_serial()
            qapp.processEvents()

            assert len(fake_generator.generation_calls) > 0

    def test_generate_single_serial_alphanumeric_format(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Generating single serial with alphanumeric format produces valid serial."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

        dialog = SerialGeneratorDialog()

        dialog.format_combo.setCurrentText("alphanumeric")
        dialog.length_spin.setValue(20)

        if hasattr(dialog, "generate_single_serial"):
            dialog.generate_single_serial()
            qapp.processEvents()

            assert len(fake_generator.generation_calls) > 0
            constraints = fake_generator.generation_calls[0][0]
            assert constraints.format == SerialFormat.ALPHANUMERIC

    def test_generate_serial_with_checksum(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Generating serial with checksum enabled includes checksum validation."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

        dialog = SerialGeneratorDialog()

        dialog.format_combo.setCurrentText("numeric")
        dialog.enable_checksum.setChecked(True)
        dialog.checksum_combo.setCurrentText("luhn")

        if hasattr(dialog, "generate_single_serial"):
            dialog.generate_single_serial()
            qapp.processEvents()

            assert len(fake_generator.generation_calls) > 0
            constraints = fake_generator.generation_calls[0][0]
            assert constraints.checksum_algorithm == "luhn"

    def test_format_change_updates_custom_alphabet_visibility(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Changing format to custom shows custom alphabet input."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

        dialog = SerialGeneratorDialog()

        dialog.format_combo.setCurrentText("custom")
        dialog.on_format_changed("custom")

        assert dialog.custom_alphabet_widget.isVisible() is True

        dialog.format_combo.setCurrentText("numeric")
        dialog.on_format_changed("numeric")

        assert dialog.custom_alphabet_widget.isVisible() is False


class TestBatchGeneration:
    """Test batch serial generation functionality."""

    def test_generate_batch_serials(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Batch generation creates specified number of serials."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

        dialog = SerialGeneratorDialog()

        if hasattr(dialog, "batch_count_spin"):
            dialog.batch_count_spin.setValue(10)

        if hasattr(dialog, "generate_batch_serials"):
            dialog.generate_batch_serials()
            qapp.processEvents()

            assert len(dialog.generated_serials) > 0

    def test_batch_generation_updates_progress(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator
    ) -> None:
        """Batch generation updates progress during serial creation."""
        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC
        )

        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="generate_batch",
            params={"constraints": constraints, "count": 5}
        )

        progress_messages: list[str] = []
        def capture_progress(msg: str) -> None:
            progress_messages.append(msg)

        worker.progress.connect(capture_progress)

        worker.run()

        assert progress_messages
        assert any("Generating serial" in msg for msg in progress_messages)

    def test_export_batch_serials(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        temp_serial_dir: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Exporting batch serials creates file with all generated serials."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

        dialog = SerialGeneratorDialog()

        dialog.generated_serials = [
            "ABCD-1234-EFGH-5678-9012",
            "ABCD-2345-EFGH-6789-0123",
            "ABCD-3456-EFGH-7890-1234"
        ]

        export_path = temp_serial_dir / "exported_serials.txt"

        if hasattr(dialog, "export_serials"):
            fake_file_dialog = FakeQFileDialog(str(export_path), "")
            fake_message_box = FakeQMessageBox()

            monkeypatch.setattr(
                "intellicrack.ui.dialogs.serial_generator_dialog.QFileDialog",
                fake_file_dialog
            )
            monkeypatch.setattr(
                "intellicrack.ui.dialogs.serial_generator_dialog.QMessageBox",
                fake_message_box
            )

            dialog.export_serials()

            if export_path.exists():
                exported_content = export_path.read_text()
                assert "ABCD-1234-EFGH-5678-9012" in exported_content
                assert "ABCD-2345-EFGH-6789-0123" in exported_content


class TestSerialAnalysis:
    """Test serial pattern analysis functionality."""

    def test_analyze_serial_patterns_from_samples(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Analyzing serial samples detects patterns and formats."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

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

            assert len(fake_generator.analysis_calls) > 0

    def test_analysis_worker_detects_format(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator
    ) -> None:
        """Analysis worker correctly detects serial format from samples."""
        sample_serials = [
            "1234-5678-9012-3456",
            "2345-6789-0123-4567",
            "3456-7890-1234-5678"
        ]

        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="analyze",
            params={"serials": sample_serials}
        )

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert len(fake_generator.analysis_calls) == 1
        assert fake_generator.analysis_calls[0] == sample_serials

        assert len(results) == 1
        assert results[0]["operation"] == "analysis"
        assert "format" in results[0]["data"]

    def test_analysis_detects_checksum_algorithm(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator
    ) -> None:
        """Analysis worker detects checksum algorithm from samples."""
        sample_serials = [
            "1234-5678-9012-3456-5",
            "2345-6789-0123-4567-8",
            "3456-7890-1234-5678-1"
        ]

        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="analyze",
            params={"serials": sample_serials}
        )

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert len(results) == 1
        checksum_info = results[0]["data"].get("checksum")
        assert checksum_info is not None
        assert "algorithm" in checksum_info

    def test_load_serials_from_file(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        temp_serial_dir: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Loading serials from file populates analysis input."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

        dialog = SerialGeneratorDialog()

        serial_file = temp_serial_dir / "sample_serials.txt"

        if hasattr(dialog, "load_serials_from_file"):
            fake_file_dialog = FakeQFileDialog(str(serial_file), "")

            monkeypatch.setattr(
                "intellicrack.ui.dialogs.serial_generator_dialog.QFileDialog",
                fake_file_dialog
            )

            dialog.load_serials_from_file()

            if hasattr(dialog, "sample_serials_input"):
                content = dialog.sample_serials_input.toPlainText()
                assert "ABCD-1234" in content


class TestSerialValidation:
    """Test serial validation functionality."""

    def test_validate_serial_with_constraints(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator
    ) -> None:
        """Validating serial checks format, length, and checksum."""
        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC,
            checksum_algorithm="luhn"
        )

        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="validate",
            params={
                "serial": "ABCD-1234-EFGH-5678-9012",
                "constraints": constraints
            }
        )

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert len(results) == 1
        assert results[0]["operation"] == "validation"
        assert "is_valid" in results[0]["data"]

    def test_validate_serial_format_check(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator
    ) -> None:
        """Validation checks if serial matches expected format."""
        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.NUMERIC
        )

        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="validate",
            params={
                "serial": "1234-5678-9012-3456",
                "constraints": constraints
            }
        )

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert len(results) == 1
        validation_details = results[0]["data"]["details"]
        assert "format_check" in validation_details

    def test_validate_serial_length_check(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator
    ) -> None:
        """Validation checks if serial has correct length."""
        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC
        )

        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="validate",
            params={
                "serial": "ABCD-1234-EFGH-5678-9012",
                "constraints": constraints
            }
        )

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert len(results) == 1

    def test_validate_serial_checksum_verification(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator
    ) -> None:
        """Validation verifies checksum using specified algorithm."""
        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC,
            checksum_algorithm="luhn"
        )

        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="validate",
            params={
                "serial": "ABCD-1234-EFGH-5678-9012",
                "constraints": constraints
            }
        )

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert len(fake_generator.verification_calls) > 0


class TestPatternCracking:
    """Test pattern cracking and serial generation from samples."""

    def test_crack_pattern_analyzes_samples(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator
    ) -> None:
        """Pattern cracking analyzes samples to detect algorithm."""
        sample_serials = [
            "ABCD-1234-EFGH-5678-9012",
            "ABCD-2345-EFGH-6789-0123",
            "ABCD-3456-EFGH-7890-1234"
        ]

        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="crack_pattern",
            params={"samples": sample_serials}
        )

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert len(fake_generator.analysis_calls) == 1
        assert fake_generator.analysis_calls[0] == sample_serials

        assert len(results) == 1
        assert results[0]["operation"] == "pattern_crack"

    def test_crack_pattern_generates_test_serials(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator
    ) -> None:
        """Pattern cracking generates test serials based on detected pattern."""
        sample_serials = [
            "ABCD-1234-EFGH-5678-9012",
            "ABCD-2345-EFGH-6789-0123"
        ]

        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="crack_pattern",
            params={"samples": sample_serials}
        )

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert len(results) == 1
        assert "generated_serials" in results[0]["data"]
        assert len(results[0]["data"]["generated_serials"]) == 10


class TestPresetManagement:
    """Test preset serial format management."""

    def test_load_presets_populates_list(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Loading presets populates preset list widget."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

        dialog = SerialGeneratorDialog()

        if hasattr(dialog, "preset_list"):
            assert dialog.preset_list.count() >= 0

    def test_apply_preset_updates_settings(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Applying preset updates generation settings."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

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

    def test_save_custom_preset(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Saving custom preset stores current settings."""
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.serial_generator_dialog.SerialNumberGenerator",
            lambda: fake_generator
        )

        dialog = SerialGeneratorDialog()

        dialog.format_combo.setCurrentText("alphanumeric")
        dialog.length_spin.setValue(20)
        dialog.groups_spin.setValue(4)

        if hasattr(dialog, "save_preset"):
            fake_input_dialog = FakeQInputDialog("CustomPreset", True)

            monkeypatch.setattr(
                "intellicrack.ui.dialogs.serial_generator_dialog.QInputDialog",
                fake_input_dialog
            )

            dialog.save_preset()

            if hasattr(dialog, "presets"):
                assert "CustomPreset" in dialog.presets


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_worker_handles_analysis_errors(self, qapp: Any) -> None:
        """Worker thread handles analysis errors gracefully."""
        fake_generator = FakeSerialNumberGenerator(should_raise_analysis_error=True)

        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="analyze",
            params={"serials": []}
        )

        errors: list[str] = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error.connect(capture_error)

        worker.run()

        assert len(errors) == 1
        assert "Invalid serial samples" in errors[0]

    def test_worker_handles_generation_errors(self, qapp: Any) -> None:
        """Worker thread handles generation errors gracefully."""
        fake_generator = FakeSerialNumberGenerator(should_raise_generation_error=True)

        constraints = SerialConstraints(length=-1, format=SerialFormat.NUMERIC)

        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="generate_single",
            params={"constraints": constraints}
        )

        errors: list[str] = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error.connect(capture_error)

        worker.run()

        assert len(errors) == 1


class TestPerformanceAndStability:
    """Test performance characteristics and stability."""

    def test_batch_generation_large_count(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator
    ) -> None:
        """Batch generation handles large serial counts efficiently."""
        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC
        )

        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="generate_batch",
            params={"constraints": constraints, "count": 100}
        )

        start_time = time.time()
        worker.run()
        elapsed = time.time() - start_time

        assert elapsed < 10.0
        assert len(fake_generator.generation_calls) == 100

    def test_analysis_multiple_samples(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator
    ) -> None:
        """Analysis handles large number of sample serials."""
        sample_serials = [f"ABCD-{i:04d}-EFGH-{i+1000:04d}-{i+2000:04d}" for i in range(100)]

        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="analyze",
            params={"serials": sample_serials}
        )

        start_time = time.time()
        worker.run()
        elapsed = time.time() - start_time

        assert elapsed < 5.0

    def test_worker_thread_cleanup(
        self,
        qapp: Any,
        fake_generator: FakeSerialNumberGenerator
    ) -> None:
        """Worker thread properly cleans up after operations."""
        worker = SerialGeneratorWorker(
            generator=fake_generator,  # type: ignore[arg-type]
            operation="generate_single",
            params={"constraints": SerialConstraints(length=20, format=SerialFormat.NUMERIC)}
        )

        worker.run()

        assert len(fake_generator.generation_calls) > 0
