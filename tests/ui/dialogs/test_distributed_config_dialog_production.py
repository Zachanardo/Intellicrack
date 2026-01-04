"""Production tests for distributed processing configuration dialog.

Validates real distributed processing configuration management including worker
allocation, backend selection, chunk sizing, and pattern search configuration
for large-scale binary analysis workflows.
"""

import multiprocessing
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication
from intellicrack.ui.dialogs.distributed_config_dialog import (
    DistributedProcessingConfigDialog,
    create_distributed_config_dialog,
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        return QApplication([])
    assert isinstance(app, QApplication), "Expected QApplication instance"
    return app


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    """Create sample binary file for testing."""
    binary_path = tmp_path / "test_binary.exe"
    binary_path.write_bytes(b"MZ\x90\x00\x03\x00" + b"\x00" * 1000)
    return binary_path


@pytest.fixture
def config_dialog(qapp: QApplication, sample_binary: Path) -> DistributedProcessingConfigDialog:
    """Create distributed config dialog."""
    return DistributedProcessingConfigDialog(str(sample_binary))


def test_dialog_initialization(qapp: QApplication, sample_binary: Path) -> None:
    """Dialog initializes with correct window title and binary path."""
    dialog = DistributedProcessingConfigDialog(str(sample_binary))

    assert dialog.windowTitle() == "Distributed Processing Configuration"
    assert dialog.binary_path == str(sample_binary)


def test_default_workers_matches_cpu_count(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Workers spin box defaults to CPU count."""
    expected_cpu_count = multiprocessing.cpu_count()

    assert config_dialog.workers_spin.value() == expected_cpu_count


def test_workers_spin_has_valid_range(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Workers spin box has valid range from 1 to 32."""
    assert config_dialog.workers_spin.minimum() == 1
    assert config_dialog.workers_spin.maximum() == 32


def test_chunk_size_defaults_to_one_mb(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Chunk size spin box defaults to 1 MB."""
    assert config_dialog.chunk_size_spin.value() == 1


def test_chunk_size_has_mb_suffix(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Chunk size displays MB suffix."""
    assert " MB" in config_dialog.chunk_size_spin.suffix()


def test_window_size_defaults_to_64kb(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Window size spin box defaults to 64 KB."""
    assert config_dialog.window_size_spin.value() == 64


def test_timeout_defaults_to_60_seconds(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Timeout spin box defaults to 60 seconds."""
    assert config_dialog.timeout_spin.value() == 60


def test_timeout_has_valid_range(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Timeout has valid range from 10 to 3600 seconds."""
    assert config_dialog.timeout_spin.minimum() == 10
    assert config_dialog.timeout_spin.maximum() == 3600


def test_backend_combo_has_all_options(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Backend combo box contains all backend options."""
    backends = [config_dialog.backend_combo.itemText(i) for i in range(config_dialog.backend_combo.count())]

    assert any("Auto" in backend for backend in backends)
    assert any("Ray" in backend for backend in backends)
    assert any("Dask" in backend for backend in backends)
    assert any("Multiprocessing" in backend for backend in backends)


def test_convenience_methods_enabled_by_default(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Convenience methods checkbox is checked by default."""
    assert config_dialog.convenience_check.isChecked()


def test_section_analysis_enabled_by_default(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Section analysis checkbox is checked by default."""
    assert config_dialog.section_check.isChecked()


def test_pattern_search_enabled_by_default(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Pattern search checkbox is checked by default."""
    assert config_dialog.pattern_check.isChecked()


def test_entropy_analysis_enabled_by_default(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Entropy analysis checkbox is checked by default."""
    assert config_dialog.entropy_check.isChecked()


def test_symbolic_execution_disabled_by_default(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Symbolic execution checkbox is unchecked by default."""
    assert not config_dialog.symbolic_check.isChecked()


def test_license_patterns_enabled_by_default(config_dialog: DistributedProcessingConfigDialog) -> None:
    """License patterns checkbox is checked by default."""
    assert config_dialog.license_check.isChecked()


def test_hardware_patterns_enabled_by_default(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Hardware patterns checkbox is checked by default."""
    assert config_dialog.hardware_check.isChecked()


def test_crypto_patterns_enabled_by_default(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Cryptography patterns checkbox is checked by default."""
    assert config_dialog.crypto_check.isChecked()


def test_get_config_returns_correct_structure(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config returns dictionary with all expected keys."""
    config = config_dialog.get_config()

    assert isinstance(config, dict)
    assert "num_workers" in config
    assert "chunk_size" in config
    assert "window_size_kb" in config
    assert "timeout" in config
    assert "preferred_backend" in config
    assert "use_convenience_methods" in config
    assert "run_section_analysis" in config
    assert "run_pattern_search" in config
    assert "run_entropy_analysis" in config
    assert "run_symbolic_execution" in config
    assert "search_license_patterns" in config
    assert "search_hardware_patterns" in config
    assert "search_crypto_patterns" in config
    assert "custom_patterns" in config
    assert "binary_path" in config


def test_get_config_workers_value(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config returns correct worker count."""
    config_dialog.workers_spin.setValue(8)

    config = config_dialog.get_config()

    assert config["num_workers"] == 8


def test_get_config_chunk_size_converts_mb_to_bytes(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config converts chunk size from MB to bytes."""
    config_dialog.chunk_size_spin.setValue(5)

    config = config_dialog.get_config()

    assert config["chunk_size"] == 5 * 1024 * 1024


def test_get_config_window_size_in_kb(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config returns window size in KB."""
    config_dialog.window_size_spin.setValue(128)

    config = config_dialog.get_config()

    assert config["window_size_kb"] == 128


def test_get_config_timeout_in_seconds(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config returns timeout in seconds."""
    config_dialog.timeout_spin.setValue(300)

    config = config_dialog.get_config()

    assert config["timeout"] == 300


def test_get_config_backend_mapping_auto(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config maps backend selection to auto."""
    config_dialog.backend_combo.setCurrentIndex(0)

    config = config_dialog.get_config()

    assert config["preferred_backend"] == "auto"


def test_get_config_backend_mapping_ray(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config maps backend selection to ray."""
    config_dialog.backend_combo.setCurrentIndex(1)

    config = config_dialog.get_config()

    assert config["preferred_backend"] == "ray"


def test_get_config_backend_mapping_dask(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config maps backend selection to dask."""
    config_dialog.backend_combo.setCurrentIndex(2)

    config = config_dialog.get_config()

    assert config["preferred_backend"] == "dask"


def test_get_config_backend_mapping_multiprocessing(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config maps backend selection to multiprocessing."""
    config_dialog.backend_combo.setCurrentIndex(3)

    config = config_dialog.get_config()

    assert config["preferred_backend"] == "multiprocessing"


def test_get_config_convenience_methods_flag(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config returns convenience methods flag."""
    config_dialog.convenience_check.setChecked(False)

    config = config_dialog.get_config()

    assert config["use_convenience_methods"] is False


def test_get_config_analysis_options(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config returns all analysis option flags."""
    config_dialog.section_check.setChecked(False)
    config_dialog.pattern_check.setChecked(True)
    config_dialog.entropy_check.setChecked(False)
    config_dialog.symbolic_check.setChecked(True)

    config = config_dialog.get_config()

    assert config["run_section_analysis"] is False
    assert config["run_pattern_search"] is True
    assert config["run_entropy_analysis"] is False
    assert config["run_symbolic_execution"] is True


def test_get_config_pattern_types(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config returns all pattern type flags."""
    config_dialog.license_check.setChecked(True)
    config_dialog.hardware_check.setChecked(False)
    config_dialog.crypto_check.setChecked(True)

    config = config_dialog.get_config()

    assert config["search_license_patterns"] is True
    assert config["search_hardware_patterns"] is False
    assert config["search_crypto_patterns"] is True


def test_get_config_custom_patterns_parsing(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config parses custom patterns from comma-separated input."""
    config_dialog.custom_patterns_edit.setText("pattern1, pattern2, pattern3")

    config = config_dialog.get_config()

    assert isinstance(config["custom_patterns"], list)
    assert len(config["custom_patterns"]) == 3
    assert "pattern1" in config["custom_patterns"]
    assert "pattern2" in config["custom_patterns"]
    assert "pattern3" in config["custom_patterns"]


def test_get_config_custom_patterns_whitespace_handling(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config handles whitespace in custom patterns."""
    config_dialog.custom_patterns_edit.setText("  spaced , more  spaces  ,trailing  ")

    config = config_dialog.get_config()

    assert "spaced" in config["custom_patterns"]
    assert "more  spaces" in config["custom_patterns"]
    assert "trailing" in config["custom_patterns"]


def test_get_config_empty_custom_patterns(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Get config returns empty list for empty custom patterns."""
    config_dialog.custom_patterns_edit.setText("")

    config = config_dialog.get_config()

    assert config["custom_patterns"] == []


def test_get_config_binary_path_included(config_dialog: DistributedProcessingConfigDialog, sample_binary: Path) -> None:
    """Get config includes binary path."""
    config = config_dialog.get_config()

    assert config["binary_path"] == str(sample_binary)


def test_set_defaults_workers(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Set defaults updates worker count."""
    config_dialog.set_defaults({"num_workers": 16})

    assert config_dialog.workers_spin.value() == 16


def test_set_defaults_chunk_size_converts_bytes_to_mb(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Set defaults converts chunk size from bytes to MB."""
    config_dialog.set_defaults({"chunk_size": 10 * 1024 * 1024})

    assert config_dialog.chunk_size_spin.value() == 10


def test_set_defaults_window_size(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Set defaults updates window size."""
    config_dialog.set_defaults({"window_size_kb": 256})

    assert config_dialog.window_size_spin.value() == 256


def test_set_defaults_timeout(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Set defaults updates timeout."""
    config_dialog.set_defaults({"timeout": 600})

    assert config_dialog.timeout_spin.value() == 600


def test_set_defaults_backend_auto(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Set defaults sets backend to auto."""
    config_dialog.set_defaults({"preferred_backend": "auto"})

    assert config_dialog.backend_combo.currentIndex() == 0


def test_set_defaults_backend_ray(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Set defaults sets backend to ray."""
    config_dialog.set_defaults({"preferred_backend": "ray"})

    assert config_dialog.backend_combo.currentIndex() == 1


def test_set_defaults_backend_dask(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Set defaults sets backend to dask."""
    config_dialog.set_defaults({"preferred_backend": "dask"})

    assert config_dialog.backend_combo.currentIndex() == 2


def test_set_defaults_backend_multiprocessing(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Set defaults sets backend to multiprocessing."""
    config_dialog.set_defaults({"preferred_backend": "multiprocessing"})

    assert config_dialog.backend_combo.currentIndex() == 3


def test_set_defaults_convenience_methods(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Set defaults updates convenience methods flag."""
    config_dialog.set_defaults({"use_convenience_methods": False})

    assert not config_dialog.convenience_check.isChecked()


def test_set_defaults_analysis_options(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Set defaults updates all analysis options."""
    config_dialog.set_defaults({
        "run_section_analysis": False,
        "run_pattern_search": True,
        "run_entropy_analysis": False,
        "run_symbolic_execution": True,
    })

    assert not config_dialog.section_check.isChecked()
    assert config_dialog.pattern_check.isChecked()
    assert not config_dialog.entropy_check.isChecked()
    assert config_dialog.symbolic_check.isChecked()


def test_set_defaults_pattern_types(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Set defaults updates all pattern type options."""
    config_dialog.set_defaults({
        "search_license_patterns": False,
        "search_hardware_patterns": True,
        "search_crypto_patterns": False,
    })

    assert not config_dialog.license_check.isChecked()
    assert config_dialog.hardware_check.isChecked()
    assert not config_dialog.crypto_check.isChecked()


def test_set_defaults_custom_patterns(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Set defaults updates custom patterns field."""
    config_dialog.set_defaults({"custom_patterns": ["test1", "test2", "test3"]})

    assert "test1" in config_dialog.custom_patterns_edit.text()
    assert "test2" in config_dialog.custom_patterns_edit.text()
    assert "test3" in config_dialog.custom_patterns_edit.text()


def test_set_defaults_partial_config(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Set defaults handles partial configuration without errors."""
    original_workers = config_dialog.workers_spin.value()

    config_dialog.set_defaults({"chunk_size": 2 * 1024 * 1024})

    assert config_dialog.chunk_size_spin.value() == 2
    assert config_dialog.workers_spin.value() == original_workers


def test_validate_config_passes_with_defaults(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Validate config passes with default values."""
    assert config_dialog.validate_config() is True


def test_validate_config_fails_with_zero_workers(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Validate config fails with zero workers."""
    config_dialog.workers_spin.setValue(0)

    assert config_dialog.validate_config() is False


def test_validate_config_fails_with_zero_chunk_size(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Validate config fails with zero chunk size."""
    config_dialog.chunk_size_spin.setValue(0)

    assert config_dialog.validate_config() is False


def test_validate_config_fails_with_low_timeout(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Validate config fails with timeout below 10 seconds."""
    config_dialog.timeout_spin.setValue(5)

    assert config_dialog.validate_config() is False


def test_validate_config_fails_with_no_analysis_options(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Validate config fails when no analysis options are selected."""
    config_dialog.section_check.setChecked(False)
    config_dialog.pattern_check.setChecked(False)
    config_dialog.entropy_check.setChecked(False)
    config_dialog.symbolic_check.setChecked(False)

    assert config_dialog.validate_config() is False


def test_validate_config_passes_with_any_single_analysis_option(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Validate config passes with at least one analysis option."""
    config_dialog.section_check.setChecked(False)
    config_dialog.pattern_check.setChecked(False)
    config_dialog.entropy_check.setChecked(False)
    config_dialog.symbolic_check.setChecked(True)

    assert config_dialog.validate_config() is True


def test_factory_function_creates_dialog(qapp: QApplication, sample_binary: Path) -> None:
    """Factory function creates valid dialog instance."""
    dialog = create_distributed_config_dialog(str(sample_binary))

    assert isinstance(dialog, DistributedProcessingConfigDialog)
    assert dialog.binary_path == str(sample_binary)


def test_roundtrip_config_preservation(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Config roundtrip through get and set preserves values."""
    test_config = {
        "num_workers": 12,
        "chunk_size": 8 * 1024 * 1024,
        "window_size_kb": 512,
        "timeout": 900,
        "preferred_backend": "dask",
        "use_convenience_methods": False,
        "run_section_analysis": True,
        "run_pattern_search": False,
        "run_entropy_analysis": True,
        "run_symbolic_execution": False,
        "search_license_patterns": False,
        "search_hardware_patterns": True,
        "search_crypto_patterns": False,
        "custom_patterns": ["custom1", "custom2"],
    }

    config_dialog.set_defaults(test_config)
    result_config = config_dialog.get_config()

    assert result_config["num_workers"] == 12
    assert result_config["chunk_size"] == 8 * 1024 * 1024
    assert result_config["window_size_kb"] == 512
    assert result_config["timeout"] == 900
    assert result_config["preferred_backend"] == "dask"
    assert result_config["use_convenience_methods"] is False
    assert result_config["run_section_analysis"] is True
    assert result_config["run_pattern_search"] is False
    assert result_config["run_entropy_analysis"] is True
    assert result_config["run_symbolic_execution"] is False
    assert result_config["search_license_patterns"] is False
    assert result_config["search_hardware_patterns"] is True
    assert result_config["search_crypto_patterns"] is False
    assert "custom1" in result_config["custom_patterns"]
    assert "custom2" in result_config["custom_patterns"]


def test_max_workers_boundary(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Workers can be set to maximum value."""
    config_dialog.workers_spin.setValue(32)

    config = config_dialog.get_config()
    assert config["num_workers"] == 32
    assert config_dialog.validate_config() is True


def test_max_timeout_boundary(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Timeout can be set to maximum value."""
    config_dialog.timeout_spin.setValue(3600)

    config = config_dialog.get_config()
    assert config["timeout"] == 3600
    assert config_dialog.validate_config() is True


def test_min_valid_timeout_boundary(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Timeout at minimum valid value passes validation."""
    config_dialog.timeout_spin.setValue(10)

    assert config_dialog.validate_config() is True


def test_large_chunk_size_handling(config_dialog: DistributedProcessingConfigDialog) -> None:
    """Large chunk sizes are handled correctly."""
    config_dialog.chunk_size_spin.setValue(100)

    config = config_dialog.get_config()
    assert config["chunk_size"] == 100 * 1024 * 1024
