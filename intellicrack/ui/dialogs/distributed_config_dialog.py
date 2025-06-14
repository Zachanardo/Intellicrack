"""
Distributed Processing Configuration Dialog 

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import multiprocessing
from typing import Any, Dict

from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QSpinBox,
    QVBoxLayout,
)

__all__ = ['DistributedProcessingConfigDialog']


class DistributedProcessingConfigDialog(QDialog):
    """
    Configuration dialog for distributed processing setup.

    Provides a user interface for configuring distributed processing parameters
    including worker count, chunk sizes, analysis options, and pattern types.
    """

    def __init__(self, binary_path: str, parent=None):
        """
        Initialize the distributed processing configuration dialog.

        Args:
            binary_path: Path to the binary for distributed processing
            parent: Optional parent widget
        """
        super().__init__(parent)
        self.binary_path = binary_path
        self.setWindowTitle("Distributed Processing Configuration")
        self.setModal(True)
        self.setup_ui()

    def setup_ui(self) -> None:
        """Set up the dialog user interface."""
        layout = QVBoxLayout()

        # Header
        header_label = QLabel(f"<b>Configure distributed processing for:</b><br>{self.binary_path}")
        layout.addWidget(header_label)

        # Processing options
        processing_group = QGroupBox("Processing Options")
        processing_layout = QFormLayout()

        # Workers
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 32)
        self.workers_spin.setValue(multiprocessing.cpu_count())
        self.workers_spin.setToolTip("Number of worker processes to use")
        processing_layout.addRow("Workers:", self.workers_spin)

        # Chunk size
        self.chunk_size_spin = QSpinBox()
        self.chunk_size_spin.setRange(1, 100)
        self.chunk_size_spin.setValue(1)
        self.chunk_size_spin.setSuffix(" MB")
        self.chunk_size_spin.setToolTip("Size of chunks for processing")
        processing_layout.addRow("Chunk size:", self.chunk_size_spin)

        # Window size for entropy analysis
        self.window_size_spin = QSpinBox()
        self.window_size_spin.setRange(1, 1024)
        self.window_size_spin.setValue(64)
        self.window_size_spin.setSuffix(" KB")
        self.window_size_spin.setToolTip("Size of sliding window for entropy analysis")
        processing_layout.addRow("Window size:", self.window_size_spin)

        # Timeout
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(10, 3600)
        self.timeout_spin.setValue(60)
        self.timeout_spin.setSuffix(" seconds")
        self.timeout_spin.setToolTip("Timeout for processing")
        processing_layout.addRow("Timeout:", self.timeout_spin)

        # Backend selection
        self.backend_combo = QComboBox()
        self.backend_combo.addItem("Auto (select best available)")
        self.backend_combo.addItem("Ray")
        self.backend_combo.addItem("Dask")
        self.backend_combo.addItem("Multiprocessing")
        self.backend_combo.setToolTip("Processing backend to use")
        processing_layout.addRow("Backend:", self.backend_combo)

        # Convenience methods
        self.convenience_check = QCheckBox("Use convenience methods")
        self.convenience_check.setChecked(True)
        self.convenience_check.setToolTip("Use built-in convenience methods instead of task queue for common operations")
        processing_layout.addRow("", self.convenience_check)

        processing_group.setLayout(processing_layout)
        layout.addWidget(processing_group)

        # Analysis options
        analysis_group = QGroupBox("Analysis Options")
        analysis_layout = QVBoxLayout()

        # Section analysis
        self.section_check = QCheckBox("Analyze sections")
        self.section_check.setChecked(True)
        self.section_check.setToolTip("Analyze binary sections")
        analysis_layout.addWidget(self.section_check)

        # Pattern search
        self.pattern_check = QCheckBox("Search for patterns")
        self.pattern_check.setChecked(True)
        self.pattern_check.setToolTip("Search for _patterns in the binary")
        analysis_layout.addWidget(self.pattern_check)

        # Entropy analysis
        self.entropy_check = QCheckBox("Analyze entropy")
        self.entropy_check.setChecked(True)
        self.entropy_check.setToolTip("Analyze entropy distribution")
        analysis_layout.addWidget(self.entropy_check)

        # Symbolic execution
        self.symbolic_check = QCheckBox("Run symbolic execution (experimental)")
        self.symbolic_check.setChecked(False)
        self.symbolic_check.setToolTip("Run symbolic execution on selected functions")
        analysis_layout.addWidget(self.symbolic_check)

        # Pattern types
        pattern_group = QGroupBox("Pattern Types")
        pattern_layout = QVBoxLayout()

        self.license_check = QCheckBox("License/registration patterns")
        self.license_check.setChecked(True)
        pattern_layout.addWidget(self.license_check)

        self.hardware_check = QCheckBox("Hardware ID patterns")
        self.hardware_check.setChecked(True)
        pattern_layout.addWidget(self.hardware_check)

        self.crypto_check = QCheckBox("Cryptography patterns")
        self.crypto_check.setChecked(True)
        pattern_layout.addWidget(self.crypto_check)

        self.custom_patterns_edit = QLineEdit()
        self.custom_patterns_edit.setPlaceholder("Custom patterns (comma-separated)")
        self.custom_patterns_edit.setToolTip("Enter custom patterns to search for, separated by commas")
        pattern_layout.addWidget(self.custom_patterns_edit)

        pattern_group.setLayout(pattern_layout)
        analysis_layout.addWidget(pattern_group)

        analysis_group.setLayout(analysis_layout)
        layout.addWidget(analysis_group)

        # Performance hint
        perf_hint = QLabel(
            "<i>Tip: For large binaries (>100MB), consider using Ray or Dask backends "
            "with smaller chunk sizes for better performance.</i>"
        )
        perf_hint.setWordWrap(True)
        layout.addWidget(perf_hint)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def get_config(self) -> Dict[str, Any]:
        """
        Get the configuration from the dialog.

        Returns:
            Dictionary containing all configuration parameters
        """
        # Parse any custom patterns
        custom_patterns = []
        if self.custom_patterns_edit.text().strip():
            custom_patterns = [_p.strip() for _p in self.custom_patterns_edit.text().split(',')]

        # Map backend selection to value
        backend_map = {
            0: "auto",
            1: "ray",
            2: "dask",
            3: "multiprocessing"
        }
        preferred_backend = backend_map.get(self.backend_combo.currentIndex(), "auto")

        return {
            # Processing options
            'num_workers': self.workers_spin.value(),
            'chunk_size': self.chunk_size_spin.value() * 1024 * 1024,  # Convert MB to bytes
            'window_size_kb': self.window_size_spin.value(),
            'timeout': self.timeout_spin.value(),
            'preferred_backend': preferred_backend,
            'use_convenience_methods': self.convenience_check.isChecked(),

            # Analysis options
            'run_section_analysis': self.section_check.isChecked(),
            'run_pattern_search': self.pattern_check.isChecked(),
            'run_entropy_analysis': self.entropy_check.isChecked(),
            'run_symbolic_execution': self.symbolic_check.isChecked(),

            # Pattern types
            'search_license_patterns': self.license_check.isChecked(),
            'search_hardware_patterns': self.hardware_check.isChecked(),
            'search_crypto_patterns': self.crypto_check.isChecked(),
            'custom_patterns': custom_patterns,

            # Binary path
            'binary_path': self.binary_path
        }

    def set_defaults(self, config: Dict[str, Any]) -> None:
        """
        Set default values from a configuration dictionary.

        Args:
            config: Configuration dictionary to apply
        """
        if 'num_workers' in config:
            self.workers_spin.setValue(config['num_workers'])

        if 'chunk_size' in config:
            # Convert bytes to MB
            chunk_size_mb = config['chunk_size'] // (1024 * 1024)
            self.chunk_size_spin.setValue(chunk_size_mb)

        if 'window_size_kb' in config:
            self.window_size_spin.setValue(config['window_size_kb'])

        if 'timeout' in config:
            self.timeout_spin.setValue(config['timeout'])

        if 'preferred_backend' in config:
            backend_index = {
                "auto": 0,
                "ray": 1,
                "dask": 2,
                "multiprocessing": 3
            }.get(config['preferred_backend'], 0)
            self.backend_combo.setCurrentIndex(backend_index)

        if 'use_convenience_methods' in config:
            self.convenience_check.setChecked(config['use_convenience_methods'])

        # Analysis options
        if 'run_section_analysis' in config:
            self.section_check.setChecked(config['run_section_analysis'])

        if 'run_pattern_search' in config:
            self.pattern_check.setChecked(config['run_pattern_search'])

        if 'run_entropy_analysis' in config:
            self.entropy_check.setChecked(config['run_entropy_analysis'])

        if 'run_symbolic_execution' in config:
            self.symbolic_check.setChecked(config['run_symbolic_execution'])

        # Pattern types
        if 'search_license_patterns' in config:
            self.license_check.setChecked(config['search_license_patterns'])

        if 'search_hardware_patterns' in config:
            self.hardware_check.setChecked(config['search_hardware_patterns'])

        if 'search_crypto_patterns' in config:
            self.crypto_check.setChecked(config['search_crypto_patterns'])

        if 'custom_patterns' in config and config['custom_patterns']:
            self.custom_patterns_edit.setText(', '.join(config['custom_patterns']))

    def validate_config(self) -> bool:
        """
        Validate the current configuration.

        Returns:
            True if configuration is valid, False otherwise
        """
        # Basic validation
        if self.workers_spin.value() < 1:
            return False

        if self.chunk_size_spin.value() < 1:
            return False

        if self.timeout_spin.value() < 10:
            return False

        # Check if at least one analysis option is selected
        analysis_selected = (
            self.section_check.isChecked() or
            self.pattern_check.isChecked() or
            self.entropy_check.isChecked() or
            self.symbolic_check.isChecked()
        )

        return analysis_selected


def create_distributed_config_dialog(binary_path: str, parent=None) -> DistributedProcessingConfigDialog:
    """
    Factory function to create a DistributedProcessingConfigDialog.

    Args:
        binary_path: Path to binary for processing
        parent: Parent widget

    Returns:
        Configured dialog instance
    """
    return DistributedProcessingConfigDialog(binary_path, parent)
