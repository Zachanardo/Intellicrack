"""
UI setup functions for Intellicrack. 

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


from typing import Any, Optional

# Optional imports with graceful fallbacks
from .common_imports import HAS_PYQT

if HAS_PYQT:
    from .common_imports import (
        QComboBox,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QPlainTextEdit,
        QProgressBar,
        QPushButton,
        QSpinBox,
        QSplitter,
        Qt,
        QTableWidget,
        QTimer,
        QVBoxLayout,
        QWidget,
    )

try:
    import matplotlib
    matplotlib.use('Qt5Agg')
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

from ..utils.logger import setup_logger

logger = setup_logger(__name__)


def setup_dataset_tab(parent: Any) -> Optional[Any]:
    """Set up the dataset management tab."""
    if not HAS_PYQT:
        logger.warning("PyQt5 not available, cannot create dataset tab")
        return None

    tab = QWidget()
    layout = QVBoxLayout()

    # Dataset controls
    controls_layout = QHBoxLayout()

    # Dataset selection
    dataset_label = QLabel("Dataset:")
    dataset_combo = QComboBox()
    dataset_combo.setObjectName("dataset_combo")
    dataset_combo.addItems(["None", "Custom", "JSONL", "CSV", "TXT"])

    browse_btn = QPushButton("Browse...")
    browse_btn.setObjectName("browse_dataset_btn")

    controls_layout.addWidget(dataset_label)
    controls_layout.addWidget(dataset_combo)
    controls_layout.addWidget(browse_btn)
    controls_layout.addStretch()

    layout.addLayout(controls_layout)

    # Dataset preview
    preview_group = QGroupBox("Dataset Preview")
    preview_layout = QVBoxLayout()

    preview_table = QTableWidget()
    preview_table.setObjectName("dataset_preview_table")
    preview_table.setAlternatingRowColors(True)
    preview_layout.addWidget(preview_table)

    preview_group.setLayout(preview_layout)
    layout.addWidget(preview_group)

    # Dataset statistics
    stats_group = QGroupBox("Dataset Statistics")
    stats_layout = QHBoxLayout()

    stats_labels = [
        ("Total Samples:", "0"),
        ("Training:", "0"),
        ("Validation:", "0"),
        ("Test:", "0"),
        ("Features:", "0")
    ]

    for label_text, default_value in stats_labels:
        label = QLabel(label_text)
        value = QLabel(default_value)
        value.setObjectName(f"dataset_{label_text.lower().replace(' ', '_').rstrip(':')}_value")
        stats_layout.addWidget(label)
        stats_layout.addWidget(value)
        stats_layout.addSpacing(20)

    stats_layout.addStretch()
    stats_group.setLayout(stats_layout)
    layout.addWidget(stats_group)

    # Dataset operations
    operations_group = QGroupBox("Dataset Operations")
    operations_layout = QHBoxLayout()

    split_btn = QPushButton("Split Dataset")
    split_btn.setObjectName("split_dataset_btn")

    augment_btn = QPushButton("Augment Data")
    augment_btn.setObjectName("augment_dataset_btn")

    clean_btn = QPushButton("Clean Dataset")
    clean_btn.setObjectName("clean_dataset_btn")

    export_btn = QPushButton("Export Dataset")
    export_btn.setObjectName("export_dataset_btn")

    operations_layout.addWidget(split_btn)
    operations_layout.addWidget(augment_btn)
    operations_layout.addWidget(clean_btn)
    operations_layout.addWidget(export_btn)
    operations_layout.addStretch()

    operations_group.setLayout(operations_layout)
    layout.addWidget(operations_group)

    # Dataset visualization
    if HAS_MATPLOTLIB:
        viz_group = QGroupBox("Data Visualization")
        viz_layout = QVBoxLayout()

        figure = Figure(figsize=(8, 4))
        canvas = FigureCanvas(figure)
        canvas.setObjectName("dataset_viz_canvas")
        viz_layout.addWidget(canvas)

        viz_group.setLayout(viz_layout)
        layout.addWidget(viz_group)

    layout.addStretch()
    tab.setLayout(layout)

    return tab


def setup_memory_monitor(parent: Any) -> Optional[Any]:
    """Set up memory monitoring widget."""
    if not HAS_PYQT:
        logger.warning("PyQt5 not available, cannot create memory monitor")
        return None

    widget = QWidget()
    layout = QVBoxLayout()

    # Memory stats
    stats_layout = QHBoxLayout()

    # Current memory usage
    current_label = QLabel("Current Memory:")
    current_value = QLabel("0 MB")
    current_value.setObjectName("current_memory_value")

    # Peak memory usage
    peak_label = QLabel("Peak Memory:")
    peak_value = QLabel("0 MB")
    peak_value.setObjectName("peak_memory_value")

    # Available memory
    available_label = QLabel("Available:")
    available_value = QLabel("0 MB")
    available_value.setObjectName("available_memory_value")

    stats_layout.addWidget(current_label)
    stats_layout.addWidget(current_value)
    stats_layout.addSpacing(20)
    stats_layout.addWidget(peak_label)
    stats_layout.addWidget(peak_value)
    stats_layout.addSpacing(20)
    stats_layout.addWidget(available_label)
    stats_layout.addWidget(available_value)
    stats_layout.addStretch()

    layout.addLayout(stats_layout)

    # Memory usage bar
    memory_bar = QProgressBar()
    memory_bar.setObjectName("memory_usage_bar")
    memory_bar.setTextVisible(True)
    memory_bar.setFormat("%p% (%v MB / %m MB)")
    layout.addWidget(memory_bar)

    # Memory history graph
    if HAS_MATPLOTLIB:
        figure = Figure(figsize=(8, 3))
        canvas = FigureCanvas(figure)
        canvas.setObjectName("memory_history_canvas")
        layout.addWidget(canvas)

    # Memory controls
    controls_layout = QHBoxLayout()

    gc_btn = QPushButton("Force GC")
    gc_btn.setObjectName("force_gc_btn")
    gc_btn.setToolTip("Force garbage collection")

    clear_cache_btn = QPushButton("Clear Cache")
    clear_cache_btn.setObjectName("clear_cache_btn")

    optimize_btn = QPushButton("Optimize Memory")
    optimize_btn.setObjectName("optimize_memory_btn")

    controls_layout.addWidget(gc_btn)
    controls_layout.addWidget(clear_cache_btn)
    controls_layout.addWidget(optimize_btn)
    controls_layout.addStretch()

    layout.addLayout(controls_layout)

    # Process list
    process_group = QGroupBox("Process Memory Usage")
    process_layout = QVBoxLayout()

    process_table = QTableWidget()
    process_table.setObjectName("process_memory_table")
    process_table.setColumnCount(4)
    process_table.setHorizontalHeaderLabels(["Process", "PID", "Memory (MB)", "CPU %"])
    process_table.horizontalHeader().setStretchLastSection(True)
    process_layout.addWidget(process_table)

    process_group.setLayout(process_layout)
    layout.addWidget(process_group)

    widget.setLayout(layout)

    # Set up auto-refresh timer
    timer = QTimer(widget)
    timer.setObjectName("memory_refresh_timer")
    timer.setInterval(1000)  # Update every second

    return widget


def setup_training_tab(parent: Any) -> Optional[Any]:
    """Set up the model training tab."""
    if not HAS_PYQT:
        logger.warning("PyQt5 not available, cannot create training tab")
        return None

    tab = QWidget()
    layout = QVBoxLayout()

    # Model selection
    model_group = QGroupBox("Model Configuration")
    model_layout = QVBoxLayout()

    # Model type selection
    model_type_layout = QHBoxLayout()
    model_type_label = QLabel("Model Type:")
    model_type_combo = QComboBox()
    model_type_combo.setObjectName("model_type_combo")
    model_type_combo.addItems([
        "Random Forest", "XGBoost", "Neural Network",
        "SVM", "Logistic Regression", "Ensemble"
    ])

    model_type_layout.addWidget(model_type_label)
    model_type_layout.addWidget(model_type_combo)
    model_type_layout.addStretch()
    model_layout.addLayout(model_type_layout)

    # Hyperparameters
    hyperparam_layout = QHBoxLayout()

    # Learning rate
    lr_label = QLabel("Learning Rate:")
    lr_spin = QSpinBox()
    lr_spin.setObjectName("learning_rate_spin")
    lr_spin.setRange(1, 1000)
    lr_spin.setValue(100)
    lr_spin.setSuffix(" x 0.001")

    # Epochs
    epochs_label = QLabel("Epochs:")
    epochs_spin = QSpinBox()
    epochs_spin.setObjectName("epochs_spin")
    epochs_spin.setRange(1, 1000)
    epochs_spin.setValue(10)

    # Batch size
    batch_label = QLabel("Batch Size:")
    batch_spin = QSpinBox()
    batch_spin.setObjectName("batch_size_spin")
    batch_spin.setRange(1, 512)
    batch_spin.setValue(32)

    hyperparam_layout.addWidget(lr_label)
    hyperparam_layout.addWidget(lr_spin)
    hyperparam_layout.addSpacing(20)
    hyperparam_layout.addWidget(epochs_label)
    hyperparam_layout.addWidget(epochs_spin)
    hyperparam_layout.addSpacing(20)
    hyperparam_layout.addWidget(batch_label)
    hyperparam_layout.addWidget(batch_spin)
    hyperparam_layout.addStretch()

    model_layout.addLayout(hyperparam_layout)
    model_group.setLayout(model_layout)
    layout.addWidget(model_group)

    # Training controls
    controls_layout = QHBoxLayout()

    start_btn = QPushButton("Start Training")
    start_btn.setObjectName("start_training_btn")
    start_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; }")

    pause_btn = QPushButton("Pause")
    pause_btn.setObjectName("pause_training_btn")
    pause_btn.setEnabled(False)

    stop_btn = QPushButton("Stop")
    stop_btn.setObjectName("stop_training_btn")
    stop_btn.setEnabled(False)
    stop_btn.setStyleSheet("QPushButton:enabled { background-color: #f44336; color: white; }")

    save_btn = QPushButton("Save Model")
    save_btn.setObjectName("save_model_btn")
    save_btn.setEnabled(False)

    controls_layout.addWidget(start_btn)
    controls_layout.addWidget(pause_btn)
    controls_layout.addWidget(stop_btn)
    controls_layout.addWidget(save_btn)
    controls_layout.addStretch()

    layout.addLayout(controls_layout)

    # Training progress
    progress_group = QGroupBox("Training Progress")
    progress_layout = QVBoxLayout()

    # Progress bar
    progress_bar = QProgressBar()
    progress_bar.setObjectName("training_progress_bar")
    progress_bar.setTextVisible(True)
    progress_layout.addWidget(progress_bar)

    # Status text
    status_text = QLabel("Ready to train")
    status_text.setObjectName("training_status_text")
    progress_layout.addWidget(status_text)

    progress_group.setLayout(progress_layout)
    layout.addWidget(progress_group)

    # Training metrics
    metrics_group = QGroupBox("Training Metrics")
    metrics_layout = QVBoxLayout()

    # Metrics display
    metrics_layout_inner = QHBoxLayout()

    metrics_labels = [
        ("Loss:", "0.0"),
        ("Accuracy:", "0.0%"),
        ("Val Loss:", "0.0"),
        ("Val Accuracy:", "0.0%"),
        ("Epoch:", "0/0"),
        ("Time:", "00:00:00")
    ]

    for label_text, default_value in metrics_labels:
        label = QLabel(label_text)
        value = QLabel(default_value)
        value.setObjectName(f"training_{label_text.lower().replace(' ', '_').rstrip(':')}_value")
        metrics_layout_inner.addWidget(label)
        metrics_layout_inner.addWidget(value)
        metrics_layout_inner.addSpacing(15)

    metrics_layout_inner.addStretch()
    metrics_layout.addLayout(metrics_layout_inner)

    # Loss/accuracy graphs
    if HAS_MATPLOTLIB:
        graphs_splitter = QSplitter(Qt.Horizontal)

        # Loss graph
        loss_figure = Figure(figsize=(4, 3))
        loss_canvas = FigureCanvas(loss_figure)
        loss_canvas.setObjectName("training_loss_canvas")
        graphs_splitter.addWidget(loss_canvas)

        # Accuracy graph
        acc_figure = Figure(figsize=(4, 3))
        acc_canvas = FigureCanvas(acc_figure)
        acc_canvas.setObjectName("training_accuracy_canvas")
        graphs_splitter.addWidget(acc_canvas)

        metrics_layout.addWidget(graphs_splitter)

    metrics_group.setLayout(metrics_layout)
    layout.addWidget(metrics_group)

    # Training log
    log_group = QGroupBox("Training Log")
    log_layout = QVBoxLayout()

    log_text = QPlainTextEdit()
    log_text.setObjectName("training_log_text")
    log_text.setReadOnly(True)
    log_text.setMaximumBlockCount(1000)
    log_layout.addWidget(log_text)

    log_group.setLayout(log_layout)
    layout.addWidget(log_group)

    tab.setLayout(layout)

    return tab


# Export all functions
__all__ = [
    'setup_dataset_tab',
    'setup_memory_monitor',
    'setup_training_tab'
]
