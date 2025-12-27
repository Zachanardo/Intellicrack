"""UI setup functions for Intellicrack.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

from collections.abc import Callable

from intellicrack.handlers.pyqt6_handler import HAS_PYQT
from intellicrack.types.ui import WidgetProtocol

from ..logger import setup_logger


# Forward declare widget class types for conditional assignment
# Using 'type' as the annotation allows both PyQt6 classes and fallback classes
QWidget: type
QVBoxLayout: type
QHBoxLayout: type
QLabel: type
QComboBox: type
QPushButton: type
QGroupBox: type
QTableWidget: type
QProgressBar: type
QSpinBox: type
QSplitter: type
QPlainTextEdit: type
QTimer: type
Qt: type


if HAS_PYQT:
    from intellicrack.handlers.pyqt6_handler import (
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
else:
    # Define production-ready fallback classes when PyQt6 is not available
    # These provide headless operation capabilities for CI/CD and server environments
    class HeadlessWidget:
        """Production fallback widget for headless operation."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            self._args = args
            self._kwargs = kwargs
            self._attributes: dict[str, object] = {}
            self._children: list[object] = []
            self._parent: object | None = None
            self._visible = False
            self._enabled = True
            self._name = kwargs.get("objectName", f"widget_{id(self)}")

        def setParent(self, parent: object) -> None:
            self._parent = parent
            if parent and hasattr(parent, "_children"):
                parent._children.append(self)

        def show(self) -> None:
            self._visible = True

        def hide(self) -> None:
            self._visible = False

        def setEnabled(self, enabled: bool) -> None:
            self._enabled = enabled

        def setText(self, text: str) -> None:
            self._attributes["text"] = text

        def text(self) -> str:
            result = self._attributes.get("text", "")
            return str(result) if result is not None else ""

        def setValue(self, value: int) -> None:
            self._attributes["value"] = value

        def value(self) -> int:
            result = self._attributes.get("value", 0)
            return int(result) if isinstance(result, (int, float)) else 0

        def addWidget(self, widget: object) -> None:
            if widget and hasattr(widget, "setParent"):
                widget.setParent(self)

        def addLayout(self, layout: object) -> None:
            if layout:
                self._children.append(layout)

        def __getattr__(self, name: str) -> Callable[..., None]:
            def method(*args: object, **kwargs: object) -> None:
                return None

            return method

    class HeadlessLayout(HeadlessWidget):
        """Production fallback layout for headless operation."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)
            self._spacing = 0
            self._margin: tuple[int, int, int, int] = (0, 0, 0, 0)

        def setSpacing(self, spacing: int) -> None:
            self._spacing = spacing

        def setContentsMargins(self, left: int, top: int, right: int, bottom: int) -> None:
            self._margin = (left, top, right, bottom)

    class HeadlessTimer:
        """Production fallback timer for headless operation."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            self._interval = 1000
            self._active = False
            self._single_shot = False

        def start(self, interval: int | None = None) -> None:
            if interval:
                self._interval = interval
            self._active = True

        def stop(self) -> None:
            self._active = False

        def setInterval(self, interval: int) -> None:
            self._interval = interval

        def setSingleShot(self, single: bool) -> None:
            self._single_shot = single

        @staticmethod
        def singleShot(interval: int, callback: Callable[..., None]) -> None:
            if callable(callback):
                callback()

    class HeadlessQt:
        """Production fallback Qt namespace for headless operation."""

        AlignCenter = 0x0004
        AlignLeft = 0x0001
        AlignRight = 0x0002
        Horizontal = 0x1
        Vertical = 0x2
        LeftButton = 0x1
        RightButton = 0x2

    QWidget = HeadlessWidget
    QVBoxLayout = HeadlessLayout
    QHBoxLayout = HeadlessLayout
    QLabel = HeadlessWidget
    QComboBox = HeadlessWidget
    QPushButton = HeadlessWidget
    QGroupBox = HeadlessWidget
    QTableWidget = HeadlessWidget
    QProgressBar = HeadlessWidget
    QSpinBox = HeadlessWidget
    QSplitter = HeadlessWidget
    QPlainTextEdit = HeadlessWidget
    QTimer = HeadlessTimer
    Qt = HeadlessQt


logger = setup_logger(__name__)


HAS_MATPLOTLIB = False
Figure: type | None = None
FigureCanvas: type | None = None

try:
    from intellicrack.handlers.matplotlib_handler import (
        HAS_MATPLOTLIB,
        Figure,
        FigureCanvasQTAgg as FigureCanvas,
    )
except ImportError as e:
    logger.exception("Import error in ui_setup_functions: %s", e)


def setup_dataset_tab(parent: object) -> WidgetProtocol | None:
    """Set up the dataset management tab.

    Configure and initialize a dataset management tab widget with controls for
    dataset selection, preview, statistics, operations, and visualization.

    Args:
        parent: Parent widget for proper widget hierarchy.

    Returns:
        Configured dataset management widget, or None if PyQt6 is unavailable.

    """
    if not HAS_PYQT:
        logger.warning("PyQt6 not available, cannot create dataset tab")
        return None

    parent_widget = parent if hasattr(parent, "setLayout") else None
    tab: WidgetProtocol = QWidget(parent_widget)
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
        ("Features:", "0"),
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
    if HAS_MATPLOTLIB and Figure is not None and FigureCanvas is not None:
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


def setup_memory_monitor(parent: object) -> WidgetProtocol | None:
    """Set up memory monitoring widget.

    Create a memory monitoring widget with statistics display, usage bar,
    history visualization, and garbage collection controls.

    Args:
        parent: Parent widget for proper widget hierarchy.

    Returns:
        Configured memory monitor widget, or None if PyQt6 is unavailable.

    """
    if not HAS_PYQT:
        logger.warning("PyQt6 not available, cannot create memory monitor")
        return None

    parent_widget = parent if hasattr(parent, "setLayout") else None
    widget: WidgetProtocol = QWidget(parent_widget)
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
    if HAS_MATPLOTLIB and Figure is not None and FigureCanvas is not None:
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
    header = process_table.horizontalHeader()
    if header is not None:
        header.setStretchLastSection(True)
    process_layout.addWidget(process_table)

    process_group.setLayout(process_layout)
    layout.addWidget(process_group)

    widget.setLayout(layout)

    timer = QTimer(widget)
    timer.setObjectName("memory_refresh_timer")
    timer.setInterval(1000)

    return widget


def setup_training_tab(parent: object) -> WidgetProtocol | None:
    """Set up the model training tab.

    Initialize a comprehensive model training interface with configuration,
    progress tracking, metrics visualization, and training logs.

    Args:
        parent: Parent widget for proper widget hierarchy.

    Returns:
        Configured training tab widget, or None if PyQt6 is unavailable.

    """
    if not HAS_PYQT:
        logger.warning("PyQt6 not available, cannot create training tab")
        return None

    parent_widget = parent if hasattr(parent, "setLayout") else None
    tab: WidgetProtocol = QWidget(parent_widget)
    layout = QVBoxLayout()

    # Model selection
    model_group = QGroupBox("Model Configuration")
    model_layout = QVBoxLayout()

    # Model type selection
    model_type_layout = QHBoxLayout()
    model_type_label = QLabel("Model Type:")
    model_type_combo = QComboBox()
    model_type_combo.setObjectName("model_type_combo")
    model_type_combo.addItems(
        [
            "Random Forest",
            "XGBoost",
            "Neural Network",
            "SVM",
            "Logistic Regression",
            "Ensemble",
        ],
    )

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
        ("Time:", "00:00:00"),
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
    if HAS_MATPLOTLIB and Figure is not None and FigureCanvas is not None:
        horizontal_orientation = getattr(Qt, "Horizontal", 0x1)
        graphs_splitter = QSplitter(horizontal_orientation)

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


__all__ = [
    "setup_dataset_tab",
    "setup_memory_monitor",
    "setup_training_tab",
]
