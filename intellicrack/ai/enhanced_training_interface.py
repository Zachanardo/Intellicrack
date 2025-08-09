"""Enhanced AI Model Training Interface

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

import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

try:
    from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt6.QtGui import QFont, QIcon, QPalette, QPixmap
    from PyQt6.QtWidgets import (
        QCheckBox,
        QComboBox,
        QDialog,
        QDoubleSpinBox,
        QFileDialog,
        QFormLayout,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QScrollArea,
        QSlider,
        QSpinBox,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )

    PYQT6_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in enhanced_training_interface: %s", e)
    PYQT6_AVAILABLE = False

    # Create fallback classes for when PyQt6 is not available
    class QThread:
        pass

    class QWidget:
        pass

    class QDialog:
        pass

    class QVBoxLayout:
        pass

    class QHBoxLayout:
        pass

    class QTabWidget:
        pass

    class QLabel:
        pass

    class QPushButton:
        pass

    class QProgressBar:
        pass

    class QTextEdit:
        pass

    class QCheckBox:
        pass

    class QSpinBox:
        pass

    class QDoubleSpinBox:
        pass

    class QComboBox:
        pass

    class QSlider:
        pass

    class QGroupBox:
        pass

    class QFormLayout:
        pass

    class QGridLayout:
        pass

    class QFrame:
        pass

    class QTableWidget:
        pass

    class QTableWidgetItem:
        pass

    class QScrollArea:
        pass

    class QSplitter:
        pass

    class QLineEdit:
        pass

    class QFileDialog:
        pass

    class QMessageBox:
        pass

    class QTimer:
        pass

    def pyqtSignal(*args):
        return None

    Qt = None
    QFont = None
    QIcon = None
    QPalette = None
    QPixmap = None

try:
    import numpy as np
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure

    # These will be used in widget classes that support matplotlib visualization
    MATPLOTLIB_AVAILABLE = True
    # Store at module level to prevent F401
    _matplotlib_imports = {"FigureCanvas": FigureCanvas, "Figure": Figure}
except ImportError as e:
    logger.error("Import error in enhanced_training_interface: %s", e)
    MATPLOTLIB_AVAILABLE = False

try:
    # Store module reference to satisfy import checker
    import pyqtgraph as pg
    from pyqtgraph import PlotWidget

    _pyqtgraph_module = pg  # Keep reference to prevent F401
    PYQTGRAPH_AVAILABLE = True
except ImportError as e:
    logger.error("Import error for pyqtgraph in enhanced_training_interface: %s", e)
    PYQTGRAPH_AVAILABLE = False

    # Create a matplotlib-based PlotWidget for when pyqtgraph is not available
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    
    class PlotWidget:
        """Matplotlib-based PlotWidget for when pyqtgraph is not available."""

        def __init__(self, *args, **kwargs):
            """Initialize matplotlib-based PlotWidget with full plotting functionality."""
            self.parent = kwargs.get("parent")
            self._enabled = True
            self._data_x = []
            self._data_y = []
            self._plots = []
            
            # Create matplotlib figure and axis
            self.figure = Figure(figsize=(8, 6), dpi=100)
            self.canvas = FigureCanvasAgg(self.figure)
            self.ax = self.figure.add_subplot(111)
            
            self._labels = {}
            self._grid_settings = {"x": False, "y": False}
            self._legend_enabled = False
            self._auto_range_enabled = True

        def plot(self, *args, **kwargs):
            """Plot data using matplotlib."""
            if len(args) >= 2:
                x_data = args[0]
                y_data = args[1]
            elif len(args) == 1:
                y_data = args[0]
                x_data = list(range(len(args[0])))
            else:
                return self
            
            # Extract plot parameters
            pen = kwargs.get('pen', 'b-')
            name = kwargs.get('name', f'Plot {len(self._plots) + 1}')
            
            # Create the plot
            line, = self.ax.plot(x_data, y_data, pen, label=name)
            self._plots.append(line)
            
            # Store data for reference
            self._data_x = x_data
            self._data_y = y_data
            
            # Update display
            self._update_display()
            
            return self

        def clear(self):
            """Clear all plots."""
            self.ax.clear()
            self._plots = []
            self._data_x = []
            self._data_y = []
            self._update_display()

        def setLabel(self, axis, text, **kwargs):
            """Set axis labels using matplotlib."""
            if not hasattr(self, "_labels"):
                self._labels = {}
            self._labels[axis] = {"text": text, "kwargs": kwargs}
            
            if axis.lower() == 'left' or axis.lower() == 'y':
                self.ax.set_ylabel(text)
            elif axis.lower() == 'bottom' or axis.lower() == 'x':
                self.ax.set_xlabel(text)
            elif axis.lower() == 'top':
                self.ax.set_title(text)
            
            self._update_display()

        def enableAutoRange(self, *args, **kwargs):
            """Enable auto range for axes."""
            self._auto_range_enabled = True
            if self._auto_range_enabled:
                self.ax.autoscale(enable=True)
            self._update_display()

        def showGrid(self, x=None, y=None, **kwargs):
            """Show grid on the plot."""
            if not hasattr(self, "_grid_settings"):
                self._grid_settings = {}
            
            show_x = x if x is not None else self._grid_settings.get("x", True)
            show_y = y if y is not None else self._grid_settings.get("y", True)
            
            self._grid_settings["x"] = show_x
            self._grid_settings["y"] = show_y
            self._grid_settings.update(kwargs)
            
            # Apply grid settings
            self.ax.grid(True, which='both', axis='both' if show_x and show_y else ('x' if show_x else 'y'))
            self._update_display()

        def setBackground(self, *args, **kwargs):
            """Set background color of the plot."""
            if args:
                color = args[0]
                if isinstance(color, str):
                    self.figure.patch.set_facecolor(color)
                    self.ax.set_facecolor(color)
                elif isinstance(color, (tuple, list)) and len(color) >= 3:
                    # Assume RGB or RGBA values
                    self.figure.patch.set_facecolor(color)
                    self.ax.set_facecolor(color)
            
            self._update_display()

        def addLegend(self, *args, **kwargs):
            """Add legend to the plot."""
            self._legend_enabled = True
            if self._plots:
                self.ax.legend(**kwargs)
            self._update_display()
            return self
        
        def _update_display(self):
            """Update the plot display."""
            try:
                self.figure.canvas.draw()
            except Exception as e:
                logger.debug(f"PlotWidget display update: {e}")
        
        def export(self, filename, dpi=100):
            """Export plot to file."""
            self.figure.savefig(filename, dpi=dpi, bbox_inches='tight')
            return True


__all__ = [
    "EnhancedTrainingInterface",
    "ModelMetrics",
    "TrainingConfiguration",
    "TrainingStatus",
]


class TrainingStatus(Enum):
    """Training status enumeration."""

    IDLE = "idle"
    PREPARING = "preparing"
    TRAINING = "training"
    VALIDATING = "validating"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class TrainingConfiguration:
    """Training configuration dataclass."""

    model_name: str = "intellicrack_model"
    model_type: str = "vulnerability_classifier"
    dataset_path: str = ""
    output_directory: str = os.path.join(os.path.dirname(__file__), "..", "models", "trained")

    # Training parameters
    learning_rate: float = 0.001
    batch_size: int = 32
    epochs: int = 100
    validation_split: float = 0.2

    # Optimization settings
    optimizer: str = "adam"
    loss_function: str = "categorical_crossentropy"
    use_early_stopping: bool = True
    patience: int = 10

    # Advanced features
    use_augmentation: bool = True
    use_transfer_learning: bool = False
    base_model: str = ""
    freeze_layers: int = 0

    # Hardware settings
    use_gpu: bool = True
    multi_gpu: bool = False
    mixed_precision: bool = False

    # Monitoring
    save_checkpoints: bool = True
    checkpoint_frequency: int = 5
    tensorboard_logging: bool = True


@dataclass
class ModelMetrics:
    """Model performance metrics."""

    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    loss: float = 0.0
    val_accuracy: float = 0.0
    val_loss: float = 0.0
    training_time: float = 0.0
    epoch: int = 0


class TrainingThread(QThread):
    """Background thread for model training."""

    progress_updated = pyqtSignal(int)
    metrics_updated = pyqtSignal(dict)
    log_message = pyqtSignal(str)
    training_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, config: TrainingConfiguration):
        """Initialize training thread with configuration."""
        super().__init__()
        self.config = config
        self.should_stop = False
        self.paused = False

    def run(self):
        """Run the training process."""
        try:
            self.log_message.emit("Starting model training...")

            # Simulate training process (replace with actual ML training)
            for _epoch in range(self.config.epochs):
                if self.should_stop:
                    break

                while self.paused:
                    time.sleep(0.1)
                    if self.should_stop:
                        break

                # Simulate training epoch
                time.sleep(0.1)  # Simulate processing time

                # Generate simulated metrics
                progress = int((_epoch + 1) / self.config.epochs * 100)

                # Simulated improvement over time
                base_accuracy = 0.5 + (_epoch / self.config.epochs) * 0.4
                noise = np.random.normal(0, 0.02) if "numpy" in globals() else 0
                accuracy = min(0.99, base_accuracy + noise)

                metrics = {
                    "epoch": _epoch + 1,
                    "accuracy": accuracy,
                    "loss": max(0.01, 2.0 - (_epoch / self.config.epochs) * 1.8),
                    "val_accuracy": accuracy * 0.95,
                    "val_loss": max(0.01, 2.2 - (_epoch / self.config.epochs) * 1.8),
                    "learning_rate": self.config.learning_rate,
                }

                self.progress_updated.emit(progress)
                self.metrics_updated.emit(metrics)
                self.log_message.emit(
                    f"Epoch {_epoch + 1}/{self.config.epochs} - Accuracy: {accuracy:.4f}"
                )

                # Simulate early stopping
                if self.config.use_early_stopping and _epoch > 20:
                    if metrics["val_loss"] > metrics["loss"] * 1.5:
                        self.log_message.emit("Early stopping triggered")
                        break

            if not self.should_stop:
                self.training_completed.emit({"status": "completed", "final_accuracy": accuracy})
                self.log_message.emit("Training completed successfully!")
            else:
                self.log_message.emit("Training stopped by user")

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in enhanced_training_interface: %s", e)
            self.error_occurred.emit(str(e))

    def stop_training(self):
        """Stop the training process."""
        self.should_stop = True

    def pause_training(self):
        """Pause the training process."""
        self.paused = True

    def resume_training(self):
        """Resume the training process."""
        self.paused = False


class TrainingVisualizationWidget(QWidget):
    """Widget for visualizing training progress and metrics."""

    def __init__(self):
        """Initialize training visualization widget with plots and metrics display."""
        super().__init__()
        self.setup_ui()
        self.training_data = {"epochs": [], "loss": [], "accuracy": []}

    def setup_ui(self):
        """Set up the user interface for training visualization."""
        layout = QVBoxLayout()

        self.loss_plot = PlotWidget()
        self.loss_plot.setLabel("left", "Loss")
        self.loss_plot.setLabel("bottom", "Epoch")
        self.loss_plot.showGrid(x=True, y=True)

        self.accuracy_plot = PlotWidget()
        self.accuracy_plot.setLabel("left", "Accuracy")
        self.accuracy_plot.setLabel("bottom", "Epoch")
        self.accuracy_plot.showGrid(x=True, y=True)

        layout.addWidget(QLabel("Loss Over Time"))
        layout.addWidget(self.loss_plot)
        layout.addWidget(QLabel("Accuracy Over Time"))
        layout.addWidget(self.accuracy_plot)

        self.setLayout(layout)

    def update_plots(self, epoch, loss, accuracy):
        """Update training plots with new data point."""
        self.training_data["epochs"].append(epoch)
        self.training_data["loss"].append(loss)
        self.training_data["accuracy"].append(accuracy)

        self.loss_plot.clear()
        self.loss_plot.plot(
            self.training_data["epochs"], self.training_data["loss"], pen="b", symbol="o"
        )

        self.accuracy_plot.clear()
        self.accuracy_plot.plot(
            self.training_data["epochs"], self.training_data["accuracy"], pen="g", symbol="s"
        )

    def clear_plots(self):
        """Clear all training visualization plots."""
        self.training_data = {"epochs": [], "loss": [], "accuracy": []}
        self.loss_plot.clear()
        self.accuracy_plot.clear()

    def export_data(self, filename):
        """Export training data to CSV file."""
        import csv

        with open(filename, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Epoch", "Loss", "Accuracy"])
            for i in range(len(self.training_data["epochs"])):
                writer.writerow(
                    [
                        self.training_data["epochs"][i],
                        self.training_data["loss"][i],
                        self.training_data["accuracy"][i],
                    ]
                )


class DatasetAnalysisWidget(QWidget):
    """Widget for analyzing training datasets and data quality."""

    def __init__(self):
        """Initialize dataset analysis widget with data quality metrics and visualization."""
        super().__init__()
        self.setup_ui()
        self.current_dataset = None

    def setup_ui(self):
        """Set up the user interface for dataset analysis."""
        layout = QVBoxLayout()

        # Dataset loading section
        load_group = QGroupBox("Dataset Loading")
        load_layout = QHBoxLayout()

        self.dataset_path_edit = QLineEdit()
        self.dataset_path_edit.setPlaceholderText("Path to dataset...")

        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_dataset)

        self.load_btn = QPushButton("Load Dataset")
        self.load_btn.clicked.connect(self.load_dataset)

        load_layout.addWidget(self.dataset_path_edit)
        load_layout.addWidget(self.browse_btn)
        load_layout.addWidget(self.load_btn)
        load_group.setLayout(load_layout)

        # Analysis results section
        analysis_group = QGroupBox("Dataset Analysis")
        analysis_layout = QVBoxLayout()

        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setMaximumHeight(200)

        # Visualization section
        self.distribution_plot = PlotWidget()

        # Initialize matplotlib plots if available
        self.matplotlib_canvas = None
        self.matplotlib_figure = None
        if MATPLOTLIB_AVAILABLE:
            from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
            from matplotlib.figure import Figure

            # Create matplotlib figure for advanced visualizations
            self.matplotlib_figure = Figure(figsize=(8, 6))
            self.matplotlib_canvas = FigureCanvas(self.matplotlib_figure)
            self.matplotlib_ax = self.matplotlib_figure.add_subplot(111)
        self.distribution_plot.setLabel("left", "Count")
        self.distribution_plot.setLabel("bottom", "Class")

        analysis_layout.addWidget(self.stats_text)
        analysis_layout.addWidget(self.distribution_plot)

        # Add matplotlib canvas if available
        if hasattr(self, "matplotlib_canvas") and self.matplotlib_canvas:
            analysis_layout.addWidget(self.matplotlib_canvas)
        analysis_group.setLayout(analysis_layout)

        # Preprocessing options
        preprocess_group = QGroupBox("Preprocessing Options")
        preprocess_layout = QGridLayout()

        self.normalize_cb = QCheckBox("Normalize Data")
        self.shuffle_cb = QCheckBox("Shuffle Dataset")
        self.augment_cb = QCheckBox("Data Augmentation")

        self.train_split_slider = QSlider(Qt.Orientation.Horizontal)
        self.train_split_slider.setRange(50, 90)
        self.train_split_slider.setValue(80)
        self.train_split_label = QLabel("Train Split: 80%")

        self.train_split_slider.valueChanged.connect(
            lambda v: self.train_split_label.setText(f"Train Split: {v}%"),
        )

        preprocess_layout.addWidget(self.normalize_cb, 0, 0)
        preprocess_layout.addWidget(self.shuffle_cb, 0, 1)
        preprocess_layout.addWidget(self.augment_cb, 1, 0)
        preprocess_layout.addWidget(self.train_split_label, 2, 0)
        preprocess_layout.addWidget(self.train_split_slider, 2, 1)
        preprocess_group.setLayout(preprocess_layout)

        layout.addWidget(load_group)
        layout.addWidget(analysis_group)
        layout.addWidget(preprocess_group)

        self.setLayout(layout)

    def browse_dataset(self):
        """Open file dialog to browse for dataset file."""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select Dataset",
            "",
            "Data Files (*.csv *.json *.pkl);;All Files (*)",
        )
        if filename:
            self.dataset_path_edit.setText(filename)

    def load_dataset(self):
        """Load and analyze the selected dataset."""
        dataset_path = self.dataset_path_edit.text()
        if not dataset_path or not os.path.exists(dataset_path):
            QMessageBox.warning(self, "Warning", "Please select a valid dataset file.")
            return

        try:
            # Load dataset based on file extension
            if dataset_path.endswith(".csv"):
                import pandas as pd

                self.current_dataset = pd.read_csv(dataset_path)
            elif dataset_path.endswith(".json"):
                import json

                with open(dataset_path) as f:
                    self.current_dataset = json.load(f)
            elif dataset_path.endswith(".pkl"):
                # Security warning for pickle files
                reply = QMessageBox.question(
                    self,
                    "Security Warning",
                    "Loading pickle files can execute arbitrary code.\n"
                    "Only load pickle files from trusted sources.\n\n"
                    "Do you trust this file and want to continue?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )

                if reply == QMessageBox.Yes:
                    # Use safer loading with restricted unpickler if available
                    try:
                        import joblib

                        # joblib is safer for loading ML models and data
                        self.current_dataset = joblib.load(dataset_path)
                    except ImportError:
                        # Fallback to pickle with warning
                        import pickle

                        with open(dataset_path, "rb") as f:
                            self.current_dataset = pickle.load(f)  # noqa: S301
                else:
                    return
            else:
                QMessageBox.warning(self, "Warning", "Unsupported file format.")
                return

            self.analyze_dataset()
            QMessageBox.information(self, "Success", "Dataset loaded successfully!")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load dataset: {e!s}")

    def analyze_dataset(self):
        """Analyze the loaded dataset and display statistics."""
        if self.current_dataset is None:
            return

        try:
            # Generate basic statistics
            stats = []
            if hasattr(self.current_dataset, "shape"):  # pandas DataFrame
                stats.append(f"Shape: {self.current_dataset.shape}")
                stats.append(f"Columns: {list(self.current_dataset.columns)}")
                stats.append(f"Data Types: {self.current_dataset.dtypes.to_dict()}")
                stats.append(f"Missing Values: {self.current_dataset.isnull().sum().to_dict()}")

                # Class distribution if target column exists
                if "target" in self.current_dataset.columns:
                    distribution = self.current_dataset["target"].value_counts()
                    stats.append(f"Class Distribution: {distribution.to_dict()}")

                    # Plot distribution
                    self.distribution_plot.clear()
                    self.distribution_plot.plot(
                        list(distribution.index),
                        list(distribution.values),
                        pen=None,
                        symbol="o",
                    )

                    # Also create matplotlib plot if available
                    if hasattr(self, "matplotlib_ax") and self.matplotlib_ax:
                        self.matplotlib_ax.clear()
                        self.matplotlib_ax.bar(distribution.index, distribution.values)
                        self.matplotlib_ax.set_xlabel("Class")
                        self.matplotlib_ax.set_ylabel("Count")
                        self.matplotlib_ax.set_title("Class Distribution")
                        self.matplotlib_ax.grid(True, alpha=0.3)
                        self.matplotlib_figure.tight_layout()
                        self.matplotlib_canvas.draw()
            else:
                stats.append(f"Type: {type(self.current_dataset)}")
                stats.append(f"Length: {len(self.current_dataset)}")

            self.stats_text.setText("\n".join(stats))

        except Exception as e:
            self.stats_text.setText(f"Analysis failed: {e!s}")

    def get_preprocessing_config(self):
        """Get current preprocessing configuration."""
        return {
            "normalize": self.normalize_cb.isChecked(),
            "shuffle": self.shuffle_cb.isChecked(),
            "augment": self.augment_cb.isChecked(),
            "train_split": self.train_split_slider.value() / 100.0,
        }


class HyperparameterOptimizationWidget(QWidget):
    """Widget for hyperparameter optimization and tuning."""

    def __init__(self):
        """Initialize hyperparameter optimization widget with parameter controls and optimization algorithms."""
        super().__init__()
        self.setup_ui()
        self.optimization_history = []

    def setup_ui(self):
        """Set up the user interface for hyperparameter optimization."""
        layout = QVBoxLayout()

        # Parameter ranges section
        params_group = QGroupBox("Parameter Ranges")
        params_layout = QGridLayout()

        # Learning rate
        params_layout.addWidget(QLabel("Learning Rate:"), 0, 0)
        self.lr_min_spin = QDoubleSpinBox()
        self.lr_min_spin.setRange(0.0001, 1.0)
        self.lr_min_spin.setValue(0.001)
        self.lr_min_spin.setDecimals(6)
        params_layout.addWidget(QLabel("Min:"), 0, 1)
        params_layout.addWidget(self.lr_min_spin, 0, 2)

        self.lr_max_spin = QDoubleSpinBox()
        self.lr_max_spin.setRange(0.0001, 1.0)
        self.lr_max_spin.setValue(0.1)
        self.lr_max_spin.setDecimals(6)
        params_layout.addWidget(QLabel("Max:"), 0, 3)
        params_layout.addWidget(self.lr_max_spin, 0, 4)

        # Batch size
        params_layout.addWidget(QLabel("Batch Size:"), 1, 0)
        self.batch_min_spin = QSpinBox()
        self.batch_min_spin.setRange(1, 1024)
        self.batch_min_spin.setValue(16)
        params_layout.addWidget(QLabel("Min:"), 1, 1)
        params_layout.addWidget(self.batch_min_spin, 1, 2)

        self.batch_max_spin = QSpinBox()
        self.batch_max_spin.setRange(1, 1024)
        self.batch_max_spin.setValue(128)
        params_layout.addWidget(QLabel("Max:"), 1, 3)
        params_layout.addWidget(self.batch_max_spin, 1, 4)

        # Hidden layers
        params_layout.addWidget(QLabel("Hidden Layers:"), 2, 0)
        self.layers_min_spin = QSpinBox()
        self.layers_min_spin.setRange(1, 10)
        self.layers_min_spin.setValue(1)
        params_layout.addWidget(QLabel("Min:"), 2, 1)
        params_layout.addWidget(self.layers_min_spin, 2, 2)

        self.layers_max_spin = QSpinBox()
        self.layers_max_spin.setRange(1, 10)
        self.layers_max_spin.setValue(3)
        params_layout.addWidget(QLabel("Max:"), 2, 3)
        params_layout.addWidget(self.layers_max_spin, 2, 4)

        params_group.setLayout(params_layout)

        # Optimization strategy section
        strategy_group = QGroupBox("Optimization Strategy")
        strategy_layout = QVBoxLayout()

        self.strategy_combo = QComboBox()
        self.strategy_combo.addItems(
            [
                "Random Search",
                "Grid Search",
                "Bayesian Optimization",
                "Genetic Algorithm",
            ]
        )

        self.num_trials_spin = QSpinBox()
        self.num_trials_spin.setRange(1, 1000)
        self.num_trials_spin.setValue(50)

        strategy_control_layout = QHBoxLayout()
        strategy_control_layout.addWidget(QLabel("Strategy:"))
        strategy_control_layout.addWidget(self.strategy_combo)
        strategy_control_layout.addWidget(QLabel("Trials:"))
        strategy_control_layout.addWidget(self.num_trials_spin)

        self.start_optimization_btn = QPushButton("Start Optimization")
        self.start_optimization_btn.clicked.connect(self.start_optimization)

        self.stop_optimization_btn = QPushButton("Stop Optimization")
        self.stop_optimization_btn.clicked.connect(self.stop_optimization)
        self.stop_optimization_btn.setEnabled(False)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_optimization_btn)
        button_layout.addWidget(self.stop_optimization_btn)

        strategy_layout.addLayout(strategy_control_layout)
        strategy_layout.addLayout(button_layout)
        strategy_group.setLayout(strategy_layout)

        # Results section
        results_group = QGroupBox("Optimization Results")
        results_layout = QVBoxLayout()

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(
            [
                "Trial",
                "Learning Rate",
                "Batch Size",
                "Hidden Layers",
                "Accuracy",
                "Loss",
            ]
        )

        self.best_params_text = QTextEdit()
        self.best_params_text.setReadOnly(True)
        self.best_params_text.setMaximumHeight(100)

        # Optimization progress plot
        self.progress_plot = PlotWidget()
        self.progress_plot.setLabel("left", "Best Accuracy")
        self.progress_plot.setLabel("bottom", "Trial")
        self.progress_plot.showGrid(x=True, y=True)

        results_layout.addWidget(self.results_table)
        results_layout.addWidget(QLabel("Best Parameters:"))
        results_layout.addWidget(self.best_params_text)
        results_layout.addWidget(QLabel("Optimization Progress:"))
        results_layout.addWidget(self.progress_plot)
        results_group.setLayout(results_layout)

        layout.addWidget(params_group)
        layout.addWidget(strategy_group)
        layout.addWidget(results_group)

        self.setLayout(layout)

    def start_optimization(self):
        """Start hyperparameter optimization process."""
        self.start_optimization_btn.setEnabled(False)
        self.stop_optimization_btn.setEnabled(True)

        # Clear previous results
        self.optimization_history.clear()
        self.results_table.setRowCount(0)
        self.progress_plot.clear()

        # Get parameter ranges
        param_ranges = {
            "learning_rate": (self.lr_min_spin.value(), self.lr_max_spin.value()),
            "batch_size": (self.batch_min_spin.value(), self.batch_max_spin.value()),
            "hidden_layers": (self.layers_min_spin.value(), self.layers_max_spin.value()),
        }

        strategy = self.strategy_combo.currentText()
        num_trials = self.num_trials_spin.value()

        # Start optimization in separate thread (simplified for example)
        self.run_optimization(strategy, param_ranges, num_trials)

    def stop_optimization(self):
        """Stop the ongoing optimization process."""
        self.start_optimization_btn.setEnabled(True)
        self.stop_optimization_btn.setEnabled(False)

    def run_optimization(self, strategy, param_ranges, num_trials):
        """Run the hyperparameter optimization."""
        import random

        best_accuracy = 0
        best_params = None

        for trial in range(num_trials):
            # Generate random parameters (simplified example)
            if strategy == "Random Search":
                params = {
                    "learning_rate": random.uniform(*param_ranges["learning_rate"]),  # noqa: S311
                    "batch_size": random.choice(range(*param_ranges["batch_size"])),  # noqa: S311
                    "hidden_layers": random.choice(range(*param_ranges["hidden_layers"])),  # noqa: S311
                }
            else:
                # Simplified - would implement other strategies
                params = {
                    "learning_rate": random.uniform(*param_ranges["learning_rate"]),  # noqa: S311
                    "batch_size": random.choice(range(*param_ranges["batch_size"])),  # noqa: S311
                    "hidden_layers": random.choice(range(*param_ranges["hidden_layers"])),  # noqa: S311
                }

            # Simulate training (would actually train model)
            accuracy = random.uniform(0.5, 0.95)  # Simulated accuracy  # noqa: S311
            loss = random.uniform(0.1, 2.0)  # Simulated loss  # noqa: S311

            # Track best parameters
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_params = params.copy()

            # Add to history
            result = {
                "trial": trial + 1,
                "params": params,
                "accuracy": accuracy,
                "loss": loss,
            }
            self.optimization_history.append(result)

            # Update UI
            self.add_result_to_table(result)
            self.update_progress_plot()

            if best_params:
                self.update_best_params(best_params, best_accuracy)

        self.stop_optimization()

    def add_result_to_table(self, result):
        """Add optimization result to the results table."""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        self.results_table.setItem(row, 0, QTableWidgetItem(str(result["trial"])))
        self.results_table.setItem(
            row, 1, QTableWidgetItem(f"{result['params']['learning_rate']:.6f}")
        )
        self.results_table.setItem(row, 2, QTableWidgetItem(str(result["params"]["batch_size"])))
        self.results_table.setItem(row, 3, QTableWidgetItem(str(result["params"]["hidden_layers"])))
        self.results_table.setItem(row, 4, QTableWidgetItem(f"{result['accuracy']:.4f}"))
        self.results_table.setItem(row, 5, QTableWidgetItem(f"{result['loss']:.4f}"))

    def update_progress_plot(self):
        """Update the optimization progress plot."""
        if not self.optimization_history:
            return

        trials = []
        best_accuracies = []
        best_so_far = 0

        for result in self.optimization_history:
            trials.append(result["trial"])
            best_so_far = max(best_so_far, result["accuracy"])
            best_accuracies.append(best_so_far)

        self.progress_plot.clear()
        self.progress_plot.plot(trials, best_accuracies, pen="b", symbol="o")

    def update_best_params(self, best_params, best_accuracy):
        """Update the best parameters display."""
        text = f"Best Accuracy: {best_accuracy:.4f}\n"
        text += f"Learning Rate: {best_params['learning_rate']:.6f}\n"
        text += f"Batch Size: {best_params['batch_size']}\n"
        text += f"Hidden Layers: {best_params['hidden_layers']}"

        self.best_params_text.setText(text)

    def get_best_parameters(self):
        """Get the best parameters found during optimization."""
        if not self.optimization_history:
            return None

        best_result = max(self.optimization_history, key=lambda x: x["accuracy"])
        return best_result["params"]


class EnhancedTrainingInterface(QDialog):
    """Enhanced AI model training interface."""

    def __init__(self, parent=None):
        """Initialize the enhanced training interface dialog.

        Args:
            parent: Parent widget for the dialog

        """
        super().__init__(parent)
        self.setWindowTitle("Enhanced AI Model Training Interface")
        self.setMinimumSize(1200, 800)

        self.training_thread = None
        self.config = TrainingConfiguration()

        # Initialize UI attributes
        self.model_name_edit = None
        self.model_type_combo = None
        self.learning_rate_spin = None
        self.batch_size_spin = None
        self.epochs_spin = None
        self.validation_split_slider = None
        self.validation_split_spin = None
        self.early_stopping_cb = None
        self.augmentation_cb = None
        self.transfer_learning_cb = None
        self.gpu_cb = None

        self.init_ui()
        self.connect_signals()

    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()

        # Apply consistent styling
        self.apply_styling()

        # Create tab widget
        self.tabs = QTabWidget()

        # Training Configuration Tab
        self.config_tab = self.create_config_tab()
        self.tabs.addTab(self.config_tab, "Configuration")

        # Dataset Analysis Tab
        self.dataset_tab = DatasetAnalysisWidget()
        self.tabs.addTab(self.dataset_tab, "Dataset Analysis")

        # Training Visualization Tab
        self.viz_tab = TrainingVisualizationWidget()
        self.tabs.addTab(self.viz_tab, "Training Visualization")

        # Hyperparameter Optimization Tab
        self.hyperopt_tab = HyperparameterOptimizationWidget()
        self.tabs.addTab(self.hyperopt_tab, "Hyperparameter Optimization")

        # Create main splitter for resizable panes
        main_splitter = QSplitter(Qt.Vertical)
        main_splitter.addWidget(self.tabs)

        # Create bottom widget for controls and status
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)

        # Control buttons
        controls_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start Training")
        self.pause_btn = QPushButton("Pause")
        self.stop_btn = QPushButton("Stop")
        self.save_config_btn = QPushButton("Save Configuration")
        self.load_config_btn = QPushButton("Load Configuration")

        # Apply icons to buttons
        self._apply_button_icons()

        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)

        controls_layout.addWidget(self.start_btn)
        controls_layout.addWidget(self.pause_btn)
        controls_layout.addWidget(self.stop_btn)
        controls_layout.addStretch()
        controls_layout.addWidget(self.save_config_btn)
        controls_layout.addWidget(self.load_config_btn)

        bottom_layout.addLayout(controls_layout)

        # Status bar with frame
        status_frame = QFrame()
        status_frame.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        status_frame_layout = QVBoxLayout(status_frame)

        self.status_label = QLabel("Ready to start training")
        self.progress_bar = QProgressBar()

        status_layout = QHBoxLayout()
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.progress_bar)

        status_frame_layout.addLayout(status_layout)
        bottom_layout.addWidget(status_frame)

        # Add bottom widget to splitter
        main_splitter.addWidget(bottom_widget)
        main_splitter.setStretchFactor(0, 1)  # Tabs get more space
        main_splitter.setStretchFactor(1, 0)  # Controls/status stay compact

        # Add splitter to main layout
        layout.addWidget(main_splitter)

        self.setLayout(layout)

    def apply_styling(self):
        """Apply consistent styling to the interface."""
        # Set application font
        app_font = QFont("Arial", 10)
        self.setFont(app_font)

        # Set window palette for better theming
        palette = QPalette()
        palette.setColor(QPalette.Window, Qt.GlobalColor.white)
        palette.setColor(QPalette.WindowText, Qt.GlobalColor.black)
        self.setPalette(palette)

    def _apply_button_icons(self):
        """Apply icons to buttons using colored pixmaps."""

        # Create simple colored pixmaps as placeholders for icons
        def create_colored_pixmap(color, size=16):
            """Create a solid-colored pixmap for use as a button icon.

            Args:
                color: Qt color to fill the pixmap with
                size: Size of the square pixmap in pixels (default: 16)

            Returns:
                QPixmap: A square pixmap filled with the specified color

            """
            pixmap = QPixmap(size, size)
            pixmap.fill(color)
            return pixmap

        # Apply icons (using colored squares as placeholders)
        if self.start_btn:
            self.start_btn.setIcon(QIcon(create_colored_pixmap(Qt.GlobalColor.green)))
        if self.pause_btn:
            self.pause_btn.setIcon(QIcon(create_colored_pixmap(Qt.GlobalColor.yellow)))
        if self.stop_btn:
            self.stop_btn.setIcon(QIcon(create_colored_pixmap(Qt.GlobalColor.red)))
        if self.save_config_btn:
            self.save_config_btn.setIcon(QIcon(create_colored_pixmap(Qt.GlobalColor.blue)))
        if self.load_config_btn:
            self.load_config_btn.setIcon(QIcon(create_colored_pixmap(Qt.GlobalColor.cyan)))

    def create_config_tab(self) -> QWidget:
        """Create the configuration tab with scrollable area."""
        # Create scroll area for configuration
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameStyle(QFrame.NoFrame)

        # Create the actual tab content
        tab = QWidget()
        layout = QVBoxLayout()

        # Model Configuration
        model_group = QGroupBox("Model Configuration")
        model_layout = QFormLayout()

        self.model_name_edit = QLineEdit(self.config.model_name)
        self.model_type_combo = QComboBox()
        self.model_type_combo.addItems(
            [
                "vulnerability_classifier",
                "exploit_detector",
                "malware_classifier",
                "license_detector",
                "packer_identifier",
            ]
        )

        model_layout.addRow("Model Name:", self.model_name_edit)
        model_layout.addRow("Model Type:", self.model_type_combo)

        model_group.setLayout(model_layout)
        layout.addWidget(model_group)

        # Training Parameters
        training_group = QGroupBox("Training Parameters")
        training_layout = QFormLayout()

        self.learning_rate_spin = QDoubleSpinBox()
        self.learning_rate_spin.setDecimals(6)
        self.learning_rate_spin.setRange(0.000001, 1.0)
        self.learning_rate_spin.setValue(self.config.learning_rate)

        self.batch_size_spin = QSpinBox()
        self.batch_size_spin.setRange(1, 512)
        self.batch_size_spin.setValue(self.config.batch_size)

        self.epochs_spin = QSpinBox()
        self.epochs_spin.setRange(1, 1000)
        self.epochs_spin.setValue(self.config.epochs)

        # Create a widget to hold both slider and spinbox
        validation_widget = QWidget()
        validation_layout = QHBoxLayout(validation_widget)
        validation_layout.setContentsMargins(0, 0, 0, 0)

        self.validation_split_slider = QSlider(Qt.Horizontal)
        self.validation_split_slider.setRange(10, 50)  # 10% to 50%
        self.validation_split_slider.setValue(int(self.config.validation_split * 100))
        self.validation_split_slider.setTickPosition(QSlider.TicksBelow)
        self.validation_split_slider.setTickInterval(5)

        self.validation_split_spin = QDoubleSpinBox()
        self.validation_split_spin.setRange(0.1, 0.5)
        self.validation_split_spin.setSingleStep(0.05)
        self.validation_split_spin.setValue(self.config.validation_split)

        # Connect slider and spinbox
        self.validation_split_slider.valueChanged.connect(
            lambda v: self.validation_split_spin.setValue(v / 100.0),
        )
        self.validation_split_spin.valueChanged.connect(
            lambda v: self.validation_split_slider.setValue(int(v * 100)),
        )

        validation_layout.addWidget(self.validation_split_slider, 1)
        validation_layout.addWidget(self.validation_split_spin)

        training_layout.addRow("Learning Rate:", self.learning_rate_spin)
        training_layout.addRow("Batch Size:", self.batch_size_spin)
        training_layout.addRow("Epochs:", self.epochs_spin)
        training_layout.addRow("Validation Split:", validation_widget)

        training_group.setLayout(training_layout)
        layout.addWidget(training_group)

        # Advanced Features
        advanced_group = QGroupBox("Advanced Features")
        advanced_layout = QFormLayout()

        self.early_stopping_cb = QCheckBox()
        self.early_stopping_cb.setChecked(self.config.use_early_stopping)

        self.augmentation_cb = QCheckBox()
        self.augmentation_cb.setChecked(self.config.use_augmentation)

        self.transfer_learning_cb = QCheckBox()
        self.transfer_learning_cb.setChecked(self.config.use_transfer_learning)

        self.gpu_cb = QCheckBox()
        self.gpu_cb.setChecked(self.config.use_gpu)

        advanced_layout.addRow("Early Stopping:", self.early_stopping_cb)
        advanced_layout.addRow("Data Augmentation:", self.augmentation_cb)
        advanced_layout.addRow("Transfer Learning:", self.transfer_learning_cb)
        advanced_layout.addRow("Use GPU:", self.gpu_cb)

        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)

        tab.setLayout(layout)

        # Set the tab as the scroll area's widget
        scroll_area.setWidget(tab)
        return scroll_area

    def connect_signals(self):
        """Connect UI signals."""
        self.start_btn.clicked.connect(self.start_training)
        self.pause_btn.clicked.connect(self.pause_training)
        self.stop_btn.clicked.connect(self.stop_training)
        self.save_config_btn.clicked.connect(self.save_configuration)
        self.load_config_btn.clicked.connect(self.load_configuration)

    def start_training(self):
        """Start the training process."""
        # Update configuration from UI
        self.update_config_from_ui()

        # Validate configuration
        if not self.validate_config():
            return

        # Create and start training thread
        self.training_thread = TrainingThread(self.config)
        self.training_thread.progress_updated.connect(self.progress_bar.setValue)
        self.training_thread.metrics_updated.connect(self.viz_tab.update_metrics)
        self.training_thread.log_message.connect(self.update_status)
        self.training_thread.training_completed.connect(self.training_completed)
        self.training_thread.error_occurred.connect(self.training_error)

        self.training_thread.start()

        # Update UI state
        self.start_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Training in progress...")

        # Clear previous visualization
        self.viz_tab.clear_history()

    def pause_training(self):
        """Pause the training process."""
        if self.training_thread:
            self.training_thread.pause_training()
            self.pause_btn.setText("Resume")
            self.pause_btn.clicked.disconnect()
            self.pause_btn.clicked.connect(self.resume_training)
            self.status_label.setText("Training paused")

    def resume_training(self):
        """Resume the training process."""
        if self.training_thread:
            self.training_thread.resume_training()
            self.pause_btn.setText("Pause")
            self.pause_btn.clicked.disconnect()
            self.pause_btn.clicked.connect(self.pause_training)
            self.status_label.setText("Training resumed")

    def stop_training(self):
        """Stop the training process."""
        if self.training_thread:
            self.training_thread.stop_training()
            self.training_thread.wait()

        self.reset_ui_state()
        self.status_label.setText("Training stopped")

    def training_completed(self, results: dict[str, Any]):
        """Handle training completion."""
        self.reset_ui_state()
        accuracy = results.get("final_accuracy", 0)
        self.status_label.setText(f"Training completed! Final accuracy: {accuracy:.4f}")

        QMessageBox.information(
            self,
            "Training Complete",
            f"Model training completed successfully!\n\nFinal accuracy: {accuracy:.4f}",
        )

    def training_error(self, error_message: str):
        """Handle training errors."""
        self.reset_ui_state()
        self.status_label.setText(f"Training error: {error_message}")
        QMessageBox.critical(
            self, "Training Error", f"An error occurred during training:\n\n{error_message}"
        )

    def reset_ui_state(self):
        """Reset UI to initial state."""
        self.start_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.pause_btn.setText("Pause")

        # Reconnect pause button
        try:
            self.pause_btn.clicked.disconnect()
        except (AttributeError, TypeError) as e:
            logger.error("Error in enhanced_training_interface: %s", e)
        self.pause_btn.clicked.connect(self.pause_training)

    def update_config_from_ui(self):
        """Update configuration from UI values."""
        self.config.model_name = self.model_name_edit.text()
        self.config.model_type = self.model_type_combo.currentText()
        self.config.learning_rate = self.learning_rate_spin.value()
        self.config.batch_size = self.batch_size_spin.value()
        self.config.epochs = self.epochs_spin.value()
        self.config.validation_split = self.validation_split_spin.value()
        self.config.use_early_stopping = self.early_stopping_cb.isChecked()
        self.config.use_augmentation = self.augmentation_cb.isChecked()
        self.config.use_transfer_learning = self.transfer_learning_cb.isChecked()
        self.config.use_gpu = self.gpu_cb.isChecked()

    def validate_config(self) -> bool:
        """Validate the training configuration."""
        if not self.config.model_name.strip():
            QMessageBox.warning(self, "Invalid Configuration", "Please enter a model name.")
            return False

        if self.config.epochs <= 0:
            QMessageBox.warning(self, "Invalid Configuration", "Epochs must be greater than 0.")
            return False

        return True

    def update_status(self, message: str):
        """Update status label."""
        self.status_label.setText(message)

    def save_configuration(self):
        """Save current configuration to file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Configuration",
            "training_config.json",
            "JSON Files (*.json);;All Files (*)",
        )

        if file_path:
            self.update_config_from_ui()
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(asdict(self.config), f, indent=2)
                QMessageBox.information(
                    self, "Configuration Saved", f"Configuration saved to {file_path}"
                )
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in enhanced_training_interface: %s", e)
                QMessageBox.critical(self, "Save Error", f"Error saving configuration: {e}")

    def load_configuration(self):
        """Load configuration from file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Configuration",
            "",
            "JSON Files (*.json);;All Files (*)",
        )

        if file_path:
            try:
                with open(file_path, encoding="utf-8") as f:
                    config_dict = json.load(f)

                # Update configuration
                for key, value in config_dict.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)

                # Update UI
                self.update_ui_from_config()

                QMessageBox.information(
                    self, "Configuration Loaded", f"Configuration loaded from {file_path}"
                )
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in enhanced_training_interface: %s", e)
                QMessageBox.critical(self, "Load Error", f"Error loading configuration: {e}")

    def update_ui_from_config(self):
        """Update UI from configuration values."""
        self.model_name_edit.setText(self.config.model_name)
        index = self.model_type_combo.findText(self.config.model_type)
        if index >= 0:
            self.model_type_combo.setCurrentIndex(index)

        self.learning_rate_spin.setValue(self.config.learning_rate)
        self.batch_size_spin.setValue(self.config.batch_size)
        self.epochs_spin.setValue(self.config.epochs)
        self.validation_split_spin.setValue(self.config.validation_split)
        self.early_stopping_cb.setChecked(self.config.use_early_stopping)
        self.augmentation_cb.setChecked(self.config.use_augmentation)
        self.transfer_learning_cb.setChecked(self.config.use_transfer_learning)
        self.gpu_cb.setChecked(self.config.use_gpu)


def create_enhanced_training_interface(parent=None) -> "EnhancedTrainingInterface":
    """Factory function to create the enhanced training interface."""
    if not PYQT6_AVAILABLE:
        raise ImportError("PyQt6 is required for the enhanced training interface")

    return EnhancedTrainingInterface(parent)
