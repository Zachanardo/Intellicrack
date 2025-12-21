"""Model Loading Dialog.

A dialog that demonstrates the integration of BackgroundModelLoader
with progress tracking and management capabilities.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import logging

from intellicrack.handlers.pyqt6_handler import (
    QCloseEvent,
    QComboBox,
    QDialogButtonBox,
    QFont,
    QFormLayout,
    QGroupBox,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSpinBox,
    Qt,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from ...ai.background_loader import LoadingState
from ...ai.llm_backends import get_llm_manager
from ...ai.llm_config_manager import LLMConfig, LLMProvider
from ..widgets.model_loading_progress_widget import ModelLoadingProgressWidget
from .base_dialog import BaseDialog


logger = logging.getLogger(__name__)


class ModelLoadingDialog(BaseDialog):
    """Dialog for managing model loading with progress tracking."""

    #: model_id (type: str)
    model_loaded = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ModelLoadingDialog with default values."""
        super().__init__(parent, "Model Loading Manager")
        self.setMinimumSize(800, 600)

        self.llm_manager = get_llm_manager()
        self.setup_content(self.content_widget.layout() or QVBoxLayout(self.content_widget))

    def setup_content(self, layout: QVBoxLayout) -> None:
        """Set up the UI content."""
        if layout is None:
            layout = QVBoxLayout(self.content_widget)

        # Title
        title = QLabel("Background Model Loading Manager")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Tab widget
        tabs = QTabWidget()

        # Progress tab
        self.progress_widget = ModelLoadingProgressWidget()
        self.progress_widget.model_loaded.connect(self.on_model_loaded)
        tabs.addTab(self.progress_widget, "Loading Progress")

        # New model tab
        new_model_widget = self.create_new_model_tab()
        tabs.addTab(new_model_widget, "Load New Model")

        # Loaded models tab
        loaded_models_widget = self.create_loaded_models_tab()
        tabs.addTab(loaded_models_widget, "Loaded Models")

        layout.addWidget(tabs)

        # Dialog buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

    def create_new_model_tab(self) -> QWidget:
        """Create the new model loading tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Model configuration group
        config_group = QGroupBox("Model Configuration")
        config_layout = QFormLayout()

        # Provider selection
        self.provider_combo = QComboBox()
        for provider in LLMProvider:
            self.provider_combo.addItem(provider.value, provider)
        config_layout.addRow("Provider:", self.provider_combo)

        # Model name
        self.model_name_combo = QComboBox()
        self.model_name_combo.setEditable(True)
        self.model_name_combo.addItems(
            [
                "llama2",
                "codellama",
                "mistral",
                "gpt-3.5-turbo",
                "gpt-4",
                "claude-2",
                "claude-instant",
            ],
        )
        config_layout.addRow("Model Name:", self.model_name_combo)

        # API URL
        self.api_url_combo = QComboBox()
        self.api_url_combo.setEditable(True)
        self.api_url_combo.addItems(
            [
                "http://localhost:11434",  # Ollama
                "http://localhost:1234",  # LM Studio
                "https://api.openai.com/v1",
                "https://api.anthropic.com/v1",
            ],
        )
        config_layout.addRow("API URL:", self.api_url_combo)

        # Priority
        self.priority_spin = QSpinBox()
        self.priority_spin.setRange(0, 10)
        self.priority_spin.setValue(5)
        config_layout.addRow("Priority:", self.priority_spin)

        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

        # Load button
        load_btn = QPushButton("Load Model in Background")
        load_btn.clicked.connect(self.load_new_model)
        load_btn.setObjectName("primaryButton")
        layout.addWidget(load_btn)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_loaded_models_tab(self) -> QWidget:
        """Create the loaded models tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Models list
        self.models_list = QListWidget()
        layout.addWidget(self.models_list)

        # Refresh button
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_loaded_models)
        layout.addWidget(refresh_btn)

        widget.setLayout(layout)

        # Initial refresh
        self.refresh_loaded_models()

        return widget

    def load_new_model(self) -> None:
        """Load a new model based on configuration."""
        try:
            # Get configuration
            provider = self.provider_combo.currentData()
            model_name = self.model_name_combo.currentText()
            api_url = self.api_url_combo.currentText()
            priority = self.priority_spin.value()

            if not model_name:
                QMessageBox.warning(self, "Warning", "Please enter a model name")
                return

            # Create configuration
            config = LLMConfig(
                provider=provider,
                model_name=model_name,
                api_url=api_url or None,
                max_tokens=2048,
                temperature=0.7,
            )

            # Generate unique ID
            model_id = f"{provider.value}_{model_name}_{self.get_next_id()}"

            if task := self.llm_manager.load_model_in_background(
                llm_id=model_id,
                config=config,
                priority=priority,
            ):
                logger.debug("Background loading task created for %s: %s", model_id, task)
                logger.info("Submitted loading task for: %s", model_id)
                QMessageBox.information(self, "Success", f"Model loading task submitted:\n{model_id}")
            else:
                QMessageBox.critical(self, "Error", "Failed to submit loading task")

        except Exception as e:
            logger.exception("Error loading model: %s", e)
            QMessageBox.critical(self, "Error", f"Error loading model:\n{e!s}")

    def get_next_id(self) -> int:
        """Get next available ID number."""
        all_tasks = self.llm_manager.get_all_loading_tasks()
        return len(all_tasks) + 1

    def refresh_loaded_models(self) -> None:
        """Refresh the loaded models list."""
        self.models_list.clear()

        # Get all available models
        available_models = self.llm_manager.get_available_llms()

        for model_id in available_models:
            if info := self.llm_manager.get_llm_info(model_id):
                item_text = f"{model_id} ({info['provider']}) - {info['model_name']}"
                if info.get("is_initialized"):
                    item_text += " OK"

                item = QListWidgetItem(item_text)
                self.models_list.addItem(item)

        # Also show loading tasks
        loading_tasks = self.llm_manager.get_all_loading_tasks()
        for model_id, task in loading_tasks.items():
            if task.state not in [LoadingState.COMPLETED, LoadingState.FAILED]:
                item_text = f"{model_id} - {task.state.value} ({task.progress:.0%})"
                item = QListWidgetItem(item_text)
                item.setForeground(Qt.GlobalColor.blue)
                self.models_list.addItem(item)

    def on_model_loaded(self, model_id: str) -> None:
        """Handle model loaded signal."""
        self.model_loaded.emit(model_id)
        self.refresh_loaded_models()

        # Show notification
        QMessageBox.information(self, "Model Loaded", f"Model successfully loaded:\n{model_id}")

    def closeEvent(self, event: QCloseEvent) -> None:
        """Handle dialog close."""
        # Cleanup progress widget
        self.progress_widget.cleanup()
        super().closeEvent(event)
