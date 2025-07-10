"""Background Model Loading Example.

This example demonstrates how to use the BackgroundModelLoader
with QueuedProgressCallback for asynchronous model loading with
progress tracking in a PyQt5 application.

Copyright (C) 2025 Zachary Flint
"""

import logging
import sys

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAction,
    QApplication,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMenuBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# Add parent directory to path for imports
sys.path.insert(0, '..')

from intellicrack.ai.background_loader import PrintProgressCallback, QueuedProgressCallback
from intellicrack.ai.llm_backends import get_llm_manager
from intellicrack.ai.llm_config_manager import LLMConfig, LLMProvider
from intellicrack.ui.dialogs.model_loading_dialog import ModelLoadingDialog
from intellicrack.ui.widgets.model_loading_progress_widget import ModelLoadingProgressWidget

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BackgroundLoadingExample(QMainWindow):
    """Example application demonstrating background model loading."""

    def __init__(self):
        """Initialize the background loading example window."""
        super().__init__()
        self.llm_manager = get_llm_manager()
        self.setWindowTitle("Background Model Loading Example")
        self.setGeometry(100, 100, 1000, 700)

        self.init_ui()
        self.setup_example_models()

    def init_ui(self):
        """Initialize the UI."""
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        layout = QVBoxLayout()

        # Title
        title = QLabel("Background Model Loading Example")
        title.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Progress widget
        self.progress_widget = ModelLoadingProgressWidget()
        self.progress_widget.model_loaded.connect(self.on_model_loaded)
        layout.addWidget(self.progress_widget)

        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(200)
        layout.addWidget(self.log_output)

        # Button layout
        button_layout = QHBoxLayout()

        # Load model buttons
        load_ollama_btn = QPushButton("Load Ollama Model")
        load_ollama_btn.clicked.connect(lambda: self.load_example_model("ollama"))
        button_layout.addWidget(load_ollama_btn)

        load_openai_btn = QPushButton("Load OpenAI Model")
        load_openai_btn.clicked.connect(lambda: self.load_example_model("openai"))
        button_layout.addWidget(load_openai_btn)

        load_local_btn = QPushButton("Load Local Model")
        load_local_btn.clicked.connect(lambda: self.load_example_model("local"))
        button_layout.addWidget(load_local_btn)

        button_layout.addStretch()

        # Manager dialog button
        manager_btn = QPushButton("Open Model Manager")
        manager_btn.clicked.connect(self.open_model_manager)
        manager_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                font-weight: bold;
                padding: 5px 15px;
            }
        """)
        button_layout.addWidget(manager_btn)

        layout.addLayout(button_layout)

        central_widget.setLayout(layout)

        # Create menu bar
        self.create_menu_bar()

    def create_menu_bar(self):
        """Create the menu bar."""
        menubar = QMenuBar(self)
        self.setMenuBar(menubar)

        # File menu
        file_menu = QMenu("File", self)
        menubar.addMenu(file_menu)

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Models menu
        models_menu = QMenu("Models", self)
        menubar.addMenu(models_menu)

        load_action = QAction("Load Model...", self)
        load_action.triggered.connect(self.open_model_manager)
        models_menu.addAction(load_action)

        models_menu.addSeparator()

        cancel_all_action = QAction("Cancel All Loading", self)
        cancel_all_action.triggered.connect(self.cancel_all_loading)
        models_menu.addAction(cancel_all_action)

        # View menu
        view_menu = QMenu("View", self)
        menubar.addMenu(view_menu)

        stats_action = QAction("Show Statistics", self)
        stats_action.triggered.connect(self.show_statistics)
        view_menu.addAction(stats_action)

    def setup_example_models(self):
        """Set up example progress callbacks."""
        # Add a print callback for console output
        print_callback = PrintProgressCallback()
        self.llm_manager.add_progress_callback(print_callback)

        # Add a queued callback for the progress widget
        queued_callback = QueuedProgressCallback()
        queued_callback.progress_updated.connect(self.progress_widget.update_progress)
        self.llm_manager.add_progress_callback(queued_callback)

        self.log("Background loading example initialized")
        self.log("Click buttons to load models in the background")

    def load_example_model(self, model_type: str):
        """Load an example model based on type."""
        configs = {
            "ollama": LLMConfig(
                provider=LLMProvider.OLLAMA,
                model_name="llama2",
                api_url="http://localhost:11434",
                max_tokens=2048
            ),
            "openai": LLMConfig(
                provider=LLMProvider.OPENAI,
                model_name="gpt-3.5-turbo",
                api_key="your-api-key-here",
                max_tokens=2048
            ),
            "local": LLMConfig(
                provider=LLMProvider.LOCAL_GGUF,
                model_path="/path/to/model.gguf",
                model_name="local-model",
                max_tokens=2048
            )
        }

        if model_type not in configs:
            self.log(f"Unknown model type: {model_type}")
            return

        config = configs[model_type]
        model_id = f"{model_type}_example_{self.get_next_id()}"

        # Set priority based on type
        priorities = {"ollama": 5, "openai": 8, "local": 3}
        priority = priorities.get(model_type, 5)

        self.log(f"Submitting loading task for {model_id} with priority {priority}")

        task = self.llm_manager.load_model_in_background(
            llm_id=model_id,
            config=config,
            priority=priority
        )

        if task:
            self.log(f"✓ Task submitted successfully: {model_id}")
        else:
            self.log(f"✗ Failed to submit task: {model_id}")

    def get_next_id(self):
        """Get next available ID."""
        return len(self.llm_manager.get_all_loading_tasks()) + 1

    def open_model_manager(self):
        """Open the model loading manager dialog."""
        dialog = ModelLoadingDialog(self)
        dialog.model_loaded.connect(self.on_model_loaded)
        dialog.exec()

    def cancel_all_loading(self):
        """Cancel all loading tasks."""
        tasks = self.llm_manager.get_all_loading_tasks()
        cancelled = 0

        for model_id in tasks:
            if self.llm_manager.cancel_loading(model_id):
                cancelled += 1

        self.log(f"Cancelled {cancelled} loading tasks")

    def show_statistics(self):
        """Show loading statistics."""
        stats = self.llm_manager.get_loading_statistics()

        self.log("\n=== Loading Statistics ===")
        self.log(f"Pending: {stats['pending']}")
        self.log(f"Active: {stats['active']}")
        self.log(f"Completed: {stats['completed']}")
        self.log(f"Success Rate: {stats['success_rate']:.1%}")
        self.log(f"Workers: {stats['active_workers']}/{stats['total_workers']}")
        self.log("========================\n")

    def on_model_loaded(self, model_id: str):
        """Handle model loaded event."""
        self.log(f"🎉 Model loaded successfully: {model_id}")

        # Try to use the model
        info = self.llm_manager.get_llm_info(model_id)
        if info:
            self.log(f"Model info: {info['provider']} - {info['model_name']}")

    def log(self, message: str):
        """Log a message to the output."""
        self.log_output.append(message)
        logger.info(message)

    def closeEvent(self, event):
        """Handle application close."""
        # Cleanup
        self.progress_widget.cleanup()

        # Cancel any remaining tasks
        self.cancel_all_loading()

        super().closeEvent(event)


def main():
    """Run the example application."""
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle("Fusion")

    # Create and show main window
    window = BackgroundLoadingExample()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
