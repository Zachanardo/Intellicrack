"""Model Loading Progress Widget.

This widget provides a visual interface for monitoring model loading progress
using the BackgroundModelLoader and QueuedProgressCallback.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import logging

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import QGroupBox, QHBoxLayout, QLabel, QProgressBar, QPushButton, QSplitter, QTextEdit, QVBoxLayout, QWidget

from intellicrack.handlers.pyqt6_handler import QFont

from ...ai.background_loader import LoadingProgress, LoadingState, QueuedProgressCallback
from ...ai.llm_backends import get_llm_manager
from ...ai.llm_config_manager import LLMConfig, LLMProvider


logger = logging.getLogger(__name__)


class ModelLoadingItemWidget(QWidget):
    """Widget for displaying a single model loading task."""

    #: model_id (type: str)
    cancelled = pyqtSignal(str)

    def __init__(self, model_id: str, parent: QWidget | None = None) -> None:
        """Initialize model loading item widget with model ID and parent widget."""
        super().__init__(parent)
        self.model_id = model_id
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the UI."""
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        # Model info
        info_layout = QHBoxLayout()
        self.name_label = QLabel(self.model_id)
        self.name_label.setFont(QFont("Arial", 10, QFont.Bold))
        info_layout.addWidget(self.name_label)

        info_layout.addStretch()

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(lambda: self.cancelled.emit(self.model_id))
        self.cancel_btn.setMaximumWidth(60)
        info_layout.addWidget(self.cancel_btn)

        layout.addLayout(info_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)

        # Status message
        self.status_label = QLabel("Queued...")
        self.status_label.setStyleSheet("color: #666;")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def update_progress(self, progress: LoadingProgress) -> None:
        """Update progress display."""
        # Update progress bar
        self.progress_bar.setValue(int(progress.progress * 100))

        # Update status message
        self.status_label.setText(progress.message)

        # Update style based on state
        if progress.state == LoadingState.COMPLETED:
            self.progress_bar.setStyleSheet("""
                QProgressBar::chunk {
                    background-color: #4CAF50;
                }
            """)
            self.cancel_btn.setEnabled(False)
        elif progress.state == LoadingState.FAILED:
            self.progress_bar.setStyleSheet("""
                QProgressBar::chunk {
                    background-color: #F44336;
                }
            """)
            self.cancel_btn.setEnabled(False)
        elif progress.state == LoadingState.CANCELLED:
            self.progress_bar.setStyleSheet("""
                QProgressBar::chunk {
                    background-color: #999;
                }
            """)
            self.cancel_btn.setEnabled(False)
        elif progress.state == LoadingState.LOADING:
            self.progress_bar.setStyleSheet("""
                QProgressBar::chunk {
                    background-color: #2196F3;
                }
            """)

    def set_completed(self, success: bool, error: str | None = None) -> None:
        """Set completion state."""
        if success:
            self.progress_bar.setValue(100)
            self.status_label.setText("Loading completed successfully")
            self.progress_bar.setStyleSheet("""
                QProgressBar::chunk {
                    background-color: #4CAF50;
                }
            """)
        else:
            self.status_label.setText(f"Failed: {error or 'Unknown error'}")
            self.progress_bar.setStyleSheet("""
                QProgressBar::chunk {
                    background-color: #F44336;
                }
            """)
        self.cancel_btn.setEnabled(False)


class ModelLoadingProgressWidget(QWidget):
    """Run widget for monitoring model loading progress."""

    #: model_id (type: str)
    model_loaded = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize model loading progress widget with LLM manager, progress callbacks, and UI components."""
        super().__init__(parent)
        self.llm_manager = get_llm_manager()
        self.progress_callback = QueuedProgressCallback()
        self.loading_items: dict[str, ModelLoadingItemWidget] = {}
        self.update_timer = None

        self.init_ui()
        self.setup_callbacks()

    def init_ui(self) -> None:
        """Initialize the UI."""
        layout = QVBoxLayout()

        # Title
        title = QLabel("Model Loading Progress")
        title.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(title)

        # Splitter for tasks and details
        splitter = QSplitter(Qt.Vertical)

        # Loading tasks group
        tasks_group = QGroupBox("Active Loading Tasks")
        tasks_layout = QVBoxLayout()

        # Scroll area for loading items
        self.tasks_container = QWidget()
        self.tasks_layout = QVBoxLayout()
        self.tasks_layout.setAlignment(Qt.AlignTop)
        self.tasks_container.setLayout(self.tasks_layout)

        tasks_layout.addWidget(self.tasks_container)
        tasks_group.setLayout(tasks_layout)
        splitter.addWidget(tasks_group)

        # Statistics group
        stats_group = QGroupBox("Loading Statistics")
        stats_layout = QVBoxLayout()

        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setMaximumHeight(100)
        stats_layout.addWidget(self.stats_text)

        stats_group.setLayout(stats_layout)
        splitter.addWidget(stats_group)

        layout.addWidget(splitter)

        # Control buttons
        button_layout = QHBoxLayout()

        self.test_load_btn = QPushButton("Test Load Model")
        self.test_load_btn.clicked.connect(self.test_load_model)
        button_layout.addWidget(self.test_load_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_display)
        button_layout.addWidget(self.refresh_btn)

        button_layout.addStretch()

        layout.addLayout(button_layout)

        self.setLayout(layout)

    def setup_callbacks(self) -> None:
        """Set up progress callbacks and update timer."""
        # Register callback with LLM manager
        self.llm_manager.add_progress_callback(self.progress_callback)

        # Setup update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.process_updates)
        self.update_timer.start(100)  # Update every 100ms

    def process_updates(self) -> None:
        """Process queued progress updates."""
        # Get progress updates
        progress_updates = self.progress_callback.get_progress_updates()
        for progress in progress_updates:
            self.handle_progress_update(progress)

        # Get completion updates
        completion_updates = self.progress_callback.get_completion_updates()
        for model_id, success, error in completion_updates:
            self.handle_completion_update(model_id, success, error)

        # Update statistics
        self.update_statistics()

    def handle_progress_update(self, progress: LoadingProgress) -> None:
        """Handle a progress update."""
        model_id = progress.model_id

        # Create item widget if doesn't exist
        if model_id not in self.loading_items:
            item_widget = ModelLoadingItemWidget(model_id)
            item_widget.cancelled.connect(self.cancel_loading)
            self.loading_items[model_id] = item_widget
            self.tasks_layout.addWidget(item_widget)

        # Update progress
        self.loading_items[model_id].update_progress(progress)

    def handle_completion_update(self, model_id: str, success: bool, error: str | None) -> None:
        """Handle a completion update."""
        if model_id in self.loading_items:
            self.loading_items[model_id].set_completed(success, error)

            if success:
                self.model_loaded.emit(model_id)

                if task := self.llm_manager.get_loading_progress(model_id):
                    self.llm_manager.register_background_loaded_model(model_id, task)

    def cancel_loading(self, model_id: str) -> None:
        """Cancel a loading task."""
        if self.llm_manager.cancel_loading(model_id):
            logger.info(f"Cancelled loading task: {model_id}")
        else:
            logger.error(f"Failed to cancel loading task: {model_id}")

    def update_statistics(self) -> None:
        """Update loading statistics display."""
        stats = self.llm_manager.get_loading_statistics()

        stats_text = f"""
Pending Tasks: {stats.get("pending", 0)}
Active Tasks: {stats.get("active", 0)}
Completed Tasks: {stats.get("completed", 0)}
Success Rate: {stats.get("success_rate", 0):.1%}
Total Workers: {stats.get("total_workers", 0)}
Active Workers: {stats.get("active_workers", 0)}
"""
        self.stats_text.setPlainText(stats_text.strip())

    def test_load_model(self) -> None:
        """Test loading a model in the background."""
        # Create a test configuration
        test_config = LLMConfig(
            provider=LLMProvider.OLLAMA,
            model_name="llama2",
            api_url="http://localhost:11434",
            max_tokens=2048,
            temperature=0.7,
        )

        # Submit loading task
        model_id = f"test_model_{len(self.loading_items) + 1}"
        if task := self.llm_manager.load_model_in_background(
            llm_id=model_id,
            config=test_config,
            priority=5,
        ):
            logger.info(f"Submitted test loading task: {model_id}")
        else:
            logger.error("Failed to submit test loading task")

    def refresh_display(self) -> None:
        """Refresh the display with current tasks."""
        # Get all loading tasks
        all_tasks = self.llm_manager.get_all_loading_tasks()

        # Update or create widgets for each task
        for model_id, task in all_tasks.items():
            if model_id not in self.loading_items:
                # Create progress update from task
                progress = LoadingProgress(
                    model_id=task.model_id,
                    model_name=task.config.model_name,
                    state=task.state,
                    progress=task.progress,
                    message=task.message,
                    details={},
                    timestamp=task.start_time or 0,
                )
                self.handle_progress_update(progress)

        # Update statistics
        self.update_statistics()

    def cleanup(self) -> None:
        """Cleanup resources."""
        if self.update_timer:
            self.update_timer.stop()

        # Remove callback
        self.llm_manager.remove_progress_callback(self.progress_callback)
