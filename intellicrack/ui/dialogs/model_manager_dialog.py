"""Model Manager Dialog for Local GGUF Models

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

from pathlib import Path

from intellicrack.handlers.pyqt6_handler import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QThread,
    QTimer,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from ...ai.local_gguf_server import gguf_manager
from ...utils.logger import get_logger

logger = get_logger(__name__)


# Utility functions for QHeaderView and QAbstractItemView
def create_custom_header_view(orientation, parent=None):
    """Create a custom header view with enhanced functionality"""
    header = QHeaderView(orientation, parent)
    header.setDefaultSectionSize(100)
    header.setMinimumSectionSize(50)
    header.setSectionsClickable(True)
    header.setSortIndicatorShown(True)
    return header


def configure_table_selection(table, behavior=None, mode=None):
    """Configure table selection behavior using QAbstractItemView"""
    if behavior is None:
        behavior = QAbstractItemView.SelectRows
    if mode is None:
        mode = QAbstractItemView.SingleSelection

    table.setSelectionBehavior(behavior)
    table.setSelectionMode(mode)

    # Additional QAbstractItemView configurations
    table.setDragDropMode(QAbstractItemView.NoDragDrop)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)

    return table


def create_enhanced_item_view(parent=None):
    """Create an enhanced item view with custom behavior"""
    from intellicrack.handlers.pyqt6_handler import QListView

    view = QListView(parent)
    # Use QAbstractItemView methods
    view.setAlternatingRowColors(True)
    view.setSelectionMode(QAbstractItemView.ExtendedSelection)
    view.setDragDropMode(QAbstractItemView.InternalMove)
    view.setEditTriggers(QAbstractItemView.DoubleClicked | QAbstractItemView.EditKeyPressed)

    return view


class ModelDownloadThread(QThread):
    """Thread for downloading models."""

    #: model_name, progress_percent (type: str, float)
    progress_updated = pyqtSignal(str, float)
    #: model_name, success (type: str, bool)
    download_finished = pyqtSignal(str, bool)
    log_message = pyqtSignal(str)

    def __init__(self, model_url: str, model_name: str):
        """Initialize the ModelDownloadThread with default values."""
        super().__init__()
        self.model_url = model_url
        self.model_name = model_name
        self.is_cancelled = False

    def run(self):
        """Download the model."""
        try:
            import requests

            self.log_message.emit(f"Starting download: {self.model_name}")

            response = requests.get(self.model_url, stream=True)
            response.raise_for_status()

            total_size = int(response.headers.get("content-length", 0))
            downloaded = 0

            model_path = gguf_manager.models_directory / self.model_name

            with open(model_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if self.is_cancelled:
                        self.log_message.emit(f"Download cancelled: {self.model_name}")
                        model_path.unlink(missing_ok=True)
                        self.download_finished.emit(self.model_name, False)
                        return

                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)

                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            self.progress_updated.emit(self.model_name, progress)

            self.log_message.emit(f"Download completed: {self.model_name}")
            self.download_finished.emit(self.model_name, True)

        except Exception as e:
            logger.error("Exception in model_manager_dialog: %s", e)
            self.log_message.emit(f"Download failed: {self.model_name} - {e}")
            self.download_finished.emit(self.model_name, False)

    def cancel(self):
        """Cancel the download."""
        self.is_cancelled = True


class ModelManagerDialog(QDialog):
    """Dialog for managing local GGUF models."""

    def __init__(self, parent=None):
        """Initialize the ModelManagerDialog with default values."""
        super().__init__(parent)
        self.setWindowTitle("Local GGUF Model Manager")
        self.setMinimumSize(900, 700)
        self.resize(1000, 800)

        self.download_threads = {}
        self.current_model = None

        self.setup_ui()
        self.refresh_models()
        self.update_server_status()

        # Setup timer for server status updates
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_server_status)
        self.status_timer.start(5000)  # Update every 5 seconds  # Update every 5 seconds

    def setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)

        # Main tabs
        tabs = QTabWidget()

        # Local Models tab
        local_models_tab = QWidget()
        self.setup_local_models_tab(local_models_tab)
        tabs.addTab(local_models_tab, "Local Models")

        # Download Models tab
        download_tab = QWidget()
        self.setup_download_tab(download_tab)
        tabs.addTab(download_tab, "Download Models")

        # Server Control tab
        server_tab = QWidget()
        self.setup_server_tab(server_tab)
        tabs.addTab(server_tab, "Server Control")

        layout.addWidget(tabs)

        # Status bar
        status_layout = QHBoxLayout()

        self.status_label = QLabel("Checking server status...")
        status_layout.addWidget(self.status_label)

        status_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        status_layout.addWidget(close_btn)

        layout.addLayout(status_layout)

    def setup_local_models_tab(self, tab_widget):
        """Setup the local models management tab."""
        layout = QVBoxLayout(tab_widget)

        # Controls
        controls_layout = QHBoxLayout()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_models)
        controls_layout.addWidget(refresh_btn)

        load_btn = QPushButton("Load Selected")
        load_btn.clicked.connect(self.load_selected_model)
        controls_layout.addWidget(load_btn)

        unload_btn = QPushButton("Unload Current")
        unload_btn.clicked.connect(self.unload_current_model)
        controls_layout.addWidget(unload_btn)

        delete_btn = QPushButton("Delete Selected")
        delete_btn.clicked.connect(self.delete_selected_model)
        controls_layout.addWidget(delete_btn)

        controls_layout.addStretch()

        # Add local model button
        add_local_btn = QPushButton("Add Local Model")
        add_local_btn.clicked.connect(self.add_local_model)
        controls_layout.addWidget(add_local_btn)

        layout.addLayout(controls_layout)

        # Models table
        self.models_table = QTableWidget()
        self.models_table.setColumnCount(5)
        self.models_table.setHorizontalHeaderLabels(
            [
                "Model Name",
                "Size (MB)",
                "Status",
                "Path",
                "Actions",
            ]
        )

        # Configure table
        header = self.models_table.horizontalHeader()
        header.setStretchLastSection(True)
        # Configure header resize modes
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)

        # Create additional custom header for advanced features
        self.custom_header = create_custom_header_view(header.orientation(), self.models_table)

        # Use utility function to configure table selection
        configure_table_selection(self.models_table, QAbstractItemView.SelectRows)
        self.models_table.setAlternatingRowColors(True)

        layout.addWidget(self.models_table)

        # Model info
        info_group = QGroupBox("Model Information")
        info_layout = QVBoxLayout(info_group)

        self.model_info_text = QTextEdit()
        self.model_info_text.setMaximumHeight(150)
        self.model_info_text.setReadOnly(True)
        info_layout.addWidget(self.model_info_text)

        layout.addWidget(info_group)

    def setup_download_tab(self, tab_widget):
        """Setup the model download tab."""
        layout = QVBoxLayout(tab_widget)

        # Recommended models
        recommended_group = QGroupBox("Recommended Models")
        recommended_layout = QVBoxLayout(recommended_group)

        self.recommended_table = QTableWidget()
        self.recommended_table.setColumnCount(4)
        self.recommended_table.setHorizontalHeaderLabels(
            [
                "Model Name",
                "Description",
                "Size",
                "Actions",
            ]
        )

        # Configure table
        header = self.recommended_table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(1, QHeaderView.Stretch)

        # Configure table selection behavior
        configure_table_selection(self.recommended_table)

        self.recommended_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.recommended_table.setAlternatingRowColors(True)

        # Populate recommended models
        self.populate_recommended_models()

        recommended_layout.addWidget(self.recommended_table)
        layout.addWidget(recommended_group)

        # Custom download
        custom_group = QGroupBox("Custom Download")
        custom_layout = QVBoxLayout(custom_group)

        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Model URL:"))

        self.custom_url_input = QLineEdit()
        self.custom_url_input.setPlaceholderText("https://huggingface.co/.../model.gguf")
        url_layout.addWidget(self.custom_url_input)

        custom_download_btn = QPushButton("Download")
        custom_download_btn.clicked.connect(self.download_custom_model)
        url_layout.addWidget(custom_download_btn)

        custom_layout.addLayout(url_layout)
        layout.addWidget(custom_group)

        # Download progress
        progress_group = QGroupBox("Download Progress")
        progress_layout = QVBoxLayout(progress_group)

        self.download_log = QTextEdit()
        self.download_log.setMaximumHeight(150)
        self.download_log.setReadOnly(True)
        progress_layout.addWidget(self.download_log)

        # Progress bars container
        self.progress_container = QWidget()
        self.progress_layout = QVBoxLayout(self.progress_container)
        progress_layout.addWidget(self.progress_container)

        layout.addWidget(progress_group)

    def setup_server_tab(self, tab_widget):
        """Setup the server control tab."""
        layout = QVBoxLayout(tab_widget)

        # Server status
        status_group = QGroupBox("Server Status")
        status_layout = QVBoxLayout(status_group)

        self.server_status_label = QLabel("Checking...")
        status_layout.addWidget(self.server_status_label)

        server_controls_layout = QHBoxLayout()

        self.start_server_btn = QPushButton("Start Server")
        self.start_server_btn.clicked.connect(self.start_server)
        server_controls_layout.addWidget(self.start_server_btn)

        self.stop_server_btn = QPushButton("Stop Server")
        self.stop_server_btn.clicked.connect(self.stop_server)
        server_controls_layout.addWidget(self.stop_server_btn)

        server_controls_layout.addStretch()
        status_layout.addLayout(server_controls_layout)

        layout.addWidget(status_group)

        # Server configuration
        config_group = QGroupBox("Server Configuration")
        config_layout = QVBoxLayout(config_group)

        # Server settings
        server_settings_layout = QHBoxLayout()

        server_settings_layout.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit("127.0.0.1")
        server_settings_layout.addWidget(self.host_input)

        server_settings_layout.addWidget(QLabel("Port:"))
        self.port_input = QSpinBox()
        self.port_input.setRange(1000, 65535)
        self.port_input.setValue(8000)
        server_settings_layout.addWidget(self.port_input)

        config_layout.addLayout(server_settings_layout)

        # Model settings
        model_settings_layout = QVBoxLayout()

        context_layout = QHBoxLayout()
        context_layout.addWidget(QLabel("Context Length:"))
        self.context_length_input = QSpinBox()
        self.context_length_input.setRange(512, 32768)
        self.context_length_input.setValue(4096)
        context_layout.addWidget(self.context_length_input)

        context_layout.addWidget(QLabel("GPU Layers:"))
        self.gpu_layers_input = QSpinBox()
        self.gpu_layers_input.setRange(0, 100)
        self.gpu_layers_input.setValue(0)
        context_layout.addWidget(self.gpu_layers_input)

        model_settings_layout.addLayout(context_layout)

        # Advanced settings
        advanced_layout = QHBoxLayout()

        self.use_mmap_checkbox = QCheckBox("Use Memory Mapping")
        self.use_mmap_checkbox.setChecked(True)
        advanced_layout.addWidget(self.use_mmap_checkbox)

        self.use_mlock_checkbox = QCheckBox("Use Memory Lock")
        self.use_mlock_checkbox.setChecked(False)
        advanced_layout.addWidget(self.use_mlock_checkbox)

        model_settings_layout.addLayout(advanced_layout)
        config_layout.addLayout(model_settings_layout)

        layout.addWidget(config_group)

        # Dependencies status
        deps_group = QGroupBox("Dependencies Status")
        deps_layout = QVBoxLayout(deps_group)

        self.deps_status_text = QTextEdit()
        self.deps_status_text.setMaximumHeight(100)
        self.deps_status_text.setReadOnly(True)
        self.check_dependencies()
        deps_layout.addWidget(self.deps_status_text)

        layout.addWidget(deps_group)

        layout.addStretch()

    def populate_recommended_models(self):
        """Populate the recommended models table."""
        recommended = gguf_manager.get_recommended_models()

        self.recommended_table.setRowCount(len(recommended))

        for row, model in enumerate(recommended):
            # Model name
            name_item = QTableWidgetItem(model["name"])
            self.recommended_table.setItem(row, 0, name_item)

            # Description
            desc_item = QTableWidgetItem(model["description"])
            self.recommended_table.setItem(row, 1, desc_item)

            # Size
            size_item = QTableWidgetItem(model["size"])
            self.recommended_table.setItem(row, 2, size_item)

            # Download button
            download_btn = QPushButton("Download")
            download_btn.clicked.connect(
                lambda checked, url=model["url"], name=model["name"]: self.download_model(
                    url, name
                ),
            )
            self.recommended_table.setCellWidget(row, 3, download_btn)

    def refresh_models(self):
        """Refresh the local models list."""
        gguf_manager.scan_models()
        models = gguf_manager.list_models()

        self.models_table.setRowCount(len(models))

        for row, (model_name, model_info) in enumerate(models.items()):
            # Model name
            name_item = QTableWidgetItem(model_name)
            self.models_table.setItem(row, 0, name_item)

            # Size
            size_item = QTableWidgetItem(str(model_info["size_mb"]))
            self.models_table.setItem(row, 1, size_item)

            # Status
            status = "Loaded" if gguf_manager.current_model == model_name else "Available"
            status_item = QTableWidgetItem(status)
            self.models_table.setItem(row, 2, status_item)

            # Path
            path_item = QTableWidgetItem(model_info["path"])
            self.models_table.setItem(row, 3, path_item)

            # Load button
            load_btn = QPushButton("Load")
            load_btn.setEnabled(status != "Loaded")
            load_btn.clicked.connect(
                lambda checked, name=model_name: self.load_model(name),
            )
            self.models_table.setCellWidget(row, 4, load_btn)

        # Update model info
        self.update_model_info()

    def update_model_info(self):
        """Update the model information display."""
        if gguf_manager.current_model:
            models = gguf_manager.list_models()
            if gguf_manager.current_model in models:
                model_info = models[gguf_manager.current_model]
                info_text = f"""Current Model: {gguf_manager.current_model}
Path: {model_info['path']}
Size: {model_info['size_mb']} MB
Server Status: {'Running' if gguf_manager.is_server_running() else 'Stopped'}
Server URL: {gguf_manager.get_server_url()}"""
                self.model_info_text.setPlainText(info_text)
            else:
                self.model_info_text.setPlainText("Model information not available")
        else:
            self.model_info_text.setPlainText("No model currently loaded")

    def load_model(self, model_name: str):
        """Load a specific model."""
        try:
            success = gguf_manager.load_model(
                model_name,
                context_length=self.context_length_input.value(),
                gpu_layers=self.gpu_layers_input.value(),
                use_mmap=self.use_mmap_checkbox.isChecked(),
                use_mlock=self.use_mlock_checkbox.isChecked(),
            )

            if success:
                QMessageBox.information(
                    self, "Success", f"Model '{model_name}' loaded successfully!"
                )
                self.refresh_models()
            else:
                QMessageBox.warning(self, "Error", f"Failed to load model '{model_name}'")

        except Exception as e:
            logger.error("Exception in model_manager_dialog: %s", e)
            QMessageBox.critical(self, "Error", f"Error loading model: {e}")

    def load_selected_model(self):
        """Load the selected model."""
        current_row = self.models_table.currentRow()
        if current_row >= 0:
            model_name = self.models_table.item(current_row, 0).text()
            self.load_model(model_name)
        else:
            QMessageBox.information(self, "Info", "Please select a model to load.")

    def unload_current_model(self):
        """Unload the current model."""
        if gguf_manager.current_model:
            gguf_manager.unload_model()
            QMessageBox.information(self, "Success", "Model unloaded successfully!")
            self.refresh_models()
        else:
            QMessageBox.information(self, "Info", "No model is currently loaded.")

    def delete_selected_model(self):
        """Delete the selected model."""
        current_row = self.models_table.currentRow()
        if current_row >= 0:
            model_name = self.models_table.item(current_row, 0).text()

            reply = QMessageBox.question(
                self,
                "Confirm Delete",
                f"Are you sure you want to delete model '{model_name}'?",
                QMessageBox.Yes | QMessageBox.No,
            )

            if reply == QMessageBox.Yes:
                try:
                    models = gguf_manager.list_models()
                    if model_name in models:
                        model_path = Path(models[model_name]["path"])

                        # Unload if currently loaded
                        if gguf_manager.current_model == model_name:
                            gguf_manager.unload_model()

                        # Delete file
                        model_path.unlink()

                        QMessageBox.information(
                            self, "Success", f"Model '{model_name}' deleted successfully!"
                        )
                        self.refresh_models()
                    else:
                        QMessageBox.warning(self, "Error", "Model not found in list.")

                except Exception as e:
                    logger.error("Exception in model_manager_dialog: %s", e)
                    QMessageBox.critical(self, "Error", f"Error deleting model: {e}")
        else:
            QMessageBox.information(self, "Info", "Please select a model to delete.")

    def add_local_model(self):
        """Add a local model file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select GGUF Model File",
            "",
            "GGUF Files (*.gguf);;All Files (*)",
        )

        if file_path:
            try:
                source_path = Path(file_path)
                dest_path = gguf_manager.models_directory / source_path.name

                # Copy file to models directory
                import shutil

                shutil.copy2(source_path, dest_path)

                QMessageBox.information(
                    self, "Success", f"Model '{source_path.name}' added successfully!"
                )
                self.refresh_models()

            except Exception as e:
                logger.error("Exception in model_manager_dialog: %s", e)
                QMessageBox.critical(self, "Error", f"Error adding model: {e}")

    def download_model(self, model_url: str, model_name: str):
        """Download a model."""
        if model_name in self.download_threads:
            QMessageBox.information(
                self, "Info", f"Model '{model_name}' is already being downloaded."
            )
            return

        # Create progress bar
        progress_widget = QWidget()
        progress_layout = QHBoxLayout(progress_widget)

        progress_layout.addWidget(QLabel(f"{model_name}:"))

        progress_bar = QProgressBar()
        progress_bar.setMinimum(0)
        progress_bar.setMaximum(100)
        progress_layout.addWidget(progress_bar)

        cancel_btn = QPushButton("Cancel")
        progress_layout.addWidget(cancel_btn)

        self.progress_layout.addWidget(progress_widget)

        # Create download thread
        download_thread = ModelDownloadThread(model_url, model_name)
        download_thread.progress_updated.connect(
            lambda name, progress: progress_bar.setValue(int(progress))
            if name == model_name
            else None,
        )
        download_thread.download_finished.connect(
            lambda name, success: self.on_download_finished(name, success, progress_widget),
        )
        download_thread.log_message.connect(self.add_download_log)

        cancel_btn.clicked.connect(download_thread.cancel)

        self.download_threads[model_name] = download_thread
        download_thread.start()

    def download_custom_model(self):
        """Download a custom model from URL."""
        url = self.custom_url_input.text().strip()
        if not url:
            QMessageBox.information(self, "Info", "Please enter a model URL.")
            return

        # Security: Validate URL to prevent SSRF attacks
        allowed_domains = [
            "huggingface.co",
            "github.com",
            "raw.githubusercontent.com",
            "ollama.ai",
            "anthropic.com",
            "openai.com",
        ]

        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)

            # Check if URL is using HTTPS
            if parsed.scheme != "https":
                QMessageBox.warning(
                    self, "Security Warning", "Only HTTPS URLs are allowed for security reasons."
                )
                return

            # Check if domain is in allowed list
            domain_allowed = False
            for allowed_domain in allowed_domains:
                if parsed.hostname and (
                    parsed.hostname == allowed_domain
                    or parsed.hostname.endswith("." + allowed_domain)
                ):
                    domain_allowed = True
                    break

            if not domain_allowed:
                QMessageBox.warning(
                    self,
                    "Security Warning",
                    f"Domain {parsed.hostname} is not in the allowed list.\n"
                    f"Allowed domains: {', '.join(allowed_domains)}",
                )
                return

        except Exception as e:
            QMessageBox.warning(self, "Error", f"Invalid URL: {e}")
            return

        # Extract model name from URL
        model_name = Path(url).name
        if not model_name.endswith(".gguf"):
            model_name += ".gguf"

        self.download_model(url, model_name)
        self.custom_url_input.clear()

    def on_download_finished(self, model_name: str, success: bool, progress_widget: QWidget):
        """Handle download completion."""
        if model_name in self.download_threads:
            del self.download_threads[model_name]

        # Remove progress widget
        self.progress_layout.removeWidget(progress_widget)
        progress_widget.deleteLater()

        if success:
            self.add_download_log(f"✓ {model_name} downloaded successfully!")
            self.refresh_models()
        else:
            self.add_download_log(f"✗ {model_name} download failed!")

    def add_download_log(self, message: str):
        """Add a message to the download log."""
        self.download_log.append(message)

    def start_server(self):
        """Start the GGUF server."""
        try:
            if gguf_manager.start_server():
                QMessageBox.information(self, "Success", "GGUF server started successfully!")
            else:
                QMessageBox.warning(
                    self, "Error", "Failed to start GGUF server. Check dependencies."
                )
        except Exception as e:
            logger.error("Exception in model_manager_dialog: %s", e)
            QMessageBox.critical(self, "Error", f"Error starting server: {e}")

        self.update_server_status()

    def stop_server(self):
        """Stop the GGUF server."""
        try:
            gguf_manager.stop_server()
            QMessageBox.information(self, "Info", "GGUF server stop requested.")
        except Exception as e:
            logger.error("Exception in model_manager_dialog: %s", e)
            QMessageBox.critical(self, "Error", f"Error stopping server: {e}")

        self.update_server_status()

    def update_server_status(self):
        """Update the server status display."""
        if gguf_manager.is_server_running():
            status_text = f"✓ Server Running - {gguf_manager.get_server_url()}"
            if gguf_manager.current_model:
                status_text += f" - Model: {gguf_manager.current_model}"

            self.status_label.setText(status_text)
            self.server_status_label.setText("✓ Server is running")
            self.start_server_btn.setEnabled(False)
            self.stop_server_btn.setEnabled(True)

        else:
            self.status_label.setText("✗ Server Stopped")
            self.server_status_label.setText("✗ Server is not running")
            self.start_server_btn.setEnabled(True)
            self.stop_server_btn.setEnabled(False)

    def check_dependencies(self):
        """Check and display dependency status."""
        deps_status = []

        try:
            import flask

            flask_version = getattr(flask, "__version__", "unknown")
            deps_status.append(f"✓ Flask available (v{flask_version})")
        except ImportError as e:
            logger.error("Import error in model_manager_dialog: %s", e)
            deps_status.append("✗ Flask not available (pip install flask flask-cors)")

        try:
            import llama_cpp

            llama_version = getattr(llama_cpp, "__version__", "unknown")
            deps_status.append(f"✓ llama-cpp-python available (v{llama_version})")
        except ImportError as e:
            logger.error("Import error in model_manager_dialog: %s", e)
            deps_status.append("✗ llama-cpp-python not available (pip install llama-cpp-python)")

        try:
            import requests

            requests_version = getattr(requests, "__version__", "unknown")
            deps_status.append(f"✓ requests available (v{requests_version})")
        except ImportError as e:
            logger.error("Import error in model_manager_dialog: %s", e)
            deps_status.append("✗ requests not available (pip install requests)")

        self.deps_status_text.setPlainText("\n".join(deps_status))

    def closeEvent(self, event):
        """Handle dialog close."""
        # Cancel any ongoing downloads
        for thread in self.download_threads.values():
            thread.cancel()
            thread.wait(1000)  # Wait up to 1 second

        event.accept()
