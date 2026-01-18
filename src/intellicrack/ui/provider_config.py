"""Provider configuration dialog for Intellicrack.

This module provides the UI for configuring LLM providers, including
API key management, model selection, and connection settings.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .resources import IconManager


if TYPE_CHECKING:
    from intellicrack.core.types import ModelInfo
    from intellicrack.providers.registry import ProviderRegistry

HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401


class ConnectionTestWorker(QThread):
    """Worker thread for testing provider connections.

    Runs connection tests in a separate thread to avoid blocking the UI.

    Attributes:
        finished: Signal emitted when test completes with (success, message).
    """

    finished: pyqtSignal = pyqtSignal(bool, str)

    def __init__(
        self,
        provider_id: str,
        api_key: str,
        api_base: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the connection test worker.

        Args:
            provider_id: The provider identifier.
            api_key: The API key to test.
            api_base: Optional API base URL.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._provider_id = provider_id
        self._api_key = api_key
        self._api_base = api_base

    def run(self) -> None:
        """Run the connection test in a separate thread."""
        try:
            success, message = self._test_provider_connection()
            self.finished.emit(success, message)
        except Exception as e:
            self.finished.emit(False, f"Connection error: {e}")

    def _test_provider_connection(self) -> tuple[bool, str]:
        """Test the connection to the provider.

        Returns:
            Tuple of (success, message).
        """
        timeout = httpx.Timeout(10.0)

        if self._provider_id == "anthropic":
            return self._test_anthropic(timeout)
        if self._provider_id == "openai":
            return self._test_openai(timeout)
        if self._provider_id == "google":
            return self._test_google(timeout)
        if self._provider_id == "ollama":
            return self._test_ollama(timeout)
        if self._provider_id == "openrouter":
            return self._test_openrouter(timeout)
        if self._provider_id == "huggingface":
            return self._test_huggingface(timeout)
        return False, f"Unknown provider: {self._provider_id}"

    def _test_anthropic(self, timeout: Any) -> tuple[bool, str]:
        """Test Anthropic API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, message).
        """
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self._api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-3-5-haiku-20241022",
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "test"}],
                    },
                )
                if response.status_code == HTTP_OK:
                    return True, "Connected to Anthropic API"
                if response.status_code == HTTP_UNAUTHORIZED:
                    return False, "Invalid API key"
                return False, f"API error: {response.status_code}"
        except httpx.ConnectError:
            return False, "Could not connect to Anthropic API"
        except Exception as e:
            return False, str(e)

    def _test_openai(self, timeout: Any) -> tuple[bool, str]:
        """Test OpenAI API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, message).
        """
        base_url = self._api_base or "https://api.openai.com/v1"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    f"{base_url}/models",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                if response.status_code == HTTP_OK:
                    return True, "Connected to OpenAI API"
                if response.status_code == HTTP_UNAUTHORIZED:
                    return False, "Invalid API key"
                return False, f"API error: {response.status_code}"
        except httpx.ConnectError:
            return False, "Could not connect to OpenAI API"
        except Exception as e:
            return False, str(e)

    def _test_google(self, timeout: Any) -> tuple[bool, str]:
        """Test Google Gemini API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, message).
        """
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    f"https://generativelanguage.googleapis.com/v1beta/models?key={self._api_key}",
                )
                if response.status_code == HTTP_OK:
                    return True, "Connected to Google Gemini API"
                if response.status_code == HTTP_BAD_REQUEST:
                    return False, "Invalid API key"
                return False, f"API error: {response.status_code}"
        except httpx.ConnectError:
            return False, "Could not connect to Google API"
        except Exception as e:
            return False, str(e)

    def _test_ollama(self, timeout: Any) -> tuple[bool, str]:
        """Test Ollama connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, message).
        """
        base_url = self._api_base or "http://localhost:11434"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(f"{base_url}/api/tags")
                if response.status_code == HTTP_OK:
                    return True, "Connected to Ollama"
                return False, f"Ollama error: {response.status_code}"
        except httpx.ConnectError:
            return False, "Could not connect to Ollama (is it running?)"
        except Exception as e:
            return False, str(e)

    def _test_openrouter(self, timeout: Any) -> tuple[bool, str]:
        """Test OpenRouter API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, message).
        """
        base_url = self._api_base or "https://openrouter.ai/api/v1"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    f"{base_url}/models",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                if response.status_code == HTTP_OK:
                    return True, "Connected to OpenRouter API"
                if response.status_code == HTTP_UNAUTHORIZED:
                    return False, "Invalid API key"
                return False, f"API error: {response.status_code}"
        except httpx.ConnectError:
            return False, "Could not connect to OpenRouter API"
        except Exception as e:
            return False, str(e)

    def _test_huggingface(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test HuggingFace Inference API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, message).
        """
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    "https://huggingface.co/api/models",
                    params={"filter": "text-generation", "limit": 1},
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                if response.status_code == HTTP_OK:
                    return True, "Connected to HuggingFace API"
                if response.status_code == HTTP_UNAUTHORIZED:
                    return False, "Invalid API token"
                return False, f"API error: {response.status_code}"
        except httpx.ConnectError:
            return False, "Could not connect to HuggingFace API"
        except Exception as e:
            return False, str(e)


class ModelRefreshWorker(QThread):
    """Worker thread for refreshing model lists from provider APIs.

    Attributes:
        finished: Signal emitted when refresh completes with (success, models, message).
    """

    finished: pyqtSignal = pyqtSignal(bool, list, str)

    def __init__(
        self,
        provider_id: str,
        api_key: str,
        api_base: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the model refresh worker.

        Args:
            provider_id: The provider identifier.
            api_key: The API key for authentication.
            api_base: Optional API base URL.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._provider_id = provider_id
        self._api_key = api_key
        self._api_base = api_base

    def run(self) -> None:
        """Run the model refresh in a separate thread."""
        try:
            success, models, message = self._fetch_models()
            self.finished.emit(success, models, message)
        except Exception as e:
            self.finished.emit(False, [], f"Error fetching models: {e}")

    def _fetch_models(self) -> tuple[bool, list[str], str]:
        """Fetch available models from the provider API.

        Returns:
            Tuple of (success, model_list, message).
        """
        timeout = httpx.Timeout(15.0)

        if self._provider_id == "anthropic":
            return self._fetch_anthropic_models()
        if self._provider_id == "openai":
            return self._fetch_openai_models(timeout)
        if self._provider_id == "google":
            return self._fetch_google_models(timeout)
        if self._provider_id == "ollama":
            return self._fetch_ollama_models(timeout)
        if self._provider_id == "openrouter":
            return self._fetch_openrouter_models(timeout)
        if self._provider_id == "huggingface":
            return self._fetch_huggingface_models(timeout)
        return False, [], f"Unknown provider: {self._provider_id}"

    @staticmethod
    def _fetch_anthropic_models() -> tuple[bool, list[str], str]:
        """Fetch Anthropic models (returns known models as API doesn't list them).

        Returns:
            Tuple of (success, model_list, message).
        """
        models = [
            "claude-sonnet-4-20250514",
            "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022",
            "claude-3-opus-20240229",
            "claude-3-haiku-20240307",
        ]
        return True, models, "Anthropic models loaded"

    def _fetch_openai_models(self, timeout: Any) -> tuple[bool, list[str], str]:
        """Fetch OpenAI models from API.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, model_list, message).
        """
        base_url = self._api_base or "https://api.openai.com/v1"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    f"{base_url}/models",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                if response.status_code == HTTP_OK:
                    data = response.json()
                    models = [m["id"] for m in data.get("data", []) if m["id"].startswith(("gpt-4", "gpt-3.5", "o1", "o3"))]
                    models.sort(reverse=True)
                    return True, models[:20], f"Found {len(models)} OpenAI models"
                return False, [], f"API error: {response.status_code}"
        except Exception as e:
            return False, [], str(e)

    def _fetch_google_models(self, timeout: Any) -> tuple[bool, list[str], str]:
        """Fetch Google Gemini models from API.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, model_list, message).
        """
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    f"https://generativelanguage.googleapis.com/v1beta/models?key={self._api_key}",
                )
                if response.status_code == HTTP_OK:
                    data = response.json()
                    models = [m["name"].replace("models/", "") for m in data.get("models", []) if "gemini" in m["name"].lower()]
                    return True, models, f"Found {len(models)} Gemini models"
                return False, [], f"API error: {response.status_code}"
        except Exception as e:
            return False, [], str(e)

    def _fetch_ollama_models(self, timeout: Any) -> tuple[bool, list[str], str]:
        """Fetch installed Ollama models.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, model_list, message).
        """
        base_url = self._api_base or "http://localhost:11434"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(f"{base_url}/api/tags")
                if response.status_code == HTTP_OK:
                    data = response.json()
                    models = [m["name"] for m in data.get("models", [])]
                    return True, models, f"Found {len(models)} Ollama models"
                return False, [], f"Ollama error: {response.status_code}"
        except Exception as e:
            return False, [], str(e)

    def _fetch_openrouter_models(self, timeout: Any) -> tuple[bool, list[str], str]:
        """Fetch OpenRouter models from API.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, model_list, message).
        """
        base_url = self._api_base or "https://openrouter.ai/api/v1"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    f"{base_url}/models",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                if response.status_code == HTTP_OK:
                    data = response.json()
                    models = [m["id"] for m in data.get("data", [])]
                    models.sort()
                    return True, models[:50], f"Found {len(models)} OpenRouter models"
                return False, [], f"API error: {response.status_code}"
        except Exception as e:
            return False, [], str(e)

    def _fetch_huggingface_models(
        self,
        timeout: httpx.Timeout,
    ) -> tuple[bool, list[str], str]:
        """Fetch HuggingFace text-generation models from Hub API.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, model_list, message).
        """
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    "https://huggingface.co/api/models",
                    params={
                        "filter": "text-generation-inference",
                        "sort": "downloads",
                        "direction": -1,
                        "limit": 50,
                    },
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                if response.status_code == HTTP_OK:
                    data = response.json()
                    models = [
                        m["id"]
                        for m in data
                        if m.get("pipeline_tag") in {"text-generation", "conversational"}
                    ]
                    return (
                        True,
                        models[:30],
                        f"Found {len(models)} HuggingFace models",
                    )
                return False, [], f"API error: {response.status_code}"
        except Exception as e:
            return False, [], str(e)


class ProviderConfigDialog(QDialog):
    """Dialog for configuring LLM providers.

    Allows users to:
    - Enter API keys for each provider
    - Select default models
    - Configure timeout and retry settings
    - Test provider connections

    Attributes:
        provider_updated: Signal emitted when a provider config changes.
    """

    provider_updated: pyqtSignal = pyqtSignal(str)

    def __init__(
        self,
        provider_registry: ProviderRegistry | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the provider configuration dialog.

        Args:
            provider_registry: Registry containing provider instances.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._registry = provider_registry
        self._provider_widgets: dict[str, ProviderSettingsWidget] = {}
        self._current_provider: str | None = None
        self._config_path = Path.home() / ".intellicrack" / "providers.json"

        self._setup_ui()
        self._load_providers()

        self.setWindowTitle("Provider Settings")
        self.resize(700, 500)

    def _setup_ui(self) -> None:
        """Set up the dialog UI layout."""
        layout = QHBoxLayout(self)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self._provider_list = QListWidget()
        self._provider_list.setMaximumWidth(180)
        self._provider_list.currentRowChanged.connect(self._on_provider_selected)

        self._settings_stack = QStackedWidget()

        splitter.addWidget(self._provider_list)
        splitter.addWidget(self._settings_stack)
        splitter.setSizes([180, 520])

        layout.addWidget(splitter)

        button_layout = QVBoxLayout()
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Apply
        )
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)

        apply_button = button_box.button(QDialogButtonBox.StandardButton.Apply)
        if apply_button:
            apply_button.clicked.connect(self._on_apply)

        button_layout.addWidget(button_box)

        main_layout = QVBoxLayout()
        main_layout.addWidget(splitter, stretch=1)
        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

    def _load_providers(self) -> None:
        """Load provider configurations into the list."""
        providers = [
            ("Anthropic", "anthropic"),
            ("OpenAI", "openai"),
            ("Google Gemini", "google"),
            ("Ollama", "ollama"),
            ("OpenRouter", "openrouter"),
        ]

        for display_name, provider_id in providers:
            item = QListWidgetItem(display_name)
            item.setData(Qt.ItemDataRole.UserRole, provider_id)
            self._provider_list.addItem(item)

            widget = ProviderSettingsWidget(provider_id, self._registry, self._config_path)
            self._settings_stack.addWidget(widget)
            self._provider_widgets[provider_id] = widget

        if self._provider_list.count() > 0:
            self._provider_list.setCurrentRow(0)

    def _on_provider_selected(self, index: int) -> None:
        """Handle provider selection change.

        Args:
            index: The selected provider index.
        """
        if index >= 0:
            item = self._provider_list.item(index)
            if item:
                provider_id = item.data(Qt.ItemDataRole.UserRole)
                self._current_provider = provider_id
                self._settings_stack.setCurrentIndex(index)

    def _on_accept(self) -> None:
        """Handle dialog acceptance."""
        self._save_all_settings()
        self.accept()

    def _on_apply(self) -> None:
        """Handle apply button click."""
        self._save_all_settings()

    def _save_all_settings(self) -> None:
        """Save settings for all providers."""
        for provider_id, widget in self._provider_widgets.items():
            widget.save_settings()
            self.provider_updated.emit(provider_id)

    def get_settings(self) -> dict[str, dict[str, Any]]:
        """Get all provider settings.

        Returns:
            Dictionary mapping provider IDs to their settings.
        """
        settings: dict[str, dict[str, Any]] = {}
        for provider_id, widget in self._provider_widgets.items():
            settings[provider_id] = widget.get_settings()
        return settings


class ProviderSettingsWidget(QFrame):
    """Widget for configuring a single provider.

    Displays API key input, model selection, and connection settings
    for a specific LLM provider.

    Attributes:
        connection_tested: Signal emitted after connection test.
    """

    connection_tested: pyqtSignal = pyqtSignal(bool, str)

    def __init__(
        self,
        provider_id: str,
        registry: ProviderRegistry | None = None,
        config_path: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the provider settings widget.

        Args:
            provider_id: The provider identifier.
            registry: Provider registry for connection testing.
            config_path: Path to configuration file.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._provider_id = provider_id
        self._registry = registry
        self._config_path = config_path or Path.home() / ".intellicrack" / "providers.json"
        self._models: list[ModelInfo] = []
        self._test_worker: ConnectionTestWorker | None = None
        self._refresh_worker: ModelRefreshWorker | None = None

        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
        """Set up the widget UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        title = QLabel(f"<h3>{self._get_display_name()} Settings</h3>")
        layout.addWidget(title)

        credentials_group = QGroupBox("Credentials")
        credentials_layout = QFormLayout()

        self._api_key_input = QLineEdit()
        self._api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_key_input.setMinimumWidth(300)
        credentials_layout.addRow("API Key:", self._api_key_input)

        self._api_base_input: QLineEdit | None
        self._org_id_input: QLineEdit | None

        if self._provider_id == "ollama":
            self._api_base_input = QLineEdit()
            self._api_base_input.setText("http://localhost:11434")
            credentials_layout.addRow("API Base URL:", self._api_base_input)
        elif self._provider_id in {"openai", "openrouter"}:
            self._api_base_input = QLineEdit()
            credentials_layout.addRow("API Base URL (optional):", self._api_base_input)
        else:
            self._api_base_input = None

        if self._provider_id == "openai":
            self._org_id_input = QLineEdit()
            credentials_layout.addRow("Organization ID:", self._org_id_input)
        else:
            self._org_id_input = None

        credentials_group.setLayout(credentials_layout)
        layout.addWidget(credentials_group)

        model_group = QGroupBox("Model Settings")
        model_layout = QFormLayout()

        model_row = QHBoxLayout()
        self._model_combo = QComboBox()
        self._model_combo.setMinimumWidth(250)
        model_row.addWidget(self._model_combo)

        self._refresh_models_btn = QPushButton("Refresh")
        self._refresh_models_btn.clicked.connect(self._refresh_models)
        model_row.addWidget(self._refresh_models_btn)
        model_row.addStretch()

        model_layout.addRow("Default Model:", model_row)

        model_group.setLayout(model_layout)
        layout.addWidget(model_group)

        connection_group = QGroupBox("Connection Settings")
        connection_layout = QFormLayout()

        self._enabled_checkbox = QCheckBox("Enable this provider")
        self._enabled_checkbox.setChecked(True)
        connection_layout.addRow(self._enabled_checkbox)

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(10, 600)
        self._timeout_spin.setValue(120)
        self._timeout_spin.setSuffix(" seconds")
        connection_layout.addRow("Timeout:", self._timeout_spin)

        self._retries_spin = QSpinBox()
        self._retries_spin.setRange(0, 10)
        self._retries_spin.setValue(3)
        connection_layout.addRow("Max Retries:", self._retries_spin)

        connection_group.setLayout(connection_layout)
        layout.addWidget(connection_group)

        test_layout = QHBoxLayout()
        self._test_btn = QPushButton("Test Connection")
        self._test_btn.clicked.connect(self._test_connection)
        test_layout.addWidget(self._test_btn)

        self._status_icon = QLabel()
        self._status_icon.setFixedSize(20, 20)
        test_layout.addWidget(self._status_icon)

        self._status_label = QLabel()
        self._status_label.setObjectName("status_label")
        test_layout.addWidget(self._status_label)
        test_layout.addStretch()

        layout.addLayout(test_layout)
        layout.addStretch()

    def _get_display_name(self) -> str:
        """Get the display name for the provider.

        Returns:
            Human-readable provider name.
        """
        names = {
            "anthropic": "Anthropic",
            "openai": "OpenAI",
            "google": "Google Gemini",
            "ollama": "Ollama",
            "openrouter": "OpenRouter",
        }
        return names.get(self._provider_id, self._provider_id.title())

    def _load_settings(self) -> None:
        """Load settings from config file and environment."""
        saved_settings = self._load_from_config()

        env_vars = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "google": "GOOGLE_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
        }

        if self._provider_id in env_vars:
            env_key = os.environ.get(env_vars[self._provider_id], "")
            config_key = saved_settings.get("api_key", "")
            key = config_key or env_key
            if key:
                self._api_key_input.setText(key)

        if self._provider_id == "ollama":
            base_url = saved_settings.get("api_base", os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
            if self._api_base_input:
                self._api_base_input.setText(base_url)
        elif self._api_base_input:
            base_url = saved_settings.get("api_base", "")
            self._api_base_input.setText(base_url)

        if self._org_id_input:
            org_id = saved_settings.get("organization_id", "")
            self._org_id_input.setText(org_id)

        self._enabled_checkbox.setChecked(saved_settings.get("enabled", True))
        self._timeout_spin.setValue(saved_settings.get("timeout_seconds", 120))
        self._retries_spin.setValue(saved_settings.get("max_retries", 3))

        saved_model = saved_settings.get("default_model", "")
        self._populate_default_models()
        if saved_model:
            idx = self._model_combo.findText(saved_model)
            if idx >= 0:
                self._model_combo.setCurrentIndex(idx)

    def _load_from_config(self) -> dict[str, Any]:
        """Load settings from the config file.

        Returns:
            Dictionary of saved settings for this provider.
        """
        if not self._config_path.exists():
            return {}

        try:
            with open(self._config_path, encoding="utf-8") as f:
                all_settings: dict[str, Any] = json.load(f)
                result: dict[str, Any] = all_settings.get(self._provider_id, {})
                return result
        except (json.JSONDecodeError, OSError):
            return {}

    def _populate_default_models(self) -> None:
        """Populate model dropdown with default models."""
        default_models: dict[str, list[str]] = {
            "anthropic": [
                "claude-sonnet-4-20250514",
                "claude-3-5-sonnet-20241022",
                "claude-3-5-haiku-20241022",
                "claude-3-opus-20240229",
            ],
            "openai": [
                "gpt-4o",
                "gpt-4o-mini",
                "gpt-4-turbo",
                "gpt-4",
                "gpt-3.5-turbo",
            ],
            "google": [
                "gemini-2.0-flash-exp",
                "gemini-1.5-pro",
                "gemini-1.5-flash",
                "gemini-1.0-pro",
            ],
            "ollama": [
                "llama3.3:latest",
                "llama3.2:latest",
                "codellama:latest",
                "mistral:latest",
                "deepseek-coder:latest",
            ],
            "openrouter": [
                "anthropic/claude-sonnet-4",
                "anthropic/claude-3.5-sonnet",
                "openai/gpt-4o",
                "google/gemini-pro-1.5",
                "meta-llama/llama-3.3-70b-instruct",
            ],
            "huggingface": [
                "meta-llama/Llama-3.3-70B-Instruct",
                "meta-llama/Llama-3.1-8B-Instruct",
                "mistralai/Mistral-7B-Instruct-v0.3",
                "Qwen/Qwen2.5-72B-Instruct",
                "google/gemma-2-9b-it",
                "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B",
            ],
        }

        models = default_models.get(self._provider_id, [])
        self._model_combo.clear()
        self._model_combo.addItems(models)

    def _refresh_models(self) -> None:
        """Refresh the model list from the provider API."""
        icon_manager = IconManager.get_instance()
        self._status_icon.setPixmap(icon_manager.get_pixmap("status_loading", 16))
        self._status_label.setText("Refreshing models...")
        self._refresh_models_btn.setEnabled(False)

        api_key = self._api_key_input.text().strip()
        api_base = self._api_base_input.text().strip() if self._api_base_input else None

        if not api_key and self._provider_id != "ollama":
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_warning", 16))
            self._status_label.setText("API key required to refresh models")
            self._refresh_models_btn.setEnabled(True)
            return

        self._refresh_worker = ModelRefreshWorker(self._provider_id, api_key, api_base, self)
        self._refresh_worker.finished.connect(self._on_models_refreshed)
        self._refresh_worker.start()

    def _on_models_refreshed(self, success: bool, models: list[str], message: str) -> None:
        """Handle model refresh completion.

        Args:
            success: Whether refresh was successful.
            models: List of model IDs.
            message: Status message.
        """
        self._refresh_models_btn.setEnabled(True)
        icon_manager = IconManager.get_instance()

        if success and models:
            current_model = self._model_combo.currentText()
            self._model_combo.clear()
            self._model_combo.addItems(models)
            idx = self._model_combo.findText(current_model)
            if idx >= 0:
                self._model_combo.setCurrentIndex(idx)
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_success", 16))
            self._status_label.setText(message)
        else:
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_error", 16))
            self._status_label.setText(message or "Failed to refresh models")

    def _test_connection(self) -> None:
        """Test the provider connection."""
        icon_manager = IconManager.get_instance()
        self._status_icon.setPixmap(icon_manager.get_pixmap("status_loading", 16))
        self._status_label.setText("Testing connection...")
        self._test_btn.setEnabled(False)

        api_key = self._api_key_input.text().strip()
        api_base = self._api_base_input.text().strip() if self._api_base_input else None

        if not api_key and self._provider_id != "ollama":
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_error", 16))
            self._status_label.setText("API key required")
            self._test_btn.setEnabled(True)
            return

        self._test_worker = ConnectionTestWorker(self._provider_id, api_key, api_base, self)
        self._test_worker.finished.connect(self._on_connection_tested)
        self._test_worker.start()

    def _on_connection_tested(self, success: bool, message: str) -> None:
        """Handle connection test completion.

        Args:
            success: Whether connection was successful.
            message: Status message.
        """
        self._test_btn.setEnabled(True)
        icon_manager = IconManager.get_instance()

        if success:
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_success", 16))
            self._status_label.setText(message)
        else:
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_error", 16))
            self._status_label.setText(message)

        self.connection_tested.emit(success, message)

    def get_settings(self) -> dict[str, Any]:
        """Get current settings as a dictionary.

        Returns:
            Dictionary of current settings.
        """
        settings: dict[str, Any] = {
            "enabled": self._enabled_checkbox.isChecked(),
            "api_key": self._api_key_input.text().strip(),
            "default_model": self._model_combo.currentText(),
            "timeout_seconds": self._timeout_spin.value(),
            "max_retries": self._retries_spin.value(),
        }

        if self._api_base_input:
            settings["api_base"] = self._api_base_input.text().strip()

        if self._org_id_input:
            settings["organization_id"] = self._org_id_input.text().strip()

        return settings

    def save_settings(self) -> None:
        """Save current settings to config file and .env file."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)

        all_settings: dict[str, dict[str, Any]] = {}
        if self._config_path.exists():
            try:
                with open(self._config_path, encoding="utf-8") as f:
                    all_settings = json.load(f)
            except (json.JSONDecodeError, OSError):
                all_settings = {}

        settings = self.get_settings()
        if settings.get("api_key"):
            all_settings[self._provider_id] = settings
        elif self._provider_id in all_settings:
            del all_settings[self._provider_id]

        try:
            with open(self._config_path, "w", encoding="utf-8") as f:
                json.dump(all_settings, f, indent=2)
        except OSError as e:
            QMessageBox.warning(
                self,
                "Save Error",
                f"Failed to save settings: {e}",
            )

        self._persist_api_key_to_env()

    def _persist_api_key_to_env(self) -> None:
        """Persist the API key to the .env file."""
        api_key = self._api_key_input.text().strip()
        if not api_key:
            return

        env_var_mapping: dict[str, str] = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "google": "GOOGLE_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
            "ollama": "OLLAMA_API_KEY",
            "grok": "XAI_API_KEY",
        }

        if self._provider_id not in env_var_mapping:
            return

        try:
            from intellicrack.credentials.env_loader import get_credential_loader  # noqa: PLC0415

            loader = get_credential_loader()
            loader.save_to_env_file(env_var_mapping[self._provider_id], api_key)

            if self._provider_id == "ollama" and self._api_base_input:
                host = self._api_base_input.text().strip()
                if host and host != "http://localhost:11434":
                    loader.save_to_env_file("OLLAMA_HOST", host)
        except Exception as e:
            QMessageBox.warning(
                self,
                "Save Warning",
                f"Settings saved but failed to update .env file: {e}",
            )


class ModelSelectionDialog(QDialog):
    """Dialog for selecting a specific model from a provider.

    Displays available models with their capabilities and allows
    the user to select one.

    Attributes:
        model_selected: Signal emitted when a model is selected.
    """

    model_selected: pyqtSignal = pyqtSignal(str)

    def __init__(
        self,
        models: list[ModelInfo],
        current_model: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the model selection dialog.

        Args:
            models: List of available models.
            current_model: Currently selected model ID.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._models = models
        self._current_model = current_model

        self._setup_ui()
        self._populate_models()

        self.setWindowTitle("Select Model")
        self.resize(500, 400)

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        self._model_list = QListWidget()
        self._model_list.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self._model_list)

        self._info_label = QLabel()
        self._info_label.setWordWrap(True)
        self._info_label.setObjectName("info_label")
        layout.addWidget(self._info_label)

        self._model_list.currentRowChanged.connect(self._on_model_selected)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _populate_models(self) -> None:
        """Populate the model list."""
        for model in self._models:
            item = QListWidgetItem(model.name)
            item.setData(Qt.ItemDataRole.UserRole, model)
            self._model_list.addItem(item)

            if self._current_model and model.id == self._current_model:
                self._model_list.setCurrentItem(item)

    def _on_model_selected(self, index: int) -> None:
        """Handle model selection change.

        Args:
            index: Selected model index.
        """
        if index >= 0:
            item = self._model_list.item(index)
            if item:
                model: ModelInfo = item.data(Qt.ItemDataRole.UserRole)
                info_parts = [
                    f"<b>{model.name}</b>",
                    f"ID: {model.id}",
                    f"Context: {model.context_window:,} tokens",
                ]
                if model.supports_tools:
                    info_parts.append("Supports tool calling")
                if model.supports_vision:
                    info_parts.append("Supports vision")

                self._info_label.setText("<br>".join(info_parts))

    def _on_item_double_clicked(self, _item: QListWidgetItem) -> None:
        """Handle double-click on model item.

        Args:
            _item: The double-clicked item (unused, current selection used).
        """
        self._on_accept()

    def _on_accept(self) -> None:
        """Handle dialog acceptance."""
        current_item = self._model_list.currentItem()
        if current_item:
            model: ModelInfo = current_item.data(Qt.ItemDataRole.UserRole)
            self.model_selected.emit(model.id)
            self.accept()

    def get_selected_model(self) -> str | None:
        """Get the selected model ID.

        Returns:
            Selected model ID or None if nothing selected.
        """
        current_item = self._model_list.currentItem()
        if current_item:
            model: ModelInfo = current_item.data(Qt.ItemDataRole.UserRole)
            return model.id
        return None
