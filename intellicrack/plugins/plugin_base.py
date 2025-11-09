"""Base plugin for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import os
from abc import ABC, abstractmethod
from typing import Any

from intellicrack.utils.logger import logger

logger.debug("Plugin base module loaded")

from ..utils.analysis.entropy_utils import calculate_byte_entropy

"""Base plugin interface for Intellicrack plugin system."""

"""
Base Plugin Framework for Intellicrack

This module provides a base class and utilities for plugin development
to reduce code duplication and standardize plugin initialization.
"""


class PluginMetadata:
    """Standard plugin metadata container."""

    def __init__(
        self,
        name: str,
        version: str,
        author: str,
        description: str,
        categories: list[str],
        supported_formats: list[str] | None = None,
        capabilities: list[str] | None = None,
    ):
        """Initialize plugin metadata.

        Args:
            name: Plugin name
            version: Plugin version
            author: Plugin author
            description: Plugin description
            categories: List of plugin categories
            supported_formats: Optional list of supported file formats
            capabilities: Optional list of plugin capabilities

        """
        self.name = name
        self.version = version
        self.author = author
        self.description = description
        self.categories = categories
        self.supported_formats = supported_formats or []
        self.capabilities = capabilities or []

    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary format."""
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "categories": self.categories,
            "supported_formats": self.supported_formats,
            "capabilities": self.capabilities,
        }


class PluginConfigManager:
    """Manages plugin configuration with defaults."""

    def __init__(self, default_config: dict[str, Any]):
        """Initialize configuration manager.

        Args:
            default_config: Default configuration dictionary

        """
        self.config = default_config.copy()

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        self.config[key] = value

    def update(self, updates: dict[str, Any]) -> None:
        """Update multiple configuration values."""
        self.config.update(updates)

    def to_dict(self) -> dict[str, Any]:
        """Return configuration as dictionary."""
        return self.config.copy()


class BasePlugin(ABC):
    """Base class for all Intellicrack plugins.

    Provides standard initialization, validation, and utility methods.
    """

    def __init__(self, metadata: PluginMetadata, default_config: dict[str, Any] | None = None):
        """Initialize base plugin.

        Args:
            metadata: Plugin metadata
            default_config: Optional default configuration

        """
        self.metadata = metadata
        self.config_manager = PluginConfigManager(default_config or {})

        # Expose metadata as direct attributes for backward compatibility
        self.name = metadata.name
        self.version = metadata.version
        self.author = metadata.author
        self.description = metadata.description
        self.categories = metadata.categories

    def get_metadata(self) -> dict[str, Any]:
        """Get plugin metadata.

        Returns:
            Dictionary containing plugin metadata

        """
        base_metadata = self.metadata.to_dict()
        base_metadata.update({"config": self.config_manager.to_dict(), "status": self.get_status()})
        return base_metadata

    def validate_binary(self, binary_path: str) -> tuple[bool, str]:
        """Validate binary file path and accessibility.

        Args:
            binary_path: Path to binary file

        Returns:
            Tuple of (is_valid, error_message)

        """
        if not binary_path:
            return False, "No binary path provided"

        if not os.path.exists(binary_path):
            return False, f"File does not exist: {binary_path}"

        if not os.path.isfile(binary_path):
            return False, f"Path is not a file: {binary_path}"

        if not os.access(binary_path, os.R_OK):
            return False, f"File is not readable: {binary_path}"

        # Check file size against config
        max_size = self.config_manager.get("max_file_size", 100 * 1024 * 1024)  # 100MB default
        try:
            file_size = os.path.getsize(binary_path)
            if file_size > max_size:
                return False, f"File too large: {file_size} bytes (max: {max_size})"
        except OSError as e:
            logger.error("OS error in plugin_base: %s", e)
            return False, f"Could not get file size: {e!s}"

        return True, "Valid"

    def get_status(self) -> str:
        """Get plugin status.

        Returns:
            Plugin status string

        """
        return "active"

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data.

        Args:
            data: Binary data

        Returns:
            Entropy value

        """
        return calculate_byte_entropy(data)

    @abstractmethod
    def run(self, *args, **kwargs) -> dict[str, Any]:
        """Execute the plugin's main functionality.

        Must be implemented by subclasses.

        Returns:
            Dictionary containing execution results

        """

    def cleanup(self) -> None:
        """Cleanup method called when plugin is unloaded.

        Override in subclasses if cleanup is needed.
        Default implementation performs no cleanup.
        """
        # Default implementation - no cleanup needed
        # Subclasses can override if they need cleanup
        logger.debug(f"Plugin {self.metadata.name} cleanup completed (no custom cleanup required)")


def create_plugin_info(metadata: PluginMetadata, entry_point: str = "register") -> dict[str, Any]:
    """Create standardized PLUGIN_INFO dictionary.

    Args:
        metadata: Plugin metadata
        entry_point: Entry point function name

    Returns:
        PLUGIN_INFO dictionary

    """
    info = metadata.to_dict()
    info["entry_point"] = entry_point
    return info


def create_register_function(plugin_class):
    """Create a standard register function for a plugin class.

    Args:
        plugin_class: Plugin class to register

    Returns:
        Register function

    """

    def register():
        """Register this plugin with Intellicrack."""
        return plugin_class()

    return register


# Common default configurations
DEFAULT_ANALYSIS_CONFIG = {
    "max_file_size": 100 * 1024 * 1024,  # 100MB
    "enable_caching": True,
    "detailed_analysis": True,
    "timeout_seconds": 30,
    "include_metadata": True,
}

DEFAULT_BINARY_CONFIG = {
    "max_file_size": 50 * 1024 * 1024,  # 50MB
    "detailed_output": True,
    "include_file_hash": True,
    "show_hex_preview": True,
    "analysis_timeout": 15,
}

DEFAULT_NETWORK_CONFIG = {
    "capture_timeout": 60,
    "max_packets": 10000,
    "enable_deep_inspection": True,
    "save_pcap": False,
    "filter_duplicates": True,
}


__all__ = [
    "DEFAULT_ANALYSIS_CONFIG",
    "DEFAULT_BINARY_CONFIG",
    "DEFAULT_NETWORK_CONFIG",
    "BasePlugin",
    "PluginConfigManager",
    "PluginMetadata",
    "create_plugin_info",
    "create_register_function",
]
