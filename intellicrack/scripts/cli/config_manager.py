#!/usr/bin/env python3
"""
Advanced Configuration Manager - Granular CLI settings for Intellicrack

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
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

# Optional imports for enhanced config management
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, FloatPrompt, IntPrompt, Prompt
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


@dataclass
class ConfigOption:
    """Represents a single configuration option."""
    name: str
    value: Any
    description: str
    data_type: type
    default: Any
    validator: Optional[Callable[[Any], bool]] = None
    choices: Optional[List[Any]] = None
    category: str = "general"
    requires_restart: bool = False
    advanced: bool = False


class ConfigManager:
    """Advanced configuration management for Intellicrack CLI."""

    def __init__(self, config_dir: Optional[str] = None):
        """Initialize configuration manager.

        Args:
            config_dir: Custom configuration directory path
        """
        self.config_dir = config_dir or os.path.expanduser("~/.intellicrack")
        self.config_file = os.path.join(self.config_dir, "cli_config.json")
        self.backup_dir = os.path.join(self.config_dir, "config_backups")

        self.console = Console() if RICH_AVAILABLE else None

        # Initialize configuration options
        self._init_config_options()

        # Current configuration values
        self.config = {}

        # Ensure directories exist
        self._ensure_directories()

        # Load configuration
        self.load_config()

    def _ensure_directories(self):
        """Ensure configuration directories exist."""
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)

    def _init_config_options(self):
        """Initialize all configuration options with defaults."""
        self.options = {
            # General Settings
            "theme": ConfigOption(
                name="theme",
                value="default",
                description="CLI color theme",
                data_type=str,
                default="default",
                choices=["default", "dark", "light", "cyberpunk", "matrix", "minimal"],
                category="appearance"
            ),
            "auto_save": ConfigOption(
                name="auto_save",
                value=True,
                description="Automatically save analysis results",
                data_type=bool,
                default=True,
                category="general"
            ),
            "max_history": ConfigOption(
                name="max_history",
                value=1000,
                description="Maximum command history entries",
                data_type=int,
                default=1000,
                validator=lambda x: 10 <= x <= 10000,
                category="general"
            ),

            # Analysis Settings
            "analysis_timeout": ConfigOption(
                name="analysis_timeout",
                value=300,
                description="Analysis timeout in seconds",
                data_type=int,
                default=300,
                validator=lambda x: 10 <= x <= 3600,
                category="analysis"
            ),
            "parallel_workers": ConfigOption(
                name="parallel_workers",
                value=4,
                description="Number of parallel analysis workers",
                data_type=int,
                default=4,
                validator=lambda x: 1 <= x <= 32,
                category="analysis"
            ),
            "cache_results": ConfigOption(
                name="cache_results",
                value=True,
                description="Cache analysis results for faster repeated analysis",
                data_type=bool,
                default=True,
                category="analysis"
            ),
            "detailed_logging": ConfigOption(
                name="detailed_logging",
                value=False,
                description="Enable detailed analysis logging",
                data_type=bool,
                default=False,
                category="analysis",
                advanced=True
            ),

            # Progress and Display
            "show_progress": ConfigOption(
                name="show_progress",
                value=True,
                description="Show progress bars during analysis",
                data_type=bool,
                default=True,
                category="display"
            ),
            "progress_style": ConfigOption(
                name="progress_style",
                value="rich",
                description="Progress bar style",
                data_type=str,
                default="rich",
                choices=["rich", "simple", "minimal", "verbose"],
                category="display"
            ),
            "table_style": ConfigOption(
                name="table_style",
                value="default",
                description="Table display style",
                data_type=str,
                default="default",
                choices=["default", "ascii", "double", "rounded", "heavy"],
                category="display"
            ),
            "page_size": ConfigOption(
                name="page_size",
                value=20,
                description="Number of items per page in listings",
                data_type=int,
                default=20,
                validator=lambda x: 5 <= x <= 100,
                category="display"
            ),

            # Export Settings
            "default_export_format": ConfigOption(
                name="default_export_format",
                value="json",
                description="Default export format",
                data_type=str,
                default="json",
                choices=["json", "html", "markdown", "csv", "xlsx", "xml"],
                category="export"
            ),
            "export_compression": ConfigOption(
                name="export_compression",
                value=True,
                description="Compress large export files",
                data_type=bool,
                default=True,
                category="export"
            ),
            "include_raw_data": ConfigOption(
                name="include_raw_data",
                value=False,
                description="Include raw binary data in exports",
                data_type=bool,
                default=False,
                category="export",
                advanced=True
            ),

            # Security Settings
            "sandbox_analysis": ConfigOption(
                name="sandbox_analysis",
                value=True,
                description="Run analysis in sandboxed environment",
                data_type=bool,
                default=True,
                category="security",
                requires_restart=True
            ),
            "network_access": ConfigOption(
                name="network_access",
                value=False,
                description="Allow network access during analysis",
                data_type=bool,
                default=False,
                category="security",
                advanced=True,
                requires_restart=True
            ),
            "temp_cleanup": ConfigOption(
                name="temp_cleanup",
                value=True,
                description="Automatically clean temporary files",
                data_type=bool,
                default=True,
                category="security"
            ),

            # AI Settings
            "ai_backend": ConfigOption(
                name="ai_backend",
                value="local",
                description="AI backend provider",
                data_type=str,
                default="local",
                choices=["local", "openai", "anthropic", "mock"],
                category="ai",
                requires_restart=True
            ),
            "ai_model": ConfigOption(
                name="ai_model",
                value="gpt-3.5-turbo",
                description="AI model to use",
                data_type=str,
                default="gpt-3.5-turbo",
                category="ai"
            ),
            "ai_max_tokens": ConfigOption(
                name="ai_max_tokens",
                value=2000,
                description="Maximum tokens for AI responses",
                data_type=int,
                default=2000,
                validator=lambda x: 100 <= x <= 8000,
                category="ai"
            ),
            "ai_temperature": ConfigOption(
                name="ai_temperature",
                value=0.7,
                description="AI response creativity (0.0-2.0)",
                data_type=float,
                default=0.7,
                validator=lambda x: 0.0 <= x <= 2.0,
                category="ai",
                advanced=True
            ),

            # Performance Settings
            "memory_limit": ConfigOption(
                name="memory_limit",
                value=2048,
                description="Memory limit in MB for analysis",
                data_type=int,
                default=2048,
                validator=lambda x: 512 <= x <= 16384,
                category="performance",
                advanced=True
            ),
            "cpu_limit": ConfigOption(
                name="cpu_limit",
                value=80,
                description="CPU usage limit percentage",
                data_type=int,
                default=80,
                validator=lambda x: 10 <= x <= 100,
                category="performance",
                advanced=True
            ),
            "disk_cache_size": ConfigOption(
                name="disk_cache_size",
                value=1024,
                description="Disk cache size in MB",
                data_type=int,
                default=1024,
                validator=lambda x: 100 <= x <= 10240,
                category="performance"
            ),

            # Developer Settings
            "debug_mode": ConfigOption(
                name="debug_mode",
                value=False,
                description="Enable debug mode",
                data_type=bool,
                default=False,
                category="developer",
                advanced=True
            ),
            "verbose_errors": ConfigOption(
                name="verbose_errors",
                value=False,
                description="Show detailed error information",
                data_type=bool,
                default=False,
                category="developer",
                advanced=True
            ),
            "profile_performance": ConfigOption(
                name="profile_performance",
                value=False,
                description="Enable performance profiling",
                data_type=bool,
                default=False,
                category="developer",
                advanced=True
            ),
        }

        # Set initial values from defaults
        for option in self.options.values():
            self.config[option.name] = option.default

    def load_config(self):
        """Load configuration from file."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)

                # Update config with saved values, validating each one
                for key, value in saved_config.items():
                    if key in self.options:
                        if self._validate_value(key, value):
                            self.config[key] = value
                            self.options[key].value = value
                        else:
                            print(f"Warning: Invalid value for {key}, using default")
                    else:
                        print(f"Warning: Unknown config option {key}, ignoring")

        except Exception as e:
            print(f"Error loading config: {e}, using defaults")

    def save_config(self, create_backup: bool = True):
        """Save configuration to file.

        Args:
            create_backup: Whether to create a backup before saving
        """
        try:
            # Create backup if requested
            if create_backup and os.path.exists(self.config_file):
                self._create_backup()

            # Save current config
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)

            return True

        except Exception as e:
            print(f"Error saving config: {e}")
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value.

        Args:
            key: Configuration key
            default: Default value if key not found

        Returns:
            Configuration value
        """
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> bool:
        """Set configuration value.

        Args:
            key: Configuration key
            value: Value to set

        Returns:
            True if successful, False otherwise
        """
        if key not in self.options:
            return False

        if not self._validate_value(key, value):
            return False

        self.config[key] = value
        self.options[key].value = value
        return True

    def reset_to_defaults(self, category: Optional[str] = None):
        """Reset configuration to defaults.

        Args:
            category: Optional category to reset (resets all if None)
        """
        for option in self.options.values():
            if category is None or option.category == category:
                self.config[option.name] = option.default
                option.value = option.default

    def get_categories(self) -> List[str]:
        """Get list of configuration categories."""
        categories = set(option.category for option in self.options.values())
        return sorted(list(categories))

    def get_options_by_category(self, category: str, include_advanced: bool = False) -> Dict[str, ConfigOption]:
        """Get configuration options by category.

        Args:
            category: Category name
            include_advanced: Whether to include advanced options

        Returns:
            Dictionary of options in the category
        """
        return {
            name: option for name, option in self.options.items()
            if option.category == category and (include_advanced or not option.advanced)
        }

    def _validate_value(self, key: str, value: Any) -> bool:
        """Validate configuration value.

        Args:
            key: Configuration key
            value: Value to validate

        Returns:
            True if valid, False otherwise
        """
        if key not in self.options:
            return False

        option = self.options[key]

        # Check type
        if not isinstance(value, option.data_type):
            try:
                # Try to convert
                value = option.data_type(value)
            except (ValueError, TypeError):
                return False

        # Check choices
        if option.choices and value not in option.choices:
            return False

        # Check custom validator
        if option.validator and not option.validator(value):
            return False

        return True

    def _create_backup(self):
        """Create configuration backup."""
        try:
            timestamp = int(time.time())
            backup_file = os.path.join(self.backup_dir, f"config_backup_{timestamp}.json")

            import shutil
            shutil.copy2(self.config_file, backup_file)

            # Keep only last 10 backups
            backups = sorted([
                f for f in os.listdir(self.backup_dir)
                if f.startswith("config_backup_") and f.endswith(".json")
            ])

            while len(backups) > 10:
                old_backup = backups.pop(0)
                try:
                    os.remove(os.path.join(self.backup_dir, old_backup))
                except OSError:
                    pass

        except Exception:
            pass  # Backup is optional

    def export_config(self, export_path: str, format_type: str = "json") -> bool:
        """Export configuration to file.

        Args:
            export_path: Export file path
            format_type: Export format (json, yaml, toml)

        Returns:
            True if successful
        """
        try:
            if format_type.lower() == "json":
                export_data = {
                    "metadata": {
                        "export_time": time.strftime('%Y-%m-%d %H:%M:%S'),
                        "version": "2.1",
                        "tool": "Intellicrack CLI"
                    },
                    "configuration": self.config,
                    "option_descriptions": {
                        name: {
                            "description": opt.description,
                            "category": opt.category,
                            "default": opt.default,
                            "advanced": opt.advanced
                        }
                        for name, opt in self.options.items()
                    }
                }

                with open(export_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)

            elif format_type.lower() == "yaml":
                try:
                    import yaml
                    export_data = {
                        "configuration": self.config,
                        "metadata": {
                            "export_time": time.strftime('%Y-%m-%d %H:%M:%S'),
                            "version": "2.1"
                        }
                    }

                    with open(export_path, 'w', encoding='utf-8') as f:
                        yaml.dump(export_data, f, default_flow_style=False)

                except ImportError:
                    return False

            else:
                return False

            return True

        except Exception:
            return False

    def import_config(self, import_path: str) -> bool:
        """Import configuration from file.

        Args:
            import_path: Import file path

        Returns:
            True if successful
        """
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                if import_path.endswith('.yaml') or import_path.endswith('.yml'):
                    import yaml
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)

            # Extract configuration
            if 'configuration' in data:
                config_data = data['configuration']
            else:
                config_data = data

            # Validate and import
            valid_count = 0
            for key, value in config_data.items():
                if self.set(key, value):
                    valid_count += 1

            return valid_count > 0

        except Exception:
            return False

    def display_config(self, category: Optional[str] = None, advanced: bool = False):
        """Display configuration in formatted table.

        Args:
            category: Category to display (all if None)
            advanced: Include advanced options
        """
        if not self.console:
            self._display_config_basic(category, advanced)
            return

        if category:
            categories = [category]
        else:
            categories = self.get_categories()

        for cat in categories:
            options = self.get_options_by_category(cat, advanced)

            if not options:
                continue

            table = Table(title=f"Configuration: {cat.title()}")
            table.add_column("Option", style="cyan")
            table.add_column("Value", style="yellow")
            table.add_column("Default", style="dim")
            table.add_column("Description", style="green")

            for name, option in sorted(options.items()):
                current_value = str(self.config[name])
                default_value = str(option.default)

                # Highlight non-default values
                if self.config[name] != option.default:
                    current_value = f"[bold]{current_value}[/bold]"

                # Mark advanced options
                desc = option.description
                if option.advanced:
                    desc = f"[dim](Advanced)[/dim] {desc}"
                if option.requires_restart:
                    desc = f"{desc} [red]*restart required*[/red]"

                table.add_row(name, current_value, default_value, desc)

            self.console.print(table)
            self.console.print()

    def _display_config_basic(self, category: Optional[str] = None, advanced: bool = False):
        """Display configuration in basic text format."""
        if category:
            categories = [category]
        else:
            categories = self.get_categories()

        for cat in categories:
            options = self.get_options_by_category(cat, advanced)

            if not options:
                continue

            print(f"\n{cat.upper()} Configuration:")
            print("=" * (len(cat) + 15))

            for name, option in sorted(options.items()):
                current = self.config[name]
                default = option.default
                marker = " *" if current != default else ""

                print(f"  {name:<20} = {current}{marker}")
                print(f"    {option.description}")
                if option.requires_restart:
                    print("    (Restart required)")
                print()

    def items(self):
        """Return items from the configuration dictionary."""
        return self.config.items()
    
    def keys(self):
        """Return keys from the configuration dictionary."""
        return self.config.keys()
    
    def values(self):
        """Return values from the configuration dictionary."""
        return self.config.values()
    
    def __getitem__(self, key):
        """Allow dictionary-style access."""
        return self.config[key]
    
    def __setitem__(self, key, value):
        """Allow dictionary-style setting."""
        self.set(key, value)
    
    def __contains__(self, key):
        """Check if key exists in configuration."""
        return key in self.config


def get_config_manager() -> ConfigManager:
    """Get default configuration manager instance."""
    if not hasattr(get_config_manager, '_instance'):
        get_config_manager._instance = ConfigManager()
    return get_config_manager._instance


if __name__ == "__main__":
    # Test configuration manager
    config = ConfigManager()
    config.display_config()
