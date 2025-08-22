"""Environment file manager for secure .env file operations.

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

import logging
import os
import re
import shutil
import tempfile
from pathlib import Path

from intellicrack.core.config_manager import get_config

logger = logging.getLogger(__name__)


class EnvFileManager:
    """Manages reading and writing to .env files with safety and validation."""

    def __init__(self, env_file_path: str | Path | None = None):
        """Initialize the EnvFileManager.

        Args:
            env_file_path: Path to the .env file. If None, uses default location from central config.
        """
        # Get central configuration
        self.central_config = get_config()

        if env_file_path is None:
            # Get .env file path from central config
            env_path_str = self.central_config.get("environment.env_file_path")
            if not env_path_str:
                # Fall back to default path if not configured
                env_path_str = "C:/Intellicrack/config/.env"
                # Store the default in central config for future use
                self.central_config.set("environment.env_file_path", env_path_str)
            self.env_path = Path(env_path_str)
        else:
            self.env_path = Path(env_file_path)
            # Update central config with the provided path
            self.central_config.set("environment.env_file_path", str(self.env_path))

        # Ensure the directory exists
        self.env_path.parent.mkdir(parents=True, exist_ok=True)

        # Create empty .env file if it doesn't exist
        if not self.env_path.exists():
            self.env_path.touch()
            logger.info(f"Created new .env file at {self.env_path}")

        # Load environment variables into central config on initialization
        self._sync_to_central_config()

    def read_env(self) -> dict[str, str]:
        """Read all key-value pairs from the .env file.

        Returns:
            Dictionary of environment variables
        """
        env_vars = {}

        if not self.env_path.exists():
            return env_vars

        try:
            with open(self.env_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue

                    # Parse key=value pairs
                    match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
                    if match:
                        key, value = match.groups()

                        # Remove surrounding quotes if present
                        if value and len(value) >= 2:
                            if (value[0] == value[-1]) and value[0] in ('"', "'"):
                                value = value[1:-1]

                        env_vars[key] = value
                    else:
                        logger.debug(f"Skipping invalid line {line_num} in .env file: {line}")

        except Exception as e:
            logger.error(f"Error reading .env file: {e}")

        return env_vars

    def write_env(self, env_vars: dict[str, str], preserve_comments: bool = True):
        """Write key-value pairs to the .env file.

        Args:
            env_vars: Dictionary of environment variables to write
            preserve_comments: Whether to preserve existing comments
        """
        # Create backup
        backup_path = self._create_backup()

        try:
            # Read existing content if preserving comments
            existing_lines = []
            existing_keys = set()

            if preserve_comments and self.env_path.exists():
                with open(self.env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.rstrip("\n")

                        # Check if it's a key=value line
                        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
                        if match:
                            key = match.group(1)
                            existing_keys.add(key)

                            # Replace with new value if it exists
                            if key in env_vars:
                                value = env_vars[key]
                                # Quote value if it contains spaces or special characters
                                if value and (" " in value or '"' in value or "'" in value):
                                    value = f'"{value}"'
                                existing_lines.append(f"{key}={value}")
                            else:
                                existing_lines.append(line)
                        else:
                            # Preserve comments and empty lines
                            existing_lines.append(line)

            # Add new keys that weren't in the file
            for key, value in env_vars.items():
                if key not in existing_keys:
                    # Quote value if needed
                    if value and (" " in value or '"' in value or "'" in value):
                        value = f'"{value}"'
                    existing_lines.append(f"{key}={value}")

            # Write to temporary file first
            temp_fd, temp_path = tempfile.mkstemp(dir=self.env_path.parent, text=True)
            try:
                with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                    for line in existing_lines:
                        f.write(line + "\n")

                # Atomic replace
                shutil.move(temp_path, self.env_path)
                logger.info(f"Successfully updated .env file at {self.env_path}")

            except Exception:
                # Clean up temp file on error
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                raise

        except Exception as e:
            logger.error(f"Error writing .env file: {e}")
            # Restore from backup
            if backup_path and backup_path.exists():
                shutil.copy2(backup_path, self.env_path)
                logger.info("Restored .env file from backup")
            raise

        finally:
            # Clean up backup
            if backup_path and backup_path.exists():
                backup_path.unlink()

    def get_key(self, key: str) -> str | None:
        """Get a single value from the .env file.

        Args:
            key: The environment variable key

        Returns:
            The value or None if not found
        """
        env_vars = self.read_env()
        return env_vars.get(key)

    def set_key(self, key: str, value: str):
        """Set a single key-value pair in the .env file.

        Args:
            key: The environment variable key
            value: The value to set
        """
        env_vars = self.read_env()
        env_vars[key] = value
        self.write_env(env_vars)
        # Sync to central config after updating
        self._sync_to_central_config()

    def update_keys(self, updates: dict[str, str]):
        """Update multiple keys in the .env file.

        Args:
            updates: Dictionary of key-value pairs to update
        """
        env_vars = self.read_env()
        env_vars.update(updates)
        self.write_env(env_vars)
        # Sync to central config after updating
        self._sync_to_central_config()

    def delete_key(self, key: str) -> bool:
        """Delete a key from the .env file.

        Args:
            key: The environment variable key to delete

        Returns:
            True if key was deleted, False if it didn't exist
        """
        env_vars = self.read_env()
        if key in env_vars:
            del env_vars[key]
            self.write_env(env_vars)
            # Sync to central config after deleting
            self._sync_to_central_config()
            return True
        return False

    def validate_key(self, key: str) -> bool:
        """Validate that a key name is valid for environment variables.

        Args:
            key: The key to validate

        Returns:
            True if valid, False otherwise
        """
        # Environment variable names must start with letter or underscore
        # and contain only letters, numbers, and underscores
        return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key))

    def _create_backup(self) -> Path | None:
        """Create a backup of the current .env file.

        Returns:
            Path to the backup file or None if no file to backup
        """
        if not self.env_path.exists():
            return None

        backup_path = self.env_path.with_suffix(".env.bak")
        try:
            shutil.copy2(self.env_path, backup_path)
            return backup_path
        except Exception as e:
            logger.warning(f"Could not create backup: {e}")
            return None

    def test_api_key(self, service: str, api_key: str) -> tuple[bool, str]:
        """Test if an API key is valid for a service.

        Args:
            service: Service name (openai, anthropic, google, etc.)
            api_key: The API key to test

        Returns:
            Tuple of (success, message)
        """
        if not api_key:
            return False, "API key is empty"

        # Basic format validation
        validations = {
            "openai": lambda k: k.startswith("sk-") and len(k) > 20,
            "anthropic": lambda k: k.startswith("sk-ant-") and len(k) > 20,
            "google": lambda k: len(k) > 20,
            "huggingface": lambda k: k.startswith("hf_") and len(k) > 20,
            "openrouter": lambda k: len(k) > 20,
            "groq": lambda k: k.startswith("gsk_") and len(k) > 20,
            "cohere": lambda k: len(k) > 20,
            "together": lambda k: len(k) > 20,
        }

        service_lower = service.lower()
        if service_lower in validations:
            if validations[service_lower](api_key):
                return True, f"API key format is valid for {service}"
            else:
                return False, f"API key format is invalid for {service}"

        # Unknown service - just check it's not empty
        return True, "API key accepted (format validation not available for this service)"

    def get_all_api_keys(self) -> dict[str, str]:
        """Get all API keys from the .env file.

        Returns:
            Dictionary of API keys (only keys ending with _API_KEY or _API_TOKEN)
        """
        env_vars = self.read_env()
        api_keys = {}

        for key, value in env_vars.items():
            if key.endswith(("_API_KEY", "_API_TOKEN", "_KEY", "_TOKEN")):
                api_keys[key] = value

        return api_keys

    def set_api_key(self, service: str, api_key: str):
        """Set an API key for a specific service.

        Args:
            service: Service name (openai, anthropic, etc.)
            api_key: The API key to set
        """
        # Normalize service name to uppercase with _API_KEY suffix
        key_mapping = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "google": "GOOGLE_API_KEY",
            "huggingface": "HUGGINGFACE_API_TOKEN",
            "openrouter": "OPENROUTER_API_KEY",
            "groq": "GROQ_API_KEY",
            "cohere": "COHERE_API_KEY",
            "together": "TOGETHER_API_KEY",
            "ollama": "OLLAMA_API_BASE",
        }

        service_lower = service.lower()
        if service_lower in key_mapping:
            key = key_mapping[service_lower]
        else:
            # Default format for unknown services
            key = f"{service.upper()}_API_KEY"

        self.set_key(key, api_key)

    def _sync_to_central_config(self):
        """Sync environment variables from .env file to central config."""
        try:
            env_vars = self.read_env()
            # Store all environment variables in central config
            self.central_config.set("environment.variables", env_vars)
            logger.debug(f"Synced {len(env_vars)} environment variables to central config")
        except Exception as e:
            logger.warning(f"Could not sync environment variables to central config: {e}")

    def _sync_from_central_config(self):
        """Sync environment variables from central config to .env file."""
        try:
            # Get environment variables from central config
            env_vars = self.central_config.get("environment.variables", {})
            if env_vars:
                self.write_env(env_vars)
                logger.debug(f"Synced {len(env_vars)} environment variables from central config")
        except Exception as e:
            logger.warning(f"Could not sync environment variables from central config: {e}")

    def load_into_environment(self, override: bool = False):
        """Load all variables from .env file into the actual environment.

        Args:
            override: Whether to override existing environment variables
        """
        env_vars = self.read_env()
        for key, value in env_vars.items():
            if override or key not in os.environ:
                os.environ[key] = value
                logger.debug(f"Loaded {key} into environment")
        logger.info(f"Loaded {len(env_vars)} environment variables")

    def auto_load(self):
        """Automatically load .env file if configured to do so in central config."""
        auto_load = self.central_config.get("environment.auto_load_env", True)
        if auto_load:
            self.load_into_environment(override=False)
            logger.info("Auto-loaded environment variables from .env file")
